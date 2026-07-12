//! Real PostgreSQL parity/adversarial coverage for the durable Activity Inbox.
//!
//! Skips unless `TEST_DATABASE_URL` is set, matching `pg_store`.

use std::sync::Arc;
use std::time::Duration;

use agora::model::{ActivityReason, Post, Thread, ThreadFollowLevel};
use agora::store::{
    AcceptedAnswerAction, ActivityFilter, PgStore, Store, StoreError, MAX_ACTIVITY_BATCH,
    MAX_MENTIONS_PER_POST, MAX_THREAD_FOLLOWERS,
};
use agora::{default_categories, new_id, now_secs};
use sqlx::postgres::PgPoolOptions;

#[tokio::test]
async fn pg_follow_levels_migrate_and_match_memory_authority() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("NOTE: TEST_DATABASE_URL not set — skipping PostgreSQL follow-level test");
        return;
    };
    let schema = new_id("agora_follow_level_migration");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(&format!("SET search_path TO {schema}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TABLE thread_subscriptions (\
             thread_id TEXT NOT NULL, subscriber_sub TEXT NOT NULL, created_at BIGINT NOT NULL, \
             PRIMARY KEY (thread_id, subscriber_sub)\
         )",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO thread_subscriptions (thread_id, subscriber_sub, created_at) \
         VALUES ('t_legacy_watch', 'u_legacy_watch', 1)",
    )
    .execute(&pool)
    .await
    .unwrap();

    let store = PgStore::from_pool(pool.clone());
    store.migrate().await.unwrap();
    assert_eq!(
        store
            .thread_follow_level("t_legacy_watch", "u_legacy_watch")
            .await
            .unwrap(),
        ThreadFollowLevel::Watch,
        "a historical boolean row migrates to Watch"
    );
    store
        .migrate()
        .await
        .expect("follow-level migration is idempotent");
    let legacy_level_column: bool = sqlx::query_scalar(
        "SELECT EXISTS (\
             SELECT 1 FROM information_schema.columns \
             WHERE table_schema = $1 AND table_name = 'thread_subscriptions' \
               AND column_name = 'level'\
         )",
    )
    .bind(&schema)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        !legacy_level_column,
        "the v6 table stays byte-for-byte Watch-only for rollback readers"
    );
    let level_check: bool = sqlx::query_scalar(
        "SELECT EXISTS (\
             SELECT 1 FROM information_schema.table_constraints \
             WHERE constraint_schema = $1 AND table_name = 'thread_follow_preferences' \
               AND constraint_name = 'ck_thread_follow_preferences_level' \
               AND constraint_type = 'CHECK'\
         )",
    )
    .bind(&schema)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(level_check, "the new preference table constrains Follow/Mute");
    let preference_fk: bool = sqlx::query_scalar(
        "SELECT EXISTS (\
             SELECT 1 FROM information_schema.table_constraints \
             WHERE constraint_schema = $1 AND table_name = 'thread_follow_preferences' \
               AND constraint_name = 'fk_thread_follow_preference_thread' \
               AND constraint_type = 'FOREIGN KEY'\
         )",
    )
    .bind(&schema)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(preference_fk, "v6 thread deletion cascades v7 preferences");
    let preference_delete_rule: String = sqlx::query_scalar(
        "SELECT delete_rule FROM information_schema.referential_constraints \
         WHERE constraint_schema = $1 \
           AND constraint_name = 'fk_thread_follow_preference_thread'",
    )
    .bind(&schema)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(preference_delete_rule, "CASCADE");
    assert!(sqlx::query(
        "INSERT INTO thread_follow_preferences \
             (thread_id, subscriber_sub, level, created_at) \
         VALUES ('invalid', 'invalid', 'surprise', 1)",
    )
    .execute(&pool)
    .await
    .is_err());
    store
        .seed_categories_if_empty(&default_categories())
        .await
        .unwrap();

    let now = now_secs();
    let mut thread_ids = Vec::new();
    for (suffix, level) in [
        ("pg_level_watch", ThreadFollowLevel::Watch),
        ("pg_level_follow", ThreadFollowLevel::Follow),
        ("pg_level_mute", ThreadFollowLevel::Mute),
    ] {
        let (thread, op) = fixture_thread(suffix, "u_alice", "alice@holdfast.local", now);
        store.create_thread(&thread, &op).await.unwrap();
        store
            .set_thread_follow_level(&thread.id, "u_carol", level, now + 1)
            .await
            .unwrap();
        let reply = fixture_reply(
            &thread.id,
            "u_bob",
            "bob@holdfast.local",
            suffix,
            "",
            now + 2,
        );
        store
            .add_reply_with_activity(&reply, &[], &new_id("a"))
            .await
            .unwrap();
        thread_ids.push(thread.id);
    }
    let activity = store
        .activity_page("u_carol", ActivityFilter::All, false, None, 20)
        .await
        .unwrap();
    assert_eq!(activity.len(), 1);
    assert_eq!(activity[0].reason, ActivityReason::Following);
    assert_eq!(activity[0].post_body_md, "pg_level_watch");

    let following = store
        .list_threads(
            None,
            agora::store::ThreadSort::Latest,
            Some("u_carol"),
            agora::store::ThreadStatusFilter::Any,
            20,
            now + 10,
        )
        .await
        .unwrap();
    assert_eq!(following.len(), 2);
    assert!(following.iter().all(|thread| thread.id != thread_ids[2]));
    let legacy_watch_rows: Vec<String> = sqlx::query_scalar(
        "SELECT thread_id FROM thread_subscriptions \
         WHERE subscriber_sub = 'u_carol' ORDER BY thread_id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(legacy_watch_rows, vec![thread_ids[0].clone()]);
    let typed_preferences: Vec<(String, String)> = sqlx::query_as(
        "SELECT thread_id, level FROM thread_follow_preferences \
         WHERE subscriber_sub = 'u_carol' ORDER BY thread_id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(typed_preferences.len(), 2);
    assert!(typed_preferences.contains(&(thread_ids[1].clone(), "follow".to_string())));
    assert!(typed_preferences.contains(&(thread_ids[2].clone(), "mute".to_string())));
    let signals = store
        .thread_personal_signals("u_carol", &thread_ids)
        .await
        .unwrap();
    assert_eq!(
        signals[&thread_ids[0]].follow_level,
        ThreadFollowLevel::Watch
    );
    assert_eq!(
        signals[&thread_ids[1]].follow_level,
        ThreadFollowLevel::Follow
    );
    assert_eq!(
        signals[&thread_ids[2]].follow_level,
        ThreadFollowLevel::Mute
    );

    // A rollback v6 Follow inserts only the legacy Watch row. Watch wins a transient conflict,
    // and the next v7 command converges back to exactly one physical representation.
    sqlx::query(
        "INSERT INTO thread_subscriptions (thread_id, subscriber_sub, created_at) \
         VALUES ($1, 'u_carol', $2)",
    )
    .bind(&thread_ids[1])
    .bind(now + 10)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        store
            .thread_follow_level(&thread_ids[1], "u_carol")
            .await
            .unwrap(),
        ThreadFollowLevel::Watch
    );
    store
        .set_thread_follow_level(
            &thread_ids[1],
            "u_carol",
            ThreadFollowLevel::Follow,
            now + 10,
        )
        .await
        .unwrap();
    let reconciled_legacy: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM thread_subscriptions \
         WHERE thread_id = $1 AND subscriber_sub = 'u_carol'",
    )
    .bind(&thread_ids[1])
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(reconciled_legacy, 0);
    assert_eq!(
        store
            .thread_follow_level(&thread_ids[1], "u_carol")
            .await
            .unwrap(),
        ThreadFollowLevel::Follow
    );

    // v6 Unfollow knows only the legacy table and can leave generic Following deliveries behind.
    // A v7 forward migration removes that one path while preserving the direct Reply reason.
    let (repair_thread, repair_op) = fixture_thread(
        "pg_rollback_repair",
        "u_carol",
        "carol@holdfast.local",
        now + 12,
    );
    store
        .create_thread(&repair_thread, &repair_op)
        .await
        .unwrap();
    store
        .set_thread_follow_level(
            &repair_thread.id,
            "u_carol",
            ThreadFollowLevel::Watch,
            now + 13,
        )
        .await
        .unwrap();
    let repair_reply = fixture_reply(
        &repair_thread.id,
        "u_bob",
        "bob@holdfast.local",
        "rollback repair",
        "",
        now + 14,
    );
    let repair_event_id = new_id("a");
    store
        .add_reply_with_activity(&repair_reply, &[], &repair_event_id)
        .await
        .unwrap();
    let repair_reasons_before: Vec<String> = sqlx::query_scalar(
        "SELECT reason FROM forum_activity_deliveries \
         WHERE activity_id = $1 AND recipient_kind = 'subject' \
           AND recipient_key = 'u_carol' ORDER BY reason",
    )
    .bind(&repair_event_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        repair_reasons_before,
        vec!["following".to_string(), "reply".to_string()]
    );
    sqlx::query(
        "DELETE FROM thread_subscriptions \
         WHERE thread_id = $1 AND subscriber_sub = 'u_carol'",
    )
    .bind(&repair_thread.id)
    .execute(&pool)
    .await
    .unwrap();
    store.migrate().await.unwrap();
    let repair_reasons_after: Vec<String> = sqlx::query_scalar(
        "SELECT reason FROM forum_activity_deliveries \
         WHERE activity_id = $1 AND recipient_kind = 'subject' \
           AND recipient_key = 'u_carol' ORDER BY reason",
    )
    .bind(&repair_event_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(repair_reasons_after, vec!["reply".to_string()]);

    store
        .set_thread_follow_level(
            &thread_ids[0],
            "u_carol",
            ThreadFollowLevel::Follow,
            now + 11,
        )
        .await
        .unwrap();
    assert!(store
        .activity_page("u_carol", ActivityFilter::All, false, None, 20)
        .await
        .unwrap()
        .iter()
        .all(|item| item.event.thread_id != thread_ids[0]));

    let (direct_thread, direct_op) = fixture_thread(
        "pg_level_direct",
        "u_carol",
        "carol@holdfast.local",
        now + 20,
    );
    store
        .create_thread(&direct_thread, &direct_op)
        .await
        .unwrap();
    store
        .set_thread_follow_level(
            &direct_thread.id,
            "u_carol",
            ThreadFollowLevel::Mute,
            now + 21,
        )
        .await
        .unwrap();
    let direct_reply = fixture_reply(
        &direct_thread.id,
        "u_bob",
        "bob@holdfast.local",
        "direct survives mute",
        "",
        now + 22,
    );
    store
        .add_reply_with_activity(&direct_reply, &[], &new_id("a"))
        .await
        .unwrap();
    let direct = store
        .activity_page("u_carol", ActivityFilter::All, false, None, 20)
        .await
        .unwrap()
        .into_iter()
        .find(|item| item.event.thread_id == direct_thread.id)
        .unwrap();
    assert_eq!(direct.reason, ActivityReason::Reply);

    store.delete_thread(&direct_thread.id).await.unwrap();
    let remaining_preference: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM thread_subscriptions WHERE thread_id = $1) + \
                (SELECT COUNT(*) FROM thread_follow_preferences WHERE thread_id = $1)",
    )
    .bind(&direct_thread.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        remaining_preference, 0,
        "thread deletion cleans preferences"
    );

    let (rollback_deleted, rollback_deleted_op) = fixture_thread(
        "pg_v6_delete_cascade",
        "u_alice",
        "alice@holdfast.local",
        now + 30,
    );
    store
        .create_thread(&rollback_deleted, &rollback_deleted_op)
        .await
        .unwrap();
    store
        .set_thread_follow_level(
            &rollback_deleted.id,
            "u_carol",
            ThreadFollowLevel::Mute,
            now + 31,
        )
        .await
        .unwrap();
    sqlx::query("DELETE FROM posts WHERE thread_id = $1")
        .bind(&rollback_deleted.id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM threads WHERE id = $1")
        .bind(&rollback_deleted.id)
        .execute(&pool)
        .await
        .unwrap();
    let rollback_orphan: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM thread_follow_preferences WHERE thread_id = $1",
    )
    .bind(&rollback_deleted.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rollback_orphan, 0, "v6-style delete cascades v7 preference");

    sqlx::query("SET search_path TO public")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg_activity_is_atomic_bounded_and_authoritative() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("NOTE: TEST_DATABASE_URL not set — skipping PostgreSQL Activity test");
        return;
    };
    let store = Arc::new(PgStore::connect(&url).await.expect("connect"));
    store.migrate().await.expect("migrate");
    let raw = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    // Simulate an upgrade from the pre-FK schema. Migration removes existing orphans, detects
    // missing constraints through information_schema, adds CASCADE FKs, and remains idempotent.
    sqlx::query(
        "ALTER TABLE forum_activity_deliveries DROP CONSTRAINT IF EXISTS fk_activity_delivery_event",
    )
    .execute(&raw)
    .await
    .unwrap();
    sqlx::query(
        "ALTER TABLE forum_activity_receipts DROP CONSTRAINT IF EXISTS fk_activity_receipt_event",
    )
    .execute(&raw)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO forum_activity_deliveries \
         (activity_id, recipient_kind, recipient_key, reason) \
         VALUES ('a_orphan', 'subject', 'u_orphan', 'reply') \
         ON CONFLICT DO NOTHING",
    )
    .execute(&raw)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO forum_activity_receipts (activity_id, viewer_sub, read_at) \
         VALUES ('a_orphan', 'u_orphan', 1) ON CONFLICT DO NOTHING",
    )
    .execute(&raw)
    .await
    .unwrap();
    store.migrate().await.expect("upgrade migrate");
    store.migrate().await.expect("idempotent migrate");
    let orphan_deliveries: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM forum_activity_deliveries WHERE activity_id = 'a_orphan'",
    )
    .fetch_one(&raw)
    .await
    .unwrap();
    let orphan_receipts: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM forum_activity_receipts WHERE activity_id = 'a_orphan'",
    )
    .fetch_one(&raw)
    .await
    .unwrap();
    assert_eq!((orphan_deliveries, orphan_receipts), (0, 0));
    let fk_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.table_constraints \
         WHERE constraint_schema = CURRENT_SCHEMA \
           AND constraint_name IN ('fk_activity_delivery_event', 'fk_activity_receipt_event') \
           AND constraint_type = 'FOREIGN KEY'",
    )
    .fetch_one(&raw)
    .await
    .unwrap();
    assert_eq!(fk_count, 2);

    for table in [
        "forum_activity_receipts",
        "forum_activity_deliveries",
        "forum_activity_events",
        "post_reactions",
        "post_mentions",
        "forum_identity_aliases",
        "thread_follow_preferences",
        "thread_subscriptions",
        "banned_authors",
        "posts",
        "threads",
        "categories",
    ] {
        sqlx::query(&format!("DELETE FROM {table}"))
            .execute(&raw)
            .await
            .unwrap();
    }
    store
        .seed_categories_if_empty(&default_categories())
        .await
        .unwrap();

    let now = now_secs();
    let (historical_thread, historical_op) = fixture_thread(
        "pg_historical_alias",
        "u_historical",
        "historical@holdfast.local",
        now - 10,
    );
    store
        .create_thread(&historical_thread, &historical_op)
        .await
        .unwrap();
    sqlx::query("DELETE FROM forum_identity_aliases WHERE subject = 'u_historical'")
        .execute(&raw)
        .await
        .unwrap();
    store.migrate().await.expect("historical alias backfill");
    store
        .migrate()
        .await
        .expect("historical alias backfill idempotent");
    let historical_aliases: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM forum_identity_aliases \
         WHERE alias = 'historical' AND subject = 'u_historical'",
    )
    .fetch_one(&raw)
    .await
    .unwrap();
    assert_eq!(historical_aliases, 1);
    store.delete_thread(&historical_thread.id).await.unwrap();

    let (thread, op) = fixture_thread("pg_activity", "u_alice", "alice@holdfast.local", now);
    store
        .create_thread_with_activity(&thread, &op, &[], &new_id("a"))
        .await
        .unwrap();

    // Repeated/concurrent desired-state follows remain idempotently ON.
    let mut tasks = Vec::new();
    for offset in 0..8 {
        let store = Arc::clone(&store);
        let thread_id = thread.id.clone();
        tasks.push(tokio::spawn(async move {
            store
                .set_thread_subscription(&thread_id, "u_carol", true, now + offset)
                .await
        }));
    }
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    assert!(store
        .is_thread_subscribed(&thread.id, "u_carol")
        .await
        .unwrap());

    let reply = fixture_reply(
        &thread.id,
        "u_bob",
        "bob@holdfast.local",
        "PG hello @alice @bob",
        &op.id,
        now + 10,
    );
    store
        .add_reply_with_activity(
            &reply,
            &["alice".to_string(), "bob".to_string()],
            &new_id("a"),
        )
        .await
        .unwrap();
    let alice = store
        .activity_page("u_alice", ActivityFilter::All, false, None, 100)
        .await
        .unwrap();
    assert_eq!(alice.len(), 1);
    assert_eq!(alice[0].reason, ActivityReason::Mention);
    assert_eq!(alice[0].post_body_md, reply.body_md);
    let carol = store
        .activity_page("u_carol", ActivityFilter::All, false, None, 100)
        .await
        .unwrap();
    assert_eq!(carol.len(), 1);
    assert_eq!(carol[0].reason, ActivityReason::Following);
    assert_eq!(store.unread_activity_count("u_bob").await.unwrap(), 0);

    // Invalid quote rolls back post + parsed mention + event as one command.
    let invalid = fixture_reply(
        &thread.id,
        "u_bob",
        "bob@holdfast.local",
        "must roll back @alice",
        "p_missing",
        now + 11,
    );
    let post_count = store.count_posts(&thread.id).await.unwrap();
    assert!(store
        .add_reply_with_activity(&invalid, &["alice".to_string()], &new_id("a"),)
        .await
        .is_err());
    assert_eq!(store.count_posts(&thread.id).await.unwrap(), post_count);
    assert_eq!(store.unread_activity_count("u_alice").await.unwrap(), 1);

    // Accepted answer and its delivery commit together.
    store
        .mutate_accepted_answer_with_activity(
            &thread.id,
            AcceptedAnswerAction::Accept {
                post_id: reply.id.clone(),
            },
            &new_id("a"),
            "u_alice",
            now + 12,
        )
        .await
        .unwrap();
    let bob = store
        .activity_page("u_bob", ActivityFilter::All, false, None, 100)
        .await
        .unwrap();
    assert_eq!(bob.len(), 1);
    assert_eq!(bob[0].reason, ActivityReason::Answer);

    // Build a full page plus one. The 31-id command is rejected before mutation.
    for index in 0..MAX_ACTIVITY_BATCH {
        let post = fixture_reply(
            &thread.id,
            "u_bob",
            "bob@holdfast.local",
            &format!("PG batch {index}"),
            "",
            now + 20 + index as i64,
        );
        store
            .add_reply_with_activity(&post, &[], &new_id("a"))
            .await
            .unwrap();
    }
    let page = store
        .activity_page("u_alice", ActivityFilter::All, false, None, 100)
        .await
        .unwrap();
    assert_eq!(page.len(), MAX_ACTIVITY_BATCH + 1);
    let all_ids: Vec<String> = page.iter().map(|item| item.event.id.clone()).collect();
    assert!(matches!(
        store
            .mark_activity_batch_read("u_alice", &all_ids, now + 100)
            .await
            .unwrap_err(),
        StoreError::InvalidOperation(_)
    ));
    assert_eq!(
        store.unread_activity_count("u_alice").await.unwrap(),
        (MAX_ACTIVITY_BATCH + 1) as i64
    );

    // Cross-viewer id after an own id rolls the entire transaction back.
    let own_id = all_ids[0].clone();
    let bob_id = bob[0].event.id.clone();
    assert!(matches!(
        store
            .mark_activity_batch_read("u_alice", &[own_id.clone(), bob_id], now + 101,)
            .await
            .unwrap_err(),
        StoreError::NotFound(_)
    ));
    assert!(!store
        .activity_page("u_alice", ActivityFilter::All, true, None, 100,)
        .await
        .unwrap()
        .iter()
        .all(|item| item.event.id != own_id));

    // An event committed after the rendered id list can never be captured by the bounded batch.
    let page_ids: Vec<String> = all_ids.into_iter().take(MAX_ACTIVITY_BATCH).collect();
    let late = fixture_reply(
        &thread.id,
        "u_bob",
        "bob@holdfast.local",
        "PG late event",
        "",
        now + 200,
    );
    let late_event_id = new_id("a");
    let batch_store = Arc::clone(&store);
    let batch = tokio::spawn(async move {
        batch_store
            .mark_activity_batch_read("u_alice", &page_ids, now + 201)
            .await
    });
    store
        .add_reply_with_activity(&late, &[], &late_event_id)
        .await
        .unwrap();
    assert_eq!(batch.await.unwrap().unwrap(), MAX_ACTIVITY_BATCH as i64);
    let unread = store
        .activity_page("u_alice", ActivityFilter::All, true, None, 100)
        .await
        .unwrap();
    assert!(unread.iter().any(|item| item.event.id == late_event_id));

    // Authoritative cleanup: deleting a target removes event/delivery/receipt rows.
    store.delete_post(&late.id).await.unwrap();
    assert!(!store
        .activity_page("u_alice", ActivityFilter::All, false, None, 100,)
        .await
        .unwrap()
        .iter()
        .any(|item| item.event.id == late_event_id));

    // An admin without any stored forum profile is represented by the event subject, never by
    // the question author's email.
    store
        .mutate_accepted_answer(&thread.id, AcceptedAnswerAction::Clear)
        .await
        .unwrap();
    let admin_event_id = new_id("a");
    store
        .mutate_accepted_answer_with_activity(
            &thread.id,
            AcceptedAnswerAction::Accept {
                post_id: reply.id.clone(),
            },
            &admin_event_id,
            "u_admin_without_profile",
            now + 300,
        )
        .await
        .unwrap();
    let admin_item = store
        .activity_page("u_bob", ActivityFilter::All, false, None, 200)
        .await
        .unwrap()
        .into_iter()
        .find(|item| item.event.id == admin_event_id)
        .unwrap();
    assert_eq!(admin_item.event.actor_sub, "u_admin_without_profile");
    assert!(admin_item.actor_email.is_empty());

    // Alias routing is append-only and subject-addressed. Rename adds an alias, a collision makes
    // future resolution ambiguous, and neither spoofing nor collision transfers old deliveries.
    let (alias_thread, alias_op) =
        fixture_thread("pg_alias", "u_bob", "bob@holdfast.local", now + 400);
    store
        .create_thread_with_activity(&alias_thread, &alias_op, &[], &new_id("a"))
        .await
        .unwrap();
    let rename = fixture_reply(
        &alias_thread.id,
        "u_alice",
        "alice-renamed@holdfast.local",
        "register rename",
        "",
        now + 401,
    );
    store
        .add_reply_with_activity(&rename, &[], &new_id("a"))
        .await
        .unwrap();
    let stable_mention_id = new_id("a");
    let unique_mention = fixture_reply(
        &alias_thread.id,
        "u_bob",
        "bob@holdfast.local",
        "Unique @alice-renamed",
        "",
        now + 402,
    );
    store
        .add_reply_with_activity(
            &unique_mention,
            &["alice-renamed".to_string()],
            &stable_mention_id,
        )
        .await
        .unwrap();
    assert!(store
        .activity_page("u_alice", ActivityFilter::All, false, None, 200)
        .await
        .unwrap()
        .iter()
        .any(|item| item.event.id == stable_mention_id));
    let collision = fixture_reply(
        &alias_thread.id,
        "u_carol",
        "alice-renamed@another.invalid",
        "colliding profile",
        "",
        now + 403,
    );
    store
        .add_reply_with_activity(&collision, &[], &new_id("a"))
        .await
        .unwrap();
    let ambiguous_event_id = new_id("a");
    let ambiguous = fixture_reply(
        &alias_thread.id,
        "u_bob",
        "bob@holdfast.local",
        "Ambiguous @alice-renamed",
        "",
        now + 404,
    );
    store
        .add_reply_with_activity(
            &ambiguous,
            &["alice-renamed".to_string()],
            &ambiguous_event_id,
        )
        .await
        .unwrap();
    let ambiguous_events: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM forum_activity_events WHERE id = $1")
            .bind(&ambiguous_event_id)
            .fetch_one(&raw)
            .await
            .unwrap();
    assert_eq!(ambiguous_events, 0);
    assert!(store
        .activity_page("u_carol", ActivityFilter::All, false, None, 200)
        .await
        .unwrap()
        .iter()
        .all(|item| item.event.id != stable_mention_id));
    assert!(store
        .activity_page("u_alias_spoofer", ActivityFilter::All, false, None, 200)
        .await
        .unwrap()
        .iter()
        .all(|item| item.event.id != stable_mention_id));

    // Concurrent follows serialize on the thread lock. Exactly one contender fills slot 256;
    // cap+1 is rejected, and a legacy over-cap row makes reply fan-out fail before any write.
    let (cap_thread, cap_op) =
        fixture_thread("pg_cap", "u_alice", "alice@holdfast.local", now + 500);
    store
        .create_thread_with_activity(&cap_thread, &cap_op, &[], &new_id("a"))
        .await
        .unwrap();
    for index in 0..(MAX_THREAD_FOLLOWERS - 1) {
        sqlx::query(
            "INSERT INTO thread_subscriptions (thread_id, subscriber_sub, created_at) \
             VALUES ($1, $2, $3)",
        )
        .bind(&cap_thread.id)
        .bind(format!("u_pg_follower_{index:03}"))
        .bind(now + 501)
        .execute(&raw)
        .await
        .unwrap();
    }
    let mut follow_tasks = Vec::new();
    for subject in ["u_pg_boundary_a", "u_pg_boundary_b"] {
        let store = Arc::clone(&store);
        let thread_id = cap_thread.id.clone();
        follow_tasks.push(tokio::spawn(async move {
            store
                .set_thread_subscription(&thread_id, subject, true, now + 502)
                .await
                .map(|_| subject)
        }));
    }
    let mut winners = Vec::new();
    let mut rejected = 0;
    for task in follow_tasks {
        match task.await.unwrap() {
            Ok(subject) => winners.push(subject),
            Err(StoreError::InvalidOperation(_)) => rejected += 1,
            Err(error) => panic!("unexpected follow result: {error}"),
        }
    }
    assert_eq!((winners.len(), rejected), (1, 1));
    store
        .set_thread_subscription(&cap_thread.id, winners[0], true, now + 503)
        .await
        .unwrap();
    assert!(matches!(
        store
            .set_thread_subscription(&cap_thread.id, "u_pg_cap_plus_one", true, now + 503)
            .await
            .unwrap_err(),
        StoreError::InvalidOperation(_)
    ));
    let at_cap = fixture_reply(
        &cap_thread.id,
        "u_bob",
        "bob@holdfast.local",
        "fanout at cap",
        "",
        now + 504,
    );
    let at_cap_mutation = store
        .add_reply_with_activity(&at_cap, &[], &new_id("a"))
        .await
        .unwrap();
    assert_eq!(
        at_cap_mutation.delivery_subjects.len(),
        MAX_THREAD_FOLLOWERS + 1
    );

    sqlx::query(
        "INSERT INTO thread_subscriptions (thread_id, subscriber_sub, created_at) \
         VALUES ($1, 'u_legacy_over_cap', $2)",
    )
    .bind(&cap_thread.id)
    .bind(now + 505)
    .execute(&raw)
    .await
    .unwrap();
    let before_cap_posts = store.count_posts(&cap_thread.id).await.unwrap();
    let over_cap = fixture_reply(
        &cap_thread.id,
        "u_bob",
        "bob@holdfast.local",
        "must not persist over cap",
        "",
        now + 506,
    );
    let over_cap_event_id = new_id("a");
    assert!(matches!(
        store
            .add_reply_with_activity(&over_cap, &[], &over_cap_event_id)
            .await
            .unwrap_err(),
        StoreError::InvalidOperation(_)
    ));
    assert_eq!(
        store.count_posts(&cap_thread.id).await.unwrap(),
        before_cap_posts
    );
    assert_eq!(activity_counts(&raw, &over_cap_event_id).await, (0, 0, 0));
    sqlx::query(
        "DELETE FROM thread_subscriptions \
         WHERE thread_id = $1 AND subscriber_sub = 'u_legacy_over_cap'",
    )
    .bind(&cap_thread.id)
    .execute(&raw)
    .await
    .unwrap();

    let too_many_aliases: Vec<String> = (0..=MAX_MENTIONS_PER_POST)
        .map(|index| format!("pg-alias-{index}"))
        .collect();
    let mention_over_cap = fixture_reply(
        &cap_thread.id,
        "u_bob",
        "bob@holdfast.local",
        "must not persist mention overflow",
        "",
        now + 507,
    );
    let mention_over_cap_event_id = new_id("a");
    assert!(matches!(
        store
            .add_reply_with_activity(
                &mention_over_cap,
                &too_many_aliases,
                &mention_over_cap_event_id,
            )
            .await
            .unwrap_err(),
        StoreError::InvalidOperation(_)
    ));
    assert_eq!(
        store.count_posts(&cap_thread.id).await.unwrap(),
        before_cap_posts
    );
    assert_eq!(
        activity_counts(&raw, &mention_over_cap_event_id).await,
        (0, 0, 0)
    );

    // Receipt mutations and moderation deletion share category->thread->post->event lock order.
    // Either command may win, but both complete without deadlock and CASCADE leaves all 3 rows 0.
    let (post_delete_thread, post_delete_op) = fixture_thread(
        "pg_concurrent_post",
        "u_alice",
        "alice@holdfast.local",
        now + 600,
    );
    store
        .create_thread_with_activity(&post_delete_thread, &post_delete_op, &[], &new_id("a"))
        .await
        .unwrap();
    let post_delete_reply = fixture_reply(
        &post_delete_thread.id,
        "u_bob",
        "bob@holdfast.local",
        "concurrent post delete",
        "",
        now + 601,
    );
    let post_delete_event_id = new_id("a");
    store
        .add_reply_with_activity(&post_delete_reply, &[], &post_delete_event_id)
        .await
        .unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let read_task = {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let event_id = post_delete_event_id.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            store
                .set_activity_read(&event_id, "u_alice", true, now + 602)
                .await
        })
    };
    let delete_post_task = {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let post_id = post_delete_reply.id.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            store.delete_post(&post_id).await
        })
    };
    barrier.wait().await;
    let (read_result, delete_result) = tokio::time::timeout(Duration::from_secs(10), async {
        (read_task.await.unwrap(), delete_post_task.await.unwrap())
    })
    .await
    .expect("set_activity_read/delete_post must not deadlock");
    assert!(read_result.is_ok() || matches!(read_result, Err(StoreError::NotFound(_))));
    delete_result.unwrap();
    assert_eq!(
        activity_counts(&raw, &post_delete_event_id).await,
        (0, 0, 0)
    );

    let (thread_delete_thread, thread_delete_op) = fixture_thread(
        "pg_concurrent_thread",
        "u_alice",
        "alice@holdfast.local",
        now + 700,
    );
    store
        .create_thread_with_activity(&thread_delete_thread, &thread_delete_op, &[], &new_id("a"))
        .await
        .unwrap();
    let thread_delete_reply = fixture_reply(
        &thread_delete_thread.id,
        "u_bob",
        "bob@holdfast.local",
        "concurrent thread delete",
        "",
        now + 701,
    );
    let thread_delete_event_id = new_id("a");
    store
        .add_reply_with_activity(&thread_delete_reply, &[], &thread_delete_event_id)
        .await
        .unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let batch_task = {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let event_id = thread_delete_event_id.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            store
                .mark_activity_batch_read("u_alice", &[event_id], now + 702)
                .await
        })
    };
    let delete_thread_task = {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let thread_id = thread_delete_thread.id.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            store.delete_thread(&thread_id).await
        })
    };
    barrier.wait().await;
    let (batch_result, delete_result) = tokio::time::timeout(Duration::from_secs(10), async {
        (batch_task.await.unwrap(), delete_thread_task.await.unwrap())
    })
    .await
    .expect("batch-read/delete_thread must not deadlock");
    assert!(batch_result.is_ok() || matches!(batch_result, Err(StoreError::NotFound(_))));
    delete_result.unwrap();
    assert_eq!(
        activity_counts(&raw, &thread_delete_event_id).await,
        (0, 0, 0)
    );
}

async fn activity_counts(pool: &sqlx::PgPool, activity_id: &str) -> (i64, i64, i64) {
    let events: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM forum_activity_events WHERE id = $1")
            .bind(activity_id)
            .fetch_one(pool)
            .await
            .unwrap();
    let deliveries: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM forum_activity_deliveries WHERE activity_id = $1")
            .bind(activity_id)
            .fetch_one(pool)
            .await
            .unwrap();
    let receipts: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM forum_activity_receipts WHERE activity_id = $1")
            .bind(activity_id)
            .fetch_one(pool)
            .await
            .unwrap();
    (events, deliveries, receipts)
}

fn fixture_thread(
    id: &str,
    author_sub: &str,
    author_email: &str,
    created_at: i64,
) -> (Thread, Post) {
    let thread_id = format!("t_{id}");
    let post_id = format!("p_{id}_op");
    (
        Thread {
            id: thread_id.clone(),
            category_id: "support".to_string(),
            title: "PG Activity".to_string(),
            author_sub: author_sub.to_string(),
            author_email: author_email.to_string(),
            created_at,
            last_at: created_at,
            locked: false,
            pinned: false,
            accepted_post_id: String::new(),
        },
        Post {
            id: post_id,
            thread_id,
            body_md: "Question".to_string(),
            quoted_post_id: String::new(),
            author_sub: author_sub.to_string(),
            author_email: author_email.to_string(),
            created_at,
        },
    )
}

fn fixture_reply(
    thread_id: &str,
    author_sub: &str,
    author_email: &str,
    body: &str,
    quote_post_id: &str,
    created_at: i64,
) -> Post {
    Post {
        id: new_id("p"),
        thread_id: thread_id.to_string(),
        body_md: body.to_string(),
        quoted_post_id: quote_post_id.to_string(),
        author_sub: author_sub.to_string(),
        author_email: author_email.to_string(),
        created_at,
    }
}
