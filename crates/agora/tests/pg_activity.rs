//! Real PostgreSQL parity/adversarial coverage for the durable Activity Inbox.
//!
//! Skips unless `TEST_DATABASE_URL` is set, matching `pg_store`.

use std::sync::Arc;
use std::time::Duration;

use agora::model::{ActivityReason, Post, Thread, ThreadFollowLevel};
use agora::store::{
    AcceptedAnswerAction, ActivityFilter, CatchUpCursor, CatchUpQuestionState, CatchUpReason,
    CatchUpView, PgStore, Store, StoreError, MAX_ACTIVITY_BATCH, MAX_CATCH_UP_PAGE,
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
    assert!(
        level_check,
        "the new preference table constrains Follow/Mute"
    );
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
        let (thread, op) = fixture_thread(suffix, "u_alice", "alice@steadholme.local", now);
        store.create_thread(&thread, &op).await.unwrap();
        store
            .set_thread_follow_level(&thread.id, "u_carol", level, now + 1)
            .await
            .unwrap();
        let reply = fixture_reply(
            &thread.id,
            "u_bob",
            "bob@steadholme.local",
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
        "carol@steadholme.local",
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
        "bob@steadholme.local",
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
        "carol@steadholme.local",
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
        "bob@steadholme.local",
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
        "alice@steadholme.local",
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
    let rollback_orphan: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM thread_follow_preferences WHERE thread_id = $1")
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

#[tokio::test]
async fn pg_catch_up_migration_backfills_v7_rows_idempotently() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("NOTE: TEST_DATABASE_URL not set — skipping PostgreSQL catch-up migration test");
        return;
    };
    let schema = new_id("agora_catch_migrate");
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
    // Minimal v7 authority: no point table, no clock, and no read_seq column.
    sqlx::query(
        "CREATE TABLE categories (id TEXT PRIMARY KEY, name TEXT NOT NULL, sort_order BIGINT NOT NULL)",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE threads (id TEXT PRIMARY KEY, category_id TEXT NOT NULL, title TEXT NOT NULL, \
         author_sub TEXT NOT NULL, author_email TEXT NOT NULL, created_at BIGINT NOT NULL, \
         last_at BIGINT NOT NULL)",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE posts (id TEXT PRIMARY KEY, thread_id TEXT NOT NULL, body_md TEXT NOT NULL, \
         quoted_post_id TEXT NOT NULL DEFAULT '', author_sub TEXT NOT NULL, author_email TEXT NOT NULL, \
         created_at BIGINT NOT NULL)",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE forum_post_read_receipts (viewer_sub TEXT NOT NULL, post_id TEXT NOT NULL, \
         read_at BIGINT NOT NULL, PRIMARY KEY (viewer_sub, post_id), \
         FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE)",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO categories (id, name, sort_order) VALUES ('support', 'Support', 1)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO threads (id, category_id, title, author_sub, author_email, created_at, last_at) \
         VALUES ('t_legacy', 'support', 'Legacy', 'u_alice', 'alice@example.test', 10, 10)",
    )
    .execute(&pool)
    .await
    .unwrap();
    for post_id in ["p_legacy_a", "p_legacy_b"] {
        sqlx::query(
            "INSERT INTO posts (id, thread_id, body_md, quoted_post_id, author_sub, author_email, created_at) \
             VALUES ($1, 't_legacy', 'legacy', '', 'u_alice', 'alice@example.test', 10)",
        )
        .bind(post_id)
        .execute(&pool)
        .await
        .unwrap();
    }
    sqlx::query(
        "INSERT INTO forum_post_read_receipts (viewer_sub, post_id, read_at) \
         VALUES ('u_reader', 'p_legacy_a', 10)",
    )
    .execute(&pool)
    .await
    .unwrap();

    let store = PgStore::from_pool(pool.clone());
    store.migrate().await.unwrap();
    let first_points = sqlx::query_as::<_, (String, i64)>(
        "SELECT post_id, seq FROM forum_catch_up_post_points ORDER BY seq ASC",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        first_points,
        vec![("p_legacy_a".to_string(), 1), ("p_legacy_b".to_string(), 2)]
    );
    let first_read_seq: i64 = sqlx::query_scalar(
        "SELECT read_seq FROM forum_post_read_receipts \
         WHERE viewer_sub = 'u_reader' AND post_id = 'p_legacy_a'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(first_read_seq, 3);
    let generation = store.catch_up_snapshot_generation().await.unwrap();
    assert_eq!(generation, 3);
    store.migrate().await.unwrap();
    assert_eq!(
        store.catch_up_snapshot_generation().await.unwrap(),
        generation
    );

    // A v7 rollback can still write its historical explicit column lists. The next v8 boot appends
    // exactly one deterministic point/read generation and a second migration is a no-op.
    sqlx::query(
        "INSERT INTO posts (id, thread_id, body_md, quoted_post_id, author_sub, author_email, created_at) \
         VALUES ('p_legacy_c', 't_legacy', 'rollback', '', 'u_bob', 'bob@example.test', 10)",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO forum_post_read_receipts (viewer_sub, post_id, read_at) \
         VALUES ('u_reader', 'p_legacy_c', 10)",
    )
    .execute(&pool)
    .await
    .unwrap();
    store.migrate().await.unwrap();
    let forward_generation = store.catch_up_snapshot_generation().await.unwrap();
    assert_eq!(forward_generation, 5);
    let rollback_point: i64 = sqlx::query_scalar(
        "SELECT seq FROM forum_catch_up_post_points WHERE post_id = 'p_legacy_c'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let rollback_read: i64 = sqlx::query_scalar(
        "SELECT read_seq FROM forum_post_read_receipts \
         WHERE viewer_sub = 'u_reader' AND post_id = 'p_legacy_c'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((rollback_point, rollback_read), (4, 5));
    store.migrate().await.unwrap();
    assert_eq!(
        store.catch_up_snapshot_generation().await.unwrap(),
        forward_generation
    );

    sqlx::query("DELETE FROM posts WHERE thread_id = 't_legacy'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM forum_catch_up_post_points WHERE thread_id = 't_legacy'",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        3,
        "post deletion retains ordering points"
    );
    sqlx::query("DELETE FROM threads WHERE id = 't_legacy'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM forum_catch_up_post_points WHERE thread_id = 't_legacy'",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        0,
        "thread deletion cascades ordering points"
    );
    drop(store);
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn pg_catch_up_is_complete_exact_keyset_and_mute_safe() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("NOTE: TEST_DATABASE_URL not set — skipping PostgreSQL catch-up test");
        return;
    };
    let schema = new_id("agora_catch_up");
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
    let store = PgStore::from_pool(pool.clone());
    store.migrate().await.unwrap();
    store
        .seed_categories_if_empty(&default_categories())
        .await
        .unwrap();

    for index_name in [
        "idx_threads_author_snapshot",
        "idx_posts_author_snapshot",
        "idx_posts_thread_snapshot",
        "idx_forum_post_read_receipts_viewer_snapshot",
        "idx_post_read_receipts_viewer_generation",
        "idx_catch_up_points_thread_snapshot",
        "idx_subscriptions_user_thread",
        "idx_follow_preferences_user",
        "idx_forum_bookmarks_recent",
    ] {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_indexes \
             WHERE schemaname = CURRENT_SCHEMA AND indexname = $1)",
        )
        .bind(index_name)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(exists, "catch-up authority index is missing: {index_name}");
    }

    let now = now_secs();
    let base = now - 20_000;
    let (mut old, old_op) = fixture_thread(
        "pg_catch_old_follow",
        "u_alice",
        "alice@steadholme.local",
        base + 100,
    );
    old.title = "Old PG explicit relationship".to_string();
    store.create_thread(&old, &old_op).await.unwrap();
    store
        .set_thread_follow_level(&old.id, "u_carol", ThreadFollowLevel::Follow, base + 101)
        .await
        .unwrap();
    store
        .mark_thread_posts_read(
            "u_carol",
            &old.id,
            std::slice::from_ref(&old_op.id),
            base + 101,
        )
        .await
        .unwrap();
    let mut first_unread = fixture_reply(
        &old.id,
        "u_bob",
        "bob@steadholme.local",
        "stale first unread",
        "",
        base + 102,
    );
    first_unread.id = "p_pg_catch_first_unread".to_string();
    let mut read_hole = fixture_reply(
        &old.id,
        "u_bob",
        "bob@steadholme.local",
        "read middle reply",
        "",
        base + 103,
    );
    read_hole.id = "p_pg_catch_read_hole".to_string();
    let mut second_unread = fixture_reply(
        &old.id,
        "u_bob",
        "bob@steadholme.local",
        "second unread",
        "",
        base + 104,
    );
    second_unread.id = "p_pg_catch_second_unread".to_string();
    for post in [&first_unread, &read_hole, &second_unread] {
        store.add_reply(post).await.unwrap();
    }
    store
        .mark_thread_posts_read(
            "u_carol",
            &old.id,
            std::slice::from_ref(&read_hole.id),
            base + 105,
        )
        .await
        .unwrap();
    store
        .update_post(
            &first_unread.id,
            "current live PostgreSQL first unread excerpt",
        )
        .await
        .unwrap();

    // The explicit relationship stays complete after 201 unrelated, newer Latest rows.
    for index in 0..201 {
        let (mut noise, op) = fixture_thread(
            &format!("pg_catch_noise_{index:03}"),
            "u_noise",
            "noise@steadholme.local",
            base + 1_000 + index,
        );
        noise.title = format!("PG unrelated noise {index:03}");
        store.create_thread(&noise, &op).await.unwrap();
    }
    let initial_generation = store.catch_up_snapshot_generation().await.unwrap();
    let following = store
        .catch_up_page(
            "u_carol",
            CatchUpView::Following,
            now,
            initial_generation,
            None,
            MAX_CATCH_UP_PAGE + 1,
        )
        .await
        .unwrap();
    assert_eq!(following.len(), 1);
    assert_eq!(following[0].thread.id, old.id);
    assert_eq!(following[0].reason, CatchUpReason::Follow);
    assert_eq!(following[0].follow_level, ThreadFollowLevel::Follow);
    assert_eq!(following[0].unread_count, 2);
    assert_eq!(
        following[0].first_unread.as_ref().unwrap().id,
        first_unread.id
    );
    assert_eq!(
        following[0].first_unread.as_ref().unwrap().body_md,
        "current live PostgreSQL first unread excerpt"
    );
    let updates = store
        .catch_up_page(
            "u_carol",
            CatchUpView::Updates,
            now,
            initial_generation,
            None,
            MAX_CATCH_UP_PAGE + 1,
        )
        .await
        .unwrap();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].thread.id, old.id);

    let (mut waiting, waiting_op) = fixture_thread(
        "pg_catch_waiting",
        "u_carol",
        "carol@steadholme.local",
        base + 300,
    );
    waiting.title = "PG question waiting".to_string();
    store.create_thread(&waiting, &waiting_op).await.unwrap();
    let (mut solved, solved_op) = fixture_thread(
        "pg_catch_solved",
        "u_carol",
        "carol@steadholme.local",
        base + 301,
    );
    solved.title = "PG question solved".to_string();
    store.create_thread(&solved, &solved_op).await.unwrap();
    let solved_answer = fixture_reply(
        &solved.id,
        "u_bob",
        "bob@steadholme.local",
        "accepted answer",
        "",
        base + 302,
    );
    store.add_reply(&solved_answer).await.unwrap();
    store
        .mutate_accepted_answer(
            &solved.id,
            AcceptedAnswerAction::Accept {
                post_id: solved_answer.id.clone(),
            },
        )
        .await
        .unwrap();
    let (mut muted, muted_op) = fixture_thread(
        "pg_catch_muted",
        "u_carol",
        "carol@steadholme.local",
        base + 303,
    );
    muted.title = "PG muted question".to_string();
    store.create_thread(&muted, &muted_op).await.unwrap();
    store
        .set_thread_follow_level(&muted.id, "u_carol", ThreadFollowLevel::Mute, base + 304)
        .await
        .unwrap();
    let muted_direct = fixture_reply(
        &muted.id,
        "u_bob",
        "bob@steadholme.local",
        "direct reply survives mute",
        "",
        base + 305,
    );
    store
        .add_reply_with_activity(&muted_direct, &[], &new_id("a"))
        .await
        .unwrap();
    let question_generation = store.catch_up_snapshot_generation().await.unwrap();
    let questions = store
        .catch_up_page(
            "u_carol",
            CatchUpView::Questions,
            now,
            question_generation,
            None,
            MAX_CATCH_UP_PAGE + 1,
        )
        .await
        .unwrap();
    assert_eq!(questions.len(), 2);
    assert!(questions
        .iter()
        .all(|item| item.reason == CatchUpReason::Authored));
    assert!(questions.iter().all(|item| item.thread.id != muted.id));
    assert_eq!(
        questions
            .iter()
            .find(|item| item.thread.id == waiting.id)
            .unwrap()
            .question_state,
        Some(CatchUpQuestionState::Waiting)
    );
    assert_eq!(
        questions
            .iter()
            .find(|item| item.thread.id == solved.id)
            .unwrap()
            .question_state,
        Some(CatchUpQuestionState::Solved)
    );
    let direct = store
        .activity_page("u_carol", ActivityFilter::All, false, None, 30)
        .await
        .unwrap();
    assert!(direct
        .iter()
        .any(|item| { item.event.thread_id == muted.id && item.reason == ActivityReason::Reply }));

    // Same-second rows use the immutable id tie-break. Mimic the handler's 31-row sentinel,
    // truncate to 30, and continue from its last rendered row.
    let tied_at = base - 100;
    for index in 0..32 {
        let (mut thread, op) = fixture_thread(
            &format!("pg_catch_tie_{index:02}"),
            "u_alice",
            "alice@steadholme.local",
            tied_at,
        );
        thread.title = format!("PG tied relationship {index:02}");
        store.create_thread(&thread, &op).await.unwrap();
        store
            .set_thread_follow_level(
                &thread.id,
                "u_carol",
                ThreadFollowLevel::Follow,
                tied_at + 1,
            )
            .await
            .unwrap();
    }
    let newest_then_deleted = fixture_reply(
        "t_pg_catch_tie_00",
        "u_bob",
        "bob@steadholme.local",
        "latest reply deleted after page one",
        "",
        base + 500,
    );
    store.add_reply(&newest_then_deleted).await.unwrap();
    let page_generation = store.catch_up_snapshot_generation().await.unwrap();
    let mut first_page = store
        .catch_up_page(
            "u_carol",
            CatchUpView::Following,
            now,
            page_generation,
            None,
            MAX_CATCH_UP_PAGE + 1,
        )
        .await
        .unwrap();
    assert_eq!(first_page.len(), 31);
    assert!(first_page.iter().any(|item| item.thread.id == old.id));
    first_page.truncate(MAX_CATCH_UP_PAGE as usize);
    let cursor = CatchUpCursor {
        view: CatchUpView::Following,
        as_of: now,
        snapshot_generation: page_generation,
        activity_at: first_page.last().unwrap().activity_at,
        thread_id: first_page.last().unwrap().thread.id.clone(),
    };
    assert!(first_page
        .iter()
        .any(|item| item.thread.id == "t_pg_catch_tie_00"));
    store.delete_post(&newest_then_deleted.id).await.unwrap();

    // A same-second read committed after page one is excluded by receipt sequence, not wall time.
    store
        .mark_thread_posts_read(
            "u_carol",
            "t_pg_catch_tie_31",
            &["p_pg_catch_tie_31_op".to_string()],
            tied_at,
        )
        .await
        .unwrap();
    let frozen_updates = store
        .catch_up_page(
            "u_carol",
            CatchUpView::Updates,
            now,
            page_generation,
            None,
            MAX_CATCH_UP_PAGE + 1,
        )
        .await
        .unwrap();
    assert_eq!(
        frozen_updates
            .iter()
            .find(|item| item.thread.id == "t_pg_catch_tie_31")
            .unwrap()
            .unread_count,
        1
    );
    let after_read_generation = store.catch_up_snapshot_generation().await.unwrap();
    assert!(!store
        .catch_up_page(
            "u_carol",
            CatchUpView::Updates,
            now,
            after_read_generation,
            None,
            MAX_CATCH_UP_PAGE + 1,
        )
        .await
        .unwrap()
        .iter()
        .any(|item| item.thread.id == "t_pg_catch_tie_31"));

    // A post created in the same wall-clock second after page one is excluded by generation.
    let future_reply = fixture_reply(
        "t_pg_catch_tie_02",
        "u_bob",
        "bob@steadholme.local",
        "after snapshot",
        "",
        tied_at,
    );
    store.add_reply(&future_reply).await.unwrap();
    let second_page = store
        .catch_up_page(
            "u_carol",
            CatchUpView::Following,
            now,
            page_generation,
            Some(&cursor),
            MAX_CATCH_UP_PAGE + 1,
        )
        .await
        .unwrap();
    assert_eq!(
        second_page
            .iter()
            .map(|item| item.thread.id.as_str())
            .collect::<Vec<_>>(),
        vec![
            "t_pg_catch_tie_03",
            "t_pg_catch_tie_02",
            "t_pg_catch_tie_01",
        ]
    );
    let wrong_view = CatchUpCursor {
        view: CatchUpView::Updates,
        ..cursor.clone()
    };
    assert!(matches!(
        store
            .catch_up_page(
                "u_carol",
                CatchUpView::Following,
                now,
                page_generation,
                Some(&wrong_view),
                1,
            )
            .await,
        Err(StoreError::InvalidOperation(_))
    ));
    let wrong_snapshot = CatchUpCursor {
        as_of: now - 1,
        ..cursor
    };
    assert!(matches!(
        store
            .catch_up_page(
                "u_carol",
                CatchUpView::Following,
                now,
                page_generation,
                Some(&wrong_snapshot),
                1,
            )
            .await,
        Err(StoreError::InvalidOperation(_))
    ));

    // Populate selective foreign rows, refresh statistics, and prove the candidate-union branches
    // can use their subject-first indexes instead of reverse-scanning thread-primary keys.
    sqlx::query(
        "INSERT INTO thread_subscriptions (thread_id, subscriber_sub, created_at) \
         SELECT 't_plan_' || n::TEXT, 'u_plan_' || n::TEXT, 1 \
         FROM generate_series(1, 4000) AS n",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO posts \
             (id, thread_id, body_md, quoted_post_id, author_sub, author_email, created_at) \
         SELECT 'p_plan_' || n::TEXT, 't_plan_' || n::TEXT, 'plan', '', \
                'u_plan_' || n::TEXT, 'plan@steadholme.local', 1 \
         FROM generate_series(1, 4000) AS n",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO forum_post_read_receipts (viewer_sub, post_id, read_at) \
         SELECT 'u_plan_' || n::TEXT, 'p_plan_' || n::TEXT, 1 \
         FROM generate_series(1, 4000) AS n",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("ANALYZE thread_subscriptions")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("ANALYZE posts").execute(&pool).await.unwrap();
    sqlx::query("ANALYZE forum_post_read_receipts")
        .execute(&pool)
        .await
        .unwrap();
    for (sql, expected_index) in [
        (
            "EXPLAIN (COSTS OFF) SELECT thread_id FROM thread_subscriptions \
             WHERE subscriber_sub = 'u_carol'",
            "idx_subscriptions_user_thread",
        ),
        (
            "EXPLAIN (COSTS OFF) SELECT thread_id FROM posts \
             WHERE author_sub = 'u_carol' AND created_at <= 9999999999",
            "idx_posts_author_snapshot",
        ),
    ] {
        let plan = sqlx::query_scalar::<_, String>(sql)
            .fetch_all(&pool)
            .await
            .unwrap()
            .join("\n");
        assert!(
            plan.contains(expected_index),
            "expected {expected_index} in PostgreSQL catch-up plan:\n{plan}"
        );
    }
    let receipt_plan = sqlx::query_scalar::<_, String>(
        "EXPLAIN (COSTS OFF) SELECT post_id FROM forum_post_read_receipts \
         WHERE viewer_sub = 'u_carol' AND read_seq <= 9999999999",
    )
    .fetch_all(&pool)
    .await
    .unwrap()
    .join("\n");
    assert!(
        !receipt_plan.contains("Seq Scan")
            && receipt_plan.contains("idx_post_read_receipts_viewer_generation"),
        "receipt authority must use a viewer-first index:\n{receipt_plan}"
    );

    sqlx::query("SET search_path TO public")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn pg_catch_up_clock_orders_commit_before_snapshot() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("NOTE: TEST_DATABASE_URL not set — skipping PostgreSQL catch-up clock test");
        return;
    };
    let schema = new_id("agora_catch_clock");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let connection_schema = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .after_connect(move |connection, _| {
            let set_path = format!("SET search_path TO {connection_schema}");
            Box::pin(async move {
                sqlx::query(&set_path).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    let store = PgStore::from_pool(pool.clone());
    store.migrate().await.unwrap();
    store
        .seed_categories_if_empty(&default_categories())
        .await
        .unwrap();
    let (thread, op) = fixture_thread("catch_clock", "u_alice", "alice@steadholme.local", 10);
    store.create_thread(&thread, &op).await.unwrap();
    assert_eq!(store.catch_up_snapshot_generation().await.unwrap(), 1);

    // Writer A owns generation 2 but deliberately withholds commit.
    let mut writer_a = pool.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO posts (id, thread_id, body_md, quoted_post_id, author_sub, author_email, created_at) \
         VALUES ('p_clock_a', $1, 'A', '', 'u_bob', 'bob@example.test', 10)",
    )
    .bind(&thread.id)
    .execute(&mut *writer_a)
    .await
    .unwrap();
    let generation_a: i64 =
        sqlx::query_scalar("SELECT generation FROM forum_catch_up_clock WHERE id = 1 FOR UPDATE")
            .fetch_one(&mut *writer_a)
            .await
            .unwrap();
    assert_eq!(generation_a, 1);
    sqlx::query("UPDATE forum_catch_up_clock SET generation = 2 WHERE id = 1")
        .execute(&mut *writer_a)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO forum_catch_up_post_points (post_id, thread_id, activity_at, seq) \
         VALUES ('p_clock_a', $1, 10, 2)",
    )
    .bind(&thread.id)
    .execute(&mut *writer_a)
    .await
    .unwrap();

    let (attempting_tx, attempting_rx) = tokio::sync::oneshot::channel();
    let (locked_tx, locked_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let writer_pool = pool.clone();
    let writer_thread = thread.id.clone();
    let writer_b = tokio::spawn(async move {
        let mut tx = writer_pool.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO posts (id, thread_id, body_md, quoted_post_id, author_sub, author_email, created_at) \
             VALUES ('p_clock_b', $1, 'B', '', 'u_carol', 'carol@example.test', 10)",
        )
        .bind(&writer_thread)
        .execute(&mut *tx)
        .await
        .unwrap();
        attempting_tx.send(()).unwrap();
        let current: i64 = sqlx::query_scalar(
            "SELECT generation FROM forum_catch_up_clock WHERE id = 1 FOR UPDATE",
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        let next = current.checked_add(1).unwrap();
        sqlx::query("UPDATE forum_catch_up_clock SET generation = $1 WHERE id = 1")
            .bind(next)
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO forum_catch_up_post_points (post_id, thread_id, activity_at, seq) \
             VALUES ('p_clock_b', $1, 10, $2)",
        )
        .bind(&writer_thread)
        .bind(next)
        .execute(&mut *tx)
        .await
        .unwrap();
        locked_tx.send(next).unwrap();
        release_rx.await.unwrap();
        tx.commit().await.unwrap();
        next
    });
    attempting_rx.await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let snapshot_store = PgStore::from_pool(pool.clone());
    let mut snapshot =
        tokio::spawn(async move { snapshot_store.catch_up_snapshot_generation().await.unwrap() });
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut snapshot)
            .await
            .is_err()
    );

    writer_a.commit().await.unwrap();
    assert_eq!(locked_rx.await.unwrap(), 3);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut snapshot)
            .await
            .is_err()
    );
    release_tx.send(()).unwrap();
    assert_eq!(writer_b.await.unwrap(), 3);
    assert_eq!(snapshot.await.unwrap(), 3);
    let points = sqlx::query_as::<_, (String, i64)>(
        "SELECT post_id, seq FROM forum_catch_up_post_points \
         WHERE post_id IN ('p_clock_a', 'p_clock_b') ORDER BY seq",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        points,
        vec![("p_clock_a".to_string(), 2), ("p_clock_b".to_string(), 3)]
    );
    sqlx::query("UPDATE forum_catch_up_clock SET generation = 9223372036854775807 WHERE id = 1")
        .execute(&pool)
        .await
        .unwrap();
    let mut overflow_reply = fixture_reply(
        &thread.id,
        "u_dave",
        "dave@example.test",
        "must roll back",
        "",
        10,
    );
    overflow_reply.id = "p_clock_overflow".to_string();
    assert!(matches!(
        store.add_reply(&overflow_reply).await,
        Err(StoreError::InvalidOperation(_))
    ));
    assert!(store.get_post(&overflow_reply.id).await.unwrap().is_none());

    drop(store);
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
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
        "historical@steadholme.local",
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

    let (thread, op) = fixture_thread("pg_activity", "u_alice", "alice@steadholme.local", now);
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
        "bob@steadholme.local",
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
        "bob@steadholme.local",
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
            "bob@steadholme.local",
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
        "bob@steadholme.local",
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
        fixture_thread("pg_alias", "u_bob", "bob@steadholme.local", now + 400);
    store
        .create_thread_with_activity(&alias_thread, &alias_op, &[], &new_id("a"))
        .await
        .unwrap();
    let rename = fixture_reply(
        &alias_thread.id,
        "u_alice",
        "alice-renamed@steadholme.local",
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
        "bob@steadholme.local",
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
        "bob@steadholme.local",
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
        fixture_thread("pg_cap", "u_alice", "alice@steadholme.local", now + 500);
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
        "bob@steadholme.local",
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
        "bob@steadholme.local",
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
        "bob@steadholme.local",
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
        "alice@steadholme.local",
        now + 600,
    );
    store
        .create_thread_with_activity(&post_delete_thread, &post_delete_op, &[], &new_id("a"))
        .await
        .unwrap();
    let post_delete_reply = fixture_reply(
        &post_delete_thread.id,
        "u_bob",
        "bob@steadholme.local",
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
        "alice@steadholme.local",
        now + 700,
    );
    store
        .create_thread_with_activity(&thread_delete_thread, &thread_delete_op, &[], &new_id("a"))
        .await
        .unwrap();
    let thread_delete_reply = fixture_reply(
        &thread_delete_thread.id,
        "u_bob",
        "bob@steadholme.local",
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
