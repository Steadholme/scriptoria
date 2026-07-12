//! Real PostgreSQL parity and quota coverage for private Category Focus rules.
//!
//! Skips unless `TEST_DATABASE_URL` is set, matching the other durable-store tests.

use std::sync::Arc;
use std::time::Duration;

use agora::model::{Category, CategoryFocusLevel, CategoryFormat, Post, Thread, ThreadFollowLevel};
use agora::new_id;
use agora::store::{
    CategoryFocusReason, PgStore, Store, MAX_CATEGORY_FOCUS_PAGE, MAX_CATEGORY_FOCUS_RULES,
};
use sqlx::postgres::PgPoolOptions;

const VIEWER: &str = "u_pg_focus_viewer";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg_focus_migrates_matches_memory_and_serializes_the_exact_cap() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("NOTE: TEST_DATABASE_URL not set — skipping PostgreSQL Category Focus test");
        return;
    };
    let schema = new_id("agora_category_focus");
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
    let store = Arc::new(PgStore::from_pool(pool.clone()));
    store.migrate().await.unwrap();
    store.migrate().await.expect("migration is idempotent");

    let index_exists: bool =
        sqlx::query_scalar("SELECT to_regclass('idx_category_focus_subject_level') IS NOT NULL")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(index_exists, "owner/level lookup has a durable index");
    let delete_rule: String = sqlx::query_scalar(
        "SELECT delete_rule FROM information_schema.referential_constraints \
         WHERE constraint_schema = $1 \
           AND constraint_name = 'fk_forum_category_focus_category'",
    )
    .bind(&schema)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        delete_rule, "CASCADE",
        "legacy category deletion cleans v9 rules"
    );

    for (id, name) in [
        ("pg-focus-priority", "PG Priority"),
        ("pg-focus-follow", "PG Follow"),
        ("pg-focus-muted", "PG Muted"),
        ("pg-focus-delete", "PG Delete"),
    ] {
        create_category(store.as_ref(), id, name).await;
    }
    assert!(
        sqlx::query(
            "INSERT INTO forum_category_focus_rules \
             (viewer_sub, category_id, level, created_at, updated_at) \
         VALUES ('u_invalid', 'pg-focus-priority', 'surprise', 1, 1)",
        )
        .execute(&pool)
        .await
        .is_err(),
        "the migration constrains category intent values"
    );

    seed_thread(
        store.as_ref(),
        "t_pg_focus_priority",
        "PG priority first",
        "pg-focus-priority",
        10,
        false,
    )
    .await;
    seed_thread(
        store.as_ref(),
        "t_pg_focus_priority_muted",
        "PG thread mute wins",
        "pg-focus-priority",
        500,
        true,
    )
    .await;
    seed_thread(
        store.as_ref(),
        "t_pg_focus_follow",
        "PG follow second",
        "pg-focus-follow",
        400,
        false,
    )
    .await;
    seed_thread(
        store.as_ref(),
        "t_pg_focus_watch_override",
        "PG Watch overrides mute",
        "pg-focus-muted",
        300,
        false,
    )
    .await;
    seed_thread(
        store.as_ref(),
        "t_pg_focus_follow_override",
        "PG Follow overrides mute",
        "pg-focus-muted",
        200,
        false,
    )
    .await;
    seed_thread(
        store.as_ref(),
        "t_pg_focus_muted_plain",
        "PG broad mute excludes",
        "pg-focus-muted",
        600,
        false,
    )
    .await;
    store
        .set_category_focus_level(
            VIEWER,
            "pg-focus-priority",
            CategoryFocusLevel::Priority,
            700,
        )
        .await
        .unwrap();
    store
        .set_category_focus_level(VIEWER, "pg-focus-follow", CategoryFocusLevel::Follow, 701)
        .await
        .unwrap();
    store
        .set_category_focus_level(VIEWER, "pg-focus-muted", CategoryFocusLevel::Mute, 702)
        .await
        .unwrap();
    let stored_rules = store.category_focus_rules(VIEWER).await.unwrap();
    assert_eq!(stored_rules.len(), 3);
    assert!(stored_rules.iter().any(|rule| {
        rule.category.id == "pg-focus-muted" && rule.level == CategoryFocusLevel::Mute
    }));
    store
        .set_thread_follow_level(
            "t_pg_focus_priority_muted",
            VIEWER,
            ThreadFollowLevel::Mute,
            703,
        )
        .await
        .unwrap();
    store
        .set_thread_follow_level(
            "t_pg_focus_watch_override",
            VIEWER,
            ThreadFollowLevel::Watch,
            704,
        )
        .await
        .unwrap();
    store
        .set_thread_follow_level(
            "t_pg_focus_follow_override",
            VIEWER,
            ThreadFollowLevel::Follow,
            705,
        )
        .await
        .unwrap();

    // Simulate an image-only v6 rollback recreating legacy Watch while the newer Mute row still
    // exists. Forward migrate must make thread Mute authoritative again and remove only generic
    // Following delivery, preserving a direct reply path for the same event.
    sqlx::query(
        "INSERT INTO thread_subscriptions (thread_id, subscriber_sub, created_at) \
         VALUES ('t_pg_focus_priority_muted', $1, 706)",
    )
    .bind(VIEWER)
    .execute(&pool)
    .await
    .unwrap();
    let muted_post_id: String = sqlx::query_scalar(
        "SELECT first_post_id FROM threads WHERE id = 't_pg_focus_priority_muted'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO forum_activity_events \
             (id, kind, thread_id, post_id, actor_sub, created_at) \
         VALUES ('a_pg_focus_rollback', 'post_created', \
                 't_pg_focus_priority_muted', $1, 'u_actor', 706)",
    )
    .bind(&muted_post_id)
    .execute(&pool)
    .await
    .unwrap();
    for reason in ["following", "reply"] {
        sqlx::query(
            "INSERT INTO forum_activity_deliveries \
                 (activity_id, recipient_kind, recipient_key, reason) \
             VALUES ('a_pg_focus_rollback', 'subject', $1, $2)",
        )
        .bind(VIEWER)
        .bind(reason)
        .execute(&pool)
        .await
        .unwrap();
    }
    store.migrate().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM thread_subscriptions \
             WHERE thread_id = 't_pg_focus_priority_muted' AND subscriber_sub = $1",
        )
        .bind(VIEWER)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0,
        "forward migrate removes a rollback Watch shadowed by thread Mute"
    );
    assert_eq!(
        store
            .thread_follow_level("t_pg_focus_priority_muted", VIEWER)
            .await
            .unwrap(),
        ThreadFollowLevel::Mute
    );
    let rollback_reasons: Vec<String> = sqlx::query_scalar(
        "SELECT reason FROM forum_activity_deliveries \
         WHERE activity_id = 'a_pg_focus_rollback' ORDER BY reason",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rollback_reasons, vec!["reply"]);
    let page = store
        .category_focus_page(VIEWER, MAX_CATEGORY_FOCUS_PAGE, 1_000)
        .await
        .unwrap();
    assert_eq!(
        page.iter()
            .map(|item| item.thread.id.as_str())
            .collect::<Vec<_>>(),
        vec![
            "t_pg_focus_priority",
            "t_pg_focus_follow",
            "t_pg_focus_watch_override",
            "t_pg_focus_follow_override",
        ]
    );
    assert_eq!(page[0].reason, CategoryFocusReason::CategoryPriority);
    assert_eq!(page[1].reason, CategoryFocusReason::CategoryFollow);
    assert_eq!(page[2].reason, CategoryFocusReason::ThreadWatchOverride);
    assert_eq!(page[3].reason, CategoryFocusReason::ThreadFollowOverride);
    let activity_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM forum_activity_events WHERE id <> 'a_pg_focus_rollback'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        activity_rows, 0,
        "category intent creates no Activity events"
    );

    store
        .set_category_focus_level(VIEWER, "pg-focus-delete", CategoryFocusLevel::Follow, 706)
        .await
        .unwrap();
    store.delete_category("pg-focus-delete").await.unwrap();
    let deleted_rules: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM forum_category_focus_rules WHERE category_id = 'pg-focus-delete'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(deleted_rules, 0);

    let cap_viewer = "u_pg_focus_cap";
    for index in 0..=MAX_CATEGORY_FOCUS_RULES {
        let id = format!("pg-focus-cap-{index:02}");
        create_category(store.as_ref(), &id, &format!("PG Focus cap {index:02}")).await;
    }
    for index in 0..MAX_CATEGORY_FOCUS_RULES - 1 {
        let id = format!("pg-focus-cap-{index:02}");
        store
            .set_category_focus_level(cap_viewer, &id, CategoryFocusLevel::Follow, index as i64)
            .await
            .unwrap();
    }
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let mut tasks = Vec::new();
    for index in [MAX_CATEGORY_FOCUS_RULES - 1, MAX_CATEGORY_FOCUS_RULES] {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            let id = format!("pg-focus-cap-{index:02}");
            barrier.wait().await;
            store
                .set_category_focus_level(
                    cap_viewer,
                    &id,
                    CategoryFocusLevel::Priority,
                    1_000 + index as i64,
                )
                .await
        }));
    }
    barrier.wait().await;
    let results = tokio::time::timeout(Duration::from_secs(10), async {
        let first = tasks.remove(0).await.unwrap();
        let second = tasks.remove(0).await.unwrap();
        [first, second]
    })
    .await
    .expect("concurrent quota writers must not deadlock");
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
    let cap_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM forum_category_focus_rules WHERE viewer_sub = $1")
            .bind(cap_viewer)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(cap_count, MAX_CATEGORY_FOCUS_RULES as i64);
    store
        .set_category_focus_level(
            cap_viewer,
            "pg-focus-cap-00",
            CategoryFocusLevel::Follow,
            2_000,
        )
        .await
        .expect("idempotent desired state succeeds at the exact cap");

    drop(store);
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
}

async fn create_category(store: &PgStore, id: &str, name: &str) {
    store
        .create_category(&Category {
            id: id.to_string(),
            name: name.to_string(),
            sort_order: 100,
            format: CategoryFormat::Discussion,
        })
        .await
        .unwrap();
}

async fn seed_thread(
    store: &PgStore,
    id: &str,
    title: &str,
    category_id: &str,
    created_at: i64,
    pinned: bool,
) {
    let thread = Thread {
        id: id.to_string(),
        category_id: category_id.to_string(),
        title: title.to_string(),
        author_sub: "u_pg_focus_author".to_string(),
        author_email: "author@holdfast.local".to_string(),
        created_at,
        last_at: created_at,
        locked: false,
        pinned,
        accepted_post_id: String::new(),
    };
    let post = Post {
        id: format!("p_{id}_op"),
        thread_id: id.to_string(),
        body_md: "Original post".to_string(),
        quoted_post_id: String::new(),
        author_sub: thread.author_sub.clone(),
        author_email: thread.author_email.clone(),
        created_at,
    };
    store.create_thread(&thread, &post).await.unwrap();
}
