//! PostgreSQL coverage for the Forum search read model.
//!
//! Set `TEST_DATABASE_URL` to run against a disposable database. The default suite remains
//! database-free and returns early when that variable is absent.

use agora::model::{Post, Thread};
use agora::store::{PgStore, Store};
use agora::{new_id, now_secs};
use sqlx::postgres::PgPoolOptions;

static PG_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg_search_matches_title_and_original_body_with_literal_like_text() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("NOTE: TEST_DATABASE_URL not set — skipping PostgreSQL search integration");
        return;
    };
    let _guard = PG_TEST_LOCK.lock().await;
    let pg = PgStore::connect(&url).await.expect("connect test Postgres");
    pg.migrate().await.expect("migrate test Postgres");

    let now = now_secs();
    let marker = new_id("search");
    let needle = format!("literal-%_!-{marker}");
    let thread = Thread {
        id: new_id("t"),
        category_id: "general".to_string(),
        title: format!("Postgres discovery {marker}"),
        author_sub: "u_pg_search".to_string(),
        author_email: "pg-search@holdfast.local".to_string(),
        created_at: now,
        last_at: now,
        locked: false,
        pinned: false,
        accepted_post_id: String::new(),
    };
    let original = Post {
        // Deliberately sorts AFTER the same-second reply id. Stable first_post_id, not
        // `(created_at,id)`, must keep this post as OP.
        id: format!("p_z_original_{marker}"),
        thread_id: thread.id.clone(),
        body_md: format!("Original post contains {needle}"),
        quoted_post_id: String::new(),
        author_sub: thread.author_sub.clone(),
        author_email: thread.author_email.clone(),
        created_at: now,
    };
    pg.create_thread(&thread, &original)
        .await
        .expect("create search fixture");
    let reply = Post {
        id: format!("p_a_reply_{marker}"),
        thread_id: thread.id.clone(),
        body_md: "One reply".to_string(),
        quoted_post_id: String::new(),
        author_sub: "u_pg_reply".to_string(),
        author_email: "reply@holdfast.local".to_string(),
        created_at: now,
    };
    pg.add_reply(&reply)
        .await
        .expect("add search fixture reply");
    pg.set_accepted_post(&thread.id, &reply.id)
        .await
        .expect("mark accepted fixture reply");

    let hits = pg
        .search_threads(&needle, Some("general"), 10)
        .await
        .expect("search original post");
    let hit = hits
        .iter()
        .find(|hit| hit.thread.id == thread.id)
        .expect("fixture found by literal OP body");
    assert_eq!(hit.reply_count, 1);
    assert_eq!(hit.thread.accepted_post_id, reply.id);
    assert_eq!(hit.thread.last_at, now);
    assert_eq!(
        pg.first_post_in_thread(&thread.id)
            .await
            .unwrap()
            .unwrap()
            .id,
        original.id,
        "same-second lexicographically earlier reply never becomes OP"
    );
    assert!(
        pg.search_threads(&needle, Some("support"), 10)
            .await
            .unwrap()
            .iter()
            .all(|hit| hit.thread.id != thread.id),
        "category filter excludes the fixture"
    );
    assert!(
        pg.search_threads(&marker, None, 0)
            .await
            .unwrap()
            .is_empty(),
        "zero store limit is empty"
    );

    let error = pg
        .delete_post(&original.id)
        .await
        .expect_err("PostgreSQL store rejects deleting the OP alone");
    assert!(error.to_string().contains("delete the thread"));
    assert!(
        pg.search_threads(&needle, None, 10)
            .await
            .unwrap()
            .iter()
            .any(|hit| hit.thread.id == thread.id),
        "rejected OP deletion leaves its authoritative search text intact"
    );

    pg.delete_post(&reply.id)
        .await
        .expect("delete a non-OP reply");
    let after_reply_delete = pg
        .search_threads(&needle, None, 10)
        .await
        .unwrap()
        .into_iter()
        .find(|hit| hit.thread.id == thread.id)
        .expect("OP body remains searchable after reply delete");
    assert_eq!(after_reply_delete.first_body_md, original.body_md);
    assert_eq!(after_reply_delete.reply_count, 0);
    assert!(after_reply_delete.thread.accepted_post_id.is_empty());
    assert_eq!(after_reply_delete.thread.last_at, now);

    pg.delete_thread(&thread.id)
        .await
        .expect("remove search fixture");
    assert!(
        pg.search_threads(&needle, None, 10)
            .await
            .unwrap()
            .iter()
            .all(|hit| hit.thread.id != thread.id),
        "Delete thread removes OP text from PostgreSQL search"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg_migrate_backfills_legacy_original_body_without_overwriting_current_content() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("NOTE: TEST_DATABASE_URL not set — skipping PostgreSQL legacy backfill");
        return;
    };
    let _guard = PG_TEST_LOCK.lock().await;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect test Postgres");
    let pg = PgStore::from_pool(pool.clone());
    pg.migrate().await.expect("prepare current schema");

    let now = now_secs();
    let marker = new_id("legacy_search");
    let legacy_thread_id = new_id("t");
    let preserved_thread_id = new_id("t");
    let legacy_op_id = new_id("p");
    let legacy_reply_id = new_id("p");
    let preserved_op_id = new_id("p");
    let legacy_needle = format!("legacy-body-{marker}");
    let preserved_body = format!("already-indexed-{marker}");

    sqlx::query(
        "INSERT INTO threads \
         (id, category_id, title, author_sub, author_email, created_at, last_at, first_body_md, locked, pinned, accepted_post_id) \
         VALUES ($1, 'general', $2, 'u_legacy', 'legacy@holdfast.local', $3, $3, '', FALSE, FALSE, '')",
    )
    .bind(&legacy_thread_id)
    .bind(format!("Legacy search fixture {marker}"))
    .bind(now)
    .execute(&pool)
    .await
    .expect("insert legacy thread");
    sqlx::query(
        "INSERT INTO posts \
         (id, thread_id, body_md, quoted_post_id, author_sub, author_email, created_at) \
         VALUES ($1, $2, $3, '', 'u_legacy', 'legacy@holdfast.local', $4)",
    )
    .bind(&legacy_op_id)
    .bind(&legacy_thread_id)
    .bind(format!("Earliest original contains {legacy_needle}"))
    .bind(now - 10)
    .execute(&pool)
    .await
    .expect("insert legacy original post");
    sqlx::query(
        "INSERT INTO posts \
         (id, thread_id, body_md, quoted_post_id, author_sub, author_email, created_at) \
         VALUES ($1, $2, $3, '', 'u_reply', 'reply@holdfast.local', $4)",
    )
    .bind(&legacy_reply_id)
    .bind(&legacy_thread_id)
    .bind(format!("Later reply {marker}"))
    .bind(now - 5)
    .execute(&pool)
    .await
    .expect("insert later legacy reply");

    sqlx::query(
        "INSERT INTO threads \
         (id, category_id, title, author_sub, author_email, created_at, last_at, first_body_md, locked, pinned, accepted_post_id) \
         VALUES ($1, 'general', $2, 'u_current', 'current@holdfast.local', $3, $3, $4, FALSE, FALSE, '')",
    )
    .bind(&preserved_thread_id)
    .bind(format!("Current search fixture {marker}"))
    .bind(now)
    .bind(&preserved_body)
    .execute(&pool)
    .await
    .expect("insert thread with current denormalised body");
    sqlx::query(
        "INSERT INTO posts \
         (id, thread_id, body_md, quoted_post_id, author_sub, author_email, created_at) \
         VALUES ($1, $2, $3, '', 'u_current', 'current@holdfast.local', $4)",
    )
    .bind(&preserved_op_id)
    .bind(&preserved_thread_id)
    .bind(format!(
        "Source post must not replace current value {marker}"
    ))
    .bind(now)
    .execute(&pool)
    .await
    .expect("insert current original post");

    pg.migrate().await.expect("backfill legacy rows");
    pg.migrate().await.expect("legacy backfill is idempotent");

    let legacy_body: String = sqlx::query_scalar("SELECT first_body_md FROM threads WHERE id = $1")
        .bind(&legacy_thread_id)
        .fetch_one(&pool)
        .await
        .expect("read backfilled body");
    assert_eq!(
        legacy_body,
        format!("Earliest original contains {legacy_needle}")
    );
    let current_body: String =
        sqlx::query_scalar("SELECT first_body_md FROM threads WHERE id = $1")
            .bind(&preserved_thread_id)
            .fetch_one(&pool)
            .await
            .expect("read preserved body");
    assert_eq!(
        current_body, preserved_body,
        "non-empty values are preserved"
    );
    let identities: Vec<(String, String)> = sqlx::query_as(
        "SELECT id, first_post_id FROM threads WHERE id = $1 OR id = $2 ORDER BY id",
    )
    .bind(&legacy_thread_id)
    .bind(&preserved_thread_id)
    .fetch_all(&pool)
    .await
    .expect("read stable OP identities");
    for (thread_id, first_post_id) in identities {
        let expected = if thread_id == legacy_thread_id {
            &legacy_op_id
        } else {
            &preserved_op_id
        };
        assert_eq!(&first_post_id, expected, "migration backfills stable OP id");
    }
    assert!(
        pg.search_threads(&legacy_needle, None, 10)
            .await
            .expect("search backfilled original body")
            .iter()
            .any(|hit| hit.thread.id == legacy_thread_id),
        "backfilled legacy body participates in search"
    );

    sqlx::query("DELETE FROM posts WHERE thread_id = $1 OR thread_id = $2")
        .bind(&legacy_thread_id)
        .bind(&preserved_thread_id)
        .execute(&pool)
        .await
        .expect("remove backfill fixture posts");
    sqlx::query("DELETE FROM threads WHERE id = $1 OR id = $2")
        .bind(&legacy_thread_id)
        .bind(&preserved_thread_id)
        .execute(&pool)
        .await
        .expect("remove backfill fixture threads");
}
