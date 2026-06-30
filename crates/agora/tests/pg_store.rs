//! PostgreSQL `Store` integration test.
//!
//! Runs ONLY when `TEST_DATABASE_URL` is set (it needs an external Postgres). When unset the
//! test prints a note and returns early — it never fails the default `cargo test` run, which
//! stays database-free. Spin up a throwaway Postgres and run:
//!
//! ```text
//! docker run --rm -d --name agora-testpg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=agora \
//!   -p 127.0.0.1:55461:5432 postgres:18-alpine
//! TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55461/agora \
//!   cargo test --test pg_store -- --nocapture
//! docker rm -f agora-testpg
//! ```
//!
//! Uses a multi-threaded runtime (matching production); the `Store` trait is async, so the
//! handlers `.await` sqlx natively with no sync-over-async bridge.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

use agora::store::{PgStore, Store};
use agora::{app, build_dev_state, default_categories, new_id, now_secs, AppState};
use agora::model::{Post, Thread};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg_store_full_integration() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!(
            "NOTE: TEST_DATABASE_URL not set — skipping Postgres integration test (needs external \
             Postgres). This is expected for the default test run."
        );
        return;
    };

    // --- connect / migrate (idempotent: run twice) -------------------------
    let pg = PgStore::connect(&url).await.expect("connect to TEST_DATABASE_URL");
    pg.migrate().await.expect("migrate");
    pg.migrate().await.expect("migrate is idempotent");

    // Clean slate on a shared raw pool, then seed defaults (idempotent).
    let raw = PgPoolOptions::new().max_connections(2).connect(&url).await.unwrap();
    for tbl in ["posts", "threads", "categories"] {
        sqlx::query(&format!("DELETE FROM {tbl}")).execute(&raw).await.unwrap();
    }
    pg.seed_categories_if_empty(&default_categories()).await.expect("seed");
    pg.seed_categories_if_empty(&default_categories()).await.expect("seed is idempotent");

    let cats = pg.list_categories().await.expect("list categories");
    assert_eq!(cats.len(), 3, "three default categories seeded");

    // --- direct store: create a thread + first post, then reply ------------
    let now = now_secs();
    let thread = Thread {
        id: new_id("t"),
        category_id: "general".to_string(),
        title: "Postgres-backed thread".to_string(),
        author_sub: "u_1".to_string(),
        author_email: "alice@holdfast.local".to_string(),
        created_at: now,
        last_at: now,
    };
    let first = Post {
        id: new_id("p"),
        thread_id: thread.id.clone(),
        body_md: "Original **post**.".to_string(),
        author_sub: "u_1".to_string(),
        author_email: "alice@holdfast.local".to_string(),
        created_at: now,
    };
    pg.create_thread(&thread, &first).await.expect("create thread");

    assert_eq!(pg.count_threads("general").await.unwrap(), 1);
    assert_eq!(pg.count_posts(&thread.id).await.unwrap(), 1);

    let reply = Post {
        id: new_id("p"),
        thread_id: thread.id.clone(),
        body_md: "A reply.".to_string(),
        author_sub: "u_2".to_string(),
        author_email: "bob@holdfast.local".to_string(),
        created_at: now + 5,
    };
    pg.add_reply(&reply).await.expect("add reply");

    assert_eq!(pg.count_posts(&thread.id).await.unwrap(), 2);
    let posts = pg.posts_in_thread(&thread.id).await.unwrap();
    assert_eq!(posts.len(), 2);
    assert_eq!(posts[0].id, first.id, "oldest first (original post)");
    assert_eq!(posts[1].id, reply.id);

    // add_reply bumped the thread's last_at.
    let reloaded = pg.get_thread(&thread.id).await.unwrap().unwrap();
    assert_eq!(reloaded.last_at, now + 5, "last_at bumped to reply time");

    // recent_threads orders by last_at DESC.
    let recent = pg.recent_threads(10).await.unwrap();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].id, thread.id);

    // --- end-to-end through the HTTP layer with the PG store ---------------
    let mut state: AppState = build_dev_state().await;
    state.store = Arc::new(PgStore::from_pool(raw.clone()));

    // Thread page renders the persisted posts (markdown rendered).
    let req = Request::builder()
        .uri(format!("/t/{}", thread.id))
        .header("x-auth-email", "viewer@holdfast.local")
        .body(Body::empty())
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = String::from_utf8(
        axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec(),
    )
    .unwrap();
    assert!(html.contains("Postgres-backed thread"));
    assert!(html.contains("<strong>post</strong>"));
    assert!(html.contains("1 reply"));

    // Create a thread through the HTTP POST path (CSRF + identity) against Postgres.
    let tok = "csrftoken123";
    let body = "csrf=csrftoken123&category=support&title=Via%20HTTP&body=Hello%20%2A%2Aworld%2A%2A";
    let req = Request::builder()
        .method("POST")
        .uri("/new")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={tok}"))
        .header("x-auth-subject", "u_9")
        .header("x-auth-email", "carol@holdfast.local")
        .body(Body::from(body))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(pg.count_threads("support").await.unwrap(), 1, "HTTP create persisted to PG");

    // Cleanup the throwaway tables.
    for tbl in ["posts", "threads", "categories"] {
        sqlx::query(&format!("DELETE FROM {tbl}")).execute(&raw).await.unwrap();
    }
    println!(
        "PG STORE INTEGRATION OK: migrate (idempotent) + seed (idempotent) + create_thread + \
         add_reply (last_at bump) + ordering + HTTP create/render against Postgres"
    );
}
