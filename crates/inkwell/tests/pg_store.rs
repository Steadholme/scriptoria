//! PostgreSQL `Store` integration test.
//!
//! Runs ONLY when `TEST_DATABASE_URL` is set (it needs an external Postgres). When unset the
//! test prints a note and returns early — it never fails the default `cargo test` run, which
//! stays database-free. Spin up a throwaway Postgres and run:
//!
//! ```text
//! docker run --rm -d -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=inkwell \
//!   -p 127.0.0.1:55460:5432 postgres:18-alpine
//! TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55460/inkwell \
//!   cargo test --test pg_store -- --nocapture
//! ```
//!
//! The `Store` trait is async: each method `.await`s sqlx natively (no `block_in_place`), so
//! it runs on any Tokio scheduler — this test stays on `multi_thread` for parallel queries.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use inkwell::store::{PgStore, Post, Store};
use inkwell::{app, build_dev_state, now_secs, AppState};
use tower::ServiceExt;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg_store_full_integration() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!(
            "NOTE: TEST_DATABASE_URL not set — skipping Postgres integration test \
             (needs external Postgres). This is expected for the default test run."
        );
        return;
    };

    // --- connect / migrate (idempotent: run twice) -------------------------
    let pg = PgStore::connect(&url).await.expect("connect TEST_DATABASE_URL");
    pg.migrate().await.expect("migrate");
    pg.migrate().await.expect("migrate is idempotent");
    let pg = Arc::new(pg);

    // --- direct Store-trait round-trip -------------------------------------
    let now = now_secs();
    let post = Post {
        id: "post_pg_1".to_string(),
        slug: "pg-hello".to_string(),
        title: "PG Hello".to_string(),
        body_md: "# Hi\n\nFrom **postgres**.".to_string(),
        author_sub: "u_alice".to_string(),
        author_email: "alice@holdfast.local".to_string(),
        created_at: now - 100,
        updated_at: now - 100,
        published: true,
    };
    pg.create_post(&post).await.expect("create");

    // Duplicate slug -> Conflict (the UNIQUE(slug) guard).
    let dup = Post {
        id: "post_pg_dup".to_string(),
        ..post.clone()
    };
    assert!(
        matches!(pg.create_post(&dup).await, Err(inkwell::store::StoreError::Conflict(_))),
        "duplicate slug rejected"
    );

    // A second, newer post — list ordering is newest-first.
    let post2 = Post {
        id: "post_pg_2".to_string(),
        slug: "pg-second".to_string(),
        title: "PG Second".to_string(),
        body_md: "later".to_string(),
        author_sub: "u_alice".to_string(),
        author_email: "alice@holdfast.local".to_string(),
        created_at: now,
        updated_at: now,
        published: true,
    };
    pg.create_post(&post2).await.expect("create 2");

    let listed = pg.list_posts(None, inkwell::config::MAX_PAGE).await;
    assert!(listed.len() >= 2);
    assert_eq!(listed[0].slug, "pg-second", "newest first");

    // Keyset "before" cursor pages strictly OLDER than the newest row (created_at DESC, id DESC).
    let cursor = (listed[0].created_at, listed[0].id.clone());
    let older = pg.list_posts(Some(cursor), inkwell::config::MAX_PAGE).await;
    assert!(
        older.iter().all(|p| p.slug != "pg-second"),
        "newest row excluded by the before cursor"
    );
    assert!(older.iter().any(|p| p.slug == "pg-hello"), "older row still reachable");

    // Fetch + update (slug stays stable) + verify.
    let fetched = pg.get_post("pg-hello").await.expect("fetch");
    assert_eq!(fetched.title, "PG Hello");
    let mut edited = fetched.clone();
    edited.title = "PG Hello (edited)".to_string();
    edited.published = false;
    edited.updated_at = now;
    pg.update_post(&edited).await.expect("update");
    let after = pg.get_post("pg-hello").await.expect("refetch");
    assert_eq!(after.title, "PG Hello (edited)");
    assert!(!after.published);

    // --- full HTTP flow through the PG-backed app --------------------------
    let mut state: AppState = build_dev_state();
    state.store = pg.clone();

    // Create through the SSO+CSRF authoring path.
    let body = "title=Via+HTTP&body=hello+%23world&published=on&csrf_token=tok";
    let resp = app(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/new")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, "__Host-csrf=tok")
                .header("x-auth-subject", "u_bob")
                .header("x-auth-email", "bob@holdfast.local")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    assert_eq!(location, "/p/via-http");

    // Read it back through the PG-backed reading view.
    let (status, html) = raw_call(&state, get("/p/via-http")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&html).contains("Via HTTP"));

    // Delete via the SSO path (correct owner).
    let (status, _) = raw_call(
        &state,
        Request::builder()
            .method("POST")
            .uri("/delete/via-http")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, "__Host-csrf=tok")
            .header("x-auth-subject", "u_bob")
            .header("x-auth-email", "bob@holdfast.local")
            .body(Body::from("csrf_token=tok"))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(pg.get_post("via-http").await.is_none(), "deleted in pg");

    // --- chunk index round-trip (the "ask your blog" store path) -----------
    use inkwell::store::Chunk;
    let now2 = now_secs();
    pg.replace_all_chunks(vec![
        Chunk { id: "pg-hello__0000".into(), post_id: "pg-hello".into(), title: "PG Hello".into(), body: "alpha gateway beta".into(), indexed_at: now2 },
        Chunk { id: "pg-second__0000".into(), post_id: "pg-second".into(), title: "PG Second".into(), body: "gamma delta".into(), indexed_at: now2 },
    ])
    .await
    .expect("replace_all_chunks");
    assert_eq!(pg.count_chunks().await, 2, "full index built");

    // Per-post reindex replaces only that post's chunks.
    pg.replace_post_chunks(
        "pg-hello",
        vec![Chunk { id: "pg-hello__0000".into(), post_id: "pg-hello".into(), title: "PG Hello".into(), body: "alpha gateway beta epsilon".into(), indexed_at: now2 }],
    )
    .await
    .expect("replace_post_chunks");
    assert_eq!(pg.count_chunks().await, 2, "per-post reindex keeps the other post");
    let fetched = pg.fetch_chunks().await;
    assert!(fetched.iter().any(|c| c.post_id == "pg-hello" && c.body.contains("epsilon")), "chunk updated");

    // De-index one post (the delete path).
    pg.delete_post_chunks("pg-second").await.expect("delete_post_chunks");
    assert_eq!(pg.count_chunks().await, 1, "one post de-indexed");

    println!(
        "PG STORE INTEGRATION OK: migrate (idempotent) + create/conflict/list/get/update/delete \
         round-trip + full new/read/delete HTTP flow against real Postgres"
    );
}

async fn raw_call(state: &AppState, req: Request<Body>) -> (StatusCode, Vec<u8>) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, bytes)
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}
