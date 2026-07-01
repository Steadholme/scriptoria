//! PostgreSQL `Store` integration test.
//!
//! Runs ONLY when `TEST_DATABASE_URL` is set (it needs an external Postgres). When unset the test
//! prints a note and returns early — it never fails the default `cargo test` run, which stays
//! database-free. Spin up a throwaway Postgres and run:
//!
//! ```text
//! docker run --rm -d --name ap-testpg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=aperture \
//!   -p 127.0.0.1:55490:5432 postgres:18-alpine
//! TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55490/aperture \
//!   cargo test --test pg_store -- --nocapture
//! docker rm -f ap-testpg
//! ```
//!
//! Uses a multi-threaded runtime (matching production); the `Store` trait is async, so the
//! handlers `.await` sqlx natively with no sync-over-async bridge. The blob store stays in-memory
//! here (Cairn is exercised at deploy), so this validates ONLY the portable SQL metadata path.

use std::sync::Arc;

use aperture::blobs::MemoryBlobs;
use aperture::model::FileRec;
use aperture::store::{PgStore, Store};
use aperture::{app, build_dev_state, now_secs, AppState};
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use tower::ServiceExt;

fn file(id: &str, owner: &str, token: &str, created_at: i64) -> FileRec {
    FileRec {
        id: id.to_string(),
        owner_sub: owner.to_string(),
        name: format!("{id}.png"),
        content_type: "image/png".to_string(),
        size: 1234,
        bucket: "aperture".to_string(),
        object_key: id.to_string(),
        share_token: token.to_string(),
        created_at,
    }
}

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

    // Raw pool to reset the table for a clean run.
    let raw = PgPoolOptions::new().max_connections(2).connect(&url).await.unwrap();
    sqlx::query("DELETE FROM files").execute(&raw).await.unwrap();

    let store: Arc<dyn Store> = Arc::new(pg);
    let now = now_secs();

    // --- create + get round-trip -------------------------------------------
    assert!(store.create(&file("aaaaaaaaaa", "alice", "tok-aaaa", now)).await.unwrap());
    let got = store.get("aaaaaaaaaa").await.unwrap().expect("file persisted");
    assert_eq!(got.name, "aaaaaaaaaa.png");
    assert_eq!(got.content_type, "image/png");
    assert_eq!(got.size, 1234);
    assert_eq!(got.bucket, "aperture");
    assert_eq!(got.object_key, "aaaaaaaaaa");
    assert_eq!(got.share_token, "tok-aaaa");

    // --- id collision -> create returns false (ON CONFLICT DO NOTHING) ------
    assert!(!store.create(&file("aaaaaaaaaa", "alice", "tok-diff", now + 5)).await.unwrap());
    // --- share-token collision ALSO trips the no-target ON CONFLICT ---------
    assert!(!store.create(&file("bbbbbbbbbb", "alice", "tok-aaaa", now + 5)).await.unwrap());

    // --- fetch by share token (the public /s/{token} path) -----------------
    assert_eq!(store.get_by_token("tok-aaaa").await.unwrap().unwrap().id, "aaaaaaaaaa");
    assert!(store.get_by_token("nope").await.unwrap().is_none());

    // --- owner-scoped gallery list, newest-first ---------------------------
    store.create(&file("cccccccccc", "alice", "tok-cccc", now + 20)).await.unwrap();
    store.create(&file("dddddddddd", "bob", "tok-dddd", now + 30)).await.unwrap();
    let mine = store.list_by_owner("alice", None, 50).await.unwrap();
    let ids: Vec<&str> = mine.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(ids, vec!["cccccccccc", "aaaaaaaaaa"], "other owner excluded, newest first");

    // --- keyset backward pagination over the portable SQL path -------------
    let page1 = store.list_by_owner("alice", None, 1).await.unwrap();
    assert_eq!(
        page1.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(),
        vec!["cccccccccc"],
        "first page = newest only"
    );
    let cur = page1.last().unwrap();
    let page2 = store
        .list_by_owner("alice", Some((cur.created_at, cur.id.clone())), 1)
        .await
        .unwrap();
    assert_eq!(
        page2.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(),
        vec!["aaaaaaaaaa"],
        "before-cursor pages into the older row"
    );

    // --- ownership-scoped delete -------------------------------------------
    assert!(!store.delete("aaaaaaaaaa", "bob").await.unwrap(), "bob cannot delete alice's");
    assert!(store.get("aaaaaaaaaa").await.unwrap().is_some());
    assert!(store.delete("aaaaaaaaaa", "alice").await.unwrap());
    assert!(store.get("aaaaaaaaaa").await.unwrap().is_none());

    // --- the full HTTP app boots against Postgres (healthz) ----------------
    let state = AppState {
        config: build_dev_state().config,
        store: store.clone(),
        blobs: Arc::new(MemoryBlobs::new()),
        audit: aperture::audit::AuditSink::disabled(),
    };
    let app = app(state);
    let res = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/healthz")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);

    // Confirm the remaining row count via a raw query (portable SQL path is live).
    let row = sqlx::query("SELECT count(*) AS n FROM files")
        .fetch_one(&raw)
        .await
        .unwrap();
    let n: i64 = row.try_get("n").unwrap();
    assert!(n >= 2, "expected remaining files, got {n}");

    sqlx::query("DELETE FROM files").execute(&raw).await.unwrap();
    eprintln!("pg_store integration test passed.");
}
