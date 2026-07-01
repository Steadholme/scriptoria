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
use aperture::model::{FileRec, FolderRec};
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
        share_token: Some(token.to_string()),
        created_at,
        expires_at: None,
        share_password_hash: None,
        folder_id: None,
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
    assert_eq!(got.share_token.as_deref(), Some("tok-aaaa"));

    // --- id collision -> create returns false (ON CONFLICT DO NOTHING) ------
    assert!(!store.create(&file("aaaaaaaaaa", "alice", "tok-diff", now + 5)).await.unwrap());
    // --- share-token collision ALSO trips the no-target ON CONFLICT ---------
    assert!(!store.create(&file("bbbbbbbbbb", "alice", "tok-aaaa", now + 5)).await.unwrap());

    // --- fetch by share token (the public /s/{token} path) -----------------
    assert_eq!(store.get_by_token("tok-aaaa").await.unwrap().unwrap().id, "aaaaaaaaaa");
    assert!(store.get_by_token("nope").await.unwrap().is_none());

    // --- share-link lifecycle: set expiry + password, then revoke ----------
    assert!(store
        .configure_share("aaaaaaaaaa", "alice", Some("tok-aaaa".into()), Some(now + 3600), Some("salt$hash".into()))
        .await
        .unwrap());
    let cfg = store.get("aaaaaaaaaa").await.unwrap().unwrap();
    assert_eq!(cfg.expires_at, Some(now + 3600));
    assert_eq!(cfg.share_password_hash.as_deref(), Some("salt$hash"));
    // Revoke clears the token to NULL; the public lookup misses and the row's token is None.
    assert!(store.configure_share("aaaaaaaaaa", "alice", None, None, None).await.unwrap());
    assert!(store.get_by_token("tok-aaaa").await.unwrap().is_none());
    assert!(store.get("aaaaaaaaaa").await.unwrap().unwrap().share_token.is_none());
    // A non-owner cannot configure the share link.
    assert!(!store
        .configure_share("aaaaaaaaaa", "bob", Some("tok-x".into()), None, None)
        .await
        .unwrap());

    // --- owner-scoped gallery list, newest-first ---------------------------
    store.create(&file("cccccccccc", "alice", "tok-cccc", now + 20)).await.unwrap();
    store.create(&file("dddddddddd", "bob", "tok-dddd", now + 30)).await.unwrap();
    let mine = store.list_by_owner("alice", None, None, 50).await.unwrap();
    let ids: Vec<&str> = mine.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(ids, vec!["cccccccccc", "aaaaaaaaaa"], "other owner excluded, newest first");

    // --- keyset backward pagination over the portable SQL path -------------
    let page1 = store.list_by_owner("alice", None, None, 1).await.unwrap();
    assert_eq!(
        page1.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(),
        vec!["cccccccccc"],
        "first page = newest only"
    );
    let cur = page1.last().unwrap();
    let page2 = store
        .list_by_owner("alice", None, Some((cur.created_at, cur.id.clone())), 1)
        .await
        .unwrap();
    assert_eq!(
        page2.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(),
        vec!["aaaaaaaaaa"],
        "before-cursor pages into the older row"
    );

    // --- folders (albums): create, filter, move, rename, delete-unfiles ----
    sqlx::query("DELETE FROM folders").execute(&raw).await.unwrap();
    let fld = |id: &str, owner: &str, name: &str| FolderRec {
        id: id.to_string(),
        owner_sub: owner.to_string(),
        name: name.to_string(),
        created_at: now,
    };
    assert!(store.create_folder(&fld("fold000001", "alice", "Zeta")).await.unwrap());
    assert!(store.create_folder(&fld("fold000002", "alice", "alpha")).await.unwrap());
    assert!(store.create_folder(&fld("fold000003", "bob", "bobs")).await.unwrap());
    // id collision -> false.
    assert!(!store.create_folder(&fld("fold000001", "alice", "dup")).await.unwrap());
    // Owner-scoped, case-insensitive name order; bob's folder excluded.
    let folder_names: Vec<String> = store
        .list_folders("alice")
        .await
        .unwrap()
        .into_iter()
        .map(|f| f.name)
        .collect();
    assert_eq!(folder_names, vec!["alpha".to_string(), "Zeta".to_string()]);
    // get_folder is ownership-scoped.
    assert!(store.get_folder("fold000001", "alice").await.unwrap().is_some());
    assert!(store.get_folder("fold000003", "alice").await.unwrap().is_none());

    // Move alice's file "cccccccccc" into a folder; the folder view returns only it.
    assert!(store.move_file("cccccccccc", "alice", Some("fold000001")).await.unwrap());
    let in_folder = store
        .list_by_owner("alice", Some("fold000001"), None, 50)
        .await
        .unwrap();
    assert_eq!(in_folder.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(), vec!["cccccccccc"]);
    // The flat view still shows the file regardless of folder.
    assert!(store
        .list_by_owner("alice", None, None, 50)
        .await
        .unwrap()
        .iter()
        .any(|f| f.id == "cccccccccc"));
    // A non-owner cannot move the file or rename/delete the folder.
    assert!(!store.move_file("cccccccccc", "bob", Some("fold000001")).await.unwrap());
    assert!(!store.rename_folder("fold000001", "bob", "hax").await.unwrap());
    assert!(!store.delete_folder("fold000001", "bob").await.unwrap());
    // Rename works for the owner.
    assert!(store.rename_folder("fold000001", "alice", "Renamed").await.unwrap());
    assert_eq!(store.get_folder("fold000001", "alice").await.unwrap().unwrap().name, "Renamed");
    // Deleting the folder unfiles its file (kept, folder_id cleared).
    assert!(store.delete_folder("fold000001", "alice").await.unwrap());
    assert!(store.get_folder("fold000001", "alice").await.unwrap().is_none());
    assert!(store.get("cccccccccc").await.unwrap().unwrap().folder_id.is_none());
    sqlx::query("DELETE FROM folders").execute(&raw).await.unwrap();

    // --- ownership-scoped delete -------------------------------------------
    assert!(!store.delete("aaaaaaaaaa", "bob").await.unwrap(), "bob cannot delete alice's");
    assert!(store.get("aaaaaaaaaa").await.unwrap().is_some());
    assert!(store.delete("aaaaaaaaaa", "alice").await.unwrap());
    assert!(store.get("aaaaaaaaaa").await.unwrap().is_none());

    // --- storage quotas: usage sums + override rows (portable SQL) ----------
    sqlx::query("DELETE FROM owner_quotas").execute(&raw).await.unwrap();
    // Remaining rows: cccccccccc (alice, 1234) and dddddddddd (bob, 1234).
    assert_eq!(store.usage_for_owner("alice").await.unwrap(), 1234);
    assert_eq!(store.usage_for_owner("nobody").await.unwrap(), 0);
    let agg = store.usage_by_owner().await.unwrap();
    assert_eq!(agg.len(), 2);
    assert!(agg.iter().any(|u| u.owner_sub == "alice" && u.files == 1 && u.bytes == 1234));
    assert!(agg.iter().any(|u| u.owner_sub == "bob" && u.files == 1 && u.bytes == 1234));
    // Overrides: missing row -> None; set is an upsert; list is owner-ordered; None clears.
    assert_eq!(store.get_quota("alice").await.unwrap(), None);
    store.set_quota("alice", Some(999)).await.unwrap();
    store.set_quota("alice", Some(2048)).await.unwrap();
    assert_eq!(store.get_quota("alice").await.unwrap(), Some(2048));
    store.set_quota("bob", Some(0)).await.unwrap();
    assert_eq!(
        store.list_quotas().await.unwrap(),
        vec![("alice".to_string(), 2048), ("bob".to_string(), 0)]
    );
    store.set_quota("alice", None).await.unwrap();
    assert_eq!(store.get_quota("alice").await.unwrap(), None);
    sqlx::query("DELETE FROM owner_quotas").execute(&raw).await.unwrap();

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
