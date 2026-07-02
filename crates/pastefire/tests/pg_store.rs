//! PostgreSQL `Store` integration test.
//!
//! Runs ONLY when `TEST_DATABASE_URL` is set (it needs an external Postgres). When unset the
//! test prints a note and returns early — it never fails the default `cargo test` run, which
//! stays database-free. Spin up a throwaway Postgres and run:
//!
//! ```text
//! docker run --rm -d --name pf-testpg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=pastefire \
//!   -p 127.0.0.1:55463:5432 postgres:18-alpine
//! TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55463/pastefire \
//!   cargo test --test pg_store -- --nocapture
//! docker rm -f pf-testpg
//! ```
//!
//! Uses a multi-threaded runtime (matching production); the `Store` trait is async, so the
//! handlers `.await` sqlx natively with no sync-over-async bridge.

use std::sync::Arc;

use pastefire::model::Paste;
use pastefire::store::{PgStore, Store};
use pastefire::{build_dev_state, now_secs};
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use tower::ServiceExt;

fn paste(id: &str, author: &str, created_at: i64, expires_at: Option<i64>) -> Paste {
    Paste {
        id: id.to_string(),
        title: format!("title {id}"),
        body: format!("body of {id}\nsecond line"),
        language: "rust".to_string(),
        author_sub: author.to_string(),
        author_email: format!("{author}@w33d.xyz"),
        created_at,
        expires_at,
        burn_after_read: false,
        source_id: None,
        password_hash: None,
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
    sqlx::query("DELETE FROM pastes").execute(&raw).await.unwrap();

    let store: Arc<dyn Store> = Arc::new(pg);
    let now = now_secs();

    // --- create + get round-trip -------------------------------------------
    assert!(store.create(&paste("aaaaaa11", "alice", now, None)).await.unwrap());
    let got = store.get("aaaaaa11").await.unwrap().expect("paste persisted");
    assert_eq!(got.title, "title aaaaaa11");
    assert_eq!(got.body, "body of aaaaaa11\nsecond line");
    assert_eq!(got.language, "rust");
    assert_eq!(got.author_email, "alice@w33d.xyz");
    assert_eq!(got.expires_at, None);

    // --- id collision -> create returns false (ON CONFLICT DO NOTHING) ------
    assert!(!store.create(&paste("aaaaaa11", "alice", now + 5, None)).await.unwrap());

    // --- recent list: newest-first, excludes expired + other authors -------
    store.create(&paste("bbbbbb22", "alice", now + 10, Some(now + 9999))).await.unwrap();
    store.create(&paste("cccccc33", "alice", now + 20, Some(now - 1))).await.unwrap(); // expired
    store.create(&paste("dddddd44", "bob", now + 30, None)).await.unwrap();

    let recent = store.list_by_author("alice", now, None, 50).await.unwrap();
    let ids: Vec<&str> = recent.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(ids, vec!["bbbbbb22", "aaaaaa11"], "expired + other-author excluded, newest first");

    // --- keyset backward paging: a `before` cursor yields only older rows ----
    let newest = &recent[0]; // bbbbbb22
    let older = store
        .list_by_author("alice", now, Some((newest.created_at, newest.id.clone())), 50)
        .await
        .unwrap();
    let older_ids: Vec<&str> = older.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(older_ids, vec!["aaaaaa11"], "cursor pages strictly backward");

    // --- nullable expires_at round-trips both ways -------------------------
    let with_exp = store.get("bbbbbb22").await.unwrap().unwrap();
    assert_eq!(with_exp.expires_at, Some(now + 9999));

    // --- burn_after_read column round-trips + excluded from similarity pool -
    let mut burner = paste("burnaa11", "alice", now + 40, None);
    burner.burn_after_read = true;
    assert!(store.create(&burner).await.unwrap());
    let got_burn = store.get("burnaa11").await.unwrap().unwrap();
    assert!(got_burn.burn_after_read, "burn flag persisted true");
    let got_plain = store.get("bbbbbb22").await.unwrap().unwrap();
    assert!(!got_plain.burn_after_read, "default burn flag is false");

    let pool = store.list_for_similarity("alice", now, 100).await.unwrap();
    let pool_ids: Vec<&str> = pool.iter().map(|p| p.id.as_str()).collect();
    assert!(pool_ids.contains(&"bbbbbb22"), "live non-burn paste in pool");
    assert!(!pool_ids.contains(&"burnaa11"), "burn paste excluded from pool");
    assert!(!pool_ids.contains(&"cccccc33"), "expired paste excluded from pool");

    // --- edit: update_paste + append-only revision history -----------------
    use pastefire::model::PasteRevision;
    // Snapshot bbbbbb22's current content as revision 1, then overwrite the row.
    let pre = store.get("bbbbbb22").await.unwrap().unwrap();
    assert!(store
        .add_revision(&PasteRevision {
            paste_id: "bbbbbb22".to_string(),
            revision: 1,
            title: pre.title.clone(),
            body: pre.body.clone(),
            language: pre.language.clone(),
            created_at: now,
        })
        .await
        .unwrap());
    // Idempotent: re-appending revision 1 is a no-op.
    assert!(!store
        .add_revision(&PasteRevision {
            paste_id: "bbbbbb22".to_string(),
            revision: 1,
            title: pre.title.clone(),
            body: pre.body.clone(),
            language: pre.language.clone(),
            created_at: now,
        })
        .await
        .unwrap());
    // Ownership-scoped update: bob cannot edit alice's paste; alice can.
    assert!(!store
        .update_paste("bbbbbb22", "bob", "hacked", "hacked", "rust")
        .await
        .unwrap());
    assert!(store
        .update_paste("bbbbbb22", "alice", "edited title", "edited body", "go")
        .await
        .unwrap());
    let edited = store.get("bbbbbb22").await.unwrap().unwrap();
    assert_eq!(edited.title, "edited title");
    assert_eq!(edited.body, "edited body");
    assert_eq!(edited.language, "go");

    let revs = store.list_revisions("bbbbbb22").await.unwrap();
    assert_eq!(revs.len(), 1, "one archived revision");
    assert_eq!(revs[0].revision, 1);
    assert_eq!(revs[0].body, pre.body, "revision holds the pre-edit body");
    let r1 = store.get_revision("bbbbbb22", 1).await.unwrap().unwrap();
    assert_eq!(r1.title, pre.title);
    assert!(store.get_revision("bbbbbb22", 99).await.unwrap().is_none());

    // --- fork: source_id round-trips ---------------------------------------
    let mut forked = paste("forkaa11", "bob", now + 60, None);
    forked.source_id = Some("bbbbbb22".to_string());
    assert!(store.create(&forked).await.unwrap());
    let got_fork = store.get("forkaa11").await.unwrap().unwrap();
    assert_eq!(got_fork.source_id.as_deref(), Some("bbbbbb22"));

    // --- password_hash round-trips -----------------------------------------
    let mut locked = paste("lockaa11", "alice", now + 70, None);
    locked.password_hash = Some(pastefire::auth::hash_password("s3cret"));
    assert!(store.create(&locked).await.unwrap());
    let got_locked = store.get("lockaa11").await.unwrap().unwrap();
    assert!(pastefire::auth::verify_password("s3cret", got_locked.password_hash.as_deref().unwrap()));

    // --- multi-file: set_files overwrite + position order + delete cascade --
    use pastefire::model::PasteFile;
    store.create(&paste("multi111", "alice", now + 80, None)).await.unwrap();
    store
        .set_files(
            "multi111",
            &[
                PasteFile {
                    id: "multi111-1".into(),
                    paste_id: "multi111".into(),
                    filename: "b.rs".into(),
                    content: "fn b() {}".into(),
                    position: 1,
                },
                PasteFile {
                    id: "multi111-0".into(),
                    paste_id: "multi111".into(),
                    filename: "a.rs".into(),
                    content: "fn a() {}".into(),
                    position: 0,
                },
            ],
        )
        .await
        .unwrap();
    let files = store.list_files("multi111").await.unwrap();
    let fnames: Vec<&str> = files.iter().map(|f| f.filename.as_str()).collect();
    assert_eq!(fnames, vec!["a.rs", "b.rs"], "files come back position-ordered");
    // Whole-set overwrite replaces the prior set.
    store
        .set_files(
            "multi111",
            &[PasteFile {
                id: "multi111-only".into(),
                paste_id: "multi111".into(),
                filename: "only.rs".into(),
                content: "fn only() {}".into(),
                position: 0,
            }],
        )
        .await
        .unwrap();
    assert_eq!(store.list_files("multi111").await.unwrap().len(), 1);
    // Deleting the paste cascades its files.
    assert!(store.delete("multi111", "alice").await.unwrap());
    assert!(store.list_files("multi111").await.unwrap().is_empty(), "files cascade on delete");

    // --- ownership-scoped delete -------------------------------------------
    assert!(!store.delete("aaaaaa11", "bob").await.unwrap(), "bob cannot delete alice's");
    assert!(store.get("aaaaaa11").await.unwrap().is_some());
    assert!(store.delete("aaaaaa11", "alice").await.unwrap());
    assert!(store.get("aaaaaa11").await.unwrap().is_none());

    // --- the full HTTP app works against Postgres (create via the router) --
    let mut state = build_dev_state();
    state.store = store.clone();
    let app = pastefire::app(state);
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

    // Confirm the row count via a raw query (portable SQL path is live).
    let row = sqlx::query("SELECT count(*) AS n FROM pastes")
        .fetch_one(&raw)
        .await
        .unwrap();
    let n: i64 = row.try_get("n").unwrap();
    assert!(n >= 2, "expected remaining pastes, got {n}");

    sqlx::query("DELETE FROM pastes").execute(&raw).await.unwrap();
    eprintln!("pg_store integration test passed.");
}
