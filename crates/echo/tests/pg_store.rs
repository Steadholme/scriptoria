//! PostgreSQL `Store` integration test.
//!
//! Runs ONLY when `TEST_DATABASE_URL` is set (it needs an external Postgres). When unset the test
//! prints a note and returns early — it never fails the default `cargo test` run, which stays
//! database-free. Spin up a throwaway Postgres and run:
//!
//! ```text
//! docker run --rm -d -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=echo \
//!   -p 127.0.0.1:55470:5432 postgres:18-alpine
//! TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55470/echo \
//!   cargo test --test pg_store -- --nocapture
//! ```

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use echo::store::{Comment, CommentReport, CommentVote, PgStore, Reaction, Sort, Store, Thread};
use echo::{app, build_dev_state, now_secs, AppState};
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
    let pg = PgStore::connect(&url)
        .await
        .expect("connect TEST_DATABASE_URL");
    pg.migrate().await.expect("migrate");
    pg.migrate().await.expect("migrate is idempotent");
    let pg = Arc::new(pg);

    let now = now_secs();

    // --- upsert a thread by key (idempotent on the key) --------------------
    let t = Thread {
        id: "thr_pg_1".to_string(),
        key: "pg/thread".to_string(),
        title: "PG Thread".to_string(),
        url: "https://x.w33d.xyz/pg".to_string(),
        created_at: now,
    };
    let stored = pg.upsert_thread(&t).await.expect("upsert");
    assert_eq!(stored.id, "thr_pg_1");
    // A second upsert with a DIFFERENT id but the SAME key keeps the original row.
    let dup = Thread {
        id: "thr_pg_other".to_string(),
        ..t.clone()
    };
    let again = pg.upsert_thread(&dup).await.expect("upsert idempotent");
    assert_eq!(again.id, "thr_pg_1", "key upsert keeps the original id");

    // --- insert comments (top-level + reply) -------------------------------
    let c1 = Comment {
        id: "cmt_pg_1".to_string(),
        thread_id: "thr_pg_1".to_string(),
        author_sub: "u_alice".to_string(),
        author_email: "alice@holdfast.local".to_string(),
        body: "root comment".to_string(),
        created_at: now,
        hidden: false,
        parent_id: String::new(),
    };
    pg.create_comment(&c1).await.expect("create c1");
    let c2 = Comment {
        id: "cmt_pg_2".to_string(),
        thread_id: "thr_pg_1".to_string(),
        author_sub: "u_bob".to_string(),
        author_email: "bob@holdfast.local".to_string(),
        body: "a reply".to_string(),
        created_at: now + 1,
        hidden: false,
        parent_id: "cmt_pg_1".to_string(),
    };
    pg.create_comment(&c2).await.expect("create c2");

    let listed = pg.list_comments("thr_pg_1").await;
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].id, "cmt_pg_1", "oldest-first ordering");
    assert_eq!(pg.count_comments("thr_pg_1").await, 2);

    // --- moderation round-trip ---------------------------------------------
    assert!(pg.set_comment_hidden("cmt_pg_1", true).await.expect("hide"));
    assert!(pg.get_comment("cmt_pg_1").await.expect("get").hidden);
    assert!(
        !pg.set_comment_hidden("cmt_missing", true)
            .await
            .expect("miss"),
        "no row -> false"
    );

    // --- recent feed across threads ----------------------------------------
    let recent = pg.recent_comments(10).await;
    assert!(recent.len() >= 2);
    assert_eq!(recent[0].id, "cmt_pg_2", "newest-first in the feed");

    // --- author self-edit / self-delete (ownership enforced by author_sub) --
    assert!(
        !pg.update_comment_body("cmt_pg_2", "u_alice", "nope")
            .await
            .expect("edit"),
        "non-owner edit updates no row"
    );
    assert!(
        pg.update_comment_body("cmt_pg_2", "u_bob", "an edited reply")
            .await
            .expect("edit"),
        "owner edit updates the row"
    );
    assert_eq!(
        pg.get_comment("cmt_pg_2").await.expect("get").body,
        "an edited reply"
    );
    assert!(
        !pg.delete_comment("cmt_pg_2", "u_alice").await.expect("del"),
        "non-owner delete removes no row"
    );
    assert!(
        pg.delete_comment("cmt_pg_2", "u_bob").await.expect("del"),
        "owner delete removes the row"
    );
    assert!(
        pg.get_comment("cmt_pg_2").await.is_none(),
        "row is gone after self-delete"
    );
    assert_eq!(
        pg.count_comments("thr_pg_1").await,
        1,
        "only the root remains"
    );

    // --- reactions: idempotent toggle + counts + most-reacted page ---------
    let react = |who: &str, kind: &str| Reaction {
        comment_id: "cmt_pg_1".to_string(),
        user_sub: who.to_string(),
        kind: kind.to_string(),
        created_at: now,
    };
    assert!(
        pg.toggle_reaction(&react("u_alice", "up"))
            .await
            .expect("react"),
        "added"
    );
    assert!(
        pg.toggle_reaction(&react("u_bob", "up"))
            .await
            .expect("react"),
        "added"
    );
    // A repeat by the same user+kind toggles OFF.
    assert!(
        !pg.toggle_reaction(&react("u_alice", "up"))
            .await
            .expect("untoggle"),
        "removed"
    );
    let rx = pg.reactions_for(&["cmt_pg_1".to_string()]).await;
    assert_eq!(rx.len(), 1, "one reaction remains after alice toggled off");
    assert_eq!(rx[0].user_sub, "u_bob");
    // The paged top-level view surfaces the (reacted) root.
    let (tops, _replies) = pg
        .list_thread_page("thr_pg_1", Sort::MostReacted, None, 10)
        .await;
    assert!(
        tops.iter().any(|c| c.id == "cmt_pg_1"),
        "root present in most-reacted page"
    );

    // --- votes: one per user/comment + top sort ---------------------------
    let vote = |who: &str, value: i64| CommentVote {
        comment_id: "cmt_pg_1".to_string(),
        voter_sub: who.to_string(),
        value,
        created_at: now,
    };
    assert_eq!(pg.toggle_vote(&vote("u_alice", 1)).await.expect("vote"), 1);
    assert_eq!(
        pg.toggle_vote(&vote("u_alice", -1)).await.expect("flip"),
        -1
    );
    assert_eq!(
        pg.toggle_vote(&vote("u_alice", -1)).await.expect("clear"),
        0
    );
    assert_eq!(pg.toggle_vote(&vote("u_bob", 1)).await.expect("vote"), 1);
    let votes = pg.votes_for(&["cmt_pg_1".to_string()]).await;
    assert_eq!(votes.len(), 1, "alice cleared, bob remains");
    assert_eq!(votes[0].value, 1);
    let (tops, _replies) = pg.list_thread_page("thr_pg_1", Sort::Top, None, 10).await;
    assert!(
        tops.iter().any(|c| c.id == "cmt_pg_1"),
        "root present in top page"
    );

    // --- reports: one per reporter/comment with reason update -------------
    let report = |who: &str, reason: &str| CommentReport {
        comment_id: "cmt_pg_1".to_string(),
        reporter_sub: who.to_string(),
        reason: reason.to_string(),
        created_at: now,
    };
    assert!(pg
        .report_comment(&report("u_alice", "spam"))
        .await
        .expect("report"));
    assert!(
        !pg.report_comment(&report("u_alice", "updated"))
            .await
            .expect("update report"),
        "same reporter updates one row"
    );
    let reports = pg.reports_for(&["cmt_pg_1".to_string()]).await;
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].reason, "updated");

    // --- full HTTP flow through the PG-backed app --------------------------
    let mut state: AppState = build_dev_state();
    state.store = pg.clone();

    let body = "thread_key=pg%2Fhttp&body=hello+%23world&csrf_token=tok";
    let resp = app(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/comment")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, "__Host-csrf=tok")
                .header("x-auth-subject", "u_carol")
                .header("x-auth-email", "carol@holdfast.local")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/t/pg%2Fhttp")
    );

    // Read it back through the PG-backed thread view.
    let resp = app(state.clone())
        .oneshot(
            Request::builder()
                .uri("/t/pg%2Fhttp")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("hello"));

    println!(
        "PG STORE INTEGRATION OK: migrate (idempotent) + thread upsert (key idempotent) + \
         comment insert/list/count/moderate + recent feed + full HTTP post/read against real Postgres"
    );
}
