//! PostgreSQL `Store` integration test.
//!
//! Runs ONLY when `TEST_DATABASE_URL` is set (it needs an external Postgres). When unset the
//! test prints a note and returns early — it never fails the default `cargo test` run, which
//! stays database-free. Spin up a throwaway Postgres and run:
//!
//! ```text
//! docker run --rm -d --name lattice-testpg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=lattice \
//!   -p 127.0.0.1:55462:5432 postgres:18-alpine
//! TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55462/lattice \
//!   cargo test --test pg_store -- --nocapture
//! docker rm -f lattice-testpg
//! ```
//!
//! Uses a multi-threaded runtime (matching production); the `Store` trait is async, so the
//! handlers `.await` sqlx natively with no sync-over-async bridge.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use tower::ServiceExt;

use lattice::store::PgStore;
use lattice::{app, build_dev_state, AppState};

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
    let pg = PgStore::connect(&url)
        .await
        .expect("connect to TEST_DATABASE_URL");
    pg.migrate().await.expect("migrate");
    pg.migrate().await.expect("migrate is idempotent");

    let mut state = build_dev_state();
    state.store = Arc::new(pg);

    // Raw pool for clean-slate setup, out-of-band asserts, and teardown.
    let raw = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    sqlx::query("DELETE FROM page_links")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DELETE FROM revisions")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DELETE FROM pages")
        .execute(&raw)
        .await
        .unwrap();

    // --- create a page through the real HTTP flow --------------------------
    let (_s, headers, _b) = call(&state, get("/edit/runbook")).await;
    let cookie = set_cookie(&headers).expect("editor sets CSRF cookie");
    let csrf = cookie_value(&cookie).expect("csrf value");

    let save = post_form(
        &state,
        "/edit/runbook",
        &cookie,
        "alice@holdfast.local",
        &[
            ("csrf_token", &csrf),
            ("title", "Runbook"),
            ("body_md", "Step one.\n\nSee [[Glossary]]."),
        ],
    )
    .await;
    assert_eq!(save.0, StatusCode::SEE_OTHER);
    assert_eq!(location(&save.1).as_deref(), Some("/w/runbook"));

    // Index + page render straight out of Postgres.
    let (_s, _h, idx) = call(&state, get("/")).await;
    assert!(idx.contains(">Runbook</a>"));
    assert!(idx.contains("alice@holdfast.local"));

    let (status, _h, page) = call(&state, get("/w/runbook")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("Step one."));
    assert!(page.contains(r#"href="/w/glossary""#));
    assert!(page.contains("wikilink--new"), "Glossary doesn't exist yet");

    // --- second edit: upsert + a second revision, created_at preserved -----
    let (_s, headers2, _b) = call(&state, get("/edit/runbook")).await;
    let cookie2 = set_cookie(&headers2).unwrap();
    let csrf2 = cookie_value(&cookie2).unwrap();
    let base2 = state
        .store
        .head_revision("runbook")
        .await
        .unwrap()
        .unwrap()
        .id;
    let save2 = post_form(
        &state,
        "/edit/runbook",
        &cookie2,
        "bob@holdfast.local",
        &[
            ("csrf_token", &csrf2),
            ("base_rev", &base2),
            ("title", "Runbook v2"),
            ("body_md", "Rewritten."),
        ],
    )
    .await;
    assert_eq!(save2.0, StatusCode::SEE_OTHER);

    // The single page row reflects the latest edit; created_at <= updated_at.
    let row = sqlx::query(
        "SELECT title, updated_by_email, created_at, updated_at FROM pages WHERE slug = $1",
    )
    .bind("runbook")
    .fetch_one(&raw)
    .await
    .unwrap();
    let title: String = row.try_get("title").unwrap();
    let updated_by: String = row.try_get("updated_by_email").unwrap();
    let created_at: i64 = row.try_get("created_at").unwrap();
    let updated_at: i64 = row.try_get("updated_at").unwrap();
    assert_eq!(title, "Runbook v2");
    assert_eq!(updated_by, "bob@holdfast.local");
    assert!(
        created_at <= updated_at,
        "created_at preserved across the upsert"
    );

    let page_count: i64 = sqlx::query("SELECT count(*) AS n FROM pages")
        .fetch_one(&raw)
        .await
        .unwrap()
        .try_get("n")
        .unwrap();
    assert_eq!(page_count, 1, "upsert never duplicates the page row");

    // Two immutable revisions, newest-first, both editors present.
    let rev_count: i64 = sqlx::query("SELECT count(*) AS n FROM revisions WHERE slug = $1")
        .bind("runbook")
        .fetch_one(&raw)
        .await
        .unwrap()
        .try_get("n")
        .unwrap();
    assert_eq!(rev_count, 2, "each save appends one revision");

    let (status, _h, history) = call(&state, get("/history/runbook")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(history.contains("alice@holdfast.local"));
    assert!(history.contains("bob@holdfast.local"));

    // CSRF is enforced against the live DB-backed app too (no write should occur).
    let bad = post_form(
        &state,
        "/edit/runbook",
        "", // no cookie
        "mallory@holdfast.local",
        &[
            ("csrf_token", "forged"),
            ("title", "Hacked"),
            ("body_md", "x"),
        ],
    )
    .await;
    assert_eq!(bad.0, StatusCode::FORBIDDEN);
    let rev_count_after: i64 = sqlx::query("SELECT count(*) AS n FROM revisions WHERE slug = $1")
        .bind("runbook")
        .fetch_one(&raw)
        .await
        .unwrap()
        .try_get("n")
        .unwrap();
    assert_eq!(rev_count_after, 2, "CSRF failure wrote nothing");

    // Teardown.
    sqlx::query("DELETE FROM page_links")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DELETE FROM revisions")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DELETE FROM pages")
        .execute(&raw)
        .await
        .unwrap();
    println!(
        "PG STORE INTEGRATION OK: migrate (idempotent) + create/edit upsert + 2 revisions + \
         created_at preserved + wiki-links + CSRF enforced — all through Postgres."
    );
}

// --- helpers ---------------------------------------------------------------------------

type Resp = (StatusCode, axum::http::HeaderMap, String);

async fn call(state: &AppState, req: Request<Body>) -> Resp {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, headers, String::from_utf8(bytes.to_vec()).unwrap())
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

async fn post_form(
    state: &AppState,
    uri: &str,
    cookie: &str,
    email: &str,
    pairs: &[(&str, &str)],
) -> Resp {
    let body = pairs
        .iter()
        .map(|(k, v)| format!("{}={}", pct(k), pct(v)))
        .collect::<Vec<_>>()
        .join("&");
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("x-auth-email", email);
    if !cookie.is_empty() {
        builder = builder.header(header::COOKIE, cookie);
    }
    call(state, builder.body(Body::from(body)).unwrap()).await
}

fn pct(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn set_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

fn cookie_value(set_cookie: &str) -> Option<String> {
    let first = set_cookie.split(';').next()?;
    let (_n, v) = first.split_once('=')?;
    Some(v.to_string())
}

fn location(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}
