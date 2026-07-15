//! End-to-end tests for the additive text-intelligence features over the in-memory store:
//! compose-time duplicate detection (`POST /api/similar`), per-thread extractive summary
//! (`GET /api/thread/{id}/summary`), and the server-rendered summary card on the thread page.
//!
//! Drives the real `app` Router via `tower::oneshot`, exactly like `forum_flow.rs`.

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use tower::ServiceExt;

use agora::{app, build_dev_state, AppState};

const TOK: &str = "csrftoken123";

#[tokio::test]
async fn similar_surfaces_existing_duplicate_thread() {
    let state = build_dev_state().await;

    // Seed an existing thread about Postgres connection pools.
    create_thread(
        &state,
        "general",
        "Tuning the Postgres connection pool",
        "We keep exhausting the postgres connection pool under load. What max size do you use?",
    )
    .await;
    // And an unrelated one.
    create_thread(&state, "general", "Best pizza in town", "Where do you get the best pizza?").await;

    // A draft that is clearly a duplicate of the first thread.
    let resp = similar_request(
        &state,
        "How should I size the postgres connection pool?",
        "Our postgres connection pool keeps getting exhausted under heavy load.",
    )
    .await;
    assert_eq!(resp.0, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&resp.1).unwrap();
    let similar = json["similar"].as_array().expect("similar array");
    assert!(!similar.is_empty(), "a similar thread must be surfaced");
    // The top hit is the connection-pool thread, not the pizza one.
    assert!(similar[0]["title"]
        .as_str()
        .unwrap()
        .to_lowercase()
        .contains("connection pool"));
    assert!(similar[0]["score"].as_f64().unwrap() > 0.08);
    assert!(!similar
        .iter()
        .any(|s| s["title"].as_str().unwrap().contains("pizza")));
}

#[tokio::test]
async fn similar_requires_csrf_and_identity() {
    let state = build_dev_state().await;
    let body = form(&[("csrf", "x"), ("title", "T"), ("body", "B")]);

    // No CSRF cookie -> forbidden.
    let req = Request::builder()
        .method("POST")
        .uri("/api/similar")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("x-auth-subject", "u_1")
        .body(Body::from(body.clone()))
        .unwrap();
    let (status, ..) = send(&state, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Valid CSRF but no identity -> unauthorized.
    let req = Request::builder()
        .method("POST")
        .uri("/api/similar")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={TOK}"))
        .body(Body::from(form(&[("csrf", TOK), ("title", "T"), ("body", "B")])))
        .unwrap();
    let (status, ..) = send(&state, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn similar_empty_draft_returns_empty_list() {
    let state = build_dev_state().await;
    let (status, body) = similar_request(&state, "", "").await;
    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(json["similar"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn thread_summary_endpoint_and_card() {
    let state = build_dev_state().await;

    // A substantial thread: a multi-sentence OP plus replies, so the summary triggers.
    let op = "The nightly export job has been failing intermittently for a week. \
        The failures all happen when the export writes to the shared NFS volume. \
        Pizza is unrelated but tasty. \
        We traced it to the NFS volume running out of inodes during the export. \
        Cleaning up stale temp files on the volume fixed the export job. \
        Thanks everyone.";
    let location = create_thread(&state, "support", "Nightly export job failing", op).await;
    let thread_id = location.trim_start_matches("/t/").to_string();
    reply(&state, &location, "I also saw the export job fail on the NFS volume last night.").await;

    // JSON endpoint returns an extractive summary.
    let req = Request::builder()
        .uri(format!("/api/thread/{thread_id}/summary"))
        .body(Body::empty())
        .unwrap();
    let (status, _h, body) = send_full(&state, req).await;
    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["thread_id"].as_str().unwrap(), thread_id);
    assert_eq!(json["post_count"].as_i64().unwrap(), 2);
    let summary = json["summary"].as_array().unwrap();
    assert!(!summary.is_empty() && summary.len() <= 3);
    // The salient export/NFS sentences win over the off-topic "pizza" line.
    let joined = summary
        .iter()
        .map(|s| s.as_str().unwrap().to_lowercase())
        .collect::<Vec<_>>()
        .join(" | ");
    assert!(joined.contains("export"));
    assert!(!joined.contains("pizza"), "off-topic sentence excluded: {joined}");

    // The thread page renders the summary card, and the original posts still render unchanged.
    let (status, page) = get_body(&state, &location).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("Thread summary"), "summary card present");
    assert!(page.contains("summary__list"));
    assert!(page.contains("Top sentences from posts visible on this page"));
    assert!(!page.contains("Top sentences across this thread"));
    assert!(page.contains("Nightly export job failing"), "thread still renders");
    assert!(page.contains("1 reply"));
}

#[tokio::test]
async fn summary_endpoint_404_for_missing_thread() {
    let state = build_dev_state().await;
    let req = Request::builder()
        .uri("/api/thread/t_missing/summary")
        .body(Body::empty())
        .unwrap();
    let (status, ..) = send(&state, req).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn small_thread_has_no_summary_card() {
    let state = build_dev_state().await;
    // One short post -> below the word/post threshold, so no card (page unchanged).
    let location = create_thread(&state, "general", "Quick question", "Short body.").await;
    let (_s, page) = get_body(&state, &location).await;
    assert!(!page.contains("Thread summary"), "tiny thread shows no summary card");
}

// --- helpers ---------------------------------------------------------------------------

async fn send(state: &AppState, req: Request<Body>) -> (StatusCode, HeaderMap, String) {
    send_full(state, req).await
}

async fn send_full(state: &AppState, req: Request<Body>) -> (StatusCode, HeaderMap, String) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, headers, String::from_utf8(bytes.to_vec()).unwrap())
}

/// Create a thread through the real POST path; returns the redirect Location (`/t/{id}`).
async fn create_thread(state: &AppState, cat: &str, title: &str, body: &str) -> String {
    let payload = form(&[("csrf", TOK), ("category", cat), ("title", title), ("body", body)]);
    let req = Request::builder()
        .method("POST")
        .uri("/new")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={TOK}"))
        .header("x-auth-subject", "u_1")
        .header("x-auth-email", "alice@steadholme.local")
        .body(Body::from(payload))
        .unwrap();
    let (status, h, _b) = send(state, req).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "create thread redirects");
    h.get(header::LOCATION).unwrap().to_str().unwrap().to_string()
}

async fn reply(state: &AppState, location: &str, body: &str) {
    let payload = form(&[("csrf", TOK), ("body", body)]);
    let req = Request::builder()
        .method("POST")
        .uri(format!("{location}/reply"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={TOK}"))
        .header("x-auth-subject", "u_2")
        .header("x-auth-email", "bob@steadholme.local")
        .body(Body::from(payload))
        .unwrap();
    let (status, ..) = send(state, req).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
}

async fn similar_request(state: &AppState, title: &str, body: &str) -> (StatusCode, String) {
    let payload = form(&[("csrf", TOK), ("title", title), ("body", body)]);
    let req = Request::builder()
        .method("POST")
        .uri("/api/similar")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={TOK}"))
        .header("x-auth-subject", "u_1")
        .header("x-auth-email", "alice@steadholme.local")
        .body(Body::from(payload))
        .unwrap();
    let (status, _h, body) = send(state, req).await;
    (status, body)
}

async fn get_body(state: &AppState, uri: &str) -> (StatusCode, String) {
    let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    let (status, _h, body) = send(state, req).await;
    (status, body)
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
