//! End-to-end wiki flow against the in-memory store (NO database).
//!
//! Drives the real `Router` in-process via `tower::oneshot`, exactly like the rest of the
//! estate. Covers: liveness, the empty index, the "missing page -> offer create" path, the
//! CSRF-protected create/edit cycle (editor identity taken from the gateway header), the
//! revision history, slug canonicalization, raw-HTML sanitization, and `[[wiki-link]]` markup.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

use lattice::{app, build_dev_state, AppState};

#[tokio::test]
async fn healthz_ok() {
    let state = build_dev_state();
    let (status, _h, body) = call(&state, get("/healthz")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");
}

#[tokio::test]
async fn full_create_edit_history_flow() {
    let state = build_dev_state();

    // Empty index.
    let (status, _h, body) = call(&state, get("/")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Knowledge base"));
    assert!(body.contains("No pages yet"));

    // Missing page offers creation.
    let (status, _h, body) = call(&state, get("/w/home")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("doesn’t exist yet"));
    assert!(body.contains("/edit/home"));

    // Open the editor; capture the minted CSRF token (cookie == hidden field).
    let (status, headers, body) = call(&state, get("/edit/home")).await;
    assert_eq!(status, StatusCode::OK);
    let cookie = set_cookie(&headers).expect("editor sets a CSRF cookie");
    let csrf = cookie_value(&cookie).expect("csrf cookie value");
    assert!(body.contains(&format!("value=\"{csrf}\"")), "hidden field matches cookie");

    // Save the page (gateway injects the editor email; CSRF cookie + field present).
    let save = post_form(
        "/edit/home",
        &cookie,
        Some("alice@holdfast.local"),
        &[
            ("csrf_token", &csrf),
            ("title", "Home"),
            ("body_md", "Welcome.\n\nSee [[Runbook]] and [[Glossary|the glossary]]."),
        ],
    );
    let (status, headers, _b) = call(&state, save).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "save redirects (POST->GET)");
    assert_eq!(location(&headers).as_deref(), Some("/w/home"));

    // Index now lists the page with the gateway editor email.
    let (_s, _h, body) = call(&state, get("/")).await;
    assert!(body.contains("1 page"));
    assert!(body.contains(">Home</a>"));
    assert!(body.contains("alice@holdfast.local"));

    // The page renders markdown + wiki-links: [[Runbook]] is missing (red), the body itself
    // (slug `home`) exists.
    let (status, _h, body) = call(&state, get("/w/home")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("<p>Welcome.</p>"));
    assert!(body.contains(r#"href="/w/runbook""#));
    assert!(body.contains("wikilink--new"), "missing target is a red link");
    assert!(body.contains(r#"href="/w/glossary""#));
    assert!(body.contains(">the glossary</a>"), "pipe label honored");

    // History shows one revision by the gateway editor.
    let (status, _h, body) = call(&state, get("/history/home")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("alice@holdfast.local"));
    assert!(body.contains("chars"));

    // A second edit by a different editor records a second revision and updates the page.
    let (_s, headers2, _b) = call(&state, get("/edit/home")).await;
    let cookie2 = set_cookie(&headers2).unwrap();
    let csrf2 = cookie_value(&cookie2).unwrap();
    let save2 = post_form(
        "/edit/home",
        &cookie2,
        Some("bob@holdfast.local"),
        &[("csrf_token", &csrf2), ("title", "Home"), ("body_md", "Updated body.")],
    );
    let (status, _h, _b) = call(&state, save2).await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (_s, _h, body) = call(&state, get("/w/home")).await;
    assert!(body.contains("Updated body."));
    assert!(body.contains("bob@holdfast.local"));

    let (_s, _h, body) = call(&state, get("/history/home")).await;
    // Both editors appear in the history list.
    assert!(body.contains("alice@holdfast.local"));
    assert!(body.contains("bob@holdfast.local"));
}

#[tokio::test]
async fn csrf_required_on_post() {
    let state = build_dev_state();
    // POST with a token but NO cookie -> double-submit fails -> 403.
    let req = post_form(
        "/edit/home",
        "", // no cookie
        Some("alice@holdfast.local"),
        &[("csrf_token", "anything"), ("title", "Home"), ("body_md", "x")],
    );
    let (status, _h, body) = call(&state, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("CSRF"));
    // Nothing was written.
    let (_s, _h, idx) = call(&state, get("/")).await;
    assert!(idx.contains("No pages yet"));
}

#[tokio::test]
async fn slug_is_canonicalized_via_redirect() {
    let state = build_dev_state();
    let (status, headers, _b) = call(&state, get("/w/Foo%20Bar")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location(&headers).as_deref(), Some("/w/foo-bar"));

    let (status, headers, _b) = call(&state, get("/history/Foo%20Bar")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location(&headers).as_deref(), Some("/history/foo-bar"));
}

#[tokio::test]
async fn stored_html_is_sanitized() {
    let state = build_dev_state();
    let (_s, headers, _b) = call(&state, get("/edit/xss")).await;
    let cookie = set_cookie(&headers).unwrap();
    let csrf = cookie_value(&cookie).unwrap();
    let save = post_form(
        "/edit/xss",
        &cookie,
        Some("alice@holdfast.local"),
        &[
            ("csrf_token", &csrf),
            ("title", "XSS"),
            ("body_md", "<script>alert(1)</script>\n\nhi"),
        ],
    );
    let (status, _h, _b) = call(&state, save).await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (_s, _h, body) = call(&state, get("/w/xss")).await;
    assert!(!body.contains("<script>alert(1)</script>"), "script must be escaped");
    assert!(body.contains("&lt;script&gt;"));
}

#[tokio::test]
async fn unknown_route_renders_404() {
    let state = build_dev_state();
    let (status, _h, body) = call(&state, get("/no/such/path")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("Not found"));
}

// --- helpers ---------------------------------------------------------------------------

async fn call(state: &AppState, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, String) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, headers, String::from_utf8(bytes.to_vec()).unwrap())
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn post_form(
    uri: &str,
    cookie: &str,
    email: Option<&str>,
    pairs: &[(&str, &str)],
) -> Request<Body> {
    let body = form_encode(pairs);
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if !cookie.is_empty() {
        builder = builder.header(header::COOKIE, cookie);
    }
    if let Some(e) = email {
        builder = builder.header("x-auth-email", e);
    }
    builder.body(Body::from(body)).unwrap()
}

/// Percent-encode a list of key/value pairs as application/x-www-form-urlencoded.
fn form_encode(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", pct(k), pct(v)))
        .collect::<Vec<_>>()
        .join("&")
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

/// Extract the `name=value` (first segment) from a Set-Cookie header.
fn cookie_value(set_cookie: &str) -> Option<String> {
    let first = set_cookie.split(';').next()?;
    let (_name, value) = first.split_once('=')?;
    Some(value.to_string())
}

fn location(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}
