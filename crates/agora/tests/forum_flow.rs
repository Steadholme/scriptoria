//! End-to-end forum flow over the in-memory store (no database).
//!
//! Drives the real `app` Router via `tower::oneshot`, exactly like keystone/keyward/beacon.
//! Covers: seeded categories on the home page; the CSRF-cookie issuing new-thread form; CSRF
//! and identity enforcement on POSTs; thread creation + reply (post/redirect/get); markdown
//! rendering; and markdown XSS sanitisation.

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use tower::ServiceExt;

use agora::{app, build_dev_state, AppState};

#[tokio::test]
async fn home_lists_seeded_categories() {
    let state = build_dev_state().await;
    let (status, _h, body) = send(&state, get("/")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Announcements"));
    assert!(body.contains("General Discussion"));
    assert!(body.contains("Support"));
    assert!(body.contains("No threads yet"));
}

#[tokio::test]
async fn new_form_issues_csrf_cookie_and_token() {
    let state = build_dev_state().await;
    let (status, h, body) = send(&state, get("/new")).await;
    assert_eq!(status, StatusCode::OK);
    let cookie = set_cookie(&h).expect("new form sets a CSRF cookie");
    assert!(cookie.contains("__Host-csrf="));
    assert!(cookie.contains("Secure"));
    let token = csrf_value(&cookie);
    // The same token must be echoed into the form's hidden input (double-submit).
    assert!(body.contains(&format!(r#"name="csrf" value="{token}""#)));
}

#[tokio::test]
async fn post_without_csrf_is_forbidden() {
    let state = build_dev_state().await;
    let body = form(&[("csrf", "x"), ("category", "general"), ("title", "T"), ("body", "B")]);
    // No CSRF cookie present -> double-submit fails.
    let (status, _h, _b) = send(&state, post_form("/new", None, true, body)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn post_without_identity_is_unauthorized() {
    let state = build_dev_state().await;
    let tok = "csrftoken123";
    let body = form(&[("csrf", tok), ("category", "general"), ("title", "T"), ("body", "B")]);
    // Valid CSRF (cookie matches field) but NO X-Auth-Subject injected.
    let (status, _h, _b) = send(&state, post_form("/new", Some(tok), false, body)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unknown_category_is_rejected() {
    let state = build_dev_state().await;
    let tok = "csrftoken123";
    let body = form(&[("csrf", tok), ("category", "nope"), ("title", "T"), ("body", "B")]);
    let (status, _h, _b) = send(&state, post_form("/new", Some(tok), true, body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_thread_reply_and_render_markdown() {
    let state = build_dev_state().await;
    let tok = "csrftoken123";

    // Create a thread with markdown in the original post.
    let body = form(&[
        ("csrf", tok),
        ("category", "general"),
        ("title", "Hello Agora"),
        ("body", "First post with **bold** text."),
    ]);
    let (status, h, _b) = send(&state, post_form("/new", Some(tok), true, body)).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "create redirects");
    let location = h
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("redirect Location")
        .to_string();
    assert!(location.starts_with("/t/t_"), "redirects to the new thread: {location}");

    // The thread page renders the markdown body + the author + the OP badge.
    let (status, _h, page) = send(&state, get(&location)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("Hello Agora"));
    assert!(page.contains("<strong>bold</strong>"), "markdown rendered");
    assert!(page.contains("alice@holdfast.local"), "trusted author shown");
    assert!(page.contains("Original post"));
    assert!(page.contains("0 replies"));

    // Reply, then confirm it shows and the count updates.
    let reply = form(&[("csrf", tok), ("body", "A _reply_ here.")]);
    let reply_uri = format!("{location}/reply");
    let (status, _h, _b) = send(&state, post_form(&reply_uri, Some(tok), true, reply)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (status, _h, page) = send(&state, get(&location)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("<em>reply</em>"), "reply markdown rendered");
    assert!(page.contains("1 reply"));

    // The thread now appears under its category and on the home page.
    let (_s, _h, cat_page) = send(&state, get("/c/general")).await;
    assert!(cat_page.contains("Hello Agora"));
    let (_s, _h, home) = send(&state, get("/")).await;
    assert!(home.contains("Hello Agora"));
}

#[tokio::test]
async fn markdown_xss_is_sanitised() {
    let state = build_dev_state().await;
    let tok = "csrftoken123";
    // The javascript link is in its own paragraph (so CommonMark parses it as a link, not as
    // part of the leading `<script>` HTML block) to exercise href defusing; the `<script>`
    // line exercises raw-HTML neutralisation.
    let md = "Click [evil](javascript:alert(2)) now.\n\n<script>alert(1)</script>";
    let body = form(&[
        ("csrf", tok),
        ("category", "general"),
        ("title", "XSS attempt"),
        ("body", md),
    ]);
    let (status, h, _b) = send(&state, post_form("/new", Some(tok), true, body)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = h.get(header::LOCATION).unwrap().to_str().unwrap().to_string();

    let (_s, _h, page) = send(&state, get(&location)).await;
    // No executable script tag and no executable javascript: href survive into the page.
    assert!(!page.contains("<script>alert"), "raw script must be neutralised");
    assert!(!page.contains("href=\"javascript"), "javascript: href must be defused");
    assert!(page.contains("href=\"#\""), "unsafe link rewritten to #");
    assert!(page.contains("&lt;script&gt;"), "script shown as escaped text");
}

#[tokio::test]
async fn missing_thread_and_category_are_404() {
    let state = build_dev_state().await;
    let (status, _h, _b) = send(&state, get("/t/t_doesnotexist")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _h, _b) = send(&state, get("/c/nope")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// --- helpers ---------------------------------------------------------------------------

async fn send(state: &AppState, req: Request<Body>) -> (StatusCode, HeaderMap, String) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, headers, String::from_utf8(bytes.to_vec()).unwrap())
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn post_form(uri: &str, csrf_cookie: Option<&str>, auth: bool, body: String) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(tok) = csrf_cookie {
        b = b.header(header::COOKIE, format!("__Host-csrf={tok}"));
    }
    if auth {
        b = b
            .header("x-auth-subject", "u_sub_1")
            .header("x-auth-email", "alice@holdfast.local");
    }
    b.body(Body::from(body)).unwrap()
}

/// Build an `application/x-www-form-urlencoded` body (percent-encoding every reserved byte).
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
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn set_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

fn csrf_value(set_cookie: &str) -> String {
    set_cookie
        .split(';')
        .next()
        .and_then(|kv| kv.split_once('='))
        .map(|(_, v)| v.to_string())
        .expect("cookie value")
}
