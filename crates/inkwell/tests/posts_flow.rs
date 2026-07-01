//! End-to-end HTTP flow over the in-memory store (NO database).
//!
//! Drives the real `app` router via `tower::oneshot`, exactly like the rest of the estate.
//! Covers: health, empty index, the SSO/CSRF guards on authoring, create/read/edit/delete,
//! ownership enforcement, draft visibility, and markdown XSS sanitization.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use inkwell::{app, build_dev_state};
use tower::ServiceExt;

const CSRF: &str = "tok_csrf_for_tests";

#[tokio::test]
async fn full_blog_flow_in_memory() {
    let state = build_dev_state();

    // --- health ------------------------------------------------------------
    let (status, _) = call(&state, get("/healthz")).await;
    assert_eq!(status, StatusCode::OK);

    // --- empty index -------------------------------------------------------
    let (status, body) = call(&state, get("/")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("No posts yet"), "empty index placeholder");

    // --- GET /new sets a CSRF cookie ---------------------------------------
    let resp = app(state.clone()).oneshot(get("/new")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(set_cookie.contains("__Host-csrf="), "GET /new mints CSRF cookie");

    // --- POST /new without identity -> 401 ---------------------------------
    let body = form(&[("title", "Nope"), ("body", "x"), ("csrf_token", CSRF)]);
    let (status, _) = call(&state, post_csrf("/new", &body, None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no X-Auth -> 401");

    // --- POST /new with bad CSRF -> 401 ------------------------------------
    let body = form(&[("title", "Nope"), ("body", "x"), ("csrf_token", "WRONG")]);
    let (status, _) = call(&state, post_csrf("/new", &body, Some(("u_alice", "alice@hf")))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "CSRF mismatch -> 401");

    // --- create a real post ------------------------------------------------
    let md = "# Heading\n\nSome **bold** body. <script>alert(1)</script> [x](javascript:alert(2))";
    let body = form(&[
        ("title", "Hello World"),
        ("body", md),
        ("published", "on"),
        ("csrf_token", CSRF),
    ]);
    let resp = app(state.clone())
        .oneshot(post_csrf("/new", &body, Some(("u_alice", "alice@hf"))))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    assert_eq!(location, "/p/hello-world", "slug derived from title");

    // --- index now lists it ------------------------------------------------
    let (_, body) = call(&state, get("/")).await;
    assert!(body.contains("Hello World"));
    assert!(body.contains("alice@hf"));

    // --- reading view renders sanitized markdown ---------------------------
    let (status, body) = call(&state, get("/p/hello-world")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("<strong>bold</strong>"), "markdown rendered");
    assert!(!body.contains("<script>alert(1)"), "raw script must be escaped");
    assert!(body.contains("&lt;script&gt;"), "script shown as escaped text");
    assert!(!body.contains("javascript:alert"), "js: link neutralized");

    // --- edit: wrong owner -> 403 ------------------------------------------
    let body = form(&[("title", "Hijack"), ("body", "x"), ("csrf_token", CSRF)]);
    let (status, _) = call(&state, post_csrf("/edit/hello-world", &body, Some(("u_mallory", "m@hf")))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "non-owner cannot edit");

    // --- edit: owner succeeds, slug stays stable ---------------------------
    let body = form(&[
        ("title", "Hello World (edited)"),
        ("body", "Updated body."),
        ("published", "on"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(&state, post_csrf("/edit/hello-world", &body, Some(("u_alice", "alice@hf")))).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, body) = call(&state, get("/p/hello-world")).await;
    assert!(body.contains("Hello World (edited)"), "title updated");
    assert!(body.contains("Updated body."), "body updated");

    // --- delete: wrong owner -> 403 ----------------------------------------
    let body = form(&[("csrf_token", CSRF)]);
    let (status, _) = call(&state, post_csrf("/delete/hello-world", &body, Some(("u_mallory", "m@hf")))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "non-owner cannot delete");

    // --- delete: owner succeeds --------------------------------------------
    let body = form(&[("csrf_token", CSRF)]);
    let (status, _) = call(&state, post_csrf("/delete/hello-world", &body, Some(("u_alice", "alice@hf")))).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (status, _) = call(&state, get("/p/hello-world")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "deleted post is gone");
}

#[tokio::test]
async fn drafts_are_private_to_their_author() {
    let state = build_dev_state();

    // Create an UNPUBLISHED post (omit the `published` checkbox field).
    let body = form(&[("title", "Secret Draft"), ("body", "wip"), ("csrf_token", CSRF)]);
    let (status, _) = call(&state, post_csrf("/new", &body, Some(("u_alice", "alice@hf")))).await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    // Anonymous viewer: not on the index, and the post 404s.
    let (_, idx) = call(&state, get("/")).await;
    assert!(!idx.contains("Secret Draft"), "draft hidden from anon index");
    let (status, _) = call(&state, get("/p/secret-draft")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "draft 404 for anon");

    // The author sees it (with the Draft badge) and can read it.
    let (_, idx) = call(&state, get_auth("/", "u_alice", "alice@hf")).await;
    assert!(idx.contains("Secret Draft"), "author sees own draft on index");
    assert!(idx.contains("Draft"), "draft badge shown to author");
    let (status, _) = call(&state, get_auth("/p/secret-draft", "u_alice", "alice@hf")).await;
    assert_eq!(status, StatusCode::OK, "author can read own draft");
}

#[tokio::test]
async fn index_pages_backward_via_load_older() {
    let state = build_dev_state();

    // Three published posts. Created within the same second is fine — the keyset falls back to
    // id DESC (ids are nanosecond-distinct), so ordering and the cursor stay well defined.
    for title in ["Alpha", "Beta", "Gamma"] {
        let body = form(&[("title", title), ("body", "x"), ("published", "on"), ("csrf_token", CSRF)]);
        let (status, _) = call(&state, post_csrf("/new", &body, Some(("u_alice", "alice@hf")))).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
    }

    // First page of 2 -> the two newest + a "Load older" cursor (a full page implies more history).
    let (status, page1) = call(&state, get("/?limit=2")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page1.contains("Gamma"), "newest shown on first page");
    assert!(page1.contains("Beta"), "second-newest shown on first page");
    assert!(!page1.contains("Alpha"), "oldest NOT on the first page (beyond the page size)");
    assert!(page1.contains("Load older"), "full page offers a Load-older cursor");

    // Follow the generated cursor link: the oldest post is now REACHABLE (was unreachable before).
    let cursor = extract_before(&page1).expect("Load older link carries a ?before= cursor");
    let (status, page2) = call(&state, get(&format!("/?before={cursor}"))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page2.contains("Alpha"), "oldest reachable via Load older");
    assert!(!page2.contains("Gamma"), "cursor pages strictly older — newest not repeated");
    assert!(!page2.contains("Beta"), "the cursor row itself is excluded (strictly older)");
    assert!(!page2.contains("Load older"), "partial last page has no further cursor");
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Pull the `?before=<cursor>` value out of a rendered "Load older" link.
fn extract_before(html: &str) -> Option<String> {
    let marker = "?before=";
    let start = html.find(marker)? + marker.len();
    let rest = &html[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

async fn call(state: &inkwell::AppState, req: Request<Body>) -> (StatusCode, String) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn get_auth(uri: &str, sub: &str, email: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("x-auth-subject", sub)
        .header("x-auth-email", email)
        .body(Body::empty())
        .unwrap()
}

/// Build a urlencoded POST carrying the test CSRF cookie + (optionally) gateway identity.
fn post_csrf(uri: &str, body: &str, ident: Option<(&str, &str)>) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={CSRF}"));
    if let Some((sub, email)) = ident {
        b = b.header("x-auth-subject", sub).header("x-auth-email", email);
    }
    b.body(Body::from(body.to_string())).unwrap()
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", k, enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Minimal application/x-www-form-urlencoded value encoder.
fn enc(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => o.push(b as char),
            b' ' => o.push('+'),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}
