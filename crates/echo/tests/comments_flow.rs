//! End-to-end HTTP flow over the in-memory store (NO database).
//!
//! Drives the real `app` router via `tower::oneshot`, exactly like the rest of the estate.
//! Covers: health, empty dashboard, the SSO/CSRF guards, thread upsert + comment insert, the
//! recent-activity feed, one-level reply nesting, hide/unhide moderation, markdown XSS
//! sanitization, and the embed view's `X-Frame-Options`.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use echo::{app, build_dev_state};
use tower::ServiceExt;

const CSRF: &str = "tok_csrf_for_tests";

#[tokio::test]
async fn full_comments_flow_in_memory() {
    let state = build_dev_state();

    // --- health ------------------------------------------------------------
    let (status, body) = call(&state, get("/healthz")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");

    // --- empty dashboard ---------------------------------------------------
    let (status, body) = call(&state, get("/")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("No threads yet"), "empty dashboard placeholder");

    // --- GET /t/{key} mints a CSRF cookie even for a not-yet-existing thread
    let resp = app(state.clone()).oneshot(get("/t/blog%2Fhello")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(set_cookie.contains("__Host-csrf="), "GET /t mints CSRF cookie");

    // --- POST /api/comment without identity -> 401 -------------------------
    let body = form(&[("thread_key", "blog/hello"), ("body", "hi"), ("csrf_token", CSRF)]);
    let (status, _) = call(&state, post_csrf("/api/comment", &body, None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no X-Auth -> 401");

    // --- POST /api/comment with bad CSRF -> 401 ----------------------------
    let body = form(&[("thread_key", "blog/hello"), ("body", "hi"), ("csrf_token", "WRONG")]);
    let (status, _) = call(&state, post_csrf("/api/comment", &body, Some(("u_alice", "alice@hf")))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "CSRF mismatch -> 401");

    // --- post a real top-level comment (creates the thread) ----------------
    let md = "First! **bold** <script>alert(1)</script> [x](javascript:alert(2))";
    let body = form(&[
        ("thread_key", "blog/hello"),
        ("title", "Hello World Post"),
        ("url", "https://blog.w33d.xyz/hello"),
        ("body", md),
        ("csrf_token", CSRF),
    ]);
    let resp = app(state.clone())
        .oneshot(post_csrf("/api/comment", &body, Some(("u_alice", "alice@hf"))))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = loc(&resp);
    assert_eq!(location, "/t/blog%2Fhello", "redirect back to the thread");

    // --- dashboard now lists the thread + activity -------------------------
    let (_, dash) = call(&state, get("/")).await;
    assert!(dash.contains("Hello World Post"), "thread title on dashboard");
    assert!(dash.contains("alice@hf"), "author in activity feed");

    // --- thread view renders sanitized markdown + the comment -------------
    let (status, view) = call(&state, get("/t/blog%2Fhello")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(view.contains("<strong>bold</strong>"), "markdown rendered");
    assert!(!view.contains("<script>alert(1)"), "raw script must be escaped");
    assert!(view.contains("&lt;script&gt;"), "script shown as escaped text");
    assert!(!view.contains("javascript:alert"), "js: link neutralized");
    assert!(view.contains("/api/comment"), "composer present");

    // --- capture the comment id from the moderation form -------------------
    let comment_id = extract_comment_id(&view).expect("comment id in thread view");

    // --- post a reply (one-level nesting) ----------------------------------
    let body = form(&[
        ("thread_key", "blog/hello"),
        ("body", "A reply to the first."),
        ("parent_id", &comment_id),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(&state, post_csrf("/api/comment", &body, Some(("u_bob", "bob@hf")))).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, view) = call(&state, get("/t/blog%2Fhello")).await;
    assert!(view.contains("A reply to the first."), "reply rendered");
    assert!(view.contains(r#"<div class="replies">"#), "reply is nested");

    // --- moderation: hide the first comment --------------------------------
    let body = form(&[
        ("comment_id", &comment_id),
        ("action", "hide"),
        ("return_to", "/t/blog%2Fhello"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(
        &state,
        post_csrf_g("/api/moderate", &body, Some(("u_mod", "mod@hf")), Some("moderators")),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, view) = call(&state, get("/t/blog%2Fhello")).await;
    assert!(view.contains("[comment hidden by a moderator]"), "hidden body replaced");
    assert!(!view.contains("First!"), "hidden comment body not shown");

    // --- moderation: unhide restores ---------------------------------------
    let body = form(&[
        ("comment_id", &comment_id),
        ("action", "unhide"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(
        &state,
        post_csrf_g("/api/moderate", &body, Some(("u_mod", "mod@hf")), Some("moderators")),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, view) = call(&state, get("/t/blog%2Fhello")).await;
    assert!(view.contains("First!"), "unhidden comment body restored");

    // --- moderation of a missing comment -> 404 ----------------------------
    let body = form(&[("comment_id", "cmt_nope"), ("action", "hide"), ("csrf_token", CSRF)]);
    let (status, _) = call(
        &state,
        post_csrf_g("/api/moderate", &body, Some(("u_mod", "mod@hf")), Some("moderators")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unknown comment -> 404");

    // --- empty body is rejected --------------------------------------------
    let body = form(&[("thread_key", "blog/hello"), ("body", "   "), ("csrf_token", CSRF)]);
    let (status, _) = call(&state, post_csrf("/api/comment", &body, Some(("u_alice", "alice@hf")))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "blank body -> 400");
}

#[tokio::test]
async fn embed_view_sets_frame_options() {
    let state = build_dev_state();
    let resp = app(state.clone()).oneshot(get("/embed/wiki%2Fpage")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let xfo = resp
        .headers()
        .get("x-frame-options")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(xfo, "SAMEORIGIN", "embed allows same-origin framing");
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8_lossy(&bytes);
    assert!(html.contains("page-embed"), "minimal embed chrome");
    assert!(html.contains("/api/comment"), "embed composer present");
}

#[tokio::test]
async fn reply_to_reply_clamps_to_one_level() {
    let state = build_dev_state();

    // top-level comment
    let body = form(&[("thread_key", "k"), ("body", "root"), ("csrf_token", CSRF)]);
    call(&state, post_csrf("/api/comment", &body, Some(("u1", "u1@hf")))).await;
    let (_, view) = call(&state, get("/t/k")).await;
    let root_id = extract_comment_id(&view).expect("root id");

    // a reply onto the root
    let body = form(&[("thread_key", "k"), ("body", "child"), ("parent_id", &root_id), ("csrf_token", CSRF)]);
    call(&state, post_csrf("/api/comment", &body, Some(("u2", "u2@hf")))).await;
    let (_, view) = call(&state, get("/t/k")).await;
    // the reply's own moderation form exposes its id; grab the first id after root in the replies block.
    let child_id = extract_nth_comment_id(&view, 1).expect("child id");
    assert_ne!(child_id, root_id);

    // a reply onto the reply -> must re-parent to the root, so the tree stays one level deep.
    let body = form(&[("thread_key", "k"), ("body", "grandchild"), ("parent_id", &child_id), ("csrf_token", CSRF)]);
    call(&state, post_csrf("/api/comment", &body, Some(("u3", "u3@hf")))).await;
    let (_, view) = call(&state, get("/t/k")).await;
    assert!(view.contains("grandchild"), "grandchild posted");
    // exactly one `.replies` container exists (no nested replies inside replies).
    assert_eq!(view.matches(r#"<div class="replies">"#).count(), 1, "only one nesting level");
}

#[tokio::test]
async fn moderation_requires_moderator_group() {
    let state = build_dev_state();

    // a plain commenter posts.
    let body = form(&[("thread_key", "k"), ("body", "hi"), ("csrf_token", CSRF)]);
    call(&state, post_csrf("/api/comment", &body, Some(("u_alice", "alice@hf")))).await;
    let (_, view) = call(&state, get("/t/k")).await;
    let id = extract_comment_id(&view).expect("comment id");

    // authenticated, correct CSRF, but NO moderator group -> 403 (the security fix).
    let mbody = form(&[("comment_id", &id), ("action", "hide"), ("csrf_token", CSRF)]);
    let (status, _) = call(&state, post_csrf("/api/moderate", &mbody, Some(("u_eve", "eve@hf")))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "non-moderator cannot moderate");

    // the hide was rejected, so the comment is NOT hidden.
    let (_, view) = call(&state, get("/t/k")).await;
    assert!(
        !view.contains("[comment hidden by a moderator]"),
        "rejected hide must not hide the comment"
    );

    // a member of `moderators` succeeds.
    let (status, _) = call(
        &state,
        post_csrf_g("/api/moderate", &mbody, Some(("u_mod", "mod@hf")), Some("moderators")),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "moderator group authorizes moderation");
    let (_, view) = call(&state, get("/t/k")).await;
    assert!(view.contains("[comment hidden by a moderator]"), "moderator hid the comment");

    // `infra-admins` (among other groups) is also authorized.
    let ubody = form(&[("comment_id", &id), ("action", "unhide"), ("csrf_token", CSRF)]);
    let (status, _) = call(
        &state,
        post_csrf_g("/api/moderate", &ubody, Some(("u_admin", "admin@hf")), Some("dev,infra-admins")),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "infra-admins authorizes moderation");
}

#[tokio::test]
async fn author_self_edit_and_delete() {
    let state = build_dev_state();

    // alice posts a comment.
    let body = form(&[("thread_key", "k"), ("body", "original text"), ("csrf_token", CSRF)]);
    call(&state, post_csrf("/api/comment", &body, Some(("u_alice", "alice@hf")))).await;
    let (_, view) = call(&state, get("/t/k")).await;
    let id = extract_comment_id(&view).expect("comment id");

    // the owner (viewer == author) sees self-edit + self-delete controls.
    let (_, owner_view) = call(&state, get_as("/t/k", "u_alice", "alice@hf")).await;
    assert!(owner_view.contains("/api/comment/edit"), "owner sees edit control");
    assert!(owner_view.contains("/api/comment/delete"), "owner sees delete control");

    // a different signed-in user does NOT see self controls on alice's comment.
    let (_, other_view) = call(&state, get_as("/t/k", "u_eve", "eve@hf")).await;
    assert!(!other_view.contains("/api/comment/edit"), "non-owner sees no edit control");
    assert!(!other_view.contains("/api/comment/delete"), "non-owner sees no delete control");

    // a non-owner cannot edit -> 404 (ownership enforced by the store).
    let ebody = form(&[("comment_id", &id), ("body", "hacked"), ("csrf_token", CSRF)]);
    let (status, _) = call(&state, post_csrf("/api/comment/edit", &ebody, Some(("u_eve", "eve@hf")))).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "non-owner edit rejected");
    let (_, view) = call(&state, get("/t/k")).await;
    assert!(view.contains("original text") && !view.contains("hacked"), "body unchanged");

    // edit requires CSRF: a mismatched form token (cookie is CSRF) -> 401, even for the owner.
    let bad = form(&[("comment_id", &id), ("body", "x"), ("csrf_token", "WRONG")]);
    let (status, _) = call(&state, post_csrf("/api/comment/edit", &bad, Some(("u_alice", "alice@hf")))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "edit CSRF mismatch -> 401");

    // the owner edits successfully.
    let ebody = form(&[("comment_id", &id), ("body", "edited text"), ("csrf_token", CSRF)]);
    let (status, _) = call(&state, post_csrf("/api/comment/edit", &ebody, Some(("u_alice", "alice@hf")))).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "owner edit ok");
    let (_, view) = call(&state, get("/t/k")).await;
    assert!(view.contains("edited text"), "edited body shown");
    assert!(!view.contains("original text"), "old body gone");

    // a non-owner cannot delete -> 404.
    let dbody = form(&[("comment_id", &id), ("csrf_token", CSRF)]);
    let (status, _) = call(&state, post_csrf("/api/comment/delete", &dbody, Some(("u_eve", "eve@hf")))).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "non-owner delete rejected");
    let (_, view) = call(&state, get("/t/k")).await;
    assert!(view.contains("edited text"), "comment still present after rejected delete");

    // the owner deletes their own comment.
    let (status, _) = call(&state, post_csrf("/api/comment/delete", &dbody, Some(("u_alice", "alice@hf")))).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "owner delete ok");
    let (_, view) = call(&state, get("/t/k")).await;
    assert!(!view.contains("edited text"), "comment removed");
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

async fn call(state: &echo::AppState, req: Request<Body>) -> (StatusCode, String) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

fn loc(resp: &axum::response::Response) -> String {
    resp.headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

/// Build a urlencoded POST carrying the test CSRF cookie + (optionally) gateway identity.
fn post_csrf(uri: &str, body: &str, ident: Option<(&str, &str)>) -> Request<Body> {
    post_csrf_g(uri, body, ident, None)
}

/// As [`post_csrf`], but also inject an `X-Auth-Groups` header (comma-separated) — used to exercise
/// the moderator-group gate on `/api/moderate`.
fn post_csrf_g(
    uri: &str,
    body: &str,
    ident: Option<(&str, &str)>,
    groups: Option<&str>,
) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={CSRF}"));
    if let Some((sub, email)) = ident {
        b = b.header("x-auth-subject", sub).header("x-auth-email", email);
    }
    if let Some(g) = groups {
        b = b.header("x-auth-groups", g);
    }
    b.body(Body::from(body.to_string())).unwrap()
}

/// A GET carrying gateway identity (so the render knows the viewer) + the test CSRF cookie.
fn get_as(uri: &str, sub: &str, email: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("x-auth-subject", sub)
        .header("x-auth-email", email)
        .header(header::COOKIE, format!("__Host-csrf={CSRF}"))
        .body(Body::empty())
        .unwrap()
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

/// Pull the first `comment_id` value out of a rendered moderation form.
fn extract_comment_id(html: &str) -> Option<String> {
    extract_nth_comment_id(html, 0)
}

/// Pull the n-th (0-based) distinct `comment_id` value out of the rendered moderation forms.
fn extract_nth_comment_id(html: &str, n: usize) -> Option<String> {
    let needle = r#"name="comment_id" value=""#;
    let mut found = Vec::new();
    let mut rest = html;
    while let Some(i) = rest.find(needle) {
        let after = &rest[i + needle.len()..];
        let end = after.find('"')?;
        let id = after[..end].to_string();
        if !found.contains(&id) {
            found.push(id);
        }
        rest = &after[end..];
    }
    found.into_iter().nth(n)
}
