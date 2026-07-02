//! End-to-end HTTP flow for the `/admin` subtree over the in-memory store (NO database).
//!
//! Covers: admin gating (403 for a non-admin, 200 for an admin), bulk hide / unhide / delete-any,
//! and the author blocklist (blocking hides existing comments AND rejects new ones; unblocking
//! restores and re-permits). Drives the real `app` router via `tower::oneshot`.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use echo::{app, build_dev_state};
use tower::ServiceExt;

const CSRF: &str = "tok_csrf_for_tests";

// ---------------------------------------------------------------------------
// Admin gating
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_dashboard_is_gated_to_admins() {
    let state = build_dev_state();

    // No identity at all -> not an admin -> 403.
    let (status, _) = call(&state, get_g("/admin", None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "anonymous cannot see /admin");

    // Ordinary signed-in user (non-admin groups) -> 403.
    let (status, _) = call(
        &state,
        get_g(
            "/admin",
            Some(("u_eve", "eve@hf")),
            Some("readers,moderators"),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "non-admin user cannot see /admin"
    );

    // `admins` group -> 200 and the panel renders.
    let (status, body) = call(
        &state,
        get_g("/admin", Some(("u_root", "root@hf")), Some("admins")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "admins group unlocks /admin");
    assert!(body.contains("Moderation"), "panel heading rendered");
    assert!(body.contains("/admin/block"), "block form present");

    // `infra-admins` also unlocks it.
    let (status, _) = call(
        &state,
        get_g(
            "/admin",
            Some(("u_ops", "ops@hf")),
            Some("dev,infra-admins"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "infra-admins group unlocks /admin");
}

#[tokio::test]
async fn admin_moderate_is_gated_and_csrf_protected() {
    let state = build_dev_state();
    seed_comment(&state, "k", "hello", ("u_alice", "alice@hf")).await;
    let (_, view) = call(&state, get("/t/k")).await;
    let id = extract_comment_id(&view).expect("comment id");

    // Non-admin cannot bulk-moderate -> 403 (gating runs before CSRF).
    let body = form(&[
        ("comment_id", &id),
        ("action", "hide"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(
        &state,
        post_g(
            "/admin/moderate",
            &body,
            Some(("u_eve", "eve@hf")),
            Some("moderators"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "non-admin cannot moderate");

    // Admin but bad CSRF -> 401.
    let bad = form(&[
        ("comment_id", &id),
        ("action", "hide"),
        ("csrf_token", "WRONG"),
    ]);
    let (status, _) = call(
        &state,
        post_g(
            "/admin/moderate",
            &bad,
            Some(("u_root", "root@hf")),
            Some("admins"),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "admin CSRF mismatch -> 401"
    );
}

// ---------------------------------------------------------------------------
// Bulk moderation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_bulk_hide_unhide_and_delete() {
    let state = build_dev_state();
    seed_comment(&state, "k", "one", ("u_a", "a@hf")).await;
    seed_comment(&state, "k", "two", ("u_b", "b@hf")).await;
    let (_, view) = call(&state, get("/t/k")).await;
    let id0 = extract_nth_comment_id(&view, 0).expect("id0");
    let id1 = extract_nth_comment_id(&view, 1).expect("id1");

    // Bulk HIDE both (repeated comment_id survives the pair decoding).
    let body = form(&[
        ("comment_id", &id0),
        ("comment_id", &id1),
        ("action", "hide"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = admin_post(&state, "/admin/moderate", &body).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, view) = call(&state, get("/t/k")).await;
    assert_eq!(
        view.matches("[comment hidden by a moderator]").count(),
        2,
        "both comments hidden"
    );

    // Bulk UNHIDE just the first.
    let body = form(&[
        ("comment_id", &id0),
        ("action", "unhide"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = admin_post(&state, "/admin/moderate", &body).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, view) = call(&state, get("/t/k")).await;
    assert!(view.contains("one"), "first comment restored");
    assert!(
        view.contains("[comment hidden by a moderator]"),
        "second still hidden"
    );

    // DELETE-ANY the second (admin deletes a comment it does not own).
    let body = form(&[
        ("comment_id", &id1),
        ("action", "delete"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = admin_post(&state, "/admin/moderate", &body).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, view) = call(&state, get("/t/k")).await;
    assert!(!view.contains("two"), "second comment deleted");
    assert!(view.contains("one"), "first comment remains");

    // An unknown action is rejected.
    let body = form(&[
        ("comment_id", &id0),
        ("action", "nuke"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = admin_post(&state, "/admin/moderate", &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unknown action -> 400");

    // No selection is rejected.
    let body = form(&[("action", "hide"), ("csrf_token", CSRF)]);
    let (status, _) = admin_post(&state, "/admin/moderate", &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "empty selection -> 400");
}

// ---------------------------------------------------------------------------
// Blocklist
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_block_hides_and_rejects_then_unblock_restores() {
    let state = build_dev_state();
    seed_comment(&state, "k", "spammy comment", ("u_spam", "spam@hf")).await;

    // Block the author.
    let body = form(&[
        ("author_sub", "u_spam"),
        ("reason", "spam"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = admin_post(&state, "/admin/block", &body).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "block ok");

    // Their existing comment is now hidden.
    let (_, view) = call(&state, get("/t/k")).await;
    assert!(
        view.contains("[comment hidden by a moderator]"),
        "block hid the author's existing comment"
    );
    assert!(!view.contains("spammy comment"), "hidden body not shown");

    // The blocklist shows the author on the admin panel.
    let (_, admin) = call(
        &state,
        get_g("/admin", Some(("u_root", "root@hf")), Some("admins")),
    )
    .await;
    assert!(admin.contains("u_spam"), "author listed on the blocklist");

    // A NEW comment from the blocked author is rejected -> 403.
    let body = form(&[("thread_key", "k"), ("body", "again"), ("csrf_token", CSRF)]);
    let (status, _) = call(
        &state,
        post_g("/api/comment", &body, Some(("u_spam", "spam@hf")), None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "blocked author cannot post");

    // A different author is unaffected.
    let body = form(&[("thread_key", "k"), ("body", "legit"), ("csrf_token", CSRF)]);
    let (status, _) = call(
        &state,
        post_g("/api/comment", &body, Some(("u_ok", "ok@hf")), None),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "unblocked author still posts"
    );

    // Unblock restores the author's comment and re-permits posting.
    let body = form(&[("author_sub", "u_spam"), ("csrf_token", CSRF)]);
    let (status, _) = admin_post(&state, "/admin/unblock", &body).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "unblock ok");
    let (_, view) = call(&state, get("/t/k")).await;
    assert!(
        view.contains("spammy comment"),
        "unblock restored the comment"
    );

    let body = form(&[
        ("thread_key", "k"),
        ("body", "back again"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(
        &state,
        post_g("/api/comment", &body, Some(("u_spam", "spam@hf")), None),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "unblocked author can post again"
    );

    // Unblocking a never-blocked author -> 404.
    let body = form(&[("author_sub", "u_nobody"), ("csrf_token", CSRF)]);
    let (status, _) = admin_post(&state, "/admin/unblock", &body).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unknown block -> 404");
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

#[tokio::test]
async fn report_comment_surfaces_in_admin_queue() {
    let state = build_dev_state();
    seed_comment(&state, "k", "reportable comment", ("u_alice", "alice@hf")).await;
    let (_, view) = call(&state, get("/t/k")).await;
    let id = extract_comment_id(&view).expect("comment id");

    // No identity -> 401.
    let body = form(&[
        ("comment_id", &id),
        ("reason", "spam"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(&state, post_g("/api/comment/report", &body, None, None)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "report needs SSO identity"
    );

    // Bad CSRF -> 401.
    let bad = form(&[
        ("comment_id", &id),
        ("reason", "spam"),
        ("csrf_token", "WRONG"),
    ]);
    let (status, _) = call(
        &state,
        post_g("/api/comment/report", &bad, Some(("u_bob", "bob@hf")), None),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "report needs CSRF");

    // Blank reason -> 400.
    let blank = form(&[("comment_id", &id), ("reason", "   "), ("csrf_token", CSRF)]);
    let (status, _) = call(
        &state,
        post_g(
            "/api/comment/report",
            &blank,
            Some(("u_bob", "bob@hf")),
            None,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "blank report reason rejected"
    );

    // Missing comment -> 404.
    let miss = form(&[
        ("comment_id", "cmt_nope"),
        ("reason", "spam"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(
        &state,
        post_g(
            "/api/comment/report",
            &miss,
            Some(("u_bob", "bob@hf")),
            None,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "report on missing comment -> 404"
    );

    // First report is stored and rendered in the existing admin moderation queue.
    let reason = "rude <script>alert(1)</script>";
    let body = form(&[
        ("comment_id", &id),
        ("reason", reason),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(
        &state,
        post_g(
            "/api/comment/report",
            &body,
            Some(("u_bob", "bob@hf")),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "report ok");

    let (_, admin) = call(
        &state,
        get_g("/admin", Some(("u_root", "root@hf")), Some("admins")),
    )
    .await;
    assert!(admin.contains("1 report"), "report count shown");
    assert!(admin.contains("rude &lt;script&gt;"), "reason is escaped");
    assert!(
        !admin.contains("<script>alert"),
        "raw reason never rendered"
    );

    // Same reporter updates their one row; count stays 1 and the reason changes.
    let update = form(&[
        ("comment_id", &id),
        ("reason", "updated reason"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(
        &state,
        post_g(
            "/api/comment/report",
            &update,
            Some(("u_bob", "bob@hf")),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "report update ok");
    let (_, admin) = call(
        &state,
        get_g("/admin", Some(("u_root", "root@hf")), Some("admins")),
    )
    .await;
    assert!(
        admin.contains("1 report"),
        "same reporter still counts once"
    );
    assert!(admin.contains("updated reason"), "updated reason shown");

    // A second reporter increments the count.
    let second = form(&[
        ("comment_id", &id),
        ("reason", "harassment"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(
        &state,
        post_g(
            "/api/comment/report",
            &second,
            Some(("u_carol", "carol@hf")),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "second reporter ok");
    let (_, admin) = call(
        &state,
        get_g("/admin", Some(("u_root", "root@hf")), Some("admins")),
    )
    .await;
    assert!(admin.contains("2 reports"), "two reporters counted");
    assert!(admin.contains("harassment"), "second reason shown");
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

async fn call(state: &echo::AppState, req: Request<Body>) -> (StatusCode, String) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

/// Post a real top-level comment as `ident`, creating the thread on first post.
async fn seed_comment(state: &echo::AppState, key: &str, body: &str, ident: (&str, &str)) {
    let b = form(&[("thread_key", key), ("body", body), ("csrf_token", CSRF)]);
    let (status, _) = call(state, post_g("/api/comment", &b, Some(ident), None)).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "seed comment posted");
}

/// A `POST /admin/...` as an `admins`-group user with the test CSRF cookie.
async fn admin_post(state: &echo::AppState, uri: &str, body: &str) -> (StatusCode, String) {
    call(
        state,
        post_g(uri, body, Some(("u_root", "root@hf")), Some("admins")),
    )
    .await
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

/// A GET carrying optional gateway identity + optional groups + the test CSRF cookie.
fn get_g(uri: &str, ident: Option<(&str, &str)>, groups: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .uri(uri)
        .header(header::COOKIE, format!("__Host-csrf={CSRF}"));
    if let Some((sub, email)) = ident {
        b = b
            .header("x-auth-subject", sub)
            .header("x-auth-email", email);
    }
    if let Some(g) = groups {
        b = b.header("x-auth-groups", g);
    }
    b.body(Body::empty()).unwrap()
}

/// A urlencoded POST carrying the test CSRF cookie + optional gateway identity + optional groups.
fn post_g(
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
        b = b
            .header("x-auth-subject", sub)
            .header("x-auth-email", email);
    }
    if let Some(g) = groups {
        b = b.header("x-auth-groups", g);
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

fn enc(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                o.push(b as char)
            }
            b' ' => o.push('+'),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

fn extract_comment_id(html: &str) -> Option<String> {
    extract_nth_comment_id(html, 0)
}

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
