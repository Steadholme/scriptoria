//! End-to-end admin-panel flow over the in-memory store (no database).
//!
//! Drives the real `app` Router via `tower::oneshot`, like `forum_flow`. Covers: the `/admin`
//! subtree group-gate (403 for non-admins, allowed for admins), and each mutation — category
//! CRUD, thread lock/pin/move/delete, any-post deletion, and the author blocklist — plus the
//! honoring of `locked` (no new replies), `pinned` (sorts first), and a ban (rejects posting).

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use tower::ServiceExt;

use agora::{app, build_dev_state, AppState};

const TOK: &str = "csrftoken123";
const ADMIN_GROUPS: &str = "admins";
const ALICE_SUB: &str = "u_sub_1";
const ALICE_EMAIL: &str = "alice@holdfast.local";

// ---------------------------------------------------------------------------
// Gate: non-admins are refused, admins pass
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_dashboard_is_group_gated() {
    let state = build_dev_state().await;

    // Signed-in but NO admin group -> 403.
    let (status, _h, _b) = send(&state, get_as("/admin", ALICE_SUB, ALICE_EMAIL, "")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Unauthenticated entirely -> still 403.
    let (status, _h, _b) = send(&state, get("/admin")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // An admin sees the panel.
    let (status, _h, body) = send(&state, get_as("/admin", ALICE_SUB, ALICE_EMAIL, ADMIN_GROUPS)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Admin"));
    assert!(body.contains("Categories"));
    assert!(body.contains("Blocked authors"));
}

#[tokio::test]
async fn admin_mutation_is_group_gated() {
    let state = build_dev_state().await;
    // Valid CSRF but non-admin -> 403 before any mutation runs.
    let body = form(&[("csrf", TOK), ("id", "ideas"), ("name", "Ideas")]);
    let (status, _h, _b) =
        send(&state, post_admin("/admin/categories", TOK, "readers", body)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // The category was NOT created.
    let (_s, _h, home) = send(&state, get("/")).await;
    assert!(!home.contains("Ideas"));
}

// ---------------------------------------------------------------------------
// Category CRUD
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_category_create_rename_reorder_delete() {
    let state = build_dev_state().await;

    // Create.
    let body = form(&[("csrf", TOK), ("id", "ideas"), ("name", "Ideas")]);
    let (s, _h, _b) = send(&state, post_admin("/admin/categories", TOK, ADMIN_GROUPS, body)).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let (_s, _h, home) = send(&state, get("/")).await;
    assert!(home.contains("Ideas"), "new category shown on home");

    // Duplicate id is rejected.
    let dup = form(&[("csrf", TOK), ("id", "ideas"), ("name", "Ideas 2")]);
    let (s, _h, _b) = send(&state, post_admin("/admin/categories", TOK, ADMIN_GROUPS, dup)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Rename.
    let body = form(&[("csrf", TOK), ("name", "Bright Ideas")]);
    let (s, _h, _b) =
        send(&state, post_admin("/admin/categories/ideas/rename", TOK, ADMIN_GROUPS, body)).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let (_s, _h, home) = send(&state, get("/")).await;
    assert!(home.contains("Bright Ideas"));

    // Reorder (up) — just needs to succeed.
    let body = form(&[("csrf", TOK), ("dir", "up")]);
    let (s, _h, _b) =
        send(&state, post_admin("/admin/categories/ideas/reorder", TOK, ADMIN_GROUPS, body)).await;
    assert_eq!(s, StatusCode::SEE_OTHER);

    // Delete (empty category → allowed).
    let body = form(&[("csrf", TOK)]);
    let (s, _h, _b) =
        send(&state, post_admin("/admin/categories/ideas/delete", TOK, ADMIN_GROUPS, body)).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let (_s, _h, home) = send(&state, get("/")).await;
    assert!(!home.contains("Bright Ideas"), "category gone after delete");
}

#[tokio::test]
async fn admin_cannot_delete_nonempty_category() {
    let state = build_dev_state().await;
    // "general" is seeded and about to hold a thread.
    let _loc = create_thread(&state, "In general", "body").await;
    let body = form(&[("csrf", TOK)]);
    let (s, _h, _b) =
        send(&state, post_admin("/admin/categories/general/delete", TOK, ADMIN_GROUPS, body)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "non-empty category delete refused");
}

// ---------------------------------------------------------------------------
// Thread moderation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_lock_blocks_new_replies() {
    let state = build_dev_state().await;
    let loc = create_thread(&state, "Lock me", "op").await;
    let tid = loc.strip_prefix("/t/").unwrap().to_string();

    // Lock the thread.
    let (s, _h, _b) = send(
        &state,
        post_admin(&format!("/admin/threads/{tid}/lock"), TOK, ADMIN_GROUPS, form(&[("csrf", TOK)])),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);

    // The thread page shows the locked notice and hides the reply form.
    let (_s, _h, page) = send(&state, get(&loc)).await;
    assert!(page.contains("locked"), "locked state visible");
    assert!(
        !page.contains(&format!(r#"action="/t/{tid}/reply""#)),
        "no reply form action on a locked thread"
    );

    // A reply is now refused.
    let reply = form(&[("csrf", TOK), ("body", "late reply")]);
    let (s, _h, _b) =
        send(&state, post_as(&format!("{loc}/reply"), TOK, ALICE_SUB, ALICE_EMAIL, "", reply)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Unlock → replies work again.
    let (s, _h, _b) = send(
        &state,
        post_admin(&format!("/admin/threads/{tid}/lock"), TOK, ADMIN_GROUPS, form(&[("csrf", TOK)])),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let reply = form(&[("csrf", TOK), ("body", "now allowed")]);
    let (s, _h, _b) =
        send(&state, post_as(&format!("{loc}/reply"), TOK, ALICE_SUB, ALICE_EMAIL, "", reply)).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn admin_pin_sorts_thread_first() {
    let state = build_dev_state().await;
    // A is created first; B second (a full second later, so its last_at is strictly greater and
    // the ordering is deterministic), so B is normally newer/first on the home list.
    let loc_a = create_thread(&state, "Alpha thread", "a").await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let _loc_b = create_thread(&state, "Beta thread", "b").await;
    let tid_a = loc_a.strip_prefix("/t/").unwrap().to_string();

    // Without a pin, Beta (newer) sorts before Alpha.
    let (_s, _h, home) = send(&state, get("/")).await;
    assert!(
        home.find("Beta thread").unwrap() < home.find("Alpha thread").unwrap(),
        "newer thread first before pinning"
    );

    // Pin Alpha → it now sorts first.
    let (s, _h, _b) = send(
        &state,
        post_admin(&format!("/admin/threads/{tid_a}/pin"), TOK, ADMIN_GROUPS, form(&[("csrf", TOK)])),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let (_s, _h, home) = send(&state, get("/")).await;
    assert!(
        home.find("Alpha thread").unwrap() < home.find("Beta thread").unwrap(),
        "pinned thread sorts first"
    );
}

#[tokio::test]
async fn admin_move_thread_between_categories() {
    let state = build_dev_state().await;
    let loc = create_thread(&state, "Movable", "op").await; // starts in "general"
    let tid = loc.strip_prefix("/t/").unwrap().to_string();

    let body = form(&[("csrf", TOK), ("category", "support")]);
    let (s, _h, _b) =
        send(&state, post_admin(&format!("/admin/threads/{tid}/move"), TOK, ADMIN_GROUPS, body)).await;
    assert_eq!(s, StatusCode::SEE_OTHER);

    let (_s, _h, support) = send(&state, get("/c/support")).await;
    assert!(support.contains("Movable"), "thread now under support");
    let (_s, _h, general) = send(&state, get("/c/general")).await;
    assert!(!general.contains("Movable"), "thread left general");

    // Moving to an unknown category is rejected.
    let bad = form(&[("csrf", TOK), ("category", "nope")]);
    let (s, _h, _b) =
        send(&state, post_admin(&format!("/admin/threads/{tid}/move"), TOK, ADMIN_GROUPS, bad)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn admin_delete_any_thread_and_post() {
    let state = build_dev_state().await;
    let loc = create_thread(&state, "Doomed", "op body").await;
    let tid = loc.strip_prefix("/t/").unwrap().to_string();

    // Add a reply from another author, then admin deletes THAT post (not the admin's own).
    let reply = form(&[("csrf", TOK), ("body", "a reply")]);
    let (s, _h, _b) =
        send(&state, post_as(&format!("{loc}/reply"), TOK, "u_bob", "bob@holdfast.local", "", reply)).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let posts = state
        .store
        .posts_in_thread(&tid)
        .await
        .unwrap();
    let op_id = posts.first().unwrap().id.clone();
    let pid = posts
        .into_iter()
        .find(|p| p.author_sub == "u_bob")
        .unwrap()
        .id;

    // The OP owns the thread identity. Even an admin must use Delete thread, otherwise the thread
    // author could gain edit authority over a promoted reply written by someone else.
    let (s, _h, body) = send(
        &state,
        post_admin(
            &format!("/admin/posts/{op_id}/delete"),
            TOK,
            ADMIN_GROUPS,
            form(&[("csrf", TOK)]),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "admin cannot delete OP alone");
    assert!(body.contains("delete the thread"));
    assert_eq!(state.store.count_posts(&tid).await.unwrap(), 2);

    let (s, _h, _b) = send(
        &state,
        post_admin(&format!("/admin/posts/{pid}/delete"), TOK, ADMIN_GROUPS, form(&[("csrf", TOK)])),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(state.store.count_posts(&tid).await.unwrap(), 1, "reply deleted by admin");

    // Now admin deletes the whole thread.
    let (s, _h, _b) = send(
        &state,
        post_admin(&format!("/admin/threads/{tid}/delete"), TOK, ADMIN_GROUPS, form(&[("csrf", TOK)])),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let (s, _h, _b) = send(&state, get(&loc)).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "thread gone");
    let (_s, _h, search) = send(&state, get("/search?q=body")).await;
    assert!(
        !search.contains("Doomed"),
        "Delete thread removes its OP text from SSR search"
    );
    let (_s, _h, suggestions) = send(&state, get("/api/search/suggest?q=body")).await;
    let suggestions: serde_json::Value = serde_json::from_str(&suggestions).unwrap();
    assert!(
        suggestions["results"].as_array().unwrap().is_empty(),
        "Delete thread removes its OP text from suggestions"
    );
}

// ---------------------------------------------------------------------------
// Author blocklist
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_ban_rejects_posting_until_unbanned() {
    let state = build_dev_state().await;

    // Ban alice.
    let body = form(&[("csrf", TOK), ("author_sub", ALICE_SUB), ("reason", "spam")]);
    let (s, _h, _b) = send(&state, post_admin("/admin/bans", TOK, ADMIN_GROUPS, body)).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert!(state.store.is_banned(ALICE_SUB).await.unwrap());

    // Alice can no longer create a thread.
    let create = form(&[("csrf", TOK), ("category", "general"), ("title", "T"), ("body", "B")]);
    let (s, _h, _b) = send(&state, post_as("/new", TOK, ALICE_SUB, ALICE_EMAIL, "", create)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // The ban shows on the dashboard.
    let (_s, _h, dash) = send(&state, get_as("/admin", ALICE_SUB, ALICE_EMAIL, ADMIN_GROUPS)).await;
    assert!(dash.contains(ALICE_SUB));
    assert!(dash.contains("spam"));

    // Unban → alice can post again.
    let enc_sub = ALICE_SUB; // no reserved chars
    let (s, _h, _b) = send(
        &state,
        post_admin(&format!("/admin/bans/{enc_sub}/delete"), TOK, ADMIN_GROUPS, form(&[("csrf", TOK)])),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert!(!state.store.is_banned(ALICE_SUB).await.unwrap());
    let create = form(&[("csrf", TOK), ("category", "general"), ("title", "T"), ("body", "B")]);
    let (s, _h, _b) = send(&state, post_as("/new", TOK, ALICE_SUB, ALICE_EMAIL, "", create)).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

async fn send(state: &AppState, req: Request<Body>) -> (StatusCode, HeaderMap, String) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, headers, String::from_utf8(bytes.to_vec()).unwrap())
}

/// Create a thread as alice in "general"; return its `/t/{id}` location.
async fn create_thread(state: &AppState, title: &str, body_md: &str) -> String {
    let body = form(&[("csrf", TOK), ("category", "general"), ("title", title), ("body", body_md)]);
    let (status, h, _b) = send(state, post_as("/new", TOK, ALICE_SUB, ALICE_EMAIL, "", body)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    h.get(header::LOCATION).unwrap().to_str().unwrap().to_string()
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

/// GET as a specific identity + groups (so admin/owner controls render).
fn get_as(uri: &str, subject: &str, email: &str, groups: &str) -> Request<Body> {
    let mut b = Request::builder()
        .uri(uri)
        .header("x-auth-subject", subject)
        .header("x-auth-email", email);
    if !groups.is_empty() {
        b = b.header("x-auth-groups", groups);
    }
    b.body(Body::empty()).unwrap()
}

/// POST into the `/admin` subtree as an admin (subject alice + the given groups) with a matching
/// CSRF cookie.
fn post_admin(uri: &str, tok: &str, groups: &str, body: String) -> Request<Body> {
    post_as(uri, tok, ALICE_SUB, ALICE_EMAIL, groups, body)
}

/// POST with a matching CSRF cookie, a gateway identity, and optional groups.
fn post_as(uri: &str, tok: &str, subject: &str, email: &str, groups: &str, body: String) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={tok}"))
        .header("x-auth-subject", subject)
        .header("x-auth-email", email);
    if !groups.is_empty() {
        b = b.header("x-auth-groups", groups);
    }
    b.body(Body::from(body)).unwrap()
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
