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
const ALICE_EMAIL: &str = "alice@steadholme.local";

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
    let (status, _h, body) = send(
        &state,
        get_as("/admin", ALICE_SUB, ALICE_EMAIL, ADMIN_GROUPS),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(r#"<h1 class="ag-head__title">Administration</h1>"#));
    assert!(body.contains(r#"id="ag-admin-categories-title">Categories</h2>"#));
    assert!(body.contains(r#"id="ag-admin-bans-title">Banned authors</h2>"#));
}

#[tokio::test]
async fn admin_mutation_is_group_gated() {
    let state = build_dev_state().await;
    // Valid CSRF but non-admin -> 403 before any mutation runs.
    let body = form(&[("csrf", TOK), ("id", "ideas"), ("name", "Ideas")]);
    let (status, _h, _b) = send(
        &state,
        post_admin("/admin/categories", TOK, "readers", body),
    )
    .await;
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
    let (s, _h, _b) = send(
        &state,
        post_admin("/admin/categories", TOK, ADMIN_GROUPS, body),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let (_s, _h, home) = send(&state, get("/")).await;
    assert!(home.contains("Ideas"), "new category shown on home");

    // Duplicate id is rejected.
    let dup = form(&[("csrf", TOK), ("id", "ideas"), ("name", "Ideas 2")]);
    let (s, _h, _b) = send(
        &state,
        post_admin("/admin/categories", TOK, ADMIN_GROUPS, dup),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Rename.
    let body = form(&[("csrf", TOK), ("name", "Bright Ideas")]);
    let (s, _h, _b) = send(
        &state,
        post_admin("/admin/categories/ideas/rename", TOK, ADMIN_GROUPS, body),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let (_s, _h, home) = send(&state, get("/")).await;
    assert!(home.contains("Bright Ideas"));

    // Reorder (up) — just needs to succeed.
    let body = form(&[("csrf", TOK), ("dir", "up")]);
    let (s, _h, _b) = send(
        &state,
        post_admin("/admin/categories/ideas/reorder", TOK, ADMIN_GROUPS, body),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);

    let delete_uri = "/admin/categories/ideas/delete";

    // A direct POST cannot skip the destructive-action review.
    let body = form(&[("csrf", TOK)]);
    let (s, _h, _b) = send(&state, post_admin(delete_uri, TOK, ADMIN_GROUPS, body)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(state.store.get_category("ideas").await.unwrap().is_some());

    // The same-path GET supplies the CSRF + actor/action-bound confirmation.
    let review = delete_review_admin(&state, delete_uri, None).await;

    let wrong_csrf = "category-wrong-csrf";
    let (s, _h, _b) = send(
        &state,
        post_admin(
            delete_uri,
            wrong_csrf,
            ADMIN_GROUPS,
            confirmation_form(wrong_csrf, &review.confirm),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(state.store.get_category("ideas").await.unwrap().is_some());

    let (s, _h, _b) = send(
        &state,
        post_admin(
            delete_uri,
            &review.csrf,
            ADMIN_GROUPS,
            confirmation_form(&review.csrf, "malformed-confirmation"),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(state.store.get_category("ideas").await.unwrap().is_some());

    // Only the exact review tuple deletes the empty category.
    let (s, h, _b) = send(
        &state,
        post_admin(
            delete_uri,
            &review.csrf,
            ADMIN_GROUPS,
            confirmation_form(&review.csrf, &review.confirm),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(h.get(header::LOCATION).unwrap().to_str().unwrap(), "/admin");
    let (_s, _h, home) = send(&state, get("/")).await;
    assert!(!home.contains("Bright Ideas"), "category gone after delete");
}

#[tokio::test]
async fn admin_cannot_delete_nonempty_category() {
    let state = build_dev_state().await;
    // "general" is seeded and about to hold a thread.
    let _loc = create_thread(&state, "In general", "body").await;
    let delete_uri = "/admin/categories/general/delete";
    let (s, _h, body) = send(
        &state,
        get_as(delete_uri, ALICE_SUB, ALICE_EMAIL, ADMIN_GROUPS),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "non-empty category never receives a delete confirmation"
    );
    assert!(body.contains("move or delete them first"));
    assert!(state.store.get_category("general").await.unwrap().is_some());
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
        post_admin(
            &format!("/admin/threads/{tid}/lock"),
            TOK,
            ADMIN_GROUPS,
            form(&[("csrf", TOK), ("state", "locked")]),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);

    // The server-issued action names its target state, so a duplicate/stale retry is a no-op,
    // never an accidental unlock.
    let (s, _h, _b) = send(
        &state,
        post_admin(
            &format!("/admin/threads/{tid}/lock"),
            TOK,
            ADMIN_GROUPS,
            form(&[("csrf", TOK), ("state", "locked")]),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert!(state.store.get_thread(&tid).await.unwrap().unwrap().locked);

    // The thread page shows the locked notice and hides the reply form.
    let (_s, _h, page) = send(&state, get(&loc)).await;
    assert!(
        page.contains(
            r#"<span class="badge ag-chip-shared ag-flag ag-flag--locked">Locked</span>"#
        ),
        "shared locked state is visible"
    );
    assert!(
        page.contains(r#"<div class="card pad ag-locked-notice" role="status">"#),
        "the typed reply boundary renders its locked notice"
    );
    assert!(
        !page.contains(&format!(r#"action="/t/{tid}/reply""#)),
        "no reply form action on a locked thread"
    );
    assert!(
        !page.contains(r#"class="ag-form ag-reply-form""#),
        "the typed view does not render a reply composer"
    );
    assert!(
        !page.contains("?quote="),
        "a locked thread does not offer a Quote shortcut to the absent reply composer"
    );

    // A reply is now refused.
    let reply = form(&[("csrf", TOK), ("body", "late reply")]);
    let (s, _h, _b) = send(
        &state,
        post_as(
            &format!("{loc}/reply"),
            TOK,
            ALICE_SUB,
            ALICE_EMAIL,
            "",
            reply,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Unlock → replies work again.
    let (s, _h, _b) = send(
        &state,
        post_admin(
            &format!("/admin/threads/{tid}/lock"),
            TOK,
            ADMIN_GROUPS,
            form(&[("csrf", TOK), ("state", "unlocked")]),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let (s, _h, _b) = send(
        &state,
        post_admin(
            &format!("/admin/threads/{tid}/lock"),
            TOK,
            ADMIN_GROUPS,
            form(&[("csrf", TOK), ("state", "unlocked")]),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert!(!state.store.get_thread(&tid).await.unwrap().unwrap().locked);
    let (_s, _h, unlocked_page) = send(&state, get(&loc)).await;
    assert!(
        unlocked_page.contains("?quote="),
        "unlocking restores the post-level Quote action"
    );
    let reply = form(&[("csrf", TOK), ("body", "now allowed")]);
    let (s, _h, _b) = send(
        &state,
        post_as(
            &format!("{loc}/reply"),
            TOK,
            ALICE_SUB,
            ALICE_EMAIL,
            "",
            reply,
        ),
    )
    .await;
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
        post_admin(
            &format!("/admin/threads/{tid_a}/pin"),
            TOK,
            ADMIN_GROUPS,
            form(&[("csrf", TOK), ("state", "pinned")]),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let (s, _h, _b) = send(
        &state,
        post_admin(
            &format!("/admin/threads/{tid_a}/pin"),
            TOK,
            ADMIN_GROUPS,
            form(&[("csrf", TOK), ("state", "pinned")]),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert!(
        state
            .store
            .get_thread(&tid_a)
            .await
            .unwrap()
            .unwrap()
            .pinned
    );
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
    let (s, _h, _b) = send(
        &state,
        post_admin(
            &format!("/admin/threads/{tid}/move"),
            TOK,
            ADMIN_GROUPS,
            body,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);

    let (_s, _h, support) = send(&state, get("/c/support")).await;
    assert!(support.contains("Movable"), "thread now under support");
    let (_s, _h, general) = send(&state, get("/c/general")).await;
    assert!(!general.contains("Movable"), "thread left general");

    // Moving to an unknown category is rejected.
    let bad = form(&[("csrf", TOK), ("category", "nope")]);
    let (s, _h, _b) = send(
        &state,
        post_admin(
            &format!("/admin/threads/{tid}/move"),
            TOK,
            ADMIN_GROUPS,
            bad,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn admin_delete_any_thread_and_post() {
    let state = build_dev_state().await;
    let loc = create_thread(&state, "Doomed", "op body").await;
    let tid = loc.strip_prefix("/t/").unwrap().to_string();

    // Add a reply from another author, then admin deletes THAT post (not the admin's own).
    let reply = form(&[("csrf", TOK), ("body", "a reply")]);
    let (s, _h, _b) = send(
        &state,
        post_as(
            &format!("{loc}/reply"),
            TOK,
            "u_bob",
            "bob@steadholme.local",
            "",
            reply,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let posts = state.store.posts_in_thread(&tid).await.unwrap();
    let op_id = posts.first().unwrap().id.clone();
    let pid = posts
        .into_iter()
        .find(|p| p.author_sub == "u_bob")
        .unwrap()
        .id;

    // The OP owns the thread identity. Even an admin cannot open a single-post delete review for
    // it; the semantic error still directs the moderator to Delete thread.
    let op_delete_uri = format!("/admin/posts/{op_id}/delete");
    let (s, _h, body) = send(
        &state,
        get_as(&op_delete_uri, ALICE_SUB, ALICE_EMAIL, ADMIN_GROUPS),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "admin cannot delete OP alone");
    assert!(body.contains("delete the thread"));
    assert_eq!(state.store.count_posts(&tid).await.unwrap(), 2);

    let post_delete_uri = format!("/admin/posts/{pid}/delete");

    // Direct POST without a confirmation is fail-closed.
    let (s, _h, _b) = send(
        &state,
        post_admin(&post_delete_uri, TOK, ADMIN_GROUPS, form(&[("csrf", TOK)])),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(state.store.get_post(&pid).await.unwrap().is_some());

    let post_review = delete_review_admin(&state, &post_delete_uri, None).await;

    // A different administrator is authorized for the route but cannot commit Alice's review.
    let (s, _h, _b) = send(
        &state,
        post_as(
            &post_delete_uri,
            &post_review.csrf,
            "u_admin_bob",
            "admin-bob@steadholme.local",
            ADMIN_GROUPS,
            confirmation_form(&post_review.csrf, &post_review.confirm),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(state.store.get_post(&pid).await.unwrap().is_some());

    let wrong_csrf = "admin-post-wrong-csrf";
    let (s, _h, _b) = send(
        &state,
        post_admin(
            &post_delete_uri,
            wrong_csrf,
            ADMIN_GROUPS,
            confirmation_form(wrong_csrf, &post_review.confirm),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(state.store.get_post(&pid).await.unwrap().is_some());

    let expired = expired_confirmation(&post_review.confirm);
    let (s, _h, _b) = send(
        &state,
        post_admin(
            &post_delete_uri,
            &post_review.csrf,
            ADMIN_GROUPS,
            confirmation_form(&post_review.csrf, &expired),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(state.store.get_post(&pid).await.unwrap().is_some());

    let (s, _h, _b) = send(
        &state,
        post_admin(
            &post_delete_uri,
            &post_review.csrf,
            ADMIN_GROUPS,
            confirmation_form(&post_review.csrf, "not-a-token"),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(state.store.get_post(&pid).await.unwrap().is_some());

    let (s, h, _b) = send(
        &state,
        post_admin(
            &post_delete_uri,
            &post_review.csrf,
            ADMIN_GROUPS,
            confirmation_form(&post_review.csrf, &post_review.confirm),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(
        h.get(header::LOCATION).unwrap().to_str().unwrap(),
        format!("/t/{tid}")
    );
    assert_eq!(
        state.store.count_posts(&tid).await.unwrap(),
        1,
        "reply deleted by admin"
    );

    let thread_delete_uri = format!("/admin/threads/{tid}/delete");

    // The thread endpoint also rejects a direct POST.
    let (s, _h, _b) = send(
        &state,
        post_admin(
            &thread_delete_uri,
            TOK,
            ADMIN_GROUPS,
            form(&[("csrf", TOK)]),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(state.store.get_thread(&tid).await.unwrap().is_some());

    // Preserve the CSRF session so the already-valid post confirmation is provably the wrong
    // action token for this thread endpoint.
    let thread_review =
        delete_review_admin(&state, &thread_delete_uri, Some(&post_review.csrf)).await;
    let (s, _h, _b) = send(
        &state,
        post_admin(
            &thread_delete_uri,
            &thread_review.csrf,
            ADMIN_GROUPS,
            confirmation_form(&thread_review.csrf, &post_review.confirm),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(state.store.get_thread(&tid).await.unwrap().is_some());

    // Now the exact thread review deletes the whole thread.
    let (s, h, _b) = send(
        &state,
        post_admin(
            &thread_delete_uri,
            &thread_review.csrf,
            ADMIN_GROUPS,
            confirmation_form(&thread_review.csrf, &thread_review.confirm),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(h.get(header::LOCATION).unwrap().to_str().unwrap(), "/admin");
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
    let existing = create_thread(&state, "Existing before ban", "Body.").await;
    let existing_id = existing.trim_start_matches("/t/");

    // Ban alice.
    let body = form(&[("csrf", TOK), ("author_sub", ALICE_SUB), ("reason", "spam")]);
    let (s, _h, _b) = send(&state, post_admin("/admin/bans", TOK, ADMIN_GROUPS, body)).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert!(state.store.is_banned(ALICE_SUB).await.unwrap());

    // Alice can no longer create a thread.
    let create = form(&[
        ("csrf", TOK),
        ("category", "general"),
        ("title", "T"),
        ("body", "B"),
    ]);
    let (s, _h, _b) = send(
        &state,
        post_as("/new", TOK, ALICE_SUB, ALICE_EMAIL, "", create),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Safe GETs do not issue actions that the same subject is forbidden to execute.
    let (s, _h, new_page) = send(&state, get_as("/new", ALICE_SUB, ALICE_EMAIL, "")).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(!new_page.contains(r#"method="post" action="/new""#));
    let (s, _h, thread_page) = send(&state, get_as(&existing, ALICE_SUB, ALICE_EMAIL, "")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(thread_page.contains("Posting unavailable"));
    assert!(!thread_page.contains(&format!(r#"action="/t/{existing_id}/reply""#)));
    assert!(!thread_page.contains(&format!(r#"/t/{existing_id}?quote="#)));
    assert!(!thread_page.contains(r#"/react""#));

    // The ban shows on the dashboard.
    let (_s, _h, dash) = send(
        &state,
        get_as("/admin", ALICE_SUB, ALICE_EMAIL, ADMIN_GROUPS),
    )
    .await;
    assert!(dash.contains(ALICE_SUB));
    assert!(dash.contains("spam"));

    // Unban → alice can post again.
    let (s, _h, _b) = send(
        &state,
        post_admin(
            "/admin/bans/delete",
            TOK,
            ADMIN_GROUPS,
            form(&[("csrf", TOK), ("author_sub", ALICE_SUB)]),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert!(!state.store.is_banned(ALICE_SUB).await.unwrap());
    let create = form(&[
        ("csrf", TOK),
        ("category", "general"),
        ("title", "T"),
        ("body", "B"),
    ]);
    let (s, _h, _b) = send(
        &state,
        post_as("/new", TOK, ALICE_SUB, ALICE_EMAIL, "", create),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);

    // Gateway subjects are opaque: reserved URL characters stay in a hidden form field instead
    // of changing the route target.
    let opaque_sub = "user/with?reserved#chars%20";
    let body = form(&[
        ("csrf", TOK),
        ("author_sub", opaque_sub),
        ("reason", "opaque subject"),
    ]);
    let (s, _h, _b) = send(&state, post_admin("/admin/bans", TOK, ADMIN_GROUPS, body)).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let (_s, _h, dash) = send(
        &state,
        get_as("/admin", ALICE_SUB, ALICE_EMAIL, ADMIN_GROUPS),
    )
    .await;
    assert!(dash.contains(r#"action="/admin/bans/delete""#));
    assert!(dash.contains(r#"name="author_sub" value="user/with?reserved#chars%20""#));
    let (s, _h, _b) = send(
        &state,
        post_admin(
            "/admin/bans/delete",
            TOK,
            ADMIN_GROUPS,
            form(&[("csrf", TOK), ("author_sub", opaque_sub)]),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert!(!state.store.is_banned(opaque_sub).await.unwrap());
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

async fn send(state: &AppState, req: Request<Body>) -> (StatusCode, HeaderMap, String) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, headers, String::from_utf8(bytes.to_vec()).unwrap())
}

/// Create a thread as alice in "general"; return its `/t/{id}` location.
async fn create_thread(state: &AppState, title: &str, body_md: &str) -> String {
    let body = form(&[
        ("csrf", TOK),
        ("category", "general"),
        ("title", title),
        ("body", body_md),
    ]);
    let (status, h, _b) = send(
        state,
        post_as("/new", TOK, ALICE_SUB, ALICE_EMAIL, "", body),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    h.get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
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
fn post_as(
    uri: &str,
    tok: &str,
    subject: &str,
    email: &str,
    groups: &str,
    body: String,
) -> Request<Body> {
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
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[derive(Debug)]
struct DeleteReview {
    csrf: String,
    confirm: String,
}

/// Open an admin destructive-action review, optionally preserving an existing CSRF session.
async fn delete_review_admin(
    state: &AppState,
    uri: &str,
    existing_csrf: Option<&str>,
) -> DeleteReview {
    let mut request = Request::builder()
        .uri(uri)
        .header("x-auth-subject", ALICE_SUB)
        .header("x-auth-email", ALICE_EMAIL)
        .header("x-auth-groups", ADMIN_GROUPS);
    if let Some(csrf) = existing_csrf {
        request = request.header(header::COOKIE, format!("__Host-csrf={csrf}"));
    }
    let (status, headers, body) = send(state, request.body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::OK, "delete review must render");
    assert!(body.contains(r#"method="post""#));
    assert!(body.contains(&format!(r#"action="{uri}""#)));

    let csrf = hidden_input_value(&body, "csrf");
    let confirm = hidden_input_value(&body, "confirm");
    assert!(!csrf.is_empty());
    assert!(!confirm.is_empty());
    match existing_csrf {
        Some(expected) => assert_eq!(csrf, expected, "review preserves the CSRF session"),
        None => {
            let cookie = set_cookie(&headers).expect("delete review sets a CSRF cookie");
            assert_eq!(csrf_value(&cookie), csrf, "hidden CSRF matches its cookie");
        }
    }
    DeleteReview { csrf, confirm }
}

fn hidden_input_value(html: &str, name: &str) -> String {
    let name_attr = format!(r#"name="{name}""#);
    html.split("<input")
        .skip(1)
        .filter_map(|rest| rest.split_once('>').map(|(tag, _)| tag))
        .find(|tag| tag.contains(&name_attr))
        .and_then(|tag| attribute_value(tag, "value"))
        .unwrap_or_else(|| panic!("hidden input {name:?} missing from review"))
        .to_string()
}

fn attribute_value<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let marker = format!(r#"{name}=""#);
    let value = tag.split_once(&marker)?.1;
    value.split_once('"').map(|(value, _)| value)
}

fn confirmation_form(csrf: &str, confirm: &str) -> String {
    form(&[("csrf", csrf), ("confirm", confirm)])
}

fn expired_confirmation(confirm: &str) -> String {
    let (_, rest) = confirm
        .split_once('.')
        .expect("confirmation has an expiry prefix");
    format!("0.{rest}")
}

fn set_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn csrf_value(set_cookie: &str) -> String {
    set_cookie
        .split(';')
        .next()
        .and_then(|pair| pair.split_once('='))
        .map(|(_, value)| value.to_string())
        .expect("cookie value")
}
