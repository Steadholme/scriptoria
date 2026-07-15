//! End-to-end HTTP flow for the /admin subtree over the in-memory store (NO database).
//!
//! Drives the real `app` router via `tower::oneshot`. Covers: the admin gate (403 for anon and
//! ordinary users, 200 for admins), the CSRF guard on mutations, feature/unpublish/delete, bulk
//! actions, admin override of the author-ownership gate, and the site-settings surface applied to
//! the index head.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use inkwell::{app, build_dev_state, AppState};
use tower::ServiceExt;

const CSRF: &str = "tok_csrf_for_tests";

#[tokio::test]
async fn admin_gate_blocks_non_admins() {
    let state = build_dev_state();

    // Anonymous -> 403.
    let (status, _) = call(&state, get("/admin", None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "anon gets 403");

    // Signed in, but not an admin group -> 403.
    let (status, _) = call(&state, get("/admin", Some("readers,writers"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "ordinary user gets 403");

    // Admin group -> 200 and the panel renders.
    let (status, body) = call(&state, get("/admin", Some("admins"))).await;
    assert_eq!(status, StatusCode::OK, "admin sees the panel");
    assert!(body.contains("All posts"), "panel table present");
    assert!(body.contains("Site settings"), "settings surface present");

    // The alternate infra-admins group also authorizes.
    let (status, _) = call(&state, get("/admin", Some("infra-admins"))).await;
    assert_eq!(status, StatusCode::OK, "infra-admins authorized too");
}

#[tokio::test]
async fn admin_mutations_feature_unpublish_delete() {
    let state = build_dev_state();

    // Seed a published post by u_alice.
    create_post(&state, "Alpha", "u_alice", "alice@hf").await;
    assert!(
        index_body(&state).await.contains("Alpha"),
        "post visible on index"
    );

    // --- feature (as admin) ------------------------------------------------
    // CSRF missing -> 401.
    let (status, _) = call(
        &state,
        post_admin(
            "/admin/posts/alpha/feature",
            "csrf_token=WRONG",
            "admins",
            false,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "bad CSRF rejected");

    // Non-admin cannot feature -> 403 (even with a good CSRF cookie).
    let (status, _) = call(
        &state,
        post_admin("/admin/posts/alpha/feature", &csrf_body(), "readers", true),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "non-admin blocked from mutation"
    );

    // Admin features it -> redirect, then the index shows the Featured badge.
    let (status, _) = call(
        &state,
        post_admin("/admin/posts/alpha/feature", &csrf_body(), "admins", true),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        index_body(&state).await.contains("badge badge-featured"),
        "featured badge shown"
    );

    // Toggle again -> unfeatured.
    let (status, _) = call(
        &state,
        post_admin("/admin/posts/alpha/feature", &csrf_body(), "admins", true),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        !index_body(&state).await.contains("badge badge-featured"),
        "badge gone after unfeature"
    );

    // --- unpublish ---------------------------------------------------------
    let (status, _) = call(
        &state,
        post_admin("/admin/posts/alpha/unpublish", &csrf_body(), "admins", true),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    // Anonymous index no longer shows it (it is a draft now).
    assert!(
        !index_body(&state).await.contains("Alpha"),
        "unpublished hidden from index"
    );

    // --- delete ------------------------------------------------------------
    let alpha = state.store.get_post("alpha").await.unwrap();
    let (status, _) = call(
        &state,
        post_admin(
            "/admin/posts/alpha/delete",
            &delete_body(&alpha),
            "admins",
            true,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (status, _) = call(
        &state,
        get_auth("/p/alpha", "u_admin", "admin@hf", Some("admins")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "deleted post is gone");
}

#[tokio::test]
async fn admin_can_pin_posts_to_top() {
    let state = build_dev_state();
    create_post(&state, "Alpha", "u_alice", "alice@hf").await;
    create_post(&state, "Beta", "u_bob", "bob@hf").await;

    let idx = index_body(&state).await;
    let beta_pos = idx.find("Beta").expect("newer post rendered");
    let alpha_pos = idx.find("Alpha").expect("older post rendered");
    assert!(beta_pos < alpha_pos, "newer post starts first");

    let (status, _) = call(
        &state,
        post_admin("/admin/posts/alpha/pin", &csrf_body(), "admins", true),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "admin pins older post");
    let alpha = state.store.get_post("alpha").await.unwrap();
    let revisions = state
        .store
        .list_post_revisions(&alpha.id, 50)
        .await
        .unwrap();
    let pin_revision = revisions
        .iter()
        .find(|revision| revision.source == "admin.pin")
        .expect("admin pin creates an immutable revision");
    assert_eq!(pin_revision.editor_email, "admin@hf");
    let pin_revision = state
        .store
        .get_post_revision(&alpha.id, &pin_revision.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pin_revision.editor_sub, "u_admin");

    let idx = index_body(&state).await;
    let alpha_pos = idx.find("Alpha").expect("pinned post rendered");
    let beta_pos = idx.find("Beta").expect("ordinary post rendered");
    assert!(
        alpha_pos < beta_pos,
        "pinned post floats above newer ordinary post"
    );

    let (_, panel) = call(&state, get("/admin", Some("admins"))).await;
    assert!(
        panel.contains("<th>Pinned</th>"),
        "admin table exposes pinned column"
    );
}

#[tokio::test]
async fn admin_bulk_action_over_stable_selections() {
    let state = build_dev_state();
    create_post(&state, "One", "u_alice", "alice@hf").await;
    create_post(&state, "Two", "u_bob", "bob@hf").await;
    create_post(&state, "Three", "u_alice", "alice@hf").await;

    // Bulk delete "one" and "three"; "two" survives.
    let one = state.store.get_post("one").await.unwrap();
    let three = state.store.get_post("three").await.unwrap();
    let body = format!(
        "csrf_token={CSRF}&action=delete&items={}&items={}",
        admin_item(&one),
        admin_item(&three)
    );
    let (status, _) = call(
        &state,
        post_admin("/admin/posts/bulk", &body, "admins", true),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let idx = index_body(&state).await;
    assert!(!idx.contains(">One<"), "one deleted");
    assert!(!idx.contains(">Three<"), "three deleted");
    assert!(idx.contains("Two"), "two survives the bulk delete");

    // Bulk feature "two".
    let two = state.store.get_post("two").await.unwrap();
    let body = format!(
        "csrf_token={CSRF}&action=feature&items={}",
        admin_item(&two)
    );
    let (status, _) = call(
        &state,
        post_admin("/admin/posts/bulk", &body, "admins", true),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        index_body(&state).await.contains("badge badge-featured"),
        "two now featured"
    );

    // Non-admin bulk -> 403.
    let body = format!(
        "csrf_token={CSRF}&action=delete&items={}",
        admin_item(&state.store.get_post("two").await.unwrap())
    );
    let (status, _) = call(
        &state,
        post_admin("/admin/posts/bulk", &body, "readers", true),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_bulk_delete_duplicate_or_later_stale_selection_deletes_nothing() {
    let state = build_dev_state();
    create_post(&state, "Atomic One", "u_alice", "alice@hf").await;
    create_post(&state, "Atomic Two", "u_bob", "bob@hf").await;
    let one = state.store.get_post("atomic-one").await.unwrap();
    let two = state.store.get_post("atomic-two").await.unwrap();

    let duplicate = format!(
        "csrf_token={CSRF}&action=delete&items={}&items={}",
        admin_item(&one),
        admin_item(&one)
    );
    let (status, body) = call(
        &state,
        post_admin("/admin/posts/bulk", &duplicate, "admins", true),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body.contains("post identity changed"));
    assert!(state.store.get_post(&one.slug).await.is_some());
    assert!(state.store.get_post(&two.slug).await.is_some());

    let mut stale_two = two.clone();
    stale_two.edit_version += 1;
    let later_stale = format!(
        "csrf_token={CSRF}&action=delete&items={}&items={}",
        admin_item(&one),
        admin_item(&stale_two)
    );
    let (status, body) = call(
        &state,
        post_admin("/admin/posts/bulk", &later_stale, "admins", true),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body.contains("post identity changed"));
    assert!(
        state.store.get_post(&one.slug).await.is_some(),
        "a valid earlier checkbox is not partially deleted"
    );
    assert!(state.store.get_post(&two.slug).await.is_some());
}

#[tokio::test]
async fn successful_admin_redirects_are_private_no_store() {
    let state = build_dev_state();
    let body = form(&[
        ("title", "Private settings"),
        ("posts_per_page", "8"),
        ("csrf_token", CSRF),
    ]);
    let response = app(state)
        .oneshot(post_admin("/admin/settings", &body, "admins", true))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "private, no-store"
    );
}

#[tokio::test]
async fn admin_can_edit_and_delete_any_authors_post() {
    let state = build_dev_state();
    create_post(&state, "Alice Post", "u_alice", "alice@hf").await;
    let post_id = state.store.get_post("alice-post").await.unwrap().id;

    // A non-owner NON-admin still cannot edit (the ownership gate holds).
    let body = form(&[("title", "Hijack"), ("body", "x"), ("csrf_token", CSRF)]);
    let (status, _) = call(
        &state,
        post_edit("/edit/alice-post", &body, "u_mallory", "m@hf", None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "non-owner non-admin blocked");

    // An admin (different subject) CAN edit it — the author gate is overridden for admins.
    let body = form(&[
        ("title", "Edited By Admin"),
        ("body", "moderated"),
        ("intent", "publish_now"),
        ("expected_version", "1"),
        ("expected_post_id", &post_id),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(
        &state,
        post_edit(
            "/edit/alice-post",
            &body,
            "u_admin",
            "admin@hf",
            Some("admins"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "admin overrides ownership");
    assert!(
        index_body(&state).await.contains("Edited By Admin"),
        "admin edit applied"
    );

    // And an admin can delete it via the ordinary delete route too.
    let current = state.store.get_post("alice-post").await.unwrap();
    let body = delete_body(&current);
    let (status, _) = call(
        &state,
        post_edit(
            "/delete/alice-post",
            &body,
            "u_admin",
            "admin@hf",
            Some("admins"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "admin deletes any post");
}

#[tokio::test]
async fn admin_delete_requires_current_immutable_identity() {
    let state = build_dev_state();
    create_post(&state, "Replace Me", "u_alice", "alice@hf").await;
    let stale = state.store.get_post("replace-me").await.unwrap();

    let (status, _) = call(
        &state,
        post_admin(
            "/admin/posts/replace-me/delete",
            &csrf_body(),
            "admins",
            true,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "legacy form fails closed");

    state.store.delete_post("replace-me").await.unwrap();
    create_post(&state, "Replace Me", "u_bob", "bob@hf").await;
    let replacement = state.store.get_post("replace-me").await.unwrap();
    assert_ne!(replacement.id, stale.id);
    let (status, body) = call(
        &state,
        post_admin(
            "/admin/posts/replace-me/delete",
            &delete_body(&stale),
            "admins",
            true,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body.contains("post identity changed"));
    assert_eq!(
        state.store.get_post("replace-me").await.unwrap().id,
        replacement.id,
        "stale admin authority never deletes the replacement"
    );
}

#[tokio::test]
async fn admin_settings_apply_to_the_index() {
    let state = build_dev_state();

    // Default title on the index head.
    assert!(
        index_body(&state).await.contains("Inkwell · Steadholme"),
        "default title"
    );

    // Save new settings.
    let body = form(&[
        ("title", "Wanderlust"),
        ("tagline", "Field notes from the road"),
        ("posts_per_page", "7"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(&state, post_admin("/admin/settings", &body, "admins", true)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let idx = index_body(&state).await;
    assert!(
        idx.contains("Wanderlust · Steadholme"),
        "custom title in head"
    );
    assert!(
        idx.contains("Field notes from the road"),
        "custom tagline in masthead"
    );

    // A non-admin cannot change settings.
    let body = form(&[
        ("title", "Hacked"),
        ("posts_per_page", "5"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(
        &state,
        post_admin("/admin/settings", &body, "readers", true),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        !index_body(&state).await.contains("Hacked"),
        "non-admin change rejected"
    );
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

async fn call(state: &AppState, req: Request<Body>) -> (StatusCode, String) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

async fn index_body(state: &AppState) -> String {
    call(state, get("/", None)).await.1
}

/// Create a published post through the ordinary SSO+CSRF authoring path.
async fn create_post(state: &AppState, title: &str, sub: &str, email: &str) {
    let body = form(&[
        ("title", title),
        ("body", "body text"),
        ("intent", "publish_now"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(state, post_edit("/new", &body, sub, email, None)).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "seed post created");
}

fn csrf_body() -> String {
    format!("csrf_token={CSRF}")
}

fn delete_body(post: &inkwell::store::Post) -> String {
    form(&[
        ("csrf_token", CSRF),
        ("expected_post_id", &post.id),
        ("expected_version", &post.edit_version.to_string()),
    ])
}

fn admin_item(post: &inkwell::store::Post) -> String {
    format!(
        "{}.{}.{}",
        hex::encode(post.id.as_bytes()),
        post.edit_version,
        hex::encode(post.slug.as_bytes())
    )
}

fn get(uri: &str, groups: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().uri(uri);
    if let Some(g) = groups {
        b = b
            .header("x-auth-subject", "u_admin")
            .header("x-auth-email", "admin@hf")
            .header("x-auth-groups", g);
    }
    b.body(Body::empty()).unwrap()
}

fn get_auth(uri: &str, sub: &str, email: &str, groups: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .uri(uri)
        .header("x-auth-subject", sub)
        .header("x-auth-email", email);
    if let Some(g) = groups {
        b = b.header("x-auth-groups", g);
    }
    b.body(Body::empty()).unwrap()
}

/// A POST into the admin subtree, carrying the test CSRF cookie and a gateway identity whose
/// `X-Auth-Groups` is `groups`. When `with_cookie` is false the CSRF cookie is omitted.
fn post_admin(uri: &str, body: &str, groups: &str, with_cookie: bool) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("x-auth-subject", "u_admin")
        .header("x-auth-email", "admin@hf")
        .header("x-auth-groups", groups);
    if with_cookie {
        b = b.header(header::COOKIE, format!("__Host-csrf={CSRF}"));
    }
    b.body(Body::from(body.to_string())).unwrap()
}

/// A POST into the authoring routes (create/edit/delete) with the CSRF cookie + identity, and an
/// optional `X-Auth-Groups` header (for the admin-override cases).
fn post_edit(uri: &str, body: &str, sub: &str, email: &str, groups: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={CSRF}"))
        .header("x-auth-subject", sub)
        .header("x-auth-email", email);
    if let Some(g) = groups {
        b = b.header("x-auth-groups", g);
    }
    b.body(Body::from(body.to_string())).unwrap()
}

fn form(pairs: &[(&str, &str)]) -> String {
    let mut fields = pairs
        .iter()
        .map(|(k, v)| format!("{}={}", k, enc(v)))
        .collect::<Vec<_>>();
    if !pairs.iter().any(|(key, _)| *key == "intent") {
        let intent = if pairs.iter().any(|(key, _)| *key == "published") {
            "publish_now"
        } else {
            "save_draft"
        };
        fields.push(format!("intent={intent}"));
    }
    fields.join("&")
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
