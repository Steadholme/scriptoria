//! End-to-end forum flow over the in-memory store (no database).
//!
//! Drives the real `app` Router via `tower::oneshot`, exactly like keystone/keyward/beacon.
//! Covers: seeded categories on the home page; the CSRF-cookie issuing new-thread form; CSRF
//! and identity enforcement on POSTs; thread creation + reply (post/redirect/get); markdown
//! rendering; and markdown XSS sanitisation.

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use tower::ServiceExt;

use agora::handlers::forum::REPLIES_PER_PAGE;
use agora::model::Post;
use agora::{app, build_dev_state, AppState};

#[tokio::test]
async fn home_lists_seeded_categories() {
    let state = build_dev_state().await;
    let (status, _h, body) = send(&state, get("/")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Announcements"));
    assert!(body.contains("General Discussion"));
    assert!(body.contains("Support"));
    assert!(body.contains(r#"<p class="muted">No threads here yet. Start the first one.</p>"#));
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
    let body = form(&[
        ("csrf", "x"),
        ("category", "general"),
        ("title", "T"),
        ("body", "B"),
    ]);
    // No CSRF cookie present -> double-submit fails.
    let (status, _h, _b) = send(&state, post_form("/new", None, true, body)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn post_without_identity_is_unauthorized() {
    let state = build_dev_state().await;
    let tok = "csrftoken123";
    let body = form(&[
        ("csrf", tok),
        ("category", "general"),
        ("title", "T"),
        ("body", "B"),
    ]);
    // Valid CSRF (cookie matches field) but NO X-Auth-Subject injected.
    let (status, _h, _b) = send(&state, post_form("/new", Some(tok), false, body)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unknown_category_is_rejected() {
    let state = build_dev_state().await;
    let tok = "csrftoken123";
    let body = form(&[
        ("csrf", tok),
        ("category", "nope"),
        ("title", "T"),
        ("body", "B"),
    ]);
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
    assert!(
        location.starts_with("/t/t_"),
        "redirects to the new thread: {location}"
    );

    // The thread page renders the markdown body + the author + the OP badge.
    let (status, _h, page) = send(&state, get(&location)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("Hello Agora"));
    assert!(page.contains("<strong>bold</strong>"), "markdown rendered");
    assert!(
        page.contains("alice@steadholme.local"),
        "trusted author shown"
    );
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
    let location = h
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let (_s, _h, page) = send(&state, get(&location)).await;
    // No executable script tag and no executable javascript: href survive into the page.
    assert!(
        !page.contains("<script>alert"),
        "raw script must be neutralised"
    );
    assert!(
        !page.contains("href=\"javascript"),
        "javascript: href must be defused"
    );
    assert!(page.contains("href=\"#\""), "unsafe link rewritten to #");
    assert!(
        page.contains("&lt;script&gt;"),
        "script shown as escaped text"
    );
}

#[tokio::test]
async fn missing_thread_and_category_are_404() {
    let state = build_dev_state().await;
    let (status, _h, _b) = send(&state, get("/t/t_doesnotexist")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _h, _b) = send(&state, get("/c/nope")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// --- author edit/delete of own threads + replies ---------------------------------------

const ALICE_SUB: &str = "u_sub_1";
const ALICE_EMAIL: &str = "alice@steadholme.local";
const BOB_SUB: &str = "u_sub_bob";
const BOB_EMAIL: &str = "bob@steadholme.local";

/// Create a thread as alice and return its `/t/{id}` location.
async fn create_thread(state: &AppState, tok: &str, title: &str, body_md: &str) -> String {
    let body = form(&[
        ("csrf", tok),
        ("category", "general"),
        ("title", title),
        ("body", body_md),
    ]);
    let (status, h, _b) = send(state, post_form("/new", Some(tok), true, body)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    h.get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn author_can_edit_and_delete_own_thread() {
    let state = build_dev_state().await;
    let tok = "csrftoken123";
    let location = create_thread(&state, tok, "Orig Title", "Orig **body**.").await;
    let tid = location.strip_prefix("/t/").unwrap().to_string();
    let edit_uri = format!("{location}/edit");
    let delete_uri = format!("{location}/delete");

    // The author sees edit + delete-review controls on the thread page.
    let (_s, _h, page) = send(&state, get_as(&location, ALICE_SUB, ALICE_EMAIL)).await;
    assert!(page.contains(&edit_uri), "author sees the edit link");
    assert!(
        page.contains(&delete_uri),
        "author sees the delete review link"
    );

    // The edit form is prefilled with the current title + original-post body.
    let (s, _h, form_page) = send(&state, get_as(&edit_uri, ALICE_SUB, ALICE_EMAIL)).await;
    assert_eq!(s, StatusCode::OK);
    assert!(form_page.contains("Orig Title"), "title prefilled");
    assert!(form_page.contains("Orig **body**."), "OP body prefilled");

    // Save an edit → the thread renders the new title + body.
    let ebody = form(&[
        ("csrf", tok),
        ("title", "New Title"),
        ("body", "New _body_."),
    ]);
    let (s, _h, _b) = send(
        &state,
        post_form_as(&edit_uri, tok, ALICE_SUB, ALICE_EMAIL, ebody),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let (_s, _h, page) = send(&state, get(&location)).await;
    assert!(page.contains("New Title"), "new title shown");
    assert!(page.contains("<em>body</em>"), "new OP markdown rendered");
    assert!(!page.contains("Orig Title"), "old title gone");

    // A direct POST without a server-rendered confirmation is refused and does not mutate.
    let (s, _h, _b) = send(
        &state,
        post_form_as(
            &delete_uri,
            tok,
            ALICE_SUB,
            ALICE_EMAIL,
            form(&[("csrf", tok)]),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(state.store.get_thread(&tid).await.unwrap().is_some());

    // GET the review on the same path. Its confirmation is bound to the actor, target action,
    // and freshly-issued CSRF session.
    let review = delete_review_as(&state, &delete_uri, ALICE_SUB, ALICE_EMAIL, None).await;

    // A valid confirmation minted for another target is the wrong action.
    let decoy_location = create_thread(&state, tok, "Keep me", "Decoy body.").await;
    let decoy_tid = decoy_location.strip_prefix("/t/").unwrap().to_string();
    let decoy_delete_uri = format!("{decoy_location}/delete");
    let wrong_action = delete_review_as(
        &state,
        &decoy_delete_uri,
        ALICE_SUB,
        ALICE_EMAIL,
        Some(&review.csrf),
    )
    .await;
    let (s, _h, _b) = send(
        &state,
        post_form_as(
            &delete_uri,
            &review.csrf,
            ALICE_SUB,
            ALICE_EMAIL,
            confirmation_form(&review.csrf, &wrong_action.confirm),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(state.store.get_thread(&tid).await.unwrap().is_some());
    assert!(state.store.get_thread(&decoy_tid).await.unwrap().is_some());

    // The same review cannot be committed by another actor.
    let (s, _h, _b) = send(
        &state,
        post_form_as(
            &delete_uri,
            &review.csrf,
            BOB_SUB,
            BOB_EMAIL,
            confirmation_form(&review.csrf, &review.confirm),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(state.store.get_thread(&tid).await.unwrap().is_some());

    // Even a matching double-submit pair cannot reuse a confirmation from another CSRF session.
    let wrong_csrf = "different-csrf-session";
    let (s, _h, _b) = send(
        &state,
        post_form_as(
            &delete_uri,
            wrong_csrf,
            ALICE_SUB,
            ALICE_EMAIL,
            confirmation_form(wrong_csrf, &review.confirm),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(state.store.get_thread(&tid).await.unwrap().is_some());

    let expired = expired_confirmation(&review.confirm);
    let (s, _h, _b) = send(
        &state,
        post_form_as(
            &delete_uri,
            &review.csrf,
            ALICE_SUB,
            ALICE_EMAIL,
            confirmation_form(&review.csrf, &expired),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(state.store.get_thread(&tid).await.unwrap().is_some());

    let (s, _h, _b) = send(
        &state,
        post_form_as(
            &delete_uri,
            &review.csrf,
            ALICE_SUB,
            ALICE_EMAIL,
            confirmation_form(&review.csrf, "malformed-confirmation"),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(state.store.get_thread(&tid).await.unwrap().is_some());

    // Only the exact review tuple commits: 303 to the category, then the thread is 404.
    let (s, dh, _b) = send(
        &state,
        post_form_as(
            &delete_uri,
            &review.csrf,
            ALICE_SUB,
            ALICE_EMAIL,
            confirmation_form(&review.csrf, &review.confirm),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(
        dh.get(header::LOCATION).unwrap().to_str().unwrap(),
        "/c/general"
    );
    let (s, _h, _b) = send(&state, get(&location)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn non_author_cannot_edit_or_delete_thread() {
    let state = build_dev_state().await;
    let tok = "csrftoken123";
    let location = create_thread(&state, tok, "Alice Thread", "Alice body.").await;
    let edit_uri = format!("{location}/edit");
    let delete_uri = format!("{location}/delete");

    // Bob sees NO owner controls on alice's thread.
    let (_s, _h, page) = send(&state, get_as(&location, BOB_SUB, BOB_EMAIL)).await;
    assert!(!page.contains(&edit_uri), "non-author sees no edit link");
    assert!(
        !page.contains(&delete_uri),
        "non-author sees no delete review link"
    );

    // Bob is blocked from the edit form, the update, and even opening the delete review.
    let (s, _h, _b) = send(&state, get_as(&edit_uri, BOB_SUB, BOB_EMAIL)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let ebody = form(&[("csrf", tok), ("title", "Hijacked"), ("body", "x")]);
    let (s, _h, _b) = send(
        &state,
        post_form_as(&edit_uri, tok, BOB_SUB, BOB_EMAIL, ebody),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _h, _b) = send(&state, get_as(&delete_uri, BOB_SUB, BOB_EMAIL)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _h, _b) = send(
        &state,
        post_form_as(&delete_uri, tok, BOB_SUB, BOB_EMAIL, form(&[("csrf", tok)])),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // The thread survives, unchanged.
    let (s, _h, page) = send(&state, get(&location)).await;
    assert_eq!(s, StatusCode::OK);
    assert!(page.contains("Alice Thread"));
}

#[tokio::test]
async fn thread_edit_requires_csrf() {
    let state = build_dev_state().await;
    let tok = "csrftoken123";
    let location = create_thread(&state, tok, "T", "B").await;
    // Valid identity but NO CSRF cookie → double-submit fails before anything mutates.
    let body = form(&[("csrf", tok), ("title", "X"), ("body", "Y")]);
    let (s, _h, _b) = send(
        &state,
        post_form(&format!("{location}/edit"), None, true, body),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn author_can_edit_and_delete_own_reply() {
    let state = build_dev_state().await;
    let tok = "csrftoken123";
    let location = create_thread(&state, tok, "Reply Home", "OP body.").await;
    let tid = location.strip_prefix("/t/").unwrap().to_string();

    // Post timestamps are epoch SECONDS; ensure the reply lands in a strictly later second so it
    // orders after the original post deterministically (the OP is the oldest, id-tiebroken post).
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    // Bob replies.
    let reply = form(&[("csrf", tok), ("body", "Bob original reply.")]);
    let (s, _h, _b) = send(
        &state,
        post_form_as(&format!("{location}/reply"), tok, BOB_SUB, BOB_EMAIL, reply),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);

    // Locate bob's reply id via the store (ids are not surfaced to non-owners in HTML).
    let posts = state.store.posts_in_thread(&tid).await.unwrap();
    let pid = posts
        .iter()
        .find(|p| p.author_sub == BOB_SUB)
        .expect("bob's reply exists")
        .id
        .clone();
    let edit_uri = format!("/t/{tid}/p/{pid}/edit");
    let delete_uri = format!("/t/{tid}/p/{pid}/delete");

    // Bob (reply author) sees the controls; alice (thread author, not reply author) does not.
    let (_s, _h, bpage) = send(&state, get_as(&location, BOB_SUB, BOB_EMAIL)).await;
    assert!(bpage.contains(&edit_uri), "reply author sees edit link");
    let (_s, _h, apage) = send(&state, get_as(&location, ALICE_SUB, ALICE_EMAIL)).await;
    assert!(
        !apage.contains(&edit_uri),
        "non-author sees no reply controls"
    );

    // Alice cannot edit bob's reply.
    let ebody = form(&[("csrf", tok), ("body", "alice hijack")]);
    let (s, _h, _b) = send(
        &state,
        post_form_as(&edit_uri, tok, ALICE_SUB, ALICE_EMAIL, ebody),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Bob edits his own reply.
    let ebody = form(&[("csrf", tok), ("body", "Bob _edited_ reply.")]);
    let (s, _h, _b) = send(
        &state,
        post_form_as(&edit_uri, tok, BOB_SUB, BOB_EMAIL, ebody),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let (_s, _h, page) = send(&state, get(&location)).await;
    assert!(
        page.contains("<em>edited</em>"),
        "edited reply markdown rendered"
    );
    assert!(!page.contains("Bob original reply"), "old reply body gone");

    // Direct POST cannot skip the review.
    let (s, _h, _b) = send(
        &state,
        post_form_as(&delete_uri, tok, BOB_SUB, BOB_EMAIL, form(&[("csrf", tok)])),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(state.store.get_post(&pid).await.unwrap().is_some());

    let review = delete_review_as(&state, &delete_uri, BOB_SUB, BOB_EMAIL, None).await;

    // The review is actor-bound.
    let (s, _h, _b) = send(
        &state,
        post_form_as(
            &delete_uri,
            &review.csrf,
            ALICE_SUB,
            ALICE_EMAIL,
            confirmation_form(&review.csrf, &review.confirm),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(state.store.get_post(&pid).await.unwrap().is_some());

    let wrong_csrf = "reply-wrong-csrf";
    let (s, _h, _b) = send(
        &state,
        post_form_as(
            &delete_uri,
            wrong_csrf,
            BOB_SUB,
            BOB_EMAIL,
            confirmation_form(wrong_csrf, &review.confirm),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(state.store.get_post(&pid).await.unwrap().is_some());

    let expired = expired_confirmation(&review.confirm);
    let (s, _h, _b) = send(
        &state,
        post_form_as(
            &delete_uri,
            &review.csrf,
            BOB_SUB,
            BOB_EMAIL,
            confirmation_form(&review.csrf, &expired),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(state.store.get_post(&pid).await.unwrap().is_some());

    let (s, _h, _b) = send(
        &state,
        post_form_as(
            &delete_uri,
            &review.csrf,
            BOB_SUB,
            BOB_EMAIL,
            confirmation_form(&review.csrf, "not.a.valid.confirmation"),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(state.store.get_post(&pid).await.unwrap().is_some());

    // Bob's exact review token deletes the reply and keeps the original redirect.
    let (s, h, _b) = send(
        &state,
        post_form_as(
            &delete_uri,
            &review.csrf,
            BOB_SUB,
            BOB_EMAIL,
            confirmation_form(&review.csrf, &review.confirm),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(h.get(header::LOCATION).unwrap().to_str().unwrap(), location);
    let (_s, _h, page) = send(&state, get(&location)).await;
    assert!(!page.contains("edited"), "reply removed");
    assert!(page.contains("0 replies"));
}

#[tokio::test]
async fn original_post_cannot_be_edited_or_deleted_via_reply_route() {
    let state = build_dev_state().await;
    let tok = "csrftoken123";
    let location = create_thread(&state, tok, "Guard OP", "OP body.").await;
    let tid = location.strip_prefix("/t/").unwrap().to_string();

    // The original post's id (oldest post). Editing/deleting it via the reply route must be
    // refused even for its own author — that path is the thread controls (which keep the
    // denormalised first_body_md in step).
    let op_id = state.store.posts_in_thread(&tid).await.unwrap()[0]
        .id
        .clone();

    let ebody = form(&[("csrf", tok), ("body", "sneaky")]);
    let (s, _h, _b) = send(
        &state,
        post_form_as(
            &format!("/t/{tid}/p/{op_id}/edit"),
            tok,
            ALICE_SUB,
            ALICE_EMAIL,
            ebody,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let op_delete_uri = format!("/t/{tid}/p/{op_id}/delete");
    let (s, _h, _b) = send(&state, get_as(&op_delete_uri, ALICE_SUB, ALICE_EMAIL)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _h, _b) = send(
        &state,
        post_form_as(
            &op_delete_uri,
            tok,
            ALICE_SUB,
            ALICE_EMAIL,
            form(&[("csrf", tok)]),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // The original post survives.
    assert_eq!(state.store.posts_in_thread(&tid).await.unwrap().len(), 1);
}

// --- reply pagination (keyset ?before / ?after / ?latest) ------------------------------

/// Seed a thread with `count` replies whose bodies are `reply-body-NNN` and whose `created_at`
/// strictly increase (so the keyset order is deterministic — HTTP replies would collide on the
/// same epoch SECOND). Inserted straight through the store, past the HTTP layer.
async fn seed_replies(state: &AppState, tid: &str, count: usize) {
    let base = state
        .store
        .first_post_in_thread(tid)
        .await
        .unwrap()
        .unwrap()
        .created_at
        + 10;
    for i in 0..count {
        let post = Post {
            id: format!("p_seed_{i:04}"),
            thread_id: tid.to_string(),
            body_md: format!("reply-body-{i:03}"),
            quoted_post_id: String::new(),
            author_sub: BOB_SUB.to_string(),
            author_email: BOB_EMAIL.to_string(),
            created_at: base + i as i64,
        };
        state.store.add_reply(&post).await.unwrap();
    }
}

#[tokio::test]
async fn thread_default_page_shows_oldest_replies_with_forward_nav() {
    let state = build_dev_state().await;
    let tok = "csrftoken123";
    let location = create_thread(&state, tok, "Paged", "OP body.").await;
    let tid = location.strip_prefix("/t/").unwrap().to_string();
    let count = REPLIES_PER_PAGE as usize + 5;
    seed_replies(&state, &tid, count).await;

    // Bare GET → the FIRST (oldest) page: oldest reply present, newest absent (it's on a later
    // page), and the total reply count is shown.
    let (status, _h, page) = send(&state, get(&location)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains("reply-body-000"),
        "oldest reply on the first page"
    );
    assert!(
        !page.contains(&format!("reply-body-{:03}", count - 1)),
        "newest reply is NOT on the first page"
    );
    assert!(
        page.contains(&format!("{count} replies")),
        "reply count shown"
    );
    // Forward-only nav on the first page: newer + jump-to-latest, no older link.
    assert!(page.contains("?after="), "Load newer link present");
    assert!(page.contains(&format!(
        r#"<a class="btn btn-ghost btn-sm ag-page__jump" href="{location}?latest=1#thread-latest">Jump to latest</a>"#
    )));
    assert!(
        !page.contains("?before="),
        "no Load older on the first page"
    );
}

#[tokio::test]
async fn thread_jump_to_latest_shows_newest_replies_with_backward_nav() {
    let state = build_dev_state().await;
    let tok = "csrftoken123";
    let location = create_thread(&state, tok, "Paged", "OP body.").await;
    let tid = location.strip_prefix("/t/").unwrap().to_string();
    let count = REPLIES_PER_PAGE as usize + 5;
    seed_replies(&state, &tid, count).await;

    let (status, _h, page) = send(&state, get(&format!("{location}?latest=1"))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains(&format!("reply-body-{:03}", count - 1)),
        "newest reply on the latest page"
    );
    assert!(
        !page.contains("reply-body-000"),
        "oldest reply is NOT on the latest page"
    );
    // The original post is still pinned at the top of every page.
    assert!(
        page.contains("Original post"),
        "OP pinned on the latest page"
    );
    // Backward-only nav on the latest page: older link, no newer / jump-to-latest.
    assert!(page.contains("?before="), "Load older link present");
    assert!(
        !page.contains("?after="),
        "no Load newer on the latest page"
    );
    assert!(
        !page.contains(r#"class="btn btn-ghost btn-sm ag-page__jump""#),
        "no Jump to latest on the latest page"
    );
}

#[tokio::test]
async fn thread_before_cursor_pages_to_older_replies() {
    let state = build_dev_state().await;
    let tok = "csrftoken123";
    let location = create_thread(&state, tok, "Paged", "OP body.").await;
    let tid = location.strip_prefix("/t/").unwrap().to_string();
    seed_replies(&state, &tid, REPLIES_PER_PAGE as usize + 5).await;

    // Cursor at the 3rd-oldest reply (id `p_seed_0003`, created_at base+3): `?before=` returns the
    // replies strictly OLDER than it — indices 0..=2 only.
    let base = state
        .store
        .first_post_in_thread(&tid)
        .await
        .unwrap()
        .unwrap()
        .created_at
        + 10;
    let cursor = format!("{ts}_p_seed_0003", ts = base + 3);
    let (status, _h, page) = send(&state, get(&format!("{location}?before={cursor}"))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains("reply-body-000"),
        "older page includes reply 0"
    );
    assert!(
        page.contains("reply-body-002"),
        "older page includes reply 2"
    );
    assert!(
        !page.contains("reply-body-003"),
        "cursor reply excluded (strictly older)"
    );
    // Only 3 replies are older than the cursor (< one page), so no further Load older; but newer
    // replies exist, so forward nav + jump-to-latest are offered.
    assert!(
        !page.contains("?before="),
        "no Load older beyond the oldest replies"
    );
    assert!(page.contains("?after="), "Load newer link present");
    assert!(page.contains(&format!(
        r#"<a class="btn btn-ghost btn-sm ag-page__jump" href="{location}?latest=1#thread-latest">Jump to latest</a>"#
    )));
}

#[tokio::test]
async fn reading_receipts_resume_at_exact_first_unread_without_swallowing_holes() {
    let state = build_dev_state().await;
    let tok = "csrftoken123";
    let location = create_thread(&state, tok, "Reading continuity", "OP body.").await;
    let tid = location.strip_prefix("/t/").unwrap().to_string();
    let reply_count = REPLIES_PER_PAGE as usize + 5;
    seed_replies(&state, &tid, reply_count).await;

    let (status, _, first_page) = send(&state, get_as(&location, ALICE_SUB, ALICE_EMAIL)).await;
    assert_eq!(status, StatusCode::OK);
    let first_unread = r#"<div class="ag-first-unread ag-key-private" id="thread-resume" role="separator" tabindex="-1"><span>First unread</span></div>"#;
    assert_eq!(first_page.matches(first_unread).count(), 1);
    assert!(first_page.contains(&format!(
        r#"<form class="inline-form" method="post" action="/t/{tid}/read" data-thread-read-form>"#
    )));
    assert!(first_page.contains(r#"data-thread-read-sentinel"#));
    assert!(first_page.contains(r#"data-thread-read-status role="status" aria-live="polite""#));
    assert!(first_page.contains("Mark page read &amp; continue"));

    let visible = state.store.posts_in_thread(&tid).await.unwrap();
    let visible_ids = visible
        .iter()
        .take(REPLIES_PER_PAGE as usize + 1)
        .map(|post| post.id.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let body = form(&[("csrf", tok), ("post_ids", &visible_ids)]);
    let (status, headers, _) = send(
        &state,
        post_form_as(
            &format!("{location}/read"),
            tok,
            ALICE_SUB,
            ALICE_EMAIL,
            body,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        headers.get(header::LOCATION).unwrap().to_str().unwrap(),
        format!("{location}?resume=1#thread-resume")
    );
    let reading = state
        .store
        .thread_reading_state(ALICE_SUB, &tid)
        .await
        .unwrap();
    assert!(reading.started);
    assert_eq!(reading.unread_count, 5);
    assert_eq!(
        reading.first_unread.as_ref().unwrap().body_md,
        "reply-body-020"
    );

    let (_, _, home) = send(&state, get_as("/", ALICE_SUB, ALICE_EMAIL)).await;
    assert!(
        home.contains(r#"<span class="ag-mark ag-key-private ag-mark--unread">5 unread</span>"#)
    );
    assert!(home.contains(&format!(
        r#"<a class="ag-mark ag-key-private ag-mark--resume" href="/t/{tid}?resume=1#thread-resume">Resume</a>"#
    )));

    let (_, _, resumed) = send(
        &state,
        get_as(&format!("{location}?resume=1"), ALICE_SUB, ALICE_EMAIL),
    )
    .await;
    assert!(resumed.contains("reply-body-020"));
    assert_eq!(resumed.matches(first_unread).count(), 1);
    assert!(resumed.find("First unread").unwrap() < resumed.find("reply-body-020").unwrap());

    let remaining_ids = visible
        .iter()
        .skip(REPLIES_PER_PAGE as usize + 1)
        .map(|post| post.id.clone())
        .collect::<Vec<_>>();
    state
        .store
        .mark_thread_posts_read(ALICE_SUB, &tid, &remaining_ids, 124)
        .await
        .unwrap();
    let caught_up = state
        .store
        .thread_reading_state(ALICE_SUB, &tid)
        .await
        .unwrap();
    assert!(caught_up.started);
    assert_eq!(caught_up.unread_count, 0);
    assert!(caught_up.first_unread.is_none());
    let (_, _, caught_up_page) = send(&state, get_as(&location, ALICE_SUB, ALICE_EMAIL)).await;
    assert!(caught_up_page
        .contains(r#"<span class="ag-mark ag-key-private ag-mark--caught-up">Caught up</span>"#));
    assert!(
        !caught_up_page.contains(&format!("{location}?resume=1#thread-resume")),
        "caught-up state never links to a missing resume target"
    );
    assert!(
        !caught_up_page.contains(&format!(r#"action="/t/{tid}/read""#)),
        "caught-up state does not issue a meaningless mark-page-read action"
    );
    assert!(!caught_up_page.contains(first_unread));

    // A replay of an old page form remains safe and lands on a real latest-page anchor.
    let stale_body = form(&[("csrf", tok), ("post_ids", &visible_ids)]);
    let (status, headers, _) = send(
        &state,
        post_form_as(
            &format!("{location}/read"),
            tok,
            ALICE_SUB,
            ALICE_EMAIL,
            stale_body,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        headers.get(header::LOCATION).unwrap().to_str().unwrap(),
        format!("{location}?latest=1#thread-latest")
    );

    let latest = state
        .store
        .replies_page(
            &tid,
            &visible[0].id,
            None,
            &agora::store::ReplyAnchor::Latest,
            REPLIES_PER_PAGE,
        )
        .await
        .unwrap();
    let mut bob_ids = vec![visible[0].id.clone()];
    bob_ids.extend(latest.into_iter().map(|post| post.id));
    state
        .store
        .mark_thread_posts_read(BOB_SUB, &tid, &bob_ids, 123)
        .await
        .unwrap();
    let bob = state
        .store
        .thread_reading_state(BOB_SUB, &tid)
        .await
        .unwrap();
    assert_eq!(bob.unread_count, 5);
    assert_eq!(bob.first_unread.unwrap().body_md, "reply-body-000");
}

#[tokio::test]
async fn accepted_solution_can_be_the_exact_first_unread_boundary() {
    let state = build_dev_state().await;
    let tok = "csrftoken123";
    let body = form(&[
        ("csrf", tok),
        ("category", "support"),
        ("title", "Accepted continuity"),
        ("body", "Question body."),
    ]);
    let (status, headers, _) = send(&state, post_form("/new", Some(tok), true, body)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = headers.get(header::LOCATION).unwrap().to_str().unwrap();
    let tid = location.strip_prefix("/t/").unwrap();
    let op = state
        .store
        .first_post_in_thread(tid)
        .await
        .unwrap()
        .unwrap();
    let solution = Post {
        id: "p_solution_reading".to_string(),
        thread_id: tid.to_string(),
        body_md: "The accepted solution body.".to_string(),
        quoted_post_id: String::new(),
        author_sub: BOB_SUB.to_string(),
        author_email: BOB_EMAIL.to_string(),
        created_at: op.created_at + 10,
    };
    let later = Post {
        id: "p_later_reading".to_string(),
        body_md: "A later ordinary reply.".to_string(),
        created_at: op.created_at + 20,
        ..solution.clone()
    };
    state.store.add_reply(&solution).await.unwrap();
    state.store.add_reply(&later).await.unwrap();
    state
        .store
        .mutate_accepted_answer(
            tid,
            agora::store::AcceptedAnswerAction::Accept {
                post_id: solution.id.clone(),
            },
        )
        .await
        .unwrap();
    state
        .store
        .mark_thread_posts_read(ALICE_SUB, tid, &[op.id], 100)
        .await
        .unwrap();

    let reading = state
        .store
        .thread_reading_state(ALICE_SUB, tid)
        .await
        .unwrap();
    assert_eq!(reading.first_unread.as_ref().unwrap().id, solution.id);
    let (_, _, page) = send(
        &state,
        get_as(&format!("{location}?resume=1"), ALICE_SUB, ALICE_EMAIL),
    )
    .await;
    assert_eq!(
        page.matches(
            r#"<div class="ag-first-unread ag-key-private" id="thread-resume" role="separator" tabindex="-1"><span>First unread</span></div>"#
        )
        .count(),
        1
    );
    assert_eq!(page.matches("The accepted solution body.").count(), 1);
    assert!(page.contains("A later ordinary reply."));
    assert!(
        !page.contains("?before="),
        "the earliest accepted boundary has no phantom older reply page"
    );
    assert!(!page.contains("Load older"));
    let dais = page.find("Answer Dais").unwrap();
    let boundary = page.find("First unread").unwrap();
    let accepted = page.find("The accepted solution body.").unwrap();
    assert!(
        dais < boundary && boundary < accepted,
        "the visible unread separator marks the accepted post inside the Answer Dais"
    );
}

#[tokio::test]
async fn reading_receipt_post_is_csrf_guarded_and_batch_atomic() {
    let state = build_dev_state().await;
    let tok = "csrftoken123";
    let first_location = create_thread(&state, tok, "First receipt thread", "First OP.").await;
    let second_location = create_thread(&state, tok, "Second receipt thread", "Second OP.").await;
    let first_tid = first_location.strip_prefix("/t/").unwrap();
    let second_tid = second_location.strip_prefix("/t/").unwrap();
    let first_op = state
        .store
        .first_post_in_thread(first_tid)
        .await
        .unwrap()
        .unwrap();
    let second_op = state
        .store
        .first_post_in_thread(second_tid)
        .await
        .unwrap()
        .unwrap();

    let body = form(&[("csrf", tok), ("post_ids", &first_op.id)]);
    let (status, _, _) = send(
        &state,
        post_form(&format!("{first_location}/read"), None, true, body.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, _) = send(
        &state,
        post_form(&format!("{first_location}/read"), Some(tok), false, body),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let result = state
        .store
        .mark_thread_posts_read(
            ALICE_SUB,
            first_tid,
            &[first_op.id.clone(), second_op.id],
            200,
        )
        .await;
    assert!(result.is_err());
    let reading = state
        .store
        .thread_reading_state(ALICE_SUB, first_tid)
        .await
        .unwrap();
    assert!(!reading.started);
}

// --- helpers ---------------------------------------------------------------------------

async fn send(state: &AppState, req: Request<Body>) -> (StatusCode, HeaderMap, String) {
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
            .header("x-auth-email", "alice@steadholme.local");
    }
    b.body(Body::from(body)).unwrap()
}

/// POST as a specific gateway identity (subject + email), with a matching CSRF cookie.
fn post_form_as(uri: &str, tok: &str, subject: &str, email: &str, body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={tok}"))
        .header("x-auth-subject", subject)
        .header("x-auth-email", email)
        .body(Body::from(body))
        .unwrap()
}

/// GET as a specific gateway identity (so owner-only controls render for that subject).
fn get_as(uri: &str, subject: &str, email: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("x-auth-subject", subject)
        .header("x-auth-email", email)
        .body(Body::empty())
        .unwrap()
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

#[derive(Debug)]
struct DeleteReview {
    csrf: String,
    confirm: String,
}

/// Open a destructive-action review as `subject`, optionally preserving an existing CSRF
/// session so a token for one target can be proved unusable for another.
async fn delete_review_as(
    state: &AppState,
    uri: &str,
    subject: &str,
    email: &str,
    existing_csrf: Option<&str>,
) -> DeleteReview {
    let mut request = Request::builder()
        .uri(uri)
        .header("x-auth-subject", subject)
        .header("x-auth-email", email);
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

/// Keep the token structurally valid while forcing verification down the expiry branch.
fn expired_confirmation(confirm: &str) -> String {
    let (_, rest) = confirm
        .split_once('.')
        .expect("confirmation has an expiry prefix");
    format!("0.{rest}")
}
