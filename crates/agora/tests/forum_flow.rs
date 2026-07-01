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

// --- author edit/delete of own threads + replies ---------------------------------------

const ALICE_SUB: &str = "u_sub_1";
const ALICE_EMAIL: &str = "alice@holdfast.local";
const BOB_SUB: &str = "u_sub_bob";
const BOB_EMAIL: &str = "bob@holdfast.local";

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
    h.get(header::LOCATION).unwrap().to_str().unwrap().to_string()
}

#[tokio::test]
async fn author_can_edit_and_delete_own_thread() {
    let state = build_dev_state().await;
    let tok = "csrftoken123";
    let location = create_thread(&state, tok, "Orig Title", "Orig **body**.").await;
    let edit_uri = format!("{location}/edit");
    let delete_uri = format!("{location}/delete");

    // The author sees edit + delete controls on the thread page.
    let (_s, _h, page) = send(&state, get_as(&location, ALICE_SUB, ALICE_EMAIL)).await;
    assert!(page.contains(&edit_uri), "author sees the edit link");
    assert!(page.contains(&delete_uri), "author sees the delete form");

    // The edit form is prefilled with the current title + original-post body.
    let (s, _h, form_page) = send(&state, get_as(&edit_uri, ALICE_SUB, ALICE_EMAIL)).await;
    assert_eq!(s, StatusCode::OK);
    assert!(form_page.contains("Orig Title"), "title prefilled");
    assert!(form_page.contains("Orig **body**."), "OP body prefilled");

    // Save an edit → the thread renders the new title + body.
    let ebody = form(&[("csrf", tok), ("title", "New Title"), ("body", "New _body_.")]);
    let (s, _h, _b) = send(&state, post_form_as(&edit_uri, tok, ALICE_SUB, ALICE_EMAIL, ebody)).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let (_s, _h, page) = send(&state, get(&location)).await;
    assert!(page.contains("New Title"), "new title shown");
    assert!(page.contains("<em>body</em>"), "new OP markdown rendered");
    assert!(!page.contains("Orig Title"), "old title gone");

    // Delete → 303 to the category, and the thread is now 404.
    let (s, dh, _b) =
        send(&state, post_form_as(&delete_uri, tok, ALICE_SUB, ALICE_EMAIL, form(&[("csrf", tok)]))).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(dh.get(header::LOCATION).unwrap().to_str().unwrap(), "/c/general");
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
    assert!(!page.contains(&delete_uri), "non-author sees no delete form");

    // Bob is blocked from the edit form, the update, and the delete (CSRF valid — author fails).
    let (s, _h, _b) = send(&state, get_as(&edit_uri, BOB_SUB, BOB_EMAIL)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let ebody = form(&[("csrf", tok), ("title", "Hijacked"), ("body", "x")]);
    let (s, _h, _b) = send(&state, post_form_as(&edit_uri, tok, BOB_SUB, BOB_EMAIL, ebody)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _h, _b) =
        send(&state, post_form_as(&delete_uri, tok, BOB_SUB, BOB_EMAIL, form(&[("csrf", tok)]))).await;
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
    let (s, _h, _b) = send(&state, post_form(&format!("{location}/edit"), None, true, body)).await;
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
    let (s, _h, _b) =
        send(&state, post_form_as(&format!("{location}/reply"), tok, BOB_SUB, BOB_EMAIL, reply)).await;
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
    assert!(!apage.contains(&edit_uri), "non-author sees no reply controls");

    // Alice cannot edit bob's reply.
    let ebody = form(&[("csrf", tok), ("body", "alice hijack")]);
    let (s, _h, _b) = send(&state, post_form_as(&edit_uri, tok, ALICE_SUB, ALICE_EMAIL, ebody)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Bob edits his own reply.
    let ebody = form(&[("csrf", tok), ("body", "Bob _edited_ reply.")]);
    let (s, _h, _b) = send(&state, post_form_as(&edit_uri, tok, BOB_SUB, BOB_EMAIL, ebody)).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let (_s, _h, page) = send(&state, get(&location)).await;
    assert!(page.contains("<em>edited</em>"), "edited reply markdown rendered");
    assert!(!page.contains("Bob original reply"), "old reply body gone");

    // Bob deletes his own reply.
    let (s, _h, _b) =
        send(&state, post_form_as(&delete_uri, tok, BOB_SUB, BOB_EMAIL, form(&[("csrf", tok)]))).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
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
    let op_id = state.store.posts_in_thread(&tid).await.unwrap()[0].id.clone();

    let ebody = form(&[("csrf", tok), ("body", "sneaky")]);
    let (s, _h, _b) = send(
        &state,
        post_form_as(&format!("/t/{tid}/p/{op_id}/edit"), tok, ALICE_SUB, ALICE_EMAIL, ebody),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _h, _b) = send(
        &state,
        post_form_as(&format!("/t/{tid}/p/{op_id}/delete"), tok, ALICE_SUB, ALICE_EMAIL, form(&[("csrf", tok)])),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // The original post survives.
    assert_eq!(state.store.posts_in_thread(&tid).await.unwrap().len(), 1);
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
