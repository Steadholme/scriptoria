//! End-to-end tests for forum reactions + accepted-answer, over the in-memory store.
//!
//! Drives the real `app` Router via `tower::oneshot`, exactly like `forum_flow`. Covers: the
//! idempotent reaction toggle + its per-viewer count/"mine" rendering; CSRF + identity gating on
//! the react POST; the unknown-kind rejection; the thread-author/admin-gated accepted-answer mark
//! (with a non-author refusal); the accepted reply sorting first under the OP and rendering its
//! badge; and the idempotent unmark (toggle-off).

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use tower::ServiceExt;

use agora::{app, build_dev_state, AppState};

const ALICE_SUB: &str = "u_sub_1";
const ALICE_EMAIL: &str = "alice@steadholme.local";
const BOB_SUB: &str = "u_sub_bob";
const BOB_EMAIL: &str = "bob@steadholme.local";
const TOK: &str = "csrftoken123";

#[tokio::test]
async fn reaction_toggle_is_idempotent_and_per_user() {
    let state = build_dev_state().await;
    let loc = create_thread(&state, "React here", "OP body.").await;
    let tid = loc.strip_prefix("/t/").unwrap().to_string();
    // The OP is the only post; grab its id from the store.
    let pid = state.store.posts_in_thread(&tid).await.unwrap()[0].id.clone();
    let react_uri = format!("/t/{tid}/p/{pid}/react");

    // Alice reacts "up" → count 1, and it renders as HER active reaction.
    let (s, _h, _b) = send(
        &state,
        post_as(&react_uri, TOK, ALICE_SUB, ALICE_EMAIL, form(&[("csrf", TOK), ("kind", "up")])),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);

    let (_s, _h, page) = send(&state, get_as(&loc, ALICE_SUB, ALICE_EMAIL)).await;
    assert!(page.contains(r##"data-wire-target="#post-"##));
    assert!(page.contains("odyssey-wire v1"));
    assert!(page.contains("odyssey-spark v1"));
    assert!(!page.contains("handleReact"));
    assert!(page.contains(r#"class="reaction is-mine""#), "alice sees her own reaction highlighted");
    assert!(page.contains(r#"<span class="reaction__count">1</span>"#), "count is 1");

    // Bob sees the same count of 1, but NOT highlighted as his.
    let (_s, _h, bpage) = send(&state, get_as(&loc, BOB_SUB, BOB_EMAIL)).await;
    assert!(bpage.contains(r#"<span class="reaction__count">1</span>"#), "bob sees count 1");
    assert!(!bpage.contains(r#"class="reaction is-mine""#), "not bob's reaction");

    // Bob adds his own "up" → count 2. Two distinct users, unique per (post,user,kind).
    let (s, _h, _b) = send(
        &state,
        post_as(&react_uri, TOK, BOB_SUB, BOB_EMAIL, form(&[("csrf", TOK), ("kind", "up")])),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let (_s, _h, page) = send(&state, get_as(&loc, ALICE_SUB, ALICE_EMAIL)).await;
    assert!(page.contains(r#"<span class="reaction__count">2</span>"#), "count is now 2");

    // Alice toggles "up" again → her reaction is removed (idempotent toggle), count back to 1.
    let (s, _h, _b) = send(
        &state,
        post_as(&react_uri, TOK, ALICE_SUB, ALICE_EMAIL, form(&[("csrf", TOK), ("kind", "up")])),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let (_s, _h, page) = send(&state, get_as(&loc, ALICE_SUB, ALICE_EMAIL)).await;
    assert!(page.contains(r#"<span class="reaction__count">1</span>"#), "alice's toggle removed → 1");
    assert!(!page.contains(r#"class="reaction is-mine""#), "alice no longer highlighted");
}

#[tokio::test]
async fn react_requires_csrf_identity_and_known_kind() {
    let state = build_dev_state().await;
    let loc = create_thread(&state, "Guarded", "OP.").await;
    let tid = loc.strip_prefix("/t/").unwrap().to_string();
    let pid = state.store.posts_in_thread(&tid).await.unwrap()[0].id.clone();
    let react_uri = format!("/t/{tid}/p/{pid}/react");

    // No CSRF cookie → forbidden.
    let (s, _h, _b) = send(
        &state,
        post_form(&react_uri, None, true, form(&[("csrf", TOK), ("kind", "up")])),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Valid CSRF but no identity → unauthorized.
    let (s, _h, _b) = send(
        &state,
        post_form(&react_uri, Some(TOK), false, form(&[("csrf", TOK), ("kind", "up")])),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Unknown reaction kind → bad request.
    let (s, _h, _b) = send(
        &state,
        post_as(&react_uri, TOK, ALICE_SUB, ALICE_EMAIL, form(&[("csrf", TOK), ("kind", "rocket")])),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn author_marks_accepted_answer_sorts_first_with_badge() {
    let state = build_dev_state().await;
    let loc = create_thread(&state, "Question", "How do I do X?").await;
    let tid = loc.strip_prefix("/t/").unwrap().to_string();

    // Two replies from bob. Space every post by >1s so the oldest-first order is deterministic
    // (timestamps are epoch SECONDS): OP, then first reply, then second reply.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    reply_as(&state, &loc, BOB_SUB, BOB_EMAIL, "First reply — not it.").await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    reply_as(&state, &loc, BOB_SUB, BOB_EMAIL, "Second reply — THE answer.").await;

    let posts = state.store.posts_in_thread(&tid).await.unwrap();
    assert_eq!(posts.len(), 3, "OP + two replies");
    let second_reply = posts[2].id.clone();

    // A non-author (bob) cannot mark the accepted answer.
    let (s, _h, _b) = send(
        &state,
        post_as(&format!("/t/{tid}/accept"), TOK, BOB_SUB, BOB_EMAIL, form(&[("csrf", TOK), ("action", "accept"), ("post_id", &second_reply)])),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "only the thread author/admin may accept");

    // The thread author (alice) marks the SECOND reply as accepted.
    let (s, _h, _b) = send(
        &state,
        post_as(&format!("/t/{tid}/accept"), TOK, ALICE_SUB, ALICE_EMAIL, form(&[("csrf", TOK), ("action", "accept"), ("post_id", &second_reply)])),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);

    // The thread persisted the accepted id.
    let reloaded = state.store.get_thread(&tid).await.unwrap().unwrap();
    assert_eq!(reloaded.accepted_post_id, second_reply);

    // Render: the accepted reply owns one labelled Solution region and appears before the first
    // ordinary reply. Its content is not duplicated in the normal stream.
    let (_s, _h, page) = send(&state, get_as(&loc, ALICE_SUB, ALICE_EMAIL)).await;
    assert!(
        page.contains("Accepted answer"),
        "accepted heading rendered"
    );
    assert_eq!(page.matches(r#"class="ag-solution""#).count(), 1);
    assert_eq!(page.matches("Second reply").count(), 1);
    assert!(page.contains(".ag-solution .post[id] {"));
    assert!(page.contains("scroll-margin-top:calc(var(--appbar-h,56px) + 124px);"));
    assert!(page.contains("scroll-margin-top:calc(var(--appbar-h,56px) + 60px);"));
    let acc = page.find("Second reply").expect("accepted reply present");
    let first = page.find("First reply").expect("first reply present");
    assert!(acc < first, "accepted reply sorts before the earlier reply");

    // Accept is idempotent: repeating it leaves the same solution selected.
    let (s, _h, _b) = send(
        &state,
        post_as(&format!("/t/{tid}/accept"), TOK, ALICE_SUB, ALICE_EMAIL, form(&[("csrf", TOK), ("action", "accept"), ("post_id", &second_reply)])),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let reloaded = state.store.get_thread(&tid).await.unwrap().unwrap();
    assert_eq!(reloaded.accepted_post_id, second_reply);

    // Clear is its own idempotent command and does not depend on a target field.
    let (s, _h, _b) = send(
        &state,
        post_as(&format!("/t/{tid}/accept"), TOK, ALICE_SUB, ALICE_EMAIL, form(&[("csrf", TOK), ("action", "clear")])),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert!(state.store.get_thread(&tid).await.unwrap().unwrap().accepted_post_id.is_empty());
}

#[tokio::test]
async fn original_post_cannot_be_accepted() {
    let state = build_dev_state().await;
    let loc = create_thread(&state, "No OP accept", "OP body.").await;
    let tid = loc.strip_prefix("/t/").unwrap().to_string();
    let op_id = state.store.posts_in_thread(&tid).await.unwrap()[0].id.clone();

    let (s, _h, _b) = send(
        &state,
        post_as(&format!("/t/{tid}/accept"), TOK, ALICE_SUB, ALICE_EMAIL, form(&[("csrf", TOK), ("action", "accept"), ("post_id", &op_id)])),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "the OP can never be the accepted answer");
    let reloaded = state.store.get_thread(&tid).await.unwrap().unwrap();
    assert!(reloaded.accepted_post_id.is_empty());
}

// --- helpers ---------------------------------------------------------------------------

async fn create_thread(state: &AppState, title: &str, body_md: &str) -> String {
    let body = form(&[("csrf", TOK), ("category", "support"), ("title", title), ("body", body_md)]);
    let (status, h, _b) = send(state, post_as("/new", TOK, ALICE_SUB, ALICE_EMAIL, body)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    h.get(header::LOCATION).unwrap().to_str().unwrap().to_string()
}

async fn reply_as(state: &AppState, loc: &str, sub: &str, email: &str, body_md: &str) {
    let body = form(&[("csrf", TOK), ("body", body_md)]);
    let (s, _h, _b) = send(state, post_as(&format!("{loc}/reply"), TOK, sub, email, body)).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
}

async fn send(state: &AppState, req: Request<Body>) -> (StatusCode, HeaderMap, String) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, headers, String::from_utf8(bytes.to_vec()).unwrap())
}

fn get_as(uri: &str, subject: &str, email: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("x-auth-subject", subject)
        .header("x-auth-email", email)
        .body(Body::empty())
        .unwrap()
}

fn post_as(uri: &str, tok: &str, subject: &str, email: &str, body: String) -> Request<Body> {
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
            .header("x-auth-subject", ALICE_SUB)
            .header("x-auth-email", ALICE_EMAIL);
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
