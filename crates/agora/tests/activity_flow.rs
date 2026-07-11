//! End-to-end and adversarial coverage for the durable Activity Inbox.

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use tower::ServiceExt;

use agora::model::{ActivityReason, Post};
use agora::store::{
    ActivityFilter, StoreError, MAX_ACTIVITY_BATCH, MAX_KLAXON_RECIPIENTS_PER_REPLY,
    MAX_MENTIONS_PER_POST, MAX_THREAD_FOLLOWERS,
};
use agora::{app, build_dev_state, new_id, now_secs, AppState};

const ALICE_SUB: &str = "u_activity_alice";
const ALICE_EMAIL: &str = "alice@holdfast.local";
const BOB_SUB: &str = "u_activity_bob";
const BOB_EMAIL: &str = "bob@holdfast.local";
const CAROL_SUB: &str = "u_activity_carol";
const CAROL_EMAIL: &str = "carol@holdfast.local";
const TOK: &str = "activitycsrftoken123";

#[tokio::test]
async fn reply_fanout_deduplicates_paths_and_suppresses_actor() {
    let state = build_dev_state().await;
    let (location, thread_id) =
        create_thread(&state, ALICE_SUB, ALICE_EMAIL, "general", "Fan-out", "OP").await;
    follow(&state, &location, CAROL_SUB, CAROL_EMAIL, "follow").await;
    let op_id = state
        .store
        .first_post_in_thread(&thread_id)
        .await
        .unwrap()
        .unwrap()
        .id;
    let reply_id = reply(
        &state,
        &location,
        BOB_SUB,
        BOB_EMAIL,
        Some(&op_id),
        "Hello @alice and @bob",
    )
    .await;

    let alice = activity(&state, ALICE_SUB).await;
    assert_eq!(alice.len(), 1, "OP, quote and mention collapse to one item");
    assert_eq!(
        alice[0].reason,
        ActivityReason::Mention,
        "strongest reason wins"
    );
    assert_eq!(alice[0].event.post_id, reply_id);
    let carol = activity(&state, CAROL_SUB).await;
    assert_eq!(carol.len(), 1);
    assert_eq!(carol[0].reason, ActivityReason::Following);
    assert!(
        activity(&state, BOB_SUB).await.is_empty(),
        "actor never receives their own @mention/follow delivery"
    );

    let (status, _, _) = send(
        &state,
        post_as(
            &format!("/t/{thread_id}/p/{reply_id}/delete"),
            BOB_SUB,
            BOB_EMAIL,
            form(&[("csrf", TOK)]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(activity(&state, ALICE_SUB).await.is_empty());
    assert!(activity(&state, CAROL_SUB).await.is_empty());
}

#[tokio::test]
async fn read_unread_open_and_cross_user_authorization_are_coherent() {
    let state = build_dev_state().await;
    let (location, _thread_id) = create_thread(
        &state,
        ALICE_SUB,
        ALICE_EMAIL,
        "general",
        "Read state",
        "OP",
    )
    .await;
    let reply_id = reply(
        &state,
        &location,
        BOB_SUB,
        BOB_EMAIL,
        None,
        "A durable reply",
    )
    .await;
    let item = activity(&state, ALICE_SUB).await.remove(0);

    let (_, _, page) = send(&state, get_as("/activity", ALICE_SUB, ALICE_EMAIL)).await;
    assert!(page.contains("Mark this page read"));
    assert!(page.contains("Activity, 1 unread"));

    let (status, _, _) = send(
        &state,
        post_as(
            &format!("/activity/{}/state", item.event.id),
            BOB_SUB,
            BOB_EMAIL,
            form(&[("csrf", TOK), ("state", "read")]),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "another user cannot mutate the receipt"
    );

    let (status, _, _) = send(
        &state,
        post_as_without_cookie(
            &format!("/activity/{}/state", item.event.id),
            ALICE_SUB,
            ALICE_EMAIL,
            form(&[("csrf", TOK), ("state", "read")]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    set_state(&state, &item.event.id, "read").await;
    assert_eq!(unread(&state, ALICE_SUB).await, 0);
    set_state(&state, &item.event.id, "unread").await;
    assert_eq!(unread(&state, ALICE_SUB).await, 1);

    let next = format!(
        "{}?around={}_{}#post-{}",
        location, item.post_created_at, reply_id, reply_id
    );
    let (status, headers, _) = send(
        &state,
        post_as(
            &format!("/activity/{}/open", item.event.id),
            ALICE_SUB,
            ALICE_EMAIL,
            form(&[("csrf", TOK), ("next", &next)]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers.get(header::LOCATION).unwrap(), next.as_str());
    assert_eq!(unread(&state, ALICE_SUB).await, 0);
    let (status, _, target) = send(&state, get_as(&next, ALICE_SUB, ALICE_EMAIL)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(target.contains("A durable reply"));
}

#[tokio::test]
async fn page_batch_is_bounded_atomic_and_does_not_capture_new_activity() {
    let state = build_dev_state().await;
    let (location, _) =
        create_thread(&state, ALICE_SUB, ALICE_EMAIL, "general", "Batch", "OP").await;
    for index in 0..=MAX_ACTIVITY_BATCH {
        reply(
            &state,
            &location,
            BOB_SUB,
            BOB_EMAIL,
            None,
            &format!("batch reply {index}"),
        )
        .await;
    }
    let initial = activity(&state, ALICE_SUB).await;
    assert_eq!(initial.len(), MAX_ACTIVITY_BATCH + 1);
    let too_many: Vec<String> = initial.iter().map(|item| item.event.id.clone()).collect();
    let error = state
        .store
        .mark_activity_batch_read(ALICE_SUB, &too_many, now_secs())
        .await
        .expect_err("31 ids must be rejected before mutation");
    assert!(matches!(error, StoreError::InvalidOperation(_)));
    assert_eq!(unread(&state, ALICE_SUB).await, 31);

    let (other_location, _) = create_thread(
        &state,
        CAROL_SUB,
        CAROL_EMAIL,
        "general",
        "Other principal",
        "OP",
    )
    .await;
    reply(
        &state,
        &other_location,
        BOB_SUB,
        BOB_EMAIL,
        None,
        "Carol only",
    )
    .await;
    let other_id = activity(&state, CAROL_SUB).await[0].event.id.clone();
    let mixed = vec![initial[0].event.id.clone(), other_id];
    let error = state
        .store
        .mark_activity_batch_read(ALICE_SUB, &mixed, now_secs())
        .await
        .expect_err("mixed-user batch must roll back atomically");
    assert!(matches!(error, StoreError::NotFound(_)));
    assert_eq!(unread(&state, ALICE_SUB).await, 31);

    let page_ids: Vec<String> = initial
        .iter()
        .take(MAX_ACTIVITY_BATCH)
        .map(|item| item.event.id.clone())
        .collect();
    reply(
        &state,
        &location,
        BOB_SUB,
        BOB_EMAIL,
        None,
        "committed after rendered page",
    )
    .await;
    assert_eq!(
        state
            .store
            .mark_activity_batch_read(ALICE_SUB, &page_ids, now_secs())
            .await
            .unwrap(),
        MAX_ACTIVITY_BATCH as i64
    );
    assert_eq!(
        unread(&state, ALICE_SUB).await,
        2,
        "the old 31st item and newly committed event remain unread"
    );
}

#[tokio::test]
async fn accepted_answer_is_durable_and_failed_reply_command_is_atomic() {
    let state = build_dev_state().await;
    let (location, thread_id) = create_thread(
        &state,
        ALICE_SUB,
        ALICE_EMAIL,
        "support",
        "Accepted event",
        "Question",
    )
    .await;
    let answer_id = reply(&state, &location, BOB_SUB, BOB_EMAIL, None, "The answer").await;
    let (status, _, _) = send(
        &state,
        post_as(
            &format!("/t/{thread_id}/accept"),
            ALICE_SUB,
            ALICE_EMAIL,
            form(&[("csrf", TOK), ("action", "accept"), ("post_id", &answer_id)]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let bob = activity(&state, BOB_SUB).await;
    assert_eq!(bob.len(), 1);
    assert_eq!(bob[0].reason, ActivityReason::Answer);
    assert_eq!(bob[0].post_body_md, "The answer");

    let before_posts = state.store.count_posts(&thread_id).await.unwrap();
    let failed = Post {
        id: new_id("p"),
        thread_id: thread_id.clone(),
        body_md: "Atomic @alice".to_string(),
        quoted_post_id: "p_missing".to_string(),
        author_sub: BOB_SUB.to_string(),
        author_email: BOB_EMAIL.to_string(),
        created_at: now_secs(),
    };
    assert!(state
        .store
        .add_reply_with_activity(&failed, &["alice".to_string()], &new_id("a"),)
        .await
        .is_err());
    assert_eq!(
        state.store.count_posts(&thread_id).await.unwrap(),
        before_posts
    );
    assert_eq!(
        activity(&state, ALICE_SUB).await.len(),
        1,
        "failed reply did not append a post, mention, or activity event"
    );
}

#[tokio::test]
async fn subject_aliases_are_resolved_once_and_collisions_fail_closed() {
    let state = build_dev_state().await;
    let (alice_location, _) = create_thread(
        &state,
        ALICE_SUB,
        ALICE_EMAIL,
        "general",
        "Alias authority",
        "OP",
    )
    .await;
    reply(
        &state,
        &alice_location,
        BOB_SUB,
        BOB_EMAIL,
        None,
        "First @alice",
    )
    .await;
    let first_id = activity(&state, ALICE_SUB).await[0].event.id.clone();

    let (_, _, spoofed) = send(&state, get_as("/activity", "u_alias_spoofer", ALICE_EMAIL)).await;
    assert!(
        !spoofed.contains("First @alice"),
        "email local-part never authorises a delivery"
    );

    let (bob_location, _) = create_thread(
        &state,
        BOB_SUB,
        BOB_EMAIL,
        "general",
        "Rename registry",
        "OP",
    )
    .await;
    reply(
        &state,
        &bob_location,
        ALICE_SUB,
        "alice-renamed@holdfast.local",
        None,
        "register renamed alias",
    )
    .await;
    reply(
        &state,
        &bob_location,
        BOB_SUB,
        BOB_EMAIL,
        None,
        "Unique @alice-renamed",
    )
    .await;
    assert!(activity(&state, ALICE_SUB)
        .await
        .iter()
        .any(|item| item.post_body_md == "Unique @alice-renamed"));

    reply(
        &state,
        &bob_location,
        CAROL_SUB,
        "alice-renamed@another.invalid",
        None,
        "colliding profile",
    )
    .await;
    let before = activity(&state, ALICE_SUB).await.len();
    reply(
        &state,
        &bob_location,
        BOB_SUB,
        BOB_EMAIL,
        None,
        "Ambiguous @alice-renamed",
    )
    .await;
    let after = activity(&state, ALICE_SUB).await;
    assert_eq!(
        after.len(),
        before,
        "ambiguous aliases create no future delivery"
    );
    assert!(after.iter().any(|item| item.event.id == first_id));
    assert!(
        activity(&state, CAROL_SUB)
            .await
            .iter()
            .all(|item| item.event.id != first_id),
        "claiming an alias cannot transfer a historical subject delivery"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fanout_bounds_are_atomic_with_concurrent_followers() {
    let state = build_dev_state().await;
    let (_location, thread_id) = create_thread(
        &state,
        ALICE_SUB,
        ALICE_EMAIL,
        "general",
        "Bounded fanout",
        "OP",
    )
    .await;
    for index in 0..(MAX_THREAD_FOLLOWERS - 1) {
        state
            .store
            .set_thread_subscription(
                &thread_id,
                &format!("u_follower_{index:03}"),
                true,
                now_secs(),
            )
            .await
            .unwrap();
    }
    let mut contenders = Vec::new();
    for subject in ["u_boundary_a", "u_boundary_b"] {
        let store = state.store.clone();
        let thread_id = thread_id.clone();
        contenders.push(tokio::spawn(async move {
            store
                .set_thread_subscription(&thread_id, subject, true, now_secs())
                .await
                .map(|_| subject)
        }));
    }
    let mut successful = Vec::new();
    let mut rejected = 0;
    for contender in contenders {
        match contender.await.unwrap() {
            Ok(subject) => successful.push(subject),
            Err(StoreError::InvalidOperation(_)) => rejected += 1,
            Err(error) => panic!("unexpected follow result: {error}"),
        }
    }
    assert_eq!(successful.len(), 1);
    assert_eq!(rejected, 1);
    state
        .store
        .set_thread_subscription(&thread_id, successful[0], true, now_secs())
        .await
        .expect("an existing follow remains idempotent at the cap");
    assert!(matches!(
        state
            .store
            .set_thread_subscription(&thread_id, "u_cap_plus_one", true, now_secs())
            .await
            .unwrap_err(),
        StoreError::InvalidOperation(_)
    ));

    let before_posts = state.store.count_posts(&thread_id).await.unwrap();
    let too_many_mentions: Vec<String> = (0..=MAX_MENTIONS_PER_POST)
        .map(|index| format!("alias{index}"))
        .collect();
    let rejected_post = Post {
        id: new_id("p"),
        thread_id: thread_id.clone(),
        body_md: "too many mentions".to_string(),
        quoted_post_id: String::new(),
        author_sub: BOB_SUB.to_string(),
        author_email: BOB_EMAIL.to_string(),
        created_at: now_secs(),
    };
    assert!(matches!(
        state
            .store
            .add_reply_with_activity(&rejected_post, &too_many_mentions, &new_id("a"))
            .await
            .unwrap_err(),
        StoreError::InvalidOperation(_)
    ));
    assert_eq!(
        state.store.count_posts(&thread_id).await.unwrap(),
        before_posts
    );

    let accepted_post = Post {
        id: new_id("p"),
        thread_id: thread_id.clone(),
        body_md: "bounded delivery".to_string(),
        quoted_post_id: String::new(),
        author_sub: BOB_SUB.to_string(),
        author_email: BOB_EMAIL.to_string(),
        created_at: now_secs(),
    };
    let mutation = state
        .store
        .add_reply_with_activity(&accepted_post, &[], &new_id("a"))
        .await
        .unwrap();
    assert_eq!(mutation.delivery_subjects.len(), MAX_THREAD_FOLLOWERS + 1);
    assert!(mutation.delivery_subjects.len() <= MAX_KLAXON_RECIPIENTS_PER_REPLY);
    assert_eq!(
        state.store.count_posts(&thread_id).await.unwrap(),
        before_posts + 1
    );
}

#[tokio::test]
async fn admin_accept_uses_actor_subject_and_activity_filters_are_navigation() {
    let state = build_dev_state().await;
    let (location, thread_id) = create_thread(
        &state,
        ALICE_SUB,
        ALICE_EMAIL,
        "support",
        "Admin accepted",
        "Question",
    )
    .await;
    let answer_id = reply(&state, &location, BOB_SUB, BOB_EMAIL, None, "Admin answer").await;
    let (status, _, _) = send(
        &state,
        post_as_groups(
            &format!("/t/{thread_id}/accept"),
            "u_admin_without_profile",
            "admin@holdfast.local",
            "admins",
            form(&[("csrf", TOK), ("action", "accept"), ("post_id", &answer_id)]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let accepted = activity(&state, BOB_SUB)
        .await
        .into_iter()
        .find(|item| item.reason == ActivityReason::Answer)
        .unwrap();
    assert_eq!(accepted.event.actor_sub, "u_admin_without_profile");
    assert!(accepted.actor_email.is_empty());

    let (_, _, page) = send(&state, get_as("/activity", BOB_SUB, BOB_EMAIL)).await;
    assert!(page.contains("<strong>u_admin_without_profile</strong> accepted your answer"));
    assert!(!page.contains("<strong>alice@holdfast.local</strong> accepted your answer"));
    assert!(page.contains(r#"aria-current="page""#));
    assert!(!page.contains("role=\"tablist\""));
    assert!(!page.contains("aria-selected="));
}

async fn activity(state: &AppState, subject: &str) -> Vec<agora::model::ActivityItem> {
    state
        .store
        .activity_page(subject, ActivityFilter::All, false, None, 100)
        .await
        .unwrap()
}

async fn unread(state: &AppState, subject: &str) -> i64 {
    state.store.unread_activity_count(subject).await.unwrap()
}

async fn create_thread(
    state: &AppState,
    subject: &str,
    email: &str,
    category: &str,
    title: &str,
    body: &str,
) -> (String, String) {
    let (status, headers, _) = send(
        state,
        post_as(
            "/new",
            subject,
            email,
            form(&[
                ("csrf", TOK),
                ("category", category),
                ("title", title),
                ("body", body),
            ]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = headers
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let thread_id = location.trim_start_matches("/t/").to_string();
    (location, thread_id)
}

async fn reply(
    state: &AppState,
    location: &str,
    subject: &str,
    email: &str,
    quote: Option<&str>,
    body: &str,
) -> String {
    let mut pairs = vec![("csrf", TOK), ("body", body)];
    if let Some(quote) = quote {
        pairs.push(("quote_post_id", quote));
    }
    let (status, _, _) = send(
        state,
        post_as(&format!("{location}/reply"), subject, email, form(&pairs)),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let thread_id = location.trim_start_matches("/t/");
    state
        .store
        .posts_in_thread(thread_id)
        .await
        .unwrap()
        .into_iter()
        .find(|post| post.author_sub == subject && post.body_md == body)
        .unwrap()
        .id
}

async fn follow(state: &AppState, location: &str, subject: &str, email: &str, action: &str) {
    let (status, _, _) = send(
        state,
        post_as(
            &format!("{location}/subscribe"),
            subject,
            email,
            form(&[("csrf", TOK), ("action", action)]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
}

async fn set_state(state: &AppState, activity_id: &str, next: &str) {
    let (status, _, _) = send(
        state,
        post_as(
            &format!("/activity/{activity_id}/state"),
            ALICE_SUB,
            ALICE_EMAIL,
            form(&[("csrf", TOK), ("state", next)]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
}

async fn send(state: &AppState, request: Request<Body>) -> (StatusCode, HeaderMap, String) {
    let response = app(state.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
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

fn post_as(uri: &str, subject: &str, email: &str, body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={TOK}"))
        .header("x-auth-subject", subject)
        .header("x-auth-email", email)
        .body(Body::from(body))
        .unwrap()
}

fn post_as_groups(
    uri: &str,
    subject: &str,
    email: &str,
    groups: &str,
    body: String,
) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={TOK}"))
        .header("x-auth-subject", subject)
        .header("x-auth-email", email)
        .header("x-auth-groups", groups)
        .body(Body::from(body))
        .unwrap()
}

fn post_as_without_cookie(uri: &str, subject: &str, email: &str, body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("x-auth-subject", subject)
        .header("x-auth-email", email)
        .body(Body::from(body))
        .unwrap()
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}
