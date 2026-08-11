//! End-to-end coverage for the product-owned Q&A Answer Desk.

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use tower::ServiceExt;

use agora::model::{CategoryFormat, Post, Thread};
use agora::store::{AcceptedAnswerAction, ThreadSort, ThreadStatusFilter};
use agora::{app, build_dev_state, now_secs, AppState};

const ALICE_SUB: &str = "u_question_alice";
const ALICE_EMAIL: &str = "alice-question@steadholme.local";
const BOB_SUB: &str = "u_question_bob";
const BOB_EMAIL: &str = "bob-question@steadholme.local";
const TOK: &str = "questioncsrftoken123";
const LATEST_ANCHOR: &str =
    r#"<span class="ag-thread-latest-anchor" id="thread-latest" tabindex="-1"></span>"#;

#[tokio::test]
async fn question_lifecycle_filters_and_historical_clear_are_coherent() {
    let state = build_dev_state().await;
    assert_eq!(
        state
            .store
            .get_category("general")
            .await
            .unwrap()
            .unwrap()
            .format,
        CategoryFormat::Discussion
    );
    assert_eq!(
        state
            .store
            .get_category("support")
            .await
            .unwrap()
            .unwrap()
            .format,
        CategoryFormat::Question
    );

    let question = create_thread(
        &state,
        "support",
        "How should leases be renewed?",
        "We need one durable renewal pattern.",
    )
    .await;
    let discussion = create_thread(
        &state,
        "general",
        "Lease design discussion",
        "Open-ended tradeoffs belong here.",
    )
    .await;

    let (_, _, unanswered) = send(&state, get("/?status=unanswered")).await;
    assert!(unanswered.contains("How should leases be renewed?"));
    assert!(!unanswered.contains("Lease design discussion"));
    assert!(unanswered.contains("Questions that need an answer"));

    let (_, _, desk) = send(&state, get("/questions")).await;
    assert!(desk.contains("How should leases be renewed?"));
    assert!(!desk.contains("Lease design discussion"));
    assert!(desk.contains("Needs answer"));
    assert!(desk.contains(r#"href="/questions?sort=latest&amp;status=answered""#));

    let (_, _, question_page) = send(&state, get_as(&question, ALICE_SUB, ALICE_EMAIL)).await;
    assert!(question_page.contains("Needs answer"));
    assert!(question_page.contains("Your answer"));
    assert!(question_page.contains("Post answer"));
    assert_eq!(question_page.matches(LATEST_ANCHOR).count(), 1);
    assert!(
        question_page.find("Original post").unwrap() < question_page.find(LATEST_ANCHOR).unwrap(),
        "a question without replies anchors Latest after the typed reply boundary"
    );

    let answer_id = reply(
        &state,
        &question,
        BOB_SUB,
        BOB_EMAIL,
        "Renew before half-life.",
    )
    .await;
    let question_id = question.trim_start_matches("/t/");
    let (status, _, _) = send(
        &state,
        post_as(
            &format!("/t/{question_id}/accept"),
            ALICE_SUB,
            ALICE_EMAIL,
            form(&[("csrf", TOK), ("action", "accept"), ("post_id", &answer_id)]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (_, _, answered_page) = send(&state, get_as(&question, ALICE_SUB, ALICE_EMAIL)).await;
    let dais = answered_page
        .find(r#"<section class="ag-dais ag-key-shared" aria-labelledby="ag-dais-title">"#)
        .unwrap();
    let answer = answered_page.find("Renew before half-life.").unwrap();
    let latest = answered_page.find(LATEST_ANCHOR).unwrap();
    assert!(
        dais < answer && answer < latest,
        "the accepted answer is rendered once on the Answer Dais before the latest boundary"
    );
    assert_eq!(answered_page.matches("Renew before half-life.").count(), 1);

    let (_, _, answered) = send(&state, get("/questions?status=answered")).await;
    assert!(answered.contains("How should leases be renewed?"));
    assert!(answered.contains("Answered"));
    let (_, _, no_longer_unanswered) = send(&state, get("/questions?status=unanswered")).await;
    assert!(!no_longer_unanswered.contains("How should leases be renewed?"));

    // A normal discussion cannot select a new solution.
    let discussion_reply = reply(
        &state,
        &discussion,
        BOB_SUB,
        BOB_EMAIL,
        "One possible tradeoff.",
    )
    .await;
    let discussion_id = discussion.trim_start_matches("/t/");
    let (status, _, body) = send(
        &state,
        post_as(
            &format!("/t/{discussion_id}/accept"),
            ALICE_SUB,
            ALICE_EMAIL,
            form(&[
                ("csrf", TOK),
                ("action", "accept"),
                ("post_id", &discussion_reply),
            ]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("only in question categories"));

    // Historical accepted data in a discussion remains visible and can be cleared, but does not
    // unlock selection of any other reply.
    let historical_id = "t_historical_discussion";
    let historical_reply_id = "p_historical_discussion_reply";
    let historical_thread = Thread {
        id: historical_id.to_string(),
        category_id: "general".to_string(),
        title: "Historical accepted discussion".to_string(),
        author_sub: ALICE_SUB.to_string(),
        author_email: ALICE_EMAIL.to_string(),
        created_at: 500,
        last_at: 501,
        locked: false,
        pinned: false,
        accepted_post_id: historical_reply_id.to_string(),
    };
    let historical_op = Post {
        id: "p_historical_discussion_op".to_string(),
        thread_id: historical_id.to_string(),
        body_md: "Historical discussion body".to_string(),
        quoted_post_id: String::new(),
        author_sub: ALICE_SUB.to_string(),
        author_email: ALICE_EMAIL.to_string(),
        created_at: 500,
    };
    state
        .store
        .create_thread(&historical_thread, &historical_op)
        .await
        .unwrap();
    state
        .store
        .add_reply(&Post {
            id: historical_reply_id.to_string(),
            thread_id: historical_id.to_string(),
            body_md: "LEGACY SOLUTION ONLY".to_string(),
            quoted_post_id: String::new(),
            author_sub: BOB_SUB.to_string(),
            author_email: BOB_EMAIL.to_string(),
            created_at: 501,
        })
        .await
        .unwrap();
    let historical_location = format!("/t/{historical_id}");
    let (_, _, historical) =
        send(&state, get_as(&historical_location, ALICE_SUB, ALICE_EMAIL)).await;
    assert!(historical.contains("Answer Dais"));
    assert!(historical.contains("Remove solution"));
    assert_eq!(
        historical
            .matches(&format!(r#"action="/t/{historical_id}/accept""#))
            .count(),
        1,
        "historical discussion exposes only the clear action"
    );
    let public_rows = state
        .store
        .list_threads(
            None,
            ThreadSort::Latest,
            None,
            ThreadStatusFilter::Any,
            100,
            1_000,
        )
        .await
        .unwrap();
    assert!(public_rows
        .iter()
        .find(|thread| thread.id == historical_id)
        .unwrap()
        .accepted_post_id
        .is_empty());
    assert!(state
        .store
        .list_threads(
            None,
            ThreadSort::Latest,
            None,
            ThreadStatusFilter::Answered,
            100,
            1_000,
        )
        .await
        .unwrap()
        .iter()
        .all(|thread| thread.id != historical_id));
    assert!(state
        .store
        .search_threads("legacy solution only", None, ThreadStatusFilter::Any, 100,)
        .await
        .unwrap()
        .iter()
        .all(|hit| hit.thread.id != historical_id));
    let (status, _, _) = send(
        &state,
        post_as(
            &format!("/t/{historical_id}/accept"),
            ALICE_SUB,
            ALICE_EMAIL,
            form(&[
                ("csrf", TOK),
                ("action", "clear"),
                ("post_id", historical_reply_id),
            ]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(state
        .store
        .get_thread(historical_id)
        .await
        .unwrap()
        .unwrap()
        .accepted_post_id
        .is_empty());
}

#[tokio::test]
async fn accepted_solution_is_fixed_above_a_full_reply_page_without_duplication() {
    let state = build_dev_state().await;
    let location = create_thread(
        &state,
        "support",
        "Paged answer fixture",
        "The accepted answer will naturally fall beyond page one.",
    )
    .await;
    let thread_id = location.trim_start_matches("/t/");
    let base = now_secs() + 10;
    let mut accepted_id = String::new();
    for index in 0..25 {
        let id = format!("p_paged_answer_{index:02}");
        let body = if index == 24 {
            accepted_id = id.clone();
            "THE PAGED SOLUTION"
        } else {
            "ordinary paged reply"
        };
        state
            .store
            .add_reply(&Post {
                id,
                thread_id: thread_id.to_string(),
                body_md: format!("{body} {index}"),
                quoted_post_id: String::new(),
                author_sub: BOB_SUB.to_string(),
                author_email: BOB_EMAIL.to_string(),
                created_at: base + index,
            })
            .await
            .unwrap();
    }
    state
        .store
        .mutate_accepted_answer(
            thread_id,
            AcceptedAnswerAction::Accept {
                post_id: accepted_id.clone(),
            },
        )
        .await
        .unwrap();

    let (_, _, first_page) = send(&state, get_as(&location, ALICE_SUB, ALICE_EMAIL)).await;
    assert_eq!(first_page.matches("THE PAGED SOLUTION").count(), 1);
    assert!(first_page.contains("ordinary paged reply 0"));
    assert!(first_page.contains("ordinary paged reply 19"));
    assert!(!first_page.contains("ordinary paged reply 20"));
    assert!(first_page.contains(&format!(
        r#"<a class="btn btn-ghost btn-sm ag-page__jump" href="/t/{thread_id}?latest=1#thread-latest">Jump to latest</a>"#
    )));

    let (_, _, latest_page) = send(
        &state,
        get_as(&format!("{location}?latest=1"), ALICE_SUB, ALICE_EMAIL),
    )
    .await;
    assert_eq!(latest_page.matches("THE PAGED SOLUTION").count(), 1);
    assert!(latest_page.contains("ordinary paged reply 23"));
    assert!(latest_page.contains("25 replies"));
    assert_eq!(latest_page.matches(LATEST_ANCHOR).count(), 1);
    let last_reply = latest_page
        .find(r#"<article class="ag-post ag-key-shared" id="post-p_paged_answer_23">"#)
        .unwrap();
    assert!(
        last_reply < latest_page.find(LATEST_ANCHOR).unwrap(),
        "the latest boundary follows the last typed reply"
    );
    assert!(
        !latest_page.contains(r#"class="btn btn-ghost btn-sm ag-page__jump""#),
        "the latest page does not render a redundant jump"
    );
}

#[tokio::test]
async fn admin_format_and_move_guards_preserve_answer_semantics() {
    let state = build_dev_state().await;
    let (status, _, _) = send(
        &state,
        post_admin(
            "/admin/categories",
            form(&[
                ("csrf", TOK),
                ("id", "expert-help"),
                ("name", "Expert Help"),
                ("format", "question"),
            ]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        state
            .store
            .get_category("expert-help")
            .await
            .unwrap()
            .unwrap()
            .format,
        CategoryFormat::Question
    );

    let location = create_thread(
        &state,
        "expert-help",
        "Format transition fixture",
        "This question will be answered.",
    )
    .await;
    let thread_id = location.trim_start_matches("/t/");
    let answer_id = reply(&state, &location, BOB_SUB, BOB_EMAIL, "Accepted expertise.").await;
    state
        .store
        .mutate_accepted_answer(
            thread_id,
            AcceptedAnswerAction::Accept {
                post_id: answer_id.clone(),
            },
        )
        .await
        .unwrap();

    let (status, _, body) = send(
        &state,
        post_admin(
            "/admin/categories/expert-help/format",
            form(&[("csrf", TOK), ("format", "discussion")]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("unmark accepted answers"));

    let (status, _, body) = send(
        &state,
        post_admin(
            &format!("/admin/threads/{thread_id}/move"),
            form(&[("csrf", TOK), ("category", "general")]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("unmark the accepted answer"));

    state
        .store
        .mutate_accepted_answer(thread_id, AcceptedAnswerAction::Clear)
        .await
        .unwrap();
    let (status, _, _) = send(
        &state,
        post_admin(
            &format!("/admin/threads/{thread_id}/move"),
            form(&[("csrf", TOK), ("category", "general")]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (status, _, _) = send(
        &state,
        post_admin(
            "/admin/categories/expert-help/format",
            form(&[("csrf", TOK), ("format", "discussion")]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
}

async fn create_thread(state: &AppState, category: &str, title: &str, body_md: &str) -> String {
    let (status, headers, _) = send(
        state,
        post_as(
            "/new",
            ALICE_SUB,
            ALICE_EMAIL,
            form(&[
                ("csrf", TOK),
                ("category", category),
                ("title", title),
                ("body", body_md),
            ]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    headers
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

async fn reply(state: &AppState, location: &str, subject: &str, email: &str, body: &str) -> String {
    let thread_id = location.trim_start_matches("/t/");
    let before = state.store.posts_in_thread(thread_id).await.unwrap();
    let (status, _, _) = send(
        state,
        post_as(
            &format!("{location}/reply"),
            subject,
            email,
            form(&[("csrf", TOK), ("body", body)]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    state
        .store
        .posts_in_thread(thread_id)
        .await
        .unwrap()
        .into_iter()
        .find(|post| before.iter().all(|old| old.id != post.id))
        .unwrap()
        .id
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

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
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

fn post_admin(uri: &str, body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={TOK}"))
        .header("x-auth-subject", "u_question_admin")
        .header("x-auth-email", "question-admin@steadholme.local")
        .header("x-auth-groups", "forum-admins")
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
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}
