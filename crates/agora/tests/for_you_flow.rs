//! Vertical coverage for result-oriented thread preferences and the explainable personal feed.

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use tower::ServiceExt;

use agora::model::{ActivityReason, Post, Thread, ThreadFollowLevel};
use agora::store::{
    AcceptedAnswerAction, ActivityFilter, ThreadSort, ThreadStatusFilter,
};
use agora::{app, build_dev_state, new_id, AppState};

const ALICE_SUB: &str = "u_v7_alice";
const ALICE_EMAIL: &str = "alice@holdfast.local";
const BOB_SUB: &str = "u_v7_bob";
const BOB_EMAIL: &str = "bob@holdfast.local";
const CAROL_SUB: &str = "u_v7_carol";
const CAROL_EMAIL: &str = "carol@holdfast.local";
const TOK: &str = "v7forumcsrftoken123";

#[tokio::test]
async fn follow_levels_split_generic_activity_following_and_direct_authority() {
    let state = build_dev_state().await;
    seed_thread(
        &state,
        "t_v7_watch",
        "Watch activity",
        ALICE_SUB,
        ALICE_EMAIL,
        100,
    )
    .await;
    seed_thread(
        &state,
        "t_v7_follow",
        "Quiet follow",
        ALICE_SUB,
        ALICE_EMAIL,
        110,
    )
    .await;
    seed_thread(
        &state,
        "t_v7_mute",
        "Muted generic",
        ALICE_SUB,
        ALICE_EMAIL,
        120,
    )
    .await;
    state
        .store
        .set_thread_follow_level("t_v7_watch", CAROL_SUB, ThreadFollowLevel::Watch, 130)
        .await
        .unwrap();
    state
        .store
        .set_thread_follow_level("t_v7_follow", CAROL_SUB, ThreadFollowLevel::Follow, 131)
        .await
        .unwrap();
    state
        .store
        .set_thread_follow_level("t_v7_mute", CAROL_SUB, ThreadFollowLevel::Mute, 132)
        .await
        .unwrap();

    reply(&state, "t_v7_watch", "watch reply", BOB_SUB, BOB_EMAIL, 140).await;
    reply(
        &state,
        "t_v7_follow",
        "follow reply",
        BOB_SUB,
        BOB_EMAIL,
        141,
    )
    .await;
    reply(&state, "t_v7_mute", "mute reply", BOB_SUB, BOB_EMAIL, 142).await;
    let activity = state
        .store
        .activity_page(CAROL_SUB, ActivityFilter::All, false, None, 20)
        .await
        .unwrap();
    assert_eq!(activity.len(), 1);
    assert_eq!(activity[0].thread_title, "Watch activity");
    assert_eq!(activity[0].reason, ActivityReason::Following);

    let following = state
        .store
        .list_threads(
            None,
            ThreadSort::Latest,
            Some(CAROL_SUB),
            ThreadStatusFilter::Any,
            20,
            200,
        )
        .await
        .unwrap();
    let following_ids = following
        .iter()
        .map(|thread| thread.id.as_str())
        .collect::<Vec<_>>();
    assert!(following_ids.contains(&"t_v7_watch"));
    assert!(following_ids.contains(&"t_v7_follow"));
    assert!(!following_ids.contains(&"t_v7_mute"));

    // Leaving Watch removes already-delivered generic activity as well as future fan-out.
    state
        .store
        .set_thread_follow_level("t_v7_watch", CAROL_SUB, ThreadFollowLevel::Follow, 201)
        .await
        .unwrap();
    assert!(state
        .store
        .activity_page(CAROL_SUB, ActivityFilter::All, false, None, 20)
        .await
        .unwrap()
        .is_empty());
    reply(
        &state,
        "t_v7_watch",
        "quiet after switch",
        BOB_SUB,
        BOB_EMAIL,
        202,
    )
    .await;
    assert!(state
        .store
        .activity_page(CAROL_SUB, ActivityFilter::All, false, None, 20)
        .await
        .unwrap()
        .is_empty());

    // Mute is not a block: a direct reply to the thread author remains authoritative.
    seed_thread(
        &state,
        "t_v7_direct",
        "Muted but direct",
        CAROL_SUB,
        CAROL_EMAIL,
        210,
    )
    .await;
    state
        .store
        .set_thread_follow_level("t_v7_direct", CAROL_SUB, ThreadFollowLevel::Mute, 211)
        .await
        .unwrap();
    reply(
        &state,
        "t_v7_direct",
        "direct owner reply",
        BOB_SUB,
        BOB_EMAIL,
        212,
    )
    .await;
    let direct = state
        .store
        .activity_page(CAROL_SUB, ActivityFilter::All, false, None, 20)
        .await
        .unwrap();
    assert_eq!(direct.len(), 1);
    assert_eq!(direct[0].reason, ActivityReason::Reply);
    assert_eq!(direct[0].thread_title, "Muted but direct");

    // Mute suppresses generic follower fan-out, not an explicit @mention.
    seed_thread(
        &state,
        "t_v7_mention",
        "Muted mention authority",
        ALICE_SUB,
        ALICE_EMAIL,
        220,
    )
    .await;
    state
        .store
        .set_thread_follow_level("t_v7_mention", CAROL_SUB, ThreadFollowLevel::Mute, 221)
        .await
        .unwrap();
    let mentioned = post(
        "p_v7_mention",
        "t_v7_mention",
        "@carol this still addresses you directly",
        BOB_SUB,
        BOB_EMAIL,
        222,
    );
    state
        .store
        .add_reply_with_activity(&mentioned, &["carol".to_string()], &new_id("a"))
        .await
        .unwrap();
    let mention_item = state
        .store
        .activity_page(CAROL_SUB, ActivityFilter::All, false, None, 20)
        .await
        .unwrap()
        .into_iter()
        .find(|item| item.thread_title == "Muted mention authority")
        .unwrap();
    assert_eq!(mention_item.reason, ActivityReason::Mention);

    // Accepting a muted participant's answer is another direct consequence and remains visible.
    let question = Thread {
        id: "t_v7_answer".to_string(),
        category_id: "support".to_string(),
        title: "Muted accepted-answer authority".to_string(),
        author_sub: ALICE_SUB.to_string(),
        author_email: ALICE_EMAIL.to_string(),
        created_at: 230,
        last_at: 230,
        locked: false,
        pinned: false,
        accepted_post_id: String::new(),
    };
    let question_op = post(
        "p_v7_answer_op",
        &question.id,
        "Question",
        ALICE_SUB,
        ALICE_EMAIL,
        230,
    );
    state
        .store
        .create_thread(&question, &question_op)
        .await
        .unwrap();
    state
        .store
        .set_thread_follow_level(&question.id, BOB_SUB, ThreadFollowLevel::Mute, 231)
        .await
        .unwrap();
    let answer = post(
        "p_v7_answer",
        &question.id,
        "Answer",
        BOB_SUB,
        BOB_EMAIL,
        232,
    );
    state
        .store
        .add_reply_with_activity(&answer, &[], &new_id("a"))
        .await
        .unwrap();
    state
        .store
        .mutate_accepted_answer_with_activity(
            &question.id,
            AcceptedAnswerAction::Accept {
                post_id: answer.id.clone(),
            },
            &new_id("a"),
            ALICE_SUB,
            233,
        )
        .await
        .unwrap();
    let answer_item = state
        .store
        .activity_page(BOB_SUB, ActivityFilter::All, false, None, 20)
        .await
        .unwrap()
        .into_iter()
        .find(|item| item.thread_title == "Muted accepted-answer authority")
        .unwrap();
    assert_eq!(answer_item.reason, ActivityReason::Answer);
}

#[tokio::test]
async fn for_you_is_private_bounded_explainable_and_mute_first() {
    let state = build_dev_state().await;
    seed_thread(
        &state,
        "t_fy_watch",
        "Reason Watch",
        ALICE_SUB,
        ALICE_EMAIL,
        100,
    )
    .await;
    seed_thread(
        &state,
        "t_fy_follow",
        "Reason Follow",
        ALICE_SUB,
        ALICE_EMAIL,
        110,
    )
    .await;
    seed_thread(
        &state,
        "t_fy_authored",
        "Reason Authored",
        CAROL_SUB,
        CAROL_EMAIL,
        120,
    )
    .await;
    seed_thread(
        &state,
        "t_fy_bookmark",
        "Reason Bookmark",
        ALICE_SUB,
        ALICE_EMAIL,
        130,
    )
    .await;
    seed_thread(
        &state,
        "t_fy_participated",
        "Reason Participated",
        ALICE_SUB,
        ALICE_EMAIL,
        140,
    )
    .await;
    seed_thread(
        &state,
        "t_fy_reading",
        "Reason Reading",
        ALICE_SUB,
        ALICE_EMAIL,
        150,
    )
    .await;
    seed_thread(
        &state,
        "t_fy_muted",
        "Must Stay Hidden",
        ALICE_SUB,
        ALICE_EMAIL,
        160,
    )
    .await;
    seed_thread(
        &state,
        "t_fy_none",
        "No Local Signal",
        ALICE_SUB,
        ALICE_EMAIL,
        170,
    )
    .await;

    state
        .store
        .set_thread_follow_level("t_fy_watch", CAROL_SUB, ThreadFollowLevel::Watch, 200)
        .await
        .unwrap();
    state
        .store
        .set_thread_follow_level("t_fy_follow", CAROL_SUB, ThreadFollowLevel::Follow, 201)
        .await
        .unwrap();
    state
        .store
        .set_thread_follow_level("t_fy_muted", CAROL_SUB, ThreadFollowLevel::Mute, 202)
        .await
        .unwrap();
    state
        .store
        .ensure_bookmark(CAROL_SUB, "p_t_fy_bookmark_op", 203)
        .await
        .unwrap();
    state
        .store
        .add_reply(&post(
            "p_t_fy_participated_reply",
            "t_fy_participated",
            "Carol joined",
            CAROL_SUB,
            CAROL_EMAIL,
            204,
        ))
        .await
        .unwrap();
    state
        .store
        .mark_thread_posts_read(
            CAROL_SUB,
            "t_fy_reading",
            &["p_t_fy_reading_op".to_string()],
            205,
        )
        .await
        .unwrap();
    state
        .store
        .add_reply(&post(
            "p_t_fy_reading_reply",
            "t_fy_reading",
            "Unread continuation",
            BOB_SUB,
            BOB_EMAIL,
            206,
        ))
        .await
        .unwrap();

    let (status, headers, body) = send(&state, get_as("/for-you", CAROL_SUB, CAROL_EMAIL)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(header::CACHE_CONTROL).unwrap(),
        "private, no-store"
    );
    for (title, reason) in [
        ("Reason Watch", "watch"),
        ("Reason Follow", "follow"),
        ("Reason Authored", "authored"),
        ("Reason Bookmark", "bookmarked"),
        ("Reason Participated", "participated"),
        ("Reason Reading", "reading"),
    ] {
        assert!(body.contains(title), "missing {title}");
        assert!(
            body.contains(&format!(r#"data-for-you-reason="{reason}""#)),
            "missing reason {reason}"
        );
    }
    assert_eq!(body.matches("data-for-you-reason=").count(), 6);
    assert!(!body.contains("Must Stay Hidden"));
    assert!(!body.contains("No Local Signal"));
    let positions = [
        "Reason Watch",
        "Reason Follow",
        "Reason Authored",
        "Reason Bookmark",
        "Reason Participated",
        "Reason Reading",
    ]
    .map(|title| body.find(title).unwrap());
    assert!(positions.windows(2).all(|window| window[0] < window[1]));

    let (status, _, _) = send(&state, get("/for-you")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn preference_form_is_csrf_guarded_no_js_and_json_compatible() {
    let state = build_dev_state().await;
    seed_thread(
        &state,
        "t_v7_form",
        "Preference form",
        ALICE_SUB,
        ALICE_EMAIL,
        100,
    )
    .await;
    let uri = "/t/t_v7_form/subscribe";

    let (status, _, _) = send(
        &state,
        post_as(
            uri,
            CAROL_SUB,
            CAROL_EMAIL,
            form(&[("csrf", TOK), ("level", "follow")]),
            false,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _, json) = send(
        &state,
        post_as_json(
            uri,
            CAROL_SUB,
            CAROL_EMAIL,
            form(&[("csrf", TOK), ("level", "follow")]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json.contains(r#""follow_level":"follow""#));
    assert!(json.contains(r#""subscribed":true"#));

    let (_, _, page) = send(&state, get_as("/t/t_v7_form", CAROL_SUB, CAROL_EMAIL)).await;
    assert!(page.contains(r#"value="follow" selected"#));
    assert!(page.contains("data-wire"));
    assert!(page.contains(r#"data-wire-target=".subscription-form""#));

    let (status, headers, _) = send(
        &state,
        post_as(
            uri,
            CAROL_SUB,
            CAROL_EMAIL,
            form(&[("csrf", TOK), ("level", "mute")]),
            true,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers.get(header::LOCATION).unwrap(), "/t/t_v7_form");
    assert_eq!(
        state
            .store
            .thread_follow_level("t_v7_form", CAROL_SUB)
            .await
            .unwrap(),
        ThreadFollowLevel::Mute
    );

    let (status, _, _) = send(
        &state,
        post_as(
            uri,
            CAROL_SUB,
            CAROL_EMAIL,
            form(&[("csrf", TOK), ("level", "surprise")]),
            true,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

async fn seed_thread(
    state: &AppState,
    id: &str,
    title: &str,
    author_sub: &str,
    author_email: &str,
    created_at: i64,
) {
    let thread = Thread {
        id: id.to_string(),
        category_id: "general".to_string(),
        title: title.to_string(),
        author_sub: author_sub.to_string(),
        author_email: author_email.to_string(),
        created_at,
        last_at: created_at,
        locked: false,
        pinned: false,
        accepted_post_id: String::new(),
    };
    let op = post(
        &format!("p_{id}_op"),
        id,
        "Original post",
        author_sub,
        author_email,
        created_at,
    );
    state.store.create_thread(&thread, &op).await.unwrap();
}

async fn reply(
    state: &AppState,
    thread_id: &str,
    body: &str,
    author_sub: &str,
    author_email: &str,
    created_at: i64,
) {
    state
        .store
        .add_reply_with_activity(
            &post(
                &new_id("p"),
                thread_id,
                body,
                author_sub,
                author_email,
                created_at,
            ),
            &[],
            &new_id("a"),
        )
        .await
        .unwrap();
}

fn post(
    id: &str,
    thread_id: &str,
    body: &str,
    author_sub: &str,
    author_email: &str,
    created_at: i64,
) -> Post {
    Post {
        id: id.to_string(),
        thread_id: thread_id.to_string(),
        body_md: body.to_string(),
        quoted_post_id: String::new(),
        author_sub: author_sub.to_string(),
        author_email: author_email.to_string(),
        created_at,
    }
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

fn post_as(
    uri: &str,
    subject: &str,
    email: &str,
    body: String,
    with_cookie: bool,
) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("x-auth-subject", subject)
        .header("x-auth-email", email);
    if with_cookie {
        request = request.header(header::COOKIE, format!("__Host-csrf={TOK}"));
    }
    request.body(Body::from(body)).unwrap()
}

fn post_as_json(uri: &str, subject: &str, email: &str, body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT, "application/json")
        .header(header::COOKIE, format!("__Host-csrf={TOK}"))
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
