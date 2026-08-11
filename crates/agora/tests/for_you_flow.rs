//! Vertical coverage for result-oriented thread preferences and the explainable personal feed.

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use tower::ServiceExt;

use agora::model::{ActivityReason, Post, Thread, ThreadFollowLevel};
use agora::store::{AcceptedAnswerAction, ActivityFilter, ThreadSort, ThreadStatusFilter};
use agora::{app, build_dev_state, new_id, now_secs, AppState};

const ALICE_SUB: &str = "u_v7_alice";
const ALICE_EMAIL: &str = "alice@steadholme.local";
const BOB_SUB: &str = "u_v7_bob";
const BOB_EMAIL: &str = "bob@steadholme.local";
const CAROL_SUB: &str = "u_v7_carol";
const CAROL_EMAIL: &str = "carol@steadholme.local";
const DAVE_SUB: &str = "u_v8_dave";
const DAVE_EMAIL: &str = "dave@steadholme.local";
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
async fn catch_up_views_are_private_native_complete_and_mute_first() {
    let state = build_dev_state().await;
    let now = now_secs();
    let base = now - 10_000;
    seed_thread(
        &state,
        "t_fy_old_follow",
        "Old explicit relationship",
        ALICE_SUB,
        ALICE_EMAIL,
        base,
    )
    .await;
    state
        .store
        .set_thread_follow_level(
            "t_fy_old_follow",
            CAROL_SUB,
            ThreadFollowLevel::Follow,
            base + 1,
        )
        .await
        .unwrap();
    state
        .store
        .mark_thread_posts_read(
            CAROL_SUB,
            "t_fy_old_follow",
            &["p_t_fy_old_follow_op".to_string()],
            base + 1,
        )
        .await
        .unwrap();
    state
        .store
        .add_reply(&post(
            "p_t_fy_old_follow_unread",
            "t_fy_old_follow",
            "An old relationship still has a current unread reply",
            BOB_SUB,
            BOB_EMAIL,
            base + 2,
        ))
        .await
        .unwrap();

    // More than 200 unrelated, newer public threads must not evict an explicit relationship.
    for index in 0..201 {
        seed_thread(
            &state,
            &format!("t_fy_noise_{index:03}"),
            &format!("Unrelated noise {index:03}"),
            ALICE_SUB,
            ALICE_EMAIL,
            base + 100 + index,
        )
        .await;
    }

    seed_question(
        &state,
        "t_fy_waiting",
        "Question waiting for a solution",
        CAROL_SUB,
        CAROL_EMAIL,
        base + 500,
    )
    .await;
    seed_question(
        &state,
        "t_fy_solved",
        "Question solved for the asker",
        CAROL_SUB,
        CAROL_EMAIL,
        base + 510,
    )
    .await;
    let answer = post(
        "p_t_fy_solved_answer",
        "t_fy_solved",
        "A live accepted reply",
        BOB_SUB,
        BOB_EMAIL,
        base + 511,
    );
    state.store.add_reply(&answer).await.unwrap();
    state
        .store
        .mutate_accepted_answer(
            "t_fy_solved",
            AcceptedAnswerAction::Accept {
                post_id: answer.id.clone(),
            },
        )
        .await
        .unwrap();
    seed_question(
        &state,
        "t_fy_muted_question",
        "Muted question must stay hidden",
        CAROL_SUB,
        CAROL_EMAIL,
        base + 520,
    )
    .await;
    state
        .store
        .set_thread_follow_level(
            "t_fy_muted_question",
            CAROL_SUB,
            ThreadFollowLevel::Mute,
            base + 521,
        )
        .await
        .unwrap();

    let (status, headers, updates) = send(&state, get_as("/for-you", CAROL_SUB, CAROL_EMAIL)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(header::CACHE_CONTROL).unwrap(),
        "private, no-store"
    );
    assert!(updates.contains(r#"<nav class="tabs ag-ledger-tabs" aria-label="Catch-up view">"#));
    assert!(updates.contains(
        r#"<a class="tab is-active" aria-current="page" href="?view=updates">Updates</a>"#
    ));
    assert!(!updates.contains(r#"role="tablist""#));
    assert!(!updates.contains(r#"role="tab""#));
    assert!(!updates.contains(r#"aria-selected="#));
    assert!(updates.contains("Old explicit relationship"));
    assert!(updates.contains("You follow this thread"));
    assert!(updates.contains("Following"));
    assert!(updates.contains("Only you can see this. It explains why each thread appears."));
    assert!(!updates.contains("Unrelated noise"));
    assert!(!updates.contains("Muted question must stay hidden"));
    for href in ["?view=updates", "?view=following", "?view=questions"] {
        assert!(updates.contains(href), "missing native GET tab {href}");
    }

    let (status, _, following) = send(
        &state,
        get_as("/for-you?view=following", CAROL_SUB, CAROL_EMAIL),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(following.contains("Old explicit relationship"));
    assert!(following.contains(
        r#"<a class="tab is-active" aria-current="page" href="?view=following">Following</a>"#
    ));
    assert!(!following.contains("Unrelated noise"));
    assert!(!following.contains("Muted question must stay hidden"));

    let (status, _, questions) = send(
        &state,
        get_as("/for-you?view=questions", CAROL_SUB, CAROL_EMAIL),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(questions.contains("Question waiting for a solution"));
    assert!(questions.contains("Question solved for the asker"));
    assert!(questions.contains("Waiting for an answer"));
    assert!(questions.contains("Accepted answer recorded"));
    assert!(questions.contains(
        r#"<a class="tab is-active" aria-current="page" href="?view=questions">Questions</a>"#
    ));
    assert!(!questions.contains("Old explicit relationship"));
    assert!(!questions.contains("Muted question must stay hidden"));

    for uri in [
        "/for-you?view=updates",
        "/for-you?view=following",
        "/for-you?view=questions",
    ] {
        let (_, _, body) = send(&state, get_as(uri, DAVE_SUB, DAVE_EMAIL)).await;
        assert!(!body.contains("Question waiting for a solution"));
        assert!(!body.contains("Question solved for the asker"));
    }
    let (status, _, _) = send(
        &state,
        get_as("/for-you?view=unknown", CAROL_SUB, CAROL_EMAIL),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, _) = send(&state, get("/for-you")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn catch_up_updates_keep_unread_holes_private_and_read_only_get() {
    let state = build_dev_state().await;
    let now = now_secs();
    seed_thread(
        &state,
        "t_fy_holes",
        "Exact unread holes",
        ALICE_SUB,
        ALICE_EMAIL,
        now - 100,
    )
    .await;
    for (id, body, created_at) in [
        ("p_fy_hole_one", "First unread old copy", now - 90),
        ("p_fy_hole_two", "Already read middle reply", now - 80),
        ("p_fy_hole_three", "Second unread reply", now - 70),
    ] {
        state
            .store
            .add_reply(&post(
                id,
                "t_fy_holes",
                body,
                BOB_SUB,
                BOB_EMAIL,
                created_at,
            ))
            .await
            .unwrap();
    }
    state
        .store
        .set_thread_follow_level("t_fy_holes", CAROL_SUB, ThreadFollowLevel::Watch, now - 60)
        .await
        .unwrap();
    state
        .store
        .mark_thread_posts_read(
            CAROL_SUB,
            "t_fy_holes",
            &["p_t_fy_holes_op".to_string(), "p_fy_hole_two".to_string()],
            now - 50,
        )
        .await
        .unwrap();
    state
        .store
        .update_post(
            "p_fy_hole_one",
            "Current live first unread <script>must stay text</script>",
        )
        .await
        .unwrap();

    let before = state
        .store
        .thread_reading_state(CAROL_SUB, "t_fy_holes")
        .await
        .unwrap();
    assert_eq!(before.unread_count, 2);
    assert_eq!(before.first_unread.as_ref().unwrap().id, "p_fy_hole_one");
    let uri = format!("/for-you?view=updates&as_of={now}");
    let (status, _, body) = send(&state, get_as(&uri, CAROL_SUB, CAROL_EMAIL)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Exact unread holes"));
    assert!(body.contains("2 unread"));
    assert!(body.contains("You are watching this thread"));
    assert!(body.contains("Watching"));
    assert!(body
        .contains(r#"href="/t/t_fy_holes?resume=1#post-p_fy_hole_one">Jump to first unread</a>"#));
    assert!(!body.contains("First unread old copy"));
    assert!(!body.contains("Current live first unread"));
    assert!(!body.contains("<script>must stay text</script>"));
    assert_eq!(body.matches("You are watching this thread").count(), 1);

    let after = state
        .store
        .thread_reading_state(CAROL_SUB, "t_fy_holes")
        .await
        .unwrap();
    assert_eq!(
        after.unread_count, before.unread_count,
        "GET must not write"
    );
    assert_eq!(
        after.first_unread.unwrap().id,
        before.first_unread.unwrap().id,
        "GET must preserve the exact first-unread hole"
    );
}

#[tokio::test]
async fn catch_up_cursor_is_view_snapshot_and_tie_bound() {
    let state = build_dev_state().await;
    let now = now_secs();
    let tied_at = now - 100;
    for index in 0..32 {
        let id = format!("t_fy_tie_{index:02}");
        seed_thread(
            &state,
            &id,
            &format!("Tie relationship {index:02}"),
            ALICE_SUB,
            ALICE_EMAIL,
            tied_at,
        )
        .await;
        state
            .store
            .set_thread_follow_level(&id, CAROL_SUB, ThreadFollowLevel::Follow, tied_at + 1)
            .await
            .unwrap();
    }
    state
        .store
        .add_reply(&post(
            "p_fy_tie_deleted_latest",
            "t_fy_tie_00",
            "Deleted after page one",
            BOB_SUB,
            BOB_EMAIL,
            tied_at + 10,
        ))
        .await
        .unwrap();
    let first_uri = format!("/for-you?view=following&as_of={now}");
    let (status, _, first) = send(&state, get_as(&first_uri, CAROL_SUB, CAROL_EMAIL)).await;
    assert_eq!(status, StatusCode::OK);
    let first_ids = thread_ids(&first);
    assert_eq!(first_ids.len(), 30);
    assert_eq!(first_ids[0], "t_fy_tie_00");
    assert_eq!(first_ids[29], "t_fy_tie_03");
    let next = pagination_href(&first);

    // Both mutations share the original wall-clock second. Their higher generation must keep the
    // old cursor's post/read authority frozen, while deleting the former latest reply must retain
    // its non-content sorting point so t00 cannot reappear below the cursor.
    state
        .store
        .delete_post("p_fy_tie_deleted_latest")
        .await
        .unwrap();
    state
        .store
        .mark_thread_posts_read(
            CAROL_SUB,
            "t_fy_tie_02",
            &["p_t_fy_tie_02_op".to_string()],
            tied_at,
        )
        .await
        .unwrap();
    state
        .store
        .add_reply(&post(
            "p_fy_tie_same_second_late",
            "t_fy_tie_02",
            "Same-second reply after page one",
            BOB_SUB,
            BOB_EMAIL,
            tied_at,
        ))
        .await
        .unwrap();
    let (status, _, second) = send(&state, get_as(&next, CAROL_SUB, CAROL_EMAIL)).await;
    assert_eq!(status, StatusCode::OK);
    let second_ids = thread_ids(&second);
    assert_eq!(second_ids, vec!["t_fy_tie_02", "t_fy_tie_01"]);
    let frozen_t02 = second
        .split_once(r#"<a class="ag-row__title" href="/t/t_fy_tie_02">Tie relationship 02</a>"#)
        .unwrap()
        .1
        .split_once("</li>")
        .unwrap()
        .0;
    assert!(frozen_t02.contains("1 unread"));
    assert!(frozen_t02.contains(
        r#"href="/t/t_fy_tie_02?resume=1#post-p_t_fy_tie_02_op">Jump to first unread</a>"#
    ));
    let mut all = first_ids;
    all.extend(second_ids);
    all.sort();
    all.dedup();
    assert_eq!(all.len(), 32, "same-second keyset must have no holes");

    let wrong_view = next.replacen("view=following", "view=updates", 1);
    let (status, _, _) = send(&state, get_as(&wrong_view, CAROL_SUB, CAROL_EMAIL)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let wrong_snapshot = next.replacen(&format!("as_of={now}"), &format!("as_of={}", now - 1), 1);
    let (status, _, _) = send(&state, get_as(&wrong_snapshot, CAROL_SUB, CAROL_EMAIL)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let without_snapshot = next.replacen(&format!("&as_of={now}"), "", 1);
    let (status, _, _) = send(&state, get_as(&without_snapshot, CAROL_SUB, CAROL_EMAIL)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let legacy_v8_cursor = next.replacen("before=v8g-", "before=v8-", 1);
    let (status, _, _) = send(&state, get_as(&legacy_v8_cursor, CAROL_SUB, CAROL_EMAIL)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, _) = send(
        &state,
        get_as(
            "/for-you?view=following&as_of=1&before=not-a-cursor",
            CAROL_SUB,
            CAROL_EMAIL,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
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

    let (_, _, page) = send(
        &state,
        get_as_with_csrf("/t/t_v7_form", CAROL_SUB, CAROL_EMAIL),
    )
    .await;
    assert!(page.contains(r#"method="post" action="/t/t_v7_form/subscribe""#));
    assert_eq!(
        page.matches(r#"action="/t/t_v7_form/subscribe""#).count(),
        1
    );
    assert!(page.contains(&format!(r#"name="csrf" value="{TOK}""#)));
    assert!(page.contains(r#"name="level""#));
    assert!(page.contains(r#"value="follow" selected"#));
    assert!(page.contains("Private: this shapes your catch-up, not notification delivery."));
    assert!(!page.contains(r#"data-wire-target=".subscription-form""#));

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
    seed_thread_in_category(
        state,
        id,
        "general",
        title,
        author_sub,
        author_email,
        created_at,
    )
    .await;
}

async fn seed_question(
    state: &AppState,
    id: &str,
    title: &str,
    author_sub: &str,
    author_email: &str,
    created_at: i64,
) {
    seed_thread_in_category(
        state,
        id,
        "support",
        title,
        author_sub,
        author_email,
        created_at,
    )
    .await;
}

async fn seed_thread_in_category(
    state: &AppState,
    id: &str,
    category_id: &str,
    title: &str,
    author_sub: &str,
    author_email: &str,
    created_at: i64,
) {
    let thread = Thread {
        id: id.to_string(),
        category_id: category_id.to_string(),
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

fn get_as_with_csrf(uri: &str, subject: &str, email: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header(header::COOKIE, format!("__Host-csrf={TOK}"))
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

fn thread_ids(body: &str) -> Vec<&str> {
    let marker = r#"<a class="ag-row__title" href="/t/"#;
    let mut values = Vec::new();
    let mut rest = body;
    while let Some(index) = rest.find(marker) {
        rest = &rest[index + marker.len()..];
        let Some(end) = rest.find('"') else {
            break;
        };
        values.push(&rest[..end]);
        rest = &rest[end + 1..];
    }
    values
}

fn pagination_href(body: &str) -> String {
    let marker = r#"<a class="btn btn-secondary btn-sm ag-page__link" rel="next" href=""#;
    let rest = body
        .split_once(marker)
        .expect("catch-up page has a pagination link")
        .1;
    rest.split_once('"')
        .expect("pagination href closes")
        .0
        .replace("&amp;", "&")
}
