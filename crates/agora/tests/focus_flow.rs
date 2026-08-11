//! Category Focus authority and SSR/no-JS flow coverage.

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use tower::ServiceExt;

use agora::model::{Category, CategoryFocusLevel, CategoryFormat, Post, Thread, ThreadFollowLevel};
use agora::store::{
    ActivityFilter, CategoryFocusReason, MAX_CATEGORY_FOCUS_PAGE, MAX_CATEGORY_FOCUS_RULES,
};
use agora::{app, build_dev_state, AppState};

const ALICE_SUB: &str = "u_v9_focus_alice";
const ALICE_EMAIL: &str = "alice@steadholme.local";
const BOB_SUB: &str = "u_v9_focus_bob";
const BOB_EMAIL: &str = "bob@steadholme.local";
const TOK: &str = "v9categoryfocuscsrftoken";

#[tokio::test]
async fn memory_focus_is_private_bounded_and_resolves_narrow_thread_intent() {
    let state = build_dev_state().await;
    for (id, name) in [
        ("focus-priority", "Priority room"),
        ("focus-follow", "Follow room"),
        ("focus-muted", "Muted room"),
    ] {
        create_category(&state, id, name).await;
    }
    seed_thread(
        &state,
        "t_focus_priority",
        "Priority first",
        "focus-priority",
        10,
        false,
    )
    .await;
    seed_thread(
        &state,
        "t_focus_priority_muted",
        "Thread mute wins",
        "focus-priority",
        500,
        true,
    )
    .await;
    seed_thread(
        &state,
        "t_focus_follow",
        "Follow second",
        "focus-follow",
        400,
        false,
    )
    .await;
    seed_thread(
        &state,
        "t_focus_watch_override",
        "Watch overrides category mute",
        "focus-muted",
        300,
        false,
    )
    .await;
    seed_thread(
        &state,
        "t_focus_follow_override",
        "Follow overrides category mute",
        "focus-muted",
        200,
        false,
    )
    .await;
    seed_thread(
        &state,
        "t_focus_muted_plain",
        "Broad mute excludes",
        "focus-muted",
        600,
        false,
    )
    .await;

    state
        .store
        .set_category_focus_level(
            ALICE_SUB,
            "focus-priority",
            CategoryFocusLevel::Priority,
            700,
        )
        .await
        .unwrap();
    state
        .store
        .set_category_focus_level(ALICE_SUB, "focus-follow", CategoryFocusLevel::Follow, 701)
        .await
        .unwrap();
    state
        .store
        .set_category_focus_level(ALICE_SUB, "focus-muted", CategoryFocusLevel::Mute, 702)
        .await
        .unwrap();
    state
        .store
        .set_thread_follow_level(
            "t_focus_priority_muted",
            ALICE_SUB,
            ThreadFollowLevel::Mute,
            703,
        )
        .await
        .unwrap();
    state
        .store
        .set_thread_follow_level(
            "t_focus_watch_override",
            ALICE_SUB,
            ThreadFollowLevel::Watch,
            704,
        )
        .await
        .unwrap();
    state
        .store
        .set_thread_follow_level(
            "t_focus_follow_override",
            ALICE_SUB,
            ThreadFollowLevel::Follow,
            705,
        )
        .await
        .unwrap();

    let page = state
        .store
        .category_focus_page(ALICE_SUB, MAX_CATEGORY_FOCUS_PAGE, 1_000)
        .await
        .unwrap();
    assert_eq!(
        page.iter()
            .map(|item| item.thread.id.as_str())
            .collect::<Vec<_>>(),
        vec![
            "t_focus_priority",
            "t_focus_follow",
            "t_focus_watch_override",
            "t_focus_follow_override",
        ],
        "Priority precedes Follow; only explicit thread intent pierces category Mute"
    );
    assert_eq!(page[0].reason, CategoryFocusReason::CategoryPriority);
    assert_eq!(page[1].reason, CategoryFocusReason::CategoryFollow);
    assert_eq!(page[2].reason, CategoryFocusReason::ThreadWatchOverride);
    assert_eq!(page[3].reason, CategoryFocusReason::ThreadFollowOverride);
    let rules = state.store.category_focus_rules(ALICE_SUB).await.unwrap();
    assert_eq!(rules.len(), 3);
    assert!(rules.iter().any(|rule| {
        rule.category.id == "focus-muted" && rule.level == CategoryFocusLevel::Mute
    }));
    assert!(state
        .store
        .category_focus_page(BOB_SUB, MAX_CATEGORY_FOCUS_PAGE, 1_000)
        .await
        .unwrap()
        .is_empty());
    assert!(
        state
            .store
            .activity_page(ALICE_SUB, ActivityFilter::All, false, None, 20)
            .await
            .unwrap()
            .is_empty(),
        "category rules do not create Activity"
    );
    assert!(state
        .store
        .category_focus_page(ALICE_SUB, MAX_CATEGORY_FOCUS_PAGE + 1, 1_000)
        .await
        .is_err());
}

#[tokio::test]
async fn memory_focus_cap_is_exact_idempotent_and_removal_frees_capacity() {
    let state = build_dev_state().await;
    for index in 0..=MAX_CATEGORY_FOCUS_RULES {
        let id = format!("focus-cap-{index:02}");
        create_category(&state, &id, &format!("Focus cap {index:02}")).await;
    }
    for index in 0..MAX_CATEGORY_FOCUS_RULES {
        let id = format!("focus-cap-{index:02}");
        state
            .store
            .set_category_focus_level(ALICE_SUB, &id, CategoryFocusLevel::Follow, index as i64)
            .await
            .unwrap();
    }
    state
        .store
        .set_category_focus_level(ALICE_SUB, "focus-cap-00", CategoryFocusLevel::Follow, 100)
        .await
        .expect("same desired state is idempotent at the cap");
    let error = state
        .store
        .set_category_focus_level(
            ALICE_SUB,
            &format!("focus-cap-{MAX_CATEGORY_FOCUS_RULES:02}"),
            CategoryFocusLevel::Priority,
            101,
        )
        .await
        .expect_err("the 65th category rule must be rejected");
    assert!(error.to_string().contains("at most 64"));
    state
        .store
        .set_category_focus_level(ALICE_SUB, "focus-cap-00", CategoryFocusLevel::None, 102)
        .await
        .unwrap();
    state
        .store
        .set_category_focus_level(
            ALICE_SUB,
            &format!("focus-cap-{MAX_CATEGORY_FOCUS_RULES:02}"),
            CategoryFocusLevel::Priority,
            103,
        )
        .await
        .expect("removing a rule frees one slot");
}

#[tokio::test]
async fn focus_handlers_use_native_csrf_form_and_explain_each_row() {
    let state = build_dev_state().await;
    seed_thread(
        &state,
        "t_focus_http",
        "Native Focus row",
        "general",
        100,
        false,
    )
    .await;
    state
        .store
        .mark_thread_posts_read(
            ALICE_SUB,
            "t_focus_http",
            &["p_t_focus_http_op".to_string()],
            101,
        )
        .await
        .unwrap();
    state
        .store
        .add_reply(&Post {
            id: "p_t_focus_http_new".to_string(),
            thread_id: "t_focus_http".to_string(),
            body_md: "Unread focused reply".to_string(),
            quoted_post_id: String::new(),
            author_sub: BOB_SUB.to_string(),
            author_email: BOB_EMAIL.to_string(),
            created_at: 102,
        })
        .await
        .unwrap();

    let (status, _, _) = send(&state, get("/focus")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, headers, category_page) =
        send(&state, get_as("/c/general", ALICE_SUB, ALICE_EMAIL)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers.contains_key(header::SET_COOKIE));
    assert!(category_page.contains(r#"method="post" action="/c/general/focus""#));
    let csrf = headers
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split_once("__Host-csrf=")
        .unwrap()
        .1
        .split(';')
        .next()
        .unwrap();
    assert!(category_page.contains(&format!(r#"name="csrf" value="{csrf}""#)));
    assert!(category_page.contains(r#"name="level""#));
    assert!(category_page
        .contains("Focus is private. It changes only what you see — never the shared category."));
    assert!(!category_page.contains(r#"action="/focus""#));

    let (status, _, _) = send(
        &state,
        post_as(
            "/c/general/focus",
            ALICE_SUB,
            ALICE_EMAIL,
            form(&[("csrf", "wrong"), ("level", "priority")]),
            true,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, headers, _) = send(
        &state,
        post_as(
            "/c/general/focus",
            ALICE_SUB,
            ALICE_EMAIL,
            form(&[
                ("csrf", TOK),
                ("level", "priority"),
                ("sort", "hot"),
                ("filter", "subscribed"),
                ("status", "unanswered"),
            ]),
            true,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        headers.get(header::LOCATION).unwrap(),
        "/c/general?focus_saved=priority&sort=hot&filter=subscribed&status=unanswered#category-focus-heading"
    );

    let (status, _, saved_page) = send(
        &state,
        get_as(
            "/c/general?focus_saved=priority&sort=hot&filter=subscribed&status=unanswered",
            ALICE_SUB,
            ALICE_EMAIL,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(saved_page.contains(r#"value="priority" selected"#));
    assert!(saved_page.contains(r#"method="post" action="/c/general/focus""#));
    assert!(saved_page
        .contains("Focus is private. It changes only what you see — never the shared category."));

    let (status, _, focus_page) = send(&state, get_as("/focus", ALICE_SUB, ALICE_EMAIL)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(focus_page.contains("Native Focus row"));
    assert!(focus_page.contains("Shown by category priority"));
    assert!(focus_page.contains("Priority"));
    assert!(focus_page.contains("Your rules"));
    assert!(focus_page.contains("What your focus surfaces"));
    assert!(focus_page.contains("Up to 64 rules · up to 30 threads shown · private to you"));
    assert!(focus_page.contains(r#"method="post" action="/c/general/focus""#));
    assert!(focus_page.contains(r#"href="/t/t_focus_http?resume=1#thread-resume""#));
    assert!(focus_page.contains("Continue · 1 new"));
    assert!(!focus_page.contains(r#"action="/focus""#));
    assert!(!focus_page.contains("no notifications"));
    assert!(!focus_page.contains("notification was sent"));

    let (_, _, bob_page) = send(&state, get_as("/focus", BOB_SUB, BOB_EMAIL)).await;
    assert!(
        !bob_page.contains("Native Focus row"),
        "Focus is owner-scoped"
    );

    let (status, _, _) = send(
        &state,
        post_as(
            "/c/general/focus",
            ALICE_SUB,
            ALICE_EMAIL,
            form(&[("csrf", TOK), ("level", "mute")]),
            true,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, _, muted_page) = send(&state, get_as("/focus", ALICE_SUB, ALICE_EMAIL)).await;
    assert!(muted_page.contains("Your rules"));
    assert!(muted_page.contains("Mute"));
    assert!(muted_page.contains(r#"method="post" action="/c/general/focus""#));
    assert!(!muted_page.contains("Native Focus row"));
}

async fn create_category(state: &AppState, id: &str, name: &str) {
    state
        .store
        .create_category(&Category {
            id: id.to_string(),
            name: name.to_string(),
            sort_order: 100,
            format: CategoryFormat::Discussion,
        })
        .await
        .unwrap();
}

async fn seed_thread(
    state: &AppState,
    id: &str,
    title: &str,
    category_id: &str,
    created_at: i64,
    pinned: bool,
) {
    let thread = Thread {
        id: id.to_string(),
        category_id: category_id.to_string(),
        title: title.to_string(),
        author_sub: BOB_SUB.to_string(),
        author_email: BOB_EMAIL.to_string(),
        created_at,
        last_at: created_at,
        locked: false,
        pinned,
        accepted_post_id: String::new(),
    };
    let post = Post {
        id: format!("p_{id}_op"),
        thread_id: id.to_string(),
        body_md: "Original post".to_string(),
        quoted_post_id: String::new(),
        author_sub: BOB_SUB.to_string(),
        author_email: BOB_EMAIL.to_string(),
        created_at,
    };
    state.store.create_thread(&thread, &post).await.unwrap();
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
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}
