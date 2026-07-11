//! End-to-end coverage for Forum discovery search and the same-origin suggestion endpoint.

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

use agora::model::{Post, Thread};
use agora::store::AcceptedAnswerAction;
use agora::{app, build_dev_state, AppState};

#[tokio::test]
async fn search_page_matches_title_and_original_body_with_result_context() {
    let state = build_dev_state().await;
    seed_thread(
        &state,
        "t_rust",
        "general",
        "Rust ownership patterns",
        "Lifetimes make borrowed data explicit.",
        100,
    )
    .await;
    seed_reply(&state, "t_rust", "p_rust_reply_1", 110).await;
    seed_reply(&state, "t_rust", "p_rust_reply_2", 120).await;
    seed_thread(
        &state,
        "t_support",
        "support",
        "Borrow checker help",
        "This support answer also discusses lifetimes.",
        200,
    )
    .await;

    let (status, _, title_html) = send(&state, get("/search?q=ownership")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(title_html.contains("Rust ownership patterns"));
    assert!(title_html.contains("General Discussion"));
    assert!(title_html.contains("2 replies"));
    assert!(title_html.contains("Active"));

    let (status, _, body_html) = send(&state, get("/search?q=lifetimes&category=general")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body_html.contains("Rust ownership patterns"),
        "OP body is searched"
    );
    assert!(body_html.contains("Lifetimes make borrowed data explicit."));
    assert!(
        !body_html.contains("Borrow checker help"),
        "category filter excludes another matching thread"
    );
    assert!(
        body_html.contains(r#"name="category""#),
        "shareable GET form remains present"
    );
    assert!(body_html.contains(r#"value="general" selected"#));
}

#[tokio::test]
async fn empty_query_is_a_prompt_and_category_filter_is_real() {
    let state = build_dev_state().await;
    seed_thread(
        &state,
        "t_general",
        "general",
        "Shared needle general",
        "Body",
        100,
    )
    .await;
    seed_thread(
        &state,
        "t_support",
        "support",
        "Shared needle support",
        "Body",
        200,
    )
    .await;

    let (status, _, empty) = send(&state, get("/search")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(empty.contains("Find a discussion"));
    assert!(!empty.contains("Shared needle general"));

    let (_, _, support) = send(&state, get("/search?q=needle&category=support")).await;
    assert!(support.contains("Shared needle support"));
    assert!(!support.contains("Shared needle general"));

    let (_, _, missing) = send(&state, get("/search?q=does-not-exist")).await;
    assert!(missing.contains("No discussions found"));
}

#[tokio::test]
async fn search_escapes_html_and_suggest_serializes_untrusted_text_as_json() {
    let state = build_dev_state().await;
    seed_thread(
        &state,
        "t_xss",
        "general",
        "Needle <img src=x onerror=alert(1)>",
        "Needle body <script>alert(2)</script>.",
        100,
    )
    .await;

    let (_, _, html) = send(&state, get("/search?q=needle")).await;
    assert!(!html.contains("<img src=x onerror=alert(1)>"));
    assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
    assert!(html.contains("&lt;script&gt;alert(2)&lt;/script&gt;"));

    let (status, headers, json) = send(&state, get("/api/search/suggest?q=needle&limit=6")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("private, no-store")
    );
    assert_eq!(
        headers
            .get("x-content-type-options")
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
    let payload: Value = serde_json::from_str(&json).expect("valid JSON despite untrusted text");
    assert_eq!(
        payload["results"][0]["title"],
        "Needle <img src=x onerror=alert(1)>"
    );
    assert!(payload["results"][0]["excerpt"]
        .as_str()
        .unwrap()
        .contains("<script>alert(2)</script>"));
}

#[tokio::test]
async fn suggest_clamps_query_and_limit_and_filters_category() {
    let state = build_dev_state().await;
    for index in 0..12 {
        seed_thread(
            &state,
            &format!("t_match_{index}"),
            if index == 0 { "support" } else { "general" },
            &format!("Clamp needle {index}"),
            "Original body",
            100 + index,
        )
        .await;
    }

    let (_, _, many) = send(&state, get("/api/search/suggest?q=needle&limit=999")).await;
    let many: Value = serde_json::from_str(&many).unwrap();
    assert_eq!(many["results"].as_array().unwrap().len(), 10);

    let (_, _, one) = send(&state, get("/api/search/suggest?q=needle&limit=0")).await;
    let one: Value = serde_json::from_str(&one).unwrap();
    assert_eq!(one["results"].as_array().unwrap().len(), 1);

    let (_, _, too_short) = send(&state, get("/api/search/suggest?q=ne&limit=10")).await;
    let too_short: Value = serde_json::from_str(&too_short).unwrap();
    assert_eq!(too_short["query"], "ne");
    assert!(
        too_short["results"].as_array().unwrap().is_empty(),
        "suggestions require at least three characters"
    );

    let (_, _, short_page) = send(&state, get("/search?q=n")).await;
    assert!(short_page.contains("Use at least two characters"));
    assert!(!short_page.contains("Clamp needle"));

    let (_, _, support) = send(
        &state,
        get("/api/search/suggest?q=needle&category=support&limit=10"),
    )
    .await;
    let support: Value = serde_json::from_str(&support).unwrap();
    assert_eq!(support["results"].as_array().unwrap().len(), 1);
    assert_eq!(support["results"][0]["categoryId"], "support");

    let long_query = "x".repeat(220);
    let (_, _, bounded) = send(
        &state,
        get(&format!("/api/search/suggest?q={long_query}&limit=3")),
    )
    .await;
    let bounded: Value = serde_json::from_str(&bounded).unwrap();
    assert_eq!(bounded["query"].as_str().unwrap().chars().count(), 160);
}

#[tokio::test]
async fn search_filters_question_status_and_surfaces_accepted_solution_matches() {
    let state = build_dev_state().await;
    seed_thread(
        &state,
        "t_answered_search",
        "support",
        "Status matrix answered",
        "Original question without the solution phrase.",
        100,
    )
    .await;
    let solution = Post {
        id: "p_answered_solution_search".to_string(),
        thread_id: "t_answered_search".to_string(),
        body_md: "The durable fix uses a cobalt rendezvous token.".to_string(),
        quoted_post_id: String::new(),
        author_sub: "u_expert".to_string(),
        author_email: "expert@holdfast.local".to_string(),
        created_at: 110,
    };
    state.store.add_reply(&solution).await.unwrap();
    state
        .store
        .mutate_accepted_answer(
            "t_answered_search",
            AcceptedAnswerAction::Accept {
                post_id: solution.id.clone(),
            },
        )
        .await
        .unwrap();
    seed_thread(
        &state,
        "t_unanswered_search",
        "support",
        "Status matrix unanswered",
        "A cobalt question still waiting for help.",
        200,
    )
    .await;
    seed_thread(
        &state,
        "t_discussion_search",
        "general",
        "Status matrix discussion",
        "A cobalt open conversation, not a question.",
        300,
    )
    .await;

    let (status, _, solution_html) = send(
        &state,
        get("/search?q=rendezvous&status=answered"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(solution_html.contains("Status matrix answered"));
    assert!(solution_html.contains("Matched in accepted answer"));
    assert!(solution_html.contains("cobalt rendezvous token"));
    assert!(solution_html.contains(r#"value="answered" selected"#));

    let (_, _, suggestions) = send(
        &state,
        get("/api/search/suggest?q=rendezvous&status=answered"),
    )
    .await;
    let suggestions: Value = serde_json::from_str(&suggestions).unwrap();
    assert_eq!(suggestions["status"], "answered");
    assert_eq!(suggestions["results"][0]["matchSource"], "solution");
    assert!(suggestions["results"][0]["excerpt"]
        .as_str()
        .unwrap()
        .contains("rendezvous token"));

    let (_, _, unanswered) = send(&state, get("/search?q=cobalt&status=unanswered")).await;
    assert!(unanswered.contains("Status matrix unanswered"));
    assert!(!unanswered.contains("Status matrix answered"));
    assert!(!unanswered.contains("Status matrix discussion"));

    let (_, _, answered) = send(&state, get("/search?q=cobalt&status=answered")).await;
    assert!(answered.contains("Status matrix answered"));
    assert!(!answered.contains("Status matrix unanswered"));
    assert!(!answered.contains("Status matrix discussion"));
}

#[tokio::test]
async fn shell_exposes_product_owned_quick_search_with_no_js_fallback() {
    let state = build_dev_state().await;
    let (_, _, html) = send(&state, get("/")).await;
    assert!(html.contains(r#"data-ag-quick-search"#));
    assert!(html.contains(r#"method="get" action="/search""#));
    assert!(html.contains("/api/search/suggest?q="));
    assert!(html.contains("event.key.toLowerCase() === 'k'"));
    assert!(html.contains("title.textContent = result.title"));
    assert!(html.contains(r#"role="combobox""#));
    assert!(html.contains("new AbortController()"));
    assert!(html.contains("requestController.abort()"));
    assert!(html.contains("(!typing || target === input)"));
    assert!(html.contains("form.addEventListener('focusout'"));
    assert!(html.contains("setTimeout(load, 300)"));
    assert!(html.contains("length < 3"));
    assert!(html.contains("active < 0 ? items.length - 1 : active - 1"));
    assert!(html.contains("link.tabIndex = -1"));
    assert!(html.contains(r#"aria-label="Quick search""#));
    assert!(html.contains(r#"aria-label="Search suggestions""#));
    assert!(html.contains("without Odyssey Wire/Spark"));
}

async fn seed_thread(
    state: &AppState,
    id: &str,
    category_id: &str,
    title: &str,
    first_body_md: &str,
    created_at: i64,
) {
    let thread = Thread {
        id: id.to_string(),
        category_id: category_id.to_string(),
        title: title.to_string(),
        author_sub: "u_alice".to_string(),
        author_email: "alice@holdfast.local".to_string(),
        created_at,
        last_at: created_at,
        locked: false,
        pinned: false,
        accepted_post_id: String::new(),
    };
    let post = Post {
        id: format!("p_{id}_op"),
        thread_id: id.to_string(),
        body_md: first_body_md.to_string(),
        quoted_post_id: String::new(),
        author_sub: "u_alice".to_string(),
        author_email: "alice@holdfast.local".to_string(),
        created_at,
    };
    state.store.create_thread(&thread, &post).await.unwrap();
}

async fn seed_reply(state: &AppState, thread_id: &str, id: &str, created_at: i64) {
    let post = Post {
        id: id.to_string(),
        thread_id: thread_id.to_string(),
        body_md: format!("Reply {id}"),
        quoted_post_id: String::new(),
        author_sub: "u_bob".to_string(),
        author_email: "bob@holdfast.local".to_string(),
        created_at,
    };
    state.store.add_reply(&post).await.unwrap();
}

async fn send(state: &AppState, req: Request<Body>) -> (StatusCode, HeaderMap, String) {
    let response = app(state.clone()).oneshot(req).await.unwrap();
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
