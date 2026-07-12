//! End-to-end tests for quote replies, mentions, thread subscriptions, and thread list sorting.
//!
//! Drives the real Router over the in-memory store, matching the existing forum flow harness.

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use tower::ServiceExt;

use agora::model::{Post, Thread};
use agora::{app, build_dev_state, now_secs, AppState};

const ALICE_SUB: &str = "u_sub_1";
const ALICE_EMAIL: &str = "alice@holdfast.local";
const BOB_SUB: &str = "u_sub_bob";
const BOB_EMAIL: &str = "bob@holdfast.local";
const TOK: &str = "csrftoken123";

#[tokio::test]
async fn quote_reply_renders_escaped_blockquote_and_deduplicated_activity() {
    let state = build_dev_state().await;
    let loc = create_thread(&state, "Quote and mention", "Original <unsafe> body.").await;
    let tid = loc.strip_prefix("/t/").unwrap().to_string();
    let op_id = state.store.posts_in_thread(&tid).await.unwrap()[0]
        .id
        .clone();

    let reply = form(&[
        ("csrf", TOK),
        ("quote_post_id", &op_id),
        ("body", "Thanks @alice for this."),
    ]);
    let (status, _h, _b) = send(
        &state,
        post_as(&format!("{loc}/reply"), TOK, BOB_SUB, BOB_EMAIL, reply),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (_s, _h, page) = send(&state, get_as(&loc, ALICE_SUB, ALICE_EMAIL)).await;
    assert!(
        page.contains(r#"<blockquote class="post-quote">"#),
        "quote block rendered"
    );
    assert!(
        page.contains("alice@holdfast.local wrote:"),
        "quoted author attributed"
    );
    assert!(
        page.contains("Original &lt;unsafe&gt; body."),
        "quoted body is escaped"
    );
    let quote_pos = page.find(r#"<blockquote class="post-quote">"#).unwrap();
    let reply_pos = page.find("Thanks @alice").unwrap();
    assert!(quote_pos < reply_pos, "quote renders above reply body");

    let (_s, _h, home) = send(&state, get_as("/", ALICE_SUB, ALICE_EMAIL)).await;
    assert!(home.contains("Activity, 1 unread"));
    assert!(home.contains(r#"aria-label="For you""#));
    assert!(home.contains(r#"href="/bookmarks""#));
    assert!(home.contains(">Saved</span>"));
    assert!(home.contains(r#"href="/?filter=subscribed""#));
    assert!(home.contains(r#"<a class="ag-cat is-active" href="/" aria-current="page">"#));
    assert!(
        home.contains(r#"class="ag-cat__count ag-personal-count">1 unread</span>"#),
        "the home rail reuses the private request-derived Activity count"
    );
    let (_s, _h, activity) = send(&state, get_as("/activity", ALICE_SUB, ALICE_EMAIL)).await;
    assert!(activity.contains("Quote and mention"));
    assert!(activity.contains("Mention"));
    assert_eq!(
        activity.matches("ag-activity-row is-unread").count(),
        1,
        "OP + quote + @mention delivery paths collapse to one event"
    );

    let (_s, _h, bob_activity) = send(&state, get_as("/activity", BOB_SUB, BOB_EMAIL)).await;
    assert!(bob_activity.contains("0 unread"), "the actor is never self-notified");
}

#[tokio::test]
async fn thread_subscription_toggle_and_filter() {
    let state = build_dev_state().await;
    let subscribed_loc = create_thread(&state, "Subscribed target", "First body.").await;
    let other_loc = create_thread(&state, "Unsubscribed target", "Second body.").await;
    let subscribe_uri = format!("{subscribed_loc}/subscribe");

    let (status, _h, _b) = send(
        &state,
        post_as(
            &subscribe_uri,
            TOK,
            ALICE_SUB,
            ALICE_EMAIL,
            form(&[("csrf", TOK), ("action", "follow")]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (_s, _h, thread_page) = send(&state, get_as(&subscribed_loc, ALICE_SUB, ALICE_EMAIL)).await;
    assert!(
        thread_page.contains("Unfollow"),
        "subscribed thread shows the reverse action"
    );
    assert!(thread_page.contains(r#"data-wire-target=".subscription-form""#));
    assert!(thread_page.contains(r#"class="ag-thread-toolbar""#));
    assert!(thread_page.contains(r##"href="#reply">Reply</a>"##));
    assert!(thread_page.contains(r##"href="#thread-latest">Latest</a>"##));
    assert!(thread_page.contains(
        "scroll-margin-top:calc(var(--appbar-h,56px) + 72px)"
    ));
    assert!(thread_page.contains(".post[id],"));
    assert_eq!(
        thread_page
            .matches(&format!(
                r#"action="/t/{}/subscribe""#,
                subscribed_loc.trim_start_matches("/t/")
            ))
            .count(),
        1,
        "sticky toolbar reuses one authoritative subscription form"
    );

    let (_s, _h, filtered) = send(
        &state,
        get_as("/?filter=subscribed", ALICE_SUB, ALICE_EMAIL),
    )
    .await;
    assert!(filtered.contains("Subscribed target"));
    assert!(!filtered.contains("Unsubscribed target"));
    assert!(filtered.contains(
        r#"<a class="ag-cat is-active" href="/?filter=subscribed" aria-current="page">"#
    ));

    let (status, _h, _b) = send(
        &state,
        post_as(
            &subscribe_uri,
            TOK,
            ALICE_SUB,
            ALICE_EMAIL,
            form(&[("csrf", TOK), ("action", "unfollow")]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_s, _h, filtered) = send(
        &state,
        get_as("/?filter=subscribed", ALICE_SUB, ALICE_EMAIL),
    )
    .await;
    assert!(
        !filtered.contains("Subscribed target"),
        "toggle-off removes it from the filter"
    );

    let (_s, _h, other_page) = send(&state, get_as(&other_loc, ALICE_SUB, ALICE_EMAIL)).await;
    assert!(
        other_page.contains("Follow"),
        "thread outside Following still offers follow"
    );
}

#[tokio::test]
async fn thread_list_top_and_hot_sort() {
    let state = build_dev_state().await;
    let now = now_secs();
    seed_thread(&state, "t_old_busy_flow", "Old Busy Top", now - 7 * 86_400).await;
    seed_thread(
        &state,
        "t_recent_small_flow",
        "Recent Hot Small",
        now - 3_600,
    )
    .await;

    for i in 0..20 {
        seed_reply(
            &state,
            "t_old_busy_flow",
            &format!("p_old_busy_{i}"),
            "old reply",
            now - 7 * 86_400 + i,
        )
        .await;
    }
    for i in 0..4 {
        seed_reply(
            &state,
            "t_recent_small_flow",
            &format!("p_recent_small_{i}"),
            "recent reply",
            now - 3_600 + i,
        )
        .await;
    }

    let (_s, _h, top) = send(&state, get("/?sort=top")).await;
    assert!(
        top.find("Old Busy Top").unwrap() < top.find("Recent Hot Small").unwrap(),
        "top prioritizes reply count"
    );

    let (_s, _h, hot) = send(&state, get("/?sort=hot")).await;
    assert!(
        hot.find("Recent Hot Small").unwrap() < hot.find("Old Busy Top").unwrap(),
        "hot decays old reply volume"
    );
}

async fn create_thread(state: &AppState, title: &str, body_md: &str) -> String {
    let body = form(&[
        ("csrf", TOK),
        ("category", "general"),
        ("title", title),
        ("body", body_md),
    ]);
    let (status, h, _b) = send(state, post_as("/new", TOK, ALICE_SUB, ALICE_EMAIL, body)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    h.get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

async fn seed_thread(state: &AppState, id: &str, title: &str, created_at: i64) {
    let thread = Thread {
        id: id.to_string(),
        category_id: "general".to_string(),
        title: title.to_string(),
        author_sub: ALICE_SUB.to_string(),
        author_email: ALICE_EMAIL.to_string(),
        created_at,
        last_at: created_at,
        locked: false,
        pinned: false,
        accepted_post_id: String::new(),
    };
    let first = Post {
        id: format!("p_{id}_op"),
        thread_id: id.to_string(),
        body_md: "OP".to_string(),
        quoted_post_id: String::new(),
        author_sub: ALICE_SUB.to_string(),
        author_email: ALICE_EMAIL.to_string(),
        created_at,
    };
    state.store.create_thread(&thread, &first).await.unwrap();
}

async fn seed_reply(state: &AppState, thread_id: &str, id: &str, body_md: &str, created_at: i64) {
    let post = Post {
        id: id.to_string(),
        thread_id: thread_id.to_string(),
        body_md: body_md.to_string(),
        quoted_post_id: String::new(),
        author_sub: BOB_SUB.to_string(),
        author_email: BOB_EMAIL.to_string(),
        created_at,
    };
    state.store.add_reply(&post).await.unwrap();
}

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
