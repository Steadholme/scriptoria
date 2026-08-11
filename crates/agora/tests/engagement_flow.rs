//! End-to-end tests for quote replies, mentions, thread subscriptions, and thread list sorting.
//!
//! Drives the real Router over the in-memory store, matching the existing forum flow harness.

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use tower::ServiceExt;

use agora::model::{Post, Thread};
use agora::{app, build_dev_state, now_secs, AppState};

const ALICE_SUB: &str = "u_sub_1";
const ALICE_EMAIL: &str = "alice@steadholme.local";
const BOB_SUB: &str = "u_sub_bob";
const BOB_EMAIL: &str = "bob@steadholme.local";
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
        page.contains(r#"<blockquote class="ag-quote ag-key-shared">"#),
        "typed shared quote block rendered"
    );
    assert!(
        page.contains(r#"<cite class="ag-quote__cite">alice@steadholme.local · <time "#),
        "quoted author attributed"
    );
    assert!(
        page.contains("Original &lt;unsafe&gt; body."),
        "quoted body is escaped"
    );
    let quote_pos = page
        .find(r#"<blockquote class="ag-quote ag-key-shared">"#)
        .unwrap();
    let reply_pos = page.find("Thanks @alice").unwrap();
    assert!(quote_pos < reply_pos, "quote renders above reply body");

    let (_s, _h, home) = send(&state, get_as("/", ALICE_SUB, ALICE_EMAIL)).await;
    assert!(home.contains(r#"aria-label="Activity, 1 unread""#));
    assert!(
        home.contains(r#"<a class="ag-ledger-link ag-key-private" href="/for-you">For You</a>"#)
    );
    assert!(home
        .contains(r#"<a class="ag-ledger-link ag-key-private" href="/bookmarks">Bookmarks</a>"#));
    assert!(home.contains(
        r#"<a class="btn btn-secondary btn-sm ag-key-private" href="/?sort=latest&amp;filter=subscribed">Following</a>"#
    ));
    assert!(!home.contains(r#"aria-pressed="false">Following</a>"#));
    assert!(home.contains(r#"<a class="appnav is-active" href="/" aria-current="location">"#));
    assert!(
        home.contains(r#"<span class="ag-count-badge ag-key-private" aria-hidden="true">1</span>"#),
        "the app bar renders the private request-derived Activity count"
    );
    let (_s, _h, activity) = send(&state, get_as("/activity", ALICE_SUB, ALICE_EMAIL)).await;
    assert!(activity.contains("Quote and mention"));
    assert!(activity
        .contains(r#"<span class="ag-mark ag-key-private ag-mark--reason">Mentioned you</span>"#));
    assert_eq!(
        activity
            .matches(r#"class="ag-activity-row ag-key-shared""#)
            .count(),
        1,
        "OP + quote + @mention delivery paths collapse to one event"
    );
    assert!(
        activity.contains(r#"<span class="ag-mark ag-key-private ag-mark--unread">Unread</span>"#)
    );

    let (_s, _h, bob_activity) = send(&state, get_as("/activity", BOB_SUB, BOB_EMAIL)).await;
    assert_eq!(
        bob_activity
            .matches(r#"class="ag-activity-row ag-key-shared""#)
            .count(),
        0,
        "the actor is never self-notified"
    );
    assert!(bob_activity.contains("No activity in this view yet."));
}

#[tokio::test]
async fn thread_follow_preference_form_and_filter() {
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
            form(&[("csrf", TOK), ("level", "watch")]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (_s, _h, thread_page) = send(&state, get_as(&subscribed_loc, ALICE_SUB, ALICE_EMAIL)).await;
    assert!(thread_page.contains(&format!(
        r#"<form class="ag-form ag-subscribe" method="post" action="{subscribe_uri}">"#
    )));
    assert!(thread_page.contains(r#"<select id="ag-sub-level" name="level">"#));
    assert!(thread_page.contains(r#"value="watch" selected"#));
    assert!(thread_page.contains(r#"<option value="none">Not following</option>"#));
    assert!(thread_page.contains(r#"<option value="watch" selected>Watch</option>"#));
    assert!(thread_page.contains(r#"<option value="follow">Follow</option>"#));
    assert!(thread_page.contains(r#"<option value="mute">Mute</option>"#));
    assert!(thread_page.contains("Private: this shapes your catch-up, not notification delivery."));
    assert_eq!(
        thread_page
            .matches(&format!(r#"action="{subscribe_uri}""#))
            .count(),
        1,
        "the typed view renders one authoritative subscription form"
    );

    let (_s, _h, filtered) = send(
        &state,
        get_as("/?filter=subscribed", ALICE_SUB, ALICE_EMAIL),
    )
    .await;
    assert!(filtered.contains("Subscribed target"));
    assert!(!filtered.contains("Unsubscribed target"));
    assert!(filtered.contains(
        r#"<a class="btn btn-secondary btn-sm ag-key-private is-active" href="/?sort=latest" aria-current="page">Show all</a>"#
    ));

    let (status, _h, _b) = send(
        &state,
        post_as(
            &subscribe_uri,
            TOK,
            ALICE_SUB,
            ALICE_EMAIL,
            form(&[("csrf", TOK), ("level", "none")]),
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
        other_page.contains(r#"value="none" selected"#),
        "thread outside Following defaults to an explicit reset state"
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
