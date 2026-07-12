//! End-to-end HTTP flow for the "ask your blog" feature + related-posts (in-memory, NO database).
//!
//! Drives the real `app` router via `tower::oneshot`, exactly like `posts_flow`. Covers: the
//! SSO/CSRF guards on `/api/ask`, lazy indexing + extractive retrieval with linked citations,
//! the no-match path, draft exclusion from answers, and the related-posts block on a post view.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use inkwell::{app, build_dev_state, AppState};
use tower::ServiceExt;

const CSRF: &str = "tok_csrf_for_tests";

#[tokio::test]
async fn ask_retrieves_with_citations_and_excludes_drafts() {
    let state = build_dev_state();

    // Seed three published posts (two related, one off-topic) + one draft with matching keywords.
    create(
        &state,
        "Rust Async Runtime",
        "the tokio runtime drives async rust tasks on the gateway",
        true,
    )
    .await;
    create(
        &state,
        "Gateway Routing",
        "the gateway routes async rust requests through tokio",
        true,
    )
    .await;
    create(
        &state,
        "Sourdough Bread",
        "a recipe for baking bread with flour and water",
        true,
    )
    .await;
    create(
        &state,
        "Secret Async Notes",
        "draft about the async rust runtime and tokio gateway",
        false,
    )
    .await;

    // --- GET /ask renders + mints a CSRF cookie ----------------------------
    let resp = app(state.clone())
        .oneshot(get_auth("/ask", "u_alice", "alice@hf"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(header::CACHE_CONTROL).unwrap(),
        "private, no-store",
        "the rendered CSRF token is never shared"
    );
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        set_cookie.contains("__Host-csrf="),
        "GET /ask mints CSRF cookie"
    );

    // --- POST /api/ask without identity -> 401 -----------------------------
    let body = form(&[("question", "rust gateway"), ("csrf_token", CSRF)]);
    let (status, _) = call(&state, post_csrf("/api/ask", &body, None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no X-Auth -> 401");

    // --- POST /api/ask with bad CSRF -> 401 --------------------------------
    let body = form(&[("question", "rust gateway"), ("csrf_token", "WRONG")]);
    let (status, _) = call(
        &state,
        post_csrf("/api/ask", &body, Some(("u_alice", "alice@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "CSRF mismatch -> 401");

    // --- a real ask: retrieves the two on-topic posts, with links ----------
    let body = form(&[
        ("question", "how does the rust async gateway runtime work"),
        ("csrf_token", CSRF),
    ]);
    let (status, html) = call(
        &state,
        post_csrf("/api/ask", &body, Some(("u_alice", "alice@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Answer"), "answer section rendered");
    assert!(html.contains("Sources"), "sources section rendered");
    assert!(
        html.contains(r#"href="/p/rust-async-runtime""#),
        "links the matching post"
    );
    assert!(
        html.contains(r#"href="/p/gateway-routing""#),
        "links the second matching post"
    );
    assert!(
        !html.contains("Sourdough Bread"),
        "off-topic post not cited"
    );
    assert!(
        !html.contains("Secret Async Notes"),
        "DRAFT never surfaces in an answer"
    );

    // --- a gibberish ask: graceful no-match (never 500) --------------------
    let body = form(&[("question", "zzzqqq nonexistentword"), ("csrf_token", CSRF)]);
    let (status, html) = call(
        &state,
        post_csrf("/api/ask", &body, Some(("u_alice", "alice@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("No matching posts"), "empty-match path");

    // --- empty question -> 400 ---------------------------------------------
    let body = form(&[("question", "   "), ("csrf_token", CSRF)]);
    let (status, _) = call(
        &state,
        post_csrf("/api/ask", &body, Some(("u_alice", "alice@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "blank question rejected");
}

#[tokio::test]
async fn ask_get_post_and_errors_are_always_private_no_store() {
    let state = build_dev_state();
    let get_response = app(state.clone())
        .oneshot(get_auth("/ask", "u_alice", "alice@hf"))
        .await
        .unwrap();
    assert_eq!(get_response.status(), StatusCode::OK);
    assert!(get_response.headers().get(header::SET_COOKIE).is_some());
    assert_eq!(
        get_response.headers().get(header::CACHE_CONTROL).unwrap(),
        "private, no-store"
    );

    let body = form(&[("question", "anything public"), ("csrf_token", CSRF)]);
    let post_response = app(state.clone())
        .oneshot(post_csrf("/api/ask", &body, Some(("u_alice", "alice@hf"))))
        .await
        .unwrap();
    assert_eq!(post_response.status(), StatusCode::OK);
    assert_eq!(
        post_response.headers().get(header::CACHE_CONTROL).unwrap(),
        "private, no-store"
    );

    let unauthorized = app(state)
        .oneshot(post_csrf("/api/ask", &body, None))
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        unauthorized.headers().get(header::CACHE_CONTROL).unwrap(),
        "private, no-store"
    );
}

#[tokio::test]
async fn related_posts_block_links_siblings_only() {
    let state = build_dev_state();

    create_tagged(
        &state,
        "Rust Async Runtime",
        "the tokio runtime drives async rust tasks on the gateway",
        "Rust, Async",
        true,
    )
    .await;
    create_tagged(
        &state,
        "Gateway Routing",
        "the gateway routes async rust requests through tokio",
        "Rust, Async, Gateway",
        true,
    )
    .await;
    create_tagged(
        &state,
        "Sourdough Bread",
        "a recipe for baking bread with flour and water",
        "Cooking",
        true,
    )
    .await;
    create_tagged(
        &state,
        "Secret Async Notes",
        "draft about the async rust runtime and tokio gateway",
        "Rust, Async",
        false,
    )
    .await;

    // Viewing the Rust post shows a Related block linking the sibling Gateway post, but never the
    // off-topic post and never the draft.
    let (status, html) = call(&state, get("/p/rust-async-runtime")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Related posts"), "related block rendered");
    assert!(
        html.contains(r#"href="/p/gateway-routing""#),
        "links the related sibling"
    );
    assert!(
        !html.contains("Sourdough Bread"),
        "off-topic post not related"
    );
    assert!(
        !html.contains("Secret Async Notes"),
        "draft never appears as related"
    );
    // The article must not list ITSELF as related.
    let related_section = html.split("Related posts").nth(1).unwrap_or("");
    assert!(
        !related_section.contains(r#"href="/p/rust-async-runtime""#),
        "post is not its own related"
    );
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

async fn create(state: &AppState, title: &str, body: &str, published: bool) {
    create_tagged(state, title, body, "", published).await;
}

async fn create_tagged(state: &AppState, title: &str, body: &str, tags: &str, published: bool) {
    let mut pairs = vec![("title", title), ("body", body), ("csrf_token", CSRF)];
    if !tags.is_empty() {
        pairs.push(("tags", tags));
    }
    if published {
        pairs.push(("published", "on"));
    }
    let form = form(&pairs);
    let (status, _) = call(
        state,
        post_csrf("/new", &form, Some(("u_alice", "alice@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "seed post created");
}

async fn call(state: &AppState, req: Request<Body>) -> (StatusCode, String) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn get_auth(uri: &str, sub: &str, email: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("x-auth-subject", sub)
        .header("x-auth-email", email)
        .body(Body::empty())
        .unwrap()
}

fn post_csrf(uri: &str, body: &str, ident: Option<(&str, &str)>) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={CSRF}"));
    if let Some((sub, email)) = ident {
        b = b
            .header("x-auth-subject", sub)
            .header("x-auth-email", email);
    }
    b.body(Body::from(body.to_string())).unwrap()
}

fn form(pairs: &[(&str, &str)]) -> String {
    let mut fields = pairs
        .iter()
        .map(|(k, v)| format!("{}={}", k, enc(v)))
        .collect::<Vec<_>>();
    if !pairs.iter().any(|(key, _)| *key == "intent") {
        let intent = if pairs.iter().any(|(key, _)| *key == "published") {
            "publish_now"
        } else {
            "save_draft"
        };
        fields.push(format!("intent={intent}"));
    }
    fields.join("&")
}

fn enc(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                o.push(b as char)
            }
            b' ' => o.push('+'),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}
