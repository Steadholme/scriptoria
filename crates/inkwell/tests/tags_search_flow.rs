//! End-to-end HTTP flow for blog tags + full-text search (in-memory, NO database).
//!
//! Drives the real `app` router via `tower::oneshot`, exactly like `posts_flow`/`ask_flow`.
//! Covers: tags set on compose survive to the card + article as chips, the `/tag/{slug}` listing
//! filters by tag AND respects draft visibility, and `/search?q=` ranks the published-post index
//! with highlighted excerpts (never leaking drafts).

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use inkwell::store::Post;
use inkwell::{app, build_dev_state, AppState};
use tower::ServiceExt;

const CSRF: &str = "tok_csrf_for_tests";

#[tokio::test]
async fn tags_render_and_tag_listing_filters() {
    let state = build_dev_state();

    // A published post tagged rust/async, another tagged cooking, and a DRAFT tagged rust.
    create(&state, "Async Rust", "the tokio runtime drives async rust", "Rust, Async", true).await;
    create(&state, "Sourdough", "a recipe for bread with flour", "Cooking", true).await;
    create(&state, "Secret Rust", "unpublished rust notes", "Rust", false).await;

    // --- chips on the index card + the article view ------------------------
    let (status, idx) = call(&state, get("/")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(idx.contains(r#"href="/tag/rust""#), "tag chip links to the listing");
    assert!(idx.contains(r#"href="/tag/async""#), "each tag renders a chip");

    let (status, article) = call(&state, get("/p/async-rust")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(article.contains(r#"href="/tag/rust""#), "article renders tag chips");

    // --- /tag/rust lists the published rust post, not the cooking one ------
    let (status, page) = call(&state, get("/tag/rust")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("Async Rust"), "tagged post listed");
    assert!(!page.contains("Sourdough"), "differently-tagged post excluded");
    // The draft rust post is hidden from an anonymous viewer.
    assert!(!page.contains("Secret Rust"), "draft never leaks on the public tag page");

    // --- the draft IS visible to its author on the tag page ---------------
    let (_, page_owner) = call(&state, get_auth("/tag/rust", "u_alice", "alice@hf")).await;
    assert!(page_owner.contains("Secret Rust"), "author sees own draft on the tag page");

    // --- an unknown tag yields the empty state -----------------------------
    let (status, none) = call(&state, get("/tag/nonexistent")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(none.contains("No posts tagged"), "empty tag listing");
}

#[tokio::test]
async fn search_ranks_and_highlights_excluding_drafts() {
    let state = build_dev_state();

    create(&state, "Gateway Routing", "the gateway routes async rust through tokio", "", true).await;
    create(&state, "Sourdough Bread", "baking bread with flour and water", "", true).await;
    create(&state, "Secret Gateway", "unpublished notes about the gateway", "", false).await;

    // --- empty query renders the prompt, not results -----------------------
    let (status, empty) = call(&state, get("/search")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(empty.contains("Search the blog"), "empty prompt shown");

    // --- a real search: matches the published gateway post, highlighted ----
    let (status, html) = call(&state, get("/search?q=gateway")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains(r#"href="/p/gateway-routing""#), "matching post linked");
    assert!(html.contains("<mark>gateway</mark>"), "query term highlighted in the excerpt");
    assert!(!html.contains("Sourdough Bread"), "off-topic post not returned");
    assert!(!html.contains("Secret Gateway"), "DRAFT never surfaces in search");

    // --- a gibberish search: graceful no-match (never 500) -----------------
    let (status, html) = call(&state, get("/search?q=zzzqqqnope")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("No matches"), "empty-match path");
}

#[tokio::test]
async fn sparse_tag_continues_across_scan_cap_without_skip_or_duplication() {
    let state = build_dev_state();
    state
        .store
        .create_post(&stored_post(
            "deep-tagged",
            "Deep Tagged Story",
            1,
            true,
            "Needle",
        ))
        .await
        .unwrap();
    state
        .store
        .create_post(&stored_post(
            "deeper-tagged",
            "Deeper Tagged Story",
            0,
            true,
            "Needle",
        ))
        .await
        .unwrap();
    state
        .store
        .create_post(&stored_post(
            "private-deep-tagged",
            "Private Deep Tagged Story",
            -1,
            false,
            "Needle",
        ))
        .await
        .unwrap();
    for index in 0..inkwell::config::TAG_SCAN_POST_LIMIT {
        state
            .store
            .create_post(&stored_post(
                &format!("ordinary-{index:04}"),
                &format!("Ordinary {index:04}"),
                10_000 + index as i64,
                true,
                "Other",
            ))
            .await
            .unwrap();
    }

    let (status, page) = call(&state, get("/tag/needle?limit=10")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !page.contains("Deep Tagged Story") && !page.contains("Deeper Tagged Story"),
        "the first bounded scan may legitimately contain no sparse-tag match"
    );
    assert!(!page.contains("No posts tagged"));
    let cursor = page
        .split("/tag/needle?before=")
        .nth(1)
        .and_then(|tail| tail.split('"').next())
        .expect("empty bounded page exposes a continuation cursor");
    let (_, next) = call(
        &state,
        get(&format!("/tag/needle?before={cursor}&limit=10")),
    )
    .await;
    assert_eq!(next.matches("Deep Tagged Story").count(), 1);
    assert_eq!(next.matches("Deeper Tagged Story").count(), 1);
    assert!(!page.contains("Private Deep Tagged Story"));
    assert!(!next.contains("Private Deep Tagged Story"));
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

async fn create(state: &AppState, title: &str, body: &str, tags: &str, published: bool) {
    let mut pairs = vec![("title", title), ("body", body), ("tags", tags), ("csrf_token", CSRF)];
    pairs.push(("intent", if published { "publish_now" } else { "save_draft" }));
    let form = form(&pairs);
    let (status, _) = call(state, post_csrf("/new", &form, Some(("u_alice", "alice@hf")))).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "seed post created");
}

fn stored_post(slug: &str, title: &str, created_at: i64, published: bool, tags: &str) -> Post {
    Post {
        id: format!("id-{slug}"),
        slug: slug.to_string(),
        title: title.to_string(),
        body_md: "scale-test body".to_string(),
        author_sub: "u_alice".to_string(),
        author_email: "alice@hf".to_string(),
        created_at,
        updated_at: created_at,
        edit_version: 1,
        published,
        publish_at: 0,
        featured: false,
        pinned: false,
        tags: tags.to_string(),
        cover_url: String::new(),
        custom_excerpt: String::new(),
        meta_title: String::new(),
        meta_description: String::new(),
        canonical_url: String::new(),
        social_title: String::new(),
        social_description: String::new(),
        social_image: String::new(),
    }
}

async fn call(state: &AppState, req: Request<Body>) -> (StatusCode, String) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
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
        b = b.header("x-auth-subject", sub).header("x-auth-email", email);
    }
    b.body(Body::from(body.to_string())).unwrap()
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", k, enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn enc(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => o.push(b as char),
            b' ' => o.push('+'),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}
