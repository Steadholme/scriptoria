//! End-to-end HTTP flow for the discovery feeds over the in-memory store (NO database).
//!
//! Drives the real `app` router via `tower::oneshot`, exactly like the rest of the estate.
//! Covers: `/feed.xml` (RSS 2.0) and `/sitemap.xml` derived from the published posts, the
//! draft-exclusion invariant (drafts are never syndicated), and the index `<link rel="alternate">`.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use inkwell::{app, build_dev_state, now_secs, AppState};
use tower::ServiceExt;

const CSRF: &str = "tok_csrf_for_tests";

#[tokio::test]
async fn feeds_expose_published_posts_only() {
    let state = build_dev_state();

    // One PUBLISHED post and one DRAFT (omit the `published` checkbox for the draft).
    create(&state, "Published Post", "hello body", true).await;
    create(&state, "Secret Draft", "wip body", false).await;
    create_scheduled(&state, "Future Post", "later body").await;

    // --- /feed.xml ---------------------------------------------------------
    let (status, ctype, body) = call(&state, "/feed.xml").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        ctype.starts_with("application/rss+xml"),
        "rss content-type, got {ctype}"
    );
    assert!(body.contains("<rss version=\"2.0\""), "declares RSS 2.0");
    assert!(
        body.contains("<title>Published Post</title>"),
        "published post is in the feed"
    );
    assert!(
        body.contains("<link>https://blog.w33d.xyz/p/published-post</link>"),
        "item carries an absolute reading-view link"
    );
    assert!(
        body.contains("<pubDate>"),
        "item carries an RFC 822 pubDate"
    );
    assert!(
        !body.contains("Secret Draft"),
        "drafts are NEVER syndicated"
    );
    assert!(
        !body.contains("Future Post"),
        "scheduled posts are not syndicated early"
    );

    // --- /sitemap.xml ------------------------------------------------------
    let (status, ctype, body) = call(&state, "/sitemap.xml").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        ctype.starts_with("application/xml"),
        "xml content-type, got {ctype}"
    );
    assert!(body.contains("<urlset"), "declares a sitemap urlset");
    assert!(
        body.contains("<loc>https://blog.w33d.xyz/</loc>"),
        "index page is in the sitemap"
    );
    assert!(
        body.contains("<loc>https://blog.w33d.xyz/p/published-post</loc>"),
        "published post is in the sitemap"
    );
    assert!(body.contains("<lastmod>"), "post url carries a lastmod");
    assert!(
        !body.contains("secret-draft"),
        "drafts are NEVER in the sitemap"
    );
    assert!(
        !body.contains("future-post"),
        "scheduled posts are NEVER in the sitemap early"
    );

    // --- index advertises the feed ----------------------------------------
    let (status, _ctype, body) = call(&state, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"<link rel="alternate" type="application/rss+xml""#),
        "index head links the RSS feed"
    );
    assert!(
        body.contains(r#"href="/feed.xml""#),
        "alternate link points at /feed.xml"
    );
}

#[tokio::test]
async fn empty_blog_feeds_are_well_formed() {
    let state = build_dev_state();

    let (status, _ctype, body) = call(&state, "/feed.xml").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("<channel>") && body.contains("</channel>"),
        "valid empty channel"
    );
    assert!(!body.contains("<item>"), "no items on an empty blog");

    let (status, _ctype, body) = call(&state, "/sitemap.xml").await;
    assert_eq!(status, StatusCode::OK);
    // The index url is always present even with no posts.
    assert!(body.contains("<loc>https://blog.w33d.xyz/</loc>"));
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// GET `uri`, returning `(status, content-type, body)`.
async fn call(state: &AppState, uri: &str) -> (StatusCode, String, String) {
    let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let ctype = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, ctype, String::from_utf8_lossy(&bytes).to_string())
}

/// Create a post via the real `POST /new` flow (author from gateway headers, CSRF double-submit).
async fn create(state: &AppState, title: &str, body: &str, published: bool) {
    let mut pairs = vec![("title", title), ("body", body), ("csrf_token", CSRF)];
    if published {
        pairs.push(("intent", "publish_now"));
    } else {
        pairs.push(("intent", "save_draft"));
    }
    let form = pairs
        .iter()
        .map(|(k, v)| format!("{}={}", k, enc(v)))
        .collect::<Vec<_>>()
        .join("&");
    let req = Request::builder()
        .method("POST")
        .uri("/new")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={CSRF}"))
        .header("x-auth-subject", "u_alice")
        .header("x-auth-email", "alice@hf")
        .body(Body::from(form))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "post created");
}

async fn create_scheduled(state: &AppState, title: &str, body: &str) {
    let future = datetime_local(now_secs() + 3_600);
    let form = [
        ("title", title),
        ("body", body),
        ("publish_at", future.as_str()),
        ("intent", "schedule"),
        ("csrf_token", CSRF),
    ]
    .iter()
    .map(|(k, v)| format!("{}={}", k, enc(v)))
    .collect::<Vec<_>>()
    .join("&");
    let req = Request::builder()
        .method("POST")
        .uri("/new")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={CSRF}"))
        .header("x-auth-subject", "u_alice")
        .header("x-auth-email", "alice@hf")
        .body(Body::from(form))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "scheduled post created"
    );
}

/// Minimal application/x-www-form-urlencoded value encoder.
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

fn datetime_local(secs: i64) -> String {
    let dt = time::OffsetDateTime::from_unix_timestamp(secs).expect("valid test timestamp");
    format!(
        "{year:04}-{mon:02}-{day:02}T{h:02}:{m:02}",
        year = dt.year(),
        mon = u8::from(dt.month()),
        day = dt.day(),
        h = dt.hour(),
        m = dt.minute(),
    )
}
