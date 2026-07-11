//! End-to-end HTTP flow for the discovery feeds over the in-memory store (NO database).
//!
//! Drives the real `app` router via `tower::oneshot`, exactly like the rest of the estate.
//! Covers: `/feed.xml` (RSS 2.0) and `/sitemap.xml` derived from the published posts, the
//! draft-exclusion invariant (drafts are never syndicated), and the index `<link rel="alternate">`.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use inkwell::store::{PgStore, Post, Settings};
use inkwell::{app, build_dev_state, now_secs, AppState};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

const CSRF: &str = "tok_csrf_for_tests";

#[tokio::test]
async fn feeds_expose_published_posts_only() {
    let state = build_dev_state();

    // One PUBLISHED post and one DRAFT (omit the `published` checkbox for the draft).
    create(&state, "Published Post", "hello body", true).await;
    create(&state, "Secret Draft", "wip body", false).await;
    create_scheduled(&state, "Future Post", "later body").await;
    state
        .store
        .update_settings(&Settings {
            title: "Test Publication".to_string(),
            tagline: "A test feed description.".to_string(),
            posts_per_page: 50,
        })
        .await
        .unwrap();

    // --- /feed.xml ---------------------------------------------------------
    let (status, ctype, body) = call(&state, "/feed.xml").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        ctype.starts_with("application/rss+xml"),
        "rss content-type, got {ctype}"
    );
    assert!(body.contains("<rss version=\"2.0\""), "declares RSS 2.0");
    assert!(body.contains("<title>Test Publication</title>"));
    assert!(body.contains("<description>A test feed description.</description>"));
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

#[tokio::test]
async fn feed_caps_recent_public_items_while_sitemap_traverses_the_archive() {
    let state = build_dev_state();
    state
        .store
        .create_post(&stored_post("deep-public", "Deep Public Story", 1, true, 0))
        .await
        .unwrap();
    // More than MAX_PAGE private rows sort ahead of the public post, but cannot consume an RSS
    // slot because the feed reads authoritative public rows directly.
    for index in 0..=inkwell::config::MAX_PAGE {
        state
            .store
            .create_post(&stored_post(
                &format!("newer-draft-{index:04}"),
                &format!("Newer Draft {index:04}"),
                90_000 + index,
                false,
                0,
            ))
            .await
            .unwrap();
    }
    let (_, _, feed) = call(&state, "/feed.xml").await;
    assert!(feed.contains("Deep Public Story"));
    assert!(!feed.contains("Newer Draft"));

    // The sitemap is the full bounded archive, while RSS remains a 100-item recent-content view.
    for index in 0..=inkwell::config::MAX_PAGE {
        state
            .store
            .create_post(&stored_post(
                &format!("newer-public-{index:04}"),
                &format!("Newer Public {index:04}"),
                10_000 + index,
                true,
                0,
            ))
            .await
            .unwrap();
    }
    state
        .store
        .create_post(&stored_post(
            "secret-at-top",
            "Secret At Top",
            99_999,
            false,
            0,
        ))
        .await
        .unwrap();
    state
        .store
        .create_post(&stored_post(
            "future-at-top",
            "Future At Top",
            99_998,
            true,
            now_secs() + 3_600,
        ))
        .await
        .unwrap();
    let due_at = now_secs() - 1;
    state
        .store
        .create_post(&stored_post(
            "schedule-arrived",
            "Schedule Arrived",
            2,
            true,
            due_at,
        ))
        .await
        .unwrap();
    // Homepage pins are intentionally orthogonal to feed chronology. One hundred ancient pinned
    // rows would consume every slot if RSS first took the homepage page and sorted afterwards.
    for index in 0..inkwell::config::FEED_ITEM_LIMIT {
        let mut pinned = stored_post(
            &format!("old-pinned-{index:03}"),
            &format!("Old Pinned {index:03}"),
            100 + index as i64,
            true,
            0,
        );
        pinned.pinned = true;
        state.store.create_post(&pinned).await.unwrap();
    }

    let (_, _, feed) = call(&state, "/feed.xml").await;
    assert!(feed.contains("Schedule Arrived"));
    assert!(feed.contains("Newer Public 0200"));
    assert!(!feed.contains("Old Pinned 000"));
    assert!(!feed.contains("Secret At Top"));
    assert!(!feed.contains("Future At Top"));
    assert_eq!(
        feed.matches("<item>").count(),
        100,
        "RSS is capped even when the public archive is larger"
    );
    assert!(
        !feed.contains("Deep Public Story"),
        "old archive entries stay in the sitemap rather than bloating RSS"
    );
    let schedule_item = feed
        .split("<title>Schedule Arrived</title>")
        .nth(1)
        .expect("scheduled item in feed");
    let pub_date = schedule_item
        .split("<pubDate>")
        .nth(1)
        .and_then(|tail| tail.split("</pubDate>").next())
        .expect("scheduled item pubDate");
    assert!(
        feed.contains(&format!(
            "<lastBuildDate>{pub_date}</lastBuildDate>"
        )),
        "lastBuildDate advances to the old-created post's actual due instant"
    );

    let authoritative = state.store.feed_posts(now_secs()).await.unwrap();
    assert_eq!(
        authoritative.len(),
        inkwell::config::FEED_ITEM_LIMIT,
        "Store owns the RSS cap"
    );
    assert_eq!(authoritative[0].slug, "schedule-arrived");
    let projected = state.store.sitemap_entries(now_secs()).await.unwrap();
    assert!(projected.iter().any(|entry| entry.slug == "deep-public"));
    assert!(projected
        .iter()
        .all(|entry| entry.slug != "secret-at-top" && entry.slug != "future-at-top"));

    let (_, _, sitemap) = call(&state, "/sitemap.xml").await;
    assert!(sitemap.contains("/p/deep-public"));
    assert!(sitemap.contains("/p/schedule-arrived"));
    assert!(!sitemap.contains("/p/secret-at-top"));
    assert!(!sitemap.contains("/p/future-at-top"));
}

#[tokio::test]
async fn sitemap_store_failure_is_a_500_not_a_partial_success() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1/unused")
        .expect("syntactically valid lazy pool");
    pool.close().await;
    let mut state = build_dev_state();
    state.store = Arc::new(PgStore::from_pool(pool));

    let (status, _, body) = call(&state, "/sitemap.xml").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        !body.contains("<urlset"),
        "a failed authoritative projection never returns a partial sitemap"
    );
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

fn stored_post(slug: &str, title: &str, created_at: i64, published: bool, publish_at: i64) -> Post {
    Post {
        id: format!("id-{slug}"),
        slug: slug.to_string(),
        title: title.to_string(),
        body_md: "discovery scale body".to_string(),
        author_sub: "u_alice".to_string(),
        author_email: "alice@hf".to_string(),
        created_at,
        updated_at: created_at,
        edit_version: 1,
        published,
        publish_at,
        featured: false,
        pinned: false,
        tags: String::new(),
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
