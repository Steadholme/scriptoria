//! Writer Studio contracts: explicit publication intents, progressive enhancement, safe preview,
//! bounded tag suggestions, and the SSR/no-JS accessibility fallback.

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

use inkwell::store::Post;
use inkwell::{app, build_dev_state, now_secs, AppState};

const CSRF: &str = "writer-studio-test-token";

#[tokio::test]
async fn writer_html_contract_and_missing_intent_default_to_draft() {
    let state = build_dev_state();
    let (status, _, html) = call(&state, get_auth("/new")).await;
    assert_eq!(status, StatusCode::OK);
    for contract in [
        r#"data-writer-studio"#,
        r#"data-initial-state="draft""#,
        r#"name="intent" value="save_draft""#,
        r#"name="intent" value="publish_now""#,
        r#"name="intent" value="schedule""#,
        r#"id="tab-split""#,
        r#"id="tab-reader""#,
        "Split body preview",
        "Article body preview",
        r#"role="status" aria-live="polite""#,
        r#"aria-autocomplete="list""#,
        "after 24 hours while open, or on your next visit",
        "sweepExpiredRecovery();",
        "data-recovery-scope=\"",
        "cancelAutosave();",
        "persistRecovery(draftKey, RECOVERY_TTL)",
        "var intent = submitter ? submitter.value : '';",
        "JavaScript is off: this value is interpreted as UTC",
        "setStatus('saving')",
        "setStatus('error')",
    ] {
        assert!(
            html.contains(contract),
            "missing Writer contract: {contract}"
        );
    }
    assert!(
        !html.contains("{{"),
        "all Writer template slots are resolved"
    );
    assert!(
        !html.contains("Reader preview"),
        "body-only rendering is not presented as a complete reader preview"
    );
    assert!(html.contains(
        r#"class="appnav appnav--studio is-active" href="/library" aria-current="page""#
    ));
    let scope = html
        .split("data-recovery-scope=\"")
        .nth(1)
        .and_then(|tail| tail.split('\"').next())
        .expect("hashed recovery scope");
    assert_eq!(scope.len(), 24);
    assert!(scope.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_ne!(scope, "u_writer");
    assert!(
        !scope.contains('@'),
        "recovery scope never contains email text"
    );

    // Even a stale/forged legacy checkbox cannot publish: without an explicit intent, create is
    // Draft. This locks publication authority to the server-side intent parser.
    let body = form(&[
        ("title", "Default Draft"),
        ("body", "not public yet"),
        ("published", "on"),
        ("csrf_token", CSRF),
    ]);
    let (status, _, raw) = call(&state, post_json("/new", &body)).await;
    assert_eq!(status, StatusCode::OK);
    let saved: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(saved["state"], "draft");
    let post = state.store.get_post("default-draft").await.unwrap();
    assert!(!post.published);

    let (status, _, _) = call(&state, get("/p/default-draft")).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "draft stays off public reads"
    );
    let (status, _, _) = call(&state, get_auth("/p/default-draft")).await;
    assert_eq!(status, StatusCode::OK, "author can still inspect the draft");

    let (status, _, edit_html) = call(&state, get_auth("/edit/default-draft")).await;
    assert_eq!(status, StatusCode::OK);
    let preserve = edit_html
        .find("Save changes")
        .expect("edit preserve action");
    let unpublish = edit_html.find("Save draft").expect("explicit draft action");
    assert!(
        preserve < unpublish,
        "implicit native submit resolves to preserve before the destructive Draft action"
    );
}

#[tokio::test]
async fn explicit_intents_publish_schedule_and_preserve_edit_state() {
    let state = build_dev_state();

    let publish = form(&[
        ("title", "Live Now"),
        ("body", "public body"),
        ("intent", "publish_now"),
        ("csrf_token", CSRF),
    ]);
    let (status, _, raw) = call(&state, post_json("/new", &publish)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<Value>(&raw).unwrap()["state"],
        "published"
    );

    let future = now_secs() + 3_600;
    let future_text = future.to_string();
    let scheduled = form(&[
        ("title", "Later Post"),
        ("body", "future body"),
        (
            "publish_at",
            "this fallback is intentionally ignored by enhanced clients",
        ),
        ("publish_at_epoch", &future_text),
        ("intent", "schedule"),
        ("csrf_token", CSRF),
    ]);
    let (status, _, raw) = call(&state, post_json("/new", &scheduled)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<Value>(&raw).unwrap()["state"],
        "scheduled"
    );
    let mut later = state.store.get_post("later-post").await.unwrap();
    assert!(later.published);
    assert_eq!(
        later.publish_at, future,
        "browser UTC epoch is authoritative"
    );
    assert!(
        state.store.count_chunks().await.unwrap() > 0,
        "an existing published post keeps the derived cache non-empty"
    );

    let (status, _, public_index) = call(&state, get("/")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(public_index.contains("Live Now"));
    assert!(!public_index.contains("Later Post"));
    let (_, _, search_before) = call(&state, get("/search?q=future")).await;
    assert!(
        !search_before.contains("Later Post"),
        "scheduled post stays out of Search before its instant"
    );

    // No intent on edit preserves the existing Published state; random legacy checkbox values do
    // not drive the transition.
    let live_now_id = state.store.get_post("live-now").await.unwrap().id;
    let preserve = form(&[
        ("title", "Live Now Updated"),
        ("body", "updated"),
        ("expected_version", "1"),
        ("expected_post_id", &live_now_id),
        ("csrf_token", CSRF),
    ]);
    let (status, _, raw) = call(&state, post_json("/edit/live-now", &preserve)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<Value>(&raw).unwrap()["state"],
        "published"
    );
    assert!(state.store.get_post("live-now").await.unwrap().published);

    // Once its instant arrives, the exact same scheduled row becomes publicly visible.
    later.publish_at = now_secs() - 1;
    state.store.update_post(&later).await.unwrap();
    let (_, _, public_index) = call(&state, get("/")).await;
    assert!(public_index.contains("Later Post"));

    // No authoring event/reindex happens at the transition. Search and Ask must still use the
    // authoritative public snapshot even though another post already keeps the cache non-empty.
    let (_, _, search_after) = call(&state, get("/search?q=future")).await;
    assert!(
        search_after.contains("Later Post"),
        "scheduled post is searchable immediately after its instant"
    );
    let ask = form(&[("question", "future body"), ("csrf_token", CSRF)]);
    let (status, _, ask_after) = call(&state, post_json("/api/ask", &ask)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        ask_after.contains("Later Post"),
        "scheduled post is retrievable by Ask immediately after its instant"
    );
    assert!(
        state
            .store
            .fetch_chunks()
            .await
            .unwrap()
            .iter()
            .any(|chunk| chunk.post_id == "later-post"),
        "the derived cache is repaired from the authoritative snapshot"
    );

    // Simulate the exact failure mode of a best-effort deindex leaving stale public chunks. Public
    // retrieval must ignore the poisoned cache and repair it from the now-Draft post table.
    let draft = form(&[
        ("title", "Later Post"),
        ("body", "retired future body"),
        ("intent", "save_draft"),
        ("expected_version", "2"),
        ("expected_post_id", &later.id),
        ("csrf_token", CSRF),
    ]);
    let (status, _, raw) = call(&state, post_json("/edit/later-post", &draft)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<Value>(&raw).unwrap()["state"],
        "draft"
    );
    let stale =
        inkwell::index::build_post_chunks("later-post", "Later Post", "future body", now_secs());
    state
        .store
        .replace_post_chunks("later-post", stale)
        .await
        .unwrap();
    assert!(
        state
            .store
            .fetch_chunks()
            .await
            .unwrap()
            .iter()
            .any(|chunk| chunk.post_id == "later-post"),
        "test precondition: stale Draft chunks exist"
    );

    let (_, _, search_draft) = call(&state, get("/search?q=future")).await;
    assert!(
        !search_draft.contains("Later Post"),
        "stale cache cannot leak a Draft through public Search"
    );
    let (status, _, ask_draft) = call(&state, post_json("/api/ask", &ask)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !ask_draft.contains("Later Post"),
        "stale cache cannot leak a Draft through Ask"
    );
    assert!(
        !state
            .store
            .fetch_public_chunks(now_secs(), inkwell::config::INDEX_CHUNK_LIMIT)
            .await
            .unwrap()
            .iter()
            .any(|chunk| chunk.post_id == "later-post"),
        "validated cache reads reject stale Draft chunks even if physical cleanup failed"
    );
}

#[tokio::test]
async fn old_draft_publish_now_uses_actual_publication_chronology() {
    let state = build_dev_state();
    let now = now_secs();
    let old_draft = Post {
        id: "old_draft_id".to_string(),
        slug: "old-draft".to_string(),
        title: "Old Draft".to_string(),
        body_md: "written long ago".to_string(),
        author_sub: "u_writer".to_string(),
        author_email: "writer@hf".to_string(),
        created_at: now - 86_400,
        updated_at: now - 86_400,
        edit_version: 1,
        published: false,
        publish_at: 0,
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
    };
    let recent = Post {
        id: "recent_public_id".to_string(),
        slug: "recent-public".to_string(),
        title: "Recent Public".to_string(),
        body_md: "already public".to_string(),
        created_at: now - 60,
        updated_at: now - 60,
        published: true,
        ..old_draft.clone()
    };
    state.store.create_post(&old_draft).await.unwrap();
    state.store.create_post(&recent).await.unwrap();

    let publish = form(&[
        ("title", "Old Draft"),
        ("body", "published today"),
        ("intent", "publish_now"),
        ("expected_version", "1"),
        ("expected_post_id", "old_draft_id"),
        ("csrf_token", CSRF),
    ]);
    let before_publish = now_secs();
    let (status, _, _) = call(&state, post_json("/edit/old-draft", &publish)).await;
    assert_eq!(status, StatusCode::OK);
    let published = state.store.get_post("old-draft").await.unwrap();
    assert!(published.published);
    assert!(published.publish_at >= before_publish);
    assert!(published.publish_at <= now_secs());

    let feed = state.store.feed_posts(now_secs()).await.unwrap();
    let old_pos = feed
        .iter()
        .position(|post| post.slug == "old-draft")
        .unwrap();
    let recent_pos = feed
        .iter()
        .position(|post| post.slug == "recent-public")
        .unwrap();
    assert!(
        old_pos < recent_pos,
        "a draft published today ranks by publication, not its old creation time"
    );
    let (_, _, rss) = call(&state, get("/feed.xml")).await;
    assert!(rss.find("Old Draft").unwrap() < rss.find("Recent Public").unwrap());

    let publication_at = published.publish_at;
    let preserve = form(&[
        ("title", "Old Draft preserved"),
        ("body", "saved without a state transition"),
        ("expected_version", "2"),
        ("expected_post_id", "old_draft_id"),
        ("csrf_token", CSRF),
    ]);
    let (status, _, _) = call(&state, post_json("/edit/old-draft", &preserve)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        state.store.get_post("old-draft").await.unwrap().publish_at,
        publication_at,
        "Save changes preserves the authoritative publication instant"
    );
}

#[tokio::test]
async fn same_second_edit_rejects_old_body_chunks_by_monotonic_version() {
    let state = build_dev_state();
    let create = form(&[
        ("title", "Versioned Post"),
        ("body", "obsolete cache token"),
        ("intent", "publish_now"),
        ("csrf_token", CSRF),
    ]);
    let (status, _, _) = call(&state, post_json("/new", &create)).await;
    assert_eq!(status, StatusCode::OK);

    // Put the prior version ahead of the wall clock so the next handler mutation must advance the
    // version independently of elapsed seconds.
    let mut prior = state.store.get_post("versioned-post").await.unwrap();
    prior.updated_at = now_secs() + 60;
    state.store.update_post(&prior).await.unwrap();
    let old_chunks = inkwell::index::build_post_chunks(
        &prior.slug,
        &prior.title,
        &prior.body_md,
        prior.updated_at,
    );
    state
        .store
        .replace_post_chunks(&prior.slug, old_chunks.clone())
        .await
        .unwrap();

    let edit = form(&[
        ("title", "Versioned Post"),
        ("body", "current cache token"),
        ("expected_version", "2"),
        ("expected_post_id", &prior.id),
        ("csrf_token", CSRF),
    ]);
    let (status, _, _) = call(&state, post_json("/edit/versioned-post", &edit)).await;
    assert_eq!(status, StatusCode::OK);
    let current = state.store.get_post("versioned-post").await.unwrap();
    assert!(
        current.updated_at > prior.updated_at,
        "mutable updates always advance the chunk version"
    );

    // Simulate a failed reindex leaving the complete old version behind.
    state
        .store
        .replace_post_chunks(&prior.slug, old_chunks)
        .await
        .unwrap();
    let (_, _, old_search) = call(&state, get("/search?q=obsolete")).await;
    assert!(!old_search.contains("Versioned Post"));
    let (_, _, current_search) = call(&state, get("/search?q=current")).await;
    assert!(current_search.contains("Versioned Post"));
}

#[tokio::test]
async fn incremental_public_index_refresh_and_reads_are_bounded() {
    let state = build_dev_state();
    let now = now_secs();
    for index in 0..=inkwell::config::INDEX_REFRESH_POST_LIMIT {
        let post = Post {
            id: format!("bounded_{index:04}"),
            slug: format!("bounded-{index:04}"),
            title: format!("Bounded {index:04}"),
            body_md: format!("bounded body {index:04}"),
            author_sub: "u_writer".to_string(),
            author_email: "writer@hf".to_string(),
            created_at: now - index,
            updated_at: now - index,
            edit_version: 1,
            published: true,
            publish_at: 0,
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
        };
        state.store.create_post(&post).await.unwrap();
    }

    let first = inkwell::public_index_snapshot(state.store.as_ref())
        .await
        .unwrap();
    assert_eq!(
        first.len() as i64,
        inkwell::config::INDEX_REFRESH_POST_LIMIT,
        "one request repairs only one bounded post batch"
    );
    let second = inkwell::public_index_snapshot(state.store.as_ref())
        .await
        .unwrap();
    assert_eq!(
        second.len() as i64,
        inkwell::config::INDEX_REFRESH_POST_LIMIT + 1,
        "a later request incrementally drains the backlog"
    );
    assert_eq!(
        state.store.fetch_public_chunks(now, 2).await.unwrap().len(),
        2,
        "validated reads obey their explicit limit"
    );
}

#[tokio::test]
async fn no_js_utc_schedule_preview_and_tag_api_are_safe() {
    let state = build_dev_state();
    let future = utc_datetime_local(now_secs() + 3_600);
    let no_js = form(&[
        ("title", "No JS Schedule"),
        ("body", "scheduled without JavaScript"),
        ("publish_at", &future),
        ("intent", "schedule"),
        ("csrf_token", CSRF),
    ]);
    let (status, _, raw) = call(&state, post_json("/new", &no_js)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<Value>(&raw).unwrap()["state"],
        "scheduled"
    );

    let preview = form(&[
        (
            "body",
            "ok <script>alert(1)</script> [bad](javascript:alert(2))",
        ),
        ("csrf_token", CSRF),
    ]);
    let (status, headers, raw) = call(&state, post_json("/api/preview", &preview)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(header::CACHE_CONTROL).unwrap(),
        "private, no-store"
    );
    let rendered = serde_json::from_str::<Value>(&raw).unwrap()["html"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!rendered.contains("<script>"));
    assert!(!rendered.contains("javascript:"));
    assert!(rendered.contains("&lt;script&gt;"));

    for i in 0..25 {
        let title = format!("Tagged {i}");
        let tag = if i == 0 {
            "<script>alert".to_string()
        } else {
            format!("tag{i:02}")
        };
        let body = form(&[
            ("title", &title),
            ("body", "tag seed"),
            ("tags", tag.as_str()),
            ("intent", "publish_now"),
            ("csrf_token", CSRF),
        ]);
        let (status, _, _) = call(&state, post_json("/new", &body)).await;
        assert_eq!(status, StatusCode::OK);
    }

    let (status, _, _) = call(&state, get("/api/tags?prefix=tag&limit=999")).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "tag taxonomy is writer-only"
    );
    let (status, headers, raw) = call(&state, get_auth("/api/tags?prefix=&limit=999")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(header::CACHE_CONTROL).unwrap(),
        "private, no-store"
    );
    assert!(
        !raw.contains("<script>"),
        "unsafe legacy tag is not suggested"
    );
    let items = serde_json::from_str::<Value>(&raw).unwrap()["items"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(items.len(), 20, "server clamps an oversized limit");
}

async fn call(state: &AppState, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, String) {
    let response = app(state.clone()).oneshot(req).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, headers, String::from_utf8_lossy(&body).to_string())
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn get_auth(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("x-auth-subject", "u_writer")
        .header("x-auth-email", "writer@hf")
        .body(Body::empty())
        .unwrap()
}

fn post_json(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT, "application/json")
        .header(header::COOKIE, format!("__Host-csrf={CSRF}"))
        .header("x-auth-subject", "u_writer")
        .header("x-auth-email", "writer@hf")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", key, encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn utc_datetime_local(secs: i64) -> String {
    let dt = time::OffsetDateTime::from_unix_timestamp(secs).unwrap();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute(),
    )
}
