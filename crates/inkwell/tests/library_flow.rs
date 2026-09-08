//! Author Content Library HTTP contract over the in-memory Store.
//!
//! Covers owner-only retrieval, composable URL filters, no-store responses, no-JavaScript forms,
//! stable id/version bulk CAS, all-or-nothing conflicts, bounded public-state transitions, and the
//! validated return path back from Writer Studio.

use axum::body::{to_bytes, Body};
use axum::http::{header, HeaderMap, Request, StatusCode};
use inkwell::store::Post;
use inkwell::{app, build_dev_state, handlers, now_secs, AppState};
use tower::ServiceExt;

const CSRF: &str = "library_csrf_token";

#[tokio::test]
async fn library_is_private_owner_scoped_and_composable_without_javascript() {
    let state = build_dev_state();
    let now = now_secs();
    let mut published = fixture("alice-published", "alice", true, 0, "Rust, Notes", 30);
    published.created_at = 100;
    seed(&state, published).await;
    let mut draft = fixture("alice-draft-needle", "alice", false, 0, "Rust", 40);
    draft.created_at = 20;
    seed(&state, draft).await;
    let mut scheduled = fixture(
        "alice-scheduled",
        "alice",
        true,
        now + 3_600,
        "Planning",
        50,
    );
    scheduled.created_at = 30;
    seed(&state, scheduled).await;
    seed(
        &state,
        fixture("bob-private-needle", "bob", false, 0, "Rust", 60),
    )
    .await;

    let (status, headers, _) = call(
        &state,
        Request::builder()
            .uri("/library")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_private_no_store(&headers);

    let (status, headers, body) = call(&state, get("/library", "alice", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_private_no_store(&headers);
    assert!(body.contains("<h1>Studio</h1>"));
    assert!(body.contains("Author library"));
    assert!(body.contains(r#"method="get" action="/library""#));
    assert!(body.contains(r#"id="library-sort" name="sort""#));
    assert!(body.contains(r#"value="updated" selected"#));
    assert!(body.contains(r#"method="post" action="/library/posts/bulk""#));
    assert!(body.contains(r#"aria-label="Author library status""#));
    assert!(body.contains(r#"data-select-page"#));
    assert!(body.contains(r#"data-selection-count"#));
    assert!(body.contains(r#"data-bulk-tag"#));
    assert!(body.contains(r#"input[data-library-item]"#));
    assert!(body.contains("bulk.hidden = selected === 0"));
    assert!(body.contains(&format!(r#"href="{}""#, handlers::APP_CSS_PATH)));
    assert!(!body.contains("<style>"));
    let (css_status, css_headers, css) = call(
        &state,
        Request::builder()
            .uri(handlers::APP_CSS_PATH)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(css_status, StatusCode::OK);
    assert_eq!(
        css_headers.get(header::CONTENT_TYPE).unwrap(),
        "text/css; charset=utf-8"
    );
    assert_eq!(
        css_headers.get(header::CACHE_CONTROL).unwrap(),
        "public, max-age=31536000, immutable"
    );
    assert!(css.contains(".ink-library__bulk[hidden] { display:none; }"));
    assert!(css.contains(".usermenu__pop{display:none"));
    assert!(css.contains(".iconbtn svg{width:18px;height:18px}"));
    assert!(css.contains(".draftbar[hidden] { display:none; }"));
    assert!(body.contains("bulkTag.hidden = action.value !== 'add_tag'"));
    assert!(body.contains("var MAX_SELECTION = 50"));
    assert!(body.contains("Math.min(boxes.length, MAX_SELECTION)"));
    assert!(body.contains("slice(MAX_SELECTION).forEach"));
    assert!(body.contains("Select first 50"));
    assert!(body.contains("maximum reached"));
    assert!(body.contains("box.disabled = selectionLimitReached && !box.checked"));
    assert!(css.contains("@media (max-width:340px)"));
    assert!(css.contains(".appbar__nav .appnav { padding-inline:9px; font-size:13px; }"));
    assert!(css.contains(".appbar__nav .appnav svg { display:none; }"));
    assert!(css.contains(".ink-library .ink-library__status-tab { padding-inline:6px; }"));
    assert!(body.contains("Every selected version is checked"));
    assert!(body.contains("alice-published"));
    assert!(body.contains("alice-draft-needle"));
    assert!(body.contains("alice-scheduled"));
    assert!(body.contains("Preview saved"));
    assert!(body.contains(r#"href="/p/alice-draft-needle?preview=1""#));
    assert!(body.contains("View live"));
    assert!(!body.contains("bob-private-needle"));
    assert!(body.contains(
        r#"class="appnav appnav--studio is-active" href="/library" aria-current="page""#
    ));
    let (_, _, first_page) = call(
        &state,
        get(&format!("/library?as_of={now}&limit=1"), "alice", None),
    )
    .await;
    assert!(first_page.contains("Load older work"));
    assert!(
        first_page.contains(&format!("as_of={now}&amp;limit=1&amp;cursor=")),
        "pager preserves the fixed status-classification instant"
    );

    let uri = format!("/library?q=needle&status=draft&tag=Rust&as_of={now}&limit=10");
    let (status, _, filtered) = call(&state, get(&uri, "alice", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(filtered.contains("alice-draft-needle"));
    assert!(!filtered.contains("alice-published"));
    assert!(!filtered.contains("alice-scheduled"));
    assert!(!filtered.contains("bob-private-needle"));
    assert!(filtered.contains(r#"name="q" type="search""#));
    assert!(filtered.contains(r#"name="status" value="draft""#));
    assert!(filtered.contains(
        r#"class="ink-library__status-tab is-active" href="/library?q=needle&amp;status=draft&amp;tag=Rust"#
    ));
    assert!(filtered.contains(r#"class="ink-library__advanced" open"#));
    assert!(filtered.contains(r#"name="tag" type="text" maxlength="40" value="Rust""#));

    let created_uri = format!("/library?sort=created&as_of={now}&limit=10");
    let (status, _, created_order) = call(&state, get(&created_uri, "alice", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(created_order.contains(r#"value="created" selected"#));
    assert!(created_order.contains(r#"href="/library?status=draft&amp;sort=created&amp;as_of="#));
    assert!(created_order.contains(r#"href="/library?tag=Rust&amp;sort=created&amp;as_of="#));
    assert!(created_order.contains(r#"name="return_to" value="/library?sort=created&amp;as_of="#));
    let published_at = created_order.find("alice-published").unwrap();
    let scheduled_at = created_order.find("alice-scheduled").unwrap();
    let draft_at = created_order.find("alice-draft-needle").unwrap();
    assert!(published_at < scheduled_at && scheduled_at < draft_at);
    let (_, _, created_page) = call(
        &state,
        get(
            &format!("/library?sort=created&as_of={now}&limit=1"),
            "alice",
            None,
        ),
    )
    .await;
    assert!(created_page.contains("sort=created&amp;as_of="));
    assert!(created_page.contains("cursor=created."));

    // Admin membership does not widen the author workspace; site-wide moderation stays /admin.
    let (_, _, admin_library) = call(&state, get("/library", "alice", Some("admins"))).await;
    assert!(!admin_library.contains("bob-private-needle"));
    let (_, admin_headers, _) = call(&state, get("/admin", "alice", Some("admins"))).await;
    assert_private_no_store(&admin_headers);

    let (status, invalid_headers, _) =
        call(&state, get("/library?cursor=forged", "alice", None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_private_no_store(&invalid_headers);
    let (status, invalid_headers, _) =
        call(&state, get("/library?limit=not-a-number", "alice", None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_private_no_store(&invalid_headers);
}

#[tokio::test]
async fn bulk_is_atomic_generic_on_conflict_and_returns_safely_to_library() {
    let state = build_dev_state();
    let one = fixture("one", "alice", false, 0, "", 10);
    let two = fixture("two", "alice", false, 0, "", 20);
    let foreign = fixture("foreign", "bob", false, 0, "", 30);
    seed(&state, one.clone()).await;
    seed(&state, two.clone()).await;
    seed(&state, foreign.clone()).await;

    let stale_body = form(&[
        ("csrf_token", CSRF.to_string()),
        ("action", "publish_now".to_string()),
        ("return_to", "/library?status=draft".to_string()),
        ("items", selection(&one, 1)),
        ("items", selection(&two, 99)),
    ]);
    let (status, headers, conflict) = call(&state, post(&stale_body, "alice")).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_private_no_store(&headers);
    assert!(conflict.contains("selection changed"));
    assert!(
        !conflict.contains("current version") && !conflict.contains("bulk-two"),
        "generic conflict leaks no row or version detail"
    );
    assert!(!state.store.get_post("one").await.unwrap().published);
    assert!(!state.store.get_post("two").await.unwrap().published);

    let foreign_body = form(&[
        ("csrf_token", CSRF.to_string()),
        ("action", "pin".to_string()),
        ("items", selection(&foreign, 1)),
    ]);
    let (status, _, foreign_conflict) = call(&state, post(&foreign_body, "alice")).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(foreign_conflict.contains("selection changed"));

    let valid = form(&[
        ("csrf_token", CSRF.to_string()),
        ("action", "publish_now".to_string()),
        ("return_to", "/library?status=draft".to_string()),
        ("items", selection(&one, 1)),
        ("items", selection(&two, 1)),
    ]);
    let (status, headers, _) = call(&state, post(&valid, "alice")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_private_no_store(&headers);
    let location = headers.get(header::LOCATION).unwrap().to_str().unwrap();
    assert_eq!(location, "/library?status=draft&changed=2");
    let (_, notice_headers, notice_page) = call(&state, get(location, "alice", None)).await;
    assert_private_no_store(&notice_headers);
    assert!(notice_page.contains("Updated 2 posts."));
    for slug in ["one", "two"] {
        let saved = state.store.get_post(slug).await.unwrap();
        assert!(saved.published);
        assert_eq!(saved.edit_version, 2);
        assert!(saved.updated_at > 20 || slug == "one");
        assert_eq!(
            state
                .store
                .list_post_revisions(&saved.id, 10)
                .await
                .unwrap()[0]
                .source,
            "library.publish"
        );
    }

    let stale_editor = form(&[
        ("title", "one".to_string()),
        ("body", "stale editor text survives".to_string()),
        ("expected_version", "1".to_string()),
        ("expected_post_id", one.id.clone()),
        ("return_to", "/library?status=published".to_string()),
        ("csrf_token", CSRF.to_string()),
    ]);
    let (status, stale_headers, stale_response) =
        call(&state, post_uri("/edit/one", &stale_editor, "alice")).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_private_no_store(&stale_headers);
    assert!(stale_response.contains("stale editor text survives"));
    assert!(stale_response.contains("return_to=%2Flibrary%3Fstatus%3Dpublished"));
    assert_eq!(
        state.store.get_post("one").await.unwrap().edit_version,
        2,
        "Library winner remains authoritative over the old editor"
    );

    let safe_return = "/library?status=published";
    let edit_uri = format!("/edit/one?return_to={}", encode(safe_return));
    let (_, edit_headers, editor) = call(&state, get(&edit_uri, "alice", None)).await;
    assert_private_no_store(&edit_headers);
    assert!(editor.contains(&format!(r#"name="return_to" value="{safe_return}""#)));
    assert!(editor.contains(&format!(r#"href="{safe_return}">Keep for later"#)));
    let current = state.store.get_post("one").await.unwrap();
    let update = form(&[
        ("title", "one".to_string()),
        ("body", "updated through native form".to_string()),
        ("expected_version", current.edit_version.to_string()),
        ("expected_post_id", current.id),
        ("return_to", safe_return.to_string()),
        ("csrf_token", CSRF.to_string()),
    ]);
    let (status, headers, _) = call(&state, post_uri("/edit/one", &update, "alice")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers.get(header::LOCATION).unwrap(), safe_return);

    // An external return target is ignored, never reflected into Location.
    let external = form(&[
        ("title", "one".to_string()),
        ("body", "second update".to_string()),
        (
            "expected_version",
            state
                .store
                .get_post("one")
                .await
                .unwrap()
                .edit_version
                .to_string(),
        ),
        (
            "expected_post_id",
            state.store.get_post("one").await.unwrap().id,
        ),
        ("return_to", "https://evil.example/".to_string()),
        ("csrf_token", CSRF.to_string()),
    ]);
    let (status, headers, _) = call(&state, post_uri("/edit/one", &external, "alice")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_ne!(
        headers.get(header::LOCATION).unwrap(),
        "https://evil.example/"
    );
}

async fn seed(state: &AppState, post: Post) {
    state.store.create_post(&post).await.unwrap();
}

fn fixture(
    slug: &str,
    owner: &str,
    published: bool,
    publish_at: i64,
    tags: &str,
    updated: i64,
) -> Post {
    Post {
        id: format!("post_{slug}"),
        slug: slug.to_string(),
        title: slug.to_string(),
        body_md: format!("body for {slug}"),
        author_sub: owner.to_string(),
        author_email: format!("{owner}@hf"),
        created_at: updated,
        updated_at: updated,
        edit_version: 1,
        published,
        publish_at,
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

async fn call(state: &AppState, request: Request<Body>) -> (StatusCode, HeaderMap, String) {
    let response = app(state.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, headers, String::from_utf8_lossy(&body).to_string())
}

fn get(uri: &str, sub: &str, groups: Option<&str>) -> Request<Body> {
    let mut request = Request::builder()
        .uri(uri)
        .header("x-auth-subject", sub)
        .header("x-auth-email", format!("{sub}@hf"));
    if let Some(groups) = groups {
        request = request.header("x-auth-groups", groups);
    }
    request.body(Body::empty()).unwrap()
}

fn post(body: &str, sub: &str) -> Request<Body> {
    post_uri("/library/posts/bulk", body, sub)
}

fn post_uri(uri: &str, body: &str, sub: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={CSRF}"))
        .header("x-auth-subject", sub)
        .header("x-auth-email", format!("{sub}@hf"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn selection(post: &Post, version: i64) -> String {
    format!("{}.{}", hex::encode(post.id.as_bytes()), version)
}

fn form(pairs: &[(&str, String)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                char::from(byte).to_string()
            }
            b' ' => "+".to_string(),
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

fn assert_private_no_store(headers: &HeaderMap) {
    assert_eq!(
        headers.get(header::CACHE_CONTROL).unwrap(),
        "private, no-store"
    );
}
