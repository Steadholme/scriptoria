//! End-to-end HTTP flow over the in-memory store (NO database).
//!
//! Drives the real `app` router via `tower::oneshot`, exactly like the rest of the estate.
//! Covers: health, empty index, the SSO/CSRF guards on authoring, create/read/edit/delete,
//! ownership enforcement, draft visibility, and markdown XSS sanitization.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use inkwell::{app, build_dev_state, now_secs};
use tower::ServiceExt;

const CSRF: &str = "tok_csrf_for_tests";

#[tokio::test]
async fn full_blog_flow_in_memory() {
    let state = build_dev_state();

    // --- health ------------------------------------------------------------
    let (status, _) = call(&state, get("/healthz")).await;
    assert_eq!(status, StatusCode::OK);

    // --- empty index -------------------------------------------------------
    let (status, body) = call(&state, get("/")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("No posts yet"), "empty index placeholder");

    // --- GET /new sets a CSRF cookie ---------------------------------------
    let resp = app(state.clone()).oneshot(get("/new")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        set_cookie.contains("__Host-csrf="),
        "GET /new mints CSRF cookie"
    );

    // --- POST /new without identity -> 401 ---------------------------------
    let body = form(&[("title", "Nope"), ("body", "x"), ("csrf_token", CSRF)]);
    let (status, _) = call(&state, post_csrf("/new", &body, None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no X-Auth -> 401");

    // --- POST /new with bad CSRF -> 401 ------------------------------------
    let body = form(&[("title", "Nope"), ("body", "x"), ("csrf_token", "WRONG")]);
    let (status, _) = call(
        &state,
        post_csrf("/new", &body, Some(("u_alice", "alice@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "CSRF mismatch -> 401");

    // --- create a real post ------------------------------------------------
    let md = "# Heading\n\nSome **bold** body. <script>alert(1)</script> [x](javascript:alert(2))";
    let body = form(&[
        ("title", "Hello World"),
        ("body", md),
        ("published", "on"),
        ("csrf_token", CSRF),
    ]);
    let resp = app(state.clone())
        .oneshot(post_csrf("/new", &body, Some(("u_alice", "alice@hf"))))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    assert_eq!(location, "/p/hello-world", "slug derived from title");

    // --- index now lists it ------------------------------------------------
    let (_, body) = call(&state, get("/")).await;
    assert!(body.contains("Hello World"));
    assert!(body.contains("alice@hf"));

    // --- reading view renders sanitized markdown ---------------------------
    let (status, body) = call(&state, get("/p/hello-world")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("<strong>bold</strong>"), "markdown rendered");
    assert!(
        !body.contains("<script>alert(1)"),
        "raw script must be escaped"
    );
    assert!(
        body.contains("&lt;script&gt;"),
        "script shown as escaped text"
    );
    assert!(!body.contains("javascript:alert"), "js: link neutralized");

    // --- edit: wrong owner -> 403 ------------------------------------------
    let body = form(&[("title", "Hijack"), ("body", "x"), ("csrf_token", CSRF)]);
    let (status, _) = call(
        &state,
        post_csrf("/edit/hello-world", &body, Some(("u_mallory", "m@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "non-owner cannot edit");

    // --- edit: owner succeeds, slug stays stable ---------------------------
    let body = form(&[
        ("title", "Hello World (edited)"),
        ("body", "Updated body."),
        ("published", "on"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(
        &state,
        post_csrf("/edit/hello-world", &body, Some(("u_alice", "alice@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, body) = call(&state, get("/p/hello-world")).await;
    assert!(body.contains("Hello World (edited)"), "title updated");
    assert!(body.contains("Updated body."), "body updated");

    // --- delete: wrong owner -> 403 ----------------------------------------
    let body = form(&[("csrf_token", CSRF)]);
    let (status, _) = call(
        &state,
        post_csrf("/delete/hello-world", &body, Some(("u_mallory", "m@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "non-owner cannot delete");

    // --- delete: owner succeeds --------------------------------------------
    let body = form(&[("csrf_token", CSRF)]);
    let (status, _) = call(
        &state,
        post_csrf("/delete/hello-world", &body, Some(("u_alice", "alice@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (status, _) = call(&state, get("/p/hello-world")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "deleted post is gone");
}

#[tokio::test]
async fn drafts_are_private_to_their_author() {
    let state = build_dev_state();

    // Create an UNPUBLISHED post (omit the `published` checkbox field).
    let body = form(&[
        ("title", "Secret Draft"),
        ("body", "wip"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(
        &state,
        post_csrf("/new", &body, Some(("u_alice", "alice@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    // Anonymous viewer: not on the index, and the post 404s.
    let (_, idx) = call(&state, get("/")).await;
    assert!(
        !idx.contains("Secret Draft"),
        "draft hidden from anon index"
    );
    let (status, _) = call(&state, get("/p/secret-draft")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "draft 404 for anon");

    // The author sees it (with the Draft badge) and can read it.
    let (_, idx) = call(&state, get_auth("/", "u_alice", "alice@hf")).await;
    assert!(
        idx.contains("Secret Draft"),
        "author sees own draft on index"
    );
    assert!(idx.contains("Draft"), "draft badge shown to author");
    let (status, _) = call(&state, get_auth("/p/secret-draft", "u_alice", "alice@hf")).await;
    assert_eq!(status, StatusCode::OK, "author can read own draft");
}

#[tokio::test]
async fn scheduled_posts_are_public_only_after_publish_at() {
    let state = build_dev_state();
    let future = datetime_local(now_secs() + 3_600);

    let (status, form_html) = call(&state, get_auth("/new", "u_alice", "alice@hf")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        form_html.contains(r#"name="publish_at""#),
        "editor exposes publish_at field"
    );

    let body = form(&[
        ("title", "Scheduled Post"),
        ("body", "soon"),
        ("publish_at", &future),
        ("published", "on"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(
        &state,
        post_csrf("/new", &body, Some(("u_alice", "alice@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (_, idx) = call(&state, get("/")).await;
    assert!(
        !idx.contains("Scheduled Post"),
        "future scheduled post hidden from anon index"
    );
    let (status, _) = call(&state, get("/p/scheduled-post")).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "future scheduled post 404s for anon"
    );

    let (_, owner_idx) = call(&state, get_auth("/", "u_alice", "alice@hf")).await;
    assert!(
        owner_idx.contains("Scheduled Post"),
        "author sees own scheduled post"
    );
    assert!(
        owner_idx.contains("Scheduled"),
        "scheduled badge shown to author"
    );
    let (status, _) = call(&state, get_auth("/p/scheduled-post", "u_alice", "alice@hf")).await;
    assert_eq!(status, StatusCode::OK, "author can read own scheduled post");

    let body = form(&[
        ("title", "Scheduled Post"),
        ("body", "now public"),
        ("publish_at", ""),
        ("published", "on"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(
        &state,
        post_csrf("/edit/scheduled-post", &body, Some(("u_alice", "alice@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "author clears schedule");
    let (status, public) = call(&state, get("/p/scheduled-post")).await;
    assert_eq!(status, StatusCode::OK, "immediate publish is public");
    assert!(public.contains("now public"), "edited body visible");
}

#[tokio::test]
async fn author_can_pin_post_to_top_from_editor() {
    let state = build_dev_state();

    for title in ["Old Pinned", "New Ordinary"] {
        let body = form(&[
            ("title", title),
            ("body", "x"),
            ("published", "on"),
            ("csrf_token", CSRF),
        ]);
        let (status, _) = call(
            &state,
            post_csrf("/new", &body, Some(("u_alice", "alice@hf"))),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
    }

    let body = form(&[
        ("title", "Old Pinned"),
        ("body", "x"),
        ("published", "on"),
        ("pinned", "on"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(
        &state,
        post_csrf("/edit/old-pinned", &body, Some(("u_alice", "alice@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "author pins their post");

    let (_, idx) = call(&state, get("/")).await;
    let pinned_pos = idx.find("Old Pinned").expect("pinned post rendered");
    let ordinary_pos = idx.find("New Ordinary").expect("ordinary post rendered");
    assert!(
        pinned_pos < ordinary_pos,
        "pinned post floats above newer ordinary post"
    );
}

#[tokio::test]
async fn index_pages_backward_via_load_older() {
    let state = build_dev_state();

    // Three published posts. Created within the same second is fine — the keyset falls back to
    // id DESC (ids are nanosecond-distinct), so ordering and the cursor stay well defined.
    for title in ["Alpha", "Beta", "Gamma"] {
        let body = form(&[
            ("title", title),
            ("body", "x"),
            ("published", "on"),
            ("csrf_token", CSRF),
        ]);
        let (status, _) = call(
            &state,
            post_csrf("/new", &body, Some(("u_alice", "alice@hf"))),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
    }

    // First page of 2 -> the two newest + a "Load older" cursor (a full page implies more history).
    let (status, page1) = call(&state, get("/?limit=2")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page1.contains("Gamma"), "newest shown on first page");
    assert!(page1.contains("Beta"), "second-newest shown on first page");
    assert!(
        !page1.contains("Alpha"),
        "oldest NOT on the first page (beyond the page size)"
    );
    assert!(
        page1.contains("Load older"),
        "full page offers a Load-older cursor"
    );

    // Follow the generated cursor link: the oldest post is now REACHABLE (was unreachable before).
    let cursor = extract_before(&page1).expect("Load older link carries a ?before= cursor");
    let (status, page2) = call(&state, get(&format!("/?before={cursor}"))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page2.contains("Alpha"), "oldest reachable via Load older");
    assert!(
        !page2.contains("Gamma"),
        "cursor pages strictly older — newest not repeated"
    );
    assert!(
        !page2.contains("Beta"),
        "the cursor row itself is excluded (strictly older)"
    );
    assert!(
        !page2.contains("Load older"),
        "partial last page has no further cursor"
    );
}

#[tokio::test]
async fn cover_image_renders_on_card_and_article_and_rejects_foreign_host() {
    let state = build_dev_state();
    let cover = "https://drive.w33d.xyz/s/covertok";

    // Create a post with an estate cover URL + an inline estate <img> in the body.
    let md = r#"Body with <img src="https://drive.w33d.xyz/s/inline" alt="inline"> media."#;
    let body = form(&[
        ("title", "With Cover"),
        ("body", md),
        ("cover_url", cover),
        ("published", "on"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(
        &state,
        post_csrf("/new", &body, Some(("u_alice", "alice@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "create with cover succeeds");

    // The index card shows the cover image.
    let (_, idx) = call(&state, get("/")).await;
    assert!(
        idx.contains(r#"class="card-post__cover""#),
        "card renders the cover wrapper"
    );
    assert!(
        idx.contains(cover),
        "card cover points at the estate share URL"
    );

    // The article header shows the cover, and the inline estate <img> survives sanitization.
    let (status, article) = call(&state, get("/p/with-cover")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        article.contains(r#"class="article__cover""#),
        "article renders the cover wrapper"
    );
    assert!(
        article.contains(r#"<img src="https://drive.w33d.xyz/s/inline""#),
        "inline estate img survives sanitized markdown",
    );

    // A non-estate cover URL is rejected (fail-loud 400), never silently rendered.
    let body = form(&[
        ("title", "Bad Cover"),
        ("body", "x"),
        ("cover_url", "https://evil.example.com/x.png"),
        ("published", "on"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(
        &state,
        post_csrf("/new", &body, Some(("u_alice", "alice@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "non-estate cover rejected");
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Pull the `?before=<cursor>` value out of a rendered "Load older" link.
fn extract_before(html: &str) -> Option<String> {
    let marker = "?before=";
    let start = html.find(marker)? + marker.len();
    let rest = &html[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

async fn call(state: &inkwell::AppState, req: Request<Body>) -> (StatusCode, String) {
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

/// Build a urlencoded POST carrying the test CSRF cookie + (optionally) gateway identity.
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
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", k, enc(v)))
        .collect::<Vec<_>>()
        .join("&")
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
