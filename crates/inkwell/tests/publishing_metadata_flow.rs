//! Publication Pack HTTP contracts: author fields, escaped/fallback head metadata, URL policy,
//! custom excerpts, and Draft/Scheduled no-leak behavior.

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use inkwell::{app, build_dev_state, now_secs, AppState};
use tower::ServiceExt;

const CSRF: &str = "publishing-metadata-csrf";

#[tokio::test]
async fn published_metadata_is_escaped_and_flows_to_cards_feed_and_sitemap_policy() {
    let state = build_dev_state();
    let body = form(&[
        ("title", "Metadata Story"),
        (
            "body",
            "body-only fallback phrase that should not lead the card",
        ),
        ("custom_excerpt", "The deliberate card and feed summary."),
        ("meta_title", "Search <title> & humans"),
        (
            "meta_description",
            "Search \"description\" <safe> & click-through context",
        ),
        ("canonical_url", "https://example.com/original?x=1&y=2"),
        ("social_title", "Social <launch> & context"),
        ("social_description", "Social <summary> & details"),
        ("social_image", "https://drive.w33d.xyz/s/social-card"),
        ("intent", "publish_now"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(&state, post("/new", &body)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (status, article) = call(&state, get("/p/metadata-story", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(article.contains("<title>Search &lt;title&gt; &amp; humans · Inkwell</title>"));
    assert!(article
        .contains(r#"<link rel="canonical" href="https://example.com/original?x=1&amp;y=2">"#));
    assert!(article.contains(
        r#"<meta name="description" content="Search &quot;description&quot; &lt;safe&gt; &amp; click-through context">"#
    ));
    assert!(article
        .contains(r#"<meta property="og:title" content="Social &lt;launch&gt; &amp; context">"#));
    assert!(article.contains(
        r#"<meta property="og:description" content="Social &lt;summary&gt; &amp; details">"#
    ));
    assert!(article
        .contains(r#"<meta property="og:image" content="https://drive.w33d.xyz/s/social-card">"#));
    assert!(article.contains(r#"<meta name="twitter:card" content="summary_large_image">"#));
    assert!(!article.contains("content=\"Social <launch>"));

    let (_, index) = call(&state, get("/", None)).await;
    assert!(index.contains("The deliberate card and feed summary."));
    assert!(!index.contains("body-only fallback phrase that should not lead the card"));

    let (_, feed) = call(&state, get("/feed.xml", None)).await;
    assert!(feed.contains("The deliberate card and feed summary."));

    let self_canonical = form(&[
        ("title", "Self Canonical Story"),
        ("body", "the canonical is the stable local Reader URL"),
        (
            "canonical_url",
            "https://blog.w33d.xyz/p/self-canonical-story",
        ),
        ("intent", "publish_now"),
        ("csrf_token", CSRF),
    ]);
    assert_eq!(
        call(&state, post("/new", &self_canonical)).await.0,
        StatusCode::SEE_OTHER
    );

    let (_, sitemap) = call(&state, get("/sitemap.xml", None)).await;
    assert!(
        !sitemap.contains("/p/metadata-story"),
        "an external canonical excludes the duplicate local URL from the sitemap"
    );
    assert!(
        sitemap.contains("/p/self-canonical-story"),
        "a self-canonical matches the local URL and remains in the sitemap"
    );
}

#[tokio::test]
async fn public_fallbacks_are_complete_while_private_states_emit_only_noindex() {
    let state = build_dev_state();
    let published = form(&[
        ("title", "Fallback Story"),
        ("body", "The body supplies the fallback description."),
        ("cover_url", "https://drive.w33d.xyz/s/fallback-cover"),
        ("intent", "publish_now"),
        ("csrf_token", CSRF),
    ]);
    assert_eq!(
        call(&state, post("/new", &published)).await.0,
        StatusCode::SEE_OTHER
    );

    let (_, article) = call(&state, get("/p/fallback-story", None)).await;
    assert!(
        article.contains(r#"<link rel="canonical" href="https://blog.w33d.xyz/p/fallback-story">"#)
    );
    assert!(article.contains(
        r#"<meta name="description" content="The body supplies the fallback description.">"#
    ));
    assert!(article.contains(r#"<meta property="og:title" content="Fallback Story">"#));
    assert!(article.contains(
        r#"<meta property="og:image" content="https://drive.w33d.xyz/s/fallback-cover">"#
    ));

    let excerpt_fallback = form(&[
        ("title", "Excerpt Fallback Story"),
        ("body", "Body text should lose to the explicit excerpt."),
        (
            "custom_excerpt",
            "The custom excerpt supplies descriptions.",
        ),
        ("meta_title", "Metadata Title Fallback"),
        ("intent", "publish_now"),
        ("csrf_token", CSRF),
    ]);
    assert_eq!(
        call(&state, post("/new", &excerpt_fallback)).await.0,
        StatusCode::SEE_OTHER
    );
    let (_, article) = call(&state, get("/p/excerpt-fallback-story", None)).await;
    assert!(article.contains("<title>Metadata Title Fallback · Inkwell</title>"));
    assert!(article.contains(
        r#"<meta name="description" content="The custom excerpt supplies descriptions.">"#
    ));
    assert!(article.contains(r#"<meta property="og:title" content="Metadata Title Fallback">"#));
    assert!(article.contains(
        r#"<meta property="og:description" content="The custom excerpt supplies descriptions.">"#
    ));

    let draft = form(&[
        ("title", "Private Metadata Draft"),
        ("body", "secret body"),
        ("meta_description", "secret metadata"),
        ("canonical_url", "https://example.com/secret-draft"),
        ("social_title", "secret social title"),
        ("intent", "save_draft"),
        ("csrf_token", CSRF),
    ]);
    assert_eq!(
        call(&state, post("/new", &draft)).await.0,
        StatusCode::SEE_OTHER
    );

    let scheduled_at = now_secs() + 3_600;
    let scheduled_epoch = scheduled_at.to_string();
    let scheduled = form(&[
        ("title", "Future Metadata Story"),
        ("body", "future secret body"),
        ("meta_description", "future secret metadata"),
        ("canonical_url", "https://example.com/future-secret"),
        ("publish_at_epoch", &scheduled_epoch),
        ("intent", "schedule"),
        ("csrf_token", CSRF),
    ]);
    assert_eq!(
        call(&state, post("/new", &scheduled)).await.0,
        StatusCode::SEE_OTHER
    );

    for slug in ["private-metadata-draft", "future-metadata-story"] {
        let (status, owner_page) = call(&state, get(&format!("/p/{slug}"), Some("u_writer"))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(owner_page.contains(r#"<meta name="robots" content="noindex,nofollow">"#));
        assert!(!owner_page.contains(r#"<link rel="canonical""#));
        assert!(!owner_page.contains(r#"<meta property="og:"#));
        assert!(!owner_page.contains(r#"<meta name="twitter:"#));

        let (status, _) = call(&state, get(&format!("/p/{slug}"), None)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    for surface in ["/", "/feed.xml", "/sitemap.xml", "/search?q=secret"] {
        let (_, page) = call(&state, get(surface, None)).await;
        assert!(!page.contains("Private Metadata Draft"));
        assert!(!page.contains("Future Metadata Story"));
        assert!(!page.contains("secret metadata"));
        assert!(!page.contains("future secret metadata"));
    }
}

#[tokio::test]
async fn writer_fields_are_no_js_and_server_limits_and_url_policies_win() {
    let state = build_dev_state();
    let (_, editor) = call(&state, get("/new", Some("u_writer"))).await;
    for contract in [
        r#"name="custom_excerpt" maxlength="500""#,
        r#"name="meta_title" maxlength="200""#,
        r#"name="meta_description" maxlength="500""#,
        r#"name="canonical_url" maxlength="2048""#,
        r#"name="social_title" maxlength="200""#,
        r#"name="social_description" maxlength="500""#,
        r#"name="social_image" maxlength="600""#,
    ] {
        assert!(
            editor.contains(contract),
            "missing no-JS field contract: {contract}"
        );
    }
    assert!(!editor.contains("{{"));

    let long_excerpt = "界".repeat(700);
    let long_title = "T".repeat(260);
    let long_description = "D".repeat(620);
    let long_social_title = "S".repeat(260);
    let long_social_description = "Q".repeat(620);
    let body = form(&[
        ("title", "Truncated Metadata"),
        ("body", "body"),
        ("custom_excerpt", &long_excerpt),
        ("meta_title", &long_title),
        ("meta_description", &long_description),
        ("social_title", &long_social_title),
        ("social_description", &long_social_description),
        ("intent", "save_draft"),
        ("csrf_token", CSRF),
    ]);
    assert_eq!(
        call(&state, post("/new", &body)).await.0,
        StatusCode::SEE_OTHER
    );
    let stored = state.store.get_post("truncated-metadata").await.unwrap();
    assert_eq!(stored.custom_excerpt.chars().count(), 500);
    assert_eq!(stored.meta_title.chars().count(), 200);
    assert_eq!(stored.meta_description.chars().count(), 500);
    assert_eq!(stored.social_title.chars().count(), 200);
    assert_eq!(stored.social_description.chars().count(), 500);

    let post_id = state.store.get_post("truncated-metadata").await.unwrap().id;
    let edit = form(&[
        ("title", "Truncated Metadata"),
        ("body", "updated body"),
        ("custom_excerpt", "Updated explicit excerpt"),
        ("meta_title", "Updated search title"),
        ("meta_description", "Updated search description"),
        ("canonical_url", "https://example.com/updated-source"),
        ("social_title", "Updated social title"),
        ("social_description", "Updated social description"),
        ("social_image", "https://drive.w33d.xyz/s/updated-social"),
        ("expected_version", "1"),
        ("expected_post_id", &post_id),
        ("csrf_token", CSRF),
    ]);
    assert_eq!(
        call(&state, post("/edit/truncated-metadata", &edit))
            .await
            .0,
        StatusCode::SEE_OTHER
    );
    let stored = state.store.get_post("truncated-metadata").await.unwrap();
    assert_eq!(stored.custom_excerpt, "Updated explicit excerpt");
    assert_eq!(stored.meta_title, "Updated search title");
    assert_eq!(stored.meta_description, "Updated search description");
    assert_eq!(stored.canonical_url, "https://example.com/updated-source");
    assert_eq!(stored.social_title, "Updated social title");
    assert_eq!(stored.social_description, "Updated social description");
    assert_eq!(
        stored.social_image,
        "https://drive.w33d.xyz/s/updated-social"
    );

    for canonical in [
        "javascript:alert(1)",
        "/relative/source",
        "https://writer@example.com/source",
    ] {
        let invalid = form(&[
            ("title", "Rejected Canonical"),
            ("canonical_url", canonical),
            ("intent", "save_draft"),
            ("csrf_token", CSRF),
        ]);
        assert_eq!(
            call(&state, post("/new", &invalid)).await.0,
            StatusCode::BAD_REQUEST
        );
    }

    let too_long_canonical = format!("https://example.com/{}", "a".repeat(2_100));
    let invalid = form(&[
        ("title", "Rejected Long Canonical"),
        ("canonical_url", &too_long_canonical),
        ("intent", "save_draft"),
        ("csrf_token", CSRF),
    ]);
    assert_eq!(
        call(&state, post("/new", &invalid)).await.0,
        StatusCode::BAD_REQUEST
    );

    let invalid_image = form(&[
        ("title", "Rejected Social Image"),
        ("social_image", "https://evil.example/card.jpg"),
        ("intent", "save_draft"),
        ("csrf_token", CSRF),
    ]);
    assert_eq!(
        call(&state, post("/new", &invalid_image)).await.0,
        StatusCode::BAD_REQUEST
    );

    let too_long_social_image = format!("https://drive.w33d.xyz/s/{}", "a".repeat(650));
    let invalid_image = form(&[
        ("title", "Rejected Long Social Image"),
        ("social_image", &too_long_social_image),
        ("intent", "save_draft"),
        ("csrf_token", CSRF),
    ]);
    assert_eq!(
        call(&state, post("/new", &invalid_image)).await.0,
        StatusCode::BAD_REQUEST
    );
}

async fn call(state: &AppState, request: Request<Body>) -> (StatusCode, String) {
    let response = app(state.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn get(uri: &str, subject: Option<&str>) -> Request<Body> {
    let mut request = Request::builder().uri(uri);
    if let Some(subject) = subject {
        request = request
            .header("x-auth-subject", subject)
            .header("x-auth-email", "writer@holdfast.local");
    }
    request.body(Body::empty()).unwrap()
}

fn post(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={CSRF}"))
        .header("x-auth-subject", "u_writer")
        .header("x-auth-email", "writer@holdfast.local")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn form(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn encode(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                output.push(byte as char)
            }
            b' ' => output.push('+'),
            _ => output.push_str(&format!("%{byte:02X}")),
        }
    }
    output
}
