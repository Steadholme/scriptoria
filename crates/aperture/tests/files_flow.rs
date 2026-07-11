//! End-to-end flow tests against the in-memory metadata store + in-memory blobs (NO database, NO
//! Cairn required).
//!
//! Drives the real `Router` in-process via `tower::oneshot`, exercising the full upload -> detail
//! -> raw -> share -> delete lifecycle, the double-submit CSRF guard, per-user ownership (403),
//! the public share-token fetch, image vs. download serving, and the size cap. This is the
//! default `cargo test` suite and stays DB-free.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use aperture::blobs::{BlobError, Blobs, MemoryBlobs};
use aperture::config::Config;
use aperture::model::UploadRequestRec;
use aperture::store::{
    InMemoryStore, Store, UploadRecoveryClaim, UploadReserve, UploadReserveInput,
};
use aperture::{app, build_dev_state, AppState};
use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use tower::ServiceExt;

const BOUNDARY: &str = "----apertureTESTboundary7MA4YWxkTrZu0gW";

struct FailingPutBlobs {
    deletes: Arc<AtomicUsize>,
    fail_delete: bool,
}

#[async_trait::async_trait]
impl Blobs for FailingPutBlobs {
    fn bucket(&self) -> &str {
        "failing"
    }

    async fn put(&self, _key: &str, _bytes: Vec<u8>) -> Result<(), BlobError> {
        Err(BlobError::Backend("injected put failure".to_string()))
    }

    async fn get(&self, _key: &str) -> Result<Vec<u8>, BlobError> {
        Err(BlobError::NotFound)
    }

    async fn get_range(
        &self,
        _key: &str,
        _start: u64,
        _end_inclusive: u64,
    ) -> Result<Vec<u8>, BlobError> {
        Err(BlobError::NotFound)
    }

    async fn delete(&self, _key: &str) -> Result<(), BlobError> {
        self.deletes.fetch_add(1, Ordering::SeqCst);
        if self.fail_delete {
            Err(BlobError::Backend(
                "injected compensation delete failure".to_string(),
            ))
        } else {
            Ok(())
        }
    }
}

/// Minimal byte payloads whose leading magic bytes drive the sniffer.
fn png_bytes() -> Vec<u8> {
    let mut v = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    v.extend_from_slice(b"\x00\x01\x02 fake png pixel data \xff\xee");
    v
}

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Resp {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }
    fn location(&self) -> String {
        self.headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    }
    fn header(&self, name: header::HeaderName) -> String {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    }
    fn csrf_cookie(&self) -> Option<String> {
        for hv in self.headers.get_all(header::SET_COOKIE).iter() {
            let raw = hv.to_str().ok()?;
            if let Some(rest) = raw.strip_prefix("__Host-csrf=") {
                return Some(rest.split(';').next().unwrap_or("").to_string());
            }
        }
        None
    }
}

async fn send(app: &axum::Router, req: Request<Body>) -> Resp {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    Resp {
        status,
        headers,
        body: bytes.to_vec(),
    }
}

fn get(path: &str, subject: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method("GET").uri(path);
    if let Some(s) = subject {
        b = b
            .header("x-auth-subject", s)
            .header("x-auth-email", format!("{s}@w33d.xyz"));
    }
    b.body(Body::empty()).unwrap()
}

fn get_with_cookie(path: &str, subject: Option<&str>, cookie: &str) -> Request<Body> {
    let mut request = get(path, subject);
    request.headers_mut().insert(
        header::COOKIE,
        format!("__Host-csrf={cookie}").parse().unwrap(),
    );
    request
}

fn get_range(path: &str, subject: Option<&str>, range: &str) -> Request<Body> {
    let mut b = Request::builder()
        .method("GET")
        .uri(path)
        .header(header::RANGE, range);
    if let Some(s) = subject {
        b = b
            .header("x-auth-subject", s)
            .header("x-auth-email", format!("{s}@w33d.xyz"));
    }
    b.body(Body::empty()).unwrap()
}

/// Build a `multipart/form-data` body carrying a `csrf_token` text field then a `file` field.
fn multipart(csrf: &str, filename: &str, content_type: &str, data: &[u8]) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"csrf_token\"\r\n\r\n");
    body.extend_from_slice(csrf.as_bytes());
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(format!("Content-Type: {content_type}\r\n\r\n").as_bytes());
    body.extend_from_slice(data);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    body
}

fn upload_req(
    csrf: &str,
    cookie: &str,
    subject: &str,
    filename: &str,
    ctype: &str,
    data: &[u8],
) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/upload")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .header(header::COOKIE, format!("__Host-csrf={cookie}"))
        .header("x-auth-subject", subject)
        .header("x-auth-email", format!("{subject}@w33d.xyz"))
        .body(Body::from(multipart(csrf, filename, ctype, data)))
        .unwrap()
}

/// A `multipart/form-data` upload body carrying a `csrf_token`, a `folder_id` (the target level),
/// then the `file` field — the gallery form's exact shape when uploading inside a folder.
fn multipart_folder(
    csrf: &str,
    folder: &str,
    filename: &str,
    content_type: &str,
    data: &[u8],
) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"csrf_token\"\r\n\r\n");
    body.extend_from_slice(csrf.as_bytes());
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"folder_id\"\r\n\r\n");
    body.extend_from_slice(folder.as_bytes());
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(format!("Content-Type: {content_type}\r\n\r\n").as_bytes());
    body.extend_from_slice(data);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    body
}

fn upload_req_folder(
    csrf: &str,
    cookie: &str,
    subject: &str,
    folder: &str,
    filename: &str,
    ctype: &str,
    data: &[u8],
) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/upload")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .header(header::COOKIE, format!("__Host-csrf={cookie}"))
        .header("x-auth-subject", subject)
        .header("x-auth-email", format!("{subject}@w33d.xyz"))
        .body(Body::from(multipart_folder(
            csrf, folder, filename, ctype, data,
        )))
        .unwrap()
}

fn public_upload_req(
    csrf: &str,
    cookie: &str,
    token: &str,
    filename: &str,
    ctype: &str,
    data: &[u8],
) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/u/{token}"))
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .header(header::COOKIE, format!("__Host-csrf={cookie}"))
        .body(Body::from(multipart(csrf, filename, ctype, data)))
        .unwrap()
}

/// A CSRF-cookie'd, SSO-identified `application/x-www-form-urlencoded` POST (share config / revoke).
fn post_form(uri: &str, cookie: &str, subject: &str, body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={cookie}"))
        .header("x-auth-subject", subject)
        .header("x-auth-email", format!("{subject}@w33d.xyz"))
        .body(Body::from(body))
        .unwrap()
}

/// An unauthenticated `application/x-www-form-urlencoded` POST (the public share-unlock form).
fn post_public(uri: &str, body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap()
}

/// Upload a PNG as `subject` and return its `/f/{id}` id plus the fresh CSRF token.
async fn upload_png(app: &axum::Router, subject: &str) -> (String, String) {
    upload_file(app, subject, "shot.png", "image/png", &png_bytes()).await
}

/// Upload an arbitrary file as `subject` and return its `/f/{id}` id plus the fresh CSRF token.
async fn upload_file(
    app: &axum::Router,
    subject: &str,
    filename: &str,
    ctype: &str,
    data: &[u8],
) -> (String, String) {
    let home = send(app, get("/", Some(subject))).await;
    let csrf = home.csrf_cookie().expect("csrf cookie");
    let created = send(
        app,
        upload_req(&csrf, &csrf, subject, filename, ctype, data),
    )
    .await;
    let id = created.location().trim_start_matches("/f/").to_string();
    (id, csrf)
}

/// Explicitly create a public read capability for a private-by-default upload.
async fn enable_file_share(
    app: &axum::Router,
    store: &Arc<dyn Store>,
    id: &str,
    subject: &str,
    csrf: &str,
) -> String {
    let response = send(
        app,
        post_form(
            &format!("/f/{id}/share"),
            csrf,
            subject,
            format!("csrf_token={csrf}&expiry=never"),
        ),
    )
    .await;
    assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());
    store.get(id).await.unwrap().unwrap().share_token.unwrap()
}

#[tokio::test]
async fn production_owner_routes_fail_closed_but_capabilities_remain_anonymous() {
    let mut state = build_dev_state();
    let mut config = (*state.config).clone();
    config.allow_dev_identity = false;
    state.config = Arc::new(config);
    let locked = app(state);

    // No gateway identity can no longer fall through to dev-user on an owner surface.
    assert_eq!(
        send(&locked, get("/", None)).await.status,
        StatusCode::UNAUTHORIZED
    );
    // A claimed identity is not trusted when the production guard has no HMAC verifier. This is
    // deliberately different from the unsigned dev seam.
    assert_eq!(
        send(&locked, get("/", Some("alice"))).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&locked, get("/healthz", None)).await.status,
        StatusCode::OK
    );

    // Existing capability namespaces stay anonymous and render the independent public error shell.
    for path in ["/s/not-a-token", "/u/not-a-token"] {
        let response = send(&locked, get(path, None)).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);
        let html = response.text();
        assert!(html.contains("data-ap-share-room"));
        assert!(html.contains("Share not found"));
        assert!(!html.contains("GENERATED FROM odyssey"));
    }

    // Strict-CSP Share Room assets are also anonymous, read-only routes.
    assert_eq!(
        send(&locked, get("/s/share-room.css", None)).await.status,
        StatusCode::OK
    );
    assert_eq!(
        send(&locked, get("/s/share-room.js", None)).await.status,
        StatusCode::OK
    );

    // Explicit dev state preserves the local/test fallback.
    assert_eq!(
        send(&app(build_dev_state()), get("/", None)).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn public_file_share_room_is_product_owned_and_escapes_remote_names() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);
    let (id, csrf) = upload_file(
        &app,
        "alice",
        "proof<svg onload=alert(1)>.png",
        "image/png",
        &png_bytes(),
    )
    .await;
    let token = enable_file_share(&app, &store, &id, "alice", &csrf).await;

    let page = send(&app, get(&format!("/s/{token}/view"), None)).await;
    assert_eq!(page.status, StatusCode::OK);
    let csp = page.header(header::CONTENT_SECURITY_POLICY);
    assert!(csp.contains("default-src 'none'"));
    assert!(csp.contains("style-src 'self'"));
    assert!(csp.contains("script-src 'self'"));
    assert!(csp.contains("connect-src 'self'"));
    assert!(csp.contains("frame-ancestors 'none'"));
    let html = page.text();
    assert!(html.contains("data-ap-share-room"));
    assert!(html.contains("PUBLIC SHARE ROOM"));
    assert!(html.contains("href=\"/s/share-room.css\""));
    assert!(html.contains("src=\"/s/share-room.js\""));
    assert!(!html.contains("href=\"/share-room.css\""));
    assert!(!html.contains("src=\"/share-room.js\""));
    assert!(!html.contains("<style>"));
    assert!(!html.contains("<script>"));
    assert!(html.contains("proof&lt;svg onload=alert(1)&gt;.png"));
    assert!(!html.contains("proof<svg onload=alert(1)>.png"));
    assert!(!html.contains("GENERATED FROM odyssey"));
    assert!(!html.contains("OdysseyWire"));
    assert!(!html.contains("OdysseySpark"));

    let css = send(&app, get("/s/share-room.css", None)).await;
    assert_eq!(css.status, StatusCode::OK);
    assert_eq!(css.header(header::CONTENT_TYPE), "text/css; charset=utf-8");
    assert!(css.text().contains("--ap-ink"));
    assert!(!css.text().contains("GENERATED FROM odyssey"));
    assert!(!css.text().contains("OdysseyWire"));

    let js = send(&app, get("/s/share-room.js", None)).await;
    assert_eq!(js.status, StatusCode::OK);
    assert_eq!(
        js.header(header::CONTENT_TYPE),
        "text/javascript; charset=utf-8"
    );
    assert!(js.text().contains("input.multiple = true"));
    assert!(js.text().contains("new XMLHttpRequest"));
    assert!(js.text().contains("Retry"));
    assert!(!js.text().contains(".style"));
    assert!(!js.text().contains("OdysseyWire"));
}

#[tokio::test]
async fn share_expiry_returns_410_after_expiry() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);
    let (id, csrf) = upload_png(&app, "alice").await;
    let token = enable_file_share(&app, &store, &id, "alice", &csrf).await;

    // Configure an expiry 1 hour out -> the public link still serves.
    let set = send(
        &app,
        post_form(
            &format!("/f/{id}/share"),
            &csrf,
            "alice",
            format!("csrf_token={csrf}&expiry=3600"),
        ),
    )
    .await;
    assert_eq!(set.status, StatusCode::FOUND);
    assert_eq!(
        send(&app, get(&format!("/s/{token}"), None)).await.status,
        StatusCode::OK
    );

    // Force the stored expiry into the past; the public fetch is now 410 Gone.
    store
        .configure_share(&id, "alice", Some(token.clone()), Some(1), None)
        .await
        .unwrap();
    let gone = send(&app, get(&format!("/s/{token}"), None)).await;
    assert_eq!(gone.status, StatusCode::GONE);
    assert!(gone.text().contains("data-ap-share-room"));
    assert!(gone.text().contains("Share expired"));
    assert!(!gone.text().contains("GENERATED FROM odyssey"));
    // The owner still reaches the file over SSO regardless of the share expiry.
    assert_eq!(
        send(&app, get(&format!("/f/{id}/raw"), Some("alice")))
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn share_password_prompts_then_serves() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);
    let (id, csrf) = upload_png(&app, "alice").await;
    let token = enable_file_share(&app, &store, &id, "alice", &csrf).await;

    // Set a password on the share link.
    let set = send(
        &app,
        post_form(
            &format!("/f/{id}/share"),
            &csrf,
            "alice",
            format!("csrf_token={csrf}&expiry=never&password=hunter2"),
        ),
    )
    .await;
    assert_eq!(set.status, StatusCode::FOUND);

    // A bare GET no longer serves the bytes — it renders a password prompt.
    let prompt = send(&app, get(&format!("/s/{token}"), None)).await;
    assert_eq!(prompt.status, StatusCode::OK);
    assert!(prompt.text().contains("Password required"));
    assert!(prompt.text().contains("Protected file"));
    assert!(prompt.text().contains("No expiry"));
    assert!(!prompt.text().contains("GENERATED FROM odyssey"));
    assert_ne!(prompt.body, png_bytes());

    // Wrong password -> 401 + prompt again.
    let wrong = send(
        &app,
        post_public(&format!("/s/{token}"), "password=nope".to_string()),
    )
    .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert!(wrong.text().contains("Incorrect password"));

    // Correct password -> the bytes.
    let ok = send(
        &app,
        post_public(&format!("/s/{token}"), "password=hunter2".to_string()),
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK);
    assert_eq!(ok.body, png_bytes());
}

#[tokio::test]
async fn share_landing_for_image_unfurls_and_counts_views() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);
    let (id, csrf) = upload_png(&app, "alice").await;
    let token = enable_file_share(&app, &store, &id, "alice", &csrf).await;

    let first = send(&app, get(&format!("/s/{token}/view"), None)).await;
    assert_eq!(first.status, StatusCode::OK);
    let first_html = first.text();
    assert!(first_html.contains("shot.png"));
    assert!(first_html.contains("og:image"));
    assert!(first_html.contains("twitter:card\" content=\"summary_large_image"));
    assert!(first_html.contains(&format!("content=\"https://drive.w33d.xyz/s/{token}\"")));
    assert!(first_html.contains(&format!("href=\"/s/{token}\"")));
    assert!(first_html.contains("Markdown"));
    assert!(first_html.contains("BBCode"));
    assert!(first_html.contains("1 views"));
    assert!(first_html.contains("Opened 1 times"));

    let second = send(&app, get(&format!("/s/{token}/view"), None)).await;
    assert_eq!(second.status, StatusCode::OK);
    assert!(second.text().contains("2 views"));
    assert_eq!(
        store
            .get_by_token(&token)
            .await
            .unwrap()
            .unwrap()
            .view_count,
        2
    );

    let direct = send(&app, get(&format!("/s/{token}"), None)).await;
    assert_eq!(direct.status, StatusCode::OK);
    assert_eq!(direct.body, png_bytes());
    assert_eq!(
        store
            .get_by_token(&token)
            .await
            .unwrap()
            .unwrap()
            .view_count,
        2
    );
}

#[tokio::test]
async fn share_landing_respects_expiry_and_password_privacy() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);
    let (id, csrf) = upload_png(&app, "alice").await;
    let token = enable_file_share(&app, &store, &id, "alice", &csrf).await;

    let set_password = send(
        &app,
        post_form(
            &format!("/f/{id}/share"),
            &csrf,
            "alice",
            format!("csrf_token={csrf}&expiry=never&password=hunter2"),
        ),
    )
    .await;
    assert_eq!(set_password.status, StatusCode::FOUND);

    let prompt = send(&app, get(&format!("/s/{token}/view"), None)).await;
    assert_eq!(prompt.status, StatusCode::OK);
    let prompt_html = prompt.text();
    assert!(prompt_html.contains("Password required"));
    assert!(prompt_html.contains(&format!("action=\"/s/{token}\"")));
    assert!(!prompt_html.contains("og:image"));
    assert!(!prompt_html.contains("Embed &amp; links"));
    assert_eq!(
        store
            .get_by_token(&token)
            .await
            .unwrap()
            .unwrap()
            .view_count,
        0
    );

    store
        .configure_share(&id, "alice", Some(token.clone()), Some(1), None)
        .await
        .unwrap();
    let gone = send(&app, get(&format!("/s/{token}/view"), None)).await;
    assert_eq!(gone.status, StatusCode::GONE);
}

#[tokio::test]
async fn share_landing_for_non_image_uses_summary_card_without_image_embeds() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);
    let home = send(&app, get("/", Some("alice"))).await;
    let csrf = home.csrf_cookie().expect("csrf cookie");
    let created = send(
        &app,
        upload_req(
            &csrf,
            &csrf,
            "alice",
            "note.txt",
            "text/plain",
            b"hello world",
        ),
    )
    .await;
    assert_eq!(created.status, StatusCode::FOUND);
    let id = created.location().trim_start_matches("/f/").to_string();
    let token = enable_file_share(&app, &store, &id, "alice", &csrf).await;

    let page = send(&app, get(&format!("/s/{token}/view"), None)).await;
    assert_eq!(page.status, StatusCode::OK);
    let html = page.text();
    assert!(html.contains("note.txt"));
    assert!(html.contains("twitter:card\" content=\"summary\""));
    assert!(!html.contains("og:image"));
    assert!(html.contains("Direct"));
    assert!(html.contains("Share page"));
    assert!(!html.contains("Markdown"));
    assert!(!html.contains("BBCode"));
}

#[tokio::test]
async fn share_revoke_clears_the_token() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);
    let (id, csrf) = upload_png(&app, "alice").await;
    let token = enable_file_share(&app, &store, &id, "alice", &csrf).await;

    // The link works before revoke.
    assert_eq!(
        send(&app, get(&format!("/s/{token}"), None)).await.status,
        StatusCode::OK
    );

    // Revoke -> 302, token cleared in the store, outstanding link now 404.
    let rev = send(
        &app,
        post_form(
            &format!("/f/{id}/revoke"),
            &csrf,
            "alice",
            format!("csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(rev.status, StatusCode::FOUND);
    assert!(store.get(&id).await.unwrap().unwrap().share_token.is_none());
    assert_eq!(
        send(&app, get(&format!("/s/{token}"), None)).await.status,
        StatusCode::NOT_FOUND
    );

    // The detail page now offers to create a new link; doing so mints a fresh, working token.
    let detail = send(&app, get(&format!("/f/{id}"), Some("alice"))).await;
    assert!(detail.text().contains("Create share link"));
    let csrf2 = detail.csrf_cookie().unwrap();
    send(
        &app,
        post_form(
            &format!("/f/{id}/share"),
            &csrf2,
            "alice",
            format!("csrf_token={csrf2}&expiry=never"),
        ),
    )
    .await;
    let new_token = store.get(&id).await.unwrap().unwrap().share_token.unwrap();
    assert_ne!(new_token, token);
    assert_eq!(
        send(&app, get(&format!("/s/{new_token}"), None))
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn share_config_requires_csrf() {
    let state = build_dev_state();
    let app = app(state);
    let (id, csrf) = upload_png(&app, "alice").await;
    // Wrong CSRF token field vs. cookie -> rejected.
    let bad = send(
        &app,
        post_form(
            &format!("/f/{id}/share"),
            &csrf,
            "alice",
            "csrf_token=wrong&expiry=3600".to_string(),
        ),
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn share_config_is_owner_scoped() {
    let state = build_dev_state();
    let app = app(state);
    let (id, _csrf) = upload_png(&app, "alice").await;
    // Bob cannot configure Alice's share link (403), even with his own valid CSRF.
    let bob_home = send(&app, get("/", Some("bob"))).await;
    let bob_csrf = bob_home.csrf_cookie().unwrap();
    let res = send(
        &app,
        post_form(
            &format!("/f/{id}/share"),
            &bob_csrf,
            "bob",
            format!("csrf_token={bob_csrf}&expiry=3600"),
        ),
    )
    .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn upload_detail_raw_share_delete_lifecycle() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let blobs: Arc<dyn Blobs> = state.blobs.clone();
    let app = app(state);

    // GET / mints a CSRF cookie; the dropzone embeds the same token.
    let home = send(&app, get("/", Some("alice"))).await;
    assert_eq!(home.status, StatusCode::OK);
    assert!(home.text().contains("ap-toolbar"));
    assert!(home.text().contains("My Drive"));
    assert!(!home.text().contains("Private files, folders and links"));
    assert!(home.text().contains("Your drive is empty"));
    let csrf = home.csrf_cookie().expect("csrf cookie on GET /");

    // POST /upload (a PNG) -> 302 /f/{id}.
    let png = png_bytes();
    let created = send(
        &app,
        upload_req(
            &csrf,
            &csrf,
            "alice",
            "screenshot.png",
            "application/octet-stream",
            &png,
        ),
    )
    .await;
    assert_eq!(created.status, StatusCode::FOUND, "{}", created.text());
    let loc = created.location();
    assert!(loc.starts_with("/f/"), "redirect to /f/, got {loc}");
    let id = loc.trim_start_matches("/f/").to_string();

    // The metadata row + blob both exist; the content type was sniffed to image/png.
    let rec = store.get(&id).await.unwrap().expect("metadata row");
    assert!(
        rec.share_token.is_none(),
        "fresh uploads are private until explicitly shared"
    );
    assert_eq!(rec.owner_sub, "alice");
    assert_eq!(rec.name, "screenshot.png");
    assert_eq!(rec.content_type, "image/png");
    assert_eq!(rec.size as usize, png.len());
    assert_eq!(blobs.get(&rec.object_key).await.unwrap(), png);

    // The private detail offers an explicit capability action; creating it enables `/s/{token}`.
    let private_detail = send(&app, get(&loc, Some("alice"))).await;
    assert!(private_detail.text().contains("Create share link"));
    let token = enable_file_share(&app, &store, &id, "alice", &csrf).await;
    let detail = send(&app, get(&loc, Some("alice"))).await;
    assert_eq!(detail.status, StatusCode::OK);
    assert!(detail.text().contains("screenshot.png"));
    assert!(detail.text().contains(&format!("/f/{id}/raw")));
    assert!(detail.text().contains(&format!("/s/{token}")));
    assert!(detail.text().contains("Embed &amp; links"));
    assert!(detail.text().contains(&format!("/s/{token}/view")));

    // GET /f/{id}/raw streams the bytes inline as image/png.
    let raw = send(&app, get(&format!("/f/{id}/raw"), Some("alice"))).await;
    assert_eq!(raw.status, StatusCode::OK);
    assert_eq!(raw.header(header::CONTENT_TYPE), "image/png");
    assert!(raw
        .header(header::CONTENT_DISPOSITION)
        .starts_with("inline"));
    assert_eq!(raw.header(header::X_CONTENT_TYPE_OPTIONS), "nosniff");
    assert_eq!(raw.body, png);

    // The gallery now lists the file.
    let home2 = send(&app, get("/", Some("alice"))).await;
    assert!(home2.text().contains("screenshot.png"));
    assert!(home2.text().contains("1 file"));

    // Public share fetch: NO auth headers, still returns the bytes.
    let shared = send(&app, get(&format!("/s/{token}"), None)).await;
    assert_eq!(shared.status, StatusCode::OK);
    assert_eq!(shared.body, png);

    // Delete it (CSRF-checked) -> 302 / ; metadata + blob remain in Trash.
    let csrf2 = detail.csrf_cookie().expect("csrf on detail page");
    let del = send(
        &app,
        post_form(
            &format!("/delete/{id}"),
            &csrf2,
            "alice",
            format!("csrf_token={csrf2}"),
        ),
    )
    .await;
    assert_eq!(del.status, StatusCode::FOUND);
    assert_eq!(del.location(), "/");
    let trashed = store
        .get(&id)
        .await
        .unwrap()
        .expect("metadata stays until purge");
    assert!(trashed.trashed_at > 0);
    assert_eq!(blobs.get(&rec.object_key).await.unwrap(), png);

    // Normal surfaces hide trashed files, and the public share link stops serving.
    let gone = send(&app, get(&loc, Some("alice"))).await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
    let hidden = send(&app, get("/", Some("alice"))).await;
    assert!(!hidden.text().contains("screenshot.png"));
    let trash = send(&app, get("/?view=trash", Some("alice"))).await;
    assert_eq!(trash.status, StatusCode::OK);
    assert!(trash.text().contains("screenshot.png"));
    assert!(trash.text().contains("Delete forever"));
    let share_gone = send(&app, get(&format!("/s/{token}"), None)).await;
    assert_eq!(share_gone.status, StatusCode::NOT_FOUND);

    // Delete forever purges metadata and blob.
    let purge = send(
        &app,
        post_form(
            &format!("/trash/{id}/purge"),
            &csrf2,
            "alice",
            format!("csrf_token={csrf2}"),
        ),
    )
    .await;
    assert_eq!(purge.status, StatusCode::FOUND);
    assert!(store.get(&id).await.unwrap().is_none());
    assert!(blobs.get(&rec.object_key).await.is_err());
}

#[tokio::test]
async fn ownership_is_enforced_with_403() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);

    let home = send(&app, get("/", Some("alice"))).await;
    let csrf = home.csrf_cookie().unwrap();
    let created = send(
        &app,
        upload_req(
            &csrf,
            &csrf,
            "alice",
            "secret.png",
            "image/png",
            &png_bytes(),
        ),
    )
    .await;
    let id = created.location().trim_start_matches("/f/").to_string();

    // Bob can neither view the detail page nor the raw bytes.
    let detail = send(&app, get(&format!("/f/{id}"), Some("bob"))).await;
    assert_eq!(detail.status, StatusCode::FORBIDDEN);
    let raw = send(&app, get(&format!("/f/{id}/raw"), Some("bob"))).await;
    assert_eq!(raw.status, StatusCode::FORBIDDEN);

    // Bob (with a valid CSRF for his own session) cannot delete Alice's file.
    let bob_home = send(&app, get("/", Some("bob"))).await;
    let bob_csrf = bob_home.csrf_cookie().unwrap();
    let del = send(
        &app,
        Request::builder()
            .method("POST")
            .uri(format!("/delete/{id}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, format!("__Host-csrf={bob_csrf}"))
            .header("x-auth-subject", "bob")
            .header("x-auth-email", "bob@w33d.xyz")
            .body(Body::from(format!("csrf_token={bob_csrf}")))
            .unwrap(),
    )
    .await;
    assert_eq!(del.status, StatusCode::FORBIDDEN);
    assert!(store.get(&id).await.unwrap().is_some(), "still there");
}

#[tokio::test]
async fn non_image_is_served_as_download() {
    let (app, _store, _blobs) = {
        let state = build_dev_state();
        (app(state.clone()), state.store.clone(), state.blobs.clone())
    };
    let home = send(&app, get("/", Some("alice"))).await;
    let csrf = home.csrf_cookie().unwrap();

    // A PDF-looking payload is NOT a sniffed raster image -> attachment + octet-stream.
    let created = send(
        &app,
        upload_req(
            &csrf,
            &csrf,
            "alice",
            "notes.pdf",
            "application/pdf",
            b"%PDF-1.7\n...content...",
        ),
    )
    .await;
    let id = created.location().trim_start_matches("/f/").to_string();

    let raw = send(&app, get(&format!("/f/{id}/raw"), Some("alice"))).await;
    assert_eq!(raw.status, StatusCode::OK);
    assert_eq!(raw.header(header::CONTENT_TYPE), "application/octet-stream");
    assert!(raw
        .header(header::CONTENT_DISPOSITION)
        .starts_with("attachment"));
    assert!(raw
        .header(header::CONTENT_DISPOSITION)
        .contains("notes.pdf"));
}

#[tokio::test]
async fn video_raw_supports_range_and_inline_playback() {
    let app = app(build_dev_state());
    let video = b"\x00\x00\x00\x18ftypmp42aperture-video".to_vec();
    let size = video.len();
    let (id, _) = upload_file(&app, "alice", "clip.mp4", "video/mp4", &video).await;

    let home = send(&app, get("/", Some("alice"))).await;
    assert!(home.text().contains("id=\"apPreview\""));
    assert!(home.text().contains("data-preview-body"));
    assert!(home.text().contains(&format!("data-preview-id=\"{id}\"")));
    assert!(home.text().contains("data-preview-kind=\"video\""));
    assert!(home.text().contains("thumb__play"));

    let full = send(&app, get(&format!("/f/{id}/raw"), Some("alice"))).await;
    assert_eq!(full.status, StatusCode::OK);
    assert_eq!(full.header(header::CONTENT_TYPE), "video/mp4");
    assert!(full
        .header(header::CONTENT_DISPOSITION)
        .starts_with("inline"));
    assert_eq!(full.header(header::X_CONTENT_TYPE_OPTIONS), "nosniff");
    assert_eq!(full.header(header::ACCEPT_RANGES), "bytes");
    assert_eq!(full.header(header::CONTENT_LENGTH), size.to_string());
    assert_eq!(full.body, video);

    let part = send(
        &app,
        get_range(&format!("/f/{id}/raw"), Some("alice"), "bytes=0-3"),
    )
    .await;
    assert_eq!(part.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        part.header(header::CONTENT_RANGE),
        format!("bytes 0-3/{size}")
    );
    assert_eq!(part.header(header::CONTENT_LENGTH), "4");
    assert_eq!(part.header(header::ACCEPT_RANGES), "bytes");
    assert_eq!(part.header(header::CONTENT_TYPE), "video/mp4");
    assert!(part
        .header(header::CONTENT_DISPOSITION)
        .starts_with("inline"));
    assert_eq!(part.header(header::X_CONTENT_TYPE_OPTIONS), "nosniff");
    assert_eq!(part.body, video[0..4].to_vec());

    let suffix = send(
        &app,
        get_range(&format!("/f/{id}/raw"), Some("alice"), "bytes=-2"),
    )
    .await;
    assert_eq!(suffix.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        suffix.header(header::CONTENT_RANGE),
        format!("bytes {}-{}/{size}", size - 2, size - 1)
    );
    assert_eq!(suffix.header(header::CONTENT_LENGTH), "2");
    assert_eq!(suffix.body, video[size - 2..].to_vec());

    let unsat = send(
        &app,
        get_range(
            &format!("/f/{id}/raw"),
            Some("alice"),
            &format!("bytes={size}-"),
        ),
    )
    .await;
    assert_eq!(unsat.status, StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        unsat.header(header::CONTENT_RANGE),
        format!("bytes */{size}")
    );
    assert_eq!(unsat.header(header::ACCEPT_RANGES), "bytes");
    assert_eq!(unsat.body, Vec::<u8>::new());
}

#[tokio::test]
async fn non_media_download_supports_range_without_inline() {
    let app = app(build_dev_state());
    let zip = b"PK\x03\x04aperture-zip-bytes".to_vec();
    let size = zip.len();
    let (id, _) = upload_file(&app, "alice", "archive.zip", "application/zip", &zip).await;

    let part = send(
        &app,
        get_range(&format!("/f/{id}/raw"), Some("alice"), "bytes=1-4"),
    )
    .await;
    assert_eq!(part.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        part.header(header::CONTENT_TYPE),
        "application/octet-stream"
    );
    assert!(part
        .header(header::CONTENT_DISPOSITION)
        .starts_with("attachment"));
    assert!(part
        .header(header::CONTENT_DISPOSITION)
        .contains("archive.zip"));
    assert_eq!(
        part.header(header::CONTENT_RANGE),
        format!("bytes 1-4/{size}")
    );
    assert_eq!(part.header(header::CONTENT_LENGTH), "4");
    assert_eq!(part.header(header::ACCEPT_RANGES), "bytes");
    assert_eq!(part.header(header::X_CONTENT_TYPE_OPTIONS), "nosniff");
    assert_eq!(part.body, zip[1..5].to_vec());
}

#[tokio::test]
async fn video_share_supports_range_after_public_gates() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);
    let video = b"\x00\x00\x00\x18ftypmp42shared-video".to_vec();
    let size = video.len();
    let (id, csrf) = upload_file(&app, "alice", "shared.mp4", "video/mp4", &video).await;
    let token = enable_file_share(&app, &store, &id, "alice", &csrf).await;

    let part = send(&app, get_range(&format!("/s/{token}"), None, "bytes=2-5")).await;
    assert_eq!(part.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(part.header(header::CONTENT_TYPE), "video/mp4");
    assert!(part
        .header(header::CONTENT_DISPOSITION)
        .starts_with("inline"));
    assert_eq!(part.header(header::X_CONTENT_TYPE_OPTIONS), "nosniff");
    assert_eq!(part.header(header::ACCEPT_RANGES), "bytes");
    assert_eq!(
        part.header(header::CONTENT_RANGE),
        format!("bytes 2-5/{size}")
    );
    assert_eq!(part.header(header::CONTENT_LENGTH), "4");
    assert_eq!(part.body, video[2..6].to_vec());

    let set_password = send(
        &app,
        post_form(
            &format!("/f/{id}/share"),
            &csrf,
            "alice",
            format!("csrf_token={csrf}&expiry=never&password=hunter2"),
        ),
    )
    .await;
    assert_eq!(set_password.status, StatusCode::FOUND);

    let protected = send(&app, get_range(&format!("/s/{token}"), None, "bytes=0-3")).await;
    assert_eq!(protected.status, StatusCode::OK);
    assert!(protected.text().contains("Password required"));
    assert_ne!(protected.body, video[0..4].to_vec());

    let wrong = send(
        &app,
        post_public(&format!("/s/{token}"), "password=nope".to_string()),
    )
    .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert!(wrong.text().contains("Incorrect password"));

    store
        .configure_share(&id, "alice", Some(token.clone()), Some(1), None)
        .await
        .unwrap();
    let gone = send(&app, get_range(&format!("/s/{token}"), None, "bytes=0-3")).await;
    assert_eq!(gone.status, StatusCode::GONE);
}

#[tokio::test]
async fn csrf_is_required_on_upload() {
    let app = app(build_dev_state());
    // No matching cookie -> rejected before anything is stored.
    let bad = send(
        &app,
        upload_req(
            "totally-wrong",
            "the-cookie-value",
            "alice",
            "x.png",
            "image/png",
            &png_bytes(),
        ),
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn oversized_upload_is_rejected() {
    // Custom state with a tiny cap so the application-level size guard fires.
    let mut cfg = Config::dev();
    cfg.max_upload = 16;
    let state = AppState {
        config: Arc::new(cfg),
        store: Arc::new(InMemoryStore::new()),
        blobs: Arc::new(MemoryBlobs::new()),
        audit: aperture::audit::AuditSink::disabled(),
    };
    let app = app(state);

    let home = send(&app, get("/", Some("alice"))).await;
    let csrf = home.csrf_cookie().unwrap();
    let big = vec![b'a'; 64];
    let res = send(
        &app,
        upload_req(
            &csrf,
            &csrf,
            "alice",
            "big.bin",
            "application/octet-stream",
            &big,
        ),
    )
    .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert!(res.text().contains("too large"));
}

#[tokio::test]
async fn empty_upload_is_rejected() {
    let app = app(build_dev_state());
    let home = send(&app, get("/", Some("alice"))).await;
    let csrf = home.csrf_cookie().unwrap();
    let res = send(
        &app,
        upload_req(
            &csrf,
            &csrf,
            "alice",
            "empty.bin",
            "application/octet-stream",
            b"",
        ),
    )
    .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert!(res.text().contains("Choose a file"));
}

/// Collect the distinct file ids referenced by `href="/f/{id}"` gallery-card anchors.
fn card_ids(html: &str) -> Vec<String> {
    let mut ids = Vec::new();
    for part in html.split("href=\"/f/").skip(1) {
        let id: String = part.chars().take_while(|&c| c != '"' && c != '/').collect();
        if !id.is_empty() && !ids.contains(&id) {
            ids.push(id);
        }
    }
    ids
}

/// Extract the `?before=<cursor>` value from the "Load older" pager link, if present.
fn extract_before(html: &str) -> Option<String> {
    let idx = html.find("?before=")?;
    let rest = &html[idx + "?before=".len()..];
    let val: String = rest.chars().take_while(|&c| c != '"').collect();
    (!val.is_empty()).then_some(val)
}

#[tokio::test]
async fn gallery_paginates_backward_with_before_cursor() {
    let app = app(build_dev_state());
    let home = send(&app, get("/", Some("alice"))).await;
    let csrf = home.csrf_cookie().unwrap();

    // Three files for alice.
    for n in ["one.png", "two.png", "three.png"] {
        let up = send(
            &app,
            upload_req(&csrf, &csrf, "alice", n, "image/png", &png_bytes()),
        )
        .await;
        assert_eq!(up.status, StatusCode::FOUND, "{}", up.text());
    }

    // First page, capped to 2 -> two cards + a "Load older" link.
    let p1 = send(&app, get("/?limit=2", Some("alice"))).await;
    assert_eq!(p1.status, StatusCode::OK);
    let p1_ids = card_ids(&p1.text());
    assert_eq!(p1_ids.len(), 2, "a full page shows exactly the page size");
    let before = extract_before(&p1.text()).expect("Load older link on a full page");

    // Follow the cursor -> the remaining file, and NO further pager (partial page).
    let p2 = send(
        &app,
        get(&format!("/?limit=2&before={before}"), Some("alice")),
    )
    .await;
    assert_eq!(p2.status, StatusCode::OK);
    let p2_ids = card_ids(&p2.text());
    assert_eq!(p2_ids.len(), 1, "the second page holds the remainder");
    assert!(
        extract_before(&p2.text()).is_none(),
        "no pager on a non-full page"
    );

    // The two pages are disjoint and together cover all three distinct files.
    let mut all = p1_ids;
    all.extend(p2_ids);
    all.sort();
    all.dedup();
    assert_eq!(all.len(), 3, "pages are disjoint and cover every file");

    // Backward compatible: the default view (no ?before, no ?limit) still returns the newest page.
    let def = send(&app, get("/", Some("alice"))).await;
    assert_eq!(def.status, StatusCode::OK);
    assert_eq!(
        card_ids(&def.text()).len(),
        3,
        "default page shows all files under the cap"
    );
    assert!(
        extract_before(&def.text()).is_none(),
        "no pager when everything fits"
    );
}

/// Extract the folder id from a `302 /?folder={id}` create/rename redirect Location.
fn folder_from_location(loc: &str) -> String {
    loc.trim_start_matches("/?folder=").to_string()
}

async fn create_upload_request(
    app: &axum::Router,
    store: &Arc<dyn Store>,
    folder_id: &str,
    csrf: &str,
    extra: &str,
) -> UploadRequestRec {
    let body = format!(
        "csrf_token={csrf}&title=Evidence+intake&description=Send+the+requested+evidence&expiry=604800{extra}"
    );
    let response = send(
        app,
        post_form(
            &format!("/folders/{folder_id}/requests"),
            csrf,
            "alice",
            body,
        ),
    )
    .await;
    assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());
    let id = response
        .location()
        .trim_start_matches("/requests/")
        .to_string();
    store
        .get_upload_request(&id, "alice")
        .await
        .unwrap()
        .expect("created upload request")
}

#[tokio::test]
async fn folder_create_move_filter_and_delete_lifecycle() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);

    // Two files for alice.
    let (id_a, csrf) = upload_png(&app, "alice").await;
    let up_b = send(
        &app,
        upload_req(&csrf, &csrf, "alice", "b.png", "image/png", &png_bytes()),
    )
    .await;
    let id_b = up_b.location().trim_start_matches("/f/").to_string();

    // Create a folder -> 302 /?folder={fid}.
    let made = send(
        &app,
        post_form(
            "/folders",
            &csrf,
            "alice",
            format!("csrf_token={csrf}&name=Trips"),
        ),
    )
    .await;
    assert_eq!(made.status, StatusCode::FOUND);
    let fid = folder_from_location(&made.location());
    assert!(store.get_folder(&fid, "alice").await.unwrap().is_some());

    // The sidebar shows the folder on the gallery, and the folder view starts empty.
    let home = send(&app, get("/", Some("alice"))).await;
    assert!(home.text().contains("Trips"));
    assert!(home.text().contains(&format!("/?folder={fid}")));
    let folder_view = send(&app, get(&format!("/?folder={fid}"), Some("alice"))).await;
    assert_eq!(folder_view.status, StatusCode::OK);
    assert_eq!(
        card_ids(&folder_view.text()).len(),
        0,
        "new folder is empty"
    );

    // Move file A into the folder (CSRF-checked) -> 302 /f/{id_a}.
    let moved = send(
        &app,
        post_form(
            &format!("/f/{id_a}/move"),
            &csrf,
            "alice",
            format!("csrf_token={csrf}&folder_id={fid}"),
        ),
    )
    .await;
    assert_eq!(moved.status, StatusCode::FOUND);
    assert_eq!(
        store
            .get(&id_a)
            .await
            .unwrap()
            .unwrap()
            .folder_id
            .as_deref(),
        Some(fid.as_str())
    );

    // The folder view now lists only A; the ROOT view now lists only B (A left the root — a tree).
    let fv = send(&app, get(&format!("/?folder={fid}"), Some("alice"))).await;
    assert_eq!(card_ids(&fv.text()), vec![id_a.clone()]);
    // The folder view breadcrumb names the folder.
    assert!(fv.text().contains("breadcrumb"));
    let flat = send(&app, get("/", Some("alice"))).await;
    assert_eq!(
        card_ids(&flat.text()),
        vec![id_b.clone()],
        "root shows only unfiled files"
    );

    // Rename the folder.
    let renamed = send(
        &app,
        post_form(
            &format!("/folders/{fid}/rename"),
            &csrf,
            "alice",
            format!("csrf_token={csrf}&name=Vacations"),
        ),
    )
    .await;
    assert_eq!(renamed.status, StatusCode::FOUND);
    assert_eq!(
        store.get_folder(&fid, "alice").await.unwrap().unwrap().name,
        "Vacations"
    );

    // Deleting a NON-empty folder (A is inside) is refused (400) — empty-only unless cascading.
    let refused = send(
        &app,
        post_form(
            &format!("/folders/{fid}/delete"),
            &csrf,
            "alice",
            format!("csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert!(
        store.get_folder(&fid, "alice").await.unwrap().is_some(),
        "refused delete kept the folder"
    );

    // Move A back to the root, then the now-empty folder deletes -> 302 to its parent (root).
    send(
        &app,
        post_form(
            &format!("/f/{id_a}/move"),
            &csrf,
            "alice",
            format!("csrf_token={csrf}&folder_id="),
        ),
    )
    .await;
    let deleted = send(
        &app,
        post_form(
            &format!("/folders/{fid}/delete"),
            &csrf,
            "alice",
            format!("csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(deleted.status, StatusCode::FOUND);
    assert_eq!(deleted.location(), "/");
    assert!(store.get_folder(&fid, "alice").await.unwrap().is_none());
    assert!(
        store.get(&id_a).await.unwrap().unwrap().folder_id.is_none(),
        "file kept at root"
    );
}

#[tokio::test]
async fn folder_actions_are_owner_scoped_and_csrf_checked() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);

    // Alice owns a folder and a file.
    let (id_a, csrf) = upload_png(&app, "alice").await;
    let made = send(
        &app,
        post_form(
            "/folders",
            &csrf,
            "alice",
            format!("csrf_token={csrf}&name=Private"),
        ),
    )
    .await;
    let fid = folder_from_location(&made.location());

    // Wrong CSRF is rejected on folder create.
    let bad_csrf = send(
        &app,
        post_form(
            "/folders",
            &csrf,
            "alice",
            "csrf_token=wrong&name=X".to_string(),
        ),
    )
    .await;
    assert_eq!(bad_csrf.status, StatusCode::BAD_REQUEST);

    // A blank name is rejected.
    let blank = send(
        &app,
        post_form(
            "/folders",
            &csrf,
            "alice",
            format!("csrf_token={csrf}&name=%20"),
        ),
    )
    .await;
    assert_eq!(blank.status, StatusCode::BAD_REQUEST);

    // Bob (own valid CSRF) cannot rename or delete Alice's folder (404 — not his).
    let bob_home = send(&app, get("/", Some("bob"))).await;
    let bob_csrf = bob_home.csrf_cookie().unwrap();
    let bob_rename = send(
        &app,
        post_form(
            &format!("/folders/{fid}/rename"),
            &bob_csrf,
            "bob",
            format!("csrf_token={bob_csrf}&name=Hax"),
        ),
    )
    .await;
    assert_eq!(bob_rename.status, StatusCode::NOT_FOUND);
    assert_eq!(
        store.get_folder(&fid, "alice").await.unwrap().unwrap().name,
        "Private"
    );

    // Moving a file into a folder the actor does not own is a 404 (and leaves the file unfiled).
    let bob_up = send(
        &app,
        upload_req(
            &bob_csrf,
            &bob_csrf,
            "bob",
            "b.png",
            "image/png",
            &png_bytes(),
        ),
    )
    .await;
    let bob_file = bob_up.location().trim_start_matches("/f/").to_string();
    let cross = send(
        &app,
        post_form(
            &format!("/f/{bob_file}/move"),
            &bob_csrf,
            "bob",
            format!("csrf_token={bob_csrf}&folder_id={fid}"),
        ),
    )
    .await;
    assert_eq!(cross.status, StatusCode::NOT_FOUND);
    assert!(store
        .get(&bob_file)
        .await
        .unwrap()
        .unwrap()
        .folder_id
        .is_none());

    // Alice can move her file back to root with a blank target.
    send(
        &app,
        post_form(
            &format!("/f/{id_a}/move"),
            &csrf,
            "alice",
            format!("csrf_token={csrf}&folder_id={fid}"),
        ),
    )
    .await;
    let to_root = send(
        &app,
        post_form(
            &format!("/f/{id_a}/move"),
            &csrf,
            "alice",
            format!("csrf_token={csrf}&folder_id="),
        ),
    )
    .await;
    assert_eq!(to_root.status, StatusCode::FOUND);
    assert!(store.get(&id_a).await.unwrap().unwrap().folder_id.is_none());
}

#[tokio::test]
async fn filename_xss_is_escaped_on_render() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);
    let home = send(&app, get("/", Some("alice"))).await;
    let csrf = home.csrf_cookie().unwrap();

    let created = send(
        &app,
        upload_req(
            &csrf,
            &csrf,
            "alice",
            "<img src=x onerror=alert(1)>.png",
            "image/png",
            &png_bytes(),
        ),
    )
    .await;
    let id = created.location().trim_start_matches("/f/").to_string();
    let _ = store.get(&id).await.unwrap().unwrap();

    let detail = send(&app, get(&format!("/f/{id}"), Some("alice"))).await;
    assert_eq!(detail.status, StatusCode::OK);
    assert!(!detail.text().contains("<img src=x onerror=alert(1)>"));
    assert!(detail.text().contains("&lt;img src=x"));
}

#[tokio::test]
async fn trash_restore_and_purge_lifecycle() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let blobs: Arc<dyn Blobs> = state.blobs.clone();
    let app = app(state);
    let (id, csrf) = upload_png(&app, "alice").await;
    let token = enable_file_share(&app, &store, &id, "alice", &csrf).await;
    let rec = store.get(&id).await.unwrap().unwrap();

    let del = send(
        &app,
        post_form(
            &format!("/delete/{id}"),
            &csrf,
            "alice",
            format!("csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(del.status, StatusCode::FOUND);
    assert!(store.get(&id).await.unwrap().unwrap().trashed_at > 0);
    assert_eq!(store.usage_for_owner("alice").await.unwrap(), rec.size);
    assert!(send(&app, get("/", Some("alice")))
        .await
        .text()
        .contains("No files yet"));
    assert_eq!(
        send(&app, get(&format!("/s/{token}"), None)).await.status,
        StatusCode::NOT_FOUND
    );

    let restore = send(
        &app,
        post_form(
            &format!("/trash/{id}/restore"),
            &csrf,
            "alice",
            format!("csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(restore.status, StatusCode::FOUND);
    assert_eq!(store.get(&id).await.unwrap().unwrap().trashed_at, 0);
    assert_eq!(
        send(&app, get(&format!("/f/{id}"), Some("alice")))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        send(&app, get(&format!("/s/{token}"), None)).await.status,
        StatusCode::OK
    );

    send(
        &app,
        post_form(
            &format!("/delete/{id}"),
            &csrf,
            "alice",
            format!("csrf_token={csrf}"),
        ),
    )
    .await;
    let purge = send(
        &app,
        post_form(
            &format!("/trash/{id}/purge"),
            &csrf,
            "alice",
            format!("csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(purge.status, StatusCode::FOUND);
    assert!(store.get(&id).await.unwrap().is_none());
    assert!(blobs.get(&rec.object_key).await.is_err());
    assert_eq!(store.usage_for_owner("alice").await.unwrap(), 0);
}

#[tokio::test]
async fn file_comments_are_escaped_and_owner_or_admin_delete() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);
    let (id, csrf) = upload_png(&app, "alice").await;

    let add = send(
        &app,
        post_form(
            &format!("/f/{id}/comments"),
            &csrf,
            "alice",
            format!("csrf_token={csrf}&body=%3Cscript%3Ealert(1)%3C%2Fscript%3E%0Ahello"),
        ),
    )
    .await;
    assert_eq!(add.status, StatusCode::FOUND);
    let detail = send(&app, get(&format!("/f/{id}"), Some("alice"))).await;
    assert!(detail
        .text()
        .contains("&lt;script&gt;alert(1)&lt;/script&gt;<br>hello"));
    assert!(!detail.text().contains("<script>alert(1)</script>"));

    let comment = store.list_comments(&id).await.unwrap().pop().unwrap();
    let admin_panel = send(&app, get_with_groups("/admin", "root", "admins")).await;
    let admin_csrf = admin_panel.csrf_cookie().unwrap();
    let deleted = send(
        &app,
        post_form_with_groups(
            &format!("/f/{id}/comments/{}/delete", comment.id),
            &admin_csrf,
            "root",
            "admins",
            format!("csrf_token={admin_csrf}"),
        ),
    )
    .await;
    assert_eq!(deleted.status, StatusCode::FOUND);
    assert!(store.list_comments(&id).await.unwrap().is_empty());
}

/// Upload a non-image file as `subject`, returning its `/f/{id}` id plus the CSRF token.
async fn upload_pdf(app: &axum::Router, subject: &str) -> (String, String) {
    let home = send(app, get("/", Some(subject))).await;
    let csrf = home.csrf_cookie().expect("csrf cookie");
    let created = send(
        app,
        upload_req(
            &csrf,
            &csrf,
            subject,
            "notes.pdf",
            "application/pdf",
            b"%PDF-1.7\n...content...",
        ),
    )
    .await;
    assert_eq!(created.status, StatusCode::FOUND, "{}", created.text());
    let id = created.location().trim_start_matches("/f/").to_string();
    (id, csrf)
}

#[tokio::test]
async fn thumb_redirects_image_to_full_bytes() {
    let state = build_dev_state();
    let blobs: Arc<dyn Blobs> = state.blobs.clone();
    let app = app(state);
    let (id, _csrf) = upload_png(&app, "alice").await;

    // A raster image cannot be downscaled without a decoder dep -> 302 to the full /f/{id}/raw.
    let thumb = send(&app, get(&format!("/d/{id}/thumb"), Some("alice"))).await;
    assert_eq!(thumb.status, StatusCode::FOUND);
    assert_eq!(thumb.location(), format!("/f/{id}/raw"));
    // The image path caches NO derived blob (nothing was generated).
    assert!(blobs.get(&format!("{id}.thumb")).await.is_err());
}

#[tokio::test]
async fn thumb_serves_and_caches_svg_type_icon_for_non_image() {
    let state = build_dev_state();
    let blobs: Arc<dyn Blobs> = state.blobs.clone();
    let app = app(state);
    let (id, _csrf) = upload_pdf(&app, "alice").await;

    // No derived blob exists until the thumbnail is first requested (lazy derivation).
    assert!(blobs.get(&format!("{id}.thumb")).await.is_err());

    let thumb = send(&app, get(&format!("/d/{id}/thumb"), Some("alice"))).await;
    assert_eq!(thumb.status, StatusCode::OK);
    assert_eq!(thumb.header(header::CONTENT_TYPE), "image/svg+xml");
    assert_eq!(thumb.header(header::X_CONTENT_TYPE_OPTIONS), "nosniff");
    assert!(thumb
        .header(header::CONTENT_SECURITY_POLICY)
        .contains("default-src 'none'"));
    let body = thumb.text();
    assert!(body.starts_with("<svg"));
    assert!(
        body.contains(">PDF<"),
        "type icon bakes the uppercase extension label"
    );

    // The derived thumbnail is now cached as a `{id}.thumb` blob, and re-requesting serves it again.
    assert_eq!(
        blobs.get(&format!("{id}.thumb")).await.unwrap(),
        body.as_bytes()
    );
    let again = send(&app, get(&format!("/d/{id}/thumb"), Some("alice"))).await;
    assert_eq!(again.status, StatusCode::OK);
    assert_eq!(again.text(), body, "cached thumbnail is deterministic");
}

#[tokio::test]
async fn thumb_is_owner_scoped() {
    let app = app(build_dev_state());
    let (id, _csrf) = upload_pdf(&app, "alice").await;

    // Bob cannot fetch Alice's thumbnail (403), exactly like /f/{id}/raw.
    let bob = send(&app, get(&format!("/d/{id}/thumb"), Some("bob"))).await;
    assert_eq!(bob.status, StatusCode::FORBIDDEN);
    // A missing id is a 404.
    let missing = send(&app, get("/d/doesnotxx/thumb", Some("alice"))).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn gallery_grid_points_at_the_thumb_route() {
    let app = app(build_dev_state());
    let (id, _csrf) = upload_png(&app, "alice").await;
    let home = send(&app, get("/", Some("alice"))).await;
    assert_eq!(home.status, StatusCode::OK);
    // Every card's <img> loads through the derived-thumbnail route (not /f/{id}/raw directly).
    assert!(home.text().contains(&format!("src=\"/d/{id}/thumb\"")));
}

// ---------------------------------------------------------------------------
// Storage quotas + the /admin panel
// ---------------------------------------------------------------------------

/// State with a custom default quota (in-memory metadata + blobs, audit off) — mirrors the
/// oversized-upload test's custom-config idiom.
fn quota_state(default_quota_bytes: i64) -> AppState {
    let mut cfg = Config::dev();
    cfg.default_quota_bytes = default_quota_bytes;
    AppState {
        config: Arc::new(cfg),
        store: Arc::new(InMemoryStore::new()),
        blobs: Arc::new(MemoryBlobs::new()),
        audit: aperture::audit::AuditSink::disabled(),
    }
}

/// A GET carrying an SSO identity AND the gateway groups header (the admin path).
fn get_with_groups(path: &str, subject: &str, groups: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .header("x-auth-subject", subject)
        .header("x-auth-email", format!("{subject}@w33d.xyz"))
        .header("x-auth-groups", groups)
        .body(Body::empty())
        .unwrap()
}

/// A CSRF-cookie'd form POST carrying an SSO identity AND the gateway groups header.
fn post_form_with_groups(
    uri: &str,
    cookie: &str,
    subject: &str,
    groups: &str,
    body: String,
) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={cookie}"))
        .header("x-auth-subject", subject)
        .header("x-auth-email", format!("{subject}@w33d.xyz"))
        .header("x-auth-groups", groups)
        .body(Body::from(body))
        .unwrap()
}

#[tokio::test]
async fn quota_allows_exactly_at_boundary_and_rejects_over() {
    let png = png_bytes();
    // The default quota is EXACTLY one PNG of room.
    let state = quota_state(png.len() as i64);
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);
    let home = send(&app, get("/", Some("alice"))).await;
    let csrf = home.csrf_cookie().unwrap();

    // used(0) + size == quota -> allowed (exactly at the boundary).
    let first = send(
        &app,
        upload_req(&csrf, &csrf, "alice", "a.png", "image/png", &png),
    )
    .await;
    assert_eq!(first.status, StatusCode::FOUND, "{}", first.text());

    // used(quota) + size > quota -> 413, rejected BEFORE anything is stored.
    let second = send(
        &app,
        upload_req(&csrf, &csrf, "alice", "b.png", "image/png", &png),
    )
    .await;
    assert_eq!(second.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(second.text().contains("Not enough storage"));
    assert_eq!(
        store
            .list_by_owner("alice", None, None, 50)
            .await
            .unwrap()
            .len(),
        1
    );

    // Quotas are per-owner: bob still has his own full quota.
    let bob_home = send(&app, get("/", Some("bob"))).await;
    let bob_csrf = bob_home.csrf_cookie().unwrap();
    let bob = send(
        &app,
        upload_req(&bob_csrf, &bob_csrf, "bob", "c.png", "image/png", &png),
    )
    .await;
    assert_eq!(bob.status, StatusCode::FOUND);
}

#[tokio::test]
async fn quota_override_beats_default() {
    let png = png_bytes();
    // A 1-byte default rejects every upload...
    let state = quota_state(1);
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);
    let home = send(&app, get("/", Some("alice"))).await;
    let csrf = home.csrf_cookie().unwrap();
    let capped = send(
        &app,
        upload_req(&csrf, &csrf, "alice", "a.png", "image/png", &png),
    )
    .await;
    assert_eq!(capped.status, StatusCode::PAYLOAD_TOO_LARGE);

    // ...an override row lifts alice above it...
    store
        .set_quota("alice", Some(10 * png.len() as i64))
        .await
        .unwrap();
    let lifted = send(
        &app,
        upload_req(&csrf, &csrf, "alice", "a.png", "image/png", &png),
    )
    .await;
    assert_eq!(lifted.status, StatusCode::FOUND, "{}", lifted.text());

    // ...clearing it drops her back to the default...
    store.set_quota("alice", None).await.unwrap();
    let back = send(
        &app,
        upload_req(&csrf, &csrf, "alice", "b.png", "image/png", &png),
    )
    .await;
    assert_eq!(back.status, StatusCode::PAYLOAD_TOO_LARGE);

    // ...and an explicit 0 override means unlimited.
    store.set_quota("alice", Some(0)).await.unwrap();
    let unlimited = send(
        &app,
        upload_req(&csrf, &csrf, "alice", "c.png", "image/png", &png),
    )
    .await;
    assert_eq!(unlimited.status, StatusCode::FOUND);
}

#[tokio::test]
async fn gallery_shows_usage_meter() {
    // Unlimited (the dev default): the used total only — no fill bar, no percent. (The class
    // names always appear inside the inlined <style>, so assert on the DOM markers instead.)
    let app_unlimited = app(build_dev_state());
    let (_id, _csrf) = upload_png(&app_unlimited, "alice").await;
    let home = send(&app_unlimited, get("/", Some("alice"))).await;
    assert!(home.text().contains("no limit"));
    assert!(
        !home.text().contains("style=\"width:"),
        "no fill bar without a quota"
    );

    // Under a quota: used / quota with a percent and the width-scaled fill bar.
    let png = png_bytes();
    let app_limited = app(quota_state(2 * png.len() as i64));
    let (_id2, _csrf2) = upload_png(&app_limited, "alice").await;
    let home2 = send(&app_limited, get("/", Some("alice"))).await;
    assert!(home2.text().contains("style=\"width:50.00%\""));
    assert!(
        home2.text().contains("(50%)"),
        "one of two PNGs of quota is 50%"
    );
}

#[tokio::test]
async fn admin_panel_is_group_gated() {
    let app = app(build_dev_state());
    // No groups at all, and non-admin groups, both get the branded 403.
    let plain = send(&app, get("/admin", Some("alice"))).await;
    assert_eq!(plain.status, StatusCode::FORBIDDEN);
    let wrong = send(&app, get_with_groups("/admin", "alice", "readers,writers")).await;
    assert_eq!(wrong.status, StatusCode::FORBIDDEN);
    // Membership in an admin group unlocks the usage table.
    let ok = send(&app, get_with_groups("/admin", "root", "admins")).await;
    assert_eq!(ok.status, StatusCode::OK);
    assert!(ok.text().contains("Storage usage by owner"));
}

#[tokio::test]
async fn admin_set_quota_form_guards_and_applies() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);
    // Alice stores one file so the usage table has a row.
    let (_id, _csrf) = upload_png(&app, "alice").await;

    let panel = send(&app, get_with_groups("/admin", "root", "infra-admins")).await;
    assert_eq!(panel.status, StatusCode::OK);
    assert!(
        panel.text().contains("alice"),
        "usage table lists the owner"
    );
    let csrf = panel.csrf_cookie().unwrap();

    // A non-admin cannot POST, even with a valid CSRF pair.
    let outsider = send(
        &app,
        post_form(
            "/admin/quota",
            &csrf,
            "alice",
            format!("csrf_token={csrf}&owner_sub=alice&quota_bytes=1"),
        ),
    )
    .await;
    assert_eq!(outsider.status, StatusCode::FORBIDDEN);
    // A wrong CSRF field is rejected.
    let bad_csrf = send(
        &app,
        post_form_with_groups(
            "/admin/quota",
            &csrf,
            "root",
            "admins",
            "csrf_token=wrong&owner_sub=alice&quota_bytes=1".to_string(),
        ),
    )
    .await;
    assert_eq!(bad_csrf.status, StatusCode::BAD_REQUEST);
    // Non-numeric bytes and a blank owner are rejected.
    let garbage = send(
        &app,
        post_form_with_groups(
            "/admin/quota",
            &csrf,
            "root",
            "admins",
            format!("csrf_token={csrf}&owner_sub=alice&quota_bytes=lots"),
        ),
    )
    .await;
    assert_eq!(garbage.status, StatusCode::BAD_REQUEST);
    let no_owner = send(
        &app,
        post_form_with_groups(
            "/admin/quota",
            &csrf,
            "root",
            "admins",
            format!("csrf_token={csrf}&owner_sub=&quota_bytes=1"),
        ),
    )
    .await;
    assert_eq!(no_owner.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        store.get_quota("alice").await.unwrap(),
        None,
        "guarded posts changed nothing"
    );

    // A valid admin POST sets the override and redirects back to the panel...
    let set = send(
        &app,
        post_form_with_groups(
            "/admin/quota",
            &csrf,
            "root",
            "admins",
            format!("csrf_token={csrf}&owner_sub=alice&quota_bytes=4096"),
        ),
    )
    .await;
    assert_eq!(set.status, StatusCode::FOUND);
    assert_eq!(set.location(), "/admin");
    assert_eq!(store.get_quota("alice").await.unwrap(), Some(4096));
    // ...which now shows the override...
    let panel2 = send(&app, get_with_groups("/admin", "root", "admins")).await;
    assert!(panel2.text().contains("4.0 KB"));
    assert!(panel2.text().contains("(override)"));
    // ...and a BLANK value clears it back to the default.
    let clear = send(
        &app,
        post_form_with_groups(
            "/admin/quota",
            &csrf,
            "root",
            "admins",
            format!("csrf_token={csrf}&owner_sub=alice&quota_bytes="),
        ),
    )
    .await;
    assert_eq!(clear.status, StatusCode::FOUND);
    assert_eq!(store.get_quota("alice").await.unwrap(), None);
}

#[tokio::test]
async fn thumb_derived_blob_is_removed_on_delete() {
    let state = build_dev_state();
    let blobs: Arc<dyn Blobs> = state.blobs.clone();
    let app = app(state);
    let (id, csrf) = upload_pdf(&app, "alice").await;

    // Prime the derived-thumbnail cache, then trash and purge the file.
    send(&app, get(&format!("/d/{id}/thumb"), Some("alice"))).await;
    assert!(
        blobs.get(&format!("{id}.thumb")).await.is_ok(),
        "thumbnail cached"
    );
    let del = send(
        &app,
        post_form(
            &format!("/delete/{id}"),
            &csrf,
            "alice",
            format!("csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(del.status, StatusCode::FOUND);
    assert!(
        blobs.get(&format!("{id}.thumb")).await.is_ok(),
        "soft delete keeps cached data until purge"
    );
    let purge = send(
        &app,
        post_form(
            &format!("/trash/{id}/purge"),
            &csrf,
            "alice",
            format!("csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(purge.status, StatusCode::FOUND);
    // Delete forever removes the derived thumbnail too (no orphan).
    assert!(
        blobs.get(&format!("{id}.thumb")).await.is_err(),
        "derived thumbnail removed on purge"
    );
}

// ---------------------------------------------------------------------------
// Folder TREE navigation + scoped upload
// ---------------------------------------------------------------------------

/// A second PNG whose bytes differ from `png_bytes()` (still a valid PNG magic) so a re-upload
/// produces a distinguishable new current blob.
fn png_bytes_alt() -> Vec<u8> {
    let mut v = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    v.extend_from_slice(b"\x00\x09\x08 SECOND revision pixels \xaa\xbb\xcc");
    v
}

#[tokio::test]
async fn folder_tree_subfolders_breadcrumb_and_scoped_upload() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);
    let (_root_file, csrf) = upload_png(&app, "alice").await; // a file at the ROOT

    // Create a root folder, then a CHILD folder inside it (parent_id carried by the form).
    let parent = send(
        &app,
        post_form(
            "/folders",
            &csrf,
            "alice",
            format!("csrf_token={csrf}&name=Parent&parent_id="),
        ),
    )
    .await;
    let pfid = folder_from_location(&parent.location());
    let child = send(
        &app,
        post_form(
            "/folders",
            &csrf,
            "alice",
            format!("csrf_token={csrf}&name=Child&parent_id={pfid}"),
        ),
    )
    .await;
    assert_eq!(child.status, StatusCode::FOUND);
    let cfid = folder_from_location(&child.location());
    assert_eq!(
        store
            .get_folder(&cfid, "alice")
            .await
            .unwrap()
            .unwrap()
            .parent_id
            .as_deref(),
        Some(pfid.as_str())
    );

    // Root view: shows the Parent tile but NOT the (nested) Child.
    let root = send(&app, get("/", Some("alice"))).await;
    assert!(
        root.text().contains(&format!("/?folder={pfid}")),
        "root lists the parent folder"
    );
    assert!(
        !root.text().contains(&format!("/?folder={cfid}")),
        "root does not list a nested child"
    );

    // Parent view: breadcrumb back to My Drive, the Child tile, and an Up-to-root tile.
    let pv = send(&app, get(&format!("/?folder={pfid}"), Some("alice"))).await;
    assert!(pv.text().contains("breadcrumb"));
    assert!(
        pv.text().contains(">My Drive<"),
        "breadcrumb links back to root"
    );
    assert!(
        pv.text().contains(&format!("/?folder={cfid}")),
        "child folder tile is shown"
    );
    assert!(
        pv.text().contains("Up one level"),
        "an Up tile is shown inside a folder"
    );

    // Upload a file INTO the child folder; it appears there, not at the root or in the parent.
    let up = send(
        &app,
        upload_req_folder(
            &csrf,
            &csrf,
            "alice",
            &cfid,
            "deep.png",
            "image/png",
            &png_bytes(),
        ),
    )
    .await;
    assert_eq!(up.status, StatusCode::FOUND, "{}", up.text());
    let deep_id = up.location().trim_start_matches("/f/").to_string();
    assert_eq!(
        store
            .get(&deep_id)
            .await
            .unwrap()
            .unwrap()
            .folder_id
            .as_deref(),
        Some(cfid.as_str())
    );
    let cv = send(&app, get(&format!("/?folder={cfid}"), Some("alice"))).await;
    assert_eq!(card_ids(&cv.text()), vec![deep_id.clone()]);
    let root2 = send(&app, get("/", Some("alice"))).await;
    assert!(
        !card_ids(&root2.text()).contains(&deep_id),
        "a filed file never shows at the root"
    );
}

#[tokio::test]
async fn folder_delete_cascade_removes_subtree_and_blobs() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let blobs: Arc<dyn Blobs> = state.blobs.clone();
    let app = app(state);
    let (_f, csrf) = upload_png(&app, "alice").await;

    let parent = send(
        &app,
        post_form(
            "/folders",
            &csrf,
            "alice",
            format!("csrf_token={csrf}&name=Parent&parent_id="),
        ),
    )
    .await;
    let pfid = folder_from_location(&parent.location());
    let child = send(
        &app,
        post_form(
            "/folders",
            &csrf,
            "alice",
            format!("csrf_token={csrf}&name=Child&parent_id={pfid}"),
        ),
    )
    .await;
    let cfid = folder_from_location(&child.location());
    // A file deep in the subtree.
    let up = send(
        &app,
        upload_req_folder(
            &csrf,
            &csrf,
            "alice",
            &cfid,
            "deep.png",
            "image/png",
            &png_bytes(),
        ),
    )
    .await;
    let deep_id = up.location().trim_start_matches("/f/").to_string();
    let deep_key = store.get(&deep_id).await.unwrap().unwrap().object_key;
    assert!(blobs.get(&deep_key).await.is_ok());

    // Cascade-delete the parent -> whole subtree + the file (blob) are gone, redirect to root.
    let del = send(
        &app,
        post_form(
            &format!("/folders/{pfid}/delete"),
            &csrf,
            "alice",
            format!("csrf_token={csrf}&cascade=1"),
        ),
    )
    .await;
    assert_eq!(del.status, StatusCode::FOUND);
    assert_eq!(del.location(), "/");
    assert!(store.get_folder(&pfid, "alice").await.unwrap().is_none());
    assert!(store.get_folder(&cfid, "alice").await.unwrap().is_none());
    assert!(
        store.get(&deep_id).await.unwrap().is_none(),
        "the nested file is deleted"
    );
    assert!(blobs.get(&deep_key).await.is_err(), "its blob is freed");
}

// ---------------------------------------------------------------------------
// Versions: re-upload keeps a version; restore + prune + quota accounting
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reupload_keeps_version_then_restore_swaps_current() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);
    let (id, csrf) = upload_png(&app, "alice").await; // "shot.png", bytes = png_bytes()

    // No versions yet.
    let d0 = send(&app, get(&format!("/f/{id}"), Some("alice"))).await;
    assert!(d0.text().contains("No earlier versions"));

    // Re-upload the SAME name at the root with DIFFERENT bytes -> same id, one retained version.
    let re = send(
        &app,
        upload_req(
            &csrf,
            &csrf,
            "alice",
            "shot.png",
            "image/png",
            &png_bytes_alt(),
        ),
    )
    .await;
    assert_eq!(re.status, StatusCode::FOUND, "{}", re.text());
    assert_eq!(
        re.location(),
        format!("/f/{id}"),
        "re-upload versions the SAME file (no new id)"
    );
    let versions = store.list_versions(&id).await.unwrap();
    assert_eq!(versions.len(), 1, "the prior blob is retained as a version");
    // Current serves the NEW bytes; the version holds the ORIGINAL bytes.
    assert_eq!(
        send(&app, get(&format!("/f/{id}/raw"), Some("alice")))
            .await
            .body,
        png_bytes_alt()
    );
    let vid = versions[0].id.clone();
    let vdl = send(
        &app,
        get(&format!("/f/{id}/versions/{vid}/raw"), Some("alice")),
    )
    .await;
    assert_eq!(vdl.status, StatusCode::OK);
    assert_eq!(
        vdl.body,
        png_bytes(),
        "the version download is the original blob"
    );
    assert!(vdl
        .header(header::CONTENT_DISPOSITION)
        .starts_with("attachment"));

    // The detail page lists the version with download + restore controls.
    let d1 = send(&app, get(&format!("/f/{id}"), Some("alice"))).await;
    assert!(d1.text().contains(&format!("/f/{id}/versions/{vid}/raw")));
    assert!(d1.text().contains("Restore"));

    // Restore the version -> current swaps back to the original bytes; history is kept (still 1).
    let rest = send(
        &app,
        post_form(
            &format!("/f/{id}/versions/{vid}/restore"),
            &csrf,
            "alice",
            format!("csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(rest.status, StatusCode::FOUND);
    assert_eq!(
        send(&app, get(&format!("/f/{id}/raw"), Some("alice")))
            .await
            .body,
        png_bytes(),
        "restored to the original"
    );
    assert_eq!(
        store.list_versions(&id).await.unwrap().len(),
        1,
        "restore keeps history (old current becomes a version)"
    );
}

#[tokio::test]
async fn versions_are_pruned_to_the_cap() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);
    let (id, csrf) = upload_png(&app, "alice").await;

    // Re-upload the same name 12 times -> history is capped at the newest 10.
    for _ in 0..12 {
        let re = send(
            &app,
            upload_req(
                &csrf,
                &csrf,
                "alice",
                "shot.png",
                "image/png",
                &png_bytes_alt(),
            ),
        )
        .await;
        assert_eq!(re.status, StatusCode::FOUND, "{}", re.text());
    }
    assert_eq!(
        store.list_versions(&id).await.unwrap().len(),
        10,
        "oldest versions are pruned to the cap"
    );
}

#[tokio::test]
async fn version_bytes_count_toward_quota() {
    let png = png_bytes();
    // Quota = exactly two PNGs of room.
    let state = quota_state(2 * png.len() as i64);
    let app = app(state);
    let home = send(&app, get("/", Some("alice"))).await;
    let csrf = home.csrf_cookie().unwrap();

    // First upload (1 PNG). Re-upload same name: old blob becomes a version (1 PNG) + new (1 PNG) =
    // exactly the quota -> allowed at the boundary. (Same-size bytes keep the boundary exact.)
    assert_eq!(
        send(
            &app,
            upload_req(&csrf, &csrf, "alice", "shot.png", "image/png", &png)
        )
        .await
        .status,
        StatusCode::FOUND
    );
    let re1 = send(
        &app,
        upload_req(&csrf, &csrf, "alice", "shot.png", "image/png", &png),
    )
    .await;
    assert_eq!(re1.status, StatusCode::FOUND, "{}", re1.text());

    // A THIRD copy would push usage (current + version) over the quota -> 413. Proves versions count.
    let re2 = send(
        &app,
        upload_req(&csrf, &csrf, "alice", "shot.png", "image/png", &png),
    )
    .await;
    assert_eq!(re2.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(re2.text().contains("Not enough storage"));
}

// ---------------------------------------------------------------------------
// Folder share: public index + expiry/password/revoke gates
// ---------------------------------------------------------------------------

#[tokio::test]
async fn folder_share_public_index_and_gates() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);
    let (root_id, csrf) = upload_png(&app, "alice").await; // a file OUTSIDE the shared folder

    // Folder with one file inside it.
    let mk = send(
        &app,
        post_form(
            "/folders",
            &csrf,
            "alice",
            format!("csrf_token={csrf}&name=Album&parent_id="),
        ),
    )
    .await;
    let fid = folder_from_location(&mk.location());
    let up = send(
        &app,
        upload_req_folder(
            &csrf,
            &csrf,
            "alice",
            &fid,
            "pic.png",
            "image/png",
            &png_bytes(),
        ),
    )
    .await;
    let inid = up.location().trim_start_matches("/f/").to_string();

    // Create a folder share link (no password, never expires) via the owner form.
    let sh = send(
        &app,
        post_form(
            &format!("/folders/{fid}/share"),
            &csrf,
            "alice",
            format!("csrf_token={csrf}&expiry=never"),
        ),
    )
    .await;
    assert_eq!(sh.status, StatusCode::FOUND);
    let token = store
        .get_folder(&fid, "alice")
        .await
        .unwrap()
        .unwrap()
        .share_token
        .unwrap();

    // Public index (NO auth) lists the folder's file + a download link.
    let idx = send(&app, get(&format!("/s/folder/{token}"), None)).await;
    assert_eq!(idx.status, StatusCode::OK);
    let idx_html = idx.text();
    assert!(idx_html.contains("pic.png"));
    assert!(idx_html.contains(&format!("/s/folder/{token}/f/{inid}")));
    assert!(idx_html.contains("data-ap-share-room"));
    assert!(idx_html.contains("data-share-preview="));
    assert!(!idx_html.contains("GENERATED FROM odyssey"));
    // Public download returns the bytes.
    let dl = send(&app, get(&format!("/s/folder/{token}/f/{inid}"), None)).await;
    assert_eq!(dl.status, StatusCode::OK);
    assert_eq!(dl.body, png_bytes());
    // The token cannot fetch a file that is NOT in the shared folder (the root file) -> 404.
    let cross = send(&app, get(&format!("/s/folder/{token}/f/{root_id}"), None)).await;
    assert_eq!(cross.status, StatusCode::NOT_FOUND);

    // Force the expiry into the past -> the public index is 410 Gone.
    store
        .configure_folder_share(&fid, "alice", Some(token.clone()), Some(1), None)
        .await
        .unwrap();
    assert_eq!(
        send(&app, get(&format!("/s/folder/{token}"), None))
            .await
            .status,
        StatusCode::GONE
    );

    // Revoke -> the outstanding link is 404.
    let rev = send(
        &app,
        post_form(
            &format!("/folders/{fid}/revoke"),
            &csrf,
            "alice",
            format!("csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(rev.status, StatusCode::FOUND);
    assert_eq!(
        send(&app, get(&format!("/s/folder/{token}"), None))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn folder_share_password_gate() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);
    let (_r, csrf) = upload_png(&app, "alice").await;

    let mk = send(
        &app,
        post_form(
            "/folders",
            &csrf,
            "alice",
            format!("csrf_token={csrf}&name=Locked&parent_id="),
        ),
    )
    .await;
    let fid = folder_from_location(&mk.location());
    let up = send(
        &app,
        upload_req_folder(
            &csrf,
            &csrf,
            "alice",
            &fid,
            "secret.png",
            "image/png",
            &png_bytes(),
        ),
    )
    .await;
    let inid = up.location().trim_start_matches("/f/").to_string();

    // Share WITH a password.
    send(
        &app,
        post_form(
            &format!("/folders/{fid}/share"),
            &csrf,
            "alice",
            format!("csrf_token={csrf}&expiry=never&password=hunter2"),
        ),
    )
    .await;
    let token = store
        .get_folder(&fid, "alice")
        .await
        .unwrap()
        .unwrap()
        .share_token
        .unwrap();

    // Bare GET prompts for the password and does NOT reveal the file list.
    let prompt = send(&app, get(&format!("/s/folder/{token}"), None)).await;
    assert_eq!(prompt.status, StatusCode::OK);
    assert!(prompt.text().contains("Password required"));
    assert!(!prompt.text().contains("secret.png"));
    assert!(!prompt.text().contains("GENERATED FROM odyssey"));
    // A direct GET download on a protected folder is refused (401), not served.
    let locked = send(&app, get(&format!("/s/folder/{token}/f/{inid}"), None)).await;
    assert_eq!(locked.status, StatusCode::UNAUTHORIZED);

    // Wrong password -> 401 + prompt again.
    let wrong = send(
        &app,
        post_public(&format!("/s/folder/{token}"), "password=nope".to_string()),
    )
    .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert!(wrong.text().contains("Incorrect password"));

    // Correct password -> the index with per-file POST download forms carrying the password.
    let ok = send(
        &app,
        post_public(
            &format!("/s/folder/{token}"),
            "password=hunter2".to_string(),
        ),
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK);
    assert!(ok.text().contains("secret.png"));
    assert!(ok.text().contains("Password verified"));
    assert!(
        !ok.text().contains("data-share-preview="),
        "protected folder keeps preview POST-gated"
    );
    assert!(ok
        .text()
        .contains(&format!("action=\"/s/folder/{token}/f/{inid}\"")));
    // Download via POST with the correct password serves the bytes.
    let dl = send(
        &app,
        post_public(
            &format!("/s/folder/{token}/f/{inid}"),
            "password=hunter2".to_string(),
        ),
    )
    .await;
    assert_eq!(dl.status, StatusCode::OK);
    assert_eq!(dl.body, png_bytes());
    // Wrong password on the download POST -> 401.
    let dlw = send(
        &app,
        post_public(
            &format!("/s/folder/{token}/f/{inid}"),
            "password=nope".to_string(),
        ),
    )
    .await;
    assert_eq!(dlw.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn public_upload_inbox_accepts_uploads_without_listing_files() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);
    let (_root, csrf) = upload_png(&app, "alice").await;

    let mk = send(
        &app,
        post_form(
            "/folders",
            &csrf,
            "alice",
            format!("csrf_token={csrf}&name=Requests&parent_id="),
        ),
    )
    .await;
    let fid = folder_from_location(&mk.location());
    let existing = send(
        &app,
        upload_req_folder(
            &csrf,
            &csrf,
            "alice",
            &fid,
            "pic.png",
            "image/png",
            &png_bytes(),
        ),
    )
    .await;
    assert_eq!(existing.status, StatusCode::FOUND);

    let enabled = send(
        &app,
        post_form(
            &format!("/folders/{fid}/upload"),
            &csrf,
            "alice",
            format!("csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(enabled.status, StatusCode::FOUND);
    let token = store
        .list_upload_requests("alice")
        .await
        .unwrap()
        .into_iter()
        .find(|request| request.folder_id == fid)
        .unwrap()
        .token;
    assert!(store
        .get_folder(&fid, "alice")
        .await
        .unwrap()
        .unwrap()
        .upload_token
        .is_none());

    let page = send(&app, get(&format!("/u/{token}"), None)).await;
    assert_eq!(page.status, StatusCode::OK);
    let page_html = page.text();
    assert!(page_html.contains("Requests"));
    assert!(
        !page_html.contains("pic.png"),
        "upload-only page does not list folder files"
    );
    assert!(page_html.contains("data-ap-share-room"));
    assert!(page_html.contains("data-upload-form"));
    assert!(page_html.contains("data-upload-queue"));
    assert!(page_html.contains("href=\"/s/share-room.css\""));
    assert!(page_html.contains("src=\"/s/share-room.js\""));
    assert!(page
        .header(header::CONTENT_SECURITY_POLICY)
        .contains("connect-src 'self'"));
    assert!(page_html.contains("name=\"file\" required>"));
    assert!(
        !page_html.contains("name=\"file\" multiple"),
        "SSR/no-JS input remains single-file; JS owns multi selection"
    );
    assert!(!page_html.contains("GENERATED FROM odyssey"));
    let public_csrf = page.csrf_cookie().unwrap();
    assert!(page_html.contains(&format!("value=\"{public_csrf}\"")));

    // A sibling tab reuses the existing cookie/token instead of rotating it underneath this page.
    let sibling = send(
        &app,
        get_with_cookie(&format!("/u/{token}"), None, &public_csrf),
    )
    .await;
    assert_eq!(sibling.status, StatusCode::OK);
    assert_eq!(sibling.csrf_cookie().as_deref(), Some(public_csrf.as_str()));
    assert!(sibling.text().contains(&format!("value=\"{public_csrf}\"")));

    // Extractor failures are collapsed into the safe CSP shell, not Axum's multipart detail.
    let malformed = send(
        &app,
        Request::builder()
            .method("POST")
            .uri(format!("/u/{token}"))
            .header(header::CONTENT_TYPE, "multipart/form-data")
            .header(header::COOKIE, format!("__Host-csrf={public_csrf}"))
            .body(Body::from("broken envelope"))
            .unwrap(),
    )
    .await;
    assert_eq!(malformed.status, StatusCode::BAD_REQUEST);
    assert!(malformed
        .text()
        .contains("Aperture could not accept this request"));
    assert!(!malformed.text().contains("boundary"));
    assert!(malformed
        .header(header::CONTENT_SECURITY_POLICY)
        .contains("default-src 'none'"));

    // A failed POST does not mutate the cookie. Retrying with the page token still succeeds.
    let rejected = send(
        &app,
        public_upload_req(
            "wrong-token",
            &public_csrf,
            &token,
            "retry.png",
            "image/png",
            &png_bytes_alt(),
        ),
    )
    .await;
    assert_eq!(rejected.status, StatusCode::BAD_REQUEST);
    assert!(rejected.csrf_cookie().is_none());
    assert!(!rejected.text().contains("session token"));
    let retry = send(
        &app,
        public_upload_req(
            &public_csrf,
            &public_csrf,
            &token,
            "retry.png",
            "image/png",
            &png_bytes_alt(),
        ),
    )
    .await;
    assert_eq!(retry.status, StatusCode::OK, "{}", retry.text());
    assert_eq!(retry.csrf_cookie().as_deref(), Some(public_csrf.as_str()));

    let up = send(
        &app,
        public_upload_req(
            &public_csrf,
            &public_csrf,
            &token,
            "pic.png",
            "image/png",
            &png_bytes_alt(),
        ),
    )
    .await;
    assert_eq!(up.status, StatusCode::OK, "{}", up.text());
    assert!(up.text().contains("Uploaded"));
    assert_eq!(up.csrf_cookie().as_deref(), Some(public_csrf.as_str()));
    let files = store.list_files_in_folder(&fid, "alice").await.unwrap();
    let names: Vec<String> = files.iter().map(|f| f.name.clone()).collect();
    assert!(names.contains(&"pic.png".to_string()));
    assert!(
        names.contains(&"pic (2).png".to_string()),
        "same-name public upload is renamed"
    );

    let used = store.usage_for_owner("alice").await.unwrap();
    store.set_quota("alice", Some(used)).await.unwrap();
    let page2 = send(
        &app,
        get_with_cookie(&format!("/u/{token}"), None, &public_csrf),
    )
    .await;
    let csrf2 = page2.csrf_cookie().unwrap();
    assert_eq!(csrf2, public_csrf);
    let over = send(
        &app,
        public_upload_req(
            &csrf2,
            &csrf2,
            &token,
            "over.png",
            "image/png",
            &png_bytes(),
        ),
    )
    .await;
    assert_eq!(over.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(over.text().contains("cannot accept that file right now"));
    assert!(!over.text().contains("quota is free"));
    assert!(!over.text().contains("of the owner's"));

    let revoked = send(
        &app,
        post_form(
            &format!("/folders/{fid}/upload/revoke"),
            &csrf,
            "alice",
            format!("csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(revoked.status, StatusCode::FOUND);
    assert_eq!(
        send(&app, get(&format!("/u/{token}"), None)).await.status,
        StatusCode::GONE
    );
}

#[tokio::test]
async fn request_rooms_owner_lifecycle_rotation_and_receipts() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);
    let home = send(&app, get("/", Some("alice"))).await;
    let csrf = home.csrf_cookie().unwrap();
    let made = send(
        &app,
        post_form(
            "/folders",
            &csrf,
            "alice",
            format!("csrf_token={csrf}&name=Evidence"),
        ),
    )
    .await;
    let folder_id = folder_from_location(&made.location());
    let request = create_upload_request(
        &app,
        &store,
        &folder_id,
        &csrf,
        "&max_file_mib=2&max_total_mib=4&max_files=3&allowed_types=image%2F*",
    )
    .await;

    let list = send(&app, get("/requests", Some("alice"))).await;
    assert_eq!(list.status, StatusCode::OK);
    assert!(list.text().contains("Evidence intake"));
    assert!(list.text().contains("Create request"));
    let detail = send(
        &app,
        get(&format!("/requests/{}", request.id), Some("alice")),
    )
    .await;
    assert_eq!(detail.status, StatusCode::OK);
    assert!(detail.text().contains("Request limits"));
    assert!(detail.text().contains("Files received"));
    assert!(detail.text().contains(&format!(
        "name=\"expected_token\" value=\"{}\"",
        request.token
    )));

    let public = send(&app, get(&format!("/u/{}", request.token), None)).await;
    assert_eq!(public.status, StatusCode::OK);
    let public_csrf = public.csrf_cookie().unwrap();
    let received = send(
        &app,
        public_upload_req(
            &public_csrf,
            &public_csrf,
            &request.token,
            "proof.png",
            "image/png",
            &png_bytes(),
        ),
    )
    .await;
    assert_eq!(received.status, StatusCode::OK, "{}", received.text());
    let submissions = store
        .list_upload_submissions(&request.id, "alice")
        .await
        .unwrap();
    assert_eq!(submissions.len(), 1);
    let received_file = store.get(&submissions[0].file_id).await.unwrap().unwrap();
    assert!(
        received_file.share_token.is_none(),
        "upload capability must not mint a read capability"
    );

    // Full owner update keeps consumed counters but changes the public policy.
    let updated = send(
        &app,
        post_form(
            &format!("/requests/{}/update", request.id),
            &csrf,
            "alice",
            format!("csrf_token={csrf}&title=Updated+request&description=PNG+only&expiry=86400&max_file_mib=2&max_total_mib=5&max_files=4&allowed_types=image%2Fpng"),
        ),
    )
    .await;
    assert_eq!(updated.status, StatusCode::FOUND, "{}", updated.text());
    let stored = store
        .get_upload_request(&request.id, "alice")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.title, "Updated request");
    assert_eq!(stored.used_files, 1);
    assert_eq!(stored.allowed_types, "image/png");

    let closed = send(
        &app,
        post_form(
            &format!("/requests/{}/close", request.id),
            &csrf,
            "alice",
            format!("csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(closed.status, StatusCode::FOUND);
    assert_eq!(
        send(&app, get(&format!("/u/{}", request.token), None))
            .await
            .status,
        StatusCode::GONE
    );
    let reopened = send(
        &app,
        post_form(
            &format!("/requests/{}/reopen", request.id),
            &csrf,
            "alice",
            format!("csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(reopened.status, StatusCode::FOUND);
    assert_eq!(
        send(&app, get(&format!("/u/{}", request.token), None))
            .await
            .status,
        StatusCode::OK
    );

    let rotated = send(
        &app,
        post_form(
            &format!("/requests/{}/rotate", request.id),
            &csrf,
            "alice",
            format!("csrf_token={csrf}&expected_token={}", request.token),
        ),
    )
    .await;
    assert_eq!(rotated.status, StatusCode::FOUND);
    let new_token = store
        .get_upload_request(&request.id, "alice")
        .await
        .unwrap()
        .unwrap()
        .token;
    assert_ne!(new_token, request.token);
    assert_eq!(
        send(&app, get(&format!("/u/{}", request.token), None))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(&app, get(&format!("/u/{new_token}"), None))
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn request_rooms_enforce_type_file_total_count_and_expiry_without_leaks() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);
    let home = send(&app, get("/", Some("alice"))).await;
    let csrf = home.csrf_cookie().unwrap();
    let made = send(
        &app,
        post_form(
            "/folders",
            &csrf,
            "alice",
            format!("csrf_token={csrf}&name=Bounded"),
        ),
    )
    .await;
    let folder_id = folder_from_location(&made.location());
    let mut request = create_upload_request(
        &app,
        &store,
        &folder_id,
        &csrf,
        "&max_file_mib=1&max_total_mib=1&max_files=1&allowed_types=image%2F*",
    )
    .await;
    let public = send(&app, get(&format!("/u/{}", request.token), None)).await;
    let public_csrf = public.csrf_cookie().unwrap();

    let denied = send(
        &app,
        public_upload_req(
            &public_csrf,
            &public_csrf,
            &request.token,
            "note.txt",
            "text/plain",
            b"not accepted",
        ),
    )
    .await;
    assert_eq!(denied.status, StatusCode::BAD_REQUEST);
    assert!(denied.text().contains("could not accept this request"));
    assert!(!denied.text().contains("text/plain"));

    let forged_image = send(
        &app,
        public_upload_req(
            &public_csrf,
            &public_csrf,
            &request.token,
            "forged.png",
            "image/png",
            b"<!doctype html><script>alert(1)</script>",
        ),
    )
    .await;
    assert_eq!(forged_image.status, StatusCode::BAD_REQUEST);
    assert!(store
        .list_upload_submissions(&request.id, "alice")
        .await
        .unwrap()
        .is_empty());

    request.allowed_types = "application/pdf".to_string();
    request.updated_at += 1;
    assert!(store.update_upload_request(&request).await.unwrap());
    let forged_pdf = send(
        &app,
        public_upload_req(
            &public_csrf,
            &public_csrf,
            &request.token,
            "forged.pdf",
            "application/pdf",
            b"<!doctype html><script>alert(1)</script>",
        ),
    )
    .await;
    assert_eq!(forged_pdf.status, StatusCode::BAD_REQUEST);
    request.allowed_types = "image/*".to_string();
    request.updated_at += 1;
    assert!(store.update_upload_request(&request).await.unwrap());

    let mut oversized = png_bytes();
    oversized.resize(1024 * 1024 + 1, 0);
    let too_large = send(
        &app,
        public_upload_req(
            &public_csrf,
            &public_csrf,
            &request.token,
            "large.png",
            "image/png",
            &oversized,
        ),
    )
    .await;
    assert_eq!(too_large.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(!too_large.text().contains("1048576"));
    assert!(!too_large.text().contains("quota"));

    let mut accepted = png_bytes();
    accepted.resize(600 * 1024, 0);
    let first = send(
        &app,
        public_upload_req(
            &public_csrf,
            &public_csrf,
            &request.token,
            "first.png",
            "image/png",
            &accepted,
        ),
    )
    .await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text());
    let second = send(
        &app,
        public_upload_req(
            &public_csrf,
            &public_csrf,
            &request.token,
            "second.png",
            "image/png",
            &accepted,
        ),
    )
    .await;
    assert_eq!(second.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(!second.text().contains("owner's"));
    assert!(!second.text().contains("quota"));
    assert!(!second.text().contains("store error"));
    let consumed = store
        .get_upload_request(&request.id, "alice")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(consumed.used_files, 1);
    assert_eq!(consumed.used_bytes, accepted.len() as i64);

    request = consumed;
    request.expires_at = Some(1);
    request.updated_at += 1;
    assert!(store.update_upload_request(&request).await.unwrap());
    assert_eq!(
        send(&app, get(&format!("/u/{}", request.token), None))
            .await
            .status,
        StatusCode::GONE
    );
}

#[tokio::test]
async fn request_blob_failure_releases_budget_and_leaves_no_receipt_or_file() {
    let base = build_dev_state();
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    let deletes = Arc::new(AtomicUsize::new(0));
    let state = AppState {
        config: base.config,
        store: store.clone(),
        blobs: Arc::new(FailingPutBlobs {
            deletes: deletes.clone(),
            fail_delete: false,
        }),
        audit: aperture::audit::AuditSink::disabled(),
    };
    let app = app(state);
    let home = send(&app, get("/", Some("alice"))).await;
    let csrf = home.csrf_cookie().unwrap();
    let made = send(
        &app,
        post_form(
            "/folders",
            &csrf,
            "alice",
            format!("csrf_token={csrf}&name=Failure"),
        ),
    )
    .await;
    let folder_id = folder_from_location(&made.location());
    let request = create_upload_request(&app, &store, &folder_id, &csrf, "").await;
    let public = send(&app, get(&format!("/u/{}", request.token), None)).await;
    let public_csrf = public.csrf_cookie().unwrap();
    let failed = send(
        &app,
        public_upload_req(
            &public_csrf,
            &public_csrf,
            &request.token,
            "failure.png",
            "image/png",
            &png_bytes(),
        ),
    )
    .await;
    assert_eq!(failed.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!failed.text().contains("injected put failure"));
    assert!(deletes.load(Ordering::SeqCst) >= 1);
    let after = store
        .get_upload_request(&request.id, "alice")
        .await
        .unwrap()
        .unwrap();
    assert_eq!((after.used_files, after.used_bytes), (0, 0));
    assert!(store
        .list_upload_submissions(&request.id, "alice")
        .await
        .unwrap()
        .is_empty());
    assert!(store
        .list_files_in_folder(&folder_id, "alice")
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn request_blob_delete_failure_keeps_the_durable_recovery_anchor() {
    let base = build_dev_state();
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    let deletes = Arc::new(AtomicUsize::new(0));
    let state = AppState {
        config: base.config,
        store: store.clone(),
        blobs: Arc::new(FailingPutBlobs {
            deletes: deletes.clone(),
            fail_delete: true,
        }),
        audit: aperture::audit::AuditSink::disabled(),
    };
    let app = app(state);
    let home = send(&app, get("/", Some("alice"))).await;
    let csrf = home.csrf_cookie().unwrap();
    let made = send(
        &app,
        post_form(
            "/folders",
            &csrf,
            "alice",
            format!("csrf_token={csrf}&name=DurableFailure"),
        ),
    )
    .await;
    let folder_id = folder_from_location(&made.location());
    let request = create_upload_request(&app, &store, &folder_id, &csrf, "").await;
    let public = send(&app, get(&format!("/u/{}", request.token), None)).await;
    let public_csrf = public.csrf_cookie().unwrap();
    let failed = send(
        &app,
        public_upload_req(
            &public_csrf,
            &public_csrf,
            &request.token,
            "orphan.png",
            "image/png",
            &png_bytes(),
        ),
    )
    .await;
    assert_eq!(failed.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(deletes.load(Ordering::SeqCst), 1);

    let after = store
        .get_upload_request(&request.id, "alice")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        after.used_files, 1,
        "failed delete keeps the file slot reserved"
    );
    assert_eq!(after.used_bytes, png_bytes().len() as i64);
    let claim = store
        .claim_upload_recovery("recovery-owner", 100, 0)
        .await
        .unwrap();
    let UploadRecoveryClaim::Claimed(items) = claim else {
        panic!("failed compensation must leave one recoverable reservation");
    };
    assert_eq!(items.len(), 1);
}

#[tokio::test]
async fn request_memory_reservation_is_atomic_under_concurrency() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);
    let home = send(&app, get("/", Some("alice"))).await;
    let csrf = home.csrf_cookie().unwrap();
    let made = send(
        &app,
        post_form(
            "/folders",
            &csrf,
            "alice",
            format!("csrf_token={csrf}&name=Atomic"),
        ),
    )
    .await;
    let folder_id = folder_from_location(&made.location());
    let request = create_upload_request(
        &app,
        &store,
        &folder_id,
        &csrf,
        "&max_file_mib=1&max_total_mib=1&max_files=1",
    )
    .await;
    let left = store.clone();
    let right = store.clone();
    let request_id = request.id.clone();
    let request_id_two = request.id.clone();
    let request_token = request.token.clone();
    let request_token_two = request.token.clone();
    let (a, b) = tokio::join!(
        async move {
            left.reserve_request_upload(UploadReserveInput {
                request_id: &request_id,
                expected_token: &request_token,
                reservation_id: "reserve-a",
                size: 1,
                content_type: "image/png",
                content_type_verified: true,
                owner_quota: None,
                now: 10,
            })
            .await
            .unwrap()
        },
        async move {
            right
                .reserve_request_upload(UploadReserveInput {
                    request_id: &request_id_two,
                    expected_token: &request_token_two,
                    reservation_id: "reserve-b",
                    size: 1,
                    content_type: "image/png",
                    content_type_verified: true,
                    owner_quota: None,
                    now: 10,
                })
                .await
                .unwrap()
        }
    );
    assert_eq!(
        [a, b]
            .into_iter()
            .filter(|outcome| *outcome == UploadReserve::Reserved)
            .count(),
        1
    );
    assert!(matches!(
        [a, b]
            .into_iter()
            .find(|outcome| *outcome != UploadReserve::Reserved),
        Some(UploadReserve::FileCountExceeded)
    ));
    let winner = if a == UploadReserve::Reserved {
        "reserve-a"
    } else {
        "reserve-b"
    };
    assert!(store.release_request_upload(winner).await.unwrap());
    let released = store
        .get_upload_request(&request.id, "alice")
        .await
        .unwrap()
        .unwrap();
    assert_eq!((released.used_files, released.used_bytes), (0, 0));
}

#[tokio::test]
async fn request_memory_recovery_claim_is_all_or_busy() {
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    let mut request = store_request("memory-recovery", "memory-recovery-token");
    request.status = "open".to_string();
    request.expires_at = Some(1_000);
    assert!(store.create_upload_request(&request).await.unwrap());
    for id in ["memory-recovery-a", "memory-recovery-b"] {
        assert_eq!(
            store
                .reserve_request_upload(UploadReserveInput {
                    request_id: &request.id,
                    expected_token: &request.token,
                    reservation_id: id,
                    size: 1,
                    content_type: "image/png",
                    content_type_verified: true,
                    owner_quota: None,
                    now: 10,
                })
                .await
                .unwrap(),
            UploadReserve::Reserved
        );
    }
    let first = store
        .claim_upload_recovery("first-worker", 20, 0)
        .await
        .unwrap();
    assert!(matches!(first, UploadRecoveryClaim::Claimed(ref items) if items.len() == 2));
    assert!(store
        .abandon_upload_recovery("memory-recovery-a", "first-worker")
        .await
        .unwrap());
    assert_eq!(
        store
            .claim_upload_recovery("second-worker", 21, 0)
            .await
            .unwrap(),
        UploadRecoveryClaim::Busy
    );
    assert!(store
        .release_request_upload("memory-recovery-a")
        .await
        .unwrap());
    assert!(
        !store
            .release_request_upload("memory-recovery-b")
            .await
            .unwrap(),
        "a leased release fails without deleting the recovery anchor"
    );
    assert!(store
        .complete_upload_recovery("memory-recovery-b", "first-worker")
        .await
        .unwrap());
}

#[tokio::test]
async fn request_rotation_invalidates_a_previously_resolved_token_at_reservation() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);
    let home = send(&app, get("/", Some("alice"))).await;
    let csrf = home.csrf_cookie().unwrap();
    let made = send(
        &app,
        post_form(
            "/folders",
            &csrf,
            "alice",
            format!("csrf_token={csrf}&name=RotateRace"),
        ),
    )
    .await;
    let folder_id = folder_from_location(&made.location());
    let request = create_upload_request(&app, &store, &folder_id, &csrf, "").await;
    let resolved = Arc::new(tokio::sync::Notify::new());
    let rotated = Arc::new(tokio::sync::Notify::new());

    let uploader_store = store.clone();
    let uploader_resolved = resolved.clone();
    let uploader_rotated = rotated.clone();
    let old_token = request.token.clone();
    let rotate_expected_token = old_token.clone();
    let upload = async move {
        let stale_page = uploader_store
            .get_upload_request_by_token(&old_token)
            .await
            .unwrap()
            .unwrap();
        uploader_resolved.notify_one();
        uploader_rotated.notified().await;
        uploader_store
            .reserve_request_upload(UploadReserveInput {
                request_id: &stale_page.id,
                expected_token: &old_token,
                reservation_id: "old-token-reservation",
                size: 1,
                content_type: "application/octet-stream",
                content_type_verified: false,
                owner_quota: None,
                now: 10,
            })
            .await
            .unwrap()
    };
    let owner_store = store.clone();
    let owner_resolved = resolved;
    let owner_rotated = rotated;
    let request_id = request.id.clone();
    let rotate = async move {
        owner_resolved.notified().await;
        assert!(owner_store
            .rotate_upload_request_token(
                &request_id,
                "alice",
                &rotate_expected_token,
                "replacement-token",
                11,
            )
            .await
            .unwrap());
        owner_rotated.notify_one();
    };
    let (outcome, ()) = tokio::join!(upload, rotate);
    assert_eq!(outcome, UploadReserve::Unavailable);
    let stored = store
        .get_upload_request(&request.id, "alice")
        .await
        .unwrap()
        .unwrap();
    assert_eq!((stored.used_files, stored.used_bytes), (0, 0));
}

fn store_request(id: &str, token: &str) -> UploadRequestRec {
    UploadRequestRec {
        id: id.to_string(),
        owner_sub: "alice".to_string(),
        folder_id: "folder".to_string(),
        token: token.to_string(),
        title: "Original policy".to_string(),
        description: "Original description".to_string(),
        status: "closed".to_string(),
        expires_at: Some(5),
        max_file_bytes: 1024,
        max_total_bytes: 4096,
        max_files: 4,
        used_bytes: 0,
        used_files: 0,
        allowed_types: "image/*".to_string(),
        created_at: 1,
        updated_at: 1,
    }
}

#[tokio::test]
async fn request_rotation_is_expected_token_compare_and_swap() {
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    let request = store_request("rotate-cas", "original-token");
    assert!(store.create_upload_request(&request).await.unwrap());
    let left = store.clone();
    let right = store.clone();
    let (a, b) = tokio::join!(
        left.rotate_upload_request_token(
            "rotate-cas",
            "alice",
            "original-token",
            "left-token",
            10,
        ),
        right.rotate_upload_request_token(
            "rotate-cas",
            "alice",
            "original-token",
            "right-token",
            10,
        )
    );
    assert_eq!(
        [a.unwrap(), b.unwrap()]
            .into_iter()
            .filter(|ok| *ok)
            .count(),
        1
    );
    let stored = store
        .get_upload_request("rotate-cas", "alice")
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        stored.token.as_str(),
        "left-token" | "right-token"
    ));
}

#[tokio::test]
async fn request_reopen_does_not_replace_a_concurrent_policy_update() {
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    let request = store_request("reopen-cas", "reopen-token");
    assert!(store.create_upload_request(&request).await.unwrap());
    let mut policy = request.clone();
    policy.title = "Concurrent policy".to_string();
    policy.description = "Must survive reopen".to_string();
    policy.max_total_bytes = 8192;
    policy.max_files = 8;
    policy.allowed_types = "application/pdf".to_string();
    policy.expires_at = Some(500);
    policy.updated_at = 100;
    let left = store.clone();
    let right = store.clone();
    let (updated, reopened) = tokio::join!(
        left.update_upload_request(&policy),
        right.reopen_upload_request("reopen-cas", "alice", 100, 700),
    );
    assert!(updated.unwrap());
    assert!(reopened.unwrap());
    let stored = store
        .get_upload_request("reopen-cas", "alice")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.title, "Concurrent policy");
    assert_eq!(stored.description, "Must survive reopen");
    assert_eq!(stored.max_total_bytes, 8192);
    assert_eq!(stored.max_files, 8);
    assert_eq!(stored.allowed_types, "application/pdf");
    assert_eq!(stored.status, "open");
    assert!(stored.expires_at.is_some_and(|expiry| expiry > 100));
}

// ---------------------------------------------------------------------------
// Inline preview: content-type routing on the detail page
// ---------------------------------------------------------------------------

#[tokio::test]
async fn preview_routing_by_content_type() {
    let state = build_dev_state();
    let app = app(state);
    let (imgid, csrf) = upload_png(&app, "alice").await;

    // Image -> inline <img> with the lightbox trigger.
    let di = send(&app, get(&format!("/f/{imgid}"), Some("alice"))).await;
    assert!(di.text().contains("preview-img"));
    assert!(di.text().contains("lightbox-trigger"));

    // Text -> escaped <pre> preview (never raw HTML).
    let ut = send(
        &app,
        upload_req(
            &csrf,
            &csrf,
            "alice",
            "notes.txt",
            "text/plain",
            b"<script>alert(1)</script> hi",
        ),
    )
    .await;
    let tid = ut.location().trim_start_matches("/f/").to_string();
    let dt = send(&app, get(&format!("/f/{tid}"), Some("alice"))).await;
    assert!(dt.text().contains("preview-text"));
    assert!(
        dt.text().contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
        "text is escaped"
    );
    assert!(
        !dt.text().contains("<script>alert(1)</script>"),
        "no raw script survives"
    );

    // PDF -> sandboxed <iframe> of the inline preview bytes.
    let (pdfid, _c) = upload_pdf(&app, "alice").await;
    let dp = send(&app, get(&format!("/f/{pdfid}"), Some("alice"))).await;
    assert!(dp.text().contains("preview-pdf"));
    assert!(dp.text().contains(&format!("/f/{pdfid}/preview-raw")));
    assert!(dp.text().contains("sandbox"));
    // The preview-raw route serves the PDF inline, sandboxed, nosniff.
    let pr = send(&app, get(&format!("/f/{pdfid}/preview-raw"), Some("alice"))).await;
    assert_eq!(pr.status, StatusCode::OK);
    assert_eq!(pr.header(header::CONTENT_TYPE), "application/pdf");
    assert!(pr.header(header::CONTENT_DISPOSITION).starts_with("inline"));
    assert_eq!(pr.header(header::X_CONTENT_TYPE_OPTIONS), "nosniff");
    assert_eq!(pr.header(header::CONTENT_SECURITY_POLICY), "sandbox");

    // Video/audio -> native controls pointed at the Range-enabled raw route.
    let uv = send(
        &app,
        upload_req(
            &csrf,
            &csrf,
            "alice",
            "clip.mp4",
            "video/mp4",
            b"\x00\x00\x00\x18ftypmp42detail-video",
        ),
    )
    .await;
    let vid = uv.location().trim_start_matches("/f/").to_string();
    let dv = send(&app, get(&format!("/f/{vid}"), Some("alice"))).await;
    assert!(dv.text().contains("<video class=\"ap-player\""));
    assert!(dv
        .text()
        .contains("controls preload=\"metadata\" playsinline"));
    assert!(dv.text().contains(&format!("src=\"/f/{vid}/raw\"")));

    let ua = send(
        &app,
        upload_req(
            &csrf,
            &csrf,
            "alice",
            "voice.mp3",
            "audio/mpeg",
            b"ID3\x04\x00\x00\x00\x00\x00\x21detail-audio",
        ),
    )
    .await;
    let aid = ua.location().trim_start_matches("/f/").to_string();
    let da = send(&app, get(&format!("/f/{aid}"), Some("alice"))).await;
    assert!(da
        .text()
        .contains("<audio class=\"ap-player ap-player--audio\""));
    assert!(da.text().contains("controls preload=\"metadata\""));
    assert!(da.text().contains(&format!("src=\"/f/{aid}/raw\"")));

    // Non-previewable binary -> the type icon + "No inline preview".
    let ub = send(
        &app,
        upload_req(
            &csrf,
            &csrf,
            "alice",
            "blob.bin",
            "application/octet-stream",
            b"\x00\x01\x02rawbytes",
        ),
    )
    .await;
    let bid = ub.location().trim_start_matches("/f/").to_string();
    let db = send(&app, get(&format!("/f/{bid}"), Some("alice"))).await;
    assert!(db.text().contains("No inline preview"));

    // preview-raw on a NON-pdf falls back to the safe attachment path (never inline execution).
    let prb = send(&app, get(&format!("/f/{bid}/preview-raw"), Some("alice"))).await;
    assert!(prb
        .header(header::CONTENT_DISPOSITION)
        .starts_with("attachment"));
}

#[tokio::test]
async fn preview_and_version_routes_are_owner_scoped() {
    let state = build_dev_state();
    let app = app(state);
    let (id, csrf) = upload_png(&app, "alice").await;
    // Give the file a version so the version route has a target.
    send(
        &app,
        upload_req(
            &csrf,
            &csrf,
            "alice",
            "shot.png",
            "image/png",
            &png_bytes_alt(),
        ),
    )
    .await;
    // Read the version id out of the detail page's version link.
    let vid = {
        let d = send(&app, get(&format!("/f/{id}"), Some("alice"))).await;
        let t = d.text();
        let marker = format!("/f/{id}/versions/");
        let after = t.split(&marker).nth(1).unwrap().to_string();
        after.chars().take_while(|&c| c != '/').collect::<String>()
    };

    // Bob cannot preview or touch Alice's file/version.
    assert_eq!(
        send(&app, get(&format!("/f/{id}/preview-raw"), Some("bob")))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(
            &app,
            get(&format!("/f/{id}/versions/{vid}/raw"), Some("bob"))
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    let bob_home = send(&app, get("/", Some("bob"))).await;
    let bob_csrf = bob_home.csrf_cookie().unwrap();
    let restore = send(
        &app,
        post_form(
            &format!("/f/{id}/versions/{vid}/restore"),
            &bob_csrf,
            "bob",
            format!("csrf_token={bob_csrf}"),
        ),
    )
    .await;
    assert_eq!(restore.status, StatusCode::FORBIDDEN);
}
