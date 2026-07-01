//! End-to-end flow tests against the in-memory metadata store + in-memory blobs (NO database, NO
//! Cairn required).
//!
//! Drives the real `Router` in-process via `tower::oneshot`, exercising the full upload -> detail
//! -> raw -> share -> delete lifecycle, the double-submit CSRF guard, per-user ownership (403),
//! the public share-token fetch, image vs. download serving, and the size cap. This is the
//! default `cargo test` suite and stays DB-free.

use std::sync::Arc;

use aperture::blobs::{Blobs, MemoryBlobs};
use aperture::config::Config;
use aperture::store::{InMemoryStore, Store};
use aperture::{app, build_dev_state, AppState};
use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use tower::ServiceExt;

const BOUNDARY: &str = "----apertureTESTboundary7MA4YWxkTrZu0gW";

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
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
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

fn upload_req(csrf: &str, cookie: &str, subject: &str, filename: &str, ctype: &str, data: &[u8]) -> Request<Body> {
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

#[tokio::test]
async fn upload_detail_raw_share_delete_lifecycle() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let blobs: Arc<dyn Blobs> = state.blobs.clone();
    let app = app(state);

    // GET / mints a CSRF cookie; the dropzone embeds the same token.
    let home = send(&app, get("/", Some("alice"))).await;
    assert_eq!(home.status, StatusCode::OK);
    assert!(home.text().contains("Your drive"));
    assert!(home.text().contains("Your drive is empty"));
    let csrf = home.csrf_cookie().expect("csrf cookie on GET /");

    // POST /upload (a PNG) -> 302 /f/{id}.
    let png = png_bytes();
    let created = send(
        &app,
        upload_req(&csrf, &csrf, "alice", "screenshot.png", "application/octet-stream", &png),
    )
    .await;
    assert_eq!(created.status, StatusCode::FOUND, "{}", created.text());
    let loc = created.location();
    assert!(loc.starts_with("/f/"), "redirect to /f/, got {loc}");
    let id = loc.trim_start_matches("/f/").to_string();

    // The metadata row + blob both exist; the content type was sniffed to image/png.
    let rec = store.get(&id).await.unwrap().expect("metadata row");
    assert_eq!(rec.owner_sub, "alice");
    assert_eq!(rec.name, "screenshot.png");
    assert_eq!(rec.content_type, "image/png");
    assert_eq!(rec.size as usize, png.len());
    assert_eq!(blobs.get(&rec.object_key).await.unwrap(), png);

    // GET /f/{id} renders the detail page with an inline image preview + share link.
    let detail = send(&app, get(&loc, Some("alice"))).await;
    assert_eq!(detail.status, StatusCode::OK);
    assert!(detail.text().contains("screenshot.png"));
    assert!(detail.text().contains(&format!("/f/{id}/raw")));
    assert!(detail.text().contains(&format!("/s/{}", rec.share_token)));

    // GET /f/{id}/raw streams the bytes inline as image/png.
    let raw = send(&app, get(&format!("/f/{id}/raw"), Some("alice"))).await;
    assert_eq!(raw.status, StatusCode::OK);
    assert_eq!(raw.header(header::CONTENT_TYPE), "image/png");
    assert!(raw.header(header::CONTENT_DISPOSITION).starts_with("inline"));
    assert_eq!(raw.header(header::X_CONTENT_TYPE_OPTIONS), "nosniff");
    assert_eq!(raw.body, png);

    // The gallery now lists the file.
    let home2 = send(&app, get("/", Some("alice"))).await;
    assert!(home2.text().contains("screenshot.png"));
    assert!(home2.text().contains("1 file"));

    // Public share fetch: NO auth headers, still returns the bytes.
    let shared = send(&app, get(&format!("/s/{}", rec.share_token), None)).await;
    assert_eq!(shared.status, StatusCode::OK);
    assert_eq!(shared.body, png);

    // Delete it (CSRF-checked) -> 302 / ; metadata + blob both gone.
    let csrf2 = detail.csrf_cookie().expect("csrf on detail page");
    let del = send(
        &app,
        Request::builder()
            .method("POST")
            .uri(format!("/delete/{id}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, format!("__Host-csrf={csrf2}"))
            .header("x-auth-subject", "alice")
            .header("x-auth-email", "alice@w33d.xyz")
            .body(Body::from(format!("csrf_token={csrf2}")))
            .unwrap(),
    )
    .await;
    assert_eq!(del.status, StatusCode::FOUND);
    assert_eq!(del.location(), "/");
    assert!(store.get(&id).await.unwrap().is_none());
    assert!(blobs.get(&rec.object_key).await.is_err());

    let gone = send(&app, get(&loc, Some("alice"))).await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
    let share_gone = send(&app, get(&format!("/s/{}", rec.share_token), None)).await;
    assert_eq!(share_gone.status, StatusCode::NOT_FOUND);
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
        upload_req(&csrf, &csrf, "alice", "secret.png", "image/png", &png_bytes()),
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
        upload_req(&csrf, &csrf, "alice", "notes.pdf", "application/pdf", b"%PDF-1.7\n...content..."),
    )
    .await;
    let id = created.location().trim_start_matches("/f/").to_string();

    let raw = send(&app, get(&format!("/f/{id}/raw"), Some("alice"))).await;
    assert_eq!(raw.status, StatusCode::OK);
    assert_eq!(raw.header(header::CONTENT_TYPE), "application/octet-stream");
    assert!(raw.header(header::CONTENT_DISPOSITION).starts_with("attachment"));
    assert!(raw.header(header::CONTENT_DISPOSITION).contains("notes.pdf"));
}

#[tokio::test]
async fn csrf_is_required_on_upload() {
    let app = app(build_dev_state());
    // No matching cookie -> rejected before anything is stored.
    let bad = send(
        &app,
        upload_req("totally-wrong", "the-cookie-value", "alice", "x.png", "image/png", &png_bytes()),
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
        upload_req(&csrf, &csrf, "alice", "big.bin", "application/octet-stream", &big),
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
        upload_req(&csrf, &csrf, "alice", "empty.bin", "application/octet-stream", b""),
    )
    .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert!(res.text().contains("Choose a file"));
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
