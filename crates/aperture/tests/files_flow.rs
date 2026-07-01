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
    let home = send(app, get("/", Some(subject))).await;
    let csrf = home.csrf_cookie().expect("csrf cookie");
    let created = send(
        app,
        upload_req(&csrf, &csrf, subject, "shot.png", "image/png", &png_bytes()),
    )
    .await;
    let id = created.location().trim_start_matches("/f/").to_string();
    (id, csrf)
}

#[tokio::test]
async fn share_expiry_returns_410_after_expiry() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);
    let (id, csrf) = upload_png(&app, "alice").await;
    let token = store
        .get(&id)
        .await
        .unwrap()
        .unwrap()
        .share_token
        .unwrap();

    // Configure an expiry 1 hour out -> the public link still serves.
    let set = send(
        &app,
        post_form(&format!("/f/{id}/share"), &csrf, "alice", format!("csrf_token={csrf}&expiry=3600")),
    )
    .await;
    assert_eq!(set.status, StatusCode::FOUND);
    assert_eq!(send(&app, get(&format!("/s/{token}"), None)).await.status, StatusCode::OK);

    // Force the stored expiry into the past; the public fetch is now 410 Gone.
    store
        .configure_share(&id, "alice", Some(token.clone()), Some(1), None)
        .await
        .unwrap();
    let gone = send(&app, get(&format!("/s/{token}"), None)).await;
    assert_eq!(gone.status, StatusCode::GONE);
    // The owner still reaches the file over SSO regardless of the share expiry.
    assert_eq!(send(&app, get(&format!("/f/{id}/raw"), Some("alice"))).await.status, StatusCode::OK);
}

#[tokio::test]
async fn share_password_prompts_then_serves() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);
    let (id, csrf) = upload_png(&app, "alice").await;
    let token = store.get(&id).await.unwrap().unwrap().share_token.unwrap();

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
    assert_ne!(prompt.body, png_bytes());

    // Wrong password -> 401 + prompt again.
    let wrong = send(&app, post_public(&format!("/s/{token}"), "password=nope".to_string())).await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert!(wrong.text().contains("Incorrect password"));

    // Correct password -> the bytes.
    let ok = send(&app, post_public(&format!("/s/{token}"), "password=hunter2".to_string())).await;
    assert_eq!(ok.status, StatusCode::OK);
    assert_eq!(ok.body, png_bytes());
}

#[tokio::test]
async fn share_revoke_clears_the_token() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);
    let (id, csrf) = upload_png(&app, "alice").await;
    let token = store.get(&id).await.unwrap().unwrap().share_token.unwrap();

    // The link works before revoke.
    assert_eq!(send(&app, get(&format!("/s/{token}"), None)).await.status, StatusCode::OK);

    // Revoke -> 302, token cleared in the store, outstanding link now 404.
    let rev = send(
        &app,
        post_form(&format!("/f/{id}/revoke"), &csrf, "alice", format!("csrf_token={csrf}")),
    )
    .await;
    assert_eq!(rev.status, StatusCode::FOUND);
    assert!(store.get(&id).await.unwrap().unwrap().share_token.is_none());
    assert_eq!(send(&app, get(&format!("/s/{token}"), None)).await.status, StatusCode::NOT_FOUND);

    // The detail page now offers to create a new link; doing so mints a fresh, working token.
    let detail = send(&app, get(&format!("/f/{id}"), Some("alice"))).await;
    assert!(detail.text().contains("Create share link"));
    let csrf2 = detail.csrf_cookie().unwrap();
    send(
        &app,
        post_form(&format!("/f/{id}/share"), &csrf2, "alice", format!("csrf_token={csrf2}&expiry=never")),
    )
    .await;
    let new_token = store.get(&id).await.unwrap().unwrap().share_token.unwrap();
    assert_ne!(new_token, token);
    assert_eq!(send(&app, get(&format!("/s/{new_token}"), None)).await.status, StatusCode::OK);
}

#[tokio::test]
async fn share_config_requires_csrf() {
    let state = build_dev_state();
    let app = app(state);
    let (id, csrf) = upload_png(&app, "alice").await;
    // Wrong CSRF token field vs. cookie -> rejected.
    let bad = send(
        &app,
        post_form(&format!("/f/{id}/share"), &csrf, "alice", "csrf_token=wrong&expiry=3600".to_string()),
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
        post_form(&format!("/f/{id}/share"), &bob_csrf, "bob", format!("csrf_token={bob_csrf}&expiry=3600")),
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
    let token = rec.share_token.clone().expect("fresh upload has a share token");
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
    assert!(detail.text().contains(&format!("/s/{token}")));

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
    let shared = send(&app, get(&format!("/s/{token}"), None)).await;
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
    let share_gone = send(&app, get(&format!("/s/{token}"), None)).await;
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
        let up = send(&app, upload_req(&csrf, &csrf, "alice", n, "image/png", &png_bytes())).await;
        assert_eq!(up.status, StatusCode::FOUND, "{}", up.text());
    }

    // First page, capped to 2 -> two cards + a "Load older" link.
    let p1 = send(&app, get("/?limit=2", Some("alice"))).await;
    assert_eq!(p1.status, StatusCode::OK);
    let p1_ids = card_ids(&p1.text());
    assert_eq!(p1_ids.len(), 2, "a full page shows exactly the page size");
    let before = extract_before(&p1.text()).expect("Load older link on a full page");

    // Follow the cursor -> the remaining file, and NO further pager (partial page).
    let p2 = send(&app, get(&format!("/?limit=2&before={before}"), Some("alice"))).await;
    assert_eq!(p2.status, StatusCode::OK);
    let p2_ids = card_ids(&p2.text());
    assert_eq!(p2_ids.len(), 1, "the second page holds the remainder");
    assert!(extract_before(&p2.text()).is_none(), "no pager on a non-full page");

    // The two pages are disjoint and together cover all three distinct files.
    let mut all = p1_ids;
    all.extend(p2_ids);
    all.sort();
    all.dedup();
    assert_eq!(all.len(), 3, "pages are disjoint and cover every file");

    // Backward compatible: the default view (no ?before, no ?limit) still returns the newest page.
    let def = send(&app, get("/", Some("alice"))).await;
    assert_eq!(def.status, StatusCode::OK);
    assert_eq!(card_ids(&def.text()).len(), 3, "default page shows all files under the cap");
    assert!(extract_before(&def.text()).is_none(), "no pager when everything fits");
}

/// Extract the folder id from a `302 /?folder={id}` create/rename redirect Location.
fn folder_from_location(loc: &str) -> String {
    loc.trim_start_matches("/?folder=").to_string()
}

#[tokio::test]
async fn folder_create_move_filter_and_delete_lifecycle() {
    let state = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);

    // Two files for alice.
    let (id_a, csrf) = upload_png(&app, "alice").await;
    let up_b = send(&app, upload_req(&csrf, &csrf, "alice", "b.png", "image/png", &png_bytes())).await;
    let id_b = up_b.location().trim_start_matches("/f/").to_string();

    // Create a folder -> 302 /?folder={fid}.
    let made = send(
        &app,
        post_form("/folders", &csrf, "alice", format!("csrf_token={csrf}&name=Trips")),
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
    assert_eq!(card_ids(&folder_view.text()).len(), 0, "new folder is empty");

    // Move file A into the folder (CSRF-checked) -> 302 /f/{id_a}.
    let moved = send(
        &app,
        post_form(&format!("/f/{id_a}/move"), &csrf, "alice", format!("csrf_token={csrf}&folder_id={fid}")),
    )
    .await;
    assert_eq!(moved.status, StatusCode::FOUND);
    assert_eq!(store.get(&id_a).await.unwrap().unwrap().folder_id.as_deref(), Some(fid.as_str()));

    // The folder view now lists only A; the flat view still lists both.
    let fv = send(&app, get(&format!("/?folder={fid}"), Some("alice"))).await;
    assert_eq!(card_ids(&fv.text()), vec![id_a.clone()]);
    let flat = send(&app, get("/", Some("alice"))).await;
    let mut flat_ids = card_ids(&flat.text());
    flat_ids.sort();
    let mut both = vec![id_a.clone(), id_b.clone()];
    both.sort();
    assert_eq!(flat_ids, both, "flat view shows every file regardless of folder");

    // Rename the folder.
    let renamed = send(
        &app,
        post_form(&format!("/folders/{fid}/rename"), &csrf, "alice", format!("csrf_token={csrf}&name=Vacations")),
    )
    .await;
    assert_eq!(renamed.status, StatusCode::FOUND);
    assert_eq!(store.get_folder(&fid, "alice").await.unwrap().unwrap().name, "Vacations");

    // Delete the folder -> 302 / ; the file is kept but unfiled.
    let deleted = send(
        &app,
        post_form(&format!("/folders/{fid}/delete"), &csrf, "alice", format!("csrf_token={csrf}")),
    )
    .await;
    assert_eq!(deleted.status, StatusCode::FOUND);
    assert_eq!(deleted.location(), "/");
    assert!(store.get_folder(&fid, "alice").await.unwrap().is_none());
    assert!(store.get(&id_a).await.unwrap().unwrap().folder_id.is_none(), "file kept, unfiled");
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
        post_form("/folders", &csrf, "alice", format!("csrf_token={csrf}&name=Private")),
    )
    .await;
    let fid = folder_from_location(&made.location());

    // Wrong CSRF is rejected on folder create.
    let bad_csrf = send(
        &app,
        post_form("/folders", &csrf, "alice", "csrf_token=wrong&name=X".to_string()),
    )
    .await;
    assert_eq!(bad_csrf.status, StatusCode::BAD_REQUEST);

    // A blank name is rejected.
    let blank = send(
        &app,
        post_form("/folders", &csrf, "alice", format!("csrf_token={csrf}&name=%20")),
    )
    .await;
    assert_eq!(blank.status, StatusCode::BAD_REQUEST);

    // Bob (own valid CSRF) cannot rename or delete Alice's folder (404 — not his).
    let bob_home = send(&app, get("/", Some("bob"))).await;
    let bob_csrf = bob_home.csrf_cookie().unwrap();
    let bob_rename = send(
        &app,
        post_form(&format!("/folders/{fid}/rename"), &bob_csrf, "bob", format!("csrf_token={bob_csrf}&name=Hax")),
    )
    .await;
    assert_eq!(bob_rename.status, StatusCode::NOT_FOUND);
    assert_eq!(store.get_folder(&fid, "alice").await.unwrap().unwrap().name, "Private");

    // Moving a file into a folder the actor does not own is a 404 (and leaves the file unfiled).
    let bob_up = send(&app, upload_req(&bob_csrf, &bob_csrf, "bob", "b.png", "image/png", &png_bytes())).await;
    let bob_file = bob_up.location().trim_start_matches("/f/").to_string();
    let cross = send(
        &app,
        post_form(&format!("/f/{bob_file}/move"), &bob_csrf, "bob", format!("csrf_token={bob_csrf}&folder_id={fid}")),
    )
    .await;
    assert_eq!(cross.status, StatusCode::NOT_FOUND);
    assert!(store.get(&bob_file).await.unwrap().unwrap().folder_id.is_none());

    // Alice can move her file back to root with a blank target.
    send(
        &app,
        post_form(&format!("/f/{id_a}/move"), &csrf, "alice", format!("csrf_token={csrf}&folder_id={fid}")),
    )
    .await;
    let to_root = send(
        &app,
        post_form(&format!("/f/{id_a}/move"), &csrf, "alice", format!("csrf_token={csrf}&folder_id=")),
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

/// Upload a non-image file as `subject`, returning its `/f/{id}` id plus the CSRF token.
async fn upload_pdf(app: &axum::Router, subject: &str) -> (String, String) {
    let home = send(app, get("/", Some(subject))).await;
    let csrf = home.csrf_cookie().expect("csrf cookie");
    let created = send(
        app,
        upload_req(&csrf, &csrf, subject, "notes.pdf", "application/pdf", b"%PDF-1.7\n...content..."),
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
    assert!(thumb.header(header::CONTENT_SECURITY_POLICY).contains("default-src 'none'"));
    let body = thumb.text();
    assert!(body.starts_with("<svg"));
    assert!(body.contains(">PDF<"), "type icon bakes the uppercase extension label");

    // The derived thumbnail is now cached as a `{id}.thumb` blob, and re-requesting serves it again.
    assert_eq!(blobs.get(&format!("{id}.thumb")).await.unwrap(), body.as_bytes());
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

#[tokio::test]
async fn thumb_derived_blob_is_removed_on_delete() {
    let state = build_dev_state();
    let blobs: Arc<dyn Blobs> = state.blobs.clone();
    let app = app(state);
    let (id, csrf) = upload_pdf(&app, "alice").await;

    // Prime the derived-thumbnail cache, then delete the file.
    send(&app, get(&format!("/d/{id}/thumb"), Some("alice"))).await;
    assert!(blobs.get(&format!("{id}.thumb")).await.is_ok(), "thumbnail cached");
    let del = send(
        &app,
        post_form(&format!("/delete/{id}"), &csrf, "alice", format!("csrf_token={csrf}")),
    )
    .await;
    assert_eq!(del.status, StatusCode::FOUND);
    // Both the original blob and its derived thumbnail are gone (no orphan).
    assert!(blobs.get(&format!("{id}.thumb")).await.is_err(), "derived thumbnail removed with file");
}
