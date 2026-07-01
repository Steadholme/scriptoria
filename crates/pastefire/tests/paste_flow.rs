//! End-to-end flow tests against the in-memory store (NO database required).
//!
//! Drives the real `Router` in-process via `tower::oneshot`, exercising the full create ->
//! view -> raw -> delete lifecycle, the double-submit CSRF guard, expiry honoring, and
//! ownership-scoped delete. This is the default `cargo test` suite and stays DB-free.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use pastefire::model::Paste;
use pastefire::store::Store;
use pastefire::{app, build_dev_state, now_secs, AppState};
use tower::ServiceExt;

/// Percent-encode a form value (encode everything that is not an unreserved character).
fn enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Resp {
    fn location(&self) -> String {
        self.headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    }
    /// Value of the `__Host-csrf` cookie set on this response, if any.
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
        body: String::from_utf8_lossy(&bytes).to_string(),
    }
}

fn get(path: &str, subject: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method("GET").uri(path);
    if let Some(s) = subject {
        b = b.header("x-auth-subject", s).header("x-auth-email", format!("{s}@w33d.xyz"));
    }
    b.body(Body::empty()).unwrap()
}

fn post_form(path: &str, fields: &[(&str, &str)], cookie: &str, subject: Option<&str>) -> Request<Body> {
    let body = fields
        .iter()
        .map(|(k, v)| format!("{}={}", k, enc(v)))
        .collect::<Vec<_>>()
        .join("&");
    let mut b = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={cookie}"));
    if let Some(s) = subject {
        b = b.header("x-auth-subject", s).header("x-auth-email", format!("{s}@w33d.xyz"));
    }
    b.body(Body::from(body)).unwrap()
}

#[tokio::test]
async fn create_view_raw_delete_lifecycle() {
    let app = app(build_dev_state());

    // GET / mints a CSRF cookie; the cookie value is also the token in the form.
    let form_page = send(&app, get("/", Some("alice"))).await;
    assert_eq!(form_page.status, StatusCode::OK);
    assert!(form_page.body.contains("New paste"));
    assert!(form_page.body.contains("You have no active pastes yet."));
    let csrf = form_page.csrf_cookie().expect("csrf cookie set on GET /");

    // POST / creates the paste -> 302 /p/{id}.
    let created = send(
        &app,
        post_form(
            "/",
            &[
                ("csrf_token", &csrf),
                ("title", "Reverse proxy"),
                ("language", "nginx-not-in-list"), // clamped to plaintext
                ("body", "server {\n  listen 443 ssl;\n}\n"),
                ("expiry", "never"),
            ],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(created.status, StatusCode::FOUND);
    let loc = created.location();
    assert!(loc.starts_with("/p/"), "redirect to /p/, got {loc}");
    let id = loc.trim_start_matches("/p/").to_string();

    // GET /p/{id} renders the escaped body + the language label fell back to Plain text.
    let view = send(&app, get(&loc, Some("alice"))).await;
    assert_eq!(view.status, StatusCode::OK);
    assert!(view.body.contains("Reverse proxy"));
    assert!(view.body.contains("listen 443 ssl;"));
    assert!(view.body.contains("Plain text"));
    assert!(view.body.contains(&format!("/raw/{id}")));
    // Owner sees a delete control.
    assert!(view.body.contains(&format!("/delete/{id}")));

    // GET /raw/{id} is text/plain and byte-identical to the submitted body.
    let raw = send(&app, get(&format!("/raw/{id}"), Some("alice"))).await;
    assert_eq!(raw.status, StatusCode::OK);
    assert_eq!(
        raw.headers.get(header::CONTENT_TYPE).unwrap(),
        "text/plain; charset=utf-8"
    );
    assert_eq!(raw.body, "server {\n  listen 443 ssl;\n}\n");

    // The recent list now shows the paste.
    let page2 = send(&app, get("/", Some("alice"))).await;
    assert!(page2.body.contains("Reverse proxy"));

    // Delete it (CSRF-checked) -> 302 / ; then it is gone (404).
    let csrf2 = view.csrf_cookie().expect("csrf on view page");
    let del = send(
        &app,
        post_form(&format!("/delete/{id}"), &[("csrf_token", &csrf2)], &csrf2, Some("alice")),
    )
    .await;
    assert_eq!(del.status, StatusCode::FOUND);
    assert_eq!(del.location(), "/");

    let gone = send(&app, get(&loc, Some("alice"))).await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn xss_in_body_is_escaped() {
    let app = app(build_dev_state());
    let page = send(&app, get("/", Some("alice"))).await;
    let csrf = page.csrf_cookie().unwrap();

    let created = send(
        &app,
        post_form(
            "/",
            &[
                ("csrf_token", &csrf),
                ("title", "<img src=x onerror=alert(1)>"),
                ("language", "html"),
                ("body", "<script>alert('xss')</script>"),
                ("expiry", "never"),
            ],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    let loc = created.location();
    let view = send(&app, get(&loc, Some("alice"))).await;
    assert_eq!(view.status, StatusCode::OK);
    // The raw script tag must NEVER appear unescaped in the HTML.
    assert!(!view.body.contains("<script>alert('xss')</script>"));
    assert!(view.body.contains("&lt;script&gt;"));
    assert!(view.body.contains("&lt;img src=x"));
}

#[tokio::test]
async fn csrf_is_required_on_create() {
    let app = app(build_dev_state());
    // No cookie / wrong token -> rejected.
    let bad = send(
        &app,
        post_form(
            "/",
            &[("csrf_token", "totally-wrong"), ("body", "hi"), ("expiry", "never")],
            "the-cookie-value",
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn empty_body_re_renders_form() {
    let app = app(build_dev_state());
    let page = send(&app, get("/", Some("alice"))).await;
    let csrf = page.csrf_cookie().unwrap();
    let res = send(
        &app,
        post_form(
            "/",
            &[("csrf_token", &csrf), ("body", "   "), ("expiry", "never")],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert!(res.body.contains("Paste body cannot be empty."));
}

#[tokio::test]
async fn expired_paste_is_not_viewable() {
    let state = build_dev_state();
    // Seed a paste that expired one second ago.
    let now = now_secs();
    let paste = Paste {
        id: "expiredone".to_string(),
        title: "old".to_string(),
        body: "gone".to_string(),
        language: "plaintext".to_string(),
        author_sub: "alice".to_string(),
        author_email: "alice@w33d.xyz".to_string(),
        created_at: now - 100,
        expires_at: Some(now - 1),
        burn_after_read: false,
        source_id: None,
        password_hash: None,
    };
    state.store.create(&paste).await.unwrap();
    let app = app(state);

    let view = send(&app, get("/p/expiredone", Some("alice"))).await;
    assert_eq!(view.status, StatusCode::NOT_FOUND);
    assert!(view.body.contains("expired"));

    let raw = send(&app, get("/raw/expiredone", Some("alice"))).await;
    assert_eq!(raw.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn view_is_syntax_highlighted_for_known_language() {
    let app = app(build_dev_state());
    let page = send(&app, get("/", Some("alice"))).await;
    let csrf = page.csrf_cookie().unwrap();

    let created = send(
        &app,
        post_form(
            "/",
            &[
                ("csrf_token", &csrf),
                ("title", "rust snippet"),
                ("language", "rust"),
                ("body", "fn main() { let n = 42; }"),
                ("expiry", "never"),
            ],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    let loc = created.location();
    let view = send(&app, get(&loc, Some("alice"))).await;
    assert_eq!(view.status, StatusCode::OK);
    // Keywords and the number get wrapped in highlight spans...
    assert!(view.body.contains("<span class=\"tok-kw\">fn</span>"));
    assert!(view.body.contains("<span class=\"tok-kw\">let</span>"));
    assert!(view.body.contains("<span class=\"tok-num\">42</span>"));
    // ...but the underlying text is all still present (copy/raw stay intact).
    let raw = send(&app, get(&loc.replace("/p/", "/raw/"), Some("alice"))).await;
    assert_eq!(raw.body, "fn main() { let n = 42; }");
}

#[tokio::test]
async fn view_renders_line_gutter_with_anchors() {
    let app = app(build_dev_state());
    let page = send(&app, get("/", Some("alice"))).await;
    let csrf = page.csrf_cookie().unwrap();

    let created = send(
        &app,
        post_form(
            "/",
            &[
                ("csrf_token", &csrf),
                ("title", "three liner"),
                ("language", "plaintext"),
                ("body", "line one\nline two\nline three"),
                ("expiry", "never"),
            ],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    let loc = created.location();
    let view = send(&app, get(&loc, Some("alice"))).await;
    assert_eq!(view.status, StatusCode::OK);
    // Each source line gets a stable anchor id and a clickable gutter number.
    assert!(view.body.contains("<div class=\"ln\" id=\"L1\">"));
    assert!(view.body.contains("<div class=\"ln\" id=\"L3\">"));
    assert!(view.body.contains("<a class=\"ln-no\" href=\"#L2\">2</a>"));
    assert!(view.body.contains("<span class=\"ln-code\">line two</span>"));
    // No phantom fourth line for a body without a trailing newline.
    assert!(!view.body.contains("id=\"L4\""));
}

#[tokio::test]
async fn view_lines_param_highlights_range() {
    let app = app(build_dev_state());
    let page = send(&app, get("/", Some("alice"))).await;
    let csrf = page.csrf_cookie().unwrap();

    let created = send(
        &app,
        post_form(
            "/",
            &[
                ("csrf_token", &csrf),
                ("title", "highlight me"),
                ("language", "plaintext"),
                ("body", "a\nb\nc\nd"),
                ("expiry", "never"),
            ],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    let id = created.location().trim_start_matches("/p/").to_string();

    // ?lines=2-3 marks exactly rows 2 and 3 with the highlight class, server-side.
    let view = send(&app, get(&format!("/p/{id}?lines=2-3"), Some("alice"))).await;
    assert_eq!(view.status, StatusCode::OK);
    assert!(view.body.contains("<div class=\"ln\" id=\"L1\">"));
    assert!(view.body.contains("<div class=\"ln ln--hl\" id=\"L2\">"));
    assert!(view.body.contains("<div class=\"ln ln--hl\" id=\"L3\">"));
    assert!(view.body.contains("<div class=\"ln\" id=\"L4\">"));

    // A malformed range degrades gracefully to no highlight (still a valid view).
    let bad = send(&app, get(&format!("/p/{id}?lines=nonsense"), Some("alice"))).await;
    assert_eq!(bad.status, StatusCode::OK);
    assert!(!bad.body.contains("<div class=\"ln ln--hl\""));
}

#[tokio::test]
async fn similar_pastes_panel_links_related_snippet() {
    let app = app(build_dev_state());
    let page = send(&app, get("/", Some("alice"))).await;
    let csrf = page.csrf_cookie().unwrap();

    // Two strongly-overlapping snippets + one unrelated.
    let mk = |title: &str, body: &str| {
        post_form(
            "/",
            &[
                ("csrf_token", &csrf),
                ("title", title),
                ("language", "plaintext"),
                ("body", body),
                ("expiry", "never"),
            ],
            &csrf,
            Some("alice"),
        )
    };
    let a = send(&app, mk("nginx one", "server listen ssl proxy_pass upstream backend")).await;
    let _b = send(&app, mk("nginx two", "server listen ssl proxy_pass upstream backend cache")).await;
    let _c = send(&app, mk("totally other", "lorem ipsum dolor sit amet consectetur")).await;

    let view = send(&app, get(&a.location(), Some("alice"))).await;
    assert_eq!(view.status, StatusCode::OK);
    assert!(view.body.contains("Similar pastes"));
    assert!(view.body.contains("nginx two"));
    assert!(view.body.contains("% match"));
    // The unrelated paste must not be surfaced.
    assert!(!view.body.contains("totally other"));
}

#[tokio::test]
async fn burn_after_read_survives_author_then_burns_for_recipient() {
    let app = app(build_dev_state());
    let page = send(&app, get("/", Some("alice"))).await;
    let csrf = page.csrf_cookie().unwrap();

    let created = send(
        &app,
        post_form(
            "/",
            &[
                ("csrf_token", &csrf),
                ("title", "one time secret"),
                ("language", "plaintext"),
                ("body", "launch-codes-1234"),
                ("expiry", "never"),
                ("burn", "on"),
            ],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    let loc = created.location();

    // The author can open it repeatedly (to copy the link) without consuming it.
    let owner1 = send(&app, get(&loc, Some("alice"))).await;
    assert_eq!(owner1.status, StatusCode::OK);
    assert!(owner1.body.contains("launch-codes-1234"));
    let owner2 = send(&app, get(&loc, Some("alice"))).await;
    assert_eq!(owner2.status, StatusCode::OK);

    // The first recipient read renders the content AND consumes the paste.
    let recipient = send(&app, get(&loc, Some("bob"))).await;
    assert_eq!(recipient.status, StatusCode::OK);
    assert!(recipient.body.contains("launch-codes-1234"));
    assert!(recipient.body.contains("burn-after-read"));

    // Now it is gone for everyone — including the author.
    let gone_recipient = send(&app, get(&loc, Some("bob"))).await;
    assert_eq!(gone_recipient.status, StatusCode::NOT_FOUND);
    let gone_owner = send(&app, get(&loc, Some("alice"))).await;
    assert_eq!(gone_owner.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn burn_after_read_consumed_via_raw_by_recipient() {
    let app = app(build_dev_state());
    let page = send(&app, get("/", Some("alice"))).await;
    let csrf = page.csrf_cookie().unwrap();

    let created = send(
        &app,
        post_form(
            "/",
            &[
                ("csrf_token", &csrf),
                ("title", "raw secret"),
                ("language", "plaintext"),
                ("body", "raw-burn-body"),
                ("expiry", "never"),
                ("burn", "on"),
            ],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    let id = created.location().trim_start_matches("/p/").to_string();

    // Recipient fetches /raw -> gets the body once, then it is burned.
    let raw1 = send(&app, get(&format!("/raw/{id}"), Some("bob"))).await;
    assert_eq!(raw1.status, StatusCode::OK);
    assert_eq!(raw1.body, "raw-burn-body");
    let raw2 = send(&app, get(&format!("/raw/{id}"), Some("bob"))).await;
    assert_eq!(raw2.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn recent_list_paginates_backward_with_load_older_link() {
    let state = build_dev_state();
    // Seed five pastes with known, distinct created_at + ids for a deterministic keyset.
    for (id, created_at) in [
        ("p1aaaaaa", 100),
        ("p2aaaaaa", 101),
        ("p3aaaaaa", 102),
        ("p4aaaaaa", 103),
        ("p5aaaaaa", 104),
    ] {
        state
            .store
            .create(&Paste {
                id: id.to_string(),
                title: format!("title {id}"),
                body: "body".to_string(),
                language: "plaintext".to_string(),
                author_sub: "alice".to_string(),
                author_email: "alice@w33d.xyz".to_string(),
                created_at,
                expires_at: None,
                burn_after_read: false,
                source_id: None,
                password_hash: None,
            })
            .await
            .unwrap();
    }
    let app = app(state);

    // Newest page of 2: p5, p4. A full page => the "Load older" link is present, keyed off the
    // last (oldest) row of this page (created_at 103, id p4). `&` is HTML-escaped in the href.
    let page1 = send(&app, get("/?limit=2", Some("alice"))).await;
    assert_eq!(page1.status, StatusCode::OK);
    assert!(page1.body.contains("/p/p5aaaaaa"));
    assert!(page1.body.contains("/p/p4aaaaaa"));
    assert!(!page1.body.contains("/p/p3aaaaaa"), "third-newest must not be on page 1");
    assert!(page1.body.contains("Load older"));
    assert!(page1.body.contains("/?before=103_p4aaaaaa&amp;limit=2"));

    // Follow the cursor: strictly older page of 2: p3, p2.
    let page2 = send(&app, get("/?before=103_p4aaaaaa&limit=2", Some("alice"))).await;
    assert_eq!(page2.status, StatusCode::OK);
    assert!(page2.body.contains("/p/p3aaaaaa"));
    assert!(page2.body.contains("/p/p2aaaaaa"));
    assert!(!page2.body.contains("/p/p4aaaaaa"), "cursor excludes the row it was cut from");
    assert!(page2.body.contains("/?before=101_p2aaaaaa&amp;limit=2"));

    // Final page: only p1 remains — a short page, so NO "Load older" link.
    let page3 = send(&app, get("/?before=101_p2aaaaaa&limit=2", Some("alice"))).await;
    assert_eq!(page3.status, StatusCode::OK);
    assert!(page3.body.contains("/p/p1aaaaaa"));
    assert!(!page3.body.contains("Load older"), "end of list has no older link");
}

#[tokio::test]
async fn recent_list_default_page_has_no_load_older_when_short() {
    // The default newest view (no ?before) with only a couple pastes is a short page => no link.
    let app = app(build_dev_state());
    let page = send(&app, get("/", Some("alice"))).await;
    let csrf = page.csrf_cookie().unwrap();
    for title in ["one", "two"] {
        send(
            &app,
            post_form(
                "/",
                &[
                    ("csrf_token", &csrf),
                    ("title", title),
                    ("language", "plaintext"),
                    ("body", "x"),
                    ("expiry", "never"),
                ],
                &csrf,
                Some("alice"),
            ),
        )
        .await;
    }
    let listing = send(&app, get("/", Some("alice"))).await;
    assert_eq!(listing.status, StatusCode::OK);
    assert!(listing.body.contains("one"));
    assert!(listing.body.contains("two"));
    assert!(!listing.body.contains("Load older"));
}

/// Create a paste as `subject` via the router, returning `(paste_id, fresh_csrf_cookie)`.
async fn create_paste(
    app: &axum::Router,
    subject: &str,
    fields: &[(&str, &str)],
) -> (String, String) {
    let page = send(app, get("/", Some(subject))).await;
    let csrf = page.csrf_cookie().unwrap();
    let mut all = vec![("csrf_token", csrf.as_str())];
    all.extend_from_slice(fields);
    let created = send(app, post_form("/", &all, &csrf, Some(subject))).await;
    assert_eq!(created.status, StatusCode::FOUND, "create should 302");
    let id = created.location().trim_start_matches("/p/").to_string();
    (id, csrf)
}

#[tokio::test]
async fn edit_appends_revision_and_updates_current() {
    let app = app(build_dev_state());
    let (id, _) = create_paste(
        &app,
        "alice",
        &[
            ("title", "v1 title"),
            ("language", "plaintext"),
            ("body", "first version"),
            ("expiry", "never"),
        ],
    )
    .await;

    // The owner view offers an Edit control; a brand-new paste has no History link yet.
    let view = send(&app, get(&format!("/p/{id}"), Some("alice"))).await;
    assert!(view.body.contains(&format!("/edit/{id}")));
    assert!(!view.body.contains(&format!("/p/{id}/history")));

    // A non-owner cannot open the edit form.
    let forbid = send(&app, get(&format!("/edit/{id}"), Some("bob"))).await;
    assert_eq!(forbid.status, StatusCode::FORBIDDEN);

    // Edit it: the current row becomes v2, and v1 is archived as revision 1.
    let ecsrf = view.csrf_cookie().unwrap();
    let edited = send(
        &app,
        post_form(
            &format!("/edit/{id}"),
            &[
                ("csrf_token", &ecsrf),
                ("title", "v2 title"),
                ("language", "rust"),
                ("body", "second version"),
            ],
            &ecsrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(edited.status, StatusCode::FOUND);
    assert_eq!(edited.location(), format!("/p/{id}"));

    // Current view shows v2; a History link is now present.
    let v2 = send(&app, get(&format!("/p/{id}"), Some("alice"))).await;
    assert!(v2.body.contains("second version"));
    assert!(v2.body.contains("v2 title"));
    assert!(v2.body.contains(&format!("/p/{id}/history")));

    // History lists the current version + revision 1.
    let hist = send(&app, get(&format!("/p/{id}/history"), Some("alice"))).await;
    assert_eq!(hist.status, StatusCode::OK);
    assert!(hist.body.contains("Current version"));
    assert!(hist.body.contains(&format!("/p/{id}/rev/1")));

    // The archived revision still holds v1's content.
    let rev = send(&app, get(&format!("/p/{id}/rev/1"), Some("alice"))).await;
    assert_eq!(rev.status, StatusCode::OK);
    assert!(rev.body.contains("first version"));
    assert!(rev.body.contains("archived version"));

    // A no-op edit (identical content) does not create a spurious second revision.
    let v2b = send(&app, get(&format!("/p/{id}"), Some("alice"))).await;
    let noop_csrf = v2b.csrf_cookie().unwrap();
    let noop = send(
        &app,
        post_form(
            &format!("/edit/{id}"),
            &[
                ("csrf_token", &noop_csrf),
                ("title", "v2 title"),
                ("language", "rust"),
                ("body", "second version"),
            ],
            &noop_csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(noop.status, StatusCode::FOUND);
    let hist2 = send(&app, get(&format!("/p/{id}/history"), Some("alice"))).await;
    assert!(!hist2.body.contains(&format!("/p/{id}/rev/2")), "no spurious revision 2");
}

#[tokio::test]
async fn fork_credits_source_and_is_owned_by_forker() {
    let app = app(build_dev_state());
    let (id, _) = create_paste(
        &app,
        "alice",
        &[
            ("title", "shared snippet"),
            ("language", "rust"),
            ("body", "fn shared() {}"),
            ("expiry", "never"),
        ],
    )
    .await;

    // Bob views the paste and forks it.
    let view = send(&app, get(&format!("/p/{id}"), Some("bob"))).await;
    assert!(view.body.contains(&format!("/fork/{id}")));
    let csrf = view.csrf_cookie().unwrap();
    let forked = send(
        &app,
        post_form(&format!("/fork/{id}"), &[("csrf_token", &csrf)], &csrf, Some("bob")),
    )
    .await;
    assert_eq!(forked.status, StatusCode::FOUND);
    let fork_id = forked.location().trim_start_matches("/p/").to_string();
    assert_ne!(fork_id, id, "fork gets a new id");

    // The fork holds the copied content, credits the source, and is owned by Bob (he can delete it).
    let fview = send(&app, get(&format!("/p/{fork_id}"), Some("bob"))).await;
    assert_eq!(fview.status, StatusCode::OK);
    // `fn` is wrapped in a highlight span; the identifier is rendered verbatim.
    assert!(fview.body.contains("shared()"));
    assert!(fview.body.contains(&format!("Forked from <a href=\"/p/{id}\">")));
    assert!(fview.body.contains(&format!("/delete/{fork_id}")));

    // The original is untouched and still owned by Alice.
    let orig = send(&app, get(&format!("/p/{id}"), Some("alice"))).await;
    assert!(orig.body.contains(&format!("/delete/{id}")));
}

#[tokio::test]
async fn password_protected_paste_prompts_and_unlocks() {
    let app = app(build_dev_state());
    let (id, _) = create_paste(
        &app,
        "alice",
        &[
            ("title", "secret config"),
            ("language", "plaintext"),
            ("body", "SECRET-TOKEN-42"),
            ("expiry", "never"),
            ("password", "hunter2"),
        ],
    )
    .await;

    // The owner sees the content directly (no prompt).
    let owner = send(&app, get(&format!("/p/{id}"), Some("alice"))).await;
    assert_eq!(owner.status, StatusCode::OK);
    assert!(owner.body.contains("SECRET-TOKEN-42"));

    // A non-owner is prompted, and the body is NOT in the prompt page.
    let bob = send(&app, get(&format!("/p/{id}"), Some("bob"))).await;
    assert_eq!(bob.status, StatusCode::OK);
    assert!(bob.body.contains("Password required"));
    assert!(!bob.body.contains("SECRET-TOKEN-42"));
    let csrf = bob.csrf_cookie().unwrap();

    // The raw route also refuses a non-owner (no bypass of the prompt).
    let raw_denied = send(&app, get(&format!("/raw/{id}"), Some("bob"))).await;
    assert_eq!(raw_denied.status, StatusCode::FORBIDDEN);

    // A wrong password is rejected; the body stays hidden.
    let wrong = send(
        &app,
        post_form(
            &format!("/unlock/{id}"),
            &[("csrf_token", &csrf), ("password", "nope")],
            &csrf,
            Some("bob"),
        ),
    )
    .await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
    assert!(wrong.body.contains("Incorrect password"));
    assert!(!wrong.body.contains("SECRET-TOKEN-42"));

    // The correct password reveals the content.
    let ok = send(
        &app,
        post_form(
            &format!("/unlock/{id}"),
            &[("csrf_token", &csrf), ("password", "hunter2")],
            &csrf,
            Some("bob"),
        ),
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK);
    assert!(ok.body.contains("SECRET-TOKEN-42"));
}

#[tokio::test]
async fn cannot_fork_a_protected_paste_as_non_owner() {
    let app = app(build_dev_state());
    let (id, _) = create_paste(
        &app,
        "alice",
        &[
            ("title", "locked"),
            ("language", "plaintext"),
            ("body", "do-not-copy"),
            ("expiry", "never"),
            ("password", "pw"),
        ],
    )
    .await;

    // Bob (a non-owner) must not exfiltrate a protected body by forking it.
    let page = send(&app, get("/", Some("bob"))).await;
    let csrf = page.csrf_cookie().unwrap();
    let denied = send(
        &app,
        post_form(&format!("/fork/{id}"), &[("csrf_token", &csrf)], &csrf, Some("bob")),
    )
    .await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn cannot_delete_another_users_paste() {
    let state: AppState = build_dev_state();
    let store: Arc<dyn Store> = state.store.clone();
    let now = now_secs();
    store
        .create(&Paste {
            id: "ownedbyA".to_string(),
            title: "secret".to_string(),
            body: "x".to_string(),
            language: "plaintext".to_string(),
            author_sub: "alice".to_string(),
            author_email: "alice@w33d.xyz".to_string(),
            created_at: now,
            expires_at: None,
            burn_after_read: false,
            source_id: None,
            password_hash: None,
        })
        .await
        .unwrap();
    let app = app(state);

    // Bob loads a page to obtain a valid CSRF cookie, then tries to delete Alice's paste.
    let page = send(&app, get("/", Some("bob"))).await;
    let csrf = page.csrf_cookie().unwrap();
    let del = send(
        &app,
        post_form("/delete/ownedbyA", &[("csrf_token", &csrf)], &csrf, Some("bob")),
    )
    .await;
    assert_eq!(del.status, StatusCode::FORBIDDEN);
    // Still there.
    assert!(store.get("ownedbyA").await.unwrap().is_some());
}
