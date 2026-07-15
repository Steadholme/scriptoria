//! End-to-end wiki flow against the in-memory store (NO database).
//!
//! Drives the real `Router` in-process via `tower::oneshot`, exactly like the rest of the
//! estate. Covers: liveness, the empty index, the "missing page -> offer create" path, the
//! CSRF-protected create/edit cycle (editor identity taken from the gateway header), the
//! revision history, slug canonicalization, raw-HTML sanitization, and `[[wiki-link]]` markup.

use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

use lattice::{app, build_dev_state, AppState};

#[tokio::test]
async fn healthz_ok() {
    let state = build_dev_state();
    let (status, _h, body) = call(&state, get("/healthz")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");
}

#[tokio::test]
async fn full_create_edit_history_flow() {
    let state = build_dev_state();

    // Empty index.
    let (status, _h, body) = call(&state, get("/")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Knowledge base"));
    assert!(body.contains("<h1>Library</h1>"));
    assert!(body.contains("<div class=\"knowledge-library\">"));
    assert!(body.contains("Knowledge map"));
    assert!(body.contains("Recently updated"));
    assert!(body.contains("href=\"/coherence\""));
    assert!(body.contains("No pages yet"));

    // Missing page offers creation.
    let (status, _h, body) = call(&state, get("/w/home")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("doesn’t exist yet"));
    assert!(body.contains("/edit/home"));

    // Open the editor; capture the minted CSRF token (cookie == hidden field).
    let (status, headers, body) = call(&state, get("/edit/home")).await;
    assert_eq!(status, StatusCode::OK);
    let cookie = set_cookie(&headers).expect("editor sets a CSRF cookie");
    let csrf = cookie_value(&cookie).expect("csrf cookie value");
    assert!(
        body.contains(&format!("value=\"{csrf}\"")),
        "hidden field matches cookie"
    );
    assert!(body.contains("<form class=\"editor editor-workspace\""));
    assert!(body.contains("data-editor-source"));
    assert!(body.contains("data-editor-preview"));
    assert!(body.contains("name=\"base_rev\""));

    // Save the page (gateway injects the editor email; CSRF cookie + field present).
    let save = post_form(
        "/edit/home",
        &cookie,
        Some("alice@steadholme.local"),
        &[
            ("csrf_token", &csrf),
            ("title", "Home"),
            (
                "body_md",
                "Welcome.\n\nSee [[Runbook]] and [[Glossary|the glossary]].",
            ),
        ],
    );
    let (status, headers, _b) = call(&state, save).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "save redirects (POST->GET)");
    assert_eq!(location(&headers).as_deref(), Some("/w/home"));

    // Index now lists the page with the gateway editor email.
    let (_s, _h, body) = call(&state, get("/")).await;
    assert!(body.contains("1 page"));
    assert!(body.contains(">Home</a>"));
    assert!(body.contains("alice@steadholme.local"));

    // The page renders markdown + wiki-links: [[Runbook]] is missing (red), the body itself
    // (slug `home`) exists.
    let (status, _h, body) = call(&state, get("/w/home")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("<div class=\"knowledge-document\">"));
    assert!(body.contains("<article class=\"page document-article\">"));
    assert!(body.contains("<aside class=\"document-inspector\""));
    assert!(body.contains("<summary>Outline</summary>"));
    assert!(body.contains("<summary>Connections</summary>"));
    assert!(body.contains("<summary>Coherence signals</summary>"));
    assert!(body.contains("<p>Welcome.</p>"));
    assert!(body.contains(r#"href="/w/runbook""#));
    assert!(
        body.contains("wikilink--new"),
        "missing target is a red link"
    );
    assert!(body.contains(r#"href="/w/glossary""#));
    assert!(body.contains(">the glossary</a>"), "pipe label honored");

    // History shows one revision by the gateway editor.
    let (status, _h, body) = call(&state, get("/history/home")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("alice@steadholme.local"));
    assert!(body.contains("chars"));

    // A second edit by a different editor records a second revision and updates the page. The
    // editor loads the current head into `base_rev`; passing it back means no conflict.
    let (_s, headers2, _b) = call(&state, get("/edit/home")).await;
    let cookie2 = set_cookie(&headers2).unwrap();
    let csrf2 = cookie_value(&cookie2).unwrap();
    let base2 = state.store.head_revision("home").await.unwrap().unwrap().id;
    let save2 = post_form(
        "/edit/home",
        &cookie2,
        Some("bob@steadholme.local"),
        &[
            ("csrf_token", &csrf2),
            ("base_rev", &base2),
            ("title", "Home"),
            ("body_md", "Updated body."),
        ],
    );
    let (status, _h, _b) = call(&state, save2).await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (_s, _h, body) = call(&state, get("/w/home")).await;
    assert!(body.contains("Updated body."));
    assert!(body.contains("bob@steadholme.local"));

    let (_s, _h, body) = call(&state, get("/history/home")).await;
    // Both editors appear in the history list.
    assert!(body.contains("alice@steadholme.local"));
    assert!(body.contains("bob@steadholme.local"));
}

#[tokio::test]
async fn recent_feed_lists_cross_page_edits_newest_first() {
    let state = build_dev_state();
    save_page_http(
        &state,
        "alpha",
        "Alpha",
        "alpha created",
        "alice@steadholme.local",
    )
    .await;
    pause_for_distinct_ts().await;
    save_page_http(&state, "beta", "Beta", "beta created", "bob@steadholme.local").await;
    pause_for_distinct_ts().await;
    save_page_http(
        &state,
        "alpha",
        "Alpha",
        "alpha edited",
        "carol@steadholme.local",
    )
    .await;

    let (status, headers, body) = call(&state, get("/recent")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(set_cookie(&headers).is_none(), "recent feed is read-only");
    assert!(body.contains("Recent changes"));
    assert!(body.contains("alice@steadholme.local"));
    assert!(body.contains("bob@steadholme.local"));
    assert!(body.contains("carol@steadholme.local"));
    assert!(body.contains(r#"href="/w/alpha""#));
    assert!(body.contains(r#"href="/w/beta""#));
    assert!(body.contains(r#"href="/history/alpha""#));
    assert!(body.contains(">created</span>"));
    assert!(body.contains(">edited</span>"));

    let carol = body.find("carol@steadholme.local").unwrap();
    let alice = body.find("alice@steadholme.local").unwrap();
    assert!(
        carol < alice,
        "newest alpha edit appears before its creation"
    );
}

#[tokio::test]
async fn recent_feed_escapes_untrusted_title() {
    let state = build_dev_state();
    save_page_http(
        &state,
        "unsafe-title",
        "<b>x</b>",
        "body",
        "alice@steadholme.local",
    )
    .await;

    let (status, _headers, body) = call(&state, get("/recent")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.contains("<b>x</b>"), "raw title must not render");
    assert!(body.contains("&lt;b&gt;"), "title is HTML-escaped");
}

#[tokio::test]
async fn recent_feed_keyset_paginates() {
    let state = build_dev_state();
    save_page_http(
        &state,
        "alpha",
        "Alpha",
        "alpha created",
        "alice@steadholme.local",
    )
    .await;
    pause_for_distinct_ts().await;
    save_page_http(&state, "beta", "Beta", "beta created", "bob@steadholme.local").await;
    pause_for_distinct_ts().await;
    save_page_http(
        &state,
        "alpha",
        "Alpha",
        "alpha edited",
        "carol@steadholme.local",
    )
    .await;

    let (status, _headers, body) = call(&state, get("/recent?limit=2")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.matches("class=\"recent-row\"").count(), 2);
    assert!(body.contains("Load older"));
    assert!(body.contains(r#"href="/recent?before="#));
    assert!(body.contains("limit=2"));
}

#[tokio::test]
async fn recent_feed_never_leaks_body() {
    let state = build_dev_state();
    let sentinel = "recent_body_sentinel_9d4598b2";
    save_page_http(
        &state,
        "secret",
        "Secret",
        &format!("visible title only\n{sentinel}"),
        "alice@steadholme.local",
    )
    .await;

    let (status, _headers, body) = call(&state, get("/recent")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(">Secret</a>"));
    assert!(
        !body.contains(sentinel),
        "recent feed must not emit revision body_md"
    );

    let (status, _headers, library) = call(&state, get("/")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(library.contains("Recently updated"));
    assert!(library.contains(">Secret</a>"));
    assert!(
        !library.contains(sentinel),
        "Library activity must not emit revision body_md"
    );
}

#[tokio::test]
async fn template_prefills_new_page_body() {
    let state = build_dev_state();

    let (status, headers, _body) =
        call(&state, get("/new?title=Retro&template=meeting-notes")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        location(&headers).as_deref(),
        Some("/edit/retro?template=meeting-notes")
    );

    let (status, _headers, body) = call(&state, get("/edit/retro?template=meeting-notes")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("# Meeting notes"),
        "meeting notes template body is prefilled: {body}"
    );
    assert!(body.contains("## Attendees"));

    let (status, _headers, body) = call(&state, get("/edit/blank?template=not-real")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("# Meeting notes"),
        "unknown template yields a blank body"
    );
    assert!(!body.contains("# Decision record"));
}

#[tokio::test]
async fn move_page_flow_renders_tree_breadcrumb_and_rejects_cycles() {
    let state = build_dev_state();
    save_page_http(
        &state,
        "parent",
        "Parent",
        "Parent body.",
        "alice@steadholme.local",
    )
    .await;
    save_page_http(
        &state,
        "child",
        "Child",
        "Child body.",
        "alice@steadholme.local",
    )
    .await;

    let (status, _headers, body) = call(
        &state,
        post_form(
            "/move/child",
            "",
            Some("alice@steadholme.local"),
            &[("csrf_token", "anything"), ("parent_id", "parent")],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("CSRF"));
    assert_eq!(
        state
            .store
            .get_page("child")
            .await
            .unwrap()
            .unwrap()
            .parent_id,
        None
    );

    let (status, headers, body) = call(&state, get("/w/child")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("action=\"/move/child\""),
        "page view includes move form"
    );
    let cookie = set_cookie(&headers).expect("page view mints a CSRF cookie for move");
    let csrf = cookie_value(&cookie).unwrap();
    let (status, headers, _body) = call(
        &state,
        post_form(
            "/move/child",
            &cookie,
            Some("alice@steadholme.local"),
            &[("csrf_token", &csrf), ("parent_id", "parent")],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location(&headers).as_deref(), Some("/w/child"));
    assert_eq!(
        state
            .store
            .get_page("child")
            .await
            .unwrap()
            .unwrap()
            .parent_id
            .as_deref(),
        Some("parent")
    );

    let (status, _headers, body) = call(&state, get("/w/child")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Page tree"),
        "nested wiki renders the sidebar tree: {body}"
    );
    assert!(
        body.contains("class=\"breadcrumb\""),
        "child page renders breadcrumb"
    );
    assert!(
        body.contains(r#"href="/w/parent">Parent</a>"#),
        "breadcrumb links to parent"
    );

    let (_status, headers, _body) = call(&state, get("/w/parent")).await;
    let cycle_cookie = set_cookie(&headers).unwrap();
    let cycle_csrf = cookie_value(&cycle_cookie).unwrap();
    let (status, _headers, body) = call(
        &state,
        post_form(
            "/move/parent",
            &cycle_cookie,
            Some("alice@steadholme.local"),
            &[("csrf_token", &cycle_csrf), ("parent_id", "child")],
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "moving a page under a descendant is rejected"
    );
    assert!(body.contains("descendants"));
    assert_eq!(
        state
            .store
            .get_page("parent")
            .await
            .unwrap()
            .unwrap()
            .parent_id,
        None
    );
}

#[tokio::test]
async fn persisted_backlinks_are_updated_on_each_save() {
    let state = build_dev_state();
    save_page_http(
        &state,
        "runbook",
        "Runbook",
        "Target page.",
        "alice@steadholme.local",
    )
    .await;
    save_page_http(
        &state,
        "guide",
        "Guide",
        "Another target.",
        "alice@steadholme.local",
    )
    .await;
    save_page_http(
        &state,
        "home",
        "Home",
        "See [[Runbook]] and [Guide](/w/guide#top).",
        "alice@steadholme.local",
    )
    .await;

    assert_eq!(
        state.store.outgoing_links("home").await.unwrap(),
        vec!["guide".to_string(), "runbook".to_string()]
    );
    let (status, _headers, body) = call(&state, get("/w/runbook")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Linked from"),
        "persisted backlinks list is rendered"
    );
    assert!(
        body.contains(r#"class="relation-link" href="/w/home""#),
        "home is a persisted backlink: {body}"
    );

    save_page_http(
        &state,
        "home",
        "Home",
        "No explicit links now.",
        "bob@steadholme.local",
    )
    .await;
    assert!(state.store.outgoing_links("home").await.unwrap().is_empty());
    let (status, _headers, body) = call(&state, get("/w/runbook")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains(r#"class="relation-link" href="/w/home""#),
        "stale backlink was removed from connections: {body}"
    );
}

#[tokio::test]
async fn history_diff_and_revert_flow() {
    let state = build_dev_state();

    // Two saves -> two revisions.
    let (_s, h1, _b) = call(&state, get("/edit/notes")).await;
    let c1 = set_cookie(&h1).unwrap();
    let t1 = cookie_value(&c1).unwrap();
    let (s, _h, _b) = call(
        &state,
        post_form(
            "/edit/notes",
            &c1,
            Some("alice@steadholme.local"),
            &[
                ("csrf_token", &t1),
                ("title", "Notes"),
                ("body_md", "line one\nline two\nline three"),
            ],
        ),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);

    let (_s, h2, _b) = call(&state, get("/edit/notes")).await;
    let c2 = set_cookie(&h2).unwrap();
    let t2 = cookie_value(&c2).unwrap();
    let base2 = state
        .store
        .head_revision("notes")
        .await
        .unwrap()
        .unwrap()
        .id;
    let (s, _h, _b) = call(
        &state,
        post_form(
            "/edit/notes",
            &c2,
            Some("bob@steadholme.local"),
            &[
                ("csrf_token", &t2),
                ("base_rev", &base2),
                ("title", "Notes"),
                ("body_md", "line one\nCHANGED two\nline three"),
            ],
        ),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);

    // History lists a compare form + a revert button, and mints a CSRF cookie for the revert.
    let (status, hist_headers, body) = call(&state, get("/history/notes")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("class=\"compare-form\""),
        "compare form present with 2 revisions"
    );
    assert!(
        body.contains("action=\"/revert/notes\""),
        "revert form present"
    );
    assert!(
        body.contains(">current</span>"),
        "newest revision marked current"
    );
    let revert_cookie = set_cookie(&hist_headers).expect("history mints a CSRF cookie");
    let revert_csrf = cookie_value(&revert_cookie).unwrap();

    // Pull the two revision ids straight out of the store (newest-first).
    let revs = state.store.list_revisions("notes").await.unwrap();
    assert_eq!(revs.len(), 2);
    let newest = &revs[0];
    let oldest = &revs[1];

    // Diff view (from oldest -> newest): the changed line shows as - old / + new, context stays.
    let (status, _h, diff) = call(
        &state,
        get(&format!(
            "/history/notes?from={}&to={}",
            oldest.id, newest.id
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        diff.contains("diff__line--del"),
        "a removed line is rendered"
    );
    assert!(
        diff.contains("diff__line--add"),
        "an added line is rendered"
    );
    assert!(diff.contains("CHANGED two"), "the new text appears");
    assert!(diff.contains(">line one<"), "unchanged context line kept");

    // Revert to the oldest revision: re-saves its body as a NEW revision.
    let (status, headers, _b) = call(
        &state,
        post_form(
            "/revert/notes",
            &revert_cookie,
            Some("carol@steadholme.local"),
            &[("csrf_token", &revert_csrf), ("rev_id", &oldest.id)],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location(&headers).as_deref(), Some("/w/notes"));

    // The page body is back to the old content, recorded by the reverting user as a 3rd revision.
    let (_s, _h, page) = call(&state, get("/w/notes")).await;
    assert!(page.contains("line two"), "reverted body restored");
    assert!(
        !page.contains("CHANGED two"),
        "reverted away from the newer body"
    );
    let revs2 = state.store.list_revisions("notes").await.unwrap();
    assert_eq!(
        revs2.len(),
        3,
        "revert appends a new revision (append-only history)"
    );
    assert_eq!(revs2[0].editor_email, "carol@steadholme.local");
    assert_eq!(revs2[0].body_md, "line one\nline two\nline three");
}

#[tokio::test]
async fn revert_requires_csrf() {
    let state = build_dev_state();
    // Seed a page with a revision.
    let (_s, h, _b) = call(&state, get("/edit/doc")).await;
    let c = set_cookie(&h).unwrap();
    let t = cookie_value(&c).unwrap();
    call(
        &state,
        post_form(
            "/edit/doc",
            &c,
            Some("alice@steadholme.local"),
            &[("csrf_token", &t), ("title", "Doc"), ("body_md", "v1")],
        ),
    )
    .await;
    let revs = state.store.list_revisions("doc").await.unwrap();
    let rid = revs[0].id.clone();

    // POST with a token but NO cookie -> double-submit fails -> 403, no write.
    let (status, _h, body) = call(
        &state,
        post_form(
            "/revert/doc",
            "",
            Some("alice@steadholme.local"),
            &[("csrf_token", "anything"), ("rev_id", &rid)],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("CSRF"));
    assert_eq!(
        state.store.list_revisions("doc").await.unwrap().len(),
        1,
        "no revision added"
    );
}

#[tokio::test]
async fn csrf_required_on_post() {
    let state = build_dev_state();
    // POST with a token but NO cookie -> double-submit fails -> 403.
    let req = post_form(
        "/edit/home",
        "", // no cookie
        Some("alice@steadholme.local"),
        &[
            ("csrf_token", "anything"),
            ("title", "Home"),
            ("body_md", "x"),
        ],
    );
    let (status, _h, body) = call(&state, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("CSRF"));
    // Nothing was written.
    let (_s, _h, idx) = call(&state, get("/")).await;
    assert!(idx.contains("No pages yet"));
}

#[tokio::test]
async fn slug_is_canonicalized_via_redirect() {
    let state = build_dev_state();
    let (status, headers, _b) = call(&state, get("/w/Foo%20Bar")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location(&headers).as_deref(), Some("/w/foo-bar"));

    let (status, headers, _b) = call(&state, get("/history/Foo%20Bar")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location(&headers).as_deref(), Some("/history/foo-bar"));
}

#[tokio::test]
async fn stored_html_is_sanitized() {
    let state = build_dev_state();
    let (_s, headers, _b) = call(&state, get("/edit/xss")).await;
    let cookie = set_cookie(&headers).unwrap();
    let csrf = cookie_value(&cookie).unwrap();
    let save = post_form(
        "/edit/xss",
        &cookie,
        Some("alice@steadholme.local"),
        &[
            ("csrf_token", &csrf),
            ("title", "XSS"),
            ("body_md", "<script>alert(1)</script>\n\nhi"),
        ],
    );
    let (status, _h, _b) = call(&state, save).await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (_s, _h, body) = call(&state, get("/w/xss")).await;
    assert!(
        !body.contains("<script>alert(1)</script>"),
        "script must be escaped"
    );
    assert!(body.contains("&lt;script&gt;"));

    let (_s, _h, editor) = call(&state, get("/edit/xss")).await;
    assert!(editor.contains("data-editor-preview"));
    assert!(
        !editor.contains("<script>alert(1)</script>"),
        "server preview and source textarea both keep the stored draft inert"
    );
    assert!(editor.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
}

#[tokio::test]
async fn toc_and_heading_anchors_render() {
    let state = build_dev_state();
    let (_s, headers, _b) = call(&state, get("/edit/guide")).await;
    let cookie = set_cookie(&headers).unwrap();
    let csrf = cookie_value(&cookie).unwrap();
    let (status, _h, _b) = call(
        &state,
        post_form(
            "/edit/guide",
            &cookie,
            Some("alice@steadholme.local"),
            &[
                ("csrf_token", &csrf),
                ("base_rev", ""),
                ("title", "Guide"),
                (
                    "body_md",
                    "# Overview\n\nintro\n\n## Setup\n\nsteps\n\n## Setup\n\nmore",
                ),
            ],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (status, _h, body) = call(&state, get("/w/guide")).await;
    assert_eq!(status, StatusCode::OK);
    // Heading anchors are stamped, and duplicate headings get unique ids.
    assert!(body.contains("<h1 id=\"overview\">Overview</h1>"), "{body}");
    assert!(body.contains("id=\"setup\""), "{body}");
    assert!(
        body.contains("id=\"setup-1\""),
        "duplicate heading disambiguated: {body}"
    );
    // The TOC box links to those anchors.
    assert!(body.contains("class=\"toc\""), "toc box rendered: {body}");
    assert!(body.contains("href=\"#overview\""), "{body}");
    assert!(body.contains("href=\"#setup-1\""), "{body}");
}

#[tokio::test]
async fn edit_conflict_is_rejected_with_both_versions() {
    let state = build_dev_state();

    // Seed the page (base_rev empty -> creates the first revision).
    let (_s, h0, _b) = call(&state, get("/edit/spec")).await;
    let c0 = set_cookie(&h0).unwrap();
    let t0 = cookie_value(&c0).unwrap();
    let (s, _h, _b) = call(
        &state,
        post_form(
            "/edit/spec",
            &c0,
            Some("alice@steadholme.local"),
            &[
                ("csrf_token", &t0),
                ("base_rev", ""),
                ("title", "Spec"),
                ("body_md", "original"),
            ],
        ),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);

    // Two editors open the editor against the SAME head revision.
    let head = state.store.head_revision("spec").await.unwrap().unwrap();
    let base = head.id.clone();

    // Editor A saves first -> head advances.
    let (_s, ha, _b) = call(&state, get("/edit/spec")).await;
    let ca = set_cookie(&ha).unwrap();
    let ta = cookie_value(&ca).unwrap();
    let (s, _h, _b) = call(
        &state,
        post_form(
            "/edit/spec",
            &ca,
            Some("alice@steadholme.local"),
            &[
                ("csrf_token", &ta),
                ("base_rev", &base),
                ("title", "Spec"),
                ("body_md", "alice update"),
            ],
        ),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER, "first save wins");

    // Editor B submits against the now-stale base -> conflict (no write).
    let (_s, hb, _b) = call(&state, get("/edit/spec")).await; // fresh cookie for CSRF
    let cb = set_cookie(&hb).unwrap();
    let tb = cookie_value(&cb).unwrap();
    let (status, _h, body) = call(
        &state,
        post_form(
            "/edit/spec",
            &cb,
            Some("bob@steadholme.local"),
            &[
                ("csrf_token", &tb),
                ("base_rev", &base),
                ("title", "Spec"),
                ("body_md", "bob update"),
            ],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "stale base_rev is rejected");
    assert!(body.contains("Edit conflict"), "{body}");
    assert!(
        body.contains("alice update"),
        "shows the version that landed: {body}"
    );
    assert!(
        body.contains("bob update"),
        "shows the rejected submission: {body}"
    );

    // Bob's write did NOT land: the page + history still hold alice's version only.
    let (_s, _h, page) = call(&state, get("/w/spec")).await;
    assert!(page.contains("alice update"));
    assert!(!page.contains("bob update"));
    // original + alice update == 2 revisions (bob's rejected).
    assert_eq!(
        state.store.list_revisions("spec").await.unwrap().len(),
        2,
        "conflict wrote nothing"
    );
}

#[tokio::test]
async fn matching_base_rev_saves_normally() {
    let state = build_dev_state();
    // Create.
    let (_s, h0, _b) = call(&state, get("/edit/doc2")).await;
    let c0 = set_cookie(&h0).unwrap();
    let t0 = cookie_value(&c0).unwrap();
    call(
        &state,
        post_form(
            "/edit/doc2",
            &c0,
            Some("alice@steadholme.local"),
            &[
                ("csrf_token", &t0),
                ("base_rev", ""),
                ("title", "Doc2"),
                ("body_md", "v1"),
            ],
        ),
    )
    .await;

    // Reopen the editor: the hidden base_rev now carries the current head id.
    let (_s, h1, edit_body) = call(&state, get("/edit/doc2")).await;
    let head = state.store.head_revision("doc2").await.unwrap().unwrap();
    assert!(
        edit_body.contains(&format!("name=\"base_rev\" value=\"{}\"", head.id)),
        "editor carries head rev"
    );
    let c1 = set_cookie(&h1).unwrap();
    let t1 = cookie_value(&c1).unwrap();

    // Save against the fresh base -> succeeds.
    let (status, _h, _b) = call(
        &state,
        post_form(
            "/edit/doc2",
            &c1,
            Some("alice@steadholme.local"),
            &[
                ("csrf_token", &t1),
                ("base_rev", &head.id),
                ("title", "Doc2"),
                ("body_md", "v2"),
            ],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "up-to-date save is applied");
    assert_eq!(state.store.list_revisions("doc2").await.unwrap().len(), 2);
}

#[tokio::test]
async fn unknown_route_renders_404() {
    let state = build_dev_state();
    let (status, _h, body) = call(&state, get("/no/such/path")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("Not found"));
}

// --- helpers ---------------------------------------------------------------------------

async fn save_page_http(state: &AppState, slug: &str, title: &str, body: &str, email: &str) {
    let (_status, headers, _body) = call(state, get(&format!("/edit/{slug}"))).await;
    let cookie = set_cookie(&headers).expect("editor sets CSRF cookie");
    let csrf = cookie_value(&cookie).unwrap();
    let base_rev = state
        .store
        .head_revision(slug)
        .await
        .unwrap()
        .map(|r| r.id)
        .unwrap_or_default();
    let (status, _headers, _body) = call(
        state,
        post_form(
            &format!("/edit/{slug}"),
            &cookie,
            Some(email),
            &[
                ("csrf_token", &csrf),
                ("base_rev", &base_rev),
                ("title", title),
                ("body_md", body),
            ],
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "save_page_http should save {slug}"
    );
}

async fn call(state: &AppState, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, String) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, headers, String::from_utf8(bytes.to_vec()).unwrap())
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

async fn pause_for_distinct_ts() {
    tokio::time::sleep(Duration::from_millis(2)).await;
}

fn post_form(
    uri: &str,
    cookie: &str,
    email: Option<&str>,
    pairs: &[(&str, &str)],
) -> Request<Body> {
    let body = form_encode(pairs);
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if !cookie.is_empty() {
        builder = builder.header(header::COOKIE, cookie);
    }
    if let Some(e) = email {
        builder = builder.header("x-auth-email", e);
    }
    builder.body(Body::from(body)).unwrap()
}

/// Percent-encode a list of key/value pairs as application/x-www-form-urlencoded.
fn form_encode(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", pct(k), pct(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn pct(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn set_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// Extract the `name=value` (first segment) from a Set-Cookie header.
fn cookie_value(set_cookie: &str) -> Option<String> {
    let first = set_cookie.split(';').next()?;
    let (_name, value) = first.split_once('=')?;
    Some(value.to_string())
}

fn location(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}
