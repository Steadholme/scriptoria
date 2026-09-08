//! End-to-end tests for the deepening: the backlink/related panel on a page, and the
//! `/coherence` maintenance view (stale pages + contradiction candidates).
//!
//! Drives the real `Router` in-process via `tower::oneshot`, in-memory store, NO database. Pages
//! are seeded directly through the `Store` so timestamps can be controlled (the HTTP save path
//! always stamps "now", which can't produce a stale page in a test).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use lattice::config::Config;
use lattice::store::{InMemoryStore, SaveInput, Store};
use lattice::{app, AppState};

const MS_PER_DAY: i64 = 86_400_000;

/// Build a state whose store is pre-seeded and whose `stale_days` is set for the test.
async fn seeded_state(stale_days: i64, pages: &[(&str, &str, &str, i64)]) -> AppState {
    let store = InMemoryStore::new();
    for (slug, title, body, updated_at) in pages {
        store
            .save_page(SaveInput {
                slug: slug.to_string(),
                title: title.to_string(),
                body_md: body.to_string(),
                editor_email: "curator@steadholme.local".to_string(),
                now: *updated_at,
                revision_id: format!("rev-{slug}-{updated_at}"),
            })
            .await
            .unwrap();
    }
    let mut config = Config::dev();
    config.stale_days = stale_days;
    AppState {
        config: Arc::new(config),
        store: Arc::new(store) as Arc<dyn Store>,
        audit: lattice::audit::AuditSink::disabled(),
    }
}

#[tokio::test]
async fn page_shows_backlinks_and_related_panel() {
    // `runbook` is referenced by `home` and `guide`; `restore` shares no link but overlapping
    // keywords with `runbook` (backup/database/restore) so it surfaces as Related.
    let state = seeded_state(
        120,
        &[
            (
                "runbook",
                "Runbook",
                "database backup restore snapshot retention steps",
                10,
            ),
            ("home", "Home", "Start at the [[Runbook]].", 10),
            (
                "guide",
                "Guide",
                "Follow the [[Runbook]] before deploy.",
                10,
            ),
            (
                "restore",
                "Restore Drill",
                "database restore snapshot retention recovery rehearsal",
                10,
            ),
            (
                "salad",
                "Salad",
                "lettuce tomato cucumber olive oil vinegar",
                10,
            ),
        ],
    )
    .await;

    let (status, _h, body) = call(&state, get("/w/runbook")).await;
    assert_eq!(status, StatusCode::OK);
    // The article itself still renders unchanged.
    assert!(body.contains("database backup restore"));
    // Linked from: both referencing pages, not the page itself.
    assert!(body.contains("Linked from"), "backlinks heading present");
    assert!(body.contains(r#"href="/w/home""#), "home backlink: {body}");
    assert!(body.contains(r#"href="/w/guide""#), "guide backlink");
    // Related: keyword neighbour surfaces; the unrelated salad page does not.
    assert!(body.contains("Related"), "related heading present");
    assert!(
        body.contains(r#"class="relation-link" href="/w/restore""#),
        "restore is keyword-related"
    );
    assert!(
        !body.contains(r#"class="relation-link" href="/w/salad""#),
        "unrelated pages may appear in the structure sidebar, but not the relation map"
    );
}

#[tokio::test]
async fn plain_page_exposes_isolation_as_a_coherence_signal() {
    // A lone page makes missing connections explicit instead of silently hiding the panel.
    let state = seeded_state(
        120,
        &[("solo", "Solo", "a wholly unique isolated note", 10)],
    )
    .await;
    let (status, _h, body) = call(&state, get("/w/solo")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Workspace health"));
    assert!(body.contains("Isolated"));
    assert!(!body.contains("Linked from"));
    assert!(!body.contains("Related"));
}

#[tokio::test]
async fn coherence_lists_stale_and_contradictions() {
    let now = lattice::now_ms();
    let fresh = now - 5 * MS_PER_DAY;
    let old = now - 400 * MS_PER_DAY;
    let state = seeded_state(
        120,
        &[
            (
                "fresh-note",
                "Fresh Note",
                "recently touched content here today",
                fresh,
            ),
            (
                "ancient",
                "Ancient Policy",
                "this has not changed in a long time",
                old,
            ),
            // Same title topic ("deploy process"), divergent bodies -> contradiction candidate.
            (
                "deploy-a",
                "Deploy Process",
                "ship via kubernetes helm rollout canary staging cluster",
                fresh,
            ),
            (
                "deploy-b",
                "Deploy Process Legacy",
                "deploy process copies tarballs over ftp by hand manually",
                fresh,
            ),
        ],
    )
    .await;

    let (status, _h, body) = call(&state, get("/coherence")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Workspace health"));
    // Stale section flags the ancient page (and links to it), not the fresh one.
    assert!(body.contains("Stale pages"));
    assert!(
        body.contains(r#"href="/w/ancient""#),
        "stale page linked: {body}"
    );
    assert!(
        !body.contains(r#"href="/w/fresh-note""#),
        "fresh page not stale"
    );
    // Contradiction section flags the same-topic divergent pair.
    assert!(body.contains("Contradiction candidates"));
    assert!(body.contains(r#"href="/w/deploy-a""#));
    assert!(body.contains(r#"href="/w/deploy-b""#));
}

#[tokio::test]
async fn coherence_empty_wiki_does_not_500() {
    let state = seeded_state(120, &[]).await;
    let (status, _h, body) = call(&state, get("/coherence")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Workspace health"));
    assert!(body.contains("0 pages"));
}

#[tokio::test]
async fn search_finds_title_and_body_matches_without_listing_unrelated_pages() {
    let state = seeded_state(
        120,
        &[
            (
                "runbook",
                "Recovery Runbook",
                "database restore snapshot retention steps",
                10,
            ),
            ("salad", "Lunch Notes", "lettuce tomato cucumber", 10),
        ],
    )
    .await;
    let (status, _h, body) = call(&state, get("/search?q=restore")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Recovery Runbook"));
    assert!(body.contains(r#"href="/w/runbook""#));
    assert!(!body.contains(r#"href="/w/salad""#));
}

// --- helpers ---------------------------------------------------------------------------

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
