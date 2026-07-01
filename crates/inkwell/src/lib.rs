//! Inkwell — personal blog / CMS with SSO authoring for the HOLDFAST stack.
//!
//! Library root: defines [`AppState`], wires the routes via [`app`], and provides
//! [`build_dev_state`] (in-memory store) and [`build_state_from_env`] (env-selected store).
//! Integration tests consume [`app`] directly via `tower::oneshot`, exactly like the rest of
//! the estate.
//!
//! Inkwell sits behind a Sluice `auth=sso` route at the subdomain ROOT (`blog.w33d.xyz`); the
//! gateway forwards the path UNMODIFIED, so the routes below are the real paths.
//!
//! Endpoints:
//! - `GET  /healthz`        liveness (container HEALTHCHECK)
//! - `GET  /`               index: posts newest-first (title + excerpt + date + author)
//! - `GET  /p/{slug}`       full post (body markdown rendered to sanitized HTML)
//! - `GET  /new`            compose form
//! - `POST /new`            create a post (author from injected X-Auth-*, slug from title)
//! - `GET  /edit/{slug}`    edit form (own post)
//! - `POST /edit/{slug}`    update (own post)
//! - `POST /delete/{slug}`  delete (own post)

pub mod auth;
pub mod config;
pub mod error;
pub mod handlers;
pub mod index;
pub mod markdown;
pub mod store;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::routing::{get, post};
use axum::Router;

use crate::config::Config;
use crate::store::{InMemoryStore, PgStore, Post, Store};

/// Shared application state. Cheap to clone (everything behind `Arc`).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
}

/// Build the router wiring all endpoints onto `state`.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(handlers::health::healthz))
        .route("/", get(handlers::posts::index))
        .route("/p/{slug}", get(handlers::posts::view))
        .route(
            "/new",
            get(handlers::posts::new_form).post(handlers::posts::create),
        )
        .route(
            "/edit/{slug}",
            get(handlers::posts::edit_form).post(handlers::posts::update),
        )
        .route("/delete/{slug}", post(handlers::posts::delete))
        // "Ask your blog" — retrieval over the blog's own published posts (additive).
        .route("/ask", get(handlers::ask::ask_page))
        .route("/api/ask", post(handlers::ask::ask))
        // Reject a forged gateway identity (spoofed X-Auth-* from a rogue in-network peer):
        // when GATEWAY_HMAC_KEY is set, an injected identity MUST carry a valid X-Auth-Sig.
        // No-op when the key is unset or no identity is present (health/public/dev).
        .layer(axum::middleware::from_fn(require_gateway_sig))
        .with_state(state)
}

/// Middleware enforcing [`auth::gateway_identity_ok`] — 401 on a missing/invalid signature.
async fn require_gateway_sig(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if auth::gateway_identity_ok(req.headers()) {
        next.run(req).await
    } else {
        (
            axum::http::StatusCode::UNAUTHORIZED,
            "invalid or missing gateway identity signature",
        )
            .into_response()
    }
}

/// Construct dev state: dev [`Config`] + an empty [`InMemoryStore`]. Used by `main`'s memory
/// mode and the integration tests, so they need no database.
pub fn build_dev_state() -> AppState {
    AppState {
        config: Arc::new(Config::dev()),
        store: Arc::new(InMemoryStore::new()),
    }
}

/// Build runtime state from the environment.
///
/// [`Config`] comes from [`Config::from_env`]. The store is selected by `INKWELL_STORE`:
/// - `memory` (default): empty [`InMemoryStore`] — no database required.
/// - `postgres`: connect `DATABASE_URL`, run the idempotent migration, wire [`PgStore`].
///
/// Returns an error string on misconfiguration so `main` can fail loudly.
pub async fn build_state_from_env() -> Result<AppState, String> {
    let config = Config::from_env();

    let store_kind = std::env::var("INKWELL_STORE").unwrap_or_else(|_| "memory".to_string());
    let store: Arc<dyn Store> = match store_kind.as_str() {
        "postgres" => {
            let database_url = std::env::var("DATABASE_URL")
                .map_err(|_| "INKWELL_STORE=postgres requires DATABASE_URL".to_string())?;
            tracing::info!("INKWELL_STORE=postgres — connecting to database");
            let pg = PgStore::connect(&database_url)
                .await
                .map_err(|e| format!("connect postgres: {e}"))?;
            pg.migrate()
                .await
                .map_err(|e| format!("run migration: {e}"))?;
            tracing::info!("postgres store ready (migrated)");
            Arc::new(pg)
        }
        "memory" => Arc::new(InMemoryStore::new()),
        other => return Err(format!("unknown INKWELL_STORE={other} (use memory|postgres)")),
    };

    Ok(AppState {
        config: Arc::new(config),
        store,
    })
}

/// Current wall-clock time in epoch seconds (the post `created_at` / `updated_at`).
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs() as i64
}

/// Monotonic-ish nanosecond counter for post ids + slug-fallback uniqueness.
pub fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos()
}

/// Resolve a unique slug for a new post: slugify the title, then append `-2`, `-3`, … until it
/// is free. `fallback` (e.g. a nanosecond stamp) seeds the all-symbol/CJK title case.
pub async fn unique_slug(store: &dyn Store, title: &str, fallback: &str) -> String {
    let base = markdown::slugify(title, fallback);
    if store.get_post(&base).await.is_none() {
        return base;
    }
    let mut n = 2;
    loop {
        let candidate = format!("{base}-{n}");
        if store.get_post(&candidate).await.is_none() {
            return candidate;
        }
        n += 1;
    }
}

// ---------------------------------------------------------------------------
// "Ask your blog" index orchestration (best-effort; never fails the caller)
// ---------------------------------------------------------------------------
//
// The chunk index is a DERIVED view of the published posts. These helpers keep it in step with the
// authoring flow — a failure here is logged and swallowed so it can NEVER break post create / edit
// / delete, and the index is always self-healing (a lazy full rebuild runs on the first ask).

/// (Re)index a single post. A PUBLISHED post is chunked into the index; a DRAFT (or any unpublished
/// post) is de-indexed so it never surfaces in an answer. Best-effort: errors are logged only.
pub async fn reindex_post(store: &dyn Store, post: &Post) {
    let chunks = if post.published {
        index::build_post_chunks(&post.slug, &post.title, &post.body_md, now_secs())
    } else {
        Vec::new()
    };
    if let Err(e) = store.replace_post_chunks(&post.slug, chunks).await {
        tracing::warn!(slug = %post.slug, error = %e, "reindex_post failed (continuing)");
    }
}

/// Drop a post's chunks from the index (on delete). Best-effort.
pub async fn deindex_post(store: &dyn Store, slug: &str) {
    if let Err(e) = store.delete_post_chunks(slug).await {
        tracing::warn!(slug = %slug, error = %e, "deindex_post failed (continuing)");
    }
}

/// Full lazy rebuild: chunk every published post into a fresh index. Returns the chunk count.
/// Triggered on the first ask when the index is empty, so the feature works without an explicit
/// reindex step.
pub async fn build_full_index(store: &dyn Store) -> i64 {
    let now = now_secs();
    let mut chunks = Vec::new();
    for p in store.list_posts().await {
        if p.published {
            chunks.extend(index::build_post_chunks(&p.slug, &p.title, &p.body_md, now));
        }
    }
    match store.replace_all_chunks(chunks).await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "build_full_index failed (continuing)");
            0
        }
    }
}
