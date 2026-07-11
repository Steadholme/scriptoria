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
//! - `GET  /tag/{slug}`     posts carrying a tag (keyset-paginated like the index)
//! - `GET  /search?q=`      full-text search over published posts (title + body), highlighted
//! - `GET  /feed.xml`       RSS 2.0 of the published posts (newest-first)
//! - `GET  /sitemap.xml`    sitemap of the index + published posts
//! - `GET  /new`            compose form
//! - `POST /new`            create a post (author from injected X-Auth-*, slug from title)
//! - `GET  /edit/{slug}`    edit form (own post)
//! - `POST /edit/{slug}`    update (own post)
//! - `POST /delete/{slug}`  delete (own post)

pub mod audit;
pub mod auth;
pub mod config;
pub mod error;
pub mod handlers;
pub mod index;
pub mod markdown;
pub mod store;
pub mod tags;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::routing::{get, post};
use axum::Router;

use crate::audit::AuditSink;
use crate::config::{env_nonempty, Config};
use crate::store::{Chunk, InMemoryStore, PgStore, Post, Store};

/// Shared application state. Cheap to clone (everything behind `Arc` / a cloneable sink).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
    pub audit: AuditSink,
}

/// Build the router wiring all endpoints onto `state`.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(handlers::health::healthz))
        .route("/", get(handlers::posts::index))
        .route("/p/{slug}", get(handlers::posts::view))
        // Tag listing: published posts (plus the viewer's own drafts) carrying a given tag,
        // keyset-paginated exactly like the index.
        .route("/tag/{slug}", get(handlers::posts::tag_index))
        // Full-text search over the published-post lexical index (title + body), highlighted.
        .route("/search", get(handlers::search::search_page))
        // Public discovery feeds derived from the published posts (read-only; no schema).
        .route("/feed.xml", get(handlers::feed::feed_xml))
        .route("/sitemap.xml", get(handlers::feed::sitemap_xml))
        .route(
            "/new",
            get(handlers::posts::new_form).post(handlers::posts::create),
        )
        .route(
            "/edit/{slug}",
            get(handlers::posts::edit_form).post(handlers::posts::update),
        )
        .route("/delete/{slug}", post(handlers::posts::delete))
        // Live Markdown preview for the editor (author-gated + CSRF, read-only JSON). Additive
        // progressive enhancement: the compose/edit form still POSTs and works without JS.
        .route("/api/preview", post(handlers::posts::preview))
        // Writer-only existing-tag autocomplete. Bounded, no-store, and read-only.
        .route("/api/tags", get(handlers::posts::tag_suggestions))
        // Admin panel: an all-authors post management table + single-row site settings. Every
        // route below is gated by `auth::require_admin` inside the handler (403 for non-admins).
        .route("/admin", get(handlers::admin::index))
        .route("/admin/settings", post(handlers::admin::update_settings))
        .route("/admin/posts/bulk", post(handlers::admin::bulk))
        .route("/admin/posts/{slug}/pin", post(handlers::admin::pin))
        .route(
            "/admin/posts/{slug}/feature",
            post(handlers::admin::feature),
        )
        .route(
            "/admin/posts/{slug}/unpublish",
            post(handlers::admin::unpublish),
        )
        .route("/admin/posts/{slug}/delete", post(handlers::admin::delete))
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
        audit: AuditSink::disabled(),
    }
}

/// Build runtime state from the environment.
///
/// [`Config`] comes from [`Config::from_env`]. The store is selected by `INKWELL_STORE`:
/// - `memory` (default): empty [`InMemoryStore`] — no database required.
/// - `postgres`: connect `DATABASE_URL`, run the idempotent migration, wire [`PgStore`].
///
/// The audit sink is enabled by `AUDIT_ENABLED` + `WATCHTOWER_URL` + `AUDIT_INGEST_TOKEN`.
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
        other => {
            return Err(format!(
                "unknown INKWELL_STORE={other} (use memory|postgres)"
            ))
        }
    };

    let audit = AuditSink::start(
        env_truthy("AUDIT_ENABLED"),
        &env_nonempty("WATCHTOWER_URL").unwrap_or_default(),
        env_nonempty("AUDIT_INGEST_TOKEN").as_deref(),
    );

    Ok(AppState {
        config: Arc::new(config),
        store,
        audit,
    })
}

/// Interpret a boolean-ish env var (`on` / `true` / `1` / `yes`, case-insensitive).
fn env_truthy(key: &str) -> bool {
    matches!(
        std::env::var(key)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "on" | "true" | "1" | "yes"
    )
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
// "Ask your blog" index orchestration
// ---------------------------------------------------------------------------
//
// The chunk table is a DERIVED cache of public posts. Authoring writes update it best-effort so a
// cache failure can never break the authoritative post save. Search and Ask incrementally repair a
// bounded number of missing/outdated public post versions, then read only chunks that still JOIN to
// a currently public post with the same `updated_at`. A failed cleanup therefore cannot leak a
// draft or stale body, and a request never rebuilds the complete corpus.

/// (Re)index a single post. A PUBLISHED post is chunked into the index; a DRAFT (or any unpublished
/// post) is de-indexed so it never surfaces in an answer. Best-effort: errors are logged only.
pub async fn reindex_post(store: &dyn Store, post: &Post) {
    let now = now_secs();
    let chunks = if post.is_public_at(now) {
        index::build_post_chunks(&post.slug, &post.title, &post.body_md, post.updated_at)
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

/// Return the bounded, visibility-validated public chunk snapshot used by Search and Ask.
///
/// Refresh and read failures are fail-closed and propagate to a 5xx; the existing cache is never
/// replaced wholesale. Store implementations enforce visibility and `updated_at` again at read
/// time, so stale Draft/future/old-body rows cannot enter a result even when cleanup failed.
pub async fn public_index_snapshot(store: &dyn Store) -> Result<Vec<Chunk>, store::StoreError> {
    let now = now_secs();
    store
        .refresh_public_chunks(now, config::INDEX_REFRESH_POST_LIMIT)
        .await?;
    store
        .fetch_public_chunks(now, config::INDEX_CHUNK_LIMIT)
        .await
}

/// Incrementally fill every missing public post version, then return the bounded valid chunk count.
/// This explicit maintenance helper may loop; request handlers call [`public_index_snapshot`] once.
pub async fn build_full_index(store: &dyn Store) -> i64 {
    let now = now_secs();
    loop {
        match store
            .refresh_public_chunks(now, config::INDEX_REFRESH_POST_LIMIT)
            .await
        {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(%error, "full public index refresh failed");
                return 0;
            }
        }
    }
    store
        .fetch_public_chunks(now, config::INDEX_CHUNK_LIMIT)
        .await
        .map(|chunks| chunks.len() as i64)
        .unwrap_or_else(|error| {
            tracing::warn!(%error, "full public index validated read failed");
            0
        })
}
