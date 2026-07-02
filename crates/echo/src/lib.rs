//! Echo — embeddable threaded-comments service for the HOLDFAST stack.
//!
//! Library root: defines [`AppState`], wires the routes via [`app`], and provides
//! [`build_dev_state`] (in-memory store, disabled audit — no database, no network) and
//! [`build_state_from_env`] (env-selected store + Watchtower audit). Integration tests consume
//! [`app`] directly via `tower::oneshot`, exactly like the rest of the estate.
//!
//! Echo sits behind a Sluice `auth=sso` route at the subdomain ROOT (`comments.w33d.xyz`); the
//! gateway forwards the path UNMODIFIED, so the routes below are the real paths. Every endpoint
//! is internal-only and trusts the gateway-injected `X-Auth-*`; there is no public, unauthed API.
//!
//! Endpoints:
//! - `GET  /healthz`        liveness (container HEALTHCHECK; no auth)
//! - `GET  /`               dashboard: all threads + counts + recent activity + moderation
//! - `GET  /t/{key}`        a single thread view + composer (?sort=, ?before= keyset page)
//! - `POST /api/comment`    upsert thread by key + insert a comment (CSRF)
//! - `POST /api/comment/edit`   author self-edit of one's OWN comment (CSRF)
//! - `POST /api/comment/delete` author self-delete of one's OWN comment (CSRF)
//! - `POST /api/comment/react`  toggle a reaction on a comment (CSRF)
//! - `POST /api/comment/vote`   toggle an up/down vote on a comment (CSRF)
//! - `POST /api/comment/report` report/flag a comment for moderation (CSRF)
//! - `POST /api/moderate`   hide / unhide a comment (CSRF + moderator group)
//! - `GET  /embed/{key}`    a minimal, iframe-able thread + composer (X-Frame-Options SAMEORIGIN)
//! - `GET  /admin`          moderation panel: all comments + bulk controls + author blocklist (admin)
//! - `POST /admin/moderate` bulk hide / unhide / delete-any on selected comments (CSRF + admin)
//! - `POST /admin/block`    add an author to the blocklist, hiding their comments (CSRF + admin)
//! - `POST /admin/unblock`  remove an author from the blocklist (CSRF + admin)

pub mod audit;
pub mod auth;
pub mod config;
pub mod error;
pub mod handlers;
pub mod markdown;
pub mod store;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::routing::{get, post};
use axum::Router;

use crate::audit::AuditSink;
use crate::config::{env_nonempty, Config};
use crate::store::{InMemoryStore, PgStore, Store};

/// Shared application state. Cheap to clone (everything behind `Arc` / a cloneable sink).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
    pub audit: AuditSink,
}

/// Build the router wiring all endpoints onto `state`. Routes are explicit (no fallback): the
/// service owns its subdomain, so Sluice forwards these exact paths.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(handlers::health::healthz))
        .route("/", get(handlers::comments::dashboard))
        .route("/t/{key}", get(handlers::comments::thread_view))
        .route("/embed/{key}", get(handlers::comments::embed_view))
        .route("/api/comment", post(handlers::comments::post_comment))
        .route("/api/comment/edit", post(handlers::comments::edit_comment))
        .route(
            "/api/comment/delete",
            post(handlers::comments::delete_comment),
        )
        .route("/api/comment/react", post(handlers::comments::react))
        .route("/api/comment/vote", post(handlers::comments::vote))
        .route("/api/comment/report", post(handlers::comments::report))
        .route("/api/moderate", post(handlers::comments::moderate))
        // Admin panel subtree — every route is gated by `require_admin` (403 for non-admins).
        .route("/admin", get(handlers::admin::dashboard))
        .route("/admin/moderate", post(handlers::admin::moderate))
        .route("/admin/block", post(handlers::admin::block))
        .route("/admin/unblock", post(handlers::admin::unblock))
        // Reject a forged gateway identity (spoofed X-Auth-* from a rogue in-network peer):
        // when GATEWAY_HMAC_KEY is set, an injected identity MUST carry a valid X-Auth-Sig.
        // No-op when the key is unset or no identity is present (health/dev).
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

/// Construct dev state: dev [`Config`], an empty [`InMemoryStore`], and a disabled audit sink (no
/// network). Used by `main`'s memory mode and the integration tests, so they need no database.
pub fn build_dev_state() -> AppState {
    AppState {
        config: Arc::new(Config::dev()),
        store: Arc::new(InMemoryStore::new()),
        audit: AuditSink::disabled(),
    }
}

/// Build runtime state from the environment.
///
/// [`Config`] comes from [`Config::from_env`]. The store is selected by `ECHO_STORE`:
/// - `memory` (default): empty [`InMemoryStore`] — no database required.
/// - `postgres`: connect `DATABASE_URL`, run the idempotent migration, wire [`PgStore`].
///
/// The audit sink is enabled by `AUDIT_ENABLED` + `WATCHTOWER_URL` + `AUDIT_INGEST_TOKEN`.
/// Returns an error string on misconfiguration so `main` can fail loudly.
pub async fn build_state_from_env() -> Result<AppState, String> {
    let config = Config::from_env();

    let store_kind = env_nonempty("ECHO_STORE").unwrap_or_else(|| "memory".to_string());
    let store: Arc<dyn Store> = match store_kind.as_str() {
        "postgres" => {
            let database_url = env_nonempty("DATABASE_URL")
                .ok_or_else(|| "ECHO_STORE=postgres requires DATABASE_URL".to_string())?;
            tracing::info!("ECHO_STORE=postgres — connecting to database");
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
        other => return Err(format!("unknown ECHO_STORE={other} (use memory|postgres)")),
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

/// Current wall-clock time in epoch seconds (the `created_at` granularity).
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs() as i64
}

/// Monotonic-ish nanosecond counter for thread/comment id uniqueness.
pub fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos()
}

/// A short random hex suffix (8 bytes) for collision-resistant ids under the same nanosecond.
pub fn rand_suffix() -> String {
    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes).expect("OS CSPRNG unavailable");
    hex::encode(bytes)
}
