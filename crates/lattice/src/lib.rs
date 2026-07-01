//! Lattice — server-rendered knowledge-base wiki for the HOLDFAST stack.
//!
//! Library root: defines [`AppState`], wires the routes via [`app`], and provides
//! [`build_dev_state`] (in-memory store) and [`build_state_from_env`] (env-selected store).
//! Integration tests consume [`app`] directly via `tower::oneshot`, exactly like the rest of
//! the estate.
//!
//! Lattice does NO login of its own: it sits behind a Sluice `auth=sso` route on
//! `wiki.w33d.xyz`, trusts the gateway-injected `X-Auth-Email`/`X-Auth-Subject` for the
//! editor/author, and serves at the subdomain ROOT (Sluice forwards the path unmodified — no
//! prefix to strip).
//!
//! Endpoints:
//! - `GET /healthz` — liveness (public; the container HEALTHCHECK).
//! - `GET /` — the page index (all pages).
//! - `GET /new?title=…` — convenience redirect to the editor for a slugified new page.
//! - `GET /w/{slug}` — render a page's markdown; if missing, offer to create it.
//! - `GET /edit/{slug}` / `POST /edit/{slug}` — edit; a save appends a revision + updates the page.
//! - `GET /history/{slug}` — the revision list.
//! - `GET /coherence` — maintenance view: stale pages + contradiction candidates (additive).

pub mod auth;
pub mod config;
pub mod error;
pub mod graph;
pub mod handlers;
pub mod markdown;
pub mod render;
pub mod slug;
pub mod store;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::routing::get;
use axum::Router;

use crate::config::Config;
use crate::store::{InMemoryStore, PgStore, Store};

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
        .route("/", get(handlers::pages::index))
        .route("/new", get(handlers::pages::new_page))
        .route("/w/{slug}", get(handlers::pages::view))
        .route(
            "/edit/{slug}",
            get(handlers::pages::edit_form).post(handlers::pages::edit_submit),
        )
        .route("/history/{slug}", get(handlers::pages::history))
        .route("/coherence", get(handlers::coherence::coherence))
        .fallback(handlers::pages::not_found)
        // Reject a forged gateway identity (spoofed X-Auth-* from a rogue in-network peer):
        // when GATEWAY_HMAC_KEY is set, an injected identity MUST carry a valid X-Auth-Sig.
        // No-op when the key is unset or no identity is present (healthz / dev).
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
/// mode and by the integration tests, so they need no database.
pub fn build_dev_state() -> AppState {
    AppState {
        config: Arc::new(Config::dev()),
        store: Arc::new(InMemoryStore::new()),
    }
}

/// Build runtime state from the environment.
///
/// [`Config`] comes from [`Config::from_env`]. The store is selected by `LATTICE_STORE`:
/// - `memory` (default): empty [`InMemoryStore`] — no database required.
/// - `postgres`: connect `DATABASE_URL`, run the idempotent migration, wire [`PgStore`].
pub async fn build_state_from_env() -> Result<AppState, String> {
    let config = Config::from_env();

    let store_kind = std::env::var("LATTICE_STORE").unwrap_or_else(|_| "memory".to_string());
    let store: Arc<dyn Store> = match store_kind.as_str() {
        "postgres" => {
            let database_url = std::env::var("DATABASE_URL")
                .map_err(|_| "LATTICE_STORE=postgres requires DATABASE_URL".to_string())?;
            tracing::info!("LATTICE_STORE=postgres — connecting to database");
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
        other => return Err(format!("unknown LATTICE_STORE={other} (use memory|postgres)")),
    };

    Ok(AppState {
        config: Arc::new(config),
        store,
    })
}

/// Current wall-clock time in epoch milliseconds (page `updated_at` + revision `ts`).
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_millis() as i64
}
