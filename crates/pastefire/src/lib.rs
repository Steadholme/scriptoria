//! Pastefire — enterprise pastebin / snippet host for the HOLDFAST stack.
//!
//! Library root: defines [`AppState`], wires the routes via [`app`], and provides
//! [`build_dev_state`] (in-memory store) and [`build_state_from_env`] (env-selected store).
//! Integration tests consume [`app`] directly via `tower::oneshot`, exactly like the rest of
//! the estate.
//!
//! Endpoints (served at the subdomain ROOT — Sluice forwards the path unmodified):
//! - `GET /healthz` — liveness (public)
//! - `GET /` — new-paste form + "my recent pastes" (SSO author)
//! - `POST /` — create a paste -> 302 `/p/{id}` (CSRF-checked)
//! - `GET /p/{id}` — view a paste, syntax-highlighted + "similar pastes" (honors expiry; a
//!   burn-after-read paste self-destructs on its first non-author view; a password-protected
//!   paste shows a prompt to non-owners)
//! - `GET /p/{id}/history` — the paste's revision history (access-gated like the paste)
//! - `GET /p/{id}/rev/{revision}` — a single archived revision, read-only
//! - `GET /raw/{id}` — the raw body as `text/plain` (honors expiry + burn)
//! - `POST /delete/{id}` — delete your own paste -> 302 `/` (CSRF-checked)
//! - `POST /unlock/{id}` — submit the password to reveal a protected paste (CSRF-checked)
//! - `GET/POST /edit/{id}` — owner edits their paste, prior version appended to history (CSRF)
//! - `POST /fork/{id}` — fork a paste into a new one crediting the source (CSRF-checked)

pub mod audit;
pub mod auth;
pub mod config;
pub mod error;
pub mod handlers;
pub mod highlight;
pub mod model;
pub mod similar;
pub mod store;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::routing::{get, post};
use axum::Router;
use rand::rngs::OsRng;
use rand::RngCore;

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
        .route("/", get(handlers::paste::new_form).post(handlers::paste::create))
        .route("/p/{id}", get(handlers::paste::view))
        .route("/p/{id}/history", get(handlers::paste::history))
        .route("/p/{id}/rev/{revision}", get(handlers::paste::view_revision))
        .route("/raw/{id}", get(handlers::paste::raw))
        .route("/delete/{id}", post(handlers::paste::delete))
        .route("/unlock/{id}", post(handlers::paste::unlock))
        .route(
            "/edit/{id}",
            get(handlers::paste::edit_form).post(handlers::paste::edit),
        )
        .route("/fork/{id}", post(handlers::paste::fork))
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
/// mode and by the integration tests, so they need no database.
pub fn build_dev_state() -> AppState {
    AppState {
        config: Arc::new(Config::dev()),
        store: Arc::new(InMemoryStore::new()),
        audit: AuditSink::disabled(),
    }
}

/// Build runtime state from the environment.
///
/// [`Config`] comes from [`Config::from_env`]. The store is selected by `PASTEFIRE_STORE`:
/// - `memory` (default): empty [`InMemoryStore`] — no database required.
/// - `postgres`: connect `DATABASE_URL`, run the idempotent migration, wire [`PgStore`].
///
/// The audit sink is enabled by `AUDIT_ENABLED` + `WATCHTOWER_URL` + `AUDIT_INGEST_TOKEN`.
/// Returns an error string on misconfiguration so `main` can fail loudly.
pub async fn build_state_from_env() -> Result<AppState, String> {
    let config = Config::from_env();

    let store_kind = std::env::var("PASTEFIRE_STORE").unwrap_or_else(|_| "memory".to_string());
    let store: Arc<dyn Store> = match store_kind.as_str() {
        "postgres" => {
            let database_url = std::env::var("DATABASE_URL")
                .map_err(|_| "PASTEFIRE_STORE=postgres requires DATABASE_URL".to_string())?;
            tracing::info!("PASTEFIRE_STORE=postgres — connecting to database");
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
                "unknown PASTEFIRE_STORE={other} (use memory|postgres)"
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

/// Current wall-clock time in epoch seconds (paste `created_at` / `expires_at` granularity).
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs() as i64
}

/// Generate a random URL-safe alphanumeric string of `len` characters from a 62-symbol
/// alphabet, via the OS CSPRNG. Used for both the short paste id and the CSRF token. The
/// modulo over 62 introduces a negligible bias that is irrelevant for ids/tokens of this size.
pub fn random_alnum(len: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect()
}
