//! Aperture — enterprise image/screenshot host + file drive for the HOLDFAST stack.
//!
//! Library root: defines [`AppState`], wires the routes via [`app`], and provides
//! [`build_dev_state`] (in-memory metadata + in-memory blobs) and [`build_state_from_env`]
//! (env-selected metadata store + blob store). Integration tests consume [`app`] directly via
//! `tower::oneshot`, exactly like the rest of the estate.
//!
//! Endpoints (served at the subdomain ROOT — Sluice forwards the path unmodified):
//! - `GET /healthz` — liveness (public)
//! - `GET /` — the signed-in user's drive (gallery grid + upload dropzone) [SSO]
//! - `POST /upload` — multipart upload -> store blob in Cairn + metadata row -> 302 `/f/{id}` [SSO]
//! - `GET /f/{id}` — file detail / preview page (owner-only) [SSO]
//! - `GET /f/{id}/raw` — stream the blob (inline image / attachment) (owner-only) [SSO]
//! - `POST /delete/{id}` — delete your own file (blob + row) -> 302 `/` (CSRF) [SSO]
//! - `GET /s/{token}` — fetch a shared file by unguessable token, NO SSO [PUBLIC `/s/` prefix]

pub mod auth;
pub mod blobs;
pub mod config;
pub mod error;
pub mod handlers;
pub mod model;
pub mod store;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::blobs::{Blobs, MemoryBlobs, S3Blobs};
use crate::config::Config;
use crate::store::{InMemoryStore, PgStore, Store};

/// Shared application state. Cheap to clone (everything behind `Arc`).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
    pub blobs: Arc<dyn Blobs>,
}

/// Build the router wiring all endpoints onto `state`. Routes are explicit (no fallback): the
/// service owns its subdomain, so Sluice forwards these exact paths. The body limit is sized to
/// the configured `MAX_UPLOAD` plus a small multipart-envelope headroom.
pub fn app(state: AppState) -> Router {
    // 1 MiB of headroom for multipart boundaries/headers above the file cap.
    let body_limit = state.config.max_upload.saturating_add(1024 * 1024);
    Router::new()
        .route("/healthz", get(handlers::health::healthz))
        .route("/", get(handlers::files::gallery))
        .route("/upload", post(handlers::files::upload))
        .route("/f/{id}", get(handlers::files::detail))
        .route("/f/{id}/raw", get(handlers::files::raw))
        .route("/delete/{id}", post(handlers::files::delete))
        .route("/s/{token}", get(handlers::files::share))
        .layer(DefaultBodyLimit::max(body_limit))
        .with_state(state)
}

/// Construct dev state: dev [`Config`] + empty in-memory metadata + in-memory blobs. Used by
/// `main`'s memory mode and by the integration tests, so they need NO database and NO Cairn.
pub fn build_dev_state() -> AppState {
    AppState {
        config: Arc::new(Config::dev()),
        store: Arc::new(InMemoryStore::new()),
        blobs: Arc::new(MemoryBlobs::new()),
    }
}

/// Build runtime state from the environment.
///
/// [`Config`] comes from [`Config::from_env`]. The metadata store is selected by `APERTURE_STORE`
/// (`memory` default | `postgres`); the blob store by `APERTURE_BLOBS` (`memory` default | `s3`).
/// Returns an error string on misconfiguration so `main` can fail loudly.
pub async fn build_state_from_env() -> Result<AppState, String> {
    let config = Config::from_env();

    let store_kind = std::env::var("APERTURE_STORE").unwrap_or_else(|_| "memory".to_string());
    let store: Arc<dyn Store> = match store_kind.as_str() {
        "postgres" => {
            let database_url = std::env::var("DATABASE_URL")
                .map_err(|_| "APERTURE_STORE=postgres requires DATABASE_URL".to_string())?;
            tracing::info!("APERTURE_STORE=postgres — connecting to database");
            let pg = PgStore::connect(&database_url)
                .await
                .map_err(|e| format!("connect postgres: {e}"))?;
            pg.migrate()
                .await
                .map_err(|e| format!("run migration: {e}"))?;
            tracing::info!("postgres metadata store ready (migrated)");
            Arc::new(pg)
        }
        "memory" => Arc::new(InMemoryStore::new()),
        other => return Err(format!("unknown APERTURE_STORE={other} (use memory|postgres)")),
    };

    let blobs_kind = std::env::var("APERTURE_BLOBS").unwrap_or_else(|_| "memory".to_string());
    let blobs: Arc<dyn Blobs> = match blobs_kind.as_str() {
        "s3" => {
            tracing::info!(
                endpoint = config.s3.endpoint,
                bucket = config.s3.bucket,
                "APERTURE_BLOBS=s3 — using Cairn object store"
            );
            Arc::new(S3Blobs::connect(&config.s3)?)
        }
        "memory" => Arc::new(MemoryBlobs::new()),
        other => return Err(format!("unknown APERTURE_BLOBS={other} (use memory|s3)")),
    };

    Ok(AppState {
        config: Arc::new(config),
        store,
        blobs,
    })
}

/// Current wall-clock time in epoch seconds (file `created_at` granularity).
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs() as i64
}

/// Generate a random URL-safe alphanumeric string of `len` characters from a 62-symbol alphabet,
/// via the OS CSPRNG. Used for the file id, the share token, and the CSRF token. The modulo over
/// 62 introduces a negligible bias that is irrelevant for ids/tokens of this size.
pub fn random_alnum(len: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect()
}
