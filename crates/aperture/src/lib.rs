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
//! - `GET /f/{id}` — file detail / preview page: inline image (lightbox) / text / sandboxed PDF,
//!   version history, share + move controls (owner-only) [SSO]
//! - `GET /f/{id}/raw` — stream the blob (inline image / attachment) (owner-only) [SSO]
//! - `GET /f/{id}/preview-raw` — inline, sandboxed PDF bytes for the detail embed (owner-only) [SSO]
//! - `GET /f/{id}/versions/{vid}/raw` — download a retained version's blob (owner-only) [SSO]
//! - `POST /f/{id}/versions/{vid}/restore` — restore a version as the current blob (CSRF) [SSO]
//! - `GET /d/{id}/thumb` — gallery thumbnail: 302 to the full image, else a cached, mime-keyed type
//!   icon derived + cached as a `{object_key}.thumb` blob (owner-only) [SSO]
//! - `POST /delete/{id}` — move your own file to Trash -> 302 `/` (CSRF) [SSO]
//! - `GET /?view=trash` — the owner's trash/recycle bin; restore or delete forever [SSO]
//! - `POST /trash/{id}/restore` — restore a trashed file (CSRF) [SSO]
//! - `POST /trash/{id}/purge` — delete a trashed file forever (CSRF) [SSO]
//! - `POST /f/{id}/comments` — add a file comment (CSRF) [SSO]
//! - `POST /f/{id}/comments/{cid}/delete` — owner/admin delete a file comment (CSRF) [SSO]
//! - `POST /f/{id}/share` — set the share link's expiry + optional password (CSRF) [SSO]
//! - `POST /f/{id}/revoke` — revoke the share link (clears the token) (CSRF) [SSO]
//! - `POST /f/{id}/move` — move the file into a folder (or back to the root) (CSRF) [SSO]
//! - `GET /?folder={id}` — the drive tree at one folder level (default: root, `folder_id` NULL);
//!   renders a breadcrumb, child-folder tiles, an "Up" tile and the level's files [SSO]
//! - `POST /folders` — create a folder under the current level (`parent_id`) (CSRF) [SSO]
//! - `POST /folders/{id}/rename` — rename an owner folder (CSRF) [SSO]
//! - `POST /folders/{id}/delete` — delete a folder: empty-only, or `cascade=1` to remove the whole
//!   subtree (subfolders + files + version blobs) (CSRF) [SSO]
//! - `POST /folders/{id}/share` — set a folder's public share-link expiry + optional password (CSRF) [SSO]
//! - `POST /folders/{id}/revoke` — revoke a folder's public share link (CSRF) [SSO]
//! - `POST /folders/{id}/upload` — create a public upload-only request link (CSRF) [SSO]
//! - `POST /folders/{id}/upload/revoke` — revoke a public upload request link (CSRF) [SSO]
//! - `GET /admin` — per-owner storage usage + quota overrides (admin groups only) [SSO]
//! - `POST /admin/quota` — set/clear an owner's quota override (CSRF) [SSO, admin]
//! - `GET /s/{token}` — fetch a shared file by unguessable token, NO SSO (410 past expiry;
//!   password prompt when protected) [PUBLIC `/s/` prefix]
//! - `POST /s/{token}` — submit a protected share link's password, NO SSO [PUBLIC `/s/` prefix]
//! - `GET /s/folder/{token}` — public index of a shared folder's files; `POST` unlocks a protected one;
//!   `GET|POST /s/folder/{token}/f/{fid}` downloads one listed file, NO SSO [PUBLIC `/s/folder/` prefix]
//! - `GET|POST /u/{token}` — public upload-only inbox for a folder, NO SSO [PUBLIC `/u/` prefix]

pub mod audit;
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

use crate::audit::AuditSink;
use crate::blobs::{Blobs, MemoryBlobs, S3Blobs};
use crate::config::Config;
use crate::store::{InMemoryStore, PgStore, Store};

/// Shared application state. Cheap to clone (everything behind `Arc` / a cloneable sink).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
    pub blobs: Arc<dyn Blobs>,
    pub audit: AuditSink,
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
        .route("/f/{id}/preview-raw", get(handlers::files::preview_raw))
        .route(
            "/f/{id}/versions/{vid}/raw",
            get(handlers::files::download_version),
        )
        .route(
            "/f/{id}/versions/{vid}/restore",
            post(handlers::files::restore_version),
        )
        .route("/d/{id}/thumb", get(handlers::files::thumb))
        .route("/delete/{id}", post(handlers::files::delete))
        .route(
            "/trash/{id}/restore",
            post(handlers::files::restore_trashed),
        )
        .route("/trash/{id}/purge", post(handlers::files::purge_trashed))
        .route("/f/{id}/comments", post(handlers::files::add_comment))
        .route(
            "/f/{id}/comments/{cid}/delete",
            post(handlers::files::delete_comment),
        )
        .route("/f/{id}/share", post(handlers::files::configure_share))
        .route("/f/{id}/revoke", post(handlers::files::revoke_share))
        .route("/f/{id}/move", post(handlers::files::move_file))
        .route("/folders", post(handlers::files::create_folder))
        .route("/folders/{id}/rename", post(handlers::files::rename_folder))
        .route("/folders/{id}/delete", post(handlers::files::delete_folder))
        .route(
            "/folders/{id}/share",
            post(handlers::files::configure_folder_share),
        )
        .route(
            "/folders/{id}/revoke",
            post(handlers::files::revoke_folder_share),
        )
        .route(
            "/folders/{id}/upload",
            post(handlers::files::configure_folder_upload),
        )
        .route(
            "/folders/{id}/upload/revoke",
            post(handlers::files::revoke_folder_upload),
        )
        .route(
            "/s/{token}",
            get(handlers::files::share).post(handlers::files::share_unlock),
        )
        .route(
            "/s/folder/{token}",
            get(handlers::files::share_folder).post(handlers::files::share_folder_unlock),
        )
        .route(
            "/s/folder/{token}/f/{fid}",
            get(handlers::files::share_folder_file).post(handlers::files::share_folder_file_unlock),
        )
        .route(
            "/u/{token}",
            get(handlers::files::upload_inbox).post(handlers::files::upload_inbox_submit),
        )
        .merge(admin_router())
        .layer(DefaultBodyLimit::max(body_limit))
        // Reject a forged gateway identity (spoofed X-Auth-* from a rogue in-network peer):
        // when GATEWAY_HMAC_KEY is set, an injected identity MUST carry a valid X-Auth-Sig.
        // No-op when the key is unset or no identity is present (share route / dev).
        .layer(axum::middleware::from_fn(require_gateway_sig))
        .with_state(state)
}

/// The `/admin` subtree, gated as one unit by [`require_admin_mw`]: the per-owner storage usage
/// table + quota overrides. Merged into [`app`] BEFORE the shared layers, so the group check
/// lives in exactly one place and the gateway-signature guard still covers it.
fn admin_router() -> Router<AppState> {
    Router::new()
        .route("/admin", get(handlers::admin::index))
        .route("/admin/quota", post(handlers::admin::set_quota))
        .layer(axum::middleware::from_fn(require_admin_mw))
}

/// Middleware gating the whole `/admin` subtree on [`auth::require_admin`]. A non-admin (or
/// unauthenticated) request gets the branded `403`; only `admins` / `infra-admins` pass.
async fn require_admin_mw(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    match auth::require_admin(req.headers()) {
        Ok(()) => next.run(req).await,
        Err(e) => e.into_response(),
    }
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

/// Construct dev state: dev [`Config`] + empty in-memory metadata + in-memory blobs. Used by
/// `main`'s memory mode and by the integration tests, so they need NO database and NO Cairn.
pub fn build_dev_state() -> AppState {
    AppState {
        config: Arc::new(Config::dev()),
        store: Arc::new(InMemoryStore::new()),
        blobs: Arc::new(MemoryBlobs::new()),
        audit: AuditSink::disabled(),
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
        other => {
            return Err(format!(
                "unknown APERTURE_STORE={other} (use memory|postgres)"
            ))
        }
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

    // The audit sink is enabled by `AUDIT_ENABLED` + `WATCHTOWER_URL` + `AUDIT_INGEST_TOKEN`;
    // any misconfiguration only warns and turns audit OFF (never fails startup).
    let audit = AuditSink::start(
        env_truthy("AUDIT_ENABLED"),
        &std::env::var("WATCHTOWER_URL").unwrap_or_default(),
        std::env::var("AUDIT_INGEST_TOKEN").ok().as_deref(),
    );

    Ok(AppState {
        config: Arc::new(config),
        store,
        blobs,
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
