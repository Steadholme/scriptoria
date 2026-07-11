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
//! - `GET /requests` / `GET /requests/{id}` — list and inspect owner-scoped upload requests [SSO]
//! - `POST /folders/{id}/requests` — create an independent, finite upload request (CSRF) [SSO]
//! - `POST /requests/{id}/update|close|reopen|rotate` — manage policy and lifecycle (CSRF) [SSO]
//! - `POST /folders/{id}/upload|upload/revoke` — compatibility aliases for legacy folder upload
//!   links; newly created capabilities are backed by an independent request record [SSO]
//! - `GET /admin` — per-owner storage usage + quota overrides (admin groups only) [SSO]
//! - `POST /admin/quota` — set/clear an owner's quota override (CSRF) [SSO, admin]
//! - `GET /s/{token}` — fetch a shared file by unguessable token, NO SSO (410 past expiry;
//!   password prompt when protected) [PUBLIC `/s/` prefix]
//! - `POST /s/{token}` — submit a protected share link's password, NO SSO [PUBLIC `/s/` prefix]
//! - `GET /s/folder/{token}` — public index of a shared folder's files; `POST` unlocks a protected one;
//!   `GET|POST /s/folder/{token}/f/{fid}` downloads one listed file, NO SSO [PUBLIC `/s/folder/` prefix]
//! - `GET|POST /u/{token}` — public upload-only request room, NO SSO; cannot enumerate its private
//!   destination and enforces expiry/type/file/count/byte budgets [PUBLIC `/u/` prefix]
//! - `GET /s/share-room.css|js` — product-owned public Share Room assets [PUBLIC, read-only]

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
use crate::store::{InMemoryStore, PgStore, Store, UploadRecoveryClaim};

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
        .route("/s/share-room.css", get(handlers::share_room_css_asset))
        .route("/s/share-room.js", get(handlers::share_room_js_asset))
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
        // Inline file rename (owner-scoped + CSRF). Additive: form POST 302s, JSON for the
        // enhanced gallery. The form route stands alongside the JSON response via Accept.
        .route("/f/{id}/rename", post(handlers::files::rename))
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
        .route("/requests", get(handlers::requests::index))
        .route("/requests/{id}", get(handlers::requests::detail))
        .route("/folders/{id}/requests", post(handlers::requests::create))
        .route("/requests/{id}/update", post(handlers::requests::update))
        .route("/requests/{id}/close", post(handlers::requests::close))
        .route("/requests/{id}/reopen", post(handlers::requests::reopen))
        .route("/requests/{id}/rotate", post(handlers::requests::rotate))
        .route(
            "/s/{token}",
            get(handlers::files::share).post(handlers::files::share_unlock),
        )
        .route("/s/{token}/view", get(handlers::files::share_landing))
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
        // Verify injected identities and make owner routes fail closed when production receives no
        // identity at all. Only health + the existing /s and /u capability namespaces are anonymous.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_gateway_sig,
        ))
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
    axum::extract::State(state): axum::extract::State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let path = req.uri().path();
    let anonymous_capability =
        path == "/healthz" || path.starts_with("/s/") || path.starts_with("/u/");
    let has_identity = req
        .headers()
        .get(auth::HEADER_SUBJECT)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .is_some_and(|subject| !subject.is_empty());

    if !anonymous_capability
        && !state.config.allow_dev_identity
        && (!has_identity || !auth::gateway_identity_verification_enabled())
    {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            "gateway identity required",
        )
            .into_response();
    }

    if !auth::gateway_identity_ok(req.headers()) {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            "invalid or missing gateway identity signature",
        )
            .into_response();
    }

    next.run(req).await
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

    if !config.allow_dev_identity && !auth::gateway_identity_verification_enabled() {
        return Err(
            "production owner routes require a non-empty GATEWAY_HMAC_KEY for signed gateway identities"
                .to_string(),
        );
    }

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

    recover_stale_request_uploads(store.as_ref(), blobs.as_ref()).await?;

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

/// Reconcile public-upload reservations left by a process that stopped after reserving budget and
/// possibly writing its blob, but before committing file metadata. The Store lease is durable and
/// exactly one startup may complete each row: bytes are deleted first, then counters are returned.
/// A delete/metadata failure leaves the row unclaimed for the next startup and fails this startup.
///
/// Embedders that construct Aperture state themselves (the Scriptoria monolith) must call this
/// after the blob backend is ready and before serving the router.
pub async fn recover_stale_request_uploads(
    store: &dyn Store,
    blobs: &dyn Blobs,
) -> Result<(), String> {
    const RECOVERY_LEASE_TTL_SECS: i64 = 5 * 60;

    let leased_at = now_secs();
    let lease_id = random_alnum(32);
    let claim = store
        .claim_upload_recovery(
            &lease_id,
            leased_at,
            leased_at.saturating_sub(RECOVERY_LEASE_TTL_SECS),
        )
        .await
        .map_err(|error| format!("claim stale upload reservations: {error}"))?;
    let items = match claim {
        UploadRecoveryClaim::Empty => return Ok(()),
        UploadRecoveryClaim::Busy => {
            return Err(
                "stale upload reservation recovery is already leased by another startup"
                    .to_string(),
            )
        }
        UploadRecoveryClaim::Claimed(items) => items,
    };

    for (index, item) in items.iter().enumerate() {
        if let Err(error) = blobs.delete(&item.object_key).await {
            for pending in &items[index..] {
                let _ = store
                    .abandon_upload_recovery(&pending.reservation_id, &lease_id)
                    .await;
            }
            return Err(format!(
                "delete stale upload blob {}: {error}",
                item.object_key
            ));
        }
        match store
            .complete_upload_recovery(&item.reservation_id, &lease_id)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                for pending in &items[index..] {
                    let _ = store
                        .abandon_upload_recovery(&pending.reservation_id, &lease_id)
                        .await;
                }
                return Err(format!(
                    "stale upload reservation {} lost its recovery lease",
                    item.reservation_id
                ));
            }
            Err(error) => {
                for pending in &items[index..] {
                    let _ = store
                        .abandon_upload_recovery(&pending.reservation_id, &lease_id)
                        .await;
                }
                return Err(format!(
                    "complete stale upload reservation {}: {error}",
                    item.reservation_id
                ));
            }
        }
    }

    tracing::info!(count = items.len(), "stale public uploads recovered");
    Ok(())
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
