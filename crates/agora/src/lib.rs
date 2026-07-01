//! Agora — server-rendered discussion forum for the HOLDFAST stack.
//!
//! Library root: defines [`AppState`], wires the routes via [`app`], and provides
//! [`build_dev_state`] (in-memory store, seeded categories) and [`build_state_from_env`]
//! (env-selected store). Integration tests consume [`app`] directly via `tower::oneshot`,
//! exactly like keystone/keyward/beacon.
//!
//! It does NO login of its own: it sits behind a Sluice `auth=sso` route which injects the
//! verified `X-Auth-Subject` / `X-Auth-Email`, trusted as the post author and shown in the
//! app-bar. State-changing POSTs are CSRF-guarded (double-submit). All endpoints serve at the
//! subdomain ROOT (Sluice forwards the path unmodified).
//!
//! Endpoints:
//! - `GET  /healthz`         liveness (container HEALTHCHECK)
//! - `GET  /`                categories (with thread counts) + recent threads
//! - `GET  /c/{id}`          threads in a category
//! - `GET  /t/{id}`          a thread: original post + a keyset page of replies (markdown
//!                           rendered) + reply form. `?before=`/`?after=` page older/newer,
//!                           `?latest=1` jumps to the newest page.
//! - `GET  /new?cat=`        new-thread form (with live "similar existing threads" hints)
//! - `POST /new`             create a thread
//! - `POST /t/{id}/reply`    post a reply
//! - `GET/POST /t/{id}/edit` edit one's OWN thread (title + original-post body)
//! - `POST /t/{id}/delete`   delete one's OWN thread (and all its posts)
//! - `GET/POST /t/{tid}/p/{pid}/edit`   edit one's OWN reply
//! - `POST /t/{tid}/p/{pid}/delete`     delete one's OWN reply
//! - `POST /t/{tid}/p/{pid}/react`      toggle a reaction (up/heart) on a post
//! - `POST /t/{id}/accept`   thread author/admin mark (or unmark) a reply as the accepted answer
//! - `POST /api/similar`     (sso+CSRF) top-3 existing threads similar to a draft {title,body}
//! - `GET  /api/thread/{id}/summary`  extractive summary (top sentences) of a thread

pub mod audit;
pub mod auth;
pub mod config;
pub mod error;
pub mod handlers;
pub mod markdown;
pub mod model;
pub mod store;
pub mod textsim;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::routing::{get, post};
use axum::Router;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::audit::AuditSink;
use crate::config::{env_nonempty, Config};
use crate::model::Category;
use crate::store::{InMemoryStore, PgStore, Store};

/// Shared application state. Cheap to clone (everything behind `Arc` / a cloneable sink).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
    pub audit: AuditSink,
}

/// Build the router wiring all endpoints onto `state`.
///
/// The home page is registered as the fallback (not just `GET /`): Sluice forwards the
/// gateway route host at the subdomain ROOT, so the home view renders for any otherwise
/// unmatched path too, with no per-deployment path config.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(handlers::health::healthz))
        .route("/", get(handlers::forum::home))
        .route("/c/{id}", get(handlers::forum::category))
        .route("/t/{id}", get(handlers::forum::thread))
        .route("/t/{id}/reply", post(handlers::forum::reply))
        .route(
            "/t/{id}/edit",
            get(handlers::forum::edit_thread_form).post(handlers::forum::update_thread),
        )
        .route("/t/{id}/delete", post(handlers::forum::delete_thread))
        .route(
            "/t/{tid}/p/{pid}/edit",
            get(handlers::forum::edit_reply_form).post(handlers::forum::update_reply),
        )
        .route("/t/{tid}/p/{pid}/delete", post(handlers::forum::delete_reply))
        .route("/t/{tid}/p/{pid}/react", post(handlers::forum::react))
        .route("/t/{id}/accept", post(handlers::forum::accept_answer))
        .route("/new", get(handlers::forum::new_form).post(handlers::forum::create))
        .route("/api/similar", post(handlers::insight::similar))
        .route("/api/thread/{id}/summary", get(handlers::insight::summary))
        .merge(admin_router())
        .fallback(get(handlers::forum::home))
        // Reject a forged gateway identity (spoofed X-Auth-* from a rogue in-network peer):
        // when GATEWAY_HMAC_KEY is set, an injected identity MUST carry a valid X-Auth-Sig.
        // No-op when the key is unset or no identity is present (health/public/dev).
        .layer(axum::middleware::from_fn(require_gateway_sig))
        .with_state(state)
}

/// The `/admin` subtree, gated as one unit by [`require_admin_mw`]: category CRUD, thread
/// moderation (lock/pin/move/delete), any-post deletion, and the author blocklist. Merged into
/// [`app`] so the group check lives in exactly one place — no per-handler repetition.
fn admin_router() -> Router<AppState> {
    Router::new()
        .route("/admin", get(handlers::admin::dashboard))
        .route("/admin/categories", post(handlers::admin::create_category))
        .route("/admin/categories/{id}/rename", post(handlers::admin::rename_category))
        .route("/admin/categories/{id}/reorder", post(handlers::admin::reorder_category))
        .route("/admin/categories/{id}/delete", post(handlers::admin::delete_category))
        .route("/admin/threads/{id}/lock", post(handlers::admin::lock_thread))
        .route("/admin/threads/{id}/pin", post(handlers::admin::pin_thread))
        .route("/admin/threads/{id}/move", post(handlers::admin::move_thread))
        .route("/admin/threads/{id}/delete", post(handlers::admin::delete_thread))
        .route("/admin/posts/{id}/delete", post(handlers::admin::delete_post))
        .route("/admin/bans", post(handlers::admin::add_ban))
        .route("/admin/bans/{sub}/delete", post(handlers::admin::remove_ban))
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

/// The default categories seeded into an empty forum.
pub fn default_categories() -> Vec<Category> {
    vec![
        Category {
            id: "announcements".to_string(),
            name: "Announcements".to_string(),
            sort_order: 0,
        },
        Category {
            id: "general".to_string(),
            name: "General Discussion".to_string(),
            sort_order: 1,
        },
        Category {
            id: "support".to_string(),
            name: "Support".to_string(),
            sort_order: 2,
        },
    ]
}

/// Construct dev state: dev [`Config`] + an [`InMemoryStore`] seeded with the default
/// categories. Used by `main`'s memory mode and the integration tests, so they need no
/// database.
pub async fn build_dev_state() -> AppState {
    let store = Arc::new(InMemoryStore::new());
    store
        .seed_categories_if_empty(&default_categories())
        .await
        .expect("in-memory seed never fails");
    AppState {
        config: Arc::new(Config::dev()),
        store,
        audit: AuditSink::disabled(),
    }
}

/// Build runtime state from the environment.
///
/// [`Config`] comes from [`Config::from_env`]. The store is selected by `AGORA_STORE`:
/// - `memory` (default): empty [`InMemoryStore`] — no database required.
/// - `postgres`: connect `DATABASE_URL`, run the idempotent migration, wire [`PgStore`].
///
/// In both cases the categories table is seeded with the defaults ONLY when empty, so later
/// operator-created categories survive restarts. Returns an error string on misconfiguration.
pub async fn build_state_from_env() -> Result<AppState, String> {
    let config = Config::from_env();

    let store_kind = std::env::var("AGORA_STORE").unwrap_or_else(|_| "memory".to_string());
    let store: Arc<dyn Store> = match store_kind.as_str() {
        "postgres" => {
            let database_url = std::env::var("DATABASE_URL")
                .map_err(|_| "AGORA_STORE=postgres requires DATABASE_URL".to_string())?;
            tracing::info!("AGORA_STORE=postgres — connecting to database");
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
        other => return Err(format!("unknown AGORA_STORE={other} (use memory|postgres)")),
    };

    store
        .seed_categories_if_empty(&default_categories())
        .await
        .map_err(|e| format!("seed categories: {e}"))?;

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

/// Current wall-clock time in epoch seconds (thread/post timestamps).
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs() as i64
}

/// A fresh opaque id with a type prefix (e.g. `t_…` for threads, `p_…` for posts). 9 random
/// bytes -> 18 hex chars: collision-resistant without a coordinating sequence.
pub fn new_id(prefix: &str) -> String {
    let mut bytes = [0u8; 9];
    OsRng.fill_bytes(&mut bytes);
    format!("{prefix}_{}", hex::encode(bytes))
}
