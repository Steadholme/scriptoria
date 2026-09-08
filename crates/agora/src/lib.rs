//! Agora — server-rendered discussion forum for the Steadholme stack.
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
//!   rendered) + reply form. `?before=`/`?after=` page older/newer, `?latest=1` jumps to the
//!   newest page.
//! - `GET  /new?cat=`        new-thread form (with live "similar existing threads" hints)
//! - `POST /new`             create a thread
//! - `POST /t/{id}/reply`    post a reply
//! - `POST /t/{id}/read`     mark only the currently rendered posts read, then continue
//! - `GET/POST /t/{id}/edit` edit one's OWN thread (title + original-post body)
//! - `GET/POST /t/{id}/delete`   review, then delete one's OWN thread (and all its posts)
//! - `GET/POST /t/{tid}/p/{pid}/edit`   edit one's OWN reply
//! - `GET/POST /t/{tid}/p/{pid}/delete` review, then delete one's OWN reply
//! - `POST /t/{tid}/p/{pid}/react`      toggle a reaction (up/heart) on a post
//! - `POST /t/{id}/accept`   thread author/admin explicitly accept or clear an accepted answer
//! - `POST /t/{id}/subscribe` toggle the current user's thread subscription
//! - `GET  /for-you`          private, explainable personal thread feed
//! - `GET  /bookmarks`       personal All/Due/Scheduled bookmark queue
//! - `GET  /search`           shareable thread + accepted-answer search (`?q=&category=&status=`)
//! - `GET  /api/search/suggest` bounded same-origin quick-search suggestions
//! - `POST /api/similar`     (sso+CSRF) top-3 existing threads similar to a draft {title,body}
//! - `GET  /api/thread/{id}/summary`  extractive summary (top sentences) of a thread

pub mod audit;
pub mod auth;
pub mod config;
pub mod error;
pub mod handlers;
pub mod markdown;
pub mod model;
pub mod notify;
pub mod store;
pub mod textsim;
pub mod view_model;
pub mod views;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::routing::{get, post};
use axum::{
    http::{header, HeaderValue},
    response::{IntoResponse, Response},
};
use axum::Router;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::audit::AuditSink;
use crate::config::{env_nonempty, Config};
use crate::model::{Category, CategoryFormat};
pub use crate::notify::KlaxonNotifier;
use crate::store::{InMemoryStore, PgStore, Store};

/// Shared application state. Cheap to clone (everything behind `Arc` / a cloneable sink).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
    pub audit: AuditSink,
    pub klaxon: Option<Arc<KlaxonNotifier>>,
}

/// Build the router wiring all endpoints onto `state`.
///
/// The home page is registered as the fallback (not just `GET /`): Sluice forwards the
/// gateway route host at the subdomain ROOT, so the home view renders for any otherwise
/// unmatched path too, with no per-deployment path config.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(handlers::health::healthz))
        .route(views::shell::APP_CSS_PATH, get(app_css_asset))
        .route("/", get(handlers::forum::home))
        .route("/for-you", get(handlers::forum::for_you))
        .route("/focus", get(handlers::forum::focus))
        .route("/questions", get(handlers::forum::questions))
        .route("/activity", get(handlers::activity::page))
        .route(
            "/activity/read-page",
            post(handlers::activity::mark_page_read),
        )
        .route("/activity/{id}/open", post(handlers::activity::open))
        .route(
            "/activity/{id}/state",
            post(handlers::activity::set_read_state),
        )
        .route("/bookmarks", get(handlers::bookmarks::page))
        .route(
            "/bookmarks/{pid}/edit",
            get(handlers::bookmarks::edit_form).post(handlers::bookmarks::update),
        )
        .route(
            "/bookmarks/{pid}/complete",
            post(handlers::bookmarks::complete),
        )
        .route("/bookmarks/{pid}/snooze", post(handlers::bookmarks::snooze))
        .route("/bookmarks/{pid}/remove", post(handlers::bookmarks::remove))
        .route("/c/{id}", get(handlers::forum::category))
        .route("/c/{id}/focus", post(handlers::forum::set_category_focus))
        .route("/t/{id}", get(handlers::forum::thread))
        .route("/t/{id}/read", post(handlers::forum::mark_thread_read))
        .route("/t/{id}/reply", post(handlers::forum::reply))
        .route(
            "/t/{id}/edit",
            get(handlers::forum::edit_thread_form).post(handlers::forum::update_thread),
        )
        .route(
            "/t/{id}/delete",
            get(handlers::forum::delete_thread_review).post(handlers::forum::delete_thread),
        )
        .route(
            "/t/{tid}/p/{pid}/edit",
            get(handlers::forum::edit_reply_form).post(handlers::forum::update_reply),
        )
        .route(
            "/t/{tid}/p/{pid}/delete",
            get(handlers::forum::delete_reply_review).post(handlers::forum::delete_reply),
        )
        .route("/t/{tid}/p/{pid}/react", post(handlers::forum::react))
        .route(
            "/t/{tid}/p/{pid}/bookmark",
            post(handlers::bookmarks::ensure),
        )
        .route("/t/{id}/accept", post(handlers::forum::accept_answer))
        .route(
            "/t/{id}/subscribe",
            post(handlers::forum::toggle_subscription),
        )
        .route(
            "/new",
            get(handlers::forum::new_form).post(handlers::forum::create),
        )
        .route("/search", get(handlers::search::page))
        .route("/api/search/suggest", get(handlers::search::suggest))
        .route("/api/similar", post(handlers::insight::similar))
        .route("/api/thread/{id}/summary", get(handlers::insight::summary))
        .merge(admin_router())
        .fallback(get(handlers::forum::home))
        // Reject a forged gateway identity (spoofed X-Auth-* from a rogue in-network peer):
        // production requires a signed subject on every product route; health remains independent.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_gateway_sig,
        ))
        // Outermost response policy: every dynamic response is no-store/nosniff, including a
        // gateway rejection. API and enhanced JSON errors receive the stable safe envelope.
        .layer(axum::middleware::from_fn(private_dynamic_no_store))
        .with_state(state)
}

async fn app_css_asset() -> Response {
    let mut response = views::shell::app_css().into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/css; charset=utf-8"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

async fn private_dynamic_no_store(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let is_static_asset = matches!(
        *req.method(),
        axum::http::Method::GET | axum::http::Method::HEAD
    ) && req.uri().path() == views::shell::APP_CSS_PATH;
    let wants_json = req.uri().path().starts_with("/api/")
        || req
            .headers()
            .get(axum::http::header::ACCEPT)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("application/json"));
    let mut response = next.run(req).await;
    if is_static_asset {
        return response;
    }
    let status = response.status();
    if wants_json && (status.is_client_error() || status.is_server_error()) {
        response = (
            status,
            axum::Json(serde_json::json!({
                "error": {
                    "code": stable_error_code(status),
                    "correlation_id": serde_json::Value::Null,
                }
            })),
        )
            .into_response();
    }
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("private, no-store"),
    );
    response.headers_mut().insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    response
}

fn stable_error_code(status: axum::http::StatusCode) -> &'static str {
    match status {
        axum::http::StatusCode::BAD_REQUEST => "invalid_request",
        axum::http::StatusCode::UNAUTHORIZED => "unauthorized",
        axum::http::StatusCode::FORBIDDEN => "forbidden",
        axum::http::StatusCode::NOT_FOUND => "not_found",
        axum::http::StatusCode::CONFLICT => "conflict",
        _ => "server_error",
    }
}

/// The `/admin` subtree, gated as one unit by [`require_admin_mw`]: category CRUD, thread
/// moderation (lock/pin/move/delete), any-post deletion, and the author blocklist. Merged into
/// [`app`] so the group check lives in exactly one place — no per-handler repetition.
fn admin_router() -> Router<AppState> {
    Router::new()
        .route("/admin", get(handlers::admin::dashboard))
        .route("/admin/categories", post(handlers::admin::create_category))
        .route(
            "/admin/categories/{id}/rename",
            post(handlers::admin::rename_category),
        )
        .route(
            "/admin/categories/{id}/format",
            post(handlers::admin::set_category_format),
        )
        .route(
            "/admin/categories/{id}/reorder",
            post(handlers::admin::reorder_category),
        )
        .route(
            "/admin/categories/{id}/delete",
            get(handlers::admin::delete_category_review).post(handlers::admin::delete_category),
        )
        .route(
            "/admin/threads/{id}/lock",
            post(handlers::admin::lock_thread),
        )
        .route("/admin/threads/{id}/pin", post(handlers::admin::pin_thread))
        .route(
            "/admin/threads/{id}/move",
            post(handlers::admin::move_thread),
        )
        .route(
            "/admin/threads/{id}/delete",
            get(handlers::admin::delete_thread_review).post(handlers::admin::delete_thread),
        )
        .route(
            "/admin/posts/{id}/delete",
            get(handlers::admin::delete_post_review).post(handlers::admin::delete_post),
        )
        .route("/admin/bans", post(handlers::admin::add_ban))
        .route("/admin/bans/delete", post(handlers::admin::remove_ban))
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
    let require_subject = state.config.is_production()
        && !matches!(req.uri().path(), "/healthz" | views::shell::APP_CSS_PATH);
    if auth::gateway_identity_ok_for(
        req.headers(),
        state.config.gateway_hmac_key(),
        require_subject,
    ) {
        next.run(req).await
    } else {
        crate::error::AppError::Unauthorized(
            "invalid or missing signed gateway identity".to_string(),
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
            format: CategoryFormat::Discussion,
        },
        Category {
            id: "general".to_string(),
            name: "General Discussion".to_string(),
            sort_order: 1,
            format: CategoryFormat::Discussion,
        },
        Category {
            id: "support".to_string(),
            name: "Support".to_string(),
            sort_order: 2,
            format: CategoryFormat::Question,
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
        klaxon: None,
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
    let config = Config::from_env()?;

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
        klaxon: KlaxonNotifier::from_env().map(Arc::new),
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

#[cfg(test)]
mod runtime_policy_tests {
    use axum::body::Body;
    use axum::http::{header, Request, StatusCode};
    use tower::ServiceExt;

    use super::Config;
    use crate::config::RuntimeProfile;

    #[tokio::test]
    async fn production_router_requires_a_signed_subject_but_keeps_health_independent() {
        let mut state = super::build_dev_state().await;
        let mut config = Config::dev();
        config.profile = RuntimeProfile::Production;
        state.config = std::sync::Arc::new(config);

        let response = super::app(state.clone())
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "private, no-store"
        );

        let response = super::app(state.clone())
            .oneshot(
                Request::builder()
                    .uri(crate::views::shell::APP_CSS_PATH)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/css; charset=utf-8"
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "public, max-age=31536000, immutable"
        );

        let response = super::app(state)
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
