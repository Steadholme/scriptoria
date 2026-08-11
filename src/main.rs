//! Scriptoria — one container hosting the Steadholme content surfaces
//! (blog / forum / wiki / comments / paste / drive).
//!
//! Each surface is its OWN library crate (Inkwell/Agora/Lattice/Echo/Pastefire/Aperture), reused
//! verbatim: same schema, same routes, same templates, same OWN database, same subdomain. This
//! binary only adds a **Host-based vhost demux** so the estate runs ONE deployable instead of six.
//! Sluice points `blog.w33d.xyz`, `forum.w33d.xyz`, `wiki.w33d.xyz`, `comments.w33d.xyz`,
//! `paste.w33d.xyz` and `drive.w33d.xyz` all at this container; each request is dispatched to the
//! matching surface's router by its `Host` header. Because the surfaces keep their exact paths and
//! separate databases, Cortex's federation + its hard-coded `blog/forum/wiki.w33d.xyz/...` deep
//! links keep working unchanged, and Echo's iframe widget keeps framing under
//! `comments.w33d.xyz/embed/{key}` (its own `X-Frame-Options: SAMEORIGIN` headers are emitted by
//! Echo's handlers, unchanged).
//!
//! Echo (comments) also runs its OWN Watchtower audit sink; Aperture (drive) stores blobs in Cairn
//! S3 over its OWN reqwest+rustls client — both built explicitly below from each surface's OWN env.
//!
//! `healthcheck` subcommand: a dependency-free loopback `GET /healthz` (host-agnostic) used as the
//! container HEALTHCHECK, so the image needs no curl.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use tower::ServiceExt;

/// Safe development listener. Production containers set their routable address explicitly.
const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8700";

/// The six composed per-surface routers, dispatched by Host. Cheap to clone (each `Router` is
/// `Arc`-backed internally).
#[derive(Clone)]
struct Vhosts {
    blog: Router,
    forum: Router,
    wiki: Router,
    comments: Router,
    paste: Router,
    drive: Router,
}

#[tokio::main]
async fn main() {
    // Container HEALTHCHECK path — handled before any setup, exits the process.
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        std::process::exit(run_healthcheck());
    }

    tracing_subscriber::fmt::init();

    // Mandatory audit under the prod profile: a tamper-evident who-changed-what trail is a
    // baseline requirement once real users share these surfaces. Refuse to boot in prod with
    // audit disabled instead of silently keeping no record. Dev (profile unset) is unaffected.
    if require_persistence() && !env_truthy("AUDIT_ENABLED") {
        fatal(
            "audit",
            "STEADHOLME_PROFILE=prod (or REQUIRE_PERSISTENCE) requires AUDIT_ENABLED=true \
             (+ WATCHTOWER_URL + AUDIT_INGEST_TOKEN) so content mutations are recorded"
                .to_string(),
        );
    }

    let addr = listener_addr(std::env::var("BIND_ADDR").ok().as_deref())
        .unwrap_or_else(|error| fatal("listener", error));

    // Each surface connects to its OWN database and migrates idempotently — exactly what the
    // standalone service did. A failure here is fatal (the surface cannot serve without its DB).
    let blog = build_blog()
        .await
        .unwrap_or_else(|e| fatal("blog (inkwell)", e));
    let forum = build_forum()
        .await
        .unwrap_or_else(|e| fatal("forum (agora)", e));
    let wiki = build_wiki()
        .await
        .unwrap_or_else(|e| fatal("wiki (lattice)", e));
    let comments = build_comments()
        .await
        .unwrap_or_else(|e| fatal("comments (echo)", e));
    let paste = build_paste()
        .await
        .unwrap_or_else(|e| fatal("paste (pastefire)", e));
    let drive = build_drive()
        .await
        .unwrap_or_else(|e| fatal("drive (aperture)", e));

    let app = Router::new()
        // Host-agnostic liveness for the container HEALTHCHECK + estate probes.
        .route("/healthz", get(|| async { "ok" }))
        .fallback(dispatch)
        .with_state(Vhosts {
            blog,
            forum,
            wiki,
            comments,
            paste,
            drive,
        });

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));
    tracing::info!(%addr, "Scriptoria listening (blog/forum/wiki/comments/paste/drive vhost demux)");
    axum::serve(listener, app).await.expect("server error");
}

/// Dispatch one request to the surface matching its `Host` header. An unknown content host is a
/// 404 — we never silently serve one surface's content under another's vhost.
async fn dispatch(State(v): State<Vhosts>, req: Request) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    // Match on the leading label (`blog`/`forum`/`wiki`/`comments`/`paste`/`drive`), ignoring any
    // port.
    let label = host
        .split(':')
        .next()
        .unwrap_or("")
        .split('.')
        .next()
        .unwrap_or("");
    let router = match label {
        "forum" => v.forum,
        "wiki" => v.wiki,
        "blog" => v.blog,
        "comments" => v.comments,
        "paste" => v.paste,
        "drive" => v.drive,
        _ => return (StatusCode::NOT_FOUND, "unknown content host").into_response(),
    };
    // `Router` is a tower `Service` (the exact `app(state).oneshot(req)` path the surfaces' own
    // tests use); its error type is `Infallible`.
    match router.oneshot(req).await {
        Ok(resp) => resp,
        Err(e) => match e {},
    }
}

/// Build the blog (Inkwell) surface router against `INKWELL_DATABASE_URL`.
async fn build_blog() -> Result<Router, String> {
    let dsn = require_env("INKWELL_DATABASE_URL")?;
    let pg = inkwell::store::PgStore::connect(&dsn)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    pg.migrate().await.map_err(|e| format!("migrate: {e}"))?;
    tracing::info!("blog (inkwell) store ready");
    let audit = inkwell::audit::AuditSink::start(
        env_truthy("AUDIT_ENABLED"),
        &inkwell::config::env_nonempty("WATCHTOWER_URL").unwrap_or_default(),
        inkwell::config::env_nonempty("AUDIT_INGEST_TOKEN").as_deref(),
    );
    let state = inkwell::AppState {
        config: Arc::new(inkwell::config::Config::from_env()),
        store: Arc::new(pg),
        audit,
    };
    Ok(inkwell::app(state))
}

/// Build the forum (Agora) surface router against `AGORA_DATABASE_URL`, seeding default
/// categories when the table is empty (exactly as the standalone service does).
async fn build_forum() -> Result<Router, String> {
    let dsn = require_env("AGORA_DATABASE_URL")?;
    let pg = agora::store::PgStore::connect(&dsn)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    pg.migrate().await.map_err(|e| format!("migrate: {e}"))?;
    let store: Arc<dyn agora::store::Store> = Arc::new(pg);
    store
        .seed_categories_if_empty(&agora::default_categories())
        .await
        .map_err(|e| format!("seed categories: {e}"))?;
    tracing::info!("forum (agora) store ready");
    let audit = agora::audit::AuditSink::start(
        env_truthy("AUDIT_ENABLED"),
        &agora::config::env_nonempty("WATCHTOWER_URL").unwrap_or_default(),
        agora::config::env_nonempty("AUDIT_INGEST_TOKEN").as_deref(),
    );
    let state = agora::AppState {
        config: Arc::new(agora::config::Config::from_env()?),
        store,
        audit,
        klaxon: agora::KlaxonNotifier::from_env().map(Arc::new),
    };
    Ok(agora::app(state))
}

/// Build the wiki (Lattice) surface router against `LATTICE_DATABASE_URL`.
async fn build_wiki() -> Result<Router, String> {
    let dsn = require_env("LATTICE_DATABASE_URL")?;
    let pg = lattice::store::PgStore::connect(&dsn)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    pg.migrate().await.map_err(|e| format!("migrate: {e}"))?;
    tracing::info!("wiki (lattice) store ready");
    let audit = lattice::audit::AuditSink::start(
        env_truthy("AUDIT_ENABLED"),
        &lattice::config::env_nonempty("WATCHTOWER_URL").unwrap_or_default(),
        lattice::config::env_nonempty("AUDIT_INGEST_TOKEN").as_deref(),
    );
    let state = lattice::AppState {
        config: Arc::new(lattice::config::Config::from_env()),
        store: Arc::new(pg),
        audit,
    };
    Ok(lattice::app(state))
}

/// Build the comments (Echo) surface router against `ECHO_DATABASE_URL`, with Echo's OWN audit sink.
///
/// State is built EXPLICITLY (not via `echo::build_state_from_env`, which keys the store off
/// `ECHO_STORE`/the bare `DATABASE_URL` that would collide in-process): connect + migrate Echo's OWN
/// Postgres, start its OWN Watchtower audit emitter exactly as Echo does
/// (`AUDIT_ENABLED` + `WATCHTOWER_URL` + `AUDIT_INGEST_TOKEN`), and assemble the `AppState` Echo's
/// `app()` expects. Echo's handlers emit `X-Frame-Options: SAMEORIGIN` on `/embed/{key}` themselves
/// — unchanged — so the iframe widget the other content apps embed keeps framing.
async fn build_comments() -> Result<Router, String> {
    let dsn = require_env("ECHO_DATABASE_URL")?;
    let pg = echo::store::PgStore::connect(&dsn)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    pg.migrate().await.map_err(|e| format!("migrate: {e}"))?;
    tracing::info!("comments (echo) store ready");
    let audit = echo::audit::AuditSink::start(
        env_truthy("AUDIT_ENABLED"),
        &echo::config::env_nonempty("WATCHTOWER_URL").unwrap_or_default(),
        echo::config::env_nonempty("AUDIT_INGEST_TOKEN").as_deref(),
    );
    let state = echo::AppState {
        config: Arc::new(echo::config::Config::from_env()),
        store: Arc::new(pg),
        audit,
        klaxon: echo::KlaxonNotifier::from_env().map(Arc::new),
    };
    Ok(echo::app(state))
}

/// Build the paste (Pastefire) surface router against `PASTEFIRE_DATABASE_URL`.
///
/// Built EXPLICITLY (not via `pastefire::build_state_from_env`, which reads the bare `DATABASE_URL`
/// that would collide in-process): connect + migrate Pastefire's OWN Postgres and assemble the
/// `AppState` its `app()` expects. `Config::from_env()` keeps every Pastefire knob unchanged.
async fn build_paste() -> Result<Router, String> {
    let dsn = require_env("PASTEFIRE_DATABASE_URL")?;
    let pg = pastefire::store::PgStore::connect(&dsn)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    pg.migrate().await.map_err(|e| format!("migrate: {e}"))?;
    tracing::info!("paste (pastefire) store ready");
    let audit = pastefire::audit::AuditSink::start(
        env_truthy("AUDIT_ENABLED"),
        &pastefire::config::env_nonempty("WATCHTOWER_URL").unwrap_or_default(),
        pastefire::config::env_nonempty("AUDIT_INGEST_TOKEN").as_deref(),
    );
    let state = pastefire::AppState {
        config: Arc::new(pastefire::config::Config::from_env()),
        store: Arc::new(pg),
        audit,
    };
    Ok(pastefire::app(state))
}

/// Build the drive (Aperture) surface router against `APERTURE_DATABASE_URL`, with Aperture's OWN
/// Cairn S3 blob store.
///
/// Built EXPLICITLY (not via `aperture::build_state_from_env`, which reads the bare `DATABASE_URL`
/// that would collide in-process): connect + migrate Aperture's OWN Postgres metadata store, then
/// stand up the OWN blob store. The blob backend mirrors Aperture's own `build_state_from_env`,
/// selected by `APERTURE_BLOBS` (`s3` -> Cairn via `S3Blobs::connect(&config.s3)` using the
/// `S3_ENDPOINT`/`S3_BUCKET`/`S3_REGION`/`S3_ACCESS_KEY`/`S3_SECRET_KEY` env Aperture's
/// `Config::from_env()` already parsed; `memory` default for a DB-only deploy). The S3 client is a
/// native-async reqwest+rustls(ring) client — no extra CryptoProvider install is needed (ring is
/// the only provider compiled in, so rustls auto-installs it), matching the rest of the estate.
async fn build_drive() -> Result<Router, String> {
    let dsn = require_env("APERTURE_DATABASE_URL")?;
    let pg = aperture::store::PgStore::connect(&dsn)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    pg.migrate().await.map_err(|e| format!("migrate: {e}"))?;
    tracing::info!("drive (aperture) metadata store ready");

    let config = aperture::config::Config::from_env();
    let blobs_kind = std::env::var("APERTURE_BLOBS").unwrap_or_else(|_| "memory".to_string());
    // Durability guard (mirrors Sanctum's refuse-on-volatile posture): the drive (aperture)
    // metadata store is always Postgres here (require_env above), so under the prod profile (or an
    // explicit REQUIRE_PERSISTENCE) a volatile in-memory blob backend would persist every file ROW
    // yet silently drop the bytes on restart — a split brain. Refuse at STARTUP naming the exact
    // vars to set (never panic mid-request). Dev, with STEADHOLME_PROFILE unset, keeps memory.
    if require_persistence() && blobs_kind == "memory" {
        return Err(
            "STEADHOLME_PROFILE=prod (or REQUIRE_PERSISTENCE) refuses the volatile in-memory blob \
             store for the drive (aperture) surface (store=postgres + blobs=memory would keep file \
             rows but drop the bytes): set APERTURE_BLOBS=s3 with S3_ENDPOINT / S3_BUCKET / \
             S3_REGION / S3_ACCESS_KEY / S3_SECRET_KEY to persist uploaded bytes in Cairn"
                .to_string(),
        );
    }
    tracing::info!(store = "postgres", blobs = %blobs_kind, "durability posture");
    let blobs: Arc<dyn aperture::blobs::Blobs> = match blobs_kind.as_str() {
        "s3" => {
            tracing::info!(
                endpoint = config.s3.endpoint,
                bucket = config.s3.bucket,
                "APERTURE_BLOBS=s3 — using Cairn object store"
            );
            Arc::new(aperture::blobs::S3Blobs::connect(&config.s3)?)
        }
        "memory" => Arc::new(aperture::blobs::MemoryBlobs::new()),
        other => return Err(format!("unknown APERTURE_BLOBS={other} (use memory|s3)")),
    };

    // Request Room reservations bridge PostgreSQL and Cairn. If a previous process stopped after
    // reserving capacity (possibly after writing the blob) but before committing the file row,
    // recover only after the durable blob backend exists: delete the orphan object first, then
    // release the leased reservation/counters. A cleanup failure keeps the reservation for retry
    // and fails startup rather than silently leaking storage or capacity.
    aperture::recover_stale_request_uploads(&pg, blobs.as_ref())
        .await
        .map_err(|e| format!("recover uploads: {e}"))?;

    let audit = aperture::audit::AuditSink::start(
        env_truthy("AUDIT_ENABLED"),
        &std::env::var("WATCHTOWER_URL").unwrap_or_default(),
        std::env::var("AUDIT_INGEST_TOKEN").ok().as_deref(),
    );
    let state = aperture::AppState {
        config: Arc::new(config),
        store: Arc::new(pg),
        blobs,
        audit,
    };
    Ok(aperture::app(state))
}

/// Interpret a boolean-ish env var (`on` / `true` / `1` / `yes`, case-insensitive). Mirrors the
/// private `env_truthy` Echo uses in its own `build_state_from_env`, so audit is gated identically.
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

/// Whether this boot must refuse a volatile (in-memory) backend. Both production aliases accepted
/// by Agora activate the same aggregate audit/durability policy.
fn require_persistence() -> bool {
    profile_requires_persistence(std::env::var("STEADHOLME_PROFILE").ok().as_deref())
        || env_truthy("REQUIRE_PERSISTENCE")
}

fn profile_requires_persistence(profile: Option<&str>) -> bool {
    profile.is_some_and(|profile| {
        matches!(
            profile.trim().to_ascii_lowercase().as_str(),
            "prod" | "production"
        )
    })
}

/// Read a required env var, returning a descriptive error when unset/empty.
fn require_env(key: &str) -> Result<String, String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Err(format!("{key} is required")),
    }
}

fn listener_addr(raw: Option<&str>) -> Result<SocketAddr, String> {
    raw.unwrap_or(DEFAULT_BIND_ADDR)
        .parse()
        .map_err(|error| format!("invalid BIND_ADDR: {error}"))
}

/// Log a fatal startup error for one surface and exit.
fn fatal(surface: &str, err: String) -> ! {
    tracing::error!(surface, error = %err, "failed to build content surface");
    std::process::exit(1);
}

/// GET `/healthz` over a raw TCP socket on the loopback. Returns the process exit code.
fn run_healthcheck() -> i32 {
    let bind_addr = std::env::var("BIND_ADDR").ok();
    let port = listener_addr(bind_addr.as_deref())
        .map(|addr| addr.port())
        .unwrap_or(8700);
    let target = format!("127.0.0.1:{port}");
    match healthcheck_once(&target) {
        Ok(true) => 0,
        Ok(false) => {
            eprintln!("healthcheck: {target} did not return 200");
            1
        }
        Err(e) => {
            eprintln!("healthcheck: {target} error: {e}");
            1
        }
    }
}

fn healthcheck_once(target: &str) -> std::io::Result<bool> {
    let addr: SocketAddr = target
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{e}")))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    Ok(buf.lines().next().unwrap_or("").contains("200"))
}

#[cfg(test)]
mod tests {
    use super::{listener_addr, profile_requires_persistence};

    #[test]
    fn missing_bind_addr_is_loopback_for_explicit_development_boots() {
        let addr = listener_addr(None).unwrap();
        assert!(addr.ip().is_loopback());
        assert_eq!(addr.port(), 8700);
    }

    #[test]
    fn every_production_profile_alias_requires_aggregate_durability() {
        assert!(profile_requires_persistence(Some("prod")));
        assert!(profile_requires_persistence(Some("PRODUCTION")));
        assert!(!profile_requires_persistence(Some("development")));
        assert!(!profile_requires_persistence(None));
    }
}
