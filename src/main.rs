//! Scriptoria — one container hosting the HOLDFAST content surfaces (blog / forum / wiki).
//!
//! Each surface is its OWN library crate (Inkwell/Agora/Lattice), reused verbatim: same schema,
//! same routes, same templates, same OWN database, same subdomain. This binary only adds a
//! **Host-based vhost demux** so the estate runs ONE deployable instead of three. Sluice points
//! `blog.w33d.xyz`, `forum.w33d.xyz` and `wiki.w33d.xyz` all at this container; each request is
//! dispatched to the matching surface's router by its `Host` header. Because the surfaces keep
//! their exact paths and separate databases, Cortex's federation + its hard-coded
//! `blog/forum/wiki.w33d.xyz/...` deep links keep working unchanged.
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

/// Default listen address — internal-only; Sluice fronts the three subdomains at this upstream.
const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8700";

/// The three composed per-surface routers, dispatched by Host. Cheap to clone (each `Router` is
/// `Arc`-backed internally).
#[derive(Clone)]
struct Vhosts {
    blog: Router,
    forum: Router,
    wiki: Router,
}

#[tokio::main]
async fn main() {
    // Container HEALTHCHECK path — handled before any setup, exits the process.
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        std::process::exit(run_healthcheck());
    }

    tracing_subscriber::fmt::init();

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string());

    // Each surface connects to its OWN database and migrates idempotently — exactly what the
    // standalone service did. A failure here is fatal (the surface cannot serve without its DB).
    let blog = build_blog().await.unwrap_or_else(|e| fatal("blog (inkwell)", e));
    let forum = build_forum().await.unwrap_or_else(|e| fatal("forum (agora)", e));
    let wiki = build_wiki().await.unwrap_or_else(|e| fatal("wiki (lattice)", e));

    let app = Router::new()
        // Host-agnostic liveness for the container HEALTHCHECK + estate probes.
        .route("/healthz", get(|| async { "ok" }))
        .fallback(dispatch)
        .with_state(Vhosts { blog, forum, wiki });

    let addr: SocketAddr = bind_addr.parse().expect("invalid BIND_ADDR");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));
    tracing::info!(%addr, "Scriptoria listening (blog/forum/wiki vhost demux)");
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
    // Match on the leading label (`blog`/`forum`/`wiki`), ignoring any port.
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
    let state = inkwell::AppState {
        config: Arc::new(inkwell::config::Config::from_env()),
        store: Arc::new(pg),
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
    let state = agora::AppState {
        config: Arc::new(agora::config::Config::from_env()),
        store,
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
    let state = lattice::AppState {
        config: Arc::new(lattice::config::Config::from_env()),
        store: Arc::new(pg),
    };
    Ok(lattice::app(state))
}

/// Read a required env var, returning a descriptive error when unset/empty.
fn require_env(key: &str) -> Result<String, String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Err(format!("{key} is required")),
    }
}

/// Log a fatal startup error for one surface and exit.
fn fatal(surface: &str, err: String) -> ! {
    tracing::error!(surface, error = %err, "failed to build content surface");
    std::process::exit(1);
}

/// GET `/healthz` over a raw TCP socket on the loopback. Returns the process exit code.
fn run_healthcheck() -> i32 {
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string());
    let port = bind_addr.rsplit(':').next().unwrap_or("8700");
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
