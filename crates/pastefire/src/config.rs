//! Server configuration, env-driven with working dev defaults.
//!
//! Every value keeps its dev default when the corresponding env var is unset/empty, so the
//! in-memory dev path boots with NO configuration and NO database — exactly like
//! keystone/keyward/watchtower. Production overrides each via the environment.

/// Default listen address (all interfaces, internal-only port 8730).
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8730";

/// Default page size for the "my recent pastes" list when the client sends no `?limit=`.
/// Keeps the newest-page view bounded (backward keyset pagination fetches older pages).
pub const DEFAULT_PAGE: i64 = 50;

/// Hard ceiling on a requested page size, regardless of what a client asks for.
pub const MAX_PAGE: i64 = 200;

/// Resolve a requested page size into `[1, MAX_PAGE]`, defaulting to [`DEFAULT_PAGE`] when the
/// value is absent or non-positive. Shared by the handler and defensively re-applied in the store.
pub fn clamp_page(requested: Option<i64>) -> i64 {
    match requested {
        Some(n) if n > 0 => n.min(MAX_PAGE),
        _ => DEFAULT_PAGE,
    }
}

/// Hard cap on a paste body, in bytes. Keeps a single submission bounded; the default axum
/// body limit (2 MiB) is the outer guard, this is the friendly application-level one.
pub const MAX_BODY_BYTES: usize = 256 * 1024;

/// Hard cap on a paste title, in characters (post-trim).
pub const MAX_TITLE_CHARS: usize = 200;

/// Runtime configuration. Cheap to clone; shared read-only behind `Arc`.
#[derive(Clone, Debug)]
pub struct Config {
    /// Listen address (`BIND_ADDR`).
    pub bind_addr: String,
}

impl Config {
    /// Default development configuration (in-memory, no database, no persistence).
    pub fn dev() -> Self {
        Config {
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
        }
    }

    /// Configuration with the dev defaults overridden by environment variables.
    pub fn from_env() -> Self {
        let mut config = Config::dev();
        if let Some(v) = env_nonempty("BIND_ADDR") {
            config.bind_addr = v;
        }
        config
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::dev()
    }
}

/// Read an env var, returning `None` when unset OR empty (empty never clobbers a default).
pub fn env_nonempty(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}
