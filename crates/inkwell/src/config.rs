//! Server configuration, env-driven with working dev defaults.
//!
//! Every value keeps its dev default when the corresponding env var is unset/empty, so the
//! in-memory dev path boots with NO configuration and NO database — exactly like
//! keystone/keyward/beacon. Production overrides each via the environment.

/// Default listen address (all interfaces, internal-only port 8700).
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8700";

/// How many posts the index renders per page when no `?limit=` is given. Keyset ("Load older")
/// pagination makes the full archive reachable page by page, so the default page stays small.
pub const DEFAULT_PAGE: i64 = 50;
/// Hard ceiling on a single index page, regardless of what a client `?limit=` asks for. Keeps an
/// unbounded scan bounded while every older page is still reachable via the `?before=` cursor.
pub const MAX_PAGE: i64 = 200;

/// Clamp a requested page size into `1..=MAX_PAGE`, falling back to [`DEFAULT_PAGE`] when the
/// request omits `?limit=` or passes a non-positive value.
pub fn clamp_page(limit: Option<i64>) -> i64 {
    match limit {
        Some(n) if n > 0 => n.min(MAX_PAGE),
        _ => DEFAULT_PAGE,
    }
}

/// Runtime configuration. Cheap to clone; shared read-only behind `Arc`.
#[derive(Clone, Debug)]
pub struct Config {
    /// Listen address (`BIND_ADDR`).
    pub bind_addr: String,
}

impl Config {
    /// Default development configuration (in-memory friendly, no database).
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
