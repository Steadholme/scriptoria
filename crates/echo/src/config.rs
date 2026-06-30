//! Server configuration, env-driven with working dev defaults.
//!
//! Every value keeps its dev default when the corresponding env var is unset/empty, so the
//! in-memory dev path boots with NO configuration and NO database — exactly like
//! inkwell/sanctum. Production overrides each via the environment.

/// Default listen address (all interfaces, internal-only port 9120).
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:9120";
/// Hard cap on how many threads the dashboard renders (keeps an unbounded list bounded).
pub const LIST_LIMIT: usize = 200;
/// Hard cap on how many comments a single thread view renders.
pub const COMMENT_LIMIT: usize = 500;
/// How many comments the dashboard's "recent activity" feed shows.
pub const RECENT_LIMIT: usize = 30;
/// Hard cap on a comment body, in characters (defense against unbounded input).
pub const MAX_BODY_CHARS: usize = 16 * 1024;

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
