//! Server configuration, env-driven with working dev defaults.
//!
//! Every value keeps its dev default when the corresponding env var is unset/empty, so the
//! in-memory dev path boots with NO configuration and NO database — exactly like the rest of
//! the estate. Production overrides each via the environment.

/// Default listen address (all interfaces, internal-only port 8720).
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8720";
/// Hard cap on how many pages a single index render lists. Keeps an unbounded wiki's index
/// page bounded; pages remain reachable directly via `/w/{slug}`.
pub const PAGE_LIST_LIMIT: usize = 1000;
/// Hard cap on how many revisions a single `/history/{slug}` render lists.
pub const HISTORY_LIMIT: usize = 500;
/// Default staleness window (days): a page not edited within this many days is flagged on the
/// `/coherence` view. Overridden by `LATTICE_STALE_DAYS`.
pub const DEFAULT_STALE_DAYS: i64 = 120;

/// Runtime configuration. Cheap to clone; shared read-only behind `Arc`.
#[derive(Clone, Debug)]
pub struct Config {
    /// Listen address (`BIND_ADDR`).
    pub bind_addr: String,
    /// Days since last edit after which a page is "stale" on `/coherence` (`LATTICE_STALE_DAYS`).
    pub stale_days: i64,
}

impl Config {
    /// Default development configuration (in-memory, no database, no persistence).
    pub fn dev() -> Self {
        Config {
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
            stale_days: DEFAULT_STALE_DAYS,
        }
    }

    /// Configuration with the dev defaults overridden by environment variables.
    pub fn from_env() -> Self {
        let mut config = Config::dev();
        if let Some(v) = env_nonempty("BIND_ADDR") {
            config.bind_addr = v;
        }
        // Only a non-negative integer overrides the default; anything else keeps the default.
        if let Some(v) = env_nonempty("LATTICE_STALE_DAYS") {
            if let Ok(n) = v.parse::<i64>() {
                if n >= 0 {
                    config.stale_days = n;
                }
            }
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
fn env_nonempty(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}
