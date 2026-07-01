//! Server configuration, env-driven with working dev defaults.
//!
//! Every value keeps its dev default when the corresponding env var is unset/empty, so the
//! in-memory dev path boots with NO configuration and NO database — exactly like
//! inkwell/sanctum. Production overrides each via the environment.

/// Default listen address (all interfaces, internal-only port 9120).
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:9120";
/// Default page size for the dashboard's keyset-paginated thread list (a request with no explicit
/// `?limit=` renders this many threads, newest-first).
pub const DEFAULT_PAGE: i64 = 50;
/// Hard ceiling on a thread-list page, regardless of what a client asks for (keeps an unbounded
/// list bounded).
pub const MAX_PAGE: i64 = 200;
/// Hard cap on how many comments a single thread view renders.
pub const COMMENT_LIMIT: usize = 500;
/// How many comments the dashboard's "recent activity" feed shows.
pub const RECENT_LIMIT: usize = 30;
/// Hard cap on a comment body, in characters (defense against unbounded input).
pub const MAX_BODY_CHARS: usize = 16 * 1024;
/// How many TOP-LEVEL comments a thread/embed view renders per keyset page (their replies come
/// along with them). Long threads page BACKWARD with `?before=` from the "Load more" control.
pub const COMMENT_PAGE: i64 = 20;

/// Allowed reaction kinds as `(id, glyph, accessible label)`. A toggle POST with any other `kind`
/// is rejected, so the `kind` column stays bounded and the UI is predictable. `id`/`glyph` are
/// constants (never user input) and safe to inline; the label is HTML-escaped on render anyway.
pub const REACTION_KINDS: &[(&str, &str, &str)] = &[
    ("up", "\u{1F44D}", "Upvote"),
    ("heart", "\u{2764}", "Heart"),
    ("celebrate", "\u{1F389}", "Celebrate"),
];

/// Whether `kind` is a known reaction kind (see [`REACTION_KINDS`]).
pub fn is_reaction_kind(kind: &str) -> bool {
    REACTION_KINDS.iter().any(|(k, _, _)| *k == kind)
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

/// Clamp a requested page size into `[1, MAX_PAGE]`, defaulting a non-positive request to
/// [`DEFAULT_PAGE`]. Idempotent (`clamp_page(clamp_page(n)) == clamp_page(n)`), so the handler and
/// store can both apply it and still agree on the effective page size.
pub fn clamp_page(limit: i64) -> i64 {
    if limit <= 0 {
        DEFAULT_PAGE
    } else {
        limit.min(MAX_PAGE)
    }
}

/// Read an env var, returning `None` when unset OR empty (empty never clobbers a default).
pub fn env_nonempty(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}
