//! Server configuration, env-driven with working dev defaults.
//!
//! Every value keeps its dev default when the corresponding env var is unset/empty, so the
//! in-memory dev path boots with NO configuration, NO database and NO object store — exactly
//! like the rest of the estate. Production overrides each via the environment.

/// Default listen address (all interfaces, internal-only port 8900).
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8900";

/// Default hard cap on a single uploaded file, in bytes (25 MiB). The HTTP body limit is set a
/// little above this to leave room for the multipart envelope; this is the friendly,
/// application-level guard.
pub const DEFAULT_MAX_UPLOAD: usize = 25 * 1024 * 1024;

/// Default public base URL used to render copyable share links (`{base}/s/{token}`).
pub const DEFAULT_PUBLIC_BASE: &str = "https://drive.w33d.xyz";

/// Default number of gallery file cards returned per page (the newest page + each "Load older").
pub const DEFAULT_PAGE: i64 = 50;
/// Hard ceiling on the gallery page size, regardless of any client-supplied `limit`.
pub const MAX_PAGE: i64 = 200;

/// Clamp a requested page size to `[1, MAX_PAGE]`, falling back to [`DEFAULT_PAGE`] when the caller
/// asks for a non-positive value (unset / `0` / negative). Idempotent: clamping an already-clamped
/// value is a no-op, so the handler and store agree on the exact page size (the `len == limit`
/// "is there another page?" check stays valid).
pub fn clamp_page(limit: i64) -> i64 {
    if limit <= 0 {
        DEFAULT_PAGE
    } else {
        limit.min(MAX_PAGE)
    }
}

/// Default S3 region handed to the client. Cairn (MinIO-compatible) ignores it, but the signer
/// requires a value.
pub const DEFAULT_S3_REGION: &str = "us-east-1";

/// Default S3 bucket holding Aperture's blobs.
pub const DEFAULT_S3_BUCKET: &str = "aperture";

/// S3 / Cairn connection settings (only consulted when `APERTURE_BLOBS=s3`).
#[derive(Clone, Debug)]
pub struct S3Config {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
}

impl S3Config {
    fn from_env() -> Self {
        S3Config {
            endpoint: env_nonempty("S3_ENDPOINT").unwrap_or_else(|| "http://cairn:9000".to_string()),
            bucket: env_nonempty("S3_BUCKET").unwrap_or_else(|| DEFAULT_S3_BUCKET.to_string()),
            region: env_nonempty("S3_REGION").unwrap_or_else(|| DEFAULT_S3_REGION.to_string()),
            access_key: env_nonempty("S3_ACCESS_KEY").unwrap_or_default(),
            secret_key: env_nonempty("S3_SECRET_KEY").unwrap_or_default(),
        }
    }
}

/// Runtime configuration. Cheap to clone; shared read-only behind `Arc`.
#[derive(Clone, Debug)]
pub struct Config {
    /// Listen address (`BIND_ADDR`).
    pub bind_addr: String,
    /// Hard cap on an uploaded file, bytes (`MAX_UPLOAD`).
    pub max_upload: usize,
    /// Public base URL for share links (`PUBLIC_BASE_URL`).
    pub public_base: String,
    /// S3 / Cairn settings.
    pub s3: S3Config,
}

impl Config {
    /// Default development configuration (in-memory stores, no database, no object store).
    pub fn dev() -> Self {
        Config {
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
            max_upload: DEFAULT_MAX_UPLOAD,
            public_base: DEFAULT_PUBLIC_BASE.to_string(),
            s3: S3Config {
                endpoint: "http://cairn:9000".to_string(),
                bucket: DEFAULT_S3_BUCKET.to_string(),
                region: DEFAULT_S3_REGION.to_string(),
                access_key: String::new(),
                secret_key: String::new(),
            },
        }
    }

    /// Configuration with the dev defaults overridden by environment variables.
    pub fn from_env() -> Self {
        let mut config = Config::dev();
        if let Some(v) = env_nonempty("BIND_ADDR") {
            config.bind_addr = v;
        }
        if let Some(v) = env_nonempty("MAX_UPLOAD") {
            if let Ok(n) = v.parse::<usize>() {
                config.max_upload = n;
            }
        }
        if let Some(v) = env_nonempty("PUBLIC_BASE_URL") {
            config.public_base = v.trim_end_matches('/').to_string();
        }
        config.s3 = S3Config::from_env();
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
