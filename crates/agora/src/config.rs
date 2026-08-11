//! Server configuration, env-driven with fail-closed runtime selection.
//!
//! Tests may construct [`Config::dev`] directly. A real process must name its profile explicitly;
//! development is loopback-only, while production requires the gateway signing key.

use std::fmt;
use std::net::SocketAddr;

use rand::rngs::OsRng;
use rand::RngCore;

/// Safe development listen address. Production supplies its routable bind explicitly.
pub const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8710";

/// Runtime policy profile. Process startup must select it via `STEADHOLME_PROFILE`; tests can use
/// [`Config::dev`] without reading process-global environment variables.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeProfile {
    Development,
    Production,
}

impl RuntimeProfile {
    fn parse(raw: Option<String>) -> Result<Self, String> {
        match raw.map(|value| value.trim().to_ascii_lowercase()) {
            Some(value) if matches!(value.as_str(), "dev" | "development" | "local" | "test") => {
                Ok(Self::Development)
            }
            Some(value) if matches!(value.as_str(), "prod" | "production") => Ok(Self::Production),
            None => Err(
                "STEADHOLME_PROFILE is required (use development for loopback or prod)".to_string(),
            ),
            Some(value) if value.is_empty() => Err(
                "STEADHOLME_PROFILE is required (use development for loopback or prod)".to_string(),
            ),
            Some(other) => Err(format!(
                "unknown STEADHOLME_PROFILE={other} (use development|prod)"
            )),
        }
    }
}

/// Runtime configuration. Cheap to clone; shared read-only behind `Arc`.
#[derive(Clone)]
pub struct Config {
    /// Listen address (`BIND_ADDR`).
    pub bind_addr: String,
    /// Explicit runtime policy profile.
    pub profile: RuntimeProfile,
    /// Gateway identity HMAC key. Empty is permitted only in Development.
    gateway_hmac_key: String,
    /// Server-only key for stateless destructive-action review tokens.
    destructive_confirmation_key: Vec<u8>,
}

impl Config {
    /// Default development configuration (in-memory, no database, no persistence).
    pub fn dev() -> Self {
        let mut destructive_confirmation_key = vec![0u8; 32];
        OsRng.fill_bytes(&mut destructive_confirmation_key);
        Config {
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
            profile: RuntimeProfile::Development,
            gateway_hmac_key: String::new(),
            destructive_confirmation_key,
        }
    }

    /// Configuration with the dev defaults overridden by environment variables.
    pub fn from_env() -> Result<Self, String> {
        let mut config = Config::dev();
        if let Some(v) = env_nonempty("BIND_ADDR") {
            config.bind_addr = v;
        }
        config.profile = RuntimeProfile::parse(std::env::var("STEADHOLME_PROFILE").ok())?;
        config.gateway_hmac_key = env_nonempty("GATEWAY_HMAC_KEY").unwrap_or_default();
        validate_runtime(config.profile, &config.bind_addr, &config.gateway_hmac_key)?;
        if let Some(key) = env_nonempty("AGORA_CONFIRM_HMAC_KEY").or_else(|| {
            (!config.gateway_hmac_key.is_empty()).then(|| config.gateway_hmac_key.clone())
        }) {
            config.destructive_confirmation_key = key.into_bytes();
        }
        Ok(config)
    }

    /// Whether production-only identity and durability guards are mandatory.
    pub fn is_production(&self) -> bool {
        self.profile == RuntimeProfile::Production
    }

    /// Key used to verify Sluice's signed identity envelope.
    pub(crate) fn gateway_hmac_key(&self) -> &str {
        &self.gateway_hmac_key
    }

    /// Server-only HMAC key used to prove that a destructive commit visited its review page.
    pub(crate) fn destructive_confirmation_key(&self) -> &[u8] {
        &self.destructive_confirmation_key
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("bind_addr", &self.bind_addr)
            .field("profile", &self.profile)
            .field("gateway_hmac_key", &"[REDACTED]")
            .field("destructive_confirmation_key", &"[REDACTED]")
            .finish()
    }
}

fn validate_runtime(profile: RuntimeProfile, bind_addr: &str, key: &str) -> Result<(), String> {
    let bind = bind_addr
        .parse::<SocketAddr>()
        .map_err(|_| format!("BIND_ADDR must be an IP socket address, got {bind_addr}"))?;
    if profile == RuntimeProfile::Development && !bind.ip().is_loopback() {
        return Err("STEADHOLME_PROFILE=development requires a loopback BIND_ADDR".to_string());
    }
    if profile == RuntimeProfile::Production && key.trim().is_empty() {
        Err("STEADHOLME_PROFILE=prod requires a non-empty GATEWAY_HMAC_KEY".to_string())
    } else {
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::{validate_runtime, RuntimeProfile};

    #[test]
    fn runtime_profile_is_explicit_and_fail_closed_on_unknown_values() {
        assert!(RuntimeProfile::parse(None).is_err());
        assert!(RuntimeProfile::parse(Some(String::new())).is_err());
        assert_eq!(
            RuntimeProfile::parse(Some("test".to_string())).unwrap(),
            RuntimeProfile::Development
        );
        assert_eq!(
            RuntimeProfile::parse(Some("prod".to_string())).unwrap(),
            RuntimeProfile::Production
        );
        assert!(RuntimeProfile::parse(Some("maybe".to_string())).is_err());
    }

    #[test]
    fn production_requires_a_gateway_key_before_startup() {
        assert!(validate_runtime(RuntimeProfile::Production, "0.0.0.0:8710", "").is_err());
        assert!(validate_runtime(RuntimeProfile::Production, "0.0.0.0:8710", "   ").is_err());
        assert!(
            validate_runtime(RuntimeProfile::Production, "0.0.0.0:8710", "configured-key").is_ok()
        );
    }

    #[test]
    fn development_bypass_is_loopback_only() {
        assert!(validate_runtime(RuntimeProfile::Development, "127.0.0.1:8710", "").is_ok());
        assert!(validate_runtime(RuntimeProfile::Development, "[::1]:8710", "").is_ok());
        assert!(validate_runtime(RuntimeProfile::Development, "0.0.0.0:8710", "").is_err());
        assert!(validate_runtime(RuntimeProfile::Development, "192.0.2.10:8710", "").is_err());
    }
}
