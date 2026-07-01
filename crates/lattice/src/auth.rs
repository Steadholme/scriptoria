//! Gateway-injected identity + CSRF (double-submit).
//!
//! Lattice does NO login of its own. It sits behind a Sluice `auth=sso` route on
//! `wiki.w33d.xyz`, where the gateway runs the OIDC browser login, STRIPS any inbound
//! `X-Auth-*`, and injects the verified `X-Auth-Subject` / `X-Auth-Email`. Because Lattice is
//! internal-only (never publicly reachable except through Sluice), it TRUSTS the injected
//! headers as the signed-in user — the editor/author of every save comes from there, NEVER
//! from a client-supplied field.
//!
//! State-changing POSTs are additionally guarded by a double-submit CSRF token: a random token
//! is minted on `GET /edit/{slug}`, set in the JS-free `__Host-lattice_csrf` cookie AND placed
//! in a hidden form field; `POST /edit/{slug}` requires the two to match (constant-time).

use axum::http::{header, HeaderMap};

/// Header carrying the gateway-verified signed-in email.
pub const HEADER_EMAIL: &str = "x-auth-email";
/// Header carrying the gateway-verified stable subject id.
pub const HEADER_SUBJECT: &str = "x-auth-subject";
/// Header carrying the gateway-verified group memberships (comma-separated).
pub const HEADER_GROUPS: &str = "x-auth-groups";
/// HMAC binding the injected identity to a 1-minute window (set by Sluice when GATEWAY_HMAC_KEY
/// is configured). See [`gateway_identity_ok`].
pub const HEADER_SIG: &str = "x-auth-sig";
/// Double-submit CSRF cookie. `__Host-` prefix => browsers only return it over TLS to this
/// exact host with `Path=/` and no `Domain`, so it cannot be planted by a sibling subdomain.
pub const CSRF_COOKIE: &str = "__Host-lattice_csrf";
/// CSRF cookie lifetime, seconds.
const CSRF_TTL: u64 = 3600;

/// The signed-in user's email, if the gateway injected one. `None` when absent or blank (e.g.
/// a direct dev hit with no gateway in front), letting the caller fall back to a generic label.
pub fn signed_in_email(headers: &HeaderMap) -> Option<String> {
    header_nonempty(headers, HEADER_EMAIL)
}

/// The signed-in user's stable subject id, if the gateway injected one.
pub fn signed_in_subject(headers: &HeaderMap) -> Option<String> {
    header_nonempty(headers, HEADER_SUBJECT)
}

fn header_nonempty(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

// ---------------------------------------------------------------------------
// Gateway identity signature (X-Auth-Sig) verification
// ---------------------------------------------------------------------------

use std::sync::OnceLock;

/// The shared gateway HMAC key, read once from `GATEWAY_HMAC_KEY`. Empty (unset) disables
/// verification — the pre-signature behavior, fully backward compatible.
fn gateway_key() -> &'static str {
    static KEY: OnceLock<String> = OnceLock::new();
    KEY.get_or_init(|| std::env::var("GATEWAY_HMAC_KEY").unwrap_or_default())
        .as_str()
}

/// Verify the gateway-injected identity is authentic. When `GATEWAY_HMAC_KEY` is set AND an
/// identity (`X-Auth-Subject`) is present, a valid `X-Auth-Sig` — HMAC-SHA256 over
/// `subject "\n" groups "\n" minute` for the current OR previous minute — is REQUIRED; a rogue
/// peer that POSTs `X-Auth-Subject` directly (bypassing Sluice) cannot forge it. Returns:
/// - `true` when the key is unset (verification off), or no identity header is present
///   (public/dev path), or the signature is valid;
/// - `false` when an identity is present but the signature is missing or invalid (=> 401).
pub fn gateway_identity_ok(headers: &HeaderMap) -> bool {
    let key = gateway_key();
    if key.is_empty() {
        return true;
    }
    let Some(subject) = header_nonempty(headers, HEADER_SUBJECT) else {
        return true; // no injected identity to verify (public route / local dev)
    };
    let groups = header_nonempty(headers, HEADER_GROUPS).unwrap_or_default();
    let Some(sig) = header_nonempty(headers, HEADER_SIG) else {
        return false; // identity present but unsigned — reject
    };
    let win = now_unix() / 60;
    // Accept the current and previous minute (clock skew + minute-boundary tolerance).
    [win, win - 1]
        .iter()
        .any(|&w| ct_eq(sig.as_bytes(), sign_identity(key, &subject, &groups, w).as_bytes()))
}

/// Recompute the gateway signature — byte-identical to Sluice's `auth.SignIdentity` (Go).
fn sign_identity(key: &str, subject: &str, groups: &str, window: i64) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC accepts any key len");
    mac.update(subject.as_bytes());
    mac.update(b"\n");
    mac.update(groups.as_bytes());
    mac.update(b"\n");
    mac.update(window.to_string().as_bytes());
    to_hex(&mac.finalize().into_bytes())
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Cookies
// ---------------------------------------------------------------------------

/// Read a single cookie value from the request's `Cookie` header(s).
pub fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    for hv in headers.get_all(header::COOKIE).iter() {
        let Ok(raw) = hv.to_str() else { continue };
        for pair in raw.split(';') {
            let pair = pair.trim();
            if let Some((k, v)) = pair.split_once('=') {
                if k.trim() == name {
                    return Some(v.trim().to_string());
                }
            }
        }
    }
    None
}

/// `Set-Cookie` value for the CSRF cookie.
pub fn csrf_cookie(value: &str) -> String {
    format!("{CSRF_COOKIE}={value}; Path=/; Secure; SameSite=Lax; Max-Age={CSRF_TTL}")
}

// ---------------------------------------------------------------------------
// CSRF (double-submit)
// ---------------------------------------------------------------------------

/// Mint a fresh CSRF token (the same value goes in the cookie and the hidden form field).
pub fn new_csrf_token() -> String {
    random_hex()
}

/// Double-submit check: the form-`submitted` token must equal the `__Host-lattice_csrf` cookie.
pub fn verify_csrf(headers: &HeaderMap, submitted: &str) -> bool {
    match get_cookie(headers, CSRF_COOKIE) {
        Some(cookie) if !cookie.is_empty() => ct_eq(cookie.as_bytes(), submitted.as_bytes()),
        _ => false,
    }
}

/// A 32-byte CSPRNG value, hex-encoded. Used for CSRF tokens and revision ids.
pub fn random_hex() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("OS CSPRNG unavailable");
    hex::encode(bytes)
}

/// Length-checked constant-time byte comparison.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csrf_double_submit() {
        let token = new_csrf_token();
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            format!("{CSRF_COOKIE}={token}").parse().unwrap(),
        );
        assert!(verify_csrf(&headers, &token));
        assert!(!verify_csrf(&headers, "not-the-token"));
        // No cookie -> never valid.
        assert!(!verify_csrf(&HeaderMap::new(), &token));
    }

    #[test]
    fn random_hex_is_64_chars_and_unique() {
        let a = random_hex();
        let b = random_hex();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
    }

    #[test]
    fn signed_in_email_trims_and_filters_blank() {
        let mut headers = HeaderMap::new();
        assert_eq!(signed_in_email(&headers), None);
        headers.insert(HEADER_EMAIL, "  a@b.co  ".parse().unwrap());
        assert_eq!(signed_in_email(&headers).as_deref(), Some("a@b.co"));
    }

    #[test]
    fn sign_identity_matches_go_vector() {
        // MUST equal sluice/internal/auth/sig_test.go — the cross-language contract.
        assert_eq!(
            sign_identity("test-key", "usr_alice", "admins,devs", 1),
            "ddc77236dcfb03dd9f462f7c84e1b25e58f5fc380997695a689e6c3ac4bb3777"
        );
        assert_eq!(
            sign_identity("test-key", "usr_bob", "", 2),
            "930f82fb1224e69c9c5bc46e545c3b108b1eeb6c9078c7a33fc24f30c595f658"
        );
    }

    #[test]
    fn gateway_ok_when_key_unset() {
        // No GATEWAY_HMAC_KEY in the test env => verification disabled => always ok.
        let mut headers = HeaderMap::new();
        headers.insert(HEADER_SUBJECT, "user-42".parse().unwrap());
        assert!(gateway_identity_ok(&headers));
    }
}
