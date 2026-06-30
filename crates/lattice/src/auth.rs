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
}
