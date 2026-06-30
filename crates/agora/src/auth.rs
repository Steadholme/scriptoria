//! Gateway-injected identity + CSRF (double-submit).
//!
//! Agora does NO login of its own. It sits behind a Sluice `auth=sso` route, where the
//! gateway runs the OIDC browser login against Keystone, STRIPS any inbound `X-Auth-*`, and
//! injects the verified `X-Auth-Subject` / `X-Auth-Email` / `X-Auth-Scope`. Because Agora is
//! internal-only (never publicly reachable), it TRUSTS those headers as the authenticated
//! author — a client-supplied author is NEVER accepted.
//!
//! State-changing POSTs (new thread, reply) are additionally guarded by a double-submit CSRF
//! token: a JS-readable `__Host-csrf` cookie whose value must equal the token submitted in the
//! form. The `__Host-` prefix (Secure + Path=/ + no Domain) means the cookie is only ever sent
//! back over TLS to this exact host (the public surface, forum.w33d.xyz, is HTTPS).

use axum::http::{header, HeaderMap};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::error::AppError;

pub const HEADER_SUBJECT: &str = "x-auth-subject";
pub const HEADER_EMAIL: &str = "x-auth-email";

/// JS-readable double-submit CSRF cookie. `__Host-` prefix pins it to TLS + this exact host.
pub const CSRF_COOKIE: &str = "__Host-csrf";
/// CSRF cookie lifetime, seconds.
const CSRF_TTL: u64 = 3600;

/// The authenticated author's identity (subject + display email), or `None` when the gateway
/// injected no identity (should not happen behind `auth=sso`, but handled defensively).
pub struct Identity {
    pub sub: String,
    pub email: String,
}

/// The authenticated author's email, if the gateway injected one.
pub fn identity_email(headers: &HeaderMap) -> Option<String> {
    header_value(headers, HEADER_EMAIL)
}

/// The authenticated author's subject, if the gateway injected one.
pub fn identity_subject(headers: &HeaderMap) -> Option<String> {
    header_value(headers, HEADER_SUBJECT)
}

/// Require an authenticated author for a state-changing request. Returns the [`Identity`], or
/// `Unauthorized` when no SSO subject is present. The email falls back to the subject when the
/// gateway injected only a subject.
pub fn require_author(headers: &HeaderMap) -> Result<Identity, AppError> {
    let sub = identity_subject(headers).ok_or_else(|| {
        AppError::Unauthorized("no gateway SSO identity (X-Auth-Subject missing)".to_string())
    })?;
    let email = identity_email(headers).unwrap_or_else(|| sub.clone());
    Ok(Identity { sub, email })
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
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

/// `Set-Cookie` value for the (JS-readable) CSRF cookie.
pub fn csrf_cookie(value: &str) -> String {
    format!("{CSRF_COOKIE}={value}; Path=/; Secure; SameSite=Lax; Max-Age={CSRF_TTL}")
}

// ---------------------------------------------------------------------------
// CSRF (double-submit)
// ---------------------------------------------------------------------------

/// A fresh random CSRF token (32 bytes, hex).
pub fn new_csrf_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Ensure the request carries a CSRF token: reuse the existing `__Host-csrf` cookie when
/// present (so multiple open forms share one token), otherwise mint a fresh one. Returns
/// `(token, set_cookie)` — `set_cookie` is `Some` only when a new cookie must be issued.
pub fn ensure_csrf(headers: &HeaderMap) -> (String, Option<String>) {
    match get_cookie(headers, CSRF_COOKIE) {
        Some(tok) if !tok.is_empty() => (tok, None),
        _ => {
            let token = new_csrf_token();
            let cookie = csrf_cookie(&token);
            (token, Some(cookie))
        }
    }
}

/// Double-submit check: the `submitted` form token must equal the `__Host-csrf` cookie.
/// Returns `Forbidden` on mismatch/absence.
pub fn verify_csrf(headers: &HeaderMap, submitted: &str) -> Result<(), AppError> {
    match get_cookie(headers, CSRF_COOKIE) {
        Some(cookie) if !cookie.is_empty() && ct_eq(cookie.as_bytes(), submitted.as_bytes()) => {
            Ok(())
        }
        _ => Err(AppError::Forbidden(
            "CSRF token missing or mismatched".to_string(),
        )),
    }
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
    use axum::http::HeaderValue;

    #[test]
    fn csrf_double_submit() {
        let token = new_csrf_token();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("{CSRF_COOKIE}={token}")).unwrap(),
        );
        assert!(verify_csrf(&headers, &token).is_ok());
        assert!(verify_csrf(&headers, "not-the-token").is_err());
    }

    #[test]
    fn csrf_absent_is_rejected() {
        let headers = HeaderMap::new();
        assert!(verify_csrf(&headers, "anything").is_err());
    }

    #[test]
    fn ensure_csrf_reuses_existing_cookie() {
        let token = new_csrf_token();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("{CSRF_COOKIE}={token}")).unwrap(),
        );
        let (reused, set) = ensure_csrf(&headers);
        assert_eq!(reused, token);
        assert!(set.is_none());

        let (minted, set2) = ensure_csrf(&HeaderMap::new());
        assert_eq!(minted.len(), 64);
        assert!(set2.is_some());
    }
}
