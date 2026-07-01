//! Gateway-injected identity + double-submit CSRF.
//!
//! Echo does NO login of its own. It sits behind a Sluice `auth=sso` route at the subdomain ROOT
//! (`comments.w33d.xyz`); the gateway runs the OIDC browser login against Keystone, STRIPS any
//! inbound `X-Auth-*`, and injects the verified `X-Auth-Subject` / `X-Auth-Email` /
//! `X-Auth-Scope`. Because Echo is internal-only (never publicly reachable), it TRUSTS those
//! headers as the authenticated commenter — the comment author is ALWAYS taken from the gateway
//! headers, never from a client-supplied field.
//!
//! State-changing POSTs (comment / moderate) are double-submit CSRF protected: a random token
//! lives in a JS-readable `__Host-csrf` cookie AND in a hidden form field; the POST is accepted
//! only when the two match. The token is minted once and REUSED across page renders.

use axum::http::{header, HeaderMap};

use crate::error::AppError;

pub const HEADER_SUBJECT: &str = "x-auth-subject";
pub const HEADER_EMAIL: &str = "x-auth-email";
pub const HEADER_SCOPE: &str = "x-auth-scope";
pub const HEADER_GROUPS: &str = "x-auth-groups";
/// HMAC binding the injected identity to a 1-minute window (set by Sluice when GATEWAY_HMAC_KEY
/// is configured). See [`gateway_identity_ok`].
pub const HEADER_SIG: &str = "x-auth-sig";

/// Double-submit CSRF cookie. `__Host-` prefix => Secure + Path=/ + no Domain, so the browser
/// only ever returns it over TLS to this exact host.
pub const CSRF_COOKIE: &str = "__Host-csrf";
/// CSRF cookie lifetime, seconds.
const CSRF_TTL: u64 = 3600;

/// The authenticated commenter's subject (stable user id), if the gateway injected one.
pub fn author_sub(headers: &HeaderMap) -> Option<String> {
    header_value(headers, HEADER_SUBJECT)
}

/// The authenticated commenter's email, if the gateway injected one.
pub fn author_email(headers: &HeaderMap) -> Option<String> {
    header_value(headers, HEADER_EMAIL)
}

/// The authenticated commenter's scope claim, if the gateway injected one (informational).
pub fn author_scope(headers: &HeaderMap) -> Option<String> {
    header_value(headers, HEADER_SCOPE)
}

/// The email for display, falling back to a neutral label when unauthenticated.
pub fn display_email(headers: &HeaderMap) -> String {
    author_email(headers).unwrap_or_else(|| "—".to_string())
}

/// Group names that authorize moderation. Membership in ANY of these lets a user hide/unhide.
pub const MODERATOR_GROUPS: &[&str] = &["moderators", "infra-admins"];

/// The authenticated user's groups, parsed from the comma-separated `X-Auth-Groups` header
/// (injected AND HMAC-verified by the gateway, so it is trustworthy). Empty when absent/blank.
pub fn author_groups(headers: &HeaderMap) -> Vec<String> {
    header_value(headers, HEADER_GROUPS)
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Whether the authenticated user belongs to `group` (exact match against `X-Auth-Groups`).
pub fn has_group(headers: &HeaderMap, group: &str) -> bool {
    author_groups(headers).iter().any(|g| g == group)
}

/// Whether the authenticated user is in ANY [`MODERATOR_GROUPS`] entry.
pub fn is_moderator(headers: &HeaderMap) -> bool {
    let groups = author_groups(headers);
    MODERATOR_GROUPS
        .iter()
        .any(|m| groups.iter().any(|g| g == m))
}

/// Require moderator group membership for a moderation action. `Forbidden` (403) when the
/// authenticated user carries no moderator group — closes the hole where ANY signed-in user could
/// hide/unhide ANY comment.
pub fn require_moderator(headers: &HeaderMap) -> Result<(), AppError> {
    if is_moderator(headers) {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "moderation requires a moderator group".to_string(),
        ))
    }
}

/// The two GLOBAL admin groups. Membership in either has ALWAYS unlocked the `/admin` panel, and
/// ALWAYS will. Kept as the default seed for [`admin_groups`]. (Comment moderation is a separate
/// gate, already delegable via the `moderators` group — see [`MODERATOR_GROUPS`].)
pub const ADMIN_GROUPS: &[&str] = &["admins", "infra-admins"];

/// Default product-scoped admin group folded in beside the globals — see [`admin_groups`].
const DEFAULT_PRODUCT_ADMIN_GROUP: &str = "comments-admins";

/// The effective admin group set: the two globals in [`ADMIN_GROUPS`] PLUS one product-scoped
/// group. This makes Echo's `/admin` panel DELEGABLE — an operator placed in the product group
/// (default `comments-admins`, overridable via `ECHO_ADMIN_GROUP`) reaches `/admin` WITHOUT
/// holding the global `admins`/`infra-admins`. Resolved once at first use. Purely additive: the
/// two globals are ALWAYS present, so nothing that authorized before loses access, and it changes
/// no behavior until an operator assigns someone to the product group via Census.
fn admin_groups() -> &'static [String] {
    static GROUPS: OnceLock<Vec<String>> = OnceLock::new();
    GROUPS
        .get_or_init(|| {
            let product = std::env::var("ECHO_ADMIN_GROUP")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| DEFAULT_PRODUCT_ADMIN_GROUP.to_string());
            let mut groups: Vec<String> = ADMIN_GROUPS.iter().map(|g| (*g).to_string()).collect();
            if !groups.iter().any(|g| g == &product) {
                groups.push(product);
            }
            groups
        })
        .as_slice()
}

/// Whether the authenticated user is in ANY [`admin_groups`] entry (the two globals plus the
/// product-scoped delegated group).
pub fn is_admin(headers: &HeaderMap) -> bool {
    admin_groups().iter().any(|a| has_group(headers, a))
}

/// Require admin group membership for the `/admin` subtree. `Forbidden` (403) when the
/// authenticated user carries no admin group — an ordinary signed-in user cannot reach the panel;
/// only `admins` / `infra-admins` do.
pub fn require_admin(headers: &HeaderMap) -> Result<(), AppError> {
    if is_admin(headers) {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "admin panel requires an admin group".to_string(),
        ))
    }
}

/// Require an authenticated identity. Returns `(subject, email)`, or `Unauthorized` when no SSO
/// identity is present — defense in depth behind the gateway.
pub fn require_author(headers: &HeaderMap) -> Result<(String, String), AppError> {
    let sub = author_sub(headers).ok_or_else(|| {
        AppError::Unauthorized("no gateway SSO identity (X-Auth-Subject missing)".to_string())
    })?;
    let email = author_email(headers).unwrap_or_default();
    Ok((sub, email))
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
    let Some(subject) = header_value(headers, HEADER_SUBJECT) else {
        return true; // no injected identity to verify (public route / local dev)
    };
    let groups = header_value(headers, HEADER_GROUPS).unwrap_or_default();
    let Some(sig) = header_value(headers, HEADER_SIG) else {
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

/// `Set-Cookie` value for the (JS-readable) CSRF cookie.
pub fn csrf_cookie(value: &str) -> String {
    format!("{CSRF_COOKIE}={value}; Path=/; Secure; SameSite=Lax; Max-Age={CSRF_TTL}")
}

// ---------------------------------------------------------------------------
// CSRF (double-submit)
// ---------------------------------------------------------------------------

/// Mint a fresh CSRF token: 32 CSPRNG bytes, hex-encoded.
pub fn new_csrf_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("OS CSPRNG unavailable");
    hex::encode(bytes)
}

/// Resolve the CSRF token to embed in this render's forms. Reuses the existing cookie token when
/// present (so it is stable across pages/tabs); otherwise mints one and returns the matching
/// `Set-Cookie` to attach to the response.
pub fn ensure_csrf(headers: &HeaderMap) -> (String, Option<String>) {
    match get_cookie(headers, CSRF_COOKIE) {
        Some(c) if !c.is_empty() => (c, None),
        _ => {
            let token = new_csrf_token();
            let set = csrf_cookie(&token);
            (token, Some(set))
        }
    }
}

/// Double-submit check: the `submitted` form token must equal the `__Host-csrf` cookie.
pub fn verify_csrf(headers: &HeaderMap, submitted: &str) -> Result<(), AppError> {
    let ok = match get_cookie(headers, CSRF_COOKIE) {
        Some(cookie) if !cookie.is_empty() => ct_eq(cookie.as_bytes(), submitted.as_bytes()),
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(AppError::Unauthorized("CSRF token mismatch".to_string()))
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
    fn csrf_token_is_random_and_hex() {
        let a = new_csrf_token();
        let b = new_csrf_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn csrf_double_submit_matches_and_rejects() {
        let token = new_csrf_token();
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            format!("{CSRF_COOKIE}={token}").parse().unwrap(),
        );
        assert!(verify_csrf(&headers, &token).is_ok());
        assert!(verify_csrf(&headers, "not-the-token").is_err());
        assert!(verify_csrf(&HeaderMap::new(), &token).is_err());
    }

    #[test]
    fn ensure_csrf_reuses_existing_cookie() {
        let token = new_csrf_token();
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            format!("{CSRF_COOKIE}={token}").parse().unwrap(),
        );
        let (t, set) = ensure_csrf(&headers);
        assert_eq!(t, token);
        assert!(set.is_none(), "existing cookie reused, no new Set-Cookie");

        let (t2, set2) = ensure_csrf(&HeaderMap::new());
        assert_eq!(t2.len(), 64);
        assert!(set2.unwrap().contains("__Host-csrf="));
    }

    #[test]
    fn require_author_needs_subject() {
        assert!(require_author(&HeaderMap::new()).is_err());
        let mut headers = HeaderMap::new();
        headers.insert(HEADER_SUBJECT, "u_123".parse().unwrap());
        headers.insert(HEADER_EMAIL, "a@holdfast.local".parse().unwrap());
        let (sub, email) = require_author(&headers).unwrap();
        assert_eq!(sub, "u_123");
        assert_eq!(email, "a@holdfast.local");
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
    fn has_group_and_require_moderator() {
        // no X-Auth-Groups -> no groups, not a moderator, require_moderator rejects.
        let mut none = HeaderMap::new();
        none.insert(HEADER_SUBJECT, HeaderValue::from_static("u_eve"));
        assert!(author_groups(&none).is_empty());
        assert!(!has_group(&none, "moderators"));
        assert!(!is_moderator(&none));
        assert!(require_moderator(&none).is_err());

        // comma-separated groups, with whitespace, parse and match by exact name.
        let mut mods = HeaderMap::new();
        mods.insert(HEADER_GROUPS, HeaderValue::from_static("dev, infra-admins ,x"));
        assert!(has_group(&mods, "infra-admins"));
        assert!(has_group(&mods, "dev"));
        assert!(!has_group(&mods, "moderators"));
        assert!(is_moderator(&mods), "infra-admins authorizes moderation");
        assert!(require_moderator(&mods).is_ok());

        // a non-moderator group alone does not authorize.
        let mut other = HeaderMap::new();
        other.insert(HEADER_GROUPS, HeaderValue::from_static("readers,writers"));
        assert!(!is_moderator(&other));
        assert!(require_moderator(&other).is_err());
    }

    #[test]
    fn require_admin_allows_only_admin_groups() {
        // no X-Auth-Groups -> not an admin, require_admin rejects (403).
        let mut none = HeaderMap::new();
        none.insert(HEADER_SUBJECT, HeaderValue::from_static("u_eve"));
        assert!(!is_admin(&none));
        assert!(require_admin(&none).is_err());

        // an ordinary signed-in user (non-admin groups only) is still rejected.
        let mut user = HeaderMap::new();
        user.insert(HEADER_GROUPS, HeaderValue::from_static("readers, moderators"));
        assert!(!is_admin(&user), "moderators is NOT an admin group");
        assert!(require_admin(&user).is_err());

        // `admins` authorizes the panel.
        let mut admin = HeaderMap::new();
        admin.insert(HEADER_GROUPS, HeaderValue::from_static("dev, admins ,x"));
        assert!(has_group(&admin, "admins"));
        assert!(is_admin(&admin));
        assert!(require_admin(&admin).is_ok());

        // `infra-admins` also authorizes.
        let mut infra = HeaderMap::new();
        infra.insert(HEADER_GROUPS, HeaderValue::from_static("infra-admins"));
        assert!(is_admin(&infra));
        assert!(require_admin(&infra).is_ok());

        // Delegated admin: the product-scoped group (default "comments-admins") ALSO authorizes
        // `/admin`, WITHOUT the caller holding a global admin group.
        let mut delegated = HeaderMap::new();
        delegated.insert(HEADER_GROUPS, HeaderValue::from_static("comments-admins"));
        assert!(!has_group(&delegated, "admins"));
        assert!(!has_group(&delegated, "infra-admins"));
        assert!(is_admin(&delegated), "the product admin group authorizes the panel");
        assert!(require_admin(&delegated).is_ok());

        // a random, unrelated group is still rejected (403).
        let mut rando = HeaderMap::new();
        rando.insert(HEADER_GROUPS, HeaderValue::from_static("some-random-group"));
        assert!(!is_admin(&rando));
        assert!(require_admin(&rando).is_err());
    }

    #[test]
    fn gateway_ok_when_key_unset() {
        // No GATEWAY_HMAC_KEY in the test env => verification disabled => always ok.
        let mut h = HeaderMap::new();
        h.insert(HEADER_SUBJECT, HeaderValue::from_static("user-42"));
        assert!(gateway_identity_ok(&h));
    }
}
