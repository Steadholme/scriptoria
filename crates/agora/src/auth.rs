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
pub const HEADER_GROUPS: &str = "x-auth-groups";
/// HMAC binding the injected identity to a 1-minute window (set by Sluice when GATEWAY_HMAC_KEY
/// is configured). See [`gateway_identity_ok`].
pub const HEADER_SIG: &str = "x-auth-sig";

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
    unique_header_value(headers, name).ok().flatten()
}

/// Read one gateway envelope field. Duplicate values — including repeated identical values —
/// are ambiguous at proxy/application boundaries and therefore invalidate the envelope.
fn unique_header_value(headers: &HeaderMap, name: &str) -> Result<Option<String>, ()> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?.trim();
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Groups + admin gating (same idiom as echo's has_group / is_moderator)
// ---------------------------------------------------------------------------

/// The two GLOBAL admin groups. Membership in either has ALWAYS unlocked `/admin`, and ALWAYS
/// will. Kept as the default seed for [`admin_groups`].
pub const ADMIN_GROUPS: &[&str] = &["admins", "infra-admins"];

/// Default product-scoped admin group folded in beside the globals — see [`admin_groups`].
const DEFAULT_PRODUCT_ADMIN_GROUP: &str = "forum-admins";

/// The effective admin group set: the two globals in [`ADMIN_GROUPS`] PLUS one product-scoped
/// group. This makes Agora administration DELEGABLE — an operator placed in the product group
/// (default `forum-admins`, overridable via `AGORA_ADMIN_GROUP`) reaches `/admin` WITHOUT holding
/// the global `admins`/`infra-admins`. Resolved once at first use. Purely additive: the two
/// globals are ALWAYS present, so nothing that authorized before loses access, and it changes no
/// behavior until an operator assigns someone to the product group via Census.
fn admin_groups() -> &'static [String] {
    static GROUPS: OnceLock<Vec<String>> = OnceLock::new();
    GROUPS
        .get_or_init(|| {
            let product = std::env::var("AGORA_ADMIN_GROUP")
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

/// Whether the authenticated user is in ANY [`admin_groups`] entry (the two globals plus the
/// product-scoped delegated group).
pub fn is_admin(headers: &HeaderMap) -> bool {
    admin_groups().iter().any(|a| has_group(headers, a))
}

/// Require admin group membership for an `/admin` route. `Forbidden` (403) when the
/// authenticated user carries no admin group — ordinary signed-in users never see the panel.
pub fn require_admin(headers: &HeaderMap) -> Result<(), AppError> {
    if is_admin(headers) {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "the admin panel requires an admin group".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Gateway identity signature (X-Auth-Sig) verification
// ---------------------------------------------------------------------------

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// The shared gateway HMAC key, read once from `GATEWAY_HMAC_KEY`. Empty (unset) disables
/// verification — the pre-signature behavior, fully backward compatible.
fn gateway_key() -> &'static str {
    static KEY: OnceLock<String> = OnceLock::new();
    KEY.get_or_init(|| std::env::var("GATEWAY_HMAC_KEY").unwrap_or_default())
        .as_str()
}

/// Backward-compatible development verifier. Production middleware uses
/// [`gateway_identity_ok_for`] with an explicit key and `require_subject=true`.
pub fn gateway_identity_ok(headers: &HeaderMap) -> bool {
    gateway_identity_ok_for(headers, gateway_key(), false)
}

/// Verify the gateway-injected identity against an explicit runtime policy.
///
/// The HMAC message and minute-window behavior remain byte-identical to Sluice. When
/// `require_subject` is true, both an empty key and a missing subject fail closed. Development
/// may omit both; once a key and identity are present the signature is always mandatory.
pub fn gateway_identity_ok_for(headers: &HeaderMap, key: &str, require_subject: bool) -> bool {
    let subject = match unique_header_value(headers, HEADER_SUBJECT) {
        Ok(value) => value,
        Err(()) => return false,
    };
    let email = match unique_header_value(headers, HEADER_EMAIL) {
        Ok(value) => value,
        Err(()) => return false,
    };
    let groups = match unique_header_value(headers, HEADER_GROUPS) {
        Ok(value) => value,
        Err(()) => return false,
    };
    let sig = match unique_header_value(headers, HEADER_SIG) {
        Ok(value) => value,
        Err(()) => return false,
    };
    if key.is_empty() {
        return !require_subject;
    }
    let Some(subject) = subject else {
        return !require_subject && email.is_none() && groups.is_none() && sig.is_none();
    };
    let groups = groups.unwrap_or_default();
    let Some(sig) = sig else {
        return false; // identity present but unsigned — reject
    };
    let win = now_unix() / 60;
    // Accept the current and previous minute (clock skew + minute-boundary tolerance).
    [win, win - 1].iter().any(|&w| {
        ct_eq(
            sig.as_bytes(),
            sign_identity(key, &subject, &groups, w).as_bytes(),
        )
    })
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

/// Lifetime of a server-rendered destructive-action review.
const DESTRUCTIVE_CONFIRM_TTL: i64 = 600;
const DESTRUCTIVE_CONFIRM_DOMAIN: &[u8] = b"steadholme.agora.destructive.v1";

/// Mint a short-lived confirmation token bound to one CSRF session, actor and action.
///
/// The random nonce makes each rendered review unique. Verification is stateless; a successful
/// delete naturally makes a replay a 404, while the expiry bounds an abandoned review.
pub fn new_destructive_confirmation(
    signing_key: &[u8],
    csrf: &str,
    action: &str,
    actor_sub: &str,
) -> String {
    let expires = now_unix().saturating_add(DESTRUCTIVE_CONFIRM_TTL);
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let nonce = hex::encode(nonce);
    let mac = destructive_confirmation_mac(signing_key, csrf, action, actor_sub, expires, &nonce);
    format!("{expires}.{nonce}.{mac}")
}

/// Verify CSRF and atomically consume the short-lived destructive review token.
///
/// The bounded process-local replay set is sufficient for Agora's single active service
/// instance. A valid token is consumed before Store mutation, so a failed mutation requires a
/// fresh review instead of making the bearer capability reusable.
pub fn consume_destructive_confirmation(
    signing_key: &[u8],
    headers: &HeaderMap,
    submitted_csrf: &str,
    submitted_confirm: &str,
    action: &str,
    actor_sub: &str,
) -> Result<(), AppError> {
    verify_csrf(headers, submitted_csrf)?;

    let mut parts = submitted_confirm.split('.');
    let expires = parts
        .next()
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(invalid_destructive_confirmation)?;
    let nonce = parts.next().filter(|value| value.len() == 32);
    let submitted_mac = parts.next().filter(|value| value.len() == 64);
    if parts.next().is_some() {
        return Err(invalid_destructive_confirmation());
    }
    let (Some(nonce), Some(submitted_mac)) = (nonce, submitted_mac) else {
        return Err(invalid_destructive_confirmation());
    };

    let now = now_unix();
    if expires < now || expires > now.saturating_add(DESTRUCTIVE_CONFIRM_TTL) {
        return Err(invalid_destructive_confirmation());
    }
    let expected = destructive_confirmation_mac(
        signing_key,
        submitted_csrf,
        action,
        actor_sub,
        expires,
        nonce,
    );
    if !ct_eq(expected.as_bytes(), submitted_mac.as_bytes()) {
        return Err(invalid_destructive_confirmation());
    }
    consume_confirmation_once(submitted_confirm, expires, now)?;
    Ok(())
}

fn consume_confirmation_once(token: &str, expires: i64, now: i64) -> Result<(), AppError> {
    static USED: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();

    let mut used = USED
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| {
            AppError::Internal(
                "The action review service is temporarily unavailable. Please retry.".to_string(),
            )
        })?;
    used.retain(|_, stored_expiry| *stored_expiry >= now);
    if used.insert(token.to_string(), expires).is_some() {
        return Err(invalid_destructive_confirmation());
    }
    Ok(())
}

fn destructive_confirmation_mac(
    signing_key: &[u8],
    csrf: &str,
    action: &str,
    actor_sub: &str,
    expires: i64,
    nonce: &str,
) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac = Hmac::<Sha256>::new_from_slice(signing_key).expect("HMAC accepts any key len");
    mac.update(DESTRUCTIVE_CONFIRM_DOMAIN);
    mac.update(b"\n");
    mac.update(csrf.as_bytes());
    mac.update(b"\n");
    mac.update(action.as_bytes());
    mac.update(b"\n");
    mac.update(actor_sub.as_bytes());
    mac.update(b"\n");
    mac.update(expires.to_string().as_bytes());
    mac.update(b"\n");
    mac.update(nonce.as_bytes());
    to_hex(&mac.finalize().into_bytes())
}

fn invalid_destructive_confirmation() -> AppError {
    AppError::Forbidden("destructive action review is missing, expired, or mismatched".to_string())
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
        let mut h = HeaderMap::new();
        h.insert(HEADER_SUBJECT, HeaderValue::from_static("user-42"));
        assert!(gateway_identity_ok(&h));
    }

    #[test]
    fn production_gateway_policy_requires_key_subject_and_signature() {
        let empty = HeaderMap::new();
        assert!(!gateway_identity_ok_for(&empty, "", true));
        assert!(!gateway_identity_ok_for(&empty, "production-key", true));
        assert!(gateway_identity_ok_for(&empty, "", false));

        let mut unsigned = HeaderMap::new();
        unsigned.insert(HEADER_SUBJECT, HeaderValue::from_static("user-42"));
        assert!(!gateway_identity_ok_for(&unsigned, "production-key", true));
    }

    #[test]
    fn duplicate_gateway_envelope_fields_fail_closed() {
        let window = now_unix() / 60;
        let sig = sign_identity("production-key", "user-42", "admins", window);
        let mut valid = HeaderMap::new();
        valid.append(HEADER_SUBJECT, HeaderValue::from_static("user-42"));
        valid.append(HEADER_GROUPS, HeaderValue::from_static("admins"));
        valid.append(HEADER_SIG, HeaderValue::from_str(&sig).unwrap());
        assert!(gateway_identity_ok_for(&valid, "production-key", true));

        for (name, duplicate) in [
            (HEADER_SUBJECT, "user-42"),
            (HEADER_SUBJECT, "user-99"),
            (HEADER_GROUPS, "admins"),
            (HEADER_GROUPS, "forum-admins"),
            (HEADER_SIG, sig.as_str()),
            (HEADER_SIG, "00"),
        ] {
            let mut headers = valid.clone();
            headers.append(name, HeaderValue::from_str(duplicate).unwrap());
            assert!(
                !gateway_identity_ok_for(&headers, "production-key", true),
                "duplicate {name} must invalidate the envelope"
            );
        }

        let mut duplicate_email = valid;
        duplicate_email.append(HEADER_EMAIL, HeaderValue::from_static("one@example.test"));
        duplicate_email.append(HEADER_EMAIL, HeaderValue::from_static("two@example.test"));
        assert!(!gateway_identity_ok_for(
            &duplicate_email,
            "production-key",
            true
        ));
        assert!(identity_email(&duplicate_email).is_none());
    }

    #[test]
    fn destructive_confirmation_is_bound_to_session_actor_and_action() {
        let signing_key = b"server-only-test-key";
        let csrf = new_csrf_token();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("{CSRF_COOKIE}={csrf}")).unwrap(),
        );
        let token = new_destructive_confirmation(signing_key, &csrf, "thread:t_1", "user-42");

        assert!(consume_destructive_confirmation(
            signing_key,
            &headers,
            &csrf,
            &token,
            "thread:t_1",
            "user-42"
        )
        .is_ok());
        assert!(consume_destructive_confirmation(
            signing_key,
            &headers,
            &csrf,
            &token,
            "thread:t_2",
            "user-42"
        )
        .is_err());
        assert!(consume_destructive_confirmation(
            signing_key,
            &headers,
            &csrf,
            &token,
            "thread:t_1",
            "user-99"
        )
        .is_err());

        let other_csrf = new_csrf_token();
        let mut other_headers = HeaderMap::new();
        other_headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("{CSRF_COOKIE}={other_csrf}")).unwrap(),
        );
        assert!(consume_destructive_confirmation(
            signing_key,
            &other_headers,
            &other_csrf,
            &token,
            "thread:t_1",
            "user-42"
        )
        .is_err());
        assert!(consume_destructive_confirmation(
            b"different-server-key",
            &headers,
            &csrf,
            &token,
            "thread:t_1",
            "user-42"
        )
        .is_err());
        assert!(consume_destructive_confirmation(
            signing_key,
            &headers,
            &csrf,
            &token,
            "thread:t_1",
            "user-42"
        )
        .is_err());
    }

    #[test]
    fn csrf_absent_is_rejected() {
        let headers = HeaderMap::new();
        assert!(verify_csrf(&headers, "anything").is_err());
    }

    #[test]
    fn has_group_and_require_admin() {
        // no X-Auth-Groups -> no groups, not admin, require_admin rejects.
        let mut none = HeaderMap::new();
        none.insert(HEADER_SUBJECT, HeaderValue::from_static("u_eve"));
        assert!(author_groups(&none).is_empty());
        assert!(!has_group(&none, "admins"));
        assert!(!is_admin(&none));
        assert!(require_admin(&none).is_err());

        // comma-separated groups, with whitespace, parse and match by exact name.
        let mut admins = HeaderMap::new();
        admins.insert(
            HEADER_GROUPS,
            HeaderValue::from_static("dev, infra-admins ,x"),
        );
        assert!(has_group(&admins, "infra-admins"));
        assert!(has_group(&admins, "dev"));
        assert!(!has_group(&admins, "admins"));
        assert!(is_admin(&admins), "infra-admins authorizes admin");
        assert!(require_admin(&admins).is_ok());

        let mut plain = HeaderMap::new();
        plain.insert(HEADER_GROUPS, HeaderValue::from_static("admins"));
        assert!(is_admin(&plain));
        assert!(require_admin(&plain).is_ok());

        // a non-admin group alone does not authorize.
        let mut other = HeaderMap::new();
        other.insert(HEADER_GROUPS, HeaderValue::from_static("readers,writers"));
        assert!(!is_admin(&other));
        assert!(require_admin(&other).is_err());

        // Delegated admin: the product-scoped group (default "forum-admins") ALSO authorizes
        // `/admin`, WITHOUT the caller holding a global admin group.
        let mut delegated = HeaderMap::new();
        delegated.insert(HEADER_GROUPS, HeaderValue::from_static("forum-admins"));
        assert!(!has_group(&delegated, "admins"));
        assert!(!has_group(&delegated, "infra-admins"));
        assert!(
            is_admin(&delegated),
            "the product admin group authorizes the panel"
        );
        assert!(require_admin(&delegated).is_ok());

        // a random, unrelated group is still rejected (403).
        let mut rando = HeaderMap::new();
        rando.insert(HEADER_GROUPS, HeaderValue::from_static("some-random-group"));
        assert!(!is_admin(&rando));
        assert!(require_admin(&rando).is_err());
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
