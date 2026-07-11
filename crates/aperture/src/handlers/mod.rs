//! HTTP handlers + shared server-render helpers.
//!
//! - [`health`] — unauthenticated liveness probe (`/healthz`).
//! - [`files`] — the drive surface (gallery, upload, detail, raw, delete, public share).
//! - [`admin`] — the admin panel (per-owner storage usage + quota overrides; admin groups only).
//!
//! The shared design tokens / CSS are embedded (via `include_str!`) and inlined into every page,
//! matching the HOLDFAST enterprise brand: brand gradient, indigo accent, cards, buttons, the
//! app-bar with the shield + wordmark. All producer-supplied text (file names, types) is
//! HTML-escaped on render (defense-in-depth against stored XSS); blob bytes are served as inline
//! images only when magic-sniffed, otherwise as downloads.

pub mod admin;
pub mod files;
pub mod health;

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use std::sync::OnceLock;

/// Aperture-only CSS layered after Odyssey's canonical font, tokens, and components.
pub const SERVICE_CSS: &str = include_str!("../../static/service.css");

/// Product-owned public Share Room assets. These intentionally do not include Odyssey CSS,
/// Components, Shell, Wire, Spark, or Motion: the anonymous capability surface owns its DOM and
/// runtime end-to-end.
pub const SHARE_ROOM_CSS: &str = include_str!("../../static/share-room.css");
pub const SHARE_ROOM_JS: &str = include_str!("../../static/share-room.js");

/// Executable policy for every anonymous Share Room HTML response. Assets are same-origin routes;
/// uploads use same-origin XHR, and no inline script/style is permitted.
pub const SHARE_ROOM_CSP: &str = "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

static APP_CSS: OnceLock<String> = OnceLock::new();
static DYNAMIC_JS: OnceLock<String> = OnceLock::new();

/// Embedded design system, inlined into each rendered page's `<style>`:
/// Odyssey's canonical CSS followed by Aperture's service surface CSS.
pub fn app_css() -> &'static str {
    APP_CSS
        .get_or_init(|| {
            let mut css = String::with_capacity(odyssey::APP_CSS.len() + SERVICE_CSS.len());
            css.push_str(odyssey::APP_CSS);
            css.push_str(SERVICE_CSS);
            css
        })
        .as_str()
}

pub fn dynamic_js() -> &'static str {
    DYNAMIC_JS
        .get_or_init(|| odyssey::dynamic_scripts().0)
        .as_str()
}

/// Wrap product-owned public HTML with its strict CSP and anti-embedding/referrer posture.
pub fn share_room_html(status: StatusCode, body: String) -> Response {
    let mut response = (status, Html(body)).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(SHARE_ROOM_CSP),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
}

/// Public upload-room HTML plus the stable double-submit cookie used by its form.
pub fn share_room_html_with_csrf(status: StatusCode, body: String, csrf: &str) -> Response {
    let mut response = share_room_html(status, body);
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&crate::auth::csrf_cookie(csrf))
            .expect("generated CSRF cookie is a valid header value"),
    );
    response
}

fn share_room_asset(content_type: &'static str, body: &'static str) -> Response {
    let mut response = body.into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

/// Product-owned, public, read-only Share Room stylesheet.
pub async fn share_room_css_asset() -> Response {
    share_room_asset("text/css; charset=utf-8", SHARE_ROOM_CSS)
}

/// Product-owned, public, read-only Share Room runtime.
pub async fn share_room_js_asset() -> Response {
    share_room_asset("text/javascript; charset=utf-8", SHARE_ROOM_JS)
}

/// The HOLDFAST shield glyph (small, for the app-bar brand lockup).
pub const SHIELD_SVG: &str = r##"<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="hf-shield-sm" x1="8" y1="4" x2="40" y2="44" gradientUnits="userSpaceOnUse"><stop stop-color="#818CF8"/><stop offset="1" stop-color="#4F46E5"/></linearGradient></defs><path d="M24 4 8 9.5V22c0 11 7 17.4 16 21.5C33 39.4 40 33 40 22V9.5L24 4Z" fill="url(#hf-shield-sm)"/><rect x="20" y="19" width="8" height="13" rx="1" fill="#fff" fill-opacity="0.92"/><path d="M20 19v-2.5a4 4 0 0 1 8 0V19" stroke="#fff" stroke-width="2" stroke-opacity="0.92" fill="none"/></svg>"##;

/// A generic document glyph shown on gallery cards / detail previews for non-image files.
pub const FILE_SVG: &str = r##"<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 4h16l10 10v28a2 2 0 0 1-2 2H12a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2Z" fill="#EEF2FF" stroke="#C7D2FE" stroke-width="2"/><path d="M28 4v10h10" fill="#fff" stroke="#C7D2FE" stroke-width="2"/></svg>"##;

/// Cross-subdomain SSO logout (terminated at the Keystone IdP behind the gateway).
pub const LOGOUT_URL: &str = "https://sso.w33d.xyz/_gw/auth/logout";

/// Branded error page shell.
const ERROR_HTML: &str = include_str!("../../templates/error.html");
const SHARE_ERROR_HTML: &str = include_str!("../../templates/share_error.html");

/// The share-link expiry menu: `(form value, label)`. A numeric value is a TTL in seconds;
/// `never` keeps the share link forever. The fixed list is a trusted allow-list (reused from
/// pastefire's expiry idiom). Escaped on render regardless.
pub const EXPIRY_OPTIONS: &[(&str, &str)] = &[
    ("never", "Never"),
    ("3600", "1 hour"),
    ("86400", "1 day"),
    ("604800", "1 week"),
    ("2592000", "30 days"),
];

/// Build the `<option>` list for the expiry `<select>`, pre-selecting `selected` (defaults to
/// `never` when `selected` is not one of the allow-listed values).
pub fn expiry_options(selected: &str) -> String {
    let chosen = if EXPIRY_OPTIONS.iter().any(|(v, _)| *v == selected) {
        selected
    } else {
        "never"
    };
    EXPIRY_OPTIONS
        .iter()
        .map(|(value, label)| {
            let sel = if *value == chosen { " selected" } else { "" };
            format!(
                "<option value=\"{v}\"{sel}>{l}</option>",
                v = esc(value),
                l = esc(label),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

/// Resolve a submitted expiry form value into an absolute `expires_at` (epoch seconds). A positive
/// integer is treated as a TTL added to `now`; `never`/blank/invalid -> no expiry (`None`). Mirrors
/// pastefire's `parse_expiry`.
pub fn parse_expiry(value: &str, now: i64) -> Option<i64> {
    match value.trim().parse::<i64>() {
        Ok(secs) if secs > 0 => Some(now + secs),
        _ => None,
    }
}

/// Format epoch seconds as a compact UTC timestamp `YYYY-MM-DD HH:MM:SSZ`.
pub fn fmt_ts(secs: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}Z",
            dt.year(),
            dt.month() as u8,
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second()
        ),
        Err(_) => secs.to_string(),
    }
}

/// Human-readable byte size (`1.0 KB`, `2.3 MB`, ...). Decimal units, one decimal place above KB.
pub fn human_size(bytes: i64) -> String {
    const KB: f64 = 1024.0;
    let b = bytes.max(0) as f64;
    if b < KB {
        return format!("{bytes} B");
    }
    let units = ["KB", "MB", "GB", "TB"];
    let mut size = b / KB;
    let mut unit = 0;
    while size >= KB && unit < units.len() - 1 {
        size /= KB;
        unit += 1;
    }
    format!("{size:.1} {}", units[unit])
}

/// Detect the content type from the leading magic bytes for the raster image types Aperture
/// renders inline. Returns `None` when no known image signature matches, so the caller falls back
/// to a sanitized client-provided type (and serves it as a download).
pub fn sniff_image(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() >= 8 && bytes[..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
        return Some("image/png");
    }
    if bytes.len() >= 3 && bytes[..3] == [0xFF, 0xD8, 0xFF] {
        return Some("image/jpeg");
    }
    if bytes.len() >= 6 && (&bytes[..6] == b"GIF87a" || &bytes[..6] == b"GIF89a") {
        return Some("image/gif");
    }
    if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    if bytes.len() >= 2 && &bytes[..2] == b"BM" {
        return Some("image/bmp");
    }
    None
}

/// Sanitize a client-supplied content type to a conservative token, defaulting to
/// `application/octet-stream`. Only `type/subtype` of safe characters survives; anything else
/// (header-injection attempts, blanks) collapses to the default.
pub fn sanitize_content_type(raw: &str) -> String {
    let raw = raw.trim();
    let base = raw.split(';').next().unwrap_or("").trim();
    let ok = !base.is_empty()
        && base.len() <= 128
        && base.contains('/')
        && base
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'/' | b'-' | b'+' | b'.'));
    if ok {
        base.to_ascii_lowercase()
    } else {
        "application/octet-stream".to_string()
    }
}

/// Resolve the stored content type for an upload: prefer the magic-sniffed image type, else the
/// sanitized client type. The returned type drives BOTH metadata display and the inline/download
/// serving decision (`model::is_inline_image`).
pub fn resolve_content_type(bytes: &[u8], client_type: &str) -> String {
    match sniff_image(bytes) {
        Some(image) => image.to_string(),
        None => sanitize_content_type(client_type),
    }
}

/// Sanitize a file name for use in a `Content-Disposition` `filename=""` parameter: strip control
/// characters, quotes and path separators so the header can't be split or traverse. Empty input
/// becomes `file`.
pub fn safe_filename(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '"' | '\\' | '/' | '\r' | '\n') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        "file".to_string()
    } else {
        trimmed.chars().take(200).collect()
    }
}

/// The app-bar's right cluster: the "All apps" waffle to the apex portal and the avatar user-menu
/// (Account / All apps / the preserved cross-subdomain gateway Sign-out). Shared by every page so
/// the chrome stays identical. Legacy `allapps`/`userchip` hooks are retained on the new elements.
/// `_title` is no longer shown in the bar (the v2 app-bar carries product + nav instead). `email`
/// unknown → a minimal, no-identity avatar (never breaks rendering).
pub fn userbox(_title: &str, email: Option<&str>) -> String {
    let e = email.unwrap_or("");
    let has_id = !e.is_empty();
    let (avatar, name_html, head_name, head_sub) = if has_id {
        let initial = e
            .chars()
            .find(|c| c.is_alphanumeric())
            .map(|c| c.to_uppercase().to_string())
            .unwrap_or_else(|| "U".to_string());
        (
            esc(&initial),
            format!("<span class=\"usermenu__name\">{}</span>", esc(e)),
            esc(e),
            "Signed in".to_string(),
        )
    } else {
        (
            r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" style="width:16px;height:16px"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>"##.to_string(),
            String::new(),
            "Account".to_string(),
            "Not signed in".to_string(),
        )
    };
    format!(
        r#"<a class="iconbtn allapps" href="https://w33d.xyz" title="All apps" aria-label="All apps"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg></a>
      <div class="usermenu userchip">
        <button class="usermenu__btn" type="button" aria-haspopup="true" aria-label="Account menu">
          <span class="avatar" aria-hidden="true">{avatar}</span>
          {name}
          <svg class="usermenu__caret" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>
        </button>
        <div class="usermenu__pop" role="menu">
          <div class="usermenu__head"><span class="avatar" aria-hidden="true">{avatar}</span><div><b>{head_name}</b><span>{head_sub}</span></div></div>
          <a class="menuitem" href="https://account.w33d.xyz" role="menuitem"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>Account</a>
          <a class="menuitem" href="https://w33d.xyz" role="menuitem"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>All apps</a>
          <a class="menuitem menuitem--danger" href="{LOGOUT_URL}" role="menuitem"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5"/><path d="M21 12H9"/></svg>Sign out</a>
        </div>
      </div>"#,
        avatar = avatar,
        name = name_html,
        head_name = head_name,
        head_sub = head_sub,
        LOGOUT_URL = LOGOUT_URL,
    )
}

/// Render the branded error page (used by [`crate::error::AppError`]). `email` is shown in the
/// app-bar when a gateway identity is known.
pub fn render_error(
    status: StatusCode,
    heading: &str,
    message: &str,
    email: Option<&str>,
) -> (StatusCode, Html<String>) {
    let body = ERROR_HTML
        .replace("{{CSS}}", app_css())
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("Drive", email))
        .replace("{{STATUS}}", &status.as_u16().to_string())
        .replace("{{HEADING}}", &esc(heading))
        .replace("{{MESSAGE}}", &esc(message));
    (status, Html(body))
}

/// Render an anonymous capability error without importing the signed-in Odyssey shell. Internal
/// details are supplied by the caller only after it has collapsed backend failures to a generic
/// message.
pub fn render_share_room_error(status: StatusCode, heading: &str, message: &str) -> Response {
    let body = SHARE_ERROR_HTML
        .replace("{{STATUS}}", &status.as_u16().to_string())
        .replace("{{HEADING}}", &esc(heading))
        .replace("{{MESSAGE}}", &esc(message));
    share_room_html(status, body)
}

/// Minimal HTML escaping for text/attribute interpolation.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html_metacharacters() {
        assert_eq!(esc("<script>&\"'"), "&lt;script&gt;&amp;&quot;&#x27;");
    }

    #[test]
    fn parse_expiry_handles_never_and_ttl() {
        assert_eq!(parse_expiry("never", 1000), None);
        assert_eq!(parse_expiry("", 1000), None);
        assert_eq!(parse_expiry("nonsense", 1000), None);
        assert_eq!(parse_expiry("3600", 1000), Some(4600));
        assert_eq!(parse_expiry("-5", 1000), None);
    }

    #[test]
    fn expiry_options_preselects_and_defaults() {
        assert!(expiry_options("86400").contains("value=\"86400\" selected"));
        // Unknown selection falls back to `never`.
        assert!(expiry_options("bogus").contains("value=\"never\" selected"));
    }

    #[test]
    fn human_size_scales_units() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1024), "1.0 KB");
        assert_eq!(human_size(1536), "1.5 KB");
        assert_eq!(human_size(1024 * 1024), "1.0 MB");
        assert_eq!(human_size(5 * 1024 * 1024), "5.0 MB");
    }

    #[test]
    fn sniff_detects_png_jpeg_gif() {
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0];
        assert_eq!(sniff_image(&png), Some("image/png"));
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0, 0];
        assert_eq!(sniff_image(&jpeg), Some("image/jpeg"));
        assert_eq!(sniff_image(b"GIF89a...."), Some("image/gif"));
        assert_eq!(sniff_image(b"not an image"), None);
    }

    #[test]
    fn resolve_prefers_magic_over_client_lies() {
        // A PNG claimed as text/html is still served as an image (and never as HTML).
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert_eq!(resolve_content_type(&png, "text/html"), "image/png");
        // HTML claimed as image/png is NOT an inline image (no magic) -> sanitized client type.
        assert_eq!(resolve_content_type(b"<html>", "image/png"), "image/png");
        assert!(!crate::model::is_inline_image(&resolve_content_type(
            b"<html>",
            "text/html"
        )));
    }

    #[test]
    fn sanitize_content_type_rejects_garbage() {
        assert_eq!(sanitize_content_type("image/png"), "image/png");
        assert_eq!(sanitize_content_type("IMAGE/PNG"), "image/png");
        assert_eq!(
            sanitize_content_type("text/html; charset=utf-8"),
            "text/html"
        );
        assert_eq!(
            sanitize_content_type("no-slash"),
            "application/octet-stream"
        );
        assert_eq!(
            sanitize_content_type("evil\r\nSet-Cookie: x"),
            "application/octet-stream"
        );
        assert_eq!(sanitize_content_type(""), "application/octet-stream");
    }

    #[test]
    fn safe_filename_strips_dangerous_chars() {
        assert_eq!(safe_filename("report.pdf"), "report.pdf");
        assert_eq!(safe_filename("a/b\\c\"d"), "a_b_c_d");
        assert_eq!(safe_filename("with\r\nnewline"), "with__newline");
        assert_eq!(safe_filename("   "), "file");
    }
}
