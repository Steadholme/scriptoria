//! HTTP handlers + shared server-render helpers.
//!
//! - [`health`] — unauthenticated liveness probe (`/healthz`).
//! - [`paste`] — the SSO pastebin surface (new form, create, view, raw, delete).
//!
//! Pastefire's product-owned design tokens / CSS are embedded (via `include_str!`) and served to
//! every page. All producer-supplied text is HTML-escaped on render (defense-in-depth against
//! stored XSS); the service injects NO raw HTML.

pub mod health;
pub mod paste;

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use std::sync::OnceLock;

/// Pastefire's complete product-owned visual system.
pub const SERVICE_CSS: &str = include_str!("../../static/service.css");

pub const APP_CSS_PATH: &str = "/assets/pastefire-20260909.css";

static APP_CSS: OnceLock<String> = OnceLock::new();
static DYNAMIC_JS: OnceLock<String> = OnceLock::new();

/// Complete, product-owned Pastefire visual system.
pub fn app_css() -> &'static str {
    APP_CSS.get_or_init(|| SERVICE_CSS.to_owned()).as_str()
}

pub async fn app_css_asset() -> Response {
    let mut response = app_css().into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/css; charset=utf-8"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

pub fn dynamic_js() -> &'static str {
    DYNAMIC_JS
        .get_or_init(|| odyssey::dynamic_scripts().0)
        .as_str()
}

/// The Steadholme shield glyph (small, for the app-bar brand lockup).
pub const SHIELD_SVG: &str = r##"<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="hf-shield-sm" x1="8" y1="4" x2="40" y2="44" gradientUnits="userSpaceOnUse"><stop stop-color="#818CF8"/><stop offset="1" stop-color="#4F46E5"/></linearGradient></defs><path d="M24 4 8 9.5V22c0 11 7 17.4 16 21.5C33 39.4 40 33 40 22V9.5L24 4Z" fill="url(#hf-shield-sm)"/><rect x="20" y="19" width="8" height="13" rx="1" fill="#fff" fill-opacity="0.92"/><path d="M20 19v-2.5a4 4 0 0 1 8 0V19" stroke="#fff" stroke-width="2" stroke-opacity="0.92" fill="none"/></svg>"##;

/// Cross-subdomain SSO logout (terminated at the Keystone IdP behind the gateway).
pub const LOGOUT_URL: &str = "https://sso.w33d.xyz/_gw/auth/logout";

/// Branded error page shell.
const ERROR_HTML: &str = include_str!("../../templates/error.html");

/// The language menu: `(value, label)`. `value` is stored on the paste and echoed into the
/// view's language badge; the menu is a fixed, trusted allow-list.
pub const LANGUAGES: &[(&str, &str)] = &[
    ("plaintext", "Plain text"),
    ("bash", "Shell / Bash"),
    ("c", "C"),
    ("cpp", "C++"),
    ("csharp", "C#"),
    ("css", "CSS"),
    ("diff", "Diff / Patch"),
    ("dockerfile", "Dockerfile"),
    ("go", "Go"),
    ("html", "HTML"),
    ("ini", "INI / Config"),
    ("java", "Java"),
    ("javascript", "JavaScript"),
    ("json", "JSON"),
    ("kotlin", "Kotlin"),
    ("markdown", "Markdown"),
    ("php", "PHP"),
    ("python", "Python"),
    ("ruby", "Ruby"),
    ("rust", "Rust"),
    ("sql", "SQL"),
    ("swift", "Swift"),
    ("toml", "TOML"),
    ("typescript", "TypeScript"),
    ("xml", "XML"),
    ("yaml", "YAML"),
];

/// The expiry menu: `(form value, label)`. A numeric value is a TTL in seconds; `never` keeps
/// the paste forever. The fixed list is a trusted allow-list.
pub const EXPIRY_OPTIONS: &[(&str, &str)] = &[
    ("never", "Never"),
    ("600", "10 minutes"),
    ("3600", "1 hour"),
    ("86400", "1 day"),
    ("604800", "1 week"),
    ("2592000", "30 days"),
];

/// Display label for a stored language token. Unknown tokens fall back to the token itself
/// (the caller escapes), an empty token to "Plain text".
pub fn language_label(token: &str) -> String {
    LANGUAGES
        .iter()
        .find(|(v, _)| *v == token)
        .map(|(_, l)| (*l).to_string())
        .unwrap_or_else(|| {
            if token.is_empty() {
                "Plain text".to_string()
            } else {
                token.to_string()
            }
        })
}

/// Build the `<option>` list for the language `<select>`, pre-selecting `selected`.
pub fn language_options(selected: &str) -> String {
    options(LANGUAGES, selected, "plaintext")
}

/// Build the `<option>` list for the expiry `<select>`, pre-selecting `selected`.
pub fn expiry_options(selected: &str) -> String {
    options(EXPIRY_OPTIONS, selected, "never")
}

fn options(items: &[(&str, &str)], selected: &str, default: &str) -> String {
    let chosen = if items.iter().any(|(v, _)| *v == selected) {
        selected
    } else {
        default
    };
    items
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

/// Resolve a submitted expiry form value into an absolute `expires_at` (epoch seconds).
/// A positive integer is treated as a TTL added to `now`; `never`/blank/invalid -> no expiry.
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

/// Format a byte count for compact file metadata in code block headers.
pub fn fmt_size(bytes: usize) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / KB)
    } else {
        format!("{:.1} MB", bytes as f64 / MB)
    }
}

/// Format a positive future duration for compact expiry badges.
pub fn fmt_dur_short(secs: i64) -> String {
    if secs <= 0 {
        "now".to_string()
    } else if secs < 60 {
        "in <1m".to_string()
    } else if secs < 3600 {
        format!("in {}m", secs / 60)
    } else if secs < 86_400 {
        format!("in {}h", secs / 3600)
    } else {
        format!("in {}d", secs / 86_400)
    }
}

/// The app-bar's right cluster: the "All apps" waffle to the apex portal and the avatar user-menu
/// (Account / All apps / the preserved cross-subdomain gateway Sign-out). Shared by every page so
/// the chrome stays identical. Legacy `allapps`/`userchip` hooks are retained on the new elements.
/// `_title` is no longer shown in the bar (the v2 app-bar carries product + nav instead). `email`
/// Render Pastefire's chrome: the Scriptoria suite bar (six vhosts, Paste filled). `active` is
/// the page's own name, used only to drop the "New paste" action on the page that already is
/// one; `email` is the gateway identity, `None` on an anonymous read.
pub fn topbar(active: &str, email: Option<&str>) -> String {
    let action = if active == "New paste" {
        ""
    } else {
        r#"<a class="btn btn-primary btn-sm" href="/">New paste</a>"#
    };
    suite_bar(email.unwrap_or(""), action)
}

/// Render the branded error page (used by [`crate::error::AppError`] and the not-found/expired
/// paths). `email` is shown in the app-bar when a gateway identity is known.
pub fn render_error(
    status: StatusCode,
    heading: &str,
    message: &str,
    email: Option<&str>,
) -> (StatusCode, Html<String>) {
    let (tone, glyph) = error_tone_glyph(status);
    let body = ERROR_HTML
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{TOPBAR}}", &topbar("Pastefire", email))
        .replace("{{FOOTER}}", FOOTER)
        .replace("{{STATUS}}", &status.as_u16().to_string())
        .replace("{{HEADING}}", &esc(heading))
        .replace("{{MESSAGE}}", &esc(message))
        .replace("{{TONE}}", tone)
        .replace("{{GLYPH}}", glyph);
    (status, Html(body))
}

fn error_tone_glyph(status: StatusCode) -> (&'static str, &'static str) {
    match status {
        StatusCode::NOT_FOUND => (
            "missing",
            r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m18.5 5.5-13 13"/><path d="M10 6h8v8"/><path d="M14 18H6v-8"/></svg>"##,
        ),
        StatusCode::BAD_REQUEST | StatusCode::FORBIDDEN => (
            "blocked",
            r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="M9.5 9.5 14.5 14.5"/><path d="m14.5 9.5-5 5"/></svg>"##,
        ),
        _ => (
            "fault",
            r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m12 3 10 18H2L12 3Z"/><path d="M12 9v5"/><path d="M12 17h.01"/></svg>"##,
        ),
    }
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
    fn language_label_falls_back() {
        assert_eq!(language_label("rust"), "Rust");
        assert_eq!(language_label(""), "Plain text");
        assert_eq!(language_label("whatever"), "whatever");
    }

    #[test]
    fn option_list_selects_known_value_else_default() {
        assert!(language_options("rust").contains("value=\"rust\" selected"));
        // Unknown selection falls back to the default (plaintext) being selected.
        assert!(language_options("bogus").contains("value=\"plaintext\" selected"));
    }
}

// ===== Scriptoria v2 suite chrome =====

/// This surface's key in the design's `surf/*` set, and the vhost it answers on.
pub const SURFACE_KEY: &str = "paste";
pub const SURFACE_HOST: &str = "paste.w33d.xyz";

/// The six Scriptoria surfaces, in the order the Figma SuiteBar (AgW9572aDQMEDkSzerg9lR,
/// component 10:705) lists them: `key, label, origin, icon`. One bar spans all six vhosts so
/// the single-container Host demux reads as one product instead of six unrelated sites.
const SUITE_SURFACES: [(&str, &str, &str, &str); 6] = [
    ("blog", "Blog", "https://blog.w33d.xyz", ICON_FEATHER),
    ("forum", "Forum", "https://forum.w33d.xyz", ICON_FORUM),
    ("wiki", "Wiki", "https://wiki.w33d.xyz", ICON_WIKI),
    ("paste", "Paste", "https://paste.w33d.xyz", ICON_PASTE),
    ("drive", "Drive", "https://drive.w33d.xyz", ICON_DRIVE),
    (
        "comments",
        "Comments",
        "https://comments.w33d.xyz",
        ICON_COMMENTS,
    ),
];

const ICON_FEATHER: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20.24 12.24a6 6 0 0 0-8.49-8.49L5 10.5V19h8.5z"/><path d="M16 8 2 22"/><path d="M17.5 15H9"/></svg>"##;
const ICON_FORUM: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>"##;
const ICON_WIKI: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 7v14"/><path d="M3 18a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h5a4 4 0 0 1 4 4 4 4 0 0 1 4-4h5a1 1 0 0 1 1 1v13a1 1 0 0 1-1 1h-6a3 3 0 0 0-3 3 3 3 0 0 0-3-3z"/></svg>"##;
const ICON_PASTE: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m16 18 6-6-6-6"/><path d="m8 6-6 6 6 6"/></svg>"##;
const ICON_DRIVE: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M22 12H2"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/><path d="M6 16h.01"/><path d="M10 16h.01"/></svg>"##;
const ICON_COMMENTS: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M7.9 20A9 9 0 1 0 4 16.1L2 22Z"/></svg>"##;
const ICON_WAFFLE: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>"##;

/// The suite bar the design puts on every Scriptoria page: brand tile, the product name over
/// this vhost, the six-surface switcher (each pill carrying its own `surf/*` colour, the
/// current one filled), then the estate's identity cluster. `extra_right` takes surface-owned
/// controls that belong beside identity; `email` empty or `—` means no gateway session, and
/// then no address and no log-out link are drawn.
pub fn suite_bar(email: &str, extra_right: &str) -> String {
    let mut pills = String::new();
    for (key, label, origin, icon) in SUITE_SURFACES {
        let here = key == SURFACE_KEY;
        pills.push_str(&format!(
            r#"<a class="surf surf--{key}{state}" href="{href}"{aria}>{icon}<span>{label}</span></a>"#,
            key = key,
            state = if here { " is-active" } else { "" },
            href = if here { "/" } else { origin },
            aria = if here { r#" aria-current="page""# } else { "" },
            icon = icon,
            label = label,
        ));
    }
    let account = suite_account(email);
    format!(
        r#"<header class="suitebar">
  <a class="suitebar__brand" href="/" aria-label="Scriptoria Paste home">
    <span class="brand-tile" aria-hidden="true">{tile}</span>
    <span class="suitebar__name"><b>Scriptoria</b><span class="suitebar__host">{host}</span></span>
  </a>
  <nav class="surfaces" aria-label="Scriptoria surfaces">{pills}</nav>
  <span class="suitebar__spacer"></span>
  <div class="suitebar__right">{extra_right}<a class="allapps" href="https://w33d.xyz">{waffle}<span>All apps</span></a>{account}</div>
</header>"#,
        tile = ICON_FEATHER,
        host = SURFACE_HOST,
        pills = pills,
        extra_right = extra_right,
        waffle = ICON_WAFFLE,
        account = account,
    )
}

/// The identity chip plus the gateway log-out. With no session the chip states that plainly and
/// the log-out is omitted: a public reader has nothing to log out of.
fn suite_account(email: &str) -> String {
    let email = email.trim();
    if email.is_empty() || email == "\u{2014}" {
        return r#"<span class="user-email user-email--none">No session</span>"#.to_string();
    }
    let initial = email
        .chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_else(|| "S".to_string());
    format!(
        r#"<span class="userchip"><span class="userchip__avatar" aria-hidden="true">{initial}</span><span class="user-email">{email}</span></span><a class="suitebar__out" href="{logout}">Log out</a>"#,
        initial = esc(&initial),
        email = esc(email),
        logout = LOGOUT_URL,
    )
}

/// The section bar: this surface's own pages, under the suite bar. `nav` is the surface's
/// existing navigation markup; `right` takes the controls that sit opposite it.
pub fn section_bar(nav: &str, right: &str) -> String {
    if nav.is_empty() && right.is_empty() {
        return String::new();
    }
    format!(
        r#"<div class="subbar">{nav}<span class="subbar__spacer"></span><div class="subbar__right">{right}</div></div>"#
    )
}

/// The estate footer: what this page is, then every surface of the suite.
pub const FOOTER: &str = r##"<footer class="v2-foot">
  <span class="v2-foot__lead">Steadholme · Scriptoria · paste.w33d.xyz</span>
  <a href="https://blog.w33d.xyz">Blog</a>
  <a href="https://forum.w33d.xyz">Forum</a>
  <a href="https://wiki.w33d.xyz">Wiki</a>
  <a href="https://paste.w33d.xyz">Paste</a>
  <a href="https://drive.w33d.xyz">Drive</a>
  <a href="https://comments.w33d.xyz">Comments</a>
  <a href="https://status.w33d.xyz">Status</a>
  <a href="https://w33d.xyz">All apps</a>
</footer>"##;
