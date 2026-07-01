//! HTTP handlers + shared server-render helpers.
//!
//! - [`health`] — unauthenticated liveness probe (`/healthz`).
//! - [`paste`] — the SSO pastebin surface (new form, create, view, raw, delete).
//!
//! The shared design tokens / CSS are embedded (via `include_str!`) and inlined into every
//! page, matching the HOLDFAST enterprise brand: brand gradient, indigo accent, cards,
//! buttons, the app-bar with the shield + wordmark. All producer-supplied text is HTML-escaped
//! on render (defense-in-depth against stored XSS); the service injects NO raw HTML.

pub mod health;
pub mod paste;

use axum::http::StatusCode;
use axum::response::Html;

/// Embedded design system, inlined into each rendered page's `<style>`.
pub const APP_CSS: &str = include_str!("../../static/app.css");

/// The HOLDFAST shield glyph (small, for the app-bar brand lockup).
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

/// Render the branded error page (used by [`crate::error::AppError`] and the not-found/expired
/// paths). `email` is shown in the app-bar when a gateway identity is known.
pub fn render_error(
    status: StatusCode,
    heading: &str,
    message: &str,
    email: Option<&str>,
) -> (StatusCode, Html<String>) {
    let body = ERROR_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("Pastefire", email))
        .replace("{{STATUS}}", &status.as_u16().to_string())
        .replace("{{HEADING}}", &esc(heading))
        .replace("{{MESSAGE}}", &esc(message));
    (status, Html(body))
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
