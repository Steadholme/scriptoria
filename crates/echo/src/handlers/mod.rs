//! HTTP handlers + shared server-render helpers.
//!
//! `health` is the unauthenticated liveness probe; `comments` carries the dashboard, the thread
//! view, the embeddable view, and the SSO+CSRF comment/moderate flow.
//!
//! Echo's product-owned design tokens / CSS are embedded (via `include_str!`) and served to every
//! page. Nonvisual gateway and identity helpers remain shared without owning Echo's presentation.

pub mod admin;
pub mod comments;
pub mod health;

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

/// Echo's complete product-owned visual system.
pub const SERVICE_CSS: &str = include_str!("../../static/service.css");

pub const APP_CSS_PATH: &str = "/assets/echo-20260909.css";

static APP_CSS: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Complete, product-owned Echo visual system.
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

/// Cross-subdomain gateway logout (Echo lives at comments.w33d.xyz; the IdP is at id.w33d.xyz).
pub const LOGOUT_URL: &str = "https://sso.w33d.xyz/_gw/auth/logout";

/// The Steadholme shield glyph (small, for the app-bar brand lockup).
pub const SHIELD_SVG: &str = r##"<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="hf-shield-sm" x1="8" y1="4" x2="40" y2="44" gradientUnits="userSpaceOnUse"><stop stop-color="#818CF8"/><stop offset="1" stop-color="#4F46E5"/></linearGradient></defs><path d="M24 4 8 9.5V22c0 11 7 17.4 16 21.5C33 39.4 40 33 40 22V9.5L24 4Z" fill="url(#hf-shield-sm)"/><rect x="20" y="19" width="8" height="13" rx="1" fill="#fff" fill-opacity="0.92"/><path d="M20 19v-2.5a4 4 0 0 1 8 0V19" stroke="#fff" stroke-width="2" stroke-opacity="0.92" fill="none"/></svg>"##;

/// Minimal HTML escaping for text/attribute interpolation (defense-in-depth on every field).
pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// The Echo (Comments) app-tile icon — a Lucide-style `messages-square` glyph.
pub const APP_ICON: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 9a2 2 0 0 1-2 2H6l-4 4V4a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2z"/><path d="M18 9h2a2 2 0 0 1 2 2v11l-4-4h-6a2 2 0 0 1-2-2v-1"/></svg>"##;

/// Render Echo's chrome: the Scriptoria suite bar (six vhosts, this one filled) over a section
/// bar carrying Echo's own pages. `page_title` selects the active section; `email` empty or `—`
/// means no gateway session, and the suite bar then states that instead of guessing an identity.
pub fn topbar(page_title: &str, email: &str) -> String {
    let a_dash = if page_title == "Admin" {
        ""
    } else {
        " is-active"
    };
    let nav = format!(
        concat!(
            r#"<nav class="appbar__nav" aria-label="Echo">"#,
            r#"<a class="appnav{a_dash}" href="/"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/></svg>Dashboard</a>"#,
            r#"</nav>"#,
        ),
        a_dash = a_dash,
    );
    format!("{}{}", suite_bar(email, ""), section_bar(&nav, ""))
}

/// Format epoch seconds as a compact UTC date-time `Mon D, YYYY HH:MM` (e.g. `Jun 29, 2026
/// 14:07`). std `time` only, no extra C deps.
pub fn fmt_datetime(secs: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => format!(
            "{} {}, {} {:02}:{:02}",
            month_abbr(dt.month()),
            dt.day(),
            dt.year(),
            dt.hour(),
            dt.minute()
        ),
        Err(_) => secs.to_string(),
    }
}

fn month_abbr(m: time::Month) -> &'static str {
    use time::Month::*;
    match m {
        January => "Jan",
        February => "Feb",
        March => "Mar",
        April => "Apr",
        May => "May",
        June => "Jun",
        July => "Jul",
        August => "Aug",
        September => "Sep",
        October => "Oct",
        November => "Nov",
        December => "Dec",
    }
}

/// A small, branded HTML error page (used by [`crate::error::AppError`]).
pub fn error_page(status: StatusCode, message: &str) -> String {
    let code = status.as_u16();
    let reason = status.canonical_reason().unwrap_or("Error");
    format!(
        r##"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<link rel="icon" href="data:,">
<title>{code} {reason} · Echo</title><link rel="stylesheet" href="{css_path}"></head>
<body class="page-v2">
<a class="skip-link" href="#main">Skip to the page</a>
{topbar}
<main class="v2-page v2-page--narrow" id="main" tabindex="-1">
  <div class="error-card">
    <div class="error-card__code">{code}</div>
    <h1 class="error-card__title">{reason}</h1>
    <p class="error-card__msg">{msg}</p>
    <a class="btn btn-primary" href="/">Back to the dashboard</a>
  </div>
{footer}
</main>
</body></html>"##,
        css_path = APP_CSS_PATH,
        topbar = topbar("Echo", "—"),
        footer = FOOTER,
        code = code,
        reason = esc(reason),
        msg = esc(message),
    )
}

// ===== Scriptoria v2 suite chrome =====

/// This surface's key in the design's `surf/*` set, and the vhost it answers on.
pub const SURFACE_KEY: &str = "comments";
pub const SURFACE_HOST: &str = "comments.w33d.xyz";

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
  <a class="suitebar__brand" href="/" aria-label="Scriptoria Comments home">
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
  <span class="v2-foot__lead">Steadholme · Scriptoria · comments.w33d.xyz</span>
  <a href="https://blog.w33d.xyz">Blog</a>
  <a href="https://forum.w33d.xyz">Forum</a>
  <a href="https://wiki.w33d.xyz">Wiki</a>
  <a href="https://paste.w33d.xyz">Paste</a>
  <a href="https://drive.w33d.xyz">Drive</a>
  <a href="https://comments.w33d.xyz">Comments</a>
  <a href="https://status.w33d.xyz">Status</a>
  <a href="https://w33d.xyz">All apps</a>
</footer>"##;
