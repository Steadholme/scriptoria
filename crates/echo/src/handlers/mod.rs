//! HTTP handlers + shared server-render helpers.
//!
//! `health` is the unauthenticated liveness probe; `comments` carries the dashboard, the thread
//! view, the embeddable view, and the SSO+CSRF comment/moderate flow.
//!
//! The shared design tokens / CSS are embedded (via `include_str!`) and inlined into every page,
//! matching the Steadholme enterprise brand (the same look as the Keystone/inkwell UI): brand
//! gradient, indigo accent, cards, app-bar.

pub mod admin;
pub mod comments;
pub mod health;

use axum::http::StatusCode;

/// Echo-only CSS layered after Odyssey's canonical font, tokens, and components.
pub const SERVICE_CSS: &str = include_str!("../../static/service.css");

static APP_CSS: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Embedded design system, inlined into each rendered page's `<style>`:
/// Odyssey's canonical CSS followed by Echo's service surface CSS.
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

/// Render the shared Odyssey v2 app-bar: the Comments app-tile + name, the moderator nav (current
/// marked `.is-active`), then the "All apps" waffle and the avatar user-menu (Account / All apps /
/// the preserved gateway Sign-out). `page_title` selects the active nav item; `email` empty or `—`
/// → a minimal, no-identity avatar (never breaks rendering).
pub fn topbar(page_title: &str, email: &str) -> String {
    let a_dash = if page_title == "Admin" { "" } else { " is-active" };
    let nav = format!(
        concat!(
            r#"<nav class="appbar__nav" aria-label="Echo">"#,
            r#"<a class="appnav{a_dash}" href="/"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/></svg>Dashboard</a>"#,
            r#"</nav>"#,
        ),
        a_dash = a_dash,
    );
    format!(
        r#"<header class="appbar">
  <a class="appbar__brand" href="/" aria-label="Steadholme Echo home">
    <span class="app-tile" aria-hidden="true">{icon}</span>
    <span class="appbar__name"><b>Comments</b><span>comments.w33d.xyz</span></span>
  </a>
  {nav}
  <span class="appbar__spacer"></span>
  <div class="appbar__right">{right}</div>
</header>"#,
        icon = APP_ICON,
        nav = nav,
        right = user_menu(email),
    )
}

/// The app-bar's right cluster: the "All apps" waffle to the apex portal and the avatar user-menu.
/// Legacy `allapps`/`userchip` hooks are retained on the new elements. `email` empty or `—` → a
/// minimal, no-identity avatar. The Sign-out preserves the exact gateway logout route/method.
pub fn user_menu(email: &str) -> String {
    let e = email.trim();
    let has_id = !e.is_empty() && e != "—";
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
        <a class="menuitem menuitem--danger" href="{logout}" role="menuitem"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5"/><path d="M21 12H9"/></svg>Sign out</a>
      </div>
    </div>"#,
        avatar = avatar,
        name = name_html,
        head_name = head_name,
        head_sub = head_sub,
        logout = LOGOUT_URL,
    )
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
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<link rel="icon" href="data:,">
<title>{code} {reason} · Echo</title><style>{css}</style></head>
<body class="page-reading">
{topbar}
<main class="reader">
  <div class="error-card">
    <div class="error-card__code">{code}</div>
    <h1 class="error-card__title">{reason}</h1>
    <p class="error-card__msg">{msg}</p>
    <a class="btn btn-primary" href="/">Back to the dashboard</a>
  </div>
</main>
</body></html>"#,
        css = app_css(),
        topbar = topbar("Echo", "—"),
        code = code,
        reason = esc(reason),
        msg = esc(message),
    )
}
