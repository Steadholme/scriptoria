//! HTTP handlers + shared server-render helpers.
//!
//! `health` is the unauthenticated liveness probe; `forum` carries every page (home,
//! category, thread, new-thread form + create, reply). The shared design tokens / CSS are
//! embedded (via `include_str!`) and inlined into every page, matching the HOLDFAST
//! enterprise brand: brand gradient app-bar, indigo accent, cards, pills.

pub mod admin;
pub mod forum;
pub mod health;
pub mod insight;

use axum::http::HeaderMap;
use std::sync::OnceLock;

/// Agora-only CSS layered after Odyssey's canonical font, tokens, and components.
pub const SERVICE_CSS: &str = include_str!("../../static/service.css");

static APP_CSS: OnceLock<String> = OnceLock::new();

/// Embedded design system, inlined into each rendered page's `<style>`:
/// Odyssey's canonical CSS followed by Agora's service surface CSS.
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
/// Page shell with `{{STYLE}}`/`{{SHIELD}}`/`{{TITLE}}`/`{{USERBOX}}`/`{{CONTENT}}` slots.
pub const SHELL: &str = include_str!("../../templates/shell.html");

/// The HOLDFAST shield glyph (small, for the app-bar brand lockup).
pub const SHIELD_SVG: &str = r##"<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="hf-shield-sm" x1="8" y1="4" x2="40" y2="44" gradientUnits="userSpaceOnUse"><stop stop-color="#818CF8"/><stop offset="1" stop-color="#4F46E5"/></linearGradient></defs><path d="M24 4 8 9.5V22c0 11 7 17.4 16 21.5C33 39.4 40 33 40 22V9.5L24 4Z" fill="url(#hf-shield-sm)"/><rect x="20" y="19" width="8" height="13" rx="1" fill="#fff" fill-opacity="0.92"/><path d="M20 19v-2.5a4 4 0 0 1 8 0V19" stroke="#fff" stroke-width="2" stroke-opacity="0.92" fill="none"/></svg>"##;

/// The logout link is the GATEWAY's, not Agora's (Agora does no login of its own).
pub const LOGOUT_URL: &str = "https://sso.w33d.xyz/_gw/auth/logout";

/// Minimal HTML escaping for text/attribute interpolation (defense-in-depth against XSS).
pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Render a full page: fill the shell with the inlined CSS, the (raw) title, the Odyssey v2
/// app-bar (brand tile + forum nav + avatar user-menu), and the already-built content HTML.
pub fn render_page(title: &str, email_display: &str, content: &str) -> String {
    let active = if title == "New thread" { "new" } else { "home" };
    SHELL
        .replace("{{STYLE}}", app_css())
        .replace("{{APPBAR}}", &app_bar(active, email_display))
        .replace("{{TITLE}}", &esc(title))
        .replace("{{CONTENT}}", content)
}

/// The Agora (Forum) app-tile icon — a Lucide-style `message-square` glyph.
pub const APP_ICON: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>"##;

/// The full Odyssey v2 app-bar: the Forum app-tile + name, the forum nav (current marked
/// `.is-active`), then the "All apps" waffle and the avatar user-menu. `email_display` is the
/// already-escaped signed-in identity ("" → a minimal, no-identity avatar).
pub fn app_bar(active: &str, email_display: &str) -> String {
    let nav = format!(
        concat!(
            r#"<nav class="appbar__nav" aria-label="Agora">"#,
            r#"<a class="appnav{a_home}" href="/"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M9 22V12h6v10"/></svg>Home</a>"#,
            r#"<a class="appnav{a_new}" href="/new"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12h14"/><path d="M12 5v14"/></svg>New thread</a>"#,
            r#"</nav>"#,
        ),
        a_home = if active == "home" { " is-active" } else { "" },
        a_new = if active == "new" { " is-active" } else { "" },
    );
    format!(
        r#"<header class="appbar">
  <a class="appbar__brand" href="/" aria-label="HOLDFAST Agora home">
    <span class="app-tile" aria-hidden="true">{icon}</span>
    <span class="appbar__name"><b>Forum</b><span>forum.w33d.xyz</span></span>
  </a>
  {nav}
  <span class="appbar__spacer"></span>
  <div class="appbar__right">{right}</div>
</header>"#,
        icon = APP_ICON,
        nav = nav,
        right = user_menu(email_display),
    )
}

/// The app-bar's right cluster: the "All apps" waffle to the apex portal and the avatar user-menu
/// (Account / All apps / the preserved cross-subdomain gateway Sign-out). Legacy `allapps`/
/// `userchip` hooks are retained. `email_display` is the already-escaped identity; "" → a minimal,
/// no-identity avatar (never breaks rendering).
pub fn user_menu(email_display: &str) -> String {
    let has_id = !email_display.is_empty();
    let (avatar, name_html, head_name, head_sub) = if has_id {
        let initial = email_display
            .chars()
            .find(|c| c.is_alphanumeric())
            .map(|c| c.to_uppercase().to_string())
            .unwrap_or_else(|| "U".to_string());
        (
            esc(&initial),
            format!("<span class=\"usermenu__name\">{email_display}</span>"),
            email_display.to_string(),
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

/// Render a branded error page (used by `AppError::into_response`).
pub fn render_error(heading: &str, message: &str) -> String {
    let content = format!(
        r#"<nav class="crumbs"><a href="/">Home</a></nav>
<section class="card pad empty-card">
  <h1 class="empty-title">{heading}</h1>
  <p class="muted">{message}</p>
  <p><a class="btn btn-primary" href="/">Back to the forum</a></p>
</section>"#,
        heading = esc(heading),
        message = esc(message),
    );
    render_page(heading, "", &content)
}

/// The signed-in email for the app-bar (pre-escaped), or an empty string when no gateway
/// session injected one (the app-bar then shows no user chip).
pub fn email_display(headers: &HeaderMap) -> String {
    match crate::auth::identity_email(headers) {
        Some(e) => esc(&e),
        None => String::new(),
    }
}

/// Compact "N ago" relative time from `ts` to `now` (both epoch seconds).
pub fn rel_time(ts: i64, now: i64) -> String {
    let d = now.saturating_sub(ts);
    if d < 5 {
        "just now".to_string()
    } else if d < 60 {
        format!("{d}s ago")
    } else if d < 3_600 {
        format!("{}m ago", d / 60)
    } else if d < 86_400 {
        format!("{}h ago", d / 3_600)
    } else {
        format!("{}d ago", d / 86_400)
    }
}

/// Format epoch seconds as a compact UTC timestamp `YYYY-MM-DD HH:MM UTC`.
pub fn fmt_ts(secs: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02} UTC",
            dt.year(),
            dt.month() as u8,
            dt.day(),
            dt.hour(),
            dt.minute(),
        ),
        Err(_) => secs.to_string(),
    }
}

/// "N replies" / "N reply" label from a post count (which includes the original post).
pub fn replies_label(post_count: i64) -> String {
    let replies = (post_count - 1).max(0);
    if replies == 1 {
        "1 reply".to_string()
    } else {
        format!("{replies} replies")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html_metacharacters() {
        assert_eq!(esc("<b>&\"'"), "&lt;b&gt;&amp;&quot;&#x27;");
    }

    #[test]
    fn formats_epoch_as_utc() {
        // 2023-11-14T22:13:20Z = 1_700_000_000 s.
        assert_eq!(fmt_ts(1_700_000_000), "2023-11-14 22:13 UTC");
    }

    #[test]
    fn replies_label_pluralises() {
        assert_eq!(replies_label(1), "0 replies");
        assert_eq!(replies_label(2), "1 reply");
        assert_eq!(replies_label(4), "3 replies");
    }
}
