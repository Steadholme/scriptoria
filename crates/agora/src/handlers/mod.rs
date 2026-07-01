//! HTTP handlers + shared server-render helpers.
//!
//! `health` is the unauthenticated liveness probe; `forum` carries every page (home,
//! category, thread, new-thread form + create, reply). The shared design tokens / CSS are
//! embedded (via `include_str!`) and inlined into every page, matching the HOLDFAST
//! enterprise brand: brand gradient app-bar, indigo accent, cards, pills.

pub mod forum;
pub mod health;
pub mod insight;

use axum::http::HeaderMap;

/// Embedded design system, inlined into each rendered page's `<style>`.
pub const APP_CSS: &str = include_str!("../../static/app.css");
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

/// Render a full page: fill the shell with the inlined CSS, the (raw) title, the shared app-bar
/// userbox (built from the pre-escaped signed-in email), and the already-built content HTML.
pub fn render_page(title: &str, email_display: &str, content: &str) -> String {
    SHELL
        .replace("{{STYLE}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox(email_display))
        .replace("{{TITLE}}", &esc(title))
        .replace("{{CONTENT}}", content)
}

/// The app-bar's right cluster: an "All apps" link back to the apex portal, the signed-in user
/// chip (avatar initial + email) when a gateway identity is present, and the cross-subdomain
/// logout. `email_display` is the already-escaped identity; an empty string means no gateway
/// session, in which case no user chip is shown (public chrome).
pub fn userbox(email_display: &str) -> String {
    let chip = if email_display.is_empty() {
        String::new()
    } else {
        let initial = email_display
            .chars()
            .next()
            .map(|c| c.to_uppercase().to_string())
            .unwrap_or_else(|| "H".to_string());
        format!(
            "<span class=\"userchip\"><span class=\"userchip__avatar\" aria-hidden=\"true\">{}</span><span class=\"user-email\">{}</span></span>",
            esc(&initial),
            email_display,
        )
    };
    format!(
        concat!(
            "<a class=\"allapps\" href=\"https://w33d.xyz\" title=\"All apps\">",
            "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\">",
            "<rect x=\"3\" y=\"3\" width=\"7\" height=\"7\" rx=\"1.5\"/><rect x=\"14\" y=\"3\" width=\"7\" height=\"7\" rx=\"1.5\"/>",
            "<rect x=\"3\" y=\"14\" width=\"7\" height=\"7\" rx=\"1.5\"/><rect x=\"14\" y=\"14\" width=\"7\" height=\"7\" rx=\"1.5\"/></svg>All apps</a>",
            "{chip}",
            "<a class=\"btn btn-ghost btn-sm\" href=\"{logout}\">Log out</a>",
        ),
        chip = chip,
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
