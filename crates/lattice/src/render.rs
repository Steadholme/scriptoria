//! Server-side HTML rendering helpers: escaping, the page shell, timestamps, error pages.
//!
//! The enterprise HOLDFAST shell (top app-bar with the shield + wordmark + page name, and the
//! signed-in email + Logout on the right) and the design-system CSS are embedded via
//! `include_str!`, so every page is self-contained with no asset round-trips. Each handler
//! builds only its inner `content` HTML and hands it to [`layout`].

use crate::auth;
use axum::http::HeaderMap;

/// Embedded design-system CSS (brand tokens shared across the HOLDFAST estate).
const APP_CSS: &str = include_str!("../static/app.css");
/// Page shell with `{{...}}` slots.
const LAYOUT: &str = include_str!("../templates/layout.html");

/// Cross-subdomain SSO logout (terminated at the Keystone IdP behind the gateway).
const LOGOUT_URL: &str = "https://id.w33d.xyz/_gw/auth/logout";

/// Wrap inner `content` HTML in the full HOLDFAST shell.
///
/// `page_title` is escaped into the `<title>` and the app-bar; `headers` supplies the
/// gateway-injected signed-in email shown on the right. `content` is already-safe HTML built by
/// the handler.
pub fn layout(page_title: &str, headers: &HeaderMap, content: &str) -> String {
    let email = auth::signed_in_email(headers);
    LAYOUT
        .replace("{{STYLE}}", APP_CSS)
        .replace("{{PAGE_TITLE}}", &esc(page_title))
        .replace("{{USERBOX}}", &userbox(email.as_deref()))
        .replace("{{CONTENT}}", content)
}

/// The right side of the shared HOLDFAST app-bar: an "All apps" link back to the apex portal, a
/// user chip (avatar initial + signed-in email) when a gateway identity is known, and the
/// cross-subdomain logout link. Public/no-session renders keep the All-apps link without a chip.
fn userbox(email: Option<&str>) -> String {
    const ALLAPPS: &str = concat!(
        "<a class=\"allapps\" href=\"https://w33d.xyz\" title=\"All apps\">",
        "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\">",
        "<rect x=\"3\" y=\"3\" width=\"7\" height=\"7\" rx=\"1.5\"/><rect x=\"14\" y=\"3\" width=\"7\" height=\"7\" rx=\"1.5\"/>",
        "<rect x=\"3\" y=\"14\" width=\"7\" height=\"7\" rx=\"1.5\"/><rect x=\"14\" y=\"14\" width=\"7\" height=\"7\" rx=\"1.5\"/></svg>All apps</a>",
    );
    let chip = match email {
        Some(e) if !e.is_empty() => {
            let initial = e
                .chars()
                .next()
                .map(|c| c.to_uppercase().to_string())
                .unwrap_or_else(|| "H".to_string());
            format!(
                "<span class=\"userchip\"><span class=\"userchip__avatar\" aria-hidden=\"true\">{}</span><span class=\"user-email\" title=\"Signed in as\">{}</span></span>",
                esc(&initial),
                esc(e),
            )
        }
        _ => String::new(),
    };
    format!("{ALLAPPS}{chip}<a class=\"btn btn-ghost btn-sm\" href=\"{LOGOUT_URL}\">Log out</a>")
}

/// A standalone HOLDFAST-styled error page (used by [`crate::error::AppError`]).
pub fn error_page(status: u16, title: &str, detail: &str) -> String {
    let content = format!(
        "<section class=\"card empty-state\">\
           <div class=\"empty-state__code\">{status}</div>\
           <h1>{title}</h1>\
           <p class=\"muted\">{detail}</p>\
           <a class=\"btn btn-primary\" href=\"/\">Back to the index</a>\
         </section>",
        status = status,
        title = esc(title),
        detail = esc(detail),
    );
    // No gateway headers here — render with a generic shell.
    layout(title, &HeaderMap::new(), &content)
}

/// Minimal HTML-escape for any untrusted text rendered into the page.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Format epoch milliseconds as a compact UTC timestamp `YYYY-MM-DD HH:MM:SSZ`.
pub fn fmt_ts(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
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
        Err(_) => ms.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html_metacharacters() {
        assert_eq!(esc("<script>&\"'"), "&lt;script&gt;&amp;&quot;&#39;");
    }

    #[test]
    fn formats_epoch_ms_as_utc() {
        assert_eq!(fmt_ts(1_700_000_000_000), "2023-11-14 22:13:20Z");
    }

    #[test]
    fn layout_embeds_title_and_email() {
        let mut headers = HeaderMap::new();
        headers.insert(auth::HEADER_EMAIL, "me@holdfast.local".parse().unwrap());
        let html = layout("Home", &headers, "<p>hi</p>");
        assert!(html.contains("<p>hi</p>"));
        assert!(html.contains("me@holdfast.local"));
        assert!(html.contains("HOLDFAST"));
        assert!(html.contains("id.w33d.xyz/_gw/auth/logout"));
        // Shared app-bar chrome: the "All apps" link back to the apex portal + the user chip.
        assert!(html.contains("class=\"allapps\""));
        assert!(html.contains("https://w33d.xyz"));
        assert!(html.contains("class=\"userchip\""));
    }
}
