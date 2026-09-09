//! Server-side HTML rendering helpers: escaping, the page shell, timestamps, error pages.
//!
//! The Lattice shell and product-owned design system are embedded in the binary. Each handler
//! builds only its inner `content` HTML and hands it to [`layout`].

use crate::auth;
use axum::http::{
    header::{self, ACCEPT_LANGUAGE, COOKIE},
    HeaderMap, HeaderValue,
};
use axum::response::{IntoResponse, Response};

/// Complete, product-owned Lattice visual system.
const SERVICE_CSS: &str = include_str!("../static/service.css");

pub const APP_CSS_PATH: &str = "/assets/lattice-20260909.css";

static APP_CSS: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Embedded, product-owned design-system CSS.
fn app_css() -> &'static str {
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
/// Page shell with `{{...}}` slots.
const LAYOUT: &str = include_str!("../templates/layout.html");

/// Cross-subdomain SSO logout (terminated at the Keystone IdP behind the gateway).
const LOGOUT_URL: &str = "https://sso.w33d.xyz/_gw/auth/logout";

/// Wrap inner `content` HTML in the full Steadholme shell.
///
/// `page_title` is escaped into the `<title>` and the app-bar; `headers` supplies the
/// gateway-injected signed-in email shown on the right. `content` is already-safe HTML built by
/// the handler.
pub fn layout(page_title: &str, headers: &HeaderMap, content: &str) -> String {
    let email = auth::signed_in_email(headers);
    let cookie = headers.get(COOKIE).and_then(|value| value.to_str().ok());
    let accept_language = headers
        .get(ACCEPT_LANGUAGE)
        .and_then(|value| value.to_str().ok());
    let locale = odyssey::resolve_locale(cookie, accept_language);
    let theme = odyssey::resolve_theme(cookie);
    let active = if page_title == "Recent changes" {
        "recent"
    } else if page_title == "Workspace health" {
        "coherence"
    } else if page_title.starts_with("Create") {
        "new"
    } else {
        "home"
    };
    LAYOUT
        .replace("{{LANG}}", locale.bcp47())
        .replace("{{HTML_THEME}}", odyssey::html_theme_attr(theme))
        .replace("{{COLOR_SCHEME}}", odyssey::color_scheme_meta(theme))
        .replace("{{PAGE_TITLE}}", &esc(page_title))
        .replace(
            "{{APPBAR}}",
            &app_bar(active, email.as_deref(), locale, theme),
        )
        .replace("{{FOOTER}}", FOOTER)
        .replace("{{CONTENT}}", content)
}

/// The Lattice app-tile icon — a Lucide-style `book-open` glyph.
pub const APP_ICON: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>"##;

/// Lattice's chrome: the Scriptoria suite bar (six vhosts, Wiki filled) over a section bar
/// carrying the wiki's own pages, its global search, and the estate preference switches.
fn app_bar(active: &str, email: Option<&str>, locale: odyssey::Locale, theme: &str) -> String {
    let nav = format!(
        concat!(
            r#"<nav class="appbar__nav" aria-label="Lattice">"#,
            r#"<a class="appnav{a_home}" href="/"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M9 22V12h6v10"/></svg>Home</a>"#,
            r#"<a class="appnav{a_recent}" href="/recent"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 8v5l3 2"/><circle cx="12" cy="12" r="10"/></svg>Recent changes</a>"#,
            r#"<a class="appnav{a_new}" href="/new"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12h14"/><path d="M12 5v14"/></svg>New page</a>"#,
            r#"<a class="appnav{a_coh}" href="/coherence"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>Workspace health</a>"#,
            r#"</nav>"#,
        ),
        a_home = if active == "home" { " is-active" } else { "" },
        a_recent = if active == "recent" { " is-active" } else { "" },
        a_new = if active == "new" { " is-active" } else { "" },
        a_coh = if active == "coherence" {
            " is-active"
        } else {
            ""
        },
    );
    let preferences = format!(
        "<div class=\"appbar__preferences\">{}{}</div>",
        odyssey::theme_switcher(theme, locale).0,
        odyssey::lang_switcher(locale).0,
    );
    let search = r#"<form class="lattice-search" role="search" method="get" action="/search">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
    <label class="sr-only" for="lattice-global-search">Search documents</label>
    <input id="lattice-global-search" type="search" name="q" placeholder="Search documents" autocomplete="off">
    <kbd aria-hidden="true">/</kbd>
  </form>"#;
    format!(
        "{}{}",
        suite_bar(email.unwrap_or(""), ""),
        section_bar(&nav, &format!("{search}{preferences}")),
    )
}

/// A standalone Steadholme-styled error page (used by [`crate::error::AppError`]).
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
        headers.insert(auth::HEADER_EMAIL, "me@steadholme.local".parse().unwrap());
        let html = layout("Home", &headers, "<p>hi</p>");
        assert!(html.contains("<p>hi</p>"));
        assert!(html.contains("me@steadholme.local"));
        assert!(html.contains("Steadholme"));
        assert!(html.contains("sso.w33d.xyz/_gw/auth/logout"));
        // Suite chrome: the six-surface switcher, the "All apps" link back to the apex
        // portal, and the identity chip.
        assert!(html.contains("class=\"suitebar\""));
        assert!(html.contains("class=\"surf surf--wiki is-active\""));
        assert!(html.contains("class=\"surf surf--blog\""));
        assert!(html.contains("allapps"));
        assert!(html.contains("https://w33d.xyz"));
        assert!(html.contains("userchip"));
    }

    #[test]
    fn layout_resolves_theme_and_locale_from_request_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            "__Secure-theme=dark; __Secure-lang=ja".parse().unwrap(),
        );
        let html = layout("Home", &headers, "<p>hi</p>");

        assert!(html.contains("<html lang=\"ja\" data-theme=\"dark\">"));
        assert!(html.contains("content=\"dark\""));
        assert!(html.contains("/_gw/theme?to=auto"));
        assert!(html.contains("/_gw/lang?to=zh"));
    }
}

// ===== Scriptoria v2 suite chrome =====

/// This surface's key in the design's `surf/*` set, and the vhost it answers on.
pub const SURFACE_KEY: &str = "wiki";
pub const SURFACE_HOST: &str = "wiki.w33d.xyz";

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
  <a class="suitebar__brand" href="/" aria-label="Scriptoria Wiki home">
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
  <span class="v2-foot__lead">Steadholme · Scriptoria · wiki.w33d.xyz</span>
  <a href="https://blog.w33d.xyz">Blog</a>
  <a href="https://forum.w33d.xyz">Forum</a>
  <a href="https://wiki.w33d.xyz">Wiki</a>
  <a href="https://paste.w33d.xyz">Paste</a>
  <a href="https://drive.w33d.xyz">Drive</a>
  <a href="https://comments.w33d.xyz">Comments</a>
  <a href="https://status.w33d.xyz">Status</a>
  <a href="https://w33d.xyz">All apps</a>
</footer>"##;
