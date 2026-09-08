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

pub const APP_CSS_PATH: &str = "/assets/lattice-20260908.css";

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
        .replace("{{CONTENT}}", content)
}

/// The Lattice app-tile icon — a Lucide-style `book-open` glyph.
pub const APP_ICON: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>"##;

/// The Lattice app-bar: product brand + workspace nav + estate preferences, then the
/// "All apps" waffle and avatar user-menu. Public/no-session renders keep a minimal avatar.
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
    format!(
        r#"<header class="appbar">
  <a class="appbar__brand" href="/" aria-label="Steadholme Lattice home">
    <span class="app-tile" aria-hidden="true">{icon}</span>
    <span class="appbar__name"><b>Lattice</b><span>Knowledge workspace</span></span>
  </a>
  {nav}
  <form class="lattice-search" role="search" method="get" action="/search">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
    <label class="sr-only" for="lattice-global-search">Search documents</label>
    <input id="lattice-global-search" type="search" name="q" placeholder="Search documents" autocomplete="off">
    <kbd aria-hidden="true">/</kbd>
  </form>
  <span class="appbar__spacer"></span>
  <div class="appbar__right">{preferences}{right}</div>
</header>"#,
        icon = APP_ICON,
        nav = nav,
        preferences = preferences,
        right = user_menu(email),
    )
}

/// The app-bar's right cluster: the "All apps" waffle and the avatar user-menu (Account / All apps
/// / the preserved cross-subdomain gateway Sign-out). Legacy `allapps`/`userchip` hooks are kept.
/// `None`/empty identity → a minimal, no-identity avatar (never breaks rendering).
fn user_menu(email: Option<&str>) -> String {
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
        // Product app-bar chrome: the "All apps" link back to the apex portal + the avatar
        // user-menu. Compatibility hooks remain on the product-owned elements.
        assert!(html.contains("class=\"appbar\""));
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
