//! HTTP handlers + shared server-render helpers.
//!
//! `health` is the unauthenticated liveness probe; `posts` carries the reading views and the
//! SSO-gated compose/edit/delete flow.
//!
//! Inkwell's product-owned CSS is embedded into the binary and served as a versioned asset.

pub mod admin;
pub mod ask;
pub mod feed;
pub mod health;
pub mod library;
pub mod posts;
pub mod search;

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

/// Complete Inkwell visual system. Theme resolution stays non-visual; the UI no longer inherits
/// Odyssey's CSS so the publishing product owns its typography, material, and components.
pub const SERVICE_CSS: &str = include_str!("../../static/service.css");

pub const APP_CSS_PATH: &str = "/assets/inkwell-20260908.css";

static APP_CSS: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Embedded, product-owned design system.
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

/// Cross-subdomain gateway logout (Inkwell lives at blog.w33d.xyz; the IdP is at id.w33d.xyz).
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

/// The Inkwell (Blog) app-tile icon — a Lucide-style `file-text` glyph.
pub const APP_ICON: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M16 13H8"/><path d="M16 17H8"/><path d="M10 9H8"/></svg>"##;

/// Render Inkwell's app-bar: the Blog app-tile + name on the left, reader navigation
/// followed by one stable Studio entry, then an "All apps" waffle back to the apex portal and the
/// avatar user-menu (Account / All apps / the preserved gateway Sign-out) on the right. Ordinary
/// Reader pages keep Studio representation-stable; the separate bearer-review shell suppresses it
/// for capability readers. `page_title` selects the active nav item; `email` is the gateway-injected
/// address (empty or the neutral `—` placeholder on public, no-session reading pages → a minimal,
/// no-identity avatar).
pub fn topbar(page_title: &str, email: &str, is_admin: bool, theme: &str) -> String {
    topbar_with_studio(page_title, email, is_admin, theme, true)
}

fn topbar_with_studio(
    page_title: &str,
    email: &str,
    is_admin: bool,
    theme: &str,
    show_studio: bool,
) -> String {
    let active = match page_title {
        "Search" => "search",
        "Ask" => "ask",
        "Studio" | "Library" => "studio",
        _ => "posts",
    };
    let admin_nav = if is_admin {
        r#"<a class="appnav" href="/admin">Admin</a>"#
    } else {
        ""
    };
    let studio_nav = if show_studio {
        format!(
            r#"<a class="appnav appnav--studio{active}" href="/library"{current}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L8 18l-4 1 1-4Z"/></svg>Studio</a>"#,
            active = if active == "studio" { " is-active" } else { "" },
            current = if active == "studio" {
                r#" aria-current="page""#
            } else {
                ""
            },
        )
    } else {
        String::new()
    };
    let nav = format!(
        concat!(
            r#"<nav class="appbar__nav" aria-label="Blog sections">"#,
            r#"<a class="appnav{a_posts}" href="/"{c_posts}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M9 22V12h6v10"/></svg>Posts</a>"#,
            r#"<a class="appnav{a_search}" href="/search"{c_search}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>Search</a>"#,
            r#"<a class="appnav{a_ask}" href="/ask"{c_ask}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m12 3-1.9 5.8a2 2 0 0 1-1.3 1.3L3 12l5.8 1.9a2 2 0 0 1 1.3 1.3L12 21l1.9-5.8a2 2 0 0 1 1.3-1.3L21 12l-5.8-1.9a2 2 0 0 1-1.3-1.3z"/><path d="M5 3v4"/><path d="M19 17v4"/><path d="M3 5h4"/><path d="M17 19h4"/></svg>Ask</a>"#,
            r#"{studio_nav}"#,
            r#"{admin_nav}"#,
            r#"</nav>"#,
        ),
        a_posts = if active == "posts" { " is-active" } else { "" },
        a_search = if active == "search" { " is-active" } else { "" },
        a_ask = if active == "ask" { " is-active" } else { "" },
        c_posts = if active == "posts" {
            r#" aria-current="page""#
        } else {
            ""
        },
        c_search = if active == "search" {
            r#" aria-current="page""#
        } else {
            ""
        },
        c_ask = if active == "ask" {
            r#" aria-current="page""#
        } else {
            ""
        },
        studio_nav = studio_nav,
        admin_nav = admin_nav,
    );
    format!(
        r#"<header class="appbar">
  <a class="appbar__brand" href="/" aria-label="Steadholme Inkwell home">
    <span class="app-tile" style="--app:var(--brand);--app-soft:var(--brand-soft)" aria-hidden="true">{icon}</span>
    <span class="appbar__name"><b>Blog</b><span>blog.w33d.xyz</span></span>
  </a>
  {nav}
  <span class="appbar__spacer"></span>
  <div class="appbar__right">{switcher}{right}</div>
</header>"#,
        icon = APP_ICON,
        nav = nav,
        switcher = theme_switcher(theme),
        right = user_menu(email),
    )
}

/// The estate three-state theme switcher (light / dark / system) for the app-bar. Pure SSR
/// `<a href>` links to the gateway `/_gw/theme` route — no JS, no new Inkwell route. `current` marks
/// the resolved theme `.is-active`. `__Secure-theme` is a display-only preference living OUTSIDE the
/// gateway HMAC, so it is never consulted for identity/authz — it only repaints. Inkwell owns the
/// `.themeswitch` presentation in its service stylesheet.
fn theme_switcher(current: &str) -> String {
    let light_active = if current == "light" { " is-active" } else { "" };
    let dark_active = if current == "dark" { " is-active" } else { "" };
    let auto_active = if current == "auto" { " is-active" } else { "" };
    let light_cur = if current == "light" {
        r#" aria-current="true""#
    } else {
        ""
    };
    let dark_cur = if current == "dark" {
        r#" aria-current="true""#
    } else {
        ""
    };
    let auto_cur = if current == "auto" {
        r#" aria-current="true""#
    } else {
        ""
    };
    format!(
        r##"<div class="themeswitch" role="group" aria-label="Theme">
  <a class="themeswitch__opt{light_active}" href="/_gw/theme?to=light" title="Light" aria-label="Light"{light_cur}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg></a>
  <a class="themeswitch__opt{dark_active}" href="/_gw/theme?to=dark" title="Dark" aria-label="Dark"{dark_cur}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3a6.5 6.5 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg></a>
  <a class="themeswitch__opt{auto_active}" href="/_gw/theme?to=auto" title="System" aria-label="System"{auto_cur}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg></a>
</div>"##
    )
}

/// Typed per-page metadata. Keeping every value as data (rather than accepting a raw head
/// fragment) makes escaping mandatory and prevents author-controlled metadata from becoming HTML.
#[derive(Clone, Debug, Default)]
pub struct PageMeta {
    pub description: Option<String>,
    pub canonical: Option<String>,
    pub robots: Option<String>,
    pub og_type: Option<String>,
    pub og_title: Option<String>,
    pub og_description: Option<String>,
    pub og_image: Option<String>,
    pub twitter_card: Option<String>,
    pub twitter_title: Option<String>,
    pub twitter_description: Option<String>,
    pub twitter_image: Option<String>,
}

/// Typed inputs for the shared document shell. Grouping the chrome, body, and optional metadata
/// contract keeps call sites self-documenting and prevents positional argument drift.
pub struct PageShell<'a> {
    pub head_title: &'a str,
    pub body_class: &'a str,
    pub rss: bool,
    pub nav_title: &'a str,
    pub email: &'a str,
    pub is_admin: bool,
    pub theme: &'a str,
    pub fragment: &'a str,
    pub metadata: Option<&'a PageMeta>,
}

/// Render the shared shell plus an optional, escaped metadata contract.
pub fn page_shell(page: PageShell<'_>) -> String {
    let rss_link = if page.rss {
        r#"<link rel="alternate" type="application/rss+xml" title="Inkwell · Steadholme" href="/feed.xml">"#
    } else {
        ""
    };
    let head_meta = page.metadata.map(render_page_meta).unwrap_or_default();
    format!(
        r#"<!DOCTYPE html><html lang="en"{theme_attr}><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="{color_scheme}">
<link rel="icon" href="data:,">
<title>{title}</title>{rss_link}{head_meta}<link rel="stylesheet" href="{css_path}"></head><body class="{body_class}">
{topbar}{fragment}</body></html>"#,
        theme_attr = odyssey::html_theme_attr(page.theme),
        color_scheme = odyssey::color_scheme_meta(page.theme),
        title = esc(page.head_title),
        rss_link = rss_link,
        head_meta = head_meta,
        css_path = APP_CSS_PATH,
        body_class = page.body_class,
        topbar = topbar(page.nav_title, page.email, page.is_admin, page.theme),
        fragment = page.fragment,
    )
}

/// Public review capabilities use the familiar Reader chrome without exposing Studio navigation
/// or identity-dependent controls. Product CSS remains inline, so the public `/review/` edge
/// prefix needs no additional anonymous asset routes.
pub fn review_page_shell(
    head_title: &str,
    theme: &str,
    fragment: &str,
    metadata: &PageMeta,
) -> String {
    let head_meta = render_page_meta(metadata);
    format!(
        r#"<!DOCTYPE html><html lang="en"{theme_attr}><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="{color_scheme}">
<meta name="referrer" content="no-referrer">
<link rel="icon" href="data:,">
<title>{title}</title>{head_meta}<link rel="stylesheet" href="{css_path}"></head><body class="page-reading page-review-link">
{topbar}{fragment}</body></html>"#,
        theme_attr = odyssey::html_theme_attr(theme),
        color_scheme = odyssey::color_scheme_meta(theme),
        title = esc(head_title),
        head_meta = head_meta,
        css_path = APP_CSS_PATH,
        topbar = topbar_with_studio("Reading", "—", false, theme, false),
        fragment = fragment,
    )
}

fn render_page_meta(meta: &PageMeta) -> String {
    let mut out = String::new();
    push_name_meta(&mut out, "description", meta.description.as_deref());
    if let Some(url) = meta.canonical.as_deref() {
        out.push_str(&format!("<link rel=\"canonical\" href=\"{}\">", esc(url)));
    }
    push_name_meta(&mut out, "robots", meta.robots.as_deref());
    push_property_meta(&mut out, "og:type", meta.og_type.as_deref());
    push_property_meta(&mut out, "og:title", meta.og_title.as_deref());
    push_property_meta(&mut out, "og:description", meta.og_description.as_deref());
    push_property_meta(&mut out, "og:url", meta.canonical.as_deref());
    push_property_meta(&mut out, "og:image", meta.og_image.as_deref());
    push_name_meta(&mut out, "twitter:card", meta.twitter_card.as_deref());
    push_name_meta(&mut out, "twitter:title", meta.twitter_title.as_deref());
    push_name_meta(
        &mut out,
        "twitter:description",
        meta.twitter_description.as_deref(),
    );
    push_name_meta(&mut out, "twitter:image", meta.twitter_image.as_deref());
    out
}

fn push_name_meta(out: &mut String, name: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        out.push_str(&format!(
            "<meta name=\"{}\" content=\"{}\">",
            esc(name),
            esc(value)
        ));
    }
}

fn push_property_meta(out: &mut String, property: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        out.push_str(&format!(
            "<meta property=\"{}\" content=\"{}\">",
            esc(property),
            esc(value)
        ));
    }
}

/// Product excerpt: prefer the author's explicit summary, falling back to Markdown-derived text.
/// The requested character cap is applied to either source so cards/feeds keep their contracts.
pub fn post_excerpt(post: &crate::store::Post, max_chars: usize) -> String {
    let explicit = post.custom_excerpt.trim();
    if explicit.is_empty() {
        return crate::markdown::excerpt(&post.body_md, max_chars);
    }
    if explicit.chars().count() > max_chars {
        let truncated: String = explicit.chars().take(max_chars).collect();
        format!("{}…", truncated.trim_end())
    } else {
        explicit.to_string()
    }
}

/// The app-bar's right cluster (shared by every Inkwell surface): the "All apps" waffle to the
/// apex portal and the avatar user-menu. Legacy `allapps`/`userchip` hooks are retained on the new
/// elements. `email` empty or `—` → a minimal, no-identity avatar (never breaks rendering). The
/// Sign-out preserves the exact gateway logout route/method (a cross-subdomain GET link).
pub fn user_menu(email: &str) -> String {
    let has_id = !email.is_empty() && email != "—";
    let initials = if has_id {
        email
            .chars()
            .find(|c| c.is_alphanumeric())
            .map(|c| c.to_uppercase().to_string())
            .unwrap_or_else(|| "U".to_string())
    } else {
        String::new()
    };
    let (avatar_inner, name_html, head_name, head_sub) = if has_id {
        (
            esc(&initials),
            format!("<span class=\"usermenu__name\">{}</span>", esc(email)),
            esc(email),
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
        avatar = avatar_inner,
        name = name_html,
        head_name = head_name,
        head_sub = head_sub,
        logout = LOGOUT_URL,
    )
}

/// Render a post's tags as a row of chips linking to their `/tag/{slug}` listing. Returns the
/// empty string when the post carries no tags (so the block is hidden). Every field is escaped;
/// parsing/slugging is shared with the `/tag/{slug}` route via [`crate::tags`].
pub fn tag_chips(raw_tags: &str) -> String {
    let tags = crate::tags::parse_tags(raw_tags);
    if tags.is_empty() {
        return String::new();
    }
    let mut chips = String::new();
    for t in &tags {
        chips.push_str(&format!(
            r#"<a class="tag" href="/tag/{slug}">{label}</a>"#,
            slug = esc(&crate::tags::tag_slug(t)),
            label = esc(t),
        ));
    }
    format!(r#"<div class="tag-list">{chips}</div>"#)
}

/// Format epoch seconds as a compact UTC date `Mon D, YYYY` (e.g. `Jun 29, 2026`). std `time`
/// only, no extra C deps.
pub fn fmt_date(secs: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => format!("{} {}, {}", month_abbr(dt.month()), dt.day(), dt.year()),
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
    let fragment = format!(
        r#"<main class="reader">
  <div class="error-card">
    <div class="error-card__code">{code}</div>
    <h1 class="error-card__title">{reason}</h1>
    <p class="error-card__msg">{msg}</p>
    <a class="btn btn-primary" href="/">Back to the blog</a>
  </div>
</main>"#,
        code = code,
        reason = esc(reason),
        msg = esc(message),
    );
    let head_title = format!("{code} {reason} · Inkwell");
    page_shell(PageShell {
        head_title: &head_title,
        body_class: "page-reading",
        rss: false,
        nav_title: "Inkwell",
        email: "—",
        is_admin: false,
        theme: "light",
        fragment: &fragment,
        metadata: None,
    })
}
