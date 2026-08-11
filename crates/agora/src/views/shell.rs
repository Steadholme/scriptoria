//! Frontend-owned page shell: the shared chrome every Agora page renders through.
//!
//! DTO consumption manifest (from `crate::view_model`, frozen by the Step 3 contract §3.2):
//! - `PageChrome { title: Text, viewer_email: Option<Text>, active_nav: NavTab,
//!   counts: PersonalCounts, cache: CacheClass }` — `cache` is authoritative at Codex and is
//!   NEVER read here (the presentation layer does not choose or display cache policy).
//! - `PersonalCounts { unread_activity: Option<i64>, due_bookmarks: Option<i64> }` —
//!   request-derived private conveniences, rendered as dashed private markers, never as shared
//!   state or delivery monitoring.
//! - `NavTab::{Home, New, Search, Activity, Bookmarks}` — Codex picks the active tab.
//! - `ErrorView { heading: Text, message: Text, correlation_id: Option<Opaque> }` — already
//!   safe, already generic; the view escapes and frames it, never sees raw backend detail.
//! - `DestructiveReviewVM { heading: Text, consequence: ConsequenceVM, commit: FormActionVM,
//!   cancel_href: Opaque }` — the no-JS consequence review (contract §10 phase 1).

use std::sync::OnceLock;

use crate::view_model::{CacheClass, DestructiveReviewVM, ErrorView, NavTab, PageChrome};

use super::{crumbs, escape, hidden_inputs, t};

/// Agora-only CSS layered after Odyssey's canonical font, tokens, and components.
pub const SERVICE_CSS: &str = include_str!("../../static/service.css");

/// Page shell with `{{STYLE}}`/`{{DYNAMIC}}`/`{{APPBAR}}`/`{{TITLE}}`/`{{CONTENT}}` slots.
pub const SHELL: &str = include_str!("../../templates/shell.html");

/// The Steadholme shield glyph (small, for the app-bar brand lockup). Flat single-ink civic
/// mark — the decorative gradient of the retired lockup is removed (reject list).
pub const SHIELD_SVG: &str = r##"<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M24 4 8 9.5V22c0 11 7 17.4 16 21.5C33 39.4 40 33 40 22V9.5L24 4Z" fill="currentColor"/><rect x="20" y="19" width="8" height="13" rx="1" fill="var(--bg)"/><path d="M20 19v-2.5a4 4 0 0 1 8 0V19" stroke="var(--bg)" stroke-width="2" fill="none"/></svg>"##;

/// The Agora (Forum) app-tile icon — a Lucide-style `message-square` glyph.
pub const APP_ICON: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>"##;

/// The logout link is the GATEWAY's, not Agora's (Agora does no login of its own).
pub const LOGOUT_URL: &str = "https://sso.w33d.xyz/_gw/auth/logout";

static APP_CSS: OnceLock<String> = OnceLock::new();
static DYNAMIC_JS: OnceLock<String> = OnceLock::new();

/// Embedded design system, inlined into each rendered page's `<style>`: Odyssey's canonical
/// CSS followed by Agora's civic surface CSS (Odyssey dependency unchanged, contract §4).
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

fn dynamic_js() -> &'static str {
    DYNAMIC_JS
        .get_or_init(|| odyssey::dynamic_scripts().0)
        .as_str()
}

/// Render a full page: fill the shell with the inlined CSS, the escaped title, the civic
/// app-bar built from `chrome`, and the already-built main HTML.
///
/// `main_html` is the output of another pure view — it is trusted because every view escapes its
/// own `Text`/`Opaque` interpolations at the boundary.
pub fn page(chrome: &PageChrome, main_html: &str) -> String {
    let _ = chrome.cache; // CacheClass stays authoritative at Codex; never rendered.
    SHELL
        .replace("{{STYLE}}", app_css())
        .replace("{{DYNAMIC}}", dynamic_js())
        .replace("{{APPBAR}}", &app_bar(chrome))
        .replace("{{TITLE}}", &t(&chrome.title))
        .replace("{{CONTENT}}", main_html)
}

/// Render the branded safe-error page (replaces the retired `handlers::render_error`). The
/// error arrives already sanitized: a stable heading, a generic recovery message, and an
/// optional opaque correlation id. Identity-free chrome — no viewer chip is rendered.
pub fn error(v: &ErrorView) -> String {
    let mut body = crumbs(&[("Home", Some("/")), (&v.heading.0, None)]);
    body.push_str(&format!(
        r#"<section class="card pad empty-card ag-review" aria-labelledby="ag-error-title">
  <p class="eyebrow ag-eyebrow">Request could not be completed</p>
  <h1 class="empty-title" id="ag-error-title">{heading}</h1>
  <p class="muted">{message}</p>{correlation}
  <p><a class="btn btn-primary" href="/">Back to the forum</a></p>
</section>"#,
        heading = t(&v.heading),
        message = t(&v.message),
        correlation = match &v.correlation_id {
            Some(id) if !id.0.trim().is_empty() => format!(
                r#"<p class="muted ag-correlation">Reference <code>{}</code> if you report this.</p>"#,
                escape(&id.0),
            ),
            _ => String::new(),
        },
    ));
    let chrome = error_chrome(&v.heading.0);
    page(&chrome, &body)
}

fn error_chrome(title: &str) -> PageChrome {
    PageChrome {
        title: crate::view_model::Text(title.to_string()),
        viewer_email: None,
        active_nav: NavTab::Home,
        counts: crate::view_model::PersonalCounts {
            unread_activity: None,
            due_bookmarks: None,
        },
        cache: CacheClass::PrivateNoStore,
    }
}

/// Render the no-JS destructive-action consequence review (contract §10 phase 1): a
/// non-mutating page that states exactly what will happen and carries the confirmed commit
/// form (CSRF + server-issued `confirm` token in the descriptor's hidden fields). Codex wraps
/// this main block in [`page`].
pub fn destructive_review(v: &DestructiveReviewVM) -> String {
    let mut out = crumbs(&[("Home", Some("/")), ("Review action", None)]);
    out.push_str(&format!(
        r#"<section class="card ag-destructive-review ag-review" aria-labelledby="destructive-review-title">
  <p class="eyebrow ag-eyebrow">Consequence review</p>
  <h1 id="destructive-review-title">{heading}</h1>
  <p>{summary}</p>{detail}
  <p><strong>This action cannot be undone.</strong></p>
  <form class="ag-form" method="post" action="{action}">
    {hidden}
    <div class="form-actions">
      <button class="btn btn-danger" type="submit">Confirm deletion</button>
      <a class="btn btn-secondary" href="{cancel}">Cancel</a>
    </div>
  </form>
</section>"#,
        heading = t(&v.heading),
        summary = t(&v.consequence.summary),
        detail = match &v.consequence.detail {
            Some(detail) => format!("<p class=\"muted\">{}</p>", t(detail)),
            None => String::new(),
        },
        action = escape(&v.commit.action.0),
        hidden = hidden_inputs(&v.commit.csrf.0, &v.commit.fields),
        cancel = escape(&v.cancel_href.0),
    ));
    out
}

/// The civic app-bar: brand lockup, forum nav (current marked `.is-active`), quick search
/// (all enhancement hooks preserved verbatim), private bookmarks/activity buttons with
/// request-derived badges (dashed private markers), the "All apps" waffle, and the avatar
/// user-menu. No identity → no user chip, and private counts render nothing (never a false
/// "0").
fn app_bar(chrome: &PageChrome) -> String {
    let active = chrome.active_nav;
    let nav = format!(
        concat!(
            r#"<nav class="appbar__nav" aria-label="Agora">"#,
            r#"<a class="appnav{a_home}" href="/"{c_home}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M9 22V12h6v10"/></svg>Home</a>"#,
            r#"<a class="appnav{a_new}" href="/new"{c_new}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12h14"/><path d="M12 5v14"/></svg>New thread</a>"#,
            r#"</nav>"#,
        ),
        a_home = if active == NavTab::Home {
            " is-active"
        } else {
            ""
        },
        a_new = if active == NavTab::New {
            " is-active"
        } else {
            ""
        },
        c_home = if active == NavTab::Home {
            r#" aria-current="location""#
        } else {
            ""
        },
        c_new = if active == NavTab::New {
            r#" aria-current="location""#
        } else {
            ""
        },
    );
    let quick_search = format!(
        r#"<form class="ag-quick-search{active}" method="get" action="/search" role="search" aria-label="Quick search" data-ag-quick-search>
  <button class="ag-quick-search__submit" type="submit" aria-label="Search discussions"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg></button>
  <input id="ag-quick-search-input" type="search" name="q" maxlength="160" placeholder="Search discussions" autocomplete="off" role="combobox" aria-label="Search discussions" aria-autocomplete="list" aria-haspopup="listbox" aria-controls="ag-quick-search-results" aria-expanded="false">
  <kbd class="ag-quick-search__key" aria-hidden="true">/</kbd>
  <div id="ag-quick-search-results" class="ag-quick-search__results" role="listbox" aria-label="Search suggestions" data-ag-search-results hidden></div>
</form>"#,
        active = if active == NavTab::Search {
            " is-active"
        } else {
            ""
        },
    );
    let bookmarks = bookmark_button(active == NavTab::Bookmarks, chrome.counts.due_bookmarks);
    let activity = activity_button(active == NavTab::Activity, chrome.counts.unread_activity);
    format!(
        r#"<header class="appbar ag-appbar">
  <a class="appbar__brand" href="/" aria-label="Steadholme Agora home">
    <span class="app-tile" aria-hidden="true" style="--app:var(--brand);--app-soft:var(--brand-soft)">{icon}</span>
    <span class="appbar__name"><b>Forum</b><span>forum.w33d.xyz</span></span>
  </a>
  {nav}
  {quick_search}
  <span class="appbar__spacer"></span>
  <div class="appbar__right">{bookmarks}{activity}{right}</div>
</header>"#,
        icon = APP_ICON,
        nav = nav,
        quick_search = quick_search,
        bookmarks = bookmarks,
        activity = activity,
        right = user_menu(chrome.viewer_email.as_ref()),
    )
}

/// A request-derived private count badge. `None` (no identity) renders NO badge and a plain
/// label — unavailable private truth never becomes a painted "0".
fn private_badge(count: Option<i64>, singular: &str, plural: &str) -> (String, String) {
    match count {
        Some(n) if n > 0 => {
            let display = if n > 99 {
                "99+".to_string()
            } else {
                n.to_string()
            };
            let label = if n == 1 {
                format!("1 {singular}")
            } else {
                format!("{n} {plural}")
            };
            (
                format!(
                    r#"<span class="ag-count-badge ag-key-private" aria-hidden="true">{display}</span>"#,
                ),
                label,
            )
        }
        _ => (String::new(), String::new()),
    }
}

fn bookmark_button(active: bool, due_bookmarks: Option<i64>) -> String {
    let (badge, state) = private_badge(due_bookmarks, "due", "due");
    let label = match state.as_str() {
        "" => "Bookmarks".to_string(),
        s => format!("Bookmarks, {s}"),
    };
    let href = if due_bookmarks.unwrap_or(0) > 0 {
        "/bookmarks?state=due"
    } else {
        "/bookmarks"
    };
    format!(
        r#"<a class="iconbtn ag-bookmark-button{active}" href="{href}" title="Bookmarks" aria-label="{label}"{current}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 3h12a1 1 0 0 1 1 1v17l-7-4-7 4V4a1 1 0 0 1 1-1z"/></svg>{badge}</a>"#,
        active = if active { " is-active" } else { "" },
        current = if active {
            r#" aria-current="location""#
        } else {
            ""
        },
        href = href,
        label = escape(&label),
        badge = badge,
    )
}

fn activity_button(active: bool, unread_activity: Option<i64>) -> String {
    let (badge, state) = private_badge(unread_activity, "unread", "unread");
    let label = match state.as_str() {
        "" => "Activity".to_string(),
        s => format!("Activity, {s}"),
    };
    format!(
        r#"<a class="iconbtn ag-activity-button{active}" href="/activity" title="Activity" aria-label="{label}"{current}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>{badge}</a>"#,
        active = if active { " is-active" } else { "" },
        current = if active {
            r#" aria-current="location""#
        } else {
            ""
        },
        label = escape(&label),
        badge = badge,
    )
}

/// The app-bar's right cluster: the "All apps" waffle and the avatar user-menu. `viewer_email`
/// is Codex-authorized display metadata; `None` renders a minimal no-identity avatar (never a
/// guessed identity). Legacy `allapps`/`userchip` hooks retained.
fn user_menu(viewer_email: Option<&crate::view_model::Text>) -> String {
    let (avatar, name_html, head_name, head_sub) = if let Some(email) = viewer_email {
        let initial = super::ag_initial(&email.0);
        (
            escape(&initial),
            format!("<span class=\"usermenu__name\">{}</span>", t(email)),
            t(email),
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
      <button class="usermenu__btn" type="button" aria-label="Account options">
        <span class="avatar" aria-hidden="true">{avatar}</span>
        {name}
        <svg class="usermenu__caret" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>
      </button>
      <div class="usermenu__pop">
        <div class="usermenu__head"><span class="avatar" aria-hidden="true">{avatar}</span><div><b>{head_name}</b><span>{head_sub}</span></div></div>
        <a class="menuitem" href="https://account.w33d.xyz"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>Account</a>
        <a class="menuitem" href="https://w33d.xyz"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>All apps</a>
        <a class="menuitem menuitem--danger" href="{logout}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5"/><path d="M21 12H9"/></svg>Sign out</a>
      </div>
    </div>"#,
        avatar = avatar,
        name = name_html,
        head_name = head_name,
        head_sub = head_sub,
        logout = LOGOUT_URL,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html_metacharacters() {
        assert_eq!(escape("<b>&\"'"), "&lt;b&gt;&amp;&quot;&#x27;");
    }
}
