//! HTTP handlers + shared server-render helpers.
//!
//! `health` is the unauthenticated liveness probe; `forum` carries every page (home,
//! category, thread, new-thread form + create, reply). The shared design tokens / CSS are
//! embedded (via `include_str!`) and inlined into every page, matching the HOLDFAST
//! enterprise brand: brand gradient app-bar, indigo accent, cards, pills.

pub mod activity;
pub mod admin;
pub mod bookmarks;
pub mod forum;
pub mod health;
pub mod insight;
pub mod search;

use axum::http::HeaderMap;
use std::sync::OnceLock;

/// Agora-only CSS layered after Odyssey's canonical font, tokens, and components.
pub const SERVICE_CSS: &str = include_str!("../../static/service.css");

static APP_CSS: OnceLock<String> = OnceLock::new();
static DYNAMIC_JS: OnceLock<String> = OnceLock::new();

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
fn dynamic_js() -> &'static str {
    DYNAMIC_JS
        .get_or_init(|| odyssey::dynamic_scripts().0)
        .as_str()
}

/// Page shell with `{{STYLE}}`/`{{DYNAMIC}}`/`{{APPBAR}}`/`{{TITLE}}`/`{{CONTENT}}` slots.
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

pub(crate) fn ag_tone(s: &str) -> usize {
    s.bytes().map(usize::from).sum::<usize>() % 5 + 1
}

pub(crate) fn ag_initial(s: &str) -> String {
    s.chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().collect())
        .unwrap_or_else(|| "U".to_string())
}

/// Render a full page: fill the shell with the inlined CSS, the (raw) title, the Odyssey v2
/// app-bar (brand tile + forum nav + avatar user-menu), and the already-built content HTML.
pub fn render_page(title: &str, email_display: &str, content: &str) -> String {
    render_page_with_activity(title, email_display, content, None)
}

/// Render a page with the personal Activity control hydrated server-side. `None` is used only by
/// identity-free error/dev surfaces; authenticated product pages pass the authoritative unread
/// count so the return-loop badge also works without JavaScript.
pub fn render_page_with_activity(
    title: &str,
    email_display: &str,
    content: &str,
    unread_activity: Option<i64>,
) -> String {
    render_page_with_personal_counts(
        title,
        email_display,
        content,
        PersonalCounts {
            unread_activity,
            due_bookmarks: None,
        },
    )
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PersonalCounts {
    pub unread_activity: Option<i64>,
    pub due_bookmarks: Option<i64>,
}

pub fn render_page_with_personal_counts(
    title: &str,
    email_display: &str,
    content: &str,
    counts: PersonalCounts,
) -> String {
    let active = match title {
        "New thread" => "new",
        "Search" => "search",
        "Activity" => "activity",
        "Bookmarks" | "Edit bookmark" => "bookmarks",
        _ => "home",
    };
    SHELL
        .replace("{{STYLE}}", app_css())
        .replace("{{DYNAMIC}}", dynamic_js())
        .replace(
            "{{APPBAR}}",
            &app_bar_with_counts(active, email_display, counts),
        )
        .replace("{{TITLE}}", &esc(title))
        .replace("{{CONTENT}}", content)
}

/// The Agora (Forum) app-tile icon — a Lucide-style `message-square` glyph.
pub const APP_ICON: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>"##;

/// The full Odyssey v2 app-bar: the Forum app-tile + name, the forum nav (current marked
/// `.is-active`), then the "All apps" waffle and the avatar user-menu. `email_display` is the
/// already-escaped signed-in identity ("" → a minimal, no-identity avatar).
pub fn app_bar(active: &str, email_display: &str) -> String {
    app_bar_with_activity(active, email_display, None)
}

pub fn app_bar_with_activity(
    active: &str,
    email_display: &str,
    unread_activity: Option<i64>,
) -> String {
    app_bar_with_counts(
        active,
        email_display,
        PersonalCounts {
            unread_activity,
            due_bookmarks: None,
        },
    )
}

pub fn app_bar_with_counts(
    active: &str,
    email_display: &str,
    counts: PersonalCounts,
) -> String {
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
    let quick_search = format!(
        r#"<form class="ag-quick-search{active}" method="get" action="/search" role="search" aria-label="Quick search" data-ag-quick-search>
  <button class="ag-quick-search__submit" type="submit" aria-label="Search discussions"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg></button>
  <input id="ag-quick-search-input" type="search" name="q" maxlength="160" placeholder="Search discussions" autocomplete="off" role="combobox" aria-label="Search discussions" aria-autocomplete="list" aria-haspopup="listbox" aria-controls="ag-quick-search-results" aria-expanded="false">
  <kbd class="ag-quick-search__key" aria-hidden="true">/</kbd>
  <div id="ag-quick-search-results" class="ag-quick-search__results" role="listbox" aria-label="Search suggestions" data-ag-search-results hidden></div>
</form>"#,
        active = if active == "search" { " is-active" } else { "" },
    );
    let bookmarks = bookmark_button(active == "bookmarks", counts.due_bookmarks);
    let activity = activity_button(active == "activity", counts.unread_activity);
    format!(
        r#"<header class="appbar">
  <a class="appbar__brand" href="/" aria-label="HOLDFAST Agora home">
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
        right = user_menu(email_display),
    )
}

fn bookmark_button(active: bool, due_bookmarks: Option<i64>) -> String {
    let count = due_bookmarks.unwrap_or(0).max(0);
    let badge = if count > 0 {
        format!(
            r#"<span class="ag-bookmark-badge" aria-hidden="true">{}</span>"#,
            if count > 99 {
                "99+".to_string()
            } else {
                count.to_string()
            }
        )
    } else {
        String::new()
    };
    let label = match count {
        0 => "Bookmarks".to_string(),
        1 => "Bookmarks, 1 due".to_string(),
        _ => format!("Bookmarks, {count} due"),
    };
    let href = if count > 0 {
        "/bookmarks?state=due"
    } else {
        "/bookmarks"
    };
    format!(
        r#"<a class="iconbtn ag-bookmark-button{active}" href="{href}" title="Bookmarks" aria-label="{label}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 3h12a1 1 0 0 1 1 1v17l-7-4-7 4V4a1 1 0 0 1 1-1z"/></svg>{badge}</a>"#,
        active = if active { " is-active" } else { "" },
        href = href,
        label = esc(&label),
        badge = badge,
    )
}

fn activity_button(active: bool, unread_activity: Option<i64>) -> String {
    let count = unread_activity.unwrap_or(0).max(0);
    let badge = if count > 0 {
        format!(
            r#"<span class="ag-activity-badge" aria-hidden="true">{}</span>"#,
            if count > 99 {
                "99+".to_string()
            } else {
                count.to_string()
            }
        )
    } else {
        String::new()
    };
    let label = if count == 0 {
        "Activity".to_string()
    } else if count == 1 {
        "Activity, 1 unread".to_string()
    } else {
        format!("Activity, {count} unread")
    };
    format!(
        r#"<a class="iconbtn ag-activity-button{active}" href="/activity" title="Activity" aria-label="{label}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>{badge}</a>"#,
        active = if active { " is-active" } else { "" },
        label = esc(&label),
        badge = badge,
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

/// Authoritative unread Activity count for the current gateway identity. Public/dev requests with
/// no identity keep the activity link but render no personalised badge.
pub async fn unread_activity_count(
    state: &crate::AppState,
    headers: &HeaderMap,
) -> Result<Option<i64>, crate::error::AppError> {
    let Some(subject) = crate::auth::identity_subject(headers) else {
        return Ok(None);
    };
    Ok(Some(state.store.unread_activity_count(&subject).await?))
}

/// Both owner-scoped app-bar counters from the same signed gateway subject. Due reminders are
/// request-derived; this never claims that a background notification was delivered.
pub async fn personal_counts(
    state: &crate::AppState,
    headers: &HeaderMap,
    as_of: i64,
) -> Result<PersonalCounts, crate::error::AppError> {
    let Some(subject) = crate::auth::identity_subject(headers) else {
        return Ok(PersonalCounts::default());
    };
    Ok(PersonalCounts {
        unread_activity: Some(state.store.unread_activity_count(&subject).await?),
        due_bookmarks: Some(
            state
                .store
                .due_bookmark_count(&subject, as_of)
                .await?,
        ),
    })
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
    fn ag_tone_is_stable_and_bounded() {
        assert_eq!(ag_tone("general"), ag_tone("general"));
        assert!((1..=5).contains(&ag_tone("support")));
        assert_eq!(ag_tone(""), 1);
    }

    #[test]
    fn ag_initial_uses_first_alphanumeric_uppercase_or_fallback() {
        assert_eq!(ag_initial("&x"), "X");
        assert_eq!(ag_initial(""), "U");
        assert_eq!(ag_initial("éclair"), "É");
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
