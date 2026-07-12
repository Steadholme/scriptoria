//! Durable personal Activity Inbox.
//!
//! The inbox is a triage stream, not per-thread reading progress. Every mutation is a real,
//! CSRF-protected form POST; JavaScript is optional. Event rows carry only authoritative pointers,
//! and the Store joins live thread/post content before returning an item.

use axum::extract::{Form, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;

use crate::auth;
use crate::error::AppError;
use crate::handlers::{
    email_display, esc, fmt_ts, personal_counts, rel_time, render_page_with_personal_counts,
};
use crate::model::{ActivityItem, ActivityReason};
use crate::store::{ActivityCursor, ActivityFilter};
use crate::{now_secs, AppState};

const ACTIVITY_PAGE_SIZE: i64 = 30;

#[derive(Debug, Default, Deserialize)]
pub struct ActivityQuery {
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub before: Option<String>,
}

impl ActivityQuery {
    fn filter(&self) -> ActivityFilter {
        match self.filter.as_deref() {
            Some("mention") => ActivityFilter::Reason(ActivityReason::Mention),
            Some("reply") => ActivityFilter::Reason(ActivityReason::Reply),
            Some("following") => ActivityFilter::Reason(ActivityReason::Following),
            Some("answer") => ActivityFilter::Reason(ActivityReason::Answer),
            _ => ActivityFilter::All,
        }
    }

    fn filter_key(&self) -> &'static str {
        match self.filter() {
            ActivityFilter::All => "all",
            ActivityFilter::Reason(reason) => reason.as_str(),
        }
    }

    fn unread_only(&self) -> bool {
        self.state.as_deref() == Some("unread")
    }
}

pub async fn page(
    State(state): State<AppState>,
    Query(query): Query<ActivityQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let identity = auth::require_author(&headers)?;
    let now = now_secs();
    let before = parse_cursor(query.before.as_deref());
    let mut items = state
        .store
        .activity_page(
            &identity.sub,
            query.filter(),
            query.unread_only(),
            before.as_ref(),
            ACTIVITY_PAGE_SIZE + 1,
        )
        .await?;
    let has_more = items.len() as i64 > ACTIVITY_PAGE_SIZE;
    items.truncate(ACTIVITY_PAGE_SIZE as usize);
    let counts = personal_counts(&state, &headers, now).await?;
    let unread_count = counts.unread_activity.unwrap_or(0);
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let controls = render_controls(&query, &csrf, &items);
    let rows = render_rows(&items, &csrf, now);
    let pagination = if has_more {
        items
            .last()
            .map(|item| {
                let cursor = format!("{}_{}", item.event.created_at, item.event.id);
                format!(
                    r#"<nav class="pagination"><a class="btn btn-secondary btn-sm" href="{href}">Older activity →</a></nav>"#,
                    href = activity_href(
                        query.filter_key(),
                        query.unread_only(),
                        Some(&cursor),
                    ),
                )
            })
            .unwrap_or_default()
    } else {
        String::new()
    };
    let content = format!(
        r#"<nav class="crumbs"><a href="/">Home</a><span class="crumbs__sep">/</span><span>Activity</span></nav>
<div class="page-head ag-activity-head">
  <div><h1>Activity</h1><p class="muted">Replies, mentions, followed threads, and accepted answers that bring you back.</p></div>
  <span class="ag-activity-total">{unread_label}</span>
</div>
{controls}
<section class="ag-activity-list" aria-label="Personal activity">{rows}</section>
{pagination}"#,
        unread_label = if unread_count == 1 {
            "1 unread".to_string()
        } else {
            format!("{unread_count} unread")
        },
    );
    let html = render_page_with_personal_counts(
        "Activity",
        &email_display(&headers),
        &content,
        counts,
    );
    Ok(html_response(html, set_cookie))
}

#[derive(Debug, Deserialize)]
pub struct ActivityStateForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub state: String,
}

pub async fn set_read_state(
    State(state): State<AppState>,
    Path(activity_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<ActivityStateForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let identity = auth::require_author(&headers)?;
    let read = match form.state.as_str() {
        "read" => true,
        "unread" => false,
        _ => {
            return Err(AppError::InvalidRequest(
                "activity state must be read or unread".to_string(),
            ));
        }
    };
    state
        .store
        .set_activity_read(&activity_id, &identity.sub, read, now_secs())
        .await?;
    Ok(redirect_to("/activity"))
}

#[derive(Debug, Deserialize)]
pub struct OpenActivityForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub next: String,
}

pub async fn open(
    State(state): State<AppState>,
    Path(activity_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<OpenActivityForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let identity = auth::require_author(&headers)?;
    state
        .store
        .set_activity_read(&activity_id, &identity.sub, true, now_secs())
        .await?;
    Ok(redirect_to(safe_thread_target(&form.next)))
}

#[derive(Debug, Deserialize)]
pub struct MarkPageForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub ids: String,
    #[serde(default)]
    pub filter: String,
    #[serde(default)]
    pub state: String,
}

pub async fn mark_page_read(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<MarkPageForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let identity = auth::require_author(&headers)?;
    let activity_ids: Vec<String> = form
        .ids
        .split(',')
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .collect();
    state
        .store
        .mark_activity_batch_read(&identity.sub, &activity_ids, now_secs())
        .await?;
    let filter_key = match parse_filter(&form.filter) {
        ActivityFilter::All => "all",
        ActivityFilter::Reason(reason) => reason.as_str(),
    };
    let location = activity_href(filter_key, form.state == "unread", None).replace("&amp;", "&");
    Ok(redirect_to(&location))
}

fn render_controls(query: &ActivityQuery, csrf: &str, items: &[ActivityItem]) -> String {
    let filter_key = query.filter_key();
    let unread = query.unread_only();
    let filter_tab = |key: &str, label: &str| {
        format!(
            r#"<a class="tab{active}"{current} href="{href}">{label}</a>"#,
            active = if filter_key == key { " is-active" } else { "" },
            current = if filter_key == key {
                r#" aria-current="page""#
            } else {
                ""
            },
            href = activity_href(key, unread, None),
        )
    };
    let state_tab = |only_unread: bool, label: &str| {
        format!(
            r#"<a class="tab{active}"{current} href="{href}">{label}</a>"#,
            active = if unread == only_unread {
                " is-active"
            } else {
                ""
            },
            current = if unread == only_unread {
                r#" aria-current="page""#
            } else {
                ""
            },
            href = activity_href(filter_key, only_unread, None),
        )
    };
    format!(
        r#"<div class="ag-activity-controls">
  <div class="ag-activity-tabs">
    <nav class="tabs" aria-label="Activity state">{all_state}{unread_state}</nav>
    <nav class="tabs ag-activity-reasons" aria-label="Activity reason">{all}{mentions}{replies}{following}{answers}</nav>
  </div>
  <form method="post" action="/activity/read-page">
    <input type="hidden" name="csrf" value="{csrf}">
    <input type="hidden" name="filter" value="{filter}">
    <input type="hidden" name="state" value="{state}">
    <input type="hidden" name="ids" value="{ids}">
    <button class="btn btn-secondary btn-sm" type="submit"{disabled}>Mark this page read</button>
  </form>
</div>"#,
        all_state = state_tab(false, "All"),
        unread_state = state_tab(true, "Unread"),
        all = filter_tab("all", "Everything"),
        mentions = filter_tab("mention", "Mentions"),
        replies = filter_tab("reply", "Replies"),
        following = filter_tab("following", "Following"),
        answers = filter_tab("answer", "Answers"),
        csrf = esc(csrf),
        filter = filter_key,
        state = if unread { "unread" } else { "all" },
        ids = esc(&items
            .iter()
            .map(|item| item.event.id.as_str())
            .collect::<Vec<_>>()
            .join(",")),
        disabled = if items.is_empty() { " disabled" } else { "" },
    )
}

fn render_rows(items: &[ActivityItem], csrf: &str, now: i64) -> String {
    if items.is_empty() {
        return r#"<div class="empty"><h3>Nothing waiting here.</h3><p>New replies and direct activity will appear here.</p></div>"#.to_string();
    }
    let mut html = String::new();
    for item in items {
        let target = activity_target(item);
        let (reason_label, sentence) = activity_copy(item);
        let actor = if item.actor_email.trim().is_empty() {
            item.event.actor_sub.as_str()
        } else {
            item.actor_email.as_str()
        };
        html.push_str(&format!(
            r#"<article class="ag-activity-row{unread}" id="activity-{id}">
  <form class="ag-activity-open" method="post" action="/activity/{id}/open">
    <input type="hidden" name="csrf" value="{csrf}">
    <input type="hidden" name="next" value="{target}">
    <button type="submit">
      <span class="ag-activity-dot" aria-hidden="true"></span>
      <span class="ag-activity-main">
        <span class="ag-activity-title">{title}</span>
        <span class="ag-activity-copy"><strong>{actor}</strong> {sentence}</span>
        <span class="ag-activity-snippet">{snippet}</span>
      </span>
      <span class="ag-activity-meta"><span class="badge">{reason}</span><time title="{absolute}">{relative}</time></span>
    </button>
  </form>
  <form class="ag-activity-state" method="post" action="/activity/{id}/state">
    <input type="hidden" name="csrf" value="{csrf}">
    <input type="hidden" name="state" value="{next_state}">
    <button class="btn btn-ghost btn-sm" type="submit">{state_label}</button>
  </form>
</article>"#,
            unread = if item.read { "" } else { " is-unread" },
            id = esc(&item.event.id),
            csrf = esc(csrf),
            target = esc(&target),
            title = esc(&item.thread_title),
            actor = esc(actor),
            sentence = sentence,
            snippet = esc(&compact_snippet(&item.post_body_md, 180)),
            reason = reason_label,
            absolute = esc(&fmt_ts(item.event.created_at)),
            relative = esc(&rel_time(item.event.created_at, now)),
            next_state = if item.read { "unread" } else { "read" },
            state_label = if item.read { "Mark unread" } else { "Mark read" },
        ));
    }
    html
}

fn activity_copy(item: &ActivityItem) -> (&'static str, &'static str) {
    match item.reason {
        ActivityReason::Mention => ("Mention", "mentioned you"),
        ActivityReason::Reply => ("Reply", "replied to you"),
        ActivityReason::Following => ("Following", "posted in a thread you follow"),
        ActivityReason::Answer => ("Accepted", "accepted your answer"),
    }
}

fn activity_target(item: &ActivityItem) -> String {
    format!(
        "/t/{}?around={}_{}#post-{}",
        item.event.thread_id, item.post_created_at, item.event.post_id, item.event.post_id
    )
}

fn activity_href(filter: &str, unread: bool, before: Option<&str>) -> String {
    let mut params = vec![format!("filter={}", esc(filter))];
    if unread {
        params.push("state=unread".to_string());
    }
    if let Some(before) = before {
        params.push(format!("before={}", esc(before)));
    }
    format!("/activity?{}", params.join("&amp;"))
}

fn parse_filter(value: &str) -> ActivityFilter {
    match value {
        "mention" => ActivityFilter::Reason(ActivityReason::Mention),
        "reply" => ActivityFilter::Reason(ActivityReason::Reply),
        "following" => ActivityFilter::Reason(ActivityReason::Following),
        "answer" => ActivityFilter::Reason(ActivityReason::Answer),
        _ => ActivityFilter::All,
    }
}

fn parse_cursor(value: Option<&str>) -> Option<ActivityCursor> {
    let (created_at, id) = value?.trim().split_once('_')?;
    let created_at = created_at.parse().ok()?;
    if id.is_empty() || id.len() > 128 {
        return None;
    }
    Some(ActivityCursor {
        created_at,
        id: id.to_string(),
    })
}

fn safe_thread_target(value: &str) -> &str {
    let value = value.trim();
    if value.starts_with("/t/")
        && !value.starts_with("//")
        && value.len() <= 512
        && !value.chars().any(char::is_control)
    {
        value
    } else {
        "/activity"
    }
}

fn compact_snippet(value: &str, max_chars: usize) -> String {
    let compact = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut chars = compact.chars();
    let mut result: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        result.push_str("...");
    }
    result
}

fn html_response(html: String, set_cookie: Option<String>) -> Response {
    let mut response = Html(html).into_response();
    if let Some(cookie) = set_cookie {
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    response
}

fn redirect_to(location: &str) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::{parse_cursor, safe_thread_target};

    #[test]
    fn activity_cursor_keeps_prefixed_id() {
        let cursor = parse_cursor(Some("123_a_deadbeef")).unwrap();
        assert_eq!(cursor.created_at, 123);
        assert_eq!(cursor.id, "a_deadbeef");
    }

    #[test]
    fn open_redirect_is_same_origin_thread_only() {
        assert_eq!(
            safe_thread_target("/t/t_one?around=1_p_one#post-p_one"),
            "/t/t_one?around=1_p_one#post-p_one"
        );
        assert_eq!(safe_thread_target("https://evil.example"), "/activity");
        assert_eq!(safe_thread_target("//evil.example"), "/activity");
    }
}
