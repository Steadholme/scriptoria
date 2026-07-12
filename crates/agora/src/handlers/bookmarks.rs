//! Private post bookmarks and the request-derived Due queue.
//!
//! A reminder is deliberately not a delivery claim: without a durable scheduler, it becomes
//! visible here when due and remains visible until the owner completes, snoozes, or removes it.

use axum::extract::{Form, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;
use time::{Date, Month, PrimitiveDateTime, Time};

use crate::audit::AuditEvent;
use crate::auth;
use crate::error::AppError;
use crate::handlers::{
    email_display, esc, fmt_ts, personal_counts, render_page_with_personal_counts,
};
use crate::model::BookmarkItem;
use crate::store::{
    BookmarkCas, BookmarkCursor, BookmarkReminderUpdate, BookmarkState, MAX_BOOKMARK_NOTE_CHARS,
    MAX_BOOKMARK_PAGE,
};
use crate::{now_secs, AppState};

const ONE_DAY: i64 = 24 * 60 * 60;
const ONE_WEEK: i64 = 7 * ONE_DAY;

#[derive(Debug, Default, Deserialize)]
pub struct BookmarkQuery {
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    before: Option<String>,
}

impl BookmarkQuery {
    fn state(&self) -> BookmarkState {
        match self.state.as_deref() {
            Some("due") => BookmarkState::Due,
            Some("scheduled") => BookmarkState::Scheduled,
            _ => BookmarkState::All,
        }
    }

    fn state_key(&self) -> &'static str {
        bookmark_state_key(self.state())
    }
}

pub async fn page(
    State(state): State<AppState>,
    Query(query): Query<BookmarkQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let identity = auth::require_author(&headers)?;
    let now = now_secs();
    let cursor = parse_cursor(query.before.as_deref());
    let mut items = state
        .store
        .bookmark_page(
            &identity.sub,
            query.state(),
            cursor.as_ref(),
            MAX_BOOKMARK_PAGE + 1,
            now,
        )
        .await?;
    let has_more = items.len() as i64 > MAX_BOOKMARK_PAGE;
    items.truncate(MAX_BOOKMARK_PAGE as usize);
    let counts = personal_counts(&state, &headers, now).await?;
    let due = counts.due_bookmarks.unwrap_or(0).max(0);
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let controls = render_tabs(query.state(), due);
    let rows = render_rows(&items, &csrf, now);
    let pagination = if has_more {
        items
            .last()
            .map(|item| {
                let sort_at = match query.state() {
                    BookmarkState::All => item.bookmark.created_at,
                    BookmarkState::Due | BookmarkState::Scheduled => {
                        item.bookmark.remind_at.unwrap_or_default()
                    }
                };
                let cursor = format!("{}_{}", sort_at, item.bookmark.post_id);
                format!(
                    r#"<nav class="pagination"><a class="btn btn-secondary btn-sm" href="{}">More bookmarks →</a></nav>"#,
                    bookmark_href(query.state_key(), Some(&cursor)),
                )
            })
            .unwrap_or_default()
    } else {
        String::new()
    };
    let content = format!(
        r#"<nav class="crumbs"><a href="/">Home</a><span class="crumbs__sep">/</span><span>Bookmarks</span></nav>
<div class="page-head ag-bookmark-head">
  <div><h1>Bookmarks</h1><p class="muted">Save a post, add a private note, or bring it back to your Forum Due queue.</p></div>
  <span class="ag-bookmark-total">{due_label}</span>
</div>
<aside class="ag-bookmark-notice" role="note"><strong>Forum reminder</strong><span>Due reminders appear here and in the Forum header when you visit. Forum does not send email or push reminders yet.</span></aside>
{controls}
<section class="ag-bookmark-list" aria-label="Personal bookmarks">{rows}</section>
{pagination}"#,
        due_label = if due == 1 {
            "1 due".to_string()
        } else {
            format!("{due} due")
        },
        controls = controls,
        rows = rows,
        pagination = pagination,
    );
    let html =
        render_page_with_personal_counts("Bookmarks", &email_display(&headers), &content, counts);
    Ok(html_response(html, set_cookie))
}

#[derive(Debug, Deserialize)]
pub struct EnsureForm {
    #[serde(default)]
    csrf: String,
}

pub async fn ensure(
    State(state): State<AppState>,
    Path((thread_id, post_id)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<EnsureForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let identity = auth::require_author(&headers)?;
    let post = state
        .store
        .get_post(&post_id)
        .await?
        .filter(|post| post.thread_id == thread_id)
        .ok_or_else(|| AppError::NotFound("post not found".to_string()))?;
    state
        .store
        .ensure_bookmark(&identity.sub, &post.id, now_secs())
        .await?;
    state.audit.emit(AuditEvent::info(
        "bookmark.ensure",
        actor_label(&identity.sub, &identity.email),
        &post.id,
        &thread_id,
    ));
    Ok(redirect_to(&post_target(
        &thread_id,
        post.created_at,
        &post.id,
    )))
}

pub async fn edit_form(
    State(state): State<AppState>,
    Path(post_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let identity = auth::require_author(&headers)?;
    let now = now_secs();
    let item = state
        .store
        .get_bookmark(&identity.sub, &post_id)
        .await?
        .ok_or_else(|| AppError::NotFound("bookmark not found".to_string()))?;
    let counts = personal_counts(&state, &headers, now).await?;
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let reminder = item
        .bookmark
        .remind_at
        .map(fmt_ts)
        .unwrap_or_else(|| "No reminder set".to_string());
    let target = post_target(
        &item.thread_id,
        item.post_created_at,
        &item.bookmark.post_id,
    );
    let content = format!(
        r#"<nav class="crumbs"><a href="/">Home</a><span class="crumbs__sep">/</span><a href="/bookmarks">Bookmarks</a><span class="crumbs__sep">/</span><span>Edit</span></nav>
<div class="page-head"><div><h1>Edit bookmark</h1><p class="muted">{title}</p></div></div>
<section class="card ag-bookmark-editor">
  <form class="ag-form" method="post" action="/bookmarks/{post_id}/edit">
    <input type="hidden" name="csrf" value="{csrf}">
    <input type="hidden" name="expected_bookmark_id" value="{bookmark_id}">
    <input type="hidden" name="expected_version" value="{version}">
    <div class="field"><label class="label" for="bookmark-note">Private note</label><textarea id="bookmark-note" name="note" rows="4" maxlength="{max_note}" placeholder="Why did you save this?">{note}</textarea><p class="hint">Plain text, visible only to you. Up to {max_note} characters.</p></div>
    <div class="field"><label class="label" for="bookmark-reminder">Reminder</label><select id="bookmark-reminder" name="reminder_action"><option value="keep">Keep current — {reminder}</option><option value="none">No reminder</option><option value="tomorrow">24 hours from now</option><option value="week">7 days from now</option><option value="custom">Custom UTC time</option></select></div>
    <div class="field"><label class="label" for="bookmark-custom">Custom time <span class="muted">(UTC)</span></label><input id="bookmark-custom" class="input" type="datetime-local" name="custom_time"><p class="hint">Used only when “Custom UTC time” is selected. It must be in the future and within 10 years.</p></div>
    <aside class="ag-bookmark-notice" role="note">This reminder appears in your Forum Due queue. It does not send email or push.</aside>
    <div class="ag-composer__actions"><a class="btn btn-secondary" href="{target}">Cancel</a><button class="btn btn-primary" type="submit">Save bookmark</button></div>
  </form>
</section>"#,
        title = esc(&item.thread_title),
        post_id = esc(&item.bookmark.post_id),
        csrf = esc(&csrf),
        bookmark_id = esc(&item.bookmark.bookmark_id),
        version = item.bookmark.version,
        max_note = MAX_BOOKMARK_NOTE_CHARS,
        note = esc(&item.bookmark.note),
        reminder = esc(&reminder),
        target = esc(&target),
    );
    let html = render_page_with_personal_counts(
        "Edit bookmark",
        &email_display(&headers),
        &content,
        counts,
    );
    Ok(html_response(html, set_cookie))
}

#[derive(Debug, Deserialize)]
pub struct EditForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    expected_bookmark_id: String,
    #[serde(default)]
    expected_version: String,
    #[serde(default)]
    note: String,
    #[serde(default)]
    reminder_action: String,
    #[serde(default)]
    custom_time: String,
}

pub async fn update(
    State(state): State<AppState>,
    Path(post_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<EditForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let identity = auth::require_author(&headers)?;
    let expected = parse_version(&form.expected_version)?;
    let now = now_secs();
    let reminder = match form.reminder_action.as_str() {
        "keep" => BookmarkReminderUpdate::Keep,
        "none" => BookmarkReminderUpdate::Clear,
        "tomorrow" => BookmarkReminderUpdate::Set(future_at(now, ONE_DAY)?),
        "week" => BookmarkReminderUpdate::Set(future_at(now, ONE_WEEK)?),
        "custom" => BookmarkReminderUpdate::Set(parse_utc_datetime(&form.custom_time)?),
        _ => {
            return Err(AppError::InvalidRequest(
                "unknown bookmark reminder option".to_string(),
            ));
        }
    };
    let note = form.note.trim();
    state
        .store
        .update_bookmark(
            &identity.sub,
            &post_id,
            BookmarkCas {
                bookmark_id: &form.expected_bookmark_id,
                version: expected,
            },
            note,
            reminder,
            now,
        )
        .await?;
    let item = state
        .store
        .get_bookmark(&identity.sub, &post_id)
        .await?
        .ok_or_else(|| AppError::NotFound("bookmark not found".to_string()))?;
    state.audit.emit(AuditEvent::info(
        "bookmark.update",
        actor_label(&identity.sub, &identity.email),
        &post_id,
        &item.thread_id,
    ));
    Ok(redirect_to(&post_target(
        &item.thread_id,
        item.post_created_at,
        &post_id,
    )))
}

#[derive(Debug, Deserialize)]
pub struct VersionForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    expected_bookmark_id: String,
    #[serde(default)]
    expected_version: String,
}

pub async fn complete(
    State(state): State<AppState>,
    Path(post_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<VersionForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let identity = auth::require_author(&headers)?;
    state
        .store
        .complete_due_bookmark(
            &identity.sub,
            &post_id,
            BookmarkCas {
                bookmark_id: &form.expected_bookmark_id,
                version: parse_version(&form.expected_version)?,
            },
            now_secs(),
        )
        .await?;
    state.audit.emit(AuditEvent::info(
        "bookmark.complete",
        actor_label(&identity.sub, &identity.email),
        &post_id,
        "due",
    ));
    Ok(redirect_to("/bookmarks?state=due"))
}

#[derive(Debug, Deserialize)]
pub struct SnoozeForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    expected_bookmark_id: String,
    #[serde(default)]
    expected_version: String,
    #[serde(default)]
    preset: String,
}

pub async fn snooze(
    State(state): State<AppState>,
    Path(post_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<SnoozeForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let identity = auth::require_author(&headers)?;
    let now = now_secs();
    let delay = match form.preset.as_str() {
        "tomorrow" => ONE_DAY,
        "week" => ONE_WEEK,
        _ => {
            return Err(AppError::InvalidRequest(
                "unknown bookmark snooze preset".to_string(),
            ));
        }
    };
    state
        .store
        .snooze_bookmark(
            &identity.sub,
            &post_id,
            BookmarkCas {
                bookmark_id: &form.expected_bookmark_id,
                version: parse_version(&form.expected_version)?,
            },
            future_at(now, delay)?,
            now,
        )
        .await?;
    state.audit.emit(AuditEvent::info(
        "bookmark.snooze",
        actor_label(&identity.sub, &identity.email),
        &post_id,
        form.preset.as_str(),
    ));
    Ok(redirect_to("/bookmarks?state=due"))
}

pub async fn remove(
    State(state): State<AppState>,
    Path(post_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<VersionForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let identity = auth::require_author(&headers)?;
    state
        .store
        .remove_bookmark(
            &identity.sub,
            &post_id,
            BookmarkCas {
                bookmark_id: &form.expected_bookmark_id,
                version: parse_version(&form.expected_version)?,
            },
        )
        .await?;
    state.audit.emit(AuditEvent::info(
        "bookmark.remove",
        actor_label(&identity.sub, &identity.email),
        &post_id,
        "personal",
    ));
    Ok(redirect_to("/bookmarks"))
}

fn render_tabs(state: BookmarkState, due: i64) -> String {
    let tab = |candidate: BookmarkState, label: &str| {
        let active = state == candidate;
        format!(
            r#"<a class="tab{active}"{current} href="{href}">{label}</a>"#,
            active = if active { " is-active" } else { "" },
            current = if active {
                r#" aria-current="page""#
            } else {
                ""
            },
            href = bookmark_href(bookmark_state_key(candidate), None),
            label = label,
        )
    };
    format!(
        r#"<nav class="tabs ag-bookmark-tabs" aria-label="Bookmark state">{}{}{}</nav>"#,
        tab(BookmarkState::All, "All"),
        tab(BookmarkState::Due, &format!("Due ({due})")),
        tab(BookmarkState::Scheduled, "Scheduled"),
    )
}

fn render_rows(items: &[BookmarkItem], csrf: &str, now: i64) -> String {
    if items.is_empty() {
        return r#"<div class="empty"><h3>Nothing in this view.</h3><p>Use Bookmark on any post to save it here.</p></div>"#.to_string();
    }
    let mut out = String::new();
    for item in items {
        let bookmark = &item.bookmark;
        let target = post_target(&item.thread_id, item.post_created_at, &bookmark.post_id);
        let note = if bookmark.note.is_empty() {
            String::new()
        } else {
            format!(r#"<p class="ag-bookmark-note">{}</p>"#, esc(&bookmark.note))
        };
        let reminder = match bookmark.remind_at {
            Some(at) if at <= now => format!(
                r#"<span class="badge ag-bookmark-due">Due · {}</span>"#,
                esc(&fmt_ts(at))
            ),
            Some(at) => format!(
                r#"<span class="badge ag-bookmark-scheduled">Scheduled · {}</span>"#,
                esc(&fmt_ts(at))
            ),
            None => r#"<span class="badge">Saved</span>"#.to_string(),
        };
        let due_actions = if bookmark.remind_at.is_some_and(|at| at <= now) {
            format!(
                r#"<form class="inline-form" method="post" action="/bookmarks/{pid}/complete"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="expected_bookmark_id" value="{bookmark_id}"><input type="hidden" name="expected_version" value="{version}"><button class="btn btn-primary btn-sm" type="submit">Done</button></form>
<form class="inline-form ag-bookmark-snooze" method="post" action="/bookmarks/{pid}/snooze"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="expected_bookmark_id" value="{bookmark_id}"><input type="hidden" name="expected_version" value="{version}"><label class="sr-only" for="snooze-{pid}">Snooze duration</label><select id="snooze-{pid}" name="preset"><option value="tomorrow">24 hours</option><option value="week">7 days</option></select><button class="btn btn-secondary btn-sm" type="submit">Snooze</button></form>"#,
                pid = esc(&bookmark.post_id),
                csrf = esc(csrf),
                bookmark_id = esc(&bookmark.bookmark_id),
                version = bookmark.version,
            )
        } else {
            String::new()
        };
        out.push_str(&format!(
            r#"<article class="card ag-bookmark-row">
  <div class="ag-bookmark-row__main"><div class="ag-bookmark-row__meta">{reminder}<span>Post by {author}</span></div><h2><a href="{target}">{title}</a></h2>{note}<p class="ag-bookmark-snippet">{snippet}</p></div>
  <div class="ag-bookmark-row__actions"><a class="btn btn-secondary btn-sm" href="{target}">Open</a>{due_actions}<a class="btn btn-ghost btn-sm" href="/bookmarks/{pid}/edit">Edit</a><form class="inline-form" method="post" action="/bookmarks/{pid}/remove" onsubmit="return confirm('Remove this bookmark?');"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="expected_bookmark_id" value="{bookmark_id}"><input type="hidden" name="expected_version" value="{version}"><button class="btn btn-ghost btn-sm" type="submit">Remove</button></form></div>
</article>"#,
            reminder = reminder,
            author = esc(&item.post_author_email),
            target = esc(&target),
            title = esc(&item.thread_title),
            note = note,
            snippet = esc(&compact_snippet(&item.post_body_md, 180)),
            due_actions = due_actions,
            pid = esc(&bookmark.post_id),
            csrf = esc(csrf),
            bookmark_id = esc(&bookmark.bookmark_id),
            version = bookmark.version,
        ));
    }
    out
}

fn bookmark_state_key(state: BookmarkState) -> &'static str {
    match state {
        BookmarkState::All => "all",
        BookmarkState::Due => "due",
        BookmarkState::Scheduled => "scheduled",
    }
}

fn bookmark_href(state: &str, before: Option<&str>) -> String {
    let mut href = format!("/bookmarks?state={}", esc(state));
    if let Some(cursor) = before {
        href.push_str("&amp;before=");
        href.push_str(&esc(cursor));
    }
    href
}

fn parse_cursor(value: Option<&str>) -> Option<BookmarkCursor> {
    let value = value?.trim();
    let (sort_at, post_id) = value.split_once('_')?;
    let sort_at = sort_at.parse().ok()?;
    if post_id.is_empty()
        || post_id.len() > 128
        || !post_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return None;
    }
    Some(BookmarkCursor {
        sort_at,
        post_id: post_id.to_string(),
    })
}

fn parse_version(value: &str) -> Result<i64, AppError> {
    value
        .trim()
        .parse::<i64>()
        .ok()
        .filter(|version| *version > 0)
        .ok_or_else(|| AppError::InvalidRequest("invalid bookmark version".to_string()))
}

fn parse_utc_datetime(value: &str) -> Result<i64, AppError> {
    let (date, clock) = value
        .trim()
        .split_once('T')
        .ok_or_else(|| AppError::InvalidRequest("custom UTC time is required".to_string()))?;
    let date_parts: Vec<&str> = date.split('-').collect();
    let time_parts: Vec<&str> = clock.split(':').collect();
    if date_parts.len() != 3 || time_parts.len() != 2 {
        return Err(AppError::InvalidRequest(
            "custom UTC time is invalid".to_string(),
        ));
    }
    let year = date_parts[0]
        .parse::<i32>()
        .map_err(|_| AppError::InvalidRequest("custom UTC time is invalid".to_string()))?;
    let month = date_parts[1]
        .parse::<u8>()
        .ok()
        .and_then(|value| Month::try_from(value).ok())
        .ok_or_else(|| AppError::InvalidRequest("custom UTC time is invalid".to_string()))?;
    let day = date_parts[2]
        .parse::<u8>()
        .map_err(|_| AppError::InvalidRequest("custom UTC time is invalid".to_string()))?;
    let hour = time_parts[0]
        .parse::<u8>()
        .map_err(|_| AppError::InvalidRequest("custom UTC time is invalid".to_string()))?;
    let minute = time_parts[1]
        .parse::<u8>()
        .map_err(|_| AppError::InvalidRequest("custom UTC time is invalid".to_string()))?;
    let date = Date::from_calendar_date(year, month, day)
        .map_err(|_| AppError::InvalidRequest("custom UTC time is invalid".to_string()))?;
    let time = Time::from_hms(hour, minute, 0)
        .map_err(|_| AppError::InvalidRequest("custom UTC time is invalid".to_string()))?;
    Ok(PrimitiveDateTime::new(date, time)
        .assume_utc()
        .unix_timestamp())
}

fn future_at(now: i64, delay: i64) -> Result<i64, AppError> {
    now.checked_add(delay)
        .ok_or_else(|| AppError::InvalidRequest("bookmark reminder is out of range".to_string()))
}

fn post_target(thread_id: &str, created_at: i64, post_id: &str) -> String {
    format!("/t/{thread_id}?around={created_at}_{post_id}#post-{post_id}")
}

fn actor_label<'a>(subject: &'a str, email: &'a str) -> &'a str {
    if email.trim().is_empty() {
        subject
    } else {
        email
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
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    if let Some(cookie) = set_cookie {
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    response
}

fn redirect_to(location: &str) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::{parse_cursor, parse_utc_datetime};

    #[test]
    fn cursor_keeps_prefixed_post_id() {
        let cursor = parse_cursor(Some("123_p_dead_beef")).unwrap();
        assert_eq!(cursor.sort_at, 123);
        assert_eq!(cursor.post_id, "p_dead_beef");
    }

    #[test]
    fn utc_datetime_is_strict() {
        assert_eq!(parse_utc_datetime("1970-01-02T00:00").unwrap(), 86_400);
        assert!(parse_utc_datetime("2026-02-30T10:00").is_err());
        assert!(parse_utc_datetime("2026-01-01 10:00").is_err());
    }
}
