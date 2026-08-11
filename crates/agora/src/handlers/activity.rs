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
use crate::handlers::{form_action, hidden_field, page_chrome, personal_counts};
use crate::model::{ActivityItem, ActivityKind, ActivityReason};
use crate::store::{ActivityCursor, ActivityFilter};
use crate::view_model::{
    ActionKind, ActivityFilterLinkVM, ActivityFilterVM, ActivityItemShared, ActivityItemVM,
    ActivityItemViewerState, ActivityKindVM, ActivityOpenFormVM, ActivityReadScopeLinkVM,
    ActivityReadScopeVM, ActivityReasonVM, ActivityShared, ActivityView, ActivityViewerState,
    CollectionState, NavTab, Opaque, PageLinkVM, PaginationVM, Text,
};
use crate::views;
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
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let filter = query.filter();
    let unread_only = query.unread_only();
    let older = has_more.then(|| {
        let item = items
            .last()
            .expect("has_more requires a retained page item");
        let cursor = format!("{}_{}", item.event.created_at, item.event.id);
        PageLinkVM {
            href: Opaque(activity_href(
                query.filter_key(),
                unread_only,
                Some(&cursor),
            )),
            label: Text("Older activity".to_string()),
        }
    });
    let mark_page_read = (!items.is_empty()).then(|| {
        form_action(
            "/activity/read-page",
            ActionKind::MarkPageRead,
            csrf.clone(),
            vec![
                hidden_field("filter", query.filter_key()),
                hidden_field("state", if unread_only { "unread" } else { "all" }),
                hidden_field(
                    "ids",
                    items
                        .iter()
                        .map(|item| item.event.id.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        )
    });
    let view = ActivityView {
        chrome: page_chrome("Activity", &headers, NavTab::Activity, counts),
        shared: ActivityShared {
            active_filter: activity_filter_vm(filter),
            read_scope: if unread_only {
                ActivityReadScopeVM::Unread
            } else {
                ActivityReadScopeVM::All
            },
            filter_links: activity_filter_links(unread_only),
            read_scope_links: activity_read_scope_links(query.filter_key()),
            visible_bound: ACTIVITY_PAGE_SIZE,
            state: activity_collection_state(&items, filter, unread_only, before.is_some()),
            now,
        },
        viewer: ActivityViewerState {
            items: items
                .iter()
                .map(|item| activity_item_vm(item, &csrf))
                .collect(),
            pagination: PaginationVM {
                previous: None,
                next: older,
                jump: None,
                at_start: before.is_none(),
                at_end: !has_more,
                visible_limit: ACTIVITY_PAGE_SIZE,
            },
            mark_page_read,
        },
    };
    let html = views::personal::activity(&view);
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
    let location = activity_href(filter_key, form.state == "unread", None);
    Ok(redirect_to(&location))
}

fn activity_filter_vm(filter: ActivityFilter) -> ActivityFilterVM {
    match filter {
        ActivityFilter::All => ActivityFilterVM::All,
        ActivityFilter::Reason(ActivityReason::Mention) => ActivityFilterVM::Mention,
        ActivityFilter::Reason(ActivityReason::Reply) => ActivityFilterVM::Reply,
        ActivityFilter::Reason(ActivityReason::Following) => ActivityFilterVM::Following,
        ActivityFilter::Reason(ActivityReason::Answer) => ActivityFilterVM::Answer,
    }
}

fn activity_filter_links(unread: bool) -> Vec<ActivityFilterLinkVM> {
    [
        (ActivityFilterVM::All, "all", "Everything"),
        (ActivityFilterVM::Mention, "mention", "Mentions"),
        (ActivityFilterVM::Reply, "reply", "Replies"),
        (ActivityFilterVM::Following, "following", "Following"),
        (ActivityFilterVM::Answer, "answer", "Answers"),
    ]
    .into_iter()
    .map(|(filter, key, label)| ActivityFilterLinkVM {
        filter,
        link: PageLinkVM {
            href: Opaque(activity_href(key, unread, None)),
            label: Text(label.to_string()),
        },
    })
    .collect()
}

fn activity_read_scope_links(filter: &str) -> Vec<ActivityReadScopeLinkVM> {
    [
        (ActivityReadScopeVM::All, false, "All"),
        (ActivityReadScopeVM::Unread, true, "Unread"),
    ]
    .into_iter()
    .map(|(scope, unread, label)| ActivityReadScopeLinkVM {
        scope,
        link: PageLinkVM {
            href: Opaque(activity_href(filter, unread, None)),
            label: Text(label.to_string()),
        },
    })
    .collect()
}

fn activity_collection_state(
    items: &[ActivityItem],
    filter: ActivityFilter,
    unread_only: bool,
    has_cursor: bool,
) -> CollectionState {
    if !items.is_empty() {
        CollectionState::Ready
    } else if has_cursor {
        CollectionState::End
    } else if filter != ActivityFilter::All || unread_only {
        CollectionState::FilteredZero
    } else {
        CollectionState::ReadyEmpty
    }
}

fn activity_item_vm(item: &ActivityItem, csrf: &str) -> ActivityItemVM {
    let actor_display = if item.actor_email.trim().is_empty() {
        item.event.actor_sub.clone()
    } else {
        item.actor_email.clone()
    };
    let next_state = if item.read { "unread" } else { "read" };
    ActivityItemVM {
        shared: ActivityItemShared {
            id: Opaque(item.event.id.clone()),
            kind: match item.event.kind {
                ActivityKind::PostCreated => ActivityKindVM::PostCreated,
                ActivityKind::AnswerAccepted => ActivityKindVM::AnswerAccepted,
            },
            thread_id: Opaque(item.event.thread_id.clone()),
            post_id: Opaque(item.event.post_id.clone()),
            thread_title: Text(item.thread_title.clone()),
            post_excerpt: Text(compact_snippet(&item.post_body_md, 180)),
            actor_display: Text(actor_display),
            created_at: item.event.created_at,
        },
        viewer: ActivityItemViewerState {
            reason: match item.reason {
                ActivityReason::Mention => ActivityReasonVM::Mention,
                ActivityReason::Reply => ActivityReasonVM::Reply,
                ActivityReason::Following => ActivityReasonVM::Following,
                ActivityReason::Answer => ActivityReasonVM::Answer,
            },
            read: item.read,
            open: ActivityOpenFormVM {
                submit: form_action(
                    format!("/activity/{}/open", item.event.id),
                    ActionKind::OpenActivity,
                    csrf,
                    Vec::new(),
                ),
                exact_target: Opaque(activity_target(item)),
            },
            toggle_read: form_action(
                format!("/activity/{}/state", item.event.id),
                if item.read {
                    ActionKind::MarkUnread
                } else {
                    ActionKind::MarkRead
                },
                csrf,
                vec![hidden_field("state", next_state)],
            ),
        },
    }
}

fn activity_target(item: &ActivityItem) -> String {
    format!(
        "/t/{}?around={}_{}#post-{}",
        item.event.thread_id, item.post_created_at, item.event.post_id, item.event.post_id
    )
}

fn activity_href(filter: &str, unread: bool, before: Option<&str>) -> String {
    let mut params = vec![format!("filter={filter}")];
    if unread {
        params.push("state=unread".to_string());
    }
    if let Some(before) = before {
        params.push(format!("before={before}"));
    }
    format!("/activity?{}", params.join("&"))
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
