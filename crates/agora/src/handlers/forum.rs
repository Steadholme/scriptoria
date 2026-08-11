//! The forum pages: home, category, thread (with markdown-rendered posts + reply), and the
//! new-thread form + create.
//!
//! Every page is server-rendered into the shared enterprise shell. Reads render for any
//! gateway-authenticated user; the two POSTs (create thread, reply) require a gateway-injected
//! identity (the trusted author) AND a valid double-submit CSRF token. Post bodies are
//! CommonMark, rendered through the sanitiser in [`crate::markdown`]; all other interpolated
//! text is HTML-escaped.

use std::collections::{HashMap, HashSet};

use axum::extract::{Form, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth;
use crate::error::AppError;
use crate::handlers::insight::thread_summary;
use crate::handlers::{
    category_vm, follow_level, form_action, hidden_field, link_action, page_chrome,
    personal_counts, thread_kind, thread_order, thread_row_shared, thread_scope,
};
use crate::model::{
    Bookmark, Category, CategoryFocusLevel, Post, ReactionCount, Thread, ThreadFollowLevel,
    ThreadReadingState,
};
use crate::store::{
    AcceptedAnswerAction, CatchUpCursor, CatchUpQuestionState, CatchUpReason, CatchUpView,
    CategoryFocusReason, ReplyAnchor, ThreadSort, ThreadStatusFilter, MAX_CATCH_UP_PAGE,
    MAX_CATEGORY_FOCUS_PAGE, MAX_CATEGORY_FOCUS_RULES, MAX_KLAXON_RECIPIENTS_PER_REPLY,
};
use crate::view_model::{
    AcceptanceMeaning, ActionKind, AdminThreadToolbarVM, AnswerDaisVM, AnswerState,
    CatchUpFeedShared, CatchUpFeedVM, CatchUpFeedViewerState, CatchUpItemVM,
    CatchUpItemViewerState, CatchUpQuestionStateVM, CatchUpReasonVM, CatchUpTab,
    CategoryFocusFormVM, CategoryFocusLevelVM, CategoryFocusReasonVM, CategoryPageShared,
    CategoryPageViewerState, CategoryView, CollectionState, ComposeMode, ComposeShared,
    ComposeView, ComposeViewerState, ConsequenceVM, DestructiveReviewVM, FocusItemVM, FocusRuleVM,
    FocusShared, FocusView, FocusViewerState, HomeShared, HomeView, MoveThreadFormVM, NavTab,
    Opaque, PageLinkVM, PaginationVM, PostActionsVM, PostBookmarkActionVM, PostVM, PostViewerState,
    QuoteVM, ReactionVM, ReadingProgressVM, ReplyFormVM, SafeHtml, SavedBookmarkStateVM,
    SubscriptionFormVM, SummaryStateVM, SummaryUnavailableReason, SummaryVM, Text,
    ThreadListControlsVM, ThreadOrder, ThreadOrderLinkVM, ThreadRowVM, ThreadRowViewerState,
    ThreadScope, ThreadScopeLinkVM, ThreadShared, ThreadView, ThreadViewerState,
};
use crate::{markdown, new_id, now_secs, AppState};

/// Most-recent threads shown on the home page.
const RECENT_LIMIT: i64 = 20;
/// Replies rendered per keyset page on the thread view. A large thread renders (and reaction-
/// queries) only one page of replies at a time; the OP is always pinned on top, separately.
pub const REPLIES_PER_PAGE: i64 = 20;
/// Threads listed on a category page.
const CATEGORY_LIMIT: i64 = 200;
/// Caps on user input (defense against absurd payloads; the store columns are TEXT).
const MAX_TITLE: usize = 200;
const MAX_BODY: usize = 20_000;

/// The reaction kinds a user may toggle on a post: `(kind, glyph)`. This is the closed set — a
/// POST with any other `kind` is rejected — and it drives the rendered button row (a button per
/// entry, in this order) so every post shows the same, stable reaction affordances.
pub const REACTION_KINDS: &[(&str, &str)] = &[("up", "\u{1F44D}"), ("heart", "\u{2764}")];

/// Whether `kind` is one of the allowed [`REACTION_KINDS`].
fn is_reaction_kind(kind: &str) -> bool {
    REACTION_KINDS.iter().any(|(k, _)| *k == kind)
}

/// Sentences in the per-thread extractive summary card.
const SUMMARY_SENTENCES: usize = 3;
/// Only render the summary card once a thread is substantial enough to be worth compressing:
/// at least this many posts AND words. Small/short threads show no card (the posts ARE the
/// summary), so the page is unchanged for them.
const SUMMARY_MIN_POSTS: usize = 2;
const SUMMARY_MIN_WORDS: usize = 60;

// ===========================================================================
// GET / — categories (with thread counts) + recent threads
// ===========================================================================

/// Shared query for thread lists (`/` and `/c/{id}`): optional sort selector and a current-user
/// subscription filter. Missing/unknown sort preserves the legacy latest ordering.
#[derive(Debug, Deserialize, Default)]
pub struct ThreadListQuery {
    #[serde(default)]
    pub sort: Option<String>,
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub focus_saved: Option<String>,
}

impl ThreadListQuery {
    fn sort(&self) -> ThreadSort {
        match self.sort.as_deref().unwrap_or("latest") {
            "top" => ThreadSort::Top,
            "hot" => ThreadSort::Hot,
            _ => ThreadSort::Latest,
        }
    }

    fn sort_key(&self) -> &'static str {
        match self.sort() {
            ThreadSort::Latest => "latest",
            ThreadSort::Top => "top",
            ThreadSort::Hot => "hot",
        }
    }

    fn subscribed_only(&self) -> bool {
        self.filter.as_deref() == Some("subscribed")
    }

    fn status(&self) -> ThreadStatusFilter {
        match self.status.as_deref() {
            Some("answered") => ThreadStatusFilter::Answered,
            Some("unanswered") => ThreadStatusFilter::Unanswered,
            _ => ThreadStatusFilter::Any,
        }
    }
}

fn thread_list_controls_vm(
    action: &str,
    query: &ThreadListQuery,
    show_subscribed: bool,
    show_answer_filters: bool,
    effective_status: ThreadStatusFilter,
    show_questions_cta: bool,
) -> ThreadListControlsVM {
    let active_order = thread_order(query.sort());
    let active_scope = thread_scope(effective_status);
    let subscribed_only = query.subscribed_only();
    let status_key = match effective_status {
        ThreadStatusFilter::Questions => Some("questions"),
        ThreadStatusFilter::Answered => Some("answered"),
        ThreadStatusFilter::Unanswered => Some("unanswered"),
        ThreadStatusFilter::Any => None,
    };
    let order_links = [
        (ThreadOrder::Latest, "latest"),
        (ThreadOrder::Top, "top"),
        (ThreadOrder::Hot, "hot"),
    ]
    .into_iter()
    .map(|(order, key)| ThreadOrderLinkVM {
        order,
        href: Opaque(list_href_raw(action, key, status_key, subscribed_only)),
    })
    .collect();
    let scope_links = if show_answer_filters {
        let all_scope = if effective_status == ThreadStatusFilter::Questions {
            ThreadScope::Questions
        } else {
            ThreadScope::Any
        };
        [
            (all_scope, None),
            (ThreadScope::Unanswered, Some("unanswered")),
            (ThreadScope::Answered, Some("answered")),
        ]
        .into_iter()
        .map(|(scope, key)| ThreadScopeLinkVM {
            scope,
            href: Opaque(list_href_raw(
                action,
                query.sort_key(),
                key,
                subscribed_only,
            )),
        })
        .collect()
    } else {
        Vec::new()
    };
    let subscribed_toggle = show_subscribed.then(|| {
        let enabling = !subscribed_only;
        PageLinkVM {
            href: Opaque(list_href_raw(
                action,
                query.sort_key(),
                status_key,
                enabling,
            )),
            label: Text(if enabling { "Following" } else { "Show all" }.to_string()),
        }
    });
    let questions = show_questions_cta.then(|| PageLinkVM {
        href: Opaque("/questions".to_string()),
        label: Text("Questions".to_string()),
    });
    ThreadListControlsVM {
        active_order,
        active_scope,
        subscribed_only,
        order_links,
        scope_links,
        subscribed_toggle,
        questions,
    }
}

fn thread_row_viewer(
    thread_id: &str,
    reading: Option<&ThreadReadingState>,
    follow: Option<ThreadFollowLevel>,
) -> ThreadRowViewerState {
    ThreadRowViewerState {
        follow_level: follow.map(follow_level),
        bookmarked: None,
        unread_count: reading.map(|state| state.unread_count.max(0)),
        resume_href: reading
            .filter(|state| state.started && state.unread_count > 0)
            .map(|_| Opaque(format!("/t/{thread_id}?resume=1#thread-resume"))),
    }
}

const fn category_focus_level_vm(level: CategoryFocusLevel) -> CategoryFocusLevelVM {
    match level {
        CategoryFocusLevel::None => CategoryFocusLevelVM::None,
        CategoryFocusLevel::Priority => CategoryFocusLevelVM::Priority,
        CategoryFocusLevel::Follow => CategoryFocusLevelVM::Follow,
        CategoryFocusLevel::Mute => CategoryFocusLevelVM::Mute,
    }
}

const fn category_focus_reason_vm(reason: CategoryFocusReason) -> CategoryFocusReasonVM {
    match reason {
        CategoryFocusReason::CategoryPriority => CategoryFocusReasonVM::CategoryPriority,
        CategoryFocusReason::CategoryFollow => CategoryFocusReasonVM::CategoryFollow,
        CategoryFocusReason::ThreadWatchOverride => CategoryFocusReasonVM::ThreadWatchOverride,
        CategoryFocusReason::ThreadFollowOverride => CategoryFocusReasonVM::ThreadFollowOverride,
    }
}

const fn catch_up_tab(view: CatchUpView) -> CatchUpTab {
    match view {
        CatchUpView::Updates => CatchUpTab::Updates,
        CatchUpView::Following => CatchUpTab::Following,
        CatchUpView::Questions => CatchUpTab::Questions,
    }
}

const fn catch_up_reason(reason: CatchUpReason) -> CatchUpReasonVM {
    match reason {
        CatchUpReason::Watch => CatchUpReasonVM::Watch,
        CatchUpReason::Follow => CatchUpReasonVM::Follow,
        CatchUpReason::Authored => CatchUpReasonVM::Authored,
        CatchUpReason::Bookmarked => CatchUpReasonVM::Bookmarked,
        CatchUpReason::Participated => CatchUpReasonVM::Participated,
        CatchUpReason::ContinueReading => CatchUpReasonVM::ContinueReading,
    }
}

const fn catch_up_question_state(state: CatchUpQuestionState) -> CatchUpQuestionStateVM {
    match state {
        CatchUpQuestionState::Waiting => CatchUpQuestionStateVM::Waiting,
        CatchUpQuestionState::Solved => CatchUpQuestionStateVM::Solved,
    }
}

pub async fn home(
    State(state): State<AppState>,
    Query(q): Query<ThreadListQuery>,
    headers: HeaderMap,
) -> Result<Html<String>, AppError> {
    let now = now_secs();
    let categories = state.store.list_categories().await?;
    let viewer_sub = auth::identity_subject(&headers);
    let recent = if q.subscribed_only() && viewer_sub.is_none() {
        Vec::new()
    } else {
        state
            .store
            .list_threads(
                None,
                q.sort(),
                subscribed_subject(&q, viewer_sub.as_deref()),
                q.status(),
                RECENT_LIMIT,
                now,
            )
            .await?
    };

    let categories_by_id: HashMap<&str, &Category> = categories
        .iter()
        .map(|category| (category.id.as_str(), category))
        .collect();
    let mut post_counts = HashMap::new();
    for t in &recent {
        post_counts.insert(t.id.clone(), state.store.count_posts(&t.id).await?);
    }
    let reading_states = load_reading_states(&state, viewer_sub.as_deref(), &recent).await?;
    let mut rows = Vec::with_capacity(recent.len());
    for thread in &recent {
        let category = categories_by_id.get(thread.category_id.as_str()).copied();
        let accepted = if category.is_some_and(|category| category.format.is_question()) {
            state
                .store
                .get_valid_accepted_post(&thread.id)
                .await?
                .is_some()
        } else {
            false
        };
        let follow = match viewer_sub.as_deref() {
            Some(subject) => Some(state.store.thread_follow_level(&thread.id, subject).await?),
            None => None,
        };
        rows.push(ThreadRowVM {
            shared: thread_row_shared(
                thread,
                category,
                post_counts.get(&thread.id).copied(),
                accepted,
            ),
            viewer: thread_row_viewer(&thread.id, reading_states.get(&thread.id), follow),
        });
    }
    let counts = personal_counts(&state, &headers, now).await?;
    let state_kind = if rows.is_empty() {
        if q.subscribed_only() || q.status() != ThreadStatusFilter::Any {
            CollectionState::FilteredZero
        } else {
            CollectionState::ReadyEmpty
        }
    } else {
        CollectionState::Ready
    };
    let view = HomeView {
        chrome: page_chrome("Forum", &headers, NavTab::Home, counts),
        shared: HomeShared {
            categories: categories.iter().map(category_vm).collect(),
            controls: thread_list_controls_vm(
                "/",
                &q,
                viewer_sub.is_some(),
                true,
                q.status(),
                true,
            ),
            state: state_kind,
            visible_bound: RECENT_LIMIT,
            now,
        },
        rows,
    };
    Ok(Html(crate::views::forum::home(&view)))
}

// ===========================================================================
// GET /for-you — private, task-oriented catch-up desk
// ===========================================================================

#[derive(Debug, Default, Deserialize)]
pub struct CatchUpQuery {
    #[serde(default)]
    view: Option<String>,
    #[serde(default)]
    as_of: Option<i64>,
    #[serde(default)]
    before: Option<String>,
}

impl CatchUpQuery {
    fn view(&self) -> Result<CatchUpView, AppError> {
        match self.view.as_deref().unwrap_or("updates") {
            "updates" => Ok(CatchUpView::Updates),
            "following" => Ok(CatchUpView::Following),
            "questions" => Ok(CatchUpView::Questions),
            _ => Err(AppError::InvalidRequest(
                "catch-up view must be updates, following, or questions".to_string(),
            )),
        }
    }

    fn page(&self, view: CatchUpView, now: i64) -> Result<(i64, Option<CatchUpCursor>), AppError> {
        let as_of = self.as_of.unwrap_or(now);
        if as_of < 0 || as_of > now {
            return Err(AppError::InvalidRequest(
                "catch-up as_of must be a current or past epoch".to_string(),
            ));
        }
        let Some(raw_cursor) = self.before.as_deref() else {
            return Ok((as_of, None));
        };
        if self.as_of.is_none() {
            return Err(AppError::InvalidRequest(
                "catch-up pagination requires its as_of snapshot".to_string(),
            ));
        }
        let cursor = parse_catch_up_cursor(raw_cursor)
            .ok_or_else(|| AppError::InvalidRequest("catch-up cursor is malformed".to_string()))?;
        if cursor.view != view || cursor.as_of != as_of {
            return Err(AppError::InvalidRequest(
                "catch-up cursor does not belong to this view and snapshot".to_string(),
            ));
        }
        Ok((as_of, Some(cursor)))
    }
}

fn encode_catch_up_cursor(cursor: &CatchUpCursor) -> String {
    format!(
        "v8g-{}-{}-{}-{}-{}",
        cursor.view.as_str(),
        cursor.as_of,
        cursor.snapshot_generation,
        cursor.activity_at,
        hex::encode(cursor.thread_id.as_bytes()),
    )
}

fn parse_catch_up_cursor(raw: &str) -> Option<CatchUpCursor> {
    let mut parts = raw.trim().splitn(6, '-');
    // The generation field is a semantic cursor upgrade. Pre-fix `v8-*` cursors fail closed
    // instead of silently continuing on their weaker second-granularity boundary.
    if parts.next()? != "v8g" {
        return None;
    }
    let view = match parts.next()? {
        "updates" => CatchUpView::Updates,
        "following" => CatchUpView::Following,
        "questions" => CatchUpView::Questions,
        _ => return None,
    };
    let as_of = parts.next()?.parse::<i64>().ok()?;
    let snapshot_generation = parts.next()?.parse::<i64>().ok()?;
    let activity_at = parts.next()?.parse::<i64>().ok()?;
    let thread_id = String::from_utf8(hex::decode(parts.next()?).ok()?).ok()?;
    if as_of < 0
        || snapshot_generation < 0
        || activity_at < 0
        || activity_at > as_of
        || thread_id.trim().is_empty()
    {
        return None;
    }
    Some(CatchUpCursor {
        view,
        as_of,
        snapshot_generation,
        activity_at,
        thread_id,
    })
}

fn catch_up_href_raw(
    view: CatchUpView,
    as_of: Option<i64>,
    before: Option<&CatchUpCursor>,
) -> String {
    let mut href = format!("/for-you?view={}", view.as_str());
    if let Some(as_of) = as_of {
        href.push_str(&format!("&as_of={as_of}"));
    }
    if let Some(cursor) = before {
        href.push_str("&before=");
        href.push_str(&encode_catch_up_cursor(cursor));
    }
    href
}

pub async fn for_you(
    State(state): State<AppState>,
    Query(query): Query<CatchUpQuery>,
    headers: HeaderMap,
) -> Result<Html<String>, AppError> {
    let identity = auth::require_author(&headers)?;
    let now = now_secs();
    let view = query.view()?;
    let (as_of, before) = query.page(view, now)?;
    let snapshot_generation = match before.as_ref() {
        Some(cursor) => cursor.snapshot_generation,
        None => state.store.catch_up_snapshot_generation().await?,
    };
    let mut items = state
        .store
        .catch_up_page(
            &identity.sub,
            view,
            as_of,
            snapshot_generation,
            before.as_ref(),
            MAX_CATCH_UP_PAGE + 1,
        )
        .await?;
    let has_more = items.len() as i64 > MAX_CATCH_UP_PAGE;
    items.truncate(MAX_CATCH_UP_PAGE as usize);
    let next_cursor = if has_more {
        items.last().map(|item| CatchUpCursor {
            view,
            as_of,
            snapshot_generation,
            activity_at: item.activity_at,
            thread_id: item.thread.id.clone(),
        })
    } else {
        None
    };
    let categories = state.store.list_categories().await?;
    let categories_by_id: HashMap<&str, &Category> = categories
        .iter()
        .map(|category| (category.id.as_str(), category))
        .collect();
    let rows = items
        .iter()
        .map(|item| {
            let category = categories_by_id
                .get(item.thread.category_id.as_str())
                .copied();
            let solved = item.question_state == Some(CatchUpQuestionState::Solved);
            CatchUpItemVM {
                shared: thread_row_shared(
                    &item.thread,
                    category,
                    Some(item.reply_count.saturating_add(1)),
                    solved,
                ),
                viewer: CatchUpItemViewerState {
                    reason: catch_up_reason(item.reason),
                    follow_level: follow_level(item.follow_level),
                    unread_count: item.unread_count.max(0),
                    first_unread_href: item.first_unread.as_ref().map(|post| {
                        Opaque(format!("/t/{}?resume=1#post-{}", item.thread.id, post.id))
                    }),
                    question_state: item.question_state.map(catch_up_question_state),
                },
            }
        })
        .collect::<Vec<_>>();
    let counts = personal_counts(&state, &headers, now).await?;
    let collection_state = if rows.is_empty() {
        if before.is_some() {
            CollectionState::End
        } else {
            CollectionState::ReadyEmpty
        }
    } else {
        CollectionState::Ready
    };
    let view_model = CatchUpFeedVM {
        chrome: page_chrome("Catch up", &headers, NavTab::Home, counts),
        shared: CatchUpFeedShared {
            active: catch_up_tab(view),
            snapshot_as_of: as_of,
            visible_bound: MAX_CATCH_UP_PAGE,
            state: collection_state,
            now,
        },
        viewer: CatchUpFeedViewerState {
            items: rows,
            pagination: PaginationVM {
                previous: None,
                next: next_cursor.as_ref().map(|cursor| PageLinkVM {
                    href: Opaque(catch_up_href_raw(view, Some(as_of), Some(cursor))),
                    label: Text("More threads".to_string()),
                }),
                jump: None,
                at_start: before.is_none(),
                at_end: !has_more,
                visible_limit: MAX_CATCH_UP_PAGE,
            },
        },
    };
    Ok(Html(crate::views::personal::catch_up(&view_model)))
}

// ===========================================================================
// GET /focus — private, bounded Category Focus desk
// ===========================================================================

pub async fn focus(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let identity = auth::require_author(&headers)?;
    let now = now_secs();
    let items = state
        .store
        .category_focus_page(&identity.sub, MAX_CATEGORY_FOCUS_PAGE, now)
        .await?;
    let rules = state.store.category_focus_rules(&identity.sub).await?;
    let focus_threads = items
        .iter()
        .map(|item| item.thread.clone())
        .collect::<Vec<_>>();
    let reading_states =
        load_reading_states(&state, Some(identity.sub.as_str()), &focus_threads).await?;
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let rule_models = rules
        .iter()
        .map(|rule| FocusRuleVM {
            category: category_vm(&rule.category),
            level: category_focus_level_vm(rule.level),
            submit: form_action(
                format!("/c/{}/focus", rule.category.id),
                ActionKind::SaveFocusRule,
                csrf.clone(),
                vec![
                    hidden_field("sort", "latest"),
                    hidden_field("filter", ""),
                    hidden_field("status", ""),
                ],
            ),
        })
        .collect::<Vec<_>>();
    let mut item_models = Vec::with_capacity(items.len());
    for item in &items {
        let accepted = if item.category.format.is_question() {
            state
                .store
                .get_valid_accepted_post(&item.thread.id)
                .await?
                .is_some()
        } else {
            false
        };
        item_models.push(FocusItemVM {
            shared: thread_row_shared(&item.thread, Some(&item.category), None, accepted),
            category_level: category_focus_level_vm(item.category_level),
            thread_level: follow_level(item.thread_level),
            reason: category_focus_reason_vm(item.reason),
            viewer: thread_row_viewer(
                &item.thread.id,
                reading_states.get(&item.thread.id),
                Some(item.thread_level),
            ),
        });
    }
    let counts = personal_counts(&state, &headers, now).await?;
    let collection_state = if item_models.is_empty() {
        if rule_models.is_empty() {
            CollectionState::ReadyEmpty
        } else {
            CollectionState::FilteredZero
        }
    } else {
        CollectionState::Ready
    };
    let view = FocusView {
        chrome: page_chrome("Focus", &headers, NavTab::Home, counts),
        shared: FocusShared {
            visible_thread_bound: MAX_CATEGORY_FOCUS_PAGE,
            rule_bound: MAX_CATEGORY_FOCUS_RULES as i64,
            state: collection_state,
            now,
        },
        viewer: FocusViewerState {
            rules: rule_models,
            items: item_models,
        },
    };
    Ok(html_response(
        crate::views::personal::focus(&view),
        set_cookie,
    ))
}

// ===========================================================================
// GET /questions — all question categories, with a stable answer-status filter
// ===========================================================================

pub async fn questions(
    State(state): State<AppState>,
    Query(q): Query<ThreadListQuery>,
    headers: HeaderMap,
) -> Result<Html<String>, AppError> {
    let now = now_secs();
    let categories = state.store.list_categories().await?;
    let viewer_sub = auth::identity_subject(&headers);
    let status = match q.status() {
        ThreadStatusFilter::Any => ThreadStatusFilter::Questions,
        filtered => filtered,
    };
    let threads = if q.subscribed_only() && viewer_sub.is_none() {
        Vec::new()
    } else {
        state
            .store
            .list_threads(
                None,
                q.sort(),
                subscribed_subject(&q, viewer_sub.as_deref()),
                status,
                CATEGORY_LIMIT,
                now,
            )
            .await?
    };
    let question_categories = categories
        .iter()
        .filter(|category| category.format.is_question())
        .collect::<Vec<_>>();
    let categories_by_id: HashMap<&str, &Category> = question_categories
        .iter()
        .map(|category| (category.id.as_str(), *category))
        .collect();
    let reading_states = load_reading_states(&state, viewer_sub.as_deref(), &threads).await?;
    let mut rows = Vec::with_capacity(threads.len());
    for thread in &threads {
        let category = categories_by_id.get(thread.category_id.as_str()).copied();
        let accepted = state
            .store
            .get_valid_accepted_post(&thread.id)
            .await?
            .is_some();
        let post_count = state.store.count_posts(&thread.id).await?;
        let follow = match viewer_sub.as_deref() {
            Some(subject) => Some(state.store.thread_follow_level(&thread.id, subject).await?),
            None => None,
        };
        rows.push(ThreadRowVM {
            shared: thread_row_shared(thread, category, Some(post_count), accepted),
            viewer: thread_row_viewer(&thread.id, reading_states.get(&thread.id), follow),
        });
    }
    let counts = personal_counts(&state, &headers, now).await?;
    let collection_state = if rows.is_empty() {
        if q.subscribed_only() || status != ThreadStatusFilter::Questions {
            CollectionState::FilteredZero
        } else {
            CollectionState::ReadyEmpty
        }
    } else {
        CollectionState::Ready
    };
    let view = HomeView {
        chrome: page_chrome("Questions", &headers, NavTab::Home, counts),
        shared: HomeShared {
            categories: question_categories.into_iter().map(category_vm).collect(),
            controls: thread_list_controls_vm(
                "/questions",
                &q,
                viewer_sub.is_some(),
                true,
                status,
                false,
            ),
            state: collection_state,
            visible_bound: CATEGORY_LIMIT,
            now,
        },
        rows,
    };
    Ok(Html(crate::views::forum::home(&view)))
}

// ===========================================================================
// GET /c/{id} — threads in a category
// ===========================================================================

pub async fn category(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<ThreadListQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let now = now_secs();
    let category = state
        .store
        .get_category(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("category not found".to_string()))?;
    let viewer_sub = auth::identity_subject(&headers);
    let status = if category.format.is_question() {
        q.status()
    } else {
        ThreadStatusFilter::Any
    };
    let threads = if q.subscribed_only() && viewer_sub.is_none() {
        Vec::new()
    } else {
        state
            .store
            .list_threads(
                Some(&id),
                q.sort(),
                subscribed_subject(&q, viewer_sub.as_deref()),
                status,
                CATEGORY_LIMIT,
                now,
            )
            .await?
    };

    let reading_states = load_reading_states(&state, viewer_sub.as_deref(), &threads).await?;
    let mut rows = Vec::with_capacity(threads.len());
    for thread in &threads {
        let accepted = if category.format.is_question() {
            state
                .store
                .get_valid_accepted_post(&thread.id)
                .await?
                .is_some()
        } else {
            false
        };
        let post_count = state.store.count_posts(&thread.id).await?;
        let follow = match viewer_sub.as_deref() {
            Some(subject) => Some(state.store.thread_follow_level(&thread.id, subject).await?),
            None => None,
        };
        rows.push(ThreadRowVM {
            shared: thread_row_shared(thread, Some(&category), Some(post_count), accepted),
            viewer: thread_row_viewer(&thread.id, reading_states.get(&thread.id), follow),
        });
    }
    let (focus, set_cookie) = if let Some(viewer_sub) = viewer_sub.as_deref() {
        let current = state
            .store
            .category_focus_level(viewer_sub, &category.id)
            .await?;
        let (csrf, set_cookie) = auth::ensure_csrf(&headers);
        let return_status = match q.status() {
            ThreadStatusFilter::Answered => "answered",
            ThreadStatusFilter::Unanswered => "unanswered",
            ThreadStatusFilter::Any | ThreadStatusFilter::Questions => "",
        };
        (
            Some(CategoryFocusFormVM {
                selected: category_focus_level_vm(current),
                saved: q.focus_saved.as_deref() == Some(current.as_str()),
                submit: form_action(
                    format!("/c/{}/focus", category.id),
                    ActionKind::ApplyFocus,
                    csrf,
                    vec![
                        hidden_field("sort", q.sort_key()),
                        hidden_field(
                            "filter",
                            if q.subscribed_only() {
                                "subscribed"
                            } else {
                                ""
                            },
                        ),
                        hidden_field("status", return_status),
                    ],
                ),
            }),
            set_cookie,
        )
    } else {
        (None, None)
    };
    let counts = personal_counts(&state, &headers, now).await?;
    let collection_state = if rows.is_empty() {
        if q.subscribed_only() || status != ThreadStatusFilter::Any {
            CollectionState::FilteredZero
        } else {
            CollectionState::ReadyEmpty
        }
    } else {
        CollectionState::Ready
    };
    let view = CategoryView {
        chrome: page_chrome(category.name.clone(), &headers, NavTab::Home, counts),
        shared: CategoryPageShared {
            category: category_vm(&category),
            controls: thread_list_controls_vm(
                &format!("/c/{}", category.id),
                &q,
                viewer_sub.is_some(),
                category.format.is_question(),
                status,
                false,
            ),
            state: collection_state,
            visible_bound: CATEGORY_LIMIT,
            now,
        },
        rows,
        viewer: CategoryPageViewerState { focus },
    };
    Ok(html_response(
        crate::views::forum::category(&view),
        set_cookie,
    ))
}

#[derive(Debug, Deserialize)]
pub struct CategoryFocusForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub sort: String,
    #[serde(default)]
    pub filter: String,
    #[serde(default)]
    pub status: String,
}

pub async fn set_category_focus(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CategoryFocusForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let author = auth::require_author(&headers)?;
    let level = CategoryFocusLevel::parse(&form.level).ok_or_else(|| {
        AppError::InvalidRequest(
            "category focus level must be priority, follow, mute, or none".to_string(),
        )
    })?;
    state
        .store
        .set_category_focus_level(&author.sub, &id, level, now_secs())
        .await?;
    let actor = if author.email.is_empty() {
        &author.sub
    } else {
        &author.email
    };
    state.audit.emit(AuditEvent::info(
        "category.focus_rule",
        actor,
        &id,
        level.as_str(),
    ));
    let mut query = vec![format!("focus_saved={}", level.as_str())];
    if matches!(form.sort.as_str(), "top" | "hot") {
        query.push(format!("sort={}", form.sort));
    }
    if form.filter == "subscribed" {
        query.push("filter=subscribed".to_string());
    }
    if matches!(form.status.as_str(), "answered" | "unanswered") {
        query.push(format!("status={}", form.status));
    }
    Ok(redirect_to(&format!(
        "/c/{}?{}#category-focus-heading",
        id,
        query.join("&")
    )))
}

// ===========================================================================
// GET /t/{id} — a thread: original post + replies (markdown) + reply form
// ===========================================================================

/// Keyset cursor + page anchor for the thread view's reply list. All optional; a bare
/// `GET /t/{id}` shows the first (oldest) page. `?before=<created_at>_<id>` pages to older
/// replies, `?after=<created_at>_<id>` to newer, `?around=<created_at>_<id>` includes an activity
/// target, and `?latest=1` jumps to the newest page.
#[derive(Debug, Deserialize, Default)]
pub struct ThreadQuery {
    #[serde(default)]
    pub before: Option<String>,
    #[serde(default)]
    pub after: Option<String>,
    #[serde(default)]
    pub latest: Option<String>,
    #[serde(default)]
    pub around: Option<String>,
    #[serde(default)]
    pub quote: Option<String>,
    /// Product-level continuation entry. It resolves from authoritative per-post receipts and is
    /// intentionally separate from raw keyset cursors.
    #[serde(default)]
    pub resume: Option<String>,
}

struct ThreadPostProjection<'a> {
    viewer: Option<&'a str>,
    is_admin: bool,
    thread_id: &'a str,
    csrf: &'a str,
    accepted_post_id: &'a str,
    can_manage_answer: bool,
    is_question: bool,
    can_reply: bool,
    can_post: bool,
    first_unread_post_id: Option<&'a str>,
    reactions: &'a HashMap<String, Vec<ReactionCount>>,
    bookmarks: &'a HashMap<String, Bookmark>,
    quoted_posts: &'a HashMap<String, Post>,
    now: i64,
}

fn project_post(post: &Post, is_op: bool, ctx: &ThreadPostProjection<'_>) -> PostVM {
    let is_accepted = !is_op && !ctx.accepted_post_id.is_empty() && post.id == ctx.accepted_post_id;
    let owner = ctx.viewer == Some(post.author_sub.as_str());
    let mut delete_reviews = Vec::new();
    if !is_op && owner {
        delete_reviews.push(link_action(
            format!("/t/{}/p/{}/delete", ctx.thread_id, post.id),
            ActionKind::DeleteReplyReview,
        ));
    }
    if !is_op && ctx.is_admin {
        delete_reviews.push(link_action(
            format!("/admin/posts/{}/delete", post.id),
            ActionKind::DeleteAdminReview,
        ));
    }
    let accept = (!is_op && ctx.can_manage_answer && ctx.is_question && !is_accepted).then(|| {
        form_action(
            format!("/t/{}/accept", ctx.thread_id),
            ActionKind::AcceptAnswer,
            ctx.csrf,
            vec![
                hidden_field("action", "accept"),
                hidden_field("post_id", post.id.clone()),
            ],
        )
    });
    let remove_solution = (!is_op && ctx.can_manage_answer && is_accepted).then(|| {
        form_action(
            format!("/t/{}/accept", ctx.thread_id),
            ActionKind::RemoveSolution,
            ctx.csrf,
            vec![
                hidden_field("action", "clear"),
                hidden_field("post_id", post.id.clone()),
            ],
        )
    });
    let bookmark = ctx.viewer.map(|_| match ctx.bookmarks.get(&post.id) {
        Some(bookmark) => {
            let state = match bookmark.remind_at {
                Some(at) if at <= ctx.now => SavedBookmarkStateVM::Due,
                Some(_) => SavedBookmarkStateVM::Scheduled,
                None => SavedBookmarkStateVM::Saved,
            };
            PostBookmarkActionVM::Saved {
                edit: link_action(
                    format!("/bookmarks/{}/edit", post.id),
                    ActionKind::BookmarkEdit,
                ),
                state,
            }
        }
        None => PostBookmarkActionVM::Save(form_action(
            format!("/t/{}/p/{}/bookmark", ctx.thread_id, post.id),
            ActionKind::BookmarkSave,
            ctx.csrf,
            Vec::new(),
        )),
    });
    let counts = ctx
        .reactions
        .get(&post.id)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let reaction_models = REACTION_KINDS
        .iter()
        .map(|(kind, _glyph)| {
            let aggregate = counts.iter().find(|count| count.kind == *kind);
            ReactionVM {
                kind: Text((*kind).to_string()),
                count: aggregate.map(|count| count.count).unwrap_or(0),
                mine: ctx
                    .viewer
                    .map(|_| aggregate.is_some_and(|count| count.mine)),
                toggle: (ctx.viewer.is_some() && ctx.can_post).then(|| {
                    form_action(
                        format!("/t/{}/p/{}/react", ctx.thread_id, post.id),
                        ActionKind::ToggleReaction,
                        ctx.csrf,
                        vec![hidden_field("kind", *kind)],
                    )
                }),
            }
        })
        .collect();
    let first_unread = ctx.first_unread_post_id == Some(post.id.as_str());
    PostVM {
        id: Opaque(post.id.clone()),
        author_display: Text(post.author_email.clone()),
        created_at: post.created_at,
        body: SafeHtml(markdown::render(&post.body_md)),
        is_op,
        quote: ctx
            .quoted_posts
            .get(&post.quoted_post_id)
            .map(|quoted| QuoteVM {
                post_id: Opaque(quoted.id.clone()),
                author_display: Text(quoted.author_email.clone()),
                created_at: quoted.created_at,
                body: SafeHtml(markdown::render(&quoted.body_md)),
            }),
        reactions: reaction_models,
        viewer: PostViewerState {
            bookmarked: ctx.viewer.map(|_| ctx.bookmarks.contains_key(&post.id)),
            unread: first_unread.then_some(true),
            resume_anchor: first_unread.then(|| Opaque("thread-resume".to_string())),
        },
        actions: PostActionsVM {
            edit: (!is_op && owner).then(|| {
                link_action(
                    format!("/t/{}/p/{}/edit", ctx.thread_id, post.id),
                    ActionKind::EditReply,
                )
            }),
            delete_reviews,
            quote: ctx.can_reply.then(|| {
                link_action(
                    format!("/t/{}?quote={}#reply", ctx.thread_id, post.id),
                    ActionKind::Quote,
                )
            }),
            bookmark,
            accept,
            remove_solution,
        },
    }
}

pub(crate) fn summary_state(posts: &[Post]) -> SummaryStateVM {
    if posts.len() < SUMMARY_MIN_POSTS {
        return SummaryStateVM::Unavailable(SummaryUnavailableReason::TooFewPosts);
    }
    let word_count = posts
        .iter()
        .map(|post| post.body_md.split_whitespace().count())
        .sum::<usize>();
    if word_count < SUMMARY_MIN_WORDS {
        return SummaryStateVM::Unavailable(SummaryUnavailableReason::TooFewWords);
    }
    let sentences = thread_summary(posts, SUMMARY_SENTENCES);
    if sentences.len() < 2 {
        return SummaryStateVM::Unavailable(SummaryUnavailableReason::Unavailable);
    }
    SummaryStateVM::Available(SummaryVM {
        sentences: sentences.into_iter().map(Text).collect(),
        source_post_count: posts.len() as i64,
        source_word_count: word_count as i64,
        sentence_bound: SUMMARY_SENTENCES as i64,
    })
}

/// One authoritative reply-page boundary shared by the HTML thread view and its JSON summary.
/// The accepted answer is extracted before the ordinary-reply limit, exactly as it is rendered.
pub(crate) struct ThreadPageBoundary {
    thread: Thread,
    reading_state: Option<ThreadReadingState>,
    op: Option<Post>,
    accepted_post: Option<Post>,
    replies: Vec<Post>,
    has_older: bool,
    has_newer: bool,
}

impl ThreadPageBoundary {
    pub(crate) fn thread_id(&self) -> &str {
        &self.thread.id
    }

    pub(crate) fn visible_posts(&self) -> Vec<Post> {
        let mut posts = Vec::with_capacity(self.replies.len() + 2);
        if let Some(op) = &self.op {
            posts.push(op.clone());
        }
        if let Some(accepted) = &self.accepted_post {
            posts.push(accepted.clone());
        }
        posts.extend(self.replies.iter().cloned());
        posts
    }
}

pub(crate) async fn thread_page_boundary(
    state: &AppState,
    id: &str,
    q: &ThreadQuery,
    viewer: Option<&str>,
) -> Result<ThreadPageBoundary, AppError> {
    let thread = state
        .store
        .get_thread(id)
        .await?
        .ok_or_else(|| AppError::NotFound("thread not found".to_string()))?;
    let reading_state = match viewer {
        Some(subject) => Some(state.store.thread_reading_state(subject, id).await?),
        None => None,
    };
    let op = state.store.first_post_in_thread(id).await?;
    let op_id = op.as_ref().map(|post| post.id.clone()).unwrap_or_default();
    let accepted_post = state.store.get_valid_accepted_post(id).await?;
    let accepted_id = accepted_post.as_ref().map(|post| post.id.as_str());
    let resume_requested = q
        .resume
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    let first_unread = reading_state
        .as_ref()
        .and_then(|reading| reading.first_unread.as_ref());
    let anchor = if resume_requested {
        match first_unread {
            Some(post) if post.id == op_id => ReplyAnchor::First,
            Some(post) => ReplyAnchor::From(post.created_at, post.id.clone()),
            None => ReplyAnchor::Latest,
        }
    } else {
        resolve_anchor(q)
    };
    let mut fetched = state
        .store
        .replies_page(id, &op_id, accepted_id, &anchor, REPLIES_PER_PAGE + 1)
        .await?;
    let around_has_newer = if let ReplyAnchor::Around(ts, post_id) = &anchor {
        !state
            .store
            .replies_page(
                id,
                &op_id,
                accepted_id,
                &ReplyAnchor::After(*ts, post_id.clone()),
                1,
            )
            .await?
            .is_empty()
    } else {
        false
    };
    let from_has_older = if let ReplyAnchor::From(ts, post_id) = &anchor {
        !state
            .store
            .replies_page(
                id,
                &op_id,
                accepted_id,
                &ReplyAnchor::Before(*ts, post_id.clone()),
                1,
            )
            .await?
            .is_empty()
    } else {
        false
    };
    let has_more = fetched.len() as i64 > REPLIES_PER_PAGE;
    fetched.truncate(REPLIES_PER_PAGE as usize);
    let (replies, has_older, has_newer) = match anchor {
        ReplyAnchor::First => (fetched, false, has_more),
        ReplyAnchor::From(..) => (fetched, from_has_older, has_more),
        ReplyAnchor::After(..) => (fetched, true, has_more),
        ReplyAnchor::Before(..) => {
            fetched.reverse();
            (fetched, has_more, true)
        }
        ReplyAnchor::Latest => {
            fetched.reverse();
            (fetched, has_more, false)
        }
        ReplyAnchor::Around(..) => {
            fetched.reverse();
            (fetched, has_more, around_has_newer)
        }
    };
    Ok(ThreadPageBoundary {
        thread,
        reading_state,
        op,
        accepted_post,
        replies,
        has_older,
        has_newer,
    })
}

pub async fn thread(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<ThreadQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let now = now_secs();
    let viewer = auth::identity_subject(&headers);
    let boundary = thread_page_boundary(&state, &id, &q, viewer.as_deref()).await?;
    let ThreadPageBoundary {
        thread,
        reading_state,
        op,
        accepted_post,
        replies,
        has_older,
        has_newer,
    } = boundary;
    let category = state.store.get_category(&thread.category_id).await?;
    let is_question = category
        .as_ref()
        .map(|category| category.format.is_question())
        .unwrap_or(false);
    let viewer_banned = match viewer.as_deref() {
        Some(subject) => state.store.is_banned(subject).await?,
        None => false,
    };
    // Reply count (every post minus the original) — shown in the head + as the reply-list total.
    let post_count = state.store.count_posts(&id).await?;
    let valid_accepted_id = accepted_post
        .as_ref()
        .map(|post| post.id.clone())
        .unwrap_or_default();
    // Cursors come from the visible page bounds (ascending: first = oldest, last = newest).
    let older_cursor = if has_older {
        replies.first().map(|p| (p.created_at, p.id.clone()))
    } else {
        None
    };
    let newer_cursor = if has_newer {
        replies.last().map(|p| (p.created_at, p.id.clone()))
    } else {
        None
    };
    let pagination = PaginationVM {
        previous: older_cursor.as_ref().map(|(ts, cursor_id)| PageLinkVM {
            href: Opaque(format!("/t/{}?before={ts}_{cursor_id}", thread.id)),
            label: Text("Load older".to_string()),
        }),
        next: newer_cursor.as_ref().map(|(ts, cursor_id)| PageLinkVM {
            href: Opaque(format!("/t/{}?after={ts}_{cursor_id}", thread.id)),
            label: Text("Load newer".to_string()),
        }),
        jump: has_newer.then(|| PageLinkVM {
            href: Opaque(format!("/t/{}?latest=1#thread-latest", thread.id)),
            label: Text("Jump to latest".to_string()),
        }),
        at_start: !has_older,
        at_end: !has_newer,
        visible_limit: REPLIES_PER_PAGE,
    };

    // Display list: original post, then the accepted solution fixed directly below it, then one
    // full page of ordinary replies. The store excluded the solution before LIMIT, so it neither
    // disappears on another page nor renders twice on its natural page.
    let mut posts: Vec<Post> = Vec::with_capacity(replies.len() + 2);
    if let Some(op_post) = op {
        posts.push(op_post);
    }
    if let Some(solution) = accepted_post {
        posts.push(solution);
    }
    posts.extend(replies);

    // The authenticated subject (if any) decides which edit/delete controls render.
    let is_admin = auth::is_admin(&headers);
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let subscription = if let Some(sub) = viewer.as_deref() {
        let current_follow = state.store.thread_follow_level(&thread.id, sub).await?;
        Some(SubscriptionFormVM {
            selected: follow_level(current_follow),
            submit: form_action(
                format!("/t/{}/subscribe", thread.id),
                ActionKind::UpdateSubscription,
                csrf.clone(),
                Vec::new(),
            ),
        })
    } else {
        None
    };
    let quote_target = match q.quote.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(pid) => state
            .store
            .get_post(pid)
            .await?
            .filter(|p| p.thread_id == thread.id),
        None => None,
    };

    // Admin moderation toolbar (lock/pin/move/delete) — only for admins. The move dropdown
    // needs the full category list, fetched only on the admin path.
    let admin = if is_admin {
        let categories = state.store.list_categories().await?;
        Some(AdminThreadToolbarVM {
            move_thread: Some(MoveThreadFormVM {
                selected_category: Opaque(thread.category_id.clone()),
                categories: categories
                    .iter()
                    .map(crate::handlers::category_ref)
                    .collect(),
                submit: form_action(
                    format!("/admin/threads/{}/move", thread.id),
                    ActionKind::MoveThread,
                    csrf.clone(),
                    Vec::new(),
                ),
            }),
            lock: Some(form_action(
                format!("/admin/threads/{}/lock", thread.id),
                if thread.locked {
                    ActionKind::Unlock
                } else {
                    ActionKind::Lock
                },
                csrf.clone(),
                vec![hidden_field(
                    "state",
                    if thread.locked { "unlocked" } else { "locked" },
                )],
            )),
            pin: Some(form_action(
                format!("/admin/threads/{}/pin", thread.id),
                if thread.pinned {
                    ActionKind::Unpin
                } else {
                    ActionKind::Pin
                },
                csrf.clone(),
                vec![hidden_field(
                    "state",
                    if thread.pinned { "unpinned" } else { "pinned" },
                )],
            )),
            delete_review: Some(link_action(
                format!("/admin/threads/{}/delete", thread.id),
                ActionKind::DeleteAdminReview,
            )),
        })
    } else {
        None
    };

    let can_manage_answer = viewer.as_deref() == Some(thread.author_sub.as_str()) || is_admin;
    // Display order: the original post stays first, then the accepted reply (if any), then the
    // rest in their natural oldest-first order. Reordering a clone never touches storage.
    let ordered = order_posts_accepted_first(&posts, &valid_accepted_id);
    let first_unread_id = reading_state
        .as_ref()
        .and_then(|reading| reading.first_unread.as_ref())
        .map(|post| post.id.as_str());
    let quoted_posts = load_quoted_posts(&state, &thread.id, &ordered).await?;

    // Per-post reaction aggregates (counts + whether THIS viewer reacted), keyed by post id.
    let mut reactions: HashMap<String, Vec<ReactionCount>> = HashMap::new();
    for p in &ordered {
        let counts = state
            .store
            .reactions_for_post(&p.id, viewer.as_deref())
            .await?;
        reactions.insert(p.id.clone(), counts);
    }
    // One bounded owner-scoped lookup for the whole visible post page. Bookmark state must never
    // add another per-post query beside the legacy reaction aggregation.
    let bookmarks: HashMap<String, Bookmark> = if let Some(subject) = viewer.as_deref() {
        let post_ids: Vec<String> = ordered.iter().map(|post| post.id.clone()).collect();
        state
            .store
            .bookmarks_for_posts(subject, &post_ids)
            .await?
            .into_iter()
            .map(|bookmark| (bookmark.post_id.clone(), bookmark))
            .collect()
    } else {
        HashMap::new()
    };

    let projection = ThreadPostProjection {
        viewer: viewer.as_deref(),
        is_admin,
        thread_id: &thread.id,
        csrf: &csrf,
        accepted_post_id: &valid_accepted_id,
        can_manage_answer,
        is_question,
        can_reply: !thread.locked && !viewer_banned,
        can_post: !viewer_banned,
        first_unread_post_id: first_unread_id,
        reactions: &reactions,
        bookmarks: &bookmarks,
        quoted_posts: &quoted_posts,
        now,
    };
    let projected = ordered
        .iter()
        .enumerate()
        .map(|(index, post)| project_post(post, index == 0, &projection))
        .collect::<Vec<_>>();
    let op = projected
        .first()
        .cloned()
        .ok_or_else(|| AppError::Internal("thread is missing its original post".to_string()))?;
    let dais = projected
        .iter()
        .find(|post| post.id.0 == valid_accepted_id)
        .cloned()
        .map(|post| AnswerDaisVM {
            post,
            acceptance: AcceptanceMeaning::AcceptedByAskerOrAuthorizedModerator,
        });
    let replies = projected
        .into_iter()
        .filter(|post| !post.is_op && post.id.0 != valid_accepted_id)
        .collect::<Vec<_>>();
    let owner = viewer.as_deref() == Some(thread.author_sub.as_str());
    let viewer_state = ThreadViewerState {
        subscription,
        edit: owner.then(|| link_action(format!("/t/{}/edit", thread.id), ActionKind::EditThread)),
        delete_review: owner.then(|| {
            link_action(
                format!("/t/{}/delete", thread.id),
                ActionKind::DeleteThreadReview,
            )
        }),
        clear_invalid_solution: (can_manage_answer
            && !thread.accepted_post_id.trim().is_empty()
            && valid_accepted_id.is_empty())
        .then(|| {
            form_action(
                format!("/t/{}/accept", thread.id),
                ActionKind::ClearInvalidSolution,
                csrf.clone(),
                vec![
                    hidden_field("action", "clear"),
                    hidden_field("post_id", thread.accepted_post_id.clone()),
                ],
            )
        }),
    };
    let visible_post_ids = ordered
        .iter()
        .map(|post| post.id.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let reading = ReadingProgressVM {
        started: reading_state.as_ref().is_some_and(|state| state.started),
        unread_count: reading_state
            .as_ref()
            .map(|state| state.unread_count.max(0)),
        first_unread_href: reading_state
            .as_ref()
            .and_then(|state| state.first_unread.as_ref())
            .map(|_| Opaque(format!("/t/{}?resume=1#thread-resume", thread.id))),
        resume_href: reading_state
            .as_ref()
            .filter(|state| state.started && state.unread_count > 0 && state.first_unread.is_some())
            .map(|_| Opaque(format!("/t/{}?resume=1#thread-resume", thread.id))),
        mark_page_read: (viewer.is_some()
            && reading_state
                .as_ref()
                .is_some_and(|state| state.unread_count > 0)
            && !visible_post_ids.is_empty())
        .then(|| {
            form_action(
                format!("/t/{}/read", thread.id),
                ActionKind::MarkThreadPageRead,
                csrf.clone(),
                vec![hidden_field("post_ids", visible_post_ids)],
            )
        }),
    };
    let reply_form = if viewer_banned {
        ReplyFormVM::UnavailableNotice {
            heading: Text("Posting unavailable".to_string()),
            message: Text(
                "Your account is blocked from creating replies or reactions.".to_string(),
            ),
        }
    } else if thread.locked {
        ReplyFormVM::LockedNotice {
            message: Text("No new replies can be posted while this thread is locked.".to_string()),
        }
    } else {
        ReplyFormVM::Available {
            submit: form_action(
                format!("/t/{}/reply", thread.id),
                if is_question {
                    ActionKind::PostAnswer
                } else {
                    ActionKind::PostReply
                },
                csrf.clone(),
                Vec::new(),
            ),
            body: Text(String::new()),
            quoted_post_id: quote_target.map(|post| Opaque(post.id)),
        }
    };
    let counts = personal_counts(&state, &headers, now).await?;
    let view = ThreadView {
        chrome: page_chrome(thread.title.clone(), &headers, NavTab::Home, counts),
        shared: ThreadShared {
            id: Opaque(thread.id.clone()),
            title: Text(thread.title.clone()),
            category: category.as_ref().map(crate::handlers::category_ref),
            kind: category
                .as_ref()
                .map(|category| thread_kind(category.format))
                .unwrap_or(crate::view_model::ThreadKind::Discussion),
            answer_state: if is_question {
                if valid_accepted_id.is_empty() {
                    AnswerState::NeedsAnswer
                } else {
                    AnswerState::Answered
                }
            } else {
                AnswerState::NotApplicable
            },
            author_display: Text(thread.author_email.clone()),
            created_at: thread.created_at,
            post_count: Some(post_count),
            pinned: thread.pinned,
            locked: thread.locked,
        },
        viewer: viewer_state,
        op,
        dais,
        replies,
        pagination,
        reply_form,
        summary: summary_state(&posts),
        reading,
        admin,
        now,
    };
    Ok(html_response(
        crate::views::forum::thread(&view),
        set_cookie,
    ))
}

#[derive(Debug, Deserialize)]
pub struct ThreadReadForm {
    #[serde(default)]
    pub csrf: String,
    /// Comma-separated stable post ids rendered by the server for this bounded page.
    #[serde(default)]
    pub post_ids: String,
}

/// `POST /t/{id}/read` — subject-scoped, idempotent page receipt. A normal form follows the
/// earliest remaining unread post; the IntersectionObserver enhancement asks for a 204 and keeps
/// the current page in place. GET / resume never mutates reading state.
pub async fn mark_thread_read(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<ThreadReadForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let identity = auth::require_author(&headers)?;
    let post_ids: Vec<String> = form
        .post_ids
        .split(',')
        .map(str::trim)
        .filter(|post_id| !post_id.is_empty())
        .map(str::to_string)
        .collect();
    state
        .store
        .mark_thread_posts_read(&identity.sub, &id, &post_ids, now_secs())
        .await?;
    if wants_json(&headers) {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    let reading = state.store.thread_reading_state(&identity.sub, &id).await?;
    if reading.unread_count > 0 && reading.first_unread.is_some() {
        Ok(redirect_to(&format!("/t/{}?resume=1#thread-resume", id)))
    } else {
        Ok(redirect_to(&format!("/t/{}?latest=1#thread-latest", id)))
    }
}

// ===========================================================================
// GET /new?cat= — new-thread form
// ===========================================================================

#[derive(Debug, Deserialize, Default)]
pub struct NewQuery {
    #[serde(default)]
    pub cat: Option<String>,
}

pub async fn new_form(
    State(state): State<AppState>,
    Query(q): Query<NewQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let now = now_secs();
    if let Some(subject) = auth::identity_subject(&headers) {
        if state.store.is_banned(&subject).await? {
            return Err(AppError::Forbidden(
                "your account is blocked from posting".to_string(),
            ));
        }
    }
    let categories = state.store.list_categories().await?;
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let requested = q.cat.unwrap_or_default();
    let selected_category = categories
        .iter()
        .find(|category| category.id == requested)
        .or_else(|| categories.first());
    let selected = selected_category
        .map(|category| category.id.as_str())
        .unwrap_or_default();
    let is_question = selected_category
        .map(|category| category.format.is_question())
        .unwrap_or(false);
    let heading = if is_question {
        "Ask a question"
    } else {
        "New thread"
    };
    let counts = personal_counts(&state, &headers, now).await?;
    let view = ComposeView {
        chrome: page_chrome(heading, &headers, NavTab::New, counts),
        shared: ComposeShared {
            mode: ComposeMode::NewThread,
            heading: Text(heading.to_string()),
            categories: categories.iter().map(category_vm).collect(),
            selected_category: (!selected.is_empty()).then(|| Opaque(selected.to_string())),
            thread_kind: selected_category.map(|category| thread_kind(category.format)),
        },
        viewer: ComposeViewerState {
            title: Text(String::new()),
            body: Text(String::new()),
            quoted_post_id: None,
            submit: form_action("/new", ActionKind::PublishThread, csrf, Vec::new()),
            cancel_href: Opaque("/".to_string()),
        },
    };
    Ok(html_response(
        crate::views::forum::compose(&view),
        set_cookie,
    ))
}

// ===========================================================================
// POST /new — create a thread
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct NewThreadForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub body: String,
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<NewThreadForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let author = auth::require_author(&headers)?;
    if state.store.is_banned(&author.sub).await? {
        return Err(AppError::Forbidden(
            "your account is blocked from posting".to_string(),
        ));
    }

    let title = form.title.trim();
    if title.is_empty() {
        return Err(AppError::InvalidRequest(
            "thread title is required".to_string(),
        ));
    }
    if title.chars().count() > MAX_TITLE {
        return Err(AppError::InvalidRequest(
            "thread title is too long".to_string(),
        ));
    }
    let category_id = form.category.trim();
    if state.store.get_category(category_id).await?.is_none() {
        return Err(AppError::InvalidRequest("unknown category".to_string()));
    }
    let body = form.body.trim();
    if body.is_empty() {
        return Err(AppError::InvalidRequest(
            "post body is required".to_string(),
        ));
    }
    if body.chars().count() > MAX_BODY {
        return Err(AppError::InvalidRequest(
            "post body is too long".to_string(),
        ));
    }

    let now = now_secs();
    let thread = Thread {
        id: new_id("t"),
        category_id: category_id.to_string(),
        title: title.to_string(),
        author_sub: author.sub.clone(),
        author_email: author.email.clone(),
        created_at: now,
        last_at: now,
        locked: false,
        pinned: false,
        accepted_post_id: String::new(),
    };
    let first_post = Post {
        id: new_id("p"),
        thread_id: thread.id.clone(),
        body_md: body.to_string(),
        quoted_post_id: String::new(),
        author_sub: author.sub,
        author_email: author.email,
        created_at: now,
    };
    let mentions = extract_mentions(&first_post.body_md);
    state
        .store
        .create_thread_with_activity(&thread, &first_post, &mentions, &new_id("a"))
        .await?;
    tracing::info!(
        thread = thread.id,
        author = thread.author_email,
        "thread created"
    );

    let actor = if thread.author_email.is_empty() {
        &thread.author_sub
    } else {
        &thread.author_email
    };
    state.audit.emit(AuditEvent::info(
        "thread.create",
        actor,
        &thread.id,
        &thread.category_id,
    ));

    Ok(redirect_to(&format!("/t/{}", thread.id)))
}

// ===========================================================================
// POST /t/{id}/reply — post a reply
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct ReplyForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub quote_post_id: String,
    #[serde(default)]
    pub body: String,
}

pub async fn reply(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<ReplyForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let author = auth::require_author(&headers)?;
    if state.store.is_banned(&author.sub).await? {
        return Err(AppError::Forbidden(
            "your account is blocked from posting".to_string(),
        ));
    }

    let thread = state
        .store
        .get_thread(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("thread not found".to_string()))?;
    if thread.locked {
        return Err(AppError::Forbidden(
            "this thread is locked — no new replies".to_string(),
        ));
    }
    let body = form.body.trim();
    if body.is_empty() {
        return Err(AppError::InvalidRequest(
            "reply body is required".to_string(),
        ));
    }
    if body.chars().count() > MAX_BODY {
        return Err(AppError::InvalidRequest(
            "reply body is too long".to_string(),
        ));
    }
    let quoted_post = match form.quote_post_id.trim().is_empty() {
        true => None,
        false => {
            let quoted = state
                .store
                .get_post(form.quote_post_id.trim())
                .await?
                .filter(|p| p.thread_id == id)
                .ok_or_else(|| {
                    AppError::InvalidRequest("quoted post must belong to this thread".to_string())
                })?;
            Some(quoted)
        }
    };
    let quoted_post_id = quoted_post
        .as_ref()
        .map(|p| p.id.clone())
        .unwrap_or_default();

    let now = now_secs();
    let post = Post {
        id: new_id("p"),
        thread_id: id.clone(),
        body_md: body.to_string(),
        quoted_post_id,
        author_sub: author.sub,
        author_email: author.email,
        created_at: now,
    };
    let mentions = extract_mentions(&post.body_md);
    let activity = state
        .store
        .add_reply_with_activity(&post, &mentions, &new_id("a"))
        .await?;
    tracing::info!(thread = id, author = post.author_email, "reply posted");

    let actor = if post.author_email.is_empty() {
        &post.author_sub
    } else {
        &post.author_email
    };
    state
        .audit
        .emit(AuditEvent::info("reply.create", actor, &post.id, &id));
    notify_reply(&state, &thread, &post, &activity.delivery_subjects);

    Ok(redirect_to(&format!("/t/{id}")))
}

// ===========================================================================
// GET/POST /t/{id}/edit — edit one's OWN thread (title + original-post body)
// ===========================================================================

/// Form body for editing a thread: title + original-post body. Identity is NEVER read from the
/// form — only from the gateway headers.
#[derive(Debug, Deserialize)]
pub struct EditThreadForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub body: String,
}

/// Commit body for a destructive action. The server-issued confirmation proves that the same
/// actor and CSRF session visited the consequence review before this POST.
#[derive(Debug, Deserialize)]
pub struct DeleteForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub confirm: String,
}

fn thread_delete_action(id: &str) -> String {
    format!("thread.delete:{id}")
}

fn reply_delete_action(thread_id: &str, post_id: &str) -> String {
    format!("reply.delete:{thread_id}:{post_id}")
}

/// Build the shared no-JS destructive-action review through the typed presentation seam.
/// Authorization, consequence selection, CSRF minting and confirmation minting stay here.
pub(crate) fn render_destructive_review(
    heading: &str,
    consequence: &str,
    action: &str,
    csrf: &str,
    confirm: &str,
    cancel_href: &str,
) -> String {
    crate::views::shell::destructive_review(&DestructiveReviewVM {
        heading: Text(heading.to_string()),
        consequence: ConsequenceVM {
            summary: Text(consequence.to_string()),
            detail: None,
        },
        commit: form_action(
            action,
            ActionKind::DeleteConfirm,
            csrf,
            vec![hidden_field("confirm", confirm)],
        ),
        cancel_href: Opaque(cancel_href.to_string()),
    })
}

pub async fn edit_thread_form(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let now = now_secs();
    let author = auth::require_author(&headers)?;
    let thread = state
        .store
        .get_thread(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("thread not found".to_string()))?;
    if thread.author_sub != author.sub {
        return Err(AppError::Forbidden(
            "you can only edit your own threads".to_string(),
        ));
    }
    let posts = state.store.posts_in_thread(&id).await?;
    let op_body = posts.first().map(|p| p.body_md.as_str()).unwrap_or("");
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    let counts = personal_counts(&state, &headers, now).await?;
    let view = ComposeView {
        chrome: page_chrome("Edit thread", &headers, NavTab::Home, counts),
        shared: ComposeShared {
            mode: ComposeMode::EditThread,
            heading: Text("Edit thread".to_string()),
            categories: Vec::new(),
            selected_category: Some(Opaque(thread.category_id.clone())),
            thread_kind: None,
        },
        viewer: ComposeViewerState {
            title: Text(thread.title.clone()),
            body: Text(op_body.to_string()),
            quoted_post_id: None,
            submit: form_action(
                format!("/t/{}/edit", thread.id),
                ActionKind::SaveThread,
                csrf,
                Vec::new(),
            ),
            cancel_href: Opaque(format!("/t/{}", thread.id)),
        },
    };
    Ok(html_response(
        crate::views::forum::compose(&view),
        set_cookie,
    ))
}

pub async fn update_thread(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<EditThreadForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let author = auth::require_author(&headers)?;

    let thread = state
        .store
        .get_thread(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("thread not found".to_string()))?;
    if thread.author_sub != author.sub {
        return Err(AppError::Forbidden(
            "you can only edit your own threads".to_string(),
        ));
    }

    let title = form.title.trim();
    if title.is_empty() {
        return Err(AppError::InvalidRequest(
            "thread title is required".to_string(),
        ));
    }
    if title.chars().count() > MAX_TITLE {
        return Err(AppError::InvalidRequest(
            "thread title is too long".to_string(),
        ));
    }
    let body = form.body.trim();
    if body.is_empty() {
        return Err(AppError::InvalidRequest(
            "post body is required".to_string(),
        ));
    }
    if body.chars().count() > MAX_BODY {
        return Err(AppError::InvalidRequest(
            "post body is too long".to_string(),
        ));
    }

    // Resolve the stable OP identity; never infer it from second-granularity timestamps.
    let op_id = state
        .store
        .first_post_in_thread(&id)
        .await?
        .map(|post| post.id)
        .ok_or_else(|| AppError::NotFound("thread has no original post".to_string()))?;

    state.store.update_thread(&id, title, &op_id, body).await?;
    state
        .store
        .replace_mentions(&op_id, &id, &extract_mentions(body), now_secs())
        .await?;
    tracing::info!(thread = id, author = thread.author_email, "thread updated");

    let actor = if thread.author_email.is_empty() {
        &thread.author_sub
    } else {
        &thread.author_email
    };
    state.audit.emit(AuditEvent::info(
        "thread.update",
        actor,
        &thread.id,
        &thread.category_id,
    ));

    Ok(redirect_to(&format!("/t/{id}")))
}

pub async fn delete_thread_review(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let author = auth::require_author(&headers)?;
    let thread = state
        .store
        .get_thread(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("thread not found".to_string()))?;
    if thread.author_sub != author.sub {
        return Err(AppError::Forbidden(
            "you can only delete your own threads".to_string(),
        ));
    }
    let reply_count = state.store.count_posts(&id).await?.saturating_sub(1);

    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let action_key = thread_delete_action(&id);
    let confirm = auth::new_destructive_confirmation(
        state.config.destructive_confirmation_key(),
        &csrf,
        &action_key,
        &author.sub,
    );
    let content = render_destructive_review(
        "Delete thread?",
        &format!(
            "The thread “{}” and its {} {} will be permanently deleted.",
            thread.title,
            reply_count,
            if reply_count == 1 { "reply" } else { "replies" }
        ),
        &format!("/t/{id}/delete"),
        &csrf,
        &confirm,
        &format!("/t/{id}"),
    );
    let counts = personal_counts(&state, &headers, now_secs()).await?;
    let chrome = page_chrome("Review thread deletion", &headers, NavTab::Home, counts);
    let html = crate::views::shell::page(&chrome, &content);
    Ok(html_response(html, set_cookie))
}

pub async fn delete_thread(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<DeleteForm>,
) -> Result<Response, AppError> {
    let author = auth::require_author(&headers)?;

    let thread = state
        .store
        .get_thread(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("thread not found".to_string()))?;
    if thread.author_sub != author.sub {
        return Err(AppError::Forbidden(
            "you can only delete your own threads".to_string(),
        ));
    }
    auth::consume_destructive_confirmation(
        state.config.destructive_confirmation_key(),
        &headers,
        &form.csrf,
        &form.confirm,
        &thread_delete_action(&id),
        &author.sub,
    )?;

    state.store.delete_thread(&id).await?;
    tracing::info!(thread = id, author = thread.author_email, "thread deleted");

    let actor = if thread.author_email.is_empty() {
        &thread.author_sub
    } else {
        &thread.author_email
    };
    state.audit.emit(AuditEvent::notice(
        "thread.delete",
        actor,
        &thread.id,
        &thread.category_id,
    ));

    // Bounce back to the thread's category (or home if it is gone).
    Ok(redirect_to(&format!("/c/{}", thread.category_id)))
}

// ===========================================================================
// GET/POST /t/{tid}/p/{pid}/edit + POST /t/{tid}/p/{pid}/delete — one's OWN reply
// ===========================================================================

/// Form body for editing a reply: just the body. Identity comes from the gateway headers.
#[derive(Debug, Deserialize)]
pub struct EditReplyForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub body: String,
}

/// Resolve a reply for an author-gated mutation. Loads the thread's posts, rejects when the post
/// is missing / not in this thread (404), is the ORIGINAL post (that is edited/deleted via the
/// thread controls, which also keep the denormalised `first_body_md` in step — 403), or is not
/// authored by `author_sub` (403). Returns the target post on success.
fn locate_own_reply(posts: &[Post], pid: &str, author_sub: &str) -> Result<Post, AppError> {
    if posts.first().map(|p| p.id == pid).unwrap_or(false) {
        return Err(AppError::Forbidden(
            "the original post is edited or deleted via the thread itself".to_string(),
        ));
    }
    let post = posts
        .iter()
        .find(|p| p.id == pid)
        .ok_or_else(|| AppError::NotFound("reply not found".to_string()))?;
    if post.author_sub != author_sub {
        return Err(AppError::Forbidden(
            "you can only edit your own replies".to_string(),
        ));
    }
    Ok(post.clone())
}

pub async fn edit_reply_form(
    State(state): State<AppState>,
    Path((tid, pid)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let now = now_secs();
    let author = auth::require_author(&headers)?;
    let posts = state.store.posts_in_thread(&tid).await?;
    let post = locate_own_reply(&posts, &pid, &author.sub)?;
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    let counts = personal_counts(&state, &headers, now).await?;
    let view = ComposeView {
        chrome: page_chrome("Edit reply", &headers, NavTab::Home, counts),
        shared: ComposeShared {
            mode: ComposeMode::EditReply,
            heading: Text("Edit reply".to_string()),
            categories: Vec::new(),
            selected_category: None,
            thread_kind: None,
        },
        viewer: ComposeViewerState {
            title: Text(String::new()),
            body: Text(post.body_md),
            quoted_post_id: None,
            submit: form_action(
                format!("/t/{tid}/p/{pid}/edit"),
                ActionKind::SaveReply,
                csrf,
                Vec::new(),
            ),
            cancel_href: Opaque(format!("/t/{tid}")),
        },
    };
    Ok(html_response(
        crate::views::forum::compose(&view),
        set_cookie,
    ))
}

pub async fn update_reply(
    State(state): State<AppState>,
    Path((tid, pid)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<EditReplyForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let author = auth::require_author(&headers)?;

    let posts = state.store.posts_in_thread(&tid).await?;
    let post = locate_own_reply(&posts, &pid, &author.sub)?;

    let body = form.body.trim();
    if body.is_empty() {
        return Err(AppError::InvalidRequest(
            "reply body is required".to_string(),
        ));
    }
    if body.chars().count() > MAX_BODY {
        return Err(AppError::InvalidRequest(
            "reply body is too long".to_string(),
        ));
    }

    state.store.update_post(&pid, body).await?;
    state
        .store
        .replace_mentions(&pid, &tid, &extract_mentions(body), now_secs())
        .await?;
    tracing::info!(thread = tid, post = pid, "reply updated");

    let actor = if post.author_email.is_empty() {
        &post.author_sub
    } else {
        &post.author_email
    };
    state
        .audit
        .emit(AuditEvent::info("reply.update", actor, &pid, &tid));

    Ok(redirect_to(&format!("/t/{tid}")))
}

pub async fn delete_reply_review(
    State(state): State<AppState>,
    Path((tid, pid)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let author = auth::require_author(&headers)?;
    let posts = state.store.posts_in_thread(&tid).await?;
    let post = locate_own_reply(&posts, &pid, &author.sub)?;

    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let action_key = reply_delete_action(&tid, &pid);
    let confirm = auth::new_destructive_confirmation(
        state.config.destructive_confirmation_key(),
        &csrf,
        &action_key,
        &author.sub,
    );
    let content = render_destructive_review(
        "Delete reply?",
        &format!(
            "Your reply by {} will be permanently removed from this thread.",
            post.author_email
        ),
        &format!("/t/{tid}/p/{pid}/delete"),
        &csrf,
        &confirm,
        &format!("/t/{tid}"),
    );
    let counts = personal_counts(&state, &headers, now_secs()).await?;
    let chrome = page_chrome("Review reply deletion", &headers, NavTab::Home, counts);
    let html = crate::views::shell::page(&chrome, &content);
    Ok(html_response(html, set_cookie))
}

pub async fn delete_reply(
    State(state): State<AppState>,
    Path((tid, pid)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<DeleteForm>,
) -> Result<Response, AppError> {
    let author = auth::require_author(&headers)?;

    let posts = state.store.posts_in_thread(&tid).await?;
    let post = locate_own_reply(&posts, &pid, &author.sub)?;
    auth::consume_destructive_confirmation(
        state.config.destructive_confirmation_key(),
        &headers,
        &form.csrf,
        &form.confirm,
        &reply_delete_action(&tid, &pid),
        &author.sub,
    )?;

    state.store.delete_post(&pid).await?;
    tracing::info!(thread = tid, post = pid, "reply deleted");

    let actor = if post.author_email.is_empty() {
        &post.author_sub
    } else {
        &post.author_email
    };
    state
        .audit
        .emit(AuditEvent::notice("reply.delete", actor, &pid, &tid));

    Ok(redirect_to(&format!("/t/{tid}")))
}

// ===========================================================================
// POST /t/{tid}/p/{pid}/react — toggle a reaction on a post
// ===========================================================================

/// Form body for a reaction toggle: the CSRF token + the reaction `kind`. Identity (the reactor)
/// comes from the gateway headers, never the form.
#[derive(Debug, Deserialize)]
pub struct ReactForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub kind: String,
}

pub async fn react(
    State(state): State<AppState>,
    Path((tid, pid)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<ReactForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let author = auth::require_author(&headers)?;
    if state.store.is_banned(&author.sub).await? {
        return Err(AppError::Forbidden(
            "your account is blocked from posting".to_string(),
        ));
    }

    let kind = form.kind.trim();
    if !is_reaction_kind(kind) {
        return Err(AppError::InvalidRequest(
            "unknown reaction kind".to_string(),
        ));
    }

    // The post must exist AND belong to this thread (guards cross-thread id spoofing).
    let post = state
        .store
        .get_post(&pid)
        .await?
        .filter(|p| p.thread_id == tid)
        .ok_or_else(|| AppError::NotFound("post not found".to_string()))?;

    let on = state
        .store
        .toggle_reaction(&post.id, &author.sub, kind, now_secs())
        .await?;
    tracing::info!(thread = tid, post = pid, kind, on, "reaction toggled");

    let actor = if author.email.is_empty() {
        &author.sub
    } else {
        &author.email
    };
    state.audit.emit(AuditEvent::info(
        "reaction.toggle",
        actor,
        &pid,
        if on { kind } else { "off" },
    ));

    if wants_json(&headers) {
        let count = state
            .store
            .reactions_for_post(&post.id, Some(&author.sub))
            .await?
            .into_iter()
            .find(|c| c.kind == kind)
            .map(|c| c.count)
            .unwrap_or(0);
        return Ok(axum::Json(serde_json::json!({
            "ok": true,
            "post_id": pid,
            "kind": kind,
            "on": on,
            "count": count,
        }))
        .into_response());
    }

    Ok(redirect_to(&format!("/t/{tid}")))
}

// ===========================================================================
// POST /t/{tid}/accept — explicitly accept or clear the accepted answer
// ===========================================================================

/// Explicit accepted-answer command. Both actions bind to `post_id`; a stale clear can never
/// remove a newer accepted answer selected after the form was rendered.
#[derive(Debug, Deserialize)]
pub struct AcceptForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub post_id: String,
}

pub async fn accept_answer(
    State(state): State<AppState>,
    Path(tid): Path<String>,
    headers: HeaderMap,
    Form(form): Form<AcceptForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let author = auth::require_author(&headers)?;

    let thread = state
        .store
        .get_thread(&tid)
        .await?
        .ok_or_else(|| AppError::NotFound("thread not found".to_string()))?;

    // Gate: only the thread author or an admin may mark an accepted answer.
    if thread.author_sub != author.sub && !auth::is_admin(&headers) {
        return Err(AppError::Forbidden(
            "only the thread author or an admin can mark the accepted answer".to_string(),
        ));
    }

    let action = match form.action.trim() {
        "accept" => AcceptedAnswerAction::Accept {
            post_id: form.post_id.trim().to_string(),
        },
        "clear" => AcceptedAnswerAction::ClearIf {
            post_id: form.post_id.trim().to_string(),
        },
        _ => {
            return Err(AppError::InvalidRequest(
                "answer action must be accept or clear".to_string(),
            ));
        }
    };
    let mutation = state
        .store
        .mutate_accepted_answer_with_activity(&tid, action, &new_id("a"), &author.sub, now_secs())
        .await?;
    let new_accepted = mutation.thread.accepted_post_id.as_str();
    tracing::info!(
        thread = tid,
        accepted = new_accepted,
        changed = mutation.changed,
        "accepted answer command applied"
    );

    let actor = if author.email.is_empty() {
        &author.sub
    } else {
        &author.email
    };
    state.audit.emit(AuditEvent::notice(
        "thread.accept",
        actor,
        &tid,
        if new_accepted.is_empty() {
            "cleared"
        } else {
            new_accepted
        },
    ));
    if mutation.changed {
        if let Some(target_post) = mutation.accepted_post.as_ref() {
            notify_accepted_answer(
                &state,
                &mutation.thread,
                target_post,
                &author.sub,
                &author.email,
            );
        }
    }

    if wants_json(&headers) {
        return Ok(axum::Json(serde_json::json!({
            "ok": true,
            "thread_id": tid,
            "accepted_post_id": new_accepted,
        }))
        .into_response());
    }

    Ok(redirect_to(&format!("/t/{tid}")))
}

// ===========================================================================
// POST /t/{id}/subscribe — explicitly set a result-oriented thread preference
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct SubscribeForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub level: String,
    /// Backwards-compatible JSON/form seam for clients from the boolean subscription release.
    #[serde(default)]
    pub action: String,
}

pub async fn toggle_subscription(
    State(state): State<AppState>,
    Path(tid): Path<String>,
    headers: HeaderMap,
    Form(form): Form<SubscribeForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let author = auth::require_author(&headers)?;
    state
        .store
        .get_thread(&tid)
        .await?
        .ok_or_else(|| AppError::NotFound("thread not found".to_string()))?;

    let follow_level = if form.level.trim().is_empty() {
        match form.action.trim() {
            "follow" => ThreadFollowLevel::Watch,
            "unfollow" => ThreadFollowLevel::None,
            _ => {
                return Err(AppError::InvalidRequest(
                    "thread preference must be watch, follow, mute, or none".to_string(),
                ));
            }
        }
    } else {
        ThreadFollowLevel::parse(&form.level).ok_or_else(|| {
            AppError::InvalidRequest(
                "thread preference must be watch, follow, mute, or none".to_string(),
            )
        })?
    };
    state
        .store
        .set_thread_follow_level(&tid, &author.sub, follow_level, now_secs())
        .await?;
    let actor = if author.email.is_empty() {
        &author.sub
    } else {
        &author.email
    };
    state.audit.emit(AuditEvent::info(
        "thread.follow_preference",
        actor,
        &tid,
        follow_level.as_str(),
    ));

    if wants_json(&headers) {
        return Ok(axum::Json(serde_json::json!({
            "ok": true,
            "thread_id": tid,
            "follow_level": follow_level.as_str(),
            "subscribed": follow_level.appears_in_personal_feeds(),
        }))
        .into_response());
    }

    Ok(redirect_to(&format!("/t/{tid}")))
}

// ===========================================================================
// Render helpers
// ===========================================================================

fn subscribed_subject<'a>(q: &ThreadListQuery, viewer_sub: Option<&'a str>) -> Option<&'a str> {
    if q.subscribed_only() {
        viewer_sub
    } else {
        None
    }
}

fn list_href_raw(action: &str, sort: &str, status: Option<&str>, subscribed: bool) -> String {
    let mut params = vec![format!("sort={sort}")];
    if let Some(status) = status {
        params.push(format!("status={status}"));
    }
    if subscribed {
        params.push("filter=subscribed".to_string());
    }
    format!("{action}?{}", params.join("&"))
}

async fn load_quoted_posts(
    state: &AppState,
    thread_id: &str,
    posts: &[Post],
) -> Result<HashMap<String, Post>, AppError> {
    let mut out = HashMap::new();
    let mut seen = HashSet::new();
    for p in posts {
        if p.quoted_post_id.is_empty() || !seen.insert(p.quoted_post_id.as_str()) {
            continue;
        }
        if let Some(quoted) = state
            .store
            .get_post(&p.quoted_post_id)
            .await?
            .filter(|qp| qp.thread_id == thread_id)
        {
            out.insert(quoted.id.clone(), quoted);
        }
    }
    Ok(out)
}

fn extract_mentions(body: &str) -> Vec<String> {
    let bytes = body.as_bytes();
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'@' || (i > 0 && is_mention_char(bytes[i - 1])) {
            i += 1;
            continue;
        }
        let start = i + 1;
        let mut end = start;
        while end < bytes.len() && is_mention_char(bytes[end]) {
            end += 1;
        }
        while end > start && matches!(bytes[end - 1], b'.' | b'-' | b'_') {
            end -= 1;
        }
        if end > start {
            if let Some(name) = normalize_mention_name(&body[start..end]) {
                if seen.insert(name.clone()) {
                    out.push(name);
                }
            }
        }
        i = end.max(start);
    }
    out
}

fn notify_reply(state: &AppState, thread: &Thread, post: &Post, recipient_subjects: &[String]) {
    let Some(klaxon) = &state.klaxon else {
        return;
    };

    let actor = post_author_label(post);
    let title = format!("{actor} 回复了「{}」", truncate_chars(&thread.title, 80));
    let body = compact_snippet(&post.body_md, 180);
    let url = forum_thread_url(&thread.id);
    for recipient_sub in recipient_subjects
        .iter()
        .take(MAX_KLAXON_RECIPIENTS_PER_REPLY)
    {
        klaxon.notify("agora", recipient_sub, &title, &body, &url);
    }
}

fn notify_accepted_answer(
    state: &AppState,
    thread: &Thread,
    accepted_post: &Post,
    actor_sub: &str,
    actor_email: &str,
) {
    if accepted_post.author_sub == actor_sub {
        return;
    }
    let Some(klaxon) = &state.klaxon else {
        return;
    };

    let actor = author_label(actor_sub, actor_email);
    let title = format!("{actor} 采纳了你的回答");
    let body = truncate_chars(&thread.title, 180);
    let url = forum_thread_url(&thread.id);
    klaxon.notify("agora", &accepted_post.author_sub, &title, &body, &url);
}

fn post_author_label(post: &Post) -> &str {
    author_label(&post.author_sub, &post.author_email)
}

fn author_label<'a>(sub: &'a str, email: &'a str) -> &'a str {
    if email.trim().is_empty() {
        sub
    } else {
        email
    }
}

fn forum_thread_url(thread_id: &str) -> String {
    format!("https://forum.w33d.xyz/t/{thread_id}")
}

fn compact_snippet(s: &str, max_chars: usize) -> String {
    let compact = s.split_whitespace().collect::<Vec<_>>().join(" ");
    truncate_chars(&compact, max_chars)
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    let mut chars = s.chars();
    let mut out: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        out.push_str("...");
    }
    out
}

fn normalize_mention_name(raw: &str) -> Option<String> {
    crate::store::normalize_activity_alias(raw)
}

fn is_mention_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')
}

async fn load_reading_states(
    state: &AppState,
    viewer_sub: Option<&str>,
    threads: &[Thread],
) -> Result<HashMap<String, ThreadReadingState>, AppError> {
    let Some(viewer_sub) = viewer_sub else {
        return Ok(HashMap::new());
    };
    let thread_ids: Vec<String> = threads.iter().map(|thread| thread.id.clone()).collect();
    state
        .store
        .thread_reading_states(viewer_sub, &thread_ids)
        .await
        .map_err(Into::into)
}

/// Reorder a thread's posts for display: keep the original post (oldest, index 0) first, then
/// float the accepted reply (if `accepted_post_id` names one that exists and is NOT the OP) to
/// the second slot, leaving the remaining replies in their natural order. Returns a fresh
/// `Vec<Post>` — the stored order is never mutated.
pub(crate) fn order_posts_accepted_first(posts: &[Post], accepted_post_id: &str) -> Vec<Post> {
    let mut ordered: Vec<Post> = posts.to_vec();
    if accepted_post_id.is_empty() {
        return ordered;
    }
    // Only replies (index >= 1) can be accepted; never move the OP.
    if let Some(pos) = ordered
        .iter()
        .position(|p| p.id == accepted_post_id)
        .filter(|&pos| pos >= 1)
    {
        let accepted = ordered.remove(pos);
        ordered.insert(1, accepted);
    }
    ordered
}

/// Resolve the requested reply page from the query cursors. `latest` wins, then the exact activity
/// target (`around`), then `before`/`after`; malformed cursors fall back to the oldest page.
fn resolve_anchor(q: &ThreadQuery) -> ReplyAnchor {
    if q.latest
        .as_deref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
    {
        return ReplyAnchor::Latest;
    }
    if let Some((ts, id)) = parse_cursor(q.around.as_deref()) {
        return ReplyAnchor::Around(ts, id);
    }
    if let Some((ts, id)) = parse_cursor(q.before.as_deref()) {
        return ReplyAnchor::Before(ts, id);
    }
    if let Some((ts, id)) = parse_cursor(q.after.as_deref()) {
        return ReplyAnchor::After(ts, id);
    }
    ReplyAnchor::First
}

/// Parse a `<created_at>_<id>` keyset cursor. `created_at` is a plain integer that never contains
/// `_`, so we split on the FIRST `_`; the post id (`p_<hex>`) keeps its own underscore intact.
/// Returns `None` for a missing/blank/malformed cursor (which falls back to the default page).
fn parse_cursor(cursor: Option<&str>) -> Option<(i64, String)> {
    let (ts, id) = cursor?.trim().split_once('_')?;
    let ts: i64 = ts.parse().ok()?;
    if id.is_empty() {
        return None;
    }
    Some((ts, id.to_string()))
}

/// Build an `Html` response, attaching a `Set-Cookie` header when a fresh CSRF cookie is due.
pub(crate) fn html_response(html: String, set_cookie: Option<String>) -> Response {
    let mut resp = Html(html).into_response();
    if let Some(cookie) = set_cookie {
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            resp.headers_mut().insert(header::SET_COOKIE, value);
        }
    }
    resp
}

/// A 303 See Other redirect (post/redirect/get).
pub(crate) fn redirect_to(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, location.to_string())],
    )
        .into_response()
}

/// True when the caller (a `fetch()` from the enhanced thread page) asked for a JSON reply via
/// the `Accept` header. A plain form POST (no-JS) never sets this, so it keeps the 303 redirect —
/// the seam that lets the optimistic JSON replies live ALONGSIDE the unchanged form routes.
pub(crate) fn wants_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|a| a.contains("application/json"))
        .unwrap_or(false)
}
