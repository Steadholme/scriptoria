//! HTTP handlers and the typed adapter boundary into pure views.
//!
//! `health` is the unauthenticated liveness probe. Product handlers own authorization, Store
//! orchestration, cache truth and server-issued action descriptors; `crate::views` exclusively
//! owns HTML, shell and presentation.

pub mod activity;
pub mod admin;
pub mod bookmarks;
pub mod forum;
pub mod health;
pub mod insight;
pub mod search;

use axum::http::HeaderMap;

use crate::model::{Category, CategoryFormat, Thread, ThreadFollowLevel};
use crate::store::{ThreadSort, ThreadStatusFilter};
use crate::view_model::{
    ActionKind, AnswerState, CacheClass, CategoryRefVM, CategoryVM, FormActionVM, HiddenField,
    LinkActionVM, NavTab, Opaque, PageChrome, Text, ThreadFollowLevelVM, ThreadKind, ThreadOrder,
    ThreadRowShared, ThreadScope,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct PersonalCounts {
    pub unread_activity: Option<i64>,
    pub due_bookmarks: Option<i64>,
}

pub(crate) fn view_personal_counts(counts: PersonalCounts) -> crate::view_model::PersonalCounts {
    crate::view_model::PersonalCounts {
        unread_activity: counts.unread_activity,
        due_bookmarks: counts.due_bookmarks,
    }
}

pub(crate) fn page_chrome(
    title: impl Into<String>,
    headers: &HeaderMap,
    active_nav: NavTab,
    counts: PersonalCounts,
) -> PageChrome {
    PageChrome {
        title: Text(title.into()),
        viewer_email: crate::auth::identity_email(headers).map(Text),
        active_nav,
        counts: view_personal_counts(counts),
        cache: CacheClass::PrivateNoStore,
    }
}

pub(crate) fn link_action(href: impl Into<String>, label_kind: ActionKind) -> LinkActionVM {
    LinkActionVM {
        href: Opaque(href.into()),
        label_kind,
    }
}

pub(crate) fn hidden_field(name: impl Into<String>, value: impl Into<String>) -> HiddenField {
    HiddenField {
        name: Text(name.into()),
        value: Opaque(value.into()),
    }
}

pub(crate) fn form_action(
    action: impl Into<String>,
    label_kind: ActionKind,
    csrf: impl Into<String>,
    fields: Vec<HiddenField>,
) -> FormActionVM {
    FormActionVM {
        action: Opaque(action.into()),
        label_kind,
        csrf: Opaque(csrf.into()),
        fields,
    }
}

pub(crate) const fn thread_kind(format: CategoryFormat) -> ThreadKind {
    match format {
        CategoryFormat::Discussion => ThreadKind::Discussion,
        CategoryFormat::Question => ThreadKind::Question,
    }
}

pub(crate) const fn thread_order(sort: ThreadSort) -> ThreadOrder {
    match sort {
        ThreadSort::Latest => ThreadOrder::Latest,
        ThreadSort::Top => ThreadOrder::Top,
        ThreadSort::Hot => ThreadOrder::Hot,
    }
}

pub(crate) const fn thread_scope(status: ThreadStatusFilter) -> ThreadScope {
    match status {
        ThreadStatusFilter::Any => ThreadScope::Any,
        ThreadStatusFilter::Questions => ThreadScope::Questions,
        ThreadStatusFilter::Answered => ThreadScope::Answered,
        ThreadStatusFilter::Unanswered => ThreadScope::Unanswered,
    }
}

pub(crate) const fn follow_level(level: ThreadFollowLevel) -> ThreadFollowLevelVM {
    match level {
        ThreadFollowLevel::None => ThreadFollowLevelVM::None,
        ThreadFollowLevel::Watch => ThreadFollowLevelVM::Watch,
        ThreadFollowLevel::Follow => ThreadFollowLevelVM::Follow,
        ThreadFollowLevel::Mute => ThreadFollowLevelVM::Mute,
    }
}

pub(crate) fn category_ref(category: &Category) -> CategoryRefVM {
    CategoryRefVM {
        id: Opaque(category.id.clone()),
        name: Text(category.name.clone()),
    }
}

pub(crate) fn category_vm(category: &Category) -> CategoryVM {
    CategoryVM {
        category: category_ref(category),
        kind: thread_kind(category.format),
        sort_order: category.sort_order,
    }
}

pub(crate) fn thread_row_shared(
    thread: &Thread,
    category: Option<&Category>,
    post_count: Option<i64>,
    accepted: bool,
) -> ThreadRowShared {
    let kind = category
        .map(|category| thread_kind(category.format))
        .unwrap_or(ThreadKind::Discussion);
    ThreadRowShared {
        id: Opaque(thread.id.clone()),
        title: Text(thread.title.clone()),
        category: category.map(category_ref),
        kind,
        answer_state: match (kind, accepted) {
            (ThreadKind::Question, true) => AnswerState::Answered,
            (ThreadKind::Question, false) => AnswerState::NeedsAnswer,
            (ThreadKind::Discussion, _) => AnswerState::NotApplicable,
        },
        author_display: Text(thread.author_email.clone()),
        created_at: thread.created_at,
        last_at: thread.last_at,
        post_count,
        pinned: thread.pinned,
        locked: thread.locked,
    }
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
        due_bookmarks: Some(state.store.due_bookmark_count(&subject, as_of).await?),
    })
}
