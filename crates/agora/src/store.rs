//! Forum storage.
//!
//! `Store` is a small trait with an in-memory and a PostgreSQL implementation, mirroring the
//! keystone/keyward/beacon seam: handlers depend only on the trait, so a FusionDB-backed
//! store can drop in later. The PostgreSQL layer uses ONLY portable standard SQL
//! (TEXT/BIGINT, PRIMARY KEY/NOT NULL/DEFAULT, parameterized queries, INSERT .. ON CONFLICT,
//! plain indexes, `COUNT(*)`) and runtime queries (no compile-time macros), so the build
//! needs NO database and the same statements later run unchanged on FusionDB over pgwire.
//!
//! The Store trait is async: the axum handlers `.await` it directly and `PgStore` drives sqlx
//! natively, so a DB round-trip never blocks a worker thread — there is NO `block_in_place`
//! and NO sync-over-async bridge. The in-memory store never holds a lock across an `.await`.
//!
//! Tables (all standard SQL):
//! - `categories(id TEXT PK, name TEXT, sort_order BIGINT, format TEXT)`
//! - `threads(id TEXT PK, category_id TEXT, title TEXT, author_sub TEXT, author_email TEXT,
//!    created_at BIGINT, last_at BIGINT)`
//! - `posts(id TEXT PK, thread_id TEXT, body_md TEXT, quoted_post_id TEXT, author_sub TEXT,
//!    author_email TEXT, created_at BIGINT)`
//! - `post_mentions(post_id TEXT, thread_id TEXT, mentioned_username TEXT, created_at BIGINT)`
//! - `forum_identity_aliases(alias TEXT, subject TEXT, created_at BIGINT)`
//! - `thread_subscriptions(thread_id TEXT, subscriber_sub TEXT, created_at BIGINT)` (Watch only)
//! - `thread_follow_preferences(thread_id TEXT, subscriber_sub TEXT, level TEXT, created_at BIGINT)`
//! - `forum_activity_events(id TEXT PK, kind TEXT, thread_id TEXT, post_id TEXT, actor_sub TEXT,
//!    created_at BIGINT)`
//! - `forum_activity_deliveries(activity_id TEXT, recipient_kind TEXT, recipient_key TEXT,
//!    reason TEXT)`
//! - `forum_activity_receipts(activity_id TEXT, viewer_sub TEXT, read_at BIGINT)`
//! - `forum_catch_up_clock(id BIGINT PK, generation BIGINT)`
//! - `forum_catch_up_post_points(post_id TEXT PK, thread_id TEXT, activity_at BIGINT, seq BIGINT)`
//! - `forum_post_read_receipts(viewer_sub TEXT, post_id TEXT, read_at BIGINT, read_seq BIGINT)`
//! - `forum_bookmarks(bookmark_id TEXT, owner_sub TEXT, post_id TEXT, note TEXT, remind_at BIGINT,
//!    created_at BIGINT, updated_at BIGINT, version BIGINT)`

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::model::{
    ActivityDelivery, ActivityEvent, ActivityItem, ActivityKind, ActivityReason,
    ActivityRecipientKind, BannedAuthor, Bookmark, BookmarkItem, Category, CategoryFocusLevel,
    CategoryFormat, Mention, Post, ReactionCount, Thread, ThreadDigest, ThreadFollowLevel,
    ThreadReadingState, ThreadSearchHit,
};

/// Storage failure surfaced to the handler layer (mapped to a 500 `server_error`).
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store error: {0}")]
    Backend(String),
    #[error("invalid store operation: {0}")]
    InvalidOperation(String),
    #[error("store record not found: {0}")]
    NotFound(String),
    #[error("store conflict: {0}")]
    Conflict(String),
}

/// Which keyset page of a thread's replies to fetch, over the shared `(created_at, id)` cursor.
/// Every page is anchored on the same portable `(created_at DESC, id DESC)` idiom the content
/// crates use; the handler always normalises the returned rows to ascending (oldest→newest)
/// display order.
///
/// - `First`  — the OLDEST replies (natural reading order), no cursor.
/// - `After`  — replies strictly NEWER than the cursor (paging forward / "Load newer").
/// - `Before` — replies strictly OLDER than the cursor (paging back / "Load older"), reusing the
///   `(created_at DESC, id DESC)` walk.
/// - `Latest` — the NEWEST replies ("jump to latest"), same DESC walk with no lower bound.
#[derive(Clone, Debug)]
pub enum ReplyAnchor {
    First,
    /// Inclusive ascending page beginning at an authoritative first-unread reply.
    From(i64, String),
    After(i64, String),
    Before(i64, String),
    Latest,
    /// A page that includes this exact reply and walks toward older replies. Activity links use it
    /// so a notification never lands on a paginated thread page that omits its target.
    Around(i64, String),
}

/// Sort mode for thread lists. `Latest` is the legacy/default ordering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadSort {
    Latest,
    Top,
    Hot,
}

/// Product-level scope for forum lists and search. Answered/unanswered are meaningful only for
/// question categories, so both variants implicitly exclude discussion categories. `Questions`
/// is the all-status scope used by `/questions`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ThreadStatusFilter {
    #[default]
    Any,
    Questions,
    Answered,
    Unanswered,
}

/// Explicit, idempotent accepted-answer mutation. `Accept` never toggles: accepting an already
/// accepted reply is a successful no-op, while `Clear` always clears the pointer and does not
/// depend on the old target post still existing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcceptedAnswerAction {
    Accept { post_id: String },
    Clear,
}

/// Atomic result returned to the handler after the Store has validated category, thread, original
/// post and target reply under one guard/transaction.
#[derive(Clone, Debug)]
pub struct AcceptedAnswerMutation {
    pub thread: Thread,
    pub accepted_post: Option<Post>,
    pub changed: bool,
    /// Stable gateway subjects that received the durable event and may receive best-effort Klaxon
    /// push after the transaction commits. Username-addressed mentions are intentionally absent.
    pub delivery_subjects: Vec<String>,
}

/// Result of an atomic post + mention + activity fan-out command.
#[derive(Clone, Debug)]
pub struct ActivityMutation {
    pub delivery_subjects: Vec<String>,
}

/// Legacy bounded owner projection retained for v7 callers and compatibility tests. The v8
/// catch-up handler uses [`Store::catch_up_page`] so explicit relationships are never intersected
/// with a bounded Latest window.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ThreadPersonalSignals {
    pub follow_level: ThreadFollowLevel,
    pub authored: bool,
    pub participated: bool,
    pub bookmarked: bool,
    pub reading_started: bool,
    pub has_unread: bool,
}

/// One task-oriented view of the private Forum catch-up desk. The value is also bound into the
/// keyset cursor so a pagination token can never silently change meaning between views.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CatchUpView {
    #[default]
    Updates,
    Following,
    Questions,
}

impl CatchUpView {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Updates => "updates",
            Self::Following => "following",
            Self::Questions => "questions",
        }
    }
}

/// The single strongest authoritative reason a thread belongs on the catch-up desk. Ordering is
/// deliberate and matches the v7 explainable feed when several signals apply to one thread.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatchUpReason {
    Watch,
    Follow,
    Authored,
    Bookmarked,
    Participated,
    ContinueReading,
}

impl CatchUpReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Watch => "watch",
            Self::Follow => "follow",
            Self::Authored => "authored",
            Self::Bookmarked => "bookmarked",
            Self::Participated => "participated",
            Self::ContinueReading => "reading",
        }
    }
}

/// A question is solved only when its category is currently a Question and its accepted pointer
/// resolves to a live reply in the same thread. It is not a claim of objective correctness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatchUpQuestionState {
    Waiting,
    Solved,
}

impl CatchUpQuestionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Solved => "solved",
        }
    }
}

/// Descending `(activity_at, thread_id)` keyset bound to one view and one content snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatchUpCursor {
    pub view: CatchUpView,
    pub as_of: i64,
    /// Commit-ordered post/read boundary. Unlike second-granularity wall time, this cannot admit a
    /// same-second mutation that committed after the first page was rendered.
    pub snapshot_generation: i64,
    pub activity_at: i64,
    pub thread_id: String,
}

/// Complete owner-scoped Store projection for one catch-up row. Handlers render this value
/// without per-thread reads; `first_unread` is the current live post row, never a stale copy.
#[derive(Clone, Debug)]
pub struct CatchUpItem {
    pub thread: Thread,
    pub category_name: String,
    pub reason: CatchUpReason,
    pub follow_level: ThreadFollowLevel,
    pub unread_count: i64,
    pub first_unread: Option<Post>,
    pub question_state: Option<CatchUpQuestionState>,
    pub activity_at: i64,
    pub reply_count: i64,
}

/// Why one live thread appears on the private Category Focus page. Category Priority/Follow are
/// read-time projections only; the two override reasons make the narrow thread choice visible when
/// it intentionally wins over a broad category Mute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CategoryFocusReason {
    CategoryPriority,
    CategoryFollow,
    ThreadWatchOverride,
    ThreadFollowOverride,
}

impl CategoryFocusReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CategoryPriority => "category_priority",
            Self::CategoryFollow => "category_follow",
            Self::ThreadWatchOverride => "thread_watch_override",
            Self::ThreadFollowOverride => "thread_follow_override",
        }
    }

    const fn sort_bucket(self) -> u8 {
        match self {
            Self::CategoryPriority => 0,
            Self::CategoryFollow => 1,
            Self::ThreadWatchOverride | Self::ThreadFollowOverride => 2,
        }
    }
}

/// One bounded, fully-explained row on `/focus`. No capability or notification state is carried:
/// handlers render only the live Thread plus its current category and winning private intent.
#[derive(Clone, Debug)]
pub struct CategoryFocusItem {
    pub thread: Thread,
    pub category: Category,
    pub category_level: CategoryFocusLevel,
    pub thread_level: ThreadFollowLevel,
    pub reason: CategoryFocusReason,
}

/// One owner-scoped desired-state rule shown on `/focus`, including negative Mute intent even when
/// it intentionally produces no thread rows.
#[derive(Clone, Debug)]
pub struct CategoryFocusRuleItem {
    pub category: Category,
    pub level: CategoryFocusLevel,
}

/// Keyset cursor for the personal activity stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityCursor {
    pub created_at: i64,
    pub id: String,
}

/// Activity list filter. `All` keeps every reason; the others match the best reason visible to the
/// current viewer after duplicate delivery paths have been collapsed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ActivityFilter {
    #[default]
    All,
    Reason(ActivityReason),
}

/// Personal bookmark list scope.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BookmarkState {
    #[default]
    All,
    Due,
    Scheduled,
}

/// State-specific keyset cursor. `sort_at` is `created_at` for All and `remind_at` otherwise.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BookmarkCursor {
    pub sort_at: i64,
    pub post_id: String,
}

/// Immutable row identity plus monotonic edit version. Both values are required for every
/// mutation so deleting and recreating the same `(owner_sub, post_id)` can never create an ABA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BookmarkCas<'a> {
    pub bookmark_id: &'a str,
    pub version: i64,
}

/// Atomic reminder edit. `Keep` is required so editing a note on an already-due bookmark does not
/// silently clear or reject its existing reminder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BookmarkReminderUpdate {
    Keep,
    Clear,
    Set(i64),
}

/// Hard mutation bound shared by the UI and both Store implementations.
pub const MAX_ACTIVITY_BATCH: usize = 30;
/// OP + accepted solution + one ordinary reply page, with a small defensive margin.
pub const MAX_THREAD_READ_BATCH: usize = 24;
/// Home/category list projection bound; prevents an accidental unbounded metadata query.
pub const MAX_THREAD_READING_STATE_BATCH: usize = 200;
/// A thread cannot accumulate an unbounded generic Watch reply fan-out. Follow and Mute
/// preferences do not create generic deliveries and therefore do not consume this budget.
pub const MAX_THREAD_FOLLOWERS: usize = 256;
/// Legacy v7 personal-signal batch bound. New catch-up reads do not use this candidate window.
pub const MAX_FOR_YOU_CANDIDATES: usize = 200;
/// Catch-up renders 30 task rows and may request one sentinel row to decide whether a keyset link
/// is needed. Both Store implementations reject a larger request.
pub const MAX_CATCH_UP_PAGE: i64 = 30;
/// A subject can keep a small, inspectable set of category rules. The cap is enforced atomically
/// by Memory and PostgreSQL; `None` removes a rule and never consumes the quota.
pub const MAX_CATEGORY_FOCUS_RULES: usize = 64;
/// `/focus` is an intentionally bounded first-page desk in v9. There is no silent unbounded load.
pub const MAX_CATEGORY_FOCUS_PAGE: i64 = 30;
/// Parsed aliases are deduplicated before this per-post bound is enforced.
pub const MAX_MENTIONS_PER_POST: usize = 32;
/// OP + quoted author + followers + mentions. Klaxon is best-effort and never exceeds this bound.
pub const MAX_KLAXON_RECIPIENTS_PER_REPLY: usize = MAX_THREAD_FOLLOWERS + MAX_MENTIONS_PER_POST + 2;
pub const MAX_BOOKMARKS_PER_USER: usize = 1_000;
pub const MAX_BOOKMARK_NOTE_CHARS: usize = 200;
pub const MAX_BOOKMARK_PAGE: i64 = 30;
pub const MAX_BOOKMARK_POST_BATCH: usize = 32;
pub const MAX_REMINDER_HORIZON_SECS: i64 = 10 * 366 * 24 * 60 * 60;

fn subject_delivery(
    recipient: &str,
    actor_sub: &str,
    reason: ActivityReason,
) -> Option<ActivityDelivery> {
    let recipient = recipient.trim();
    if recipient.is_empty() || recipient == actor_sub {
        return None;
    }
    Some(ActivityDelivery {
        recipient_kind: ActivityRecipientKind::Subject,
        recipient_key: recipient.to_string(),
        reason,
    })
}

pub(crate) fn normalize_activity_alias(raw: &str) -> Option<String> {
    let alias = raw.trim().trim_start_matches('@');
    if alias.is_empty() || alias.len() > 64 {
        return None;
    }
    if !alias
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !alias
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return None;
    }
    Some(alias.to_ascii_lowercase())
}

fn identity_alias(subject: &str, email: &str) -> Option<String> {
    email
        .split('@')
        .next()
        .and_then(normalize_activity_alias)
        .or_else(|| normalize_activity_alias(subject))
}

fn bounded_mention_aliases(mentioned_aliases: &[String]) -> Result<Vec<String>, StoreError> {
    let mut seen = HashSet::new();
    let mut aliases = Vec::new();
    for raw in mentioned_aliases {
        let Some(alias) = normalize_activity_alias(raw) else {
            continue;
        };
        if seen.insert(alias.clone()) {
            aliases.push(alias);
        }
    }
    if aliases.len() > MAX_MENTIONS_PER_POST {
        return Err(StoreError::InvalidOperation(format!(
            "a post may mention at most {MAX_MENTIONS_PER_POST} aliases"
        )));
    }
    Ok(aliases)
}

fn dedupe_deliveries(deliveries: &mut Vec<ActivityDelivery>) {
    let mut seen = HashSet::new();
    deliveries.retain(|delivery| {
        seen.insert((
            delivery.recipient_kind,
            delivery.recipient_key.clone(),
            delivery.reason,
        ))
    });
}

fn delivery_subjects(deliveries: &[ActivityDelivery]) -> Vec<String> {
    let mut subjects: Vec<String> = deliveries
        .iter()
        .filter(|delivery| delivery.recipient_kind == ActivityRecipientKind::Subject)
        .map(|delivery| delivery.recipient_key.clone())
        .collect();
    subjects.sort();
    subjects.dedup();
    subjects
}

fn delivery_matches_viewer(delivery: &ActivityDelivery, viewer_sub: &str) -> bool {
    delivery.recipient_kind == ActivityRecipientKind::Subject
        && delivery.recipient_key == viewer_sub
}

fn best_activity_reason(
    deliveries: impl Iterator<Item = ActivityDelivery>,
) -> Option<ActivityReason> {
    deliveries
        .map(|delivery| delivery.reason)
        .min_by_key(|reason| reason.priority())
}

fn activity_filter_matches(filter: ActivityFilter, reason: ActivityReason) -> bool {
    match filter {
        ActivityFilter::All => true,
        ActivityFilter::Reason(expected) => expected == reason,
    }
}

fn validate_bookmark_note(note: &str) -> Result<(), StoreError> {
    if note.chars().count() > MAX_BOOKMARK_NOTE_CHARS {
        return Err(StoreError::InvalidOperation(format!(
            "bookmark note may contain at most {MAX_BOOKMARK_NOTE_CHARS} characters"
        )));
    }
    Ok(())
}

fn validate_future_reminder(remind_at: i64, now: i64) -> Result<(), StoreError> {
    let latest = now.saturating_add(MAX_REMINDER_HORIZON_SECS);
    if remind_at <= now {
        return Err(StoreError::InvalidOperation(
            "bookmark reminder must be in the future".to_string(),
        ));
    }
    if remind_at > latest {
        return Err(StoreError::InvalidOperation(
            "bookmark reminder may be at most 10 years in the future".to_string(),
        ));
    }
    Ok(())
}

fn next_bookmark_version(version: i64) -> Result<i64, StoreError> {
    version.checked_add(1).ok_or_else(|| {
        StoreError::Conflict("bookmark version is exhausted; reload and retry".to_string())
    })
}

fn validate_bookmark_cas(bookmark: &Bookmark, expected: BookmarkCas<'_>) -> Result<(), StoreError> {
    if bookmark.bookmark_id != expected.bookmark_id || bookmark.version != expected.version {
        return Err(StoreError::Conflict(
            "bookmark changed in another tab; reload and retry".to_string(),
        ));
    }
    Ok(())
}

fn bookmark_state_matches(bookmark: &Bookmark, state: BookmarkState, now: i64) -> bool {
    match state {
        BookmarkState::All => true,
        BookmarkState::Due => bookmark.remind_at.is_some_and(|at| at <= now),
        BookmarkState::Scheduled => bookmark.remind_at.is_some_and(|at| at > now),
    }
}

fn bounded_thread_ids(thread_ids: &[String]) -> Result<Vec<String>, StoreError> {
    let mut unique = BTreeSet::new();
    for thread_id in thread_ids {
        if !thread_id.trim().is_empty() {
            unique.insert(thread_id.clone());
        }
    }
    if unique.len() > MAX_THREAD_READING_STATE_BATCH {
        return Err(StoreError::InvalidOperation(format!(
            "reading state accepts at most {MAX_THREAD_READING_STATE_BATCH} threads"
        )));
    }
    Ok(unique.into_iter().collect())
}

fn bounded_personal_thread_ids(thread_ids: &[String]) -> Result<Vec<String>, StoreError> {
    let mut unique = BTreeSet::new();
    for thread_id in thread_ids {
        let thread_id = thread_id.trim();
        if !thread_id.is_empty() {
            unique.insert(thread_id.to_string());
        }
    }
    if unique.len() > MAX_FOR_YOU_CANDIDATES {
        return Err(StoreError::InvalidOperation(format!(
            "personal signals accept at most {MAX_FOR_YOU_CANDIDATES} threads"
        )));
    }
    Ok(unique.into_iter().collect())
}

fn bounded_post_ids(post_ids: &[String]) -> Result<Vec<String>, StoreError> {
    let mut unique = BTreeSet::new();
    for post_id in post_ids {
        let post_id = post_id.trim();
        if !post_id.is_empty() {
            unique.insert(post_id.to_string());
        }
    }
    if unique.is_empty() {
        return Err(StoreError::InvalidOperation(
            "marking read requires at least one post".to_string(),
        ));
    }
    if unique.len() > MAX_THREAD_READ_BATCH {
        return Err(StoreError::InvalidOperation(format!(
            "one reading receipt may contain at most {MAX_THREAD_READ_BATCH} posts"
        )));
    }
    Ok(unique.into_iter().collect())
}

fn reading_state_from_posts(posts: &[Post], read_post_ids: &HashSet<String>) -> ThreadReadingState {
    let is_read = |post: &Post| read_post_ids.contains(&post.id);
    let first_unread_index = posts.iter().position(|post| !is_read(post));
    let unread_count = posts.iter().filter(|post| !is_read(post)).count() as i64;
    ThreadReadingState {
        started: posts.iter().any(is_read),
        unread_count,
        first_unread: first_unread_index.map(|index| posts[index].clone()),
        last_contiguous_read: match first_unread_index {
            Some(0) => None,
            Some(index) => posts.get(index - 1).cloned(),
            None => posts.last().cloned(),
        },
    }
}

fn catch_up_reason(
    view: CatchUpView,
    follow_level: ThreadFollowLevel,
    authored: bool,
    bookmarked: bool,
    participated: bool,
    reading_started: bool,
) -> Option<CatchUpReason> {
    if follow_level == ThreadFollowLevel::Mute {
        return None;
    }
    match view {
        CatchUpView::Questions => authored.then_some(CatchUpReason::Authored),
        CatchUpView::Following => match follow_level {
            ThreadFollowLevel::Watch => Some(CatchUpReason::Watch),
            ThreadFollowLevel::Follow => Some(CatchUpReason::Follow),
            ThreadFollowLevel::None | ThreadFollowLevel::Mute => None,
        },
        CatchUpView::Updates => match follow_level {
            ThreadFollowLevel::Watch => Some(CatchUpReason::Watch),
            ThreadFollowLevel::Follow => Some(CatchUpReason::Follow),
            ThreadFollowLevel::None | ThreadFollowLevel::Mute if authored => {
                Some(CatchUpReason::Authored)
            }
            ThreadFollowLevel::None | ThreadFollowLevel::Mute if bookmarked => {
                Some(CatchUpReason::Bookmarked)
            }
            ThreadFollowLevel::None | ThreadFollowLevel::Mute if participated => {
                Some(CatchUpReason::Participated)
            }
            ThreadFollowLevel::None | ThreadFollowLevel::Mute if reading_started => {
                Some(CatchUpReason::ContinueReading)
            }
            ThreadFollowLevel::None | ThreadFollowLevel::Mute => None,
        },
    }
}

fn category_focus_reason(
    category_level: CategoryFocusLevel,
    thread_level: ThreadFollowLevel,
) -> Option<CategoryFocusReason> {
    if thread_level == ThreadFollowLevel::Mute {
        return None;
    }
    match category_level {
        CategoryFocusLevel::Priority => Some(CategoryFocusReason::CategoryPriority),
        CategoryFocusLevel::Follow => Some(CategoryFocusReason::CategoryFollow),
        CategoryFocusLevel::Mute => match thread_level {
            ThreadFollowLevel::Watch => Some(CategoryFocusReason::ThreadWatchOverride),
            ThreadFollowLevel::Follow => Some(CategoryFocusReason::ThreadFollowOverride),
            ThreadFollowLevel::None | ThreadFollowLevel::Mute => None,
        },
        CategoryFocusLevel::None => None,
    }
}

fn validate_category_focus_page(limit: i64, as_of: i64) -> Result<usize, StoreError> {
    if as_of < 0 {
        return Err(StoreError::InvalidOperation(
            "focus as_of must be non-negative".to_string(),
        ));
    }
    if !(0..=MAX_CATEGORY_FOCUS_PAGE).contains(&limit) {
        return Err(StoreError::InvalidOperation(format!(
            "focus page may request at most {MAX_CATEGORY_FOCUS_PAGE} rows"
        )));
    }
    Ok(limit as usize)
}

fn validate_catch_up_page(
    view: CatchUpView,
    as_of: i64,
    snapshot_generation: i64,
    cursor: Option<&CatchUpCursor>,
    limit: i64,
) -> Result<usize, StoreError> {
    if as_of < 0 || snapshot_generation < 0 {
        return Err(StoreError::InvalidOperation(
            "catch-up snapshot bounds must be non-negative".to_string(),
        ));
    }
    if !(0..=MAX_CATCH_UP_PAGE + 1).contains(&limit) {
        return Err(StoreError::InvalidOperation(format!(
            "catch-up page may request at most {} rows",
            MAX_CATCH_UP_PAGE + 1
        )));
    }
    if let Some(cursor) = cursor {
        if cursor.view != view
            || cursor.as_of != as_of
            || cursor.snapshot_generation != snapshot_generation
        {
            return Err(StoreError::InvalidOperation(
                "catch-up cursor does not belong to this view and snapshot".to_string(),
            ));
        }
        if cursor.thread_id.trim().is_empty()
            || cursor.activity_at < 0
            || cursor.activity_at > as_of
        {
            return Err(StoreError::InvalidOperation(
                "catch-up cursor is malformed".to_string(),
            ));
        }
    }
    Ok(limit as usize)
}

/// Pluggable forum store. All methods are `async` and `.await`ed on the serving runtime.
#[async_trait]
pub trait Store: Send + Sync {
    /// Insert the default categories ONLY when the table is currently empty (never clobbers
    /// operator edits). Idempotent.
    async fn seed_categories_if_empty(&self, defaults: &[Category]) -> Result<(), StoreError>;

    /// All categories, ordered by `sort_order` then name.
    async fn list_categories(&self) -> Result<Vec<Category>, StoreError>;
    /// A single category by id, if it exists.
    async fn get_category(&self, id: &str) -> Result<Option<Category>, StoreError>;
    /// Number of threads in a category.
    async fn count_threads(&self, category_id: &str) -> Result<i64, StoreError>;

    /// Insert a new category. Admin-only; the caller validates that `id` is free/well-formed.
    async fn create_category(&self, category: &Category) -> Result<(), StoreError>;
    /// Rename a category (its display `name`). Admin-only.
    async fn rename_category(&self, id: &str, name: &str) -> Result<(), StoreError>;
    /// Atomically change a category's product format. A transition to `discussion` is rejected
    /// while any thread in the category has a valid accepted reply.
    async fn transition_category_format(
        &self,
        id: &str,
        format: CategoryFormat,
    ) -> Result<(), StoreError>;
    /// Set a category's `sort_order` (used to reorder the list). Admin-only.
    async fn set_category_order(&self, id: &str, sort_order: i64) -> Result<(), StoreError>;
    /// Delete an empty category atomically. The Store rechecks emptiness under the category guard
    /// so a concurrent thread creation/move cannot leave an orphan.
    async fn delete_category(&self, id: &str) -> Result<(), StoreError>;
    /// The most recently active threads across all categories (by `last_at` DESC), capped.
    async fn recent_threads(&self, limit: i64) -> Result<Vec<Thread>, StoreError>;
    /// Threads in one category, most recently active first, capped.
    async fn threads_in_category(
        &self,
        category_id: &str,
        limit: i64,
    ) -> Result<Vec<Thread>, StoreError>;
    /// Threads optionally filtered by category and/or current subscriber, sorted by the requested
    /// list mode. Used by public lists; `Latest` preserves the legacy pinned/latest order.
    async fn list_threads(
        &self,
        category_id: Option<&str>,
        sort: ThreadSort,
        subscribed_sub: Option<&str>,
        status: ThreadStatusFilter,
        limit: i64,
        now: i64,
    ) -> Result<Vec<Thread>, StoreError>;
    /// Search thread titles and original-post bodies, optionally within one category. Results are
    /// most-recently-active first and include their reply count for one-query rendering.
    async fn search_threads(
        &self,
        query: &str,
        category_id: Option<&str>,
        status: ThreadStatusFilter,
        limit: i64,
    ) -> Result<Vec<ThreadSearchHit>, StoreError>;
    /// A single thread by id, if it exists.
    async fn get_thread(&self, id: &str) -> Result<Option<Thread>, StoreError>;

    /// Digests (id, category, title, original-post body) of the most recently active threads,
    /// capped. Feeds compose-time similarity scoring without loading every post.
    async fn thread_digests(&self, limit: i64) -> Result<Vec<ThreadDigest>, StoreError>;

    /// Number of posts in a thread (original post + replies).
    async fn count_posts(&self, thread_id: &str) -> Result<i64, StoreError>;
    /// A single post by id, if it exists (used by admin post-deletion + audit).
    async fn get_post(&self, id: &str) -> Result<Option<Post>, StoreError>;
    /// The thread's accepted reply only when the pointer is valid: the post exists, belongs to the
    /// same thread and is not the recorded original post. Category format is deliberately not part
    /// of this predicate so a historical discussion solution remains readable on its detail page.
    async fn get_valid_accepted_post(&self, thread_id: &str) -> Result<Option<Post>, StoreError>;
    /// All posts in a thread, with its stable original post first, then replies oldest-first.
    async fn posts_in_thread(&self, thread_id: &str) -> Result<Vec<Post>, StoreError>;

    /// The thread's explicitly recorded original post, if any. Fetched on its own so the thread
    /// page can pin the OP at the top while paginating only the replies below it.
    async fn first_post_in_thread(&self, thread_id: &str) -> Result<Option<Post>, StoreError>;

    /// One keyset page of a thread's replies (every post EXCEPT the original, identified by
    /// `op_id`), selected by `anchor` over the `(created_at, id)` cursor and capped at `limit`.
    /// Rows come back in FETCH order: ascending for [`ReplyAnchor::First`]/[`ReplyAnchor::After`],
    /// descending for [`ReplyAnchor::Before`]/[`ReplyAnchor::Latest`] (the caller reverses the
    /// descending pages for display). The same portable predicate as the content crates.
    async fn replies_page(
        &self,
        thread_id: &str,
        op_id: &str,
        excluded_post_id: Option<&str>,
        anchor: &ReplyAnchor,
        limit: i64,
    ) -> Result<Vec<Post>, StoreError>;

    /// Create a thread together with its original post, atomically, after locking and confirming
    /// its category still exists.
    async fn create_thread(&self, thread: &Thread, first_post: &Post) -> Result<(), StoreError>;
    /// Browser create path: create the thread/original post, persist parsed mentions, and fan out a
    /// durable mention event in the SAME command. No event row is written when every recipient is
    /// the actor or the post contains no mentions.
    async fn create_thread_with_activity(
        &self,
        thread: &Thread,
        first_post: &Post,
        mentioned_usernames: &[String],
        activity_id: &str,
    ) -> Result<ActivityMutation, StoreError>;
    /// Append a reply and bump the parent thread's `last_at` to the reply's timestamp. The Store
    /// locks category then thread and rechecks that the thread exists and is still unlocked.
    async fn add_reply(&self, post: &Post) -> Result<(), StoreError>;
    /// Browser reply path: append the reply, replace parsed mentions, collect OP/quote/follower/
    /// mention recipients, and persist one deduplicated durable event atomically. Self deliveries
    /// are omitted; multiple reasons still collapse to one inbox item/read receipt per viewer.
    async fn add_reply_with_activity(
        &self,
        post: &Post,
        mentioned_usernames: &[String],
        activity_id: &str,
    ) -> Result<ActivityMutation, StoreError>;

    /// Replace the parsed mentions for one post with the supplied normalised usernames.
    async fn replace_mentions(
        &self,
        post_id: &str,
        thread_id: &str,
        mentioned_usernames: &[String],
        created_at: i64,
    ) -> Result<(), StoreError>;
    /// Count mentions for one normalised username.
    async fn count_mentions_for_user(&self, mentioned_username: &str) -> Result<i64, StoreError>;
    /// Most recent mentions for one normalised username.
    async fn mentions_for_user(
        &self,
        mentioned_username: &str,
        limit: i64,
    ) -> Result<Vec<Mention>, StoreError>;

    /// Edit a thread's title AND its original-post body, atomically. `op_post_id` is the
    /// thread's original post; its `body_md` and the denormalised `first_body_md` (which powers
    /// compose-time similarity) are updated together so they never desync. Author authorisation
    /// is enforced by the caller.
    async fn update_thread(
        &self,
        thread_id: &str,
        title: &str,
        op_post_id: &str,
        body_md: &str,
    ) -> Result<(), StoreError>;
    /// Delete a thread and ALL of its posts, atomically. Author authorisation is enforced by the
    /// caller.
    async fn delete_thread(&self, thread_id: &str) -> Result<(), StoreError>;
    /// Update a single post's body (used to edit a reply). Author authorisation is enforced by
    /// the caller.
    async fn update_post(&self, post_id: &str, body_md: &str) -> Result<(), StoreError>;
    /// Delete a single post (used to delete a reply). Author authorisation is enforced by the
    /// caller.
    async fn delete_post(&self, post_id: &str) -> Result<(), StoreError>;

    /// Set a thread's `locked` flag (a locked thread accepts no new replies). Admin-only.
    async fn set_thread_locked(&self, thread_id: &str, locked: bool) -> Result<(), StoreError>;
    /// Set a thread's `pinned` flag (pinned threads sort first in the lists). Admin-only.
    async fn set_thread_pinned(&self, thread_id: &str, pinned: bool) -> Result<(), StoreError>;
    /// Atomically move a thread. A valid accepted reply cannot be moved into a discussion category.
    async fn move_thread_to_category(
        &self,
        thread_id: &str,
        category_id: &str,
    ) -> Result<(), StoreError>;

    /// Atomically accept or clear an answer. The Store owns all category/thread/post invariants;
    /// authorisation remains a handler concern because identity is gateway-owned.
    async fn mutate_accepted_answer(
        &self,
        thread_id: &str,
        action: AcceptedAnswerAction,
    ) -> Result<AcceptedAnswerMutation, StoreError>;
    /// Accepted-answer browser command: apply the answer state and, when it changed to an accepted
    /// reply owned by someone else, insert its durable activity delivery in the same transaction.
    async fn mutate_accepted_answer_with_activity(
        &self,
        thread_id: &str,
        action: AcceptedAnswerAction,
        activity_id: &str,
        actor_sub: &str,
        created_at: i64,
    ) -> Result<AcceptedAnswerMutation, StoreError>;

    /// Explicitly set one user's thread relationship. `None` removes the persistence row. The
    /// desired state makes retries and concurrent duplicate form submissions idempotent; the
    /// Store also rechecks the thread under its guard and removes obsolete generic follower
    /// deliveries when leaving Watch.
    async fn set_thread_follow_level(
        &self,
        thread_id: &str,
        subscriber_sub: &str,
        level: ThreadFollowLevel,
        created_at: i64,
    ) -> Result<(), StoreError>;
    /// The current explicit level; a missing row returns `None` rather than a nullable result.
    async fn thread_follow_level(
        &self,
        thread_id: &str,
        subscriber_sub: &str,
    ) -> Result<ThreadFollowLevel, StoreError>;
    /// One owner-scoped, bounded batch for explainable personal-feed signals. Implementations
    /// must issue no per-thread backend query and must return rows only for live input threads.
    async fn thread_personal_signals(
        &self,
        viewer_sub: &str,
        thread_ids: &[String],
    ) -> Result<HashMap<String, ThreadPersonalSignals>, StoreError>;
    /// Current desired-state Category Focus rule. Absence is returned as `None`.
    async fn category_focus_level(
        &self,
        viewer_sub: &str,
        category_id: &str,
    ) -> Result<CategoryFocusLevel, StoreError>;
    /// List every current desired-state rule for the owner so no-JavaScript users can inspect and
    /// navigate back to edit Priority, Follow, and Mute independently of thread projection.
    async fn category_focus_rules(
        &self,
        viewer_sub: &str,
    ) -> Result<Vec<CategoryFocusRuleItem>, StoreError>;
    /// Atomically create, replace, or remove one owner-scoped rule. Category rules are private
    /// Catch-up intent only and must never create an Activity delivery.
    async fn set_category_focus_level(
        &self,
        viewer_sub: &str,
        category_id: &str,
        level: CategoryFocusLevel,
        changed_at: i64,
    ) -> Result<(), StoreError>;
    /// One exact, set-based `/focus` projection. Priority precedes Follow, thread Watch/Follow can
    /// override a category Mute, thread Mute always excludes, and `limit` is hard-capped at 30.
    async fn category_focus_page(
        &self,
        viewer_sub: &str,
        limit: i64,
        as_of: i64,
    ) -> Result<Vec<CategoryFocusItem>, StoreError>;
    /// Read the current commit-ordered post/read boundary without advancing it. PostgreSQL takes a
    /// shared lock on the singleton clock so a writer that already allocated a generation must
    /// commit or roll back before this returns; GET remains write-free.
    async fn catch_up_snapshot_generation(&self) -> Result<i64, StoreError>;
    /// Complete private catch-up page, selected directly from full relationship/content
    /// authority rather than from a bounded public Latest candidate window. `snapshot_generation`
    /// freezes post/read authority even for same-second writes; `as_of` retains the wall-time bound
    /// for legacy bookmark/relationship projections. Current Mute always wins.
    async fn catch_up_page(
        &self,
        viewer_sub: &str,
        view: CatchUpView,
        as_of: i64,
        snapshot_generation: i64,
        before: Option<&CatchUpCursor>,
        limit: i64,
    ) -> Result<Vec<CatchUpItem>, StoreError>;

    /// Compatibility seam for older callers: the historical boolean subscription maps to Watch.
    /// New product code must use [`Store::set_thread_follow_level`].
    async fn set_thread_subscription(
        &self,
        thread_id: &str,
        subscriber_sub: &str,
        subscribed: bool,
        created_at: i64,
    ) -> Result<(), StoreError> {
        self.set_thread_follow_level(
            thread_id,
            subscriber_sub,
            if subscribed {
                ThreadFollowLevel::Watch
            } else {
                ThreadFollowLevel::None
            },
            created_at,
        )
        .await
    }

    /// Historical `subscribed` means present in Following, not merely any preference row.
    async fn is_thread_subscribed(
        &self,
        thread_id: &str,
        subscriber_sub: &str,
    ) -> Result<bool, StoreError> {
        Ok(self
            .thread_follow_level(thread_id, subscriber_sub)
            .await?
            .appears_in_personal_feeds())
    }

    /// Exact per-post reading projection for one stable gateway subject and thread.
    async fn thread_reading_state(
        &self,
        viewer_sub: &str,
        thread_id: &str,
    ) -> Result<ThreadReadingState, StoreError>;
    /// One bounded list projection. Implementations must not issue one backend query per thread.
    async fn thread_reading_states(
        &self,
        viewer_sub: &str,
        thread_ids: &[String],
    ) -> Result<HashMap<String, ThreadReadingState>, StoreError>;
    /// Atomically mark one rendered page of posts read. The Store deduplicates, bounds, and
    /// re-authorises every post against `thread_id` before writing any receipt.
    async fn mark_thread_posts_read(
        &self,
        viewer_sub: &str,
        thread_id: &str,
        post_ids: &[String],
        read_at: i64,
    ) -> Result<(), StoreError>;

    /// One authoritative keyset page of activity for a gateway subject. Mention aliases are
    /// resolved to a unique subject when the event is written; reads never authorise by email.
    /// Content is joined from live thread/post rows and deleted targets are never returned.
    async fn activity_page(
        &self,
        viewer_sub: &str,
        filter: ActivityFilter,
        unread_only: bool,
        before: Option<&ActivityCursor>,
        limit: i64,
    ) -> Result<Vec<ActivityItem>, StoreError>;
    async fn unread_activity_count(&self, viewer_sub: &str) -> Result<i64, StoreError>;
    /// Mark one delivered activity read/unread. A caller cannot probe or mutate another viewer's
    /// event: an inaccessible id is returned as `NotFound`.
    async fn set_activity_read(
        &self,
        activity_id: &str,
        viewer_sub: &str,
        read: bool,
        changed_at: i64,
    ) -> Result<(), StoreError>;
    /// Mark one rendered page read. The command rejects more than [`MAX_ACTIVITY_BATCH`] ids,
    /// deduplicates them, and re-authorises each id against live delivery + thread/post rows.
    async fn mark_activity_batch_read(
        &self,
        viewer_sub: &str,
        activity_ids: &[String],
        changed_at: i64,
    ) -> Result<i64, StoreError>;

    /// Idempotently create a plain personal bookmark after rechecking the live post and enforcing
    /// the per-owner quota atomically. Existing rows are returned unchanged.
    async fn ensure_bookmark(
        &self,
        owner_sub: &str,
        post_id: &str,
        created_at: i64,
    ) -> Result<Bookmark, StoreError>;
    /// Fetch the bookmark state for one bounded visible post page in one Store call.
    async fn bookmarks_for_posts(
        &self,
        owner_sub: &str,
        post_ids: &[String],
    ) -> Result<Vec<Bookmark>, StoreError>;
    /// Stable owner-only All/Due/Scheduled keyset page joined to live post/thread content.
    async fn bookmark_page(
        &self,
        owner_sub: &str,
        state: BookmarkState,
        cursor: Option<&BookmarkCursor>,
        limit: i64,
        now: i64,
    ) -> Result<Vec<BookmarkItem>, StoreError>;
    async fn due_bookmark_count(&self, owner_sub: &str, now: i64) -> Result<i64, StoreError>;
    async fn get_bookmark(
        &self,
        owner_sub: &str,
        post_id: &str,
    ) -> Result<Option<BookmarkItem>, StoreError>;
    /// CAS update of private note/reminder state. The post identity is immutable.
    async fn update_bookmark(
        &self,
        owner_sub: &str,
        post_id: &str,
        expected: BookmarkCas<'_>,
        note: &str,
        reminder: BookmarkReminderUpdate,
        changed_at: i64,
    ) -> Result<Bookmark, StoreError>;
    /// Clear a currently-due reminder while retaining the bookmark itself.
    async fn complete_due_bookmark(
        &self,
        owner_sub: &str,
        post_id: &str,
        expected: BookmarkCas<'_>,
        changed_at: i64,
    ) -> Result<Bookmark, StoreError>;
    /// Move a reminder to an explicit future UTC epoch, guarded by the same version CAS.
    async fn snooze_bookmark(
        &self,
        owner_sub: &str,
        post_id: &str,
        expected: BookmarkCas<'_>,
        remind_at: i64,
        changed_at: i64,
    ) -> Result<Bookmark, StoreError>;
    async fn remove_bookmark(
        &self,
        owner_sub: &str,
        post_id: &str,
        expected: BookmarkCas<'_>,
    ) -> Result<(), StoreError>;

    /// Toggle one user's reaction of `kind` on a post. Idempotent per `(post_id, user_sub, kind)`:
    /// if the reaction already exists it is removed and `false` returned; otherwise it is inserted
    /// and `true` returned. `created_at` stamps a newly-inserted row.
    async fn toggle_reaction(
        &self,
        post_id: &str,
        user_sub: &str,
        kind: &str,
        created_at: i64,
    ) -> Result<bool, StoreError>;

    /// Aggregate reaction counts for a post: one [`ReactionCount`] per kind that has at least one
    /// reaction, with `mine` set when `viewer_sub` is one of the reactors. Kinds with no reactions
    /// are omitted (the caller fills them in from its allowed-kind list).
    async fn reactions_for_post(
        &self,
        post_id: &str,
        viewer_sub: Option<&str>,
    ) -> Result<Vec<ReactionCount>, StoreError>;

    /// All blocked authors, most-recently-banned first.
    async fn list_bans(&self) -> Result<Vec<BannedAuthor>, StoreError>;
    /// Whether `author_sub` is currently blocked (rejects their new threads/replies).
    async fn is_banned(&self, author_sub: &str) -> Result<bool, StoreError>;
    /// Add (or refresh) a blocklist entry. Idempotent on `author_sub`. Admin-only.
    async fn add_ban(&self, ban: &BannedAuthor) -> Result<(), StoreError>;
    /// Remove a blocklist entry (unblock). Admin-only.
    async fn remove_ban(&self, author_sub: &str) -> Result<(), StoreError>;
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

#[derive(Default)]
pub struct InMemoryStore {
    /// One fixed outer lock domain for category/thread/post invariant commands. Commands then take
    /// data locks in category -> thread metadata -> post order and never await while held.
    qa_guard: Mutex<()>,
    categories: Mutex<Vec<Category>>,
    threads: Mutex<Vec<Thread>>,
    posts: Mutex<Vec<Post>>,
    /// Stable thread -> original-post identity. Timestamps are second-granularity and random ids
    /// cannot safely break same-second ties, so ownership must never be inferred from ordering.
    original_posts: Mutex<HashMap<String, String>>,
    mentions: Mutex<Vec<Mention>>,
    identity_aliases: Mutex<Vec<IdentityAlias>>,
    subscriptions: Mutex<Vec<ThreadSubscription>>,
    activity_events: Mutex<Vec<ActivityEvent>>,
    activity_deliveries: Mutex<Vec<StoredActivityDelivery>>,
    activity_receipts: Mutex<Vec<ActivityReceipt>>,
    catch_up_state: Mutex<MemoryCatchUpState>,
    category_focus_rules: Mutex<Vec<MemoryCategoryFocusRule>>,
    bookmarks: Mutex<Vec<Bookmark>>,
    banned: Mutex<Vec<BannedAuthor>>,
    /// One row per `(post_id, user_sub, kind)` — the in-memory mirror of `post_reactions`.
    reactions: Mutex<Vec<Reaction>>,
}

#[derive(Default)]
struct MemoryCatchUpState {
    generation: i64,
    post_points: Vec<CatchUpPostPoint>,
    read_receipts: HashMap<(String, String), MemoryPostReadReceipt>,
}

#[derive(Clone, Debug)]
struct CatchUpPostPoint {
    post_id: String,
    thread_id: String,
    activity_at: i64,
    seq: i64,
}

#[derive(Clone, Copy, Debug)]
struct MemoryPostReadReceipt {
    read_at: i64,
    read_seq: i64,
}

#[derive(Clone, Debug)]
struct MemoryCategoryFocusRule {
    viewer_sub: String,
    category_id: String,
    level: CategoryFocusLevel,
    _created_at: i64,
    _updated_at: i64,
}

impl MemoryCatchUpState {
    fn next_generation(&mut self) -> Result<i64, StoreError> {
        let next = self.generation.checked_add(1).ok_or_else(|| {
            StoreError::InvalidOperation("catch-up generation is exhausted".to_string())
        })?;
        self.generation = next;
        Ok(next)
    }

    fn append_post(&mut self, post: &Post) -> Result<(), StoreError> {
        if self
            .post_points
            .iter()
            .any(|point| point.post_id == post.id)
        {
            return Err(StoreError::Conflict(
                "catch-up post point already exists".to_string(),
            ));
        }
        let seq = self.next_generation()?;
        self.post_points.push(CatchUpPostPoint {
            post_id: post.id.clone(),
            thread_id: post.thread_id.clone(),
            activity_at: post.created_at,
            seq,
        });
        Ok(())
    }
}

/// A single stored reaction (in-memory mirror of a `post_reactions` row).
#[derive(Clone, Debug)]
struct Reaction {
    post_id: String,
    user_sub: String,
    kind: String,
    #[allow(dead_code)]
    created_at: i64,
}

/// One effective in-memory relationship. PostgreSQL projects the same value from its rollback-
/// compatible Watch table plus the separate Follow/Mute preference table.
#[derive(Clone, Debug)]
struct ThreadSubscription {
    thread_id: String,
    subscriber_sub: String,
    level: ThreadFollowLevel,
    _created_at: i64,
}

/// Append-only alias observation. Keeping every `(alias, subject)` pair makes collisions
/// ambiguous forever instead of allowing the newest profile to steal existing mention routing.
#[derive(Clone, Debug)]
struct IdentityAlias {
    alias: String,
    subject: String,
    _created_at: i64,
}

#[derive(Clone, Debug)]
struct StoredActivityDelivery {
    activity_id: String,
    delivery: ActivityDelivery,
}

#[derive(Clone, Debug)]
struct ActivityReceipt {
    activity_id: String,
    viewer_sub: String,
    _read_at: i64,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn register_identity_alias(&self, subject: &str, email: &str, created_at: i64) {
        let Some(alias) = identity_alias(subject, email) else {
            return;
        };
        let mut aliases = self
            .identity_aliases
            .lock()
            .expect("identity_aliases lock poisoned");
        if aliases
            .iter()
            .any(|row| row.alias == alias && row.subject == subject)
        {
            return;
        }
        aliases.push(IdentityAlias {
            alias,
            subject: subject.to_string(),
            _created_at: created_at,
        });
    }

    fn resolve_mention_deliveries(
        &self,
        mentioned_aliases: &[String],
        actor_sub: &str,
    ) -> Vec<ActivityDelivery> {
        let aliases = self
            .identity_aliases
            .lock()
            .expect("identity_aliases lock poisoned");
        mentioned_aliases
            .iter()
            .filter_map(|alias| {
                let subjects: HashSet<&str> = aliases
                    .iter()
                    .filter(|row| row.alias == *alias)
                    .map(|row| row.subject.as_str())
                    .collect();
                (subjects.len() == 1)
                    .then(|| subjects.into_iter().next())
                    .flatten()
                    .and_then(|subject| {
                        subject_delivery(subject, actor_sub, ActivityReason::Mention)
                    })
            })
            .collect()
    }
}

#[async_trait]
impl Store for InMemoryStore {
    // The std `Mutex` is fine throughout: each critical section is fully synchronous (no
    // `.await` inside), so a guard is never held across a yield point.
    async fn seed_categories_if_empty(&self, defaults: &[Category]) -> Result<(), StoreError> {
        let mut cats = self.categories.lock().expect("categories lock poisoned");
        if cats.is_empty() {
            cats.extend(defaults.iter().cloned());
        }
        Ok(())
    }

    async fn list_categories(&self) -> Result<Vec<Category>, StoreError> {
        let mut v: Vec<Category> = self
            .categories
            .lock()
            .expect("categories lock poisoned")
            .clone();
        v.sort_by(|a, b| {
            a.sort_order
                .cmp(&b.sort_order)
                .then_with(|| a.name.cmp(&b.name))
        });
        Ok(v)
    }

    async fn get_category(&self, id: &str) -> Result<Option<Category>, StoreError> {
        Ok(self
            .categories
            .lock()
            .expect("categories lock poisoned")
            .iter()
            .find(|c| c.id == id)
            .cloned())
    }

    async fn count_threads(&self, category_id: &str) -> Result<i64, StoreError> {
        Ok(self
            .threads
            .lock()
            .expect("threads lock poisoned")
            .iter()
            .filter(|t| t.category_id == category_id)
            .count() as i64)
    }

    async fn create_category(&self, category: &Category) -> Result<(), StoreError> {
        let mut cats = self.categories.lock().expect("categories lock poisoned");
        if cats.iter().all(|c| c.id != category.id) {
            cats.push(category.clone());
        }
        Ok(())
    }

    async fn rename_category(&self, id: &str, name: &str) -> Result<(), StoreError> {
        let mut cats = self.categories.lock().expect("categories lock poisoned");
        if let Some(c) = cats.iter_mut().find(|c| c.id == id) {
            c.name = name.to_string();
        }
        Ok(())
    }

    async fn transition_category_format(
        &self,
        id: &str,
        format: CategoryFormat,
    ) -> Result<(), StoreError> {
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        let mut cats = self.categories.lock().expect("categories lock poisoned");
        let category = cats
            .iter_mut()
            .find(|category| category.id == id)
            .ok_or_else(|| StoreError::NotFound("category not found".to_string()))?;
        if category.format == format {
            return Ok(());
        }

        let threads = self.threads.lock().expect("threads lock poisoned");
        let original_posts = self
            .original_posts
            .lock()
            .expect("original_posts lock poisoned");
        let posts = self.posts.lock().expect("posts lock poisoned");
        if format == CategoryFormat::Discussion
            && threads.iter().any(|thread| {
                thread.category_id == id
                    && valid_accepted_post(thread, &original_posts, &posts).is_some()
            })
        {
            return Err(StoreError::InvalidOperation(
                "unmark accepted answers before changing this category to discussion".to_string(),
            ));
        }
        category.format = format;
        Ok(())
    }

    async fn set_category_order(&self, id: &str, sort_order: i64) -> Result<(), StoreError> {
        let mut cats = self.categories.lock().expect("categories lock poisoned");
        if let Some(c) = cats.iter_mut().find(|c| c.id == id) {
            c.sort_order = sort_order;
        }
        Ok(())
    }

    async fn delete_category(&self, id: &str) -> Result<(), StoreError> {
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        let mut categories = self.categories.lock().expect("categories lock poisoned");
        let threads = self.threads.lock().expect("threads lock poisoned");
        if threads.iter().any(|thread| thread.category_id == id) {
            return Err(StoreError::InvalidOperation(
                "category still has threads — move or delete them first".to_string(),
            ));
        }
        categories.retain(|category| category.id != id);
        self.category_focus_rules
            .lock()
            .expect("category_focus_rules lock poisoned")
            .retain(|rule| rule.category_id != id);
        Ok(())
    }

    async fn recent_threads(&self, limit: i64) -> Result<Vec<Thread>, StoreError> {
        let mut v: Vec<Thread> = self.threads.lock().expect("threads lock poisoned").clone();
        v.sort_by(thread_display_order);
        v.truncate(limit.max(0) as usize);
        Ok(v)
    }

    async fn threads_in_category(
        &self,
        category_id: &str,
        limit: i64,
    ) -> Result<Vec<Thread>, StoreError> {
        let mut v: Vec<Thread> = self
            .threads
            .lock()
            .expect("threads lock poisoned")
            .iter()
            .filter(|t| t.category_id == category_id)
            .cloned()
            .collect();
        v.sort_by(thread_display_order);
        v.truncate(limit.max(0) as usize);
        Ok(v)
    }

    async fn list_threads(
        &self,
        category_id: Option<&str>,
        sort: ThreadSort,
        subscribed_sub: Option<&str>,
        status: ThreadStatusFilter,
        limit: i64,
        now: i64,
    ) -> Result<Vec<Thread>, StoreError> {
        let subscribed_threads: Option<HashSet<String>> = subscribed_sub.map(|sub| {
            self.subscriptions
                .lock()
                .expect("subscriptions lock poisoned")
                .iter()
                .filter(|s| s.subscriber_sub == sub && s.level.appears_in_personal_feeds())
                .map(|s| s.thread_id.clone())
                .collect()
        });
        let (category_formats, threads, original_posts, posts) = {
            let _domain = self.qa_guard.lock().expect("qa guard poisoned");
            let category_formats: HashMap<String, CategoryFormat> = self
                .categories
                .lock()
                .expect("categories lock poisoned")
                .iter()
                .map(|category| (category.id.clone(), category.format))
                .collect();
            let threads = self.threads.lock().expect("threads lock poisoned").clone();
            let original_posts = self
                .original_posts
                .lock()
                .expect("original_posts lock poisoned")
                .clone();
            let posts = self.posts.lock().expect("posts lock poisoned").clone();
            (category_formats, threads, original_posts, posts)
        };
        let mut rows: Vec<(Thread, i64)> = threads
            .iter()
            .filter(|t| category_id.map(|cid| t.category_id == cid).unwrap_or(true))
            .filter(|thread| {
                let format = category_formats
                    .get(&thread.category_id)
                    .copied()
                    .unwrap_or_default();
                let valid = has_valid_question_solution(thread, format, &original_posts, &posts);
                thread_matches_status(valid, format.is_question(), status)
            })
            .filter(|t| {
                subscribed_threads
                    .as_ref()
                    .map(|ids| ids.contains(&t.id))
                    .unwrap_or(true)
            })
            .cloned()
            .map(|t| {
                let post_count = posts.iter().filter(|p| p.thread_id == t.id).count() as i64;
                let format = category_formats
                    .get(&t.category_id)
                    .copied()
                    .unwrap_or_default();
                let valid = has_valid_question_solution(&t, format, &original_posts, &posts);
                (public_thread(t, valid), (post_count - 1).max(0))
            })
            .collect();
        sort_thread_rows(&mut rows, sort, now);
        rows.truncate(limit.max(0) as usize);
        Ok(rows.into_iter().map(|(t, _)| t).collect())
    }

    async fn search_threads(
        &self,
        query: &str,
        category_id: Option<&str>,
        status: ThreadStatusFilter,
        limit: i64,
    ) -> Result<Vec<ThreadSearchHit>, StoreError> {
        let needle = query.trim().to_lowercase();
        if needle.is_empty() || limit <= 0 {
            return Ok(Vec::new());
        }

        // Build one original-post/accepted-post/count record per thread up front. This keeps search
        // O(posts + threads), instead of rescanning the complete post corpus for every thread.
        let (category_formats, threads, original_posts, posts) = {
            let _domain = self.qa_guard.lock().expect("qa guard poisoned");
            let category_formats: HashMap<String, CategoryFormat> = self
                .categories
                .lock()
                .expect("categories lock poisoned")
                .iter()
                .map(|category| (category.id.clone(), category.format))
                .collect();
            let threads = self.threads.lock().expect("threads lock poisoned").clone();
            let original_posts = self
                .original_posts
                .lock()
                .expect("original_posts lock poisoned")
                .clone();
            let posts = self.posts.lock().expect("posts lock poisoned").clone();
            (category_formats, threads, original_posts, posts)
        };
        let mut post_counts: HashMap<String, i64> = HashMap::new();
        let mut original_bodies: HashMap<String, String> = HashMap::new();
        let mut posts_by_id: HashMap<String, Post> = HashMap::new();
        for post in &posts {
            *post_counts.entry(post.thread_id.clone()).or_insert(0) += 1;
            if original_posts.get(&post.thread_id) == Some(&post.id) {
                original_bodies.insert(post.thread_id.clone(), post.body_md.clone());
            }
            posts_by_id.insert(post.id.clone(), post.clone());
        }
        let mut hits: Vec<ThreadSearchHit> = threads
            .iter()
            .filter(|thread| {
                category_id
                    .map(|category_id| thread.category_id == category_id)
                    .unwrap_or(true)
            })
            .filter(|thread| {
                let format = category_formats
                    .get(&thread.category_id)
                    .copied()
                    .unwrap_or_default();
                let valid = has_valid_question_solution(thread, format, &original_posts, &posts);
                thread_matches_status(valid, format.is_question(), status)
            })
            .filter_map(|thread| {
                let first_body_md = original_bodies.get(&thread.id).cloned().unwrap_or_default();
                let format = category_formats
                    .get(&thread.category_id)
                    .copied()
                    .unwrap_or_default();
                let valid_post = format
                    .is_question()
                    .then(|| valid_accepted_post(thread, &original_posts, &posts))
                    .flatten();
                let valid_solution = valid_post.is_some();
                let accepted_body_md = valid_post
                    .and_then(|post| posts_by_id.get(&post.id))
                    .map(|post| post.body_md.clone())
                    .unwrap_or_default();
                let post_count = post_counts.get(&thread.id).copied().unwrap_or_default();
                let matched_in_solution = accepted_body_md.to_lowercase().contains(&needle);
                let matches = thread.title.to_lowercase().contains(&needle)
                    || first_body_md.to_lowercase().contains(&needle)
                    || matched_in_solution;
                matches.then(|| ThreadSearchHit {
                    thread: public_thread(thread.clone(), valid_solution),
                    first_body_md,
                    accepted_body_md,
                    matched_in_solution,
                    reply_count: (post_count - 1).max(0),
                })
            })
            .collect();
        hits.sort_by(|a, b| thread_display_order(&a.thread, &b.thread));
        hits.truncate(limit as usize);
        Ok(hits)
    }

    async fn get_thread(&self, id: &str) -> Result<Option<Thread>, StoreError> {
        Ok(self
            .threads
            .lock()
            .expect("threads lock poisoned")
            .iter()
            .find(|t| t.id == id)
            .cloned())
    }

    async fn thread_digests(&self, limit: i64) -> Result<Vec<ThreadDigest>, StoreError> {
        // Most-recently-active threads, capped — same ordering as `recent_threads`.
        let mut threads: Vec<Thread> = self.threads.lock().expect("threads lock poisoned").clone();
        threads.sort_by(|a, b| {
            b.last_at
                .cmp(&a.last_at)
                .then_with(|| b.created_at.cmp(&a.created_at))
                .then_with(|| b.id.cmp(&a.id))
        });
        threads.truncate(limit.max(0) as usize);
        // Clone the posts once, then resolve each thread's explicit original-post identity.
        let posts: Vec<Post> = self.posts.lock().expect("posts lock poisoned").clone();
        let original_posts = self
            .original_posts
            .lock()
            .expect("original_posts lock poisoned")
            .clone();
        let digests = threads
            .into_iter()
            .map(|t| {
                let first_body_md = posts
                    .iter()
                    .find(|post| original_posts.get(&t.id) == Some(&post.id))
                    .map(|p| p.body_md.clone())
                    .unwrap_or_default();
                ThreadDigest {
                    id: t.id,
                    category_id: t.category_id,
                    title: t.title,
                    first_body_md,
                }
            })
            .collect();
        Ok(digests)
    }

    async fn count_posts(&self, thread_id: &str) -> Result<i64, StoreError> {
        Ok(self
            .posts
            .lock()
            .expect("posts lock poisoned")
            .iter()
            .filter(|p| p.thread_id == thread_id)
            .count() as i64)
    }

    async fn get_post(&self, id: &str) -> Result<Option<Post>, StoreError> {
        Ok(self
            .posts
            .lock()
            .expect("posts lock poisoned")
            .iter()
            .find(|p| p.id == id)
            .cloned())
    }

    async fn get_valid_accepted_post(&self, thread_id: &str) -> Result<Option<Post>, StoreError> {
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        let thread = self
            .threads
            .lock()
            .expect("threads lock poisoned")
            .iter()
            .find(|thread| thread.id == thread_id)
            .cloned();
        let original_posts = self
            .original_posts
            .lock()
            .expect("original_posts lock poisoned");
        let posts = self.posts.lock().expect("posts lock poisoned");
        Ok(thread
            .as_ref()
            .and_then(|thread| valid_accepted_post(thread, &original_posts, &posts))
            .cloned())
    }

    async fn posts_in_thread(&self, thread_id: &str) -> Result<Vec<Post>, StoreError> {
        let op_id = self
            .original_posts
            .lock()
            .expect("original_posts lock poisoned")
            .get(thread_id)
            .cloned();
        let mut v: Vec<Post> = self
            .posts
            .lock()
            .expect("posts lock poisoned")
            .iter()
            .filter(|p| p.thread_id == thread_id)
            .cloned()
            .collect();
        v.sort_by(|a, b| {
            (op_id.as_deref() != Some(a.id.as_str()))
                .cmp(&(op_id.as_deref() != Some(b.id.as_str())))
                .then_with(|| {
                    a.created_at
                        .cmp(&b.created_at)
                        .then_with(|| a.id.cmp(&b.id))
                })
        });
        Ok(v)
    }

    async fn first_post_in_thread(&self, thread_id: &str) -> Result<Option<Post>, StoreError> {
        let op_id = self
            .original_posts
            .lock()
            .expect("original_posts lock poisoned")
            .get(thread_id)
            .cloned();
        Ok(self
            .posts
            .lock()
            .expect("posts lock poisoned")
            .iter()
            .find(|post| op_id.as_deref() == Some(post.id.as_str()))
            .cloned())
    }

    async fn replies_page(
        &self,
        thread_id: &str,
        op_id: &str,
        excluded_post_id: Option<&str>,
        anchor: &ReplyAnchor,
        limit: i64,
    ) -> Result<Vec<Post>, StoreError> {
        // Replies are every post in the thread except the original and the separately-rendered
        // accepted solution. Excluding the solution before LIMIT keeps every page full and avoids
        // rendering it twice when its natural position falls inside the current page.
        let mut v: Vec<Post> = self
            .posts
            .lock()
            .expect("posts lock poisoned")
            .iter()
            .filter(|p| {
                p.thread_id == thread_id
                    && p.id != op_id
                    && excluded_post_id.map(|id| p.id != id).unwrap_or(true)
            })
            .cloned()
            .collect();
        // Same keyset predicate as the SQL path: strictly newer/older than the composite cursor.
        match anchor {
            ReplyAnchor::First | ReplyAnchor::Latest => {}
            ReplyAnchor::From(ts, id) => {
                v.retain(|p| {
                    p.created_at > *ts || (p.created_at == *ts && p.id.as_str() >= id.as_str())
                });
            }
            ReplyAnchor::After(ts, id) => {
                v.retain(|p| {
                    p.created_at > *ts || (p.created_at == *ts && p.id.as_str() > id.as_str())
                });
            }
            ReplyAnchor::Before(ts, id) => {
                v.retain(|p| {
                    p.created_at < *ts || (p.created_at == *ts && p.id.as_str() < id.as_str())
                });
            }
            ReplyAnchor::Around(ts, id) => {
                v.retain(|p| {
                    p.created_at < *ts || (p.created_at == *ts && p.id.as_str() <= id.as_str())
                });
            }
        }
        // First/After walk ascending; Before/Latest walk descending — matching the SQL ORDER BY.
        match anchor {
            ReplyAnchor::First | ReplyAnchor::From(..) | ReplyAnchor::After(..) => {
                v.sort_by(|a, b| {
                    a.created_at
                        .cmp(&b.created_at)
                        .then_with(|| a.id.cmp(&b.id))
                });
            }
            ReplyAnchor::Before(..) | ReplyAnchor::Latest | ReplyAnchor::Around(..) => {
                v.sort_by(|a, b| {
                    b.created_at
                        .cmp(&a.created_at)
                        .then_with(|| b.id.cmp(&a.id))
                });
            }
        }
        v.truncate(limit.max(0) as usize);
        Ok(v)
    }

    async fn create_thread(&self, thread: &Thread, first_post: &Post) -> Result<(), StoreError> {
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        if first_post.thread_id != thread.id {
            return Err(StoreError::InvalidOperation(
                "the original post must belong to the new thread".to_string(),
            ));
        }
        let categories = self.categories.lock().expect("categories lock poisoned");
        if categories
            .iter()
            .all(|category| category.id != thread.category_id)
        {
            return Err(StoreError::NotFound("category not found".to_string()));
        }
        let mut threads = self.threads.lock().expect("threads lock poisoned");
        let mut original_posts = self
            .original_posts
            .lock()
            .expect("original_posts lock poisoned");
        let mut posts = self.posts.lock().expect("posts lock poisoned");
        self.register_identity_alias(
            &first_post.author_sub,
            &first_post.author_email,
            first_post.created_at,
        );
        self.catch_up_state
            .lock()
            .expect("catch_up_state lock poisoned")
            .append_post(first_post)?;
        threads.push(thread.clone());
        original_posts.insert(thread.id.clone(), first_post.id.clone());
        posts.push(first_post.clone());
        Ok(())
    }

    async fn create_thread_with_activity(
        &self,
        thread: &Thread,
        first_post: &Post,
        mentioned_usernames: &[String],
        activity_id: &str,
    ) -> Result<ActivityMutation, StoreError> {
        let mentioned_aliases = bounded_mention_aliases(mentioned_usernames)?;
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        if first_post.thread_id != thread.id {
            return Err(StoreError::InvalidOperation(
                "the original post must belong to the new thread".to_string(),
            ));
        }
        let categories = self.categories.lock().expect("categories lock poisoned");
        if categories
            .iter()
            .all(|category| category.id != thread.category_id)
        {
            return Err(StoreError::NotFound("category not found".to_string()));
        }
        let mut threads = self.threads.lock().expect("threads lock poisoned");
        let mut original_posts = self
            .original_posts
            .lock()
            .expect("original_posts lock poisoned");
        let mut posts = self.posts.lock().expect("posts lock poisoned");
        let mut mentions = self.mentions.lock().expect("mentions lock poisoned");

        self.register_identity_alias(
            &first_post.author_sub,
            &first_post.author_email,
            first_post.created_at,
        );
        let mut deliveries =
            self.resolve_mention_deliveries(&mentioned_aliases, &first_post.author_sub);
        dedupe_deliveries(&mut deliveries);

        self.catch_up_state
            .lock()
            .expect("catch_up_state lock poisoned")
            .append_post(first_post)?;
        threads.push(thread.clone());
        original_posts.insert(thread.id.clone(), first_post.id.clone());
        posts.push(first_post.clone());
        let mut seen = HashSet::new();
        for name in &mentioned_aliases {
            if seen.insert(name.as_str()) {
                mentions.push(Mention {
                    post_id: first_post.id.clone(),
                    thread_id: thread.id.clone(),
                    mentioned_username: name.clone(),
                    created_at: first_post.created_at,
                });
            }
        }

        if !deliveries.is_empty() {
            self.activity_events
                .lock()
                .expect("activity_events lock poisoned")
                .push(ActivityEvent {
                    id: activity_id.to_string(),
                    kind: ActivityKind::PostCreated,
                    thread_id: thread.id.clone(),
                    post_id: first_post.id.clone(),
                    actor_sub: first_post.author_sub.clone(),
                    created_at: first_post.created_at,
                });
            let mut stored = self
                .activity_deliveries
                .lock()
                .expect("activity_deliveries lock poisoned");
            stored.extend(
                deliveries
                    .iter()
                    .cloned()
                    .map(|delivery| StoredActivityDelivery {
                        activity_id: activity_id.to_string(),
                        delivery,
                    }),
            );
        }
        Ok(ActivityMutation {
            delivery_subjects: delivery_subjects(&deliveries),
        })
    }

    async fn add_reply(&self, post: &Post) -> Result<(), StoreError> {
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        let categories = self.categories.lock().expect("categories lock poisoned");
        let mut threads = self.threads.lock().expect("threads lock poisoned");
        let thread = threads
            .iter_mut()
            .find(|thread| thread.id == post.thread_id)
            .ok_or_else(|| StoreError::NotFound("thread not found".to_string()))?;
        if categories
            .iter()
            .all(|category| category.id != thread.category_id)
        {
            return Err(StoreError::NotFound("category not found".to_string()));
        }
        if thread.locked {
            return Err(StoreError::InvalidOperation(
                "this thread is locked — no new replies".to_string(),
            ));
        }
        let mut posts = self.posts.lock().expect("posts lock poisoned");
        if !post.quoted_post_id.is_empty()
            && posts.iter().all(|quoted| {
                quoted.id != post.quoted_post_id || quoted.thread_id != post.thread_id
            })
        {
            return Err(StoreError::InvalidOperation(
                "quoted post must belong to this thread".to_string(),
            ));
        }
        self.register_identity_alias(&post.author_sub, &post.author_email, post.created_at);
        self.catch_up_state
            .lock()
            .expect("catch_up_state lock poisoned")
            .append_post(post)?;
        posts.push(post.clone());
        thread.last_at = post.created_at;
        Ok(())
    }

    async fn add_reply_with_activity(
        &self,
        post: &Post,
        mentioned_usernames: &[String],
        activity_id: &str,
    ) -> Result<ActivityMutation, StoreError> {
        let mentioned_aliases = bounded_mention_aliases(mentioned_usernames)?;
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        let categories = self.categories.lock().expect("categories lock poisoned");
        let mut threads = self.threads.lock().expect("threads lock poisoned");
        let thread = threads
            .iter_mut()
            .find(|thread| thread.id == post.thread_id)
            .ok_or_else(|| StoreError::NotFound("thread not found".to_string()))?;
        if categories
            .iter()
            .all(|category| category.id != thread.category_id)
        {
            return Err(StoreError::NotFound("category not found".to_string()));
        }
        if thread.locked {
            return Err(StoreError::InvalidOperation(
                "this thread is locked — no new replies".to_string(),
            ));
        }
        let mut posts = self.posts.lock().expect("posts lock poisoned");
        let quoted_author = if post.quoted_post_id.is_empty() {
            None
        } else {
            Some(
                posts
                    .iter()
                    .find(|quoted| {
                        quoted.id == post.quoted_post_id && quoted.thread_id == post.thread_id
                    })
                    .ok_or_else(|| {
                        StoreError::InvalidOperation(
                            "quoted post must belong to this thread".to_string(),
                        )
                    })?
                    .author_sub
                    .clone(),
            )
        };
        let subscriptions = self
            .subscriptions
            .lock()
            .expect("subscriptions lock poisoned");
        let follower_count = subscriptions
            .iter()
            .filter(|subscription| {
                subscription.thread_id == post.thread_id
                    && subscription.level.delivers_generic_activity()
            })
            .count();
        if follower_count > MAX_THREAD_FOLLOWERS {
            return Err(StoreError::InvalidOperation(format!(
                "a thread may have at most {MAX_THREAD_FOLLOWERS} followers"
            )));
        }
        let mut deliveries = Vec::new();
        if let Some(delivery) =
            subject_delivery(&thread.author_sub, &post.author_sub, ActivityReason::Reply)
        {
            deliveries.push(delivery);
        }
        if let Some(quoted_author) = quoted_author.as_deref() {
            if let Some(delivery) =
                subject_delivery(quoted_author, &post.author_sub, ActivityReason::Reply)
            {
                deliveries.push(delivery);
            }
        }
        deliveries.extend(
            subscriptions
                .iter()
                .filter(|subscription| {
                    subscription.thread_id == post.thread_id
                        && subscription.level.delivers_generic_activity()
                })
                .filter_map(|subscription| {
                    subject_delivery(
                        &subscription.subscriber_sub,
                        &post.author_sub,
                        ActivityReason::Following,
                    )
                }),
        );
        self.register_identity_alias(&post.author_sub, &post.author_email, post.created_at);
        deliveries.extend(self.resolve_mention_deliveries(&mentioned_aliases, &post.author_sub));
        dedupe_deliveries(&mut deliveries);

        self.catch_up_state
            .lock()
            .expect("catch_up_state lock poisoned")
            .append_post(post)?;
        posts.push(post.clone());
        thread.last_at = post.created_at;
        let mut mentions = self.mentions.lock().expect("mentions lock poisoned");
        mentions.retain(|mention| mention.post_id != post.id);
        let mut seen = HashSet::new();
        for name in &mentioned_aliases {
            if seen.insert(name.as_str()) {
                mentions.push(Mention {
                    post_id: post.id.clone(),
                    thread_id: post.thread_id.clone(),
                    mentioned_username: name.clone(),
                    created_at: post.created_at,
                });
            }
        }
        if !deliveries.is_empty() {
            self.activity_events
                .lock()
                .expect("activity_events lock poisoned")
                .push(ActivityEvent {
                    id: activity_id.to_string(),
                    kind: ActivityKind::PostCreated,
                    thread_id: post.thread_id.clone(),
                    post_id: post.id.clone(),
                    actor_sub: post.author_sub.clone(),
                    created_at: post.created_at,
                });
            let mut stored = self
                .activity_deliveries
                .lock()
                .expect("activity_deliveries lock poisoned");
            stored.extend(
                deliveries
                    .iter()
                    .cloned()
                    .map(|delivery| StoredActivityDelivery {
                        activity_id: activity_id.to_string(),
                        delivery,
                    }),
            );
        }
        Ok(ActivityMutation {
            delivery_subjects: delivery_subjects(&deliveries),
        })
    }

    async fn replace_mentions(
        &self,
        post_id: &str,
        thread_id: &str,
        mentioned_usernames: &[String],
        created_at: i64,
    ) -> Result<(), StoreError> {
        let mut mentions = self.mentions.lock().expect("mentions lock poisoned");
        mentions.retain(|m| m.post_id != post_id);
        let mut seen = HashSet::new();
        for name in mentioned_usernames {
            if seen.insert(name.as_str()) {
                mentions.push(Mention {
                    post_id: post_id.to_string(),
                    thread_id: thread_id.to_string(),
                    mentioned_username: name.to_string(),
                    created_at,
                });
            }
        }
        Ok(())
    }

    async fn count_mentions_for_user(&self, mentioned_username: &str) -> Result<i64, StoreError> {
        Ok(self
            .mentions
            .lock()
            .expect("mentions lock poisoned")
            .iter()
            .filter(|m| m.mentioned_username == mentioned_username)
            .count() as i64)
    }

    async fn mentions_for_user(
        &self,
        mentioned_username: &str,
        limit: i64,
    ) -> Result<Vec<Mention>, StoreError> {
        let mut v: Vec<Mention> = self
            .mentions
            .lock()
            .expect("mentions lock poisoned")
            .iter()
            .filter(|m| m.mentioned_username == mentioned_username)
            .cloned()
            .collect();
        v.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.post_id.cmp(&a.post_id))
        });
        v.truncate(limit.max(0) as usize);
        Ok(v)
    }

    async fn update_thread(
        &self,
        thread_id: &str,
        title: &str,
        op_post_id: &str,
        body_md: &str,
    ) -> Result<(), StoreError> {
        if self
            .original_posts
            .lock()
            .expect("original_posts lock poisoned")
            .get(thread_id)
            .is_some_and(|stored| stored != op_post_id)
        {
            return Err(StoreError::InvalidOperation(
                "thread update must target its original post".to_string(),
            ));
        }
        // Lock order threads-then-posts matches `create_thread`/`delete_thread` (no deadlock).
        {
            let mut threads = self.threads.lock().expect("threads lock poisoned");
            if let Some(t) = threads.iter_mut().find(|t| t.id == thread_id) {
                t.title = title.to_string();
            }
        }
        let mut posts = self.posts.lock().expect("posts lock poisoned");
        if let Some(p) = posts.iter_mut().find(|p| p.id == op_post_id) {
            p.body_md = body_md.to_string();
        }
        Ok(())
    }

    async fn delete_thread(&self, thread_id: &str) -> Result<(), StoreError> {
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        let _category_hint = self
            .threads
            .lock()
            .expect("threads lock poisoned")
            .iter()
            .find(|thread| thread.id == thread_id)
            .map(|thread| thread.category_id.clone());
        let categories = self.categories.lock().expect("categories lock poisoned");
        let mut threads = self.threads.lock().expect("threads lock poisoned");
        let mut original_posts = self
            .original_posts
            .lock()
            .expect("original_posts lock poisoned");
        let mut posts = self.posts.lock().expect("posts lock poisoned");
        let removed_ids: HashSet<String> = posts
            .iter()
            .filter(|post| post.thread_id == thread_id)
            .map(|post| post.id.clone())
            .collect();
        threads.retain(|thread| thread.id != thread_id);
        posts.retain(|post| post.thread_id != thread_id);
        original_posts.remove(thread_id);
        drop(posts);
        drop(original_posts);
        drop(threads);
        drop(categories);
        self.bookmarks
            .lock()
            .expect("bookmarks lock poisoned")
            .retain(|bookmark| !removed_ids.contains(&bookmark.post_id));
        let mut reactions = self.reactions.lock().expect("reactions lock poisoned");
        reactions.retain(|reaction| !removed_ids.contains(&reaction.post_id));
        let mut mentions = self.mentions.lock().expect("mentions lock poisoned");
        mentions.retain(|m| m.thread_id != thread_id);
        let mut subscriptions = self
            .subscriptions
            .lock()
            .expect("subscriptions lock poisoned");
        subscriptions.retain(|s| s.thread_id != thread_id);
        let mut events = self
            .activity_events
            .lock()
            .expect("activity_events lock poisoned");
        let removed_activity_ids: HashSet<String> = events
            .iter()
            .filter(|event| event.thread_id == thread_id)
            .map(|event| event.id.clone())
            .collect();
        events.retain(|event| event.thread_id != thread_id);
        self.activity_deliveries
            .lock()
            .expect("activity_deliveries lock poisoned")
            .retain(|stored| !removed_activity_ids.contains(&stored.activity_id));
        self.activity_receipts
            .lock()
            .expect("activity_receipts lock poisoned")
            .retain(|receipt| !removed_activity_ids.contains(&receipt.activity_id));
        let mut catch_up = self
            .catch_up_state
            .lock()
            .expect("catch_up_state lock poisoned");
        catch_up
            .post_points
            .retain(|point| point.thread_id != thread_id);
        catch_up
            .read_receipts
            .retain(|(_, post_id), _| !removed_ids.contains(post_id));
        Ok(())
    }

    async fn update_post(&self, post_id: &str, body_md: &str) -> Result<(), StoreError> {
        let mut posts = self.posts.lock().expect("posts lock poisoned");
        if let Some(p) = posts.iter_mut().find(|p| p.id == post_id) {
            p.body_md = body_md.to_string();
        }
        Ok(())
    }

    async fn delete_post(&self, post_id: &str) -> Result<(), StoreError> {
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        let thread_hint = self
            .posts
            .lock()
            .expect("posts lock poisoned")
            .iter()
            .find(|post| post.id == post_id)
            .map(|post| post.thread_id.clone());
        let Some(thread_id) = thread_hint else {
            return Ok(());
        };
        let _category_hint = self
            .threads
            .lock()
            .expect("threads lock poisoned")
            .iter()
            .find(|thread| thread.id == thread_id)
            .map(|thread| thread.category_id.clone())
            .ok_or_else(|| StoreError::NotFound("thread not found".to_string()))?;

        let categories = self.categories.lock().expect("categories lock poisoned");
        let mut threads = self.threads.lock().expect("threads lock poisoned");
        let original_posts = self
            .original_posts
            .lock()
            .expect("original_posts lock poisoned");
        let mut posts = self.posts.lock().expect("posts lock poisoned");
        let Some(post) = posts.iter().find(|post| post.id == post_id) else {
            return Ok(());
        };
        if post.thread_id != thread_id {
            return Err(StoreError::Backend(
                "post changed thread during guarded delete".to_string(),
            ));
        }
        let op_id = original_posts.get(&thread_id).cloned();
        if op_id.as_deref() == Some(post_id) {
            return Err(StoreError::InvalidOperation(
                "the original post cannot be deleted separately; delete the thread".to_string(),
            ));
        }
        for post in posts
            .iter_mut()
            .filter(|post| post.quoted_post_id == post_id)
        {
            post.quoted_post_id.clear();
        }
        posts.retain(|post| post.id != post_id);
        let newest_at = posts
            .iter()
            .filter(|post| post.thread_id == thread_id)
            .map(|post| post.created_at)
            .max();
        if let Some(thread) = threads.iter_mut().find(|thread| thread.id == thread_id) {
            if thread.accepted_post_id == post_id
                || op_id.as_deref() == Some(thread.accepted_post_id.as_str())
            {
                thread.accepted_post_id.clear();
            }
            thread.last_at = newest_at.unwrap_or(thread.created_at);
        }
        drop(posts);
        drop(original_posts);
        drop(threads);
        drop(categories);

        self.bookmarks
            .lock()
            .expect("bookmarks lock poisoned")
            .retain(|bookmark| bookmark.post_id != post_id);
        self.reactions
            .lock()
            .expect("reactions lock poisoned")
            .retain(|reaction| reaction.post_id != post_id);
        self.mentions
            .lock()
            .expect("mentions lock poisoned")
            .retain(|mention| mention.post_id != post_id);
        let mut events = self
            .activity_events
            .lock()
            .expect("activity_events lock poisoned");
        let removed_activity_ids: HashSet<String> = events
            .iter()
            .filter(|event| event.post_id == post_id)
            .map(|event| event.id.clone())
            .collect();
        events.retain(|event| event.post_id != post_id);
        self.activity_deliveries
            .lock()
            .expect("activity_deliveries lock poisoned")
            .retain(|stored| !removed_activity_ids.contains(&stored.activity_id));
        self.activity_receipts
            .lock()
            .expect("activity_receipts lock poisoned")
            .retain(|receipt| !removed_activity_ids.contains(&receipt.activity_id));
        // The read authority is live-post scoped and disappears with the post. Its append-only
        // activity point deliberately remains so deleting the newest reply cannot move the thread
        // backward between pages of an already-issued snapshot.
        self.catch_up_state
            .lock()
            .expect("catch_up_state lock poisoned")
            .read_receipts
            .retain(|(_, receipt_post_id), _| receipt_post_id != post_id);
        Ok(())
    }

    async fn set_thread_locked(&self, thread_id: &str, locked: bool) -> Result<(), StoreError> {
        let mut threads = self.threads.lock().expect("threads lock poisoned");
        if let Some(t) = threads.iter_mut().find(|t| t.id == thread_id) {
            t.locked = locked;
        }
        Ok(())
    }

    async fn set_thread_pinned(&self, thread_id: &str, pinned: bool) -> Result<(), StoreError> {
        let mut threads = self.threads.lock().expect("threads lock poisoned");
        if let Some(t) = threads.iter_mut().find(|t| t.id == thread_id) {
            t.pinned = pinned;
        }
        Ok(())
    }

    async fn move_thread_to_category(
        &self,
        thread_id: &str,
        category_id: &str,
    ) -> Result<(), StoreError> {
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        let source_hint = self
            .threads
            .lock()
            .expect("threads lock poisoned")
            .iter()
            .find(|thread| thread.id == thread_id)
            .map(|thread| thread.category_id.clone())
            .ok_or_else(|| StoreError::NotFound("thread not found".to_string()))?;

        let categories = self.categories.lock().expect("categories lock poisoned");
        if categories.iter().all(|category| category.id != source_hint) {
            return Err(StoreError::NotFound(
                "source category not found".to_string(),
            ));
        }
        let target = categories
            .iter()
            .find(|category| category.id == category_id)
            .ok_or_else(|| StoreError::InvalidOperation("unknown category".to_string()))?;
        let mut threads = self.threads.lock().expect("threads lock poisoned");
        let thread = threads
            .iter_mut()
            .find(|thread| thread.id == thread_id)
            .ok_or_else(|| StoreError::NotFound("thread not found".to_string()))?;
        let original_posts = self
            .original_posts
            .lock()
            .expect("original_posts lock poisoned");
        let posts = self.posts.lock().expect("posts lock poisoned");
        let valid_solution = valid_accepted_post(thread, &original_posts, &posts).is_some();
        if thread.category_id != category_id && valid_solution && !target.format.is_question() {
            return Err(StoreError::InvalidOperation(
                "unmark the accepted answer before moving this thread to a discussion category"
                    .to_string(),
            ));
        }
        if !thread.accepted_post_id.is_empty() && !valid_solution {
            thread.accepted_post_id.clear();
        }
        thread.category_id = category_id.to_string();
        Ok(())
    }

    async fn mutate_accepted_answer(
        &self,
        thread_id: &str,
        action: AcceptedAnswerAction,
    ) -> Result<AcceptedAnswerMutation, StoreError> {
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        let category_hint = self
            .threads
            .lock()
            .expect("threads lock poisoned")
            .iter()
            .find(|thread| thread.id == thread_id)
            .map(|thread| thread.category_id.clone())
            .ok_or_else(|| StoreError::NotFound("thread not found".to_string()))?;
        let categories = self.categories.lock().expect("categories lock poisoned");
        let category = categories
            .iter()
            .find(|category| category.id == category_hint)
            .ok_or_else(|| StoreError::NotFound("category not found".to_string()))?;
        let mut threads = self.threads.lock().expect("threads lock poisoned");
        let thread = threads
            .iter_mut()
            .find(|thread| thread.id == thread_id)
            .ok_or_else(|| StoreError::NotFound("thread not found".to_string()))?;
        let original_posts = self
            .original_posts
            .lock()
            .expect("original_posts lock poisoned");
        let posts = self.posts.lock().expect("posts lock poisoned");

        let (accepted_post, next_id) = match action {
            AcceptedAnswerAction::Clear => (None, String::new()),
            AcceptedAnswerAction::Accept { post_id } => {
                if !category.format.is_question() {
                    return Err(StoreError::InvalidOperation(
                        "accepted answers are available only in question categories".to_string(),
                    ));
                }
                let post_id = post_id.trim();
                if post_id.is_empty() {
                    return Err(StoreError::InvalidOperation(
                        "reply is required when accepting an answer".to_string(),
                    ));
                }
                if original_posts.get(thread_id).map(String::as_str) == Some(post_id) {
                    return Err(StoreError::InvalidOperation(
                        "the original post cannot be the accepted answer".to_string(),
                    ));
                }
                let post = posts
                    .iter()
                    .find(|post| post.id == post_id && post.thread_id == thread_id)
                    .cloned()
                    .ok_or_else(|| StoreError::NotFound("reply not found".to_string()))?;
                (Some(post), post_id.to_string())
            }
        };
        let changed = thread.accepted_post_id != next_id;
        thread.accepted_post_id = next_id;
        Ok(AcceptedAnswerMutation {
            thread: thread.clone(),
            accepted_post,
            changed,
            delivery_subjects: Vec::new(),
        })
    }

    async fn mutate_accepted_answer_with_activity(
        &self,
        thread_id: &str,
        action: AcceptedAnswerAction,
        activity_id: &str,
        actor_sub: &str,
        created_at: i64,
    ) -> Result<AcceptedAnswerMutation, StoreError> {
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        let category_hint = self
            .threads
            .lock()
            .expect("threads lock poisoned")
            .iter()
            .find(|thread| thread.id == thread_id)
            .map(|thread| thread.category_id.clone())
            .ok_or_else(|| StoreError::NotFound("thread not found".to_string()))?;
        let categories = self.categories.lock().expect("categories lock poisoned");
        let category = categories
            .iter()
            .find(|category| category.id == category_hint)
            .ok_or_else(|| StoreError::NotFound("category not found".to_string()))?;
        let mut threads = self.threads.lock().expect("threads lock poisoned");
        let thread = threads
            .iter_mut()
            .find(|thread| thread.id == thread_id)
            .ok_or_else(|| StoreError::NotFound("thread not found".to_string()))?;
        let original_posts = self
            .original_posts
            .lock()
            .expect("original_posts lock poisoned");
        let posts = self.posts.lock().expect("posts lock poisoned");
        let (accepted_post, next_id) = match action {
            AcceptedAnswerAction::Clear => (None, String::new()),
            AcceptedAnswerAction::Accept { post_id } => {
                if !category.format.is_question() {
                    return Err(StoreError::InvalidOperation(
                        "accepted answers are available only in question categories".to_string(),
                    ));
                }
                let post_id = post_id.trim();
                if post_id.is_empty() {
                    return Err(StoreError::InvalidOperation(
                        "reply is required when accepting an answer".to_string(),
                    ));
                }
                if original_posts.get(thread_id).map(String::as_str) == Some(post_id) {
                    return Err(StoreError::InvalidOperation(
                        "the original post cannot be the accepted answer".to_string(),
                    ));
                }
                let post = posts
                    .iter()
                    .find(|post| post.id == post_id && post.thread_id == thread_id)
                    .cloned()
                    .ok_or_else(|| StoreError::NotFound("reply not found".to_string()))?;
                (Some(post), post_id.to_string())
            }
        };
        let changed = thread.accepted_post_id != next_id;
        thread.accepted_post_id = next_id;
        let mut deliveries = Vec::new();
        if changed {
            if let Some(post) = accepted_post.as_ref() {
                if let Some(delivery) =
                    subject_delivery(&post.author_sub, actor_sub, ActivityReason::Answer)
                {
                    deliveries.push(delivery);
                }
            }
        }
        if !deliveries.is_empty() {
            self.activity_events
                .lock()
                .expect("activity_events lock poisoned")
                .push(ActivityEvent {
                    id: activity_id.to_string(),
                    kind: ActivityKind::AnswerAccepted,
                    thread_id: thread_id.to_string(),
                    post_id: accepted_post
                        .as_ref()
                        .map(|post| post.id.clone())
                        .unwrap_or_default(),
                    actor_sub: actor_sub.to_string(),
                    created_at,
                });
            let mut stored = self
                .activity_deliveries
                .lock()
                .expect("activity_deliveries lock poisoned");
            stored.extend(
                deliveries
                    .iter()
                    .cloned()
                    .map(|delivery| StoredActivityDelivery {
                        activity_id: activity_id.to_string(),
                        delivery,
                    }),
            );
        }
        Ok(AcceptedAnswerMutation {
            thread: thread.clone(),
            accepted_post,
            changed,
            delivery_subjects: delivery_subjects(&deliveries),
        })
    }

    async fn set_thread_follow_level(
        &self,
        thread_id: &str,
        subscriber_sub: &str,
        level: ThreadFollowLevel,
        created_at: i64,
    ) -> Result<(), StoreError> {
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        if self
            .threads
            .lock()
            .expect("threads lock poisoned")
            .iter()
            .all(|thread| thread.id != thread_id)
        {
            return Err(StoreError::NotFound("thread not found".to_string()));
        }
        let mut subscriptions = self
            .subscriptions
            .lock()
            .expect("subscriptions lock poisoned");
        let existing = subscriptions
            .iter()
            .position(|s| s.thread_id == thread_id && s.subscriber_sub == subscriber_sub);
        let was_watch = existing
            .is_some_and(|position| subscriptions[position].level.delivers_generic_activity());
        if level.delivers_generic_activity() && !was_watch {
            let watcher_count = subscriptions
                .iter()
                .filter(|row| row.thread_id == thread_id && row.level.delivers_generic_activity())
                .count();
            if watcher_count >= MAX_THREAD_FOLLOWERS {
                return Err(StoreError::InvalidOperation(format!(
                    "a thread may have at most {MAX_THREAD_FOLLOWERS} watchers"
                )));
            }
        }
        match (level, existing) {
            (ThreadFollowLevel::None, Some(position)) => {
                subscriptions.remove(position);
            }
            (ThreadFollowLevel::None, None) => {}
            (next, Some(position)) => {
                subscriptions[position].level = next;
                subscriptions[position]._created_at = created_at;
            }
            (next, None) => subscriptions.push(ThreadSubscription {
                thread_id: thread_id.to_string(),
                subscriber_sub: subscriber_sub.to_string(),
                level: next,
                _created_at: created_at,
            }),
        }
        drop(subscriptions);

        // Leaving Watch is immediately authoritative for generic follower Activity. Remove only
        // that delivery path; a direct reply, mention, or accepted-answer delivery for the same
        // event survives together with its existing read receipt.
        if !level.delivers_generic_activity() {
            let mut events = self
                .activity_events
                .lock()
                .expect("activity_events lock poisoned");
            let thread_event_ids: HashSet<String> = events
                .iter()
                .filter(|event| event.thread_id == thread_id)
                .map(|event| event.id.clone())
                .collect();
            let mut deliveries = self
                .activity_deliveries
                .lock()
                .expect("activity_deliveries lock poisoned");
            deliveries.retain(|stored| {
                !thread_event_ids.contains(&stored.activity_id)
                    || stored.delivery.recipient_kind != ActivityRecipientKind::Subject
                    || stored.delivery.recipient_key != subscriber_sub
                    || stored.delivery.reason != ActivityReason::Following
            });
            let remaining_for_viewer: HashSet<String> = deliveries
                .iter()
                .filter(|stored| {
                    stored.delivery.recipient_kind == ActivityRecipientKind::Subject
                        && stored.delivery.recipient_key == subscriber_sub
                })
                .map(|stored| stored.activity_id.clone())
                .collect();
            let delivered_event_ids: HashSet<String> = deliveries
                .iter()
                .map(|stored| stored.activity_id.clone())
                .collect();
            let orphan_event_ids: HashSet<String> = thread_event_ids
                .iter()
                .filter(|activity_id| !delivered_event_ids.contains(*activity_id))
                .cloned()
                .collect();
            events.retain(|event| !orphan_event_ids.contains(&event.id));
            deliveries.retain(|stored| !orphan_event_ids.contains(&stored.activity_id));
            drop(deliveries);
            drop(events);
            self.activity_receipts
                .lock()
                .expect("activity_receipts lock poisoned")
                .retain(|receipt| {
                    !orphan_event_ids.contains(&receipt.activity_id)
                        && (receipt.viewer_sub != subscriber_sub
                            || !thread_event_ids.contains(&receipt.activity_id)
                            || remaining_for_viewer.contains(&receipt.activity_id))
                });
        }
        Ok(())
    }

    async fn thread_follow_level(
        &self,
        thread_id: &str,
        subscriber_sub: &str,
    ) -> Result<ThreadFollowLevel, StoreError> {
        Ok(self
            .subscriptions
            .lock()
            .expect("subscriptions lock poisoned")
            .iter()
            .find(|s| s.thread_id == thread_id && s.subscriber_sub == subscriber_sub)
            .map(|row| row.level)
            .unwrap_or_default())
    }

    async fn thread_personal_signals(
        &self,
        viewer_sub: &str,
        thread_ids: &[String],
    ) -> Result<HashMap<String, ThreadPersonalSignals>, StoreError> {
        let thread_ids = bounded_personal_thread_ids(thread_ids)?;
        if thread_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let requested: HashSet<&str> = thread_ids.iter().map(String::as_str).collect();
        let (threads, posts) = {
            let _domain = self.qa_guard.lock().expect("qa guard poisoned");
            let threads = self
                .threads
                .lock()
                .expect("threads lock poisoned")
                .iter()
                .filter(|thread| requested.contains(thread.id.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            let posts = self.posts.lock().expect("posts lock poisoned").clone();
            (threads, posts)
        };
        let subscriptions = self
            .subscriptions
            .lock()
            .expect("subscriptions lock poisoned")
            .clone();
        let bookmarks = self
            .bookmarks
            .lock()
            .expect("bookmarks lock poisoned")
            .clone();
        let receipts = self
            .catch_up_state
            .lock()
            .expect("catch_up_state lock poisoned")
            .read_receipts
            .clone();
        let bookmarked_posts: HashSet<&str> = bookmarks
            .iter()
            .filter(|bookmark| bookmark.owner_sub == viewer_sub)
            .map(|bookmark| bookmark.post_id.as_str())
            .collect();
        let read_posts: HashSet<&str> = receipts
            .keys()
            .filter(|(subject, _)| subject == viewer_sub)
            .map(|(_, post_id)| post_id.as_str())
            .collect();
        let mut signals = HashMap::new();
        for thread in threads {
            let thread_posts: Vec<&Post> = posts
                .iter()
                .filter(|post| post.thread_id == thread.id)
                .collect();
            let follow_level = subscriptions
                .iter()
                .find(|row| row.thread_id == thread.id && row.subscriber_sub == viewer_sub)
                .map(|row| row.level)
                .unwrap_or_default();
            signals.insert(
                thread.id.clone(),
                ThreadPersonalSignals {
                    follow_level,
                    authored: thread.author_sub == viewer_sub,
                    participated: thread_posts
                        .iter()
                        .any(|post| post.author_sub == viewer_sub),
                    bookmarked: thread_posts
                        .iter()
                        .any(|post| bookmarked_posts.contains(post.id.as_str())),
                    reading_started: thread_posts
                        .iter()
                        .any(|post| read_posts.contains(post.id.as_str())),
                    has_unread: thread_posts
                        .iter()
                        .any(|post| !read_posts.contains(post.id.as_str())),
                },
            );
        }
        Ok(signals)
    }

    async fn category_focus_level(
        &self,
        viewer_sub: &str,
        category_id: &str,
    ) -> Result<CategoryFocusLevel, StoreError> {
        Ok(self
            .category_focus_rules
            .lock()
            .expect("category_focus_rules lock poisoned")
            .iter()
            .find(|rule| rule.viewer_sub == viewer_sub && rule.category_id == category_id)
            .map(|rule| rule.level)
            .unwrap_or_default())
    }

    async fn category_focus_rules(
        &self,
        viewer_sub: &str,
    ) -> Result<Vec<CategoryFocusRuleItem>, StoreError> {
        if viewer_sub.trim().is_empty() {
            return Ok(Vec::new());
        }
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        let categories = self.categories.lock().expect("categories lock poisoned");
        let rules = self
            .category_focus_rules
            .lock()
            .expect("category_focus_rules lock poisoned");
        let mut items = rules
            .iter()
            .filter(|rule| rule.viewer_sub == viewer_sub)
            .filter_map(|rule| {
                categories
                    .iter()
                    .find(|category| category.id == rule.category_id)
                    .cloned()
                    .map(|category| CategoryFocusRuleItem {
                        category,
                        level: rule.level,
                    })
            })
            .collect::<Vec<_>>();
        items.sort_by(|left, right| {
            left.category
                .sort_order
                .cmp(&right.category.sort_order)
                .then_with(|| left.category.id.cmp(&right.category.id))
        });
        Ok(items)
    }

    async fn set_category_focus_level(
        &self,
        viewer_sub: &str,
        category_id: &str,
        level: CategoryFocusLevel,
        changed_at: i64,
    ) -> Result<(), StoreError> {
        if viewer_sub.trim().is_empty() || changed_at < 0 {
            return Err(StoreError::InvalidOperation(
                "invalid category focus rule".to_string(),
            ));
        }
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        if self
            .categories
            .lock()
            .expect("categories lock poisoned")
            .iter()
            .all(|category| category.id != category_id)
        {
            return Err(StoreError::NotFound("category not found".to_string()));
        }
        let mut rules = self
            .category_focus_rules
            .lock()
            .expect("category_focus_rules lock poisoned");
        let existing = rules
            .iter()
            .position(|rule| rule.viewer_sub == viewer_sub && rule.category_id == category_id);
        match (level, existing) {
            (CategoryFocusLevel::None, Some(position)) => {
                rules.remove(position);
            }
            (CategoryFocusLevel::None, None) => {}
            (next, Some(position)) => {
                if rules[position].level != next {
                    rules[position].level = next;
                    rules[position]._updated_at = changed_at;
                }
            }
            (next, None) => {
                let count = rules
                    .iter()
                    .filter(|rule| rule.viewer_sub == viewer_sub)
                    .count();
                if count >= MAX_CATEGORY_FOCUS_RULES {
                    return Err(StoreError::InvalidOperation(format!(
                        "a user may keep at most {MAX_CATEGORY_FOCUS_RULES} category focus rules"
                    )));
                }
                rules.push(MemoryCategoryFocusRule {
                    viewer_sub: viewer_sub.to_string(),
                    category_id: category_id.to_string(),
                    level: next,
                    _created_at: changed_at,
                    _updated_at: changed_at,
                });
            }
        }
        Ok(())
    }

    async fn category_focus_page(
        &self,
        viewer_sub: &str,
        limit: i64,
        as_of: i64,
    ) -> Result<Vec<CategoryFocusItem>, StoreError> {
        let limit = validate_category_focus_page(limit, as_of)?;
        if limit == 0 || viewer_sub.trim().is_empty() {
            return Ok(Vec::new());
        }
        let (categories, threads, original_posts, posts, subscriptions, rules) = {
            let _domain = self.qa_guard.lock().expect("qa guard poisoned");
            (
                self.categories
                    .lock()
                    .expect("categories lock poisoned")
                    .clone(),
                self.threads.lock().expect("threads lock poisoned").clone(),
                self.original_posts
                    .lock()
                    .expect("original_posts lock poisoned")
                    .clone(),
                self.posts.lock().expect("posts lock poisoned").clone(),
                self.subscriptions
                    .lock()
                    .expect("subscriptions lock poisoned")
                    .clone(),
                self.category_focus_rules
                    .lock()
                    .expect("category_focus_rules lock poisoned")
                    .clone(),
            )
        };
        let category_rules: HashMap<&str, CategoryFocusLevel> = rules
            .iter()
            .filter(|rule| rule.viewer_sub == viewer_sub)
            .map(|rule| (rule.category_id.as_str(), rule.level))
            .collect();
        let mut items = Vec::new();
        for mut thread in threads
            .into_iter()
            .filter(|thread| thread.created_at <= as_of)
        {
            let Some(category_level) = category_rules.get(thread.category_id.as_str()).copied()
            else {
                continue;
            };
            let Some(category) = categories
                .iter()
                .find(|category| category.id == thread.category_id)
                .cloned()
            else {
                continue;
            };
            let thread_level = subscriptions
                .iter()
                .find(|row| row.thread_id == thread.id && row.subscriber_sub == viewer_sub)
                .map(|row| row.level)
                .unwrap_or_default();
            let Some(reason) = category_focus_reason(category_level, thread_level) else {
                continue;
            };
            if !category.format.is_question()
                || valid_accepted_post(&thread, &original_posts, &posts).is_none()
            {
                thread.accepted_post_id.clear();
            }
            items.push(CategoryFocusItem {
                thread,
                category,
                category_level,
                thread_level,
                reason,
            });
        }
        items.sort_by(|left, right| {
            left.reason
                .sort_bucket()
                .cmp(&right.reason.sort_bucket())
                .then_with(|| right.thread.pinned.cmp(&left.thread.pinned))
                .then_with(|| right.thread.last_at.cmp(&left.thread.last_at))
                .then_with(|| right.thread.created_at.cmp(&left.thread.created_at))
                .then_with(|| right.thread.id.cmp(&left.thread.id))
        });
        items.truncate(limit);
        Ok(items)
    }

    async fn catch_up_snapshot_generation(&self) -> Result<i64, StoreError> {
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        Ok(self
            .catch_up_state
            .lock()
            .expect("catch_up_state lock poisoned")
            .generation)
    }

    async fn catch_up_page(
        &self,
        viewer_sub: &str,
        view: CatchUpView,
        as_of: i64,
        snapshot_generation: i64,
        before: Option<&CatchUpCursor>,
        limit: i64,
    ) -> Result<Vec<CatchUpItem>, StoreError> {
        let limit = validate_catch_up_page(view, as_of, snapshot_generation, before, limit)?;
        if limit == 0 {
            return Ok(Vec::new());
        }
        let (
            categories,
            threads,
            original_posts,
            posts,
            subscriptions,
            bookmarks,
            current_generation,
            points,
            receipts,
        ) = {
            let _domain = self.qa_guard.lock().expect("qa guard poisoned");
            // Keep one Memory lock order everywhere: category/thread/post/relationship authority
            // first, Catch-up generation/receipts last. `thread_reading_states` and post/read
            // commands use the same outer domain, so no reader can hold thread/post locks while
            // waiting on Catch-up state that this projection already owns.
            let categories = self
                .categories
                .lock()
                .expect("categories lock poisoned")
                .clone();
            let threads = self.threads.lock().expect("threads lock poisoned").clone();
            let original_posts = self
                .original_posts
                .lock()
                .expect("original_posts lock poisoned")
                .clone();
            let posts = self.posts.lock().expect("posts lock poisoned").clone();
            let subscriptions = self
                .subscriptions
                .lock()
                .expect("subscriptions lock poisoned")
                .clone();
            let bookmarks = self
                .bookmarks
                .lock()
                .expect("bookmarks lock poisoned")
                .clone();
            let catch_up = self
                .catch_up_state
                .lock()
                .expect("catch_up_state lock poisoned");
            (
                categories,
                threads,
                original_posts,
                posts,
                subscriptions,
                bookmarks,
                catch_up.generation,
                catch_up.post_points.clone(),
                catch_up.read_receipts.clone(),
            )
        };
        if snapshot_generation > current_generation {
            return Err(StoreError::InvalidOperation(
                "catch-up snapshot generation is in the future".to_string(),
            ));
        }
        let snapshot_points: Vec<_> = points
            .iter()
            .filter(|point| point.seq <= snapshot_generation && point.activity_at <= as_of)
            .collect();
        let snapshot_post_ids: HashSet<&str> = snapshot_points
            .iter()
            .map(|point| point.post_id.as_str())
            .collect();
        let read_post_ids: HashSet<String> = receipts
            .iter()
            .filter(|((subject, post_id), receipt)| {
                subject == viewer_sub
                    && receipt.read_at <= as_of
                    && receipt.read_seq <= snapshot_generation
                    && snapshot_post_ids.contains(post_id.as_str())
            })
            .map(|((_, post_id), _)| post_id.clone())
            .collect();
        let bookmarked_post_ids: HashSet<String> = bookmarks
            .iter()
            .filter(|bookmark| bookmark.owner_sub == viewer_sub && bookmark.created_at <= as_of)
            .map(|bookmark| bookmark.post_id.clone())
            .collect();
        let mut items = Vec::new();
        for thread in threads
            .into_iter()
            .filter(|thread| thread.created_at <= as_of)
        {
            let Some(category) = categories
                .iter()
                .find(|category| category.id == thread.category_id)
            else {
                continue;
            };
            let Some(op_id) = original_posts.get(&thread.id).map(String::as_str) else {
                continue;
            };
            if !snapshot_post_ids.contains(op_id) {
                continue;
            }
            let mut thread_posts = posts
                .iter()
                .filter(|post| {
                    post.thread_id == thread.id && snapshot_post_ids.contains(post.id.as_str())
                })
                .cloned()
                .collect::<Vec<_>>();
            if thread_posts.is_empty() {
                continue;
            }
            thread_posts.sort_by(|left, right| {
                (op_id != left.id.as_str())
                    .cmp(&(op_id != right.id.as_str()))
                    .then_with(|| {
                        left.created_at
                            .cmp(&right.created_at)
                            .then_with(|| left.id.cmp(&right.id))
                    })
            });
            // Points survive a reply deletion, so current live-content fail-closed behaviour can
            // remove that reply without moving the thread across an already-issued page keyset.
            let activity_at = snapshot_points
                .iter()
                .filter(|point| point.thread_id == thread.id)
                .map(|point| point.activity_at)
                .max()
                .unwrap_or(thread.created_at);
            if before.is_some_and(|cursor| {
                activity_at > cursor.activity_at
                    || (activity_at == cursor.activity_at && thread.id >= cursor.thread_id)
            }) {
                continue;
            }
            let follow_level = subscriptions
                .iter()
                .find(|row| row.thread_id == thread.id && row.subscriber_sub == viewer_sub)
                .map(|row| row.level)
                .unwrap_or_default();
            if follow_level == ThreadFollowLevel::Mute {
                continue;
            }
            let authored = thread.author_sub == viewer_sub;
            let participated = thread_posts
                .iter()
                .any(|post| post.author_sub == viewer_sub);
            let bookmarked = thread_posts
                .iter()
                .any(|post| bookmarked_post_ids.contains(&post.id));
            let reading = reading_state_from_posts(&thread_posts, &read_post_ids);
            let reason = catch_up_reason(
                view,
                follow_level,
                authored,
                bookmarked,
                participated,
                reading.started,
            );
            let solved = category.format.is_question()
                && valid_accepted_post(&thread, &original_posts, &posts)
                    .is_some_and(|post| snapshot_post_ids.contains(post.id.as_str()));
            let eligible = match view {
                CatchUpView::Updates => reading.unread_count > 0 && reason.is_some(),
                CatchUpView::Following => reason.is_some(),
                CatchUpView::Questions => authored && category.format.is_question(),
            };
            if !eligible {
                continue;
            }
            let mut public_thread = thread;
            if !solved {
                public_thread.accepted_post_id.clear();
            }
            items.push(CatchUpItem {
                thread: public_thread,
                category_name: category.name.clone(),
                reason: reason.expect("eligible catch-up row has one reason"),
                follow_level,
                unread_count: reading.unread_count,
                first_unread: reading.first_unread,
                question_state: category.format.is_question().then_some(if solved {
                    CatchUpQuestionState::Solved
                } else {
                    CatchUpQuestionState::Waiting
                }),
                activity_at,
                reply_count: (thread_posts.len() as i64 - 1).max(0),
            });
        }
        items.sort_by(|left, right| {
            right
                .activity_at
                .cmp(&left.activity_at)
                .then_with(|| right.thread.id.cmp(&left.thread.id))
        });
        items.truncate(limit);
        Ok(items)
    }

    async fn thread_reading_state(
        &self,
        viewer_sub: &str,
        thread_id: &str,
    ) -> Result<ThreadReadingState, StoreError> {
        self.thread_reading_states(viewer_sub, &[thread_id.to_string()])
            .await?
            .remove(thread_id)
            .ok_or_else(|| StoreError::NotFound("thread not found".to_string()))
    }

    async fn thread_reading_states(
        &self,
        viewer_sub: &str,
        thread_ids: &[String],
    ) -> Result<HashMap<String, ThreadReadingState>, StoreError> {
        let thread_ids = bounded_thread_ids(thread_ids)?;
        // This projection spans live posts and Catch-up receipts. Share the same outer domain and
        // inner thread -> original-post -> post -> Catch-up order as every related Memory command;
        // otherwise a Catch-up page and a thread page can acquire the two ends in reverse order.
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        let threads = self.threads.lock().expect("threads lock poisoned");
        let original_posts = self
            .original_posts
            .lock()
            .expect("original_posts lock poisoned");
        let posts = self.posts.lock().expect("posts lock poisoned");
        let catch_up = self
            .catch_up_state
            .lock()
            .expect("catch_up_state lock poisoned");
        let read_post_ids: HashSet<String> = catch_up
            .read_receipts
            .keys()
            .filter(|(subject, _)| subject == viewer_sub)
            .map(|(_, post_id)| post_id.clone())
            .collect();
        let mut states = HashMap::new();
        for thread_id in thread_ids {
            if threads.iter().all(|thread| thread.id != thread_id) {
                continue;
            }
            let mut thread_posts: Vec<Post> = posts
                .iter()
                .filter(|post| post.thread_id == thread_id)
                .cloned()
                .collect();
            let op_id = original_posts.get(&thread_id).map(String::as_str);
            thread_posts.sort_by(|left, right| {
                (op_id != Some(left.id.as_str()))
                    .cmp(&(op_id != Some(right.id.as_str())))
                    .then_with(|| {
                        left.created_at
                            .cmp(&right.created_at)
                            .then_with(|| left.id.cmp(&right.id))
                    })
            });
            states.insert(
                thread_id.clone(),
                reading_state_from_posts(&thread_posts, &read_post_ids),
            );
        }
        Ok(states)
    }

    async fn mark_thread_posts_read(
        &self,
        viewer_sub: &str,
        thread_id: &str,
        post_ids: &[String],
        read_at: i64,
    ) -> Result<(), StoreError> {
        let post_ids = bounded_post_ids(post_ids)?;
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        if viewer_sub.trim().is_empty() || read_at < 0 {
            return Err(StoreError::InvalidOperation(
                "invalid thread reading receipt".to_string(),
            ));
        }
        if self
            .threads
            .lock()
            .expect("threads lock poisoned")
            .iter()
            .all(|thread| thread.id != thread_id)
        {
            return Err(StoreError::NotFound("thread not found".to_string()));
        }
        let posts = self.posts.lock().expect("posts lock poisoned");
        if post_ids.iter().any(|post_id| {
            posts
                .iter()
                .all(|post| post.id != *post_id || post.thread_id != thread_id)
        }) {
            return Err(StoreError::NotFound("thread post not found".to_string()));
        }
        let mut catch_up = self
            .catch_up_state
            .lock()
            .expect("catch_up_state lock poisoned");
        let missing: Vec<_> = post_ids
            .into_iter()
            .filter(|post_id| {
                !catch_up
                    .read_receipts
                    .contains_key(&(viewer_sub.to_string(), post_id.clone()))
            })
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        let read_seq = catch_up.next_generation()?;
        for post_id in missing {
            catch_up.read_receipts.insert(
                (viewer_sub.to_string(), post_id),
                MemoryPostReadReceipt { read_at, read_seq },
            );
        }
        Ok(())
    }

    async fn activity_page(
        &self,
        viewer_sub: &str,
        filter: ActivityFilter,
        unread_only: bool,
        before: Option<&ActivityCursor>,
        limit: i64,
    ) -> Result<Vec<ActivityItem>, StoreError> {
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        let threads = self.threads.lock().expect("threads lock poisoned").clone();
        let posts = self.posts.lock().expect("posts lock poisoned").clone();
        let events = self
            .activity_events
            .lock()
            .expect("activity_events lock poisoned")
            .clone();
        let deliveries = self
            .activity_deliveries
            .lock()
            .expect("activity_deliveries lock poisoned")
            .clone();
        let receipts = self
            .activity_receipts
            .lock()
            .expect("activity_receipts lock poisoned")
            .clone();

        let mut items = Vec::new();
        for event in events {
            if before.is_some_and(|cursor| {
                event.created_at > cursor.created_at
                    || (event.created_at == cursor.created_at && event.id >= cursor.id)
            }) {
                continue;
            }
            let reason = best_activity_reason(
                deliveries
                    .iter()
                    .filter(|stored| stored.activity_id == event.id)
                    .map(|stored| stored.delivery.clone())
                    .filter(|delivery| delivery_matches_viewer(delivery, viewer_sub)),
            );
            let Some(reason) = reason else {
                continue;
            };
            if !activity_filter_matches(filter, reason) {
                continue;
            }
            let read = receipts
                .iter()
                .any(|receipt| receipt.activity_id == event.id && receipt.viewer_sub == viewer_sub);
            if unread_only && read {
                continue;
            }
            let Some(thread) = threads.iter().find(|thread| thread.id == event.thread_id) else {
                continue;
            };
            let Some(post) = posts
                .iter()
                .find(|post| post.id == event.post_id && post.thread_id == event.thread_id)
            else {
                continue;
            };
            let actor_email = match event.kind {
                ActivityKind::PostCreated => post.author_email.clone(),
                ActivityKind::AnswerAccepted => posts
                    .iter()
                    .filter(|candidate| candidate.author_sub == event.actor_sub)
                    .max_by(|left, right| {
                        left.created_at
                            .cmp(&right.created_at)
                            .then_with(|| left.id.cmp(&right.id))
                    })
                    .map(|candidate| candidate.author_email.clone())
                    .or_else(|| {
                        threads
                            .iter()
                            .filter(|candidate| candidate.author_sub == event.actor_sub)
                            .max_by(|left, right| {
                                left.created_at
                                    .cmp(&right.created_at)
                                    .then_with(|| left.id.cmp(&right.id))
                            })
                            .map(|candidate| candidate.author_email.clone())
                    })
                    .unwrap_or_default(),
            };
            items.push(ActivityItem {
                event,
                reason,
                thread_title: thread.title.clone(),
                post_body_md: post.body_md.clone(),
                post_created_at: post.created_at,
                actor_email,
                read,
            });
        }
        items.sort_by(|left, right| {
            right
                .event
                .created_at
                .cmp(&left.event.created_at)
                .then_with(|| right.event.id.cmp(&left.event.id))
        });
        items.truncate(limit.max(0) as usize);
        Ok(items)
    }

    async fn unread_activity_count(&self, viewer_sub: &str) -> Result<i64, StoreError> {
        Ok(self
            .activity_page(viewer_sub, ActivityFilter::All, true, None, i64::MAX)
            .await?
            .len() as i64)
    }

    async fn set_activity_read(
        &self,
        activity_id: &str,
        viewer_sub: &str,
        read: bool,
        changed_at: i64,
    ) -> Result<(), StoreError> {
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        let delivered = self
            .activity_deliveries
            .lock()
            .expect("activity_deliveries lock poisoned")
            .iter()
            .any(|stored| {
                stored.activity_id == activity_id
                    && delivery_matches_viewer(&stored.delivery, viewer_sub)
            });
        let target = self
            .activity_events
            .lock()
            .expect("activity_events lock poisoned")
            .iter()
            .find(|event| event.id == activity_id)
            .cloned();
        let authoritative = target.is_some_and(|event| {
            self.threads
                .lock()
                .expect("threads lock poisoned")
                .iter()
                .any(|thread| thread.id == event.thread_id)
                && self
                    .posts
                    .lock()
                    .expect("posts lock poisoned")
                    .iter()
                    .any(|post| post.id == event.post_id && post.thread_id == event.thread_id)
        });
        if !delivered || !authoritative {
            return Err(StoreError::NotFound("activity not found".to_string()));
        }
        let mut receipts = self
            .activity_receipts
            .lock()
            .expect("activity_receipts lock poisoned");
        receipts.retain(|receipt| {
            receipt.activity_id != activity_id || receipt.viewer_sub != viewer_sub
        });
        if read {
            receipts.push(ActivityReceipt {
                activity_id: activity_id.to_string(),
                viewer_sub: viewer_sub.to_string(),
                _read_at: changed_at,
            });
        }
        Ok(())
    }

    async fn mark_activity_batch_read(
        &self,
        viewer_sub: &str,
        activity_ids: &[String],
        changed_at: i64,
    ) -> Result<i64, StoreError> {
        if activity_ids.len() > MAX_ACTIVITY_BATCH {
            return Err(StoreError::InvalidOperation(format!(
                "activity batch may contain at most {MAX_ACTIVITY_BATCH} ids"
            )));
        }
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        let threads: HashSet<String> = self
            .threads
            .lock()
            .expect("threads lock poisoned")
            .iter()
            .map(|thread| thread.id.clone())
            .collect();
        let posts: HashSet<(String, String)> = self
            .posts
            .lock()
            .expect("posts lock poisoned")
            .iter()
            .map(|post| (post.thread_id.clone(), post.id.clone()))
            .collect();
        let events = self
            .activity_events
            .lock()
            .expect("activity_events lock poisoned")
            .clone();
        let deliveries = self
            .activity_deliveries
            .lock()
            .expect("activity_deliveries lock poisoned")
            .clone();
        let requested: HashSet<&str> = activity_ids.iter().map(String::as_str).collect();
        let target_ids: Vec<String> = events
            .iter()
            .filter(|event| requested.contains(event.id.as_str()))
            .filter(|event| {
                threads.contains(&event.thread_id)
                    && posts.contains(&(event.thread_id.clone(), event.post_id.clone()))
            })
            .filter(|event| {
                deliveries.iter().any(|stored| {
                    stored.activity_id == event.id
                        && delivery_matches_viewer(&stored.delivery, viewer_sub)
                })
            })
            .map(|event| event.id.clone())
            .collect();
        if target_ids.len() != requested.len() {
            return Err(StoreError::NotFound("activity not found".to_string()));
        }
        let mut receipts = self
            .activity_receipts
            .lock()
            .expect("activity_receipts lock poisoned");
        let mut changed = 0_i64;
        for activity_id in target_ids {
            if receipts.iter().any(|receipt| {
                receipt.activity_id == activity_id && receipt.viewer_sub == viewer_sub
            }) {
                continue;
            }
            receipts.push(ActivityReceipt {
                activity_id,
                viewer_sub: viewer_sub.to_string(),
                _read_at: changed_at,
            });
            changed += 1;
        }
        Ok(changed)
    }

    async fn ensure_bookmark(
        &self,
        owner_sub: &str,
        post_id: &str,
        created_at: i64,
    ) -> Result<Bookmark, StoreError> {
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        if !self
            .posts
            .lock()
            .expect("posts lock poisoned")
            .iter()
            .any(|post| post.id == post_id)
        {
            return Err(StoreError::NotFound("post not found".to_string()));
        }
        let mut bookmarks = self.bookmarks.lock().expect("bookmarks lock poisoned");
        if let Some(existing) = bookmarks
            .iter()
            .find(|row| row.owner_sub == owner_sub && row.post_id == post_id)
        {
            return Ok(existing.clone());
        }
        if bookmarks
            .iter()
            .filter(|row| row.owner_sub == owner_sub)
            .count()
            >= MAX_BOOKMARKS_PER_USER
        {
            return Err(StoreError::InvalidOperation(format!(
                "a user may save at most {MAX_BOOKMARKS_PER_USER} bookmarks"
            )));
        }
        let bookmark = Bookmark {
            bookmark_id: crate::new_id("bm"),
            owner_sub: owner_sub.to_string(),
            post_id: post_id.to_string(),
            note: String::new(),
            remind_at: None,
            created_at,
            updated_at: created_at,
            version: 1,
        };
        bookmarks.push(bookmark.clone());
        Ok(bookmark)
    }

    async fn bookmarks_for_posts(
        &self,
        owner_sub: &str,
        post_ids: &[String],
    ) -> Result<Vec<Bookmark>, StoreError> {
        if post_ids.len() > MAX_BOOKMARK_POST_BATCH {
            return Err(StoreError::InvalidOperation(format!(
                "bookmark post batch may contain at most {MAX_BOOKMARK_POST_BATCH} ids"
            )));
        }
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        let requested: HashSet<&str> = post_ids.iter().map(String::as_str).collect();
        let live_posts: HashSet<String> = self
            .posts
            .lock()
            .expect("posts lock poisoned")
            .iter()
            .map(|post| post.id.clone())
            .collect();
        Ok(self
            .bookmarks
            .lock()
            .expect("bookmarks lock poisoned")
            .iter()
            .filter(|row| {
                row.owner_sub == owner_sub
                    && requested.contains(row.post_id.as_str())
                    && live_posts.contains(&row.post_id)
            })
            .cloned()
            .collect())
    }

    async fn bookmark_page(
        &self,
        owner_sub: &str,
        state: BookmarkState,
        cursor: Option<&BookmarkCursor>,
        limit: i64,
        now: i64,
    ) -> Result<Vec<BookmarkItem>, StoreError> {
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        let threads = self.threads.lock().expect("threads lock poisoned");
        let posts = self.posts.lock().expect("posts lock poisoned");
        let bookmarks = self.bookmarks.lock().expect("bookmarks lock poisoned");
        let mut items = Vec::new();
        for bookmark in bookmarks
            .iter()
            .filter(|row| row.owner_sub == owner_sub)
            .filter(|row| bookmark_state_matches(row, state, now))
        {
            let sort_at = match state {
                BookmarkState::All => bookmark.created_at,
                BookmarkState::Due | BookmarkState::Scheduled => {
                    bookmark.remind_at.unwrap_or_default()
                }
            };
            let outside_page = cursor.is_some_and(|cursor| match state {
                BookmarkState::All => {
                    sort_at > cursor.sort_at
                        || (sort_at == cursor.sort_at && bookmark.post_id >= cursor.post_id)
                }
                BookmarkState::Due | BookmarkState::Scheduled => {
                    sort_at < cursor.sort_at
                        || (sort_at == cursor.sort_at && bookmark.post_id <= cursor.post_id)
                }
            });
            if outside_page {
                continue;
            }
            let Some(post) = posts.iter().find(|post| post.id == bookmark.post_id) else {
                continue;
            };
            let Some(thread) = threads.iter().find(|thread| thread.id == post.thread_id) else {
                continue;
            };
            items.push(BookmarkItem {
                bookmark: bookmark.clone(),
                thread_id: thread.id.clone(),
                thread_title: thread.title.clone(),
                post_author_email: post.author_email.clone(),
                post_body_md: post.body_md.clone(),
                post_created_at: post.created_at,
            });
        }
        items.sort_by(|left, right| match state {
            BookmarkState::All => right
                .bookmark
                .created_at
                .cmp(&left.bookmark.created_at)
                .then_with(|| right.bookmark.post_id.cmp(&left.bookmark.post_id)),
            BookmarkState::Due | BookmarkState::Scheduled => left
                .bookmark
                .remind_at
                .cmp(&right.bookmark.remind_at)
                .then_with(|| left.bookmark.post_id.cmp(&right.bookmark.post_id)),
        });
        items.truncate(limit.clamp(0, MAX_BOOKMARK_PAGE + 1) as usize);
        Ok(items)
    }

    async fn due_bookmark_count(&self, owner_sub: &str, now: i64) -> Result<i64, StoreError> {
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        let live_posts: HashSet<String> = self
            .posts
            .lock()
            .expect("posts lock poisoned")
            .iter()
            .map(|post| post.id.clone())
            .collect();
        Ok(self
            .bookmarks
            .lock()
            .expect("bookmarks lock poisoned")
            .iter()
            .filter(|row| {
                row.owner_sub == owner_sub
                    && row.remind_at.is_some_and(|at| at <= now)
                    && live_posts.contains(&row.post_id)
            })
            .count() as i64)
    }

    async fn get_bookmark(
        &self,
        owner_sub: &str,
        post_id: &str,
    ) -> Result<Option<BookmarkItem>, StoreError> {
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        let threads = self.threads.lock().expect("threads lock poisoned");
        let posts = self.posts.lock().expect("posts lock poisoned");
        let bookmarks = self.bookmarks.lock().expect("bookmarks lock poisoned");
        let Some(bookmark) = bookmarks
            .iter()
            .find(|row| row.owner_sub == owner_sub && row.post_id == post_id)
            .cloned()
        else {
            return Ok(None);
        };
        let Some(post) = posts.iter().find(|post| post.id == post_id) else {
            return Ok(None);
        };
        let Some(thread) = threads.iter().find(|thread| thread.id == post.thread_id) else {
            return Ok(None);
        };
        Ok(Some(BookmarkItem {
            bookmark,
            thread_id: thread.id.clone(),
            thread_title: thread.title.clone(),
            post_author_email: post.author_email.clone(),
            post_body_md: post.body_md.clone(),
            post_created_at: post.created_at,
        }))
    }

    async fn update_bookmark(
        &self,
        owner_sub: &str,
        post_id: &str,
        expected: BookmarkCas<'_>,
        note: &str,
        reminder: BookmarkReminderUpdate,
        changed_at: i64,
    ) -> Result<Bookmark, StoreError> {
        validate_bookmark_note(note)?;
        if let BookmarkReminderUpdate::Set(remind_at) = reminder {
            validate_future_reminder(remind_at, changed_at)?;
        }
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        if !self
            .posts
            .lock()
            .expect("posts lock poisoned")
            .iter()
            .any(|post| post.id == post_id)
        {
            return Err(StoreError::NotFound("bookmark not found".to_string()));
        }
        let mut bookmarks = self.bookmarks.lock().expect("bookmarks lock poisoned");
        let row = bookmarks
            .iter_mut()
            .find(|row| row.owner_sub == owner_sub && row.post_id == post_id)
            .ok_or_else(|| StoreError::NotFound("bookmark not found".to_string()))?;
        validate_bookmark_cas(row, expected)?;
        row.note = note.to_string();
        match reminder {
            BookmarkReminderUpdate::Keep => {}
            BookmarkReminderUpdate::Clear => row.remind_at = None,
            BookmarkReminderUpdate::Set(remind_at) => row.remind_at = Some(remind_at),
        }
        row.updated_at = changed_at;
        row.version = next_bookmark_version(row.version)?;
        Ok(row.clone())
    }

    async fn complete_due_bookmark(
        &self,
        owner_sub: &str,
        post_id: &str,
        expected: BookmarkCas<'_>,
        changed_at: i64,
    ) -> Result<Bookmark, StoreError> {
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        if !self
            .posts
            .lock()
            .expect("posts lock poisoned")
            .iter()
            .any(|post| post.id == post_id)
        {
            return Err(StoreError::NotFound("bookmark not found".to_string()));
        }
        let mut bookmarks = self.bookmarks.lock().expect("bookmarks lock poisoned");
        let row = bookmarks
            .iter_mut()
            .find(|row| row.owner_sub == owner_sub && row.post_id == post_id)
            .ok_or_else(|| StoreError::NotFound("bookmark not found".to_string()))?;
        validate_bookmark_cas(row, expected)?;
        if row.remind_at.is_none_or(|at| at > changed_at) {
            return Err(StoreError::InvalidOperation(
                "bookmark reminder is not due".to_string(),
            ));
        }
        row.remind_at = None;
        row.updated_at = changed_at;
        row.version = next_bookmark_version(row.version)?;
        Ok(row.clone())
    }

    async fn snooze_bookmark(
        &self,
        owner_sub: &str,
        post_id: &str,
        expected: BookmarkCas<'_>,
        remind_at: i64,
        changed_at: i64,
    ) -> Result<Bookmark, StoreError> {
        validate_future_reminder(remind_at, changed_at)?;
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        if !self
            .posts
            .lock()
            .expect("posts lock poisoned")
            .iter()
            .any(|post| post.id == post_id)
        {
            return Err(StoreError::NotFound("bookmark not found".to_string()));
        }
        let mut bookmarks = self.bookmarks.lock().expect("bookmarks lock poisoned");
        let row = bookmarks
            .iter_mut()
            .find(|row| row.owner_sub == owner_sub && row.post_id == post_id)
            .ok_or_else(|| StoreError::NotFound("bookmark not found".to_string()))?;
        validate_bookmark_cas(row, expected)?;
        if row.remind_at.is_none_or(|at| at > changed_at) {
            return Err(StoreError::InvalidOperation(
                "bookmark reminder is not due".to_string(),
            ));
        }
        row.remind_at = Some(remind_at);
        row.updated_at = changed_at;
        row.version = next_bookmark_version(row.version)?;
        Ok(row.clone())
    }

    async fn remove_bookmark(
        &self,
        owner_sub: &str,
        post_id: &str,
        expected: BookmarkCas<'_>,
    ) -> Result<(), StoreError> {
        let _domain = self.qa_guard.lock().expect("qa guard poisoned");
        let mut bookmarks = self.bookmarks.lock().expect("bookmarks lock poisoned");
        let index = bookmarks
            .iter()
            .position(|row| row.owner_sub == owner_sub && row.post_id == post_id)
            .ok_or_else(|| StoreError::NotFound("bookmark not found".to_string()))?;
        validate_bookmark_cas(&bookmarks[index], expected)?;
        bookmarks.remove(index);
        Ok(())
    }

    async fn toggle_reaction(
        &self,
        post_id: &str,
        user_sub: &str,
        kind: &str,
        created_at: i64,
    ) -> Result<bool, StoreError> {
        let mut reactions = self.reactions.lock().expect("reactions lock poisoned");
        if let Some(pos) = reactions
            .iter()
            .position(|r| r.post_id == post_id && r.user_sub == user_sub && r.kind == kind)
        {
            reactions.remove(pos);
            Ok(false)
        } else {
            reactions.push(Reaction {
                post_id: post_id.to_string(),
                user_sub: user_sub.to_string(),
                kind: kind.to_string(),
                created_at,
            });
            Ok(true)
        }
    }

    async fn reactions_for_post(
        &self,
        post_id: &str,
        viewer_sub: Option<&str>,
    ) -> Result<Vec<ReactionCount>, StoreError> {
        let reactions = self.reactions.lock().expect("reactions lock poisoned");
        // Aggregate by kind, preserving first-seen order for a stable render.
        let mut out: Vec<ReactionCount> = Vec::new();
        for r in reactions.iter().filter(|r| r.post_id == post_id) {
            let mine = viewer_sub == Some(r.user_sub.as_str());
            match out.iter_mut().find(|c| c.kind == r.kind) {
                Some(c) => {
                    c.count += 1;
                    c.mine = c.mine || mine;
                }
                None => out.push(ReactionCount {
                    kind: r.kind.clone(),
                    count: 1,
                    mine,
                }),
            }
        }
        Ok(out)
    }

    async fn list_bans(&self) -> Result<Vec<BannedAuthor>, StoreError> {
        let mut v: Vec<BannedAuthor> = self.banned.lock().expect("banned lock poisoned").clone();
        v.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| a.author_sub.cmp(&b.author_sub))
        });
        Ok(v)
    }

    async fn is_banned(&self, author_sub: &str) -> Result<bool, StoreError> {
        Ok(self
            .banned
            .lock()
            .expect("banned lock poisoned")
            .iter()
            .any(|b| b.author_sub == author_sub))
    }

    async fn add_ban(&self, ban: &BannedAuthor) -> Result<(), StoreError> {
        let mut banned = self.banned.lock().expect("banned lock poisoned");
        match banned.iter_mut().find(|b| b.author_sub == ban.author_sub) {
            Some(existing) => *existing = ban.clone(),
            None => banned.push(ban.clone()),
        }
        Ok(())
    }

    async fn remove_ban(&self, author_sub: &str) -> Result<(), StoreError> {
        self.banned
            .lock()
            .expect("banned lock poisoned")
            .retain(|b| b.author_sub != author_sub);
        Ok(())
    }
}

/// Display sort for thread lists: pinned first, then most-recent activity, then newest.
/// Shared by `recent_threads` + `threads_in_category` so both views honor `pinned`.
fn thread_display_order(a: &Thread, b: &Thread) -> std::cmp::Ordering {
    b.pinned
        .cmp(&a.pinned)
        .then_with(|| b.last_at.cmp(&a.last_at))
        .then_with(|| b.created_at.cmp(&a.created_at))
        .then_with(|| b.id.cmp(&a.id))
}

/// One authoritative accepted-answer predicate shared by every in-memory read and mutation.
/// A category is intentionally not consulted here: historical discussion solutions remain valid
/// records for their detail page, even though only Question categories expose them publicly.
fn valid_accepted_post<'a>(
    thread: &Thread,
    original_posts: &HashMap<String, String>,
    posts: &'a [Post],
) -> Option<&'a Post> {
    let accepted_id = thread.accepted_post_id.trim();
    if accepted_id.is_empty()
        || original_posts.get(&thread.id).map(String::as_str) == Some(accepted_id)
    {
        return None;
    }
    posts
        .iter()
        .find(|post| post.id == accepted_id && post.thread_id == thread.id)
}

fn has_valid_question_solution(
    thread: &Thread,
    category_format: CategoryFormat,
    original_posts: &HashMap<String, String>,
    posts: &[Post],
) -> bool {
    category_format.is_question() && valid_accepted_post(thread, original_posts, posts).is_some()
}

/// Public list/search rows expose the pointer only for a valid Question solution. The raw pointer
/// remains available through `get_thread` for detail-page legacy recovery and explicit clearing.
fn public_thread(mut thread: Thread, has_valid_question_solution: bool) -> Thread {
    if !has_valid_question_solution {
        thread.accepted_post_id.clear();
    }
    thread
}

fn thread_matches_status(
    has_valid_question_solution: bool,
    is_question: bool,
    status: ThreadStatusFilter,
) -> bool {
    match status {
        ThreadStatusFilter::Any => true,
        ThreadStatusFilter::Questions => is_question,
        ThreadStatusFilter::Answered => has_valid_question_solution,
        ThreadStatusFilter::Unanswered => is_question && !has_valid_question_solution,
    }
}

/// Sort threads with their reply counts. Pinned threads remain first for every mode; each
/// non-latest mode falls back to the legacy latest order for deterministic ties.
fn sort_thread_rows(rows: &mut [(Thread, i64)], sort: ThreadSort, now: i64) {
    rows.sort_by(|(a, ac), (b, bc)| {
        b.pinned.cmp(&a.pinned).then_with(|| match sort {
            ThreadSort::Latest => b
                .last_at
                .cmp(&a.last_at)
                .then_with(|| b.created_at.cmp(&a.created_at))
                .then_with(|| b.id.cmp(&a.id)),
            ThreadSort::Top => bc
                .cmp(ac)
                .then_with(|| b.last_at.cmp(&a.last_at))
                .then_with(|| b.created_at.cmp(&a.created_at))
                .then_with(|| b.id.cmp(&a.id)),
            ThreadSort::Hot => hot_score(*bc, b.created_at, now)
                .partial_cmp(&hot_score(*ac, a.created_at, now))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| bc.cmp(ac))
                .then_with(|| b.last_at.cmp(&a.last_at))
                .then_with(|| b.created_at.cmp(&a.created_at))
                .then_with(|| b.id.cmp(&a.id)),
        })
    });
}

fn hot_score(reply_count: i64, created_at: i64, now: i64) -> f64 {
    let age_hours = now.saturating_sub(created_at).max(0) as f64 / 3600.0;
    reply_count.max(0) as f64 / (age_hours + 2.0).powf(1.5)
}

/// Build a literal contains-pattern for SQL `LIKE ... ESCAPE '!'`. Escaping `%`, `_`, and the
/// escape marker itself keeps a user's search text from becoming a wildcard expression.
fn like_contains_pattern(query: &str) -> String {
    let mut pattern = String::with_capacity(query.len() + 2);
    pattern.push('%');
    for ch in query.chars().flat_map(char::to_lowercase) {
        if matches!(ch, '!' | '%' | '_') {
            pattern.push('!');
        }
        pattern.push(ch);
    }
    pattern.push('%');
    pattern
}

// --------------------------------------------------------------------------------------
// PostgreSQL-backed store (portable: standard SQL, runtime queries, no macros).
// --------------------------------------------------------------------------------------
//
// Selected at runtime by `AGORA_STORE=postgres`. Each method drives sqlx natively, so the
// handlers `.await` it on the serving runtime — NO `block_in_place`, NO sync-over-async.
// `create_thread`/`add_reply` use a short DB transaction for their two-statement atomicity;
// the database enforces the primary keys, so no in-process serializer is needed.

use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};
use sqlx::{Postgres, QueryBuilder, Row, Transaction};

/// PostgreSQL-backed [`Store`]. Holds just a `PgPool`; the async trait methods drive sqlx
/// natively, so no worker thread is ever blocked on a DB round-trip.
pub struct PgStore {
    pool: PgPool,
}

/// Canonical lock key used by Activity receipt mutations. Ordering every batch by
/// category -> thread -> post -> event matches moderation deletion and prevents deadlocks.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ActivityLockTarget {
    category_id: String,
    thread_id: String,
    post_id: String,
    activity_id: String,
}

impl PgStore {
    /// Open a pooled connection. Async; call from within a Tokio runtime.
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(database_url)
            .await?;
        Ok(Self::from_pool(pool))
    }

    /// Construct from an existing pool (used by tests that share a pool).
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Allocate one commit-ordered Catch-up generation. Every v8 post/read writer holds the
    /// singleton row lock until its surrounding transaction commits; a snapshot's `FOR SHARE`
    /// therefore cannot observe a generation whose authority rows are still uncommitted.
    async fn next_catch_up_generation_tx(
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<i64, StoreError> {
        let current = sqlx::query_scalar::<_, i64>(
            "SELECT generation FROM forum_catch_up_clock WHERE id = 1 FOR UPDATE",
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(backend)?;
        let next = current.checked_add(1).ok_or_else(|| {
            StoreError::InvalidOperation("catch-up generation is exhausted".to_string())
        })?;
        sqlx::query("UPDATE forum_catch_up_clock SET generation = $1 WHERE id = 1")
            .bind(next)
            .execute(&mut **tx)
            .await
            .map_err(backend)?;
        Ok(next)
    }

    async fn insert_catch_up_post_point_tx(
        tx: &mut Transaction<'_, Postgres>,
        post: &Post,
    ) -> Result<(), StoreError> {
        let seq = Self::next_catch_up_generation_tx(tx).await?;
        sqlx::query(
            "INSERT INTO forum_catch_up_post_points (post_id, thread_id, activity_at, seq) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(&post.id)
        .bind(&post.thread_id)
        .bind(post.created_at)
        .bind(seq)
        .execute(&mut **tx)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn catch_up_snapshot_generation_async(&self) -> Result<i64, StoreError> {
        let mut tx = self.pool.begin().await.map_err(backend)?;
        let generation = sqlx::query_scalar::<_, i64>(
            "SELECT generation FROM forum_catch_up_clock WHERE id = 1 FOR SHARE",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(backend)?;
        tx.commit().await.map_err(backend)?;
        Ok(generation)
    }

    async fn register_identity_alias_tx(
        tx: &mut Transaction<'_, Postgres>,
        subject: &str,
        email: &str,
        created_at: i64,
    ) -> Result<(), sqlx::Error> {
        let Some(alias) = identity_alias(subject, email) else {
            return Ok(());
        };
        sqlx::query(
            "INSERT INTO forum_identity_aliases (alias, subject, created_at) \
             VALUES ($1, $2, $3) ON CONFLICT (alias, subject) DO NOTHING",
        )
        .bind(alias)
        .bind(subject)
        .bind(created_at)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    async fn resolve_mention_deliveries_tx(
        tx: &mut Transaction<'_, Postgres>,
        mentioned_aliases: &[String],
        actor_sub: &str,
    ) -> Result<Vec<ActivityDelivery>, sqlx::Error> {
        let mut deliveries = Vec::new();
        for alias in mentioned_aliases {
            let subjects = sqlx::query_scalar::<_, String>(
                "SELECT subject FROM forum_identity_aliases \
                 WHERE alias = $1 ORDER BY subject LIMIT 2",
            )
            .bind(alias)
            .fetch_all(&mut **tx)
            .await?;
            if subjects.len() == 1 {
                if let Some(delivery) =
                    subject_delivery(&subjects[0], actor_sub, ActivityReason::Mention)
                {
                    deliveries.push(delivery);
                }
            }
        }
        Ok(deliveries)
    }

    async fn activity_lock_targets(
        &self,
        activity_ids: &[&str],
    ) -> Result<Vec<ActivityLockTarget>, StoreError> {
        let mut targets = Vec::with_capacity(activity_ids.len());
        for activity_id in activity_ids {
            let row = sqlx::query(
                "SELECT t.category_id, e.thread_id, e.post_id, e.id AS activity_id \
                 FROM forum_activity_events AS e \
                 JOIN threads AS t ON t.id = e.thread_id \
                 WHERE e.id = $1",
            )
            .bind(activity_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(backend)?
            .ok_or_else(|| StoreError::NotFound("activity not found".to_string()))?;
            targets.push(ActivityLockTarget {
                category_id: row.try_get("category_id").map_err(backend)?,
                thread_id: row.try_get("thread_id").map_err(backend)?,
                post_id: row.try_get("post_id").map_err(backend)?,
                activity_id: row.try_get("activity_id").map_err(backend)?,
            });
        }
        targets.sort();
        Ok(targets)
    }

    async fn lock_activity_targets_tx(
        tx: &mut Transaction<'_, Postgres>,
        viewer_sub: &str,
        targets: &[ActivityLockTarget],
    ) -> Result<(), StoreError> {
        let categories: BTreeSet<&str> = targets
            .iter()
            .map(|target| target.category_id.as_str())
            .collect();
        for category_id in categories {
            let exists = sqlx::query_scalar::<_, String>(
                "SELECT id FROM categories WHERE id = $1 FOR UPDATE",
            )
            .bind(category_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(backend)?;
            if exists.is_none() {
                return Err(StoreError::NotFound("activity not found".to_string()));
            }
        }

        let threads: BTreeSet<(&str, &str)> = targets
            .iter()
            .map(|target| (target.category_id.as_str(), target.thread_id.as_str()))
            .collect();
        for (category_id, thread_id) in threads {
            let current_category = sqlx::query_scalar::<_, String>(
                "SELECT category_id FROM threads WHERE id = $1 FOR UPDATE",
            )
            .bind(thread_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(backend)?;
            if current_category.as_deref() != Some(category_id) {
                return Err(StoreError::NotFound("activity not found".to_string()));
            }
        }

        let posts: BTreeSet<(&str, &str)> = targets
            .iter()
            .map(|target| (target.thread_id.as_str(), target.post_id.as_str()))
            .collect();
        for (thread_id, post_id) in posts {
            let current_thread = sqlx::query_scalar::<_, String>(
                "SELECT thread_id FROM posts WHERE id = $1 FOR UPDATE",
            )
            .bind(post_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(backend)?;
            if current_thread.as_deref() != Some(thread_id) {
                return Err(StoreError::NotFound("activity not found".to_string()));
            }
        }

        for target in targets {
            let visible = sqlx::query_scalar::<_, String>(
                "SELECT e.id FROM forum_activity_events AS e \
                 WHERE e.id = $1 AND e.thread_id = $2 AND e.post_id = $3 \
                   AND EXISTS (\
                       SELECT 1 FROM forum_activity_deliveries AS d \
                       WHERE d.activity_id = e.id AND d.recipient_kind = 'subject' \
                         AND d.recipient_key = $4\
                   ) \
                 FOR UPDATE OF e",
            )
            .bind(&target.activity_id)
            .bind(&target.thread_id)
            .bind(&target.post_id)
            .bind(viewer_sub)
            .fetch_optional(&mut **tx)
            .await
            .map_err(backend)?;
            if visible.is_none() {
                return Err(StoreError::NotFound("activity not found".to_string()));
            }
        }
        Ok(())
    }

    async fn insert_activity_tx(
        tx: &mut Transaction<'_, Postgres>,
        event: &ActivityEvent,
        deliveries: &[ActivityDelivery],
    ) -> Result<(), sqlx::Error> {
        if deliveries.is_empty() {
            return Ok(());
        }
        sqlx::query(
            "INSERT INTO forum_activity_events \
                 (id, kind, thread_id, post_id, actor_sub, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&event.id)
        .bind(event.kind.as_str())
        .bind(&event.thread_id)
        .bind(&event.post_id)
        .bind(&event.actor_sub)
        .bind(event.created_at)
        .execute(&mut **tx)
        .await?;
        for delivery in deliveries {
            sqlx::query(
                "INSERT INTO forum_activity_deliveries \
                     (activity_id, recipient_kind, recipient_key, reason) \
                 VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (activity_id, recipient_kind, recipient_key, reason) DO NOTHING",
            )
            .bind(&event.id)
            .bind(delivery.recipient_kind.as_str())
            .bind(&delivery.recipient_key)
            .bind(delivery.reason.as_str())
            .execute(&mut **tx)
            .await?;
        }
        Ok(())
    }

    fn bookmark_from_row(row: &PgRow) -> Result<Bookmark, sqlx::Error> {
        Ok(Bookmark {
            bookmark_id: row.try_get("bookmark_id")?,
            owner_sub: row.try_get("owner_sub")?,
            post_id: row.try_get("post_id")?,
            note: row.try_get("note")?,
            remind_at: row.try_get("remind_at")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
            version: row.try_get("version")?,
        })
    }

    fn bookmark_item_from_row(row: &PgRow) -> Result<BookmarkItem, sqlx::Error> {
        Ok(BookmarkItem {
            bookmark: Self::bookmark_from_row(row)?,
            thread_id: row.try_get("thread_id")?,
            thread_title: row.try_get("thread_title")?,
            post_author_email: row.try_get("post_author_email")?,
            post_body_md: row.try_get("post_body_md")?,
            post_created_at: row.try_get("post_created_at")?,
        })
    }

    async fn lock_bookmark_tx(
        tx: &mut Transaction<'_, Postgres>,
        owner_sub: &str,
        post_id: &str,
    ) -> Result<Bookmark, StoreError> {
        let post = sqlx::query_scalar::<_, String>("SELECT id FROM posts WHERE id = $1 FOR UPDATE")
            .bind(post_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(backend)?;
        if post.is_none() {
            return Err(StoreError::NotFound("bookmark not found".to_string()));
        }
        let row = sqlx::query(
            "SELECT bookmark_id, owner_sub, post_id, note, remind_at, created_at, updated_at, version \
             FROM forum_bookmarks WHERE owner_sub = $1 AND post_id = $2 FOR UPDATE",
        )
        .bind(owner_sub)
        .bind(post_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(backend)?
        .ok_or_else(|| StoreError::NotFound("bookmark not found".to_string()))?;
        Self::bookmark_from_row(&row).map_err(backend)
    }

    async fn persist_bookmark_tx(
        tx: &mut Transaction<'_, Postgres>,
        bookmark: &Bookmark,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE forum_bookmarks SET note = $1, remind_at = $2, updated_at = $3, version = $4 \
             WHERE owner_sub = $5 AND post_id = $6 AND bookmark_id = $7",
        )
        .bind(&bookmark.note)
        .bind(bookmark.remind_at)
        .bind(bookmark.updated_at)
        .bind(bookmark.version)
        .bind(&bookmark.owner_sub)
        .bind(&bookmark.post_id)
        .bind(&bookmark.bookmark_id)
        .execute(&mut **tx)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn replace_mentions_tx(
        tx: &mut Transaction<'_, Postgres>,
        post_id: &str,
        thread_id: &str,
        mentioned_usernames: &[String],
        created_at: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM post_mentions WHERE post_id = $1")
            .bind(post_id)
            .execute(&mut **tx)
            .await?;
        let mut seen = HashSet::new();
        for name in mentioned_usernames {
            if !seen.insert(name.as_str()) {
                continue;
            }
            sqlx::query(
                "INSERT INTO post_mentions (post_id, thread_id, mentioned_username, created_at) \
                 VALUES ($1, $2, $3, $4) ON CONFLICT (post_id, mentioned_username) DO NOTHING",
            )
            .bind(post_id)
            .bind(thread_id)
            .bind(name)
            .bind(created_at)
            .execute(&mut **tx)
            .await?;
        }
        Ok(())
    }

    /// Idempotent, portable migration. Standard SQL only — safe to run on every startup.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS categories (\
                 id TEXT PRIMARY KEY, \
                 name TEXT NOT NULL, \
                 sort_order BIGINT NOT NULL DEFAULT 0, \
                 format TEXT NOT NULL DEFAULT 'discussion'\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Existing deployments predate category formats. Add the column nullable, classify only
        // rows that have never been classified, then lock in the default/invariant. The `IS NULL`
        // guard is essential: startup migration must never undo an operator's later format edit.
        sqlx::query("ALTER TABLE categories ADD COLUMN IF NOT EXISTS format TEXT")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "UPDATE categories SET format = CASE WHEN id = 'support' THEN 'question' \
             ELSE 'discussion' END WHERE format IS NULL",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("ALTER TABLE categories ALTER COLUMN format SET DEFAULT 'discussion'")
            .execute(&self.pool)
            .await?;
        sqlx::query("ALTER TABLE categories ALTER COLUMN format SET NOT NULL")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS threads (\
                 id TEXT PRIMARY KEY, \
                 category_id TEXT NOT NULL, \
                 title TEXT NOT NULL, \
                 author_sub TEXT NOT NULL, \
                 author_email TEXT NOT NULL, \
                 created_at BIGINT NOT NULL, \
                 last_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Additive, idempotent: denormalised copy of the original-post body, populated on
        // create_thread. Powers compose-time similarity without joining `posts`. Pre-existing
        // rows receive an empty default and are backfilled once the posts table is ready below.
        sqlx::query(
            "ALTER TABLE threads ADD COLUMN IF NOT EXISTS first_body_md TEXT NOT NULL DEFAULT ''",
        )
        .execute(&self.pool)
        .await?;
        // Stable OP identity. created_at is second-granularity and ids are random, so ordering
        // cannot safely distinguish a same-second reply from the original post.
        sqlx::query(
            "ALTER TABLE threads ADD COLUMN IF NOT EXISTS first_post_id TEXT NOT NULL DEFAULT ''",
        )
        .execute(&self.pool)
        .await?;
        // Admin moderation flags: locked (no new replies) + pinned (sort first). Additive,
        // idempotent; pre-existing rows default to unlocked/unpinned. Portable BOOLEAN only.
        sqlx::query(
            "ALTER TABLE threads ADD COLUMN IF NOT EXISTS locked BOOLEAN NOT NULL DEFAULT FALSE",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE threads ADD COLUMN IF NOT EXISTS pinned BOOLEAN NOT NULL DEFAULT FALSE",
        )
        .execute(&self.pool)
        .await?;
        // Additive, idempotent: the reply the author/admin marked as the accepted answer. Empty
        // string means none. Portable TEXT NOT NULL DEFAULT '' — pre-existing rows read as unset.
        sqlx::query("ALTER TABLE threads ADD COLUMN IF NOT EXISTS accepted_post_id TEXT NOT NULL DEFAULT ''")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_threads_category ON threads (category_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_threads_last_at ON threads (last_at)")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_threads_author_snapshot \
             ON threads (author_sub, created_at, id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS posts (\
                 id TEXT PRIMARY KEY, \
                 thread_id TEXT NOT NULL, \
                 body_md TEXT NOT NULL, \
                 quoted_post_id TEXT NOT NULL DEFAULT '', \
                 author_sub TEXT NOT NULL, \
                 author_email TEXT NOT NULL, \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE posts ADD COLUMN IF NOT EXISTS quoted_post_id TEXT NOT NULL DEFAULT ''",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_posts_thread ON posts (thread_id)")
            .execute(&self.pool)
            .await?;
        // Catch-up begins from subject-owned candidate ids, then walks one content snapshot. The
        // composite indexes keep both sides bounded without introducing a new authority table.
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_posts_author_snapshot \
             ON posts (author_sub, created_at, thread_id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_posts_thread_snapshot \
             ON posts (thread_id, created_at, id)",
        )
        .execute(&self.pool)
        .await?;
        // Subject-scoped reading continuity is stored per post rather than as a high-water
        // cursor. This preserves unread holes after Latest/activity jumps and after the accepted
        // answer is floated out of natural chronology. The FK lets every old/new delete path
        // clean receipts without knowing about this additive feature.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS forum_post_read_receipts (\
                 viewer_sub TEXT NOT NULL, \
                 post_id TEXT NOT NULL, \
                 read_at BIGINT NOT NULL, \
                 PRIMARY KEY (viewer_sub, post_id), \
                 CONSTRAINT fk_forum_post_read_receipt_post FOREIGN KEY (post_id) \
                     REFERENCES posts(id) ON DELETE CASCADE\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_forum_post_read_receipts_post \
             ON forum_post_read_receipts (post_id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_forum_post_read_receipts_viewer_snapshot \
             ON forum_post_read_receipts (viewer_sub, read_at, post_id)",
        )
        .execute(&self.pool)
        .await?;
        // Personal bookmarks are addressed only by the stable gateway subject. The Post FK is
        // also the cross-version deletion protocol: an older binary deleting a post still removes
        // its private bookmarks. Owner guard rows serialize quota checks for concurrent creates.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS forum_bookmark_owner_guards (\
                 owner_sub TEXT PRIMARY KEY\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS forum_bookmarks (\
                 bookmark_id TEXT NOT NULL, \
                 owner_sub TEXT NOT NULL, \
                 post_id TEXT NOT NULL, \
                 note TEXT NOT NULL DEFAULT '', \
                 remind_at BIGINT, \
                 created_at BIGINT NOT NULL, \
                 updated_at BIGINT NOT NULL, \
                 version BIGINT NOT NULL DEFAULT 1, \
                 PRIMARY KEY (owner_sub, post_id), \
                 CONSTRAINT fk_forum_bookmark_post FOREIGN KEY (post_id) \
                     REFERENCES posts(id) ON DELETE CASCADE, \
                 CHECK (char_length(note) <= 200), \
                 CHECK (remind_at IS NULL OR remind_at >= 0), \
                 CHECK (version > 0)\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Existing Bookmark deployments predate the immutable row identity used by CAS. Add it
        // nullable, backfill only missing rows with opaque ids, then make it mandatory. A restart
        // during backfill is safe: already-assigned ids are never rewritten, and a recreated
        // bookmark receives a new id in `ensure_bookmark_async`.
        sqlx::query("ALTER TABLE forum_bookmarks ADD COLUMN IF NOT EXISTS bookmark_id TEXT")
            .execute(&self.pool)
            .await?;
        let legacy_bookmarks = sqlx::query(
            "SELECT owner_sub, post_id FROM forum_bookmarks \
             WHERE bookmark_id IS NULL OR bookmark_id = ''",
        )
        .fetch_all(&self.pool)
        .await?;
        for row in legacy_bookmarks {
            let owner_sub: String = row.try_get("owner_sub")?;
            let post_id: String = row.try_get("post_id")?;
            sqlx::query(
                "UPDATE forum_bookmarks SET bookmark_id = $1 \
                 WHERE owner_sub = $2 AND post_id = $3 \
                   AND (bookmark_id IS NULL OR bookmark_id = '')",
            )
            .bind(crate::new_id("bm"))
            .bind(owner_sub)
            .bind(post_id)
            .execute(&self.pool)
            .await?;
        }
        sqlx::query("ALTER TABLE forum_bookmarks ALTER COLUMN bookmark_id SET NOT NULL")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_forum_bookmarks_identity \
             ON forum_bookmarks (bookmark_id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_forum_bookmarks_recent \
             ON forum_bookmarks (owner_sub, created_at DESC, post_id DESC)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_forum_bookmarks_due \
             ON forum_bookmarks (owner_sub, remind_at ASC, post_id ASC) \
             WHERE remind_at IS NOT NULL",
        )
        .execute(&self.pool)
        .await?;
        // Older deployments predate stable OP identity. Preserve their established display rule
        // once during migration, then every new/read path uses this explicit id rather than
        // re-inferring ownership from timestamps. Both updates are empty-only and idempotent.
        sqlx::query(
            "UPDATE threads AS t \
             SET first_post_id = (\
                 SELECT p.id \
                 FROM posts AS p \
                 WHERE p.thread_id = t.id \
                 ORDER BY p.created_at ASC, p.id ASC \
                 FETCH FIRST 1 ROW ONLY\
             ) \
             WHERE t.first_post_id = '' \
               AND EXISTS (SELECT 1 FROM posts AS p WHERE p.thread_id = t.id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "UPDATE threads AS t \
             SET first_body_md = (\
                 SELECT p.body_md \
                 FROM posts AS p \
                 WHERE p.thread_id = t.id AND p.id = t.first_post_id\
             ) \
             WHERE t.first_body_md = '' \
               AND EXISTS (\
                   SELECT 1 FROM posts AS p \
                   WHERE p.thread_id = t.id AND p.id = t.first_post_id\
               )",
        )
        .execute(&self.pool)
        .await?;
        // Accepted pointers predate the guarded command contract. Keep a historical Discussion
        // solution when it is structurally valid, but clear every dangling, cross-thread or OP
        // pointer. Already-valid and already-empty rows remain unchanged, so this is idempotent.
        sqlx::query(
            "UPDATE threads AS t SET accepted_post_id = '' \
             WHERE t.accepted_post_id <> '' \
               AND NOT EXISTS (\
                   SELECT 1 FROM posts AS p \
                   WHERE p.id = t.accepted_post_id \
                     AND p.thread_id = t.id \
                     AND p.id <> t.first_post_id\
               )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_posts_quote ON posts (quoted_post_id)")
            .execute(&self.pool)
            .await?;
        // Catch-up snapshots use one commit-ordered clock instead of second-granularity wall time.
        // `post_id` deliberately has no Post FK: deleting a reply removes its content authority but
        // retains the non-content ordering point. The Thread FK still makes a thread deletion erase
        // the whole history, including when a v7 image performs the delete during rollback.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS forum_catch_up_clock (\
                 id BIGINT PRIMARY KEY, \
                 generation BIGINT NOT NULL, \
                 CHECK (id = 1), \
                 CHECK (generation >= 0)\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "INSERT INTO forum_catch_up_clock (id, generation) VALUES (1, 0) \
             ON CONFLICT (id) DO NOTHING",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS forum_catch_up_post_points (\
                 post_id TEXT PRIMARY KEY, \
                 thread_id TEXT NOT NULL REFERENCES threads(id) ON DELETE CASCADE, \
                 activity_at BIGINT NOT NULL, \
                 seq BIGINT NOT NULL UNIQUE, \
                 CHECK (activity_at >= 0), \
                 CHECK (seq > 0)\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_catch_up_points_thread_snapshot \
             ON forum_catch_up_post_points (thread_id, seq, activity_at, post_id)",
        )
        .execute(&self.pool)
        .await?;
        // Nullable is intentional rollback protocol: v7 keeps inserting its three historical
        // columns. The next v8 quiescent boot assigns those rows a deterministic first-read seq.
        sqlx::query(
            "ALTER TABLE forum_post_read_receipts ADD COLUMN IF NOT EXISTS read_seq BIGINT",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_post_read_receipts_viewer_generation \
             ON forum_post_read_receipts (viewer_sub, read_seq, post_id)",
        )
        .execute(&self.pool)
        .await?;

        // Deterministic, idempotent forward backfill. Existing point/read sequences are never
        // rewritten; missing v7 rows append in a stable order after the greatest durable value.
        // Holding the singleton clock lock makes accidental current-version writers serialize
        // behind the migration, while normal deployment remains single-active and quiescent.
        let mut catch_up_tx = self.pool.begin().await?;
        let stored_generation = sqlx::query_scalar::<_, i64>(
            "SELECT generation FROM forum_catch_up_clock WHERE id = 1 FOR UPDATE",
        )
        .fetch_one(&mut *catch_up_tx)
        .await?;
        let point_max =
            sqlx::query_scalar::<_, Option<i64>>("SELECT MAX(seq) FROM forum_catch_up_post_points")
                .fetch_one(&mut *catch_up_tx)
                .await?
                .unwrap_or(0);
        let receipt_max = sqlx::query_scalar::<_, Option<i64>>(
            "SELECT MAX(read_seq) FROM forum_post_read_receipts",
        )
        .fetch_one(&mut *catch_up_tx)
        .await?
        .unwrap_or(0);
        let mut generation = stored_generation.max(point_max).max(receipt_max);
        let missing_posts = sqlx::query(
            "SELECT p.id, p.thread_id, p.created_at \
             FROM posts AS p \
             JOIN threads AS t ON t.id = p.thread_id \
             LEFT JOIN forum_catch_up_post_points AS point ON point.post_id = p.id \
             WHERE point.post_id IS NULL \
             ORDER BY p.created_at ASC, p.thread_id ASC, p.id ASC",
        )
        .fetch_all(&mut *catch_up_tx)
        .await?;
        for row in missing_posts {
            generation = generation.checked_add(1).ok_or_else(|| {
                sqlx::Error::Protocol("catch-up generation is exhausted".to_string())
            })?;
            sqlx::query(
                "INSERT INTO forum_catch_up_post_points (post_id, thread_id, activity_at, seq) \
                 VALUES ($1, $2, $3, $4) ON CONFLICT (post_id) DO NOTHING",
            )
            .bind(row.try_get::<String, _>("id")?)
            .bind(row.try_get::<String, _>("thread_id")?)
            .bind(row.try_get::<i64, _>("created_at")?)
            .bind(generation)
            .execute(&mut *catch_up_tx)
            .await?;
        }
        let missing_receipts = sqlx::query(
            "SELECT viewer_sub, post_id FROM forum_post_read_receipts \
             WHERE read_seq IS NULL ORDER BY read_at ASC, viewer_sub ASC, post_id ASC",
        )
        .fetch_all(&mut *catch_up_tx)
        .await?;
        for row in missing_receipts {
            generation = generation.checked_add(1).ok_or_else(|| {
                sqlx::Error::Protocol("catch-up generation is exhausted".to_string())
            })?;
            sqlx::query(
                "UPDATE forum_post_read_receipts SET read_seq = $1 \
                 WHERE viewer_sub = $2 AND post_id = $3 AND read_seq IS NULL",
            )
            .bind(generation)
            .bind(row.try_get::<String, _>("viewer_sub")?)
            .bind(row.try_get::<String, _>("post_id")?)
            .execute(&mut *catch_up_tx)
            .await?;
        }
        sqlx::query("UPDATE forum_catch_up_clock SET generation = $1 WHERE id = 1")
            .bind(generation)
            .execute(&mut *catch_up_tx)
            .await?;
        catch_up_tx.commit().await?;
        // Parsed @mentions. One row per post + mentioned username; usernames are normalised by the
        // handler before write. No cross-service notification is attempted here.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS post_mentions (\
                 post_id TEXT NOT NULL, \
                 thread_id TEXT NOT NULL, \
                 mentioned_username TEXT NOT NULL, \
                 created_at BIGINT NOT NULL, \
                 PRIMARY KEY (post_id, mentioned_username)\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_mentions_user ON post_mentions (mentioned_username)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_mentions_thread ON post_mentions (thread_id)")
            .execute(&self.pool)
            .await?;
        // Append-only identity aliases resolve @name to one stable gateway subject at event-write
        // time. Multiple subjects may claim an alias; that alias then resolves to nobody.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS forum_identity_aliases (\
                 alias TEXT NOT NULL, \
                 subject TEXT NOT NULL, \
                 created_at BIGINT NOT NULL, \
                 PRIMARY KEY (alias, subject)\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_identity_aliases_subject \
             ON forum_identity_aliases (subject)",
        )
        .execute(&self.pool)
        .await?;
        let historical_authors = sqlx::query(
            "SELECT author_sub, author_email, MIN(created_at) AS created_at \
             FROM (\
                 SELECT author_sub, author_email, created_at FROM posts \
                 UNION ALL \
                 SELECT author_sub, author_email, created_at FROM threads\
             ) AS authors \
             GROUP BY author_sub, author_email",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut alias_tx = self.pool.begin().await?;
        for row in historical_authors {
            let subject: String = row.try_get("author_sub")?;
            let email: String = row.try_get("author_email")?;
            let created_at: i64 = row.try_get("created_at")?;
            Self::register_identity_alias_tx(&mut alias_tx, &subject, &email, created_at).await?;
        }
        alias_tx.commit().await?;
        // Keep the legacy v6 subscription table as a Watch-only compatibility projection. An
        // image-only rollback therefore never interprets Follow or Mute as a generic watcher.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS thread_subscriptions (\
                 thread_id TEXT NOT NULL, \
                 subscriber_sub TEXT NOT NULL, \
                 created_at BIGINT NOT NULL, \
                 PRIMARY KEY (thread_id, subscriber_sub)\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS thread_follow_preferences (\
                 thread_id TEXT NOT NULL, \
                 subscriber_sub TEXT NOT NULL, \
                 level TEXT NOT NULL, \
                 created_at BIGINT NOT NULL, \
                 CONSTRAINT ck_thread_follow_preferences_level \
                     CHECK (level IN ('follow', 'mute')), \
                 CONSTRAINT fk_thread_follow_preference_thread \
                     FOREIGN KEY (thread_id) REFERENCES threads(id) ON DELETE CASCADE, \
                 PRIMARY KEY (thread_id, subscriber_sub)\
             )",
        )
        .execute(&self.pool)
        .await?;
        let mut follow_schema_tx = self.pool.begin().await?;
        // A development candidate briefly stored all levels in the legacy table. It was never a
        // production release, but migrate it forward safely if an operator evaluated that build:
        // move only Follow/Mute into the new table, then leave only Watch rows for v6 readers.
        let candidate_level_column = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (\
                 SELECT 1 FROM information_schema.columns \
                 WHERE table_schema = CURRENT_SCHEMA \
                   AND table_name = 'thread_subscriptions' AND column_name = 'level'\
             )",
        )
        .fetch_one(&mut *follow_schema_tx)
        .await?;
        if candidate_level_column {
            sqlx::query(
                "INSERT INTO thread_follow_preferences \
                     (thread_id, subscriber_sub, level, created_at) \
                 SELECT subscription.thread_id, subscription.subscriber_sub, \
                        subscription.level, subscription.created_at \
                   FROM thread_subscriptions AS subscription \
                   JOIN threads AS thread ON thread.id = subscription.thread_id \
                  WHERE subscription.level IN ('follow', 'mute') \
                 ON CONFLICT (thread_id, subscriber_sub) DO UPDATE \
                 SET level = EXCLUDED.level, created_at = EXCLUDED.created_at",
            )
            .execute(&mut *follow_schema_tx)
            .await?;
            sqlx::query("DELETE FROM thread_subscriptions WHERE level <> 'watch'")
                .execute(&mut *follow_schema_tx)
                .await?;
            let watch_only_check = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (\
                     SELECT 1 FROM information_schema.table_constraints \
                     WHERE constraint_schema = CURRENT_SCHEMA \
                       AND table_name = 'thread_subscriptions' \
                       AND constraint_name = 'ck_thread_subscriptions_watch_only' \
                       AND constraint_type = 'CHECK'\
                 )",
            )
            .fetch_one(&mut *follow_schema_tx)
            .await?;
            if !watch_only_check {
                sqlx::query(
                    "ALTER TABLE thread_subscriptions \
                     ADD CONSTRAINT ck_thread_subscriptions_watch_only CHECK (level = 'watch')",
                )
                .execute(&mut *follow_schema_tx)
                .await?;
            }
        }
        sqlx::query(
            "DELETE FROM thread_follow_preferences AS preference \
             WHERE NOT EXISTS (\
                 SELECT 1 FROM threads AS thread WHERE thread.id = preference.thread_id\
             )",
        )
        .execute(&mut *follow_schema_tx)
        .await?;
        let preference_fk = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (\
                 SELECT 1 FROM information_schema.table_constraints \
                 WHERE constraint_schema = CURRENT_SCHEMA \
                   AND table_name = 'thread_follow_preferences' \
                   AND constraint_name = 'fk_thread_follow_preference_thread' \
                   AND constraint_type = 'FOREIGN KEY'\
             )",
        )
        .fetch_one(&mut *follow_schema_tx)
        .await?;
        if !preference_fk {
            sqlx::query(
                "ALTER TABLE thread_follow_preferences \
                 ADD CONSTRAINT fk_thread_follow_preference_thread FOREIGN KEY (thread_id) \
                 REFERENCES threads(id) ON DELETE CASCADE",
            )
            .execute(&mut *follow_schema_tx)
            .await?;
        }
        // An older v6 image can recreate a legacy Watch while a newer Mute row remains. Mute is
        // the narrow thread authority and must win after the next forward boot; otherwise the
        // mixed row would revive Activity and personal projections. Follow intentionally does not
        // delete a legacy Watch because Watch is the stronger positive intent.
        sqlx::query(
            "DELETE FROM thread_subscriptions AS watcher \
             WHERE EXISTS (\
                 SELECT 1 FROM thread_follow_preferences AS preference \
                 WHERE preference.thread_id = watcher.thread_id \
                   AND preference.subscriber_sub = watcher.subscriber_sub \
                   AND preference.level = 'mute'\
             )",
        )
        .execute(&mut *follow_schema_tx)
        .await?;
        follow_schema_tx.commit().await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_subscriptions_user ON thread_subscriptions (subscriber_sub)")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_subscriptions_user_thread \
             ON thread_subscriptions (subscriber_sub, thread_id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_follow_preferences_user \
             ON thread_follow_preferences (subscriber_sub, thread_id)",
        )
        .execute(&self.pool)
        .await?;
        // Category Focus is owner-scoped read intent only. The owner guard serializes the exact
        // 64-rule quota, while the Category FK is also the rollback protocol: an older image may
        // delete an empty category without knowing about v9 and its private rules still cascade.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS forum_category_focus_owner_guards (\
                 viewer_sub TEXT PRIMARY KEY\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS forum_category_focus_rules (\
                 viewer_sub TEXT NOT NULL, \
                 category_id TEXT NOT NULL, \
                 level TEXT NOT NULL, \
                 created_at BIGINT NOT NULL, \
                 updated_at BIGINT NOT NULL, \
                 PRIMARY KEY (viewer_sub, category_id), \
                 CONSTRAINT fk_forum_category_focus_category FOREIGN KEY (category_id) \
                     REFERENCES categories(id) ON DELETE CASCADE, \
                 CHECK (level IN ('priority', 'follow', 'mute')), \
                 CHECK (created_at >= 0), \
                 CHECK (updated_at >= created_at)\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_category_focus_subject_level \
             ON forum_category_focus_rules (viewer_sub, level, category_id)",
        )
        .execute(&self.pool)
        .await?;
        // Durable personal activity. Event rows contain no title/body snapshot: every read joins
        // through the live thread/post rows, and moderation deletes explicitly remove the event.
        // Fresh tables intentionally begin empty; migration never turns historical lifetime
        // mentions into a surprise wall of unread notifications.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS forum_activity_events (\
                 id TEXT PRIMARY KEY, \
                 kind TEXT NOT NULL, \
                 thread_id TEXT NOT NULL, \
                 post_id TEXT NOT NULL, \
                 actor_sub TEXT NOT NULL, \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_activity_events_order \
             ON forum_activity_events (created_at, id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_activity_events_thread \
             ON forum_activity_events (thread_id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_activity_events_post \
             ON forum_activity_events (post_id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS forum_activity_deliveries (\
                 activity_id TEXT NOT NULL, \
                 recipient_kind TEXT NOT NULL, \
                 recipient_key TEXT NOT NULL, \
                 reason TEXT NOT NULL, \
                 PRIMARY KEY (activity_id, recipient_kind, recipient_key, reason), \
                 CONSTRAINT fk_activity_delivery_event FOREIGN KEY (activity_id) \
                     REFERENCES forum_activity_events(id) ON DELETE CASCADE\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_activity_deliveries_recipient \
             ON forum_activity_deliveries (recipient_kind, recipient_key, activity_id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS forum_activity_receipts (\
                 activity_id TEXT NOT NULL, \
                 viewer_sub TEXT NOT NULL, \
                 read_at BIGINT NOT NULL, \
                 PRIMARY KEY (activity_id, viewer_sub), \
                 CONSTRAINT fk_activity_receipt_event FOREIGN KEY (activity_id) \
                     REFERENCES forum_activity_events(id) ON DELETE CASCADE\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_activity_receipts_viewer \
             ON forum_activity_receipts (viewer_sub, activity_id)",
        )
        .execute(&self.pool)
        .await?;
        // Upgrade pre-FK deployments in the existing single-active/quiescent boot migration
        // window. Legacy username deliveries are converted only when the alias has exactly one
        // subject; unresolved or ambiguous aliases fail closed.
        let mut activity_schema_tx = self.pool.begin().await?;
        sqlx::query(
            "DELETE FROM forum_activity_deliveries AS d \
             WHERE NOT EXISTS (SELECT 1 FROM forum_activity_events AS e WHERE e.id = d.activity_id)",
        )
        .execute(&mut *activity_schema_tx)
        .await?;
        sqlx::query(
            "DELETE FROM forum_activity_receipts AS r \
             WHERE NOT EXISTS (SELECT 1 FROM forum_activity_events AS e WHERE e.id = r.activity_id)",
        )
        .execute(&mut *activity_schema_tx)
        .await?;
        sqlx::query(
            "INSERT INTO forum_activity_deliveries \
                 (activity_id, recipient_kind, recipient_key, reason) \
             SELECT d.activity_id, 'subject', resolved.subject, d.reason \
             FROM forum_activity_deliveries AS d \
             JOIN (\
                 SELECT alias, MIN(subject) AS subject \
                 FROM forum_identity_aliases GROUP BY alias HAVING COUNT(*) = 1\
             ) AS resolved ON resolved.alias = d.recipient_key \
             WHERE d.recipient_kind = 'username' \
             ON CONFLICT (activity_id, recipient_kind, recipient_key, reason) DO NOTHING",
        )
        .execute(&mut *activity_schema_tx)
        .await?;
        sqlx::query("DELETE FROM forum_activity_deliveries WHERE recipient_kind <> 'subject'")
            .execute(&mut *activity_schema_tx)
            .await?;
        // A v6 rollback can delete a Watch row without knowing about v7's Activity cleanup. On
        // the next forward boot, reconcile only generic Following deliveries against the
        // effective Watch projection. A mixed-version Mute remains defensive authority even if an
        // unsupported concurrent legacy writer recreates Watch; direct deliveries remain intact.
        sqlx::query(
            "DELETE FROM forum_activity_deliveries AS delivery \
             WHERE delivery.recipient_kind = 'subject' \
               AND delivery.reason = 'following' \
               AND EXISTS (\
                   SELECT 1 FROM forum_activity_events AS event \
                   WHERE event.id = delivery.activity_id \
                     AND (NOT EXISTS (\
                             SELECT 1 FROM thread_subscriptions AS watcher \
                             WHERE watcher.thread_id = event.thread_id \
                               AND watcher.subscriber_sub = delivery.recipient_key\
                         ) OR EXISTS (\
                             SELECT 1 FROM thread_follow_preferences AS preference \
                             WHERE preference.thread_id = event.thread_id \
                               AND preference.subscriber_sub = delivery.recipient_key \
                               AND preference.level = 'mute'\
                         ))\
               )",
        )
        .execute(&mut *activity_schema_tx)
        .await?;
        sqlx::query(
            "DELETE FROM forum_activity_receipts AS r \
             WHERE NOT EXISTS (\
                 SELECT 1 FROM forum_activity_deliveries AS d \
                 WHERE d.activity_id = r.activity_id \
                   AND d.recipient_kind = 'subject' AND d.recipient_key = r.viewer_sub\
             )",
        )
        .execute(&mut *activity_schema_tx)
        .await?;
        sqlx::query(
            "DELETE FROM forum_activity_events AS e \
             WHERE NOT EXISTS (\
                 SELECT 1 FROM forum_activity_deliveries AS d WHERE d.activity_id = e.id\
             )",
        )
        .execute(&mut *activity_schema_tx)
        .await?;
        let delivery_fk = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (\
                 SELECT 1 FROM information_schema.table_constraints \
                 WHERE constraint_schema = CURRENT_SCHEMA \
                   AND table_name = 'forum_activity_deliveries' \
                   AND constraint_name = 'fk_activity_delivery_event' \
                   AND constraint_type = 'FOREIGN KEY'\
             )",
        )
        .fetch_one(&mut *activity_schema_tx)
        .await?;
        if !delivery_fk {
            sqlx::query(
                "ALTER TABLE forum_activity_deliveries \
                 ADD CONSTRAINT fk_activity_delivery_event FOREIGN KEY (activity_id) \
                 REFERENCES forum_activity_events(id) ON DELETE CASCADE",
            )
            .execute(&mut *activity_schema_tx)
            .await?;
        }
        let receipt_fk = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (\
                 SELECT 1 FROM information_schema.table_constraints \
                 WHERE constraint_schema = CURRENT_SCHEMA \
                   AND table_name = 'forum_activity_receipts' \
                   AND constraint_name = 'fk_activity_receipt_event' \
                   AND constraint_type = 'FOREIGN KEY'\
             )",
        )
        .fetch_one(&mut *activity_schema_tx)
        .await?;
        if !receipt_fk {
            sqlx::query(
                "ALTER TABLE forum_activity_receipts \
                 ADD CONSTRAINT fk_activity_receipt_event FOREIGN KEY (activity_id) \
                 REFERENCES forum_activity_events(id) ON DELETE CASCADE",
            )
            .execute(&mut *activity_schema_tx)
            .await?;
        }
        activity_schema_tx.commit().await?;
        // Per-user post reactions. One row is one user's single reaction of a kind; the composite
        // PRIMARY KEY makes it unique + idempotent per (post, user, kind). Portable standard SQL.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS post_reactions (\
                 post_id TEXT NOT NULL, \
                 user_sub TEXT NOT NULL, \
                 kind TEXT NOT NULL, \
                 created_at BIGINT NOT NULL, \
                 PRIMARY KEY (post_id, user_sub, kind)\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_reactions_post ON post_reactions (post_id)")
            .execute(&self.pool)
            .await?;
        // Author blocklist: while a row is present, that author_sub's new threads/replies are
        // rejected. Portable standard SQL (TEXT/BIGINT PK), idempotent.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS banned_authors (\
                 author_sub TEXT PRIMARY KEY, \
                 reason TEXT NOT NULL DEFAULT '', \
                 banned_by TEXT NOT NULL DEFAULT '', \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    fn category_from_row(row: &sqlx::postgres::PgRow) -> Result<Category, sqlx::Error> {
        let format: String = row.try_get("format")?;
        Ok(Category {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            sort_order: row.try_get("sort_order")?,
            format: CategoryFormat::parse(&format).unwrap_or_default(),
        })
    }

    fn thread_from_row(row: &sqlx::postgres::PgRow) -> Result<Thread, sqlx::Error> {
        Ok(Thread {
            id: row.try_get("id")?,
            category_id: row.try_get("category_id")?,
            title: row.try_get("title")?,
            author_sub: row.try_get("author_sub")?,
            author_email: row.try_get("author_email")?,
            created_at: row.try_get("created_at")?,
            last_at: row.try_get("last_at")?,
            locked: row.try_get("locked")?,
            pinned: row.try_get("pinned")?,
            accepted_post_id: row.try_get("accepted_post_id")?,
        })
    }

    fn post_from_row(row: &sqlx::postgres::PgRow) -> Result<Post, sqlx::Error> {
        Ok(Post {
            id: row.try_get("id")?,
            thread_id: row.try_get("thread_id")?,
            body_md: row.try_get("body_md")?,
            quoted_post_id: row.try_get("quoted_post_id")?,
            author_sub: row.try_get("author_sub")?,
            author_email: row.try_get("author_email")?,
            created_at: row.try_get("created_at")?,
        })
    }

    const THREAD_COLS: &'static str =
        "id, category_id, title, author_sub, author_email, created_at, last_at, locked, pinned, accepted_post_id";
    const POST_COLS: &'static str =
        "id, thread_id, body_md, quoted_post_id, author_sub, author_email, created_at";
    const POST_COLS_P: &'static str =
        "p.id AS id, p.thread_id AS thread_id, p.body_md AS body_md, \
         p.quoted_post_id AS quoted_post_id, p.author_sub AS author_sub, \
         p.author_email AS author_email, p.created_at AS created_at";

    async fn seed_async(&self, defaults: &[Category]) -> Result<(), sqlx::Error> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM categories")
            .fetch_one(&self.pool)
            .await?;
        let n: i64 = row.try_get("n")?;
        if n > 0 {
            return Ok(());
        }
        for c in defaults {
            sqlx::query(
                "INSERT INTO categories (id, name, sort_order, format) VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(&c.id)
            .bind(&c.name)
            .bind(c.sort_order)
            .bind(c.format.as_str())
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    async fn list_categories_async(&self) -> Result<Vec<Category>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, name, sort_order, format FROM categories ORDER BY sort_order, name",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::category_from_row).collect()
    }

    async fn get_category_async(&self, id: &str) -> Result<Option<Category>, sqlx::Error> {
        let row = sqlx::query("SELECT id, name, sort_order, format FROM categories WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(Self::category_from_row).transpose()
    }

    async fn count_threads_async(&self, category_id: &str) -> Result<i64, sqlx::Error> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM threads WHERE category_id = $1")
            .bind(category_id)
            .fetch_one(&self.pool)
            .await?;
        row.try_get("n")
    }

    async fn create_category_async(&self, c: &Category) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO categories (id, name, sort_order, format) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&c.id)
        .bind(&c.name)
        .bind(c.sort_order)
        .bind(c.format.as_str())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn rename_category_async(&self, id: &str, name: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE categories SET name = $1 WHERE id = $2")
            .bind(name)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn transition_category_format_async(
        &self,
        id: &str,
        format: CategoryFormat,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(backend)?;
        let row = sqlx::query("SELECT format FROM categories WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(backend)?
            .ok_or_else(|| StoreError::NotFound("category not found".to_string()))?;
        let current: String = row.try_get("format").map_err(backend)?;
        if CategoryFormat::parse(&current).unwrap_or_default() == format {
            tx.commit().await.map_err(backend)?;
            return Ok(());
        }

        if format == CategoryFormat::Discussion {
            let thread_rows = sqlx::query(
                "SELECT id, first_post_id, accepted_post_id FROM threads \
                 WHERE category_id = $1 ORDER BY id FOR UPDATE",
            )
            .bind(id)
            .fetch_all(&mut *tx)
            .await
            .map_err(backend)?;
            let locked_threads: Vec<(String, String, String)> = thread_rows
                .iter()
                .map(|row| {
                    Ok((
                        row.try_get("id")?,
                        row.try_get("first_post_id")?,
                        row.try_get("accepted_post_id")?,
                    ))
                })
                .collect::<Result<_, sqlx::Error>>()
                .map_err(backend)?;
            let mut accepted_ids: Vec<String> = locked_threads
                .iter()
                .map(|(_, _, accepted_id)| accepted_id.clone())
                .filter(|accepted| !accepted.trim().is_empty())
                .collect();
            accepted_ids.sort();
            accepted_ids.dedup();
            let mut accepted_threads: HashMap<String, String> = HashMap::new();
            for accepted_id in accepted_ids {
                if let Some(post_thread_id) = sqlx::query_scalar::<_, String>(
                    "SELECT thread_id FROM posts WHERE id = $1 FOR UPDATE",
                )
                .bind(&accepted_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(backend)?
                {
                    accepted_threads.insert(accepted_id, post_thread_id);
                }
            }
            for (thread_id, op_id, accepted_id) in locked_threads {
                if !accepted_id.is_empty()
                    && accepted_id != op_id
                    && accepted_threads.get(&accepted_id) == Some(&thread_id)
                {
                    return Err(StoreError::InvalidOperation(
                        "unmark accepted answers before changing this category to discussion"
                            .to_string(),
                    ));
                }
            }
        }

        sqlx::query("UPDATE categories SET format = $1 WHERE id = $2")
            .bind(format.as_str())
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        tx.commit().await.map_err(backend)?;
        Ok(())
    }

    async fn set_category_order_async(&self, id: &str, sort_order: i64) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE categories SET sort_order = $1 WHERE id = $2")
            .bind(sort_order)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_category_async(&self, id: &str) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(backend)?;
        let category =
            sqlx::query_scalar::<_, String>("SELECT id FROM categories WHERE id = $1 FOR UPDATE")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(backend)?;
        if category.is_none() {
            tx.commit().await.map_err(backend)?;
            return Ok(());
        }
        let thread_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM threads WHERE category_id = $1")
                .bind(id)
                .fetch_one(&mut *tx)
                .await
                .map_err(backend)?;
        if thread_count > 0 {
            return Err(StoreError::InvalidOperation(
                "category still has threads — move or delete them first".to_string(),
            ));
        }
        sqlx::query("DELETE FROM categories WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        tx.commit().await.map_err(backend)?;
        Ok(())
    }

    async fn recent_threads_async(&self, limit: i64) -> Result<Vec<Thread>, sqlx::Error> {
        if limit <= 0 {
            return Ok(Vec::new());
        }
        let sql = format!(
            "SELECT {} FROM threads \
             ORDER BY pinned DESC, last_at DESC, created_at DESC, id DESC LIMIT $1",
            Self::THREAD_COLS
        );
        let rows = sqlx::query(&sql).bind(limit).fetch_all(&self.pool).await?;
        rows.iter().map(Self::thread_from_row).collect()
    }

    async fn threads_in_category_async(
        &self,
        category_id: &str,
        limit: i64,
    ) -> Result<Vec<Thread>, sqlx::Error> {
        if limit <= 0 {
            return Ok(Vec::new());
        }
        let sql = format!(
            "SELECT {} FROM threads WHERE category_id = $1 \
             ORDER BY pinned DESC, last_at DESC, created_at DESC, id DESC LIMIT $2",
            Self::THREAD_COLS
        );
        let rows = sqlx::query(&sql)
            .bind(category_id)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(Self::thread_from_row).collect()
    }

    async fn list_threads_async(
        &self,
        category_id: Option<&str>,
        sort: ThreadSort,
        subscribed_sub: Option<&str>,
        status: ThreadStatusFilter,
        limit: i64,
        now: i64,
    ) -> Result<Vec<Thread>, sqlx::Error> {
        if limit <= 0 {
            return Ok(Vec::new());
        }
        let cols = "t.id AS id, t.category_id AS category_id, t.title AS title, \
                    t.author_sub AS author_sub, t.author_email AS author_email, \
                    t.created_at AS created_at, t.last_at AS last_at, t.locked AS locked, \
                    t.pinned AS pinned, \
                    CASE WHEN c.format = 'question' AND accepted.id IS NOT NULL \
                         THEN t.accepted_post_id ELSE '' END AS accepted_post_id";
        let group_cols = "t.id, t.category_id, t.title, t.author_sub, t.author_email, \
                          t.created_at, t.last_at, t.locked, t.pinned, t.accepted_post_id, \
                          t.first_post_id, c.format, accepted.id";

        let mut sql = format!(
            "SELECT {cols}, COUNT(p.id) AS post_count \
             FROM threads t \
             LEFT JOIN categories c ON c.id = t.category_id \
             LEFT JOIN posts accepted ON accepted.id = t.accepted_post_id \
                                     AND accepted.thread_id = t.id \
                                     AND accepted.id <> t.first_post_id \
             LEFT JOIN posts p ON p.thread_id = t.id"
        );
        let mut where_parts: Vec<String> = Vec::new();
        let mut next_param = 1;
        let category_param = category_id.map(|_| {
            let n = next_param;
            next_param += 1;
            n
        });
        let subscriber_param = subscribed_sub.map(|_| {
            let n = next_param;
            next_param += 1;
            n
        });
        let hot_now_param = if sort == ThreadSort::Hot {
            let n = next_param;
            next_param += 1;
            Some(n)
        } else {
            None
        };
        let limit_param = next_param;
        if let Some(n) = category_param {
            where_parts.push(format!("t.category_id = ${n}"));
        }
        if let Some(n) = subscriber_param {
            sql.push_str(
                " JOIN (\
                    SELECT watcher.thread_id FROM thread_subscriptions AS watcher \
                     WHERE watcher.subscriber_sub = $",
            );
            sql.push_str(&n.to_string());
            sql.push_str(
                " AND NOT EXISTS (\
                    SELECT 1 FROM thread_follow_preferences AS preference \
                     WHERE preference.thread_id = watcher.thread_id \
                       AND preference.subscriber_sub = watcher.subscriber_sub \
                       AND preference.level = 'mute')",
            );
            sql.push_str(
                " UNION \
                    SELECT thread_id FROM thread_follow_preferences \
                     WHERE level = 'follow' AND subscriber_sub = $",
            );
            sql.push_str(&n.to_string());
            sql.push_str(") s ON s.thread_id = t.id");
        }
        match status {
            ThreadStatusFilter::Any => {}
            ThreadStatusFilter::Questions => where_parts.push("c.format = 'question'".to_string()),
            ThreadStatusFilter::Answered => {
                where_parts.push("c.format = 'question'".to_string());
                where_parts.push("accepted.id IS NOT NULL".to_string());
            }
            ThreadStatusFilter::Unanswered => {
                where_parts.push("c.format = 'question'".to_string());
                where_parts.push("accepted.id IS NULL".to_string());
            }
        }
        if !where_parts.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&where_parts.join(" AND "));
        }
        sql.push_str(" GROUP BY ");
        sql.push_str(group_cols);
        sql.push_str(" ORDER BY t.pinned DESC, ");
        match sort {
            ThreadSort::Latest => {
                sql.push_str("t.last_at DESC, t.created_at DESC, t.id DESC");
            }
            ThreadSort::Top => {
                sql.push_str("COUNT(p.id) DESC, t.last_at DESC, t.created_at DESC, t.id DESC");
            }
            ThreadSort::Hot => {
                let now_param = hot_now_param.expect("hot sort has timestamp parameter");
                sql.push_str(&format!(
                    "CAST(GREATEST(COUNT(p.id) - 1, 0) AS DOUBLE PRECISION) / \
                     POWER(CAST(GREATEST(${now_param} - t.created_at, 0) AS DOUBLE PRECISION) \
                     / 3600.0 + 2.0, 1.5) DESC, COUNT(p.id) DESC, t.last_at DESC, \
                     t.created_at DESC, t.id DESC"
                ));
            }
        }
        sql.push_str(&format!(" LIMIT ${limit_param}"));

        let mut query = sqlx::query(&sql);
        if let Some(category_id) = category_id {
            query = query.bind(category_id);
        }
        if let Some(subscriber_sub) = subscribed_sub {
            query = query.bind(subscriber_sub);
        }
        if hot_now_param.is_some() {
            query = query.bind(now);
        }
        query = query.bind(limit);
        let rows = query.fetch_all(&self.pool).await?;
        rows.iter().map(Self::thread_from_row).collect()
    }

    async fn search_threads_async(
        &self,
        query: &str,
        category_id: Option<&str>,
        status: ThreadStatusFilter,
        limit: i64,
    ) -> Result<Vec<ThreadSearchHit>, sqlx::Error> {
        if query.trim().is_empty() || limit <= 0 {
            return Ok(Vec::new());
        }

        let cols = "t.id AS id, t.category_id AS category_id, t.title AS title, \
                    t.author_sub AS author_sub, t.author_email AS author_email, \
                    t.created_at AS created_at, t.last_at AS last_at, t.locked AS locked, \
                    t.pinned AS pinned, \
                    CASE WHEN c.format = 'question' AND accepted.id IS NOT NULL \
                         THEN t.accepted_post_id ELSE '' END AS accepted_post_id";
        let mut sql = format!(
            "SELECT {cols}, t.first_body_md AS first_body_md, \
                    COALESCE(accepted.body_md, '') AS accepted_body_md, \
                    (LOWER(COALESCE(accepted.body_md, '')) LIKE $1 ESCAPE '!') \
                        AS matched_in_solution, \
                    (SELECT COUNT(*) FROM posts p WHERE p.thread_id = t.id) AS post_count \
             FROM threads t \
             LEFT JOIN categories c ON c.id = t.category_id \
             LEFT JOIN posts accepted ON accepted.id = t.accepted_post_id \
                                      AND accepted.thread_id = t.id \
                                      AND accepted.id <> t.first_post_id \
                                      AND c.format = 'question' \
             WHERE (LOWER(t.title) LIKE $1 ESCAPE '!' \
                    OR LOWER(t.first_body_md) LIKE $1 ESCAPE '!' \
                    OR LOWER(COALESCE(accepted.body_md, '')) LIKE $1 ESCAPE '!')"
        );
        let mut next_param = 2;
        let category_param = category_id.map(|_| {
            let n = next_param;
            next_param += 1;
            n
        });
        if let Some(param) = category_param {
            sql.push_str(&format!(" AND t.category_id = ${param}"));
        }
        match status {
            ThreadStatusFilter::Any => {}
            ThreadStatusFilter::Questions => sql.push_str(" AND c.format = 'question'"),
            ThreadStatusFilter::Answered => {
                sql.push_str(" AND c.format = 'question' AND accepted.id IS NOT NULL");
            }
            ThreadStatusFilter::Unanswered => {
                sql.push_str(" AND c.format = 'question' AND accepted.id IS NULL");
            }
        }
        let limit_param = next_param;
        sql.push_str(&format!(
            " ORDER BY t.pinned DESC, t.last_at DESC, t.created_at DESC, t.id DESC \
             LIMIT ${limit_param}"
        ));

        let mut query_builder = sqlx::query(&sql).bind(like_contains_pattern(query.trim()));
        if let Some(category_id) = category_id {
            query_builder = query_builder.bind(category_id);
        }
        let rows = query_builder.bind(limit).fetch_all(&self.pool).await?;
        rows.iter()
            .map(|row| {
                let post_count: i64 = row.try_get("post_count")?;
                Ok(ThreadSearchHit {
                    thread: Self::thread_from_row(row)?,
                    first_body_md: row.try_get("first_body_md")?,
                    accepted_body_md: row.try_get("accepted_body_md")?,
                    matched_in_solution: row.try_get("matched_in_solution")?,
                    reply_count: (post_count - 1).max(0),
                })
            })
            .collect()
    }

    async fn get_thread_async(&self, id: &str) -> Result<Option<Thread>, sqlx::Error> {
        let sql = format!("SELECT {} FROM threads WHERE id = $1", Self::THREAD_COLS);
        let row = sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(Self::thread_from_row).transpose()
    }

    async fn thread_digests_async(&self, limit: i64) -> Result<Vec<ThreadDigest>, sqlx::Error> {
        if limit <= 0 {
            return Ok(Vec::new());
        }
        let rows = sqlx::query(
            "SELECT id, category_id, title, first_body_md FROM threads \
             ORDER BY last_at DESC, created_at DESC, id DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(ThreadDigest {
                    id: row.try_get("id")?,
                    category_id: row.try_get("category_id")?,
                    title: row.try_get("title")?,
                    first_body_md: row.try_get("first_body_md")?,
                })
            })
            .collect()
    }

    async fn count_posts_async(&self, thread_id: &str) -> Result<i64, sqlx::Error> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM posts WHERE thread_id = $1")
            .bind(thread_id)
            .fetch_one(&self.pool)
            .await?;
        row.try_get("n")
    }

    async fn get_post_async(&self, id: &str) -> Result<Option<Post>, sqlx::Error> {
        let sql = format!("SELECT {} FROM posts WHERE id = $1", Self::POST_COLS);
        let row = sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(Self::post_from_row).transpose()
    }

    async fn get_valid_accepted_post_async(
        &self,
        thread_id: &str,
    ) -> Result<Option<Post>, sqlx::Error> {
        let sql = format!(
            "SELECT {} FROM posts p \
             JOIN threads t ON t.id = $1 \
             WHERE p.id = t.accepted_post_id \
               AND p.thread_id = t.id \
               AND p.id <> t.first_post_id \
             FETCH FIRST 1 ROW ONLY",
            Self::POST_COLS_P
        );
        let row = sqlx::query(&sql)
            .bind(thread_id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(Self::post_from_row).transpose()
    }

    async fn posts_in_thread_async(&self, thread_id: &str) -> Result<Vec<Post>, sqlx::Error> {
        let sql = format!(
            "SELECT {} FROM posts WHERE thread_id = $1 \
             ORDER BY CASE WHEN id = (SELECT first_post_id FROM threads WHERE id = $1) \
                           THEN 0 ELSE 1 END, created_at ASC, id ASC",
            Self::POST_COLS
        );
        let rows = sqlx::query(&sql)
            .bind(thread_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(Self::post_from_row).collect()
    }

    async fn first_post_in_thread_async(
        &self,
        thread_id: &str,
    ) -> Result<Option<Post>, sqlx::Error> {
        let sql = format!(
            "SELECT {} FROM posts \
             WHERE thread_id = $1 \
               AND id = (SELECT first_post_id FROM threads WHERE id = $1) \
             FETCH FIRST 1 ROW ONLY",
            Self::POST_COLS
        );
        let row = sqlx::query(&sql)
            .bind(thread_id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(Self::post_from_row).transpose()
    }

    async fn replies_page_async(
        &self,
        thread_id: &str,
        op_id: &str,
        excluded_post_id: Option<&str>,
        anchor: &ReplyAnchor,
        limit: i64,
    ) -> Result<Vec<Post>, sqlx::Error> {
        // Replies = every post in the thread except the original (`id <> op_id`). The keyset
        // predicate is the portable expanded form (no row-value comparison), matching the content
        // crates; First/After walk ascending, Before/Latest walk descending.
        let rows = match anchor {
            ReplyAnchor::First => {
                let sql = format!(
                    "SELECT {} FROM posts WHERE thread_id = $1 AND id <> $2 \
                     AND ($3 IS NULL OR id <> $3) \
                     ORDER BY created_at ASC, id ASC LIMIT $4",
                    Self::POST_COLS
                );
                sqlx::query(&sql)
                    .bind(thread_id)
                    .bind(op_id)
                    .bind(excluded_post_id)
                    .bind(limit)
                    .fetch_all(&self.pool)
                    .await?
            }
            ReplyAnchor::Latest => {
                let sql = format!(
                    "SELECT {} FROM posts WHERE thread_id = $1 AND id <> $2 \
                     AND ($3 IS NULL OR id <> $3) \
                     ORDER BY created_at DESC, id DESC LIMIT $4",
                    Self::POST_COLS
                );
                sqlx::query(&sql)
                    .bind(thread_id)
                    .bind(op_id)
                    .bind(excluded_post_id)
                    .bind(limit)
                    .fetch_all(&self.pool)
                    .await?
            }
            ReplyAnchor::From(ts, id) => {
                let sql = format!(
                    "SELECT {} FROM posts WHERE thread_id = $1 AND id <> $2 \
                     AND ($3 IS NULL OR id <> $3) \
                     AND (created_at > $4 OR (created_at = $4 AND id >= $5)) \
                     ORDER BY created_at ASC, id ASC LIMIT $6",
                    Self::POST_COLS
                );
                sqlx::query(&sql)
                    .bind(thread_id)
                    .bind(op_id)
                    .bind(excluded_post_id)
                    .bind(ts)
                    .bind(id)
                    .bind(limit)
                    .fetch_all(&self.pool)
                    .await?
            }
            ReplyAnchor::After(ts, id) => {
                let sql = format!(
                    "SELECT {} FROM posts WHERE thread_id = $1 AND id <> $2 \
                     AND ($3 IS NULL OR id <> $3) \
                     AND (created_at > $4 OR (created_at = $4 AND id > $5)) \
                     ORDER BY created_at ASC, id ASC LIMIT $6",
                    Self::POST_COLS
                );
                sqlx::query(&sql)
                    .bind(thread_id)
                    .bind(op_id)
                    .bind(excluded_post_id)
                    .bind(ts)
                    .bind(id)
                    .bind(limit)
                    .fetch_all(&self.pool)
                    .await?
            }
            ReplyAnchor::Before(ts, id) => {
                let sql = format!(
                    "SELECT {} FROM posts WHERE thread_id = $1 AND id <> $2 \
                     AND ($3 IS NULL OR id <> $3) \
                     AND (created_at < $4 OR (created_at = $4 AND id < $5)) \
                     ORDER BY created_at DESC, id DESC LIMIT $6",
                    Self::POST_COLS
                );
                sqlx::query(&sql)
                    .bind(thread_id)
                    .bind(op_id)
                    .bind(excluded_post_id)
                    .bind(ts)
                    .bind(id)
                    .bind(limit)
                    .fetch_all(&self.pool)
                    .await?
            }
            ReplyAnchor::Around(ts, id) => {
                let sql = format!(
                    "SELECT {} FROM posts WHERE thread_id = $1 AND id <> $2 \
                     AND ($3 IS NULL OR id <> $3) \
                     AND (created_at < $4 OR (created_at = $4 AND id <= $5)) \
                     ORDER BY created_at DESC, id DESC LIMIT $6",
                    Self::POST_COLS
                );
                sqlx::query(&sql)
                    .bind(thread_id)
                    .bind(op_id)
                    .bind(excluded_post_id)
                    .bind(ts)
                    .bind(id)
                    .bind(limit)
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        rows.iter().map(Self::post_from_row).collect()
    }

    async fn create_thread_async(
        &self,
        thread: &Thread,
        first_post: &Post,
    ) -> Result<(), StoreError> {
        if first_post.thread_id != thread.id {
            return Err(StoreError::InvalidOperation(
                "the original post must belong to the new thread".to_string(),
            ));
        }
        let mut tx = self.pool.begin().await.map_err(backend)?;
        sqlx::query_scalar::<_, String>("SELECT id FROM categories WHERE id = $1 FOR UPDATE")
            .bind(&thread.category_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(backend)?
            .ok_or_else(|| StoreError::NotFound("category not found".to_string()))?;
        Self::register_identity_alias_tx(
            &mut tx,
            &first_post.author_sub,
            &first_post.author_email,
            first_post.created_at,
        )
        .await
        .map_err(backend)?;
        sqlx::query(
            "INSERT INTO threads \
                 (id, category_id, title, author_sub, author_email, created_at, last_at, first_body_md, first_post_id, locked, pinned, accepted_post_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(&thread.id)
        .bind(&thread.category_id)
        .bind(&thread.title)
        .bind(&thread.author_sub)
        .bind(&thread.author_email)
        .bind(thread.created_at)
        .bind(thread.last_at)
        .bind(&first_post.body_md)
        .bind(&first_post.id)
        .bind(thread.locked)
        .bind(thread.pinned)
        .bind(&thread.accepted_post_id)
        .execute(&mut *tx)
        .await
        .map_err(backend)?;
        sqlx::query(
            "INSERT INTO posts \
                 (id, thread_id, body_md, quoted_post_id, author_sub, author_email, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&first_post.id)
        .bind(&first_post.thread_id)
        .bind(&first_post.body_md)
        .bind(&first_post.quoted_post_id)
        .bind(&first_post.author_sub)
        .bind(&first_post.author_email)
        .bind(first_post.created_at)
        .execute(&mut *tx)
        .await
        .map_err(backend)?;
        Self::insert_catch_up_post_point_tx(&mut tx, first_post).await?;
        tx.commit().await.map_err(backend)?;
        Ok(())
    }

    async fn create_thread_with_activity_async(
        &self,
        thread: &Thread,
        first_post: &Post,
        mentioned_usernames: &[String],
        activity_id: &str,
    ) -> Result<ActivityMutation, StoreError> {
        let mentioned_aliases = bounded_mention_aliases(mentioned_usernames)?;
        if first_post.thread_id != thread.id {
            return Err(StoreError::InvalidOperation(
                "the original post must belong to the new thread".to_string(),
            ));
        }
        let mut tx = self.pool.begin().await.map_err(backend)?;
        sqlx::query_scalar::<_, String>("SELECT id FROM categories WHERE id = $1 FOR UPDATE")
            .bind(&thread.category_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(backend)?
            .ok_or_else(|| StoreError::NotFound("category not found".to_string()))?;
        Self::register_identity_alias_tx(
            &mut tx,
            &first_post.author_sub,
            &first_post.author_email,
            first_post.created_at,
        )
        .await
        .map_err(backend)?;
        let mut deliveries = Self::resolve_mention_deliveries_tx(
            &mut tx,
            &mentioned_aliases,
            &first_post.author_sub,
        )
        .await
        .map_err(backend)?;
        dedupe_deliveries(&mut deliveries);
        sqlx::query(
            "INSERT INTO threads \
                 (id, category_id, title, author_sub, author_email, created_at, last_at, first_body_md, first_post_id, locked, pinned, accepted_post_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(&thread.id)
        .bind(&thread.category_id)
        .bind(&thread.title)
        .bind(&thread.author_sub)
        .bind(&thread.author_email)
        .bind(thread.created_at)
        .bind(thread.last_at)
        .bind(&first_post.body_md)
        .bind(&first_post.id)
        .bind(thread.locked)
        .bind(thread.pinned)
        .bind(&thread.accepted_post_id)
        .execute(&mut *tx)
        .await
        .map_err(backend)?;
        sqlx::query(
            "INSERT INTO posts \
                 (id, thread_id, body_md, quoted_post_id, author_sub, author_email, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&first_post.id)
        .bind(&first_post.thread_id)
        .bind(&first_post.body_md)
        .bind(&first_post.quoted_post_id)
        .bind(&first_post.author_sub)
        .bind(&first_post.author_email)
        .bind(first_post.created_at)
        .execute(&mut *tx)
        .await
        .map_err(backend)?;
        Self::insert_catch_up_post_point_tx(&mut tx, first_post).await?;
        Self::replace_mentions_tx(
            &mut tx,
            &first_post.id,
            &thread.id,
            &mentioned_aliases,
            first_post.created_at,
        )
        .await
        .map_err(backend)?;
        Self::insert_activity_tx(
            &mut tx,
            &ActivityEvent {
                id: activity_id.to_string(),
                kind: ActivityKind::PostCreated,
                thread_id: thread.id.clone(),
                post_id: first_post.id.clone(),
                actor_sub: first_post.author_sub.clone(),
                created_at: first_post.created_at,
            },
            &deliveries,
        )
        .await
        .map_err(backend)?;
        tx.commit().await.map_err(backend)?;
        Ok(ActivityMutation {
            delivery_subjects: delivery_subjects(&deliveries),
        })
    }

    async fn add_reply_async(&self, post: &Post) -> Result<(), StoreError> {
        for _ in 0..4 {
            let category_hint =
                sqlx::query_scalar::<_, String>("SELECT category_id FROM threads WHERE id = $1")
                    .bind(&post.thread_id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(backend)?
                    .ok_or_else(|| StoreError::NotFound("thread not found".to_string()))?;

            let mut tx = self.pool.begin().await.map_err(backend)?;
            sqlx::query_scalar::<_, String>("SELECT id FROM categories WHERE id = $1 FOR UPDATE")
                .bind(&category_hint)
                .fetch_optional(&mut *tx)
                .await
                .map_err(backend)?
                .ok_or_else(|| StoreError::NotFound("category not found".to_string()))?;
            let thread =
                sqlx::query("SELECT category_id, locked FROM threads WHERE id = $1 FOR UPDATE")
                    .bind(&post.thread_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(backend)?;
            let Some(thread) = thread else {
                return Err(StoreError::NotFound("thread not found".to_string()));
            };
            let current_category: String = thread.try_get("category_id").map_err(backend)?;
            if current_category != category_hint {
                continue;
            }
            if thread.try_get::<bool, _>("locked").map_err(backend)? {
                return Err(StoreError::InvalidOperation(
                    "this thread is locked — no new replies".to_string(),
                ));
            }
            if !post.quoted_post_id.is_empty() {
                let quoted_thread = sqlx::query_scalar::<_, String>(
                    "SELECT thread_id FROM posts WHERE id = $1 FOR UPDATE",
                )
                .bind(&post.quoted_post_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(backend)?;
                if quoted_thread.as_deref() != Some(post.thread_id.as_str()) {
                    return Err(StoreError::InvalidOperation(
                        "quoted post must belong to this thread".to_string(),
                    ));
                }
            }
            Self::register_identity_alias_tx(
                &mut tx,
                &post.author_sub,
                &post.author_email,
                post.created_at,
            )
            .await
            .map_err(backend)?;
            sqlx::query(
                "INSERT INTO posts \
                     (id, thread_id, body_md, quoted_post_id, author_sub, author_email, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(&post.id)
            .bind(&post.thread_id)
            .bind(&post.body_md)
            .bind(&post.quoted_post_id)
            .bind(&post.author_sub)
            .bind(&post.author_email)
            .bind(post.created_at)
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
            Self::insert_catch_up_post_point_tx(&mut tx, post).await?;
            sqlx::query("UPDATE threads SET last_at = $1 WHERE id = $2")
                .bind(post.created_at)
                .bind(&post.thread_id)
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
            tx.commit().await.map_err(backend)?;
            return Ok(());
        }
        Err(StoreError::Backend(
            "thread category changed repeatedly; retry the reply".to_string(),
        ))
    }

    async fn add_reply_with_activity_async(
        &self,
        post: &Post,
        mentioned_usernames: &[String],
        activity_id: &str,
    ) -> Result<ActivityMutation, StoreError> {
        let mentioned_aliases = bounded_mention_aliases(mentioned_usernames)?;
        for _ in 0..4 {
            let category_hint =
                sqlx::query_scalar::<_, String>("SELECT category_id FROM threads WHERE id = $1")
                    .bind(&post.thread_id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(backend)?
                    .ok_or_else(|| StoreError::NotFound("thread not found".to_string()))?;
            let mut tx = self.pool.begin().await.map_err(backend)?;
            sqlx::query_scalar::<_, String>("SELECT id FROM categories WHERE id = $1 FOR UPDATE")
                .bind(&category_hint)
                .fetch_optional(&mut *tx)
                .await
                .map_err(backend)?
                .ok_or_else(|| StoreError::NotFound("category not found".to_string()))?;
            let thread_sql = format!(
                "SELECT {} FROM threads WHERE id = $1 FOR UPDATE",
                Self::THREAD_COLS
            );
            let thread_row = sqlx::query(&thread_sql)
                .bind(&post.thread_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(backend)?;
            let Some(thread_row) = thread_row else {
                return Err(StoreError::NotFound("thread not found".to_string()));
            };
            let thread = Self::thread_from_row(&thread_row).map_err(backend)?;
            if thread.category_id != category_hint {
                continue;
            }
            if thread.locked {
                return Err(StoreError::InvalidOperation(
                    "this thread is locked — no new replies".to_string(),
                ));
            }
            let quoted_author = if post.quoted_post_id.is_empty() {
                None
            } else {
                let post_sql = format!(
                    "SELECT {} FROM posts WHERE id = $1 FOR UPDATE",
                    Self::POST_COLS
                );
                let quoted = sqlx::query(&post_sql)
                    .bind(&post.quoted_post_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(backend)?
                    .ok_or_else(|| {
                        StoreError::InvalidOperation(
                            "quoted post must belong to this thread".to_string(),
                        )
                    })?;
                let quoted = Self::post_from_row(&quoted).map_err(backend)?;
                if quoted.thread_id != post.thread_id {
                    return Err(StoreError::InvalidOperation(
                        "quoted post must belong to this thread".to_string(),
                    ));
                }
                Some(quoted.author_sub)
            };
            let follower_rows = sqlx::query(
                "SELECT subscriber_sub FROM thread_subscriptions \
                 WHERE thread_id = $1 \
                   AND NOT EXISTS (\
                       SELECT 1 FROM thread_follow_preferences AS preference \
                       WHERE preference.thread_id = thread_subscriptions.thread_id \
                         AND preference.subscriber_sub = thread_subscriptions.subscriber_sub \
                         AND preference.level = 'mute'\
                   ) \
                 ORDER BY subscriber_sub LIMIT $2",
            )
            .bind(&post.thread_id)
            .bind((MAX_THREAD_FOLLOWERS + 1) as i64)
            .fetch_all(&mut *tx)
            .await
            .map_err(backend)?;
            if follower_rows.len() > MAX_THREAD_FOLLOWERS {
                return Err(StoreError::InvalidOperation(format!(
                    "a thread may have at most {MAX_THREAD_FOLLOWERS} followers"
                )));
            }
            Self::register_identity_alias_tx(
                &mut tx,
                &post.author_sub,
                &post.author_email,
                post.created_at,
            )
            .await
            .map_err(backend)?;
            let mut deliveries = Vec::new();
            if let Some(delivery) =
                subject_delivery(&thread.author_sub, &post.author_sub, ActivityReason::Reply)
            {
                deliveries.push(delivery);
            }
            if let Some(quoted_author) = quoted_author.as_deref() {
                if let Some(delivery) =
                    subject_delivery(quoted_author, &post.author_sub, ActivityReason::Reply)
                {
                    deliveries.push(delivery);
                }
            }
            for row in follower_rows {
                let subscriber_sub: String = row.try_get("subscriber_sub").map_err(backend)?;
                if let Some(delivery) =
                    subject_delivery(&subscriber_sub, &post.author_sub, ActivityReason::Following)
                {
                    deliveries.push(delivery);
                }
            }
            deliveries.extend(
                Self::resolve_mention_deliveries_tx(&mut tx, &mentioned_aliases, &post.author_sub)
                    .await
                    .map_err(backend)?,
            );
            dedupe_deliveries(&mut deliveries);

            sqlx::query(
                "INSERT INTO posts \
                     (id, thread_id, body_md, quoted_post_id, author_sub, author_email, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(&post.id)
            .bind(&post.thread_id)
            .bind(&post.body_md)
            .bind(&post.quoted_post_id)
            .bind(&post.author_sub)
            .bind(&post.author_email)
            .bind(post.created_at)
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
            Self::insert_catch_up_post_point_tx(&mut tx, post).await?;
            sqlx::query("UPDATE threads SET last_at = $1 WHERE id = $2")
                .bind(post.created_at)
                .bind(&post.thread_id)
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
            Self::replace_mentions_tx(
                &mut tx,
                &post.id,
                &post.thread_id,
                &mentioned_aliases,
                post.created_at,
            )
            .await
            .map_err(backend)?;
            Self::insert_activity_tx(
                &mut tx,
                &ActivityEvent {
                    id: activity_id.to_string(),
                    kind: ActivityKind::PostCreated,
                    thread_id: post.thread_id.clone(),
                    post_id: post.id.clone(),
                    actor_sub: post.author_sub.clone(),
                    created_at: post.created_at,
                },
                &deliveries,
            )
            .await
            .map_err(backend)?;
            tx.commit().await.map_err(backend)?;
            return Ok(ActivityMutation {
                delivery_subjects: delivery_subjects(&deliveries),
            });
        }
        Err(StoreError::Backend(
            "thread category changed repeatedly; retry the reply".to_string(),
        ))
    }

    async fn replace_mentions_async(
        &self,
        post_id: &str,
        thread_id: &str,
        mentioned_usernames: &[String],
        created_at: i64,
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM post_mentions WHERE post_id = $1")
            .bind(post_id)
            .execute(&mut *tx)
            .await?;
        for name in mentioned_usernames {
            sqlx::query(
                "INSERT INTO post_mentions (post_id, thread_id, mentioned_username, created_at) \
                 VALUES ($1, $2, $3, $4) ON CONFLICT (post_id, mentioned_username) DO NOTHING",
            )
            .bind(post_id)
            .bind(thread_id)
            .bind(name)
            .bind(created_at)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn count_mentions_for_user_async(
        &self,
        mentioned_username: &str,
    ) -> Result<i64, sqlx::Error> {
        let row =
            sqlx::query("SELECT COUNT(*) AS n FROM post_mentions WHERE mentioned_username = $1")
                .bind(mentioned_username)
                .fetch_one(&self.pool)
                .await?;
        row.try_get("n")
    }

    async fn mentions_for_user_async(
        &self,
        mentioned_username: &str,
        limit: i64,
    ) -> Result<Vec<Mention>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT post_id, thread_id, mentioned_username, created_at \
             FROM post_mentions WHERE mentioned_username = $1 \
             ORDER BY created_at DESC, post_id DESC LIMIT $2",
        )
        .bind(mentioned_username)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(Mention {
                    post_id: row.try_get("post_id")?,
                    thread_id: row.try_get("thread_id")?,
                    mentioned_username: row.try_get("mentioned_username")?,
                    created_at: row.try_get("created_at")?,
                })
            })
            .collect()
    }

    async fn update_thread_async(
        &self,
        thread_id: &str,
        title: &str,
        op_post_id: &str,
        body_md: &str,
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        // Keep the denormalised `first_body_md` in step with the original post's body.
        sqlx::query("UPDATE threads SET title = $1, first_body_md = $2 WHERE id = $3")
            .bind(title)
            .bind(body_md)
            .bind(thread_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE posts SET body_md = $1 WHERE id = $2")
            .bind(body_md)
            .bind(op_post_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn delete_thread_async(&self, thread_id: &str) -> Result<(), StoreError> {
        for _ in 0..4 {
            let category_hint =
                sqlx::query_scalar::<_, String>("SELECT category_id FROM threads WHERE id = $1")
                    .bind(thread_id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(backend)?;
            let Some(category_hint) = category_hint else {
                return Ok(());
            };
            let mut tx = self.pool.begin().await.map_err(backend)?;
            sqlx::query("SELECT id FROM categories WHERE id = $1 FOR UPDATE")
                .bind(&category_hint)
                .fetch_optional(&mut *tx)
                .await
                .map_err(backend)?;
            let current_category = sqlx::query_scalar::<_, String>(
                "SELECT category_id FROM threads WHERE id = $1 FOR UPDATE",
            )
            .bind(thread_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(backend)?;
            let Some(current_category) = current_category else {
                tx.commit().await.map_err(backend)?;
                return Ok(());
            };
            if current_category != category_hint {
                continue;
            }
            sqlx::query("SELECT id FROM posts WHERE thread_id = $1 ORDER BY id FOR UPDATE")
                .bind(thread_id)
                .fetch_all(&mut *tx)
                .await
                .map_err(backend)?;
            sqlx::query(
                "DELETE FROM post_reactions \
                 WHERE post_id IN (SELECT id FROM posts WHERE thread_id = $1)",
            )
            .bind(thread_id)
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
            sqlx::query("DELETE FROM post_mentions WHERE thread_id = $1")
                .bind(thread_id)
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
            sqlx::query("DELETE FROM thread_subscriptions WHERE thread_id = $1")
                .bind(thread_id)
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
            sqlx::query("DELETE FROM thread_follow_preferences WHERE thread_id = $1")
                .bind(thread_id)
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
            sqlx::query(
                "SELECT id FROM forum_activity_events \
                 WHERE thread_id = $1 ORDER BY id FOR UPDATE",
            )
            .bind(thread_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(backend)?;
            sqlx::query("DELETE FROM forum_activity_events WHERE thread_id = $1")
                .bind(thread_id)
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
            sqlx::query("DELETE FROM posts WHERE thread_id = $1")
                .bind(thread_id)
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
            sqlx::query("DELETE FROM threads WHERE id = $1")
                .bind(thread_id)
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
            tx.commit().await.map_err(backend)?;
            return Ok(());
        }
        Err(StoreError::Backend(
            "thread category changed repeatedly; retry the thread delete".to_string(),
        ))
    }

    async fn update_post_async(&self, post_id: &str, body_md: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE posts SET body_md = $1 WHERE id = $2")
            .bind(body_md)
            .bind(post_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Delete a reply transactionally. Returns `false` without mutating when `post_id` is the OP;
    /// callers surface that as a product-level invalid operation instead of silently promoting a
    /// reply owned by another author.
    async fn delete_post_async(&self, post_id: &str) -> Result<bool, StoreError> {
        for _ in 0..4 {
            let thread_hint =
                sqlx::query_scalar::<_, String>("SELECT thread_id FROM posts WHERE id = $1")
                    .bind(post_id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(backend)?;
            let Some(thread_hint) = thread_hint else {
                return Ok(true);
            };
            let category_hint =
                sqlx::query_scalar::<_, String>("SELECT category_id FROM threads WHERE id = $1")
                    .bind(&thread_hint)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(backend)?
                    .ok_or_else(|| StoreError::NotFound("thread not found".to_string()))?;

            let mut tx = self.pool.begin().await.map_err(backend)?;
            sqlx::query("SELECT id FROM categories WHERE id = $1 FOR UPDATE")
                .bind(&category_hint)
                .fetch_optional(&mut *tx)
                .await
                .map_err(backend)?;
            let thread_sql = format!(
                "SELECT {}, first_post_id FROM threads WHERE id = $1 FOR UPDATE",
                Self::THREAD_COLS
            );
            let thread_row = sqlx::query(&thread_sql)
                .bind(&thread_hint)
                .fetch_optional(&mut *tx)
                .await
                .map_err(backend)?
                .ok_or_else(|| StoreError::NotFound("thread not found".to_string()))?;
            let mut thread = Self::thread_from_row(&thread_row).map_err(backend)?;
            let first_post_id: String = thread_row.try_get("first_post_id").map_err(backend)?;
            if thread.category_id != category_hint {
                continue;
            }
            let post_sql = format!(
                "SELECT {} FROM posts WHERE id = $1 FOR UPDATE",
                Self::POST_COLS
            );
            let post_row = sqlx::query(&post_sql)
                .bind(post_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(backend)?;
            let Some(post_row) = post_row else {
                tx.commit().await.map_err(backend)?;
                return Ok(true);
            };
            let post = Self::post_from_row(&post_row).map_err(backend)?;
            if post.thread_id != thread_hint {
                continue;
            }
            if post.id == first_post_id {
                return Ok(false);
            }

            sqlx::query("DELETE FROM post_reactions WHERE post_id = $1")
                .bind(post_id)
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
            sqlx::query("DELETE FROM post_mentions WHERE post_id = $1")
                .bind(post_id)
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
            sqlx::query(
                "SELECT id FROM forum_activity_events \
                 WHERE post_id = $1 ORDER BY id FOR UPDATE",
            )
            .bind(post_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(backend)?;
            sqlx::query("DELETE FROM forum_activity_events WHERE post_id = $1")
                .bind(post_id)
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
            sqlx::query("UPDATE posts SET quoted_post_id = '' WHERE quoted_post_id = $1")
                .bind(post_id)
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
            sqlx::query("DELETE FROM posts WHERE id = $1")
                .bind(post_id)
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
            let newest_at: Option<i64> =
                sqlx::query_scalar("SELECT MAX(created_at) FROM posts WHERE thread_id = $1")
                    .bind(&thread_hint)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(backend)?;
            let newest_at = newest_at.ok_or_else(|| {
                StoreError::Backend("thread has no original post after reply deletion".to_string())
            })?;
            if thread.accepted_post_id == post_id || thread.accepted_post_id == first_post_id {
                thread.accepted_post_id.clear();
            }
            sqlx::query("UPDATE threads SET last_at = $1, accepted_post_id = $2 WHERE id = $3")
                .bind(newest_at)
                .bind(&thread.accepted_post_id)
                .bind(&thread_hint)
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
            tx.commit().await.map_err(backend)?;
            return Ok(true);
        }
        Err(StoreError::Backend(
            "thread category changed repeatedly; retry the post delete".to_string(),
        ))
    }

    async fn set_thread_locked_async(
        &self,
        thread_id: &str,
        locked: bool,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE threads SET locked = $1 WHERE id = $2")
            .bind(locked)
            .bind(thread_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn set_thread_pinned_async(
        &self,
        thread_id: &str,
        pinned: bool,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE threads SET pinned = $1 WHERE id = $2")
            .bind(pinned)
            .bind(thread_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn move_thread_to_category_async(
        &self,
        thread_id: &str,
        category_id: &str,
    ) -> Result<(), StoreError> {
        for _ in 0..4 {
            let source_hint =
                sqlx::query_scalar::<_, String>("SELECT category_id FROM threads WHERE id = $1")
                    .bind(thread_id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(backend)?
                    .ok_or_else(|| StoreError::NotFound("thread not found".to_string()))?;
            let mut tx = self.pool.begin().await.map_err(backend)?;
            let mut category_ids = vec![source_hint.clone(), category_id.to_string()];
            category_ids.sort();
            category_ids.dedup();
            let mut formats = HashMap::new();
            for locked_id in category_ids {
                let format = sqlx::query_scalar::<_, String>(
                    "SELECT format FROM categories WHERE id = $1 FOR UPDATE",
                )
                .bind(&locked_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(backend)?;
                if let Some(format) = format {
                    formats.insert(locked_id, format);
                }
            }
            if !formats.contains_key(&source_hint) {
                return Err(StoreError::NotFound(
                    "source category not found".to_string(),
                ));
            }
            let target_format = formats
                .get(category_id)
                .and_then(|format| CategoryFormat::parse(format))
                .ok_or_else(|| StoreError::InvalidOperation("unknown category".to_string()))?;
            let thread_sql = format!(
                "SELECT {}, first_post_id FROM threads WHERE id = $1 FOR UPDATE",
                Self::THREAD_COLS
            );
            let row = sqlx::query(&thread_sql)
                .bind(thread_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(backend)?
                .ok_or_else(|| StoreError::NotFound("thread not found".to_string()))?;
            let mut thread = Self::thread_from_row(&row).map_err(backend)?;
            let first_post_id: String = row.try_get("first_post_id").map_err(backend)?;
            if thread.category_id != source_hint {
                continue;
            }
            let accepted_thread = if thread.accepted_post_id.trim().is_empty() {
                None
            } else {
                sqlx::query_scalar::<_, String>(
                    "SELECT thread_id FROM posts WHERE id = $1 FOR UPDATE",
                )
                .bind(&thread.accepted_post_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(backend)?
            };
            let valid_solution = thread.accepted_post_id != first_post_id
                && accepted_thread.as_deref() == Some(thread_id);
            if thread.category_id != category_id && valid_solution && !target_format.is_question() {
                return Err(StoreError::InvalidOperation(
                    "unmark the accepted answer before moving this thread to a discussion category"
                        .to_string(),
                ));
            }
            if !valid_solution {
                thread.accepted_post_id.clear();
            }
            sqlx::query("UPDATE threads SET category_id = $1, accepted_post_id = $2 WHERE id = $3")
                .bind(category_id)
                .bind(&thread.accepted_post_id)
                .bind(thread_id)
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
            tx.commit().await.map_err(backend)?;
            return Ok(());
        }
        Err(StoreError::Backend(
            "thread category changed repeatedly; retry the move".to_string(),
        ))
    }

    async fn mutate_accepted_answer_async(
        &self,
        thread_id: &str,
        action: AcceptedAnswerAction,
        activity: Option<(&str, &str, i64)>,
    ) -> Result<AcceptedAnswerMutation, StoreError> {
        for _ in 0..4 {
            let category_hint =
                sqlx::query_scalar::<_, String>("SELECT category_id FROM threads WHERE id = $1")
                    .bind(thread_id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(backend)?
                    .ok_or_else(|| StoreError::NotFound("thread not found".to_string()))?;
            let mut tx = self.pool.begin().await.map_err(backend)?;
            let category_format = sqlx::query_scalar::<_, String>(
                "SELECT format FROM categories WHERE id = $1 FOR UPDATE",
            )
            .bind(&category_hint)
            .fetch_optional(&mut *tx)
            .await
            .map_err(backend)?
            .ok_or_else(|| StoreError::NotFound("category not found".to_string()))?;
            let thread_sql = format!(
                "SELECT {}, first_post_id FROM threads WHERE id = $1 FOR UPDATE",
                Self::THREAD_COLS
            );
            let row = sqlx::query(&thread_sql)
                .bind(thread_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(backend)?
                .ok_or_else(|| StoreError::NotFound("thread not found".to_string()))?;
            let mut thread = Self::thread_from_row(&row).map_err(backend)?;
            let first_post_id: String = row.try_get("first_post_id").map_err(backend)?;
            if thread.category_id != category_hint {
                continue;
            }

            let (accepted_post, next_id) = match &action {
                AcceptedAnswerAction::Clear => (None, String::new()),
                AcceptedAnswerAction::Accept { post_id } => {
                    if CategoryFormat::parse(&category_format).unwrap_or_default()
                        != CategoryFormat::Question
                    {
                        return Err(StoreError::InvalidOperation(
                            "accepted answers are available only in question categories"
                                .to_string(),
                        ));
                    }
                    let post_id = post_id.trim();
                    if post_id.is_empty() {
                        return Err(StoreError::InvalidOperation(
                            "reply is required when accepting an answer".to_string(),
                        ));
                    }
                    if post_id == first_post_id {
                        return Err(StoreError::InvalidOperation(
                            "the original post cannot be the accepted answer".to_string(),
                        ));
                    }
                    let post_sql = format!(
                        "SELECT {} FROM posts WHERE id = $1 FOR UPDATE",
                        Self::POST_COLS
                    );
                    let post_row = sqlx::query(&post_sql)
                        .bind(post_id)
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(backend)?
                        .ok_or_else(|| StoreError::NotFound("reply not found".to_string()))?;
                    let post = Self::post_from_row(&post_row).map_err(backend)?;
                    if post.thread_id != thread_id {
                        return Err(StoreError::NotFound("reply not found".to_string()));
                    }
                    (Some(post), post_id.to_string())
                }
            };
            let changed = thread.accepted_post_id != next_id;
            sqlx::query("UPDATE threads SET accepted_post_id = $1 WHERE id = $2")
                .bind(&next_id)
                .bind(thread_id)
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
            thread.accepted_post_id = next_id;
            let mut deliveries = Vec::new();
            if changed {
                if let (Some(post), Some((activity_id, actor_sub, created_at))) =
                    (accepted_post.as_ref(), activity)
                {
                    if let Some(delivery) =
                        subject_delivery(&post.author_sub, actor_sub, ActivityReason::Answer)
                    {
                        deliveries.push(delivery);
                    }
                    Self::insert_activity_tx(
                        &mut tx,
                        &ActivityEvent {
                            id: activity_id.to_string(),
                            kind: ActivityKind::AnswerAccepted,
                            thread_id: thread_id.to_string(),
                            post_id: post.id.clone(),
                            actor_sub: actor_sub.to_string(),
                            created_at,
                        },
                        &deliveries,
                    )
                    .await
                    .map_err(backend)?;
                }
            }
            tx.commit().await.map_err(backend)?;
            return Ok(AcceptedAnswerMutation {
                thread,
                accepted_post,
                changed,
                delivery_subjects: delivery_subjects(&deliveries),
            });
        }
        Err(StoreError::Backend(
            "thread category changed repeatedly; retry the answer mutation".to_string(),
        ))
    }

    async fn set_thread_follow_level_async(
        &self,
        thread_id: &str,
        subscriber_sub: &str,
        level: ThreadFollowLevel,
        created_at: i64,
    ) -> Result<(), StoreError> {
        for _ in 0..4 {
            let category_hint =
                sqlx::query_scalar::<_, String>("SELECT category_id FROM threads WHERE id = $1")
                    .bind(thread_id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(backend)?
                    .ok_or_else(|| StoreError::NotFound("thread not found".to_string()))?;
            let mut tx = self.pool.begin().await.map_err(backend)?;
            sqlx::query_scalar::<_, String>("SELECT id FROM categories WHERE id = $1 FOR UPDATE")
                .bind(&category_hint)
                .fetch_optional(&mut *tx)
                .await
                .map_err(backend)?
                .ok_or_else(|| StoreError::NotFound("category not found".to_string()))?;
            let current_category = sqlx::query_scalar::<_, String>(
                "SELECT category_id FROM threads WHERE id = $1 FOR UPDATE",
            )
            .bind(thread_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(backend)?
            .ok_or_else(|| StoreError::NotFound("thread not found".to_string()))?;
            if current_category != category_hint {
                continue;
            }
            let legacy_watch = sqlx::query_scalar::<_, String>(
                "SELECT subscriber_sub FROM thread_subscriptions \
                 WHERE thread_id = $1 AND subscriber_sub = $2",
            )
            .bind(thread_id)
            .bind(subscriber_sub)
            .fetch_optional(&mut *tx)
            .await
            .map_err(backend)?;
            if level == ThreadFollowLevel::Watch && legacy_watch.is_none() {
                let watchers = sqlx::query_scalar::<_, String>(
                    "SELECT subscriber_sub FROM thread_subscriptions \
                     WHERE thread_id = $1 \
                     ORDER BY subscriber_sub LIMIT $2",
                )
                .bind(thread_id)
                .bind((MAX_THREAD_FOLLOWERS + 1) as i64)
                .fetch_all(&mut *tx)
                .await
                .map_err(backend)?;
                if watchers.len() >= MAX_THREAD_FOLLOWERS {
                    return Err(StoreError::InvalidOperation(format!(
                        "a thread may have at most {MAX_THREAD_FOLLOWERS} watchers"
                    )));
                }
            }
            match level {
                ThreadFollowLevel::None => {
                    sqlx::query(
                        "DELETE FROM thread_subscriptions \
                         WHERE thread_id = $1 AND subscriber_sub = $2",
                    )
                    .bind(thread_id)
                    .bind(subscriber_sub)
                    .execute(&mut *tx)
                    .await
                    .map_err(backend)?;
                    sqlx::query(
                        "DELETE FROM thread_follow_preferences \
                         WHERE thread_id = $1 AND subscriber_sub = $2",
                    )
                    .bind(thread_id)
                    .bind(subscriber_sub)
                    .execute(&mut *tx)
                    .await
                    .map_err(backend)?;
                }
                ThreadFollowLevel::Watch => {
                    sqlx::query(
                        "INSERT INTO thread_subscriptions \
                             (thread_id, subscriber_sub, created_at) \
                         VALUES ($1, $2, $3) \
                         ON CONFLICT (thread_id, subscriber_sub) DO UPDATE \
                         SET created_at = EXCLUDED.created_at",
                    )
                    .bind(thread_id)
                    .bind(subscriber_sub)
                    .bind(created_at)
                    .execute(&mut *tx)
                    .await
                    .map_err(backend)?;
                    sqlx::query(
                        "DELETE FROM thread_follow_preferences \
                         WHERE thread_id = $1 AND subscriber_sub = $2",
                    )
                    .bind(thread_id)
                    .bind(subscriber_sub)
                    .execute(&mut *tx)
                    .await
                    .map_err(backend)?;
                }
                ThreadFollowLevel::Follow | ThreadFollowLevel::Mute => {
                    sqlx::query(
                        "DELETE FROM thread_subscriptions \
                         WHERE thread_id = $1 AND subscriber_sub = $2",
                    )
                    .bind(thread_id)
                    .bind(subscriber_sub)
                    .execute(&mut *tx)
                    .await
                    .map_err(backend)?;
                    sqlx::query(
                        "INSERT INTO thread_follow_preferences \
                             (thread_id, subscriber_sub, level, created_at) \
                         VALUES ($1, $2, $3, $4) \
                         ON CONFLICT (thread_id, subscriber_sub) DO UPDATE \
                         SET level = EXCLUDED.level, created_at = EXCLUDED.created_at",
                    )
                    .bind(thread_id)
                    .bind(subscriber_sub)
                    .bind(level.as_str())
                    .bind(created_at)
                    .execute(&mut *tx)
                    .await
                    .map_err(backend)?;
                }
            }

            if !level.delivers_generic_activity() {
                // Preference changes serialize on the same category -> thread locks as reply
                // creation. Removing only `following` keeps direct reply/mention/answer authority.
                sqlx::query(
                    "DELETE FROM forum_activity_deliveries \
                     WHERE recipient_kind = 'subject' AND recipient_key = $1 \
                       AND reason = 'following' \
                       AND activity_id IN (\
                           SELECT id FROM forum_activity_events WHERE thread_id = $2\
                       )",
                )
                .bind(subscriber_sub)
                .bind(thread_id)
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
                sqlx::query(
                    "DELETE FROM forum_activity_receipts AS receipt \
                     WHERE receipt.viewer_sub = $1 \
                       AND receipt.activity_id IN (\
                           SELECT id FROM forum_activity_events WHERE thread_id = $2\
                       ) \
                       AND NOT EXISTS (\
                           SELECT 1 FROM forum_activity_deliveries AS delivery \
                           WHERE delivery.activity_id = receipt.activity_id \
                             AND delivery.recipient_kind = 'subject' \
                             AND delivery.recipient_key = $1\
                       )",
                )
                .bind(subscriber_sub)
                .bind(thread_id)
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
                sqlx::query(
                    "DELETE FROM forum_activity_events AS event \
                     WHERE event.thread_id = $1 \
                       AND NOT EXISTS (\
                           SELECT 1 FROM forum_activity_deliveries AS delivery \
                           WHERE delivery.activity_id = event.id\
                       )",
                )
                .bind(thread_id)
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
            }
            tx.commit().await.map_err(backend)?;
            return Ok(());
        }
        Err(StoreError::Backend(
            "thread category changed repeatedly; retry the follow command".to_string(),
        ))
    }

    async fn thread_follow_level_async(
        &self,
        thread_id: &str,
        subscriber_sub: &str,
    ) -> Result<ThreadFollowLevel, StoreError> {
        let stored = sqlx::query_scalar::<_, String>(
            "SELECT CASE \
                 WHEN EXISTS (\
                     SELECT 1 FROM thread_follow_preferences \
                     WHERE thread_id = $1 AND subscriber_sub = $2 AND level = 'mute'\
                 ) THEN 'mute' \
                 WHEN EXISTS (\
                     SELECT 1 FROM thread_subscriptions \
                     WHERE thread_id = $1 AND subscriber_sub = $2\
                 ) THEN 'watch' \
                 ELSE COALESCE((\
                     SELECT level FROM thread_follow_preferences \
                     WHERE thread_id = $1 AND subscriber_sub = $2\
                 ), 'none') \
             END",
        )
        .bind(thread_id)
        .bind(subscriber_sub)
        .fetch_one(&self.pool)
        .await
        .map_err(backend)?;
        ThreadFollowLevel::parse(&stored).ok_or_else(|| {
            StoreError::Backend(format!(
                "unknown thread follow level for {thread_id}: {stored}"
            ))
        })
    }

    async fn thread_personal_signals_async(
        &self,
        viewer_sub: &str,
        thread_ids: &[String],
    ) -> Result<HashMap<String, ThreadPersonalSignals>, StoreError> {
        let thread_ids = bounded_personal_thread_ids(thread_ids)?;
        if thread_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let placeholders = (0..thread_ids.len())
            .map(|index| format!("${}", index + 2))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT t.id AS thread_id, \
                    CASE WHEN preference.level = 'mute' THEN 'mute' \
                         WHEN watcher.subscriber_sub IS NOT NULL THEN 'watch' \
                         ELSE COALESCE(preference.level, 'none') END AS follow_level, \
                    CASE WHEN t.author_sub = $1 THEN TRUE ELSE FALSE END AS authored, \
                    EXISTS (\
                        SELECT 1 FROM posts AS participant \
                        WHERE participant.thread_id = t.id AND participant.author_sub = $1\
                    ) AS participated, \
                    EXISTS (\
                        SELECT 1 FROM forum_bookmarks AS bookmark \
                        JOIN posts AS bookmarked_post ON bookmarked_post.id = bookmark.post_id \
                        WHERE bookmark.owner_sub = $1 AND bookmarked_post.thread_id = t.id\
                    ) AS bookmarked, \
                    EXISTS (\
                        SELECT 1 FROM forum_post_read_receipts AS receipt \
                        JOIN posts AS read_post ON read_post.id = receipt.post_id \
                        WHERE receipt.viewer_sub = $1 AND read_post.thread_id = t.id\
                    ) AS reading_started, \
                    EXISTS (\
                        SELECT 1 FROM posts AS unread_post \
                        WHERE unread_post.thread_id = t.id \
                          AND NOT EXISTS (\
                              SELECT 1 FROM forum_post_read_receipts AS receipt \
                              WHERE receipt.viewer_sub = $1 \
                                AND receipt.post_id = unread_post.id\
                          )\
                    ) AS has_unread \
             FROM threads AS t \
             LEFT JOIN thread_subscriptions AS watcher \
               ON watcher.thread_id = t.id AND watcher.subscriber_sub = $1 \
             LEFT JOIN thread_follow_preferences AS preference \
               ON preference.thread_id = t.id AND preference.subscriber_sub = $1 \
             WHERE t.id IN ({placeholders})"
        );
        let mut query = sqlx::query(&sql).bind(viewer_sub);
        for thread_id in &thread_ids {
            query = query.bind(thread_id);
        }
        let rows = query.fetch_all(&self.pool).await.map_err(backend)?;
        let mut signals = HashMap::new();
        for row in rows {
            let thread_id: String = row.try_get("thread_id").map_err(backend)?;
            let stored_level: String = row.try_get("follow_level").map_err(backend)?;
            let follow_level = ThreadFollowLevel::parse(&stored_level).ok_or_else(|| {
                StoreError::Backend(format!(
                    "unknown thread follow level for {thread_id}: {stored_level}"
                ))
            })?;
            signals.insert(
                thread_id,
                ThreadPersonalSignals {
                    follow_level,
                    authored: row.try_get("authored").map_err(backend)?,
                    participated: row.try_get("participated").map_err(backend)?,
                    bookmarked: row.try_get("bookmarked").map_err(backend)?,
                    reading_started: row.try_get("reading_started").map_err(backend)?,
                    has_unread: row.try_get("has_unread").map_err(backend)?,
                },
            );
        }
        Ok(signals)
    }

    async fn category_focus_level_async(
        &self,
        viewer_sub: &str,
        category_id: &str,
    ) -> Result<CategoryFocusLevel, StoreError> {
        let stored = sqlx::query_scalar::<_, String>(
            "SELECT level FROM forum_category_focus_rules \
             WHERE viewer_sub = $1 AND category_id = $2",
        )
        .bind(viewer_sub)
        .bind(category_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        stored
            .map(|level| {
                CategoryFocusLevel::parse(&level).ok_or_else(|| {
                    StoreError::Backend(format!(
                        "unknown category focus level for {category_id}: {level}"
                    ))
                })
            })
            .transpose()
            .map(|level| level.unwrap_or_default())
    }

    async fn category_focus_rules_async(
        &self,
        viewer_sub: &str,
    ) -> Result<Vec<CategoryFocusRuleItem>, StoreError> {
        if viewer_sub.trim().is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query(
            "SELECT c.id, c.name, c.sort_order, c.format, rule.level \
             FROM forum_category_focus_rules rule \
             JOIN categories c ON c.id = rule.category_id \
             WHERE rule.viewer_sub = $1 \
             ORDER BY c.sort_order ASC, c.id ASC",
        )
        .bind(viewer_sub)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.into_iter()
            .map(|row| {
                let category_id: String = row.try_get("id").map_err(backend)?;
                let raw_level: String = row.try_get("level").map_err(backend)?;
                let level = CategoryFocusLevel::parse(&raw_level).ok_or_else(|| {
                    StoreError::Backend(format!(
                        "unknown category focus level for {category_id}: {raw_level}"
                    ))
                })?;
                let raw_format: String = row.try_get("format").map_err(backend)?;
                Ok(CategoryFocusRuleItem {
                    category: Category {
                        id: category_id,
                        name: row.try_get("name").map_err(backend)?,
                        sort_order: row.try_get("sort_order").map_err(backend)?,
                        format: CategoryFormat::parse(&raw_format).unwrap_or_default(),
                    },
                    level,
                })
            })
            .collect()
    }

    async fn set_category_focus_level_async(
        &self,
        viewer_sub: &str,
        category_id: &str,
        level: CategoryFocusLevel,
        changed_at: i64,
    ) -> Result<(), StoreError> {
        if viewer_sub.trim().is_empty() || changed_at < 0 {
            return Err(StoreError::InvalidOperation(
                "invalid category focus rule".to_string(),
            ));
        }
        let mut tx = self.pool.begin().await.map_err(backend)?;
        sqlx::query_scalar::<_, String>("SELECT id FROM categories WHERE id = $1 FOR UPDATE")
            .bind(category_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(backend)?
            .ok_or_else(|| StoreError::NotFound("category not found".to_string()))?;
        sqlx::query(
            "INSERT INTO forum_category_focus_owner_guards (viewer_sub) VALUES ($1) \
             ON CONFLICT (viewer_sub) DO NOTHING",
        )
        .bind(viewer_sub)
        .execute(&mut *tx)
        .await
        .map_err(backend)?;
        sqlx::query_scalar::<_, String>(
            "SELECT viewer_sub FROM forum_category_focus_owner_guards \
             WHERE viewer_sub = $1 FOR UPDATE",
        )
        .bind(viewer_sub)
        .fetch_one(&mut *tx)
        .await
        .map_err(backend)?;
        let stored = sqlx::query_scalar::<_, String>(
            "SELECT level FROM forum_category_focus_rules \
             WHERE viewer_sub = $1 AND category_id = $2 FOR UPDATE",
        )
        .bind(viewer_sub)
        .bind(category_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(backend)?;

        if level == CategoryFocusLevel::None {
            if stored.is_some() {
                sqlx::query(
                    "DELETE FROM forum_category_focus_rules \
                     WHERE viewer_sub = $1 AND category_id = $2",
                )
                .bind(viewer_sub)
                .bind(category_id)
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
            }
            tx.commit().await.map_err(backend)?;
            return Ok(());
        }

        if let Some(stored) = stored {
            let stored = CategoryFocusLevel::parse(&stored).ok_or_else(|| {
                StoreError::Backend(format!(
                    "unknown category focus level for {category_id}: {stored}"
                ))
            })?;
            if stored != level {
                sqlx::query(
                    "UPDATE forum_category_focus_rules \
                     SET level = $1, updated_at = GREATEST($2, created_at) \
                     WHERE viewer_sub = $3 AND category_id = $4",
                )
                .bind(level.as_str())
                .bind(changed_at)
                .bind(viewer_sub)
                .bind(category_id)
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
            }
            tx.commit().await.map_err(backend)?;
            return Ok(());
        }

        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM forum_category_focus_rules WHERE viewer_sub = $1",
        )
        .bind(viewer_sub)
        .fetch_one(&mut *tx)
        .await
        .map_err(backend)?;
        if count >= MAX_CATEGORY_FOCUS_RULES as i64 {
            return Err(StoreError::InvalidOperation(format!(
                "a user may keep at most {MAX_CATEGORY_FOCUS_RULES} category focus rules"
            )));
        }
        sqlx::query(
            "INSERT INTO forum_category_focus_rules \
                 (viewer_sub, category_id, level, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $4)",
        )
        .bind(viewer_sub)
        .bind(category_id)
        .bind(level.as_str())
        .bind(changed_at)
        .execute(&mut *tx)
        .await
        .map_err(backend)?;
        tx.commit().await.map_err(backend)?;
        Ok(())
    }

    async fn category_focus_page_async(
        &self,
        viewer_sub: &str,
        limit: i64,
        as_of: i64,
    ) -> Result<Vec<CategoryFocusItem>, StoreError> {
        let limit = validate_category_focus_page(limit, as_of)? as i64;
        if limit == 0 || viewer_sub.trim().is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query(
            "SELECT t.id AS id, t.category_id AS category_id, t.title AS title, \
                    t.author_sub AS author_sub, t.author_email AS author_email, \
                    t.created_at AS created_at, t.last_at AS last_at, \
                    t.locked AS locked, t.pinned AS pinned, \
                    CASE WHEN c.format = 'question' AND accepted.id IS NOT NULL \
                         THEN t.accepted_post_id ELSE '' END AS accepted_post_id, \
                    c.name AS focus_category_name, c.sort_order AS focus_category_sort_order, \
                    c.format AS focus_category_format, rule.level AS category_focus_level, \
                    CASE WHEN preference.level = 'mute' THEN 'mute' \
                         WHEN watcher.subscriber_sub IS NOT NULL THEN 'watch' \
                         ELSE COALESCE(preference.level, 'none') END AS thread_follow_level \
             FROM forum_category_focus_rules AS rule \
             JOIN categories AS c ON c.id = rule.category_id \
             JOIN threads AS t ON t.category_id = c.id \
             LEFT JOIN posts AS accepted ON accepted.id = t.accepted_post_id \
                                        AND accepted.thread_id = t.id \
                                        AND accepted.id <> t.first_post_id \
             LEFT JOIN thread_subscriptions AS watcher \
                    ON watcher.thread_id = t.id AND watcher.subscriber_sub = $1 \
             LEFT JOIN thread_follow_preferences AS preference \
                    ON preference.thread_id = t.id AND preference.subscriber_sub = $1 \
             WHERE rule.viewer_sub = $1 AND t.created_at <= $2 \
               AND CASE WHEN preference.level = 'mute' THEN 'mute' \
                        WHEN watcher.subscriber_sub IS NOT NULL THEN 'watch' \
                        ELSE COALESCE(preference.level, 'none') END <> 'mute' \
               AND (rule.level IN ('priority', 'follow') \
                    OR CASE WHEN preference.level = 'mute' THEN 'mute' \
                            WHEN watcher.subscriber_sub IS NOT NULL THEN 'watch' \
                            ELSE COALESCE(preference.level, 'none') END IN ('watch', 'follow')) \
             ORDER BY CASE rule.level WHEN 'priority' THEN 0 WHEN 'follow' THEN 1 ELSE 2 END, \
                      t.pinned DESC, t.last_at DESC, t.created_at DESC, t.id DESC \
             LIMIT $3",
        )
        .bind(viewer_sub)
        .bind(as_of)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        let mut items = Vec::with_capacity(rows.len());
        for row in rows {
            let category_id: String = row.try_get("category_id").map_err(backend)?;
            let stored_category_level: String =
                row.try_get("category_focus_level").map_err(backend)?;
            let category_level =
                CategoryFocusLevel::parse(&stored_category_level).ok_or_else(|| {
                    StoreError::Backend(format!(
                        "unknown category focus level for {category_id}: {stored_category_level}"
                    ))
                })?;
            let stored_thread_level: String =
                row.try_get("thread_follow_level").map_err(backend)?;
            let thread_level = ThreadFollowLevel::parse(&stored_thread_level).ok_or_else(|| {
                StoreError::Backend(format!(
                    "unknown thread follow level in category focus: {stored_thread_level}"
                ))
            })?;
            let reason = category_focus_reason(category_level, thread_level).ok_or_else(|| {
                StoreError::Backend(format!(
                    "category focus query returned an excluded thread in {category_id}"
                ))
            })?;
            let category_format: String = row.try_get("focus_category_format").map_err(backend)?;
            items.push(CategoryFocusItem {
                thread: Self::thread_from_row(&row).map_err(backend)?,
                category: Category {
                    id: category_id,
                    name: row.try_get("focus_category_name").map_err(backend)?,
                    sort_order: row.try_get("focus_category_sort_order").map_err(backend)?,
                    format: CategoryFormat::parse(&category_format).unwrap_or_default(),
                },
                category_level,
                thread_level,
                reason,
            });
        }
        Ok(items)
    }

    async fn catch_up_page_async(
        &self,
        viewer_sub: &str,
        view: CatchUpView,
        as_of: i64,
        snapshot_generation: i64,
        before: Option<&CatchUpCursor>,
        limit: i64,
    ) -> Result<Vec<CatchUpItem>, StoreError> {
        let limit = validate_catch_up_page(view, as_of, snapshot_generation, before, limit)? as i64;
        if limit == 0 {
            return Ok(Vec::new());
        }
        let current_generation = self.catch_up_snapshot_generation_async().await?;
        if snapshot_generation > current_generation {
            return Err(StoreError::InvalidOperation(
                "catch-up snapshot generation is in the future".to_string(),
            ));
        }
        let view_scope = match view {
            CatchUpView::Updates => {
                "unread_count > 0 AND (follow_level IN ('watch', 'follow') OR authored \
                 OR participated OR bookmarked OR reading_started)"
            }
            CatchUpView::Following => "follow_level IN ('watch', 'follow')",
            CatchUpView::Questions => "authored AND category_format = 'question'",
        };
        let candidate_sources = match view {
            CatchUpView::Following => {
                "SELECT watcher.thread_id FROM thread_subscriptions AS watcher \
                  WHERE watcher.subscriber_sub = $1 \
                    AND NOT EXISTS (\
                        SELECT 1 FROM thread_follow_preferences AS preference \
                         WHERE preference.thread_id = watcher.thread_id \
                           AND preference.subscriber_sub = watcher.subscriber_sub \
                           AND preference.level = 'mute'\
                    ) \
                 UNION \
                 SELECT thread_id FROM thread_follow_preferences \
                  WHERE subscriber_sub = $1 AND level = 'follow'"
            }
            CatchUpView::Questions => {
                "SELECT id AS thread_id FROM threads \
                  WHERE author_sub = $1 AND created_at <= $2"
            }
            CatchUpView::Updates => {
                "SELECT watcher.thread_id FROM thread_subscriptions AS watcher \
                  WHERE watcher.subscriber_sub = $1 \
                    AND NOT EXISTS (\
                        SELECT 1 FROM thread_follow_preferences AS preference \
                         WHERE preference.thread_id = watcher.thread_id \
                           AND preference.subscriber_sub = watcher.subscriber_sub \
                           AND preference.level = 'mute'\
                    ) \
                 UNION \
                 SELECT thread_id FROM thread_follow_preferences \
                  WHERE subscriber_sub = $1 AND level = 'follow' \
                 UNION \
                 SELECT id AS thread_id FROM threads WHERE author_sub = $1 \
                 UNION \
                 SELECT thread_id FROM snapshot_posts WHERE author_sub = $1 \
                 UNION \
                 SELECT saved_post.thread_id \
                   FROM forum_bookmarks AS bookmark \
                   JOIN snapshot_posts AS saved_post ON saved_post.id = bookmark.post_id \
                  WHERE bookmark.owner_sub = $1 AND bookmark.created_at <= $2 \
                 UNION \
                 SELECT read_post.thread_id \
                   FROM forum_post_read_receipts AS receipt \
                   JOIN snapshot_posts AS read_post ON read_post.id = receipt.post_id \
                  WHERE receipt.viewer_sub = $1 AND receipt.read_at <= $2 \
                    AND receipt.read_seq <= $3"
            }
        };
        // Candidate ids come directly from every personal authority. In particular, explicit
        // Watch/Follow rows are not intersected with Latest and therefore cannot fall out after
        // 200 newer public threads. Post/read authority is bounded by one commit-ordered generation;
        // wall time remains an additional fail-closed guard for malformed future-dated rows.
        let sql = format!(
            r#"WITH snapshot_points AS (
                 SELECT post_id, thread_id, activity_at, seq
                   FROM forum_catch_up_post_points
                  WHERE seq <= $3 AND activity_at <= $2
             ), snapshot_posts AS (
                 SELECT p.id, p.thread_id, p.body_md, p.quoted_post_id,
                        p.author_sub, p.author_email, p.created_at
                   FROM posts AS p
                   JOIN snapshot_points AS point ON point.post_id = p.id
             ), personal_thread_ids AS (
                 {candidate_sources}
             ), projected AS (
                 SELECT t.id AS id, t.category_id AS category_id, t.title AS title,
                        t.author_sub AS author_sub, t.author_email AS author_email,
                        t.created_at AS created_at, t.last_at AS last_at,
                        t.locked AS locked, t.pinned AS pinned,
                        CASE WHEN c.format = 'question' AND accepted.id IS NOT NULL
                             THEN t.accepted_post_id ELSE '' END AS accepted_post_id,
                        t.first_post_id AS first_post_id,
                        c.name AS category_name, c.format AS category_format,
                        CASE WHEN preference.level = 'mute' THEN 'mute'
                             WHEN watcher.subscriber_sub IS NOT NULL THEN 'watch'
                             ELSE COALESCE(preference.level, 'none') END AS follow_level,
                        CASE WHEN t.author_sub = $1 THEN TRUE ELSE FALSE END AS authored,
                        EXISTS (
                            SELECT 1 FROM snapshot_posts AS participant
                             WHERE participant.thread_id = t.id
                               AND participant.author_sub = $1
                        ) AS participated,
                        EXISTS (
                            SELECT 1
                              FROM forum_bookmarks AS bookmark
                              JOIN snapshot_posts AS bookmarked_post
                                ON bookmarked_post.id = bookmark.post_id
                             WHERE bookmark.owner_sub = $1
                               AND bookmark.created_at <= $2
                               AND bookmarked_post.thread_id = t.id
                        ) AS bookmarked,
                        EXISTS (
                            SELECT 1
                              FROM forum_post_read_receipts AS receipt
                              JOIN snapshot_posts AS read_post ON read_post.id = receipt.post_id
                             WHERE receipt.viewer_sub = $1 AND receipt.read_at <= $2
                               AND read_post.thread_id = t.id
                               AND receipt.read_seq <= $3
                        ) AS reading_started,
                        (SELECT COUNT(*)
                           FROM snapshot_posts AS unread_post
                          WHERE unread_post.thread_id = t.id
                            AND NOT EXISTS (
                                SELECT 1 FROM forum_post_read_receipts AS receipt
                                 WHERE receipt.viewer_sub = $1
                                   AND receipt.post_id = unread_post.id
                                   AND receipt.read_at <= $2
                                   AND receipt.read_seq <= $3
                            )) AS unread_count,
                        COALESCE((SELECT MAX(point.activity_at)
                                    FROM snapshot_points AS point
                                   WHERE point.thread_id = t.id), t.created_at)
                            AS activity_at,
                        (SELECT COUNT(*) FROM snapshot_posts AS counted_post
                          WHERE counted_post.thread_id = t.id) AS post_count,
                        CASE WHEN c.format = 'question' AND accepted.id IS NOT NULL
                             THEN TRUE ELSE FALSE END AS solved
                   FROM personal_thread_ids AS personal
                   JOIN threads AS t ON t.id = personal.thread_id
                   JOIN categories AS c ON c.id = t.category_id
                   JOIN snapshot_points AS initial_point
                     ON initial_point.post_id = t.first_post_id
                   LEFT JOIN thread_subscriptions AS watcher
                     ON watcher.thread_id = t.id AND watcher.subscriber_sub = $1
                   LEFT JOIN thread_follow_preferences AS preference
                     ON preference.thread_id = t.id AND preference.subscriber_sub = $1
                   LEFT JOIN snapshot_posts AS accepted
                     ON accepted.id = t.accepted_post_id
                    AND accepted.thread_id = t.id
                    AND accepted.id <> t.first_post_id
                  WHERE t.created_at <= $2
             ), eligible AS (
                 SELECT * FROM projected
                  WHERE follow_level <> 'mute' AND {view_scope}
             ), page AS (
                 SELECT * FROM eligible
                  WHERE ($4 = FALSE OR activity_at < $5
                         OR (activity_at = $5 AND id < $6))
                  ORDER BY activity_at DESC, id DESC
                  LIMIT $7
             )
             SELECT page.*,
                    first_unread.id AS unread_id,
                    first_unread.thread_id AS unread_thread_id,
                    first_unread.body_md AS unread_body_md,
                    first_unread.quoted_post_id AS unread_quoted_post_id,
                    first_unread.author_sub AS unread_author_sub,
                    first_unread.author_email AS unread_author_email,
                    first_unread.created_at AS unread_created_at
               FROM page
               LEFT JOIN snapshot_posts AS first_unread ON first_unread.id = (
                    SELECT candidate.id
                      FROM snapshot_posts AS candidate
                     WHERE candidate.thread_id = page.id
                       AND NOT EXISTS (
                           SELECT 1 FROM forum_post_read_receipts AS receipt
                            WHERE receipt.viewer_sub = $1
                              AND receipt.post_id = candidate.id
                              AND receipt.read_at <= $2
                              AND receipt.read_seq <= $3
                       )
                     ORDER BY CASE WHEN candidate.id = page.first_post_id THEN 0 ELSE 1 END,
                              candidate.created_at ASC, candidate.id ASC
                     LIMIT 1
               )
              ORDER BY page.activity_at DESC, page.id DESC"#
        );
        let has_cursor = before.is_some();
        let cursor_at = before.map(|cursor| cursor.activity_at).unwrap_or_default();
        let cursor_id = before
            .map(|cursor| cursor.thread_id.as_str())
            .unwrap_or_default();
        let rows = sqlx::query(&sql)
            .bind(viewer_sub)
            .bind(as_of)
            .bind(snapshot_generation)
            .bind(has_cursor)
            .bind(cursor_at)
            .bind(cursor_id)
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(backend)?;
        let mut items = Vec::with_capacity(rows.len());
        for row in rows {
            let thread_id: String = row.try_get("id").map_err(backend)?;
            let stored_level: String = row.try_get("follow_level").map_err(backend)?;
            let follow_level = ThreadFollowLevel::parse(&stored_level).ok_or_else(|| {
                StoreError::Backend(format!(
                    "unknown catch-up follow level for {thread_id}: {stored_level}"
                ))
            })?;
            let authored: bool = row.try_get("authored").map_err(backend)?;
            let bookmarked: bool = row.try_get("bookmarked").map_err(backend)?;
            let participated: bool = row.try_get("participated").map_err(backend)?;
            let reading_started: bool = row.try_get("reading_started").map_err(backend)?;
            let reason = catch_up_reason(
                view,
                follow_level,
                authored,
                bookmarked,
                participated,
                reading_started,
            )
            .ok_or_else(|| {
                StoreError::Backend(format!(
                    "catch-up query returned an unexplained thread: {thread_id}"
                ))
            })?;
            let category_format: String = row.try_get("category_format").map_err(backend)?;
            // Match every other public read: manually-corrupted/forward format values are the
            // conservative Discussion mode and can never enter the Questions view.
            let category_format = CategoryFormat::parse(&category_format).unwrap_or_default();
            let solved: bool = row.try_get("solved").map_err(backend)?;
            let unread_count: i64 = row.try_get("unread_count").map_err(backend)?;
            let unread_id: Option<String> = row.try_get("unread_id").map_err(backend)?;
            let first_unread = if let Some(id) = unread_id {
                Some(Post {
                    id,
                    thread_id: row
                        .try_get::<Option<String>, _>("unread_thread_id")
                        .map_err(backend)?
                        .ok_or_else(|| {
                            StoreError::Backend("catch-up unread thread is missing".to_string())
                        })?,
                    body_md: row
                        .try_get::<Option<String>, _>("unread_body_md")
                        .map_err(backend)?
                        .ok_or_else(|| {
                            StoreError::Backend("catch-up unread body is missing".to_string())
                        })?,
                    quoted_post_id: row
                        .try_get::<Option<String>, _>("unread_quoted_post_id")
                        .map_err(backend)?
                        .unwrap_or_default(),
                    author_sub: row
                        .try_get::<Option<String>, _>("unread_author_sub")
                        .map_err(backend)?
                        .ok_or_else(|| {
                            StoreError::Backend("catch-up unread author is missing".to_string())
                        })?,
                    author_email: row
                        .try_get::<Option<String>, _>("unread_author_email")
                        .map_err(backend)?
                        .ok_or_else(|| {
                            StoreError::Backend(
                                "catch-up unread author email is missing".to_string(),
                            )
                        })?,
                    created_at: row
                        .try_get::<Option<i64>, _>("unread_created_at")
                        .map_err(backend)?
                        .ok_or_else(|| {
                            StoreError::Backend("catch-up unread time is missing".to_string())
                        })?,
                })
            } else {
                None
            };
            if (unread_count > 0) != first_unread.is_some() {
                return Err(StoreError::Backend(format!(
                    "catch-up unread projection is inconsistent for {thread_id}"
                )));
            }
            let thread = Self::thread_from_row(&row).map_err(backend)?;
            let post_count: i64 = row.try_get("post_count").map_err(backend)?;
            items.push(CatchUpItem {
                thread,
                category_name: row.try_get("category_name").map_err(backend)?,
                reason,
                follow_level,
                unread_count,
                first_unread,
                question_state: category_format.is_question().then_some(if solved {
                    CatchUpQuestionState::Solved
                } else {
                    CatchUpQuestionState::Waiting
                }),
                activity_at: row.try_get("activity_at").map_err(backend)?,
                reply_count: (post_count - 1).max(0),
            });
        }
        Ok(items)
    }

    async fn thread_reading_states_async(
        &self,
        viewer_sub: &str,
        thread_ids: &[String],
    ) -> Result<HashMap<String, ThreadReadingState>, StoreError> {
        let thread_ids = bounded_thread_ids(thread_ids)?;
        if thread_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let placeholders = (0..thread_ids.len())
            .map(|index| format!("${}", index + 2))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT {}, r.read_at AS read_at \
             FROM posts AS p \
             JOIN threads AS t ON t.id = p.thread_id \
             LEFT JOIN forum_post_read_receipts AS r \
               ON r.post_id = p.id AND r.viewer_sub = $1 \
             WHERE p.thread_id IN ({placeholders}) \
             ORDER BY p.thread_id ASC, \
                      CASE WHEN p.id = t.first_post_id THEN 0 ELSE 1 END ASC, \
                      p.created_at ASC, p.id ASC",
            Self::POST_COLS_P,
        );
        let mut query = sqlx::query(&sql).bind(viewer_sub);
        for thread_id in &thread_ids {
            query = query.bind(thread_id);
        }
        let rows = query.fetch_all(&self.pool).await.map_err(backend)?;
        let mut posts_by_thread: HashMap<String, Vec<Post>> = HashMap::new();
        let mut read_post_ids = HashSet::new();
        for row in rows {
            let post = Self::post_from_row(&row).map_err(backend)?;
            if row
                .try_get::<Option<i64>, _>("read_at")
                .map_err(backend)?
                .is_some()
            {
                read_post_ids.insert(post.id.clone());
            }
            posts_by_thread
                .entry(post.thread_id.clone())
                .or_default()
                .push(post);
        }
        let mut states = HashMap::new();
        for thread_id in thread_ids {
            if let Some(posts) = posts_by_thread.remove(&thread_id) {
                states.insert(thread_id, reading_state_from_posts(&posts, &read_post_ids));
            }
        }
        Ok(states)
    }

    async fn mark_thread_posts_read_async(
        &self,
        viewer_sub: &str,
        thread_id: &str,
        post_ids: &[String],
        read_at: i64,
    ) -> Result<(), StoreError> {
        let post_ids = bounded_post_ids(post_ids)?;
        if viewer_sub.trim().is_empty() || read_at < 0 {
            return Err(StoreError::InvalidOperation(
                "invalid thread reading receipt".to_string(),
            ));
        }
        let mut tx = self.pool.begin().await.map_err(backend)?;
        sqlx::query_scalar::<_, String>("SELECT id FROM threads WHERE id = $1 FOR UPDATE")
            .bind(thread_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(backend)?
            .ok_or_else(|| StoreError::NotFound("thread not found".to_string()))?;
        for post_id in &post_ids {
            let owner = sqlx::query_scalar::<_, String>(
                "SELECT thread_id FROM posts WHERE id = $1 FOR UPDATE",
            )
            .bind(post_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(backend)?;
            if owner.as_deref() != Some(thread_id) {
                return Err(StoreError::NotFound("thread post not found".to_string()));
            }
        }
        let mut needs_sequence = Vec::new();
        for post_id in &post_ids {
            let stored = sqlx::query_scalar::<_, Option<i64>>(
                "SELECT read_seq FROM forum_post_read_receipts \
                 WHERE viewer_sub = $1 AND post_id = $2 FOR UPDATE",
            )
            .bind(viewer_sub)
            .bind(post_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(backend)?;
            if !matches!(stored, Some(Some(_))) {
                needs_sequence.push(post_id.clone());
            }
        }
        if needs_sequence.is_empty() {
            tx.commit().await.map_err(backend)?;
            return Ok(());
        }
        let read_seq = Self::next_catch_up_generation_tx(&mut tx).await?;
        for post_id in needs_sequence {
            sqlx::query(
                "INSERT INTO forum_post_read_receipts (viewer_sub, post_id, read_at, read_seq) \
                 VALUES ($1, $2, $3, $4) ON CONFLICT (viewer_sub, post_id) DO NOTHING",
            )
            .bind(viewer_sub)
            .bind(&post_id)
            .bind(read_at)
            .bind(read_seq)
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
            // A nullable row can only come from a rollback-era v7 writer. Preserve its original
            // `read_at` and assign the first v8-visible generation exactly once.
            sqlx::query(
                "UPDATE forum_post_read_receipts SET read_seq = $1 \
                 WHERE viewer_sub = $2 AND post_id = $3 AND read_seq IS NULL",
            )
            .bind(read_seq)
            .bind(viewer_sub)
            .bind(&post_id)
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        }
        tx.commit().await.map_err(backend)?;
        Ok(())
    }

    async fn activity_page_async(
        &self,
        viewer_sub: &str,
        filter: ActivityFilter,
        unread_only: bool,
        before: Option<&ActivityCursor>,
        limit: i64,
    ) -> Result<Vec<ActivityItem>, StoreError> {
        let filter_key = match filter {
            ActivityFilter::All => "all",
            ActivityFilter::Reason(reason) => reason.as_str(),
        };
        let before_at = before.map(|cursor| cursor.created_at);
        let before_id = before.map(|cursor| cursor.id.as_str()).unwrap_or_default();
        let rows = sqlx::query(
            "WITH visible AS (\
                 SELECT e.id, e.kind, e.thread_id, e.post_id, e.actor_sub, e.created_at, \
                        t.title AS thread_title, p.body_md AS post_body_md, \
                        p.created_at AS post_created_at, \
                        CASE WHEN e.kind = 'post_created' THEN p.author_email \
                             ELSE COALESCE(\
                                 (SELECT profile.author_email FROM posts AS profile \
                                  WHERE profile.author_sub = e.actor_sub \
                                    AND profile.author_email <> '' \
                                  ORDER BY profile.created_at DESC, profile.id DESC LIMIT 1), \
                                 (SELECT profile.author_email FROM threads AS profile \
                                  WHERE profile.author_sub = e.actor_sub \
                                    AND profile.author_email <> '' \
                                  ORDER BY profile.created_at DESC, profile.id DESC LIMIT 1), \
                                 ''\
                             ) END AS actor_email, \
                        CASE WHEN r.activity_id IS NULL THEN FALSE ELSE TRUE END AS is_read, \
                        CASE \
                          WHEN EXISTS (SELECT 1 FROM forum_activity_deliveries d \
                               WHERE d.activity_id = e.id AND d.reason = 'mention' \
                                 AND d.recipient_kind = 'subject' AND d.recipient_key = $1) \
                            THEN 'mention' \
                          WHEN EXISTS (SELECT 1 FROM forum_activity_deliveries d \
                               WHERE d.activity_id = e.id AND d.reason = 'reply' \
                                 AND d.recipient_kind = 'subject' AND d.recipient_key = $1) \
                            THEN 'reply' \
                          WHEN EXISTS (SELECT 1 FROM forum_activity_deliveries d \
                               WHERE d.activity_id = e.id AND d.reason = 'answer' \
                                 AND d.recipient_kind = 'subject' AND d.recipient_key = $1) \
                            THEN 'answer' \
                          ELSE 'following' END AS reason \
                 FROM forum_activity_events e \
                 JOIN threads t ON t.id = e.thread_id \
                 JOIN posts p ON p.id = e.post_id AND p.thread_id = e.thread_id \
                 LEFT JOIN forum_activity_receipts r \
                   ON r.activity_id = e.id AND r.viewer_sub = $1 \
                 WHERE EXISTS (SELECT 1 FROM forum_activity_deliveries d \
                       WHERE d.activity_id = e.id \
                         AND d.recipient_kind = 'subject' AND d.recipient_key = $1) \
                   AND ($4::BIGINT IS NULL OR e.created_at < $4 \
                        OR (e.created_at = $4 AND e.id < $5))\
             ) \
             SELECT id, kind, thread_id, post_id, actor_sub, created_at, thread_title, \
                    post_body_md, post_created_at, actor_email, is_read, reason \
             FROM visible \
             WHERE ($2 = 'all' OR reason = $2) AND (NOT $3 OR NOT is_read) \
             ORDER BY created_at DESC, id DESC LIMIT $6",
        )
        .bind(viewer_sub)
        .bind(filter_key)
        .bind(unread_only)
        .bind(before_at)
        .bind(before_id)
        .bind(limit.max(0))
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.iter()
            .map(|row| {
                let kind: String = row.try_get("kind").map_err(backend)?;
                let reason: String = row.try_get("reason").map_err(backend)?;
                Ok(ActivityItem {
                    event: ActivityEvent {
                        id: row.try_get("id").map_err(backend)?,
                        kind: ActivityKind::parse(&kind).ok_or_else(|| {
                            StoreError::Backend(format!("unknown activity kind: {kind}"))
                        })?,
                        thread_id: row.try_get("thread_id").map_err(backend)?,
                        post_id: row.try_get("post_id").map_err(backend)?,
                        actor_sub: row.try_get("actor_sub").map_err(backend)?,
                        created_at: row.try_get("created_at").map_err(backend)?,
                    },
                    reason: ActivityReason::parse(&reason).ok_or_else(|| {
                        StoreError::Backend(format!("unknown activity reason: {reason}"))
                    })?,
                    thread_title: row.try_get("thread_title").map_err(backend)?,
                    post_body_md: row.try_get("post_body_md").map_err(backend)?,
                    post_created_at: row.try_get("post_created_at").map_err(backend)?,
                    actor_email: row.try_get("actor_email").map_err(backend)?,
                    read: row.try_get("is_read").map_err(backend)?,
                })
            })
            .collect()
    }

    async fn unread_activity_count_async(&self, viewer_sub: &str) -> Result<i64, sqlx::Error> {
        let row = sqlx::query(
            "SELECT COUNT(*) AS n \
             FROM forum_activity_events e \
             JOIN threads t ON t.id = e.thread_id \
             JOIN posts p ON p.id = e.post_id AND p.thread_id = e.thread_id \
             WHERE EXISTS (SELECT 1 FROM forum_activity_deliveries d \
                   WHERE d.activity_id = e.id \
                     AND d.recipient_kind = 'subject' AND d.recipient_key = $1) \
               AND NOT EXISTS (SELECT 1 FROM forum_activity_receipts r \
                   WHERE r.activity_id = e.id AND r.viewer_sub = $1)",
        )
        .bind(viewer_sub)
        .fetch_one(&self.pool)
        .await?;
        row.try_get("n")
    }

    async fn set_activity_read_async(
        &self,
        activity_id: &str,
        viewer_sub: &str,
        read: bool,
        changed_at: i64,
    ) -> Result<(), StoreError> {
        let targets = self.activity_lock_targets(&[activity_id]).await?;
        let mut tx = self.pool.begin().await.map_err(backend)?;
        Self::lock_activity_targets_tx(&mut tx, viewer_sub, &targets).await?;
        if read {
            sqlx::query(
                "INSERT INTO forum_activity_receipts (activity_id, viewer_sub, read_at) \
                 VALUES ($1, $2, $3) \
                 ON CONFLICT (activity_id, viewer_sub) DO UPDATE SET read_at = EXCLUDED.read_at",
            )
            .bind(activity_id)
            .bind(viewer_sub)
            .bind(changed_at)
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        } else {
            sqlx::query(
                "DELETE FROM forum_activity_receipts WHERE activity_id = $1 AND viewer_sub = $2",
            )
            .bind(activity_id)
            .bind(viewer_sub)
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        }
        tx.commit().await.map_err(backend)?;
        Ok(())
    }

    async fn mark_activity_batch_read_async(
        &self,
        viewer_sub: &str,
        activity_ids: &[String],
        changed_at: i64,
    ) -> Result<i64, StoreError> {
        if activity_ids.len() > MAX_ACTIVITY_BATCH {
            return Err(StoreError::InvalidOperation(format!(
                "activity batch may contain at most {MAX_ACTIVITY_BATCH} ids"
            )));
        }
        let unique: BTreeSet<&str> = activity_ids.iter().map(String::as_str).collect();
        let unique_ids: Vec<&str> = unique.into_iter().collect();
        let targets = self.activity_lock_targets(&unique_ids).await?;
        let mut tx = self.pool.begin().await.map_err(backend)?;
        Self::lock_activity_targets_tx(&mut tx, viewer_sub, &targets).await?;
        let mut changed = 0_i64;
        for target in &targets {
            changed += sqlx::query(
                "INSERT INTO forum_activity_receipts (activity_id, viewer_sub, read_at) \
                 VALUES ($1, $2, $3) \
                 ON CONFLICT (activity_id, viewer_sub) DO NOTHING",
            )
            .bind(&target.activity_id)
            .bind(viewer_sub)
            .bind(changed_at)
            .execute(&mut *tx)
            .await
            .map_err(backend)?
            .rows_affected() as i64;
        }
        tx.commit().await.map_err(backend)?;
        Ok(changed)
    }

    async fn ensure_bookmark_async(
        &self,
        owner_sub: &str,
        post_id: &str,
        created_at: i64,
    ) -> Result<Bookmark, StoreError> {
        let mut tx = self.pool.begin().await.map_err(backend)?;
        let post = sqlx::query_scalar::<_, String>("SELECT id FROM posts WHERE id = $1 FOR UPDATE")
            .bind(post_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(backend)?;
        if post.is_none() {
            return Err(StoreError::NotFound("post not found".to_string()));
        }
        sqlx::query(
            "INSERT INTO forum_bookmark_owner_guards (owner_sub) VALUES ($1) \
             ON CONFLICT (owner_sub) DO NOTHING",
        )
        .bind(owner_sub)
        .execute(&mut *tx)
        .await
        .map_err(backend)?;
        sqlx::query(
            "SELECT owner_sub FROM forum_bookmark_owner_guards WHERE owner_sub = $1 FOR UPDATE",
        )
        .bind(owner_sub)
        .fetch_one(&mut *tx)
        .await
        .map_err(backend)?;
        if let Some(row) = sqlx::query(
            "SELECT bookmark_id, owner_sub, post_id, note, remind_at, created_at, updated_at, version \
             FROM forum_bookmarks WHERE owner_sub = $1 AND post_id = $2",
        )
        .bind(owner_sub)
        .bind(post_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(backend)?
        {
            let bookmark = Self::bookmark_from_row(&row).map_err(backend)?;
            tx.commit().await.map_err(backend)?;
            return Ok(bookmark);
        }
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM forum_bookmarks WHERE owner_sub = $1",
        )
        .bind(owner_sub)
        .fetch_one(&mut *tx)
        .await
        .map_err(backend)?;
        if count >= MAX_BOOKMARKS_PER_USER as i64 {
            return Err(StoreError::InvalidOperation(format!(
                "a user may save at most {MAX_BOOKMARKS_PER_USER} bookmarks"
            )));
        }
        let bookmark = Bookmark {
            bookmark_id: crate::new_id("bm"),
            owner_sub: owner_sub.to_string(),
            post_id: post_id.to_string(),
            note: String::new(),
            remind_at: None,
            created_at,
            updated_at: created_at,
            version: 1,
        };
        sqlx::query(
            "INSERT INTO forum_bookmarks \
                 (bookmark_id, owner_sub, post_id, note, remind_at, created_at, updated_at, version) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&bookmark.bookmark_id)
        .bind(&bookmark.owner_sub)
        .bind(&bookmark.post_id)
        .bind(&bookmark.note)
        .bind(bookmark.remind_at)
        .bind(bookmark.created_at)
        .bind(bookmark.updated_at)
        .bind(bookmark.version)
        .execute(&mut *tx)
        .await
        .map_err(backend)?;
        tx.commit().await.map_err(backend)?;
        Ok(bookmark)
    }

    async fn bookmarks_for_posts_async(
        &self,
        owner_sub: &str,
        post_ids: &[String],
    ) -> Result<Vec<Bookmark>, StoreError> {
        if post_ids.len() > MAX_BOOKMARK_POST_BATCH {
            return Err(StoreError::InvalidOperation(format!(
                "bookmark post batch may contain at most {MAX_BOOKMARK_POST_BATCH} ids"
            )));
        }
        if post_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut query = QueryBuilder::<Postgres>::new(
            "SELECT bookmark_id, owner_sub, post_id, note, remind_at, created_at, updated_at, version \
             FROM forum_bookmarks WHERE owner_sub = ",
        );
        query.push_bind(owner_sub).push(" AND post_id IN (");
        let mut ids = query.separated(", ");
        for post_id in post_ids {
            ids.push_bind(post_id);
        }
        ids.push_unseparated(")");
        let rows = query.build().fetch_all(&self.pool).await.map_err(backend)?;
        rows.iter()
            .map(|row| Self::bookmark_from_row(row).map_err(backend))
            .collect()
    }

    async fn bookmark_page_async(
        &self,
        owner_sub: &str,
        state: BookmarkState,
        cursor: Option<&BookmarkCursor>,
        limit: i64,
        now: i64,
    ) -> Result<Vec<BookmarkItem>, StoreError> {
        let cursor_at = cursor.map(|value| value.sort_at);
        let cursor_id = cursor
            .map(|value| value.post_id.as_str())
            .unwrap_or_default();
        let limit = limit.clamp(0, MAX_BOOKMARK_PAGE + 1);
        let base =
            "SELECT b.bookmark_id, b.owner_sub, b.post_id, b.note, b.remind_at, b.created_at, \
                           b.updated_at, b.version, p.thread_id, t.title AS thread_title, \
                           p.author_email AS post_author_email, p.body_md AS post_body_md, \
                           p.created_at AS post_created_at \
                    FROM forum_bookmarks AS b \
                    JOIN posts AS p ON p.id = b.post_id \
                    JOIN threads AS t ON t.id = p.thread_id ";
        let sql = match state {
            BookmarkState::All => format!(
                "{base} WHERE b.owner_sub = $1 \
                 AND ($2::BIGINT IS NULL OR b.created_at < $2 \
                      OR (b.created_at = $2 AND b.post_id < $3)) \
                 ORDER BY b.created_at DESC, b.post_id DESC LIMIT $4"
            ),
            BookmarkState::Due => format!(
                "{base} WHERE b.owner_sub = $1 AND b.remind_at <= $4 \
                 AND ($2::BIGINT IS NULL OR b.remind_at > $2 \
                      OR (b.remind_at = $2 AND b.post_id > $3)) \
                 ORDER BY b.remind_at ASC, b.post_id ASC LIMIT $5"
            ),
            BookmarkState::Scheduled => format!(
                "{base} WHERE b.owner_sub = $1 AND b.remind_at > $4 \
                 AND ($2::BIGINT IS NULL OR b.remind_at > $2 \
                      OR (b.remind_at = $2 AND b.post_id > $3)) \
                 ORDER BY b.remind_at ASC, b.post_id ASC LIMIT $5"
            ),
        };
        let rows = match state {
            BookmarkState::All => {
                sqlx::query(&sql)
                    .bind(owner_sub)
                    .bind(cursor_at)
                    .bind(cursor_id)
                    .bind(limit)
                    .fetch_all(&self.pool)
                    .await
            }
            BookmarkState::Due | BookmarkState::Scheduled => {
                sqlx::query(&sql)
                    .bind(owner_sub)
                    .bind(cursor_at)
                    .bind(cursor_id)
                    .bind(now)
                    .bind(limit)
                    .fetch_all(&self.pool)
                    .await
            }
        }
        .map_err(backend)?;
        rows.iter()
            .map(|row| Self::bookmark_item_from_row(row).map_err(backend))
            .collect()
    }

    async fn due_bookmark_count_async(
        &self,
        owner_sub: &str,
        now: i64,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM forum_bookmarks AS b \
             JOIN posts AS p ON p.id = b.post_id \
             WHERE b.owner_sub = $1 AND b.remind_at <= $2",
        )
        .bind(owner_sub)
        .bind(now)
        .fetch_one(&self.pool)
        .await
    }

    async fn get_bookmark_async(
        &self,
        owner_sub: &str,
        post_id: &str,
    ) -> Result<Option<BookmarkItem>, StoreError> {
        let row = sqlx::query(
            "SELECT b.bookmark_id, b.owner_sub, b.post_id, b.note, b.remind_at, b.created_at, \
                    b.updated_at, b.version, p.thread_id, t.title AS thread_title, \
                    p.author_email AS post_author_email, p.body_md AS post_body_md, \
                    p.created_at AS post_created_at \
             FROM forum_bookmarks AS b \
             JOIN posts AS p ON p.id = b.post_id \
             JOIN threads AS t ON t.id = p.thread_id \
             WHERE b.owner_sub = $1 AND b.post_id = $2",
        )
        .bind(owner_sub)
        .bind(post_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.as_ref()
            .map(Self::bookmark_item_from_row)
            .transpose()
            .map_err(backend)
    }

    async fn update_bookmark_async(
        &self,
        owner_sub: &str,
        post_id: &str,
        expected: BookmarkCas<'_>,
        note: &str,
        reminder: BookmarkReminderUpdate,
        changed_at: i64,
    ) -> Result<Bookmark, StoreError> {
        validate_bookmark_note(note)?;
        if let BookmarkReminderUpdate::Set(remind_at) = reminder {
            validate_future_reminder(remind_at, changed_at)?;
        }
        let mut tx = self.pool.begin().await.map_err(backend)?;
        let mut bookmark = Self::lock_bookmark_tx(&mut tx, owner_sub, post_id).await?;
        validate_bookmark_cas(&bookmark, expected)?;
        bookmark.note = note.to_string();
        match reminder {
            BookmarkReminderUpdate::Keep => {}
            BookmarkReminderUpdate::Clear => bookmark.remind_at = None,
            BookmarkReminderUpdate::Set(remind_at) => bookmark.remind_at = Some(remind_at),
        }
        bookmark.updated_at = changed_at;
        bookmark.version = next_bookmark_version(bookmark.version)?;
        Self::persist_bookmark_tx(&mut tx, &bookmark).await?;
        tx.commit().await.map_err(backend)?;
        Ok(bookmark)
    }

    async fn complete_due_bookmark_async(
        &self,
        owner_sub: &str,
        post_id: &str,
        expected: BookmarkCas<'_>,
        changed_at: i64,
    ) -> Result<Bookmark, StoreError> {
        let mut tx = self.pool.begin().await.map_err(backend)?;
        let mut bookmark = Self::lock_bookmark_tx(&mut tx, owner_sub, post_id).await?;
        validate_bookmark_cas(&bookmark, expected)?;
        if bookmark.remind_at.is_none_or(|at| at > changed_at) {
            return Err(StoreError::InvalidOperation(
                "bookmark reminder is not due".to_string(),
            ));
        }
        bookmark.remind_at = None;
        bookmark.updated_at = changed_at;
        bookmark.version = next_bookmark_version(bookmark.version)?;
        Self::persist_bookmark_tx(&mut tx, &bookmark).await?;
        tx.commit().await.map_err(backend)?;
        Ok(bookmark)
    }

    async fn snooze_bookmark_async(
        &self,
        owner_sub: &str,
        post_id: &str,
        expected: BookmarkCas<'_>,
        remind_at: i64,
        changed_at: i64,
    ) -> Result<Bookmark, StoreError> {
        validate_future_reminder(remind_at, changed_at)?;
        let mut tx = self.pool.begin().await.map_err(backend)?;
        let mut bookmark = Self::lock_bookmark_tx(&mut tx, owner_sub, post_id).await?;
        validate_bookmark_cas(&bookmark, expected)?;
        if bookmark.remind_at.is_none_or(|at| at > changed_at) {
            return Err(StoreError::InvalidOperation(
                "bookmark reminder is not due".to_string(),
            ));
        }
        bookmark.remind_at = Some(remind_at);
        bookmark.updated_at = changed_at;
        bookmark.version = next_bookmark_version(bookmark.version)?;
        Self::persist_bookmark_tx(&mut tx, &bookmark).await?;
        tx.commit().await.map_err(backend)?;
        Ok(bookmark)
    }

    async fn remove_bookmark_async(
        &self,
        owner_sub: &str,
        post_id: &str,
        expected: BookmarkCas<'_>,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(backend)?;
        let bookmark = Self::lock_bookmark_tx(&mut tx, owner_sub, post_id).await?;
        validate_bookmark_cas(&bookmark, expected)?;
        sqlx::query(
            "DELETE FROM forum_bookmarks \
             WHERE owner_sub = $1 AND post_id = $2 AND bookmark_id = $3",
        )
        .bind(owner_sub)
        .bind(post_id)
        .bind(expected.bookmark_id)
        .execute(&mut *tx)
        .await
        .map_err(backend)?;
        tx.commit().await.map_err(backend)?;
        Ok(())
    }

    async fn toggle_reaction_async(
        &self,
        post_id: &str,
        user_sub: &str,
        kind: &str,
        created_at: i64,
    ) -> Result<bool, sqlx::Error> {
        // Idempotent toggle without a race window: try to insert; ON CONFLICT DO NOTHING tells us
        // (via rows_affected) whether the row was new. If it already existed, delete it instead.
        let inserted = sqlx::query(
            "INSERT INTO post_reactions (post_id, user_sub, kind, created_at) \
             VALUES ($1, $2, $3, $4) ON CONFLICT (post_id, user_sub, kind) DO NOTHING",
        )
        .bind(post_id)
        .bind(user_sub)
        .bind(kind)
        .bind(created_at)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if inserted > 0 {
            return Ok(true);
        }
        sqlx::query(
            "DELETE FROM post_reactions WHERE post_id = $1 AND user_sub = $2 AND kind = $3",
        )
        .bind(post_id)
        .bind(user_sub)
        .bind(kind)
        .execute(&self.pool)
        .await?;
        Ok(false)
    }

    async fn reactions_for_post_async(
        &self,
        post_id: &str,
        viewer_sub: Option<&str>,
    ) -> Result<Vec<ReactionCount>, sqlx::Error> {
        // Count per kind, and (via a conditional SUM) whether the viewer is among the reactors.
        // The viewer marker binds '' when absent, which no real user_sub equals.
        let rows = sqlx::query(
            "SELECT kind, COUNT(*) AS n, \
                    SUM(CASE WHEN user_sub = $2 THEN 1 ELSE 0 END) AS mine \
             FROM post_reactions WHERE post_id = $1 GROUP BY kind ORDER BY kind",
        )
        .bind(post_id)
        .bind(viewer_sub.unwrap_or(""))
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                let mine: i64 = row.try_get("mine")?;
                Ok(ReactionCount {
                    kind: row.try_get("kind")?,
                    count: row.try_get("n")?,
                    mine: mine > 0,
                })
            })
            .collect()
    }

    async fn list_bans_async(&self) -> Result<Vec<BannedAuthor>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT author_sub, reason, banned_by, created_at FROM banned_authors \
             ORDER BY created_at DESC, author_sub ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(BannedAuthor {
                    author_sub: row.try_get("author_sub")?,
                    reason: row.try_get("reason")?,
                    banned_by: row.try_get("banned_by")?,
                    created_at: row.try_get("created_at")?,
                })
            })
            .collect()
    }

    async fn is_banned_async(&self, author_sub: &str) -> Result<bool, sqlx::Error> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM banned_authors WHERE author_sub = $1")
            .bind(author_sub)
            .fetch_one(&self.pool)
            .await?;
        let n: i64 = row.try_get("n")?;
        Ok(n > 0)
    }

    async fn add_ban_async(&self, ban: &BannedAuthor) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO banned_authors (author_sub, reason, banned_by, created_at) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (author_sub) DO UPDATE SET \
                 reason = EXCLUDED.reason, banned_by = EXCLUDED.banned_by, created_at = EXCLUDED.created_at",
        )
        .bind(&ban.author_sub)
        .bind(&ban.reason)
        .bind(&ban.banned_by)
        .bind(ban.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn remove_ban_async(&self, author_sub: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM banned_authors WHERE author_sub = $1")
            .bind(author_sub)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl Store for PgStore {
    async fn seed_categories_if_empty(&self, defaults: &[Category]) -> Result<(), StoreError> {
        self.seed_async(defaults).await.map_err(backend)
    }

    async fn list_categories(&self) -> Result<Vec<Category>, StoreError> {
        self.list_categories_async().await.map_err(backend)
    }

    async fn get_category(&self, id: &str) -> Result<Option<Category>, StoreError> {
        self.get_category_async(id).await.map_err(backend)
    }

    async fn count_threads(&self, category_id: &str) -> Result<i64, StoreError> {
        self.count_threads_async(category_id).await.map_err(backend)
    }

    async fn create_category(&self, category: &Category) -> Result<(), StoreError> {
        self.create_category_async(category).await.map_err(backend)
    }

    async fn rename_category(&self, id: &str, name: &str) -> Result<(), StoreError> {
        self.rename_category_async(id, name).await.map_err(backend)
    }

    async fn transition_category_format(
        &self,
        id: &str,
        format: CategoryFormat,
    ) -> Result<(), StoreError> {
        self.transition_category_format_async(id, format).await
    }

    async fn set_category_order(&self, id: &str, sort_order: i64) -> Result<(), StoreError> {
        self.set_category_order_async(id, sort_order)
            .await
            .map_err(backend)
    }

    async fn delete_category(&self, id: &str) -> Result<(), StoreError> {
        self.delete_category_async(id).await
    }

    async fn recent_threads(&self, limit: i64) -> Result<Vec<Thread>, StoreError> {
        self.recent_threads_async(limit).await.map_err(backend)
    }

    async fn threads_in_category(
        &self,
        category_id: &str,
        limit: i64,
    ) -> Result<Vec<Thread>, StoreError> {
        self.threads_in_category_async(category_id, limit)
            .await
            .map_err(backend)
    }

    async fn list_threads(
        &self,
        category_id: Option<&str>,
        sort: ThreadSort,
        subscribed_sub: Option<&str>,
        status: ThreadStatusFilter,
        limit: i64,
        now: i64,
    ) -> Result<Vec<Thread>, StoreError> {
        self.list_threads_async(category_id, sort, subscribed_sub, status, limit, now)
            .await
            .map_err(backend)
    }

    async fn search_threads(
        &self,
        query: &str,
        category_id: Option<&str>,
        status: ThreadStatusFilter,
        limit: i64,
    ) -> Result<Vec<ThreadSearchHit>, StoreError> {
        self.search_threads_async(query, category_id, status, limit)
            .await
            .map_err(backend)
    }

    async fn get_thread(&self, id: &str) -> Result<Option<Thread>, StoreError> {
        self.get_thread_async(id).await.map_err(backend)
    }

    async fn thread_digests(&self, limit: i64) -> Result<Vec<ThreadDigest>, StoreError> {
        self.thread_digests_async(limit).await.map_err(backend)
    }

    async fn count_posts(&self, thread_id: &str) -> Result<i64, StoreError> {
        self.count_posts_async(thread_id).await.map_err(backend)
    }

    async fn get_post(&self, id: &str) -> Result<Option<Post>, StoreError> {
        self.get_post_async(id).await.map_err(backend)
    }

    async fn get_valid_accepted_post(&self, thread_id: &str) -> Result<Option<Post>, StoreError> {
        self.get_valid_accepted_post_async(thread_id)
            .await
            .map_err(backend)
    }

    async fn posts_in_thread(&self, thread_id: &str) -> Result<Vec<Post>, StoreError> {
        self.posts_in_thread_async(thread_id).await.map_err(backend)
    }

    async fn first_post_in_thread(&self, thread_id: &str) -> Result<Option<Post>, StoreError> {
        self.first_post_in_thread_async(thread_id)
            .await
            .map_err(backend)
    }

    async fn replies_page(
        &self,
        thread_id: &str,
        op_id: &str,
        excluded_post_id: Option<&str>,
        anchor: &ReplyAnchor,
        limit: i64,
    ) -> Result<Vec<Post>, StoreError> {
        self.replies_page_async(thread_id, op_id, excluded_post_id, anchor, limit)
            .await
            .map_err(backend)
    }

    async fn create_thread(&self, thread: &Thread, first_post: &Post) -> Result<(), StoreError> {
        self.create_thread_async(thread, first_post).await
    }

    async fn create_thread_with_activity(
        &self,
        thread: &Thread,
        first_post: &Post,
        mentioned_usernames: &[String],
        activity_id: &str,
    ) -> Result<ActivityMutation, StoreError> {
        self.create_thread_with_activity_async(thread, first_post, mentioned_usernames, activity_id)
            .await
    }

    async fn add_reply(&self, post: &Post) -> Result<(), StoreError> {
        self.add_reply_async(post).await
    }

    async fn add_reply_with_activity(
        &self,
        post: &Post,
        mentioned_usernames: &[String],
        activity_id: &str,
    ) -> Result<ActivityMutation, StoreError> {
        self.add_reply_with_activity_async(post, mentioned_usernames, activity_id)
            .await
    }

    async fn replace_mentions(
        &self,
        post_id: &str,
        thread_id: &str,
        mentioned_usernames: &[String],
        created_at: i64,
    ) -> Result<(), StoreError> {
        self.replace_mentions_async(post_id, thread_id, mentioned_usernames, created_at)
            .await
            .map_err(backend)
    }

    async fn count_mentions_for_user(&self, mentioned_username: &str) -> Result<i64, StoreError> {
        self.count_mentions_for_user_async(mentioned_username)
            .await
            .map_err(backend)
    }

    async fn mentions_for_user(
        &self,
        mentioned_username: &str,
        limit: i64,
    ) -> Result<Vec<Mention>, StoreError> {
        self.mentions_for_user_async(mentioned_username, limit)
            .await
            .map_err(backend)
    }

    async fn update_thread(
        &self,
        thread_id: &str,
        title: &str,
        op_post_id: &str,
        body_md: &str,
    ) -> Result<(), StoreError> {
        self.update_thread_async(thread_id, title, op_post_id, body_md)
            .await
            .map_err(backend)
    }

    async fn delete_thread(&self, thread_id: &str) -> Result<(), StoreError> {
        self.delete_thread_async(thread_id).await
    }

    async fn update_post(&self, post_id: &str, body_md: &str) -> Result<(), StoreError> {
        self.update_post_async(post_id, body_md)
            .await
            .map_err(backend)
    }

    async fn delete_post(&self, post_id: &str) -> Result<(), StoreError> {
        match self.delete_post_async(post_id).await? {
            true => Ok(()),
            false => Err(StoreError::InvalidOperation(
                "the original post cannot be deleted separately; delete the thread".to_string(),
            )),
        }
    }

    async fn set_thread_locked(&self, thread_id: &str, locked: bool) -> Result<(), StoreError> {
        self.set_thread_locked_async(thread_id, locked)
            .await
            .map_err(backend)
    }

    async fn set_thread_pinned(&self, thread_id: &str, pinned: bool) -> Result<(), StoreError> {
        self.set_thread_pinned_async(thread_id, pinned)
            .await
            .map_err(backend)
    }

    async fn move_thread_to_category(
        &self,
        thread_id: &str,
        category_id: &str,
    ) -> Result<(), StoreError> {
        self.move_thread_to_category_async(thread_id, category_id)
            .await
    }

    async fn mutate_accepted_answer(
        &self,
        thread_id: &str,
        action: AcceptedAnswerAction,
    ) -> Result<AcceptedAnswerMutation, StoreError> {
        self.mutate_accepted_answer_async(thread_id, action, None)
            .await
    }

    async fn mutate_accepted_answer_with_activity(
        &self,
        thread_id: &str,
        action: AcceptedAnswerAction,
        activity_id: &str,
        actor_sub: &str,
        created_at: i64,
    ) -> Result<AcceptedAnswerMutation, StoreError> {
        self.mutate_accepted_answer_async(
            thread_id,
            action,
            Some((activity_id, actor_sub, created_at)),
        )
        .await
    }

    async fn set_thread_follow_level(
        &self,
        thread_id: &str,
        subscriber_sub: &str,
        level: ThreadFollowLevel,
        created_at: i64,
    ) -> Result<(), StoreError> {
        self.set_thread_follow_level_async(thread_id, subscriber_sub, level, created_at)
            .await
    }

    async fn thread_follow_level(
        &self,
        thread_id: &str,
        subscriber_sub: &str,
    ) -> Result<ThreadFollowLevel, StoreError> {
        self.thread_follow_level_async(thread_id, subscriber_sub)
            .await
    }

    async fn thread_personal_signals(
        &self,
        viewer_sub: &str,
        thread_ids: &[String],
    ) -> Result<HashMap<String, ThreadPersonalSignals>, StoreError> {
        self.thread_personal_signals_async(viewer_sub, thread_ids)
            .await
    }

    async fn category_focus_level(
        &self,
        viewer_sub: &str,
        category_id: &str,
    ) -> Result<CategoryFocusLevel, StoreError> {
        self.category_focus_level_async(viewer_sub, category_id)
            .await
    }

    async fn category_focus_rules(
        &self,
        viewer_sub: &str,
    ) -> Result<Vec<CategoryFocusRuleItem>, StoreError> {
        self.category_focus_rules_async(viewer_sub).await
    }

    async fn set_category_focus_level(
        &self,
        viewer_sub: &str,
        category_id: &str,
        level: CategoryFocusLevel,
        changed_at: i64,
    ) -> Result<(), StoreError> {
        self.set_category_focus_level_async(viewer_sub, category_id, level, changed_at)
            .await
    }

    async fn category_focus_page(
        &self,
        viewer_sub: &str,
        limit: i64,
        as_of: i64,
    ) -> Result<Vec<CategoryFocusItem>, StoreError> {
        self.category_focus_page_async(viewer_sub, limit, as_of)
            .await
    }

    async fn catch_up_snapshot_generation(&self) -> Result<i64, StoreError> {
        self.catch_up_snapshot_generation_async().await
    }

    async fn catch_up_page(
        &self,
        viewer_sub: &str,
        view: CatchUpView,
        as_of: i64,
        snapshot_generation: i64,
        before: Option<&CatchUpCursor>,
        limit: i64,
    ) -> Result<Vec<CatchUpItem>, StoreError> {
        self.catch_up_page_async(viewer_sub, view, as_of, snapshot_generation, before, limit)
            .await
    }

    async fn thread_reading_state(
        &self,
        viewer_sub: &str,
        thread_id: &str,
    ) -> Result<ThreadReadingState, StoreError> {
        self.thread_reading_states_async(viewer_sub, &[thread_id.to_string()])
            .await?
            .remove(thread_id)
            .ok_or_else(|| StoreError::NotFound("thread not found".to_string()))
    }

    async fn thread_reading_states(
        &self,
        viewer_sub: &str,
        thread_ids: &[String],
    ) -> Result<HashMap<String, ThreadReadingState>, StoreError> {
        self.thread_reading_states_async(viewer_sub, thread_ids)
            .await
    }

    async fn mark_thread_posts_read(
        &self,
        viewer_sub: &str,
        thread_id: &str,
        post_ids: &[String],
        read_at: i64,
    ) -> Result<(), StoreError> {
        self.mark_thread_posts_read_async(viewer_sub, thread_id, post_ids, read_at)
            .await
    }

    async fn activity_page(
        &self,
        viewer_sub: &str,
        filter: ActivityFilter,
        unread_only: bool,
        before: Option<&ActivityCursor>,
        limit: i64,
    ) -> Result<Vec<ActivityItem>, StoreError> {
        self.activity_page_async(viewer_sub, filter, unread_only, before, limit)
            .await
    }

    async fn unread_activity_count(&self, viewer_sub: &str) -> Result<i64, StoreError> {
        self.unread_activity_count_async(viewer_sub)
            .await
            .map_err(backend)
    }

    async fn set_activity_read(
        &self,
        activity_id: &str,
        viewer_sub: &str,
        read: bool,
        changed_at: i64,
    ) -> Result<(), StoreError> {
        self.set_activity_read_async(activity_id, viewer_sub, read, changed_at)
            .await
    }

    async fn mark_activity_batch_read(
        &self,
        viewer_sub: &str,
        activity_ids: &[String],
        changed_at: i64,
    ) -> Result<i64, StoreError> {
        self.mark_activity_batch_read_async(viewer_sub, activity_ids, changed_at)
            .await
    }

    async fn ensure_bookmark(
        &self,
        owner_sub: &str,
        post_id: &str,
        created_at: i64,
    ) -> Result<Bookmark, StoreError> {
        self.ensure_bookmark_async(owner_sub, post_id, created_at)
            .await
    }

    async fn bookmarks_for_posts(
        &self,
        owner_sub: &str,
        post_ids: &[String],
    ) -> Result<Vec<Bookmark>, StoreError> {
        self.bookmarks_for_posts_async(owner_sub, post_ids).await
    }

    async fn bookmark_page(
        &self,
        owner_sub: &str,
        state: BookmarkState,
        cursor: Option<&BookmarkCursor>,
        limit: i64,
        now: i64,
    ) -> Result<Vec<BookmarkItem>, StoreError> {
        self.bookmark_page_async(owner_sub, state, cursor, limit, now)
            .await
    }

    async fn due_bookmark_count(&self, owner_sub: &str, now: i64) -> Result<i64, StoreError> {
        self.due_bookmark_count_async(owner_sub, now)
            .await
            .map_err(backend)
    }

    async fn get_bookmark(
        &self,
        owner_sub: &str,
        post_id: &str,
    ) -> Result<Option<BookmarkItem>, StoreError> {
        self.get_bookmark_async(owner_sub, post_id).await
    }

    async fn update_bookmark(
        &self,
        owner_sub: &str,
        post_id: &str,
        expected: BookmarkCas<'_>,
        note: &str,
        reminder: BookmarkReminderUpdate,
        changed_at: i64,
    ) -> Result<Bookmark, StoreError> {
        self.update_bookmark_async(owner_sub, post_id, expected, note, reminder, changed_at)
            .await
    }

    async fn complete_due_bookmark(
        &self,
        owner_sub: &str,
        post_id: &str,
        expected: BookmarkCas<'_>,
        changed_at: i64,
    ) -> Result<Bookmark, StoreError> {
        self.complete_due_bookmark_async(owner_sub, post_id, expected, changed_at)
            .await
    }

    async fn snooze_bookmark(
        &self,
        owner_sub: &str,
        post_id: &str,
        expected: BookmarkCas<'_>,
        remind_at: i64,
        changed_at: i64,
    ) -> Result<Bookmark, StoreError> {
        self.snooze_bookmark_async(owner_sub, post_id, expected, remind_at, changed_at)
            .await
    }

    async fn remove_bookmark(
        &self,
        owner_sub: &str,
        post_id: &str,
        expected: BookmarkCas<'_>,
    ) -> Result<(), StoreError> {
        self.remove_bookmark_async(owner_sub, post_id, expected)
            .await
    }

    async fn toggle_reaction(
        &self,
        post_id: &str,
        user_sub: &str,
        kind: &str,
        created_at: i64,
    ) -> Result<bool, StoreError> {
        self.toggle_reaction_async(post_id, user_sub, kind, created_at)
            .await
            .map_err(backend)
    }

    async fn reactions_for_post(
        &self,
        post_id: &str,
        viewer_sub: Option<&str>,
    ) -> Result<Vec<ReactionCount>, StoreError> {
        self.reactions_for_post_async(post_id, viewer_sub)
            .await
            .map_err(backend)
    }

    async fn list_bans(&self) -> Result<Vec<BannedAuthor>, StoreError> {
        self.list_bans_async().await.map_err(backend)
    }

    async fn is_banned(&self, author_sub: &str) -> Result<bool, StoreError> {
        self.is_banned_async(author_sub).await.map_err(backend)
    }

    async fn add_ban(&self, ban: &BannedAuthor) -> Result<(), StoreError> {
        self.add_ban_async(ban).await.map_err(backend)
    }

    async fn remove_ban(&self, author_sub: &str) -> Result<(), StoreError> {
        self.remove_ban_async(author_sub).await.map_err(backend)
    }
}

/// Map an sqlx error into a [`StoreError`].
fn backend(e: sqlx::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Arc, time::Duration};

    use tokio::sync::Barrier;

    fn thread(id: &str, title: &str, created_at: i64) -> Thread {
        Thread {
            id: id.to_string(),
            category_id: "general".to_string(),
            title: title.to_string(),
            author_sub: "u_alice".to_string(),
            author_email: "alice@steadholme.local".to_string(),
            created_at,
            last_at: created_at,
            locked: false,
            pinned: false,
            accepted_post_id: String::new(),
        }
    }

    fn post(
        id: &str,
        thread_id: &str,
        body_md: &str,
        quoted_post_id: &str,
        created_at: i64,
    ) -> Post {
        Post {
            id: id.to_string(),
            thread_id: thread_id.to_string(),
            body_md: body_md.to_string(),
            quoted_post_id: quoted_post_id.to_string(),
            author_sub: "u_bob".to_string(),
            author_email: "bob@steadholme.local".to_string(),
            created_at,
        }
    }

    async fn seed_thread(store: &InMemoryStore, id: &str, title: &str, created_at: i64) {
        store
            .create_category(&Category {
                id: "general".to_string(),
                name: "General".to_string(),
                sort_order: 0,
                format: CategoryFormat::Discussion,
            })
            .await
            .unwrap();
        let t = thread(id, title, created_at);
        let first = post(&format!("p_{id}_op"), id, "OP", "", created_at);
        store.create_thread(&t, &first).await.unwrap();
    }

    async fn seed_category(store: &InMemoryStore, id: &str, format: CategoryFormat) {
        store
            .create_category(&Category {
                id: id.to_string(),
                name: id.to_string(),
                sort_order: 0,
                format,
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn in_memory_quote_mentions_and_cleanup() {
        let store = InMemoryStore::new();
        seed_thread(&store, "t_quote", "Quote", 100).await;

        let reply = post(
            "p_reply",
            "t_quote",
            "Thanks @Alice and @alice.",
            "p_t_quote_op",
            100,
        );
        store.add_reply(&reply).await.unwrap();
        store
            .replace_mentions(
                &reply.id,
                &reply.thread_id,
                &["alice".to_string()],
                reply.created_at,
            )
            .await
            .unwrap();

        let posts = store.posts_in_thread("t_quote").await.unwrap();
        assert_eq!(posts[1].quoted_post_id, "p_t_quote_op");
        assert_eq!(store.count_mentions_for_user("alice").await.unwrap(), 1);
        let mentions = store.mentions_for_user("alice", 10).await.unwrap();
        assert_eq!(mentions[0].post_id, "p_reply");

        let error = store
            .delete_post("p_t_quote_op")
            .await
            .expect_err("OP deletion must use delete_thread");
        assert!(error.to_string().contains("delete the thread"));

        let follower = post("p_follower", "t_quote", "Following", "p_reply", 120);
        store.add_reply(&follower).await.unwrap();
        store.delete_post("p_reply").await.unwrap();
        let follower = store.get_post("p_follower").await.unwrap().unwrap();
        assert!(
            follower.quoted_post_id.is_empty(),
            "deleted quoted posts are cleared from replies"
        );
        assert_eq!(store.count_mentions_for_user("alice").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn in_memory_subscriptions_are_explicit_idempotent_and_filterable() {
        let store = InMemoryStore::new();
        seed_thread(&store, "t_one", "One", 100).await;
        seed_thread(&store, "t_two", "Two", 200).await;

        store
            .set_thread_subscription("t_one", "u_alice", true, 300)
            .await
            .unwrap();
        store
            .set_thread_subscription("t_one", "u_alice", true, 301)
            .await
            .unwrap();
        assert!(store
            .is_thread_subscribed("t_one", "u_alice")
            .await
            .unwrap());
        let subscribed = store
            .list_threads(
                None,
                ThreadSort::Latest,
                Some("u_alice"),
                ThreadStatusFilter::Any,
                10,
                400,
            )
            .await
            .unwrap();
        assert_eq!(subscribed.len(), 1);
        assert_eq!(subscribed[0].id, "t_one");

        store
            .set_thread_subscription("t_one", "u_alice", false, 302)
            .await
            .unwrap();
        store
            .set_thread_subscription("t_one", "u_alice", false, 303)
            .await
            .unwrap();
        assert!(!store
            .is_thread_subscribed("t_one", "u_alice")
            .await
            .unwrap());
        assert!(store
            .list_threads(
                None,
                ThreadSort::Latest,
                Some("u_alice"),
                ThreadStatusFilter::Any,
                10,
                400,
            )
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn in_memory_follow_levels_and_personal_signals_are_bounded() {
        let store = InMemoryStore::new();
        seed_thread(&store, "t_personal", "Personal", 100).await;
        let reply = post("p_personal_reply", "t_personal", "joined", "", 101);
        store.add_reply(&reply).await.unwrap();
        store
            .set_thread_follow_level("t_personal", "u_bob", ThreadFollowLevel::Follow, 200)
            .await
            .unwrap();
        store
            .ensure_bookmark("u_bob", &reply.id, 201)
            .await
            .unwrap();
        store
            .mark_thread_posts_read("u_bob", "t_personal", std::slice::from_ref(&reply.id), 202)
            .await
            .unwrap();

        let signals = store
            .thread_personal_signals("u_bob", &["t_personal".to_string()])
            .await
            .unwrap();
        assert_eq!(
            signals["t_personal"],
            ThreadPersonalSignals {
                follow_level: ThreadFollowLevel::Follow,
                authored: false,
                participated: true,
                bookmarked: true,
                reading_started: true,
                has_unread: true,
            }
        );
        assert!(store
            .list_threads(
                None,
                ThreadSort::Latest,
                Some("u_bob"),
                ThreadStatusFilter::Any,
                10,
                300,
            )
            .await
            .unwrap()
            .iter()
            .any(|thread| thread.id == "t_personal"));

        store
            .set_thread_follow_level("t_personal", "u_bob", ThreadFollowLevel::Mute, 203)
            .await
            .unwrap();
        assert!(store
            .list_threads(
                None,
                ThreadSort::Latest,
                Some("u_bob"),
                ThreadStatusFilter::Any,
                10,
                300,
            )
            .await
            .unwrap()
            .is_empty());

        let too_many = (0..=MAX_FOR_YOU_CANDIDATES)
            .map(|index| format!("t_candidate_{index}"))
            .collect::<Vec<_>>();
        assert!(matches!(
            store
                .thread_personal_signals("u_bob", &too_many)
                .await
                .unwrap_err(),
            StoreError::InvalidOperation(_)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn in_memory_catch_up_reading_and_receipt_writes_share_one_lock_order() {
        let store = Arc::new(InMemoryStore::new());
        seed_thread(&store, "t_catch_lock_order", "Catch-up lock order", 1).await;
        store
            .set_thread_follow_level(
                "t_catch_lock_order",
                "u_reader",
                ThreadFollowLevel::Follow,
                1,
            )
            .await
            .unwrap();

        for index in 0..64 {
            let generation = store.catch_up_snapshot_generation().await.unwrap();
            let reply = post(
                &format!("p_catch_lock_order_{index}"),
                "t_catch_lock_order",
                "new reply",
                "",
                index + 2,
            );
            let start = Arc::new(Barrier::new(4));
            let catch_task = {
                let store = Arc::clone(&store);
                let start = Arc::clone(&start);
                tokio::spawn(async move {
                    start.wait().await;
                    store
                        .catch_up_page(
                            "u_reader",
                            CatchUpView::Following,
                            10_000,
                            generation,
                            None,
                            MAX_CATCH_UP_PAGE + 1,
                        )
                        .await
                })
            };
            let reading_task = {
                let store = Arc::clone(&store);
                let start = Arc::clone(&start);
                tokio::spawn(async move {
                    start.wait().await;
                    store
                        .thread_reading_states("u_reader", &["t_catch_lock_order".to_string()])
                        .await
                })
            };
            let reply_task = {
                let store = Arc::clone(&store);
                let start = Arc::clone(&start);
                let reply = reply.clone();
                tokio::spawn(async move {
                    start.wait().await;
                    store.add_reply(&reply).await
                })
            };
            start.wait().await;
            let (page, reading, reply_result) =
                tokio::time::timeout(Duration::from_secs(2), async {
                    tokio::join!(catch_task, reading_task, reply_task)
                })
                .await
                .expect("Catch-up, reading, and reply commands must make bounded progress");
            let page = page.unwrap().unwrap();
            reading.unwrap().unwrap();
            reply_result.unwrap().unwrap();
            assert_eq!(page.len(), 1);
            assert_eq!(page[0].reply_count, index);

            // Freeze the new post, then race its first receipt with both read projections. The
            // frozen Catch-up page must keep the receipt unread regardless of winner order.
            let receipt_generation = store.catch_up_snapshot_generation().await.unwrap();
            let start = Arc::new(Barrier::new(4));
            let catch_task = {
                let store = Arc::clone(&store);
                let start = Arc::clone(&start);
                tokio::spawn(async move {
                    start.wait().await;
                    store
                        .catch_up_page(
                            "u_reader",
                            CatchUpView::Updates,
                            10_000,
                            receipt_generation,
                            None,
                            MAX_CATCH_UP_PAGE + 1,
                        )
                        .await
                })
            };
            let reading_task = {
                let store = Arc::clone(&store);
                let start = Arc::clone(&start);
                tokio::spawn(async move {
                    start.wait().await;
                    store
                        .thread_reading_states("u_reader", &["t_catch_lock_order".to_string()])
                        .await
                })
            };
            let receipt_task = {
                let store = Arc::clone(&store);
                let start = Arc::clone(&start);
                let post_id = reply.id.clone();
                tokio::spawn(async move {
                    start.wait().await;
                    store
                        .mark_thread_posts_read(
                            "u_reader",
                            "t_catch_lock_order",
                            &[post_id],
                            10_000,
                        )
                        .await
                })
            };
            start.wait().await;
            let (page, reading, receipt_result) =
                tokio::time::timeout(Duration::from_secs(2), async {
                    tokio::join!(catch_task, reading_task, receipt_task)
                })
                .await
                .expect("Catch-up, reading, and receipt commands must make bounded progress");
            let page = page.unwrap().unwrap();
            reading.unwrap().unwrap();
            receipt_result.unwrap().unwrap();
            assert_eq!(page.len(), 1);
            assert_eq!(page[0].unread_count, 2);
        }
    }

    #[tokio::test]
    async fn in_memory_thread_sort_top_and_hot() {
        let store = InMemoryStore::new();
        let now = 10_000;
        seed_thread(&store, "t_old_busy", "Old busy", now - 7 * 86_400).await;
        seed_thread(&store, "t_recent_small", "Recent small", now - 3_600).await;

        for i in 0..20 {
            store
                .add_reply(&post(
                    &format!("p_old_{i}"),
                    "t_old_busy",
                    "old reply",
                    "",
                    now - 7 * 86_400 + i,
                ))
                .await
                .unwrap();
        }
        for i in 0..4 {
            store
                .add_reply(&post(
                    &format!("p_recent_{i}"),
                    "t_recent_small",
                    "recent reply",
                    "",
                    now - 3_600 + i,
                ))
                .await
                .unwrap();
        }

        let top = store
            .list_threads(
                None,
                ThreadSort::Top,
                None,
                ThreadStatusFilter::Any,
                10,
                now,
            )
            .await
            .unwrap();
        assert_eq!(top[0].id, "t_old_busy", "top sorts by reply count");

        let hot = store
            .list_threads(
                None,
                ThreadSort::Hot,
                None,
                ThreadStatusFilter::Any,
                10,
                now,
            )
            .await
            .unwrap();
        assert_eq!(hot[0].id, "t_recent_small", "hot decays older reply volume");
    }

    #[tokio::test]
    async fn in_memory_reply_pages_share_all_four_composite_anchor_semantics() {
        let store = InMemoryStore::new();
        seed_category(&store, "support", CategoryFormat::Question).await;
        let mut t = thread("t_pages", "Pages", 100);
        t.category_id = "support".to_string();
        let op = post("p_op", &t.id, "OP", "", 100);
        store.create_thread(&t, &op).await.unwrap();
        for id in ["p_e", "p_c", "p_a", "p_d", "p_b"] {
            store
                .add_reply(&post(id, &t.id, id, "", 200))
                .await
                .unwrap();
        }
        store
            .mutate_accepted_answer(
                &t.id,
                AcceptedAnswerAction::Accept {
                    post_id: "p_c".to_string(),
                },
            )
            .await
            .unwrap();

        let ids = |posts: Vec<Post>| posts.into_iter().map(|post| post.id).collect::<Vec<_>>();
        assert_eq!(
            ids(store
                .replies_page(&t.id, &op.id, Some("p_c"), &ReplyAnchor::First, 2)
                .await
                .unwrap()),
            ["p_a", "p_b"]
        );
        assert_eq!(
            ids(store
                .replies_page(
                    &t.id,
                    &op.id,
                    Some("p_c"),
                    &ReplyAnchor::After(200, "p_b".to_string()),
                    2,
                )
                .await
                .unwrap()),
            ["p_d", "p_e"]
        );
        assert_eq!(
            ids(store
                .replies_page(
                    &t.id,
                    &op.id,
                    Some("p_c"),
                    &ReplyAnchor::Before(200, "p_e".to_string()),
                    2,
                )
                .await
                .unwrap()),
            ["p_d", "p_b"]
        );
        assert_eq!(
            ids(store
                .replies_page(&t.id, &op.id, Some("p_c"), &ReplyAnchor::Latest, 2)
                .await
                .unwrap()),
            ["p_e", "p_d"]
        );
        assert!(store
            .replies_page(&t.id, &op.id, Some("p_c"), &ReplyAnchor::First, 0)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn in_memory_invalid_answers_are_not_public_status_or_search_solutions() {
        let store = InMemoryStore::new();
        seed_category(&store, "questions", CategoryFormat::Question).await;
        seed_category(&store, "discussion", CategoryFormat::Discussion).await;

        let mut target = thread("t_target", "Target", 100);
        target.category_id = "questions".to_string();
        let target_op = post("p_target_op", &target.id, "Target OP", "", 100);
        store.create_thread(&target, &target_op).await.unwrap();
        let target_reply = post(
            "p_target_reply",
            &target.id,
            "CROSS SOLUTION SECRET",
            "",
            101,
        );
        store.add_reply(&target_reply).await.unwrap();

        let mut missing = thread("t_missing", "Missing pointer", 200);
        missing.category_id = "questions".to_string();
        missing.accepted_post_id = "p_does_not_exist".to_string();
        let missing_op = post("p_missing_op", &missing.id, "Missing OP", "", 200);
        store.create_thread(&missing, &missing_op).await.unwrap();

        let mut original = thread("t_original", "Original pointer", 300);
        original.category_id = "questions".to_string();
        original.accepted_post_id = "p_original_op".to_string();
        let original_op = post("p_original_op", &original.id, "Original OP", "", 300);
        store.create_thread(&original, &original_op).await.unwrap();

        let mut cross = thread("t_cross", "Cross pointer", 400);
        cross.category_id = "questions".to_string();
        cross.accepted_post_id = target_reply.id.clone();
        let cross_op = post("p_cross_op", &cross.id, "Cross OP", "", 400);
        store.create_thread(&cross, &cross_op).await.unwrap();

        let answered = store
            .list_threads(
                None,
                ThreadSort::Latest,
                None,
                ThreadStatusFilter::Answered,
                20,
                500,
            )
            .await
            .unwrap();
        assert!(answered.is_empty());
        let unanswered = store
            .list_threads(
                None,
                ThreadSort::Latest,
                None,
                ThreadStatusFilter::Unanswered,
                20,
                500,
            )
            .await
            .unwrap();
        let unanswered_ids: HashSet<_> =
            unanswered.iter().map(|thread| thread.id.as_str()).collect();
        for expected in ["t_target", "t_missing", "t_original", "t_cross"] {
            assert!(unanswered_ids.contains(expected));
        }
        assert!(unanswered
            .iter()
            .all(|thread| thread.accepted_post_id.is_empty()));
        assert!(store
            .search_threads(
                "  cross solution secret  ",
                None,
                ThreadStatusFilter::Any,
                20,
            )
            .await
            .unwrap()
            .is_empty());
        for invalid in ["t_missing", "t_original", "t_cross"] {
            assert!(store
                .get_valid_accepted_post(invalid)
                .await
                .unwrap()
                .is_none());
        }
        let first_clear = store
            .mutate_accepted_answer("t_missing", AcceptedAnswerAction::Clear)
            .await
            .unwrap();
        assert!(first_clear.changed);
        assert!(first_clear.accepted_post.is_none());
        let second_clear = store
            .mutate_accepted_answer("t_missing", AcceptedAnswerAction::Clear)
            .await
            .unwrap();
        assert!(
            !second_clear.changed,
            "clear is idempotent and needs no target post"
        );

        let mut historical = thread("t_historical", "Historical", 600);
        historical.category_id = "discussion".to_string();
        historical.accepted_post_id = "p_historical_reply".to_string();
        let historical_op = post("p_historical_op", &historical.id, "Historical OP", "", 600);
        store
            .create_thread(&historical, &historical_op)
            .await
            .unwrap();
        store
            .add_reply(&post(
                "p_historical_reply",
                &historical.id,
                "LEGACY SOLUTION ONLY",
                "",
                601,
            ))
            .await
            .unwrap();
        assert_eq!(
            store
                .get_valid_accepted_post(&historical.id)
                .await
                .unwrap()
                .unwrap()
                .id,
            "p_historical_reply"
        );
        let public = store
            .list_threads(
                None,
                ThreadSort::Latest,
                None,
                ThreadStatusFilter::Any,
                20,
                700,
            )
            .await
            .unwrap();
        assert!(public
            .iter()
            .find(|thread| thread.id == historical.id)
            .unwrap()
            .accepted_post_id
            .is_empty());
        assert!(store
            .search_threads("legacy solution only", None, ThreadStatusFilter::Any, 20,)
            .await
            .unwrap()
            .is_empty());
        store
            .mutate_accepted_answer(&historical.id, AcceptedAnswerAction::Clear)
            .await
            .unwrap();
        assert!(store
            .get_thread(&historical.id)
            .await
            .unwrap()
            .unwrap()
            .accepted_post_id
            .is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn in_memory_guarded_commands_preserve_cross_operation_invariants() {
        let store = Arc::new(InMemoryStore::new());
        for id in [
            "q_accept_format",
            "q_accept_delete",
            "q_move_source",
            "q_move_target",
            "q_reply_delete",
            "q_reply_lock",
            "q_create_delete",
        ] {
            seed_category(&store, id, CategoryFormat::Question).await;
        }

        let mut accept_format = thread("t_accept_format", "Accept format", 100);
        accept_format.category_id = "q_accept_format".to_string();
        let accept_format_op = post("p_accept_format_op", &accept_format.id, "OP", "", 100);
        let accept_format_reply = post(
            "p_accept_format_reply",
            &accept_format.id,
            "answer",
            "",
            101,
        );
        store
            .create_thread(&accept_format, &accept_format_op)
            .await
            .unwrap();
        store.add_reply(&accept_format_reply).await.unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let accept_task = {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let thread_id = accept_format.id.clone();
            let post_id = accept_format_reply.id.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .mutate_accepted_answer(&thread_id, AcceptedAnswerAction::Accept { post_id })
                    .await
            })
        };
        let format_task = {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .transition_category_format("q_accept_format", CategoryFormat::Discussion)
                    .await
            })
        };
        barrier.wait().await;
        let _ = accept_task.await.unwrap();
        let _ = format_task.await.unwrap();
        let category = store
            .get_category("q_accept_format")
            .await
            .unwrap()
            .unwrap();
        let raw = store.get_thread(&accept_format.id).await.unwrap().unwrap();
        assert!(category.format.is_question() || raw.accepted_post_id.is_empty());

        let mut accept_delete = thread("t_accept_delete", "Accept delete", 200);
        accept_delete.category_id = "q_accept_delete".to_string();
        let accept_delete_op = post("p_accept_delete_op", &accept_delete.id, "OP", "", 200);
        let accept_delete_reply = post(
            "p_accept_delete_reply",
            &accept_delete.id,
            "answer",
            "",
            201,
        );
        store
            .create_thread(&accept_delete, &accept_delete_op)
            .await
            .unwrap();
        store.add_reply(&accept_delete_reply).await.unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let accept_task = {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let thread_id = accept_delete.id.clone();
            let post_id = accept_delete_reply.id.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .mutate_accepted_answer(&thread_id, AcceptedAnswerAction::Accept { post_id })
                    .await
            })
        };
        let delete_task = {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let post_id = accept_delete_reply.id.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store.delete_post(&post_id).await
            })
        };
        barrier.wait().await;
        let _ = accept_task.await.unwrap();
        delete_task.await.unwrap().unwrap();
        assert!(store
            .get_post(&accept_delete_reply.id)
            .await
            .unwrap()
            .is_none());
        assert!(store
            .get_thread(&accept_delete.id)
            .await
            .unwrap()
            .unwrap()
            .accepted_post_id
            .is_empty());

        let mut moving = thread("t_move_format", "Move format", 300);
        moving.category_id = "q_move_source".to_string();
        let moving_op = post("p_move_format_op", &moving.id, "OP", "", 300);
        let moving_reply = post("p_move_format_reply", &moving.id, "answer", "", 301);
        store.create_thread(&moving, &moving_op).await.unwrap();
        store.add_reply(&moving_reply).await.unwrap();
        store
            .mutate_accepted_answer(
                &moving.id,
                AcceptedAnswerAction::Accept {
                    post_id: moving_reply.id.clone(),
                },
            )
            .await
            .unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let move_task = {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let thread_id = moving.id.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .move_thread_to_category(&thread_id, "q_move_target")
                    .await
            })
        };
        let format_task = {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .transition_category_format("q_move_target", CategoryFormat::Discussion)
                    .await
            })
        };
        barrier.wait().await;
        let _ = move_task.await.unwrap();
        let _ = format_task.await.unwrap();
        let moved = store.get_thread(&moving.id).await.unwrap().unwrap();
        let target = store.get_category("q_move_target").await.unwrap().unwrap();
        assert!(
            moved.category_id != "q_move_target"
                || target.format.is_question()
                || moved.accepted_post_id.is_empty()
        );

        let mut reply_delete = thread("t_reply_delete", "Reply delete", 400);
        reply_delete.category_id = "q_reply_delete".to_string();
        let reply_delete_op = post("p_reply_delete_op", &reply_delete.id, "OP", "", 400);
        store
            .create_thread(&reply_delete, &reply_delete_op)
            .await
            .unwrap();
        let concurrent_reply = post("p_reply_delete_race", &reply_delete.id, "reply", "", 401);
        let barrier = Arc::new(Barrier::new(3));
        let reply_task = {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let reply = concurrent_reply.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store.add_reply(&reply).await
            })
        };
        let delete_task = {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let thread_id = reply_delete.id.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store.delete_thread(&thread_id).await
            })
        };
        barrier.wait().await;
        let _ = reply_task.await.unwrap();
        delete_task.await.unwrap().unwrap();
        assert!(store.get_thread(&reply_delete.id).await.unwrap().is_none());
        assert!(store
            .get_post(&concurrent_reply.id)
            .await
            .unwrap()
            .is_none());

        let mut reply_lock = thread("t_reply_lock", "Reply lock", 500);
        reply_lock.category_id = "q_reply_lock".to_string();
        let reply_lock_op = post("p_reply_lock_op", &reply_lock.id, "OP", "", 500);
        store
            .create_thread(&reply_lock, &reply_lock_op)
            .await
            .unwrap();
        let lock_race_reply = post("p_reply_lock_race", &reply_lock.id, "reply", "", 501);
        let barrier = Arc::new(Barrier::new(3));
        let reply_task = {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let reply = lock_race_reply.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store.add_reply(&reply).await
            })
        };
        let lock_task = {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let thread_id = reply_lock.id.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store.set_thread_locked(&thread_id, true).await
            })
        };
        barrier.wait().await;
        let reply_result = reply_task.await.unwrap();
        lock_task.await.unwrap().unwrap();
        assert_eq!(
            reply_result.is_ok(),
            store.get_post(&lock_race_reply.id).await.unwrap().is_some()
        );
        assert!(store
            .add_reply(&post("p_reply_after_lock", &reply_lock.id, "late", "", 502,))
            .await
            .is_err());

        let mut create_race = thread("t_create_delete", "Create delete", 600);
        create_race.category_id = "q_create_delete".to_string();
        let create_race_op = post("p_create_delete_op", &create_race.id, "OP", "", 600);
        let barrier = Arc::new(Barrier::new(3));
        let create_task = {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let thread = create_race.clone();
            let op = create_race_op.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store.create_thread(&thread, &op).await
            })
        };
        let category_delete_task = {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                barrier.wait().await;
                store.delete_category("q_create_delete").await
            })
        };
        barrier.wait().await;
        let _ = create_task.await.unwrap();
        let _ = category_delete_task.await.unwrap();
        let category_exists = store
            .get_category("q_create_delete")
            .await
            .unwrap()
            .is_some();
        let thread_exists = store.get_thread(&create_race.id).await.unwrap().is_some();
        assert_eq!(
            category_exists, thread_exists,
            "thread and category cannot orphan"
        );
    }
}
