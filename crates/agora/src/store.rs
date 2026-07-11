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
//! - `thread_subscriptions(thread_id TEXT, subscriber_sub TEXT, created_at BIGINT)`

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::model::{
    BannedAuthor, Category, CategoryFormat, Mention, Post, ReactionCount, Thread, ThreadDigest,
    ThreadSearchHit,
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
    After(i64, String),
    Before(i64, String),
    Latest,
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
    async fn get_valid_accepted_post(
        &self,
        thread_id: &str,
    ) -> Result<Option<Post>, StoreError>;
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
    /// Append a reply and bump the parent thread's `last_at` to the reply's timestamp. The Store
    /// locks category then thread and rechecks that the thread exists and is still unlocked.
    async fn add_reply(&self, post: &Post) -> Result<(), StoreError>;

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

    /// Toggle one user's subscription to a thread. Returns `true` when subscribed, `false` when the
    /// existing subscription was removed.
    async fn toggle_thread_subscription(
        &self,
        thread_id: &str,
        subscriber_sub: &str,
        created_at: i64,
    ) -> Result<bool, StoreError>;
    /// Whether a user is currently subscribed to a thread.
    async fn is_thread_subscribed(
        &self,
        thread_id: &str,
        subscriber_sub: &str,
    ) -> Result<bool, StoreError>;

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
    subscriptions: Mutex<Vec<ThreadSubscription>>,
    banned: Mutex<Vec<BannedAuthor>>,
    /// One row per `(post_id, user_sub, kind)` — the in-memory mirror of `post_reactions`.
    reactions: Mutex<Vec<Reaction>>,
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

/// A single stored subscription (in-memory mirror of a `thread_subscriptions` row).
#[derive(Clone, Debug)]
struct ThreadSubscription {
    thread_id: String,
    subscriber_sub: String,
    _created_at: i64,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
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
                .filter(|s| s.subscriber_sub == sub)
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
                let valid = has_valid_question_solution(
                    thread,
                    format,
                    &original_posts,
                    &posts,
                );
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
                let valid = has_valid_question_solution(
                    thread,
                    format,
                    &original_posts,
                    &posts,
                );
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

    async fn get_valid_accepted_post(
        &self,
        thread_id: &str,
    ) -> Result<Option<Post>, StoreError> {
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
        }
        // First/After walk ascending; Before/Latest walk descending — matching the SQL ORDER BY.
        match anchor {
            ReplyAnchor::First | ReplyAnchor::After(..) => {
                v.sort_by(|a, b| {
                    a.created_at
                        .cmp(&b.created_at)
                        .then_with(|| a.id.cmp(&b.id))
                });
            }
            ReplyAnchor::Before(..) | ReplyAnchor::Latest => {
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
        threads.push(thread.clone());
        original_posts.insert(thread.id.clone(), first_post.id.clone());
        posts.push(first_post.clone());
        Ok(())
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
        posts.push(post.clone());
        thread.last_at = post.created_at;
        Ok(())
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
        let mut reactions = self.reactions.lock().expect("reactions lock poisoned");
        reactions.retain(|reaction| !removed_ids.contains(&reaction.post_id));
        let mut mentions = self.mentions.lock().expect("mentions lock poisoned");
        mentions.retain(|m| m.thread_id != thread_id);
        let mut subscriptions = self
            .subscriptions
            .lock()
            .expect("subscriptions lock poisoned");
        subscriptions.retain(|s| s.thread_id != thread_id);
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
        for post in posts.iter_mut().filter(|post| post.quoted_post_id == post_id) {
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

        self.reactions
            .lock()
            .expect("reactions lock poisoned")
            .retain(|reaction| reaction.post_id != post_id);
        self.mentions
            .lock()
            .expect("mentions lock poisoned")
            .retain(|mention| mention.post_id != post_id);
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
            return Err(StoreError::NotFound("source category not found".to_string()));
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
        })
    }

    async fn toggle_thread_subscription(
        &self,
        thread_id: &str,
        subscriber_sub: &str,
        created_at: i64,
    ) -> Result<bool, StoreError> {
        let mut subscriptions = self
            .subscriptions
            .lock()
            .expect("subscriptions lock poisoned");
        if let Some(pos) = subscriptions
            .iter()
            .position(|s| s.thread_id == thread_id && s.subscriber_sub == subscriber_sub)
        {
            subscriptions.remove(pos);
            Ok(false)
        } else {
            subscriptions.push(ThreadSubscription {
                thread_id: thread_id.to_string(),
                subscriber_sub: subscriber_sub.to_string(),
                _created_at: created_at,
            });
            Ok(true)
        }
    }

    async fn is_thread_subscribed(
        &self,
        thread_id: &str,
        subscriber_sub: &str,
    ) -> Result<bool, StoreError> {
        Ok(self
            .subscriptions
            .lock()
            .expect("subscriptions lock poisoned")
            .iter()
            .any(|s| s.thread_id == thread_id && s.subscriber_sub == subscriber_sub))
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

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

/// PostgreSQL-backed [`Store`]. Holds just a `PgPool`; the async trait methods drive sqlx
/// natively, so no worker thread is ever blocked on a DB round-trip.
pub struct PgStore {
    pool: PgPool,
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
        // Per-thread subscriptions. The composite primary key gives one subscription per user/thread.
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
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_subscriptions_user ON thread_subscriptions (subscriber_sub)")
            .execute(&self.pool)
            .await?;
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
        let category = sqlx::query_scalar::<_, String>(
            "SELECT id FROM categories WHERE id = $1 FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(backend)?;
        if category.is_none() {
            tx.commit().await.map_err(backend)?;
            return Ok(());
        }
        let thread_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM threads WHERE category_id = $1",
        )
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
                " JOIN thread_subscriptions s ON s.thread_id = t.id AND s.subscriber_sub = $",
            );
            sql.push_str(&n.to_string());
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
                sql.push_str(
                    "COUNT(p.id) DESC, t.last_at DESC, t.created_at DESC, t.id DESC",
                );
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
        sqlx::query_scalar::<_, String>(
            "SELECT id FROM categories WHERE id = $1 FOR UPDATE",
        )
        .bind(&thread.category_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(backend)?
        .ok_or_else(|| StoreError::NotFound("category not found".to_string()))?;
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
        tx.commit().await.map_err(backend)?;
        Ok(())
    }

    async fn add_reply_async(&self, post: &Post) -> Result<(), StoreError> {
        for _ in 0..4 {
            let category_hint = sqlx::query_scalar::<_, String>(
                "SELECT category_id FROM threads WHERE id = $1",
            )
            .bind(&post.thread_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(backend)?
            .ok_or_else(|| StoreError::NotFound("thread not found".to_string()))?;

            let mut tx = self.pool.begin().await.map_err(backend)?;
            sqlx::query_scalar::<_, String>(
                "SELECT id FROM categories WHERE id = $1 FOR UPDATE",
            )
            .bind(&category_hint)
            .fetch_optional(&mut *tx)
            .await
            .map_err(backend)?
            .ok_or_else(|| StoreError::NotFound("category not found".to_string()))?;
            let thread = sqlx::query(
                "SELECT category_id, locked FROM threads WHERE id = $1 FOR UPDATE",
            )
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
            let category_hint = sqlx::query_scalar::<_, String>(
                "SELECT category_id FROM threads WHERE id = $1",
            )
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
            sqlx::query(
                "SELECT id FROM posts WHERE thread_id = $1 ORDER BY id FOR UPDATE",
            )
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
            let thread_hint = sqlx::query_scalar::<_, String>(
                "SELECT thread_id FROM posts WHERE id = $1",
            )
            .bind(post_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(backend)?;
            let Some(thread_hint) = thread_hint else {
                return Ok(true);
            };
            let category_hint = sqlx::query_scalar::<_, String>(
                "SELECT category_id FROM threads WHERE id = $1",
            )
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
            let newest_at: Option<i64> = sqlx::query_scalar(
                "SELECT MAX(created_at) FROM posts WHERE thread_id = $1",
            )
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
            sqlx::query(
                "UPDATE threads SET last_at = $1, accepted_post_id = $2 WHERE id = $3",
            )
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
            let source_hint = sqlx::query_scalar::<_, String>(
                "SELECT category_id FROM threads WHERE id = $1",
            )
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
                return Err(StoreError::NotFound("source category not found".to_string()));
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
            if thread.category_id != category_id
                && valid_solution
                && !target_format.is_question()
            {
                return Err(StoreError::InvalidOperation(
                    "unmark the accepted answer before moving this thread to a discussion category"
                        .to_string(),
                ));
            }
            if !valid_solution {
                thread.accepted_post_id.clear();
            }
            sqlx::query(
                "UPDATE threads SET category_id = $1, accepted_post_id = $2 WHERE id = $3",
            )
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
    ) -> Result<AcceptedAnswerMutation, StoreError> {
        for _ in 0..4 {
            let category_hint = sqlx::query_scalar::<_, String>(
                "SELECT category_id FROM threads WHERE id = $1",
            )
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
            tx.commit().await.map_err(backend)?;
            return Ok(AcceptedAnswerMutation {
                thread,
                accepted_post,
                changed,
            });
        }
        Err(StoreError::Backend(
            "thread category changed repeatedly; retry the answer mutation".to_string(),
        ))
    }

    async fn toggle_thread_subscription_async(
        &self,
        thread_id: &str,
        subscriber_sub: &str,
        created_at: i64,
    ) -> Result<bool, sqlx::Error> {
        let inserted = sqlx::query(
            "INSERT INTO thread_subscriptions (thread_id, subscriber_sub, created_at) \
             VALUES ($1, $2, $3) ON CONFLICT (thread_id, subscriber_sub) DO NOTHING",
        )
        .bind(thread_id)
        .bind(subscriber_sub)
        .bind(created_at)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if inserted > 0 {
            return Ok(true);
        }
        sqlx::query(
            "DELETE FROM thread_subscriptions WHERE thread_id = $1 AND subscriber_sub = $2",
        )
        .bind(thread_id)
        .bind(subscriber_sub)
        .execute(&self.pool)
        .await?;
        Ok(false)
    }

    async fn is_thread_subscribed_async(
        &self,
        thread_id: &str,
        subscriber_sub: &str,
    ) -> Result<bool, sqlx::Error> {
        let row = sqlx::query(
            "SELECT COUNT(*) AS n FROM thread_subscriptions \
             WHERE thread_id = $1 AND subscriber_sub = $2",
        )
        .bind(thread_id)
        .bind(subscriber_sub)
        .fetch_one(&self.pool)
        .await?;
        let n: i64 = row.try_get("n")?;
        Ok(n > 0)
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

    async fn get_valid_accepted_post(
        &self,
        thread_id: &str,
    ) -> Result<Option<Post>, StoreError> {
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

    async fn add_reply(&self, post: &Post) -> Result<(), StoreError> {
        self.add_reply_async(post).await
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
        self.mutate_accepted_answer_async(thread_id, action).await
    }

    async fn toggle_thread_subscription(
        &self,
        thread_id: &str,
        subscriber_sub: &str,
        created_at: i64,
    ) -> Result<bool, StoreError> {
        self.toggle_thread_subscription_async(thread_id, subscriber_sub, created_at)
            .await
            .map_err(backend)
    }

    async fn is_thread_subscribed(
        &self,
        thread_id: &str,
        subscriber_sub: &str,
    ) -> Result<bool, StoreError> {
        self.is_thread_subscribed_async(thread_id, subscriber_sub)
            .await
            .map_err(backend)
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
    use std::sync::Arc;

    use tokio::sync::Barrier;

    fn thread(id: &str, title: &str, created_at: i64) -> Thread {
        Thread {
            id: id.to_string(),
            category_id: "general".to_string(),
            title: title.to_string(),
            author_sub: "u_alice".to_string(),
            author_email: "alice@holdfast.local".to_string(),
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
            author_email: "bob@holdfast.local".to_string(),
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
    async fn in_memory_subscriptions_toggle_and_filter() {
        let store = InMemoryStore::new();
        seed_thread(&store, "t_one", "One", 100).await;
        seed_thread(&store, "t_two", "Two", 200).await;

        assert!(store
            .toggle_thread_subscription("t_one", "u_alice", 300)
            .await
            .unwrap());
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

        assert!(!store
            .toggle_thread_subscription("t_one", "u_alice", 301)
            .await
            .unwrap());
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
            .list_threads(None, ThreadSort::Top, None, ThreadStatusFilter::Any, 10, now)
            .await
            .unwrap();
        assert_eq!(top[0].id, "t_old_busy", "top sorts by reply count");

        let hot = store
            .list_threads(None, ThreadSort::Hot, None, ThreadStatusFilter::Any, 10, now)
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
        let unanswered_ids: HashSet<_> = unanswered.iter().map(|thread| thread.id.as_str()).collect();
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
        assert!(!second_clear.changed, "clear is idempotent and needs no target post");

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
            .search_threads(
                "legacy solution only",
                None,
                ThreadStatusFilter::Any,
                20,
            )
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
                    .transition_category_format(
                        "q_accept_format",
                        CategoryFormat::Discussion,
                    )
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
        let raw = store
            .get_thread(&accept_format.id)
            .await
            .unwrap()
            .unwrap();
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
        let target = store
            .get_category("q_move_target")
            .await
            .unwrap()
            .unwrap();
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
        let concurrent_reply = post(
            "p_reply_delete_race",
            &reply_delete.id,
            "reply",
            "",
            401,
        );
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
        store.create_thread(&reply_lock, &reply_lock_op).await.unwrap();
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
            store
                .get_post(&lock_race_reply.id)
                .await
                .unwrap()
                .is_some()
        );
        assert!(store
            .add_reply(&post(
                "p_reply_after_lock",
                &reply_lock.id,
                "late",
                "",
                502,
            ))
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
        let thread_exists = store
            .get_thread(&create_race.id)
            .await
            .unwrap()
            .is_some();
        assert_eq!(category_exists, thread_exists, "thread and category cannot orphan");
    }
}
