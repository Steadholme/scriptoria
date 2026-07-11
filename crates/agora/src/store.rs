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
//! - `categories(id TEXT PK, name TEXT, sort_order BIGINT)`
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
    BannedAuthor, Category, Mention, Post, ReactionCount, Thread, ThreadDigest, ThreadSearchHit,
};

/// Storage failure surfaced to the handler layer (mapped to a 500 `server_error`).
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store error: {0}")]
    Backend(String),
    #[error("invalid store operation: {0}")]
    InvalidOperation(String),
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
    /// Set a category's `sort_order` (used to reorder the list). Admin-only.
    async fn set_category_order(&self, id: &str, sort_order: i64) -> Result<(), StoreError>;
    /// Delete a category. Admin-only; the caller refuses when it still holds threads.
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
        limit: i64,
        now: i64,
    ) -> Result<Vec<Thread>, StoreError>;
    /// Search thread titles and original-post bodies, optionally within one category. Results are
    /// most-recently-active first and include their reply count for one-query rendering.
    async fn search_threads(
        &self,
        query: &str,
        category_id: Option<&str>,
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
        anchor: &ReplyAnchor,
        limit: i64,
    ) -> Result<Vec<Post>, StoreError>;

    /// Create a thread together with its original post, atomically.
    async fn create_thread(&self, thread: &Thread, first_post: &Post) -> Result<(), StoreError>;
    /// Append a reply and bump the parent thread's `last_at` to the reply's timestamp.
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
    /// Move a thread to another category. Admin-only; the caller validates the target exists.
    async fn move_thread(&self, thread_id: &str, category_id: &str) -> Result<(), StoreError>;

    /// Set (or clear, with an empty string) a thread's `accepted_post_id` — the reply the thread
    /// author/admin marked as the accepted answer. Idempotent (setting the same value twice is a
    /// no-op change). Authorisation is enforced by the caller.
    async fn set_accepted_post(&self, thread_id: &str, post_id: &str) -> Result<(), StoreError>;

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

    async fn set_category_order(&self, id: &str, sort_order: i64) -> Result<(), StoreError> {
        let mut cats = self.categories.lock().expect("categories lock poisoned");
        if let Some(c) = cats.iter_mut().find(|c| c.id == id) {
            c.sort_order = sort_order;
        }
        Ok(())
    }

    async fn delete_category(&self, id: &str) -> Result<(), StoreError> {
        self.categories
            .lock()
            .expect("categories lock poisoned")
            .retain(|c| c.id != id);
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
        let posts = self.posts.lock().expect("posts lock poisoned").clone();
        let mut rows: Vec<(Thread, i64)> = self
            .threads
            .lock()
            .expect("threads lock poisoned")
            .iter()
            .filter(|t| category_id.map(|cid| t.category_id == cid).unwrap_or(true))
            .filter(|t| {
                subscribed_threads
                    .as_ref()
                    .map(|ids| ids.contains(&t.id))
                    .unwrap_or(true)
            })
            .cloned()
            .map(|t| {
                let post_count = posts.iter().filter(|p| p.thread_id == t.id).count() as i64;
                (t, (post_count - 1).max(0))
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
        limit: i64,
    ) -> Result<Vec<ThreadSearchHit>, StoreError> {
        let needle = query.trim().to_lowercase();
        if needle.is_empty() || limit <= 0 {
            return Ok(Vec::new());
        }

        // Build one original-post/count record per thread up front. This keeps search O(posts +
        // threads), instead of rescanning and sorting the complete post corpus for every thread.
        let posts = self.posts.lock().expect("posts lock poisoned").clone();
        let original_posts = self
            .original_posts
            .lock()
            .expect("original_posts lock poisoned")
            .clone();
        let mut post_counts: HashMap<String, i64> = HashMap::new();
        let mut original_bodies: HashMap<String, String> = HashMap::new();
        for post in posts {
            *post_counts.entry(post.thread_id.clone()).or_insert(0) += 1;
            if original_posts.get(&post.thread_id) == Some(&post.id) {
                original_bodies.insert(post.thread_id.clone(), post.body_md);
            }
        }
        let mut hits: Vec<ThreadSearchHit> = self
            .threads
            .lock()
            .expect("threads lock poisoned")
            .iter()
            .filter(|thread| {
                category_id
                    .map(|category_id| thread.category_id == category_id)
                    .unwrap_or(true)
            })
            .filter_map(|thread| {
                let first_body_md = original_bodies.get(&thread.id).cloned().unwrap_or_default();
                let post_count = post_counts.get(&thread.id).copied().unwrap_or_default();
                let matches = thread.title.to_lowercase().contains(&needle)
                    || first_body_md.to_lowercase().contains(&needle);
                matches.then(|| ThreadSearchHit {
                    thread: thread.clone(),
                    first_body_md,
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
        anchor: &ReplyAnchor,
        limit: i64,
    ) -> Result<Vec<Post>, StoreError> {
        // Replies are every post in the thread except the original (`op_id`).
        let mut v: Vec<Post> = self
            .posts
            .lock()
            .expect("posts lock poisoned")
            .iter()
            .filter(|p| p.thread_id == thread_id && p.id != op_id)
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
        let mut threads = self.threads.lock().expect("threads lock poisoned");
        let mut posts = self.posts.lock().expect("posts lock poisoned");
        threads.push(thread.clone());
        posts.push(first_post.clone());
        self.original_posts
            .lock()
            .expect("original_posts lock poisoned")
            .insert(thread.id.clone(), first_post.id.clone());
        Ok(())
    }

    async fn add_reply(&self, post: &Post) -> Result<(), StoreError> {
        {
            let mut posts = self.posts.lock().expect("posts lock poisoned");
            posts.push(post.clone());
        }
        let mut threads = self.threads.lock().expect("threads lock poisoned");
        if let Some(t) = threads.iter_mut().find(|t| t.id == post.thread_id) {
            t.last_at = post.created_at;
        }
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
        // Collect the doomed posts' ids first so their reactions can be dropped too.
        let removed_ids: Vec<String> = {
            let posts = self.posts.lock().expect("posts lock poisoned");
            posts
                .iter()
                .filter(|p| p.thread_id == thread_id)
                .map(|p| p.id.clone())
                .collect()
        };
        {
            let mut threads = self.threads.lock().expect("threads lock poisoned");
            threads.retain(|t| t.id != thread_id);
        }
        {
            let mut posts = self.posts.lock().expect("posts lock poisoned");
            posts.retain(|p| p.thread_id != thread_id);
        }
        self.original_posts
            .lock()
            .expect("original_posts lock poisoned")
            .remove(thread_id);
        let mut reactions = self.reactions.lock().expect("reactions lock poisoned");
        reactions.retain(|r| !removed_ids.iter().any(|id| id == &r.post_id));
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
        let (thread_id, op_id, newest_at) = {
            let mut posts = self.posts.lock().expect("posts lock poisoned");
            let thread_id = posts
                .iter()
                .find(|post| post.id == post_id)
                .map(|post| post.thread_id.clone());
            let op_id = thread_id.as_deref().and_then(|thread_id| {
                self.original_posts
                    .lock()
                    .expect("original_posts lock poisoned")
                    .get(thread_id)
                    .cloned()
            });
            if op_id.as_deref() == Some(post_id) {
                return Err(StoreError::InvalidOperation(
                    "the original post cannot be deleted separately; delete the thread".to_string(),
                ));
            }
            for p in posts.iter_mut().filter(|p| p.quoted_post_id == post_id) {
                p.quoted_post_id.clear();
            }
            posts.retain(|p| p.id != post_id);
            let newest_at = thread_id.as_deref().and_then(|thread_id| {
                posts
                    .iter()
                    .filter(|post| post.thread_id == thread_id)
                    .map(|post| post.created_at)
                    .max()
            });
            (thread_id, op_id, newest_at)
        };
        // Drop this post's reactions, and clear it as any thread's accepted answer.
        {
            let mut reactions = self.reactions.lock().expect("reactions lock poisoned");
            reactions.retain(|r| r.post_id != post_id);
        }
        {
            let mut mentions = self.mentions.lock().expect("mentions lock poisoned");
            mentions.retain(|m| m.post_id != post_id);
        }
        let mut threads = self.threads.lock().expect("threads lock poisoned");
        for t in threads.iter_mut().filter(|t| t.accepted_post_id == post_id) {
            t.accepted_post_id.clear();
        }
        if let Some(thread_id) = thread_id {
            if let Some(thread) = threads.iter_mut().find(|thread| thread.id == thread_id) {
                // OP deletion is rejected above. Repair any pre-existing invalid accepted=OP state,
                // and keep last_at aligned with the newest post that still exists.
                if op_id.as_deref() == Some(thread.accepted_post_id.as_str()) {
                    thread.accepted_post_id.clear();
                }
                thread.last_at = newest_at.unwrap_or(thread.created_at);
            }
        }
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

    async fn move_thread(&self, thread_id: &str, category_id: &str) -> Result<(), StoreError> {
        let mut threads = self.threads.lock().expect("threads lock poisoned");
        if let Some(t) = threads.iter_mut().find(|t| t.id == thread_id) {
            t.category_id = category_id.to_string();
        }
        Ok(())
    }

    async fn set_accepted_post(&self, thread_id: &str, post_id: &str) -> Result<(), StoreError> {
        let mut threads = self.threads.lock().expect("threads lock poisoned");
        if let Some(t) = threads.iter_mut().find(|t| t.id == thread_id) {
            t.accepted_post_id = post_id.to_string();
        }
        Ok(())
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
                 sort_order BIGINT NOT NULL DEFAULT 0\
             )",
        )
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
        Ok(Category {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            sort_order: row.try_get("sort_order")?,
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
                "INSERT INTO categories (id, name, sort_order) VALUES ($1, $2, $3) \
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(&c.id)
            .bind(&c.name)
            .bind(c.sort_order)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    async fn list_categories_async(&self) -> Result<Vec<Category>, sqlx::Error> {
        let rows =
            sqlx::query("SELECT id, name, sort_order FROM categories ORDER BY sort_order, name")
                .fetch_all(&self.pool)
                .await?;
        rows.iter().map(Self::category_from_row).collect()
    }

    async fn get_category_async(&self, id: &str) -> Result<Option<Category>, sqlx::Error> {
        let row = sqlx::query("SELECT id, name, sort_order FROM categories WHERE id = $1")
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
            "INSERT INTO categories (id, name, sort_order) VALUES ($1, $2, $3) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&c.id)
        .bind(&c.name)
        .bind(c.sort_order)
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

    async fn set_category_order_async(&self, id: &str, sort_order: i64) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE categories SET sort_order = $1 WHERE id = $2")
            .bind(sort_order)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_category_async(&self, id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM categories WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn recent_threads_async(&self, limit: i64) -> Result<Vec<Thread>, sqlx::Error> {
        let sql = format!(
            "SELECT {} FROM threads ORDER BY pinned DESC, last_at DESC, created_at DESC LIMIT $1",
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
        let sql = format!(
            "SELECT {} FROM threads WHERE category_id = $1 ORDER BY pinned DESC, last_at DESC, created_at DESC LIMIT $2",
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
        limit: i64,
        now: i64,
    ) -> Result<Vec<Thread>, sqlx::Error> {
        let cols = "t.id AS id, t.category_id AS category_id, t.title AS title, \
                    t.author_sub AS author_sub, t.author_email AS author_email, \
                    t.created_at AS created_at, t.last_at AS last_at, t.locked AS locked, \
                    t.pinned AS pinned, t.accepted_post_id AS accepted_post_id";
        let group_cols = "t.id, t.category_id, t.title, t.author_sub, t.author_email, \
                          t.created_at, t.last_at, t.locked, t.pinned, t.accepted_post_id";

        let mut sql = format!(
            "SELECT {cols}, COUNT(p.id) AS post_count \
             FROM threads t \
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
        if let Some(n) = category_param {
            where_parts.push(format!("t.category_id = ${n}"));
        }
        if let Some(n) = subscriber_param {
            sql.push_str(
                " JOIN thread_subscriptions s ON s.thread_id = t.id AND s.subscriber_sub = $",
            );
            sql.push_str(&n.to_string());
        }
        if !where_parts.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&where_parts.join(" AND "));
        }
        sql.push_str(" GROUP BY ");
        sql.push_str(group_cols);

        let mut query = sqlx::query(&sql);
        if let Some(category_id) = category_id {
            query = query.bind(category_id);
        }
        if let Some(subscriber_sub) = subscribed_sub {
            query = query.bind(subscriber_sub);
        }
        let rows = query.fetch_all(&self.pool).await?;
        let mut threads_with_counts: Vec<(Thread, i64)> = rows
            .iter()
            .map(|row| {
                let thread = Self::thread_from_row(row)?;
                let post_count: i64 = row.try_get("post_count")?;
                Ok((thread, (post_count - 1).max(0)))
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()?;
        sort_thread_rows(&mut threads_with_counts, sort, now);
        threads_with_counts.truncate(limit.max(0) as usize);
        Ok(threads_with_counts.into_iter().map(|(t, _)| t).collect())
    }

    async fn search_threads_async(
        &self,
        query: &str,
        category_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<ThreadSearchHit>, sqlx::Error> {
        if query.trim().is_empty() || limit <= 0 {
            return Ok(Vec::new());
        }

        let cols = "t.id AS id, t.category_id AS category_id, t.title AS title, \
                    t.author_sub AS author_sub, t.author_email AS author_email, \
                    t.created_at AS created_at, t.last_at AS last_at, t.locked AS locked, \
                    t.pinned AS pinned, t.accepted_post_id AS accepted_post_id";
        let mut sql = format!(
            "SELECT {cols}, t.first_body_md AS first_body_md, \
                    (SELECT COUNT(*) FROM posts p WHERE p.thread_id = t.id) AS post_count \
             FROM threads t \
             WHERE (LOWER(t.title) LIKE $1 ESCAPE '!' \
                    OR LOWER(t.first_body_md) LIKE $1 ESCAPE '!')"
        );
        if category_id.is_some() {
            sql.push_str(" AND t.category_id = $2");
            sql.push_str(
                " ORDER BY t.pinned DESC, t.last_at DESC, t.created_at DESC, t.id DESC LIMIT $3",
            );
        } else {
            sql.push_str(
                " ORDER BY t.pinned DESC, t.last_at DESC, t.created_at DESC, t.id DESC LIMIT $2",
            );
        }

        let mut query_builder = sqlx::query(&sql).bind(like_contains_pattern(query));
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
        let rows = sqlx::query(
            "SELECT id, category_id, title, first_body_md FROM threads \
             ORDER BY last_at DESC, created_at DESC LIMIT $1",
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
                     ORDER BY created_at ASC, id ASC LIMIT $3",
                    Self::POST_COLS
                );
                sqlx::query(&sql)
                    .bind(thread_id)
                    .bind(op_id)
                    .bind(limit)
                    .fetch_all(&self.pool)
                    .await?
            }
            ReplyAnchor::Latest => {
                let sql = format!(
                    "SELECT {} FROM posts WHERE thread_id = $1 AND id <> $2 \
                     ORDER BY created_at DESC, id DESC LIMIT $3",
                    Self::POST_COLS
                );
                sqlx::query(&sql)
                    .bind(thread_id)
                    .bind(op_id)
                    .bind(limit)
                    .fetch_all(&self.pool)
                    .await?
            }
            ReplyAnchor::After(ts, id) => {
                let sql = format!(
                    "SELECT {} FROM posts WHERE thread_id = $1 AND id <> $2 \
                     AND (created_at > $3 OR (created_at = $3 AND id > $4)) \
                     ORDER BY created_at ASC, id ASC LIMIT $5",
                    Self::POST_COLS
                );
                sqlx::query(&sql)
                    .bind(thread_id)
                    .bind(op_id)
                    .bind(ts)
                    .bind(id)
                    .bind(limit)
                    .fetch_all(&self.pool)
                    .await?
            }
            ReplyAnchor::Before(ts, id) => {
                let sql = format!(
                    "SELECT {} FROM posts WHERE thread_id = $1 AND id <> $2 \
                     AND (created_at < $3 OR (created_at = $3 AND id < $4)) \
                     ORDER BY created_at DESC, id DESC LIMIT $5",
                    Self::POST_COLS
                );
                sqlx::query(&sql)
                    .bind(thread_id)
                    .bind(op_id)
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
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
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
        .await?;
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
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn add_reply_async(&self, post: &Post) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
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
        .await?;
        sqlx::query("UPDATE threads SET last_at = $1 WHERE id = $2")
            .bind(post.created_at)
            .bind(&post.thread_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
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

    async fn delete_thread_async(&self, thread_id: &str) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        // Drop reactions on every post in the thread (subquery over the doomed posts) first.
        sqlx::query(
            "DELETE FROM post_reactions WHERE post_id IN (SELECT id FROM posts WHERE thread_id = $1)",
        )
        .bind(thread_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM post_mentions WHERE thread_id = $1")
            .bind(thread_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM thread_subscriptions WHERE thread_id = $1")
            .bind(thread_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM posts WHERE thread_id = $1")
            .bind(thread_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM threads WHERE id = $1")
            .bind(thread_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
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
    async fn delete_post_async(&self, post_id: &str) -> Result<bool, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let thread_id: Option<String> =
            sqlx::query_scalar("SELECT thread_id FROM posts WHERE id = $1")
                .bind(post_id)
                .fetch_optional(&mut *tx)
                .await?;
        if let Some(thread_id) = thread_id.as_deref() {
            let op_id: Option<String> =
                sqlx::query_scalar("SELECT first_post_id FROM threads WHERE id = $1")
                    .bind(thread_id)
                    .fetch_optional(&mut *tx)
                    .await?;
            if op_id.as_deref() == Some(post_id) {
                return Ok(false);
            }
        }
        sqlx::query("DELETE FROM post_reactions WHERE post_id = $1")
            .bind(post_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM post_mentions WHERE post_id = $1")
            .bind(post_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE posts SET quoted_post_id = '' WHERE quoted_post_id = $1")
            .bind(post_id)
            .execute(&mut *tx)
            .await?;
        // Clear it wherever it was the accepted answer, so no thread points at a gone post.
        sqlx::query("UPDATE threads SET accepted_post_id = '' WHERE accepted_post_id = $1")
            .bind(post_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM posts WHERE id = $1")
            .bind(post_id)
            .execute(&mut *tx)
            .await?;
        if let Some(thread_id) = thread_id {
            let new_op = sqlx::query(
                "SELECT id, body_md FROM posts \
                 WHERE thread_id = $1 \
                   AND id = (SELECT first_post_id FROM threads WHERE id = $1) \
                 FETCH FIRST 1 ROW ONLY",
            )
            .bind(&thread_id)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(row) = new_op {
                let op_id: String = row.try_get("id")?;
                let first_body_md: String = row.try_get("body_md")?;
                let newest_at: Option<i64> =
                    sqlx::query_scalar("SELECT MAX(created_at) FROM posts WHERE thread_id = $1")
                        .bind(&thread_id)
                        .fetch_one(&mut *tx)
                        .await?;
                sqlx::query(
                    "UPDATE threads \
                     SET first_body_md = $1, last_at = $2, \
                         accepted_post_id = CASE WHEN accepted_post_id = $3 THEN '' ELSE accepted_post_id END \
                     WHERE id = $4",
                )
                .bind(first_body_md)
                .bind(newest_at.expect("OP-preserving delete leaves at least one post"))
                .bind(op_id)
                .bind(&thread_id)
                .execute(&mut *tx)
                .await?;
            }
        }
        tx.commit().await?;
        Ok(true)
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

    async fn move_thread_async(
        &self,
        thread_id: &str,
        category_id: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE threads SET category_id = $1 WHERE id = $2")
            .bind(category_id)
            .bind(thread_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn set_accepted_post_async(
        &self,
        thread_id: &str,
        post_id: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE threads SET accepted_post_id = $1 WHERE id = $2")
            .bind(post_id)
            .bind(thread_id)
            .execute(&self.pool)
            .await?;
        Ok(())
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

    async fn set_category_order(&self, id: &str, sort_order: i64) -> Result<(), StoreError> {
        self.set_category_order_async(id, sort_order)
            .await
            .map_err(backend)
    }

    async fn delete_category(&self, id: &str) -> Result<(), StoreError> {
        self.delete_category_async(id).await.map_err(backend)
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
        limit: i64,
        now: i64,
    ) -> Result<Vec<Thread>, StoreError> {
        self.list_threads_async(category_id, sort, subscribed_sub, limit, now)
            .await
            .map_err(backend)
    }

    async fn search_threads(
        &self,
        query: &str,
        category_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<ThreadSearchHit>, StoreError> {
        self.search_threads_async(query, category_id, limit)
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
        anchor: &ReplyAnchor,
        limit: i64,
    ) -> Result<Vec<Post>, StoreError> {
        self.replies_page_async(thread_id, op_id, anchor, limit)
            .await
            .map_err(backend)
    }

    async fn create_thread(&self, thread: &Thread, first_post: &Post) -> Result<(), StoreError> {
        self.create_thread_async(thread, first_post)
            .await
            .map_err(backend)
    }

    async fn add_reply(&self, post: &Post) -> Result<(), StoreError> {
        self.add_reply_async(post).await.map_err(backend)
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
        self.delete_thread_async(thread_id).await.map_err(backend)
    }

    async fn update_post(&self, post_id: &str, body_md: &str) -> Result<(), StoreError> {
        self.update_post_async(post_id, body_md)
            .await
            .map_err(backend)
    }

    async fn delete_post(&self, post_id: &str) -> Result<(), StoreError> {
        match self.delete_post_async(post_id).await.map_err(backend)? {
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

    async fn move_thread(&self, thread_id: &str, category_id: &str) -> Result<(), StoreError> {
        self.move_thread_async(thread_id, category_id)
            .await
            .map_err(backend)
    }

    async fn set_accepted_post(&self, thread_id: &str, post_id: &str) -> Result<(), StoreError> {
        self.set_accepted_post_async(thread_id, post_id)
            .await
            .map_err(backend)
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
        let t = thread(id, title, created_at);
        let first = post(&format!("p_{id}_op"), id, "OP", "", created_at);
        store.create_thread(&t, &first).await.unwrap();
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
            .list_threads(None, ThreadSort::Latest, Some("u_alice"), 10, 400)
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
            .list_threads(None, ThreadSort::Latest, Some("u_alice"), 10, 400)
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
            .list_threads(None, ThreadSort::Top, None, 10, now)
            .await
            .unwrap();
        assert_eq!(top[0].id, "t_old_busy", "top sorts by reply count");

        let hot = store
            .list_threads(None, ThreadSort::Hot, None, 10, now)
            .await
            .unwrap();
        assert_eq!(hot[0].id, "t_recent_small", "hot decays older reply volume");
    }
}
