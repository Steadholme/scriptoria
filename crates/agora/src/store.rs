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
//! - `posts(id TEXT PK, thread_id TEXT, body_md TEXT, author_sub TEXT, author_email TEXT,
//!    created_at BIGINT)`

use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::model::{BannedAuthor, Category, Post, ReactionCount, Thread, ThreadDigest};

/// Storage failure surfaced to the handler layer (mapped to a 500 `server_error`).
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store error: {0}")]
    Backend(String),
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
    /// A single thread by id, if it exists.
    async fn get_thread(&self, id: &str) -> Result<Option<Thread>, StoreError>;

    /// Digests (id, category, title, original-post body) of the most recently active threads,
    /// capped. Feeds compose-time similarity scoring without loading every post.
    async fn thread_digests(&self, limit: i64) -> Result<Vec<ThreadDigest>, StoreError>;

    /// Number of posts in a thread (original post + replies).
    async fn count_posts(&self, thread_id: &str) -> Result<i64, StoreError>;
    /// A single post by id, if it exists (used by admin post-deletion + audit).
    async fn get_post(&self, id: &str) -> Result<Option<Post>, StoreError>;
    /// All posts in a thread, oldest first (original post first, then replies).
    async fn posts_in_thread(&self, thread_id: &str) -> Result<Vec<Post>, StoreError>;

    /// Create a thread together with its original post, atomically.
    async fn create_thread(&self, thread: &Thread, first_post: &Post) -> Result<(), StoreError>;
    /// Append a reply and bump the parent thread's `last_at` to the reply's timestamp.
    async fn add_reply(&self, post: &Post) -> Result<(), StoreError>;

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
        v.sort_by(|a, b| a.sort_order.cmp(&b.sort_order).then_with(|| a.name.cmp(&b.name)));
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
        threads.sort_by(|a, b| b.last_at.cmp(&a.last_at).then_with(|| b.created_at.cmp(&a.created_at)));
        threads.truncate(limit.max(0) as usize);
        // Clone the posts once, then pick each thread's original post (oldest, id-tiebroken).
        let posts: Vec<Post> = self.posts.lock().expect("posts lock poisoned").clone();
        let digests = threads
            .into_iter()
            .map(|t| {
                let first_body_md = posts
                    .iter()
                    .filter(|p| p.thread_id == t.id)
                    .min_by(|a, b| a.created_at.cmp(&b.created_at).then_with(|| a.id.cmp(&b.id)))
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
        let mut v: Vec<Post> = self
            .posts
            .lock()
            .expect("posts lock poisoned")
            .iter()
            .filter(|p| p.thread_id == thread_id)
            .cloned()
            .collect();
        v.sort_by(|a, b| a.created_at.cmp(&b.created_at).then_with(|| a.id.cmp(&b.id)));
        Ok(v)
    }

    async fn create_thread(&self, thread: &Thread, first_post: &Post) -> Result<(), StoreError> {
        let mut threads = self.threads.lock().expect("threads lock poisoned");
        let mut posts = self.posts.lock().expect("posts lock poisoned");
        threads.push(thread.clone());
        posts.push(first_post.clone());
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

    async fn update_thread(
        &self,
        thread_id: &str,
        title: &str,
        op_post_id: &str,
        body_md: &str,
    ) -> Result<(), StoreError> {
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
        let mut reactions = self.reactions.lock().expect("reactions lock poisoned");
        reactions.retain(|r| !removed_ids.iter().any(|id| id == &r.post_id));
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
        {
            let mut posts = self.posts.lock().expect("posts lock poisoned");
            posts.retain(|p| p.id != post_id);
        }
        // Drop this post's reactions, and clear it as any thread's accepted answer.
        {
            let mut reactions = self.reactions.lock().expect("reactions lock poisoned");
            reactions.retain(|r| r.post_id != post_id);
        }
        let mut threads = self.threads.lock().expect("threads lock poisoned");
        for t in threads.iter_mut().filter(|t| t.accepted_post_id == post_id) {
            t.accepted_post_id.clear();
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
        v.sort_by(|a, b| b.created_at.cmp(&a.created_at).then_with(|| a.author_sub.cmp(&b.author_sub)));
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
        // rows default to '' and still match on their title — graceful degradation.
        sqlx::query("ALTER TABLE threads ADD COLUMN IF NOT EXISTS first_body_md TEXT NOT NULL DEFAULT ''")
            .execute(&self.pool)
            .await?;
        // Admin moderation flags: locked (no new replies) + pinned (sort first). Additive,
        // idempotent; pre-existing rows default to unlocked/unpinned. Portable BOOLEAN only.
        sqlx::query("ALTER TABLE threads ADD COLUMN IF NOT EXISTS locked BOOLEAN NOT NULL DEFAULT FALSE")
            .execute(&self.pool)
            .await?;
        sqlx::query("ALTER TABLE threads ADD COLUMN IF NOT EXISTS pinned BOOLEAN NOT NULL DEFAULT FALSE")
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
                 author_sub TEXT NOT NULL, \
                 author_email TEXT NOT NULL, \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_posts_thread ON posts (thread_id)")
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
            author_sub: row.try_get("author_sub")?,
            author_email: row.try_get("author_email")?,
            created_at: row.try_get("created_at")?,
        })
    }

    const THREAD_COLS: &'static str =
        "id, category_id, title, author_sub, author_email, created_at, last_at, locked, pinned, accepted_post_id";
    const POST_COLS: &'static str =
        "id, thread_id, body_md, author_sub, author_email, created_at";

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
        let rows = sqlx::query("SELECT id, name, sort_order FROM categories ORDER BY sort_order, name")
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

    async fn get_thread_async(&self, id: &str) -> Result<Option<Thread>, sqlx::Error> {
        let sql = format!("SELECT {} FROM threads WHERE id = $1", Self::THREAD_COLS);
        let row = sqlx::query(&sql).bind(id).fetch_optional(&self.pool).await?;
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
        let row = sqlx::query(&sql).bind(id).fetch_optional(&self.pool).await?;
        row.as_ref().map(Self::post_from_row).transpose()
    }

    async fn posts_in_thread_async(&self, thread_id: &str) -> Result<Vec<Post>, sqlx::Error> {
        let sql = format!(
            "SELECT {} FROM posts WHERE thread_id = $1 ORDER BY created_at ASC, id ASC",
            Self::POST_COLS
        );
        let rows = sqlx::query(&sql)
            .bind(thread_id)
            .fetch_all(&self.pool)
            .await?;
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
                 (id, category_id, title, author_sub, author_email, created_at, last_at, first_body_md, locked, pinned, accepted_post_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(&thread.id)
        .bind(&thread.category_id)
        .bind(&thread.title)
        .bind(&thread.author_sub)
        .bind(&thread.author_email)
        .bind(thread.created_at)
        .bind(thread.last_at)
        .bind(&first_post.body_md)
        .bind(thread.locked)
        .bind(thread.pinned)
        .bind(&thread.accepted_post_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO posts \
                 (id, thread_id, body_md, author_sub, author_email, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&first_post.id)
        .bind(&first_post.thread_id)
        .bind(&first_post.body_md)
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
                 (id, thread_id, body_md, author_sub, author_email, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&post.id)
        .bind(&post.thread_id)
        .bind(&post.body_md)
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

    async fn delete_post_async(&self, post_id: &str) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM post_reactions WHERE post_id = $1")
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
        tx.commit().await?;
        Ok(())
    }

    async fn set_thread_locked_async(&self, thread_id: &str, locked: bool) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE threads SET locked = $1 WHERE id = $2")
            .bind(locked)
            .bind(thread_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn set_thread_pinned_async(&self, thread_id: &str, pinned: bool) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE threads SET pinned = $1 WHERE id = $2")
            .bind(pinned)
            .bind(thread_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn move_thread_async(&self, thread_id: &str, category_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE threads SET category_id = $1 WHERE id = $2")
            .bind(category_id)
            .bind(thread_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn set_accepted_post_async(&self, thread_id: &str, post_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE threads SET accepted_post_id = $1 WHERE id = $2")
            .bind(post_id)
            .bind(thread_id)
            .execute(&self.pool)
            .await?;
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
        sqlx::query("DELETE FROM post_reactions WHERE post_id = $1 AND user_sub = $2 AND kind = $3")
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
        self.set_category_order_async(id, sort_order).await.map_err(backend)
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

    async fn create_thread(&self, thread: &Thread, first_post: &Post) -> Result<(), StoreError> {
        self.create_thread_async(thread, first_post)
            .await
            .map_err(backend)
    }

    async fn add_reply(&self, post: &Post) -> Result<(), StoreError> {
        self.add_reply_async(post).await.map_err(backend)
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
        self.update_post_async(post_id, body_md).await.map_err(backend)
    }

    async fn delete_post(&self, post_id: &str) -> Result<(), StoreError> {
        self.delete_post_async(post_id).await.map_err(backend)
    }

    async fn set_thread_locked(&self, thread_id: &str, locked: bool) -> Result<(), StoreError> {
        self.set_thread_locked_async(thread_id, locked).await.map_err(backend)
    }

    async fn set_thread_pinned(&self, thread_id: &str, pinned: bool) -> Result<(), StoreError> {
        self.set_thread_pinned_async(thread_id, pinned).await.map_err(backend)
    }

    async fn move_thread(&self, thread_id: &str, category_id: &str) -> Result<(), StoreError> {
        self.move_thread_async(thread_id, category_id).await.map_err(backend)
    }

    async fn set_accepted_post(&self, thread_id: &str, post_id: &str) -> Result<(), StoreError> {
        self.set_accepted_post_async(thread_id, post_id).await.map_err(backend)
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
