//! Comment + thread storage.
//!
//! `Store` is a small async trait with an in-memory and a PostgreSQL implementation, mirroring
//! the inkwell/sanctum seam: handlers depend only on the trait, so a FusionDB-backed store can
//! drop in later. The PostgreSQL layer uses ONLY portable standard SQL (TEXT/BIGINT/BOOLEAN,
//! PK/UNIQUE/NOT NULL/DEFAULT, `INSERT .. ON CONFLICT`, parameterized queries, `CREATE INDEX`)
//! and runtime queries (no compile-time macros), so the build needs NO database and the same
//! statements later run unchanged on FusionDB over pgwire.
//!
//! The methods are `async`: the axum handlers `.await` them directly on the serving runtime, and
//! `PgStore` drives sqlx natively — there is NO `block_in_place` and NO sync-over-async bridge.

use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::config::{clamp_page, COMMENT_LIMIT};

/// A comment thread (maps 1:1 to a `threads` row). A thread is keyed by an opaque `key` (the
/// embedding page's stable identifier, e.g. `blog/hello-world`).
#[derive(Clone, Debug)]
pub struct Thread {
    pub id: String,
    pub key: String,
    pub title: String,
    pub url: String,
    pub created_at: i64,
}

/// A single comment (maps 1:1 to a `comments` row). `parent_id` is `""` for a top-level comment,
/// or the id of the top-level comment it replies to (replies nest exactly one level).
#[derive(Clone, Debug)]
pub struct Comment {
    pub id: String,
    pub thread_id: String,
    pub author_sub: String,
    pub author_email: String,
    pub body: String,
    pub created_at: i64,
    pub hidden: bool,
    pub parent_id: String,
}

/// Storage failure surfaced to the handler layer.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Backend I/O failure (mapped to a 500).
    #[error("store error: {0}")]
    Backend(String),
}

/// Pluggable comment store.
#[async_trait]
pub trait Store: Send + Sync {
    /// One keyset page of threads, newest-first (`created_at` DESC, `id` DESC). `before` is the
    /// `(created_at, id)` of the last row of the previous page (the exclusive upper bound);
    /// `None` returns the newest page. `limit` is clamped to `[1, MAX_PAGE]` (see [`clamp_page`]).
    async fn list_threads(&self, before: Option<(i64, String)>, limit: i64) -> Vec<Thread>;
    /// One thread by its unique key.
    async fn get_thread(&self, key: &str) -> Option<Thread>;
    /// Upsert a thread by key: insert `thread` when its key is free, otherwise leave the existing
    /// row untouched. Returns the resulting row (existing or newly inserted) either way, so the
    /// caller always gets a stable `thread_id`.
    async fn upsert_thread(&self, thread: &Thread) -> Result<Thread, StoreError>;
    /// All comments in a thread, oldest-first (`created_at` ASC), capped at [`COMMENT_LIMIT`].
    async fn list_comments(&self, thread_id: &str) -> Vec<Comment>;
    /// One comment by id.
    async fn get_comment(&self, id: &str) -> Option<Comment>;
    /// Insert a new comment.
    async fn create_comment(&self, comment: &Comment) -> Result<(), StoreError>;
    /// Set a comment's `hidden` flag. Returns `true` when a row was actually updated.
    async fn set_comment_hidden(&self, id: &str, hidden: bool) -> Result<bool, StoreError>;
    /// Number of comments in a thread (all, including hidden).
    async fn count_comments(&self, thread_id: &str) -> i64;
    /// The most recent comments across all threads, newest-first, capped at `limit` — backs the
    /// dashboard's activity feed.
    async fn recent_comments(&self, limit: usize) -> Vec<Comment>;
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

#[derive(Default)]
pub struct InMemoryStore {
    threads: Mutex<Vec<Thread>>,
    comments: Mutex<Vec<Comment>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for InMemoryStore {
    // The std `Mutex` is fine throughout: each critical section is fully synchronous (no `.await`
    // inside), so a guard is never held across a yield point.
    async fn list_threads(&self, before: Option<(i64, String)>, limit: i64) -> Vec<Thread> {
        let limit = clamp_page(limit) as usize;
        let threads = self.threads.lock().expect("threads lock poisoned");
        // Same keyset predicate as the SQL path: strictly "older than" the cursor under the
        // (created_at DESC, id DESC) ordering, i.e. created_at < ts OR (created_at == ts AND id < id).
        let mut v: Vec<Thread> = threads
            .iter()
            .filter(|t| match &before {
                Some((ts, id)) => {
                    t.created_at < *ts || (t.created_at == *ts && t.id.as_str() < id.as_str())
                }
                None => true,
            })
            .cloned()
            .collect();
        v.sort_by(|a, b| b.created_at.cmp(&a.created_at).then_with(|| b.id.cmp(&a.id)));
        v.truncate(limit);
        v
    }

    async fn get_thread(&self, key: &str) -> Option<Thread> {
        self.threads
            .lock()
            .expect("threads lock poisoned")
            .iter()
            .find(|t| t.key == key)
            .cloned()
    }

    async fn upsert_thread(&self, thread: &Thread) -> Result<Thread, StoreError> {
        let mut threads = self.threads.lock().expect("threads lock poisoned");
        if let Some(existing) = threads.iter().find(|t| t.key == thread.key) {
            return Ok(existing.clone());
        }
        threads.push(thread.clone());
        Ok(thread.clone())
    }

    async fn list_comments(&self, thread_id: &str) -> Vec<Comment> {
        let comments = self.comments.lock().expect("comments lock poisoned");
        let mut v: Vec<Comment> = comments
            .iter()
            .filter(|c| c.thread_id == thread_id)
            .cloned()
            .collect();
        v.sort_by(|a, b| a.created_at.cmp(&b.created_at).then_with(|| a.id.cmp(&b.id)));
        v.truncate(COMMENT_LIMIT);
        v
    }

    async fn get_comment(&self, id: &str) -> Option<Comment> {
        self.comments
            .lock()
            .expect("comments lock poisoned")
            .iter()
            .find(|c| c.id == id)
            .cloned()
    }

    async fn create_comment(&self, comment: &Comment) -> Result<(), StoreError> {
        self.comments
            .lock()
            .expect("comments lock poisoned")
            .push(comment.clone());
        Ok(())
    }

    async fn set_comment_hidden(&self, id: &str, hidden: bool) -> Result<bool, StoreError> {
        let mut comments = self.comments.lock().expect("comments lock poisoned");
        match comments.iter_mut().find(|c| c.id == id) {
            Some(c) => {
                c.hidden = hidden;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn count_comments(&self, thread_id: &str) -> i64 {
        self.comments
            .lock()
            .expect("comments lock poisoned")
            .iter()
            .filter(|c| c.thread_id == thread_id)
            .count() as i64
    }

    async fn recent_comments(&self, limit: usize) -> Vec<Comment> {
        let comments = self.comments.lock().expect("comments lock poisoned");
        let mut v: Vec<Comment> = comments.clone();
        v.sort_by(|a, b| b.created_at.cmp(&a.created_at).then_with(|| b.id.cmp(&a.id)));
        v.truncate(limit);
        v
    }
}

// --------------------------------------------------------------------------------------
// PostgreSQL-backed store (portable: standard SQL, runtime queries, no macros).
// --------------------------------------------------------------------------------------
//
// Selected at runtime by `ECHO_STORE=postgres`. Each method drives sqlx natively and the handlers
// `.await` it on the serving runtime — NO `block_in_place`, NO sync-over-async. The thread `key`
// UNIQUE constraint + `INSERT .. ON CONFLICT (key) DO NOTHING` make the upsert race-safe with no
// in-process serializer; comment inserts are independent rows, so no write lock is needed either.

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

/// PostgreSQL-backed [`Store`]. Holds just a `PgPool`.
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
            "CREATE TABLE IF NOT EXISTS threads (\
                 id TEXT PRIMARY KEY, \
                 key TEXT UNIQUE NOT NULL, \
                 title TEXT NOT NULL DEFAULT '', \
                 url TEXT NOT NULL DEFAULT '', \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS comments (\
                 id TEXT PRIMARY KEY, \
                 thread_id TEXT NOT NULL, \
                 author_sub TEXT NOT NULL, \
                 author_email TEXT NOT NULL DEFAULT '', \
                 body TEXT NOT NULL, \
                 created_at BIGINT NOT NULL, \
                 hidden BOOLEAN NOT NULL DEFAULT FALSE, \
                 parent_id TEXT NOT NULL DEFAULT ''\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Backs the per-thread oldest-first scan + the recent-activity feed.
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_comments_thread_created \
             ON comments (thread_id, created_at)",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    fn thread_from_row(row: &sqlx::postgres::PgRow) -> Result<Thread, sqlx::Error> {
        Ok(Thread {
            id: row.try_get("id")?,
            key: row.try_get("key")?,
            title: row.try_get("title")?,
            url: row.try_get("url")?,
            created_at: row.try_get("created_at")?,
        })
    }

    fn comment_from_row(row: &sqlx::postgres::PgRow) -> Result<Comment, sqlx::Error> {
        Ok(Comment {
            id: row.try_get("id")?,
            thread_id: row.try_get("thread_id")?,
            author_sub: row.try_get("author_sub")?,
            author_email: row.try_get("author_email")?,
            body: row.try_get("body")?,
            created_at: row.try_get("created_at")?,
            hidden: row.try_get("hidden")?,
            parent_id: row.try_get("parent_id")?,
        })
    }

    async fn list_threads_async(
        &self,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<Thread>, sqlx::Error> {
        let limit = clamp_page(limit);
        // Portable keyset page: the table is already ORDER BY (created_at DESC, id DESC), so the
        // cursor is simply "strictly before" that composite key. No cursor -> the newest page.
        let rows = match before {
            None => {
                sqlx::query(
                    "SELECT id, key, title, url, created_at \
                     FROM threads ORDER BY created_at DESC, id DESC LIMIT $1",
                )
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            Some((ts, id)) => {
                sqlx::query(
                    "SELECT id, key, title, url, created_at \
                     FROM threads \
                     WHERE (created_at < $1 OR (created_at = $1 AND id < $2)) \
                     ORDER BY created_at DESC, id DESC LIMIT $3",
                )
                .bind(ts)
                .bind(id)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
        };
        rows.iter().map(Self::thread_from_row).collect()
    }

    async fn get_thread_async(&self, key: &str) -> Result<Option<Thread>, sqlx::Error> {
        let row = sqlx::query("SELECT id, key, title, url, created_at FROM threads WHERE key = $1")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Ok(Some(Self::thread_from_row(&r)?)),
            None => Ok(None),
        }
    }

    async fn upsert_thread_async(&self, t: &Thread) -> Result<Thread, sqlx::Error> {
        // Race-safe insert: a concurrent poster that wins the key keeps its row; we then read the
        // canonical row back so the caller always gets a stable id.
        sqlx::query(
            "INSERT INTO threads (id, key, title, url, created_at) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (key) DO NOTHING",
        )
        .bind(&t.id)
        .bind(&t.key)
        .bind(&t.title)
        .bind(&t.url)
        .bind(t.created_at)
        .execute(&self.pool)
        .await?;
        let row = sqlx::query("SELECT id, key, title, url, created_at FROM threads WHERE key = $1")
            .bind(&t.key)
            .fetch_one(&self.pool)
            .await?;
        Self::thread_from_row(&row)
    }

    async fn list_comments_async(&self, thread_id: &str) -> Result<Vec<Comment>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, thread_id, author_sub, author_email, body, created_at, hidden, parent_id \
             FROM comments WHERE thread_id = $1 ORDER BY created_at ASC, id ASC LIMIT $2",
        )
        .bind(thread_id)
        .bind(COMMENT_LIMIT as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::comment_from_row).collect()
    }

    async fn get_comment_async(&self, id: &str) -> Result<Option<Comment>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT id, thread_id, author_sub, author_email, body, created_at, hidden, parent_id \
             FROM comments WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(r) => Ok(Some(Self::comment_from_row(&r)?)),
            None => Ok(None),
        }
    }

    async fn create_comment_async(&self, c: &Comment) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO comments \
                 (id, thread_id, author_sub, author_email, body, created_at, hidden, parent_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&c.id)
        .bind(&c.thread_id)
        .bind(&c.author_sub)
        .bind(&c.author_email)
        .bind(&c.body)
        .bind(c.created_at)
        .bind(c.hidden)
        .bind(&c.parent_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn set_comment_hidden_async(&self, id: &str, hidden: bool) -> Result<bool, sqlx::Error> {
        let res = sqlx::query("UPDATE comments SET hidden = $1 WHERE id = $2")
            .bind(hidden)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn count_comments_async(&self, thread_id: &str) -> Result<i64, sqlx::Error> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM comments WHERE thread_id = $1")
            .bind(thread_id)
            .fetch_one(&self.pool)
            .await?;
        row.try_get("n")
    }

    async fn recent_comments_async(&self, limit: usize) -> Result<Vec<Comment>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, thread_id, author_sub, author_email, body, created_at, hidden, parent_id \
             FROM comments ORDER BY created_at DESC, id DESC LIMIT $1",
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::comment_from_row).collect()
    }
}

#[async_trait]
impl Store for PgStore {
    async fn list_threads(&self, before: Option<(i64, String)>, limit: i64) -> Vec<Thread> {
        self.list_threads_async(before, limit).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg list_threads failed");
            Vec::new()
        })
    }

    async fn get_thread(&self, key: &str) -> Option<Thread> {
        self.get_thread_async(key).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg get_thread failed");
            None
        })
    }

    async fn upsert_thread(&self, thread: &Thread) -> Result<Thread, StoreError> {
        self.upsert_thread_async(thread)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_comments(&self, thread_id: &str) -> Vec<Comment> {
        self.list_comments_async(thread_id).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg list_comments failed");
            Vec::new()
        })
    }

    async fn get_comment(&self, id: &str) -> Option<Comment> {
        self.get_comment_async(id).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg get_comment failed");
            None
        })
    }

    async fn create_comment(&self, comment: &Comment) -> Result<(), StoreError> {
        self.create_comment_async(comment)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn set_comment_hidden(&self, id: &str, hidden: bool) -> Result<bool, StoreError> {
        self.set_comment_hidden_async(id, hidden)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn count_comments(&self, thread_id: &str) -> i64 {
        self.count_comments_async(thread_id).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg count_comments failed");
            0
        })
    }

    async fn recent_comments(&self, limit: usize) -> Vec<Comment> {
        self.recent_comments_async(limit).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg recent_comments failed");
            Vec::new()
        })
    }
}

// --------------------------------------------------------------------------------------
// Tests (in-memory keyset pagination — database-free).
// --------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DEFAULT_PAGE, MAX_PAGE};

    fn thread(id: &str, created_at: i64) -> Thread {
        Thread {
            id: id.to_string(),
            key: format!("k/{id}"),
            title: String::new(),
            url: String::new(),
            created_at,
        }
    }

    fn ids(v: &[Thread]) -> Vec<&str> {
        v.iter().map(|t| t.id.as_str()).collect()
    }

    // A full page walk over distinct timestamps: newest-first, cursor threads through every row.
    #[tokio::test]
    async fn list_threads_keyset_walks_all_pages() {
        let store = InMemoryStore::new();
        for (id, ts) in [("t1", 10), ("t2", 20), ("t3", 30), ("t4", 40), ("t5", 50)] {
            store.upsert_thread(&thread(id, ts)).await.unwrap();
        }

        // no cursor -> newest page.
        let page1 = store.list_threads(None, 2).await;
        assert_eq!(ids(&page1), ["t5", "t4"]);

        // cursor from the last row of page1 -> the next-older page.
        let last = page1.last().unwrap().clone();
        let page2 = store.list_threads(Some((last.created_at, last.id)), 2).await;
        assert_eq!(ids(&page2), ["t3", "t2"]);

        // final (partial) page.
        let last = page2.last().unwrap().clone();
        let page3 = store.list_threads(Some((last.created_at, last.id)), 2).await;
        assert_eq!(ids(&page3), ["t1"]);
    }

    // Ties on created_at break by id DESC, and the cursor must not skip or repeat the tie group.
    #[tokio::test]
    async fn list_threads_keyset_breaks_ties_by_id() {
        let store = InMemoryStore::new();
        for id in ["a", "b", "c"] {
            store.upsert_thread(&thread(id, 100)).await.unwrap();
        }
        // id DESC within the equal timestamp: c, b, a.
        let page1 = store.list_threads(None, 2).await;
        assert_eq!(ids(&page1), ["c", "b"]);
        let last = page1.last().unwrap().clone();
        let page2 = store.list_threads(Some((last.created_at, last.id)), 2).await;
        assert_eq!(ids(&page2), ["a"]);
    }

    // A non-positive limit defaults; an oversized one is capped.
    #[test]
    fn clamp_page_defaults_and_caps() {
        assert_eq!(clamp_page(0), DEFAULT_PAGE);
        assert_eq!(clamp_page(-5), DEFAULT_PAGE);
        assert_eq!(clamp_page(10), 10);
        assert_eq!(clamp_page(10_000), MAX_PAGE);
    }
}
