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

use crate::model::{Category, Post, Thread, ThreadDigest};

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
    /// All posts in a thread, oldest first (original post first, then replies).
    async fn posts_in_thread(&self, thread_id: &str) -> Result<Vec<Post>, StoreError>;

    /// Create a thread together with its original post, atomically.
    async fn create_thread(&self, thread: &Thread, first_post: &Post) -> Result<(), StoreError>;
    /// Append a reply and bump the parent thread's `last_at` to the reply's timestamp.
    async fn add_reply(&self, post: &Post) -> Result<(), StoreError>;
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

#[derive(Default)]
pub struct InMemoryStore {
    categories: Mutex<Vec<Category>>,
    threads: Mutex<Vec<Thread>>,
    posts: Mutex<Vec<Post>>,
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

    async fn recent_threads(&self, limit: i64) -> Result<Vec<Thread>, StoreError> {
        let mut v: Vec<Thread> = self.threads.lock().expect("threads lock poisoned").clone();
        v.sort_by(|a, b| b.last_at.cmp(&a.last_at).then_with(|| b.created_at.cmp(&a.created_at)));
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
        v.sort_by(|a, b| b.last_at.cmp(&a.last_at).then_with(|| b.created_at.cmp(&a.created_at)));
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
        "id, category_id, title, author_sub, author_email, created_at, last_at";
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

    async fn recent_threads_async(&self, limit: i64) -> Result<Vec<Thread>, sqlx::Error> {
        let sql = format!(
            "SELECT {} FROM threads ORDER BY last_at DESC, created_at DESC LIMIT $1",
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
            "SELECT {} FROM threads WHERE category_id = $1 ORDER BY last_at DESC, created_at DESC LIMIT $2",
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
                 (id, category_id, title, author_sub, author_email, created_at, last_at, first_body_md) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&thread.id)
        .bind(&thread.category_id)
        .bind(&thread.title)
        .bind(&thread.author_sub)
        .bind(&thread.author_email)
        .bind(thread.created_at)
        .bind(thread.last_at)
        .bind(&first_post.body_md)
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
}

/// Map an sqlx error into a [`StoreError`].
fn backend(e: sqlx::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}
