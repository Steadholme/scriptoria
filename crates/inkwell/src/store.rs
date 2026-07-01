//! Blog post storage.
//!
//! `Store` is a small async trait with an in-memory and a PostgreSQL implementation, mirroring
//! the keystone/keyward/beacon seam: handlers depend only on the trait, so a FusionDB-backed
//! store can drop in later. The PostgreSQL layer uses ONLY portable standard SQL
//! (TEXT/BIGINT/BOOLEAN, PK/UNIQUE/NOT NULL/DEFAULT, parameterized queries, an UPDATE/DELETE
//! by slug) and runtime queries (no compile-time macros), so the build needs NO database and
//! the same statements later run unchanged on FusionDB over pgwire.
//!
//! The methods are `async`: the axum handlers `.await` them directly on the serving runtime,
//! and `PgStore` drives sqlx natively — there is NO `block_in_place` and NO sync-over-async
//! bridge, so a DB round-trip never blocks a worker thread.

use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::config::MAX_PAGE;

/// A blog post (maps 1:1 to a `posts` row).
#[derive(Clone, Debug)]
pub struct Post {
    pub id: String,
    pub slug: String,
    pub title: String,
    pub body_md: String,
    pub author_sub: String,
    pub author_email: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub published: bool,
}

/// A retrieval chunk: a slice of one published post's body, indexed for the "ask your blog"
/// feature. `post_id` holds the post's slug (the stable URL key), so a citation links straight to
/// `/p/{post_id}`. Maps 1:1 to a `chunks` row.
#[derive(Clone, Debug)]
pub struct Chunk {
    pub id: String,
    pub post_id: String,
    pub title: String,
    pub body: String,
    pub indexed_at: i64,
}

/// Storage failure surfaced to the handler layer.
#[derive(Debug, Error)]
pub enum StoreError {
    /// A post with this slug already exists (the UNIQUE(slug) guard).
    #[error("slug already exists: {0}")]
    Conflict(String),
    /// Backend I/O failure (mapped to a 500).
    #[error("store error: {0}")]
    Backend(String),
}

/// Pluggable blog store.
#[async_trait]
pub trait Store: Send + Sync {
    /// One keyset page of posts, newest-first (`created_at` DESC, `id` DESC). `before` is the
    /// exclusive cursor `(created_at, id)` of the previous page's LAST row: `None` returns the
    /// newest page, `Some(..)` returns rows strictly OLDER than the cursor. `limit` is clamped to
    /// `1..=`[`MAX_PAGE`]. Visibility (published vs. own drafts) is decided in the handler from the
    /// viewer's identity; the keyset itself is exactly the `ORDER BY` the stores already use.
    async fn list_posts(&self, before: Option<(i64, String)>, limit: i64) -> Vec<Post>;
    /// One post by its unique slug.
    async fn get_post(&self, slug: &str) -> Option<Post>;
    /// Insert a new post. Errors with [`StoreError::Conflict`] if the slug is taken.
    async fn create_post(&self, post: &Post) -> Result<(), StoreError>;
    /// Update an existing post's mutable fields (title/body/published/updated_at) by slug.
    async fn update_post(&self, post: &Post) -> Result<(), StoreError>;
    /// Delete a post by slug.
    async fn delete_post(&self, slug: &str) -> Result<(), StoreError>;

    // -- "ask your blog" retrieval index (additive; see [`crate::index`]) -----------------
    //
    // The chunk table is a derived, rebuildable lexical index over the blog's OWN published
    // posts. It carries NO authoritative data: it is (re)built from `posts` on create/update and
    // lazily on the first ask, so an empty index is always self-healing.

    /// How many chunks are currently indexed (drives the lazy first-ask rebuild).
    async fn count_chunks(&self) -> i64;
    /// All indexed chunks, newest-indexed first (the ask handler ranks these in memory).
    async fn fetch_chunks(&self) -> Vec<Chunk>;
    /// Replace the ENTIRE chunk index with `chunks` (the lazy full rebuild). Returns the count.
    async fn replace_all_chunks(&self, chunks: Vec<Chunk>) -> Result<i64, StoreError>;
    /// Replace just one post's chunks: drop every chunk for `post_id`, then insert `chunks`
    /// (empty `chunks` simply de-indexes the post — e.g. when it becomes a draft).
    async fn replace_post_chunks(&self, post_id: &str, chunks: Vec<Chunk>)
        -> Result<(), StoreError>;
    /// Drop every chunk for `post_id` (on post delete).
    async fn delete_post_chunks(&self, post_id: &str) -> Result<(), StoreError>;
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

#[derive(Default)]
pub struct InMemoryStore {
    posts: Mutex<Vec<Post>>,
    chunks: Mutex<Vec<Chunk>>,
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
    async fn list_posts(&self, before: Option<(i64, String)>, limit: i64) -> Vec<Post> {
        let limit = limit.clamp(1, MAX_PAGE) as usize;
        let posts = self.posts.lock().expect("posts lock poisoned");
        let mut v: Vec<Post> = posts.clone();
        // Newest-first; ties broken by id DESC so output is stable and matches the keyset order.
        v.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.id.cmp(&a.id))
        });
        // Keyset "before" cursor: keep only rows strictly OLDER than (b_ts, b_id) — the exact
        // in-memory mirror of the SQL `created_at < $ts OR (created_at = $ts AND id < $id)`.
        if let Some((b_ts, b_id)) = before {
            v.retain(|p| p.created_at < b_ts || (p.created_at == b_ts && p.id < b_id));
        }
        v.truncate(limit);
        v
    }

    async fn get_post(&self, slug: &str) -> Option<Post> {
        self.posts
            .lock()
            .expect("posts lock poisoned")
            .iter()
            .find(|p| p.slug == slug)
            .cloned()
    }

    async fn create_post(&self, post: &Post) -> Result<(), StoreError> {
        let mut posts = self.posts.lock().expect("posts lock poisoned");
        if posts.iter().any(|p| p.slug == post.slug) {
            return Err(StoreError::Conflict(post.slug.clone()));
        }
        posts.push(post.clone());
        Ok(())
    }

    async fn update_post(&self, post: &Post) -> Result<(), StoreError> {
        let mut posts = self.posts.lock().expect("posts lock poisoned");
        match posts.iter_mut().find(|p| p.slug == post.slug) {
            Some(existing) => {
                existing.title = post.title.clone();
                existing.body_md = post.body_md.clone();
                existing.published = post.published;
                existing.updated_at = post.updated_at;
                Ok(())
            }
            None => Err(StoreError::Backend(format!("no post with slug {}", post.slug))),
        }
    }

    async fn delete_post(&self, slug: &str) -> Result<(), StoreError> {
        let mut posts = self.posts.lock().expect("posts lock poisoned");
        posts.retain(|p| p.slug != slug);
        Ok(())
    }

    async fn count_chunks(&self) -> i64 {
        self.chunks.lock().expect("chunks lock poisoned").len() as i64
    }

    async fn fetch_chunks(&self) -> Vec<Chunk> {
        let mut v: Vec<Chunk> = self.chunks.lock().expect("chunks lock poisoned").clone();
        // Newest-indexed first; ties broken by id so output is stable.
        v.sort_by(|a, b| b.indexed_at.cmp(&a.indexed_at).then_with(|| a.id.cmp(&b.id)));
        v
    }

    async fn replace_all_chunks(&self, chunks: Vec<Chunk>) -> Result<i64, StoreError> {
        let mut g = self.chunks.lock().expect("chunks lock poisoned");
        let n = chunks.len() as i64;
        *g = chunks;
        Ok(n)
    }

    async fn replace_post_chunks(
        &self,
        post_id: &str,
        chunks: Vec<Chunk>,
    ) -> Result<(), StoreError> {
        let mut g = self.chunks.lock().expect("chunks lock poisoned");
        g.retain(|c| c.post_id != post_id);
        g.extend(chunks);
        Ok(())
    }

    async fn delete_post_chunks(&self, post_id: &str) -> Result<(), StoreError> {
        self.chunks
            .lock()
            .expect("chunks lock poisoned")
            .retain(|c| c.post_id != post_id);
        Ok(())
    }
}

// --------------------------------------------------------------------------------------
// PostgreSQL-backed store (portable: standard SQL, runtime queries, no macros).
// --------------------------------------------------------------------------------------
//
// Selected at runtime by `INKWELL_STORE=postgres`. Each method drives sqlx natively and the
// handlers `.await` it on the serving runtime — NO `block_in_place`, NO sync-over-async. The
// DB enforces the slug UNIQUE constraint, so no in-process serializer is needed.

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

/// Hard cap on how many chunks the ask handler scans per query (keeps the in-memory rank bounded).
const CHUNK_SCAN_LIMIT: i64 = 20_000;

/// PostgreSQL-backed [`Store`]. Holds a `PgPool`; the async `Mutex` serializes index rebuilds so a
/// full reindex and a per-post reindex never interleave their delete/insert.
pub struct PgStore {
    pool: PgPool,
    index_lock: tokio::sync::Mutex<()>,
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
        Self {
            pool,
            index_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Idempotent, portable migration. Standard SQL only — safe to run on every startup.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS posts (\
                 id TEXT PRIMARY KEY, \
                 slug TEXT UNIQUE NOT NULL, \
                 title TEXT NOT NULL, \
                 body_md TEXT NOT NULL, \
                 author_sub TEXT NOT NULL, \
                 author_email TEXT NOT NULL, \
                 created_at BIGINT NOT NULL, \
                 updated_at BIGINT NOT NULL, \
                 published BOOLEAN NOT NULL DEFAULT TRUE\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Backs the newest-first index scan.
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_posts_created_at ON posts (created_at)")
            .execute(&self.pool)
            .await?;
        // Derived lexical index for the "ask your blog" feature — additive, rebuildable, owns no
        // authoritative data. Standard SQL only, so it runs unchanged on FusionDB over pgwire.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS chunks (\
                 id TEXT PRIMARY KEY, \
                 post_id TEXT NOT NULL, \
                 title TEXT NOT NULL, \
                 body TEXT NOT NULL, \
                 indexed_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Backs the per-post reindex (delete-by-post) and keeps citations groupable by post.
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_chunks_post_id ON chunks (post_id)")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    fn chunk_from_row(row: &sqlx::postgres::PgRow) -> Result<Chunk, sqlx::Error> {
        Ok(Chunk {
            id: row.try_get("id")?,
            post_id: row.try_get("post_id")?,
            title: row.try_get("title")?,
            body: row.try_get("body")?,
            indexed_at: row.try_get("indexed_at")?,
        })
    }

    async fn count_chunks_async(&self) -> Result<i64, sqlx::Error> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM chunks")
            .fetch_one(&self.pool)
            .await?;
        row.try_get("n")
    }

    async fn fetch_chunks_async(&self) -> Result<Vec<Chunk>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, post_id, title, body, indexed_at \
             FROM chunks ORDER BY indexed_at DESC, id ASC LIMIT $1",
        )
        .bind(CHUNK_SCAN_LIMIT)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::chunk_from_row).collect()
    }

    async fn insert_chunk(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        c: &Chunk,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO chunks (id, post_id, title, body, indexed_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (id) DO UPDATE SET \
                 post_id = EXCLUDED.post_id, title = EXCLUDED.title, \
                 body = EXCLUDED.body, indexed_at = EXCLUDED.indexed_at",
        )
        .bind(&c.id)
        .bind(&c.post_id)
        .bind(&c.title)
        .bind(&c.body)
        .bind(c.indexed_at)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    async fn replace_all_chunks_async(&self, chunks: Vec<Chunk>) -> Result<i64, sqlx::Error> {
        let _guard = self.index_lock.lock().await;
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM chunks").execute(&mut *tx).await?;
        for c in &chunks {
            Self::insert_chunk(&mut tx, c).await?;
        }
        tx.commit().await?;
        Ok(chunks.len() as i64)
    }

    async fn replace_post_chunks_async(
        &self,
        post_id: &str,
        chunks: Vec<Chunk>,
    ) -> Result<(), sqlx::Error> {
        let _guard = self.index_lock.lock().await;
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM chunks WHERE post_id = $1")
            .bind(post_id)
            .execute(&mut *tx)
            .await?;
        for c in &chunks {
            Self::insert_chunk(&mut tx, c).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn delete_post_chunks_async(&self, post_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM chunks WHERE post_id = $1")
            .bind(post_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    fn post_from_row(row: &sqlx::postgres::PgRow) -> Result<Post, sqlx::Error> {
        Ok(Post {
            id: row.try_get("id")?,
            slug: row.try_get("slug")?,
            title: row.try_get("title")?,
            body_md: row.try_get("body_md")?,
            author_sub: row.try_get("author_sub")?,
            author_email: row.try_get("author_email")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
            published: row.try_get("published")?,
        })
    }

    async fn list_posts_async(
        &self,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<Post>, sqlx::Error> {
        let limit = limit.clamp(1, MAX_PAGE);
        const COLS: &str = "SELECT id, slug, title, body_md, author_sub, author_email, \
                            created_at, updated_at, published FROM posts";
        // The `ORDER BY created_at DESC, id DESC` IS the keyset. With a cursor, add the standard
        // "strictly older" tuple comparison before the ORDER BY so paging never skips a tie.
        let rows = match before {
            None => {
                sqlx::query(&format!("{COLS} ORDER BY created_at DESC, id DESC LIMIT $1"))
                    .bind(limit)
                    .fetch_all(&self.pool)
                    .await?
            }
            Some((b_ts, b_id)) => {
                sqlx::query(&format!(
                    "{COLS} WHERE (created_at < $1 OR (created_at = $1 AND id < $2)) \
                     ORDER BY created_at DESC, id DESC LIMIT $3"
                ))
                .bind(b_ts)
                .bind(b_id)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
        };
        rows.iter().map(Self::post_from_row).collect()
    }

    async fn get_post_async(&self, slug: &str) -> Result<Option<Post>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT id, slug, title, body_md, author_sub, author_email, created_at, updated_at, \
                    published \
             FROM posts WHERE slug = $1",
        )
        .bind(slug)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(r) => Ok(Some(Self::post_from_row(&r)?)),
            None => Ok(None),
        }
    }

    async fn create_post_async(&self, p: &Post) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO posts \
                 (id, slug, title, body_md, author_sub, author_email, created_at, updated_at, \
                  published) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(&p.id)
        .bind(&p.slug)
        .bind(&p.title)
        .bind(&p.body_md)
        .bind(&p.author_sub)
        .bind(&p.author_email)
        .bind(p.created_at)
        .bind(p.updated_at)
        .bind(p.published)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn update_post_async(&self, p: &Post) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE posts SET title = $1, body_md = $2, published = $3, updated_at = $4 \
             WHERE slug = $5",
        )
        .bind(&p.title)
        .bind(&p.body_md)
        .bind(p.published)
        .bind(p.updated_at)
        .bind(&p.slug)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn delete_post_async(&self, slug: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM posts WHERE slug = $1")
            .bind(slug)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

/// True when a sqlx error is a UNIQUE/PK violation (Postgres SQLSTATE 23505) — the slug clash.
fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}

#[async_trait]
impl Store for PgStore {
    async fn list_posts(&self, before: Option<(i64, String)>, limit: i64) -> Vec<Post> {
        self.list_posts_async(before, limit).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg list_posts failed");
            Vec::new()
        })
    }

    async fn get_post(&self, slug: &str) -> Option<Post> {
        self.get_post_async(slug).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg get_post failed");
            None
        })
    }

    async fn create_post(&self, post: &Post) -> Result<(), StoreError> {
        self.create_post_async(post).await.map_err(|e| {
            if is_unique_violation(&e) {
                StoreError::Conflict(post.slug.clone())
            } else {
                StoreError::Backend(e.to_string())
            }
        })
    }

    async fn update_post(&self, post: &Post) -> Result<(), StoreError> {
        self.update_post_async(post)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn delete_post(&self, slug: &str) -> Result<(), StoreError> {
        self.delete_post_async(slug)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn count_chunks(&self) -> i64 {
        self.count_chunks_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg count_chunks failed");
            0
        })
    }

    async fn fetch_chunks(&self) -> Vec<Chunk> {
        self.fetch_chunks_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg fetch_chunks failed");
            Vec::new()
        })
    }

    async fn replace_all_chunks(&self, chunks: Vec<Chunk>) -> Result<i64, StoreError> {
        self.replace_all_chunks_async(chunks)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn replace_post_chunks(
        &self,
        post_id: &str,
        chunks: Vec<Chunk>,
    ) -> Result<(), StoreError> {
        self.replace_post_chunks_async(post_id, chunks)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn delete_post_chunks(&self, post_id: &str) -> Result<(), StoreError> {
        self.delete_post_chunks_async(post_id)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MAX_PAGE;

    fn post(id: &str, created_at: i64) -> Post {
        Post {
            id: id.to_string(),
            slug: id.to_string(),
            title: id.to_string(),
            body_md: String::new(),
            author_sub: "u".to_string(),
            author_email: "u@hf".to_string(),
            created_at,
            updated_at: created_at,
            published: true,
        }
    }

    /// Newest page first, then the `before` cursor pages strictly backward until exhausted — the
    /// whole archive is reachable page by page even past a single page's `limit`.
    #[tokio::test]
    async fn list_posts_keyset_pages_backward() {
        let store = InMemoryStore::new();
        for i in 1..=5 {
            store.create_post(&post(&format!("post_{i}"), i)).await.unwrap();
        }

        let page1 = store.list_posts(None, 2).await;
        assert_eq!(page1.iter().map(|p| p.created_at).collect::<Vec<_>>(), vec![5, 4]);

        let last = page1.last().unwrap();
        let page2 = store.list_posts(Some((last.created_at, last.id.clone())), 2).await;
        assert_eq!(page2.iter().map(|p| p.created_at).collect::<Vec<_>>(), vec![3, 2]);

        let last = page2.last().unwrap();
        let page3 = store.list_posts(Some((last.created_at, last.id.clone())), 2).await;
        assert_eq!(page3.iter().map(|p| p.created_at).collect::<Vec<_>>(), vec![1]);

        // Past the end: nothing older than the last row.
        let last = page3.last().unwrap();
        let page4 = store.list_posts(Some((last.created_at, last.id.clone())), 2).await;
        assert!(page4.is_empty(), "no rows older than the oldest post");
    }

    /// Ties on `created_at` are broken by `id DESC`, and the cursor's id component keeps paging
    /// strict (never re-emits the cursor row, never skips a tie).
    #[tokio::test]
    async fn list_posts_cursor_breaks_ties_by_id() {
        let store = InMemoryStore::new();
        for id in ["post_a", "post_b", "post_c"] {
            store.create_post(&post(id, 10)).await.unwrap();
        }
        let all = store.list_posts(None, 10).await;
        assert_eq!(
            all.iter().map(|p| p.id.as_str()).collect::<Vec<_>>(),
            vec!["post_c", "post_b", "post_a"],
        );
        let page = store.list_posts(Some((10, "post_c".to_string())), 10).await;
        assert_eq!(
            page.iter().map(|p| p.id.as_str()).collect::<Vec<_>>(),
            vec!["post_b", "post_a"],
        );
    }

    /// A caller asking for more than [`MAX_PAGE`] rows is clamped, so a single page stays bounded.
    #[tokio::test]
    async fn list_posts_clamps_limit_to_max() {
        let store = InMemoryStore::new();
        for i in 0..(MAX_PAGE + 10) {
            store.create_post(&post(&format!("post_{i:05}"), i)).await.unwrap();
        }
        let page = store.list_posts(None, MAX_PAGE + 100).await;
        assert_eq!(page.len() as i64, MAX_PAGE, "limit clamped to MAX_PAGE");
    }
}
