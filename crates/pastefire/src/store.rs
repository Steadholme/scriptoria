//! Paste storage.
//!
//! `Store` is a small async trait with an in-memory and a PostgreSQL implementation, mirroring
//! the keystone/keyward/watchtower seam: handlers depend only on the trait, so a FusionDB-backed
//! store can drop in later. The PostgreSQL layer uses ONLY portable standard SQL
//! (TEXT/BIGINT, PRIMARY KEY/NOT NULL, parameterized queries, `INSERT .. ON CONFLICT`, a plain
//! index) and runtime queries (no compile-time macros), so the build needs NO database and the
//! same statements later run unchanged on FusionDB over pgwire.
//!
//! The trait is async: the axum handlers `.await` it directly on the serving runtime, and
//! `PgStore` drives sqlx natively — there is NO `block_in_place` and NO sync-over-async bridge.

use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::config::RECENT_LIMIT;
use crate::model::Paste;

/// Storage failure surfaced to the handler layer (mapped to a 500 `server_error`).
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store error: {0}")]
    Backend(String),
}

/// Pluggable paste store. `create` is collision-aware (returns `false` when the id already
/// exists, so the handler retries with a fresh id); `delete` is ownership-scoped (only the
/// author's own row is removed).
#[async_trait]
pub trait Store: Send + Sync {
    /// Insert a paste. Returns `Ok(true)` when inserted, `Ok(false)` when the id already
    /// existed (the caller retries with a new id). Idempotent at the id level.
    async fn create(&self, paste: &Paste) -> Result<bool, StoreError>;

    /// Fetch a paste by id (no expiry filtering — the caller decides how to present an expired
    /// paste, so `/p` and `/raw` share one expiry definition).
    async fn get(&self, id: &str) -> Result<Option<Paste>, StoreError>;

    /// An author's own non-expired pastes, newest-first, capped at [`RECENT_LIMIT`]. `now` is
    /// epoch seconds; expired rows are excluded at the source so both stores agree.
    async fn list_by_author(&self, author_sub: &str, now: i64) -> Result<Vec<Paste>, StoreError>;

    /// Delete a paste only if it belongs to `author_sub`. Returns `true` when a row was
    /// removed (existed AND owned), `false` otherwise.
    async fn delete(&self, id: &str, author_sub: &str) -> Result<bool, StoreError>;

    /// Candidate pool for the "similar pastes" panel: an author's own non-expired,
    /// non-burn pastes, newest-first, capped at `limit`. Burn pastes are excluded because
    /// they are single-read and must not be surfaced as suggestions. `now` is epoch seconds;
    /// expired rows are filtered at the source so both stores agree.
    async fn list_for_similarity(
        &self,
        author_sub: &str,
        now: i64,
        limit: i64,
    ) -> Result<Vec<Paste>, StoreError>;
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

/// In-memory `Store`. The `Mutex<Vec<_>>` critical sections are fully synchronous (no `.await`
/// held across the guard), so the std `Mutex` is correct here.
#[derive(Default)]
pub struct InMemoryStore {
    pastes: Mutex<Vec<Paste>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for InMemoryStore {
    async fn create(&self, paste: &Paste) -> Result<bool, StoreError> {
        let mut pastes = self.pastes.lock().expect("pastes lock poisoned");
        if pastes.iter().any(|p| p.id == paste.id) {
            return Ok(false);
        }
        pastes.push(paste.clone());
        Ok(true)
    }

    async fn get(&self, id: &str) -> Result<Option<Paste>, StoreError> {
        let pastes = self.pastes.lock().expect("pastes lock poisoned");
        Ok(pastes.iter().find(|p| p.id == id).cloned())
    }

    async fn list_by_author(&self, author_sub: &str, now: i64) -> Result<Vec<Paste>, StoreError> {
        let pastes = self.pastes.lock().expect("pastes lock poisoned");
        let mut out: Vec<Paste> = pastes
            .iter()
            .filter(|p| p.author_sub == author_sub && !p.is_expired(now))
            .cloned()
            .collect();
        // Newest first; id as a deterministic tiebreak when created_at collides (same second).
        out.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.id.cmp(&a.id))
        });
        out.truncate(RECENT_LIMIT);
        Ok(out)
    }

    async fn delete(&self, id: &str, author_sub: &str) -> Result<bool, StoreError> {
        let mut pastes = self.pastes.lock().expect("pastes lock poisoned");
        let before = pastes.len();
        pastes.retain(|p| !(p.id == id && p.author_sub == author_sub));
        Ok(pastes.len() != before)
    }

    async fn list_for_similarity(
        &self,
        author_sub: &str,
        now: i64,
        limit: i64,
    ) -> Result<Vec<Paste>, StoreError> {
        let pastes = self.pastes.lock().expect("pastes lock poisoned");
        let mut out: Vec<Paste> = pastes
            .iter()
            .filter(|p| {
                p.author_sub == author_sub && !p.is_expired(now) && !p.burn_after_read
            })
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.id.cmp(&a.id))
        });
        out.truncate(limit.max(0) as usize);
        Ok(out)
    }
}

// --------------------------------------------------------------------------------------
// PostgreSQL-backed store (portable: standard SQL, runtime queries, no macros).
// --------------------------------------------------------------------------------------
//
// Selected at runtime by `PASTEFIRE_STORE=postgres`. The `Store` trait is async, so each method
// uses sqlx natively and the handlers `.await` it on the serving runtime — there is NO
// `block_in_place` and NO sync-over-async, so a query never blocks a worker thread.

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

/// Column list shared by every SELECT, so the row decoder stays in lock-step with the query.
const COLS: &str =
    "id, title, body, language, author_sub, author_email, created_at, expires_at, burn_after_read";

/// PostgreSQL-backed [`Store`]. Holds a pooled connection; the async trait methods drive sqlx
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
    /// `expires_at` is the only nullable column (NULL = never expires). The composite index
    /// backs the "my recent pastes" lookup (`author_sub` filter + `created_at` ordering).
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS pastes (\
                 id TEXT PRIMARY KEY, \
                 title TEXT NOT NULL, \
                 body TEXT NOT NULL, \
                 language TEXT NOT NULL, \
                 author_sub TEXT NOT NULL, \
                 author_email TEXT NOT NULL, \
                 created_at BIGINT NOT NULL, \
                 expires_at BIGINT\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Additive, idempotent column for burn-after-read. Pre-existing rows default to false
        // (their current "persists" behavior). Standard SQL only — portable to FusionDB.
        sqlx::query(
            "ALTER TABLE pastes ADD COLUMN IF NOT EXISTS \
             burn_after_read BOOLEAN NOT NULL DEFAULT false",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_pastes_author_created \
             ON pastes (author_sub, created_at)",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    fn paste_from_row(row: &sqlx::postgres::PgRow) -> Result<Paste, sqlx::Error> {
        Ok(Paste {
            id: row.try_get("id")?,
            title: row.try_get("title")?,
            body: row.try_get("body")?,
            language: row.try_get("language")?,
            author_sub: row.try_get("author_sub")?,
            author_email: row.try_get("author_email")?,
            created_at: row.try_get("created_at")?,
            expires_at: row.try_get("expires_at")?,
            burn_after_read: row.try_get("burn_after_read")?,
        })
    }

    async fn create_async(&self, paste: &Paste) -> Result<bool, sqlx::Error> {
        // ON CONFLICT DO NOTHING => 0 rows affected signals an id collision; the handler then
        // retries with a fresh id. This is the single, race-free insert path.
        let result = sqlx::query(
            "INSERT INTO pastes \
                 (id, title, body, language, author_sub, author_email, created_at, expires_at, \
                  burn_after_read) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&paste.id)
        .bind(&paste.title)
        .bind(&paste.body)
        .bind(&paste.language)
        .bind(&paste.author_sub)
        .bind(&paste.author_email)
        .bind(paste.created_at)
        .bind(paste.expires_at)
        .bind(paste.burn_after_read)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn get_async(&self, id: &str) -> Result<Option<Paste>, sqlx::Error> {
        let row = sqlx::query(&format!("SELECT {COLS} FROM pastes WHERE id = $1"))
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(Self::paste_from_row).transpose()
    }

    async fn list_by_author_async(
        &self,
        author_sub: &str,
        now: i64,
    ) -> Result<Vec<Paste>, sqlx::Error> {
        let rows = sqlx::query(&format!(
            "SELECT {COLS} FROM pastes \
             WHERE author_sub = $1 AND (expires_at IS NULL OR expires_at > $2) \
             ORDER BY created_at DESC LIMIT $3"
        ))
        .bind(author_sub)
        .bind(now)
        .bind(RECENT_LIMIT as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::paste_from_row).collect()
    }

    async fn delete_async(&self, id: &str, author_sub: &str) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM pastes WHERE id = $1 AND author_sub = $2")
            .bind(id)
            .bind(author_sub)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_for_similarity_async(
        &self,
        author_sub: &str,
        now: i64,
        limit: i64,
    ) -> Result<Vec<Paste>, sqlx::Error> {
        let rows = sqlx::query(&format!(
            "SELECT {COLS} FROM pastes \
             WHERE author_sub = $1 AND (expires_at IS NULL OR expires_at > $2) \
               AND burn_after_read = false \
             ORDER BY created_at DESC LIMIT $3"
        ))
        .bind(author_sub)
        .bind(now)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::paste_from_row).collect()
    }
}

#[async_trait]
impl Store for PgStore {
    async fn create(&self, paste: &Paste) -> Result<bool, StoreError> {
        self.create_async(paste)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get(&self, id: &str) -> Result<Option<Paste>, StoreError> {
        self.get_async(id)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_by_author(&self, author_sub: &str, now: i64) -> Result<Vec<Paste>, StoreError> {
        self.list_by_author_async(author_sub, now)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn delete(&self, id: &str, author_sub: &str) -> Result<bool, StoreError> {
        self.delete_async(id, author_sub)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_for_similarity(
        &self,
        author_sub: &str,
        now: i64,
        limit: i64,
    ) -> Result<Vec<Paste>, StoreError> {
        self.list_for_similarity_async(author_sub, now, limit)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paste(id: &str, author: &str, created_at: i64, expires_at: Option<i64>) -> Paste {
        Paste {
            id: id.into(),
            title: "t".into(),
            body: "b".into(),
            language: "plaintext".into(),
            author_sub: author.into(),
            author_email: "e@x".into(),
            created_at,
            expires_at,
            burn_after_read: false,
        }
    }

    fn burn_paste(id: &str, author: &str, created_at: i64) -> Paste {
        Paste {
            burn_after_read: true,
            ..paste(id, author, created_at, None)
        }
    }

    #[tokio::test]
    async fn create_is_collision_aware() {
        let s = InMemoryStore::new();
        assert!(s.create(&paste("a", "u", 1, None)).await.unwrap());
        assert!(!s.create(&paste("a", "u", 2, None)).await.unwrap());
    }

    #[tokio::test]
    async fn recent_excludes_expired_and_other_authors() {
        let s = InMemoryStore::new();
        s.create(&paste("a", "u", 10, None)).await.unwrap();
        s.create(&paste("b", "u", 20, Some(100))).await.unwrap(); // expired at now=200
        s.create(&paste("c", "u", 30, Some(999))).await.unwrap();
        s.create(&paste("d", "other", 40, None)).await.unwrap();
        let recent = s.list_by_author("u", 200).await.unwrap();
        let ids: Vec<&str> = recent.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["c", "a"]); // newest-first, expired + other author excluded
    }

    #[tokio::test]
    async fn delete_is_ownership_scoped() {
        let s = InMemoryStore::new();
        s.create(&paste("a", "u", 1, None)).await.unwrap();
        assert!(!s.delete("a", "intruder").await.unwrap());
        assert!(s.get("a").await.unwrap().is_some());
        assert!(s.delete("a", "u").await.unwrap());
        assert!(s.get("a").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn similarity_pool_excludes_expired_burn_and_other_authors() {
        let s = InMemoryStore::new();
        s.create(&paste("a", "u", 10, None)).await.unwrap();
        s.create(&paste("b", "u", 20, Some(100))).await.unwrap(); // expired at now=200
        s.create(&burn_paste("c", "u", 30)).await.unwrap(); // burn -> excluded
        s.create(&paste("d", "u", 40, None)).await.unwrap();
        s.create(&paste("e", "other", 50, None)).await.unwrap(); // other author
        let pool = s.list_for_similarity("u", 200, 100).await.unwrap();
        let ids: Vec<&str> = pool.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["d", "a"]); // newest-first; expired, burn, other-author dropped
    }
}
