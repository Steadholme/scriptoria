//! File metadata storage.
//!
//! `Store` is a small async trait with an in-memory and a PostgreSQL implementation, mirroring
//! the keystone/pastefire seam: handlers depend only on the trait. The PostgreSQL layer uses ONLY
//! portable standard SQL (TEXT/BIGINT, PRIMARY KEY/UNIQUE/NOT NULL, parameterized queries,
//! `INSERT .. ON CONFLICT`, plain indexes) and runtime queries (no compile-time macros), so the
//! build needs NO database and the same statements later run unchanged on FusionDB over pgwire.
//!
//! The trait is async: the axum handlers `.await` it directly on the serving runtime, and
//! `PgStore` drives sqlx natively — there is NO `block_in_place` and NO sync-over-async bridge.

use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::model::FileRec;

/// Storage failure surfaced to the handler layer (mapped to a 500 `server_error`).
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store error: {0}")]
    Backend(String),
}

/// Pluggable metadata store. `create` is collision-aware over BOTH the id and the share token
/// (returns `false` on any unique conflict so the handler retries with fresh values); `delete`
/// is ownership-scoped.
#[async_trait]
pub trait Store: Send + Sync {
    /// Insert a file row. Returns `Ok(true)` when inserted, `Ok(false)` when a unique value
    /// (id or share token) already existed (the caller retries with fresh values).
    async fn create(&self, file: &FileRec) -> Result<bool, StoreError>;

    /// Fetch a file by id.
    async fn get(&self, id: &str) -> Result<Option<FileRec>, StoreError>;

    /// Fetch a file by its public share token (the unauthenticated `/s/{token}` path).
    async fn get_by_token(&self, token: &str) -> Result<Option<FileRec>, StoreError>;

    /// An owner's files, newest-first.
    async fn list_by_owner(&self, owner_sub: &str) -> Result<Vec<FileRec>, StoreError>;

    /// Delete a file only if it belongs to `owner_sub`. Returns `true` when a row was removed.
    async fn delete(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError>;
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

/// In-memory `Store`. The `Mutex<Vec<_>>` critical sections are fully synchronous (no `.await`
/// held across the guard), so the std `Mutex` is correct here.
#[derive(Default)]
pub struct InMemoryStore {
    files: Mutex<Vec<FileRec>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for InMemoryStore {
    async fn create(&self, file: &FileRec) -> Result<bool, StoreError> {
        let mut files = self.files.lock().expect("files lock poisoned");
        // Reject on any unique conflict (id OR share token), matching the Postgres constraints.
        if files
            .iter()
            .any(|f| f.id == file.id || f.share_token == file.share_token)
        {
            return Ok(false);
        }
        files.push(file.clone());
        Ok(true)
    }

    async fn get(&self, id: &str) -> Result<Option<FileRec>, StoreError> {
        let files = self.files.lock().expect("files lock poisoned");
        Ok(files.iter().find(|f| f.id == id).cloned())
    }

    async fn get_by_token(&self, token: &str) -> Result<Option<FileRec>, StoreError> {
        let files = self.files.lock().expect("files lock poisoned");
        Ok(files.iter().find(|f| f.share_token == token).cloned())
    }

    async fn list_by_owner(&self, owner_sub: &str) -> Result<Vec<FileRec>, StoreError> {
        let files = self.files.lock().expect("files lock poisoned");
        let mut out: Vec<FileRec> = files
            .iter()
            .filter(|f| f.owner_sub == owner_sub)
            .cloned()
            .collect();
        // Newest first; id as a deterministic tiebreak when created_at collides (same second).
        out.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.id.cmp(&a.id))
        });
        Ok(out)
    }

    async fn delete(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError> {
        let mut files = self.files.lock().expect("files lock poisoned");
        let before = files.len();
        files.retain(|f| !(f.id == id && f.owner_sub == owner_sub));
        Ok(files.len() != before)
    }
}

// --------------------------------------------------------------------------------------
// PostgreSQL-backed store (portable: standard SQL, runtime queries, no macros).
// --------------------------------------------------------------------------------------
//
// Selected at runtime by `APERTURE_STORE=postgres`. The `Store` trait is async, so each method
// uses sqlx natively and the handlers `.await` it on the serving runtime — there is NO
// `block_in_place` and NO sync-over-async, so a query never blocks a worker thread.

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

/// Column list shared by every SELECT, so the row decoder stays in lock-step with the query.
const COLS: &str =
    "id, owner_sub, name, content_type, size, bucket, object_key, share_token, created_at";

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

    /// Idempotent, portable migration. Standard SQL only — safe to run on every startup. The
    /// composite index backs the gallery lookup (`owner_sub` filter + `created_at` ordering); the
    /// share token gets its own unique index for the `/s/{token}` fetch.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS files (\
                 id TEXT PRIMARY KEY, \
                 owner_sub TEXT NOT NULL, \
                 name TEXT NOT NULL, \
                 content_type TEXT NOT NULL, \
                 size BIGINT NOT NULL, \
                 bucket TEXT NOT NULL, \
                 object_key TEXT NOT NULL, \
                 share_token TEXT NOT NULL UNIQUE, \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_files_owner_created \
             ON files (owner_sub, created_at)",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    fn file_from_row(row: &sqlx::postgres::PgRow) -> Result<FileRec, sqlx::Error> {
        Ok(FileRec {
            id: row.try_get("id")?,
            owner_sub: row.try_get("owner_sub")?,
            name: row.try_get("name")?,
            content_type: row.try_get("content_type")?,
            size: row.try_get("size")?,
            bucket: row.try_get("bucket")?,
            object_key: row.try_get("object_key")?,
            share_token: row.try_get("share_token")?,
            created_at: row.try_get("created_at")?,
        })
    }

    async fn create_async(&self, file: &FileRec) -> Result<bool, sqlx::Error> {
        // No conflict target => any unique violation (id OR share_token) yields 0 rows affected,
        // signaling the handler to retry with fresh values. Single, race-free insert path.
        let result = sqlx::query(
            "INSERT INTO files \
                 (id, owner_sub, name, content_type, size, bucket, object_key, share_token, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT DO NOTHING",
        )
        .bind(&file.id)
        .bind(&file.owner_sub)
        .bind(&file.name)
        .bind(&file.content_type)
        .bind(file.size)
        .bind(&file.bucket)
        .bind(&file.object_key)
        .bind(&file.share_token)
        .bind(file.created_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn get_async(&self, id: &str) -> Result<Option<FileRec>, sqlx::Error> {
        let row = sqlx::query(&format!("SELECT {COLS} FROM files WHERE id = $1"))
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(Self::file_from_row).transpose()
    }

    async fn get_by_token_async(&self, token: &str) -> Result<Option<FileRec>, sqlx::Error> {
        let row = sqlx::query(&format!("SELECT {COLS} FROM files WHERE share_token = $1"))
            .bind(token)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(Self::file_from_row).transpose()
    }

    async fn list_by_owner_async(&self, owner_sub: &str) -> Result<Vec<FileRec>, sqlx::Error> {
        let rows = sqlx::query(&format!(
            "SELECT {COLS} FROM files WHERE owner_sub = $1 ORDER BY created_at DESC, id DESC"
        ))
        .bind(owner_sub)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::file_from_row).collect()
    }

    async fn delete_async(&self, id: &str, owner_sub: &str) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM files WHERE id = $1 AND owner_sub = $2")
            .bind(id)
            .bind(owner_sub)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[async_trait]
impl Store for PgStore {
    async fn create(&self, file: &FileRec) -> Result<bool, StoreError> {
        self.create_async(file)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get(&self, id: &str) -> Result<Option<FileRec>, StoreError> {
        self.get_async(id)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get_by_token(&self, token: &str) -> Result<Option<FileRec>, StoreError> {
        self.get_by_token_async(token)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_by_owner(&self, owner_sub: &str) -> Result<Vec<FileRec>, StoreError> {
        self.list_by_owner_async(owner_sub)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn delete(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError> {
        self.delete_async(id, owner_sub)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(id: &str, owner: &str, token: &str, created_at: i64) -> FileRec {
        FileRec {
            id: id.into(),
            owner_sub: owner.into(),
            name: format!("{id}.png"),
            content_type: "image/png".into(),
            size: 3,
            bucket: "memory".into(),
            object_key: id.into(),
            share_token: token.into(),
            created_at,
        }
    }

    #[tokio::test]
    async fn create_is_collision_aware_over_id_and_token() {
        let s = InMemoryStore::new();
        assert!(s.create(&file("a", "u", "tok-a", 1)).await.unwrap());
        // Same id -> conflict.
        assert!(!s.create(&file("a", "u", "tok-b", 2)).await.unwrap());
        // Same token -> conflict.
        assert!(!s.create(&file("b", "u", "tok-a", 3)).await.unwrap());
        assert!(s.create(&file("b", "u", "tok-b", 3)).await.unwrap());
    }

    #[tokio::test]
    async fn list_is_owner_scoped_newest_first() {
        let s = InMemoryStore::new();
        s.create(&file("a", "u", "t1", 10)).await.unwrap();
        s.create(&file("c", "u", "t3", 30)).await.unwrap();
        s.create(&file("d", "other", "t4", 40)).await.unwrap();
        let mine = s.list_by_owner("u").await.unwrap();
        let ids: Vec<&str> = mine.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, vec!["c", "a"]);
    }

    #[tokio::test]
    async fn get_by_token_and_ownership_scoped_delete() {
        let s = InMemoryStore::new();
        s.create(&file("a", "u", "secret-tok", 1)).await.unwrap();
        assert_eq!(s.get_by_token("secret-tok").await.unwrap().unwrap().id, "a");
        assert!(s.get_by_token("nope").await.unwrap().is_none());
        assert!(!s.delete("a", "intruder").await.unwrap());
        assert!(s.get("a").await.unwrap().is_some());
        assert!(s.delete("a", "u").await.unwrap());
        assert!(s.get("a").await.unwrap().is_none());
    }
}
