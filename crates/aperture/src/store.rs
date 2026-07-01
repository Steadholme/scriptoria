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

use crate::config::clamp_page;
use crate::model::{FileRec, FolderRec};

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

    /// An owner's files, newest-first, one keyset page at a time.
    ///
    /// `folder` filters the view: `None` is the flat "all files" view (every file the owner has,
    /// regardless of folder — the default), while `Some(id)` returns only the files whose
    /// `folder_id` equals that folder. Ordering is the fixed keyset `(created_at DESC, id DESC)`.
    /// `before` is the exclusive `(created_at, id)` cursor of the last row already seen — pass
    /// `None` for the newest page, or the previous page's last (oldest) row to page BACKWARD into
    /// older files. `limit` is clamped to `[1, MAX_PAGE]` (see [`crate::config::clamp_page`]) so the
    /// read is always bounded.
    async fn list_by_owner(
        &self,
        owner_sub: &str,
        folder: Option<&str>,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<FileRec>, StoreError>;

    /// Delete a file only if it belongs to `owner_sub`. Returns `true` when a row was removed.
    async fn delete(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError>;

    /// Configure a file's share link, ownership-scoped. Sets all three share columns atomically:
    /// `share_token` (`Some(tok)` to (re)enable, `None` to REVOKE — the file then has no public
    /// surface), `expires_at` (`None` = never), and `share_password_hash` (`None` = no password).
    /// Returns `true` when the owner's row was updated. Callers pass a freshly-random token, so the
    /// `UNIQUE(share_token)` constraint is not a practical concern; multiple revoked (`NULL`) rows
    /// coexist because SQL treats NULLs as distinct.
    async fn configure_share(
        &self,
        id: &str,
        owner_sub: &str,
        share_token: Option<String>,
        expires_at: Option<i64>,
        share_password_hash: Option<String>,
    ) -> Result<bool, StoreError>;

    /// Insert a folder row. Returns `Ok(true)` when inserted, `Ok(false)` when the id already
    /// existed (the caller retries with a fresh id).
    async fn create_folder(&self, folder: &FolderRec) -> Result<bool, StoreError>;

    /// An owner's folders, name-ordered (case-insensitive, id tiebreak) for a stable sidebar.
    async fn list_folders(&self, owner_sub: &str) -> Result<Vec<FolderRec>, StoreError>;

    /// Fetch one folder, ownership-scoped (used to validate a move target and to render the active
    /// folder's controls). `None` when it does not exist or belongs to someone else.
    async fn get_folder(&self, id: &str, owner_sub: &str)
        -> Result<Option<FolderRec>, StoreError>;

    /// Rename a folder only if it belongs to `owner_sub`. Returns `true` when a row was updated.
    async fn rename_folder(
        &self,
        id: &str,
        owner_sub: &str,
        name: &str,
    ) -> Result<bool, StoreError>;

    /// Delete a folder only if it belongs to `owner_sub`, first UNFILING its files (their
    /// `folder_id` is cleared to `NULL`) so no file is orphaned. Returns `true` when the folder row
    /// was removed.
    async fn delete_folder(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError>;

    /// Move a file into a folder (`Some(folder_id)`) or back to the root/unfiled view (`None`),
    /// ownership-scoped. The caller validates that a `Some` target folder belongs to the owner.
    /// Returns `true` when the owner's file row was updated.
    async fn move_file(
        &self,
        id: &str,
        owner_sub: &str,
        folder_id: Option<&str>,
    ) -> Result<bool, StoreError>;
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

/// In-memory `Store`. The `Mutex<Vec<_>>` critical sections are fully synchronous (no `.await`
/// held across the guard), so the std `Mutex` is correct here.
#[derive(Default)]
pub struct InMemoryStore {
    files: Mutex<Vec<FileRec>>,
    folders: Mutex<Vec<FolderRec>>,
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
        // Reject on any unique conflict (id OR a non-null share token), matching the Postgres
        // constraints (NULL share tokens are distinct, so revoked rows never collide).
        if files.iter().any(|f| {
            f.id == file.id
                || (file.share_token.is_some() && f.share_token == file.share_token)
        }) {
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
        Ok(files
            .iter()
            .find(|f| f.share_token.as_deref() == Some(token))
            .cloned())
    }

    async fn list_by_owner(
        &self,
        owner_sub: &str,
        folder: Option<&str>,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<FileRec>, StoreError> {
        let limit = clamp_page(limit);
        let files = self.files.lock().expect("files lock poisoned");
        let mut out: Vec<FileRec> = files
            .iter()
            .filter(|f| f.owner_sub == owner_sub)
            // Folder filter: `None` = the flat all-files view; `Some(id)` = only that folder.
            .filter(|f| match folder {
                None => true,
                Some(fid) => f.folder_id.as_deref() == Some(fid),
            })
            // Keyset cursor: keep only rows strictly OLDER than `before` under (created_at, id).
            .filter(|f| match &before {
                None => true,
                Some((ts, id)) => f.created_at < *ts || (f.created_at == *ts && f.id < *id),
            })
            .cloned()
            .collect();
        // Newest first; id as a deterministic tiebreak when created_at collides (same second).
        out.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.id.cmp(&a.id))
        });
        out.truncate(limit as usize);
        Ok(out)
    }

    async fn delete(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError> {
        let mut files = self.files.lock().expect("files lock poisoned");
        let before = files.len();
        files.retain(|f| !(f.id == id && f.owner_sub == owner_sub));
        Ok(files.len() != before)
    }

    async fn configure_share(
        &self,
        id: &str,
        owner_sub: &str,
        share_token: Option<String>,
        expires_at: Option<i64>,
        share_password_hash: Option<String>,
    ) -> Result<bool, StoreError> {
        let mut files = self.files.lock().expect("files lock poisoned");
        match files
            .iter_mut()
            .find(|f| f.id == id && f.owner_sub == owner_sub)
        {
            Some(f) => {
                f.share_token = share_token;
                f.expires_at = expires_at;
                f.share_password_hash = share_password_hash;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn create_folder(&self, folder: &FolderRec) -> Result<bool, StoreError> {
        let mut folders = self.folders.lock().expect("folders lock poisoned");
        if folders.iter().any(|f| f.id == folder.id) {
            return Ok(false);
        }
        folders.push(folder.clone());
        Ok(true)
    }

    async fn list_folders(&self, owner_sub: &str) -> Result<Vec<FolderRec>, StoreError> {
        let folders = self.folders.lock().expect("folders lock poisoned");
        let mut out: Vec<FolderRec> = folders
            .iter()
            .filter(|f| f.owner_sub == owner_sub)
            .cloned()
            .collect();
        // Name-ordered (case-insensitive), id as a deterministic tiebreak — matches the Pg index.
        out.sort_by(|a, b| {
            a.name
                .to_lowercase()
                .cmp(&b.name.to_lowercase())
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(out)
    }

    async fn get_folder(
        &self,
        id: &str,
        owner_sub: &str,
    ) -> Result<Option<FolderRec>, StoreError> {
        let folders = self.folders.lock().expect("folders lock poisoned");
        Ok(folders
            .iter()
            .find(|f| f.id == id && f.owner_sub == owner_sub)
            .cloned())
    }

    async fn rename_folder(
        &self,
        id: &str,
        owner_sub: &str,
        name: &str,
    ) -> Result<bool, StoreError> {
        let mut folders = self.folders.lock().expect("folders lock poisoned");
        match folders
            .iter_mut()
            .find(|f| f.id == id && f.owner_sub == owner_sub)
        {
            Some(f) => {
                f.name = name.to_string();
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn delete_folder(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError> {
        // Unfile the owner's files that point at this folder BEFORE removing it, so none is orphaned.
        {
            let mut files = self.files.lock().expect("files lock poisoned");
            for f in files.iter_mut() {
                if f.owner_sub == owner_sub && f.folder_id.as_deref() == Some(id) {
                    f.folder_id = None;
                }
            }
        }
        let mut folders = self.folders.lock().expect("folders lock poisoned");
        let before = folders.len();
        folders.retain(|f| !(f.id == id && f.owner_sub == owner_sub));
        Ok(folders.len() != before)
    }

    async fn move_file(
        &self,
        id: &str,
        owner_sub: &str,
        folder_id: Option<&str>,
    ) -> Result<bool, StoreError> {
        let mut files = self.files.lock().expect("files lock poisoned");
        match files
            .iter_mut()
            .find(|f| f.id == id && f.owner_sub == owner_sub)
        {
            Some(f) => {
                f.folder_id = folder_id.map(str::to_string);
                Ok(true)
            }
            None => Ok(false),
        }
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
const COLS: &str = "id, owner_sub, name, content_type, size, bucket, object_key, share_token, \
     created_at, expires_at, share_password_hash, folder_id";

/// Column list shared by every folder SELECT.
const FOLDER_COLS: &str = "id, owner_sub, name, created_at";

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
        // A revoked share link clears `share_token` to NULL, so the column must be nullable. The
        // UNIQUE constraint stays (SQL treats NULLs as distinct, so many revoked rows coexist).
        // Idempotent: dropping NOT NULL when already dropped is a no-op. Standard SQL only.
        sqlx::query("ALTER TABLE files ALTER COLUMN share_token DROP NOT NULL")
            .execute(&self.pool)
            .await?;
        // Additive, idempotent columns for the share-link lifecycle. Pre-existing rows default to
        // NULL (never expires / no password) — their current always-shareable behavior. Portable.
        sqlx::query("ALTER TABLE files ADD COLUMN IF NOT EXISTS expires_at BIGINT")
            .execute(&self.pool)
            .await?;
        sqlx::query("ALTER TABLE files ADD COLUMN IF NOT EXISTS share_password_hash TEXT")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_files_owner_created \
             ON files (owner_sub, created_at)",
        )
        .execute(&self.pool)
        .await?;
        // Folders (albums). Additive + idempotent; pre-existing files default to NULL folder_id
        // (unfiled), preserving the flat all-files view. Portable standard SQL only.
        sqlx::query("ALTER TABLE files ADD COLUMN IF NOT EXISTS folder_id TEXT")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS folders (\
                 id TEXT PRIMARY KEY, \
                 owner_sub TEXT NOT NULL, \
                 name TEXT NOT NULL, \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_folders_owner_name \
             ON folders (owner_sub, name)",
        )
        .execute(&self.pool)
        .await?;
        // Backs the folder-filtered gallery lookup (owner + folder filter, created ordering).
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_files_owner_folder \
             ON files (owner_sub, folder_id, created_at)",
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
            expires_at: row.try_get("expires_at")?,
            share_password_hash: row.try_get("share_password_hash")?,
            folder_id: row.try_get("folder_id")?,
        })
    }

    fn folder_from_row(row: &sqlx::postgres::PgRow) -> Result<FolderRec, sqlx::Error> {
        Ok(FolderRec {
            id: row.try_get("id")?,
            owner_sub: row.try_get("owner_sub")?,
            name: row.try_get("name")?,
            created_at: row.try_get("created_at")?,
        })
    }

    async fn create_async(&self, file: &FileRec) -> Result<bool, sqlx::Error> {
        // No conflict target => any unique violation (id OR share_token) yields 0 rows affected,
        // signaling the handler to retry with fresh values. Single, race-free insert path.
        let result = sqlx::query(
            "INSERT INTO files \
                 (id, owner_sub, name, content_type, size, bucket, object_key, share_token, \
                  created_at, expires_at, share_password_hash, folder_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
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
        .bind(file.expires_at)
        .bind(&file.share_password_hash)
        .bind(&file.folder_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn configure_share_async(
        &self,
        id: &str,
        owner_sub: &str,
        share_token: Option<String>,
        expires_at: Option<i64>,
        share_password_hash: Option<String>,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE files SET share_token = $1, expires_at = $2, share_password_hash = $3 \
             WHERE id = $4 AND owner_sub = $5",
        )
        .bind(&share_token)
        .bind(expires_at)
        .bind(&share_password_hash)
        .bind(id)
        .bind(owner_sub)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
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

    async fn list_by_owner_async(
        &self,
        owner_sub: &str,
        folder: Option<&str>,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<FileRec>, sqlx::Error> {
        let limit = clamp_page(limit);
        // The table index/order IS the keyset `(created_at DESC, id DESC)`; the cursor clause
        // (created_at, id) < (b_ts, b_id) selects the next page of strictly-older rows. The four
        // branches keep the positional bind order in lock-step with each SQL variant (folder filter
        // × keyset cursor).
        let rows = match (folder, &before) {
            (None, None) => {
                sqlx::query(&format!(
                    "SELECT {COLS} FROM files WHERE owner_sub = $1 \
                     ORDER BY created_at DESC, id DESC LIMIT $2"
                ))
                .bind(owner_sub)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (None, Some((ts, id))) => {
                sqlx::query(&format!(
                    "SELECT {COLS} FROM files WHERE owner_sub = $1 \
                     AND (created_at < $2 OR (created_at = $2 AND id < $3)) \
                     ORDER BY created_at DESC, id DESC LIMIT $4"
                ))
                .bind(owner_sub)
                .bind(ts)
                .bind(id)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (Some(fid), None) => {
                sqlx::query(&format!(
                    "SELECT {COLS} FROM files WHERE owner_sub = $1 AND folder_id = $2 \
                     ORDER BY created_at DESC, id DESC LIMIT $3"
                ))
                .bind(owner_sub)
                .bind(fid)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (Some(fid), Some((ts, id))) => {
                sqlx::query(&format!(
                    "SELECT {COLS} FROM files WHERE owner_sub = $1 AND folder_id = $2 \
                     AND (created_at < $3 OR (created_at = $3 AND id < $4)) \
                     ORDER BY created_at DESC, id DESC LIMIT $5"
                ))
                .bind(owner_sub)
                .bind(fid)
                .bind(ts)
                .bind(id)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
        };
        rows.iter().map(Self::file_from_row).collect()
    }

    async fn create_folder_async(&self, folder: &FolderRec) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "INSERT INTO folders (id, owner_sub, name, created_at) \
             VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
        )
        .bind(&folder.id)
        .bind(&folder.owner_sub)
        .bind(&folder.name)
        .bind(folder.created_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn list_folders_async(&self, owner_sub: &str) -> Result<Vec<FolderRec>, sqlx::Error> {
        let rows = sqlx::query(&format!(
            "SELECT {FOLDER_COLS} FROM folders WHERE owner_sub = $1 \
             ORDER BY lower(name) ASC, id ASC"
        ))
        .bind(owner_sub)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::folder_from_row).collect()
    }

    async fn get_folder_async(
        &self,
        id: &str,
        owner_sub: &str,
    ) -> Result<Option<FolderRec>, sqlx::Error> {
        let row = sqlx::query(&format!(
            "SELECT {FOLDER_COLS} FROM folders WHERE id = $1 AND owner_sub = $2"
        ))
        .bind(id)
        .bind(owner_sub)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::folder_from_row).transpose()
    }

    async fn rename_folder_async(
        &self,
        id: &str,
        owner_sub: &str,
        name: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("UPDATE folders SET name = $1 WHERE id = $2 AND owner_sub = $3")
            .bind(name)
            .bind(id)
            .bind(owner_sub)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_folder_async(&self, id: &str, owner_sub: &str) -> Result<bool, sqlx::Error> {
        // Unfile the owner's files first (clear folder_id), then drop the folder row. Two portable
        // statements — a file pointing at a missing folder is worse than a brief unfiled state.
        sqlx::query("UPDATE files SET folder_id = NULL WHERE folder_id = $1 AND owner_sub = $2")
            .bind(id)
            .bind(owner_sub)
            .execute(&self.pool)
            .await?;
        let result = sqlx::query("DELETE FROM folders WHERE id = $1 AND owner_sub = $2")
            .bind(id)
            .bind(owner_sub)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn move_file_async(
        &self,
        id: &str,
        owner_sub: &str,
        folder_id: Option<&str>,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("UPDATE files SET folder_id = $1 WHERE id = $2 AND owner_sub = $3")
            .bind(folder_id)
            .bind(id)
            .bind(owner_sub)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
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

    async fn list_by_owner(
        &self,
        owner_sub: &str,
        folder: Option<&str>,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<FileRec>, StoreError> {
        self.list_by_owner_async(owner_sub, folder, before, limit)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn delete(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError> {
        self.delete_async(id, owner_sub)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn configure_share(
        &self,
        id: &str,
        owner_sub: &str,
        share_token: Option<String>,
        expires_at: Option<i64>,
        share_password_hash: Option<String>,
    ) -> Result<bool, StoreError> {
        self.configure_share_async(id, owner_sub, share_token, expires_at, share_password_hash)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn create_folder(&self, folder: &FolderRec) -> Result<bool, StoreError> {
        self.create_folder_async(folder)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_folders(&self, owner_sub: &str) -> Result<Vec<FolderRec>, StoreError> {
        self.list_folders_async(owner_sub)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get_folder(
        &self,
        id: &str,
        owner_sub: &str,
    ) -> Result<Option<FolderRec>, StoreError> {
        self.get_folder_async(id, owner_sub)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn rename_folder(
        &self,
        id: &str,
        owner_sub: &str,
        name: &str,
    ) -> Result<bool, StoreError> {
        self.rename_folder_async(id, owner_sub, name)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn delete_folder(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError> {
        self.delete_folder_async(id, owner_sub)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn move_file(
        &self,
        id: &str,
        owner_sub: &str,
        folder_id: Option<&str>,
    ) -> Result<bool, StoreError> {
        self.move_file_async(id, owner_sub, folder_id)
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
            share_token: Some(token.into()),
            created_at,
            expires_at: None,
            share_password_hash: None,
            folder_id: None,
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
        let mine = s.list_by_owner("u", None, None, 50).await.unwrap();
        let ids: Vec<&str> = mine.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, vec!["c", "a"]);
    }

    #[tokio::test]
    async fn list_paginates_backward_with_before_cursor() {
        let s = InMemoryStore::new();
        for (id, ts) in [("a", 10), ("b", 20), ("c", 30), ("d", 40), ("e", 50)] {
            s.create(&file(id, "u", &format!("t-{id}"), ts)).await.unwrap();
        }
        // Page 1 (newest 2).
        let p1 = s.list_by_owner("u", None, None, 2).await.unwrap();
        assert_eq!(p1.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(), vec!["e", "d"]);
        // Cursor = last (oldest) row of page 1 -> next 2, strictly older.
        let c1 = p1.last().unwrap();
        let p2 = s
            .list_by_owner("u", None, Some((c1.created_at, c1.id.clone())), 2)
            .await
            .unwrap();
        assert_eq!(p2.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(), vec!["c", "b"]);
        // Final partial page.
        let c2 = p2.last().unwrap();
        let p3 = s
            .list_by_owner("u", None, Some((c2.created_at, c2.id.clone())), 2)
            .await
            .unwrap();
        assert_eq!(p3.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(), vec!["a"]);
    }

    #[tokio::test]
    async fn cursor_tiebreaks_on_id_when_created_at_collides() {
        let s = InMemoryStore::new();
        // Identical created_at: ordering falls back to id DESC => c, b, a.
        s.create(&file("a", "u", "ta", 100)).await.unwrap();
        s.create(&file("b", "u", "tb", 100)).await.unwrap();
        s.create(&file("c", "u", "tc", 100)).await.unwrap();
        let p1 = s.list_by_owner("u", None, None, 2).await.unwrap();
        assert_eq!(p1.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(), vec!["c", "b"]);
        let c1 = p1.last().unwrap();
        let p2 = s
            .list_by_owner("u", None, Some((c1.created_at, c1.id.clone())), 2)
            .await
            .unwrap();
        assert_eq!(p2.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(), vec!["a"]);
    }

    #[tokio::test]
    async fn limit_is_clamped_to_max_page() {
        let s = InMemoryStore::new();
        for i in 0..10 {
            s.create(&file(&format!("id{i:02}"), "u", &format!("t{i:02}"), i))
                .await
                .unwrap();
        }
        // A non-positive limit falls back to the default page size (>= 10 here, so all 10 return).
        assert_eq!(s.list_by_owner("u", None, None, 0).await.unwrap().len(), 10);
        // An absurd limit is capped to MAX_PAGE but still returns everything available.
        assert_eq!(s.list_by_owner("u", None, None, 100_000).await.unwrap().len(), 10);
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

    #[tokio::test]
    async fn configure_share_updates_expiry_password_and_revokes() {
        let s = InMemoryStore::new();
        s.create(&file("a", "u", "tok-a", 1)).await.unwrap();

        // Non-owner cannot configure.
        assert!(!s
            .configure_share("a", "intruder", Some("tok-a".into()), Some(999), None)
            .await
            .unwrap());

        // Owner sets an expiry + password on the existing token.
        assert!(s
            .configure_share("a", "u", Some("tok-a".into()), Some(999), Some("salt$hash".into()))
            .await
            .unwrap());
        let rec = s.get("a").await.unwrap().unwrap();
        assert_eq!(rec.expires_at, Some(999));
        assert_eq!(rec.share_password_hash.as_deref(), Some("salt$hash"));
        assert!(rec.share_expired(999));

        // Revoke: token cleared to None, and the public lookup misses.
        assert!(s.configure_share("a", "u", None, None, None).await.unwrap());
        assert!(s.get_by_token("tok-a").await.unwrap().is_none());
        let rec = s.get("a").await.unwrap().unwrap();
        assert!(rec.share_token.is_none());
        assert!(rec.expires_at.is_none());
        assert!(rec.share_password_hash.is_none());

        // A second revoked file coexists (NULL tokens are distinct — no unique collision).
        s.create(&file("b", "u", "tok-b", 2)).await.unwrap();
        assert!(s.configure_share("b", "u", None, None, None).await.unwrap());
        assert_eq!(s.list_by_owner("u", None, None, 50).await.unwrap().len(), 2);
    }

    fn folder(id: &str, owner: &str, name: &str, created_at: i64) -> FolderRec {
        FolderRec {
            id: id.into(),
            owner_sub: owner.into(),
            name: name.into(),
            created_at,
        }
    }

    #[tokio::test]
    async fn folders_are_owner_scoped_and_name_ordered() {
        let s = InMemoryStore::new();
        s.create_folder(&folder("f2", "u", "Zeta", 1)).await.unwrap();
        s.create_folder(&folder("f1", "u", "alpha", 2)).await.unwrap();
        s.create_folder(&folder("f3", "other", "Mine", 3)).await.unwrap();
        // id collision -> false.
        assert!(!s.create_folder(&folder("f1", "u", "dup", 9)).await.unwrap());

        let mine = s.list_folders("u").await.unwrap();
        let names: Vec<&str> = mine.iter().map(|f| f.name.as_str()).collect();
        // Case-insensitive name order: "alpha" before "Zeta"; the other owner's folder is excluded.
        assert_eq!(names, vec!["alpha", "Zeta"]);

        // get_folder is ownership-scoped.
        assert!(s.get_folder("f1", "u").await.unwrap().is_some());
        assert!(s.get_folder("f1", "intruder").await.unwrap().is_none());
        assert!(s.get_folder("f3", "u").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn rename_and_delete_folder_are_owner_scoped() {
        let s = InMemoryStore::new();
        s.create_folder(&folder("f1", "u", "Old", 1)).await.unwrap();
        // A non-owner cannot rename or delete.
        assert!(!s.rename_folder("f1", "intruder", "Hax").await.unwrap());
        assert!(!s.delete_folder("f1", "intruder").await.unwrap());
        // Owner renames.
        assert!(s.rename_folder("f1", "u", "New").await.unwrap());
        assert_eq!(s.get_folder("f1", "u").await.unwrap().unwrap().name, "New");
        // Owner deletes.
        assert!(s.delete_folder("f1", "u").await.unwrap());
        assert!(s.get_folder("f1", "u").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn move_file_filters_the_folder_view() {
        let s = InMemoryStore::new();
        s.create_folder(&folder("f1", "u", "Album", 1)).await.unwrap();
        s.create(&file("a", "u", "ta", 10)).await.unwrap();
        s.create(&file("b", "u", "tb", 20)).await.unwrap();

        // Both files start unfiled: the folder view is empty, the flat view has both.
        assert_eq!(s.list_by_owner("u", Some("f1"), None, 50).await.unwrap().len(), 0);
        assert_eq!(s.list_by_owner("u", None, None, 50).await.unwrap().len(), 2);

        // A non-owner cannot move the file.
        assert!(!s.move_file("a", "intruder", Some("f1")).await.unwrap());
        // Owner moves "a" into the folder; only it shows in the folder view, both in the flat view.
        assert!(s.move_file("a", "u", Some("f1")).await.unwrap());
        let in_folder = s.list_by_owner("u", Some("f1"), None, 50).await.unwrap();
        assert_eq!(in_folder.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(), vec!["a"]);
        assert_eq!(s.list_by_owner("u", None, None, 50).await.unwrap().len(), 2);

        // Move "a" back to root -> the folder view empties again.
        assert!(s.move_file("a", "u", None).await.unwrap());
        assert_eq!(s.list_by_owner("u", Some("f1"), None, 50).await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn delete_folder_unfiles_its_files() {
        let s = InMemoryStore::new();
        s.create_folder(&folder("f1", "u", "Album", 1)).await.unwrap();
        s.create(&file("a", "u", "ta", 10)).await.unwrap();
        s.move_file("a", "u", Some("f1")).await.unwrap();
        assert_eq!(s.get("a").await.unwrap().unwrap().folder_id.as_deref(), Some("f1"));

        // Deleting the folder keeps the file but clears its folder_id (no orphaned reference).
        assert!(s.delete_folder("f1", "u").await.unwrap());
        assert!(s.get("a").await.unwrap().unwrap().folder_id.is_none());
        assert_eq!(s.list_by_owner("u", None, None, 50).await.unwrap().len(), 1);
    }
}
