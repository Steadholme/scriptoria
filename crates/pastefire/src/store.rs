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

use crate::config::MAX_PAGE;
use crate::model::{Paste, PasteFile, PasteRevision};

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

    /// An author's own non-expired pastes, newest-first (`created_at DESC, id DESC`), one keyset
    /// page. `before` is the exclusive cursor `(created_at, id)` of the last row already seen
    /// (`None` = newest page); `limit` is the page size (clamped to `[1, MAX_PAGE]`). `now` is
    /// epoch seconds; expired rows are excluded at the source so both stores agree.
    async fn list_by_author(
        &self,
        author_sub: &str,
        now: i64,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<Paste>, StoreError>;

    /// Delete a paste only if it belongs to `author_sub`. Returns `true` when a row was
    /// removed (existed AND owned), `false` otherwise.
    async fn delete(&self, id: &str, author_sub: &str) -> Result<bool, StoreError>;

    /// Overwrite a paste's editable content (`title`/`body`/`language`), ownership-scoped: only
    /// the author's own row is updated. Returns `true` when a row was updated. The paste's
    /// identity, timestamps, expiry, burn flag and password are untouched.
    async fn update_paste(
        &self,
        id: &str,
        author_sub: &str,
        title: &str,
        body: &str,
        language: &str,
    ) -> Result<bool, StoreError>;

    /// Append a historical revision. Idempotent on `(paste_id, revision)` — re-inserting the same
    /// revision number is a no-op returning `false` (a fresh insert returns `true`).
    async fn add_revision(&self, rev: &PasteRevision) -> Result<bool, StoreError>;

    /// All revisions for a paste, oldest-first (`revision ASC`). Empty when the paste was never
    /// edited. The count `+ 1` is the next revision number for a fresh edit.
    async fn list_revisions(&self, paste_id: &str) -> Result<Vec<PasteRevision>, StoreError>;

    /// Fetch a single historical revision by `(paste_id, revision)`.
    async fn get_revision(
        &self,
        paste_id: &str,
        revision: i64,
    ) -> Result<Option<PasteRevision>, StoreError>;

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

    /// Replace the entire set of named files for a paste (delete-then-insert), so a paste's
    /// `paste_files` rows always reflect its current multi-file layout. An empty slice clears the
    /// rows, collapsing the paste back to its single-content (`pastes.body`) representation. The
    /// caller owns id/position assignment; this is a whole-set overwrite, never a partial merge.
    async fn set_files(&self, paste_id: &str, files: &[PasteFile]) -> Result<(), StoreError>;

    /// All files for a paste, ascending by `position` (then `id` as a deterministic tiebreak).
    /// Empty for a legacy/single-content paste — the caller then synthesizes one file from the
    /// paste body, so pre-existing pastes render exactly as before.
    async fn list_files(&self, paste_id: &str) -> Result<Vec<PasteFile>, StoreError>;
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

/// In-memory `Store`. The `Mutex<Vec<_>>` critical sections are fully synchronous (no `.await`
/// held across the guard), so the std `Mutex` is correct here.
#[derive(Default)]
pub struct InMemoryStore {
    pastes: Mutex<Vec<Paste>>,
    revisions: Mutex<Vec<PasteRevision>>,
    files: Mutex<Vec<PasteFile>>,
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

    async fn list_by_author(
        &self,
        author_sub: &str,
        now: i64,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<Paste>, StoreError> {
        let limit = limit.clamp(1, MAX_PAGE);
        let pastes = self.pastes.lock().expect("pastes lock poisoned");
        let mut out: Vec<Paste> = pastes
            .iter()
            .filter(|p| p.author_sub == author_sub && !p.is_expired(now))
            // Keyset "before" cursor: keep rows strictly older than the cursor under the
            // (created_at DESC, id DESC) ordering — same predicate as the SQL path.
            .filter(|p| match &before {
                Some((b_ts, b_id)) => {
                    p.created_at < *b_ts || (p.created_at == *b_ts && p.id.as_str() < b_id.as_str())
                }
                None => true,
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

    async fn delete(&self, id: &str, author_sub: &str) -> Result<bool, StoreError> {
        let mut pastes = self.pastes.lock().expect("pastes lock poisoned");
        let before = pastes.len();
        pastes.retain(|p| !(p.id == id && p.author_sub == author_sub));
        let removed = pastes.len() != before;
        // Cascade: an owned paste's files go with it (never orphan `paste_files` rows).
        if removed {
            self.files
                .lock()
                .expect("files lock poisoned")
                .retain(|f| f.paste_id != id);
        }
        Ok(removed)
    }

    async fn update_paste(
        &self,
        id: &str,
        author_sub: &str,
        title: &str,
        body: &str,
        language: &str,
    ) -> Result<bool, StoreError> {
        let mut pastes = self.pastes.lock().expect("pastes lock poisoned");
        match pastes
            .iter_mut()
            .find(|p| p.id == id && p.author_sub == author_sub)
        {
            Some(p) => {
                p.title = title.to_string();
                p.body = body.to_string();
                p.language = language.to_string();
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn add_revision(&self, rev: &PasteRevision) -> Result<bool, StoreError> {
        let mut revs = self.revisions.lock().expect("revisions lock poisoned");
        if revs
            .iter()
            .any(|r| r.paste_id == rev.paste_id && r.revision == rev.revision)
        {
            return Ok(false);
        }
        revs.push(rev.clone());
        Ok(true)
    }

    async fn list_revisions(&self, paste_id: &str) -> Result<Vec<PasteRevision>, StoreError> {
        let revs = self.revisions.lock().expect("revisions lock poisoned");
        let mut out: Vec<PasteRevision> =
            revs.iter().filter(|r| r.paste_id == paste_id).cloned().collect();
        out.sort_by_key(|r| r.revision);
        Ok(out)
    }

    async fn get_revision(
        &self,
        paste_id: &str,
        revision: i64,
    ) -> Result<Option<PasteRevision>, StoreError> {
        let revs = self.revisions.lock().expect("revisions lock poisoned");
        Ok(revs
            .iter()
            .find(|r| r.paste_id == paste_id && r.revision == revision)
            .cloned())
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

    async fn set_files(&self, paste_id: &str, files: &[PasteFile]) -> Result<(), StoreError> {
        let mut store = self.files.lock().expect("files lock poisoned");
        // Whole-set overwrite: drop the paste's current rows, then insert the new set.
        store.retain(|f| f.paste_id != paste_id);
        store.extend(files.iter().cloned());
        Ok(())
    }

    async fn list_files(&self, paste_id: &str) -> Result<Vec<PasteFile>, StoreError> {
        let store = self.files.lock().expect("files lock poisoned");
        let mut out: Vec<PasteFile> =
            store.iter().filter(|f| f.paste_id == paste_id).cloned().collect();
        out.sort_by(|a, b| a.position.cmp(&b.position).then_with(|| a.id.cmp(&b.id)));
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
const COLS: &str = "id, title, body, language, author_sub, author_email, created_at, expires_at, \
     burn_after_read, source_id, password_hash";

/// Column list for the `paste_revisions` history table, shared by its SELECTs.
const REV_COLS: &str = "paste_id, revision, title, body, language, created_at";

/// Column list for the `paste_files` multi-file table, shared by its SELECTs.
const FILE_COLS: &str = "id, paste_id, filename, content, position";

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
        // Additive, idempotent columns for fork-crediting + optional password protection. Both
        // nullable (NULL = original paste / no password). Standard SQL only — portable to FusionDB.
        sqlx::query("ALTER TABLE pastes ADD COLUMN IF NOT EXISTS source_id TEXT")
            .execute(&self.pool)
            .await?;
        sqlx::query("ALTER TABLE pastes ADD COLUMN IF NOT EXISTS password_hash TEXT")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_pastes_author_created \
             ON pastes (author_sub, created_at)",
        )
        .execute(&self.pool)
        .await?;
        // Append-only revision history. Composite PRIMARY KEY makes the append idempotent at the
        // `(paste_id, revision)` level; the PK's leftmost `paste_id` also backs the history lookup.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS paste_revisions (\
                 paste_id TEXT NOT NULL, \
                 revision BIGINT NOT NULL, \
                 title TEXT NOT NULL, \
                 body TEXT NOT NULL, \
                 language TEXT NOT NULL, \
                 created_at BIGINT NOT NULL, \
                 PRIMARY KEY (paste_id, revision)\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Multi-file pastes (GitHub Gist-style). A paste with NO rows here is a legacy/single
        // paste rendered from `pastes.body`, so this table is purely additive — pre-existing
        // pastes are untouched. The index backs the per-paste, position-ordered file lookup.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS paste_files (\
                 id TEXT PRIMARY KEY, \
                 paste_id TEXT NOT NULL, \
                 filename TEXT NOT NULL, \
                 content TEXT NOT NULL, \
                 position BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_paste_files_paste \
             ON paste_files (paste_id, position)",
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
            source_id: row.try_get("source_id")?,
            password_hash: row.try_get("password_hash")?,
        })
    }

    fn revision_from_row(row: &sqlx::postgres::PgRow) -> Result<PasteRevision, sqlx::Error> {
        Ok(PasteRevision {
            paste_id: row.try_get("paste_id")?,
            revision: row.try_get("revision")?,
            title: row.try_get("title")?,
            body: row.try_get("body")?,
            language: row.try_get("language")?,
            created_at: row.try_get("created_at")?,
        })
    }

    fn file_from_row(row: &sqlx::postgres::PgRow) -> Result<PasteFile, sqlx::Error> {
        Ok(PasteFile {
            id: row.try_get("id")?,
            paste_id: row.try_get("paste_id")?,
            filename: row.try_get("filename")?,
            content: row.try_get("content")?,
            position: row.try_get("position")?,
        })
    }

    async fn create_async(&self, paste: &Paste) -> Result<bool, sqlx::Error> {
        // ON CONFLICT DO NOTHING => 0 rows affected signals an id collision; the handler then
        // retries with a fresh id. This is the single, race-free insert path.
        let result = sqlx::query(
            "INSERT INTO pastes \
                 (id, title, body, language, author_sub, author_email, created_at, expires_at, \
                  burn_after_read, source_id, password_hash) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
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
        .bind(&paste.source_id)
        .bind(&paste.password_hash)
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
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<Paste>, sqlx::Error> {
        let limit = limit.clamp(1, MAX_PAGE);
        // The keyset is exactly the ORDER BY: `(created_at DESC, id DESC)`. With a `before`
        // cursor we keep only rows strictly older than it under that ordering.
        let rows = match before {
            None => {
                sqlx::query(&format!(
                    "SELECT {COLS} FROM pastes \
                     WHERE author_sub = $1 AND (expires_at IS NULL OR expires_at > $2) \
                     ORDER BY created_at DESC, id DESC LIMIT $3"
                ))
                .bind(author_sub)
                .bind(now)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            Some((b_ts, b_id)) => {
                sqlx::query(&format!(
                    "SELECT {COLS} FROM pastes \
                     WHERE author_sub = $1 AND (expires_at IS NULL OR expires_at > $2) \
                       AND (created_at < $3 OR (created_at = $3 AND id < $4)) \
                     ORDER BY created_at DESC, id DESC LIMIT $5"
                ))
                .bind(author_sub)
                .bind(now)
                .bind(b_ts)
                .bind(b_id)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
        };
        rows.iter().map(Self::paste_from_row).collect()
    }

    async fn delete_async(&self, id: &str, author_sub: &str) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM pastes WHERE id = $1 AND author_sub = $2")
            .bind(id)
            .bind(author_sub)
            .execute(&self.pool)
            .await?;
        let removed = result.rows_affected() > 0;
        // Cascade: an owned paste's files go with it (never orphan `paste_files` rows).
        if removed {
            sqlx::query("DELETE FROM paste_files WHERE paste_id = $1")
                .bind(id)
                .execute(&self.pool)
                .await?;
        }
        Ok(removed)
    }

    async fn update_paste_async(
        &self,
        id: &str,
        author_sub: &str,
        title: &str,
        body: &str,
        language: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE pastes SET title = $3, body = $4, language = $5 \
             WHERE id = $1 AND author_sub = $2",
        )
        .bind(id)
        .bind(author_sub)
        .bind(title)
        .bind(body)
        .bind(language)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn add_revision_async(&self, rev: &PasteRevision) -> Result<bool, sqlx::Error> {
        // ON CONFLICT DO NOTHING makes the append idempotent on (paste_id, revision).
        let result = sqlx::query(
            "INSERT INTO paste_revisions \
                 (paste_id, revision, title, body, language, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (paste_id, revision) DO NOTHING",
        )
        .bind(&rev.paste_id)
        .bind(rev.revision)
        .bind(&rev.title)
        .bind(&rev.body)
        .bind(&rev.language)
        .bind(rev.created_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn list_revisions_async(
        &self,
        paste_id: &str,
    ) -> Result<Vec<PasteRevision>, sqlx::Error> {
        let rows = sqlx::query(&format!(
            "SELECT {REV_COLS} FROM paste_revisions WHERE paste_id = $1 ORDER BY revision ASC"
        ))
        .bind(paste_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::revision_from_row).collect()
    }

    async fn get_revision_async(
        &self,
        paste_id: &str,
        revision: i64,
    ) -> Result<Option<PasteRevision>, sqlx::Error> {
        let row = sqlx::query(&format!(
            "SELECT {REV_COLS} FROM paste_revisions WHERE paste_id = $1 AND revision = $2"
        ))
        .bind(paste_id)
        .bind(revision)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::revision_from_row).transpose()
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

    async fn set_files_async(&self, paste_id: &str, files: &[PasteFile]) -> Result<(), sqlx::Error> {
        // Whole-set overwrite in one transaction so a reader never sees a half-replaced set.
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM paste_files WHERE paste_id = $1")
            .bind(paste_id)
            .execute(&mut *tx)
            .await?;
        for f in files {
            sqlx::query(
                "INSERT INTO paste_files (id, paste_id, filename, content, position) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(&f.id)
            .bind(&f.paste_id)
            .bind(&f.filename)
            .bind(&f.content)
            .bind(f.position)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await
    }

    async fn list_files_async(&self, paste_id: &str) -> Result<Vec<PasteFile>, sqlx::Error> {
        let rows = sqlx::query(&format!(
            "SELECT {FILE_COLS} FROM paste_files WHERE paste_id = $1 \
             ORDER BY position ASC, id ASC"
        ))
        .bind(paste_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::file_from_row).collect()
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

    async fn list_by_author(
        &self,
        author_sub: &str,
        now: i64,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<Paste>, StoreError> {
        self.list_by_author_async(author_sub, now, before, limit)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn delete(&self, id: &str, author_sub: &str) -> Result<bool, StoreError> {
        self.delete_async(id, author_sub)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn update_paste(
        &self,
        id: &str,
        author_sub: &str,
        title: &str,
        body: &str,
        language: &str,
    ) -> Result<bool, StoreError> {
        self.update_paste_async(id, author_sub, title, body, language)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn add_revision(&self, rev: &PasteRevision) -> Result<bool, StoreError> {
        self.add_revision_async(rev)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_revisions(&self, paste_id: &str) -> Result<Vec<PasteRevision>, StoreError> {
        self.list_revisions_async(paste_id)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get_revision(
        &self,
        paste_id: &str,
        revision: i64,
    ) -> Result<Option<PasteRevision>, StoreError> {
        self.get_revision_async(paste_id, revision)
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

    async fn set_files(&self, paste_id: &str, files: &[PasteFile]) -> Result<(), StoreError> {
        self.set_files_async(paste_id, files)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_files(&self, paste_id: &str) -> Result<Vec<PasteFile>, StoreError> {
        self.list_files_async(paste_id)
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
            source_id: None,
            password_hash: None,
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
        let recent = s.list_by_author("u", 200, None, 50).await.unwrap();
        let ids: Vec<&str> = recent.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["c", "a"]); // newest-first, expired + other author excluded
    }

    #[tokio::test]
    async fn list_by_author_paginates_backward_with_cursor() {
        let s = InMemoryStore::new();
        // All share one created_at so the (created_at DESC, id DESC) keyset falls to the id
        // tiebreak — the case a created_at-only cursor would get wrong.
        for id in ["a", "b", "c", "d", "e"] {
            s.create(&paste(id, "u", 100, None)).await.unwrap();
        }

        // Newest page of 2: e, d.
        let p1 = s.list_by_author("u", 200, None, 2).await.unwrap();
        let ids1: Vec<&str> = p1.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids1, vec!["e", "d"]);

        // Older page, keyed off the last row of page 1: c, b.
        let last = p1.last().unwrap();
        let p2 = s
            .list_by_author("u", 200, Some((last.created_at, last.id.clone())), 2)
            .await
            .unwrap();
        let ids2: Vec<&str> = p2.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids2, vec!["c", "b"]);

        // Final page is short (the end): just a, no overlap, no rows dropped.
        let last2 = p2.last().unwrap();
        let p3 = s
            .list_by_author("u", 200, Some((last2.created_at, last2.id.clone())), 2)
            .await
            .unwrap();
        let ids3: Vec<&str> = p3.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids3, vec!["a"]);
    }

    #[tokio::test]
    async fn list_by_author_clamps_page_size() {
        let s = InMemoryStore::new();
        for id in ["a", "b", "c"] {
            s.create(&paste(id, "u", 100, None)).await.unwrap();
        }
        // A non-positive limit is clamped up to at least 1 (never an empty/negative take).
        assert_eq!(s.list_by_author("u", 200, None, 0).await.unwrap().len(), 1);
        // An oversized limit is clamped down to MAX_PAGE (here just returns all 3).
        assert_eq!(
            s.list_by_author("u", 200, None, MAX_PAGE + 1000).await.unwrap().len(),
            3
        );
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

    fn revision(paste_id: &str, revision: i64) -> PasteRevision {
        PasteRevision {
            paste_id: paste_id.into(),
            revision,
            title: format!("t{revision}"),
            body: format!("b{revision}"),
            language: "plaintext".into(),
            created_at: 1000 + revision,
        }
    }

    #[tokio::test]
    async fn update_paste_is_ownership_scoped() {
        let s = InMemoryStore::new();
        s.create(&paste("a", "u", 1, None)).await.unwrap();
        // A non-owner update touches nothing.
        assert!(!s.update_paste("a", "intruder", "x", "y", "rust").await.unwrap());
        assert_eq!(s.get("a").await.unwrap().unwrap().body, "b");
        // The owner's update overwrites just the editable content.
        assert!(s.update_paste("a", "u", "new title", "new body", "rust").await.unwrap());
        let got = s.get("a").await.unwrap().unwrap();
        assert_eq!(got.title, "new title");
        assert_eq!(got.body, "new body");
        assert_eq!(got.language, "rust");
        assert_eq!(got.author_sub, "u"); // identity untouched
    }

    #[tokio::test]
    async fn add_revision_is_idempotent_and_lists_in_order() {
        let s = InMemoryStore::new();
        assert!(s.add_revision(&revision("a", 1)).await.unwrap());
        assert!(s.add_revision(&revision("a", 2)).await.unwrap());
        // Re-appending revision 1 is a no-op.
        assert!(!s.add_revision(&revision("a", 1)).await.unwrap());
        // A different paste's revisions are isolated.
        assert!(s.add_revision(&revision("b", 1)).await.unwrap());

        let revs = s.list_revisions("a").await.unwrap();
        let nums: Vec<i64> = revs.iter().map(|r| r.revision).collect();
        assert_eq!(nums, vec![1, 2]);
        assert_eq!(s.list_revisions("b").await.unwrap().len(), 1);
        assert!(s.list_revisions("missing").await.unwrap().is_empty());

        let r2 = s.get_revision("a", 2).await.unwrap().unwrap();
        assert_eq!(r2.body, "b2");
        assert!(s.get_revision("a", 99).await.unwrap().is_none());
    }

    fn file(paste_id: &str, filename: &str, position: i64) -> PasteFile {
        PasteFile {
            id: format!("{paste_id}-{position}"),
            paste_id: paste_id.into(),
            filename: filename.into(),
            content: format!("content of {filename}"),
            position,
        }
    }

    #[tokio::test]
    async fn set_files_overwrites_whole_set_and_lists_in_position_order() {
        let s = InMemoryStore::new();
        // Legacy/single paste: no rows yet.
        assert!(s.list_files("p").await.unwrap().is_empty());

        // Insert two files out of order — they come back ordered by position.
        s.set_files("p", &[file("p", "b.rs", 1), file("p", "a.rs", 0)])
            .await
            .unwrap();
        let names: Vec<String> = s
            .list_files("p")
            .await
            .unwrap()
            .into_iter()
            .map(|f| f.filename)
            .collect();
        assert_eq!(names, vec!["a.rs", "b.rs"]);

        // A whole-set overwrite replaces (never merges) the prior set.
        s.set_files("p", &[file("p", "only.rs", 0)]).await.unwrap();
        let names: Vec<String> = s
            .list_files("p")
            .await
            .unwrap()
            .into_iter()
            .map(|f| f.filename)
            .collect();
        assert_eq!(names, vec!["only.rs"]);

        // The empty set collapses the paste back to single-content (no rows).
        s.set_files("p", &[]).await.unwrap();
        assert!(s.list_files("p").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn deleting_a_paste_cascades_its_files() {
        let s = InMemoryStore::new();
        s.create(&paste("p", "u", 1, None)).await.unwrap();
        s.set_files("p", &[file("p", "a.rs", 0), file("p", "b.rs", 1)])
            .await
            .unwrap();
        // A non-owner delete leaves the files intact (ownership-scoped, no cascade).
        assert!(!s.delete("p", "intruder").await.unwrap());
        assert_eq!(s.list_files("p").await.unwrap().len(), 2);
        // The owner's delete removes the paste AND its files.
        assert!(s.delete("p", "u").await.unwrap());
        assert!(s.list_files("p").await.unwrap().is_empty());
    }
}
