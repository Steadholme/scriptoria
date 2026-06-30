//! Wiki storage: pages + a simple per-page revision history.
//!
//! `Store` is a small async trait with an in-memory and a PostgreSQL implementation, mirroring
//! the keystone/keyward/watchtower seam: handlers depend only on the trait, so a FusionDB-backed
//! store can drop in later. The PostgreSQL layer uses ONLY portable standard SQL
//! (TEXT/BIGINT, PRIMARY KEY/NOT NULL, `INSERT .. ON CONFLICT .. DO UPDATE`, plain indexes) and
//! runtime queries (no compile-time macros), so the build needs NO database and the same
//! statements later run unchanged on FusionDB over pgwire.
//!
//! A save is a single logical operation ([`Store::save_page`]): it upserts the `pages` row and
//! appends one immutable `revisions` row, atomically (the Postgres impl wraps both in a
//! transaction). Revisions are never updated or deleted — they are the edit history.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::config::{HISTORY_LIMIT, PAGE_LIST_LIMIT};

/// Storage failure surfaced to the handler layer (mapped to a 500).
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store error: {0}")]
    Backend(String),
}

/// A wiki page (the current version). `slug` is the canonical id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    pub slug: String,
    pub title: String,
    pub body_md: String,
    pub updated_by_email: String,
    pub updated_at: i64,
    pub created_at: i64,
}

/// One historical edit of a page. Immutable once written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revision {
    pub id: String,
    pub slug: String,
    pub body_md: String,
    pub editor_email: String,
    pub ts: i64,
}

/// What a save needs from the caller. `editor_email` comes from the gateway identity, NEVER
/// from a client-supplied field. `now` and `revision_id` are passed in so the store stays free
/// of clock/RNG concerns (and tests are deterministic).
#[derive(Clone, Debug)]
pub struct SaveInput {
    pub slug: String,
    pub title: String,
    pub body_md: String,
    pub editor_email: String,
    pub now: i64,
    pub revision_id: String,
}

/// Pluggable wiki store. Methods are `async`: the axum handlers `.await` them directly on the
/// serving runtime, and `PgStore` drives sqlx natively, so a worker thread is never blocked on
/// a DB round-trip (no `block_in_place`, no sync-over-async bridge).
#[async_trait]
pub trait Store: Send + Sync {
    /// All pages, ordered by `title` ascending (case-insensitive), capped for the index.
    async fn list_pages(&self) -> Result<Vec<Page>, StoreError>;

    /// The set of all existing slugs — used to mark `[[wiki-links]]` to missing pages.
    async fn all_slugs(&self) -> Result<Vec<String>, StoreError>;

    /// Fetch one page by slug, if it exists.
    async fn get_page(&self, slug: &str) -> Result<Option<Page>, StoreError>;

    /// Upsert the page AND append one revision, atomically. Returns the saved page.
    async fn save_page(&self, input: SaveInput) -> Result<Page, StoreError>;

    /// Revisions for a slug, newest-first, capped for the history view.
    async fn list_revisions(&self, slug: &str) -> Result<Vec<Revision>, StoreError>;
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

#[derive(Default)]
struct MemData {
    pages: HashMap<String, Page>,
    revisions: Vec<Revision>,
}

/// In-memory `Store`. A single `Mutex` guards both maps so a save (upsert + revision append) is
/// atomic, exactly like the Postgres transaction.
#[derive(Default)]
pub struct InMemoryStore {
    data: Mutex<MemData>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for InMemoryStore {
    async fn list_pages(&self) -> Result<Vec<Page>, StoreError> {
        let data = self.data.lock().expect("lattice store lock poisoned");
        let mut pages: Vec<Page> = data.pages.values().cloned().collect();
        pages.sort_by(|a, b| {
            a.title
                .to_lowercase()
                .cmp(&b.title.to_lowercase())
                .then_with(|| a.slug.cmp(&b.slug))
        });
        pages.truncate(PAGE_LIST_LIMIT);
        Ok(pages)
    }

    async fn all_slugs(&self) -> Result<Vec<String>, StoreError> {
        let data = self.data.lock().expect("lattice store lock poisoned");
        Ok(data.pages.keys().cloned().collect())
    }

    async fn get_page(&self, slug: &str) -> Result<Option<Page>, StoreError> {
        let data = self.data.lock().expect("lattice store lock poisoned");
        Ok(data.pages.get(slug).cloned())
    }

    async fn save_page(&self, input: SaveInput) -> Result<Page, StoreError> {
        let mut data = self.data.lock().expect("lattice store lock poisoned");
        let created_at = data
            .pages
            .get(&input.slug)
            .map(|p| p.created_at)
            .unwrap_or(input.now);
        let page = Page {
            slug: input.slug.clone(),
            title: input.title,
            body_md: input.body_md.clone(),
            updated_by_email: input.editor_email.clone(),
            updated_at: input.now,
            created_at,
        };
        data.pages.insert(input.slug.clone(), page.clone());
        data.revisions.push(Revision {
            id: input.revision_id,
            slug: input.slug,
            body_md: input.body_md,
            editor_email: input.editor_email,
            ts: input.now,
        });
        Ok(page)
    }

    async fn list_revisions(&self, slug: &str) -> Result<Vec<Revision>, StoreError> {
        let data = self.data.lock().expect("lattice store lock poisoned");
        let mut revs: Vec<Revision> = data
            .revisions
            .iter()
            .filter(|r| r.slug == slug)
            .cloned()
            .collect();
        // Newest first; ties (same ms) broken by id for a stable order.
        revs.sort_by(|a, b| b.ts.cmp(&a.ts).then_with(|| b.id.cmp(&a.id)));
        revs.truncate(HISTORY_LIMIT);
        Ok(revs)
    }
}

// --------------------------------------------------------------------------------------
// PostgreSQL-backed store (portable: standard SQL, runtime queries, no macros).
// --------------------------------------------------------------------------------------
//
// Selected at runtime by `LATTICE_STORE=postgres`. The `Store` trait is async, so each method
// uses sqlx natively and the handlers `.await` it on the serving runtime — there is NO
// `block_in_place` and NO sync-over-async. A save runs inside a transaction so the page upsert
// and the revision insert commit together.

use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};
use sqlx::Row;

/// PostgreSQL-backed [`Store`].
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
            "CREATE TABLE IF NOT EXISTS pages (\
                 slug TEXT PRIMARY KEY, \
                 title TEXT NOT NULL, \
                 body_md TEXT NOT NULL, \
                 updated_by_email TEXT NOT NULL, \
                 updated_at BIGINT NOT NULL, \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS revisions (\
                 id TEXT PRIMARY KEY, \
                 slug TEXT NOT NULL, \
                 body_md TEXT NOT NULL, \
                 editor_email TEXT NOT NULL, \
                 ts BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_revisions_slug_ts ON revisions (slug, ts)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_pages_title ON pages (title)")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    fn page_from_row(row: &PgRow) -> Result<Page, sqlx::Error> {
        Ok(Page {
            slug: row.try_get("slug")?,
            title: row.try_get("title")?,
            body_md: row.try_get("body_md")?,
            updated_by_email: row.try_get("updated_by_email")?,
            updated_at: row.try_get("updated_at")?,
            created_at: row.try_get("created_at")?,
        })
    }

    fn revision_from_row(row: &PgRow) -> Result<Revision, sqlx::Error> {
        Ok(Revision {
            id: row.try_get("id")?,
            slug: row.try_get("slug")?,
            body_md: row.try_get("body_md")?,
            editor_email: row.try_get("editor_email")?,
            ts: row.try_get("ts")?,
        })
    }

    async fn list_pages_async(&self) -> Result<Vec<Page>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT slug, title, body_md, updated_by_email, updated_at, created_at \
             FROM pages ORDER BY lower(title) ASC, slug ASC LIMIT $1",
        )
        .bind(PAGE_LIST_LIMIT as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::page_from_row).collect()
    }

    async fn all_slugs_async(&self) -> Result<Vec<String>, sqlx::Error> {
        let rows = sqlx::query("SELECT slug FROM pages")
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(|r| r.try_get::<String, _>("slug")).collect()
    }

    async fn get_page_async(&self, slug: &str) -> Result<Option<Page>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT slug, title, body_md, updated_by_email, updated_at, created_at \
             FROM pages WHERE slug = $1",
        )
        .bind(slug)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::page_from_row).transpose()
    }

    async fn save_page_async(&self, input: SaveInput) -> Result<Page, sqlx::Error> {
        let mut tx = self.pool.begin().await?;

        // Preserve the original creation time when the page already exists.
        let existing_created: Option<i64> =
            sqlx::query("SELECT created_at FROM pages WHERE slug = $1")
                .bind(&input.slug)
                .fetch_optional(&mut *tx)
                .await?
                .map(|r| r.try_get::<i64, _>("created_at"))
                .transpose()?;
        let created_at = existing_created.unwrap_or(input.now);

        sqlx::query(
            "INSERT INTO pages (slug, title, body_md, updated_by_email, updated_at, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (slug) DO UPDATE SET \
                 title = EXCLUDED.title, \
                 body_md = EXCLUDED.body_md, \
                 updated_by_email = EXCLUDED.updated_by_email, \
                 updated_at = EXCLUDED.updated_at",
        )
        .bind(&input.slug)
        .bind(&input.title)
        .bind(&input.body_md)
        .bind(&input.editor_email)
        .bind(input.now)
        .bind(created_at)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO revisions (id, slug, body_md, editor_email, ts) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&input.revision_id)
        .bind(&input.slug)
        .bind(&input.body_md)
        .bind(&input.editor_email)
        .bind(input.now)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(Page {
            slug: input.slug,
            title: input.title,
            body_md: input.body_md,
            updated_by_email: input.editor_email,
            updated_at: input.now,
            created_at,
        })
    }

    async fn list_revisions_async(&self, slug: &str) -> Result<Vec<Revision>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, slug, body_md, editor_email, ts \
             FROM revisions WHERE slug = $1 ORDER BY ts DESC, id DESC LIMIT $2",
        )
        .bind(slug)
        .bind(HISTORY_LIMIT as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::revision_from_row).collect()
    }
}

#[async_trait]
impl Store for PgStore {
    async fn list_pages(&self) -> Result<Vec<Page>, StoreError> {
        self.list_pages_async()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn all_slugs(&self) -> Result<Vec<String>, StoreError> {
        self.all_slugs_async()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get_page(&self, slug: &str) -> Result<Option<Page>, StoreError> {
        self.get_page_async(slug)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn save_page(&self, input: SaveInput) -> Result<Page, StoreError> {
        self.save_page_async(input)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_revisions(&self, slug: &str) -> Result<Vec<Revision>, StoreError> {
        self.list_revisions_async(slug)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(slug: &str, title: &str, body: &str, who: &str, now: i64) -> SaveInput {
        SaveInput {
            slug: slug.to_string(),
            title: title.to_string(),
            body_md: body.to_string(),
            editor_email: who.to_string(),
            now,
            revision_id: format!("rev-{slug}-{now}"),
        }
    }

    #[tokio::test]
    async fn save_creates_then_updates_preserving_created_at() {
        let store = InMemoryStore::new();
        let first = store
            .save_page(input("home", "Home", "v1", "a@x.co", 100))
            .await
            .unwrap();
        assert_eq!(first.created_at, 100);
        assert_eq!(first.updated_at, 100);

        let second = store
            .save_page(input("home", "Home", "v2", "b@x.co", 200))
            .await
            .unwrap();
        assert_eq!(second.created_at, 100, "created_at is preserved");
        assert_eq!(second.updated_at, 200);
        assert_eq!(second.updated_by_email, "b@x.co");
        assert_eq!(second.body_md, "v2");

        let revs = store.list_revisions("home").await.unwrap();
        assert_eq!(revs.len(), 2, "each save records a revision");
        assert_eq!(revs[0].body_md, "v2", "newest first");
        assert_eq!(revs[1].body_md, "v1");
    }

    #[tokio::test]
    async fn list_pages_sorted_and_slugs_collected() {
        let store = InMemoryStore::new();
        store.save_page(input("beta", "Beta", "b", "a@x.co", 1)).await.unwrap();
        store.save_page(input("alpha", "Alpha", "a", "a@x.co", 2)).await.unwrap();
        let pages = store.list_pages().await.unwrap();
        assert_eq!(pages[0].slug, "alpha");
        assert_eq!(pages[1].slug, "beta");
        let mut slugs = store.all_slugs().await.unwrap();
        slugs.sort();
        assert_eq!(slugs, vec!["alpha".to_string(), "beta".to_string()]);
    }
}
