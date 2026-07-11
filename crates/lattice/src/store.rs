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

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::config::{clamp_page_limit, HISTORY_LIMIT};
use crate::graph;

/// Storage failure surfaced to the handler layer (mapped to a 500).
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store error: {0}")]
    Backend(String),
    #[error("invalid page move: {0}")]
    InvalidMove(String),
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
    /// Parent page slug for nested pages; `None` means a legacy top-level page.
    pub parent_id: Option<String>,
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

/// One revision joined to the page metadata needed by the cross-page recent feed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecentEntry {
    pub rev: Revision,
    pub title: String,
    pub page_created_at: i64,
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
    /// One keyset page of pages, newest-first by `(created_at DESC, slug DESC)`. `before` is the
    /// exclusive cursor `(created_at, slug)` taken from the last row of the previous page (`None`
    /// starts at the newest page); `limit` is clamped to `MAX_PAGE`. Older pages stay reachable by
    /// passing the last row's cursor back in.
    async fn list_pages(
        &self,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<Page>, StoreError>;

    /// The set of all existing slugs — used to mark `[[wiki-links]]` to missing pages.
    async fn all_slugs(&self) -> Result<Vec<String>, StoreError>;

    /// Fetch one page by slug, if it exists.
    async fn get_page(&self, slug: &str) -> Result<Option<Page>, StoreError>;

    /// Upsert the page AND append one revision, atomically. Returns the saved page.
    async fn save_page(&self, input: SaveInput) -> Result<Page, StoreError>;

    /// Root-to-current path for breadcrumbs. Missing pages return an empty path.
    async fn page_path(&self, slug: &str) -> Result<Vec<Page>, StoreError>;

    /// Re-parent a page. `None` moves it back to the top level. Implementations reject cycles.
    async fn move_page(&self, slug: &str, parent_id: Option<String>) -> Result<Page, StoreError>;

    /// Persisted explicit outbound links parsed from the current page body.
    async fn outgoing_links(&self, slug: &str) -> Result<Vec<String>, StoreError>;

    /// Persisted explicit backlinks: existing pages whose stored outbound links point at `slug`.
    async fn list_backlinks(&self, slug: &str) -> Result<Vec<Page>, StoreError>;

    /// Revisions for a slug, newest-first, capped for the history view.
    async fn list_revisions(&self, slug: &str) -> Result<Vec<Revision>, StoreError>;

    /// Fetch one revision by slug + id, if it exists (the diff/revert views resolve both
    /// endpoints of a comparison, and the revert target, this way). Scoped to `slug` so a
    /// revision id can never be redirected onto another page.
    async fn get_revision(&self, slug: &str, id: &str) -> Result<Option<Revision>, StoreError>;

    /// The current head (newest) revision of a page, if any. Edit-conflict detection compares
    /// the revision the editor was opened against with this — a mismatch means someone else saved
    /// in between. Reuses the revisions table; `None` for a page with no history yet.
    async fn head_revision(&self, slug: &str) -> Result<Option<Revision>, StoreError>;

    /// Cross-page revision feed, newest-first by `(ts DESC, id DESC)`. `before` is the exclusive
    /// keyset cursor from the previous page's last revision.
    async fn recent_revisions(
        &self,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<RecentEntry>, StoreError>;
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

#[derive(Default)]
struct MemData {
    pages: HashMap<String, Page>,
    revisions: Vec<Revision>,
    page_links: BTreeSet<(String, String)>,
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
    async fn list_pages(
        &self,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<Page>, StoreError> {
        let limit = clamp_page_limit(limit) as usize;
        let data = self.data.lock().expect("lattice store lock poisoned");
        let mut pages: Vec<Page> = data.pages.values().cloned().collect();
        // Newest-first keyset — the exact ORDER BY the PgStore uses: created_at DESC, slug DESC.
        pages.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.slug.cmp(&a.slug))
        });
        // Drop everything at/after the cursor (strictly older than the last row seen)...
        if let Some((b_ts, b_id)) = before {
            pages.retain(|p| p.created_at < b_ts || (p.created_at == b_ts && p.slug < b_id));
        }
        // ...then take one page.
        pages.truncate(limit);
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
        let parent_id = data
            .pages
            .get(&input.slug)
            .and_then(|p| p.parent_id.clone());
        let page = Page {
            slug: input.slug.clone(),
            title: input.title,
            body_md: input.body_md.clone(),
            updated_by_email: input.editor_email.clone(),
            updated_at: input.now,
            created_at,
            parent_id,
        };
        data.pages.insert(input.slug.clone(), page.clone());
        replace_mem_links(&mut data, &input.slug, &input.body_md);
        data.revisions.push(Revision {
            id: input.revision_id,
            slug: input.slug,
            body_md: input.body_md,
            editor_email: input.editor_email,
            ts: input.now,
        });
        Ok(page)
    }

    async fn page_path(&self, slug: &str) -> Result<Vec<Page>, StoreError> {
        let data = self.data.lock().expect("lattice store lock poisoned");
        page_path_from(&data.pages, slug)
    }

    async fn move_page(&self, slug: &str, parent_id: Option<String>) -> Result<Page, StoreError> {
        let mut data = self.data.lock().expect("lattice store lock poisoned");
        move_mem_page(&mut data.pages, slug, parent_id)
    }

    async fn outgoing_links(&self, slug: &str) -> Result<Vec<String>, StoreError> {
        let data = self.data.lock().expect("lattice store lock poisoned");
        Ok(data
            .page_links
            .iter()
            .filter(|(from, _)| from == slug)
            .map(|(_, to)| to.clone())
            .collect())
    }

    async fn list_backlinks(&self, slug: &str) -> Result<Vec<Page>, StoreError> {
        let data = self.data.lock().expect("lattice store lock poisoned");
        let mut pages: Vec<Page> = data
            .page_links
            .iter()
            .filter(|(from, to)| to == slug && from != slug)
            .filter_map(|(from, _)| data.pages.get(from).cloned())
            .collect();
        pages.sort_by(|a, b| {
            a.title
                .to_lowercase()
                .cmp(&b.title.to_lowercase())
                .then_with(|| a.slug.cmp(&b.slug))
        });
        Ok(pages)
    }

    async fn list_revisions(&self, slug: &str) -> Result<Vec<Revision>, StoreError> {
        let data = self.data.lock().expect("lattice store lock poisoned");
        let mut revs: Vec<Revision> = data
            .revisions
            .iter()
            .filter(|r| r.slug == slug)
            .cloned()
            .collect();
        // Newest first; ties (same ms) broken by insertion order — the Vec is append-only, so
        // reversing first and then stable-sorting on ts keeps the later write ahead. (A random-id
        // tiebreak would make the head flap between same-ms revisions.)
        revs.reverse();
        revs.sort_by_key(|revision| std::cmp::Reverse(revision.ts));
        revs.truncate(HISTORY_LIMIT);
        Ok(revs)
    }

    async fn get_revision(&self, slug: &str, id: &str) -> Result<Option<Revision>, StoreError> {
        let data = self.data.lock().expect("lattice store lock poisoned");
        Ok(data
            .revisions
            .iter()
            .find(|r| r.slug == slug && r.id == id)
            .cloned())
    }

    async fn head_revision(&self, slug: &str) -> Result<Option<Revision>, StoreError> {
        let data = self.data.lock().expect("lattice store lock poisoned");
        // Newest first, matching `list_revisions`: max ts wins, and `max_by` returns the LAST
        // maximal element, so same-ms ties resolve to the most recently appended revision.
        // (Tiebreaking on the random id here made the head — and thus the edit-conflict
        // check — non-deterministic for same-millisecond saves.)
        Ok(data
            .revisions
            .iter()
            .filter(|r| r.slug == slug)
            .max_by(|a, b| a.ts.cmp(&b.ts))
            .cloned())
    }

    async fn recent_revisions(
        &self,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<RecentEntry>, StoreError> {
        let limit = clamp_page_limit(limit) as usize;
        let data = self.data.lock().expect("lattice store lock poisoned");
        let mut revs: Vec<Revision> = data.revisions.clone();
        revs.sort_by(|a, b| b.ts.cmp(&a.ts).then_with(|| b.id.cmp(&a.id)));
        if let Some((b_ts, b_id)) = before {
            revs.retain(|r| r.ts < b_ts || (r.ts == b_ts && r.id < b_id));
        }
        revs.truncate(limit);
        Ok(revs
            .into_iter()
            .filter_map(|r| {
                data.pages.get(&r.slug).map(|p| RecentEntry {
                    title: p.title.clone(),
                    page_created_at: p.created_at,
                    rev: r,
                })
            })
            .collect())
    }
}

fn normalize_parent_id(parent_id: Option<String>) -> Option<String> {
    parent_id
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
}

fn replace_mem_links(data: &mut MemData, from_slug: &str, body_md: &str) {
    data.page_links.retain(|(from, _)| from != from_slug);
    for to_slug in graph::referenced_slugs(body_md) {
        data.page_links.insert((from_slug.to_string(), to_slug));
    }
}

fn page_path_from(pages: &HashMap<String, Page>, slug: &str) -> Result<Vec<Page>, StoreError> {
    let mut path = Vec::new();
    let mut current = slug.to_string();
    let mut seen = HashSet::new();

    loop {
        if !seen.insert(current.clone()) {
            return Err(StoreError::InvalidMove(
                "page parent cycle detected".to_string(),
            ));
        }
        let Some(page) = pages.get(&current).cloned() else {
            break;
        };
        let parent_id = page.parent_id.clone();
        path.push(page);
        let Some(parent) = parent_id else {
            break;
        };
        current = parent;
    }

    path.reverse();
    Ok(path)
}

fn move_mem_page(
    pages: &mut HashMap<String, Page>,
    slug: &str,
    parent_id: Option<String>,
) -> Result<Page, StoreError> {
    let parent_id = normalize_parent_id(parent_id);
    if !pages.contains_key(slug) {
        return Err(StoreError::InvalidMove("page not found".to_string()));
    }
    if parent_id.as_deref() == Some(slug) {
        return Err(StoreError::InvalidMove(
            "a page cannot be moved under itself".to_string(),
        ));
    }

    let mut current = parent_id.clone();
    let mut seen = HashSet::new();
    while let Some(parent) = current {
        if parent == slug {
            return Err(StoreError::InvalidMove(
                "a page cannot be moved under one of its descendants".to_string(),
            ));
        }
        if !seen.insert(parent.clone()) {
            return Err(StoreError::InvalidMove(
                "page parent cycle detected".to_string(),
            ));
        }
        let Some(parent_page) = pages.get(&parent) else {
            return Err(StoreError::InvalidMove("parent page not found".to_string()));
        };
        current = parent_page.parent_id.clone();
    }

    let page = pages
        .get_mut(slug)
        .expect("page existence checked before parent update");
    page.parent_id = parent_id;
    Ok(page.clone())
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
        sqlx::query("ALTER TABLE pages ADD COLUMN IF NOT EXISTS parent_id TEXT")
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
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS page_links (\
                 from_slug TEXT NOT NULL, \
                 to_slug TEXT NOT NULL, \
                 PRIMARY KEY (from_slug, to_slug)\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_revisions_slug_ts ON revisions (slug, ts)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_revisions_ts_id ON revisions (ts, id)")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_page_links_to_from ON page_links (to_slug, from_slug)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_page_links_from ON page_links (from_slug)")
            .execute(&self.pool)
            .await?;
        // Supports the newest-first keyset scan (created_at DESC, slug DESC) the index pages by.
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_pages_created_slug ON pages (created_at, slug)",
        )
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
            parent_id: row.try_get("parent_id")?,
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

    async fn list_pages_async(
        &self,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<Page>, sqlx::Error> {
        let limit = clamp_page_limit(limit);
        let rows = match before {
            None => sqlx::query(
                "SELECT slug, title, body_md, updated_by_email, updated_at, created_at, parent_id \
                     FROM pages ORDER BY created_at DESC, slug DESC LIMIT $1",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?,
            Some((b_ts, b_id)) => sqlx::query(
                "SELECT slug, title, body_md, updated_by_email, updated_at, created_at, parent_id \
                     FROM pages \
                     WHERE (created_at < $1 OR (created_at = $1 AND slug < $2)) \
                     ORDER BY created_at DESC, slug DESC LIMIT $3",
            )
            .bind(b_ts)
            .bind(b_id)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?,
        };
        rows.iter().map(Self::page_from_row).collect()
    }

    async fn all_slugs_async(&self) -> Result<Vec<String>, sqlx::Error> {
        let rows = sqlx::query("SELECT slug FROM pages")
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|r| r.try_get::<String, _>("slug"))
            .collect()
    }

    async fn get_page_async(&self, slug: &str) -> Result<Option<Page>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT slug, title, body_md, updated_by_email, updated_at, created_at, parent_id \
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
        let existing: Option<(i64, Option<String>)> =
            sqlx::query("SELECT created_at, parent_id FROM pages WHERE slug = $1")
                .bind(&input.slug)
                .fetch_optional(&mut *tx)
                .await?
                .map(|r| {
                    Ok::<_, sqlx::Error>((
                        r.try_get::<i64, _>("created_at")?,
                        r.try_get::<Option<String>, _>("parent_id")?,
                    ))
                })
                .transpose()?;
        let (created_at, parent_id) = existing.unwrap_or((input.now, None));

        sqlx::query(
            "INSERT INTO pages (slug, title, body_md, updated_by_email, updated_at, created_at, parent_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
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
        .bind(&parent_id)
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

        sqlx::query("DELETE FROM page_links WHERE from_slug = $1")
            .bind(&input.slug)
            .execute(&mut *tx)
            .await?;
        for to_slug in graph::referenced_slugs(&input.body_md) {
            sqlx::query(
                "INSERT INTO page_links (from_slug, to_slug) VALUES ($1, $2) \
                 ON CONFLICT (from_slug, to_slug) DO NOTHING",
            )
            .bind(&input.slug)
            .bind(&to_slug)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        Ok(Page {
            slug: input.slug,
            title: input.title,
            body_md: input.body_md,
            updated_by_email: input.editor_email,
            updated_at: input.now,
            created_at,
            parent_id,
        })
    }

    async fn page_path_async(&self, slug: &str) -> Result<Vec<Page>, StoreError> {
        let mut path = Vec::new();
        let mut current = slug.to_string();
        let mut seen = HashSet::new();

        loop {
            if !seen.insert(current.clone()) {
                return Err(StoreError::InvalidMove(
                    "page parent cycle detected".to_string(),
                ));
            }
            let row = sqlx::query(
                "SELECT slug, title, body_md, updated_by_email, updated_at, created_at, parent_id \
                 FROM pages WHERE slug = $1",
            )
            .bind(&current)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
            let Some(row) = row else {
                break;
            };
            let page = Self::page_from_row(&row).map_err(|e| StoreError::Backend(e.to_string()))?;
            let parent_id = page.parent_id.clone();
            path.push(page);
            let Some(parent) = parent_id else {
                break;
            };
            current = parent;
        }

        path.reverse();
        Ok(path)
    }

    async fn move_page_async(
        &self,
        slug: &str,
        parent_id: Option<String>,
    ) -> Result<Page, StoreError> {
        let parent_id = normalize_parent_id(parent_id);
        if parent_id.as_deref() == Some(slug) {
            return Err(StoreError::InvalidMove(
                "a page cannot be moved under itself".to_string(),
            ));
        }

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let row = sqlx::query(
            "SELECT slug, title, body_md, updated_by_email, updated_at, created_at, parent_id \
             FROM pages WHERE slug = $1",
        )
        .bind(slug)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        let Some(row) = row else {
            return Err(StoreError::InvalidMove("page not found".to_string()));
        };
        let mut page = Self::page_from_row(&row).map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut current = parent_id.clone();
        let mut seen = HashSet::new();
        while let Some(parent) = current {
            if parent == slug {
                return Err(StoreError::InvalidMove(
                    "a page cannot be moved under one of its descendants".to_string(),
                ));
            }
            if !seen.insert(parent.clone()) {
                return Err(StoreError::InvalidMove(
                    "page parent cycle detected".to_string(),
                ));
            }
            let parent_row = sqlx::query(
                "SELECT slug, title, body_md, updated_by_email, updated_at, created_at, parent_id \
                 FROM pages WHERE slug = $1",
            )
            .bind(&parent)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
            let Some(parent_row) = parent_row else {
                return Err(StoreError::InvalidMove("parent page not found".to_string()));
            };
            let parent_page =
                Self::page_from_row(&parent_row).map_err(|e| StoreError::Backend(e.to_string()))?;
            current = parent_page.parent_id;
        }

        sqlx::query("UPDATE pages SET parent_id = $2 WHERE slug = $1")
            .bind(slug)
            .bind(&parent_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

        page.parent_id = parent_id;
        Ok(page)
    }

    async fn outgoing_links_async(&self, slug: &str) -> Result<Vec<String>, sqlx::Error> {
        let rows =
            sqlx::query("SELECT to_slug FROM page_links WHERE from_slug = $1 ORDER BY to_slug")
                .bind(slug)
                .fetch_all(&self.pool)
                .await?;
        rows.iter()
            .map(|r| r.try_get::<String, _>("to_slug"))
            .collect()
    }

    async fn list_backlinks_async(&self, slug: &str) -> Result<Vec<Page>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT p.slug, p.title, p.body_md, p.updated_by_email, p.updated_at, p.created_at, p.parent_id \
             FROM page_links l \
             JOIN pages p ON p.slug = l.from_slug \
             WHERE l.to_slug = $1 AND l.from_slug <> $1 \
             ORDER BY p.title, p.slug",
        )
        .bind(slug)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::page_from_row).collect()
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

    async fn recent_revisions_async(
        &self,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<RecentEntry>, sqlx::Error> {
        let limit = clamp_page_limit(limit);
        let rows =
            match before {
                None => sqlx::query(
                    "SELECT r.id, r.slug, r.body_md, r.editor_email, r.ts, p.title, p.created_at \
                 FROM revisions r \
                 JOIN pages p ON p.slug = r.slug \
                 ORDER BY r.ts DESC, r.id DESC LIMIT $1",
                )
                .bind(limit)
                .fetch_all(&self.pool)
                .await?,
                Some((b_ts, b_id)) => sqlx::query(
                    "SELECT r.id, r.slug, r.body_md, r.editor_email, r.ts, p.title, p.created_at \
                 FROM revisions r \
                 JOIN pages p ON p.slug = r.slug \
                 WHERE (r.ts < $1 OR (r.ts = $1 AND r.id < $2)) \
                 ORDER BY r.ts DESC, r.id DESC LIMIT $3",
                )
                .bind(b_ts)
                .bind(b_id)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?,
            };
        rows.iter()
            .map(|row| {
                Ok(RecentEntry {
                    rev: Self::revision_from_row(row)?,
                    title: row.try_get("title")?,
                    page_created_at: row.try_get("created_at")?,
                })
            })
            .collect()
    }

    async fn get_revision_async(
        &self,
        slug: &str,
        id: &str,
    ) -> Result<Option<Revision>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT id, slug, body_md, editor_email, ts \
             FROM revisions WHERE slug = $1 AND id = $2",
        )
        .bind(slug)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::revision_from_row).transpose()
    }

    async fn head_revision_async(&self, slug: &str) -> Result<Option<Revision>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT id, slug, body_md, editor_email, ts \
             FROM revisions WHERE slug = $1 ORDER BY ts DESC, id DESC LIMIT 1",
        )
        .bind(slug)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::revision_from_row).transpose()
    }
}

#[async_trait]
impl Store for PgStore {
    async fn list_pages(
        &self,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<Page>, StoreError> {
        self.list_pages_async(before, limit)
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

    async fn page_path(&self, slug: &str) -> Result<Vec<Page>, StoreError> {
        self.page_path_async(slug).await
    }

    async fn move_page(&self, slug: &str, parent_id: Option<String>) -> Result<Page, StoreError> {
        self.move_page_async(slug, parent_id).await
    }

    async fn outgoing_links(&self, slug: &str) -> Result<Vec<String>, StoreError> {
        self.outgoing_links_async(slug)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_backlinks(&self, slug: &str) -> Result<Vec<Page>, StoreError> {
        self.list_backlinks_async(slug)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_revisions(&self, slug: &str) -> Result<Vec<Revision>, StoreError> {
        self.list_revisions_async(slug)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get_revision(&self, slug: &str, id: &str) -> Result<Option<Revision>, StoreError> {
        self.get_revision_async(slug, id)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn head_revision(&self, slug: &str) -> Result<Option<Revision>, StoreError> {
        self.head_revision_async(slug)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn recent_revisions(
        &self,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<RecentEntry>, StoreError> {
        self.recent_revisions_async(before, limit)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DEFAULT_PAGE, MAX_PAGE};

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
    async fn get_revision_resolves_scoped_to_slug() {
        let store = InMemoryStore::new();
        store
            .save_page(input("home", "Home", "v1", "a@x.co", 100))
            .await
            .unwrap();
        store
            .save_page(input("home", "Home", "v2", "b@x.co", 200))
            .await
            .unwrap();
        store
            .save_page(input("other", "Other", "z", "c@x.co", 150))
            .await
            .unwrap();

        let revs = store.list_revisions("home").await.unwrap();
        let oldest = revs.last().unwrap();
        let got = store
            .get_revision("home", &oldest.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.body_md, "v1");

        // A real revision id is invisible from another page's scope.
        assert!(store
            .get_revision("other", &oldest.id)
            .await
            .unwrap()
            .is_none());
        // Unknown id -> None (never an error).
        assert!(store.get_revision("home", "nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn head_revision_tracks_newest_per_slug() {
        let store = InMemoryStore::new();
        assert!(
            store.head_revision("home").await.unwrap().is_none(),
            "no history yet"
        );

        store
            .save_page(input("home", "Home", "v1", "a@x.co", 100))
            .await
            .unwrap();
        let h1 = store.head_revision("home").await.unwrap().unwrap();
        assert_eq!(h1.body_md, "v1");

        store
            .save_page(input("home", "Home", "v2", "b@x.co", 200))
            .await
            .unwrap();
        let h2 = store.head_revision("home").await.unwrap().unwrap();
        assert_eq!(h2.body_md, "v2", "head advances to the newest revision");
        assert_eq!(
            h2.id,
            store.list_revisions("home").await.unwrap()[0].id,
            "matches list head"
        );

        // Scoped to the slug: another page's history is invisible.
        store
            .save_page(input("other", "Other", "z", "c@x.co", 300))
            .await
            .unwrap();
        assert_eq!(
            store.head_revision("home").await.unwrap().unwrap().body_md,
            "v2"
        );
    }

    #[tokio::test]
    async fn list_pages_newest_first_and_slugs_collected() {
        let store = InMemoryStore::new();
        // beta created earliest, alpha latest → newest-first (created_at DESC) puts alpha first.
        store
            .save_page(input("beta", "Beta", "b", "a@x.co", 1))
            .await
            .unwrap();
        store
            .save_page(input("alpha", "Alpha", "a", "a@x.co", 2))
            .await
            .unwrap();
        let pages = store.list_pages(None, DEFAULT_PAGE).await.unwrap();
        assert_eq!(pages[0].slug, "alpha");
        assert_eq!(pages[1].slug, "beta");
        let mut slugs = store.all_slugs().await.unwrap();
        slugs.sort();
        assert_eq!(slugs, vec!["alpha".to_string(), "beta".to_string()]);
    }

    #[tokio::test]
    async fn list_pages_keyset_paginates_newest_first() {
        let store = InMemoryStore::new();
        // Four pages with distinct created_at; the newest carries the largest timestamp.
        store
            .save_page(input("a", "A", "x", "e@x.co", 10))
            .await
            .unwrap();
        store
            .save_page(input("b", "B", "x", "e@x.co", 20))
            .await
            .unwrap();
        store
            .save_page(input("c", "C", "x", "e@x.co", 30))
            .await
            .unwrap();
        store
            .save_page(input("d", "D", "x", "e@x.co", 40))
            .await
            .unwrap();

        // First page of 2: newest-first.
        let p1 = store.list_pages(None, 2).await.unwrap();
        assert_eq!(
            p1.iter().map(|p| p.slug.as_str()).collect::<Vec<_>>(),
            ["d", "c"]
        );

        // Cursor from the last row of page 1 yields the next-older page — no overlap, no gap.
        let last = p1.last().unwrap();
        let p2 = store
            .list_pages(Some((last.created_at, last.slug.clone())), 2)
            .await
            .unwrap();
        assert_eq!(
            p2.iter().map(|p| p.slug.as_str()).collect::<Vec<_>>(),
            ["b", "a"]
        );

        // Cursor past the oldest row returns nothing (the walk terminates).
        let last2 = p2.last().unwrap();
        let p3 = store
            .list_pages(Some((last2.created_at, last2.slug.clone())), 2)
            .await
            .unwrap();
        assert!(p3.is_empty());
    }

    #[tokio::test]
    async fn list_pages_keyset_breaks_created_at_ties_by_slug() {
        let store = InMemoryStore::new();
        // Same created_at across all three; slug DESC is the deterministic tiebreak.
        store
            .save_page(input("a", "A", "x", "e@x.co", 5))
            .await
            .unwrap();
        store
            .save_page(input("b", "B", "x", "e@x.co", 5))
            .await
            .unwrap();
        store
            .save_page(input("c", "C", "x", "e@x.co", 5))
            .await
            .unwrap();

        let p1 = store.list_pages(None, 2).await.unwrap();
        assert_eq!(
            p1.iter().map(|p| p.slug.as_str()).collect::<Vec<_>>(),
            ["c", "b"]
        );
        let last = p1.last().unwrap();
        let p2 = store
            .list_pages(Some((last.created_at, last.slug.clone())), 2)
            .await
            .unwrap();
        assert_eq!(
            p2.iter().map(|p| p.slug.as_str()).collect::<Vec<_>>(),
            ["a"]
        );
    }

    #[tokio::test]
    async fn list_pages_limit_is_clamped_to_max() {
        let store = InMemoryStore::new();
        for i in 0..(MAX_PAGE + 5) {
            store
                .save_page(input(&format!("p{i:04}"), "T", "x", "e@x.co", i))
                .await
                .unwrap();
        }
        let page = store.list_pages(None, MAX_PAGE + 100).await.unwrap();
        assert_eq!(
            page.len() as i64,
            MAX_PAGE,
            "an oversized limit is clamped to MAX_PAGE"
        );
    }

    #[tokio::test]
    async fn move_page_sets_parent_path_and_rejects_cycles() {
        let store = InMemoryStore::new();
        store
            .save_page(input("root", "Root", "x", "e@x.co", 10))
            .await
            .unwrap();
        store
            .save_page(input("child", "Child", "x", "e@x.co", 20))
            .await
            .unwrap();
        store
            .save_page(input("grandchild", "Grandchild", "x", "e@x.co", 30))
            .await
            .unwrap();

        let child = store
            .move_page("child", Some("root".to_string()))
            .await
            .unwrap();
        assert_eq!(child.parent_id.as_deref(), Some("root"));
        let grandchild = store
            .move_page("grandchild", Some("child".to_string()))
            .await
            .unwrap();
        assert_eq!(grandchild.parent_id.as_deref(), Some("child"));

        let path = store.page_path("grandchild").await.unwrap();
        assert_eq!(
            path.iter().map(|p| p.slug.as_str()).collect::<Vec<_>>(),
            ["root", "child", "grandchild"]
        );

        let err = store
            .move_page("root", Some("grandchild".to_string()))
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::InvalidMove(_)));
        assert_eq!(
            store.get_page("root").await.unwrap().unwrap().parent_id,
            None,
            "cycle rejection leaves the tree unchanged"
        );

        let moved_top = store.move_page("child", None).await.unwrap();
        assert_eq!(moved_top.parent_id, None);
    }

    #[tokio::test]
    async fn save_replaces_persisted_outbound_links_and_backlinks() {
        let store = InMemoryStore::new();
        store
            .save_page(input("runbook", "Runbook", "target", "e@x.co", 10))
            .await
            .unwrap();
        store
            .save_page(input("guide", "Guide", "target", "e@x.co", 20))
            .await
            .unwrap();
        store
            .save_page(input(
                "home",
                "Home",
                "See [[Runbook]] and [the guide](/w/guide?from=home).",
                "e@x.co",
                30,
            ))
            .await
            .unwrap();

        assert_eq!(
            store.outgoing_links("home").await.unwrap(),
            vec!["guide".to_string(), "runbook".to_string()]
        );
        let backlinks = store.list_backlinks("runbook").await.unwrap();
        assert_eq!(
            backlinks
                .iter()
                .map(|p| p.slug.as_str())
                .collect::<Vec<_>>(),
            ["home"]
        );

        store
            .save_page(input("home", "Home", "No links now.", "e@x.co", 40))
            .await
            .unwrap();
        assert!(store.outgoing_links("home").await.unwrap().is_empty());
        assert!(store.list_backlinks("runbook").await.unwrap().is_empty());
    }
}
