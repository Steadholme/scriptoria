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

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::config::MAX_PAGE;

/// A blog post (maps 1:1 to a `posts` row).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Post {
    pub id: String,
    pub slug: String,
    pub title: String,
    pub body_md: String,
    pub author_sub: String,
    pub author_email: String,
    pub created_at: i64,
    pub updated_at: i64,
    /// Monotonic optimistic-concurrency token for authoritative mutations. Unlike `updated_at`,
    /// this is never a wall-clock value and advances exactly once per committed post version.
    pub edit_version: i64,
    pub published: bool,
    /// UTC epoch seconds when a published post becomes public. `0` preserves legacy immediate
    /// publication; a future value makes the post behave like a draft on public surfaces.
    pub publish_at: i64,
    /// Admin-set "featured" flag: surfaced with a badge on the index and toggled from /admin.
    /// Additive; defaults to FALSE for every existing row.
    pub featured: bool,
    /// Author/admin-set pin: public index ordering floats pinned posts before ordinary posts.
    /// Additive; defaults to FALSE for every existing row.
    pub pinned: bool,
    /// Comma-separated tags (e.g. `rust, async`). Backed by a nullable TEXT column; empty string
    /// when the post has no tags. Parsed/slugged by [`crate::tags`] for the tag chips and the
    /// `/tag/{slug}` listing. Additive: pre-existing rows read back as NULL -> empty string.
    pub tags: String,
    /// Optional cover image URL — an Aperture share link (`https://drive.w33d.xyz/s/{token}`),
    /// validated to an estate host before storage so the rendered `<img src>` can never point at
    /// an arbitrary third-party host. Backed by a nullable TEXT column; empty string when the post
    /// has no cover. Additive: pre-existing rows read back as NULL -> empty string.
    pub cover_url: String,
    /// Author-written summary used by cards and feeds. Empty falls back to a body-derived excerpt.
    /// Nullable in PostgreSQL for additive migration compatibility; exposed as an empty string here.
    pub custom_excerpt: String,
    /// Optional search-engine title. Empty falls back to the post title.
    pub meta_title: String,
    /// Optional search-engine description. Empty falls back to the custom/body excerpt.
    pub meta_description: String,
    /// Optional absolute HTTP(S) canonical URL. Validation happens at the authoring boundary and
    /// rendering re-checks it defensively before emitting a `<link rel="canonical">`.
    pub canonical_url: String,
    /// Optional social-card title. Empty falls back through `meta_title` to the post title.
    pub social_title: String,
    /// Optional social-card description. Empty falls back through `meta_description` and excerpt.
    pub social_description: String,
    /// Optional social-card image. It uses the same trusted Aperture URL policy as cover images.
    pub social_image: String,
}

/// An immutable full snapshot of one committed post version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostRevision {
    pub id: String,
    pub post_id: String,
    pub edit_version: i64,
    pub title: String,
    pub body_md: String,
    pub published: bool,
    pub publish_at: i64,
    pub featured: bool,
    pub pinned: bool,
    pub tags: String,
    pub cover_url: String,
    pub custom_excerpt: String,
    pub meta_title: String,
    pub meta_description: String,
    pub canonical_url: String,
    pub social_title: String,
    pub social_description: String,
    pub social_image: String,
    pub editor_sub: String,
    pub editor_email: String,
    pub source: String,
    pub restored_from: Option<String>,
    pub created_at: i64,
}

/// Lightweight history row; full bodies and metadata are fetched only for a selected revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostRevisionSummary {
    pub id: String,
    pub post_id: String,
    pub edit_version: i64,
    pub title: String,
    pub body_chars: i64,
    pub editor_email: String,
    pub source: String,
    pub created_at: i64,
}

/// Private, replace-in-place recovery copy for one existing-post editor session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriterAutosave {
    pub session_id: String,
    pub post_id: String,
    pub owner_sub: String,
    pub base_version: i64,
    pub client_seq: i64,
    pub title: String,
    pub body_md: String,
    pub tags: String,
    pub cover_url: String,
    pub custom_excerpt: String,
    pub meta_title: String,
    pub meta_description: String,
    pub canonical_url: String,
    pub social_title: String,
    pub social_description: String,
    pub social_image: String,
    pub publish_at: String,
    pub pinned: bool,
    pub updated_at: i64,
    pub expires_at: i64,
}

#[derive(Clone, Debug)]
pub struct SavePostCommand {
    pub post: Post,
    pub expected_version: i64,
    pub editor_sub: String,
    pub editor_email: String,
    pub source: String,
    pub restored_from: Option<String>,
    pub consume_autosave_session: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SavePostOutcome {
    Saved(Box<Post>),
    Conflict { current_version: i64 },
    NotFound,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AutosaveOutcome {
    Saved(Box<WriterAutosave>),
    Stale { stored_client_seq: i64 },
    Conflict { current_version: i64 },
    NotFound,
}

impl Post {
    /// Public visibility at `now`: published and not scheduled for the future.
    pub fn is_public_at(&self, now: i64) -> bool {
        self.published && (self.publish_at == 0 || self.publish_at <= now)
    }

    /// True when this is a checked "published" post whose publish time is still in the future.
    pub fn is_scheduled_at(&self, now: i64) -> bool {
        self.published && self.publish_at > now
    }

    /// The chronological publication instant used by RSS. Legacy immediate posts use their
    /// creation time; scheduled posts use the instant at which they actually became public.
    pub fn effective_publish_at(&self) -> i64 {
        if self.publish_at > 0 {
            self.publish_at
        } else {
            self.created_at
        }
    }

    /// Advance the content/cache version even when two mutations land in the same wall-clock
    /// second. Chunks use `updated_at` as their version, so equality must imply current content.
    pub fn bump_updated_at(&mut self, now: i64) {
        self.updated_at = now.max(self.updated_at.saturating_add(1));
    }
}

/// Public index cursor matching `ORDER BY pinned DESC, created_at DESC, id DESC`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostCursor {
    pub pinned: bool,
    pub created_at: i64,
    pub id: String,
}

impl PostCursor {
    pub fn from_post(post: &Post) -> Self {
        Self {
            pinned: post.pinned,
            created_at: post.created_at,
            id: post.id.clone(),
        }
    }
}

/// Lightweight authoritative sitemap projection. A sitemap needs no body, author, tags, or social
/// metadata, so keeping this separate from [`Post`] bounds memory even at the protocol ceiling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SitemapEntry {
    pub slug: String,
    pub updated_at: i64,
    pub canonical_url: String,
}

/// Single-row site settings, editable from /admin and applied to the index/head. Kept in its own
/// one-row table (`id = 'singleton'`), so reading it is a single point-lookup with a sane default.
#[derive(Clone, Debug, PartialEq)]
pub struct Settings {
    /// Blog title (index `<title>` + masthead heading).
    pub title: String,
    /// Masthead tagline under the title.
    pub tagline: String,
    /// Default posts-per-page on the index when no `?limit=` is given (clamped to `1..=MAX_PAGE`).
    pub posts_per_page: i64,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            title: "Inkwell".to_string(),
            tagline: "Notes, essays, and changelog from the HOLDFAST estate.".to_string(),
            posts_per_page: crate::config::DEFAULT_PAGE,
        }
    }
}

/// A retrieval chunk: a slice of one published post's body, indexed for the "ask your blog"
/// feature. `post_id` holds the post's slug (the stable URL key), so a citation links straight to
/// `/p/{post_id}`. Maps 1:1 to a `chunks` row.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    /// Fail-closed post read for authoring commands; database errors must never look like a 404.
    async fn get_post_authoritative(&self, slug: &str) -> Result<Option<Post>, StoreError>;
    /// Public/reader-visible keyset page (`pinned DESC, created_at DESC, id DESC`). Anonymous
    /// readers see only posts whose publish time has arrived; an author also sees their own drafts
    /// and scheduled posts.
    async fn list_visible_posts(
        &self,
        before: Option<PostCursor>,
        limit: i64,
        now: i64,
        viewer_sub: Option<&str>,
    ) -> Vec<Post>;
    /// One reader-visible post by slug, with the same publish-time predicate as the public index.
    async fn get_visible_post(
        &self,
        slug: &str,
        now: i64,
        viewer_sub: Option<&str>,
    ) -> Option<Post>;
    /// The 100 most recently effective public publications, independent of homepage pinning.
    /// Implementations apply the public-due predicate before ordering and limiting.
    async fn feed_posts(&self, now: i64) -> Result<Vec<Post>, StoreError>;
    /// Public-due sitemap rows as a lightweight bounded projection. Backend failures are returned
    /// so the HTTP layer never mistakes a partial/failed database read for a valid `200` sitemap.
    async fn sitemap_entries(&self, now: i64) -> Result<Vec<SitemapEntry>, StoreError>;
    /// Up to `limit` public posts sharing tags with `tags`, ranked by shared-tag count.
    async fn related_posts_by_tags(
        &self,
        slug: &str,
        tags: &str,
        now: i64,
        limit: i64,
    ) -> Vec<Post>;
    /// Insert a new post. Errors with [`StoreError::Conflict`] if the slug is taken.
    async fn create_post(&self, post: &Post) -> Result<(), StoreError>;
    /// Update an existing post's mutable fields (title/body/published/updated_at) by slug.
    async fn update_post(&self, post: &Post) -> Result<(), StoreError>;
    /// Compare-and-swap an authoritative post and append its resulting immutable revision in the
    /// same store transaction. A consumed autosave is deleted only after the save succeeds.
    async fn save_post(&self, command: SavePostCommand) -> Result<SavePostOutcome, StoreError>;
    async fn list_post_revisions(
        &self,
        post_id: &str,
        limit: i64,
    ) -> Result<Vec<PostRevisionSummary>, StoreError>;
    async fn get_post_revision(
        &self,
        post_id: &str,
        revision_id: &str,
    ) -> Result<Option<PostRevision>, StoreError>;
    async fn put_writer_autosave(
        &self,
        autosave: WriterAutosave,
        now: i64,
    ) -> Result<AutosaveOutcome, StoreError>;
    async fn get_writer_autosave(
        &self,
        session_id: &str,
        owner_sub: &str,
        now: i64,
    ) -> Result<Option<WriterAutosave>, StoreError>;
    async fn delete_writer_autosave(
        &self,
        session_id: &str,
        owner_sub: &str,
    ) -> Result<(), StoreError>;
    /// Delete a post by slug.
    async fn delete_post(&self, slug: &str) -> Result<(), StoreError>;

    // -- site settings (single-row; edited from /admin, applied to the index) --------------

    /// The current site settings, or [`Settings::default`] when none have been saved yet.
    async fn get_settings(&self) -> Settings;
    /// Persist the single settings row (insert-or-replace).
    async fn update_settings(&self, settings: &Settings) -> Result<(), StoreError>;

    // -- "ask your blog" retrieval index (additive; see [`crate::index`]) -----------------
    //
    // The chunk table is a derived, rebuildable lexical index over the blog's OWN published
    // posts. It carries NO authoritative data: authoring updates it best-effort, while request-time
    // incremental refresh repairs missing/outdated public post versions in bounded batches.

    /// Raw derived-cache count, used by diagnostics/tests. Backend failures remain observable.
    async fn count_chunks(&self) -> Result<i64, StoreError>;
    /// Raw derived-cache rows, used by diagnostics/tests. Public retrieval must instead use
    /// [`Store::fetch_public_chunks`], which joins every chunk to its authoritative post version.
    async fn fetch_chunks(&self) -> Result<Vec<Chunk>, StoreError>;
    /// Incrementally rebuild at most `limit` public posts whose chunks are missing or carry an old
    /// `updated_at` version. Draft/future posts are never candidates.
    async fn refresh_public_chunks(&self, now: i64, limit: i64) -> Result<i64, StoreError>;
    /// Read at most `limit` chunks that still join to a post public at `now` and whose
    /// `indexed_at == posts.updated_at`. This is the only cache read Search/Ask may consume.
    async fn fetch_public_chunks(&self, now: i64, limit: i64) -> Result<Vec<Chunk>, StoreError>;
    /// Replace the ENTIRE chunk index with `chunks` for explicit maintenance/tests. Request paths
    /// never call this method. Returns the count.
    async fn replace_all_chunks(&self, chunks: Vec<Chunk>) -> Result<i64, StoreError>;
    /// Replace just one post's chunks: drop every chunk for `post_id`, then insert `chunks`
    /// (empty `chunks` simply de-indexes the post — e.g. when it becomes a draft).
    async fn replace_post_chunks(
        &self,
        post_id: &str,
        chunks: Vec<Chunk>,
    ) -> Result<(), StoreError>;
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
    /// `None` until an admin saves settings; reads then fall back to [`Settings::default`].
    settings: Mutex<Option<Settings>>,
    revisions: Mutex<Vec<PostRevision>>,
    autosaves: Mutex<Vec<WriterAutosave>>,
    /// Serializes multi-collection authoring commands. The post lock is held until the associated
    /// revision/autosave work completes, so readers cannot observe half a command.
    mutation_lock: Mutex<()>,
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

    async fn get_post_authoritative(&self, slug: &str) -> Result<Option<Post>, StoreError> {
        Ok(self
            .posts
            .lock()
            .expect("posts lock poisoned")
            .iter()
            .find(|post| post.slug == slug)
            .cloned())
    }

    async fn list_visible_posts(
        &self,
        before: Option<PostCursor>,
        limit: i64,
        now: i64,
        viewer_sub: Option<&str>,
    ) -> Vec<Post> {
        let limit = limit.clamp(1, MAX_PAGE) as usize;
        let posts = self.posts.lock().expect("posts lock poisoned");
        let mut v: Vec<Post> = posts
            .iter()
            .filter(|p| p.is_public_at(now) || viewer_sub == Some(p.author_sub.as_str()))
            .cloned()
            .collect();
        sort_public(&mut v);
        if let Some(cursor) = before {
            v.retain(|p| after_public_cursor(p, &cursor));
        }
        v.truncate(limit);
        v
    }

    async fn get_visible_post(
        &self,
        slug: &str,
        now: i64,
        viewer_sub: Option<&str>,
    ) -> Option<Post> {
        self.posts
            .lock()
            .expect("posts lock poisoned")
            .iter()
            .find(|p| {
                p.slug == slug && (p.is_public_at(now) || viewer_sub == Some(p.author_sub.as_str()))
            })
            .cloned()
    }

    async fn feed_posts(&self, now: i64) -> Result<Vec<Post>, StoreError> {
        let posts = self.posts.lock().expect("posts lock poisoned");
        let mut public: Vec<&Post> = posts.iter().filter(|post| post.is_public_at(now)).collect();
        sort_feed_refs(&mut public);
        Ok(public
            .into_iter()
            .take(crate::config::FEED_ITEM_LIMIT)
            .cloned()
            .collect())
    }

    async fn sitemap_entries(&self, now: i64) -> Result<Vec<SitemapEntry>, StoreError> {
        let posts = self.posts.lock().expect("posts lock poisoned");
        let mut public: Vec<&Post> = posts.iter().filter(|post| post.is_public_at(now)).collect();
        sort_feed_refs(&mut public);
        Ok(public
            .into_iter()
            .take(crate::config::SITEMAP_POST_LIMIT)
            .map(|post| SitemapEntry {
                slug: post.slug.clone(),
                updated_at: post.updated_at,
                canonical_url: post.canonical_url.clone(),
            })
            .collect())
    }

    async fn related_posts_by_tags(
        &self,
        slug: &str,
        tags: &str,
        now: i64,
        limit: i64,
    ) -> Vec<Post> {
        let candidates: Vec<Post> = self
            .posts
            .lock()
            .expect("posts lock poisoned")
            .iter()
            .filter(|p| p.slug != slug && p.is_public_at(now))
            .cloned()
            .collect();
        rank_related_by_tags(candidates, slug, tags, limit)
    }

    async fn create_post(&self, post: &Post) -> Result<(), StoreError> {
        let _mutation = self.mutation_lock.lock().expect("mutation lock poisoned");
        let mut posts = self.posts.lock().expect("posts lock poisoned");
        if posts.iter().any(|p| p.slug == post.slug) {
            return Err(StoreError::Conflict(post.slug.clone()));
        }
        let mut stored = post.clone();
        stored.edit_version = stored.edit_version.max(1);
        let revision = revision_from_post(
            &stored,
            &stored.author_sub,
            &stored.author_email,
            "create",
            None,
        );
        self.revisions
            .lock()
            .expect("revisions lock poisoned")
            .push(revision);
        posts.push(stored);
        Ok(())
    }

    async fn update_post(&self, post: &Post) -> Result<(), StoreError> {
        match self
            .save_post(SavePostCommand {
                post: post.clone(),
                expected_version: post.edit_version,
                editor_sub: post.author_sub.clone(),
                editor_email: post.author_email.clone(),
                source: "legacy-update".to_string(),
                restored_from: None,
                consume_autosave_session: None,
            })
            .await?
        {
            SavePostOutcome::Saved(_) => Ok(()),
            SavePostOutcome::Conflict { .. } => Err(StoreError::Conflict(post.slug.clone())),
            SavePostOutcome::NotFound => Err(StoreError::Backend(format!(
                "no post with slug {}",
                post.slug
            ))),
        }
    }

    async fn save_post(&self, command: SavePostCommand) -> Result<SavePostOutcome, StoreError> {
        let _mutation = self.mutation_lock.lock().expect("mutation lock poisoned");
        let mut posts = self.posts.lock().expect("posts lock poisoned");
        let Some(index) = posts
            .iter()
            .position(|post| post.id == command.post.id && post.slug == command.post.slug)
        else {
            return Ok(SavePostOutcome::NotFound);
        };
        let current = posts[index].clone();
        if current.edit_version != command.expected_version {
            return Ok(SavePostOutcome::Conflict {
                current_version: current.edit_version,
            });
        }

        let mut revisions = self.revisions.lock().expect("revisions lock poisoned");
        ensure_current_revision(
            &mut revisions,
            &current,
            &command.editor_sub,
            &command.editor_email,
        );
        let mut saved = command.post;
        saved.id = current.id.clone();
        saved.slug = current.slug.clone();
        saved.author_sub = current.author_sub.clone();
        saved.author_email = current.author_email.clone();
        saved.created_at = current.created_at;
        saved.edit_version = current.edit_version.saturating_add(1);
        saved.updated_at = saved.updated_at.max(current.updated_at.saturating_add(1));
        revisions.push(revision_from_post(
            &saved,
            &command.editor_sub,
            &command.editor_email,
            &command.source,
            command.restored_from,
        ));
        prune_mem_revisions(&mut revisions, &saved.id);

        let mut autosaves = self.autosaves.lock().expect("autosaves lock poisoned");
        if let Some(session_id) = command.consume_autosave_session {
            autosaves.retain(|autosave| {
                !(autosave.session_id == session_id
                    && autosave.owner_sub == command.editor_sub
                    && autosave.post_id == saved.id)
            });
        }
        posts[index] = saved.clone();
        Ok(SavePostOutcome::Saved(Box::new(saved)))
    }

    async fn list_post_revisions(
        &self,
        post_id: &str,
        limit: i64,
    ) -> Result<Vec<PostRevisionSummary>, StoreError> {
        let mut rows: Vec<PostRevisionSummary> = self
            .revisions
            .lock()
            .expect("revisions lock poisoned")
            .iter()
            .filter(|revision| revision.post_id == post_id)
            .map(revision_summary)
            .collect();
        rows.sort_by(|a, b| {
            b.edit_version
                .cmp(&a.edit_version)
                .then_with(|| b.id.cmp(&a.id))
        });
        rows.truncate(limit.clamp(1, crate::config::REVISION_PAGE_LIMIT) as usize);
        Ok(rows)
    }

    async fn get_post_revision(
        &self,
        post_id: &str,
        revision_id: &str,
    ) -> Result<Option<PostRevision>, StoreError> {
        Ok(self
            .revisions
            .lock()
            .expect("revisions lock poisoned")
            .iter()
            .find(|revision| revision.post_id == post_id && revision.id == revision_id)
            .cloned())
    }

    async fn put_writer_autosave(
        &self,
        autosave: WriterAutosave,
        now: i64,
    ) -> Result<AutosaveOutcome, StoreError> {
        let posts = self.posts.lock().expect("posts lock poisoned");
        let Some(post) = posts.iter().find(|post| post.id == autosave.post_id) else {
            return Ok(AutosaveOutcome::NotFound);
        };
        if post.edit_version != autosave.base_version {
            return Ok(AutosaveOutcome::Conflict {
                current_version: post.edit_version,
            });
        }
        let mut rows = self.autosaves.lock().expect("autosaves lock poisoned");
        // The target session is resolved before opportunistic cleanup. An expired high sequence
        // must never reject a fresh session write with the same random id.
        rows.retain(|row| {
            !(row.session_id == autosave.session_id && row.expires_at <= now)
        });
        cleanup_expired_mem_autosaves(&mut rows, now);
        if let Some(existing) = rows
            .iter_mut()
            .find(|row| row.session_id == autosave.session_id)
        {
            if existing.owner_sub != autosave.owner_sub || existing.post_id != autosave.post_id {
                return Ok(AutosaveOutcome::NotFound);
            }
            if existing.client_seq >= autosave.client_seq {
                return Ok(AutosaveOutcome::Stale {
                    stored_client_seq: existing.client_seq,
                });
            }
            *existing = autosave.clone();
        } else {
            rows.push(autosave.clone());
        }
        Ok(AutosaveOutcome::Saved(Box::new(autosave)))
    }

    async fn get_writer_autosave(
        &self,
        session_id: &str,
        owner_sub: &str,
        now: i64,
    ) -> Result<Option<WriterAutosave>, StoreError> {
        let mut rows = self.autosaves.lock().expect("autosaves lock poisoned");
        cleanup_expired_mem_autosaves(&mut rows, now);
        Ok(rows
            .iter()
            .find(|row| {
                row.session_id == session_id
                    && row.owner_sub == owner_sub
                    && row.expires_at > now
            })
            .cloned())
    }

    async fn delete_writer_autosave(
        &self,
        session_id: &str,
        owner_sub: &str,
    ) -> Result<(), StoreError> {
        self.autosaves
            .lock()
            .expect("autosaves lock poisoned")
            .retain(|row| !(row.session_id == session_id && row.owner_sub == owner_sub));
        Ok(())
    }

    async fn delete_post(&self, slug: &str) -> Result<(), StoreError> {
        let _mutation = self.mutation_lock.lock().expect("mutation lock poisoned");
        let mut posts = self.posts.lock().expect("posts lock poisoned");
        let post_id = posts
            .iter()
            .find(|post| post.slug == slug)
            .map(|post| post.id.clone());
        posts.retain(|p| p.slug != slug);
        if let Some(post_id) = post_id {
            self.revisions
                .lock()
                .expect("revisions lock poisoned")
                .retain(|revision| revision.post_id != post_id);
            self.autosaves
                .lock()
                .expect("autosaves lock poisoned")
                .retain(|autosave| autosave.post_id != post_id);
        }
        Ok(())
    }

    async fn get_settings(&self) -> Settings {
        self.settings
            .lock()
            .expect("settings lock poisoned")
            .clone()
            .unwrap_or_default()
    }

    async fn update_settings(&self, settings: &Settings) -> Result<(), StoreError> {
        *self.settings.lock().expect("settings lock poisoned") = Some(settings.clone());
        Ok(())
    }

    async fn count_chunks(&self) -> Result<i64, StoreError> {
        Ok(self.chunks.lock().expect("chunks lock poisoned").len() as i64)
    }

    async fn fetch_chunks(&self) -> Result<Vec<Chunk>, StoreError> {
        let mut v: Vec<Chunk> = self.chunks.lock().expect("chunks lock poisoned").clone();
        // Newest-indexed first; ties broken by id so output is stable.
        v.sort_by(|a, b| {
            b.indexed_at
                .cmp(&a.indexed_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(v)
    }

    async fn refresh_public_chunks(&self, now: i64, limit: i64) -> Result<i64, StoreError> {
        let limit = limit.clamp(0, crate::config::INDEX_REFRESH_POST_LIMIT) as usize;
        if limit == 0 {
            return Ok(0);
        }
        // Keep one atomic in-memory view while deriving candidates. Every dual-lock path uses the
        // same posts -> chunks order, so a concurrent Draft/version mutation cannot race the cache.
        let posts_guard = self.posts.lock().expect("posts lock poisoned");
        let mut cache = self.chunks.lock().expect("chunks lock poisoned");
        let mut posts: Vec<Post> = posts_guard
            .iter()
            .filter(|post| post.is_public_at(now))
            .cloned()
            .collect();
        posts.sort_by(|a, b| {
            a.updated_at
                .cmp(&b.updated_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        let mut candidates: Vec<Post> = posts
            .into_iter()
            .filter(|post| {
                let mut versions = cache
                    .iter()
                    .filter(|chunk| chunk.post_id == post.slug)
                    .map(|chunk| chunk.indexed_at);
                let first = versions.next();
                first.is_none()
                    || first != Some(post.updated_at)
                    || versions.any(|version| version != post.updated_at)
            })
            .take(limit)
            .collect();
        let refreshed = candidates.len() as i64;
        for post in candidates.drain(..) {
            cache.retain(|chunk| chunk.post_id != post.slug);
            cache.extend(crate::index::build_post_chunks(
                &post.slug,
                &post.title,
                &post.body_md,
                post.updated_at,
            ));
        }
        Ok(refreshed)
    }

    async fn fetch_public_chunks(&self, now: i64, limit: i64) -> Result<Vec<Chunk>, StoreError> {
        if limit <= 0 {
            return Ok(Vec::new());
        }
        // Match PostgreSQL statement-snapshot semantics: visibility/version and chunks are read
        // under one in-memory critical section, with the canonical posts -> chunks lock order.
        let posts = self.posts.lock().expect("posts lock poisoned");
        let cache = self.chunks.lock().expect("chunks lock poisoned");
        let versions: HashMap<&str, i64> = posts
            .iter()
            .filter(|post| post.is_public_at(now))
            .map(|post| (post.slug.as_str(), post.updated_at))
            .collect();
        let mut chunks: Vec<Chunk> = cache
            .iter()
            .filter(|chunk| versions.get(chunk.post_id.as_str()) == Some(&chunk.indexed_at))
            .cloned()
            .collect();
        chunks.sort_by(|a, b| {
            b.indexed_at
                .cmp(&a.indexed_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        chunks.truncate(limit.min(crate::config::INDEX_CHUNK_LIMIT) as usize);
        Ok(chunks)
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

/// Public ordering shared by memory tests and SQL (`pinned DESC, created_at DESC, id DESC`).
fn sort_public(posts: &mut [Post]) {
    posts.sort_by(|a, b| {
        b.pinned
            .cmp(&a.pinned)
            .then_with(|| b.created_at.cmp(&a.created_at))
            .then_with(|| b.id.cmp(&a.id))
    });
}

/// Authoritative RSS/sitemap chronology over borrowed rows, deliberately independent of homepage
/// pins. Memory discovery clones only the selected top rows/projection, never every post body.
fn sort_feed_refs(posts: &mut [&Post]) {
    posts.sort_by(|a, b| {
        b.effective_publish_at()
            .cmp(&a.effective_publish_at())
            .then_with(|| b.id.cmp(&a.id))
    });
}

/// Whether `post` sorts strictly after `cursor` in the public keyset order.
fn after_public_cursor(post: &Post, cursor: &PostCursor) -> bool {
    if post.pinned != cursor.pinned {
        return cursor.pinned && !post.pinned;
    }
    post.created_at < cursor.created_at
        || (post.created_at == cursor.created_at && post.id < cursor.id)
}

fn tag_slug_set(raw: &str) -> HashSet<String> {
    crate::tags::parse_tags(raw)
        .into_iter()
        .map(|t| crate::tags::tag_slug(&t))
        .filter(|s| !s.is_empty())
        .collect()
}

fn rank_related_by_tags(candidates: Vec<Post>, slug: &str, tags: &str, limit: i64) -> Vec<Post> {
    let source = tag_slug_set(tags);
    if source.is_empty() {
        return Vec::new();
    }
    let limit = limit.clamp(1, MAX_PAGE) as usize;
    let mut scored: Vec<(usize, Post)> = candidates
        .into_iter()
        .filter(|p| p.slug != slug)
        .filter_map(|p| {
            let overlap = tag_slug_set(&p.tags)
                .iter()
                .filter(|tag| source.contains(*tag))
                .count();
            if overlap == 0 {
                None
            } else {
                Some((overlap, p))
            }
        })
        .collect();
    scored.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| b.1.created_at.cmp(&a.1.created_at))
            .then_with(|| a.1.slug.cmp(&b.1.slug))
    });
    scored.truncate(limit);
    scored.into_iter().map(|(_, p)| p).collect()
}

fn revision_id(post_id: &str, edit_version: i64) -> String {
    format!("rev_{post_id}_{edit_version}")
}

fn revision_from_post(
    post: &Post,
    editor_sub: &str,
    editor_email: &str,
    source: &str,
    restored_from: Option<String>,
) -> PostRevision {
    PostRevision {
        id: revision_id(&post.id, post.edit_version),
        post_id: post.id.clone(),
        edit_version: post.edit_version,
        title: post.title.clone(),
        body_md: post.body_md.clone(),
        published: post.published,
        publish_at: post.publish_at,
        featured: post.featured,
        pinned: post.pinned,
        tags: post.tags.clone(),
        cover_url: post.cover_url.clone(),
        custom_excerpt: post.custom_excerpt.clone(),
        meta_title: post.meta_title.clone(),
        meta_description: post.meta_description.clone(),
        canonical_url: post.canonical_url.clone(),
        social_title: post.social_title.clone(),
        social_description: post.social_description.clone(),
        social_image: post.social_image.clone(),
        editor_sub: editor_sub.to_string(),
        editor_email: editor_email.to_string(),
        source: source.to_string(),
        restored_from,
        created_at: post.updated_at,
    }
}

fn revision_summary(revision: &PostRevision) -> PostRevisionSummary {
    PostRevisionSummary {
        id: revision.id.clone(),
        post_id: revision.post_id.clone(),
        edit_version: revision.edit_version,
        title: revision.title.clone(),
        body_chars: revision.body_md.chars().count() as i64,
        editor_email: revision.editor_email.clone(),
        source: revision.source.clone(),
        created_at: revision.created_at,
    }
}

fn ensure_current_revision(
    revisions: &mut Vec<PostRevision>,
    post: &Post,
    editor_sub: &str,
    editor_email: &str,
) {
    if !revisions
        .iter()
        .any(|revision| revision.post_id == post.id && revision.edit_version == post.edit_version)
    {
        revisions.push(revision_from_post(
            post,
            editor_sub,
            editor_email,
            "snapshot",
            None,
        ));
    }
}

fn prune_mem_revisions(revisions: &mut Vec<PostRevision>, post_id: &str) {
    let mut versions: Vec<i64> = revisions
        .iter()
        .filter(|revision| revision.post_id == post_id)
        .map(|revision| revision.edit_version)
        .collect();
    versions.sort_unstable_by(|a, b| b.cmp(a));
    if versions.len() <= crate::config::REVISION_KEEP_LIMIT {
        return;
    }
    let oldest_kept = versions[crate::config::REVISION_KEEP_LIMIT - 1];
    revisions
        .retain(|revision| revision.post_id != post_id || revision.edit_version >= oldest_kept);
}

fn cleanup_expired_mem_autosaves(autosaves: &mut Vec<WriterAutosave>, now: i64) {
    let mut removed = 0usize;
    autosaves.retain(|autosave| {
        if autosave.expires_at <= now && removed < 256 {
            removed += 1;
            false
        } else {
            true
        }
    });
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

const POST_COLS: &str = "SELECT id, slug, title, body_md, author_sub, author_email, \
                         created_at, updated_at, edit_version, published, publish_at, featured, pinned, \
                         tags, cover_url, custom_excerpt, meta_title, meta_description, \
                         canonical_url, social_title, social_description, social_image \
                         FROM posts";
const REVISION_COLS: &str = "SELECT id, post_id, edit_version, title, body_md, published, \
                             publish_at, featured, pinned, tags, cover_url, custom_excerpt, \
                             meta_title, meta_description, canonical_url, social_title, \
                             social_description, social_image, editor_sub, editor_email, source, \
                             restored_from, created_at FROM post_revisions";
const AUTOSAVE_COLS: &str = "SELECT session_id, post_id, owner_sub, base_version, client_seq, \
                             title, body_md, tags, cover_url, custom_excerpt, meta_title, \
                             meta_description, canonical_url, social_title, social_description, \
                             social_image, publish_at, pinned, updated_at, expires_at \
                             FROM writer_autosaves";

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
        // Additive "featured" flag (admin panel). IF NOT EXISTS keeps the migration idempotent and
        // backward compatible — existing rows default to FALSE.
        sqlx::query(
            "ALTER TABLE posts ADD COLUMN IF NOT EXISTS featured BOOLEAN NOT NULL DEFAULT FALSE",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE posts ADD COLUMN IF NOT EXISTS edit_version BIGINT NOT NULL DEFAULT 1",
        )
        .execute(&self.pool)
        .await?;
        // Additive scheduled-publish timestamp. `0` is the legacy immediate-publish behavior.
        sqlx::query(
            "ALTER TABLE posts ADD COLUMN IF NOT EXISTS publish_at BIGINT NOT NULL DEFAULT 0",
        )
        .execute(&self.pool)
        .await?;
        // Additive public-index pin. Existing rows stay ordinary (not pinned).
        sqlx::query(
            "ALTER TABLE posts ADD COLUMN IF NOT EXISTS pinned BOOLEAN NOT NULL DEFAULT FALSE",
        )
        .execute(&self.pool)
        .await?;
        // Additive nullable tags column (comma-separated). IF NOT EXISTS keeps the migration
        // idempotent and backward compatible — existing rows read back as NULL -> empty string.
        sqlx::query("ALTER TABLE posts ADD COLUMN IF NOT EXISTS tags TEXT")
            .execute(&self.pool)
            .await?;
        // Additive nullable cover-image URL (an Aperture share link). IF NOT EXISTS keeps the
        // migration idempotent and backward compatible — existing rows read back as NULL -> "".
        sqlx::query("ALTER TABLE posts ADD COLUMN IF NOT EXISTS cover_url TEXT")
            .execute(&self.pool)
            .await?;
        // Additive publication metadata. Nullable columns let legacy rows migrate without a
        // table rewrite; row mapping normalizes NULL to the product's empty/fallback semantics.
        for column in [
            "custom_excerpt",
            "meta_title",
            "meta_description",
            "canonical_url",
            "social_title",
            "social_description",
            "social_image",
        ] {
            sqlx::query(&format!(
                "ALTER TABLE posts ADD COLUMN IF NOT EXISTS {column} TEXT"
            ))
            .execute(&self.pool)
            .await?;
        }
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS post_revisions (\
                 id TEXT PRIMARY KEY, \
                 post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE, \
                 edit_version BIGINT NOT NULL, \
                 title TEXT NOT NULL, body_md TEXT NOT NULL, \
                 published BOOLEAN NOT NULL, publish_at BIGINT NOT NULL, \
                 featured BOOLEAN NOT NULL, pinned BOOLEAN NOT NULL, \
                 tags TEXT NOT NULL, cover_url TEXT NOT NULL, custom_excerpt TEXT NOT NULL, \
                 meta_title TEXT NOT NULL, meta_description TEXT NOT NULL, canonical_url TEXT NOT NULL, \
                 social_title TEXT NOT NULL, social_description TEXT NOT NULL, social_image TEXT NOT NULL, \
                 editor_sub TEXT NOT NULL, editor_email TEXT NOT NULL, source TEXT NOT NULL, \
                 restored_from TEXT, created_at BIGINT NOT NULL, \
                 UNIQUE (post_id, edit_version)\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_post_revisions_post_version \
             ON post_revisions (post_id, edit_version)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS writer_autosaves (\
                 session_id TEXT PRIMARY KEY, \
                 post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE, \
                 owner_sub TEXT NOT NULL, \
                 base_version BIGINT NOT NULL, client_seq BIGINT NOT NULL, \
                 title TEXT NOT NULL, body_md TEXT NOT NULL, tags TEXT NOT NULL, cover_url TEXT NOT NULL, \
                 custom_excerpt TEXT NOT NULL, meta_title TEXT NOT NULL, meta_description TEXT NOT NULL, \
                 canonical_url TEXT NOT NULL, social_title TEXT NOT NULL, \
                 social_description TEXT NOT NULL, social_image TEXT NOT NULL, \
                 publish_at TEXT NOT NULL, pinned BOOLEAN NOT NULL, \
                 updated_at BIGINT NOT NULL, expires_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_writer_autosaves_owner_expiry \
             ON writer_autosaves (owner_sub, expires_at)",
        )
        .execute(&self.pool)
        .await?;
        // Forward repair is deliberately plain SQL. A rollback image can update a post without
        // advancing `edit_version`; compare the authoritative row with its same-version snapshot,
        // advance mismatches, then backfill the resulting current revision atomically. Legacy
        // orphan rows (from tables created before the fresh-schema FKs) are removed first.
        let mut repair = self.pool.begin().await?;
        sqlx::query("SELECT id FROM posts ORDER BY id FOR UPDATE")
            .fetch_all(&mut *repair)
            .await?;
        sqlx::query(
            "DELETE FROM writer_autosaves WHERE NOT EXISTS (\
                 SELECT 1 FROM posts WHERE posts.id = writer_autosaves.post_id\
             )",
        )
        .execute(&mut *repair)
        .await?;
        sqlx::query(
            "DELETE FROM post_revisions WHERE NOT EXISTS (\
                 SELECT 1 FROM posts WHERE posts.id = post_revisions.post_id\
             )",
        )
        .execute(&mut *repair)
        .await?;
        sqlx::query(
            "UPDATE posts SET edit_version = posts.edit_version + 1 \
             WHERE EXISTS (\
                 SELECT 1 FROM post_revisions r \
                 WHERE r.post_id = posts.id AND r.edit_version = posts.edit_version AND (\
                     r.title IS DISTINCT FROM posts.title OR \
                     r.body_md IS DISTINCT FROM posts.body_md OR \
                     r.published IS DISTINCT FROM posts.published OR \
                     r.publish_at IS DISTINCT FROM posts.publish_at OR \
                     r.featured IS DISTINCT FROM posts.featured OR \
                     r.pinned IS DISTINCT FROM posts.pinned OR \
                     r.tags IS DISTINCT FROM COALESCE(posts.tags, '') OR \
                     r.cover_url IS DISTINCT FROM COALESCE(posts.cover_url, '') OR \
                     r.custom_excerpt IS DISTINCT FROM COALESCE(posts.custom_excerpt, '') OR \
                     r.meta_title IS DISTINCT FROM COALESCE(posts.meta_title, '') OR \
                     r.meta_description IS DISTINCT FROM COALESCE(posts.meta_description, '') OR \
                     r.canonical_url IS DISTINCT FROM COALESCE(posts.canonical_url, '') OR \
                     r.social_title IS DISTINCT FROM COALESCE(posts.social_title, '') OR \
                     r.social_description IS DISTINCT FROM COALESCE(posts.social_description, '') OR \
                     r.social_image IS DISTINCT FROM COALESCE(posts.social_image, '')\
                 )\
             )",
        )
        .execute(&mut *repair)
        .await?;
        sqlx::query(
            "INSERT INTO post_revisions \
                 (id, post_id, edit_version, title, body_md, published, publish_at, featured, pinned, \
                  tags, cover_url, custom_excerpt, meta_title, meta_description, canonical_url, \
                  social_title, social_description, social_image, editor_sub, editor_email, source, \
                  restored_from, created_at) \
             SELECT 'rev_' || id || '_' || edit_version, id, edit_version, title, body_md, published, \
                    publish_at, featured, pinned, COALESCE(tags, ''), COALESCE(cover_url, ''), \
                    COALESCE(custom_excerpt, ''), COALESCE(meta_title, ''), \
                    COALESCE(meta_description, ''), COALESCE(canonical_url, ''), \
                    COALESCE(social_title, ''), COALESCE(social_description, ''), \
                    COALESCE(social_image, ''), author_sub, author_email, \
                    CASE WHEN EXISTS (SELECT 1 FROM post_revisions prior WHERE prior.post_id = posts.id) \
                         THEN 'forward-repair' ELSE 'baseline' END, NULL, updated_at \
             FROM posts ON CONFLICT (post_id, edit_version) DO NOTHING",
        )
        .execute(&mut *repair)
        .await?;
        repair.commit().await?;
        // Backs the newest-first index scan.
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_posts_created_at ON posts (created_at)")
            .execute(&self.pool)
            .await?;
        // Backs the public index order (`pinned DESC, created_at DESC, id DESC`).
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_posts_public_order ON posts (pinned, created_at)",
        )
        .execute(&self.pool)
        .await?;
        // Single-row site settings (blog title / tagline / posts-per-page), edited from /admin.
        // Standard SQL only; the one row is keyed by a constant `id = 'singleton'`.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS settings (\
                 id TEXT PRIMARY KEY, \
                 title TEXT NOT NULL, \
                 tagline TEXT NOT NULL, \
                 posts_per_page BIGINT NOT NULL\
             )",
        )
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
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_chunks_indexed_at ON chunks (indexed_at)")
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
        .bind(crate::config::INDEX_CHUNK_LIMIT)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::chunk_from_row).collect()
    }

    async fn refresh_public_chunks_async(&self, now: i64, limit: i64) -> Result<i64, sqlx::Error> {
        let limit = limit.clamp(0, crate::config::INDEX_REFRESH_POST_LIMIT);
        if limit == 0 {
            return Ok(0);
        }
        let _guard = self.index_lock.lock().await;
        let rows = sqlx::query(&format!(
            "{POST_COLS} WHERE published = TRUE AND (publish_at = 0 OR publish_at <= $1) \
             AND (NOT EXISTS (\
                    SELECT 1 FROM chunks c \
                    WHERE c.post_id = posts.slug AND c.indexed_at = posts.updated_at\
                  ) OR EXISTS (\
                    SELECT 1 FROM chunks c \
                    WHERE c.post_id = posts.slug AND c.indexed_at <> posts.updated_at\
                  )) \
             ORDER BY updated_at ASC, id ASC LIMIT $2"
        ))
        .bind(now)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        let posts: Vec<Post> = rows
            .iter()
            .map(Self::post_from_row)
            .collect::<Result<_, _>>()?;
        if posts.is_empty() {
            return Ok(0);
        }

        let mut tx = self.pool.begin().await?;
        for post in &posts {
            sqlx::query("DELETE FROM chunks WHERE post_id = $1")
                .bind(&post.slug)
                .execute(&mut *tx)
                .await?;
            let chunks = crate::index::build_post_chunks(
                &post.slug,
                &post.title,
                &post.body_md,
                post.updated_at,
            );
            for chunk in &chunks {
                Self::insert_chunk(&mut tx, chunk).await?;
            }
        }
        tx.commit().await?;
        Ok(posts.len() as i64)
    }

    async fn fetch_public_chunks_async(
        &self,
        now: i64,
        limit: i64,
    ) -> Result<Vec<Chunk>, sqlx::Error> {
        if limit <= 0 {
            return Ok(Vec::new());
        }
        let rows = sqlx::query(
            "SELECT c.id AS id, c.post_id AS post_id, c.title AS title, c.body AS body, \
                    c.indexed_at AS indexed_at \
             FROM chunks c \
             JOIN posts p ON p.slug = c.post_id AND p.updated_at = c.indexed_at \
             WHERE p.published = TRUE AND (p.publish_at = 0 OR p.publish_at <= $1) \
             ORDER BY c.indexed_at DESC, c.id ASC LIMIT $2",
        )
        .bind(now)
        .bind(limit.min(crate::config::INDEX_CHUNK_LIMIT))
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
        let _guard = self.index_lock.lock().await;
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
            edit_version: row.try_get("edit_version")?,
            published: row.try_get("published")?,
            publish_at: row.try_get("publish_at")?,
            featured: row.try_get("featured")?,
            pinned: row.try_get("pinned")?,
            // Nullable column: a pre-migration row (or a post with no tags) reads back as NULL.
            tags: row
                .try_get::<Option<String>, _>("tags")?
                .unwrap_or_default(),
            // Nullable column: a pre-migration row (or a post with no cover) reads back as NULL.
            cover_url: row
                .try_get::<Option<String>, _>("cover_url")?
                .unwrap_or_default(),
            custom_excerpt: row
                .try_get::<Option<String>, _>("custom_excerpt")?
                .unwrap_or_default(),
            meta_title: row
                .try_get::<Option<String>, _>("meta_title")?
                .unwrap_or_default(),
            meta_description: row
                .try_get::<Option<String>, _>("meta_description")?
                .unwrap_or_default(),
            canonical_url: row
                .try_get::<Option<String>, _>("canonical_url")?
                .unwrap_or_default(),
            social_title: row
                .try_get::<Option<String>, _>("social_title")?
                .unwrap_or_default(),
            social_description: row
                .try_get::<Option<String>, _>("social_description")?
                .unwrap_or_default(),
            social_image: row
                .try_get::<Option<String>, _>("social_image")?
                .unwrap_or_default(),
        })
    }

    fn revision_from_row(row: &sqlx::postgres::PgRow) -> Result<PostRevision, sqlx::Error> {
        Ok(PostRevision {
            id: row.try_get("id")?,
            post_id: row.try_get("post_id")?,
            edit_version: row.try_get("edit_version")?,
            title: row.try_get("title")?,
            body_md: row.try_get("body_md")?,
            published: row.try_get("published")?,
            publish_at: row.try_get("publish_at")?,
            featured: row.try_get("featured")?,
            pinned: row.try_get("pinned")?,
            tags: row.try_get("tags")?,
            cover_url: row.try_get("cover_url")?,
            custom_excerpt: row.try_get("custom_excerpt")?,
            meta_title: row.try_get("meta_title")?,
            meta_description: row.try_get("meta_description")?,
            canonical_url: row.try_get("canonical_url")?,
            social_title: row.try_get("social_title")?,
            social_description: row.try_get("social_description")?,
            social_image: row.try_get("social_image")?,
            editor_sub: row.try_get("editor_sub")?,
            editor_email: row.try_get("editor_email")?,
            source: row.try_get("source")?,
            restored_from: row.try_get("restored_from")?,
            created_at: row.try_get("created_at")?,
        })
    }

    fn autosave_from_row(row: &sqlx::postgres::PgRow) -> Result<WriterAutosave, sqlx::Error> {
        Ok(WriterAutosave {
            session_id: row.try_get("session_id")?,
            post_id: row.try_get("post_id")?,
            owner_sub: row.try_get("owner_sub")?,
            base_version: row.try_get("base_version")?,
            client_seq: row.try_get("client_seq")?,
            title: row.try_get("title")?,
            body_md: row.try_get("body_md")?,
            tags: row.try_get("tags")?,
            cover_url: row.try_get("cover_url")?,
            custom_excerpt: row.try_get("custom_excerpt")?,
            meta_title: row.try_get("meta_title")?,
            meta_description: row.try_get("meta_description")?,
            canonical_url: row.try_get("canonical_url")?,
            social_title: row.try_get("social_title")?,
            social_description: row.try_get("social_description")?,
            social_image: row.try_get("social_image")?,
            publish_at: row.try_get("publish_at")?,
            pinned: row.try_get("pinned")?,
            updated_at: row.try_get("updated_at")?,
            expires_at: row.try_get("expires_at")?,
        })
    }

    async fn get_settings_async(&self) -> Result<Settings, sqlx::Error> {
        let row = sqlx::query(
            "SELECT title, tagline, posts_per_page FROM settings WHERE id = 'singleton'",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            Some(r) => Settings {
                title: r.try_get("title")?,
                tagline: r.try_get("tagline")?,
                posts_per_page: r.try_get("posts_per_page")?,
            },
            None => Settings::default(),
        })
    }

    async fn update_settings_async(&self, s: &Settings) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO settings (id, title, tagline, posts_per_page) \
             VALUES ('singleton', $1, $2, $3) \
             ON CONFLICT (id) DO UPDATE SET \
                 title = EXCLUDED.title, tagline = EXCLUDED.tagline, \
                 posts_per_page = EXCLUDED.posts_per_page",
        )
        .bind(&s.title)
        .bind(&s.tagline)
        .bind(s.posts_per_page)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_posts_async(
        &self,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<Post>, sqlx::Error> {
        let limit = limit.clamp(1, MAX_PAGE);
        // The `ORDER BY created_at DESC, id DESC` IS the keyset. With a cursor, add the standard
        // "strictly older" tuple comparison before the ORDER BY so paging never skips a tie.
        let rows = match before {
            None => {
                sqlx::query(&format!(
                    "{POST_COLS} ORDER BY created_at DESC, id DESC LIMIT $1"
                ))
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            Some((b_ts, b_id)) => {
                sqlx::query(&format!(
                    "{POST_COLS} WHERE (created_at < $1 OR (created_at = $1 AND id < $2)) \
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
        let row = sqlx::query(&format!("{POST_COLS} WHERE slug = $1"))
            .bind(slug)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Ok(Some(Self::post_from_row(&r)?)),
            None => Ok(None),
        }
    }

    async fn list_visible_posts_async(
        &self,
        before: Option<PostCursor>,
        limit: i64,
        now: i64,
        viewer_sub: Option<&str>,
    ) -> Result<Vec<Post>, sqlx::Error> {
        let limit = limit.clamp(1, MAX_PAGE);
        let order = "ORDER BY pinned DESC, created_at DESC, id DESC";
        let rows = match (viewer_sub, before) {
            (None, None) => {
                sqlx::query(&format!(
                    "{POST_COLS} WHERE published = TRUE AND (publish_at = 0 OR publish_at <= $1) \
                     {order} LIMIT $2",
                ))
                .bind(now)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (None, Some(c)) => {
                sqlx::query(&format!(
                    "{POST_COLS} WHERE published = TRUE AND (publish_at = 0 OR publish_at <= $1) \
                     AND (($2 = TRUE AND pinned = FALSE) OR \
                          (pinned = $2 AND (created_at < $3 OR (created_at = $3 AND id < $4)))) \
                     {order} LIMIT $5",
                ))
                .bind(now)
                .bind(c.pinned)
                .bind(c.created_at)
                .bind(c.id)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (Some(viewer), None) => {
                sqlx::query(&format!(
                    "{POST_COLS} WHERE author_sub = $1 OR \
                         (published = TRUE AND (publish_at = 0 OR publish_at <= $2)) \
                     {order} LIMIT $3",
                ))
                .bind(viewer)
                .bind(now)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (Some(viewer), Some(c)) => {
                sqlx::query(&format!(
                    "{POST_COLS} WHERE (author_sub = $1 OR \
                         (published = TRUE AND (publish_at = 0 OR publish_at <= $2))) \
                     AND (($3 = TRUE AND pinned = FALSE) OR \
                          (pinned = $3 AND (created_at < $4 OR (created_at = $4 AND id < $5)))) \
                     {order} LIMIT $6",
                ))
                .bind(viewer)
                .bind(now)
                .bind(c.pinned)
                .bind(c.created_at)
                .bind(c.id)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
        };
        rows.iter().map(Self::post_from_row).collect()
    }

    async fn get_visible_post_async(
        &self,
        slug: &str,
        now: i64,
        viewer_sub: Option<&str>,
    ) -> Result<Option<Post>, sqlx::Error> {
        let row = match viewer_sub {
            Some(viewer) => {
                sqlx::query(&format!(
                    "{POST_COLS} WHERE slug = $1 AND \
                     (author_sub = $2 OR (published = TRUE AND (publish_at = 0 OR publish_at <= $3)))",
                ))
                .bind(slug)
                .bind(viewer)
                .bind(now)
                .fetch_optional(&self.pool)
                .await?
            }
            None => {
                sqlx::query(&format!(
                    "{POST_COLS} WHERE slug = $1 AND published = TRUE \
                     AND (publish_at = 0 OR publish_at <= $2)",
                ))
                .bind(slug)
                .bind(now)
                .fetch_optional(&self.pool)
                .await?
            }
        };
        match row {
            Some(r) => Ok(Some(Self::post_from_row(&r)?)),
            None => Ok(None),
        }
    }

    async fn feed_posts_async(&self, now: i64) -> Result<Vec<Post>, sqlx::Error> {
        let rows = sqlx::query(&format!(
            "{POST_COLS} WHERE published = TRUE AND (publish_at = 0 OR publish_at <= $1) \
             ORDER BY CASE WHEN publish_at > 0 THEN publish_at ELSE created_at END DESC, id DESC \
             LIMIT $2"
        ))
        .bind(now)
        .bind(crate::config::FEED_ITEM_LIMIT as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::post_from_row).collect()
    }

    async fn sitemap_entries_async(&self, now: i64) -> Result<Vec<SitemapEntry>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT slug, updated_at, COALESCE(canonical_url, '') AS canonical_url \
             FROM posts \
             WHERE published = TRUE AND (publish_at = 0 OR publish_at <= $1) \
             ORDER BY CASE WHEN publish_at > 0 THEN publish_at ELSE created_at END DESC, id DESC \
             LIMIT $2",
        )
        .bind(now)
        .bind(crate::config::SITEMAP_POST_LIMIT as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(SitemapEntry {
                    slug: row.try_get("slug")?,
                    updated_at: row.try_get("updated_at")?,
                    canonical_url: row.try_get("canonical_url")?,
                })
            })
            .collect()
    }

    async fn related_posts_by_tags_async(
        &self,
        slug: &str,
        tags: &str,
        now: i64,
        limit: i64,
    ) -> Result<Vec<Post>, sqlx::Error> {
        let rows = sqlx::query(&format!(
            "{POST_COLS} WHERE slug <> $1 AND published = TRUE \
             AND (publish_at = 0 OR publish_at <= $2)"
        ))
        .bind(slug)
        .bind(now)
        .fetch_all(&self.pool)
        .await?;
        let candidates: Result<Vec<Post>, sqlx::Error> =
            rows.iter().map(Self::post_from_row).collect();
        Ok(rank_related_by_tags(candidates?, slug, tags, limit))
    }

    async fn create_post_async(&self, p: &Post) -> Result<(), sqlx::Error> {
        let mut stored = p.clone();
        stored.edit_version = stored.edit_version.max(1);
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO posts \
                 (id, slug, title, body_md, author_sub, author_email, created_at, updated_at, edit_version, \
                  published, publish_at, featured, pinned, tags, cover_url, custom_excerpt, \
                  meta_title, meta_description, canonical_url, social_title, social_description, \
                  social_image) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
                     $15, $16, $17, $18, $19, $20, $21, $22)",
        )
        .bind(&stored.id)
        .bind(&stored.slug)
        .bind(&stored.title)
        .bind(&stored.body_md)
        .bind(&stored.author_sub)
        .bind(&stored.author_email)
        .bind(stored.created_at)
        .bind(stored.updated_at)
        .bind(stored.edit_version)
        .bind(stored.published)
        .bind(stored.publish_at)
        .bind(stored.featured)
        .bind(stored.pinned)
        .bind(&stored.tags)
        .bind(&stored.cover_url)
        .bind(&stored.custom_excerpt)
        .bind(&stored.meta_title)
        .bind(&stored.meta_description)
        .bind(&stored.canonical_url)
        .bind(&stored.social_title)
        .bind(&stored.social_description)
        .bind(&stored.social_image)
        .execute(&mut *tx)
        .await?;
        let revision = revision_from_post(
            &stored,
            &stored.author_sub,
            &stored.author_email,
            "create",
            None,
        );
        Self::insert_revision_tx(&mut tx, &revision).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn insert_revision_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        revision: &PostRevision,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO post_revisions \
                 (id, post_id, edit_version, title, body_md, published, publish_at, featured, pinned, \
                  tags, cover_url, custom_excerpt, meta_title, meta_description, canonical_url, \
                  social_title, social_description, social_image, editor_sub, editor_email, source, \
                  restored_from, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
                     $15, $16, $17, $18, $19, $20, $21, $22, $23) \
             ON CONFLICT (post_id, edit_version) DO NOTHING",
        )
        .bind(&revision.id)
        .bind(&revision.post_id)
        .bind(revision.edit_version)
        .bind(&revision.title)
        .bind(&revision.body_md)
        .bind(revision.published)
        .bind(revision.publish_at)
        .bind(revision.featured)
        .bind(revision.pinned)
        .bind(&revision.tags)
        .bind(&revision.cover_url)
        .bind(&revision.custom_excerpt)
        .bind(&revision.meta_title)
        .bind(&revision.meta_description)
        .bind(&revision.canonical_url)
        .bind(&revision.social_title)
        .bind(&revision.social_description)
        .bind(&revision.social_image)
        .bind(&revision.editor_sub)
        .bind(&revision.editor_email)
        .bind(&revision.source)
        .bind(&revision.restored_from)
        .bind(revision.created_at)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    async fn save_post_async(
        &self,
        command: SavePostCommand,
    ) -> Result<SavePostOutcome, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(&format!(
            "{POST_COLS} WHERE slug = $1 AND id = $2 FOR UPDATE"
        ))
            .bind(&command.post.slug)
            .bind(&command.post.id)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(row) = row else {
            return Ok(SavePostOutcome::NotFound);
        };
        let current = Self::post_from_row(&row)?;
        if current.edit_version != command.expected_version {
            return Ok(SavePostOutcome::Conflict {
                current_version: current.edit_version,
            });
        }

        let current_revision = revision_from_post(
            &current,
            &command.editor_sub,
            &command.editor_email,
            "snapshot",
            None,
        );
        Self::insert_revision_tx(&mut tx, &current_revision).await?;

        let mut saved = command.post;
        saved.id = current.id.clone();
        saved.slug = current.slug.clone();
        saved.author_sub = current.author_sub.clone();
        saved.author_email = current.author_email.clone();
        saved.created_at = current.created_at;
        saved.edit_version = current.edit_version.saturating_add(1);
        saved.updated_at = saved.updated_at.max(current.updated_at.saturating_add(1));
        let result = sqlx::query(
            "UPDATE posts SET title = $1, body_md = $2, published = $3, updated_at = $4, \
                    edit_version = $5, publish_at = $6, featured = $7, pinned = $8, tags = $9, \
                    cover_url = $10, custom_excerpt = $11, meta_title = $12, \
                    meta_description = $13, canonical_url = $14, social_title = $15, \
                    social_description = $16, social_image = $17 \
             WHERE id = $18 AND edit_version = $19",
        )
        .bind(&saved.title)
        .bind(&saved.body_md)
        .bind(saved.published)
        .bind(saved.updated_at)
        .bind(saved.edit_version)
        .bind(saved.publish_at)
        .bind(saved.featured)
        .bind(saved.pinned)
        .bind(&saved.tags)
        .bind(&saved.cover_url)
        .bind(&saved.custom_excerpt)
        .bind(&saved.meta_title)
        .bind(&saved.meta_description)
        .bind(&saved.canonical_url)
        .bind(&saved.social_title)
        .bind(&saved.social_description)
        .bind(&saved.social_image)
        .bind(&saved.id)
        .bind(command.expected_version)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() != 1 {
            return Ok(SavePostOutcome::Conflict {
                current_version: current.edit_version,
            });
        }

        let revision = revision_from_post(
            &saved,
            &command.editor_sub,
            &command.editor_email,
            &command.source,
            command.restored_from,
        );
        Self::insert_revision_tx(&mut tx, &revision).await?;
        if let Some(session_id) = command.consume_autosave_session {
            sqlx::query(
                "DELETE FROM writer_autosaves \
                 WHERE session_id = $1 AND owner_sub = $2 AND post_id = $3",
            )
            .bind(session_id)
            .bind(&command.editor_sub)
            .bind(&saved.id)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query(
            "DELETE FROM post_revisions WHERE post_id = $1 AND id IN (\
                 SELECT id FROM post_revisions WHERE post_id = $1 \
                 ORDER BY edit_version DESC, id DESC OFFSET $2\
             )",
        )
        .bind(&saved.id)
        .bind(crate::config::REVISION_KEEP_LIMIT as i64)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(SavePostOutcome::Saved(Box::new(saved)))
    }

    async fn list_post_revisions_async(
        &self,
        post_id: &str,
        limit: i64,
    ) -> Result<Vec<PostRevisionSummary>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, post_id, edit_version, title, CAST(char_length(body_md) AS BIGINT) AS body_chars, \
                    editor_email, source, created_at FROM post_revisions \
             WHERE post_id = $1 ORDER BY edit_version DESC, id DESC LIMIT $2",
        )
        .bind(post_id)
        .bind(limit.clamp(1, crate::config::REVISION_PAGE_LIMIT))
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(PostRevisionSummary {
                    id: row.try_get("id")?,
                    post_id: row.try_get("post_id")?,
                    edit_version: row.try_get("edit_version")?,
                    title: row.try_get("title")?,
                    body_chars: row.try_get("body_chars")?,
                    editor_email: row.try_get("editor_email")?,
                    source: row.try_get("source")?,
                    created_at: row.try_get("created_at")?,
                })
            })
            .collect()
    }

    async fn get_post_revision_async(
        &self,
        post_id: &str,
        revision_id: &str,
    ) -> Result<Option<PostRevision>, sqlx::Error> {
        let row = sqlx::query(&format!("{REVISION_COLS} WHERE post_id = $1 AND id = $2"))
            .bind(post_id)
            .bind(revision_id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(Self::revision_from_row).transpose()
    }

    async fn put_writer_autosave_async(
        &self,
        autosave: &WriterAutosave,
        now: i64,
    ) -> Result<AutosaveOutcome, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let post = sqlx::query("SELECT edit_version FROM posts WHERE id = $1 FOR UPDATE")
            .bind(&autosave.post_id)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(post) = post else {
            return Ok(AutosaveOutcome::NotFound);
        };
        let current_version: i64 = post.try_get("edit_version")?;
        if current_version != autosave.base_version {
            return Ok(AutosaveOutcome::Conflict { current_version });
        }
        // Keep the global lock order `post -> autosave`. The exact target is removed first so an
        // expired high client_seq cannot participate in the following CAS.
        sqlx::query(
            "DELETE FROM writer_autosaves WHERE session_id = $1 AND expires_at <= $2",
        )
        .bind(&autosave.session_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        if let Some(row) = sqlx::query(
            "SELECT owner_sub, post_id, client_seq FROM writer_autosaves \
             WHERE session_id = $1 FOR UPDATE",
        )
        .bind(&autosave.session_id)
        .fetch_optional(&mut *tx)
        .await?
        {
            let owner_sub: String = row.try_get("owner_sub")?;
            let post_id: String = row.try_get("post_id")?;
            let client_seq: i64 = row.try_get("client_seq")?;
            if owner_sub != autosave.owner_sub || post_id != autosave.post_id {
                return Ok(AutosaveOutcome::NotFound);
            }
            if client_seq >= autosave.client_seq {
                return Ok(AutosaveOutcome::Stale {
                    stored_client_seq: client_seq,
                });
            }
        }
        sqlx::query(
            "INSERT INTO writer_autosaves \
                 (session_id, post_id, owner_sub, base_version, client_seq, title, body_md, tags, \
                  cover_url, custom_excerpt, meta_title, meta_description, canonical_url, \
                  social_title, social_description, social_image, publish_at, pinned, updated_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
                     $16, $17, $18, $19, $20) \
             ON CONFLICT (session_id) DO UPDATE SET \
                 base_version = EXCLUDED.base_version, client_seq = EXCLUDED.client_seq, \
                 title = EXCLUDED.title, body_md = EXCLUDED.body_md, tags = EXCLUDED.tags, \
                 cover_url = EXCLUDED.cover_url, custom_excerpt = EXCLUDED.custom_excerpt, \
                 meta_title = EXCLUDED.meta_title, meta_description = EXCLUDED.meta_description, \
                 canonical_url = EXCLUDED.canonical_url, social_title = EXCLUDED.social_title, \
                 social_description = EXCLUDED.social_description, social_image = EXCLUDED.social_image, \
                 publish_at = EXCLUDED.publish_at, pinned = EXCLUDED.pinned, \
                 updated_at = EXCLUDED.updated_at, expires_at = EXCLUDED.expires_at",
        )
        .bind(&autosave.session_id)
        .bind(&autosave.post_id)
        .bind(&autosave.owner_sub)
        .bind(autosave.base_version)
        .bind(autosave.client_seq)
        .bind(&autosave.title)
        .bind(&autosave.body_md)
        .bind(&autosave.tags)
        .bind(&autosave.cover_url)
        .bind(&autosave.custom_excerpt)
        .bind(&autosave.meta_title)
        .bind(&autosave.meta_description)
        .bind(&autosave.canonical_url)
        .bind(&autosave.social_title)
        .bind(&autosave.social_description)
        .bind(&autosave.social_image)
        .bind(&autosave.publish_at)
        .bind(autosave.pinned)
        .bind(autosave.updated_at)
        .bind(autosave.expires_at)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        if let Err(error) = self.cleanup_expired_autosaves_async(now).await {
            tracing::warn!(%error, "bounded writer autosave cleanup failed");
        }
        Ok(AutosaveOutcome::Saved(Box::new(autosave.clone())))
    }

    async fn cleanup_expired_autosaves_async(&self, now: i64) -> Result<(), sqlx::Error> {
        sqlx::query(
            "DELETE FROM writer_autosaves WHERE session_id IN (\
                 SELECT session_id FROM writer_autosaves WHERE expires_at <= $1 \
                 ORDER BY expires_at ASC, session_id ASC LIMIT 256\
             )",
        )
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_writer_autosave_async(
        &self,
        session_id: &str,
        owner_sub: &str,
        now: i64,
    ) -> Result<Option<WriterAutosave>, sqlx::Error> {
        let row = sqlx::query(&format!(
            "{AUTOSAVE_COLS} WHERE session_id = $1 AND owner_sub = $2 AND expires_at > $3"
        ))
        .bind(session_id)
        .bind(owner_sub)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::autosave_from_row).transpose()
    }

    async fn delete_post_async(&self, slug: &str) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        if let Some(row) = sqlx::query("SELECT id FROM posts WHERE slug = $1 FOR UPDATE")
            .bind(slug)
            .fetch_optional(&mut *tx)
            .await?
        {
            let post_id: String = row.try_get("id")?;
            sqlx::query("DELETE FROM writer_autosaves WHERE post_id = $1")
                .bind(&post_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM post_revisions WHERE post_id = $1")
                .bind(&post_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM posts WHERE id = $1")
                .bind(&post_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
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
        self.list_posts_async(before, limit)
            .await
            .unwrap_or_else(|e| {
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

    async fn get_post_authoritative(&self, slug: &str) -> Result<Option<Post>, StoreError> {
        self.get_post_async(slug)
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))
    }

    async fn list_visible_posts(
        &self,
        before: Option<PostCursor>,
        limit: i64,
        now: i64,
        viewer_sub: Option<&str>,
    ) -> Vec<Post> {
        self.list_visible_posts_async(before, limit, now, viewer_sub)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg list_visible_posts failed");
                Vec::new()
            })
    }

    async fn get_visible_post(
        &self,
        slug: &str,
        now: i64,
        viewer_sub: Option<&str>,
    ) -> Option<Post> {
        self.get_visible_post_async(slug, now, viewer_sub)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg get_visible_post failed");
                None
            })
    }

    async fn feed_posts(&self, now: i64) -> Result<Vec<Post>, StoreError> {
        self.feed_posts_async(now)
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))
    }

    async fn sitemap_entries(&self, now: i64) -> Result<Vec<SitemapEntry>, StoreError> {
        self.sitemap_entries_async(now)
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))
    }

    async fn related_posts_by_tags(
        &self,
        slug: &str,
        tags: &str,
        now: i64,
        limit: i64,
    ) -> Vec<Post> {
        self.related_posts_by_tags_async(slug, tags, now, limit)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg related_posts_by_tags failed");
                Vec::new()
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
        match self
            .save_post_async(SavePostCommand {
                post: post.clone(),
                expected_version: post.edit_version,
                editor_sub: post.author_sub.clone(),
                editor_email: post.author_email.clone(),
                source: "legacy-update".to_string(),
                restored_from: None,
                consume_autosave_session: None,
            })
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))?
        {
            SavePostOutcome::Saved(_) => Ok(()),
            SavePostOutcome::Conflict { .. } => Err(StoreError::Conflict(post.slug.clone())),
            SavePostOutcome::NotFound => Err(StoreError::Backend(format!(
                "no post with slug {}",
                post.slug
            ))),
        }
    }

    async fn save_post(&self, command: SavePostCommand) -> Result<SavePostOutcome, StoreError> {
        self.save_post_async(command)
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))
    }

    async fn list_post_revisions(
        &self,
        post_id: &str,
        limit: i64,
    ) -> Result<Vec<PostRevisionSummary>, StoreError> {
        self.list_post_revisions_async(post_id, limit)
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))
    }

    async fn get_post_revision(
        &self,
        post_id: &str,
        revision_id: &str,
    ) -> Result<Option<PostRevision>, StoreError> {
        self.get_post_revision_async(post_id, revision_id)
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))
    }

    async fn put_writer_autosave(
        &self,
        autosave: WriterAutosave,
        now: i64,
    ) -> Result<AutosaveOutcome, StoreError> {
        self.put_writer_autosave_async(&autosave, now)
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))
    }

    async fn get_writer_autosave(
        &self,
        session_id: &str,
        owner_sub: &str,
        now: i64,
    ) -> Result<Option<WriterAutosave>, StoreError> {
        self.get_writer_autosave_async(session_id, owner_sub, now)
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))
    }

    async fn delete_writer_autosave(
        &self,
        session_id: &str,
        owner_sub: &str,
    ) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM writer_autosaves WHERE session_id = $1 AND owner_sub = $2")
            .bind(session_id)
            .bind(owner_sub)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(|error| StoreError::Backend(error.to_string()))
    }

    async fn delete_post(&self, slug: &str) -> Result<(), StoreError> {
        self.delete_post_async(slug)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get_settings(&self) -> Settings {
        self.get_settings_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg get_settings failed");
            Settings::default()
        })
    }

    async fn update_settings(&self, settings: &Settings) -> Result<(), StoreError> {
        self.update_settings_async(settings)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn count_chunks(&self) -> Result<i64, StoreError> {
        self.count_chunks_async()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn fetch_chunks(&self) -> Result<Vec<Chunk>, StoreError> {
        self.fetch_chunks_async()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn refresh_public_chunks(&self, now: i64, limit: i64) -> Result<i64, StoreError> {
        self.refresh_public_chunks_async(now, limit)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn fetch_public_chunks(&self, now: i64, limit: i64) -> Result<Vec<Chunk>, StoreError> {
        self.fetch_public_chunks_async(now, limit)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
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
            edit_version: 1,
            published: true,
            publish_at: 0,
            featured: false,
            pinned: false,
            tags: String::new(),
            cover_url: String::new(),
            custom_excerpt: String::new(),
            meta_title: String::new(),
            meta_description: String::new(),
            canonical_url: String::new(),
            social_title: String::new(),
            social_description: String::new(),
            social_image: String::new(),
        }
    }

    /// Newest page first, then the `before` cursor pages strictly backward until exhausted — the
    /// whole archive is reachable page by page even past a single page's `limit`.
    #[tokio::test]
    async fn list_posts_keyset_pages_backward() {
        let store = InMemoryStore::new();
        for i in 1..=5 {
            store
                .create_post(&post(&format!("post_{i}"), i))
                .await
                .unwrap();
        }

        let page1 = store.list_posts(None, 2).await;
        assert_eq!(
            page1.iter().map(|p| p.created_at).collect::<Vec<_>>(),
            vec![5, 4]
        );

        let last = page1.last().unwrap();
        let page2 = store
            .list_posts(Some((last.created_at, last.id.clone())), 2)
            .await;
        assert_eq!(
            page2.iter().map(|p| p.created_at).collect::<Vec<_>>(),
            vec![3, 2]
        );

        let last = page2.last().unwrap();
        let page3 = store
            .list_posts(Some((last.created_at, last.id.clone())), 2)
            .await;
        assert_eq!(
            page3.iter().map(|p| p.created_at).collect::<Vec<_>>(),
            vec![1]
        );

        // Past the end: nothing older than the last row.
        let last = page3.last().unwrap();
        let page4 = store
            .list_posts(Some((last.created_at, last.id.clone())), 2)
            .await;
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

    /// Settings default until saved, then round-trip through the store (single-row semantics).
    #[tokio::test]
    async fn settings_default_then_roundtrip() {
        let store = InMemoryStore::new();
        assert_eq!(
            store.get_settings().await,
            Settings::default(),
            "default before any save"
        );

        let s = Settings {
            title: "My Blog".to_string(),
            tagline: "hello".to_string(),
            posts_per_page: 12,
        };
        store.update_settings(&s).await.unwrap();
        assert_eq!(store.get_settings().await, s, "saved settings read back");

        // A second save replaces the single row (no accumulation).
        let s2 = Settings {
            title: "Renamed".to_string(),
            ..s.clone()
        };
        store.update_settings(&s2).await.unwrap();
        assert_eq!(store.get_settings().await, s2);
    }

    /// The admin `featured` flag persists through create + update.
    #[tokio::test]
    async fn featured_flag_persists() {
        let store = InMemoryStore::new();
        store.create_post(&post("p1", 1)).await.unwrap();
        assert!(
            !store.get_post("p1").await.unwrap().featured,
            "defaults to not featured"
        );
        let mut p = store.get_post("p1").await.unwrap();
        p.featured = true;
        store.update_post(&p).await.unwrap();
        assert!(
            store.get_post("p1").await.unwrap().featured,
            "featured persisted"
        );
    }

    /// Scheduled posts use a store-level time predicate on reader-visible reads, while the author
    /// still sees their own scheduled work.
    #[tokio::test]
    async fn visible_posts_apply_publish_at_predicate() {
        let store = InMemoryStore::new();
        let now = 1_000;
        let mut scheduled = post("scheduled", now - 10);
        scheduled.publish_at = now + 3_600;
        store.create_post(&scheduled).await.unwrap();

        assert!(
            store
                .list_visible_posts(None, 10, now, None)
                .await
                .is_empty(),
            "future publish_at hidden from anonymous list",
        );
        assert!(
            store
                .get_visible_post("scheduled", now, None)
                .await
                .is_none(),
            "future publish_at hidden from anonymous read",
        );
        assert!(
            store
                .get_visible_post("scheduled", now, Some("u"))
                .await
                .is_some(),
            "author can read scheduled post",
        );
        assert_eq!(
            store.list_visible_posts(None, 10, now + 3_600, None).await[0].slug,
            "scheduled",
            "post becomes public once publish_at arrives",
        );
    }

    /// Public index ordering floats pinned posts ahead of newer ordinary posts.
    #[tokio::test]
    async fn visible_posts_sort_pinned_first() {
        let store = InMemoryStore::new();
        let mut older = post("older", 10);
        older.pinned = true;
        store.create_post(&older).await.unwrap();
        store.create_post(&post("newer", 20)).await.unwrap();

        let page = store.list_visible_posts(None, 10, 30, None).await;
        assert_eq!(
            page.iter().map(|p| p.slug.as_str()).collect::<Vec<_>>(),
            vec!["older", "newer"],
            "pinned post floats before newer ordinary post",
        );

        let cursor = PostCursor::from_post(&page[0]);
        let next = store.list_visible_posts(Some(cursor), 10, 30, None).await;
        assert_eq!(
            next[0].slug, "newer",
            "public cursor crosses pinned boundary"
        );
    }

    /// Related posts are ranked by shared tag overlap, excluding drafts/future scheduled posts and
    /// breaking ties deterministically.
    #[tokio::test]
    async fn related_posts_rank_by_shared_tags() {
        let store = InMemoryStore::new();
        let mut current = post("current", 10);
        current.tags = "rust, async, gateway".to_string();
        store.create_post(&current).await.unwrap();

        let mut one = post("one", 20);
        one.tags = "rust".to_string();
        store.create_post(&one).await.unwrap();

        let mut two = post("two", 15);
        two.tags = "rust, async".to_string();
        store.create_post(&two).await.unwrap();

        let mut draft = post("draft", 30);
        draft.published = false;
        draft.tags = "rust, async, gateway".to_string();
        store.create_post(&draft).await.unwrap();

        let mut future = post("future", 40);
        future.publish_at = 10_000;
        future.tags = "rust, async, gateway".to_string();
        store.create_post(&future).await.unwrap();

        let related = store
            .related_posts_by_tags("current", &current.tags, 100, 3)
            .await;
        assert_eq!(
            related.iter().map(|p| p.slug.as_str()).collect::<Vec<_>>(),
            vec!["two", "one"],
            "highest shared-tag overlap wins; non-public posts are excluded",
        );
    }

    /// The comma-separated `tags` field persists through create + update (nullable column, so a
    /// tag-less post round-trips as the empty string).
    #[tokio::test]
    async fn tags_persist_through_create_and_update() {
        let store = InMemoryStore::new();
        let mut p = post("p1", 1);
        p.tags = "rust, async".to_string();
        store.create_post(&p).await.unwrap();
        assert_eq!(
            store.get_post("p1").await.unwrap().tags,
            "rust, async",
            "tags stored on create"
        );

        let mut edited = store.get_post("p1").await.unwrap();
        edited.tags = "gateway".to_string();
        store.update_post(&edited).await.unwrap();
        assert_eq!(
            store.get_post("p1").await.unwrap().tags,
            "gateway",
            "tags replaced on update"
        );
    }

    /// The nullable `cover_url` field persists through create + update (a cover-less post
    /// round-trips as the empty string, mirroring the tags column's NULL -> "" contract).
    #[tokio::test]
    async fn cover_url_persists_through_create_and_update() {
        let store = InMemoryStore::new();
        let mut p = post("p1", 1);
        assert!(store.get_post("p1").await.is_none(), "not created yet");
        p.cover_url = "https://drive.w33d.xyz/s/abc123".to_string();
        store.create_post(&p).await.unwrap();
        assert_eq!(
            store.get_post("p1").await.unwrap().cover_url,
            "https://drive.w33d.xyz/s/abc123",
            "cover stored on create",
        );

        let mut edited = store.get_post("p1").await.unwrap();
        edited.cover_url = String::new();
        store.update_post(&edited).await.unwrap();
        assert_eq!(
            store.get_post("p1").await.unwrap().cover_url,
            "",
            "cover cleared on update"
        );
    }

    /// A caller asking for more than [`MAX_PAGE`] rows is clamped, so a single page stays bounded.
    #[tokio::test]
    async fn list_posts_clamps_limit_to_max() {
        let store = InMemoryStore::new();
        for i in 0..(MAX_PAGE + 10) {
            store
                .create_post(&post(&format!("post_{i:05}"), i))
                .await
                .unwrap();
        }
        let page = store.list_posts(None, MAX_PAGE + 100).await;
        assert_eq!(page.len() as i64, MAX_PAGE, "limit clamped to MAX_PAGE");
    }

    #[tokio::test]
    async fn save_cas_rejects_delete_recreate_same_slug_aba() {
        let store = InMemoryStore::new();
        let old = post("aba", 1);
        store.create_post(&old).await.unwrap();
        let mut stale = old.clone();
        stale.body_md = "stale old identity".to_string();

        store.delete_post("aba").await.unwrap();
        let mut replacement = post("aba", 2);
        replacement.id = "replacement-id".to_string();
        replacement.body_md = "replacement content".to_string();
        store.create_post(&replacement).await.unwrap();

        for source in ["update", "restore"] {
            let outcome = store
                .save_post(SavePostCommand {
                    post: stale.clone(),
                    expected_version: 1,
                    editor_sub: old.author_sub.clone(),
                    editor_email: old.author_email.clone(),
                    source: source.to_string(),
                    restored_from: (source == "restore").then(|| "old-revision".to_string()),
                    consume_autosave_session: Some("old-session".to_string()),
                })
                .await
                .unwrap();
            assert_eq!(outcome, SavePostOutcome::NotFound);
        }
        let current = store.get_post("aba").await.unwrap();
        assert_eq!(current.id, "replacement-id");
        assert_eq!(current.body_md, "replacement content");

        let stale_autosave = WriterAutosave {
            session_id: "old-session".to_string(),
            post_id: old.id,
            owner_sub: old.author_sub,
            base_version: 1,
            client_seq: 1,
            title: "old".to_string(),
            body_md: "must not attach to replacement".to_string(),
            tags: String::new(),
            cover_url: String::new(),
            custom_excerpt: String::new(),
            meta_title: String::new(),
            meta_description: String::new(),
            canonical_url: String::new(),
            social_title: String::new(),
            social_description: String::new(),
            social_image: String::new(),
            publish_at: String::new(),
            pinned: false,
            updated_at: 2,
            expires_at: 100,
        };
        assert_eq!(
            store.put_writer_autosave(stale_autosave, 2).await.unwrap(),
            AutosaveOutcome::NotFound
        );
    }

    #[tokio::test]
    async fn expired_autosaves_are_invisible_and_do_not_win_sequence_cas() {
        let store = InMemoryStore::new();
        let post = post("ttl", 1);
        store.create_post(&post).await.unwrap();
        let make = |session_id: String, client_seq: i64, expires_at: i64| WriterAutosave {
            session_id,
            post_id: post.id.clone(),
            owner_sub: post.author_sub.clone(),
            base_version: 1,
            client_seq,
            title: post.title.clone(),
            body_md: format!("seq {client_seq}"),
            tags: String::new(),
            cover_url: String::new(),
            custom_excerpt: String::new(),
            meta_title: String::new(),
            meta_description: String::new(),
            canonical_url: String::new(),
            social_title: String::new(),
            social_description: String::new(),
            social_image: String::new(),
            publish_at: String::new(),
            pinned: false,
            updated_at: 0,
            expires_at,
        };
        for index in 0..256 {
            store
                .put_writer_autosave(make(format!("expired-{index:03}"), 1, 1), 0)
                .await
                .unwrap();
        }
        let target = "expired-target";
        store
            .put_writer_autosave(make(target.to_string(), 999, 1), 0)
            .await
            .unwrap();

        assert!(store
            .get_writer_autosave(target, &post.author_sub, 2)
            .await
            .unwrap()
            .is_none(), "expired row beyond cleanup batch stays unreadable");
        let fresh = make(target.to_string(), 1, 100);
        assert!(matches!(
            store.put_writer_autosave(fresh, 2).await.unwrap(),
            AutosaveOutcome::Saved(_)
        ));
        assert_eq!(
            store
                .get_writer_autosave(target, &post.author_sub, 2)
                .await
                .unwrap()
                .unwrap()
                .client_seq,
            1,
            "expired high sequence never rejects the fresh write"
        );
    }
}
