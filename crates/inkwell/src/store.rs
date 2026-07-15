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

/// One immutable, same-post pair used by the private Revision Workbench. Implementations resolve
/// both sides under one in-memory lock or one PostgreSQL statement so pruning/deletion cannot
/// produce a mixed comparison snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostRevisionPair {
    pub from: PostRevision,
    pub to: PostRevision,
}

/// One active, version-pinned bearer capability for an unpublished post. `token_hash` is the
/// SHA-256 digest of a 256-bit random token; the raw token never crosses the Store seam.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostReviewLink {
    pub post_id: String,
    pub revision_version: i64,
    /// Last authoritative post version observed by review-link-aware code. A rollback image can
    /// still write `posts`, but it cannot advance this guard; resolution then fails closed.
    pub guard_edit_version: i64,
    pub token_hash: String,
    pub generation: i64,
    pub expires_at: i64,
    pub issued_at: i64,
    pub issued_by_sub: String,
}

/// Authoritative input shared by first issue and refresh-to-current. `expected_generation=None`
/// means create only; `Some(n)` rotates only generation `n` and advances it exactly once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavePostReviewLinkCommand {
    pub post_id: String,
    pub owner_sub: String,
    pub expected_post_version: i64,
    pub expected_generation: Option<i64>,
    pub token_hash: String,
    pub requested_expires_at: i64,
    pub now: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SavePostReviewLinkOutcome {
    Saved(PostReviewLink),
    /// Stale post version, stale generation, an already-active first issue, and a token collision
    /// deliberately share one result.
    Conflict,
    /// Missing and foreign post identities deliberately share one result.
    NotFound,
    /// Public posts and invalid expiry requests cannot receive review capabilities.
    NotEligible,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevokePostReviewLinkCommand {
    pub post_id: String,
    pub owner_sub: String,
    pub expected_post_version: i64,
    pub expected_generation: i64,
    pub now: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevokePostReviewLinkOutcome {
    Revoked,
    Conflict,
    NotFound,
}

/// Immutable public resolution. Stable post identity supplies slug/author/creation fields while
/// every editable presentation field comes from the pinned revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedPostReview {
    pub post: Post,
    pub revision: PostRevision,
    pub link: PostReviewLink,
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

/// Authorization scope for an atomic post delete. Owner commands bind the authoritative row to
/// the gateway subject; admin commands deliberately omit that predicate after the handler has
/// already enforced the admin gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeletePostScope {
    Owner(String),
    Admin,
}

/// Stable delete compare-and-swap. The URL slug is retained as an additional identity component,
/// but neither it nor a freshly loaded row can substitute for the immutable id and edit version
/// rendered into the form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletePostCommand {
    pub slug: String,
    pub post_id: String,
    pub expected_version: i64,
    pub scope: DeletePostScope,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeletePostOutcome {
    Deleted(Box<Post>),
    /// Missing, foreign, stale, and replaced identities intentionally share one outcome.
    Conflict,
}

/// One immutable identity in a bounded destructive bulk command. Both the URL slug and stable row
/// id are compared so a delete/recreate of the same slug cannot grant a stale checkbox authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletePostSelection {
    pub slug: String,
    pub post_id: String,
    pub expected_version: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletePostsCommand {
    pub selections: Vec<DeletePostSelection>,
    pub scope: DeletePostScope,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeletePostsOutcome {
    /// Returned only after every selected post and its private children have been committed away.
    Deleted(Vec<Post>),
    /// Empty, oversized, duplicate, missing, foreign, stale, and replaced batches are identical.
    Conflict,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AutosaveOutcome {
    Saved(Box<WriterAutosave>),
    Stale { stored_client_seq: i64 },
    Conflict { current_version: i64 },
    NotFound,
}

/// Author Content Library status. It is derived from the authoritative publication fields at one
/// fixed `as_of` instant; no second persisted status can drift from `published` / `publish_at`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LibraryStatus {
    #[default]
    All,
    Draft,
    Scheduled,
    Published,
}

/// Author Library ordering. Both modes use an integer authority already stored on the post, so
/// Memory and PostgreSQL can share byte-for-byte cursor semantics without collation-dependent
/// title ordering.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LibrarySort {
    /// Work touched most recently, useful for returning to an active draft.
    #[default]
    Updated,
    /// Work created most recently, useful for reconstructing the publication backlog independently
    /// of later metadata edits.
    Created,
}

/// Exclusive keyset for the selected author-library sort plus `id DESC`. Carrying the sort inside
/// the cursor prevents a cursor copied from one URL order being interpreted in another order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LibraryCursor {
    pub sort: LibrarySort,
    pub sort_at: i64,
    pub post_id: String,
}

/// Fully-authorized Content Library query. `owner_sub` is supplied by the gateway identity, never
/// by a form field. Search and tag filtering run against authoritative post rows, including drafts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LibraryQuery {
    pub owner_sub: String,
    pub q: String,
    pub status: LibraryStatus,
    pub tag: String,
    pub sort: LibrarySort,
    pub as_of: i64,
    pub cursor: Option<LibraryCursor>,
    pub limit: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LibraryPage {
    pub posts: Vec<Post>,
    pub next: Option<LibraryCursor>,
}

/// Stable selection identity carried by a Library checkbox. Slugs are intentionally absent: a
/// delete/recreate of the same URL can never turn a stale selection into authority over a new row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LibrarySelection {
    pub post_id: String,
    pub expected_version: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LibraryBulkAction {
    PublishNow,
    Draft,
    Pin,
    Unpin,
    AddTag(String),
    RemoveTag(String),
}

#[derive(Clone, Debug)]
pub struct LibraryBulkCommand {
    pub owner_sub: String,
    pub editor_email: String,
    pub selections: Vec<LibrarySelection>,
    pub action: LibraryBulkAction,
    pub now: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LibraryBulkOutcome {
    /// Only posts whose authoritative state actually changed are returned. No-op selections still
    /// participate in the all-row CAS but do not create revisions or advance versions.
    Applied(Vec<Post>),
    /// Deliberately carries no row/version detail, so cross-owner ids and stale rows look identical.
    Conflict,
}

impl LibraryBulkAction {
    pub fn audit_detail(&self) -> &'static str {
        match self {
            Self::PublishNow => "publish_now",
            Self::Draft => "draft",
            Self::Pin => "pin",
            Self::Unpin => "unpin",
            Self::AddTag(_) => "add_tag",
            Self::RemoveTag(_) => "remove_tag",
        }
    }

    fn revision_source(&self) -> &'static str {
        match self {
            Self::PublishNow => "library.publish",
            Self::Draft => "library.draft",
            Self::Pin => "library.pin",
            Self::Unpin => "library.unpin",
            Self::AddTag(_) => "library.tag.add",
            Self::RemoveTag(_) => "library.tag.remove",
        }
    }
}

fn library_status_matches(post: &Post, status: LibraryStatus, as_of: i64) -> bool {
    match status {
        LibraryStatus::All => true,
        LibraryStatus::Draft => !post.published,
        LibraryStatus::Scheduled => post.published && post.publish_at > as_of,
        LibraryStatus::Published => post.is_public_at(as_of),
    }
}

fn library_text_matches(post: &Post, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    let query = query.to_lowercase();
    [&post.title, &post.slug, &post.body_md, &post.tags]
        .iter()
        .any(|value| value.to_lowercase().contains(&query))
}

fn library_tag_matches(post: &Post, tag: &str) -> bool {
    tag.is_empty()
        || crate::tags::parse_tags(&post.tags)
            .iter()
            .any(|candidate| candidate.to_lowercase() == tag.to_lowercase())
}

fn library_sort_at(post: &Post, sort: LibrarySort) -> i64 {
    match sort {
        LibrarySort::Updated => post.updated_at,
        LibrarySort::Created => post.created_at,
    }
}

fn after_library_cursor(post: &Post, cursor: &LibraryCursor, sort: LibrarySort) -> bool {
    if cursor.sort != sort {
        return false;
    }
    let sort_at = library_sort_at(post, sort);
    sort_at < cursor.sort_at || (sort_at == cursor.sort_at && post.id < cursor.post_id)
}

fn finish_library_page(mut posts: Vec<Post>, limit: i64, sort: LibrarySort) -> LibraryPage {
    let limit = limit.clamp(1, crate::config::LIBRARY_MAX_PAGE) as usize;
    let has_more = posts.len() > limit;
    posts.truncate(limit);
    let next = has_more.then(|| {
        let post = posts.last().expect("a page with look-ahead has one item");
        LibraryCursor {
            sort,
            sort_at: library_sort_at(post, sort),
            post_id: post.id.clone(),
        }
    });
    LibraryPage { posts, next }
}

/// Mutate author-owned fields only. `featured` and every body/metadata field remain untouched.
/// Invalid tag commands and version exhaustion fail before the caller persists any selected row.
fn apply_library_action(post: &mut Post, action: &LibraryBulkAction, now: i64) -> Result<bool, ()> {
    let changed = match action {
        LibraryBulkAction::PublishNow => {
            if post.is_public_at(now) {
                false
            } else {
                post.published = true;
                post.publish_at = now;
                true
            }
        }
        LibraryBulkAction::Draft => {
            let changed = post.published || post.publish_at != 0;
            post.published = false;
            post.publish_at = 0;
            changed
        }
        LibraryBulkAction::Pin => {
            let changed = !post.pinned;
            post.pinned = true;
            changed
        }
        LibraryBulkAction::Unpin => {
            let changed = post.pinned;
            post.pinned = false;
            changed
        }
        LibraryBulkAction::AddTag(raw) => {
            let additions = crate::tags::parse_tags(raw);
            if additions.len() != 1 {
                return Err(());
            }
            let addition = &additions[0];
            let key = crate::tags::tag_slug(addition);
            let mut tags = crate::tags::parse_tags(&post.tags);
            if tags
                .iter()
                .any(|candidate| crate::tags::tag_slug(candidate) == key)
            {
                false
            } else {
                if tags.len() >= crate::tags::MAX_TAGS {
                    return Err(());
                }
                tags.push(addition.clone());
                post.tags = crate::tags::join_tags(&tags);
                true
            }
        }
        LibraryBulkAction::RemoveTag(raw) => {
            let removals = crate::tags::parse_tags(raw);
            if removals.len() != 1 {
                return Err(());
            }
            let key = crate::tags::tag_slug(&removals[0]);
            let mut tags = crate::tags::parse_tags(&post.tags);
            let original_len = tags.len();
            tags.retain(|candidate| crate::tags::tag_slug(candidate) != key);
            let changed = tags.len() != original_len;
            if changed {
                post.tags = crate::tags::join_tags(&tags);
            }
            changed
        }
    };
    if changed {
        post.edit_version = post.edit_version.checked_add(1).ok_or(())?;
        post.updated_at = now.max(post.updated_at.checked_add(1).ok_or(())?);
    }
    Ok(changed)
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
            tagline: "Notes, essays, and changelog from the Steadholme estate.".to_string(),
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
    /// One fail-closed, owner-scoped Content Library page. Every implementation applies all filters
    /// before the selected stable timestamp + id keyset and returns backend failures as errors.
    async fn list_library(&self, query: LibraryQuery) -> Result<LibraryPage, StoreError>;
    /// Apply one bounded author action to stable id/version selections atomically. All selections
    /// are authorized and compared before any write; autosaves are neither read nor consumed.
    async fn bulk_update_library(
        &self,
        command: LibraryBulkCommand,
    ) -> Result<LibraryBulkOutcome, StoreError>;
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
    async fn get_post_revision_pair(
        &self,
        post_id: &str,
        from_revision_id: &str,
        to_revision_id: &str,
    ) -> Result<Option<PostRevisionPair>, StoreError>;
    /// Current non-expired capability state for one exact owner/post pair. The raw token is never
    /// persisted and therefore cannot be recovered by this read.
    async fn get_post_review_link(
        &self,
        post_id: &str,
        owner_sub: &str,
        now: i64,
    ) -> Result<Option<PostReviewLink>, StoreError>;
    /// Issue or atomically rotate a review link, always binding it to the post's current committed
    /// revision. Implementations serialize against publication-state changes on the post row.
    async fn save_post_review_link(
        &self,
        command: SavePostReviewLinkCommand,
    ) -> Result<SavePostReviewLinkOutcome, StoreError>;
    async fn revoke_post_review_link(
        &self,
        command: RevokePostReviewLinkCommand,
    ) -> Result<RevokePostReviewLinkOutcome, StoreError>;
    /// Resolve a bearer digest to one immutable revision. Expired, revoked, published, scheduled-
    /// due, deleted and malformed/unknown digests all resolve to `None`.
    async fn resolve_post_review(
        &self,
        token_hash: &str,
        now: i64,
    ) -> Result<Option<ResolvedPostReview>, StoreError>;
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
    /// Atomically delete exactly one stable post identity under an owner/admin authorization scope.
    async fn delete_post_cas(
        &self,
        command: DeletePostCommand,
    ) -> Result<DeletePostOutcome, StoreError>;
    /// Atomically delete one bounded set of immutable post identities. Implementations compare and
    /// authorize every selection before the first delete, and return no per-row conflict detail.
    async fn delete_posts_cas(
        &self,
        command: DeletePostsCommand,
    ) -> Result<DeletePostsOutcome, StoreError>;
    /// Unconditional delete retained for maintenance and test fixture setup. HTTP commands must use
    /// [`Store::delete_post_cas`] so a slug delete/recreate cannot become authority over a new row.
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
    review_links: Mutex<Vec<PostReviewLink>>,
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

    async fn list_library(&self, query: LibraryQuery) -> Result<LibraryPage, StoreError> {
        let limit = query.limit.clamp(1, crate::config::LIBRARY_MAX_PAGE);
        if query
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.sort != query.sort)
        {
            return Ok(LibraryPage {
                posts: Vec::new(),
                next: None,
            });
        }
        let search: String = query.q.trim().chars().take(200).collect();
        let tag: String = query
            .tag
            .trim()
            .chars()
            .take(crate::tags::MAX_TAG_CHARS)
            .collect();
        let posts = self.posts.lock().expect("posts lock poisoned");
        let mut rows: Vec<Post> = posts
            .iter()
            .filter(|post| post.author_sub == query.owner_sub)
            .filter(|post| library_status_matches(post, query.status, query.as_of))
            .filter(|post| library_text_matches(post, &search))
            .filter(|post| library_tag_matches(post, &tag))
            .filter(|post| {
                query
                    .cursor
                    .as_ref()
                    .is_none_or(|cursor| after_library_cursor(post, cursor, query.sort))
            })
            .cloned()
            .collect();
        rows.sort_by(|a, b| {
            library_sort_at(b, query.sort)
                .cmp(&library_sort_at(a, query.sort))
                .then_with(|| b.id.cmp(&a.id))
        });
        rows.truncate(limit as usize + 1);
        Ok(finish_library_page(rows, limit, query.sort))
    }

    async fn bulk_update_library(
        &self,
        mut command: LibraryBulkCommand,
    ) -> Result<LibraryBulkOutcome, StoreError> {
        if command.selections.is_empty()
            || command.selections.len() > crate::config::LIBRARY_BULK_MAX
        {
            return Ok(LibraryBulkOutcome::Conflict);
        }
        command.selections.sort_by(|a, b| a.post_id.cmp(&b.post_id));
        if command
            .selections
            .windows(2)
            .any(|pair| pair[0].post_id == pair[1].post_id)
        {
            return Ok(LibraryBulkOutcome::Conflict);
        }

        let _mutation = self.mutation_lock.lock().expect("mutation lock poisoned");
        let mut posts = self.posts.lock().expect("posts lock poisoned");
        let mut updates = Vec::with_capacity(command.selections.len());
        for selection in &command.selections {
            let Some(index) = posts.iter().position(|post| {
                post.id == selection.post_id && post.author_sub == command.owner_sub
            }) else {
                return Ok(LibraryBulkOutcome::Conflict);
            };
            let current = posts[index].clone();
            if current.edit_version != selection.expected_version {
                return Ok(LibraryBulkOutcome::Conflict);
            }
            let mut saved = current.clone();
            let changed = match apply_library_action(&mut saved, &command.action, command.now) {
                Ok(changed) => changed,
                Err(()) => return Ok(LibraryBulkOutcome::Conflict),
            };
            updates.push((index, current, saved, changed));
        }

        let mut revisions = self.revisions.lock().expect("revisions lock poisoned");
        let mut review_links = self
            .review_links
            .lock()
            .expect("review links lock poisoned");
        let mut changed_posts = Vec::new();
        for (index, current, saved, changed) in updates {
            if !changed {
                continue;
            }
            ensure_current_revision(
                &mut revisions,
                &current,
                &command.owner_sub,
                &command.editor_email,
            );
            revisions.push(revision_from_post(
                &saved,
                &command.owner_sub,
                &command.editor_email,
                command.action.revision_source(),
                None,
            ));
            reconcile_mem_review_link_after_save(&mut review_links, &current, &saved);
            let protected_version = review_links
                .iter()
                .find(|link| link.post_id == saved.id)
                .map(|link| link.revision_version);
            prune_mem_revisions(&mut revisions, &saved.id, protected_version);
            posts[index] = saved.clone();
            changed_posts.push(saved);
        }
        Ok(LibraryBulkOutcome::Applied(changed_posts))
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

        let Some(next_version) = current.edit_version.checked_add(1) else {
            return Ok(SavePostOutcome::Conflict {
                current_version: current.edit_version,
            });
        };
        let Some(next_updated_at) = current.updated_at.checked_add(1) else {
            return Ok(SavePostOutcome::Conflict {
                current_version: current.edit_version,
            });
        };

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
        saved.edit_version = next_version;
        saved.updated_at = saved.updated_at.max(next_updated_at);
        revisions.push(revision_from_post(
            &saved,
            &command.editor_sub,
            &command.editor_email,
            &command.source,
            command.restored_from,
        ));
        let mut review_links = self
            .review_links
            .lock()
            .expect("review links lock poisoned");
        reconcile_mem_review_link_after_save(&mut review_links, &current, &saved);
        let protected_version = review_links
            .iter()
            .find(|link| link.post_id == saved.id)
            .map(|link| link.revision_version);
        prune_mem_revisions(&mut revisions, &saved.id, protected_version);

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

    async fn get_post_revision_pair(
        &self,
        post_id: &str,
        from_revision_id: &str,
        to_revision_id: &str,
    ) -> Result<Option<PostRevisionPair>, StoreError> {
        let revisions = self.revisions.lock().expect("revisions lock poisoned");
        let from = revisions
            .iter()
            .find(|revision| revision.post_id == post_id && revision.id == from_revision_id)
            .cloned();
        let to = if from_revision_id == to_revision_id {
            from.clone()
        } else {
            revisions
                .iter()
                .find(|revision| revision.post_id == post_id && revision.id == to_revision_id)
                .cloned()
        };
        Ok(from.zip(to).map(|(from, to)| PostRevisionPair { from, to }))
    }

    async fn get_post_review_link(
        &self,
        post_id: &str,
        owner_sub: &str,
        now: i64,
    ) -> Result<Option<PostReviewLink>, StoreError> {
        let _mutation = self.mutation_lock.lock().expect("mutation lock poisoned");
        let posts = self.posts.lock().expect("posts lock poisoned");
        let Some(post) = posts
            .iter()
            .find(|post| post.id == post_id && post.author_sub == owner_sub)
        else {
            return Ok(None);
        };
        if post.is_public_at(now) {
            return Ok(None);
        }
        let revisions = self.revisions.lock().expect("revisions lock poisoned");
        let links = self
            .review_links
            .lock()
            .expect("review links lock poisoned");
        Ok(links
            .iter()
            .find(|link| {
                link.post_id == post_id
                    && link.expires_at > now
                    && link.guard_edit_version == post.edit_version
                    && revisions.iter().any(|revision| {
                        revision.post_id == link.post_id
                            && revision.edit_version == link.revision_version
                    })
            })
            .cloned())
    }

    async fn save_post_review_link(
        &self,
        command: SavePostReviewLinkCommand,
    ) -> Result<SavePostReviewLinkOutcome, StoreError> {
        if !review_token_hash_is_valid(&command.token_hash) {
            return Ok(SavePostReviewLinkOutcome::NotEligible);
        }
        let _mutation = self.mutation_lock.lock().expect("mutation lock poisoned");
        let posts = self.posts.lock().expect("posts lock poisoned");
        let Some(post) = posts
            .iter()
            .find(|post| post.id == command.post_id && post.author_sub == command.owner_sub)
        else {
            return Ok(SavePostReviewLinkOutcome::NotFound);
        };
        if post.edit_version != command.expected_post_version {
            return Ok(SavePostReviewLinkOutcome::Conflict);
        }
        let Some(expires_at) = review_link_expiry(post, command.requested_expires_at, command.now)
        else {
            return Ok(SavePostReviewLinkOutcome::NotEligible);
        };
        let revisions = self.revisions.lock().expect("revisions lock poisoned");
        if !revisions.iter().any(|revision| {
            revision.post_id == post.id && revision.edit_version == post.edit_version
        }) {
            return Err(StoreError::Backend(
                "current post revision is missing".to_string(),
            ));
        }
        let mut links = self
            .review_links
            .lock()
            .expect("review links lock poisoned");
        // A guard mismatch means an older image changed the post without review-link awareness.
        // Delete that capability. Expired/revoked rows remain as generation tombstones so a stale
        // form can never win an ABA race against a later issue for the same post version.
        links
            .retain(|link| link.post_id != post.id || link.guard_edit_version == post.edit_version);
        let existing = links.iter().position(|link| link.post_id == post.id);
        let generation = match (command.expected_generation, existing) {
            (None, None) => 1,
            (None, Some(index)) if links[index].expires_at <= command.now => {
                let Some(next) = links[index].generation.checked_add(1) else {
                    return Ok(SavePostReviewLinkOutcome::Conflict);
                };
                next
            }
            (Some(expected), Some(index))
                if links[index].generation == expected && links[index].expires_at > command.now =>
            {
                if links[index].token_hash == command.token_hash {
                    return Ok(SavePostReviewLinkOutcome::Conflict);
                }
                let Some(next) = expected.checked_add(1) else {
                    return Ok(SavePostReviewLinkOutcome::Conflict);
                };
                next
            }
            _ => return Ok(SavePostReviewLinkOutcome::Conflict),
        };
        if links
            .iter()
            .any(|link| link.token_hash == command.token_hash)
        {
            return Ok(SavePostReviewLinkOutcome::Conflict);
        }
        let saved = PostReviewLink {
            post_id: post.id.clone(),
            revision_version: post.edit_version,
            guard_edit_version: post.edit_version,
            token_hash: command.token_hash,
            generation,
            expires_at,
            issued_at: command.now,
            issued_by_sub: command.owner_sub,
        };
        if let Some(index) = existing {
            links[index] = saved.clone();
        } else {
            links.push(saved.clone());
        }
        Ok(SavePostReviewLinkOutcome::Saved(saved))
    }

    async fn revoke_post_review_link(
        &self,
        command: RevokePostReviewLinkCommand,
    ) -> Result<RevokePostReviewLinkOutcome, StoreError> {
        let _mutation = self.mutation_lock.lock().expect("mutation lock poisoned");
        let posts = self.posts.lock().expect("posts lock poisoned");
        let Some(post) = posts
            .iter()
            .find(|post| post.id == command.post_id && post.author_sub == command.owner_sub)
        else {
            return Ok(RevokePostReviewLinkOutcome::NotFound);
        };
        if post.edit_version != command.expected_post_version {
            return Ok(RevokePostReviewLinkOutcome::Conflict);
        }
        let mut links = self
            .review_links
            .lock()
            .expect("review links lock poisoned");
        let Some(index) = links.iter().position(|link| {
            link.post_id == command.post_id
                && link.generation == command.expected_generation
                && link.guard_edit_version == command.expected_post_version
                && link.expires_at > command.now
        }) else {
            return Ok(RevokePostReviewLinkOutcome::Conflict);
        };
        let Some(next_generation) = links[index].generation.checked_add(1) else {
            return Ok(RevokePostReviewLinkOutcome::Conflict);
        };
        links[index].generation = next_generation;
        links[index].expires_at = 0;
        Ok(RevokePostReviewLinkOutcome::Revoked)
    }

    async fn resolve_post_review(
        &self,
        token_hash: &str,
        now: i64,
    ) -> Result<Option<ResolvedPostReview>, StoreError> {
        if !review_token_hash_is_valid(token_hash) {
            return Ok(None);
        }
        let _mutation = self.mutation_lock.lock().expect("mutation lock poisoned");
        let posts = self.posts.lock().expect("posts lock poisoned");
        let revisions = self.revisions.lock().expect("revisions lock poisoned");
        let links = self
            .review_links
            .lock()
            .expect("review links lock poisoned");
        let Some(link) = links
            .iter()
            .find(|link| link.token_hash == token_hash && link.expires_at > now)
            .cloned()
        else {
            return Ok(None);
        };
        let Some(post) = posts.iter().find(|post| {
            post.id == link.post_id
                && post.edit_version == link.guard_edit_version
                && !post.is_public_at(now)
        }) else {
            return Ok(None);
        };
        let Some(revision) = revisions
            .iter()
            .find(|revision| {
                revision.post_id == link.post_id && revision.edit_version == link.revision_version
            })
            .cloned()
        else {
            return Ok(None);
        };
        Ok(Some(ResolvedPostReview {
            post: review_post_from_revision(post, &revision),
            revision,
            link,
        }))
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
        rows.retain(|row| !(row.session_id == autosave.session_id && row.expires_at <= now));
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
                row.session_id == session_id && row.owner_sub == owner_sub && row.expires_at > now
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

    async fn delete_post_cas(
        &self,
        command: DeletePostCommand,
    ) -> Result<DeletePostOutcome, StoreError> {
        let _mutation = self.mutation_lock.lock().expect("mutation lock poisoned");
        let mut posts = self.posts.lock().expect("posts lock poisoned");
        let Some(index) = posts.iter().position(|post| {
            post.slug == command.slug
                && post.id == command.post_id
                && post.edit_version == command.expected_version
                && match &command.scope {
                    DeletePostScope::Owner(owner_sub) => post.author_sub == *owner_sub,
                    DeletePostScope::Admin => true,
                }
        }) else {
            return Ok(DeletePostOutcome::Conflict);
        };
        let deleted = posts.remove(index);
        self.revisions
            .lock()
            .expect("revisions lock poisoned")
            .retain(|revision| revision.post_id != deleted.id);
        self.autosaves
            .lock()
            .expect("autosaves lock poisoned")
            .retain(|autosave| autosave.post_id != deleted.id);
        self.review_links
            .lock()
            .expect("review links lock poisoned")
            .retain(|link| link.post_id != deleted.id);
        Ok(DeletePostOutcome::Deleted(Box::new(deleted)))
    }

    async fn delete_posts_cas(
        &self,
        mut command: DeletePostsCommand,
    ) -> Result<DeletePostsOutcome, StoreError> {
        if command.selections.is_empty()
            || command.selections.len() > crate::config::POST_BULK_DELETE_MAX
        {
            return Ok(DeletePostsOutcome::Conflict);
        }
        command
            .selections
            .sort_by(|left, right| left.post_id.cmp(&right.post_id));
        if command
            .selections
            .windows(2)
            .any(|pair| pair[0].post_id == pair[1].post_id)
        {
            return Ok(DeletePostsOutcome::Conflict);
        }

        let _mutation = self.mutation_lock.lock().expect("mutation lock poisoned");
        let mut posts = self.posts.lock().expect("posts lock poisoned");
        let mut revisions = self.revisions.lock().expect("revisions lock poisoned");
        let mut autosaves = self.autosaves.lock().expect("autosaves lock poisoned");
        let mut review_links = self
            .review_links
            .lock()
            .expect("review links lock poisoned");

        let mut deleted = Vec::with_capacity(command.selections.len());
        for selection in &command.selections {
            let Some(post) = posts.iter().find(|post| {
                post.slug == selection.slug
                    && post.id == selection.post_id
                    && post.edit_version == selection.expected_version
                    && match &command.scope {
                        DeletePostScope::Owner(owner_sub) => post.author_sub == *owner_sub,
                        DeletePostScope::Admin => true,
                    }
            }) else {
                return Ok(DeletePostsOutcome::Conflict);
            };
            deleted.push(post.clone());
        }

        let deleted_ids: HashSet<&str> = deleted.iter().map(|post| post.id.as_str()).collect();
        posts.retain(|post| !deleted_ids.contains(post.id.as_str()));
        revisions.retain(|revision| !deleted_ids.contains(revision.post_id.as_str()));
        autosaves.retain(|autosave| !deleted_ids.contains(autosave.post_id.as_str()));
        review_links.retain(|link| !deleted_ids.contains(link.post_id.as_str()));
        Ok(DeletePostsOutcome::Deleted(deleted))
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
            self.review_links
                .lock()
                .expect("review links lock poisoned")
                .retain(|link| link.post_id != post_id);
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

fn review_token_hash_is_valid(token_hash: &str) -> bool {
    token_hash.len() == 64
        && token_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn review_link_expiry(post: &Post, requested_expires_at: i64, now: i64) -> Option<i64> {
    if post.is_public_at(now)
        || requested_expires_at <= now
        || requested_expires_at > now.saturating_add(crate::config::REVIEW_LINK_MAX_TTL_SECS)
    {
        return None;
    }
    Some(if post.is_scheduled_at(now) {
        requested_expires_at.min(post.publish_at)
    } else {
        requested_expires_at
    })
}

/// Visibility transitions never make an old capability usable again. A legacy immediate-public
/// row has no future boundary and deletes the link; every timestamped publication clamps expiry
/// to that instant. Publish-now uses `publish_at=now`, so it expires in the same transaction.
fn reconcile_mem_review_link_after_save(
    links: &mut Vec<PostReviewLink>,
    current: &Post,
    saved: &Post,
) {
    let Some(index) = links.iter().position(|link| link.post_id == saved.id) else {
        return;
    };
    if links[index].guard_edit_version != current.edit_version {
        links.remove(index);
        return;
    }

    let visibility_changed =
        current.published != saved.published || current.publish_at != saved.publish_at;
    if visibility_changed && (!saved.published || saved.publish_at <= 0) {
        let link = &mut links[index];
        link.guard_edit_version = saved.edit_version;
        link.revision_version = saved.edit_version;
        link.expires_at = 0;
        return;
    }

    let link = &mut links[index];
    link.guard_edit_version = saved.edit_version;
    if link.expires_at <= saved.updated_at {
        link.revision_version = saved.edit_version;
    }
    if visibility_changed {
        link.expires_at = link.expires_at.min(saved.publish_at);
        if link.expires_at <= saved.updated_at {
            link.revision_version = saved.edit_version;
        }
    }
}

fn review_post_from_revision(post: &Post, revision: &PostRevision) -> Post {
    Post {
        id: post.id.clone(),
        slug: post.slug.clone(),
        title: revision.title.clone(),
        body_md: revision.body_md.clone(),
        author_sub: post.author_sub.clone(),
        author_email: post.author_email.clone(),
        created_at: post.created_at,
        updated_at: revision.created_at,
        edit_version: revision.edit_version,
        published: revision.published,
        publish_at: revision.publish_at,
        featured: revision.featured,
        pinned: revision.pinned,
        tags: revision.tags.clone(),
        cover_url: revision.cover_url.clone(),
        custom_excerpt: revision.custom_excerpt.clone(),
        meta_title: revision.meta_title.clone(),
        meta_description: revision.meta_description.clone(),
        canonical_url: revision.canonical_url.clone(),
        social_title: revision.social_title.clone(),
        social_description: revision.social_description.clone(),
        social_image: revision.social_image.clone(),
    }
}

fn prune_mem_revisions(
    revisions: &mut Vec<PostRevision>,
    post_id: &str,
    protected_version: Option<i64>,
) {
    let mut versions: Vec<i64> = revisions
        .iter()
        .filter(|revision| revision.post_id == post_id)
        .map(|revision| revision.edit_version)
        .collect();
    versions.sort_unstable_by(|a, b| b.cmp(a));
    versions.dedup();
    let mut kept: HashSet<i64> = versions
        .into_iter()
        .take(crate::config::REVISION_KEEP_LIMIT)
        .collect();
    if let Some(version) = protected_version {
        kept.insert(version);
    }
    revisions
        .retain(|revision| revision.post_id != post_id || kept.contains(&revision.edit_version));
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
use sqlx::{Postgres, QueryBuilder, Row};

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
const REVIEW_LINK_COLS: &str = "SELECT post_id, revision_version, guard_edit_version, token_hash, \
                                generation, expires_at, issued_at, issued_by_sub \
                                FROM post_review_links";
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
            "CREATE TABLE IF NOT EXISTS post_review_links (\
                 post_id TEXT PRIMARY KEY REFERENCES posts(id) ON DELETE CASCADE, \
                 revision_version BIGINT NOT NULL, \
                 guard_edit_version BIGINT NOT NULL, \
                 token_hash TEXT UNIQUE NOT NULL, \
                 generation BIGINT NOT NULL CHECK (generation > 0), \
                 expires_at BIGINT NOT NULL, issued_at BIGINT NOT NULL, \
                 issued_by_sub TEXT NOT NULL, \
                 FOREIGN KEY (post_id, revision_version) \
                     REFERENCES post_revisions(post_id, edit_version) ON DELETE CASCADE\
             )",
        )
        .execute(&self.pool)
        .await?;
        // An interim schema may predate the rollback guard. Existing capabilities are invalidated
        // conservatively instead of guessing whether a rollback image changed their posts.
        sqlx::query(
            "ALTER TABLE post_review_links \
             ADD COLUMN IF NOT EXISTS guard_edit_version BIGINT",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "UPDATE post_review_links SET guard_edit_version = 0 \
             WHERE guard_edit_version IS NULL",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("ALTER TABLE post_review_links ALTER COLUMN guard_edit_version SET NOT NULL")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_post_review_links_expiry \
             ON post_review_links (expires_at, post_id)",
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
        // Deliberately use PostgreSQL's checked BIGINT arithmetic here. If a legacy/operator row
        // is already at either numeric maximum, the repair transaction and startup migration must
        // fail closed; silently skipping it would preserve two different authoring states under
        // one cache/CAS version and allow stale public chunks to remain authoritative.
        sqlx::query(
            "UPDATE posts SET edit_version = posts.edit_version + 1, \
                              updated_at = posts.updated_at + 1 \
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
        sqlx::query(
            "DELETE FROM post_review_links AS link USING posts AS post \
             WHERE link.post_id = post.id \
               AND link.guard_edit_version <> post.edit_version",
        )
        .execute(&mut *repair)
        .await?;
        repair.commit().await?;
        // Backs the newest-first index scan.
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_posts_created_at ON posts (created_at)")
            .execute(&self.pool)
            .await?;
        // Backs owner-first Content Library traversal and its updated-work keyset.
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_posts_author_updated \
             ON posts (author_sub, updated_at, id)",
        )
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

    fn review_link_from_row(row: &sqlx::postgres::PgRow) -> Result<PostReviewLink, sqlx::Error> {
        Ok(PostReviewLink {
            post_id: row.try_get("post_id")?,
            revision_version: row.try_get("revision_version")?,
            guard_edit_version: row.try_get("guard_edit_version")?,
            token_hash: row.try_get("token_hash")?,
            generation: row.try_get("generation")?,
            expires_at: row.try_get("expires_at")?,
            issued_at: row.try_get("issued_at")?,
            issued_by_sub: row.try_get("issued_by_sub")?,
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

    async fn list_library_async(&self, query: LibraryQuery) -> Result<LibraryPage, sqlx::Error> {
        let limit = query.limit.clamp(1, crate::config::LIBRARY_MAX_PAGE);
        if query
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.sort != query.sort)
        {
            return Ok(LibraryPage {
                posts: Vec::new(),
                next: None,
            });
        }
        let mut sql = QueryBuilder::<Postgres>::new(POST_COLS);
        sql.push(" WHERE author_sub = ")
            .push_bind(query.owner_sub.clone());
        match query.status {
            LibraryStatus::All => {}
            LibraryStatus::Draft => {
                sql.push(" AND published = FALSE");
            }
            LibraryStatus::Scheduled => {
                sql.push(" AND published = TRUE AND publish_at > ")
                    .push_bind(query.as_of);
            }
            LibraryStatus::Published => {
                sql.push(" AND published = TRUE AND (publish_at = 0 OR publish_at <= ")
                    .push_bind(query.as_of)
                    .push(")");
            }
        }
        let search: String = query.q.trim().chars().take(200).collect();
        if !search.is_empty() {
            sql.push(" AND (POSITION(LOWER(")
                .push_bind(search.clone())
                .push(") IN LOWER(title)) > 0 OR POSITION(LOWER(")
                .push_bind(search.clone())
                .push(") IN LOWER(slug)) > 0 OR POSITION(LOWER(")
                .push_bind(search.clone())
                .push(") IN LOWER(body_md)) > 0 OR POSITION(LOWER(")
                .push_bind(search)
                .push(") IN LOWER(COALESCE(tags, ''))) > 0)");
        }
        let tag: String = query
            .tag
            .trim()
            .chars()
            .take(crate::tags::MAX_TAG_CHARS)
            .collect();
        if !tag.is_empty() {
            // Tags are stored in canonical `", "` form. Delimiter wrapping makes this an exact
            // membership test without LIKE wildcards or a PostgreSQL-only array operator.
            sql.push(" AND POSITION(LOWER(', ' || ")
                .push_bind(tag)
                .push(" || ', ') IN LOWER(', ' || COALESCE(tags, '') || ', ')) > 0");
        }
        let sort_column = match query.sort {
            LibrarySort::Updated => "updated_at",
            LibrarySort::Created => "created_at",
        };
        if let Some(cursor) = query.cursor {
            sql.push(format!(" AND ({sort_column} < "))
                .push_bind(cursor.sort_at)
                .push(format!(" OR ({sort_column} = "))
                .push_bind(cursor.sort_at)
                .push(" AND id < ")
                .push_bind(cursor.post_id)
                .push("))");
        }
        sql.push(format!(" ORDER BY {sort_column} DESC, id DESC LIMIT "))
            .push_bind(limit + 1);
        let rows = sql.build().fetch_all(&self.pool).await?;
        let posts: Result<Vec<Post>, sqlx::Error> = rows.iter().map(Self::post_from_row).collect();
        Ok(finish_library_page(posts?, limit, query.sort))
    }

    async fn bulk_update_library_async(
        &self,
        mut command: LibraryBulkCommand,
    ) -> Result<LibraryBulkOutcome, sqlx::Error> {
        if command.selections.is_empty()
            || command.selections.len() > crate::config::LIBRARY_BULK_MAX
        {
            return Ok(LibraryBulkOutcome::Conflict);
        }
        command.selections.sort_by(|a, b| a.post_id.cmp(&b.post_id));
        if command
            .selections
            .windows(2)
            .any(|pair| pair[0].post_id == pair[1].post_id)
        {
            return Ok(LibraryBulkOutcome::Conflict);
        }

        let mut tx = self.pool.begin().await?;
        let mut updates = Vec::with_capacity(command.selections.len());
        // Every bulk command locks rows in stable id order. The owner predicate is part of the
        // authoritative lookup, so a foreign id and a deleted id produce the same generic outcome.
        for selection in &command.selections {
            let row = sqlx::query(&format!(
                "{POST_COLS} WHERE author_sub = $1 AND id = $2 FOR UPDATE"
            ))
            .bind(&command.owner_sub)
            .bind(&selection.post_id)
            .fetch_optional(&mut *tx)
            .await?;
            let Some(row) = row else {
                return Ok(LibraryBulkOutcome::Conflict);
            };
            let current = Self::post_from_row(&row)?;
            if current.edit_version != selection.expected_version {
                return Ok(LibraryBulkOutcome::Conflict);
            }
            let mut saved = current.clone();
            let changed = match apply_library_action(&mut saved, &command.action, command.now) {
                Ok(changed) => changed,
                Err(()) => return Ok(LibraryBulkOutcome::Conflict),
            };
            updates.push((current, saved, changed));
        }

        let mut changed_posts = Vec::new();
        for (current, saved, changed) in updates {
            if !changed {
                continue;
            }
            let snapshot = revision_from_post(
                &current,
                &command.owner_sub,
                &command.editor_email,
                "snapshot",
                None,
            );
            Self::insert_revision_tx(&mut tx, &snapshot).await?;
            let updated = sqlx::query(
                "UPDATE posts SET published = $1, publish_at = $2, pinned = $3, tags = $4, \
                        updated_at = $5, edit_version = $6 \
                 WHERE author_sub = $7 AND id = $8 AND edit_version = $9",
            )
            .bind(saved.published)
            .bind(saved.publish_at)
            .bind(saved.pinned)
            .bind(&saved.tags)
            .bind(saved.updated_at)
            .bind(saved.edit_version)
            .bind(&command.owner_sub)
            .bind(&saved.id)
            .bind(current.edit_version)
            .execute(&mut *tx)
            .await?;
            if updated.rows_affected() != 1 {
                return Ok(LibraryBulkOutcome::Conflict);
            }
            let revision = revision_from_post(
                &saved,
                &command.owner_sub,
                &command.editor_email,
                command.action.revision_source(),
                None,
            );
            Self::insert_revision_tx(&mut tx, &revision).await?;
            Self::reconcile_review_link_after_save_tx(&mut tx, &current, &saved).await?;
            Self::prune_revisions_tx(&mut tx, &saved.id).await?;
            changed_posts.push(saved);
        }
        tx.commit().await?;
        Ok(LibraryBulkOutcome::Applied(changed_posts))
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

    async fn reconcile_review_link_after_save_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        current: &Post,
        saved: &Post,
    ) -> Result<(), sqlx::Error> {
        // A v7 image can update `posts` without knowing this table. Its edit version then outruns
        // the guard. The next v8 write deletes the stale capability instead of advancing it and
        // accidentally reviving the bearer URL.
        sqlx::query(
            "DELETE FROM post_review_links \
             WHERE post_id = $1 AND guard_edit_version <> $2",
        )
        .bind(&saved.id)
        .bind(current.edit_version)
        .execute(&mut **tx)
        .await?;

        let visibility_changed =
            current.published != saved.published || current.publish_at != saved.publish_at;
        if visibility_changed && (!saved.published || saved.publish_at <= 0) {
            sqlx::query(
                "UPDATE post_review_links \
                 SET guard_edit_version = $2, revision_version = $2, expires_at = 0 \
                 WHERE post_id = $1 AND guard_edit_version = $3",
            )
            .bind(&saved.id)
            .bind(saved.edit_version)
            .bind(current.edit_version)
            .execute(&mut **tx)
            .await?;
        } else if visibility_changed {
            sqlx::query(
                "UPDATE post_review_links \
                 SET guard_edit_version = $2, \
                     expires_at = CASE WHEN expires_at > $3 THEN $3 ELSE expires_at END, \
                     revision_version = CASE \
                         WHEN expires_at <= $4 OR $3 <= $4 THEN $2 ELSE revision_version END \
                 WHERE post_id = $1 AND guard_edit_version = $5",
            )
            .bind(&saved.id)
            .bind(saved.edit_version)
            .bind(saved.publish_at)
            .bind(saved.updated_at)
            .bind(current.edit_version)
            .execute(&mut **tx)
            .await?;
        } else {
            sqlx::query(
                "UPDATE post_review_links \
                 SET guard_edit_version = $2, \
                     revision_version = CASE WHEN expires_at <= $3 THEN $2 \
                                             ELSE revision_version END \
                 WHERE post_id = $1 AND guard_edit_version = $4",
            )
            .bind(&saved.id)
            .bind(saved.edit_version)
            .bind(saved.updated_at)
            .bind(current.edit_version)
            .execute(&mut **tx)
            .await?;
        }
        Ok(())
    }

    async fn prune_revisions_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        post_id: &str,
    ) -> Result<(), sqlx::Error> {
        // Select the ordinary newest-N window before applying review-link protection, matching
        // Memory exactly. A pinned revision inside that window must not enlarge it; one older
        // pinned snapshot may be retained in addition so an unexpired review remains resolvable.
        sqlx::query(
            "DELETE FROM post_revisions AS revision \
             WHERE revision.post_id = $1 \
               AND NOT EXISTS (\
                   SELECT 1 FROM (\
                       SELECT kept.id FROM post_revisions AS kept \
                       WHERE kept.post_id = $1 \
                       ORDER BY kept.edit_version DESC, kept.id DESC LIMIT $2\
                   ) AS newest WHERE newest.id = revision.id\
               ) \
               AND NOT EXISTS (\
                   SELECT 1 FROM post_review_links AS link \
                   WHERE link.post_id = revision.post_id \
                     AND link.revision_version = revision.edit_version\
               )",
        )
        .bind(post_id)
        .bind(crate::config::REVISION_KEEP_LIMIT as i64)
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

        let Some(next_version) = current.edit_version.checked_add(1) else {
            return Ok(SavePostOutcome::Conflict {
                current_version: current.edit_version,
            });
        };
        let Some(next_updated_at) = current.updated_at.checked_add(1) else {
            return Ok(SavePostOutcome::Conflict {
                current_version: current.edit_version,
            });
        };

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
        saved.edit_version = next_version;
        saved.updated_at = saved.updated_at.max(next_updated_at);
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
        Self::reconcile_review_link_after_save_tx(&mut tx, &current, &saved).await?;
        Self::prune_revisions_tx(&mut tx, &saved.id).await?;
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

    async fn get_post_revision_pair_async(
        &self,
        post_id: &str,
        from_revision_id: &str,
        to_revision_id: &str,
    ) -> Result<Option<PostRevisionPair>, sqlx::Error> {
        // One statement gives both immutable sides one MVCC snapshot. `post_id` is part of the
        // predicate, so a revision id copied from another post is indistinguishable from missing.
        let rows = sqlx::query(&format!(
            "{REVISION_COLS} WHERE post_id = $1 AND (id = $2 OR id = $3)"
        ))
        .bind(post_id)
        .bind(from_revision_id)
        .bind(to_revision_id)
        .fetch_all(&self.pool)
        .await?;
        let revisions: Result<Vec<PostRevision>, sqlx::Error> =
            rows.iter().map(Self::revision_from_row).collect();
        let revisions = revisions?;
        let from = revisions
            .iter()
            .find(|revision| revision.id == from_revision_id)
            .cloned();
        let to = if from_revision_id == to_revision_id {
            from.clone()
        } else {
            revisions
                .iter()
                .find(|revision| revision.id == to_revision_id)
                .cloned()
        };
        Ok(from.zip(to).map(|(from, to)| PostRevisionPair { from, to }))
    }

    async fn get_post_review_link_async(
        &self,
        post_id: &str,
        owner_sub: &str,
        now: i64,
    ) -> Result<Option<PostReviewLink>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT link.post_id, link.revision_version, link.guard_edit_version, \
                    link.token_hash, link.generation, link.expires_at, link.issued_at, \
                    link.issued_by_sub \
             FROM post_review_links AS link \
             JOIN posts AS post ON post.id = link.post_id \
             JOIN post_revisions AS revision \
               ON revision.post_id = link.post_id \
              AND revision.edit_version = link.revision_version \
             WHERE link.post_id = $1 AND post.author_sub = $2 AND link.expires_at > $3 \
               AND link.guard_edit_version = post.edit_version \
               AND NOT (post.published = TRUE \
                        AND (post.publish_at = 0 OR post.publish_at <= $3))",
        )
        .bind(post_id)
        .bind(owner_sub)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::review_link_from_row).transpose()
    }

    async fn save_post_review_link_async(
        &self,
        command: &SavePostReviewLinkCommand,
    ) -> Result<SavePostReviewLinkOutcome, sqlx::Error> {
        if !review_token_hash_is_valid(&command.token_hash) {
            return Ok(SavePostReviewLinkOutcome::NotEligible);
        }
        let mut tx = self.pool.begin().await?;
        let post = sqlx::query(&format!(
            "{POST_COLS} WHERE id = $1 AND author_sub = $2 FOR UPDATE"
        ))
        .bind(&command.post_id)
        .bind(&command.owner_sub)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(post) = post else {
            return Ok(SavePostReviewLinkOutcome::NotFound);
        };
        let post = Self::post_from_row(&post)?;
        if post.edit_version != command.expected_post_version {
            return Ok(SavePostReviewLinkOutcome::Conflict);
        }
        let Some(expires_at) = review_link_expiry(&post, command.requested_expires_at, command.now)
        else {
            return Ok(SavePostReviewLinkOutcome::NotEligible);
        };
        let revision_exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(\
                 SELECT 1 FROM post_revisions \
                 WHERE post_id = $1 AND edit_version = $2\
             )",
        )
        .bind(&post.id)
        .bind(post.edit_version)
        .fetch_one(&mut *tx)
        .await?;
        if !revision_exists {
            return Err(sqlx::Error::Protocol(
                "current post revision is missing".to_string(),
            ));
        }
        sqlx::query(
            "DELETE FROM post_review_links \
             WHERE post_id = $1 AND guard_edit_version <> $2",
        )
        .bind(&post.id)
        .bind(post.edit_version)
        .execute(&mut *tx)
        .await?;
        let existing = sqlx::query(&format!("{REVIEW_LINK_COLS} WHERE post_id = $1 FOR UPDATE"))
            .bind(&post.id)
            .fetch_optional(&mut *tx)
            .await?
            .as_ref()
            .map(Self::review_link_from_row)
            .transpose()?;
        let generation = match (command.expected_generation, existing.as_ref()) {
            (None, None) => 1,
            (None, Some(link)) if link.expires_at <= command.now => {
                let Some(next) = link.generation.checked_add(1) else {
                    return Ok(SavePostReviewLinkOutcome::Conflict);
                };
                next
            }
            (Some(expected), Some(link))
                if link.generation == expected && link.expires_at > command.now =>
            {
                if link.token_hash == command.token_hash {
                    return Ok(SavePostReviewLinkOutcome::Conflict);
                }
                let Some(next) = expected.checked_add(1) else {
                    return Ok(SavePostReviewLinkOutcome::Conflict);
                };
                next
            }
            _ => return Ok(SavePostReviewLinkOutcome::Conflict),
        };
        let token_in_use = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM post_review_links WHERE token_hash = $1)",
        )
        .bind(&command.token_hash)
        .fetch_one(&mut *tx)
        .await?;
        if token_in_use {
            return Ok(SavePostReviewLinkOutcome::Conflict);
        }
        let saved = PostReviewLink {
            post_id: post.id.clone(),
            revision_version: post.edit_version,
            guard_edit_version: post.edit_version,
            token_hash: command.token_hash.clone(),
            generation,
            expires_at,
            issued_at: command.now,
            issued_by_sub: command.owner_sub.clone(),
        };
        let write = if let Some(existing) = existing.as_ref() {
            sqlx::query(
                "UPDATE post_review_links \
                 SET revision_version = $2, guard_edit_version = $3, token_hash = $4, \
                     generation = $5, expires_at = $6, issued_at = $7, issued_by_sub = $8 \
                 WHERE post_id = $1 AND generation = $9",
            )
            .bind(&saved.post_id)
            .bind(saved.revision_version)
            .bind(saved.guard_edit_version)
            .bind(&saved.token_hash)
            .bind(saved.generation)
            .bind(saved.expires_at)
            .bind(saved.issued_at)
            .bind(&saved.issued_by_sub)
            .bind(existing.generation)
            .execute(&mut *tx)
            .await
        } else {
            sqlx::query(
                "INSERT INTO post_review_links \
                     (post_id, revision_version, guard_edit_version, token_hash, generation, \
                      expires_at, issued_at, issued_by_sub) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(&saved.post_id)
            .bind(saved.revision_version)
            .bind(saved.guard_edit_version)
            .bind(&saved.token_hash)
            .bind(saved.generation)
            .bind(saved.expires_at)
            .bind(saved.issued_at)
            .bind(&saved.issued_by_sub)
            .execute(&mut *tx)
            .await
        };
        match write {
            Ok(result) if result.rows_affected() == 1 => {}
            Ok(_) => return Ok(SavePostReviewLinkOutcome::Conflict),
            Err(error) if is_unique_violation(&error) => {
                return Ok(SavePostReviewLinkOutcome::Conflict);
            }
            Err(error) => return Err(error),
        }
        tx.commit().await?;
        Ok(SavePostReviewLinkOutcome::Saved(saved))
    }

    async fn revoke_post_review_link_async(
        &self,
        command: &RevokePostReviewLinkCommand,
    ) -> Result<RevokePostReviewLinkOutcome, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let post_version = sqlx::query_scalar::<_, i64>(
            "SELECT edit_version FROM posts \
             WHERE id = $1 AND author_sub = $2 FOR UPDATE",
        )
        .bind(&command.post_id)
        .bind(&command.owner_sub)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(post_version) = post_version else {
            return Ok(RevokePostReviewLinkOutcome::NotFound);
        };
        if post_version != command.expected_post_version {
            return Ok(RevokePostReviewLinkOutcome::Conflict);
        }
        let updated = sqlx::query(
            "UPDATE post_review_links SET generation = generation + 1, expires_at = 0 \
             WHERE post_id = $1 AND generation = $2 AND guard_edit_version = $3 \
               AND expires_at > $4 AND generation < 9223372036854775807",
        )
        .bind(&command.post_id)
        .bind(command.expected_generation)
        .bind(command.expected_post_version)
        .bind(command.now)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() != 1 {
            return Ok(RevokePostReviewLinkOutcome::Conflict);
        }
        tx.commit().await?;
        Ok(RevokePostReviewLinkOutcome::Revoked)
    }

    async fn resolve_post_review_async(
        &self,
        token_hash: &str,
        now: i64,
    ) -> Result<Option<ResolvedPostReview>, sqlx::Error> {
        if !review_token_hash_is_valid(token_hash) {
            return Ok(None);
        }
        // One statement snapshot keeps capability, guard, visibility, and pinned revision
        // mutually consistent while a concurrent author save publishes, rotates, or deletes.
        let row = sqlx::query(
            "SELECT post.id AS stable_id, post.slug AS stable_slug, \
                    post.author_sub AS stable_author_sub, \
                    post.author_email AS stable_author_email, \
                    post.created_at AS stable_created_at, \
                    link.post_id AS link_post_id, link.revision_version, \
                    link.guard_edit_version, link.token_hash, link.generation, \
                    link.expires_at, link.issued_at, link.issued_by_sub, \
                    revision.id, revision.post_id, revision.edit_version, revision.title, \
                    revision.body_md, revision.published, revision.publish_at, \
                    revision.featured, revision.pinned, revision.tags, revision.cover_url, \
                    revision.custom_excerpt, revision.meta_title, revision.meta_description, \
                    revision.canonical_url, revision.social_title, revision.social_description, \
                    revision.social_image, revision.editor_sub, revision.editor_email, \
                    revision.source, revision.restored_from, revision.created_at \
             FROM post_review_links AS link \
             JOIN posts AS post ON post.id = link.post_id \
             JOIN post_revisions AS revision \
               ON revision.post_id = link.post_id \
              AND revision.edit_version = link.revision_version \
             WHERE link.token_hash = $1 AND link.expires_at > $2 \
               AND link.guard_edit_version = post.edit_version \
               AND NOT (post.published = TRUE \
                        AND (post.publish_at = 0 OR post.publish_at <= $2))",
        )
        .bind(token_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let revision = Self::revision_from_row(&row)?;
        let link = PostReviewLink {
            post_id: row.try_get("link_post_id")?,
            revision_version: row.try_get("revision_version")?,
            guard_edit_version: row.try_get("guard_edit_version")?,
            token_hash: row.try_get("token_hash")?,
            generation: row.try_get("generation")?,
            expires_at: row.try_get("expires_at")?,
            issued_at: row.try_get("issued_at")?,
            issued_by_sub: row.try_get("issued_by_sub")?,
        };
        let stable = Post {
            id: row.try_get("stable_id")?,
            slug: row.try_get("stable_slug")?,
            title: String::new(),
            body_md: String::new(),
            author_sub: row.try_get("stable_author_sub")?,
            author_email: row.try_get("stable_author_email")?,
            created_at: row.try_get("stable_created_at")?,
            updated_at: 0,
            edit_version: link.guard_edit_version,
            published: false,
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
        };
        Ok(Some(ResolvedPostReview {
            post: review_post_from_revision(&stable, &revision),
            revision,
            link,
        }))
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
        sqlx::query("DELETE FROM writer_autosaves WHERE session_id = $1 AND expires_at <= $2")
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

    async fn delete_post_cas_async(
        &self,
        command: &DeletePostCommand,
    ) -> Result<DeletePostOutcome, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let row = match &command.scope {
            DeletePostScope::Owner(owner_sub) => {
                sqlx::query(&format!(
                    "{POST_COLS} WHERE slug = $1 AND id = $2 AND edit_version = $3 \
                     AND author_sub = $4 FOR UPDATE"
                ))
                .bind(&command.slug)
                .bind(&command.post_id)
                .bind(command.expected_version)
                .bind(owner_sub)
                .fetch_optional(&mut *tx)
                .await?
            }
            DeletePostScope::Admin => {
                sqlx::query(&format!(
                    "{POST_COLS} WHERE slug = $1 AND id = $2 AND edit_version = $3 FOR UPDATE"
                ))
                .bind(&command.slug)
                .bind(&command.post_id)
                .bind(command.expected_version)
                .fetch_optional(&mut *tx)
                .await?
            }
        };
        let Some(row) = row else {
            return Ok(DeletePostOutcome::Conflict);
        };
        let deleted = Self::post_from_row(&row)?;
        sqlx::query("DELETE FROM writer_autosaves WHERE post_id = $1")
            .bind(&deleted.id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM post_revisions WHERE post_id = $1")
            .bind(&deleted.id)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query("DELETE FROM posts WHERE id = $1 AND edit_version = $2")
            .bind(&deleted.id)
            .bind(command.expected_version)
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() != 1 {
            return Ok(DeletePostOutcome::Conflict);
        }
        tx.commit().await?;
        Ok(DeletePostOutcome::Deleted(Box::new(deleted)))
    }

    async fn delete_posts_cas_async(
        &self,
        mut command: DeletePostsCommand,
    ) -> Result<DeletePostsOutcome, sqlx::Error> {
        if command.selections.is_empty()
            || command.selections.len() > crate::config::POST_BULK_DELETE_MAX
        {
            return Ok(DeletePostsOutcome::Conflict);
        }
        // A deterministic immutable-id order prevents two overlapping admin batches from taking
        // row locks in opposite orders. Duplicate ids are rejected before a transaction starts.
        command
            .selections
            .sort_by(|left, right| left.post_id.cmp(&right.post_id));
        if command
            .selections
            .windows(2)
            .any(|pair| pair[0].post_id == pair[1].post_id)
        {
            return Ok(DeletePostsOutcome::Conflict);
        }

        let mut tx = self.pool.begin().await?;
        let mut deleted = Vec::with_capacity(command.selections.len());
        // Lock and authorize the complete stable set before deleting any parent or child row.
        // Returning Conflict drops this transaction, so every category remains all-or-nothing.
        for selection in &command.selections {
            let row = match &command.scope {
                DeletePostScope::Owner(owner_sub) => {
                    sqlx::query(&format!(
                        "{POST_COLS} WHERE author_sub = $1 AND id = $2 FOR UPDATE"
                    ))
                    .bind(owner_sub)
                    .bind(&selection.post_id)
                    .fetch_optional(&mut *tx)
                    .await?
                }
                DeletePostScope::Admin => {
                    sqlx::query(&format!("{POST_COLS} WHERE id = $1 FOR UPDATE"))
                        .bind(&selection.post_id)
                        .fetch_optional(&mut *tx)
                        .await?
                }
            };
            let Some(row) = row else {
                return Ok(DeletePostsOutcome::Conflict);
            };
            let post = Self::post_from_row(&row)?;
            if post.slug != selection.slug || post.edit_version != selection.expected_version {
                return Ok(DeletePostsOutcome::Conflict);
            }
            deleted.push(post);
        }

        for post in &deleted {
            sqlx::query("DELETE FROM writer_autosaves WHERE post_id = $1")
                .bind(&post.id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM post_revisions WHERE post_id = $1")
                .bind(&post.id)
                .execute(&mut *tx)
                .await?;
            let result =
                sqlx::query("DELETE FROM posts WHERE id = $1 AND slug = $2 AND edit_version = $3")
                    .bind(&post.id)
                    .bind(&post.slug)
                    .bind(post.edit_version)
                    .execute(&mut *tx)
                    .await?;
            if result.rows_affected() != 1 {
                return Ok(DeletePostsOutcome::Conflict);
            }
        }
        tx.commit().await?;
        Ok(DeletePostsOutcome::Deleted(deleted))
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

    async fn list_library(&self, query: LibraryQuery) -> Result<LibraryPage, StoreError> {
        self.list_library_async(query)
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))
    }

    async fn bulk_update_library(
        &self,
        command: LibraryBulkCommand,
    ) -> Result<LibraryBulkOutcome, StoreError> {
        self.bulk_update_library_async(command)
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

    async fn get_post_revision_pair(
        &self,
        post_id: &str,
        from_revision_id: &str,
        to_revision_id: &str,
    ) -> Result<Option<PostRevisionPair>, StoreError> {
        self.get_post_revision_pair_async(post_id, from_revision_id, to_revision_id)
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))
    }

    async fn get_post_review_link(
        &self,
        post_id: &str,
        owner_sub: &str,
        now: i64,
    ) -> Result<Option<PostReviewLink>, StoreError> {
        self.get_post_review_link_async(post_id, owner_sub, now)
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))
    }

    async fn save_post_review_link(
        &self,
        command: SavePostReviewLinkCommand,
    ) -> Result<SavePostReviewLinkOutcome, StoreError> {
        self.save_post_review_link_async(&command)
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))
    }

    async fn revoke_post_review_link(
        &self,
        command: RevokePostReviewLinkCommand,
    ) -> Result<RevokePostReviewLinkOutcome, StoreError> {
        self.revoke_post_review_link_async(&command)
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))
    }

    async fn resolve_post_review(
        &self,
        token_hash: &str,
        now: i64,
    ) -> Result<Option<ResolvedPostReview>, StoreError> {
        self.resolve_post_review_async(token_hash, now)
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

    async fn delete_post_cas(
        &self,
        command: DeletePostCommand,
    ) -> Result<DeletePostOutcome, StoreError> {
        self.delete_post_cas_async(&command)
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))
    }

    async fn delete_posts_cas(
        &self,
        command: DeletePostsCommand,
    ) -> Result<DeletePostsOutcome, StoreError> {
        self.delete_posts_cas_async(command)
            .await
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

        assert!(
            store
                .get_writer_autosave(target, &post.author_sub, 2)
                .await
                .unwrap()
                .is_none(),
            "expired row beyond cleanup batch stays unreadable"
        );
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

    #[tokio::test]
    async fn library_is_owner_scoped_composable_and_keyset_stable() {
        let store = InMemoryStore::new();
        let now = 1_000;
        let mut published = post("alice-published", 10);
        published.author_sub = "alice".to_string();
        published.title = "Needle field note".to_string();
        published.tags = "Rust, Notes".to_string();
        published.updated_at = 30;
        store.create_post(&published).await.unwrap();

        let mut draft = post("alice-draft", 20);
        draft.author_sub = "alice".to_string();
        draft.title = "Needle draft".to_string();
        draft.tags = "Rust".to_string();
        draft.published = false;
        draft.updated_at = 40;
        store.create_post(&draft).await.unwrap();

        let mut scheduled = post("alice-scheduled", 30);
        scheduled.author_sub = "alice".to_string();
        scheduled.title = "Needle scheduled".to_string();
        scheduled.tags = "Rust".to_string();
        scheduled.publish_at = now + 60;
        scheduled.updated_at = 40;
        store.create_post(&scheduled).await.unwrap();

        let mut foreign = post("bob-private-needle", 40);
        foreign.author_sub = "bob".to_string();
        foreign.published = false;
        foreign.tags = "Rust".to_string();
        foreign.updated_at = 50;
        store.create_post(&foreign).await.unwrap();

        let query = |status, cursor, limit, sort| LibraryQuery {
            owner_sub: "alice".to_string(),
            q: "needle".to_string(),
            status,
            tag: "rust".to_string(),
            sort,
            as_of: now,
            cursor,
            limit,
        };
        let first = store
            .list_library(query(LibraryStatus::All, None, 1, LibrarySort::Updated))
            .await
            .unwrap();
        assert_eq!(
            first.posts[0].id, "alice-scheduled",
            "id breaks updated_at tie"
        );
        let second = store
            .list_library(query(
                LibraryStatus::All,
                first.next,
                2,
                LibrarySort::Updated,
            ))
            .await
            .unwrap();
        assert_eq!(
            second
                .posts
                .iter()
                .map(|post| post.id.as_str())
                .collect::<Vec<_>>(),
            vec!["alice-draft", "alice-published"]
        );
        assert!(second.posts.iter().all(|post| post.author_sub == "alice"));
        assert_eq!(
            store
                .list_library(query(LibraryStatus::Draft, None, 10, LibrarySort::Updated))
                .await
                .unwrap()
                .posts
                .iter()
                .map(|post| post.id.as_str())
                .collect::<Vec<_>>(),
            vec!["alice-draft"]
        );
        assert_eq!(
            store
                .list_library(query(
                    LibraryStatus::Scheduled,
                    None,
                    10,
                    LibrarySort::Updated,
                ))
                .await
                .unwrap()
                .posts[0]
                .id,
            "alice-scheduled"
        );
        assert_eq!(
            store
                .list_library(query(
                    LibraryStatus::Published,
                    None,
                    10,
                    LibrarySort::Updated,
                ))
                .await
                .unwrap()
                .posts[0]
                .id,
            "alice-published"
        );
        let created = store
            .list_library(query(LibraryStatus::All, None, 10, LibrarySort::Created))
            .await
            .unwrap();
        assert_eq!(
            created
                .posts
                .iter()
                .map(|post| post.id.as_str())
                .collect::<Vec<_>>(),
            vec!["alice-scheduled", "alice-draft", "alice-published"]
        );
        assert_eq!(created.next, None);
        let mismatched = store
            .list_library(query(
                LibraryStatus::All,
                Some(LibraryCursor {
                    sort: LibrarySort::Created,
                    sort_at: 30,
                    post_id: "alice-scheduled".to_string(),
                }),
                10,
                LibrarySort::Updated,
            ))
            .await
            .unwrap();
        assert!(mismatched.posts.is_empty());
        assert_eq!(mismatched.next, None);
    }

    #[tokio::test]
    async fn library_bulk_is_atomic_versioned_and_leaves_autosaves_private() {
        let store = InMemoryStore::new();
        let mut one = post("bulk-one", 10);
        one.author_sub = "alice".to_string();
        one.author_email = "alice@hf".to_string();
        one.published = false;
        one.featured = true;
        store.create_post(&one).await.unwrap();
        let mut two = post("bulk-two", 20);
        two.author_sub = "alice".to_string();
        two.author_email = "alice@hf".to_string();
        two.published = false;
        store.create_post(&two).await.unwrap();
        let mut foreign = post("bulk-foreign", 30);
        foreign.author_sub = "bob".to_string();
        store.create_post(&foreign).await.unwrap();

        let autosave = WriterAutosave {
            session_id: "library-autosave".to_string(),
            post_id: one.id.clone(),
            owner_sub: "alice".to_string(),
            base_version: 1,
            client_seq: 1,
            title: one.title.clone(),
            body_md: "private recovery".to_string(),
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
            updated_at: 30,
            expires_at: 1_000,
        };
        store.put_writer_autosave(autosave, 30).await.unwrap();

        let command = |selections, action| LibraryBulkCommand {
            owner_sub: "alice".to_string(),
            editor_email: "alice@hf".to_string(),
            selections,
            action,
            now: 30,
        };
        let stale = store
            .bulk_update_library(command(
                vec![
                    LibrarySelection {
                        post_id: one.id.clone(),
                        expected_version: 1,
                    },
                    LibrarySelection {
                        post_id: two.id.clone(),
                        expected_version: 99,
                    },
                ],
                LibraryBulkAction::PublishNow,
            ))
            .await
            .unwrap();
        assert_eq!(stale, LibraryBulkOutcome::Conflict);
        assert!(!store.get_post("bulk-one").await.unwrap().published);

        let applied = store
            .bulk_update_library(command(
                vec![
                    LibrarySelection {
                        post_id: two.id.clone(),
                        expected_version: 1,
                    },
                    LibrarySelection {
                        post_id: one.id.clone(),
                        expected_version: 1,
                    },
                ],
                LibraryBulkAction::AddTag("Roadmap".to_string()),
            ))
            .await
            .unwrap();
        let LibraryBulkOutcome::Applied(changed) = applied else {
            panic!("valid author bulk command must apply");
        };
        assert_eq!(changed.len(), 2);
        let saved_one = store.get_post("bulk-one").await.unwrap();
        assert_eq!(saved_one.edit_version, 2);
        assert!(saved_one.updated_at > one.updated_at);
        assert!(crate::tags::has_tag(&saved_one.tags, "roadmap"));
        assert!(
            saved_one.featured,
            "author bulk never changes admin feature state"
        );
        assert!(
            store
                .get_writer_autosave("library-autosave", "alice", 31)
                .await
                .unwrap()
                .is_some(),
            "bulk never consumes private Writer recovery"
        );
        assert_eq!(
            store.list_post_revisions(&one.id, 10).await.unwrap()[0].source,
            "library.tag.add"
        );

        let no_op = store
            .bulk_update_library(command(
                vec![LibrarySelection {
                    post_id: one.id.clone(),
                    expected_version: 2,
                }],
                LibraryBulkAction::AddTag("roadmap".to_string()),
            ))
            .await
            .unwrap();
        assert_eq!(no_op, LibraryBulkOutcome::Applied(Vec::new()));
        assert_eq!(store.get_post("bulk-one").await.unwrap().edit_version, 2);

        let oversized = store
            .bulk_update_library(command(
                vec![
                    LibrarySelection {
                        post_id: one.id.clone(),
                        expected_version: 2,
                    };
                    crate::config::LIBRARY_BULK_MAX + 1
                ],
                LibraryBulkAction::Pin,
            ))
            .await
            .unwrap();
        assert_eq!(oversized, LibraryBulkOutcome::Conflict);
        assert!(!store.get_post("bulk-one").await.unwrap().pinned);

        let foreign = store
            .bulk_update_library(command(
                vec![LibrarySelection {
                    post_id: foreign.id,
                    expected_version: 1,
                }],
                LibraryBulkAction::Pin,
            ))
            .await
            .unwrap();
        assert_eq!(foreign, LibraryBulkOutcome::Conflict);
    }

    #[tokio::test]
    async fn library_bulk_accepts_exactly_fifty_and_rolls_back_all_on_one_stale_row() {
        let store = InMemoryStore::new();
        let mut selections = Vec::new();
        for index in 0..crate::config::LIBRARY_BULK_MAX {
            let mut item = post(&format!("bounded-{index:02}"), index as i64);
            item.author_sub = "alice".to_string();
            item.published = false;
            store.create_post(&item).await.unwrap();
            selections.push(LibrarySelection {
                post_id: item.id,
                expected_version: 1,
            });
        }
        let applied = store
            .bulk_update_library(LibraryBulkCommand {
                owner_sub: "alice".to_string(),
                editor_email: "alice@hf".to_string(),
                selections: selections.clone(),
                action: LibraryBulkAction::Pin,
                now: 100,
            })
            .await
            .unwrap();
        let LibraryBulkOutcome::Applied(changed) = applied else {
            panic!("the exact 50-row boundary must be accepted");
        };
        assert_eq!(changed.len(), crate::config::LIBRARY_BULK_MAX);
        assert!(changed
            .iter()
            .all(|item| item.pinned && item.edit_version == 2));

        let mut stale = selections
            .into_iter()
            .map(|mut selection| {
                selection.expected_version = 2;
                selection
            })
            .collect::<Vec<_>>();
        stale[37].expected_version = 1;
        assert_eq!(
            store
                .bulk_update_library(LibraryBulkCommand {
                    owner_sub: "alice".to_string(),
                    editor_email: "alice@hf".to_string(),
                    selections: stale,
                    action: LibraryBulkAction::Unpin,
                    now: 101,
                })
                .await
                .unwrap(),
            LibraryBulkOutcome::Conflict
        );
        for index in 0..crate::config::LIBRARY_BULK_MAX {
            let saved = store
                .get_post(&format!("bounded-{index:02}"))
                .await
                .unwrap();
            assert!(saved.pinned);
            assert_eq!(saved.edit_version, 2, "no row partially advanced");
        }
    }

    #[tokio::test]
    async fn delete_cas_is_owner_scoped_and_rejects_slug_replacement_aba() {
        let store = InMemoryStore::new();
        let mut original = post("delete-original", 10);
        original.slug = "stable-slug".to_string();
        original.author_sub = "alice".to_string();
        store.create_post(&original).await.unwrap();

        let command = |post_id: &str, version: i64, scope| DeletePostCommand {
            slug: "stable-slug".to_string(),
            post_id: post_id.to_string(),
            expected_version: version,
            scope,
        };
        assert_eq!(
            store
                .delete_post_cas(command(
                    &original.id,
                    original.edit_version,
                    DeletePostScope::Owner("bob".to_string()),
                ))
                .await
                .unwrap(),
            DeletePostOutcome::Conflict
        );
        assert_eq!(
            store
                .delete_post_cas(command(
                    &original.id,
                    original.edit_version + 1,
                    DeletePostScope::Owner("alice".to_string()),
                ))
                .await
                .unwrap(),
            DeletePostOutcome::Conflict
        );

        store.delete_post("stable-slug").await.unwrap();
        let mut replacement = post("delete-replacement", 20);
        replacement.slug = "stable-slug".to_string();
        replacement.author_sub = "alice".to_string();
        store.create_post(&replacement).await.unwrap();
        assert_eq!(
            store
                .delete_post_cas(command(
                    &original.id,
                    original.edit_version,
                    DeletePostScope::Admin,
                ))
                .await
                .unwrap(),
            DeletePostOutcome::Conflict,
            "even admin authority is bound to the rendered immutable identity"
        );
        assert_eq!(
            store.get_post("stable-slug").await.unwrap().id,
            replacement.id
        );

        let deleted = store
            .delete_post_cas(command(
                &replacement.id,
                replacement.edit_version,
                DeletePostScope::Admin,
            ))
            .await
            .unwrap();
        assert!(matches!(deleted, DeletePostOutcome::Deleted(post) if post.id == replacement.id));
        assert!(store.get_post("stable-slug").await.is_none());
    }

    #[tokio::test]
    async fn bulk_delete_cas_is_bounded_generic_and_all_or_nothing() {
        let store = InMemoryStore::new();
        let mut one = post("bulk-delete-one", 10);
        one.author_sub = "alice".to_string();
        let mut two = post("bulk-delete-two", 20);
        two.author_sub = "alice".to_string();
        let mut foreign = post("bulk-delete-foreign", 30);
        foreign.author_sub = "bob".to_string();
        for item in [&one, &two, &foreign] {
            store.create_post(item).await.unwrap();
        }
        let selection = |item: &Post, version: i64| DeletePostSelection {
            slug: item.slug.clone(),
            post_id: item.id.clone(),
            expected_version: version,
        };
        let command = |selections, scope| DeletePostsCommand { selections, scope };

        assert_eq!(
            store
                .delete_posts_cas(command(
                    vec![
                        selection(&one, one.edit_version),
                        selection(&one, one.edit_version),
                    ],
                    DeletePostScope::Admin,
                ))
                .await
                .unwrap(),
            DeletePostsOutcome::Conflict,
            "duplicate immutable ids fail as one generic conflict"
        );
        assert!(store.get_post(&one.slug).await.is_some());
        assert!(store.get_post(&two.slug).await.is_some());

        assert_eq!(
            store
                .delete_posts_cas(command(
                    vec![
                        selection(&one, one.edit_version),
                        selection(&two, two.edit_version + 1),
                    ],
                    DeletePostScope::Admin,
                ))
                .await
                .unwrap(),
            DeletePostsOutcome::Conflict,
            "a stale later checkbox deletes no earlier valid row"
        );
        assert!(store.get_post(&one.slug).await.is_some());
        assert!(store.get_post(&two.slug).await.is_some());

        assert_eq!(
            store
                .delete_posts_cas(command(
                    vec![
                        selection(&one, one.edit_version),
                        selection(&foreign, foreign.edit_version),
                    ],
                    DeletePostScope::Owner("alice".to_string()),
                ))
                .await
                .unwrap(),
            DeletePostsOutcome::Conflict,
            "foreign and missing identities share the generic conflict"
        );
        assert!(store.get_post(&one.slug).await.is_some());
        assert!(store.get_post(&foreign.slug).await.is_some());

        let missing = DeletePostSelection {
            slug: "bulk-delete-missing".to_string(),
            post_id: "bulk-delete-missing".to_string(),
            expected_version: 1,
        };
        assert_eq!(
            store
                .delete_posts_cas(command(
                    vec![selection(&one, one.edit_version), missing],
                    DeletePostScope::Admin,
                ))
                .await
                .unwrap(),
            DeletePostsOutcome::Conflict
        );
        assert!(store.get_post(&one.slug).await.is_some());

        let mut old = post("bulk-delete-old", 40);
        old.slug = "bulk-delete-reused".to_string();
        store.create_post(&old).await.unwrap();
        store.delete_post(&old.slug).await.unwrap();
        let mut replacement = post("bulk-delete-replacement", 41);
        replacement.slug = old.slug.clone();
        store.create_post(&replacement).await.unwrap();
        assert_eq!(
            store
                .delete_posts_cas(command(
                    vec![
                        selection(&one, one.edit_version),
                        selection(&old, old.edit_version),
                    ],
                    DeletePostScope::Admin,
                ))
                .await
                .unwrap(),
            DeletePostsOutcome::Conflict,
            "slug replacement never inherits a stale bulk selection"
        );
        assert!(store.get_post(&one.slug).await.is_some());
        assert_eq!(
            store.get_post(&replacement.slug).await.unwrap().id,
            replacement.id
        );

        let oversized = (0..=crate::config::POST_BULK_DELETE_MAX)
            .map(|index| DeletePostSelection {
                slug: format!("oversized-{index}"),
                post_id: format!("oversized-{index}"),
                expected_version: 1,
            })
            .collect();
        assert_eq!(
            store
                .delete_posts_cas(command(oversized, DeletePostScope::Admin))
                .await
                .unwrap(),
            DeletePostsOutcome::Conflict
        );
        assert!(store.get_post(&one.slug).await.is_some());

        let deleted = store
            .delete_posts_cas(command(
                vec![
                    selection(&two, two.edit_version),
                    selection(&one, one.edit_version),
                ],
                DeletePostScope::Admin,
            ))
            .await
            .unwrap();
        assert!(matches!(deleted, DeletePostsOutcome::Deleted(posts) if posts.len() == 2));
        assert!(store.get_post(&one.slug).await.is_none());
        assert!(store.get_post(&two.slug).await.is_none());
        assert!(store.get_post(&foreign.slug).await.is_some());
        assert!(store.get_post(&replacement.slug).await.is_some());

        let mut boundary = Vec::with_capacity(crate::config::POST_BULK_DELETE_MAX);
        for index in 0..crate::config::POST_BULK_DELETE_MAX {
            let item = post(
                &format!("bulk-delete-boundary-{index:02}"),
                100 + index as i64,
            );
            store.create_post(&item).await.unwrap();
            boundary.push(selection(&item, item.edit_version));
        }
        let deleted = store
            .delete_posts_cas(command(boundary, DeletePostScope::Admin))
            .await
            .unwrap();
        assert!(
            matches!(deleted, DeletePostsOutcome::Deleted(posts) if posts.len() == crate::config::POST_BULK_DELETE_MAX)
        );
        for index in 0..crate::config::POST_BULK_DELETE_MAX {
            assert!(
                store
                    .get_post(&format!("bulk-delete-boundary-{index:02}"))
                    .await
                    .is_none(),
                "the exact 50-row boundary is accepted"
            );
        }
    }

    #[tokio::test]
    async fn save_post_fails_closed_when_version_or_updated_at_is_exhausted() {
        let store = InMemoryStore::new();
        let mut version_exhausted = post("version-exhausted", 10);
        version_exhausted.edit_version = i64::MAX;
        store.create_post(&version_exhausted).await.unwrap();
        let revisions_before = store
            .list_post_revisions(&version_exhausted.id, 10)
            .await
            .unwrap()
            .len();
        let mut changed = version_exhausted.clone();
        changed.title = "must not save".to_string();
        assert_eq!(
            store
                .save_post(SavePostCommand {
                    post: changed,
                    expected_version: i64::MAX,
                    editor_sub: "u".to_string(),
                    editor_email: "u@hf".to_string(),
                    source: "test".to_string(),
                    restored_from: None,
                    consume_autosave_session: None,
                })
                .await
                .unwrap(),
            SavePostOutcome::Conflict {
                current_version: i64::MAX
            }
        );
        assert_eq!(
            store.get_post("version-exhausted").await.unwrap().title,
            version_exhausted.title
        );
        assert_eq!(
            store
                .list_post_revisions(&version_exhausted.id, 10)
                .await
                .unwrap()
                .len(),
            revisions_before,
            "failed save appends no revision"
        );

        let mut timestamp_exhausted = post("timestamp-exhausted", 20);
        timestamp_exhausted.updated_at = i64::MAX;
        store.create_post(&timestamp_exhausted).await.unwrap();
        let mut changed = timestamp_exhausted.clone();
        changed.body_md = "must not save".to_string();
        assert_eq!(
            store
                .save_post(SavePostCommand {
                    post: changed,
                    expected_version: 1,
                    editor_sub: "u".to_string(),
                    editor_email: "u@hf".to_string(),
                    source: "test".to_string(),
                    restored_from: None,
                    consume_autosave_session: None,
                })
                .await
                .unwrap(),
            SavePostOutcome::Conflict { current_version: 1 }
        );
        assert_eq!(
            store.get_post("timestamp-exhausted").await.unwrap().body_md,
            timestamp_exhausted.body_md
        );
    }

    #[test]
    fn memory_revision_prune_keeps_newest_window_then_one_older_pinned_snapshot() {
        let revisions = |post_id: &str, count: i64| {
            let mut fixture = post(post_id, 100);
            (1..=count)
                .map(|version| {
                    fixture.edit_version = version;
                    fixture.updated_at = version;
                    revision_from_post(&fixture, "u", "u@hf", "test", None)
                })
                .collect::<Vec<_>>()
        };

        let mut pinned_inside = revisions("review-prune-inside", 101);
        prune_mem_revisions(&mut pinned_inside, "review-prune-inside", Some(100));
        assert_eq!(pinned_inside.len(), crate::config::REVISION_KEEP_LIMIT);
        assert!(pinned_inside
            .iter()
            .any(|revision| revision.edit_version == 100));
        assert!(!pinned_inside
            .iter()
            .any(|revision| revision.edit_version == 1));

        let mut pinned_outside = revisions("review-prune-outside", 102);
        prune_mem_revisions(&mut pinned_outside, "review-prune-outside", Some(1));
        assert_eq!(pinned_outside.len(), crate::config::REVISION_KEEP_LIMIT + 1);
        assert!(pinned_outside
            .iter()
            .any(|revision| revision.edit_version == 1));
        assert!(!pinned_outside
            .iter()
            .any(|revision| revision.edit_version == 2));
    }

    #[tokio::test]
    async fn rollback_version_advance_invalidates_guard_and_v8_save_never_revives_link() {
        let store = InMemoryStore::new();
        let mut fixture = post("review-rollback-guard", 100);
        fixture.published = false;
        fixture.body_md = "v8 pinned body".to_string();
        store.create_post(&fixture).await.unwrap();
        let issued = store
            .save_post_review_link(SavePostReviewLinkCommand {
                post_id: fixture.id.clone(),
                owner_sub: fixture.author_sub.clone(),
                expected_post_version: 1,
                expected_generation: None,
                token_hash: "a".repeat(64),
                requested_expires_at: 1_000,
                now: 100,
            })
            .await
            .unwrap();
        assert!(matches!(issued, SavePostReviewLinkOutcome::Saved(_)));
        assert!(store
            .resolve_post_review(&"a".repeat(64), 101)
            .await
            .unwrap()
            .is_some());

        // Simulate a rollback image that knows `posts.edit_version` but not review-link guards.
        // It advances the post row directly and leaves the capability row untouched.
        {
            let _mutation = store.mutation_lock.lock().unwrap();
            let mut posts = store.posts.lock().unwrap();
            let current = posts.iter_mut().find(|post| post.id == fixture.id).unwrap();
            current.edit_version = 2;
            current.updated_at = 101;
            current.body_md = "rollback image body".to_string();
        }
        assert!(store
            .resolve_post_review(&"a".repeat(64), 102)
            .await
            .unwrap()
            .is_none());

        let current = store.get_post(&fixture.slug).await.unwrap();
        let mut v8_edit = current.clone();
        v8_edit.body_md = "v8 after rollback".to_string();
        v8_edit.updated_at = 102;
        assert!(matches!(
            store
                .save_post(SavePostCommand {
                    post: v8_edit,
                    expected_version: 2,
                    editor_sub: fixture.author_sub.clone(),
                    editor_email: fixture.author_email.clone(),
                    source: "v8-after-rollback".to_string(),
                    restored_from: None,
                    consume_autosave_session: None,
                })
                .await
                .unwrap(),
            SavePostOutcome::Saved(_)
        ));
        assert!(store.review_links.lock().unwrap().is_empty());
        assert!(store
            .resolve_post_review(&"a".repeat(64), 103)
            .await
            .unwrap()
            .is_none());

        let current = store.get_post(&fixture.slug).await.unwrap();
        let replacement = store
            .save_post_review_link(SavePostReviewLinkCommand {
                post_id: current.id,
                owner_sub: current.author_sub,
                expected_post_version: current.edit_version,
                expected_generation: None,
                token_hash: "b".repeat(64),
                requested_expires_at: 1_000,
                now: 103,
            })
            .await
            .unwrap();
        assert!(matches!(replacement, SavePostReviewLinkOutcome::Saved(_)));
        assert!(store
            .resolve_post_review(&"a".repeat(64), 104)
            .await
            .unwrap()
            .is_none());
        assert!(store
            .resolve_post_review(&"b".repeat(64), 104)
            .await
            .unwrap()
            .is_some());
    }
}
