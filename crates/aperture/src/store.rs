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
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use thiserror::Error;

use crate::config::clamp_page;
use crate::model::{
    library_type_for, FileComment, FileRec, FolderRec, LibraryCursor, LibraryItem, LibraryItemKind,
    LibraryPage, LibraryQuery, LibraryType, LibraryView, OwnerUsage, TrashEntry, TrashItem,
    TrashPage, UploadRequestInbox, UploadRequestInboxCounts, UploadRequestInboxState,
    UploadRequestInboxView, UploadRequestRec, UploadRequestSummary, UploadSubmission, VersionRec,
    UPLOAD_REQUEST_EXPIRING_WINDOW_SECS, UPLOAD_REQUEST_INBOX_CAP,
};

const DEFAULT_TRASH_RETENTION_SECS: i64 = 30 * 24 * 60 * 60;
/// Domain boundary for every lifecycle mutation, including non-HTTP callers and workers.
pub const MAX_BULK_ITEMS: usize = 200;

fn mutation_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn next_mutation_time(previous: i64) -> i64 {
    mutation_time().max(previous.saturating_add(1))
}

fn file_library_item(file: &FileRec, now: i64) -> LibraryItem {
    LibraryItem {
        kind: LibraryItemKind::File,
        id: file.id.clone(),
        parent_id: file.folder_id.clone(),
        name: file.name.clone(),
        content_type: Some(file.content_type.clone()),
        size: Some(file.size),
        created_at: file.created_at,
        updated_at: file.updated_at,
        shared: file.share_token.is_some(),
        share_expired: file.share_token.is_some() && file.share_expired(now),
        share_protected: file.share_token.is_some() && file.share_has_password(),
    }
}

fn folder_library_item(folder: &FolderRec, now: i64) -> LibraryItem {
    LibraryItem {
        kind: LibraryItemKind::Folder,
        id: folder.id.clone(),
        parent_id: folder.parent_id.clone(),
        name: folder.name.clone(),
        content_type: None,
        size: None,
        created_at: folder.created_at,
        updated_at: folder.updated_at,
        shared: folder.share_token.is_some(),
        share_expired: folder.share_token.is_some() && folder.share_expired(now),
        share_protected: folder.share_token.is_some() && folder.share_has_password(),
    }
}

fn library_item_before(item: &LibraryItem, cursor: &LibraryCursor) -> bool {
    item.updated_at < cursor.updated_at
        || (item.updated_at == cursor.updated_at
            && (item.kind.rank() < cursor.kind.rank()
                || (item.kind == cursor.kind && item.id < cursor.id)))
}

fn library_item_matches(item: &LibraryItem, query: &LibraryQuery) -> bool {
    if query.view == LibraryView::Shared && !item.shared {
        return false;
    }
    if let Some(needle) = query.query.as_deref() {
        if !item.name.to_lowercase().contains(&needle.to_lowercase()) {
            return false;
        }
    }
    let item_type = match item.kind {
        LibraryItemKind::Folder => LibraryType::Folder,
        LibraryItemKind::File => library_type_for(item.content_type.as_deref().unwrap_or_default()),
    };
    (query.type_filter == LibraryType::All || query.type_filter == item_type)
        && query
            .before
            .as_ref()
            .is_none_or(|cursor| library_item_before(item, cursor))
}

fn finish_library_page(mut items: Vec<LibraryItem>, limit: i64) -> LibraryPage {
    let limit = clamp_page(limit) as usize;
    items.sort_by(|left, right| {
        right
            .updated_at
            .cmp(&left.updated_at)
            .then_with(|| right.kind.rank().cmp(&left.kind.rank()))
            .then_with(|| right.id.cmp(&left.id))
    });
    let has_more = items.len() > limit;
    items.truncate(limit);
    let next = has_more.then(|| items.last().expect("non-empty bounded page").cursor());
    LibraryPage { items, next }
}

/// Safe, finite defaults for a newly-created upload request. The per-file limit is additionally
/// clamped to the runtime `MAX_UPLOAD` by the handler.
pub const DEFAULT_REQUEST_MAX_FILE_BYTES: i64 = 25 * 1024 * 1024;
pub const DEFAULT_REQUEST_MAX_TOTAL_BYTES: i64 = 100 * 1024 * 1024;
pub const DEFAULT_REQUEST_MAX_FILES: i64 = 50;
pub const DEFAULT_REQUEST_ALLOWED_TYPES: &str = "*/*";

/// Domain result of the atomic public-upload reservation. Expected policy rejections are values,
/// not backend errors, so the public handler can collapse them into its fixed capability shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadReserve {
    Reserved,
    Unavailable,
    FileTooLarge,
    TotalBudgetExceeded,
    FileCountExceeded,
    TypeDenied,
    OwnerQuotaExceeded,
    Collision,
}

/// Inputs to one atomic public-upload reservation. Keeping authority, verified type and budgets in
/// one value makes it harder for callers to omit a check when the reservation contract evolves.
#[derive(Debug, Clone, Copy)]
pub struct UploadReserveInput<'a> {
    pub request_id: &'a str,
    pub expected_token: &'a str,
    pub reservation_id: &'a str,
    pub size: i64,
    pub content_type: &'a str,
    pub content_type_verified: bool,
    pub owner_quota: Option<i64>,
    pub now: i64,
}

/// One durable reservation claimed by startup recovery. The reservation id is also the blob's
/// object key, so recovery can remove bytes before it returns the request budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadRecoveryItem {
    pub reservation_id: String,
    pub object_key: String,
}

/// Atomic result of trying to lease every outstanding upload reservation for recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadRecoveryClaim {
    /// This startup owns these rows until it completes or abandons the lease.
    Claimed(Vec<UploadRecoveryItem>),
    /// There are no outstanding reservations.
    Empty,
    /// Another startup currently owns the outstanding rows. Failing this startup avoids serving
    /// while cleanup outcome is unknown.
    Busy,
}

/// Tokens are fixed-size capabilities, but compare every byte without an early mismatch return so
/// the authority check behaves consistently in both Store implementations.
fn capability_token_eq(actual: &str, expected: &str) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    actual
        .bytes()
        .zip(expected.bytes())
        .fold(0_u8, |diff, (left, right)| diff | (left ^ right))
        == 0
}

fn request_allows_unverified_type(request: &UploadRequestRec) -> bool {
    request
        .allowed_types
        .split(',')
        .any(|pattern| pattern.trim() == "*/*")
}

fn upload_request_summary(request: &UploadRequestRec, as_of: i64) -> UploadRequestSummary {
    UploadRequestSummary {
        id: request.id.clone(),
        title: request.title.clone(),
        description: request.description.clone(),
        state: UploadRequestInboxState::classify(&request.status, request.expires_at, as_of),
        expires_at: request.expires_at,
        max_total_bytes: request.max_total_bytes,
        max_files: request.max_files,
        used_bytes: request.used_bytes,
        used_files: request.used_files,
        updated_at: request.updated_at,
    }
}

fn finish_upload_request_inbox(
    requests: impl IntoIterator<Item = UploadRequestRec>,
    view: UploadRequestInboxView,
    as_of: i64,
) -> UploadRequestInbox {
    let mut counts = UploadRequestInboxCounts::default();
    let mut items = Vec::new();
    for request in requests {
        let summary = upload_request_summary(&request, as_of);
        counts.all = counts.all.saturating_add(1);
        match summary.state {
            UploadRequestInboxState::Open => counts.open = counts.open.saturating_add(1),
            UploadRequestInboxState::Expiring => {
                counts.expiring = counts.expiring.saturating_add(1)
            }
            UploadRequestInboxState::Closed => counts.closed = counts.closed.saturating_add(1),
            UploadRequestInboxState::Expired => counts.expired = counts.expired.saturating_add(1),
        }
        if summary.state.is_in_view(view) {
            items.push(summary);
        }
    }
    items.sort_by(|left, right| {
        right
            .updated_at
            .cmp(&left.updated_at)
            .then_with(|| right.id.cmp(&left.id))
    });
    let matched_total = items.len().min(i64::MAX as usize) as i64;
    items.truncate(UPLOAD_REQUEST_INBOX_CAP as usize);
    UploadRequestInbox {
        as_of,
        view,
        counts,
        matched_total,
        truncated: matched_total > items.len() as i64,
        items,
    }
}

/// Storage failure surfaced to the handler layer (mapped to a 500 `server_error`).
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store error: {0}")]
    Backend(String),
}

/// Outcome of an "empty-only" folder delete: either the row was removed, the folder still holds
/// child folders / files (so a cascade is required), or it was absent / owned by someone else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FolderDelete {
    Deleted,
    NotEmpty,
    NotFound,
}

/// A type-tagged owner item submitted by the bulk control plane. Handlers parse the wire value;
/// Store implementations still re-check every id, owner and state atomically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveItemRef {
    pub kind: LibraryItemKind,
    pub id: String,
}

/// One selected live root paired with the freshly-random durable Trash entry id allocated by the
/// handler. The Store rejects the whole batch if any root is stale or the id collides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrashRootInput {
    pub item: DriveItemRef,
    pub entry_id: String,
}

/// Expected bulk conflicts are values rather than backend failures so handlers can return a
/// uniform 409 without leaking whether a stale id was absent, foreign, or in another lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BulkMutation {
    Applied { changed: usize },
    Conflict,
}

/// One durable object-delete outbox row leased by a bounded cleanup worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobDeleteItem {
    pub object_key: String,
    pub attempts: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlobDeleteClaim {
    Claimed(Vec<BlobDeleteItem>),
    Empty,
}

/// Result of an owner blob/metadata commit. Expected races stay domain values so HTTP handlers can
/// compensate a blob that was already written without turning a stale target into a false 302.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerBlobCommit {
    Applied,
    Conflict,
    Collision,
    QuotaExceeded,
}

pub const OWNER_WRITE_FRESH: &str = "fresh";
pub const OWNER_WRITE_REUPLOAD: &str = "reupload";
pub const OWNER_WRITE_THUMBNAIL: &str = "thumbnail";

/// Durable authority created before an owner blob write. The object key remains recoverable across
/// a process crash until metadata finalization consumes this row in the same transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerBlobWriteIntent {
    pub object_key: String,
    pub owner_sub: String,
    pub size: i64,
    pub kind: String,
    pub file_id: String,
    pub folder_id: Option<String>,
    pub expected_object_key: Option<String>,
    pub created_at: i64,
    pub attempts: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct OwnerReuploadInput<'a> {
    pub owner_sub: &'a str,
    pub file_id: &'a str,
    pub expected_object_key: &'a str,
    pub new_object_key: &'a str,
    pub new_size: i64,
    pub new_content_type: &'a str,
    pub snapshot_id: &'a str,
    pub changed_at: i64,
    pub owner_quota: Option<i64>,
}

#[derive(Debug, Clone, Copy)]
pub struct OwnerVersionRestoreInput<'a> {
    pub owner_sub: &'a str,
    pub file_id: &'a str,
    pub expected_object_key: &'a str,
    pub version_id: &'a str,
    pub snapshot_id: &'a str,
    pub changed_at: i64,
}

/// Pluggable metadata store. `create` is collision-aware over BOTH the id and the share token
/// (returns `false` on any unique conflict so the handler retries with fresh values); `delete`
/// is ownership-scoped.
#[async_trait]
pub trait Store: Send + Sync {
    /// Insert a file row. Returns `Ok(true)` when inserted, `Ok(false)` when a unique value
    /// (id or share token) already existed (the caller retries with fresh values).
    async fn create(&self, file: &FileRec) -> Result<bool, StoreError>;

    /// Commit owner upload metadata only after its blob exists. Implementations serialize on the
    /// owner guard, revalidate the live destination, and recompute quota in the same transaction.
    async fn commit_owner_upload(
        &self,
        file: &FileRec,
        owner_quota: Option<i64>,
    ) -> Result<OwnerBlobCommit, StoreError>;

    /// Reserve quota/cleanup authority before writing an owner blob.
    async fn reserve_owner_blob_write(
        &self,
        intent: &OwnerBlobWriteIntent,
        owner_quota: Option<i64>,
    ) -> Result<OwnerBlobCommit, StoreError>;

    /// CAS a live file's current object key, snapshot the actual current row, prune history, and
    /// durably enqueue stale derived/pruned objects as one metadata transaction.
    async fn commit_owner_reupload(
        &self,
        input: OwnerReuploadInput<'_>,
    ) -> Result<OwnerBlobCommit, StoreError>;

    /// Atomically restore one retained version while snapshotting the actual current file row.
    async fn commit_owner_version_restore(
        &self,
        input: OwnerVersionRestoreInput<'_>,
    ) -> Result<OwnerBlobCommit, StoreError>;

    /// Validate that the file still points at the source object and consume the thumbnail intent.
    async fn finalize_owner_thumbnail(
        &self,
        object_key: &str,
        owner_sub: &str,
        file_id: &str,
        expected_object_key: &str,
    ) -> Result<OwnerBlobCommit, StoreError>;

    async fn claim_owner_blob_writes(
        &self,
        lease_id: &str,
        now: i64,
        created_before: i64,
        lease_expired_before: i64,
        limit: i64,
    ) -> Result<Vec<OwnerBlobWriteIntent>, StoreError>;

    async fn complete_owner_blob_write(
        &self,
        object_key: &str,
        lease_id: &str,
    ) -> Result<bool, StoreError>;

    async fn abandon_owner_blob_write(
        &self,
        object_key: &str,
        lease_id: &str,
        retry_at: i64,
    ) -> Result<bool, StoreError>;

    /// Create an idempotent durable cleanup anchor for a blob that has no live metadata owner.
    async fn enqueue_blob_deletion(
        &self,
        object_key: &str,
        enqueued_at: i64,
        reason: &str,
    ) -> Result<(), StoreError>;

    /// Fetch a file by id.
    async fn get(&self, id: &str) -> Result<Option<FileRec>, StoreError>;

    /// Fetch a file by its public share token (the unauthenticated `/s/{token}` path).
    async fn get_by_token(&self, token: &str) -> Result<Option<FileRec>, StoreError>;

    /// Best-effort public landing-page view counter. Missing ids are a no-op so handlers can call
    /// it after a share-token lookup without turning analytics failures into public 500s.
    async fn bump_view_count(&self, id: &str) -> Result<(), StoreError>;

    /// An owner's files, newest-first, one keyset page at a time.
    ///
    /// `folder` selects the tree level: `None` is the ROOT view (only files whose `folder_id` IS
    /// NULL — the drive's top level), while `Some(id)` returns only the files whose `folder_id`
    /// equals that folder. Ordering is the fixed keyset `(created_at DESC, id DESC)`.
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

    /// Search/filter the owner's complete live library (files plus folders) using one stable
    /// `(updated_at, kind, id)` keyset. The result projection intentionally omits capability tokens.
    async fn query_library(
        &self,
        owner_sub: &str,
        query: &LibraryQuery,
    ) -> Result<LibraryPage, StoreError>;

    /// Hard-delete a file row only if it belongs to `owner_sub`. Returns `true` when a row was
    /// removed. Handler-level "Delete" uses [`Store::trash_file`]; this hard path is retained for
    /// upload rollback and "Delete forever".
    async fn delete(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError>;

    /// Soft-delete a live file only if it belongs to `owner_sub`.
    async fn trash_file(
        &self,
        id: &str,
        owner_sub: &str,
        trashed_at: i64,
    ) -> Result<bool, StoreError>;

    /// Restore a trashed file only if it belongs to `owner_sub`.
    async fn restore_file(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError>;

    /// Rename an owner's live (non-trashed) file. Returns `true` when a row was updated.
    async fn rename_file(&self, id: &str, owner_sub: &str, name: &str) -> Result<bool, StoreError>;

    /// An owner's trashed files, newest-trash-first.
    async fn list_trashed_by_owner(&self, owner_sub: &str) -> Result<Vec<FileRec>, StoreError>;

    /// Stable, bounded unified Trash roots (files + folders). Descendants hidden by an ancestor
    /// entry never appear as duplicate cards.
    async fn query_trash(
        &self,
        owner_sub: &str,
        before: Option<&LibraryCursor>,
        limit: i64,
    ) -> Result<TrashPage, StoreError>;

    /// Atomically move all selected effective-live roots to Trash, propagating folder ancestor
    /// scope without overwriting nested independent Trash scopes.
    async fn bulk_trash(
        &self,
        owner_sub: &str,
        roots: &[TrashRootInput],
        trashed_at: i64,
        purge_after: i64,
    ) -> Result<BulkMutation, StoreError>;

    /// Atomically restore explicitly-trashed roots and only the descendant scope owned by them.
    async fn bulk_restore(
        &self,
        owner_sub: &str,
        items: &[DriveItemRef],
    ) -> Result<BulkMutation, StoreError>;

    /// Atomically move effective-live files/folders. Moving a folder into itself or its descendant
    /// is rejected with no partial mutation.
    async fn bulk_move(
        &self,
        owner_sub: &str,
        items: &[DriveItemRef],
        folder_id: Option<&str>,
    ) -> Result<BulkMutation, StoreError>;

    /// Logically purge Trash roots in one transaction. Every current/version/thumbnail object key
    /// is first placed in the durable delete outbox; metadata is never removed without recovery
    /// authority.
    async fn bulk_purge(
        &self,
        owner_sub: &str,
        items: &[DriveItemRef],
        enqueued_at: i64,
    ) -> Result<BulkMutation, StoreError>;

    /// Claim expired Trash roots for the retention worker. A returned item stays protected by its
    /// lease until purge succeeds or the lease is abandoned/reclaimed.
    async fn claim_expired_trash(
        &self,
        lease_id: &str,
        now: i64,
        lease_expired_before: i64,
        limit: i64,
    ) -> Result<Vec<TrashEntry>, StoreError>;

    async fn abandon_trash_claim(&self, entry_id: &str, lease_id: &str)
        -> Result<bool, StoreError>;

    /// Lease a bounded set of due object deletions.
    async fn claim_blob_deletions(
        &self,
        lease_id: &str,
        now: i64,
        lease_expired_before: i64,
        limit: i64,
    ) -> Result<BlobDeleteClaim, StoreError>;

    async fn complete_blob_deletion(
        &self,
        object_key: &str,
        lease_id: &str,
    ) -> Result<bool, StoreError>;

    async fn abandon_blob_deletion(
        &self,
        object_key: &str,
        lease_id: &str,
        retry_at: i64,
    ) -> Result<bool, StoreError>;

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

    /// ALL of an owner's folders, name-ordered (case-insensitive, id tiebreak). The caller builds
    /// the tree (breadcrumbs, per-level children) from the flat list in memory.
    async fn list_folders(&self, owner_sub: &str) -> Result<Vec<FolderRec>, StoreError>;

    /// Fetch one folder, ownership-scoped (used to validate a move target and to render the active
    /// folder's controls). `None` when it does not exist or belongs to someone else.
    async fn get_folder(&self, id: &str, owner_sub: &str) -> Result<Option<FolderRec>, StoreError>;

    /// Fetch a folder regardless of Trash visibility. Reserved for Trash rendering/reconciliation;
    /// ordinary owner and capability surfaces use [`Store::get_folder`].
    async fn get_folder_any(
        &self,
        id: &str,
        owner_sub: &str,
    ) -> Result<Option<FolderRec>, StoreError>;

    /// Fetch a folder by its public share token (the unauthenticated `/s/folder/{token}` index). `None`
    /// when the token is unknown / revoked. The row carries `owner_sub`, so the public handler
    /// scopes the file listing WITHOUT any request identity.
    async fn get_folder_by_token(&self, token: &str) -> Result<Option<FolderRec>, StoreError>;

    /// Fetch a folder by its public upload-inbox token (`/u/{token}`). The row carries `owner_sub`,
    /// so anonymous uploads can be charged to the owner without trusting request identity.
    async fn get_folder_by_upload_token(
        &self,
        token: &str,
    ) -> Result<Option<FolderRec>, StoreError>;

    /// Rename a folder only if it belongs to `owner_sub`. Returns `true` when a row was updated.
    async fn rename_folder(
        &self,
        id: &str,
        owner_sub: &str,
        name: &str,
    ) -> Result<bool, StoreError>;

    /// Configure a folder's public share link, ownership-scoped. Sets all three share columns
    /// atomically: `share_token` (`Some` to (re)enable, `None` to REVOKE), `expires_at`, and
    /// `share_password_hash`. Returns `true` when the owner's row was updated. Mirrors
    /// [`Store::configure_share`] for files.
    async fn configure_folder_share(
        &self,
        id: &str,
        owner_sub: &str,
        share_token: Option<String>,
        expires_at: Option<i64>,
        share_password_hash: Option<String>,
    ) -> Result<bool, StoreError>;

    /// Configure a folder's public upload-inbox token, ownership-scoped. `Some` enables/rotates,
    /// `None` revokes.
    async fn configure_folder_upload(
        &self,
        id: &str,
        owner_sub: &str,
        upload_token: Option<String>,
    ) -> Result<bool, StoreError>;

    /// Delete a folder ONLY when it is empty (no child folders AND no files) and owned by
    /// `owner_sub`. Never touches file rows. See [`FolderDelete`] for the three outcomes.
    async fn delete_folder_if_empty(
        &self,
        id: &str,
        owner_sub: &str,
    ) -> Result<FolderDelete, StoreError>;

    /// Cascade-delete a folder and its WHOLE subtree — every descendant folder and every file in
    /// them (file rows + their version rows) — ownership-scoped. Returns the object keys of every
    /// removed blob (file currents AND versions) so the caller drops them from the object store.
    async fn delete_folder_cascade(
        &self,
        id: &str,
        owner_sub: &str,
    ) -> Result<Vec<String>, StoreError>;

    /// Move a file into a folder (`Some(folder_id)`) or back to the root (`None`), ownership-scoped.
    /// The caller validates that a `Some` target folder belongs to the owner. Returns `true` when
    /// the owner's file row was updated.
    async fn move_file(
        &self,
        id: &str,
        owner_sub: &str,
        folder_id: Option<&str>,
    ) -> Result<bool, StoreError>;

    /// ALL files directly in a folder (`folder_id` = `folder_id`), owner-scoped, newest-first.
    /// Unpaginated — backs the public folder-share index and cascade cleanup, which need the whole
    /// set. (The paged gallery uses [`Store::list_by_owner`] instead.)
    async fn list_files_in_folder(
        &self,
        folder_id: &str,
        owner_sub: &str,
    ) -> Result<Vec<FileRec>, StoreError>;

    /// The owner's file with the given display `name` at a specific tree level (`folder_id`: `None`
    /// = root). Backs re-upload version detection ("same name in the same folder"). `None` when no
    /// such file exists.
    async fn find_file_in_folder(
        &self,
        owner_sub: &str,
        name: &str,
        folder_id: Option<&str>,
    ) -> Result<Option<FileRec>, StoreError>;

    /// Repoint a file's current blob (object key + size + content type) and bump `updated_at`,
    /// ownership-scoped. Used by a re-upload (point at the new blob) and a version restore (point
    /// back at the snapshot). Returns `true` when the owner's row was updated.
    async fn update_file_blob(
        &self,
        id: &str,
        owner_sub: &str,
        object_key: &str,
        size: i64,
        content_type: &str,
        updated_at: i64,
    ) -> Result<bool, StoreError>;

    /// Append a version snapshot row.
    async fn add_version(&self, version: &VersionRec) -> Result<bool, StoreError>;

    /// A file's versions, newest-first (`created_at DESC, id DESC`). Scoped by `file_id`; the caller
    /// has already ownership-checked the file.
    async fn list_versions(&self, file_id: &str) -> Result<Vec<VersionRec>, StoreError>;

    /// Fetch one version by id, scoped to its `file_id`. `None` when absent / not this file's.
    async fn get_version(
        &self,
        version_id: &str,
        file_id: &str,
    ) -> Result<Option<VersionRec>, StoreError>;

    /// Remove one version row (scoped to `file_id`) and return it, so the caller can decide whether
    /// to drop its blob (a restore keeps the blob — it becomes current; an explicit prune drops it).
    async fn delete_version(
        &self,
        version_id: &str,
        file_id: &str,
    ) -> Result<Option<VersionRec>, StoreError>;

    /// Prune a file's OLDEST versions beyond the newest `keep`, returning the removed rows so the
    /// caller drops their blobs. Keeps the version history bounded.
    async fn prune_versions(&self, file_id: &str, keep: i64)
        -> Result<Vec<VersionRec>, StoreError>;

    /// Remove ALL of a file's version rows (when the file itself is deleted), returning them so the
    /// caller drops their blobs.
    async fn delete_versions_for_file(&self, file_id: &str) -> Result<Vec<VersionRec>, StoreError>;

    /// Total stored bytes for `owner_sub`: the SUM of the owner's current file sizes PLUS the SUM of
    /// all their retained version blobs (versions count toward usage). `0` with nothing stored.
    /// Backs the drive's usage meter and the upload quota precheck.
    async fn usage_for_owner(&self, owner_sub: &str) -> Result<i64, StoreError>;

    /// Aggregated usage for every owner with at least one file, largest first (`bytes` DESC,
    /// `owner_sub` ASC tiebreak). `bytes` includes retained version blobs; `files` counts only the
    /// current file rows. Backs the `/admin` usage table.
    async fn usage_by_owner(&self) -> Result<Vec<OwnerUsage>, StoreError>;

    /// The owner's per-owner quota override, when one exists. `None` means "no override" — the
    /// caller falls back to the configured default (see [`crate::config::effective_quota`]).
    async fn get_quota(&self, owner_sub: &str) -> Result<Option<i64>, StoreError>;

    /// Set (`Some`, upsert) or clear (`None`, delete the row) an owner's quota override.
    async fn set_quota(&self, owner_sub: &str, quota_bytes: Option<i64>) -> Result<(), StoreError>;

    /// Every quota override row as `(owner_sub, quota_bytes)`, owner-ordered (for `/admin`).
    async fn list_quotas(&self) -> Result<Vec<(String, i64)>, StoreError>;

    /// Insert a file comment. Returns `false` on id collision so the caller can retry.
    async fn create_comment(&self, comment: &FileComment) -> Result<bool, StoreError>;

    /// A file's comments, oldest-first.
    async fn list_comments(&self, file_id: &str) -> Result<Vec<FileComment>, StoreError>;

    /// Fetch one comment by id.
    async fn get_comment(&self, comment_id: &str) -> Result<Option<FileComment>, StoreError>;

    /// Delete one comment scoped to its file. Successful add/delete operations also touch the
    /// file's owner-visible activity timestamp atomically.
    async fn delete_comment(&self, comment_id: &str, file_id: &str) -> Result<bool, StoreError>;

    /// Delete all comments for a file, used by hard purge.
    async fn delete_comments_for_file(&self, file_id: &str) -> Result<(), StoreError>;

    // ------------------------------------------------------------------
    // Product-level public upload requests.
    // ------------------------------------------------------------------

    async fn create_upload_request(&self, request: &UploadRequestRec) -> Result<bool, StoreError>;

    async fn list_upload_requests(
        &self,
        owner_sub: &str,
    ) -> Result<Vec<UploadRequestRec>, StoreError>;

    /// Return one exact-count, bounded, token-free owner Inbox snapshot. Every effective state and
    /// count is classified against the caller's single `as_of`; implementations keep stable
    /// `updated_at DESC, id DESC` ordering and never project capability or storage material.
    async fn upload_request_inbox(
        &self,
        owner_sub: &str,
        view: UploadRequestInboxView,
        as_of: i64,
    ) -> Result<UploadRequestInbox, StoreError>;

    async fn get_upload_request(
        &self,
        id: &str,
        owner_sub: &str,
    ) -> Result<Option<UploadRequestRec>, StoreError>;

    async fn get_upload_request_by_token(
        &self,
        token: &str,
    ) -> Result<Option<UploadRequestRec>, StoreError>;

    /// Replace all owner-editable request settings. Implementations reject a budget lower than
    /// already-consumed usage and never change token, owner, destination or counters here.
    async fn update_upload_request(&self, request: &UploadRequestRec) -> Result<bool, StoreError>;

    async fn set_upload_request_status(
        &self,
        id: &str,
        owner_sub: &str,
        status: &str,
        updated_at: i64,
    ) -> Result<bool, StoreError>;

    /// Reopen a request without replacing any owner policy. An expired finite request receives
    /// `renewed_expires_at`; a still-live or legacy no-expiry request keeps its current expiry.
    async fn reopen_upload_request(
        &self,
        id: &str,
        owner_sub: &str,
        now: i64,
        renewed_expires_at: i64,
    ) -> Result<bool, StoreError>;

    async fn rotate_upload_request_token(
        &self,
        id: &str,
        owner_sub: &str,
        expected_token: &str,
        token: &str,
        updated_at: i64,
    ) -> Result<bool, StoreError>;

    async fn list_upload_submissions(
        &self,
        request_id: &str,
        owner_sub: &str,
    ) -> Result<Vec<UploadSubmission>, StoreError>;

    /// Atomically reserve one request/file slot and owner quota before touching the blob store.
    /// `owner_quota=None` means the owner has no configured global limit; the request's own finite
    /// budgets are always enforced. A reservation counts toward both request and owner usage.
    async fn reserve_request_upload(
        &self,
        input: UploadReserveInput<'_>,
    ) -> Result<UploadReserve, StoreError>;

    /// Commit a successfully-written blob into the file index and immutable request receipt.
    async fn commit_request_upload(
        &self,
        reservation_id: &str,
        file: &FileRec,
        submission: &UploadSubmission,
    ) -> Result<bool, StoreError>;

    /// Release a failed reservation and return its bytes/file slot to the request budget.
    async fn release_request_upload(&self, reservation_id: &str) -> Result<bool, StoreError>;

    /// Atomically lease all stale reservations for one startup recovery worker. A lease older than
    /// `lease_expired_before` can be reclaimed after a recovery process itself crashed.
    async fn claim_upload_recovery(
        &self,
        lease_id: &str,
        leased_at: i64,
        lease_expired_before: i64,
    ) -> Result<UploadRecoveryClaim, StoreError>;

    /// Finish one leased recovery item after its blob was deleted. This is the only recovery path
    /// that returns bytes/file counters, and the lease predicate makes it exactly-once.
    async fn complete_upload_recovery(
        &self,
        reservation_id: &str,
        lease_id: &str,
    ) -> Result<bool, StoreError>;

    /// Give back a recovery lease without changing counters. Used when blob deletion fails so a
    /// later startup can retry the same durable row.
    async fn abandon_upload_recovery(
        &self,
        reservation_id: &str,
        lease_id: &str,
    ) -> Result<bool, StoreError>;
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

/// In-memory `Store`. The `Mutex<Vec<_>>` critical sections are fully synchronous (no `.await`
/// held across the guard), so the std `Mutex` is correct here.
#[derive(Default)]
pub struct InMemoryStore {
    /// Serializes cross-domain owner lifecycle commits before any request/file/folder lock. A
    /// single process-wide guard is intentionally conservative and keeps Memory lock order equal to
    /// PostgreSQL's owner guard without holding an async mutex across awaits.
    lifecycle_guard: Mutex<()>,
    files: Mutex<Vec<FileRec>>,
    folders: Mutex<Vec<FolderRec>>,
    /// Retained blob snapshots (mirrors the `file_versions` table).
    versions: Mutex<Vec<VersionRec>>,
    /// Per-owner quota override rows, `(owner_sub, quota_bytes)` — mirrors the `owner_quotas` table.
    quotas: Mutex<Vec<(String, i64)>>,
    /// Per-file comments (mirrors the `file_comments` table).
    comments: Mutex<Vec<FileComment>>,
    /// Unified Trash roots and durable object-delete outbox. New bulk operations acquire the
    /// locks in folders -> files -> versions -> comments -> trash -> deletes order.
    trash_entries: Mutex<Vec<TrashEntry>>,
    blob_deletions: Mutex<Vec<MemoryBlobDelete>>,
    owner_blob_writes: Mutex<Vec<MemoryOwnerBlobWrite>>,
    /// Upload-request control plane and its short-lived reservations. Keeping these three vectors
    /// behind one lock makes reserve/commit/release atomic in the memory implementation.
    request_state: Mutex<MemoryRequestState>,
}

#[derive(Default)]
struct MemoryRequestState {
    requests: Vec<UploadRequestRec>,
    submissions: Vec<UploadSubmission>,
    reservations: Vec<MemoryUploadReservation>,
}

#[derive(Clone)]
struct MemoryUploadReservation {
    id: String,
    request_id: String,
    owner_sub: String,
    size: i64,
    recovery_lease: Option<String>,
    recovery_leased_at: Option<i64>,
}

#[derive(Clone)]
struct MemoryBlobDelete {
    object_key: String,
    enqueued_at: i64,
    attempts: i64,
    next_attempt_at: i64,
    recovery_lease: Option<String>,
    recovery_leased_at: Option<i64>,
}

#[derive(Clone)]
struct MemoryOwnerBlobWrite {
    intent: OwnerBlobWriteIntent,
    next_attempt_at: i64,
    recovery_lease: Option<String>,
    recovery_leased_at: Option<i64>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

fn folder_descends_from(folders: &[FolderRec], child_id: &str, ancestor_id: &str) -> bool {
    let mut current = Some(child_id);
    let mut seen: Vec<&str> = Vec::new();
    while let Some(id) = current {
        if id == ancestor_id {
            return true;
        }
        if seen.contains(&id) {
            return false;
        }
        seen.push(id);
        current = folders
            .iter()
            .find(|folder| folder.id == id)
            .and_then(|folder| folder.parent_id.as_deref());
    }
    false
}

fn item_under_selected_folder(
    item: &DriveItemRef,
    selected: &[DriveItemRef],
    files: &[FileRec],
    folders: &[FolderRec],
) -> bool {
    let parent = match item.kind {
        LibraryItemKind::File => files
            .iter()
            .find(|file| file.id == item.id)
            .and_then(|file| file.folder_id.as_deref()),
        LibraryItemKind::Folder => folders
            .iter()
            .find(|folder| folder.id == item.id)
            .and_then(|folder| folder.parent_id.as_deref()),
    };
    selected.iter().any(|candidate| {
        candidate.kind == LibraryItemKind::Folder
            && parent.is_some_and(|parent| folder_descends_from(folders, parent, &candidate.id))
    })
}

fn normalized_refs(
    items: &[DriveItemRef],
    files: &[FileRec],
    folders: &[FolderRec],
) -> Vec<DriveItemRef> {
    items
        .iter()
        .filter(|item| !item_under_selected_folder(item, items, files, folders))
        .cloned()
        .collect()
}

fn trash_before(item: &TrashItem, cursor: &LibraryCursor) -> bool {
    item.trashed_at < cursor.updated_at
        || (item.trashed_at == cursor.updated_at
            && (item.kind.rank() < cursor.kind.rank()
                || (item.kind == cursor.kind && item.id < cursor.id)))
}

fn finish_trash_page(mut items: Vec<TrashItem>, limit: i64) -> TrashPage {
    let limit = clamp_page(limit) as usize;
    items.sort_by(|left, right| {
        right
            .trashed_at
            .cmp(&left.trashed_at)
            .then_with(|| right.kind.rank().cmp(&left.kind.rank()))
            .then_with(|| right.id.cmp(&left.id))
    });
    let has_more = items.len() > limit;
    items.truncate(limit);
    let next = has_more.then(|| items.last().expect("non-empty bounded page").cursor());
    TrashPage { items, next }
}

#[async_trait]
impl Store for InMemoryStore {
    async fn create(&self, file: &FileRec) -> Result<bool, StoreError> {
        let mut files = self.files.lock().expect("files lock poisoned");
        // Reject on any unique conflict (id OR a non-null share token), matching the Postgres
        // constraints (NULL share tokens are distinct, so revoked rows never collide).
        if files.iter().any(|f| {
            f.id == file.id || (file.share_token.is_some() && f.share_token == file.share_token)
        }) {
            return Ok(false);
        }
        files.push(file.clone());
        Ok(true)
    }

    async fn reserve_owner_blob_write(
        &self,
        intent: &OwnerBlobWriteIntent,
        owner_quota: Option<i64>,
    ) -> Result<OwnerBlobCommit, StoreError> {
        if intent.object_key.is_empty()
            || intent.owner_sub.is_empty()
            || intent.file_id.is_empty()
            || intent.size < 0
            || !matches!(
                intent.kind.as_str(),
                OWNER_WRITE_FRESH | OWNER_WRITE_REUPLOAD | OWNER_WRITE_THUMBNAIL
            )
        {
            return Ok(OwnerBlobCommit::Conflict);
        }
        let _lifecycle = self
            .lifecycle_guard
            .lock()
            .expect("lifecycle guard poisoned");
        let requests = self
            .request_state
            .lock()
            .expect("request state lock poisoned");
        let folders = self.folders.lock().expect("folders lock poisoned");
        let files = self.files.lock().expect("files lock poisoned");
        let versions = self.versions.lock().expect("versions lock poisoned");
        let mut intents = self
            .owner_blob_writes
            .lock()
            .expect("owner blob writes lock poisoned");
        let deletions = self
            .blob_deletions
            .lock()
            .expect("blob deletion lock poisoned");

        let authority_ok = match intent.kind.as_str() {
            OWNER_WRITE_FRESH => {
                intent.expected_object_key.is_none()
                    && intent.object_key == intent.file_id
                    && intent.folder_id.as_deref().is_none_or(|folder_id| {
                        folders.iter().any(|folder| {
                            folder.id == folder_id
                                && folder.owner_sub == intent.owner_sub
                                && folder.is_effectively_live()
                        })
                    })
                    && !files.iter().any(|file| file.id == intent.file_id)
            }
            OWNER_WRITE_REUPLOAD => intent
                .expected_object_key
                .as_deref()
                .is_some_and(|expected| {
                    files.iter().any(|file| {
                        file.id == intent.file_id
                            && file.owner_sub == intent.owner_sub
                            && file.object_key == expected
                            && file.is_effectively_live()
                    })
                }),
            OWNER_WRITE_THUMBNAIL => {
                intent
                    .expected_object_key
                    .as_deref()
                    .is_some_and(|expected| {
                        intent.object_key == format!("{expected}.thumb")
                            && files.iter().any(|file| {
                                file.id == intent.file_id
                                    && file.owner_sub == intent.owner_sub
                                    && file.object_key == expected
                                    && file.is_effectively_live()
                            })
                    })
            }
            _ => false,
        };
        if !authority_ok {
            return Ok(OwnerBlobCommit::Conflict);
        }
        if intents
            .iter()
            .any(|row| row.intent.object_key == intent.object_key)
            || requests
                .reservations
                .iter()
                .any(|row| row.id == intent.object_key)
            || files
                .iter()
                .any(|file| file.object_key == intent.object_key)
            || versions
                .iter()
                .any(|version| version.object_key == intent.object_key)
            || deletions
                .iter()
                .any(|deletion| deletion.object_key == intent.object_key)
        {
            return Ok(OwnerBlobCommit::Collision);
        }
        if intent.kind != OWNER_WRITE_THUMBNAIL {
            let owned_ids: Vec<&str> = files
                .iter()
                .filter(|file| file.owner_sub == intent.owner_sub)
                .map(|file| file.id.as_str())
                .collect();
            let committed = files
                .iter()
                .filter(|file| file.owner_sub == intent.owner_sub)
                .map(|file| file.size)
                .sum::<i64>()
                .saturating_add(
                    versions
                        .iter()
                        .filter(|version| owned_ids.contains(&version.file_id.as_str()))
                        .map(|version| version.size)
                        .sum(),
                )
                .saturating_add(
                    requests
                        .reservations
                        .iter()
                        .filter(|reservation| reservation.owner_sub == intent.owner_sub)
                        .map(|reservation| reservation.size)
                        .sum(),
                )
                .saturating_add(
                    intents
                        .iter()
                        .filter(|row| {
                            row.intent.owner_sub == intent.owner_sub
                                && row.intent.kind != OWNER_WRITE_THUMBNAIL
                        })
                        .map(|row| row.intent.size)
                        .sum(),
                );
            if owner_quota.is_some_and(|quota| committed.saturating_add(intent.size) > quota) {
                return Ok(OwnerBlobCommit::QuotaExceeded);
            }
        }
        intents.push(MemoryOwnerBlobWrite {
            intent: intent.clone(),
            next_attempt_at: intent.created_at,
            recovery_lease: None,
            recovery_leased_at: None,
        });
        Ok(OwnerBlobCommit::Applied)
    }

    async fn commit_owner_upload(
        &self,
        file: &FileRec,
        owner_quota: Option<i64>,
    ) -> Result<OwnerBlobCommit, StoreError> {
        let _lifecycle = self
            .lifecycle_guard
            .lock()
            .expect("lifecycle guard poisoned");
        let requests = self
            .request_state
            .lock()
            .expect("request state lock poisoned");
        let folders = self.folders.lock().expect("folders lock poisoned");
        let mut files = self.files.lock().expect("files lock poisoned");
        let versions = self.versions.lock().expect("versions lock poisoned");
        let mut intents = self
            .owner_blob_writes
            .lock()
            .expect("owner blob writes lock poisoned");
        let Some(intent_index) = intents.iter().position(|row| {
            row.intent.object_key == file.object_key
                && row.intent.owner_sub == file.owner_sub
                && row.intent.file_id == file.id
                && row.intent.folder_id == file.folder_id
                && row.intent.size == file.size
                && row.intent.kind == OWNER_WRITE_FRESH
                && row.recovery_lease.is_none()
        }) else {
            return Ok(OwnerBlobCommit::Conflict);
        };
        if file.object_key != file.id
            || !file.is_effectively_live()
            || file.folder_id.as_deref().is_some_and(|folder_id| {
                !folders.iter().any(|folder| {
                    folder.id == folder_id
                        && folder.owner_sub == file.owner_sub
                        && folder.is_effectively_live()
                })
            })
        {
            return Ok(OwnerBlobCommit::Conflict);
        }
        if files.iter().any(|existing| {
            existing.id == file.id
                || (file.share_token.is_some() && existing.share_token == file.share_token)
        }) {
            return Ok(OwnerBlobCommit::Collision);
        }
        let owned_ids: Vec<&str> = files
            .iter()
            .filter(|existing| existing.owner_sub == file.owner_sub)
            .map(|existing| existing.id.as_str())
            .collect();
        let total = files
            .iter()
            .filter(|existing| existing.owner_sub == file.owner_sub)
            .map(|existing| existing.size)
            .sum::<i64>()
            .saturating_add(
                versions
                    .iter()
                    .filter(|version| owned_ids.contains(&version.file_id.as_str()))
                    .map(|version| version.size)
                    .sum(),
            )
            .saturating_add(
                requests
                    .reservations
                    .iter()
                    .filter(|reservation| reservation.owner_sub == file.owner_sub)
                    .map(|reservation| reservation.size)
                    .sum(),
            )
            .saturating_add(
                intents
                    .iter()
                    .filter(|row| {
                        row.intent.owner_sub == file.owner_sub
                            && row.intent.kind != OWNER_WRITE_THUMBNAIL
                    })
                    .map(|row| row.intent.size)
                    .sum(),
            );
        if owner_quota.is_some_and(|quota| total > quota) {
            return Ok(OwnerBlobCommit::QuotaExceeded);
        }
        files.push(file.clone());
        intents.remove(intent_index);
        Ok(OwnerBlobCommit::Applied)
    }

    async fn commit_owner_reupload(
        &self,
        input: OwnerReuploadInput<'_>,
    ) -> Result<OwnerBlobCommit, StoreError> {
        let _lifecycle = self
            .lifecycle_guard
            .lock()
            .expect("lifecycle guard poisoned");
        let requests = self
            .request_state
            .lock()
            .expect("request state lock poisoned");
        let mut files = self.files.lock().expect("files lock poisoned");
        let mut versions = self.versions.lock().expect("versions lock poisoned");
        let mut intents = self
            .owner_blob_writes
            .lock()
            .expect("owner blob writes lock poisoned");
        let mut deletions = self
            .blob_deletions
            .lock()
            .expect("blob deletion lock poisoned");
        let Some(intent_index) = intents.iter().position(|row| {
            row.intent.object_key == input.new_object_key
                && row.intent.owner_sub == input.owner_sub
                && row.intent.file_id == input.file_id
                && row.intent.expected_object_key.as_deref() == Some(input.expected_object_key)
                && row.intent.size == input.new_size
                && row.intent.kind == OWNER_WRITE_REUPLOAD
                && row.recovery_lease.is_none()
        }) else {
            return Ok(OwnerBlobCommit::Conflict);
        };
        let Some(file_index) = files.iter().position(|file| {
            file.id == input.file_id
                && file.owner_sub == input.owner_sub
                && file.object_key == input.expected_object_key
                && file.is_effectively_live()
        }) else {
            return Ok(OwnerBlobCommit::Conflict);
        };
        if versions
            .iter()
            .any(|version| version.id == input.snapshot_id)
        {
            return Ok(OwnerBlobCommit::Collision);
        }
        let owned_ids: Vec<&str> = files
            .iter()
            .filter(|file| file.owner_sub == input.owner_sub)
            .map(|file| file.id.as_str())
            .collect();
        let total = files
            .iter()
            .filter(|file| file.owner_sub == input.owner_sub)
            .map(|file| file.size)
            .sum::<i64>()
            .saturating_add(
                versions
                    .iter()
                    .filter(|version| owned_ids.contains(&version.file_id.as_str()))
                    .map(|version| version.size)
                    .sum(),
            )
            .saturating_add(
                requests
                    .reservations
                    .iter()
                    .filter(|reservation| reservation.owner_sub == input.owner_sub)
                    .map(|reservation| reservation.size)
                    .sum(),
            )
            .saturating_add(
                intents
                    .iter()
                    .filter(|row| {
                        row.intent.owner_sub == input.owner_sub
                            && row.intent.kind != OWNER_WRITE_THUMBNAIL
                    })
                    .map(|row| row.intent.size)
                    .sum(),
            );
        if input.owner_quota.is_some_and(|quota| total > quota) {
            return Ok(OwnerBlobCommit::QuotaExceeded);
        }
        let current = files[file_index].clone();
        versions.push(VersionRec {
            id: input.snapshot_id.to_string(),
            file_id: current.id.clone(),
            object_key: current.object_key.clone(),
            size: current.size,
            content_type: current.content_type.clone(),
            created_at: input.changed_at,
        });
        files[file_index].object_key = input.new_object_key.to_string();
        files[file_index].size = input.new_size;
        files[file_index].content_type = input.new_content_type.to_string();
        files[file_index].updated_at = input
            .changed_at
            .max(files[file_index].updated_at.saturating_add(1));

        let mut mine: Vec<VersionRec> = versions
            .iter()
            .filter(|version| version.file_id == input.file_id)
            .cloned()
            .collect();
        mine.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| right.id.cmp(&left.id))
        });
        let pruned_ids: Vec<String> = mine
            .iter()
            .skip(MAX_VERSIONS_PER_FILE as usize)
            .map(|version| version.id.clone())
            .collect();
        let pruned: Vec<VersionRec> = versions
            .iter()
            .filter(|version| pruned_ids.contains(&version.id))
            .cloned()
            .collect();
        versions.retain(|version| !pruned_ids.contains(&version.id));
        let mut live_keys = vec![files[file_index].object_key.clone()];
        live_keys.extend(
            versions
                .iter()
                .filter(|version| version.file_id == input.file_id)
                .map(|version| version.object_key.clone()),
        );
        live_keys.push(format!("{}.thumb", files[file_index].object_key));
        let mut stale_keys = vec![format!("{}.thumb", current.object_key)];
        for version in pruned {
            stale_keys.push(version.object_key.clone());
            stale_keys.push(format!("{}.thumb", version.object_key));
        }
        stale_keys.retain(|key| !live_keys.contains(key));
        stale_keys.sort();
        stale_keys.dedup();
        for key in stale_keys {
            if !deletions.iter().any(|row| row.object_key == key) {
                deletions.push(MemoryBlobDelete {
                    object_key: key,
                    enqueued_at: input.changed_at,
                    attempts: 0,
                    next_attempt_at: input.changed_at,
                    recovery_lease: None,
                    recovery_leased_at: None,
                });
            }
        }
        intents.remove(intent_index);
        Ok(OwnerBlobCommit::Applied)
    }

    async fn commit_owner_version_restore(
        &self,
        input: OwnerVersionRestoreInput<'_>,
    ) -> Result<OwnerBlobCommit, StoreError> {
        let _lifecycle = self
            .lifecycle_guard
            .lock()
            .expect("lifecycle guard poisoned");
        let mut files = self.files.lock().expect("files lock poisoned");
        let mut versions = self.versions.lock().expect("versions lock poisoned");
        let mut deletions = self
            .blob_deletions
            .lock()
            .expect("blob deletion lock poisoned");
        let Some(file_index) = files.iter().position(|file| {
            file.id == input.file_id
                && file.owner_sub == input.owner_sub
                && file.object_key == input.expected_object_key
                && file.is_effectively_live()
        }) else {
            return Ok(OwnerBlobCommit::Conflict);
        };
        let Some(version_index) = versions
            .iter()
            .position(|version| version.id == input.version_id && version.file_id == input.file_id)
        else {
            return Ok(OwnerBlobCommit::Conflict);
        };
        if versions
            .iter()
            .any(|version| version.id == input.snapshot_id)
        {
            return Ok(OwnerBlobCommit::Collision);
        }
        let current = files[file_index].clone();
        let selected = versions[version_index].clone();
        versions.push(VersionRec {
            id: input.snapshot_id.to_string(),
            file_id: current.id.clone(),
            object_key: current.object_key.clone(),
            size: current.size,
            content_type: current.content_type.clone(),
            created_at: input.changed_at,
        });
        versions.retain(|version| version.id != selected.id);
        files[file_index].object_key = selected.object_key;
        files[file_index].size = selected.size;
        files[file_index].content_type = selected.content_type;
        files[file_index].updated_at = input
            .changed_at
            .max(files[file_index].updated_at.saturating_add(1));
        let mut mine: Vec<VersionRec> = versions
            .iter()
            .filter(|version| version.file_id == input.file_id)
            .cloned()
            .collect();
        mine.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| right.id.cmp(&left.id))
        });
        let pruned_ids: Vec<String> = mine
            .iter()
            .skip(MAX_VERSIONS_PER_FILE as usize)
            .map(|version| version.id.clone())
            .collect();
        let pruned: Vec<VersionRec> = versions
            .iter()
            .filter(|version| pruned_ids.contains(&version.id))
            .cloned()
            .collect();
        versions.retain(|version| !pruned_ids.contains(&version.id));
        let mut live_keys = vec![files[file_index].object_key.clone()];
        live_keys.extend(
            versions
                .iter()
                .filter(|version| version.file_id == input.file_id)
                .map(|version| version.object_key.clone()),
        );
        live_keys.push(format!("{}.thumb", files[file_index].object_key));
        let mut stale_keys = vec![format!("{}.thumb", current.object_key)];
        for version in pruned {
            stale_keys.push(version.object_key.clone());
            stale_keys.push(format!("{}.thumb", version.object_key));
        }
        stale_keys.retain(|key| !live_keys.contains(key));
        stale_keys.sort();
        stale_keys.dedup();
        for key in stale_keys {
            if !deletions.iter().any(|row| row.object_key == key) {
                deletions.push(MemoryBlobDelete {
                    object_key: key,
                    enqueued_at: input.changed_at,
                    attempts: 0,
                    next_attempt_at: input.changed_at,
                    recovery_lease: None,
                    recovery_leased_at: None,
                });
            }
        }
        Ok(OwnerBlobCommit::Applied)
    }

    async fn finalize_owner_thumbnail(
        &self,
        object_key: &str,
        owner_sub: &str,
        file_id: &str,
        expected_object_key: &str,
    ) -> Result<OwnerBlobCommit, StoreError> {
        let _lifecycle = self
            .lifecycle_guard
            .lock()
            .expect("lifecycle guard poisoned");
        let files = self.files.lock().expect("files lock poisoned");
        let mut intents = self
            .owner_blob_writes
            .lock()
            .expect("owner blob writes lock poisoned");
        let valid_file = files.iter().any(|file| {
            file.id == file_id
                && file.owner_sub == owner_sub
                && file.object_key == expected_object_key
                && file.is_effectively_live()
        });
        let intent_index = intents.iter().position(|row| {
            row.intent.object_key == object_key
                && row.intent.owner_sub == owner_sub
                && row.intent.file_id == file_id
                && row.intent.expected_object_key.as_deref() == Some(expected_object_key)
                && row.intent.kind == OWNER_WRITE_THUMBNAIL
                && row.recovery_lease.is_none()
        });
        if !valid_file || intent_index.is_none() {
            return Ok(OwnerBlobCommit::Conflict);
        }
        intents.remove(intent_index.expect("checked intent"));
        Ok(OwnerBlobCommit::Applied)
    }

    async fn enqueue_blob_deletion(
        &self,
        object_key: &str,
        enqueued_at: i64,
        _reason: &str,
    ) -> Result<(), StoreError> {
        let _lifecycle = self
            .lifecycle_guard
            .lock()
            .expect("lifecycle guard poisoned");
        let requests = self
            .request_state
            .lock()
            .expect("request state lock poisoned");
        let files = self.files.lock().expect("files lock poisoned");
        let versions = self.versions.lock().expect("versions lock poisoned");
        let intents = self
            .owner_blob_writes
            .lock()
            .expect("owner blob writes lock poisoned");
        if requests
            .reservations
            .iter()
            .any(|reservation| reservation.id == object_key)
            || files.iter().any(|file| file.object_key == object_key)
            || versions
                .iter()
                .any(|version| version.object_key == object_key)
            || intents
                .iter()
                .any(|intent| intent.intent.object_key == object_key)
        {
            return Err(StoreError::Backend(format!(
                "blob deletion key {object_key} still has live authority"
            )));
        }
        let mut rows = self
            .blob_deletions
            .lock()
            .expect("blob deletion lock poisoned");
        if !rows.iter().any(|row| row.object_key == object_key) {
            rows.push(MemoryBlobDelete {
                object_key: object_key.to_string(),
                enqueued_at,
                attempts: 0,
                next_attempt_at: enqueued_at,
                recovery_lease: None,
                recovery_leased_at: None,
            });
        }
        Ok(())
    }

    async fn claim_owner_blob_writes(
        &self,
        lease_id: &str,
        now: i64,
        created_before: i64,
        lease_expired_before: i64,
        limit: i64,
    ) -> Result<Vec<OwnerBlobWriteIntent>, StoreError> {
        let mut rows = self
            .owner_blob_writes
            .lock()
            .expect("owner blob writes lock poisoned");
        let mut candidates: Vec<usize> = rows
            .iter()
            .enumerate()
            .filter(|(_, row)| {
                row.intent.created_at <= created_before
                    && row.next_attempt_at <= now
                    && (row.recovery_lease.is_none()
                        || row
                            .recovery_leased_at
                            .is_some_and(|at| at <= lease_expired_before))
            })
            .map(|(index, _)| index)
            .collect();
        candidates.sort_by_key(|index| {
            (
                rows[*index].next_attempt_at,
                rows[*index].intent.created_at,
                rows[*index].intent.object_key.clone(),
            )
        });
        candidates.truncate(clamp_page(limit) as usize);
        let mut claimed = Vec::with_capacity(candidates.len());
        for index in candidates {
            rows[index].recovery_lease = Some(lease_id.to_string());
            rows[index].recovery_leased_at = Some(now);
            claimed.push(rows[index].intent.clone());
        }
        Ok(claimed)
    }

    async fn complete_owner_blob_write(
        &self,
        object_key: &str,
        lease_id: &str,
    ) -> Result<bool, StoreError> {
        let mut rows = self
            .owner_blob_writes
            .lock()
            .expect("owner blob writes lock poisoned");
        let before = rows.len();
        rows.retain(|row| {
            !(row.intent.object_key == object_key
                && row.recovery_lease.as_deref() == Some(lease_id))
        });
        Ok(rows.len() != before)
    }

    async fn abandon_owner_blob_write(
        &self,
        object_key: &str,
        lease_id: &str,
        retry_at: i64,
    ) -> Result<bool, StoreError> {
        let mut rows = self
            .owner_blob_writes
            .lock()
            .expect("owner blob writes lock poisoned");
        let Some(row) = rows.iter_mut().find(|row| {
            row.intent.object_key == object_key && row.recovery_lease.as_deref() == Some(lease_id)
        }) else {
            return Ok(false);
        };
        row.intent.attempts = row.intent.attempts.saturating_add(1);
        row.next_attempt_at = retry_at;
        row.recovery_lease = None;
        row.recovery_leased_at = None;
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
            .find(|f| f.is_effectively_live() && f.share_token.as_deref() == Some(token))
            .cloned())
    }

    async fn bump_view_count(&self, id: &str) -> Result<(), StoreError> {
        let mut files = self.files.lock().expect("files lock poisoned");
        if let Some(f) = files
            .iter_mut()
            .find(|f| f.id == id && f.is_effectively_live())
        {
            f.view_count += 1;
        }
        Ok(())
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
            .filter(|f| f.is_effectively_live())
            // Tree level: `None` = the ROOT (folder_id IS NULL); `Some(id)` = only that folder.
            .filter(|f| match folder {
                None => f.folder_id.is_none(),
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

    async fn query_library(
        &self,
        owner_sub: &str,
        query: &LibraryQuery,
    ) -> Result<LibraryPage, StoreError> {
        let now = mutation_time();
        // Use the mutation lock order and clone while both guards are held. A reader can therefore
        // observe the complete state before or after a subtree lifecycle change, never a hybrid.
        let folders_guard = self.folders.lock().expect("folders lock poisoned");
        let files_guard = self.files.lock().expect("files lock poisoned");
        let folders = folders_guard.clone();
        let files = files_guard.clone();
        drop(files_guard);
        drop(folders_guard);
        let mut items: Vec<LibraryItem> = files
            .iter()
            .filter(|file| file.owner_sub == owner_sub && file.is_effectively_live())
            .map(|file| file_library_item(file, now))
            .chain(
                folders
                    .iter()
                    .filter(|folder| folder.owner_sub == owner_sub && folder.is_effectively_live())
                    .map(|folder| folder_library_item(folder, now)),
            )
            .filter(|item| library_item_matches(item, query))
            .collect();
        // Retain one look-ahead row so `next` is exact rather than guessed from a full page.
        let read_cap = clamp_page(query.limit) as usize + 1;
        items.sort_by(|left, right| {
            right
                .updated_at
                .cmp(&left.updated_at)
                .then_with(|| right.kind.rank().cmp(&left.kind.rank()))
                .then_with(|| right.id.cmp(&left.id))
        });
        items.truncate(read_cap);
        Ok(finish_library_page(items, query.limit))
    }

    async fn delete(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError> {
        let mut files = self.files.lock().expect("files lock poisoned");
        let before = files.len();
        files.retain(|f| !(f.id == id && f.owner_sub == owner_sub));
        Ok(files.len() != before)
    }

    async fn trash_file(
        &self,
        id: &str,
        owner_sub: &str,
        trashed_at: i64,
    ) -> Result<bool, StoreError> {
        let now = trashed_at.max(1);
        Ok(matches!(
            self.bulk_trash(
                owner_sub,
                &[TrashRootInput {
                    item: DriveItemRef {
                        kind: LibraryItemKind::File,
                        id: id.to_string(),
                    },
                    entry_id: format!("compat-file-{id}-{now}"),
                }],
                now,
                now.saturating_add(DEFAULT_TRASH_RETENTION_SECS),
            )
            .await?,
            BulkMutation::Applied { .. }
        ))
    }

    async fn restore_file(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError> {
        Ok(matches!(
            self.bulk_restore(
                owner_sub,
                &[DriveItemRef {
                    kind: LibraryItemKind::File,
                    id: id.to_string(),
                }],
            )
            .await?,
            BulkMutation::Applied { .. }
        ))
    }

    async fn rename_file(&self, id: &str, owner_sub: &str, name: &str) -> Result<bool, StoreError> {
        let mut files = self.files.lock().expect("files lock poisoned");
        match files
            .iter_mut()
            .find(|f| f.id == id && f.owner_sub == owner_sub && f.trashed_at == 0)
        {
            Some(f) => {
                f.name = name.to_string();
                f.updated_at = next_mutation_time(f.updated_at);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn list_trashed_by_owner(&self, owner_sub: &str) -> Result<Vec<FileRec>, StoreError> {
        let files = self.files.lock().expect("files lock poisoned");
        let mut out: Vec<FileRec> = files
            .iter()
            .filter(|f| f.owner_sub == owner_sub && f.trashed_at > 0)
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            b.trashed_at
                .cmp(&a.trashed_at)
                .then_with(|| b.id.cmp(&a.id))
        });
        Ok(out)
    }

    async fn query_trash(
        &self,
        owner_sub: &str,
        before: Option<&LibraryCursor>,
        limit: i64,
    ) -> Result<TrashPage, StoreError> {
        // Match lifecycle mutation order and snapshot all three collections under one critical
        // section so a Trash root and the metadata fields authorizing it cannot diverge.
        let folders_guard = self.folders.lock().expect("folders lock poisoned");
        let files_guard = self.files.lock().expect("files lock poisoned");
        let entries_guard = self.trash_entries.lock().expect("trash lock poisoned");
        let folders = folders_guard.clone();
        let files = files_guard.clone();
        let entries = entries_guard.clone();
        drop(entries_guard);
        drop(files_guard);
        drop(folders_guard);
        let mut items = Vec::new();
        for entry in entries.iter().filter(|entry| entry.owner_sub == owner_sub) {
            let item = match entry.kind {
                LibraryItemKind::File => files
                    .iter()
                    .find(|file| {
                        file.id == entry.item_id
                            && file.owner_sub == entry.owner_sub
                            && file.trash_entry_id.as_deref() == Some(entry.id.as_str())
                            && file.trash_ancestor_id.is_none()
                    })
                    .map(|file| TrashItem {
                        entry_id: entry.id.clone(),
                        kind: LibraryItemKind::File,
                        id: file.id.clone(),
                        name: file.name.clone(),
                        content_type: Some(file.content_type.clone()),
                        size: Some(file.size),
                        trashed_at: entry.trashed_at,
                        purge_after: entry.purge_after,
                    }),
                LibraryItemKind::Folder => folders
                    .iter()
                    .find(|folder| {
                        folder.id == entry.item_id
                            && folder.owner_sub == entry.owner_sub
                            && folder.trash_entry_id.as_deref() == Some(entry.id.as_str())
                            && folder.trash_ancestor_id.is_none()
                    })
                    .map(|folder| TrashItem {
                        entry_id: entry.id.clone(),
                        kind: LibraryItemKind::Folder,
                        id: folder.id.clone(),
                        name: folder.name.clone(),
                        content_type: None,
                        size: None,
                        trashed_at: entry.trashed_at,
                        purge_after: entry.purge_after,
                    }),
            };
            if let Some(item) =
                item.filter(|item| before.is_none_or(|cursor| trash_before(item, cursor)))
            {
                items.push(item);
            }
        }
        items.sort_by(|left, right| {
            right
                .trashed_at
                .cmp(&left.trashed_at)
                .then_with(|| right.kind.rank().cmp(&left.kind.rank()))
                .then_with(|| right.id.cmp(&left.id))
        });
        items.truncate(clamp_page(limit) as usize + 1);
        Ok(finish_trash_page(items, limit))
    }

    async fn bulk_trash(
        &self,
        owner_sub: &str,
        roots: &[TrashRootInput],
        trashed_at: i64,
        purge_after: i64,
    ) -> Result<BulkMutation, StoreError> {
        if roots.is_empty() || roots.len() > MAX_BULK_ITEMS {
            return Ok(BulkMutation::Conflict);
        }
        let mut folders = self.folders.lock().expect("folders lock poisoned");
        let mut files = self.files.lock().expect("files lock poisoned");
        let mut entries = self.trash_entries.lock().expect("trash lock poisoned");
        let mut seen_items: Vec<(LibraryItemKind, &str)> = Vec::new();
        let mut seen_entries: Vec<&str> = Vec::new();
        for root in roots {
            if root.item.id.is_empty()
                || root.entry_id.is_empty()
                || seen_items.contains(&(root.item.kind, root.item.id.as_str()))
                || seen_entries.contains(&root.entry_id.as_str())
                || entries.iter().any(|entry| entry.id == root.entry_id)
            {
                return Ok(BulkMutation::Conflict);
            }
            seen_items.push((root.item.kind, &root.item.id));
            seen_entries.push(&root.entry_id);
            let valid = match root.item.kind {
                LibraryItemKind::File => files.iter().any(|file| {
                    file.id == root.item.id
                        && file.owner_sub == owner_sub
                        && file.is_effectively_live()
                }),
                LibraryItemKind::Folder => folders.iter().any(|folder| {
                    folder.id == root.item.id
                        && folder.owner_sub == owner_sub
                        && folder.is_effectively_live()
                }),
            };
            if !valid {
                return Ok(BulkMutation::Conflict);
            }
        }
        let refs: Vec<DriveItemRef> = roots.iter().map(|root| root.item.clone()).collect();
        let normalized = normalized_refs(&refs, &files, &folders);
        let folder_snapshot = folders.clone();
        let now = trashed_at.max(1);
        for item in &normalized {
            let root = roots
                .iter()
                .find(|root| root.item == *item)
                .expect("normalized root came from input");
            entries.push(TrashEntry {
                id: root.entry_id.clone(),
                owner_sub: owner_sub.to_string(),
                kind: item.kind,
                item_id: item.id.clone(),
                trashed_at: now,
                purge_after: purge_after.max(now),
                recovery_lease: None,
                recovery_leased_at: None,
            });
            match item.kind {
                LibraryItemKind::File => {
                    let file = files
                        .iter_mut()
                        .find(|file| file.id == item.id)
                        .expect("validated file");
                    file.trashed_at = now;
                    file.trash_entry_id = Some(root.entry_id.clone());
                    file.updated_at = next_mutation_time(file.updated_at);
                }
                LibraryItemKind::Folder => {
                    let folder = folders
                        .iter_mut()
                        .find(|folder| folder.id == item.id)
                        .expect("validated folder");
                    folder.trashed_at = now;
                    folder.trash_entry_id = Some(root.entry_id.clone());
                    folder.updated_at = next_mutation_time(folder.updated_at);
                    for descendant in folders.iter_mut().filter(|folder| {
                        folder.id != item.id
                            && folder.owner_sub == owner_sub
                            && folder.trash_ancestor_id.is_none()
                            && folder_descends_from(&folder_snapshot, &folder.id, &item.id)
                    }) {
                        descendant.trash_ancestor_id = Some(root.entry_id.clone());
                        if descendant.trash_entry_id.is_none() {
                            descendant.trashed_at = now;
                        }
                    }
                    for file in files.iter_mut().filter(|file| {
                        file.owner_sub == owner_sub
                            && file.trash_ancestor_id.is_none()
                            && file.folder_id.as_deref().is_some_and(|folder_id| {
                                folder_descends_from(&folder_snapshot, folder_id, &item.id)
                            })
                    }) {
                        file.trash_ancestor_id = Some(root.entry_id.clone());
                        if file.trash_entry_id.is_none() {
                            file.trashed_at = now;
                        }
                    }
                }
            }
        }
        Ok(BulkMutation::Applied {
            changed: normalized.len(),
        })
    }

    async fn bulk_restore(
        &self,
        owner_sub: &str,
        items: &[DriveItemRef],
    ) -> Result<BulkMutation, StoreError> {
        if items.is_empty() || items.len() > MAX_BULK_ITEMS {
            return Ok(BulkMutation::Conflict);
        }
        let _lifecycle = self
            .lifecycle_guard
            .lock()
            .expect("lifecycle guard poisoned");
        let mut folders = self.folders.lock().expect("folders lock poisoned");
        let mut files = self.files.lock().expect("files lock poisoned");
        let mut entries = self.trash_entries.lock().expect("trash lock poisoned");
        let mut entry_ids = Vec::new();
        let mut seen = Vec::new();
        for item in items {
            if seen.contains(&(item.kind, item.id.as_str())) {
                return Ok(BulkMutation::Conflict);
            }
            seen.push((item.kind, item.id.as_str()));
            let entry_id = match item.kind {
                LibraryItemKind::File => files.iter().find_map(|file| {
                    (file.id == item.id
                        && file.owner_sub == owner_sub
                        && file.trash_ancestor_id.is_none())
                    .then(|| file.trash_entry_id.clone())
                    .flatten()
                }),
                LibraryItemKind::Folder => folders.iter().find_map(|folder| {
                    (folder.id == item.id
                        && folder.owner_sub == owner_sub
                        && folder.trash_ancestor_id.is_none())
                    .then(|| folder.trash_entry_id.clone())
                    .flatten()
                }),
            };
            let Some(entry_id) = entry_id else {
                return Ok(BulkMutation::Conflict);
            };
            if !entries.iter().any(|entry| {
                entry.id == entry_id
                    && entry.owner_sub == owner_sub
                    && entry.kind == item.kind
                    && entry.item_id == item.id
            }) {
                return Ok(BulkMutation::Conflict);
            }
            entry_ids.push(entry_id);
        }
        for (item, entry_id) in items.iter().zip(&entry_ids) {
            match item.kind {
                LibraryItemKind::File => {
                    let file = files
                        .iter_mut()
                        .find(|file| file.id == item.id)
                        .expect("validated file");
                    file.trashed_at = 0;
                    file.trash_entry_id = None;
                    file.updated_at = next_mutation_time(file.updated_at);
                }
                LibraryItemKind::Folder => {
                    let folder = folders
                        .iter_mut()
                        .find(|folder| folder.id == item.id)
                        .expect("validated folder");
                    folder.trashed_at = 0;
                    folder.trash_entry_id = None;
                    folder.updated_at = next_mutation_time(folder.updated_at);
                }
            }
            for folder in folders
                .iter_mut()
                .filter(|folder| folder.trash_ancestor_id.as_deref() == Some(entry_id))
            {
                folder.trash_ancestor_id = None;
                if folder.trash_entry_id.is_none() {
                    folder.trashed_at = 0;
                }
            }
            for file in files
                .iter_mut()
                .filter(|file| file.trash_ancestor_id.as_deref() == Some(entry_id))
            {
                file.trash_ancestor_id = None;
                if file.trash_entry_id.is_none() {
                    file.trashed_at = 0;
                }
            }
        }
        entries.retain(|entry| !entry_ids.contains(&entry.id));
        Ok(BulkMutation::Applied {
            changed: items.len(),
        })
    }

    async fn bulk_move(
        &self,
        owner_sub: &str,
        items: &[DriveItemRef],
        folder_id: Option<&str>,
    ) -> Result<BulkMutation, StoreError> {
        if items.is_empty() || items.len() > MAX_BULK_ITEMS {
            return Ok(BulkMutation::Conflict);
        }
        let mut folders = self.folders.lock().expect("folders lock poisoned");
        let mut files = self.files.lock().expect("files lock poisoned");
        if folder_id.is_some_and(|target| {
            !folders.iter().any(|folder| {
                folder.id == target && folder.owner_sub == owner_sub && folder.is_effectively_live()
            })
        }) {
            return Ok(BulkMutation::Conflict);
        }
        let mut seen = Vec::new();
        for item in items {
            if seen.contains(&(item.kind, item.id.as_str())) {
                return Ok(BulkMutation::Conflict);
            }
            seen.push((item.kind, item.id.as_str()));
            let valid = match item.kind {
                LibraryItemKind::File => files.iter().any(|file| {
                    file.id == item.id && file.owner_sub == owner_sub && file.is_effectively_live()
                }),
                LibraryItemKind::Folder => folders.iter().any(|folder| {
                    folder.id == item.id
                        && folder.owner_sub == owner_sub
                        && folder.is_effectively_live()
                }),
            };
            if !valid {
                return Ok(BulkMutation::Conflict);
            }
            if item.kind == LibraryItemKind::Folder
                && folder_id.is_some_and(|target| {
                    target == item.id || folder_descends_from(&folders, target, &item.id)
                })
            {
                return Ok(BulkMutation::Conflict);
            }
        }
        let normalized = normalized_refs(items, &files, &folders);
        let target = folder_id.map(str::to_string);
        for item in &normalized {
            match item.kind {
                LibraryItemKind::File => {
                    let file = files
                        .iter_mut()
                        .find(|file| file.id == item.id)
                        .expect("validated file");
                    file.folder_id = target.clone();
                    file.updated_at = next_mutation_time(file.updated_at);
                }
                LibraryItemKind::Folder => {
                    let folder = folders
                        .iter_mut()
                        .find(|folder| folder.id == item.id)
                        .expect("validated folder");
                    folder.parent_id = target.clone();
                    folder.updated_at = next_mutation_time(folder.updated_at);
                }
            }
        }
        Ok(BulkMutation::Applied {
            changed: normalized.len(),
        })
    }

    async fn bulk_purge(
        &self,
        owner_sub: &str,
        items: &[DriveItemRef],
        enqueued_at: i64,
    ) -> Result<BulkMutation, StoreError> {
        if items.is_empty() || items.len() > MAX_BULK_ITEMS {
            return Ok(BulkMutation::Conflict);
        }
        let _lifecycle = self
            .lifecycle_guard
            .lock()
            .expect("lifecycle guard poisoned");
        let mut requests = self
            .request_state
            .lock()
            .expect("request state lock poisoned");
        let mut folders = self.folders.lock().expect("folders lock poisoned");
        let mut files = self.files.lock().expect("files lock poisoned");
        let mut versions = self.versions.lock().expect("versions lock poisoned");
        let mut comments = self.comments.lock().expect("comments lock poisoned");
        let mut entries = self.trash_entries.lock().expect("trash lock poisoned");
        let mut deletions = self
            .blob_deletions
            .lock()
            .expect("blob deletion lock poisoned");
        let mut seen = Vec::new();
        for item in items {
            if seen.contains(&(item.kind, item.id.as_str())) {
                return Ok(BulkMutation::Conflict);
            }
            seen.push((item.kind, item.id.as_str()));
            let entry_id = match item.kind {
                LibraryItemKind::File => files.iter().find_map(|file| {
                    (file.id == item.id
                        && file.owner_sub == owner_sub
                        && file.trash_ancestor_id.is_none())
                    .then(|| file.trash_entry_id.clone())
                    .flatten()
                }),
                LibraryItemKind::Folder => folders.iter().find_map(|folder| {
                    (folder.id == item.id
                        && folder.owner_sub == owner_sub
                        && folder.trash_ancestor_id.is_none())
                    .then(|| folder.trash_entry_id.clone())
                    .flatten()
                }),
            };
            let exact = entry_id.is_some_and(|entry_id| {
                entries.iter().any(|entry| {
                    entry.id == entry_id
                        && entry.owner_sub == owner_sub
                        && entry.kind == item.kind
                        && entry.item_id == item.id
                })
            });
            if !exact {
                return Ok(BulkMutation::Conflict);
            }
        }
        let normalized = normalized_refs(items, &files, &folders);
        let folder_snapshot = folders.clone();
        let mut doomed_folders: Vec<String> = Vec::new();
        let mut doomed_files: Vec<String> = normalized
            .iter()
            .filter(|item| item.kind == LibraryItemKind::File)
            .map(|item| item.id.clone())
            .collect();
        for root in normalized
            .iter()
            .filter(|item| item.kind == LibraryItemKind::Folder)
        {
            doomed_folders.extend(
                folder_snapshot
                    .iter()
                    .filter(|folder| {
                        folder.owner_sub == owner_sub
                            && folder_descends_from(&folder_snapshot, &folder.id, &root.id)
                    })
                    .map(|folder| folder.id.clone()),
            );
        }
        doomed_folders.sort();
        doomed_folders.dedup();
        doomed_files.extend(
            files
                .iter()
                .filter(|file| {
                    file.owner_sub == owner_sub
                        && file
                            .folder_id
                            .as_ref()
                            .is_some_and(|folder| doomed_folders.contains(folder))
                })
                .map(|file| file.id.clone()),
        );
        doomed_files.sort();
        doomed_files.dedup();
        let mut keys: Vec<String> = files
            .iter()
            .filter(|file| doomed_files.contains(&file.id))
            .map(|file| file.object_key.clone())
            .chain(
                versions
                    .iter()
                    .filter(|version| doomed_files.contains(&version.file_id))
                    .map(|version| version.object_key.clone()),
            )
            .collect();
        let thumbs: Vec<String> = keys.iter().map(|key| format!("{key}.thumb")).collect();
        keys.extend(thumbs);
        keys.sort();
        keys.dedup();
        for key in keys {
            if !deletions.iter().any(|entry| entry.object_key == key) {
                deletions.push(MemoryBlobDelete {
                    object_key: key,
                    enqueued_at,
                    attempts: 0,
                    next_attempt_at: enqueued_at,
                    recovery_lease: None,
                    recovery_leased_at: None,
                });
            }
        }
        versions.retain(|version| !doomed_files.contains(&version.file_id));
        comments.retain(|comment| !doomed_files.contains(&comment.file_id));
        files.retain(|file| !doomed_files.contains(&file.id));
        for request in requests.requests.iter_mut().filter(|request| {
            request.owner_sub == owner_sub && doomed_folders.contains(&request.folder_id)
        }) {
            request.status = "closed".to_string();
            request.updated_at = enqueued_at;
        }
        folders.retain(|folder| !doomed_folders.contains(&folder.id));
        entries.retain(|entry| match entry.kind {
            LibraryItemKind::File => !doomed_files.contains(&entry.item_id),
            LibraryItemKind::Folder => !doomed_folders.contains(&entry.item_id),
        });
        Ok(BulkMutation::Applied {
            changed: normalized.len(),
        })
    }

    async fn claim_expired_trash(
        &self,
        lease_id: &str,
        now: i64,
        lease_expired_before: i64,
        limit: i64,
    ) -> Result<Vec<TrashEntry>, StoreError> {
        let folders = self.folders.lock().expect("folders lock poisoned");
        let files = self.files.lock().expect("files lock poisoned");
        let mut entries = self.trash_entries.lock().expect("trash lock poisoned");
        let mut candidates: Vec<usize> = entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                entry.purge_after <= now
                    && (entry.recovery_lease.is_none()
                        || entry
                            .recovery_leased_at
                            .is_some_and(|leased| leased <= lease_expired_before))
                    && match entry.kind {
                        LibraryItemKind::File => files.iter().any(|file| {
                            file.id == entry.item_id
                                && file.owner_sub == entry.owner_sub
                                && file.trash_entry_id.as_deref() == Some(entry.id.as_str())
                                && file.trash_ancestor_id.is_none()
                        }),
                        LibraryItemKind::Folder => folders.iter().any(|folder| {
                            folder.id == entry.item_id
                                && folder.owner_sub == entry.owner_sub
                                && folder.trash_entry_id.as_deref() == Some(entry.id.as_str())
                                && folder.trash_ancestor_id.is_none()
                        }),
                    }
            })
            .map(|(index, _)| index)
            .collect();
        candidates.sort_by_key(|index| (entries[*index].purge_after, entries[*index].id.clone()));
        candidates.truncate(clamp_page(limit) as usize);
        let mut claimed = Vec::new();
        for index in candidates {
            entries[index].recovery_lease = Some(lease_id.to_string());
            entries[index].recovery_leased_at = Some(now);
            claimed.push(entries[index].clone());
        }
        Ok(claimed)
    }

    async fn abandon_trash_claim(
        &self,
        entry_id: &str,
        lease_id: &str,
    ) -> Result<bool, StoreError> {
        let mut entries = self.trash_entries.lock().expect("trash lock poisoned");
        let Some(entry) = entries.iter_mut().find(|entry| {
            entry.id == entry_id && entry.recovery_lease.as_deref() == Some(lease_id)
        }) else {
            return Ok(false);
        };
        entry.recovery_lease = None;
        entry.recovery_leased_at = None;
        Ok(true)
    }

    async fn claim_blob_deletions(
        &self,
        lease_id: &str,
        now: i64,
        lease_expired_before: i64,
        limit: i64,
    ) -> Result<BlobDeleteClaim, StoreError> {
        let mut rows = self
            .blob_deletions
            .lock()
            .expect("blob deletion lock poisoned");
        let mut candidates: Vec<usize> = rows
            .iter()
            .enumerate()
            .filter(|(_, row)| {
                row.next_attempt_at <= now
                    && (row.recovery_lease.is_none()
                        || row
                            .recovery_leased_at
                            .is_some_and(|leased| leased <= lease_expired_before))
            })
            .map(|(index, _)| index)
            .collect();
        candidates.sort_by_key(|index| (rows[*index].enqueued_at, rows[*index].object_key.clone()));
        candidates.truncate(clamp_page(limit) as usize);
        if candidates.is_empty() {
            return Ok(BlobDeleteClaim::Empty);
        }
        let mut claimed = Vec::new();
        for index in candidates {
            rows[index].recovery_lease = Some(lease_id.to_string());
            rows[index].recovery_leased_at = Some(now);
            claimed.push(BlobDeleteItem {
                object_key: rows[index].object_key.clone(),
                attempts: rows[index].attempts,
            });
        }
        Ok(BlobDeleteClaim::Claimed(claimed))
    }

    async fn complete_blob_deletion(
        &self,
        object_key: &str,
        lease_id: &str,
    ) -> Result<bool, StoreError> {
        let mut rows = self
            .blob_deletions
            .lock()
            .expect("blob deletion lock poisoned");
        let before = rows.len();
        rows.retain(|row| {
            !(row.object_key == object_key && row.recovery_lease.as_deref() == Some(lease_id))
        });
        Ok(rows.len() != before)
    }

    async fn abandon_blob_deletion(
        &self,
        object_key: &str,
        lease_id: &str,
        retry_at: i64,
    ) -> Result<bool, StoreError> {
        let mut rows = self
            .blob_deletions
            .lock()
            .expect("blob deletion lock poisoned");
        let Some(row) = rows.iter_mut().find(|row| {
            row.object_key == object_key && row.recovery_lease.as_deref() == Some(lease_id)
        }) else {
            return Ok(false);
        };
        row.attempts = row.attempts.saturating_add(1);
        row.next_attempt_at = retry_at;
        row.recovery_lease = None;
        row.recovery_leased_at = None;
        Ok(true)
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
            .find(|f| f.id == id && f.owner_sub == owner_sub && f.is_effectively_live())
        {
            Some(f) => {
                f.share_token = share_token;
                f.expires_at = expires_at;
                f.share_password_hash = share_password_hash;
                f.updated_at = next_mutation_time(f.updated_at);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn create_folder(&self, folder: &FolderRec) -> Result<bool, StoreError> {
        let _lifecycle = self
            .lifecycle_guard
            .lock()
            .expect("lifecycle guard poisoned");
        let mut folders = self.folders.lock().expect("folders lock poisoned");
        if folder.parent_id.as_deref() == Some(folder.id.as_str())
            || folders.iter().any(|f| f.id == folder.id)
            || folder.parent_id.as_deref().is_some_and(|parent_id| {
                !folders.iter().any(|parent| {
                    parent.id == parent_id
                        && parent.owner_sub == folder.owner_sub
                        && parent.is_effectively_live()
                })
            })
        {
            return Ok(false);
        }
        folders.push(folder.clone());
        Ok(true)
    }

    async fn list_folders(&self, owner_sub: &str) -> Result<Vec<FolderRec>, StoreError> {
        let folders = self.folders.lock().expect("folders lock poisoned");
        let mut out: Vec<FolderRec> = folders
            .iter()
            .filter(|f| f.owner_sub == owner_sub && f.is_effectively_live())
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

    async fn get_folder(&self, id: &str, owner_sub: &str) -> Result<Option<FolderRec>, StoreError> {
        let folders = self.folders.lock().expect("folders lock poisoned");
        Ok(folders
            .iter()
            .find(|f| f.id == id && f.owner_sub == owner_sub && f.is_effectively_live())
            .cloned())
    }

    async fn get_folder_any(
        &self,
        id: &str,
        owner_sub: &str,
    ) -> Result<Option<FolderRec>, StoreError> {
        let folders = self.folders.lock().expect("folders lock poisoned");
        Ok(folders
            .iter()
            .find(|folder| folder.id == id && folder.owner_sub == owner_sub)
            .cloned())
    }

    async fn get_folder_by_token(&self, token: &str) -> Result<Option<FolderRec>, StoreError> {
        let folders = self.folders.lock().expect("folders lock poisoned");
        Ok(folders
            .iter()
            .find(|f| f.is_effectively_live() && f.share_token.as_deref() == Some(token))
            .cloned())
    }

    async fn get_folder_by_upload_token(
        &self,
        token: &str,
    ) -> Result<Option<FolderRec>, StoreError> {
        let folders = self.folders.lock().expect("folders lock poisoned");
        Ok(folders
            .iter()
            .find(|f| f.is_effectively_live() && f.upload_token.as_deref() == Some(token))
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
            .find(|f| f.id == id && f.owner_sub == owner_sub && f.is_effectively_live())
        {
            Some(f) => {
                f.name = name.to_string();
                f.updated_at = next_mutation_time(f.updated_at);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn configure_folder_share(
        &self,
        id: &str,
        owner_sub: &str,
        share_token: Option<String>,
        expires_at: Option<i64>,
        share_password_hash: Option<String>,
    ) -> Result<bool, StoreError> {
        let mut folders = self.folders.lock().expect("folders lock poisoned");
        match folders
            .iter_mut()
            .find(|f| f.id == id && f.owner_sub == owner_sub && f.is_effectively_live())
        {
            Some(f) => {
                f.share_token = share_token;
                f.expires_at = expires_at;
                f.share_password_hash = share_password_hash;
                f.updated_at = next_mutation_time(f.updated_at);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn configure_folder_upload(
        &self,
        id: &str,
        owner_sub: &str,
        upload_token: Option<String>,
    ) -> Result<bool, StoreError> {
        let mut folders = self.folders.lock().expect("folders lock poisoned");
        match folders
            .iter_mut()
            .find(|f| f.id == id && f.owner_sub == owner_sub && f.is_effectively_live())
        {
            Some(f) => {
                f.upload_token = upload_token;
                f.updated_at = next_mutation_time(f.updated_at);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn delete_folder_if_empty(
        &self,
        id: &str,
        owner_sub: &str,
    ) -> Result<FolderDelete, StoreError> {
        let mut folders = self.folders.lock().expect("folders lock poisoned");
        if !folders
            .iter()
            .any(|f| f.id == id && f.owner_sub == owner_sub)
        {
            return Ok(FolderDelete::NotFound);
        }
        // Empty = no child folder AND no file points at it (owner-scoped).
        let has_subfolder = folders
            .iter()
            .any(|f| f.owner_sub == owner_sub && f.parent_id.as_deref() == Some(id));
        let has_files = self
            .files
            .lock()
            .expect("files lock poisoned")
            .iter()
            .any(|f| f.owner_sub == owner_sub && f.folder_id.as_deref() == Some(id));
        if has_subfolder || has_files {
            return Ok(FolderDelete::NotEmpty);
        }
        folders.retain(|f| !(f.id == id && f.owner_sub == owner_sub));
        Ok(FolderDelete::Deleted)
    }

    async fn delete_folder_cascade(
        &self,
        id: &str,
        owner_sub: &str,
    ) -> Result<Vec<String>, StoreError> {
        let mut folders = self.folders.lock().expect("folders lock poisoned");
        if !folders
            .iter()
            .any(|f| f.id == id && f.owner_sub == owner_sub)
        {
            return Ok(Vec::new());
        }
        // Compute the descendant folder-id set (BFS on parent_id, owner-scoped, cycle-safe).
        let mut set: Vec<String> = vec![id.to_string()];
        let mut i = 0;
        while i < set.len() {
            let parent = set[i].clone();
            for f in folders.iter() {
                if f.owner_sub == owner_sub
                    && f.parent_id.as_deref() == Some(parent.as_str())
                    && !set.contains(&f.id)
                {
                    set.push(f.id.clone());
                }
            }
            i += 1;
        }
        // Remove every file in those folders (+ its versions), collecting the freed blob keys.
        let mut keys: Vec<String> = Vec::new();
        {
            let mut files = self.files.lock().expect("files lock poisoned");
            let mut versions = self.versions.lock().expect("versions lock poisoned");
            let doomed: Vec<String> = files
                .iter()
                .filter(|f| {
                    f.owner_sub == owner_sub
                        && f.folder_id
                            .as_deref()
                            .is_some_and(|fid| set.iter().any(|s| s == fid))
                })
                .map(|f| f.id.clone())
                .collect();
            for fid in &doomed {
                if let Some(f) = files.iter().find(|f| &f.id == fid) {
                    keys.push(f.object_key.clone());
                }
                for v in versions.iter().filter(|v| &v.file_id == fid) {
                    keys.push(v.object_key.clone());
                }
            }
            files.retain(|f| !doomed.contains(&f.id));
            versions.retain(|v| !doomed.contains(&v.file_id));
            self.comments
                .lock()
                .expect("comments lock poisoned")
                .retain(|c| !doomed.contains(&c.file_id));
        }
        folders.retain(|f| !(f.owner_sub == owner_sub && set.contains(&f.id)));
        Ok(keys)
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
                f.updated_at = next_mutation_time(f.updated_at);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn list_files_in_folder(
        &self,
        folder_id: &str,
        owner_sub: &str,
    ) -> Result<Vec<FileRec>, StoreError> {
        let files = self.files.lock().expect("files lock poisoned");
        let mut out: Vec<FileRec> = files
            .iter()
            .filter(|f| {
                f.owner_sub == owner_sub
                    && f.is_effectively_live()
                    && f.folder_id.as_deref() == Some(folder_id)
            })
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.id.cmp(&a.id))
        });
        Ok(out)
    }

    async fn find_file_in_folder(
        &self,
        owner_sub: &str,
        name: &str,
        folder_id: Option<&str>,
    ) -> Result<Option<FileRec>, StoreError> {
        let files = self.files.lock().expect("files lock poisoned");
        Ok(files
            .iter()
            .find(|f| {
                f.owner_sub == owner_sub
                    && f.is_effectively_live()
                    && f.name == name
                    && f.folder_id.as_deref() == folder_id
            })
            .cloned())
    }

    async fn update_file_blob(
        &self,
        id: &str,
        owner_sub: &str,
        object_key: &str,
        size: i64,
        content_type: &str,
        updated_at: i64,
    ) -> Result<bool, StoreError> {
        let mut files = self.files.lock().expect("files lock poisoned");
        match files
            .iter_mut()
            .find(|f| f.id == id && f.owner_sub == owner_sub)
        {
            Some(f) => {
                f.object_key = object_key.to_string();
                f.size = size;
                f.content_type = content_type.to_string();
                f.updated_at = updated_at.max(f.updated_at.saturating_add(1));
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn add_version(&self, version: &VersionRec) -> Result<bool, StoreError> {
        let mut versions = self.versions.lock().expect("versions lock poisoned");
        if versions.iter().any(|v| v.id == version.id) {
            return Ok(false);
        }
        versions.push(version.clone());
        Ok(true)
    }

    async fn list_versions(&self, file_id: &str) -> Result<Vec<VersionRec>, StoreError> {
        let versions = self.versions.lock().expect("versions lock poisoned");
        let mut out: Vec<VersionRec> = versions
            .iter()
            .filter(|v| v.file_id == file_id)
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.id.cmp(&a.id))
        });
        Ok(out)
    }

    async fn get_version(
        &self,
        version_id: &str,
        file_id: &str,
    ) -> Result<Option<VersionRec>, StoreError> {
        let versions = self.versions.lock().expect("versions lock poisoned");
        Ok(versions
            .iter()
            .find(|v| v.id == version_id && v.file_id == file_id)
            .cloned())
    }

    async fn delete_version(
        &self,
        version_id: &str,
        file_id: &str,
    ) -> Result<Option<VersionRec>, StoreError> {
        let mut versions = self.versions.lock().expect("versions lock poisoned");
        if let Some(pos) = versions
            .iter()
            .position(|v| v.id == version_id && v.file_id == file_id)
        {
            Ok(Some(versions.remove(pos)))
        } else {
            Ok(None)
        }
    }

    async fn prune_versions(
        &self,
        file_id: &str,
        keep: i64,
    ) -> Result<Vec<VersionRec>, StoreError> {
        let mut versions = self.versions.lock().expect("versions lock poisoned");
        // Newest-first within this file; anything past the first `keep` is pruned (oldest go).
        let mut mine: Vec<VersionRec> = versions
            .iter()
            .filter(|v| v.file_id == file_id)
            .cloned()
            .collect();
        mine.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.id.cmp(&a.id))
        });
        let keep = keep.max(0) as usize;
        let pruned: Vec<VersionRec> = mine.into_iter().skip(keep).collect();
        let pruned_ids: Vec<String> = pruned.iter().map(|v| v.id.clone()).collect();
        versions.retain(|v| !pruned_ids.contains(&v.id));
        Ok(pruned)
    }

    async fn delete_versions_for_file(&self, file_id: &str) -> Result<Vec<VersionRec>, StoreError> {
        let mut versions = self.versions.lock().expect("versions lock poisoned");
        let removed: Vec<VersionRec> = versions
            .iter()
            .filter(|v| v.file_id == file_id)
            .cloned()
            .collect();
        versions.retain(|v| v.file_id != file_id);
        Ok(removed)
    }

    async fn usage_for_owner(&self, owner_sub: &str) -> Result<i64, StoreError> {
        let files = self.files.lock().expect("files lock poisoned");
        let file_bytes: i64 = files
            .iter()
            .filter(|f| f.owner_sub == owner_sub)
            .map(|f| f.size)
            .sum();
        // Retained version blobs of the owner's files also count toward usage.
        let owned_ids: Vec<&str> = files
            .iter()
            .filter(|f| f.owner_sub == owner_sub)
            .map(|f| f.id.as_str())
            .collect();
        let version_bytes: i64 = self
            .versions
            .lock()
            .expect("versions lock poisoned")
            .iter()
            .filter(|v| owned_ids.contains(&v.file_id.as_str()))
            .map(|v| v.size)
            .sum();
        Ok(file_bytes + version_bytes)
    }

    async fn usage_by_owner(&self) -> Result<Vec<OwnerUsage>, StoreError> {
        let files = self.files.lock().expect("files lock poisoned");
        let mut out: Vec<OwnerUsage> = Vec::new();
        for f in files.iter() {
            match out.iter_mut().find(|u| u.owner_sub == f.owner_sub) {
                Some(u) => {
                    if f.trashed_at == 0 {
                        u.files += 1;
                    }
                    u.bytes += f.size;
                }
                None => out.push(OwnerUsage {
                    owner_sub: f.owner_sub.clone(),
                    files: if f.trashed_at == 0 { 1 } else { 0 },
                    bytes: f.size,
                }),
            }
        }
        // Fold each version's bytes into its file's owner (versions never add to the file COUNT).
        let versions = self.versions.lock().expect("versions lock poisoned");
        for v in versions.iter() {
            if let Some(owner) = files
                .iter()
                .find(|f| f.id == v.file_id)
                .map(|f| f.owner_sub.clone())
            {
                if let Some(u) = out.iter_mut().find(|u| u.owner_sub == owner) {
                    u.bytes += v.size;
                }
            }
        }
        // Largest first; owner as a deterministic tiebreak — matches the Pg ORDER BY.
        out.sort_by(|a, b| {
            b.bytes
                .cmp(&a.bytes)
                .then_with(|| a.owner_sub.cmp(&b.owner_sub))
        });
        Ok(out)
    }

    async fn get_quota(&self, owner_sub: &str) -> Result<Option<i64>, StoreError> {
        let quotas = self.quotas.lock().expect("quotas lock poisoned");
        Ok(quotas.iter().find(|(o, _)| o == owner_sub).map(|(_, q)| *q))
    }

    async fn set_quota(&self, owner_sub: &str, quota_bytes: Option<i64>) -> Result<(), StoreError> {
        let mut quotas = self.quotas.lock().expect("quotas lock poisoned");
        quotas.retain(|(o, _)| o != owner_sub);
        if let Some(q) = quota_bytes {
            quotas.push((owner_sub.to_string(), q));
        }
        Ok(())
    }

    async fn list_quotas(&self) -> Result<Vec<(String, i64)>, StoreError> {
        let quotas = self.quotas.lock().expect("quotas lock poisoned");
        let mut out = quotas.clone();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    async fn create_comment(&self, comment: &FileComment) -> Result<bool, StoreError> {
        // Keep the global Memory lock order `files -> comments`, matching cascade deletion.
        let mut files = self.files.lock().expect("files lock poisoned");
        let Some(file) = files.iter_mut().find(|file| file.id == comment.file_id) else {
            return Ok(false);
        };
        let mut comments = self.comments.lock().expect("comments lock poisoned");
        if comments.iter().any(|c| c.id == comment.id) {
            return Ok(false);
        }
        comments.push(comment.clone());
        file.updated_at = next_mutation_time(file.updated_at);
        Ok(true)
    }

    async fn list_comments(&self, file_id: &str) -> Result<Vec<FileComment>, StoreError> {
        let comments = self.comments.lock().expect("comments lock poisoned");
        let mut out: Vec<FileComment> = comments
            .iter()
            .filter(|c| c.file_id == file_id)
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(out)
    }

    async fn get_comment(&self, comment_id: &str) -> Result<Option<FileComment>, StoreError> {
        let comments = self.comments.lock().expect("comments lock poisoned");
        Ok(comments.iter().find(|c| c.id == comment_id).cloned())
    }

    async fn delete_comment(&self, comment_id: &str, file_id: &str) -> Result<bool, StoreError> {
        let mut files = self.files.lock().expect("files lock poisoned");
        let mut comments = self.comments.lock().expect("comments lock poisoned");
        let before = comments.len();
        comments.retain(|c| !(c.id == comment_id && c.file_id == file_id));
        let deleted = comments.len() != before;
        if deleted {
            if let Some(file) = files.iter_mut().find(|file| file.id == file_id) {
                file.updated_at = next_mutation_time(file.updated_at);
            }
        }
        Ok(deleted)
    }

    async fn delete_comments_for_file(&self, file_id: &str) -> Result<(), StoreError> {
        let mut comments = self.comments.lock().expect("comments lock poisoned");
        comments.retain(|c| c.file_id != file_id);
        Ok(())
    }

    async fn create_upload_request(&self, request: &UploadRequestRec) -> Result<bool, StoreError> {
        let _lifecycle = self
            .lifecycle_guard
            .lock()
            .expect("lifecycle guard poisoned");
        let mut state = self
            .request_state
            .lock()
            .expect("request state lock poisoned");
        if !self
            .folders
            .lock()
            .expect("folders lock poisoned")
            .iter()
            .any(|folder| {
                folder.id == request.folder_id
                    && folder.owner_sub == request.owner_sub
                    && folder.is_effectively_live()
            })
        {
            return Ok(false);
        }
        if state
            .requests
            .iter()
            .any(|item| item.id == request.id || item.token == request.token)
        {
            return Ok(false);
        }
        state.requests.push(request.clone());
        Ok(true)
    }

    async fn list_upload_requests(
        &self,
        owner_sub: &str,
    ) -> Result<Vec<UploadRequestRec>, StoreError> {
        let state = self
            .request_state
            .lock()
            .expect("request state lock poisoned");
        let mut out: Vec<_> = state
            .requests
            .iter()
            .filter(|request| request.owner_sub == owner_sub)
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            b.updated_at
                .cmp(&a.updated_at)
                .then_with(|| b.id.cmp(&a.id))
        });
        Ok(out)
    }

    async fn upload_request_inbox(
        &self,
        owner_sub: &str,
        view: UploadRequestInboxView,
        as_of: i64,
    ) -> Result<UploadRequestInbox, StoreError> {
        let state = self
            .request_state
            .lock()
            .expect("request state lock poisoned");
        let requests = state
            .requests
            .iter()
            .filter(|request| request.owner_sub == owner_sub)
            .cloned()
            .collect::<Vec<_>>();
        Ok(finish_upload_request_inbox(requests, view, as_of))
    }

    async fn get_upload_request(
        &self,
        id: &str,
        owner_sub: &str,
    ) -> Result<Option<UploadRequestRec>, StoreError> {
        let state = self
            .request_state
            .lock()
            .expect("request state lock poisoned");
        Ok(state
            .requests
            .iter()
            .find(|request| request.id == id && request.owner_sub == owner_sub)
            .cloned())
    }

    async fn get_upload_request_by_token(
        &self,
        token: &str,
    ) -> Result<Option<UploadRequestRec>, StoreError> {
        let state = self
            .request_state
            .lock()
            .expect("request state lock poisoned");
        Ok(state
            .requests
            .iter()
            .find(|request| request.token == token)
            .cloned())
    }

    async fn update_upload_request(&self, request: &UploadRequestRec) -> Result<bool, StoreError> {
        let mut state = self
            .request_state
            .lock()
            .expect("request state lock poisoned");
        let Some(current) = state
            .requests
            .iter_mut()
            .find(|item| item.id == request.id && item.owner_sub == request.owner_sub)
        else {
            return Ok(false);
        };
        if request.max_total_bytes < current.used_bytes || request.max_files < current.used_files {
            return Ok(false);
        }
        current.title = request.title.clone();
        current.description = request.description.clone();
        current.expires_at = request.expires_at;
        current.max_file_bytes = request.max_file_bytes;
        current.max_total_bytes = request.max_total_bytes;
        current.max_files = request.max_files;
        current.allowed_types = request.allowed_types.clone();
        current.updated_at = request.updated_at;
        Ok(true)
    }

    async fn set_upload_request_status(
        &self,
        id: &str,
        owner_sub: &str,
        status: &str,
        updated_at: i64,
    ) -> Result<bool, StoreError> {
        let mut state = self
            .request_state
            .lock()
            .expect("request state lock poisoned");
        let Some(index) = state
            .requests
            .iter()
            .position(|item| item.id == id && item.owner_sub == owner_sub)
        else {
            return Ok(false);
        };
        let folder_id = state.requests[index].folder_id.clone();
        if !self
            .folders
            .lock()
            .expect("folders lock poisoned")
            .iter()
            .any(|folder| {
                folder.id == folder_id
                    && folder.owner_sub == owner_sub
                    && folder.is_effectively_live()
            })
        {
            return Ok(false);
        }
        let request = &mut state.requests[index];
        request.status = status.to_string();
        request.updated_at = updated_at;
        Ok(true)
    }

    async fn reopen_upload_request(
        &self,
        id: &str,
        owner_sub: &str,
        now: i64,
        renewed_expires_at: i64,
    ) -> Result<bool, StoreError> {
        let mut state = self
            .request_state
            .lock()
            .expect("request state lock poisoned");
        let Some(index) = state
            .requests
            .iter()
            .position(|item| item.id == id && item.owner_sub == owner_sub)
        else {
            return Ok(false);
        };
        let folder_id = state.requests[index].folder_id.clone();
        if !self
            .folders
            .lock()
            .expect("folders lock poisoned")
            .iter()
            .any(|folder| {
                folder.id == folder_id
                    && folder.owner_sub == owner_sub
                    && folder.is_effectively_live()
            })
        {
            return Ok(false);
        }
        let request = &mut state.requests[index];
        if request.is_expired(now) {
            request.expires_at = Some(renewed_expires_at);
        }
        request.status = "open".to_string();
        request.updated_at = now;
        Ok(true)
    }

    async fn rotate_upload_request_token(
        &self,
        id: &str,
        owner_sub: &str,
        expected_token: &str,
        token: &str,
        updated_at: i64,
    ) -> Result<bool, StoreError> {
        let mut state = self
            .request_state
            .lock()
            .expect("request state lock poisoned");
        if state
            .requests
            .iter()
            .any(|item| item.token == token && item.id != id)
        {
            return Ok(false);
        }
        let Some(request) = state.requests.iter_mut().find(|item| {
            item.id == id
                && item.owner_sub == owner_sub
                && capability_token_eq(&item.token, expected_token)
        }) else {
            return Ok(false);
        };
        request.token = token.to_string();
        request.updated_at = updated_at;
        Ok(true)
    }

    async fn list_upload_submissions(
        &self,
        request_id: &str,
        owner_sub: &str,
    ) -> Result<Vec<UploadSubmission>, StoreError> {
        let state = self
            .request_state
            .lock()
            .expect("request state lock poisoned");
        if !state
            .requests
            .iter()
            .any(|request| request.id == request_id && request.owner_sub == owner_sub)
        {
            return Ok(Vec::new());
        }
        let mut out: Vec<_> = state
            .submissions
            .iter()
            .filter(|submission| submission.request_id == request_id)
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.id.cmp(&a.id))
        });
        Ok(out)
    }

    async fn reserve_request_upload(
        &self,
        input: UploadReserveInput<'_>,
    ) -> Result<UploadReserve, StoreError> {
        let UploadReserveInput {
            request_id,
            expected_token,
            reservation_id,
            size,
            content_type,
            content_type_verified,
            owner_quota,
            now,
        } = input;
        let _lifecycle = self
            .lifecycle_guard
            .lock()
            .expect("lifecycle guard poisoned");
        let mut state = self
            .request_state
            .lock()
            .expect("request state lock poisoned");
        let Some(index) = state
            .requests
            .iter()
            .position(|request| request.id == request_id)
        else {
            return Ok(UploadReserve::Unavailable);
        };
        let request = state.requests[index].clone();
        if !capability_token_eq(&request.token, expected_token)
            || !request.is_open()
            || request.is_expired(now)
        {
            return Ok(UploadReserve::Unavailable);
        }
        if !self
            .folders
            .lock()
            .expect("folders lock poisoned")
            .iter()
            .any(|folder| {
                folder.id == request.folder_id
                    && folder.owner_sub == request.owner_sub
                    && folder.is_effectively_live()
            })
        {
            return Ok(UploadReserve::Unavailable);
        }
        if size <= 0 || size > request.max_file_bytes {
            return Ok(UploadReserve::FileTooLarge);
        }
        if (!content_type_verified && !request_allows_unverified_type(&request))
            || !request.accepts_content_type(content_type)
        {
            return Ok(UploadReserve::TypeDenied);
        }
        if request.used_bytes.saturating_add(size) > request.max_total_bytes {
            return Ok(UploadReserve::TotalBudgetExceeded);
        }
        if request.used_files.saturating_add(1) > request.max_files {
            return Ok(UploadReserve::FileCountExceeded);
        }
        if state
            .reservations
            .iter()
            .any(|reservation| reservation.id == reservation_id)
        {
            return Ok(UploadReserve::Collision);
        }

        let files = self.files.lock().expect("files lock poisoned");
        if files.iter().any(|file| file.id == reservation_id) {
            return Ok(UploadReserve::Collision);
        }
        let committed: i64 = files
            .iter()
            .filter(|file| file.owner_sub == request.owner_sub)
            .map(|file| file.size)
            .sum();
        let owned_ids: Vec<&str> = files
            .iter()
            .filter(|file| file.owner_sub == request.owner_sub)
            .map(|file| file.id.as_str())
            .collect();
        let versions = self.versions.lock().expect("versions lock poisoned");
        let version_bytes: i64 = versions
            .iter()
            .filter(|version| owned_ids.contains(&version.file_id.as_str()))
            .map(|version| version.size)
            .sum();
        let reserved: i64 = state
            .reservations
            .iter()
            .filter(|reservation| reservation.owner_sub == request.owner_sub)
            .map(|reservation| reservation.size)
            .sum();
        let owner_writes: i64 = self
            .owner_blob_writes
            .lock()
            .expect("owner blob writes lock poisoned")
            .iter()
            .filter(|row| {
                row.intent.owner_sub == request.owner_sub
                    && row.intent.kind != OWNER_WRITE_THUMBNAIL
            })
            .map(|row| row.intent.size)
            .sum();
        if owner_quota.is_some_and(|quota| {
            committed
                .saturating_add(version_bytes)
                .saturating_add(reserved)
                .saturating_add(owner_writes)
                .saturating_add(size)
                > quota
        }) {
            return Ok(UploadReserve::OwnerQuotaExceeded);
        }
        drop(versions);
        drop(files);

        state.requests[index].used_bytes = request.used_bytes.saturating_add(size);
        state.requests[index].used_files = request.used_files.saturating_add(1);
        state.requests[index].updated_at = now;
        state.reservations.push(MemoryUploadReservation {
            id: reservation_id.to_string(),
            request_id: request.id,
            owner_sub: request.owner_sub,
            size,
            recovery_lease: None,
            recovery_leased_at: None,
        });
        Ok(UploadReserve::Reserved)
    }

    async fn commit_request_upload(
        &self,
        reservation_id: &str,
        file: &FileRec,
        submission: &UploadSubmission,
    ) -> Result<bool, StoreError> {
        let _lifecycle = self
            .lifecycle_guard
            .lock()
            .expect("lifecycle guard poisoned");
        let mut state = self
            .request_state
            .lock()
            .expect("request state lock poisoned");
        let Some(reservation) = state
            .reservations
            .iter()
            .find(|reservation| reservation.id == reservation_id)
            .cloned()
        else {
            return Ok(false);
        };
        if reservation.recovery_lease.is_some() {
            return Ok(false);
        }
        if file.id != reservation.id
            || file.object_key != reservation.id
            || file.owner_sub != reservation.owner_sub
            || file.size != reservation.size
            || !file.is_effectively_live()
            || submission.request_id != reservation.request_id
            || submission.file_id != file.id
            || submission.name != file.name
            || submission.content_type != file.content_type
            || submission.size != file.size
        {
            return Ok(false);
        }
        if state
            .submissions
            .iter()
            .any(|item| item.id == submission.id || item.file_id == submission.file_id)
        {
            return Ok(false);
        }
        if !self
            .folders
            .lock()
            .expect("folders lock poisoned")
            .iter()
            .any(|folder| {
                file.folder_id.as_deref() == Some(folder.id.as_str())
                    && folder.owner_sub == file.owner_sub
                    && folder.is_effectively_live()
            })
        {
            return Ok(false);
        }
        let mut files = self.files.lock().expect("files lock poisoned");
        if files.iter().any(|existing| {
            existing.id == file.id
                || (file.share_token.is_some() && existing.share_token == file.share_token)
        }) {
            return Ok(false);
        }
        files.push(file.clone());
        state.submissions.push(submission.clone());
        state
            .reservations
            .retain(|reservation| reservation.id != reservation_id);
        Ok(true)
    }

    async fn release_request_upload(&self, reservation_id: &str) -> Result<bool, StoreError> {
        let mut state = self
            .request_state
            .lock()
            .expect("request state lock poisoned");
        let Some(index) = state
            .reservations
            .iter()
            .position(|reservation| reservation.id == reservation_id)
        else {
            return Ok(false);
        };
        if state.reservations[index].recovery_lease.is_some() {
            return Ok(false);
        }
        let reservation = state.reservations.remove(index);
        if let Some(request) = state
            .requests
            .iter_mut()
            .find(|request| request.id == reservation.request_id)
        {
            request.used_bytes = request.used_bytes.saturating_sub(reservation.size);
            request.used_files = request.used_files.saturating_sub(1);
        }
        Ok(true)
    }

    async fn claim_upload_recovery(
        &self,
        lease_id: &str,
        leased_at: i64,
        lease_expired_before: i64,
    ) -> Result<UploadRecoveryClaim, StoreError> {
        let mut state = self
            .request_state
            .lock()
            .expect("request state lock poisoned");
        if state.reservations.is_empty() {
            return Ok(UploadRecoveryClaim::Empty);
        }
        let held_by_other = state.reservations.iter().any(|reservation| {
            reservation
                .recovery_lease
                .as_deref()
                .is_some_and(|current| {
                    current != lease_id
                        && reservation
                            .recovery_leased_at
                            .is_none_or(|at| at > lease_expired_before)
                })
        });
        if held_by_other {
            return Ok(UploadRecoveryClaim::Busy);
        }
        for reservation in &mut state.reservations {
            let available = reservation.recovery_lease.as_deref() == Some(lease_id)
                || reservation.recovery_lease.is_none()
                || reservation
                    .recovery_leased_at
                    .is_some_and(|at| at <= lease_expired_before);
            if available {
                reservation.recovery_lease = Some(lease_id.to_string());
                reservation.recovery_leased_at = Some(leased_at);
            }
        }
        let claimed: Vec<_> = state
            .reservations
            .iter()
            .filter(|reservation| reservation.recovery_lease.as_deref() == Some(lease_id))
            .map(|reservation| UploadRecoveryItem {
                reservation_id: reservation.id.clone(),
                object_key: reservation.id.clone(),
            })
            .collect();
        Ok(UploadRecoveryClaim::Claimed(claimed))
    }

    async fn complete_upload_recovery(
        &self,
        reservation_id: &str,
        lease_id: &str,
    ) -> Result<bool, StoreError> {
        let mut state = self
            .request_state
            .lock()
            .expect("request state lock poisoned");
        let Some(index) = state.reservations.iter().position(|reservation| {
            reservation.id == reservation_id
                && reservation.recovery_lease.as_deref() == Some(lease_id)
        }) else {
            return Ok(false);
        };
        let reservation = state.reservations.remove(index);
        if let Some(request) = state
            .requests
            .iter_mut()
            .find(|request| request.id == reservation.request_id)
        {
            request.used_bytes = request.used_bytes.saturating_sub(reservation.size);
            request.used_files = request.used_files.saturating_sub(1);
        }
        Ok(true)
    }

    async fn abandon_upload_recovery(
        &self,
        reservation_id: &str,
        lease_id: &str,
    ) -> Result<bool, StoreError> {
        let mut state = self
            .request_state
            .lock()
            .expect("request state lock poisoned");
        let Some(reservation) = state.reservations.iter_mut().find(|reservation| {
            reservation.id == reservation_id
                && reservation.recovery_lease.as_deref() == Some(lease_id)
        }) else {
            return Ok(false);
        };
        reservation.recovery_lease = None;
        reservation.recovery_leased_at = None;
        Ok(true)
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
use sqlx::{Postgres, QueryBuilder, Row, Transaction};

fn push_library_cursor(
    query: &mut QueryBuilder<'_, Postgres>,
    cursor: &LibraryCursor,
    kind: LibraryItemKind,
) {
    use std::cmp::Ordering;

    match kind.rank().cmp(&cursor.kind.rank()) {
        Ordering::Less => {
            query
                .push(" AND updated_at <= ")
                .push_bind(cursor.updated_at);
        }
        Ordering::Greater => {
            query
                .push(" AND updated_at < ")
                .push_bind(cursor.updated_at);
        }
        Ordering::Equal => {
            query
                .push(" AND (updated_at < ")
                .push_bind(cursor.updated_at)
                .push(" OR (updated_at = ")
                .push_bind(cursor.updated_at)
                .push(" AND id < ")
                .push_bind(cursor.id.clone())
                .push("))");
        }
    }
}

const LIBRARY_FILE_TYPE_SQL: &str = "CASE \
    WHEN LOWER(content_type) LIKE 'image/%' THEN 'image' \
    WHEN LOWER(content_type) LIKE 'video/%' THEN 'video' \
    WHEN LOWER(content_type) LIKE 'audio/%' THEN 'audio' \
    WHEN LOWER(content_type) = 'application/pdf' THEN 'pdf' \
    WHEN LOWER(content_type) LIKE 'text/%' OR LOWER(content_type) IN (\
        'application/msword', \
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document', \
        'application/vnd.oasis.opendocument.text', 'application/rtf'\
    ) THEN 'document' \
    WHEN LOWER(content_type) LIKE '%zip%' OR LOWER(content_type) LIKE '%tar%' \
        OR LOWER(content_type) LIKE '%gzip%' OR LOWER(content_type) LIKE '%compress%' \
        OR LOWER(content_type) LIKE '%x-7z%' OR LOWER(content_type) LIKE '%x-rar%' \
        THEN 'archive' \
    ELSE 'other' END";

fn push_library_file_type(query: &mut QueryBuilder<'_, Postgres>, filter: LibraryType) {
    match filter {
        LibraryType::All => {}
        LibraryType::Folder => unreachable!("folder filter skips the files query"),
        selected => {
            query
                .push(" AND (")
                .push(LIBRARY_FILE_TYPE_SQL)
                .push(") = ")
                .push_bind(selected.slug());
        }
    };
}

/// Column list shared by every SELECT, so the row decoder stays in lock-step with the query.
const COLS: &str = "id, owner_sub, name, content_type, size, bucket, object_key, share_token, \
     created_at, updated_at, expires_at, share_password_hash, folder_id, trashed_at, \
     trash_entry_id, trash_ancestor_id, view_count";

/// Column list shared by every folder SELECT.
const FOLDER_COLS: &str =
    "id, owner_sub, parent_id, name, created_at, updated_at, share_token, expires_at, share_password_hash, \
     upload_token, trashed_at, trash_entry_id, trash_ancestor_id";

/// Column list shared by every version SELECT.
const VERSION_COLS: &str = "id, file_id, object_key, size, content_type, created_at";

const UPLOAD_REQUEST_COLS: &str = "id, owner_sub, folder_id, token, title, description, status, \
     expires_at, max_file_bytes, max_total_bytes, max_files, used_bytes, used_files, allowed_types, \
     created_at, updated_at";

/// Keep at most this many versions per file; older snapshots are pruned (blobs deleted).
pub const MAX_VERSIONS_PER_FILE: i64 = 10;

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

    async fn lock_owner_storage_guard_tx(
        tx: &mut Transaction<'_, Postgres>,
        owner_sub: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO owner_storage_guards (owner_sub) VALUES ($1) ON CONFLICT DO NOTHING",
        )
        .bind(owner_sub)
        .execute(&mut **tx)
        .await?;
        sqlx::query("SELECT owner_sub FROM owner_storage_guards WHERE owner_sub = $1 FOR UPDATE")
            .bind(owner_sub)
            .fetch_one(&mut **tx)
            .await?;
        Ok(())
    }

    /// Permanent per-key mutex. Rows intentionally survive authority deletion so a key can never
    /// suffer an ABA window between independent metadata tables. The row is only a lock sentinel;
    /// the authoritative collision decision still comes from the live tables below the lock.
    async fn lock_blob_key_guard_tx(
        tx: &mut Transaction<'_, Postgres>,
        object_key: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO blob_key_guards (object_key) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(object_key)
            .execute(&mut **tx)
            .await?;
        sqlx::query("SELECT object_key FROM blob_key_guards WHERE object_key = $1 FOR UPDATE")
            .bind(object_key)
            .fetch_one(&mut **tx)
            .await?;
        Ok(())
    }

    async fn owner_usage_with_pending_tx(
        tx: &mut Transaction<'_, Postgres>,
        owner_sub: &str,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query(
            "SELECT CAST(\
                 COALESCE((SELECT SUM(size) FROM files WHERE owner_sub = $1), 0) + \
                 COALESCE((SELECT SUM(v.size) FROM file_versions v \
                           JOIN files f ON f.id = v.file_id WHERE f.owner_sub = $1), 0) + \
                 COALESCE((SELECT SUM(size) FROM upload_reservations WHERE owner_sub = $1), 0) + \
                 COALESCE((SELECT SUM(size) FROM owner_blob_write_intents \
                           WHERE owner_sub = $1 AND write_kind <> 'thumbnail'), 0) \
                 AS BIGINT) AS bytes",
        )
        .bind(owner_sub)
        .fetch_one(&mut **tx)
        .await?
        .try_get("bytes")
    }

    async fn enqueue_blob_delete_tx(
        tx: &mut Transaction<'_, Postgres>,
        object_key: &str,
        enqueued_at: i64,
        reason: &str,
    ) -> Result<(), sqlx::Error> {
        Self::lock_blob_key_guard_tx(tx, object_key).await?;
        sqlx::query(
            "INSERT INTO blob_delete_queue \
                 (object_key, enqueued_at, next_attempt_at, reason) \
             VALUES ($1, $2, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(object_key)
        .bind(enqueued_at)
        .bind(reason)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    fn owner_blob_write_from_row(
        row: &sqlx::postgres::PgRow,
    ) -> Result<OwnerBlobWriteIntent, sqlx::Error> {
        Ok(OwnerBlobWriteIntent {
            object_key: row.try_get("object_key")?,
            owner_sub: row.try_get("owner_sub")?,
            size: row.try_get("size")?,
            kind: row.try_get("write_kind")?,
            file_id: row.try_get("file_id")?,
            folder_id: row.try_get("folder_id")?,
            expected_object_key: row.try_get("expected_object_key")?,
            created_at: row.try_get("created_at")?,
            attempts: row.try_get("attempts")?,
        })
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
        // Owner-library activity time. DEFAULT 0 keeps a rolled-back older binary able to insert;
        // every current boot backfills those rows from immutable creation time before reading them.
        sqlx::query("ALTER TABLE files ADD COLUMN IF NOT EXISTS updated_at BIGINT DEFAULT 0")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "UPDATE files SET updated_at = created_at WHERE updated_at IS NULL OR updated_at = 0",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("ALTER TABLE files ALTER COLUMN updated_at SET NOT NULL")
            .execute(&self.pool)
            .await?;
        // Folders (albums). Additive + idempotent; pre-existing files default to NULL folder_id
        // (unfiled), preserving the flat all-files view. Portable standard SQL only.
        sqlx::query("ALTER TABLE files ADD COLUMN IF NOT EXISTS folder_id TEXT")
            .execute(&self.pool)
            .await?;
        // Soft-delete marker. Live rows are `0`; trashed rows keep their blob and continue counting
        // toward usage until purged. Additive + idempotent; existing rows become live.
        sqlx::query("ALTER TABLE files ADD COLUMN IF NOT EXISTS trashed_at BIGINT DEFAULT 0")
            .execute(&self.pool)
            .await?;
        sqlx::query("ALTER TABLE files ADD COLUMN IF NOT EXISTS trash_entry_id TEXT")
            .execute(&self.pool)
            .await?;
        sqlx::query("ALTER TABLE files ADD COLUMN IF NOT EXISTS trash_ancestor_id TEXT")
            .execute(&self.pool)
            .await?;
        // Public landing-page opens. Direct `/s/{token}` blob fetches intentionally do not update
        // this counter, preserving hotlink/backward-compatible byte behavior.
        sqlx::query("ALTER TABLE files ADD COLUMN IF NOT EXISTS view_count BIGINT DEFAULT 0")
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
        sqlx::query("ALTER TABLE folders ADD COLUMN IF NOT EXISTS updated_at BIGINT DEFAULT 0")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "UPDATE folders SET updated_at = created_at WHERE updated_at IS NULL OR updated_at = 0",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("ALTER TABLE folders ALTER COLUMN updated_at SET NOT NULL")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_folders_owner_name \
             ON folders (owner_sub, name)",
        )
        .execute(&self.pool)
        .await?;
        // Deepen folders into a TREE: a nullable parent (NULL = a root folder). Additive +
        // idempotent; pre-existing folders default to NULL parent (they become root folders),
        // preserving today's flat behavior. Portable standard SQL only.
        sqlx::query("ALTER TABLE folders ADD COLUMN IF NOT EXISTS parent_id TEXT")
            .execute(&self.pool)
            .await?;
        // Folder-level public share link (mirrors the file share columns). Additive + idempotent;
        // pre-existing folders default to NULL (no public surface). Portable standard SQL only.
        sqlx::query("ALTER TABLE folders ADD COLUMN IF NOT EXISTS share_token TEXT")
            .execute(&self.pool)
            .await?;
        sqlx::query("ALTER TABLE folders ADD COLUMN IF NOT EXISTS expires_at BIGINT")
            .execute(&self.pool)
            .await?;
        sqlx::query("ALTER TABLE folders ADD COLUMN IF NOT EXISTS share_password_hash TEXT")
            .execute(&self.pool)
            .await?;
        // Public upload-inbox token (`/u/{token}`), separate from folder share links so request-file
        // visitors can upload without listing/downloading existing files.
        sqlx::query("ALTER TABLE folders ADD COLUMN IF NOT EXISTS upload_token TEXT")
            .execute(&self.pool)
            .await?;
        // Unified Trash is a forward-only, single-active migration: an older binary does not know
        // folder ancestor scope and must never run concurrently after these columns are in use.
        sqlx::query("ALTER TABLE folders ADD COLUMN IF NOT EXISTS trashed_at BIGINT DEFAULT 0")
            .execute(&self.pool)
            .await?;
        sqlx::query("ALTER TABLE folders ADD COLUMN IF NOT EXISTS trash_entry_id TEXT")
            .execute(&self.pool)
            .await?;
        sqlx::query("ALTER TABLE folders ADD COLUMN IF NOT EXISTS trash_ancestor_id TEXT")
            .execute(&self.pool)
            .await?;
        sqlx::query("UPDATE folders SET trashed_at = 0 WHERE trashed_at IS NULL")
            .execute(&self.pool)
            .await?;
        sqlx::query("ALTER TABLE folders ALTER COLUMN trashed_at SET NOT NULL")
            .execute(&self.pool)
            .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS trash_entries (\
                 id TEXT PRIMARY KEY, \
                 owner_sub TEXT NOT NULL, \
                 item_kind TEXT NOT NULL, \
                 item_id TEXT NOT NULL, \
                 trashed_at BIGINT NOT NULL, \
                 purge_after BIGINT NOT NULL, \
                 recovery_lease TEXT, \
                 recovery_leased_at BIGINT, \
                 UNIQUE(owner_sub, item_kind, item_id)\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_trash_owner_order \
             ON trash_entries (owner_sub, trashed_at DESC, item_kind DESC, item_id DESC)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_trash_expiry \
             ON trash_entries (purge_after, id)",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS blob_delete_queue (\
                 object_key TEXT PRIMARY KEY, \
                 enqueued_at BIGINT NOT NULL, \
                 attempts BIGINT NOT NULL DEFAULT 0, \
                 next_attempt_at BIGINT NOT NULL, \
                 recovery_lease TEXT, \
                 recovery_leased_at BIGINT, \
                 reason TEXT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_blob_delete_due \
             ON blob_delete_queue (next_attempt_at, enqueued_at, object_key)",
        )
        .execute(&self.pool)
        .await?;

        // Owner uploads and derived thumbnails persist cleanup authority before touching Cairn.
        // Finalization consumes this row in the same transaction as the metadata CAS; a crash on
        // either side of `put` therefore leaves an idempotently recoverable object key.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS owner_blob_write_intents (\
                 object_key TEXT PRIMARY KEY, \
                 owner_sub TEXT NOT NULL, \
                 size BIGINT NOT NULL, \
                 write_kind TEXT NOT NULL, \
                 file_id TEXT NOT NULL, \
                 folder_id TEXT, \
                 expected_object_key TEXT, \
                 created_at BIGINT NOT NULL, \
                 attempts BIGINT NOT NULL DEFAULT 0, \
                 next_attempt_at BIGINT NOT NULL, \
                 recovery_lease TEXT, \
                 recovery_leased_at BIGINT\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_owner_blob_write_due \
             ON owner_blob_write_intents (next_attempt_at, created_at, object_key)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_owner_blob_write_owner_kind \
             ON owner_blob_write_intents (owner_sub, write_kind)",
        )
        .execute(&self.pool)
        .await?;

        // Legacy file Trash receives a fresh full retention window from migration time. Lock and
        // materialize every source before binding it to authority: a deterministic id occupied by a
        // different row is corruption, while a partial prior migration may already have created the
        // exact `(owner, file, item)` row under a different id. Both discovery and source update live
        // in one transaction, so a failed collision never leaves a newly-bound file behind.
        let migration_now = mutation_time();
        let legacy_purge_after = migration_now.saturating_add(DEFAULT_TRASH_RETENTION_SECS);
        let mut trash_tx = self.pool.begin().await?;
        let legacy_rows = sqlx::query(
            "SELECT id, owner_sub, trashed_at FROM files \
             WHERE trashed_at <> 0 AND trash_entry_id IS NULL ORDER BY id ASC FOR UPDATE",
        )
        .fetch_all(&mut *trash_tx)
        .await?;
        for row in legacy_rows {
            let file_id: String = row.try_get("id")?;
            let owner_sub: String = row.try_get("owner_sub")?;
            let trashed_at: i64 = row.try_get("trashed_at")?;
            let exact = sqlx::query(
                "SELECT id FROM trash_entries WHERE owner_sub = $1 AND item_kind = 'file' \
                 AND item_id = $2 FOR UPDATE",
            )
            .bind(&owner_sub)
            .bind(&file_id)
            .fetch_optional(&mut *trash_tx)
            .await?;
            let entry_id = if let Some(exact) = exact {
                let entry_id: String = exact.try_get("id")?;
                sqlx::query(
                    "UPDATE trash_entries SET purge_after = CASE WHEN purge_after < $1 THEN $1 \
                     ELSE purge_after END WHERE id = $2 AND owner_sub = $3 \
                     AND item_kind = 'file' AND item_id = $4",
                )
                .bind(legacy_purge_after)
                .bind(&entry_id)
                .bind(&owner_sub)
                .bind(&file_id)
                .execute(&mut *trash_tx)
                .await?;
                entry_id
            } else {
                let deterministic_id = format!("legacy-file-{file_id}");
                if sqlx::query("SELECT 1 FROM trash_entries WHERE id = $1 FOR UPDATE")
                    .bind(&deterministic_id)
                    .fetch_optional(&mut *trash_tx)
                    .await?
                    .is_some()
                {
                    trash_tx.rollback().await?;
                    return Err(sqlx::Error::Protocol(format!(
                        "legacy Trash id conflict for file {file_id}"
                    )));
                }
                let inserted = sqlx::query(
                    "INSERT INTO trash_entries \
                         (id, owner_sub, item_kind, item_id, trashed_at, purge_after) \
                     VALUES ($1, $2, 'file', $3, $4, $5) ON CONFLICT DO NOTHING",
                )
                .bind(&deterministic_id)
                .bind(&owner_sub)
                .bind(&file_id)
                .bind(trashed_at)
                .bind(legacy_purge_after)
                .execute(&mut *trash_tx)
                .await?;
                if inserted.rows_affected() != 1 {
                    trash_tx.rollback().await?;
                    return Err(sqlx::Error::Protocol(format!(
                        "legacy Trash authority conflict for file {file_id}"
                    )));
                }
                deterministic_id
            };
            let bound = sqlx::query(
                "UPDATE files SET trash_entry_id = $1 WHERE id = $2 AND owner_sub = $3 \
                 AND trashed_at = $4 AND trash_entry_id IS NULL",
            )
            .bind(&entry_id)
            .bind(&file_id)
            .bind(&owner_sub)
            .bind(trashed_at)
            .execute(&mut *trash_tx)
            .await?;
            if bound.rows_affected() != 1 {
                trash_tx.rollback().await?;
                return Err(sqlx::Error::Protocol(format!(
                    "legacy Trash source changed for file {file_id}"
                )));
            }
        }
        trash_tx.commit().await?;
        // The folder-share token gets its own unique index for the `/s/folder/{token}` lookup (NULLs are
        // distinct, so many revoked/never-shared folders coexist).
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_folders_share_token \
             ON folders (share_token)",
        )
        .execute(&self.pool)
        .await?;
        // Backs per-level child-folder lookups (owner + parent).
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_folders_upload_token \
             ON folders (upload_token)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_folders_owner_parent \
             ON folders (owner_sub, parent_id)",
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
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_files_owner_updated_live \
             ON files (owner_sub, updated_at DESC, id DESC) WHERE trashed_at = 0",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_files_owner_shared_updated \
             ON files (owner_sub, updated_at DESC, id DESC) \
             WHERE trashed_at = 0 AND share_token IS NOT NULL",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_folders_owner_updated \
             ON folders (owner_sub, updated_at DESC, id DESC)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_folders_owner_shared_updated \
             ON folders (owner_sub, updated_at DESC, id DESC) WHERE share_token IS NOT NULL",
        )
        .execute(&self.pool)
        .await?;
        // Retained blob snapshots: a re-upload of the same name in the same folder keeps the prior
        // blob here instead of overwriting it. `content_type` is stored so a restore swaps the file
        // back to the snapshot's type. Additive + idempotent; portable standard SQL only.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS file_versions (\
                 id TEXT PRIMARY KEY, \
                 file_id TEXT NOT NULL, \
                 object_key TEXT NOT NULL, \
                 size BIGINT NOT NULL, \
                 content_type TEXT NOT NULL, \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_file_versions_file \
             ON file_versions (file_id, created_at)",
        )
        .execute(&self.pool)
        .await?;
        // Per-owner storage quota overrides. A missing row means "use the configured default"
        // (APERTURE_DEFAULT_QUOTA_BYTES); 0 means an explicit unlimited override. Additive +
        // idempotent; portable standard SQL only.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS owner_quotas (\
                 owner_sub TEXT PRIMARY KEY, \
                 quota_bytes BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Per-file comments. `author_sub` is the authenticated subject; bodies are escaped only at
        // render time so the stored text stays literal.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS file_comments (\
                 id TEXT PRIMARY KEY, \
                 file_id TEXT NOT NULL, \
                 author_sub TEXT NOT NULL, \
                 body TEXT NOT NULL, \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_file_comments_file \
             ON file_comments (file_id, created_at)",
        )
        .execute(&self.pool)
        .await?;

        // Product-level upload requests. Limits are stored on the capability itself so every
        // anonymous write is bounded even when the owner's global quota is intentionally unlimited.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS upload_requests (\
                 id TEXT PRIMARY KEY, \
                 owner_sub TEXT NOT NULL, \
                 folder_id TEXT NOT NULL, \
                 token TEXT NOT NULL UNIQUE, \
                 title TEXT NOT NULL, \
                 description TEXT NOT NULL, \
                 status TEXT NOT NULL, \
                 expires_at BIGINT, \
                 max_file_bytes BIGINT NOT NULL, \
                 max_total_bytes BIGINT NOT NULL, \
                 max_files BIGINT NOT NULL, \
                 used_bytes BIGINT NOT NULL, \
                 used_files BIGINT NOT NULL, \
                 allowed_types TEXT NOT NULL, \
                 created_at BIGINT NOT NULL, \
                 updated_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_upload_requests_owner_updated \
             ON upload_requests (owner_sub, updated_at)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_upload_requests_folder \
             ON upload_requests (owner_sub, folder_id)",
        )
        .execute(&self.pool)
        .await?;

        // Immutable owner receipts. Snapshotting display metadata keeps request history useful even
        // after the destination file is moved, renamed or purged.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS upload_submissions (\
                 id TEXT PRIMARY KEY, \
                 request_id TEXT NOT NULL, \
                 file_id TEXT NOT NULL UNIQUE, \
                 name TEXT NOT NULL, \
                 content_type TEXT NOT NULL, \
                 size BIGINT NOT NULL, \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_upload_submissions_request \
             ON upload_submissions (request_id, created_at)",
        )
        .execute(&self.pool)
        .await?;

        // Reservations bridge Postgres and Cairn: budgets are claimed transactionally before the
        // blob write, committed only after the write, and released on every failure path.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS upload_reservations (\
                 id TEXT PRIMARY KEY, \
                 request_id TEXT NOT NULL, \
                 owner_sub TEXT NOT NULL, \
                 size BIGINT NOT NULL, \
                 created_at BIGINT NOT NULL, \
                 recovery_lease TEXT, \
                 recovery_leased_at BIGINT\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("ALTER TABLE upload_reservations ADD COLUMN IF NOT EXISTS recovery_lease TEXT")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "ALTER TABLE upload_reservations ADD COLUMN IF NOT EXISTS recovery_leased_at BIGINT",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_upload_reservations_owner \
             ON upload_reservations (owner_sub)",
        )
        .execute(&self.pool)
        .await?;
        // One lockable row per owner serializes quota decisions across that owner's request rooms.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS owner_storage_guards (\
                 owner_sub TEXT PRIMARY KEY\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Cross-table object-key authority uses a permanent row mutex. Random keys make this
        // append-only table practical, and retaining rows closes delete/reuse ABA windows.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS blob_key_guards (\
                 object_key TEXT PRIMARY KEY\
             )",
        )
        .execute(&self.pool)
        .await?;

        // Preserve every legacy `/u/{folders.upload_token}` URL. Lock and materialize the source
        // rows before inserting anything: without this lock, a concurrent legacy revoke can clear
        // `upload_token` between INSERT and validation, make validation skip the source, and leave
        // the just-created request live. Scriptoria migrations run during a quiescent single-active
        // boot; the row locks additionally make an accidental current-version writer serialize
        // behind this transaction instead of producing a torn backfill.
        let mut legacy_tx = self.pool.begin().await?;
        let source_rows = sqlx::query(
            "SELECT id, owner_sub, upload_token, name, created_at \
             FROM folders WHERE upload_token IS NOT NULL \
             ORDER BY id ASC FOR UPDATE",
        )
        .fetch_all(&mut *legacy_tx)
        .await?;
        let mut legacy_sources = Vec::with_capacity(source_rows.len());
        for row in source_rows {
            legacy_sources.push((
                row.try_get::<String, _>("id")?,
                row.try_get::<String, _>("owner_sub")?,
                row.try_get::<String, _>("upload_token")?,
                row.try_get::<String, _>("name")?,
                row.try_get::<i64, _>("created_at")?,
            ));
        }

        for (folder_id, owner_sub, token, name, created_at) in &legacy_sources {
            let request_id = format!("legacy_{folder_id}");
            sqlx::query(
                "INSERT INTO upload_requests \
                     (id, owner_sub, folder_id, token, title, description, status, expires_at, \
                      max_file_bytes, max_total_bytes, max_files, used_bytes, used_files, \
                      allowed_types, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, '', 'open', NULL, $6, $7, $8, 0, 0, $9, $10, $10) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(&request_id)
            .bind(owner_sub)
            .bind(folder_id)
            .bind(token)
            .bind(format!("{name} uploads"))
            .bind(DEFAULT_REQUEST_MAX_FILE_BYTES)
            .bind(DEFAULT_REQUEST_MAX_TOTAL_BYTES)
            .bind(DEFAULT_REQUEST_MAX_FILES)
            .bind(DEFAULT_REQUEST_ALLOWED_TYPES)
            .bind(created_at)
            .execute(&mut *legacy_tx)
            .await?;

            let exact = sqlx::query(
                "SELECT 1 FROM upload_requests \
                 WHERE id = $1 AND owner_sub = $2 AND folder_id = $3 AND token = $4",
            )
            .bind(&request_id)
            .bind(owner_sub)
            .bind(folder_id)
            .bind(token)
            .fetch_optional(&mut *legacy_tx)
            .await?
            .is_some();
            if !exact {
                let conflict_id = folder_id.clone();
                legacy_tx.rollback().await?;
                return Err(sqlx::Error::Protocol(format!(
                    "legacy upload request conflict for folder {conflict_id}"
                )));
            }
        }

        // The exact request rows are now authoritative. Compare every clear against the locked
        // snapshot; a missing row or changed token is a migration failure, never a reason to skip.
        for (folder_id, owner_sub, token, _, _) in &legacy_sources {
            let cleared = sqlx::query(
                "UPDATE folders SET upload_token = NULL \
                 WHERE id = $1 AND owner_sub = $2 AND upload_token = $3",
            )
            .bind(folder_id)
            .bind(owner_sub)
            .bind(token)
            .execute(&mut *legacy_tx)
            .await?;
            if cleared.rows_affected() != 1 {
                let conflict_id = folder_id.clone();
                legacy_tx.rollback().await?;
                return Err(sqlx::Error::Protocol(format!(
                    "legacy upload source changed for folder {conflict_id}"
                )));
            }
        }
        legacy_tx.commit().await?;
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
            updated_at: row.try_get("updated_at")?,
            expires_at: row.try_get("expires_at")?,
            share_password_hash: row.try_get("share_password_hash")?,
            folder_id: row.try_get("folder_id")?,
            trashed_at: row.try_get("trashed_at")?,
            trash_entry_id: row.try_get("trash_entry_id")?,
            trash_ancestor_id: row.try_get("trash_ancestor_id")?,
            view_count: row.try_get("view_count")?,
        })
    }

    fn folder_from_row(row: &sqlx::postgres::PgRow) -> Result<FolderRec, sqlx::Error> {
        Ok(FolderRec {
            id: row.try_get("id")?,
            owner_sub: row.try_get("owner_sub")?,
            parent_id: row.try_get("parent_id")?,
            name: row.try_get("name")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
            share_token: row.try_get("share_token")?,
            expires_at: row.try_get("expires_at")?,
            share_password_hash: row.try_get("share_password_hash")?,
            upload_token: row.try_get("upload_token")?,
            trashed_at: row.try_get("trashed_at")?,
            trash_entry_id: row.try_get("trash_entry_id")?,
            trash_ancestor_id: row.try_get("trash_ancestor_id")?,
        })
    }

    fn trash_entry_from_row(row: &sqlx::postgres::PgRow) -> Result<TrashEntry, sqlx::Error> {
        let kind: String = row.try_get("item_kind")?;
        let kind = match kind.as_str() {
            "file" => LibraryItemKind::File,
            "folder" => LibraryItemKind::Folder,
            other => {
                return Err(sqlx::Error::Decode(
                    format!("unknown trash item kind {other}").into(),
                ))
            }
        };
        Ok(TrashEntry {
            id: row.try_get("id")?,
            owner_sub: row.try_get("owner_sub")?,
            kind,
            item_id: row.try_get("item_id")?,
            trashed_at: row.try_get("trashed_at")?,
            purge_after: row.try_get("purge_after")?,
            recovery_lease: row.try_get("recovery_lease")?,
            recovery_leased_at: row.try_get("recovery_leased_at")?,
        })
    }

    fn version_from_row(row: &sqlx::postgres::PgRow) -> Result<VersionRec, sqlx::Error> {
        Ok(VersionRec {
            id: row.try_get("id")?,
            file_id: row.try_get("file_id")?,
            object_key: row.try_get("object_key")?,
            size: row.try_get("size")?,
            content_type: row.try_get("content_type")?,
            created_at: row.try_get("created_at")?,
        })
    }

    fn comment_from_row(row: &sqlx::postgres::PgRow) -> Result<FileComment, sqlx::Error> {
        Ok(FileComment {
            id: row.try_get("id")?,
            file_id: row.try_get("file_id")?,
            author_sub: row.try_get("author_sub")?,
            body: row.try_get("body")?,
            created_at: row.try_get("created_at")?,
        })
    }

    fn upload_request_from_row(
        row: &sqlx::postgres::PgRow,
    ) -> Result<UploadRequestRec, sqlx::Error> {
        Ok(UploadRequestRec {
            id: row.try_get("id")?,
            owner_sub: row.try_get("owner_sub")?,
            folder_id: row.try_get("folder_id")?,
            token: row.try_get("token")?,
            title: row.try_get("title")?,
            description: row.try_get("description")?,
            status: row.try_get("status")?,
            expires_at: row.try_get("expires_at")?,
            max_file_bytes: row.try_get("max_file_bytes")?,
            max_total_bytes: row.try_get("max_total_bytes")?,
            max_files: row.try_get("max_files")?,
            used_bytes: row.try_get("used_bytes")?,
            used_files: row.try_get("used_files")?,
            allowed_types: row.try_get("allowed_types")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }

    fn upload_submission_from_row(
        row: &sqlx::postgres::PgRow,
    ) -> Result<UploadSubmission, sqlx::Error> {
        Ok(UploadSubmission {
            id: row.try_get("id")?,
            request_id: row.try_get("request_id")?,
            file_id: row.try_get("file_id")?,
            name: row.try_get("name")?,
            content_type: row.try_get("content_type")?,
            size: row.try_get("size")?,
            created_at: row.try_get("created_at")?,
        })
    }

    async fn create_async(&self, file: &FileRec) -> Result<bool, sqlx::Error> {
        // No conflict target => any unique violation (id OR share_token) yields 0 rows affected,
        // signaling the handler to retry with fresh values. Single, race-free insert path.
        let result = sqlx::query(
            "INSERT INTO files \
                 (id, owner_sub, name, content_type, size, bucket, object_key, share_token, \
                  created_at, updated_at, expires_at, share_password_hash, folder_id, trashed_at, \
                  trash_entry_id, trash_ancestor_id, view_count) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17) \
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
        .bind(file.updated_at)
        .bind(file.expires_at)
        .bind(&file.share_password_hash)
        .bind(&file.folder_id)
        .bind(file.trashed_at)
        .bind(&file.trash_entry_id)
        .bind(&file.trash_ancestor_id)
        .bind(file.view_count)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn reserve_owner_blob_write_async(
        &self,
        intent: &OwnerBlobWriteIntent,
        owner_quota: Option<i64>,
    ) -> Result<OwnerBlobCommit, sqlx::Error> {
        if intent.object_key.is_empty()
            || intent.owner_sub.is_empty()
            || intent.file_id.is_empty()
            || intent.size < 0
            || !matches!(
                intent.kind.as_str(),
                OWNER_WRITE_FRESH | OWNER_WRITE_REUPLOAD | OWNER_WRITE_THUMBNAIL
            )
        {
            return Ok(OwnerBlobCommit::Conflict);
        }
        let mut tx = self.pool.begin().await?;
        Self::lock_owner_storage_guard_tx(&mut tx, &intent.owner_sub).await?;
        let authority_ok = match intent.kind.as_str() {
            OWNER_WRITE_FRESH => {
                let folder_ok = if let Some(folder_id) = intent.folder_id.as_deref() {
                    sqlx::query(
                        "SELECT 1 FROM folders WHERE id = $1 AND owner_sub = $2 \
                         AND trashed_at = 0 AND trash_entry_id IS NULL \
                         AND trash_ancestor_id IS NULL FOR UPDATE",
                    )
                    .bind(folder_id)
                    .bind(&intent.owner_sub)
                    .fetch_optional(&mut *tx)
                    .await?
                    .is_some()
                } else {
                    true
                };
                folder_ok
                    && intent.expected_object_key.is_none()
                    && intent.object_key == intent.file_id
                    && sqlx::query("SELECT 1 FROM files WHERE id = $1 FOR UPDATE")
                        .bind(&intent.file_id)
                        .fetch_optional(&mut *tx)
                        .await?
                        .is_none()
            }
            OWNER_WRITE_REUPLOAD | OWNER_WRITE_THUMBNAIL => {
                let Some(expected) = intent.expected_object_key.as_deref() else {
                    tx.rollback().await?;
                    return Ok(OwnerBlobCommit::Conflict);
                };
                let valid = sqlx::query(
                    "SELECT 1 FROM files WHERE id = $1 AND owner_sub = $2 AND object_key = $3 \
                     AND trashed_at = 0 AND trash_entry_id IS NULL \
                     AND trash_ancestor_id IS NULL FOR UPDATE",
                )
                .bind(&intent.file_id)
                .bind(&intent.owner_sub)
                .bind(expected)
                .fetch_optional(&mut *tx)
                .await?
                .is_some();
                valid
                    && (intent.kind != OWNER_WRITE_THUMBNAIL
                        || intent.object_key == format!("{expected}.thumb"))
            }
            _ => false,
        };
        if !authority_ok {
            tx.rollback().await?;
            return Ok(OwnerBlobCommit::Conflict);
        }
        // Metadata authority is locked before the global key sentinel. Purge follows the same
        // metadata -> key order, so a random cross-owner id collision cannot form an ABBA cycle.
        Self::lock_blob_key_guard_tx(&mut tx, &intent.object_key).await?;
        let collision = sqlx::query(
            "SELECT 1 WHERE \
                 EXISTS (SELECT 1 FROM owner_blob_write_intents WHERE object_key = $1) OR \
                 EXISTS (SELECT 1 FROM upload_reservations WHERE id = $1) OR \
                 EXISTS (SELECT 1 FROM files WHERE object_key = $1) OR \
                 EXISTS (SELECT 1 FROM file_versions WHERE object_key = $1) OR \
                 EXISTS (SELECT 1 FROM blob_delete_queue WHERE object_key = $1)",
        )
        .bind(&intent.object_key)
        .fetch_optional(&mut *tx)
        .await?
        .is_some();
        if collision {
            tx.rollback().await?;
            return Ok(OwnerBlobCommit::Collision);
        }
        if intent.kind != OWNER_WRITE_THUMBNAIL {
            let used = Self::owner_usage_with_pending_tx(&mut tx, &intent.owner_sub).await?;
            if owner_quota.is_some_and(|quota| used.saturating_add(intent.size) > quota) {
                tx.rollback().await?;
                return Ok(OwnerBlobCommit::QuotaExceeded);
            }
        }
        let inserted = sqlx::query(
            "INSERT INTO owner_blob_write_intents \
                 (object_key, owner_sub, size, write_kind, file_id, folder_id, \
                  expected_object_key, created_at, next_attempt_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT DO NOTHING",
        )
        .bind(&intent.object_key)
        .bind(&intent.owner_sub)
        .bind(intent.size)
        .bind(&intent.kind)
        .bind(&intent.file_id)
        .bind(&intent.folder_id)
        .bind(&intent.expected_object_key)
        .bind(intent.created_at)
        .bind(intent.created_at)
        .execute(&mut *tx)
        .await?;
        if inserted.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(OwnerBlobCommit::Collision);
        }
        tx.commit().await?;
        Ok(OwnerBlobCommit::Applied)
    }

    async fn commit_owner_upload_async(
        &self,
        file: &FileRec,
        owner_quota: Option<i64>,
    ) -> Result<OwnerBlobCommit, sqlx::Error> {
        if file.object_key != file.id || !file.is_effectively_live() {
            return Ok(OwnerBlobCommit::Conflict);
        }
        let mut tx = self.pool.begin().await?;
        Self::lock_owner_storage_guard_tx(&mut tx, &file.owner_sub).await?;
        let intent = sqlx::query(
            "SELECT object_key, owner_sub, size, write_kind, file_id, folder_id, \
                    expected_object_key, created_at, attempts \
             FROM owner_blob_write_intents WHERE object_key = $1 AND recovery_lease IS NULL \
             FOR UPDATE",
        )
        .bind(&file.object_key)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(intent) = intent else {
            tx.rollback().await?;
            return Ok(OwnerBlobCommit::Conflict);
        };
        let intent = Self::owner_blob_write_from_row(&intent)?;
        if intent.owner_sub != file.owner_sub
            || intent.file_id != file.id
            || intent.folder_id != file.folder_id
            || intent.size != file.size
            || intent.kind != OWNER_WRITE_FRESH
            || intent.expected_object_key.is_some()
        {
            tx.rollback().await?;
            return Ok(OwnerBlobCommit::Conflict);
        }
        if let Some(folder_id) = file.folder_id.as_deref() {
            if sqlx::query(
                "SELECT 1 FROM folders WHERE id = $1 AND owner_sub = $2 AND trashed_at = 0 \
                 AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL FOR UPDATE",
            )
            .bind(folder_id)
            .bind(&file.owner_sub)
            .fetch_optional(&mut *tx)
            .await?
            .is_none()
            {
                tx.rollback().await?;
                return Ok(OwnerBlobCommit::Conflict);
            }
        }
        let used = Self::owner_usage_with_pending_tx(&mut tx, &file.owner_sub).await?;
        if owner_quota.is_some_and(|quota| used > quota) {
            tx.rollback().await?;
            return Ok(OwnerBlobCommit::QuotaExceeded);
        }
        let inserted = sqlx::query(
            "INSERT INTO files \
                 (id, owner_sub, name, content_type, size, bucket, object_key, share_token, \
                  created_at, updated_at, expires_at, share_password_hash, folder_id, trashed_at, \
                  trash_entry_id, trash_ancestor_id, view_count) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17) \
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
        .bind(file.updated_at)
        .bind(file.expires_at)
        .bind(&file.share_password_hash)
        .bind(&file.folder_id)
        .bind(file.trashed_at)
        .bind(&file.trash_entry_id)
        .bind(&file.trash_ancestor_id)
        .bind(file.view_count)
        .execute(&mut *tx)
        .await?;
        if inserted.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(OwnerBlobCommit::Collision);
        }
        let consumed = sqlx::query(
            "DELETE FROM owner_blob_write_intents WHERE object_key = $1 \
             AND owner_sub = $2 AND write_kind = 'fresh' AND recovery_lease IS NULL",
        )
        .bind(&file.object_key)
        .bind(&file.owner_sub)
        .execute(&mut *tx)
        .await?;
        if consumed.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(OwnerBlobCommit::Conflict);
        }
        tx.commit().await?;
        Ok(OwnerBlobCommit::Applied)
    }

    async fn commit_owner_reupload_async(
        &self,
        input: OwnerReuploadInput<'_>,
    ) -> Result<OwnerBlobCommit, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        Self::lock_owner_storage_guard_tx(&mut tx, input.owner_sub).await?;
        let intent = sqlx::query(
            "SELECT object_key, owner_sub, size, write_kind, file_id, folder_id, \
                    expected_object_key, created_at, attempts \
             FROM owner_blob_write_intents WHERE object_key = $1 AND recovery_lease IS NULL \
             FOR UPDATE",
        )
        .bind(input.new_object_key)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(intent) = intent else {
            tx.rollback().await?;
            return Ok(OwnerBlobCommit::Conflict);
        };
        let intent = Self::owner_blob_write_from_row(&intent)?;
        if intent.owner_sub != input.owner_sub
            || intent.file_id != input.file_id
            || intent.size != input.new_size
            || intent.kind != OWNER_WRITE_REUPLOAD
            || intent.expected_object_key.as_deref() != Some(input.expected_object_key)
        {
            tx.rollback().await?;
            return Ok(OwnerBlobCommit::Conflict);
        }
        let current_row = sqlx::query(&format!(
            "SELECT {COLS} FROM files WHERE id = $1 AND owner_sub = $2 AND object_key = $3 \
             AND trashed_at = 0 AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL FOR UPDATE"
        ))
        .bind(input.file_id)
        .bind(input.owner_sub)
        .bind(input.expected_object_key)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(current_row) = current_row else {
            tx.rollback().await?;
            return Ok(OwnerBlobCommit::Conflict);
        };
        let current = Self::file_from_row(&current_row)?;
        if sqlx::query("SELECT 1 FROM file_versions WHERE id = $1 FOR UPDATE")
            .bind(input.snapshot_id)
            .fetch_optional(&mut *tx)
            .await?
            .is_some()
        {
            tx.rollback().await?;
            return Ok(OwnerBlobCommit::Collision);
        }
        let used = Self::owner_usage_with_pending_tx(&mut tx, input.owner_sub).await?;
        if input.owner_quota.is_some_and(|quota| used > quota) {
            tx.rollback().await?;
            return Ok(OwnerBlobCommit::QuotaExceeded);
        }
        let inserted = sqlx::query(
            "INSERT INTO file_versions (id, file_id, object_key, size, content_type, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
        )
        .bind(input.snapshot_id)
        .bind(input.file_id)
        .bind(&current.object_key)
        .bind(current.size)
        .bind(&current.content_type)
        .bind(input.changed_at)
        .execute(&mut *tx)
        .await?;
        if inserted.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(OwnerBlobCommit::Collision);
        }
        let updated = sqlx::query(
            "UPDATE files SET object_key = $1, size = $2, content_type = $3, updated_at = \
               CASE WHEN updated_at = 9223372036854775807 THEN updated_at \
                    WHEN updated_at >= $4 THEN updated_at + 1 ELSE $4 END \
             WHERE id = $5 AND owner_sub = $6 AND object_key = $7 AND trashed_at = 0 \
               AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL",
        )
        .bind(input.new_object_key)
        .bind(input.new_size)
        .bind(input.new_content_type)
        .bind(input.changed_at)
        .bind(input.file_id)
        .bind(input.owner_sub)
        .bind(input.expected_object_key)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(OwnerBlobCommit::Conflict);
        }
        let version_rows = sqlx::query(&format!(
            "SELECT {VERSION_COLS} FROM file_versions WHERE file_id = $1 \
             ORDER BY created_at DESC, id DESC FOR UPDATE"
        ))
        .bind(input.file_id)
        .fetch_all(&mut *tx)
        .await?;
        let mut live_keys = vec![input.new_object_key.to_string()];
        for row in version_rows.iter().take(MAX_VERSIONS_PER_FILE as usize) {
            live_keys.push(Self::version_from_row(row)?.object_key);
        }
        live_keys.push(format!("{}.thumb", input.new_object_key));
        let mut pruned_ids = Vec::new();
        let mut deletions: Vec<(String, &'static str)> = Vec::new();
        for row in version_rows.iter().skip(MAX_VERSIONS_PER_FILE as usize) {
            let version = Self::version_from_row(row)?;
            deletions.push((version.object_key.clone(), "version-prune"));
            deletions.push((
                format!("{}.thumb", version.object_key),
                "version-prune-thumbnail",
            ));
            pruned_ids.push(version.id);
        }
        deletions.push((format!("{}.thumb", current.object_key), "stale-thumbnail"));
        deletions.retain(|(key, _)| !live_keys.contains(key));
        deletions.sort_by(|left, right| left.0.cmp(&right.0));
        deletions.dedup_by(|left, right| left.0 == right.0);
        for (key, reason) in deletions {
            Self::enqueue_blob_delete_tx(&mut tx, &key, input.changed_at, reason).await?;
        }
        for version_id in pruned_ids {
            sqlx::query("DELETE FROM file_versions WHERE id = $1 AND file_id = $2")
                .bind(version_id)
                .bind(input.file_id)
                .execute(&mut *tx)
                .await?;
        }
        let consumed = sqlx::query(
            "DELETE FROM owner_blob_write_intents WHERE object_key = $1 AND owner_sub = $2 \
             AND write_kind = 'reupload' AND recovery_lease IS NULL",
        )
        .bind(input.new_object_key)
        .bind(input.owner_sub)
        .execute(&mut *tx)
        .await?;
        if consumed.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(OwnerBlobCommit::Conflict);
        }
        tx.commit().await?;
        Ok(OwnerBlobCommit::Applied)
    }

    async fn commit_owner_version_restore_async(
        &self,
        input: OwnerVersionRestoreInput<'_>,
    ) -> Result<OwnerBlobCommit, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        Self::lock_owner_storage_guard_tx(&mut tx, input.owner_sub).await?;
        let current_row = sqlx::query(&format!(
            "SELECT {COLS} FROM files WHERE id = $1 AND owner_sub = $2 AND object_key = $3 \
             AND trashed_at = 0 AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL FOR UPDATE"
        ))
        .bind(input.file_id)
        .bind(input.owner_sub)
        .bind(input.expected_object_key)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(current_row) = current_row else {
            tx.rollback().await?;
            return Ok(OwnerBlobCommit::Conflict);
        };
        let current = Self::file_from_row(&current_row)?;
        let selected_row = sqlx::query(&format!(
            "SELECT {VERSION_COLS} FROM file_versions WHERE id = $1 AND file_id = $2 FOR UPDATE"
        ))
        .bind(input.version_id)
        .bind(input.file_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(selected_row) = selected_row else {
            tx.rollback().await?;
            return Ok(OwnerBlobCommit::Conflict);
        };
        let selected = Self::version_from_row(&selected_row)?;
        if sqlx::query("SELECT 1 FROM file_versions WHERE id = $1 FOR UPDATE")
            .bind(input.snapshot_id)
            .fetch_optional(&mut *tx)
            .await?
            .is_some()
        {
            tx.rollback().await?;
            return Ok(OwnerBlobCommit::Collision);
        }
        let inserted = sqlx::query(
            "INSERT INTO file_versions (id, file_id, object_key, size, content_type, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
        )
        .bind(input.snapshot_id)
        .bind(input.file_id)
        .bind(&current.object_key)
        .bind(current.size)
        .bind(&current.content_type)
        .bind(input.changed_at)
        .execute(&mut *tx)
        .await?;
        if inserted.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(OwnerBlobCommit::Collision);
        }
        let updated = sqlx::query(
            "UPDATE files SET object_key = $1, size = $2, content_type = $3, updated_at = \
               CASE WHEN updated_at = 9223372036854775807 THEN updated_at \
                    WHEN updated_at >= $4 THEN updated_at + 1 ELSE $4 END \
             WHERE id = $5 AND owner_sub = $6 AND object_key = $7 AND trashed_at = 0 \
               AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL",
        )
        .bind(&selected.object_key)
        .bind(selected.size)
        .bind(&selected.content_type)
        .bind(input.changed_at)
        .bind(input.file_id)
        .bind(input.owner_sub)
        .bind(input.expected_object_key)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(OwnerBlobCommit::Conflict);
        }
        let consumed_version =
            sqlx::query("DELETE FROM file_versions WHERE id = $1 AND file_id = $2")
                .bind(input.version_id)
                .bind(input.file_id)
                .execute(&mut *tx)
                .await?;
        if consumed_version.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(OwnerBlobCommit::Conflict);
        }
        let version_rows = sqlx::query(&format!(
            "SELECT {VERSION_COLS} FROM file_versions WHERE file_id = $1 \
             ORDER BY created_at DESC, id DESC FOR UPDATE"
        ))
        .bind(input.file_id)
        .fetch_all(&mut *tx)
        .await?;
        let mut live_keys = vec![selected.object_key.clone()];
        for row in version_rows.iter().take(MAX_VERSIONS_PER_FILE as usize) {
            live_keys.push(Self::version_from_row(row)?.object_key);
        }
        live_keys.push(format!("{}.thumb", selected.object_key));
        let mut pruned_ids = Vec::new();
        let mut deletions: Vec<(String, &'static str)> = Vec::new();
        for row in version_rows.iter().skip(MAX_VERSIONS_PER_FILE as usize) {
            let version = Self::version_from_row(row)?;
            deletions.push((version.object_key.clone(), "version-prune"));
            deletions.push((
                format!("{}.thumb", version.object_key),
                "version-prune-thumbnail",
            ));
            pruned_ids.push(version.id);
        }
        deletions.push((format!("{}.thumb", current.object_key), "stale-thumbnail"));
        deletions.retain(|(key, _)| !live_keys.contains(key));
        deletions.sort_by(|left, right| left.0.cmp(&right.0));
        deletions.dedup_by(|left, right| left.0 == right.0);
        for (key, reason) in deletions {
            Self::enqueue_blob_delete_tx(&mut tx, &key, input.changed_at, reason).await?;
        }
        for version_id in pruned_ids {
            sqlx::query("DELETE FROM file_versions WHERE id = $1 AND file_id = $2")
                .bind(version_id)
                .bind(input.file_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(OwnerBlobCommit::Applied)
    }

    async fn finalize_owner_thumbnail_async(
        &self,
        object_key: &str,
        owner_sub: &str,
        file_id: &str,
        expected_object_key: &str,
    ) -> Result<OwnerBlobCommit, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        Self::lock_owner_storage_guard_tx(&mut tx, owner_sub).await?;
        if sqlx::query(
            "SELECT 1 FROM files WHERE id = $1 AND owner_sub = $2 AND object_key = $3 \
             AND trashed_at = 0 AND trash_entry_id IS NULL \
             AND trash_ancestor_id IS NULL FOR UPDATE",
        )
        .bind(file_id)
        .bind(owner_sub)
        .bind(expected_object_key)
        .fetch_optional(&mut *tx)
        .await?
        .is_none()
        {
            tx.rollback().await?;
            return Ok(OwnerBlobCommit::Conflict);
        }
        let consumed = sqlx::query(
            "DELETE FROM owner_blob_write_intents WHERE object_key = $1 AND owner_sub = $2 \
             AND file_id = $3 AND expected_object_key = $4 AND write_kind = 'thumbnail' \
             AND recovery_lease IS NULL",
        )
        .bind(object_key)
        .bind(owner_sub)
        .bind(file_id)
        .bind(expected_object_key)
        .execute(&mut *tx)
        .await?;
        if consumed.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(OwnerBlobCommit::Conflict);
        }
        tx.commit().await?;
        Ok(OwnerBlobCommit::Applied)
    }

    async fn enqueue_blob_deletion_async(
        &self,
        object_key: &str,
        enqueued_at: i64,
        reason: &str,
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        Self::lock_blob_key_guard_tx(&mut tx, object_key).await?;
        if sqlx::query(
            "SELECT 1 WHERE \
                 EXISTS (SELECT 1 FROM owner_blob_write_intents WHERE object_key = $1) OR \
                 EXISTS (SELECT 1 FROM upload_reservations WHERE id = $1) OR \
                 EXISTS (SELECT 1 FROM files WHERE object_key = $1) OR \
                 EXISTS (SELECT 1 FROM file_versions WHERE object_key = $1)",
        )
        .bind(object_key)
        .fetch_optional(&mut *tx)
        .await?
        .is_some()
        {
            tx.rollback().await?;
            return Err(sqlx::Error::Protocol(format!(
                "blob deletion key {object_key} still has live authority"
            )));
        }
        sqlx::query(
            "INSERT INTO blob_delete_queue \
                 (object_key, enqueued_at, next_attempt_at, reason) \
             VALUES ($1, $2, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(object_key)
        .bind(enqueued_at)
        .bind(reason)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn claim_owner_blob_writes_async(
        &self,
        lease_id: &str,
        now: i64,
        created_before: i64,
        lease_expired_before: i64,
        limit: i64,
    ) -> Result<Vec<OwnerBlobWriteIntent>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query(
            "SELECT object_key, owner_sub, size, write_kind, file_id, folder_id, \
                    expected_object_key, created_at, attempts \
             FROM owner_blob_write_intents \
             WHERE created_at <= $1 AND next_attempt_at <= $2 \
               AND (recovery_lease IS NULL OR recovery_leased_at <= $3) \
             ORDER BY next_attempt_at ASC, created_at ASC, object_key ASC LIMIT $4 FOR UPDATE",
        )
        .bind(created_before)
        .bind(now)
        .bind(lease_expired_before)
        .bind(clamp_page(limit))
        .fetch_all(&mut *tx)
        .await?;
        let mut claimed = Vec::with_capacity(rows.len());
        for row in rows {
            let intent = Self::owner_blob_write_from_row(&row)?;
            let updated = sqlx::query(
                "UPDATE owner_blob_write_intents SET recovery_lease = $1, recovery_leased_at = $2 \
                 WHERE object_key = $3 \
                   AND (recovery_lease IS NULL OR recovery_leased_at <= $4)",
            )
            .bind(lease_id)
            .bind(now)
            .bind(&intent.object_key)
            .bind(lease_expired_before)
            .execute(&mut *tx)
            .await?;
            if updated.rows_affected() == 1 {
                claimed.push(intent);
            }
        }
        tx.commit().await?;
        Ok(claimed)
    }

    async fn complete_owner_blob_write_async(
        &self,
        object_key: &str,
        lease_id: &str,
    ) -> Result<bool, sqlx::Error> {
        let deleted = sqlx::query(
            "DELETE FROM owner_blob_write_intents WHERE object_key = $1 AND recovery_lease = $2",
        )
        .bind(object_key)
        .bind(lease_id)
        .execute(&self.pool)
        .await?;
        Ok(deleted.rows_affected() == 1)
    }

    async fn abandon_owner_blob_write_async(
        &self,
        object_key: &str,
        lease_id: &str,
        retry_at: i64,
    ) -> Result<bool, sqlx::Error> {
        let updated = sqlx::query(
            "UPDATE owner_blob_write_intents \
             SET attempts = attempts + 1, next_attempt_at = $1, \
                 recovery_lease = NULL, recovery_leased_at = NULL \
             WHERE object_key = $2 AND recovery_lease = $3",
        )
        .bind(retry_at)
        .bind(object_key)
        .bind(lease_id)
        .execute(&self.pool)
        .await?;
        Ok(updated.rows_affected() == 1)
    }

    async fn configure_share_async(
        &self,
        id: &str,
        owner_sub: &str,
        share_token: Option<String>,
        expires_at: Option<i64>,
        share_password_hash: Option<String>,
    ) -> Result<bool, sqlx::Error> {
        let updated_at = mutation_time();
        let result = sqlx::query(
            "UPDATE files SET share_token = $1, expires_at = $2, share_password_hash = $3, \
             updated_at = CASE WHEN updated_at = 9223372036854775807 THEN updated_at \
                               WHEN updated_at >= $4 THEN updated_at + 1 ELSE $4 END \
             WHERE id = $5 AND owner_sub = $6 AND trashed_at = 0 \
               AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL",
        )
        .bind(&share_token)
        .bind(expires_at)
        .bind(&share_password_hash)
        .bind(updated_at)
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
        let row = sqlx::query(&format!(
            "SELECT {COLS} FROM files WHERE share_token = $1 AND trashed_at = 0 \
             AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL"
        ))
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::file_from_row).transpose()
    }

    async fn bump_view_count_async(&self, id: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE files SET view_count = view_count + 1 WHERE id = $1 AND trashed_at = 0 \
             AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
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
                    "SELECT {COLS} FROM files WHERE owner_sub = $1 AND folder_id IS NULL \
                     AND trashed_at = 0 AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL \
                     ORDER BY created_at DESC, id DESC LIMIT $2"
                ))
                .bind(owner_sub)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (None, Some((ts, id))) => {
                sqlx::query(&format!(
                    "SELECT {COLS} FROM files WHERE owner_sub = $1 AND folder_id IS NULL \
                     AND trashed_at = 0 AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL \
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
                     AND trashed_at = 0 AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL \
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
                     AND trashed_at = 0 AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL \
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

    async fn query_library_async(
        &self,
        owner_sub: &str,
        query: &LibraryQuery,
    ) -> Result<LibraryPage, sqlx::Error> {
        let now = mutation_time();
        let fetch_limit = clamp_page(query.limit) + 1;
        let needle = query.query.as_ref().map(|value| value.to_lowercase());
        let mut items = Vec::with_capacity((fetch_limit * 2) as usize);

        if query.type_filter != LibraryType::Folder {
            let mut files = QueryBuilder::<Postgres>::new(format!(
                "SELECT {COLS} FROM files WHERE owner_sub = "
            ));
            files.push_bind(owner_sub).push(
                " AND trashed_at = 0 AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL",
            );
            if query.view == LibraryView::Shared {
                files.push(" AND share_token IS NOT NULL");
            }
            if let Some(needle) = needle.as_deref() {
                files
                    .push(" AND POSITION(")
                    .push_bind(needle)
                    .push(" IN LOWER(name)) > 0");
            }
            push_library_file_type(&mut files, query.type_filter);
            if let Some(cursor) = query.before.as_ref() {
                push_library_cursor(&mut files, cursor, LibraryItemKind::File);
            }
            files
                .push(" ORDER BY updated_at DESC, id DESC LIMIT ")
                .push_bind(fetch_limit);
            let rows = files.build().fetch_all(&self.pool).await?;
            let records: Vec<FileRec> = rows
                .iter()
                .map(Self::file_from_row)
                .collect::<Result<_, _>>()?;
            items.extend(records.iter().map(|file| file_library_item(file, now)));
        }

        if matches!(query.type_filter, LibraryType::All | LibraryType::Folder) {
            let mut folders = QueryBuilder::<Postgres>::new(format!(
                "SELECT {FOLDER_COLS} FROM folders WHERE owner_sub = "
            ));
            folders.push_bind(owner_sub).push(
                " AND trashed_at = 0 AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL",
            );
            if query.view == LibraryView::Shared {
                folders.push(" AND share_token IS NOT NULL");
            }
            if let Some(needle) = needle.as_deref() {
                folders
                    .push(" AND POSITION(")
                    .push_bind(needle)
                    .push(" IN LOWER(name)) > 0");
            }
            if let Some(cursor) = query.before.as_ref() {
                push_library_cursor(&mut folders, cursor, LibraryItemKind::Folder);
            }
            folders
                .push(" ORDER BY updated_at DESC, id DESC LIMIT ")
                .push_bind(fetch_limit);
            let rows = folders.build().fetch_all(&self.pool).await?;
            let records: Vec<FolderRec> = rows
                .iter()
                .map(Self::folder_from_row)
                .collect::<Result<_, _>>()?;
            items.extend(
                records
                    .iter()
                    .map(|folder| folder_library_item(folder, now)),
            );
        }

        Ok(finish_library_page(items, query.limit))
    }

    async fn trash_file_async(
        &self,
        id: &str,
        owner_sub: &str,
        trashed_at: i64,
    ) -> Result<bool, sqlx::Error> {
        let now = trashed_at.max(1);
        Ok(matches!(
            self.bulk_trash_async(
                owner_sub,
                &[TrashRootInput {
                    item: DriveItemRef {
                        kind: LibraryItemKind::File,
                        id: id.to_string(),
                    },
                    entry_id: format!("compat-file-{id}-{now}"),
                }],
                now,
                now.saturating_add(DEFAULT_TRASH_RETENTION_SECS),
            )
            .await?,
            BulkMutation::Applied { .. }
        ))
    }

    async fn restore_file_async(&self, id: &str, owner_sub: &str) -> Result<bool, sqlx::Error> {
        Ok(matches!(
            self.bulk_restore_async(
                owner_sub,
                &[DriveItemRef {
                    kind: LibraryItemKind::File,
                    id: id.to_string(),
                }],
            )
            .await?,
            BulkMutation::Applied { .. }
        ))
    }

    async fn rename_file_async(
        &self,
        id: &str,
        owner_sub: &str,
        name: &str,
    ) -> Result<bool, sqlx::Error> {
        let updated_at = mutation_time();
        let result = sqlx::query(
            "UPDATE files SET name = $1, \
             updated_at = CASE WHEN updated_at = 9223372036854775807 THEN updated_at \
                               WHEN updated_at >= $2 THEN updated_at + 1 ELSE $2 END \
             WHERE id = $3 AND owner_sub = $4 AND trashed_at = 0",
        )
        .bind(name)
        .bind(updated_at)
        .bind(id)
        .bind(owner_sub)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_trashed_by_owner_async(
        &self,
        owner_sub: &str,
    ) -> Result<Vec<FileRec>, sqlx::Error> {
        let rows = sqlx::query(&format!(
            "SELECT {COLS} FROM files WHERE owner_sub = $1 AND trashed_at <> 0 \
             ORDER BY trashed_at DESC, id DESC"
        ))
        .bind(owner_sub)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::file_from_row).collect()
    }

    async fn query_trash_async(
        &self,
        owner_sub: &str,
        before: Option<&LibraryCursor>,
        limit: i64,
    ) -> Result<TrashPage, sqlx::Error> {
        let fetch_limit = clamp_page(limit) + 1;
        let mut query = QueryBuilder::<Postgres>::new(
            "SELECT entry_id, item_kind, item_id, trashed_at, purge_after, name, \
                    content_type, size, kind_rank FROM (\
               SELECT t.id AS entry_id, t.item_kind, t.item_id, t.trashed_at, t.purge_after, \
                      f.name, f.content_type, f.size, 1 AS kind_rank \
               FROM trash_entries t JOIN files f ON f.id = t.item_id \
               WHERE t.item_kind = 'file' AND f.trash_entry_id = t.id \
                 AND f.owner_sub = t.owner_sub AND f.trash_ancestor_id IS NULL \
               UNION ALL \
               SELECT t.id AS entry_id, t.item_kind, t.item_id, t.trashed_at, t.purge_after, \
                      d.name, NULL AS content_type, NULL AS size, 0 AS kind_rank \
               FROM trash_entries t JOIN folders d ON d.id = t.item_id \
               WHERE t.item_kind = 'folder' AND d.trash_entry_id = t.id \
                 AND d.owner_sub = t.owner_sub AND d.trash_ancestor_id IS NULL\
             ) roots WHERE ",
        );
        query.push("roots.item_id <> '' AND EXISTS (SELECT 1 FROM trash_entries authority WHERE authority.id = roots.entry_id AND authority.owner_sub = ")
            .push_bind(owner_sub)
            .push(")");
        if let Some(cursor) = before {
            query
                .push(" AND (trashed_at < ")
                .push_bind(cursor.updated_at)
                .push(" OR (trashed_at = ")
                .push_bind(cursor.updated_at)
                .push(" AND (kind_rank < ")
                .push_bind(cursor.kind.rank())
                .push(" OR (kind_rank = ")
                .push_bind(cursor.kind.rank())
                .push(" AND item_id < ")
                .push_bind(cursor.id.clone())
                .push("))))");
        }
        query
            .push(" ORDER BY trashed_at DESC, kind_rank DESC, item_id DESC LIMIT ")
            .push_bind(fetch_limit);
        let rows = query.build().fetch_all(&self.pool).await?;
        let mut items = Vec::with_capacity(rows.len());
        for row in rows {
            let kind: String = row.try_get("item_kind")?;
            items.push(TrashItem {
                entry_id: row.try_get("entry_id")?,
                kind: if kind == "file" {
                    LibraryItemKind::File
                } else {
                    LibraryItemKind::Folder
                },
                id: row.try_get("item_id")?,
                name: row.try_get("name")?,
                content_type: row.try_get("content_type")?,
                size: row.try_get("size")?,
                trashed_at: row.try_get("trashed_at")?,
                purge_after: row.try_get("purge_after")?,
            });
        }
        Ok(finish_trash_page(items, limit))
    }

    async fn bulk_trash_async(
        &self,
        owner_sub: &str,
        roots: &[TrashRootInput],
        trashed_at: i64,
        purge_after: i64,
    ) -> Result<BulkMutation, sqlx::Error> {
        if roots.is_empty() || roots.len() > MAX_BULK_ITEMS {
            return Ok(BulkMutation::Conflict);
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO owner_storage_guards (owner_sub) VALUES ($1) ON CONFLICT DO NOTHING",
        )
        .bind(owner_sub)
        .execute(&mut *tx)
        .await?;
        sqlx::query("SELECT owner_sub FROM owner_storage_guards WHERE owner_sub = $1 FOR UPDATE")
            .bind(owner_sub)
            .fetch_one(&mut *tx)
            .await?;
        let file_rows = sqlx::query(&format!(
            "SELECT {COLS} FROM files WHERE owner_sub = $1 FOR UPDATE"
        ))
        .bind(owner_sub)
        .fetch_all(&mut *tx)
        .await?;
        let files: Vec<FileRec> = file_rows
            .iter()
            .map(Self::file_from_row)
            .collect::<Result<_, _>>()?;
        let folder_rows = sqlx::query(&format!(
            "SELECT {FOLDER_COLS} FROM folders WHERE owner_sub = $1 FOR UPDATE"
        ))
        .bind(owner_sub)
        .fetch_all(&mut *tx)
        .await?;
        let folders: Vec<FolderRec> = folder_rows
            .iter()
            .map(Self::folder_from_row)
            .collect::<Result<_, _>>()?;
        let mut seen_items = Vec::new();
        let mut seen_entries = Vec::new();
        for root in roots {
            let valid = !root.item.id.is_empty()
                && !root.entry_id.is_empty()
                && !seen_items.contains(&(root.item.kind, root.item.id.as_str()))
                && !seen_entries.contains(&root.entry_id.as_str())
                && match root.item.kind {
                    LibraryItemKind::File => files
                        .iter()
                        .any(|file| file.id == root.item.id && file.is_effectively_live()),
                    LibraryItemKind::Folder => folders
                        .iter()
                        .any(|folder| folder.id == root.item.id && folder.is_effectively_live()),
                };
            if !valid {
                tx.rollback().await?;
                return Ok(BulkMutation::Conflict);
            }
            seen_items.push((root.item.kind, root.item.id.as_str()));
            seen_entries.push(root.entry_id.as_str());
        }
        let mut entry_ids: Vec<&str> = roots.iter().map(|root| root.entry_id.as_str()).collect();
        entry_ids.sort_unstable();
        for entry_id in entry_ids {
            if sqlx::query("SELECT 1 FROM trash_entries WHERE id = $1 FOR UPDATE")
                .bind(entry_id)
                .fetch_optional(&mut *tx)
                .await?
                .is_some()
            {
                tx.rollback().await?;
                return Ok(BulkMutation::Conflict);
            }
        }
        let refs: Vec<DriveItemRef> = roots.iter().map(|root| root.item.clone()).collect();
        let normalized = normalized_refs(&refs, &files, &folders);
        let mut normalized_roots: Vec<&TrashRootInput> = normalized
            .iter()
            .map(|item| {
                roots
                    .iter()
                    .find(|root| root.item == *item)
                    .expect("normalized root came from input")
            })
            .collect();
        normalized_roots.sort_by(|left, right| left.entry_id.cmp(&right.entry_id));
        let now = trashed_at.max(1);
        for root in normalized_roots {
            let item = &root.item;
            let inserted = sqlx::query(
                "INSERT INTO trash_entries \
                     (id, owner_sub, item_kind, item_id, trashed_at, purge_after) \
                 VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
            )
            .bind(&root.entry_id)
            .bind(owner_sub)
            .bind(item.kind.slug())
            .bind(&item.id)
            .bind(now)
            .bind(purge_after.max(now))
            .execute(&mut *tx)
            .await?;
            if inserted.rows_affected() != 1 {
                tx.rollback().await?;
                return Ok(BulkMutation::Conflict);
            }
            match item.kind {
                LibraryItemKind::File => {
                    let updated = sqlx::query(
                        "UPDATE files SET trashed_at = $1, trash_entry_id = $2, updated_at = \
                           CASE WHEN updated_at = 9223372036854775807 THEN updated_at \
                                WHEN updated_at >= $1 THEN updated_at + 1 ELSE $1 END \
                         WHERE id = $3 AND owner_sub = $4 AND trashed_at = 0 \
                           AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL",
                    )
                    .bind(now)
                    .bind(&root.entry_id)
                    .bind(&item.id)
                    .bind(owner_sub)
                    .execute(&mut *tx)
                    .await?;
                    if updated.rows_affected() != 1 {
                        tx.rollback().await?;
                        return Ok(BulkMutation::Conflict);
                    }
                }
                LibraryItemKind::Folder => {
                    let updated = sqlx::query(
                        "UPDATE folders SET trashed_at = $1, trash_entry_id = $2, updated_at = \
                           CASE WHEN updated_at = 9223372036854775807 THEN updated_at \
                                WHEN updated_at >= $1 THEN updated_at + 1 ELSE $1 END \
                         WHERE id = $3 AND owner_sub = $4 AND trashed_at = 0 \
                           AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL",
                    )
                    .bind(now)
                    .bind(&root.entry_id)
                    .bind(&item.id)
                    .bind(owner_sub)
                    .execute(&mut *tx)
                    .await?;
                    if updated.rows_affected() != 1 {
                        tx.rollback().await?;
                        return Ok(BulkMutation::Conflict);
                    }
                    let descendants: Vec<&FolderRec> = folders
                        .iter()
                        .filter(|folder| {
                            folder.id != item.id
                                && folder_descends_from(&folders, &folder.id, &item.id)
                        })
                        .collect();
                    for folder in &descendants {
                        sqlx::query(
                            "UPDATE folders SET trash_ancestor_id = $1, \
                               trashed_at = CASE WHEN trash_entry_id IS NULL THEN $2 ELSE trashed_at END \
                             WHERE id = $3 AND owner_sub = $4 AND trash_ancestor_id IS NULL",
                        )
                        .bind(&root.entry_id)
                        .bind(now)
                        .bind(&folder.id)
                        .bind(owner_sub)
                        .execute(&mut *tx)
                        .await?;
                    }
                    let mut scope: Vec<&str> = descendants
                        .iter()
                        .map(|folder| folder.id.as_str())
                        .collect();
                    scope.push(&item.id);
                    for folder_id in scope {
                        sqlx::query(
                            "UPDATE files SET trash_ancestor_id = $1, \
                               trashed_at = CASE WHEN trash_entry_id IS NULL THEN $2 ELSE trashed_at END \
                             WHERE owner_sub = $3 AND folder_id = $4 \
                               AND trash_ancestor_id IS NULL",
                        )
                        .bind(&root.entry_id)
                        .bind(now)
                        .bind(owner_sub)
                        .bind(folder_id)
                        .execute(&mut *tx)
                        .await?;
                    }
                }
            }
        }
        tx.commit().await?;
        Ok(BulkMutation::Applied {
            changed: normalized.len(),
        })
    }

    async fn bulk_restore_async(
        &self,
        owner_sub: &str,
        items: &[DriveItemRef],
    ) -> Result<BulkMutation, sqlx::Error> {
        if items.is_empty() || items.len() > MAX_BULK_ITEMS {
            return Ok(BulkMutation::Conflict);
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO owner_storage_guards (owner_sub) VALUES ($1) ON CONFLICT DO NOTHING",
        )
        .bind(owner_sub)
        .execute(&mut *tx)
        .await?;
        sqlx::query("SELECT owner_sub FROM owner_storage_guards WHERE owner_sub = $1 FOR UPDATE")
            .bind(owner_sub)
            .fetch_one(&mut *tx)
            .await?;
        let mut seen = Vec::new();
        let mut roots: Vec<(DriveItemRef, String)> = Vec::new();
        for item in items {
            if seen.contains(&(item.kind, item.id.as_str())) {
                tx.rollback().await?;
                return Ok(BulkMutation::Conflict);
            }
            seen.push((item.kind, item.id.as_str()));
            let table = match item.kind {
                LibraryItemKind::File => "files",
                LibraryItemKind::Folder => "folders",
            };
            let sql = format!(
                "SELECT trash_entry_id FROM {table} WHERE id = $1 AND owner_sub = $2 \
                 AND trash_entry_id IS NOT NULL AND trash_ancestor_id IS NULL FOR UPDATE"
            );
            let row = sqlx::query(&sql)
                .bind(&item.id)
                .bind(owner_sub)
                .fetch_optional(&mut *tx)
                .await?;
            let Some(row) = row else {
                tx.rollback().await?;
                return Ok(BulkMutation::Conflict);
            };
            let entry_id: String = row.try_get("trash_entry_id")?;
            roots.push((item.clone(), entry_id));
        }
        let mut authority_roots = roots.clone();
        authority_roots.sort_by(|left, right| left.1.cmp(&right.1));
        for (item, entry_id) in &authority_roots {
            let authority = sqlx::query(
                "SELECT 1 FROM trash_entries WHERE id = $1 AND owner_sub = $2 \
                 AND item_kind = $3 AND item_id = $4 FOR UPDATE",
            )
            .bind(entry_id)
            .bind(owner_sub)
            .bind(item.kind.slug())
            .bind(&item.id)
            .fetch_optional(&mut *tx)
            .await?;
            if authority.is_none() {
                tx.rollback().await?;
                return Ok(BulkMutation::Conflict);
            }
        }
        let updated_at = mutation_time();
        for (item, entry_id) in &roots {
            let table = match item.kind {
                LibraryItemKind::File => "files",
                LibraryItemKind::Folder => "folders",
            };
            let sql = format!(
                "UPDATE {table} SET trashed_at = 0, trash_entry_id = NULL, updated_at = \
                   CASE WHEN updated_at = 9223372036854775807 THEN updated_at \
                        WHEN updated_at >= $1 THEN updated_at + 1 ELSE $1 END \
                 WHERE id = $2 AND owner_sub = $3 AND trash_entry_id = $4 \
                   AND trash_ancestor_id IS NULL"
            );
            let updated = sqlx::query(&sql)
                .bind(updated_at)
                .bind(&item.id)
                .bind(owner_sub)
                .bind(entry_id)
                .execute(&mut *tx)
                .await?;
            if updated.rows_affected() != 1 {
                tx.rollback().await?;
                return Ok(BulkMutation::Conflict);
            }
            sqlx::query(
                "UPDATE files SET trash_ancestor_id = NULL, \
                   trashed_at = CASE WHEN trash_entry_id IS NULL THEN 0 ELSE trashed_at END \
                 WHERE trash_ancestor_id = $1 AND owner_sub = $2",
            )
            .bind(entry_id)
            .bind(owner_sub)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE folders SET trash_ancestor_id = NULL, \
                   trashed_at = CASE WHEN trash_entry_id IS NULL THEN 0 ELSE trashed_at END \
                 WHERE trash_ancestor_id = $1 AND owner_sub = $2",
            )
            .bind(entry_id)
            .bind(owner_sub)
            .execute(&mut *tx)
            .await?;
            let deleted = sqlx::query(
                "DELETE FROM trash_entries WHERE id = $1 AND owner_sub = $2 \
                 AND item_kind = $3 AND item_id = $4",
            )
            .bind(entry_id)
            .bind(owner_sub)
            .bind(item.kind.slug())
            .bind(&item.id)
            .execute(&mut *tx)
            .await?;
            if deleted.rows_affected() != 1 {
                tx.rollback().await?;
                return Ok(BulkMutation::Conflict);
            }
        }
        tx.commit().await?;
        Ok(BulkMutation::Applied {
            changed: roots.len(),
        })
    }

    async fn bulk_move_async(
        &self,
        owner_sub: &str,
        items: &[DriveItemRef],
        folder_id: Option<&str>,
    ) -> Result<BulkMutation, sqlx::Error> {
        if items.is_empty() || items.len() > MAX_BULK_ITEMS {
            return Ok(BulkMutation::Conflict);
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO owner_storage_guards (owner_sub) VALUES ($1) ON CONFLICT DO NOTHING",
        )
        .bind(owner_sub)
        .execute(&mut *tx)
        .await?;
        sqlx::query("SELECT owner_sub FROM owner_storage_guards WHERE owner_sub = $1 FOR UPDATE")
            .bind(owner_sub)
            .fetch_one(&mut *tx)
            .await?;
        let file_rows = sqlx::query(&format!(
            "SELECT {COLS} FROM files WHERE owner_sub = $1 FOR UPDATE"
        ))
        .bind(owner_sub)
        .fetch_all(&mut *tx)
        .await?;
        let files: Vec<FileRec> = file_rows
            .iter()
            .map(Self::file_from_row)
            .collect::<Result<_, _>>()?;
        let folder_rows = sqlx::query(&format!(
            "SELECT {FOLDER_COLS} FROM folders WHERE owner_sub = $1 FOR UPDATE"
        ))
        .bind(owner_sub)
        .fetch_all(&mut *tx)
        .await?;
        let folders: Vec<FolderRec> = folder_rows
            .iter()
            .map(Self::folder_from_row)
            .collect::<Result<_, _>>()?;
        if folder_id.is_some_and(|target| {
            !folders
                .iter()
                .any(|folder| folder.id == target && folder.is_effectively_live())
        }) {
            tx.rollback().await?;
            return Ok(BulkMutation::Conflict);
        }
        let mut seen = Vec::new();
        for item in items {
            let valid = !seen.contains(&(item.kind, item.id.as_str()))
                && match item.kind {
                    LibraryItemKind::File => files
                        .iter()
                        .any(|file| file.id == item.id && file.is_effectively_live()),
                    LibraryItemKind::Folder => folders
                        .iter()
                        .any(|folder| folder.id == item.id && folder.is_effectively_live()),
                };
            if !valid
                || (item.kind == LibraryItemKind::Folder
                    && folder_id.is_some_and(|target| {
                        target == item.id || folder_descends_from(&folders, target, &item.id)
                    }))
            {
                tx.rollback().await?;
                return Ok(BulkMutation::Conflict);
            }
            seen.push((item.kind, item.id.as_str()));
        }
        let normalized = normalized_refs(items, &files, &folders);
        let updated_at = mutation_time();
        for item in &normalized {
            let (table, parent_column) = match item.kind {
                LibraryItemKind::File => ("files", "folder_id"),
                LibraryItemKind::Folder => ("folders", "parent_id"),
            };
            let sql = format!(
                "UPDATE {table} SET {parent_column} = $1, updated_at = \
                   CASE WHEN updated_at = 9223372036854775807 THEN updated_at \
                        WHEN updated_at >= $2 THEN updated_at + 1 ELSE $2 END \
                 WHERE id = $3 AND owner_sub = $4 AND trashed_at = 0 \
                   AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL"
            );
            let updated = sqlx::query(&sql)
                .bind(folder_id)
                .bind(updated_at)
                .bind(&item.id)
                .bind(owner_sub)
                .execute(&mut *tx)
                .await?;
            if updated.rows_affected() != 1 {
                tx.rollback().await?;
                return Ok(BulkMutation::Conflict);
            }
        }
        tx.commit().await?;
        Ok(BulkMutation::Applied {
            changed: normalized.len(),
        })
    }

    async fn bulk_purge_async(
        &self,
        owner_sub: &str,
        items: &[DriveItemRef],
        enqueued_at: i64,
    ) -> Result<BulkMutation, sqlx::Error> {
        if items.is_empty() || items.len() > MAX_BULK_ITEMS {
            return Ok(BulkMutation::Conflict);
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO owner_storage_guards (owner_sub) VALUES ($1) ON CONFLICT DO NOTHING",
        )
        .bind(owner_sub)
        .execute(&mut *tx)
        .await?;
        sqlx::query("SELECT owner_sub FROM owner_storage_guards WHERE owner_sub = $1 FOR UPDATE")
            .bind(owner_sub)
            .fetch_one(&mut *tx)
            .await?;
        // Folder purge also closes request rooms. Lock them before any reservation/file/folder row,
        // matching reserve/commit and eliminating request<->guard ABBA cycles.
        sqlx::query(
            "SELECT id FROM upload_requests WHERE owner_sub = $1 ORDER BY id ASC FOR UPDATE",
        )
        .bind(owner_sub)
        .fetch_all(&mut *tx)
        .await?;
        let file_rows = sqlx::query(&format!(
            "SELECT {COLS} FROM files WHERE owner_sub = $1 FOR UPDATE"
        ))
        .bind(owner_sub)
        .fetch_all(&mut *tx)
        .await?;
        let files: Vec<FileRec> = file_rows
            .iter()
            .map(Self::file_from_row)
            .collect::<Result<_, _>>()?;
        let folder_rows = sqlx::query(&format!(
            "SELECT {FOLDER_COLS} FROM folders WHERE owner_sub = $1 FOR UPDATE"
        ))
        .bind(owner_sub)
        .fetch_all(&mut *tx)
        .await?;
        let folders: Vec<FolderRec> = folder_rows
            .iter()
            .map(Self::folder_from_row)
            .collect::<Result<_, _>>()?;
        let mut seen = Vec::new();
        let mut authorities = Vec::new();
        for item in items {
            let entry_id = match item.kind {
                LibraryItemKind::File => files.iter().find_map(|file| {
                    (file.id == item.id
                        && file.trash_entry_id.is_some()
                        && file.trash_ancestor_id.is_none())
                    .then(|| file.trash_entry_id.clone())
                    .flatten()
                }),
                LibraryItemKind::Folder => folders.iter().find_map(|folder| {
                    (folder.id == item.id
                        && folder.trash_entry_id.is_some()
                        && folder.trash_ancestor_id.is_none())
                    .then(|| folder.trash_entry_id.clone())
                    .flatten()
                }),
            };
            if seen.contains(&(item.kind, item.id.as_str())) || entry_id.is_none() {
                tx.rollback().await?;
                return Ok(BulkMutation::Conflict);
            }
            seen.push((item.kind, item.id.as_str()));
            authorities.push((
                entry_id.expect("checked entry id"),
                item.kind,
                item.id.clone(),
            ));
        }
        authorities.sort_by(|left, right| left.0.cmp(&right.0));
        for (entry_id, kind, item_id) in &authorities {
            let authority = sqlx::query(
                "SELECT 1 FROM trash_entries WHERE id = $1 AND owner_sub = $2 \
                 AND item_kind = $3 AND item_id = $4 FOR UPDATE",
            )
            .bind(entry_id)
            .bind(owner_sub)
            .bind(kind.slug())
            .bind(item_id)
            .fetch_optional(&mut *tx)
            .await?;
            if authority.is_none() {
                tx.rollback().await?;
                return Ok(BulkMutation::Conflict);
            }
        }
        let normalized = normalized_refs(items, &files, &folders);
        let mut doomed_folders = Vec::new();
        let mut doomed_files: Vec<String> = normalized
            .iter()
            .filter(|item| item.kind == LibraryItemKind::File)
            .map(|item| item.id.clone())
            .collect();
        for root in normalized
            .iter()
            .filter(|item| item.kind == LibraryItemKind::Folder)
        {
            doomed_folders.extend(
                folders
                    .iter()
                    .filter(|folder| folder_descends_from(&folders, &folder.id, &root.id))
                    .map(|folder| folder.id.clone()),
            );
        }
        doomed_folders.sort();
        doomed_folders.dedup();
        doomed_files.extend(
            files
                .iter()
                .filter(|file| {
                    file.folder_id
                        .as_ref()
                        .is_some_and(|folder| doomed_folders.contains(folder))
                })
                .map(|file| file.id.clone()),
        );
        doomed_files.sort();
        doomed_files.dedup();
        let mut keys: Vec<String> = files
            .iter()
            .filter(|file| doomed_files.contains(&file.id))
            .map(|file| file.object_key.clone())
            .collect();
        for file_id in &doomed_files {
            let rows =
                sqlx::query("SELECT object_key FROM file_versions WHERE file_id = $1 FOR UPDATE")
                    .bind(file_id)
                    .fetch_all(&mut *tx)
                    .await?;
            for row in rows {
                keys.push(row.try_get("object_key")?);
            }
        }
        let thumbs: Vec<String> = keys.iter().map(|key| format!("{key}.thumb")).collect();
        keys.extend(thumbs);
        keys.sort();
        keys.dedup();
        for key in &keys {
            Self::enqueue_blob_delete_tx(&mut tx, key, enqueued_at, "trash-purge").await?;
        }
        for file_id in &doomed_files {
            sqlx::query("DELETE FROM file_comments WHERE file_id = $1")
                .bind(file_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM file_versions WHERE file_id = $1")
                .bind(file_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM files WHERE id = $1 AND owner_sub = $2")
                .bind(file_id)
                .bind(owner_sub)
                .execute(&mut *tx)
                .await?;
            sqlx::query(
                "DELETE FROM trash_entries WHERE owner_sub = $1 \
                 AND item_kind = 'file' AND item_id = $2",
            )
            .bind(owner_sub)
            .bind(file_id)
            .execute(&mut *tx)
            .await?;
        }
        for folder_id in &doomed_folders {
            sqlx::query(
                "UPDATE upload_requests SET status = 'closed', updated_at = $1 \
                 WHERE owner_sub = $2 AND folder_id = $3",
            )
            .bind(enqueued_at)
            .bind(owner_sub)
            .bind(folder_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query("DELETE FROM folders WHERE id = $1 AND owner_sub = $2")
                .bind(folder_id)
                .bind(owner_sub)
                .execute(&mut *tx)
                .await?;
            sqlx::query(
                "DELETE FROM trash_entries WHERE owner_sub = $1 \
                 AND item_kind = 'folder' AND item_id = $2",
            )
            .bind(owner_sub)
            .bind(folder_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(BulkMutation::Applied {
            changed: normalized.len(),
        })
    }

    async fn claim_expired_trash_async(
        &self,
        lease_id: &str,
        now: i64,
        lease_expired_before: i64,
        limit: i64,
    ) -> Result<Vec<TrashEntry>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let candidate_rows = sqlx::query(
            "SELECT t.id FROM trash_entries t \
             WHERE t.purge_after <= $1 \
               AND (t.recovery_lease IS NULL OR t.recovery_leased_at <= $2) \
               AND (\
                 (t.item_kind = 'file' AND EXISTS (\
                    SELECT 1 FROM files f WHERE f.id = t.item_id \
                      AND f.owner_sub = t.owner_sub AND f.trash_entry_id = t.id \
                      AND f.trash_ancestor_id IS NULL)) OR \
                 (t.item_kind = 'folder' AND EXISTS (\
                    SELECT 1 FROM folders d WHERE d.id = t.item_id \
                      AND d.owner_sub = t.owner_sub AND d.trash_entry_id = t.id \
                      AND d.trash_ancestor_id IS NULL))\
               ) \
             ORDER BY t.purge_after ASC, t.id ASC LIMIT $3",
        )
        .bind(now)
        .bind(lease_expired_before)
        .bind(clamp_page(limit))
        .fetch_all(&mut *tx)
        .await?;
        let mut candidate_ids: Vec<String> = candidate_rows
            .iter()
            .map(|row| row.try_get("id"))
            .collect::<Result<_, _>>()?;
        // Every lifecycle mutation locks Trash authority by id. Fairness is decided above before
        // LIMIT; only the lock acquisition order changes, eliminating claim-vs-bulk ABBA.
        candidate_ids.sort();
        let mut claimed = Vec::new();
        for candidate_id in candidate_ids {
            let row = sqlx::query(
                "SELECT t.id, t.owner_sub, t.item_kind, t.item_id, t.trashed_at, t.purge_after, \
                        t.recovery_lease, t.recovery_leased_at \
                 FROM trash_entries t WHERE t.id = $1 AND t.purge_after <= $2 \
                   AND (t.recovery_lease IS NULL OR t.recovery_leased_at <= $3) \
                   AND (\
                     (t.item_kind = 'file' AND EXISTS (\
                        SELECT 1 FROM files f WHERE f.id = t.item_id \
                          AND f.owner_sub = t.owner_sub AND f.trash_entry_id = t.id \
                          AND f.trash_ancestor_id IS NULL)) OR \
                     (t.item_kind = 'folder' AND EXISTS (\
                        SELECT 1 FROM folders d WHERE d.id = t.item_id \
                          AND d.owner_sub = t.owner_sub AND d.trash_entry_id = t.id \
                          AND d.trash_ancestor_id IS NULL))\
                   ) FOR UPDATE",
            )
            .bind(&candidate_id)
            .bind(now)
            .bind(lease_expired_before)
            .fetch_optional(&mut *tx)
            .await?;
            let Some(row) = row else {
                continue;
            };
            let entry = Self::trash_entry_from_row(&row)?;
            let table = match entry.kind {
                LibraryItemKind::File => "files",
                LibraryItemKind::Folder => "folders",
            };
            let sql = format!(
                "SELECT 1 FROM {table} WHERE id = $1 AND owner_sub = $2 \
                 AND trash_entry_id = $3 AND trash_ancestor_id IS NULL"
            );
            if sqlx::query(&sql)
                .bind(&entry.item_id)
                .bind(&entry.owner_sub)
                .bind(&entry.id)
                .fetch_optional(&mut *tx)
                .await?
                .is_none()
            {
                continue;
            }
            let updated = sqlx::query(
                "UPDATE trash_entries SET recovery_lease = $1, recovery_leased_at = $2 \
                 WHERE id = $3 AND (recovery_lease IS NULL OR recovery_leased_at <= $4)",
            )
            .bind(lease_id)
            .bind(now)
            .bind(&entry.id)
            .bind(lease_expired_before)
            .execute(&mut *tx)
            .await?;
            if updated.rows_affected() == 1 {
                let mut leased = entry;
                leased.recovery_lease = Some(lease_id.to_string());
                leased.recovery_leased_at = Some(now);
                claimed.push(leased);
            }
        }
        tx.commit().await?;
        Ok(claimed)
    }

    async fn abandon_trash_claim_async(
        &self,
        entry_id: &str,
        lease_id: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE trash_entries SET recovery_lease = NULL, recovery_leased_at = NULL \
             WHERE id = $1 AND recovery_lease = $2",
        )
        .bind(entry_id)
        .bind(lease_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn claim_blob_deletions_async(
        &self,
        lease_id: &str,
        now: i64,
        lease_expired_before: i64,
        limit: i64,
    ) -> Result<BlobDeleteClaim, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query(
            "SELECT object_key, attempts FROM blob_delete_queue \
             WHERE next_attempt_at <= $1 \
               AND (recovery_lease IS NULL OR recovery_leased_at <= $2) \
             ORDER BY next_attempt_at ASC, enqueued_at ASC, object_key ASC \
             LIMIT $3 FOR UPDATE",
        )
        .bind(now)
        .bind(lease_expired_before)
        .bind(clamp_page(limit))
        .fetch_all(&mut *tx)
        .await?;
        if rows.is_empty() {
            tx.commit().await?;
            return Ok(BlobDeleteClaim::Empty);
        }
        let mut claimed = Vec::with_capacity(rows.len());
        for row in rows {
            let object_key: String = row.try_get("object_key")?;
            let attempts: i64 = row.try_get("attempts")?;
            let updated = sqlx::query(
                "UPDATE blob_delete_queue SET recovery_lease = $1, recovery_leased_at = $2 \
                 WHERE object_key = $3 \
                   AND (recovery_lease IS NULL OR recovery_leased_at <= $4)",
            )
            .bind(lease_id)
            .bind(now)
            .bind(&object_key)
            .bind(lease_expired_before)
            .execute(&mut *tx)
            .await?;
            if updated.rows_affected() == 1 {
                claimed.push(BlobDeleteItem {
                    object_key,
                    attempts,
                });
            }
        }
        tx.commit().await?;
        if claimed.is_empty() {
            Ok(BlobDeleteClaim::Empty)
        } else {
            Ok(BlobDeleteClaim::Claimed(claimed))
        }
    }

    async fn complete_blob_deletion_async(
        &self,
        object_key: &str,
        lease_id: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "DELETE FROM blob_delete_queue WHERE object_key = $1 AND recovery_lease = $2",
        )
        .bind(object_key)
        .bind(lease_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn abandon_blob_deletion_async(
        &self,
        object_key: &str,
        lease_id: &str,
        retry_at: i64,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE blob_delete_queue \
             SET attempts = CASE WHEN attempts = 9223372036854775807 THEN attempts \
                                 ELSE attempts + 1 END, \
                 next_attempt_at = $1, recovery_lease = NULL, recovery_leased_at = NULL \
             WHERE object_key = $2 AND recovery_lease = $3",
        )
        .bind(retry_at)
        .bind(object_key)
        .bind(lease_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn create_folder_async(&self, folder: &FolderRec) -> Result<bool, sqlx::Error> {
        if folder.parent_id.as_deref() == Some(folder.id.as_str()) {
            return Ok(false);
        }
        let mut tx = self.pool.begin().await?;
        Self::lock_owner_storage_guard_tx(&mut tx, &folder.owner_sub).await?;
        let result = sqlx::query(
            "INSERT INTO folders \
                 (id, owner_sub, parent_id, name, created_at, updated_at, share_token, expires_at, \
                  share_password_hash, upload_token, trashed_at, trash_entry_id, trash_ancestor_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
             ON CONFLICT DO NOTHING",
        )
        .bind(&folder.id)
        .bind(&folder.owner_sub)
        .bind(&folder.parent_id)
        .bind(&folder.name)
        .bind(folder.created_at)
        .bind(folder.updated_at)
        .bind(&folder.share_token)
        .bind(folder.expires_at)
        .bind(&folder.share_password_hash)
        .bind(&folder.upload_token)
        .bind(folder.trashed_at)
        .bind(&folder.trash_entry_id)
        .bind(&folder.trash_ancestor_id)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(false);
        }
        if let Some(parent_id) = folder.parent_id.as_deref() {
            if sqlx::query(
                "SELECT 1 FROM folders WHERE id = $1 AND owner_sub = $2 AND trashed_at = 0 \
                 AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL FOR UPDATE",
            )
            .bind(parent_id)
            .bind(&folder.owner_sub)
            .fetch_optional(&mut *tx)
            .await?
            .is_none()
            {
                tx.rollback().await?;
                return Ok(false);
            }
        }
        tx.commit().await?;
        Ok(true)
    }

    async fn list_folders_async(&self, owner_sub: &str) -> Result<Vec<FolderRec>, sqlx::Error> {
        let rows = sqlx::query(&format!(
            "SELECT {FOLDER_COLS} FROM folders WHERE owner_sub = $1 \
             AND trashed_at = 0 AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL \
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
            "SELECT {FOLDER_COLS} FROM folders WHERE id = $1 AND owner_sub = $2 \
             AND trashed_at = 0 AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL"
        ))
        .bind(id)
        .bind(owner_sub)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::folder_from_row).transpose()
    }

    async fn get_folder_any_async(
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

    async fn get_folder_by_token_async(
        &self,
        token: &str,
    ) -> Result<Option<FolderRec>, sqlx::Error> {
        let row = sqlx::query(&format!(
            "SELECT {FOLDER_COLS} FROM folders WHERE share_token = $1 \
             AND trashed_at = 0 AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL"
        ))
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::folder_from_row).transpose()
    }

    async fn get_folder_by_upload_token_async(
        &self,
        token: &str,
    ) -> Result<Option<FolderRec>, sqlx::Error> {
        let row = sqlx::query(&format!(
            "SELECT {FOLDER_COLS} FROM folders WHERE upload_token = $1 \
             AND trashed_at = 0 AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL"
        ))
        .bind(token)
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
        let updated_at = mutation_time();
        let result = sqlx::query(
            "UPDATE folders SET name = $1, \
             updated_at = CASE WHEN updated_at = 9223372036854775807 THEN updated_at \
                               WHEN updated_at >= $2 THEN updated_at + 1 ELSE $2 END \
             WHERE id = $3 AND owner_sub = $4 AND trashed_at = 0 \
               AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL",
        )
        .bind(name)
        .bind(updated_at)
        .bind(id)
        .bind(owner_sub)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn configure_folder_share_async(
        &self,
        id: &str,
        owner_sub: &str,
        share_token: Option<String>,
        expires_at: Option<i64>,
        share_password_hash: Option<String>,
    ) -> Result<bool, sqlx::Error> {
        let updated_at = mutation_time();
        let result = sqlx::query(
            "UPDATE folders SET share_token = $1, expires_at = $2, share_password_hash = $3, \
             updated_at = CASE WHEN updated_at = 9223372036854775807 THEN updated_at \
                               WHEN updated_at >= $4 THEN updated_at + 1 ELSE $4 END \
             WHERE id = $5 AND owner_sub = $6 AND trashed_at = 0 \
               AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL",
        )
        .bind(&share_token)
        .bind(expires_at)
        .bind(&share_password_hash)
        .bind(updated_at)
        .bind(id)
        .bind(owner_sub)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn configure_folder_upload_async(
        &self,
        id: &str,
        owner_sub: &str,
        upload_token: Option<String>,
    ) -> Result<bool, sqlx::Error> {
        let updated_at = mutation_time();
        let result = sqlx::query(
            "UPDATE folders SET upload_token = $1, \
             updated_at = CASE WHEN updated_at = 9223372036854775807 THEN updated_at \
                               WHEN updated_at >= $2 THEN updated_at + 1 ELSE $2 END \
             WHERE id = $3 AND owner_sub = $4 AND trashed_at = 0 \
               AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL",
        )
        .bind(&upload_token)
        .bind(updated_at)
        .bind(id)
        .bind(owner_sub)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_folder_if_empty_async(
        &self,
        id: &str,
        owner_sub: &str,
    ) -> Result<FolderDelete, sqlx::Error> {
        // Absent / not owned?
        let exists = sqlx::query("SELECT 1 FROM folders WHERE id = $1 AND owner_sub = $2")
            .bind(id)
            .bind(owner_sub)
            .fetch_optional(&self.pool)
            .await?;
        if exists.is_none() {
            return Ok(FolderDelete::NotFound);
        }
        // Any child folder or file (owner-scoped) => not empty.
        let child = sqlx::query(
            "SELECT 1 FROM folders WHERE parent_id = $1 AND owner_sub = $2 \
             UNION ALL SELECT 1 FROM files WHERE folder_id = $1 AND owner_sub = $2 LIMIT 1",
        )
        .bind(id)
        .bind(owner_sub)
        .fetch_optional(&self.pool)
        .await?;
        if child.is_some() {
            return Ok(FolderDelete::NotEmpty);
        }
        sqlx::query("DELETE FROM folders WHERE id = $1 AND owner_sub = $2")
            .bind(id)
            .bind(owner_sub)
            .execute(&self.pool)
            .await?;
        Ok(FolderDelete::Deleted)
    }

    async fn delete_folder_cascade_async(
        &self,
        id: &str,
        owner_sub: &str,
    ) -> Result<Vec<String>, sqlx::Error> {
        // Load ALL of the owner's folders and compute the descendant id set in Rust (portable — no
        // recursive CTE, so it runs unchanged on FusionDB), then delete files + versions + folders.
        let rows = sqlx::query("SELECT id, parent_id FROM folders WHERE owner_sub = $1")
            .bind(owner_sub)
            .fetch_all(&self.pool)
            .await?;
        let all: Vec<(String, Option<String>)> = rows
            .iter()
            .map(|r| Ok((r.try_get("id")?, r.try_get("parent_id")?)))
            .collect::<Result<_, sqlx::Error>>()?;
        if !all.iter().any(|(fid, _)| fid == id) {
            return Ok(Vec::new());
        }
        let mut set: Vec<String> = vec![id.to_string()];
        let mut i = 0;
        while i < set.len() {
            let parent = set[i].clone();
            for (fid, pid) in &all {
                if pid.as_deref() == Some(parent.as_str()) && !set.contains(fid) {
                    set.push(fid.clone());
                }
            }
            i += 1;
        }
        let mut keys: Vec<String> = Vec::new();
        for fid in &set {
            // File current blobs + version blobs in this folder, then remove the rows.
            let file_rows = sqlx::query(
                "SELECT object_key, id FROM files WHERE folder_id = $1 AND owner_sub = $2",
            )
            .bind(fid)
            .bind(owner_sub)
            .fetch_all(&self.pool)
            .await?;
            for fr in &file_rows {
                keys.push(fr.try_get("object_key")?);
                let file_id: String = fr.try_get("id")?;
                let vrows = sqlx::query("SELECT object_key FROM file_versions WHERE file_id = $1")
                    .bind(&file_id)
                    .fetch_all(&self.pool)
                    .await?;
                for vr in &vrows {
                    keys.push(vr.try_get("object_key")?);
                }
                sqlx::query("DELETE FROM file_versions WHERE file_id = $1")
                    .bind(&file_id)
                    .execute(&self.pool)
                    .await?;
                sqlx::query("DELETE FROM file_comments WHERE file_id = $1")
                    .bind(&file_id)
                    .execute(&self.pool)
                    .await?;
            }
            sqlx::query("DELETE FROM files WHERE folder_id = $1 AND owner_sub = $2")
                .bind(fid)
                .bind(owner_sub)
                .execute(&self.pool)
                .await?;
            sqlx::query("DELETE FROM folders WHERE id = $1 AND owner_sub = $2")
                .bind(fid)
                .bind(owner_sub)
                .execute(&self.pool)
                .await?;
        }
        Ok(keys)
    }

    async fn list_files_in_folder_async(
        &self,
        folder_id: &str,
        owner_sub: &str,
    ) -> Result<Vec<FileRec>, sqlx::Error> {
        let rows = sqlx::query(&format!(
            "SELECT {COLS} FROM files WHERE folder_id = $1 AND owner_sub = $2 \
             AND trashed_at = 0 AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL \
             ORDER BY created_at DESC, id DESC"
        ))
        .bind(folder_id)
        .bind(owner_sub)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::file_from_row).collect()
    }

    async fn find_file_in_folder_async(
        &self,
        owner_sub: &str,
        name: &str,
        folder_id: Option<&str>,
    ) -> Result<Option<FileRec>, sqlx::Error> {
        // NULL folder_id (root) needs `IS NULL`, not `= NULL`; branch to keep the bind order right.
        let row = match folder_id {
            None => {
                sqlx::query(&format!(
                    "SELECT {COLS} FROM files \
                     WHERE owner_sub = $1 AND name = $2 AND folder_id IS NULL \
                     AND trashed_at = 0 AND trash_entry_id IS NULL \
                     AND trash_ancestor_id IS NULL LIMIT 1"
                ))
                .bind(owner_sub)
                .bind(name)
                .fetch_optional(&self.pool)
                .await?
            }
            Some(fid) => {
                sqlx::query(&format!(
                    "SELECT {COLS} FROM files \
                     WHERE owner_sub = $1 AND name = $2 AND folder_id = $3 \
                     AND trashed_at = 0 AND trash_entry_id IS NULL \
                     AND trash_ancestor_id IS NULL LIMIT 1"
                ))
                .bind(owner_sub)
                .bind(name)
                .bind(fid)
                .fetch_optional(&self.pool)
                .await?
            }
        };
        row.as_ref().map(Self::file_from_row).transpose()
    }

    async fn update_file_blob_async(
        &self,
        id: &str,
        owner_sub: &str,
        object_key: &str,
        size: i64,
        content_type: &str,
        updated_at: i64,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE files SET object_key = $1, size = $2, content_type = $3, \
             updated_at = CASE WHEN updated_at = 9223372036854775807 THEN updated_at \
                               WHEN updated_at >= $4 THEN updated_at + 1 ELSE $4 END \
             WHERE id = $5 AND owner_sub = $6",
        )
        .bind(object_key)
        .bind(size)
        .bind(content_type)
        .bind(updated_at)
        .bind(id)
        .bind(owner_sub)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn add_version_async(&self, version: &VersionRec) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "INSERT INTO file_versions (id, file_id, object_key, size, content_type, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
        )
        .bind(&version.id)
        .bind(&version.file_id)
        .bind(&version.object_key)
        .bind(version.size)
        .bind(&version.content_type)
        .bind(version.created_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn list_versions_async(&self, file_id: &str) -> Result<Vec<VersionRec>, sqlx::Error> {
        let rows = sqlx::query(&format!(
            "SELECT {VERSION_COLS} FROM file_versions WHERE file_id = $1 \
             ORDER BY created_at DESC, id DESC"
        ))
        .bind(file_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::version_from_row).collect()
    }

    async fn get_version_async(
        &self,
        version_id: &str,
        file_id: &str,
    ) -> Result<Option<VersionRec>, sqlx::Error> {
        let row = sqlx::query(&format!(
            "SELECT {VERSION_COLS} FROM file_versions WHERE id = $1 AND file_id = $2"
        ))
        .bind(version_id)
        .bind(file_id)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::version_from_row).transpose()
    }

    async fn delete_version_async(
        &self,
        version_id: &str,
        file_id: &str,
    ) -> Result<Option<VersionRec>, sqlx::Error> {
        let existing = self.get_version_async(version_id, file_id).await?;
        if existing.is_some() {
            sqlx::query("DELETE FROM file_versions WHERE id = $1 AND file_id = $2")
                .bind(version_id)
                .bind(file_id)
                .execute(&self.pool)
                .await?;
        }
        Ok(existing)
    }

    async fn prune_versions_async(
        &self,
        file_id: &str,
        keep: i64,
    ) -> Result<Vec<VersionRec>, sqlx::Error> {
        let all = self.list_versions_async(file_id).await?; // newest-first
        let keep = keep.max(0) as usize;
        let pruned: Vec<VersionRec> = all.into_iter().skip(keep).collect();
        for v in &pruned {
            sqlx::query("DELETE FROM file_versions WHERE id = $1")
                .bind(&v.id)
                .execute(&self.pool)
                .await?;
        }
        Ok(pruned)
    }

    async fn delete_versions_for_file_async(
        &self,
        file_id: &str,
    ) -> Result<Vec<VersionRec>, sqlx::Error> {
        let all = self.list_versions_async(file_id).await?;
        if !all.is_empty() {
            sqlx::query("DELETE FROM file_versions WHERE file_id = $1")
                .bind(file_id)
                .execute(&self.pool)
                .await?;
        }
        Ok(all)
    }

    async fn move_file_async(
        &self,
        id: &str,
        owner_sub: &str,
        folder_id: Option<&str>,
    ) -> Result<bool, sqlx::Error> {
        let updated_at = mutation_time();
        let result = sqlx::query(
            "UPDATE files SET folder_id = $1, \
             updated_at = CASE WHEN updated_at = 9223372036854775807 THEN updated_at \
                               WHEN updated_at >= $2 THEN updated_at + 1 ELSE $2 END \
             WHERE id = $3 AND owner_sub = $4",
        )
        .bind(folder_id)
        .bind(updated_at)
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

    async fn usage_for_owner_async(&self, owner_sub: &str) -> Result<i64, sqlx::Error> {
        // SUM(BIGINT) widens to NUMERIC in PostgreSQL; the CAST keeps the decoded type BIGINT.
        // Current file bytes + retained version blobs of the owner's files (two portable SUMs).
        let files_row = sqlx::query(
            "SELECT CAST(COALESCE(SUM(size), 0) AS BIGINT) AS bytes \
             FROM files WHERE owner_sub = $1",
        )
        .bind(owner_sub)
        .fetch_one(&self.pool)
        .await?;
        let file_bytes: i64 = files_row.try_get("bytes")?;
        let ver_row = sqlx::query(
            "SELECT CAST(COALESCE(SUM(v.size), 0) AS BIGINT) AS bytes \
             FROM file_versions v JOIN files f ON v.file_id = f.id WHERE f.owner_sub = $1",
        )
        .bind(owner_sub)
        .fetch_one(&self.pool)
        .await?;
        let version_bytes: i64 = ver_row.try_get("bytes")?;
        Ok(file_bytes + version_bytes)
    }

    async fn usage_by_owner_async(&self) -> Result<Vec<OwnerUsage>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT owner_sub, \
                    CAST(COALESCE(SUM(CASE WHEN trashed_at = 0 THEN 1 ELSE 0 END), 0) AS BIGINT) AS files, \
                    CAST(COALESCE(SUM(size), 0) AS BIGINT) AS bytes \
             FROM files GROUP BY owner_sub ORDER BY bytes DESC, owner_sub ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out: Vec<OwnerUsage> = rows
            .iter()
            .map(|row| {
                Ok(OwnerUsage {
                    owner_sub: row.try_get("owner_sub")?,
                    files: row.try_get("files")?,
                    bytes: row.try_get("bytes")?,
                })
            })
            .collect::<Result<_, sqlx::Error>>()?;
        // Fold retained version bytes into each owner's total (a separate portable aggregate).
        let vrows = sqlx::query(
            "SELECT f.owner_sub AS owner_sub, CAST(COALESCE(SUM(v.size), 0) AS BIGINT) AS bytes \
             FROM file_versions v JOIN files f ON v.file_id = f.id GROUP BY f.owner_sub",
        )
        .fetch_all(&self.pool)
        .await?;
        for row in &vrows {
            let owner: String = row.try_get("owner_sub")?;
            let bytes: i64 = row.try_get("bytes")?;
            if let Some(u) = out.iter_mut().find(|u| u.owner_sub == owner) {
                u.bytes += bytes;
            }
        }
        out.sort_by(|a, b| {
            b.bytes
                .cmp(&a.bytes)
                .then_with(|| a.owner_sub.cmp(&b.owner_sub))
        });
        Ok(out)
    }

    async fn get_quota_async(&self, owner_sub: &str) -> Result<Option<i64>, sqlx::Error> {
        let row = sqlx::query("SELECT quota_bytes FROM owner_quotas WHERE owner_sub = $1")
            .bind(owner_sub)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|r| r.try_get("quota_bytes")).transpose()
    }

    async fn set_quota_async(
        &self,
        owner_sub: &str,
        quota_bytes: Option<i64>,
    ) -> Result<(), sqlx::Error> {
        match quota_bytes {
            // Upsert the override row (standard ON CONFLICT .. DO UPDATE on the primary key).
            Some(q) => {
                sqlx::query(
                    "INSERT INTO owner_quotas (owner_sub, quota_bytes) VALUES ($1, $2) \
                     ON CONFLICT (owner_sub) DO UPDATE SET quota_bytes = EXCLUDED.quota_bytes",
                )
                .bind(owner_sub)
                .bind(q)
                .execute(&self.pool)
                .await?;
            }
            // Clear the override: the owner falls back to the configured default.
            None => {
                sqlx::query("DELETE FROM owner_quotas WHERE owner_sub = $1")
                    .bind(owner_sub)
                    .execute(&self.pool)
                    .await?;
            }
        }
        Ok(())
    }

    async fn list_quotas_async(&self) -> Result<Vec<(String, i64)>, sqlx::Error> {
        let rows =
            sqlx::query("SELECT owner_sub, quota_bytes FROM owner_quotas ORDER BY owner_sub ASC")
                .fetch_all(&self.pool)
                .await?;
        rows.iter()
            .map(|row| Ok((row.try_get("owner_sub")?, row.try_get("quota_bytes")?)))
            .collect()
    }

    async fn create_comment_async(&self, comment: &FileComment) -> Result<bool, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(
            "INSERT INTO file_comments (id, file_id, author_sub, body, created_at) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
        )
        .bind(&comment.id)
        .bind(&comment.file_id)
        .bind(&comment.author_sub)
        .bind(&comment.body)
        .bind(comment.created_at)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(false);
        }
        let updated_at = mutation_time();
        let touched = sqlx::query(
            "UPDATE files SET updated_at = CASE WHEN updated_at = 9223372036854775807 THEN updated_at \
                                                 WHEN updated_at >= $1 THEN updated_at + 1 ELSE $1 END \
             WHERE id = $2",
        )
        .bind(updated_at)
        .bind(&comment.file_id)
        .execute(&mut *tx)
        .await?;
        if touched.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(false);
        }
        tx.commit().await?;
        Ok(true)
    }

    async fn list_comments_async(&self, file_id: &str) -> Result<Vec<FileComment>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, file_id, author_sub, body, created_at FROM file_comments \
             WHERE file_id = $1 ORDER BY created_at ASC, id ASC",
        )
        .bind(file_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::comment_from_row).collect()
    }

    async fn get_comment_async(
        &self,
        comment_id: &str,
    ) -> Result<Option<FileComment>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT id, file_id, author_sub, body, created_at FROM file_comments WHERE id = $1",
        )
        .bind(comment_id)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::comment_from_row).transpose()
    }

    async fn delete_comment_async(
        &self,
        comment_id: &str,
        file_id: &str,
    ) -> Result<bool, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query("DELETE FROM file_comments WHERE id = $1 AND file_id = $2")
            .bind(comment_id)
            .bind(file_id)
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(false);
        }
        let updated_at = mutation_time();
        sqlx::query(
            "UPDATE files SET updated_at = CASE WHEN updated_at = 9223372036854775807 THEN updated_at \
                                                 WHEN updated_at >= $1 THEN updated_at + 1 ELSE $1 END \
             WHERE id = $2",
        )
        .bind(updated_at)
        .bind(file_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    async fn delete_comments_for_file_async(&self, file_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM file_comments WHERE file_id = $1")
            .bind(file_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn create_upload_request_async(
        &self,
        request: &UploadRequestRec,
    ) -> Result<bool, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        Self::lock_owner_storage_guard_tx(&mut tx, &request.owner_sub).await?;
        let result = sqlx::query(
            "INSERT INTO upload_requests \
                 (id, owner_sub, folder_id, token, title, description, status, expires_at, \
                  max_file_bytes, max_total_bytes, max_files, used_bytes, used_files, \
                  allowed_types, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) \
             ON CONFLICT DO NOTHING",
        )
        .bind(&request.id)
        .bind(&request.owner_sub)
        .bind(&request.folder_id)
        .bind(&request.token)
        .bind(&request.title)
        .bind(&request.description)
        .bind(&request.status)
        .bind(request.expires_at)
        .bind(request.max_file_bytes)
        .bind(request.max_total_bytes)
        .bind(request.max_files)
        .bind(request.used_bytes)
        .bind(request.used_files)
        .bind(&request.allowed_types)
        .bind(request.created_at)
        .bind(request.updated_at)
        .execute(&mut *tx)
        .await?;
        let inserted = result.rows_affected() == 1;
        if !inserted {
            tx.rollback().await?;
            return Ok(false);
        }
        if sqlx::query(
            "SELECT 1 FROM folders WHERE id = $1 AND owner_sub = $2 AND trashed_at = 0 \
             AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL FOR UPDATE",
        )
        .bind(&request.folder_id)
        .bind(&request.owner_sub)
        .fetch_optional(&mut *tx)
        .await?
        .is_none()
        {
            tx.rollback().await?;
            return Ok(false);
        }
        tx.commit().await?;
        Ok(true)
    }

    async fn list_upload_requests_async(
        &self,
        owner_sub: &str,
    ) -> Result<Vec<UploadRequestRec>, sqlx::Error> {
        let rows = sqlx::query(&format!(
            "SELECT {UPLOAD_REQUEST_COLS} FROM upload_requests WHERE owner_sub = $1 \
             ORDER BY updated_at DESC, id DESC"
        ))
        .bind(owner_sub)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::upload_request_from_row).collect()
    }

    async fn upload_request_inbox_async(
        &self,
        owner_sub: &str,
        view: UploadRequestInboxView,
        as_of: i64,
    ) -> Result<UploadRequestInbox, sqlx::Error> {
        // One statement gives the bounded page and every tab count the same PostgreSQL snapshot
        // and the same explicit classification instant. The CTE deliberately never selects the
        // raw token, owner, destination folder, MIME policy, or any storage column.
        let rows = sqlx::query(
            r#"WITH classified AS (
                   SELECT id, title, description, expires_at, max_total_bytes, max_files,
                          used_bytes, used_files, updated_at,
                          CASE
                            WHEN status <> 'open' THEN 'closed'
                            WHEN expires_at IS NOT NULL AND expires_at <= $2 THEN 'expired'
                            WHEN expires_at IS NOT NULL AND expires_at <= $3 THEN 'expiring'
                            ELSE 'open'
                          END AS inbox_state
                     FROM upload_requests
                    WHERE owner_sub = $1
                 ), totals AS (
                   SELECT COUNT(*)::BIGINT AS all_count,
                          COUNT(*) FILTER (WHERE inbox_state = 'open')::BIGINT AS open_count,
                          COUNT(*) FILTER (WHERE inbox_state = 'expiring')::BIGINT AS expiring_count,
                          COUNT(*) FILTER (WHERE inbox_state = 'closed')::BIGINT AS closed_count,
                          COUNT(*) FILTER (WHERE inbox_state = 'expired')::BIGINT AS expired_count
                     FROM classified
                 ), page AS (
                   SELECT *
                     FROM classified
                    WHERE $4 = 'all' OR inbox_state = $4
                    ORDER BY updated_at DESC, id DESC
                    LIMIT $5
                 )
                 SELECT page.id, page.title, page.description, page.inbox_state,
                        page.expires_at, page.max_total_bytes, page.max_files,
                        page.used_bytes, page.used_files, page.updated_at,
                        totals.all_count, totals.open_count, totals.expiring_count,
                        totals.closed_count, totals.expired_count
                   FROM totals
                   LEFT JOIN page ON TRUE
                  ORDER BY page.updated_at DESC NULLS LAST, page.id DESC NULLS LAST"#,
        )
        .bind(owner_sub)
        .bind(as_of)
        .bind(as_of.saturating_add(UPLOAD_REQUEST_EXPIRING_WINDOW_SECS))
        .bind(view.slug())
        .bind(UPLOAD_REQUEST_INBOX_CAP)
        .fetch_all(&self.pool)
        .await?;

        let totals = rows
            .first()
            .expect("aggregate-left-join Inbox query always returns one totals row");
        let counts = UploadRequestInboxCounts {
            all: totals.try_get("all_count")?,
            open: totals.try_get("open_count")?,
            expiring: totals.try_get("expiring_count")?,
            closed: totals.try_get("closed_count")?,
            expired: totals.try_get("expired_count")?,
        };
        let mut items = Vec::with_capacity(rows.len().min(UPLOAD_REQUEST_INBOX_CAP as usize));
        for row in rows {
            let Some(id) = row.try_get::<Option<String>, _>("id")? else {
                continue;
            };
            let state = row
                .try_get::<Option<String>, _>("inbox_state")?
                .as_deref()
                .and_then(UploadRequestInboxState::from_slug)
                .ok_or_else(|| sqlx::Error::Decode("unknown upload request Inbox state".into()))?;
            items.push(UploadRequestSummary {
                id,
                title: row
                    .try_get::<Option<String>, _>("title")?
                    .ok_or_else(|| sqlx::Error::Decode("missing Inbox title".into()))?,
                description: row
                    .try_get::<Option<String>, _>("description")?
                    .ok_or_else(|| sqlx::Error::Decode("missing Inbox description".into()))?,
                state,
                expires_at: row.try_get("expires_at")?,
                max_total_bytes: row
                    .try_get::<Option<i64>, _>("max_total_bytes")?
                    .ok_or_else(|| sqlx::Error::Decode("missing Inbox byte budget".into()))?,
                max_files: row
                    .try_get::<Option<i64>, _>("max_files")?
                    .ok_or_else(|| sqlx::Error::Decode("missing Inbox file budget".into()))?,
                used_bytes: row
                    .try_get::<Option<i64>, _>("used_bytes")?
                    .ok_or_else(|| sqlx::Error::Decode("missing Inbox used bytes".into()))?,
                used_files: row
                    .try_get::<Option<i64>, _>("used_files")?
                    .ok_or_else(|| sqlx::Error::Decode("missing Inbox used files".into()))?,
                updated_at: row
                    .try_get::<Option<i64>, _>("updated_at")?
                    .ok_or_else(|| sqlx::Error::Decode("missing Inbox updated time".into()))?,
            });
        }
        let matched_total = counts.for_view(view);
        Ok(UploadRequestInbox {
            as_of,
            view,
            counts,
            matched_total,
            truncated: matched_total > items.len() as i64,
            items,
        })
    }

    async fn get_upload_request_async(
        &self,
        id: &str,
        owner_sub: &str,
    ) -> Result<Option<UploadRequestRec>, sqlx::Error> {
        let row = sqlx::query(&format!(
            "SELECT {UPLOAD_REQUEST_COLS} FROM upload_requests WHERE id = $1 AND owner_sub = $2"
        ))
        .bind(id)
        .bind(owner_sub)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::upload_request_from_row).transpose()
    }

    async fn get_upload_request_by_token_async(
        &self,
        token: &str,
    ) -> Result<Option<UploadRequestRec>, sqlx::Error> {
        let row = sqlx::query(&format!(
            "SELECT {UPLOAD_REQUEST_COLS} FROM upload_requests WHERE token = $1"
        ))
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::upload_request_from_row).transpose()
    }

    async fn update_upload_request_async(
        &self,
        request: &UploadRequestRec,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE upload_requests \
             SET title = $1, description = $2, expires_at = $3, max_file_bytes = $4, \
                 max_total_bytes = $5, max_files = $6, allowed_types = $7, updated_at = $8 \
             WHERE id = $9 AND owner_sub = $10 AND used_bytes <= $5 AND used_files <= $6",
        )
        .bind(&request.title)
        .bind(&request.description)
        .bind(request.expires_at)
        .bind(request.max_file_bytes)
        .bind(request.max_total_bytes)
        .bind(request.max_files)
        .bind(&request.allowed_types)
        .bind(request.updated_at)
        .bind(&request.id)
        .bind(&request.owner_sub)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn set_upload_request_status_async(
        &self,
        id: &str,
        owner_sub: &str,
        status: &str,
        updated_at: i64,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE upload_requests SET status = $1, updated_at = $2 \
             WHERE id = $3 AND owner_sub = $4",
        )
        .bind(status)
        .bind(updated_at)
        .bind(id)
        .bind(owner_sub)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn reopen_upload_request_async(
        &self,
        id: &str,
        owner_sub: &str,
        now: i64,
        renewed_expires_at: i64,
    ) -> Result<bool, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let request = sqlx::query(
            "SELECT folder_id FROM upload_requests WHERE id = $1 AND owner_sub = $2 FOR UPDATE",
        )
        .bind(id)
        .bind(owner_sub)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(request) = request else {
            tx.rollback().await?;
            return Ok(false);
        };
        let folder_id: String = request.try_get("folder_id")?;
        if sqlx::query(
            "SELECT 1 FROM folders WHERE id = $1 AND owner_sub = $2 AND trashed_at = 0 \
             AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL FOR UPDATE",
        )
        .bind(&folder_id)
        .bind(owner_sub)
        .fetch_optional(&mut *tx)
        .await?
        .is_none()
        {
            tx.rollback().await?;
            return Ok(false);
        }
        let result = sqlx::query(
            "UPDATE upload_requests \
             SET status = 'open', \
                 expires_at = CASE \
                     WHEN expires_at IS NOT NULL AND expires_at <= $1 THEN $2 \
                     ELSE expires_at \
                 END, \
                 updated_at = $1 \
             WHERE id = $3 AND owner_sub = $4",
        )
        .bind(now)
        .bind(renewed_expires_at)
        .bind(id)
        .bind(owner_sub)
        .execute(&mut *tx)
        .await?;
        let changed = result.rows_affected() == 1;
        tx.commit().await?;
        Ok(changed)
    }

    async fn rotate_upload_request_token_async(
        &self,
        id: &str,
        owner_sub: &str,
        expected_token: &str,
        token: &str,
        updated_at: i64,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE upload_requests SET token = $1, updated_at = $2 \
             WHERE id = $3 AND owner_sub = $4 AND token = $5 \
               AND NOT EXISTS (SELECT 1 FROM upload_requests WHERE token = $1 AND id <> $3)",
        )
        .bind(token)
        .bind(updated_at)
        .bind(id)
        .bind(owner_sub)
        .bind(expected_token)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn list_upload_submissions_async(
        &self,
        request_id: &str,
        owner_sub: &str,
    ) -> Result<Vec<UploadSubmission>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT s.id, s.request_id, s.file_id, s.name, s.content_type, s.size, s.created_at \
             FROM upload_submissions s \
             JOIN upload_requests r ON r.id = s.request_id \
             WHERE s.request_id = $1 AND r.owner_sub = $2 \
             ORDER BY s.created_at DESC, s.id DESC",
        )
        .bind(request_id)
        .bind(owner_sub)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::upload_submission_from_row).collect()
    }

    async fn reserve_request_upload_async(
        &self,
        input: UploadReserveInput<'_>,
    ) -> Result<UploadReserve, sqlx::Error> {
        let UploadReserveInput {
            request_id,
            expected_token,
            reservation_id,
            size,
            content_type,
            content_type_verified,
            owner_quota,
            now,
        } = input;
        let mut tx = self.pool.begin().await?;
        // Unlocked hint discovers the immutable owner key. The authoritative request is re-read
        // after taking the owner guard, establishing guard -> request -> folder/reservation order.
        let owner_hint = sqlx::query("SELECT owner_sub FROM upload_requests WHERE id = $1")
            .bind(request_id)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(owner_hint) = owner_hint else {
            tx.rollback().await?;
            return Ok(UploadReserve::Unavailable);
        };
        let owner_hint: String = owner_hint.try_get("owner_sub")?;
        Self::lock_owner_storage_guard_tx(&mut tx, &owner_hint).await?;
        let request_row = sqlx::query(&format!(
            "SELECT {UPLOAD_REQUEST_COLS} FROM upload_requests WHERE id = $1 FOR UPDATE"
        ))
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(request_row) = request_row else {
            tx.rollback().await?;
            return Ok(UploadReserve::Unavailable);
        };
        let request = Self::upload_request_from_row(&request_row)?;
        if request.owner_sub != owner_hint
            || !capability_token_eq(&request.token, expected_token)
            || !request.is_open()
            || request.is_expired(now)
        {
            tx.rollback().await?;
            return Ok(UploadReserve::Unavailable);
        }
        if size <= 0 || size > request.max_file_bytes {
            tx.rollback().await?;
            return Ok(UploadReserve::FileTooLarge);
        }
        if (!content_type_verified && !request_allows_unverified_type(&request))
            || !request.accepts_content_type(content_type)
        {
            tx.rollback().await?;
            return Ok(UploadReserve::TypeDenied);
        }
        if request.used_bytes.saturating_add(size) > request.max_total_bytes {
            tx.rollback().await?;
            return Ok(UploadReserve::TotalBudgetExceeded);
        }
        if request.used_files.saturating_add(1) > request.max_files {
            tx.rollback().await?;
            return Ok(UploadReserve::FileCountExceeded);
        }

        if sqlx::query(
            "SELECT 1 FROM folders WHERE id = $1 AND owner_sub = $2 AND trashed_at = 0 \
             AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL FOR UPDATE",
        )
        .bind(&request.folder_id)
        .bind(&request.owner_sub)
        .fetch_optional(&mut *tx)
        .await?
        .is_none()
        {
            tx.rollback().await?;
            return Ok(UploadReserve::Unavailable);
        }

        Self::lock_blob_key_guard_tx(&mut tx, reservation_id).await?;

        if sqlx::query(
            "SELECT 1 WHERE \
                 EXISTS (SELECT 1 FROM files WHERE id = $1 OR object_key = $1) OR \
                 EXISTS (SELECT 1 FROM file_versions WHERE object_key = $1) OR \
                 EXISTS (SELECT 1 FROM owner_blob_write_intents WHERE object_key = $1) OR \
                 EXISTS (SELECT 1 FROM blob_delete_queue WHERE object_key = $1)",
        )
        .bind(reservation_id)
        .fetch_optional(&mut *tx)
        .await?
        .is_some()
        {
            tx.rollback().await?;
            return Ok(UploadReserve::Collision);
        }

        if let Some(quota) = owner_quota {
            let used = Self::owner_usage_with_pending_tx(&mut tx, &request.owner_sub).await?;
            if used.saturating_add(size) > quota {
                tx.rollback().await?;
                return Ok(UploadReserve::OwnerQuotaExceeded);
            }
        }

        let inserted = sqlx::query(
            "INSERT INTO upload_reservations (id, request_id, owner_sub, size, created_at) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
        )
        .bind(reservation_id)
        .bind(&request.id)
        .bind(&request.owner_sub)
        .bind(size)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        if inserted.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(UploadReserve::Collision);
        }
        sqlx::query(
            "UPDATE upload_requests \
             SET used_bytes = used_bytes + $1, used_files = used_files + 1, updated_at = $2 \
             WHERE id = $3",
        )
        .bind(size)
        .bind(now)
        .bind(&request.id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(UploadReserve::Reserved)
    }

    async fn commit_request_upload_async(
        &self,
        reservation_id: &str,
        file: &FileRec,
        submission: &UploadSubmission,
    ) -> Result<bool, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        // Peek only to discover immutable lock keys, then re-read every value under the canonical
        // owner guard -> request -> reservation -> folder/file order.
        let reservation_hint = sqlx::query(
            "SELECT request_id, owner_sub, size FROM upload_reservations \
             WHERE id = $1 AND recovery_lease IS NULL",
        )
        .bind(reservation_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(reservation_hint) = reservation_hint else {
            tx.rollback().await?;
            return Ok(false);
        };
        let request_id: String = reservation_hint.try_get("request_id")?;
        let owner_sub: String = reservation_hint.try_get("owner_sub")?;
        let reserved_size: i64 = reservation_hint.try_get("size")?;
        if file.id != reservation_id
            || file.object_key != reservation_id
            || file.owner_sub != owner_sub
            || file.size != reserved_size
            || !file.is_effectively_live()
            || submission.request_id != request_id
            || submission.file_id != file.id
            || submission.name != file.name
            || submission.content_type != file.content_type
            || submission.size != file.size
        {
            tx.rollback().await?;
            return Ok(false);
        }

        Self::lock_owner_storage_guard_tx(&mut tx, &owner_sub).await?;

        let request_locked = sqlx::query(
            "SELECT id, owner_sub, folder_id FROM upload_requests WHERE id = $1 FOR UPDATE",
        )
        .bind(&request_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(request_locked) = request_locked else {
            tx.rollback().await?;
            return Ok(false);
        };
        if request_locked.try_get::<String, _>("owner_sub")? != owner_sub {
            tx.rollback().await?;
            return Ok(false);
        }
        let destination_id: String = request_locked.try_get("folder_id")?;
        if file.folder_id.as_deref() != Some(destination_id.as_str()) {
            tx.rollback().await?;
            return Ok(false);
        }

        let reservation = sqlx::query(
            "SELECT request_id, owner_sub, size FROM upload_reservations \
             WHERE id = $1 AND recovery_lease IS NULL FOR UPDATE",
        )
        .bind(reservation_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(reservation) = reservation else {
            tx.rollback().await?;
            return Ok(false);
        };
        if reservation.try_get::<String, _>("request_id")? != request_id
            || reservation.try_get::<String, _>("owner_sub")? != owner_sub
            || reservation.try_get::<i64, _>("size")? != reserved_size
        {
            tx.rollback().await?;
            return Ok(false);
        }

        if sqlx::query(
            "SELECT 1 FROM folders WHERE id = $1 AND owner_sub = $2 AND trashed_at = 0 \
             AND trash_entry_id IS NULL AND trash_ancestor_id IS NULL FOR UPDATE",
        )
        .bind(&destination_id)
        .bind(&owner_sub)
        .fetch_optional(&mut *tx)
        .await?
        .is_none()
        {
            tx.rollback().await?;
            return Ok(false);
        }

        let inserted_file = sqlx::query(
            "INSERT INTO files \
                 (id, owner_sub, name, content_type, size, bucket, object_key, share_token, \
                  created_at, updated_at, expires_at, share_password_hash, folder_id, trashed_at, \
                  trash_entry_id, trash_ancestor_id, view_count) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17) \
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
        .bind(file.updated_at)
        .bind(file.expires_at)
        .bind(&file.share_password_hash)
        .bind(&file.folder_id)
        .bind(file.trashed_at)
        .bind(&file.trash_entry_id)
        .bind(&file.trash_ancestor_id)
        .bind(file.view_count)
        .execute(&mut *tx)
        .await?;
        if inserted_file.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(false);
        }
        let inserted_receipt = sqlx::query(
            "INSERT INTO upload_submissions \
                 (id, request_id, file_id, name, content_type, size, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
        )
        .bind(&submission.id)
        .bind(&submission.request_id)
        .bind(&submission.file_id)
        .bind(&submission.name)
        .bind(&submission.content_type)
        .bind(submission.size)
        .bind(submission.created_at)
        .execute(&mut *tx)
        .await?;
        if inserted_receipt.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(false);
        }
        sqlx::query("DELETE FROM upload_reservations WHERE id = $1")
            .bind(reservation_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    }

    async fn release_request_upload_async(
        &self,
        reservation_id: &str,
    ) -> Result<bool, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let reservation_hint = sqlx::query(
            "SELECT request_id FROM upload_reservations \
             WHERE id = $1 AND recovery_lease IS NULL",
        )
        .bind(reservation_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(reservation_hint) = reservation_hint else {
            tx.rollback().await?;
            return Ok(false);
        };
        let request_id: String = reservation_hint.try_get("request_id")?;
        let request_locked = sqlx::query("SELECT id FROM upload_requests WHERE id = $1 FOR UPDATE")
            .bind(&request_id)
            .fetch_optional(&mut *tx)
            .await?
            .is_some();
        if !request_locked {
            tx.rollback().await?;
            return Ok(false);
        }
        let reservation = sqlx::query(
            "SELECT request_id, size FROM upload_reservations \
             WHERE id = $1 AND recovery_lease IS NULL FOR UPDATE",
        )
        .bind(reservation_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(reservation) = reservation else {
            tx.rollback().await?;
            return Ok(false);
        };
        if reservation.try_get::<String, _>("request_id")? != request_id {
            tx.rollback().await?;
            return Ok(false);
        }
        let size: i64 = reservation.try_get("size")?;
        sqlx::query("DELETE FROM upload_reservations WHERE id = $1")
            .bind(reservation_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE upload_requests \
             SET used_bytes = CASE WHEN used_bytes >= $1 THEN used_bytes - $1 ELSE 0 END, \
                 used_files = CASE WHEN used_files >= 1 THEN used_files - 1 ELSE 0 END \
             WHERE id = $2",
        )
        .bind(size)
        .bind(&request_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    async fn claim_upload_recovery_async(
        &self,
        lease_id: &str,
        leased_at: i64,
        lease_expired_before: i64,
    ) -> Result<UploadRecoveryClaim, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "UPDATE upload_reservations \
             SET recovery_lease = $1, recovery_leased_at = $2 \
             WHERE recovery_lease IS NULL OR recovery_leased_at <= $3",
        )
        .bind(lease_id)
        .bind(leased_at)
        .bind(lease_expired_before)
        .execute(&mut *tx)
        .await?;
        let rows = sqlx::query(
            "SELECT id FROM upload_reservations \
             WHERE recovery_lease = $1 ORDER BY created_at ASC, id ASC",
        )
        .bind(lease_id)
        .fetch_all(&mut *tx)
        .await?;
        let outstanding: i64 =
            sqlx::query("SELECT CAST(COUNT(*) AS BIGINT) AS count FROM upload_reservations")
                .fetch_one(&mut *tx)
                .await?
                .try_get("count")?;
        if outstanding == 0 {
            tx.commit().await?;
            return Ok(UploadRecoveryClaim::Empty);
        }
        if rows.len() as i64 != outstanding {
            // Roll back any rows this worker tentatively claimed. Recovery is all-or-busy: serving
            // must not start while even one outstanding row remains under another live lease.
            tx.rollback().await?;
            return Ok(UploadRecoveryClaim::Busy);
        }
        let claimed = rows
            .iter()
            .map(|row| {
                let id: String = row.try_get("id")?;
                Ok(UploadRecoveryItem {
                    reservation_id: id.clone(),
                    object_key: id,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()?;
        tx.commit().await?;
        Ok(UploadRecoveryClaim::Claimed(claimed))
    }

    async fn complete_upload_recovery_async(
        &self,
        reservation_id: &str,
        lease_id: &str,
    ) -> Result<bool, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let reservation_hint = sqlx::query(
            "SELECT request_id FROM upload_reservations \
             WHERE id = $1 AND recovery_lease = $2",
        )
        .bind(reservation_id)
        .bind(lease_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(reservation_hint) = reservation_hint else {
            tx.rollback().await?;
            return Ok(false);
        };
        let request_id: String = reservation_hint.try_get("request_id")?;
        let request_locked = sqlx::query("SELECT id FROM upload_requests WHERE id = $1 FOR UPDATE")
            .bind(&request_id)
            .fetch_optional(&mut *tx)
            .await?
            .is_some();
        if !request_locked {
            tx.rollback().await?;
            return Ok(false);
        }
        let reservation = sqlx::query(
            "SELECT request_id, size FROM upload_reservations \
             WHERE id = $1 AND recovery_lease = $2 FOR UPDATE",
        )
        .bind(reservation_id)
        .bind(lease_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(reservation) = reservation else {
            tx.rollback().await?;
            return Ok(false);
        };
        if reservation.try_get::<String, _>("request_id")? != request_id {
            tx.rollback().await?;
            return Ok(false);
        }
        let size: i64 = reservation.try_get("size")?;
        sqlx::query("DELETE FROM upload_reservations WHERE id = $1 AND recovery_lease = $2")
            .bind(reservation_id)
            .bind(lease_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE upload_requests \
             SET used_bytes = CASE WHEN used_bytes >= $1 THEN used_bytes - $1 ELSE 0 END, \
                 used_files = CASE WHEN used_files >= 1 THEN used_files - 1 ELSE 0 END \
             WHERE id = $2",
        )
        .bind(size)
        .bind(&request_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    async fn abandon_upload_recovery_async(
        &self,
        reservation_id: &str,
        lease_id: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE upload_reservations \
             SET recovery_lease = NULL, recovery_leased_at = NULL \
             WHERE id = $1 AND recovery_lease = $2",
        )
        .bind(reservation_id)
        .bind(lease_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }
}

#[async_trait]
impl Store for PgStore {
    async fn create(&self, file: &FileRec) -> Result<bool, StoreError> {
        self.create_async(file)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn reserve_owner_blob_write(
        &self,
        intent: &OwnerBlobWriteIntent,
        owner_quota: Option<i64>,
    ) -> Result<OwnerBlobCommit, StoreError> {
        self.reserve_owner_blob_write_async(intent, owner_quota)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn commit_owner_upload(
        &self,
        file: &FileRec,
        owner_quota: Option<i64>,
    ) -> Result<OwnerBlobCommit, StoreError> {
        self.commit_owner_upload_async(file, owner_quota)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn commit_owner_reupload(
        &self,
        input: OwnerReuploadInput<'_>,
    ) -> Result<OwnerBlobCommit, StoreError> {
        self.commit_owner_reupload_async(input)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn commit_owner_version_restore(
        &self,
        input: OwnerVersionRestoreInput<'_>,
    ) -> Result<OwnerBlobCommit, StoreError> {
        self.commit_owner_version_restore_async(input)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn finalize_owner_thumbnail(
        &self,
        object_key: &str,
        owner_sub: &str,
        file_id: &str,
        expected_object_key: &str,
    ) -> Result<OwnerBlobCommit, StoreError> {
        self.finalize_owner_thumbnail_async(object_key, owner_sub, file_id, expected_object_key)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn enqueue_blob_deletion(
        &self,
        object_key: &str,
        enqueued_at: i64,
        reason: &str,
    ) -> Result<(), StoreError> {
        self.enqueue_blob_deletion_async(object_key, enqueued_at, reason)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn claim_owner_blob_writes(
        &self,
        lease_id: &str,
        now: i64,
        created_before: i64,
        lease_expired_before: i64,
        limit: i64,
    ) -> Result<Vec<OwnerBlobWriteIntent>, StoreError> {
        self.claim_owner_blob_writes_async(
            lease_id,
            now,
            created_before,
            lease_expired_before,
            limit,
        )
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn complete_owner_blob_write(
        &self,
        object_key: &str,
        lease_id: &str,
    ) -> Result<bool, StoreError> {
        self.complete_owner_blob_write_async(object_key, lease_id)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn abandon_owner_blob_write(
        &self,
        object_key: &str,
        lease_id: &str,
        retry_at: i64,
    ) -> Result<bool, StoreError> {
        self.abandon_owner_blob_write_async(object_key, lease_id, retry_at)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn query_library(
        &self,
        owner_sub: &str,
        query: &LibraryQuery,
    ) -> Result<LibraryPage, StoreError> {
        self.query_library_async(owner_sub, query)
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

    async fn bump_view_count(&self, id: &str) -> Result<(), StoreError> {
        self.bump_view_count_async(id)
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

    async fn trash_file(
        &self,
        id: &str,
        owner_sub: &str,
        trashed_at: i64,
    ) -> Result<bool, StoreError> {
        self.trash_file_async(id, owner_sub, trashed_at)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn restore_file(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError> {
        self.restore_file_async(id, owner_sub)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn rename_file(&self, id: &str, owner_sub: &str, name: &str) -> Result<bool, StoreError> {
        self.rename_file_async(id, owner_sub, name)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_trashed_by_owner(&self, owner_sub: &str) -> Result<Vec<FileRec>, StoreError> {
        self.list_trashed_by_owner_async(owner_sub)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn query_trash(
        &self,
        owner_sub: &str,
        before: Option<&LibraryCursor>,
        limit: i64,
    ) -> Result<TrashPage, StoreError> {
        self.query_trash_async(owner_sub, before, limit)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn bulk_trash(
        &self,
        owner_sub: &str,
        roots: &[TrashRootInput],
        trashed_at: i64,
        purge_after: i64,
    ) -> Result<BulkMutation, StoreError> {
        self.bulk_trash_async(owner_sub, roots, trashed_at, purge_after)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn bulk_restore(
        &self,
        owner_sub: &str,
        items: &[DriveItemRef],
    ) -> Result<BulkMutation, StoreError> {
        self.bulk_restore_async(owner_sub, items)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn bulk_move(
        &self,
        owner_sub: &str,
        items: &[DriveItemRef],
        folder_id: Option<&str>,
    ) -> Result<BulkMutation, StoreError> {
        self.bulk_move_async(owner_sub, items, folder_id)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn bulk_purge(
        &self,
        owner_sub: &str,
        items: &[DriveItemRef],
        enqueued_at: i64,
    ) -> Result<BulkMutation, StoreError> {
        self.bulk_purge_async(owner_sub, items, enqueued_at)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn claim_expired_trash(
        &self,
        lease_id: &str,
        now: i64,
        lease_expired_before: i64,
        limit: i64,
    ) -> Result<Vec<TrashEntry>, StoreError> {
        self.claim_expired_trash_async(lease_id, now, lease_expired_before, limit)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn abandon_trash_claim(
        &self,
        entry_id: &str,
        lease_id: &str,
    ) -> Result<bool, StoreError> {
        self.abandon_trash_claim_async(entry_id, lease_id)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn claim_blob_deletions(
        &self,
        lease_id: &str,
        now: i64,
        lease_expired_before: i64,
        limit: i64,
    ) -> Result<BlobDeleteClaim, StoreError> {
        self.claim_blob_deletions_async(lease_id, now, lease_expired_before, limit)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn complete_blob_deletion(
        &self,
        object_key: &str,
        lease_id: &str,
    ) -> Result<bool, StoreError> {
        self.complete_blob_deletion_async(object_key, lease_id)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn abandon_blob_deletion(
        &self,
        object_key: &str,
        lease_id: &str,
        retry_at: i64,
    ) -> Result<bool, StoreError> {
        self.abandon_blob_deletion_async(object_key, lease_id, retry_at)
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

    async fn get_folder(&self, id: &str, owner_sub: &str) -> Result<Option<FolderRec>, StoreError> {
        self.get_folder_async(id, owner_sub)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get_folder_any(
        &self,
        id: &str,
        owner_sub: &str,
    ) -> Result<Option<FolderRec>, StoreError> {
        self.get_folder_any_async(id, owner_sub)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get_folder_by_token(&self, token: &str) -> Result<Option<FolderRec>, StoreError> {
        self.get_folder_by_token_async(token)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get_folder_by_upload_token(
        &self,
        token: &str,
    ) -> Result<Option<FolderRec>, StoreError> {
        self.get_folder_by_upload_token_async(token)
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

    async fn configure_folder_share(
        &self,
        id: &str,
        owner_sub: &str,
        share_token: Option<String>,
        expires_at: Option<i64>,
        share_password_hash: Option<String>,
    ) -> Result<bool, StoreError> {
        self.configure_folder_share_async(
            id,
            owner_sub,
            share_token,
            expires_at,
            share_password_hash,
        )
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn configure_folder_upload(
        &self,
        id: &str,
        owner_sub: &str,
        upload_token: Option<String>,
    ) -> Result<bool, StoreError> {
        self.configure_folder_upload_async(id, owner_sub, upload_token)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn delete_folder_if_empty(
        &self,
        id: &str,
        owner_sub: &str,
    ) -> Result<FolderDelete, StoreError> {
        self.delete_folder_if_empty_async(id, owner_sub)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn delete_folder_cascade(
        &self,
        id: &str,
        owner_sub: &str,
    ) -> Result<Vec<String>, StoreError> {
        self.delete_folder_cascade_async(id, owner_sub)
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

    async fn list_files_in_folder(
        &self,
        folder_id: &str,
        owner_sub: &str,
    ) -> Result<Vec<FileRec>, StoreError> {
        self.list_files_in_folder_async(folder_id, owner_sub)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn find_file_in_folder(
        &self,
        owner_sub: &str,
        name: &str,
        folder_id: Option<&str>,
    ) -> Result<Option<FileRec>, StoreError> {
        self.find_file_in_folder_async(owner_sub, name, folder_id)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn update_file_blob(
        &self,
        id: &str,
        owner_sub: &str,
        object_key: &str,
        size: i64,
        content_type: &str,
        updated_at: i64,
    ) -> Result<bool, StoreError> {
        self.update_file_blob_async(id, owner_sub, object_key, size, content_type, updated_at)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn add_version(&self, version: &VersionRec) -> Result<bool, StoreError> {
        self.add_version_async(version)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_versions(&self, file_id: &str) -> Result<Vec<VersionRec>, StoreError> {
        self.list_versions_async(file_id)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get_version(
        &self,
        version_id: &str,
        file_id: &str,
    ) -> Result<Option<VersionRec>, StoreError> {
        self.get_version_async(version_id, file_id)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn delete_version(
        &self,
        version_id: &str,
        file_id: &str,
    ) -> Result<Option<VersionRec>, StoreError> {
        self.delete_version_async(version_id, file_id)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn prune_versions(
        &self,
        file_id: &str,
        keep: i64,
    ) -> Result<Vec<VersionRec>, StoreError> {
        self.prune_versions_async(file_id, keep)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn delete_versions_for_file(&self, file_id: &str) -> Result<Vec<VersionRec>, StoreError> {
        self.delete_versions_for_file_async(file_id)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn usage_for_owner(&self, owner_sub: &str) -> Result<i64, StoreError> {
        self.usage_for_owner_async(owner_sub)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn usage_by_owner(&self) -> Result<Vec<OwnerUsage>, StoreError> {
        self.usage_by_owner_async()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get_quota(&self, owner_sub: &str) -> Result<Option<i64>, StoreError> {
        self.get_quota_async(owner_sub)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn set_quota(&self, owner_sub: &str, quota_bytes: Option<i64>) -> Result<(), StoreError> {
        self.set_quota_async(owner_sub, quota_bytes)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_quotas(&self) -> Result<Vec<(String, i64)>, StoreError> {
        self.list_quotas_async()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn create_comment(&self, comment: &FileComment) -> Result<bool, StoreError> {
        self.create_comment_async(comment)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_comments(&self, file_id: &str) -> Result<Vec<FileComment>, StoreError> {
        self.list_comments_async(file_id)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get_comment(&self, comment_id: &str) -> Result<Option<FileComment>, StoreError> {
        self.get_comment_async(comment_id)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn delete_comment(&self, comment_id: &str, file_id: &str) -> Result<bool, StoreError> {
        self.delete_comment_async(comment_id, file_id)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn delete_comments_for_file(&self, file_id: &str) -> Result<(), StoreError> {
        self.delete_comments_for_file_async(file_id)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn create_upload_request(&self, request: &UploadRequestRec) -> Result<bool, StoreError> {
        self.create_upload_request_async(request)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_upload_requests(
        &self,
        owner_sub: &str,
    ) -> Result<Vec<UploadRequestRec>, StoreError> {
        self.list_upload_requests_async(owner_sub)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn upload_request_inbox(
        &self,
        owner_sub: &str,
        view: UploadRequestInboxView,
        as_of: i64,
    ) -> Result<UploadRequestInbox, StoreError> {
        self.upload_request_inbox_async(owner_sub, view, as_of)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get_upload_request(
        &self,
        id: &str,
        owner_sub: &str,
    ) -> Result<Option<UploadRequestRec>, StoreError> {
        self.get_upload_request_async(id, owner_sub)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get_upload_request_by_token(
        &self,
        token: &str,
    ) -> Result<Option<UploadRequestRec>, StoreError> {
        self.get_upload_request_by_token_async(token)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn update_upload_request(&self, request: &UploadRequestRec) -> Result<bool, StoreError> {
        self.update_upload_request_async(request)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn set_upload_request_status(
        &self,
        id: &str,
        owner_sub: &str,
        status: &str,
        updated_at: i64,
    ) -> Result<bool, StoreError> {
        self.set_upload_request_status_async(id, owner_sub, status, updated_at)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn reopen_upload_request(
        &self,
        id: &str,
        owner_sub: &str,
        now: i64,
        renewed_expires_at: i64,
    ) -> Result<bool, StoreError> {
        self.reopen_upload_request_async(id, owner_sub, now, renewed_expires_at)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn rotate_upload_request_token(
        &self,
        id: &str,
        owner_sub: &str,
        expected_token: &str,
        token: &str,
        updated_at: i64,
    ) -> Result<bool, StoreError> {
        self.rotate_upload_request_token_async(id, owner_sub, expected_token, token, updated_at)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_upload_submissions(
        &self,
        request_id: &str,
        owner_sub: &str,
    ) -> Result<Vec<UploadSubmission>, StoreError> {
        self.list_upload_submissions_async(request_id, owner_sub)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn reserve_request_upload(
        &self,
        input: UploadReserveInput<'_>,
    ) -> Result<UploadReserve, StoreError> {
        self.reserve_request_upload_async(input)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn commit_request_upload(
        &self,
        reservation_id: &str,
        file: &FileRec,
        submission: &UploadSubmission,
    ) -> Result<bool, StoreError> {
        self.commit_request_upload_async(reservation_id, file, submission)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn release_request_upload(&self, reservation_id: &str) -> Result<bool, StoreError> {
        self.release_request_upload_async(reservation_id)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn claim_upload_recovery(
        &self,
        lease_id: &str,
        leased_at: i64,
        lease_expired_before: i64,
    ) -> Result<UploadRecoveryClaim, StoreError> {
        self.claim_upload_recovery_async(lease_id, leased_at, lease_expired_before)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn complete_upload_recovery(
        &self,
        reservation_id: &str,
        lease_id: &str,
    ) -> Result<bool, StoreError> {
        self.complete_upload_recovery_async(reservation_id, lease_id)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn abandon_upload_recovery(
        &self,
        reservation_id: &str,
        lease_id: &str,
    ) -> Result<bool, StoreError> {
        self.abandon_upload_recovery_async(reservation_id, lease_id)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutation_clock_saturates_without_overflow() {
        assert_eq!(next_mutation_time(i64::MAX), i64::MAX);
    }

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
            updated_at: created_at,
            expires_at: None,
            share_password_hash: None,
            folder_id: None,
            trashed_at: 0,
            trash_entry_id: None,
            trash_ancestor_id: None,
            view_count: 0,
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
            s.create(&file(id, "u", &format!("t-{id}"), ts))
                .await
                .unwrap();
        }
        // Page 1 (newest 2).
        let p1 = s.list_by_owner("u", None, None, 2).await.unwrap();
        assert_eq!(
            p1.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(),
            vec!["e", "d"]
        );
        // Cursor = last (oldest) row of page 1 -> next 2, strictly older.
        let c1 = p1.last().unwrap();
        let p2 = s
            .list_by_owner("u", None, Some((c1.created_at, c1.id.clone())), 2)
            .await
            .unwrap();
        assert_eq!(
            p2.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(),
            vec!["c", "b"]
        );
        // Final partial page.
        let c2 = p2.last().unwrap();
        let p3 = s
            .list_by_owner("u", None, Some((c2.created_at, c2.id.clone())), 2)
            .await
            .unwrap();
        assert_eq!(
            p3.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(),
            vec!["a"]
        );
    }

    #[tokio::test]
    async fn cursor_tiebreaks_on_id_when_created_at_collides() {
        let s = InMemoryStore::new();
        // Identical created_at: ordering falls back to id DESC => c, b, a.
        s.create(&file("a", "u", "ta", 100)).await.unwrap();
        s.create(&file("b", "u", "tb", 100)).await.unwrap();
        s.create(&file("c", "u", "tc", 100)).await.unwrap();
        let p1 = s.list_by_owner("u", None, None, 2).await.unwrap();
        assert_eq!(
            p1.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(),
            vec!["c", "b"]
        );
        let c1 = p1.last().unwrap();
        let p2 = s
            .list_by_owner("u", None, Some((c1.created_at, c1.id.clone())), 2)
            .await
            .unwrap();
        assert_eq!(
            p2.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(),
            vec!["a"]
        );
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
        assert_eq!(
            s.list_by_owner("u", None, None, 100_000)
                .await
                .unwrap()
                .len(),
            10
        );
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
    async fn bump_view_count_increments_and_missing_id_is_noop() {
        let s = InMemoryStore::new();
        s.create(&file("a", "u", "tok-a", 1)).await.unwrap();

        s.bump_view_count("a").await.unwrap();
        s.bump_view_count("a").await.unwrap();
        s.bump_view_count("missing").await.unwrap();

        assert_eq!(s.get("a").await.unwrap().unwrap().view_count, 2);
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
            .configure_share(
                "a",
                "u",
                Some("tok-a".into()),
                Some(999),
                Some("salt$hash".into())
            )
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

    #[tokio::test]
    async fn trash_hides_live_surfaces_but_counts_usage_until_hard_delete() {
        let s = InMemoryStore::new();
        let mut a = file("a", "u", "tok-a", 1);
        a.size = 25;
        s.create(&a).await.unwrap();
        assert_eq!(s.usage_for_owner("u").await.unwrap(), 25);

        assert!(s.trash_file("a", "u", 99).await.unwrap());
        assert!(s
            .list_by_owner("u", None, None, 50)
            .await
            .unwrap()
            .is_empty());
        assert!(s.get_by_token("tok-a").await.unwrap().is_none());
        assert_eq!(s.list_trashed_by_owner("u").await.unwrap()[0].id, "a");
        assert_eq!(s.usage_for_owner("u").await.unwrap(), 25);
        let agg = s.usage_by_owner().await.unwrap();
        assert_eq!(
            agg[0].files, 0,
            "trashed files are hidden from visible file counts"
        );
        assert_eq!(agg[0].bytes, 25, "trashed bytes still count toward usage");

        assert!(s.restore_file("a", "u").await.unwrap());
        assert_eq!(s.get("a").await.unwrap().unwrap().trashed_at, 0);
        assert_eq!(s.list_by_owner("u", None, None, 50).await.unwrap().len(), 1);

        assert!(s.trash_file("a", "u", 100).await.unwrap());
        assert!(s.delete("a", "u").await.unwrap());
        assert_eq!(s.usage_for_owner("u").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn comments_roundtrip_oldest_first_and_delete_for_file() {
        let s = InMemoryStore::new();
        s.create(&file("a", "u", "tok-a", 1)).await.unwrap();
        let c1 = FileComment {
            id: "c1".into(),
            file_id: "a".into(),
            author_sub: "u".into(),
            body: "first".into(),
            created_at: 1,
        };
        let c2 = FileComment {
            id: "c2".into(),
            file_id: "a".into(),
            author_sub: "v".into(),
            body: "second".into(),
            created_at: 2,
        };
        assert!(s.create_comment(&c2).await.unwrap());
        assert!(s.create_comment(&c1).await.unwrap());
        assert!(
            !s.create_comment(&c1).await.unwrap(),
            "comment id collision returns false"
        );
        let comments = s.list_comments("a").await.unwrap();
        assert_eq!(
            comments.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            vec!["c1", "c2"]
        );
        assert_eq!(s.get_comment("c2").await.unwrap().unwrap().body, "second");
        assert!(s.delete_comment("c1", "a").await.unwrap());
        assert_eq!(s.list_comments("a").await.unwrap().len(), 1);
        s.delete_comments_for_file("a").await.unwrap();
        assert!(s.list_comments("a").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn library_query_is_owner_scoped_cross_tree_filterable_and_token_free() {
        let s = InMemoryStore::new();
        let mut nested = file("nested9", "alice", "secret-file-token", 30);
        nested.name = "Quarterly Report.png".into();
        nested.folder_id = Some("folder9".into());
        nested.expires_at = Some(1);
        nested.share_password_hash = Some("salt$hash".into());
        s.create(&nested).await.unwrap();

        let mut private = file("private9", "alice", "unused", 20);
        private.name = "Quarterly notes.txt".into();
        private.content_type = "text/plain".into();
        private.share_token = None;
        s.create(&private).await.unwrap();
        let mut foreign = file("foreign9", "bob", "foreign-token", 99);
        foreign.name = "Quarterly Report.png".into();
        s.create(&foreign).await.unwrap();

        let mut reports = folder("folder9", "alice", "Quarterly Reports", 40);
        reports.share_token = Some("secret-folder-token".into());
        reports.expires_at = Some(1);
        s.create_folder(&reports).await.unwrap();

        let search = LibraryQuery {
            view: LibraryView::All,
            query: Some("quarterly".into()),
            type_filter: LibraryType::All,
            before: None,
            limit: 20,
        };
        let page = s.query_library("alice", &search).await.unwrap();
        assert_eq!(
            page.items.len(),
            3,
            "files and folders are searched globally"
        );
        assert!(page.items.iter().all(|item| item.id != "foreign9"));
        assert!(page.items.iter().any(|item| item.id == "nested9"));
        assert!(page.items.iter().any(|item| item.id == "folder9"));

        let shared = s
            .query_library(
                "alice",
                &LibraryQuery {
                    view: LibraryView::Shared,
                    query: None,
                    type_filter: LibraryType::All,
                    before: None,
                    limit: 20,
                },
            )
            .await
            .unwrap();
        assert_eq!(shared.items.len(), 2);
        assert!(shared.items.iter().all(|item| item.shared));
        assert!(shared.items.iter().all(|item| item.share_expired));
        assert!(
            shared
                .items
                .iter()
                .find(|item| item.id == "nested9")
                .unwrap()
                .share_protected
        );

        let images = s
            .query_library(
                "alice",
                &LibraryQuery {
                    view: LibraryView::All,
                    query: None,
                    type_filter: LibraryType::Image,
                    before: None,
                    limit: 20,
                },
            )
            .await
            .unwrap();
        assert_eq!(images.items.len(), 1);
        assert_eq!(images.items[0].id, "nested9");
    }

    #[tokio::test]
    async fn library_type_filters_use_one_priority_order() {
        let s = InMemoryStore::new();
        let mut text_tar = file("texttar9", "u", "unused-text-tar", 2);
        text_tar.name = "Priority document".into();
        text_tar.content_type = "text/x-tar".into();
        text_tar.share_token = None;
        s.create(&text_tar).await.unwrap();

        let mut image_zip = file("imagezip9", "u", "unused-image-zip", 1);
        image_zip.name = "Priority image".into();
        image_zip.content_type = "image/x-zip".into();
        image_zip.share_token = None;
        s.create(&image_zip).await.unwrap();

        let ids_for = |type_filter| LibraryQuery {
            view: LibraryView::All,
            query: Some("priority".into()),
            type_filter,
            before: None,
            limit: 20,
        };
        let documents = s
            .query_library("u", &ids_for(LibraryType::Document))
            .await
            .unwrap();
        assert_eq!(documents.items[0].id, "texttar9");
        assert_eq!(documents.items.len(), 1);

        let images = s
            .query_library("u", &ids_for(LibraryType::Image))
            .await
            .unwrap();
        assert_eq!(images.items[0].id, "imagezip9");
        assert_eq!(images.items.len(), 1);

        let archives = s
            .query_library("u", &ids_for(LibraryType::Archive))
            .await
            .unwrap();
        assert!(archives.items.is_empty());
    }

    #[tokio::test]
    async fn library_cursor_is_stable_across_file_and_folder_ties() {
        let s = InMemoryStore::new();
        s.create(&file("filea", "u", "tok-a", 10)).await.unwrap();
        s.create(&file("fileb", "u", "tok-b", 10)).await.unwrap();
        s.create_folder(&folder("folda", "u", "A", 10))
            .await
            .unwrap();
        s.create_folder(&folder("foldb", "u", "B", 10))
            .await
            .unwrap();
        let first_query = LibraryQuery {
            view: LibraryView::Recent,
            query: None,
            type_filter: LibraryType::All,
            before: None,
            limit: 2,
        };
        let first = s.query_library("u", &first_query).await.unwrap();
        assert_eq!(
            first
                .items
                .iter()
                .map(|item| item.id.as_str())
                .collect::<Vec<_>>(),
            vec!["fileb", "filea"]
        );
        let second = s
            .query_library(
                "u",
                &LibraryQuery {
                    before: first.next.clone(),
                    ..first_query
                },
            )
            .await
            .unwrap();
        assert_eq!(
            second
                .items
                .iter()
                .map(|item| item.id.as_str())
                .collect::<Vec<_>>(),
            vec!["foldb", "folda"]
        );
        assert!(second.next.is_none());
    }

    #[tokio::test]
    async fn owner_mutations_touch_activity_but_anonymous_views_do_not() {
        let s = InMemoryStore::new();
        let mut rec = file("activity", "u", "share-token", 1);
        rec.updated_at = 1;
        s.create(&rec).await.unwrap();
        s.rename_file("activity", "u", "renamed.png").await.unwrap();
        let after_rename = s.get("activity").await.unwrap().unwrap().updated_at;
        assert!(after_rename > 1);
        s.rename_file("activity", "u", "renamed-again.png")
            .await
            .unwrap();
        let after_second_rename = s.get("activity").await.unwrap().unwrap().updated_at;
        assert!(
            after_second_rename > after_rename,
            "two owner mutations in one wall-clock second remain observable"
        );
        s.bump_view_count("activity").await.unwrap();
        let after_public_view = s.get("activity").await.unwrap().unwrap();
        assert_eq!(after_public_view.updated_at, after_second_rename);
        assert_eq!(after_public_view.view_count, 1);

        let comment = FileComment {
            id: "comment1".into(),
            file_id: "activity".into(),
            author_sub: "u".into(),
            body: "note".into(),
            created_at: mutation_time(),
        };
        assert!(s.create_comment(&comment).await.unwrap());
        assert!(s.get("activity").await.unwrap().unwrap().updated_at > after_second_rename);

        let mut folder = folder("activity-folder", "u", "Folder", 1);
        folder.updated_at = 1;
        s.create_folder(&folder).await.unwrap();
        s.configure_folder_share(
            "activity-folder",
            "u",
            Some("folder-token".into()),
            None,
            None,
        )
        .await
        .unwrap();
        assert!(
            s.get_folder("activity-folder", "u")
                .await
                .unwrap()
                .unwrap()
                .updated_at
                > 1
        );
    }

    fn folder(id: &str, owner: &str, name: &str, created_at: i64) -> FolderRec {
        FolderRec {
            id: id.into(),
            owner_sub: owner.into(),
            parent_id: None,
            name: name.into(),
            created_at,
            updated_at: created_at,
            share_token: None,
            expires_at: None,
            share_password_hash: None,
            upload_token: None,
            trashed_at: 0,
            trash_entry_id: None,
            trash_ancestor_id: None,
        }
    }

    fn inbox_request(
        id: &str,
        owner: &str,
        folder_id: &str,
        status: &str,
        expires_at: Option<i64>,
        updated_at: i64,
    ) -> UploadRequestRec {
        UploadRequestRec {
            id: id.into(),
            owner_sub: owner.into(),
            folder_id: folder_id.into(),
            token: format!("capability-{owner}-{id}"),
            title: format!("Request {id}"),
            description: format!("Instructions for {id}"),
            status: status.into(),
            expires_at,
            max_file_bytes: 10,
            max_total_bytes: 100,
            max_files: 10,
            used_bytes: 20,
            used_files: 2,
            allowed_types: "*/*".into(),
            created_at: updated_at.saturating_sub(1),
            updated_at,
        }
    }

    #[tokio::test]
    async fn request_inbox_is_owner_scoped_and_classifies_one_stable_snapshot() {
        let store = InMemoryStore::new();
        let as_of: i64 = 1_000_000;
        assert!(store
            .create_folder(&folder("inbox-u", "u", "Inbox", 1))
            .await
            .unwrap());
        assert!(store
            .create_folder(&folder("inbox-v", "v", "Foreign", 1))
            .await
            .unwrap());
        let requests = [
            inbox_request(
                "request-open",
                "u",
                "inbox-u",
                "open",
                Some(
                    as_of
                        .saturating_add(UPLOAD_REQUEST_EXPIRING_WINDOW_SECS)
                        .saturating_add(1),
                ),
                9,
            ),
            inbox_request(
                "request-expiring",
                "u",
                "inbox-u",
                "open",
                Some(as_of.saturating_add(UPLOAD_REQUEST_EXPIRING_WINDOW_SECS)),
                9,
            ),
            inbox_request("request-expired", "u", "inbox-u", "open", Some(as_of), 9),
            inbox_request(
                "request-closed",
                "u",
                "inbox-u",
                "closed",
                Some(as_of.saturating_sub(1)),
                9,
            ),
            inbox_request("request-foreign", "v", "inbox-v", "open", None, 99),
        ];
        for request in requests {
            assert!(store.create_upload_request(&request).await.unwrap());
        }

        let first = store
            .upload_request_inbox("u", UploadRequestInboxView::All, as_of)
            .await
            .unwrap();
        let second = store
            .upload_request_inbox("u", UploadRequestInboxView::All, as_of)
            .await
            .unwrap();
        assert_eq!(first, second, "the same as_of is classification-stable");
        assert_eq!(
            first.counts,
            UploadRequestInboxCounts {
                all: 4,
                open: 1,
                expiring: 1,
                closed: 1,
                expired: 1,
            }
        );
        assert_eq!(
            first
                .items
                .iter()
                .map(|request| request.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "request-open",
                "request-expiring",
                "request-expired",
                "request-closed"
            ],
            "updated_at ties use descending id order"
        );
        assert!(first
            .items
            .iter()
            .all(|request| request.id != "request-foreign"));
        for view in [
            UploadRequestInboxView::Open,
            UploadRequestInboxView::Expiring,
            UploadRequestInboxView::Closed,
            UploadRequestInboxView::Expired,
        ] {
            let filtered = store.upload_request_inbox("u", view, as_of).await.unwrap();
            assert_eq!(filtered.counts, first.counts);
            assert_eq!(filtered.matched_total, 1);
            assert_eq!(filtered.items.len(), 1);
            assert_eq!(filtered.items[0].state.slug(), view.slug());
        }
        let later = store
            .upload_request_inbox(
                "u",
                UploadRequestInboxView::All,
                as_of
                    .saturating_add(UPLOAD_REQUEST_EXPIRING_WINDOW_SECS)
                    .saturating_add(2),
            )
            .await
            .unwrap();
        assert_eq!(later.counts.expired, 3);
        assert_eq!(later.counts.open, 0);
        assert_eq!(later.counts.expiring, 0);
    }

    #[tokio::test]
    async fn request_inbox_has_an_explicit_newest_first_cap() {
        let store = InMemoryStore::new();
        assert!(store
            .create_folder(&folder("bounded-inbox", "u", "Bounded", 1))
            .await
            .unwrap());
        for index in 0..=UPLOAD_REQUEST_INBOX_CAP {
            let id = format!("request-{index:03}");
            assert!(store
                .create_upload_request(&inbox_request(&id, "u", "bounded-inbox", "open", None, 10,))
                .await
                .unwrap());
        }
        let inbox = store
            .upload_request_inbox("u", UploadRequestInboxView::All, 10)
            .await
            .unwrap();
        assert_eq!(inbox.matched_total, UPLOAD_REQUEST_INBOX_CAP + 1);
        assert_eq!(inbox.items.len(), UPLOAD_REQUEST_INBOX_CAP as usize);
        assert!(inbox.truncated);
        assert_eq!(inbox.items.first().unwrap().id, "request-100");
        assert_eq!(inbox.items.last().unwrap().id, "request-001");
    }

    /// A child folder under `parent`.
    fn subfolder(id: &str, owner: &str, parent: &str, name: &str) -> FolderRec {
        FolderRec {
            id: id.into(),
            owner_sub: owner.into(),
            parent_id: Some(parent.into()),
            name: name.into(),
            created_at: 0,
            updated_at: 0,
            share_token: None,
            expires_at: None,
            share_password_hash: None,
            upload_token: None,
            trashed_at: 0,
            trash_entry_id: None,
            trash_ancestor_id: None,
        }
    }

    fn version(id: &str, file_id: &str, size: i64, created_at: i64) -> VersionRec {
        VersionRec {
            id: id.into(),
            file_id: file_id.into(),
            object_key: format!("{id}-blob"),
            size,
            content_type: "image/png".into(),
            created_at,
        }
    }

    #[tokio::test]
    async fn folders_are_owner_scoped_and_name_ordered() {
        let s = InMemoryStore::new();
        s.create_folder(&folder("f2", "u", "Zeta", 1))
            .await
            .unwrap();
        s.create_folder(&folder("f1", "u", "alpha", 2))
            .await
            .unwrap();
        s.create_folder(&folder("f3", "other", "Mine", 3))
            .await
            .unwrap();
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
        assert_eq!(
            s.delete_folder_if_empty("f1", "intruder").await.unwrap(),
            FolderDelete::NotFound
        );
        // Owner renames.
        assert!(s.rename_folder("f1", "u", "New").await.unwrap());
        assert_eq!(s.get_folder("f1", "u").await.unwrap().unwrap().name, "New");
        // Owner deletes the empty folder.
        assert_eq!(
            s.delete_folder_if_empty("f1", "u").await.unwrap(),
            FolderDelete::Deleted
        );
        assert!(s.get_folder("f1", "u").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn move_file_filters_root_vs_folder_view() {
        let s = InMemoryStore::new();
        s.create_folder(&folder("f1", "u", "Album", 1))
            .await
            .unwrap();
        s.create(&file("a", "u", "ta", 10)).await.unwrap();
        s.create(&file("b", "u", "tb", 20)).await.unwrap();

        // Both files start at ROOT: the folder view is empty, the root view has both.
        assert_eq!(
            s.list_by_owner("u", Some("f1"), None, 50)
                .await
                .unwrap()
                .len(),
            0
        );
        assert_eq!(s.list_by_owner("u", None, None, 50).await.unwrap().len(), 2);

        // A non-owner cannot move the file.
        assert!(!s.move_file("a", "intruder", Some("f1")).await.unwrap());
        // Owner moves "a" into the folder; the folder view shows only it, the ROOT view now shows
        // only "b" (a filed file leaves the root — the tree model).
        assert!(s.move_file("a", "u", Some("f1")).await.unwrap());
        let in_folder = s.list_by_owner("u", Some("f1"), None, 50).await.unwrap();
        assert_eq!(
            in_folder.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(),
            vec!["a"]
        );
        let root = s.list_by_owner("u", None, None, 50).await.unwrap();
        assert_eq!(
            root.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(),
            vec!["b"]
        );
        // list_files_in_folder returns the whole folder unpaginated.
        assert_eq!(s.list_files_in_folder("f1", "u").await.unwrap().len(), 1);

        // Move "a" back to root -> the folder view empties, root has both again.
        assert!(s.move_file("a", "u", None).await.unwrap());
        assert_eq!(
            s.list_by_owner("u", Some("f1"), None, 50)
                .await
                .unwrap()
                .len(),
            0
        );
        assert_eq!(s.list_by_owner("u", None, None, 50).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn find_file_in_folder_scopes_by_name_and_level() {
        let s = InMemoryStore::new();
        s.create_folder(&folder("f1", "u", "Album", 1))
            .await
            .unwrap();
        let mut root = file("r", "u", "tr", 1);
        root.name = "same.png".into();
        s.create(&root).await.unwrap();
        let mut filed = file("g", "u", "tg", 2);
        filed.name = "same.png".into();
        filed.folder_id = Some("f1".into());
        s.create(&filed).await.unwrap();

        // Same name resolves per-level: root vs folder are distinct files.
        assert_eq!(
            s.find_file_in_folder("u", "same.png", None)
                .await
                .unwrap()
                .unwrap()
                .id,
            "r"
        );
        assert_eq!(
            s.find_file_in_folder("u", "same.png", Some("f1"))
                .await
                .unwrap()
                .unwrap()
                .id,
            "g"
        );
        assert!(s
            .find_file_in_folder("u", "nope.png", None)
            .await
            .unwrap()
            .is_none());
        // Owner-scoped.
        assert!(s
            .find_file_in_folder("other", "same.png", None)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn quota_override_set_get_clear_roundtrip() {
        let s = InMemoryStore::new();
        // No row yet -> no override.
        assert_eq!(s.get_quota("u").await.unwrap(), None);
        // Set, then update (upsert semantics), then clear.
        s.set_quota("u", Some(1024)).await.unwrap();
        assert_eq!(s.get_quota("u").await.unwrap(), Some(1024));
        s.set_quota("u", Some(2048)).await.unwrap();
        assert_eq!(s.get_quota("u").await.unwrap(), Some(2048));
        s.set_quota("v", Some(0)).await.unwrap(); // explicit unlimited override
        let all = s.list_quotas().await.unwrap();
        assert_eq!(all, vec![("u".to_string(), 2048), ("v".to_string(), 0)]);
        s.set_quota("u", None).await.unwrap();
        assert_eq!(s.get_quota("u").await.unwrap(), None);
        assert_eq!(s.list_quotas().await.unwrap(), vec![("v".to_string(), 0)]);
    }

    #[tokio::test]
    async fn usage_sums_are_owner_scoped_and_aggregated() {
        let s = InMemoryStore::new();
        // No files -> zero usage, empty aggregate.
        assert_eq!(s.usage_for_owner("u").await.unwrap(), 0);
        assert!(s.usage_by_owner().await.unwrap().is_empty());

        let mut a = file("a", "u", "ta", 1);
        a.size = 100;
        let mut b = file("b", "u", "tb", 2);
        b.size = 50;
        let mut c = file("c", "other", "tc", 3);
        c.size = 700;
        for f in [&a, &b, &c] {
            s.create(f).await.unwrap();
        }

        assert_eq!(s.usage_for_owner("u").await.unwrap(), 150);
        assert_eq!(s.usage_for_owner("other").await.unwrap(), 700);
        // Aggregate: largest first, per-owner file counts and byte sums.
        let agg = s.usage_by_owner().await.unwrap();
        assert_eq!(
            agg,
            vec![
                OwnerUsage {
                    owner_sub: "other".into(),
                    files: 1,
                    bytes: 700
                },
                OwnerUsage {
                    owner_sub: "u".into(),
                    files: 2,
                    bytes: 150
                },
            ]
        );
        // Deleting a file shrinks the sum (usage tracks the live rows).
        s.delete("a", "u").await.unwrap();
        assert_eq!(s.usage_for_owner("u").await.unwrap(), 50);
    }

    #[tokio::test]
    async fn delete_folder_empty_only_then_cascade() {
        let s = InMemoryStore::new();
        s.create_folder(&folder("f1", "u", "Album", 1))
            .await
            .unwrap();
        s.create_folder(&subfolder("f2", "u", "f1", "Sub"))
            .await
            .unwrap();
        s.create(&file("a", "u", "ta", 10)).await.unwrap();
        s.move_file("a", "u", Some("f2")).await.unwrap();

        // f1 has a subfolder -> not empty; f2 has a file -> not empty.
        assert_eq!(
            s.delete_folder_if_empty("f1", "u").await.unwrap(),
            FolderDelete::NotEmpty
        );
        assert_eq!(
            s.delete_folder_if_empty("f2", "u").await.unwrap(),
            FolderDelete::NotEmpty
        );

        // Cascade from f1 removes the whole subtree (f1, f2) AND the file, returning the freed keys.
        let keys = s.delete_folder_cascade("f1", "u").await.unwrap();
        assert!(
            keys.contains(&"a".to_string()),
            "the file's object key is freed for blob cleanup"
        );
        assert!(s.get_folder("f1", "u").await.unwrap().is_none());
        assert!(s.get_folder("f2", "u").await.unwrap().is_none());
        assert!(
            s.get("a").await.unwrap().is_none(),
            "cascade deletes the file too"
        );
    }

    #[tokio::test]
    async fn cascade_frees_version_blobs_and_is_owner_scoped() {
        let s = InMemoryStore::new();
        s.create_folder(&folder("f1", "u", "Album", 1))
            .await
            .unwrap();
        let mut a = file("a", "u", "ta", 10);
        a.object_key = "a".into();
        a.folder_id = Some("f1".into());
        s.create(&a).await.unwrap();
        s.add_version(&version("v1", "a", 5, 1)).await.unwrap();

        // A non-owner cascade removes nothing.
        assert!(s
            .delete_folder_cascade("f1", "other")
            .await
            .unwrap()
            .is_empty());
        assert!(s.get_folder("f1", "u").await.unwrap().is_some());

        // Owner cascade frees the current blob AND the version blob.
        let keys = s.delete_folder_cascade("f1", "u").await.unwrap();
        assert!(keys.contains(&"a".to_string()));
        assert!(keys.contains(&"v1-blob".to_string()));
        assert!(s.list_versions("a").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn folder_share_configure_and_lookup_by_token() {
        let s = InMemoryStore::new();
        s.create_folder(&folder("f1", "u", "Shared", 1))
            .await
            .unwrap();
        // Non-owner cannot configure.
        assert!(!s
            .configure_folder_share("f1", "intruder", Some("ftok".into()), None, None)
            .await
            .unwrap());
        // Owner enables a share with an expiry + password.
        assert!(s
            .configure_folder_share(
                "f1",
                "u",
                Some("ftok".into()),
                Some(999),
                Some("salt$h".into())
            )
            .await
            .unwrap());
        let byf = s.get_folder_by_token("ftok").await.unwrap().unwrap();
        assert_eq!(byf.id, "f1");
        assert_eq!(byf.expires_at, Some(999));
        assert!(byf.share_has_password());
        // Revoke clears the token; the public lookup misses.
        assert!(s
            .configure_folder_share("f1", "u", None, None, None)
            .await
            .unwrap());
        assert!(s.get_folder_by_token("ftok").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn folder_upload_token_configure_lookup_and_revoke() {
        let s = InMemoryStore::new();
        s.create_folder(&folder("f1", "u", "Inbox", 1))
            .await
            .unwrap();
        assert!(!s
            .configure_folder_upload("f1", "intruder", Some("utok".into()))
            .await
            .unwrap());
        assert!(s
            .configure_folder_upload("f1", "u", Some("utok".into()))
            .await
            .unwrap());
        let got = s.get_folder_by_upload_token("utok").await.unwrap().unwrap();
        assert_eq!(got.id, "f1");
        assert!(s.configure_folder_upload("f1", "u", None).await.unwrap());
        assert!(s
            .get_folder_by_upload_token("utok")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn versions_list_prune_and_delete_roundtrip() {
        let s = InMemoryStore::new();
        s.create(&file("a", "u", "ta", 100)).await.unwrap();
        // Three snapshots, oldest-first by created_at.
        s.add_version(&version("v1", "a", 10, 1)).await.unwrap();
        s.add_version(&version("v2", "a", 20, 2)).await.unwrap();
        s.add_version(&version("v3", "a", 30, 3)).await.unwrap();
        // Newest-first ordering.
        let ids: Vec<String> = s
            .list_versions("a")
            .await
            .unwrap()
            .into_iter()
            .map(|v| v.id)
            .collect();
        assert_eq!(ids, vec!["v3", "v2", "v1"]);
        // get is file-scoped.
        assert!(s.get_version("v2", "a").await.unwrap().is_some());
        assert!(s.get_version("v2", "other").await.unwrap().is_none());
        // Prune to keep the newest 2 -> the oldest (v1) is returned for blob cleanup.
        let pruned = s.prune_versions("a", 2).await.unwrap();
        assert_eq!(
            pruned.iter().map(|v| v.id.as_str()).collect::<Vec<_>>(),
            vec!["v1"]
        );
        assert_eq!(s.list_versions("a").await.unwrap().len(), 2);
        // delete_version returns the removed row (caller decides whether to drop the blob).
        let removed = s.delete_version("v2", "a").await.unwrap().unwrap();
        assert_eq!(removed.object_key, "v2-blob");
        assert_eq!(s.list_versions("a").await.unwrap().len(), 1);
        // delete_versions_for_file clears the rest.
        assert_eq!(s.delete_versions_for_file("a").await.unwrap().len(), 1);
        assert!(s.list_versions("a").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn usage_counts_version_bytes() {
        let s = InMemoryStore::new();
        let mut a = file("a", "u", "ta", 1);
        a.size = 100;
        s.create(&a).await.unwrap();
        assert_eq!(s.usage_for_owner("u").await.unwrap(), 100);
        // A retained version adds its bytes to usage (but not to the file COUNT).
        s.add_version(&version("v1", "a", 40, 1)).await.unwrap();
        assert_eq!(s.usage_for_owner("u").await.unwrap(), 140);
        let agg = s.usage_by_owner().await.unwrap();
        assert_eq!(agg.len(), 1);
        assert_eq!(agg[0].files, 1, "versions do not inflate the file count");
        assert_eq!(agg[0].bytes, 140, "versions do inflate the byte total");
    }

    #[tokio::test]
    async fn update_file_blob_repoints_current() {
        let s = InMemoryStore::new();
        s.create(&file("a", "u", "ta", 1)).await.unwrap();
        assert!(s
            .update_file_blob("a", "u", "newkey", 77, "application/pdf", 999)
            .await
            .unwrap());
        let got = s.get("a").await.unwrap().unwrap();
        assert_eq!(got.object_key, "newkey");
        assert_eq!(got.size, 77);
        assert_eq!(got.content_type, "application/pdf");
        assert_eq!(got.created_at, 1, "creation time remains immutable");
        assert_eq!(
            got.updated_at, 999,
            "content replacement is recent activity"
        );
        // Owner-scoped.
        assert!(!s
            .update_file_blob("a", "intruder", "x", 1, "text/plain", 1)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn unified_trash_preserves_nested_scope_and_capabilities() {
        let s = InMemoryStore::new();
        let mut parent = folder("trashparent", "u", "Parent", 1);
        parent.share_token = Some("parent-share-token".into());
        s.create_folder(&parent).await.unwrap();
        let mut child = subfolder("trashchild", "u", "trashparent", "Child");
        child.share_token = Some("child-share-token".into());
        s.create_folder(&child).await.unwrap();
        let mut nested = file("trashfile", "u", "file-share-token", 2);
        nested.folder_id = Some("trashchild".into());
        s.create(&nested).await.unwrap();

        assert_eq!(
            s.bulk_trash(
                "u",
                &[TrashRootInput {
                    item: DriveItemRef {
                        kind: LibraryItemKind::Folder,
                        id: "trashchild".into(),
                    },
                    entry_id: "child-entry".into(),
                }],
                10,
                100,
            )
            .await
            .unwrap(),
            BulkMutation::Applied { changed: 1 }
        );
        assert!(s
            .get_folder_by_token("child-share-token")
            .await
            .unwrap()
            .is_none());
        assert!(s.get_by_token("file-share-token").await.unwrap().is_none());

        assert_eq!(
            s.bulk_trash(
                "u",
                &[TrashRootInput {
                    item: DriveItemRef {
                        kind: LibraryItemKind::Folder,
                        id: "trashparent".into(),
                    },
                    entry_id: "parent-entry".into(),
                }],
                20,
                200,
            )
            .await
            .unwrap(),
            BulkMutation::Applied { changed: 1 }
        );
        let hidden_child = s.get_folder_any("trashchild", "u").await.unwrap().unwrap();
        assert_eq!(hidden_child.trash_entry_id.as_deref(), Some("child-entry"));
        assert_eq!(
            hidden_child.trash_ancestor_id.as_deref(),
            Some("parent-entry")
        );
        let roots = s.query_trash("u", None, 20).await.unwrap();
        assert_eq!(roots.items.len(), 1, "nested roots are deduplicated");
        assert_eq!(roots.items[0].id, "trashparent");

        assert_eq!(
            s.bulk_restore(
                "u",
                &[DriveItemRef {
                    kind: LibraryItemKind::Folder,
                    id: "trashparent".into(),
                }],
            )
            .await
            .unwrap(),
            BulkMutation::Applied { changed: 1 }
        );
        assert!(s.get_folder("trashparent", "u").await.unwrap().is_some());
        assert!(s.get_folder("trashchild", "u").await.unwrap().is_none());
        assert!(s.get_by_token("file-share-token").await.unwrap().is_none());
        let roots = s.query_trash("u", None, 20).await.unwrap();
        assert_eq!(roots.items.len(), 1);
        assert_eq!(roots.items[0].id, "trashchild");

        assert!(matches!(
            s.bulk_restore(
                "u",
                &[DriveItemRef {
                    kind: LibraryItemKind::Folder,
                    id: "trashchild".into(),
                }],
            )
            .await
            .unwrap(),
            BulkMutation::Applied { .. }
        ));
        assert_eq!(
            s.get_folder_by_token("child-share-token")
                .await
                .unwrap()
                .unwrap()
                .id,
            "trashchild"
        );
        assert_eq!(
            s.get_by_token("file-share-token")
                .await
                .unwrap()
                .unwrap()
                .id,
            "trashfile"
        );
    }

    #[tokio::test]
    async fn trash_projection_fails_closed_when_metadata_owner_is_corrupt() {
        let s = InMemoryStore::new();
        s.create(&file("ownerdriftfile", "u", "owner-drift-token", 1))
            .await
            .unwrap();
        s.create_folder(&folder("ownerdriftfolder", "u", "Owner drift", 1))
            .await
            .unwrap();
        assert!(matches!(
            s.bulk_trash(
                "u",
                &[
                    TrashRootInput {
                        item: DriveItemRef {
                            kind: LibraryItemKind::File,
                            id: "ownerdriftfile".into(),
                        },
                        entry_id: "owner-drift-file-entry".into(),
                    },
                    TrashRootInput {
                        item: DriveItemRef {
                            kind: LibraryItemKind::Folder,
                            id: "ownerdriftfolder".into(),
                        },
                        entry_id: "owner-drift-folder-entry".into(),
                    },
                ],
                10,
                100,
            )
            .await
            .unwrap(),
            BulkMutation::Applied { changed: 2 }
        ));
        assert_eq!(s.query_trash("u", None, 20).await.unwrap().items.len(), 2);

        {
            let mut folders = s.folders.lock().expect("folders lock poisoned");
            let mut files = s.files.lock().expect("files lock poisoned");
            folders
                .iter_mut()
                .find(|folder| folder.id == "ownerdriftfolder")
                .unwrap()
                .owner_sub = "v".into();
            files
                .iter_mut()
                .find(|file| file.id == "ownerdriftfile")
                .unwrap()
                .owner_sub = "v".into();
        }
        assert!(
            s.query_trash("u", None, 20).await.unwrap().items.is_empty(),
            "entry ownership cannot project metadata owned by another subject"
        );
        assert!(s.query_trash("v", None, 20).await.unwrap().items.is_empty());
    }

    #[tokio::test]
    async fn bulk_mutations_are_atomic_cycle_safe_and_domain_bounded() {
        let s = InMemoryStore::new();
        s.create_folder(&folder("cycleparent", "u", "Parent", 1))
            .await
            .unwrap();
        s.create_folder(&subfolder("cyclechild", "u", "cycleparent", "Child"))
            .await
            .unwrap();
        s.create(&file("ownedfile", "u", "owned-token", 1))
            .await
            .unwrap();
        s.create(&file("foreignfile", "v", "foreign-token", 1))
            .await
            .unwrap();

        let mixed = [
            TrashRootInput {
                item: DriveItemRef {
                    kind: LibraryItemKind::File,
                    id: "ownedfile".into(),
                },
                entry_id: "owned-entry".into(),
            },
            TrashRootInput {
                item: DriveItemRef {
                    kind: LibraryItemKind::File,
                    id: "foreignfile".into(),
                },
                entry_id: "foreign-entry".into(),
            },
        ];
        assert_eq!(
            s.bulk_trash("u", &mixed, 10, 100).await.unwrap(),
            BulkMutation::Conflict
        );
        assert!(s
            .get("ownedfile")
            .await
            .unwrap()
            .unwrap()
            .is_effectively_live());

        assert_eq!(
            s.bulk_move(
                "u",
                &[DriveItemRef {
                    kind: LibraryItemKind::Folder,
                    id: "cycleparent".into(),
                }],
                Some("cyclechild"),
            )
            .await
            .unwrap(),
            BulkMutation::Conflict
        );
        assert!(s
            .get_folder("cycleparent", "u")
            .await
            .unwrap()
            .unwrap()
            .parent_id
            .is_none());

        let too_many_items: Vec<DriveItemRef> = (0..=MAX_BULK_ITEMS)
            .map(|index| DriveItemRef {
                kind: LibraryItemKind::File,
                id: format!("oversized{index}"),
            })
            .collect();
        let too_many_roots: Vec<TrashRootInput> = too_many_items
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, item)| TrashRootInput {
                item,
                entry_id: format!("oversizedentry{index}"),
            })
            .collect();
        assert_eq!(
            s.bulk_trash("u", &too_many_roots, 1, 2).await.unwrap(),
            BulkMutation::Conflict
        );
        assert_eq!(
            s.bulk_restore("u", &too_many_items).await.unwrap(),
            BulkMutation::Conflict
        );
        assert_eq!(
            s.bulk_move("u", &too_many_items, None).await.unwrap(),
            BulkMutation::Conflict
        );
        assert_eq!(
            s.bulk_purge("u", &too_many_items, 1).await.unwrap(),
            BulkMutation::Conflict
        );
    }

    #[tokio::test]
    async fn purge_requires_exact_trash_authority_and_closes_doomed_request_rooms() {
        let s = InMemoryStore::new();
        s.create_folder(&folder("authorityfolder", "u", "Authority", 1))
            .await
            .unwrap();
        assert!(s
            .create_upload_request(&UploadRequestRec {
                id: "authorityrequest".into(),
                owner_sub: "u".into(),
                folder_id: "authorityfolder".into(),
                token: "authority-token".into(),
                title: "Authority".into(),
                description: String::new(),
                status: "open".into(),
                expires_at: None,
                max_file_bytes: 10,
                max_total_bytes: 10,
                max_files: 1,
                used_bytes: 0,
                used_files: 0,
                allowed_types: "*/*".into(),
                created_at: 1,
                updated_at: 1,
            })
            .await
            .unwrap());
        let item = DriveItemRef {
            kind: LibraryItemKind::Folder,
            id: "authorityfolder".into(),
        };
        assert_eq!(
            s.bulk_trash(
                "u",
                &[TrashRootInput {
                    item: item.clone(),
                    entry_id: "authorityentry".into(),
                }],
                10,
                100,
            )
            .await
            .unwrap(),
            BulkMutation::Applied { changed: 1 }
        );
        {
            let mut entries = s.trash_entries.lock().expect("trash lock poisoned");
            entries
                .iter_mut()
                .find(|entry| entry.id == "authorityentry")
                .unwrap()
                .item_id = "dangling-item".into();
        }
        assert_eq!(
            s.bulk_purge("u", std::slice::from_ref(&item), 20)
                .await
                .unwrap(),
            BulkMutation::Conflict
        );
        assert!(s
            .get_folder_any("authorityfolder", "u")
            .await
            .unwrap()
            .is_some());
        {
            let mut entries = s.trash_entries.lock().expect("trash lock poisoned");
            entries
                .iter_mut()
                .find(|entry| entry.id == "authorityentry")
                .unwrap()
                .item_id = "authorityfolder".into();
        }
        assert_eq!(
            s.bulk_purge("u", &[item], 21).await.unwrap(),
            BulkMutation::Applied { changed: 1 }
        );
        assert_eq!(
            s.get_upload_request("authorityrequest", "u")
                .await
                .unwrap()
                .unwrap()
                .status,
            "closed"
        );
        assert!(!s
            .reopen_upload_request("authorityrequest", "u", 22, 100)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn owner_reupload_and_restore_are_atomic_cas_transitions() {
        let s = InMemoryStore::new();
        let current = file("atomicfile", "u", "atomic-token", 1);
        assert!(s.create(&current).await.unwrap());
        let intent = OwnerBlobWriteIntent {
            object_key: "atomic-new".into(),
            owner_sub: "u".into(),
            size: 5,
            kind: OWNER_WRITE_REUPLOAD.into(),
            file_id: current.id.clone(),
            folder_id: None,
            expected_object_key: Some(current.object_key.clone()),
            created_at: 2,
            attempts: 0,
        };
        assert_eq!(
            s.reserve_owner_blob_write(&intent, Some(8)).await.unwrap(),
            OwnerBlobCommit::Applied
        );
        assert_eq!(
            s.commit_owner_reupload(OwnerReuploadInput {
                owner_sub: "u",
                file_id: "atomicfile",
                expected_object_key: "atomicfile",
                new_object_key: "atomic-new",
                new_size: 5,
                new_content_type: "image/webp",
                snapshot_id: "atomic-old-version",
                changed_at: 2,
                owner_quota: Some(8),
            })
            .await
            .unwrap(),
            OwnerBlobCommit::Applied
        );
        let replaced = s.get("atomicfile").await.unwrap().unwrap();
        assert_eq!(replaced.object_key, "atomic-new");
        assert_eq!(replaced.size, 5);
        let old = s
            .get_version("atomic-old-version", "atomicfile")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(old.object_key, "atomicfile");
        assert_eq!(old.size, 3);

        assert_eq!(
            s.commit_owner_version_restore(OwnerVersionRestoreInput {
                owner_sub: "u",
                file_id: "atomicfile",
                expected_object_key: "atomic-new",
                version_id: "atomic-old-version",
                snapshot_id: "atomic-new-version",
                changed_at: 3,
            })
            .await
            .unwrap(),
            OwnerBlobCommit::Applied
        );
        let restored = s.get("atomicfile").await.unwrap().unwrap();
        assert_eq!(restored.object_key, "atomicfile");
        assert_eq!(restored.size, 3);
        assert!(s
            .get_version("atomic-old-version", "atomicfile")
            .await
            .unwrap()
            .is_none());
        let snap = s
            .get_version("atomic-new-version", "atomicfile")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(snap.object_key, "atomic-new");
        assert_eq!(snap.size, 5);
        assert!(s
            .claim_owner_blob_writes("worker", 10, 10, 10, 10)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn public_commit_requires_exact_blob_and_receipt_without_consuming_on_conflict() {
        let s = InMemoryStore::new();
        s.create_folder(&folder("requestfolder", "u", "Request", 1))
            .await
            .unwrap();
        let request = UploadRequestRec {
            id: "exactrequest".into(),
            owner_sub: "u".into(),
            folder_id: "requestfolder".into(),
            token: "exact-token".into(),
            title: "Exact".into(),
            description: String::new(),
            status: "open".into(),
            expires_at: None,
            max_file_bytes: 10,
            max_total_bytes: 10,
            max_files: 1,
            used_bytes: 0,
            used_files: 0,
            allowed_types: "image/*".into(),
            created_at: 1,
            updated_at: 1,
        };
        assert!(s.create_upload_request(&request).await.unwrap());
        assert_eq!(
            s.reserve_request_upload(UploadReserveInput {
                request_id: &request.id,
                expected_token: &request.token,
                reservation_id: "exactblob",
                size: 3,
                content_type: "image/png",
                content_type_verified: true,
                owner_quota: None,
                now: 2,
            })
            .await
            .unwrap(),
            UploadReserve::Reserved
        );
        let mut exact = file("exactblob", "u", "unused", 2);
        exact.share_token = None;
        exact.folder_id = Some("requestfolder".into());
        let receipt = UploadSubmission {
            id: "exactreceipt".into(),
            request_id: request.id.clone(),
            file_id: exact.id.clone(),
            name: exact.name.clone(),
            content_type: exact.content_type.clone(),
            size: exact.size,
            created_at: 2,
        };
        let mut wrong_key = exact.clone();
        wrong_key.object_key = "different-blob".into();
        assert!(!s
            .commit_request_upload("exactblob", &wrong_key, &receipt)
            .await
            .unwrap());
        let mut wrong_receipt = receipt.clone();
        wrong_receipt.size = 2;
        assert!(!s
            .commit_request_upload("exactblob", &exact, &wrong_receipt)
            .await
            .unwrap());
        assert!(s
            .commit_request_upload("exactblob", &exact, &receipt)
            .await
            .unwrap());
        assert_eq!(
            s.get("exactblob").await.unwrap().unwrap().object_key,
            "exactblob"
        );
    }

    #[tokio::test]
    async fn purge_queues_all_blob_keys_and_failed_claims_back_off() {
        let s = InMemoryStore::new();
        s.create(&file("queuefile", "u", "queue-token", 1))
            .await
            .unwrap();
        s.add_version(&version("queueversion", "queuefile", 2, 1))
            .await
            .unwrap();
        assert!(s.trash_file("queuefile", "u", 10).await.unwrap());
        assert_eq!(
            s.bulk_purge(
                "u",
                &[DriveItemRef {
                    kind: LibraryItemKind::File,
                    id: "queuefile".into(),
                }],
                20,
            )
            .await
            .unwrap(),
            BulkMutation::Applied { changed: 1 }
        );
        assert!(s.get("queuefile").await.unwrap().is_none());

        let BlobDeleteClaim::Claimed(mut claimed) = s
            .claim_blob_deletions("worker-one", 20, 0, 20)
            .await
            .unwrap()
        else {
            panic!("purge must enqueue current, version, and thumbnail keys");
        };
        claimed.sort_by(|left, right| left.object_key.cmp(&right.object_key));
        assert_eq!(
            claimed
                .iter()
                .map(|item| item.object_key.as_str())
                .collect::<Vec<_>>(),
            vec![
                "queuefile",
                "queuefile.thumb",
                "queueversion-blob",
                "queueversion-blob.thumb",
            ]
        );
        let failed = &claimed[0];
        assert!(s
            .abandon_blob_deletion(&failed.object_key, "worker-one", 100)
            .await
            .unwrap());
        for item in &claimed[1..] {
            assert!(s
                .complete_blob_deletion(&item.object_key, "worker-one")
                .await
                .unwrap());
        }
        assert_eq!(
            s.claim_blob_deletions("worker-two", 99, 90, 20)
                .await
                .unwrap(),
            BlobDeleteClaim::Empty
        );
        let BlobDeleteClaim::Claimed(retry) = s
            .claim_blob_deletions("worker-two", 100, 90, 20)
            .await
            .unwrap()
        else {
            panic!("the failed key must become due after its backoff");
        };
        assert_eq!(retry.len(), 1);
        assert_eq!(retry[0].object_key, failed.object_key);
        assert_eq!(retry[0].attempts, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn lifecycle_read_snapshots_never_mix_subtree_generations() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let s = Arc::new(InMemoryStore::new());
        s.create_folder(&folder("snapshotfolder", "u", "Folder", 1))
            .await
            .unwrap();
        let mut nested = file("snapshotfile", "u", "snapshot-token", 1);
        nested.folder_id = Some("snapshotfolder".into());
        s.create(&nested).await.unwrap();
        let done = Arc::new(AtomicBool::new(false));

        let writer_store = s.clone();
        let writer_done = done.clone();
        let writer = tokio::spawn(async move {
            for index in 0..2_000 {
                assert!(matches!(
                    writer_store
                        .bulk_trash(
                            "u",
                            &[TrashRootInput {
                                item: DriveItemRef {
                                    kind: LibraryItemKind::Folder,
                                    id: "snapshotfolder".into(),
                                },
                                entry_id: format!("snapshotentry{index}"),
                            }],
                            index + 1,
                            index + 10_000,
                        )
                        .await
                        .unwrap(),
                    BulkMutation::Applied { .. }
                ));
                tokio::task::yield_now().await;
                assert!(matches!(
                    writer_store
                        .bulk_restore(
                            "u",
                            &[DriveItemRef {
                                kind: LibraryItemKind::Folder,
                                id: "snapshotfolder".into(),
                            }],
                        )
                        .await
                        .unwrap(),
                    BulkMutation::Applied { .. }
                ));
                tokio::task::yield_now().await;
            }
            writer_done.store(true, Ordering::Release);
        });

        let reader_store = s.clone();
        let reader_done = done.clone();
        let reader = tokio::spawn(async move {
            let query = LibraryQuery {
                view: LibraryView::All,
                query: None,
                type_filter: LibraryType::All,
                before: None,
                limit: 20,
            };
            let mut checks = 0;
            while !reader_done.load(Ordering::Acquire) || checks < 2_000 {
                let live = reader_store.query_library("u", &query).await.unwrap();
                assert!(
                    live.items.is_empty() || live.items.len() == 2,
                    "a snapshot cannot combine a live folder with a hidden descendant"
                );
                let trash = reader_store.query_trash("u", None, 20).await.unwrap();
                assert!(
                    trash.items.len() <= 1,
                    "a subtree has one visible Trash root"
                );
                checks += 1;
                tokio::task::yield_now().await;
            }
        });
        writer.await.unwrap();
        reader.await.unwrap();
    }
}
