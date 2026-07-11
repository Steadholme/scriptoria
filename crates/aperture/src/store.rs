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
use crate::model::{
    FileComment, FileRec, FolderRec, OwnerUsage, UploadRequestRec, UploadSubmission, VersionRec,
};

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

    /// Repoint a file's current blob (object key + size + content type) and bump `created_at`,
    /// ownership-scoped. Used by a re-upload (point at the new blob) and a version restore (point
    /// back at the snapshot). Returns `true` when the owner's row was updated.
    async fn update_file_blob(
        &self,
        id: &str,
        owner_sub: &str,
        object_key: &str,
        size: i64,
        content_type: &str,
        created_at: i64,
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

    /// Delete one comment by id.
    async fn delete_comment(&self, comment_id: &str) -> Result<bool, StoreError>;

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
    files: Mutex<Vec<FileRec>>,
    folders: Mutex<Vec<FolderRec>>,
    /// Retained blob snapshots (mirrors the `file_versions` table).
    versions: Mutex<Vec<VersionRec>>,
    /// Per-owner quota override rows, `(owner_sub, quota_bytes)` — mirrors the `owner_quotas` table.
    quotas: Mutex<Vec<(String, i64)>>,
    /// Per-file comments (mirrors the `file_comments` table).
    comments: Mutex<Vec<FileComment>>,
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
            f.id == file.id || (file.share_token.is_some() && f.share_token == file.share_token)
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
            .find(|f| f.trashed_at == 0 && f.share_token.as_deref() == Some(token))
            .cloned())
    }

    async fn bump_view_count(&self, id: &str) -> Result<(), StoreError> {
        let mut files = self.files.lock().expect("files lock poisoned");
        if let Some(f) = files.iter_mut().find(|f| f.id == id && f.trashed_at == 0) {
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
            .filter(|f| f.trashed_at == 0)
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
        let mut files = self.files.lock().expect("files lock poisoned");
        match files
            .iter_mut()
            .find(|f| f.id == id && f.owner_sub == owner_sub && f.trashed_at == 0)
        {
            Some(f) => {
                f.trashed_at = trashed_at.max(1);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn restore_file(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError> {
        let mut files = self.files.lock().expect("files lock poisoned");
        match files
            .iter_mut()
            .find(|f| f.id == id && f.owner_sub == owner_sub && f.trashed_at > 0)
        {
            Some(f) => {
                f.trashed_at = 0;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn rename_file(&self, id: &str, owner_sub: &str, name: &str) -> Result<bool, StoreError> {
        let mut files = self.files.lock().expect("files lock poisoned");
        match files
            .iter_mut()
            .find(|f| f.id == id && f.owner_sub == owner_sub && f.trashed_at == 0)
        {
            Some(f) => {
                f.name = name.to_string();
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

    async fn get_folder(&self, id: &str, owner_sub: &str) -> Result<Option<FolderRec>, StoreError> {
        let folders = self.folders.lock().expect("folders lock poisoned");
        Ok(folders
            .iter()
            .find(|f| f.id == id && f.owner_sub == owner_sub)
            .cloned())
    }

    async fn get_folder_by_token(&self, token: &str) -> Result<Option<FolderRec>, StoreError> {
        let folders = self.folders.lock().expect("folders lock poisoned");
        Ok(folders
            .iter()
            .find(|f| f.share_token.as_deref() == Some(token))
            .cloned())
    }

    async fn get_folder_by_upload_token(
        &self,
        token: &str,
    ) -> Result<Option<FolderRec>, StoreError> {
        let folders = self.folders.lock().expect("folders lock poisoned");
        Ok(folders
            .iter()
            .find(|f| f.upload_token.as_deref() == Some(token))
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

    async fn configure_folder_upload(
        &self,
        id: &str,
        owner_sub: &str,
        upload_token: Option<String>,
    ) -> Result<bool, StoreError> {
        let mut folders = self.folders.lock().expect("folders lock poisoned");
        match folders
            .iter_mut()
            .find(|f| f.id == id && f.owner_sub == owner_sub)
        {
            Some(f) => {
                f.upload_token = upload_token;
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
                    && f.trashed_at == 0
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
                    && f.trashed_at == 0
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
        created_at: i64,
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
                f.created_at = created_at;
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
        let mut comments = self.comments.lock().expect("comments lock poisoned");
        if comments.iter().any(|c| c.id == comment.id) {
            return Ok(false);
        }
        comments.push(comment.clone());
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

    async fn delete_comment(&self, comment_id: &str) -> Result<bool, StoreError> {
        let mut comments = self.comments.lock().expect("comments lock poisoned");
        let before = comments.len();
        comments.retain(|c| c.id != comment_id);
        Ok(comments.len() != before)
    }

    async fn delete_comments_for_file(&self, file_id: &str) -> Result<(), StoreError> {
        let mut comments = self.comments.lock().expect("comments lock poisoned");
        comments.retain(|c| c.file_id != file_id);
        Ok(())
    }

    async fn create_upload_request(&self, request: &UploadRequestRec) -> Result<bool, StoreError> {
        let mut state = self
            .request_state
            .lock()
            .expect("request state lock poisoned");
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
        let Some(request) = state
            .requests
            .iter_mut()
            .find(|item| item.id == id && item.owner_sub == owner_sub)
        else {
            return Ok(false);
        };
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
        let Some(request) = state
            .requests
            .iter_mut()
            .find(|item| item.id == id && item.owner_sub == owner_sub)
        else {
            return Ok(false);
        };
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
        if owner_quota.is_some_and(|quota| {
            committed
                .saturating_add(version_bytes)
                .saturating_add(reserved)
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
            || file.owner_sub != reservation.owner_sub
            || file.size != reservation.size
            || submission.request_id != reservation.request_id
            || submission.file_id != file.id
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
use sqlx::Row;

/// Column list shared by every SELECT, so the row decoder stays in lock-step with the query.
const COLS: &str = "id, owner_sub, name, content_type, size, bucket, object_key, share_token, \
     created_at, expires_at, share_password_hash, folder_id, trashed_at, view_count";

/// Column list shared by every folder SELECT.
const FOLDER_COLS: &str =
    "id, owner_sub, parent_id, name, created_at, share_token, expires_at, share_password_hash, \
     upload_token";

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
        // Soft-delete marker. Live rows are `0`; trashed rows keep their blob and continue counting
        // toward usage until purged. Additive + idempotent; existing rows become live.
        sqlx::query("ALTER TABLE files ADD COLUMN IF NOT EXISTS trashed_at BIGINT DEFAULT 0")
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
            expires_at: row.try_get("expires_at")?,
            share_password_hash: row.try_get("share_password_hash")?,
            folder_id: row.try_get("folder_id")?,
            trashed_at: row.try_get("trashed_at")?,
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
            share_token: row.try_get("share_token")?,
            expires_at: row.try_get("expires_at")?,
            share_password_hash: row.try_get("share_password_hash")?,
            upload_token: row.try_get("upload_token")?,
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
                  created_at, expires_at, share_password_hash, folder_id, trashed_at, view_count) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
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
        .bind(file.trashed_at)
        .bind(file.view_count)
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
        let row = sqlx::query(&format!(
            "SELECT {COLS} FROM files WHERE share_token = $1 AND trashed_at = 0"
        ))
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::file_from_row).transpose()
    }

    async fn bump_view_count_async(&self, id: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE files SET view_count = view_count + 1 WHERE id = $1 AND trashed_at = 0",
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
                     AND trashed_at = 0 \
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
                     AND trashed_at = 0 \
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
                     AND trashed_at = 0 \
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
                     AND trashed_at = 0 \
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

    async fn trash_file_async(
        &self,
        id: &str,
        owner_sub: &str,
        trashed_at: i64,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE files SET trashed_at = $1 WHERE id = $2 AND owner_sub = $3 AND trashed_at = 0",
        )
        .bind(trashed_at.max(1))
        .bind(id)
        .bind(owner_sub)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn restore_file_async(&self, id: &str, owner_sub: &str) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE files SET trashed_at = 0 WHERE id = $1 AND owner_sub = $2 AND trashed_at <> 0",
        )
        .bind(id)
        .bind(owner_sub)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn rename_file_async(
        &self,
        id: &str,
        owner_sub: &str,
        name: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE files SET name = $1 WHERE id = $2 AND owner_sub = $3 AND trashed_at = 0",
        )
        .bind(name)
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

    async fn create_folder_async(&self, folder: &FolderRec) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "INSERT INTO folders \
                 (id, owner_sub, parent_id, name, created_at, share_token, expires_at, \
                  share_password_hash, upload_token) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT DO NOTHING",
        )
        .bind(&folder.id)
        .bind(&folder.owner_sub)
        .bind(&folder.parent_id)
        .bind(&folder.name)
        .bind(folder.created_at)
        .bind(&folder.share_token)
        .bind(folder.expires_at)
        .bind(&folder.share_password_hash)
        .bind(&folder.upload_token)
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

    async fn get_folder_by_token_async(
        &self,
        token: &str,
    ) -> Result<Option<FolderRec>, sqlx::Error> {
        let row = sqlx::query(&format!(
            "SELECT {FOLDER_COLS} FROM folders WHERE share_token = $1"
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
            "SELECT {FOLDER_COLS} FROM folders WHERE upload_token = $1"
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
        let result = sqlx::query("UPDATE folders SET name = $1 WHERE id = $2 AND owner_sub = $3")
            .bind(name)
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
        let result = sqlx::query(
            "UPDATE folders SET share_token = $1, expires_at = $2, share_password_hash = $3 \
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

    async fn configure_folder_upload_async(
        &self,
        id: &str,
        owner_sub: &str,
        upload_token: Option<String>,
    ) -> Result<bool, sqlx::Error> {
        let result =
            sqlx::query("UPDATE folders SET upload_token = $1 WHERE id = $2 AND owner_sub = $3")
                .bind(&upload_token)
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
             AND trashed_at = 0 \
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
                     AND trashed_at = 0 LIMIT 1"
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
                     AND trashed_at = 0 LIMIT 1"
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
        created_at: i64,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE files SET object_key = $1, size = $2, content_type = $3, created_at = $4 \
             WHERE id = $5 AND owner_sub = $6",
        )
        .bind(object_key)
        .bind(size)
        .bind(content_type)
        .bind(created_at)
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
        let result =
            sqlx::query("UPDATE files SET folder_id = $1 WHERE id = $2 AND owner_sub = $3")
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
        let result = sqlx::query(
            "INSERT INTO file_comments (id, file_id, author_sub, body, created_at) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
        )
        .bind(&comment.id)
        .bind(&comment.file_id)
        .bind(&comment.author_sub)
        .bind(&comment.body)
        .bind(comment.created_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
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

    async fn delete_comment_async(&self, comment_id: &str) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM file_comments WHERE id = $1")
            .bind(comment_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
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
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
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
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
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
        if !capability_token_eq(&request.token, expected_token)
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

        // Lock one stable row per owner so simultaneous uploads through DIFFERENT request rooms
        // cannot both pass the global quota decision.
        sqlx::query(
            "INSERT INTO owner_storage_guards (owner_sub) VALUES ($1) ON CONFLICT DO NOTHING",
        )
        .bind(&request.owner_sub)
        .execute(&mut *tx)
        .await?;
        sqlx::query("SELECT owner_sub FROM owner_storage_guards WHERE owner_sub = $1 FOR UPDATE")
            .bind(&request.owner_sub)
            .fetch_one(&mut *tx)
            .await?;

        if sqlx::query("SELECT 1 FROM files WHERE id = $1")
            .bind(reservation_id)
            .fetch_optional(&mut *tx)
            .await?
            .is_some()
        {
            tx.rollback().await?;
            return Ok(UploadReserve::Collision);
        }

        if let Some(quota) = owner_quota {
            let files = sqlx::query(
                "SELECT CAST(COALESCE(SUM(size), 0) AS BIGINT) AS bytes \
                 FROM files WHERE owner_sub = $1",
            )
            .bind(&request.owner_sub)
            .fetch_one(&mut *tx)
            .await?
            .try_get::<i64, _>("bytes")?;
            let versions = sqlx::query(
                "SELECT CAST(COALESCE(SUM(v.size), 0) AS BIGINT) AS bytes \
                 FROM file_versions v JOIN files f ON f.id = v.file_id WHERE f.owner_sub = $1",
            )
            .bind(&request.owner_sub)
            .fetch_one(&mut *tx)
            .await?
            .try_get::<i64, _>("bytes")?;
            let reservations = sqlx::query(
                "SELECT CAST(COALESCE(SUM(size), 0) AS BIGINT) AS bytes \
                 FROM upload_reservations WHERE owner_sub = $1",
            )
            .bind(&request.owner_sub)
            .fetch_one(&mut *tx)
            .await?
            .try_get::<i64, _>("bytes")?;
            if files
                .saturating_add(versions)
                .saturating_add(reservations)
                .saturating_add(size)
                > quota
            {
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
        // Peek only to discover the immutable request/owner lock keys. Every writer then takes
        // locks in request -> owner guard -> reservation order, matching reserve. The reservation
        // is re-read FOR UPDATE below before any state is committed.
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
            || file.owner_sub != owner_sub
            || file.size != reserved_size
            || submission.request_id != request_id
            || submission.file_id != file.id
        {
            tx.rollback().await?;
            return Ok(false);
        }

        let request_locked = sqlx::query("SELECT id FROM upload_requests WHERE id = $1 FOR UPDATE")
            .bind(&request_id)
            .fetch_optional(&mut *tx)
            .await?
            .is_some();
        if !request_locked {
            tx.rollback().await?;
            return Ok(false);
        }

        // Serialize the reservation -> file conversion with every public quota decision for this
        // owner. Without this lock, a READ COMMITTED reserve could read `files` before this commit
        // and `upload_reservations` after it, missing the same bytes in both snapshots.
        sqlx::query(
            "INSERT INTO owner_storage_guards (owner_sub) VALUES ($1) ON CONFLICT DO NOTHING",
        )
        .bind(&owner_sub)
        .execute(&mut *tx)
        .await?;
        sqlx::query("SELECT owner_sub FROM owner_storage_guards WHERE owner_sub = $1 FOR UPDATE")
            .bind(&owner_sub)
            .fetch_one(&mut *tx)
            .await?;

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

        let inserted_file = sqlx::query(
            "INSERT INTO files \
                 (id, owner_sub, name, content_type, size, bucket, object_key, share_token, \
                  created_at, expires_at, share_password_hash, folder_id, trashed_at, view_count) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
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
        .bind(file.trashed_at)
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
        created_at: i64,
    ) -> Result<bool, StoreError> {
        self.update_file_blob_async(id, owner_sub, object_key, size, content_type, created_at)
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

    async fn delete_comment(&self, comment_id: &str) -> Result<bool, StoreError> {
        self.delete_comment_async(comment_id)
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
            trashed_at: 0,
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
        assert!(s.delete_comment("c1").await.unwrap());
        assert_eq!(s.list_comments("a").await.unwrap().len(), 1);
        s.delete_comments_for_file("a").await.unwrap();
        assert!(s.list_comments("a").await.unwrap().is_empty());
    }

    fn folder(id: &str, owner: &str, name: &str, created_at: i64) -> FolderRec {
        FolderRec {
            id: id.into(),
            owner_sub: owner.into(),
            parent_id: None,
            name: name.into(),
            created_at,
            share_token: None,
            expires_at: None,
            share_password_hash: None,
            upload_token: None,
        }
    }

    /// A child folder under `parent`.
    fn subfolder(id: &str, owner: &str, parent: &str, name: &str) -> FolderRec {
        FolderRec {
            id: id.into(),
            owner_sub: owner.into(),
            parent_id: Some(parent.into()),
            name: name.into(),
            created_at: 0,
            share_token: None,
            expires_at: None,
            share_password_hash: None,
            upload_token: None,
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
        assert_eq!(got.created_at, 999);
        // Owner-scoped.
        assert!(!s
            .update_file_blob("a", "intruder", "x", 1, "text/plain", 1)
            .await
            .unwrap());
    }
}
