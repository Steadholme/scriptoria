//! Core domain type: a stored file's metadata row.
//!
//! One flat record per the agreed schema (db `aperture`, table `files`). The blob bytes live in
//! Cairn under `(bucket, object_key)`; this row is the index over them. Identity (`owner_sub`)
//! always comes from the Sluice-injected `X-Auth-Subject`, never from client input.

/// The set of raster image content types Aperture renders INLINE (gallery thumbnail, detail
/// preview, `Content-Disposition: inline`). Detected from magic bytes only — a client-claimed
/// type is never trusted to mark content as an inline image. Everything else (including
/// `image/svg+xml`, HTML, scripts) is served as a download, neutralizing stored-content XSS.
pub const INLINE_IMAGE_TYPES: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/bmp",
];

/// True when `content_type` is a raster image we are willing to serve inline / preview.
pub fn is_inline_image(content_type: &str) -> bool {
    INLINE_IMAGE_TYPES.contains(&content_type)
}

/// True when `content_type` is browser-native media that can be served inline and range-streamed.
pub fn is_streamable_media(content_type: &str) -> bool {
    content_type.starts_with("video/") || content_type.starts_with("audio/")
}

/// A single stored file. Field order/types mirror the `files` table exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRec {
    /// Short, random, URL-safe id (the `/f/{id}` slug + primary key).
    pub id: String,
    /// Owner subject from `X-Auth-Subject` (ownership key for view/raw/delete).
    pub owner_sub: String,
    /// Original file name as submitted (display only; escaped on render, sanitized for headers).
    pub name: String,
    /// Resolved content type (magic-sniffed for images, else the sanitized client type).
    pub content_type: String,
    /// Size in bytes.
    pub size: i64,
    /// Object-store bucket holding the blob.
    pub bucket: String,
    /// Object-store key holding the blob.
    pub object_key: String,
    /// Unguessable public share token (`/s/{token}` fetches the blob WITHOUT SSO). `None` once the
    /// share link has been revoked — the file then has NO public surface at all.
    pub share_token: Option<String>,
    /// Upload time, epoch seconds.
    pub created_at: i64,
    /// Last owner-visible metadata/content mutation, epoch seconds. Unlike `view_count`, this is
    /// never changed by anonymous share traffic; it is the authoritative ordering key for Recent.
    pub updated_at: i64,
    /// Optional share-link expiry instant, epoch seconds. `None` = the share link never expires.
    /// Past this instant the public `/s/{token}` fetch returns `410 Gone` (the OWNER still has full
    /// SSO access via `/f/{id}`).
    pub expires_at: Option<i64>,
    /// Optional salted-hash of a share-link password (`{salt}${sha256_hex}`). `None` = no password.
    /// When set, the public `/s/{token}` fetch prompts for the password before serving the blob.
    pub share_password_hash: Option<String>,
    /// Optional owning folder id (a [`FolderRec`] belonging to the same `owner_sub`). `None` = the
    /// file lives at the drive ROOT (the tree's top level). A folder view (`?folder={id}`) lists
    /// exactly the files whose `folder_id` matches; the root view lists the files whose `folder_id`
    /// IS NULL.
    pub folder_id: Option<String>,
    /// Soft-delete marker, epoch seconds. `0` means live; a positive value means the file is in the
    /// owner's trash. Trashed files stay in storage (and quota usage) until purged.
    pub trashed_at: i64,
    /// Durable root entry when this file was explicitly moved to Trash. `None` for live files and
    /// for files hidden only because an ancestor folder is in Trash.
    pub trash_entry_id: Option<String>,
    /// The nearest independently-trashed ancestor folder that currently hides this file. Keeping
    /// this separate from `trash_entry_id` lets restoring an outer folder preserve nested items
    /// that had already been trashed on their own.
    pub trash_ancestor_id: Option<String>,
    /// Public landing-page open count. Only `/s/{token}/view` increments this; direct blob fetches
    /// remain byte-for-byte compatible and do not count views.
    pub view_count: i64,
}

/// A single per-file comment. Bodies are display-only and always escaped at render time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileComment {
    /// Short random id for delete forms.
    pub id: String,
    /// The commented file.
    pub file_id: String,
    /// Subject from `X-Auth-Subject` of the commenter.
    pub author_sub: String,
    /// Submitted comment body, trimmed and capped by the handler.
    pub body: String,
    /// Creation time, epoch seconds.
    pub created_at: i64,
}

/// A single blob snapshot kept when a file is re-uploaded under the same name in the same folder.
/// The prior blob is retained under its own `object_key` instead of being overwritten, so the
/// owner can download or restore it. Field order/types mirror the `file_versions` table exactly.
///
/// NOTE on columns: the schema keeps `content_type` alongside the spec's
/// `id, file_id, object_key, size, created_at` so a restore can swap the file's content type back
/// to the snapshotted blob's type (a same-name re-upload can still change the type); without it a
/// restored blob would inherit the current row's — possibly wrong — type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionRec {
    /// Short, random, URL-safe id (the version selector + primary key).
    pub id: String,
    /// The owning file's id (a [`FileRec::id`]). Ownership is enforced through that file.
    pub file_id: String,
    /// Object-store key holding this version's blob.
    pub object_key: String,
    /// Size in bytes (counts toward the owner's storage usage / quota).
    pub size: i64,
    /// The snapshotted blob's resolved content type (restored verbatim on a restore).
    pub content_type: String,
    /// Snapshot time (when this blob stopped being the current one), epoch seconds.
    pub created_at: i64,
}

/// Aggregated per-owner storage usage (file count + total stored bytes), computed from the
/// `files` table. Backs the drive's usage meter and the `/admin` usage table; it is never
/// persisted itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerUsage {
    /// Owner subject (`X-Auth-Subject`), the same ownership key as [`FileRec::owner_sub`].
    pub owner_sub: String,
    /// Number of stored files.
    pub files: i64,
    /// Total stored bytes (SUM of the owner's file sizes).
    pub bytes: i64,
}

/// A single owner-scoped folder node in the drive's folder TREE. Field order/types mirror the
/// `folders` table exactly. Files reference it via [`FileRec::folder_id`]; child folders reference
/// it via [`FolderRec::parent_id`]. A folder can carry its OWN public share link (token / expiry /
/// password), mirroring a file's share fields, so a whole folder can be shared as a public index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FolderRec {
    /// Short, random, URL-safe id (the `?folder={id}` selector + primary key).
    pub id: String,
    /// Owner subject from `X-Auth-Subject` (ownership key for list/rename/delete/share).
    pub owner_sub: String,
    /// Optional parent folder id (a [`FolderRec`] of the same owner). `None` = a ROOT folder (top
    /// of the tree). Folders are only ever created under the current level, so the parent chain can
    /// never form a cycle.
    pub parent_id: Option<String>,
    /// Display name as submitted (display only; escaped on render).
    pub name: String,
    /// Creation time, epoch seconds.
    pub created_at: i64,
    /// Last owner-visible folder mutation, epoch seconds. Child activity does not implicitly touch
    /// the folder, so Recent never amplifies one upload into a whole ancestor chain.
    pub updated_at: i64,
    /// Unguessable public share token (`/s/folder/{token}` lists this folder's files WITHOUT SSO). `None`
    /// once revoked (or never shared) — the folder then has NO public surface.
    pub share_token: Option<String>,
    /// Optional folder-share expiry instant, epoch seconds. `None` = never expires. Past it the
    /// public `/s/folder/{token}` index returns `410 Gone`.
    pub expires_at: Option<i64>,
    /// Optional salted-hash of a folder-share password (`{salt}${sha256_hex}`). `None` = no password.
    pub share_password_hash: Option<String>,
    /// Unguessable public upload-inbox token (`/u/{token}`) for anonymous uploads into this folder.
    /// `None` means the upload inbox is disabled/revoked.
    pub upload_token: Option<String>,
    /// Epoch seconds when this folder was explicitly moved to Trash; `0` while it is not a Trash
    /// root. Descendants inherit visibility through `trash_ancestor_id` instead of becoming roots.
    pub trashed_at: i64,
    /// Durable root entry when this folder was explicitly moved to Trash.
    pub trash_entry_id: Option<String>,
    /// The independently-trashed ancestor folder that currently hides this folder.
    pub trash_ancestor_id: Option<String>,
}

impl FileRec {
    /// Whether the file is reachable from normal owner and capability surfaces.
    pub fn is_effectively_live(&self) -> bool {
        self.trashed_at == 0 && self.trash_entry_id.is_none() && self.trash_ancestor_id.is_none()
    }
}

impl FolderRec {
    /// Whether the folder is reachable from normal owner and capability surfaces.
    pub fn is_effectively_live(&self) -> bool {
        self.trashed_at == 0 && self.trash_entry_id.is_none() && self.trash_ancestor_id.is_none()
    }
}

/// One explicitly-trashed root. Descendants are hidden by `trash_ancestor_id`; they do not create
/// duplicate rows in the Trash view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrashEntry {
    pub id: String,
    pub owner_sub: String,
    pub kind: LibraryItemKind,
    pub item_id: String,
    pub trashed_at: i64,
    pub purge_after: i64,
    pub recovery_lease: Option<String>,
    pub recovery_leased_at: Option<i64>,
}

/// Owner-facing projection for a single Trash root. It intentionally contains no capability
/// token, object key, or password material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrashItem {
    pub entry_id: String,
    pub kind: LibraryItemKind,
    pub id: String,
    pub name: String,
    pub content_type: Option<String>,
    pub size: Option<i64>,
    pub trashed_at: i64,
    pub purge_after: i64,
}

impl TrashItem {
    pub fn cursor(&self) -> LibraryCursor {
        LibraryCursor {
            updated_at: self.trashed_at,
            kind: self.kind,
            id: self.id.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrashPage {
    pub items: Vec<TrashItem>,
    pub next: Option<LibraryCursor>,
}

/// A product-level public file request. Unlike the legacy `folders.upload_token` flag, a request
/// has its own lifecycle and finite abuse budget. The destination folder remains private: the
/// public capability can only append files and can never enumerate the folder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadRequestRec {
    /// Short owner-facing id used by `/requests/{id}`.
    pub id: String,
    /// Owner charged for every accepted submission.
    pub owner_sub: String,
    /// Private destination folder owned by `owner_sub`.
    pub folder_id: String,
    /// Unguessable public `/u/{token}` capability. Rotation replaces this atomically.
    pub token: String,
    /// Public request-room title.
    pub title: String,
    /// Optional public instructions; stored as literal text and escaped on render.
    pub description: String,
    /// `open` accepts uploads; `closed` keeps receipts but rejects the public capability.
    pub status: String,
    /// Optional absolute close instant. New requests always receive a finite default; `None` is
    /// retained only for migrated legacy links so migration never silently breaks them.
    pub expires_at: Option<i64>,
    /// Per-file byte ceiling, additionally bounded by the service-wide HTTP upload limit.
    pub max_file_bytes: i64,
    /// Cumulative byte budget for this request, including in-flight reservations.
    pub max_total_bytes: i64,
    /// Cumulative file-count budget for this request, including in-flight reservations.
    pub max_files: i64,
    /// Committed plus in-flight bytes consumed from this request's budget.
    pub used_bytes: i64,
    /// Committed plus in-flight files consumed from this request's budget.
    pub used_files: i64,
    /// Comma-separated normalized MIME patterns (`image/*`, `application/pdf`, or `*/*`).
    pub allowed_types: String,
    pub created_at: i64,
    pub updated_at: i64,
}

impl UploadRequestRec {
    pub fn is_open(&self) -> bool {
        self.status == "open"
    }

    pub fn is_expired(&self, now: i64) -> bool {
        matches!(self.expires_at, Some(expiry) if now >= expiry)
    }

    pub fn accepts_content_type(&self, content_type: &str) -> bool {
        self.allowed_types.split(',').any(|raw| {
            let pattern = raw.trim();
            pattern == "*/*"
                || pattern == content_type
                || pattern
                    .strip_suffix("/*")
                    .is_some_and(|prefix| content_type.starts_with(&format!("{prefix}/")))
        })
    }
}

/// Fixed owner-Inbox ceiling. Counts remain exact, but the HTML surface deliberately renders only
/// the newest bounded slice so one owner cannot turn a control-plane GET into an unbounded read.
pub const UPLOAD_REQUEST_INBOX_CAP: i64 = 100;

/// A live request enters the attention-oriented Expiring bucket during its final 72 hours. The
/// classification always receives an explicit `as_of`; callers must not sample the wall clock per
/// row or per count.
pub const UPLOAD_REQUEST_EXPIRING_WINDOW_SECS: i64 = 72 * 60 * 60;

/// URL-selected, mutually-exclusive owner Inbox view. `All` is the only aggregate view; the other
/// variants partition every request at one shared `as_of` instant.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UploadRequestInboxView {
    #[default]
    All,
    Open,
    Expiring,
    Closed,
    Expired,
}

impl UploadRequestInboxView {
    pub const ALL: [Self; 5] = [
        Self::All,
        Self::Open,
        Self::Expiring,
        Self::Closed,
        Self::Expired,
    ];

    pub fn slug(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Open => "open",
            Self::Expiring => "expiring",
            Self::Closed => "closed",
            Self::Expired => "expired",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Open => "Open",
            Self::Expiring => "Expiring",
            Self::Closed => "Closed",
            Self::Expired => "Expired",
        }
    }

    pub fn from_slug(value: &str) -> Option<Self> {
        match value {
            "all" => Some(Self::All),
            "open" => Some(Self::Open),
            "expiring" => Some(Self::Expiring),
            "closed" => Some(Self::Closed),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }
}

/// Effective request state at one owner-Inbox snapshot. Expiring is a display bucket, not a
/// persisted lifecycle mutation. Explicit closure wins over a passed deadline; only persisted
/// `open` requests can classify as Expired or Expiring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UploadRequestInboxState {
    Open,
    Expiring,
    Closed,
    Expired,
}

impl UploadRequestInboxState {
    pub fn classify(status: &str, expires_at: Option<i64>, as_of: i64) -> Self {
        if status != "open" {
            return Self::Closed;
        }
        let Some(expires_at) = expires_at else {
            return Self::Open;
        };
        if expires_at <= as_of {
            return Self::Expired;
        }
        if expires_at <= as_of.saturating_add(UPLOAD_REQUEST_EXPIRING_WINDOW_SECS) {
            return Self::Expiring;
        }
        Self::Open
    }

    pub fn slug(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Expiring => "expiring",
            Self::Closed => "closed",
            Self::Expired => "expired",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Open => "Open",
            Self::Expiring => "Expiring",
            Self::Closed => "Closed",
            Self::Expired => "Expired",
        }
    }

    pub fn from_slug(value: &str) -> Option<Self> {
        match value {
            "open" => Some(Self::Open),
            "expiring" => Some(Self::Expiring),
            "closed" => Some(Self::Closed),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }

    pub fn is_in_view(self, view: UploadRequestInboxView) -> bool {
        view == UploadRequestInboxView::All
            || matches!(
                (self, view),
                (Self::Open, UploadRequestInboxView::Open)
                    | (Self::Expiring, UploadRequestInboxView::Expiring)
                    | (Self::Closed, UploadRequestInboxView::Closed)
                    | (Self::Expired, UploadRequestInboxView::Expired)
            )
    }
}

/// Dedicated, token-free owner Inbox projection. It intentionally has no owner subject,
/// destination folder id, raw token, public URL, MIME policy, object key, bucket, or other storage
/// material. The owner can reach the authorized canonical detail page through `id`; only that
/// explicit Access panel projects the current public capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadRequestSummary {
    pub id: String,
    pub title: String,
    pub description: String,
    pub state: UploadRequestInboxState,
    pub expires_at: Option<i64>,
    pub max_total_bytes: i64,
    pub max_files: i64,
    pub used_bytes: i64,
    pub used_files: i64,
    pub updated_at: i64,
}

/// Exact counts from the same owner query and `as_of` used to classify the bounded rows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UploadRequestInboxCounts {
    pub all: i64,
    pub open: i64,
    pub expiring: i64,
    pub closed: i64,
    pub expired: i64,
}

impl UploadRequestInboxCounts {
    pub fn for_view(self, view: UploadRequestInboxView) -> i64 {
        match view {
            UploadRequestInboxView::All => self.all,
            UploadRequestInboxView::Open => self.open,
            UploadRequestInboxView::Expiring => self.expiring,
            UploadRequestInboxView::Closed => self.closed,
            UploadRequestInboxView::Expired => self.expired,
        }
    }
}

/// One bounded owner Inbox snapshot. `matched_total` can exceed `items.len()`; `truncated` makes
/// that condition explicit to the renderer instead of silently hiding older requests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadRequestInbox {
    pub as_of: i64,
    pub view: UploadRequestInboxView,
    pub counts: UploadRequestInboxCounts,
    pub matched_total: i64,
    pub items: Vec<UploadRequestSummary>,
    pub truncated: bool,
}

/// One anonymous delivery session created by the first successfully committed request upload.
/// `receipt_token_hash` is the SHA-256 digest of an independently generated receipt capability;
/// the raw token is returned only to the submitter and is never stored in metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadDelivery {
    pub id: String,
    pub request_id: String,
    pub receipt_token_hash: String,
    pub created_at: i64,
    pub acknowledged_at: Option<i64>,
    pub receipt_expires_at: i64,
}

/// A delivery plus the immutable file snapshots that belong to it. Owner and public receipt
/// renderers share this value, while authorization remains in the Store query that constructs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadDeliveryBundle {
    pub delivery: UploadDelivery,
    pub submissions: Vec<UploadSubmission>,
}

/// Immutable receipt for one file accepted through an [`UploadRequestRec`]. File metadata is
/// snapshotted here so the request history remains intelligible after the file is moved or purged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadSubmission {
    pub id: String,
    pub request_id: String,
    pub file_id: String,
    pub name: String,
    pub content_type: String,
    pub size: i64,
    pub created_at: i64,
    /// `None` for pre-v8 legacy rows. New uploads always bind to one delivery session.
    pub delivery_id: Option<String>,
}

/// Owner-library view selected by the URL. `All` is the global search/filter result set;
/// `Recent` has the same membership but communicates owner-activity ordering; `Shared` includes
/// owner-created file/folder read links, including expired or password-protected links.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LibraryView {
    #[default]
    All,
    Recent,
    Shared,
}

impl LibraryView {
    pub fn slug(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Recent => "recent",
            Self::Shared => "shared",
        }
    }
}

/// Stable, product-level type groups for URL filters. These labels are discovery metadata only;
/// inline/download security continues to use the stricter magic-derived content-type checks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LibraryType {
    #[default]
    All,
    Folder,
    Image,
    Video,
    Audio,
    Pdf,
    Document,
    Archive,
    Other,
}

impl LibraryType {
    pub fn slug(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Folder => "folder",
            Self::Image => "image",
            Self::Video => "video",
            Self::Audio => "audio",
            Self::Pdf => "pdf",
            Self::Document => "document",
            Self::Archive => "archive",
            Self::Other => "other",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All types",
            Self::Folder => "Folders",
            Self::Image => "Images",
            Self::Video => "Videos",
            Self::Audio => "Audio",
            Self::Pdf => "PDFs",
            Self::Document => "Documents",
            Self::Archive => "Archives",
            Self::Other => "Other",
        }
    }
}

/// Classify a stored file for owner-facing filters. This intentionally has no bearing on whether a
/// blob may render inline: [`is_inline_image`] remains the security authority for that decision.
pub fn library_type_for(content_type: &str) -> LibraryType {
    let ct = content_type.to_ascii_lowercase();
    if ct.starts_with("image/") {
        LibraryType::Image
    } else if ct.starts_with("video/") {
        LibraryType::Video
    } else if ct.starts_with("audio/") {
        LibraryType::Audio
    } else if ct == "application/pdf" {
        LibraryType::Pdf
    } else if ct.starts_with("text/")
        || matches!(
            ct.as_str(),
            "application/msword"
                | "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                | "application/vnd.oasis.opendocument.text"
                | "application/rtf"
        )
    {
        LibraryType::Document
    } else if ct.contains("zip")
        || ct.contains("tar")
        || ct.contains("gzip")
        || ct.contains("compress")
        || ct.contains("x-7z")
        || ct.contains("x-rar")
    {
        LibraryType::Archive
    } else {
        LibraryType::Other
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LibraryItemKind {
    Folder,
    File,
}

impl LibraryItemKind {
    /// Files sort before folders when their update timestamps collide. The rank is part of the
    /// cursor so pagination stays stable across the two independently queried tables.
    pub fn rank(self) -> i8 {
        match self {
            Self::Folder => 0,
            Self::File => 1,
        }
    }

    pub fn slug(self) -> &'static str {
        match self {
            Self::Folder => "folder",
            Self::File => "file",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LibraryCursor {
    pub updated_at: i64,
    pub kind: LibraryItemKind,
    pub id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LibraryQuery {
    pub view: LibraryView,
    pub query: Option<String>,
    pub type_filter: LibraryType,
    pub before: Option<LibraryCursor>,
    pub limit: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LibraryItem {
    pub kind: LibraryItemKind,
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub content_type: Option<String>,
    pub size: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    pub shared: bool,
    pub share_expired: bool,
    pub share_protected: bool,
}

impl LibraryItem {
    pub fn cursor(&self) -> LibraryCursor {
        LibraryCursor {
            updated_at: self.updated_at,
            kind: self.kind,
            id: self.id.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LibraryPage {
    pub items: Vec<LibraryItem>,
    pub next: Option<LibraryCursor>,
}

impl FileRec {
    /// True when this file is a raster image we render inline.
    pub fn is_image(&self) -> bool {
        is_inline_image(&self.content_type)
    }

    /// True when this file is browser-native video.
    pub fn is_video(&self) -> bool {
        self.content_type.starts_with("video/")
    }

    /// True when this file is browser-native audio.
    pub fn is_audio(&self) -> bool {
        self.content_type.starts_with("audio/")
    }

    /// True when this file is safe to serve inline as image/video/audio media.
    pub fn is_media(&self) -> bool {
        self.is_image() || self.is_video() || self.is_audio()
    }

    /// True once `now` (epoch seconds) has reached the share-link expiry instant. A `None` expiry
    /// never expires. Mirrors pastefire's `Paste::is_expired` idiom.
    pub fn share_expired(&self, now: i64) -> bool {
        matches!(self.expires_at, Some(exp) if now >= exp)
    }

    /// True when the share link is password-protected.
    pub fn share_has_password(&self) -> bool {
        self.share_password_hash.is_some()
    }
}

impl FolderRec {
    /// True once `now` (epoch seconds) has reached the folder-share expiry instant. A `None` expiry
    /// never expires. Mirrors [`FileRec::share_expired`].
    pub fn share_expired(&self, now: i64) -> bool {
        matches!(self.expires_at, Some(exp) if now >= exp)
    }

    /// True when the folder share link is password-protected.
    pub fn share_has_password(&self) -> bool {
        self.share_password_hash.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_image_allowlist_is_magic_only() {
        assert!(is_inline_image("image/png"));
        assert!(is_inline_image("image/jpeg"));
        // SVG can carry script — never inline.
        assert!(!is_inline_image("image/svg+xml"));
        assert!(!is_inline_image("text/html"));
        assert!(!is_inline_image("application/octet-stream"));
    }

    #[test]
    fn streamable_media_is_video_or_audio_only() {
        assert!(is_streamable_media("video/mp4"));
        assert!(is_streamable_media("audio/mpeg"));
        assert!(!is_streamable_media("image/png"));
        assert!(!is_streamable_media("image/svg+xml"));
        assert!(!is_streamable_media("text/html"));
        assert!(!is_streamable_media("application/javascript"));
    }

    #[test]
    fn library_type_groups_are_stable_and_not_inline_authority() {
        assert_eq!(library_type_for("image/svg+xml"), LibraryType::Image);
        assert!(!is_inline_image("image/svg+xml"));
        assert_eq!(library_type_for("video/mp4"), LibraryType::Video);
        assert_eq!(library_type_for("audio/mpeg"), LibraryType::Audio);
        assert_eq!(library_type_for("application/pdf"), LibraryType::Pdf);
        assert_eq!(library_type_for("text/markdown"), LibraryType::Document);
        assert_eq!(library_type_for("application/zip"), LibraryType::Archive);
        assert_eq!(
            library_type_for("application/octet-stream"),
            LibraryType::Other
        );
    }

    fn rec(expires_at: Option<i64>) -> FileRec {
        FileRec {
            id: "x".into(),
            owner_sub: "u".into(),
            name: "x.png".into(),
            content_type: "image/png".into(),
            size: 1,
            bucket: "memory".into(),
            object_key: "x".into(),
            share_token: Some("tok".into()),
            created_at: 0,
            updated_at: 0,
            expires_at,
            share_password_hash: None,
            folder_id: None,
            trashed_at: 0,
            trash_entry_id: None,
            trash_ancestor_id: None,
            view_count: 0,
        }
    }

    #[test]
    fn folder_share_expired_and_password_helpers() {
        let mut f = FolderRec {
            id: "f".into(),
            owner_sub: "u".into(),
            parent_id: None,
            name: "F".into(),
            created_at: 0,
            updated_at: 0,
            share_token: Some("t".into()),
            expires_at: Some(1000),
            share_password_hash: None,
            upload_token: None,
            trashed_at: 0,
            trash_entry_id: None,
            trash_ancestor_id: None,
        };
        assert!(!f.share_expired(999));
        assert!(f.share_expired(1000)); // inclusive
        assert!(!f.share_has_password());
        f.share_password_hash = Some("salt$hash".into());
        assert!(f.share_has_password());
    }

    #[test]
    fn share_expired_at_or_after_instant() {
        assert!(!rec(None).share_expired(10_000)); // never expires
        assert!(!rec(Some(1000)).share_expired(999));
        assert!(rec(Some(1000)).share_expired(1000)); // inclusive
        assert!(rec(Some(1000)).share_expired(1001));
    }
}
