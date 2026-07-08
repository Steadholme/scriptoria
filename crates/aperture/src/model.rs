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
            expires_at,
            share_password_hash: None,
            folder_id: None,
            trashed_at: 0,
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
            share_token: Some("t".into()),
            expires_at: Some(1000),
            share_password_hash: None,
            upload_token: None,
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
