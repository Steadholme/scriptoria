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
    /// file is unfiled and appears only in the flat "all files" view. A folder view (`?folder={id}`)
    /// lists exactly the files whose `folder_id` matches.
    pub folder_id: Option<String>,
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

/// A single owner-scoped folder (album) grouping a subset of the owner's files. Field
/// order/types mirror the `folders` table exactly. Files reference it via [`FileRec::folder_id`];
/// deleting a folder unfiles its files rather than deleting them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FolderRec {
    /// Short, random, URL-safe id (the `?folder={id}` selector + primary key).
    pub id: String,
    /// Owner subject from `X-Auth-Subject` (ownership key for list/rename/delete).
    pub owner_sub: String,
    /// Display name as submitted (display only; escaped on render).
    pub name: String,
    /// Creation time, epoch seconds.
    pub created_at: i64,
}

impl FileRec {
    /// True when this file is a raster image we render inline.
    pub fn is_image(&self) -> bool {
        is_inline_image(&self.content_type)
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
        }
    }

    #[test]
    fn share_expired_at_or_after_instant() {
        assert!(!rec(None).share_expired(10_000)); // never expires
        assert!(!rec(Some(1000)).share_expired(999));
        assert!(rec(Some(1000)).share_expired(1000)); // inclusive
        assert!(rec(Some(1000)).share_expired(1001));
    }
}
