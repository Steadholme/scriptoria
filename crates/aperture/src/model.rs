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
    /// Unguessable public share token (`/s/{token}` fetches the blob WITHOUT SSO).
    pub share_token: String,
    /// Upload time, epoch seconds.
    pub created_at: i64,
}

impl FileRec {
    /// True when this file is a raster image we render inline.
    pub fn is_image(&self) -> bool {
        is_inline_image(&self.content_type)
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
}
