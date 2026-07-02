//! Core domain type: a stored paste/snippet.
//!
//! One flat record per the agreed schema (db `pastefire`, table `pastes`). `expires_at` is
//! nullable — `None` means "never expires". Identity (`author_sub`/`author_email`) always
//! comes from the Sluice-injected `X-Auth-*` headers, never from client input.

/// A single paste. Field order/types mirror the `pastes` table exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paste {
    /// Short, random, URL-safe id (the public `/p/{id}` slug + primary key).
    pub id: String,
    /// Human title (may be empty -> rendered as "Untitled paste").
    pub title: String,
    /// The snippet body (rendered verbatim into an HTML-escaped `<pre>`).
    pub body: String,
    /// Language token (e.g. `rust`, `plaintext`) selected on the form; drives the label.
    pub language: String,
    /// Author subject from `X-Auth-Subject` (ownership key for delete).
    pub author_sub: String,
    /// Author email from `X-Auth-Email` (display only).
    pub author_email: String,
    /// Creation time, epoch seconds.
    pub created_at: i64,
    /// Expiry time, epoch seconds; `None` = never expires.
    pub expires_at: Option<i64>,
    /// Burn-after-read: when true the paste self-destructs on its first authenticated view by
    /// someone OTHER than its author (the author can still open it to copy the share link).
    /// Defaults to false, so every pre-existing paste keeps its current "persists" behavior.
    pub burn_after_read: bool,
    /// Id of the paste this was forked from; `None` for an original paste. Rendered as a "Forked
    /// from …" credit on the view. Purely informational — the fork is an independent copy.
    pub source_id: Option<String>,
    /// Salted SHA-256 password hash (`sha256$salt$hex`); `None` = no password. When set, a viewer
    /// who is NOT the author must supply the correct password before the body is revealed.
    pub password_hash: Option<String>,
}

/// One historical version of a paste's editable content. Each owner edit snapshots the paste's
/// PRE-edit content here (the `pastes` row always holds the CURRENT version), so `paste_revisions`
/// is an append-only history. `revision` is a per-paste monotonic counter starting at 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasteRevision {
    /// The paste this revision belongs to (`pastes.id`).
    pub paste_id: String,
    /// Per-paste revision number (1, 2, 3, …); unique within `paste_id`.
    pub revision: i64,
    /// Snapshotted title at the time this version was superseded.
    pub title: String,
    /// Snapshotted body.
    pub body: String,
    /// Snapshotted language token.
    pub language: String,
    /// When this snapshot was archived (epoch seconds) — i.e. when the edit that superseded it ran.
    pub created_at: i64,
}

/// One named file within a multi-file paste (a la a GitHub Gist with several files). Field
/// order/types mirror the `paste_files` table exactly. A paste with NO `paste_files` rows is a
/// legacy/single-content paste: its lone "file" is synthesized from `pastes.body` on read, so
/// pre-existing pastes keep their exact single-file rendering with zero migration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasteFile {
    /// Random, unique file id (primary key). Never surfaced in a URL — files are addressed by
    /// their parent paste + position.
    pub id: String,
    /// The paste this file belongs to (`pastes.id`).
    pub paste_id: String,
    /// The file's display name (may be empty -> rendered as "File {n}").
    pub filename: String,
    /// The file's verbatim content (rendered into an HTML-escaped, line-numbered block).
    pub content: String,
    /// 0-based ordering within the paste; the view renders files in ascending `position`.
    pub position: i64,
}

impl Paste {
    /// True once `now` (epoch seconds) has reached the expiry instant. A `None` expiry never
    /// expires. Keeping this on the model means the view path, the raw path, and the recent
    /// list all share one definition of "expired".
    pub fn is_expired(&self, now: i64) -> bool {
        matches!(self.expires_at, Some(exp) if now >= exp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paste(expires_at: Option<i64>) -> Paste {
        Paste {
            id: "abc".into(),
            title: "t".into(),
            body: "b".into(),
            language: "plaintext".into(),
            author_sub: "s".into(),
            author_email: "e@x".into(),
            created_at: 1000,
            expires_at,
            burn_after_read: false,
            source_id: None,
            password_hash: None,
        }
    }

    #[test]
    fn never_expires_when_none() {
        assert!(!paste(None).is_expired(i64::MAX));
    }

    #[test]
    fn expires_at_or_after_instant() {
        let p = paste(Some(2000));
        assert!(!p.is_expired(1999));
        assert!(p.is_expired(2000));
        assert!(p.is_expired(2001));
    }
}
