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
