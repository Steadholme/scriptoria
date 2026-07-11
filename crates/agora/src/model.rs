//! Forum domain types — each maps 1:1 to a row of its table.
//!
//! All identity fields (`author_sub`/`author_email`) come from the gateway-injected
//! `X-Auth-*` headers; a client-supplied author is NEVER trusted. Timestamps are epoch
//! seconds.

use serde::Serialize;

/// A discussion category (maps 1:1 to a `categories` row). Ordered by `sort_order` then name.
#[derive(Clone, Debug, Serialize)]
pub struct Category {
    pub id: String,
    pub name: String,
    pub sort_order: i64,
}

/// A thread of discussion within a category (maps 1:1 to a `threads` row). `last_at` tracks
/// the most recent post so lists can sort by recent activity. `locked` (no new replies) and
/// `pinned` (sort first) are admin-controlled moderation flags; both default to `false`.
/// `accepted_post_id` names the reply the thread author (or an admin) marked as the accepted
/// answer; an empty string means none is marked. The accepted reply renders first under the OP.
#[derive(Clone, Debug, Serialize)]
pub struct Thread {
    pub id: String,
    pub category_id: String,
    pub title: String,
    pub author_sub: String,
    pub author_email: String,
    pub created_at: i64,
    pub last_at: i64,
    pub locked: bool,
    pub pinned: bool,
    pub accepted_post_id: String,
}

/// A lightweight thread digest for compose-time similarity scoring: the thread's identity plus
/// the text that defines it (title + original-post body). NOT a stored row — it is assembled
/// from `threads` (the denormalised `first_body_md` column) so similarity can be computed
/// without loading every post. Additive: it never affects how [`Thread`]/[`Post`] are read.
#[derive(Clone, Debug, Serialize)]
pub struct ThreadDigest {
    pub id: String,
    pub category_id: String,
    pub title: String,
    pub first_body_md: String,
}

/// One thread returned by discovery search. The original-post body is carried separately from
/// [`Thread`] so the search page can render a safe excerpt, while `reply_count` avoids an N+1
/// count query in the handler. This is a read model, not a stored table.
#[derive(Clone, Debug)]
pub struct ThreadSearchHit {
    pub thread: Thread,
    pub first_body_md: String,
    pub reply_count: i64,
}

/// A blocked author (maps 1:1 to a `banned_authors` row). Keyed by the gateway-injected
/// `author_sub`; while present it rejects that user's new threads and replies. `reason` and
/// `banned_by` are short operator notes for the audit trail.
#[derive(Clone, Debug, Serialize)]
pub struct BannedAuthor {
    pub author_sub: String,
    pub reason: String,
    pub banned_by: String,
    pub created_at: i64,
}

/// An aggregate reaction count for one post + one kind (e.g. `up`, `heart`). NOT a stored row —
/// it is assembled from the `post_reactions` table (each row is one user's single reaction of a
/// kind, unique per `(post_id, user_sub, kind)`). `mine` is whether the current viewer is one of
/// the `count` reactors, so the UI can highlight the viewer's own toggle.
#[derive(Clone, Debug, Serialize)]
pub struct ReactionCount {
    pub kind: String,
    pub count: i64,
    pub mine: bool,
}

/// A single post in a thread (maps 1:1 to a `posts` row). The first post of a thread is the
/// original post; the rest are replies. `body_md` is raw CommonMark, rendered (sanitised) at
/// display time. `quoted_post_id` is empty for normal posts; when set it points at another post in
/// the same thread whose escaped body renders above this reply as a quote.
#[derive(Clone, Debug, Serialize)]
pub struct Post {
    pub id: String,
    pub thread_id: String,
    pub body_md: String,
    pub quoted_post_id: String,
    pub author_sub: String,
    pub author_email: String,
    pub created_at: i64,
}

/// One parsed `@username` occurrence for a post. Usernames are normalised to lowercase at write
/// time and are matched against the viewer's gateway email local-part.
#[derive(Clone, Debug, Serialize)]
pub struct Mention {
    pub post_id: String,
    pub thread_id: String,
    pub mentioned_username: String,
    pub created_at: i64,
}
