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
/// the most recent post so lists can sort by recent activity.
#[derive(Clone, Debug, Serialize)]
pub struct Thread {
    pub id: String,
    pub category_id: String,
    pub title: String,
    pub author_sub: String,
    pub author_email: String,
    pub created_at: i64,
    pub last_at: i64,
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

/// A single post in a thread (maps 1:1 to a `posts` row). The first post of a thread is the
/// original post; the rest are replies. `body_md` is raw CommonMark, rendered (sanitised) at
/// display time.
#[derive(Clone, Debug, Serialize)]
pub struct Post {
    pub id: String,
    pub thread_id: String,
    pub body_md: String,
    pub author_sub: String,
    pub author_email: String,
    pub created_at: i64,
}
