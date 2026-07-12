//! Forum domain types — each maps 1:1 to a row of its table.
//!
//! All identity fields (`author_sub`/`author_email`) come from the gateway-injected
//! `X-Auth-*` headers; a client-supplied author is NEVER trusted. Timestamps are epoch
//! seconds.

use serde::Serialize;

/// Product behaviour attached to a category. A discussion is an open conversation; a question
/// participates in the answered/unanswered workflow and may have one accepted reply.
///
/// The textual representation is persisted in PostgreSQL so migrations remain transparent and
/// operator-readable. Unknown values are rejected by handlers before write and treated as the
/// conservative `discussion` mode when reading a manually-corrupted row.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CategoryFormat {
    #[default]
    Discussion,
    Question,
}

impl CategoryFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Discussion => "discussion",
            Self::Question => "question",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "discussion" => Some(Self::Discussion),
            "question" => Some(Self::Question),
            _ => None,
        }
    }

    pub const fn is_question(self) -> bool {
        matches!(self, Self::Question)
    }
}

/// A discussion category (maps 1:1 to a `categories` row). Ordered by `sort_order` then name.
#[derive(Clone, Debug, Serialize)]
pub struct Category {
    pub id: String,
    pub name: String,
    pub sort_order: i64,
    pub format: CategoryFormat,
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
    /// Accepted-reply body, when the thread currently has a valid accepted reply.
    pub accepted_body_md: String,
    /// Whether the search query matched the accepted reply. The UI uses this to display the
    /// solution excerpt and make the source of the result explicit.
    pub matched_in_solution: bool,
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

/// Authoritative subject-scoped reading projection for one thread. Receipts are stored per post,
/// so `first_unread` remains exact after a user jumps to Latest or sees a floated accepted answer;
/// a single high-water cursor would incorrectly swallow those unread holes.
#[derive(Clone, Debug)]
pub struct ThreadReadingState {
    pub started: bool,
    pub unread_count: i64,
    pub first_unread: Option<Post>,
    pub last_contiguous_read: Option<Post>,
}

/// One user's explicit relationship with a thread. `None` is represented by the absence of a
/// persistence row; the other three values are stored as operator-readable text. The names are
/// deliberately product language rather than transport language:
///
/// - `Watch` delivers every new reply into generic Activity and appears in personal feeds.
/// - `Follow` appears in personal feeds without generic follower Activity.
/// - `Mute` suppresses the thread from personal feeds and generic follower Activity. Direct
///   mention/reply/accepted-answer authority remains independent from this preference.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ThreadFollowLevel {
    #[default]
    None,
    Watch,
    Follow,
    Mute,
}

impl ThreadFollowLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Watch => "watch",
            Self::Follow => "follow",
            Self::Mute => "mute",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "none" => Some(Self::None),
            "watch" => Some(Self::Watch),
            "follow" => Some(Self::Follow),
            "mute" => Some(Self::Mute),
            _ => None,
        }
    }

    pub const fn appears_in_personal_feeds(self) -> bool {
        matches!(self, Self::Watch | Self::Follow)
    }

    pub const fn delivers_generic_activity(self) -> bool {
        matches!(self, Self::Watch)
    }
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

/// One durable, immutable piece of Forum activity. The row deliberately stores only identities
/// and authoritative content pointers: titles and bodies are always loaded from `threads` and
/// `posts` when an inbox is read, so an edit or moderation delete can never leave stale content in
/// a personal inbox.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActivityEvent {
    pub id: String,
    pub kind: ActivityKind,
    pub thread_id: String,
    pub post_id: String,
    pub actor_sub: String,
    pub created_at: i64,
}

/// The mutation that produced an activity event. Delivery reasons live separately because one
/// viewer can qualify through several paths (for example: thread author + explicit follower).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityKind {
    PostCreated,
    AnswerAccepted,
}

impl ActivityKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PostCreated => "post_created",
            Self::AnswerAccepted => "answer_accepted",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "post_created" => Some(Self::PostCreated),
            "answer_accepted" => Some(Self::AnswerAccepted),
            _ => None,
        }
    }
}

/// Why a viewer received an event. Ordering is intentional: a direct mention is more useful than
/// a generic reply/follow delivery when the same event reached the viewer through multiple paths.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ActivityReason {
    Mention,
    Reply,
    Following,
    Answer,
}

impl ActivityReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mention => "mention",
            Self::Reply => "reply",
            Self::Following => "following",
            Self::Answer => "answer",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "mention" => Some(Self::Mention),
            "reply" => Some(Self::Reply),
            "following" => Some(Self::Following),
            "answer" => Some(Self::Answer),
            _ => None,
        }
    }

    pub const fn priority(self) -> u8 {
        match self {
            Self::Mention => 0,
            Self::Reply => 1,
            Self::Answer => 2,
            Self::Following => 3,
        }
    }
}

/// Recipient addressing preserves the gateway subject for known participants/followers and the
/// existing normalised `@username` contract for mentions. A read receipt is still keyed by the
/// actual gateway subject, so two delivery paths collapse to one viewer-owned read state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ActivityRecipientKind {
    Subject,
    Username,
}

impl ActivityRecipientKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Subject => "subject",
            Self::Username => "username",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "subject" => Some(Self::Subject),
            "username" => Some(Self::Username),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ActivityDelivery {
    pub recipient_kind: ActivityRecipientKind,
    pub recipient_key: String,
    pub reason: ActivityReason,
}

/// Authoritative read model returned by the Store. `thread_title`, `post_body_md`, and actor email
/// are joined from live rows rather than copied into the activity tables.
#[derive(Clone, Debug)]
pub struct ActivityItem {
    pub event: ActivityEvent,
    pub reason: ActivityReason,
    pub thread_title: String,
    pub post_body_md: String,
    pub post_created_at: i64,
    pub actor_email: String,
    pub read: bool,
}

/// One private bookmark owned exclusively by a stable gateway subject. The target is always a
/// concrete post; bookmarking the original post is therefore the topic-level case without a
/// second polymorphic identity. `remind_at` is an optional UTC epoch second and becomes due when
/// it is less than or equal to the current request time.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Bookmark {
    /// Immutable identity for this saved generation. Removing and saving the same post again
    /// creates a fresh id so a stale form can never pass CAS against the replacement row.
    pub bookmark_id: String,
    pub owner_sub: String,
    pub post_id: String,
    pub note: String,
    pub remind_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    pub version: i64,
}

/// Authoritative private bookmark read model. Public thread/post text is joined live instead of
/// copied into `forum_bookmarks`, so edits and moderation are reflected immediately.
#[derive(Clone, Debug)]
pub struct BookmarkItem {
    pub bookmark: Bookmark,
    pub thread_id: String,
    pub thread_title: String,
    pub post_author_email: String,
    pub post_body_md: String,
    pub post_created_at: i64,
}
