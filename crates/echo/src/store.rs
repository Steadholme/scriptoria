//! Comment + thread storage.
//!
//! `Store` is a small async trait with an in-memory and a PostgreSQL implementation, mirroring
//! the inkwell/sanctum seam: handlers depend only on the trait, so a FusionDB-backed store can
//! drop in later. The PostgreSQL layer uses ONLY portable standard SQL (TEXT/BIGINT/BOOLEAN,
//! PK/UNIQUE/NOT NULL/DEFAULT, `INSERT .. ON CONFLICT`, parameterized queries, `CREATE INDEX`)
//! and runtime queries (no compile-time macros), so the build needs NO database and the same
//! statements later run unchanged on FusionDB over pgwire.
//!
//! The methods are `async`: the axum handlers `.await` them directly on the serving runtime, and
//! `PgStore` drives sqlx natively — there is NO `block_in_place` and NO sync-over-async bridge.

use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::config::{clamp_page, COMMENT_LIMIT};

/// A comment thread (maps 1:1 to a `threads` row). A thread is keyed by an opaque `key` (the
/// embedding page's stable identifier, e.g. `blog/hello-world`).
#[derive(Clone, Debug)]
pub struct Thread {
    pub id: String,
    pub key: String,
    pub title: String,
    pub url: String,
    pub created_at: i64,
}

/// A single comment (maps 1:1 to a `comments` row). `parent_id` is `""` for a top-level comment,
/// or the id of the top-level comment it replies to (replies nest exactly one level).
#[derive(Clone, Debug)]
pub struct Comment {
    pub id: String,
    pub thread_id: String,
    pub author_sub: String,
    pub author_email: String,
    pub body: String,
    pub created_at: i64,
    pub hidden: bool,
    pub parent_id: String,
}

/// A blocklist entry (maps 1:1 to a `blocked_authors` row), keyed by the opaque `author_sub`.
/// A blocked author's existing comments are hidden and their new comments are rejected.
#[derive(Clone, Debug)]
pub struct BlockedAuthor {
    pub author_sub: String,
    pub reason: String,
    pub blocked_by: String,
    pub created_at: i64,
}

/// A single reaction (maps 1:1 to a `comment_reactions` row): one `user_sub` reacting to one
/// `comment_id` with one `kind`. The `(comment_id, user_sub, kind)` triple is UNIQUE, so a repeat
/// react is a no-op insert and the toggle simply removes the existing row.
#[derive(Clone, Debug)]
pub struct Reaction {
    pub comment_id: String,
    pub user_sub: String,
    pub kind: String,
    pub created_at: i64,
}

/// A single vote (maps 1:1 to a `comment_votes` row): one voter may hold one `+1` or `-1` vote on
/// one comment. Toggling the same value removes the row; toggling the opposite value updates it.
#[derive(Clone, Debug)]
pub struct CommentVote {
    pub comment_id: String,
    pub voter_sub: String,
    pub value: i64,
    pub created_at: i64,
}

/// A single report/flag (maps 1:1 to a `comment_reports` row): one reporter may file one reason on
/// one comment. A repeat report by the same reporter updates the reason and timestamp.
#[derive(Clone, Debug)]
pub struct CommentReport {
    pub comment_id: String,
    pub reporter_sub: String,
    pub reason: String,
    pub created_at: i64,
}

/// Ordering for a thread's top-level comments. `Top` ranks by vote score, `MostReacted` ranks by
/// total reaction count, and both fall back to newest-first for stable ties.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sort {
    Newest,
    Oldest,
    Top,
    MostReacted,
}

impl Sort {
    /// Parse the `?sort=` query value. Anything unrecognized (including a bare view with no
    /// `?sort=`) falls back to `Oldest` — the chronological order the thread view has always
    /// rendered, so the default page is unchanged.
    pub fn parse(s: &str) -> Sort {
        match s.trim() {
            "newest" => Sort::Newest,
            "top" => Sort::Top,
            "reacted" | "most-reacted" | "most_reacted" => Sort::MostReacted,
            _ => Sort::Oldest,
        }
    }

    /// The stable token used in `?sort=` links.
    pub fn as_str(&self) -> &'static str {
        match self {
            Sort::Newest => "newest",
            Sort::Oldest => "oldest",
            Sort::Top => "top",
            Sort::MostReacted => "reacted",
        }
    }
}

/// A keyset cursor into a thread's top-level comments. `reactions` carries the cursor comment's
/// rank count: total reactions for [`Sort::MostReacted`], vote score for [`Sort::Top`], and
/// 0/ignored for the time-ordered sorts. The field name is retained for compatibility with the
/// existing most-reacted cursor/tests.
#[derive(Clone, Debug)]
pub struct CommentCursor {
    pub reactions: i64,
    pub created_at: i64,
    pub id: String,
}

/// Storage failure surfaced to the handler layer.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Backend I/O failure (mapped to a 500).
    #[error("store error: {0}")]
    Backend(String),
}

/// Pluggable comment store.
#[async_trait]
pub trait Store: Send + Sync {
    /// One keyset page of threads, newest-first (`created_at` DESC, `id` DESC). `before` is the
    /// `(created_at, id)` of the last row of the previous page (the exclusive upper bound);
    /// `None` returns the newest page. `limit` is clamped to `[1, MAX_PAGE]` (see [`clamp_page`]).
    async fn list_threads(&self, before: Option<(i64, String)>, limit: i64) -> Vec<Thread>;
    /// One thread by its unique key.
    async fn get_thread(&self, key: &str) -> Option<Thread>;
    /// Upsert a thread by key: insert `thread` when its key is free, otherwise leave the existing
    /// row untouched. Returns the resulting row (existing or newly inserted) either way, so the
    /// caller always gets a stable `thread_id`.
    async fn upsert_thread(&self, thread: &Thread) -> Result<Thread, StoreError>;
    /// All comments in a thread, oldest-first (`created_at` ASC), capped at [`COMMENT_LIMIT`].
    async fn list_comments(&self, thread_id: &str) -> Vec<Comment>;
    /// One keyset page of a thread's TOP-LEVEL comments under `sort`, together with ALL replies of
    /// exactly those parents (replies stay oldest-first). `before` is the [`CommentCursor`] of the
    /// last row of the previous page (`None` returns the first page); `limit` is clamped like the
    /// thread list. Returns `(top_level_page, replies_of_page)`.
    async fn list_thread_page(
        &self,
        thread_id: &str,
        sort: Sort,
        before: Option<CommentCursor>,
        limit: i64,
    ) -> (Vec<Comment>, Vec<Comment>);
    /// Every reaction row attached to any of `comment_ids` — the handler folds these into per-kind
    /// counts + the viewer's own reaction state. Empty input returns empty (no query).
    async fn reactions_for(&self, comment_ids: &[String]) -> Vec<Reaction>;
    /// Idempotent toggle of one `(comment_id, user_sub, kind)` reaction: removes it and returns
    /// `false` ("now un-reacted") when it already existed, otherwise inserts it and returns `true`
    /// ("now reacted").
    async fn toggle_reaction(&self, reaction: &Reaction) -> Result<bool, StoreError>;
    /// Every vote row attached to any of `comment_ids` — the handler folds these into per-comment
    /// scores + the viewer's own vote state. Empty input returns empty (no query).
    async fn votes_for(&self, comment_ids: &[String]) -> Vec<CommentVote>;
    /// Toggle one `(comment_id, voter_sub)` vote. Same direction clears to `0`; opposite direction
    /// flips to `+1`/`-1`; a first vote inserts. Returns the viewer's resulting value.
    async fn toggle_vote(&self, vote: &CommentVote) -> Result<i64, StoreError>;
    /// Every report row attached to any of `comment_ids`, used by the admin moderation queue.
    /// Empty input returns empty (no query).
    async fn reports_for(&self, comment_ids: &[String]) -> Vec<CommentReport>;
    /// Insert or update one `(comment_id, reporter_sub)` report. Returns `true` for a new row and
    /// `false` when an existing row's reason/timestamp was updated.
    async fn report_comment(&self, report: &CommentReport) -> Result<bool, StoreError>;
    /// One comment by id.
    async fn get_comment(&self, id: &str) -> Option<Comment>;
    /// Insert a new comment.
    async fn create_comment(&self, comment: &Comment) -> Result<(), StoreError>;
    /// Set a comment's `hidden` flag. Returns `true` when a row was actually updated.
    async fn set_comment_hidden(&self, id: &str, hidden: bool) -> Result<bool, StoreError>;
    /// Author self-edit: update a comment's `body`, but ONLY when `author_sub` owns it. Returns
    /// `true` when a row was actually updated (the comment exists AND belongs to `author_sub`).
    async fn update_comment_body(
        &self,
        id: &str,
        author_sub: &str,
        body: &str,
    ) -> Result<bool, StoreError>;
    /// Author self-delete: delete a comment, but ONLY when `author_sub` owns it. Returns `true`
    /// when a row was actually deleted.
    async fn delete_comment(&self, id: &str, author_sub: &str) -> Result<bool, StoreError>;
    /// Number of comments in a thread (all, including hidden).
    async fn count_comments(&self, thread_id: &str) -> i64;
    /// The most recent comments across all threads, newest-first, capped at `limit` — backs the
    /// dashboard's activity feed.
    async fn recent_comments(&self, limit: usize) -> Vec<Comment>;
    /// Admin "delete any": delete a comment by id regardless of author. Returns `true` when a row
    /// was actually removed.
    async fn delete_comment_any(&self, id: &str) -> Result<bool, StoreError>;
    /// Set the `hidden` flag on ALL comments authored by `author_sub`. Returns the number of rows
    /// updated — backs the blocklist (blocking hides an author's existing comments).
    async fn set_hidden_by_author(&self, author_sub: &str, hidden: bool)
        -> Result<u64, StoreError>;
    /// Whether `author_sub` is currently on the blocklist.
    async fn is_blocked(&self, author_sub: &str) -> bool;
    /// All blocklist entries, newest-first (`created_at` DESC, `author_sub` DESC).
    async fn list_blocked(&self) -> Vec<BlockedAuthor>;
    /// Add an author to the blocklist (idempotent on `author_sub`). Returns `true` when the row was
    /// newly inserted, `false` when the author was already blocked.
    async fn block_author(&self, entry: &BlockedAuthor) -> Result<bool, StoreError>;
    /// Remove an author from the blocklist. Returns `true` when a row was actually removed.
    async fn unblock_author(&self, author_sub: &str) -> Result<bool, StoreError>;
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

#[derive(Default)]
pub struct InMemoryStore {
    threads: Mutex<Vec<Thread>>,
    comments: Mutex<Vec<Comment>>,
    blocked: Mutex<Vec<BlockedAuthor>>,
    reactions: Mutex<Vec<Reaction>>,
    votes: Mutex<Vec<CommentVote>>,
    reports: Mutex<Vec<CommentReport>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for InMemoryStore {
    // The std `Mutex` is fine throughout: each critical section is fully synchronous (no `.await`
    // inside), so a guard is never held across a yield point.
    async fn list_threads(&self, before: Option<(i64, String)>, limit: i64) -> Vec<Thread> {
        let limit = clamp_page(limit) as usize;
        let threads = self.threads.lock().expect("threads lock poisoned");
        // Same keyset predicate as the SQL path: strictly "older than" the cursor under the
        // (created_at DESC, id DESC) ordering, i.e. created_at < ts OR (created_at == ts AND id < id).
        let mut v: Vec<Thread> = threads
            .iter()
            .filter(|t| match &before {
                Some((ts, id)) => {
                    t.created_at < *ts || (t.created_at == *ts && t.id.as_str() < id.as_str())
                }
                None => true,
            })
            .cloned()
            .collect();
        v.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.id.cmp(&a.id))
        });
        v.truncate(limit);
        v
    }

    async fn get_thread(&self, key: &str) -> Option<Thread> {
        self.threads
            .lock()
            .expect("threads lock poisoned")
            .iter()
            .find(|t| t.key == key)
            .cloned()
    }

    async fn upsert_thread(&self, thread: &Thread) -> Result<Thread, StoreError> {
        let mut threads = self.threads.lock().expect("threads lock poisoned");
        if let Some(existing) = threads.iter().find(|t| t.key == thread.key) {
            return Ok(existing.clone());
        }
        threads.push(thread.clone());
        Ok(thread.clone())
    }

    async fn list_comments(&self, thread_id: &str) -> Vec<Comment> {
        let comments = self.comments.lock().expect("comments lock poisoned");
        let mut v: Vec<Comment> = comments
            .iter()
            .filter(|c| c.thread_id == thread_id)
            .cloned()
            .collect();
        v.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        v.truncate(COMMENT_LIMIT);
        v
    }

    async fn list_thread_page(
        &self,
        thread_id: &str,
        sort: Sort,
        before: Option<CommentCursor>,
        limit: i64,
    ) -> (Vec<Comment>, Vec<Comment>) {
        let limit = clamp_page(limit) as usize;
        let comments = self.comments.lock().expect("comments lock poisoned");
        let reactions = self.reactions.lock().expect("reactions lock poisoned");
        let votes = self.votes.lock().expect("votes lock poisoned");
        // Total reaction count for a comment id (mirrors the SQL COUNT(*) over comment_reactions).
        let rcount = |id: &str| reactions.iter().filter(|r| r.comment_id == id).count() as i64;
        // Vote score for a comment id (mirrors the SQL SUM(value) over comment_votes).
        let score = |id: &str| {
            votes
                .iter()
                .filter(|v| v.comment_id == id)
                .map(|v| v.value)
                .sum::<i64>()
        };

        let mut tops: Vec<Comment> = comments
            .iter()
            .filter(|c| c.thread_id == thread_id && c.parent_id.is_empty())
            .cloned()
            .collect();
        // Same ordering the SQL path uses for each sort.
        match sort {
            Sort::Newest => tops.sort_by(|a, b| {
                b.created_at
                    .cmp(&a.created_at)
                    .then_with(|| b.id.cmp(&a.id))
            }),
            Sort::Oldest => tops.sort_by(|a, b| {
                a.created_at
                    .cmp(&b.created_at)
                    .then_with(|| a.id.cmp(&b.id))
            }),
            Sort::Top => tops.sort_by(|a, b| {
                score(&b.id)
                    .cmp(&score(&a.id))
                    .then_with(|| b.created_at.cmp(&a.created_at))
                    .then_with(|| b.id.cmp(&a.id))
            }),
            Sort::MostReacted => tops.sort_by(|a, b| {
                rcount(&b.id)
                    .cmp(&rcount(&a.id))
                    .then_with(|| b.created_at.cmp(&a.created_at))
                    .then_with(|| b.id.cmp(&a.id))
            }),
        }
        // Keyset predicate: strictly "after" the cursor under the sort's ordering.
        if let Some(cur) = &before {
            tops.retain(|c| match sort {
                Sort::Newest => {
                    c.created_at < cur.created_at
                        || (c.created_at == cur.created_at && c.id.as_str() < cur.id.as_str())
                }
                Sort::Oldest => {
                    c.created_at > cur.created_at
                        || (c.created_at == cur.created_at && c.id.as_str() > cur.id.as_str())
                }
                Sort::MostReacted => {
                    let rc = rcount(&c.id);
                    rc < cur.reactions
                        || (rc == cur.reactions && c.created_at < cur.created_at)
                        || (rc == cur.reactions
                            && c.created_at == cur.created_at
                            && c.id.as_str() < cur.id.as_str())
                }
                Sort::Top => {
                    let sc = score(&c.id);
                    sc < cur.reactions
                        || (sc == cur.reactions && c.created_at < cur.created_at)
                        || (sc == cur.reactions
                            && c.created_at == cur.created_at
                            && c.id.as_str() < cur.id.as_str())
                }
            });
        }
        tops.truncate(limit);

        let parent_ids: Vec<&str> = tops.iter().map(|c| c.id.as_str()).collect();
        let mut replies: Vec<Comment> = comments
            .iter()
            .filter(|c| !c.parent_id.is_empty() && parent_ids.contains(&c.parent_id.as_str()))
            .cloned()
            .collect();
        replies.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        (tops, replies)
    }

    async fn reactions_for(&self, comment_ids: &[String]) -> Vec<Reaction> {
        if comment_ids.is_empty() {
            return Vec::new();
        }
        self.reactions
            .lock()
            .expect("reactions lock poisoned")
            .iter()
            .filter(|r| comment_ids.iter().any(|id| id == &r.comment_id))
            .cloned()
            .collect()
    }

    async fn toggle_reaction(&self, reaction: &Reaction) -> Result<bool, StoreError> {
        let mut reactions = self.reactions.lock().expect("reactions lock poisoned");
        if let Some(pos) = reactions.iter().position(|r| {
            r.comment_id == reaction.comment_id
                && r.user_sub == reaction.user_sub
                && r.kind == reaction.kind
        }) {
            reactions.remove(pos);
            Ok(false)
        } else {
            reactions.push(reaction.clone());
            Ok(true)
        }
    }

    async fn votes_for(&self, comment_ids: &[String]) -> Vec<CommentVote> {
        if comment_ids.is_empty() {
            return Vec::new();
        }
        self.votes
            .lock()
            .expect("votes lock poisoned")
            .iter()
            .filter(|v| comment_ids.iter().any(|id| id == &v.comment_id))
            .cloned()
            .collect()
    }

    async fn toggle_vote(&self, vote: &CommentVote) -> Result<i64, StoreError> {
        let mut votes = self.votes.lock().expect("votes lock poisoned");
        match votes
            .iter()
            .position(|v| v.comment_id == vote.comment_id && v.voter_sub == vote.voter_sub)
        {
            Some(pos) if votes[pos].value == vote.value => {
                votes.remove(pos);
                Ok(0)
            }
            Some(pos) => {
                votes[pos].value = vote.value;
                votes[pos].created_at = vote.created_at;
                Ok(vote.value)
            }
            None => {
                votes.push(vote.clone());
                Ok(vote.value)
            }
        }
    }

    async fn reports_for(&self, comment_ids: &[String]) -> Vec<CommentReport> {
        if comment_ids.is_empty() {
            return Vec::new();
        }
        let mut rows: Vec<CommentReport> = self
            .reports
            .lock()
            .expect("reports lock poisoned")
            .iter()
            .filter(|r| comment_ids.iter().any(|id| id == &r.comment_id))
            .cloned()
            .collect();
        rows.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.reporter_sub.cmp(&a.reporter_sub))
        });
        rows
    }

    async fn report_comment(&self, report: &CommentReport) -> Result<bool, StoreError> {
        let mut reports = self.reports.lock().expect("reports lock poisoned");
        match reports
            .iter_mut()
            .find(|r| r.comment_id == report.comment_id && r.reporter_sub == report.reporter_sub)
        {
            Some(existing) => {
                existing.reason = report.reason.clone();
                existing.created_at = report.created_at;
                Ok(false)
            }
            None => {
                reports.push(report.clone());
                Ok(true)
            }
        }
    }

    async fn get_comment(&self, id: &str) -> Option<Comment> {
        self.comments
            .lock()
            .expect("comments lock poisoned")
            .iter()
            .find(|c| c.id == id)
            .cloned()
    }

    async fn create_comment(&self, comment: &Comment) -> Result<(), StoreError> {
        self.comments
            .lock()
            .expect("comments lock poisoned")
            .push(comment.clone());
        Ok(())
    }

    async fn set_comment_hidden(&self, id: &str, hidden: bool) -> Result<bool, StoreError> {
        let mut comments = self.comments.lock().expect("comments lock poisoned");
        match comments.iter_mut().find(|c| c.id == id) {
            Some(c) => {
                c.hidden = hidden;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn update_comment_body(
        &self,
        id: &str,
        author_sub: &str,
        body: &str,
    ) -> Result<bool, StoreError> {
        let mut comments = self.comments.lock().expect("comments lock poisoned");
        match comments
            .iter_mut()
            .find(|c| c.id == id && c.author_sub == author_sub)
        {
            Some(c) => {
                c.body = body.to_string();
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn delete_comment(&self, id: &str, author_sub: &str) -> Result<bool, StoreError> {
        let mut comments = self.comments.lock().expect("comments lock poisoned");
        let before = comments.len();
        comments.retain(|c| !(c.id == id && c.author_sub == author_sub));
        Ok(comments.len() != before)
    }

    async fn count_comments(&self, thread_id: &str) -> i64 {
        self.comments
            .lock()
            .expect("comments lock poisoned")
            .iter()
            .filter(|c| c.thread_id == thread_id)
            .count() as i64
    }

    async fn recent_comments(&self, limit: usize) -> Vec<Comment> {
        let comments = self.comments.lock().expect("comments lock poisoned");
        let mut v: Vec<Comment> = comments.clone();
        v.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.id.cmp(&a.id))
        });
        v.truncate(limit);
        v
    }

    async fn delete_comment_any(&self, id: &str) -> Result<bool, StoreError> {
        let mut comments = self.comments.lock().expect("comments lock poisoned");
        let before = comments.len();
        comments.retain(|c| c.id != id);
        Ok(comments.len() != before)
    }

    async fn set_hidden_by_author(
        &self,
        author_sub: &str,
        hidden: bool,
    ) -> Result<u64, StoreError> {
        let mut comments = self.comments.lock().expect("comments lock poisoned");
        let mut n = 0u64;
        for c in comments.iter_mut().filter(|c| c.author_sub == author_sub) {
            c.hidden = hidden;
            n += 1;
        }
        Ok(n)
    }

    async fn is_blocked(&self, author_sub: &str) -> bool {
        self.blocked
            .lock()
            .expect("blocked lock poisoned")
            .iter()
            .any(|b| b.author_sub == author_sub)
    }

    async fn list_blocked(&self) -> Vec<BlockedAuthor> {
        let mut v: Vec<BlockedAuthor> = self.blocked.lock().expect("blocked lock poisoned").clone();
        v.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.author_sub.cmp(&a.author_sub))
        });
        v
    }

    async fn block_author(&self, entry: &BlockedAuthor) -> Result<bool, StoreError> {
        let mut blocked = self.blocked.lock().expect("blocked lock poisoned");
        if blocked.iter().any(|b| b.author_sub == entry.author_sub) {
            return Ok(false);
        }
        blocked.push(entry.clone());
        Ok(true)
    }

    async fn unblock_author(&self, author_sub: &str) -> Result<bool, StoreError> {
        let mut blocked = self.blocked.lock().expect("blocked lock poisoned");
        let before = blocked.len();
        blocked.retain(|b| b.author_sub != author_sub);
        Ok(blocked.len() != before)
    }
}

// --------------------------------------------------------------------------------------
// PostgreSQL-backed store (portable: standard SQL, runtime queries, no macros).
// --------------------------------------------------------------------------------------
//
// Selected at runtime by `ECHO_STORE=postgres`. Each method drives sqlx natively and the handlers
// `.await` it on the serving runtime — NO `block_in_place`, NO sync-over-async. The thread `key`
// UNIQUE constraint + `INSERT .. ON CONFLICT (key) DO NOTHING` make the upsert race-safe with no
// in-process serializer; comment inserts are independent rows, so no write lock is needed either.

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

/// PostgreSQL-backed [`Store`]. Holds just a `PgPool`.
pub struct PgStore {
    pool: PgPool,
}

/// Build a comma-separated `$1, $2, …, $n` placeholder list for a dynamic `IN (...)` clause. The
/// count is bounded by the page/reply set, and only positional binds follow — no value is ever
/// interpolated, so this stays injection-safe.
fn bind_placeholders(n: usize) -> String {
    (1..=n)
        .map(|i| format!("${i}"))
        .collect::<Vec<_>>()
        .join(", ")
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

    /// Idempotent, portable migration. Standard SQL only — safe to run on every startup.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS threads (\
                 id TEXT PRIMARY KEY, \
                 key TEXT UNIQUE NOT NULL, \
                 title TEXT NOT NULL DEFAULT '', \
                 url TEXT NOT NULL DEFAULT '', \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS comments (\
                 id TEXT PRIMARY KEY, \
                 thread_id TEXT NOT NULL, \
                 author_sub TEXT NOT NULL, \
                 author_email TEXT NOT NULL DEFAULT '', \
                 body TEXT NOT NULL, \
                 created_at BIGINT NOT NULL, \
                 hidden BOOLEAN NOT NULL DEFAULT FALSE, \
                 parent_id TEXT NOT NULL DEFAULT ''\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Backs the per-thread oldest-first scan + the recent-activity feed.
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_comments_thread_created \
             ON comments (thread_id, created_at)",
        )
        .execute(&self.pool)
        .await?;
        // Author blocklist for the admin panel: a blocked author's existing comments are hidden and
        // their new comments rejected. Keyed by the opaque author_sub.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS blocked_authors (\
                 author_sub TEXT PRIMARY KEY, \
                 reason TEXT NOT NULL DEFAULT '', \
                 blocked_by TEXT NOT NULL DEFAULT '', \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Backs blocking hiding an author's existing comments (bulk update by author_sub).
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_comments_author \
             ON comments (author_sub)",
        )
        .execute(&self.pool)
        .await?;
        // Per-comment reactions. The (comment_id, user_sub, kind) UNIQUE makes a repeat react a
        // no-op insert (idempotent) and lets the toggle remove the exact row.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS comment_reactions (\
                 comment_id TEXT NOT NULL, \
                 user_sub TEXT NOT NULL, \
                 kind TEXT NOT NULL, \
                 created_at BIGINT NOT NULL, \
                 UNIQUE (comment_id, user_sub, kind)\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Backs the per-comment reaction COUNT(*) + the most-reacted ordering join.
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_reactions_comment \
             ON comment_reactions (comment_id)",
        )
        .execute(&self.pool)
        .await?;
        // Per-comment votes. The PRIMARY KEY enforces one vote per user per comment.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS comment_votes (\
                 comment_id TEXT NOT NULL, \
                 voter_sub TEXT NOT NULL, \
                 value BIGINT NOT NULL, \
                 created_at BIGINT NOT NULL, \
                 PRIMARY KEY (comment_id, voter_sub)\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Backs per-comment vote score SUM(value) and top sorting.
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_votes_comment \
             ON comment_votes (comment_id)",
        )
        .execute(&self.pool)
        .await?;
        // Per-comment reports. The PRIMARY KEY enforces one report per user per comment.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS comment_reports (\
                 comment_id TEXT NOT NULL, \
                 reporter_sub TEXT NOT NULL, \
                 reason TEXT NOT NULL DEFAULT '', \
                 created_at BIGINT NOT NULL, \
                 PRIMARY KEY (comment_id, reporter_sub)\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Backs the admin moderation queue report summary.
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_reports_comment \
             ON comment_reports (comment_id)",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    fn thread_from_row(row: &sqlx::postgres::PgRow) -> Result<Thread, sqlx::Error> {
        Ok(Thread {
            id: row.try_get("id")?,
            key: row.try_get("key")?,
            title: row.try_get("title")?,
            url: row.try_get("url")?,
            created_at: row.try_get("created_at")?,
        })
    }

    fn comment_from_row(row: &sqlx::postgres::PgRow) -> Result<Comment, sqlx::Error> {
        Ok(Comment {
            id: row.try_get("id")?,
            thread_id: row.try_get("thread_id")?,
            author_sub: row.try_get("author_sub")?,
            author_email: row.try_get("author_email")?,
            body: row.try_get("body")?,
            created_at: row.try_get("created_at")?,
            hidden: row.try_get("hidden")?,
            parent_id: row.try_get("parent_id")?,
        })
    }

    async fn list_threads_async(
        &self,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<Thread>, sqlx::Error> {
        let limit = clamp_page(limit);
        // Portable keyset page: the table is already ORDER BY (created_at DESC, id DESC), so the
        // cursor is simply "strictly before" that composite key. No cursor -> the newest page.
        let rows = match before {
            None => {
                sqlx::query(
                    "SELECT id, key, title, url, created_at \
                     FROM threads ORDER BY created_at DESC, id DESC LIMIT $1",
                )
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            Some((ts, id)) => {
                sqlx::query(
                    "SELECT id, key, title, url, created_at \
                     FROM threads \
                     WHERE (created_at < $1 OR (created_at = $1 AND id < $2)) \
                     ORDER BY created_at DESC, id DESC LIMIT $3",
                )
                .bind(ts)
                .bind(id)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
        };
        rows.iter().map(Self::thread_from_row).collect()
    }

    async fn get_thread_async(&self, key: &str) -> Result<Option<Thread>, sqlx::Error> {
        let row = sqlx::query("SELECT id, key, title, url, created_at FROM threads WHERE key = $1")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Ok(Some(Self::thread_from_row(&r)?)),
            None => Ok(None),
        }
    }

    async fn upsert_thread_async(&self, t: &Thread) -> Result<Thread, sqlx::Error> {
        // Race-safe insert: a concurrent poster that wins the key keeps its row; we then read the
        // canonical row back so the caller always gets a stable id.
        sqlx::query(
            "INSERT INTO threads (id, key, title, url, created_at) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (key) DO NOTHING",
        )
        .bind(&t.id)
        .bind(&t.key)
        .bind(&t.title)
        .bind(&t.url)
        .bind(t.created_at)
        .execute(&self.pool)
        .await?;
        let row = sqlx::query("SELECT id, key, title, url, created_at FROM threads WHERE key = $1")
            .bind(&t.key)
            .fetch_one(&self.pool)
            .await?;
        Self::thread_from_row(&row)
    }

    async fn list_comments_async(&self, thread_id: &str) -> Result<Vec<Comment>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, thread_id, author_sub, author_email, body, created_at, hidden, parent_id \
             FROM comments WHERE thread_id = $1 ORDER BY created_at ASC, id ASC LIMIT $2",
        )
        .bind(thread_id)
        .bind(COMMENT_LIMIT as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::comment_from_row).collect()
    }

    // The 8 comment columns, aliased `c.`, for the join in the paged top-level query.
    const PAGE_COLS: &'static str =
        "c.id, c.thread_id, c.author_sub, c.author_email, c.body, c.created_at, c.hidden, c.parent_id";
    // Left-join per-comment reaction count as r.n and vote score as v.score (COALESCE'd to 0 for
    // un-reacted / unvoted comments).
    const PAGE_JOIN: &'static str = "FROM comments c \
         LEFT JOIN (SELECT comment_id, COUNT(*) AS n FROM comment_reactions GROUP BY comment_id) r \
         ON r.comment_id = c.id \
         LEFT JOIN (SELECT comment_id, SUM(value) AS score FROM comment_votes GROUP BY comment_id) v \
         ON v.comment_id = c.id \
         WHERE c.thread_id = $1 AND c.parent_id = ''";

    async fn list_thread_page_async(
        &self,
        thread_id: &str,
        sort: Sort,
        before: Option<CommentCursor>,
        limit: i64,
    ) -> Result<(Vec<Comment>, Vec<Comment>), sqlx::Error> {
        let limit = clamp_page(limit);
        let cols = Self::PAGE_COLS;
        let join = Self::PAGE_JOIN;
        // Build the sort's ORDER BY + keyset WHERE. Aliases aren't legal in WHERE, so the reaction
        // count uses the full COALESCE(r.n, 0) expression there.
        let rows = match (sort, &before) {
            (Sort::Newest, None) => {
                sqlx::query(&format!(
                    "SELECT {cols} {join} ORDER BY c.created_at DESC, c.id DESC LIMIT $2"
                ))
                .bind(thread_id)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (Sort::Newest, Some(cur)) => {
                sqlx::query(&format!(
                    "SELECT {cols} {join} \
                     AND (c.created_at < $2 OR (c.created_at = $2 AND c.id < $3)) \
                     ORDER BY c.created_at DESC, c.id DESC LIMIT $4"
                ))
                .bind(thread_id)
                .bind(cur.created_at)
                .bind(&cur.id)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (Sort::Oldest, None) => {
                sqlx::query(&format!(
                    "SELECT {cols} {join} ORDER BY c.created_at ASC, c.id ASC LIMIT $2"
                ))
                .bind(thread_id)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (Sort::Oldest, Some(cur)) => {
                sqlx::query(&format!(
                    "SELECT {cols} {join} \
                     AND (c.created_at > $2 OR (c.created_at = $2 AND c.id > $3)) \
                     ORDER BY c.created_at ASC, c.id ASC LIMIT $4"
                ))
                .bind(thread_id)
                .bind(cur.created_at)
                .bind(&cur.id)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (Sort::Top, None) => {
                sqlx::query(&format!(
                    "SELECT {cols} {join} \
                     ORDER BY COALESCE(v.score, 0) DESC, c.created_at DESC, c.id DESC LIMIT $2"
                ))
                .bind(thread_id)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (Sort::Top, Some(cur)) => {
                sqlx::query(&format!(
                    "SELECT {cols} {join} \
                     AND (COALESCE(v.score, 0) < $2 \
                          OR (COALESCE(v.score, 0) = $2 AND c.created_at < $3) \
                          OR (COALESCE(v.score, 0) = $2 AND c.created_at = $3 AND c.id < $4)) \
                     ORDER BY COALESCE(v.score, 0) DESC, c.created_at DESC, c.id DESC LIMIT $5"
                ))
                .bind(thread_id)
                .bind(cur.reactions)
                .bind(cur.created_at)
                .bind(&cur.id)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (Sort::MostReacted, None) => {
                sqlx::query(&format!(
                    "SELECT {cols} {join} \
                     ORDER BY COALESCE(r.n, 0) DESC, c.created_at DESC, c.id DESC LIMIT $2"
                ))
                .bind(thread_id)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (Sort::MostReacted, Some(cur)) => {
                sqlx::query(&format!(
                    "SELECT {cols} {join} \
                     AND (COALESCE(r.n, 0) < $2 \
                          OR (COALESCE(r.n, 0) = $2 AND c.created_at < $3) \
                          OR (COALESCE(r.n, 0) = $2 AND c.created_at = $3 AND c.id < $4)) \
                     ORDER BY COALESCE(r.n, 0) DESC, c.created_at DESC, c.id DESC LIMIT $5"
                ))
                .bind(thread_id)
                .bind(cur.reactions)
                .bind(cur.created_at)
                .bind(&cur.id)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
        };
        let tops: Vec<Comment> = rows
            .iter()
            .map(Self::comment_from_row)
            .collect::<Result<_, _>>()?;

        let parent_ids: Vec<String> = tops.iter().map(|c| c.id.clone()).collect();
        let replies = self.replies_for_async(&parent_ids).await?;
        Ok((tops, replies))
    }

    async fn replies_for_async(&self, parent_ids: &[String]) -> Result<Vec<Comment>, sqlx::Error> {
        if parent_ids.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = bind_placeholders(parent_ids.len());
        let sql = format!(
            "SELECT id, thread_id, author_sub, author_email, body, created_at, hidden, parent_id \
             FROM comments WHERE parent_id IN ({placeholders}) \
             ORDER BY created_at ASC, id ASC"
        );
        let mut q = sqlx::query(&sql);
        for id in parent_ids {
            q = q.bind(id);
        }
        let rows = q.fetch_all(&self.pool).await?;
        rows.iter().map(Self::comment_from_row).collect()
    }

    async fn reactions_for_async(
        &self,
        comment_ids: &[String],
    ) -> Result<Vec<Reaction>, sqlx::Error> {
        if comment_ids.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = bind_placeholders(comment_ids.len());
        let sql = format!(
            "SELECT comment_id, user_sub, kind, created_at \
             FROM comment_reactions WHERE comment_id IN ({placeholders})"
        );
        let mut q = sqlx::query(&sql);
        for id in comment_ids {
            q = q.bind(id);
        }
        let rows = q.fetch_all(&self.pool).await?;
        rows.iter().map(Self::reaction_from_row).collect()
    }

    fn reaction_from_row(row: &sqlx::postgres::PgRow) -> Result<Reaction, sqlx::Error> {
        Ok(Reaction {
            comment_id: row.try_get("comment_id")?,
            user_sub: row.try_get("user_sub")?,
            kind: row.try_get("kind")?,
            created_at: row.try_get("created_at")?,
        })
    }

    async fn toggle_reaction_async(&self, r: &Reaction) -> Result<bool, sqlx::Error> {
        // Toggle in two portable steps: a DELETE that hits the row means it existed (=> now off);
        // otherwise INSERT it (=> now on). ON CONFLICT DO NOTHING keeps a concurrent double-react
        // idempotent.
        let del = sqlx::query(
            "DELETE FROM comment_reactions WHERE comment_id = $1 AND user_sub = $2 AND kind = $3",
        )
        .bind(&r.comment_id)
        .bind(&r.user_sub)
        .bind(&r.kind)
        .execute(&self.pool)
        .await?;
        if del.rows_affected() > 0 {
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO comment_reactions (comment_id, user_sub, kind, created_at) \
             VALUES ($1, $2, $3, $4) ON CONFLICT (comment_id, user_sub, kind) DO NOTHING",
        )
        .bind(&r.comment_id)
        .bind(&r.user_sub)
        .bind(&r.kind)
        .bind(r.created_at)
        .execute(&self.pool)
        .await?;
        Ok(true)
    }

    async fn votes_for_async(
        &self,
        comment_ids: &[String],
    ) -> Result<Vec<CommentVote>, sqlx::Error> {
        if comment_ids.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = bind_placeholders(comment_ids.len());
        let sql = format!(
            "SELECT comment_id, voter_sub, value, created_at \
             FROM comment_votes WHERE comment_id IN ({placeholders})"
        );
        let mut q = sqlx::query(&sql);
        for id in comment_ids {
            q = q.bind(id);
        }
        let rows = q.fetch_all(&self.pool).await?;
        rows.iter().map(Self::vote_from_row).collect()
    }

    fn vote_from_row(row: &sqlx::postgres::PgRow) -> Result<CommentVote, sqlx::Error> {
        Ok(CommentVote {
            comment_id: row.try_get("comment_id")?,
            voter_sub: row.try_get("voter_sub")?,
            value: row.try_get("value")?,
            created_at: row.try_get("created_at")?,
        })
    }

    async fn toggle_vote_async(&self, v: &CommentVote) -> Result<i64, sqlx::Error> {
        // Toggle in portable steps while preserving the one-row-per-user PK invariant.
        let existing =
            sqlx::query("SELECT value FROM comment_votes WHERE comment_id = $1 AND voter_sub = $2")
                .bind(&v.comment_id)
                .bind(&v.voter_sub)
                .fetch_optional(&self.pool)
                .await?;
        if let Some(row) = existing {
            let current: i64 = row.try_get("value")?;
            if current == v.value {
                sqlx::query("DELETE FROM comment_votes WHERE comment_id = $1 AND voter_sub = $2")
                    .bind(&v.comment_id)
                    .bind(&v.voter_sub)
                    .execute(&self.pool)
                    .await?;
                return Ok(0);
            }
            sqlx::query(
                "UPDATE comment_votes SET value = $1, created_at = $2 \
                 WHERE comment_id = $3 AND voter_sub = $4",
            )
            .bind(v.value)
            .bind(v.created_at)
            .bind(&v.comment_id)
            .bind(&v.voter_sub)
            .execute(&self.pool)
            .await?;
            return Ok(v.value);
        }
        sqlx::query(
            "INSERT INTO comment_votes (comment_id, voter_sub, value, created_at) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (comment_id, voter_sub) DO UPDATE \
             SET value = EXCLUDED.value, created_at = EXCLUDED.created_at",
        )
        .bind(&v.comment_id)
        .bind(&v.voter_sub)
        .bind(v.value)
        .bind(v.created_at)
        .execute(&self.pool)
        .await?;
        Ok(v.value)
    }

    async fn reports_for_async(
        &self,
        comment_ids: &[String],
    ) -> Result<Vec<CommentReport>, sqlx::Error> {
        if comment_ids.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = bind_placeholders(comment_ids.len());
        let sql = format!(
            "SELECT comment_id, reporter_sub, reason, created_at \
             FROM comment_reports WHERE comment_id IN ({placeholders}) \
             ORDER BY created_at DESC, reporter_sub DESC"
        );
        let mut q = sqlx::query(&sql);
        for id in comment_ids {
            q = q.bind(id);
        }
        let rows = q.fetch_all(&self.pool).await?;
        rows.iter().map(Self::report_from_row).collect()
    }

    fn report_from_row(row: &sqlx::postgres::PgRow) -> Result<CommentReport, sqlx::Error> {
        Ok(CommentReport {
            comment_id: row.try_get("comment_id")?,
            reporter_sub: row.try_get("reporter_sub")?,
            reason: row.try_get("reason")?,
            created_at: row.try_get("created_at")?,
        })
    }

    async fn report_comment_async(&self, r: &CommentReport) -> Result<bool, sqlx::Error> {
        let inserted = sqlx::query(
            "INSERT INTO comment_reports (comment_id, reporter_sub, reason, created_at) \
             VALUES ($1, $2, $3, $4) ON CONFLICT (comment_id, reporter_sub) DO NOTHING",
        )
        .bind(&r.comment_id)
        .bind(&r.reporter_sub)
        .bind(&r.reason)
        .bind(r.created_at)
        .execute(&self.pool)
        .await?;
        if inserted.rows_affected() > 0 {
            return Ok(true);
        }
        sqlx::query(
            "UPDATE comment_reports SET reason = $1, created_at = $2 \
             WHERE comment_id = $3 AND reporter_sub = $4",
        )
        .bind(&r.reason)
        .bind(r.created_at)
        .bind(&r.comment_id)
        .bind(&r.reporter_sub)
        .execute(&self.pool)
        .await?;
        Ok(false)
    }

    async fn get_comment_async(&self, id: &str) -> Result<Option<Comment>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT id, thread_id, author_sub, author_email, body, created_at, hidden, parent_id \
             FROM comments WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(r) => Ok(Some(Self::comment_from_row(&r)?)),
            None => Ok(None),
        }
    }

    async fn create_comment_async(&self, c: &Comment) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO comments \
                 (id, thread_id, author_sub, author_email, body, created_at, hidden, parent_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&c.id)
        .bind(&c.thread_id)
        .bind(&c.author_sub)
        .bind(&c.author_email)
        .bind(&c.body)
        .bind(c.created_at)
        .bind(c.hidden)
        .bind(&c.parent_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn set_comment_hidden_async(&self, id: &str, hidden: bool) -> Result<bool, sqlx::Error> {
        let res = sqlx::query("UPDATE comments SET hidden = $1 WHERE id = $2")
            .bind(hidden)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn update_comment_body_async(
        &self,
        id: &str,
        author_sub: &str,
        body: &str,
    ) -> Result<bool, sqlx::Error> {
        // Ownership is enforced atomically in the WHERE clause: a non-owner (or missing) id updates
        // zero rows, so the handler cannot edit someone else's comment.
        let res = sqlx::query("UPDATE comments SET body = $1 WHERE id = $2 AND author_sub = $3")
            .bind(body)
            .bind(id)
            .bind(author_sub)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn delete_comment_async(&self, id: &str, author_sub: &str) -> Result<bool, sqlx::Error> {
        let res = sqlx::query("DELETE FROM comments WHERE id = $1 AND author_sub = $2")
            .bind(id)
            .bind(author_sub)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn count_comments_async(&self, thread_id: &str) -> Result<i64, sqlx::Error> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM comments WHERE thread_id = $1")
            .bind(thread_id)
            .fetch_one(&self.pool)
            .await?;
        row.try_get("n")
    }

    async fn recent_comments_async(&self, limit: usize) -> Result<Vec<Comment>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, thread_id, author_sub, author_email, body, created_at, hidden, parent_id \
             FROM comments ORDER BY created_at DESC, id DESC LIMIT $1",
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::comment_from_row).collect()
    }

    fn blocked_from_row(row: &sqlx::postgres::PgRow) -> Result<BlockedAuthor, sqlx::Error> {
        Ok(BlockedAuthor {
            author_sub: row.try_get("author_sub")?,
            reason: row.try_get("reason")?,
            blocked_by: row.try_get("blocked_by")?,
            created_at: row.try_get("created_at")?,
        })
    }

    async fn delete_comment_any_async(&self, id: &str) -> Result<bool, sqlx::Error> {
        let res = sqlx::query("DELETE FROM comments WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn set_hidden_by_author_async(
        &self,
        author_sub: &str,
        hidden: bool,
    ) -> Result<u64, sqlx::Error> {
        let res = sqlx::query("UPDATE comments SET hidden = $1 WHERE author_sub = $2")
            .bind(hidden)
            .bind(author_sub)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    async fn is_blocked_async(&self, author_sub: &str) -> Result<bool, sqlx::Error> {
        let row = sqlx::query("SELECT 1 AS x FROM blocked_authors WHERE author_sub = $1")
            .bind(author_sub)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    async fn list_blocked_async(&self) -> Result<Vec<BlockedAuthor>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT author_sub, reason, blocked_by, created_at \
             FROM blocked_authors ORDER BY created_at DESC, author_sub DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::blocked_from_row).collect()
    }

    async fn block_author_async(&self, e: &BlockedAuthor) -> Result<bool, sqlx::Error> {
        // Race-safe idempotent insert: an already-blocked author affects zero rows.
        let res = sqlx::query(
            "INSERT INTO blocked_authors (author_sub, reason, blocked_by, created_at) \
             VALUES ($1, $2, $3, $4) ON CONFLICT (author_sub) DO NOTHING",
        )
        .bind(&e.author_sub)
        .bind(&e.reason)
        .bind(&e.blocked_by)
        .bind(e.created_at)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn unblock_author_async(&self, author_sub: &str) -> Result<bool, sqlx::Error> {
        let res = sqlx::query("DELETE FROM blocked_authors WHERE author_sub = $1")
            .bind(author_sub)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }
}

#[async_trait]
impl Store for PgStore {
    async fn list_threads(&self, before: Option<(i64, String)>, limit: i64) -> Vec<Thread> {
        self.list_threads_async(before, limit)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg list_threads failed");
                Vec::new()
            })
    }

    async fn get_thread(&self, key: &str) -> Option<Thread> {
        self.get_thread_async(key).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg get_thread failed");
            None
        })
    }

    async fn upsert_thread(&self, thread: &Thread) -> Result<Thread, StoreError> {
        self.upsert_thread_async(thread)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_comments(&self, thread_id: &str) -> Vec<Comment> {
        self.list_comments_async(thread_id)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg list_comments failed");
                Vec::new()
            })
    }

    async fn list_thread_page(
        &self,
        thread_id: &str,
        sort: Sort,
        before: Option<CommentCursor>,
        limit: i64,
    ) -> (Vec<Comment>, Vec<Comment>) {
        self.list_thread_page_async(thread_id, sort, before, limit)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg list_thread_page failed");
                (Vec::new(), Vec::new())
            })
    }

    async fn reactions_for(&self, comment_ids: &[String]) -> Vec<Reaction> {
        self.reactions_for_async(comment_ids)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg reactions_for failed");
                Vec::new()
            })
    }

    async fn toggle_reaction(&self, reaction: &Reaction) -> Result<bool, StoreError> {
        self.toggle_reaction_async(reaction)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn votes_for(&self, comment_ids: &[String]) -> Vec<CommentVote> {
        self.votes_for_async(comment_ids).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg votes_for failed");
            Vec::new()
        })
    }

    async fn toggle_vote(&self, vote: &CommentVote) -> Result<i64, StoreError> {
        self.toggle_vote_async(vote)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn reports_for(&self, comment_ids: &[String]) -> Vec<CommentReport> {
        self.reports_for_async(comment_ids)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg reports_for failed");
                Vec::new()
            })
    }

    async fn report_comment(&self, report: &CommentReport) -> Result<bool, StoreError> {
        self.report_comment_async(report)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get_comment(&self, id: &str) -> Option<Comment> {
        self.get_comment_async(id).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg get_comment failed");
            None
        })
    }

    async fn create_comment(&self, comment: &Comment) -> Result<(), StoreError> {
        self.create_comment_async(comment)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn set_comment_hidden(&self, id: &str, hidden: bool) -> Result<bool, StoreError> {
        self.set_comment_hidden_async(id, hidden)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn update_comment_body(
        &self,
        id: &str,
        author_sub: &str,
        body: &str,
    ) -> Result<bool, StoreError> {
        self.update_comment_body_async(id, author_sub, body)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn delete_comment(&self, id: &str, author_sub: &str) -> Result<bool, StoreError> {
        self.delete_comment_async(id, author_sub)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn count_comments(&self, thread_id: &str) -> i64 {
        self.count_comments_async(thread_id)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg count_comments failed");
                0
            })
    }

    async fn recent_comments(&self, limit: usize) -> Vec<Comment> {
        self.recent_comments_async(limit).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg recent_comments failed");
            Vec::new()
        })
    }

    async fn delete_comment_any(&self, id: &str) -> Result<bool, StoreError> {
        self.delete_comment_any_async(id)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn set_hidden_by_author(
        &self,
        author_sub: &str,
        hidden: bool,
    ) -> Result<u64, StoreError> {
        self.set_hidden_by_author_async(author_sub, hidden)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn is_blocked(&self, author_sub: &str) -> bool {
        self.is_blocked_async(author_sub).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg is_blocked failed");
            false
        })
    }

    async fn list_blocked(&self) -> Vec<BlockedAuthor> {
        self.list_blocked_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg list_blocked failed");
            Vec::new()
        })
    }

    async fn block_author(&self, entry: &BlockedAuthor) -> Result<bool, StoreError> {
        self.block_author_async(entry)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn unblock_author(&self, author_sub: &str) -> Result<bool, StoreError> {
        self.unblock_author_async(author_sub)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }
}

// --------------------------------------------------------------------------------------
// Tests (in-memory keyset pagination — database-free).
// --------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DEFAULT_PAGE, MAX_PAGE};

    fn thread(id: &str, created_at: i64) -> Thread {
        Thread {
            id: id.to_string(),
            key: format!("k/{id}"),
            title: String::new(),
            url: String::new(),
            created_at,
        }
    }

    fn ids(v: &[Thread]) -> Vec<&str> {
        v.iter().map(|t| t.id.as_str()).collect()
    }

    // A full page walk over distinct timestamps: newest-first, cursor threads through every row.
    #[tokio::test]
    async fn list_threads_keyset_walks_all_pages() {
        let store = InMemoryStore::new();
        for (id, ts) in [("t1", 10), ("t2", 20), ("t3", 30), ("t4", 40), ("t5", 50)] {
            store.upsert_thread(&thread(id, ts)).await.unwrap();
        }

        // no cursor -> newest page.
        let page1 = store.list_threads(None, 2).await;
        assert_eq!(ids(&page1), ["t5", "t4"]);

        // cursor from the last row of page1 -> the next-older page.
        let last = page1.last().unwrap().clone();
        let page2 = store
            .list_threads(Some((last.created_at, last.id)), 2)
            .await;
        assert_eq!(ids(&page2), ["t3", "t2"]);

        // final (partial) page.
        let last = page2.last().unwrap().clone();
        let page3 = store
            .list_threads(Some((last.created_at, last.id)), 2)
            .await;
        assert_eq!(ids(&page3), ["t1"]);
    }

    // Ties on created_at break by id DESC, and the cursor must not skip or repeat the tie group.
    #[tokio::test]
    async fn list_threads_keyset_breaks_ties_by_id() {
        let store = InMemoryStore::new();
        for id in ["a", "b", "c"] {
            store.upsert_thread(&thread(id, 100)).await.unwrap();
        }
        // id DESC within the equal timestamp: c, b, a.
        let page1 = store.list_threads(None, 2).await;
        assert_eq!(ids(&page1), ["c", "b"]);
        let last = page1.last().unwrap().clone();
        let page2 = store
            .list_threads(Some((last.created_at, last.id)), 2)
            .await;
        assert_eq!(ids(&page2), ["a"]);
    }

    // A non-positive limit defaults; an oversized one is capped.
    #[test]
    fn clamp_page_defaults_and_caps() {
        assert_eq!(clamp_page(0), DEFAULT_PAGE);
        assert_eq!(clamp_page(-5), DEFAULT_PAGE);
        assert_eq!(clamp_page(10), 10);
        assert_eq!(clamp_page(10_000), MAX_PAGE);
    }

    fn comment(id: &str, thread_id: &str, parent_id: &str, created_at: i64) -> Comment {
        Comment {
            id: id.to_string(),
            thread_id: thread_id.to_string(),
            author_sub: format!("u_{id}"),
            author_email: String::new(),
            body: id.to_string(),
            created_at,
            hidden: false,
            parent_id: parent_id.to_string(),
        }
    }

    fn cids(v: &[Comment]) -> Vec<&str> {
        v.iter().map(|c| c.id.as_str()).collect()
    }

    // toggle_reaction flips on/off idempotently and reactions_for reflects the live rows.
    #[tokio::test]
    async fn toggle_reaction_is_idempotent() {
        let store = InMemoryStore::new();
        let r = |kind: &str, who: &str| Reaction {
            comment_id: "c1".into(),
            user_sub: who.into(),
            kind: kind.into(),
            created_at: 1,
        };
        // First toggle adds (=> true, now reacted).
        assert!(store.toggle_reaction(&r("up", "alice")).await.unwrap());
        // A different user reacting "up" is a distinct row.
        assert!(store.toggle_reaction(&r("up", "bob")).await.unwrap());
        let rows = store.reactions_for(&["c1".to_string()]).await;
        assert_eq!(rows.len(), 2, "two distinct up reactions");
        // Re-toggling alice's "up" removes it (=> false, now un-reacted).
        assert!(!store.toggle_reaction(&r("up", "alice")).await.unwrap());
        let rows = store.reactions_for(&["c1".to_string()]).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].user_sub, "bob");
        // Unknown comment ids return nothing.
        assert!(store.reactions_for(&["nope".to_string()]).await.is_empty());
    }

    // toggle_vote enforces one vote per user/comment, with same-direction clearing and
    // opposite-direction flipping.
    #[tokio::test]
    async fn toggle_vote_is_one_per_user_with_flip() {
        let store = InMemoryStore::new();
        let v = |who: &str, value: i64, ts: i64| CommentVote {
            comment_id: "c1".into(),
            voter_sub: who.into(),
            value,
            created_at: ts,
        };

        assert_eq!(store.toggle_vote(&v("alice", 1, 1)).await.unwrap(), 1);
        assert_eq!(store.toggle_vote(&v("bob", -1, 1)).await.unwrap(), -1);
        let rows = store.votes_for(&["c1".to_string()]).await;
        assert_eq!(rows.len(), 2, "two distinct voters");
        assert_eq!(
            rows.iter().map(|r| r.value).sum::<i64>(),
            0,
            "score balances"
        );

        // Alice flips from +1 to -1 without creating a second row.
        assert_eq!(store.toggle_vote(&v("alice", -1, 2)).await.unwrap(), -1);
        let rows = store.votes_for(&["c1".to_string()]).await;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows.iter().map(|r| r.value).sum::<i64>(), -2);

        // Alice repeats -1, clearing her vote.
        assert_eq!(store.toggle_vote(&v("alice", -1, 3)).await.unwrap(), 0);
        let rows = store.votes_for(&["c1".to_string()]).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].voter_sub, "bob");
        assert!(store.votes_for(&["nope".to_string()]).await.is_empty());
    }

    // report_comment is one report per user/comment; a repeat updates the reason/timestamp.
    #[tokio::test]
    async fn report_comment_is_one_per_user_and_updates_reason() {
        let store = InMemoryStore::new();
        let r = |who: &str, reason: &str, ts: i64| CommentReport {
            comment_id: "c1".into(),
            reporter_sub: who.into(),
            reason: reason.into(),
            created_at: ts,
        };

        assert!(store.report_comment(&r("alice", "spam", 1)).await.unwrap());
        assert!(!store
            .report_comment(&r("alice", "updated reason", 2))
            .await
            .unwrap());
        assert!(store.report_comment(&r("bob", "abuse", 3)).await.unwrap());

        let rows = store.reports_for(&["c1".to_string()]).await;
        assert_eq!(rows.len(), 2, "one row per reporter");
        assert!(rows
            .iter()
            .any(|row| row.reporter_sub == "alice" && row.reason == "updated reason"));
        assert!(store.reports_for(&["nope".to_string()]).await.is_empty());
    }

    // Top-level pagination walks a full page under each sort; replies of the page's parents ride
    // along, and most-reacted ranks by total reaction count with a newest-first tie-break.
    #[tokio::test]
    async fn thread_page_sorts_and_keyset() {
        let store = InMemoryStore::new();
        // Four top-level comments at distinct timestamps + one reply under t2.
        for (id, ts) in [("t1", 10), ("t2", 20), ("t3", 30), ("t4", 40)] {
            store
                .create_comment(&comment(id, "th", "", ts))
                .await
                .unwrap();
        }
        store
            .create_comment(&comment("r2", "th", "t2", 25))
            .await
            .unwrap();
        // Reactions: t2 gets 3, t4 gets 1, t1/t3 get 0.
        for who in ["a", "b", "c"] {
            store
                .toggle_reaction(&Reaction {
                    comment_id: "t2".into(),
                    user_sub: who.into(),
                    kind: "up".into(),
                    created_at: 1,
                })
                .await
                .unwrap();
        }
        store
            .toggle_reaction(&Reaction {
                comment_id: "t4".into(),
                user_sub: "a".into(),
                kind: "up".into(),
                created_at: 1,
            })
            .await
            .unwrap();
        // Votes: t3 scores +2, t4 scores +1, t2 scores 0, t1 scores -1.
        for (comment_id, voter_sub, value) in [
            ("t3", "va", 1),
            ("t3", "vb", 1),
            ("t4", "vc", 1),
            ("t1", "vd", -1),
        ] {
            store
                .toggle_vote(&CommentVote {
                    comment_id: comment_id.into(),
                    voter_sub: voter_sub.into(),
                    value,
                    created_at: 1,
                })
                .await
                .unwrap();
        }

        // Oldest: chronological; the reply rides with its parent t2.
        let (tops, replies) = store.list_thread_page("th", Sort::Oldest, None, 10).await;
        assert_eq!(cids(&tops), ["t1", "t2", "t3", "t4"]);
        assert_eq!(cids(&replies), ["r2"], "reply of a page parent comes along");

        // Newest: reverse chronological.
        let (tops, _) = store.list_thread_page("th", Sort::Newest, None, 10).await;
        assert_eq!(cids(&tops), ["t4", "t3", "t2", "t1"]);

        // Most-reacted: t2(3) > t4(1) > {t3,t1}(0) with newest-first tie-break (t3 before t1).
        let (tops, _) = store
            .list_thread_page("th", Sort::MostReacted, None, 10)
            .await;
        assert_eq!(cids(&tops), ["t2", "t4", "t3", "t1"]);

        // Top: t3(+2) > t4(+1) > t2(0) > t1(-1).
        let (tops, _) = store.list_thread_page("th", Sort::Top, None, 10).await;
        assert_eq!(cids(&tops), ["t3", "t4", "t2", "t1"]);

        // Keyset walk under Oldest with a page size of 2.
        let (p1, _) = store.list_thread_page("th", Sort::Oldest, None, 2).await;
        assert_eq!(cids(&p1), ["t1", "t2"]);
        let last = p1.last().unwrap();
        let cur = CommentCursor {
            reactions: 0,
            created_at: last.created_at,
            id: last.id.clone(),
        };
        let (p2, _) = store
            .list_thread_page("th", Sort::Oldest, Some(cur), 2)
            .await;
        assert_eq!(cids(&p2), ["t3", "t4"]);

        // Keyset walk under MostReacted: cursor carries the reaction count of the last row.
        let (p1, _) = store
            .list_thread_page("th", Sort::MostReacted, None, 2)
            .await;
        assert_eq!(cids(&p1), ["t2", "t4"]);
        let last = p1.last().unwrap();
        let cur = CommentCursor {
            reactions: 1, // t4's total
            created_at: last.created_at,
            id: last.id.clone(),
        };
        let (p2, _) = store
            .list_thread_page("th", Sort::MostReacted, Some(cur), 2)
            .await;
        assert_eq!(cids(&p2), ["t3", "t1"]);

        // Keyset walk under Top: cursor carries the vote score of the last row.
        let (p1, _) = store.list_thread_page("th", Sort::Top, None, 2).await;
        assert_eq!(cids(&p1), ["t3", "t4"]);
        let last = p1.last().unwrap();
        let cur = CommentCursor {
            reactions: 1, // t4's vote score
            created_at: last.created_at,
            id: last.id.clone(),
        };
        let (p2, _) = store.list_thread_page("th", Sort::Top, Some(cur), 2).await;
        assert_eq!(cids(&p2), ["t2", "t1"]);
    }
}
