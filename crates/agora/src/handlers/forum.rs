//! The forum pages: home, category, thread (with markdown-rendered posts + reply), and the
//! new-thread form + create.
//!
//! Every page is server-rendered into the shared enterprise shell. Reads render for any
//! gateway-authenticated user; the two POSTs (create thread, reply) require a gateway-injected
//! identity (the trusted author) AND a valid double-submit CSRF token. Post bodies are
//! CommonMark, rendered through the sanitiser in [`crate::markdown`]; all other interpolated
//! text is HTML-escaped.

use std::collections::{HashMap, HashSet};

use axum::extract::{Form, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth;
use crate::error::AppError;
use crate::handlers::insight::thread_summary;
use crate::handlers::{
    ag_initial, ag_tone, email_display, esc, fmt_ts, personal_counts, rel_time,
    render_page_with_personal_counts, replies_label,
};
use crate::model::{Bookmark, Post, ReactionCount, Thread, ThreadFollowLevel, ThreadReadingState};
use crate::store::{
    AcceptedAnswerAction, ReplyAnchor, ThreadPersonalSignals, ThreadSort, ThreadStatusFilter,
    MAX_FOR_YOU_CANDIDATES, MAX_KLAXON_RECIPIENTS_PER_REPLY,
};
use crate::{markdown, new_id, now_secs, AppState};

/// Most-recent threads shown on the home page.
const RECENT_LIMIT: i64 = 20;
/// Replies rendered per keyset page on the thread view. A large thread renders (and reaction-
/// queries) only one page of replies at a time; the OP is always pinned on top, separately.
pub const REPLIES_PER_PAGE: i64 = 20;
/// Threads listed on a category page.
const CATEGORY_LIMIT: i64 = 200;
/// Final `/for-you` surface bound after a larger authoritative candidate set is projected.
const FOR_YOU_LIMIT: usize = 30;
/// Caps on user input (defense against absurd payloads; the store columns are TEXT).
const MAX_TITLE: usize = 200;
const MAX_BODY: usize = 20_000;

/// The reaction kinds a user may toggle on a post: `(kind, glyph)`. This is the closed set — a
/// POST with any other `kind` is rejected — and it drives the rendered button row (a button per
/// entry, in this order) so every post shows the same, stable reaction affordances.
pub const REACTION_KINDS: &[(&str, &str)] = &[("up", "\u{1F44D}"), ("heart", "\u{2764}")];

/// Whether `kind` is one of the allowed [`REACTION_KINDS`].
fn is_reaction_kind(kind: &str) -> bool {
    REACTION_KINDS.iter().any(|(k, _)| *k == kind)
}

/// Inline progressive-enhancement script for the new-thread form: as the user types, it asks
/// `POST /api/similar` for the top existing threads similar to the draft and lists them. It
/// reads the draft's own double-submit CSRF token from the form's hidden input, builds result
/// links with `textContent` (never `innerHTML`), and silently hides on any error — so a user
/// with JS disabled, or an API hiccup, just sees the normal form.
const SIMILAR_SCRIPT: &str = r#"<script>
(function () {
  var form = document.querySelector('form[action="/new"]');
  if (!form) return;
  var title = document.getElementById('nt-title');
  var body = document.getElementById('nt-body');
  var box = document.getElementById('similar-box');
  var list = document.getElementById('similar-list');
  if (!title || !body || !box || !list) return;
  var csrfInput = form.querySelector('input[name="csrf"]');
  var csrf = csrfInput ? csrfInput.value : '';
  var timer = null;
  function run() {
    var t = (title.value || '').trim();
    var b = (body.value || '').trim();
    if (t.length < 4 && b.length < 12) { box.hidden = true; return; }
    var payload = 'csrf=' + encodeURIComponent(csrf) +
      '&title=' + encodeURIComponent(t) + '&body=' + encodeURIComponent(b);
    fetch('/api/similar', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: payload,
      credentials: 'same-origin'
    }).then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        list.textContent = '';
        var items = (data && data.similar) || [];
        if (!items.length) { box.hidden = true; return; }
        items.forEach(function (it) {
          var li = document.createElement('li');
          var a = document.createElement('a');
          a.href = '/t/' + it.id;
          a.target = '_blank';
          a.rel = 'noopener';
          a.textContent = it.title;
          li.appendChild(a);
          list.appendChild(li);
        });
        box.hidden = false;
      }).catch(function () { box.hidden = true; });
  }
  function schedule() { if (timer) clearTimeout(timer); timer = setTimeout(run, 500); }
  title.addEventListener('input', schedule);
  body.addEventListener('input', schedule);
})();
</script>"#;

/// Sentences in the per-thread extractive summary card.
const SUMMARY_SENTENCES: usize = 3;
/// Only render the summary card once a thread is substantial enough to be worth compressing:
/// at least this many posts AND words. Small/short threads show no card (the posts ARE the
/// summary), so the page is unchanged for them.
const SUMMARY_MIN_POSTS: usize = 2;
const SUMMARY_MIN_WORDS: usize = 60;

// ===========================================================================
// GET / — categories (with thread counts) + recent threads
// ===========================================================================

/// Shared query for thread lists (`/` and `/c/{id}`): optional sort selector and a current-user
/// subscription filter. Missing/unknown sort preserves the legacy latest ordering.
#[derive(Debug, Deserialize, Default)]
pub struct ThreadListQuery {
    #[serde(default)]
    pub sort: Option<String>,
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
}

impl ThreadListQuery {
    fn sort(&self) -> ThreadSort {
        match self.sort.as_deref().unwrap_or("latest") {
            "top" => ThreadSort::Top,
            "hot" => ThreadSort::Hot,
            _ => ThreadSort::Latest,
        }
    }

    fn sort_key(&self) -> &'static str {
        match self.sort() {
            ThreadSort::Latest => "latest",
            ThreadSort::Top => "top",
            ThreadSort::Hot => "hot",
        }
    }

    fn subscribed_only(&self) -> bool {
        self.filter.as_deref() == Some("subscribed")
    }

    fn status(&self) -> ThreadStatusFilter {
        match self.status.as_deref() {
            Some("answered") => ThreadStatusFilter::Answered,
            Some("unanswered") => ThreadStatusFilter::Unanswered,
            _ => ThreadStatusFilter::Any,
        }
    }
}

/// Compact owner-scoped count used only inside the home rail. `None` means there is no trusted
/// gateway subject, while zero deliberately renders no badge. The count is request-derived from
/// the same authoritative reads as the app bar and never implies background delivery.
fn render_personal_rail_count(count: Option<i64>, noun: &str) -> String {
    let count = count.unwrap_or(0).max(0);
    if count == 0 {
        return String::new();
    }
    let display = if count > 99 {
        "99+".to_string()
    } else {
        count.to_string()
    };
    format!(
        r#"<span class="ag-cat__count ag-personal-count">{display} {noun}</span>"#,
        display = display,
        noun = esc(noun),
    )
}

pub async fn home(
    State(state): State<AppState>,
    Query(q): Query<ThreadListQuery>,
    headers: HeaderMap,
) -> Result<Html<String>, AppError> {
    let now = now_secs();
    let categories = state.store.list_categories().await?;
    let viewer_sub = auth::identity_subject(&headers);
    let recent = if q.subscribed_only() && viewer_sub.is_none() {
        Vec::new()
    } else {
        state
            .store
            .list_threads(
                None,
                q.sort(),
                subscribed_subject(&q, viewer_sub.as_deref()),
                q.status(),
                RECENT_LIMIT,
                now,
            )
            .await?
    };

    // id -> name map so recent rows can name their category.
    let cat_names: HashMap<&str, &str> = categories
        .iter()
        .map(|c| (c.id.as_str(), c.name.as_str()))
        .collect();
    let question_categories: HashSet<&str> = categories
        .iter()
        .filter(|category| category.format.is_question())
        .map(|category| category.id.as_str())
        .collect();
    let mut reply_counts = HashMap::new();
    for t in &recent {
        reply_counts.insert(t.id.clone(), state.store.count_posts(&t.id).await?);
    }
    let reading_states = load_reading_states(&state, viewer_sub.as_deref(), &recent).await?;

    let mut cats_html = String::new();
    for c in &categories {
        let count = state.store.count_threads(&c.id).await?;
        cats_html.push_str(&format!(
            r#"<a class="ag-cat" href="/c/{id}">
  <span class="ag-cat__dot ag-tone-{tone}" aria-hidden="true"></span>
  <span class="ag-cat__name">{name}</span>
  <span class="ag-cat__count">{count}</span>
</a>"#,
            id = esc(&c.id),
            tone = ag_tone(&c.id),
            name = esc(&c.name),
            count = count,
        ));
    }
    if cats_html.is_empty() {
        cats_html = r#"<div class="empty">No categories yet.</div>"#.to_string();
    }

    let recent_html = render_thread_rows(
        &recent,
        now,
        Some(&cat_names),
        Some(&reply_counts),
        &question_categories,
        &reading_states,
    );
    let thread_controls =
        render_thread_list_controls("/", &q, viewer_sub.is_some(), true, q.status());
    let counts = personal_counts(&state, &headers, now).await?;
    let activity_count = render_personal_rail_count(counts.unread_activity, "unread");
    let bookmark_count = render_personal_rail_count(counts.due_bookmarks, "due");

    let content = format!(
        r#"<div class="page-head">
  <div>
    <h1>Forum</h1>
    <p class="muted">Discussions across the keep — sign-in is handled by Keystone SSO.</p>
  </div>
</div>
<div class="ag-home">
  <aside class="ag-rail">
    <a class="btn btn-primary ag-cta" href="/new">New thread</a>
    <div class="ag-rail__group">
      <p class="ag-rail__label">Discover</p>
      <nav class="ag-rail__nav" aria-label="Discover discussions">
      <a class="ag-cat{all_active}" href="/"{all_current}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg><span class="ag-cat__name">All threads</span></a>
      <a class="ag-cat" href="/questions"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M9.1 9a3 3 0 1 1 5.8 1c0 2-3 2-3 4"/><path d="M12 18h.01"/></svg><span class="ag-cat__name">Questions</span></a>
      </nav>
    </div>
    <div class="ag-rail__group ag-rail__group--personal">
      <p class="ag-rail__label">For you</p>
      <nav class="ag-rail__nav" aria-label="For you">
      <a class="ag-cat" href="/for-you"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m12 3 1.7 5.3L19 10l-5.3 1.7L12 17l-1.7-5.3L5 10l5.3-1.7L12 3z"/><path d="M19 15v4"/><path d="M21 17h-4"/></svg><span class="ag-cat__name">For You</span></a>
      <a class="ag-cat" href="/activity"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg><span class="ag-cat__name">Activity</span>{activity_count}</a>
      <a class="ag-cat" href="/bookmarks"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 3h12a1 1 0 0 1 1 1v17l-7-4-7 4V4a1 1 0 0 1 1-1z"/></svg><span class="ag-cat__name">Saved</span>{bookmark_count}</a>
      <a class="ag-cat{following_active}" href="/?filter=subscribed"{following_current}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8 5h8"/><path d="M6 9h12"/><path d="M4 13h16"/><path d="m9 17 3 3 3-3"/></svg><span class="ag-cat__name">Following</span></a>
      </nav>
    </div>
    <div class="ag-rail__group">
      <p class="ag-rail__label">Spaces</p>
      <nav class="ag-rail__nav" aria-label="Categories">
      {cats}
      </nav>
    </div>
  </aside>
  <div class="ag-feed">
    <section class="section">
      <h2 class="section__title">{thread_title}</h2>
      {controls}
      <div class="thread-list">{recent}</div>
    </section>
  </div>
</div>"#,
        cats = cats_html,
        all_active = if q.subscribed_only() {
            ""
        } else {
            " is-active"
        },
        all_current = if q.subscribed_only() {
            ""
        } else {
            r#" aria-current="page""#
        },
        following_active = if q.subscribed_only() {
            " is-active"
        } else {
            ""
        },
        following_current = if q.subscribed_only() {
            r#" aria-current="page""#
        } else {
            ""
        },
        activity_count = activity_count,
        bookmark_count = bookmark_count,
        thread_title = thread_list_title(&q, "Recent activity"),
        controls = thread_controls,
        recent = recent_html,
    );

    Ok(Html(render_page_with_personal_counts(
        "Forum",
        &email_display(&headers),
        &content,
        counts,
    )))
}

// ===========================================================================
// GET /for-you — private, explainable personal feed
// ===========================================================================

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ForYouReason {
    Watch,
    Follow,
    Authored,
    Bookmarked,
    Participated,
    ContinueReading,
}

impl ForYouReason {
    const fn key(self) -> &'static str {
        match self {
            Self::Watch => "watch",
            Self::Follow => "follow",
            Self::Authored => "authored",
            Self::Bookmarked => "bookmarked",
            Self::Participated => "participated",
            Self::ContinueReading => "reading",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Watch => "Watching · new replies also enter Activity",
            Self::Follow => "Following · kept in your personal feeds",
            Self::Authored => "You started this thread",
            Self::Bookmarked => "You bookmarked a post here",
            Self::Participated => "You joined this conversation",
            Self::ContinueReading => "Continue reading · unread posts remain",
        }
    }

    const fn priority(self) -> u8 {
        match self {
            Self::Watch => 0,
            Self::Follow => 1,
            Self::Authored => 2,
            Self::Bookmarked => 3,
            Self::Participated => 4,
            Self::ContinueReading => 5,
        }
    }
}

fn explain_personal_candidate(signals: ThreadPersonalSignals) -> Option<ForYouReason> {
    if signals.follow_level == ThreadFollowLevel::Mute {
        return None;
    }
    match signals.follow_level {
        ThreadFollowLevel::Watch => Some(ForYouReason::Watch),
        ThreadFollowLevel::Follow => Some(ForYouReason::Follow),
        ThreadFollowLevel::None | ThreadFollowLevel::Mute if signals.authored => {
            Some(ForYouReason::Authored)
        }
        ThreadFollowLevel::None | ThreadFollowLevel::Mute if signals.bookmarked => {
            Some(ForYouReason::Bookmarked)
        }
        ThreadFollowLevel::None | ThreadFollowLevel::Mute if signals.participated => {
            Some(ForYouReason::Participated)
        }
        ThreadFollowLevel::None | ThreadFollowLevel::Mute
            if signals.reading_started && signals.has_unread =>
        {
            Some(ForYouReason::ContinueReading)
        }
        ThreadFollowLevel::None | ThreadFollowLevel::Mute => None,
    }
}

pub async fn for_you(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Html<String>, AppError> {
    let identity = auth::require_author(&headers)?;
    let now = now_secs();

    // Authorization comes first. The personal projection can only score ids returned by the
    // same authoritative list path used by Latest; it can never introduce an otherwise-hidden
    // thread through a bookmark, receipt, or stale preference row.
    let candidates = state
        .store
        .list_threads(
            None,
            ThreadSort::Latest,
            None,
            ThreadStatusFilter::Any,
            MAX_FOR_YOU_CANDIDATES as i64,
            now,
        )
        .await?;
    let candidate_ids: Vec<String> = candidates.iter().map(|thread| thread.id.clone()).collect();
    let signals = state
        .store
        .thread_personal_signals(&identity.sub, &candidate_ids)
        .await?;
    let mut personalized: Vec<(Thread, ForYouReason)> = candidates
        .into_iter()
        .filter_map(|thread| {
            signals
                .get(&thread.id)
                .copied()
                .and_then(explain_personal_candidate)
                .map(|reason| (thread, reason))
        })
        .collect();
    // `sort_by_key` is stable: within one explainable reason the authoritative Latest order is
    // preserved, including its pinned semantics and deterministic id tie-break.
    personalized.sort_by_key(|(_, reason)| reason.priority());
    personalized.truncate(FOR_YOU_LIMIT);
    let reasons: HashMap<String, ForYouReason> = personalized
        .iter()
        .map(|(thread, reason)| (thread.id.clone(), *reason))
        .collect();
    let threads: Vec<Thread> = personalized.into_iter().map(|(thread, _)| thread).collect();

    let categories = state.store.list_categories().await?;
    let category_names: HashMap<&str, &str> = categories
        .iter()
        .map(|category| (category.id.as_str(), category.name.as_str()))
        .collect();
    let question_categories: HashSet<&str> = categories
        .iter()
        .filter(|category| category.format.is_question())
        .map(|category| category.id.as_str())
        .collect();
    // Exact unread details are loaded once only for the final rendered page, not for the larger
    // candidate set. Candidate reading signals were already projected in the bounded batch.
    let reading_states = load_reading_states(&state, Some(&identity.sub), &threads).await?;
    let rows = render_for_you_rows(
        &threads,
        now,
        &category_names,
        &question_categories,
        &reading_states,
        &reasons,
    );
    let content = format!(
        r#"<nav class="crumbs"><a href="/">Home</a><span class="crumbs__sep">/</span><span>For You</span></nav>
<div class="page-head ag-for-you-head">
  <div><p class="ag-for-you-eyebrow">Private · explainable</p><h1>For You</h1><p class="muted">A bounded view built only from your Forum relationships — never from hidden content or an external recommender.</p></div>
  <a class="btn btn-secondary" href="/?filter=subscribed">Open Following</a>
</div>
<aside class="ag-for-you-note" role="note"><strong>Why these threads?</strong><span>Every row names one authoritative reason. Watch, Follow, Mute or reset a thread from its page; Mute always wins here.</span></aside>
<section class="section ag-for-you-feed" aria-labelledby="for-you-heading">
  <h2 id="for-you-heading" class="section__title">Your current threads</h2>
  <div class="thread-list">{rows}</div>
</section>"#,
        rows = rows,
    );
    let counts = personal_counts(&state, &headers, now).await?;
    Ok(Html(render_page_with_personal_counts(
        "For You",
        &email_display(&headers),
        &content,
        counts,
    )))
}

// ===========================================================================
// GET /questions — all question categories, with a stable answer-status filter
// ===========================================================================

pub async fn questions(
    State(state): State<AppState>,
    Query(q): Query<ThreadListQuery>,
    headers: HeaderMap,
) -> Result<Html<String>, AppError> {
    let now = now_secs();
    let categories = state.store.list_categories().await?;
    let viewer_sub = auth::identity_subject(&headers);
    let status = match q.status() {
        ThreadStatusFilter::Any => ThreadStatusFilter::Questions,
        filtered => filtered,
    };
    let threads = if q.subscribed_only() && viewer_sub.is_none() {
        Vec::new()
    } else {
        state
            .store
            .list_threads(
                None,
                q.sort(),
                subscribed_subject(&q, viewer_sub.as_deref()),
                status,
                CATEGORY_LIMIT,
                now,
            )
            .await?
    };
    let category_names: HashMap<&str, &str> = categories
        .iter()
        .map(|category| (category.id.as_str(), category.name.as_str()))
        .collect();
    let question_categories: HashSet<&str> = categories
        .iter()
        .filter(|category| category.format.is_question())
        .map(|category| category.id.as_str())
        .collect();
    let ask_href = categories
        .iter()
        .find(|category| category.format.is_question())
        .map(|category| format!("/new?cat={}", esc(&category.id)))
        .unwrap_or_else(|| "/new".to_string());
    let reading_states = load_reading_states(&state, viewer_sub.as_deref(), &threads).await?;
    let list = render_thread_rows(
        &threads,
        now,
        Some(&category_names),
        None,
        &question_categories,
        &reading_states,
    );
    let controls =
        render_thread_list_controls("/questions", &q, viewer_sub.is_some(), true, status);
    let heading = match status {
        ThreadStatusFilter::Answered => "Answered questions",
        ThreadStatusFilter::Unanswered => "Questions that need an answer",
        ThreadStatusFilter::Any | ThreadStatusFilter::Questions => "All questions",
    };
    let content = format!(
        r#"<nav class="crumbs"><a href="/">Home</a><span class="crumbs__sep">/</span><span>Questions</span></nav>
<div class="page-head ag-question-head">
  <div><h1>{heading}</h1><p class="muted">A focused answer desk across every question category.</p></div>
  <a class="btn btn-primary" href="{ask_href}">Ask question</a>
</div>
<section class="section">
  {controls}
  <div class="thread-list">{list}</div>
</section>"#,
        heading = heading,
        ask_href = ask_href,
        controls = controls,
        list = list,
    );
    let counts = personal_counts(&state, &headers, now).await?;
    Ok(Html(render_page_with_personal_counts(
        "Questions",
        &email_display(&headers),
        &content,
        counts,
    )))
}

// ===========================================================================
// GET /c/{id} — threads in a category
// ===========================================================================

pub async fn category(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<ThreadListQuery>,
    headers: HeaderMap,
) -> Result<Html<String>, AppError> {
    let now = now_secs();
    let category = state
        .store
        .get_category(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("category not found".to_string()))?;
    let viewer_sub = auth::identity_subject(&headers);
    let status = if category.format.is_question() {
        q.status()
    } else {
        ThreadStatusFilter::Any
    };
    let threads = if q.subscribed_only() && viewer_sub.is_none() {
        Vec::new()
    } else {
        state
            .store
            .list_threads(
                Some(&id),
                q.sort(),
                subscribed_subject(&q, viewer_sub.as_deref()),
                status,
                CATEGORY_LIMIT,
                now,
            )
            .await?
    };

    let crumbs = format!(
        r#"<nav class="crumbs"><a href="/">Home</a><span class="crumbs__sep">/</span><span>{name}</span></nav>"#,
        name = esc(&category.name),
    );
    let question_categories: HashSet<&str> = if category.format.is_question() {
        std::iter::once(category.id.as_str()).collect()
    } else {
        HashSet::new()
    };
    let reading_states = load_reading_states(&state, viewer_sub.as_deref(), &threads).await?;
    let list = render_thread_rows(
        &threads,
        now,
        None,
        None,
        &question_categories,
        &reading_states,
    );
    let controls = render_thread_list_controls(
        &format!("/c/{}", esc(&category.id)),
        &q,
        viewer_sub.is_some(),
        category.format.is_question(),
        status,
    );

    let content = format!(
        r#"{crumbs}
<div class="page-head">
  <div>
    <h1>{name}</h1>
    <p class="muted">{count} {tw} in this {format_label} category.</p>
  </div>
  <a class="btn btn-primary" href="/new?cat={id}">{new_label}</a>
</div>
<section class="section">
  {controls}
  <div class="thread-list">{list}</div>
</section>"#,
        crumbs = crumbs,
        name = esc(&category.name),
        count = threads.len(),
        tw = if threads.len() == 1 {
            if category.format.is_question() {
                "question"
            } else {
                "thread"
            }
        } else {
            if category.format.is_question() {
                "questions"
            } else {
                "threads"
            }
        },
        format_label = if category.format.is_question() {
            "question"
        } else {
            "discussion"
        },
        new_label = if category.format.is_question() {
            "Ask question"
        } else {
            "New thread"
        },
        id = esc(&category.id),
        controls = controls,
        list = list,
    );

    let counts = personal_counts(&state, &headers, now).await?;
    Ok(Html(render_page_with_personal_counts(
        &category.name,
        &email_display(&headers),
        &content,
        counts,
    )))
}

// ===========================================================================
// GET /t/{id} — a thread: original post + replies (markdown) + reply form
// ===========================================================================

/// Keyset cursor + page anchor for the thread view's reply list. All optional; a bare
/// `GET /t/{id}` shows the first (oldest) page. `?before=<created_at>_<id>` pages to older
/// replies, `?after=<created_at>_<id>` to newer, `?around=<created_at>_<id>` includes an activity
/// target, and `?latest=1` jumps to the newest page.
#[derive(Debug, Deserialize, Default)]
pub struct ThreadQuery {
    #[serde(default)]
    pub before: Option<String>,
    #[serde(default)]
    pub after: Option<String>,
    #[serde(default)]
    pub latest: Option<String>,
    #[serde(default)]
    pub around: Option<String>,
    #[serde(default)]
    pub quote: Option<String>,
    /// Product-level continuation entry. It resolves from authoritative per-post receipts and is
    /// intentionally separate from raw keyset cursors.
    #[serde(default)]
    pub resume: Option<String>,
}

pub async fn thread(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<ThreadQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let now = now_secs();
    let thread = state
        .store
        .get_thread(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("thread not found".to_string()))?;
    let category = state.store.get_category(&thread.category_id).await?;
    let is_question = category
        .as_ref()
        .map(|category| category.format.is_question())
        .unwrap_or(false);
    let viewer = auth::identity_subject(&headers);
    let reading_state = match viewer.as_deref() {
        Some(subject) => Some(state.store.thread_reading_state(subject, &id).await?),
        None => None,
    };

    // Reply count (every post minus the original) — shown in the head + as the reply-list total.
    let post_count = state.store.count_posts(&id).await?;

    // Keyset-paginated reply list. The original post is pinned at the top on its own; the replies
    // below it are ONE page under the shared `(created_at, id)` idiom, so a huge thread renders —
    // and reaction-queries — only a page of replies at a time. We fetch one extra row to learn
    // whether more replies exist in the fetch direction, then normalise every page to ascending
    // (oldest→newest) display order.
    let op = state.store.first_post_in_thread(&id).await?;
    let op_id = op.as_ref().map(|p| p.id.clone()).unwrap_or_default();
    let accepted_post = state.store.get_valid_accepted_post(&id).await?;
    let valid_accepted_id = accepted_post
        .as_ref()
        .map(|post| post.id.clone())
        .unwrap_or_default();
    let accepted_id = (!valid_accepted_id.is_empty()).then_some(valid_accepted_id.as_str());
    let resume_requested = q
        .resume
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    let first_unread = reading_state
        .as_ref()
        .and_then(|reading| reading.first_unread.as_ref());
    let anchor = if resume_requested {
        match first_unread {
            Some(post) if post.id == op_id => ReplyAnchor::First,
            Some(post) if Some(post.id.as_str()) == accepted_id => {
                ReplyAnchor::After(post.created_at, post.id.clone())
            }
            Some(post) => ReplyAnchor::From(post.created_at, post.id.clone()),
            None => ReplyAnchor::Latest,
        }
    } else {
        resolve_anchor(&q)
    };
    let mut fetched = state
        .store
        .replies_page(&id, &op_id, accepted_id, &anchor, REPLIES_PER_PAGE + 1)
        .await?;
    let around_has_newer = if let ReplyAnchor::Around(ts, post_id) = &anchor {
        !state
            .store
            .replies_page(
                &id,
                &op_id,
                accepted_id,
                &ReplyAnchor::After(*ts, post_id.clone()),
                1,
            )
            .await?
            .is_empty()
    } else {
        false
    };
    let from_has_older = if let ReplyAnchor::From(ts, post_id) = &anchor {
        !state
            .store
            .replies_page(
                &id,
                &op_id,
                accepted_id,
                &ReplyAnchor::Before(*ts, post_id.clone()),
                1,
            )
            .await?
            .is_empty()
    } else {
        false
    };
    let has_more = fetched.len() as i64 > REPLIES_PER_PAGE;
    fetched.truncate(REPLIES_PER_PAGE as usize);
    let (replies, has_older, has_newer) = match anchor {
        // Ascending fetches: already oldest→newest. First has nothing older (OP is the floor);
        // After was reached from an older page, so older replies exist.
        ReplyAnchor::First => (fetched, false, has_more),
        ReplyAnchor::From(..) => (fetched, from_has_older, has_more),
        ReplyAnchor::After(..) => (fetched, true, has_more),
        // Descending fetches: reverse to oldest→newest. Before/Latest were walked newest-first, so
        // `has_more` means more OLDER replies; Before was reached from a newer page.
        ReplyAnchor::Before(..) => {
            fetched.reverse();
            (fetched, has_more, true)
        }
        ReplyAnchor::Latest => {
            fetched.reverse();
            (fetched, has_more, false)
        }
        ReplyAnchor::Around(..) => {
            fetched.reverse();
            (fetched, has_more, around_has_newer)
        }
    };
    // Cursors come from the visible page bounds (ascending: first = oldest, last = newest).
    let older_cursor = if has_older {
        replies.first().map(|p| (p.created_at, p.id.clone()))
    } else {
        None
    };
    let newer_cursor = if has_newer {
        replies.last().map(|p| (p.created_at, p.id.clone()))
    } else {
        None
    };
    let pagination = render_reply_pagination(
        &thread.id,
        older_cursor.as_ref(),
        newer_cursor.as_ref(),
        has_newer,
    );

    // The stable Latest anchor targets the final ordinary reply on this page. On the newest page
    // that is the newest ordinary reply; if the solution is the only reply, it falls back to that
    // solution, and an otherwise empty discussion falls back to its original post.
    let latest_post_id = replies
        .last()
        .map(|post| post.id.clone())
        .or_else(|| accepted_post.as_ref().map(|post| post.id.clone()))
        .or_else(|| op.as_ref().map(|post| post.id.clone()))
        .unwrap_or_default();

    // Display list: original post, then the accepted solution fixed directly below it, then one
    // full page of ordinary replies. The store excluded the solution before LIMIT, so it neither
    // disappears on another page nor renders twice on its natural page.
    let mut posts: Vec<Post> = Vec::with_capacity(replies.len() + 2);
    if let Some(op_post) = op {
        posts.push(op_post);
    }
    if let Some(solution) = accepted_post {
        posts.push(solution);
    }
    posts.extend(replies);

    // The authenticated subject (if any) decides which edit/delete controls render.
    let is_admin = auth::is_admin(&headers);
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let subscription_action = if let Some(sub) = viewer.as_deref() {
        let follow_level = state.store.thread_follow_level(&thread.id, sub).await?;
        render_subscription_form(&thread.id, &csrf, follow_level)
    } else {
        String::new()
    };
    let quote_target = match q.quote.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(pid) => state
            .store
            .get_post(pid)
            .await?
            .filter(|p| p.thread_id == thread.id),
        None => None,
    };

    // Admin moderation toolbar (lock/pin/move/delete) — only for admins. The move dropdown
    // needs the full category list, fetched only on the admin path.
    let admin_actions = if is_admin {
        let categories = state.store.list_categories().await?;
        render_admin_thread_toolbar(&thread, &categories, &csrf)
    } else {
        String::new()
    };

    // Breadcrumb: Home / Category / Thread.
    let cat_crumb = match &category {
        Some(c) => format!(
            r#"<a href="/c/{cid}">{cname}</a><span class="crumbs__sep">/</span>"#,
            cid = esc(&c.id),
            cname = esc(&c.name),
        ),
        None => String::new(),
    };
    let crumbs = format!(
        r#"<nav class="crumbs"><a href="/">Home</a><span class="crumbs__sep">/</span>{cat}<span>{title}</span></nav>"#,
        cat = cat_crumb,
        title = esc(&thread.title),
    );

    let can_manage_answer = viewer.as_deref() == Some(thread.author_sub.as_str()) || is_admin;
    // Thread-level controls (edit title + original post, delete whole thread) — author only.
    let mut thread_actions = if viewer.as_deref() == Some(thread.author_sub.as_str()) {
        format!(
            r#"<div class="owner-actions">
  <a class="btn btn-secondary btn-sm" href="/t/{tid}/edit">Edit thread</a>
  <form class="inline-form" method="post" action="/t/{tid}/delete" onsubmit="return confirm('Delete this thread and all its replies? This cannot be undone.');">
    <input type="hidden" name="csrf" value="{csrf}">
    <button class="btn btn-danger btn-sm" type="submit">Delete thread</button>
  </form>
</div>"#,
            tid = esc(&thread.id),
            csrf = esc(&csrf),
        )
    } else {
        String::new()
    };
    if can_manage_answer
        && !thread.accepted_post_id.trim().is_empty()
        && valid_accepted_id.is_empty()
    {
        thread_actions.push_str(&format!(
            r#"<form class="inline-form" method="post" action="/t/{tid}/accept">
  <input type="hidden" name="csrf" value="{csrf}">
  <input type="hidden" name="action" value="clear">
  <button class="btn btn-secondary btn-sm" type="submit">Clear invalid solution</button>
</form>"#,
            tid = esc(&thread.id),
            csrf = esc(&csrf),
        ));
    }

    let summary_html = render_summary(&posts);

    // Display order: the original post stays first, then the accepted reply (if any), then the
    // rest in their natural oldest-first order. Reordering a clone never touches storage.
    let ordered = order_posts_accepted_first(&posts, &valid_accepted_id);
    let first_unread_id = reading_state
        .as_ref()
        .and_then(|reading| reading.first_unread.as_ref())
        .map(|post| post.id.as_str());
    let resume_marker_in_posts =
        first_unread_id.is_some_and(|post_id| ordered.iter().any(|post| post.id == post_id));
    let quoted_posts = load_quoted_posts(&state, &thread.id, &ordered).await?;

    // Per-post reaction aggregates (counts + whether THIS viewer reacted), keyed by post id.
    let mut reactions: HashMap<String, Vec<ReactionCount>> = HashMap::new();
    for p in &ordered {
        let counts = state
            .store
            .reactions_for_post(&p.id, viewer.as_deref())
            .await?;
        reactions.insert(p.id.clone(), counts);
    }
    // One bounded owner-scoped lookup for the whole visible post page. Bookmark state must never
    // add another per-post query beside the legacy reaction aggregation.
    let bookmarks: HashMap<String, Bookmark> = if let Some(subject) = viewer.as_deref() {
        let post_ids: Vec<String> = ordered.iter().map(|post| post.id.clone()).collect();
        state
            .store
            .bookmarks_for_posts(subject, &post_ids)
            .await?
            .into_iter()
            .map(|bookmark| (bookmark.post_id.clone(), bookmark))
            .collect()
    } else {
        HashMap::new()
    };

    let posts_html = render_posts(
        &ordered,
        now,
        viewer.as_deref(),
        is_admin,
        &thread.id,
        &csrf,
        &valid_accepted_id,
        can_manage_answer,
        is_question,
        !thread.locked,
        &latest_post_id,
        first_unread_id,
        &reactions,
        &bookmarks,
        &quoted_posts,
    );
    let read_progress = render_thread_read_progress(
        &thread.id,
        &csrf,
        viewer.as_deref(),
        reading_state.as_ref(),
        &ordered,
    );

    // A locked thread shows a notice instead of the reply form (admins still moderate above).
    let reply_form = if thread.locked {
        r#"<section class="card pad"><p class="muted ag-locked"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect width="18" height="11" x="3" y="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>This thread is locked — no new replies.</p></section>"#
            .to_string()
    } else {
        let quote_fields = render_reply_quote_fields(quote_target.as_ref());
        let composer_head = render_composer_head(
            &headers,
            &format!(
                r#"<b>{verb}</b><span>{context} &quot;{}&quot;</span>"#,
                esc(&thread.title),
                verb = if is_question { "Answer" } else { "Reply" },
                context = if is_question {
                    "answering"
                } else {
                    "replying to"
                },
            ),
        );
        format!(
            r#"<section id="reply" class="card ag-composer ag-composer--reply">
  <form class="ag-form" method="post" action="/t/{tid}/reply">
    <input type="hidden" name="csrf" value="{csrf}">
    {head}
    <div class="ag-composer__fields">
      {quote}
      <div class="field">
        <label class="label" for="reply-body">Your {reply_noun} <span class="muted">(Markdown supported)</span></label>
        <textarea id="reply-body" name="body" rows="6" placeholder="Write {reply_article} {reply_noun}…" required></textarea>
      </div>
    </div>
    <div class="ag-composer__bar">
      {hint}
      <div class="ag-composer__actions"><button class="btn btn-primary" type="submit">Post {reply_noun}</button></div>
    </div>
  </form>
</section>"#,
            tid = esc(&thread.id),
            csrf = esc(&csrf),
            head = composer_head,
            quote = quote_fields,
            hint = markdown_hint(),
            reply_noun = if is_question { "answer" } else { "reply" },
            reply_article = if is_question { "an" } else { "a" },
        )
    };

    // Status badges in the thread head (pinned / locked) so the state is visible to everyone.
    let mut badges = String::new();
    if thread.pinned {
        badges.push_str(r#" <span class="badge badge-op">Pinned</span>"#);
    }
    if thread.locked {
        badges.push_str(r#" <span class="badge badge-op">Locked</span>"#);
    }
    if is_question {
        if valid_accepted_id.is_empty() {
            badges.push_str(
                r#" <span class="badge ag-answer-state ag-answer-state--open">Needs answer</span>"#,
            );
        } else {
            badges
                .push_str(r#" <span class="badge badge-accepted ag-answer-state">Answered</span>"#);
        }
    }
    let category_chip = category
        .as_ref()
        .map(|c| {
            format!(
                r#"<a class="ag-chip ag-tone-{tone}" href="/c/{cid}">{name}</a>"#,
                tone = ag_tone(&c.id),
                cid = esc(&c.id),
                name = esc(&c.name),
            )
        })
        .unwrap_or_default();
    let head_tools = if thread_actions.is_empty() {
        String::new()
    } else {
        format!(r#"<div class="ag-head-tools">{thread_actions}</div>"#)
    };
    // Product-native reading controls share the existing reply anchor, keyset route and the one
    // authoritative subscription form. No duplicate form/id/state is introduced for the sticky
    // desktop rail or its mobile bottom-dock presentation.
    let reading_toolbar = render_thread_reading_toolbar(ThreadToolbarView {
        thread_id: &thread.id,
        post_count,
        subscription_form: &subscription_action,
        can_reply: !thread.locked,
        is_question,
        has_newer,
        reading_state: reading_state.as_ref(),
        resume_marker_in_posts,
    });

    let content = format!(
        r#"{crumbs}
<div class="thread-head ag-thread-head">
  <div>
    <h1>{title}{badges}</h1>
    <div class="ag-thread-meta">{category_chip}<span>Started by <strong>{author}</strong></span><time title="{created_abs}">{created_rel}</time><span>{replies}</span></div>
    {actions}
  </div>
  {admin_actions}
</div>
{reading_toolbar}
{summary}
<section id="thread-replies" class="posts" aria-label="Thread posts">{posts}</section>
{read_progress}
{pagination}
{reply}"#,
        crumbs = crumbs,
        title = esc(&thread.title),
        badges = badges,
        category_chip = category_chip,
        author = esc(&thread.author_email),
        created_abs = esc(&fmt_ts(thread.created_at)),
        created_rel = esc(&rel_time(thread.created_at, now)),
        replies = esc(&replies_label(post_count)),
        actions = head_tools,
        admin_actions = admin_actions,
        reading_toolbar = reading_toolbar,
        summary = summary_html,
        posts = posts_html,
        read_progress = read_progress,
        pagination = pagination,
        reply = reply_form,
    );

    let counts = personal_counts(&state, &headers, now).await?;
    let html = render_page_with_personal_counts(
        &thread.title,
        &email_display(&headers),
        &content,
        counts,
    );
    Ok(html_response(html, set_cookie))
}

#[derive(Debug, Deserialize)]
pub struct ThreadReadForm {
    #[serde(default)]
    pub csrf: String,
    /// Comma-separated stable post ids rendered by the server for this bounded page.
    #[serde(default)]
    pub post_ids: String,
}

/// `POST /t/{id}/read` — subject-scoped, idempotent page receipt. A normal form follows the
/// earliest remaining unread post; the IntersectionObserver enhancement asks for a 204 and keeps
/// the current page in place. GET / resume never mutates reading state.
pub async fn mark_thread_read(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<ThreadReadForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let identity = auth::require_author(&headers)?;
    let post_ids: Vec<String> = form
        .post_ids
        .split(',')
        .map(str::trim)
        .filter(|post_id| !post_id.is_empty())
        .map(str::to_string)
        .collect();
    state
        .store
        .mark_thread_posts_read(&identity.sub, &id, &post_ids, now_secs())
        .await?;
    if wants_json(&headers) {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    Ok(redirect_to(&format!("/t/{}?resume=1#thread-resume", id)))
}

// ===========================================================================
// GET /new?cat= — new-thread form
// ===========================================================================

#[derive(Debug, Deserialize, Default)]
pub struct NewQuery {
    #[serde(default)]
    pub cat: Option<String>,
}

pub async fn new_form(
    State(state): State<AppState>,
    Query(q): Query<NewQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let now = now_secs();
    let categories = state.store.list_categories().await?;
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let requested = q.cat.unwrap_or_default();
    let selected_category = categories
        .iter()
        .find(|category| category.id == requested)
        .or_else(|| categories.first());
    let selected = selected_category
        .map(|category| category.id.as_str())
        .unwrap_or_default();
    let is_question = selected_category
        .map(|category| category.format.is_question())
        .unwrap_or(false);
    let (_, _, viewer_email) = composer_identity(&headers);

    let mut options = String::new();
    for c in &categories {
        let sel = if c.id == selected { " selected" } else { "" };
        options.push_str(&format!(
            r#"<option value="{id}"{sel}>{name}</option>"#,
            id = esc(&c.id),
            sel = sel,
            name = esc(&c.name),
        ));
    }

    let content = format!(
        r#"<nav class="crumbs"><a href="/">Home</a><span class="crumbs__sep">/</span><span>{page_title}</span></nav>
<div class="page-head"><div><h1>{page_title}</h1><p class="muted">{page_note}</p></div></div>
<section class="card ag-composer ag-composer--new">
  <form class="ag-form" method="post" action="/new">
    <input type="hidden" name="csrf" value="{csrf}">
    {head}
    <div class="ag-composer__fields">
      <div class="field">
        <label class="label" for="nt-title">Title</label>
        <input id="nt-title" class="input ag-title-input" type="text" name="title" maxlength="{maxt}" placeholder="A short, descriptive title" required>
        <p class="hint">Up to 200 characters — make it easy to find</p>
        <div id="similar-box" class="similar ag-similar" hidden>
          <div class="similar__head">Similar existing threads — is one of these your topic?</div>
          <ul id="similar-list" class="similar__list"></ul>
        </div>
      </div>
      <div class="ag-meta-row">
        <div class="field">
          <label class="label" for="nt-cat">Category</label>
          <select id="nt-cat" name="category" required>{options}</select>
        </div>
      </div>
      <div class="field">
        <label class="label" for="nt-body">Body <span class="muted">(Markdown supported)</span></label>
        <textarea id="nt-body" name="body" rows="12" placeholder="Write the first post…" required></textarea>
      </div>
    </div>
    <div class="ag-composer__bar">
      {hint}
      <div class="ag-composer__actions">
      <a class="btn btn-secondary" href="/">Cancel</a>
      <button class="btn btn-primary" type="submit">{submit_label}</button>
      </div>
    </div>
  </form>
</section>
{script}"#,
        csrf = esc(&csrf),
        page_title = if is_question {
            "Ask a question"
        } else {
            "New thread"
        },
        page_note = if is_question {
            "Describe the problem clearly so the community can propose a reusable answer."
        } else {
            "Start an open discussion with the community."
        },
        head = render_composer_head(
            &headers,
            &format!(r#"<b>{viewer_email}</b><span>posting a new thread</span>"#),
        ),
        options = options,
        maxt = MAX_TITLE,
        hint = markdown_hint(),
        submit_label = if is_question {
            "Ask question"
        } else {
            "Create thread"
        },
        script = SIMILAR_SCRIPT,
    );

    let counts = personal_counts(&state, &headers, now).await?;
    let html = render_page_with_personal_counts(
        if is_question {
            "Ask a question"
        } else {
            "New thread"
        },
        &email_display(&headers),
        &content,
        counts,
    );
    Ok(html_response(html, set_cookie))
}

// ===========================================================================
// POST /new — create a thread
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct NewThreadForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub body: String,
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<NewThreadForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let author = auth::require_author(&headers)?;
    if state.store.is_banned(&author.sub).await? {
        return Err(AppError::Forbidden(
            "your account is blocked from posting".to_string(),
        ));
    }

    let title = form.title.trim();
    if title.is_empty() {
        return Err(AppError::InvalidRequest(
            "thread title is required".to_string(),
        ));
    }
    if title.chars().count() > MAX_TITLE {
        return Err(AppError::InvalidRequest(
            "thread title is too long".to_string(),
        ));
    }
    let category_id = form.category.trim();
    if state.store.get_category(category_id).await?.is_none() {
        return Err(AppError::InvalidRequest("unknown category".to_string()));
    }
    let body = form.body.trim();
    if body.is_empty() {
        return Err(AppError::InvalidRequest(
            "post body is required".to_string(),
        ));
    }
    if body.chars().count() > MAX_BODY {
        return Err(AppError::InvalidRequest(
            "post body is too long".to_string(),
        ));
    }

    let now = now_secs();
    let thread = Thread {
        id: new_id("t"),
        category_id: category_id.to_string(),
        title: title.to_string(),
        author_sub: author.sub.clone(),
        author_email: author.email.clone(),
        created_at: now,
        last_at: now,
        locked: false,
        pinned: false,
        accepted_post_id: String::new(),
    };
    let first_post = Post {
        id: new_id("p"),
        thread_id: thread.id.clone(),
        body_md: body.to_string(),
        quoted_post_id: String::new(),
        author_sub: author.sub,
        author_email: author.email,
        created_at: now,
    };
    let mentions = extract_mentions(&first_post.body_md);
    state
        .store
        .create_thread_with_activity(&thread, &first_post, &mentions, &new_id("a"))
        .await?;
    tracing::info!(
        thread = thread.id,
        author = thread.author_email,
        "thread created"
    );

    let actor = if thread.author_email.is_empty() {
        &thread.author_sub
    } else {
        &thread.author_email
    };
    state.audit.emit(AuditEvent::info(
        "thread.create",
        actor,
        &thread.id,
        &thread.category_id,
    ));

    Ok(redirect_to(&format!("/t/{}", thread.id)))
}

// ===========================================================================
// POST /t/{id}/reply — post a reply
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct ReplyForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub quote_post_id: String,
    #[serde(default)]
    pub body: String,
}

pub async fn reply(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<ReplyForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let author = auth::require_author(&headers)?;
    if state.store.is_banned(&author.sub).await? {
        return Err(AppError::Forbidden(
            "your account is blocked from posting".to_string(),
        ));
    }

    let thread = state
        .store
        .get_thread(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("thread not found".to_string()))?;
    if thread.locked {
        return Err(AppError::Forbidden(
            "this thread is locked — no new replies".to_string(),
        ));
    }
    let body = form.body.trim();
    if body.is_empty() {
        return Err(AppError::InvalidRequest(
            "reply body is required".to_string(),
        ));
    }
    if body.chars().count() > MAX_BODY {
        return Err(AppError::InvalidRequest(
            "reply body is too long".to_string(),
        ));
    }
    let quoted_post = match form.quote_post_id.trim().is_empty() {
        true => None,
        false => {
            let quoted = state
                .store
                .get_post(form.quote_post_id.trim())
                .await?
                .filter(|p| p.thread_id == id)
                .ok_or_else(|| {
                    AppError::InvalidRequest("quoted post must belong to this thread".to_string())
                })?;
            Some(quoted)
        }
    };
    let quoted_post_id = quoted_post
        .as_ref()
        .map(|p| p.id.clone())
        .unwrap_or_default();

    let now = now_secs();
    let post = Post {
        id: new_id("p"),
        thread_id: id.clone(),
        body_md: body.to_string(),
        quoted_post_id,
        author_sub: author.sub,
        author_email: author.email,
        created_at: now,
    };
    let mentions = extract_mentions(&post.body_md);
    let activity = state
        .store
        .add_reply_with_activity(&post, &mentions, &new_id("a"))
        .await?;
    tracing::info!(thread = id, author = post.author_email, "reply posted");

    let actor = if post.author_email.is_empty() {
        &post.author_sub
    } else {
        &post.author_email
    };
    state
        .audit
        .emit(AuditEvent::info("reply.create", actor, &post.id, &id));
    notify_reply(&state, &thread, &post, &activity.delivery_subjects);

    Ok(redirect_to(&format!("/t/{id}")))
}

// ===========================================================================
// GET/POST /t/{id}/edit — edit one's OWN thread (title + original-post body)
// ===========================================================================

/// Form body for editing a thread: title + original-post body. Identity is NEVER read from the
/// form — only from the gateway headers.
#[derive(Debug, Deserialize)]
pub struct EditThreadForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub body: String,
}

/// Minimal form body for a delete: just the CSRF token (identity comes from the gateway).
#[derive(Debug, Deserialize)]
pub struct DeleteForm {
    #[serde(default)]
    pub csrf: String,
}

pub async fn edit_thread_form(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let now = now_secs();
    let author = auth::require_author(&headers)?;
    let thread = state
        .store
        .get_thread(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("thread not found".to_string()))?;
    if thread.author_sub != author.sub {
        return Err(AppError::Forbidden(
            "you can only edit your own threads".to_string(),
        ));
    }
    let posts = state.store.posts_in_thread(&id).await?;
    let op_body = posts.first().map(|p| p.body_md.as_str()).unwrap_or("");
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    let content = render_edit_form(
        "Edit thread",
        &format!("/t/{}/edit", esc(&thread.id)),
        &csrf,
        Some(&thread.title),
        op_body,
        &format!("/t/{}", esc(&thread.id)),
        &headers,
    );
    let counts = personal_counts(&state, &headers, now).await?;
    let html = render_page_with_personal_counts(
        "Edit thread",
        &email_display(&headers),
        &content,
        counts,
    );
    Ok(html_response(html, set_cookie))
}

pub async fn update_thread(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<EditThreadForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let author = auth::require_author(&headers)?;

    let thread = state
        .store
        .get_thread(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("thread not found".to_string()))?;
    if thread.author_sub != author.sub {
        return Err(AppError::Forbidden(
            "you can only edit your own threads".to_string(),
        ));
    }

    let title = form.title.trim();
    if title.is_empty() {
        return Err(AppError::InvalidRequest(
            "thread title is required".to_string(),
        ));
    }
    if title.chars().count() > MAX_TITLE {
        return Err(AppError::InvalidRequest(
            "thread title is too long".to_string(),
        ));
    }
    let body = form.body.trim();
    if body.is_empty() {
        return Err(AppError::InvalidRequest(
            "post body is required".to_string(),
        ));
    }
    if body.chars().count() > MAX_BODY {
        return Err(AppError::InvalidRequest(
            "post body is too long".to_string(),
        ));
    }

    // Resolve the stable OP identity; never infer it from second-granularity timestamps.
    let op_id = state
        .store
        .first_post_in_thread(&id)
        .await?
        .map(|post| post.id)
        .ok_or_else(|| AppError::NotFound("thread has no original post".to_string()))?;

    state.store.update_thread(&id, title, &op_id, body).await?;
    state
        .store
        .replace_mentions(&op_id, &id, &extract_mentions(body), now_secs())
        .await?;
    tracing::info!(thread = id, author = thread.author_email, "thread updated");

    let actor = if thread.author_email.is_empty() {
        &thread.author_sub
    } else {
        &thread.author_email
    };
    state.audit.emit(AuditEvent::info(
        "thread.update",
        actor,
        &thread.id,
        &thread.category_id,
    ));

    Ok(redirect_to(&format!("/t/{id}")))
}

pub async fn delete_thread(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<DeleteForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let author = auth::require_author(&headers)?;

    let thread = state
        .store
        .get_thread(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("thread not found".to_string()))?;
    if thread.author_sub != author.sub {
        return Err(AppError::Forbidden(
            "you can only delete your own threads".to_string(),
        ));
    }

    state.store.delete_thread(&id).await?;
    tracing::info!(thread = id, author = thread.author_email, "thread deleted");

    let actor = if thread.author_email.is_empty() {
        &thread.author_sub
    } else {
        &thread.author_email
    };
    state.audit.emit(AuditEvent::notice(
        "thread.delete",
        actor,
        &thread.id,
        &thread.category_id,
    ));

    // Bounce back to the thread's category (or home if it is gone).
    Ok(redirect_to(&format!("/c/{}", thread.category_id)))
}

// ===========================================================================
// GET/POST /t/{tid}/p/{pid}/edit + POST /t/{tid}/p/{pid}/delete — one's OWN reply
// ===========================================================================

/// Form body for editing a reply: just the body. Identity comes from the gateway headers.
#[derive(Debug, Deserialize)]
pub struct EditReplyForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub body: String,
}

/// Resolve a reply for an author-gated mutation. Loads the thread's posts, rejects when the post
/// is missing / not in this thread (404), is the ORIGINAL post (that is edited/deleted via the
/// thread controls, which also keep the denormalised `first_body_md` in step — 403), or is not
/// authored by `author_sub` (403). Returns the target post on success.
fn locate_own_reply(posts: &[Post], pid: &str, author_sub: &str) -> Result<Post, AppError> {
    if posts.first().map(|p| p.id == pid).unwrap_or(false) {
        return Err(AppError::Forbidden(
            "the original post is edited or deleted via the thread itself".to_string(),
        ));
    }
    let post = posts
        .iter()
        .find(|p| p.id == pid)
        .ok_or_else(|| AppError::NotFound("reply not found".to_string()))?;
    if post.author_sub != author_sub {
        return Err(AppError::Forbidden(
            "you can only edit your own replies".to_string(),
        ));
    }
    Ok(post.clone())
}

pub async fn edit_reply_form(
    State(state): State<AppState>,
    Path((tid, pid)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let now = now_secs();
    let author = auth::require_author(&headers)?;
    let posts = state.store.posts_in_thread(&tid).await?;
    let post = locate_own_reply(&posts, &pid, &author.sub)?;
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    let content = render_edit_form(
        "Edit reply",
        &format!("/t/{}/p/{}/edit", esc(&tid), esc(&pid)),
        &csrf,
        None,
        &post.body_md,
        &format!("/t/{}", esc(&tid)),
        &headers,
    );
    let counts = personal_counts(&state, &headers, now).await?;
    let html = render_page_with_personal_counts(
        "Edit reply",
        &email_display(&headers),
        &content,
        counts,
    );
    Ok(html_response(html, set_cookie))
}

pub async fn update_reply(
    State(state): State<AppState>,
    Path((tid, pid)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<EditReplyForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let author = auth::require_author(&headers)?;

    let posts = state.store.posts_in_thread(&tid).await?;
    let post = locate_own_reply(&posts, &pid, &author.sub)?;

    let body = form.body.trim();
    if body.is_empty() {
        return Err(AppError::InvalidRequest(
            "reply body is required".to_string(),
        ));
    }
    if body.chars().count() > MAX_BODY {
        return Err(AppError::InvalidRequest(
            "reply body is too long".to_string(),
        ));
    }

    state.store.update_post(&pid, body).await?;
    state
        .store
        .replace_mentions(&pid, &tid, &extract_mentions(body), now_secs())
        .await?;
    tracing::info!(thread = tid, post = pid, "reply updated");

    let actor = if post.author_email.is_empty() {
        &post.author_sub
    } else {
        &post.author_email
    };
    state
        .audit
        .emit(AuditEvent::info("reply.update", actor, &pid, &tid));

    Ok(redirect_to(&format!("/t/{tid}")))
}

pub async fn delete_reply(
    State(state): State<AppState>,
    Path((tid, pid)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<DeleteForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let author = auth::require_author(&headers)?;

    let posts = state.store.posts_in_thread(&tid).await?;
    let post = locate_own_reply(&posts, &pid, &author.sub)?;

    state.store.delete_post(&pid).await?;
    tracing::info!(thread = tid, post = pid, "reply deleted");

    let actor = if post.author_email.is_empty() {
        &post.author_sub
    } else {
        &post.author_email
    };
    state
        .audit
        .emit(AuditEvent::notice("reply.delete", actor, &pid, &tid));

    Ok(redirect_to(&format!("/t/{tid}")))
}

// ===========================================================================
// POST /t/{tid}/p/{pid}/react — toggle a reaction on a post
// ===========================================================================

/// Form body for a reaction toggle: the CSRF token + the reaction `kind`. Identity (the reactor)
/// comes from the gateway headers, never the form.
#[derive(Debug, Deserialize)]
pub struct ReactForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub kind: String,
}

pub async fn react(
    State(state): State<AppState>,
    Path((tid, pid)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<ReactForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let author = auth::require_author(&headers)?;
    if state.store.is_banned(&author.sub).await? {
        return Err(AppError::Forbidden(
            "your account is blocked from posting".to_string(),
        ));
    }

    let kind = form.kind.trim();
    if !is_reaction_kind(kind) {
        return Err(AppError::InvalidRequest(
            "unknown reaction kind".to_string(),
        ));
    }

    // The post must exist AND belong to this thread (guards cross-thread id spoofing).
    let post = state
        .store
        .get_post(&pid)
        .await?
        .filter(|p| p.thread_id == tid)
        .ok_or_else(|| AppError::NotFound("post not found".to_string()))?;

    let on = state
        .store
        .toggle_reaction(&post.id, &author.sub, kind, now_secs())
        .await?;
    tracing::info!(thread = tid, post = pid, kind, on, "reaction toggled");

    let actor = if author.email.is_empty() {
        &author.sub
    } else {
        &author.email
    };
    state.audit.emit(AuditEvent::info(
        "reaction.toggle",
        actor,
        &pid,
        if on { kind } else { "off" },
    ));

    if wants_json(&headers) {
        let count = state
            .store
            .reactions_for_post(&post.id, Some(&author.sub))
            .await?
            .into_iter()
            .find(|c| c.kind == kind)
            .map(|c| c.count)
            .unwrap_or(0);
        return Ok(axum::Json(serde_json::json!({
            "ok": true,
            "post_id": pid,
            "kind": kind,
            "on": on,
            "count": count,
        }))
        .into_response());
    }

    Ok(redirect_to(&format!("/t/{tid}")))
}

// ===========================================================================
// POST /t/{tid}/accept — explicitly accept or clear the accepted answer
// ===========================================================================

/// Explicit accepted-answer command. `accept` requires `post_id`; `clear` ignores it and is
/// idempotent even when a legacy pointer references a post that no longer exists.
#[derive(Debug, Deserialize)]
pub struct AcceptForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub post_id: String,
}

pub async fn accept_answer(
    State(state): State<AppState>,
    Path(tid): Path<String>,
    headers: HeaderMap,
    Form(form): Form<AcceptForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let author = auth::require_author(&headers)?;

    let thread = state
        .store
        .get_thread(&tid)
        .await?
        .ok_or_else(|| AppError::NotFound("thread not found".to_string()))?;

    // Gate: only the thread author or an admin may mark an accepted answer.
    if thread.author_sub != author.sub && !auth::is_admin(&headers) {
        return Err(AppError::Forbidden(
            "only the thread author or an admin can mark the accepted answer".to_string(),
        ));
    }

    let action = match form.action.trim() {
        "accept" => AcceptedAnswerAction::Accept {
            post_id: form.post_id.trim().to_string(),
        },
        "clear" => AcceptedAnswerAction::Clear,
        _ => {
            return Err(AppError::InvalidRequest(
                "answer action must be accept or clear".to_string(),
            ));
        }
    };
    let mutation = state
        .store
        .mutate_accepted_answer_with_activity(&tid, action, &new_id("a"), &author.sub, now_secs())
        .await?;
    let new_accepted = mutation.thread.accepted_post_id.as_str();
    tracing::info!(
        thread = tid,
        accepted = new_accepted,
        changed = mutation.changed,
        "accepted answer command applied"
    );

    let actor = if author.email.is_empty() {
        &author.sub
    } else {
        &author.email
    };
    state.audit.emit(AuditEvent::notice(
        "thread.accept",
        actor,
        &tid,
        if new_accepted.is_empty() {
            "cleared"
        } else {
            new_accepted
        },
    ));
    if mutation.changed {
        if let Some(target_post) = mutation.accepted_post.as_ref() {
            notify_accepted_answer(
                &state,
                &mutation.thread,
                target_post,
                &author.sub,
                &author.email,
            );
        }
    }

    if wants_json(&headers) {
        return Ok(axum::Json(serde_json::json!({
            "ok": true,
            "thread_id": tid,
            "accepted_post_id": new_accepted,
        }))
        .into_response());
    }

    Ok(redirect_to(&format!("/t/{tid}")))
}

// ===========================================================================
// POST /t/{id}/subscribe — explicitly set a result-oriented thread preference
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct SubscribeForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub level: String,
    /// Backwards-compatible JSON/form seam for clients from the boolean subscription release.
    #[serde(default)]
    pub action: String,
}

pub async fn toggle_subscription(
    State(state): State<AppState>,
    Path(tid): Path<String>,
    headers: HeaderMap,
    Form(form): Form<SubscribeForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let author = auth::require_author(&headers)?;
    state
        .store
        .get_thread(&tid)
        .await?
        .ok_or_else(|| AppError::NotFound("thread not found".to_string()))?;

    let follow_level = if form.level.trim().is_empty() {
        match form.action.trim() {
            "follow" => ThreadFollowLevel::Watch,
            "unfollow" => ThreadFollowLevel::None,
            _ => {
                return Err(AppError::InvalidRequest(
                    "thread preference must be watch, follow, mute, or none".to_string(),
                ));
            }
        }
    } else {
        ThreadFollowLevel::parse(&form.level).ok_or_else(|| {
            AppError::InvalidRequest(
                "thread preference must be watch, follow, mute, or none".to_string(),
            )
        })?
    };
    state
        .store
        .set_thread_follow_level(&tid, &author.sub, follow_level, now_secs())
        .await?;
    let actor = if author.email.is_empty() {
        &author.sub
    } else {
        &author.email
    };
    state.audit.emit(AuditEvent::info(
        "thread.follow_preference",
        actor,
        &tid,
        follow_level.as_str(),
    ));

    if wants_json(&headers) {
        return Ok(axum::Json(serde_json::json!({
            "ok": true,
            "thread_id": tid,
            "follow_level": follow_level.as_str(),
            "subscribed": follow_level.appears_in_personal_feeds(),
        }))
        .into_response());
    }

    Ok(redirect_to(&format!("/t/{tid}")))
}

// ===========================================================================
// Render helpers
// ===========================================================================

fn subscribed_subject<'a>(q: &ThreadListQuery, viewer_sub: Option<&'a str>) -> Option<&'a str> {
    if q.subscribed_only() {
        viewer_sub
    } else {
        None
    }
}

fn render_thread_list_controls(
    action: &str,
    q: &ThreadListQuery,
    show_subscribed: bool,
    show_answer_filters: bool,
    effective_status: ThreadStatusFilter,
) -> String {
    let sort = q.sort_key();
    let sub = q.subscribed_only();
    let status_key = match effective_status {
        ThreadStatusFilter::Answered => Some("answered"),
        ThreadStatusFilter::Unanswered => Some("unanswered"),
        ThreadStatusFilter::Any | ThreadStatusFilter::Questions => None,
    };
    // Sort as tabs: real links (no-JS navigates + keeps the `?sort=` contract); the enhancement
    // script intercepts a click, fetches the same URL and swaps the `.thread-list` in place.
    let tab = |key: &str, label: &str| {
        let active = sort == key;
        format!(
            r#"<a class="tab{cls}" role="tab" aria-selected="{sel}" data-sort-tab="{key}" href="{href}">{label}</a>"#,
            cls = if active { " is-active" } else { "" },
            sel = if active { "true" } else { "false" },
            key = key,
            href = list_href(action, key, status_key, sub),
            label = label,
        )
    };
    // Following filter as a toggle link that preserves the current sort. Storage keeps the
    // existing subscription name, but the UI does not promise notification delivery.
    let filter = if show_subscribed {
        let (href, label, cls) = if sub {
            (
                list_href(action, sort, status_key, false),
                "Show all",
                "btn btn-secondary btn-sm",
            )
        } else {
            (
                list_href(action, sort, status_key, true),
                "Following",
                "btn btn-ghost btn-sm",
            )
        };
        format!(
            r#"<a class="{cls} thread-filter" href="{href}">{label}</a>"#,
            cls = cls,
            href = href,
            label = label,
        )
    } else {
        String::new()
    };
    let answer_filters = if show_answer_filters {
        let status_tab = |key: Option<&str>, label: &str| {
            let active = status_key == key;
            format!(
                r#"<a class="tab{cls}" role="tab" aria-selected="{selected}" href="{href}">{label}</a>"#,
                cls = if active { " is-active" } else { "" },
                selected = if active { "true" } else { "false" },
                href = list_href(action, sort, key, sub),
                label = label,
            )
        };
        format!(
            r#"<nav class="tabs answer-tabs" role="tablist" aria-label="Filter by answer status">{all}{unanswered}{answered}</nav>"#,
            all = status_tab(None, "All"),
            unanswered = status_tab(Some("unanswered"), "Unanswered"),
            answered = status_tab(Some("answered"), "Answered"),
        )
    } else {
        String::new()
    };
    format!(
        r#"<div class="thread-controls" data-thread-controls>
  <div class="thread-controls__tabs">
    <nav class="tabs sort-tabs" role="tablist" aria-label="Sort threads">{latest}{top}{hot}</nav>
    {answer_filters}
  </div>
  {following}
</div>"#,
        latest = tab("latest", "Latest"),
        top = tab("top", "Top"),
        hot = tab("hot", "Hot"),
        answer_filters = answer_filters,
        following = filter,
    )
}

fn list_href(action: &str, sort: &str, status: Option<&str>, subscribed: bool) -> String {
    let mut params = vec![format!("sort={sort}")];
    if let Some(status) = status {
        params.push(format!("status={status}"));
    }
    if subscribed {
        params.push("filter=subscribed".to_string());
    }
    format!("{}?{}", esc(action), params.join("&amp;"))
}

fn thread_list_title(q: &ThreadListQuery, fallback: &'static str) -> &'static str {
    match q.status() {
        ThreadStatusFilter::Answered => "Answered questions",
        ThreadStatusFilter::Unanswered => "Questions that need an answer",
        ThreadStatusFilter::Any | ThreadStatusFilter::Questions if q.subscribed_only() => {
            "Following"
        }
        ThreadStatusFilter::Any | ThreadStatusFilter::Questions => fallback,
    }
}

struct ThreadToolbarView<'a> {
    thread_id: &'a str,
    post_count: i64,
    subscription_form: &'a str,
    can_reply: bool,
    is_question: bool,
    has_newer: bool,
    reading_state: Option<&'a ThreadReadingState>,
    resume_marker_in_posts: bool,
}

fn render_thread_reading_toolbar(view: ThreadToolbarView<'_>) -> String {
    let latest_href = if view.has_newer {
        format!("/t/{}?latest=1#thread-latest", esc(view.thread_id))
    } else {
        "#thread-latest".to_string()
    };
    let reply_action = if view.can_reply {
        format!(
            r##"<a class="btn btn-primary btn-sm ag-thread-toolbar__reply" href="#reply">{label}</a>"##,
            label = if view.is_question { "Answer" } else { "Reply" },
        )
    } else {
        r#"<span class="btn btn-secondary btn-sm ag-thread-toolbar__locked" aria-disabled="true">Locked</span>"#
            .to_string()
    };
    let continuity = match view.reading_state {
        Some(reading) if reading.first_unread.is_some() => {
            let marker = if view.resume_marker_in_posts {
                ""
            } else {
                r#" id="thread-resume""#
            };
            let label = if reading.started {
                "Continue reading"
            } else {
                "Start reading"
            };
            format!(
                r##"<a{marker} class="btn btn-secondary btn-sm ag-thread-toolbar__continue" href="/t/{tid}?resume=1#thread-resume">{label}<span>{count} unread</span></a>"##,
                marker = marker,
                tid = esc(view.thread_id),
                label = label,
                count = reading.unread_count,
            )
        }
        Some(_) => {
            let marker = if view.resume_marker_in_posts {
                ""
            } else {
                r#" id="thread-resume""#
            };
            format!(
                r#"<span{marker} class="ag-thread-toolbar__caught"><span class="ag-thread-toolbar__caught-dot" aria-hidden="true"></span>Caught up</span>"#,
                marker = marker,
            )
        }
        None => String::new(),
    };
    format!(
        r#"<nav class="ag-thread-toolbar" aria-label="Thread reading actions">
  <div class="ag-thread-toolbar__context"><span class="ag-thread-toolbar__eyebrow">In this thread</span><strong>{replies}</strong></div>
  <div class="ag-thread-toolbar__actions">
    {continuity}
    <a class="btn btn-ghost btn-sm" href="{latest_href}">Latest</a>
    {subscription_form}
    {reply_action}
  </div>
</nav>"#,
        replies = esc(&replies_label(view.post_count)),
        latest_href = latest_href,
        continuity = continuity,
        subscription_form = view.subscription_form,
        reply_action = reply_action,
    )
}

fn render_thread_read_progress(
    thread_id: &str,
    csrf: &str,
    viewer_sub: Option<&str>,
    reading_state: Option<&ThreadReadingState>,
    visible_posts: &[Post],
) -> String {
    if viewer_sub.is_none()
        || visible_posts.is_empty()
        || reading_state.is_some_and(|reading| reading.unread_count == 0)
    {
        return String::new();
    }
    let post_ids = visible_posts
        .iter()
        .map(|post| post.id.as_str())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"<section class="ag-read-progress" data-thread-read-progress>
  <span class="ag-read-progress__sentinel" data-thread-read-sentinel aria-hidden="true"></span>
  <div class="ag-read-progress__copy"><span>Reading progress</span><strong data-thread-read-status>Only posts shown on this page will be marked read.</strong></div>
  <form class="inline-form" method="post" action="/t/{tid}/read" data-thread-read-form>
    <input type="hidden" name="csrf" value="{csrf}">
    <input type="hidden" name="post_ids" value="{post_ids}">
    <button class="btn btn-secondary btn-sm" type="submit" data-thread-read-submit>Mark page read &amp; continue</button>
  </form>
</section>
<script>
(function () {{
  var form = document.querySelector('[data-thread-read-form]');
  var sentinel = document.querySelector('[data-thread-read-sentinel]');
  if (!form || !sentinel || !window.fetch || !window.IntersectionObserver) return;
  var sent = false;
  var observer = new IntersectionObserver(function (entries) {{
    if (sent || !entries.some(function (entry) {{ return entry.isIntersecting; }})) return;
    sent = true;
    observer.disconnect();
    fetch(form.action, {{
      method: 'POST', body: new URLSearchParams(new FormData(form)), credentials: 'same-origin',
      headers: {{ 'Accept': 'application/json' }}
    }}).then(function (response) {{
      if (!response.ok) throw new Error('read receipt failed');
      var status = document.querySelector('[data-thread-read-status]');
      var button = document.querySelector('[data-thread-read-submit]');
      if (status) status.textContent = 'Page marked read · Continue returns to the earliest unread post.';
      if (button) {{ button.textContent = 'Read through this page'; button.disabled = true; }}
      form.closest('[data-thread-read-progress]').classList.add('is-read');
    }}).catch(function () {{
      var status = document.querySelector('[data-thread-read-status]');
      if (status) status.textContent = 'Automatic progress was not saved · use the button to retry.';
    }});
  }}, {{ rootMargin: '0px 0px -8% 0px' }});
  observer.observe(sentinel);
}})();
</script>"#,
        tid = esc(thread_id),
        csrf = esc(csrf),
        post_ids = esc(&post_ids),
    )
}

fn render_subscription_form(
    thread_id: &str,
    csrf: &str,
    follow_level: ThreadFollowLevel,
) -> String {
    let option = |level: ThreadFollowLevel, label: &str| {
        format!(
            r#"<option value="{value}"{selected}>{label}</option>"#,
            value = level.as_str(),
            selected = if follow_level == level {
                " selected"
            } else {
                ""
            },
            label = esc(label),
        )
    };
    format!(
        r#"<form class="inline-form subscription-form" method="post" action="/t/{tid}/subscribe" data-wire data-wire-target=".subscription-form" data-wire-ok="Thread preference saved" data-wire-err="Could not update your thread preference">
  <input type="hidden" name="csrf" value="{csrf}">
  <span class="subscription-form__field">
    <label class="subscription-form__label" for="thread-follow-{tid}">Thread updates</label>
    <select id="thread-follow-{tid}" name="level" aria-describedby="thread-follow-help-{tid}">
      {watch}
      {follow}
      {mute}
      {none}
    </select>
    <span class="subscription-form__help" id="thread-follow-help-{tid}">Direct replies, mentions and accepted answers still appear in Activity.</span>
  </span>
  <button class="btn btn-secondary btn-sm" type="submit">Apply</button>
</form>"#,
        tid = esc(thread_id),
        csrf = esc(csrf),
        watch = option(ThreadFollowLevel::Watch, "Watch · replies in Activity"),
        follow = option(ThreadFollowLevel::Follow, "Follow · personal feeds only"),
        mute = option(ThreadFollowLevel::Mute, "Mute · hide from personal feeds"),
        none = option(ThreadFollowLevel::None, "None · reset preference"),
    )
}

fn composer_identity(headers: &HeaderMap) -> (usize, String, String) {
    let email = auth::identity_email(headers).unwrap_or_default();
    let subject = auth::identity_subject(headers);
    let tone_key = subject
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(email.as_str());
    let tone = if tone_key.trim().is_empty() {
        1
    } else {
        ag_tone(tone_key)
    };
    let label = if email.trim().is_empty() {
        "Not signed in".to_string()
    } else {
        email.clone()
    };
    (tone, esc(&ag_initial(&email)), esc(&label))
}

fn render_composer_head(headers: &HeaderMap, who_html: &str) -> String {
    let (tone, initial, _) = composer_identity(headers);
    format!(
        r#"<div class="ag-composer__head"><span class="avatar ag-avatar ag-tone-{tone}" aria-hidden="true">{initial}</span><div class="ag-composer__who">{who}</div><span class="pill pill-neutral ag-composer__badge">Markdown</span></div>"#,
        tone = tone,
        initial = initial,
        who = who_html,
    )
}

fn markdown_hint() -> &'static str {
    r#"<div class="ag-md-hint"><code>**bold**</code><code>_italic_</code><code>`code`</code><code>&gt; quote</code><span>@name to mention</span></div>"#
}

fn render_reply_quote_fields(quote: Option<&Post>) -> String {
    let Some(quote) = quote else {
        return String::new();
    };
    format!(
        r##"<input type="hidden" name="quote_post_id" value="{pid}">
      <blockquote class="ag-composer__quote">
        <p class="ag-composer__quote-by">Quoting {author}<a href="/t/{tid}#reply">Remove</a></p>
        <p class="ag-composer__quote-body">{body}</p>
      </blockquote>"##,
        pid = esc(&quote.id),
        tid = esc(&quote.thread_id),
        author = esc(&quote.author_email),
        body = esc(&quote.body_md),
    )
}

async fn load_quoted_posts(
    state: &AppState,
    thread_id: &str,
    posts: &[Post],
) -> Result<HashMap<String, Post>, AppError> {
    let mut out = HashMap::new();
    let mut seen = HashSet::new();
    for p in posts {
        if p.quoted_post_id.is_empty() || !seen.insert(p.quoted_post_id.as_str()) {
            continue;
        }
        if let Some(quoted) = state
            .store
            .get_post(&p.quoted_post_id)
            .await?
            .filter(|qp| qp.thread_id == thread_id)
        {
            out.insert(quoted.id.clone(), quoted);
        }
    }
    Ok(out)
}

fn render_quote_block(post: &Post, quoted_posts: &HashMap<String, Post>) -> String {
    if post.quoted_post_id.is_empty() {
        return String::new();
    }
    let Some(quoted) = quoted_posts.get(&post.quoted_post_id) else {
        return String::new();
    };
    format!(
        r#"<blockquote class="post-quote">
  <p class="post-quote__by">{author} wrote:</p>
  <p>{body}</p>
</blockquote>"#,
        author = esc(&quoted.author_email),
        body = esc(&quoted.body_md),
    )
}

fn extract_mentions(body: &str) -> Vec<String> {
    let bytes = body.as_bytes();
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'@' || (i > 0 && is_mention_char(bytes[i - 1])) {
            i += 1;
            continue;
        }
        let start = i + 1;
        let mut end = start;
        while end < bytes.len() && is_mention_char(bytes[end]) {
            end += 1;
        }
        while end > start && matches!(bytes[end - 1], b'.' | b'-' | b'_') {
            end -= 1;
        }
        if end > start {
            if let Some(name) = normalize_mention_name(&body[start..end]) {
                if seen.insert(name.clone()) {
                    out.push(name);
                }
            }
        }
        i = end.max(start);
    }
    out
}

fn notify_reply(state: &AppState, thread: &Thread, post: &Post, recipient_subjects: &[String]) {
    let Some(klaxon) = &state.klaxon else {
        return;
    };

    let actor = post_author_label(post);
    let title = format!("{actor} 回复了「{}」", truncate_chars(&thread.title, 80));
    let body = compact_snippet(&post.body_md, 180);
    let url = forum_thread_url(&thread.id);
    for recipient_sub in recipient_subjects
        .iter()
        .take(MAX_KLAXON_RECIPIENTS_PER_REPLY)
    {
        klaxon.notify("agora", recipient_sub, &title, &body, &url);
    }
}

fn notify_accepted_answer(
    state: &AppState,
    thread: &Thread,
    accepted_post: &Post,
    actor_sub: &str,
    actor_email: &str,
) {
    if accepted_post.author_sub == actor_sub {
        return;
    }
    let Some(klaxon) = &state.klaxon else {
        return;
    };

    let actor = author_label(actor_sub, actor_email);
    let title = format!("{actor} 采纳了你的回答");
    let body = truncate_chars(&thread.title, 180);
    let url = forum_thread_url(&thread.id);
    klaxon.notify("agora", &accepted_post.author_sub, &title, &body, &url);
}

fn post_author_label(post: &Post) -> &str {
    author_label(&post.author_sub, &post.author_email)
}

fn author_label<'a>(sub: &'a str, email: &'a str) -> &'a str {
    if email.trim().is_empty() {
        sub
    } else {
        email
    }
}

fn forum_thread_url(thread_id: &str) -> String {
    format!("https://forum.w33d.xyz/t/{thread_id}")
}

fn compact_snippet(s: &str, max_chars: usize) -> String {
    let compact = s.split_whitespace().collect::<Vec<_>>().join(" ");
    truncate_chars(&compact, max_chars)
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    let mut chars = s.chars();
    let mut out: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        out.push_str("...");
    }
    out
}

fn normalize_mention_name(raw: &str) -> Option<String> {
    crate::store::normalize_activity_alias(raw)
}

fn is_mention_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')
}

/// Render the admin moderation toolbar for a thread: toggle lock, toggle pin, move to another
/// category, and delete the whole thread. Every action is a CSRF-guarded POST into the
/// group-gated `/admin` subtree. Category options are HTML-escaped.
pub(crate) fn render_admin_thread_toolbar(
    thread: &Thread,
    categories: &[crate::model::Category],
    csrf: &str,
) -> String {
    let lock_label = if thread.locked { "Unlock" } else { "Lock" };
    let pin_label = if thread.pinned { "Unpin" } else { "Pin" };
    let mut options = String::new();
    for c in categories {
        let sel = if c.id == thread.category_id {
            " selected"
        } else {
            ""
        };
        options.push_str(&format!(
            r#"<option value="{id}"{sel}>{name}</option>"#,
            id = esc(&c.id),
            sel = sel,
            name = esc(&c.name),
        ));
    }
    format!(
        r#"<div class="owner-actions admin-toolbar ag-modbar">
  <form class="inline-form" method="post" action="/admin/threads/{tid}/lock">
    <input type="hidden" name="csrf" value="{csrf}">
    <button class="btn btn-secondary btn-sm" type="submit">{lock_label}</button>
  </form>
  <form class="inline-form" method="post" action="/admin/threads/{tid}/pin">
    <input type="hidden" name="csrf" value="{csrf}">
    <button class="btn btn-secondary btn-sm" type="submit">{pin_label}</button>
  </form>
  <form class="inline-form" method="post" action="/admin/threads/{tid}/move">
    <input type="hidden" name="csrf" value="{csrf}">
    <select name="category" aria-label="Move to category">{options}</select>
    <button class="btn btn-secondary btn-sm" type="submit">Move</button>
  </form>
  <form class="inline-form" method="post" action="/admin/threads/{tid}/delete" onsubmit="return confirm('Delete this thread and all replies as admin? This cannot be undone.');">
    <input type="hidden" name="csrf" value="{csrf}">
    <button class="btn btn-danger btn-sm" type="submit">Delete (admin)</button>
  </form>
</div>"#,
        tid = esc(&thread.id),
        csrf = esc(csrf),
        lock_label = lock_label,
        pin_label = pin_label,
        options = options,
    )
}

/// Render the shared edit-form card (thread or reply). `title_value` is `Some` for a thread
/// (renders a Title input) and `None` for a reply (body only). Every interpolated value is
/// HTML-escaped.
fn render_edit_form(
    heading: &str,
    action: &str,
    csrf: &str,
    title_value: Option<&str>,
    body_value: &str,
    cancel_href: &str,
    headers: &HeaderMap,
) -> String {
    let title_input = match title_value {
        Some(v) => format!(
            r#"<div class="field">
      <label class="label" for="ed-title">Title</label>
      <input id="ed-title" class="input ag-title-input" type="text" name="title" maxlength="{maxt}" required value="{value}">
    </div>"#,
            maxt = MAX_TITLE,
            value = esc(v),
        ),
        None => String::new(),
    };
    format!(
        r#"<nav class="crumbs"><a href="/">Home</a><span class="crumbs__sep">/</span><span>{heading}</span></nav>
<div class="page-head"><div><h1>{heading}</h1></div></div>
<section class="card ag-composer ag-composer--edit">
  <form class="ag-form" method="post" action="{action}">
    <input type="hidden" name="csrf" value="{csrf}">
    {head}
    <div class="ag-composer__fields">
      {title_input}
      <div class="field">
        <label class="label" for="ed-body">Body <span class="muted">(Markdown supported)</span></label>
        <textarea id="ed-body" name="body" rows="10" required>{body}</textarea>
      </div>
    </div>
    <div class="ag-composer__bar">
      {hint}
      <div class="ag-composer__actions">
      <a class="btn btn-secondary" href="{cancel}">Cancel</a>
      <button class="btn btn-primary" type="submit">Save changes</button>
      </div>
    </div>
  </form>
</section>"#,
        heading = esc(heading),
        action = action,
        csrf = esc(csrf),
        head = render_composer_head(headers, &format!(r#"<b>{}</b>"#, esc(heading))),
        title_input = title_input,
        body = esc(body_value),
        hint = markdown_hint(),
        cancel = cancel_href,
    )
}

async fn load_reading_states(
    state: &AppState,
    viewer_sub: Option<&str>,
    threads: &[Thread],
) -> Result<HashMap<String, ThreadReadingState>, AppError> {
    let Some(viewer_sub) = viewer_sub else {
        return Ok(HashMap::new());
    };
    let thread_ids: Vec<String> = threads.iter().map(|thread| thread.id.clone()).collect();
    state
        .store
        .thread_reading_states(viewer_sub, &thread_ids)
        .await
        .map_err(Into::into)
}

/// Render a list of threads as rows. When `cat_names` is provided (home page) each row also
/// names its category; otherwise (category page) it is omitted.
fn render_thread_rows(
    threads: &[Thread],
    now: i64,
    cat_names: Option<&HashMap<&str, &str>>,
    counts: Option<&HashMap<String, i64>>,
    question_categories: &HashSet<&str>,
    reading_states: &HashMap<String, ThreadReadingState>,
) -> String {
    render_thread_rows_with_reasons(
        threads,
        now,
        cat_names,
        counts,
        question_categories,
        reading_states,
        None,
    )
}

fn render_for_you_rows(
    threads: &[Thread],
    now: i64,
    cat_names: &HashMap<&str, &str>,
    question_categories: &HashSet<&str>,
    reading_states: &HashMap<String, ThreadReadingState>,
    reasons: &HashMap<String, ForYouReason>,
) -> String {
    if threads.is_empty() {
        return r#"<div class="empty ag-for-you-empty"><div class="empty__ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m12 3 1.7 5.3L19 10l-5.3 1.7L12 17l-1.7-5.3L5 10l5.3-1.7L12 3z"/><path d="M19 15v4"/><path d="M21 17h-4"/></svg></div><h3>Your personal feed is ready when you are.</h3><p>Watch or Follow a thread, bookmark a post, join a conversation, or begin reading. Muted threads stay out.</p><a class="btn btn-primary btn-sm" href="/">Explore Latest</a></div>"#.to_string();
    }
    render_thread_rows_with_reasons(
        threads,
        now,
        Some(cat_names),
        None,
        question_categories,
        reading_states,
        Some(reasons),
    )
}

fn render_thread_rows_with_reasons(
    threads: &[Thread],
    now: i64,
    cat_names: Option<&HashMap<&str, &str>>,
    counts: Option<&HashMap<String, i64>>,
    question_categories: &HashSet<&str>,
    reading_states: &HashMap<String, ThreadReadingState>,
    reasons: Option<&HashMap<String, ForYouReason>>,
) -> String {
    if threads.is_empty() {
        return r#"<div class="empty"><div class="empty__ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg></div><h3>No threads yet — start the conversation.</h3><p>Every thread supports Markdown, reactions and @mentions.</p><a class="btn btn-primary btn-sm" href="/new">New thread</a></div>"#.to_string();
    }
    let mut out = String::new();
    for t in threads {
        let reading = reading_states.get(&t.id);
        let (href, reading_badge) = match reading {
            Some(state) if state.started && state.unread_count > 0 => (
                format!("/t/{}?resume=1#thread-resume", esc(&t.id)),
                format!(
                    r#"<span class="ag-row__continue">Continue · {count} new</span>"#,
                    count = state.unread_count,
                ),
            ),
            _ => (format!("/t/{}", esc(&t.id)), String::new()),
        };
        let is_question = question_categories.contains(t.category_id.as_str());
        let cat_part = match cat_names {
            Some(map) => {
                let name = map.get(t.category_id.as_str()).copied().unwrap_or("—");
                format!(
                    r#"<span class="ag-chip ag-tone-{tone} thread-row__cat">{name}</span>"#,
                    tone = ag_tone(&t.category_id),
                    name = esc(name),
                )
            }
            None => String::new(),
        };
        let mut glyphs = String::new();
        if t.pinned {
            glyphs.push_str(r#"<svg class="ag-glyph ag-glyph--pin" role="img" aria-label="Pinned" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 17v5"/><path d="M5 17h14"/><path d="m7 9 5-5 5 5"/><path d="M8 14h8"/></svg>"#);
        }
        if t.locked {
            glyphs.push_str(r#"<svg class="ag-glyph ag-glyph--lock" role="img" aria-label="Locked" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>"#);
        }
        if !t.accepted_post_id.is_empty() {
            glyphs.push_str(r#"<svg class="ag-glyph ag-glyph--answered" role="img" aria-label="Answered" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><path d="m9 11 3 3L22 4"/></svg>"#);
        }
        let answer_state = if is_question {
            if t.accepted_post_id.is_empty() {
                r#"<span class="ag-chip ag-answer-state ag-answer-state--open">Needs answer</span>"#
                    .to_string()
            } else {
                r#"<span class="ag-chip ag-answer-state ag-answer-state--done">Answered</span>"#
                    .to_string()
            }
        } else {
            String::new()
        };
        let personal_reason = reasons
            .and_then(|reasons| reasons.get(&t.id))
            .map(|reason| {
                format!(
                    r#"<span class="ag-for-you-reason" data-for-you-reason="{key}">{label}</span>"#,
                    key = reason.key(),
                    label = esc(reason.label()),
                )
            })
            .unwrap_or_default();
        let replies = counts
            .and_then(|map| map.get(&t.id))
            .map(|count| {
                format!(
                    r#"<span class="ag-row__replies" title="{label}">{replies}</span>"#,
                    label = esc(&replies_label(*count)),
                    replies = (*count - 1).max(0),
                )
            })
            .unwrap_or_default();
        let pinned_class = if t.pinned { " ag-row--pinned" } else { "" };
        out.push_str(&format!(
            r#"<a class="thread-row ag-row{pinned}" href="{href}">
  <span class="avatar ag-avatar ag-tone-{tone}" aria-hidden="true">{initial}</span>
  <span class="thread-row__main">
    <span class="thread-row__title">{glyphs}<span class="ag-title">{title}</span></span>
    <span class="thread-row__sub">{personal_reason}{cat}{answer_state}{reading_badge}<span class="ag-row__by">started by {author}</span></span>
  </span>
  <span class="ag-row__side">{replies}<span class="thread-row__time" title="{abs}">{when}</span></span>
</a>"#,
            href = href,
            pinned = pinned_class,
            tone = ag_tone(&t.author_sub),
            initial = esc(&ag_initial(&t.author_email)),
            glyphs = glyphs,
            title = esc(&t.title),
            cat = cat_part,
            personal_reason = personal_reason,
            answer_state = answer_state,
            reading_badge = reading_badge,
            author = esc(&t.author_email),
            replies = replies,
            abs = esc(&fmt_ts(t.last_at)),
            when = esc(&rel_time(t.last_at, now)),
        ));
    }
    out
}

/// Render the per-thread extractive summary card, or an empty string when the thread is too
/// small/short to be worth summarising. Sentences come from [`thread_summary`] (local,
/// deterministic, no LLM) and are HTML-escaped before display.
fn render_summary(posts: &[Post]) -> String {
    if posts.len() < SUMMARY_MIN_POSTS {
        return String::new();
    }
    let words: usize = posts
        .iter()
        .map(|p| p.body_md.split_whitespace().count())
        .sum();
    if words < SUMMARY_MIN_WORDS {
        return String::new();
    }
    let sentences = thread_summary(posts, SUMMARY_SENTENCES);
    if sentences.len() < 2 {
        return String::new();
    }
    let items: String = sentences
        .iter()
        .map(|s| format!("<li>{}</li>", esc(s)))
        .collect();
    format!(
        r#"<section class="card pad summary ag-insight">
  <h2 class="section__title"><svg class="ag-insight__glyph" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m12 3 1.7 5.3L19 10l-5.3 1.7L12 17l-1.7-5.3L5 10l5.3-1.7L12 3z"/><path d="M19 15v4"/><path d="M21 17h-4"/></svg>Thread summary <span class="badge badge-op">Auto</span></h2>
  <p class="muted summary__note">Top sentences from posts visible on this page — generated locally, no AI service.</p>
  <ul class="summary__list">{items}</ul>
</section>"#,
        items = items,
    )
}

/// Reorder a thread's posts for display: keep the original post (oldest, index 0) first, then
/// float the accepted reply (if `accepted_post_id` names one that exists and is NOT the OP) to
/// the second slot, leaving the remaining replies in their natural order. Returns a fresh
/// `Vec<Post>` — the stored order is never mutated.
pub(crate) fn order_posts_accepted_first(posts: &[Post], accepted_post_id: &str) -> Vec<Post> {
    let mut ordered: Vec<Post> = posts.to_vec();
    if accepted_post_id.is_empty() {
        return ordered;
    }
    // Only replies (index >= 1) can be accepted; never move the OP.
    if let Some(pos) = ordered
        .iter()
        .position(|p| p.id == accepted_post_id)
        .filter(|&pos| pos >= 1)
    {
        let accepted = ordered.remove(pos);
        ordered.insert(1, accepted);
    }
    ordered
}

/// Resolve the requested reply page from the query cursors. `latest` wins, then the exact activity
/// target (`around`), then `before`/`after`; malformed cursors fall back to the oldest page.
fn resolve_anchor(q: &ThreadQuery) -> ReplyAnchor {
    if q.latest
        .as_deref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
    {
        return ReplyAnchor::Latest;
    }
    if let Some((ts, id)) = parse_cursor(q.around.as_deref()) {
        return ReplyAnchor::Around(ts, id);
    }
    if let Some((ts, id)) = parse_cursor(q.before.as_deref()) {
        return ReplyAnchor::Before(ts, id);
    }
    if let Some((ts, id)) = parse_cursor(q.after.as_deref()) {
        return ReplyAnchor::After(ts, id);
    }
    ReplyAnchor::First
}

/// Parse a `<created_at>_<id>` keyset cursor. `created_at` is a plain integer that never contains
/// `_`, so we split on the FIRST `_`; the post id (`p_<hex>`) keeps its own underscore intact.
/// Returns `None` for a missing/blank/malformed cursor (which falls back to the default page).
fn parse_cursor(cursor: Option<&str>) -> Option<(i64, String)> {
    let (ts, id) = cursor?.trim().split_once('_')?;
    let ts: i64 = ts.parse().ok()?;
    if id.is_empty() {
        return None;
    }
    Some((ts, id.to_string()))
}

/// Render the reply-list pagination nav: "Load older" (`?before=`) when older replies exist,
/// "Load newer" (`?after=`) when newer replies exist, and a "Jump to latest" (`?latest=1`) link
/// whenever the newest page is not already shown. Returns an empty string when the whole reply
/// list fits on one page (so small threads render exactly as before). Every value is HTML-escaped.
fn render_reply_pagination(
    thread_id: &str,
    older: Option<&(i64, String)>,
    newer: Option<&(i64, String)>,
    show_latest: bool,
) -> String {
    let mut links = String::new();
    if let Some((ts, id)) = older {
        links.push_str(&format!(
            r#"<a class="btn btn-secondary btn-sm" href="/t/{tid}?before={ts}_{cid}">← Load older</a>"#,
            tid = esc(thread_id),
            ts = ts,
            cid = esc(id),
        ));
    }
    if let Some((ts, id)) = newer {
        links.push_str(&format!(
            r#"<a class="btn btn-secondary btn-sm" href="/t/{tid}?after={ts}_{cid}">Load newer →</a>"#,
            tid = esc(thread_id),
            ts = ts,
            cid = esc(id),
        ));
    }
    if show_latest {
        links.push_str(&format!(
            r#"<a class="btn btn-ghost btn-sm" href="/t/{tid}?latest=1">Jump to latest</a>"#,
            tid = esc(thread_id),
        ));
    }
    if links.is_empty() {
        String::new()
    } else {
        format!(r#"<nav class="pagination">{links}</nav>"#)
    }
}

/// Render the reaction button row for a post: one CSRF-guarded toggle form per allowed kind (in
/// [`REACTION_KINDS`] order), each showing the glyph and its live count. The viewer's own active
/// reactions carry `is-mine`. Every value is HTML-escaped.
fn render_reactions(
    thread_id: &str,
    post_id: &str,
    csrf: &str,
    counts: &[ReactionCount],
) -> String {
    let mut buttons = String::new();
    for (kind, glyph) in REACTION_KINDS {
        let hit = counts.iter().find(|c| c.kind == *kind);
        let count = hit.map(|c| c.count).unwrap_or(0);
        let mine = hit.map(|c| c.mine).unwrap_or(false);
        let mine_class = if mine { " is-mine" } else { "" };
        buttons.push_str(&format!(
            r##"<form class="inline-form" method="post" action="/t/{tid}/p/{pid}/react" data-wire data-wire-target="#post-{pid}" data-wire-err="Could not save your reaction">
    <input type="hidden" name="csrf" value="{csrf}">
    <input type="hidden" name="kind" value="{kind}">
    <button class="reaction{mine}" type="submit" aria-pressed="{pressed}" title="{kind} reaction">
      <span class="reaction__glyph" aria-hidden="true">{glyph}</span>
      <span class="reaction__count">{count}</span>
    </button>
  </form>"##,
            tid = esc(thread_id),
            pid = esc(post_id),
            csrf = esc(csrf),
            kind = esc(kind),
            mine = mine_class,
            pressed = if mine { "true" } else { "false" },
            glyph = esc(glyph),
            count = count,
        ));
    }
    format!(r#"<div class="reactions">{buttons}</div>"#)
}

/// Render the posts of a thread. The first post is flagged as the original post (`is-op`);
/// each body is rendered through the markdown sanitiser. A REPLY (never the original post —
/// that is edited/deleted via the thread controls) gets inline Edit/Delete controls when
/// `viewer` is its author. Every post shows the reaction row; the reply marked as the accepted
/// answer is wrapped once in a labelled Solution region, and when `can_accept` (thread author or
/// admin) each reply gets a mark/unmark-accepted control. A post with `quoted_post_id` renders an
/// escaped quote block above its own markdown body when the referenced post still exists here.
#[allow(clippy::too_many_arguments)]
fn render_posts(
    posts: &[Post],
    now: i64,
    viewer: Option<&str>,
    is_admin: bool,
    thread_id: &str,
    csrf: &str,
    accepted_post_id: &str,
    can_manage_answer: bool,
    is_question: bool,
    can_reply: bool,
    latest_post_id: &str,
    first_unread_post_id: Option<&str>,
    reactions: &HashMap<String, Vec<ReactionCount>>,
    bookmarks: &HashMap<String, Bookmark>,
    quoted_posts: &HashMap<String, Post>,
) -> String {
    if posts.is_empty() {
        return r#"<span id="thread-latest" class="ag-thread-latest-anchor" aria-hidden="true"></span><div class="empty">This thread has no posts.</div>"#.to_string();
    }
    let empty_counts: Vec<ReactionCount> = Vec::new();
    let mut out = String::new();
    for (i, p) in posts.iter().enumerate() {
        if first_unread_post_id == Some(p.id.as_str()) {
            out.push_str(
                r#"<div id="thread-resume" class="ag-first-unread" role="separator"><span>First unread</span></div>"#,
            );
        }
        let is_accepted = i > 0 && !accepted_post_id.is_empty() && p.id == accepted_post_id;
        let latest_anchor = if p.id == latest_post_id {
            r#"<span id="thread-latest" class="ag-thread-latest-anchor" aria-hidden="true"></span>"#
        } else {
            ""
        };
        let op = if i == 0 {
            " is-op"
        } else if is_accepted {
            " is-accepted"
        } else {
            ""
        };
        let tag = if i == 0 {
            r#"<span class="badge badge-op">Original post</span>"#.to_string()
        } else {
            String::new()
        };
        // Own-reply controls: not on the original post (i == 0), only for the author.
        let owner_controls = if i > 0 && viewer == Some(p.author_sub.as_str()) {
            format!(
                r#"<a class="btn btn-ghost btn-sm" href="/t/{tid}/p/{pid}/edit">Edit</a>
  <form class="inline-form" method="post" action="/t/{tid}/p/{pid}/delete" onsubmit="return confirm('Delete this reply? This cannot be undone.');">
    <input type="hidden" name="csrf" value="{csrf}">
    <button class="btn btn-danger btn-sm" type="submit">Delete</button>
  </form>"#,
                tid = esc(thread_id),
                pid = esc(&p.id),
                csrf = esc(csrf),
            )
        } else {
            String::new()
        };
        // Mark/unmark accepted: replies only (i > 0), gated to the thread author + admin.
        // Question categories can accept any reply. A historical accepted answer in a discussion
        // remains readable and removable, but the discussion cannot select a new one.
        let accept_control = if i > 0 && can_manage_answer && (is_question || is_accepted) {
            let label = if is_accepted {
                "Remove solution"
            } else {
                "Accept answer"
            };
            let action = if is_accepted { "clear" } else { "accept" };
            format!(
                r#"<form class="inline-form" method="post" action="/t/{tid}/accept">
    <input type="hidden" name="csrf" value="{csrf}">
    <input type="hidden" name="action" value="{action}">
    <input type="hidden" name="post_id" value="{pid}">
    <button class="btn btn-secondary btn-sm" type="submit">{label}</button>
  </form>"#,
                tid = esc(thread_id),
                pid = esc(&p.id),
                csrf = esc(csrf),
                action = action,
                label = label,
            )
        } else {
            String::new()
        };
        let quote_control = if can_reply {
            format!(
                r##"<a class="btn btn-ghost btn-sm" href="/t/{tid}?quote={pid}#reply">Quote</a>"##,
                tid = esc(thread_id),
                pid = esc(&p.id),
            )
        } else {
            String::new()
        };
        let bookmark_control = if viewer.is_none() {
            String::new()
        } else if let Some(bookmark) = bookmarks.get(&p.id) {
            let state = if bookmark.remind_at.is_some_and(|at| at <= now) {
                " · Due"
            } else if bookmark.remind_at.is_some() {
                " · Scheduled"
            } else {
                ""
            };
            format!(
                r#"<a class="btn btn-ghost btn-sm ag-post-bookmark is-saved" href="/bookmarks/{pid}/edit" aria-label="Edit saved bookmark{state}">Saved{state}</a>"#,
                pid = esc(&p.id),
                state = state,
            )
        } else {
            format!(
                r#"<form class="inline-form" method="post" action="/t/{tid}/p/{pid}/bookmark"><input type="hidden" name="csrf" value="{csrf}"><button class="btn btn-ghost btn-sm ag-post-bookmark" type="submit" aria-label="Bookmark this post">Bookmark</button></form>"#,
                tid = esc(thread_id),
                pid = esc(&p.id),
                csrf = esc(csrf),
            )
        };
        // Admins can remove any reply. The OP owns the thread identity and must be removed through
        // Delete thread, so a reply by another author is never silently promoted into editable OP.
        let admin_controls = if is_admin && i > 0 {
            format!(
                r#"<form class="inline-form" method="post" action="/admin/posts/{pid}/delete" onsubmit="return confirm('Delete this post as admin? This cannot be undone.');">
    <input type="hidden" name="csrf" value="{csrf}">
    <button class="btn btn-danger btn-sm" type="submit">Delete (admin)</button>
  </form>"#,
                pid = esc(&p.id),
                csrf = esc(csrf),
            )
        } else {
            String::new()
        };
        let controls = if quote_control.is_empty()
            && bookmark_control.is_empty()
            && owner_controls.is_empty()
            && accept_control.is_empty()
            && admin_controls.is_empty()
        {
            String::new()
        } else {
            format!(
                r#"<div class="owner-actions post__actions">{quote_control}{bookmark_control}{owner_controls}{accept_control}{admin_controls}</div>"#,
            )
        };
        let counts = reactions.get(&p.id).unwrap_or(&empty_counts);
        let reactions_html = render_reactions(thread_id, &p.id, csrf, counts);
        let quote_html = render_quote_block(p, quoted_posts);
        let post_html = format!(
            r##"<article id="post-{pid}" class="post{op}">{latest_anchor}
  <div class="ag-post-rail"><span class="avatar ag-avatar ag-tone-{tone}" aria-hidden="true">{initial}</span></div>
  <div class="ag-post-main">
    <header class="post__meta">
      <span class="post__author">{author}</span>
      <span class="post__dot">·</span>
      <a class="ag-permalink" href="#post-{pid}"><time class="post__time" title="{abs}">{ago}</time></a>
      {tag}
    </header>
    <div class="markdown">{quote}{body}</div>
    <footer class="ag-post-foot">{reactions}{controls}</footer>
  </div>
</article>"##,
            pid = esc(&p.id),
            op = op,
            latest_anchor = if is_accepted { "" } else { latest_anchor },
            tone = ag_tone(&p.author_sub),
            initial = esc(&ag_initial(&p.author_email)),
            author = esc(&p.author_email),
            abs = esc(&fmt_ts(p.created_at)),
            ago = esc(&rel_time(p.created_at, now)),
            tag = tag,
            quote = quote_html,
            body = markdown::render(&p.body_md),
            reactions = reactions_html,
            controls = controls,
        );
        if is_accepted {
            out.push_str(&format!(
                r#"<section class="ag-solution" aria-labelledby="solution-heading-{pid}">{latest_anchor}
  <header class="ag-solution__head">
    <span class="ag-solution__eyebrow">Solution</span>
    <h2 id="solution-heading-{pid}">Accepted answer</h2>
  </header>
  {post}
</section>"#,
                pid = esc(&p.id),
                latest_anchor = latest_anchor,
                post = post_html,
            ));
        } else {
            out.push_str(&post_html);
        }
    }
    out
}

/// Build an `Html` response, attaching a `Set-Cookie` header when a fresh CSRF cookie is due.
pub(crate) fn html_response(html: String, set_cookie: Option<String>) -> Response {
    let mut resp = Html(html).into_response();
    if let Some(cookie) = set_cookie {
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            resp.headers_mut().insert(header::SET_COOKIE, value);
        }
    }
    resp
}

/// A 303 See Other redirect (post/redirect/get).
pub(crate) fn redirect_to(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, location.to_string())],
    )
        .into_response()
}

/// True when the caller (a `fetch()` from the enhanced thread page) asked for a JSON reply via
/// the `Accept` header. A plain form POST (no-JS) never sets this, so it keeps the 303 redirect —
/// the seam that lets the optimistic JSON replies live ALONGSIDE the unchanged form routes.
pub(crate) fn wants_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|a| a.contains("application/json"))
        .unwrap_or(false)
}
