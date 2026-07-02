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
use crate::handlers::{email_display, esc, fmt_ts, rel_time, render_page, replies_label};
use crate::model::{Post, ReactionCount, Thread};
use crate::store::{ReplyAnchor, ThreadSort};
use crate::{markdown, new_id, now_secs, AppState};

/// Most-recent threads shown on the home page.
const RECENT_LIMIT: i64 = 20;
/// Replies rendered per keyset page on the thread view. A large thread renders (and reaction-
/// queries) only one page of replies at a time; the OP is always pinned on top, separately.
pub const REPLIES_PER_PAGE: i64 = 20;
/// Threads listed on a category page.
const CATEGORY_LIMIT: i64 = 200;
/// Recent mentions shown on the home page for the signed-in viewer.
const MENTION_LIMIT: i64 = 5;
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

    let mut cats_html = String::new();
    for c in &categories {
        let count = state.store.count_threads(&c.id).await?;
        cats_html.push_str(&format!(
            r#"<a class="cat-card" href="/c/{id}">
  <span class="cat-card__name">{name}</span>
  <span class="cat-card__meta">{count} {tw}</span>
</a>"#,
            id = esc(&c.id),
            name = esc(&c.name),
            count = count,
            tw = if count == 1 { "thread" } else { "threads" },
        ));
    }
    if cats_html.is_empty() {
        cats_html = r#"<div class="empty">No categories yet.</div>"#.to_string();
    }

    let recent_html = render_thread_rows(&recent, now, Some(&cat_names));
    let mentions_html = render_mentions_panel(&state, &headers).await?;
    let thread_controls = render_thread_list_controls("/", &q, viewer_sub.is_some());

    let content = format!(
        r#"<div class="page-head">
  <div>
    <h1>Forum</h1>
    <p class="muted">Discussions across the keep — sign-in is handled by Keystone SSO.</p>
  </div>
  <a class="btn btn-primary" href="/new">New thread</a>
</div>
<section class="section">
  <h2 class="section__title">Categories</h2>
  <div class="cat-grid">{cats}</div>
</section>
{mentions}
<section class="section">
  <h2 class="section__title">{thread_title}</h2>
  {controls}
  <div class="thread-list">{recent}</div>
</section>"#,
        cats = cats_html,
        mentions = mentions_html,
        thread_title = if q.subscribed_only() {
            "Subscribed threads"
        } else {
            "Recent activity"
        },
        controls = thread_controls,
        recent = recent_html,
    );

    Ok(Html(render_page(
        "Forum",
        &email_display(&headers),
        &content,
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
    let threads = if q.subscribed_only() && viewer_sub.is_none() {
        Vec::new()
    } else {
        state
            .store
            .list_threads(
                Some(&id),
                q.sort(),
                subscribed_subject(&q, viewer_sub.as_deref()),
                CATEGORY_LIMIT,
                now,
            )
            .await?
    };

    let crumbs = format!(
        r#"<nav class="crumbs"><a href="/">Home</a><span class="crumbs__sep">/</span><span>{name}</span></nav>"#,
        name = esc(&category.name),
    );
    let list = render_thread_rows(&threads, now, None);
    let controls = render_thread_list_controls(
        &format!("/c/{}", esc(&category.id)),
        &q,
        viewer_sub.is_some(),
    );

    let content = format!(
        r#"{crumbs}
<div class="page-head">
  <div>
    <h1>{name}</h1>
    <p class="muted">{count} {tw} in this category.</p>
  </div>
  <a class="btn btn-primary" href="/new?cat={id}">New thread</a>
</div>
<section class="section">
  {controls}
  <div class="thread-list">{list}</div>
</section>"#,
        crumbs = crumbs,
        name = esc(&category.name),
        count = threads.len(),
        tw = if threads.len() == 1 {
            "thread"
        } else {
            "threads"
        },
        id = esc(&category.id),
        controls = controls,
        list = list,
    );

    Ok(Html(render_page(
        &category.name,
        &email_display(&headers),
        &content,
    )))
}

// ===========================================================================
// GET /t/{id} — a thread: original post + replies (markdown) + reply form
// ===========================================================================

/// Keyset cursor + page anchor for the thread view's reply list. All optional; a bare
/// `GET /t/{id}` shows the first (oldest) page. `?before=<created_at>_<id>` pages to older
/// replies, `?after=<created_at>_<id>` to newer, and `?latest=1` jumps to the newest page.
#[derive(Debug, Deserialize, Default)]
pub struct ThreadQuery {
    #[serde(default)]
    pub before: Option<String>,
    #[serde(default)]
    pub after: Option<String>,
    #[serde(default)]
    pub latest: Option<String>,
    #[serde(default)]
    pub quote: Option<String>,
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

    // Reply count (every post minus the original) — shown in the head + as the reply-list total.
    let post_count = state.store.count_posts(&id).await?;

    // Keyset-paginated reply list. The original post is pinned at the top on its own; the replies
    // below it are ONE page under the shared `(created_at, id)` idiom, so a huge thread renders —
    // and reaction-queries — only a page of replies at a time. We fetch one extra row to learn
    // whether more replies exist in the fetch direction, then normalise every page to ascending
    // (oldest→newest) display order.
    let op = state.store.first_post_in_thread(&id).await?;
    let op_id = op.as_ref().map(|p| p.id.clone()).unwrap_or_default();
    let anchor = resolve_anchor(&q);
    let mut fetched = state
        .store
        .replies_page(&id, &op_id, &anchor, REPLIES_PER_PAGE + 1)
        .await?;
    let has_more = fetched.len() as i64 > REPLIES_PER_PAGE;
    fetched.truncate(REPLIES_PER_PAGE as usize);
    let (replies, has_older, has_newer) = match anchor {
        // Ascending fetches: already oldest→newest. First has nothing older (OP is the floor);
        // After was reached from an older page, so older replies exist.
        ReplyAnchor::First => (fetched, false, has_more),
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

    // Display list: the original post first, then this page of replies.
    let mut posts: Vec<Post> = Vec::with_capacity(replies.len() + 1);
    if let Some(op_post) = op {
        posts.push(op_post);
    }
    posts.extend(replies);

    // The authenticated subject (if any) decides which edit/delete controls render.
    let viewer = auth::identity_subject(&headers);
    let is_admin = auth::is_admin(&headers);
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let subscription_action = if let Some(sub) = viewer.as_deref() {
        let subscribed = state.store.is_thread_subscribed(&thread.id, sub).await?;
        render_subscription_form(&thread.id, &csrf, subscribed)
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

    // Thread-level controls (edit title + original post, delete whole thread) — author only.
    let thread_actions = if viewer.as_deref() == Some(thread.author_sub.as_str()) {
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

    let summary_html = render_summary(&posts);

    // Display order: the original post stays first, then the accepted reply (if any), then the
    // rest in their natural oldest-first order. Reordering a clone never touches storage.
    let ordered = order_posts_accepted_first(&posts, &thread.accepted_post_id);
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

    // The "mark accepted" control is gated to the THREAD AUTHOR and to admins.
    let can_accept = viewer.as_deref() == Some(thread.author_sub.as_str()) || is_admin;

    let posts_html = render_posts(
        &ordered,
        now,
        viewer.as_deref(),
        is_admin,
        &thread.id,
        &csrf,
        &thread.accepted_post_id,
        can_accept,
        &reactions,
        &quoted_posts,
    );

    // A locked thread shows a notice instead of the reply form (admins still moderate above).
    let reply_form = if thread.locked {
        r#"<section class="card pad"><p class="muted">This thread is locked — no new replies.</p></section>"#
            .to_string()
    } else {
        let quote_fields = render_reply_quote_fields(quote_target.as_ref());
        format!(
            r#"<section id="reply" class="card pad">
  <h2 class="section__title">Reply</h2>
  <form class="form" method="post" action="/t/{tid}/reply">
    <input type="hidden" name="csrf" value="{csrf}">
    {quote}
    <label for="reply-body">Your reply <span class="muted">(Markdown supported)</span></label>
    <textarea id="reply-body" name="body" rows="5" placeholder="Write a reply…" required></textarea>
    <div class="form__actions">
      <button class="btn btn-primary" type="submit">Post reply</button>
    </div>
  </form>
</section>"#,
            tid = esc(&thread.id),
            csrf = esc(&csrf),
            quote = quote_fields,
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

    let content = format!(
        r#"{crumbs}
<div class="thread-head">
  <h1>{title}{badges}</h1>
  <p class="muted">Started by <strong>{author}</strong> · {when} · {replies}</p>
  {actions}
  {subscription}
  {admin_actions}
</div>
{summary}
<section class="posts">{posts}</section>
{pagination}
{reply}"#,
        crumbs = crumbs,
        title = esc(&thread.title),
        badges = badges,
        author = esc(&thread.author_email),
        when = esc(&fmt_ts(thread.created_at)),
        replies = esc(&replies_label(post_count)),
        actions = thread_actions,
        subscription = subscription_action,
        admin_actions = admin_actions,
        summary = summary_html,
        posts = posts_html,
        pagination = pagination,
        reply = reply_form,
    );

    let html = render_page(&thread.title, &email_display(&headers), &content);
    Ok(html_response(html, set_cookie))
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
    let categories = state.store.list_categories().await?;
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let selected = q.cat.unwrap_or_default();

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
        r#"<nav class="crumbs"><a href="/">Home</a><span class="crumbs__sep">/</span><span>New thread</span></nav>
<div class="page-head"><div><h1>New thread</h1></div></div>
<section class="card pad">
  <form class="form" method="post" action="/new">
    <input type="hidden" name="csrf" value="{csrf}">
    <label for="nt-cat">Category</label>
    <select id="nt-cat" name="category" required>{options}</select>
    <label for="nt-title">Title</label>
    <input id="nt-title" type="text" name="title" maxlength="{maxt}" placeholder="A short, descriptive title" required>
    <label for="nt-body">Body <span class="muted">(Markdown supported)</span></label>
    <textarea id="nt-body" name="body" rows="10" placeholder="Write the first post…" required></textarea>
    <div id="similar-box" class="similar" hidden>
      <div class="similar__head">Similar existing threads — is one of these your topic?</div>
      <ul id="similar-list" class="similar__list"></ul>
    </div>
    <div class="form__actions">
      <button class="btn btn-primary" type="submit">Create thread</button>
      <a class="btn btn-secondary" href="/">Cancel</a>
    </div>
  </form>
</section>
{script}"#,
        csrf = esc(&csrf),
        options = options,
        maxt = MAX_TITLE,
        script = SIMILAR_SCRIPT,
    );

    let html = render_page("New thread", &email_display(&headers), &content);
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
    state.store.create_thread(&thread, &first_post).await?;
    state
        .store
        .replace_mentions(
            &first_post.id,
            &thread.id,
            &extract_mentions(&first_post.body_md),
            first_post.created_at,
        )
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
    let quoted_post_id = match form.quote_post_id.trim().is_empty() {
        true => String::new(),
        false => {
            let quoted = state
                .store
                .get_post(form.quote_post_id.trim())
                .await?
                .filter(|p| p.thread_id == id)
                .ok_or_else(|| {
                    AppError::InvalidRequest("quoted post must belong to this thread".to_string())
                })?;
            quoted.id
        }
    };

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
    state.store.add_reply(&post).await?;
    state
        .store
        .replace_mentions(
            &post.id,
            &id,
            &extract_mentions(&post.body_md),
            post.created_at,
        )
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
    );
    let html = render_page("Edit thread", &email_display(&headers), &content);
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

    // The original post is the oldest post in the thread (first in display order).
    let posts = state.store.posts_in_thread(&id).await?;
    let op_id = posts
        .first()
        .map(|p| p.id.clone())
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
    );
    let html = render_page("Edit reply", &email_display(&headers), &content);
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
// POST /t/{tid}/accept — mark/unmark a reply as the accepted answer
// ===========================================================================

/// Form body for accepting an answer: the CSRF token + the reply's `post_id`. Authorisation
/// (thread author or admin) is checked against the gateway identity, never the form.
#[derive(Debug, Deserialize)]
pub struct AcceptForm {
    #[serde(default)]
    pub csrf: String,
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

    // The target must be a REPLY in this thread — never the original post (index 0).
    let posts = state.store.posts_in_thread(&tid).await?;
    let target = form.post_id.trim();
    if posts.first().map(|p| p.id == target).unwrap_or(false) {
        return Err(AppError::InvalidRequest(
            "the original post cannot be the accepted answer".to_string(),
        ));
    }
    if !posts.iter().any(|p| p.id == target) {
        return Err(AppError::NotFound("reply not found".to_string()));
    }

    // Toggle: re-accepting the currently accepted reply clears it; otherwise set it. Idempotent
    // (marking the same reply that is already accepted flips it off — a deliberate unmark).
    let new_accepted = if thread.accepted_post_id == target {
        ""
    } else {
        target
    };
    state.store.set_accepted_post(&tid, new_accepted).await?;
    tracing::info!(thread = tid, accepted = new_accepted, "accepted answer set");

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
// POST /t/{id}/subscribe — toggle current user's thread subscription
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct SubscribeForm {
    #[serde(default)]
    pub csrf: String,
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

    let subscribed = state
        .store
        .toggle_thread_subscription(&tid, &author.sub, now_secs())
        .await?;
    let actor = if author.email.is_empty() {
        &author.sub
    } else {
        &author.email
    };
    state.audit.emit(AuditEvent::info(
        if subscribed {
            "thread.subscribe"
        } else {
            "thread.unsubscribe"
        },
        actor,
        &tid,
        if subscribed {
            "subscribed"
        } else {
            "unsubscribed"
        },
    ));

    if wants_json(&headers) {
        return Ok(axum::Json(serde_json::json!({
            "ok": true,
            "thread_id": tid,
            "subscribed": subscribed,
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

fn render_thread_list_controls(action: &str, q: &ThreadListQuery, show_subscribed: bool) -> String {
    let sort = q.sort_key();
    let sub = q.subscribed_only();
    let filter_q = if sub { "&filter=subscribed" } else { "" };
    // Sort as tabs: real links (no-JS navigates + keeps the `?sort=` contract); the enhancement
    // script intercepts a click, fetches the same URL and swaps the `.thread-list` in place.
    let tab = |key: &str, label: &str| {
        let active = sort == key;
        format!(
            r#"<a class="tab{cls}" role="tab" aria-selected="{sel}" data-sort-tab="{key}" href="{action}?sort={key}{filter}">{label}</a>"#,
            cls = if active { " is-active" } else { "" },
            sel = if active { "true" } else { "false" },
            action = esc(action),
            key = key,
            filter = filter_q,
            label = label,
        )
    };
    // Subscribed filter as a toggle link that preserves the current sort.
    let filter = if show_subscribed {
        let (href, label, cls) = if sub {
            (
                format!("{}?sort={}", esc(action), sort),
                "Show all",
                "btn btn-secondary btn-sm",
            )
        } else {
            (
                format!("{}?sort={}&filter=subscribed", esc(action), sort),
                "Subscribed",
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
    format!(
        r#"<div class="thread-controls" data-thread-controls>
  <nav class="tabs sort-tabs" role="tablist" aria-label="Sort threads">{latest}{top}{hot}</nav>
  {filter}
</div>"#,
        latest = tab("latest", "Latest"),
        top = tab("top", "Top"),
        hot = tab("hot", "Hot"),
        filter = filter,
    )
}

async fn render_mentions_panel(state: &AppState, headers: &HeaderMap) -> Result<String, AppError> {
    let Some(username) = mention_username_from_headers(headers) else {
        return Ok(String::new());
    };
    let count = state.store.count_mentions_for_user(&username).await?;
    if count == 0 {
        return Ok(String::new());
    }
    let mentions = state
        .store
        .mentions_for_user(&username, MENTION_LIMIT)
        .await?;
    let mut rows = String::new();
    for mention in mentions {
        if let Some(thread) = state.store.get_thread(&mention.thread_id).await? {
            rows.push_str(&format!(
                r##"<a class="thread-row" href="/t/{tid}#post-{pid}">
  <span class="thread-row__main">
    <span class="thread-row__title">{title}</span>
    <span class="thread-row__sub">@{user} mentioned you</span>
  </span>
  <span class="thread-row__time">{when}</span>
</a>"##,
                tid = esc(&mention.thread_id),
                pid = esc(&mention.post_id),
                title = esc(&thread.title),
                user = esc(&mention.mentioned_username),
                when = esc(&fmt_ts(mention.created_at)),
            ));
        }
    }
    if rows.is_empty() {
        return Ok(String::new());
    }
    Ok(format!(
        r#"<section class="section mentions">
  <h2 class="section__title mentions__title">Mentions <span class="badge mention-badge">@{count}</span></h2>
  <div class="thread-list">{rows}</div>
</section>"#,
        count = count,
        rows = rows,
    ))
}

fn render_subscription_form(thread_id: &str, csrf: &str, subscribed: bool) -> String {
    let label = if subscribed {
        "Unsubscribe"
    } else {
        "Subscribe"
    };
    let class = if subscribed {
        "btn btn-secondary btn-sm"
    } else {
        "btn btn-ghost btn-sm"
    };
    format!(
        r#"<form class="inline-form subscription-form" method="post" action="/t/{tid}/subscribe">
  <input type="hidden" name="csrf" value="{csrf}">
  <button class="{class}" type="submit">{label}</button>
</form>"#,
        tid = esc(thread_id),
        csrf = esc(csrf),
        class = class,
        label = label,
    )
}

fn render_reply_quote_fields(quote: Option<&Post>) -> String {
    let Some(quote) = quote else {
        return String::new();
    };
    format!(
        r#"<input type="hidden" name="quote_post_id" value="{pid}">
    <div class="quote-preview">
      <blockquote>
        <p class="quote-preview__by">{author} wrote:</p>
        <p>{body}</p>
      </blockquote>
    </div>"#,
        pid = esc(&quote.id),
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

fn mention_username_from_headers(headers: &HeaderMap) -> Option<String> {
    auth::identity_email(headers)
        .and_then(|email| email.split('@').next().and_then(normalize_mention_name))
        .or_else(|| auth::identity_subject(headers).and_then(|sub| normalize_mention_name(&sub)))
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

fn normalize_mention_name(raw: &str) -> Option<String> {
    let s = raw.trim().trim_start_matches('@');
    if s.is_empty() || s.len() > 64 {
        return None;
    }
    if !s
        .bytes()
        .next()
        .map(|b| b.is_ascii_alphanumeric())
        .unwrap_or(false)
    {
        return None;
    }
    if !s.bytes().all(is_mention_char) {
        return None;
    }
    Some(s.to_ascii_lowercase())
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
        r#"<div class="owner-actions admin-toolbar">
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
) -> String {
    let title_input = match title_value {
        Some(v) => format!(
            r#"<label for="ed-title">Title</label>
    <input id="ed-title" type="text" name="title" maxlength="{maxt}" required value="{value}">"#,
            maxt = MAX_TITLE,
            value = esc(v),
        ),
        None => String::new(),
    };
    format!(
        r#"<nav class="crumbs"><a href="/">Home</a><span class="crumbs__sep">/</span><span>{heading}</span></nav>
<div class="page-head"><div><h1>{heading}</h1></div></div>
<section class="card pad">
  <form class="form" method="post" action="{action}">
    <input type="hidden" name="csrf" value="{csrf}">
    {title_input}
    <label for="ed-body">Body <span class="muted">(Markdown supported)</span></label>
    <textarea id="ed-body" name="body" rows="10" required>{body}</textarea>
    <div class="form__actions">
      <button class="btn btn-primary" type="submit">Save changes</button>
      <a class="btn btn-secondary" href="{cancel}">Cancel</a>
    </div>
  </form>
</section>"#,
        heading = esc(heading),
        action = action,
        csrf = esc(csrf),
        title_input = title_input,
        body = esc(body_value),
        cancel = cancel_href,
    )
}

/// Render a list of threads as rows. When `cat_names` is provided (home page) each row also
/// names its category; otherwise (category page) it is omitted.
fn render_thread_rows(
    threads: &[Thread],
    now: i64,
    cat_names: Option<&HashMap<&str, &str>>,
) -> String {
    if threads.is_empty() {
        return r#"<div class="empty">No threads yet — start the conversation.</div>"#.to_string();
    }
    let mut out = String::new();
    for t in threads {
        let cat_part = match cat_names {
            Some(map) => {
                let name = map.get(t.category_id.as_str()).copied().unwrap_or("—");
                format!("in <span class=\"thread-row__cat\">{}</span> · ", esc(name))
            }
            None => String::new(),
        };
        out.push_str(&format!(
            r#"<a class="thread-row" href="/t/{id}">
  <span class="thread-row__main">
    <span class="thread-row__title">{title}</span>
    <span class="thread-row__sub">{cat}started by {author}</span>
  </span>
  <span class="thread-row__time">{when}</span>
</a>"#,
            id = esc(&t.id),
            title = esc(&t.title),
            cat = cat_part,
            author = esc(&t.author_email),
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
        r#"<section class="card pad summary">
  <h2 class="section__title">Thread summary <span class="badge badge-op">Auto</span></h2>
  <p class="muted summary__note">Top sentences across this thread — generated locally, no AI service.</p>
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

/// Resolve the requested reply page from the query cursors. `latest` wins, then `before` (older),
/// then `after` (newer); a missing/malformed cursor falls back to the first (oldest) page — the
/// default view, so a bare `GET /t/{id}` is unchanged.
fn resolve_anchor(q: &ThreadQuery) -> ReplyAnchor {
    if q.latest
        .as_deref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
    {
        return ReplyAnchor::Latest;
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
            r#"<form class="inline-form" method="post" action="/t/{tid}/p/{pid}/react">
    <input type="hidden" name="csrf" value="{csrf}">
    <input type="hidden" name="kind" value="{kind}">
    <button class="reaction{mine}" type="submit" aria-pressed="{pressed}" title="{kind} reaction">
      <span class="reaction__glyph" aria-hidden="true">{glyph}</span>
      <span class="reaction__count">{count}</span>
    </button>
  </form>"#,
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
/// answer shows an "Accepted answer" badge, and when `can_accept` (thread author or admin) each
/// reply gets a mark/unmark-accepted control. A post with `quoted_post_id` renders an escaped
/// quote block above its own markdown body when the referenced post still exists in this thread.
#[allow(clippy::too_many_arguments)]
fn render_posts(
    posts: &[Post],
    now: i64,
    viewer: Option<&str>,
    is_admin: bool,
    thread_id: &str,
    csrf: &str,
    accepted_post_id: &str,
    can_accept: bool,
    reactions: &HashMap<String, Vec<ReactionCount>>,
    quoted_posts: &HashMap<String, Post>,
) -> String {
    if posts.is_empty() {
        return r#"<div class="empty">This thread has no posts.</div>"#.to_string();
    }
    let empty_counts: Vec<ReactionCount> = Vec::new();
    let mut out = String::new();
    for (i, p) in posts.iter().enumerate() {
        let is_accepted = i > 0 && !accepted_post_id.is_empty() && p.id == accepted_post_id;
        let op = if i == 0 {
            " is-op"
        } else if is_accepted {
            " is-accepted"
        } else {
            ""
        };
        let mut tag = if i == 0 {
            r#"<span class="badge badge-op">Original post</span>"#.to_string()
        } else {
            String::new()
        };
        if is_accepted {
            tag.push_str(r#"<span class="badge badge-accepted">Accepted answer</span>"#);
        }
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
        let accept_control = if i > 0 && can_accept {
            let label = if is_accepted {
                "Unmark accepted"
            } else {
                "Mark accepted"
            };
            format!(
                r#"<form class="inline-form" method="post" action="/t/{tid}/accept">
    <input type="hidden" name="csrf" value="{csrf}">
    <input type="hidden" name="post_id" value="{pid}">
    <button class="btn btn-secondary btn-sm" type="submit">{label}</button>
  </form>"#,
                tid = esc(thread_id),
                pid = esc(&p.id),
                csrf = esc(csrf),
                label = label,
            )
        } else {
            String::new()
        };
        let quote_control = format!(
            r##"<a class="btn btn-ghost btn-sm" href="/t/{tid}?quote={pid}#reply">Quote</a>"##,
            tid = esc(thread_id),
            pid = esc(&p.id),
        );
        // Admin can delete ANY post (original post included). The admin route is group-gated.
        let admin_controls = if is_admin {
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
            && owner_controls.is_empty()
            && accept_control.is_empty()
            && admin_controls.is_empty()
        {
            String::new()
        } else {
            format!(
                r#"<div class="owner-actions post__actions">{quote_control}{owner_controls}{accept_control}{admin_controls}</div>"#,
            )
        };
        let counts = reactions.get(&p.id).unwrap_or(&empty_counts);
        let reactions_html = render_reactions(thread_id, &p.id, csrf, counts);
        let quote_html = render_quote_block(p, quoted_posts);
        out.push_str(&format!(
            r#"<article id="post-{pid}" class="post{op}">
  <header class="post__meta">
    <span class="post__author">{author}</span>
    <span class="post__dot">·</span>
    <time class="post__time" title="{abs}">{ago}</time>
    {tag}
  </header>
  <div class="markdown">{quote}{body}</div>
  {reactions}
  {controls}
</article>"#,
            pid = esc(&p.id),
            op = op,
            author = esc(&p.author_email),
            abs = esc(&fmt_ts(p.created_at)),
            ago = esc(&rel_time(p.created_at, now)),
            tag = tag,
            quote = quote_html,
            body = markdown::render(&p.body_md),
            reactions = reactions_html,
            controls = controls,
        ));
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
