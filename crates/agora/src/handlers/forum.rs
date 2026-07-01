//! The forum pages: home, category, thread (with markdown-rendered posts + reply), and the
//! new-thread form + create.
//!
//! Every page is server-rendered into the shared enterprise shell. Reads render for any
//! gateway-authenticated user; the two POSTs (create thread, reply) require a gateway-injected
//! identity (the trusted author) AND a valid double-submit CSRF token. Post bodies are
//! CommonMark, rendered through the sanitiser in [`crate::markdown`]; all other interpolated
//! text is HTML-escaped.

use std::collections::HashMap;

use axum::extract::{Form, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth;
use crate::error::AppError;
use crate::handlers::insight::thread_summary;
use crate::handlers::{
    email_display, esc, fmt_ts, rel_time, render_page, replies_label,
};
use crate::model::{Post, Thread};
use crate::{markdown, new_id, now_secs, AppState};

/// Most-recent threads shown on the home page.
const RECENT_LIMIT: i64 = 20;
/// Threads listed on a category page.
const CATEGORY_LIMIT: i64 = 200;
/// Caps on user input (defense against absurd payloads; the store columns are TEXT).
const MAX_TITLE: usize = 200;
const MAX_BODY: usize = 20_000;

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

pub async fn home(State(state): State<AppState>, headers: HeaderMap) -> Result<Html<String>, AppError> {
    let now = now_secs();
    let categories = state.store.list_categories().await?;
    let recent = state.store.recent_threads(RECENT_LIMIT).await?;

    // id -> name map so recent rows can name their category.
    let cat_names: HashMap<&str, &str> =
        categories.iter().map(|c| (c.id.as_str(), c.name.as_str())).collect();

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
<section class="section">
  <h2 class="section__title">Recent activity</h2>
  <div class="thread-list">{recent}</div>
</section>"#,
        cats = cats_html,
        recent = recent_html,
    );

    Ok(Html(render_page("Forum", &email_display(&headers), &content)))
}

// ===========================================================================
// GET /c/{id} — threads in a category
// ===========================================================================

pub async fn category(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Html<String>, AppError> {
    let now = now_secs();
    let category = state
        .store
        .get_category(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("category not found".to_string()))?;
    let threads = state.store.threads_in_category(&id, CATEGORY_LIMIT).await?;

    let crumbs = format!(
        r#"<nav class="crumbs"><a href="/">Home</a><span class="crumbs__sep">/</span><span>{name}</span></nav>"#,
        name = esc(&category.name),
    );
    let list = render_thread_rows(&threads, now, None);

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
  <div class="thread-list">{list}</div>
</section>"#,
        crumbs = crumbs,
        name = esc(&category.name),
        count = threads.len(),
        tw = if threads.len() == 1 { "thread" } else { "threads" },
        id = esc(&category.id),
        list = list,
    );

    Ok(Html(render_page(&category.name, &email_display(&headers), &content)))
}

// ===========================================================================
// GET /t/{id} — a thread: original post + replies (markdown) + reply form
// ===========================================================================

pub async fn thread(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let now = now_secs();
    let thread = state
        .store
        .get_thread(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("thread not found".to_string()))?;
    let posts = state.store.posts_in_thread(&id).await?;
    let category = state.store.get_category(&thread.category_id).await?;

    // The authenticated subject (if any) decides which edit/delete controls render.
    let viewer = auth::identity_subject(&headers);
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

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
    let posts_html = render_posts(&posts, now, viewer.as_deref(), &thread.id, &csrf);

    let reply_form = format!(
        r#"<section class="card pad">
  <h2 class="section__title">Reply</h2>
  <form class="form" method="post" action="/t/{tid}/reply">
    <input type="hidden" name="csrf" value="{csrf}">
    <label for="reply-body">Your reply <span class="muted">(Markdown supported)</span></label>
    <textarea id="reply-body" name="body" rows="5" placeholder="Write a reply…" required></textarea>
    <div class="form__actions">
      <button class="btn btn-primary" type="submit">Post reply</button>
    </div>
  </form>
</section>"#,
        tid = esc(&thread.id),
        csrf = esc(&csrf),
    );

    let content = format!(
        r#"{crumbs}
<div class="thread-head">
  <h1>{title}</h1>
  <p class="muted">Started by <strong>{author}</strong> · {when} · {replies}</p>
  {actions}
</div>
{summary}
<section class="posts">{posts}</section>
{reply}"#,
        crumbs = crumbs,
        title = esc(&thread.title),
        author = esc(&thread.author_email),
        when = esc(&fmt_ts(thread.created_at)),
        replies = esc(&replies_label(posts.len() as i64)),
        actions = thread_actions,
        summary = summary_html,
        posts = posts_html,
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

    let title = form.title.trim();
    if title.is_empty() {
        return Err(AppError::InvalidRequest("thread title is required".to_string()));
    }
    if title.chars().count() > MAX_TITLE {
        return Err(AppError::InvalidRequest("thread title is too long".to_string()));
    }
    let category_id = form.category.trim();
    if state.store.get_category(category_id).await?.is_none() {
        return Err(AppError::InvalidRequest("unknown category".to_string()));
    }
    let body = form.body.trim();
    if body.is_empty() {
        return Err(AppError::InvalidRequest("post body is required".to_string()));
    }
    if body.chars().count() > MAX_BODY {
        return Err(AppError::InvalidRequest("post body is too long".to_string()));
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
    };
    let first_post = Post {
        id: new_id("p"),
        thread_id: thread.id.clone(),
        body_md: body.to_string(),
        author_sub: author.sub,
        author_email: author.email,
        created_at: now,
    };
    state.store.create_thread(&thread, &first_post).await?;
    tracing::info!(thread = thread.id, author = thread.author_email, "thread created");

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

    if state.store.get_thread(&id).await?.is_none() {
        return Err(AppError::NotFound("thread not found".to_string()));
    }
    let body = form.body.trim();
    if body.is_empty() {
        return Err(AppError::InvalidRequest("reply body is required".to_string()));
    }
    if body.chars().count() > MAX_BODY {
        return Err(AppError::InvalidRequest("reply body is too long".to_string()));
    }

    let now = now_secs();
    let post = Post {
        id: new_id("p"),
        thread_id: id.clone(),
        body_md: body.to_string(),
        author_sub: author.sub,
        author_email: author.email,
        created_at: now,
    };
    state.store.add_reply(&post).await?;
    tracing::info!(thread = id, author = post.author_email, "reply posted");

    let actor = if post.author_email.is_empty() {
        &post.author_sub
    } else {
        &post.author_email
    };
    state.audit.emit(AuditEvent::info("reply.create", actor, &post.id, &id));

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
        return Err(AppError::Forbidden("you can only edit your own threads".to_string()));
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
        return Err(AppError::Forbidden("you can only edit your own threads".to_string()));
    }

    let title = form.title.trim();
    if title.is_empty() {
        return Err(AppError::InvalidRequest("thread title is required".to_string()));
    }
    if title.chars().count() > MAX_TITLE {
        return Err(AppError::InvalidRequest("thread title is too long".to_string()));
    }
    let body = form.body.trim();
    if body.is_empty() {
        return Err(AppError::InvalidRequest("post body is required".to_string()));
    }
    if body.chars().count() > MAX_BODY {
        return Err(AppError::InvalidRequest("post body is too long".to_string()));
    }

    // The original post is the oldest post in the thread (first in display order).
    let posts = state.store.posts_in_thread(&id).await?;
    let op_id = posts
        .first()
        .map(|p| p.id.clone())
        .ok_or_else(|| AppError::NotFound("thread has no original post".to_string()))?;

    state.store.update_thread(&id, title, &op_id, body).await?;
    tracing::info!(thread = id, author = thread.author_email, "thread updated");

    let actor = if thread.author_email.is_empty() {
        &thread.author_sub
    } else {
        &thread.author_email
    };
    state
        .audit
        .emit(AuditEvent::info("thread.update", actor, &thread.id, &thread.category_id));

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
        return Err(AppError::Forbidden("you can only delete your own threads".to_string()));
    }

    state.store.delete_thread(&id).await?;
    tracing::info!(thread = id, author = thread.author_email, "thread deleted");

    let actor = if thread.author_email.is_empty() {
        &thread.author_sub
    } else {
        &thread.author_email
    };
    state
        .audit
        .emit(AuditEvent::notice("thread.delete", actor, &thread.id, &thread.category_id));

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
        return Err(AppError::Forbidden("you can only edit your own replies".to_string()));
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
        return Err(AppError::InvalidRequest("reply body is required".to_string()));
    }
    if body.chars().count() > MAX_BODY {
        return Err(AppError::InvalidRequest("reply body is too long".to_string()));
    }

    state.store.update_post(&pid, body).await?;
    tracing::info!(thread = tid, post = pid, "reply updated");

    let actor = if post.author_email.is_empty() {
        &post.author_sub
    } else {
        &post.author_email
    };
    state.audit.emit(AuditEvent::info("reply.update", actor, &pid, &tid));

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
    state.audit.emit(AuditEvent::notice("reply.delete", actor, &pid, &tid));

    Ok(redirect_to(&format!("/t/{tid}")))
}

// ===========================================================================
// Render helpers
// ===========================================================================

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

/// Render the posts of a thread. The first post is flagged as the original post (`is-op`);
/// each body is rendered through the markdown sanitiser. A REPLY (never the original post —
/// that is edited/deleted via the thread controls) gets inline Edit/Delete controls when
/// `viewer` is its author.
fn render_posts(
    posts: &[Post],
    now: i64,
    viewer: Option<&str>,
    thread_id: &str,
    csrf: &str,
) -> String {
    if posts.is_empty() {
        return r#"<div class="empty">This thread has no posts.</div>"#.to_string();
    }
    let mut out = String::new();
    for (i, p) in posts.iter().enumerate() {
        let op = if i == 0 { " is-op" } else { "" };
        let tag = if i == 0 {
            r#"<span class="badge badge-op">Original post</span>"#
        } else {
            ""
        };
        // Own-reply controls: not on the original post (i == 0), only for the author.
        let controls = if i > 0 && viewer == Some(p.author_sub.as_str()) {
            format!(
                r#"<div class="owner-actions post__actions">
  <a class="btn btn-ghost btn-sm" href="/t/{tid}/p/{pid}/edit">Edit</a>
  <form class="inline-form" method="post" action="/t/{tid}/p/{pid}/delete" onsubmit="return confirm('Delete this reply? This cannot be undone.');">
    <input type="hidden" name="csrf" value="{csrf}">
    <button class="btn btn-danger btn-sm" type="submit">Delete</button>
  </form>
</div>"#,
                tid = esc(thread_id),
                pid = esc(&p.id),
                csrf = esc(csrf),
            )
        } else {
            String::new()
        };
        out.push_str(&format!(
            r#"<article class="post{op}">
  <header class="post__meta">
    <span class="post__author">{author}</span>
    <span class="post__dot">·</span>
    <time class="post__time" title="{abs}">{ago}</time>
    {tag}
  </header>
  <div class="markdown">{body}</div>
  {controls}
</article>"#,
            op = op,
            author = esc(&p.author_email),
            abs = esc(&fmt_ts(p.created_at)),
            ago = esc(&rel_time(p.created_at, now)),
            tag = tag,
            body = markdown::render(&p.body_md),
            controls = controls,
        ));
    }
    out
}

/// Build an `Html` response, attaching a `Set-Cookie` header when a fresh CSRF cookie is due.
fn html_response(html: String, set_cookie: Option<String>) -> Response {
    let mut resp = Html(html).into_response();
    if let Some(cookie) = set_cookie {
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            resp.headers_mut().insert(header::SET_COOKIE, value);
        }
    }
    resp
}

/// A 303 See Other redirect (post/redirect/get).
fn redirect_to(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, location.to_string())],
    )
        .into_response()
}
