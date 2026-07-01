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

    let summary_html = render_summary(&posts);
    let posts_html = render_posts(&posts, now);

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
</div>
{summary}
<section class="posts">{posts}</section>
{reply}"#,
        crumbs = crumbs,
        title = esc(&thread.title),
        author = esc(&thread.author_email),
        when = esc(&fmt_ts(thread.created_at)),
        replies = esc(&replies_label(posts.len() as i64)),
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
// Render helpers
// ===========================================================================

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
/// each body is rendered through the markdown sanitiser.
fn render_posts(posts: &[Post], now: i64) -> String {
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
        out.push_str(&format!(
            r#"<article class="post{op}">
  <header class="post__meta">
    <span class="post__author">{author}</span>
    <span class="post__dot">·</span>
    <time class="post__time" title="{abs}">{ago}</time>
    {tag}
  </header>
  <div class="markdown">{body}</div>
</article>"#,
            op = op,
            author = esc(&p.author_email),
            abs = esc(&fmt_ts(p.created_at)),
            ago = esc(&rel_time(p.created_at, now)),
            tag = tag,
            body = markdown::render(&p.body_md),
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
