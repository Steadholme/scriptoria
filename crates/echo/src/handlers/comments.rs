//! Dashboard, thread view, embeddable view, and the SSO+CSRF comment / moderate flow.
//!
//! Reading + posting happen behind the gateway `auth=sso` route: the commenter identity is
//! ALWAYS taken from the injected `X-Auth-Subject` / `X-Auth-Email` (never a client field), and
//! every state-changing POST is double-submit CSRF protected. Comment bodies are author-supplied
//! markdown, rendered to SANITIZED HTML. Replies nest exactly one level: a reply to a reply is
//! re-parented onto the original top-level comment.

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;
use std::collections::HashMap;

use crate::auth;
use crate::audit::AuditEvent;
use crate::config::{clamp_page, MAX_BODY_CHARS, RECENT_LIMIT};
use crate::error::AppError;
use crate::handlers::{esc, fmt_datetime, topbar, APP_CSS};
use crate::markdown;
use crate::store::{Comment, Thread};
use crate::{now_nanos, now_secs, rand_suffix, AppState};

const DASHBOARD_HTML: &str = include_str!("../../templates/dashboard.html");
const THREAD_HTML: &str = include_str!("../../templates/thread.html");
const EMBED_HTML: &str = include_str!("../../templates/embed.html");

/// `POST /api/comment` body. Identity is NEVER taken from the form — only the gateway headers.
#[derive(Debug, Deserialize)]
pub struct CommentForm {
    #[serde(default)]
    pub thread_key: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub parent_id: String,
    #[serde(default)]
    pub return_to: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// `POST /api/moderate` body. `action` is `hide` | `unhide`.
#[derive(Debug, Deserialize)]
pub struct ModerateForm {
    #[serde(default)]
    pub comment_id: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub return_to: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// `POST /api/comment/edit` body — author self-edit of one's OWN comment.
#[derive(Debug, Deserialize)]
pub struct EditForm {
    #[serde(default)]
    pub comment_id: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub return_to: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// `POST /api/comment/delete` body — author self-delete of one's OWN comment.
#[derive(Debug, Deserialize)]
pub struct DeleteForm {
    #[serde(default)]
    pub comment_id: String,
    #[serde(default)]
    pub return_to: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// `GET /?before=<created_at>_<id>&limit=<n>` — keyset-pagination cursor + page size for the
/// dashboard thread list. Both are optional; a bare `GET /` returns the newest page.
#[derive(Debug, Deserialize)]
pub struct DashboardQuery {
    #[serde(default)]
    pub before: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

/// `GET /` — the moderation dashboard: one keyset page of threads (newest-first) with their comment
/// counts, plus a recent-activity feed with inline hide/unhide controls. `?before=<created_at>_<id>`
/// pages BACKWARD into older threads; `?limit=` overrides the page size (clamped). A bare `GET /`
/// returns the newest page, so the default view is unchanged.
pub async fn dashboard(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<DashboardQuery>,
) -> Response {
    let email = auth::display_email(&headers);
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    let before = parse_before(q.before.as_deref());
    // Clamp here too so the FULL-page check below compares against the exact size the store used
    // (`clamp_page` is idempotent, so the store re-clamping is a no-op).
    let limit = clamp_page(q.limit.unwrap_or(0));
    let threads = state.store.list_threads(before, limit).await;

    // thread_id -> (key, title) so the activity feed can link a comment back to its thread.
    let mut by_id: HashMap<String, (String, String)> = HashMap::new();

    let mut rows = String::new();
    for t in &threads {
        let count = state.store.count_comments(&t.id).await;
        by_id.insert(t.id.clone(), (t.key.clone(), display_title(t)));
        rows.push_str(&render_thread_row(t, count));
    }
    if threads.is_empty() {
        rows.push_str(
            r#"<tr><td colspan="4" class="table__empty">No threads yet — comments create their thread on first post.</td></tr>"#,
        );
    }
    let threads_table = format!(
        r#"<table class="table">
  <thead><tr><th>Thread</th><th>Key</th><th class="num">Comments</th><th>Created</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"#,
        rows = rows
    );

    // A FULL page (len == limit) means there may be older threads: derive the next cursor from the
    // last (oldest) row on this page. A short/empty page ends the walk (no link).
    let next_cursor = if threads.len() as i64 == limit {
        threads.last().map(|t| (t.created_at, t.id.clone()))
    } else {
        None
    };
    let threads_more = render_load_older(next_cursor.as_ref());

    let recent = state.store.recent_comments(RECENT_LIMIT).await;
    let mut feed = String::new();
    for c in &recent {
        feed.push_str(&render_activity_item(c, &by_id, &csrf));
    }
    if recent.is_empty() {
        feed.push_str(r#"<p class="muted">No comments yet.</p>"#);
    }

    let body = DASHBOARD_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{TOPBAR}}", &topbar("Dashboard", &email))
        .replace("{{THREADS}}", &threads_table)
        .replace("{{THREADS_MORE}}", &threads_more)
        .replace("{{RECENT}}", &feed);
    html_with_cookie(body, set_cookie)
}

/// Parse a `?before=<created_at>_<id>` keyset cursor. `created_at` is a plain integer that never
/// contains `_`, so we split on the FIRST `_`; the id (`thr_<nanos>_<hex>`) keeps its own
/// underscores intact. Returns `None` for a missing/blank/malformed cursor (which falls back to
/// the newest page — the default view).
fn parse_before(before: Option<&str>) -> Option<(i64, String)> {
    let (ts, id) = before?.trim().split_once('_')?;
    let ts: i64 = ts.parse().ok()?;
    if id.is_empty() {
        return None;
    }
    Some((ts, id.to_string()))
}

/// The "Load older" link for the dashboard thread list, rendered ONLY when a next cursor exists
/// (i.e. a full page came back). Links to `?before=<created_at>_<id>` so the next request pages
/// one step older.
fn render_load_older(next: Option<&(i64, String)>) -> String {
    match next {
        Some((ts, id)) => format!(
            r#"<nav class="pagination"><a class="btn btn-secondary btn-sm" href="?before={ts}_{id}">Load older</a></nav>"#,
            ts = ts,
            id = esc(id),
        ),
        None => String::new(),
    }
}

// ---------------------------------------------------------------------------
// Thread view
// ---------------------------------------------------------------------------

/// `GET /t/{key}` — a single thread: its comments (nested one level) + a composer. A key with no
/// thread yet renders an empty view whose composer will create the thread on first post.
pub async fn thread_view(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Response {
    let email = auth::display_email(&headers);
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let viewer_sub = auth::author_sub(&headers).unwrap_or_default();

    let thread = state.store.get_thread(&key).await;
    let (title, comments, count) = match &thread {
        Some(t) => {
            let cs = state.store.list_comments(&t.id).await;
            let n = cs.len();
            (display_title(t), cs, n)
        }
        None => (key.clone(), Vec::new(), 0),
    };

    let return_to = format!("/t/{}", path_seg(&key));
    let comments_html = render_comment_tree(&comments, &csrf, &key, &return_to, true, &viewer_sub);
    let composer = render_composer(&csrf, &key, "", &return_to, thread_url(&thread));

    let meta = format!(
        "{count} comment{plural}{url}",
        plural = if count == 1 { "" } else { "s" },
        url = thread_meta_url(&thread),
    );

    let body = THREAD_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{TOPBAR}}", &topbar("Thread", &email))
        .replace("{{TITLE_TEXT}}", &esc(&title))
        .replace("{{TITLE}}", &esc(&title))
        .replace("{{META}}", &meta)
        .replace("{{COMMENTS}}", &comments_html)
        .replace("{{COMPOSER}}", &composer);
    html_with_cookie(body, set_cookie)
}

// ---------------------------------------------------------------------------
// Embeddable view
// ---------------------------------------------------------------------------

/// `GET /embed/{key}` — a minimal, chrome-free thread + composer intended to be iframe'd by a
/// sibling service. Sets `X-Frame-Options: SAMEORIGIN` so only this origin may frame it.
pub async fn embed_view(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Response {
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let viewer_sub = auth::author_sub(&headers).unwrap_or_default();

    let thread = state.store.get_thread(&key).await;
    let comments = match &thread {
        Some(t) => state.store.list_comments(&t.id).await,
        None => Vec::new(),
    };

    let return_to = format!("/embed/{}", path_seg(&key));
    // No moderation controls in the embed — it is the end-user reading/posting surface — but an
    // author still gets self-edit/delete on their OWN comments.
    let comments_html =
        render_comment_tree(&comments, &csrf, &key, &return_to, false, &viewer_sub);
    let composer = render_composer(&csrf, &key, "", &return_to, thread_url(&thread));

    let body = EMBED_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{COMMENTS}}", &comments_html)
        .replace("{{COMPOSER}}", &composer);

    embed_response(body, set_cookie)
}

// ---------------------------------------------------------------------------
// Post a comment
// ---------------------------------------------------------------------------

/// `POST /api/comment` — upsert the thread by `thread_key`, then insert the comment. Author is the
/// gateway identity; CSRF is required. A reply (`parent_id` set) is clamped to one nesting level.
pub async fn post_comment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CommentForm>,
) -> Result<Response, AppError> {
    let (sub, email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    // A blocked author may not post: reject before any thread/comment mutation.
    if state.store.is_blocked(&sub).await {
        return Err(AppError::Forbidden("author is blocked".to_string()));
    }

    let key = form.thread_key.trim();
    if key.is_empty() {
        return Err(AppError::InvalidRequest("thread_key is required".to_string()));
    }
    let body = form.body.trim();
    if body.is_empty() {
        return Err(AppError::InvalidRequest("comment body is required".to_string()));
    }
    if body.chars().count() > MAX_BODY_CHARS {
        return Err(AppError::InvalidRequest("comment body is too long".to_string()));
    }

    let now = now_secs();
    // Upsert the thread by key — returns the canonical row (existing or freshly created).
    let new_thread = Thread {
        id: format!("thr_{}_{}", now_nanos(), rand_suffix()),
        key: key.to_string(),
        title: form.title.trim().to_string(),
        url: sanitize_thread_url(form.url.trim()),
        created_at: now,
    };
    let thread = state.store.upsert_thread(&new_thread).await?;

    // Resolve the parent so replies nest exactly one level: a reply to a reply re-parents onto the
    // original top-level comment. The parent must belong to this thread.
    let parent_id = resolve_parent(&state, &thread.id, form.parent_id.trim()).await;

    let comment = Comment {
        id: format!("cmt_{}_{}", now_nanos(), rand_suffix()),
        thread_id: thread.id.clone(),
        author_sub: sub,
        author_email: email.clone(),
        body: body.to_string(),
        created_at: now,
        hidden: false,
        parent_id: parent_id.clone(),
    };
    state.store.create_comment(&comment).await?;
    tracing::info!(thread = %thread.key, comment = %comment.id, "comment posted");

    let actor = if email.is_empty() { &comment.author_sub } else { &email };
    state.audit.emit(AuditEvent::info(
        "echo.comment.post",
        actor,
        &thread.key,
        if parent_id.is_empty() { "top-level" } else { "reply" },
    ));

    Ok(redirect(&local_redirect(
        &form.return_to,
        &format!("/t/{}", path_seg(&thread.key)),
    )))
}

// ---------------------------------------------------------------------------
// Moderate
// ---------------------------------------------------------------------------

/// `POST /api/moderate` — hide or unhide a comment. Behind SSO; CSRF required. Additionally gated
/// on moderator group membership (`X-Auth-Groups`): a merely-authenticated user gets 403, so a
/// regular commenter can NO LONGER hide/unhide arbitrary comments.
pub async fn moderate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ModerateForm>,
) -> Result<Response, AppError> {
    let (sub, email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;
    auth::require_moderator(&headers)?;

    let id = form.comment_id.trim();
    if id.is_empty() {
        return Err(AppError::InvalidRequest("comment_id is required".to_string()));
    }
    let hidden = match form.action.trim() {
        "hide" => true,
        "unhide" => false,
        other => {
            return Err(AppError::InvalidRequest(format!(
                "unknown action {other} (use hide|unhide)"
            )))
        }
    };

    let updated = state.store.set_comment_hidden(id, hidden).await?;
    if !updated {
        return Err(AppError::NotFound("no such comment".to_string()));
    }
    tracing::info!(comment = %id, hidden, "comment moderated");

    let actor = if email.is_empty() { &sub } else { &email };
    state.audit.emit(AuditEvent::notice(
        "echo.moderate",
        actor,
        id,
        if hidden { "hide" } else { "unhide" },
    ));

    Ok(redirect(&local_redirect(&form.return_to, "/")))
}

// ---------------------------------------------------------------------------
// Author self-edit / self-delete
// ---------------------------------------------------------------------------

/// `POST /api/comment/edit` — an author edits the body of their OWN comment. Behind SSO; CSRF
/// required. Ownership is enforced by the store (`author_sub` match), so a mismatched/foreign
/// comment updates nothing and returns 404 (the same shape as a missing comment — no ownership
/// leak).
pub async fn edit_comment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<EditForm>,
) -> Result<Response, AppError> {
    let (sub, email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let id = form.comment_id.trim();
    if id.is_empty() {
        return Err(AppError::InvalidRequest("comment_id is required".to_string()));
    }
    let body = form.body.trim();
    if body.is_empty() {
        return Err(AppError::InvalidRequest("comment body is required".to_string()));
    }
    if body.chars().count() > MAX_BODY_CHARS {
        return Err(AppError::InvalidRequest("comment body is too long".to_string()));
    }

    let updated = state.store.update_comment_body(id, &sub, body).await?;
    if !updated {
        return Err(AppError::NotFound("no such comment".to_string()));
    }
    tracing::info!(comment = %id, "comment edited by author");

    let actor = if email.is_empty() { &sub } else { &email };
    state
        .audit
        .emit(AuditEvent::info("echo.comment.edit", actor, id, "self-edit"));

    Ok(redirect(&local_redirect(&form.return_to, "/")))
}

/// `POST /api/comment/delete` — an author deletes their OWN comment. Behind SSO; CSRF required.
/// Ownership is enforced by the store; a foreign/missing comment deletes nothing and returns 404.
pub async fn delete_comment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DeleteForm>,
) -> Result<Response, AppError> {
    let (sub, email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let id = form.comment_id.trim();
    if id.is_empty() {
        return Err(AppError::InvalidRequest("comment_id is required".to_string()));
    }

    let deleted = state.store.delete_comment(id, &sub).await?;
    if !deleted {
        return Err(AppError::NotFound("no such comment".to_string()));
    }
    tracing::info!(comment = %id, "comment deleted by author");

    let actor = if email.is_empty() { &sub } else { &email };
    state
        .audit
        .emit(AuditEvent::notice("echo.comment.delete", actor, id, "self-delete"));

    Ok(redirect(&local_redirect(&form.return_to, "/")))
}

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------

/// The display title for a thread: its title when set, else the key as a fallback.
fn display_title(t: &Thread) -> String {
    if t.title.trim().is_empty() {
        t.key.clone()
    } else {
        t.title.clone()
    }
}

/// The thread's external URL when present AND scheme-safe; otherwise empty.
fn thread_url(thread: &Option<Thread>) -> &str {
    match thread {
        Some(t) if !t.url.is_empty() && markdown::is_safe_url(&t.url) => t.url.as_str(),
        _ => "",
    }
}

/// Keep only a scheme-safe external URL for storage; drop anything else (e.g. `javascript:`).
fn sanitize_thread_url(url: &str) -> String {
    if !url.is_empty() && markdown::is_safe_url(url) {
        url.to_string()
    } else {
        String::new()
    }
}

/// A " · <a>source</a>" suffix for the thread meta line when the thread has a safe URL.
fn thread_meta_url(thread: &Option<Thread>) -> String {
    let url = thread_url(thread);
    if url.is_empty() {
        String::new()
    } else {
        format!(r#" · <a href="{u}" rel="noopener noreferrer">source</a>"#, u = esc(url))
    }
}

/// One dashboard thread row.
fn render_thread_row(t: &Thread, count: i64) -> String {
    format!(
        r#"<tr>
  <td><a href="/t/{key}">{title}</a></td>
  <td class="mono">{rawkey}</td>
  <td class="num">{count}</td>
  <td class="muted">{created}</td>
</tr>"#,
        key = esc(&path_seg(&t.key)),
        title = esc(&display_title(t)),
        rawkey = esc(&t.key),
        count = count,
        created = esc(&fmt_datetime(t.created_at)),
    )
}

/// One dashboard activity-feed item (with an inline hide/unhide control).
fn render_activity_item(
    c: &Comment,
    by_id: &HashMap<String, (String, String)>,
    csrf: &str,
) -> String {
    let (thread_link, thread_label) = match by_id.get(&c.thread_id) {
        Some((key, title)) => (
            format!("/t/{}", path_seg(key)),
            title.clone(),
        ),
        None => ("/".to_string(), c.thread_id.clone()),
    };
    let preview = markdown::preview(&c.body, 160);
    let hidden_badge = if c.hidden {
        r#" <span class="badge badge-hidden">Hidden</span>"#
    } else {
        ""
    };
    format!(
        r#"<div class="activity">
  <div class="activity__head">
    <span class="activity__author">{author}</span>
    <span class="activity__sep">on</span>
    <a class="activity__thread" href="{link}">{thread}</a>{badge}
    <span class="activity__date">{date}</span>
  </div>
  <p class="activity__body">{preview}</p>
  {control}
</div>"#,
        author = esc(&author_label(c)),
        link = esc(&thread_link),
        thread = esc(&thread_label),
        badge = hidden_badge,
        date = esc(&fmt_datetime(c.created_at)),
        preview = esc(&preview),
        control = moderation_control(c, csrf, "/"),
    )
}

/// Render a thread's comments as a one-level tree: top-level comments in order, each followed by
/// its replies. `moderate` toggles the hide/unhide controls (on in the admin views, off in embed).
fn render_comment_tree(
    comments: &[Comment],
    csrf: &str,
    thread_key: &str,
    return_to: &str,
    moderate: bool,
    viewer_sub: &str,
) -> String {
    if comments.is_empty() {
        return r#"<p class="muted comment-list__empty">No comments yet. Be the first to comment.</p>"#
            .to_string();
    }
    // Group replies by their parent id (already clamped to one level on write).
    let mut replies: HashMap<&str, Vec<&Comment>> = HashMap::new();
    for c in comments {
        if !c.parent_id.is_empty() {
            replies.entry(c.parent_id.as_str()).or_default().push(c);
        }
    }

    let mut out = String::new();
    for c in comments.iter().filter(|c| c.parent_id.is_empty()) {
        out.push_str(&render_comment(
            c, csrf, thread_key, return_to, moderate, false, viewer_sub,
        ));
        if let Some(kids) = replies.get(c.id.as_str()) {
            out.push_str(r#"<div class="replies">"#);
            for k in kids {
                out.push_str(&render_comment(
                    k, csrf, thread_key, return_to, moderate, true, viewer_sub,
                ));
            }
            out.push_str("</div>");
        }
    }
    out
}

/// One rendered comment. Hidden comments show a neutral placeholder instead of their body. A
/// top-level comment (not `is_reply`) gets a compact reply composer.
fn render_comment(
    c: &Comment,
    csrf: &str,
    thread_key: &str,
    return_to: &str,
    moderate: bool,
    is_reply: bool,
    viewer_sub: &str,
) -> String {
    let body_html = if c.hidden {
        r#"<em class="comment__hidden">[comment hidden by a moderator]</em>"#.to_string()
    } else {
        markdown::render_html(&c.body)
    };
    let control = if moderate {
        moderation_control(c, csrf, return_to)
    } else {
        String::new()
    };
    // The viewer's own comment gets self-edit/delete controls — but not while a moderator has it
    // hidden (editing wouldn't unhide it, and we don't re-expose a hidden body in the edit box).
    let owner = !viewer_sub.is_empty() && c.author_sub == viewer_sub;
    let self_ctl = if owner && !c.hidden {
        self_controls(c, csrf, return_to)
    } else {
        String::new()
    };
    let reply_form = if is_reply {
        String::new()
    } else {
        render_reply_form(csrf, thread_key, &c.id, return_to)
    };
    format!(
        r#"<article class="comment">
  <div class="comment__head">
    <span class="comment__author">{author}</span>
    <span class="comment__date">{date}</span>
    {control}
  </div>
  <div class="comment__body">{body}</div>
  {self_ctl}
  {reply}
</article>"#,
        author = esc(&author_label(c)),
        date = esc(&fmt_datetime(c.created_at)),
        control = control,
        body = body_html,
        self_ctl = self_ctl,
        reply = reply_form,
    )
}

/// The author's self-edit (collapsible composer prefilled with the raw body) + self-delete controls
/// for their OWN comment. Reuses the reply/moderation form idioms; the body is HTML-escaped.
fn self_controls(c: &Comment, csrf: &str, return_to: &str) -> String {
    format!(
        r#"<div class="self-controls">
  <details class="reply-toggle edit-toggle">
    <summary>Edit</summary>
    <form class="composer-form composer-form--reply" method="post" action="/api/comment/edit">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <input type="hidden" name="comment_id" value="{id}">
      <input type="hidden" name="return_to" value="{ret}">
      <textarea name="body" class="composer__body" required>{body}</textarea>
      <div class="composer__actions"><button class="btn btn-primary btn-sm" type="submit">Save</button></div>
    </form>
  </details>
  <form class="inline-form mod-form" method="post" action="/api/comment/delete">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <input type="hidden" name="comment_id" value="{id}">
    <input type="hidden" name="return_to" value="{ret}">
    <button class="btn btn-ghost btn-sm" type="submit">Delete</button>
  </form>
</div>"#,
        csrf = esc(csrf),
        id = esc(&c.id),
        ret = esc(return_to),
        body = esc(&c.body),
    )
}

/// The author display label: email when present, else the opaque subject id.
fn author_label(c: &Comment) -> String {
    if c.author_email.trim().is_empty() {
        c.author_sub.clone()
    } else {
        c.author_email.clone()
    }
}

/// The hide/unhide form for a single comment.
fn moderation_control(c: &Comment, csrf: &str, return_to: &str) -> String {
    let (action, label, cls) = if c.hidden {
        ("unhide", "Unhide", "btn-secondary")
    } else {
        ("hide", "Hide", "btn-ghost")
    };
    format!(
        r#"<form class="inline-form mod-form" method="post" action="/api/moderate">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <input type="hidden" name="comment_id" value="{id}">
  <input type="hidden" name="action" value="{action}">
  <input type="hidden" name="return_to" value="{ret}">
  <button class="btn {cls} btn-sm" type="submit">{label}</button>
</form>"#,
        csrf = esc(csrf),
        id = esc(&c.id),
        action = action,
        ret = esc(return_to),
        cls = cls,
        label = label,
    )
}

/// A compact reply composer under a top-level comment.
fn render_reply_form(csrf: &str, thread_key: &str, parent_id: &str, return_to: &str) -> String {
    format!(
        r#"<details class="reply-toggle">
  <summary>Reply</summary>
  <form class="composer-form composer-form--reply" method="post" action="/api/comment">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <input type="hidden" name="thread_key" value="{key}">
    <input type="hidden" name="parent_id" value="{parent}">
    <input type="hidden" name="return_to" value="{ret}">
    <textarea name="body" class="composer__body" required placeholder="Write a reply (Markdown)&hellip;"></textarea>
    <div class="composer__actions"><button class="btn btn-primary btn-sm" type="submit">Post reply</button></div>
  </form>
</details>"#,
        csrf = esc(csrf),
        key = esc(thread_key),
        parent = esc(parent_id),
        ret = esc(return_to),
    )
}

/// The top-level new-comment composer for a thread. `_thread_url` is reserved for a future "source"
/// hint; the form posts body only (title/url seeding is done by service-to-service callers).
fn render_composer(
    csrf: &str,
    thread_key: &str,
    parent_id: &str,
    return_to: &str,
    _thread_url: &str,
) -> String {
    format!(
        r#"<form class="composer-form" method="post" action="/api/comment">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <input type="hidden" name="thread_key" value="{key}">
  <input type="hidden" name="parent_id" value="{parent}">
  <input type="hidden" name="return_to" value="{ret}">
  <textarea name="body" class="composer__body" required placeholder="Write a comment (Markdown)&hellip;"></textarea>
  <div class="composer__actions"><button class="btn btn-primary" type="submit">Post comment</button></div>
</form>"#,
        csrf = esc(csrf),
        key = esc(thread_key),
        parent = esc(parent_id),
        ret = esc(return_to),
    )
}

/// Resolve the effective parent id for a new comment, enforcing one-level nesting. Returns `""`
/// (top-level) when `requested` is empty, missing, or points outside this thread. When the parent
/// is itself a reply, re-parent onto the original top-level comment.
async fn resolve_parent(state: &AppState, thread_id: &str, requested: &str) -> String {
    if requested.is_empty() {
        return String::new();
    }
    match state.store.get_comment(requested).await {
        Some(p) if p.thread_id == thread_id => {
            if p.parent_id.is_empty() {
                p.id
            } else {
                p.parent_id
            }
        }
        _ => String::new(),
    }
}

/// Validate a `return_to` for an open-redirect-safe local navigation: it must be a single-slash
/// absolute path (`/...`), never protocol-relative (`//host`) or an absolute URL. Falls back to
/// `default` otherwise.
pub(crate) fn local_redirect(return_to: &str, default: &str) -> String {
    let t = return_to.trim();
    if t.starts_with('/')
        && !t.starts_with("//")
        && !t.contains(|c: char| c.is_ascii_control())
    {
        t.to_string()
    } else {
        default.to_string()
    }
}

/// Percent-encode a path segment so a thread key with `/`, spaces, etc. survives in a URL path.
pub(crate) fn path_seg(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// A 303 redirect (post/redirect/get).
pub(crate) fn redirect(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(
            header::LOCATION,
            HeaderValue::from_str(location).unwrap_or_else(|_| HeaderValue::from_static("/")),
        )],
    )
        .into_response()
}

/// An HTML response, optionally attaching a freshly-minted CSRF `Set-Cookie`.
pub(crate) fn html_with_cookie(body: String, set_cookie: Option<String>) -> Response {
    let mut resp = Html(body).into_response();
    attach_cookie(&mut resp, set_cookie);
    resp
}

/// The embed response: HTML + `X-Frame-Options: SAMEORIGIN` (so only this origin may frame it) +
/// the optional CSRF `Set-Cookie`.
fn embed_response(body: String, set_cookie: Option<String>) -> Response {
    let mut resp = Html(body).into_response();
    resp.headers_mut().insert(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("SAMEORIGIN"),
    );
    attach_cookie(&mut resp, set_cookie);
    resp
}

fn attach_cookie(resp: &mut Response, set_cookie: Option<String>) {
    if let Some(c) = set_cookie {
        if let Ok(value) = HeaderValue::from_str(&c) {
            resp.headers_mut().insert(header::SET_COOKIE, value);
        }
    }
}
