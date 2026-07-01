//! Reading views + the SSO-gated compose / edit / delete flow.
//!
//! Reading (`GET /`, `GET /p/{slug}`) renders the markdown body to SANITIZED HTML. Authoring
//! (`/new`, `/edit/{slug}`, `/delete/{slug}`) is mounted behind the gateway `auth=sso` route:
//! the author identity is ALWAYS taken from the injected `X-Auth-Subject` / `X-Auth-Email`
//! (never a client field), and every state-changing POST is double-submit CSRF protected.
//! A post may be edited or deleted only by its own author.

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth;
use crate::error::AppError;
use crate::handlers::{esc, fmt_date, topbar, APP_CSS};
use crate::markdown;
use crate::store::Post;
use crate::{now_nanos, now_secs, unique_slug, AppState};

const LIST_HTML: &str = include_str!("../../templates/list.html");
const POST_HTML: &str = include_str!("../../templates/post.html");
const EDITOR_HTML: &str = include_str!("../../templates/editor.html");

/// Form body shared by compose + edit. `published` is a checkbox: present (`"on"`) when ticked,
/// absent otherwise. Identity is NEVER taken from the form — only from the gateway headers.
#[derive(Debug, Deserialize)]
pub struct PostForm {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub published: Option<String>,
    #[serde(default)]
    pub csrf_token: String,
}

/// Minimal form body for delete: just the CSRF token (identity comes from the gateway headers).
#[derive(Debug, Deserialize)]
pub struct DeleteForm {
    #[serde(default)]
    pub csrf_token: String,
}

/// Index query string: the keyset cursor `?before=<created_at>_<id>` and an optional `?limit=`.
/// Both are absent on the default (newest-page) view, so an old bookmark keeps working.
#[derive(Debug, Deserialize)]
pub struct IndexQuery {
    #[serde(default)]
    pub before: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
}

// ---------------------------------------------------------------------------
// Reading views
// ---------------------------------------------------------------------------

/// `GET /` — the index: one keyset page of posts, newest-first (title + excerpt + date + author),
/// with a "Load older" link when a full page came back. `?before=<created_at>_<id>` pages backward
/// and `?limit=` sizes the page (clamped); both absent yields the default newest page.
pub async fn index(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<IndexQuery>,
) -> Response {
    let viewer = auth::author_sub(&headers);
    let email = auth::display_email(&headers);

    // Site settings drive the title/tagline in the head + masthead and the default page size.
    let settings = state.store.get_settings().await;

    let before = q.before.as_deref().and_then(parse_before);
    let limit = crate::config::clamp_page_with_default(q.limit, settings.posts_per_page);
    let posts = state.store.list_posts(before, limit).await;

    // A FULL page means more history may exist: the next cursor is the LAST (oldest) row of THIS
    // store page — derived before visibility filtering so drafts never desync the keyset position.
    let next_cursor = if posts.len() as i64 == limit {
        posts.last().map(|p| format!("{}_{}", p.created_at, p.id))
    } else {
        None
    };

    let mut cards = String::new();
    let mut shown = 0usize;
    for p in &posts {
        if !visible_to(p, viewer.as_deref()) {
            continue;
        }
        shown += 1;
        cards.push_str(&render_card(p, viewer.as_deref()));
    }
    if shown == 0 && next_cursor.is_none() {
        cards.push_str(
            r#"<div class="empty-state"><h2>No posts yet</h2><p>Start writing — your first post will appear here.</p><a class="btn btn-primary" href="/new">Write the first post</a></div>"#,
        );
    }

    let pager = match &next_cursor {
        Some(cursor) => format!(
            r#"<nav class="post-list__pager"><a class="btn btn-secondary" href="/?before={cursor}">Load older</a></nav>"#,
            cursor = esc(cursor),
        ),
        None => String::new(),
    };

    let body = LIST_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{TOPBAR}}", &topbar(&settings.title, &email))
        .replace("{{BLOG_TITLE}}", &esc(&settings.title))
        .replace("{{TAGLINE}}", &esc(&settings.tagline))
        .replace("{{POSTS}}", &cards)
        .replace("{{PAGER}}", &pager);
    Html(body).into_response()
}

/// Parse a `?before=<created_at>_<id>` keyset cursor into `(created_at, id)`. `created_at` is a
/// plain integer (no `_`) and inkwell post ids are `post_<nanos>` (they DO contain `_`), so the
/// split is on the FIRST `_`: everything after it is the id, round-tripping the cursor exactly.
/// Returns `None` for anything malformed (treated as "no cursor" — the newest page).
fn parse_before(raw: &str) -> Option<(i64, String)> {
    let (ts, id) = raw.split_once('_')?;
    let ts: i64 = ts.parse().ok()?;
    if id.is_empty() {
        return None;
    }
    Some((ts, id.to_string()))
}

/// `GET /p/{slug}` — a full post, body markdown rendered to sanitized HTML. Unpublished drafts
/// are visible only to their author; otherwise 404.
pub async fn view(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
) -> Result<Response, AppError> {
    let viewer = auth::author_sub(&headers);
    let email = auth::display_email(&headers);

    let post = state
        .store
        .get_post(&slug)
        .await
        .filter(|p| visible_to(p, viewer.as_deref()))
        .ok_or_else(|| AppError::NotFound("no such post".to_string()))?;

    let is_owner = viewer.as_deref() == Some(post.author_sub.as_str());
    // The owner gets edit/delete controls; the delete form needs a CSRF token.
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    let meta = format!(
        "{date} · {author}{draft}",
        date = fmt_date(post.created_at),
        author = post.author_email,
        draft = if post.published { "" } else { " · Draft" },
    );

    let actions = if is_owner {
        format!(
            r#"<div class="article__actions">
  <a class="btn btn-secondary btn-sm" href="/edit/{slug}">Edit</a>
  <form class="inline-form" method="post" action="/delete/{slug}" onsubmit="return confirm('Delete this post? This cannot be undone.');">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <button class="btn btn-danger btn-sm" type="submit">Delete</button>
  </form>
</div>"#,
            slug = esc(&post.slug),
            csrf = esc(&csrf),
        )
    } else {
        String::new()
    };

    let body_html = markdown::render_html(&post.body_md);

    // Related posts: top-3 OTHER published posts by keyword-overlap to this one (additive block).
    // Rank over the newest bounded page (same cap the index used before pagination).
    let related =
        render_related(&post, &state.store.list_posts(None, crate::config::MAX_PAGE).await);

    let page = POST_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{TOPBAR}}", &topbar("Reading", &email))
        .replace("{{TITLE_TEXT}}", &esc(&post.title))
        .replace("{{TITLE}}", &esc(&post.title))
        .replace("{{META}}", &esc(&meta))
        .replace("{{ACTIONS}}", &actions)
        .replace("{{BODY}}", &body_html)
        .replace("{{RELATED}}", &related);

    Ok(html_with_cookie(page, set_cookie))
}

// ---------------------------------------------------------------------------
// Compose
// ---------------------------------------------------------------------------

/// `GET /new` — the compose form.
pub async fn new_form(State(_state): State<AppState>, headers: HeaderMap) -> Response {
    let email = auth::display_email(&headers);
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let page = render_editor(EditorView {
        email: &email,
        heading: "New post",
        subhead: "Compose a post in Markdown. You are the author.",
        action: "/new",
        csrf: &csrf,
        title_value: "",
        body_value: "",
        published: true,
        submit_label: "Publish",
        cancel_href: "/",
        delete_slug: None,
    });
    html_with_cookie(page, set_cookie)
}

/// `POST /new` — create a post: author from the injected `X-Auth-*`, slug from the title.
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<PostForm>,
) -> Result<Response, AppError> {
    let (sub, email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let title = form.title.trim();
    if title.is_empty() {
        return Err(AppError::InvalidRequest("title is required".to_string()));
    }
    let body_md = form.body.trim().to_string();
    let now = now_secs();
    let fallback = now_nanos().to_string();
    let slug = unique_slug(state.store.as_ref(), title, &fallback).await;

    let post = Post {
        id: format!("post_{}", now_nanos()),
        slug: slug.clone(),
        title: title.to_string(),
        body_md,
        author_sub: sub,
        author_email: email,
        created_at: now,
        updated_at: now,
        published: form.published.is_some(),
        featured: false,
    };
    state.store.create_post(&post).await?;
    tracing::info!(slug = %slug, "post created");

    let actor = if post.author_email.is_empty() { &post.author_sub } else { &post.author_email };
    state.audit.emit(AuditEvent::info(
        "post.create",
        actor,
        &slug,
        if post.published { "published" } else { "draft" },
    ));

    // Keep the ask index in step (best-effort; never fails the create).
    crate::reindex_post(state.store.as_ref(), &post).await;

    Ok(redirect(&format!("/p/{slug}")))
}

// ---------------------------------------------------------------------------
// Edit
// ---------------------------------------------------------------------------

/// `GET /edit/{slug}` — the edit form for an own post.
pub async fn edit_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
) -> Result<Response, AppError> {
    let (sub, email) = auth::require_author(&headers)?;
    let post = state
        .store
        .get_post(&slug)
        .await
        .ok_or_else(|| AppError::NotFound("no such post".to_string()))?;
    // Own posts, or ANY post for an admin (the admin panel edits every author's posts).
    if post.author_sub != sub && !auth::is_admin(&headers) {
        return Err(AppError::Forbidden("you can only edit your own posts".to_string()));
    }
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    let page = render_editor(EditorView {
        email: &email,
        heading: "Edit post",
        subhead: "Update the title, body, or publication state.",
        action: &format!("/edit/{}", esc(&post.slug)),
        csrf: &csrf,
        title_value: &post.title,
        body_value: &post.body_md,
        published: post.published,
        submit_label: "Save changes",
        cancel_href: &format!("/p/{}", esc(&post.slug)),
        delete_slug: Some(&post.slug),
    });
    Ok(html_with_cookie(page, set_cookie))
}

/// `POST /edit/{slug}` — update an own post (slug stays stable so existing links never break).
pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Form(form): Form<PostForm>,
) -> Result<Response, AppError> {
    let (sub, _email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let mut post = state
        .store
        .get_post(&slug)
        .await
        .ok_or_else(|| AppError::NotFound("no such post".to_string()))?;
    if post.author_sub != sub && !auth::is_admin(&headers) {
        return Err(AppError::Forbidden("you can only edit your own posts".to_string()));
    }

    let title = form.title.trim();
    if title.is_empty() {
        return Err(AppError::InvalidRequest("title is required".to_string()));
    }
    post.title = title.to_string();
    post.body_md = form.body.trim().to_string();
    post.published = form.published.is_some();
    post.updated_at = now_secs();
    state.store.update_post(&post).await?;
    tracing::info!(slug = %slug, "post updated");

    let actor = if post.author_email.is_empty() { &post.author_sub } else { &post.author_email };
    state.audit.emit(AuditEvent::info(
        "post.update",
        actor,
        &slug,
        if post.published { "published" } else { "draft" },
    ));

    // Re-chunk on edit (a now-draft post is de-indexed). Best-effort; never fails the update.
    crate::reindex_post(state.store.as_ref(), &post).await;

    Ok(redirect(&format!("/p/{slug}")))
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

/// `POST /delete/{slug}` — delete an own post, then bounce to the index.
pub async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Form(form): Form<DeleteForm>,
) -> Result<Response, AppError> {
    let (sub, _email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let post = state
        .store
        .get_post(&slug)
        .await
        .ok_or_else(|| AppError::NotFound("no such post".to_string()))?;
    if post.author_sub != sub && !auth::is_admin(&headers) {
        return Err(AppError::Forbidden("you can only delete your own posts".to_string()));
    }
    state.store.delete_post(&slug).await?;
    tracing::info!(slug = %slug, "post deleted");

    let actor = if post.author_email.is_empty() { &post.author_sub } else { &post.author_email };
    state.audit.emit(AuditEvent::notice("post.delete", actor, &slug, "delete"));

    // Drop the post's chunks from the ask index (best-effort; never fails the delete).
    crate::deindex_post(state.store.as_ref(), &slug).await;

    Ok(redirect("/"))
}

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------

/// A post is visible when it is published, or when the viewer is its author (own drafts).
fn visible_to(post: &Post, viewer_sub: Option<&str>) -> bool {
    post.published || viewer_sub == Some(post.author_sub.as_str())
}

/// How many related posts to show beneath an article.
const RELATED_LIMIT: usize = 3;

/// Render the "Related posts" block: the top [`RELATED_LIMIT`] OTHER PUBLISHED posts ranked by
/// keyword-overlap (title + body) to `current`. Drafts and the current post are excluded, so no
/// unpublished content ever leaks. Returns an empty string when nothing overlaps (block hidden).
fn render_related(current: &Post, candidates: &[Post]) -> String {
    let query = format!("{} {}", current.title, current.body_md);
    let terms = crate::index::tokenize(&query);
    if terms.is_empty() {
        return String::new();
    }

    let mut scored: Vec<(f64, &Post)> = candidates
        .iter()
        .filter(|p| p.published && p.slug != current.slug)
        .filter_map(|p| {
            let s = crate::index::doc_score(&terms, &p.title, &p.body_md);
            if s > 0.0 {
                Some((s, p))
            } else {
                None
            }
        })
        .collect();
    // Highest overlap first; ties broken newest-first then by slug for stable output.
    scored.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.1.created_at.cmp(&a.1.created_at))
            .then_with(|| a.1.slug.cmp(&b.1.slug))
    });
    scored.truncate(RELATED_LIMIT);
    if scored.is_empty() {
        return String::new();
    }

    let mut items = String::new();
    for (_, p) in &scored {
        items.push_str(&format!(
            r#"<li class="related__item">
  <a class="related__link" href="/p/{slug}">{title}</a>
  <span class="related__meta muted">{date}</span>
</li>"#,
            slug = esc(&p.slug),
            title = esc(&p.title),
            date = esc(&fmt_date(p.created_at)),
        ));
    }
    format!(
        r#"<aside class="related">
  <h2 class="related__title">Related posts</h2>
  <ul class="related__list">{items}</ul>
</aside>"#,
    )
}

/// One index card: title link, meta line, excerpt, and (own posts only) a draft badge + edit
/// link. Every interpolated field is HTML-escaped.
fn render_card(post: &Post, viewer_sub: Option<&str>) -> String {
    let is_owner = viewer_sub == Some(post.author_sub.as_str());
    let draft_badge = if !post.published {
        r#"<span class="badge badge-draft">Draft</span>"#
    } else {
        ""
    };
    // Admin-set featured flag: a small badge on the (published) index card.
    let featured_badge = if post.featured {
        r#"<span class="badge badge-featured">Featured</span>"#
    } else {
        ""
    };
    let owner_link = if is_owner {
        format!(
            r#" · <a class="card__edit" href="/edit/{slug}">Edit</a>"#,
            slug = esc(&post.slug)
        )
    } else {
        String::new()
    };
    format!(
        r#"<article class="card-post">
  <h2 class="card-post__title"><a href="/p/{slug}">{title}</a>{featured}{badge}</h2>
  <div class="card-post__meta">{date} · {author}{owner}</div>
  <p class="card-post__excerpt">{excerpt}</p>
</article>"#,
        slug = esc(&post.slug),
        title = esc(&post.title),
        featured = featured_badge,
        badge = draft_badge,
        date = esc(&fmt_date(post.created_at)),
        author = esc(&post.author_email),
        owner = owner_link,
        excerpt = esc(&markdown::excerpt(&post.body_md, 200)),
    )
}

/// Inputs for rendering the compose/edit form (one shared template).
struct EditorView<'a> {
    email: &'a str,
    heading: &'a str,
    subhead: &'a str,
    action: &'a str,
    csrf: &'a str,
    title_value: &'a str,
    body_value: &'a str,
    published: bool,
    submit_label: &'a str,
    cancel_href: &'a str,
    /// `Some(slug)` on the edit form -> render a separate delete form; `None` on compose.
    delete_slug: Option<&'a str>,
}

fn render_editor(v: EditorView<'_>) -> String {
    let delete_block = match v.delete_slug {
        Some(slug) => format!(
            r#"<div class="danger-zone">
  <div class="danger-zone__text"><strong>Delete this post</strong><span>Once deleted, it cannot be recovered.</span></div>
  <form class="inline-form" method="post" action="/delete/{slug}" onsubmit="return confirm('Delete this post? This cannot be undone.');">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <button class="btn btn-danger" type="submit">Delete</button>
  </form>
</div>"#,
            slug = esc(slug),
            csrf = esc(v.csrf),
        ),
        None => String::new(),
    };

    EDITOR_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{TOPBAR}}", &topbar(v.heading, v.email))
        .replace("{{HEADING}}", &esc(v.heading))
        .replace("{{SUBHEAD}}", &esc(v.subhead))
        .replace("{{ACTION}}", v.action)
        .replace("{{CSRF}}", &esc(v.csrf))
        .replace("{{TITLE_VALUE}}", &esc(v.title_value))
        .replace("{{BODY_VALUE}}", &esc(v.body_value))
        .replace(
            "{{PUBLISHED_CHECKED}}",
            if v.published { "checked" } else { "" },
        )
        .replace("{{SUBMIT_LABEL}}", &esc(v.submit_label))
        .replace("{{CANCEL_HREF}}", v.cancel_href)
        .replace("{{DELETE}}", &delete_block)
}

/// A 303 redirect (post/redirect/get).
fn redirect(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, HeaderValue::from_str(location).expect("valid location"))],
    )
        .into_response()
}

/// An HTML response, optionally attaching a freshly-minted CSRF `Set-Cookie`.
fn html_with_cookie(body: String, set_cookie: Option<String>) -> Response {
    let mut resp = Html(body).into_response();
    if let Some(c) = set_cookie {
        if let Ok(value) = HeaderValue::from_str(&c) {
            resp.headers_mut().insert(header::SET_COOKIE, value);
        }
    }
    resp
}
