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
use crate::handlers::{esc, fmt_date, tag_chips, topbar, APP_CSS};
use crate::markdown;
use crate::store::{Post, PostCursor};
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
    /// Comma-separated tags (normalized on save via [`crate::tags::normalize`]).
    #[serde(default)]
    pub tags: String,
    /// Optional cover image, pasted as an Aperture share URL. Validated to an estate host on save
    /// via [`sanitize_cover`]; empty (or omitted) means no cover.
    #[serde(default)]
    pub cover_url: String,
    /// Optional UTC datetime-local value. Blank or omitted keeps the legacy immediate behavior.
    #[serde(default)]
    pub publish_at: String,
    #[serde(default)]
    pub pinned: Option<String>,
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
    let now = now_secs();
    let posts = state
        .store
        .list_visible_posts(before, limit, now, viewer.as_deref())
        .await;

    // A FULL page means more history may exist: the next cursor is the LAST (oldest) row of THIS
    // store page — derived before visibility filtering so drafts never desync the keyset position.
    let next_cursor = if posts.len() as i64 == limit {
        posts
            .last()
            .map(|p| format_cursor(&PostCursor::from_post(p)))
    } else {
        None
    };

    let mut cards = String::new();
    for p in &posts {
        cards.push_str(&render_card(p, viewer.as_deref(), now));
    }
    if posts.is_empty() && next_cursor.is_none() {
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

/// `GET /tag/{slug}` — one keyset page of posts carrying the tag `slug`, newest-first. Reuses the
/// index's `list_posts` + in-handler filtering (visibility THEN tag membership) and the same
/// `?before=`/`?limit=` cursor, so drafts never leak and the whole tagged archive stays reachable
/// page by page. The "Load older" cursor is derived from the store page's LAST row (before
/// filtering) exactly like the index, so paging never desyncs.
pub async fn tag_index(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(tag_slug): Path<String>,
    Query(q): Query<IndexQuery>,
) -> Response {
    let viewer = auth::author_sub(&headers);
    let email = auth::display_email(&headers);
    let settings = state.store.get_settings().await;

    let before = q.before.as_deref().and_then(parse_before);
    let limit = crate::config::clamp_page_with_default(q.limit, settings.posts_per_page);
    let now = now_secs();
    let posts = state
        .store
        .list_visible_posts(before, limit, now, viewer.as_deref())
        .await;

    let next_cursor = if posts.len() as i64 == limit {
        posts
            .last()
            .map(|p| format_cursor(&PostCursor::from_post(p)))
    } else {
        None
    };

    // Recover a display label for the tag from the first matching post (the URL only carries the
    // slug); fall back to the slug itself when this page has no match to name it.
    let mut cards = String::new();
    let mut shown = 0usize;
    let mut label: Option<String> = None;
    for p in &posts {
        if !crate::tags::has_tag(&p.tags, &tag_slug) {
            continue;
        }
        if label.is_none() {
            label = crate::tags::parse_tags(&p.tags)
                .into_iter()
                .find(|t| crate::tags::tag_slug(t) == tag_slug);
        }
        shown += 1;
        cards.push_str(&render_card(p, viewer.as_deref(), now));
    }
    let label = label.unwrap_or_else(|| tag_slug.clone());

    if shown == 0 && next_cursor.is_none() {
        cards.push_str(&format!(
            r#"<div class="empty-state"><h2>No posts tagged “{tag}”</h2><p>Nothing here yet. <a href="/">Back to all posts</a>.</p></div>"#,
            tag = esc(&label),
        ));
    }

    let pager = match &next_cursor {
        Some(cursor) => format!(
            r#"<nav class="post-list__pager"><a class="btn btn-secondary" href="/tag/{slug}?before={cursor}">Load older</a></nav>"#,
            slug = esc(&tag_slug),
            cursor = esc(cursor),
        ),
        None => String::new(),
    };

    let heading = format!("#{label}");
    let body = LIST_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{TOPBAR}}", &topbar(&heading, &email))
        .replace("{{BLOG_TITLE}}", &esc(&heading))
        .replace("{{TAGLINE}}", &esc(&format!("Posts tagged “{label}”")))
        .replace("{{POSTS}}", &cards)
        .replace("{{PAGER}}", &pager);
    Html(body).into_response()
}

/// Parse a `?before=<created_at>_<id>` keyset cursor into `(created_at, id)`. `created_at` is a
/// plain integer (no `_`) and inkwell post ids are `post_<nanos>` (they DO contain `_`), so the
/// split is on the FIRST `_`: everything after it is the id, round-tripping the cursor exactly.
/// Returns `None` for anything malformed (treated as "no cursor" — the newest page).
fn parse_before(raw: &str) -> Option<PostCursor> {
    for (prefix, pinned) in [("1_", true), ("0_", false)] {
        if let Some(rest) = raw.strip_prefix(prefix) {
            let (ts, id) = rest.split_once('_')?;
            let ts: i64 = ts.parse().ok()?;
            if id.is_empty() {
                return None;
            }
            return Some(PostCursor {
                pinned,
                created_at: ts,
                id: id.to_string(),
            });
        }
    }
    let (ts, id) = raw.split_once('_')?;
    let ts: i64 = ts.parse().ok()?;
    if id.is_empty() {
        return None;
    }
    Some(PostCursor {
        pinned: false,
        created_at: ts,
        id: id.to_string(),
    })
}

fn format_cursor(cursor: &PostCursor) -> String {
    format!(
        "{}_{}_{}",
        if cursor.pinned { 1 } else { 0 },
        cursor.created_at,
        cursor.id
    )
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

    let now = now_secs();
    let post = state
        .store
        .get_visible_post(&slug, now, viewer.as_deref())
        .await
        .ok_or_else(|| AppError::NotFound("no such post".to_string()))?;

    let is_owner = viewer.as_deref() == Some(post.author_sub.as_str());
    // The owner gets edit/delete controls; the delete form needs a CSRF token.
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    let meta = format!(
        "{date} · {author}{draft}",
        date = fmt_date(post.created_at),
        author = post.author_email,
        draft = if !post.published {
            " · Draft"
        } else if post.is_scheduled_at(now) {
            " · Scheduled"
        } else {
            ""
        },
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
    let related_posts = state
        .store
        .related_posts_by_tags(&post.slug, &post.tags, now, RELATED_LIMIT as i64)
        .await;
    let related = render_related(&related_posts);

    let page = POST_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{TOPBAR}}", &topbar("Reading", &email))
        .replace("{{TITLE_TEXT}}", &esc(&post.title))
        .replace("{{TITLE}}", &esc(&post.title))
        .replace(
            "{{COVER}}",
            &render_cover(&post.cover_url, "article__cover", &post.title),
        )
        .replace("{{META}}", &esc(&meta))
        .replace("{{TAGS}}", &tag_chips(&post.tags))
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
        tags_value: "",
        cover_value: "",
        publish_at_value: "",
        published: true,
        pinned: false,
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
    let cover_url = sanitize_cover(&form.cover_url)?;
    let publish_at = parse_publish_at(&form.publish_at)?;
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
        publish_at,
        featured: false,
        pinned: form.pinned.is_some(),
        tags: crate::tags::normalize(&form.tags),
        cover_url,
    };
    state.store.create_post(&post).await?;
    tracing::info!(slug = %slug, "post created");

    let actor = if post.author_email.is_empty() {
        &post.author_sub
    } else {
        &post.author_email
    };
    state.audit.emit(AuditEvent::info(
        "post.create",
        actor,
        &slug,
        publication_detail(&post, now),
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
        return Err(AppError::Forbidden(
            "you can only edit your own posts".to_string(),
        ));
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
        tags_value: &post.tags,
        cover_value: &post.cover_url,
        publish_at_value: &format_publish_at_value(post.publish_at),
        published: post.published,
        pinned: post.pinned,
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
        return Err(AppError::Forbidden(
            "you can only edit your own posts".to_string(),
        ));
    }

    let title = form.title.trim();
    if title.is_empty() {
        return Err(AppError::InvalidRequest("title is required".to_string()));
    }
    post.title = title.to_string();
    post.body_md = form.body.trim().to_string();
    post.tags = crate::tags::normalize(&form.tags);
    post.cover_url = sanitize_cover(&form.cover_url)?;
    post.publish_at = parse_publish_at(&form.publish_at)?;
    post.published = form.published.is_some();
    post.pinned = form.pinned.is_some();
    post.updated_at = now_secs();
    state.store.update_post(&post).await?;
    tracing::info!(slug = %slug, "post updated");

    let actor = if post.author_email.is_empty() {
        &post.author_sub
    } else {
        &post.author_email
    };
    state.audit.emit(AuditEvent::info(
        "post.update",
        actor,
        &slug,
        publication_detail(&post, now_secs()),
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
        return Err(AppError::Forbidden(
            "you can only delete your own posts".to_string(),
        ));
    }
    state.store.delete_post(&slug).await?;
    tracing::info!(slug = %slug, "post deleted");

    let actor = if post.author_email.is_empty() {
        &post.author_sub
    } else {
        &post.author_email
    };
    state
        .audit
        .emit(AuditEvent::notice("post.delete", actor, &slug, "delete"));

    // Drop the post's chunks from the ask index (best-effort; never fails the delete).
    crate::deindex_post(state.store.as_ref(), &slug).await;

    Ok(redirect("/"))
}

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------

/// Validate a submitted cover URL. Empty is fine (no cover); otherwise it MUST be an estate image
/// URL (an Aperture share link), so the rendered `<img src>` can never point at an arbitrary host.
/// Fails loud with a 400 rather than silently dropping a mistyped URL.
fn sanitize_cover(raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if markdown::is_estate_image_url(trimmed) {
        Ok(trimmed.to_string())
    } else {
        Err(AppError::InvalidRequest(
            "cover image must be an Aperture share URL (https://drive.w33d.xyz/s/…)".to_string(),
        ))
    }
}

/// Render a stored cover image as a sanitized `<img>` wrapped in `wrapper_class`. Re-checks the
/// estate host (defense-in-depth) and escapes both the URL and the alt text; returns the empty
/// string when there is no cover, so the block is simply omitted.
fn render_cover(cover_url: &str, wrapper_class: &str, alt: &str) -> String {
    if cover_url.is_empty() || !markdown::is_estate_image_url(cover_url) {
        return String::new();
    }
    format!(
        r#"<div class="{cls}"><img src="{src}" alt="{alt}" loading="lazy"></div>"#,
        cls = wrapper_class,
        src = esc(cover_url),
        alt = esc(alt),
    )
}

fn parse_publish_at(raw: &str) -> Result<i64, AppError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(0);
    }
    let (date, time) = raw
        .split_once('T')
        .ok_or_else(|| AppError::InvalidRequest("publish_at must be a UTC datetime".to_string()))?;
    let mut d = date.split('-');
    let year = parse_year(d.next())?;
    let month = parse_part(d.next(), "publish_at month")?;
    let day = parse_part(d.next(), "publish_at day")?;
    if d.next().is_some() {
        return Err(AppError::InvalidRequest(
            "publish_at date is invalid".to_string(),
        ));
    }

    let mut t = time.split(':');
    let hour = parse_part(t.next(), "publish_at hour")?;
    let minute = parse_part(t.next(), "publish_at minute")?;
    let second = match t.next() {
        Some(raw_second) => {
            let whole = raw_second
                .split_once('.')
                .map(|(s, _)| s)
                .unwrap_or(raw_second);
            parse_part(Some(whole), "publish_at second")?
        }
        None => 0,
    };
    if t.next().is_some() {
        return Err(AppError::InvalidRequest(
            "publish_at time is invalid".to_string(),
        ));
    }

    let month = time::Month::try_from(month)
        .map_err(|_| AppError::InvalidRequest("publish_at month is invalid".to_string()))?;
    let date = time::Date::from_calendar_date(year, month, day)
        .map_err(|_| AppError::InvalidRequest("publish_at date is invalid".to_string()))?;
    let time = time::Time::from_hms(hour, minute, second)
        .map_err(|_| AppError::InvalidRequest("publish_at time is invalid".to_string()))?;
    Ok(time::PrimitiveDateTime::new(date, time)
        .assume_utc()
        .unix_timestamp())
}

fn parse_part(raw: Option<&str>, name: &str) -> Result<u8, AppError> {
    raw.filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::InvalidRequest(format!("{name} is required")))?
        .parse::<u8>()
        .map_err(|_| AppError::InvalidRequest(format!("{name} is invalid")))
}

fn parse_year(raw: Option<&str>) -> Result<i32, AppError> {
    raw.filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::InvalidRequest("publish_at year is required".to_string()))?
        .parse::<i32>()
        .map_err(|_| AppError::InvalidRequest("publish_at year is invalid".to_string()))
}

fn format_publish_at_value(secs: i64) -> String {
    if secs <= 0 {
        return String::new();
    }
    match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => format!(
            "{year:04}-{mon:02}-{day:02}T{h:02}:{m:02}",
            year = dt.year(),
            mon = u8::from(dt.month()),
            day = dt.day(),
            h = dt.hour(),
            m = dt.minute(),
        ),
        Err(_) => String::new(),
    }
}

fn publication_detail(post: &Post, now: i64) -> &'static str {
    if !post.published {
        "draft"
    } else if post.is_scheduled_at(now) {
        "scheduled"
    } else {
        "published"
    }
}

/// How many related posts to show beneath an article.
const RELATED_LIMIT: usize = 3;

/// Render the "Related posts" block from the store-ranked shared-tag overlap results.
fn render_related(posts: &[Post]) -> String {
    if posts.is_empty() {
        return String::new();
    }

    let mut items = String::new();
    for p in posts {
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
fn render_card(post: &Post, viewer_sub: Option<&str>, now: i64) -> String {
    let is_owner = viewer_sub == Some(post.author_sub.as_str());
    let state_badge = if !post.published {
        r#"<span class="badge badge-draft">Draft</span>"#
    } else if post.is_scheduled_at(now) {
        r#"<span class="badge badge-warn">Scheduled</span>"#
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
  {cover}
  <h2 class="card-post__title"><a href="/p/{slug}">{title}</a>{featured}{badge}</h2>
  <div class="card-post__meta">{date} · {author}{owner}</div>
  <p class="card-post__excerpt">{excerpt}</p>
  {tags}
</article>"#,
        cover = render_cover(&post.cover_url, "card-post__cover", &post.title),
        slug = esc(&post.slug),
        title = esc(&post.title),
        featured = featured_badge,
        badge = state_badge,
        date = esc(&fmt_date(post.created_at)),
        author = esc(&post.author_email),
        owner = owner_link,
        excerpt = esc(&markdown::excerpt(&post.body_md, 200)),
        tags = tag_chips(&post.tags),
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
    tags_value: &'a str,
    cover_value: &'a str,
    publish_at_value: &'a str,
    published: bool,
    pinned: bool,
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
        .replace("{{TAGS_VALUE}}", &esc(v.tags_value))
        .replace("{{COVER_VALUE}}", &esc(v.cover_value))
        .replace("{{PUBLISH_AT_VALUE}}", &esc(v.publish_at_value))
        .replace(
            "{{PUBLISHED_CHECKED}}",
            if v.published { "checked" } else { "" },
        )
        .replace("{{PINNED_CHECKED}}", if v.pinned { "checked" } else { "" })
        .replace("{{SUBMIT_LABEL}}", &esc(v.submit_label))
        .replace("{{CANCEL_HREF}}", v.cancel_href)
        .replace("{{DELETE}}", &delete_block)
}

/// A 303 redirect (post/redirect/get).
fn redirect(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(
            header::LOCATION,
            HeaderValue::from_str(location).expect("valid location"),
        )],
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
