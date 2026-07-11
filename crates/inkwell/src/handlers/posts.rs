//! Reading views + the SSO-gated compose / edit / delete flow.
//!
//! Reading (`GET /`, `GET /p/{slug}`) renders the markdown body to SANITIZED HTML. Authoring
//! (`/new`, `/edit/{slug}`, `/delete/{slug}`) is mounted behind the gateway `auth=sso` route:
//! the author identity is ALWAYS taken from the injected `X-Auth-Subject` / `X-Auth-Email`
//! (never a client field), and every state-changing POST is double-submit CSRF protected.
//! A post may be edited or deleted only by its own author.

use std::collections::BTreeMap;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::{Form, Json};
use serde::{Deserialize, Serialize};

use crate::audit::AuditEvent;
use crate::auth;
use crate::error::AppError;
use crate::handlers::{esc, fmt_date, page_shell, tag_chips};
use crate::markdown;
use crate::store::{Post, PostCursor};
use crate::{now_nanos, now_secs, unique_slug, AppState};

const LIST_HTML: &str = include_str!("../../templates/list.html");
const POST_HTML: &str = include_str!("../../templates/post.html");
const EDITOR_HTML: &str = include_str!("../../templates/editor.html");

/// Form body shared by compose + edit. Publication changes require an explicit [`PublishIntent`];
/// identity is NEVER taken from the form — only from the gateway headers.
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
    /// Browser-enhanced epoch seconds for a local-time scheduling choice. When absent, the server
    /// interprets `publish_at` as UTC so the no-JS form remains correct.
    #[serde(default)]
    pub publish_at_epoch: String,
    #[serde(default)]
    pub pinned: Option<String>,
    /// Explicit Writer Studio action: `save_draft`, `publish_now`, or `schedule`.
    /// A missing value means Draft on create and "preserve current publication state" on edit.
    #[serde(default)]
    pub intent: String,
    #[serde(default)]
    pub csrf_token: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublishIntent {
    SaveDraft,
    PublishNow,
    Schedule,
    Preserve,
}

impl PublishIntent {
    fn for_create(raw: &str) -> Result<Self, AppError> {
        match raw.trim() {
            "" | "save_draft" => Ok(Self::SaveDraft),
            "publish_now" => Ok(Self::PublishNow),
            "schedule" => Ok(Self::Schedule),
            other => Err(AppError::InvalidRequest(format!(
                "unknown publication intent: {other}"
            ))),
        }
    }

    fn for_update(raw: &str) -> Result<Self, AppError> {
        match raw.trim() {
            "" => Ok(Self::Preserve),
            "save_draft" => Ok(Self::SaveDraft),
            "publish_now" => Ok(Self::PublishNow),
            "schedule" => Ok(Self::Schedule),
            other => Err(AppError::InvalidRequest(format!(
                "unknown publication intent: {other}"
            ))),
        }
    }
}

#[derive(Serialize)]
struct SaveResponse {
    ok: bool,
    slug: String,
    state: &'static str,
    redirect: String,
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

#[derive(Debug, Deserialize, Default)]
pub struct EditorQuery {
    #[serde(default)]
    pub studio_saved: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct TagSuggestionsQuery {
    #[serde(default)]
    pub prefix: String,
    pub limit: Option<usize>,
}

#[derive(Serialize)]
struct TagSuggestionsResponse {
    items: Vec<String>,
}

/// `GET /api/tags?prefix=&limit=` — bounded autocomplete for Writer Studio. Suggestions are drawn
/// only from published posts plus the authenticated author's own drafts/scheduled posts, so one
/// author cannot infer another author's unpublished taxonomy. JSON is consumed with `textContent`.
pub async fn tag_suggestions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<TagSuggestionsQuery>,
) -> Result<Response, AppError> {
    let (sub, _) = auth::require_author(&headers)?;
    let prefix: String = query.prefix.trim().chars().take(40).collect();
    let prefix_lower = prefix.to_lowercase();
    let limit = query.limit.unwrap_or(8).clamp(1, 20);
    let posts = state
        .store
        .list_visible_posts(None, crate::config::MAX_PAGE, now_secs(), Some(&sub))
        .await;
    let mut by_slug = BTreeMap::new();
    for post in posts {
        for tag in crate::tags::parse_tags(&post.tags) {
            let safe_display = !tag
                .chars()
                .any(|c| c.is_control() || matches!(c, '<' | '>' | '&' | '"' | '\''));
            if safe_display
                && (prefix_lower.is_empty() || tag.to_lowercase().starts_with(&prefix_lower))
            {
                by_slug.entry(crate::tags::tag_slug(&tag)).or_insert(tag);
            }
        }
    }
    let items = by_slug.into_values().take(limit).collect();
    let mut response = Json(TagSuggestionsResponse { items }).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    Ok(response)
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
    let is_admin = auth::is_admin(&headers);

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

    let (hero, list_posts): (String, &[Post]) = if q.before.is_none() && !posts.is_empty() {
        (render_hero(&posts[0], viewer.as_deref(), now), &posts[1..])
    } else {
        (String::new(), &posts[..])
    };

    let mut cards = String::new();
    for p in list_posts {
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

    let fragment = LIST_HTML
        .replace("{{BLOG_TITLE}}", &esc(&settings.title))
        .replace("{{TAGLINE}}", &esc(&settings.tagline))
        .replace("{{HERO}}", &hero)
        .replace("{{PAGE_CLASS}}", "")
        .replace("{{MH_EYEBROW}}", "Publication")
        .replace("{{POSTS}}", &cards)
        .replace("{{PAGER}}", &pager);
    let theme = odyssey::resolve_theme(
        headers
            .get(axum::http::header::COOKIE)
            .and_then(|v| v.to_str().ok()),
    );
    let page = page_shell(
        &format!("{} · HOLDFAST", settings.title),
        "page-reading",
        true,
        &settings.title,
        &email,
        is_admin,
        theme,
        &fragment,
    );
    Html(page).into_response()
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
    let is_admin = auth::is_admin(&headers);
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

    let heading = label.clone();
    let fragment = LIST_HTML
        .replace("{{BLOG_TITLE}}", &esc(&heading))
        .replace("{{TAGLINE}}", &esc(&format!("Posts tagged “{label}”")))
        .replace("{{HERO}}", "")
        .replace("{{PAGE_CLASS}}", " ink-tagview")
        .replace("{{MH_EYEBROW}}", "Tagged")
        .replace("{{POSTS}}", &cards)
        .replace("{{PAGER}}", &pager);
    let theme = odyssey::resolve_theme(
        headers
            .get(axum::http::header::COOKIE)
            .and_then(|v| v.to_str().ok()),
    );
    let page = page_shell(
        &format!("{heading} · HOLDFAST"),
        "page-reading",
        true,
        &heading,
        &email,
        is_admin,
        theme,
        &fragment,
    );
    Html(page).into_response()
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
    let is_admin = auth::is_admin(&headers);

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
        r#"<div class="ink-byline"><span class="ink-avatar ink-avatar--lg">{initial}</span><div class="ink-byline__col"><span class="ink-byline__author">{author}</span><span class="ink-byline__meta">{date} · {mins} min read{state}</span></div></div>"#,
        initial = esc(&author_initial(&post.author_email)),
        author = esc(&post.author_email),
        date = esc(&fmt_date(post.created_at)),
        mins = read_minutes(&post.body_md),
        state = state_badge(&post, now),
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

    let fragment = POST_HTML
        .replace("{{TITLE}}", &esc(&post.title))
        .replace(
            "{{COVER}}",
            &render_cover(&post.cover_url, "article__cover", &post.title),
        )
        .replace("{{META}}", &meta)
        .replace("{{TAGS}}", &tag_chips(&post.tags))
        .replace("{{ACTIONS}}", &actions)
        .replace("{{BODY}}", &body_html)
        .replace("{{RELATED}}", &related);
    let theme = odyssey::resolve_theme(
        headers
            .get(axum::http::header::COOKIE)
            .and_then(|v| v.to_str().ok()),
    );
    let page = page_shell(
        &format!("{} · Inkwell", post.title),
        "page-reading",
        true,
        "Reading",
        &email,
        is_admin,
        theme,
        &fragment,
    );

    Ok(html_with_cookie(page, set_cookie))
}

// ---------------------------------------------------------------------------
// Compose
// ---------------------------------------------------------------------------

/// `GET /new` — the compose form.
pub async fn new_form(State(_state): State<AppState>, headers: HeaderMap) -> Response {
    let email = auth::display_email(&headers);
    let subject = auth::author_sub(&headers).unwrap_or_else(|| "anonymous".to_string());
    let recovery_scope = recovery_scope(&subject);
    let is_admin = auth::is_admin(&headers);
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let theme = odyssey::resolve_theme(
        headers
            .get(axum::http::header::COOKIE)
            .and_then(|v| v.to_str().ok()),
    );
    let page = render_editor(EditorView {
        email: &email,
        is_admin,
        theme,
        state_label: "draft",
        saved: false,
        heading: "New post",
        subhead: "Compose a post in Markdown. You are the author.",
        action: "/new",
        recovery_scope: &recovery_scope,
        csrf: &csrf,
        title_value: "",
        body_value: "",
        tags_value: "",
        cover_value: "",
        publish_at_value: "",
        pinned: false,
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
    let now = now_secs();
    let intent = PublishIntent::for_create(&form.intent)?;
    let (published, publish_at) = publication_from_intent(intent, &form, now, false, 0)?;
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
        published,
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

    Ok(save_response(&headers, &post))
}

// ---------------------------------------------------------------------------
// Live preview (progressive enhancement)
// ---------------------------------------------------------------------------

/// The Markdown-body payload for the live-preview endpoint.
#[derive(Debug, Deserialize)]
pub struct PreviewForm {
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// The rendered-preview envelope.
#[derive(Serialize)]
struct PreviewResponse {
    html: String,
}

/// `POST /api/preview` — render the editor's Markdown to the SAME sanitized HTML the published
/// post uses, for the live-preview pane. Author-gated + double-submit-CSRF-checked exactly like
/// the compose/edit POST it shadows; it is read-only (no store write), so it emits no audit
/// event. Returns `{ "html": "<sanitized>" }`. The HTML is safe because [`markdown::render_html`]
/// neutralizes raw HTML and scheme-restricts links — identical to the reading view.
pub async fn preview(
    headers: HeaderMap,
    Form(form): Form<PreviewForm>,
) -> Result<Response, AppError> {
    auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;
    let html = markdown::render_html(form.body.trim());
    Ok(axum::Json(PreviewResponse { html }).into_response())
}

// ---------------------------------------------------------------------------
// Edit
// ---------------------------------------------------------------------------

/// `GET /edit/{slug}` — the edit form for an own post.
pub async fn edit_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Query(query): Query<EditorQuery>,
) -> Result<Response, AppError> {
    let (sub, email) = auth::require_author(&headers)?;
    let is_admin = auth::is_admin(&headers);
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
    let state_label = publication_detail(&post, now_secs());
    let saved = query.studio_saved.as_deref() == Some(state_label);
    let recovery_scope = recovery_scope(&sub);
    let theme = odyssey::resolve_theme(
        headers
            .get(axum::http::header::COOKIE)
            .and_then(|v| v.to_str().ok()),
    );

    let page = render_editor(EditorView {
        email: &email,
        is_admin,
        theme,
        state_label,
        saved,
        heading: "Edit post",
        subhead: "Update the title, body, or publication state.",
        action: &format!("/edit/{}", esc(&post.slug)),
        recovery_scope: &recovery_scope,
        csrf: &csrf,
        title_value: &post.title,
        body_value: &post.body_md,
        tags_value: &post.tags,
        cover_value: &post.cover_url,
        publish_at_value: &format_publish_at_value(post.publish_at),
        pinned: post.pinned,
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
    let now = now_secs();
    let intent = PublishIntent::for_update(&form.intent)?;
    let (published, publish_at) =
        publication_from_intent(intent, &form, now, post.published, post.publish_at)?;
    post.publish_at = publish_at;
    post.published = published;
    post.pinned = form.pinned.is_some();
    post.bump_updated_at(now);
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
        publication_detail(&post, now),
    ));

    // Re-chunk on edit (a now-draft post is de-indexed). Best-effort; never fails the update.
    crate::reindex_post(state.store.as_ref(), &post).await;

    Ok(save_response(&headers, &post))
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

fn publication_from_intent(
    intent: PublishIntent,
    form: &PostForm,
    now: i64,
    current_published: bool,
    current_publish_at: i64,
) -> Result<(bool, i64), AppError> {
    match intent {
        PublishIntent::SaveDraft => Ok((false, 0)),
        PublishIntent::PublishNow => Ok((true, 0)),
        PublishIntent::Preserve => Ok((current_published, current_publish_at)),
        PublishIntent::Schedule => {
            let publish_at = if form.publish_at_epoch.trim().is_empty() {
                // No JavaScript: datetime-local is documented and interpreted as UTC.
                parse_publish_at(&form.publish_at)?
            } else {
                form.publish_at_epoch.trim().parse::<i64>().map_err(|_| {
                    AppError::InvalidRequest(
                        "publish_at_epoch must be UTC epoch seconds".to_string(),
                    )
                })?
            };
            if publish_at <= now {
                return Err(AppError::InvalidRequest(
                    "scheduled publication time must be in the future".to_string(),
                ));
            }
            Ok((true, publish_at))
        }
    }
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

fn save_response(headers: &HeaderMap, post: &Post) -> Response {
    let state = publication_detail(post, now_secs());
    let redirect_to = if state == "published" {
        format!("/p/{}", post.slug)
    } else {
        format!("/edit/{}?studio_saved={state}", post.slug)
    };
    let accepts_json = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|part| part.trim() == "application/json"));
    if accepts_json {
        let mut response = Json(SaveResponse {
            ok: true,
            slug: post.slug.clone(),
            state,
            redirect: redirect_to,
        })
        .into_response();
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        );
        response
    } else {
        redirect(&redirect_to)
    }
}

/// Stable non-sensitive browser-storage scope. The gateway subject never appears in HTML or in a
/// localStorage key; 96 bits of SHA-256 output are sufficient to avoid accidental user collisions.
fn recovery_scope(subject: &str) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(subject.as_bytes());
    hex::encode(&digest[..12])
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

fn read_minutes(body_md: &str) -> u64 {
    (body_md.split_whitespace().count() as u64)
        .div_ceil(200)
        .max(1)
}

fn author_initial(email: &str) -> String {
    if email.is_empty() || email == "—" {
        return String::new();
    }
    email
        .chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_default()
}

fn hero_letter(title: &str) -> String {
    title
        .chars()
        .find(|c| !c.is_whitespace())
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_else(|| "I".to_string())
}

fn state_badge(post: &Post, now: i64) -> &'static str {
    if !post.published {
        r#"<span class="badge badge-draft">Draft</span>"#
    } else if post.is_scheduled_at(now) {
        r#"<span class="badge badge-warn">Scheduled</span>"#
    } else {
        ""
    }
}

fn featured_badge(post: &Post) -> &'static str {
    if post.featured {
        r#"<span class="badge badge-featured">Featured</span>"#
    } else {
        ""
    }
}

fn pin_badge(post: &Post) -> &'static str {
    if post.pinned {
        r#"<span class="badge ink-pin">Pinned</span>"#
    } else {
        ""
    }
}

fn owner_link(post: &Post, viewer_sub: Option<&str>) -> String {
    if viewer_sub == Some(post.author_sub.as_str()) {
        format!(
            r#" · <a class="card__edit" href="/edit/{slug}">Edit</a>"#,
            slug = esc(&post.slug)
        )
    } else {
        String::new()
    }
}

fn render_hero(post: &Post, viewer_sub: Option<&str>, now: i64) -> String {
    let cover = if post.cover_url.is_empty() {
        format!(
            r#"<div class="ink-hero__fallback" aria-hidden="true"><span>{letter}</span></div>"#,
            letter = esc(&hero_letter(&post.title)),
        )
    } else {
        render_cover(&post.cover_url, "card-post__cover", &post.title)
    };
    format!(
        r#"<article class="ink-hero">
  {cover}
  <div class="ink-hero__pills">{pin}{featured}{badge}</div>
  <h2 class="ink-hero__title"><a href="/p/{slug}">{title}</a></h2>
  <p class="ink-hero__excerpt">{excerpt}</p>
  <div class="ink-byline"><span class="ink-avatar">{initial}</span><span>{author}</span><span>·</span><span>{date}</span><span>·</span><span>{mins} min read</span>{owner}</div>
  {tags}
</article>"#,
        cover = cover,
        pin = pin_badge(post),
        featured = featured_badge(post),
        badge = state_badge(post, now),
        slug = esc(&post.slug),
        title = esc(&post.title),
        excerpt = esc(&markdown::excerpt(&post.body_md, 280)),
        initial = esc(&author_initial(&post.author_email)),
        author = esc(&post.author_email),
        date = esc(&fmt_date(post.created_at)),
        mins = read_minutes(&post.body_md),
        owner = owner_link(post, viewer_sub),
        tags = tag_chips(&post.tags),
    )
}

/// One index card: title link, meta line, excerpt, and (own posts only) a draft badge + edit
/// link. Every interpolated field is HTML-escaped.
fn render_card(post: &Post, viewer_sub: Option<&str>, now: i64) -> String {
    let owner_link = owner_link(post, viewer_sub);
    format!(
        r#"<article class="card-post">
  {cover}
  <h2 class="card-post__title"><a href="/p/{slug}">{title}</a>{featured}{badge}{pin}</h2>
  <div class="card-post__meta"><span class="ink-avatar">{initial}</span>{author} · {date} · {mins} min read{owner}</div>
  <p class="card-post__excerpt">{excerpt}</p>
  {tags}
</article>"#,
        cover = render_cover(&post.cover_url, "card-post__cover", &post.title),
        slug = esc(&post.slug),
        title = esc(&post.title),
        featured = featured_badge(post),
        badge = state_badge(post, now),
        pin = pin_badge(post),
        initial = esc(&author_initial(&post.author_email)),
        author = esc(&post.author_email),
        date = esc(&fmt_date(post.created_at)),
        mins = read_minutes(&post.body_md),
        owner = owner_link,
        excerpt = esc(&markdown::excerpt(&post.body_md, 200)),
        tags = tag_chips(&post.tags),
    )
}

/// Inputs for rendering the compose/edit form (one shared template).
struct EditorView<'a> {
    email: &'a str,
    is_admin: bool,
    theme: &'a str,
    state_label: &'a str,
    saved: bool,
    heading: &'a str,
    subhead: &'a str,
    action: &'a str,
    recovery_scope: &'a str,
    csrf: &'a str,
    title_value: &'a str,
    body_value: &'a str,
    tags_value: &'a str,
    cover_value: &'a str,
    publish_at_value: &'a str,
    pinned: bool,
    cancel_href: &'a str,
    /// `Some(slug)` on the edit form -> render a separate delete form; `None` on compose.
    delete_slug: Option<&'a str>,
}

fn render_editor(v: EditorView<'_>) -> String {
    let state_name = match v.state_label {
        "scheduled" => "Scheduled",
        "published" => "Published",
        _ => "Draft",
    };
    let state_text = if v.saved {
        format!("Saved · {state_name}")
    } else {
        state_name.to_string()
    };
    let state_pill_html = format!(
        r#"<span class="writer-state writer-state--{state}" id="writerStatus" data-state="{state}" role="status" aria-live="polite"><span class="writer-state__dot" aria-hidden="true"></span><span id="writerStatusText">{text}</span></span>"#,
        state = esc(v.state_label),
        text = esc(&state_text),
    );
    let preserve_action = if v.delete_slug.is_some() {
        r#"<button class="btn btn-secondary" type="submit" name="intent" value="" data-final-state="preserve">Save changes</button>"#
    } else {
        ""
    };
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

    let fragment = EDITOR_HTML
        .replace("{{HEADING}}", &esc(v.heading))
        .replace("{{SUBHEAD}}", &esc(v.subhead))
        .replace("{{ACTION}}", v.action)
        .replace("{{RECOVERY_SCOPE}}", &esc(v.recovery_scope))
        .replace("{{CSRF}}", &esc(v.csrf))
        .replace("{{TITLE_VALUE}}", &esc(v.title_value))
        .replace("{{BODY_VALUE}}", &esc(v.body_value))
        .replace("{{TAGS_VALUE}}", &esc(v.tags_value))
        .replace("{{COVER_VALUE}}", &esc(v.cover_value))
        .replace("{{PUBLISH_AT_VALUE}}", &esc(v.publish_at_value))
        .replace("{{PINNED_CHECKED}}", if v.pinned { "checked" } else { "" })
        .replace("{{STATE_PILL}}", &state_pill_html)
        .replace("{{STATE_KEY}}", &esc(v.state_label))
        .replace("{{PRESERVE_ACTION}}", preserve_action)
        .replace("{{CANCEL_HREF}}", v.cancel_href)
        .replace("{{DELETE}}", &delete_block);
    page_shell(
        &format!("{} · Inkwell", v.heading),
        "page-console",
        false,
        v.heading,
        v.email,
        v.is_admin,
        v.theme,
        &fragment,
    )
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
