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
use crate::handlers::{esc, fmt_date, page_shell, post_excerpt, tag_chips, PageMeta, PageShell};
use crate::markdown;
use crate::store::{
    AutosaveOutcome, DeletePostCommand, DeletePostOutcome, DeletePostScope, Post, PostCursor,
    SavePostCommand, SavePostOutcome, WriterAutosave,
};
use crate::{now_nanos, now_secs, unique_slug, AppState};

const LIST_HTML: &str = include_str!("../../templates/list.html");
const POST_HTML: &str = include_str!("../../templates/post.html");
const EDITOR_HTML: &str = include_str!("../../templates/editor.html");
const PUBLIC_REPRESENTATION_VARY: &str = "Cookie, X-Auth-Subject, X-Auth-Email, X-Auth-Groups";

pub const CUSTOM_EXCERPT_MAX: usize = 500;
pub const META_TITLE_MAX: usize = 200;
pub const META_DESCRIPTION_MAX: usize = 500;
pub const CANONICAL_URL_MAX: usize = 2_048;
pub const SOCIAL_TITLE_MAX: usize = 200;
pub const SOCIAL_DESCRIPTION_MAX: usize = 500;
pub const SOCIAL_IMAGE_MAX: usize = 600;
const JS_MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

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
    /// Optional author-written summary for cards and feeds.
    #[serde(default)]
    pub custom_excerpt: String,
    /// Optional search metadata. Text values are server-truncated to the documented limits.
    #[serde(default)]
    pub meta_title: String,
    #[serde(default)]
    pub meta_description: String,
    /// Optional absolute HTTP(S) canonical URL.
    #[serde(default)]
    pub canonical_url: String,
    /// Optional social-card overrides. The image follows the trusted Aperture URL policy.
    #[serde(default)]
    pub social_title: String,
    #[serde(default)]
    pub social_description: String,
    #[serde(default)]
    pub social_image: String,
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
    /// Optimistic-concurrency token rendered by the edit page. Missing/stale values never fall back
    /// to last-write-wins; the submitted text is retained as a private recovery copy.
    #[serde(default)]
    pub expected_version: String,
    #[serde(default)]
    pub expected_post_id: String,
    /// Random edit-session id. It scopes server autosave ownership and is consumed on a successful
    /// authoritative save.
    #[serde(default)]
    pub autosave_session: String,
    #[serde(default)]
    pub client_seq: String,
    /// Optional local Content Library return target. It is accepted only after strict path
    /// validation and never participates in authoring or authorization.
    #[serde(default)]
    pub return_to: String,
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

/// Delete authority combines gateway identity with the immutable id/version rendered by the
/// current post. Defaults make every pre-CAS legacy form fail closed.
#[derive(Debug, Deserialize)]
pub struct DeleteForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub expected_post_id: String,
    #[serde(default)]
    pub expected_version: String,
    #[serde(default)]
    pub return_to: String,
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
    #[serde(default)]
    pub recover: Option<String>,
    #[serde(default)]
    pub return_to: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RestoreForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub expected_version: String,
    #[serde(default)]
    pub expected_post_id: String,
    #[serde(default)]
    pub return_to: String,
}

#[derive(Serialize)]
struct AutosaveResponse {
    ok: bool,
    client_seq: i64,
    base_version: i64,
}

#[derive(Serialize)]
struct SaveConflictResponse {
    ok: bool,
    conflict: bool,
    current_version: i64,
    recover: String,
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
    let head_title = format!("{} · HOLDFAST", settings.title);
    let page = page_shell(PageShell {
        head_title: &head_title,
        body_class: "page-reading",
        rss: true,
        nav_title: &settings.title,
        email: &email,
        is_admin,
        theme,
        fragment: &fragment,
        metadata: None,
    });
    public_read_response(
        Html(page).into_response(),
        &headers,
        viewer.as_deref(),
        is_admin,
    )
}

/// `GET /tag/{slug}` — one keyset page of posts carrying the tag `slug`, newest-first. It traverses
/// authoritative visible-post pages until it fills a tag page (or reaches the bounded continuation),
/// so sparse tags remain reachable beyond the generic `MAX_PAGE` window without leaking drafts.
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
    let (posts, next_cursor) = scan_tag_page(
        &state,
        &tag_slug,
        before,
        limit as usize,
        now,
        viewer.as_deref(),
    )
    .await;

    // Recover a display label for the tag from the first matching post (the URL only carries the
    // slug); fall back to the slug itself when this page has no match to name it.
    let mut cards = String::new();
    let mut shown = 0usize;
    let mut label: Option<String> = None;
    for p in &posts {
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
    let head_title = format!("{heading} · HOLDFAST");
    let page = page_shell(PageShell {
        head_title: &head_title,
        body_class: "page-reading",
        rss: true,
        nav_title: &heading,
        email: &email,
        is_admin,
        theme,
        fragment: &fragment,
        metadata: None,
    });
    public_read_response(
        Html(page).into_response(),
        &headers,
        viewer.as_deref(),
        is_admin,
    )
}

/// Traverse authoritative visible-post pages until one full tag page (plus one look-ahead match)
/// is found. This fixes the old "paginate everything, then filter" behavior where sparse tags
/// produced empty pages and older tagged posts disappeared behind the generic `MAX_PAGE` window.
///
/// Work is bounded to [`crate::config::TAG_SCAN_POST_LIMIT`] rows per request. If that bound
/// is reached, the continuation cursor points at the last scanned authoritative row, so no content
/// is skipped and the caller can continue the traversal on the next request.
async fn scan_tag_page(
    state: &AppState,
    tag_slug: &str,
    before: Option<PostCursor>,
    limit: usize,
    now: i64,
    viewer_sub: Option<&str>,
) -> (Vec<Post>, Option<String>) {
    let wanted = limit.max(1);
    let mut matches = Vec::with_capacity(wanted.saturating_add(1));
    let mut cursor = before;
    let mut scanned = 0usize;
    let mut exhausted = false;

    while scanned < crate::config::TAG_SCAN_POST_LIMIT && matches.len() <= wanted {
        let remaining = crate::config::TAG_SCAN_POST_LIMIT - scanned;
        let batch_limit = remaining.min(crate::config::MAX_PAGE as usize).max(1);
        let batch = state
            .store
            .list_visible_posts(cursor.clone(), batch_limit as i64, now, viewer_sub)
            .await;
        if batch.is_empty() {
            exhausted = true;
            break;
        }
        let batch_len = batch.len();
        for post in batch {
            scanned += 1;
            cursor = Some(PostCursor::from_post(&post));
            if crate::tags::has_tag(&post.tags, tag_slug) {
                matches.push(post);
                if matches.len() > wanted {
                    break;
                }
            }
        }
        if matches.len() > wanted {
            break;
        }
        if batch_len < batch_limit {
            exhausted = true;
            break;
        }
    }

    if matches.len() > wanted {
        matches.truncate(wanted);
        let next = matches
            .last()
            .map(|post| format_cursor(&PostCursor::from_post(post)));
        (matches, next)
    } else if !exhausted && scanned >= crate::config::TAG_SCAN_POST_LIMIT {
        (matches, cursor.as_ref().map(format_cursor))
    } else {
        (matches, None)
    }
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
    // Only an owner representation needs a CSRF token. Anonymous public reads remain a genuinely
    // cacheable representation and never mint a per-browser cookie.
    let (csrf, set_cookie) = if is_owner {
        auth::ensure_csrf(&headers)
    } else {
        (String::new(), None)
    };

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
    <input type="hidden" name="expected_post_id" value="{post_id}">
    <input type="hidden" name="expected_version" value="{version}">
    <button class="btn btn-danger btn-sm" type="submit">Delete</button>
  </form>
</div>"#,
            slug = esc(&post.slug),
            csrf = esc(&csrf),
            post_id = esc(&post.id),
            version = post.edit_version,
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
    let page_meta = if post.is_public_at(now) {
        public_post_meta(&post)
    } else {
        PageMeta {
            robots: Some("noindex,nofollow".to_string()),
            ..PageMeta::default()
        }
    };
    let document_title = if post.is_public_at(now) && !post.meta_title.trim().is_empty() {
        post.meta_title.trim()
    } else {
        post.title.as_str()
    };
    let head_title = format!("{document_title} · Inkwell");
    let page = page_shell(PageShell {
        head_title: &head_title,
        body_class: "page-reading",
        rss: true,
        nav_title: "Reading",
        email: &email,
        is_admin,
        theme,
        fragment: &fragment,
        metadata: Some(&page_meta),
    });

    Ok(public_read_response(
        html_with_cookie(page, set_cookie),
        &headers,
        viewer.as_deref(),
        is_admin,
    ))
}

// ---------------------------------------------------------------------------
// Compose
// ---------------------------------------------------------------------------

/// `GET /new` — the compose form.
pub async fn new_form(
    State(_state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<EditorQuery>,
) -> Response {
    let email = auth::display_email(&headers);
    let subject = auth::author_sub(&headers).unwrap_or_else(|| "anonymous".to_string());
    let recovery_scope = recovery_scope(&subject);
    let is_admin = auth::is_admin(&headers);
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let return_to = validated_return_to(query.return_to.as_deref());
    let cancel_href = if return_to.is_empty() {
        "/".to_string()
    } else {
        return_to.clone()
    };
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
        autosave_url: "",
        autosave_session: "",
        expected_version: 0,
        expected_post_id: "",
        client_seq: 0,
        history_href: "",
        return_to: &return_to,
        recovery_notice: "",
        recovery_scope: &recovery_scope,
        csrf: &csrf,
        title_value: "",
        body_value: "",
        tags_value: "",
        cover_value: "",
        custom_excerpt_value: "",
        meta_title_value: "",
        meta_description_value: "",
        canonical_url_value: "",
        social_title_value: "",
        social_description_value: "",
        social_image_value: "",
        publish_at_value: "",
        pinned: false,
        cancel_href: &cancel_href,
        delete_slug: None,
    });
    private_no_store(html_with_cookie(page, set_cookie))
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
    let publication_meta = publication_metadata(&form)?;
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
        edit_version: 1,
        published,
        publish_at,
        featured: false,
        pinned: form.pinned.is_some(),
        tags: crate::tags::normalize(&form.tags),
        cover_url,
        custom_excerpt: publication_meta.custom_excerpt,
        meta_title: publication_meta.meta_title,
        meta_description: publication_meta.meta_description,
        canonical_url: publication_meta.canonical_url,
        social_title: publication_meta.social_title,
        social_description: publication_meta.social_description,
        social_image: publication_meta.social_image,
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

    Ok(save_response(&headers, &post, &form.return_to))
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
    Ok(private_no_store(
        axum::Json(PreviewResponse { html }).into_response(),
    ))
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
        .get_post_authoritative(&slug)
        .await?
        .ok_or_else(|| AppError::NotFound("no such post".to_string()))?;
    // Own posts, or ANY post for an admin (the admin panel edits every author's posts).
    if post.author_sub != sub && !auth::is_admin(&headers) {
        return Err(AppError::Forbidden(
            "you can only edit your own posts".to_string(),
        ));
    }
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let return_to = validated_return_to(query.return_to.as_deref());
    let cancel_href = if return_to.is_empty() {
        format!("/p/{}", esc(&post.slug))
    } else {
        return_to.clone()
    };
    let history_href = if return_to.is_empty() {
        format!("/edit/{}/history", esc(&post.slug))
    } else {
        format!(
            "/edit/{}/history?return_to={}",
            esc(&post.slug),
            crate::handlers::library::percent_encode(&return_to)
        )
    };
    let state_label = publication_detail(&post, now_secs());
    let saved = query.studio_saved.as_deref() == Some(state_label);
    let recovery_scope = recovery_scope(&sub);
    let autosave_session = query
        .recover
        .as_deref()
        .filter(|session| valid_autosave_session(session))
        .map(str::to_string)
        .unwrap_or_else(auth::new_csrf_token);
    let recovered = state
        .store
        .get_writer_autosave(&autosave_session, &sub, now_secs())
        .await?
        .filter(|autosave| autosave.post_id == post.id);
    let mut editor_post = post.clone();
    let mut publish_at_value = format_publish_at_value(post.publish_at);
    let recovery_notice = if let Some(autosave) = &recovered {
        editor_post.title = autosave.title.clone();
        editor_post.body_md = autosave.body_md.clone();
        editor_post.tags = autosave.tags.clone();
        editor_post.cover_url = autosave.cover_url.clone();
        editor_post.custom_excerpt = autosave.custom_excerpt.clone();
        editor_post.meta_title = autosave.meta_title.clone();
        editor_post.meta_description = autosave.meta_description.clone();
        editor_post.canonical_url = autosave.canonical_url.clone();
        editor_post.social_title = autosave.social_title.clone();
        editor_post.social_description = autosave.social_description.clone();
        editor_post.social_image = autosave.social_image.clone();
        editor_post.pinned = autosave.pinned;
        publish_at_value = autosave.publish_at.clone();
        format!(
            r#"<div class="draftbar server-recovery"><span>Private conflict recovery copy loaded · review it against current server version {} before saving.</span></div>"#,
            autosave.base_version
        )
    } else {
        String::new()
    };
    let client_seq = recovered
        .as_ref()
        .map(|autosave| autosave.client_seq)
        .unwrap_or(0);
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
        autosave_url: &format!("/api/writer/autosave/{}", esc(&post.slug)),
        autosave_session: &autosave_session,
        expected_version: post.edit_version,
        expected_post_id: &post.id,
        client_seq,
        history_href: &history_href,
        return_to: &return_to,
        recovery_notice: &recovery_notice,
        recovery_scope: &recovery_scope,
        csrf: &csrf,
        title_value: &editor_post.title,
        body_value: &editor_post.body_md,
        tags_value: &editor_post.tags,
        cover_value: &editor_post.cover_url,
        custom_excerpt_value: &editor_post.custom_excerpt,
        meta_title_value: &editor_post.meta_title,
        meta_description_value: &editor_post.meta_description,
        canonical_url_value: &editor_post.canonical_url,
        social_title_value: &editor_post.social_title,
        social_description_value: &editor_post.social_description,
        social_image_value: &editor_post.social_image,
        publish_at_value: &publish_at_value,
        pinned: editor_post.pinned,
        cancel_href: &cancel_href,
        delete_slug: Some(&post.slug),
    });
    Ok(private_no_store(html_with_cookie(page, set_cookie)))
}

/// `POST /edit/{slug}` — update an own post (slug stays stable so existing links never break).
pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Form(form): Form<PostForm>,
) -> Result<Response, AppError> {
    let (sub, email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let Some(mut post) = state.store.get_post_authoritative(&slug).await? else {
        // An editor form can outlive deletion even when the slug has not been reused. Treat that
        // exactly like every other immutable-identity loss: return only the private submission
        // recovery surface, never a pre-CAS 404 that discards the submitted body.
        return Ok(identity_conflict_response(&headers, &form.body));
    };
    let submitted_post_id = form.expected_post_id.trim();
    let legacy_form = submitted_post_id.is_empty();
    // A modern form is bound to the immutable post id. Handle a replaced identity before
    // author comparison: the authenticated caller gets only their own submitted body back, while
    // no replacement owner or content is disclosed and no recovery copy is attached to it.
    if !legacy_form && submitted_post_id != post.id {
        return Ok(identity_conflict_response(&headers, &form.body));
    }
    if post.author_sub != sub && !auth::is_admin(&headers) {
        return Err(AppError::Forbidden(
            "you can only edit your own posts".to_string(),
        ));
    }
    let loaded_post_id = post.id.clone();

    let title = form.title.trim();
    if title.is_empty() {
        return Err(AppError::InvalidRequest("title is required".to_string()));
    }
    post.title = title.to_string();
    post.body_md = form.body.trim().to_string();
    post.tags = crate::tags::normalize(&form.tags);
    post.cover_url = sanitize_cover(&form.cover_url)?;
    let publication_meta = publication_metadata(&form)?;
    post.custom_excerpt = publication_meta.custom_excerpt;
    post.meta_title = publication_meta.meta_title;
    post.meta_description = publication_meta.meta_description;
    post.canonical_url = publication_meta.canonical_url;
    post.social_title = publication_meta.social_title;
    post.social_description = publication_meta.social_description;
    post.social_image = publication_meta.social_image;
    let now = now_secs();
    let intent = PublishIntent::for_update(&form.intent)?;
    let (published, publish_at) =
        publication_from_intent(intent, &form, now, post.published, post.publish_at)?;
    post.publish_at = publish_at;
    post.published = published;
    post.pinned = form.pinned.is_some();
    post.updated_at = now;
    // Forms opened before `expected_post_id` shipped must never become last-write-wins even when
    // they happen to carry a currently valid version. Force the normal CAS-conflict recovery path.
    let expected_version = if legacy_form {
        -1
    } else {
        form.expected_version.trim().parse::<i64>().unwrap_or(-1)
    };
    let autosave_session = form.autosave_session.trim().to_string();
    let consume_autosave_session =
        valid_autosave_session(&autosave_session).then_some(autosave_session.clone());
    let outcome = state
        .store
        .save_post(SavePostCommand {
            post,
            expected_version,
            editor_sub: sub.clone(),
            editor_email: email.clone(),
            source: "update".to_string(),
            restored_from: None,
            consume_autosave_session,
        })
        .await?;
    let post = match outcome {
        SavePostOutcome::Saved(post) => *post,
        SavePostOutcome::Conflict { current_version } => {
            let recovery_session = retain_conflicting_submission(
                &state,
                &sub,
                &slug,
                &loaded_post_id,
                &form,
                &autosave_session,
            )
            .await?;
            return Ok(match recovery_session {
                Some(recovery_session) => save_conflict_response(
                    &headers,
                    &slug,
                    current_version,
                    &recovery_session,
                    &form.body,
                    &form.return_to,
                ),
                None => identity_conflict_response(&headers, &form.body),
            });
        }
        SavePostOutcome::NotFound => {
            return Ok(identity_conflict_response(&headers, &form.body));
        }
    };
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

    Ok(save_response(&headers, &post, &form.return_to))
}

/// `POST /api/writer/autosave/{slug}` — private server recovery for an existing edit session.
/// It never mutates publication state or the public index. Both post version and client sequence
/// are compare-and-swapped, so a stale tab or late network response cannot overwrite newer work.
pub async fn autosave(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Form(form): Form<PostForm>,
) -> Result<Response, AppError> {
    let (sub, _email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;
    if !valid_autosave_session(&form.autosave_session) {
        return Err(AppError::InvalidRequest(
            "autosave_session must be a server-issued session id".to_string(),
        ));
    }
    let post = state
        .store
        .get_post_authoritative(&slug)
        .await?
        .ok_or_else(|| AppError::NotFound("no such post".to_string()))?;
    if post.author_sub != sub && !auth::is_admin(&headers) {
        return Err(AppError::Forbidden(
            "you can only autosave a post you may edit".to_string(),
        ));
    }
    if form.expected_post_id != post.id {
        return Err(AppError::NotFound(
            "the autosaved post identity no longer exists".to_string(),
        ));
    }
    let base_version = form.expected_version.trim().parse::<i64>().unwrap_or(-1);
    let client_seq = form.client_seq.trim().parse::<i64>().unwrap_or(0);
    if !(1..=JS_MAX_SAFE_INTEGER).contains(&client_seq) {
        return Err(AppError::InvalidRequest(
            "client_seq must be a positive JavaScript-safe integer".to_string(),
        ));
    }
    let now = now_secs();
    let autosave = writer_autosave_from_form(
        &form.autosave_session,
        &post,
        &sub,
        base_version,
        client_seq,
        &form,
        now,
    );
    let mut response = match state.store.put_writer_autosave(autosave, now).await? {
        AutosaveOutcome::Saved(saved) => Json(AutosaveResponse {
            ok: true,
            client_seq: saved.client_seq,
            base_version: saved.base_version,
        })
        .into_response(),
        AutosaveOutcome::Stale { stored_client_seq } => (
            StatusCode::CONFLICT,
            Json(SaveConflictResponse {
                ok: false,
                conflict: true,
                current_version: base_version,
                recover: format!("stale-client-seq:{stored_client_seq}"),
            }),
        )
            .into_response(),
        AutosaveOutcome::Conflict { current_version } => (
            StatusCode::CONFLICT,
            Json(SaveConflictResponse {
                ok: false,
                conflict: true,
                current_version,
                recover: format!("/edit/{slug}"),
            }),
        )
            .into_response(),
        AutosaveOutcome::NotFound => {
            return Err(AppError::NotFound("no such post".to_string()));
        }
    };
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    Ok(response)
}

/// `GET /edit/{slug}/history` — owner/admin-only immutable history summaries.
pub async fn history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Query(query): Query<EditorQuery>,
) -> Result<Response, AppError> {
    let (sub, email) = auth::require_author(&headers)?;
    let is_admin = auth::is_admin(&headers);
    let post = state
        .store
        .get_post_authoritative(&slug)
        .await?
        .ok_or_else(|| AppError::NotFound("no such post".to_string()))?;
    if post.author_sub != sub && !is_admin {
        return Err(AppError::Forbidden(
            "you can only view history for your own posts".to_string(),
        ));
    }
    let revisions = state
        .store
        .list_post_revisions(&post.id, crate::config::REVISION_PAGE_LIMIT)
        .await?;
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let return_to = validated_return_to(query.return_to.as_deref());
    let return_field = esc(&return_to);
    let rows = revisions
        .iter()
        .map(|revision| {
            let action = if revision.edit_version == post.edit_version {
                r#"<span class="badge">current</span>"#.to_string()
            } else {
                format!(
                    r#"<form class="inline-form" method="post" action="/edit/{slug}/history/{revision_id}/restore">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <input type="hidden" name="expected_version" value="{version}">
  <input type="hidden" name="expected_post_id" value="{post_id}">
  <input type="hidden" name="return_to" value="{return_to}">
  <button class="btn btn-secondary btn-sm" type="submit">Restore content</button>
</form>"#,
                    slug = esc(&slug),
                    revision_id = esc(&revision.id),
                    csrf = esc(&csrf),
                    version = post.edit_version,
                    post_id = esc(&post.id),
                    return_to = return_field,
                )
            };
            format!(
                r#"<tr><td>v{version}</td><td>{title}</td><td>{editor}</td><td>{source}</td><td>{chars}</td><td>{action}</td></tr>"#,
                version = revision.edit_version,
                title = esc(&revision.title),
                editor = esc(&revision.editor_email),
                source = esc(&revision.source),
                chars = revision.body_chars,
            )
        })
        .collect::<String>();
    let editor_href = if return_to.is_empty() {
        format!("/edit/{}", esc(&slug))
    } else {
        format!(
            "/edit/{}?return_to={}",
            esc(&slug),
            crate::handlers::library::percent_encode(&return_to)
        )
    };
    let fragment = format!(
        r#"<main class="console console--narrow"><div class="console__head"><h1>Post history</h1><p class="sub">{title}</p></div>
<p><a class="btn btn-ghost" href="{editor_href}">Back to editor</a></p>
<section class="card"><div class="card__body"><p class="muted">Restoring recovers content and metadata while preserving the current Draft, Scheduled, or Published state, publication time, pin, and feature flags.</p>
<div class="table-wrap"><table class="history"><thead><tr><th>Version</th><th>Title</th><th>Editor</th><th>Source</th><th>Chars</th><th>Action</th></tr></thead><tbody>{rows}</tbody></table></div></div></section></main>"#,
        title = esc(&post.title),
        editor_href = esc(&editor_href),
    );
    let theme = odyssey::resolve_theme(
        headers
            .get(axum::http::header::COOKIE)
            .and_then(|value| value.to_str().ok()),
    );
    let page = page_shell(PageShell {
        head_title: "Post history · Inkwell",
        body_class: "page-console",
        rss: false,
        nav_title: "Post history",
        email: &email,
        is_admin,
        theme,
        fragment: &fragment,
        metadata: None,
    });
    Ok(private_no_store(html_with_cookie(page, set_cookie)))
}

/// Restore one immutable revision as a new authoritative version. Publication and administrative
/// state remain exactly as they are on the current row; only authoring content/metadata is copied.
pub async fn restore_revision(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((slug, revision_id)): Path<(String, String)>,
    Form(form): Form<RestoreForm>,
) -> Result<Response, AppError> {
    let (sub, email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;
    let mut current = state
        .store
        .get_post_authoritative(&slug)
        .await?
        .ok_or_else(|| AppError::NotFound("no such post".to_string()))?;
    if current.author_sub != sub && !auth::is_admin(&headers) {
        return Err(AppError::Forbidden(
            "you can only restore your own posts".to_string(),
        ));
    }
    if form.expected_post_id != current.id {
        return Err(AppError::NotFound(
            "the restored post identity no longer exists".to_string(),
        ));
    }
    let revision = state
        .store
        .get_post_revision(&current.id, &revision_id)
        .await?
        .ok_or_else(|| AppError::NotFound("no such revision for this post".to_string()))?;
    let expected_version = form.expected_version.trim().parse::<i64>().unwrap_or(-1);

    current.title = revision.title;
    current.body_md = revision.body_md;
    current.tags = revision.tags;
    current.cover_url = revision.cover_url;
    current.custom_excerpt = revision.custom_excerpt;
    current.meta_title = revision.meta_title;
    current.meta_description = revision.meta_description;
    current.canonical_url = revision.canonical_url;
    current.social_title = revision.social_title;
    current.social_description = revision.social_description;
    current.social_image = revision.social_image;
    current.updated_at = now_secs();
    let outcome = state
        .store
        .save_post(SavePostCommand {
            post: current,
            expected_version,
            editor_sub: sub.clone(),
            editor_email: email.clone(),
            source: "restore".to_string(),
            restored_from: Some(revision_id.clone()),
            consume_autosave_session: None,
        })
        .await?;
    let saved = match outcome {
        SavePostOutcome::Saved(post) => *post,
        SavePostOutcome::Conflict { current_version } => {
            return Ok(simple_conflict_response(
                &slug,
                current_version,
                "The post changed before restore. Reload history and review the newer version.",
                &form.return_to,
            ));
        }
        SavePostOutcome::NotFound => {
            return Err(AppError::NotFound("no such post".to_string()));
        }
    };
    crate::reindex_post(state.store.as_ref(), &saved).await;
    state.audit.emit(AuditEvent::notice(
        "post.revision.restore",
        if email.is_empty() { &sub } else { &email },
        &slug,
        &format!("restore {revision_id} as v{}", saved.edit_version),
    ));
    let return_to = validated_return_to(Some(&form.return_to));
    let location = if return_to.is_empty() {
        format!("/edit/{slug}/history")
    } else {
        format!(
            "/edit/{slug}/history?return_to={}",
            crate::handlers::library::percent_encode(&return_to)
        )
    };
    Ok(redirect(&location))
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
    let expected_post_id = form.expected_post_id.trim();
    let expected_version = form
        .expected_version
        .trim()
        .parse::<i64>()
        .ok()
        .filter(|version| *version > 0);
    if expected_post_id.is_empty() || expected_version.is_none() {
        return Err(delete_conflict());
    }
    let scope = if auth::is_admin(&headers) {
        DeletePostScope::Admin
    } else {
        DeletePostScope::Owner(sub)
    };
    let post = match state
        .store
        .delete_post_cas(DeletePostCommand {
            slug: slug.clone(),
            post_id: expected_post_id.to_string(),
            expected_version: expected_version.expect("validated delete version"),
            scope,
        })
        .await?
    {
        DeletePostOutcome::Deleted(post) => *post,
        DeletePostOutcome::Conflict => return Err(delete_conflict()),
    };
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

    let return_to = validated_return_to(Some(&form.return_to));
    Ok(redirect(if return_to.is_empty() {
        "/"
    } else {
        &return_to
    }))
}

fn delete_conflict() -> AppError {
    AppError::Conflict(
        "the post identity changed; reload the current page before deleting".to_string(),
    )
}

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------

struct PublicationMetadata {
    custom_excerpt: String,
    meta_title: String,
    meta_description: String,
    canonical_url: String,
    social_title: String,
    social_description: String,
    social_image: String,
}

fn valid_autosave_session(raw: &str) -> bool {
    raw.len() == 64 && raw.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn raw_bounded(raw: &str, max_chars: usize) -> String {
    raw.chars().take(max_chars).collect()
}

fn writer_autosave_from_form(
    session_id: &str,
    post: &Post,
    owner_sub: &str,
    base_version: i64,
    client_seq: i64,
    form: &PostForm,
    now: i64,
) -> WriterAutosave {
    WriterAutosave {
        session_id: session_id.to_string(),
        post_id: post.id.clone(),
        owner_sub: owner_sub.to_string(),
        base_version,
        client_seq,
        title: raw_bounded(&form.title, 200),
        body_md: raw_bounded(&form.body, 1_000_000),
        tags: raw_bounded(&form.tags, 800),
        cover_url: raw_bounded(&form.cover_url, 600),
        custom_excerpt: raw_bounded(&form.custom_excerpt, CUSTOM_EXCERPT_MAX),
        meta_title: raw_bounded(&form.meta_title, META_TITLE_MAX),
        meta_description: raw_bounded(&form.meta_description, META_DESCRIPTION_MAX),
        canonical_url: raw_bounded(&form.canonical_url, CANONICAL_URL_MAX),
        social_title: raw_bounded(&form.social_title, SOCIAL_TITLE_MAX),
        social_description: raw_bounded(&form.social_description, SOCIAL_DESCRIPTION_MAX),
        social_image: raw_bounded(&form.social_image, SOCIAL_IMAGE_MAX),
        publish_at: raw_bounded(&form.publish_at, 64),
        pinned: form.pinned.is_some(),
        updated_at: now,
        expires_at: now.saturating_add(crate::config::AUTOSAVE_TTL_SECS),
    }
}

async fn retain_conflicting_submission(
    state: &AppState,
    owner_sub: &str,
    slug: &str,
    expected_post_id: &str,
    form: &PostForm,
    submitted_session: &str,
) -> Result<Option<String>, AppError> {
    let session = if valid_autosave_session(submitted_session) {
        submitted_session.to_string()
    } else {
        auth::new_csrf_token()
    };
    let mut client_seq = form
        .client_seq
        .trim()
        .parse::<i64>()
        .unwrap_or(0)
        .saturating_add(1)
        .clamp(1, JS_MAX_SAFE_INTEGER);
    for _ in 0..3 {
        let current = state.store.get_post_authoritative(slug).await?;
        let Some(current) = current else {
            return Ok(None);
        };
        if current.id != expected_post_id {
            return Ok(None);
        }
        let now = now_secs();
        let autosave = writer_autosave_from_form(
            &session,
            &current,
            owner_sub,
            current.edit_version,
            client_seq,
            form,
            now,
        );
        match state.store.put_writer_autosave(autosave, now).await? {
            AutosaveOutcome::Saved(_) => return Ok(Some(session)),
            AutosaveOutcome::Stale { stored_client_seq } => {
                if stored_client_seq >= JS_MAX_SAFE_INTEGER {
                    return Err(AppError::Conflict(
                        "autosave sequence exhausted; reload the editor for a new session"
                            .to_string(),
                    ));
                }
                client_seq = stored_client_seq + 1;
            }
            AutosaveOutcome::Conflict { .. } => continue,
            AutosaveOutcome::NotFound => {
                return Ok(None);
            }
        }
    }
    Err(AppError::Conflict(
        "post kept changing while retaining the recovery copy; your browser copy remains available"
            .to_string(),
    ))
}

fn save_conflict_response(
    headers: &HeaderMap,
    slug: &str,
    current_version: i64,
    recovery_session: &str,
    submitted_body: &str,
    requested_return_to: &str,
) -> Response {
    let return_to = validated_return_to(Some(requested_return_to));
    let recover = if return_to.is_empty() {
        format!("/edit/{slug}?recover={recovery_session}")
    } else {
        format!(
            "/edit/{slug}?recover={recovery_session}&return_to={}",
            crate::handlers::library::percent_encode(&return_to)
        )
    };
    let accepts_json = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|part| part.trim() == "application/json")
        });
    let mut response = if accepts_json {
        (
            StatusCode::CONFLICT,
            Json(SaveConflictResponse {
                ok: false,
                conflict: true,
                current_version,
                recover,
            }),
        )
            .into_response()
    } else {
        let html = format!(
            r#"<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Edit conflict · Inkwell</title><body><main><h1>A newer version was saved</h1><p>Your submitted text is preserved below and as a private server recovery copy.</p><p><a href="{recover}">Review recovery against version {version}</a></p><label for="conflict-body">Your submitted body</label><textarea id="conflict-body" rows="24" readonly>{body}</textarea></main></body></html>"#,
            recover = esc(&recover),
            version = current_version,
            body = esc(submitted_body),
        );
        (StatusCode::CONFLICT, Html(html)).into_response()
    };
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response
}

/// A stale form can outlive deletion and slug reuse. Return only caller-supplied text: unlike an
/// ordinary version conflict there is deliberately no recovery URL, because attaching that copy
/// to the replacement post would cross an immutable identity boundary.
fn identity_conflict_response(headers: &HeaderMap, submitted_body: &str) -> Response {
    let accepts_json = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|part| part.trim() == "application/json")
        });
    let mut response = if accepts_json {
        (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "ok": false,
                "conflict": true,
                "submitted_body": submitted_body
            })),
        )
            .into_response()
    } else {
        let html = format!(
            r#"<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Edit conflict · Inkwell</title><body><main><h1>This post changed identity</h1><p>The post opened by this form no longer exists. Your submitted text was not attached to the current post.</p><label for="conflict-body">Your submitted body</label><textarea id="conflict-body" rows="24" readonly>{body}</textarea></main></body></html>"#,
            body = esc(submitted_body),
        );
        (StatusCode::CONFLICT, Html(html)).into_response()
    };
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response
}

fn simple_conflict_response(
    slug: &str,
    current_version: i64,
    message: &str,
    requested_return_to: &str,
) -> Response {
    let return_to = validated_return_to(Some(requested_return_to));
    let history_href = if return_to.is_empty() {
        format!("/edit/{slug}/history")
    } else {
        format!(
            "/edit/{slug}/history?return_to={}",
            crate::handlers::library::percent_encode(&return_to)
        )
    };
    let html = format!(
        r#"<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Edit conflict · Inkwell</title><body><main><h1>Edit conflict</h1><p>{message}</p><p>Current version: {version}</p><a href="{history_href}">Reload history</a></main></body></html>"#,
        message = esc(message),
        version = current_version,
        history_href = esc(&history_href),
    );
    let mut response = (StatusCode::CONFLICT, Html(html)).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response
}

/// Normalize the optional publication fields at the server boundary. Text is character-truncated
/// to the same limits advertised by the no-JavaScript form; URLs are rejected rather than truncated
/// because silently cutting a URL can change its authority or resource.
fn publication_metadata(form: &PostForm) -> Result<PublicationMetadata, AppError> {
    Ok(PublicationMetadata {
        custom_excerpt: truncate_text(&form.custom_excerpt, CUSTOM_EXCERPT_MAX),
        meta_title: truncate_text(&form.meta_title, META_TITLE_MAX),
        meta_description: truncate_text(&form.meta_description, META_DESCRIPTION_MAX),
        canonical_url: sanitize_canonical_url(&form.canonical_url)?,
        social_title: truncate_text(&form.social_title, SOCIAL_TITLE_MAX),
        social_description: truncate_text(&form.social_description, SOCIAL_DESCRIPTION_MAX),
        social_image: sanitize_social_image(&form.social_image)?,
    })
}

fn truncate_text(raw: &str, max_chars: usize) -> String {
    raw.trim().chars().take(max_chars).collect()
}

/// Canonical URLs are optional, but when present must be a bounded absolute HTTP(S) URL with an
/// authority and no embedded userinfo. `http::Uri` also rejects whitespace/control/fragment tricks.
fn sanitize_canonical_url(raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.chars().count() > CANONICAL_URL_MAX {
        return Err(AppError::InvalidRequest(format!(
            "canonical URL must be at most {CANONICAL_URL_MAX} characters"
        )));
    }
    let uri = trimmed.parse::<axum::http::Uri>().map_err(|_| {
        AppError::InvalidRequest("canonical URL must be absolute HTTP(S)".to_string())
    })?;
    let scheme_ok = uri
        .scheme_str()
        .is_some_and(|scheme| matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https"));
    let authority_ok = uri.authority().is_some_and(|authority| {
        !authority.as_str().contains('@') && !authority.host().trim().is_empty()
    });
    if !scheme_ok || !authority_ok {
        return Err(AppError::InvalidRequest(
            "canonical URL must be absolute HTTP(S) without userinfo".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

pub(crate) fn canonical_url_is_safe(raw: &str) -> bool {
    sanitize_canonical_url(raw).is_ok()
}

fn sanitize_social_image(raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.chars().count() > SOCIAL_IMAGE_MAX {
        return Err(AppError::InvalidRequest(format!(
            "social image must be at most {SOCIAL_IMAGE_MAX} characters"
        )));
    }
    if !markdown::is_estate_image_url(trimmed) {
        return Err(AppError::InvalidRequest(
            "social image must be an Aperture share URL (https://drive.w33d.xyz/s/…)".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

/// Build the complete public head contract for a reader-visible post. Every value is escaped by
/// [`page_shell`]; URL fields are also revalidated here so a legacy/manually-written row
/// cannot bypass the current authoring policy.
fn public_post_meta(post: &Post) -> PageMeta {
    let local_url = format!("{}/p/{}", crate::config::SITE_BASE_URL, post.slug);
    let canonical = sanitize_canonical_url(&post.canonical_url)
        .ok()
        .filter(|url| !url.is_empty())
        .unwrap_or(local_url);
    let excerpt = post_excerpt(post, META_DESCRIPTION_MAX);
    let description = if post.meta_description.trim().is_empty() {
        excerpt
    } else {
        post.meta_description.trim().to_string()
    };
    let meta_title = if post.meta_title.trim().is_empty() {
        post.title.clone()
    } else {
        post.meta_title.trim().to_string()
    };
    let social_title = if post.social_title.trim().is_empty() {
        meta_title.clone()
    } else {
        post.social_title.trim().to_string()
    };
    let social_description = if post.social_description.trim().is_empty() {
        description.clone()
    } else {
        post.social_description.trim().to_string()
    };
    let social_image = [&post.social_image, &post.cover_url]
        .into_iter()
        .find(|url| markdown::is_estate_image_url(url.trim()))
        .map(|url| url.trim().to_string());
    let twitter_card = if social_image.is_some() {
        "summary_large_image"
    } else {
        "summary"
    };

    PageMeta {
        description: Some(description.clone()),
        canonical: Some(canonical),
        og_type: Some("article".to_string()),
        og_title: Some(social_title.clone()),
        og_description: Some(social_description.clone()),
        og_image: social_image.clone(),
        twitter_card: Some(twitter_card.to_string()),
        twitter_title: Some(social_title),
        twitter_description: Some(social_description),
        twitter_image: social_image,
        ..PageMeta::default()
    }
}

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
        // `publish_at` doubles as the actual publication timestamp. A value equal to `now` is
        // already public (`is_scheduled_at` is strictly future) while preserving the chronology of
        // an old Draft that is published or republished today.
        PublishIntent::PublishNow => Ok((true, now)),
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

fn save_response(headers: &HeaderMap, post: &Post, requested_return_to: &str) -> Response {
    let state = publication_detail(post, now_secs());
    let return_to = validated_return_to(Some(requested_return_to));
    let redirect_to = if !return_to.is_empty() {
        return_to
    } else if state == "published" {
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

fn validated_return_to(raw: Option<&str>) -> String {
    raw.and_then(crate::handlers::library::safe_library_return_to)
        .unwrap_or_default()
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
        excerpt = esc(&post_excerpt(post, 280)),
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
        excerpt = esc(&post_excerpt(post, 200)),
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
    autosave_url: &'a str,
    autosave_session: &'a str,
    expected_version: i64,
    expected_post_id: &'a str,
    client_seq: i64,
    history_href: &'a str,
    return_to: &'a str,
    recovery_notice: &'a str,
    recovery_scope: &'a str,
    csrf: &'a str,
    title_value: &'a str,
    body_value: &'a str,
    tags_value: &'a str,
    cover_value: &'a str,
    custom_excerpt_value: &'a str,
    meta_title_value: &'a str,
    meta_description_value: &'a str,
    canonical_url_value: &'a str,
    social_title_value: &'a str,
    social_description_value: &'a str,
    social_image_value: &'a str,
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
    let history_action = if v.history_href.is_empty() {
        String::new()
    } else {
        format!(
            r#"<a class="btn btn-ghost" href="{}">History</a>"#,
            esc(v.history_href)
        )
    };
    let delete_block = match v.delete_slug {
        Some(slug) => format!(
            r#"<div class="danger-zone">
  <div class="danger-zone__text"><strong>Delete this post</strong><span>Once deleted, it cannot be recovered.</span></div>
  <form class="inline-form" method="post" action="/delete/{slug}" onsubmit="return confirm('Delete this post? This cannot be undone.');">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <input type="hidden" name="expected_post_id" value="{post_id}">
    <input type="hidden" name="expected_version" value="{version}">
    <input type="hidden" name="return_to" value="{return_to}">
    <button class="btn btn-danger" type="submit">Delete</button>
  </form>
</div>"#,
            slug = esc(slug),
            csrf = esc(v.csrf),
            post_id = esc(v.expected_post_id),
            version = v.expected_version,
            return_to = esc(v.return_to),
        ),
        None => String::new(),
    };

    let fragment = EDITOR_HTML
        .replace("{{HEADING}}", &esc(v.heading))
        .replace("{{SUBHEAD}}", &esc(v.subhead))
        .replace("{{ACTION}}", v.action)
        .replace("{{AUTOSAVE_URL}}", &esc(v.autosave_url))
        .replace("{{AUTOSAVE_SESSION}}", &esc(v.autosave_session))
        .replace("{{EXPECTED_VERSION}}", &v.expected_version.to_string())
        .replace("{{EXPECTED_POST_ID}}", &esc(v.expected_post_id))
        .replace("{{CLIENT_SEQ}}", &v.client_seq.to_string())
        .replace("{{RETURN_TO}}", &esc(v.return_to))
        .replace("{{HISTORY_ACTION}}", &history_action)
        .replace("{{SERVER_RECOVERY_NOTICE}}", v.recovery_notice)
        .replace("{{RECOVERY_SCOPE}}", &esc(v.recovery_scope))
        .replace("{{CSRF}}", &esc(v.csrf))
        .replace("{{TITLE_VALUE}}", &esc(v.title_value))
        .replace("{{BODY_VALUE}}", &esc(v.body_value))
        .replace("{{TAGS_VALUE}}", &esc(v.tags_value))
        .replace("{{COVER_VALUE}}", &esc(v.cover_value))
        .replace("{{CUSTOM_EXCERPT_VALUE}}", &esc(v.custom_excerpt_value))
        .replace("{{META_TITLE_VALUE}}", &esc(v.meta_title_value))
        .replace("{{META_DESCRIPTION_VALUE}}", &esc(v.meta_description_value))
        .replace("{{CANONICAL_URL_VALUE}}", &esc(v.canonical_url_value))
        .replace("{{SOCIAL_TITLE_VALUE}}", &esc(v.social_title_value))
        .replace(
            "{{SOCIAL_DESCRIPTION_VALUE}}",
            &esc(v.social_description_value),
        )
        .replace("{{SOCIAL_IMAGE_VALUE}}", &esc(v.social_image_value))
        .replace("{{PUBLISH_AT_VALUE}}", &esc(v.publish_at_value))
        .replace("{{PINNED_CHECKED}}", if v.pinned { "checked" } else { "" })
        .replace("{{STATE_PILL}}", &state_pill_html)
        .replace("{{STATE_KEY}}", &esc(v.state_label))
        .replace("{{PRESERVE_ACTION}}", preserve_action)
        .replace("{{CANCEL_HREF}}", v.cancel_href)
        .replace("{{DELETE}}", &delete_block);
    let head_title = format!("{} · Inkwell", v.heading);
    page_shell(PageShell {
        head_title: &head_title,
        body_class: "page-console",
        rss: false,
        nav_title: v.heading,
        email: v.email,
        is_admin: v.is_admin,
        theme: v.theme,
        fragment: &fragment,
        metadata: None,
    })
}

/// A 303 redirect (post/redirect/get).
fn redirect(location: &str) -> Response {
    let location =
        HeaderValue::from_str(location).unwrap_or_else(|_| HeaderValue::from_static("/"));
    private_no_store((StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response())
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

fn private_no_store(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response
}

pub(crate) fn public_read_response(
    mut response: Response,
    headers: &HeaderMap,
    viewer_sub: Option<&str>,
    is_admin: bool,
) -> Response {
    // These are exactly the request fields that can change public reader HTML: Cookie selects the
    // theme, subject controls own-draft visibility/actions, email is rendered in the top bar, and
    // groups control admin navigation. Vary prevents a compliant shared cache from serving an
    // anonymous URL-keyed object before an identity-bearing request reaches Inkwell.
    response.headers_mut().insert(
        header::VARY,
        HeaderValue::from_static(PUBLIC_REPRESENTATION_VARY),
    );
    if request_is_personalized(headers, viewer_sub, is_admin) {
        private_no_store(response)
    } else {
        response
    }
}

fn request_is_personalized(headers: &HeaderMap, viewer_sub: Option<&str>, is_admin: bool) -> bool {
    viewer_sub.is_some()
        || auth::author_email(headers).is_some()
        || is_admin
        || headers.contains_key(header::COOKIE)
}
