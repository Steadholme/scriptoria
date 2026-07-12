//! The admin panel: an all-authors post management table + single-row site settings.
//!
//! Every route in the `/admin` subtree is gated by [`auth::require_admin`] — an ordinary
//! signed-in user (or an anonymous caller) gets a 403, only members of an admin group see it.
//! Each state-changing POST is double-submit CSRF protected and emits an [`AuditEvent`]
//! (`notice` for the destructive/moderation ops, `info` for feature + settings). All interpolated
//! user input is HTML-escaped.
//!
//! Admin post actions are built on the SAME `Store` primitives the authoring flow uses
//! (`get_post` + `update_post` + `delete_post`), so there is one code path per mutation and the
//! ask-index stays in step via [`crate::reindex_post`] / [`crate::deindex_post`].

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth;
use crate::config::MAX_PAGE;
use crate::error::AppError;
use crate::handlers::{esc, page_shell, PageShell};
use crate::store::{
    DeletePostCommand, DeletePostOutcome, DeletePostScope, DeletePostSelection, DeletePostsCommand,
    DeletePostsOutcome, Post, SavePostCommand, SavePostOutcome, Settings,
};
use crate::{now_secs, AppState};

const ADMIN_HTML: &str = include_str!("../../templates/admin.html");

/// Minimal CSRF-only form body (per-row feature / unpublish / delete actions).
#[derive(Debug, Deserialize)]
pub struct CsrfForm {
    #[serde(default)]
    pub csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub struct DeleteForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub expected_post_id: String,
    #[serde(default)]
    pub expected_version: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AdminSelection {
    slug: String,
    post_id: String,
    expected_version: i64,
}

/// Site-settings form body. `posts_per_page` arrives as a string and is parsed + clamped.
#[derive(Debug, Deserialize)]
pub struct SettingsForm {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub tagline: String,
    #[serde(default)]
    pub posts_per_page: String,
    #[serde(default)]
    pub csrf_token: String,
}

// ---------------------------------------------------------------------------
// GET /admin — the management panel
// ---------------------------------------------------------------------------

/// `GET /admin` — the all-posts table (across every author) + the site-settings form.
pub async fn index(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    auth::require_admin(&headers)?;
    let email = auth::display_email(&headers);
    let theme = odyssey::resolve_theme(
        headers
            .get(axum::http::header::COOKIE)
            .and_then(|v| v.to_str().ok()),
    );
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    let settings = state.store.get_settings().await;
    // Every post, newest-first, regardless of author (the admin's whole-estate view).
    let posts = state.store.list_posts(None, MAX_PAGE).await;

    let mut rows = String::new();
    let now = now_secs();
    for p in &posts {
        rows.push_str(&render_row(p, &csrf, now));
    }
    if posts.is_empty() {
        rows.push_str(r#"<tr><td colspan="7" class="admin-table__empty">No posts yet.</td></tr>"#);
    }

    let fragment = ADMIN_HTML
        .replace("{{CSRF}}", &esc(&csrf))
        .replace("{{SETTINGS_TITLE}}", &esc(&settings.title))
        .replace("{{SETTINGS_TAGLINE}}", &esc(&settings.tagline))
        .replace("{{SETTINGS_PPP}}", &settings.posts_per_page.to_string())
        .replace("{{ROWS}}", &rows);
    let page = page_shell(PageShell {
        head_title: "Admin · Inkwell",
        body_class: "page-console",
        rss: false,
        nav_title: "Admin",
        email: &email,
        is_admin: true,
        theme,
        fragment: &fragment,
        metadata: None,
    });

    Ok(private_no_store(html_with_cookie(page, set_cookie)))
}

/// One admin table row: selection checkbox (bound to the external bulk form via `form=`),
/// title/author/status/featured cells, and the per-row action forms. Every field is escaped.
fn render_row(p: &Post, csrf: &str, now: i64) -> String {
    let status = if !p.published {
        "Draft"
    } else if p.is_scheduled_at(now) {
        "Scheduled"
    } else {
        "Published"
    };
    let pinned = if p.pinned { "Yes" } else { "—" };
    let pin_label = if p.pinned { "Unpin" } else { "Pin" };
    let featured = if p.featured { "Yes" } else { "—" };
    let feature_label = if p.featured { "Unfeature" } else { "Feature" };
    let slug = esc(&p.slug);
    let csrf = esc(csrf);
    format!(
        r#"          <tr>
            <td class="admin-table__check"><input type="checkbox" name="items" form="bulk-form" value="{selection}"></td>
            <td><a href="/p/{slug}">{title}</a></td>
            <td>{author}</td>
            <td>{status}</td>
            <td>{pinned}</td>
            <td>{featured}</td>
            <td class="admin-table__actions">
              <form class="inline-form" method="post" action="/admin/posts/{slug}/pin">
                <input type="hidden" name="csrf_token" value="{csrf}">
                <button class="btn btn-secondary btn-sm" type="submit">{pin_label}</button>
              </form>
              <form class="inline-form" method="post" action="/admin/posts/{slug}/feature">
                <input type="hidden" name="csrf_token" value="{csrf}">
                <button class="btn btn-secondary btn-sm" type="submit">{feature_label}</button>
              </form>
              <form class="inline-form" method="post" action="/admin/posts/{slug}/unpublish">
                <input type="hidden" name="csrf_token" value="{csrf}">
                <button class="btn btn-secondary btn-sm" type="submit">Unpublish</button>
              </form>
              <a class="btn btn-secondary btn-sm" href="/edit/{slug}">Edit</a>
              <form class="inline-form" method="post" action="/admin/posts/{slug}/delete" onsubmit="return confirm('Delete this post? This cannot be undone.');">
                <input type="hidden" name="csrf_token" value="{csrf}">
                <input type="hidden" name="expected_post_id" value="{post_id}">
                <input type="hidden" name="expected_version" value="{version}">
                <button class="btn btn-danger btn-sm" type="submit">Delete</button>
              </form>
            </td>
          </tr>
"#,
        slug = slug,
        selection = encode_selection(p),
        post_id = esc(&p.id),
        version = p.edit_version,
        title = esc(&p.title),
        author = esc(&p.author_email),
        status = status,
        pinned = pinned,
        pin_label = pin_label,
        featured = featured,
        feature_label = feature_label,
        csrf = csrf,
    )
}

// ---------------------------------------------------------------------------
// POST /admin/settings
// ---------------------------------------------------------------------------

/// `POST /admin/settings` — persist the single settings row, then bounce back to /admin.
pub async fn update_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SettingsForm>,
) -> Result<Response, AppError> {
    auth::require_admin(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let title = form.title.trim();
    if title.is_empty() {
        return Err(AppError::InvalidRequest(
            "blog title is required".to_string(),
        ));
    }
    // Fall back to the current value on a non-numeric input; clamp into the sane page bounds.
    let current = state.store.get_settings().await;
    let posts_per_page = form
        .posts_per_page
        .trim()
        .parse::<i64>()
        .unwrap_or(current.posts_per_page)
        .clamp(1, MAX_PAGE);

    let settings = Settings {
        title: title.to_string(),
        tagline: form.tagline.trim().to_string(),
        posts_per_page,
    };
    state.store.update_settings(&settings).await?;
    tracing::info!("site settings updated");

    state.audit.emit(AuditEvent::info(
        "admin.settings.update",
        &actor(&headers),
        "settings",
        "update",
    ));

    Ok(redirect("/admin"))
}

// ---------------------------------------------------------------------------
// Per-post admin actions
// ---------------------------------------------------------------------------

/// `POST /admin/posts/{slug}/pin` — toggle a post's public-index pin.
pub async fn pin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    auth::require_admin(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let mut post = load(&state, &slug).await?;
    post.pinned = !post.pinned;
    post.bump_updated_at(now_secs());
    let post = save_admin_post(&state, &headers, post, "admin.pin").await?;
    tracing::info!(slug = %slug, pinned = post.pinned, "admin toggled pinned");

    state.audit.emit(AuditEvent::info(
        "admin.post.pin",
        &actor(&headers),
        &slug,
        if post.pinned { "pinned" } else { "unpinned" },
    ));

    Ok(redirect("/admin"))
}

/// `POST /admin/posts/{slug}/feature` — toggle a post's featured flag.
pub async fn feature(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    auth::require_admin(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let mut post = load(&state, &slug).await?;
    post.featured = !post.featured;
    post.bump_updated_at(now_secs());
    let post = save_admin_post(&state, &headers, post, "admin.feature").await?;
    tracing::info!(slug = %slug, featured = post.featured, "admin toggled featured");

    state.audit.emit(AuditEvent::info(
        "admin.post.feature",
        &actor(&headers),
        &slug,
        if post.featured {
            "featured"
        } else {
            "unfeatured"
        },
    ));

    Ok(redirect("/admin"))
}

/// `POST /admin/posts/{slug}/unpublish` — force a post back to draft (hides it from the index).
pub async fn unpublish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    auth::require_admin(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let mut post = load(&state, &slug).await?;
    post.published = false;
    post.bump_updated_at(now_secs());
    let post = save_admin_post(&state, &headers, post, "admin.unpublish").await?;
    tracing::info!(slug = %slug, "admin unpublished post");

    // A now-draft post is de-indexed from the ask index (best-effort).
    crate::reindex_post(state.store.as_ref(), &post).await;

    state.audit.emit(AuditEvent::notice(
        "admin.post.unpublish",
        &actor(&headers),
        &slug,
        "unpublish",
    ));

    Ok(redirect("/admin"))
}

/// `POST /admin/posts/{slug}/delete` — delete ANY author's post.
pub async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Form(form): Form<DeleteForm>,
) -> Result<Response, AppError> {
    auth::require_admin(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;
    let Some(expected_version) = form
        .expected_version
        .trim()
        .parse::<i64>()
        .ok()
        .filter(|version| *version > 0)
    else {
        return Err(delete_conflict());
    };
    if form.expected_post_id.trim().is_empty() {
        return Err(delete_conflict());
    }
    match state
        .store
        .delete_post_cas(DeletePostCommand {
            slug: slug.clone(),
            post_id: form.expected_post_id.trim().to_string(),
            expected_version,
            scope: DeletePostScope::Admin,
        })
        .await?
    {
        DeletePostOutcome::Deleted(_) => {}
        DeletePostOutcome::Conflict => return Err(delete_conflict()),
    }
    tracing::info!(slug = %slug, "admin deleted post");

    crate::deindex_post(state.store.as_ref(), &slug).await;

    state.audit.emit(AuditEvent::notice(
        "admin.post.delete",
        &actor(&headers),
        &slug,
        "delete",
    ));

    Ok(redirect("/admin"))
}

// ---------------------------------------------------------------------------
// POST /admin/posts/bulk — apply one action to the selected slugs
// ---------------------------------------------------------------------------

/// `POST /admin/posts/bulk` — apply `action` (pin|unpin|feature|unfeature|unpublish|delete) to every
/// checked stable selection. Parsed from the raw body: repeated `items=` keys don't round-trip
/// through `serde_urlencoded` into a `Vec`, so the body is decoded by hand here.
pub async fn bulk(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, AppError> {
    auth::require_admin(&headers)?;

    let pairs = parse_pairs(&body);
    let csrf = field(&pairs, "csrf_token");
    auth::verify_csrf(&headers, &csrf)?;

    let action = field(&pairs, "action");
    let selections: Vec<AdminSelection> = pairs
        .iter()
        .filter(|(key, _)| key == "items")
        .map(|(_, value)| parse_selection(value))
        .collect::<Result<_, _>>()?;
    if selections.is_empty() {
        return Err(delete_conflict());
    }

    let actor = actor(&headers);
    if action == "delete" {
        let deleted = match state
            .store
            .delete_posts_cas(DeletePostsCommand {
                selections: selections
                    .iter()
                    .map(|selection| DeletePostSelection {
                        slug: selection.slug.clone(),
                        post_id: selection.post_id.clone(),
                        expected_version: selection.expected_version,
                    })
                    .collect(),
                scope: DeletePostScope::Admin,
            })
            .await?
        {
            DeletePostsOutcome::Deleted(posts) => posts,
            DeletePostsOutcome::Conflict => return Err(delete_conflict()),
        };
        // The store transaction has committed the complete set before derived-index cleanup and
        // audit side effects begin, so a stale later selection can never leave a partial delete.
        for post in &deleted {
            crate::deindex_post(state.store.as_ref(), &post.slug).await;
            state.audit.emit(AuditEvent::notice(
                "admin.post.delete",
                &actor,
                &post.slug,
                "delete",
            ));
        }
        tracing::info!(action = %action, count = deleted.len(), "admin bulk action");
        return Ok(redirect("/admin"));
    }

    for selection in &selections {
        let slug = &selection.slug;
        match action.as_str() {
            "pin" | "unpin" => {
                let mut post = load_selection(&state, selection).await?;
                post.pinned = action == "pin";
                post.bump_updated_at(now_secs());
                let post = save_admin_post(&state, &headers, post, "admin.pin").await?;
                state.audit.emit(AuditEvent::info(
                    "admin.post.pin",
                    &actor,
                    slug,
                    if post.pinned { "pinned" } else { "unpinned" },
                ));
            }
            "feature" | "unfeature" => {
                let mut post = load_selection(&state, selection).await?;
                post.featured = action == "feature";
                post.bump_updated_at(now_secs());
                let post = save_admin_post(&state, &headers, post, "admin.feature").await?;
                state.audit.emit(AuditEvent::info(
                    "admin.post.feature",
                    &actor,
                    slug,
                    if post.featured {
                        "featured"
                    } else {
                        "unfeatured"
                    },
                ));
            }
            "unpublish" => {
                let mut post = load_selection(&state, selection).await?;
                post.published = false;
                post.bump_updated_at(now_secs());
                let post = save_admin_post(&state, &headers, post, "admin.unpublish").await?;
                crate::reindex_post(state.store.as_ref(), &post).await;
                state.audit.emit(AuditEvent::notice(
                    "admin.post.unpublish",
                    &actor,
                    slug,
                    "unpublish",
                ));
            }
            other => {
                return Err(AppError::InvalidRequest(format!(
                    "unknown bulk action: {other}"
                )));
            }
        }
    }
    tracing::info!(action = %action, count = selections.len(), "admin bulk action");

    Ok(redirect("/admin"))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Fetch a post or 404.
async fn load(state: &AppState, slug: &str) -> Result<Post, AppError> {
    state
        .store
        .get_post_authoritative(slug)
        .await?
        .ok_or_else(|| AppError::NotFound("no such post".to_string()))
}

async fn load_selection(state: &AppState, selection: &AdminSelection) -> Result<Post, AppError> {
    let post = state
        .store
        .get_post_authoritative(&selection.slug)
        .await?
        .ok_or_else(delete_conflict)?;
    if post.id != selection.post_id || post.edit_version != selection.expected_version {
        return Err(delete_conflict());
    }
    Ok(post)
}

fn delete_conflict() -> AppError {
    AppError::Conflict(
        "the post identity changed; reload the admin page before applying this action".to_string(),
    )
}

fn encode_selection(post: &Post) -> String {
    format!(
        "{}.{}.{}",
        hex::encode(post.id.as_bytes()),
        post.edit_version,
        hex::encode(post.slug.as_bytes())
    )
}

fn parse_selection(raw: &str) -> Result<AdminSelection, AppError> {
    let mut parts = raw.split('.');
    let encoded_id = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    let encoded_slug = parts.next().unwrap_or_default();
    if parts.next().is_some() || encoded_id.len() > 512 || encoded_slug.len() > 512 {
        return Err(delete_conflict());
    }
    let decode = |value: &str| {
        hex::decode(value)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .filter(|value| !value.is_empty())
    };
    let Some(post_id) = decode(encoded_id) else {
        return Err(delete_conflict());
    };
    let Some(slug) = decode(encoded_slug) else {
        return Err(delete_conflict());
    };
    let Some(expected_version) = version.parse::<i64>().ok().filter(|version| *version > 0) else {
        return Err(delete_conflict());
    };
    Ok(AdminSelection {
        slug,
        post_id,
        expected_version,
    })
}

async fn save_admin_post(
    state: &AppState,
    headers: &HeaderMap,
    post: Post,
    source: &str,
) -> Result<Post, AppError> {
    let expected_version = post.edit_version;
    let editor_sub = auth::author_sub(headers).unwrap_or_else(|| "admin".to_string());
    let editor_email = auth::author_email(headers).unwrap_or_default();
    match state
        .store
        .save_post(SavePostCommand {
            post,
            expected_version,
            editor_sub,
            editor_email,
            source: source.to_string(),
            restored_from: None,
            consume_autosave_session: None,
        })
        .await?
    {
        SavePostOutcome::Saved(post) => Ok(*post),
        SavePostOutcome::Conflict { current_version } => Err(AppError::Conflict(format!(
            "post changed before admin action (current version {current_version})"
        ))),
        SavePostOutcome::NotFound => Err(AppError::NotFound("no such post".to_string())),
    }
}

/// The audit actor for an admin action: the gateway email, falling back to the subject.
fn actor(headers: &HeaderMap) -> String {
    auth::author_email(headers)
        .or_else(|| auth::author_sub(headers))
        .unwrap_or_else(|| "admin".to_string())
}

/// Parse an `application/x-www-form-urlencoded` body into ordered `(key, value)` pairs,
/// preserving duplicate keys (so multiple `items=` selections all survive).
fn parse_pairs(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter(|s| !s.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (urldecode(k), urldecode(v))
        })
        .collect()
}

/// First value for `key` in the parsed pairs, or empty when absent.
fn field(pairs: &[(String, String)], key: &str) -> String {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

/// Percent-decode one urlencoded token (`+` -> space, `%XX` -> byte).
fn urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => match (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push(h * 16 + l);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Hex digit -> value, or `None` for a non-hex byte.
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// A 303 redirect (post/redirect/get).
fn redirect(location: &str) -> Response {
    let location =
        HeaderValue::from_str(location).unwrap_or_else(|_| HeaderValue::from_static("/admin"));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pairs_keeps_duplicate_items() {
        let pairs = parse_pairs("csrf_token=tok&action=delete&items=a&items=b-2&items=c");
        assert_eq!(field(&pairs, "csrf_token"), "tok");
        assert_eq!(field(&pairs, "action"), "delete");
        let items: Vec<&str> = pairs
            .iter()
            .filter(|(k, _)| k == "items")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(items, vec!["a", "b-2", "c"]);
    }

    #[test]
    fn urldecode_handles_plus_and_percent() {
        assert_eq!(urldecode("hello+world"), "hello world");
        assert_eq!(urldecode("a%20b%2Fc"), "a b/c");
        // A stray percent is left as-is rather than dropped.
        assert_eq!(urldecode("100%"), "100%");
    }
}
