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
use crate::handlers::{esc, page_shell};
use crate::store::{Post, Settings};
use crate::{now_secs, AppState};

const ADMIN_HTML: &str = include_str!("../../templates/admin.html");

/// Minimal CSRF-only form body (per-row feature / unpublish / delete actions).
#[derive(Debug, Deserialize)]
pub struct CsrfForm {
    #[serde(default)]
    pub csrf_token: String,
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
    let page = page_shell(
        "Admin · Inkwell",
        "page-console",
        false,
        "Admin",
        &email,
        true,
        theme,
        &fragment,
    );

    Ok(html_with_cookie(page, set_cookie))
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
            <td class="admin-table__check"><input type="checkbox" name="slugs" form="bulk-form" value="{slug}"></td>
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
                <button class="btn btn-danger btn-sm" type="submit">Delete</button>
              </form>
            </td>
          </tr>
"#,
        slug = slug,
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
    state.store.update_post(&post).await?;
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
    state.store.update_post(&post).await?;
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
    state.store.update_post(&post).await?;
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
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    auth::require_admin(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    // Confirm existence (404 otherwise) before deleting.
    load(&state, &slug).await?;
    state.store.delete_post(&slug).await?;
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
/// checked `slugs` value. Parsed from the raw body: repeated `slugs=` keys don't round-trip
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
    let slugs: Vec<String> = pairs
        .iter()
        .filter(|(k, _)| k == "slugs")
        .map(|(_, v)| v.clone())
        .collect();

    let actor = actor(&headers);
    for slug in &slugs {
        match action.as_str() {
            "pin" | "unpin" => {
                if let Some(mut post) = state.store.get_post(slug).await {
                    post.pinned = action == "pin";
                    post.bump_updated_at(now_secs());
                    state.store.update_post(&post).await?;
                    state.audit.emit(AuditEvent::info(
                        "admin.post.pin",
                        &actor,
                        slug,
                        if post.pinned { "pinned" } else { "unpinned" },
                    ));
                }
            }
            "feature" | "unfeature" => {
                if let Some(mut post) = state.store.get_post(slug).await {
                    post.featured = action == "feature";
                    post.bump_updated_at(now_secs());
                    state.store.update_post(&post).await?;
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
            }
            "unpublish" => {
                if let Some(mut post) = state.store.get_post(slug).await {
                    post.published = false;
                    post.bump_updated_at(now_secs());
                    state.store.update_post(&post).await?;
                    crate::reindex_post(state.store.as_ref(), &post).await;
                    state.audit.emit(AuditEvent::notice(
                        "admin.post.unpublish",
                        &actor,
                        slug,
                        "unpublish",
                    ));
                }
            }
            "delete" => {
                if state.store.get_post(slug).await.is_some() {
                    state.store.delete_post(slug).await?;
                    crate::deindex_post(state.store.as_ref(), slug).await;
                    state.audit.emit(AuditEvent::notice(
                        "admin.post.delete",
                        &actor,
                        slug,
                        "delete",
                    ));
                }
            }
            other => {
                return Err(AppError::InvalidRequest(format!(
                    "unknown bulk action: {other}"
                )));
            }
        }
    }
    tracing::info!(action = %action, count = slugs.len(), "admin bulk action");

    Ok(redirect("/admin"))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Fetch a post or 404.
async fn load(state: &AppState, slug: &str) -> Result<Post, AppError> {
    state
        .store
        .get_post(slug)
        .await
        .ok_or_else(|| AppError::NotFound("no such post".to_string()))
}

/// The audit actor for an admin action: the gateway email, falling back to the subject.
fn actor(headers: &HeaderMap) -> String {
    auth::author_email(headers)
        .or_else(|| auth::author_sub(headers))
        .unwrap_or_else(|| "admin".to_string())
}

/// Parse an `application/x-www-form-urlencoded` body into ordered `(key, value)` pairs,
/// preserving duplicate keys (so multiple `slugs=` selections all survive).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pairs_keeps_duplicate_slugs() {
        let pairs = parse_pairs("csrf_token=tok&action=delete&slugs=a&slugs=b-2&slugs=c");
        assert_eq!(field(&pairs, "csrf_token"), "tok");
        assert_eq!(field(&pairs, "action"), "delete");
        let slugs: Vec<&str> = pairs
            .iter()
            .filter(|(k, _)| k == "slugs")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(slugs, vec!["a", "b-2", "c"]);
    }

    #[test]
    fn urldecode_handles_plus_and_percent() {
        assert_eq!(urldecode("hello+world"), "hello world");
        assert_eq!(urldecode("a%20b%2Fc"), "a b/c");
        // A stray percent is left as-is rather than dropped.
        assert_eq!(urldecode("100%"), "100%");
    }
}
