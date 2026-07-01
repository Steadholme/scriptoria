//! The `/admin` panel: category CRUD, thread moderation (lock / pin / move / delete), any-post
//! deletion, and the author blocklist (ban / unban).
//!
//! The whole subtree is gated by [`crate::auth::require_admin`] (applied as a router middleware
//! in [`crate::app`]): an ordinary signed-in user gets a branded `403`, only members of
//! `admins` / `infra-admins` reach these handlers. Every state-changing POST is additionally
//! double-submit CSRF protected, and every mutation emits an [`AuditEvent`] (a `notice` for the
//! destructive ones). All interpolated user input is HTML-escaped; the dashboard is rendered
//! into the same enterprise shell as the rest of the app.

use axum::extract::{Form, Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth;
use crate::error::AppError;
use crate::handlers::forum::{html_response, redirect_to, render_admin_thread_toolbar};
use crate::handlers::{email_display, esc, fmt_ts, render_page};
use crate::model::{BannedAuthor, Category};
use crate::{now_secs, AppState};

/// Recent threads listed on the admin dashboard.
const ADMIN_THREAD_LIMIT: i64 = 100;
/// Caps on operator input (the store columns are TEXT; these just reject absurd payloads).
const MAX_CATEGORY_ID: usize = 64;
const MAX_NAME: usize = 100;
const MAX_SUB: usize = 200;
const MAX_REASON: usize = 500;

/// The acting admin's identity for the audit trail: their email, falling back to the subject.
fn actor(headers: &HeaderMap) -> String {
    auth::identity_email(headers)
        .or_else(|| auth::identity_subject(headers))
        .unwrap_or_else(|| "admin".to_string())
}

// ===========================================================================
// GET /admin — dashboard
// ===========================================================================

pub async fn dashboard(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let categories = state.store.list_categories().await?;
    let threads = state.store.recent_threads(ADMIN_THREAD_LIMIT).await?;
    let bans = state.store.list_bans().await?;

    // --- categories: rename / reorder / delete rows + a create form ---------
    let mut cat_rows = String::new();
    for c in &categories {
        let count = state.store.count_threads(&c.id).await?;
        cat_rows.push_str(&format!(
            r#"<div class="admin-row">
  <form class="inline-form" method="post" action="/admin/categories/{id}/rename">
    <input type="hidden" name="csrf" value="{csrf}">
    <input type="text" name="name" maxlength="{maxn}" value="{name}" required>
    <button class="btn btn-secondary btn-sm" type="submit">Rename</button>
  </form>
  <span class="muted">{count} {tw} · <code>{id}</code></span>
  <form class="inline-form" method="post" action="/admin/categories/{id}/reorder">
    <input type="hidden" name="csrf" value="{csrf}">
    <button class="btn btn-ghost btn-sm" name="dir" value="up" type="submit">↑</button>
    <button class="btn btn-ghost btn-sm" name="dir" value="down" type="submit">↓</button>
  </form>
  <form class="inline-form" method="post" action="/admin/categories/{id}/delete" onsubmit="return confirm('Delete this category?');">
    <input type="hidden" name="csrf" value="{csrf}">
    <button class="btn btn-danger btn-sm" type="submit">Delete</button>
  </form>
</div>"#,
            id = esc(&c.id),
            csrf = esc(&csrf),
            maxn = MAX_NAME,
            name = esc(&c.name),
            count = count,
            tw = if count == 1 { "thread" } else { "threads" },
        ));
    }

    let create_cat = format!(
        r#"<form class="form inline-form" method="post" action="/admin/categories">
  <input type="hidden" name="csrf" value="{csrf}">
  <input type="text" name="id" maxlength="{maxid}" placeholder="slug-id" required>
  <input type="text" name="name" maxlength="{maxn}" placeholder="Display name" required>
  <button class="btn btn-primary btn-sm" type="submit">Add category</button>
</form>"#,
        csrf = esc(&csrf),
        maxid = MAX_CATEGORY_ID,
        maxn = MAX_NAME,
    );

    // --- threads: each with the shared lock/pin/move/delete toolbar ---------
    let mut thread_rows = String::new();
    for t in &threads {
        thread_rows.push_str(&format!(
            r#"<div class="admin-row">
  <a class="thread-row__title" href="/t/{id}">{title}</a>
  {toolbar}
</div>"#,
            id = esc(&t.id),
            title = esc(&t.title),
            toolbar = render_admin_thread_toolbar(t, &categories, &csrf),
        ));
    }
    if thread_rows.is_empty() {
        thread_rows = r#"<div class="empty">No threads yet.</div>"#.to_string();
    }

    // --- bans: list + remove, plus an add form ------------------------------
    let mut ban_rows = String::new();
    for b in &bans {
        ban_rows.push_str(&format!(
            r#"<div class="admin-row">
  <span><code>{sub}</code>{reason} <span class="muted">· by {by} · {when}</span></span>
  <form class="inline-form" method="post" action="/admin/bans/{sub_enc}/delete">
    <input type="hidden" name="csrf" value="{csrf}">
    <button class="btn btn-secondary btn-sm" type="submit">Unban</button>
  </form>
</div>"#,
            sub = esc(&b.author_sub),
            reason = if b.reason.is_empty() {
                String::new()
            } else {
                format!(" — {}", esc(&b.reason))
            },
            by = esc(&b.banned_by),
            when = esc(&fmt_ts(b.created_at)),
            sub_enc = esc(&b.author_sub),
            csrf = esc(&csrf),
        ));
    }
    if ban_rows.is_empty() {
        ban_rows = r#"<div class="empty">No blocked authors.</div>"#.to_string();
    }
    let add_ban = format!(
        r#"<form class="form inline-form" method="post" action="/admin/bans">
  <input type="hidden" name="csrf" value="{csrf}">
  <input type="text" name="author_sub" maxlength="{maxsub}" placeholder="author subject id" required>
  <input type="text" name="reason" maxlength="{maxr}" placeholder="reason (optional)">
  <button class="btn btn-danger btn-sm" type="submit">Block author</button>
</form>"#,
        csrf = esc(&csrf),
        maxsub = MAX_SUB,
        maxr = MAX_REASON,
    );

    let content = format!(
        r#"<nav class="crumbs"><a href="/">Home</a><span class="crumbs__sep">/</span><span>Admin</span></nav>
<div class="page-head"><div><h1>Admin</h1><p class="muted">Moderate categories, threads, and authors.</p></div></div>
<section class="section">
  <h2 class="section__title">Categories</h2>
  <div class="card pad">{cat_rows}{create_cat}</div>
</section>
<section class="section">
  <h2 class="section__title">Threads</h2>
  <div class="card pad">{thread_rows}</div>
</section>
<section class="section">
  <h2 class="section__title">Blocked authors</h2>
  <div class="card pad">{ban_rows}{add_ban}</div>
</section>"#,
        cat_rows = cat_rows,
        create_cat = create_cat,
        thread_rows = thread_rows,
        ban_rows = ban_rows,
        add_ban = add_ban,
    );

    let html = render_page("Admin", &email_display(&headers), &content);
    Ok(html_response(html, set_cookie))
}

// ===========================================================================
// Category CRUD
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct CreateCategoryForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
}

pub async fn create_category(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateCategoryForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;

    let id = form.id.trim();
    if !is_valid_slug(id) || id.len() > MAX_CATEGORY_ID {
        return Err(AppError::InvalidRequest(
            "category id must be a slug of lowercase letters, digits and hyphens".to_string(),
        ));
    }
    let name = form.name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME {
        return Err(AppError::InvalidRequest("category name is required".to_string()));
    }
    if state.store.get_category(id).await?.is_some() {
        return Err(AppError::InvalidRequest("a category with that id already exists".to_string()));
    }

    // Append to the end of the current ordering.
    let next_order = state
        .store
        .list_categories()
        .await?
        .iter()
        .map(|c| c.sort_order)
        .max()
        .map(|m| m + 1)
        .unwrap_or(0);
    let category = Category {
        id: id.to_string(),
        name: name.to_string(),
        sort_order: next_order,
    };
    state.store.create_category(&category).await?;
    state
        .audit
        .emit(AuditEvent::notice("admin.category.create", &actor(&headers), &category.id, name));
    Ok(redirect_to("/admin"))
}

#[derive(Debug, Deserialize)]
pub struct RenameCategoryForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub name: String,
}

pub async fn rename_category(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<RenameCategoryForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    if state.store.get_category(&id).await?.is_none() {
        return Err(AppError::NotFound("category not found".to_string()));
    }
    let name = form.name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME {
        return Err(AppError::InvalidRequest("category name is required".to_string()));
    }
    state.store.rename_category(&id, name).await?;
    state
        .audit
        .emit(AuditEvent::notice("admin.category.rename", &actor(&headers), &id, name));
    Ok(redirect_to("/admin"))
}

#[derive(Debug, Deserialize)]
pub struct ReorderForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub dir: String,
}

pub async fn reorder_category(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<ReorderForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let cats = state.store.list_categories().await?; // sorted by (sort_order, name)
    let pos = cats
        .iter()
        .position(|c| c.id == id)
        .ok_or_else(|| AppError::NotFound("category not found".to_string()))?;

    // Swap `sort_order` with the neighbor in the requested direction. Boundary moves are no-ops.
    let neighbor = match form.dir.trim() {
        "up" if pos > 0 => Some(pos - 1),
        "down" if pos + 1 < cats.len() => Some(pos + 1),
        "up" | "down" => None,
        _ => return Err(AppError::InvalidRequest("reorder direction must be up or down".to_string())),
    };
    if let Some(n) = neighbor {
        let (a, b) = (&cats[pos], &cats[n]);
        // If two categories share a sort_order, nudge to keep the swap meaningful.
        let (ao, bo) = if a.sort_order == b.sort_order {
            (b.sort_order, a.sort_order + if n > pos { 1 } else { -1 })
        } else {
            (b.sort_order, a.sort_order)
        };
        state.store.set_category_order(&a.id, ao).await?;
        state.store.set_category_order(&b.id, bo).await?;
        state
            .audit
            .emit(AuditEvent::notice("admin.category.reorder", &actor(&headers), &id, form.dir.trim()));
    }
    Ok(redirect_to("/admin"))
}

#[derive(Debug, Deserialize)]
pub struct CsrfForm {
    #[serde(default)]
    pub csrf: String,
}

pub async fn delete_category(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    if state.store.get_category(&id).await?.is_none() {
        return Err(AppError::NotFound("category not found".to_string()));
    }
    // Refuse to orphan threads: a non-empty category must be emptied (or its threads moved) first.
    if state.store.count_threads(&id).await? > 0 {
        return Err(AppError::InvalidRequest(
            "category still has threads — move or delete them first".to_string(),
        ));
    }
    state.store.delete_category(&id).await?;
    state
        .audit
        .emit(AuditEvent::notice("admin.category.delete", &actor(&headers), &id, "delete"));
    Ok(redirect_to("/admin"))
}

// ===========================================================================
// Thread moderation
// ===========================================================================

pub async fn lock_thread(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let thread = state
        .store
        .get_thread(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("thread not found".to_string()))?;
    let locked = !thread.locked;
    state.store.set_thread_locked(&id, locked).await?;
    state.audit.emit(AuditEvent::notice(
        "admin.thread.lock",
        &actor(&headers),
        &id,
        if locked { "locked" } else { "unlocked" },
    ));
    Ok(redirect_to(&format!("/t/{id}")))
}

pub async fn pin_thread(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let thread = state
        .store
        .get_thread(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("thread not found".to_string()))?;
    let pinned = !thread.pinned;
    state.store.set_thread_pinned(&id, pinned).await?;
    state.audit.emit(AuditEvent::notice(
        "admin.thread.pin",
        &actor(&headers),
        &id,
        if pinned { "pinned" } else { "unpinned" },
    ));
    Ok(redirect_to(&format!("/t/{id}")))
}

#[derive(Debug, Deserialize)]
pub struct MoveThreadForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub category: String,
}

pub async fn move_thread(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<MoveThreadForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    if state.store.get_thread(&id).await?.is_none() {
        return Err(AppError::NotFound("thread not found".to_string()));
    }
    let category_id = form.category.trim();
    if state.store.get_category(category_id).await?.is_none() {
        return Err(AppError::InvalidRequest("unknown category".to_string()));
    }
    state.store.move_thread(&id, category_id).await?;
    state
        .audit
        .emit(AuditEvent::notice("admin.thread.move", &actor(&headers), &id, category_id));
    Ok(redirect_to(&format!("/t/{id}")))
}

pub async fn delete_thread(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    if state.store.get_thread(&id).await?.is_none() {
        return Err(AppError::NotFound("thread not found".to_string()));
    }
    state.store.delete_thread(&id).await?;
    state
        .audit
        .emit(AuditEvent::notice("admin.thread.delete", &actor(&headers), &id, "delete"));
    Ok(redirect_to("/admin"))
}

// ===========================================================================
// Any-post deletion
// ===========================================================================

pub async fn delete_post(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let post = state
        .store
        .get_post(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("post not found".to_string()))?;
    let thread_id = post.thread_id.clone();
    state.store.delete_post(&id).await?;
    state
        .audit
        .emit(AuditEvent::notice("admin.post.delete", &actor(&headers), &id, &thread_id));
    Ok(redirect_to(&format!("/t/{thread_id}")))
}

// ===========================================================================
// Author blocklist
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct AddBanForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub author_sub: String,
    #[serde(default)]
    pub reason: String,
}

pub async fn add_ban(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AddBanForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let author_sub = form.author_sub.trim();
    if author_sub.is_empty() || author_sub.len() > MAX_SUB {
        return Err(AppError::InvalidRequest("author subject id is required".to_string()));
    }
    let reason = form.reason.trim();
    if reason.chars().count() > MAX_REASON {
        return Err(AppError::InvalidRequest("reason is too long".to_string()));
    }
    let ban = BannedAuthor {
        author_sub: author_sub.to_string(),
        reason: reason.to_string(),
        banned_by: actor(&headers),
        created_at: now_secs(),
    };
    state.store.add_ban(&ban).await?;
    state
        .audit
        .emit(AuditEvent::notice("admin.author.ban", &actor(&headers), author_sub, reason));
    Ok(redirect_to("/admin"))
}

pub async fn remove_ban(
    State(state): State<AppState>,
    Path(sub): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    state.store.remove_ban(&sub).await?;
    state
        .audit
        .emit(AuditEvent::notice("admin.author.unban", &actor(&headers), &sub, "unban"));
    Ok(redirect_to("/admin"))
}

/// A URL/DOM-safe category slug: non-empty, lowercase ascii letters, digits, or hyphens.
fn is_valid_slug(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}
