//! Admin moderation panel (`/admin` subtree).
//!
//! The whole subtree is gated by [`auth::require_admin`]: an ordinary signed-in user gets 403;
//! only `admins` / `infra-admins` see the panel. It provides:
//! - a listing of EVERY comment across all threads with bulk hide / unhide / delete-any controls
//!   (the per-comment moderate logic already lives in the store; this builds the admin surface), and
//! - an author blocklist keyed by `author_sub` — blocking hides an author's existing comments and
//!   [`comments::post_comment`](super::comments) rejects any new ones.
//!
//! Every state-changing POST is double-submit CSRF protected and emits an [`AuditEvent`] (a
//! `notice` for the destructive actions). All user-supplied text is HTML-escaped on render.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Form;
use serde::Deserialize;
use std::collections::HashMap;

use crate::audit::AuditEvent;
use crate::auth;
use crate::config::MAX_PAGE;
use crate::error::AppError;
use crate::handlers::comments::{html_with_cookie, local_redirect, path_seg, redirect};
use crate::handlers::{esc, fmt_datetime, topbar};
use crate::markdown;
use crate::store::{BlockedAuthor, Comment, CommentReport, Thread};
use crate::{now_secs, AppState};

const ADMIN_HTML: &str = include_str!("../../templates/admin.html");

/// `POST /admin/block` body — add an author to the blocklist.
#[derive(Debug, Deserialize)]
pub struct BlockForm {
    #[serde(default)]
    pub author_sub: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub return_to: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// `POST /admin/unblock` body — remove an author from the blocklist.
#[derive(Debug, Deserialize)]
pub struct UnblockForm {
    #[serde(default)]
    pub author_sub: String,
    #[serde(default)]
    pub return_to: String,
    #[serde(default)]
    pub csrf_token: String,
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

/// `GET /admin` — the moderation panel: every comment (grouped under its thread) with a bulk
/// hide/unhide/delete form, plus the author blocklist. Admin-gated; a non-admin gets a 403 page.
pub async fn dashboard(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    auth::require_admin(&headers)?;
    let email = auth::display_email(&headers);
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    // Newest threads first; for each, its comments oldest-first (the store's natural order).
    let threads = state.store.list_threads(None, MAX_PAGE).await;
    let mut queue: Vec<(Thread, Comment)> = Vec::new();
    for t in &threads {
        for c in &state.store.list_comments(&t.id).await {
            queue.push((t.clone(), c.clone()));
        }
    }
    let ids: Vec<String> = queue.iter().map(|(_, c)| c.id.clone()).collect();
    let reports = state.store.reports_for(&ids).await;
    let report_summary = ReportSummaries::build(&reports);

    let mut rows = String::new();
    for (t, c) in &queue {
        rows.push_str(&render_mod_row(t, c, &report_summary));
    }
    if rows.is_empty() {
        rows.push_str(r#"<tr><td colspan="7" class="table__empty">No comments yet.</td></tr>"#);
    }
    let moderation = render_moderation_form(&rows, &csrf);

    let blocked = state.store.list_blocked().await;
    let blocklist = render_blocklist(&blocked, &csrf);
    let block_form = render_block_form(&csrf);

    let body = ADMIN_HTML
        .replace("{{TOPBAR}}", &topbar("Admin", &email))
        .replace("{{MODERATION}}", &moderation)
        .replace("{{BLOCKLIST}}", &blocklist)
        .replace("{{BLOCK_FORM}}", &block_form);
    Ok(html_with_cookie(body, set_cookie))
}

// ---------------------------------------------------------------------------
// Bulk moderate (hide / unhide / delete-any)
// ---------------------------------------------------------------------------

/// `POST /admin/moderate` — apply one action to the selected comments. The clicked submit button
/// supplies `action` (`hide` | `unhide` | `delete`); each ticked checkbox supplies a repeated
/// `comment_id`. Admin-gated + CSRF; `delete` uses the store's "delete any" (no ownership check).
///
/// The body is decoded as an ordered list of `(key, value)` pairs so the repeated `comment_id`
/// checkboxes all survive (a struct would keep only the last).
pub async fn moderate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Result<Response, AppError> {
    auth::require_admin(&headers)?;
    let (sub, email) = auth::require_author(&headers)?;

    let mut action = String::new();
    let mut csrf = String::new();
    let mut return_to = String::new();
    let mut ids: Vec<String> = Vec::new();
    for (k, v) in &pairs {
        match k.as_str() {
            "action" => action = v.clone(),
            "csrf_token" => csrf = v.clone(),
            "return_to" => return_to = v.clone(),
            "comment_id" => {
                let id = v.trim();
                if !id.is_empty() {
                    ids.push(id.to_string());
                }
            }
            _ => {}
        }
    }
    auth::verify_csrf(&headers, &csrf)?;

    // None => delete; Some(bool) => set hidden.
    let hidden = match action.trim() {
        "hide" => Some(true),
        "unhide" => Some(false),
        "delete" => None,
        other => {
            return Err(AppError::InvalidRequest(format!(
                "unknown action {other} (use hide|unhide|delete)"
            )));
        }
    };
    if ids.is_empty() {
        return Err(AppError::InvalidRequest("no comments selected".to_string()));
    }

    let mut affected = 0u64;
    for id in &ids {
        let changed = match hidden {
            Some(h) => state.store.set_comment_hidden(id, h).await?,
            None => state.store.delete_comment_any(id).await?,
        };
        if changed {
            affected += 1;
        }
    }
    tracing::info!(action = %action, selected = ids.len(), affected, "admin bulk moderate");

    let actor = if email.is_empty() { &sub } else { &email };
    state.audit.emit(AuditEvent::notice(
        "echo.admin.moderate",
        actor,
        &format!("{affected} comment(s)"),
        action.trim(),
    ));

    Ok(redirect(&local_redirect(&return_to, "/admin")))
}

// ---------------------------------------------------------------------------
// Blocklist
// ---------------------------------------------------------------------------

/// `POST /admin/block` — add an author to the blocklist and hide their existing comments. Admin-gated
/// + CSRF. Idempotent: re-blocking an already-blocked author still (re-)hides their comments.
pub async fn block(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<BlockForm>,
) -> Result<Response, AppError> {
    auth::require_admin(&headers)?;
    let (sub, email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let target = form.author_sub.trim();
    if target.is_empty() {
        return Err(AppError::InvalidRequest(
            "author_sub is required".to_string(),
        ));
    }
    let actor = if email.is_empty() {
        sub.clone()
    } else {
        email.clone()
    };

    let entry = BlockedAuthor {
        author_sub: target.to_string(),
        reason: form.reason.trim().to_string(),
        blocked_by: actor.clone(),
        created_at: now_secs(),
    };
    state.store.block_author(&entry).await?;
    // Blocking hides everything the author has already posted.
    let hidden = state.store.set_hidden_by_author(target, true).await?;
    tracing::info!(author = %target, hidden, "author blocked");

    state.audit.emit(AuditEvent::notice(
        "echo.admin.block",
        &actor,
        target,
        &format!("hid {hidden} comment(s)"),
    ));

    Ok(redirect(&local_redirect(&form.return_to, "/admin")))
}

/// `POST /admin/unblock` — remove an author from the blocklist and restore (unhide) their comments.
/// Admin-gated + CSRF. A `author_sub` that is not on the list returns 404.
pub async fn unblock(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<UnblockForm>,
) -> Result<Response, AppError> {
    auth::require_admin(&headers)?;
    let (sub, email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let target = form.author_sub.trim();
    if target.is_empty() {
        return Err(AppError::InvalidRequest(
            "author_sub is required".to_string(),
        ));
    }
    let removed = state.store.unblock_author(target).await?;
    if !removed {
        return Err(AppError::NotFound(
            "author is not on the blocklist".to_string(),
        ));
    }
    // Symmetric with block: unblocking restores the author's previously auto-hidden comments.
    let restored = state.store.set_hidden_by_author(target, false).await?;
    tracing::info!(author = %target, restored, "author unblocked");

    let actor = if email.is_empty() { &sub } else { &email };
    state.audit.emit(AuditEvent::notice(
        "echo.admin.unblock",
        actor,
        target,
        &format!("restored {restored} comment(s)"),
    ));

    Ok(redirect(&local_redirect(&form.return_to, "/admin")))
}

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------

/// The display title for a thread: its title when set, else the key.
fn display_title(t: &Thread) -> String {
    if t.title.trim().is_empty() {
        t.key.clone()
    } else {
        t.title.clone()
    }
}

/// The author display label: email when present, else the opaque subject id.
fn author_label(c: &Comment) -> String {
    if c.author_email.trim().is_empty() {
        c.author_sub.clone()
    } else {
        c.author_email.clone()
    }
}

/// Reports folded by comment id for the moderation table.
struct ReportSummaries {
    by_comment: HashMap<String, Vec<CommentReport>>,
}

impl ReportSummaries {
    fn build(rows: &[CommentReport]) -> Self {
        let mut by_comment: HashMap<String, Vec<CommentReport>> = HashMap::new();
        for r in rows {
            by_comment
                .entry(r.comment_id.clone())
                .or_default()
                .push(r.clone());
        }
        ReportSummaries { by_comment }
    }

    fn for_comment(&self, comment_id: &str) -> &[CommentReport] {
        self.by_comment
            .get(comment_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

/// One row of the bulk-moderation table: a select checkbox, the thread link, author, a body
/// preview, the report summary, the hidden/visible status, and the created time. Every field is
/// HTML-escaped.
fn render_mod_row(t: &Thread, c: &Comment, reports: &ReportSummaries) -> String {
    let status = if c.hidden {
        r#"<span class="badge badge-hidden">Hidden</span>"#
    } else {
        r#"<span class="muted">Visible</span>"#
    };
    let report_html = render_report_summary(reports.for_comment(&c.id));
    format!(
        r#"<tr>
  <td><input type="checkbox" name="comment_id" value="{id}"></td>
  <td><a href="/t/{key}">{title}</a></td>
  <td>{author}</td>
  <td>{preview}</td>
  <td>{reports}</td>
  <td>{status}</td>
  <td class="muted">{created}</td>
</tr>"#,
        id = esc(&c.id),
        key = esc(&path_seg(&t.key)),
        title = esc(&display_title(t)),
        author = esc(&author_label(c)),
        preview = esc(&markdown::preview(&c.body, 120)),
        reports = report_html,
        status = status,
        created = esc(&fmt_datetime(c.created_at)),
    )
}

fn render_report_summary(reports: &[CommentReport]) -> String {
    if reports.is_empty() {
        return r#"<span class="muted">None</span>"#.to_string();
    }
    let mut reasons = String::new();
    for r in reports {
        reasons.push_str(&format!(
            r#"<li><span class="mono">{who}</span>: {reason}</li>"#,
            who = esc(&r.reporter_sub),
            reason = esc(&preview_text(&r.reason, 120)),
        ));
    }
    let label = if reports.len() == 1 {
        "report"
    } else {
        "reports"
    };
    format!(
        r#"<div class="report-summary"><span class="badge badge-warn">{n} {label}</span><ul>{reasons}</ul></div>"#,
        n = reports.len(),
        label = label,
        reasons = reasons,
    )
}

fn preview_text(s: &str, max_chars: usize) -> String {
    let trimmed = s.trim();
    let mut out: String = trimmed.chars().take(max_chars).collect();
    if trimmed.chars().count() > max_chars {
        out.push_str("...");
    }
    out
}

/// Wrap the comment rows in the bulk-action form. Three submit buttons share the `action` name so
/// the clicked one selects the operation applied to every ticked `comment_id`.
fn render_moderation_form(rows: &str, csrf: &str) -> String {
    format!(
        r#"<form class="admin-mod" method="post" action="/admin/moderate">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <input type="hidden" name="return_to" value="/admin">
  <table class="table">
    <thead><tr><th></th><th>Thread</th><th>Author</th><th>Comment</th><th>Reports</th><th>Status</th><th>Created</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <div class="composer__actions">
    <button class="btn btn-secondary btn-sm" type="submit" name="action" value="hide">Hide selected</button>
    <button class="btn btn-secondary btn-sm" type="submit" name="action" value="unhide">Unhide selected</button>
    <button class="btn btn-danger btn-sm" type="submit" name="action" value="delete">Delete selected</button>
  </div>
</form>"#,
        csrf = esc(csrf),
        rows = rows,
    )
}

/// The blocklist table: one row per blocked author with an inline unblock form.
fn render_blocklist(blocked: &[BlockedAuthor], csrf: &str) -> String {
    if blocked.is_empty() {
        return r#"<p class="muted">No authors are blocked.</p>"#.to_string();
    }
    let mut rows = String::new();
    for b in blocked {
        rows.push_str(&format!(
            r#"<tr>
  <td class="mono">{author}</td>
  <td>{reason}</td>
  <td class="muted">{by}</td>
  <td class="muted">{created}</td>
  <td>
    <form class="inline-form" method="post" action="/admin/unblock">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <input type="hidden" name="author_sub" value="{author}">
      <input type="hidden" name="return_to" value="/admin">
      <button class="btn btn-secondary btn-sm" type="submit">Unblock</button>
    </form>
  </td>
</tr>"#,
            author = esc(&b.author_sub),
            reason = esc(&b.reason),
            by = esc(&b.blocked_by),
            created = esc(&fmt_datetime(b.created_at)),
            csrf = esc(csrf),
        ));
    }
    format!(
        r#"<table class="table">
  <thead><tr><th>Author</th><th>Reason</th><th>Blocked by</th><th>When</th><th></th></tr></thead>
  <tbody>{rows}</tbody>
</table>"#,
        rows = rows,
    )
}

/// The "block an author" form.
fn render_block_form(csrf: &str) -> String {
    format!(
        r#"<form class="composer-form" method="post" action="/admin/block">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <input type="hidden" name="return_to" value="/admin">
  <input class="field" type="text" name="author_sub" required placeholder="author_sub to block">
  <input class="field" type="text" name="reason" placeholder="reason (optional)">
  <div class="composer__actions"><button class="btn btn-primary btn-sm" type="submit">Block author</button></div>
</form>"#,
        csrf = esc(csrf),
    )
}
