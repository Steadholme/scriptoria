//! The SSO pastebin surface: new-paste form, create, view, raw, delete.
//!
//! Mounted behind a Sluice `auth=sso` route: the gateway authenticates the user and injects
//! `X-Auth-Subject` / `X-Auth-Email`, which we trust (Pastefire is internal-only). The author
//! of a paste is ALWAYS those headers — never a client-supplied field. State-changing POSTs
//! (`create`, `delete`) carry a double-submit CSRF token. Every producer-supplied string is
//! HTML-escaped on render, and the raw endpoint serves `text/plain` (+ `nosniff`), so a paste
//! body can never execute as HTML.

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth::{self, Identity};
use crate::config::{clamp_page, DEFAULT_PAGE, MAX_BODY_BYTES, MAX_TITLE_CHARS};
use crate::error::AppError;
use crate::handlers::{
    esc, expiry_options, fmt_ts, language_label, language_options, parse_expiry, userbox, APP_CSS,
    LANGUAGES, SHIELD_SVG,
};
use crate::model::{Paste, PasteFile, PasteRevision};
use crate::{highlight, now_secs, random_alnum, similar, AppState};

/// Length of the short random paste id (62-symbol alphabet => ~48 bits at 8 chars; the
/// `ON CONFLICT` insert retries on the astronomically rare collision).
const PASTE_ID_LEN: usize = 8;

/// Length of the random `paste_files.id` primary key (never surfaced in a URL).
const FILE_ID_LEN: usize = 12;

/// Upper bound on the number of files a single paste may hold (bounds per-request work).
const MAX_FILES: usize = 20;

/// Upper bound on a stored filename length (characters).
const MAX_FILENAME_CHARS: usize = 128;

/// A small file glyph for the multi-file per-file header.
const FILE_ICON_SVG: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg>"##;

/// One file's worth of submitted form input (a filename + its content), before it is assigned an
/// id/position and persisted. A paste with a single [`FileInput`] is stored the legacy way (in
/// `pastes.body` only, no `paste_files` rows), so single-file pastes stay byte-identical.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FileInput {
    filename: String,
    content: String,
}

const NEW_HTML: &str = include_str!("../../templates/new.html");
const VIEW_HTML: &str = include_str!("../../templates/view.html");
const EDIT_HTML: &str = include_str!("../../templates/edit.html");
const UNLOCK_HTML: &str = include_str!("../../templates/unlock.html");
const HISTORY_HTML: &str = include_str!("../../templates/history.html");

// ---------------------------------------------------------------------------
// GET / — new-paste form + "my recent pastes"
// ---------------------------------------------------------------------------

/// Query string for the recent-pastes list: an optional backward keyset cursor
/// (`?before=<created_at>_<id>`) and an optional page size (`?limit=`).
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub before: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
}

/// `GET /` — render the new-paste form (with a fresh CSRF token) and the author's recent pastes,
/// one keyset page (newest by default; `?before=<created_at>_<id>` walks older pages).
pub async fn new_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Response {
    let who = auth::identity(&headers);
    let now = now_secs();
    let csrf = auth::new_csrf_token();
    let before = q.before.as_deref().and_then(parse_before);
    let limit = clamp_page(q.limit);
    let recent = state
        .store
        .list_by_author(&who.subject, now, before, limit)
        .await
        .unwrap_or_default();
    let load_older = render_load_older(&recent, limit, q.limit);

    let html = render_new(
        &who, &csrf, &recent, &load_older, None, "", "plaintext", "never", false, &[],
    );
    html_with_csrf(StatusCode::OK, html, &csrf)
}

// ---------------------------------------------------------------------------
// POST / — create a paste
// ---------------------------------------------------------------------------

/// Interpret a checkbox form value: present and non-empty (e.g. `on`) => checked.
fn checkbox_on(value: &str) -> bool {
    !value.trim().is_empty()
}

/// `POST /` — validate + store a paste, then 302 to `/p/{id}`. On a validation error the form
/// is re-rendered (preserving the user's input) with an inline message.
///
/// The body is parsed by hand (not `Form<T>`) because a multi-file paste submits repeated
/// `file_name` / `file_content` fields, which `serde_urlencoded` cannot map into a sequence. A
/// paste with a single file is stored the legacy way; the older single-`body` field is still
/// accepted (so pre-existing clients/tests keep working).
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, AppError> {
    let pairs = parse_pairs(&body);
    if !auth::verify_csrf(&headers, field(&pairs, "csrf_token")) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and submit again.".to_string(),
        ));
    }

    let who = auth::identity(&headers);
    let now = now_secs();
    let title = field(&pairs, "title").trim();
    let language = field(&pairs, "language");
    let expiry = field(&pairs, "expiry");
    let burn = field(&pairs, "burn");
    let password = field(&pairs, "password");
    let files = collect_files_or_legacy(&pairs);

    // Validation: at least one non-empty file, within the overall byte budget. On failure
    // re-render the form with the input intact and a fresh CSRF token.
    if let Some(msg) = files_problem(&files) {
        let csrf = auth::new_csrf_token();
        let recent = state
            .store
            .list_by_author(&who.subject, now, None, DEFAULT_PAGE)
            .await
            .unwrap_or_default();
        let load_older = render_load_older(&recent, DEFAULT_PAGE, None);
        let html = render_new(
            &who,
            &csrf,
            &recent,
            &load_older,
            Some(msg),
            title,
            language,
            expiry,
            checkbox_on(burn),
            &files,
        );
        return Ok(html_with_csrf(StatusCode::BAD_REQUEST, html, &csrf));
    }

    let mut paste = Paste {
        id: String::new(),
        title: title.chars().take(MAX_TITLE_CHARS).collect(),
        body: combined_body(&files),
        language: normalize_language(language),
        author_sub: who.subject.clone(),
        author_email: who.email.clone(),
        created_at: now,
        expires_at: parse_expiry(expiry, now),
        burn_after_read: checkbox_on(burn),
        source_id: None,
        password_hash: password_hash(password),
    };

    // Allocate a unique id: generate, try to insert, retry on the rare collision.
    let mut created = false;
    for _ in 0..6 {
        paste.id = random_alnum(PASTE_ID_LEN);
        if state.store.create(&paste).await? {
            created = true;
            break;
        }
    }
    if !created {
        return Err(AppError::Internal(
            "could not allocate a unique paste id".to_string(),
        ));
    }

    // Persist the per-file breakdown ONLY for a genuinely multi-file paste; a single file lives
    // in `pastes.body` alone (byte-identical to the legacy single-content path).
    if files.len() >= 2 {
        let rows = build_file_rows(&paste.id, &files);
        state.store.set_files(&paste.id, &rows).await?;
    }

    tracing::info!(id = paste.id, author = who.subject, files = files.len(), "paste created");

    // Tamper-evident trail: record the create AFTER the store insert succeeded. `detail` is
    // value-free metadata (never the body) — only whether the paste self-destructs on read.
    let actor = if who.email.is_empty() {
        &who.subject
    } else {
        &who.email
    };
    state.audit.emit(AuditEvent::info(
        "paste.create",
        actor,
        &paste.id,
        if paste.burn_after_read {
            "burn-after-read"
        } else {
            "standard"
        },
    ));

    Ok(redirect_found(&format!("/p/{}", paste.id)))
}

// ---------------------------------------------------------------------------
// GET /p/{id} — view a paste
// ---------------------------------------------------------------------------

/// Query string for the view: an optional `?lines=<start>[-<end>]` line-range to highlight, the
/// server side of the line-range permalink (the client `#L10-L20` hash handler applies the same
/// highlight without a round-trip).
#[derive(Debug, Deserialize)]
pub struct ViewQuery {
    #[serde(default)]
    pub lines: Option<String>,
}

/// `GET /p/{id}` — render the paste (honoring expiry), syntax-highlighted with a numbered line
/// gutter, with a "similar pastes" panel. An optional `?lines=<start>[-<end>]` highlights that
/// row range. The delete control is shown only to the author. A burn-after-read paste is
/// deleted after this render when the viewer is NOT its author (so the author can still open it
/// to copy the share link; the first recipient read consumes it).
pub async fn view(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<ViewQuery>,
) -> Result<Response, AppError> {
    let viewer = auth::identity(&headers);
    let now = now_secs();

    let paste = load_live(&state, &id, now).await?;
    let is_owner = paste.author_sub == viewer.subject;

    // Password gate: a non-owner of a protected paste sees a password prompt (body withheld, and
    // — importantly — a burn paste is NOT consumed until the password actually reveals it).
    if paste.password_hash.is_some() && !is_owner {
        let csrf = auth::new_csrf_token();
        let html = render_unlock(&viewer, &paste.id, &csrf, None);
        return Ok(html_with_csrf(StatusCode::OK, html, &csrf));
    }

    let highlight_lines = q.lines.as_deref().and_then(parse_lines);
    let csrf = auth::new_csrf_token();
    let html = render_paste_view(&state, &paste, &viewer, is_owner, &csrf, highlight_lines, now).await;

    // Burn-after-read: this recipient's read consumes the paste (see [`maybe_burn`]).
    maybe_burn(&state, &paste, &viewer, is_owner).await;

    Ok(html_with_csrf(StatusCode::OK, html, &csrf))
}

/// Fetch a live (existing, non-expired) paste or map to the right 404. Shared by every read path.
async fn load_live(state: &AppState, id: &str, now: i64) -> Result<Paste, AppError> {
    match state.store.get(id).await? {
        Some(p) if !p.is_expired(now) => Ok(p),
        Some(_) => Err(AppError::NotFound(
            "This paste has expired and is no longer available.".to_string(),
        )),
        None => Err(AppError::NotFound("No paste exists at that link.".to_string())),
    }
}

/// Consume a burn-after-read paste once a non-author has actually seen its body. Best-effort,
/// never fatal — a failed purge leaves the paste readable rather than failing a good render.
async fn maybe_burn(state: &AppState, paste: &Paste, viewer: &Identity, is_owner: bool) {
    if !paste.burn_after_read || is_owner {
        return;
    }
    if let Err(e) = state.store.delete(&paste.id, &paste.author_sub).await {
        tracing::warn!(id = paste.id, error = %e, "burn-after-read purge failed");
    } else {
        tracing::info!(id = paste.id, viewer = viewer.subject, "paste burned after read");
    }
}

/// Number of "similar pastes" surfaced on the view.
const SIMILAR_COUNT: usize = 3;
/// Candidate pool size scanned for similarity (bounds work per view).
const SIMILAR_POOL: i64 = 100;

/// Rank `paste`'s sibling pastes (same author, live, non-burn) by bag-of-words cosine overlap,
/// returning the top [`SIMILAR_COUNT`] with a non-zero score. Deterministic and fully local.
async fn similar_pastes(state: &AppState, paste: &Paste, now: i64) -> Vec<(f64, Paste)> {
    let candidates = state
        .store
        .list_for_similarity(&paste.author_sub, now, SIMILAR_POOL)
        .await
        .unwrap_or_default();

    let target = similar::bag(&similar::tokenize(&format!(
        "{} {}",
        paste.title, paste.body
    )));

    let mut scored: Vec<(f64, Paste)> = candidates
        .into_iter()
        .filter(|c| c.id != paste.id)
        .filter_map(|c| {
            let bag = similar::bag(&similar::tokenize(&format!("{} {}", c.title, c.body)));
            let score = similar::cosine(&target, &bag);
            (score > 0.0).then_some((score, c))
        })
        .collect();

    // Highest score first; id as a deterministic tiebreak.
    scored.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.1.id.cmp(&b.1.id))
    });
    scored.truncate(SIMILAR_COUNT);
    scored
}

// ---------------------------------------------------------------------------
// GET /raw/{id} — the raw body as text/plain
// ---------------------------------------------------------------------------

/// `GET /raw/{id}` — serve the body verbatim as `text/plain` (with `nosniff`, so a browser
/// never reinterprets it as HTML). Honors expiry. A raw read by a non-author also consumes a
/// burn-after-read paste (so a recipient cannot bypass the burn by fetching `/raw`).
pub async fn raw(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let viewer = auth::identity(&headers);
    let now = now_secs();
    match state.store.get(&id).await? {
        Some(p) if !p.is_expired(now) => {
            // A protected paste's raw body is owner-only — a non-owner must open it in the browser
            // and enter the password (the raw route has no unlock UI). This closes the obvious
            // bypass of fetching `/raw` to sidestep the prompt.
            if p.password_hash.is_some() && p.author_sub != viewer.subject {
                return Err(AppError::Forbidden(
                    "This paste is password-protected — open it from its main page to unlock."
                        .to_string(),
                ));
            }
            let body = p.body.clone();
            if p.burn_after_read && p.author_sub != viewer.subject {
                if let Err(e) = state.store.delete(&p.id, &p.author_sub).await {
                    tracing::warn!(id = p.id, error = %e, "burn-after-read purge (raw) failed");
                } else {
                    tracing::info!(id = p.id, viewer = viewer.subject, "paste burned after raw read");
                }
            }
            Ok((
                [
                    (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                    (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
                ],
                body,
            )
                .into_response())
        }
        Some(_) => Err(AppError::NotFound("This paste has expired.".to_string())),
        None => Err(AppError::NotFound("No paste exists at that link.".to_string())),
    }
}

// ---------------------------------------------------------------------------
// POST /delete/{id} — delete your own paste
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct DeleteForm {
    #[serde(default)]
    pub csrf_token: String,
}

/// `POST /delete/{id}` — CSRF-checked, ownership-scoped delete, then 302 to `/`. Deleting a
/// paste you do not own is a 403; a missing paste is a 404.
pub async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<DeleteForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let actor = auth::identity(&headers);

    if state.store.delete(&id, &actor.subject).await? {
        tracing::info!(id, author = actor.subject, "paste deleted");

        // Tamper-evident trail: record the delete AFTER the ownership-scoped purge succeeded.
        // Deletes are deliberate, destructive lifecycle events => `notice` severity.
        let who = if actor.email.is_empty() {
            &actor.subject
        } else {
            &actor.email
        };
        state
            .audit
            .emit(AuditEvent::notice("paste.delete", who, &id, "owner-delete"));

        return Ok(redirect_found("/"));
    }
    // Nothing deleted: distinguish "not yours" from "does not exist" for a precise message.
    match state.store.get(&id).await? {
        Some(_) => Err(AppError::Forbidden(
            "You can only delete your own pastes.".to_string(),
        )),
        None => Err(AppError::NotFound("No paste exists at that link.".to_string())),
    }
}

// ---------------------------------------------------------------------------
// POST /unlock/{id} — supply the password to view a protected paste
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct UnlockForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub password: String,
}

/// `POST /unlock/{id}` — verify the paste password and, on success, render the paste inline (the
/// reveal is stateless: a later reload re-prompts). CSRF-checked. An owner / an unprotected paste
/// needs no password and is simply redirected to the normal view.
pub async fn unlock(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<UnlockForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let viewer = auth::identity(&headers);
    let now = now_secs();
    let paste = load_live(&state, &id, now).await?;
    let is_owner = paste.author_sub == viewer.subject;

    // No password (or the owner) => nothing to unlock; go to the normal view.
    let Some(hash) = paste.password_hash.as_deref().filter(|_| !is_owner) else {
        return Ok(redirect_found(&format!("/p/{}", paste.id)));
    };

    if !auth::verify_password(&form.password, hash) {
        let csrf = auth::new_csrf_token();
        let html = render_unlock(&viewer, &paste.id, &csrf, Some("Incorrect password. Try again."));
        return Ok(html_with_csrf(StatusCode::BAD_REQUEST, html, &csrf));
    }

    let csrf = auth::new_csrf_token();
    let html = render_paste_view(&state, &paste, &viewer, is_owner, &csrf, None, now).await;
    // The reveal to this non-owner consumes a burn-after-read paste.
    maybe_burn(&state, &paste, &viewer, is_owner).await;
    Ok(html_with_csrf(StatusCode::OK, html, &csrf))
}

// ---------------------------------------------------------------------------
// GET/POST /edit/{id} — owner edits their paste (append-only history)
// ---------------------------------------------------------------------------

/// `GET /edit/{id}` — render the edit form pre-filled with the current files. Owner-only. A
/// legacy/single-content paste is shown as one file row (its body); a multi-file paste shows one
/// row per file.
pub async fn edit_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let now = now_secs();
    let paste = load_live(&state, &id, now).await?;
    if paste.author_sub != who.subject {
        return Err(AppError::Forbidden(
            "You can only edit your own pastes.".to_string(),
        ));
    }
    let files = load_file_inputs(&state, &paste).await;
    let csrf = auth::new_csrf_token();
    let html = render_edit(&who, &paste.id, None, &paste.title, &paste.language, &files, &csrf);
    Ok(html_with_csrf(StatusCode::OK, html, &csrf))
}

/// `POST /edit/{id}` — CSRF-checked, ownership-scoped edit (multi-file capable; still accepts the
/// legacy single-`body` field). The pre-edit content is appended to `paste_revisions`
/// (idempotently) and the paste row + `paste_files` are overwritten with the new content; an edit
/// that changes nothing is a no-op (no spurious revision). Then 302 to `/p/{id}`.
pub async fn edit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: String,
) -> Result<Response, AppError> {
    let pairs = parse_pairs(&body);
    if !auth::verify_csrf(&headers, field(&pairs, "csrf_token")) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and submit again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let now = now_secs();
    let paste = load_live(&state, &id, now).await?;
    if paste.author_sub != who.subject {
        return Err(AppError::Forbidden(
            "You can only edit your own pastes.".to_string(),
        ));
    }

    let new_title: String = field(&pairs, "title").trim().chars().take(MAX_TITLE_CHARS).collect();
    let new_language = normalize_language(field(&pairs, "language"));
    let files = collect_files_or_legacy(&pairs);

    if let Some(msg) = files_problem(&files) {
        let csrf = auth::new_csrf_token();
        let html = render_edit(&who, &paste.id, Some(msg), &new_title, &new_language, &files, &csrf);
        return Ok(html_with_csrf(StatusCode::BAD_REQUEST, html, &csrf));
    }

    let new_body = combined_body(&files);
    let current_files = load_file_inputs(&state, &paste).await;

    // Idempotent no-op: an edit that changes nothing (title, language, body AND file layout)
    // writes no revision and does not touch the row.
    if new_title == paste.title
        && new_body == paste.body
        && new_language == paste.language
        && files == current_files
    {
        return Ok(redirect_found(&format!("/p/{}", paste.id)));
    }

    // Snapshot the PRE-edit content as the next revision (append-only, idempotent on the number).
    let next = state.store.list_revisions(&id).await?.len() as i64 + 1;
    let rev = crate::model::PasteRevision {
        paste_id: paste.id.clone(),
        revision: next,
        title: paste.title.clone(),
        body: paste.body.clone(),
        language: paste.language.clone(),
        created_at: now,
    };
    state.store.add_revision(&rev).await?;
    state
        .store
        .update_paste(&id, &who.subject, &new_title, &new_body, &new_language)
        .await?;
    // Overwrite the per-file breakdown: multi-file -> replace rows; single-file -> clear rows so
    // the paste collapses back to its `pastes.body` representation.
    if files.len() >= 2 {
        let rows = build_file_rows(&paste.id, &files);
        state.store.set_files(&paste.id, &rows).await?;
    } else {
        state.store.set_files(&paste.id, &[]).await?;
    }

    tracing::info!(id = paste.id, author = who.subject, revision = next, "paste edited");
    let actor = if who.email.is_empty() { &who.subject } else { &who.email };
    state.audit.emit(AuditEvent::info(
        "paste.edit",
        actor,
        &paste.id,
        &format!("revision {next}"),
    ));

    Ok(redirect_found(&format!("/p/{}", paste.id)))
}

// ---------------------------------------------------------------------------
// POST /fork/{id} — copy a paste into a new one crediting the source
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ForkForm {
    #[serde(default)]
    pub csrf_token: String,
}

/// `POST /fork/{id}` — CSRF-checked. Copy a live paste's content (INCLUDING all of a multi-file
/// paste's named files) into a brand-new paste owned by the current user, crediting the source via
/// `source_id`. A password-protected source can only be forked by its owner (a non-owner must not
/// exfiltrate a protected body by forking it). The fork is a fresh, unprotected, non-burn,
/// never-expiring copy. Then 302 to `/p/{new_id}`.
pub async fn fork(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<ForkForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let now = now_secs();
    let source = load_live(&state, &id, now).await?;
    let is_owner = source.author_sub == who.subject;

    if source.password_hash.is_some() && !is_owner {
        return Err(AppError::Forbidden(
            "This paste is password-protected and cannot be forked.".to_string(),
        ));
    }

    let mut paste = Paste {
        id: String::new(),
        title: source.title.clone(),
        body: source.body.clone(),
        language: source.language.clone(),
        author_sub: who.subject.clone(),
        author_email: who.email.clone(),
        created_at: now,
        expires_at: None,
        burn_after_read: false,
        source_id: Some(source.id.clone()),
        password_hash: None,
    };

    let mut created = false;
    for _ in 0..6 {
        paste.id = random_alnum(PASTE_ID_LEN);
        if state.store.create(&paste).await? {
            created = true;
            break;
        }
    }
    if !created {
        return Err(AppError::Internal(
            "could not allocate a unique paste id".to_string(),
        ));
    }

    // Copy the source's per-file breakdown, if any (a multi-file paste forks all its files with
    // fresh ids under the new paste). A single-content source has no rows, so nothing to copy.
    let source_files = state.store.list_files(&source.id).await.unwrap_or_default();
    if !source_files.is_empty() {
        let rows: Vec<PasteFile> = source_files
            .iter()
            .enumerate()
            .map(|(i, f)| PasteFile {
                id: random_alnum(FILE_ID_LEN),
                paste_id: paste.id.clone(),
                filename: f.filename.clone(),
                content: f.content.clone(),
                position: i as i64,
            })
            .collect();
        state.store.set_files(&paste.id, &rows).await?;
    }

    tracing::info!(id = paste.id, source = source.id, author = who.subject, "paste forked");
    let actor = if who.email.is_empty() { &who.subject } else { &who.email };
    state
        .audit
        .emit(AuditEvent::info("paste.fork", actor, &paste.id, &source.id));

    Ok(redirect_found(&format!("/p/{}", paste.id)))
}

// ---------------------------------------------------------------------------
// GET /p/{id}/history + GET /p/{id}/rev/{revision} — revision history & viewing
// ---------------------------------------------------------------------------

/// Same access gate the raw/history/revision paths use: the owner always, and any viewer of an
/// unprotected paste. A non-owner of a protected paste is refused (they must use the main view,
/// which handles the password prompt) — so a protected body never leaks via a side route.
fn access_or_forbidden(paste: &Paste, viewer: &Identity) -> Result<(), AppError> {
    if paste.author_sub == viewer.subject || paste.password_hash.is_none() {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "This paste is password-protected — open it from its main page to unlock.".to_string(),
        ))
    }
}

/// `GET /p/{id}/history` — the paste's revision history, newest first, each linking to that
/// version. Access-gated like the paste itself.
pub async fn history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let viewer = auth::identity(&headers);
    let now = now_secs();
    let paste = load_live(&state, &id, now).await?;
    access_or_forbidden(&paste, &viewer)?;
    let revisions = state.store.list_revisions(&id).await?;
    let html = render_history(&viewer, &paste, &revisions);
    Ok((StatusCode::OK, Html(html)).into_response())
}

/// `GET /p/{id}/rev/{revision}` — a single historical version, read-only, with a banner marking it
/// as archived. Access-gated like the paste itself.
pub async fn view_revision(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, revision)): Path<(String, i64)>,
) -> Result<Response, AppError> {
    let viewer = auth::identity(&headers);
    let now = now_secs();
    let paste = load_live(&state, &id, now).await?;
    access_or_forbidden(&paste, &viewer)?;
    let rev = state
        .store
        .get_revision(&id, revision)
        .await?
        .ok_or_else(|| AppError::NotFound("No such revision of this paste.".to_string()))?;
    let html = render_revision(&viewer, &paste.id, &rev);
    Ok((StatusCode::OK, Html(html)).into_response())
}

// ---------------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------------

/// Validate the submitted files. Returns a user-facing message when they are unacceptable. The
/// empty-files message matches the legacy single-body wording so nothing downstream changes.
fn files_problem(files: &[FileInput]) -> Option<&'static str> {
    if files.is_empty() {
        return Some("Paste body cannot be empty.");
    }
    let total: usize = files.iter().map(|f| f.content.len()).sum();
    if total > MAX_BODY_BYTES {
        return Some("Paste is too large (256 KiB maximum across all files).");
    }
    None
}

// ---------------------------------------------------------------------------
// Form-body parsing (hand-rolled: a multi-file paste submits REPEATED `file_name` /
// `file_content` fields, which `serde_urlencoded` cannot map into a sequence).
// ---------------------------------------------------------------------------

/// Decode one `application/x-www-form-urlencoded` token (`+` -> space, `%XX` -> byte), lossily
/// to UTF-8 (identical semantics to a standard form decoder for our ASCII field names/values).
fn form_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                match (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                    (Some(h), Some(l)) => {
                        out.push((h << 4) | l);
                        i += 3;
                    }
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Hex digit -> nibble value (`None` for a non-hex byte).
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parse a urlencoded body into ordered, decoded `(key, value)` pairs. Order is preserved so the
/// repeated `file_name`/`file_content` fields keep their on-form row order.
fn parse_pairs(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter(|s| !s.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (form_decode(k), form_decode(v)),
            None => (form_decode(pair), String::new()),
        })
        .collect()
}

/// The first decoded value for `key` (empty string when absent) — the scalar-field accessor.
fn field<'a>(pairs: &'a [(String, String)], key: &str) -> &'a str {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
        .unwrap_or("")
}

/// Collect the repeated `file_name`/`file_content` rows (in form order) into [`FileInput`]s,
/// dropping any row whose content is blank and capping at [`MAX_FILES`]. A `file_name` is trimmed
/// and length-capped; it is matched to the `file_content` at the same 0-based row index.
fn collect_file_inputs(pairs: &[(String, String)]) -> Vec<FileInput> {
    let names: Vec<&str> = pairs
        .iter()
        .filter(|(k, _)| k == "file_name")
        .map(|(_, v)| v.as_str())
        .collect();
    pairs
        .iter()
        .filter(|(k, _)| k == "file_content")
        .enumerate()
        .filter(|(_, (_, c))| !c.trim().is_empty())
        .map(|(i, (_, c))| FileInput {
            filename: names
                .get(i)
                .copied()
                .unwrap_or("")
                .trim()
                .chars()
                .take(MAX_FILENAME_CHARS)
                .collect(),
            content: c.clone(),
        })
        .take(MAX_FILES)
        .collect()
}

/// The paste's files from the submitted form: the multi-file rows if present, else the legacy
/// single `body` field (so pre-existing clients/tests that post one `body` still work).
fn collect_files_or_legacy(pairs: &[(String, String)]) -> Vec<FileInput> {
    let files = collect_file_inputs(pairs);
    if !files.is_empty() {
        return files;
    }
    let legacy = field(pairs, "body");
    if legacy.trim().is_empty() {
        Vec::new()
    } else {
        vec![FileInput {
            filename: String::new(),
            content: legacy.to_string(),
        }]
    }
}

/// The content stored in `pastes.body`. A single file is stored verbatim (byte-identical to the
/// legacy single-content path); a multi-file paste stores a readable, `filename`-delimited
/// concatenation so `/raw` and the similarity index stay useful.
fn combined_body(files: &[FileInput]) -> String {
    if files.len() == 1 {
        return files[0].content.clone();
    }
    files
        .iter()
        .enumerate()
        .map(|(i, f)| format!("===== {} =====\n{}", display_filename(&f.filename, i), f.content))
        .collect::<Vec<_>>()
        .join("\n\n")
}

/// Assign fresh ids + ascending positions to the submitted files for persistence.
fn build_file_rows(paste_id: &str, files: &[FileInput]) -> Vec<PasteFile> {
    files
        .iter()
        .enumerate()
        .map(|(i, f)| PasteFile {
            id: random_alnum(FILE_ID_LEN),
            paste_id: paste_id.to_string(),
            filename: f.filename.clone(),
            content: f.content.clone(),
            position: i as i64,
        })
        .collect()
}

/// The current files of a paste as [`FileInput`]s: the persisted `paste_files` rows, or — for a
/// legacy/single-content paste with no rows — one synthesized file from `pastes.body`. This is the
/// lazy read-side migration: pre-existing pastes present as exactly one file with no DB write.
async fn load_file_inputs(state: &AppState, paste: &Paste) -> Vec<FileInput> {
    let files = state.store.list_files(&paste.id).await.unwrap_or_default();
    if files.is_empty() {
        return vec![FileInput {
            filename: String::new(),
            content: paste.body.clone(),
        }];
    }
    files
        .into_iter()
        .map(|f| FileInput {
            filename: f.filename,
            content: f.content,
        })
        .collect()
}

/// Clamp a submitted language token to the trusted allow-list (default `plaintext`).
fn normalize_language(token: &str) -> String {
    let t = token.trim();
    if LANGUAGES.iter().any(|(v, _)| *v == t) {
        t.to_string()
    } else {
        "plaintext".to_string()
    }
}

/// Wrap rendered HTML in a 200/4xx response that also (re)sets the CSRF cookie.
fn html_with_csrf(status: StatusCode, html: String, csrf: &str) -> Response {
    (
        status,
        [(header::SET_COOKIE, auth::csrf_cookie(csrf))],
        Html(html),
    )
        .into_response()
}

/// A `302 Found` redirect to `location` (the spec'd create/delete response code).
fn redirect_found(location: &str) -> Response {
    (
        StatusCode::FOUND,
        [(header::LOCATION, location.to_string())],
    )
        .into_response()
}

/// Parse a `?before=<created_at>_<id>` keyset cursor. Ids are alphanumeric (never contain `_`),
/// so the split is on the LAST `_`. A malformed cursor yields `None` — the handler then serves
/// the newest page, so a bad/hand-edited cursor degrades gracefully instead of erroring.
fn parse_before(raw: &str) -> Option<(i64, String)> {
    let (ts, id) = raw.rsplit_once('_')?;
    let ts: i64 = ts.parse().ok()?;
    if id.is_empty() {
        return None;
    }
    Some((ts, id.to_string()))
}

/// Parse a `?lines=<start>[-<end>]` line-range (1-based, inclusive) into a normalized
/// `(start, end)` with `start <= end`. Accepts an optional `L` prefix on either bound (so a
/// `#L10-L20` hash pasted into the query still parses). A malformed or zero range yields `None`,
/// so a bad value simply renders the paste with no highlight instead of erroring.
fn parse_lines(raw: &str) -> Option<(usize, usize)> {
    let s = raw.trim().trim_start_matches('L');
    let (a, b) = match s.split_once('-') {
        Some((x, y)) => (x, y.trim_start_matches('L')),
        None => (s, s),
    };
    let a: usize = a.trim().parse().ok()?;
    let b: usize = b.trim().parse().ok()?;
    if a == 0 || b == 0 {
        return None;
    }
    Some(if a <= b { (a, b) } else { (b, a) })
}

/// The "Load older" control, rendered ONLY when a FULL page came back (so an older page may
/// exist). The link carries the next backward cursor `?before=<created_at>_<id>` computed from
/// the last (oldest) row of this page; an explicit `?limit=` is preserved so paging stays at the
/// user's chosen page size.
fn render_load_older(recent: &[Paste], limit: i64, limit_param: Option<i64>) -> String {
    // A short page means the end of the list — no older page to link to.
    if (recent.len() as i64) < limit {
        return String::new();
    }
    let Some(last) = recent.last() else {
        return String::new();
    };
    let mut href = format!("/?before={}_{}", last.created_at, last.id);
    if let Some(n) = limit_param {
        href.push_str(&format!("&limit={n}"));
    }
    format!(
        "<div class=\"paste-more\">\
           <a class=\"btn btn-ghost btn-sm\" href=\"{href}\" rel=\"next\">Load older</a>\
         </div>",
        href = esc(&href),
    )
}

#[allow(clippy::too_many_arguments)]
fn render_new(
    who: &Identity,
    csrf: &str,
    recent: &[Paste],
    load_older: &str,
    error: Option<&str>,
    title: &str,
    language: &str,
    expiry: &str,
    burn: bool,
    files: &[FileInput],
) -> String {
    let error_block = match error {
        Some(msg) => format!(
            "<div class=\"alert alert-danger\" role=\"alert\">{}</div>",
            esc(msg)
        ),
        None => String::new(),
    };
    let burn_checked = if burn { " checked" } else { "" };
    NEW_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("New paste", Some(&who.email)))
        .replace("{{ERROR}}", &error_block)
        .replace("{{TITLE}}", &esc(title))
        .replace("{{LANGUAGE_OPTIONS}}", &language_options(language))
        .replace("{{EXPIRY_OPTIONS}}", &expiry_options(expiry))
        .replace("{{BURN_CHECKED}}", burn_checked)
        .replace("{{FILE_ROWS}}", &render_file_rows(files))
        .replace("{{CSRF}}", &esc(csrf))
        .replace("{{RECENT}}", &render_recent(recent))
        .replace("{{LOAD_OLDER}}", load_older)
}

/// Render the compose/edit file rows (one `<div class="file-row">` per file), always emitting at
/// least one row so a fresh form starts with a single empty file. Every user string is escaped.
fn render_file_rows(files: &[FileInput]) -> String {
    if files.is_empty() {
        return render_file_row("", "");
    }
    files
        .iter()
        .map(|f| render_file_row(&f.filename, &f.content))
        .collect::<Vec<_>>()
        .join("")
}

/// A single compose/edit file row: a filename input + a content textarea (matching the static
/// `<template>` the add-file JS clones), with both values HTML-escaped.
fn render_file_row(filename: &str, content: &str) -> String {
    format!(
        "<div class=\"file-row\" data-file-row>\
           <div class=\"file-row__head\">\
             <div class=\"field field--grow\">\
               <label>Filename <span class=\"field-hint\">optional</span></label>\
               <input type=\"text\" name=\"file_name\" maxlength=\"128\" value=\"{name}\" placeholder=\"e.g. main.rs\">\
             </div>\
             <button class=\"btn btn-ghost btn-sm\" type=\"button\" data-file-remove>Remove</button>\
           </div>\
           <textarea name=\"file_content\" class=\"code-input\" spellcheck=\"false\" autocomplete=\"off\" placeholder=\"Paste this file's content here…\">{content}</textarea>\
         </div>",
        name = esc(filename),
        content = esc(content),
    )
}

/// The author's recent-pastes list (already filtered/ordered by the store).
fn render_recent(recent: &[Paste]) -> String {
    if recent.is_empty() {
        return "<li class=\"paste-item paste-item--empty\">You have no active pastes yet.</li>"
            .to_string();
    }
    recent
        .iter()
        .map(|p| {
            let title = if p.title.trim().is_empty() {
                "Untitled paste".to_string()
            } else {
                p.title.clone()
            };
            let expiry = match p.expires_at {
                Some(exp) => format!("expires {}", fmt_ts(exp)),
                None => "never expires".to_string(),
            };
            format!(
                "<li class=\"paste-item\">\
                   <a class=\"paste-item__title\" href=\"/p/{id}\">{title}</a>\
                   <span class=\"paste-item__meta\">\
                     <span class=\"lang-badge\">{lang}</span>\
                     <span>{created}</span>\
                     <span>{expiry}</span>\
                   </span>\
                 </li>",
                id = esc(&p.id),
                title = esc(&title),
                lang = esc(&language_label(&p.language)),
                created = esc(&fmt_ts(p.created_at)),
                expiry = esc(&expiry),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

/// Optional-password -> stored hash. Blank (all-whitespace) password => `None` (no protection).
fn password_hash(raw: &str) -> Option<String> {
    if raw.trim().is_empty() {
        None
    } else {
        Some(auth::hash_password(raw))
    }
}

/// A paste title, or the "Untitled paste" placeholder when blank.
fn title_or_untitled(title: &str) -> String {
    if title.trim().is_empty() {
        "Untitled paste".to_string()
    } else {
        title.to_string()
    }
}

/// The inline error alert (or empty string when there is no error).
fn error_block(error: Option<&str>) -> String {
    match error {
        Some(msg) => format!(
            "<div class=\"alert alert-danger\" role=\"alert\">{}</div>",
            esc(msg)
        ),
        None => String::new(),
    }
}

/// Gather the similar panel + revision count, then render the full paste view. Shared by the
/// direct view (`GET /p/{id}`) and the post-unlock reveal (`POST /unlock/{id}`).
async fn render_paste_view(
    state: &AppState,
    paste: &Paste,
    viewer: &Identity,
    is_owner: bool,
    csrf: &str,
    highlight_lines: Option<(usize, usize)>,
    now: i64,
) -> String {
    let similar = similar_pastes(state, paste, now).await;
    let revision_count = state
        .store
        .list_revisions(&paste.id)
        .await
        .unwrap_or_default()
        .len();
    // Multi-file pastes render each file as its own titled, line-numbered block; a
    // legacy/single-content paste (no `paste_files` rows) renders one unlabeled block exactly
    // as before, and the `?lines=` line-range highlight still applies to it.
    let files = state.store.list_files(&paste.id).await.unwrap_or_default();
    let body_html = render_body_html(paste, &files, highlight_lines);
    let burned = paste.burn_after_read && !is_owner;
    render_view_html(
        paste,
        viewer,
        is_owner,
        burned,
        &similar,
        csrf,
        &body_html,
        revision_count,
    )
}

/// Render a paste's code area: one titled block per file for a multi-file paste, or a single
/// unlabeled `code-pre code-lines` block for a legacy/single-content paste (byte-identical to the
/// old view — the `?lines=` highlight only applies in the single-file case).
fn render_body_html(
    paste: &Paste,
    files: &[PasteFile],
    highlight_lines: Option<(usize, usize)>,
) -> String {
    if files.is_empty() {
        return format!(
            "<div class=\"code-pre code-lines\">{}</div>",
            highlight::render_lines(&paste.language, &paste.body, highlight_lines)
        );
    }
    let count = files.len();
    files
        .iter()
        .enumerate()
        .map(|(i, f)| {
            format!(
                "<div class=\"file-block\">\
                   <div class=\"file-block__head\">{icon}<span>{name}</span>\
                     <span class=\"file-block__count\">{n} of {count}</span></div>\
                   <div class=\"code-pre code-lines\">{lines}</div>\
                 </div>",
                icon = FILE_ICON_SVG,
                name = esc(&display_filename(&f.filename, i)),
                n = i + 1,
                count = count,
                lines = highlight::render_lines(&paste.language, &f.content, None),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

/// A file's display name, or the `File {n}` placeholder when it has no name.
fn display_filename(filename: &str, index: usize) -> String {
    if filename.trim().is_empty() {
        format!("File {}", index + 1)
    } else {
        filename.to_string()
    }
}

/// The per-paste action buttons (`{{TOOLS}}`). Raw/history/fork honor the password gate; edit and
/// delete are owner-only. Each POST control carries the double-submit CSRF token.
fn view_tools(paste: &Paste, is_owner: bool, csrf: &str, revision_count: usize) -> String {
    let id = esc(&paste.id);
    let accessible = is_owner || paste.password_hash.is_none();
    let mut out = String::new();
    if accessible {
        out.push_str(&format!(
            "<a class=\"btn btn-ghost btn-sm\" href=\"/raw/{id}\">View raw</a>"
        ));
    }
    if revision_count > 0 && accessible {
        out.push_str(&format!(
            "<a class=\"btn btn-ghost btn-sm\" href=\"/p/{id}/history\">History</a>"
        ));
    }
    if accessible {
        out.push_str(&format!(
            "<form class=\"inline-form\" method=\"post\" action=\"/fork/{id}\">\
               <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
               <button class=\"btn btn-ghost btn-sm\" type=\"submit\">Fork</button>\
             </form>",
            csrf = esc(csrf),
        ));
    }
    if is_owner {
        out.push_str(&format!(
            "<a class=\"btn btn-secondary btn-sm\" href=\"/edit/{id}\">Edit</a>"
        ));
        out.push_str(&format!(
            "<form class=\"delete-form\" method=\"post\" action=\"/delete/{id}\" \
               onsubmit=\"return confirm('Delete this paste? This cannot be undone.');\">\
               <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
               <button class=\"btn btn-danger btn-sm\" type=\"submit\">Delete</button>\
             </form>",
            csrf = esc(csrf),
        ));
    }
    out
}

/// The "Forked from …" credit line (`{{SOURCE}}`), or empty for an original paste.
fn source_credit(paste: &Paste) -> String {
    match &paste.source_id {
        Some(src) => format!(
            "<p class=\"sub sub--credit\">Forked from <a href=\"/p/{id}\">{id}</a></p>",
            id = esc(src),
        ),
        None => String::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn render_view_html(
    paste: &Paste,
    viewer: &Identity,
    is_owner: bool,
    burned: bool,
    similar: &[(f64, Paste)],
    csrf: &str,
    body_html: &str,
    revision_count: usize,
) -> String {
    let expiry = match paste.expires_at {
        Some(exp) => format!("Expires {}", fmt_ts(exp)),
        None => "Never expires".to_string(),
    };
    let burn_meta = if paste.burn_after_read {
        " · Burn after read"
    } else {
        ""
    };
    let lock_meta = if paste.password_hash.is_some() {
        " · Password-protected"
    } else {
        ""
    };
    let meta = format!(
        "Created {created} by {author} · {expiry}{burn}{lock}",
        created = esc(&fmt_ts(paste.created_at)),
        author = esc(&paste.author_email),
        expiry = esc(&expiry),
        burn = burn_meta,
        lock = lock_meta,
    );

    // A one-time notice shown to the recipient whose read just consumed a burn paste.
    let burn_notice = if burned {
        "<div class=\"alert alert-warn\" role=\"alert\">This was a burn-after-read paste. \
         It has now been deleted and this link will no longer work.</div>"
            .to_string()
    } else if paste.burn_after_read {
        "<div class=\"alert alert-warn\" role=\"alert\">Burn after read — this paste will be \
         deleted the first time someone other than you opens it.</div>"
            .to_string()
    } else {
        String::new()
    };

    let tools = view_tools(paste, is_owner, csrf, revision_count);
    // `body_html` is pre-rendered by [`render_body_html`] (every character already HTML-escaped
    // by `highlight::render_lines`), so this is never less safe than a plain `esc(body)`.
    fill_view(
        &viewer.email,
        &title_or_untitled(&paste.title),
        &language_label(&paste.language),
        &meta,
        &burn_notice,
        &source_credit(paste),
        &paste.id,
        &tools,
        body_html,
        &render_similar(similar),
    )
}

/// Fill `view.html` from already-prepared (escaped where user-controlled) fragments. Shared by the
/// live view and the read-only revision view.
#[allow(clippy::too_many_arguments)]
fn fill_view(
    viewer_email: &str,
    title: &str,
    lang_label: &str,
    meta: &str,
    banner: &str,
    source: &str,
    id: &str,
    tools: &str,
    body_html: &str,
    similar: &str,
) -> String {
    VIEW_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("View paste", Some(viewer_email)))
        .replace("{{TITLE}}", &esc(title))
        .replace("{{LANG_LABEL}}", &esc(lang_label))
        .replace("{{META}}", meta)
        .replace("{{BURN_NOTICE}}", banner)
        .replace("{{SOURCE}}", source)
        .replace("{{ID}}", &esc(id))
        .replace("{{TOOLS}}", tools)
        .replace("{{BODY}}", body_html)
        .replace("{{SIMILAR}}", similar)
}

/// Render a single archived revision, read-only, with a banner and minimal tools.
fn render_revision(viewer: &Identity, paste_id: &str, rev: &PasteRevision) -> String {
    let meta = format!(
        "Revision {n} · archived {ts}",
        n = rev.revision,
        ts = esc(&fmt_ts(rev.created_at)),
    );
    let banner = format!(
        "<div class=\"alert alert-warn\" role=\"alert\">You are viewing revision {n}, an archived \
         version of this paste. <a href=\"/p/{id}\">View the current version</a>.</div>",
        n = rev.revision,
        id = esc(paste_id),
    );
    let tools = format!(
        "<a class=\"btn btn-ghost btn-sm\" href=\"/p/{id}\">Current version</a>\
         <a class=\"btn btn-ghost btn-sm\" href=\"/p/{id}/history\">History</a>",
        id = esc(paste_id),
    );
    let body_html = format!(
        "<div class=\"code-pre code-lines\">{}</div>",
        highlight::render_lines(&rev.language, &rev.body, None)
    );
    fill_view(
        &viewer.email,
        &title_or_untitled(&rev.title),
        &language_label(&rev.language),
        &meta,
        &banner,
        "",
        paste_id,
        &tools,
        &body_html,
        "",
    )
}

/// Render the password-prompt page for a protected paste (non-owner view). CSRF token echoed into
/// the unlock form.
fn render_unlock(viewer: &Identity, id: &str, csrf: &str, error: Option<&str>) -> String {
    UNLOCK_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("Locked paste", Some(&viewer.email)))
        .replace("{{ERROR}}", &error_block(error))
        .replace("{{ID}}", &esc(id))
        .replace("{{CSRF}}", &esc(csrf))
}

/// Render the edit form pre-filled with the current (or resubmitted) files.
#[allow(clippy::too_many_arguments)]
fn render_edit(
    who: &Identity,
    id: &str,
    error: Option<&str>,
    title: &str,
    language: &str,
    files: &[FileInput],
    csrf: &str,
) -> String {
    EDIT_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("Edit paste", Some(&who.email)))
        .replace("{{ID}}", &esc(id))
        .replace("{{ERROR}}", &error_block(error))
        .replace("{{CSRF}}", &esc(csrf))
        .replace("{{TITLE}}", &esc(title))
        .replace("{{LANGUAGE_OPTIONS}}", &language_options(language))
        .replace("{{FILE_ROWS}}", &render_file_rows(files))
}

/// Render the revision-history page: the current version plus every archived revision, newest
/// first, each linking to that version.
fn render_history(viewer: &Identity, paste: &Paste, revisions: &[PasteRevision]) -> String {
    HISTORY_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("Paste history", Some(&viewer.email)))
        .replace("{{ID}}", &esc(&paste.id))
        .replace("{{TITLE}}", &esc(&title_or_untitled(&paste.title)))
        .replace("{{REVISIONS}}", &render_history_items(paste, revisions))
}

/// The `<li>` items for the history list: the current version at the top, then revisions newest
/// first (or an "unedited" note when there are none).
fn render_history_items(paste: &Paste, revisions: &[PasteRevision]) -> String {
    let id = esc(&paste.id);
    let mut out = format!(
        "<li class=\"paste-item\">\
           <a class=\"paste-item__title\" href=\"/p/{id}\">Current version</a>\
           <span class=\"paste-item__meta\">\
             <span class=\"lang-badge\">{lang}</span>\
             <span>created {created}</span>\
           </span>\
         </li>",
        lang = esc(&language_label(&paste.language)),
        created = esc(&fmt_ts(paste.created_at)),
    );
    if revisions.is_empty() {
        out.push_str(
            "<li class=\"paste-item paste-item--empty\">No earlier versions — this paste has not \
             been edited.</li>",
        );
        return out;
    }
    for rev in revisions.iter().rev() {
        out.push_str(&format!(
            "<li class=\"paste-item\">\
               <a class=\"paste-item__title\" href=\"/p/{id}/rev/{n}\">Revision {n}</a>\
               <span class=\"paste-item__meta\">\
                 <span class=\"lang-badge\">{lang}</span>\
                 <span>archived {ts}</span>\
               </span>\
             </li>",
            n = rev.revision,
            lang = esc(&language_label(&rev.language)),
            ts = esc(&fmt_ts(rev.created_at)),
        ));
    }
    out
}

/// Render the "Similar pastes" panel, or an empty string when there are no scored matches (the
/// section is simply omitted so the view stays uncluttered for unique snippets).
fn render_similar(similar: &[(f64, Paste)]) -> String {
    if similar.is_empty() {
        return String::new();
    }
    let items = similar
        .iter()
        .map(|(score, p)| {
            let title = if p.title.trim().is_empty() {
                "Untitled paste".to_string()
            } else {
                p.title.clone()
            };
            // Score rendered as a 0–100% match for a human-readable signal.
            let pct = (score * 100.0).round() as i64;
            format!(
                "<li class=\"paste-item\">\
                   <a class=\"paste-item__title\" href=\"/p/{id}\">{title}</a>\
                   <span class=\"paste-item__meta\">\
                     <span class=\"lang-badge\">{lang}</span>\
                     <span>{pct}% match</span>\
                   </span>\
                 </li>",
                id = esc(&p.id),
                title = esc(&title),
                lang = esc(&language_label(&p.language)),
                pct = pct,
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        "<section class=\"card\">\
           <div class=\"card__head\"><h2>Similar pastes</h2></div>\
           <div class=\"card__body\"><ul class=\"paste-list\">{items}</ul></div>\
         </section>"
    )
}

#[cfg(test)]
mod tests {
    use super::parse_lines;

    #[test]
    fn parse_lines_single_and_range() {
        assert_eq!(parse_lines("10"), Some((10, 10)));
        assert_eq!(parse_lines("10-20"), Some((10, 20)));
    }

    #[test]
    fn parse_lines_normalizes_reversed_range() {
        assert_eq!(parse_lines("20-10"), Some((10, 20)));
    }

    #[test]
    fn parse_lines_tolerates_l_prefix() {
        assert_eq!(parse_lines("L10-L20"), Some((10, 20)));
    }

    #[test]
    fn parse_lines_rejects_bad_input() {
        assert_eq!(parse_lines("0"), None);
        assert_eq!(parse_lines("0-5"), None);
        assert_eq!(parse_lines("abc"), None);
        assert_eq!(parse_lines(""), None);
        assert_eq!(parse_lines("5-"), None);
    }
}
