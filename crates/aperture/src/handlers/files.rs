//! The drive surface: gallery, upload, detail/preview, raw stream, delete, and the public share
//! fetch.
//!
//! Mounted behind a Sluice `auth=sso` route except the `/s/{token}` share path, which the deploy
//! marks `auth=public`. The owner of every file is ALWAYS the gateway-injected `X-Auth-Subject`
//! (never a client field). The SSO routes enforce per-user ownership (a non-owner gets 403);
//! cross-user access happens only through the unguessable share token. State-changing POSTs carry
//! a double-submit CSRF token. Blob bytes are served as inline images only when magic-sniffed,
//! otherwise as `attachment` downloads (+ `nosniff`), so an uploaded file can never execute as
//! HTML in the drive's origin.

use axum::extract::{Multipart, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth::{self, Identity};
use crate::config::{clamp_page, Config};
use crate::error::AppError;
use crate::handlers::{
    esc, expiry_options, fmt_ts, human_size, parse_expiry, resolve_content_type, safe_filename,
    userbox, APP_CSS, FILE_SVG, SHIELD_SVG,
};
use crate::model::{FileRec, FolderRec};
use crate::{now_secs, random_alnum, AppState};

/// Length of the short random file id / object key (62-symbol alphabet, ~59 bits at 10 chars).
const FILE_ID_LEN: usize = 10;
/// Length of the short random folder id.
const FOLDER_ID_LEN: usize = 10;
/// Length of the unguessable public share token (~190 bits at 32 chars).
const SHARE_TOKEN_LEN: usize = 32;
/// Hard cap on a stored display file name (characters).
const MAX_NAME_CHARS: usize = 255;
/// Hard cap on a submitted share-link password (characters).
const MAX_PASSWORD_CHARS: usize = 128;

const GALLERY_HTML: &str = include_str!("../../templates/gallery.html");
const DETAIL_HTML: &str = include_str!("../../templates/detail.html");
const SHARE_PW_HTML: &str = include_str!("../../templates/share_password.html");

// ---------------------------------------------------------------------------
// GET / — the signed-in user's drive (gallery grid + upload dropzone)
// ---------------------------------------------------------------------------

/// Gallery query string: an optional keyset cursor (`?before=<created_at>_<id>`) to page back into
/// older files, and an optional `?limit=` page size (clamped to `[1, MAX_PAGE]`).
#[derive(Debug, Deserialize)]
pub struct GalleryQuery {
    #[serde(default)]
    pub before: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
    /// Optional folder filter. When it names one of the owner's folders the gallery shows only that
    /// folder's files; otherwise (unset / unknown) it falls back to the flat "all files" view.
    #[serde(default)]
    pub folder: Option<String>,
}

/// `GET /` — render the upload dropzone (with a fresh CSRF token) and one keyset page of the
/// owner's files, newest-first. With no `?before` cursor this is the newest page (the default
/// view, now capped at `DEFAULT_PAGE`); a `?before=<created_at>_<id>` cursor pages into older files.
pub async fn gallery(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<GalleryQuery>,
) -> Response {
    let who = auth::identity(&headers);
    let csrf = auth::new_csrf_token();
    let before = parse_cursor(q.before.as_deref());
    // Same clamp the store applies, so `files.len() == limit` below is an exact "page was full" test.
    let limit = clamp_page(q.limit.unwrap_or(0));

    let folders = state
        .store
        .list_folders(&who.subject)
        .await
        .unwrap_or_default();
    // The active folder must belong to the owner; an unknown/blank id falls back to all files.
    let active = q
        .folder
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|fid| folders.iter().find(|f| f.id == fid).cloned());
    let folder_filter = active.as_ref().map(|f| f.id.as_str());

    let files = state
        .store
        .list_by_owner(&who.subject, folder_filter, before, limit)
        .await
        .unwrap_or_default();

    // A FULL page means older rows may remain: the next cursor is the last (oldest) row shown.
    let next = if files.len() as i64 == limit {
        files.last().map(|f| (f.created_at, f.id.clone()))
    } else {
        None
    };

    let html = render_gallery(&who, &csrf, &files, next.as_ref(), &folders, active.as_ref());
    html_with_csrf(StatusCode::OK, html, &csrf)
}

/// Parse a `?before=<created_at>_<id>` keyset cursor. Ids are alphanumeric (never contain `_`) and
/// `created_at` is a plain integer, so the LAST `_` is the boundary. Any malformed value yields
/// `None`, so a bad cursor simply falls back to the newest page.
fn parse_cursor(raw: Option<&str>) -> Option<(i64, String)> {
    let (ts, id) = raw?.trim().rsplit_once('_')?;
    let ts: i64 = ts.parse().ok()?;
    if id.is_empty() {
        return None;
    }
    Some((ts, id.to_string()))
}

// ---------------------------------------------------------------------------
// POST /upload — multipart upload -> Cairn blob + metadata row
// ---------------------------------------------------------------------------

/// `POST /upload` — read the multipart form, store the bytes in the object store, persist the
/// metadata row, then 302 to `/f/{id}`. CSRF-checked; size-capped; content type magic-sniffed.
pub async fn upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);

    let mut csrf_field = String::new();
    let mut file: Option<(String, String, Vec<u8>)> = None; // (name, client_type, bytes)

    loop {
        let field = match multipart.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e) => {
                return Err(AppError::BadRequest(format!(
                    "Upload failed (it may exceed the size limit): {e}"
                )))
            }
        };
        match field.name().unwrap_or("") {
            "csrf_token" => {
                csrf_field = field
                    .text()
                    .await
                    .map_err(|e| AppError::BadRequest(e.to_string()))?;
            }
            "file" => {
                let name = field
                    .file_name()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| s.chars().take(MAX_NAME_CHARS).collect::<String>())
                    .unwrap_or_else(|| "file".to_string());
                let client_type = field.content_type().unwrap_or("").to_string();
                let data = field.bytes().await.map_err(|e| {
                    AppError::BadRequest(format!(
                        "Upload failed (it may exceed the size limit): {e}"
                    ))
                })?;
                file = Some((name, client_type, data.to_vec()));
            }
            _ => {
                let _ = field.bytes().await;
            }
        }
    }

    if !auth::verify_csrf(&headers, &csrf_field) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }

    let (name, client_type, bytes) = match file {
        Some(f) if !f.2.is_empty() => f,
        _ => return Err(AppError::BadRequest("Choose a file to upload.".to_string())),
    };
    if bytes.len() > state.config.max_upload {
        return Err(AppError::BadRequest(format!(
            "File is too large (maximum {}).",
            human_size(state.config.max_upload as i64)
        )));
    }

    let content_type = resolve_content_type(&bytes, &client_type);
    let size = bytes.len() as i64;
    let now = now_secs();

    let mut rec = FileRec {
        id: String::new(),
        owner_sub: who.subject.clone(),
        name,
        content_type,
        size,
        bucket: state.blobs.bucket().to_string(),
        object_key: String::new(),
        // A fresh upload is shareable immediately with no expiry and no password (the owner tunes
        // the share-link lifecycle afterwards on the detail page). Backward compatible.
        share_token: None,
        created_at: now,
        expires_at: None,
        share_password_hash: None,
        // A fresh upload is unfiled (appears in the flat all-files view); the owner files it later.
        folder_id: None,
    };

    // Reserve a unique row (id + share token) BEFORE writing the blob, retrying on the rare
    // unique collision. Cheap — no bytes have been uploaded yet.
    let mut reserved = false;
    for _ in 0..6 {
        rec.id = random_alnum(FILE_ID_LEN);
        rec.object_key = rec.id.clone();
        rec.share_token = Some(random_alnum(SHARE_TOKEN_LEN));
        if state.store.create(&rec).await? {
            reserved = true;
            break;
        }
    }
    if !reserved {
        return Err(AppError::Internal(
            "could not allocate a unique file id".to_string(),
        ));
    }

    // Write the bytes; roll the metadata row back if the object store rejects them, so we never
    // leave a row pointing at a missing blob.
    if let Err(e) = state.blobs.put(&rec.object_key, bytes).await {
        let _ = state.store.delete(&rec.id, &who.subject).await;
        return Err(e.into());
    }

    tracing::info!(id = rec.id, owner = who.subject, size, "file uploaded");
    state.audit.emit(AuditEvent::info(
        "file.upload",
        &who.subject,
        &rec.id,
        if rec.is_image() { "image" } else { "file" },
    ));
    Ok(redirect_found(&format!("/f/{}", rec.id)))
}

// ---------------------------------------------------------------------------
// GET /f/{id} — file detail / preview (owner-only)
// ---------------------------------------------------------------------------

/// `GET /f/{id}` — render the detail/preview page (inline image preview or a download prompt),
/// the metadata, the copyable share link and the delete control. Owner-only.
pub async fn detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let viewer = auth::identity(&headers);
    let rec = owned_file(&state, &id, &viewer).await?;
    let csrf = auth::new_csrf_token();
    let folders = state
        .store
        .list_folders(&viewer.subject)
        .await
        .unwrap_or_default();
    let html = render_detail(&state.config, &rec, &viewer, &csrf, &folders);
    Ok(html_with_csrf(StatusCode::OK, html, &csrf))
}

// ---------------------------------------------------------------------------
// GET /f/{id}/raw — stream the blob (owner-only)
// ---------------------------------------------------------------------------

/// `GET /f/{id}/raw` — stream the bytes from the object store. Inline for magic-sniffed images,
/// attachment otherwise. Owner-only.
pub async fn raw(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let viewer = auth::identity(&headers);
    let rec = owned_file(&state, &id, &viewer).await?;
    let bytes = state.blobs.get(&rec.object_key).await?;
    Ok(serve_blob(&rec, bytes))
}

// ---------------------------------------------------------------------------
// POST /delete/{id} — delete your own file (blob + row)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct DeleteForm {
    #[serde(default)]
    pub csrf_token: String,
}

/// `POST /delete/{id}` — CSRF-checked, ownership-scoped delete (metadata then best-effort blob),
/// then 302 to `/`.
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
    let rec = owned_file(&state, &id, &actor).await?;

    // Remove the metadata row first; a row pointing at a missing blob is worse than an orphan
    // blob, so the blob delete is best-effort afterwards.
    state.store.delete(&rec.id, &actor.subject).await?;
    if let Err(e) = state.blobs.delete(&rec.object_key).await {
        tracing::warn!(id = rec.id, error = %e, "metadata removed but blob delete failed (orphan)");
    }
    tracing::info!(id = rec.id, owner = actor.subject, "file deleted");
    state.audit.emit(AuditEvent::notice(
        "file.delete",
        &actor.subject,
        &rec.id,
        if rec.is_image() { "image" } else { "file" },
    ));
    Ok(redirect_found("/"))
}

// ---------------------------------------------------------------------------
// GET /s/{token} — public share fetch (NO SSO)
// ---------------------------------------------------------------------------

/// `GET /s/{token}` — fetch a shared file by its unguessable token, WITHOUT SSO. Deploy marks the
/// `/s/` prefix `auth=public`; this handler never consults identity or ownership. Honors the share
/// lifecycle: a revoked token is 404, an expired link is 410 Gone, and a password-protected link
/// renders a password prompt instead of the bytes. Inline for images, attachment otherwise.
pub async fn share(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Response, AppError> {
    let rec = load_shared(&state, &token).await?;
    // Password-protected: never serve the bytes on a bare GET — prompt for the password first.
    if rec.share_has_password() {
        return Ok(render_share_prompt(&token, StatusCode::OK, None));
    }
    serve_shared(&state, &rec).await
}

/// Submitted share-link password (the public unlock form). The route is unauthenticated and this
/// POST performs NO state change (it only reads a file after a password check), so it carries no
/// CSRF token — there is no ambient session authority to protect.
#[derive(Debug, Deserialize)]
pub struct SharePasswordForm {
    #[serde(default)]
    pub password: String,
}

/// `POST /s/{token}` — verify the submitted password for a protected share link and, on success,
/// serve the bytes. Wrong password re-renders the prompt (401). Same 404/410 lifecycle as the GET.
pub async fn share_unlock(
    State(state): State<AppState>,
    Path(token): Path<String>,
    Form(form): Form<SharePasswordForm>,
) -> Result<Response, AppError> {
    let rec = load_shared(&state, &token).await?;
    match &rec.share_password_hash {
        // Correct password (or the link is no longer protected) -> serve.
        Some(hash) if auth::verify_share_password(hash, &form.password) => {
            serve_shared(&state, &rec).await
        }
        None => serve_shared(&state, &rec).await,
        Some(_) => Ok(render_share_prompt(
            &token,
            StatusCode::UNAUTHORIZED,
            Some("Incorrect password."),
        )),
    }
}

// ---------------------------------------------------------------------------
// POST /f/{id}/share, POST /f/{id}/revoke — share-link lifecycle (owner-only)
// ---------------------------------------------------------------------------

/// Share-link configuration form: an expiry allow-list value + an optional password. CSRF-checked.
#[derive(Debug, Deserialize)]
pub struct ShareConfigForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub expiry: String,
    #[serde(default)]
    pub password: String,
}

/// `POST /f/{id}/share` — (re)enable / update the share link: set its expiry and optional password,
/// minting a fresh token when the link had been revoked. CSRF-checked, owner-scoped, then 302 to
/// `/f/{id}`. Submitting a blank password CLEARS any existing password.
pub async fn configure_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<ShareConfigForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let actor = auth::identity(&headers);
    let rec = owned_file(&state, &id, &actor).await?;

    let expires_at = parse_expiry(&form.expiry, now_secs());
    let password = form.password.trim();
    let password_hash = if password.is_empty() {
        None
    } else {
        let capped: String = password.chars().take(MAX_PASSWORD_CHARS).collect();
        Some(auth::hash_share_password(&capped))
    };
    // Reuse the live token when present; mint a fresh one when re-enabling after a revoke.
    let token = rec
        .share_token
        .clone()
        .unwrap_or_else(|| random_alnum(SHARE_TOKEN_LEN));

    state
        .store
        .configure_share(&id, &actor.subject, Some(token), expires_at, password_hash)
        .await?;
    tracing::info!(id = rec.id, owner = actor.subject, "share link configured");
    state.audit.emit(AuditEvent::notice(
        "file.share.update",
        &actor.subject,
        &rec.id,
        if rec.is_image() { "image" } else { "file" },
    ));
    Ok(redirect_found(&format!("/f/{}", rec.id)))
}

/// `POST /f/{id}/revoke` — revoke the share link: clear the token (and its expiry/password), so the
/// outstanding `/s/{token}` link stops working immediately. CSRF-checked, owner-scoped, then 302 to
/// `/f/{id}`.
pub async fn revoke_share(
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
    let rec = owned_file(&state, &id, &actor).await?;

    state
        .store
        .configure_share(&id, &actor.subject, None, None, None)
        .await?;
    tracing::info!(id = rec.id, owner = actor.subject, "share link revoked");
    state.audit.emit(AuditEvent::notice(
        "file.share.revoke",
        &actor.subject,
        &rec.id,
        if rec.is_image() { "image" } else { "file" },
    ));
    Ok(redirect_found(&format!("/f/{}", rec.id)))
}

// ---------------------------------------------------------------------------
// Folders (albums): create / rename / delete (owner-only), and move a file
// ---------------------------------------------------------------------------

/// New-folder form: a display name. CSRF-checked.
#[derive(Debug, Deserialize)]
pub struct FolderCreateForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub name: String,
}

/// Rename-folder form: the new display name. CSRF-checked.
#[derive(Debug, Deserialize)]
pub struct FolderRenameForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub name: String,
}

/// Move-file form: the target folder id (empty = move back to the root/unfiled view). CSRF-checked.
#[derive(Debug, Deserialize)]
pub struct MoveForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub folder_id: String,
}

/// `POST /folders` — create an owner-scoped folder from the submitted name, then 302 to that
/// folder's view. CSRF-checked; the name is trimmed, required, and length-capped.
pub async fn create_folder(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<FolderCreateForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let actor = auth::identity(&headers);
    let name = clean_folder_name(&form.name)?;

    let mut rec = FolderRec {
        id: String::new(),
        owner_sub: actor.subject.clone(),
        name,
        created_at: now_secs(),
    };
    // Reserve a unique folder id, retrying on the rare collision.
    let mut created = false;
    for _ in 0..6 {
        rec.id = random_alnum(FOLDER_ID_LEN);
        if state.store.create_folder(&rec).await? {
            created = true;
            break;
        }
    }
    if !created {
        return Err(AppError::Internal(
            "could not allocate a unique folder id".to_string(),
        ));
    }

    tracing::info!(id = rec.id, owner = actor.subject, "folder created");
    state
        .audit
        .emit(AuditEvent::notice("folder.create", &actor.subject, &rec.id, "folder"));
    Ok(redirect_found(&format!("/?folder={}", rec.id)))
}

/// `POST /folders/{id}/rename` — rename an owner's folder, then 302 back to its view. CSRF-checked,
/// owner-scoped (404 when the folder is absent or owned by someone else).
pub async fn rename_folder(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<FolderRenameForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let actor = auth::identity(&headers);
    let name = clean_folder_name(&form.name)?;
    if !state.store.rename_folder(&id, &actor.subject, &name).await? {
        return Err(AppError::NotFound("No such folder.".to_string()));
    }
    tracing::info!(id, owner = actor.subject, "folder renamed");
    state
        .audit
        .emit(AuditEvent::notice("folder.rename", &actor.subject, &id, "folder"));
    Ok(redirect_found(&format!("/?folder={id}")))
}

/// `POST /folders/{id}/delete` — delete an owner's folder (its files are UNFILED, never deleted),
/// then 302 to the flat drive. CSRF-checked, owner-scoped.
pub async fn delete_folder(
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
    if !state.store.delete_folder(&id, &actor.subject).await? {
        return Err(AppError::NotFound("No such folder.".to_string()));
    }
    tracing::info!(id, owner = actor.subject, "folder deleted");
    state
        .audit
        .emit(AuditEvent::notice("folder.delete", &actor.subject, &id, "folder"));
    Ok(redirect_found("/"))
}

/// `POST /f/{id}/move` — move an owned file into a folder (or back to the root when the target is
/// blank), then 302 to `/f/{id}`. CSRF-checked, owner-scoped; a non-blank target folder must belong
/// to the same owner (else 404), so a file can never reference a folder it does not own.
pub async fn move_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<MoveForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let actor = auth::identity(&headers);
    let rec = owned_file(&state, &id, &actor).await?;

    // Resolve the target: blank => root (unfile); otherwise it MUST be one of the owner's folders.
    let target = match form.folder_id.trim() {
        "" => None,
        fid => {
            if state.store.get_folder(fid, &actor.subject).await?.is_none() {
                return Err(AppError::NotFound("No such folder.".to_string()));
            }
            Some(fid.to_string())
        }
    };
    state
        .store
        .move_file(&rec.id, &actor.subject, target.as_deref())
        .await?;
    tracing::info!(id = rec.id, owner = actor.subject, folder = ?target, "file moved");
    state.audit.emit(AuditEvent::notice(
        "file.move",
        &actor.subject,
        &rec.id,
        if rec.is_image() { "image" } else { "file" },
    ));
    Ok(redirect_found(&format!("/f/{}", rec.id)))
}

/// Validate + normalize a submitted folder name: trimmed, required, and capped at [`MAX_NAME_CHARS`].
fn clean_folder_name(raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AppError::BadRequest("Enter a folder name.".to_string()));
    }
    Ok(trimmed.chars().take(MAX_NAME_CHARS).collect())
}

/// Load a file by share token for the PUBLIC path, enforcing the share lifecycle: a missing/revoked
/// token is 404, an expired link is 410 Gone.
async fn load_shared(state: &AppState, token: &str) -> Result<FileRec, AppError> {
    let rec = state.store.get_by_token(token).await?.ok_or_else(|| {
        AppError::NotFound("This share link is invalid or has been removed.".to_string())
    })?;
    if rec.share_expired(now_secs()) {
        return Err(AppError::Gone(
            "This share link has expired and is no longer available.".to_string(),
        ));
    }
    Ok(rec)
}

/// Fetch the blob for a (validated) shared file, emit the public-share audit event, and serve it.
async fn serve_shared(state: &AppState, rec: &FileRec) -> Result<Response, AppError> {
    let bytes = state.blobs.get(&rec.object_key).await?;
    // Public share fetch: no gateway identity on this route, so the affected file's owner is the
    // subject the event is attributed to.
    state.audit.emit(AuditEvent::info(
        "file.share",
        &rec.owner_sub,
        &rec.id,
        if rec.is_image() { "image" } else { "file" },
    ));
    Ok(serve_blob(rec, bytes))
}

/// Render the public share-link password prompt (`status` = 200 on first ask, 401 after a wrong
/// password). `error` is an optional inline message.
fn render_share_prompt(token: &str, status: StatusCode, error: Option<&str>) -> Response {
    let error_html = match error {
        Some(msg) => format!("<p class=\"form-error\">{}</p>", esc(msg)),
        None => String::new(),
    };
    let html = SHARE_PW_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{ERROR}}", &error_html)
        .replace("{{TOKEN}}", &esc(token));
    (status, Html(html)).into_response()
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Fetch a file by id and enforce per-user ownership: 404 when absent, 403 when owned by someone
/// else.
async fn owned_file(state: &AppState, id: &str, who: &Identity) -> Result<FileRec, AppError> {
    let rec = state
        .store
        .get(id)
        .await?
        .ok_or_else(|| AppError::NotFound("No file exists at that link.".to_string()))?;
    if rec.owner_sub != who.subject {
        return Err(AppError::Forbidden(
            "You can only access your own files.".to_string(),
        ));
    }
    Ok(rec)
}

/// Serve raw blob bytes: inline for sniffed images, attachment otherwise; always `nosniff`.
fn serve_blob(rec: &FileRec, bytes: Vec<u8>) -> Response {
    let filename = safe_filename(&rec.name);
    let (ctype, disposition) = if rec.is_image() {
        (rec.content_type.clone(), format!("inline; filename=\"{filename}\""))
    } else {
        (
            "application/octet-stream".to_string(),
            format!("attachment; filename=\"{filename}\""),
        )
    };
    (
        [
            (header::CONTENT_TYPE, ctype),
            (header::CONTENT_DISPOSITION, disposition),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
        ],
        bytes,
    )
        .into_response()
}

/// Wrap rendered HTML in a response that also (re)sets the CSRF cookie.
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
    (StatusCode::FOUND, [(header::LOCATION, location.to_string())]).into_response()
}

/// Uppercase file extension label for the non-image card/preview glyph (e.g. `PDF`, `ZIP`).
fn ext_label(name: &str) -> String {
    name.rsplit_once('.')
        .map(|(_, ext)| ext)
        .filter(|ext| !ext.is_empty() && ext.len() <= 6 && ext.chars().all(|c| c.is_alphanumeric()))
        .map(|ext| ext.to_ascii_uppercase())
        .unwrap_or_else(|| "FILE".to_string())
}

fn render_gallery(
    who: &Identity,
    csrf: &str,
    files: &[FileRec],
    next: Option<&(i64, String)>,
    folders: &[FolderRec],
    active: Option<&FolderRec>,
) -> String {
    let count = match files.len() {
        0 => "No files yet".to_string(),
        1 => "1 file".to_string(),
        n => format!("{n} files"),
    };
    // The content heading names the active folder, or "All files" for the flat view.
    let heading = match active {
        Some(f) => f.name.clone(),
        None => "All files".to_string(),
    };
    // Preserve the active folder across the "Load older" pager (ids are alphanumeric => URL-safe).
    let folder_qs = active
        .map(|f| format!("&folder={}", f.id))
        .unwrap_or_default();
    // A "Load older" link only when a full page came back (there may be older files to page into).
    let pager = match next {
        Some((ts, id)) => format!(
            "<nav class=\"gallery-pager\"><a class=\"btn btn-ghost\" href=\"/?before={ts}_{id}{folder_qs}\">Load older</a></nav>",
            ts = ts,
            id = esc(id),
            folder_qs = folder_qs,
        ),
        None => String::new(),
    };
    GALLERY_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("Drive", Some(&who.email)))
        .replace("{{CSRF}}", &esc(csrf))
        .replace("{{SIDEBAR}}", &render_sidebar(csrf, folders, active))
        .replace("{{HEADING}}", &esc(&heading))
        .replace("{{COUNT}}", &esc(&count))
        .replace("{{CARDS}}", &render_cards(files))
        .replace("{{PAGER}}", &pager)
}

/// Render the folder sidebar/switcher: an "All files" entry, one link per folder (the active one
/// highlighted), a "New folder" form, and — when a folder is active — its rename + delete controls.
/// Every form is CSRF-protected and owner-scoped.
fn render_sidebar(csrf: &str, folders: &[FolderRec], active: Option<&FolderRec>) -> String {
    let all_sel = if active.is_none() {
        " folder-item--active"
    } else {
        ""
    };
    let mut items = format!(
        "<li><a class=\"folder-item{all_sel}\" href=\"/\">All files</a></li>",
        all_sel = all_sel,
    );
    for f in folders {
        let sel = if active.map(|a| a.id.as_str()) == Some(f.id.as_str()) {
            " folder-item--active"
        } else {
            ""
        };
        items.push_str(&format!(
            "<li><a class=\"folder-item{sel}\" href=\"/?folder={id}\">{name}</a></li>",
            sel = sel,
            id = esc(&f.id),
            name = esc(&f.name),
        ));
    }

    // Rename + delete controls, shown only when viewing a specific folder.
    let manage = match active {
        Some(f) => format!(
            "<form class=\"folder-form\" method=\"post\" action=\"/folders/{id}/rename\">\
               <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
               <label for=\"renameFolder\">Rename folder</label>\
               <div class=\"share-row\">\
                 <input id=\"renameFolder\" type=\"text\" name=\"name\" value=\"{name}\" maxlength=\"255\" required>\
                 <button class=\"btn btn-secondary btn-sm\" type=\"submit\">Save</button>\
               </div>\
             </form>\
             <form class=\"folder-form\" method=\"post\" action=\"/folders/{id}/delete\" \
               onsubmit=\"return confirm('Delete this folder? Its files are kept and moved back to All files.');\">\
               <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
               <button class=\"btn btn-danger btn-sm\" type=\"submit\">Delete folder</button>\
             </form>",
            id = esc(&f.id),
            csrf = esc(csrf),
            name = esc(&f.name),
        ),
        None => String::new(),
    };

    format!(
        "<aside class=\"folder-rail\">\
           <div class=\"section-head\"><h2>Folders</h2></div>\
           <ul class=\"folder-list\">{items}</ul>\
           <form class=\"folder-form\" method=\"post\" action=\"/folders\">\
             <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
             <label for=\"newFolder\">New folder</label>\
             <div class=\"share-row\">\
               <input id=\"newFolder\" type=\"text\" name=\"name\" placeholder=\"Folder name\" maxlength=\"255\" required>\
               <button class=\"btn btn-secondary btn-sm\" type=\"submit\">Create</button>\
             </div>\
           </form>\
           {manage}\
         </aside>",
        items = items,
        csrf = esc(csrf),
        manage = manage,
    )
}

fn render_cards(files: &[FileRec]) -> String {
    if files.is_empty() {
        return "<li class=\"file-card file-card--empty\">Your drive is empty. Drop a file above to get started.</li>"
            .to_string();
    }
    files
        .iter()
        .map(|f| {
            let thumb = if f.is_image() {
                format!(
                    "<span class=\"thumb\"><img src=\"/f/{id}/raw\" alt=\"{alt}\" loading=\"lazy\"></span>",
                    id = esc(&f.id),
                    alt = esc(&f.name),
                )
            } else {
                format!(
                    "<span class=\"thumb thumb--file\">{glyph}<span class=\"thumb__ext\">{ext}</span></span>",
                    glyph = FILE_SVG,
                    ext = esc(&ext_label(&f.name)),
                )
            };
            format!(
                "<li class=\"file-card\">\
                   <a class=\"file-card__link\" href=\"/f/{id}\">{thumb}</a>\
                   <div class=\"file-card__body\">\
                     <a class=\"file-card__name\" href=\"/f/{id}\" title=\"{name}\">{name}</a>\
                     <div class=\"file-card__meta\"><span>{size}</span><span>{date}</span></div>\
                   </div>\
                 </li>",
                id = esc(&f.id),
                name = esc(&f.name),
                size = esc(&human_size(f.size)),
                date = esc(&fmt_ts(f.created_at)),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn render_detail(
    config: &Config,
    rec: &FileRec,
    viewer: &Identity,
    csrf: &str,
    folders: &[FolderRec],
) -> String {
    let preview = if rec.is_image() {
        format!(
            "<img class=\"preview-img\" src=\"/f/{id}/raw\" alt=\"{alt}\">",
            id = esc(&rec.id),
            alt = esc(&rec.name),
        )
    } else {
        format!(
            "<div class=\"preview-file\">{glyph}<span class=\"thumb__ext\">{ext}</span>\
               <p class=\"muted\">No inline preview for this file type.</p></div>",
            glyph = FILE_SVG,
            ext = esc(&ext_label(&rec.name)),
        )
    };

    let meta_list = format!(
        "<dl class=\"meta-list\">\
           <div><dt>Type</dt><dd>{ctype}</dd></div>\
           <div><dt>Size</dt><dd>{size}</dd></div>\
           <div><dt>Uploaded</dt><dd>{date}</dd></div>\
           <div><dt>Storage</dt><dd>{bucket}</dd></div>\
         </dl>",
        ctype = esc(&rec.content_type),
        size = esc(&human_size(rec.size)),
        date = esc(&fmt_ts(rec.created_at)),
        bucket = esc(&rec.bucket),
    );

    let share = render_share_section(config, rec, csrf);
    let move_section = render_move_section(rec, csrf, folders);

    let sub = format!(
        "{ctype} · {size} · {date}",
        ctype = rec.content_type,
        size = human_size(rec.size),
        date = fmt_ts(rec.created_at),
    );

    let delete = format!(
        "<form class=\"delete-form\" method=\"post\" action=\"/delete/{id}\" \
           onsubmit=\"return confirm('Delete this file? This cannot be undone.');\">\
           <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
           <button class=\"btn btn-danger\" type=\"submit\">Delete</button>\
         </form>",
        id = esc(&rec.id),
        csrf = esc(csrf),
    );

    DETAIL_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("Drive", Some(&viewer.email)))
        .replace("{{NAME}}", &esc(&rec.name))
        .replace("{{SUB}}", &esc(&sub))
        .replace("{{PREVIEW}}", &preview)
        .replace("{{META_LIST}}", &meta_list)
        .replace("{{MOVE}}", &move_section)
        .replace("{{SHARE}}", &share)
        .replace("{{ID}}", &esc(&rec.id))
        .replace("{{DELETE}}", &delete)
}

/// Build the "Move to folder" control for the detail page: a `<select>` of the owner's folders
/// (plus a "No folder" root option), pre-selecting the file's current folder. CSRF-protected,
/// owner-scoped on submit.
fn render_move_section(rec: &FileRec, csrf: &str, folders: &[FolderRec]) -> String {
    let root_sel = if rec.folder_id.is_none() {
        " selected"
    } else {
        ""
    };
    let mut options = format!(
        "<option value=\"\"{root_sel}>No folder (All files)</option>",
        root_sel = root_sel,
    );
    for f in folders {
        let sel = if rec.folder_id.as_deref() == Some(f.id.as_str()) {
            " selected"
        } else {
            ""
        };
        options.push_str(&format!(
            "<option value=\"{id}\"{sel}>{name}</option>",
            id = esc(&f.id),
            sel = sel,
            name = esc(&f.name),
        ));
    }
    format!(
        "<form class=\"share-form\" method=\"post\" action=\"/f/{id}/move\">\
           <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
           <div class=\"field\">\
             <label for=\"folderSelect\">Folder</label>\
             <div class=\"share-row\">\
               <select id=\"folderSelect\" name=\"folder_id\">{options}</select>\
               <button class=\"btn btn-secondary btn-sm\" type=\"submit\">Move</button>\
             </div>\
           </div>\
         </form>",
        id = esc(&rec.id),
        csrf = esc(csrf),
        options = options,
    )
}

/// Build the share-link lifecycle section for the detail page. An active link shows its URL with a
/// copy control, the expiry and password state, an update form, and a revoke button. A revoked link
/// shows a "create share link" form instead. Every form is CSRF-protected and owner-scoped.
fn render_share_section(config: &Config, rec: &FileRec, csrf: &str) -> String {
    // The expiry <select> + optional password input, shared by the "update" and "create" forms.
    let controls = format!(
        "<div class=\"field\">\
           <label for=\"expiry\">Link expires</label>\
           <select id=\"expiry\" name=\"expiry\">{options}</select>\
         </div>\
         <div class=\"field\">\
           <label for=\"password\">Password (optional)</label>\
           <input id=\"password\" type=\"password\" name=\"password\" autocomplete=\"off\" \
             placeholder=\"Leave blank for no password\">\
         </div>",
        options = expiry_options("never"),
    );

    match &rec.share_token {
        Some(token) => {
            let share_url = format!("{}/s/{}", config.public_base, token);
            let expiry_status = match rec.expires_at {
                Some(exp) => format!("Expires {}", esc(&fmt_ts(exp))),
                None => "Never expires".to_string(),
            };
            let pw_status = if rec.share_has_password() {
                "Password-protected"
            } else {
                "No password"
            };
            format!(
                "<div class=\"field\">\
                   <label for=\"shareUrl\">Share link (no sign-in required)</label>\
                   <div class=\"share-row\">\
                     <input id=\"shareUrl\" type=\"text\" readonly value=\"{url}\">\
                     <button class=\"btn btn-secondary btn-sm\" id=\"copyBtn\" type=\"button\" data-label=\"Copy\">Copy</button>\
                   </div>\
                   <p class=\"muted\">{expiry_status} · {pw_status}</p>\
                 </div>\
                 <form class=\"share-form\" method=\"post\" action=\"/f/{id}/share\">\
                   <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                   {controls}\
                   <div class=\"actions actions--split\">\
                     <button class=\"btn btn-secondary\" type=\"submit\">Update share settings</button>\
                   </div>\
                 </form>\
                 <form class=\"revoke-form\" method=\"post\" action=\"/f/{id}/revoke\" \
                   onsubmit=\"return confirm('Revoke this share link? The current link will stop working.');\">\
                   <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                   <button class=\"btn btn-danger btn-sm\" type=\"submit\">Revoke share link</button>\
                 </form>",
                url = esc(&share_url),
                expiry_status = expiry_status,
                pw_status = pw_status,
                id = esc(&rec.id),
                csrf = esc(csrf),
                controls = controls,
            )
        }
        None => format!(
            "<div class=\"field\">\
               <label>Share link</label>\
               <p class=\"muted\">This file is private — there is no active share link.</p>\
             </div>\
             <form class=\"share-form\" method=\"post\" action=\"/f/{id}/share\">\
               <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
               {controls}\
               <div class=\"actions actions--split\">\
                 <button class=\"btn btn-primary\" type=\"submit\">Create share link</button>\
               </div>\
             </form>",
            id = esc(&rec.id),
            csrf = esc(csrf),
            controls = controls,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ext_label_handles_names() {
        assert_eq!(ext_label("report.pdf"), "PDF");
        assert_eq!(ext_label("archive.tar.gz"), "GZ");
        assert_eq!(ext_label("noext"), "FILE");
        assert_eq!(ext_label("weird.name!"), "FILE");
    }
}
