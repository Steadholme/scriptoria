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

use axum::extract::{Multipart, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth::{self, Identity};
use crate::config::Config;
use crate::error::AppError;
use crate::handlers::{
    esc, fmt_ts, human_size, resolve_content_type, safe_filename, userbox, APP_CSS, FILE_SVG,
    SHIELD_SVG,
};
use crate::model::FileRec;
use crate::{now_secs, random_alnum, AppState};

/// Length of the short random file id / object key (62-symbol alphabet, ~59 bits at 10 chars).
const FILE_ID_LEN: usize = 10;
/// Length of the unguessable public share token (~190 bits at 32 chars).
const SHARE_TOKEN_LEN: usize = 32;
/// Hard cap on a stored display file name (characters).
const MAX_NAME_CHARS: usize = 255;

const GALLERY_HTML: &str = include_str!("../../templates/gallery.html");
const DETAIL_HTML: &str = include_str!("../../templates/detail.html");

// ---------------------------------------------------------------------------
// GET / — the signed-in user's drive (gallery grid + upload dropzone)
// ---------------------------------------------------------------------------

/// `GET /` — render the upload dropzone (with a fresh CSRF token) and the owner's files as a grid.
pub async fn gallery(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let who = auth::identity(&headers);
    let csrf = auth::new_csrf_token();
    let files = state
        .store
        .list_by_owner(&who.subject)
        .await
        .unwrap_or_default();

    let html = render_gallery(&who, &csrf, &files);
    html_with_csrf(StatusCode::OK, html, &csrf)
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
        share_token: String::new(),
        created_at: now,
    };

    // Reserve a unique row (id + share token) BEFORE writing the blob, retrying on the rare
    // unique collision. Cheap — no bytes have been uploaded yet.
    let mut reserved = false;
    for _ in 0..6 {
        rec.id = random_alnum(FILE_ID_LEN);
        rec.object_key = rec.id.clone();
        rec.share_token = random_alnum(SHARE_TOKEN_LEN);
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
    let html = render_detail(&state.config, &rec, &viewer, &csrf);
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
/// `/s/` prefix `auth=public`; this handler never consults identity or ownership. Inline for
/// images, attachment otherwise.
pub async fn share(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Response, AppError> {
    let rec = state
        .store
        .get_by_token(&token)
        .await?
        .ok_or_else(|| AppError::NotFound("This share link is invalid or has been removed.".to_string()))?;
    let bytes = state.blobs.get(&rec.object_key).await?;
    // Public share fetch: no gateway identity on this route, so the affected file's owner is the
    // subject the event is attributed to.
    state.audit.emit(AuditEvent::info(
        "file.share",
        &rec.owner_sub,
        &rec.id,
        if rec.is_image() { "image" } else { "file" },
    ));
    Ok(serve_blob(&rec, bytes))
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

fn render_gallery(who: &Identity, csrf: &str, files: &[FileRec]) -> String {
    let count = match files.len() {
        0 => "No files yet".to_string(),
        1 => "1 file".to_string(),
        n => format!("{n} files"),
    };
    GALLERY_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("Drive", Some(&who.email)))
        .replace("{{CSRF}}", &esc(csrf))
        .replace("{{COUNT}}", &esc(&count))
        .replace("{{CARDS}}", &render_cards(files))
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

fn render_detail(config: &Config, rec: &FileRec, viewer: &Identity, csrf: &str) -> String {
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

    let share_url = format!("{}/s/{}", config.public_base, rec.share_token);

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
        .replace("{{SHARE_URL}}", &esc(&share_url))
        .replace("{{ID}}", &esc(&rec.id))
        .replace("{{DELETE}}", &delete)
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
