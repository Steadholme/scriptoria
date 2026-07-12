//! The drive surface: gallery, upload, detail/preview, raw stream, delete, and the public share
//! fetch.
//!
//! Mounted behind a Sluice `auth=sso` route except the `/s/{token}` share path, which the deploy
//! marks `auth=public`. The owner of every file is ALWAYS the gateway-injected `X-Auth-Subject`
//! (never a client field). The SSO routes enforce per-user ownership (a non-owner gets 403);
//! cross-user access happens only through the unguessable share token. State-changing POSTs carry
//! a double-submit CSRF token. Blob bytes are served as inline images only when magic-sniffed,
//! otherwise as `attachment` downloads (+ `nosniff`), so an uploaded file can never execute as
//! HTML in the drive's origin. Owner raw downloads and public share fetches also honor HTTP Range
//! so browser-native image/video/audio media can stream and seek without buffering the whole blob.

use std::collections::HashMap;

use axum::extract::multipart::MultipartRejection;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth::{self, Identity};
use crate::config::{clamp_page, effective_quota, Config};
use crate::error::AppError;
use crate::handlers::{
    app_css, dynamic_js, esc, expiry_options, fmt_ts, human_size, parse_expiry,
    render_share_room_error, resolve_content_type, safe_filename, share_room_html,
    share_room_html_with_csrf, sniff_verified_upload_type, userbox, FILE_SVG, SHIELD_SVG,
};
use crate::model::{
    library_type_for, FileComment, FileRec, FolderRec, LibraryCursor, LibraryItem, LibraryItemKind,
    LibraryQuery, LibraryType, LibraryView, TrashItem, UploadRequestRec, UploadSubmission,
    VersionRec,
};
use crate::store::{
    BulkMutation, DriveItemRef, OwnerBlobCommit, OwnerBlobWriteIntent, OwnerReuploadInput,
    OwnerVersionRestoreInput, TrashRootInput, UploadReserve, UploadReserveInput,
    DEFAULT_REQUEST_ALLOWED_TYPES, DEFAULT_REQUEST_MAX_FILES, DEFAULT_REQUEST_MAX_FILE_BYTES,
    DEFAULT_REQUEST_MAX_TOTAL_BYTES, MAX_BULK_ITEMS, OWNER_WRITE_FRESH, OWNER_WRITE_REUPLOAD,
    OWNER_WRITE_THUMBNAIL,
};
use crate::{now_secs, random_alnum, AppState};

/// Length of the short random file id / object key (62-symbol alphabet, ~59 bits at 10 chars).
const FILE_ID_LEN: usize = 10;
/// Length of the short random folder id.
const FOLDER_ID_LEN: usize = 10;
/// Length of a retained version's short random id.
const VERSION_ID_LEN: usize = 10;
/// Length of the unguessable public share token (~190 bits at 32 chars).
const SHARE_TOKEN_LEN: usize = 32;
/// Length of a public upload-inbox token.
const UPLOAD_TOKEN_LEN: usize = 32;
/// Length of a file comment id.
const COMMENT_ID_LEN: usize = 10;
/// Length of an immutable upload-request receipt id.
const SUBMISSION_ID_LEN: usize = 12;
const TRASH_ENTRY_ID_LEN: usize = 20;
const TRASH_RETENTION_SECS: i64 = 30 * 24 * 60 * 60;
/// Hard cap on a stored display file name (characters).
const MAX_NAME_CHARS: usize = 255;
/// Hard cap on a submitted comment body (characters).
const MAX_COMMENT_CHARS: usize = 2000;
/// Hard cap on a submitted share-link password (characters).
const MAX_PASSWORD_CHARS: usize = 128;
/// Search is metadata-only and owner-scoped; bounding the literal keeps URLs, SQL work and rendered
/// controls predictable without inventing a separate search service.
const MAX_LIBRARY_QUERY_CHARS: usize = 128;
/// Hard cap on the byte prefix rendered inline for a text/markdown preview (256 KiB). Larger files
/// still preview, but the tail is elided with a note.
const MAX_TEXT_PREVIEW_BYTES: usize = 256 * 1024;
/// Depth guard when walking a folder's parent chain to build breadcrumbs (defensive; the tree is
/// acyclic by construction).
const MAX_TREE_DEPTH: usize = 64;

const GALLERY_HTML: &str = include_str!("../../templates/gallery.html");
const DETAIL_HTML: &str = include_str!("../../templates/detail.html");
const SHARE_LANDING_HTML: &str = include_str!("../../templates/share_landing.html");
const SHARE_PW_HTML: &str = include_str!("../../templates/share_password.html");
const SHARE_FOLDER_HTML: &str = include_str!("../../templates/share_folder.html");
const UPLOAD_INBOX_HTML: &str = include_str!("../../templates/upload_inbox.html");

/// Folder glyph for the drive's subfolder tiles (trusted, server-owned markup).
const FOLDER_SVG: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 5h5l2 2.5h9a1 1 0 0 1 1 1V18a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1Z"/></svg>"##;

/// "Up one level" glyph for the tile that navigates to the parent folder.
const FOLDER_UP_SVG: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 5h5l2 2.5h9a1 1 0 0 1 1 1V18a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1Z"/><path d="m12 16 0-5"/><path d="m9.5 13 2.5-2.5 2.5 2.5"/></svg>"##;

/// Film-strip glyph for browser-native video cards.
const VIDEO_SVG: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="M7 5v14M17 5v14M3 9h4M3 15h4M17 9h4M17 15h4"/><path d="m11 10 4 2-4 2Z" fill="currentColor" stroke="none"/></svg>"##;

/// Waveform glyph for browser-native audio cards.
const AUDIO_SVG: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 13v-2M8 17V7M12 20V4M16 17V7M20 13v-2"/></svg>"##;

const PLAY_SVG: &str = r##"<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M9 7.5v9l7-4.5-7-4.5Z"/></svg>"##;

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
    /// Optional view selector. `view=trash` renders the owner's recycle bin instead of live files.
    #[serde(default)]
    pub view: Option<String>,
    /// Literal, case-insensitive file/folder name search across the signed-in owner's whole tree.
    #[serde(default)]
    pub q: Option<String>,
    /// Stable owner-facing type group (`type` is kept in the URL for readable/shareable filters).
    #[serde(default, rename = "type")]
    pub type_filter: Option<String>,
}

/// `GET /` — render the upload dropzone (with the browser's valid reusable double-submit CSRF
/// token) and one keyset page of the owner's files, newest-first. With no `?before` cursor this is
/// the newest page (the default view, now capped at `DEFAULT_PAGE`); a
/// `?before=<created_at>_<id>` cursor pages into older files.
pub async fn gallery(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<GalleryQuery>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    // Keep the owner's valid double-submit token stable across gallery GETs. Wire's optimistic
    // single-card Trash path follows its POST redirect without replacing the rest of the DOM; a
    // rotating GET token would otherwise invalidate every still-rendered form after that delete.
    let csrf = auth::existing_or_new_csrf_token(&headers);
    // Same clamp the store applies, so `files.len() == limit` below is an exact "page was full" test.
    let limit = clamp_page(q.limit.unwrap_or(0));
    let search = clean_library_query(q.q.as_deref())?;
    let type_filter = parse_library_type(q.type_filter.as_deref())?;
    let library_view = parse_library_view(q.view.as_deref())?;

    let folders = state.store.list_folders(&who.subject).await?;
    // The active folder must belong to the owner; an unknown/blank id falls back to all files.
    let active = q
        .folder
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|fid| folders.iter().find(|f| f.id == fid).cloned());
    // The usage meter: total stored bytes vs. the effective quota (override else default).
    let used = state.store.usage_for_owner(&who.subject).await?;
    let quota = effective_quota(
        state.store.get_quota(&who.subject).await?,
        state.config.default_quota_bytes,
    );

    if q.view.as_deref().is_some_and(|view| view.trim() == "trash") {
        let before = parse_library_cursor(q.before.as_deref())?;
        let page = state
            .store
            .query_trash(&who.subject, before.as_ref(), limit)
            .await?;
        let html = render_trash_gallery(TrashRender {
            config: &state.config,
            who: &who,
            csrf: &csrf,
            items: &page.items,
            next: page.next.as_ref(),
            folders: &folders,
            used,
            quota,
        });
        return Ok(html_with_csrf(StatusCode::OK, html, &csrf));
    }

    let library_mode =
        library_view != LibraryView::All || search.is_some() || type_filter != LibraryType::All;
    if library_mode {
        let before = parse_library_cursor(q.before.as_deref())?;
        let query = LibraryQuery {
            view: library_view,
            query: search,
            type_filter,
            before,
            limit,
        };
        let page = state.store.query_library(&who.subject, &query).await?;
        let html = render_library_gallery(LibraryRender {
            config: &state.config,
            who: &who,
            csrf: &csrf,
            items: &page.items,
            next: page.next.as_ref(),
            folders: &folders,
            query: &query,
            used,
            quota,
        });
        return Ok(html_with_csrf(StatusCode::OK, html, &csrf));
    }

    let before = parse_cursor(q.before.as_deref());
    let folder_filter = active.as_ref().map(|f| f.id.as_str());
    let files = state
        .store
        .list_by_owner(&who.subject, folder_filter, before, limit)
        .await?;

    // Legacy folder browsing keeps its existing cursor contract. Library views use an exact
    // look-ahead page returned by Store.
    let next = if files.len() as i64 == limit {
        files.last().map(|f| (f.created_at, f.id.clone()))
    } else {
        None
    };

    let html = render_gallery(
        &state.config,
        &who,
        &csrf,
        &files,
        next.as_ref(),
        &folders,
        active.as_ref(),
        used,
        quota,
    );
    Ok(html_with_csrf(StatusCode::OK, html, &csrf))
}

fn clean_library_query(raw: Option<&str>) -> Result<Option<String>, AppError> {
    let Some(value) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if value.chars().count() > MAX_LIBRARY_QUERY_CHARS || value.chars().any(char::is_control) {
        return Err(AppError::BadRequest(format!(
            "Search text must be at most {MAX_LIBRARY_QUERY_CHARS} characters."
        )));
    }
    Ok(Some(value.to_string()))
}

fn parse_library_view(raw: Option<&str>) -> Result<LibraryView, AppError> {
    match raw.map(str::trim).filter(|value| !value.is_empty()) {
        None | Some("all") | Some("trash") => Ok(LibraryView::All),
        Some("recent") => Ok(LibraryView::Recent),
        Some("shared") => Ok(LibraryView::Shared),
        Some(_) => Err(AppError::BadRequest("Unknown library view.".to_string())),
    }
}

fn parse_library_type(raw: Option<&str>) -> Result<LibraryType, AppError> {
    match raw.map(str::trim).filter(|value| !value.is_empty()) {
        None | Some("all") => Ok(LibraryType::All),
        Some("folder") => Ok(LibraryType::Folder),
        Some("image") => Ok(LibraryType::Image),
        Some("video") => Ok(LibraryType::Video),
        Some("audio") => Ok(LibraryType::Audio),
        Some("pdf") => Ok(LibraryType::Pdf),
        Some("document") => Ok(LibraryType::Document),
        Some("archive") => Ok(LibraryType::Archive),
        Some("other") => Ok(LibraryType::Other),
        Some(_) => Err(AppError::BadRequest(
            "Unknown file type filter.".to_string(),
        )),
    }
}

fn parse_library_cursor(raw: Option<&str>) -> Result<Option<LibraryCursor>, AppError> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let mut parts = raw.splitn(3, '_');
    let updated_at = parts.next().and_then(|part| part.parse::<i64>().ok());
    let kind = match parts.next() {
        Some("file") => Some(LibraryItemKind::File),
        Some("folder") => Some(LibraryItemKind::Folder),
        _ => None,
    };
    let id = parts.next().filter(|id| {
        !id.is_empty() && id.len() <= 64 && id.chars().all(|ch| ch.is_ascii_alphanumeric())
    });
    match (updated_at, kind, id) {
        (Some(updated_at), Some(kind), Some(id)) => Ok(Some(LibraryCursor {
            updated_at,
            kind,
            id: id.to_string(),
        })),
        _ => Err(AppError::BadRequest(
            "This result cursor is invalid. Start again from the first page.".to_string(),
        )),
    }
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
    let mut folder_field = String::new();
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
            "folder_id" => {
                folder_field = field
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

    // Resolve the upload target level: blank => root; otherwise an owned folder (else 404). A file
    // is uploaded INTO the folder currently being viewed (the gallery form carries its id).
    let target: Option<String> = match folder_field.trim() {
        "" => None,
        fid => {
            if state.store.get_folder(fid, &who.subject).await?.is_none() {
                return Err(AppError::NotFound("No such folder.".to_string()));
            }
            Some(fid.to_string())
        }
    };

    // Enforce the owner's storage quota BEFORE reserving the row or writing the blob. The
    // effective quota is the per-owner override else the configured default; unlimited (the
    // pre-quota default) skips the usage read entirely, so the fast path is unchanged. Usage
    // already includes retained version blobs, so a re-upload is checked against the true total.
    let owner_quota = effective_quota(
        state.store.get_quota(&who.subject).await?,
        state.config.default_quota_bytes,
    );
    if let Some(quota) = owner_quota {
        let used = state.store.usage_for_owner(&who.subject).await?;
        if used.saturating_add(size) > quota {
            tracing::info!(
                owner = who.subject,
                used,
                size,
                quota,
                "upload rejected: over quota"
            );
            state.audit.emit(AuditEvent::warning(
                "file.quota.reject",
                &who.subject,
                "upload",
                "over-quota upload rejected",
            ));
            return Err(AppError::QuotaExceeded(format!(
                "Not enough storage. This file is {size}, but only {free} of your {quota} quota \
                 is free. Delete some files and try again.",
                size = human_size(size),
                free = human_size((quota - used).max(0)),
                quota = human_size(quota),
            )));
        }
    }

    // Re-upload of the SAME name in the SAME folder -> keep the prior blob as a version rather than
    // overwriting it, and repoint the existing file at the new bytes.
    if let Some(existing) = state
        .store
        .find_file_in_folder(&who.subject, &name, target.as_deref())
        .await?
    {
        return reupload_as_version(
            &state,
            &who,
            OwnerReuploadPayload {
                existing,
                content_type,
                bytes,
                size,
                now,
                owner_quota,
            },
        )
        .await;
    }

    let mut rec = FileRec {
        id: String::new(),
        owner_sub: who.subject.clone(),
        name,
        content_type,
        size,
        bucket: state.blobs.bucket().to_string(),
        object_key: String::new(),
        // Private by default. A public capability exists only after the owner explicitly creates it
        // from the detail page.
        share_token: None,
        created_at: now,
        updated_at: now,
        expires_at: None,
        share_password_hash: None,
        // A fresh upload lands at the level it was uploaded into (root when unset).
        folder_id: target,
        trashed_at: 0,
        trash_entry_id: None,
        trash_ancestor_id: None,
        view_count: 0,
    };

    // Persist quota + cleanup authority before touching Cairn. Metadata is finalized only after the
    // put, consuming the intent in the same transaction as the file insert.
    let mut committed = false;
    for _ in 0..6 {
        rec.id = random_alnum(FILE_ID_LEN);
        rec.object_key = rec.id.clone();
        let intent = OwnerBlobWriteIntent {
            object_key: rec.object_key.clone(),
            owner_sub: rec.owner_sub.clone(),
            size: rec.size,
            kind: OWNER_WRITE_FRESH.to_string(),
            file_id: rec.id.clone(),
            folder_id: rec.folder_id.clone(),
            expected_object_key: None,
            created_at: now,
            attempts: 0,
        };
        match state
            .store
            .reserve_owner_blob_write(&intent, owner_quota)
            .await?
        {
            OwnerBlobCommit::Collision => continue,
            OwnerBlobCommit::QuotaExceeded => return Err(owner_quota_error()),
            OwnerBlobCommit::Conflict => return Err(owner_target_conflict()),
            OwnerBlobCommit::Applied => {}
        }
        // A failed/partial put deliberately leaves the durable intent for startup/periodic cleanup.
        state.blobs.put(&rec.object_key, bytes.clone()).await?;
        match state.store.commit_owner_upload(&rec, owner_quota).await? {
            OwnerBlobCommit::Applied => {
                committed = true;
                break;
            }
            OwnerBlobCommit::QuotaExceeded => return Err(owner_quota_error()),
            OwnerBlobCommit::Conflict => return Err(owner_target_conflict()),
            OwnerBlobCommit::Collision => {
                return Err(AppError::Internal(
                    "could not finalize a unique file id".to_string(),
                ))
            }
        }
    }
    if !committed {
        return Err(AppError::Internal(
            "could not allocate a unique file id".to_string(),
        ));
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

/// Re-upload path: snapshot the file's CURRENT blob as a version (it stays in place under its own
/// object key), write the new bytes to a fresh key, repoint the file, then prune the oldest
/// versions past the cap (deleting their blobs). Quota was already checked by the caller.
struct OwnerReuploadPayload {
    existing: FileRec,
    content_type: String,
    bytes: Vec<u8>,
    size: i64,
    now: i64,
    owner_quota: Option<i64>,
}

async fn reupload_as_version(
    state: &AppState,
    who: &Identity,
    input: OwnerReuploadPayload,
) -> Result<Response, AppError> {
    let OwnerReuploadPayload {
        existing,
        content_type,
        bytes,
        size,
        now,
        owner_quota,
    } = input;
    // Allocate cleanup/quota authority before the put. A purge may win after this reservation; the
    // final CAS then fails and the retained intent authorizes idempotent blob cleanup.
    let mut new_key = String::new();
    for _ in 0..6 {
        let candidate = random_alnum(FILE_ID_LEN);
        let intent = OwnerBlobWriteIntent {
            object_key: candidate.clone(),
            owner_sub: who.subject.clone(),
            size,
            kind: OWNER_WRITE_REUPLOAD.to_string(),
            file_id: existing.id.clone(),
            folder_id: existing.folder_id.clone(),
            expected_object_key: Some(existing.object_key.clone()),
            created_at: now,
            attempts: 0,
        };
        match state
            .store
            .reserve_owner_blob_write(&intent, owner_quota)
            .await?
        {
            OwnerBlobCommit::Applied => {
                new_key = candidate;
                break;
            }
            OwnerBlobCommit::Collision => continue,
            OwnerBlobCommit::QuotaExceeded => return Err(owner_quota_error()),
            OwnerBlobCommit::Conflict => return Err(owner_target_conflict()),
        }
    }
    if new_key.is_empty() {
        return Err(AppError::Internal(
            "could not allocate a unique object key".to_string(),
        ));
    }
    state.blobs.put(&new_key, bytes).await?;

    let mut finalized = false;
    for _ in 0..6 {
        let snapshot_id = random_alnum(VERSION_ID_LEN);
        match state
            .store
            .commit_owner_reupload(OwnerReuploadInput {
                owner_sub: &who.subject,
                file_id: &existing.id,
                expected_object_key: &existing.object_key,
                new_object_key: &new_key,
                new_size: size,
                new_content_type: &content_type,
                snapshot_id: &snapshot_id,
                changed_at: now,
                owner_quota,
            })
            .await?
        {
            OwnerBlobCommit::Applied => {
                finalized = true;
                break;
            }
            OwnerBlobCommit::Collision => continue,
            OwnerBlobCommit::QuotaExceeded => return Err(owner_quota_error()),
            OwnerBlobCommit::Conflict => return Err(owner_target_conflict()),
        }
    }
    if !finalized {
        return Err(AppError::Internal(
            "could not allocate a unique version id".to_string(),
        ));
    }

    tracing::info!(
        id = existing.id,
        owner = who.subject,
        size,
        "file re-uploaded as new version"
    );
    state.audit.emit(AuditEvent::notice(
        "file.version.add",
        &who.subject,
        &existing.id,
        "new version",
    ));
    Ok(redirect_found(&format!("/f/{}", existing.id)))
}

fn owner_target_conflict() -> AppError {
    AppError::Conflict(
        "The destination or file changed while the blob was being written. Reload and try again."
            .to_string(),
    )
}

fn owner_quota_error() -> AppError {
    AppError::QuotaExceeded(
        "Your storage changed while the upload was in progress and there is no longer enough space."
            .to_string(),
    )
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
    let preview = build_preview(&state, &rec).await;
    let versions = state.store.list_versions(&rec.id).await.unwrap_or_default();
    let comments = state.store.list_comments(&rec.id).await.unwrap_or_default();
    let html = render_detail(DetailRender {
        config: &state.config,
        rec: &rec,
        viewer: &viewer,
        csrf: &csrf,
        folders: &folders,
        preview: &preview,
        versions: &versions,
        comments: &comments,
    });
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
    serve_file(&state, &rec, &headers).await
}

// ---------------------------------------------------------------------------
// GET /f/{id}/preview-raw — inline, sandboxed PDF bytes for the detail embed (owner-only)
// ---------------------------------------------------------------------------

/// `GET /f/{id}/preview-raw` — serve a PDF INLINE (sandboxed) so the detail page can embed it in a
/// sandboxed `<iframe>`. Owner-only. Only `application/pdf` is served inline: the bytes carry
/// `Content-Type: application/pdf` + `nosniff` (so a file lying about its type can never be
/// interpreted as HTML) and a `Content-Security-Policy: sandbox` (no scripts, no plugins). Every
/// other type falls back to the safe attachment path.
pub async fn preview_raw(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let viewer = auth::identity(&headers);
    let rec = owned_file(&state, &id, &viewer).await?;
    let bytes = state.blobs.get(&rec.object_key).await?;
    if rec.content_type == "application/pdf" {
        Ok(serve_pdf_inline(&rec, bytes))
    } else {
        Ok(serve_blob(&rec, bytes))
    }
}

// ---------------------------------------------------------------------------
// Versions: download / restore a retained blob snapshot (owner-only)
// ---------------------------------------------------------------------------

/// `GET /f/{id}/versions/{vid}/raw` — download one retained version's blob (always as an
/// attachment). Owner-only (through the file's ownership gate); the version is scoped to the file.
pub async fn download_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, vid)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let viewer = auth::identity(&headers);
    let rec = owned_file(&state, &id, &viewer).await?;
    let version = state
        .store
        .get_version(&vid, &rec.id)
        .await?
        .ok_or_else(|| AppError::NotFound("No such version.".to_string()))?;
    let bytes = state.blobs.get(&version.object_key).await?;
    Ok(serve_version_download(&rec, bytes))
}

/// `POST /f/{id}/versions/{vid}/restore` — make a retained version the current blob. CSRF-checked,
/// owner-scoped. The current blob is first snapshotted as a NEW version (history is kept), then the
/// file is repointed at the chosen version's blob and that version row is consumed; finally the
/// history is pruned to the cap. Then 302 to `/f/{id}`.
pub async fn restore_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, vid)): Path<(String, String)>,
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
        .get_version(&vid, &rec.id)
        .await?
        .ok_or_else(|| AppError::NotFound("No such version.".to_string()))?;

    let changed_at = now_secs();
    let mut restored = false;
    for _ in 0..6 {
        let snapshot_id = random_alnum(VERSION_ID_LEN);
        match state
            .store
            .commit_owner_version_restore(OwnerVersionRestoreInput {
                owner_sub: &actor.subject,
                file_id: &rec.id,
                expected_object_key: &rec.object_key,
                version_id: &vid,
                snapshot_id: &snapshot_id,
                changed_at,
            })
            .await?
        {
            OwnerBlobCommit::Applied => {
                restored = true;
                break;
            }
            OwnerBlobCommit::Collision => continue,
            OwnerBlobCommit::Conflict => return Err(owner_target_conflict()),
            OwnerBlobCommit::QuotaExceeded => {
                return Err(AppError::Internal(
                    "version restore returned an impossible quota outcome".to_string(),
                ))
            }
        }
    }
    if !restored {
        return Err(AppError::Internal(
            "could not allocate a unique version id".to_string(),
        ));
    }

    tracing::info!(
        id = rec.id,
        owner = actor.subject,
        version = vid,
        "file version restored"
    );
    state.audit.emit(AuditEvent::notice(
        "file.version.restore",
        &actor.subject,
        &rec.id,
        "restore version",
    ));
    Ok(redirect_found(&format!("/f/{}", rec.id)))
}

// ---------------------------------------------------------------------------
// GET /d/{id}/thumb — derived gallery thumbnail (owner-only)
// ---------------------------------------------------------------------------

/// `GET /d/{id}/thumb` — serve the gallery-card thumbnail for a file. Owner-only, mirroring
/// `/f/{id}/raw`'s ownership gate EXACTLY (404 when absent, 403 when owned by someone else).
///
/// Aperture ships no image-decoder dependency, so a sniffed raster image cannot be downscaled here;
/// it is treated as "undecodable" and 302-redirects to the full `/f/{id}/raw` bytes, so the grid
/// still shows the real picture (no regression). Every OTHER type gets a deterministic, mime-keyed
/// SVG type-icon that is derived lazily on first request and cached as a derived blob
/// (`{object_key}.thumb`), then served from that cache on later requests. The placeholder is
/// server-generated + fully escaped, so no user bytes are ever served inline by this route.
pub async fn thumb(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let viewer = auth::identity(&headers);
    let rec = owned_file(&state, &id, &viewer).await?;
    // A raster image is undecodable-for-resize without a decoder dep: fall back to the full bytes.
    if rec.is_image() {
        return Ok(redirect_found(&format!("/f/{}/raw", rec.id)));
    }
    Ok(serve_thumb(&state, &rec).await)
}

// ---------------------------------------------------------------------------
// POST /delete/{id} — move your own file to Trash
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct DeleteForm {
    #[serde(default)]
    pub csrf_token: String,
}

fn parse_bulk_form(
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> Result<(Vec<DriveItemRef>, String), AppError> {
    let csrf = form
        .get("csrf_token")
        .map(String::as_str)
        .unwrap_or_default();
    if !auth::verify_csrf(headers, csrf) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let mut items = Vec::new();
    for key in form.keys().filter(|key| key.starts_with("item:")) {
        let mut parts = key.splitn(3, ':');
        let _ = parts.next();
        let kind = match parts.next() {
            Some("file") => LibraryItemKind::File,
            Some("folder") => LibraryItemKind::Folder,
            _ => {
                return Err(AppError::BadRequest(
                    "The selection contains an invalid item.".to_string(),
                ))
            }
        };
        let id = parts.next().unwrap_or_default();
        if id.is_empty() || id.len() > 128 || !id.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            return Err(AppError::BadRequest(
                "The selection contains an invalid item.".to_string(),
            ));
        }
        items.push(DriveItemRef {
            kind,
            id: id.to_string(),
        });
    }
    items.sort_by(|left, right| {
        left.kind
            .rank()
            .cmp(&right.kind.rank())
            .then_with(|| left.id.cmp(&right.id))
    });
    if items.is_empty() {
        return Err(AppError::BadRequest(
            "Select at least one item.".to_string(),
        ));
    }
    if items.len() > MAX_BULK_ITEMS {
        return Err(AppError::BadRequest(format!(
            "Select at most {MAX_BULK_ITEMS} items at a time."
        )));
    }
    let return_to = match form.get("return_to").map(String::as_str) {
        None => "/",
        Some(value)
            if (value == "/" || value.starts_with("/?"))
                && value.is_ascii()
                && !value.bytes().any(|byte| byte.is_ascii_control())
                && HeaderValue::from_str(value).is_ok() =>
        {
            value
        }
        Some(_) => {
            return Err(AppError::BadRequest(
                "The return location is invalid.".to_string(),
            ))
        }
    }
    .to_string();
    Ok((items, return_to))
}

fn require_bulk_applied(result: BulkMutation) -> Result<usize, AppError> {
    match result {
        BulkMutation::Applied { changed } => Ok(changed),
        BulkMutation::Conflict => Err(AppError::Conflict(
            "One or more selected items changed. Reload and try again.".to_string(),
        )),
    }
}

pub async fn bulk_trash(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let (items, return_to) = parse_bulk_form(&headers, &form)?;
    let actor = auth::identity(&headers);
    let now = now_secs();
    let roots: Vec<TrashRootInput> = items
        .iter()
        .cloned()
        .map(|item| TrashRootInput {
            item,
            entry_id: random_alnum(TRASH_ENTRY_ID_LEN),
        })
        .collect();
    let changed = require_bulk_applied(
        state
            .store
            .bulk_trash(
                &actor.subject,
                &roots,
                now,
                now.saturating_add(TRASH_RETENTION_SECS),
            )
            .await?,
    )?;
    state.audit.emit(AuditEvent::notice(
        "drive.bulk.trash",
        &actor.subject,
        "selection",
        &format!("{changed} roots"),
    ));
    Ok(redirect_found(&return_to))
}

pub async fn bulk_restore(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let (items, return_to) = parse_bulk_form(&headers, &form)?;
    let actor = auth::identity(&headers);
    let changed = require_bulk_applied(state.store.bulk_restore(&actor.subject, &items).await?)?;
    state.audit.emit(AuditEvent::notice(
        "drive.bulk.restore",
        &actor.subject,
        "selection",
        &format!("{changed} roots"),
    ));
    Ok(redirect_found(&return_to))
}

pub async fn bulk_move(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let (items, return_to) = parse_bulk_form(&headers, &form)?;
    let actor = auth::identity(&headers);
    let destination = form
        .get("folder_id")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let changed = require_bulk_applied(
        state
            .store
            .bulk_move(&actor.subject, &items, destination)
            .await?,
    )?;
    state.audit.emit(AuditEvent::notice(
        "drive.bulk.move",
        &actor.subject,
        "selection",
        &format!("{changed} roots"),
    ));
    Ok(redirect_found(&return_to))
}

pub async fn bulk_purge(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let (items, return_to) = parse_bulk_form(&headers, &form)?;
    let actor = auth::identity(&headers);
    let changed = require_bulk_applied(
        state
            .store
            .bulk_purge(&actor.subject, &items, now_secs())
            .await?,
    )?;
    if let Err(error) =
        crate::drain_trash_lifecycle_once(state.store.as_ref(), state.blobs.as_ref(), now_secs())
            .await
    {
        tracing::warn!(%error, "logical purge committed; object cleanup remains queued");
    }
    state.audit.emit(AuditEvent::warning(
        "drive.bulk.purge",
        &actor.subject,
        "selection",
        &format!("{changed} roots"),
    ));
    Ok(redirect_found(&return_to))
}

/// `POST /delete/{id}` — CSRF-checked, ownership-scoped soft delete, then 302 to `/`.
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

    let now = now_secs();
    require_bulk_applied(
        state
            .store
            .bulk_trash(
                &actor.subject,
                &[TrashRootInput {
                    item: DriveItemRef {
                        kind: LibraryItemKind::File,
                        id: rec.id.clone(),
                    },
                    entry_id: random_alnum(TRASH_ENTRY_ID_LEN),
                }],
                now,
                now.saturating_add(TRASH_RETENTION_SECS),
            )
            .await?,
    )?;
    tracing::info!(id = rec.id, owner = actor.subject, "file moved to trash");
    state.audit.emit(AuditEvent::notice(
        "file.trash",
        &actor.subject,
        &rec.id,
        if rec.is_image() { "image" } else { "file" },
    ));
    if wants_json(&headers) {
        return Ok(axum::Json(serde_json::json!({ "ok": true, "id": rec.id })).into_response());
    }
    Ok(redirect_found("/"))
}

/// True when the caller (a `fetch()` from the enhanced gallery) asked for JSON via `Accept`. A
/// plain form POST (no-JS) never sets this, so it keeps its 302 — this is the seam that lets the
/// optimistic JSON replies live ALONGSIDE the unchanged form routes.
fn wants_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|a| a.contains("application/json"))
        .unwrap_or(false)
}

/// Form body for an inline file rename: the CSRF token + the new display name.
#[derive(Debug, Deserialize)]
pub struct RenameForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub name: String,
}

/// `POST /f/{id}/rename` — rename your own live file, then 302 back to its view. CSRF-checked,
/// ownership-scoped, name trimmed + required + length-capped. The enhanced gallery asks for JSON
/// (`Accept: application/json`) and updates the card in place; a plain form POST 302s as usual.
pub async fn rename(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<RenameForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let actor = auth::identity(&headers);
    let rec = owned_file(&state, &id, &actor).await?;

    let name: String = form.name.trim().chars().take(MAX_NAME_CHARS).collect();
    if name.is_empty() {
        return Err(AppError::BadRequest("A file name is required.".to_string()));
    }

    state
        .store
        .rename_file(&rec.id, &actor.subject, &name)
        .await?;
    tracing::info!(id = rec.id, owner = actor.subject, "file renamed");
    state.audit.emit(AuditEvent::notice(
        "file.rename",
        &actor.subject,
        &rec.id,
        &name,
    ));

    if wants_json(&headers) {
        return Ok(
            axum::Json(serde_json::json!({ "ok": true, "id": rec.id, "name": name }))
                .into_response(),
        );
    }
    Ok(redirect_found(&format!("/f/{}", rec.id)))
}

/// `POST /trash/{id}/restore` — restore a trashed file to the normal drive view.
pub async fn restore_trashed(
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
    let rec = owned_trashed_file(&state, &id, &actor).await?;
    require_bulk_applied(
        state
            .store
            .bulk_restore(
                &actor.subject,
                &[DriveItemRef {
                    kind: LibraryItemKind::File,
                    id: rec.id.clone(),
                }],
            )
            .await?,
    )?;
    tracing::info!(
        id = rec.id,
        owner = actor.subject,
        "file restored from trash"
    );
    state.audit.emit(AuditEvent::notice(
        "file.trash.restore",
        &actor.subject,
        &rec.id,
        if rec.is_image() { "image" } else { "file" },
    ));
    if wants_json(&headers) {
        return Ok(axum::Json(serde_json::json!({ "ok": true, "id": rec.id })).into_response());
    }
    Ok(redirect_found("/?view=trash"))
}

/// `POST /trash/{id}/purge` — permanently delete a trashed file and all retained data.
pub async fn purge_trashed(
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
    let rec = owned_trashed_file(&state, &id, &actor).await?;
    require_bulk_applied(
        state
            .store
            .bulk_purge(
                &actor.subject,
                &[DriveItemRef {
                    kind: LibraryItemKind::File,
                    id: rec.id.clone(),
                }],
                now_secs(),
            )
            .await?,
    )?;
    if let Err(error) =
        crate::drain_trash_lifecycle_once(state.store.as_ref(), state.blobs.as_ref(), now_secs())
            .await
    {
        tracing::warn!(%error, "logical purge committed; object cleanup remains queued");
    }
    tracing::info!(id = rec.id, owner = actor.subject, "trashed file purged");
    state.audit.emit(AuditEvent::warning(
        "file.delete.forever",
        &actor.subject,
        &rec.id,
        if rec.is_image() { "image" } else { "file" },
    ));
    Ok(redirect_found("/?view=trash"))
}

// ---------------------------------------------------------------------------
// File comments (owner detail page)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CommentForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub body: String,
}

/// `POST /f/{id}/comments` — append a comment to a live owned file.
pub async fn add_comment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<CommentForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let actor = auth::identity(&headers);
    let rec = owned_file(&state, &id, &actor).await?;
    let body = clean_comment_body(&form.body)?;
    let mut comment = FileComment {
        id: String::new(),
        file_id: rec.id.clone(),
        author_sub: actor.subject.clone(),
        body,
        created_at: now_secs(),
    };
    let mut created = false;
    for _ in 0..6 {
        comment.id = random_alnum(COMMENT_ID_LEN);
        if state.store.create_comment(&comment).await? {
            created = true;
            break;
        }
    }
    if !created {
        return Err(AppError::Internal(
            "could not allocate a unique comment id".to_string(),
        ));
    }
    tracing::info!(
        id = rec.id,
        comment = comment.id,
        author = actor.subject,
        "file comment added"
    );
    state.audit.emit(AuditEvent::info(
        "file.comment.add",
        &actor.subject,
        &rec.id,
        "comment",
    ));
    Ok(redirect_found(&format!("/f/{}", rec.id)))
}

/// `POST /f/{id}/comments/{cid}/delete` — delete one comment. The file owner or an admin may
/// delete any comment; the comment must belong to the addressed file.
pub async fn delete_comment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, cid)): Path<(String, String)>,
    Form(form): Form<DeleteForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let actor = auth::identity(&headers);
    let rec = state
        .store
        .get(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("No file exists at that link.".to_string()))?;
    let comment = state
        .store
        .get_comment(&cid)
        .await?
        .filter(|c| c.file_id == rec.id)
        .ok_or_else(|| AppError::NotFound("No such comment.".to_string()))?;
    if rec.owner_sub != actor.subject && !auth::is_admin(&headers) {
        return Err(AppError::Forbidden(
            "Only the file owner or an admin can delete comments.".to_string(),
        ));
    }
    state.store.delete_comment(&comment.id, &rec.id).await?;
    tracing::info!(
        id = rec.id,
        comment = comment.id,
        actor = actor.subject,
        "file comment deleted"
    );
    state.audit.emit(AuditEvent::notice(
        "file.comment.delete",
        &actor.subject,
        &rec.id,
        "comment",
    ));
    Ok(redirect_found(&format!("/f/{}", rec.id)))
}

// ---------------------------------------------------------------------------
// GET /s/{token} — public share fetch (NO SSO)
// ---------------------------------------------------------------------------

/// Collapse every public capability failure into the product-owned Share Room error shell. Backend
/// details are never reflected to anonymous callers.
fn share_room_response(result: Result<Response, AppError>) -> Response {
    match result {
        Ok(response) => response,
        Err(error) => {
            let (status, heading, message) = match error {
                AppError::BadRequest(detail) => {
                    tracing::warn!(reason = %detail, "public capability request rejected");
                    (
                        StatusCode::BAD_REQUEST,
                        "Request rejected",
                        "Aperture could not accept this request. Reload the room and try again."
                            .to_string(),
                    )
                }
                AppError::Forbidden(_) => (
                    StatusCode::FORBIDDEN,
                    "Access denied",
                    "This capability does not grant access to that item.".to_string(),
                ),
                AppError::Conflict(_) => (
                    StatusCode::CONFLICT,
                    "Request changed",
                    "This request changed while it was being processed. Reload and try again."
                        .to_string(),
                ),
                AppError::NotFound(_) => (
                    StatusCode::NOT_FOUND,
                    "Share not found",
                    "This share link is invalid or has been removed.".to_string(),
                ),
                AppError::Gone(detail) if detail.contains("upload request") => (
                    StatusCode::GONE,
                    "Upload room closed",
                    "This upload room is closed or has expired and is no longer accepting files."
                        .to_string(),
                ),
                AppError::Gone(_) => (
                    StatusCode::GONE,
                    "Share expired",
                    "This share link has expired and is no longer available.".to_string(),
                ),
                AppError::QuotaExceeded(detail) => {
                    tracing::warn!(reason = %detail, "public upload rejected");
                    (
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "Upload unavailable",
                        "This upload room cannot accept that file right now. Try a smaller file or contact the owner."
                            .to_string(),
                    )
                }
                AppError::Internal(detail) => {
                    tracing::error!(reason = %detail, "public capability request failed");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Share Room unavailable",
                        "Aperture could not complete this request. Try again later.".to_string(),
                    )
                }
            };
            render_share_room_error(status, heading, &message)
        }
    }
}

fn share_expiry_label(expires_at: Option<i64>) -> String {
    match expires_at {
        Some(expiry) => format!("Expires {}", fmt_ts(expiry)),
        None => "No expiry".to_string(),
    }
}

/// `GET /s/{token}` — fetch a shared file by its unguessable token, WITHOUT SSO. Deploy marks the
/// `/s/` prefix `auth=public`; this handler never consults identity or ownership. Honors the share
/// lifecycle: a revoked token is 404, an expired link is 410 Gone, and a password-protected link
/// renders a password prompt instead of the bytes. Inline for images, attachment otherwise.
pub async fn share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    share_room_response(
        async move {
            let rec = load_shared(&state, &token).await?;
            // Password-protected: never serve the bytes on a bare GET — prompt first.
            if rec.share_has_password() {
                return Ok(render_share_prompt(
                    &format!("/s/{token}"),
                    StatusCode::OK,
                    None,
                    "file",
                    rec.expires_at,
                    "Unlock and download",
                ));
            }
            serve_shared(&state, &rec, &headers).await
        }
        .await,
    )
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
    headers: HeaderMap,
    Path(token): Path<String>,
    Form(form): Form<SharePasswordForm>,
) -> Response {
    share_room_response(
        async move {
            let rec = load_shared(&state, &token).await?;
            match &rec.share_password_hash {
                // Correct password (or the link is no longer protected) -> serve.
                Some(hash) if auth::verify_share_password(hash, &form.password) => {
                    serve_shared(&state, &rec, &headers).await
                }
                None => serve_shared(&state, &rec, &headers).await,
                Some(_) => Ok(render_share_prompt(
                    &format!("/s/{token}"),
                    StatusCode::UNAUTHORIZED,
                    Some("Incorrect password."),
                    "file",
                    rec.expires_at,
                    "Unlock and download",
                )),
            }
        }
        .await,
    )
}

/// `GET /s/{token}/view` — render the public share landing page used for unfurls and human opens.
/// Password-protected links do not reveal metadata here; the prompt posts to `/s/{token}`, the
/// existing unlock route that serves the bytes after a correct password.
pub async fn share_landing(State(state): State<AppState>, Path(token): Path<String>) -> Response {
    share_room_response(
        async move {
            let mut rec = load_shared(&state, &token).await?;
            if rec.share_has_password() {
                return Ok(render_share_prompt(
                    &format!("/s/{token}"),
                    StatusCode::OK,
                    None,
                    "file",
                    rec.expires_at,
                    "Unlock and download",
                ));
            }
            if state.store.bump_view_count(&rec.id).await.is_ok() {
                rec.view_count += 1;
            }
            Ok(render_share_landing(&state.config, &rec, &token))
        }
        .await,
    )
}

// ---------------------------------------------------------------------------
// GET/POST /s/folder/{token} + /s/folder/{token}/f/{fid} — public folder share (NO SSO)
// ---------------------------------------------------------------------------

/// `GET /s/folder/{token}` — the public index of a shared folder's files, WITHOUT SSO. Honors the same
/// lifecycle as a file share: revoked/unknown token -> 404, expired -> 410, password-protected ->
/// a password prompt (no listing). The owner comes from the folder row, never the request.
pub async fn share_folder(State(state): State<AppState>, Path(token): Path<String>) -> Response {
    share_room_response(
        async move {
            let folder = load_shared_folder(&state, &token).await?;
            if folder.share_has_password() {
                return Ok(render_share_prompt(
                    &format!("/s/folder/{token}"),
                    StatusCode::OK,
                    None,
                    "folder",
                    folder.expires_at,
                    "Open shared folder",
                ));
            }
            let files = state
                .store
                .list_files_in_folder(&folder.id, &folder.owner_sub)
                .await?;
            emit_folder_share_audit(&state, &folder);
            Ok(render_folder_index(&folder, &files, &token, None))
        }
        .await,
    )
}

/// `POST /s/folder/{token}` — verify a protected folder's password and, on success, render the index with
/// per-file download FORMS that carry the just-entered password (so downloads stay gated). Wrong
/// password re-prompts (401). Same 404/410 lifecycle as the GET.
pub async fn share_folder_unlock(
    State(state): State<AppState>,
    Path(token): Path<String>,
    Form(form): Form<SharePasswordForm>,
) -> Response {
    share_room_response(
        async move {
            let folder = load_shared_folder(&state, &token).await?;
            let unlocked = match &folder.share_password_hash {
                Some(hash) => auth::verify_share_password(hash, &form.password),
                None => true,
            };
            if !unlocked {
                return Ok(render_share_prompt(
                    &format!("/s/folder/{token}"),
                    StatusCode::UNAUTHORIZED,
                    Some("Incorrect password."),
                    "folder",
                    folder.expires_at,
                    "Open shared folder",
                ));
            }
            let files = state
                .store
                .list_files_in_folder(&folder.id, &folder.owner_sub)
                .await?;
            emit_folder_share_audit(&state, &folder);
            // Non-password folders never reach this branch with a value; carry the password only when set.
            let pw = folder
                .share_has_password()
                .then_some(form.password.as_str());
            Ok(render_folder_index(&folder, &files, &token, pw))
        }
        .await,
    )
}

/// `GET /s/folder/{token}/f/{fid}` — download one file listed under a NON-password folder share. A
/// password-protected folder can't authorize a bare GET, so it re-prompts; those downloads go
/// through the POST form instead.
pub async fn share_folder_file(
    State(state): State<AppState>,
    Path((token, fid)): Path<(String, String)>,
) -> Response {
    share_room_response(
        async move {
            let folder = load_shared_folder(&state, &token).await?;
            if folder.share_has_password() {
                return Ok(render_share_prompt(
                    &format!("/s/folder/{token}"),
                    StatusCode::UNAUTHORIZED,
                    Some("Enter the folder password to download."),
                    "folder",
                    folder.expires_at,
                    "Open shared folder",
                ));
            }
            let file = shared_folder_file(&state, &folder, &fid).await?;
            let bytes = state.blobs.get(&file.object_key).await?;
            Ok(serve_blob(&file, bytes))
        }
        .await,
    )
}

/// `POST /s/folder/{token}/f/{fid}` — download one file under a PASSWORD-protected folder share, gated by
/// the folder password submitted with the form. Wrong password re-prompts (401).
pub async fn share_folder_file_unlock(
    State(state): State<AppState>,
    Path((token, fid)): Path<(String, String)>,
    Form(form): Form<SharePasswordForm>,
) -> Response {
    share_room_response(
        async move {
            let folder = load_shared_folder(&state, &token).await?;
            if let Some(hash) = &folder.share_password_hash {
                if !auth::verify_share_password(hash, &form.password) {
                    return Ok(render_share_prompt(
                        &format!("/s/folder/{token}"),
                        StatusCode::UNAUTHORIZED,
                        Some("Incorrect password."),
                        "folder",
                        folder.expires_at,
                        "Open shared folder",
                    ));
                }
            }
            let file = shared_folder_file(&state, &folder, &fid).await?;
            let bytes = state.blobs.get(&file.object_key).await?;
            Ok(serve_blob(&file, bytes))
        }
        .await,
    )
}

// ---------------------------------------------------------------------------
// GET/POST /u/{token} — public upload inbox (NO SSO)
// ---------------------------------------------------------------------------

/// `GET /u/{token}` — render an anonymous upload form for a folder upload inbox. It never lists
/// existing files. A CSRF cookie is minted once, then reused across reloads and tabs because the
/// POST changes server state and a rotating double-submit cookie would invalidate sibling tabs.
pub async fn upload_inbox(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    share_room_response(upload_inbox_inner(state, headers, token).await)
}

async fn upload_inbox_inner(
    state: AppState,
    headers: HeaderMap,
    token: String,
) -> Result<Response, AppError> {
    let request = load_upload_request(&state, &token).await?;
    let csrf = auth::existing_or_new_csrf_token(&headers);
    let html = render_upload_inbox(&state.config, &request, &token, &csrf, None);
    Ok(share_room_html_with_csrf(StatusCode::OK, html, &csrf))
}

/// `POST /u/{token}` — anonymous upload into the token's folder. The visitor cannot choose owner
/// or folder; both come from the token row.
pub async fn upload_inbox_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
    multipart: Result<Multipart, MultipartRejection>,
) -> Response {
    let result = match multipart {
        Ok(multipart) => upload_inbox_submit_inner(state, headers, token, multipart).await,
        Err(rejection) => {
            tracing::warn!(reason = %rejection, "public upload multipart rejected");
            Err(AppError::BadRequest(
                "invalid public upload multipart envelope".to_string(),
            ))
        }
    };
    share_room_response(result)
}

async fn upload_inbox_submit_inner(
    state: AppState,
    headers: HeaderMap,
    token: String,
    mut multipart: Multipart,
) -> Result<Response, AppError> {
    let request = load_upload_request(&state, &token).await?;
    // A request whose private destination disappeared is unusable. Keep the public response
    // indistinguishable from an invalid/revoked capability.
    state
        .store
        .get_folder(&request.folder_id, &request.owner_sub)
        .await?
        .ok_or_else(|| AppError::NotFound("The upload destination is unavailable.".to_string()))?;
    let mut csrf_field = String::new();
    let mut file: Option<(String, String, Vec<u8>)> = None;

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

    let verified_content_type = sniff_verified_upload_type(&bytes);
    let content_type_verified = verified_content_type.is_some();
    let content_type = verified_content_type
        .map(str::to_string)
        .unwrap_or_else(|| resolve_content_type(&bytes, &client_type));
    let size = bytes.len() as i64;
    let owner_quota = effective_quota(
        state.store.get_quota(&request.owner_sub).await?,
        state.config.default_quota_bytes,
    );
    let unique_name =
        unique_upload_name(&state, &request.owner_sub, &request.folder_id, &name).await?;
    let now = now_secs();
    let mut rec = FileRec {
        id: String::new(),
        owner_sub: request.owner_sub.clone(),
        name: unique_name,
        content_type,
        size,
        bucket: state.blobs.bucket().to_string(),
        object_key: String::new(),
        // Files received from an anonymous request are private until the owner explicitly shares
        // them. Possession of an upload capability never creates a read capability.
        share_token: None,
        created_at: now,
        updated_at: now,
        expires_at: None,
        share_password_hash: None,
        folder_id: Some(request.folder_id.clone()),
        trashed_at: 0,
        trash_entry_id: None,
        trash_ancestor_id: None,
        view_count: 0,
    };

    // Claim request budget + global owner quota in one Store operation BEFORE touching Cairn. The
    // Postgres implementation locks both the request and an owner guard row, so concurrent uploads
    // (even via different rooms) cannot pass on the same remaining bytes.
    let mut reserved = false;
    for _ in 0..6 {
        rec.id = random_alnum(FILE_ID_LEN);
        rec.object_key = rec.id.clone();
        match state
            .store
            .reserve_request_upload(UploadReserveInput {
                request_id: &request.id,
                expected_token: &token,
                reservation_id: &rec.id,
                size,
                content_type: &rec.content_type,
                content_type_verified,
                owner_quota,
                now,
            })
            .await?
        {
            UploadReserve::Reserved => {
                reserved = true;
                break;
            }
            UploadReserve::Collision => continue,
            UploadReserve::Unavailable => {
                return Err(AppError::Gone(
                    "This upload request is closed or expired.".to_string(),
                ))
            }
            UploadReserve::TypeDenied => {
                return Err(AppError::BadRequest(
                    "This file type is not accepted by the upload request.".to_string(),
                ))
            }
            UploadReserve::FileTooLarge
            | UploadReserve::TotalBudgetExceeded
            | UploadReserve::FileCountExceeded
            | UploadReserve::OwnerQuotaExceeded => {
                state.audit.emit(AuditEvent::warning(
                    "upload_request.budget.reject",
                    &request.owner_sub,
                    &request.id,
                    "public upload budget rejected",
                ));
                return Err(AppError::QuotaExceeded(
                    "upload request budget unavailable".to_string(),
                ));
            }
        }
    }
    if !reserved {
        return Err(AppError::Internal(
            "could not allocate a unique file id".to_string(),
        ));
    }
    if let Err(e) = state.blobs.put(&rec.object_key, bytes).await {
        // `put` may have failed after a partial backend write. Delete is idempotent, then release
        // the database reservation. If deletion fails, retain the durable reservation: startup
        // recovery still knows the object key and can retry without losing the cleanup anchor.
        compensate_failed_request_upload(&state, &rec.object_key, &rec.id).await;
        return Err(e.into());
    }

    let mut committed = false;
    for _ in 0..6 {
        let submission = UploadSubmission {
            id: random_alnum(SUBMISSION_ID_LEN),
            request_id: request.id.clone(),
            file_id: rec.id.clone(),
            name: rec.name.clone(),
            content_type: rec.content_type.clone(),
            size: rec.size,
            created_at: now,
        };
        match state
            .store
            .commit_request_upload(&rec.id, &rec, &submission)
            .await
        {
            Ok(true) => {
                committed = true;
                break;
            }
            Ok(false) => continue,
            Err(error) => {
                compensate_failed_request_upload(&state, &rec.object_key, &rec.id).await;
                return Err(error.into());
            }
        }
    }
    if !committed {
        compensate_failed_request_upload(&state, &rec.object_key, &rec.id).await;
        return Err(AppError::Internal(
            "could not commit public upload receipt".to_string(),
        ));
    }

    tracing::info!(
        id = rec.id,
        owner = request.owner_sub,
        request = request.id,
        size,
        "public upload accepted"
    );
    state.audit.emit(AuditEvent::info(
        "upload_request.file",
        &request.owner_sub,
        &request.id,
        "file",
    ));
    let status = Some(format!("Uploaded {}.", rec.name));
    let html = render_upload_inbox(
        &state.config,
        &request,
        &token,
        &csrf_field,
        status.as_deref(),
    );
    Ok(share_room_html_with_csrf(StatusCode::OK, html, &csrf_field))
}

/// Compensate an upload that reserved database capacity but did not commit metadata. Cairn bytes
/// are always removed first. Only a confirmed idempotent delete permits releasing the reservation;
/// otherwise the row remains the durable object-key recovery anchor for a later startup.
async fn compensate_failed_request_upload(
    state: &AppState,
    object_key: &str,
    reservation_id: &str,
) {
    if let Err(error) = state.blobs.delete(object_key).await {
        tracing::error!(
            reservation = reservation_id,
            object_key,
            error = %error,
            "public upload compensation kept reservation after blob delete failure"
        );
        return;
    }
    match state.store.release_request_upload(reservation_id).await {
        Ok(true) => {}
        Ok(false) => tracing::warn!(
            reservation = reservation_id,
            "public upload compensation could not release reservation; recovery retains authority"
        ),
        Err(error) => tracing::error!(
            reservation = reservation_id,
            error = %error,
            "public upload compensation kept reservation after release failure"
        ),
    }
}

/// Load a folder by its public share token, enforcing the lifecycle (missing/revoked -> 404,
/// expired -> 410 Gone). No request identity is consulted.
async fn load_shared_folder(state: &AppState, token: &str) -> Result<FolderRec, AppError> {
    let folder = state
        .store
        .get_folder_by_token(token)
        .await?
        .ok_or_else(|| {
            AppError::NotFound("This share link is invalid or has been removed.".to_string())
        })?;
    if folder.share_expired(now_secs()) {
        return Err(AppError::Gone(
            "This share link has expired and is no longer available.".to_string(),
        ));
    }
    Ok(folder)
}

/// Load an independent upload request by capability token. Missing/rotated tokens are
/// indistinguishable; closed and expired requests return 410 without leaking their destination.
async fn load_upload_request(state: &AppState, token: &str) -> Result<UploadRequestRec, AppError> {
    let request = state
        .store
        .get_upload_request_by_token(token)
        .await?
        .ok_or_else(|| {
            AppError::NotFound("This upload link is invalid or has been removed.".to_string())
        })?;
    if !request.is_open() || request.is_expired(now_secs()) {
        return Err(AppError::Gone(
            "This upload request is closed or expired.".to_string(),
        ));
    }
    state
        .store
        .get_folder(&request.folder_id, &request.owner_sub)
        .await?
        .ok_or_else(|| {
            AppError::NotFound("This upload link is invalid or has been removed.".to_string())
        })?;
    Ok(request)
}

fn render_upload_inbox(
    config: &Config,
    request: &UploadRequestRec,
    token: &str,
    csrf: &str,
    status: Option<&str>,
) -> String {
    let status_html = match status {
        Some(msg) => format!("<p class=\"sr-status\" role=\"status\">{}</p>", esc(msg)),
        None => String::new(),
    };
    let accept = if request.allowed_types == "*/*" {
        String::new()
    } else {
        format!(" accept=\"{}\"", esc(&request.allowed_types))
    };
    UPLOAD_INBOX_HTML
        .replace("{{HEADING}}", &esc(&request.title))
        .replace(
            "{{DESCRIPTION}}",
            &esc(if request.description.is_empty() {
                "Send the requested files directly to this private upload room."
            } else {
                &request.description
            }),
        )
        .replace(
            "{{MAX_UPLOAD}}",
            &esc(&human_size(
                request.max_file_bytes.min(config.max_upload as i64),
            )),
        )
        .replace(
            "{{REMAINING_FILES}}",
            &(request.max_files - request.used_files).max(0).to_string(),
        )
        .replace(
            "{{REMAINING_BYTES}}",
            &esc(&human_size(
                (request.max_total_bytes - request.used_bytes).max(0),
            )),
        )
        .replace("{{ALLOWED_TYPES}}", &esc(&request.allowed_types))
        .replace("{{ACCEPT}}", &accept)
        .replace("{{STATUS}}", &status_html)
        .replace("{{ACTION}}", &format!("/u/{}", esc(token)))
        .replace("{{CSRF}}", &esc(csrf))
}

async fn unique_upload_name(
    state: &AppState,
    owner_sub: &str,
    folder_id: &str,
    desired: &str,
) -> Result<String, AppError> {
    let base = desired.chars().take(MAX_NAME_CHARS).collect::<String>();
    if state
        .store
        .find_file_in_folder(owner_sub, &base, Some(folder_id))
        .await?
        .is_none()
    {
        return Ok(base);
    }
    let (stem, ext) = split_name_ext(&base);
    for n in 2..100 {
        let candidate = if ext.is_empty() {
            format!("{stem} ({n})")
        } else {
            format!("{stem} ({n}).{ext}")
        };
        let capped: String = candidate.chars().take(MAX_NAME_CHARS).collect();
        if state
            .store
            .find_file_in_folder(owner_sub, &capped, Some(folder_id))
            .await?
            .is_none()
        {
            return Ok(capped);
        }
    }
    let suffix = random_alnum(6);
    let candidate = if ext.is_empty() {
        format!("{stem} {suffix}")
    } else {
        format!("{stem} {suffix}.{ext}")
    };
    Ok(candidate.chars().take(MAX_NAME_CHARS).collect())
}

fn split_name_ext(name: &str) -> (String, String) {
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() => {
            (stem.to_string(), ext.to_string())
        }
        _ => (name.to_string(), String::new()),
    }
}

/// Resolve one file requested under a folder share: it MUST belong to the shared folder (same
/// `folder_id`) AND the folder's owner, so a folder token can never fetch an unrelated file.
async fn shared_folder_file(
    state: &AppState,
    folder: &FolderRec,
    file_id: &str,
) -> Result<FileRec, AppError> {
    let file = state
        .store
        .get(file_id)
        .await?
        .filter(|f| {
            f.owner_sub == folder.owner_sub
                && f.is_effectively_live()
                && f.folder_id.as_deref() == Some(&folder.id)
        })
        .ok_or_else(|| AppError::NotFound("No such file in this shared folder.".to_string()))?;
    Ok(file)
}

/// Attribute a public folder-share view to the folder's owner (no request identity on this route).
fn emit_folder_share_audit(state: &AppState, folder: &FolderRec) {
    state.audit.emit(AuditEvent::info(
        "folder.share.view",
        &folder.owner_sub,
        &folder.id,
        "folder",
    ));
}

/// Render the public folder-share index page: a simple list of the folder's files with a download
/// control each. `unlock_password` (`Some` only for a password-protected folder) is embedded in
/// per-file POST forms so downloads stay password-gated; `None` renders plain GET download links.
/// Every remote string is HTML-escaped.
fn render_folder_index(
    folder: &FolderRec,
    files: &[FileRec],
    token: &str,
    unlock_password: Option<&str>,
) -> Response {
    let rows = if files.is_empty() {
        "<li class=\"sr-empty\">This shared folder is empty.</li>".to_string()
    } else {
        files
            .iter()
            .map(|f| {
                let download = match unlock_password {
                    Some(pw) => format!(
                        "<form method=\"post\" action=\"/s/folder/{token}/f/{fid}\">\
                           <input type=\"hidden\" name=\"password\" value=\"{pw}\">\
                           <button class=\"sr-button sr-button--small\" type=\"submit\">Download</button>\
                         </form>",
                        token = esc(token),
                        fid = esc(&f.id),
                        pw = esc(pw),
                    ),
                    None => format!(
                        "<a class=\"sr-button sr-button--small\" href=\"/s/folder/{token}/f/{fid}\">Download</a>",
                        token = esc(token),
                        fid = esc(&f.id),
                    ),
                };
                // Existing unprotected image downloads are already safe inline endpoints. Reuse
                // exactly that authority for a product-native quick preview; protected folders keep
                // their POST-only download flow and intentionally do not expose a preview URL.
                let preview = if unlock_password.is_none() && f.is_image() {
                    let src = format!("/s/folder/{token}/f/{}", f.id);
                    format!(
                        "<button class=\"sr-button sr-button--small\" type=\"button\" data-share-preview=\"{src}\" data-share-preview-name=\"{name}\">Preview</button>",
                        src = esc(&src),
                        name = esc(&f.name),
                    )
                } else {
                    String::new()
                };
                format!(
                    "<li class=\"sr-file-row\">\
                       <span class=\"sr-file-row__icon\" aria-hidden=\"true\">{ext}</span>\
                       <div>\
                         <span class=\"sr-file-row__name\" title=\"{name}\">{name}</span>\
                         <span class=\"sr-file-row__meta\">{ctype} · {size}</span>\
                       </div>\
                       <div class=\"sr-file-row__actions\">{preview}{download}</div>\
                     </li>",
                    ext = esc(&ext_label(&f.name)),
                    name = esc(&f.name),
                    ctype = esc(&f.content_type),
                    size = esc(&human_size(f.size)),
                    preview = preview,
                    download = download,
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let count = match files.len() {
        1 => "1 file".to_string(),
        n => format!("{n} files"),
    };
    let html = SHARE_FOLDER_HTML
        .replace("{{HEADING}}", &esc(&folder.name))
        .replace("{{COUNT}}", &esc(&count))
        .replace(
            "{{ACCESS_STATE}}",
            if unlock_password.is_some() {
                "Password verified"
            } else {
                "Link access"
            },
        )
        .replace("{{EXPIRY}}", &esc(&share_expiry_label(folder.expires_at)))
        .replace("{{FILES}}", &rows);
    share_room_html(StatusCode::OK, html)
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

/// New-folder form: a display name + the parent level (empty = a root folder). CSRF-checked.
#[derive(Debug, Deserialize)]
pub struct FolderCreateForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub name: String,
    /// The folder currently being viewed; the new folder is created as its child. Blank = root.
    #[serde(default)]
    pub parent_id: String,
}

/// Folder-delete form: CSRF + an optional `cascade` flag. Without it the delete succeeds only when
/// the folder is empty; with `cascade=1` the whole subtree (subfolders + files) is removed.
#[derive(Debug, Deserialize)]
pub struct FolderDeleteForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub cascade: String,
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

    // The parent (current level) must be one of the owner's folders, else the folder is a root.
    let parent_id: Option<String> = match form.parent_id.trim() {
        "" => None,
        pid => {
            if state.store.get_folder(pid, &actor.subject).await?.is_none() {
                return Err(AppError::NotFound("No such folder.".to_string()));
            }
            Some(pid.to_string())
        }
    };

    let now = now_secs();
    let mut rec = FolderRec {
        id: String::new(),
        owner_sub: actor.subject.clone(),
        parent_id,
        name,
        created_at: now,
        updated_at: now,
        // A fresh folder has no public share link until the owner creates one.
        share_token: None,
        expires_at: None,
        share_password_hash: None,
        upload_token: None,
        trashed_at: 0,
        trash_entry_id: None,
        trash_ancestor_id: None,
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
    state.audit.emit(AuditEvent::notice(
        "folder.create",
        &actor.subject,
        &rec.id,
        "folder",
    ));
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
    if !state
        .store
        .rename_folder(&id, &actor.subject, &name)
        .await?
    {
        return Err(AppError::NotFound("No such folder.".to_string()));
    }
    tracing::info!(id, owner = actor.subject, "folder renamed");
    state.audit.emit(AuditEvent::notice(
        "folder.rename",
        &actor.subject,
        &id,
        "folder",
    ));
    Ok(redirect_found(&format!("/?folder={id}")))
}

/// `POST /folders/{id}/delete` — compatibility alias that now moves an owner's whole folder
/// subtree to Trash. The historical `cascade` field is accepted but no longer bypasses recovery;
/// permanent deletion exists only on the explicit Trash surface.
pub async fn delete_folder(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<FolderDeleteForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let actor = auth::identity(&headers);
    // Capture the parent BEFORE deleting so we can land the redirect at the right level.
    let folder = state
        .store
        .get_folder(&id, &actor.subject)
        .await?
        .ok_or_else(|| AppError::NotFound("No such folder.".to_string()))?;
    let up = match &folder.parent_id {
        Some(pid) => format!("/?folder={pid}"),
        None => "/".to_string(),
    };

    let _legacy_cascade = &form.cascade;
    let now = now_secs();
    require_bulk_applied(
        state
            .store
            .bulk_trash(
                &actor.subject,
                &[TrashRootInput {
                    item: DriveItemRef {
                        kind: LibraryItemKind::Folder,
                        id: id.clone(),
                    },
                    entry_id: random_alnum(TRASH_ENTRY_ID_LEN),
                }],
                now,
                now.saturating_add(TRASH_RETENTION_SECS),
            )
            .await?,
    )?;
    tracing::info!(id, owner = actor.subject, "folder moved to trash");
    state.audit.emit(AuditEvent::notice(
        "folder.trash",
        &actor.subject,
        &id,
        "folder subtree",
    ));
    Ok(redirect_found(&up))
}

// ---------------------------------------------------------------------------
// Folder share links: configure / revoke (owner-only)
// ---------------------------------------------------------------------------

/// `POST /folders/{id}/share` — (re)enable / update a folder's PUBLIC share link: set its expiry +
/// optional password, minting a fresh token when the link had been revoked. CSRF-checked,
/// owner-scoped, then 302 back to the folder. Mirrors [`configure_share`] for files.
pub async fn configure_folder_share(
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
    let folder = state
        .store
        .get_folder(&id, &actor.subject)
        .await?
        .ok_or_else(|| AppError::NotFound("No such folder.".to_string()))?;

    let expires_at = parse_expiry(&form.expiry, now_secs());
    let password = form.password.trim();
    let password_hash = if password.is_empty() {
        None
    } else {
        let capped: String = password.chars().take(MAX_PASSWORD_CHARS).collect();
        Some(auth::hash_share_password(&capped))
    };
    let token = folder
        .share_token
        .clone()
        .unwrap_or_else(|| random_alnum(SHARE_TOKEN_LEN));

    state
        .store
        .configure_folder_share(&id, &actor.subject, Some(token), expires_at, password_hash)
        .await?;
    tracing::info!(id, owner = actor.subject, "folder share link configured");
    state.audit.emit(AuditEvent::notice(
        "folder.share.update",
        &actor.subject,
        &id,
        "folder",
    ));
    Ok(redirect_found(&format!("/?folder={id}")))
}

/// `POST /folders/{id}/revoke` — revoke a folder's public share link (clears token + expiry +
/// password). CSRF-checked, owner-scoped, then 302 back to the folder.
pub async fn revoke_folder_share(
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
    if !state
        .store
        .configure_folder_share(&id, &actor.subject, None, None, None)
        .await?
    {
        return Err(AppError::NotFound("No such folder.".to_string()));
    }
    tracing::info!(id, owner = actor.subject, "folder share link revoked");
    state.audit.emit(AuditEvent::notice(
        "folder.share.revoke",
        &actor.subject,
        &id,
        "folder",
    ));
    Ok(redirect_found(&format!("/?folder={id}")))
}

/// `POST /folders/{id}/upload` — enable/rotate a folder's public upload-inbox token. Anonymous
/// visitors can upload into the folder at `/u/{token}` but cannot list or download its files.
pub async fn configure_folder_upload(
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
    let folder = state
        .store
        .get_folder(&id, &actor.subject)
        .await?
        .ok_or_else(|| AppError::NotFound("No such folder.".to_string()))?;
    let token = folder
        .upload_token
        .clone()
        .unwrap_or_else(|| random_alnum(UPLOAD_TOKEN_LEN));
    state
        .store
        .configure_folder_upload(&id, &actor.subject, Some(token))
        .await?;
    let token = state
        .store
        .get_folder(&id, &actor.subject)
        .await?
        .and_then(|folder| folder.upload_token)
        .ok_or_else(|| AppError::Internal("upload token was not persisted".to_string()))?;
    if state
        .store
        .get_upload_request_by_token(&token)
        .await?
        .is_none()
    {
        let now = now_secs();
        let mut request = UploadRequestRec {
            id: String::new(),
            owner_sub: actor.subject.clone(),
            folder_id: id.clone(),
            token,
            title: format!("{} uploads", folder.name),
            description: String::new(),
            status: "open".to_string(),
            expires_at: Some(now.saturating_add(7 * 24 * 60 * 60)),
            max_file_bytes: DEFAULT_REQUEST_MAX_FILE_BYTES.min(state.config.max_upload as i64),
            max_total_bytes: DEFAULT_REQUEST_MAX_TOTAL_BYTES,
            max_files: DEFAULT_REQUEST_MAX_FILES,
            used_bytes: 0,
            used_files: 0,
            allowed_types: DEFAULT_REQUEST_ALLOWED_TYPES.to_string(),
            created_at: now,
            updated_at: now,
        };
        let mut created = false;
        for _ in 0..6 {
            request.id = random_alnum(12);
            if state.store.create_upload_request(&request).await? {
                created = true;
                break;
            }
        }
        if !created {
            return Err(AppError::Internal(
                "could not create upload request".to_string(),
            ));
        }
    }
    // The independent request row is authoritative. Clear the deprecated folder column so future
    // migrations cannot resurrect this pre-rotation token.
    state
        .store
        .configure_folder_upload(&id, &actor.subject, None)
        .await?;
    tracing::info!(id, owner = actor.subject, "folder upload inbox configured");
    state.audit.emit(AuditEvent::notice(
        "folder.upload_inbox.update",
        &actor.subject,
        &id,
        "folder",
    ));
    Ok(redirect_found(&format!("/?folder={id}")))
}

/// `POST /folders/{id}/upload/revoke` — revoke a folder's public upload-inbox token.
pub async fn revoke_folder_upload(
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
    let folder = state
        .store
        .get_folder(&id, &actor.subject)
        .await?
        .ok_or_else(|| AppError::NotFound("No such folder.".to_string()))?;
    if !state
        .store
        .configure_folder_upload(&id, &actor.subject, None)
        .await?
    {
        return Err(AppError::NotFound("No such folder.".to_string()));
    }
    if let Some(token) = folder.upload_token {
        if let Some(request) = state.store.get_upload_request_by_token(&token).await? {
            let _ = state
                .store
                .set_upload_request_status(&request.id, &actor.subject, "closed", now_secs())
                .await?;
        }
    }
    // Once migrated, `folders.upload_token` is intentionally NULL. Preserve the legacy revoke
    // route by closing every independent request targeting this folder.
    for request in state.store.list_upload_requests(&actor.subject).await? {
        if request.folder_id == id && request.is_open() {
            let _ = state
                .store
                .set_upload_request_status(&request.id, &actor.subject, "closed", now_secs())
                .await?;
        }
    }
    tracing::info!(id, owner = actor.subject, "folder upload inbox revoked");
    state.audit.emit(AuditEvent::notice(
        "folder.upload_inbox.revoke",
        &actor.subject,
        &id,
        "folder",
    ));
    Ok(redirect_found(&format!("/?folder={id}")))
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

fn clean_comment_body(raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AppError::BadRequest("Enter a comment.".to_string()));
    }
    Ok(trimmed.chars().take(MAX_COMMENT_CHARS).collect())
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
async fn serve_shared(
    state: &AppState,
    rec: &FileRec,
    headers: &HeaderMap,
) -> Result<Response, AppError> {
    let response = serve_file(state, rec, headers).await?;
    // Public share fetch: no gateway identity on this route, so the affected file's owner is the
    // subject the event is attributed to.
    state.audit.emit(AuditEvent::info(
        "file.share",
        &rec.owner_sub,
        &rec.id,
        if rec.is_image() { "image" } else { "file" },
    ));
    Ok(response)
}

/// Render the public share-link password prompt (`status` = 200 on first ask, 401 after a wrong
/// password). `action` is the form POST target (`/s/{token}` for a file, `/s/folder/{token}` for a
/// folder). `error` is an optional inline message.
fn render_share_prompt(
    action: &str,
    status: StatusCode,
    error: Option<&str>,
    kind: &str,
    expires_at: Option<i64>,
    action_label: &str,
) -> Response {
    let error_html = match error {
        Some(msg) => format!("<p class=\"sr-alert\" role=\"alert\">{}</p>", esc(msg)),
        None => String::new(),
    };
    let html = SHARE_PW_HTML
        .replace("{{ERROR}}", &error_html)
        .replace("{{ACTION}}", &esc(action))
        .replace("{{KIND}}", &esc(kind))
        .replace("{{EXPIRY}}", &esc(&share_expiry_label(expires_at)))
        .replace("{{ACTION_LABEL}}", &esc(action_label));
    share_room_html(status, html)
}

fn render_share_landing(config: &Config, rec: &FileRec, token: &str) -> Response {
    let direct_url = format!("{}/s/{}", config.public_base, token);
    let page_url = format!("{}/s/{}/view", config.public_base, token);
    let description = format!(
        "{} · {} · {} views",
        rec.content_type,
        human_size(rec.size),
        rec.view_count
    );
    let twitter_card = if rec.is_image() {
        "summary_large_image"
    } else {
        "summary"
    };
    let mut og_meta = format!(
        "<meta property=\"og:title\" content=\"{title}\">\
         <meta property=\"og:description\" content=\"{description}\">\
         <meta property=\"og:url\" content=\"{page_url}\">\
         <meta name=\"twitter:card\" content=\"{twitter_card}\">\
         <meta name=\"twitter:title\" content=\"{title}\">\
         <meta name=\"twitter:description\" content=\"{description}\">",
        title = esc(&rec.name),
        description = esc(&description),
        page_url = esc(&page_url),
        twitter_card = twitter_card,
    );
    if rec.is_image() {
        og_meta.push_str(&format!(
            "<meta property=\"og:image\" content=\"{direct_url}\">\
             <meta name=\"twitter:image\" content=\"{direct_url}\">",
            direct_url = esc(&direct_url),
        ));
    }

    let preview = if rec.is_image() {
        format!(
            "<img src=\"/s/{token}\" alt=\"{name}\">",
            token = esc(token),
            name = esc(&rec.name),
        )
    } else {
        format!(
            "<div class=\"sr-file-art\">{}</div>",
            render_type_thumb(&rec.content_type, &rec.name)
        )
    };

    let html = SHARE_LANDING_HTML
        .replace("{{NAME}}", &esc(&rec.name))
        .replace("{{OG_META}}", &og_meta)
        .replace("{{PREVIEW}}", &preview)
        .replace("{{TYPE}}", &esc(&rec.content_type))
        .replace("{{SIZE}}", &esc(&human_size(rec.size)))
        .replace("{{VIEWS}}", &rec.view_count.to_string())
        .replace("{{EXPIRY}}", &esc(&share_expiry_label(rec.expires_at)))
        .replace("{{DOWNLOAD_URL}}", &format!("/s/{}", esc(token)))
        .replace("{{EMBED}}", &render_embed_codes(config, rec));
    share_room_html(StatusCode::OK, html)
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
    if !rec.is_effectively_live() {
        return Err(AppError::NotFound(
            "No file exists at that link.".to_string(),
        ));
    }
    Ok(rec)
}

/// Fetch an owner-scoped file that MUST currently be in Trash.
async fn owned_trashed_file(
    state: &AppState,
    id: &str,
    who: &Identity,
) -> Result<FileRec, AppError> {
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
    if rec.trashed_at == 0 || rec.trash_entry_id.is_none() || rec.trash_ancestor_id.is_some() {
        return Err(AppError::NotFound(
            "No trashed file exists at that link.".to_string(),
        ));
    }
    Ok(rec)
}

#[derive(Debug, PartialEq, Eq)]
enum RangeSpec {
    Full,
    Partial { start: u64, end: u64 },
    Unsatisfiable,
}

fn parse_range(range: Option<&str>, total: u64) -> RangeSpec {
    let Some(raw) = range.map(str::trim) else {
        return RangeSpec::Full;
    };
    let Some(spec) = raw.strip_prefix("bytes=") else {
        return RangeSpec::Full;
    };
    if spec.is_empty() || spec.contains(',') {
        return RangeSpec::Full;
    }

    if let Some(suffix) = spec.strip_prefix('-') {
        let Ok(wanted) = suffix.parse::<u64>() else {
            return RangeSpec::Full;
        };
        if wanted == 0 || total == 0 {
            return RangeSpec::Unsatisfiable;
        }
        let len = wanted.min(total);
        return RangeSpec::Partial {
            start: total - len,
            end: total - 1,
        };
    }

    let Some((start_raw, end_raw)) = spec.split_once('-') else {
        return RangeSpec::Full;
    };
    if start_raw.is_empty() {
        return RangeSpec::Full;
    }
    let Ok(start) = start_raw.parse::<u64>() else {
        return RangeSpec::Full;
    };
    let end = if end_raw.is_empty() {
        total.saturating_sub(1)
    } else {
        let Ok(end) = end_raw.parse::<u64>() else {
            return RangeSpec::Full;
        };
        end
    };
    if total == 0 || start >= total || start > end {
        return RangeSpec::Unsatisfiable;
    }
    RangeSpec::Partial {
        start,
        end: end.min(total - 1),
    }
}

fn blob_delivery_headers(rec: &FileRec) -> (String, String) {
    let filename = safe_filename(&rec.name);
    if rec.is_media() {
        (
            rec.content_type.clone(),
            format!("inline; filename=\"{filename}\""),
        )
    } else {
        (
            "application/octet-stream".to_string(),
            format!("attachment; filename=\"{filename}\""),
        )
    }
}

fn normalize_partial_bytes(bytes: Vec<u8>, start: u64, end: u64, total: u64) -> Vec<u8> {
    let expected_len = (end - start + 1) as usize;
    if bytes.len() == expected_len {
        return bytes;
    }

    let total_len = total as usize;
    let start_ix = start as usize;
    let end_ix = end as usize + 1;
    if bytes.len() == total_len && end_ix <= bytes.len() {
        return bytes[start_ix..end_ix].to_vec();
    }

    if bytes.len() > expected_len {
        let mut truncated = bytes;
        truncated.truncate(expected_len);
        return truncated;
    }
    bytes
}

/// Serve a current file blob with HTTP Range support. Image/video/audio are inline with their
/// resolved content type; everything else remains an octet-stream attachment.
async fn serve_file(
    state: &AppState,
    rec: &FileRec,
    headers: &HeaderMap,
) -> Result<Response, AppError> {
    let total = rec.size.max(0) as u64;
    let (ctype, disposition) = blob_delivery_headers(rec);
    let range = parse_range(
        headers.get(header::RANGE).and_then(|v| v.to_str().ok()),
        total,
    );

    match range {
        RangeSpec::Full => {
            let bytes = state.blobs.get(&rec.object_key).await?;
            Ok((
                [
                    (header::CONTENT_TYPE, ctype),
                    (header::CONTENT_DISPOSITION, disposition),
                    (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
                    (header::ACCEPT_RANGES, "bytes".to_string()),
                    (header::CONTENT_LENGTH, total.to_string()),
                ],
                bytes,
            )
                .into_response())
        }
        RangeSpec::Partial { start, end } => {
            let bytes = state.blobs.get_range(&rec.object_key, start, end).await?;
            let bytes = normalize_partial_bytes(bytes, start, end, total);
            Ok((
                StatusCode::PARTIAL_CONTENT,
                [
                    (header::CONTENT_TYPE, ctype),
                    (header::CONTENT_DISPOSITION, disposition),
                    (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
                    (header::ACCEPT_RANGES, "bytes".to_string()),
                    (
                        header::CONTENT_RANGE,
                        format!("bytes {start}-{end}/{total}"),
                    ),
                    (header::CONTENT_LENGTH, (end - start + 1).to_string()),
                ],
                bytes,
            )
                .into_response())
        }
        RangeSpec::Unsatisfiable => Ok((
            StatusCode::RANGE_NOT_SATISFIABLE,
            [
                (header::CONTENT_RANGE, format!("bytes */{total}")),
                (header::ACCEPT_RANGES, "bytes".to_string()),
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
                (header::CONTENT_LENGTH, "0".to_string()),
            ],
            Vec::<u8>::new(),
        )
            .into_response()),
    }
}

/// Serve raw blob bytes: inline for sniffed images, attachment otherwise; always `nosniff`.
fn serve_blob(rec: &FileRec, bytes: Vec<u8>) -> Response {
    let filename = safe_filename(&rec.name);
    let (ctype, disposition) = if rec.is_image() {
        (
            rec.content_type.clone(),
            format!("inline; filename=\"{filename}\""),
        )
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

/// Derived-blob key for a file's cached thumbnail, namespaced off the original object key. The `id`
/// alphabet is alphanumeric (never contains `.`), so the `.thumb` suffix can never collide with a
/// real file's object key.
fn thumb_object_key(object_key: &str) -> String {
    format!("{object_key}.thumb")
}

/// Serve the derived thumbnail for a non-image file, deriving + caching it on first request. The
/// thumbnail is a deterministic, mime-keyed SVG type-icon (server-generated, trusted content), so
/// its generation cost is paid at most once per file. A cache miss OR a backend read error both
/// simply regenerate — the thumbnail is always reproducible, so this never surfaces a 500.
async fn serve_thumb(state: &AppState, rec: &FileRec) -> Response {
    let key = thumb_object_key(&rec.object_key);
    let svg = match state.blobs.get(&key).await {
        Ok(bytes) => bytes,
        Err(_) => {
            let generated = render_type_thumb(&rec.content_type, &rec.name).into_bytes();
            let intent = OwnerBlobWriteIntent {
                object_key: key.clone(),
                owner_sub: rec.owner_sub.clone(),
                size: generated.len() as i64,
                kind: OWNER_WRITE_THUMBNAIL.to_string(),
                file_id: rec.id.clone(),
                folder_id: rec.folder_id.clone(),
                expected_object_key: Some(rec.object_key.clone()),
                created_at: now_secs(),
                attempts: 0,
            };
            if matches!(
                state.store.reserve_owner_blob_write(&intent, None).await,
                Ok(OwnerBlobCommit::Applied)
            ) {
                match state.blobs.put(&key, generated.clone()).await {
                    Ok(()) => {
                        if !matches!(
                            state
                                .store
                                .finalize_owner_thumbnail(
                                    &key,
                                    &rec.owner_sub,
                                    &rec.id,
                                    &rec.object_key,
                                )
                                .await,
                            Ok(OwnerBlobCommit::Applied)
                        ) {
                            tracing::warn!(
                                id = rec.id,
                                "thumbnail finalize lost its file CAS; cleanup intent retained"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(id = rec.id, error = %e, "thumbnail cache write failed; cleanup intent retained");
                    }
                }
            }
            generated
        }
    };
    serve_svg_thumb(svg)
}

/// Serve server-generated SVG thumbnail bytes: an image content type plus `nosniff` and a strict CSP
/// so the trusted placeholder can never execute as script, even if the URL is opened directly
/// (defense in depth — the estate never serves user-supplied SVG inline).
fn serve_svg_thumb(bytes: Vec<u8>) -> Response {
    (
        [
            (header::CONTENT_TYPE, "image/svg+xml".to_string()),
            (header::CONTENT_DISPOSITION, "inline".to_string()),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; style-src 'unsafe-inline'".to_string(),
            ),
        ],
        bytes,
    )
        .into_response()
}

/// Build a deterministic, mime-keyed SVG type-icon thumbnail for a non-image file: a category tint
/// behind the file's short uppercase extension label. Server-generated and fully escaped (the label
/// is the whitelisted [`ext_label`] output), so it is safe to serve as an image. "Keyed by mime"
/// gives each content-type category a stable accent, so the same file always yields the same icon.
fn render_type_thumb(content_type: &str, name: &str) -> String {
    let (tint, ink) = thumb_palette(content_type);
    let label = esc(&ext_label(name));
    format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 160 120\" width=\"160\" \
           height=\"120\" role=\"img\">\
           <rect width=\"160\" height=\"120\" fill=\"{tint}\"/>\
           <rect x=\"44\" y=\"32\" width=\"72\" height=\"56\" rx=\"9\" fill=\"#ffffff\" \
             fill-opacity=\"0.86\"/>\
           <text x=\"80\" y=\"62\" text-anchor=\"middle\" dominant-baseline=\"middle\" \
             font-family=\"system-ui,-apple-system,Segoe UI,Roboto,sans-serif\" font-size=\"22\" \
             font-weight=\"700\" fill=\"{ink}\">{label}</text>\
         </svg>",
        tint = tint,
        ink = ink,
        label = label,
    )
}

/// Map a content type to a `(background_tint, label_ink)` color pair for its type-icon thumbnail.
/// A fixed, trusted allow-list (never interpolated from user input), so no escaping is required.
fn thumb_palette(content_type: &str) -> (&'static str, &'static str) {
    let ct = content_type;
    if ct == "application/pdf" {
        ("#FEE2E2", "#B91C1C") // red — documents
    } else if ct.starts_with("image/") {
        ("#E0E7FF", "#4338CA") // indigo — non-raster images (e.g. svg), never downscaled here
    } else if ct.starts_with("audio/") {
        ("#DCFCE7", "#15803D") // green — audio
    } else if ct.starts_with("video/") {
        ("#F3E8FF", "#7E22CE") // purple — video
    } else if ct.starts_with("text/") {
        ("#E2E8F0", "#334155") // slate — text
    } else if ct.contains("zip")
        || ct.contains("tar")
        || ct.contains("gzip")
        || ct.contains("compress")
        || ct.contains("x-7z")
        || ct.contains("x-rar")
    {
        ("#FEF3C7", "#B45309") // amber — archives
    } else {
        ("#EEF2FF", "#4F46E5") // brand indigo — everything else
    }
}

fn ap_tone_class(content_type: &str) -> &'static str {
    let ct = content_type;
    if ct == "application/pdf" {
        "ap-tone-doc"
    } else if ct.starts_with("image/") {
        "ap-tone-img"
    } else if ct.starts_with("audio/") {
        "ap-tone-aud"
    } else if ct.starts_with("video/") {
        "ap-tone-vid"
    } else if ct.starts_with("text/") {
        "ap-tone-txt"
    } else if ct.contains("zip")
        || ct.contains("tar")
        || ct.contains("gzip")
        || ct.contains("compress")
        || ct.contains("x-7z")
        || ct.contains("x-rar")
    {
        "ap-tone-zip"
    } else {
        "ap-tone-bin"
    }
}

/// Wrap rendered HTML in a response that also (re)sets the CSRF cookie.
pub(crate) fn html_with_csrf(status: StatusCode, html: String, csrf: &str) -> Response {
    (
        status,
        [(header::SET_COOKIE, auth::csrf_cookie(csrf))],
        Html(html),
    )
        .into_response()
}

/// A `302 Found` redirect to `location` (the spec'd create/delete response code).
pub(crate) fn redirect_found(location: &str) -> Response {
    let mut response = StatusCode::FOUND.into_response();
    let location =
        HeaderValue::from_str(location).unwrap_or_else(|_| HeaderValue::from_static("/"));
    response.headers_mut().insert(header::LOCATION, location);
    response
}

/// Uppercase file extension label for the non-image card/preview glyph (e.g. `PDF`, `ZIP`).
fn ext_label(name: &str) -> String {
    name.rsplit_once('.')
        .map(|(_, ext)| ext)
        .filter(|ext| !ext.is_empty() && ext.len() <= 6 && ext.chars().all(|c| c.is_alphanumeric()))
        .map(|ext| ext.to_ascii_uppercase())
        .unwrap_or_else(|| "FILE".to_string())
}

/// The direct child folders of `parent` (`None` = the root level), owner list already name-ordered
/// by [`crate::store::Store::list_folders`] so this preserves that order.
fn folder_children<'a>(folders: &'a [FolderRec], parent: Option<&str>) -> Vec<&'a FolderRec> {
    folders
        .iter()
        .filter(|f| f.parent_id.as_deref() == parent)
        .collect()
}

/// The breadcrumb chain root→…→`folder` (inclusive), walking `parent_id` up. Depth-guarded so a
/// (never-created) cycle cannot loop. Returned root-first for rendering.
fn folder_chain(folders: &[FolderRec], folder: &FolderRec) -> Vec<FolderRec> {
    let mut chain = vec![folder.clone()];
    let mut cursor = folder.parent_id.clone();
    let mut guard = 0;
    while let Some(pid) = cursor {
        if guard >= MAX_TREE_DEPTH {
            break;
        }
        guard += 1;
        match folders.iter().find(|f| f.id == pid) {
            Some(p) => {
                cursor = p.parent_id.clone();
                chain.push(p.clone());
            }
            None => break,
        }
    }
    chain.reverse();
    chain
}

/// Render the folder breadcrumb: `My Drive › … › current`, each ancestor a link, the current node
/// plain text. Owner-scoped; every name escaped.
fn render_breadcrumb(chain: &[FolderRec]) -> String {
    let mut out = String::from("<nav class=\"breadcrumb\" aria-label=\"Folder path\">");
    if chain.is_empty() {
        out.push_str("<span class=\"breadcrumb__here\">My Drive</span>");
    } else {
        out.push_str("<a class=\"breadcrumb__crumb\" href=\"/\">My Drive</a>");
        for (i, f) in chain.iter().enumerate() {
            out.push_str("<span class=\"breadcrumb__sep\" aria-hidden=\"true\">&rsaquo;</span>");
            if i + 1 == chain.len() {
                out.push_str(&format!(
                    "<span class=\"breadcrumb__here\">{}</span>",
                    esc(&f.name)
                ));
            } else {
                out.push_str(&format!(
                    "<a class=\"breadcrumb__crumb\" href=\"/?folder={id}\">{name}</a>",
                    id = esc(&f.id),
                    name = esc(&f.name),
                ));
            }
        }
    }
    out.push_str("</nav>");
    out
}

/// Render the subfolder tiles for the current level (child folders + an "Up" tile when inside a
/// folder), prepended to the file grid. Each tile navigates into `/?folder={id}`.
fn render_folder_tiles(children: &[&FolderRec], up_href: Option<&str>) -> String {
    let mut out = String::new();
    if let Some(href) = up_href {
        out.push_str(&format!(
            "<li class=\"folder-tile file-card file-card--folder file-card--up\">\
               <a class=\"file-card__link\" href=\"{href}\">\
                 <span class=\"thumb thumb--folder\">{FOLDER_UP_SVG}</span>\
               </a>\
               <div class=\"file-card__body folder-tile__body\">\
                 <a class=\"file-card__name\" href=\"{href}\">Up one level</a>\
                 <span class=\"folder-tile__badge\">Parent</span>\
                 <span class=\"ap-folder-cue\" aria-hidden=\"true\">›</span>\
               </div>\
             </li>",
            href = esc(href),
            FOLDER_UP_SVG = FOLDER_UP_SVG,
        ));
    }
    for f in children {
        let href = format!("/?folder={}", f.id);
        let mut badges = String::new();
        if f.share_token.is_some() {
            badges.push_str("<span class=\"ap-badge ap-badge--link\" title=\"Folder link enabled\">Linked</span>");
        }
        if f.upload_token.is_some() {
            badges.push_str("<span class=\"ap-badge ap-badge--views\" title=\"Upload request enabled\">Inbox</span>");
        }
        out.push_str(&format!(
            "<li class=\"folder-tile file-card file-card--folder\">\
               <label class=\"ap-select\" title=\"Select {name}\"><span class=\"sr-only\">Select {name}</span><input type=\"checkbox\" name=\"item:folder:{id}\" value=\"1\" form=\"bulkSelection\" data-bulk-item></label>\
               <a class=\"file-card__link\" href=\"{href}\">\
                 <span class=\"thumb thumb--folder\">{FOLDER_SVG}</span>\
               </a>\
               <div class=\"file-card__body folder-tile__body\">\
                 <div class=\"ap-name-row\"><a class=\"file-card__name\" href=\"{href}\" title=\"{name}\">{name}</a><span class=\"ap-folder-cue\" aria-hidden=\"true\">›</span></div>\
                 <div class=\"file-card__meta\"><span class=\"folder-tile__badge\">Folder</span><span class=\"ap-badges\">{badges}</span></div>\
               </div>\
             </li>",
            href = esc(&href),
            id = esc(&f.id),
            name = esc(&f.name),
            badges = badges,
            FOLDER_SVG = FOLDER_SVG,
        ));
    }
    out
}

fn url_component(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    out
}

fn library_href(query: &LibraryQuery, before: Option<&LibraryCursor>) -> String {
    let mut params = Vec::new();
    if query.view != LibraryView::All {
        params.push(format!("view={}", query.view.slug()));
    }
    if let Some(value) = query.query.as_deref() {
        params.push(format!("q={}", url_component(value)));
    }
    if query.type_filter != LibraryType::All {
        params.push(format!("type={}", query.type_filter.slug()));
    }
    if let Some(cursor) = before {
        params.push(format!(
            "before={}_{}_{}",
            cursor.updated_at,
            cursor.kind.slug(),
            cursor.id
        ));
        params.push(format!("limit={}", clamp_page(query.limit)));
    }
    if params.is_empty() {
        "/".to_string()
    } else {
        format!("/?{}", params.join("&"))
    }
}

fn render_library_controls(query: &LibraryQuery) -> String {
    const TYPES: &[LibraryType] = &[
        LibraryType::All,
        LibraryType::Folder,
        LibraryType::Image,
        LibraryType::Video,
        LibraryType::Audio,
        LibraryType::Pdf,
        LibraryType::Document,
        LibraryType::Archive,
        LibraryType::Other,
    ];
    let options = TYPES
        .iter()
        .map(|value| {
            let selected = if *value == query.type_filter {
                " selected"
            } else {
                ""
            };
            format!(
                "<option value=\"{}\"{}>{}</option>",
                value.slug(),
                selected,
                value.label()
            )
        })
        .collect::<String>();
    let hidden_view = if query.view == LibraryView::All {
        String::new()
    } else {
        format!(
            "<input type=\"hidden\" name=\"view\" value=\"{}\">",
            query.view.slug()
        )
    };
    let clear = if query.query.is_some() || query.type_filter != LibraryType::All {
        let base = LibraryQuery {
            view: query.view,
            query: None,
            type_filter: LibraryType::All,
            before: None,
            limit: query.limit,
        };
        format!(
            "<a class=\"btn btn-ghost btn-sm\" href=\"{}\">Clear</a>",
            esc(&library_href(&base, None))
        )
    } else {
        String::new()
    };
    format!(
        "<form class=\"ap-library-search\" method=\"get\" action=\"/\" role=\"search\">\
           {hidden_view}\
           <label class=\"sr-only\" for=\"libraryQuery\">Search file and folder names</label>\
           <div class=\"ap-library-search__field\">\
             <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" aria-hidden=\"true\"><circle cx=\"11\" cy=\"11\" r=\"7\"/><path d=\"m20 20-4-4\"/></svg>\
             <input id=\"libraryQuery\" type=\"search\" name=\"q\" value=\"{value}\" maxlength=\"{max}\" placeholder=\"Search names across your drive\">\
           </div>\
           <label class=\"sr-only\" for=\"libraryType\">File type</label>\
           <select id=\"libraryType\" name=\"type\">{options}</select>\
           <button class=\"btn btn-primary btn-sm\" type=\"submit\">Search</button>\
           {clear}\
         </form>",
        hidden_view = hidden_view,
        value = esc(query.query.as_deref().unwrap_or_default()),
        max = MAX_LIBRARY_QUERY_CHARS,
        options = options,
        clear = clear,
    )
}

fn render_library_badges(item: &LibraryItem) -> String {
    if !item.shared {
        return "<span class=\"ap-badges\"></span>".to_string();
    }
    let mut badges = String::from(
        "<span class=\"ap-badges\"><span class=\"ap-badge ap-badge--link\">Shared by me</span>",
    );
    if item.share_expired {
        badges.push_str("<span class=\"ap-badge ap-badge--expired\">Expired</span>");
    }
    if item.share_protected {
        badges.push_str("<span class=\"ap-badge ap-badge--lock\">Password</span>");
    }
    badges.push_str("</span>");
    badges
}

fn render_library_cards(items: &[LibraryItem], folders: &[FolderRec]) -> String {
    items
        .iter()
        .map(|item| {
            let location = item
                .parent_id
                .as_deref()
                .and_then(|id| folders.iter().find(|folder| folder.id == id))
                .map(|folder| folder.name.as_str())
                .unwrap_or("My Drive");
            let updated = fmt_ts(item.updated_at);
            let badges = render_library_badges(item);
            match item.kind {
                LibraryItemKind::Folder => format!(
                    "<li class=\"file-card file-card--folder ap-library-item\">\
                       <label class=\"ap-select\" title=\"Select {name}\"><span class=\"sr-only\">Select {name}</span><input type=\"checkbox\" name=\"item:folder:{id}\" value=\"1\" form=\"bulkSelection\" data-bulk-item></label>\
                       <a class=\"file-card__link\" href=\"/?folder={id}\"><span class=\"thumb thumb--folder\">{folder_svg}</span></a>\
                       <div class=\"file-card__body\">\
                         <div class=\"ap-name-row\"><a class=\"file-card__name\" href=\"/?folder={id}\" title=\"{name}\">{name}</a></div>\
                         <div class=\"file-card__meta\">{badges}<span class=\"ap-location\">In {location}</span><time class=\"ap-date\" data-spark-reltime data-ts=\"{ts}\" title=\"{updated}\">{updated}</time></div>\
                       </div>\
                     </li>",
                    id = esc(&item.id),
                    name = esc(&item.name),
                    folder_svg = FOLDER_SVG,
                    badges = badges,
                    location = esc(location),
                    ts = item.updated_at,
                    updated = esc(&updated),
                ),
                LibraryItemKind::File => {
                    let content_type = item.content_type.as_deref().unwrap_or_default();
                    let tone = ap_tone_class(content_type);
                    let file_type = library_type_for(content_type).slug();
                    let thumb = if library_type_for(content_type) == LibraryType::Image {
                        format!(
                            "<span class=\"thumb thumb--image\"><img src=\"/d/{id}/thumb\" alt=\"{name}\" loading=\"lazy\"></span>",
                            id = esc(&item.id),
                            name = esc(&item.name),
                        )
                    } else {
                        format!(
                            "<span class=\"thumb thumb--file {tone}\"><span class=\"thumb__glyph\">{glyph}</span><span class=\"thumb__ext {tone}\">{ext}</span></span>",
                            tone = tone,
                            glyph = FILE_SVG,
                            ext = esc(&ext_label(&item.name)),
                        )
                    };
                    format!(
                        "<li class=\"file-card file-card--{file_type} ap-library-item\" data-file-id=\"{id}\">\
                           <label class=\"ap-select\" title=\"Select {name}\"><span class=\"sr-only\">Select {name}</span><input type=\"checkbox\" name=\"item:file:{id}\" value=\"1\" form=\"bulkSelection\" data-bulk-item></label>\
                           <a class=\"file-card__link\" href=\"/f/{id}\" data-wire-off>{thumb}</a>\
                           <div class=\"file-card__body\">\
                             <div class=\"ap-name-row\"><span class=\"ap-glyph {tone}\">{ext}</span><a class=\"file-card__name\" href=\"/f/{id}\" title=\"{name}\">{name}</a></div>\
                             <div class=\"file-card__meta\">{badges}<span class=\"ap-size\">{size}</span><span class=\"ap-location\">In {location}</span><time class=\"ap-date\" data-spark-reltime data-ts=\"{ts}\" title=\"{updated}\">{updated}</time></div>\
                           </div>\
                         </li>",
                        file_type = file_type,
                        id = esc(&item.id),
                        thumb = thumb,
                        tone = tone,
                        ext = esc(&ext_label(&item.name)),
                        name = esc(&item.name),
                        badges = badges,
                        size = esc(&human_size(item.size.unwrap_or_default())),
                        location = esc(location),
                        ts = item.updated_at,
                        updated = esc(&updated),
                    )
                }
            }
        })
        .collect::<String>()
}

struct LibraryRender<'a> {
    config: &'a Config,
    who: &'a Identity,
    csrf: &'a str,
    items: &'a [LibraryItem],
    next: Option<&'a LibraryCursor>,
    folders: &'a [FolderRec],
    query: &'a LibraryQuery,
    used: i64,
    quota: Option<i64>,
}

fn render_library_gallery(input: LibraryRender<'_>) -> String {
    let heading = if input.query.query.is_some() {
        "Search results"
    } else {
        match input.query.view {
            LibraryView::Recent => "Recent",
            LibraryView::Shared => "Shared by me",
            LibraryView::All => "Filtered items",
        }
    };
    let count = match input.items.len() {
        0 => "No matches".to_string(),
        1 => "1 item shown".to_string(),
        value => format!("{value} items shown"),
    };
    let cards = if input.items.is_empty() {
        "<li class=\"file-card file-card--empty ap-empty\"><div class=\"ap-empty__art\" aria-hidden=\"true\"></div><h3>No matching items.</h3><p>Try another name or clear a filter.</p></li>".to_string()
    } else {
        render_library_cards(input.items, input.folders)
    };
    let pager = input
        .next
        .map(|cursor| {
            format!(
                "<nav class=\"gallery-pager\" aria-label=\"Library results\"><a class=\"btn btn-ghost\" href=\"{}\">Load older</a></nav>",
                esc(&library_href(input.query, Some(cursor)))
            )
        })
        .unwrap_or_default();
    let breadcrumb = format!(
        "<nav class=\"breadcrumb\" aria-label=\"Library view\"><span class=\"breadcrumb__here\">{}</span></nav>",
        esc(heading)
    );
    let upload = render_upload_form(input.csrf, "");

    GALLERY_HTML
        .replace("{{CSS}}", app_css())
        .replace("{{DYNAMIC}}", dynamic_js())
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("Drive", Some(&input.who.email)))
        .replace("{{USAGE}}", &render_usage_meter(input.used, input.quota))
        .replace("{{UPLOAD}}", &upload)
        .replace(
            "{{SIDEBAR}}",
            &render_sidebar(
                input.config,
                input.csrf,
                input.folders,
                None,
                false,
                Some(input.query.view),
            ),
        )
        .replace(
            "{{LIBRARY_CONTROLS}}",
            &format!(
                "{}{}",
                render_library_controls(input.query),
                render_bulk_controls(
                    input.csrf,
                    input.folders,
                    false,
                    &library_href(input.query, input.query.before.as_ref()).replace("&amp;", "&")
                )
            ),
        )
        .replace("{{BREADCRUMB}}", &breadcrumb)
        .replace("{{FOLDERS_SECTION}}", "")
        .replace("{{ITEMS_LABEL}}", "Items")
        .replace("{{COUNT}}", &esc(&count))
        .replace("{{CARDS}}", &cards)
        .replace("{{PAGER}}", &pager)
}

#[allow(clippy::too_many_arguments)]
fn render_gallery(
    config: &Config,
    who: &Identity,
    csrf: &str,
    files: &[FileRec],
    next: Option<&(i64, String)>,
    folders: &[FolderRec],
    active: Option<&FolderRec>,
    used: i64,
    quota: Option<i64>,
) -> String {
    let count = match files.len() {
        0 => "No files yet".to_string(),
        1 => "1 file".to_string(),
        n => format!("{n} files"),
    };
    // Preserve the active folder across the "Load older" pager (ids are alphanumeric => URL-safe).
    let folder_qs = active
        .map(|f| format!("&folder={}", f.id))
        .unwrap_or_default();
    let pager = match next {
        Some((ts, id)) => format!(
            "<nav class=\"gallery-pager\"><a class=\"btn btn-ghost\" href=\"/?before={ts}_{id}{folder_qs}\">Load older</a></nav>",
            ts = ts,
            id = esc(id),
            folder_qs = folder_qs,
        ),
        None => String::new(),
    };

    // Tree context: breadcrumb, the current level's child folders, and the "Up" target.
    let chain = active.map(|a| folder_chain(folders, a)).unwrap_or_default();
    let breadcrumb = render_breadcrumb(&chain);
    let children = folder_children(folders, active.map(|a| a.id.as_str()));
    let up_href = active.map(|a| match &a.parent_id {
        Some(pid) => format!("/?folder={pid}"),
        None => "/".to_string(),
    });
    let tiles = render_folder_tiles(&children, up_href.as_deref());
    let file_cards = render_cards(files, csrf);
    let folder_section = if tiles.is_empty() {
        String::new()
    } else {
        format!(
            "<section class=\"drive-section drive-section--folders\" aria-labelledby=\"foldersLabel\">\
               <div class=\"drive-section__head\">\
                 <h2 class=\"drive-section__label\" id=\"foldersLabel\">Folders</h2>\
               </div>\
               <ul class=\"folder-grid\">{tiles}</ul>\
             </section>",
            tiles = tiles,
        )
    };
    // The empty placeholder shows only when the whole level is empty (no subfolders, no files).
    let cards = if folder_section.is_empty() && file_cards.is_empty() {
        let (title, class) = if active.is_none() {
            ("Your drive is empty.", "")
        } else {
            ("This folder is empty.", "")
        };
        format!(
            "<li class=\"file-card file-card--empty ap-empty{class}\"><div class=\"ap-empty__art\" aria-hidden=\"true\"></div><h3>{title}</h3><p>Drag a file anywhere or use Upload file.</p></li>",
            class = class,
            title = title,
        )
    } else {
        file_cards
    };
    let upload_folder = active.map(|a| a.id.clone()).unwrap_or_default();
    let upload = render_upload_form(csrf, &upload_folder);
    let controls = LibraryQuery {
        view: LibraryView::All,
        query: None,
        type_filter: LibraryType::All,
        before: None,
        limit: crate::config::DEFAULT_PAGE,
    };

    GALLERY_HTML
        .replace("{{CSS}}", app_css())
        .replace("{{DYNAMIC}}", dynamic_js())
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("Drive", Some(&who.email)))
        .replace("{{USAGE}}", &render_usage_meter(used, quota))
        .replace("{{UPLOAD}}", &upload)
        .replace(
            "{{SIDEBAR}}",
            &render_sidebar(config, csrf, folders, active, false, None),
        )
        .replace(
            "{{LIBRARY_CONTROLS}}",
            &format!(
                "{}{}",
                render_library_controls(&controls),
                render_bulk_controls(
                    csrf,
                    folders,
                    false,
                    &active
                        .map(|folder| format!("/?folder={}", folder.id))
                        .unwrap_or_else(|| "/".to_string())
                )
            ),
        )
        .replace("{{BREADCRUMB}}", &breadcrumb)
        .replace("{{FOLDERS_SECTION}}", &folder_section)
        .replace("{{ITEMS_LABEL}}", "Files")
        .replace("{{COUNT}}", &esc(&count))
        .replace("{{CARDS}}", &cards)
        .replace("{{PAGER}}", &pager)
}

fn render_upload_form(csrf: &str, folder_id: &str) -> String {
    format!(
        "<form id=\"uploadForm\" class=\"dropzone ap-new\" method=\"post\" action=\"/upload\" enctype=\"multipart/form-data\">\
          <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
          <input type=\"hidden\" name=\"folder_id\" value=\"{folder}\">\
          <div class=\"ap-new__pick\">\
            <label for=\"fileInput\" class=\"ap-newbtn\">\
              <span class=\"ap-newbtn__plus\" aria-hidden=\"true\">+</span>\
              <span>New / Upload</span>\
            </label>\
            <input id=\"fileInput\" class=\"dropzone__input\" type=\"file\" name=\"file\" required>\
            <span id=\"fileName\" class=\"dropzone__hint\">Nothing selected yet</span>\
          </div>\
          <div class=\"dropzone__actions\">\
            <button class=\"btn btn-secondary btn-sm\" type=\"submit\">Upload</button>\
          </div>\
          <div class=\"dropzone__progress ap-upload-progress\" id=\"uploadProgress\" role=\"progressbar\" aria-label=\"Upload progress\" aria-valuemin=\"0\" aria-valuemax=\"100\" hidden>\
            <div class=\"dropzone__bar\" id=\"uploadBar\"></div>\
          </div>\
        </form>",
        csrf = esc(csrf),
        folder = esc(folder_id),
    )
}

fn render_bulk_controls(
    csrf: &str,
    folders: &[FolderRec],
    trash_mode: bool,
    return_to: &str,
) -> String {
    let options = std::iter::once("<option value=\"\">My Drive</option>".to_string())
        .chain(folders.iter().map(|folder| {
            format!(
                "<option value=\"{}\">{}</option>",
                esc(&folder.id),
                esc(&folder.name)
            )
        }))
        .collect::<String>();
    let actions = if trash_mode {
        "<button class=\"btn btn-secondary btn-sm\" type=\"submit\" formaction=\"/trash/restore\">Restore</button>\
         <button class=\"btn btn-danger btn-sm\" type=\"submit\" formaction=\"/trash/purge\" \
           onclick=\"return confirm('Delete the selected items forever? This cannot be undone.');\">Delete forever</button>"
            .to_string()
    } else {
        format!(
            "<label class=\"ap-bulk__destination\"><span>Move to</span><select name=\"folder_id\">{options}</select></label>\
             <button class=\"btn btn-secondary btn-sm\" type=\"submit\" formaction=\"/items/move\">Move</button>\
             <button class=\"btn btn-danger btn-sm\" type=\"submit\" formaction=\"/items/trash\" \
               onclick=\"return confirm('Move the selected items to Trash?');\">Move to Trash</button>"
        )
    };
    format!(
        "<span data-bulk-anchor hidden></span>\
         <form class=\"ap-bulk\" id=\"bulkSelection\" method=\"post\" action=\"{default_action}\" data-bulk-form>\
           <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
           <input type=\"hidden\" name=\"return_to\" value=\"{return_to}\">\
           <button class=\"btn btn-ghost btn-sm ap-bulk__all\" type=\"button\" data-bulk-select-all aria-pressed=\"false\" hidden>Select this page</button>\
           <span class=\"ap-bulk__count\" data-bulk-count aria-live=\"polite\">Choose items below, then use these actions.</span>\
           <div class=\"ap-bulk__actions\" data-bulk-actions>{actions}</div>\
         </form>",
        default_action = if trash_mode {
            "/trash/restore"
        } else {
            "/items/move"
        },
        csrf = esc(csrf),
        return_to = esc(return_to),
        actions = actions,
    )
}

struct TrashRender<'a> {
    config: &'a Config,
    who: &'a Identity,
    csrf: &'a str,
    items: &'a [TrashItem],
    next: Option<&'a LibraryCursor>,
    folders: &'a [FolderRec],
    used: i64,
    quota: Option<i64>,
}

fn render_trash_gallery(input: TrashRender<'_>) -> String {
    let count = match input.items.len() {
        0 => "No items".to_string(),
        1 => "1 trashed item".to_string(),
        n => format!("{n} trashed items shown"),
    };
    let cards = if input.items.is_empty() {
        "<li class=\"file-card file-card--empty ap-empty ap-empty--trash\"><div class=\"ap-empty__art\" aria-hidden=\"true\"></div><h3>Trash is empty.</h3><p>Deleted files and folders can be restored for up to 30 days unless you delete them forever sooner.</p></li>".to_string()
    } else {
        render_trash_cards(input.items, input.csrf)
    };
    let breadcrumb =
        "<nav class=\"breadcrumb\" aria-label=\"Folder path\"><a class=\"breadcrumb__crumb\" href=\"/\">My Drive</a><span class=\"breadcrumb__sep\" aria-hidden=\"true\">&rsaquo;</span><span class=\"breadcrumb__here\">Trash</span></nav>";
    GALLERY_HTML
        .replace("{{CSS}}", app_css())
        .replace("{{DYNAMIC}}", dynamic_js())
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("Drive", Some(&input.who.email)))
        .replace("{{USAGE}}", &render_usage_meter(input.used, input.quota))
        .replace("{{UPLOAD}}", "")
        .replace(
            "{{SIDEBAR}}",
            &render_sidebar(input.config, input.csrf, input.folders, None, true, None),
        )
        .replace(
            "{{LIBRARY_CONTROLS}}",
            &render_bulk_controls(input.csrf, input.folders, true, "/?view=trash"),
        )
        .replace("{{BREADCRUMB}}", breadcrumb)
        .replace("{{FOLDERS_SECTION}}", "")
        .replace("{{ITEMS_LABEL}}", "Items")
        .replace("{{COUNT}}", &esc(&count))
        .replace("{{CARDS}}", &cards)
        .replace(
            "{{PAGER}}",
            &input
                .next
                .map(|cursor| {
                    format!(
                        "<nav class=\"gallery-pager\" aria-label=\"Trash results\"><a class=\"btn btn-ghost\" href=\"/?view=trash&amp;before={}_{}_{}\">Load older</a></nav>",
                        cursor.updated_at,
                        cursor.kind.slug(),
                        esc(&cursor.id)
                    )
                })
                .unwrap_or_default(),
        )
}

fn render_trash_cards(items: &[TrashItem], csrf: &str) -> String {
    items
        .iter()
        .map(|item| {
            let tone = item
                .content_type
                .as_deref()
                .map(ap_tone_class)
                .unwrap_or("ap-tone-folder");
            let deleted = fmt_ts(item.trashed_at);
            let purge = fmt_ts(item.purge_after);
            let glyph = if item.kind == LibraryItemKind::Folder {
                FOLDER_SVG
            } else {
                FILE_SVG
            };
            let ext = if item.kind == LibraryItemKind::Folder {
                "Folder".to_string()
            } else {
                ext_label(&item.name)
            };
            let summary = item
                .size
                .map(human_size)
                .unwrap_or_else(|| "Contents recover together".to_string());
            let kind = item.kind.slug();
            let kind_label = if item.kind == LibraryItemKind::Folder {
                "Folder"
            } else {
                "File"
            };
            format!(
                "<li class=\"file-card file-card--trash\" id=\"file-{id}\">\
                   <label class=\"ap-select\" title=\"Select {name}\"><span class=\"sr-only\">Select {name}</span><input type=\"checkbox\" name=\"item:{kind}:{id}\" value=\"1\" form=\"bulkSelection\" data-bulk-item></label>\
                   <div class=\"thumb thumb--file {tone}\">{glyph}<span class=\"thumb__ext {tone}\">{ext}</span></div>\
                   <div class=\"file-card__body\">\
                     <span class=\"file-card__name\" title=\"{name}\">{name}</span>\
                     <div class=\"file-card__meta ap-trash-meta\">\
                       <span>{kind_label} · {summary}</span>\
                       <span>Deleted <time class=\"ap-date\" data-spark-reltime data-ts=\"{deleted_ts}\" title=\"{deleted}\">{deleted}</time></span>\
                       <span class=\"ap-trash-meta__recovery\">Eligible for automatic deletion after <time class=\"ap-date\" title=\"{purge}\">{purge}</time></span>\
                     </div>\
                     <div class=\"trash-actions\">\
                       <form method=\"post\" action=\"/trash/restore\">\
                         <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                         <input type=\"hidden\" name=\"return_to\" value=\"/?view=trash\">\
                         <input type=\"hidden\" name=\"item:{kind}:{id}\" value=\"1\">\
                         <button class=\"btn btn-secondary btn-sm\" type=\"submit\">Restore</button>\
                       </form>\
                       <form method=\"post\" action=\"/trash/purge\" \
                         onsubmit=\"return confirm('Delete this item forever? This cannot be undone.');\">\
                         <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                         <input type=\"hidden\" name=\"return_to\" value=\"/?view=trash\">\
                         <input type=\"hidden\" name=\"item:{kind}:{id}\" value=\"1\">\
                         <button class=\"btn btn-danger btn-sm\" type=\"submit\">Delete forever</button>\
                       </form>\
                     </div>\
                   </div>\
                 </li>",
                glyph = glyph,
                ext = esc(&ext),
                tone = tone,
                kind = kind,
                kind_label = kind_label,
                id = esc(&item.id),
                csrf = esc(csrf),
                name = esc(&item.name),
                summary = esc(&summary),
                deleted = esc(&deleted),
                deleted_ts = item.trashed_at,
                purge = esc(&purge),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

/// Render the drive's storage usage meter: under a quota it is a labeled fill bar ("used of
/// quota (percent)", amber past 90%); with UNLIMITED storage it shows just the used total, so
/// the pre-quota look barely changes. All sizes are server-formatted ([`human_size`]), escaped
/// regardless.
fn render_usage_meter(used: i64, quota: Option<i64>) -> String {
    match quota {
        Some(quota) => {
            let pct = (used as f64 / quota as f64 * 100.0).clamp(0.0, 100.0);
            let warn = if pct >= 90.0 {
                " usage-meter__fill--warn"
            } else {
                ""
            };
            format!(
                "<div class=\"usage-meter\">\
                   <div class=\"usage-meter__labels\">\
                     <span>Storage</span>\
                     <span>{used} of {quota} used ({pct:.0}%)</span>\
                   </div>\
                   <div class=\"usage-meter__track\">\
                     <div class=\"usage-meter__fill{warn}\" style=\"width:{pct:.2}%\"></div>\
                   </div>\
                 </div>",
                used = esc(&human_size(used)),
                quota = esc(&human_size(quota)),
                pct = pct,
                warn = warn,
            )
        }
        None => format!(
            "<div class=\"usage-meter\">\
               <div class=\"usage-meter__labels\">\
                 <span>Storage</span>\
                 <span>{used} used · no limit</span>\
               </div>\
             </div>",
            used = esc(&human_size(used)),
        ),
    }
}

/// Render the folder management rail: a "New folder" form (creating INTO the current level), and —
/// when a folder is active — its rename, empty/cascade delete, and public folder-share controls.
/// Every form is CSRF-protected and owner-scoped. Navigation itself (breadcrumb + child tiles +
/// "Up") lives in the main grid; this rail is the per-folder actions.
fn render_sidebar(
    config: &Config,
    csrf: &str,
    folders: &[FolderRec],
    active: Option<&FolderRec>,
    trash_active: bool,
    library_active: Option<LibraryView>,
) -> String {
    // The new-folder form carries the current level as the hidden parent (empty = a root folder).
    let parent_id = active.map(|a| a.id.clone()).unwrap_or_default();
    let new_form = format!(
        "<form class=\"folder-form\" method=\"post\" action=\"/folders\">\
           <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
           <input type=\"hidden\" name=\"parent_id\" value=\"{parent}\">\
           <label for=\"newFolder\">New folder here</label>\
           <div class=\"share-row\">\
             <input id=\"newFolder\" type=\"text\" name=\"name\" placeholder=\"Folder name\" maxlength=\"255\" required>\
             <button class=\"btn btn-secondary btn-sm\" type=\"submit\">Create</button>\
           </div>\
         </form>",
        csrf = esc(csrf),
        parent = esc(&parent_id),
    );
    let new_folder = if trash_active {
        String::new()
    } else {
        format!(
            "<details class=\"ap-fold ap-new-folder\"><summary>New folder</summary>{new_form}</details>",
            new_form = new_form,
        )
    };

    // Rename + delete + folder-share controls, shown only when viewing a specific folder.
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
             {share}\
             {upload_inbox}\
             <form class=\"folder-form\" method=\"post\" action=\"/folders/{id}/delete\" \
               onsubmit=\"return confirm('Delete this folder? It must be empty.');\">\
               <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
               <button class=\"btn btn-danger btn-sm\" type=\"submit\">Delete (if empty)</button>\
             </form>\
             <form class=\"folder-form\" method=\"post\" action=\"/folders/{id}/delete\" \
               onsubmit=\"return confirm('Delete this folder AND everything inside it (subfolders and files)? This cannot be undone.');\">\
               <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
               <input type=\"hidden\" name=\"cascade\" value=\"1\">\
               <button class=\"btn btn-danger btn-sm\" type=\"submit\">Delete everything</button>\
             </form>",
            id = esc(&f.id),
            csrf = esc(csrf),
            name = esc(&f.name),
            share = render_folder_share_section(config, f, csrf),
            upload_inbox = render_folder_upload_section(config, f, csrf),
        ),
        None => String::new(),
    };
    let settings = if manage.is_empty() {
        String::new()
    } else {
        format!(
            "<details class=\"ap-fold ap-rail__settings\"><summary>Folder settings</summary>{manage}</details>",
            manage = manage,
        )
    };
    let chain = active.map(|a| folder_chain(folders, a)).unwrap_or_default();
    let tree = if trash_active {
        String::new()
    } else {
        render_folder_tree(folders, active.map(|a| a.id.as_str()), &chain)
    };
    let all_selected = active.is_none()
        && !trash_active
        && matches!(library_active, None | Some(LibraryView::All));
    let all_active = if all_selected {
        " is-active"
    } else {
        ""
    };
    let all_current = if all_selected {
        " aria-current=\"page\""
    } else {
        ""
    };
    let trash_active_class = if trash_active { " is-active" } else { "" };
    let trash_current = if trash_active {
        " aria-current=\"page\""
    } else {
        ""
    };
    let recent_active = if library_active == Some(LibraryView::Recent) {
        " is-active"
    } else {
        ""
    };
    let recent_current = if library_active == Some(LibraryView::Recent) {
        " aria-current=\"page\""
    } else {
        ""
    };
    let shared_active = if library_active == Some(LibraryView::Shared) {
        " is-active"
    } else {
        ""
    };
    let shared_current = if library_active == Some(LibraryView::Shared) {
        " aria-current=\"page\""
    } else {
        ""
    };
    let foot = if trash_active {
        "<p class=\"ap-rail__foot trash-note\">Trashed files and folders stay in storage and count toward quota until deleted forever.</p>"
    } else {
        ""
    };

    format!(
        "<nav class=\"ap-nav\" aria-label=\"Drive folders\">\
           <a class=\"ap-nav__row{all_active}\" href=\"/\"{all_current}>\
             <svg class=\"ap-nav__ico\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z\"/></svg>\
             <span class=\"ap-nav__name\">My Drive</span>\
           </a>\
           {tree}\
           <div class=\"ap-rail__rule\" aria-hidden=\"true\"></div>\
           <a class=\"ap-nav__row{recent_active}\" href=\"/?view=recent\"{recent_current}>\
             <svg class=\"ap-nav__ico\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M12 7v5l3 2\"/></svg>\
             <span class=\"ap-nav__name\">Recent</span>\
           </a>\
           <a class=\"ap-nav__row{shared_active}\" href=\"/?view=shared\"{shared_current}>\
             <svg class=\"ap-nav__ico\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7\"/><path d=\"M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7\"/></svg>\
             <span class=\"ap-nav__name\">Shared by me</span>\
           </a>\
           <a class=\"ap-nav__row{trash_active_class}\" href=\"/?view=trash\"{trash_current}>\
             <svg class=\"ap-nav__ico\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M3 6h18\"/><path d=\"M8 6V4h8v2\"/><path d=\"m19 6-1 14H6L5 6\"/></svg>\
             <span class=\"ap-nav__name\">Trash</span>\
           </a>\
         </nav>\
         <div class=\"ap-rail__tools\">{new_folder}{settings}{foot}</div>",
        new_folder = new_folder,
        all_active = all_active,
        all_current = all_current,
        tree = tree,
        recent_active = recent_active,
        recent_current = recent_current,
        shared_active = shared_active,
        shared_current = shared_current,
        trash_active_class = trash_active_class,
        trash_current = trash_current,
        settings = settings,
        foot = foot,
    )
}

fn render_folder_tree(
    folders: &[FolderRec],
    active_id: Option<&str>,
    chain: &[FolderRec],
) -> String {
    render_folder_tree_level(folders, None, active_id, chain, 0)
}

fn render_folder_tree_level(
    folders: &[FolderRec],
    parent: Option<&str>,
    active_id: Option<&str>,
    chain: &[FolderRec],
    depth: usize,
) -> String {
    if depth >= MAX_TREE_DEPTH {
        return String::new();
    }
    let children = folder_children(folders, parent);
    if children.is_empty() {
        return String::new();
    }
    let mut out = String::from("<ul class=\"ap-nav__tree\">");
    for f in children {
        let active = active_id == Some(f.id.as_str());
        let expanded = chain.iter().any(|c| c.id == f.id);
        let class = if active { " is-active" } else { "" };
        let current = if active {
            " aria-current=\"page\""
        } else {
            ""
        };
        out.push_str(&format!(
            "<li><a class=\"ap-nav__row{class}\" href=\"/?folder={id}\" title=\"{name}\"{current}>\
               <svg class=\"ap-nav__ico\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M4 5h5l2 2.5h9a1 1 0 0 1 1 1V18a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1Z\"/></svg>\
               <span class=\"ap-nav__name\">{name}</span>\
             </a>",
            class = class,
            current = current,
            id = esc(&f.id),
            name = esc(&f.name),
        ));
        if expanded {
            out.push_str(&render_folder_tree_level(
                folders,
                Some(&f.id),
                active_id,
                chain,
                depth + 1,
            ));
        }
        out.push_str("</li>");
    }
    out.push_str("</ul>");
    out
}

/// Build the public folder-share control for the rail (shown while viewing a folder). An active
/// link shows its `/s/folder/{token}` URL + expiry/password state + update + revoke; a folder with no
/// link shows a "create folder link" form. Mirrors [`render_share_section`] for files; CSRF-scoped.
fn render_folder_share_section(config: &Config, folder: &FolderRec, csrf: &str) -> String {
    let controls = format!(
        "<div class=\"field\">\
           <label for=\"folderExpiry\">Link expires</label>\
           <select id=\"folderExpiry\" name=\"expiry\">{options}</select>\
         </div>\
         <div class=\"field\">\
           <label for=\"folderPassword\">Password (optional)</label>\
           <input id=\"folderPassword\" type=\"password\" name=\"password\" autocomplete=\"off\" \
             placeholder=\"Leave blank for no password\">\
         </div>",
        options = expiry_options("never"),
    );
    match &folder.share_token {
        Some(token) => {
            let share_url = format!("{}/s/folder/{}", config.public_base, token);
            let expiry_status = match folder.expires_at {
                Some(exp) => format!("Expires {}", esc(&fmt_ts(exp))),
                None => "Never expires".to_string(),
            };
            let pw_status = if folder.share_has_password() {
                "Password-protected"
            } else {
                "No password"
            };
            format!(
                "<div class=\"field\">\
                   <label for=\"folderShareUrl\">Folder share link (no sign-in)</label>\
                   <div class=\"share-row\">\
                     <input id=\"folderShareUrl\" type=\"text\" readonly value=\"{url}\">\
                   </div>\
                   <p class=\"muted\">{expiry_status} · {pw_status}</p>\
                 </div>\
                 <form class=\"folder-form\" method=\"post\" action=\"/folders/{id}/share\">\
                   <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                   {controls}\
                   <button class=\"btn btn-secondary btn-sm\" type=\"submit\">Update folder link</button>\
                 </form>\
                 <form class=\"folder-form\" method=\"post\" action=\"/folders/{id}/revoke\" \
                   onsubmit=\"return confirm('Revoke this folder share link?');\">\
                   <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                   <button class=\"btn btn-danger btn-sm\" type=\"submit\">Revoke folder link</button>\
                 </form>",
                url = esc(&share_url),
                expiry_status = expiry_status,
                pw_status = pw_status,
                id = esc(&folder.id),
                csrf = esc(csrf),
                controls = controls,
            )
        }
        None => format!(
            "<form class=\"folder-form\" method=\"post\" action=\"/folders/{id}/share\">\
               <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
               <label>Share this folder</label>\
               {controls}\
               <button class=\"btn btn-secondary btn-sm\" type=\"submit\">Create folder link</button>\
             </form>",
            id = esc(&folder.id),
            csrf = esc(csrf),
            controls = controls,
        ),
    }
}

/// Build the public upload-inbox control for a folder. This is intentionally separate from the
/// folder share link: upload visitors get `/u/{token}`, which never lists or downloads files.
fn render_folder_upload_section(_config: &Config, folder: &FolderRec, csrf: &str) -> String {
    format!(
        "<form class=\"folder-form\" method=\"post\" action=\"/folders/{id}/requests\">\
           <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
           <input type=\"hidden\" name=\"title\" value=\"{title}\">\
           <input type=\"hidden\" name=\"expiry\" value=\"604800\">\
           <label>Request files</label>\
           <p class=\"muted\">Create a finite upload-only room, then manage its deadline and budgets.</p>\
           <div class=\"share-row\"><button class=\"btn btn-secondary btn-sm\" type=\"submit\">Create upload request</button>\
           <a class=\"btn btn-ghost btn-sm\" href=\"/requests\">Manage requests</a></div>\
         </form>",
        id = esc(&folder.id),
        csrf = esc(csrf),
        title = esc(&format!("{} uploads", folder.name)),
    )
}

fn render_cards(files: &[FileRec], csrf: &str) -> String {
    files
        .iter()
        .map(|f| {
            let tone = ap_tone_class(&f.content_type);
            let date = fmt_ts(f.updated_at);
            let badges = render_card_badges(f);
            let kind = if f.is_video() {
                "video"
            } else if f.is_audio() {
                "audio"
            } else if f.is_image() {
                "image"
            } else {
                "file"
            };
            let media = f.is_media();
            let preview_attrs = if media {
                format!(
                    " data-preview data-preview-id=\"{id}\" data-preview-kind=\"{kind}\" data-preview-name=\"{name}\"",
                    id = esc(&f.id),
                    kind = kind,
                    name = esc(&f.name),
                )
            } else {
                String::new()
            };
            let media_class = if media { " file-card--media" } else { "" };
            let play = if f.is_video() || f.is_audio() {
                format!(
                    "<span class=\"thumb__play\" aria-hidden=\"true\">{PLAY_SVG}</span>",
                    PLAY_SVG = PLAY_SVG,
                )
            } else {
                String::new()
            };
            let thumb = if f.is_image() {
                format!(
                    "<span class=\"thumb thumb--image\"><img src=\"/d/{id}/thumb\" alt=\"{alt}\" loading=\"lazy\"></span>",
                    id = esc(&f.id),
                    alt = esc(&f.name),
                )
            } else {
                let glyph = if f.is_video() {
                    VIDEO_SVG
                } else if f.is_audio() {
                    AUDIO_SVG
                } else {
                    FILE_SVG
                };
                format!(
                    "<span class=\"thumb thumb--file thumb--{kind} {tone}\">\
                       <span class=\"thumb__glyph\" aria-hidden=\"true\">{glyph}</span>\
                       <span class=\"thumb__ext {tone}\">{ext}</span>\
                       {play}\
                     </span>",
                    kind = kind,
                    tone = tone,
                    glyph = glyph,
                    ext = esc(&ext_label(&f.name)),
                    play = play,
                )
            };
            // Per-card actions live in a native <details> menu — no-JS: expand, rename/trash via
            // the real forms (302 back). With JS: the rename becomes an inline PATCH-like update
            // and "Move to trash" removes the card optimistically. All owner-scoped + CSRF-checked.
            let menu = format!(
                "<details class=\"card-menu\">\
                   <summary class=\"card-menu__btn\" title=\"Actions\" aria-label=\"File actions\">\
                     <svg viewBox=\"0 0 24 24\" width=\"16\" height=\"16\" fill=\"currentColor\" aria-hidden=\"true\"><circle cx=\"5\" cy=\"12\" r=\"1.6\"/><circle cx=\"12\" cy=\"12\" r=\"1.6\"/><circle cx=\"19\" cy=\"12\" r=\"1.6\"/></svg>\
                   </summary>\
                   <div class=\"card-menu__pop\">\
                     <form class=\"card-menu__form rename-form\" method=\"post\" action=\"/f/{id}/rename\">\
                       <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                       <input class=\"rename-form__input\" type=\"text\" name=\"name\" value=\"{name}\" maxlength=\"255\" required aria-label=\"New file name\">\
                       <button class=\"btn btn-primary btn-sm\" type=\"submit\">Rename</button>\
                     </form>\
                     <form class=\"card-menu__form trash-form\" method=\"post\" action=\"/delete/{id}\" data-wire data-wire-target=\"#file-{id}\" data-wire-swap=\"delete\" data-wire-optimistic data-wire-ok=\"Moved to trash\" data-wire-err=\"Action failed — please retry\">\
                       <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                       <button class=\"btn btn-danger btn-sm\" type=\"submit\">Move to trash</button>\
                     </form>\
                   </div>\
                 </details>",
                id = esc(&f.id),
                csrf = esc(csrf),
                name = esc(&f.name),
            );
            format!(
                "<li class=\"file-card file-card--{kind}{media_class}\" id=\"file-{id}\" data-file-id=\"{id}\"{preview_attrs}>\
                   <label class=\"ap-select\" title=\"Select {name}\"><span class=\"sr-only\">Select {name}</span><input type=\"checkbox\" name=\"item:file:{id}\" value=\"1\" form=\"bulkSelection\" data-bulk-item></label>\
                   <a class=\"file-card__link\" href=\"/f/{id}\" data-wire-off>{thumb}</a>\
                   <div class=\"file-card__body\">\
                     <div class=\"ap-name-row\"><span class=\"ap-glyph {tone}\" aria-hidden=\"true\">{ext}</span><a class=\"file-card__name\" href=\"/f/{id}\" title=\"{name}\" data-file-name>{name}</a></div>\
                     <div class=\"file-card__meta\">{badges}<span class=\"ap-size\">{size}</span><time class=\"ap-date\" data-spark-reltime data-ts=\"{created_ts}\" title=\"{date}\">{date}</time></div>\
                     {menu}\
                   </div>\
                 </li>",
                id = esc(&f.id),
                name = esc(&f.name),
                kind = kind,
                media_class = media_class,
                preview_attrs = preview_attrs,
                tone = tone,
                ext = esc(&ext_label(&f.name)),
                badges = badges,
                size = esc(&human_size(f.size)),
                date = esc(&date),
                created_ts = f.updated_at,
                menu = menu,
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn render_card_badges(f: &FileRec) -> String {
    let mut badges = String::from("<span class=\"ap-badges\">");
    if f.share_token.is_some() {
        badges.push_str(
            "<span class=\"ap-badge ap-badge--link\" title=\"Share link enabled\">\
               <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71\"/><path d=\"M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71\"/></svg>\
               Linked\
             </span>",
        );
    }
    if f.share_has_password() {
        badges.push_str(
            "<span class=\"ap-badge ap-badge--lock\" title=\"Password required\">\
               <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><rect x=\"3\" y=\"11\" width=\"18\" height=\"11\" rx=\"2\"/><path d=\"M7 11V7a5 5 0 0 1 10 0v4\"/></svg>\
               Locked\
             </span>",
        );
    }
    if let Some(exp) = f.expires_at {
        let date = fmt_ts(exp);
        let expired = if f.share_expired(now_secs()) {
            " ap-badge--expired"
        } else {
            ""
        };
        badges.push_str(&format!(
            "<span class=\"ap-badge ap-badge--exp{expired}\" title=\"Expires {date}\">\
               <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><circle cx=\"12\" cy=\"12\" r=\"10\"/><path d=\"M12 6v6l4 2\"/></svg>\
               Expires\
             </span>",
            expired = expired,
            date = esc(&date),
        ));
    }
    if f.share_token.is_some() && f.view_count > 0 {
        badges.push_str(&format!(
            "<span class=\"ap-badge ap-badge--views\" title=\"Opened {views} times\">\
               <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z\"/><circle cx=\"12\" cy=\"12\" r=\"3\"/></svg>\
               {views}\
             </span>",
            views = f.view_count,
        ));
    }
    badges.push_str("</span>");
    badges
}

/// Which inline preview a file gets on its detail page.
enum Preview {
    Image,
    Video,
    Audio,
    Text,
    Pdf,
    None,
}

/// Classify a file for inline preview from its resolved content type (+ name for extension hints).
fn preview_kind(rec: &FileRec) -> Preview {
    if rec.is_image() {
        Preview::Image
    } else if rec.is_video() {
        Preview::Video
    } else if rec.is_audio() {
        Preview::Audio
    } else if rec.content_type == "application/pdf" {
        Preview::Pdf
    } else if is_text_preview(&rec.content_type, &rec.name) {
        Preview::Text
    } else {
        Preview::None
    }
}

/// True when a file should preview as escaped text/markdown: any `text/*`, a couple of textual
/// application types, or a known text-ish extension (covers files uploaded as octet-stream).
fn is_text_preview(content_type: &str, name: &str) -> bool {
    if content_type.starts_with("text/")
        || content_type == "application/json"
        || content_type == "application/xml"
    {
        return true;
    }
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
    matches!(
        ext.as_deref(),
        Some("txt" | "md" | "markdown" | "json" | "xml" | "csv" | "log" | "toml" | "yaml" | "yml")
    )
}

/// Build the inline preview block for the detail page. Images render inline (click to open full
/// size — a tiny CSS/JS lightbox, no library); video/audio use native browser controls pointed at
/// the Range-enabled raw route; text/markdown is fetched, escaped and shown in a `<pre>` (this
/// crate ships no markdown renderer, so the safe escaped fallback is used); PDFs are embedded in a
/// sandboxed `<iframe>` of the inline-served bytes; everything else shows the type icon + a download
/// prompt.
async fn build_preview(state: &AppState, rec: &FileRec) -> String {
    match preview_kind(rec) {
        Preview::Image => format!(
            "<a class=\"lightbox-trigger\" href=\"/f/{id}/raw\" title=\"Open full size\">\
               <img class=\"preview-img\" src=\"/f/{id}/raw\" alt=\"{alt}\"></a>",
            id = esc(&rec.id),
            alt = esc(&rec.name),
        ),
        Preview::Video => format!(
            "<video class=\"ap-player\" controls preload=\"metadata\" playsinline src=\"/f/{id}/raw\" title=\"{alt}\"></video>",
            id = esc(&rec.id),
            alt = esc(&rec.name),
        ),
        Preview::Audio => format!(
            "<audio class=\"ap-player ap-player--audio\" controls preload=\"metadata\" src=\"/f/{id}/raw\" title=\"{alt}\"></audio>",
            id = esc(&rec.id),
            alt = esc(&rec.name),
        ),
        Preview::Pdf => format!(
            "<iframe class=\"preview-pdf\" src=\"/f/{id}/preview-raw\" sandbox \
               title=\"{alt}\"></iframe>",
            id = esc(&rec.id),
            alt = esc(&rec.name),
        ),
        Preview::Text => match state.blobs.get(&rec.object_key).await {
            Ok(bytes) => render_text_preview(&bytes),
            Err(_) => preview_none(rec),
        },
        Preview::None => preview_none(rec),
    }
}

/// Render a text/markdown preview: the leading [`MAX_TEXT_PREVIEW_BYTES`] as ESCAPED text in a
/// `<pre>` (never interpreted as HTML), with a truncation note when the file is larger.
fn render_text_preview(bytes: &[u8]) -> String {
    let truncated = bytes.len() > MAX_TEXT_PREVIEW_BYTES;
    let slice = &bytes[..bytes.len().min(MAX_TEXT_PREVIEW_BYTES)];
    let text = String::from_utf8_lossy(slice);
    let note = if truncated {
        "<p class=\"muted preview-text__note\">Preview truncated — download the file for the full contents.</p>"
    } else {
        ""
    };
    format!(
        "<div class=\"preview-text\"><pre class=\"preview-text__pre\">{body}</pre>{note}</div>",
        body = esc(&text),
        note = note,
    )
}

/// The non-previewable fallback: the document glyph + extension label + a download prompt.
fn preview_none(rec: &FileRec) -> String {
    let tone = ap_tone_class(&rec.content_type);
    format!(
        "<div class=\"preview-file ap-stage__none\">\
           <span class=\"letter-tile ap-type-tile {tone}\" aria-hidden=\"true\">{ext}</span>\
           <span class=\"mono\">{ctype}</span>\
           <p class=\"muted\">No inline preview for this file type.</p>\
           <a class=\"btn btn-secondary\" href=\"/f/{id}/raw\">Download</a>\
         </div>",
        tone = tone,
        ext = esc(&ext_label(&rec.name)),
        ctype = esc(&rec.content_type),
        id = esc(&rec.id),
    )
}

struct DetailRender<'a> {
    config: &'a Config,
    rec: &'a FileRec,
    viewer: &'a Identity,
    csrf: &'a str,
    folders: &'a [FolderRec],
    preview: &'a str,
    versions: &'a [VersionRec],
    comments: &'a [FileComment],
}

fn render_detail(ctx: DetailRender<'_>) -> String {
    let DetailRender {
        config,
        rec,
        viewer,
        csrf,
        folders,
        preview,
        versions,
        comments,
    } = ctx;
    let uploaded = fmt_ts(rec.created_at);
    let meta_list = format!(
        "<dl class=\"meta-list\">\
           <div><dt>Type</dt><dd>{ctype}</dd></div>\
           <div><dt>Size</dt><dd>{size}</dd></div>\
           <div><dt>Uploaded</dt><dd><time data-spark-reltime data-ts=\"{created_ts}\" title=\"{date}\">{date}</time></dd></div>\
           <div><dt>Storage</dt><dd>{bucket}</dd></div>\
         </dl>",
        ctype = esc(&rec.content_type),
        size = esc(&human_size(rec.size)),
        date = esc(&uploaded),
        created_ts = rec.created_at,
        bucket = esc(&rec.bucket),
    );

    let share = render_share_section(config, rec, csrf);
    let embed_codes = render_embed_codes(config, rec);
    let embed = if embed_codes.is_empty() {
        String::new()
    } else {
        format!(
            "<details class=\"ap-fold\"><summary>Embed &amp; links</summary><div class=\"ap-fold__body\">{embed_codes}</div></details>",
            embed_codes = embed_codes,
        )
    };
    let move_section = render_move_section(rec, csrf, folders);
    let versions_section = render_versions(rec, versions, csrf);
    let comments_section = render_comments(rec, comments, csrf, viewer);

    let tone = ap_tone_class(&rec.content_type);
    let type_tile = format!(
        "<span class=\"letter-tile ap-type-tile {tone}\" aria-hidden=\"true\">{ext}</span>",
        tone = tone,
        ext = esc(&ext_label(&rec.name)),
    );
    let facts = format!(
        "<p class=\"ap-facts\">\
           <span class=\"ap-fact ap-fact--type mono\">{ctype}</span>\
           <span class=\"ap-fact\">{size}</span>\
           <span class=\"ap-fact\"><time data-spark-reltime data-ts=\"{created_ts}\" title=\"{date}\">{date}</time></span>\
         </p>",
        ctype = esc(&rec.content_type),
        size = esc(&human_size(rec.size)),
        created_ts = rec.created_at,
        date = esc(&uploaded),
    );
    let stage_mod = match preview_kind(rec) {
        Preview::Image => "ap-stage--checker",
        Preview::Video => "ap-stage--player ap-stage--video",
        Preview::Audio => "ap-stage--player ap-stage--audio",
        Preview::Text | Preview::Pdf => "ap-stage--doc",
        Preview::None => "",
    };

    let delete = format!(
        "<form class=\"delete-form\" method=\"post\" action=\"/delete/{id}\" \
           onsubmit=\"return confirm('Move this file to Trash?');\">\
           <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
           <button class=\"btn btn-danger\" type=\"submit\">Delete</button>\
         </form>",
        id = esc(&rec.id),
        csrf = esc(csrf),
    );

    DETAIL_HTML
        .replace("{{CSS}}", app_css())
        .replace("{{DYNAMIC}}", dynamic_js())
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("Drive", Some(&viewer.email)))
        .replace("{{NAME}}", &esc(&rec.name))
        .replace("{{TYPE_TILE}}", &type_tile)
        .replace("{{FACTS}}", &facts)
        .replace("{{STAGE_MOD}}", stage_mod)
        .replace("{{PREVIEW}}", preview)
        .replace("{{META_LIST}}", &meta_list)
        .replace("{{MOVE}}", &move_section)
        .replace("{{SHARE}}", &share)
        .replace("{{EMBED}}", &embed)
        .replace("{{VERSIONS}}", &versions_section)
        .replace("{{COMMENTS}}", &comments_section)
        .replace("{{ID}}", &esc(&rec.id))
        .replace("{{DELETE}}", &delete)
}

fn render_comments(
    rec: &FileRec,
    comments: &[FileComment],
    csrf: &str,
    viewer: &Identity,
) -> String {
    let rows = if comments.is_empty() {
        "<p class=\"muted\">No comments yet.</p>".to_string()
    } else {
        comments
            .iter()
            .map(|c| {
                let date = fmt_ts(c.created_at);
                let tone = ap_avatar_tone(&c.author_sub);
                let initial = ap_initial(&c.author_sub);
                format!(
                    "<li class=\"comment-item ap-comment\">\
                       <span class=\"letter-tile ap-comment__avatar ap-tone-{tone}\" aria-hidden=\"true\">{initial}</span>\
                       <div>\
                         <div class=\"comment-item__head ap-comment__head\">\
                           <span class=\"mono\">{author}</span>\
                           <time class=\"muted\" data-spark-reltime data-ts=\"{created_ts}\" title=\"{date}\">{date}</time>\
                         </div>\
                         <div class=\"comment-item__body ap-comment__body\">{body}</div>\
                         <form class=\"comment-item__delete ap-comment__delete\" method=\"post\" action=\"/f/{fid}/comments/{cid}/delete\" \
                           onsubmit=\"return confirm('Delete this comment?');\">\
                           <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                           <button class=\"btn btn-ghost btn-sm\" type=\"submit\">Delete</button>\
                         </form>\
                       </div>\
                     </li>",
                    tone = tone,
                    initial = initial,
                    author = esc(&c.author_sub),
                    date = esc(&date),
                    created_ts = c.created_at,
                    body = render_comment_body(&c.body),
                    fid = esc(&rec.id),
                    cid = esc(&c.id),
                    csrf = esc(csrf),
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };
    let viewer_initial = ap_initial(&viewer.subject);
    let viewer_tone = ap_avatar_tone(&viewer.subject);
    format!(
        "<div class=\"field comments\">\
           <label>Comments <span class=\"count-badge\">{count}</span></label>\
           <ul class=\"comment-list\">{rows}</ul>\
           <form class=\"comment-form ap-comment-form\" method=\"post\" action=\"/f/{id}/comments\">\
             <span class=\"letter-tile ap-comment__avatar ap-tone-{viewer_tone}\" aria-hidden=\"true\">{viewer_initial}</span>\
             <div>\
               <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
               <textarea name=\"body\" rows=\"4\" maxlength=\"{max}\" placeholder=\"Add a comment\" required></textarea>\
               <div class=\"actions\">\
                 <button class=\"btn btn-secondary\" type=\"submit\">Comment</button>\
               </div>\
             </div>\
           </form>\
         </div>",
        count = comments.len(),
        rows = rows,
        id = esc(&rec.id),
        csrf = esc(csrf),
        max = MAX_COMMENT_CHARS,
        viewer_tone = viewer_tone,
        viewer_initial = viewer_initial,
    )
}

fn render_comment_body(body: &str) -> String {
    esc(body).replace('\n', "<br>")
}

fn ap_avatar_tone(s: &str) -> usize {
    s.bytes().map(usize::from).sum::<usize>() % 5 + 1
}

fn ap_initial(s: &str) -> String {
    esc(s)
        .chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().collect())
        .unwrap_or_else(|| "U".to_string())
}

/// Render the version history block for the detail page: each retained snapshot with its date,
/// size and type, a download link, and a CSRF-protected "Restore" form. Empty history shows a
/// muted note. Every value is server-formatted + escaped.
fn render_versions(rec: &FileRec, versions: &[VersionRec], csrf: &str) -> String {
    if versions.is_empty() {
        return "<div class=\"field\"><label>Versions</label>\
                <p class=\"muted\">No earlier versions. Re-uploading a file with the same name in \
                this folder keeps the previous copy here.</p></div>"
            .to_string();
    }
    let rows = versions
        .iter()
        .map(|v| {
            let date = fmt_ts(v.created_at);
            format!(
                "<li class=\"eventline__item\">\
                   <span class=\"eventline__dot\" aria-hidden=\"true\"></span>\
                   <div class=\"eventline__body\">\
                     <time class=\"eventline__time\" data-spark-reltime data-ts=\"{created_ts}\" title=\"{date}\">{date}</time>\
                     <div class=\"ap-facts\">\
                       <span class=\"ap-fact\">{size}</span>\
                       <span class=\"ap-fact mono\">{ctype}</span>\
                     </div>\
                   </div>\
                   <div class=\"version-actions\">\
                     <a class=\"btn btn-secondary btn-sm\" href=\"/f/{id}/versions/{vid}/raw\">Download</a>\
                     <form method=\"post\" action=\"/f/{id}/versions/{vid}/restore\" \
                       onsubmit=\"return confirm('Restore this version? The current file becomes a version.');\">\
                       <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                       <button class=\"btn btn-secondary btn-sm\" type=\"submit\">Restore</button>\
                     </form>\
                   </div>\
                 </li>",
                date = esc(&date),
                created_ts = v.created_at,
                size = esc(&human_size(v.size)),
                ctype = esc(&v.content_type),
                id = esc(&rec.id),
                vid = esc(&v.id),
                csrf = esc(csrf),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        "<div class=\"field\">\
           <label>Versions <span class=\"count-badge\">{count}</span></label>\
           <ol class=\"eventline ap-versions version-table\">{rows}</ol>\
           <p class=\"muted\">Versions count toward your storage quota.</p>\
         </div>",
        count = versions.len(),
        rows = rows,
    )
}

/// Serve a retained version's blob as a download (always an attachment; `nosniff`), named after the
/// current file. A version is never served inline — only the current blob previews.
fn serve_version_download(rec: &FileRec, bytes: Vec<u8>) -> Response {
    let filename = safe_filename(&rec.name);
    (
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
        ],
        bytes,
    )
        .into_response()
}

/// Serve a PDF INLINE for the sandboxed detail embed: `application/pdf` + `nosniff` (so a file
/// lying about its type is never run as HTML) + a `sandbox` CSP (no scripts, no plugins-as-script).
fn serve_pdf_inline(rec: &FileRec, bytes: Vec<u8>) -> Response {
    let filename = safe_filename(&rec.name);
    (
        [
            (header::CONTENT_TYPE, "application/pdf".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("inline; filename=\"{filename}\""),
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
            (header::CONTENT_SECURITY_POLICY, "sandbox".to_string()),
        ],
        bytes,
    )
        .into_response()
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
        "<option value=\"\"{root_sel}>No folder (My Drive)</option>",
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

fn render_embed_code_row(label: &str, value: &str) -> String {
    format!(
        "<div class=\"embed-box__row\">\
           <span class=\"embed-box__label\">{label}</span>\
           <input class=\"embed-box__input\" type=\"text\" readonly value=\"{value}\">\
           <button class=\"btn btn-secondary btn-sm copy-btn\" type=\"button\" \
             data-copy=\".embed-box__input\" data-label=\"Copy\">Copy</button>\
         </div>",
        label = esc(label),
        value = esc(value),
    )
}

fn render_embed_codes(config: &Config, rec: &FileRec) -> String {
    let Some(token) = rec.share_token.as_deref() else {
        return String::new();
    };

    let direct = format!("{}/s/{}", config.public_base, token);
    let page = format!("{}/s/{}/view", config.public_base, token);
    let mut rows = vec![
        render_embed_code_row("Direct", &direct),
        render_embed_code_row("Share page", &page),
    ];
    if rec.is_image() {
        rows.push(render_embed_code_row(
            "Markdown",
            &format!("![{}]({})", rec.name, direct),
        ));
        rows.push(render_embed_code_row(
            "HTML",
            &format!("<img src=\"{}\" alt=\"{}\">", direct, rec.name),
        ));
        rows.push(render_embed_code_row(
            "BBCode",
            &format!("[img]{}[/img]", direct),
        ));
    }

    format!(
        "<div class=\"embed-box\">\
           <label>Embed &amp; links</label>\
           {rows}\
           <p class=\"muted embed-box__stats\">Opened {views} times</p>\
         </div>",
        rows = rows.join(""),
        views = rec.view_count,
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
                Some(exp) => {
                    let date = fmt_ts(exp);
                    format!(
                        "Expires <time data-spark-reltime data-ts=\"{exp}\" title=\"{date}\">{date}</time>",
                        exp = exp,
                        date = esc(&date),
                    )
                }
                None => "Never expires".to_string(),
            };
            let pw_status = if rec.share_has_password() {
                "Password-protected"
            } else {
                "No password"
            };
            format!(
                "<div class=\"ap-share-status\">\
                   <span class=\"ap-badge ap-badge--link\">Public link live</span>\
                   <span class=\"ap-badge ap-badge--exp\">{expiry_status}</span>\
                   <span class=\"ap-badge ap-badge--lock\">{pw_status}</span>\
                 </div>\
                 <div class=\"field\">\
                   <label for=\"shareUrl\">Share link (no sign-in required)</label>\
                   <div class=\"share-row embed-box__row\">\
                     <input id=\"shareUrl\" class=\"embed-box__input\" type=\"text\" readonly value=\"{url}\">\
                     <button class=\"btn btn-secondary btn-sm copy-btn\" id=\"copyBtn\" type=\"button\" data-copy=\".embed-box__input\" data-label=\"Copy\">Copy</button>\
                   </div>\
                 </div>\
                 <details class=\"ap-fold\"><summary>Link settings</summary><div class=\"ap-fold__body\">\
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
                   </form>\
                 </div></details>",
                url = esc(&share_url),
                expiry_status = expiry_status,
                pw_status = pw_status,
                id = esc(&rec.id),
                csrf = esc(csrf),
                controls = controls,
            )
        }
        None => format!(
            "<div class=\"ap-share-status\"><span class=\"ap-badge ap-badge--link\">Private</span></div>\
             <div class=\"field\">\
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

    #[test]
    fn redirect_found_falls_back_instead_of_panicking_on_invalid_header_input() {
        let response = redirect_found("/?ok=1\nlocation: https://evil.example");
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/");
    }

    #[test]
    fn thumb_object_key_is_namespaced() {
        assert_eq!(thumb_object_key("abc123"), "abc123.thumb");
    }

    #[test]
    fn parse_range_handles_rfc_byte_forms() {
        assert_eq!(parse_range(None, 10), RangeSpec::Full);
        assert_eq!(parse_range(Some("items=0-3"), 10), RangeSpec::Full);
        assert_eq!(parse_range(Some("bytes=0-3,5-6"), 10), RangeSpec::Full);
        assert_eq!(parse_range(Some("bytes=x-y"), 10), RangeSpec::Full);
        assert_eq!(
            parse_range(Some("bytes=0-3"), 10),
            RangeSpec::Partial { start: 0, end: 3 }
        );
        assert_eq!(
            parse_range(Some("bytes=7-"), 10),
            RangeSpec::Partial { start: 7, end: 9 }
        );
        assert_eq!(
            parse_range(Some("bytes=-2"), 10),
            RangeSpec::Partial { start: 8, end: 9 }
        );
        assert_eq!(
            parse_range(Some("bytes=8-99"), 10),
            RangeSpec::Partial { start: 8, end: 9 }
        );
        assert_eq!(parse_range(Some("bytes=10-"), 10), RangeSpec::Unsatisfiable);
        assert_eq!(parse_range(Some("bytes=4-3"), 10), RangeSpec::Unsatisfiable);
        assert_eq!(parse_range(Some("bytes=-0"), 10), RangeSpec::Unsatisfiable);
    }

    #[test]
    fn thumb_palette_is_mime_keyed_and_stable() {
        // Same mime -> same colors every time (deterministic).
        assert_eq!(
            thumb_palette("application/pdf"),
            thumb_palette("application/pdf")
        );
        // Distinct categories get distinct tints.
        assert_ne!(
            thumb_palette("application/pdf").0,
            thumb_palette("audio/mpeg").0
        );
        assert_eq!(thumb_palette("application/zip").0, "#FEF3C7");
        assert_eq!(thumb_palette("text/plain").0, "#E2E8F0");
    }

    #[test]
    fn usage_meter_renders_quota_bar_or_unlimited_total() {
        // Under a quota: used/quota labels, a percent, and a width-scaled fill bar.
        let limited = render_usage_meter(512 * 1024, Some(1024 * 1024));
        assert!(limited.contains("512.0 KB of 1.0 MB used (50%)"));
        assert!(limited.contains("usage-meter__track"));
        assert!(limited.contains("width:50.00%"));
        assert!(!limited.contains("usage-meter__fill--warn"));
        // Past 90% the fill switches to the warning tint; over-quota is clamped to 100%.
        let hot = render_usage_meter(99, Some(100));
        assert!(hot.contains("usage-meter__fill--warn"));
        assert!(render_usage_meter(300, Some(100)).contains("width:100.00%"));
        // Unlimited: just the used total — no track, no percent.
        let unlimited = render_usage_meter(2048, None);
        assert!(unlimited.contains("2.0 KB used · no limit"));
        assert!(!unlimited.contains("usage-meter__track"));
    }

    #[test]
    fn render_type_thumb_bakes_escaped_label() {
        let svg = render_type_thumb("application/pdf", "report.pdf");
        assert!(svg.starts_with("<svg"));
        assert!(!svg.contains("image/svg")); // it's the body, not a content type
        assert!(svg.contains(">PDF<"));
        assert!(svg.contains("#B91C1C")); // pdf ink color
                                          // A hostile "extension" is neutralized by ext_label (whitelist) before it can reach the SVG.
        let hostile = render_type_thumb("application/octet-stream", "x.<svg onload=alert(1)>");
        assert!(!hostile.contains("onload"));
        assert!(hostile.contains(">FILE<"));
    }
}
