//! Owner control plane for product-level public upload requests.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Form;
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth;
use crate::error::AppError;
use crate::handlers::files::{html_with_csrf, redirect_found};
use crate::handlers::{app_css, dynamic_js, esc, fmt_ts, human_size, userbox};
use crate::model::{
    FolderRec, UploadDeliveryBundle, UploadRequestInbox, UploadRequestInboxView, UploadRequestRec,
    UploadRequestSummary, UploadSubmission, UPLOAD_REQUEST_INBOX_CAP,
};
use crate::store::{
    DEFAULT_REQUEST_ALLOWED_TYPES, DEFAULT_REQUEST_MAX_FILES, DEFAULT_REQUEST_MAX_FILE_BYTES,
    DEFAULT_REQUEST_MAX_TOTAL_BYTES,
};
use crate::{now_secs, random_alnum, AppState};

const REQUEST_ID_LEN: usize = 12;
const REQUEST_TOKEN_LEN: usize = 32;
const DEFAULT_EXPIRY_SECS: i64 = 7 * 24 * 60 * 60;
const MAX_EXPIRY_SECS: i64 = 30 * 24 * 60 * 60;
const MAX_REQUEST_FILES: i64 = 1000;
const MAX_REQUEST_TOTAL_BYTES: i64 = 10 * 1024 * 1024 * 1024;
const MAX_TITLE_CHARS: usize = 120;
const MAX_DESCRIPTION_CHARS: usize = 2000;

const REQUESTS_HTML: &str = include_str!("../../templates/requests.html");
const REQUEST_DETAIL_HTML: &str = include_str!("../../templates/request_detail.html");

#[derive(Debug, Deserialize)]
pub struct RequestInboxQuery {
    /// Stable owner-facing URL state: all/open/expiring/closed/expired.
    #[serde(default)]
    pub view: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RequestConfigForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub description: String,
    /// Relative lifetime in seconds. Values are bounded to 30 days.
    #[serde(default)]
    pub expiry: String,
    #[serde(default)]
    pub max_file_mib: String,
    #[serde(default)]
    pub max_total_mib: String,
    #[serde(default)]
    pub max_files: String,
    #[serde(default)]
    pub allowed_types: String,
}

#[derive(Debug, Deserialize)]
pub struct RequestActionForm {
    #[serde(default)]
    pub csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub struct RequestRotateForm {
    #[serde(default)]
    pub csrf_token: String,
    /// Token rendered with the owner page. The Store compares this atomically so two stale forms
    /// cannot both rotate the same capability.
    #[serde(default)]
    pub expected_token: String,
}

pub async fn index(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<RequestInboxQuery>,
) -> Result<Response, AppError> {
    let actor = auth::identity(&headers);
    let csrf = auth::new_csrf_token();
    let view = parse_inbox_view(query.view.as_deref())?;
    let as_of = now_secs();
    let inbox = state
        .store
        .upload_request_inbox(&actor.subject, view, as_of)
        .await?;
    let folders = state.store.list_folders(&actor.subject).await?;
    let html = render_index(&actor.email, &csrf, &inbox, &folders);
    Ok(html_with_csrf(StatusCode::OK, html, &csrf))
}

pub async fn detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let actor = auth::identity(&headers);
    let request = state
        .store
        .get_upload_request(&id, &actor.subject)
        .await?
        .ok_or_else(|| AppError::NotFound("No such upload request.".to_string()))?;
    let folder = state
        .store
        .get_folder(&request.folder_id, &actor.subject)
        .await?;
    let submissions = state
        .store
        .list_upload_submissions(&request.id, &actor.subject)
        .await?;
    let deliveries = state
        .store
        .list_upload_deliveries(&request.id, &actor.subject)
        .await?;
    let csrf = auth::new_csrf_token();
    let as_of = now_secs();
    let html = render_detail(
        &actor.email,
        &csrf,
        RequestDetailContext {
            request: &request,
            folder: folder.as_ref(),
            deliveries: &deliveries,
            submissions: &submissions,
            public_base: &state.config.public_base,
            as_of,
        },
    );
    Ok(html_with_csrf(StatusCode::OK, html, &csrf))
}

/// Create a request scoped to one owned destination folder.
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(folder_id): Path<String>,
    Form(form): Form<RequestConfigForm>,
) -> Result<Response, AppError> {
    verify_csrf(&headers, &form.csrf_token)?;
    let actor = auth::identity(&headers);
    let folder = state
        .store
        .get_folder(&folder_id, &actor.subject)
        .await?
        .ok_or_else(|| AppError::NotFound("No such folder.".to_string()))?;
    let now = now_secs();
    let mut request = build_request(&state, &actor.subject, &folder, &form, now)?;
    let mut created = false;
    for _ in 0..6 {
        request.id = random_alnum(REQUEST_ID_LEN);
        request.token = random_alnum(REQUEST_TOKEN_LEN);
        if state.store.create_upload_request(&request).await? {
            created = true;
            break;
        }
    }
    if !created {
        return Err(AppError::Internal(
            "could not allocate a unique upload request".to_string(),
        ));
    }
    state.audit.emit(AuditEvent::notice(
        "upload_request.create",
        &actor.subject,
        &request.id,
        "upload request",
    ));
    Ok(redirect_found(&format!("/requests/{}", request.id)))
}

pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<RequestConfigForm>,
) -> Result<Response, AppError> {
    verify_csrf(&headers, &form.csrf_token)?;
    let actor = auth::identity(&headers);
    let current = state
        .store
        .get_upload_request(&id, &actor.subject)
        .await?
        .ok_or_else(|| AppError::NotFound("No such upload request.".to_string()))?;
    let folder = state
        .store
        .get_folder(&current.folder_id, &actor.subject)
        .await?
        .ok_or_else(|| {
            AppError::NotFound("The destination folder no longer exists.".to_string())
        })?;
    let mut next = build_request(&state, &actor.subject, &folder, &form, now_secs())?;
    next.id = current.id.clone();
    next.token = current.token.clone();
    next.status = current.status.clone();
    next.used_bytes = current.used_bytes;
    next.used_files = current.used_files;
    next.created_at = current.created_at;
    if next.max_total_bytes < current.used_bytes || next.max_files < current.used_files {
        return Err(AppError::BadRequest(
            "Limits cannot be lower than already received files.".to_string(),
        ));
    }
    if !state.store.update_upload_request(&next).await? {
        return Err(AppError::BadRequest(
            "The request settings could not be applied.".to_string(),
        ));
    }
    state.audit.emit(AuditEvent::notice(
        "upload_request.update",
        &actor.subject,
        &id,
        "upload request",
    ));
    Ok(redirect_found(&format!("/requests/{id}")))
}

pub async fn close(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<RequestActionForm>,
) -> Result<Response, AppError> {
    set_status(state, headers, id, form, "closed").await
}

pub async fn reopen(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<RequestActionForm>,
) -> Result<Response, AppError> {
    verify_csrf(&headers, &form.csrf_token)?;
    let actor = auth::identity(&headers);
    let now = now_secs();
    if !state
        .store
        .reopen_upload_request(
            &id,
            &actor.subject,
            now,
            now.saturating_add(DEFAULT_EXPIRY_SECS),
        )
        .await?
    {
        return Err(AppError::NotFound("No such upload request.".to_string()));
    }
    state.audit.emit(AuditEvent::notice(
        "upload_request.reopen",
        &actor.subject,
        &id,
        "upload request",
    ));
    Ok(redirect_found(&format!("/requests/{id}")))
}

pub async fn rotate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<RequestRotateForm>,
) -> Result<Response, AppError> {
    verify_csrf(&headers, &form.csrf_token)?;
    if form.expected_token.is_empty() {
        return Err(AppError::BadRequest(
            "Reload the request before rotating its link.".to_string(),
        ));
    }
    let actor = auth::identity(&headers);
    let mut rotated = false;
    for _ in 0..6 {
        let token = random_alnum(REQUEST_TOKEN_LEN);
        if state
            .store
            .rotate_upload_request_token(
                &id,
                &actor.subject,
                &form.expected_token,
                &token,
                now_secs(),
            )
            .await?
        {
            rotated = true;
            break;
        }
    }
    if !rotated {
        let current = state
            .store
            .get_upload_request(&id, &actor.subject)
            .await?
            .ok_or_else(|| AppError::NotFound("No such upload request.".to_string()))?;
        if current.token != form.expected_token {
            return Err(AppError::BadRequest(
                "This upload link was already rotated. Reload the page and try again.".to_string(),
            ));
        }
        return Err(AppError::Internal(
            "could not rotate the upload request token".to_string(),
        ));
    }
    state.audit.emit(AuditEvent::warning(
        "upload_request.rotate",
        &actor.subject,
        &id,
        "upload request",
    ));
    Ok(redirect_found(&format!("/requests/{id}")))
}

pub async fn acknowledge_delivery(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, delivery_id)): Path<(String, String)>,
    Form(form): Form<RequestActionForm>,
) -> Result<Response, AppError> {
    verify_csrf(&headers, &form.csrf_token)?;
    let actor = auth::identity(&headers);
    if !state
        .store
        .acknowledge_upload_delivery(&id, &delivery_id, &actor.subject, now_secs())
        .await?
    {
        return Err(AppError::NotFound("No such delivery.".to_string()));
    }
    state.audit.emit(AuditEvent::notice(
        "upload_delivery.acknowledge",
        &actor.subject,
        &id,
        "delivery",
    ));
    Ok(redirect_found(&format!("/requests/{id}")))
}

async fn set_status(
    state: AppState,
    headers: HeaderMap,
    id: String,
    form: RequestActionForm,
    status: &str,
) -> Result<Response, AppError> {
    verify_csrf(&headers, &form.csrf_token)?;
    let actor = auth::identity(&headers);
    if !state
        .store
        .set_upload_request_status(&id, &actor.subject, status, now_secs())
        .await?
    {
        return Err(AppError::NotFound("No such upload request.".to_string()));
    }
    state.audit.emit(AuditEvent::notice(
        "upload_request.close",
        &actor.subject,
        &id,
        "upload request",
    ));
    Ok(redirect_found(&format!("/requests/{id}")))
}

fn verify_csrf(headers: &HeaderMap, submitted: &str) -> Result<(), AppError> {
    if auth::verify_csrf(headers, submitted) {
        Ok(())
    } else {
        Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ))
    }
}

fn build_request(
    state: &AppState,
    owner_sub: &str,
    folder: &FolderRec,
    form: &RequestConfigForm,
    now: i64,
) -> Result<UploadRequestRec, AppError> {
    let title: String = if form.title.trim().is_empty() {
        format!("{} uploads", folder.name)
    } else {
        form.title.trim().to_string()
    }
    .chars()
    .take(MAX_TITLE_CHARS)
    .collect();
    let description = form
        .description
        .trim()
        .chars()
        .take(MAX_DESCRIPTION_CHARS)
        .collect();
    let expiry_secs = parse_bounded(
        &form.expiry,
        DEFAULT_EXPIRY_SECS,
        60,
        MAX_EXPIRY_SECS,
        "expiry",
    )?;
    let service_max = state.config.max_upload.min(i64::MAX as usize) as i64;
    let default_file = DEFAULT_REQUEST_MAX_FILE_BYTES.min(service_max).max(1);
    let max_file_bytes = parse_mib(&form.max_file_mib, default_file, service_max, "file limit")?;
    let max_total_bytes = parse_mib(
        &form.max_total_mib,
        DEFAULT_REQUEST_MAX_TOTAL_BYTES.max(max_file_bytes),
        MAX_REQUEST_TOTAL_BYTES,
        "total budget",
    )?;
    if max_total_bytes < max_file_bytes {
        return Err(AppError::BadRequest(
            "Total budget must be at least the per-file limit.".to_string(),
        ));
    }
    let max_files = parse_bounded(
        &form.max_files,
        DEFAULT_REQUEST_MAX_FILES,
        1,
        MAX_REQUEST_FILES,
        "file count",
    )?;
    let allowed_types = normalize_allowed_types(&form.allowed_types)?;
    Ok(UploadRequestRec {
        id: String::new(),
        owner_sub: owner_sub.to_string(),
        folder_id: folder.id.clone(),
        token: String::new(),
        title,
        description,
        status: "open".to_string(),
        expires_at: Some(now.saturating_add(expiry_secs)),
        max_file_bytes,
        max_total_bytes,
        max_files,
        used_bytes: 0,
        used_files: 0,
        allowed_types,
        created_at: now,
        updated_at: now,
    })
}

fn parse_mib(raw: &str, default_bytes: i64, max_bytes: i64, label: &str) -> Result<i64, AppError> {
    if raw.trim().is_empty() {
        return Ok(default_bytes.min(max_bytes));
    }
    let mib = parse_bounded(raw, 1, 1, max_bytes / (1024 * 1024), label)?;
    Ok(mib.saturating_mul(1024 * 1024))
}

fn parse_bounded(
    raw: &str,
    default: i64,
    min: i64,
    max: i64,
    label: &str,
) -> Result<i64, AppError> {
    if raw.trim().is_empty() {
        return Ok(default.clamp(min, max));
    }
    raw.trim()
        .parse::<i64>()
        .ok()
        .filter(|value| *value >= min && *value <= max)
        .ok_or_else(|| AppError::BadRequest(format!("Invalid {label}.")))
}

fn normalize_allowed_types(raw: &str) -> Result<String, AppError> {
    let source = if raw.trim().is_empty() {
        DEFAULT_REQUEST_ALLOWED_TYPES
    } else {
        raw
    };
    let mut out = Vec::new();
    for entry in source.split(',') {
        let pattern = entry.trim().to_ascii_lowercase();
        let valid = pattern == "*/*"
            || pattern.split_once('/').is_some_and(|(kind, subtype)| {
                !kind.is_empty()
                    && !subtype.is_empty()
                    && kind.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'+' | b'.')
                    })
                    && (subtype == "*"
                        || subtype.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'+' | b'.')
                        }))
            });
        if !valid || out.len() >= 32 {
            return Err(AppError::BadRequest(
                "Allowed types must be comma-separated MIME patterns.".to_string(),
            ));
        }
        if !out.contains(&pattern) {
            out.push(pattern);
        }
    }
    if out.is_empty() {
        return Err(AppError::BadRequest(
            "At least one allowed type is required.".to_string(),
        ));
    }
    Ok(out.join(","))
}

fn parse_inbox_view(raw: Option<&str>) -> Result<UploadRequestInboxView, AppError> {
    let value = raw.map(str::trim).filter(|value| !value.is_empty());
    match value {
        None => Ok(UploadRequestInboxView::All),
        Some(value) => UploadRequestInboxView::from_slug(value).ok_or_else(|| {
            AppError::BadRequest(
                "Unknown request view. Use all, open, expiring, closed, or expired.".to_string(),
            )
        }),
    }
}

fn render_index(
    email: &str,
    csrf: &str,
    inbox: &UploadRequestInbox,
    folders: &[FolderRec],
) -> String {
    let filters = UploadRequestInboxView::ALL
        .into_iter()
        .map(|view| {
            let current = if view == inbox.view {
                " is-active"
            } else {
                ""
            };
            let aria_current = if view == inbox.view {
                " aria-current=\"page\""
            } else {
                ""
            };
            format!(
                "<a class=\"request-filter{current}\" href=\"/requests?view={slug}\"{aria_current}><span>{label}</span><b>{count}</b></a>",
                slug = view.slug(),
                label = view.label(),
                count = inbox.counts.for_view(view),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let rows = if inbox.items.is_empty() {
        let (heading, body) = if inbox.view == UploadRequestInboxView::All {
            (
                "No upload requests yet".to_string(),
                "Create one for a private destination folder below.".to_string(),
            )
        } else {
            (
                format!("No {} requests", inbox.view.label().to_ascii_lowercase()),
                "This status filter is empty at the Inbox snapshot. Try another view.".to_string(),
            )
        };
        let reset = if inbox.view == UploadRequestInboxView::All {
            String::new()
        } else {
            "<a class=\"btn btn-ghost btn-sm\" href=\"/requests?view=all\">Show all requests</a>"
                .to_string()
        };
        format!(
            "<div class=\"request-empty\"><span class=\"request-empty__mark\" aria-hidden=\"true\">⇧</span><h2>{heading}</h2><p>{body}</p>{reset}</div>",
            heading = esc(&heading),
            body = esc(&body),
        )
    } else {
        inbox
            .items
            .iter()
            .map(|request| render_inbox_row(request, inbox.as_of))
            .collect::<Vec<_>>()
            .join("")
    };
    let scope = if inbox.truncated {
        format!(
            "Showing the newest {} of {} matching requests · Inbox cap {} · as of {}",
            inbox.items.len(),
            inbox.matched_total,
            UPLOAD_REQUEST_INBOX_CAP,
            fmt_ts(inbox.as_of),
        )
    } else {
        format!(
            "Showing all {} matching requests · Inbox cap {} · as of {}",
            inbox.matched_total,
            UPLOAD_REQUEST_INBOX_CAP,
            fmt_ts(inbox.as_of),
        )
    };
    let folder_rows = if folders.is_empty() {
        "<p class=\"muted\">Create a folder in Files before opening an upload request.</p>"
            .to_string()
    } else {
        folders
            .iter()
            .map(|folder| {
                format!(
                    "<form class=\"request-create-row\" method=\"post\" action=\"/folders/{id}/requests\"><input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\"><input type=\"hidden\" name=\"expiry\" value=\"604800\"><span>{name}</span><input name=\"title\" value=\"{name} uploads\" maxlength=\"120\" aria-label=\"Request title\"><button class=\"btn btn-primary btn-sm\" type=\"submit\">Create request</button></form>",
                    id = esc(&folder.id),
                    csrf = esc(csrf),
                    name = esc(&folder.name),
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };
    REQUESTS_HTML
        .replace("{{CSS}}", app_css())
        .replace("{{DYNAMIC}}", dynamic_js())
        .replace("{{USERBOX}}", &userbox("Drive", Some(email)))
        .replace("{{FILTERS}}", &filters)
        .replace("{{SCOPE}}", &esc(&scope))
        .replace("{{REQUESTS}}", &rows)
        .replace("{{FOLDERS}}", &folder_rows)
}

fn render_inbox_row(request: &UploadRequestSummary, as_of: i64) -> String {
    let description = if request.description.is_empty() {
        "<p class=\"request-inbox-row__description muted\">No public instructions.</p>".to_string()
    } else {
        format!(
            "<p class=\"request-inbox-row__description\">{}</p>",
            esc(&request.description)
        )
    };
    format!(
        "<article class=\"card request-inbox-row\"><div class=\"request-inbox-row__lead\"><span class=\"badge request-state request-state--{state_slug}\">{state}</span><div><h2><a href=\"/requests/{id}\">{title}</a></h2>{description}</div></div><dl class=\"request-inbox-row__facts\"><div><dt>Files</dt><dd>{used_files} / {max_files}</dd></div><div><dt>Storage</dt><dd>{used_bytes} / {max_bytes}</dd></div><div><dt>Deadline</dt><dd>{deadline}</dd></div><div><dt>Updated</dt><dd>{updated}</dd></div></dl><a class=\"btn btn-ghost btn-sm request-inbox-row__detail\" href=\"/requests/{id}\">Open details</a></article>",
        state_slug = request.state.slug(),
        state = request.state.label(),
        id = esc(&request.id),
        title = esc(&request.title),
        used_files = request.used_files,
        max_files = request.max_files,
        used_bytes = esc(&human_size(request.used_bytes)),
        max_bytes = esc(&human_size(request.max_total_bytes)),
        deadline = esc(&deadline_label(request.expires_at, as_of)),
        updated = esc(&fmt_ts(request.updated_at)),
    )
}

struct RequestDetailContext<'a> {
    request: &'a UploadRequestRec,
    folder: Option<&'a FolderRec>,
    deliveries: &'a [UploadDeliveryBundle],
    submissions: &'a [UploadSubmission],
    public_base: &'a str,
    as_of: i64,
}

fn render_detail(email: &str, csrf: &str, detail: RequestDetailContext<'_>) -> String {
    let RequestDetailContext {
        request,
        folder,
        deliveries,
        submissions,
        public_base,
        as_of,
    } = detail;
    let url = format!("{}/u/{}", public_base, request.token);
    let mut receipts = deliveries
        .iter()
        .map(|bundle| {
            let files = bundle
                .submissions
                .iter()
                .map(|submission| {
                    format!(
                        "<li class=\"request-receipt\"><a href=\"/f/{file_id}\">{name}</a><span>{size} · {kind} · {date}</span></li>",
                        file_id = esc(&submission.file_id),
                        name = esc(&submission.name),
                        size = esc(&human_size(submission.size)),
                        kind = esc(&submission.content_type),
                        date = esc(&fmt_ts(submission.created_at)),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let (status, acknowledgement) = match bundle.delivery.acknowledged_at {
                Some(at) => (
                    "Acknowledged",
                    format!("<span class=\"muted\">Acknowledged {}</span>", esc(&fmt_ts(at))),
                ),
                None => (
                    "Received",
                    format!(
                        "<form method=\"post\" action=\"/requests/{request_id}/deliveries/{delivery_id}/acknowledge\"><input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\"><button class=\"btn btn-secondary btn-sm\" type=\"submit\">Acknowledge</button></form>",
                        request_id = esc(&request.id),
                        delivery_id = esc(&bundle.delivery.id),
                        csrf = esc(csrf),
                    ),
                ),
            };
            format!(
                "<article class=\"request-delivery\"><div class=\"card__head\"><div><p class=\"eyebrow\">Delivery · {created}</p><h3>{status}</h3></div>{acknowledgement}</div><ol class=\"request-receipts\">{files}</ol><p class=\"muted\">Receipt available until {expiry}</p></article>",
                created = esc(&fmt_ts(bundle.delivery.created_at)),
                expiry = esc(&fmt_ts(bundle.delivery.receipt_expires_at)),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let legacy: Vec<_> = submissions
        .iter()
        .filter(|submission| submission.delivery_id.is_none())
        .collect();
    if !legacy.is_empty() {
        let files = legacy
            .iter()
            .map(|submission| {
                format!(
                    "<li class=\"request-receipt\"><a href=\"/f/{file_id}\">{name}</a><span>{size} · {kind} · {date}</span></li>",
                    file_id = esc(&submission.file_id),
                    name = esc(&submission.name),
                    size = esc(&human_size(submission.size)),
                    kind = esc(&submission.content_type),
                    date = esc(&fmt_ts(submission.created_at)),
                )
            })
            .collect::<Vec<_>>()
            .join("");
        receipts.push_str(&format!(
            "<article class=\"request-delivery request-delivery--legacy\"><div><p class=\"eyebrow\">Legacy receipts</p><h3>Recorded before delivery tracking</h3></div><ol class=\"request-receipts\">{files}</ol></article>"
        ));
    }
    if receipts.is_empty() {
        receipts = "<p class=\"muted\">No files received yet.</p>".to_string();
    }
    let action = if request.is_open() && !request.is_expired(as_of) {
        format!(
            "<form method=\"post\" action=\"/requests/{id}/close\"><input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\"><button class=\"btn btn-danger\" type=\"submit\">Close request</button></form>",
            id = esc(&request.id), csrf = esc(csrf)
        )
    } else {
        format!(
            "<form method=\"post\" action=\"/requests/{id}/reopen\"><input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\"><button class=\"btn btn-primary\" type=\"submit\">Reopen for 7 days</button></form>",
            id = esc(&request.id), csrf = esc(csrf)
        )
    };
    REQUEST_DETAIL_HTML
        .replace("{{CSS}}", app_css())
        .replace("{{DYNAMIC}}", dynamic_js())
        .replace("{{USERBOX}}", &userbox("Drive", Some(email)))
        .replace("{{ID}}", &esc(&request.id))
        .replace("{{TITLE}}", &esc(&request.title))
        .replace("{{DESCRIPTION}}", &esc(&request.description))
        .replace("{{STATE}}", &esc(request_state_at(request, as_of)))
        .replace(
            "{{FOLDER}}",
            &esc(folder.map_or("Missing folder", |item| &item.name)),
        )
        .replace("{{URL}}", &esc(&url))
        .replace(
            "{{EXPIRY}}",
            &esc(&deadline_label(request.expires_at, as_of)),
        )
        .replace(
            "{{MAX_FILE_MIB}}",
            &(request.max_file_bytes / 1024 / 1024).to_string(),
        )
        .replace(
            "{{MAX_TOTAL_MIB}}",
            &(request.max_total_bytes / 1024 / 1024).to_string(),
        )
        .replace("{{MAX_FILES}}", &request.max_files.to_string())
        .replace("{{USED_BYTES}}", &esc(&human_size(request.used_bytes)))
        .replace("{{USED_FILES}}", &request.used_files.to_string())
        .replace("{{ALLOWED_TYPES}}", &esc(&request.allowed_types))
        .replace("{{EXPECTED_TOKEN}}", &esc(&request.token))
        .replace("{{CSRF}}", &esc(csrf))
        .replace("{{ACTION}}", &action)
        .replace("{{RECEIPTS}}", &receipts)
}

fn request_state_at(request: &UploadRequestRec, as_of: i64) -> &'static str {
    if !request.is_open() {
        "Closed"
    } else if request.is_expired(as_of) {
        "Expired"
    } else {
        "Open"
    }
}

fn deadline_label(expires_at: Option<i64>, as_of: i64) -> String {
    match expires_at {
        Some(expiry) if expiry <= as_of => format!("Expired {}", fmt_ts(expiry)),
        Some(expiry) => format!("Due {}", fmt_ts(expiry)),
        None => "No deadline".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_types_are_normalized_and_validated() {
        assert_eq!(
            normalize_allowed_types(" Image/*, application/PDF, image/* ").unwrap(),
            "image/*,application/pdf"
        );
        assert!(normalize_allowed_types("image").is_err());
        assert!(normalize_allowed_types("text/ht ml").is_err());
    }
}
