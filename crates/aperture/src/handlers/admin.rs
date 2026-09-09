//! The `/admin` panel: per-owner storage usage + quota overrides.
//!
//! The whole subtree is gated by [`crate::auth::require_admin`] (applied as a router middleware
//! in [`crate::app`]): an ordinary signed-in user gets a branded `403`, only members of
//! `admins` / `infra-admins` reach these handlers. The state-changing POST is additionally
//! double-submit CSRF protected and emits an [`AuditEvent`] (mirroring the drive's write
//! handlers). All interpolated user input (owner subjects) is HTML-escaped; the panel renders
//! into the same enterprise shell as the rest of the drive.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Form;
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth;
use crate::config::effective_quota;
use crate::error::AppError;
use crate::handlers::files::{html_with_csrf, redirect_found};
use crate::handlers::{esc, human_size, topbar, FOOTER, SHIELD_SVG};
use crate::model::OwnerUsage;
use crate::AppState;

/// Hard cap on a submitted owner subject (the store column is TEXT; this only rejects absurd
/// payloads).
const MAX_OWNER_SUB_CHARS: usize = 200;

const ADMIN_HTML: &str = include_str!("../../templates/admin.html");

// ---------------------------------------------------------------------------
// GET /admin — per-owner usage table + set-quota form
// ---------------------------------------------------------------------------

/// `GET /admin` — render the per-owner storage usage table (owner, files, bytes, effective
/// quota) and the CSRF-protected set-quota form. Admin-gated by the router middleware.
pub async fn index(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let viewer = auth::identity(&headers);
    let csrf = auth::new_csrf_token();

    let mut usage = state.store.usage_by_owner().await?;
    let quotas = state.store.list_quotas().await?;
    // An owner can carry a quota override before their first upload — surface those rows too,
    // with zero usage, so a set override is always visible in the table.
    for (owner, _) in &quotas {
        if !usage.iter().any(|u| &u.owner_sub == owner) {
            usage.push(OwnerUsage {
                owner_sub: owner.clone(),
                files: 0,
                bytes: 0,
            });
        }
    }

    let html = render_admin(
        state.config.default_quota_bytes,
        &viewer.email,
        &csrf,
        &usage,
        &quotas,
    );
    Ok(html_with_csrf(StatusCode::OK, html, &csrf))
}

// ---------------------------------------------------------------------------
// POST /admin/quota — set or clear an owner's quota override
// ---------------------------------------------------------------------------

/// Set-quota form: the target owner subject + the override in bytes. A BLANK `quota_bytes`
/// CLEARS the override (back to the default); `0` is an explicit unlimited override.
#[derive(Debug, Deserialize)]
pub struct QuotaForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub owner_sub: String,
    #[serde(default)]
    pub quota_bytes: String,
}

/// `POST /admin/quota` — upsert (or, on a blank value, clear) an owner's quota override, emit
/// the audit trail, then 302 back to `/admin`. CSRF-checked; admin-gated by the router
/// middleware.
pub async fn set_quota(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<QuotaForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let actor = auth::identity(&headers);

    let owner = form.owner_sub.trim();
    if owner.is_empty() || owner.chars().count() > MAX_OWNER_SUB_CHARS {
        return Err(AppError::BadRequest(
            "Enter the owner's subject id.".to_string(),
        ));
    }
    let quota = match form.quota_bytes.trim() {
        "" => None,
        raw => match raw.parse::<i64>() {
            Ok(n) if n >= 0 => Some(n),
            _ => {
                return Err(AppError::BadRequest(
                    "Quota must be a whole number of bytes (0 = unlimited, blank = clear the \
                     override)."
                        .to_string(),
                ))
            }
        },
    };

    state.store.set_quota(owner, quota).await?;
    let detail = match quota {
        Some(n) => format!("quota set to {n} bytes"),
        None => "quota override cleared".to_string(),
    };
    tracing::info!(owner, quota = ?quota, actor = actor.subject, "owner quota updated");
    state.audit.emit(AuditEvent::notice(
        "admin.quota.set",
        &actor.subject,
        owner,
        &detail,
    ));
    Ok(redirect_found("/admin"))
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn render_admin(
    default_quota_bytes: i64,
    viewer_email: &str,
    csrf: &str,
    usage: &[OwnerUsage],
    quotas: &[(String, i64)],
) -> String {
    let default_label = match effective_quota(None, default_quota_bytes) {
        Some(q) => format!("{} per owner", human_size(q)),
        None => "unlimited".to_string(),
    };

    let rows = if usage.is_empty() {
        "<tr><td colspan=\"4\" class=\"empty\">No files stored yet.</td></tr>".to_string()
    } else {
        usage
            .iter()
            .map(|u| {
                let override_bytes = quotas
                    .iter()
                    .find(|(o, _)| o == &u.owner_sub)
                    .map(|(_, q)| *q);
                let effective = effective_quota(override_bytes, default_quota_bytes);
                let quota_cell = match (effective, override_bytes.is_some()) {
                    (Some(q), true) => {
                        format!(
                            "{} <span class=\"muted\">(override)</span>",
                            esc(&human_size(q))
                        )
                    }
                    (None, true) => "Unlimited <span class=\"muted\">(override)</span>".to_string(),
                    (Some(q), false) => {
                        format!(
                            "{} <span class=\"muted\">(default)</span>",
                            esc(&human_size(q))
                        )
                    }
                    (None, false) => "Unlimited".to_string(),
                };
                format!(
                    "<tr>\
                       <td class=\"mono\">{owner}</td>\
                       <td>{files}</td>\
                       <td>{bytes}</td>\
                       <td>{quota_cell}</td>\
                     </tr>",
                    owner = esc(&u.owner_sub),
                    files = u.files,
                    bytes = esc(&human_size(u.bytes)),
                    quota_cell = quota_cell,
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let quota_form = format!(
        "<form class=\"share-form\" method=\"post\" action=\"/admin/quota\">\
           <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
           <div class=\"field\">\
             <label for=\"ownerSub\">Owner subject</label>\
             <input id=\"ownerSub\" type=\"text\" name=\"owner_sub\" maxlength=\"{max_sub}\" \
               placeholder=\"the owner&#x27;s X-Auth-Subject\" required>\
           </div>\
           <div class=\"field\">\
             <label for=\"quotaBytes\">Quota override (bytes)</label>\
             <input id=\"quotaBytes\" type=\"text\" name=\"quota_bytes\" inputmode=\"numeric\" \
               placeholder=\"blank = clear override · 0 = unlimited\">\
           </div>\
           <div class=\"actions\">\
             <button class=\"btn btn-primary\" type=\"submit\">Set quota</button>\
           </div>\
         </form>",
        csrf = esc(csrf),
        max_sub = MAX_OWNER_SUB_CHARS,
    );

    ADMIN_HTML
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{TOPBAR}}", &topbar("Drive admin", Some(viewer_email)))
        .replace("{{FOOTER}}", FOOTER)
        .replace("{{DEFAULT_QUOTA}}", &esc(&default_label))
        .replace("{{ROWS}}", &rows)
        .replace("{{QUOTA_FORM}}", &quota_form)
}
