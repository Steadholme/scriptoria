//! The SSO pastebin surface: new-paste form, create, view, raw, delete.
//!
//! Mounted behind a Sluice `auth=sso` route: the gateway authenticates the user and injects
//! `X-Auth-Subject` / `X-Auth-Email`, which we trust (Pastefire is internal-only). The author
//! of a paste is ALWAYS those headers — never a client-supplied field. State-changing POSTs
//! (`create`, `delete`) carry a double-submit CSRF token. Every producer-supplied string is
//! HTML-escaped on render, and the raw endpoint serves `text/plain` (+ `nosniff`), so a paste
//! body can never execute as HTML.

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth::{self, Identity};
use crate::config::{MAX_BODY_BYTES, MAX_TITLE_CHARS};
use crate::error::AppError;
use crate::handlers::{
    esc, expiry_options, fmt_ts, language_label, language_options, parse_expiry, userbox, APP_CSS,
    LANGUAGES, SHIELD_SVG,
};
use crate::model::Paste;
use crate::{highlight, now_secs, random_alnum, similar, AppState};

/// Length of the short random paste id (62-symbol alphabet => ~48 bits at 8 chars; the
/// `ON CONFLICT` insert retries on the astronomically rare collision).
const PASTE_ID_LEN: usize = 8;

const NEW_HTML: &str = include_str!("../../templates/new.html");
const VIEW_HTML: &str = include_str!("../../templates/view.html");

// ---------------------------------------------------------------------------
// GET / — new-paste form + "my recent pastes"
// ---------------------------------------------------------------------------

/// `GET /` — render the new-paste form (with a fresh CSRF token) and the author's recent
/// pastes.
pub async fn new_form(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let who = auth::identity(&headers);
    let now = now_secs();
    let csrf = auth::new_csrf_token();
    let recent = state
        .store
        .list_by_author(&who.subject, now)
        .await
        .unwrap_or_default();

    let html = render_new(&who, &csrf, &recent, None, "", "plaintext", "never", false, "");
    html_with_csrf(StatusCode::OK, html, &csrf)
}

// ---------------------------------------------------------------------------
// POST / — create a paste
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub language: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub expiry: String,
    /// Burn-after-read toggle. An unchecked checkbox is omitted from the body, so the default
    /// (empty) reads as `false` — existing POSTs that never send this field keep their behavior.
    #[serde(default)]
    pub burn: String,
}

/// Interpret a checkbox form value: present and non-empty (e.g. `on`) => checked.
fn checkbox_on(value: &str) -> bool {
    !value.trim().is_empty()
}

/// `POST /` — validate + store a paste, then 302 to `/p/{id}`. On a validation error the form
/// is re-rendered (preserving the user's input) with an inline message.
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and submit again.".to_string(),
        ));
    }

    let who = auth::identity(&headers);
    let now = now_secs();
    let title = form.title.trim();

    // Validation: a non-empty, bounded body. On failure re-render the form with the input
    // intact and a fresh CSRF token.
    if let Some(msg) = body_problem(&form.body) {
        let csrf = auth::new_csrf_token();
        let recent = state
            .store
            .list_by_author(&who.subject, now)
            .await
            .unwrap_or_default();
        let html = render_new(
            &who,
            &csrf,
            &recent,
            Some(msg),
            title,
            &form.language,
            &form.expiry,
            checkbox_on(&form.burn),
            &form.body,
        );
        return Ok(html_with_csrf(StatusCode::BAD_REQUEST, html, &csrf));
    }

    let mut paste = Paste {
        id: String::new(),
        title: title.chars().take(MAX_TITLE_CHARS).collect(),
        body: form.body,
        language: normalize_language(&form.language),
        author_sub: who.subject.clone(),
        author_email: who.email.clone(),
        created_at: now,
        expires_at: parse_expiry(&form.expiry, now),
        burn_after_read: checkbox_on(&form.burn),
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

    tracing::info!(id = paste.id, author = who.subject, "paste created");

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

/// `GET /p/{id}` — render the paste (honoring expiry), syntax-highlighted, with a "similar
/// pastes" panel. The delete control is shown only to the author. A burn-after-read paste is
/// deleted after this render when the viewer is NOT its author (so the author can still open it
/// to copy the share link; the first recipient read consumes it).
pub async fn view(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let viewer = auth::identity(&headers);
    let now = now_secs();

    let paste = match state.store.get(&id).await? {
        Some(p) if !p.is_expired(now) => p,
        Some(_) => {
            return Err(AppError::NotFound(
                "This paste has expired and is no longer available.".to_string(),
            ))
        }
        None => return Err(AppError::NotFound("No paste exists at that link.".to_string())),
    };

    let is_owner = paste.author_sub == viewer.subject;
    let burned = paste.burn_after_read && !is_owner;

    // Similar pastes: rank the author's other live, non-burn pastes by BoW cosine overlap.
    let similar = similar_pastes(&state, &paste, now).await;

    let csrf = auth::new_csrf_token();
    let html = render_view(&paste, &viewer, is_owner, burned, &similar, &csrf);

    // Burn-after-read: this recipient's read consumes the paste. Best-effort, never fatal — a
    // failed purge leaves the paste readable rather than 500-ing on a successful render.
    if burned {
        if let Err(e) = state.store.delete(&paste.id, &paste.author_sub).await {
            tracing::warn!(id = paste.id, error = %e, "burn-after-read purge failed");
        } else {
            tracing::info!(id = paste.id, viewer = viewer.subject, "paste burned after read");
        }
    }

    Ok(html_with_csrf(StatusCode::OK, html, &csrf))
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
// Rendering helpers
// ---------------------------------------------------------------------------

/// Validate the submitted body. Returns a user-facing message when it is unacceptable.
fn body_problem(body: &str) -> Option<&'static str> {
    if body.trim().is_empty() {
        return Some("Paste body cannot be empty.");
    }
    if body.len() > MAX_BODY_BYTES {
        return Some("Paste is too large (256 KiB maximum).");
    }
    None
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

#[allow(clippy::too_many_arguments)]
fn render_new(
    who: &Identity,
    csrf: &str,
    recent: &[Paste],
    error: Option<&str>,
    title: &str,
    language: &str,
    expiry: &str,
    burn: bool,
    body: &str,
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
        .replace("{{BODY}}", &esc(body))
        .replace("{{CSRF}}", &esc(csrf))
        .replace("{{RECENT}}", &render_recent(recent))
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

fn render_view(
    paste: &Paste,
    viewer: &Identity,
    is_owner: bool,
    burned: bool,
    similar: &[(f64, Paste)],
    csrf: &str,
) -> String {
    let title = if paste.title.trim().is_empty() {
        "Untitled paste".to_string()
    } else {
        paste.title.clone()
    };
    let expiry = match paste.expires_at {
        Some(exp) => format!("Expires {}", fmt_ts(exp)),
        None => "Never expires".to_string(),
    };
    let burn_meta = if paste.burn_after_read {
        " · Burn after read"
    } else {
        ""
    };
    let meta = format!(
        "Created {created} by {author} · {expiry}{burn}",
        created = esc(&fmt_ts(paste.created_at)),
        author = esc(&paste.author_email),
        expiry = esc(&expiry),
        burn = burn_meta,
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

    // The delete control is owner-only; it carries the double-submit CSRF token.
    let delete_block = if is_owner {
        format!(
            "<form class=\"delete-form\" method=\"post\" action=\"/delete/{id}\" \
               onsubmit=\"return confirm('Delete this paste? This cannot be undone.');\">\
               <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
               <button class=\"btn btn-danger btn-sm\" type=\"submit\">Delete</button>\
             </form>",
            id = esc(&paste.id),
            csrf = esc(csrf),
        )
    } else {
        String::new()
    };

    VIEW_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("View paste", Some(&viewer.email)))
        .replace("{{TITLE}}", &esc(&title))
        .replace("{{LANG_LABEL}}", &esc(&language_label(&paste.language)))
        .replace("{{META}}", &meta)
        .replace("{{BURN_NOTICE}}", &burn_notice)
        .replace("{{ID}}", &esc(&paste.id))
        .replace("{{DELETE}}", &delete_block)
        // Syntax-highlighted body. `highlight` HTML-escapes every character (and falls back to
        // plain `esc` for plaintext/unknown languages), so this is never less safe than before.
        .replace("{{BODY}}", &highlight::highlight(&paste.language, &paste.body))
        .replace("{{SIMILAR}}", &render_similar(similar))
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
