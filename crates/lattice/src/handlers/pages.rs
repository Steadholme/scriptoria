//! The wiki handlers: index, page view, editor (GET/POST), history, and the 404 fallback.
//!
//! Slug handling is canonical everywhere: the incoming URL slug (and every `[[wiki-link]]`
//! target) is passed through [`slugify`], so `/w/Foo Bar`, `/w/foo-bar` and `[[Foo Bar]]` all
//! resolve to the single page `foo-bar`. The read paths (`/w`, `/history`) additionally 303 to
//! the canonical URL when the request slug isn't already canonical, so the address bar stays
//! clean and there is exactly one URL per page.
//!
//! The editor identity ALWAYS comes from the gateway-injected `X-Auth-Email` — never from a
//! client field — and every state-changing POST is double-submit CSRF checked.

use std::collections::HashSet;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth;
use crate::config::{clamp_page_limit, DEFAULT_PAGE, MAX_PAGE};
use crate::diff::{self, Op};
use crate::error::AppError;
use crate::graph::{self, PagePanel};
use crate::markdown;
use crate::render::{esc, fmt_ts, layout};
use crate::slug::{humanize, slugify};
use crate::store::{Page, Revision, SaveInput};
use crate::{now_ms, AppState};

/// Query for `GET /new` — the title the operator typed into the "new page" box.
#[derive(Debug, Deserialize)]
pub struct NewQuery {
    #[serde(default)]
    pub title: String,
}

/// Query for `GET /` — keyset pagination over the page index. `before=<created_at>_<slug>` is the
/// cursor taken from the previous page's last row (absent = the newest page); `limit` overrides
/// the page size and is clamped into `1..=MAX_PAGE`.
#[derive(Debug, Deserialize)]
pub struct IndexQuery {
    #[serde(default)]
    pub before: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
}

/// The edit form body (`POST /edit/{slug}`). The editor/author is NEVER taken from here.
#[derive(Debug, Deserialize)]
pub struct EditForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub body_md: String,
}

/// Query for `GET /history/{slug}`. With both `from` and `to` set to revision ids, the handler
/// renders the line-level diff between those two revisions instead of the revision list.
#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
}

/// The revert form body (`POST /revert/{slug}`). `rev_id` names the revision whose body is
/// re-saved as a NEW revision. The actor is taken from the gateway, NEVER from here.
#[derive(Debug, Deserialize)]
pub struct RevertForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub rev_id: String,
}

// ---------------------------------------------------------------------------
// GET /  — the page index
// ---------------------------------------------------------------------------

pub async fn index(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<IndexQuery>,
) -> Result<Html<String>, AppError> {
    let before = q.before.as_deref().and_then(parse_before);
    let limit = clamp_page_limit(q.limit.unwrap_or(DEFAULT_PAGE));
    let pages = state.store.list_pages(before, limit).await?;
    // A full page means older pages may exist: derive the next cursor from the last row. A short
    // (or empty) page is the end of the walk, so no "Load older" link is rendered.
    let next = if pages.len() as i64 == limit {
        pages.last().map(|p| (p.created_at, p.slug.clone()))
    } else {
        None
    };
    let content = render_index(&pages, next.as_ref());
    Ok(Html(layout("Knowledge base", &headers, &content)))
}

/// Parse a `?before=<created_at>_<slug>` cursor. Slugs are alnum + hyphen only (never `_`, per
/// [`slugify`]), so the single `_` cleanly separates the numeric `created_at` from the slug;
/// a malformed value is ignored and the request falls back to the newest page.
fn parse_before(raw: &str) -> Option<(i64, String)> {
    let (ts, id) = raw.rsplit_once('_')?;
    let ts = ts.parse::<i64>().ok()?;
    if id.is_empty() {
        None
    } else {
        Some((ts, id.to_string()))
    }
}

fn render_index(pages: &[Page], next: Option<&(i64, String)>) -> String {
    let count = pages.len();
    let head = format!(
        "<div class=\"page-head\">\
           <div>\
             <h1>Knowledge base</h1>\
             <p class=\"muted\">{count} page{plural}</p>\
           </div>\
           <form class=\"newpage\" method=\"get\" action=\"/new\">\
             <input type=\"text\" name=\"title\" placeholder=\"New page title…\" autocomplete=\"off\" aria-label=\"New page title\">\
             <button class=\"btn btn-primary\" type=\"submit\">Create page</button>\
           </form>\
         </div>",
        count = count,
        plural = if count == 1 { "" } else { "s" },
    );

    let list = if pages.is_empty() {
        "<div class=\"list-empty\">No pages yet. Create the first one above — or link to it with \
         <code>[[double brackets]]</code> from any page.</div>"
            .to_string()
    } else {
        let items: String = pages
            .iter()
            .map(|p| {
                format!(
                    "<li class=\"page-list__item\">\
                       <a class=\"page-list__title\" href=\"/w/{slug}\">{title}</a>\
                       <span class=\"page-list__meta\">edited by {email} · {time}</span>\
                     </li>",
                    slug = esc(&p.slug),
                    title = esc(&p.title),
                    email = esc(&p.updated_by_email),
                    time = esc(&fmt_ts(p.updated_at)),
                )
            })
            .collect();
        format!("<ul class=\"page-list\">{items}</ul>")
    };

    // "Load older" only when a full page came back (a next cursor exists). The slug is alnum +
    // hyphen (URL-safe) but still escaped for the attribute; created_at is a plain integer.
    let older = match next {
        Some((ts, slug)) => format!(
            "<nav class=\"pager\"><a class=\"btn btn-secondary\" rel=\"next\" href=\"/?before={ts}_{slug}\">Load older</a></nav>",
            ts = ts,
            slug = esc(slug),
        ),
        None => String::new(),
    };

    format!(
        "{head}<section class=\"card\">{list}</section>{older}\
         <p class=\"site-foot\">HOLDFAST Lattice · server-rendered wiki · Markdown with <code>[[wiki-links]]</code> · <a href=\"/coherence\">Coherence report</a></p>"
    )
}

// ---------------------------------------------------------------------------
// GET /new  — redirect into the editor for a slugified new page
// ---------------------------------------------------------------------------

pub async fn new_page(Query(q): Query<NewQuery>) -> Response {
    let slug = slugify(&q.title);
    if slug.is_empty() {
        return Redirect::to("/").into_response();
    }
    Redirect::to(&format!("/edit/{slug}")).into_response()
}

// ---------------------------------------------------------------------------
// GET /w/{slug}  — render a page, or offer to create it
// ---------------------------------------------------------------------------

pub async fn view(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_slug): Path<String>,
) -> Result<Response, AppError> {
    let slug = slugify(&raw_slug);
    if slug.is_empty() {
        return Ok(Redirect::to("/").into_response());
    }
    if slug != raw_slug {
        return Ok(Redirect::to(&format!("/w/{slug}")).into_response());
    }

    match state.store.get_page(&slug).await? {
        Some(page) => {
            let existing: HashSet<String> = state.store.all_slugs().await?.into_iter().collect();
            let body_html = markdown::render(&page.body_md, &existing);
            // Backlink graph + keyword-related neighbours, computed locally from the page set.
            let panel = graph::Corpus::build(state.store.list_pages(None, MAX_PAGE).await?).panel(&slug);
            let content = render_view(&page, &body_html, &panel);
            Ok(Html(layout(&page.title, &headers, &content)).into_response())
        }
        None => {
            let title = humanize(&slug);
            let content = render_missing(&slug, &title);
            Ok(Html(layout(&title, &headers, &content)).into_response())
        }
    }
}

fn render_view(page: &Page, body_html: &str, panel: &PagePanel) -> String {
    format!(
        "<article class=\"card page\">\
           <div class=\"page__bar\">\
             <div>\
               <h1>{title}</h1>\
               <p class=\"meta\">Last edited by {email} · {time}</p>\
             </div>\
             <div class=\"page__actions\">\
               <a class=\"btn btn-secondary btn-sm\" href=\"/history/{slug}\">History</a>\
               <a class=\"btn btn-primary btn-sm\" href=\"/edit/{slug}\">Edit</a>\
             </div>\
           </div>\
           <div class=\"prose\">{body}</div>\
         </article>{relations}",
        title = esc(&page.title),
        email = esc(&page.updated_by_email),
        time = esc(&fmt_ts(page.updated_at)),
        slug = esc(&page.slug),
        body = body_html,
        relations = render_relations(panel),
    )
}

/// The "Linked from / Related" panel beneath a page. Renders nothing when the page has neither
/// explicit backlinks nor keyword-related neighbours, so simple pages look exactly as before.
fn render_relations(panel: &PagePanel) -> String {
    if panel.is_empty() {
        return String::new();
    }
    let backlinks = render_link_group(
        "Linked from",
        "Pages that reference this one.",
        &panel.backlinks,
    );
    let related = render_link_group(
        "Related",
        "Pages with overlapping terms (heuristic).",
        &panel.related,
    );
    format!("<aside class=\"card relations\">{backlinks}{related}</aside>")
}

fn render_link_group(heading: &str, hint: &str, links: &[graph::LinkRef]) -> String {
    if links.is_empty() {
        return String::new();
    }
    let items: String = links
        .iter()
        .map(|l| {
            format!(
                "<li><a href=\"/w/{slug}\">{title}</a></li>",
                slug = esc(&l.slug),
                title = esc(&l.title),
            )
        })
        .collect();
    format!(
        "<div class=\"relations__group\">\
           <h2 class=\"relations__title\">{heading}</h2>\
           <p class=\"relations__hint\">{hint}</p>\
           <ul class=\"relations__list\">{items}</ul>\
         </div>",
        heading = esc(heading),
        hint = esc(hint),
        items = items,
    )
}

fn render_missing(slug: &str, title: &str) -> String {
    format!(
        "<section class=\"card empty-state\">\
           <h1>{title}</h1>\
           <p class=\"muted\">This page doesn’t exist yet.</p>\
           <a class=\"btn btn-primary\" href=\"/edit/{slug}\">Create this page</a>\
         </section>",
        title = esc(title),
        slug = esc(slug),
    )
}

// ---------------------------------------------------------------------------
// GET /edit/{slug}  — the editor (mints a CSRF token)
// ---------------------------------------------------------------------------

pub async fn edit_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_slug): Path<String>,
) -> Result<Response, AppError> {
    let slug = slugify(&raw_slug);
    if slug.is_empty() {
        return Ok(Redirect::to("/").into_response());
    }

    let existing = state.store.get_page(&slug).await?;
    let (title, body, exists) = match &existing {
        Some(p) => (p.title.clone(), p.body_md.clone(), true),
        None => (humanize(&slug), String::new(), false),
    };

    let csrf = auth::new_csrf_token();
    let content = render_editor(&slug, &title, &body, &csrf, exists);
    let page_title = format!("{} {}", if exists { "Edit" } else { "Create" }, title);
    let html = layout(&page_title, &headers, &content);
    Ok(html_with_csrf_cookie(html, &csrf))
}

fn render_editor(slug: &str, title: &str, body: &str, csrf: &str, exists: bool) -> String {
    format!(
        "<form class=\"card editor\" method=\"post\" action=\"/edit/{slug}\">\
           <div class=\"editor__head\">\
             <h1>{verb} page</h1>\
             <code>/w/{slug}</code>\
           </div>\
           <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
           <div class=\"editor__field\">\
             <label for=\"title\">Title</label>\
             <input id=\"title\" type=\"text\" name=\"title\" value=\"{title}\" autocomplete=\"off\" required>\
           </div>\
           <div class=\"editor__field\">\
             <label for=\"body\">Body</label>\
             <textarea id=\"body\" name=\"body_md\" rows=\"22\" spellcheck=\"false\">{body}</textarea>\
             <p class=\"editor__hint\">Markdown supported. Link to other pages with <code>[[Page Name]]</code> or <code>[[slug|label]]</code>. Raw HTML is escaped.</p>\
           </div>\
           <div class=\"editor__actions\">\
             <a class=\"btn btn-secondary\" href=\"/w/{slug}\">Cancel</a>\
             <button class=\"btn btn-primary\" type=\"submit\">Save page</button>\
           </div>\
         </form>",
        slug = esc(slug),
        verb = if exists { "Edit" } else { "Create" },
        csrf = esc(csrf),
        title = esc(title),
        body = esc(body),
    )
}

// ---------------------------------------------------------------------------
// POST /edit/{slug}  — save a revision + update the page
// ---------------------------------------------------------------------------

pub async fn edit_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_slug): Path<String>,
    Form(form): Form<EditForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::Forbidden(
            "CSRF token missing or invalid — reload the editor and try again.".to_string(),
        ));
    }

    let slug = slugify(&raw_slug);
    if slug.is_empty() {
        return Ok(Redirect::to("/").into_response());
    }

    // Identity is authoritative from the gateway; fall back only for direct dev hits.
    let editor_email = auth::signed_in_email(&headers).unwrap_or_else(|| "anonymous".to_string());

    let title = {
        let t = form.title.trim();
        if t.is_empty() {
            humanize(&slug)
        } else {
            t.to_string()
        }
    };

    let saved = state
        .store
        .save_page(SaveInput {
            slug: slug.clone(),
            title,
            body_md: form.body_md,
            editor_email,
            now: now_ms(),
            revision_id: auth::random_hex(),
        })
        .await?;

    // Tamper-evident audit trail: record the save AFTER the store commit succeeds. A brand-new
    // page has `created_at == updated_at`; an edit keeps its earlier `created_at`. The event only
    // carries logical fields (actor / slug / create|edit) — the page body NEVER rides an event.
    let detail = if saved.created_at == saved.updated_at {
        "create"
    } else {
        "edit"
    };
    state.audit.emit(AuditEvent::info(
        "page.save",
        &saved.updated_by_email,
        &saved.slug,
        detail,
    ));

    Ok(Redirect::to(&format!("/w/{slug}")).into_response())
}

// ---------------------------------------------------------------------------
// GET /history/{slug}  — the revision list (or a two-revision diff)
// ---------------------------------------------------------------------------

pub async fn history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_slug): Path<String>,
    Query(q): Query<HistoryQuery>,
) -> Result<Response, AppError> {
    let slug = slugify(&raw_slug);
    if slug.is_empty() {
        return Ok(Redirect::to("/").into_response());
    }
    if slug != raw_slug {
        return Ok(Redirect::to(&format!("/history/{slug}")).into_response());
    }

    let page = state.store.get_page(&slug).await?;
    let title = page.as_ref().map(|p| p.title.clone()).unwrap_or_else(|| humanize(&slug));

    // Diff view: both endpoints selected AND both resolve (scoped to this slug). An unknown/foreign
    // id falls through to the plain revision list rather than erroring.
    if let (Some(from_id), Some(to_id)) = (q.from.as_deref(), q.to.as_deref()) {
        let from = state.store.get_revision(&slug, from_id).await?;
        let to = state.store.get_revision(&slug, to_id).await?;
        if let (Some(from), Some(to)) = (from, to) {
            let content = render_diff(&slug, &title, &from, &to);
            return Ok(Html(layout(&format!("Diff · {title}"), &headers, &content)).into_response());
        }
    }

    let revs = state.store.list_revisions(&slug).await?;
    // Mint a CSRF token so the per-revision revert buttons can double-submit (same idiom as the
    // editor). The list is a GET, so we also set the cookie on the response.
    let csrf = auth::new_csrf_token();
    let content = render_history(&slug, &title, &revs, page.is_some(), &csrf);
    let html = layout(&format!("History · {title}"), &headers, &content);
    Ok(html_with_csrf_cookie(html, &csrf))
}

fn render_history(
    slug: &str,
    title: &str,
    revs: &[Revision],
    page_exists: bool,
    csrf: &str,
) -> String {
    let back = if page_exists {
        format!("<a class=\"btn btn-secondary btn-sm\" href=\"/w/{}\">Back to page</a>", esc(slug))
    } else {
        format!("<a class=\"btn btn-primary btn-sm\" href=\"/edit/{}\">Create this page</a>", esc(slug))
    };

    let rows = if revs.is_empty() {
        "<tr><td class=\"empty\" colspan=\"4\">No revisions recorded for this page.</td></tr>".to_string()
    } else {
        revs.iter()
            .enumerate()
            .map(|(i, r)| {
                // The newest revision IS the current page body — reverting to it is a no-op, so it
                // shows a "current" badge instead of a revert button.
                let action = if i == 0 {
                    "<span class=\"badge\">current</span>".to_string()
                } else {
                    format!(
                        "<form class=\"revert-form\" method=\"post\" action=\"/revert/{slug}\">\
                           <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                           <input type=\"hidden\" name=\"rev_id\" value=\"{rid}\">\
                           <button class=\"btn btn-secondary btn-sm\" type=\"submit\">Revert to this</button>\
                         </form>",
                        slug = esc(slug),
                        csrf = esc(csrf),
                        rid = esc(&r.id),
                    )
                };
                format!(
                    "<tr>\
                       <td class=\"h-when\"><time>{when}</time></td>\
                       <td class=\"h-editor\">{editor}</td>\
                       <td class=\"h-size\">{chars} chars</td>\
                       <td class=\"h-act\">{action}</td>\
                     </tr>",
                    when = esc(&fmt_ts(r.ts)),
                    editor = esc(&r.editor_email),
                    chars = r.body_md.chars().count(),
                    action = action,
                )
            })
            .collect::<String>()
    };

    // Compare form: pick two revisions -> the line diff. Only offered when there are ≥2. Defaults
    // to `from = second-newest`, `to = newest`, i.e. "what changed in the latest edit".
    let compare = if revs.len() >= 2 {
        let from_opts = rev_options(revs, &revs[1].id);
        let to_opts = rev_options(revs, &revs[0].id);
        format!(
            "<form class=\"compare-form\" method=\"get\" action=\"/history/{slug}\">\
               <label>From <select name=\"from\">{from_opts}</select></label>\
               <label>To <select name=\"to\">{to_opts}</select></label>\
               <button class=\"btn btn-secondary btn-sm\" type=\"submit\">Compare</button>\
             </form>",
            slug = esc(slug),
            from_opts = from_opts,
            to_opts = to_opts,
        )
    } else {
        String::new()
    };

    format!(
        "<div class=\"page-head\">\
           <div><h1>History</h1><p class=\"muted\">{title}</p></div>\
           {back}\
         </div>\
         {compare}\
         <section class=\"card\">\
           <table class=\"history\">\
             <thead><tr><th>When (UTC)</th><th>Editor</th><th>Size</th><th>Action</th></tr></thead>\
             <tbody>{rows}</tbody>\
           </table>\
         </section>",
        title = esc(title),
        back = back,
        compare = compare,
        rows = rows,
    )
}

/// `<option>`s for a revision picker, marking `selected` as the pre-selected default.
fn rev_options(revs: &[Revision], selected: &str) -> String {
    revs.iter()
        .map(|r| {
            let sel = if r.id == selected { " selected" } else { "" };
            format!(
                "<option value=\"{id}\"{sel}>{when} · {editor}</option>",
                id = esc(&r.id),
                sel = sel,
                when = esc(&fmt_ts(r.ts)),
                editor = esc(&r.editor_email),
            )
        })
        .collect()
}

/// Render the line-level diff between two revisions. Every line is escaped; the LCS keeps shared
/// lines as context so only true `+`/`-` changes stand out.
fn render_diff(slug: &str, title: &str, from: &Revision, to: &Revision) -> String {
    let lines = diff::line_diff(&from.body_md, &to.body_md);
    let adds = lines.iter().filter(|l| l.op == Op::Insert).count();
    let dels = lines.iter().filter(|l| l.op == Op::Delete).count();

    let body = if lines.is_empty() {
        "<div class=\"diff__empty\">Both revisions are empty.</div>".to_string()
    } else {
        lines
            .iter()
            .map(|l| {
                let (cls, sign) = match l.op {
                    Op::Equal => ("diff__line diff__line--ctx", ' '),
                    Op::Delete => ("diff__line diff__line--del", '-'),
                    Op::Insert => ("diff__line diff__line--add", '+'),
                };
                format!(
                    "<div class=\"{cls}\"><span class=\"diff__sign\">{sign}</span><span class=\"diff__text\">{text}</span></div>",
                    cls = cls,
                    sign = sign,
                    text = esc(&l.text),
                )
            })
            .collect::<String>()
    };

    format!(
        "<div class=\"page-head\">\
           <div><h1>Diff</h1><p class=\"muted\">{title}</p></div>\
           <a class=\"btn btn-secondary btn-sm\" href=\"/history/{slug}\">Back to history</a>\
         </div>\
         <section class=\"card\">\
           <p class=\"diff__summary\">Comparing {from_when} → {to_when} · \
             <span class=\"diff__stat diff__stat--add\">+{adds}</span> \
             <span class=\"diff__stat diff__stat--del\">−{dels}</span></p>\
           <div class=\"diff\">{body}</div>\
         </section>",
        title = esc(title),
        slug = esc(slug),
        from_when = esc(&fmt_ts(from.ts)),
        to_when = esc(&fmt_ts(to.ts)),
        adds = adds,
        dels = dels,
        body = body,
    )
}

// ---------------------------------------------------------------------------
// POST /revert/{slug}  — re-save an old revision's body as a new revision
// ---------------------------------------------------------------------------

pub async fn revert_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_slug): Path<String>,
    Form(form): Form<RevertForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::Forbidden(
            "CSRF token missing or invalid — reload the history and try again.".to_string(),
        ));
    }

    let slug = slugify(&raw_slug);
    if slug.is_empty() {
        return Ok(Redirect::to("/").into_response());
    }

    // The page must exist to revert it; keep its current title (revert only restores the body).
    let Some(page) = state.store.get_page(&slug).await? else {
        return Ok(Redirect::to(&format!("/w/{slug}")).into_response());
    };

    // Resolve the target revision scoped to this slug; a bogus/foreign id is a no-op back to
    // history (never writes, never errors).
    let Some(target) = state.store.get_revision(&slug, &form.rev_id).await? else {
        return Ok(Redirect::to(&format!("/history/{slug}")).into_response());
    };

    // Identity is authoritative from the gateway; fall back only for direct dev hits.
    let editor_email = auth::signed_in_email(&headers).unwrap_or_else(|| "anonymous".to_string());

    // Append the restored body as a NEW revision — history stays append-only, nothing is rewritten.
    state
        .store
        .save_page(SaveInput {
            slug: slug.clone(),
            title: page.title,
            body_md: target.body_md,
            editor_email: editor_email.clone(),
            now: now_ms(),
            revision_id: auth::random_hex(),
        })
        .await?;

    // A revert is a deliberate rollback → notice severity. Value-free detail only.
    state.audit.emit(AuditEvent::notice("page.revert", &editor_email, &slug, "revert"));

    Ok(Redirect::to(&format!("/w/{slug}")).into_response())
}

// ---------------------------------------------------------------------------
// Fallback — 404
// ---------------------------------------------------------------------------

pub async fn not_found(headers: HeaderMap) -> Response {
    let content = "<section class=\"card empty-state\">\
           <div class=\"empty-state__code\">404</div>\
           <h1>Not found</h1>\
           <p class=\"muted\">There is no such route. Pages live under <code>/w/&lt;slug&gt;</code>.</p>\
           <a class=\"btn btn-primary\" href=\"/\">Back to the index</a>\
         </section>";
    (
        StatusCode::NOT_FOUND,
        Html(layout("Not found", &headers, content)),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Build an HTML response that also sets the double-submit CSRF cookie.
fn html_with_csrf_cookie(body: String, csrf: &str) -> Response {
    let mut response = Html(body).into_response();
    if let Ok(value) = header::HeaderValue::from_str(&auth::csrf_cookie(csrf)) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}
