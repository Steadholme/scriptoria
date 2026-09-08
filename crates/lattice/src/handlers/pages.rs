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

use std::collections::{BTreeMap, BTreeSet, HashSet};

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
use crate::store::{Page, RecentEntry, Revision, SaveInput};
use crate::{now_ms, AppState};

/// Query for `GET /new` — the title the operator typed into the "new page" box.
#[derive(Debug, Deserialize)]
pub struct NewQuery {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub template: String,
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

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    pub q: String,
}

/// Query for `GET /recent` — keyset pagination over all revisions. `before=<ts>_<rev_id>` is the
/// cursor taken from the previous page's last row (absent = the newest revision).
#[derive(Debug, Deserialize)]
pub struct RecentQuery {
    #[serde(default)]
    pub before: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
}

/// The edit form body (`POST /edit/{slug}`). The editor/author is NEVER taken from here.
/// `base_rev` is the head revision id the editor was loaded against — the save is rejected as a
/// conflict when it no longer matches the current head (someone else saved in between).
#[derive(Debug, Deserialize)]
pub struct EditForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub body_md: String,
    #[serde(default)]
    pub base_rev: String,
}

/// Query for `GET /edit/{slug}`. A trusted template id can prefill brand-new pages.
#[derive(Debug, Deserialize)]
pub struct EditQuery {
    #[serde(default)]
    pub template: String,
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

/// The move form body (`POST /move/{slug}`). `parent_id` is a page slug selected from the UI;
/// blank means top-level. The actor is taken from the gateway, NEVER from here.
#[derive(Debug, Deserialize)]
pub struct MoveForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub parent_id: String,
}

struct PageTemplate {
    id: &'static str,
    label: &'static str,
    body: &'static str,
}

const PAGE_TEMPLATES: &[PageTemplate] = &[
    PageTemplate {
        id: "meeting-notes",
        label: "Meeting notes",
        body: "# Meeting notes\n\n## Attendees\n\n- \n\n## Agenda\n\n- \n\n## Notes\n\n\n## Action items\n\n- [ ] ",
    },
    PageTemplate {
        id: "how-to",
        label: "How-to",
        body: "# How-to\n\n## Goal\n\n\n## Prerequisites\n\n- \n\n## Steps\n\n1. \n\n## Verification\n\n",
    },
    PageTemplate {
        id: "decision-record",
        label: "Decision record",
        body: "# Decision record\n\n## Context\n\n\n## Decision\n\n\n## Consequences\n\n",
    },
];

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
    // The Library orientation uses the bounded hierarchy alongside the paginated directory.
    // Its activity pulse is derived from this same result, avoiding another revision-body query.
    let structure_pages = state.store.list_pages(None, MAX_PAGE).await?;
    // A full page means older pages may exist: derive the next cursor from the last row. A short
    // (or empty) page is the end of the walk, so no "Load older" link is rendered.
    let next = if pages.len() as i64 == limit {
        pages.last().map(|p| (p.created_at, p.slug.clone()))
    } else {
        None
    };
    let content = render_index(&pages, &structure_pages, next.as_ref());
    Ok(Html(layout("Library", &headers, &content)))
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

pub async fn search(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SearchQuery>,
) -> Result<Html<String>, AppError> {
    let raw = query.q.trim();
    let needle = raw.to_lowercase();
    let mut pages = if needle.is_empty() {
        Vec::new()
    } else {
        state
            .store
            .list_pages(None, MAX_PAGE)
            .await?
            .into_iter()
            .filter(|page| {
                page.title.to_lowercase().contains(&needle)
                    || page.slug.to_lowercase().contains(&needle)
                    || page.body_md.to_lowercase().contains(&needle)
            })
            .collect::<Vec<_>>()
    };
    pages.sort_by_key(|page| {
        let title = page.title.to_lowercase();
        if title == needle {
            0
        } else if title.starts_with(&needle) {
            1
        } else if title.contains(&needle) {
            2
        } else {
            3
        }
    });

    let results = pages
        .iter()
        .map(|page| {
            let excerpt = page
                .body_md
                .lines()
                .map(str::trim)
                .find(|line| !line.is_empty() && !line.starts_with('#'))
                .unwrap_or("Open this document to read its contents.");
            let excerpt = excerpt.chars().take(220).collect::<String>();
            format!(
                "<li class=\"search-page__result\"><h2><a href=\"/w/{slug}\">{title}</a></h2><p>{excerpt}</p><small>Updated {updated}</small></li>",
                slug = esc(&page.slug),
                title = esc(&page.title),
                excerpt = esc(&excerpt),
                updated = esc(&fmt_ts(page.updated_at)),
            )
        })
        .collect::<String>();
    let result_block = if raw.is_empty() {
        "<div class=\"empty-state\"><h2>Find a document</h2><p>Search titles, page names, and document text.</p></div>".to_string()
    } else if pages.is_empty() {
        "<div class=\"empty-state\"><h2>No matching documents</h2><p>Try a shorter phrase or browse the page tree.</p><a class=\"btn btn-secondary\" href=\"/\">Browse the library</a></div>".to_string()
    } else {
        format!(
            "<p class=\"muted\">{} result{}</p><ol class=\"search-page__results\">{results}</ol>",
            pages.len(),
            if pages.len() == 1 { "" } else { "s" },
        )
    };
    let content = format!(
        "<section class=\"search-page\"><p class=\"eyebrow\">Knowledge search</p><h1>Search documents</h1><form class=\"search-page__form\" role=\"search\" method=\"get\" action=\"/search\"><label class=\"sr-only\" for=\"search-page-query\">Search documents</label><input id=\"search-page-query\" type=\"search\" name=\"q\" value=\"{query}\" placeholder=\"Title, topic, or phrase\" autofocus><button class=\"btn btn-primary\" type=\"submit\">Search</button></form>{result_block}</section>",
        query = esc(raw),
    );
    Ok(Html(layout("Search", &headers, &content)))
}

fn render_index(
    pages: &[Page],
    structure_pages: &[Page],
    next: Option<&(i64, String)>,
) -> String {
    let total = structure_pages.len();
    let roots = structure_pages
        .iter()
        .filter(|page| page.parent_id.is_none())
        .count();
    let hero = format!(
        "<section class=\"library-hero\">\
           <div class=\"library-hero__copy\">\
             <p class=\"eyebrow\">Knowledge base</p>\
             <h1>Library</h1>\
             <p>Find the source of truth, follow its context, and keep operational knowledge coherent.</p>\
           </div>\
           <form class=\"newpage library-create\" method=\"get\" action=\"/new\">\
             <label for=\"library-title\">Start a document</label>\
             <div class=\"library-create__row\">\
               <input id=\"library-title\" type=\"text\" name=\"title\" placeholder=\"Document title…\" autocomplete=\"off\" required>\
               <select name=\"template\" aria-label=\"Page template\">{templates}</select>\
               <button class=\"btn btn-primary\" type=\"submit\">Create</button>\
             </div>\
           </form>\
         </section>",
        templates = render_template_options(""),
    );

    let structure = if structure_pages.is_empty() {
        "<div class=\"list-empty library-empty\"><strong>No pages yet.</strong> Create the first document above, or connect one with <code>[[double brackets]]</code>.</div>".to_string()
    } else {
        format!(
            "<ul class=\"library-tree\">{}</ul>",
            render_tree_items(structure_pages, "")
        )
    };

    let directory = if pages.is_empty() {
        "<div class=\"list-empty\">No pages yet.</div>".to_string()
    } else {
        let items: String = pages
            .iter()
            .map(|page| {
                format!(
                    "<li class=\"page-list__item\">\
                       <a class=\"page-list__title\" href=\"/w/{slug}\">{title}</a>\
                       <span class=\"page-list__meta\">{email} · {time}</span>\
                     </li>",
                    slug = esc(&page.slug),
                    title = esc(&page.title),
                    email = esc(&page.updated_by_email),
                    time = esc(&fmt_ts(page.updated_at)),
                )
            })
            .collect();
        format!("<ul class=\"page-list\">{items}</ul>")
    };

    let mut latest: Vec<&Page> = structure_pages.iter().collect();
    latest.sort_by(|a, b| {
        b.updated_at
            .cmp(&a.updated_at)
            .then_with(|| b.slug.cmp(&a.slug))
    });
    latest.truncate(6);
    let activity = if latest.is_empty() {
        "<p class=\"library-rail__empty\">No changes yet.</p>".to_string()
    } else {
        let items: String = latest
            .iter()
            .map(|page| {
                format!(
                    "<li>\
                       <span class=\"library-timeline__mark\" aria-hidden=\"true\"></span>\
                       <div><a href=\"/w/{slug}\">{title}</a>\
                       <span>{editor} · {time}</span></div>\
                     </li>",
                    slug = esc(&page.slug),
                    title = esc(&page.title),
                    editor = esc(&page.updated_by_email),
                    time = esc(&fmt_ts(page.updated_at)),
                )
            })
            .collect();
        format!("<ol class=\"library-timeline\">{items}</ol>")
    };

    let older = match next {
        Some((ts, slug)) => format!(
            "<nav class=\"pager\"><a class=\"btn btn-secondary\" rel=\"next\" href=\"/?before={ts}_{slug}\">Load older</a></nav>",
            ts = ts,
            slug = esc(slug),
        ),
        None => String::new(),
    };

    format!(
        "{hero}\
         <div class=\"knowledge-library\">\
           <div class=\"library-main\">\
             <section class=\"library-section library-structure\">\
               <div class=\"section-heading\"><div><p class=\"eyebrow\">Browse</p><h2>Knowledge map</h2></div><span>{total} page{plural} · {roots} root{root_plural}</span></div>\
               {structure}\
             </section>\
             <section class=\"library-section library-directory\">\
               <div class=\"section-heading\"><div><p class=\"eyebrow\">Directory</p><h2>All documents</h2></div></div>\
               {directory}{older}\
             </section>\
           </div>\
           <aside class=\"library-rail\" aria-label=\"Workspace overview\">\
             <a class=\"coherence-entry\" href=\"/coherence\">\
               <span class=\"coherence-entry__signal\" aria-hidden=\"true\"></span>\
               <span><strong>Workspace health</strong><small>Review stale or contradictory knowledge</small></span>\
               <span aria-hidden=\"true\">→</span>\
             </a>\
             <section class=\"library-activity\">\
               <div class=\"section-heading\"><div><p class=\"eyebrow\">Activity</p><h2>Recently updated</h2></div><a href=\"/recent\">View all</a></div>\
               {activity}\
             </section>\
             <section class=\"library-principle\">\
               <p class=\"eyebrow\">Working model</p>\
               <p>Documents become useful when their ownership, history, and relationships stay visible.</p>\
             </section>\
           </aside>\
         </div>\
         <p class=\"site-foot\">Steadholme Lattice · Markdown with <code>[[wiki-links]]</code> · revision-safe by default</p>",
        plural = if total == 1 { "" } else { "s" },
        root_plural = if roots == 1 { "" } else { "s" },
    )
}

// ---------------------------------------------------------------------------
// GET /recent  — cross-page recent changes
// ---------------------------------------------------------------------------

pub async fn recent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<RecentQuery>,
) -> Result<Html<String>, AppError> {
    let before = q.before.as_deref().and_then(parse_before);
    let limit = clamp_page_limit(q.limit.unwrap_or(DEFAULT_PAGE));
    let entries = state.store.recent_revisions(before, limit).await?;
    let next = if entries.len() as i64 == limit {
        entries.last().map(|e| (e.rev.ts, e.rev.id.clone()))
    } else {
        None
    };
    let content = render_recent(&entries, next.as_ref());
    Ok(Html(layout("Recent changes", &headers, &content)))
}

fn render_recent(entries: &[RecentEntry], next: Option<&(i64, String)>) -> String {
    let count = entries.len();
    let head = format!(
        "<div class=\"page-head\">\
           <div>\
             <h1>Recent changes</h1>\
             <p class=\"muted\">{count} change{plural}</p>\
           </div>\
           <a class=\"btn btn-secondary btn-sm\" href=\"/\">Back to the index</a>\
         </div>",
        count = count,
        plural = if count == 1 { "" } else { "s" },
    );

    let rows = if entries.is_empty() {
        "<tr><td class=\"empty\" colspan=\"5\">No changes yet.</td></tr>".to_string()
    } else {
        entries
            .iter()
            .map(|entry| {
                let badge = if entry.rev.ts == entry.page_created_at {
                    "created"
                } else {
                    "edited"
                };
                format!(
                    "<tr class=\"recent-row\">\
                       <td class=\"c-title\"><a href=\"/w/{slug}\">{title}</a> <span class=\"badge\">{badge}</span></td>\
                       <td class=\"h-editor\">{editor}</td>\
                       <td class=\"h-when\"><time>{when}</time></td>\
                       <td class=\"h-size\">{chars}</td>\
                       <td class=\"h-act\"><a class=\"btn btn-secondary btn-sm\" href=\"/history/{slug}\">History</a></td>\
                     </tr>",
                    slug = esc(&entry.rev.slug),
                    title = esc(&entry.title),
                    badge = badge,
                    editor = esc(&entry.rev.editor_email),
                    when = esc(&fmt_ts(entry.rev.ts)),
                    chars = entry.rev.body_md.chars().count(),
                )
            })
            .collect::<String>()
    };

    let older = match next {
        Some((ts, id)) => format!(
            "<nav class=\"pager\"><a class=\"btn btn-secondary\" rel=\"next\" href=\"/recent?before={ts}_{id}&limit={limit}\">Load older</a></nav>",
            ts = ts,
            id = esc(id),
            limit = entries.len(),
        ),
        None => String::new(),
    };

    format!(
        "{head}<section class=\"card\">\
           <table class=\"history\">\
             <thead><tr><th>Page</th><th>Editor</th><th>When (UTC)</th><th>Size</th><th>History</th></tr></thead>\
             <tbody>{rows}</tbody>\
           </table>\
         </section>{older}"
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
    let target = match template_for(&q.template) {
        Some(t) => format!("/edit/{slug}?template={}", t.id),
        None => format!("/edit/{slug}"),
    };
    Redirect::to(&target).into_response()
}

fn template_for(raw: &str) -> Option<&'static PageTemplate> {
    let trimmed = raw.trim();
    PAGE_TEMPLATES
        .iter()
        .find(|t| t.id == trimmed || t.label.eq_ignore_ascii_case(trimmed))
}

fn template_body(raw: &str) -> &'static str {
    template_for(raw).map(|t| t.body).unwrap_or("")
}

fn render_template_options(selected: &str) -> String {
    let mut out = String::from("<option value=\"\">Blank page</option>");
    for t in PAGE_TEMPLATES {
        let sel = if t.id == selected { " selected" } else { "" };
        out.push_str(&format!(
            "<option value=\"{id}\"{sel}>{label}</option>",
            id = esc(t.id),
            sel = sel,
            label = esc(t.label),
        ));
    }
    out
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
            let rendered = markdown::render(&page.body_md, &existing);
            let pages = state.store.list_pages(None, MAX_PAGE).await?;
            // Keyword-related neighbours stay computed locally from the existing semantic graph.
            // The explicit backlinks shown in the same panel come from the persisted page_links table.
            let mut panel = graph::Corpus::build(pages.clone()).panel(&slug);
            panel.backlinks = state
                .store
                .list_backlinks(&slug)
                .await?
                .into_iter()
                .map(|p| graph::LinkRef {
                    slug: p.slug,
                    title: p.title,
                })
                .collect();
            let path = state.store.page_path(&slug).await?;
            let outgoing_count = state.store.outgoing_links(&slug).await?.len();
            let csrf = auth::new_csrf_token();
            let content = render_view(DocumentView {
                page: &page,
                body_html: &rendered.html,
                toc: &rendered.toc,
                panel: &panel,
                pages: &pages,
                path: &path,
                csrf: &csrf,
                outgoing_count,
                stale_days: state.config.stale_days,
                now: now_ms(),
            });
            let html = layout(&page.title, &headers, &content);
            Ok(html_with_csrf_cookie(html, &csrf))
        }
        None => {
            let title = humanize(&slug);
            let content = render_missing(&slug, &title);
            Ok(Html(layout(&title, &headers, &content)).into_response())
        }
    }
}

struct DocumentView<'a> {
    page: &'a Page,
    body_html: &'a str,
    toc: &'a [markdown::TocEntry],
    panel: &'a PagePanel,
    pages: &'a [Page],
    path: &'a [Page],
    csrf: &'a str,
    outgoing_count: usize,
    stale_days: i64,
    now: i64,
}

fn render_view(view: DocumentView<'_>) -> String {
    let page = view.page;
    let article = format!(
        "<article class=\"page document-article\">\
           <header class=\"document-header\">\
             {breadcrumb}\
             <p class=\"eyebrow\">Document</p>\
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
           </header>\
           <div class=\"prose document-body\">{body}</div>\
           <footer class=\"document-end\"><span>End of document</span><a href=\"/edit/{slug}\">Improve this page</a></footer>\
         </article>",
        breadcrumb = render_breadcrumb(view.path),
        title = esc(&page.title),
        email = esc(&page.updated_by_email),
        time = esc(&fmt_ts(page.updated_at)),
        slug = esc(&page.slug),
        body = view.body_html,
    );

    format!(
        "<div class=\"knowledge-document\">\
           {tree}\
           <section class=\"document-canvas\" aria-label=\"Document\">{article}</section>\
           {inspector}\
         </div>",
        tree = render_page_tree(view.pages, &page.slug),
        inspector = render_document_inspector(&view),
    )
}

fn render_document_inspector(view: &DocumentView<'_>) -> String {
    let page = view.page;
    let age_days = view.now.saturating_sub(page.updated_at).max(0) / 86_400_000;
    let stale_cutoff = view
        .now
        .saturating_sub(view.stale_days.max(0).saturating_mul(86_400_000));
    let stale = page.updated_at < stale_cutoff;
    let freshness_class = if stale { " is-warning" } else { " is-healthy" };
    let freshness_label = if stale { "Review due" } else { "Current" };
    let freshness_detail = if stale {
        format!("Last touched {age_days} days ago")
    } else {
        format!("Updated {age_days} days ago")
    };
    let connected = !view.panel.backlinks.is_empty()
        || view.outgoing_count > 0
        || !view.panel.related.is_empty();
    let connection_label = if connected { "Connected" } else { "Isolated" };
    let outline = if view.toc.is_empty() {
        String::new()
    } else {
        format!(
            "<details class=\"inspector-section\" open><summary>Outline</summary>{}</details>",
            render_toc(view.toc)
        )
    };
    let relations = if connected {
        format!(
            "<details class=\"inspector-section\" open><summary>Connections</summary>{}</details>",
            render_relations(view.panel)
        )
    } else {
        String::new()
    };
    let health_open = if stale || !connected { " open" } else { "" };
    let move_form = render_move_form(page, view.pages, view.csrf);
    let move_form = if move_form.is_empty() {
        "<p class=\"inspector-empty\">This is the only page in the workspace.</p>".to_string()
    } else {
        move_form
    };

    format!(
        "<aside class=\"document-inspector\" aria-label=\"Document inspector\">\
           <div class=\"inspector-head\"><p class=\"eyebrow\">Context</p><h2>Inspector</h2></div>\
           {outline}\
           {relations}\
           <details class=\"inspector-section\">\
             <summary>Document</summary>\
             <dl class=\"document-meta\">\
               <div><dt>Owner</dt><dd>{owner}</dd></div>\
               <div><dt>Updated</dt><dd>{updated}</dd></div>\
               <div><dt>History</dt><dd><a href=\"/history/{slug}\">View revisions</a></dd></div>\
               <div><dt>Slug</dt><dd><code>{slug}</code></dd></div>\
             </dl>\
           </details>\
           <details class=\"inspector-section\"{health_open}>\
             <summary>Workspace health</summary>\
             <div class=\"signal-line{freshness_class}\"><span aria-hidden=\"true\"></span><div><strong>{freshness_label}</strong><small>{freshness_detail}</small></div></div>\
             <div class=\"signal-line\"><span aria-hidden=\"true\"></span><div><strong>{connection_label}</strong><small>{incoming} inbound · {outgoing} outbound · {related} related</small></div></div>\
             <a class=\"inspector-link\" href=\"/coherence\">Open workspace report →</a>\
           </details>\
           <details class=\"inspector-section\">\
             <summary>Structure</summary>\
             {move_form}\
           </details>\
         </aside>",
        outline = outline,
        relations = relations,
        owner = esc(&page.updated_by_email),
        updated = esc(&fmt_ts(page.updated_at)),
        slug = esc(&page.slug),
        freshness_class = freshness_class,
        freshness_label = freshness_label,
        freshness_detail = esc(&freshness_detail),
        connection_label = connection_label,
        health_open = health_open,
        incoming = view.panel.backlinks.len(),
        outgoing = view.outgoing_count,
        related = view.panel.related.len(),
        move_form = move_form,
    )
}

fn render_breadcrumb(path: &[Page]) -> String {
    let last = path.len().saturating_sub(1);
    let path_items: String = path
        .iter()
        .enumerate()
        .map(|(i, p)| {
            if i == last {
                format!("<span aria-current=\"page\">{}</span>", esc(&p.title))
            } else {
                format!(
                    "<a href=\"/w/{slug}\">{title}</a>",
                    slug = esc(&p.slug),
                    title = esc(&p.title)
                )
            }
        })
        .collect();
    format!(
        "<nav class=\"breadcrumb\" aria-label=\"Breadcrumb\"><a href=\"/\">Library</a>{path_items}</nav>"
    )
}

fn render_page_tree(pages: &[Page], current_slug: &str) -> String {
    let items = render_tree_items(pages, current_slug);
    format!(
        "<aside class=\"page-tree\" aria-label=\"Page tree\">\
           <div class=\"page-tree__head\"><p class=\"eyebrow\">Workspace</p><h2>Page tree</h2></div>\
           <ul class=\"page-tree__list\">{items}</ul>\
         </aside>",
    )
}

fn render_tree_items(pages: &[Page], current_slug: &str) -> String {
    let known: BTreeSet<&str> = pages.iter().map(|p| p.slug.as_str()).collect();
    let mut children: BTreeMap<String, Vec<&Page>> = BTreeMap::new();
    for page in pages {
        let parent = page
            .parent_id
            .as_deref()
            .filter(|p| known.contains(p))
            .unwrap_or("");
        children.entry(parent.to_string()).or_default().push(page);
    }
    for siblings in children.values_mut() {
        siblings.sort_by(|a, b| {
            a.title
                .to_lowercase()
                .cmp(&b.title.to_lowercase())
                .then_with(|| a.slug.cmp(&b.slug))
        });
    }
    let mut visited = BTreeSet::new();
    render_tree_children("", &children, current_slug, &mut visited)
}

fn render_tree_children(
    parent: &str,
    children: &BTreeMap<String, Vec<&Page>>,
    current_slug: &str,
    visited: &mut BTreeSet<String>,
) -> String {
    let Some(siblings) = children.get(parent) else {
        return String::new();
    };
    siblings
        .iter()
        .map(|page| {
            if !visited.insert(page.slug.clone()) {
                return String::new();
            }
            let cls = if page.slug == current_slug {
                " class=\"is-current\""
            } else {
                ""
            };
            let nested = render_tree_children(&page.slug, children, current_slug, visited);
            let nested = if nested.is_empty() {
                String::new()
            } else {
                format!("<ul>{nested}</ul>")
            };
            format!(
                "<li{cls}><a href=\"/w/{slug}\">{title}</a>{nested}</li>",
                cls = cls,
                slug = esc(&page.slug),
                title = esc(&page.title),
                nested = nested,
            )
        })
        .collect()
}

fn render_move_form(page: &Page, pages: &[Page], csrf: &str) -> String {
    if pages.len() <= 1 {
        return String::new();
    }
    let descendants = descendant_slugs(&page.slug, pages);
    let mut candidates: Vec<&Page> = pages
        .iter()
        .filter(|p| p.slug != page.slug && !descendants.contains(p.slug.as_str()))
        .collect();
    candidates.sort_by(|a, b| {
        a.title
            .to_lowercase()
            .cmp(&b.title.to_lowercase())
            .then_with(|| a.slug.cmp(&b.slug))
    });
    let top_selected = if page.parent_id.is_none() {
        " selected"
    } else {
        ""
    };
    let mut options = format!("<option value=\"\"{top_selected}>Top level</option>");
    for candidate in candidates {
        let selected = if page.parent_id.as_deref() == Some(candidate.slug.as_str()) {
            " selected"
        } else {
            ""
        };
        options.push_str(&format!(
            "<option value=\"{slug}\"{selected}>{title}</option>",
            slug = esc(&candidate.slug),
            selected = selected,
            title = esc(&candidate.title),
        ));
    }
    format!(
        "<div class=\"move-card\">\
           <form class=\"move-form\" method=\"post\" action=\"/move/{slug}\">\
             <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
             <label for=\"parent_id\">Parent page</label>\
             <select id=\"parent_id\" name=\"parent_id\">{options}</select>\
             <button class=\"btn btn-secondary btn-sm\" type=\"submit\">Move</button>\
           </form>\
         </div>",
        slug = esc(&page.slug),
        csrf = esc(csrf),
        options = options,
    )
}

fn descendant_slugs<'a>(slug: &str, pages: &'a [Page]) -> BTreeSet<&'a str> {
    let mut out = BTreeSet::new();
    let mut changed = true;
    while changed {
        changed = false;
        for page in pages {
            let Some(parent) = page.parent_id.as_deref() else {
                continue;
            };
            if (parent == slug || out.contains(parent)) && out.insert(page.slug.as_str()) {
                changed = true;
            }
        }
    }
    out
}

/// Inspector outline. Heading text is escaped and every link points at a sanitizer-produced id.
fn render_toc(toc: &[markdown::TocEntry]) -> String {
    if toc.is_empty() {
        return "<p class=\"inspector-empty\">No headings in this document.</p>".to_string();
    }
    let items: String = toc
        .iter()
        .map(|e| {
            format!(
                "<li class=\"toc__item toc__item--l{level}\"><a href=\"#{id}\">{text}</a></li>",
                level = e.level.clamp(1, 6),
                id = esc(&e.id),
                text = esc(&e.text),
            )
        })
        .collect();
    format!(
        "<nav class=\"toc\" aria-label=\"Table of contents\">\
           <ul class=\"toc__list\">{items}</ul>\
         </nav>"
    )
}

/// The inspector's stable connection map. Empty groups remain visible so an isolated document is
/// an explicit coherence signal instead of silently looking complete.
fn render_relations(panel: &PagePanel) -> String {
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
    format!("<div class=\"relations\">{backlinks}{related}</div>")
}

fn render_link_group(heading: &str, hint: &str, links: &[graph::LinkRef]) -> String {
    let items = if links.is_empty() {
        "<li class=\"relations__empty\">None yet</li>".to_string()
    } else {
        links
            .iter()
            .map(|link| {
                format!(
                    "<li><a class=\"relation-link\" href=\"/w/{slug}\">{title}</a></li>",
                    slug = esc(&link.slug),
                    title = esc(&link.title),
                )
            })
            .collect()
    };
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
    Query(q): Query<EditQuery>,
) -> Result<Response, AppError> {
    let slug = slugify(&raw_slug);
    if slug.is_empty() {
        return Ok(Redirect::to("/").into_response());
    }

    let existing = state.store.get_page(&slug).await?;
    let (title, body, exists) = match &existing {
        Some(p) => (p.title.clone(), p.body_md.clone(), true),
        None => (
            humanize(&slug),
            template_body(&q.template).to_string(),
            false,
        ),
    };

    // The head revision the editor is loaded against. On save we compare it to the current head:
    // a mismatch means someone else edited in between, so the save is rejected as a conflict.
    // Empty for a brand-new page with no history yet.
    let base_rev = state
        .store
        .head_revision(&slug)
        .await?
        .map(|r| r.id)
        .unwrap_or_default();

    let known_slugs: HashSet<String> = state.store.all_slugs().await?.into_iter().collect();
    let preview = markdown::render(&body, &known_slugs);
    let csrf = auth::new_csrf_token();
    let content = render_editor(
        &slug,
        &title,
        &body,
        &preview.html,
        &csrf,
        exists,
        &base_rev,
    );
    let page_title = format!("{} {}", if exists { "Edit" } else { "Create" }, title);
    let html = layout(&page_title, &headers, &content);
    Ok(html_with_csrf_cookie(html, &csrf))
}

fn render_editor(
    slug: &str,
    title: &str,
    body: &str,
    preview_html: &str,
    csrf: &str,
    exists: bool,
    base_rev: &str,
) -> String {
    format!(
        "<form class=\"editor editor-workspace\" method=\"post\" action=\"/edit/{slug}\">\
           <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
           <input type=\"hidden\" name=\"base_rev\" value=\"{base_rev}\">\
           <header class=\"editor__head\">\
             <div><p class=\"eyebrow\">Writing workspace</p><h1>{verb} document</h1></div>\
             <code>/w/{slug}</code>\
           </header>\
           <div class=\"editor__title-field\">\
             <label for=\"title\">Document title</label>\
             <input id=\"title\" type=\"text\" name=\"title\" value=\"{title}\" autocomplete=\"off\" required>\
           </div>\
           <div class=\"editor-split\">\
             <section class=\"editor-pane editor-pane--source\" aria-labelledby=\"source-label\">\
               <div class=\"editor-pane__head\"><h2 id=\"source-label\">Markdown</h2><span>Source</span></div>\
               <textarea id=\"body\" name=\"body_md\" rows=\"28\" spellcheck=\"true\" data-editor-source>{body}</textarea>\
             </section>\
             <section class=\"editor-pane editor-pane--preview\" aria-labelledby=\"preview-label\">\
               <div class=\"editor-pane__head\"><h2 id=\"preview-label\">Preview</h2><span>Safe rendering</span></div>\
               <div class=\"prose editor-preview\" data-editor-preview>{preview}</div>\
             </section>\
           </div>\
           <footer class=\"editor-footer\">\
             <p class=\"editor__hint\">Use Markdown and <code>[[Page Name]]</code> links. Raw HTML remains escaped.</p>\
             <div class=\"editor__actions\">\
               <a class=\"btn btn-secondary\" href=\"/w/{slug}\">Cancel</a>\
               <button class=\"btn btn-primary\" type=\"submit\">Save document</button>\
             </div>\
           </footer>\
         </form>",
        slug = esc(slug),
        verb = if exists { "Edit" } else { "Create" },
        csrf = esc(csrf),
        base_rev = esc(base_rev),
        title = esc(title),
        body = esc(body),
        preview = preview_html,
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

    // Edit-conflict detection: the form carries the head revision id the editor was loaded
    // against. If the current head has moved on (a concurrent save), REJECT with a friendly
    // conflict page showing both versions — nothing is written, no audit event is emitted.
    let head = state.store.head_revision(&slug).await?;
    let current_head = head.as_ref().map(|r| r.id.as_str()).unwrap_or("");
    if form.base_rev != current_head {
        let content = render_conflict(&slug, &title, &form.body_md, head.as_ref());
        let html = layout(&format!("Edit conflict · {title}"), &headers, &content);
        return Ok((StatusCode::CONFLICT, Html(html)).into_response());
    }

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

/// The friendly edit-conflict page (HTTP 409). Shows the version that landed while the operator
/// was editing side-by-side with the rejected submission, so nothing is lost — they copy what
/// they need and reload the editor (which re-reads the new head). Both bodies are escaped.
fn render_conflict(slug: &str, title: &str, yours: &str, head: Option<&Revision>) -> String {
    let (theirs, their_meta) = match head {
        Some(r) => (
            r.body_md.as_str(),
            format!("saved by {} · {}", esc(&r.editor_email), esc(&fmt_ts(r.ts))),
        ),
        // No head means the page was created concurrently (base_rev was empty, head is now set is
        // the usual case; this arm only fires if head vanished) — degrade gracefully.
        None => ("", "the current version".to_string()),
    };
    format!(
        "<section class=\"card conflict\">\
           <div class=\"page-head\">\
             <div><h1>Edit conflict</h1><p class=\"muted\">{title}</p></div>\
             <a class=\"btn btn-primary btn-sm\" href=\"/edit/{slug}\">Reload editor</a>\
           </div>\
           <p class=\"conflict__lead\">Someone else saved <code>/w/{slug}</code> while you were \
             editing, so your changes were <strong>not</strong> applied. Copy anything you need \
             from your version below, then reload the editor to start from the latest text.</p>\
           <div class=\"conflict__cols\">\
             <div class=\"conflict__col\">\
               <h2 class=\"conflict__label\">Their version <span class=\"muted\">({their_meta})</span></h2>\
               <pre class=\"conflict__body\">{theirs}</pre>\
             </div>\
             <div class=\"conflict__col\">\
               <h2 class=\"conflict__label\">Your version <span class=\"muted\">(not saved)</span></h2>\
               <pre class=\"conflict__body\">{yours}</pre>\
             </div>\
           </div>\
           <div class=\"conflict__actions\">\
             <a class=\"btn btn-secondary\" href=\"/w/{slug}\">View current page</a>\
             <a class=\"btn btn-primary\" href=\"/edit/{slug}\">Reload editor</a>\
           </div>\
         </section>",
        title = esc(title),
        slug = esc(slug),
        their_meta = their_meta,
        theirs = esc(theirs),
        yours = esc(yours),
    )
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
    let title = page
        .as_ref()
        .map(|p| p.title.clone())
        .unwrap_or_else(|| humanize(&slug));

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
        format!(
            "<a class=\"btn btn-secondary btn-sm\" href=\"/w/{}\">Back to page</a>",
            esc(slug)
        )
    } else {
        format!(
            "<a class=\"btn btn-primary btn-sm\" href=\"/edit/{}\">Create this page</a>",
            esc(slug)
        )
    };

    let rows = if revs.is_empty() {
        "<tr><td class=\"empty\" colspan=\"4\">No revisions recorded for this page.</td></tr>"
            .to_string()
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
    state.audit.emit(AuditEvent::notice(
        "page.revert",
        &editor_email,
        &slug,
        "revert",
    ));

    Ok(Redirect::to(&format!("/w/{slug}")).into_response())
}

// ---------------------------------------------------------------------------
// POST /move/{slug}  — re-parent a page in the nested tree
// ---------------------------------------------------------------------------

pub async fn move_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_slug): Path<String>,
    Form(form): Form<MoveForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::Forbidden(
            "CSRF token missing or invalid — reload the page and try again.".to_string(),
        ));
    }

    let slug = slugify(&raw_slug);
    if slug.is_empty() {
        return Ok(Redirect::to("/").into_response());
    }

    let parent_id = {
        let parent = slugify(&form.parent_id);
        if parent.is_empty() {
            None
        } else {
            Some(parent)
        }
    };
    let actor = auth::signed_in_email(&headers).unwrap_or_else(|| "anonymous".to_string());
    let moved = state.store.move_page(&slug, parent_id).await?;

    state
        .audit
        .emit(AuditEvent::notice("page.move", &actor, &moved.slug, "move"));

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
