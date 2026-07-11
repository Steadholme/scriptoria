//! Forum discovery search: a shareable SSR result page plus a small same-origin suggestion API.
//!
//! Both surfaces search thread titles, original-post bodies, and accepted solution bodies. They
//! are read-only and sit behind the existing Sluice SSO route; no draft text or mutation is
//! involved.

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::handlers::{ag_tone, email_display, esc, fmt_ts, rel_time, render_page};
use crate::model::{Category, CategoryFormat, ThreadSearchHit};
use crate::store::ThreadStatusFilter;
use crate::{now_secs, AppState};

const SEARCH_PAGE_LIMIT: i64 = 50;
const SEARCH_PAGE_QUERY_MIN_CHARS: usize = 2;
const SUGGEST_DEFAULT_LIMIT: i64 = 6;
const SUGGEST_MAX_LIMIT: i64 = 10;
const SUGGEST_QUERY_MIN_CHARS: usize = 3;
const SEARCH_QUERY_MAX_CHARS: usize = 160;
const SEARCH_CATEGORY_MAX_CHARS: usize = 64;
const SEARCH_EXCERPT_CHARS: usize = 180;

#[derive(Debug, Deserialize, Default)]
pub struct SearchQuery {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SuggestResponse {
    query: String,
    category: Option<String>,
    status: Option<String>,
    results: Vec<SuggestHit>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SuggestHit {
    id: String,
    title: String,
    category_id: String,
    category: String,
    url: String,
    excerpt: String,
    match_source: String,
    reply_count: i64,
    answered: bool,
    last_at: i64,
}

/// `GET /search?q=&category=` — a stable, shareable, no-JavaScript-required search page.
pub async fn page(
    State(state): State<AppState>,
    Query(params): Query<SearchQuery>,
    headers: HeaderMap,
) -> Result<Html<String>, AppError> {
    let query = normalize_query(params.q.as_deref());
    let category_id = normalize_category(params.category.as_deref());
    let status = normalize_status(params.status.as_deref());
    let categories = state.store.list_categories().await?;
    let category_names = category_names(&categories);
    let hits = if query.chars().count() < SEARCH_PAGE_QUERY_MIN_CHARS {
        Vec::new()
    } else {
        state
            .store
            .search_threads(
                &query,
                category_id.as_deref(),
                status_filter(status.as_deref()),
                SEARCH_PAGE_LIMIT,
            )
            .await?
    };

    let content = render_search_page(
        &query,
        category_id.as_deref(),
        status.as_deref(),
        &categories,
        &category_names,
        &hits,
        now_secs(),
    );
    Ok(Html(render_page(
        "Search",
        &email_display(&headers),
        &content,
    )))
}

/// `GET /api/search/suggest?q=&category=&limit=` — same-origin suggestions for the product-owned
/// quick-search. Query text is normalised, requires at least three characters, and is
/// character-capped; the result limit is clamped to `1..=10`. `axum::Json` owns serialization so
/// titles and excerpts can never break JSON syntax.
pub async fn suggest(
    State(state): State<AppState>,
    Query(params): Query<SearchQuery>,
) -> Result<Response, AppError> {
    let query = normalize_query(params.q.as_deref());
    let category_id = normalize_category(params.category.as_deref());
    let status = normalize_status(params.status.as_deref());
    let limit = params
        .limit
        .unwrap_or(SUGGEST_DEFAULT_LIMIT)
        .clamp(1, SUGGEST_MAX_LIMIT);
    let categories = state.store.list_categories().await?;
    let names = category_names(&categories);
    let hits = if query.chars().count() < SUGGEST_QUERY_MIN_CHARS {
        Vec::new()
    } else {
        state
            .store
            .search_threads(
                &query,
                category_id.as_deref(),
                status_filter(status.as_deref()),
                limit,
            )
            .await?
    };
    let results = hits
        .into_iter()
        .map(|hit| {
            let matched_in_solution = hit.matched_in_solution;
            let excerpt_source = if matched_in_solution {
                hit.accepted_body_md.as_str()
            } else {
                hit.first_body_md.as_str()
            };
            let excerpt = compact_excerpt(excerpt_source, SEARCH_EXCERPT_CHARS);
            let thread = hit.thread;
            let category = names
                .get(thread.category_id.as_str())
                .copied()
                .unwrap_or("Unknown category")
                .to_string();
            let answered = !thread.accepted_post_id.is_empty();
            let url = format!("/t/{}", thread.id);
            SuggestHit {
                category,
                id: thread.id,
                title: thread.title,
                category_id: thread.category_id,
                url,
                excerpt,
                match_source: if matched_in_solution {
                    "solution".to_string()
                } else {
                    "original".to_string()
                },
                reply_count: hit.reply_count,
                answered,
                last_at: thread.last_at,
            }
        })
        .collect();
    let mut response = Json(SuggestResponse {
        query,
        category: category_id,
        status,
        results,
    })
    .into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    Ok(response)
}

fn normalize_query(raw: Option<&str>) -> String {
    let bounded: String = raw
        .unwrap_or_default()
        .chars()
        .take(SEARCH_QUERY_MAX_CHARS)
        .collect();
    bounded.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn normalize_category(raw: Option<&str>) -> Option<String> {
    let bounded: String = raw?
        .trim()
        .chars()
        .take(SEARCH_CATEGORY_MAX_CHARS)
        .collect();
    (!bounded.is_empty()).then_some(bounded)
}

fn normalize_status(raw: Option<&str>) -> Option<String> {
    match raw.map(str::trim) {
        Some("answered") => Some("answered".to_string()),
        Some("unanswered") => Some("unanswered".to_string()),
        _ => None,
    }
}

fn status_filter(status: Option<&str>) -> ThreadStatusFilter {
    match status {
        Some("answered") => ThreadStatusFilter::Answered,
        Some("unanswered") => ThreadStatusFilter::Unanswered,
        _ => ThreadStatusFilter::Any,
    }
}

fn category_names(categories: &[Category]) -> HashMap<&str, &str> {
    categories
        .iter()
        .map(|category| (category.id.as_str(), category.name.as_str()))
        .collect()
}

fn render_search_page(
    query: &str,
    selected_category: Option<&str>,
    selected_status: Option<&str>,
    categories: &[Category],
    category_names: &HashMap<&str, &str>,
    hits: &[ThreadSearchHit],
    now: i64,
) -> String {
    let options = render_category_options(categories, selected_category);
    let status_options = format!(
        r#"<option value="">All discussions</option><option value="unanswered"{unanswered}>Unanswered questions</option><option value="answered"{answered}>Answered questions</option>"#,
        unanswered = if selected_status == Some("unanswered") { " selected" } else { "" },
        answered = if selected_status == Some("answered") { " selected" } else { "" },
    );
    let category_formats: HashMap<&str, CategoryFormat> = categories
        .iter()
        .map(|category| (category.id.as_str(), category.format))
        .collect();
    let body = if query.is_empty() {
        r#"<section class="empty ag-search-empty">
  <div class="empty__ico" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg></div>
  <h2>Find a discussion</h2>
  <p>Search titles, original posts, and accepted solutions. Add a category or answer status to narrow the result.</p>
</section>"#
            .to_string()
    } else if query.chars().count() < SEARCH_PAGE_QUERY_MIN_CHARS {
        r#"<section class="empty ag-search-empty">
  <h2>Keep typing</h2>
  <p>Use at least two characters to search the forum.</p>
</section>"#
            .to_string()
    } else if hits.is_empty() {
        format!(
            r#"<section class="empty ag-search-empty">
  <h2>No discussions found</h2>
  <p>No thread matched <strong>{query}</strong>{scope}. Try fewer words or search every category.</p>
</section>"#,
            query = esc(query),
            scope = selected_category
                .map(|category| format!(" in <strong>{}</strong>", esc(category)))
                .unwrap_or_default(),
        )
    } else {
        render_results(hits, category_names, &category_formats, now)
    };
    let result_label = if query.is_empty() {
        "Search across the forum".to_string()
    } else if query.chars().count() < SEARCH_PAGE_QUERY_MIN_CHARS {
        "Search queries need at least two characters".to_string()
    } else {
        format!(
            "{} {} for “{}”",
            hits.len(),
            if hits.len() == 1 { "result" } else { "results" },
            esc(query)
        )
    };

    format!(
        r#"<nav class="crumbs"><a href="/">Home</a><span class="crumbs__sep">/</span><span>Search</span></nav>
<div class="page-head ag-search-head">
  <div><h1>Search discussions</h1><p class="muted">{result_label}</p></div>
</div>
<form class="card ag-search-form" method="get" action="/search" role="search" aria-label="Forum search">
  <div class="field ag-search-form__query">
    <label class="label" for="search-page-query">Keywords</label>
    <input id="search-page-query" class="input" type="search" name="q" value="{query}" maxlength="{max}" placeholder="Search titles and original posts" autofocus>
  </div>
  <div class="field ag-search-form__category">
    <label class="label" for="search-page-category">Category</label>
    <select id="search-page-category" name="category"><option value="">All categories</option>{options}</select>
  </div>
  <div class="field ag-search-form__status">
    <label class="label" for="search-page-status">Answer status</label>
    <select id="search-page-status" name="status">{status_options}</select>
  </div>
  <button class="btn btn-primary" type="submit">Search</button>
</form>
{body}"#,
        result_label = result_label,
        query = esc(query),
        max = SEARCH_QUERY_MAX_CHARS,
        options = options,
        status_options = status_options,
        body = body,
    )
}

fn render_category_options(categories: &[Category], selected: Option<&str>) -> String {
    let mut options = String::new();
    for category in categories {
        options.push_str(&format!(
            r#"<option value="{id}"{selected}>{name}</option>"#,
            id = esc(&category.id),
            selected = if selected == Some(category.id.as_str()) {
                " selected"
            } else {
                ""
            },
            name = esc(&category.name),
        ));
    }
    options
}

fn render_results(
    hits: &[ThreadSearchHit],
    category_names: &HashMap<&str, &str>,
    category_formats: &HashMap<&str, CategoryFormat>,
    now: i64,
) -> String {
    let mut items = String::new();
    for hit in hits {
        let category_name = category_names
            .get(hit.thread.category_id.as_str())
            .copied()
            .unwrap_or("Unknown category");
        let is_question = category_formats
            .get(hit.thread.category_id.as_str())
            .copied()
            .unwrap_or_default()
            .is_question();
        let answer_state = if !hit.thread.accepted_post_id.is_empty() {
            r#"<span class="badge badge-accepted">Answered</span>"#.to_string()
        } else if is_question {
            r#"<span class="badge ag-answer-state ag-answer-state--open">Needs answer</span>"#
                .to_string()
        } else {
            String::new()
        };
        let (excerpt, match_source) = if hit.matched_in_solution {
            (
                hit.accepted_body_md.as_str(),
                r#"<span class="ag-search-hit__source">Matched in accepted answer</span>"#,
            )
        } else {
            (hit.first_body_md.as_str(), "")
        };
        items.push_str(&format!(
            r#"<li><a class="ag-search-hit" href="/t/{id}">
  <span class="ag-search-hit__main">
    <span class="ag-search-hit__title">{title}{answer_state}</span>
    {match_source}<span class="ag-search-hit__excerpt">{excerpt}</span>
    <span class="ag-search-hit__meta"><span class="ag-chip ag-tone-{tone}">{category}</span><span>{replies}</span><time title="{absolute}">Active {relative}</time></span>
  </span>
</a></li>"#,
            id = esc(&hit.thread.id),
            title = esc(&hit.thread.title),
            answer_state = answer_state,
            match_source = match_source,
            excerpt = esc(&compact_excerpt(
                excerpt,
                SEARCH_EXCERPT_CHARS
            )),
            tone = ag_tone(&hit.thread.category_id),
            category = esc(category_name),
            replies = if hit.reply_count == 1 {
                "1 reply".to_string()
            } else {
                format!("{} replies", hit.reply_count)
            },
            absolute = esc(&fmt_ts(hit.thread.last_at)),
            relative = esc(&rel_time(hit.thread.last_at, now)),
        ));
    }
    format!(r#"<ol class="ag-search-results">{items}</ol>"#)
}

fn compact_excerpt(input: &str, max_chars: usize) -> String {
    let compact = input.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut chars = compact.chars();
    let mut excerpt: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        excerpt.push('…');
    }
    excerpt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_and_category_are_bounded() {
        let query = "x".repeat(SEARCH_QUERY_MAX_CHARS + 50);
        assert_eq!(
            normalize_query(Some(&query)).chars().count(),
            SEARCH_QUERY_MAX_CHARS
        );
        let category = "c".repeat(SEARCH_CATEGORY_MAX_CHARS + 20);
        assert_eq!(
            normalize_category(Some(&category)).unwrap().chars().count(),
            SEARCH_CATEGORY_MAX_CHARS
        );
    }

    #[test]
    fn query_normalization_collapses_whitespace() {
        assert_eq!(
            normalize_query(Some("  rust\n  ownership  ")),
            "rust ownership"
        );
        assert!(normalize_query(Some(" \t ")).is_empty());
    }
}
