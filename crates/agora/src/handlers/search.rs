//! Forum discovery search: a shareable SSR result page plus a small same-origin suggestion API.
//!
//! Both surfaces search only thread titles and the denormalised original-post body. They are
//! read-only and sit behind the existing Sluice SSO route; no draft text or mutation is involved.

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::handlers::{ag_tone, email_display, esc, fmt_ts, rel_time, render_page};
use crate::model::{Category, ThreadSearchHit};
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
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SuggestResponse {
    query: String,
    category: Option<String>,
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
    let categories = state.store.list_categories().await?;
    let category_names = category_names(&categories);
    let hits = if query.chars().count() < SEARCH_PAGE_QUERY_MIN_CHARS {
        Vec::new()
    } else {
        state
            .store
            .search_threads(&query, category_id.as_deref(), SEARCH_PAGE_LIMIT)
            .await?
    };

    let content = render_search_page(
        &query,
        category_id.as_deref(),
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
            .search_threads(&query, category_id.as_deref(), limit)
            .await?
    };
    let results = hits
        .into_iter()
        .map(|hit| SuggestHit {
            category: names
                .get(hit.thread.category_id.as_str())
                .copied()
                .unwrap_or("Unknown category")
                .to_string(),
            id: hit.thread.id.clone(),
            title: hit.thread.title,
            category_id: hit.thread.category_id,
            url: format!("/t/{}", hit.thread.id),
            excerpt: compact_excerpt(&hit.first_body_md, SEARCH_EXCERPT_CHARS),
            reply_count: hit.reply_count,
            answered: !hit.thread.accepted_post_id.is_empty(),
            last_at: hit.thread.last_at,
        })
        .collect();
    let mut response = Json(SuggestResponse {
        query,
        category: category_id,
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

fn category_names(categories: &[Category]) -> HashMap<&str, &str> {
    categories
        .iter()
        .map(|category| (category.id.as_str(), category.name.as_str()))
        .collect()
}

fn render_search_page(
    query: &str,
    selected_category: Option<&str>,
    categories: &[Category],
    category_names: &HashMap<&str, &str>,
    hits: &[ThreadSearchHit],
    now: i64,
) -> String {
    let options = render_category_options(categories, selected_category);
    let body = if query.is_empty() {
        r#"<section class="empty ag-search-empty">
  <div class="empty__ico" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg></div>
  <h2>Find a discussion</h2>
  <p>Search thread titles and original posts. Add a category when you want to narrow the result.</p>
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
        render_results(hits, category_names, now)
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
  <button class="btn btn-primary" type="submit">Search</button>
</form>
{body}"#,
        result_label = result_label,
        query = esc(query),
        max = SEARCH_QUERY_MAX_CHARS,
        options = options,
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
    now: i64,
) -> String {
    let mut items = String::new();
    for hit in hits {
        let category_name = category_names
            .get(hit.thread.category_id.as_str())
            .copied()
            .unwrap_or("Unknown category");
        let answered = if hit.thread.accepted_post_id.is_empty() {
            String::new()
        } else {
            r#"<span class="badge badge-accepted">Answered</span>"#.to_string()
        };
        items.push_str(&format!(
            r#"<li><a class="ag-search-hit" href="/t/{id}">
  <span class="ag-search-hit__main">
    <span class="ag-search-hit__title">{title}{answered}</span>
    <span class="ag-search-hit__excerpt">{excerpt}</span>
    <span class="ag-search-hit__meta"><span class="ag-chip ag-tone-{tone}">{category}</span><span>{replies}</span><time title="{absolute}">Active {relative}</time></span>
  </span>
</a></li>"#,
            id = esc(&hit.thread.id),
            title = esc(&hit.thread.title),
            answered = answered,
            excerpt = esc(&compact_excerpt(
                &hit.first_body_md,
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
