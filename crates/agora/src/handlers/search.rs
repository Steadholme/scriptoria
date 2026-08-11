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
use crate::handlers::{category_vm, page_chrome, personal_counts, thread_row_shared, thread_scope};
use crate::model::Category;
use crate::store::ThreadStatusFilter;
use crate::view_model::{
    CollectionState, NavTab, Opaque, SearchMatchSource, SearchQueryState, SearchResultVM,
    SearchShared, SearchView, SearchViewerState, Text, ThreadOrder,
};
use crate::views;
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
    let now = now_secs();
    let query = normalize_query(params.q.as_deref());
    let category_id = normalize_category(params.category.as_deref());
    let status = normalize_status(params.status.as_deref());
    let categories = state.store.list_categories().await?;
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
    let counts = personal_counts(&state, &headers, now).await?;
    let categories_by_id: HashMap<&str, &Category> = categories
        .iter()
        .map(|category| (category.id.as_str(), category))
        .collect();
    let results: Vec<SearchResultVM> = hits
        .iter()
        .map(|hit| {
            let excerpt = if hit.matched_in_solution {
                hit.accepted_body_md.as_str()
            } else {
                hit.first_body_md.as_str()
            };
            SearchResultVM {
                thread: thread_row_shared(
                    &hit.thread,
                    categories_by_id
                        .get(hit.thread.category_id.as_str())
                        .copied(),
                    Some(hit.reply_count.saturating_add(1)),
                    !hit.thread.accepted_post_id.is_empty(),
                ),
                excerpt: Text(compact_excerpt(excerpt, SEARCH_EXCERPT_CHARS)),
                source: if hit.matched_in_solution {
                    SearchMatchSource::AcceptedAnswer
                } else {
                    SearchMatchSource::Topic
                },
            }
        })
        .collect();
    let query_state = if query.is_empty() {
        SearchQueryState::Empty
    } else if query.chars().count() < SEARCH_PAGE_QUERY_MIN_CHARS {
        SearchQueryState::TooShort
    } else {
        SearchQueryState::Valid
    };
    let collection_state = if !results.is_empty() {
        CollectionState::Ready
    } else if query_state == SearchQueryState::TooShort {
        CollectionState::TooShort
    } else if query_state == SearchQueryState::Valid && (category_id.is_some() || status.is_some())
    {
        CollectionState::FilteredZero
    } else {
        CollectionState::ReadyEmpty
    };
    let view = SearchView {
        chrome: page_chrome("Search", &headers, NavTab::Search, counts),
        shared: SearchShared {
            categories: categories.iter().map(category_vm).collect(),
            query_state,
            results,
            visible_bound: SEARCH_PAGE_LIMIT,
            state: collection_state,
            now,
        },
        viewer: SearchViewerState {
            query: Text(query),
            selected_category: category_id.map(Opaque),
            order: ThreadOrder::Latest,
            scope: thread_scope(status_filter(status.as_deref())),
        },
    };
    Ok(Html(views::search::search(&view)))
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
