//! Full-text search over the blog's published posts (`GET /search?q=`).
//!
//! Search reuses the SAME lexical/BoW index the "ask your blog" feature builds. Each query ranks an
//! authoritative snapshot of posts public at that instant; the persisted `chunks` table is only a
//! repaired derived cache. Consequently a scheduled post appears as soon as its instant arrives,
//! while a stale/de-index failure can never expose a draft or old body.
//!
//! Each result carries a short excerpt with the matched query terms wrapped in `<mark>`. The
//! excerpt is HTML-escaped per segment BEFORE any `<mark>` is inserted, so author text can never
//! inject markup (defense-in-depth on top of the sanitized reading view).

use std::collections::HashSet;

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;

use crate::auth;
use crate::error::AppError;
use crate::handlers::{esc, fmt_date, page_shell, PageShell};
use crate::index::{self, Scored};
use crate::AppState;

const SEARCH_HTML: &str = include_str!("../../templates/search.html");

/// How many distinct posts to surface per search.
const TOP_K: usize = 10;
/// Hard cap on a query length (chars) — bounds the work.
const MAX_QUERY_CHARS: usize = 200;
/// How many characters of a passage to show per result.
const SNIPPET_CHARS: usize = 280;

/// Search query string: `?q=` (absent/blank renders the empty prompt).
#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    pub q: Option<String>,
}

/// `GET /search?q=` — rank the published-post index against the query and render highlighted
/// excerpts, deduped to one result per post, each linking back to its reading view.
pub async fn search_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(sq): Query<SearchQuery>,
) -> Result<Response, AppError> {
    let email = auth::display_email(&headers);
    let is_admin = auth::is_admin(&headers);
    let theme = odyssey::resolve_theme(
        headers
            .get(axum::http::header::COOKIE)
            .and_then(|v| v.to_str().ok()),
    );
    let query: String =
        sq.q.unwrap_or_default()
            .trim()
            .chars()
            .take(MAX_QUERY_CHARS)
            .collect();

    let results_html = if query.is_empty() {
        empty_prompt()
    } else {
        let chunks = crate::public_index_snapshot(state.store.as_ref()).await?;
        let top = index::rank(&query, &chunks, TOP_K);
        if top.is_empty() {
            no_results(&query)
        } else {
            render_results(&top, &query)
        }
    };

    let fragment = SEARCH_HTML
        .replace("{{QUERY}}", &esc(&query))
        .replace("{{RESULTS}}", &results_html);
    let page = page_shell(PageShell {
        head_title: "Search · Inkwell",
        body_class: "page-console",
        rss: false,
        nav_title: "Search",
        email: &email,
        is_admin,
        theme,
        fragment: &fragment,
        metadata: None,
    });
    Ok(Html(page).into_response())
}

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------

/// Render the ranked results, deduped to the best chunk per post. Every interpolated field is
/// escaped; excerpts are highlighted via [`highlight`].
fn render_results(top: &[Scored], query: &str) -> String {
    let terms: HashSet<String> = index::tokenize(query).into_iter().collect();
    let mut seen: HashSet<String> = HashSet::new();
    let mut items = String::new();
    let mut count = 0usize;
    for s in top {
        // `rank` returns chunks; collapse to one result per post (best chunk wins, since ranked).
        if !seen.insert(s.chunk.post_id.clone()) {
            continue;
        }
        count += 1;
        let snippet = highlight(&snippet_of(&s.chunk.body, SNIPPET_CHARS), &terms);
        items.push_str(&format!(
            r#"<li class="search-result">
  <a class="search-result__title" href="/p/{slug}">{title}</a>
  <span class="search-result__date muted">{date}</span>
  <p class="search-result__excerpt">{snippet}</p>
</li>"#,
            slug = esc(&s.chunk.post_id),
            title = esc(&s.chunk.title),
            date = esc(&fmt_date(s.chunk.indexed_at)),
            snippet = snippet,
        ));
    }
    format!(
        r#"<section class="search-results">
  <div class="search-results__head"><h2>Results</h2><span class="muted">{count} matching post{plural}</span></div>
  <ul class="search-results__list">{items}</ul>
</section>"#,
        count = count,
        plural = if count == 1 { "" } else { "s" },
        items = items,
    )
}

/// The empty state (GET /search with no query yet).
fn empty_prompt() -> String {
    r#"<section class="search-results search-results--empty">
  <div class="empty-state">
    <h2>Search the blog</h2>
    <p>Type a few words to search across every published post. Matches are highlighted in context.</p>
  </div>
</section>"#
        .to_string()
}

/// Results area when nothing matched the query.
fn no_results(query: &str) -> String {
    format!(
        r#"<section class="search-results">
  <div class="empty-state">
    <h2>No matches</h2>
    <p>Nothing in the published posts matched <strong>"{q}"</strong>. Try different words.</p>
  </div>
</section>"#,
        q = esc(query),
    )
}

/// Escape `text` and wrap every whole word whose lowercased form is a query term in `<mark>`.
/// Segments are escaped BEFORE any markup is added, so no user text can inject HTML.
fn highlight(text: &str, terms: &HashSet<String>) -> String {
    let mut out = String::new();
    let mut word = String::new();
    for c in text.chars() {
        if c.is_alphanumeric() {
            word.push(c);
        } else {
            flush_word(&mut word, terms, &mut out);
            out.push_str(&esc(&c.to_string()));
        }
    }
    flush_word(&mut word, terms, &mut out);
    out
}

/// Emit one accumulated word: `<mark>`-wrapped (escaped) when it is a query term, escaped otherwise.
fn flush_word(word: &mut String, terms: &HashSet<String>, out: &mut String) {
    if word.is_empty() {
        return;
    }
    if terms.contains(&word.to_lowercase()) {
        out.push_str("<mark>");
        out.push_str(&esc(word));
        out.push_str("</mark>");
    } else {
        out.push_str(&esc(word));
    }
    word.clear();
}

/// A short, whitespace-collapsed excerpt of `body`, char-safe, with a trailing `…` when clipped.
fn snippet_of(body: &str, n: usize) -> String {
    let mut collapsed = String::with_capacity(body.len());
    let mut prev = false;
    for c in body.chars() {
        if c.is_whitespace() {
            if !prev {
                collapsed.push(' ');
            }
            prev = true;
        } else {
            collapsed.push(c);
            prev = false;
        }
    }
    let collapsed = collapsed.trim();
    if collapsed.chars().count() > n {
        let t: String = collapsed.chars().take(n).collect();
        format!("{}…", t.trim_end())
    } else {
        collapsed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terms(q: &str) -> HashSet<String> {
        index::tokenize(q).into_iter().collect()
    }

    #[test]
    fn highlight_wraps_query_terms_only() {
        let out = highlight("the gateway is fast", &terms("gateway"));
        assert!(out.contains("<mark>gateway</mark>"), "matched term wrapped");
        assert!(out.contains("the"), "non-match kept as text");
        assert!(!out.contains("<mark>the</mark>"), "non-term not wrapped");
    }

    #[test]
    fn highlight_is_case_insensitive() {
        let out = highlight("Gateway GATEWAY gateway", &terms("gateway"));
        assert_eq!(
            out.matches("<mark>").count(),
            3,
            "all case variants highlighted"
        );
    }

    #[test]
    fn highlight_escapes_before_marking() {
        // A `<script>` in the body must be escaped; only the word tokens get `<mark>`.
        let out = highlight("<script>gateway</script>", &terms("gateway"));
        assert!(!out.contains("<script>"), "raw markup escaped");
        assert!(out.contains("&lt;script&gt;"), "shown as escaped text");
        assert!(
            out.contains("<mark>gateway</mark>"),
            "term still highlighted"
        );
    }
}
