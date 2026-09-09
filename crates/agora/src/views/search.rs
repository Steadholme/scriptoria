//! Deliberation Desk — bounded shared search.
//!
//! The GET form is complete without JavaScript (the app-bar quick-search is a pure enhancement).
//! Results are an explicitly bounded set, never a total-corpus figure, and an accepted-answer
//! match names its source without implying the snippet is the whole solution.

use crate::view_model::{
    CategoryVM, SearchMatchSource, SearchQueryState, SearchResultVM, SearchShared, SearchView,
    SearchViewerState, ThreadKind, ThreadScope,
};

use super::shell;
use super::{
    answer_state_chip, collection_note, escape, kind_chip, monogram, t, thread_href, time_el,
};

pub fn search(v: &SearchView) -> String {
    shell::page(&v.chrome, &search_main(&v.shared, &v.viewer))
}

fn scope_status(scope: ThreadScope) -> Option<&'static str> {
    match scope {
        ThreadScope::Answered => Some("answered"),
        ThreadScope::Unanswered => Some("unanswered"),
        ThreadScope::Any | ThreadScope::Questions => None,
    }
}

fn search_main(s: &SearchShared, vs: &SearchViewerState) -> String {
    let form = search_form(&s.categories, vs);
    let body = match s.query_state {
        SearchQueryState::Empty => note(
            "Search the amphitheatre",
            "Enter 2 to 160 characters to search thread titles, original posts, and accepted answers.",
        ),
        SearchQueryState::TooShort => note(
            "Keep typing",
            "Search needs at least 2 characters.",
        ),
        SearchQueryState::Invalid => note(
            "That search could not be run",
            "Adjust the query and try again.",
        ),
        SearchQueryState::Valid => results_block(s),
    };
    format!(
        r#"<div class="ag-desk-page">
  <header class="pagehead"><div class="pagehead__titles ag-head-tools__lead"><h1 class="ag-head__title">Search</h1></div></header>
  {form}
  {body}
</div>"#,
        form = form,
        body = body,
    )
}

fn search_form(cats: &[CategoryVM], vs: &SearchViewerState) -> String {
    let selected = vs.selected_category.as_ref().map(|c| c.0.as_str());
    let mut options = format!(
        r#"<option value=""{sel}>All categories</option>"#,
        sel = if selected.is_none() { " selected" } else { "" },
    );
    for c in cats {
        let value = &c.category.id.0;
        options.push_str(&format!(
            r#"<option value="{value}"{sel}>{name}</option>"#,
            value = escape(value),
            sel = if selected == Some(value.as_str()) {
                " selected"
            } else {
                ""
            },
            name = t(&c.category.name),
        ));
    }
    let status_opt = |val: &str, label: &str, this: Option<&str>| {
        let cur = scope_status(vs.scope);
        format!(
            r#"<option value="{val}"{sel}>{label}</option>"#,
            val = val,
            sel = if cur == this { " selected" } else { "" },
            label = label,
        )
    };
    format!(
        r#"<form class="ag-form ag-search-form" method="get" action="/search" role="search">
  <label class="ag-form__label" for="ag-search-q">Search</label>
  <div class="ag-form__row">
    <input id="ag-search-q" type="search" name="q" maxlength="160" value="{query}" placeholder="Search discussions" autocomplete="off">
    <select name="category" aria-label="Category">{options}</select>
    <select name="status" aria-label="Answer status">{status_all}{status_unanswered}{status_answered}</select>
    <button class="btn btn-primary" type="submit">Search</button>
  </div>
</form>"#,
        query = t(&vs.query),
        options = options,
        status_all = status_opt("", "Any status", None),
        status_unanswered = status_opt("unanswered", "Unanswered", Some("unanswered")),
        status_answered = status_opt("answered", "Answered", Some("answered")),
    )
}

fn results_block(s: &SearchShared) -> String {
    if s.results.is_empty() {
        return collection_note(s.state, "No threads matched this search.")
            .unwrap_or_else(|| note("No matches", "No threads matched this search."));
    }
    let rows: String = s.results.iter().map(|r| result_row(r, s.now)).collect();
    format!(
        r#"<section class="ag-search-results" aria-labelledby="ag-search-results-title">
  <h2 class="eyebrow ag-eyebrow" id="ag-search-results-title">Matching discussions</h2>
  <p class="muted ag-desk__bound">Showing {shown} · up to {bound} results (a bounded set, not a total count)</p>
  <ul class="ag-search-list">{rows}</ul>
</section>"#,
        shown = s.results.len(),
        bound = s.visible_bound,
        rows = rows,
    )
}

fn source_label(source: SearchMatchSource) -> &'static str {
    match source {
        SearchMatchSource::Topic => "Matched in the topic",
        SearchMatchSource::AcceptedAnswer => "Matched in the accepted answer",
    }
}

fn result_row(r: &SearchResultVM, now: i64) -> String {
    let th = &r.thread;
    let mut chips = String::from(kind_chip(th.kind));
    if th.kind == ThreadKind::Question {
        chips.push_str(&answer_state_chip(th.answer_state));
    }
    format!(
        r#"<li class="ag-search-hit ag-key-shared">
  <div class="ag-row__chips">{chips}<span class="badge ag-chip-shared ag-search-source">{source}</span></div>
  <a class="ag-row__title" href="{href}">{title}</a>
  <p class="ag-row__by">{monogram} <span class="ag-row__author">{author}</span> · latest {time}</p>
  <p class="ag-search-hit__excerpt">{excerpt}</p>
</li>"#,
        chips = chips,
        source = escape(source_label(r.source)),
        href = escape(&thread_href(&th.id)),
        title = t(&th.title),
        monogram = monogram(&th.author_display.0),
        author = t(&th.author_display),
        time = time_el(th.last_at, now),
        excerpt = t(&r.excerpt),
    )
}

fn note(title: &str, body: &str) -> String {
    format!(
        r#"<div class="card pad empty-card ag-empty" role="status"><p class="empty-title">{title}</p><p class="muted">{body}</p></div>"#,
        title = escape(title),
        body = escape(body),
    )
}
