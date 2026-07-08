//! "Ask your blog" — local, extractive retrieval over the blog's OWN published posts.
//!
//! `GET /ask` renders the ask console; `POST /api/ask` retrieves the top chunks for the question by
//! keyword-overlap and returns an EXTRACTIVE answer — the most relevant passages, stitched together
//! with `[n]` markers and linked back to the source posts. There is NO external LLM: the answer is
//! built locally and deterministically from the indexed post corpus, so the feature is fully
//! self-contained and never depends on a model being reachable.
//!
//! Like the authoring flow, `/api/ask` is mounted behind the gateway `auth=sso` route: the user
//! identity is taken from the injected `X-Auth-*`, and the POST is double-submit CSRF protected.
//! The index is rebuildable + self-healing: an empty index triggers a lazy full rebuild on the
//! first ask, so the feature works without any explicit reindex step.

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use crate::auth;
use crate::error::AppError;
use crate::handlers::{esc, fmt_date, page_shell};
use crate::index::{self, Scored};
use crate::AppState;

const ASK_HTML: &str = include_str!("../../templates/ask.html");

/// How many post passages to retrieve and cite per question.
const TOP_K: usize = 5;
/// Hard cap on a question length (chars) — bounds the work.
const MAX_QUESTION_CHARS: usize = 2000;
/// How many characters of a passage to show per citation.
const SNIPPET_CHARS: usize = 300;

/// Ask form body. Identity is NEVER taken from the form — only from the gateway headers.
#[derive(Debug, Deserialize)]
pub struct AskForm {
    #[serde(default)]
    pub question: String,
    #[serde(default)]
    pub csrf_token: String,
}

// ---------------------------------------------------------------------------
// GET /ask — the ask console
// ---------------------------------------------------------------------------

/// `GET /ask` — the ask console: a question box + an empty answer area.
pub async fn ask_page(State(_state): State<AppState>, headers: HeaderMap) -> Response {
    let email = auth::display_email(&headers);
    let is_admin = auth::is_admin(&headers);
    let theme = odyssey::resolve_theme(
        headers
            .get(axum::http::header::COOKIE)
            .and_then(|v| v.to_str().ok()),
    );
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let page = render_console(&email, is_admin, theme, &csrf, "", &empty_answer());
    html_with_cookie(page, set_cookie)
}

// ---------------------------------------------------------------------------
// POST /api/ask — retrieve + extractive answer
// ---------------------------------------------------------------------------

/// `POST /api/ask` — retrieve the top passages by keyword-overlap and render an extractive answer
/// with citations linked to the source posts. Never 500s on retrieval shape; an empty index is
/// rebuilt lazily on the way in.
pub async fn ask(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AskForm>,
) -> Result<Response, AppError> {
    let (_sub, email) = auth::require_author(&headers)?;
    let is_admin = auth::is_admin(&headers);
    let theme = odyssey::resolve_theme(
        headers
            .get(axum::http::header::COOKIE)
            .and_then(|v| v.to_str().ok()),
    );
    auth::verify_csrf(&headers, &form.csrf_token)?;
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    let question: String = form
        .question
        .trim()
        .chars()
        .take(MAX_QUESTION_CHARS)
        .collect();
    if question.is_empty() {
        return Err(AppError::InvalidRequest(
            "a question is required".to_string(),
        ));
    }

    // Lazy initial index: if nothing is indexed yet, rebuild from the published posts first so the
    // very first ask has something to retrieve.
    if state.store.count_chunks().await == 0 {
        let n = crate::build_full_index(state.store.as_ref()).await;
        tracing::info!(chunks = n, "lazy index build on first ask");
    }

    let chunks = state.store.fetch_chunks().await;
    let top = index::rank(&question, &chunks, TOP_K);

    let answer_html = if top.is_empty() {
        no_results_answer(&question)
    } else {
        render_answer(&top)
    };
    let echo = format!(
        r#"<blockquote class="ink-echo"><span class="ink-echo__kicker">You asked</span>{}</blockquote>"#,
        esc(&question)
    );

    let page = render_console(
        &email,
        is_admin,
        theme,
        &csrf,
        &question,
        &format!("{echo}{answer_html}"),
    );
    Ok(html_with_cookie(page, set_cookie))
}

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------

/// Render the full console page around its parts.
fn render_console(
    email: &str,
    is_admin: bool,
    theme: &str,
    csrf: &str,
    question: &str,
    answer_html: &str,
) -> String {
    let fragment = ASK_HTML
        .replace("{{CSRF}}", &esc(csrf))
        .replace("{{QUESTION}}", &esc(question))
        .replace("{{ANSWER}}", answer_html);
    page_shell(
        "Ask the blog · Inkwell",
        "page-console",
        false,
        "Ask",
        email,
        is_admin,
        theme,
        &fragment,
    )
}

/// Render the extractive answer: the top passages stitched with `[n]` markers, then a linked list
/// of the cited source posts. Every interpolated field is HTML-escaped.
fn render_answer(top: &[Scored]) -> String {
    let mut passages = String::new();
    let mut sources = String::new();
    for (i, s) in top.iter().enumerate() {
        let n = i + 1;
        let snippet = esc(&snippet_of(&s.chunk.body, SNIPPET_CHARS));
        passages.push_str(&format!(
            r#"<p class="answer__passage"><span class="answer__n">[{n}]</span> {snippet}</p>"#,
            n = n,
            snippet = snippet,
        ));
        sources.push_str(&format!(
            r#"<li class="cite">
  <span class="cite__n">[{n}]</span>
  <a class="cite__title" href="/p/{slug}">{title}</a>
  <span class="cite__date muted">{date}</span>
</li>"#,
            n = n,
            slug = esc(&s.chunk.post_id),
            title = esc(&s.chunk.title),
            date = esc(&fmt_date(s.chunk.indexed_at)),
        ));
    }
    format!(
        r#"<section class="answer">
  <div class="answer__head"><h2>Answer</h2><span class="muted">the most relevant passages from your posts</span></div>
  <div class="answer__body">{passages}</div>
  <div class="sources">
    <h3 class="sources__head">Sources</h3>
    <ul class="sources__list">{sources}</ul>
  </div>
</section>"#,
        passages = passages,
        sources = sources,
    )
}

/// The empty answer area (GET /ask, before any question).
fn empty_answer() -> String {
    r#"<section class="answer answer--empty">
  <div class="empty-state">
    <h2>Ask anything you've published</h2>
    <p>Inkwell searches your own posts and answers with the most relevant passages, linked to the originals.</p>
    <p class="ink-ask__try muted">Try: “What have I written about deployment?” · “How does the gateway route requests?”</p>
  </div>
</section>"#
        .to_string()
}

/// Answer area when retrieval found nothing for the question.
fn no_results_answer(question: &str) -> String {
    format!(
        r#"<section class="answer">
  <div class="empty-state">
    <h2>No matching posts</h2>
    <p>Nothing in your published posts matched <strong>"{q}"</strong>. Try different words.</p>
    <form class="ink-ask-redo" method="get" action="/search"><input type="hidden" name="q" value="{q}"><button class="btn btn-ghost" type="submit">Search the blog instead</button></form>
  </div>
</section>"#,
        q = esc(question),
    )
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

/// An HTML response, optionally attaching a freshly-minted CSRF `Set-Cookie`.
fn html_with_cookie(body: String, set_cookie: Option<String>) -> Response {
    let mut resp = Html(body).into_response();
    if let Some(c) = set_cookie {
        if let Ok(value) = HeaderValue::from_str(&c) {
            resp.headers_mut().insert(header::SET_COOKIE, value);
        }
    }
    resp
}
