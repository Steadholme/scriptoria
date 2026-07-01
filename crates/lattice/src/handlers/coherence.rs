//! `GET /coherence` — the maintenance/coherence view.
//!
//! A read-only report (no writes, so no CSRF) sitting behind the same Sluice `auth=sso` route as
//! the rest of the wiki. It lists two things, both computed locally from the current page set:
//!
//!  - **Stale pages** — not edited in more than `LATTICE_STALE_DAYS` days (default 120).
//!  - **Contradiction candidates** — pairs of pages whose titles strongly overlap (same topic)
//!    yet whose bodies diverge. This is a HEURISTIC FLAG for a human to review — never a claim
//!    that the pages actually contradict.
//!
//! It never 500s on an empty wiki: both sections degrade to a friendly empty state.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Html;

use crate::config::MAX_PAGE;
use crate::error::AppError;
use crate::graph::{Contradiction, Corpus, StalePage};
use crate::render::{esc, fmt_ts, layout};
use crate::{now_ms, AppState};

pub async fn coherence(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Html<String>, AppError> {
    let pages = state.store.list_pages(None, MAX_PAGE).await?;
    let total = pages.len();
    let corpus = Corpus::build(pages);
    let stale = corpus.stale(now_ms(), state.config.stale_days);
    let contradictions = corpus.contradictions();

    let content = render_coherence(total, state.config.stale_days, &stale, &contradictions);
    Ok(Html(layout("Coherence", &headers, &content)))
}

fn render_coherence(
    total: usize,
    stale_days: i64,
    stale: &[StalePage],
    contradictions: &[Contradiction],
) -> String {
    let head = format!(
        "<div class=\"page-head\">\
           <div>\
             <h1>Coherence</h1>\
             <p class=\"muted\">{total} page{plural} · {stale_n} stale · {contra_n} contradiction candidate{contra_plural}</p>\
           </div>\
           <a class=\"btn btn-secondary btn-sm\" href=\"/\">Back to the index</a>\
         </div>",
        total = total,
        plural = if total == 1 { "" } else { "s" },
        stale_n = stale.len(),
        contra_n = contradictions.len(),
        contra_plural = if contradictions.len() == 1 { "" } else { "s" },
    );

    format!(
        "{head}{stale}{contra}\
         <p class=\"site-foot\">Stale + contradiction signals are computed locally (no edits made). \
          Contradiction candidates are a heuristic for review, not a verdict.</p>",
        head = head,
        stale = render_stale(stale_days, stale),
        contra = render_contradictions(contradictions),
    )
}

fn render_stale(stale_days: i64, stale: &[StalePage]) -> String {
    let body = if stale.is_empty() {
        format!(
            "<div class=\"list-empty\">No pages older than {stale_days} days. The wiki is fresh.</div>"
        )
    } else {
        let rows: String = stale
            .iter()
            .map(|s| {
                format!(
                    "<tr>\
                       <td class=\"c-title\"><a href=\"/w/{slug}\">{title}</a></td>\
                       <td class=\"h-when\"><time>{when}</time></td>\
                       <td class=\"h-editor\">{editor}</td>\
                       <td class=\"h-size\">{age} days ago</td>\
                     </tr>",
                    slug = esc(&s.slug),
                    title = esc(&s.title),
                    when = esc(&fmt_ts(s.updated_at)),
                    editor = esc(&s.updated_by_email),
                    age = s.age_days,
                )
            })
            .collect();
        format!(
            "<table class=\"history\">\
               <thead><tr><th>Page</th><th>Last edited (UTC)</th><th>Editor</th><th>Age</th></tr></thead>\
               <tbody>{rows}</tbody>\
             </table>"
        )
    };

    format!(
        "<section class=\"coherence-block\">\
           <div class=\"coherence-block__head\">\
             <h2>Stale pages</h2>\
             <p class=\"muted\">Not edited in more than {stale_days} days.</p>\
           </div>\
           <div class=\"card\">{body}</div>\
         </section>"
    )
}

fn render_contradictions(contradictions: &[Contradiction]) -> String {
    let body = if contradictions.is_empty() {
        "<div class=\"list-empty\">No contradiction candidates — no two same-topic pages diverge.</div>"
            .to_string()
    } else {
        let items: String = contradictions
            .iter()
            .map(|c| {
                let terms: String = c
                    .shared_terms
                    .iter()
                    .map(|t| format!("<code>{}</code>", esc(t)))
                    .collect::<Vec<_>>()
                    .join(" ");
                format!(
                    "<li class=\"contra\">\
                       <div class=\"contra__pair\">\
                         <a href=\"/w/{a_slug}\">{a_title}</a>\
                         <span class=\"contra__vs\" aria-hidden=\"true\">⇄</span>\
                         <a href=\"/w/{b_slug}\">{b_title}</a>\
                       </div>\
                       <div class=\"contra__meta\">shared topic: {terms} · body similarity {sim}</div>\
                     </li>",
                    a_slug = esc(&c.a.slug),
                    a_title = esc(&c.a.title),
                    b_slug = esc(&c.b.slug),
                    b_title = esc(&c.b.title),
                    terms = terms,
                    sim = format_sim(c.body_similarity),
                )
            })
            .collect();
        format!("<ul class=\"contra-list\">{items}</ul>")
    };

    format!(
        "<section class=\"coherence-block\">\
           <div class=\"coherence-block__head\">\
             <h2>Contradiction candidates</h2>\
             <p class=\"muted\">Same topic by title, divergent bodies — review for drift or disagreement.</p>\
           </div>\
           <div class=\"card\">{body}</div>\
         </section>"
    )
}

/// Two-decimal similarity for display (e.g. `0.21`).
fn format_sim(sim: f64) -> String {
    format!("{:.2}", sim)
}
