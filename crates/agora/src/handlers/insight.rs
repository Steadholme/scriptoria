//! Local text-intelligence endpoints (JSON): compose-time duplicate detection + per-thread
//! extractive summaries. Both are powered by [`crate::textsim`] — pure Rust, deterministic, NO
//! external LLM. They are ADDITIVE: every existing forum page/route is untouched.
//!
//! - `POST /api/similar` (SSO + CSRF): given a draft `{title, body}`, returns the top-3 existing
//!   threads most similar to it, so a user can spot a duplicate before posting. Same
//!   double-submit CSRF + gateway-identity guard as the other POSTs.
//! - `GET  /api/thread/{id}/summary`: the extractive summary for the same bounded reply page as
//!   the HTML thread view. Read-only, like the other GETs.
//!
//! Errors reuse [`AppError`] (the same branded surface as the rest of the app); the empty/no-op
//! cases return `200` with an empty list rather than an error, so the UI never has to special-
//! case a failure and the endpoints never 500 on ordinary input.

use axum::extract::{Form, Path, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth;
use crate::error::AppError;
use crate::handlers::forum::{summary_state, thread_page_boundary, ThreadQuery};
use crate::model::Post;
use crate::view_model::{SummaryStateVM, SummaryUnavailableReason};
use crate::{textsim, AppState};

/// How many recent threads to score a draft against.
const DIGEST_LIMIT: i64 = 500;
/// How many similar threads to surface.
const TOP_K: usize = 3;
/// Minimum cosine score for a thread to count as "similar" (filters weak/coincidental overlap).
const MIN_SCORE: f64 = 0.08;
/// Sentences in a thread summary.
const SUMMARY_SENTENCES: usize = 3;

// ===========================================================================
// POST /api/similar — top-3 existing threads similar to a draft
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct SimilarForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub body: String,
}

/// One similar existing thread surfaced for a draft.
#[derive(Debug, Serialize)]
pub struct SimilarThread {
    pub id: String,
    pub title: String,
    pub category_id: String,
    /// Cosine similarity in `0.0..=1.0`, rounded to 3 decimals (presentation only).
    pub score: f64,
}

#[derive(Debug, Serialize)]
pub struct SimilarResponse {
    pub similar: Vec<SimilarThread>,
}

pub async fn similar(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SimilarForm>,
) -> Result<Json<SimilarResponse>, AppError> {
    // Same guards as the other state-adjacent POSTs: double-submit CSRF + gateway identity.
    auth::verify_csrf(&headers, &form.csrf)?;
    let _author = auth::require_author(&headers)?;

    let query = format!("{}\n{}", form.title.trim(), form.body.trim());
    if query.trim().is_empty() {
        return Ok(Json(SimilarResponse {
            similar: Vec::new(),
        }));
    }

    let digests = state.store.thread_digests(DIGEST_LIMIT).await?;
    // Each candidate document is the thread's title + its original-post body.
    let docs: Vec<String> = digests
        .iter()
        .map(|d| format!("{}\n{}", d.title, d.first_body_md))
        .collect();

    let similar = textsim::rank(&query, &docs, TOP_K, MIN_SCORE)
        .into_iter()
        .map(|s| {
            let d = &digests[s.index];
            SimilarThread {
                id: d.id.clone(),
                title: d.title.clone(),
                category_id: d.category_id.clone(),
                score: (s.score * 1000.0).round() / 1000.0,
            }
        })
        .collect();

    Ok(Json(SimilarResponse { similar }))
}

// ===========================================================================
// GET /api/thread/{id}/summary — extractive summary of a thread
// ===========================================================================

#[derive(Debug, Serialize)]
pub struct SummaryResponse {
    pub thread_id: String,
    /// Posts in this explicit HTML/JSON page boundary, not the whole thread.
    pub post_count: i64,
    pub word_count: i64,
    pub sentence_bound: i64,
    pub scope: &'static str,
    pub state: &'static str,
    pub summary: Vec<String>,
}

pub async fn summary(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<ThreadQuery>,
    headers: HeaderMap,
) -> Result<Json<SummaryResponse>, AppError> {
    let viewer = auth::identity_subject(&headers);
    let boundary = thread_page_boundary(&state, &id, &q, viewer.as_deref()).await?;
    let thread_id = boundary.thread_id().to_string();
    let posts = boundary.visible_posts();
    let (state_name, word_count, sentence_bound, summary) = match summary_state(&posts) {
        SummaryStateVM::Available(summary) => (
            "available",
            summary.source_word_count,
            summary.sentence_bound,
            summary
                .sentences
                .into_iter()
                .map(|sentence| sentence.0)
                .collect(),
        ),
        SummaryStateVM::Unavailable(reason) => {
            let state = match reason {
                SummaryUnavailableReason::TooFewPosts => "too_few_posts",
                SummaryUnavailableReason::TooFewWords => "too_few_words",
                SummaryUnavailableReason::Unavailable => "unavailable",
            };
            (
                state,
                posts
                    .iter()
                    .map(|post| post.body_md.split_whitespace().count() as i64)
                    .sum(),
                SUMMARY_SENTENCES as i64,
                Vec::new(),
            )
        }
    };

    Ok(Json(SummaryResponse {
        thread_id,
        post_count: posts.len() as i64,
        word_count,
        sentence_bound,
        scope: "visible_page",
        state: state_name,
        summary,
    }))
}

/// Extractive summary of a bounded page's posts, in reading order.
pub fn thread_summary(posts: &[Post], max_sentences: usize) -> Vec<String> {
    let combined = posts
        .iter()
        .map(|p| p.body_md.as_str())
        .collect::<Vec<_>>()
        .join("\n\n");
    textsim::summarize(&combined, max_sentences)
}
