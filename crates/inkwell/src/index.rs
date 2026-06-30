//! Pure lexical core for the "ask your blog" feature + semantic related-posts.
//!
//! This module is intentionally I/O-free so the whole chunking + ranking contract is unit-tested
//! with plain values (no DB, no HTTP). The store persists the chunks; the ask handler ranks stored
//! chunks against a question with [`rank`]; the reading view ranks sibling posts with
//! [`doc_score`]. Everything here is local + deterministic — bag-of-words / keyword-overlap, NO
//! external LLM, NO vector service, pure Rust (the same approach as Grimoire's index core).
//!
//! Ranking is bag-of-words: a chunk (or post) scores by how many of the query's DISTINCT terms it
//! contains, weighted by term frequency (a TF-ish signal), with a fixed title-match bonus.

use crate::store::Chunk;

/// Target chunk size, in characters. Longer post bodies are split on word boundaries so a single
/// retrieved chunk stays a readable, citable passage.
pub const CHUNK_CHARS: usize = 900;

/// A chunk paired with its relevance score for a query. Higher is more relevant.
#[derive(Clone, Debug)]
pub struct Scored {
    pub chunk: Chunk,
    pub score: f64,
}

// ---------------------------------------------------------------------------
// Chunking
// ---------------------------------------------------------------------------

/// Split a document `body` into chunks of roughly [`CHUNK_CHARS`] characters, breaking on
/// whitespace so words are never cut. Collapses internal whitespace runs. Returns at least one
/// chunk for any non-empty body; an empty/blank body yields no chunks.
pub fn chunk_body(body: &str, max_chars: usize) -> Vec<String> {
    let max = max_chars.max(1);
    let mut chunks = Vec::new();
    let mut current = String::new();
    let mut current_len = 0usize;

    for word in body.split_whitespace() {
        let wlen = word.chars().count();
        // +1 for the joining space (when current isn't empty).
        let added = if current.is_empty() { wlen } else { wlen + 1 };
        if current_len + added > max && !current.is_empty() {
            chunks.push(std::mem::take(&mut current));
            current_len = 0;
        }
        if !current.is_empty() {
            current.push(' ');
            current_len += 1;
        }
        current.push_str(word);
        current_len += wlen;
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

/// Build the index [`Chunk`]s for one post: chunk its body, tag every chunk with the post's slug
/// (`post_id`, the stable URL key) + title, and assign each a deterministic id so a re-index of the
/// same post cleanly replaces its prior chunks. A post with an empty body still yields one
/// title-only chunk so a title-only post stays retrievable.
pub fn build_post_chunks(post_id: &str, title: &str, body: &str, indexed_at: i64) -> Vec<Chunk> {
    let mut parts = chunk_body(body, CHUNK_CHARS);
    if parts.is_empty() {
        // Title-only post: index the title text as a single chunk so it is still findable.
        parts.push(title.to_string());
    }
    parts
        .into_iter()
        .enumerate()
        .map(|(i, part)| Chunk {
            id: format!("{post_id}__{i:04}"),
            post_id: post_id.to_string(),
            title: title.to_string(),
            body: part,
            indexed_at,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tokenization + scoring
// ---------------------------------------------------------------------------

/// Tokenize text into lowercase alphanumeric terms. Splits on every non-alphanumeric character and
/// drops very short tokens (length < 2) so single letters / punctuation don't dominate the score.
pub fn tokenize(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.chars().count() >= 2)
        .map(|t| t.to_lowercase())
        .collect()
}

/// Relevance of a `title`+`body` document to a set of query terms. BoW/TF-ish: for each DISTINCT
/// query term, add the number of times it occurs in the body (term frequency, log-dampened), plus a
/// fixed bonus when the term also appears in the title (titles are high-signal). `0.0` = no overlap.
pub fn doc_score(query_terms: &[String], title: &str, body: &str) -> f64 {
    if query_terms.is_empty() {
        return 0.0;
    }
    let body_terms = tokenize(body);
    let title_terms = tokenize(title);

    // Distinct query terms only, so a repeated query word doesn't multiply the weight.
    let mut seen = std::collections::HashSet::new();
    let mut total = 0.0;
    for qt in query_terms {
        if !seen.insert(qt.clone()) {
            continue;
        }
        let tf = body_terms.iter().filter(|t| *t == qt).count() as f64;
        if tf > 0.0 {
            // Dampen term frequency so one very long passage can't swamp the ranking.
            total += 1.0 + tf.ln();
        }
        if title_terms.iter().any(|t| t == qt) {
            total += 2.0;
        }
    }
    total
}

/// Relevance of one chunk to a set of query terms (delegates to [`doc_score`]).
pub fn score(query_terms: &[String], chunk: &Chunk) -> f64 {
    doc_score(query_terms, &chunk.title, &chunk.body)
}

/// Rank `chunks` against `query`, returning the top `k` by score (descending), dropping any chunk
/// that does not match at all. Ties are broken by `indexed_at` DESC then chunk id for stability.
pub fn rank(query: &str, chunks: &[Chunk], k: usize) -> Vec<Scored> {
    let terms = tokenize(query);
    if terms.is_empty() {
        return Vec::new();
    }
    let mut scored: Vec<Scored> = chunks
        .iter()
        .filter_map(|c| {
            let s = score(&terms, c);
            if s > 0.0 {
                Some(Scored {
                    chunk: c.clone(),
                    score: s,
                })
            } else {
                None
            }
        })
        .collect();

    scored.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.chunk.indexed_at.cmp(&a.chunk.indexed_at))
            .then_with(|| a.chunk.id.cmp(&b.chunk.id))
    });
    scored.truncate(k);
    scored
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(id: &str, title: &str, body: &str) -> Chunk {
        Chunk {
            id: id.to_string(),
            post_id: "p1".to_string(),
            title: title.to_string(),
            body: body.to_string(),
            indexed_at: 1,
        }
    }

    #[test]
    fn chunk_body_splits_on_words_and_bounds_size() {
        let body = "alpha ".repeat(100);
        let chunks = chunk_body(&body, 50);
        assert!(chunks.len() > 1, "long body splits into multiple chunks");
        for c in &chunks {
            assert!(c.chars().count() <= 50, "chunk respects the size bound");
            assert!(!c.starts_with(' ') && !c.ends_with(' '));
        }
    }

    #[test]
    fn chunk_body_single_chunk_for_short_body() {
        let chunks = chunk_body("a short note", CHUNK_CHARS);
        assert_eq!(chunks, vec!["a short note".to_string()]);
    }

    #[test]
    fn chunk_body_empty_is_no_chunks() {
        assert!(chunk_body("   ", CHUNK_CHARS).is_empty());
        assert!(chunk_body("", CHUNK_CHARS).is_empty());
    }

    #[test]
    fn build_post_chunks_tags_and_ids() {
        let chunks = build_post_chunks("hello-world", "Hello World", "the body text", 7);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].post_id, "hello-world");
        assert_eq!(chunks[0].title, "Hello World");
        assert_eq!(chunks[0].indexed_at, 7);
        assert_eq!(chunks[0].id, "hello-world__0000");
    }

    #[test]
    fn build_post_chunks_title_only_for_empty_body() {
        let chunks = build_post_chunks("t", "Just a Title", "   ", 1);
        assert_eq!(chunks.len(), 1, "title-only post stays retrievable");
        assert_eq!(chunks[0].body, "Just a Title");
    }

    #[test]
    fn tokenize_lowercases_and_drops_short() {
        assert_eq!(tokenize("The Rust Gateway, v2!"), vec!["the", "rust", "gateway", "v2"]);
        assert!(tokenize("a I .").is_empty(), "1-char tokens dropped");
    }

    #[test]
    fn score_counts_overlap_and_title_bonus() {
        let q = tokenize("gateway");
        let body_hit = chunk("c1", "Misc", "the gateway is up and the gateway is fast");
        let title_hit = chunk("c2", "Gateway design", "unrelated text here");
        let miss = chunk("c3", "Nope", "nothing relevant");
        assert!(score(&q, &body_hit) > 0.0);
        assert!(score(&q, &title_hit) >= 2.0, "title match scores the bonus");
        assert_eq!(score(&q, &miss), 0.0);
    }

    #[test]
    fn rank_orders_and_truncates() {
        let chunks = vec![
            chunk("c1", "Misc", "gateway"),
            chunk("c2", "Gateway primer", "the gateway routes the gateway"),
            chunk("c3", "Nope", "irrelevant"),
        ];
        let top = rank("gateway", &chunks, 2);
        assert_eq!(top.len(), 2, "k limit applied, miss dropped");
        assert_eq!(top[0].chunk.id, "c2", "title + body hit ranks first");
    }

    #[test]
    fn rank_empty_query_is_empty() {
        let chunks = vec![chunk("c1", "t", "gateway")];
        assert!(rank("   ", &chunks, 5).is_empty());
    }

    #[test]
    fn doc_score_powers_related_posts() {
        let terms = tokenize("rust async runtime");
        let near = doc_score(&terms, "Async Rust", "the rust runtime drives async tasks");
        let far = doc_score(&terms, "Cooking", "a recipe for bread");
        assert!(near > far);
        assert_eq!(far, 0.0);
    }
}
