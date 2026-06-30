//! Local, deterministic text intelligence — self-contained, NO external LLM, NO network.
//!
//! Two capabilities power the forum's compose-time duplicate detection and per-thread
//! summaries. Both are pure Rust over a shared bag-of-words tokeniser, so the same input always
//! yields the same output: cheap to run inline in a request and trivial to unit-test.
//!
//! 1. [`rank`] / [`similarity`] — score texts by cosine similarity over their bag-of-words term
//!    frequencies (common stopwords dropped). Used to surface the existing threads most similar
//!    to a draft, so duplicates collapse before they fragment.
//! 2. [`summarize`] — an extractive summary: rank a body's sentences by the summed salience of
//!    their terms and return the top few in original reading order.

use std::collections::{HashMap, HashSet};
use std::cmp::Ordering;

/// Common English stopwords dropped from the bag of words (kept small + obvious — this is a
/// heuristic, not a linguistics engine).
const STOPWORDS: &[&str] = &[
    "the", "a", "an", "and", "or", "but", "if", "then", "else", "for", "of", "to", "in", "on",
    "at", "by", "is", "are", "was", "were", "be", "been", "being", "it", "its", "this", "that",
    "these", "those", "with", "as", "from", "into", "about", "i", "you", "he", "she", "we",
    "they", "them", "his", "her", "our", "your", "my", "me", "us", "do", "does", "did", "so",
    "not", "no", "yes", "can", "could", "would", "should", "will", "shall", "may", "might",
    "have", "has", "had", "there", "here", "what", "which", "who", "whom", "how", "when", "where",
    "why", "all", "any", "some", "such", "than", "too", "very", "just", "also", "up", "out",
];

/// A scored candidate: its index into the input slice and the cosine score in `0.0..=1.0`.
pub struct Scored {
    pub index: usize,
    pub score: f64,
}

/// Split text into lowercase alphanumeric tokens, dropping stopwords and 1-char fragments.
fn tokenize(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| w.to_lowercase())
        .filter(|w| w.chars().count() >= 2 && !STOPWORDS.contains(&w.as_str()))
        .collect()
}

/// Bag-of-words term-frequency map for a text.
fn term_freq(text: &str) -> HashMap<String, u32> {
    let mut tf = HashMap::new();
    for tok in tokenize(text) {
        *tf.entry(tok).or_insert(0) += 1;
    }
    tf
}

/// Cosine similarity of two term-frequency vectors, in `0.0..=1.0` (0 when either is empty).
fn cosine(a: &HashMap<String, u32>, b: &HashMap<String, u32>) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    // Iterate the smaller map for the dot product.
    let (small, large) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    let mut dot = 0.0f64;
    for (k, v) in small {
        if let Some(w) = large.get(k) {
            dot += (*v as f64) * (*w as f64);
        }
    }
    if dot == 0.0 {
        return 0.0;
    }
    let na = a.values().map(|v| (*v as f64).powi(2)).sum::<f64>().sqrt();
    let nb = b.values().map(|v| (*v as f64).powi(2)).sum::<f64>().sqrt();
    if na == 0.0 || nb == 0.0 {
        0.0
    } else {
        dot / (na * nb)
    }
}

/// Bag-of-words cosine similarity of two raw texts, in `0.0..=1.0`.
pub fn similarity(a: &str, b: &str) -> f64 {
    cosine(&term_freq(a), &term_freq(b))
}

/// Rank `docs` by similarity to `query`, keeping the top `k` whose score is `>= min_score`,
/// most-similar first (ties broken by original index). The query is tokenised once.
pub fn rank(query: &str, docs: &[String], k: usize, min_score: f64) -> Vec<Scored> {
    let q = term_freq(query);
    if q.is_empty() {
        return Vec::new();
    }
    let mut scored: Vec<Scored> = docs
        .iter()
        .enumerate()
        .map(|(index, d)| Scored {
            index,
            score: cosine(&q, &term_freq(d)),
        })
        .filter(|s| s.score >= min_score)
        .collect();
    scored.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(Ordering::Equal)
            .then(a.index.cmp(&b.index))
    });
    scored.truncate(k);
    scored
}

// ---------------------------------------------------------------------------
// Extractive summarisation
// ---------------------------------------------------------------------------

/// Extractive summary: pick the `max_sentences` most salient sentences of `text` and return
/// them in original reading order. Markdown markup is stripped first. When the source has no
/// more sentences than requested, every sentence is returned unchanged (nothing to compress).
pub fn summarize(text: &str, max_sentences: usize) -> Vec<String> {
    if max_sentences == 0 {
        return Vec::new();
    }
    let plain = to_plain(text);
    let sentences = split_sentences(&plain);
    if sentences.len() <= max_sentences {
        return sentences;
    }

    // Global term salience: how often each term occurs across the whole body.
    let sent_tokens: Vec<Vec<String>> = sentences.iter().map(|s| tokenize(s)).collect();
    let mut global: HashMap<&str, u32> = HashMap::new();
    for toks in &sent_tokens {
        for t in toks {
            *global.entry(t.as_str()).or_insert(0) += 1;
        }
    }

    // Score each sentence by the mean salience of its unique terms; very short sentences are
    // discounted so a stray "Thanks!" never displaces a substantive sentence.
    let mut scored: Vec<(usize, f64)> = sent_tokens
        .iter()
        .enumerate()
        .map(|(i, toks)| {
            let mut seen: HashSet<&str> = HashSet::new();
            let mut sum = 0.0f64;
            for t in toks {
                if seen.insert(t.as_str()) {
                    sum += *global.get(t.as_str()).unwrap_or(&0) as f64;
                }
            }
            let uniq = seen.len();
            let score = if uniq == 0 {
                0.0
            } else if uniq < 3 {
                (sum / uniq as f64) * 0.5
            } else {
                sum / uniq as f64
            };
            (i, score)
        })
        .collect();

    // Top-N by score (ties -> earlier sentence wins), then restore reading order.
    scored.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(Ordering::Equal)
            .then(a.0.cmp(&b.0))
    });
    scored.truncate(max_sentences);
    scored.sort_by_key(|(i, _)| *i);
    scored.into_iter().map(|(i, _)| sentences[i].clone()).collect()
}

/// Strip the common markdown / inline-HTML markup so sentence extraction sees readable prose.
/// Conservative on purpose: it removes markup punctuation, unwraps `[text](url)` to its text,
/// and drops `<...>` tags — it never tries to fully parse markdown.
fn to_plain(md: &str) -> String {
    let mut out = String::with_capacity(md.len());
    let mut chars = md.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            // Inline/structural markup punctuation -> dropped.
            '`' | '*' | '_' | '#' | '>' | '~' => {}
            // Link/image: keep the bracketed text, discard the `(url)` part.
            '[' => {
                while let Some(&n) = chars.peek() {
                    chars.next();
                    if n == ']' {
                        break;
                    }
                    out.push(n);
                }
                if chars.peek() == Some(&'(') {
                    chars.next();
                    while let Some(&n) = chars.peek() {
                        chars.next();
                        if n == ')' {
                            break;
                        }
                    }
                }
            }
            // Raw HTML tag -> dropped (so `<script>alert(1)</script>` collapses to `alert(1)`).
            '<' => {
                while let Some(&n) = chars.peek() {
                    chars.next();
                    if n == '>' {
                        break;
                    }
                }
            }
            other => out.push(other),
        }
    }
    out
}

/// Split plain text into trimmed sentences on terminators (`.`/`!`/`?`) and line breaks,
/// keeping only fragments that contain at least one alphanumeric character.
fn split_sentences(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let flush = |cur: &mut String, out: &mut Vec<String>| {
        let s = cur.trim();
        if s.chars().any(|c| c.is_alphanumeric()) {
            out.push(s.to_string());
        }
        cur.clear();
    };
    for ch in text.chars() {
        match ch {
            '.' | '!' | '?' | '\n' | '\r' => flush(&mut cur, &mut out),
            _ => cur.push(ch),
        }
    }
    flush(&mut cur, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_text_is_maximally_similar() {
        let s = similarity("database connection pool tuning", "database connection pool tuning");
        assert!(s > 0.99, "identical token sets score ~1.0, got {s}");
    }

    #[test]
    fn related_scores_above_unrelated() {
        let q = "how to tune the postgres connection pool size";
        let related = "postgres connection pool sizing best practices";
        let unrelated = "favourite pizza topping recipes for the weekend";
        assert!(similarity(q, related) > similarity(q, unrelated));
        assert!(similarity(q, related) > 0.1);
    }

    #[test]
    fn stopwords_do_not_create_false_matches() {
        // Two sentences sharing only stopwords must not look similar.
        let s = similarity("the cat is on the mat", "we are in the house and it is warm");
        assert!(s < 0.05, "stopword-only overlap scored {s}");
    }

    #[test]
    fn rank_returns_top_k_most_similar() {
        let docs = vec![
            "postgres connection pool tuning and sizing".to_string(),
            "weekend pizza recipes".to_string(),
            "connection pool exhaustion in postgres under load".to_string(),
            "favourite movies of the year".to_string(),
        ];
        let ranked = rank("postgres connection pool size", &docs, 3, 0.05);
        assert!(!ranked.is_empty());
        // The two postgres docs (idx 0 and 2) must rank above the off-topic ones.
        assert!(ranked.iter().any(|s| s.index == 0));
        assert!(ranked.iter().any(|s| s.index == 2));
        assert!(!ranked.iter().any(|s| s.index == 1), "pizza must not surface");
        // Scores are non-increasing.
        for w in ranked.windows(2) {
            assert!(w[0].score >= w[1].score);
        }
    }

    #[test]
    fn rank_respects_min_score_and_empty_query() {
        let docs = vec!["totally unrelated content here".to_string()];
        assert!(rank("xyz qrs", &docs, 3, 0.5).is_empty(), "below threshold -> none");
        assert!(rank("the and of", &docs, 3, 0.0).is_empty(), "all-stopword query -> none");
    }

    #[test]
    fn summarize_picks_salient_sentences_in_order() {
        let text = "The deployment failed because the database migration timed out. \
            Pizza is nice. \
            The database migration timed out due to a missing index on the orders table. \
            We added the index and the migration now completes quickly. \
            Thanks.";
        let summary = summarize(text, 2);
        assert_eq!(summary.len(), 2);
        // The two migration/database sentences are the most salient.
        assert!(summary.iter().all(|s| s.to_lowercase().contains("migration")));
        // Returned in original reading order.
        assert!(summary[0].contains("failed"));
    }

    #[test]
    fn summarize_strips_markdown_and_html() {
        let md = "# Heading\n\nThis is **bold** and a [link](http://x.y) to docs. \
            <script>alert(1)</script> end.";
        let summary = summarize(md, 3);
        let joined = summary.join(" ");
        assert!(!joined.contains('#'));
        assert!(!joined.contains('*'));
        assert!(!joined.contains("<script>"));
        assert!(joined.contains("link"), "link text survives");
    }

    #[test]
    fn summarize_short_text_returns_all_sentences() {
        let summary = summarize("Only one sentence here.", 3);
        assert_eq!(summary.len(), 1);
        assert_eq!(summary[0], "Only one sentence here");
    }
}
