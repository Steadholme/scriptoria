//! Local, deterministic "find similar snippet" via bag-of-words cosine similarity.
//!
//! Pure Rust, no external model: a snippet is reduced to a term-frequency bag over lowercased
//! alphanumeric word tokens (title + body), and two snippets are scored by the cosine of their
//! TF vectors. The view handler ranks an author's other pastes by this score and shows the top
//! few — a self-contained, offline "AI" feature with no Relay/LLM dependency.

use std::collections::HashMap;

/// Minimum token length kept in the bag (drops single-character noise).
const MIN_TOKEN_LEN: usize = 2;
/// Tokens scanned per document — bounds work on very large pastes.
const MAX_TOKENS: usize = 4096;

/// Split `text` into lowercased alphanumeric word tokens (`_` included), keeping tokens of at
/// least [`MIN_TOKEN_LEN`] chars, capped at [`MAX_TOKENS`].
pub fn tokenize(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in text.chars() {
        if c.is_alphanumeric() || c == '_' {
            cur.extend(c.to_lowercase());
        } else if !cur.is_empty() {
            push_token(&mut out, &mut cur);
            if out.len() >= MAX_TOKENS {
                return out;
            }
        }
    }
    if !cur.is_empty() {
        push_token(&mut out, &mut cur);
    }
    out
}

fn push_token(out: &mut Vec<String>, cur: &mut String) {
    if cur.chars().count() >= MIN_TOKEN_LEN {
        out.push(std::mem::take(cur));
    } else {
        cur.clear();
    }
}

/// Term-frequency bag for a token list.
pub fn bag(tokens: &[String]) -> HashMap<String, u32> {
    let mut map = HashMap::new();
    for t in tokens {
        *map.entry(t.clone()).or_insert(0) += 1;
    }
    map
}

/// Cosine similarity of two term-frequency bags, in `[0.0, 1.0]`. Empty bags score `0.0`.
pub fn cosine(a: &HashMap<String, u32>, b: &HashMap<String, u32>) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    // Iterate the smaller map for the dot product.
    let (small, large) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    let mut dot = 0.0_f64;
    for (term, &count) in small {
        if let Some(&other) = large.get(term) {
            dot += count as f64 * other as f64;
        }
    }
    if dot == 0.0 {
        return 0.0;
    }
    let norm = |m: &HashMap<String, u32>| -> f64 {
        m.values().map(|&v| (v as f64) * (v as f64)).sum::<f64>().sqrt()
    };
    dot / (norm(a) * norm(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_lowercases_and_drops_singletons() {
        assert_eq!(
            tokenize("Hello, WORLD! a b2 c"),
            vec!["hello", "world", "b2"]
        );
    }

    #[test]
    fn identical_docs_score_one() {
        let t = tokenize("the quick brown fox jumps");
        let s = cosine(&bag(&t), &bag(&t));
        assert!((s - 1.0).abs() < 1e-9);
    }

    #[test]
    fn disjoint_docs_score_zero() {
        let a = bag(&tokenize("alpha beta gamma"));
        let b = bag(&tokenize("delta epsilon zeta"));
        assert_eq!(cosine(&a, &b), 0.0);
    }

    #[test]
    fn partial_overlap_is_between() {
        let a = bag(&tokenize("server listen ssl config nginx"));
        let b = bag(&tokenize("server listen http config apache"));
        let s = cosine(&a, &b);
        assert!(s > 0.0 && s < 1.0, "score was {s}");
    }

    #[test]
    fn empty_doc_scores_zero() {
        assert_eq!(cosine(&bag(&tokenize("")), &bag(&tokenize("x y"))), 0.0);
    }
}
