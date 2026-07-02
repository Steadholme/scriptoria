//! Semantic backlink graph + coherence analysis over the wiki corpus.
//!
//! Pure, deterministic, LOCAL — no external services, no LLM. Everything here is computed on the
//! fly from the pages the store already holds (their `title` + `body_md`), so the feature adds NO
//! schema and NO migration: the graph is always consistent with the current page set, and the
//! existing page CRUD/render path is untouched.
//!
//! It computes four things:
//!  - **explicit backlinks** — pages that reference a page via a `[[wiki-link]]` or a
//!    `[label](/w/slug)` markdown link ("Linked from"),
//!  - **related pages** — keyword-overlap neighbours, scored by TF-IDF cosine over title+body
//!    ("Related"); a self-contained bag-of-words model, no embeddings,
//!  - **stale pages** — not edited in more than `stale_days` days,
//!  - **contradiction candidates** — pairs whose titles strongly overlap (same topic) yet whose
//!    bodies are dissimilar (potential drift/disagreement). This is a HEURISTIC FLAG for a human
//!    to review, never a claim that the pages actually contradict.
//!
//! Like the index, analysis is bounded by the page set the store returns (`MAX_PAGE`).

use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};

use crate::slug::slugify;
use crate::store::Page;

/// Shortest token kept as a significant term (drops `a`, `is`, `to`, …).
const MIN_TERM_LEN: usize = 3;
/// Milliseconds in one day (stale-age arithmetic).
const MS_PER_DAY: i64 = 86_400_000;
/// Most "related" pages surfaced on a page's relations panel.
pub const RELATED_LIMIT: usize = 6;
/// Minimum TF-IDF cosine for a page to be surfaced as "related".
const RELATED_MIN_SIM: f64 = 0.08;
/// Most contradiction-candidate pairs surfaced on the coherence view.
pub const CONTRADICTION_LIMIT: usize = 50;
/// Title-term Jaccard at/above which two pages are treated as "about the same thing".
const TITLE_SIM_MIN: f64 = 0.34;
/// Body cosine at/below which two same-topic pages count as "divergent".
const BODY_DIVERGE_MAX: f64 = 0.5;

/// Tiny English stop-word list — common glue words carry no topical signal.
const STOPWORDS: &[&str] = &[
    "the", "and", "for", "are", "but", "not", "you", "all", "any", "can", "had", "her", "was",
    "one", "our", "out", "day", "get", "has", "him", "his", "how", "its", "may", "new", "now",
    "old", "see", "two", "way", "who", "boy", "did", "use", "this", "that", "with", "from",
    "they", "them", "then", "than", "have", "has", "will", "would", "could", "should", "their",
    "there", "these", "those", "when", "what", "which", "while", "into", "over", "such", "your",
    "page", "pages", "wiki", "also", "been", "more", "most", "some", "only", "very", "each",
    "about", "after", "before", "between", "under", "above", "here",
];

fn is_stopword(t: &str) -> bool {
    STOPWORDS.contains(&t)
}

/// Split text into lowercased significant terms (alphanumeric runs, length-filtered, stop-words
/// and pure-numeric tokens dropped). Used for both the TF-IDF model and the title-term sets.
fn tokenize(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in text.chars() {
        if ch.is_alphanumeric() {
            for lower in ch.to_lowercase() {
                cur.push(lower);
            }
        } else if !cur.is_empty() {
            push_term(&mut out, &cur);
            cur.clear();
        }
    }
    if !cur.is_empty() {
        push_term(&mut out, &cur);
    }
    out
}

fn push_term(out: &mut Vec<String>, t: &str) {
    if t.chars().count() >= MIN_TERM_LEN && !is_stopword(t) && !t.chars().all(|c| c.is_numeric()) {
        out.push(t.to_string());
    }
}

/// The set of page slugs a body references, via `[[Target]]`/`[[Target|Label]]` wiki-links AND
/// `[label](/w/slug)` markdown links. Targets are slugified through the SAME [`slugify`] the
/// router uses, so a reference resolves to a page iff the page exists under that slug.
pub fn referenced_slugs(body_md: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();

    // [[Target]] / [[Target|Label]]
    let mut i = 0;
    while let Some(rel) = body_md[i..].find("[[") {
        let open = i + rel;
        let Some(crel) = body_md[open + 2..].find("]]") else {
            break;
        };
        let close = open + 2 + crel;
        let inner = &body_md[open + 2..close];
        let target = inner.split('|').next().unwrap_or("").trim();
        let s = slugify(target);
        if !s.is_empty() {
            out.insert(s);
        }
        i = close + 2;
    }

    // [label](/w/slug) markdown links
    let needle = "](/w/";
    let mut j = 0;
    while let Some(rel) = body_md[j..].find(needle) {
        let start = j + rel + needle.len();
        let rest = &body_md[start..];
        let end = rest
            .find(|c: char| matches!(c, ')' | '#' | '?' | '"') || c.is_whitespace())
            .unwrap_or(rest.len());
        let s = slugify(&rest[..end]);
        if !s.is_empty() {
            out.insert(s);
        }
        j = start + end;
    }

    out
}

/// A reference to a page by its canonical slug + display title.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkRef {
    pub slug: String,
    pub title: String,
}

/// The relations panel shown beneath a page: explicit backlinks + keyword-related pages.
#[derive(Clone, Debug, Default)]
pub struct PagePanel {
    pub backlinks: Vec<LinkRef>,
    pub related: Vec<LinkRef>,
}

impl PagePanel {
    pub fn is_empty(&self) -> bool {
        self.backlinks.is_empty() && self.related.is_empty()
    }
}

/// A page that has not been edited within the staleness window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StalePage {
    pub slug: String,
    pub title: String,
    pub updated_by_email: String,
    pub updated_at: i64,
    pub age_days: i64,
}

/// A heuristic contradiction candidate: two same-topic pages whose bodies diverge.
#[derive(Clone, Debug)]
pub struct Contradiction {
    pub a: LinkRef,
    pub b: LinkRef,
    pub shared_terms: Vec<String>,
    pub body_similarity: f64,
}

/// Per-page derived data:
///  - `weights`/`norm`: the TF-IDF vector (title+body) used for "related" ranking across the
///    corpus (down-weights words common to many pages),
///  - `body_tf`/`body_norm`: a RAW term-frequency vector over the body only, used to measure
///    whether two specific bodies agree. Raw (un-IDF'd) so it is corpus-size independent —
///    identical bodies score 1.0 even in a two-page wiki, where every term's IDF would be zero.
struct Doc {
    weights: HashMap<String, f64>,
    norm: f64,
    body_tf: HashMap<String, f64>,
    body_norm: f64,
    title_terms: BTreeSet<String>,
    refs: BTreeSet<String>,
}

/// The analysed corpus. Built once from the page set, then queried for panels + coherence.
pub struct Corpus {
    pages: Vec<Page>,
    docs: Vec<Doc>,
    index: HashMap<String, usize>,
}

impl Corpus {
    /// Tokenize every page, compute document frequencies, and derive a TF-IDF vector per page.
    /// Terms that appear in EVERY page get zero IDF and are dropped (no topical signal).
    pub fn build(pages: Vec<Page>) -> Self {
        let n = pages.len();
        let mut tfs: Vec<HashMap<String, f64>> = Vec::with_capacity(n);
        let mut body_tfs: Vec<HashMap<String, f64>> = Vec::with_capacity(n);
        let mut title_terms_v: Vec<BTreeSet<String>> = Vec::with_capacity(n);
        let mut refs_v: Vec<BTreeSet<String>> = Vec::with_capacity(n);
        let mut df: HashMap<String, usize> = HashMap::new();

        for p in &pages {
            let title_tokens = tokenize(&p.title);
            let body_tokens = tokenize(&p.body_md);

            let mut tf: HashMap<String, f64> = HashMap::new();
            for t in title_tokens.iter().chain(body_tokens.iter()) {
                *tf.entry(t.clone()).or_insert(0.0) += 1.0;
            }
            for t in tf.keys() {
                *df.entry(t.clone()).or_insert(0) += 1;
            }

            let mut body_tf: HashMap<String, f64> = HashMap::new();
            for t in &body_tokens {
                *body_tf.entry(t.clone()).or_insert(0.0) += 1.0;
            }

            title_terms_v.push(title_tokens.into_iter().collect());
            refs_v.push(referenced_slugs(&p.body_md));
            tfs.push(tf);
            body_tfs.push(body_tf);
        }

        let nf = n as f64;
        let mut docs = Vec::with_capacity(n);
        for (k, tf) in tfs.into_iter().enumerate() {
            let mut weights = HashMap::with_capacity(tf.len());
            let mut sumsq = 0.0;
            for (t, c) in tf {
                let dfi = *df.get(&t).unwrap_or(&1) as f64;
                let idf = (nf / dfi).ln();
                if idf <= 0.0 {
                    continue; // term in every doc -> no signal
                }
                let w = c * idf;
                sumsq += w * w;
                weights.insert(t, w);
            }
            let body_tf = std::mem::take(&mut body_tfs[k]);
            let body_norm = body_tf.values().map(|c| c * c).sum::<f64>().sqrt();
            docs.push(Doc {
                weights,
                norm: sumsq.sqrt(),
                body_tf,
                body_norm,
                title_terms: std::mem::take(&mut title_terms_v[k]),
                refs: std::mem::take(&mut refs_v[k]),
            });
        }

        let index = pages
            .iter()
            .enumerate()
            .map(|(i, p)| (p.slug.clone(), i))
            .collect();

        Self { pages, docs, index }
    }

    /// Cosine similarity between two pages' TF-IDF vectors (0.0 when either is empty).
    fn cosine(&self, i: usize, j: usize) -> f64 {
        let a = &self.docs[i];
        let b = &self.docs[j];
        if a.norm == 0.0 || b.norm == 0.0 {
            return 0.0;
        }
        // Iterate the smaller map for the dot product.
        let (small, big) = if a.weights.len() <= b.weights.len() {
            (a, b)
        } else {
            (b, a)
        };
        let mut dot = 0.0;
        for (t, w) in &small.weights {
            if let Some(w2) = big.weights.get(t) {
                dot += w * w2;
            }
        }
        dot / (a.norm * b.norm)
    }

    /// Raw (non-IDF) body term-frequency cosine — how lexically alike two bodies are, independent
    /// of corpus size. 1.0 = identical bodies, 0.0 = no shared terms. Used to gauge "divergence".
    fn body_cosine(&self, i: usize, j: usize) -> f64 {
        let a = &self.docs[i];
        let b = &self.docs[j];
        if a.body_norm == 0.0 || b.body_norm == 0.0 {
            return 0.0;
        }
        let (small, big) = if a.body_tf.len() <= b.body_tf.len() {
            (a, b)
        } else {
            (b, a)
        };
        let mut dot = 0.0;
        for (t, c) in &small.body_tf {
            if let Some(c2) = big.body_tf.get(t) {
                dot += c * c2;
            }
        }
        dot / (a.body_norm * b.body_norm)
    }

    /// Pages that explicitly reference `slug` (excluding the page itself), title-sorted.
    pub fn backlinks(&self, slug: &str) -> Vec<LinkRef> {
        let mut v: Vec<LinkRef> = self
            .pages
            .iter()
            .enumerate()
            .filter(|(idx, p)| p.slug != slug && self.docs[*idx].refs.contains(slug))
            .map(|(_, p)| LinkRef {
                slug: p.slug.clone(),
                title: p.title.clone(),
            })
            .collect();
        v.sort_by(|a, b| {
            a.title
                .to_lowercase()
                .cmp(&b.title.to_lowercase())
                .then_with(|| a.slug.cmp(&b.slug))
        });
        v
    }

    /// Top keyword-related pages for `slug` by TF-IDF cosine, excluding the page itself and any
    /// page already connected by an explicit link (either direction) so the panel never repeats.
    pub fn related(&self, slug: &str) -> Vec<LinkRef> {
        let Some(&i) = self.index.get(slug) else {
            return Vec::new();
        };
        let mut excluded: BTreeSet<String> = self.docs[i].refs.clone();
        excluded.insert(slug.to_string());
        for lr in self.backlinks(slug) {
            excluded.insert(lr.slug);
        }

        let mut scored: Vec<(f64, usize)> = Vec::new();
        for j in 0..self.pages.len() {
            if j == i || excluded.contains(&self.pages[j].slug) {
                continue;
            }
            let s = self.cosine(i, j);
            if s >= RELATED_MIN_SIM {
                scored.push((s, j));
            }
        }
        scored.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(Ordering::Equal)
                .then_with(|| self.pages[a.1].slug.cmp(&self.pages[b.1].slug))
        });
        scored.truncate(RELATED_LIMIT);
        scored
            .into_iter()
            .map(|(_, j)| LinkRef {
                slug: self.pages[j].slug.clone(),
                title: self.pages[j].title.clone(),
            })
            .collect()
    }

    /// The relations panel (backlinks + related) for one page.
    pub fn panel(&self, slug: &str) -> PagePanel {
        PagePanel {
            backlinks: self.backlinks(slug),
            related: self.related(slug),
        }
    }

    /// Pages whose last edit is strictly older than `stale_days` days before `now`, oldest first.
    pub fn stale(&self, now: i64, stale_days: i64) -> Vec<StalePage> {
        let cutoff_ms = stale_days.max(0) * MS_PER_DAY;
        let mut v: Vec<StalePage> = self
            .pages
            .iter()
            .filter_map(|p| {
                let age = now - p.updated_at;
                if age > cutoff_ms {
                    Some(StalePage {
                        slug: p.slug.clone(),
                        title: p.title.clone(),
                        updated_by_email: p.updated_by_email.clone(),
                        updated_at: p.updated_at,
                        age_days: age / MS_PER_DAY,
                    })
                } else {
                    None
                }
            })
            .collect();
        v.sort_by(|a, b| {
            a.updated_at
                .cmp(&b.updated_at)
                .then_with(|| a.slug.cmp(&b.slug))
        });
        v
    }

    /// Heuristic contradiction candidates: unordered page pairs sharing enough title terms
    /// (Jaccard >= [`TITLE_SIM_MIN`]) whose bodies are dissimilar (cosine <= [`BODY_DIVERGE_MAX`]).
    /// Candidate pairs are pruned through a title-term inverted index, so only pages that share at
    /// least one title term are ever compared. Ranked by most shared terms, then most divergent.
    pub fn contradictions(&self) -> Vec<Contradiction> {
        let mut inverted: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i, d) in self.docs.iter().enumerate() {
            for t in &d.title_terms {
                inverted.entry(t.as_str()).or_default().push(i);
            }
        }

        let mut seen: BTreeSet<(usize, usize)> = BTreeSet::new();
        let mut out: Vec<Contradiction> = Vec::new();
        for idxs in inverted.values() {
            for a in 0..idxs.len() {
                for b in (a + 1)..idxs.len() {
                    let (i, j) = (idxs[a], idxs[b]);
                    let key = if i < j { (i, j) } else { (j, i) };
                    if !seen.insert(key) {
                        continue;
                    }
                    let ti = &self.docs[key.0].title_terms;
                    let tj = &self.docs[key.1].title_terms;
                    if jaccard(ti, tj) < TITLE_SIM_MIN {
                        continue;
                    }
                    let sim = self.body_cosine(key.0, key.1);
                    if sim > BODY_DIVERGE_MAX {
                        continue;
                    }
                    let shared: Vec<String> = ti.intersection(tj).cloned().collect();
                    out.push(Contradiction {
                        a: LinkRef {
                            slug: self.pages[key.0].slug.clone(),
                            title: self.pages[key.0].title.clone(),
                        },
                        b: LinkRef {
                            slug: self.pages[key.1].slug.clone(),
                            title: self.pages[key.1].title.clone(),
                        },
                        shared_terms: shared,
                        body_similarity: sim,
                    });
                }
            }
        }

        out.sort_by(|x, y| {
            y.shared_terms
                .len()
                .cmp(&x.shared_terms.len())
                .then_with(|| {
                    x.body_similarity
                        .partial_cmp(&y.body_similarity)
                        .unwrap_or(Ordering::Equal)
                })
                .then_with(|| x.a.slug.cmp(&y.a.slug))
                .then_with(|| x.b.slug.cmp(&y.b.slug))
        });
        out.truncate(CONTRADICTION_LIMIT);
        out
    }
}

/// Jaccard similarity of two term sets (|∩| / |∪|); 0.0 when both are empty.
fn jaccard(a: &BTreeSet<String>, b: &BTreeSet<String>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let inter = a.intersection(b).count() as f64;
    let union = a.union(b).count() as f64;
    if union == 0.0 {
        0.0
    } else {
        inter / union
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(slug: &str, title: &str, body: &str, updated_at: i64) -> Page {
        Page {
            slug: slug.to_string(),
            title: title.to_string(),
            body_md: body.to_string(),
            updated_by_email: "a@x.co".to_string(),
            updated_at,
            created_at: updated_at,
            parent_id: None,
        }
    }

    #[test]
    fn referenced_slugs_finds_wikilinks_and_markdown_links() {
        let refs = referenced_slugs("See [[Runbook]] and [[Glossary|the glossary]].");
        assert!(refs.contains("runbook"));
        assert!(refs.contains("glossary"));

        let refs = referenced_slugs("A [direct](/w/deploy-guide) link and [[Home Page]].");
        assert!(refs.contains("deploy-guide"));
        assert!(refs.contains("home-page"));

        // Blank / malformed targets contribute nothing.
        assert!(referenced_slugs("[[   ]] and [[unterminated").is_empty());
    }

    #[test]
    fn backlinks_lists_referencing_pages_only() {
        let pages = vec![
            page("home", "Home", "See [[Runbook]].", 10),
            page("guide", "Guide", "Follow the [[Runbook]] closely.", 10),
            page("runbook", "Runbook", "Self-link [[Runbook]] ignored.", 10),
            page("other", "Other", "Nothing here.", 10),
        ];
        let corpus = Corpus::build(pages);
        let back = corpus.backlinks("runbook");
        let slugs: Vec<&str> = back.iter().map(|l| l.slug.as_str()).collect();
        assert_eq!(slugs, vec!["guide", "home"], "title-sorted, self excluded");
    }

    #[test]
    fn related_uses_keyword_overlap_and_excludes_explicit_links() {
        let pages = vec![
            page("backup", "Backup Policy", "database backup snapshot restore retention schedule", 10),
            page("restore", "Restore Drill", "database restore snapshot retention recovery schedule", 10),
            page("kitchen", "Kitchen Notes", "coffee machine descaling vinegar cleaning", 10),
            page("linked", "Linked", "points at [[backup]] heavily database backup snapshot", 10),
        ];
        let corpus = Corpus::build(pages);
        let related = corpus.related("backup");
        let slugs: Vec<&str> = related.iter().map(|l| l.slug.as_str()).collect();
        assert!(slugs.contains(&"restore"), "shared DB/backup terms -> related: {slugs:?}");
        assert!(!slugs.contains(&"kitchen"), "no term overlap -> not related");
        assert!(!slugs.contains(&"linked"), "explicit backlink is excluded from related");
    }

    #[test]
    fn stale_flags_old_pages_only() {
        let now = 1_000 * MS_PER_DAY; // day 1000
        let pages = vec![
            page("fresh", "Fresh", "x", 995 * MS_PER_DAY),
            page("old", "Old", "y", 800 * MS_PER_DAY),
            page("ancient", "Ancient", "z", 100 * MS_PER_DAY),
        ];
        let corpus = Corpus::build(pages);
        let stale = corpus.stale(now, 120);
        let slugs: Vec<&str> = stale.iter().map(|s| s.slug.as_str()).collect();
        assert_eq!(slugs, vec!["ancient", "old"], "oldest first; fresh excluded");
        assert_eq!(stale[1].age_days, 200);
    }

    #[test]
    fn contradiction_flags_same_title_divergent_body() {
        let pages = vec![
            // Same topic by title (deploy/process), wildly different bodies.
            page("deploy-a", "Deploy Process", "ship via kubernetes helm rollout canary staging", 10),
            page("deploy-b", "Deploy Process Legacy", "deploy process means copying tarballs over ftp by hand", 10),
            // Unrelated page sharing no title terms.
            page("salad", "Salad Recipe", "lettuce tomato cucumber olive oil", 10),
        ];
        let corpus = Corpus::build(pages);
        let cands = corpus.contradictions();
        assert!(
            cands.iter().any(|c| {
                let s = [c.a.slug.as_str(), c.b.slug.as_str()];
                s.contains(&"deploy-a") && s.contains(&"deploy-b")
            }),
            "same-title divergent-body pair flagged: {cands:?}"
        );
        assert!(
            cands.iter().all(|c| c.a.slug != "salad" && c.b.slug != "salad"),
            "unrelated page never paired"
        );
    }

    #[test]
    fn identical_bodies_are_not_contradictions() {
        let body = "ship via kubernetes helm rollout canary staging environment";
        let pages = vec![
            page("deploy-a", "Deploy Process", body, 10),
            page("deploy-b", "Deploy Process Two", body, 10),
        ];
        let corpus = Corpus::build(pages);
        assert!(
            corpus.contradictions().is_empty(),
            "agreeing bodies (high cosine) are not contradictions"
        );
    }
}
