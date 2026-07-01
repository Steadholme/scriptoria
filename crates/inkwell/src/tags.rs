//! Tag parsing + slugging for the blog tags feature.
//!
//! A post's tags live in one comma-separated TEXT column (e.g. `rust, async`). This module is the
//! pure, I/O-free core that turns that raw string into a normalized, de-duplicated display list and
//! the URL slug each tag links to (`/tag/{slug}`), mirroring [`crate::markdown::slugify`]'s ASCII
//! rules so the `/tag/{slug}` route and the chip links always agree. Kept value-only so the whole
//! contract is unit-tested without a DB or HTTP.

/// Hard cap on how many tags one post carries (bounds chip rendering + the stored string).
pub const MAX_TAGS: usize = 20;
/// Hard cap on one tag's display length in characters (bounds a runaway paste).
pub const MAX_TAG_CHARS: usize = 40;

/// Parse a comma-separated raw tags string into a normalized, de-duplicated display list.
///
/// Splits on `,`, trims each part, drops empties, caps each to [`MAX_TAG_CHARS`] characters, and
/// collapses case-insensitive duplicates (by [`tag_slug`], keeping the first display form). A tag
/// that slugs to empty (all punctuation/CJK) is dropped, since it could never round-trip through the
/// `/tag/{slug}` URL. At most [`MAX_TAGS`] tags are returned.
pub fn parse_tags(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for part in raw.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let display: String = trimmed.chars().take(MAX_TAG_CHARS).collect();
        let slug = tag_slug(&display);
        if slug.is_empty() {
            continue; // no URL-safe slug -> can't be listed, so it isn't a tag
        }
        if out.iter().any(|e| tag_slug(e) == slug) {
            continue; // case-insensitive duplicate
        }
        out.push(display);
        if out.len() >= MAX_TAGS {
            break;
        }
    }
    out
}

/// Slug for one tag's `/tag/{slug}` URL: lowercase ASCII alphanumerics, every other run collapsed to
/// a single `-`, trimmed. Same ASCII rules as [`crate::markdown::slugify`] (minus its fallback), so
/// an all-symbol/CJK tag slugs to the empty string (and is filtered out by [`parse_tags`]).
pub fn tag_slug(tag: &str) -> String {
    let mut slug = String::with_capacity(tag.len());
    let mut prev_dash = false;
    for c in tag.chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            slug.push('-');
            prev_dash = true;
        }
    }
    slug.trim_matches('-').to_string()
}

/// Serialize a parsed tag list back to the comma-separated storage form (`"rust, async"`). The
/// canonical stored representation, so editing a post shows the normalized tags back.
pub fn join_tags(tags: &[String]) -> String {
    tags.join(", ")
}

/// Normalize a raw tags input for storage: parse then re-join, so the stored column is always the
/// de-duplicated, bounded, canonical form.
pub fn normalize(raw: &str) -> String {
    join_tags(&parse_tags(raw))
}

/// Whether a post's raw tags string contains a tag whose slug equals `slug` (the `/tag/{slug}`
/// membership test).
pub fn has_tag(raw: &str, slug: &str) -> bool {
    parse_tags(raw).iter().any(|t| tag_slug(t) == slug)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_trims_dedupes_and_drops_empty() {
        assert_eq!(
            parse_tags("Rust,  async , rust ,, RUST"),
            vec!["Rust".to_string(), "async".to_string()],
            "trimmed, empties dropped, case-insensitive dupes collapsed (first form kept)",
        );
        assert!(parse_tags("   ").is_empty(), "blank -> no tags");
        assert!(parse_tags(",,,").is_empty(), "only separators -> no tags");
    }

    #[test]
    fn parse_drops_unsluggable_tags() {
        // A CJK-only / symbol-only tag has no ASCII slug, so it can't be listed and is dropped.
        assert_eq!(parse_tags("rust, 你好, !!!"), vec!["rust".to_string()]);
    }

    #[test]
    fn parse_caps_count_and_length() {
        let many = (0..50).map(|i| format!("t{i}")).collect::<Vec<_>>().join(",");
        assert_eq!(parse_tags(&many).len(), MAX_TAGS, "count capped");
        let long = "a".repeat(100);
        assert_eq!(parse_tags(&long)[0].chars().count(), MAX_TAG_CHARS, "length capped");
    }

    #[test]
    fn slug_matches_slugify_rules() {
        assert_eq!(tag_slug("Rust Async!"), "rust-async");
        assert_eq!(tag_slug("  C++ / Systems  "), "c-systems");
        assert_eq!(tag_slug("你好"), "", "no ASCII -> empty slug");
    }

    #[test]
    fn normalize_roundtrips_to_canonical() {
        assert_eq!(normalize(" Rust , async,Rust "), "Rust, async");
        assert_eq!(normalize("  "), "");
    }

    #[test]
    fn has_tag_matches_by_slug() {
        assert!(has_tag("Rust, Async Runtime", "async-runtime"));
        assert!(has_tag("Rust, Async Runtime", "rust"));
        assert!(!has_tag("Rust, Async Runtime", "gateway"));
    }
}
