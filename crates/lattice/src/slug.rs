//! Slug + title helpers.
//!
//! A page's canonical id is its slug: lowercase, Unicode-alphanumeric runs joined by single
//! hyphens, no leading/trailing hyphen. Handlers slugify the incoming URL path AND
//! `[[wiki-link]]` targets through the same function, so `/w/Foo Bar`, `/w/foo-bar` and
//! `[[Foo Bar]]` all resolve to the one page `foo-bar` — there is exactly one spelling of any
//! page, which removes a whole class of "duplicate page" edge cases.

/// Normalize arbitrary text into a canonical slug. Unicode letters/digits are kept (lowercased)
/// so non-ASCII titles still produce a usable slug; every other character collapses to a single
/// hyphen separator. The result is always safe to interpolate into an `href`/path (it contains
/// only alphanumerics and hyphens — never quotes, spaces, `<`, `>` or `/`).
pub fn slugify(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut prev_hyphen = false;
    for ch in input.chars() {
        if ch.is_alphanumeric() {
            for lower in ch.to_lowercase() {
                out.push(lower);
            }
            prev_hyphen = false;
        } else if !prev_hyphen && !out.is_empty() {
            out.push('-');
            prev_hyphen = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

/// Turn a slug back into a human-friendly default title (`some-page` -> `Some Page`). Used to
/// pre-fill the title when a brand-new page is created from a bare slug.
pub fn humanize(slug: &str) -> String {
    slug.split('-')
        .filter(|w| !w.is_empty())
        .map(|w| {
            let mut chars = w.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().chain(chars).collect::<String>(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugify_canonicalizes() {
        assert_eq!(slugify("Foo Bar"), "foo-bar");
        assert_eq!(slugify("  Hello, World!  "), "hello-world");
        assert_eq!(slugify("already-a-slug"), "already-a-slug");
        assert_eq!(slugify("Mixed___Separators  here"), "mixed-separators-here");
        assert_eq!(slugify("UPPER"), "upper");
        assert_eq!(slugify("!!!"), "");
        assert_eq!(slugify(""), "");
    }

    #[test]
    fn slugify_is_idempotent() {
        let once = slugify("Some Page Title!");
        assert_eq!(once, slugify(&once));
    }

    #[test]
    fn humanize_reads_back() {
        assert_eq!(humanize("some-page"), "Some Page");
        assert_eq!(humanize("home"), "Home");
        assert_eq!(humanize(""), "");
    }
}
