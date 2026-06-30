//! CommonMark rendering with `[[wiki-links]]`, sanitized against stored XSS.
//!
//! Two safety properties, both enforced at the pulldown-cmark EVENT level (never by HTML
//! post-processing, which is fragile):
//!
//! 1. Raw HTML in the stored markdown is NEUTRALIZED — every `Html`/`InlineHtml` event is
//!    re-emitted as a `Text` event, so `<script>`/`<img onerror>` etc. render as visible,
//!    escaped text instead of live markup. The ONLY HTML reaching the output verbatim are the
//!    `<a>` anchors WE synthesize for wiki-links, whose href is a `/w/<slug>` path (the slug is
//!    alphanumerics + hyphens only) — no injection vector.
//!
//! `[[Target]]` / `[[Target|Label]]` is expanded to a real markdown link `[Label](/w/<slug>)`
//! BEFORE parsing — pulldown-cmark fragments bare `[[ ]]` across several text events (it tries
//! to read them as reference links), so a reliable transform has to run on the source, not the
//! event stream. The expansion SKIPS any `[[ ]]` that falls inside inline code or a code block
//! (their byte ranges come from a first offset-tracking parse), so `[[x]]` shown in a code
//! sample is left untouched. During rendering the resulting `/w/...` links are re-emitted with a
//! `wikilink` class (and `wikilink--new` when the target page doesn't exist yet) so the UI can
//! style classic "red links" that invite creation.

use std::collections::HashSet;
use std::ops::Range;

use pulldown_cmark::{html, CowStr, Event, Options, Parser, Tag, TagEnd};

use crate::render::esc;
use crate::slug::slugify;

const WIKI_PREFIX: &str = "/w/";

fn options() -> Options {
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_TABLES);
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    opts.insert(Options::ENABLE_TASKLISTS);
    opts
}

/// Render `body_md` to sanitized HTML. `existing` is the set of slugs that currently have a
/// page, used to mark wiki-links to missing pages.
pub fn render(body_md: &str, existing: &HashSet<String>) -> String {
    let opts = options();
    let protected = protected_ranges(body_md, opts);
    let expanded = expand_wikilinks_source(body_md, &protected);

    let mut events: Vec<Event> = Vec::new();
    let mut in_wiki_link = false;
    for event in Parser::new_ext(&expanded, opts) {
        match event {
            // Neutralize any raw/inline HTML by re-emitting it as escaped text.
            Event::Html(s) | Event::InlineHtml(s) => {
                events.push(Event::Text(CowStr::from(s.into_string())));
            }
            // Re-skin our own `/w/<slug>` links: replace the default <a> with one carrying the
            // wikilink class, letting the (escaped) link-text events flow through unchanged.
            Event::Start(Tag::Link { dest_url, .. }) if dest_url.starts_with(WIKI_PREFIX) => {
                let slug = dest_url.strip_prefix(WIKI_PREFIX).unwrap_or_default();
                let class = if existing.contains(slug) {
                    "wikilink"
                } else {
                    "wikilink wikilink--new"
                };
                let anchor = format!("<a class=\"{class}\" href=\"{}\">", esc(&dest_url));
                events.push(Event::InlineHtml(CowStr::from(anchor)));
                in_wiki_link = true;
            }
            Event::End(TagEnd::Link) if in_wiki_link => {
                events.push(Event::InlineHtml(CowStr::from("</a>")));
                in_wiki_link = false;
            }
            other => events.push(other),
        }
    }

    let mut out = String::new();
    html::push_html(&mut out, events.into_iter());
    out
}

/// Byte ranges covered by inline code spans and code blocks — `[[ ]]` inside these is left as
/// literal source text.
fn protected_ranges(md: &str, opts: Options) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut block_start: Option<usize> = None;
    for (event, range) in Parser::new_ext(md, opts).into_offset_iter() {
        match event {
            Event::Code(_) => ranges.push(range),
            Event::Start(Tag::CodeBlock(_)) => block_start = Some(range.start),
            Event::End(TagEnd::CodeBlock) => {
                let start = block_start.take().unwrap_or(range.start);
                ranges.push(start..range.end);
            }
            _ => {}
        }
    }
    ranges
}

/// Rewrite `[[Target]]` / `[[Target|Label]]` into markdown links, skipping protected ranges.
fn expand_wikilinks_source(md: &str, protected: &[Range<usize>]) -> String {
    let mut out = String::with_capacity(md.len());
    let mut i = 0;
    while let Some(rel) = md[i..].find("[[") {
        let open = i + rel;
        let Some(crel) = md[open + 2..].find("]]") else {
            break; // no closing `]]` — copy the remainder verbatim below.
        };
        let close = open + 2 + crel;
        let end = close + 2;

        out.push_str(&md[i..open]);
        if is_protected(open, protected) {
            out.push_str("[[");
            i = open + 2;
            continue;
        }
        match build_md_link(&md[open + 2..close]) {
            Some(link) => out.push_str(&link),
            None => out.push_str(&md[open..end]), // blank target — keep the literal text.
        }
        i = end;
    }
    out.push_str(&md[i..]);
    out
}

fn is_protected(pos: usize, protected: &[Range<usize>]) -> bool {
    protected.iter().any(|r| r.start <= pos && pos < r.end)
}

/// Build `[Label](/w/<slug>)` from a `[[inner]]` payload, or `None` when the target slugifies to
/// nothing. `inner` may be `Target` or `Target|Label`.
fn build_md_link(inner: &str) -> Option<String> {
    let (target, label) = match inner.split_once('|') {
        Some((t, l)) => (t.trim(), l.trim()),
        None => (inner.trim(), inner.trim()),
    };
    let slug = slugify(target);
    if slug.is_empty() {
        return None;
    }
    let label = if label.is_empty() { target } else { label };
    Some(format!("[{}]({WIKI_PREFIX}{slug})", escape_link_text(label)))
}

/// Backslash-escape the characters that would prematurely close markdown link text.
fn escape_link_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if matches!(ch, '\\' | '[' | ']') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn existing(slugs: &[&str]) -> HashSet<String> {
        slugs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn renders_basic_markdown() {
        let html = render("# Title\n\nsome **bold** text", &existing(&[]));
        assert!(html.contains("<h1>Title</h1>"));
        assert!(html.contains("<strong>bold</strong>"));
    }

    #[test]
    fn neutralizes_raw_html() {
        let html = render("<script>alert(1)</script>\n\nhi", &existing(&[]));
        assert!(!html.contains("<script>"), "script tag must be escaped: {html}");
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn neutralizes_inline_html_event_attributes() {
        let html = render("a <img src=x onerror=alert(1)> b", &existing(&[]));
        assert!(!html.contains("<img"), "inline html must be escaped: {html}");
        assert!(html.contains("&lt;img"));
    }

    #[test]
    fn wikilink_to_existing_page() {
        let html = render("see [[Home]] please", &existing(&["home"]));
        assert!(
            html.contains(r#"<a class="wikilink" href="/w/home">Home</a>"#),
            "{html}"
        );
    }

    #[test]
    fn wikilink_to_missing_page_gets_new_class() {
        let html = render("see [[Brand New]]", &existing(&[]));
        assert!(html.contains(r#"href="/w/brand-new""#), "{html}");
        assert!(html.contains("wikilink--new"), "{html}");
    }

    #[test]
    fn wikilink_with_pipe_label() {
        let html = render("[[runbook|the runbook]]", &existing(&["runbook"]));
        assert!(html.contains(r#"href="/w/runbook""#));
        assert!(html.contains(">the runbook</a>"));
    }

    #[test]
    fn wikilink_label_is_escaped() {
        let html = render("[[slug|<b>x</b>]]", &existing(&["slug"]));
        assert!(!html.contains("<b>x</b>"));
        assert!(html.contains("&lt;b&gt;x&lt;/b&gt;"));
    }

    #[test]
    fn wikilinks_left_alone_in_code() {
        let html = render("`[[not a link]]`\n\n```\n[[also not]]\n```", &existing(&[]));
        assert!(!html.contains("/w/not-a-link"), "inline code untouched: {html}");
        assert!(!html.contains("/w/also-not"), "fenced code untouched: {html}");
    }

    #[test]
    fn empty_wikilink_is_literal() {
        let html = render("[[   ]] end", &existing(&[]));
        assert!(!html.contains("<a "));
        assert!(html.contains("[["));
    }

    #[test]
    fn ordinary_external_links_are_untouched() {
        let html = render("[docs](https://example.com)", &existing(&[]));
        assert!(html.contains(r#"href="https://example.com""#));
        assert!(!html.contains("wikilink"));
    }
}
