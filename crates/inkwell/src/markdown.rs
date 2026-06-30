//! Markdown rendering + slug/excerpt text helpers.
//!
//! SECURITY: rendering is SANITIZED at the event level so no raw HTML / `javascript:` survives
//! into the page (defense against stored XSS, since the body is author-supplied markdown).
//! Raw block + inline HTML events are converted to escaped TEXT (so `<script>` renders as the
//! literal characters, never a live tag), and link/image destination URLs are scheme-
//! allowlisted (http/https/mailto/tel + relative); anything else (e.g. `javascript:`) is
//! rewritten to `#`. Everything else pulldown-cmark emits is a known, safe tag set.

use pulldown_cmark::{html, CowStr, Event, Options, Parser, Tag};

/// Render sanitized HTML from markdown `src` for the reading view.
pub fn render_html(src: &str) -> String {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_TASKLISTS);
    options.insert(Options::ENABLE_FOOTNOTES);

    let parser = Parser::new_ext(src, options).map(sanitize_event);
    let mut out = String::new();
    html::push_html(&mut out, parser);
    out
}

/// Neutralize the only two event classes that can carry an XSS payload.
fn sanitize_event(event: Event<'_>) -> Event<'_> {
    match event {
        // Raw HTML -> escaped text (push_html escapes Text via escape_html).
        Event::Html(h) => Event::Text(h),
        Event::InlineHtml(h) => Event::Text(h),
        Event::Start(Tag::Link {
            link_type,
            dest_url,
            title,
            id,
        }) => Event::Start(Tag::Link {
            link_type,
            dest_url: sanitize_url(dest_url),
            title,
            id,
        }),
        Event::Start(Tag::Image {
            link_type,
            dest_url,
            title,
            id,
        }) => Event::Start(Tag::Image {
            link_type,
            dest_url: sanitize_url(dest_url),
            title,
            id,
        }),
        other => other,
    }
}

/// Allow http/https/mailto/tel and relative URLs; rewrite any other scheme (javascript:,
/// data:, vbscript:, …) to a harmless `#`.
fn sanitize_url(url: CowStr<'_>) -> CowStr<'_> {
    if is_safe_url(&url) {
        url
    } else {
        CowStr::Borrowed("#")
    }
}

fn is_safe_url(url: &str) -> bool {
    // Strip whitespace + control chars first, so `java\tscript:` can't slip past the scheme check.
    let cleaned: String = url
        .chars()
        .filter(|c| !c.is_whitespace() && !c.is_ascii_control())
        .collect::<String>()
        .to_ascii_lowercase();

    match cleaned.find(':') {
        Some(idx) => {
            let scheme = &cleaned[..idx];
            // A real scheme is non-empty and only `[a-z0-9+.-]`. If `scheme` contains `/`, `?`,
            // or `#`, the `:` belongs to a path/fragment, not a scheme -> treat as relative.
            let is_scheme = !scheme.is_empty()
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'));
            if is_scheme {
                matches!(scheme, "http" | "https" | "mailto" | "tel")
            } else {
                true // relative path / fragment
            }
        }
        None => true, // no scheme -> relative
    }
}

/// A short plain-text excerpt of `n` characters, extracted from the markdown text (ignores
/// markup so the index reads cleanly). Appends `…` when truncated.
pub fn excerpt(src: &str, n: usize) -> String {
    let options = Options::empty();
    let mut text = String::new();
    for event in Parser::new_ext(src, options) {
        match event {
            Event::Text(t) | Event::Code(t) => text.push_str(&t),
            Event::SoftBreak | Event::HardBreak | Event::End(_) if !text.ends_with(' ') => {
                text.push(' ');
            }
            _ => {}
        }
    }
    let text = text.trim();
    if text.chars().count() > n {
        let truncated: String = text.chars().take(n).collect();
        format!("{}…", truncated.trim_end())
    } else {
        text.to_string()
    }
}

/// Turn a title into a URL slug: lowercase ASCII alphanumerics, every other run collapsed to a
/// single `-`, trimmed. Empty results (e.g. an all-CJK or all-symbol title) fall back to
/// `post-<fallback>` so we always get a usable, unique-able slug.
pub fn slugify(title: &str, fallback: &str) -> String {
    let mut slug = String::with_capacity(title.len());
    let mut prev_dash = false;
    for c in title.chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            slug.push('-');
            prev_dash = true;
        }
    }
    let trimmed = slug.trim_matches('-');
    if trimmed.is_empty() {
        format!("post-{fallback}")
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_basic_markdown() {
        let html = render_html("# Title\n\nHello **world**.");
        assert!(html.contains("<h1>Title</h1>"));
        assert!(html.contains("<strong>world</strong>"));
    }

    #[test]
    fn escapes_raw_html_script() {
        let html = render_html("ok <script>alert(1)</script> done");
        assert!(!html.contains("<script>"), "raw script tag must not survive");
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn escapes_inline_html_event_handler() {
        let html = render_html("<img src=x onerror=alert(1)>");
        // The tag is neutralized to escaped text: no live `<img ...>` element survives (the
        // literal `onerror=...` may remain as harmless visible text, which is fine).
        assert!(!html.contains("<img"), "raw img tag must not survive");
        assert!(html.contains("&lt;img"), "rendered as escaped text");
    }

    #[test]
    fn neutralizes_javascript_link() {
        let html = render_html("[click](javascript:alert(1))");
        assert!(!html.contains("javascript:"), "js scheme link neutralized");
        assert!(html.contains("href=\"#\""));
    }

    #[test]
    fn keeps_safe_and_relative_links() {
        let html = render_html("[a](https://example.com) [b](/local) [c](#frag)");
        assert!(html.contains("href=\"https://example.com\""));
        assert!(html.contains("href=\"/local\""));
        assert!(html.contains("href=\"#frag\""));
    }

    #[test]
    fn slugify_basics_and_fallback() {
        assert_eq!(slugify("Hello, World!", "x"), "hello-world");
        assert_eq!(slugify("  Multiple   Spaces  ", "x"), "multiple-spaces");
        assert_eq!(slugify("Rust 2024!!", "x"), "rust-2024");
        assert_eq!(slugify("你好世界", "abc"), "post-abc");
        assert_eq!(slugify("", "abc"), "post-abc");
    }

    #[test]
    fn excerpt_strips_markup_and_truncates() {
        let ex = excerpt("# Heading\n\nThis is **bold** body text that runs on.", 20);
        assert!(!ex.contains('#'));
        assert!(!ex.contains('*'));
        assert!(ex.ends_with('…'));
        assert!(ex.chars().count() <= 21);
    }
}
