//! Public discovery feeds: RSS 2.0 (`GET /feed.xml`) and a sitemap (`GET /sitemap.xml`).
//!
//! Both are DERIVED, read-only views over the blog's PUBLISHED posts — drafts are never exposed,
//! exactly like the public index. No new schema: they read the same `posts` the index does,
//! and emit ABSOLUTE URLs under the blog's canonical origin so feed readers and crawlers resolve
//! links correctly. RSS uses effective publication chronology; sitemap uses a lightweight Store
//! projection. Being public reads, they carry no identity, no CSRF, and no mutation.

use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};

use crate::error::AppError;
use crate::handlers::{esc, post_excerpt};
use crate::store::SitemapEntry;
use crate::AppState;

/// How many characters of the post body to carry as an RSS item `<description>`.
const FEED_DESC_CHARS: usize = 500;
// ---------------------------------------------------------------------------
// GET /feed.xml — RSS 2.0
// ---------------------------------------------------------------------------

/// `GET /feed.xml` — RSS 2.0 of the 100 most recently effective public publications. Homepage
/// pinning never changes chronology, and the Store applies visibility/order before `LIMIT`.
pub async fn feed_xml(State(state): State<AppState>) -> Result<Response, AppError> {
    let settings = state.store.get_settings().await;
    let posts = state.store.feed_posts(crate::now_secs()).await?;
    // Content edits and a scheduled post's actual publication can each advance the feed. Never emit
    // a lastBuildDate older than either event.
    let last_build = posts
        .iter()
        .map(|post| post.updated_at.max(post.effective_publish_at()))
        .max()
        .unwrap_or_else(crate::now_secs);

    let mut items = String::new();
    for p in &posts {
        let url = post_url(&p.slug);
        let desc = post_excerpt(p, FEED_DESC_CHARS);
        items.push_str(&format!(
            "  <item>\n\
             \x20   <title>{title}</title>\n\
             \x20   <link>{url}</link>\n\
             \x20   <guid isPermaLink=\"true\">{url}</guid>\n\
             \x20   <pubDate>{date}</pubDate>\n\
             \x20   <description>{desc}</description>\n\
             \x20 </item>\n",
            title = esc(&p.title),
            url = esc(&url),
            date = fmt_rfc822(p.effective_publish_at()),
            desc = esc(&desc),
        ));
    }

    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <rss version=\"2.0\" xmlns:atom=\"http://www.w3.org/2005/Atom\">\n\
         <channel>\n\
         \x20 <title>{title}</title>\n\
         \x20 <link>{base}/</link>\n\
         \x20 <atom:link href=\"{base}/feed.xml\" rel=\"self\" type=\"application/rss+xml\"/>\n\
         \x20 <description>{description}</description>\n\
         \x20 <lastBuildDate>{last_build}</lastBuildDate>\n\
         {items}</channel>\n\
         </rss>\n",
        base = crate::config::SITE_BASE_URL,
        title = esc(&settings.title),
        description = esc(&settings.tagline),
        last_build = fmt_rfc822(last_build),
        items = items,
    );
    Ok(xml_response("application/rss+xml; charset=utf-8", body))
}

// ---------------------------------------------------------------------------
// GET /sitemap.xml — sitemaps.org urlset
// ---------------------------------------------------------------------------

/// `GET /sitemap.xml` — the index page plus every published post, newest-first, with `<lastmod>`.
pub async fn sitemap_xml(State(state): State<AppState>) -> Result<Response, AppError> {
    let entries = state.store.sitemap_entries(crate::now_secs()).await?;

    let mut urls = String::new();
    // The index page itself.
    urls.push_str(&format!(
        "  <url>\n    <loc>{base}/</loc>\n  </url>\n",
        base = crate::config::SITE_BASE_URL,
    ));
    for entry in &entries {
        // An explicit external canonical says this local URL is a duplicate source. Match Ghost's
        // behavior and omit it from the sitemap while keeping the authenticated reading route.
        if has_external_canonical(entry) {
            continue;
        }
        urls.push_str(&format!(
            "  <url>\n    <loc>{url}</loc>\n    <lastmod>{lastmod}</lastmod>\n  </url>\n",
            url = esc(&post_url(&entry.slug)),
            lastmod = fmt_iso8601(entry.updated_at),
        ));
    }

    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n\
         {urls}</urlset>\n",
        urls = urls,
    );
    Ok(xml_response("application/xml; charset=utf-8", body))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Absolute reading-view URL for a post slug (slugs are already URL-safe `[a-z0-9-]`).
fn post_url(slug: &str) -> String {
    format!("{}/p/{slug}", crate::config::SITE_BASE_URL)
}

fn has_external_canonical(entry: &SitemapEntry) -> bool {
    let override_url = entry.canonical_url.trim();
    !override_url.is_empty()
        && super::posts::canonical_url_is_safe(override_url)
        && override_url != post_url(&entry.slug)
}

/// An XML response with the given content type.
fn xml_response(content_type: &'static str, body: String) -> Response {
    ([(header::CONTENT_TYPE, content_type)], body).into_response()
}

/// Format epoch seconds as an RFC 822 date in GMT (RSS `pubDate` / `lastBuildDate`), e.g.
/// `Mon, 29 Jun 2026 12:00:00 GMT`. Falls back to the raw integer on an out-of-range timestamp.
fn fmt_rfc822(secs: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => format!(
            "{wd}, {day:02} {mon} {year} {h:02}:{m:02}:{s:02} GMT",
            wd = weekday_abbr(dt.weekday()),
            day = dt.day(),
            mon = super::month_abbr(dt.month()),
            year = dt.year(),
            h = dt.hour(),
            m = dt.minute(),
            s = dt.second(),
        ),
        Err(_) => secs.to_string(),
    }
}

/// Format epoch seconds as an ISO 8601 UTC instant (sitemap `<lastmod>`), e.g.
/// `2026-06-29T12:00:00Z`. Falls back to the raw integer on an out-of-range timestamp.
fn fmt_iso8601(secs: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => format!(
            "{year:04}-{mon:02}-{day:02}T{h:02}:{m:02}:{s:02}Z",
            year = dt.year(),
            mon = u8::from(dt.month()),
            day = dt.day(),
            h = dt.hour(),
            m = dt.minute(),
            s = dt.second(),
        ),
        Err(_) => secs.to_string(),
    }
}

fn weekday_abbr(wd: time::Weekday) -> &'static str {
    use time::Weekday::*;
    match wd {
        Monday => "Mon",
        Tuesday => "Tue",
        Wednesday => "Wed",
        Thursday => "Thu",
        Friday => "Fri",
        Saturday => "Sat",
        Sunday => "Sun",
    }
}
