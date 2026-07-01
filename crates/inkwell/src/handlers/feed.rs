//! Public discovery feeds: RSS 2.0 (`GET /feed.xml`) and a sitemap (`GET /sitemap.xml`).
//!
//! Both are DERIVED, read-only views over the blog's PUBLISHED posts — drafts are never exposed,
//! exactly like the public index. No new schema: they read the same `posts` the index does,
//! newest-first (the store already returns that order), and emit ABSOLUTE URLs under the blog's
//! canonical origin so feed readers and crawlers resolve links correctly. Being public reads, they
//! carry no identity, no CSRF, and no mutation, so there is nothing to audit.

use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};

use crate::config::MAX_PAGE;
use crate::handlers::esc;
use crate::markdown;
use crate::store::Post;
use crate::AppState;

/// Canonical public origin of the blog (Inkwell serves `blog.w33d.xyz` behind the gateway).
/// Absolute links in the feed/sitemap resolve against this, matching the estate's other hardcoded
/// origins (the app-bar portal + gateway logout links).
const SITE_BASE_URL: &str = "https://blog.w33d.xyz";

/// How many characters of the post body to carry as an RSS item `<description>`.
const FEED_DESC_CHARS: usize = 500;

// ---------------------------------------------------------------------------
// GET /feed.xml — RSS 2.0
// ---------------------------------------------------------------------------

/// `GET /feed.xml` — RSS 2.0 of the published posts, newest-first (the same order the index uses).
pub async fn feed_xml(State(state): State<AppState>) -> Response {
    let posts = published_newest_first(&state).await;
    // Newest post's timestamp drives lastBuildDate; fall back to now for an empty blog.
    let last_build = posts
        .iter()
        .map(|p| p.updated_at.max(p.created_at))
        .max()
        .unwrap_or_else(crate::now_secs);

    let mut items = String::new();
    for p in &posts {
        let url = post_url(&p.slug);
        let desc = markdown::excerpt(&p.body_md, FEED_DESC_CHARS);
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
            date = fmt_rfc822(p.created_at),
            desc = esc(&desc),
        ));
    }

    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <rss version=\"2.0\" xmlns:atom=\"http://www.w3.org/2005/Atom\">\n\
         <channel>\n\
         \x20 <title>Inkwell · HOLDFAST</title>\n\
         \x20 <link>{base}/</link>\n\
         \x20 <atom:link href=\"{base}/feed.xml\" rel=\"self\" type=\"application/rss+xml\"/>\n\
         \x20 <description>Notes, essays, and changelog from the HOLDFAST estate.</description>\n\
         \x20 <lastBuildDate>{last_build}</lastBuildDate>\n\
         {items}</channel>\n\
         </rss>\n",
        base = SITE_BASE_URL,
        last_build = fmt_rfc822(last_build),
        items = items,
    );
    xml_response("application/rss+xml; charset=utf-8", body)
}

// ---------------------------------------------------------------------------
// GET /sitemap.xml — sitemaps.org urlset
// ---------------------------------------------------------------------------

/// `GET /sitemap.xml` — the index page plus every published post, newest-first, with `<lastmod>`.
pub async fn sitemap_xml(State(state): State<AppState>) -> Response {
    let posts = published_newest_first(&state).await;

    let mut urls = String::new();
    // The index page itself.
    urls.push_str(&format!(
        "  <url>\n    <loc>{base}/</loc>\n  </url>\n",
        base = SITE_BASE_URL,
    ));
    for p in &posts {
        urls.push_str(&format!(
            "  <url>\n    <loc>{url}</loc>\n    <lastmod>{lastmod}</lastmod>\n  </url>\n",
            url = esc(&post_url(&p.slug)),
            lastmod = fmt_iso8601(p.updated_at),
        ));
    }

    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n\
         {urls}</urlset>\n",
        urls = urls,
    );
    xml_response("application/xml; charset=utf-8", body)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// One bounded, newest-first page of the PUBLISHED posts (drafts filtered out — never syndicated).
async fn published_newest_first(state: &AppState) -> Vec<Post> {
    state
        .store
        .list_posts(None, MAX_PAGE)
        .await
        .into_iter()
        .filter(|p| p.published)
        .collect()
}

/// Absolute reading-view URL for a post slug (slugs are already URL-safe `[a-z0-9-]`).
fn post_url(slug: &str) -> String {
    format!("{SITE_BASE_URL}/p/{slug}")
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
