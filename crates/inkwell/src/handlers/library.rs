//! Owner-scoped Author Content Library.
//!
//! This is deliberately separate from `/admin`: ordinary authors search and organize only their
//! own authoritative posts, while site-wide moderation keeps its independent admin authorization.
//! Every filter is URL state and every mutation is a real CSRF-protected HTML form, so JavaScript is
//! optional. Bulk commands use stable post ids plus edit versions and commit all selected rows or
//! none; slugs and submitted owner fields never participate in authorization.

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth;
use crate::error::AppError;
use crate::handlers::{esc, fmt_date, page_shell, PageShell};
use crate::store::{
    LibraryBulkAction, LibraryBulkCommand, LibraryBulkOutcome, LibraryCursor, LibraryQuery,
    LibrarySelection, LibrarySort, LibraryStatus, Post,
};
use crate::{now_secs, AppState};

const LIBRARY_HTML: &str = include_str!("../../templates/library.html");
const MAX_QUERY_CHARS: usize = 200;
const MAX_RETURN_TO_BYTES: usize = 2_048;

#[derive(Debug, Default, Deserialize)]
pub struct LibraryParams {
    #[serde(default)]
    q: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    tag: String,
    #[serde(default)]
    sort: String,
    #[serde(default)]
    as_of: String,
    #[serde(default)]
    cursor: String,
    #[serde(default)]
    limit: String,
    #[serde(default)]
    changed: String,
}

#[derive(Clone)]
struct ViewState {
    q: String,
    status: LibraryStatus,
    tag: String,
    sort: LibrarySort,
    as_of: i64,
    limit: i64,
    cursor: Option<LibraryCursor>,
    changed: usize,
}

/// `GET /library` — one private, fail-closed keyset page of the signed-in author's own posts.
pub async fn index(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<LibraryParams>,
) -> Result<Response, AppError> {
    let (owner_sub, email) = auth::require_author(&headers)?;
    let now = now_secs();
    let view = normalize_view(params, now)?;
    let page = state
        .store
        .list_library(LibraryQuery {
            owner_sub,
            q: view.q.clone(),
            status: view.status,
            tag: view.tag.clone(),
            sort: view.sort,
            as_of: view.as_of,
            cursor: view.cursor.clone(),
            limit: view.limit,
        })
        .await?;
    let current_url = library_url(&view, view.cursor.as_ref());
    let return_param = percent_encode(&current_url);
    let mut rows = String::new();
    for post in &page.posts {
        rows.push_str(&render_row(post, &view, &current_url));
    }
    if page.posts.is_empty() {
        rows.push_str(
            r#"<div class="empty-state ink-library__empty" role="listitem"><h3>No matching posts</h3><p>Try another status, tag, or search phrase.</p><a class="btn btn-primary" href="/new">Write a post</a></div>"#,
        );
    }
    let pager = page
        .next
        .as_ref()
        .map(|cursor| {
            format!(
                r#"<nav class="ink-library__pager" aria-label="Author library pages"><a class="btn btn-secondary" href="{}">Load older work</a></nav>"#,
                esc(&library_url(&view, Some(cursor)))
            )
        })
        .unwrap_or_default();
    let status_tabs = render_status_tabs(&view);
    let sort_options = render_sort_options(view.sort);
    let result_summary = if page.posts.len() == 1 {
        "1 post on this page".to_string()
    } else {
        format!("{} posts on this page", page.posts.len())
    };
    let notice = render_notice(view.changed);
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let fragment = LIBRARY_HTML
        .replace("{{NEW_HREF}}", &format!("/new?return_to={return_param}"))
        .replace("{{NOTICE}}", &notice)
        .replace("{{QUERY}}", &esc(&view.q))
        .replace("{{TAG}}", &esc(&view.tag))
        .replace("{{SORT_OPTIONS}}", &sort_options)
        .replace("{{STATUS_TABS}}", &status_tabs)
        .replace("{{STATUS_KEY}}", status_key(view.status))
        .replace(
            "{{ADVANCED_OPEN}}",
            if view.tag.is_empty() { "" } else { " open" },
        )
        .replace("{{LIMIT}}", &view.limit.to_string())
        .replace("{{RESULT_SUMMARY}}", &result_summary)
        .replace("{{CSRF}}", &esc(&csrf))
        .replace("{{RETURN_TO}}", &esc(&current_url))
        .replace("{{ROWS}}", &rows)
        .replace("{{PAGER}}", &pager);
    let theme = odyssey::resolve_theme(
        headers
            .get(header::COOKIE)
            .and_then(|value| value.to_str().ok()),
    );
    let page = page_shell(PageShell {
        head_title: "Studio · Inkwell",
        body_class: "page-console page-library",
        rss: false,
        nav_title: "Studio",
        email: &email,
        is_admin: auth::is_admin(&headers),
        theme,
        fragment: &fragment,
        metadata: None,
    });
    Ok(private_no_store(html_with_cookie(page, set_cookie)))
}

/// `POST /library/posts/bulk` — one bounded, all-or-nothing author command.
pub async fn bulk(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, AppError> {
    let (owner_sub, email) = auth::require_author(&headers)?;
    let pairs = parse_pairs(&body);
    auth::verify_csrf(&headers, &field(&pairs, "csrf_token"))?;
    let selections: Vec<LibrarySelection> = pairs
        .iter()
        .filter(|(key, _)| key == "items")
        .map(|(_, value)| parse_selection(value))
        .collect::<Result<_, _>>()?;
    if selections.is_empty() {
        return Err(AppError::InvalidRequest(
            "select at least one post".to_string(),
        ));
    }
    if selections.len() > crate::config::LIBRARY_BULK_MAX {
        return Err(AppError::InvalidRequest(format!(
            "select at most {} posts",
            crate::config::LIBRARY_BULK_MAX
        )));
    }
    let action = parse_action(&field(&pairs, "action"), &field(&pairs, "tag"))?;
    let detail = action.audit_detail();
    let return_to = safe_library_return_to(&field(&pairs, "return_to"))
        .unwrap_or_else(|| "/library".to_string());
    let outcome = state
        .store
        .bulk_update_library(LibraryBulkCommand {
            owner_sub: owner_sub.clone(),
            editor_email: email.clone(),
            selections,
            action,
            now: now_secs(),
        })
        .await?;
    let changed = match outcome {
        LibraryBulkOutcome::Applied(posts) => posts,
        LibraryBulkOutcome::Conflict => {
            return Err(AppError::Conflict(
                "the selection changed; reload the Content Library and try again".to_string(),
            ));
        }
    };

    // The public retrieval layer joins chunks back to authoritative visibility/version, so a failed
    // best-effort refresh can only omit a newly public result; it can never expose stale/draft text.
    for post in &changed {
        crate::reindex_post(state.store.as_ref(), post).await;
        state.audit.emit(AuditEvent::notice(
            "post.library.bulk",
            if email.is_empty() { &owner_sub } else { &email },
            &post.slug,
            detail,
        ));
    }
    Ok(private_no_store(redirect(&with_changed(
        &return_to,
        changed.len(),
    ))))
}

fn normalize_view(params: LibraryParams, now: i64) -> Result<ViewState, AppError> {
    let q: String = params.q.trim().chars().take(MAX_QUERY_CHARS).collect();
    let tag: String = params
        .tag
        .trim()
        .chars()
        .take(crate::tags::MAX_TAG_CHARS)
        .collect();
    let status = parse_status(&params.status)?;
    let sort = parse_sort(&params.sort)?;
    let as_of = if params.as_of.trim().is_empty() {
        now
    } else {
        params
            .as_of
            .trim()
            .parse::<i64>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| AppError::InvalidRequest("invalid library as_of".to_string()))?
            .min(now)
    };
    let cursor = if params.cursor.trim().is_empty() {
        None
    } else {
        Some(parse_cursor(params.cursor.trim(), sort)?)
    };
    let limit = if params.limit.trim().is_empty() {
        crate::config::LIBRARY_DEFAULT_PAGE
    } else {
        params
            .limit
            .trim()
            .parse::<i64>()
            .map_err(|_| AppError::InvalidRequest("invalid library limit".to_string()))?
            .clamp(1, crate::config::LIBRARY_MAX_PAGE)
    };
    Ok(ViewState {
        q,
        status,
        tag,
        sort,
        as_of,
        limit,
        cursor,
        changed: params
            .changed
            .trim()
            .parse::<usize>()
            .unwrap_or(0)
            .min(crate::config::LIBRARY_BULK_MAX),
    })
}

fn parse_status(raw: &str) -> Result<LibraryStatus, AppError> {
    match raw.trim() {
        "" | "all" => Ok(LibraryStatus::All),
        "draft" => Ok(LibraryStatus::Draft),
        "scheduled" => Ok(LibraryStatus::Scheduled),
        "published" => Ok(LibraryStatus::Published),
        _ => Err(AppError::InvalidRequest(
            "unknown library status".to_string(),
        )),
    }
}

fn status_key(status: LibraryStatus) -> &'static str {
    match status {
        LibraryStatus::All => "all",
        LibraryStatus::Draft => "draft",
        LibraryStatus::Scheduled => "scheduled",
        LibraryStatus::Published => "published",
    }
}

fn parse_sort(raw: &str) -> Result<LibrarySort, AppError> {
    match raw.trim() {
        "" | "updated" => Ok(LibrarySort::Updated),
        "created" => Ok(LibrarySort::Created),
        _ => Err(AppError::InvalidRequest("unknown library sort".to_string())),
    }
}

fn sort_key(sort: LibrarySort) -> &'static str {
    match sort {
        LibrarySort::Updated => "updated",
        LibrarySort::Created => "created",
    }
}

fn render_sort_options(sort: LibrarySort) -> String {
    [
        (LibrarySort::Updated, "Recently updated"),
        (LibrarySort::Created, "Newest created"),
    ]
    .into_iter()
    .map(|(value, label)| {
        format!(
            r#"<option value="{}"{}>{label}</option>"#,
            sort_key(value),
            if value == sort { " selected" } else { "" },
        )
    })
    .collect::<Vec<_>>()
    .join("")
}

fn render_status_tabs(view: &ViewState) -> String {
    [
        (LibraryStatus::All, "All"),
        (LibraryStatus::Draft, "Draft"),
        (LibraryStatus::Scheduled, "Scheduled"),
        (LibraryStatus::Published, "Published"),
    ]
    .into_iter()
    .map(|(status, label)| {
        let mut target = view.clone();
        target.status = status;
        target.cursor = None;
        target.changed = 0;
        format!(
            r#"    <a class="ink-library__status-tab{}" href="{}"{}>{label}</a>"#,
            if status == view.status {
                " is-active"
            } else {
                ""
            },
            esc(&library_url(&target, None)),
            if status == view.status {
                r#" aria-current="page""#
            } else {
                ""
            },
        )
    })
    .collect::<Vec<_>>()
    .join("\n")
}

fn render_row(post: &Post, view: &ViewState, current_url: &str) -> String {
    let (status, status_class) = if !post.published {
        ("Draft", "draft")
    } else if post.is_scheduled_at(view.as_of) {
        ("Scheduled", "scheduled")
    } else {
        ("Published", "published")
    };
    let mut flags = format!(
        r#"<span class="badge ink-library__status ink-library__status--{status_class}">{status}</span>"#
    );
    if post.pinned {
        flags.push_str(r#"<span class="badge ink-pin">Pinned</span>"#);
    }
    if post.featured {
        flags.push_str(r#"<span class="badge badge-featured">Featured</span>"#);
    }
    let return_param = percent_encode(current_url);
    let edit_href = format!("/edit/{}?return_to={return_param}", post.slug);
    let history_href = format!("/edit/{}/history?return_to={return_param}", post.slug);
    let tags = crate::tags::parse_tags(&post.tags)
        .into_iter()
        .map(|tag| {
            let tag_view = ViewState {
                tag: tag.clone(),
                cursor: None,
                changed: 0,
                ..view.clone()
            };
            format!(
                r#"<a class="tag" href="{}">{}</a>"#,
                esc(&library_url(&tag_view, None)),
                esc(&tag),
            )
        })
        .collect::<String>();
    let schedule = if post.is_scheduled_at(view.as_of) {
        format!(" · publishes {}", esc(&fmt_date(post.publish_at)))
    } else {
        String::new()
    };
    let view_label = if post.is_public_at(view.as_of) {
        "View live"
    } else {
        "Preview saved"
    };
    let view_href = if post.is_public_at(view.as_of) {
        format!("/p/{}", esc(&post.slug))
    } else {
        format!("/p/{}?preview=1", esc(&post.slug))
    };
    format!(
        r#"        <article class="ink-library__row" role="listitem">
          <label class="ink-library__select"><input type="checkbox" name="items" form="library-bulk" value="{selection}" data-library-item aria-label="Select {title}"></label>
          <div class="ink-library__main">
            <div class="ink-library__titleline"><a href="{edit_href}">{title}</a><span class="ink-library__badges">{flags}</span></div>
            <p class="muted">Updated {updated}{schedule} · version {version}</p>
            <div class="tags">{tags}</div>
          </div>
          <div class="ink-library__rowactions">
            <a class="btn btn-ghost btn-sm" href="{view_href}">{view_label}</a>
            <a class="btn btn-ghost btn-sm" href="{history_href}">History</a>
            <a class="btn btn-secondary btn-sm" href="{edit_href}">Edit</a>
          </div>
        </article>
"#,
        selection = encode_selection(post),
        title = esc(&post.title),
        edit_href = esc(&edit_href),
        history_href = esc(&history_href),
        flags = flags,
        updated = esc(&fmt_date(post.updated_at)),
        schedule = schedule,
        version = post.edit_version,
        tags = tags,
        view_href = view_href,
        view_label = view_label,
    )
}

fn parse_action(raw: &str, raw_tag: &str) -> Result<LibraryBulkAction, AppError> {
    match raw.trim() {
        "publish_now" => Ok(LibraryBulkAction::PublishNow),
        "draft" => Ok(LibraryBulkAction::Draft),
        "pin" => Ok(LibraryBulkAction::Pin),
        "unpin" => Ok(LibraryBulkAction::Unpin),
        "add_tag" => Ok(LibraryBulkAction::AddTag(single_tag(raw_tag)?)),
        "remove_tag" => Ok(LibraryBulkAction::RemoveTag(single_tag(raw_tag)?)),
        _ => Err(AppError::InvalidRequest(
            "unknown library bulk action".to_string(),
        )),
    }
}

fn single_tag(raw: &str) -> Result<String, AppError> {
    let tags = crate::tags::parse_tags(raw);
    if tags.len() == 1 {
        Ok(tags[0].clone())
    } else {
        Err(AppError::InvalidRequest(
            "add/remove tag requires exactly one valid tag".to_string(),
        ))
    }
}

fn encode_selection(post: &Post) -> String {
    format!("{}.{}", hex::encode(post.id.as_bytes()), post.edit_version)
}

fn parse_selection(raw: &str) -> Result<LibrarySelection, AppError> {
    let (encoded_id, version) = raw
        .rsplit_once('.')
        .ok_or_else(|| AppError::InvalidRequest("invalid library selection".to_string()))?;
    if encoded_id.len() > 512 {
        return Err(AppError::InvalidRequest(
            "invalid library selection".to_string(),
        ));
    }
    let id = hex::decode(encoded_id)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .filter(|id| !id.is_empty())
        .ok_or_else(|| AppError::InvalidRequest("invalid library selection".to_string()))?;
    let expected_version = version
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| AppError::InvalidRequest("invalid library selection".to_string()))?;
    Ok(LibrarySelection {
        post_id: id,
        expected_version,
    })
}

fn encode_cursor(cursor: &LibraryCursor) -> String {
    format!(
        "{}.{}.{}",
        sort_key(cursor.sort),
        cursor.sort_at,
        hex::encode(cursor.post_id.as_bytes())
    )
}

fn parse_cursor(raw: &str, expected_sort: LibrarySort) -> Result<LibraryCursor, AppError> {
    let parts = raw.split('.').collect::<Vec<_>>();
    let (cursor_sort, sort_at, encoded_id) = match parts.as_slice() {
        // v5/v6 updated-at cursor. Keeping it valid avoids turning an open Studio tab into a 400
        // when v7 adds an explicit sort discriminator.
        [sort_at, encoded_id] if expected_sort == LibrarySort::Updated => {
            (LibrarySort::Updated, *sort_at, *encoded_id)
        }
        [sort, sort_at, encoded_id] => (parse_sort(sort)?, *sort_at, *encoded_id),
        _ => {
            return Err(AppError::InvalidRequest(
                "invalid library cursor".to_string(),
            ));
        }
    };
    if cursor_sort != expected_sort {
        return Err(AppError::InvalidRequest(
            "library cursor does not match sort".to_string(),
        ));
    }
    if encoded_id.len() > 512 {
        return Err(AppError::InvalidRequest(
            "invalid library cursor".to_string(),
        ));
    }
    let sort_at = sort_at
        .parse::<i64>()
        .map_err(|_| AppError::InvalidRequest("invalid library cursor".to_string()))?;
    let post_id = hex::decode(encoded_id)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .filter(|id| !id.is_empty())
        .ok_or_else(|| AppError::InvalidRequest("invalid library cursor".to_string()))?;
    Ok(LibraryCursor {
        sort: cursor_sort,
        sort_at,
        post_id,
    })
}

fn library_url(view: &ViewState, cursor: Option<&LibraryCursor>) -> String {
    let mut pairs = Vec::new();
    if !view.q.is_empty() {
        pairs.push(format!("q={}", percent_encode(&view.q)));
    }
    if view.status != LibraryStatus::All {
        pairs.push(format!("status={}", status_key(view.status)));
    }
    if !view.tag.is_empty() {
        pairs.push(format!("tag={}", percent_encode(&view.tag)));
    }
    if view.sort != LibrarySort::Updated {
        pairs.push(format!("sort={}", sort_key(view.sort)));
    }
    pairs.push(format!("as_of={}", view.as_of));
    pairs.push(format!("limit={}", view.limit));
    if let Some(cursor) = cursor {
        pairs.push(format!("cursor={}", encode_cursor(cursor)));
    }
    format!("/library?{}", pairs.join("&"))
}

/// Only the local Content Library is a valid authoring return target. The strict path shape avoids
/// scheme-relative URLs, path confusion, response splitting, and redirects to other product routes.
pub(crate) fn safe_library_return_to(raw: &str) -> Option<String> {
    if raw.len() > MAX_RETURN_TO_BYTES
        || !raw.is_ascii()
        || raw.bytes().any(|byte| byte.is_ascii_control())
    {
        return None;
    }
    let value = raw.trim();
    if value.is_empty()
        || value.contains('#')
        || HeaderValue::from_str(value).is_err()
        || !(value == "/library" || value.starts_with("/library?"))
    {
        None
    } else {
        Some(value.to_string())
    }
}

fn with_changed(return_to: &str, changed: usize) -> String {
    format!(
        "{return_to}{}changed={changed}",
        if return_to.contains('?') { '&' } else { '?' }
    )
}

fn render_notice(changed: usize) -> String {
    if changed == 0 {
        String::new()
    } else {
        format!(
            r#"<div class="flash flash-ok" role="status">Updated {changed} post{plural}.</div>"#,
            plural = if changed == 1 { "" } else { "s" },
        )
    }
}

pub(crate) fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn parse_pairs(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter(|part| !part.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (urldecode(key), urldecode(value))
        })
        .collect()
}

fn field(pairs: &[(String, String)], key: &str) -> String {
    pairs
        .iter()
        .find(|(candidate, _)| candidate == key)
        .map(|(_, value)| value.clone())
        .unwrap_or_default()
}

fn urldecode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                match (hex_value(bytes[index + 1]), hex_value(bytes[index + 2])) {
                    (Some(high), Some(low)) => {
                        out.push(high * 16 + low);
                        index += 3;
                    }
                    _ => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn redirect(location: &str) -> Response {
    let location =
        HeaderValue::from_str(location).unwrap_or_else(|_| HeaderValue::from_static("/library"));
    private_no_store((StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response())
}

fn html_with_cookie(body: String, set_cookie: Option<String>) -> Response {
    let mut response = Html(body).into_response();
    if let Some(cookie) = set_cookie {
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            response.headers_mut().insert(header::SET_COOKIE, value);
        }
    }
    response
}

fn private_no_store(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_and_selection_round_trip_stable_identity() {
        let cursor = LibraryCursor {
            sort: LibrarySort::Updated,
            sort_at: 42,
            post_id: "post.with:odd/id".to_string(),
        };
        assert_eq!(
            parse_cursor(&encode_cursor(&cursor), LibrarySort::Updated).unwrap(),
            cursor
        );
        assert!(parse_cursor(&encode_cursor(&cursor), LibrarySort::Created).is_err());
        assert_eq!(
            parse_cursor("42.706f7374", LibrarySort::Updated).unwrap(),
            LibraryCursor {
                sort: LibrarySort::Updated,
                sort_at: 42,
                post_id: "post".to_string(),
            }
        );
        assert!(parse_cursor("42.706f7374", LibrarySort::Created).is_err());
        assert_eq!(
            render_sort_options(LibrarySort::Created)
                .matches(" selected")
                .count(),
            1
        );
        assert!(render_sort_options(LibrarySort::Created).contains(r#"value="created" selected"#));
        let post = Post {
            id: "post.with:odd/id".to_string(),
            slug: "safe".to_string(),
            title: String::new(),
            body_md: String::new(),
            author_sub: String::new(),
            author_email: String::new(),
            created_at: 0,
            updated_at: 0,
            edit_version: 7,
            published: false,
            publish_at: 0,
            featured: false,
            pinned: false,
            tags: String::new(),
            cover_url: String::new(),
            custom_excerpt: String::new(),
            meta_title: String::new(),
            meta_description: String::new(),
            canonical_url: String::new(),
            social_title: String::new(),
            social_description: String::new(),
            social_image: String::new(),
        };
        assert_eq!(
            parse_selection(&encode_selection(&post)).unwrap(),
            LibrarySelection {
                post_id: post.id,
                expected_version: 7,
            }
        );
    }

    #[test]
    fn return_target_is_only_local_library() {
        assert_eq!(
            safe_library_return_to("/library?q=rust"),
            Some("/library?q=rust".to_string())
        );
        for invalid in [
            "https://evil.example/library",
            "//evil.example/library",
            "/library/other",
            "/library?x=1\r\nX-Evil: yes",
            "/library\n",
            "\t/library",
            "/library?q=\0",
            "/library?q=\u{7f}",
            "/library?q=中文",
            "/edit/post",
        ] {
            assert_eq!(safe_library_return_to(invalid), None, "{invalid}");
        }
        assert_eq!(
            safe_library_return_to("/library?q=%E4%B8%AD%E6%96%87"),
            Some("/library?q=%E4%B8%AD%E6%96%87".to_string())
        );
    }

    #[test]
    fn redirect_never_panics_on_an_invalid_header_value() {
        let response = redirect("/library?q=\0");
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "/library"
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "private, no-store"
        );
    }
}
