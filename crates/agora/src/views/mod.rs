//! Frontend-owned pure view layer for Agora — the Civic Amphitheatre.
//!
//! Boundary (Step 3 contract §2/§14): these modules are PURE presentation. They consume the
//! typed, already-authorized view models Codex builds in `crate::view_model` and return escaped
//! HTML strings. They NEVER touch `crate::store`, `crate::auth`, `crate::error`, `AppState`,
//! `HeaderMap`, axum extractors, CSRF minting/verification, permission decisions, cache policy,
//! or raw backend errors. `tests/ui_contract.rs` machine-checks this boundary.
//!
//! Escape discipline: every `Text`/`Opaque` value is HTML-escaped at interpolation time via
//! [`escape`] (owned here at the views root); `SafeHtml` is already sanitized by Codex
//! (`markdown.rs`) and is emitted verbatim. The view layer owns presentation formatting: relative/
//! absolute time, plural labels, civic keyline classes, state chips, and action control markup.
//!
//! Civic grammar (structural, not decorative):
//! - solid etched keylines (`.ag-key-shared` family) = shared civic truth (terraces, floor,
//!   dais, steps, shared state chips);
//! - dashed penciled keylines (`.ag-key-private` family) = private subject state (Focus
//!   markers, subscription intent, bookmark/unread/resume overlays, ledger reasons).

pub mod admin;
pub mod forum;
pub mod personal;
pub mod search;
pub mod shell;

use crate::view_model::{
    AcceptanceMeaning, ActionKind, AnswerDaisVM, AnswerState, CollectionState, FormActionVM,
    HiddenField, LinkActionVM, Opaque, PageLinkVM, PaginationVM, PostBookmarkActionVM, PostVM,
    QuoteVM, ReactionVM, SavedBookmarkStateVM, Text, ThreadFollowLevelVM, ThreadKind,
    ThreadRowShared, ThreadRowViewerState,
};

// ===========================================================================
// Escape (owned at the views root — see the C8 de-circularisation note). `shell.rs` and every
// sibling view module import this via `super::escape`; nothing re-exports it back down, so the
// module graph is acyclic.
// ===========================================================================

/// Minimal HTML escaping for text/attribute interpolation. The presentation layer owns escaping
/// layer (contract §4: migrated from the retired `handlers::esc`).
pub fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Escape a [`Text`] newtype for HTML interpolation.
pub(crate) fn t(value: &Text) -> String {
    escape(&value.0)
}

/// Escape an [`Opaque`] newtype for attribute interpolation (href/id/token). The value stays
/// semantically opaque; escaping only makes it attribute-safe.
pub(crate) fn o(value: &Opaque) -> String {
    escape(&value.0)
}

// ===========================================================================
// Time, counts, and plural labels — presentation-owned formatting.
// ===========================================================================

/// Compact "N ago" relative time from `ts` to `now` (both epoch seconds). Migrated verbatim
/// from the retired `handlers::rel_time` helper (C8 symbol migration).
pub(crate) fn rel_time(ts: i64, now: i64) -> String {
    let d = now.saturating_sub(ts);
    if d < 5 {
        "just now".to_string()
    } else if d < 60 {
        format!("{d}s ago")
    } else if d < 3_600 {
        format!("{}m ago", d / 60)
    } else if d < 86_400 {
        format!("{}h ago", d / 3_600)
    } else {
        format!("{}d ago", d / 86_400)
    }
}

/// Format epoch seconds as a compact UTC timestamp `YYYY-MM-DD HH:MM UTC`. Migrated verbatim
/// from the retired `handlers::fmt_ts` helper.
pub(crate) fn fmt_ts(secs: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02} UTC",
            dt.year(),
            dt.month() as u8,
            dt.day(),
            dt.hour(),
            dt.minute(),
        ),
        Err(_) => secs.to_string(),
    }
}

/// Machine-readable ISO-8601 UTC stamp for a `<time datetime="…">` attribute.
fn iso8601(secs: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            dt.year(),
            dt.month() as u8,
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second(),
        ),
        Err(_) => secs.to_string(),
    }
}

/// A `<time>` element carrying the machine stamp plus a human relative label and an absolute
/// title, so the same value is readable to sighted, keyboard, and assistive users.
pub(crate) fn time_el(ts: i64, now: i64) -> String {
    format!(
        r#"<time class="ag-time" datetime="{iso}" title="{abs}">{rel}</time>"#,
        iso = escape(&iso8601(ts)),
        abs = escape(&fmt_ts(ts)),
        rel = escape(&rel_time(ts, now)),
    )
}

/// "N replies" / "N reply" label from a post count (which includes the original post).
/// Migrated verbatim from the retired `handlers::replies_label` helper.
pub(crate) fn replies_label(post_count: i64) -> String {
    let replies = (post_count - 1).max(0);
    if replies == 1 {
        "1 reply".to_string()
    } else {
        format!("{replies} replies")
    }
}

// ===========================================================================
// Monograms, breadcrumbs, tabs, chips — small shared civic primitives.
// ===========================================================================

/// First alphanumeric character, uppercased, for a monogram tile. Migrated verbatim from the
/// retired `handlers::ag_initial`. The hash-tone palette (`ag_tone`) is DELETED per C9: no
/// tone class is ever emitted.
pub(crate) fn ag_initial(s: &str) -> String {
    s.chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().collect())
        .unwrap_or_else(|| "U".to_string())
}

/// A single-tone etched monogram tile. One neutral treatment for every author — identity
/// initials only, never a per-subject hash color.
pub(crate) fn monogram(display: &str) -> String {
    format!(
        r#"<span class="avatar ag-avatar" aria-hidden="true">{}</span>"#,
        escape(&ag_initial(display)),
    )
}

/// Breadcrumb trail. The final segment is plain text (current location); earlier segments are
/// links. All labels are escaped.
pub(crate) fn crumbs(segments: &[(&str, Option<&str>)]) -> String {
    let mut out = String::from(r#"<nav class="crumbs" aria-label="Breadcrumb">"#);
    for (i, (label, href)) in segments.iter().enumerate() {
        if i > 0 {
            out.push_str(r#"<span class="crumbs__sep">/</span>"#);
        }
        match href {
            Some(href) => out.push_str(&format!(
                r#"<a href="{}">{}</a>"#,
                escape(href),
                escape(label),
            )),
            None => out.push_str(&format!("<span>{}</span>", escape(label))),
        }
    }
    out.push_str("</nav>");
    out
}

/// Shared-truth state chip (solid etched keyline): the valid answer state. Text is always
/// present — state is never color-only.
pub(crate) fn answer_state_chip(state: AnswerState) -> String {
    match state {
        AnswerState::NotApplicable => String::new(),
        AnswerState::NeedsAnswer => {
            r#"<span class="badge ag-chip-shared ag-answer-state ag-answer-state--open">Needs answer</span>"#.to_string()
        }
        AnswerState::Answered => {
            r#"<span class="badge badge-accepted ag-chip-shared ag-answer-state">Answered</span>"#.to_string()
        }
    }
}

/// Thread-kind chip (shared truth, solid etched). Discussion/Question are distinct civic kinds.
pub(crate) fn kind_chip(kind: ThreadKind) -> &'static str {
    match kind {
        ThreadKind::Question => {
            r#"<span class="badge ag-chip-shared ag-kind ag-kind--question">Question</span>"#
        }
        ThreadKind::Discussion => {
            r#"<span class="badge ag-chip-shared ag-kind ag-kind--discussion">Discussion</span>"#
        }
    }
}

/// A shared-truth structural flag (pinned/locked). Text + shape, never icon-only colour.
fn shared_flag(modifier: &str, label: &str) -> String {
    format!(
        r#"<span class="badge ag-chip-shared ag-flag ag-flag--{modifier}">{label}</span>"#,
        modifier = modifier,
        label = escape(label),
    )
}

/// Eyebrow label (small caps civic register) naming a structure or privacy register.
pub(crate) fn eyebrow(text: &str) -> String {
    format!(r#"<p class="eyebrow ag-eyebrow">{}</p>"#, escape(text))
}

// ===========================================================================
// Server-issued action descriptors — presence/absence only; views never invent authority.
// ===========================================================================

/// Render the hidden inputs of a server-issued action descriptor (`name`/`value` pairs plus the
/// CSRF token). Values are escaped; the view never invents field names or values.
pub(crate) fn hidden_inputs(csrf: &str, fields: &[HiddenField]) -> String {
    let mut out = format!(
        r#"<input type="hidden" name="csrf" value="{}">"#,
        escape(csrf),
    );
    for field in fields {
        out.push_str(&format!(
            r#"<input type="hidden" name="{}" value="{}">"#,
            escape(&field.name.0),
            escape(&field.value.0),
        ));
    }
    out
}

/// Human label + button class for a server-issued action kind. Copy is presentation-owned; the
/// decision WHETHER the action exists belongs to the handler (absence = no control).
pub(crate) fn action_label(kind: &ActionKind) -> (&'static str, &'static str) {
    match kind {
        ActionKind::EditReply => ("Edit", "btn btn-ghost btn-sm"),
        ActionKind::EditThread => ("Edit thread", "btn btn-secondary btn-sm"),
        ActionKind::DeleteThreadReview => ("Delete thread", "btn btn-danger btn-sm"),
        ActionKind::DeleteReplyReview => ("Delete", "btn btn-danger btn-sm"),
        ActionKind::DeleteAdminReview => ("Delete (admin)", "btn btn-danger btn-sm"),
        ActionKind::DeleteConfirm => ("Confirm deletion", "btn btn-danger"),
        ActionKind::Quote => ("Quote", "btn btn-ghost btn-sm"),
        ActionKind::BookmarkSave => ("Bookmark", "btn btn-ghost btn-sm"),
        ActionKind::BookmarkEdit => ("Saved", "btn btn-ghost btn-sm"),
        ActionKind::SaveBookmarkChanges => ("Save bookmark", "btn btn-primary"),
        ActionKind::AcceptAnswer => ("Accept answer", "btn btn-secondary btn-sm"),
        ActionKind::RemoveSolution => ("Remove solution", "btn btn-secondary btn-sm"),
        ActionKind::ClearInvalidSolution => ("Clear invalid solution", "btn btn-secondary btn-sm"),
        ActionKind::UpdateSubscription => ("Update", "btn btn-secondary btn-sm"),
        ActionKind::ApplyFocus => ("Apply", "btn btn-secondary btn-sm"),
        ActionKind::SaveFocusRule => ("Save rule", "btn btn-primary"),
        ActionKind::OpenActivity => ("Open", "btn btn-ghost btn-sm"),
        ActionKind::MarkPageRead => ("Mark this page read", "btn btn-secondary btn-sm"),
        ActionKind::MarkThreadPageRead => {
            ("Mark page read &amp; continue", "btn btn-secondary btn-sm")
        }
        ActionKind::MarkRead => ("Mark read", "btn btn-ghost btn-sm"),
        ActionKind::MarkUnread => ("Mark unread", "btn btn-ghost btn-sm"),
        ActionKind::CompleteBookmark => ("Done", "btn btn-primary btn-sm"),
        ActionKind::SnoozeTomorrow => ("Snooze 24 hours", "btn btn-secondary btn-sm"),
        ActionKind::SnoozeWeek => ("Snooze 7 days", "btn btn-secondary btn-sm"),
        ActionKind::RemoveBookmark => ("Remove", "btn btn-ghost btn-sm"),
        ActionKind::CreateCategory => ("Create category", "btn btn-primary"),
        ActionKind::RenameCategory => ("Rename", "btn btn-secondary btn-sm"),
        ActionKind::SetCategoryFormat => ("Set format", "btn btn-secondary btn-sm"),
        ActionKind::MoveThread => ("Move", "btn btn-secondary btn-sm"),
        ActionKind::MoveCategoryUp => ("Move up", "btn btn-ghost btn-sm"),
        ActionKind::MoveCategoryDown => ("Move down", "btn btn-ghost btn-sm"),
        ActionKind::Lock => ("Lock", "btn btn-secondary btn-sm"),
        ActionKind::Unlock => ("Unlock", "btn btn-secondary btn-sm"),
        ActionKind::Pin => ("Pin", "btn btn-secondary btn-sm"),
        ActionKind::Unpin => ("Unpin", "btn btn-secondary btn-sm"),
        ActionKind::AddBan => ("Ban author", "btn btn-danger"),
        ActionKind::Unban => ("Unban", "btn btn-secondary btn-sm"),
        ActionKind::PublishThread => ("Publish thread", "btn btn-primary"),
        ActionKind::SaveThread => ("Save thread", "btn btn-primary"),
        ActionKind::SaveReply => ("Save reply", "btn btn-primary"),
        ActionKind::PostReply => ("Post reply", "btn btn-primary"),
        ActionKind::PostAnswer => ("Post answer", "btn btn-primary"),
        ActionKind::ToggleReaction => ("React", "ag-react"),
    }
}

/// Render a handler-issued non-mutating link.
pub(crate) fn link_action(a: &LinkActionVM) -> String {
    let (label, class) = action_label(&a.label_kind);
    format!(
        r#"<a class="{class}" href="{href}">{label}</a>"#,
        class = class,
        href = o(&a.href),
        label = label,
    )
}

/// Render a handler-issued CSRF-guarded POST form.
pub(crate) fn form_action(a: &FormActionVM) -> String {
    let (label, class) = action_label(&a.label_kind);
    format!(
        r#"<form class="inline-form" method="post" action="{action}">{hidden}<button class="{class}" type="submit">{label}</button></form>"#,
        action = o(&a.action),
        hidden = hidden_inputs(&a.csrf.0, &a.fields),
        class = class,
        label = label,
    )
}

pub(crate) fn link_action_opt(a: &Option<LinkActionVM>) -> String {
    a.as_ref().map(link_action).unwrap_or_default()
}

pub(crate) fn form_action_opt(a: &Option<FormActionVM>) -> String {
    a.as_ref().map(form_action).unwrap_or_default()
}

// ===========================================================================
// Presentation route helpers. The IDs are already-authorized opaque values; the `/t/` and
// `/c/` prefixes are stable presentation routes (no authority is recovered from the id).
// ===========================================================================

pub(crate) fn thread_href(id: &Opaque) -> String {
    format!("/t/{}", o(id))
}

pub(crate) fn category_href(id: &Opaque) -> String {
    format!("/c/{}", o(id))
}

// ===========================================================================
// Private markers — dashed penciled keylines. `None` private truth renders NOTHING (never a
// painted "0" / "not followed"). Every marker carries text AND shape, so it survives grayscale
// and forced colors and never collapses into a shared-truth chip.
// ===========================================================================

/// A dashed private marker: an explicit personal-state pill that explains its own effect.
pub(crate) fn private_marker(modifier: &str, label: &str) -> String {
    format!(
        r#"<span class="ag-mark ag-key-private ag-mark--{modifier}">{label}</span>"#,
        modifier = modifier,
        label = escape(label),
    )
}

/// The follow/watch/mute intent as a private marker. `None`/`Some(None)` render nothing.
pub(crate) fn follow_marker(level: ThreadFollowLevelVM) -> String {
    match level {
        ThreadFollowLevelVM::None => String::new(),
        ThreadFollowLevelVM::Watch => private_marker("watch", "Watching"),
        ThreadFollowLevelVM::Follow => private_marker("follow", "Following"),
        ThreadFollowLevelVM::Mute => private_marker("mute", "Muted"),
    }
}

/// Unread count as a private marker. `Some(0)`/`None` render nothing.
fn unread_marker(count: Option<i64>) -> String {
    match count {
        Some(n) if n > 0 => {
            let label = if n == 1 {
                "1 unread".to_string()
            } else {
                format!("{n} unread")
            };
            private_marker("unread", &label)
        }
        _ => String::new(),
    }
}

/// Bookmarked overlay as a private marker. `None`/`Some(false)` render nothing.
fn bookmark_marker(on: Option<bool>) -> String {
    if on == Some(true) {
        private_marker("bookmark", "Bookmarked")
    } else {
        String::new()
    }
}

/// A private "resume where you left off" link (opaque href supplied by Codex).
fn resume_link(href: &Option<Opaque>) -> String {
    match href {
        Some(h) => format!(
            r#"<a class="ag-mark ag-key-private ag-mark--resume" href="{}">Resume</a>"#,
            o(h),
        ),
        None => String::new(),
    }
}

// ===========================================================================
// Thread rows (Topic Terrace entries) — shared solid truth + a separately keyed private overlay.
// ===========================================================================

/// One topic-terrace row: shared civic truth on a solid keyline, then the current subject's
/// private overlay on dashed keylines. The two never share a container class, so grayscale and
/// forced-colors keep them distinct.
pub(crate) fn thread_row(
    shared: &ThreadRowShared,
    viewer: &ThreadRowViewerState,
    now: i64,
) -> String {
    let mut chips = String::new();
    chips.push_str(kind_chip(shared.kind));
    if shared.kind == ThreadKind::Question {
        chips.push_str(&answer_state_chip(shared.answer_state));
    }
    if shared.pinned {
        chips.push_str(&shared_flag("pinned", "Pinned"));
    }
    if shared.locked {
        chips.push_str(&shared_flag("locked", "Locked"));
    }

    let category = shared
        .category
        .as_ref()
        .map(|c| {
            format!(
                r#" <span class="ag-row__cat">in <a href="{href}">{name}</a></span>"#,
                href = escape(&category_href(&c.id)),
                name = t(&c.name),
            )
        })
        .unwrap_or_default();

    // Private overlay: dashed markers. Any absent private fact renders nothing.
    let mut marks = String::new();
    if let Some(level) = viewer.follow_level {
        marks.push_str(&follow_marker(level));
    }
    marks.push_str(&bookmark_marker(viewer.bookmarked));
    marks.push_str(&unread_marker(viewer.unread_count));
    marks.push_str(&resume_link(&viewer.resume_href));
    let overlay = if marks.is_empty() {
        String::new()
    } else {
        format!(r#"<p class="ag-row__mine ag-key-private">{marks}</p>"#)
    };
    let replies = shared
        .post_count
        .map(|count| format!(" · {}", escape(&replies_label(count))))
        .unwrap_or_default();

    format!(
        r#"<li class="ag-row ag-key-shared">
  <div class="ag-row__body">
    <div class="ag-row__chips">{chips}</div>
    <a class="ag-row__title" href="{href}">{title}</a>
    <p class="ag-row__by">{monogram} <span class="ag-row__author">{author}</span>{category} · started {started}{replies} · latest {latest}</p>
    {overlay}
  </div>
</li>"#,
        chips = chips,
        href = escape(&thread_href(&shared.id)),
        title = t(&shared.title),
        monogram = monogram(&shared.author_display.0),
        author = t(&shared.author_display),
        category = category,
        started = time_el(shared.created_at, now),
        replies = replies,
        latest = time_el(shared.last_at, now),
        overlay = overlay,
    )
}

/// A row list wrapper carrying the `.thread-list` enhancement hook the shell's sort-swap script
/// keys off. Empty collections render a distinct civic note instead of a false "0 threads".
pub(crate) fn thread_list(rows: &str, empty: Option<String>) -> String {
    match empty {
        Some(note) => note,
        None => format!(r#"<ul class="thread-list ag-terrace__list">{rows}</ul>"#),
    }
}

// ===========================================================================
// Posts — the Speaker Floor (OP) and Reply Steps share one renderer; the Answer Dais reuses it
// with an explicit acceptance caveat and no chronological placement.
// ===========================================================================

/// One post: shared authorship/body truth on a solid keyline, private overlays on dashed ones,
/// and only the server-issued action controls that Codex supplied.
pub(crate) fn post(p: &PostVM, now: i64) -> String {
    let op_badge = if p.is_op {
        r#"<span class="badge ag-chip-shared ag-op-badge">Original post</span>"#
    } else {
        ""
    };

    // Private post overlays (dashed). Absent private facts render nothing.
    let mut marks = String::new();
    marks.push_str(&bookmark_marker(p.viewer.bookmarked));
    if p.viewer.unread == Some(true) {
        marks.push_str(&private_marker("unread", "Unread"));
    }
    let mine = if marks.is_empty() {
        String::new()
    } else {
        format!(r#"<div class="ag-post__mine ag-key-private">{marks}</div>"#)
    };

    let quote = p
        .quote
        .as_ref()
        .map(|q| quote_block(q, now))
        .unwrap_or_default();
    let reactions = reactions_row(&p.reactions);
    let actions = post_actions(&p.actions);

    // Private resume/first-unread jump target (opaque anchor id from Codex), placed just before
    // the post so a `#…` resume link lands on it without colliding with the post's own id.
    let resume_anchor = p
        .viewer
        .resume_anchor
        .as_ref()
        .map(|a| {
            format!(
                r#"<div class="ag-first-unread ag-key-private" id="{}" role="separator" tabindex="-1"><span>First unread</span></div>"#,
                o(a),
            )
        })
        .unwrap_or_default();

    let anchor = format!("post-{}", o(&p.id));
    format!(
        r##"{resume_anchor}<article class="ag-post ag-key-shared{op}" id="{anchor}">
  <header class="ag-post__head">
    {monogram}
    <div class="ag-post__ident">
      <span class="ag-post__author">{author}</span>
      <span class="ag-post__meta">{op_badge} {time} <a class="ag-permalink" href="#{anchor}">Permalink</a></span>
    </div>
    {mine}
  </header>
  {quote}
  <div class="ag-md">{body}</div>
  <footer class="ag-post__foot">
    {reactions}
    <div class="ag-post__actions">{actions}</div>
  </footer>
</article>"##,
        resume_anchor = resume_anchor,
        op = if p.is_op { " ag-post--op" } else { "" },
        anchor = anchor,
        monogram = monogram(&p.author_display.0),
        author = t(&p.author_display),
        op_badge = op_badge,
        time = time_el(p.created_at, now),
        mine = mine,
        quote = quote,
        body = p.body.0, // SafeHtml — sanitized by Codex, emitted verbatim (never escaped).
        reactions = reactions,
        actions = actions,
    )
}

/// A sanitized same-thread quotation. Author/time are escaped; the quoted body is SafeHtml.
fn quote_block(q: &QuoteVM, now: i64) -> String {
    format!(
        r#"<blockquote class="ag-quote ag-key-shared"><cite class="ag-quote__cite">{author} · {time}</cite><div class="ag-md">{body}</div></blockquote>"#,
        author = t(&q.author_display),
        time = time_el(q.created_at, now),
        body = q.body.0, // SafeHtml — verbatim.
    )
}

/// The aggregate reaction row. The count is shared truth; the viewer's own membership is a
/// private state expressed with `aria-pressed` plus a non-colour "· yours" marker.
fn reactions_row(rs: &[ReactionVM]) -> String {
    if rs.is_empty() {
        return String::new();
    }
    let mut out = String::from(r#"<div class="ag-reactions" role="group" aria-label="Reactions">"#);
    for r in rs {
        let kind = t(&r.kind);
        let mine = r.mine == Some(true);
        let yours = if mine {
            r#" <span class="ag-react__mine">· yours</span>"#
        } else {
            ""
        };
        match &r.toggle {
            Some(a) => out.push_str(&format!(
                r#"<form class="inline-form" method="post" action="{action}">{hidden}<button class="ag-react{on}" type="submit" aria-pressed="{pressed}">{kind} <span class="ag-react__count">{count}</span>{yours}</button></form>"#,
                action = o(&a.action),
                hidden = hidden_inputs(&a.csrf.0, &a.fields),
                on = if mine { " is-mine" } else { "" },
                pressed = if mine { "true" } else { "false" },
                kind = kind,
                count = r.count,
                yours = yours,
            )),
            None => out.push_str(&format!(
                r#"<span class="ag-react is-static">{kind} <span class="ag-react__count">{count}</span>{yours}</span>"#,
                kind = kind,
                count = r.count,
                yours = yours,
            )),
        }
    }
    out.push_str("</div>");
    out
}

/// The server-issued per-post controls, in a stable order. Each is present only if Codex
/// supplied it. Destructive controls render their two-phase review entry (a GET link).
fn post_actions(a: &crate::view_model::PostActionsVM) -> String {
    let mut out = String::new();
    out.push_str(&form_action_opt(&a.accept));
    out.push_str(&form_action_opt(&a.remove_solution));
    out.push_str(&link_action_opt(&a.quote));
    if let Some(bookmark) = &a.bookmark {
        match bookmark {
            PostBookmarkActionVM::Save(save) => out.push_str(&form_action(save)),
            PostBookmarkActionVM::Saved { edit, state } => {
                let (state_label, aria) = match state {
                    SavedBookmarkStateVM::Saved => ("Saved", "Edit saved bookmark"),
                    SavedBookmarkStateVM::Due => ("Saved · Due", "Edit saved bookmark, due"),
                    SavedBookmarkStateVM::Scheduled => {
                        ("Saved · Scheduled", "Edit saved bookmark, scheduled")
                    }
                };
                out.push_str(&format!(
                    r#"<a class="btn btn-ghost btn-sm ag-post-bookmark is-saved" href="{href}" aria-label="{aria}">{label}</a>"#,
                    href = o(&edit.href),
                    aria = escape(aria),
                    label = escape(state_label),
                ));
            }
        }
    }
    out.push_str(&link_action_opt(&a.edit));
    for review in &a.delete_reviews {
        out.push_str(&link_action(review));
    }
    out
}

/// The Answer Dais: one valid accepted reply, rendered ONCE directly below the original post and
/// excluded from ordinary chronology. The caveat states acceptance meaning only — never
/// "correct", "verified", "best", or "newest".
pub(crate) fn answer_dais(d: &AnswerDaisVM, now: i64) -> String {
    let caveat = match d.acceptance {
        AcceptanceMeaning::AcceptedByAskerOrAuthorizedModerator => {
            "Accepted by the asker or an authorized moderator. This marks acceptance, not objective correctness."
        }
    };
    format!(
        r#"<section class="ag-dais ag-key-shared" aria-labelledby="ag-dais-title">
  <h2 class="eyebrow ag-eyebrow" id="ag-dais-title">Answer Dais</h2>
  <p class="ag-dais__caveat">{caveat}</p>
  {post}
</section>"#,
        caveat = escape(caveat),
        post = post(&d.post, now),
    )
}

// ===========================================================================
// Pagination — the "continuation edge": an exact cursor/page/end state. Hrefs are opaque
// (handler-issued); the view never parses or edits a cursor.
// ===========================================================================

pub(crate) fn pagination(p: &PaginationVM) -> String {
    let link = |l: &Option<PageLinkVM>, rel: &str| -> String {
        match l {
            Some(link) => format!(
                r#"<a class="btn btn-secondary btn-sm ag-page__link" rel="{rel}" href="{href}">{label}</a>"#,
                rel = rel,
                href = o(&link.href),
                label = t(&link.label),
            ),
            None => String::new(),
        }
    };
    let edge = if p.at_end {
        r#"<span class="ag-page__edge">End of results</span>"#.to_string()
    } else if p.at_start {
        r#"<span class="ag-page__edge">Beginning of results</span>"#.to_string()
    } else {
        String::new()
    };
    let jump = p
        .jump
        .as_ref()
        .map(|link| {
            format!(
                r#"<a class="btn btn-ghost btn-sm ag-page__jump" href="{href}">{label}</a>"#,
                href = o(&link.href),
                label = t(&link.label),
            )
        })
        .unwrap_or_default();
    format!(
        r#"<nav class="ag-page" aria-label="Pagination"><span class="ag-page__bound">Page bound {limit}</span>{edge}<span class="ag-page__links">{jump}{newer}{older}</span></nav>"#,
        limit = p.visible_limit,
        edge = edge,
        jump = jump,
        newer = link(&p.previous, "prev"),
        older = link(&p.next, "next"),
    )
}

// ===========================================================================
// Collection states — empty / end / filtered-zero / too-short / invalid-cursor / unavailable are
// all distinct civic notes, never the same silent blank.
// ===========================================================================

/// The distinct note for a non-populated [`CollectionState`]. Returns `None` for `Ready` (the
/// caller renders real rows). `ReadyEmpty` uses the caller-supplied `empty_msg`.
pub(crate) fn collection_note(state: CollectionState, empty_msg: &str) -> Option<String> {
    let (title, body) = match state {
        CollectionState::Ready => return None,
        CollectionState::ReadyEmpty => ("Nothing here yet", empty_msg),
        CollectionState::End => (
            "You've reached the end",
            "There are no more items on this page.",
        ),
        CollectionState::FilteredZero => (
            "No matches for this filter",
            "Nothing matches the current filter. Clear it to see more.",
        ),
        CollectionState::TooShort => (
            "Keep typing",
            "The query is too short to run. Add a couple more characters.",
        ),
        CollectionState::InvalidCursor => (
            "That page link expired",
            "The continuation link is no longer valid. Start from the most recent page.",
        ),
        CollectionState::Unavailable => (
            "Temporarily unavailable",
            "This list could not be loaded right now. Try again shortly.",
        ),
    };
    Some(format!(
        r#"<div class="card pad empty-card ag-empty" role="status"><p class="empty-title">{title}</p><p class="muted">{body}</p></div>"#,
        title = escape(title),
        body = escape(body),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_epoch_as_utc() {
        // 2023-11-14T22:13:20Z = 1_700_000_000 s.
        assert_eq!(fmt_ts(1_700_000_000), "2023-11-14 22:13 UTC");
        assert_eq!(iso8601(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn replies_label_pluralises() {
        assert_eq!(replies_label(1), "0 replies");
        assert_eq!(replies_label(2), "1 reply");
        assert_eq!(replies_label(4), "3 replies");
    }

    #[test]
    fn monogram_never_carries_tone() {
        let tile = monogram("éclair@example.com");
        assert!(tile.contains('É'));
        assert!(!tile.contains("ag-tone"));
    }

    #[test]
    fn escapes_html_metacharacters() {
        assert_eq!(escape("<b>&\"'"), "&lt;b&gt;&amp;&quot;&#x27;");
    }
}
