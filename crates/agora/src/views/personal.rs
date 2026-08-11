//! Civic Ledgers — the subject-private rooms: For You, Focus, Activity, Bookmarks.
//!
//! These views lead with the signed-in subject context, private ownership, the reason a row is
//! present, and the snapshot/bound, THEN the content (contract five-second hierarchy for private
//! views). Every private fact is drawn on dashed penciled keylines and worded as personal intent,
//! never shared status or delivery. Tab switches are real relative-query links so no-JS works.

use crate::view_model::{
    ActivityItemVM, ActivityKindVM, ActivityReasonVM, ActivityShared, ActivityView,
    BookmarkEditView, BookmarkItemVM, BookmarkReminderChoiceVM, BookmarkStateVM, BookmarksView,
    CatchUpFeedVM, CatchUpItemVM, CatchUpQuestionStateVM, CatchUpReasonVM, CatchUpTab,
    CategoryFocusLevelVM, CategoryFocusReasonVM, FocusItemVM, FocusRuleVM, FocusView, ThreadKind,
};

use super::shell;
use super::{
    action_label, answer_state_chip, collection_note, crumbs, escape, eyebrow, follow_marker,
    form_action, form_action_opt, hidden_inputs, kind_chip, link_action, monogram, o, pagination,
    private_marker, t, thread_href, time_el,
};

// ===========================================================================
// Shared ledger chrome.
// ===========================================================================

/// One tab row for a ledger, using a relative `?{param}={value}` href (path-agnostic).
fn ledger_tabs(param: &str, aria: &str, tabs: &[(&str, &str, bool)]) -> String {
    let mut nav = format!(
        r#"<nav class="tabs ag-ledger-tabs" aria-label="{aria}">"#,
        aria = escape(aria),
    );
    for (value, label, active) in tabs {
        nav.push_str(&format!(
            r#"<a class="tab{cls}"{current} href="?{param}={value}">{label}</a>"#,
            cls = if *active { " is-active" } else { "" },
            current = if *active {
                r#" aria-current="page""#
            } else {
                ""
            },
            param = param,
            value = value,
            label = escape(label),
        ));
    }
    nav.push_str("</nav>");
    nav
}

/// A private ledger header: eyebrow, title, an explicit owner note, and a snapshot/bound line.
fn ledger_head(title: &str, owner_note: &str, meta: &str) -> String {
    format!(
        r#"<header class="pagehead ag-ledger-head ag-key-private">
  <div class="ag-head-tools__lead">
    {eyebrow}
    <h1 class="ag-head__title">{title}</h1>
    <p class="ag-ledger-owner muted">{owner_note}</p>
    <p class="ag-ledger-meta muted">{meta}</p>
  </div>
</header>"#,
        eyebrow = eyebrow("Civic Ledger"),
        title = escape(title),
        owner_note = escape(owner_note),
        meta = escape(meta),
    )
}

// ===========================================================================
// For You — private catch-up (never an engagement feed).
// ===========================================================================

pub fn catch_up(v: &CatchUpFeedVM) -> String {
    shell::page(&v.chrome, &catch_up_main(v))
}

fn catch_up_main(v: &CatchUpFeedVM) -> String {
    let s = &v.shared;
    let tabs = ledger_tabs(
        "view",
        "Catch-up view",
        &[
            ("updates", "Updates", s.active == CatchUpTab::Updates),
            ("following", "Following", s.active == CatchUpTab::Following),
            ("questions", "Questions", s.active == CatchUpTab::Questions),
        ],
    );
    let meta = format!(
        "As of {} · page bound {} · a private snapshot, not a global feed",
        super::fmt_ts(s.snapshot_as_of),
        s.visible_bound,
    );
    let body = if v.viewer.items.is_empty() {
        collection_note(s.state, "You're all caught up. Nothing new in this view.")
            .unwrap_or_default()
    } else {
        let rows: String = v
            .viewer
            .items
            .iter()
            .map(|it| catch_up_item(it, s.now))
            .collect();
        format!(
            r#"<ul class="ag-ledger-list">{rows}</ul>{page}"#,
            page = pagination(&v.viewer.pagination)
        )
    };
    format!(
        r#"<div class="ag-ledger ag-for-you">{head}{tabs}{body}</div>"#,
        head = ledger_head(
            "For You",
            "Only you can see this. It explains why each thread appears.",
            &meta,
        ),
        tabs = tabs,
        body = body,
    )
}

fn catch_up_reason(reason: CatchUpReasonVM) -> &'static str {
    match reason {
        CatchUpReasonVM::Watch => "You are watching this thread",
        CatchUpReasonVM::Follow => "You follow this thread",
        CatchUpReasonVM::Authored => "You started this thread",
        CatchUpReasonVM::Bookmarked => "You bookmarked this thread",
        CatchUpReasonVM::Participated => "You replied in this thread",
        CatchUpReasonVM::ContinueReading => "Continue where you left off",
    }
}

fn catch_up_item(it: &CatchUpItemVM, now: i64) -> String {
    let s = &it.shared;
    let vr = &it.viewer;
    let mut chips = String::from(kind_chip(s.kind));
    if s.kind == ThreadKind::Question {
        chips.push_str(&answer_state_chip(s.answer_state));
    }

    // Private overlay (dashed): why, follow intent, unread, question waiting/solved.
    let mut marks = private_marker("reason", catch_up_reason(vr.reason));
    marks.push_str(&follow_marker(vr.follow_level));
    if vr.unread_count > 0 {
        let label = if vr.unread_count == 1 {
            "1 unread".to_string()
        } else {
            format!("{} unread", vr.unread_count)
        };
        marks.push_str(&private_marker("unread", &label));
    }
    if let Some(qs) = vr.question_state {
        let label = match qs {
            CatchUpQuestionStateVM::Waiting => "Waiting for an answer",
            CatchUpQuestionStateVM::Solved => "Accepted answer recorded",
        };
        marks.push_str(&private_marker("question", label));
    }
    let resume = vr
        .first_unread_href
        .as_ref()
        .map(|h| {
            format!(
                r#"<a class="ag-mark ag-key-private ag-mark--resume" href="{}">Jump to first unread</a>"#,
                o(h),
            )
        })
        .unwrap_or_default();

    format!(
        r#"<li class="ag-ledger-item ag-key-shared">
  <div class="ag-row__chips">{chips}</div>
  <a class="ag-row__title" href="{href}">{title}</a>
  <p class="ag-row__by">{monogram} <span class="ag-row__author">{author}</span> · latest {time}</p>
  <p class="ag-ledger-item__mine ag-key-private">{marks}{resume}</p>
</li>"#,
        chips = chips,
        href = escape(&thread_href(&s.id)),
        title = t(&s.title),
        monogram = monogram(&s.author_display.0),
        author = t(&s.author_display),
        time = time_el(s.last_at, now),
        marks = marks,
        resume = resume,
    )
}

// ===========================================================================
// Focus — private category priority/follow/mute rules and the threads they surface.
// ===========================================================================

pub fn focus(v: &FocusView) -> String {
    shell::page(&v.chrome, &focus_main(v))
}

fn focus_main(v: &FocusView) -> String {
    let s = &v.shared;
    let meta = format!(
        "Up to {} rules · up to {} threads shown · private to you",
        s.rule_bound, s.visible_thread_bound,
    );

    let rules = if v.viewer.rules.is_empty() {
        r#"<p class="muted">No category focus rules yet.</p>"#.to_string()
    } else {
        let items: String = v.viewer.rules.iter().map(focus_rule).collect();
        format!(r#"<ul class="ag-focus-rule-list">{items}</ul>"#)
    };

    let items = if v.viewer.items.is_empty() {
        collection_note(s.state, "No focused threads right now.").unwrap_or_default()
    } else {
        let rows: String = v
            .viewer
            .items
            .iter()
            .map(|it| focus_item(it, s.now))
            .collect();
        format!(r#"<ul class="ag-ledger-list">{rows}</ul>"#)
    };

    format!(
        r#"<div class="ag-ledger ag-focus">{head}
  <section class="ag-focus-rules ag-key-private" aria-labelledby="ag-focus-rules-title">
    <h2 class="eyebrow ag-eyebrow" id="ag-focus-rules-title">Your rules</h2>
    {rules}
  </section>
  <section class="ag-focus-threads" aria-labelledby="ag-focus-threads-title"><h2 class="eyebrow ag-eyebrow" id="ag-focus-threads-title">What your focus surfaces</h2>{items}</section>
</div>"#,
        head = ledger_head(
            "Focus",
            "Only you can see these rules. Focus changes your view, never the shared category.",
            &meta,
        ),
        rules = rules,
        items = items,
    )
}

fn focus_level_word(level: CategoryFocusLevelVM) -> &'static str {
    match level {
        CategoryFocusLevelVM::None => "No focus",
        CategoryFocusLevelVM::Priority => "Priority",
        CategoryFocusLevelVM::Follow => "Follow",
        CategoryFocusLevelVM::Mute => "Mute",
    }
}

fn focus_rule(r: &FocusRuleVM) -> String {
    let option = |value: &str, label: &str, level: CategoryFocusLevelVM| {
        format!(
            r#"<option value="{value}"{selected}>{label}</option>"#,
            selected = if level == r.level { " selected" } else { "" },
        )
    };
    let options = [
        option("none", "No focus", CategoryFocusLevelVM::None),
        option("priority", "Priority", CategoryFocusLevelVM::Priority),
        option("follow", "Follow", CategoryFocusLevelVM::Follow),
        option("mute", "Mute", CategoryFocusLevelVM::Mute),
    ]
    .join("");
    let (label, class) = action_label(&r.submit.label_kind);
    format!(
        r#"<li class="ag-focus-rule ag-key-private"><span class="ag-focus-rule__cat">{name}</span>{marker}<form class="ag-form ag-focus-rule__form" method="post" action="{action}">{hidden}<select name="level" aria-label="Focus rule for {name}">{options}</select><button class="{class}" type="submit">{label}</button></form></li>"#,
        name = t(&r.category.category.name),
        marker = private_marker("focus", focus_level_word(r.level)),
        action = o(&r.submit.action),
        hidden = hidden_inputs(&r.submit.csrf.0, &r.submit.fields),
        options = options,
        class = class,
        label = label,
    )
}

fn focus_reason(reason: CategoryFocusReasonVM) -> &'static str {
    match reason {
        CategoryFocusReasonVM::CategoryPriority => "Shown by category priority",
        CategoryFocusReasonVM::CategoryFollow => "Shown by category follow",
        CategoryFocusReasonVM::ThreadWatchOverride => "Your thread watch overrides the category",
        CategoryFocusReasonVM::ThreadFollowOverride => "Your thread follow overrides the category",
    }
}

fn focus_item(it: &FocusItemVM, now: i64) -> String {
    let s = &it.shared;
    let mut chips = String::from(kind_chip(s.kind));
    if s.kind == ThreadKind::Question {
        chips.push_str(&answer_state_chip(s.answer_state));
    }
    let mut marks = private_marker("reason", focus_reason(it.reason));
    if it.category_level != CategoryFocusLevelVM::None {
        marks.push_str(&private_marker(
            "focus",
            focus_level_word(it.category_level),
        ));
    }
    marks.push_str(&follow_marker(it.thread_level));
    let href = it
        .viewer
        .resume_href
        .as_ref()
        .map(o)
        .unwrap_or_else(|| escape(&thread_href(&s.id)));
    if let (Some(unread), Some(_)) = (it.viewer.unread_count, it.viewer.resume_href.as_ref()) {
        if unread > 0 {
            marks.push_str(&private_marker(
                "unread",
                &format!("Continue · {unread} new"),
            ));
        }
    }
    format!(
        r#"<li class="ag-ledger-item ag-key-shared">
  <div class="ag-row__chips">{chips}</div>
  <a class="ag-row__title" href="{href}">{title}</a>
  <p class="ag-row__by">{monogram} <span class="ag-row__author">{author}</span> · latest {time}</p>
  <p class="ag-ledger-item__mine ag-key-private">{marks}</p>
</li>"#,
        chips = chips,
        href = href,
        title = t(&s.title),
        monogram = monogram(&s.author_display.0),
        author = t(&s.author_display),
        time = time_el(s.last_at, now),
        marks = marks,
    )
}

// ===========================================================================
// Activity — durable subject-scoped record (not a delivery receipt).
// ===========================================================================

pub fn activity(v: &ActivityView) -> String {
    shell::page(&v.chrome, &activity_main(v))
}

fn activity_main(v: &ActivityView) -> String {
    let s = &v.shared;
    let tabs = activity_tabs(s);
    let meta = format!(
        "Page bound {} · durable record of application events, not a delivery receipt",
        s.visible_bound,
    );
    let mark = v
        .viewer
        .mark_page_read
        .as_ref()
        .map(|a| format!(r#"<div class="ag-ledger-actions">{}</div>"#, form_action(a)))
        .unwrap_or_default();
    let body = if v.viewer.items.is_empty() {
        collection_note(s.state, "No activity in this view yet.").unwrap_or_default()
    } else {
        let rows: String = v
            .viewer
            .items
            .iter()
            .map(|it| activity_item(it, s.now))
            .collect();
        format!(
            r#"<ul class="ag-activity-list">{rows}</ul>{page}"#,
            page = pagination(&v.viewer.pagination),
        )
    };
    format!(
        r#"<div class="ag-ledger ag-activity">{head}{tabs}{mark}{body}</div>"#,
        head = ledger_head(
            "Activity",
            "Only you can see your activity. Each row is reauthorized when shown.",
            &meta,
        ),
        tabs = tabs,
        mark = mark,
        body = body,
    )
}

fn activity_tabs(s: &ActivityShared) -> String {
    let state_tabs: String = s
        .read_scope_links
        .iter()
        .map(|entry| {
            let active = entry.scope == s.read_scope;
            format!(
                r#"<a class="tab{active}"{current} href="{href}">{label}</a>"#,
                active = if active { " is-active" } else { "" },
                current = if active {
                    r#" aria-current="page""#
                } else {
                    ""
                },
                href = o(&entry.link.href),
                label = t(&entry.link.label),
            )
        })
        .collect();
    let filter_tabs: String = s
        .filter_links
        .iter()
        .map(|entry| {
            let active = entry.filter == s.active_filter;
            format!(
                r#"<a class="tab{active}"{current} href="{href}">{label}</a>"#,
                active = if active { " is-active" } else { "" },
                current = if active {
                    r#" aria-current="page""#
                } else {
                    ""
                },
                href = o(&entry.link.href),
                label = t(&entry.link.label),
            )
        })
        .collect();
    format!(
        r#"<div class="ag-activity-tabs"><nav class="tabs" aria-label="Activity state">{state_tabs}</nav><nav class="tabs ag-activity-reasons" aria-label="Activity reason">{filter_tabs}</nav></div>"#
    )
}

fn activity_kind_word(kind: ActivityKindVM) -> &'static str {
    match kind {
        ActivityKindVM::PostCreated => "New post",
        ActivityKindVM::AnswerAccepted => "Answer accepted",
    }
}

fn activity_reason_word(reason: ActivityReasonVM) -> &'static str {
    match reason {
        ActivityReasonVM::Mention => "Mentioned you",
        ActivityReasonVM::Reply => "Replied to you",
        ActivityReasonVM::Following => "In a thread you follow",
        ActivityReasonVM::Answer => "Answer activity",
    }
}

fn activity_item(it: &ActivityItemVM, now: i64) -> String {
    let s = &it.shared;
    let vr = &it.viewer;
    let read_marker = if vr.read {
        private_marker("read", "Read")
    } else {
        private_marker("unread", "Unread")
    };
    format!(
        r#"<li class="ag-activity-row ag-key-shared">
  <div class="ag-activity-main">
    <p class="ag-activity-meta"><span class="badge ag-chip-shared">{kind}</span> {reason} · {time}</p>
    <form class="ag-activity-open" method="post" action="{open_action}">{open_hidden}<input type="hidden" name="next" value="{exact_target}"><button class="ag-row__title" type="submit">{title}</button></form>
    <p class="ag-activity-snippet">{body}</p>
    <p class="ag-activity-actor muted">{monogram} <span class="ag-row__author">{actor}</span></p>
  </div>
  <div class="ag-activity-controls ag-key-private">{read_marker}{toggle}</div>
</li>"#,
        kind = escape(activity_kind_word(s.kind)),
        reason = private_marker("reason", activity_reason_word(vr.reason)),
        time = time_el(s.created_at, now),
        open_action = o(&vr.open.submit.action),
        open_hidden = hidden_inputs(&vr.open.submit.csrf.0, &vr.open.submit.fields),
        exact_target = o(&vr.open.exact_target),
        title = t(&s.thread_title),
        body = t(&s.post_excerpt),
        monogram = monogram(&s.actor_display.0),
        actor = t(&s.actor_display),
        read_marker = read_marker,
        toggle = form_action(&vr.toggle_read),
    )
}

// ===========================================================================
// Bookmarks — subject-owned queue with private notes and reminders.
// ===========================================================================

pub fn bookmarks(v: &BookmarksView) -> String {
    shell::page(&v.chrome, &bookmarks_main(v))
}

fn bookmarks_main(v: &BookmarksView) -> String {
    let s = &v.shared;
    let st = s.active_state;
    let tabs = ledger_tabs(
        "state",
        "Bookmark filter",
        &[
            ("all", "All", st == BookmarkStateVM::All),
            ("due", "Due", st == BookmarkStateVM::Due),
            ("scheduled", "Scheduled", st == BookmarkStateVM::Scheduled),
        ],
    );
    let meta = format!(
        "Page bound {} · private bookmarks and notes",
        s.visible_bound
    );
    let body = if v.viewer.items.is_empty() {
        collection_note(s.state, "No bookmarks in this view.").unwrap_or_default()
    } else {
        let rows: String = v
            .viewer
            .items
            .iter()
            .map(|it| bookmark_item(it, s.now))
            .collect();
        format!(
            r#"<ul class="ag-bookmark-list">{rows}</ul>{page}"#,
            page = pagination(&v.viewer.pagination),
        )
    };
    format!(
        r#"<div class="ag-ledger ag-bookmarks">{head}{tabs}{body}</div>"#,
        head = ledger_head(
            "Bookmarks",
            "Only you can see your bookmarks and notes.",
            &meta,
        ),
        tabs = tabs,
        body = body,
    )
}

fn bookmark_item(it: &BookmarkItemVM, now: i64) -> String {
    let s = &it.shared;
    let vr = &it.viewer;
    let note = if vr.note.0.trim().is_empty() {
        String::new()
    } else {
        format!(
            r#"<p class="ag-bookmark-note ag-key-private">{}</p>"#,
            t(&vr.note)
        )
    };
    let remind = match vr.remind_at {
        Some(at) => private_marker("remind", &format!("Reminder {}", super::fmt_ts(at))),
        None => String::new(),
    };
    let mut actions = String::new();
    actions.push_str(&form_action_opt(&vr.done));
    actions.push_str(&form_action_opt(&vr.snooze_tomorrow));
    actions.push_str(&form_action_opt(&vr.snooze_week));
    actions.push_str(&link_action(&vr.edit));
    actions.push_str(&form_action(&vr.remove));
    format!(
        r#"<li class="ag-bookmark-row ag-key-shared">
  <div class="ag-bookmark-body">
    <a class="ag-row__title" href="{href}">{title}</a>
    <p class="ag-row__by">{monogram} <span class="ag-row__author">{author}</span> · {time}</p>
    <p class="ag-bookmark-snippet">{body}</p>
    <div class="ag-bookmark-private ag-key-private">{note}{remind}</div>
  </div>
  <div class="ag-bookmark-actions">{actions}</div>
</li>"#,
        href = o(&s.exact_post_href),
        title = t(&s.thread_title),
        monogram = monogram(&s.post_author_display.0),
        author = t(&s.post_author_display),
        time = time_el(s.post_created_at, now),
        body = t(&s.post_excerpt),
        note = note,
        remind = remind,
        actions = actions,
    )
}

pub fn bookmark_edit(v: &BookmarkEditView) -> String {
    shell::page(&v.chrome, &bookmark_edit_main(v))
}

fn bookmark_edit_main(v: &BookmarkEditView) -> String {
    let s = &v.shared;
    let vs = &v.viewer;
    let reminder = s
        .current_reminder_at
        .map(super::fmt_ts)
        .unwrap_or_else(|| "No reminder set".to_string());
    let option = |value: &str, label: &str, choice: BookmarkReminderChoiceVM| -> String {
        format!(
            r#"<option value="{value}"{selected}>{label}</option>"#,
            selected = if choice == vs.selected_reminder {
                " selected"
            } else {
                ""
            },
            label = escape(label),
        )
    };
    let options = format!(
        "{}{}{}{}{}",
        option(
            "keep",
            &format!("Keep current — {reminder}"),
            BookmarkReminderChoiceVM::Keep
        ),
        option("none", "No reminder", BookmarkReminderChoiceVM::None),
        option(
            "tomorrow",
            "24 hours from now",
            BookmarkReminderChoiceVM::Tomorrow
        ),
        option("week", "7 days from now", BookmarkReminderChoiceVM::Week),
        option(
            "custom",
            "Custom UTC time",
            BookmarkReminderChoiceVM::Custom
        ),
    );
    format!(
        r#"<div class="ag-bookmark-edit">
  {crumb}
  <header class="pagehead"><div class="ag-head-tools__lead">{eyebrow}<h1 class="ag-head__title">Edit bookmark</h1><p class="muted">{title}</p></div></header>
  <section class="card ag-bookmark-editor ag-key-private">
    <form class="ag-form" method="post" action="{action}">{hidden}
      <label class="ag-form__label" for="bookmark-note">Private note</label>
      <textarea id="bookmark-note" name="note" rows="4" maxlength="{max_note}" placeholder="Why did you save this?">{note}</textarea>
      <p class="muted">Plain text, visible only to you. Up to {max_note} characters.</p>
      <label class="ag-form__label" for="bookmark-reminder">Reminder</label>
      <select id="bookmark-reminder" name="reminder_action">{options}</select>
      <label class="ag-form__label" for="bookmark-custom">Custom time <span class="muted">(UTC)</span></label>
      <input id="bookmark-custom" type="datetime-local" name="custom_time" value="{custom}">
      <p class="muted">Used only for “Custom UTC time”; it must be in the future and within 10 years.</p>
      <aside class="ag-bookmark-notice" role="note">This reminder appears in your Forum Due queue. It does not send email or push.</aside>
      <div class="form-actions"><a class="btn btn-secondary" href="{cancel}">Cancel</a><button class="btn btn-primary" type="submit">Save bookmark</button></div>
    </form>
  </section>
</div>"#,
        crumb = crumbs(&[
            ("Home", Some("/")),
            ("Bookmarks", Some("/bookmarks")),
            ("Edit", None)
        ]),
        eyebrow = eyebrow("Civic Ledger"),
        title = t(&s.thread_title),
        action = o(&vs.save.action),
        hidden = hidden_inputs(&vs.save.csrf.0, &vs.save.fields),
        max_note = s.note_max_chars,
        note = t(&vs.note),
        options = options,
        custom = t(&vs.custom_time),
        cancel = o(&s.exact_post_href),
    )
}
