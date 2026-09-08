//! Shared forum truth — the discussion rooms.
//!
//! Renders categories, original posts, accepted answers, replies, and the compose flow. Every
//! value arrives already authorized and typed; this module
//! only formats and escapes it. Sort/scope/subscription switches use exact handler-issued links so
//! the shell's `data-sort-tab` swap script is a pure enhancement over working no-JS navigation.

use crate::view_model::{
    CategoryFocusFormVM, CategoryFocusLevelVM, CategoryPageShared, CategoryPageViewerState,
    CategoryVM, CategoryView, ComposeMode, ComposeShared, ComposeView, ComposeViewerState,
    HomeShared, HomeView, ReplyFormVM, SubscriptionFormVM, SummaryStateVM, ThreadFollowLevelVM,
    ThreadKind, ThreadListControlsVM, ThreadOrder, ThreadRowVM, ThreadScope, ThreadShared,
    ThreadView, ThreadViewerState,
};

use super::shell;
use super::{
    answer_dais, answer_state_chip, category_href, collection_note, crumbs, escape, eyebrow,
    form_action_opt, hidden_inputs, kind_chip, link_action_opt, o, pagination, post, t,
    thread_list, thread_row, time_el,
};
use crate::view_model::AdminThreadToolbarVM;

// ===========================================================================
// Sort / scope controls — the exact `?sort=`/`?status=` wire grammar, rendered as relative
// hrefs (path-agnostic, so `/`, `/questions`, and `/c/{id}` all reuse the same control) and
// carrying the `data-sort-tab` / `data-thread-controls` enhancement hooks the shell keys off.
// ===========================================================================

fn order_label(order: ThreadOrder) -> &'static str {
    match order {
        ThreadOrder::Latest => "Latest",
        ThreadOrder::Top => "Top",
        ThreadOrder::Hot => "Hot",
    }
}

fn order_key(order: ThreadOrder) -> &'static str {
    match order {
        ThreadOrder::Latest => "latest",
        ThreadOrder::Top => "top",
        ThreadOrder::Hot => "hot",
    }
}

fn scope_label(scope: ThreadScope) -> &'static str {
    match scope {
        ThreadScope::Any => "All",
        ThreadScope::Questions => "Questions",
        ThreadScope::Answered => "Answered",
        ThreadScope::Unanswered => "Unanswered",
    }
}

fn thread_controls(c: &ThreadListControlsVM) -> String {
    let sort_tabs: String = c
        .order_links
        .iter()
        .map(|link| {
            let active = link.order == c.active_order;
            format!(
                r#"<a class="tab{cls}"{current} data-sort-tab="{key}" href="{href}">{label}</a>"#,
                cls = if active { " is-active" } else { "" },
                current = if active {
                    r#" aria-current="page""#
                } else {
                    ""
                },
                key = order_key(link.order),
                href = o(&link.href),
                label = order_label(link.order),
            )
        })
        .collect();
    let sort_nav =
        format!(r#"<nav class="tabs sort-tabs" aria-label="Sort threads">{sort_tabs}</nav>"#);
    let status_nav = if c.scope_links.is_empty() {
        String::new()
    } else {
        let tabs: String = c
            .scope_links
            .iter()
            .map(|link| {
                let active = link.scope == c.active_scope;
                format!(
                    r#"<a class="tab{cls}"{current} href="{href}">{label}</a>"#,
                    cls = if active { " is-active" } else { "" },
                    current = if active {
                        r#" aria-current="page""#
                    } else {
                        ""
                    },
                    href = o(&link.href),
                    label = scope_label(link.scope),
                )
            })
            .collect();
        format!(
            r#"<nav class="tabs answer-tabs" aria-label="Filter by answer status">{tabs}</nav>"#
        )
    };
    let subscribed = c
        .subscribed_toggle
        .as_ref()
        .map(|link| {
            format!(
                r#"<a class="btn btn-secondary btn-sm ag-key-private{active}" href="{href}"{current}>{label}</a>"#,
                active = if c.subscribed_only { " is-active" } else { "" },
                current = if c.subscribed_only {
                    r#" aria-current="page""#
                } else {
                    ""
                },
                href = o(&link.href),
                label = t(&link.label),
            )
        })
        .unwrap_or_default();
    format!(
        r#"<div class="thread-controls" data-thread-controls><div class="thread-controls__tabs">{sort_nav}{status_nav}</div>{subscribed}</div>"#,
    )
}

fn scope_heading(scope: ThreadScope, subscribed_only: bool) -> String {
    let base = match scope {
        ThreadScope::Any => "All discussions",
        ThreadScope::Questions => "Questions",
        ThreadScope::Answered => "Answered questions",
        ThreadScope::Unanswered => "Questions that need an answer",
    };
    if subscribed_only {
        format!("{base} you subscribe to")
    } else {
        base.to_string()
    }
}

fn rows_html(rows: &[ThreadRowVM], now: i64) -> String {
    rows.iter()
        .map(|row| thread_row(&row.shared, &row.viewer, now))
        .collect()
}

// ===========================================================================
// Home — category navigation + discussion feed.
// ===========================================================================

pub fn home(v: &HomeView) -> String {
    shell::page(&v.chrome, &home_main(&v.shared, &v.rows))
}

fn home_main(s: &HomeShared, thread_rows: &[ThreadRowVM]) -> String {
    let controls = thread_controls(&s.controls);
    let rows = rows_html(thread_rows, s.now);
    let shown = match thread_rows.len() {
        1 => "1 discussion".to_string(),
        count => format!("{count} discussions"),
    };
    let list = thread_list(
        &rows,
        collection_note(s.state, "No threads here yet. Start the first one."),
    );
    let questions = s
        .controls
        .questions
        .as_ref()
        .map(|link| {
            format!(
                r#"<a class="btn btn-secondary ag-cta" href="{href}">{label}</a>"#,
                href = o(&link.href),
                label = t(&link.label),
            )
        })
        .unwrap_or_default();
    format!(
        r#"<div class="ag-home">
  <section class="ag-home__feed" id="threads" aria-labelledby="ag-home-title">
    <div class="pagehead ag-head-tools">
      <div class="ag-head-tools__lead">
        {eyebrow}
        <h1 class="ag-head__title" id="ag-home-title">{heading}</h1>
        <p class="muted ag-feed__bound">{shown} in this view</p>
      </div>
    </div>
    {controls}
    {list}
  </section>
  <aside class="ag-home__rail">
    {terraces}
    {ledgers}
    {questions}
    <a class="btn btn-primary ag-cta" href="/new">Start a new thread</a>
  </aside>
</div>"#,
        terraces = category_terraces(&s.categories),
        ledgers = ledger_nav(),
        questions = questions,
        eyebrow = eyebrow("Discussions"),
        heading = escape(&scope_heading(
            s.controls.active_scope,
            s.controls.subscribed_only
        )),
        shown = shown,
        controls = controls,
        list = list,
    )
}

/// Category navigation. Each entry states its discussion kind as shared truth.
fn category_terraces(cats: &[CategoryVM]) -> String {
    if cats.is_empty() {
        return String::new();
    }
    let mut items = String::new();
    for c in cats {
        items.push_str(&format!(
            r#"<li class="ag-terrace"><a class="ag-terrace__link ag-key-shared" href="{href}"><span class="ag-terrace__name">{name}</span>{kind}</a></li>"#,
            href = escape(&category_href(&c.category.id)),
            name = t(&c.category.name),
            kind = kind_chip(c.kind),
        ));
    }
    format!(
        r#"<nav class="ag-terraces" aria-label="Categories">{eyebrow}<ul class="ag-terraces__list">{items}</ul></nav>"#,
        eyebrow = eyebrow("Categories"),
    )
}

/// Entry points to private personal views.
fn ledger_nav() -> String {
    format!(
        r#"<nav class="ag-ledgers" aria-label="My activity">{eyebrow}<ul class="ag-ledgers__list">
    <li><a class="ag-ledger-link ag-key-private" href="/for-you">For You</a></li>
    <li><a class="ag-ledger-link ag-key-private" href="/focus">Reading priorities</a></li>
    <li><a class="ag-ledger-link ag-key-private" href="/activity">Activity</a></li>
    <li><a class="ag-ledger-link ag-key-private" href="/bookmarks">Bookmarks</a></li>
  </ul></nav>"#,
        eyebrow = eyebrow("My activity"),
    )
}

// ===========================================================================
// Category page — one terrace's threads plus the private Focus control.
// ===========================================================================

pub fn category(v: &CategoryView) -> String {
    shell::page(&v.chrome, &category_main(&v.shared, &v.rows, &v.viewer))
}

fn category_main(
    s: &CategoryPageShared,
    thread_rows: &[ThreadRowVM],
    vs: &CategoryPageViewerState,
) -> String {
    let controls = thread_controls(&s.controls);
    let rows = rows_html(thread_rows, s.now);
    let list = thread_list(
        &rows,
        collection_note(s.state, "No threads in this category yet."),
    );
    let name = t(&s.category.category.name);
    let crumb = crumbs(&[("Home", Some("/")), (&s.category.category.name.0, None)]);
    let focus = vs
        .focus
        .as_ref()
        .map(category_focus_form)
        .unwrap_or_default();
    format!(
        r#"<div class="ag-category">
  {crumb}
  <header class="pagehead ag-head-tools ag-key-shared">
    <div class="ag-head-tools__lead">
      <div class="ag-thread__chips">{kind}</div>
      <h1 class="ag-head__title">{name}</h1>
      <p class="muted ag-feed__bound">{shown} discussions in this view</p>
    </div>
  </header>
  {focus}
  {controls}
  {list}
</div>"#,
        crumb = crumb,
        kind = kind_chip(s.category.kind),
        name = name,
        shown = thread_rows.len(),
        focus = focus,
        controls = controls,
        list = list,
    )
}

fn focus_level_options(selected: CategoryFocusLevelVM) -> String {
    let opt = |val: &str, label: &str, this: CategoryFocusLevelVM| {
        format!(
            r#"<option value="{val}"{sel}>{label}</option>"#,
            val = val,
            sel = if this == selected { " selected" } else { "" },
            label = label,
        )
    };
    format!(
        "{}{}{}{}",
        opt("none", "No focus", CategoryFocusLevelVM::None),
        opt("priority", "Priority", CategoryFocusLevelVM::Priority),
        opt("follow", "Follow", CategoryFocusLevelVM::Follow),
        opt("mute", "Mute", CategoryFocusLevelVM::Mute),
    )
}

fn focus_level_label(level: CategoryFocusLevelVM) -> &'static str {
    match level {
        CategoryFocusLevelVM::None => "No focus",
        CategoryFocusLevelVM::Priority => "Priority",
        CategoryFocusLevelVM::Follow => "Follow",
        CategoryFocusLevelVM::Mute => "Mute",
    }
}

/// The private per-category Focus form. Dashed keyline; explains that Focus changes only the
/// current subject's view, never the shared category.
fn category_focus_form(f: &CategoryFocusFormVM) -> String {
    let saved = if f.saved {
        format!(
            r#"<p class="ag-form__status" role="status">Saved: {}.</p>"#,
            focus_level_label(f.selected),
        )
    } else {
        String::new()
    };
    format!(
        r#"<form class="ag-form ag-focus-form ag-key-private" id="category-focus-heading" method="post" action="{action}">{hidden}
  <label class="ag-form__label" for="ag-focus-level">Reading priority for this category</label>
  <div class="ag-form__row">
    <select id="ag-focus-level" name="level">{options}</select>
    <button class="btn btn-secondary btn-sm" type="submit">Apply</button>
  </div>
  {saved}
  <p class="ag-mark-note muted">This preference is private and changes only what appears in your reading view.</p>
</form>"#,
        action = o(&f.submit.action),
        hidden = hidden_inputs(&f.submit.csrf.0, &f.submit.fields),
        options = focus_level_options(f.selected),
        saved = saved,
    )
}

// ===========================================================================
// Thread page — original post, accepted answer, replies.
// ===========================================================================

pub fn thread(v: &ThreadView) -> String {
    shell::page(&v.chrome, &thread_main(v))
}

fn thread_main(v: &ThreadView) -> String {
    let s = &v.shared;
    let now = v.now;

    // Breadcrumb: Home / [category] / title. `cat_href` outlives the slice only where used.
    let cat_href;
    let mut segs: Vec<(&str, Option<&str>)> = vec![("Home", Some("/"))];
    if let Some(c) = &s.category {
        cat_href = category_href(&c.id);
        segs.push((c.name.0.as_str(), Some(cat_href.as_str())));
    }
    segs.push((s.title.0.as_str(), None));
    let crumb = crumbs(&segs);

    let spine = reading_spine(v);
    let spined = if spine.is_empty() {
        ""
    } else {
        " ag-thread--spined"
    };

    let floor = format!(
        r#"<section class="ag-floor" aria-labelledby="ag-floor-title"><h2 class="eyebrow ag-eyebrow" id="ag-floor-title">Original post</h2>{post}</section>"#,
        post = post(&v.op, now),
    );
    let dais = v
        .dais
        .as_ref()
        .map(|d| answer_dais(d, now))
        .unwrap_or_default();

    let accepted_id = v.dais.as_ref().map(|dais| &dais.post.id);
    let chronological: Vec<_> = v
        .replies
        .iter()
        .filter(|reply| accepted_id != Some(&reply.id))
        .collect();

    let bounds_start = if !v.pagination.at_start {
        r#"<div class="ag-steps__bound ag-steps__bound--start" role="separator"><span>Earlier replies on previous page</span></div>"#
    } else {
        ""
    };
    let bounds_end = if !v.pagination.at_end {
        r#"<div class="ag-steps__bound ag-steps__bound--end" role="separator"><span>More replies on next page</span></div>"#
    } else {
        ""
    };

    let replies = if chronological.is_empty() {
        collection_note(
            crate::view_model::CollectionState::ReadyEmpty,
            "No replies yet.",
        )
        .unwrap_or_default()
    } else {
        chronological
            .into_iter()
            .map(|reply| post(reply, now))
            .collect::<String>()
    };
    let read_sentinel = if v.reading.mark_page_read.is_some() {
        r#"<span class="ag-read-progress__sentinel" data-thread-read-sentinel aria-hidden="true"></span>"#
    } else {
        ""
    };
    let steps = format!(
        r#"<section class="ag-steps" aria-labelledby="ag-steps-title"><h2 class="eyebrow ag-eyebrow" id="ag-steps-title">Replies</h2>{bounds_start}{replies}{bounds_end}{read_sentinel}<span class="ag-thread-latest-anchor" id="thread-latest" tabindex="-1"></span></section>"#,
        bounds_start = bounds_start,
        replies = replies,
        bounds_end = bounds_end,
        read_sentinel = read_sentinel,
    );

    let admin = v
        .admin
        .as_ref()
        .map(admin_thread_toolbar)
        .unwrap_or_default();

    let controls = reading_controls(v);

    format!(
        r#"<article class="ag-thread{spined}">
  {crumb}
  {head}
  <div class="ag-thread__body">
    {spine}
    <div class="ag-thread__col">
      {admin}
      {summary}
      {floor}
      {dais}
      {steps}
      {controls}
      {reply}
    </div>
  </div>
</article>"#,
        spined = spined,
        crumb = crumb,
        head = thread_head(s, &v.viewer, now),
        spine = spine,
        admin = admin,
        summary = summary_block(&v.summary),
        floor = floor,
        dais = dais,
        steps = steps,
        controls = controls,
        reply = reply_form_block(&v.reply_form, s.kind == ThreadKind::Question),
    )
}

fn thread_head(s: &ThreadShared, viewer: &ThreadViewerState, now: i64) -> String {
    let mut chips = String::new();
    chips.push_str(kind_chip(s.kind));
    if s.kind == ThreadKind::Question {
        chips.push_str(&answer_state_chip(s.answer_state));
    }
    if s.pinned {
        chips.push_str(
            r#"<span class="badge ag-chip-shared ag-flag ag-flag--pinned">Pinned</span>"#,
        );
    }
    if s.locked {
        chips.push_str(
            r#"<span class="badge ag-chip-shared ag-flag ag-flag--locked">Locked</span>"#,
        );
    }

    // Private viewer controls (dashed): subscription, own edit/delete, invalid-solution repair.
    let mut viewer_controls = String::new();
    if let Some(sub) = &viewer.subscription {
        viewer_controls.push_str(&subscription_form(sub));
    }
    let mut owner_actions = String::new();
    owner_actions.push_str(&link_action_opt(&viewer.edit));
    owner_actions.push_str(&link_action_opt(&viewer.delete_review));
    if !owner_actions.is_empty() {
        viewer_controls.push_str(&format!(
            r#"<div class="ag-owner-actions">{owner_actions}</div>"#
        ));
    }
    if let Some(clear) = &viewer.clear_invalid_solution {
        viewer_controls.push_str(&format!(
            r#"<div class="ag-repair ag-key-private" role="note"><p class="ag-mark-note muted">A previously accepted answer is no longer valid. Only you can clear this private repair state.</p>{action}</div>"#,
            action = super::form_action(clear),
        ));
    }
    let viewer_block = if viewer_controls.is_empty() {
        String::new()
    } else {
        format!(r#"<div class="ag-thread__viewer ag-key-private">{viewer_controls}</div>"#)
    };

    let replies = s
        .post_count
        .map(|count| format!(" · {}", escape(&super::replies_label(count))))
        .unwrap_or_default();
    format!(
        r#"<header class="ag-thread__head ag-key-shared">
  <div class="ag-thread__chips">{chips}</div>
  <h1 class="ag-thread__title">{title}</h1>
  <p class="ag-thread__meta">Started by <span class="ag-thread__author">{author}</span> · {time}{replies}</p>
  {viewer_block}
</header>"#,
        chips = chips,
        title = t(&s.title),
        author = t(&s.author_display),
        time = time_el(s.created_at, now),
        replies = replies,
        viewer_block = viewer_block,
    )
}

fn follow_level_options(selected: ThreadFollowLevelVM) -> String {
    let opt = |val: &str, label: &str, this: ThreadFollowLevelVM| {
        format!(
            r#"<option value="{val}"{sel}>{label}</option>"#,
            val = val,
            sel = if this == selected { " selected" } else { "" },
            label = label,
        )
    };
    format!(
        "{}{}{}{}",
        opt("none", "Not following", ThreadFollowLevelVM::None),
        opt("watch", "Add to reading list", ThreadFollowLevelVM::Watch),
        opt("follow", "Prioritize", ThreadFollowLevelVM::Follow),
        opt("mute", "Mute", ThreadFollowLevelVM::Mute),
    )
}

/// The private subscription form. Dashed keyline; explicit that it controls the viewer's own
/// catch-up, and does NOT promise notification delivery.
fn subscription_form(s: &SubscriptionFormVM) -> String {
    format!(
        r#"<form class="ag-form ag-subscribe" method="post" action="{action}">{hidden}
  <label class="ag-form__label" for="ag-sub-level">Reading preference</label>
  <div class="ag-form__row">
    <select id="ag-sub-level" name="level">{options}</select>
    <button class="btn btn-secondary btn-sm" type="submit">Update</button>
  </div>
  <p class="ag-mark-note muted">Private: this changes your reading view. It does not send notifications.</p>
</form>"#,
        action = o(&s.submit.action),
        hidden = hidden_inputs(&s.submit.csrf.0, &s.submit.fields),
        options = follow_level_options(s.selected),
    )
}

/// The vertical reading spine for Question threads. Desktop: sticky aside. Mobile: inline.
/// Marks Question, accepted answer dais, resume/unread state using civic geometry.
fn reading_spine(v: &ThreadView) -> String {
    if v.shared.kind != ThreadKind::Question {
        return String::new();
    }

    let dais_section = if v.dais.is_some() {
        r##"<div class="ag-spine__section ag-spine__section--dais"><span class="ag-spine__mark">◆</span><a class="ag-spine__link" href="#ag-dais-title">Accepted Answer</a></div>"##
    } else {
        ""
    };

    let resume_section = if v.reading.resume_href.is_some() || v.reading.first_unread_href.is_some()
    {
        let href = v
            .reading
            .resume_href
            .as_ref()
            .or(v.reading.first_unread_href.as_ref());
        let label = if v.reading.resume_href.is_some() {
            "Continue reading"
        } else {
            "Start reading"
        };
        format!(
            r##"<div class="ag-spine__section ag-spine__section--private"><span class="ag-spine__mark">→</span><a class="ag-spine__link" href="{href}">{label}</a></div>"##,
            href = o(href.unwrap()),
            label = label,
        )
    } else {
        String::new()
    };

    let unread_indicator = if let Some(n) = v.reading.unread_count {
        if n > 0 {
            let label = if n == 1 {
                "1 unread".to_string()
            } else {
                format!("{n} unread")
            };
            format!(
                r##"<div class="ag-spine__section ag-spine__section--private"><span class="ag-spine__mark">•</span><span class="ag-spine__text">{label}</span></div>"##,
                label = escape(&label),
            )
        } else if v.reading.started {
            r##"<div class="ag-spine__section ag-spine__section--private"><span class="ag-spine__mark">✓</span><span class="ag-spine__text">Caught up</span></div>"##.to_string()
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    format!(
        r##"<aside class="ag-reading-spine ag-key-shared" aria-label="Reading guide">
  <div class="ag-spine__section"><span class="ag-spine__mark">○</span><a class="ag-spine__link" href="#ag-floor-title">Question</a></div>
  {dais_section}
  {resume_section}
  {unread_indicator}
</aside>"##,
        dais_section = dais_section,
        resume_section = resume_section,
        unread_indicator = unread_indicator,
    )
}

/// Consolidated reading controls: resume links, unread status, mark-page-read, pagination.
/// Jump control is provided by the pagination() helper. Placed after steps, before reply form.
fn reading_controls(v: &ThreadView) -> String {
    let mut parts = String::new();

    // Resume/start reading link
    if let Some(h) = &v.reading.resume_href {
        parts.push_str(&format!(
            r#"<a class="ag-mark ag-mark--resume" href="{}">Continue reading</a>"#,
            o(h),
        ));
    } else if let Some(h) = &v.reading.first_unread_href {
        parts.push_str(&format!(
            r#"<a class="ag-mark ag-mark--resume" href="{}">Start reading</a>"#,
            o(h),
        ));
    }

    // Unread count or caught-up status
    if let Some(n) = v.reading.unread_count {
        if n > 0 {
            let label = if n == 1 {
                "1 unread post".to_string()
            } else {
                format!("{n} unread posts")
            };
            parts.push_str(&super::private_marker("unread", &label));
        } else if v.reading.started {
            parts.push_str(&super::private_marker("caught-up", "Caught up"));
        }
    }

    // Mark page read form
    if let Some(action) = &v.reading.mark_page_read {
        parts.push_str(
            r#"<span class="ag-read-progress__status muted" data-thread-read-status role="status" aria-live="polite">Only posts shown on this page will be marked read.</span>"#,
        );
        parts.push_str(&format!(
            r#"<form class="inline-form" method="post" action="{action}" data-thread-read-form>{hidden}<button class="btn btn-secondary btn-sm" type="submit" data-thread-read-submit>Mark page read &amp; continue</button></form>"#,
            action = o(&action.action),
            hidden = hidden_inputs(&action.csrf.0, &action.fields),
        ));
    }

    // Pagination (includes built-in jump control)
    let pagination_html = pagination(&v.pagination);

    if parts.is_empty() && pagination_html.is_empty() {
        return String::new();
    }

    format!(
        r#"<div class="ag-reading-controls ag-key-private" role="region" aria-label="Reading controls" data-thread-read-progress>
  {parts}
  {pagination}
</div>"#,
        parts = parts,
        pagination = pagination_html,
    )
}

/// Page-local extractive summary. Server-rendered from the same page boundary used by JSON.
fn summary_block(s: &SummaryStateVM) -> String {
    match s {
        SummaryStateVM::Available(sv) => {
            let items: String = sv
                .sentences
                .iter()
                .map(|line| format!("<li>{}</li>", t(line)))
                .collect();
            format!(
                r#"<details class="ag-desk ag-summary">
  <summary class="ag-desk__summary">Summary of the replies shown here</summary>
  <p class="muted ag-desk__bound">Based on {posts} posts on this page · up to {bound} sentences. This may not represent the entire thread or consensus.</p>
  <ol class="ag-summary__list">{items}</ol>
</details>"#,
                posts = sv.source_post_count,
                bound = sv.sentence_bound,
                items = items,
            )
        }
        SummaryStateVM::Unavailable(_) => String::new(),
    }
}

fn reply_form_block(f: &ReplyFormVM, is_question: bool) -> String {
    match f {
        ReplyFormVM::Available {
            submit,
            body,
            quoted_post_id,
        } => {
            let (quote_hidden, quote_note) = match quoted_post_id {
                Some(q) => (
                    format!(
                        r#"<input type="hidden" name="quote_post_id" value="{}">"#,
                        o(q),
                    ),
                    format!(
                        r##"<p class="ag-reply-quote muted">Quoting <a href="#post-{}">a post above</a>.</p>"##,
                        o(q),
                    ),
                ),
                None => (String::new(), String::new()),
            };
            let label = if is_question {
                "Your answer"
            } else {
                "Your reply"
            };
            let submit_label = if is_question {
                "Post answer"
            } else {
                "Post reply"
            };
            format!(
                r#"<form class="ag-form ag-reply-form" id="reply" method="post" action="{action}">{hidden}{quote_hidden}
  {quote_note}
  <label class="ag-form__label" for="ag-reply-body">{label}</label>
  <textarea id="ag-reply-body" name="body" rows="6" required>{body}</textarea>
  <p class="ag-md-hint muted">Markdown is supported.</p>
  <div class="form-actions"><button class="btn btn-primary" type="submit">{submit}</button></div>
</form>"#,
                action = o(&submit.action),
                hidden = hidden_inputs(&submit.csrf.0, &submit.fields),
                quote_hidden = quote_hidden,
                quote_note = quote_note,
                label = label,
                body = t(body),
                submit = submit_label,
            )
        }
        ReplyFormVM::LockedNotice { message } => format!(
            r#"<div class="card pad ag-locked-notice" role="status"><p class="empty-title">This thread is locked</p><p class="muted">{}</p></div>"#,
            t(message),
        ),
        ReplyFormVM::UnavailableNotice { heading, message } => format!(
            r#"<div class="card pad ag-locked-notice" role="status"><p class="empty-title">{}</p><p class="muted">{}</p></div>"#,
            t(heading),
            t(message),
        ),
    }
}

/// The admin moderation toolbar for a thread (shared civic authority, solid keyline). Rendered
/// only when Codex supplied the descriptors (verified admin).
pub(crate) fn admin_thread_toolbar(a: &AdminThreadToolbarVM) -> String {
    let mut c = String::new();
    if let Some(move_thread) = &a.move_thread {
        let options: String = move_thread
            .categories
            .iter()
            .map(|category| {
                format!(
                    r#"<option value="{value}"{selected}>{name}</option>"#,
                    value = o(&category.id),
                    selected = if category.id == move_thread.selected_category {
                        " selected"
                    } else {
                        ""
                    },
                    name = t(&category.name),
                )
            })
            .collect();
        c.push_str(&format!(
            r#"<form class="inline-form ag-admin-move" method="post" action="{action}">{hidden}<select name="category" aria-label="Move to category" required>{options}</select><button class="btn btn-secondary btn-sm" type="submit">Move</button></form>"#,
            action = o(&move_thread.submit.action),
            hidden = hidden_inputs(
                &move_thread.submit.csrf.0,
                &move_thread.submit.fields
            ),
        ));
    }
    c.push_str(&form_action_opt(&a.lock));
    c.push_str(&form_action_opt(&a.pin));
    c.push_str(&link_action_opt(&a.delete_review));
    if c.is_empty() {
        return String::new();
    }
    format!(
        r#"<div class="ag-thread-toolbar ag-key-shared" role="group" aria-label="Moderation">{eyebrow}{c}</div>"#,
        eyebrow = eyebrow("Moderation"),
    )
}

// ===========================================================================
// Compose desk — new thread / edit thread / edit reply.
// ===========================================================================

pub fn compose(v: &ComposeView) -> String {
    shell::page(&v.chrome, &compose_main(&v.shared, &v.viewer))
}

fn compose_main(s: &ComposeShared, vs: &ComposeViewerState) -> String {
    let category_field = match s.mode {
        ComposeMode::NewThread => category_select(&s.categories, s.selected_category.as_ref()),
        ComposeMode::EditThread | ComposeMode::EditReply => String::new(),
    };
    let title_field = match s.mode {
        ComposeMode::NewThread | ComposeMode::EditThread => format!(
            r#"<label class="ag-form__label" for="ag-compose-title">Title</label>
  <input id="ag-compose-title" type="text" name="title" maxlength="200" value="{title}" required>"#,
            title = t(&vs.title),
        ),
        ComposeMode::EditReply => String::new(),
    };
    let quote_hidden = vs
        .quoted_post_id
        .as_ref()
        .map(|q| {
            format!(
                r#"<input type="hidden" name="quote_post_id" value="{}">"#,
                o(q)
            )
        })
        .unwrap_or_default();
    let submit_label = match s.mode {
        ComposeMode::NewThread => "Publish thread",
        ComposeMode::EditThread => "Save thread",
        ComposeMode::EditReply => "Save reply",
    };
    let similarity = if s.mode == ComposeMode::NewThread {
        r#"<aside class="ag-similar ag-key-shared" data-ag-similar data-candidate-bound="500" data-result-bound="3" data-threshold-bps="800" hidden aria-live="polite" aria-labelledby="ag-similar-title">
  <h2 class="eyebrow ag-eyebrow" id="ag-similar-title">Possible related discussions</h2>
  <p class="muted ag-desk__bound">Up to 3 heuristic matches from up to 500 recent thread digests, using an 8% similarity threshold. This is not duplicate proof.</p>
  <ol class="ag-similar__list" data-ag-similar-list></ol>
</aside>"#
    } else {
        ""
    };
    format!(
        r#"<div class="ag-compose">
  {crumb}
  <header class="pagehead"><div class="ag-head-tools__lead">{eyebrow}<h1 class="ag-head__title">{heading}</h1></div></header>
  <form class="ag-form ag-composer" method="post" action="{action}">{hidden}{quote_hidden}
  {category_field}
  {title_field}
  <label class="ag-form__label" for="ag-compose-body">Body</label>
  <textarea id="ag-compose-body" name="body" rows="12" required>{body}</textarea>
  <p class="ag-md-hint muted">Markdown is supported. Drafts are not saved automatically.</p>
  {similarity}
  <div class="form-actions">
    <button class="btn btn-primary" type="submit">{submit}</button>
    <a class="btn btn-secondary" href="{cancel}">Cancel</a>
  </div>
</form>
</div>"#,
        crumb = crumbs(&[("Home", Some("/")), (&s.heading.0, None)]),
        eyebrow = eyebrow("Compose"),
        heading = t(&s.heading),
        action = o(&vs.submit.action),
        hidden = hidden_inputs(&vs.submit.csrf.0, &vs.submit.fields),
        quote_hidden = quote_hidden,
        category_field = category_field,
        title_field = title_field,
        body = t(&vs.body),
        similarity = similarity,
        submit = submit_label,
        cancel = o(&vs.cancel_href),
    )
}

fn category_select(cats: &[CategoryVM], selected: Option<&crate::view_model::Opaque>) -> String {
    let selected = selected.map(|s| s.0.as_str());
    let mut options = String::new();
    for c in cats {
        let value = &c.category.id.0;
        let kind = match c.kind {
            ThreadKind::Question => "Question",
            ThreadKind::Discussion => "Discussion",
        };
        options.push_str(&format!(
            r#"<option value="{value}"{sel}>{name} · {kind}</option>"#,
            value = escape(value),
            sel = if selected == Some(value.as_str()) {
                " selected"
            } else {
                ""
            },
            name = t(&c.category.name),
            kind = kind,
        ));
    }
    format!(
        r#"<label class="ag-form__label" for="ag-compose-category">Category</label>
  <select id="ag-compose-category" name="category" required>{options}</select>"#,
    )
}
