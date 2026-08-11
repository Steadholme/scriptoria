//! Admin console — verified-group civic authority.
//!
//! Every control here was issued by Codex only after a verified admin-group decision; this view
//! renders presence/absence and never infers moderation rights. Category rename/format/create and
//! thread moves carry the exact `name`/`format`/`category` fields the handlers parse; list-level
//! destructive controls contain only a non-mutating review link.

use crate::view_model::{
    AddBanFormVM, AdminCategoryVM, AdminShared, AdminThreadVM, AdminView, AdminViewerState,
    BannedAuthorVM, CreateCategoryFormVM, ThreadKind,
};

use super::forum::admin_thread_toolbar;
use super::shell;
use super::{
    answer_state_chip, collection_note, crumbs, escape, eyebrow, form_action, form_action_opt,
    hidden_inputs, kind_chip, link_action, monogram, o, t, thread_href, time_el,
};

pub fn admin(v: &AdminView) -> String {
    shell::page(&v.chrome, &admin_main(&v.shared, &v.viewer))
}

fn admin_main(s: &AdminShared, vs: &AdminViewerState) -> String {
    format!(
        r#"<div class="ag-admin">
  {crumb}
  <header class="pagehead"><div class="ag-head-tools__lead">{eyebrow}<h1 class="ag-head__title">Administration</h1><p class="muted">Every control here required a verified admin group.</p></div></header>
  <section class="ag-admin-sect ag-key-shared" aria-labelledby="ag-admin-categories-title">
    <h2 class="eyebrow ag-eyebrow" id="ag-admin-categories-title">Categories</h2>
    {create}
    {categories}
  </section>
  <section class="ag-admin-sect ag-key-shared" aria-labelledby="ag-admin-threads-title">
    <h2 class="eyebrow ag-eyebrow" id="ag-admin-threads-title">Recent threads</h2>
    <p class="muted ag-desk__bound">Up to {bound} recent threads</p>
    {threads}
  </section>
  <section class="ag-admin-sect ag-key-shared" aria-labelledby="ag-admin-bans-title">
    <h2 class="eyebrow ag-eyebrow" id="ag-admin-bans-title">Banned authors</h2>
    {add_ban}
    {bans}
  </section>
</div>"#,
        crumb = crumbs(&[("Home", Some("/")), ("Administration", None)]),
        eyebrow = eyebrow("Civic Authority"),
        create = create_category_form(&vs.create_category),
        categories = admin_categories(&vs.categories),
        bound = s.visible_thread_bound,
        threads = admin_threads(&vs.threads, s.now, s.state),
        add_ban = add_ban_form(&vs.add_ban),
        bans = banned_authors(&vs.banned_authors, s.now),
    )
}

fn format_options(selected: ThreadKind) -> String {
    format!(
        r#"<option value="discussion"{d}>Discussion</option><option value="question"{q}>Question</option>"#,
        d = if selected == ThreadKind::Discussion {
            " selected"
        } else {
            ""
        },
        q = if selected == ThreadKind::Question {
            " selected"
        } else {
            ""
        },
    )
}

fn create_category_form(f: &CreateCategoryFormVM) -> String {
    format!(
        r#"<form class="ag-form ag-admin-new" method="post" action="{action}">{hidden}
  <div class="ag-form__row">
    <input type="text" name="id" maxlength="{id_max}" value="{id}" placeholder="Category ID" aria-label="Category ID" required>
    <input type="text" name="name" maxlength="{name_max}" value="{name}" placeholder="New category name" aria-label="New category name" required>
    <select name="format" aria-label="Category format">{formats}</select>
    <button class="btn btn-primary" type="submit">Create category</button>
  </div>
</form>"#,
        action = o(&f.submit.action),
        hidden = hidden_inputs(&f.submit.csrf.0, &f.submit.fields),
        id_max = f.id_max_chars,
        id = t(&f.id),
        name_max = f.name_max_chars,
        name = t(&f.name),
        formats = format_options(f.selected_kind),
    )
}

fn admin_categories(cats: &[AdminCategoryVM]) -> String {
    if cats.is_empty() {
        return r#"<p class="muted">No categories yet.</p>"#.to_string();
    }
    let rows: String = cats.iter().map(admin_category_row).collect();
    format!(r#"<ul class="ag-admin-list">{rows}</ul>"#)
}

fn admin_category_row(c: &AdminCategoryVM) -> String {
    let name = t(&c.category.category.name);
    let rename = format!(
        r#"<form class="inline-form ag-admin-rename" method="post" action="{action}">{hidden}<input type="text" name="name" maxlength="{max}" value="{name}" aria-label="Rename category"><button class="btn btn-secondary btn-sm" type="submit">Rename</button></form>"#,
        action = o(&c.rename.submit.action),
        hidden = hidden_inputs(&c.rename.submit.csrf.0, &c.rename.submit.fields),
        max = c.rename.name_max_chars,
        name = name,
    );
    let format = format!(
        r#"<form class="inline-form ag-admin-format" method="post" action="{action}">{hidden}<select name="format" aria-label="Category format">{formats}</select><button class="btn btn-secondary btn-sm" type="submit">Set format</button></form>"#,
        action = o(&c.set_format.action),
        hidden = hidden_inputs(&c.set_format.csrf.0, &c.set_format.fields),
        formats = format_options(c.category.kind),
    );
    format!(
        r#"<li class="ag-admin-row ag-key-shared">
  <div class="ag-admin-row__lead"><span class="ag-admin-row__name">{name}</span>{kind}</div>
  <div class="ag-admin-row__controls">{rename}{format}{move_up}{move_down}{delete}</div>
</li>"#,
        name = name,
        kind = kind_chip(c.category.kind),
        rename = rename,
        format = format,
        move_up = form_action_opt(&c.move_up),
        move_down = form_action_opt(&c.move_down),
        delete = link_action(&c.delete_review),
    )
}

fn admin_threads(
    threads: &[AdminThreadVM],
    now: i64,
    state: crate::view_model::CollectionState,
) -> String {
    if threads.is_empty() {
        return collection_note(state, "No recent threads.").unwrap_or_default();
    }
    let rows: String = threads.iter().map(|at| admin_thread_row(at, now)).collect();
    format!(r#"<ul class="ag-admin-list">{rows}</ul>"#)
}

fn admin_thread_row(at: &AdminThreadVM, now: i64) -> String {
    let th = &at.thread;
    let mut chips = String::from(kind_chip(th.kind));
    if th.kind == ThreadKind::Question {
        chips.push_str(&answer_state_chip(th.answer_state));
    }
    format!(
        r#"<li class="ag-admin-row ag-key-shared">
  <div class="ag-admin-row__lead">
    <div class="ag-row__chips">{chips}</div>
    <a class="ag-row__title" href="{href}">{title}</a>
    <p class="ag-row__by">{monogram} <span class="ag-row__author">{author}</span> · latest {time}</p>
  </div>
  {toolbar}
</li>"#,
        chips = chips,
        href = escape(&thread_href(&th.id)),
        title = t(&th.title),
        monogram = monogram(&th.author_display.0),
        author = t(&th.author_display),
        time = time_el(th.last_at, now),
        toolbar = admin_thread_toolbar(&at.toolbar),
    )
}

fn banned_authors(bans: &[BannedAuthorVM], now: i64) -> String {
    if bans.is_empty() {
        return r#"<p class="muted">No banned authors.</p>"#.to_string();
    }
    let rows: String = bans.iter().map(|ban| banned_author_row(ban, now)).collect();
    format!(r#"<ul class="ag-admin-list">{rows}</ul>"#)
}

fn add_ban_form(f: &AddBanFormVM) -> String {
    format!(
        r#"<form class="ag-form ag-admin-ban" method="post" action="{action}">{hidden}
  <div class="ag-form__row">
    <input type="text" name="author_sub" maxlength="{sub_max}" value="{subject}" placeholder="Author subject" aria-label="Author subject" required>
    <input type="text" name="reason" maxlength="{reason_max}" value="{reason}" placeholder="Reason" aria-label="Ban reason" required>
    <button class="btn btn-danger" type="submit">Ban author</button>
  </div>
</form>"#,
        action = o(&f.submit.action),
        hidden = hidden_inputs(&f.submit.csrf.0, &f.submit.fields),
        sub_max = f.author_sub_max_chars,
        subject = t(&f.subject_input),
        reason_max = f.reason_max_chars,
        reason = t(&f.reason),
    )
}

fn banned_author_row(b: &BannedAuthorVM, now: i64) -> String {
    format!(
        r#"<li class="ag-admin-row ag-key-shared">
  <div class="ag-admin-row__lead">
    <p class="ag-admin-row__name">{author}</p>
    <p class="ag-ban-reason">{reason}</p>
    <p class="ag-row__by muted">Banned by {by} · {time}</p>
  </div>
  <div class="ag-admin-row__controls">{unban}</div>
</li>"#,
        author = t(&b.author_display),
        reason = t(&b.reason),
        by = t(&b.banned_by),
        time = time_el(b.created_at, now),
        unban = form_action(&b.unban),
    )
}
