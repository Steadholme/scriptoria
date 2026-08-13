//! Render-contract tests for Agora's product-owned Civic Amphitheatre views.
//!
//! These tests exercise presentation boundaries directly. Handler/Store authority is covered by
//! the existing flow suites; this file verifies that pure views preserve escaped text, sanitized
//! HTML, server-issued actions, truthful bounds, no-JavaScript controls, and the shared/private
//! visual grammar.

use agora::view_model::*;
use agora::views::{admin, forum, personal, search, shell};

fn text(value: &str) -> Text {
    Text(value.to_string())
}

fn opaque(value: &str) -> Opaque {
    Opaque(value.to_string())
}

fn chrome(title: &str) -> PageChrome {
    PageChrome {
        title: text(title),
        viewer_email: Some(text("alice@example.test")),
        active_nav: NavTab::Home,
        counts: PersonalCounts {
            unread_activity: None,
            due_bookmarks: None,
        },
        cache: CacheClass::PrivateNoStore,
    }
}

fn form_action(path: &str, kind: ActionKind) -> FormActionVM {
    FormActionVM {
        action: opaque(path),
        label_kind: kind,
        csrf: opaque("csrf<&>"),
        fields: Vec::new(),
    }
}

fn link_action(path: &str, kind: ActionKind) -> LinkActionVM {
    LinkActionVM {
        href: opaque(path),
        label_kind: kind,
    }
}

fn page_link(path: &str, label: &str) -> PageLinkVM {
    PageLinkVM {
        href: opaque(path),
        label: text(label),
    }
}

fn list_controls() -> ThreadListControlsVM {
    ThreadListControlsVM {
        active_order: ThreadOrder::Latest,
        active_scope: ThreadScope::Questions,
        subscribed_only: true,
        order_links: vec![
            ThreadOrderLinkVM {
                order: ThreadOrder::Latest,
                href: opaque("/?sort=latest&filter=subscribed"),
            },
            ThreadOrderLinkVM {
                order: ThreadOrder::Top,
                href: opaque("/?sort=top&filter=subscribed"),
            },
        ],
        scope_links: vec![
            ThreadScopeLinkVM {
                scope: ThreadScope::Questions,
                href: opaque("/questions?filter=subscribed"),
            },
            ThreadScopeLinkVM {
                scope: ThreadScope::Unanswered,
                href: opaque("/questions?status=unanswered&filter=subscribed"),
            },
        ],
        subscribed_toggle: Some(page_link("/questions", "Show all threads")),
        questions: Some(page_link("/questions?sort=latest", "Browse questions")),
    }
}

fn category() -> CategoryVM {
    CategoryVM {
        category: CategoryRefVM {
            id: opaque("support"),
            name: text("Support & repair"),
        },
        kind: ThreadKind::Question,
        sort_order: 10,
    }
}

fn row(id: &str, title: &str) -> ThreadRowShared {
    ThreadRowShared {
        id: opaque(id),
        title: text(title),
        category: Some(category().category),
        kind: ThreadKind::Question,
        answer_state: AnswerState::NeedsAnswer,
        author_display: text("Alice <admin>"),
        created_at: 1_700_000_000,
        last_at: 1_700_000_600,
        post_count: Some(2),
        pinned: true,
        locked: false,
    }
}

fn post(id: &str, body: &str, is_op: bool) -> PostVM {
    PostVM {
        id: opaque(id),
        author_display: text("Bob & Carol"),
        created_at: 1_700_000_000,
        body: SafeHtml(body.to_string()),
        is_op,
        quote: None,
        reactions: Vec::new(),
        viewer: PostViewerState::default(),
        actions: PostActionsVM::default(),
    }
}

#[test]
fn pure_view_sources_do_not_import_authority_layers() {
    let sources = [
        include_str!("../src/views/mod.rs"),
        include_str!("../src/views/shell.rs"),
        include_str!("../src/views/forum.rs"),
        include_str!("../src/views/personal.rs"),
        include_str!("../src/views/search.rs"),
        include_str!("../src/views/admin.rs"),
    ];
    let forbidden = [
        "use crate::store",
        "use crate::auth",
        "use crate::error",
        "use crate::AppState",
        "use axum::",
        "use sqlx::",
    ];
    for source in sources {
        for needle in forbidden {
            assert!(
                !source.contains(needle),
                "pure presentation source imported authority via {needle}"
            );
        }
    }
}

#[test]
fn shell_and_css_preserve_accessible_progressive_enhancement() {
    let template = shell::SHELL;
    let css = shell::SERVICE_CSS;

    assert!(template.contains(r##"href="#ag-main""##));
    assert!(template.contains(r#"<main class="wrap ag-main" id="ag-main" tabindex="-1">"#));
    assert!(template.contains("credentials: 'same-origin'"));
    assert!(template.contains("textContent"));
    assert!(!template.contains("innerHTML"));
    assert!(template.contains("form.getAttribute('action') !== '/new'"));
    assert!(template.contains("active.focus();"));
    assert!(template.contains("Threads sorted by "));
    assert!(template.contains("var requestId = 0;"));
    assert!(template.contains("requestController.abort();"));
    assert!(template.contains("focus.replaceWith(freshFocus)"));
    assert!(template.contains("window.IntersectionObserver"));
    assert!(template.contains("[data-thread-read-form]"));
    assert!(template.contains("'Accept': 'application/json'"));

    assert!(css.contains(".ag-key-shared"));
    assert!(css.contains("border-style: solid;"));
    assert!(css.contains(".ag-key-private"));
    assert!(css.contains("border-style: dashed;"));
    assert!(css.contains("min-height: 44px"));
    assert!(css.contains(".ag-row__cat a"));

    // Orphan CSS rules must be removed
    assert!(!css.contains(".ag-read-progress {"));

    // Print rules must hide spine and controls
    let print_section = &css[css.find("@media print").unwrap()..];
    assert!(print_section.contains(".ag-reading-spine"));
    assert!(print_section.contains(".ag-reading-controls"));

    assert!(css.contains("min-height: 24px"));
    assert!(css.contains(".ag-appbar .usermenu:focus-within .usermenu__pop"));
    assert!(css.contains("overflow-wrap: anywhere"));
    assert!(css.contains("@media (min-width: 1440px)"));
    assert!(css.contains("@media (max-width: 760px)"));
    assert!(css.contains("@media (max-width: 360px)"));
    assert!(css.contains("@media (prefers-reduced-motion: reduce)"));
    assert!(css.contains("@media (forced-colors: active)"));
    assert!(css.contains("backdrop-filter: none;"));
    assert!(!css.contains("linear-gradient("));
    assert!(!css.contains("radial-gradient("));
    assert!(!css.contains("ag-tone-"));
    assert!(!css.contains("border-radius: var(--r-pill)"));
}

#[test]
fn identity_display_text_is_escaped_exactly_once() {
    let mut page_chrome = chrome("Identity");
    page_chrome.viewer_email = Some(text("alice+<&>@example.test"));

    let html = shell::page(&page_chrome, "<p>content</p>");
    assert!(html.contains("alice+&lt;&amp;&gt;@example.test"));
    assert!(!html.contains("&amp;lt;"));
}

#[test]
fn home_is_one_landmark_and_separates_shared_from_private_truth() {
    let view = HomeView {
        chrome: chrome("Agora <home>"),
        shared: HomeShared {
            categories: vec![category()],
            controls: list_controls(),
            state: CollectionState::Ready,
            visible_bound: 20,
            now: 1_700_001_000,
        },
        rows: vec![ThreadRowVM {
            shared: row("t<&>", "<script>alert('thread')</script>"),
            viewer: ThreadRowViewerState {
                follow_level: Some(ThreadFollowLevelVM::Watch),
                bookmarked: Some(true),
                unread_count: Some(3),
                resume_href: Some(opaque("/t/t-1?resume=1#first")),
            },
        }],
    };

    let html = forum::home(&view);
    assert_eq!(
        html.matches("<main").count(),
        1,
        "shell owns the only main landmark"
    );
    assert!(html.contains("Topic Terraces"));
    assert!(html.contains("Civic Ledgers"));
    assert!(html.contains("page bound 20"));
    assert!(html.contains("ag-key-shared"));
    assert!(html.contains("ag-key-private"));
    assert!(html.contains("Watching"));
    assert!(html.contains("3 unread"));
    assert!(html.contains("&lt;script&gt;alert(&#x27;thread&#x27;)&lt;/script&gt;"));
    assert!(!html.contains("<script>alert('thread')</script>"));
    assert!(html.contains(r#"method="get" action="/search""#));
    assert!(html.contains(r#"href="/?sort=latest&amp;filter=subscribed""#));
    assert!(html.contains(r#"href="/questions?sort=latest""#));
    assert!(html.contains("Questions you subscribe to"));
    assert!(html.contains(r#"<nav class="tabs sort-tabs" aria-label="Sort threads">"#));
    assert!(html.contains(r#"<a class="tab is-active" aria-current="page" data-sort-tab="latest""#));
    assert!(!html.contains(r#"role="tablist""#));
    assert!(!html.contains(r#"role="tab""#));
    assert!(!html.contains(r#"aria-pressed="#));
    assert!(html.contains(r#"<a class="appnav is-active" href="/" aria-current="location">"#));
    assert!(!html.contains(r#"role="menu""#));
    assert!(!html.contains(r#"role="menuitem""#));
    assert!(!html.contains(r#"aria-haspopup="true""#));
    assert!(
        !html.contains(r#"<span class="ag-count-badge"#),
        "unavailable private counts stay absent"
    );
}

#[test]
fn unknown_post_count_stays_absent_while_exact_one_means_zero_replies() {
    let mut unknown = row("unknown", "Unknown count");
    unknown.post_count = None;
    let mut exact_one = row("exact", "Exact count");
    exact_one.post_count = Some(1);
    let view = HomeView {
        chrome: chrome("Counts"),
        shared: HomeShared {
            categories: vec![],
            controls: list_controls(),
            state: CollectionState::Ready,
            visible_bound: 20,
            now: 1_700_001_000,
        },
        rows: vec![
            ThreadRowVM {
                shared: unknown,
                viewer: ThreadRowViewerState::default(),
            },
            ThreadRowVM {
                shared: exact_one,
                viewer: ThreadRowViewerState::default(),
            },
        ],
    };

    let html = forum::home(&view);
    assert_eq!(
        html.matches("0 replies").count(),
        1,
        "unknown is omitted; only exact Some(1) renders zero replies"
    );
}

#[test]
fn thread_renders_one_answer_dais_and_truthful_page_bounds() {
    let accepted = post("accepted", "<p>accepted-body</p>", false);
    let mut ordinary = post("ordinary", "<p>ordinary-body</p>", false);
    ordinary.actions.bookmark = Some(PostBookmarkActionVM::Saved {
        edit: link_action("/bookmarks/ordinary/edit", ActionKind::BookmarkEdit),
        state: SavedBookmarkStateVM::Due,
    });
    ordinary.actions.delete_reviews = vec![
        link_action(
            "/t/thread-1/p/ordinary/delete",
            ActionKind::DeleteReplyReview,
        ),
        link_action(
            "/admin/posts/ordinary/delete",
            ActionKind::DeleteAdminReview,
        ),
    ];
    let view = ThreadView {
        chrome: chrome("Question"),
        shared: ThreadShared {
            id: opaque("thread-1"),
            title: text("How does this work?"),
            category: Some(category().category),
            kind: ThreadKind::Question,
            answer_state: AnswerState::Answered,
            author_display: text("Alice"),
            created_at: 1_700_000_000,
            post_count: Some(3),
            pinned: false,
            locked: false,
        },
        viewer: ThreadViewerState {
            subscription: None,
            edit: None,
            delete_review: None,
            clear_invalid_solution: None,
        },
        op: post("op", "<p>speaker-floor-body</p>", true),
        dais: Some(AnswerDaisVM {
            post: accepted.clone(),
            acceptance: AcceptanceMeaning::AcceptedByAskerOrAuthorizedModerator,
        }),
        // A defensive duplicate is deliberately supplied: the view must never paint it twice.
        replies: vec![accepted, ordinary],
        pagination: PaginationVM {
            previous: None,
            next: None,
            jump: Some(PageLinkVM {
                href: opaque("/t/thread-1?latest=1#thread-latest"),
                label: text("Jump to latest"),
            }),
            at_start: true,
            at_end: false,
            visible_limit: 20,
        },
        reply_form: ReplyFormVM::Available {
            submit: form_action("/t/thread-1/reply", ActionKind::PostAnswer),
            body: text(""),
            quoted_post_id: None,
        },
        summary: SummaryStateVM::Available(SummaryVM {
            sentences: vec![text("A bounded sentence.")],
            source_post_count: 2,
            source_word_count: 72,
            sentence_bound: 3,
        }),
        reading: ReadingProgressVM {
            started: true,
            unread_count: Some(1),
            first_unread_href: Some(opaque("#first-unread")),
            resume_href: None,
            mark_page_read: None,
        },
        admin: None,
        now: 1_700_001_000,
    };

    let html = forum::thread(&view);
    assert_eq!(html.matches(r#"id="ag-dais-title""#).count(), 1);
    assert_eq!(html.matches("accepted-body").count(), 1);
    assert!(html.contains("acceptance, not objective correctness"));
    assert!(html.contains("Selected from 2 posts / 72 words on this page · at most 3 sentences"));
    assert!(html.contains("Page bound 20"));
    assert!(html.contains(r#"href="/t/thread-1?latest=1#thread-latest""#));
    assert!(html.contains("Beginning of results"));
    assert!(html.contains(r#"method="post" action="/t/thread-1/reply""#));
    assert!(html.contains(r#"name="csrf" value="csrf&lt;&amp;&gt;""#));
    assert!(html.contains(r#"href="/bookmarks/ordinary/edit""#));
    assert!(html.contains("Saved · Due"));
    assert!(html.contains(r#"href="/t/thread-1/p/ordinary/delete""#));
    assert!(html.contains(r#"href="/admin/posts/ordinary/delete""#));
    assert_eq!(
        html.matches("ordinary/delete").count(),
        2,
        "owner and admin review links can coexist"
    );

    let floor = html.find("Speaker Floor").expect("speaker floor");
    let dais = html.find("Answer Dais").expect("answer dais");
    let steps = html.find("Reply Steps").expect("reply steps");
    assert!(
        floor < dais && dais < steps,
        "civic reading order is structural"
    );
}

#[test]
fn question_thread_renders_reading_spine_with_structural_markers() {
    let view = ThreadView {
        chrome: chrome("Question with spine"),
        shared: ThreadShared {
            id: opaque("thread-spine"),
            title: text("Question with reading spine"),
            category: Some(category().category),
            kind: ThreadKind::Question,
            answer_state: AnswerState::Answered,
            author_display: text("Alice"),
            created_at: 1_700_000_000,
            post_count: Some(5),
            pinned: false,
            locked: false,
        },
        viewer: ThreadViewerState {
            subscription: None,
            edit: None,
            delete_review: None,
            clear_invalid_solution: None,
        },
        op: post("op", "<p>question body</p>", true),
        dais: Some(AnswerDaisVM {
            post: post("accepted", "<p>accepted answer</p>", false),
            acceptance: AcceptanceMeaning::AcceptedByAskerOrAuthorizedModerator,
        }),
        replies: vec![
            post("r1", "<p>reply 1</p>", false),
            post("r2", "<p>reply 2</p>", false),
        ],
        pagination: PaginationVM {
            previous: None,
            next: Some(page_link("/t/thread-spine?page=2", "Next")),
            jump: None,
            at_start: true,
            at_end: false,
            visible_limit: 20,
        },
        reply_form: ReplyFormVM::Available {
            submit: form_action("/t/thread-spine/reply", ActionKind::PostAnswer),
            body: text(""),
            quoted_post_id: None,
        },
        summary: SummaryStateVM::Unavailable(SummaryUnavailableReason::TooFewPosts),
        reading: ReadingProgressVM {
            started: true,
            unread_count: Some(2),
            first_unread_href: Some(opaque("#first-unread")),
            resume_href: Some(opaque("/t/thread-spine?resume=1#resume-post")),
            mark_page_read: None,
        },
        admin: None,
        now: 1_700_001_000,
    };

    let html = forum::thread(&view);

    assert!(html.contains(r##"class="ag-reading-spine ag-key-shared""##));
    assert!(html.contains(r##"href="#ag-floor-title">Question</a>"##));
    assert!(html.contains(r##"href="#ag-dais-title">Accepted Answer</a>"##));
    assert!(html.contains("ag-spine__section--dais"));
    assert!(html.contains("ag-spine__section--private"));
    assert!(html.contains(r##"href="/t/thread-spine?resume=1#resume-post">Continue reading</a>"##));
    assert!(html.contains("2 unread"));
}

#[test]
fn discussion_thread_has_no_reading_spine() {
    let view = ThreadView {
        chrome: chrome("Discussion"),
        shared: ThreadShared {
            id: opaque("disc-1"),
            title: text("Discussion thread"),
            category: Some(category().category),
            kind: ThreadKind::Discussion,
            answer_state: AnswerState::NotApplicable,
            author_display: text("Bob"),
            created_at: 1_700_000_000,
            post_count: Some(3),
            pinned: false,
            locked: false,
        },
        viewer: ThreadViewerState {
            subscription: None,
            edit: None,
            delete_review: None,
            clear_invalid_solution: None,
        },
        op: post("op", "<p>discussion</p>", true),
        dais: None,
        replies: vec![post("r1", "<p>reply</p>", false)],
        pagination: PaginationVM {
            previous: None,
            next: None,
            jump: None,
            at_start: true,
            at_end: true,
            visible_limit: 20,
        },
        reply_form: ReplyFormVM::Available {
            submit: form_action("/t/disc-1/reply", ActionKind::PostReply),
            body: text(""),
            quoted_post_id: None,
        },
        summary: SummaryStateVM::Unavailable(SummaryUnavailableReason::TooFewPosts),
        reading: ReadingProgressVM {
            started: false,
            unread_count: None,
            first_unread_href: None,
            resume_href: None,
            mark_page_read: None,
        },
        admin: None,
        now: 1_700_001_000,
    };

    let html = forum::thread(&view);

    assert!(
        !html.contains(r##"<aside class="ag-reading-spine"##),
        "Discussion threads have no spine element"
    );
    assert!(
        !html.contains(r#"<article class="ag-thread ag-thread--spined"#),
        "Discussion threads do not have the spined modifier on article element"
    );
    assert!(
        html.contains(r#"<article class="ag-thread">"#),
        "Discussion threads have plain ag-thread class without spined modifier"
    );
}

#[test]
fn steps_spine_marks_pagination_bounds_and_resume_anchor() {
    let mut resume_post = post("resume", "<p>resume here</p>", false);
    resume_post.viewer.resume_anchor = Some(opaque("first-unread"));

    let view = ThreadView {
        chrome: chrome("Paginated"),
        shared: ThreadShared {
            id: opaque("pag-1"),
            title: text("Paginated thread"),
            category: Some(category().category),
            kind: ThreadKind::Question,
            answer_state: AnswerState::NeedsAnswer,
            author_display: text("Alice"),
            created_at: 1_700_000_000,
            post_count: Some(50),
            pinned: false,
            locked: false,
        },
        viewer: ThreadViewerState {
            subscription: None,
            edit: None,
            delete_review: None,
            clear_invalid_solution: None,
        },
        op: post("op", "<p>question</p>", true),
        dais: None,
        replies: vec![
            post("r1", "<p>reply 1</p>", false),
            resume_post,
            post("r3", "<p>reply 3</p>", false),
        ],
        pagination: PaginationVM {
            previous: Some(page_link("/t/pag-1?page=1", "Previous")),
            next: Some(page_link("/t/pag-1?page=3", "Next")),
            jump: None,
            at_start: false,
            at_end: false,
            visible_limit: 20,
        },
        reply_form: ReplyFormVM::Available {
            submit: form_action("/t/pag-1/reply", ActionKind::PostAnswer),
            body: text(""),
            quoted_post_id: None,
        },
        summary: SummaryStateVM::Unavailable(SummaryUnavailableReason::TooFewPosts),
        reading: ReadingProgressVM {
            started: true,
            unread_count: Some(5),
            first_unread_href: Some(opaque("#first-unread")),
            resume_href: None,
            mark_page_read: None,
        },
        admin: None,
        now: 1_700_001_000,
    };

    let html = forum::thread(&view);

    assert!(html.contains(r#"class="ag-steps__bound ag-steps__bound--start""#));
    assert!(html.contains("Earlier replies on previous page"));
    assert!(html.contains(r#"class="ag-steps__bound ag-steps__bound--end""#));
    assert!(html.contains("More replies on next page"));
    assert!(html.contains("ag-first-unread"));

    // Count actual bound elements (not CSS occurrences)
    let bound_elements = html.matches(r#"<div class="ag-steps__bound"#).count();
    assert_eq!(bound_elements, 2, "both start and end bounds present");
}

#[test]
fn reading_controls_consolidate_resume_pagination_and_jump() {
    let view = ThreadView {
        chrome: chrome("Controls"),
        shared: ThreadShared {
            id: opaque("ctrl-1"),
            title: text("Thread with controls"),
            category: Some(category().category),
            kind: ThreadKind::Question,
            answer_state: AnswerState::NeedsAnswer,
            author_display: text("Alice"),
            created_at: 1_700_000_000,
            post_count: Some(100),
            pinned: false,
            locked: false,
        },
        viewer: ThreadViewerState {
            subscription: None,
            edit: None,
            delete_review: None,
            clear_invalid_solution: None,
        },
        op: post("op", "<p>question</p>", true),
        dais: None,
        replies: vec![post("r1", "<p>reply 1</p>", false)],
        pagination: PaginationVM {
            previous: Some(page_link("/t/ctrl-1?page=1", "Previous")),
            next: Some(page_link("/t/ctrl-1?page=3", "Next")),
            jump: Some(page_link(
                "/t/ctrl-1?latest=1#thread-latest",
                "Jump to latest",
            )),
            at_start: false,
            at_end: false,
            visible_limit: 20,
        },
        reply_form: ReplyFormVM::Available {
            submit: form_action("/t/ctrl-1/reply", ActionKind::PostAnswer),
            body: text(""),
            quoted_post_id: None,
        },
        summary: SummaryStateVM::Unavailable(SummaryUnavailableReason::TooFewPosts),
        reading: ReadingProgressVM {
            started: true,
            unread_count: Some(8),
            first_unread_href: Some(opaque("#first-unread")),
            resume_href: None,
            mark_page_read: Some(form_action("/t/ctrl-1/mark-read", ActionKind::MarkPageRead)),
        },
        admin: None,
        now: 1_700_001_000,
    };

    let html = forum::thread(&view);
    assert!(html.contains(r#"class="ag-reading-controls ag-key-private""#));
    assert!(html.contains(r#"data-thread-read-form"#));
    assert!(html.contains(r#"data-thread-read-progress"#));
    assert!(html.contains(r#"class="ag-page""#));

    // Jump control is provided by pagination() helper, not separately
    assert!(html.contains(r#"class="btn btn-ghost btn-sm ag-page__jump""#));
    assert!(!html.contains("ag-jump-latest"));

    // Jump link appears exactly once
    assert_eq!(
        html.matches(r#"href="/t/ctrl-1?latest=1#thread-latest""#)
            .count(),
        1,
        "Jump to latest link must appear exactly once"
    );
    assert_eq!(
        html.matches(">Jump to latest<").count(),
        1,
        "Jump to latest label must appear exactly once"
    );

    assert!(html.contains("8 unread posts"));
}

#[test]
fn spine_layout_uses_grid_not_float() {
    let css = shell::SERVICE_CSS;

    // Float must not be used anywhere in the stylesheet
    assert!(
        !css.contains("float:"),
        "Float layout is forbidden; use grid for two-column spine layout"
    );

    // Desktop layout must use grid
    assert!(css.contains(".ag-thread--spined"));
    assert!(css.contains("grid-template-columns: 200px minmax(0, 1fr)"));
}

#[test]
fn spine_dom_order_places_head_before_body() {
    let view = ThreadView {
        chrome: chrome("Layout"),
        shared: ThreadShared {
            id: opaque("layout-1"),
            title: text("Question with spine"),
            category: Some(category().category),
            kind: ThreadKind::Question,
            answer_state: AnswerState::NeedsAnswer,
            author_display: text("Alice"),
            created_at: 1_700_000_000,
            post_count: Some(5),
            pinned: false,
            locked: false,
        },
        viewer: ThreadViewerState {
            subscription: None,
            edit: None,
            delete_review: None,
            clear_invalid_solution: None,
        },
        op: post("op", "<p>question</p>", true),
        dais: None,
        replies: vec![],
        pagination: PaginationVM {
            previous: None,
            next: None,
            jump: None,
            at_start: true,
            at_end: true,
            visible_limit: 20,
        },
        reply_form: ReplyFormVM::Available {
            submit: form_action("/t/layout-1/reply", ActionKind::PostAnswer),
            body: text(""),
            quoted_post_id: None,
        },
        summary: SummaryStateVM::Unavailable(SummaryUnavailableReason::TooFewPosts),
        reading: ReadingProgressVM {
            started: false,
            unread_count: None,
            first_unread_href: None,
            resume_href: None,
            mark_page_read: None,
        },
        admin: None,
        now: 1_700_001_000,
    };

    let html = forum::thread(&view);

    // Find positions of key elements
    let head_pos = html
        .find(r#"class="ag-thread__head"#)
        .expect("head must exist");
    let body_pos = html
        .find(r#"class="ag-thread__body"#)
        .expect("body must exist");
    let spine_pos = html
        .find(r#"class="ag-reading-spine"#)
        .expect("spine must exist");
    let col_pos = html
        .find(r#"class="ag-thread__col"#)
        .expect("col must exist");

    // Head comes before body wrapper
    assert!(
        head_pos < body_pos,
        "Thread head must come before body wrapper for proper mobile order"
    );

    // Within body: spine comes before content column
    assert!(
        spine_pos < col_pos,
        "Spine must come before content column in DOM order"
    );

    // Body wrapper comes after head
    assert!(body_pos > head_pos, "Body wrapper must come after head");
}

#[test]
fn destructive_review_uses_only_the_server_issued_commit() {
    let view = DestructiveReviewVM {
        heading: text("Delete <thread>?"),
        consequence: ConsequenceVM {
            summary: text("Deletes the thread and its replies."),
            detail: Some(text("This does not affect other categories.")),
        },
        commit: FormActionVM {
            action: opaque("/t/thread-1/delete"),
            label_kind: ActionKind::DeleteConfirm,
            csrf: opaque("csrf-token"),
            fields: vec![HiddenField {
                name: text("confirm"),
                value: opaque("server-issued-confirm"),
            }],
        },
        cancel_href: opaque("/t/thread-1"),
    };

    let html = shell::destructive_review(&view);
    assert!(html.contains("Consequence review"));
    assert!(html.contains("Delete &lt;thread&gt;?"));
    assert!(html.contains(r#"method="post" action="/t/thread-1/delete""#));
    assert!(html.contains(r#"name="csrf" value="csrf-token""#));
    assert!(html.contains(r#"name="confirm" value="server-issued-confirm""#));
    assert!(html.contains(r#"href="/t/thread-1">Cancel</a>"#));
}

#[test]
fn activity_keeps_read_scope_independent_and_opens_exact_post_by_post() {
    let exact_target = "/t/thread-1?around=1700000000_post-1#post-post-1";
    let open = ActivityOpenFormVM {
        submit: form_action("/activity/a-1/open", ActionKind::OpenActivity),
        exact_target: opaque(exact_target),
    };
    let view = ActivityView {
        chrome: PageChrome {
            active_nav: NavTab::Activity,
            ..chrome("Activity")
        },
        shared: ActivityShared {
            active_filter: ActivityFilterVM::Mention,
            read_scope: ActivityReadScopeVM::Unread,
            filter_links: vec![ActivityFilterLinkVM {
                filter: ActivityFilterVM::Mention,
                link: page_link("/activity?filter=mention&state=unread", "Mentions"),
            }],
            read_scope_links: vec![
                ActivityReadScopeLinkVM {
                    scope: ActivityReadScopeVM::All,
                    link: page_link("/activity?filter=mention", "All"),
                },
                ActivityReadScopeLinkVM {
                    scope: ActivityReadScopeVM::Unread,
                    link: page_link("/activity?filter=mention&state=unread", "Unread"),
                },
            ],
            visible_bound: 30,
            state: CollectionState::Ready,
            now: 1_700_001_000,
        },
        viewer: ActivityViewerState {
            items: vec![ActivityItemVM {
                shared: ActivityItemShared {
                    id: opaque("a-1"),
                    kind: ActivityKindVM::PostCreated,
                    thread_id: opaque("thread-1"),
                    post_id: opaque("post-1"),
                    thread_title: text("A <thread>"),
                    post_excerpt: text("<script>not html</script>"),
                    actor_display: text("Actor & friend"),
                    created_at: 1_700_000_000,
                },
                viewer: ActivityItemViewerState {
                    reason: ActivityReasonVM::Mention,
                    read: false,
                    open,
                    toggle_read: form_action("/activity/a-1/state", ActionKind::MarkRead),
                },
            }],
            pagination: PaginationVM {
                previous: None,
                next: None,
                jump: None,
                at_start: true,
                at_end: true,
                visible_limit: 30,
            },
            mark_page_read: None,
        },
    };

    let html = personal::activity(&view);
    assert!(html.contains(r#"href="/activity?filter=mention&amp;state=unread""#));
    assert!(html.contains(r#"method="post" action="/activity/a-1/open""#));
    assert!(html.contains(&format!(
        r#"name="next" value="{}""#,
        exact_target.replace('&', "&amp;")
    )));
    assert!(html.contains("&lt;script&gt;not html&lt;/script&gt;"));
    assert!(!html.contains("<script>not html</script>"));
    assert!(!html.contains(r#"href="/t/thread-1""#));
}

#[test]
fn bookmark_queue_and_editor_preserve_exact_target_cas_and_both_snoozes() {
    let exact_target = "/t/thread-1?around=1700000000_post-1#post-post-1";
    let cas_fields = || {
        vec![
            HiddenField {
                name: text("expected_bookmark_id"),
                value: opaque("bookmark-1"),
            },
            HiddenField {
                name: text("expected_version"),
                value: opaque("7"),
            },
        ]
    };
    let with_fields = |path: &str, kind: ActionKind, mut fields: Vec<HiddenField>| {
        let mut action = form_action(path, kind);
        action.fields.append(&mut fields);
        action
    };
    let mut tomorrow_fields = cas_fields();
    tomorrow_fields.push(HiddenField {
        name: text("preset"),
        value: opaque("tomorrow"),
    });
    let mut week_fields = cas_fields();
    week_fields.push(HiddenField {
        name: text("preset"),
        value: opaque("week"),
    });
    let list = BookmarksView {
        chrome: PageChrome {
            active_nav: NavTab::Bookmarks,
            ..chrome("Bookmarks")
        },
        shared: BookmarksShared {
            active_state: BookmarkStateVM::Due,
            visible_bound: 30,
            state: CollectionState::Ready,
            now: 1_700_001_000,
        },
        viewer: BookmarksViewerState {
            items: vec![BookmarkItemVM {
                shared: BookmarkItemShared {
                    post_id: opaque("post-1"),
                    thread_id: opaque("thread-1"),
                    thread_title: text("Saved <thread>"),
                    post_author_display: text("Author"),
                    exact_post_href: opaque(exact_target),
                    post_excerpt: text("<b>plain excerpt</b>"),
                    post_created_at: 1_700_000_000,
                },
                viewer: BookmarkItemViewerState {
                    note: text("Private <note>"),
                    remind_at: Some(1_700_000_100),
                    created_at: 1_700_000_000,
                    updated_at: 1_700_000_500,
                    edit: link_action("/bookmarks/post-1/edit", ActionKind::BookmarkEdit),
                    remove: with_fields(
                        "/bookmarks/post-1/remove",
                        ActionKind::RemoveBookmark,
                        cas_fields(),
                    ),
                    done: Some(with_fields(
                        "/bookmarks/post-1/complete",
                        ActionKind::CompleteBookmark,
                        cas_fields(),
                    )),
                    snooze_tomorrow: Some(with_fields(
                        "/bookmarks/post-1/snooze",
                        ActionKind::SnoozeTomorrow,
                        tomorrow_fields,
                    )),
                    snooze_week: Some(with_fields(
                        "/bookmarks/post-1/snooze",
                        ActionKind::SnoozeWeek,
                        week_fields,
                    )),
                },
            }],
            pagination: PaginationVM {
                previous: None,
                next: None,
                jump: None,
                at_start: true,
                at_end: true,
                visible_limit: 30,
            },
        },
    };

    let list_html = personal::bookmarks(&list);
    assert!(list_html.contains(&format!(r#"href="{exact_target}""#)));
    assert!(list_html.contains("Snooze 24 hours"));
    assert!(list_html.contains("Snooze 7 days"));
    assert!(list_html.contains(r#"name="preset" value="tomorrow""#));
    assert!(list_html.contains(r#"name="preset" value="week""#));
    assert!(list_html.contains("&lt;b&gt;plain excerpt&lt;/b&gt;"));
    assert!(!list_html.contains("<b>plain excerpt</b>"));

    let mut save = form_action("/bookmarks/post-1/edit", ActionKind::SaveBookmarkChanges);
    save.fields = cas_fields();
    let editor = BookmarkEditView {
        chrome: chrome("Edit bookmark"),
        shared: BookmarkEditShared {
            thread_title: text("Saved <thread>"),
            exact_post_href: opaque(exact_target),
            current_reminder_at: Some(1_700_010_000),
            note_max_chars: 2_000,
        },
        viewer: BookmarkEditViewerState {
            note: text("Private <note>"),
            selected_reminder: BookmarkReminderChoiceVM::Keep,
            custom_time: text("2026-08-01T12:00"),
            save,
        },
    };
    let edit_html = personal::bookmark_edit(&editor);
    assert!(edit_html.contains(r#"name="note""#));
    assert!(edit_html.contains(r#"maxlength="2000""#));
    assert!(edit_html.contains(r#"name="reminder_action""#));
    assert!(edit_html.contains(r#"name="custom_time""#));
    assert!(edit_html.contains(r#"name="expected_bookmark_id" value="bookmark-1""#));
    assert!(edit_html.contains(r#"name="expected_version" value="7""#));
    assert!(edit_html.contains(&format!(r#"href="{exact_target}""#)));
}

#[test]
fn focus_has_only_category_bound_mutations() {
    let view = FocusView {
        chrome: chrome("Focus"),
        shared: FocusShared {
            visible_thread_bound: 30,
            rule_bound: 100,
            state: CollectionState::ReadyEmpty,
            now: 1_700_001_000,
        },
        viewer: FocusViewerState {
            rules: vec![FocusRuleVM {
                category: category(),
                level: CategoryFocusLevelVM::Follow,
                submit: form_action("/c/support/focus", ActionKind::ApplyFocus),
            }],
            items: Vec::new(),
        },
    };

    let html = personal::focus(&view);
    assert!(html.contains(r#"method="post" action="/c/support/focus""#));
    assert!(html.contains(r#"select name="level""#));
    assert!(html.contains(r#"<option value="follow" selected>Follow</option>"#));
    assert!(!html.contains("ag-focus-create"));
    assert!(!html.contains(r#"action="/focus""#));
}

#[test]
fn admin_forms_match_handlers_and_admin_truth_is_not_duplicated() {
    let move_form = MoveThreadFormVM {
        selected_category: opaque("support"),
        categories: vec![
            category().category,
            CategoryRefVM {
                id: opaque("general"),
                name: text("General <room>"),
            },
        ],
        submit: form_action("/admin/threads/thread-1/move", ActionKind::MoveThread),
    };
    let view = AdminView {
        chrome: chrome("Administration"),
        shared: AdminShared {
            visible_thread_bound: 100,
            state: CollectionState::Ready,
            now: 1_700_001_000,
        },
        viewer: AdminViewerState {
            create_category: CreateCategoryFormVM {
                id: text("new-id"),
                name: text("New <category>"),
                selected_kind: ThreadKind::Question,
                id_max_chars: 64,
                name_max_chars: 100,
                submit: form_action("/admin/categories", ActionKind::CreateCategory),
            },
            add_ban: AddBanFormVM {
                subject_input: text("subject-1"),
                reason: text("Repeated <spam>"),
                author_sub_max_chars: 200,
                reason_max_chars: 500,
                submit: form_action("/admin/bans", ActionKind::AddBan),
            },
            categories: vec![AdminCategoryVM {
                category: category(),
                rename: RenameCategoryFormVM {
                    name_max_chars: 100,
                    submit: form_action(
                        "/admin/categories/support/rename",
                        ActionKind::RenameCategory,
                    ),
                },
                set_format: form_action(
                    "/admin/categories/support/format",
                    ActionKind::SetCategoryFormat,
                ),
                move_up: Some(form_action(
                    "/admin/categories/support/reorder",
                    ActionKind::MoveCategoryUp,
                )),
                move_down: None,
                delete_review: link_action(
                    "/admin/categories/support/delete",
                    ActionKind::DeleteAdminReview,
                ),
            }],
            threads: vec![AdminThreadVM {
                thread: row("thread-1", "Moderated thread"),
                toolbar: AdminThreadToolbarVM {
                    move_thread: Some(move_form),
                    lock: None,
                    pin: None,
                    delete_review: Some(link_action(
                        "/admin/threads/thread-1/delete",
                        ActionKind::DeleteAdminReview,
                    )),
                },
            }],
            banned_authors: vec![BannedAuthorVM {
                author_display: text("Display <author>"),
                reason: text("Repeated spam"),
                banned_by: text("Admin"),
                created_at: 1_700_000_000,
                unban: form_action("/admin/bans/sealed-target/delete", ActionKind::Unban),
            }],
        },
    };

    let html = admin::admin(&view);
    assert!(html.contains(r#"name="id" maxlength="64""#));
    assert!(html.contains(r#"name="name" maxlength="100""#));
    assert!(html.contains(r#"method="post" action="/admin/bans""#));
    assert!(html.contains(r#"name="author_sub" maxlength="200""#));
    assert!(html.contains(r#"name="reason" maxlength="500""#));
    assert!(html.contains(r#"method="post" action="/admin/threads/thread-1/move""#));
    assert!(html.contains(r#"name="category""#));
    assert!(html.contains(r#"<option value="support" selected>"#));
    assert!(html.contains("&lt;room&gt;"));
    assert!(html.contains("Display &lt;author&gt;"));
    assert!(html.contains(r#"href="/admin/threads/thread-1/delete""#));
    assert!(!html.contains("server-issued-confirm"));
}

#[test]
fn action_contract_separates_links_forms_and_destructive_commit_scope() {
    let source = include_str!("../src/view_model.rs");
    assert!(source.contains("pub struct LinkActionVM"));
    assert!(source.contains("pub struct FormActionVM"));
    assert!(!source.contains("pub struct ActionVM"));
    assert!(!source.contains("pub struct DestructiveActionVM"));
    assert!(source.contains("pub commit: FormActionVM"));
    assert!(source.contains("pub delete_reviews: Vec<LinkActionVM>"));
}

#[test]
fn search_is_a_real_get_form_with_explicit_result_bounds() {
    let view = SearchView {
        chrome: PageChrome {
            active_nav: NavTab::Search,
            ..chrome("Search")
        },
        shared: SearchShared {
            categories: vec![category()],
            query_state: SearchQueryState::Valid,
            results: vec![SearchResultVM {
                thread: row("t-1", "Escaped <topic>"),
                excerpt: text("<mark>bounded excerpt</mark>"),
                source: SearchMatchSource::AcceptedAnswer,
            }],
            visible_bound: 50,
            state: CollectionState::Ready,
            now: 1_700_001_000,
        },
        viewer: SearchViewerState {
            query: text("\"quoted\" <query>"),
            selected_category: Some(opaque("support")),
            order: ThreadOrder::Latest,
            scope: ThreadScope::Answered,
        },
    };

    let html = search::search(&view);
    assert!(html.contains(r#"method="get" action="/search""#));
    assert!(html.contains("up to 50 results (a bounded set, not a total count)"));
    assert!(html.contains("Matched in the accepted answer"));
    assert!(html.contains("&lt;mark&gt;bounded excerpt&lt;/mark&gt;"));
    assert!(!html.contains("<mark>bounded excerpt</mark>"));
    assert!(html.contains("&quot;quoted&quot; &lt;query&gt;"));
    assert_eq!(html.matches("<h1").count(), 1);
    assert!(html.contains(r#"<h2 class="eyebrow ag-eyebrow" id="ag-search-results-title">"#));
}
