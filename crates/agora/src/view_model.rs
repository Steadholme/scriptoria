//! Authority-free presentation data for Agora's pure server-rendered views.
//!
//! Handlers construct these owned values only after authentication, authorization, Store
//! loading, accepted-answer validation, CSRF minting, and private-state isolation.  Views may
//! format and escape them, but must not infer permissions or recover authority from opaque
//! values.  Stable gateway subjects (`author_sub`, `owner_sub`, and `actor_sub`) deliberately
//! have no representation in this module.

/// Untrusted display text.  A view must HTML-escape the inner value at interpolation time.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Text(pub String);

/// HTML produced by the server's sanitizing Markdown renderer.
///
/// A pure view may emit the inner value verbatim.  Handlers must never construct this from
/// untrusted HTML without passing through the sanitizer first.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SafeHtml(pub String);

/// An already-authorized token, cursor, identifier, or URL.
///
/// The value is intentionally opaque to the view.  Attribute interpolation still requires HTML
/// escaping.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Opaque(pub String);

/// Response privacy selected by the handler layer.  Pure views do not make cache decisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheClass {
    PrivateNoStore,
    PublicStatic,
}

/// The application-bar destination selected by the handler, never inferred from a page title.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NavTab {
    Home,
    New,
    Search,
    Activity,
    Bookmarks,
}

/// Request-derived private counters.  `None` means unavailable, not a painted zero.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PersonalCounts {
    pub unread_activity: Option<i64>,
    pub due_bookmarks: Option<i64>,
}

/// Shared chrome passed to every full-page renderer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageChrome {
    pub title: Text,
    /// Raw display text projected from identity data. Adapters must not pre-escape it; the view
    /// performs the single HTML-escaping pass.
    pub viewer_email: Option<Text>,
    pub active_nav: NavTab,
    pub counts: PersonalCounts,
    pub cache: CacheClass,
}

/// Presentation copy selected for an already-authorized action.
///
/// The enum does not grant authority.  A control exists only when a handler supplies the
/// corresponding [`LinkActionVM`] or [`FormActionVM`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionKind {
    EditReply,
    EditThread,
    DeleteThreadReview,
    DeleteReplyReview,
    DeleteAdminReview,
    DeleteConfirm,
    Quote,
    BookmarkSave,
    BookmarkEdit,
    SaveBookmarkChanges,
    AcceptAnswer,
    RemoveSolution,
    ClearInvalidSolution,
    UpdateSubscription,
    ApplyFocus,
    SaveFocusRule,
    OpenActivity,
    MarkPageRead,
    MarkThreadPageRead,
    MarkRead,
    MarkUnread,
    CompleteBookmark,
    SnoozeTomorrow,
    SnoozeWeek,
    RemoveBookmark,
    CreateCategory,
    RenameCategory,
    SetCategoryFormat,
    MoveThread,
    MoveCategoryUp,
    MoveCategoryDown,
    Lock,
    Unlock,
    Pin,
    Unpin,
    AddBan,
    Unban,
    PublishThread,
    SaveThread,
    SaveReply,
    PostReply,
    PostAnswer,
    ToggleReaction,
}

/// One opaque hidden field in an action form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HiddenField {
    pub name: Text,
    pub value: Opaque,
}

/// A non-mutating navigation descriptor signed off by the handler layer.
///
/// Keeping links separate from forms makes it impossible for a list view to accidentally receive
/// or render a destructive commit token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkActionVM {
    pub href: Opaque,
    pub label_kind: ActionKind,
}

/// A complete POST form descriptor signed off by the handler layer.
///
/// `action`, CSRF, CAS values, redirect targets, and any other hidden fields are opaque.  Views
/// render them unchanged and never mint or reinterpret them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FormActionVM {
    pub action: Opaque,
    pub label_kind: ActionKind,
    pub csrf: Opaque,
    pub fields: Vec<HiddenField>,
}

/// Consequences displayed before an irreversible mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsequenceVM {
    pub summary: Text,
    pub detail: Option<Text>,
}

/// The standalone no-JavaScript consequence-review page.
///
/// This is the only presentation model allowed to contain a destructive commit form.  Thread,
/// post, category, and admin list models carry only [`LinkActionVM`] review entries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestructiveReviewVM {
    pub heading: Text,
    pub consequence: ConsequenceVM,
    pub commit: FormActionVM,
    pub cancel_href: Opaque,
}

/// A safe, already-classified HTML error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErrorView {
    pub heading: Text,
    pub message: Text,
    pub correlation_id: Option<Opaque>,
}

/// Product behavior of a category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadKind {
    Discussion,
    Question,
}

/// Valid answer state after the handler has resolved any historical accepted-answer pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnswerState {
    NotApplicable,
    NeedsAnswer,
    Answered,
}

/// The only semantic claim the accepted-answer treatment is permitted to make.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceptanceMeaning {
    AcceptedByAskerOrAuthorizedModerator,
}

/// Stable category facts without presentation tone or CSS decisions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CategoryRefVM {
    pub id: Opaque,
    pub name: Text,
}

/// Category facts used in lists and forms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CategoryVM {
    pub category: CategoryRefVM,
    pub kind: ThreadKind,
    pub sort_order: i64,
}

/// Whether a visible count is exact or intentionally bounded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CountKind {
    Exact,
    Bounded,
    Partial,
}

/// A visible count and its explicit authority boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CountVM {
    pub value: i64,
    pub kind: CountKind,
    pub bound: Option<i64>,
    pub scope: Text,
}

/// A typed list-order selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadOrder {
    Latest,
    Top,
    Hot,
}

/// Question-state filtering selected by the request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadScope {
    Any,
    Questions,
    Answered,
    Unanswered,
}

/// A server-issued page link.  The view neither parses nor edits its cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageLinkVM {
    pub href: Opaque,
    pub label: Text,
}

/// Exact keyset-navigation state for a bounded result page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaginationVM {
    /// Exact handler-issued link to the preceding page in the current surface's reading order.
    pub previous: Option<PageLinkVM>,
    /// Exact handler-issued link to the following page in the current surface's reading order.
    pub next: Option<PageLinkVM>,
    /// Optional handler-issued shortcut such as a thread's exact latest-page target. The view
    /// renders this opaque href verbatim and never reconstructs cursor or route state.
    pub jump: Option<PageLinkVM>,
    pub at_start: bool,
    pub at_end: bool,
    pub visible_limit: i64,
}

/// Explicit non-success list states.  An empty collection with `Ready` is valid populated-state
/// data only when another field explains it; handlers should otherwise select a precise variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectionState {
    Ready,
    ReadyEmpty,
    End,
    FilteredZero,
    TooShort,
    InvalidCursor,
    Unavailable,
}

/// Shared thread truth used by the thread page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThreadShared {
    pub id: Opaque,
    pub title: Text,
    pub category: Option<CategoryRefVM>,
    pub kind: ThreadKind,
    pub answer_state: AnswerState,
    pub author_display: Text,
    pub created_at: i64,
    /// Exact total posts when the handler loaded it. `None` means unknown and must not be painted
    /// as zero; `Some(1)` truthfully means the original post with zero replies.
    pub post_count: Option<i64>,
    pub pinned: bool,
    pub locked: bool,
}

/// A server-authorized subscription form and its current private value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionFormVM {
    pub selected: ThreadFollowLevelVM,
    pub submit: FormActionVM,
}

/// Private relationship between the current viewer and a thread.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadFollowLevelVM {
    None,
    Watch,
    Follow,
    Mute,
}

/// Private thread-page overlays.  Booleans are facts computed by handlers, not permissions for
/// views to reinterpret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThreadViewerState {
    pub subscription: Option<SubscriptionFormVM>,
    pub edit: Option<LinkActionVM>,
    pub delete_review: Option<LinkActionVM>,
    pub clear_invalid_solution: Option<FormActionVM>,
}

/// Sanitized same-thread quotation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuoteVM {
    pub post_id: Opaque,
    pub author_display: Text,
    pub created_at: i64,
    pub body: SafeHtml,
}

/// Aggregate reaction truth plus the current viewer's private membership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReactionVM {
    pub kind: Text,
    pub count: i64,
    pub mine: Option<bool>,
    pub toggle: Option<FormActionVM>,
}

/// Private overlays on one post.  `None` means the handler could not establish the private fact.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PostViewerState {
    pub bookmarked: Option<bool>,
    pub unread: Option<bool>,
    pub resume_anchor: Option<Opaque>,
}

/// Server-issued controls for one post.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PostActionsVM {
    pub edit: Option<LinkActionVM>,
    /// All independently-authorized review entries. An author who is also an administrator may
    /// legitimately receive both owner and admin deletion reviews.
    pub delete_reviews: Vec<LinkActionVM>,
    pub quote: Option<LinkActionVM>,
    pub bookmark: Option<PostBookmarkActionVM>,
    pub accept: Option<FormActionVM>,
    pub remove_solution: Option<FormActionVM>,
}

/// Private saved-state copy for an already-bookmarked post.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SavedBookmarkStateVM {
    Saved,
    Due,
    Scheduled,
}

/// A post is either saveable with a POST or already saved with an exact edit link.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PostBookmarkActionVM {
    Save(FormActionVM),
    Saved {
        edit: LinkActionVM,
        state: SavedBookmarkStateVM,
    },
}

/// A post after identity projection, Markdown sanitization, and permission checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostVM {
    pub id: Opaque,
    pub author_display: Text,
    pub created_at: i64,
    pub body: SafeHtml,
    pub is_op: bool,
    pub quote: Option<QuoteVM>,
    pub reactions: Vec<ReactionVM>,
    pub viewer: PostViewerState,
    pub actions: PostActionsVM,
}

/// A valid accepted answer, kept structurally separate from ordinary reply chronology.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnswerDaisVM {
    pub post: PostVM,
    pub acceptance: AcceptanceMeaning,
}

/// Current viewer's exact, owner-scoped reading projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadingProgressVM {
    pub started: bool,
    pub unread_count: Option<i64>,
    pub first_unread_href: Option<Opaque>,
    pub resume_href: Option<Opaque>,
    pub mark_page_read: Option<FormActionVM>,
}

/// Page-local, bounded extractive summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SummaryVM {
    pub sentences: Vec<Text>,
    pub source_post_count: i64,
    pub source_word_count: i64,
    pub sentence_bound: i64,
}

/// Why a summary was not rendered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SummaryUnavailableReason {
    TooFewPosts,
    TooFewWords,
    Unavailable,
}

/// Complete typed summary state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SummaryStateVM {
    Available(SummaryVM),
    Unavailable(SummaryUnavailableReason),
}

/// Reply composer or a shared locked-state notice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplyFormVM {
    Available {
        submit: FormActionVM,
        body: Text,
        quoted_post_id: Option<Opaque>,
    },
    LockedNotice {
        message: Text,
    },
    UnavailableNotice {
        heading: Text,
        message: Text,
    },
}

/// Admin-only server-issued controls for a thread.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AdminThreadToolbarVM {
    pub move_thread: Option<MoveThreadFormVM>,
    pub lock: Option<FormActionVM>,
    pub pin: Option<FormActionVM>,
    pub delete_review: Option<LinkActionVM>,
}

/// Complete thread page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThreadView {
    pub chrome: PageChrome,
    pub shared: ThreadShared,
    pub viewer: ThreadViewerState,
    pub op: PostVM,
    pub dais: Option<AnswerDaisVM>,
    pub replies: Vec<PostVM>,
    pub pagination: PaginationVM,
    pub reply_form: ReplyFormVM,
    pub summary: SummaryStateVM,
    pub reading: ReadingProgressVM,
    pub admin: Option<AdminThreadToolbarVM>,
    pub now: i64,
}

/// Shared facts for one thread row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThreadRowShared {
    pub id: Opaque,
    pub title: Text,
    pub category: Option<CategoryRefVM>,
    pub kind: ThreadKind,
    pub answer_state: AnswerState,
    pub author_display: Text,
    pub created_at: i64,
    pub last_at: i64,
    /// Exact total posts when loaded; `None` is unknown, never a synthetic zero.
    pub post_count: Option<i64>,
    pub pinned: bool,
    pub locked: bool,
}

/// Private overlay for one thread row.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ThreadRowViewerState {
    pub follow_level: Option<ThreadFollowLevelVM>,
    pub bookmarked: Option<bool>,
    pub unread_count: Option<i64>,
    pub resume_href: Option<Opaque>,
}

/// A shared-truth row plus its separately keyed private overlay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThreadRowVM {
    pub shared: ThreadRowShared,
    pub viewer: ThreadRowViewerState,
}

/// One exact sort link supplied by the handler. The view never rewrites query parameters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThreadOrderLinkVM {
    pub order: ThreadOrder,
    pub href: Opaque,
}

/// One exact question-state link supplied by the handler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThreadScopeLinkVM {
    pub scope: ThreadScope,
    pub href: Opaque,
}

/// Independent list dimensions and their exact navigation targets.
///
/// `subscribed_only` is deliberately separate from question scope. `questions` is the optional
/// product CTA into the Questions view, not a scope value inferred by presentation code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThreadListControlsVM {
    pub active_order: ThreadOrder,
    pub active_scope: ThreadScope,
    pub subscribed_only: bool,
    pub order_links: Vec<ThreadOrderLinkVM>,
    pub scope_links: Vec<ThreadScopeLinkVM>,
    pub subscribed_toggle: Option<PageLinkVM>,
    pub questions: Option<PageLinkVM>,
}

/// Public category terraces and shared list controls on the forum home.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HomeShared {
    pub categories: Vec<CategoryVM>,
    pub controls: ThreadListControlsVM,
    pub state: CollectionState,
    pub visible_bound: i64,
    pub now: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HomeView {
    pub chrome: PageChrome,
    pub shared: HomeShared,
    /// Shared facts and their private overlay travel as the same keyed row; no positional zip.
    pub rows: Vec<ThreadRowVM>,
}

/// Shared facts for one category terrace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CategoryPageShared {
    pub category: CategoryVM,
    pub controls: ThreadListControlsVM,
    pub state: CollectionState,
    pub visible_bound: i64,
    pub now: i64,
}

/// Server-issued focus action for a category page.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CategoryPageViewerState {
    pub focus: Option<CategoryFocusFormVM>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CategoryView {
    pub chrome: PageChrome,
    pub shared: CategoryPageShared,
    /// Shared facts and their private overlay travel as the same keyed row; no positional zip.
    pub rows: Vec<ThreadRowVM>,
    pub viewer: CategoryPageViewerState,
}

/// The kind of editor selected by the handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComposeMode {
    NewThread,
    EditThread,
    EditReply,
}

/// Shared choices and labels for a compose page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComposeShared {
    pub mode: ComposeMode,
    pub heading: Text,
    pub categories: Vec<CategoryVM>,
    pub selected_category: Option<Opaque>,
    pub thread_kind: Option<ThreadKind>,
}

/// Current draft and the already-authorized submission descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComposeViewerState {
    pub title: Text,
    pub body: Text,
    pub quoted_post_id: Option<Opaque>,
    pub submit: FormActionVM,
    pub cancel_href: Opaque,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComposeView {
    pub chrome: PageChrome,
    pub shared: ComposeShared,
    pub viewer: ComposeViewerState,
}

/// Active task-oriented catch-up tab.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatchUpTab {
    Updates,
    Following,
    Questions,
}

/// Strongest authoritative reason a private catch-up row exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatchUpReasonVM {
    Watch,
    Follow,
    Authored,
    Bookmarked,
    Participated,
    ContinueReading,
}

/// Valid Question state for one catch-up row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatchUpQuestionStateVM {
    Waiting,
    Solved,
}

/// The private explanation attached to a shared catch-up thread.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatchUpItemViewerState {
    pub reason: CatchUpReasonVM,
    pub follow_level: ThreadFollowLevelVM,
    pub unread_count: i64,
    pub first_unread_href: Option<Opaque>,
    pub question_state: Option<CatchUpQuestionStateVM>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatchUpItemVM {
    pub shared: ThreadRowShared,
    pub viewer: CatchUpItemViewerState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatchUpFeedShared {
    pub active: CatchUpTab,
    pub snapshot_as_of: i64,
    pub visible_bound: i64,
    pub state: CollectionState,
    pub now: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatchUpFeedViewerState {
    pub items: Vec<CatchUpItemVM>,
    pub pagination: PaginationVM,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatchUpFeedVM {
    pub chrome: PageChrome,
    pub shared: CatchUpFeedShared,
    pub viewer: CatchUpFeedViewerState,
}

/// Current viewer's explicit category-focus level.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CategoryFocusLevelVM {
    None,
    Priority,
    Follow,
    Mute,
}

/// Winning private reason a focused thread is visible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CategoryFocusReasonVM {
    CategoryPriority,
    CategoryFollow,
    ThreadWatchOverride,
    ThreadFollowOverride,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CategoryFocusFormVM {
    pub selected: CategoryFocusLevelVM,
    pub saved: bool,
    pub submit: FormActionVM,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FocusRuleVM {
    pub category: CategoryVM,
    pub level: CategoryFocusLevelVM,
    pub submit: FormActionVM,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FocusItemVM {
    pub shared: ThreadRowShared,
    pub category_level: CategoryFocusLevelVM,
    pub thread_level: ThreadFollowLevelVM,
    pub reason: CategoryFocusReasonVM,
    pub viewer: ThreadRowViewerState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FocusShared {
    pub visible_thread_bound: i64,
    pub rule_bound: i64,
    pub state: CollectionState,
    pub now: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FocusViewerState {
    pub rules: Vec<FocusRuleVM>,
    pub items: Vec<FocusItemVM>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FocusView {
    pub chrome: PageChrome,
    pub shared: FocusShared,
    pub viewer: FocusViewerState,
}

/// Immutable kind of an activity event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivityKindVM {
    PostCreated,
    AnswerAccepted,
}

/// Best private delivery reason retained after duplicate paths are collapsed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivityReasonVM {
    Mention,
    Reply,
    Following,
    Answer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivityFilterVM {
    All,
    Mention,
    Reply,
    Following,
    Answer,
}

/// Read-state scope is independent from the delivery-reason filter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivityReadScopeVM {
    All,
    Unread,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityFilterLinkVM {
    pub filter: ActivityFilterVM,
    pub link: PageLinkVM,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityReadScopeLinkVM {
    pub scope: ActivityReadScopeVM,
    pub link: PageLinkVM,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityItemShared {
    pub id: Opaque,
    pub kind: ActivityKindVM,
    pub thread_id: Opaque,
    pub post_id: Opaque,
    pub thread_title: Text,
    /// Bounded plain-text excerpt, escaped by the view.
    pub post_excerpt: Text,
    pub actor_display: Text,
    pub created_at: i64,
}

/// The activity-open mutation and its exact post redirect.
///
/// `submit.fields` contains only additional opaque fields; the exact target is rendered once as
/// the endpoint's `next` field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityOpenFormVM {
    pub submit: FormActionVM,
    pub exact_target: Opaque,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityItemViewerState {
    pub reason: ActivityReasonVM,
    pub read: bool,
    /// POST that both marks this event read and redirects to its handler-issued exact post target.
    pub open: ActivityOpenFormVM,
    pub toggle_read: FormActionVM,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityItemVM {
    pub shared: ActivityItemShared,
    pub viewer: ActivityItemViewerState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityShared {
    pub active_filter: ActivityFilterVM,
    pub read_scope: ActivityReadScopeVM,
    pub filter_links: Vec<ActivityFilterLinkVM>,
    pub read_scope_links: Vec<ActivityReadScopeLinkVM>,
    pub visible_bound: i64,
    pub state: CollectionState,
    pub now: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityViewerState {
    pub items: Vec<ActivityItemVM>,
    pub pagination: PaginationVM,
    pub mark_page_read: Option<FormActionVM>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityView {
    pub chrome: PageChrome,
    pub shared: ActivityShared,
    pub viewer: ActivityViewerState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BookmarkStateVM {
    All,
    Due,
    Scheduled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BookmarkItemShared {
    pub post_id: Opaque,
    pub thread_id: Opaque,
    pub thread_title: Text,
    pub post_author_display: Text,
    /// Handler-issued exact post target, including the around cursor and fragment.
    pub exact_post_href: Opaque,
    /// Bounded plain-text excerpt, escaped by the view.
    pub post_excerpt: Text,
    pub post_created_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BookmarkItemViewerState {
    pub note: Text,
    pub remind_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    pub edit: LinkActionVM,
    pub remove: FormActionVM,
    pub done: Option<FormActionVM>,
    pub snooze_tomorrow: Option<FormActionVM>,
    pub snooze_week: Option<FormActionVM>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BookmarkItemVM {
    pub shared: BookmarkItemShared,
    pub viewer: BookmarkItemViewerState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BookmarksShared {
    pub active_state: BookmarkStateVM,
    pub visible_bound: i64,
    pub state: CollectionState,
    pub now: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BookmarksViewerState {
    pub items: Vec<BookmarkItemVM>,
    pub pagination: PaginationVM,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BookmarksView {
    pub chrome: PageChrome,
    pub shared: BookmarksShared,
    pub viewer: BookmarksViewerState,
}

/// Reminder operation selected by the bookmark editor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BookmarkReminderChoiceVM {
    Keep,
    None,
    Tomorrow,
    Week,
    Custom,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BookmarkEditShared {
    pub thread_title: Text,
    pub exact_post_href: Opaque,
    pub current_reminder_at: Option<i64>,
    pub note_max_chars: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BookmarkEditViewerState {
    pub note: Text,
    pub selected_reminder: BookmarkReminderChoiceVM,
    pub custom_time: Text,
    /// Contains handler-issued CSRF and bookmark-id/version CAS fields.
    pub save: FormActionVM,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BookmarkEditView {
    pub chrome: PageChrome,
    pub shared: BookmarkEditShared,
    pub viewer: BookmarkEditViewerState,
}

/// Validation state of a search query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchQueryState {
    Empty,
    TooShort,
    Valid,
    Invalid,
}

/// Which body made a result match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchMatchSource {
    Topic,
    AcceptedAnswer,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchResultVM {
    pub thread: ThreadRowShared,
    /// Bounded plain-text excerpt, escaped by the view.
    pub excerpt: Text,
    pub source: SearchMatchSource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchShared {
    pub categories: Vec<CategoryVM>,
    pub query_state: SearchQueryState,
    pub results: Vec<SearchResultVM>,
    pub visible_bound: i64,
    pub state: CollectionState,
    pub now: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchViewerState {
    pub query: Text,
    pub selected_category: Option<Opaque>,
    pub order: ThreadOrder,
    pub scope: ThreadScope,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchView {
    pub chrome: PageChrome,
    pub shared: SearchShared,
    pub viewer: SearchViewerState,
}

/// Compose-time similarity evidence; it is explicitly heuristic and bounded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimilarThreadVM {
    pub thread_id: Opaque,
    pub title: Text,
    pub category_id: Opaque,
    pub score_basis_points: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimilarityEvidenceVM {
    pub candidates_scanned_bound: i64,
    pub result_bound: i64,
    pub threshold_basis_points: i64,
    pub results: Vec<SimilarThreadVM>,
}

/// Complete, validated shape of the admin create-category form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateCategoryFormVM {
    pub id: Text,
    pub name: Text,
    pub selected_kind: ThreadKind,
    pub id_max_chars: usize,
    pub name_max_chars: usize,
    pub submit: FormActionVM,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenameCategoryFormVM {
    pub name_max_chars: usize,
    pub submit: FormActionVM,
}

/// Complete move form with the current category and all handler-authorized destinations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MoveThreadFormVM {
    pub selected_category: Opaque,
    pub categories: Vec<CategoryRefVM>,
    pub submit: FormActionVM,
}

/// Complete admin ban form. `subject_input` is an untrusted admin draft, not established identity
/// truth; the handler validates it on submit. Existing stable subjects remain sealed in actions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddBanFormVM {
    pub subject_input: Text,
    pub reason: Text,
    pub author_sub_max_chars: usize,
    pub reason_max_chars: usize,
    pub submit: FormActionVM,
}

/// Admin category row.  Every control was issued after a verified admin-group decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminCategoryVM {
    pub category: CategoryVM,
    pub rename: RenameCategoryFormVM,
    pub set_format: FormActionVM,
    pub move_up: Option<FormActionVM>,
    pub move_down: Option<FormActionVM>,
    pub delete_review: LinkActionVM,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminThreadVM {
    pub thread: ThreadRowShared,
    pub toolbar: AdminThreadToolbarVM,
}

/// Sanitized moderation history for a banned author.  The stable gateway subject is intentionally
/// absent; any unban authority and target are sealed inside `unban`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BannedAuthorVM {
    /// Handler-approved display label; never reconstructed from the sealed unban target.
    pub author_display: Text,
    pub reason: Text,
    pub banned_by: Text,
    pub created_at: i64,
    pub unban: FormActionVM,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminShared {
    pub visible_thread_bound: i64,
    pub state: CollectionState,
    pub now: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminViewerState {
    pub create_category: CreateCategoryFormVM,
    pub add_ban: AddBanFormVM,
    pub categories: Vec<AdminCategoryVM>,
    pub threads: Vec<AdminThreadVM>,
    pub banned_authors: Vec<BannedAuthorVM>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminView {
    pub chrome: PageChrome,
    pub shared: AdminShared,
    pub viewer: AdminViewerState,
}
