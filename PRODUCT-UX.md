# Scriptoria Product UX Program

Scriptoria hosts six products in one Rust process, but Forum, Drive, and Blog are not three
skins over one dashboard. They have different jobs, interaction density, public exposure, and
trust boundaries. This program gives each product its own information architecture and runtime
while keeping Odyssey at the Foundation layer only.

## Product ownership contract

- Odyssey may provide scoped design tokens, focus treatment, reduced-motion behavior, and shared
  status semantics.
- Each product owns its DOM, URL state, components, client state, caching, interaction model, and
  motion.
- A product must not depend on Odyssey Wire or Spark for its defining workflow. Every mutation
  keeps a real HTML form and server-side authorization/CSRF fallback.
- A pattern is promoted into Odyssey Components only after at least two products independently
  prove the same behavior and accessibility contract.
- Scriptoria's Host demultiplexer, Sluice routes, authentication, and capability URLs remain
  access authorities. UI code never widens exposure.

`public` in Experience Manifest means discoverable from the public product plane. It does not
mean anonymous: Forum and Blog roots are SSO protected. Drive has anonymous capability surfaces
under `/s/` and `/u/` and therefore carries the strictest public-content regression gates.

## Competitor evidence

### Forum / Agora

GitHub Discussions separates open discussions, Q&A, announcements, and polls, supports accepted
answers, pinning, labels, filtering, and upvotes. Discourse adds category/tag notification levels,
unread state, bookmarks, trust, and global search. Agora already has categories, reactions,
accepted answers, following, mentions, quotes, and Latest/Top/Hot ordering; its largest gap is
discovery and return behavior, not another card layout.

- <https://docs.github.com/en/discussions/collaborating-with-your-community-using-discussions/about-discussions>
- <https://docs.github.com/en/discussions/managing-discussions-for-your-community/managing-categories-for-discussions>
- <https://docs.github.com/en/search-github/searching-on-github/searching-discussions>
- <https://meta.discourse.org/t/discourse-solved/30155>
- <https://meta.discourse.org/t/understanding-discourse-trust-levels/90752>
- <https://meta.discourse.org/t/improved-bookmarks-with-reminders/144542>
- <https://github.com/discourse/discourse/blob/main/app/models/bookmark.rb>
- <https://github.com/discourse/discourse/blob/main/app/jobs/scheduled/bookmark_reminder_notifications.rb>

### Drive / Aperture

Google Drive treats search, filter chips, sorting, list/grid modes, preview, and activity as one
continuous explorer. Dropbox makes preview, comments, sharing, downloads, and file requests part
of the same quick-view flow. Proton Drive makes share state, password/expiry, shared-with-me, and
version history explicit. Aperture must not imply end-to-end encryption it does not implement;
its honest differentiation is self-hosted storage, auditable capability links, and public upload
rooms.

- <https://support.google.com/drive/answer/2375114?hl=en>
- <https://help.dropbox.com/view-edit/preview>
- <https://help.dropbox.com/share/create-file-request>
- <https://help.dropbox.com/share/received-file-request>
- <https://proton.me/support/drive-web-guide>
- <https://proton.me/support/drive-shareable-link>
- <https://support.google.com/drive/answer/2375102>
- <https://support.google.com/drive/answer/1716222>
- <https://support.google.com/drive/answer/13318592>
- <https://help.dropbox.com/organize/select-multiple-files>
- <https://help.dropbox.com/delete-restore/recover-deleted-files-folders>
- <https://help.dropbox.com/delete-restore/deleted-files>

### Blog / Inkwell

Ghost makes Draft, Preview, Publish, Schedule, web/email/social preview, tags, post settings, and
history one coherent Writer workflow. Inkwell already has Markdown, sanitized preview, scheduled
publishing, tags, covers, local crash recovery, RSS, sitemap, search, and cited Ask. Its highest
value gap is a reliable Writer state machine, not newsletters or payments.

- <https://ghost.org/help/publishing-content/>
- <https://ghost.org/help/post-settings/>
- <https://ghost.org/help/organizing-content/>
- <https://ghost.org/changelog/bulk-actions/>
- <https://ghost.org/help/cards/>
- <https://help.medium.com/hc/en-us/articles/360033930293-Set-a-canonical-link>
- <https://wordpress.org/documentation/article/posts-screen/>
- <https://wordpress.org/documentation/article/post-status/>

## Iteration 1: find, share, publish

### Forum: Search-first

- Add shareable server-rendered search over thread titles and original posts.
- Add a bounded same-origin suggestion endpoint and a keyboard-accessible quick-search surface.
- Preserve no-JavaScript form submission and make query/category state part of the URL.
- Call subscriptions `Following` until notification fan-out is actually guaranteed.

Acceptance: bounded and escaped results, category filtering, stable URLs, PostgreSQL and memory
parity, no authorization changes, keyboard access, and no Odyssey runtime dependency for search.

### Drive: Public Share Room

- Give file shares, folder shares, password prompts, and upload inboxes one trustworthy Share Room
  information architecture.
- Show what is shared, who controls it when safely available, expiry/password state, and the exact
  primary action without exposing owner identifiers or internal storage details.
- Enhance upload inboxes with a product-owned multi-file queue, per-file progress, retry, and a
  completion receipt while preserving the single-file no-JavaScript form.
- Public Share Room pages must not load Odyssey Wire or Spark.

Acceptance: anonymous capability flows remain scoped to `/s/` and `/u/`; owner pages fail closed
without gateway identity in production; expired/password/XSS cases remain safe; no capability or
route is widened.

### Blog: Writer Studio

- Make Draft, Publish now, and Schedule explicit server intents. New posts start as Draft.
- Add Write, Split preview, and Reader preview modes using the same server sanitizer as published
  content.
- Present a truthful Saving/Saved/Published/Scheduled/Error state. Local storage is disaster
  recovery, not authoritative persistence.
- Interpret scheduling in the writer's local timezone while retaining a clear UTC/no-JavaScript
  fallback.
- Suggest existing tags through a bounded, escaped, read-only endpoint.

Acceptance: drafts and scheduled posts never enter reader, feed, sitemap, search, or Ask before
their visibility time; preview parity and sanitization remain exact; no-JavaScript save/publish
continues to work.

## Iteration 2: resolve, request, distribute

### Forum: Q&A Answer Desk

- Persist `discussion` and `question` category formats and give Support question semantics.
- Add a stable `/questions` answer desk plus Answered/Unanswered URL filters.
- Keep the accepted solution directly below the original post even when its natural reply is on a
  different keyset page, without duplicating it or shrinking the ordinary-reply page.
- Search accepted solution text and identify when a result matched the solution rather than the
  question body.
- Reject new accepted answers outside question categories and reject category/move transitions
  that would strand an existing solution; historical accepted discussions remain readable and can
  be cleared.

Acceptance: PostgreSQL migration is idempotent and never overwrites an operator's later format
choice; status filters are enforced in Store queries; Memory/PostgreSQL search and pagination agree;
all answer mutations retain author/admin authorization and CSRF.

### Drive: Request Rooms v2

- Replace the folder-token flag as the active product model with independent upload requests that
  own title, instructions, state, deadline, MIME policy, per-file limit, cumulative byte limit, and
  cumulative file-count limit.
- Give owners `/requests` and `/requests/{id}` control-plane views for receipts, close/reopen,
  update, and token rotation while preserving the public `/u/{token}` URL contract.
- Reserve request capacity and the configured owner quota atomically before writing a blob, then
  commit the private file + immutable receipt or release the reservation and compensate the blob.
- Backfill legacy folder upload tokens without changing their URLs, and recover abandoned
  reservations at startup so a process failure cannot consume room capacity forever.
- Rotate capability tokens with compare-and-swap semantics, reopen only lifecycle fields, and keep
  the same owner quota guard across reservation hand-off so concurrent control-plane commands
  cannot overwrite policy or hide committed bytes from a new reservation.
- Make ordinary and requested uploads private by default; an owner must explicitly create a read
  capability.

Acceptance: closed/expired/rotated links disclose no destination or quota detail; concurrent rooms
for one owner cannot overrun their public-request quota decision; blob/DB failures leave neither an
orphan file row nor an unrecoverable blob; a failed blob delete retains its reservation as the
recovery anchor; legacy token conflicts fail migration instead of silently rebinding a capability;
startup recovery claims every outstanding reservation or none; no-JavaScript single-file upload
and the multi-file queue use the same server authority.

### Blog: Publication Pack

- Add custom excerpt, search metadata, canonical URL, and social-card overrides to Writer Studio
  with bounded server validation and browser recovery.
- Emit typed, escaped canonical/description/OpenGraph/Twitter metadata only for reader-visible
  posts. Draft and future Scheduled owner views emit `noindex,nofollow` and no share metadata.
- Prefer the custom excerpt on cards and RSS while preserving a body-derived fallback.
- Traverse sparse Tag archives through authoritative visible-post keysets, cap RSS at the newest
  100 public posts, and traverse Sitemap independently up to the protocol ceiling; externally
  canonicalized posts stay out of the local Sitemap.

Acceptance: metadata cannot inject HTML or unsafe URL schemes; Draft/Scheduled content cannot leak
through head tags, Tag, RSS, Sitemap, Search, or Ask; Memory/PostgreSQL metadata round-trip and
derived-index visibility/version joins remain consistent.

## Iteration 3: return, retrieve, recover

### Forum: Durable Activity Inbox

- Replace the home-only permanent Mentions list with an owner-scoped `/activity` inbox for mention,
  direct reply/quote, followed-thread reply, and accepted-answer events.
- Create reply/mention/follower activity in the same Store command as the post, and accepted-answer
  activity in the same command as the solution mutation. Events carry target identity and actor,
  never a stale copy of the post body.
- Add stable All/Unread/reason URL filters, `(created_at,id)` keyset pagination, unread count, Open
  and mark-read/mark-unread commands. Bulk triage is explicitly “Mark this page read”: the server
  accepts at most the 30 event ids it just rendered and re-authorizes every id, so no request hides
  an unbounded whole-stream transaction behind a “Mark all” label.
- Replace subscription toggle writes with explicit idempotent Follow/Unfollow commands so retries
  and concurrent tabs cannot invert state twice.
- Resolve each mention alias to one stable gateway subject at event-write time. Alias mappings are
  append-only; ambiguous aliases fail closed, and Activity reads/receipts never authorize through
  a mutable email local-part. A thread accepts at most 256 followers and one post at most 32
  distinct mentions; an over-cap reply fails before either post or activity is written.

Acceptance: self-notifications and duplicate recipient reasons follow one documented precedence;
delivery/receipt rows cascade with their event, so concurrent delete/read cannot leave an orphan;
Memory/PostgreSQL ordering and read state agree; recipient fan-out is bounded and atomic; all owner
actions retain subject identity, CSRF, and no-JavaScript form behavior.

### Drive: Library Control Plane

- Give the owner library URL-backed `q`, `view=recent|shared`, and
  `type=folder|image|video|audio|pdf|document|archive|other` controls across the full tree.
- Add authoritative `updated_at` semantics for files and folders. Upload, re-upload, rename, move,
  restore, and share-policy changes advance it strictly even within one wall-clock second;
  anonymous view counts do not reorder the library. The only non-strict boundary is an already
  corrupted/synthetic `i64::MAX` value, which saturates instead of overflowing PostgreSQL BIGINT.
- Return a unified owner-scoped File/Folder read model with stable `(sort_at,kind,id)` keyset
  pagination. Search defaults to names, Recent orders by owner mutation, and Shared means
  "shared by me" including expired/password-protected links that still need governance.
- Never return capability tokens through the read model, URL, markup, logs, or filter state, and do
  not add or widen `/s/` or `/u/` routes.

Acceptance: every PostgreSQL query starts with owner/live scope and matches Memory behavior;
backend errors propagate instead of rendering an empty library; filters compose and survive pager
links; 390 px and 1440 px retain keyboard/no-JavaScript access with no horizontal page overflow.

### Blog: Writer Durability

- Add private server autosave for existing-post edit sessions. Session id + monotonic client
  sequence reject stale/out-of-order requests; autosaves expire after seven days and never mutate
  post visibility, publication metadata, or the public index.
- Give authoritative posts an edit version. Explicit save/publish performs expected-version CAS,
  also matches the stable post id, appends a full Writer snapshot, updates the post, and consumes
  that session's autosave in one Store command. Delete/recreate of the same slug therefore cannot
  turn a stale tab into an ABA overwrite of another post identity.
- Add owner/admin revision history and atomic restore. Restore snapshots the current Writer state,
  restores content and discoverability metadata, and deliberately preserves the current
  Draft/Published/Scheduled, publish time, pin, and feature state.
- Keep `/new` local recovery until the first explicit Save draft creates an authoritative post;
  no-JavaScript save/publish remains the baseline, and a 409 conflict preserves submitted text as
  a recovery copy rather than silently overwriting another tab.
- Serve compose, editor/recovery, history, preview, autosave, and conflict responses as
  `private, no-store`. Fresh revision/autosave tables cascade on post delete; if a single-active
  rollback image writes without `edit_version`, the next candidate boot compares the same-version
  snapshot, advances the version, and records a `forward-repair` revision before accepting writes.

Acceptance: autosaves are readable only by their author (not an unrelated admin); revision and
post writes are one Memory/PG atomic command; stale versions and client sequences fail closed;
restore never changes public visibility implicitly; cleanup is bounded and public surfaces cannot
read autosave or revision rows; a legacy open form receives a recoverable 409 rather than 404 or
last-write-wins after the candidate deploys.

## Iteration 4: remember, recover, operate

### Forum: Personal Retrieval Loop

- Let a signed-in subject bookmark either the original post or a reply. A bookmark owns an
  optional private plain-text note and an optional UTC reminder; neither is visible to authors,
  admins, search, Activity, or another subject.
- Render `/bookmarks` as a stable keyset list with All, Scheduled, and Due URL states. A due item
  remains due until its owner explicitly chooses Done, Snooze, or Remove; opening the post does not
  silently complete it.
- Describe delivery honestly: the Due queue is evaluated when Forum is requested and does not
  claim email, push, or a background notification scheduler.
- Give every bookmark an immutable random identity plus an expected version. Delete/recreate of
  the same post bookmark cannot let a stale tab update or remove the replacement. Owner subject is
  the only authority, including for admins.
- Bound one account to 1,000 bookmarks, one page to 30 rows, one rendered-post lookup batch to 32
  ids, and every batch mutation to the exact stable identities that were rendered.

Acceptance: ensure is idempotent at quota; update, Done, Snooze, Remove, and delete races are CAS
linearizable; reminder count and Due rows share one request `as_of`; post deletion cascades without
orphans; all pages, redirects, conflicts, and mutations are `private, no-store`; JavaScript is not
required for any bookmark action.

### Drive: Recoverable Workspace

- Replace file-only delete state with one owner-scoped Trash model for both files and folders.
  A trashed folder is one root entry; descendants inherit its inactive scope without materialising
  duplicate Trash rows. Restore and permanent delete operate on the authoritative root.
- Add no-JavaScript multi-select commands for at most 200 stable file/folder identities. Move,
  Trash, restore, and permanent delete validate the complete selection before committing anything;
  ancestor duplicates are normalised, cycles fail closed, and public conflicts stay generic.
- Make `/s/` reads and `/u/` uploads inactive while their file/folder or any ancestor is trashed.
  Restoring the same root reactivates the existing capability rather than rotating or exposing its
  token.
- Retain Trash roots for 30 days. Permanent and retention purge commit metadata removal together
  with durable current/version/thumbnail delete jobs; a leased worker retries object deletion with
  bounded backoff, and poison or orphan rows cannot starve valid expired roots.
- Put every owner-side fresh upload, re-upload, version restore, and derived thumbnail behind a
  durable pre-put write intent. The intent exists before bytes are written, finalisation performs
  the metadata CAS and consumes the intent in one owner-guarded transaction, and startup/periodic
  recovery removes bytes left by a crash or losing purge race. Intent bytes count toward quota.
- Backfill legacy Trash entries in an exact, fail-closed transaction. PostgreSQL commands use one
  owner-guard-first lock order, and Memory implements the same lifecycle and request-close
  semantics.

Acceptance: Memory and PostgreSQL agree for nested Trash, bulk atomicity, capability inactivity,
request closure, restore, retention, and purge; reserve/commit/purge interleavings terminate without
deadlock; crashes before put, after put, and before finalise leave no unanchored blob; a legal
expired root remains claimable behind more than 200 poison rows. This schema is single-active and
forward-only after its first lifecycle/write-intent mutation: an image-only rollback is forbidden;
a true rollback restores both the database checkpoint and the Cairn object snapshot.

### Blog: Author Library

- Give each author a private `/library` with composable `q`, status, exact tag, fixed `as_of`, and
  stable `(updated_at,id)` keyset navigation. Admin membership does not widen this personal
  workspace; site-wide moderation remains `/admin`.
- Let an author atomically operate on at most 50 rendered stable id/version selections: Publish
  now, Move to draft, Pin, Unpin, Add tag, or Remove tag. A duplicate, foreign, missing, stale, or
  replaced row rejects the whole command with one generic conflict.
- Keep destructive bulk delete out of the Author Library. The existing admin delete path also uses
  one all-or-nothing stable-id/version command; deindex and audit happen only after commit.
- Preserve autosaves and revision history during Library actions. Old editors retain post-id plus
  version CAS, and a deleted/replaced target returns a private recoverable conflict rather than a
  last-write-wins update or a lost submission.
- Treat public caching as representation authority: anonymous public pages may be cached with a
  complete `Vary`, but any Cookie/identity/admin-personalised reader, Search, error, redirect, Ask,
  editor, History, or Library response is `private, no-store`. Ask never places a browser-specific
  CSRF token in a shared-cacheable response.

Acceptance: fixed-`as_of` pages cannot reclassify Scheduled rows mid-pagination; Memory/PostgreSQL
bulk commands lock and validate every selection before any write; delete/recreate ABA and BIGINT
version exhaustion fail closed; safe `return_to` values cannot create an open redirect or invalid
header; public reader/feed/sitemap/search authority still follows the committed post state.

## Iteration 5: focus, inspect, publish

Iteration 5 advances the existing v4 authority into product-native interaction models. It does not
add a shared Odyssey page runtime, a database migration, a new public route, or a new mutation
authority. The enhanced controls remain projections over the same SSR links and HTML forms.

### Forum: Conversation Focus

- Organize the home rail into Discover, For you, and Spaces. For you links Activity, Saved, and
  Following without conflating request-derived unread/due counts with outbound delivery.
- Give each thread one sticky reading toolbar for Latest, Reply/Answer, and the existing Follow
  form. Desktop and mobile presentations reuse that single CSRF form instead of cloning state.
- Render the accepted answer once inside a labelled Solution region directly after the original
  post. Locked threads expose no reply shortcut that can bypass the server permission check.
- Describe the extractive summary as sentences from posts visible on the current page; it must not
  claim whole-thread authority when reply pagination bounds its input.

Acceptance: the Follow form appears exactly once; Latest still resolves through keyset navigation;
the Solution post is neither duplicated nor detached from its owner/reaction/bookmark controls;
mobile fixed actions do not obscure anchors; all actions work as ordinary links/forms without
JavaScript.

### Drive: Explorer Priority

- On narrow screens, place the file canvas, breadcrumb, result count, and primary Files/Requests
  navigation before the full folder/action rail. The desktop rail remains the spatial workspace.
- In the enhanced client, keep the selection surface compact at zero selected items and expand it
  into a contextual action shelf only after real file/folder checkboxes are selected. The original
  bounded form remains visible and complete without JavaScript.
- Treat Trash as a Recovery Center for both files and folders. Do not render Library search/type
  controls that silently leave Trash; use item language, deletion time, and the authoritative
  automatic-deletion eligibility threshold, with Restore visually ahead of permanent deletion.

Acceptance: the DOM contains no duplicate upload/bulk forms or ids; selection never becomes an
unbounded cross-page promise; the mobile canvas precedes the rail and has no horizontal overflow;
Trash retains `view=trash` for every action and does not imply a filter the Store does not execute.

### Blog: Reader and Studio

- Keep public reader chrome focused on Posts, Search, and Ask, with one stable Studio entry that
  does not vary the shared representation merely to reveal an author session. Remove authoring
  calls to action from the publication masthead and empty public index.
- Make Studio the active information architecture for Library and Writer pages. Add URL-backed
  All, Draft, Scheduled, and Published tabs; move the exact-tag field into an Advanced disclosure.
- Under JavaScript, show the bounded bulk shelf only after selection, expose Select/Clear page and
  an honest selected count, and reveal the tag input only for add/remove-tag commands. The same
  max-50 stable-id/version form remains the no-JavaScript baseline.
- Name the current editor pane Article body preview: it renders the sanitized body, not a complete
  cover/byline/social/publication representation. A true full-document preview remains a later,
  separately-authorized product slice.

Acceptance: Reader and Studio navigation preserve complete cache `Vary`/private boundaries;
status tabs retain query/tag/fixed-`as_of` state while resetting the cursor; CSS cannot override the
bulk shelf's `hidden` attribute; Writer save/publish intents and recovery semantics are unchanged.

### Competitive reference — 2026-07-12

This comparison uses official product documentation, not visual-gallery screenshots. It guides the
next task slice without turning Scriptoria into a clone or claiming capabilities it does not own.

- Forum: [Discourse reading state](https://meta.discourse.org/t/understanding-discourse-for-new-users/96331),
  [GitHub Discussion categories](https://docs.github.com/en/discussions/managing-discussions-for-your-community/managing-categories-for-discussions),
  and [Stack Overflow accepted-answer semantics](https://stackoverflow.com/help/accepted-answer)
  agree that category intent, reading continuity, and answer provenance are separate concerns.
  Agora already has category-aware questions and one authoritative Solution region. Its next P0 is
  deterministic `Continue reading / First unread`, followed by three understandable Follow levels;
  it will not import Discourse's five-level notification menu, nested replies, or reputation gates.
- Drive: [Google Drive keyboard guidance](https://support.google.com/drive/answer/2563044?hl=en),
  [Dropbox Quick View](https://help.dropbox.com/view-edit/preview),
  [Dropbox File Requests](https://help.dropbox.com/share/create-file-request), and
  [Nextcloud File Drop](https://docs.nextcloud.com/server/stable/user_manual/en/files/file_drop.html)
  show a stable explorer, contextual inspector, explicit intake queue, and upload-only capability
  as distinct jobs. Aperture keeps its stricter anonymous `/u/` boundary and authoritative 30-day
  recovery date. Its next P0 is an Explorer Inspector backed by the existing `/f/{id}` authority,
  then an Open/Closed/Expired Request Inbox; it will not imply account ACLs or E2EE.
- Blog: [Ghost publishing](https://ghost.org/help/publishing-content/),
  [Ghost Library views](https://ghost.org/changelog/sidebar-views-filter/),
  [Substack's publishing flow](https://support.substack.com/hc/en-us/articles/360037831771-How-do-I-publish-a-new-post-on-Substack),
  and [WordPress scheduling](https://wordpress.com/support/schedule-a-post-or-page/) converge on a
  quiet editor followed by an explicit publication review. Inkwell's next P0 is `Review & publish`
  with target state, timezone, final URL, metadata, and desktop/mobile Reader preview. It will not
  absorb newsletter delivery, paid audiences, a page builder, or a theme marketplace.

The shared lesson is not “add more components.” Mature products preserve context between reads,
make irreversible transitions explicit, and expose advanced controls only inside the task that
owns them. Odyssey remains the accessibility/token foundation; these product workflows own their
information architecture and interaction ceiling.

### Iteration 5 candidate verification

- The exact candidate passes 541/541 Rust tests across the six public products: Forum 111, Blog
  112, Wiki 71, Comments 41, Paste 71, and Drive 135. Writer recovery passes 3/3 Node tests; the
  composed binary and every crate pass strict Clippy, `git diff --check`, and the release build.
- A real Chromium task audit passes at 320, 390, and 1440 px with JavaScript enabled and disabled.
  Blog proves a public Reader without author CTA, stable Studio entry, 100-row `limit=100` page,
  max-50 selection cap, contextual tag field, and no-JavaScript form. Forum creates a Support
  question, posts and accepts an answer through POST → 303, renders one Solution, and lands Latest,
  permalink, and Reply anchors below sticky chrome. Drive creates a folder, uploads, selects,
  keyboard-enters the mobile action shelf, trashes, and reads lifecycle metadata in grid/list views.
  All checked pages have zero horizontal overflow, console/page errors, or failed responses.
- A separate real View Transition run proves the observed event order is `wire:after` then
  `odyssey:swap`. Aperture therefore rebinds against the latter authoritative DOM event. Folder,
  Back, and Trash swaps each retain the correct upload target, rail controls, bulk enhancement, and
  exact CSRF cookie/form pair; Trash carries no stale upload or folder-management surface.
- A sequential card-menu run proves two optimistic Trash mutations retain one valid double-submit
  CSRF pair, with no stale remaining form or failed response. The keyboard-reachable action menu
  opens upward inside the card, so the final grid row cannot clip Rename or Move to trash.
- Blog public/Studio and Drive selected/Trash screenshots were inspected. Drive's source and
  desktop visual order are both content-first, the mobile shelf is viewport-fixed but immediately
  follows the selected checkbox in keyboard order, long rails scroll above the persistent usage
  meter, and mixed Trash rows remain compact and readable at both widths.

### Iteration 3 candidate verification

- The six public product crates pass 494/494 Rust tests; Writer recovery passes 3/3 browser-logic
  tests; every crate and the composed Scriptoria binary pass strict Clippy, `git diff --check`, and
  the release build.
- A real PostgreSQL 18 matrix passes 10/10 migration/store checks: eight Forum Activity paths, one
  Drive Library path, and one Blog Writer Durability path. FusionDB remains unavailable locally,
  so the migrations deliberately use standard PostgreSQL SQL and do not claim a silent fallback.
- A local release candidate passes 30/30 browser route probes across all six hosts with JavaScript
  both enabled and disabled at 390 px: zero page overflow, console errors, or failed statuses;
  Drive URL filters work as links without JavaScript and survive Back; Activity unread state,
  shared-link governance badges, Writer history, and private `no-store` headers are visible.
- Blog, Wiki, Comments, and Paste now use the same empty `data:` favicon contract already used by
  the other public shells. This removes automatic `/favicon.ico` failures without adding a network
  dependency or allowing Odyssey availability to gate a product task.

### Iteration 4 candidate verification

- The six public product crates pass 541/541 Rust tests: Forum 111, Blog 112, Wiki 71, Comments 41,
  Paste 71, and Drive 135. Writer recovery passes 3/3 Node tests; all six changed/unchanged product
  crates and the composed Scriptoria binary pass strict Clippy, `git diff --check`, and the release
  build.
- A fresh PostgreSQL 18 matrix passes 15/15 real migration/store tests: ten Forum Activity,
  Bookmark, Search, and base-store tests, plus Blog, Wiki, Comments, Paste, and Drive store tests.
  Drive's single PG harness includes deterministic barriers for reserve/commit/folder-create vs
  purge, reversed claim/bulk order, cross-table object-key authority, and snapshot-id collision.
- Ten browser task/viewport checks pass across Forum, Blog, and Drive at 390 px and 1440 px with
  JavaScript enabled and disabled: zero horizontal overflow, console/page errors, failed requests,
  or status failures. The run creates and bulk-publishes Blog content; creates, saves, and schedules
  a Forum bookmark; and completes Drive's folder → upload → inherited Trash → restore flow plus a
  progressively-enhanced upload and bulk Trash.
- Four Forum/Blog and two Drive screenshots were inspected at both widths. Blog keeps an editorial
  Writer workspace, Forum a discussion-grid retrieval surface, and Drive a rail-based file manager;
  Odyssey remains their shared foundation rather than their component or layout ceiling.
- All eleven Aperture HTML shells now declare the empty `data:` favicon. A compile-time contract
  prevents a detail, Request Room, Share Room, admin, error, or upload page from reintroducing the
  implicit owner-gated `/favicon.ico` request that the browser audit caught.

## Iteration 6: continuity, context, consequence

Iteration 6 turns the three v5 orientation surfaces into authoritative workflows. Odyssey still
owns tokens, focus visibility and reduced-motion semantics; Forum reading state, Drive owner
inspection and Blog publication review remain product data and product runtime.

### Forum: Continue reading / First unread

- Store subject-scoped receipts per post, not one last-read cursor. A user may jump to Latest or
  see the accepted Solution outside chronological order; those actions must not silently mark the
  unseen posts between them read.
- Resolve `?resume=1` from the earliest post without a receipt. The original post remains the
  canonical floor, an ordinary first unread begins an inclusive ascending keyset page, and an
  accepted first unread keeps the single fixed Solution region without consuming an ordinary
  reply slot.
- Mark only the OP, Solution and ordinary replies actually rendered on the current page. The
  CSRF-guarded form is the no-JavaScript authority; the IntersectionObserver enhancement submits
  the same bounded form when the reader reaches the page boundary.
- Project reading state over a bounded set of thread ids in one Store call. A started thread with
  unread posts links directly to `Continue · N new`; first-time historical content does not create
  a synthetic global notification backlog.

Acceptance: Memory and PostgreSQL isolate gateway subjects, validate the whole max-24 post batch
before writing, preserve same-second/random-id holes, and cascade receipts when a post or thread is
deleted. GET never writes. Latest, Activity-style Around, accepted-answer promotion, locked threads
and old Before/After cursors retain their existing authority and pagination semantics.

The interaction follows the official [Discourse first-unread behaviour](https://meta.discourse.org/t/access-the-top-of-the-topic-page/269510),
but Agora does not import its timeline runtime or notification-level menu. GitHub's thread-level
notification unread bit is insufficient here because an Agora page can contain real reading holes.

### Drive: Explorer Inspector

- Every file card remains a canonical owner `/f/{id}` link. The enhanced Explorer asks that same
  route for an Inspector fragment with `X-Aperture-Surface: inspector`; failed fetch, disabled
  JavaScript, refresh and modifier-click all land on the complete detail page.
- Build a dedicated token-free view model. It may expose owner file id/name/type/size/location,
  created/updated times, boolean sharing posture, counts and known version/comment events; it can
  never receive a share token, password hash, object key, bucket or public `/s/` capability URL.
- Use a desktop right sheet and mobile full-screen dialog so the Explorer remains the spatial
  context. Back closes, Forward reloads the owner fragment, Escape/scrim close, Tab is trapped,
  background surfaces become inert, media is stopped on close and focus returns to the surviving
  opener after a Wire swap.
- Describe Activity honestly. Aperture currently knows Uploaded, Last changed, retained versions
  and comments; it does not fabricate rename/move/share actors from a generic `updated_at`.

Acceptance: full and fragment representations share exact owner/Trash authorization and
`private, no-store`; all image/video/audio/PDF/text/fallback preview routes stay same-origin and
owner-only; the fragment contains no CSRF or capability material; Library Recent/Shared/Search,
Wire navigation, History and no-JavaScript links remain coherent.

This combines [Google Drive's file Details/activity side panel](https://support.google.com/drive/answer/2409045?co=GENIE.Platform%3DDesktop&hl=en)
with [Dropbox Quick View's retained list context](https://help.dropbox.com/view-edit/preview), while
keeping Aperture's stricter capability boundary and existing full-detail authority.

### Blog: Review & publish

- Publish now and Schedule first POST the complete editor payload to an author+CSRF protected SSR
  review route. The review is read-only, `private, no-store`, does not consume autosave and uses the
  same title, URL, metadata, image, schedule and fallback normalization as final publication.
- Show the exact target state, UTC instant plus explanatory browser timezone, final local URL,
  excerpt/search/social fallbacks, canonical effect, trusted Drive image and sanitized body sample.
  Name the sample honestly; it is not a theme, email-client or social-platform rendering.
- Confirmation POSTs the canonical payload to the existing `/new` or `/edit/{slug}` mutation with
  its original explicit intent. Final authorisation, validation, immutable post id/edit-version
  CAS, revision creation and autosave consumption still happen there, so a stale review cannot
  become a last-write-wins save.
- Edit draft/recovery from review must round-trip every literal value, including template-looking
  text. A review-time edit conflict returns a private submitted-content recovery surface for
  no-JavaScript users rather than dropping their uncommitted body.
- A browser-originated schedule carries one exact UTC epoch through Review, local recovery and
  server autosave. Repeated wall times during a DST rollback remain reversible until the author
  actually edits the `datetime-local` field; no-JavaScript input continues to mean UTC.

Acceptance: old clients may still direct-POST explicit publish/schedule intents; forged review
fields gain no authority because final handlers revalidate; no-JavaScript uses UTC input and the
same two-step flow; placeholder literals survive preflight → confirm byte-for-byte; review does not
write a post or revision. A successful read-only review does not touch autosave; a stale edit
review may persist the latest submitted payload only as an owner-scoped recovery copy before
returning `409`, so refresh cannot discard the conflict the page claims to preserve. Self-canonical
and external-canonical explanations use the same rule as sitemap emission.

The two-step decision follows WordPress.com's documented
[pre-publish checks](https://wordpress.com/support/posts/) and Ghost's separation of
[preview, publish and schedule](https://ghost.org/help/publishing-content/). Inkwell keeps its
server-owned CAS and does not imply subscriber email delivery, a full theme preview or social
network rendering.

### Odyssey Foundation: compact public chrome

- Odyssey `1.1.1` contains the shared fix for the product chrome rather than leaving a Forum-only
  override: at 360 px and below the app name/caret compact while the product tile, theme/apps and
  account entry remain available.
- Long account identifiers are constrained inside the user popover instead of increasing the
  document scroll width while the popover is hidden. This contract is covered by canonical CSS
  tests and the vendored fingerprint, then consumed by Scriptoria through `odysseyctl`.
- Forum still owns its denser activity/search controls and post metadata wrapping. Odyssey does
  not learn Forum receipt state, Drive Inspector layout or Blog publishing state.

### Iteration 6 candidate verification

- The six public product crates pass 549/549 Rust tests: Forum 114, Blog 116, Wiki 71, Comments 41,
  Paste 71 and Drive 136. Writer recovery passes 5/5 Node tests; all six crates and the composed
  Scriptoria binary pass strict Clippy, `git diff --check` and the release build.
- A fresh PostgreSQL 18 matrix passes 15/15 real migration/store tests. Forum's matrix includes
  exact subject-scoped post receipts and post-delete cascade; the other five product stores retain
  their complete migration round trips.
- Real Chromium passes the three product workflows at 320 / 390 / 1440 px with JavaScript and
  no-JavaScript fallbacks, plus all six Host arms: zero horizontal overflow, console warning/error,
  page error or failed workflow response. The run proves exact five-unread resume, native receipt
  submission, Inspector Back/Forward/Escape/focus/PDF/no-JS detail, SSR review/edit/confirm, a
  Europe/Berlin second-fold `02:30`, and a native no-JavaScript schedule.
- Browser and read-only cross-review found issues that string tests did not: multipart `415` on the
  automatic Forum receipt, 320 px appbar/post overflow, an Inspector scrim entering the focus ring,
  stale focus restoration, ambiguous schedule epoch, stale Review recovery and self-canonical
  wording. The first immutable-image audit additionally caught a browser-skipped View Transition
  surfacing as a global page error during competing navigation. Each issue is fixed in the product
  or Foundation layer that owns it; Odyssey now observes skipped presentation promises while
  preserving the original transition's failure semantics for explicit callers, and the reduced-
  motion/unsupported fallback propagates synchronous DOM update errors instead of reporting a
  successful navigation.
- Canonical Odyssey canary passes 68/68 tests plus `odysseyctl` 5/5; the stable backport passes
  65/65 plus `odysseyctl` 4/4. Scriptoria consumes stable `1.1.1` fingerprint
  `fnv1a64:ad66b297b913388c`; the reproducible stable check
  `cargo run --locked --manifest-path ../odyssey-1.1.1/tools/odysseyctl/Cargo.toml -- check --repo scriptoria`
  is clean. The PATH canary binary is deliberately not the verifier for a stable consumer.

## Iteration 7: relationships, intake, and saved-state preview

Iteration 7 gives each public product one new product-owned control plane. Odyssey still supplies
the shell, tokens, focus and responsive primitives; Forum relationships, Drive capability
governance and Blog author ordering remain service authority and service runtime.

### Forum: outcome-oriented relationships and explainable For You

- Replace the ambiguous boolean Follow control with four explicit outcomes. `Watch` appears in
  Following and For You and sends ordinary new replies to Activity. `Follow` appears in the two
  personal feeds without ordinary reply Activity. `Mute` is a hard exclusion from those feeds and
  generic follower Activity. `None` removes the stored preference.
- Mute is not a block. Direct replies, mentions and accepted-answer consequences remain in
  Activity, and that exception is visible beside the selector rather than hidden in documentation.
  The CSRF-protected native form is authoritative without JavaScript; Wire uses the same endpoint
  and the JSON response retains the previous `subscribed` compatibility field.
- `/for-you` authenticates first, obtains at most 200 threads from the authoritative visible Latest
  path, projects all owner signals in one bounded Store call, and renders at most 30 rows. Every row
  has exactly one deterministic reason: Watch, Follow, Authored, Bookmarked, Participated, or
  Continue Reading. Mute wins over every other reason.
- Keep the v6 `thread_subscriptions` table as a Watch-only rollback projection. Follow and Mute live
  in `thread_follow_preferences`, whose value check and thread `ON DELETE CASCADE` are database
  constraints. A v6 image can therefore never reinterpret Mute as a watcher or count quiet
  preferences against the 256-Watch reply budget. v7 setters converge both tables on every command,
  and forward migration removes stale generic Following deliveries left by a v6 Unfollow while
  preserving direct Reply, Mention and Answer deliveries.

This separates saving, personal-feed membership and notification delivery in the same spirit as
[Stack Exchange Follow](https://meta.stackexchange.com/questions/345661/the-follow-questions-and-answers-feature-is-now-live-across-the-network),
[Discourse notification levels](https://meta.discourse.org/t/configuring-default-notification-settings-for-users/285619),
and [GitHub notification reasons](https://docs.github.com/en/subscriptions-and-notifications/concepts/about-notifications).
Agora deliberately uses result labels and deterministic local signals instead of importing their
terminology, ranking runtime or opaque recommendations.

Acceptance: Memory and PostgreSQL agree on all four outcomes; Watch alone fans out ordinary reply
Activity; leaving Watch removes its existing generic path without deleting a direct delivery for
the same event; legacy boolean clients map Follow/Unfollow to Watch/None; no candidate or stale
preference can introduce a hidden thread; For You is private and `no-store`.

### Drive: token-free Request Inbox

- `/requests?view=all|open|expiring|closed|expired` is a durable owner URL surface. The four states
  are mutually exclusive at one explicit `as_of`; Expiring is the final 72 hours, and explicit
  closure wins over a passed deadline. Counts and rows use the same snapshot.
- Return exact counts but render only the newest 100 matching rows in `updated_at DESC, id DESC`
  order. The page names the cap, matched total and snapshot time instead of implying an unbounded
  history. Native filter links and empty states work without JavaScript.
- Project a dedicated `UploadRequestSummary`: id, title, public instructions, effective state,
  deadline, file/byte budgets and `updated_at`. It contains no token, public URL, owner subject,
  folder id, MIME policy, bucket, object key or storage key. The PostgreSQL CTE likewise never
  selects those fields, and HTTP tests use distinctive owner and foreign tokens to prove neither
  enters Inbox HTML.
- The canonical owner detail remains the only Access panel that projects the current `/u/{token}`
  capability and rotation command. Inbox and detail are both owner-scoped and `private, no-store`;
  a foreign detail is a generic 404. Activity is not fabricated from `updated_at`.

The control plane combines the intake clarity of
[Dropbox file requests](https://help.dropbox.com/share/create-file-request) and
[Box File Request](https://support.box.com/hc/en-us/articles/360045304813-Using-File-Request-to-get-Content-from-Anyone)
with Aperture's stricter capability boundary. It does not claim uploader identity, malware
quarantine, a durable event ledger, or per-request rate limiting that the service does not yet own.

### Blog: stable Studio order and private saved Reader preview

- Studio supports `updated` (default) and `created` order as URL state. Each cursor carries its
  sort discriminator, selected timestamp and immutable post id; Memory and PostgreSQL use the same
  descending keyset. A cursor from another order is rejected/fails closed. Two-part v5/v6
  `updated_at.id` cursors remain valid only under Updated.
- Status tabs, exact-tag links, pager, bulk `return_to` and Writer return links preserve the
  selected order. Applying the native GET form deliberately samples a new status-classification
  instant while navigation within the result set preserves its existing `as_of`.
- Draft and scheduled Library rows say `Preview saved` and link to `/p/{slug}?preview=1`. The
  route still resolves the canonical owner-only post representation: anonymous and foreign users
  receive 404, responses are `private, no-store` and `noindex,nofollow`, and no canonical, Open
  Graph or Twitter metadata is emitted. Article Edit/Delete actions are hidden; one explicit
  `Edit saved version` exit returns the owner to Writer Studio.
- This is intentionally not a shareable preview. A revocable anonymous preview capability changes
  public exposure and token authority, so it remains a later product feature rather than a query
  parameter pretending to grant access.

The ordering and saved-state decision borrow the explicit pre-publication posture of
[Ghost post settings and preview](https://ghost.org/help/post-settings/) and
[WordPress pre-publish checks](https://wordpress.com/support/posts/), while retaining Inkwell's
server-owned visibility, immutable identity and edit-version CAS.

### Iteration 7 candidate verification

- The six public product crates pass 556/556 Rust tests: Forum 119, Blog 116, Wiki 71, Comments 41,
  Paste 71 and Drive 138. Writer recovery passes 5/5 Node tests. All six crates and the composed
  Scriptoria binary pass strict Clippy with `-D warnings`, `git diff --check`, and the release build.
- Six isolated PostgreSQL 18 databases pass 16/16 real tests: eleven Forum migration/activity/
  bookmark/search/store paths and one complete store path for each other product. The matrix covers
  the Watch-only rollback projection, both-table convergence, v6 Activity repair, Follow/Mute
  constraints and cascade, Blog equal-created-at pagination/cross-sort rejection, and Drive's exact
  101-row count with a 100-row cap.
- Real Chromium passes the v7 workflows at 320 / 390 / 1440 px plus no-JavaScript at 390 px:
  Watch/Follow/Mute, explainable For You, five Request Inbox filters with zero capability material,
  updated/created Studio order, and owner-only saved Reader preview. All six Host arms pass with no
  horizontal overflow, console warning/error, page error or unexpected request failure.
- The complete v6 browser matrix also remains green on the same candidate: exact five-unread Forum
  resume, Drive Inspector History/focus/Escape/PDF/no-JS detail, Blog SSR review/edit/confirm, exact
  Europe/Berlin DST-fold schedule, and all six Host arms.
- Three independent read-only reviews found and closed the release-level Forum rollback hazard,
  then found no remaining P0/P1 in Forum, Drive or Blog. Drive additionally locks capability detail
  cache/foreign-scope evidence; Blog locks preview metadata and real PostgreSQL keyset parity.

## Iteration 8: catch-up, delivery acknowledgement, and review hand-off

Iteration 8 turns three private control planes into complete hand-off workflows. Forum lets a
returning reader finish what changed, Drive lets a submitter prove one delivery was received and
later acknowledged, and Blog lets an author hand one immutable saved revision to an external
reviewer. These workflows share no token or state model: Odyssey remains Foundation, while each
product owns its own authority, URLs, persistence, expiry and recovery.

### Forum: complete Catch-up views

- `/for-you?view=updates|following|questions` is one private, stable Catch-up surface. `Updates`
  contains related threads with exact unread posts, `Following` directly enumerates every explicit
  Watch or Follow relationship, and `Questions` contains the viewer's own valid Question threads
  with Waiting for solution or Solved state. Mute wins over every view while direct Activity
  delivery remains independent.
- Following starts from the complete relationship tables instead of first sampling Latest, so an
  old explicit relationship cannot disappear at candidate 201. The other views union only
  authoritative authored, participated, bookmarked, reading and relationship signals, then join
  current live thread, category, accepted-answer and post visibility.
- A page contains at most 30 threads. Its `v8g` keyset cursor binds view, fixed `as_of`, a
  monotonic snapshot generation, effective activity time and immutable thread id; a cursor from
  another view, generation or weak pre-v8 snapshot fails closed. Tied timestamps, same-second
  replies/read receipts and deletion of the newest reply do not duplicate or skip a thread.
- Every row has one deterministic reason, exact unread count, a current sanitized excerpt of the
  first unread post and a `Continue from first unread` anchor. GET never writes a receipt and there
  is no synthetic Mark all read command. Activity continues to mean an actually delivered Reply,
  Mention, Answer or Watch event; Updates means a thread the viewer can return to.

This uses the task separation shown by
[Discourse's unified New views](https://meta.discourse.org/t/introducing-the-unified-new-view-for-the-topic-list/404728),
[GitHub's notification filters](https://docs.github.com/en/subscriptions-and-notifications/reference/inbox-filters)
and [GitHub's subscription management](https://docs.github.com/en/subscriptions-and-notifications/how-tos/managing-subscriptions-for-activity-on-github/managing-your-subscriptions),
without importing their delivery systems or adding opaque ranking.

Acceptance: Watch/Follow outside the Latest 200 window remains reachable; unread holes and floated
solutions preserve the exact first-unread anchor; Questions only uses a valid Question category and
accepted reply; Memory and PostgreSQL return the same keyset pages; the response is subject-scoped,
`private, no-store`, SSR-first and usable without JavaScript. The Memory implementation uses one
audited lock order for Catch-up, thread-reading and post/read mutations; PostgreSQL serializes the
singleton generation clock so snapshot order follows transaction commit order.

### Drive: capability-scoped Delivery Receipt

- The first successfully committed file in one upload session atomically creates a Delivery. A
  JavaScript multi-file queue reuses it, while the native single-file fallback naturally creates
  one Delivery. A failed reservation, blob write or metadata commit cannot leave a receipt that
  claims a file was received.
- `/receipts/{token}` is a separate anonymous, read-only capability. It exposes only the file names,
  sizes and receive times that submitter already supplied, plus `Received` or `Acknowledged` and a
  30-day expiry. It cannot upload, enumerate the destination folder, read file bytes, disclose an
  owner or inspect another delivery.
- Receipt tokens are independent 256-bit secrets; PostgreSQL stores only SHA-256 digests. Raw
  tokens appear only in the successful submitter response, never in Request Inbox, owner detail,
  audit payload or storage metadata. Invalid, expired and unknown receipts share a generic 404.
- Canonical owner request detail groups immutable `UploadSubmission` rows by Delivery. The owner
  can perform one idempotent, CSRF-protected `Acknowledge delivery` command; a foreign owner sees a
  generic 404. Acknowledgement is terminal: an upload that races it either commits completely
  before the acknowledgement or rolls back its blob, metadata, reservation and budget. Existing
  pre-v8 submissions remain visible as legacy ungrouped receipts.
- `Acknowledged` means only that the owner marked the delivery seen. It never means verified
  uploader identity, malware-safe content, approval, correctness or a communication channel.

The flow keeps the upload-only privacy boundary documented by
[OneDrive Request Files](https://support.microsoft.com/en-us/onedrive/create-a-file-request), while
borrowing the explicit successful-upload posture of
[Dropbox File Requests](https://help.dropbox.com/share/received-file-request) and
[Box File Request](https://support.box.com/hc/en-us/articles/360045304913-How-Content-Submitters-View-and-Use-File-Request).
Aperture deliberately does not collect an unverified name or email and call it identity.

Acceptance: Memory and PostgreSQL commit file, submission and first Delivery atomically; multiple
files can share one receipt without crossing request scope; acknowledgement is owner-only and
idempotent and permanently closes that Delivery to appended files; closing or expiring a Request
stops new uploads but does not rewrite an existing receipt; public receipt HTML is
`private, no-store` with `Referrer-Policy: no-referrer` and contains no file id, folder id, object
key, owner, upload token or download authority.

### Blog: version-pinned Review Link

- A Draft or not-yet-public Scheduled post can issue one Review Link for the current immutable
  revision. The author chooses 48 hours or 7 days; a scheduled publication instant is an earlier
  hard stop. The raw URL is shown exactly once, while later owner management shows only revision,
  generation and expiry.
- `/review/{token}` renders that saved revision in real Reader chrome. Later editing does not
  silently change what the reviewer sees. `Refresh to current version` atomically rotates the
  token and advances a generation CAS; concurrent stale refreshes conflict and the former token
  immediately becomes a generic 404. Revoke, expiry, publication, scheduled publication and post
  deletion also invalidate it.
- The database stores a SHA-256 token digest, never the raw 256-bit capability. The link binds one
  post id to one revision version with foreign keys and at most one active generation. Publishing
  or changing publication identity invalidates the link inside the same Store transaction so a
  later Unpublish cannot revive an old reviewer capability.
- The reviewer page has a `Saved review · vN` banner and no Edit, Delete, Studio or owner identity
  controls. It is `private, no-store`, sends `X-Robots-Tag: noindex, nofollow, noarchive` and
  `Referrer-Policy: no-referrer`, emits matching robots metadata, and emits no canonical, Open
  Graph or Twitter metadata. It never enters Reader indexes, tags, Search, Ask, RSS or sitemap.
- v8 adds no reviewer account, comments, private notes, email preview, analytics or editorial
  status. Those require separate roles, delivery and retention authorities rather than UI labels.

The capability lifecycle follows the share-and-reset posture documented by
[Ghost post previews](https://ghost.org/help/publishing-content/) and
[Substack secret draft links](https://support.substack.com/hc/en-us/articles/360038433692-How-do-I-share-a-preview-of-my-post-with-others),
while the immutable snapshot is an Inkwell-specific consequence of its existing revision and CAS
authority. [WordPress revisions](https://wordpress.com/support/page-post-revisions/) remain a useful
future reference for visual comparison, not an excuse to mix restore and external review.

Acceptance: issue, pinned read, rotate, revoke, expiry, publication and deletion agree between
Memory and PostgreSQL; the old link stays on its issued revision across ordinary edits; only one
concurrent generation wins; anonymous readers cannot infer slug, post id, revision id or owner
routes; the existing `?preview=1` path remains owner-only.

### Iteration 8 exposure contract

Sluice adds exactly two longest-prefix anonymous routes: `blog.w33d.xyz/review/` and
`drive.w33d.xyz/receipts/`. The Blog and Drive root routes stay SSO-protected, Drive `/s/` and `/u/`
retain their existing authority, and Forum receives no new anonymous route. The two new capability
surfaces strip gateway identity, never set an SSO session, and rely on product-owned random token,
digest lookup, expiry and revocation. Deployment must verify the more-specific public routes and
the unchanged root redirects independently. Every `/review/`, `/receipts/`, `/s/` and `/u/`
outcome—including router 404, method 405, proxy 502 and malformed Host—forces `private, no-store`
and `no-referrer`; access, auth and WAF logs replace the complete bearer tail with `[capability]`.
Only exact Share Room CSS/JavaScript assets retain public caching. Share Room CSP permits `data:`
only for its explicit empty favicon, avoiding both a favicon request and a browser console error.

### Iteration 8 candidate verification

- The six public product crates pass 572/572 Rust tests: Forum 125, Blog 121, Wiki 71, Comments 41,
  Paste 71 and Drive 143. Writer recovery passes 5/5 Node tests. All six crates and the composed
  Scriptoria binary pass strict Clippy with `-D warnings`; the release build, `git diff --check` and
  Odyssey stable consumer check pass.
- Six isolated PostgreSQL 18 databases pass 19/19 real tests: fourteen Forum migration/activity/
  bookmark/search/store paths and one complete store path for each other product. The matrix covers
  commit-order snapshots, same-second reply/read ordering, deletion, legacy idempotent backfill,
  terminal delivery acknowledgement, review-link generation/rollback guards and newest-100 plus
  externally pinned revision retention.
- Real Chromium passes the v8 workflows at 320 / 390 / 1440 px plus no-JavaScript at 390 px:
  Updates/Following/Questions Catch-up, exact unread resume, JavaScript multi-file and native
  single-file delivery, receipt acknowledgement and terminal append rejection, and Review Link
  issue/pinned read/refresh/revoke. All six Host arms have no horizontal overflow, console warning/
  error, page error or unexpected request failure.
- The complete v7 matrix remains green, and the v6 matrix passes again from a clean database:
  Watch/Follow/Mute, token-free Request Inbox, owner-only saved preview, exact five-unread resume,
  Drive Inspector/PDF/no-JavaScript detail, Blog SSR review/edit/confirm and Europe/Berlin DST fold.
- Independent read-only reviews found and closed the Forum seconds-snapshot and Memory lock-order
  hazards, Drive post-ack append race, Blog revision-retention parity, and Share Room favicon CSP
  noise. Final Forum, Drive, Blog, Sluice and CSP reviews report no remaining P0/P1/P2; Sluice's full
  Go suite and capability-path privacy tests pass.

## Iteration 9: focus rules, review hold, and revision evidence

Iteration 9 improves three owner control planes without turning Odyssey into a product ceiling.
Odyssey still supplies Foundation tokens and primitives; Forum owns attention intent, Drive owns
intake disposition and byte access, and Blog owns immutable revision evidence. No product state is
derived from a CSS class, badge, client-side filter, or best-effort audit event.

### Forum: Category Focus Rules

- `/focus` is a private, SSR-first desk for explicit category intent. A signed-in user may keep at
  most 64 rules with `Priority`, `Follow`, `Mute`, or `None`; the page returns at most 30 current,
  live threads. Priority categories precede Follow categories, then thread activity ordering is
  deterministic.
- Focus never creates Activity and never promises an outbound notification. Thread `Watch` remains
  the only generic Activity subscription. This avoids turning one broad category preference into
  unbounded recipient fan-out.
- Precedence is fixed and visible: thread Watch/Follow can opt one thread back into a muted
  category, while thread Mute always excludes it. Direct Reply, Mention and accepted Answer
  Activity remain independent. Every rendered row names the winning category or thread reason.
- Each category page carries a native CSRF-protected desired-state form and links back to Focus.
  Save preserves canonical list state, returns to the editor anchor, and renders an accessible SSR
  confirmation. `/focus` separately lists every active rule, including Mute rules that intentionally
  yield no thread, so no-JavaScript users can inspect and undo negative intent. Memory and
  PostgreSQL enforce the same rule cap and projection; the PostgreSQL owner guard serializes
  concurrent creates and category deletion cascades its rules.
- Forum still has no authoritative tag taxonomy, thread-tag membership, or tag administration.
  v9 therefore does not add a cosmetic tag preference table. Tag Focus waits for that complete
  domain instead of storing intent that cannot match authoritative content.
- A v6 rollback may recreate legacy Watch beside a newer Mute. Forward migration removes that
  shadow Watch, Activity reconciliation deletes only its generic Following delivery, and all PG
  projections defensively make Mute win. Direct delivery paths survive.

This keeps subscriptions separate from inbox projection, as in
[GitHub notifications](https://docs.github.com/en/subscriptions-and-notifications/concepts/about-notifications),
while borrowing the visible positive/negative topic intent of
[Stack Overflow watched and ignored tags](https://stackoverflow.com/help/interesting-topics).
[Discourse category and tag notification levels](https://meta.discourse.org/t/configuring-default-notification-settings-for-users/285619)
show why hidden overlap rules become hard to explain; v9 deliberately has one fixed precedence and
does not copy their five-level delivery model.

Acceptance: GET writes nothing; unknown categories and a 65th rule fail atomically; Memory and PG
agree on Priority/Follow/Mute and thread overrides; category changes create no Activity event,
delivery or receipt; legacy Watch + Mute converges to Mute on forward boot; every HTML result is
subject-scoped `private, no-store` and usable without JavaScript.

### Drive: deep Request Inbox and explicit Review Hold

- Request Inbox replaces the newest-100 dead end with 30-row keyset pages. Continuation cursor
  `v9` binds the selected view, one fixed classification `as_of`, and `(updated_at, id)`; missing
  snapshot state, malformed values, future boundaries or replay under another view fail closed.
  Every response computes exact All/Open/Expiring/Closed/Expired counts and rows in one database
  snapshot at that classification instant. Continuations are intentionally live across HTTP
  requests rather than one long-lived MVCC snapshot: mutations at or before `as_of` may appear,
  while rows touched beyond the boundary wait for refresh.
- Every new Request upload atomically commits file metadata, immutable Submission, optional first
  Delivery and one `Held` disposition. A disposition insert failure rolls the whole metadata
  transaction back and the existing reservation/blob recovery path removes the object. Pre-v9
  submissions have no disposition and remain available for compatibility.
- Held content appears in the owner Gallery and Inspector with safe metadata and a distinct badge,
  but the server never reads its blob for preview. Raw, PDF preview, thumbnail, version download,
  version restore, Trash restore and share enable fail closed. Direct share and folder share do not
  enumerate or fetch held content. Trash and purge remain available as the rejection path.
- The owner releases one exact submission from Request detail through an idempotent, CSRF-protected
  `Held -> Released` command plus an explicit share-impact confirmation. Release is terminal. It
  means only “permit this file to be used”; it is not a malware verdict, identity verification,
  correctness review or security approval, and existing direct/folder shares may become readable.
  A permanently purged submission remains visible as Removed intake history and cannot be released.
- Public Delivery Receipt intentionally remains `Received` or `Acknowledged`. It does not disclose
  the internal Hold state, file id, byte authority or owner workflow, and acknowledgement still
  does not imply approval.

The access posture follows the separation used by
[Google Drive malware handling](https://support.google.com/drive/answer/141702?hl=en),
[Microsoft 365 malicious-file blocking](https://support.microsoft.com/en-au/office/what-to-do-when-a-malicious-file-is-found-in-sharepoint-online-onedrive-or-microsoft-teams-01e902ad-a903-4e0f-b093-1e1ac0c37ad2)
and [Box Shield malicious content rules](https://support.box.com/hc/en-us/articles/46976541627411-Malicious-Content-Detection-Rule):
receipt, scanner verdict, access restriction, human review and override are different states. v9
implements only an intake Hold and manual release; there is no scanner behind its badge.

Acceptance: pages beyond row 100 are reachable without duplicates across timestamp ties; cursor
scope cannot change silently; same-second mutation semantics are explicit; Memory and PG
counts/pages agree; new uploads cannot exist without their Hold row; held bytes cannot be replaced
by same-name owner upload and have no owner or public read bypass; release is owner-scoped,
idempotent and no-JavaScript; receipt HTML remains unchanged and capability-free; legacy
submissions remain available.

### Blog: Revision Workbench

- History replaces one-click Restore with `Review changes`. The private Workbench compares any two
  retained immutable revisions using explicit ids, a no-JavaScript GET selector, Swap, `Changes`
  and `Rendered preview` modes. A missing pair redirects to a bookmarkable previous/current URL.
- Source mode renders an escaped unified Markdown diff with added/removed symbols and text, not
  color alone. Metadata comparison covers title, tags, cover, excerpt, canonical, SEO and social
  fields; publication, schedule, pin and feature flags are shown separately as historical context
  because Restore preserves their current values.
- Preview mode renders each side independently through the existing sanitizer. It is not described
  as a DOM diff. Source and preview share explicit 200,000-character and 10,000-line limits; source
  also has a 12,000-edit budget and bounded lookahead. An oversized revision shows a clear bounded
  fallback instead of silently truncating, exhausting memory or recommending an unbounded path.
- Memory reads both sides under one revision lock; PostgreSQL reads both in one statement and one
  MVCC snapshot. Cross-post and missing ids share an unavailable result. All retained
  `100 + 1 externally pinned` summaries stay selectable while full bodies are fetched only for the
  chosen pair.
- Restore remains a CSRF-protected append-only command bound to stable post id and current edit
  version. It additionally binds the `private` or `public` impact scope the author reviewed; if a
  Scheduled post becomes public before POST, the command returns conflict and requires another
  comparison. Public copy warns that article content and restorable metadata, including custom
  canonical URL, change immediately.
- External Review Link remains a separate anonymous, version-pinned capability. Restore does not
  rotate it, and `/review/{token}` gains no History, adjacent revision id, diff or Restore access.

This takes the “compare before restore” interaction from
[WordPress revisions](https://wordpress.org/documentation/article/revisions/) and the attributable
history posture of [Ghost post history](https://ghost.org/changelog/post-history/), while keeping
Inkwell's stronger immutable pair, CAS and external-review boundaries.

Acceptance: owner/admin can compare retained pairs and a foreign user cannot; same-id, cross-post,
missing and oversized cases fail safely; diff source is escaped and preview is sanitized; Restore
requires confirmation, stable identity, edit CAS and unchanged visibility scope; published Restore
preserves publication flags but replaces authoring metadata; an active Review Link stays on its
original pinned revision.

### Iteration 9 exposure contract

No anonymous gateway route is added. Forum `/focus`, Drive Request/Review Hold controls and Blog
Revision Workbench all remain behind their existing SSO root routes. Drive `/u/`, `/s/` and
`/receipts/`, plus Blog `/review/`, retain the v8 capability contracts and generic public errors.
The candidate therefore changes Scriptoria only; Sluice route count and authentication matrix must
remain byte-for-byte stable.

Candidate gate: all 583 Rust targets pass across the six public crates, Writer recovery is 5/5,
strict Clippy and the release build pass, and isolated PostgreSQL 18 is 20/20. Real Chromium passes
Forum Focus, Drive Review Hold, and Blog Revision Workbench at 320 / 390 / 1440 px, including
JavaScript disabled at 390 px, with zero horizontal page overflow, console/page errors, or failed
resources. The Review Hold schema is forward-only after its first disposition write: rollback then
requires a forward fix or the matching pre-v9 database and Cairn checkpoints.

## Iteration 10: Lattice Knowledge Workspace

Lattice is a knowledge foundation rather than a generic page list. This iteration reorganizes the
existing hierarchy, revision, backlink, related-page and coherence capabilities into three stable
product contexts without changing their storage or authorization models.

- **Library** is the orientation surface. It combines a bounded page tree, the paginated document
  directory, six recent revision summaries, one native create form and a prominent Coherence entry.
  Activity never copies revision bodies into the response.
- **Document** uses a page tree, a focused article canvas and an Inspector. Outline, backlinks,
  related pages, revision history, owner/update metadata, structure controls and stale/isolation
  signals remain visible in the reading context instead of becoming unrelated cards below it.
- **Editor** uses a Markdown/source and safe-preview split. The first preview is rendered by the
  existing server sanitizer; progressive input preview creates inert DOM nodes with `textContent`.
  Native form submission, CSRF, append-only history and `base_rev` conflict rejection remain the
  authority when JavaScript is disabled or fails.
- Lattice owns its editorial layout and responsive behavior. Odyssey remains the foundation for
  tokens, theme, locale preferences, focus and reduced motion; it does not constrain the product
  DOM or turn the workspace into a shared card template.

No route, schema or anonymous capability is added. `wiki.w33d.xyz` remains an SSO root, and the
shared Scriptoria candidate must still pass all six product crates, the Writer recovery suite,
strict Clippy, isolated PostgreSQL 18 and Chromium at 320 / 390 / 1440 px plus 390 px no-JavaScript.
Acceptance additionally requires no horizontal overflow, no failed resources, a usable collapsed
Inspector on narrow screens, and unchanged Blog Review / Drive capability boundaries.

## Next iterations

1. Forum: add an admin-owned tag taxonomy and thread-tag membership before Tag Focus, then add
   stable Focus pagination. A bounded off-site digest remains a separate delivery authority.
2. Drive: add request-specific rate limits, then integrate a real scanner verdict as a state
   separate from Review Hold/manual release. Crucible integration needs asynchronous retry,
   immutable result provenance and false-positive override before any “safe” label.
3. Blog: link Review management to a private “shared vN versus current” comparison. Reviewer notes
   or editorial states still wait for explicit reviewer identity, authorization, notification and
   retention models.

## Rollout gate

Scriptoria deploys Blog, Forum, Wiki, Comments, Paste, and Drive together. A candidate therefore
must run the full Scriptoria workspace tests and build, then probe all six hosts. Forum and Blog
must retain exact SSO redirects. Drive `/s/` and `/u/` capability flows must remain anonymous and
scoped. No production restart happens until an immutable prior image, database checkpoint, Cairn
object snapshot, and browser checks at 390 px and 1440 px exist. Once Iteration 4 writes a Trash
entry, purge job, or owner blob intent, an image-only rollback is no longer valid: recover by a
forward fix, or restore the matching database and Cairn checkpoints together. The same rule is
immediate for v9 Review Hold: after the first disposition row exists, a pre-v9 binary would ignore
that access authority, so rollback must be a forward fix or a matching pre-v9 database and Cairn
restore, never an image-only downgrade.

Cross-product review additionally makes these invariants release blockers:

- Forum suggestion requests are invalid below the server minimum and stale browser responses can
  never reopen a dismissed result list. PostgreSQL migration must backfill legacy original posts
  before body search is considered complete. The original post has a stable stored identity and
  cannot be deleted separately from its thread, so a reply is never silently promoted across an
  author boundary.
- Blog's derived Search/Ask index is part of publication correctness. Drafting a published post
  must remove it, and a scheduled post must appear when it becomes reader-visible even when other
  index chunks already exist. Request-time maintenance is incremental (at most 200 posts) and
  retrieval is bounded to 20,000 chunks joined back to the authoritative post visibility/version;
  index errors propagate instead of returning stale text.
- Drive owner routes require a configured, valid gateway identity signature in production.
  Anonymous upload CSRF must survive multiple tabs and retry without rotating cookie/form values
  out of sync. Public errors use fixed text and never disclose parser, tenant, quota, or storage
  details.
- Share Room HTML uses product-owned same-origin assets under the existing public `/s/` route and
  an enforceable CSP. Public pages do not need Odyssey runtime availability to render or complete
  their baseline task.
- Forum bookmarks are authorized only by gateway subject and immutable bookmark CAS. The Due
  queue is request-derived and must never imply an outbound delivery that does not exist.
- Forum v7 keeps the v6 table Watch-only, so an old image cannot turn Follow/Mute into generic
  Activity. However, a v7 Follow/Mute -> v6 Follow -> v6 Unfollow -> v7 round trip has no portable
  deletion tombstone and can revive the earlier v7 preference. During an emergency v6 rollback,
  freeze thread-preference mutation, use a schema-aware compatibility image, or restore the paired
  pre-v7 Agora checkpoint; do not claim the preference round trip is lossless.
- Drive Trash, upload requests, object intents, and delete jobs use one owner guard and deterministic
  lock order. A metadata commit cannot leave bytes without an intent/delete-job authority, and
  capability URLs are inactive throughout inherited Trash scope.
- Blog Library mutations are stable-id/version commands; all selected rows validate before commit.
  Any response containing identity, theme, admin navigation, recovery content, autosave, History,
  or CSRF material is `private, no-store` and cannot enter a shared cache.

Request Rooms still have finite byte/file budgets but no dedicated request rate limiter or password
challenge. Those remain explicit product limits rather than implied abuse protection. Iteration 4
closes the earlier ordinary-writer guard and startup-only recovery gaps, but it does not add a
multi-replica protocol: migration, intent recovery, Trash retention, and deployment remain
single-active until an explicit lease/compatibility design is reviewed.

The legacy folder-token and Trash migrations have the same single-active deployment contract: stop
the old Scriptoria container before starting the candidate. Their transactions lock and verify
every legacy source before exact backfill/bind; a foreign deterministic id or competing authority
fails boot instead of silently rebinding data. Mixed-version rolling or blue/green deployment is
not supported. Adding replicas or zero-downtime rollout requires an explicit dual-version token and
Trash/write-intent protocol before these migrations may run concurrently with an older writer.
