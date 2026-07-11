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

### Blog / Inkwell

Ghost makes Draft, Preview, Publish, Schedule, web/email/social preview, tags, post settings, and
history one coherent Writer workflow. Inkwell already has Markdown, sanitized preview, scheduled
publishing, tags, covers, local crash recovery, RSS, sitemap, search, and cited Ask. Its highest
value gap is a reliable Writer state machine, not newsletters or payments.

- <https://ghost.org/help/publishing-content/>
- <https://ghost.org/help/post-settings/>
- <https://ghost.org/help/cards/>
- <https://help.medium.com/hc/en-us/articles/360033930293-Set-a-canonical-link>

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

## Next iterations

1. Forum: Activity Inbox with durable follower delivery and read state, personal bookmarks, report
   and moderator review, then remaining list N+1 removal.
2. Drive: signed-in command search, filter/sort chips, Recent/Shared views, multi-select inspector,
   request-room passwords, and explicit trash/object-retention policy.
3. Blog: server autosave and revisions/restore, a writer content library, Drive media picker, and a
   separately-authorized shareable draft preview.

## Rollout gate

Scriptoria deploys Blog, Forum, Wiki, Comments, Paste, and Drive together. A candidate therefore
must run the full Scriptoria workspace tests and build, then probe all six hosts. Forum and Blog
must retain exact SSO redirects. Drive `/s/` and `/u/` capability flows must remain anonymous and
scoped. No production restart happens until a rollback image exists and browser checks pass at
390 px and 1440 px.

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

Iteration 2 intentionally leaves three Drive limits visible in the backlog rather than implying
stronger guarantees: ordinary signed-in upload/version writes do not yet share the public-request
owner guard; startup recovery assumes a quiescent single active boot and has no periodic sweeper;
and anonymous `/u/` rooms have finite byte/file budgets but no dedicated request rate limiter yet.
These do not weaken room-local budgets, private-by-default storage, capability secrecy, or the
release blockers above, but they must be closed before multi-replica recovery or abuse-sensitive
public intake is claimed.

The legacy folder-token migration has the same single-active deployment contract: stop the old
Scriptoria container before starting the candidate. Its transaction locks and snapshots every
legacy source before exact backfill/clear, but mixed-version rolling or blue/green deployment is
not supported. Adding replicas or zero-downtime rollout requires an explicit dual-version token
protocol before this migration may run concurrently with an older writer.
