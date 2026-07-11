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

## Next iterations

1. Forum: accepted-answer retrieval across pagination, follower notification delivery, unread
   state, bookmarks, and N+1 query removal.
2. Drive: signed-in command search, filters/sort, Recent/Shared views, multi-select, inspector,
   version activity, and a transfer tray.
3. Blog: server autosave and revisions, restore, Drive media picker, custom excerpt/SEO/social
   metadata, and shareable preview.

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
