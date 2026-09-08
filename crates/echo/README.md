# Echo — embeddable comments

One owned comment layer for the Steadholme estate, reusable across blog / wiki / paste. Echo is a
standalone threaded-comments service plus a minimal, iframe-able embed view (later other services
iframe `/embed/{key}`).

## Where it sits

- Internal-only, behind a Sluice `auth=sso` route at the subdomain ROOT (`comments.w33d.xyz`).
- The gateway runs the OIDC login against Keystone, STRIPS inbound `X-Auth-*`, and injects the
  verified `X-Auth-Subject` / `X-Auth-Email` / `X-Auth-Scope`. Echo trusts those headers and does
  no login of its own. The comment author is ALWAYS the gateway identity, never a client field.
- Internal port **9120**.

## Endpoints

| Method | Path             | Auth      | Description                                                        |
|--------|------------------|-----------|-------------------------------------------------------------------|
| GET    | `/healthz`       | none      | Liveness (container HEALTHCHECK), 200 `ok`.                        |
| GET    | `/`              | sso       | Dashboard: all threads + counts + recent activity + moderation.   |
| GET    | `/t/{key}`       | sso       | Single thread view + composer.                                    |
| POST   | `/api/comment`   | sso, CSRF | Upsert thread by `thread_key` + insert a comment.                 |
| POST   | `/api/moderate`  | sso, CSRF | Hide / unhide a comment.                                          |
| GET    | `/embed/{key}`   | sso       | Minimal iframe-able thread + composer (`X-Frame-Options SAMEORIGIN`). |

Comment bodies are author-supplied markdown rendered to SANITIZED HTML (raw HTML escaped,
link/image URLs scheme-allowlisted). Replies nest exactly one level. Notable events are emitted to
Watchtower (`echo.comment.post`, `echo.moderate`) via the non-blocking bounded-queue audit sink.

## Configuration (env)

| Var                  | Default            | Notes                                                  |
|----------------------|--------------------|--------------------------------------------------------|
| `BIND_ADDR`          | `0.0.0.0:9120`     | Listen address.                                        |
| `ECHO_STORE`         | `memory`           | `memory` (no DB) or `postgres`.                        |
| `DATABASE_URL`       | —                  | Required when `ECHO_STORE=postgres`.                   |
| `AUDIT_ENABLED`      | `false`            | `on`/`true`/`1`/`yes` to enable the Watchtower sink.   |
| `WATCHTOWER_URL`     | —                  | e.g. `http://watchtower:8500`.                         |
| `AUDIT_INGEST_TOKEN` | —                  | Bearer token for Watchtower ingest.                    |

Boots zero-config: with no env set it serves on `:9120` with an in-memory store and audit off.

## Data model (portable standard SQL)

```
threads(id TEXT PK, key TEXT UNIQUE, title TEXT NOT NULL DEFAULT '', url TEXT NOT NULL DEFAULT '',
        created_at BIGINT)
comments(id TEXT PK, thread_id TEXT NOT NULL, author_sub TEXT NOT NULL,
         author_email TEXT NOT NULL DEFAULT '', body TEXT NOT NULL, created_at BIGINT,
         hidden BOOLEAN NOT NULL DEFAULT false, parent_id TEXT NOT NULL DEFAULT '')
INDEX comments(thread_id, created_at)
```

No JSONB/arrays/SERIAL/extensions — the same statements run unchanged on FusionDB over pgwire.
`migrate()` runs `CREATE TABLE IF NOT EXISTS` on startup.

## Build & test

```sh
CARGO_BUILD_JOBS=2 cargo check --all-targets
cargo test                       # in-memory flow + unit tests (no database)
# Optional Postgres integration test:
TEST_DATABASE_URL=postgres://... cargo test --test pg_store -- --nocapture
```

## Frontend (v2, 2026-09-08)

This surface follows the shared Steadholme v2 system implemented from the Figma
file `AgW9572aDQMEDkSzerg9lR` (Scriptoria, plum accent), carrying its own
`surf/*` colour on the accent.

Each crate here defines a COMPLETE palette in its own `:root`, so the shared
kit cannot be prepended — it would simply be overridden. `static/service.css`
is therefore this crate's original layer with a token re-point appended after
everything else.
