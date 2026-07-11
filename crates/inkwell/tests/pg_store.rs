//! PostgreSQL `Store` integration test.
//!
//! Runs ONLY when `TEST_DATABASE_URL` is set (it needs an external Postgres). When unset the
//! test prints a note and returns early — it never fails the default `cargo test` run, which
//! stays database-free. Spin up a throwaway Postgres and run:
//!
//! ```text
//! docker run --rm -d -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=inkwell \
//!   -p 127.0.0.1:55460:5432 postgres:18-alpine
//! TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55460/inkwell \
//!   cargo test --test pg_store -- --nocapture
//! ```
//!
//! The `Store` trait is async: each method `.await`s sqlx natively (no `block_in_place`), so
//! it runs on any Tokio scheduler — this test stays on `multi_thread` for parallel queries.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use inkwell::store::{
    AutosaveOutcome, PgStore, Post, SavePostCommand, SavePostOutcome, Store, WriterAutosave,
};
use inkwell::{app, build_dev_state, now_secs, AppState};
use tower::ServiceExt;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg_store_full_integration() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!(
            "NOTE: TEST_DATABASE_URL not set — skipping Postgres integration test \
             (needs external Postgres). This is expected for the default test run."
        );
        return;
    };

    // --- connect / migrate (fresh child schema + idempotent re-run) --------
    let pg = PgStore::connect(&url)
        .await
        .expect("connect TEST_DATABASE_URL");
    let raw = sqlx::PgPool::connect(&url).await.expect("raw test pool");
    sqlx::query("DROP TABLE IF EXISTS writer_autosaves, post_revisions")
        .execute(&raw)
        .await
        .expect("reset child tables for a fresh-schema migration");
    pg.migrate().await.expect("migrate");
    pg.migrate().await.expect("migrate is idempotent");
    for table in ["writer_autosaves", "post_revisions", "chunks", "posts"] {
        sqlx::query(&format!("DELETE FROM {table}"))
            .execute(&raw)
            .await
            .expect("clear isolated test table");
    }
    let cascading_foreign_keys: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_constraint c \
         JOIN pg_class child ON child.oid = c.conrelid \
         WHERE c.contype = 'f' AND c.confdeltype = 'c' \
           AND child.relname IN ('post_revisions', 'writer_autosaves') \
           AND child.relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = current_schema())",
    )
    .fetch_one(&raw)
    .await
    .expect("inspect fresh-schema foreign keys");
    assert_eq!(
        cascading_foreign_keys, 2,
        "fresh revision and autosave tables both cascade with their post"
    );
    let pg = Arc::new(pg);

    // --- direct Store-trait round-trip -------------------------------------
    let now = now_secs();
    let post = Post {
        id: "post_pg_1".to_string(),
        slug: "pg-hello".to_string(),
        title: "PG Hello".to_string(),
        body_md: "# Hi\n\nFrom **postgres**.".to_string(),
        author_sub: "u_alice".to_string(),
        author_email: "alice@holdfast.local".to_string(),
        created_at: now - 100,
        updated_at: now - 100,
        edit_version: 1,
        published: true,
        publish_at: 0,
        featured: false,
        pinned: false,
        tags: "rust, postgres".to_string(),
        cover_url: "https://drive.w33d.xyz/s/cover_tok".to_string(),
        custom_excerpt: "A PostgreSQL-backed hello.".to_string(),
        meta_title: "PG metadata title".to_string(),
        meta_description: "PG metadata description".to_string(),
        canonical_url: "https://example.com/original-pg-hello".to_string(),
        social_title: "PG social title".to_string(),
        social_description: "PG social description".to_string(),
        social_image: "https://drive.w33d.xyz/s/social_tok".to_string(),
    };
    pg.create_post(&post).await.expect("create");
    let baseline = pg
        .list_post_revisions(&post.id, 50)
        .await
        .expect("baseline revision");
    assert_eq!(baseline.len(), 1);
    assert_eq!(baseline[0].edit_version, 1);

    let autosave_session = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let autosave = WriterAutosave {
        session_id: autosave_session.to_string(),
        post_id: post.id.clone(),
        owner_sub: post.author_sub.clone(),
        base_version: 1,
        client_seq: 2,
        title: post.title.clone(),
        body_md: "pg private recovery".to_string(),
        tags: post.tags.clone(),
        cover_url: post.cover_url.clone(),
        custom_excerpt: post.custom_excerpt.clone(),
        meta_title: post.meta_title.clone(),
        meta_description: post.meta_description.clone(),
        canonical_url: post.canonical_url.clone(),
        social_title: post.social_title.clone(),
        social_description: post.social_description.clone(),
        social_image: post.social_image.clone(),
        publish_at: String::new(),
        pinned: post.pinned,
        updated_at: now,
        expires_at: now + inkwell::config::AUTOSAVE_TTL_SECS,
    };
    assert!(matches!(
        pg.put_writer_autosave(autosave.clone(), now).await.unwrap(),
        AutosaveOutcome::Saved(_)
    ));
    let mut stale_sequence = autosave.clone();
    stale_sequence.client_seq = 1;
    stale_sequence.body_md = "must not replace".to_string();
    assert!(matches!(
        pg.put_writer_autosave(stale_sequence, now).await.unwrap(),
        AutosaveOutcome::Stale {
            stored_client_seq: 2
        }
    ));
    assert_eq!(
        pg.get_writer_autosave(autosave_session, "u_alice", now)
            .await
            .unwrap()
            .unwrap()
            .body_md,
        "pg private recovery"
    );
    assert!(pg
        .get_writer_autosave(autosave_session, "u_admin", now)
        .await
        .unwrap()
        .is_none());

    // Expiration is enforced on reads and before sequence CAS: an expired high sequence cannot
    // block a fresh editor from restarting at a lower sequence for the same session.
    let ttl_session = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let mut expired_target = autosave.clone();
    expired_target.session_id = ttl_session.to_string();
    expired_target.client_seq = 999;
    expired_target.expires_at = now + 1;
    assert!(matches!(
        pg.put_writer_autosave(expired_target, now).await.unwrap(),
        AutosaveOutcome::Saved(_)
    ));
    assert!(pg
        .get_writer_autosave(ttl_session, "u_alice", now + 2)
        .await
        .unwrap()
        .is_none());
    let mut fresh_target = autosave.clone();
    fresh_target.session_id = ttl_session.to_string();
    fresh_target.client_seq = 1;
    fresh_target.body_md = "fresh after expiry".to_string();
    fresh_target.updated_at = now + 2;
    fresh_target.expires_at = now + 100;
    assert!(matches!(
        pg.put_writer_autosave(fresh_target, now + 2)
            .await
            .unwrap(),
        AutosaveOutcome::Saved(_)
    ));
    assert_eq!(
        pg.get_writer_autosave(ttl_session, "u_alice", now + 2)
            .await
            .unwrap()
            .unwrap()
            .client_seq,
        1
    );

    // Duplicate slug -> Conflict (the UNIQUE(slug) guard).
    let dup = Post {
        id: "post_pg_dup".to_string(),
        ..post.clone()
    };
    assert!(
        matches!(
            pg.create_post(&dup).await,
            Err(inkwell::store::StoreError::Conflict(_))
        ),
        "duplicate slug rejected"
    );

    // A second, newer post — list ordering is newest-first.
    let post2 = Post {
        id: "post_pg_2".to_string(),
        slug: "pg-second".to_string(),
        title: "PG Second".to_string(),
        body_md: "later".to_string(),
        author_sub: "u_alice".to_string(),
        author_email: "alice@holdfast.local".to_string(),
        created_at: now,
        updated_at: now,
        edit_version: 1,
        published: true,
        publish_at: 0,
        featured: false,
        pinned: false,
        tags: String::new(),
        cover_url: String::new(),
        custom_excerpt: String::new(),
        meta_title: String::new(),
        meta_description: String::new(),
        canonical_url: String::new(),
        social_title: String::new(),
        social_description: String::new(),
        social_image: String::new(),
    };
    pg.create_post(&post2).await.expect("create 2");

    // Fresh-schema child rows are database-owned and cascade even when a post is deleted outside
    // the Store implementation (for example by an operator or a rollback image).
    let mut cascade_post = post2.clone();
    cascade_post.id = "post_pg_cascade".to_string();
    cascade_post.slug = "pg-cascade".to_string();
    pg.create_post(&cascade_post)
        .await
        .expect("create cascade fixture");
    let mut cascade_autosave = autosave.clone();
    cascade_autosave.session_id =
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string();
    cascade_autosave.post_id = cascade_post.id.clone();
    cascade_autosave.base_version = cascade_post.edit_version;
    assert!(matches!(
        pg.put_writer_autosave(cascade_autosave, now)
            .await
            .unwrap(),
        AutosaveOutcome::Saved(_)
    ));
    sqlx::query("DELETE FROM posts WHERE id = $1")
        .bind(&cascade_post.id)
        .execute(&raw)
        .await
        .expect("direct post delete cascades");
    let cascade_children: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM post_revisions WHERE post_id = $1) + \
                (SELECT count(*) FROM writer_autosaves WHERE post_id = $1)",
    )
    .bind(&cascade_post.id)
    .fetch_one(&raw)
    .await
    .unwrap();
    assert_eq!(cascade_children, 0, "database cascades both child tables");

    // Slug reuse must not turn a stale tab into an ABA overwrite of a different post identity.
    let mut old_aba = post2.clone();
    old_aba.id = "post_pg_aba_old".to_string();
    old_aba.slug = "pg-aba".to_string();
    old_aba.body_md = "old identity".to_string();
    old_aba.created_at = now - 500;
    old_aba.updated_at = now - 500;
    pg.create_post(&old_aba).await.expect("create old ABA post");
    let mut stale_aba = old_aba.clone();
    stale_aba.body_md = "stale tab must not win".to_string();
    pg.delete_post(&old_aba.slug).await.expect("delete old ABA post");
    let mut replacement = post2.clone();
    replacement.id = "post_pg_aba_replacement".to_string();
    replacement.slug = old_aba.slug.clone();
    replacement.body_md = "replacement identity".to_string();
    replacement.created_at = old_aba.created_at;
    replacement.updated_at = old_aba.updated_at;
    pg.create_post(&replacement)
        .await
        .expect("recreate same slug with a new id");
    for source in ["update", "restore"] {
        let outcome = pg
            .save_post(SavePostCommand {
                post: stale_aba.clone(),
                expected_version: 1,
                editor_sub: old_aba.author_sub.clone(),
                editor_email: old_aba.author_email.clone(),
                source: source.to_string(),
                restored_from: (source == "restore").then(|| "old-revision".to_string()),
                consume_autosave_session: Some("old-aba-session".to_string()),
            })
            .await
            .unwrap();
        assert_eq!(outcome, SavePostOutcome::NotFound);
    }
    let mut stale_aba_autosave = autosave.clone();
    stale_aba_autosave.session_id = "old-aba-session".to_string();
    stale_aba_autosave.post_id = old_aba.id.clone();
    stale_aba_autosave.base_version = 1;
    stale_aba_autosave.client_seq = 1;
    stale_aba_autosave.body_md = "must not attach to replacement".to_string();
    assert_eq!(
        pg.put_writer_autosave(stale_aba_autosave, now)
            .await
            .unwrap(),
        AutosaveOutcome::NotFound
    );
    let replacement_after = pg.get_post("pg-aba").await.unwrap();
    assert_eq!(replacement_after.id, replacement.id);
    assert_eq!(replacement_after.body_md, "replacement identity");
    assert_eq!(
        pg.list_post_revisions(&replacement.id, 50)
            .await
            .unwrap()
            .len(),
        1,
        "stale save and restore append no replacement revision"
    );
    let old_aba_children: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM post_revisions WHERE post_id = $1) + \
                (SELECT count(*) FROM writer_autosaves WHERE post_id = $1)",
    )
    .bind(&old_aba.id)
    .fetch_one(&raw)
    .await
    .unwrap();
    assert_eq!(old_aba_children, 0, "stale identity leaves no child pollution");

    let listed = pg.list_posts(None, inkwell::config::MAX_PAGE).await;
    assert!(listed.len() >= 2);
    assert_eq!(listed[0].slug, "pg-second", "newest first");

    // Keyset "before" cursor pages strictly OLDER than the newest row (created_at DESC, id DESC).
    let cursor = (listed[0].created_at, listed[0].id.clone());
    let older = pg.list_posts(Some(cursor), inkwell::config::MAX_PAGE).await;
    assert!(
        older.iter().all(|p| p.slug != "pg-second"),
        "newest row excluded by the before cursor"
    );
    assert!(
        older.iter().any(|p| p.slug == "pg-hello"),
        "older row still reachable"
    );

    // Public reader-visible Store methods apply pinned ordering and the publish_at predicate.
    let mut pinned = post.clone();
    pinned.id = "post_pg_pinned".to_string();
    pinned.slug = "pg-pinned".to_string();
    pinned.title = "PG Pinned".to_string();
    pinned.created_at = now - 200;
    pinned.updated_at = now - 200;
    pinned.pinned = true;
    pg.create_post(&pinned).await.expect("create pinned");

    let mut future = post.clone();
    future.id = "post_pg_future".to_string();
    future.slug = "pg-future".to_string();
    future.title = "PG Future".to_string();
    future.created_at = now + 10;
    future.updated_at = now + 10;
    future.publish_at = now + 3_600;
    pg.create_post(&future).await.expect("create future");

    let visible = pg
        .list_visible_posts(None, inkwell::config::MAX_PAGE, now, None)
        .await;
    assert_eq!(
        visible[0].slug, "pg-pinned",
        "pinned public post floats to top"
    );
    assert!(
        visible.iter().all(|p| p.slug != "pg-future"),
        "future scheduled post hidden from anonymous list",
    );
    assert!(
        pg.get_visible_post("pg-future", now, None).await.is_none(),
        "future scheduled post hidden from anonymous read",
    );
    assert!(
        pg.get_visible_post("pg-future", now, Some("u_alice"))
            .await
            .is_some(),
        "author can read scheduled post",
    );
    let feed_posts = pg.feed_posts(now).await.expect("authoritative PG feed");
    let second_pos = feed_posts
        .iter()
        .position(|post| post.slug == "pg-second")
        .expect("recent post in feed");
    let pinned_pos = feed_posts
        .iter()
        .position(|post| post.slug == "pg-pinned")
        .expect("old pinned post in feed");
    assert!(
        second_pos < pinned_pos,
        "PG feed chronology is independent of homepage pinning"
    );
    assert!(feed_posts.iter().all(|post| post.slug != "pg-future"));
    let sitemap = pg
        .sitemap_entries(now)
        .await
        .expect("lightweight PG sitemap projection");
    let sitemap_hello = sitemap
        .iter()
        .find(|entry| entry.slug == "pg-hello")
        .expect("public post in sitemap projection");
    assert_eq!(sitemap_hello.updated_at, post.updated_at);
    assert_eq!(sitemap_hello.canonical_url, post.canonical_url);
    assert!(sitemap.iter().all(|entry| entry.slug != "pg-future"));
    let related = pg
        .related_posts_by_tags("pg-pinned", "rust, postgres", now, 3)
        .await;
    assert!(
        related.iter().any(|p| p.slug == "pg-hello"),
        "shared-tag related post found"
    );

    // Fetch + update (slug stays stable) + verify.
    let fetched = pg.get_post("pg-hello").await.expect("fetch");
    assert_eq!(fetched.title, "PG Hello");
    assert_eq!(
        fetched.tags, "rust, postgres",
        "tags column round-trips through pg"
    );
    assert_eq!(
        fetched.cover_url, "https://drive.w33d.xyz/s/cover_tok",
        "cover_url column round-trips through pg",
    );
    assert_eq!(fetched.custom_excerpt, "A PostgreSQL-backed hello.");
    assert_eq!(fetched.meta_title, "PG metadata title");
    assert_eq!(fetched.meta_description, "PG metadata description");
    assert_eq!(
        fetched.canonical_url,
        "https://example.com/original-pg-hello"
    );
    assert_eq!(fetched.social_title, "PG social title");
    assert_eq!(fetched.social_description, "PG social description");
    assert_eq!(fetched.social_image, "https://drive.w33d.xyz/s/social_tok");
    let mut metadata_state = build_dev_state();
    metadata_state.store = pg.clone();
    let (status, html) = raw_call(&metadata_state, get("/p/pg-hello")).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("<title>PG metadata title · Inkwell</title>"));
    assert!(html.contains(r#"<link rel="canonical" href="https://example.com/original-pg-hello">"#));
    assert!(html
        .contains(r#"<meta property="og:image" content="https://drive.w33d.xyz/s/social_tok">"#));
    let mut edited = fetched.clone();
    edited.title = "PG Hello (edited)".to_string();
    edited.tags = "rust".to_string();
    edited.cover_url = String::new();
    edited.custom_excerpt = "Updated PG excerpt".to_string();
    edited.meta_description = "Updated PG description".to_string();
    edited.social_image = String::new();
    edited.published = false;
    edited.updated_at = now;
    let saved = pg
        .save_post(SavePostCommand {
            post: edited.clone(),
            expected_version: 1,
            editor_sub: "u_alice".to_string(),
            editor_email: "alice@holdfast.local".to_string(),
            source: "update".to_string(),
            restored_from: None,
            consume_autosave_session: Some(autosave_session.to_string()),
        })
        .await
        .expect("atomic update");
    assert!(matches!(saved, SavePostOutcome::Saved(_)));
    assert!(
        pg.get_writer_autosave(autosave_session, "u_alice", now)
            .await
            .unwrap()
            .is_none(),
        "authoritative transaction consumed autosave"
    );
    let after = pg.get_post("pg-hello").await.expect("refetch");
    assert_eq!(after.edit_version, 2);
    assert_eq!(after.title, "PG Hello (edited)");
    assert_eq!(after.tags, "rust", "tags update persisted in pg");
    assert_eq!(after.cover_url, "", "cover_url cleared through pg update");
    assert_eq!(after.custom_excerpt, "Updated PG excerpt");
    assert_eq!(after.meta_description, "Updated PG description");
    assert_eq!(after.social_image, "");
    assert!(!after.published);
    let stale = pg
        .save_post(SavePostCommand {
            post: edited.clone(),
            expected_version: 1,
            editor_sub: "u_alice".to_string(),
            editor_email: "alice@holdfast.local".to_string(),
            source: "stale".to_string(),
            restored_from: None,
            consume_autosave_session: None,
        })
        .await
        .expect("stale CAS outcome");
    assert!(matches!(
        stale,
        SavePostOutcome::Conflict { current_version: 2 }
    ));
    assert_eq!(
        pg.list_post_revisions(&post.id, 50).await.unwrap().len(),
        2,
        "conflict appends no revision"
    );

    // Opportunistic autosave cleanup is a bounded 256-row batch and never touches valid recovery
    // rows or the independent revision history.
    sqlx::query(
        "INSERT INTO writer_autosaves \
             (session_id, post_id, owner_sub, base_version, client_seq, title, body_md, tags, \
              cover_url, custom_excerpt, meta_title, meta_description, canonical_url, social_title, \
              social_description, social_image, publish_at, pinned, updated_at, expires_at) \
         SELECT 'expired-' || lpad(g::text, 4, '0'), $1, 'expired-owner', $2, g, 't', 'b', '', \
                '', '', '', '', '', '', '', '', '', FALSE, $3 - 100, $3 - 1 \
         FROM generate_series(1, 300) AS g",
    )
    .bind(&post.id)
    .bind(after.edit_version)
    .bind(now)
    .execute(&raw)
    .await
    .expect("seed expired autosaves");
    let revisions_before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM post_revisions WHERE post_id = $1")
            .bind(&post.id)
            .fetch_one(&raw)
            .await
            .unwrap();
    let cleanup_session = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let mut cleanup_trigger = autosave.clone();
    cleanup_trigger.session_id = cleanup_session.to_string();
    cleanup_trigger.base_version = after.edit_version;
    cleanup_trigger.client_seq = 1;
    cleanup_trigger.expires_at = now + inkwell::config::AUTOSAVE_TTL_SECS;
    assert!(matches!(
        pg.put_writer_autosave(cleanup_trigger, now).await.unwrap(),
        AutosaveOutcome::Saved(_)
    ));
    let expired_left: i64 =
        sqlx::query_scalar("SELECT count(*) FROM writer_autosaves WHERE expires_at <= $1")
            .bind(now)
            .fetch_one(&raw)
            .await
            .unwrap();
    assert_eq!(
        expired_left, 44,
        "one write cleans exactly one bounded batch"
    );
    assert!(
        pg.get_writer_autosave(cleanup_session, "u_alice", now)
            .await
            .unwrap()
            .is_some(),
        "valid autosave survives cleanup"
    );
    let revisions_after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM post_revisions WHERE post_id = $1")
            .bind(&post.id)
            .fetch_one(&raw)
            .await
            .unwrap();
    assert_eq!(revisions_after, revisions_before);

    // --- full HTTP flow through the PG-backed app --------------------------
    let mut state: AppState = build_dev_state();
    state.store = pg.clone();

    // Create through the SSO+CSRF authoring path.
    let body = "title=Via+HTTP&body=hello+%23world&intent=publish_now&csrf_token=tok";
    let resp = app(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/new")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, "__Host-csrf=tok")
                .header("x-auth-subject", "u_bob")
                .header("x-auth-email", "bob@holdfast.local")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    assert_eq!(location, "/p/via-http");

    // Read it back through the PG-backed reading view.
    let (status, html) = raw_call(&state, get("/p/via-http")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&html).contains("Via HTTP"));

    // Delete via the SSO path (correct owner).
    let (status, _) = raw_call(
        &state,
        Request::builder()
            .method("POST")
            .uri("/delete/via-http")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, "__Host-csrf=tok")
            .header("x-auth-subject", "u_bob")
            .header("x-auth-email", "bob@holdfast.local")
            .body(Body::from("csrf_token=tok"))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(pg.get_post("via-http").await.is_none(), "deleted in pg");

    // --- chunk index round-trip (the "ask your blog" store path) -----------
    use inkwell::store::Chunk;
    let now2 = now_secs();
    pg.replace_all_chunks(vec![
        Chunk {
            id: "pg-hello__0000".into(),
            post_id: "pg-hello".into(),
            title: "PG Hello".into(),
            body: "alpha gateway beta".into(),
            indexed_at: now2,
        },
        Chunk {
            id: "pg-second__0000".into(),
            post_id: "pg-second".into(),
            title: "PG Second".into(),
            body: "gamma delta".into(),
            indexed_at: now2,
        },
    ])
    .await
    .expect("replace_all_chunks");
    assert_eq!(pg.count_chunks().await.unwrap(), 2, "full index built");

    // Per-post reindex replaces only that post's chunks.
    pg.replace_post_chunks(
        "pg-hello",
        vec![Chunk {
            id: "pg-hello__0000".into(),
            post_id: "pg-hello".into(),
            title: "PG Hello".into(),
            body: "alpha gateway beta epsilon".into(),
            indexed_at: now2,
        }],
    )
    .await
    .expect("replace_post_chunks");
    assert_eq!(
        pg.count_chunks().await.unwrap(),
        2,
        "per-post reindex keeps the other post"
    );
    let fetched = pg.fetch_chunks().await.unwrap();
    assert!(
        fetched
            .iter()
            .any(|c| c.post_id == "pg-hello" && c.body.contains("epsilon")),
        "chunk updated"
    );

    // De-index one post (the delete path).
    pg.delete_post_chunks("pg-second")
        .await
        .expect("delete_post_chunks");
    assert_eq!(pg.count_chunks().await.unwrap(), 1, "one post de-indexed");

    // Incremental repair starts from a non-empty/poisoned cache. The stale pg-hello chunk belongs
    // to a Draft and must remain invisible even if physical cleanup failed; current public rows are
    // repaired by version, and the scheduled row joins only once its instant arrives.
    let repaired = pg
        .refresh_public_chunks(now2, 10)
        .await
        .expect("incremental public refresh");
    assert!(repaired >= 1);
    let valid = pg
        .fetch_public_chunks(now2, inkwell::config::INDEX_CHUNK_LIMIT)
        .await
        .expect("validated public chunks");
    assert!(valid.iter().any(|chunk| chunk.post_id == "pg-second"));
    assert!(valid.iter().all(|chunk| chunk.post_id != "pg-hello"));
    assert!(valid.iter().all(|chunk| chunk.post_id != "pg-future"));

    pg.refresh_public_chunks(now + 3_600, 10)
        .await
        .expect("scheduled post due refresh");
    let due = pg
        .fetch_public_chunks(now + 3_600, inkwell::config::INDEX_CHUNK_LIMIT)
        .await
        .expect("validated due chunks");
    assert!(
        due.iter().any(|chunk| chunk.post_id == "pg-future"),
        "scheduled post joins an already non-empty cache at its instant"
    );

    // Simulate an old rollback image writing every authoring field without advancing the new CAS
    // token. The forward migration must preserve that row as a new immutable version, then become
    // idempotent once its current snapshot matches.
    let mut repair_post = post2.clone();
    repair_post.id = "post_pg_forward_repair".to_string();
    repair_post.slug = "pg-forward-repair".to_string();
    repair_post.created_at = now - 700;
    repair_post.updated_at = now - 700;
    pg.create_post(&repair_post)
        .await
        .expect("create forward-repair fixture");
    sqlx::query(
        "UPDATE posts SET title = $2, body_md = $3, published = $4, publish_at = $5, \
                featured = $6, pinned = $7, tags = $8, cover_url = $9, custom_excerpt = $10, \
                meta_title = $11, meta_description = $12, canonical_url = $13, \
                social_title = $14, social_description = $15, social_image = $16, updated_at = $17 \
         WHERE id = $1",
    )
    .bind(&repair_post.id)
    .bind("Rollback title")
    .bind("rollback body and metadata")
    .bind(false)
    .bind(now + 7_200)
    .bind(true)
    .bind(true)
    .bind("rollback, repair")
    .bind("https://drive.w33d.xyz/s/rollback_cover")
    .bind("Rollback excerpt")
    .bind("Rollback meta title")
    .bind("Rollback meta description")
    .bind("https://example.com/rollback")
    .bind("Rollback social title")
    .bind("Rollback social description")
    .bind("https://drive.w33d.xyz/s/rollback_social")
    .bind(now + 1)
    .execute(&raw)
    .await
    .expect("simulate old-image update without edit_version bump");
    assert_eq!(
        pg.get_post("pg-forward-repair").await.unwrap().edit_version,
        1,
        "rollback image left the CAS token stale"
    );
    pg.migrate().await.expect("forward repair rollback write");
    let repaired_post = pg.get_post("pg-forward-repair").await.unwrap();
    assert_eq!(repaired_post.edit_version, 2);
    let repaired_revisions = pg
        .list_post_revisions(&repaired_post.id, 50)
        .await
        .unwrap();
    assert_eq!(repaired_revisions.len(), 2);
    assert_eq!(repaired_revisions[0].source, "forward-repair");
    let repaired_revision = pg
        .get_post_revision(&repaired_post.id, &repaired_revisions[0].id)
        .await
        .unwrap()
        .unwrap();
    assert_revision_matches_post(&repaired_revision, &repaired_post);
    pg.migrate()
        .await
        .expect("forward repair is idempotent after snapshot");
    assert_eq!(
        pg.get_post("pg-forward-repair")
            .await
            .unwrap()
            .edit_version,
        2
    );
    assert_eq!(
        pg.list_post_revisions(&repaired_post.id, 50)
            .await
            .unwrap()
            .len(),
        2
    );

    // Emulate legacy child tables without foreign keys, then delete through an old image. A
    // re-upgrade must remove both orphan kinds and remain safe on repeated startup.
    for (table, constraint) in [
        ("post_revisions", "post_revisions_post_id_fkey"),
        ("writer_autosaves", "writer_autosaves_post_id_fkey"),
    ] {
        sqlx::query(&format!(
            "ALTER TABLE {table} DROP CONSTRAINT {constraint}"
        ))
        .execute(&raw)
        .await
        .expect("remove fresh FK to emulate a legacy table");
    }
    let mut legacy_post = post2.clone();
    legacy_post.id = "post_pg_legacy_orphan".to_string();
    legacy_post.slug = "pg-legacy-orphan".to_string();
    legacy_post.created_at = now - 800;
    legacy_post.updated_at = now - 800;
    pg.create_post(&legacy_post)
        .await
        .expect("create legacy orphan fixture");
    let mut legacy_autosave = autosave.clone();
    legacy_autosave.session_id =
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string();
    legacy_autosave.post_id = legacy_post.id.clone();
    legacy_autosave.base_version = 1;
    legacy_autosave.client_seq = 1;
    assert!(matches!(
        pg.put_writer_autosave(legacy_autosave, now)
            .await
            .unwrap(),
        AutosaveOutcome::Saved(_)
    ));
    sqlx::query("DELETE FROM posts WHERE id = $1")
        .bind(&legacy_post.id)
        .execute(&raw)
        .await
        .expect("legacy image deletes parent only");
    let legacy_children: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM post_revisions WHERE post_id = $1) + \
                (SELECT count(*) FROM writer_autosaves WHERE post_id = $1)",
    )
    .bind(&legacy_post.id)
    .fetch_one(&raw)
    .await
    .unwrap();
    assert_eq!(legacy_children, 2, "legacy delete leaves both orphan kinds");
    pg.migrate().await.expect("re-upgrade cleans legacy orphans");
    pg.migrate()
        .await
        .expect("legacy orphan repair is idempotent");
    let repaired_legacy_children: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM post_revisions WHERE post_id = $1) + \
                (SELECT count(*) FROM writer_autosaves WHERE post_id = $1)",
    )
    .bind(&legacy_post.id)
    .fetch_one(&raw)
    .await
    .unwrap();
    assert_eq!(repaired_legacy_children, 0);

    println!(
        "PG STORE INTEGRATION OK: migrate (idempotent) + create/conflict/list/get/update/delete \
         round-trip + full new/read/delete HTTP flow against real Postgres"
    );
}

async fn raw_call(state: &AppState, req: Request<Body>) -> (StatusCode, Vec<u8>) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, bytes)
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn assert_revision_matches_post(revision: &inkwell::store::PostRevision, post: &Post) {
    assert_eq!(revision.post_id, post.id);
    assert_eq!(revision.edit_version, post.edit_version);
    assert_eq!(revision.title, post.title);
    assert_eq!(revision.body_md, post.body_md);
    assert_eq!(revision.published, post.published);
    assert_eq!(revision.publish_at, post.publish_at);
    assert_eq!(revision.featured, post.featured);
    assert_eq!(revision.pinned, post.pinned);
    assert_eq!(revision.tags, post.tags);
    assert_eq!(revision.cover_url, post.cover_url);
    assert_eq!(revision.custom_excerpt, post.custom_excerpt);
    assert_eq!(revision.meta_title, post.meta_title);
    assert_eq!(revision.meta_description, post.meta_description);
    assert_eq!(revision.canonical_url, post.canonical_url);
    assert_eq!(revision.social_title, post.social_title);
    assert_eq!(revision.social_description, post.social_description);
    assert_eq!(revision.social_image, post.social_image);
}
