//! Real PostgreSQL migration, quota, CAS and deletion-race coverage for personal Bookmarks.

use std::sync::Arc;

use agora::model::{Post, Thread};
use agora::store::{
    BookmarkCas, BookmarkReminderUpdate, BookmarkState, PgStore, Store, StoreError,
    MAX_BOOKMARKS_PER_USER,
};
use agora::{default_categories, new_id, now_secs};
use sqlx::postgres::PgPoolOptions;
use tokio::sync::Barrier;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg_bookmarks_are_migrated_linearizable_and_cascading() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("NOTE: TEST_DATABASE_URL not set — skipping PostgreSQL Bookmark test");
        return;
    };
    let store = Arc::new(PgStore::connect(&url).await.expect("connect"));
    store.migrate().await.expect("migrate");
    store.migrate().await.expect("idempotent migrate");
    store
        .seed_categories_if_empty(&default_categories())
        .await
        .unwrap();
    let raw = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    let fk_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.table_constraints \
         WHERE constraint_schema = CURRENT_SCHEMA \
           AND table_name = 'forum_bookmarks' \
           AND constraint_name = 'fk_forum_bookmark_post' \
           AND constraint_type = 'FOREIGN KEY'",
    )
    .fetch_one(&raw)
    .await
    .unwrap();
    assert_eq!(fk_count, 1);

    let suffix = new_id("bookmark_pg");
    let owner = format!("u_{suffix}");
    let now = now_secs();
    let (thread, op) = fixture_thread(&suffix, now);
    store.create_thread(&thread, &op).await.unwrap();

    let mut creates = Vec::new();
    for _ in 0..12 {
        let store = Arc::clone(&store);
        let owner = owner.clone();
        let post_id = op.id.clone();
        creates.push(tokio::spawn(async move {
            store.ensure_bookmark(&owner, &post_id, now).await
        }));
    }
    for create in creates {
        assert_eq!(create.await.unwrap().unwrap().version, 1);
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM forum_bookmarks WHERE owner_sub = $1 AND post_id = $2",
    )
    .bind(&owner)
    .bind(&op.id)
    .fetch_one(&raw)
    .await
    .unwrap();
    assert_eq!(count, 1);
    let saved = store
        .get_bookmark(&owner, &op.id)
        .await
        .unwrap()
        .unwrap()
        .bookmark;

    let due = store
        .update_bookmark(
            &owner,
            &op.id,
            cas(&saved),
            "private pg note",
            BookmarkReminderUpdate::Set(now + 1),
            now,
        )
        .await
        .unwrap();
    let complete_store = Arc::clone(&store);
    let snooze_store = Arc::clone(&store);
    let complete_owner = owner.clone();
    let snooze_owner = owner.clone();
    let complete_post = op.id.clone();
    let snooze_post = op.id.clone();
    let complete_bookmark_id = due.bookmark_id.clone();
    let snooze_bookmark_id = due.bookmark_id.clone();
    let due_version = due.version;
    let complete = tokio::spawn(async move {
        complete_store
            .complete_due_bookmark(
                &complete_owner,
                &complete_post,
                BookmarkCas {
                    bookmark_id: &complete_bookmark_id,
                    version: due_version,
                },
                now + 2,
            )
            .await
    });
    let snooze = tokio::spawn(async move {
        snooze_store
            .snooze_bookmark(
                &snooze_owner,
                &snooze_post,
                BookmarkCas {
                    bookmark_id: &snooze_bookmark_id,
                    version: due_version,
                },
                now + 86_400,
                now + 2,
            )
            .await
    });
    let results = [complete.await.unwrap(), snooze.await.unwrap()];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(StoreError::Conflict(_))))
            .count(),
        1
    );

    let lifecycle = Post {
        id: format!("p_{}_lifecycle", suffix),
        thread_id: thread.id.clone(),
        body_md: "due lifecycle".to_string(),
        quoted_post_id: String::new(),
        author_sub: owner.clone(),
        author_email: format!("{owner}@holdfast.local"),
        created_at: now + 3,
    };
    store.add_reply(&lifecycle).await.unwrap();
    let lifecycle_saved = store
        .ensure_bookmark(&owner, &lifecycle.id, now + 3)
        .await
        .unwrap();
    let due_lifecycle = store
        .update_bookmark(
            &owner,
            &lifecycle.id,
            cas(&lifecycle_saved),
            "lifecycle",
            BookmarkReminderUpdate::Set(now + 10),
            now + 3,
        )
        .await
        .unwrap();
    assert!(store
        .bookmark_page(&owner, BookmarkState::Due, None, 30, now + 10)
        .await
        .unwrap()
        .iter()
        .any(|item| item.bookmark.post_id == lifecycle.id));
    let snoozed = store
        .snooze_bookmark(
            &owner,
            &lifecycle.id,
            cas(&due_lifecycle),
            now + 100,
            now + 11,
        )
        .await
        .unwrap();
    assert!(store
        .bookmark_page(&owner, BookmarkState::Scheduled, None, 30, now + 11)
        .await
        .unwrap()
        .iter()
        .any(|item| item.bookmark.post_id == lifecycle.id));
    let completed = store
        .complete_due_bookmark(
            &owner,
            &lifecycle.id,
            cas(&snoozed),
            now + 100,
        )
        .await
        .unwrap();
    assert_eq!(completed.remind_at, None);
    store
        .remove_bookmark(
            &owner,
            &lifecycle.id,
            cas(&completed),
        )
        .await
        .unwrap();
    assert!(store
        .get_bookmark(&owner, &lifecycle.id)
        .await
        .unwrap()
        .is_none());

    let reply = Post {
        id: format!("p_{}_reply", suffix),
        thread_id: thread.id.clone(),
        body_md: "delete target".to_string(),
        quoted_post_id: String::new(),
        author_sub: owner.clone(),
        author_email: format!("{owner}@holdfast.local"),
        created_at: now + 3,
    };
    store.add_reply(&reply).await.unwrap();
    let race_start = Arc::new(Barrier::new(3));
    let ensure_store = Arc::clone(&store);
    let delete_store = Arc::clone(&store);
    let ensure_start = Arc::clone(&race_start);
    let delete_start = Arc::clone(&race_start);
    let ensure_owner = owner.clone();
    let ensure_post = reply.id.clone();
    let delete_post = reply.id.clone();
    let ensure = tokio::spawn(async move {
        ensure_start.wait().await;
        ensure_store
            .ensure_bookmark(&ensure_owner, &ensure_post, now + 3)
            .await
    });
    let delete = tokio::spawn(async move {
        delete_start.wait().await;
        delete_store.delete_post(&delete_post).await
    });
    race_start.wait().await;
    let ensure_result = ensure.await.unwrap();
    delete.await.unwrap().unwrap();
    assert!(ensure_result.is_ok() || matches!(ensure_result, Err(StoreError::NotFound(_))));
    assert!(store
        .get_bookmark(&owner, &reply.id)
        .await
        .unwrap()
        .is_none());

    let aba_post = Post {
        id: format!("p_{}_aba", suffix),
        thread_id: thread.id.clone(),
        body_md: "ABA target".to_string(),
        quoted_post_id: String::new(),
        author_sub: owner.clone(),
        author_email: format!("{owner}@holdfast.local"),
        created_at: now + 4,
    };
    store.add_reply(&aba_post).await.unwrap();
    let original = store
        .ensure_bookmark(&owner, &aba_post.id, now + 4)
        .await
        .unwrap();
    assert!(matches!(
        store
            .snooze_bookmark(
                &owner,
                &aba_post.id,
                cas(&original),
                now + 100,
                now + 5,
            )
            .await
            .unwrap_err(),
        StoreError::InvalidOperation(_)
    ));
    store
        .remove_bookmark(
            &owner,
            &aba_post.id,
            cas(&original),
        )
        .await
        .unwrap();
    let replacement = store
        .ensure_bookmark(&owner, &aba_post.id, now + 5)
        .await
        .unwrap();
    assert_eq!(replacement.version, original.version);
    assert_ne!(replacement.bookmark_id, original.bookmark_id);
    assert!(matches!(
        store
            .update_bookmark(
                &owner,
                &aba_post.id,
                cas(&original),
                "stale ABA update",
                BookmarkReminderUpdate::Clear,
                now + 6,
            )
            .await
            .unwrap_err(),
        StoreError::Conflict(_)
    ));
    assert!(matches!(
        store
            .remove_bookmark(
                &owner,
                &aba_post.id,
                cas(&original),
            )
            .await
            .unwrap_err(),
        StoreError::Conflict(_)
    ));
    assert_eq!(
        store
            .get_bookmark(&owner, &aba_post.id)
            .await
            .unwrap()
            .unwrap()
            .bookmark
            .bookmark_id,
        replacement.bookmark_id
    );

    // Fill a separate owner to one below the quota in one bounded SQL fixture, then race two
    // creates. The owner guard must serialize count+insert so exactly one reaches the cap.
    let quota_owner = format!("u_quota_{suffix}");
    let quota_thread_id = format!("t_quota_{suffix}");
    let quota_op_id = format!("p_quota_{suffix}_op");
    let quota_thread = Thread {
        id: quota_thread_id.clone(),
        category_id: "general".to_string(),
        title: "PG bookmark quota".to_string(),
        author_sub: quota_owner.clone(),
        author_email: format!("{quota_owner}@holdfast.local"),
        created_at: now,
        last_at: now,
        locked: false,
        pinned: false,
        accepted_post_id: String::new(),
    };
    let quota_op = Post {
        id: quota_op_id,
        thread_id: quota_thread_id.clone(),
        body_md: "quota op".to_string(),
        quoted_post_id: String::new(),
        author_sub: quota_owner.clone(),
        author_email: format!("{quota_owner}@holdfast.local"),
        created_at: now,
    };
    store.create_thread(&quota_thread, &quota_op).await.unwrap();
    let prefix = format!("p_quota_{suffix}_");
    sqlx::query(
        "INSERT INTO posts \
             (id, thread_id, body_md, quoted_post_id, author_sub, author_email, created_at) \
         SELECT $1 || n::TEXT, $2, 'quota', '', $3, $4, $5 + n \
         FROM generate_series(1, $6) AS n",
    )
    .bind(&prefix)
    .bind(&quota_thread_id)
    .bind(&quota_owner)
    .bind(format!("{quota_owner}@holdfast.local"))
    .bind(now)
    .bind((MAX_BOOKMARKS_PER_USER - 1) as i64)
    .execute(&raw)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO forum_bookmarks \
             (bookmark_id, owner_sub, post_id, note, remind_at, created_at, updated_at, version) \
         SELECT $5 || n::TEXT, $1, $2 || n::TEXT, '', NULL, $3 + n, $3 + n, 1 \
         FROM generate_series(1, $4) AS n",
    )
    .bind(&quota_owner)
    .bind(&prefix)
    .bind(now)
    .bind((MAX_BOOKMARKS_PER_USER - 1) as i64)
    .bind(format!("bm_quota_{suffix}_"))
    .execute(&raw)
    .await
    .unwrap();
    let candidate_a = Post {
        id: format!("{prefix}candidate_a"),
        thread_id: quota_thread_id.clone(),
        body_md: "candidate a".to_string(),
        quoted_post_id: String::new(),
        author_sub: quota_owner.clone(),
        author_email: format!("{quota_owner}@holdfast.local"),
        created_at: now + 20_000,
    };
    let candidate_b = Post {
        id: format!("{prefix}candidate_b"),
        ..candidate_a.clone()
    };
    store.add_reply(&candidate_a).await.unwrap();
    store.add_reply(&candidate_b).await.unwrap();
    let first_store = Arc::clone(&store);
    let second_store = Arc::clone(&store);
    let first_owner = quota_owner.clone();
    let second_owner = quota_owner.clone();
    let first_id = candidate_a.id.clone();
    let second_id = candidate_b.id.clone();
    let first = tokio::spawn(async move {
        first_store
            .ensure_bookmark(&first_owner, &first_id, now + 30_000)
            .await
    });
    let second = tokio::spawn(async move {
        second_store
            .ensure_bookmark(&second_owner, &second_id, now + 30_000)
            .await
    });
    let quota_results = [first.await.unwrap(), second.await.unwrap()];
    assert_eq!(
        quota_results.iter().filter(|result| result.is_ok()).count(),
        1
    );
    assert_eq!(
        quota_results
            .iter()
            .filter(|result| matches!(result, Err(StoreError::InvalidOperation(_))))
            .count(),
        1
    );
    assert_eq!(
        store
            .bookmark_page(&quota_owner, BookmarkState::All, None, 31, now + 40_000)
            .await
            .unwrap()
            .len(),
        31,
        "page remains bounded while the database contains exactly the quota"
    );
    let quota_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM forum_bookmarks WHERE owner_sub = $1")
            .bind(&quota_owner)
            .fetch_one(&raw)
            .await
            .unwrap();
    assert_eq!(quota_count, MAX_BOOKMARKS_PER_USER as i64);

    store.delete_thread(&thread.id).await.unwrap();
    store.delete_thread(&quota_thread_id).await.unwrap();
    assert_eq!(store.due_bookmark_count(&owner, i64::MAX).await.unwrap(), 0);
    sqlx::query("DELETE FROM forum_bookmark_owner_guards WHERE owner_sub = $1 OR owner_sub = $2")
        .bind(&owner)
        .bind(&quota_owner)
        .execute(&raw)
        .await
        .unwrap();
}

#[tokio::test]
async fn pg_legacy_bookmarks_receive_stable_ids_without_losing_post_cascade() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("NOTE: TEST_DATABASE_URL not set — skipping PostgreSQL Bookmark migration test");
        return;
    };
    let schema = new_id("agora_bookmark_migration");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    sqlx::query(&format!("SET search_path TO {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TABLE posts (\
             id TEXT PRIMARY KEY, thread_id TEXT NOT NULL, body_md TEXT NOT NULL, \
             quoted_post_id TEXT NOT NULL DEFAULT '', author_sub TEXT NOT NULL, \
             author_email TEXT NOT NULL, created_at BIGINT NOT NULL\
         )",
    )
    .execute(&admin)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO posts \
             (id, thread_id, body_md, quoted_post_id, author_sub, author_email, created_at) \
         VALUES ('p_legacy_bookmark', 't_legacy_bookmark', 'legacy', '', \
                 'u_legacy_bookmark', 'legacy@holdfast.local', 1)",
    )
    .execute(&admin)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE forum_bookmarks (\
             owner_sub TEXT NOT NULL, post_id TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', \
             remind_at BIGINT, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, \
             version BIGINT NOT NULL DEFAULT 1, PRIMARY KEY (owner_sub, post_id), \
             CONSTRAINT fk_forum_bookmark_post FOREIGN KEY (post_id) \
                 REFERENCES posts(id) ON DELETE CASCADE\
         )",
    )
    .execute(&admin)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO forum_bookmarks \
             (owner_sub, post_id, note, remind_at, created_at, updated_at, version) \
         VALUES ('u_legacy_bookmark', 'p_legacy_bookmark', 'keep me', NULL, 1, 1, 7)",
    )
    .execute(&admin)
    .await
    .unwrap();

    let store = PgStore::from_pool(admin.clone());
    store.migrate().await.unwrap();
    let first_id: String = sqlx::query_scalar(
        "SELECT bookmark_id FROM forum_bookmarks \
         WHERE owner_sub = 'u_legacy_bookmark' AND post_id = 'p_legacy_bookmark'",
    )
    .fetch_one(&admin)
    .await
    .unwrap();
    assert!(first_id.starts_with("bm_"));
    let nullable: String = sqlx::query_scalar(
        "SELECT is_nullable FROM information_schema.columns \
         WHERE table_schema = $1 AND table_name = 'forum_bookmarks' \
           AND column_name = 'bookmark_id'",
    )
    .bind(&schema)
    .fetch_one(&admin)
    .await
    .unwrap();
    assert_eq!(nullable, "NO");

    store.migrate().await.unwrap();
    let second_id: String = sqlx::query_scalar(
        "SELECT bookmark_id FROM forum_bookmarks \
         WHERE owner_sub = 'u_legacy_bookmark' AND post_id = 'p_legacy_bookmark'",
    )
    .fetch_one(&admin)
    .await
    .unwrap();
    assert_eq!(second_id, first_id, "idempotent migrate must not rewrite identity");

    sqlx::query("DELETE FROM posts WHERE id = 'p_legacy_bookmark'")
        .execute(&admin)
        .await
        .unwrap();
    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM forum_bookmarks")
        .fetch_one(&admin)
        .await
        .unwrap();
    assert_eq!(remaining, 0, "legacy post FK keeps ON DELETE CASCADE");

    sqlx::query("SET search_path TO public")
        .execute(&admin)
        .await
        .unwrap();
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
}

fn fixture_thread(suffix: &str, created_at: i64) -> (Thread, Post) {
    let thread_id = format!("t_{suffix}");
    let post_id = format!("p_{suffix}");
    let subject = format!("u_{suffix}");
    (
        Thread {
            id: thread_id.clone(),
            category_id: "general".to_string(),
            title: "PG bookmarks".to_string(),
            author_sub: subject.clone(),
            author_email: format!("{subject}@holdfast.local"),
            created_at,
            last_at: created_at,
            locked: false,
            pinned: false,
            accepted_post_id: String::new(),
        },
        Post {
            id: post_id,
            thread_id,
            body_md: "PG bookmark body".to_string(),
            quoted_post_id: String::new(),
            author_sub: subject.clone(),
            author_email: format!("{subject}@holdfast.local"),
            created_at,
        },
    )
}

fn cas(bookmark: &agora::model::Bookmark) -> BookmarkCas<'_> {
    BookmarkCas {
        bookmark_id: &bookmark.bookmark_id,
        version: bookmark.version,
    }
}
