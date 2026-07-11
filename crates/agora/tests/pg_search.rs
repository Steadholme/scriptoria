//! PostgreSQL coverage for the Forum search read model.
//!
//! Set `TEST_DATABASE_URL` to run against a disposable database. The default suite remains
//! database-free and returns early when that variable is absent.

use agora::model::{Category, CategoryFormat, Post, Thread};
use agora::store::{AcceptedAnswerAction, PgStore, Store, ThreadSort, ThreadStatusFilter};
use std::sync::Arc;
use std::time::Duration;

use agora::{new_id, now_secs};
use sqlx::postgres::PgPoolOptions;
use tokio::sync::Barrier;

static PG_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg_search_matches_title_and_original_body_with_literal_like_text() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("NOTE: TEST_DATABASE_URL not set — skipping PostgreSQL search integration");
        return;
    };
    let _guard = PG_TEST_LOCK.lock().await;
    let pg = PgStore::connect(&url).await.expect("connect test Postgres");
    pg.migrate().await.expect("migrate test Postgres");
    ensure_category(&pg, "general", CategoryFormat::Discussion).await;

    let now = now_secs();
    let marker = new_id("search");
    let needle = format!("literal-%_!-{marker}");
    let thread = Thread {
        id: new_id("t"),
        category_id: "general".to_string(),
        title: format!("Postgres discovery {marker}"),
        author_sub: "u_pg_search".to_string(),
        author_email: "pg-search@holdfast.local".to_string(),
        created_at: now,
        last_at: now,
        locked: false,
        pinned: false,
        accepted_post_id: String::new(),
    };
    let original = Post {
        // Deliberately sorts AFTER the same-second reply id. Stable first_post_id, not
        // `(created_at,id)`, must keep this post as OP.
        id: format!("p_z_original_{marker}"),
        thread_id: thread.id.clone(),
        body_md: format!("Original post contains {needle}"),
        quoted_post_id: String::new(),
        author_sub: thread.author_sub.clone(),
        author_email: thread.author_email.clone(),
        created_at: now,
    };
    pg.create_thread(&thread, &original)
        .await
        .expect("create search fixture");
    let reply = Post {
        id: format!("p_a_reply_{marker}"),
        thread_id: thread.id.clone(),
        body_md: "One reply".to_string(),
        quoted_post_id: String::new(),
        author_sub: "u_pg_reply".to_string(),
        author_email: "reply@holdfast.local".to_string(),
        created_at: now,
    };
    pg.add_reply(&reply)
        .await
        .expect("add search fixture reply");
    let hits = pg
        .search_threads(
            &format!("  {needle}  "),
            Some("general"),
            ThreadStatusFilter::Any,
            10,
        )
        .await
        .expect("search original post");
    let hit = hits
        .iter()
        .find(|hit| hit.thread.id == thread.id)
        .expect("fixture found by literal OP body");
    assert_eq!(hit.reply_count, 1);
    assert!(hit.thread.accepted_post_id.is_empty());
    assert_eq!(hit.thread.last_at, now);
    assert_eq!(
        pg.first_post_in_thread(&thread.id)
            .await
            .unwrap()
            .unwrap()
            .id,
        original.id,
        "same-second lexicographically earlier reply never becomes OP"
    );
    assert!(
        pg.search_threads(&needle, Some("support"), ThreadStatusFilter::Any, 10)
            .await
            .unwrap()
            .iter()
            .all(|hit| hit.thread.id != thread.id),
        "category filter excludes the fixture"
    );
    assert!(
        pg.search_threads(&marker, None, ThreadStatusFilter::Any, 0)
            .await
            .unwrap()
            .is_empty(),
        "zero store limit is empty"
    );

    let error = pg
        .delete_post(&original.id)
        .await
        .expect_err("PostgreSQL store rejects deleting the OP alone");
    assert!(error.to_string().contains("delete the thread"));
    assert!(
        pg.search_threads(&needle, None, ThreadStatusFilter::Any, 10)
            .await
            .unwrap()
            .iter()
            .any(|hit| hit.thread.id == thread.id),
        "rejected OP deletion leaves its authoritative search text intact"
    );

    pg.delete_post(&reply.id)
        .await
        .expect("delete a non-OP reply");
    let after_reply_delete = pg
        .search_threads(&needle, None, ThreadStatusFilter::Any, 10)
        .await
        .unwrap()
        .into_iter()
        .find(|hit| hit.thread.id == thread.id)
        .expect("OP body remains searchable after reply delete");
    assert_eq!(after_reply_delete.first_body_md, original.body_md);
    assert_eq!(after_reply_delete.reply_count, 0);
    assert!(after_reply_delete.thread.accepted_post_id.is_empty());
    assert_eq!(after_reply_delete.thread.last_at, now);

    pg.delete_thread(&thread.id)
        .await
        .expect("remove search fixture");
    assert!(
        pg.search_threads(&needle, None, ThreadStatusFilter::Any, 10)
            .await
            .unwrap()
            .iter()
            .all(|hit| hit.thread.id != thread.id),
        "Delete thread removes OP text from PostgreSQL search"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg_question_status_and_solution_body_are_one_bounded_read_model() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("NOTE: TEST_DATABASE_URL not set — skipping PostgreSQL Q&A search integration");
        return;
    };
    let _guard = PG_TEST_LOCK.lock().await;
    let pg = PgStore::connect(&url).await.expect("connect test Postgres");
    pg.migrate().await.expect("migrate test Postgres");

    let now = now_secs();
    let marker = new_id("qa_search");
    let category_id = format!("question-{marker}");
    pg.create_category(&Category {
        id: category_id.clone(),
        name: "PG Question Search".to_string(),
        sort_order: 900,
        format: CategoryFormat::Question,
    })
    .await
    .unwrap();

    let answered = Thread {
        id: new_id("t"),
        category_id: category_id.clone(),
        title: format!("Answered fixture {marker}"),
        author_sub: "u_pg_question".to_string(),
        author_email: "pg-question@holdfast.local".to_string(),
        created_at: now,
        last_at: now,
        locked: false,
        pinned: false,
        accepted_post_id: String::new(),
    };
    let answered_op = Post {
        id: new_id("p"),
        thread_id: answered.id.clone(),
        body_md: "Original question has no secret solution term.".to_string(),
        quoted_post_id: String::new(),
        author_sub: answered.author_sub.clone(),
        author_email: answered.author_email.clone(),
        created_at: now,
    };
    pg.create_thread(&answered, &answered_op).await.unwrap();
    let solution_needle = format!("solution-only-{marker}");
    let solution = Post {
        id: new_id("p"),
        thread_id: answered.id.clone(),
        body_md: format!("Accepted body contains {solution_needle}"),
        quoted_post_id: String::new(),
        author_sub: "u_pg_expert".to_string(),
        author_email: "pg-expert@holdfast.local".to_string(),
        created_at: now + 1,
    };
    pg.add_reply(&solution).await.unwrap();
    pg.mutate_accepted_answer(
        &answered.id,
        AcceptedAnswerAction::Accept {
            post_id: solution.id.clone(),
        },
    )
    .await
    .unwrap();

    let unanswered = Thread {
        id: new_id("t"),
        category_id: category_id.clone(),
        title: format!("Unanswered fixture {marker}"),
        author_sub: "u_pg_question_2".to_string(),
        author_email: "pg-question-2@holdfast.local".to_string(),
        created_at: now + 2,
        last_at: now + 2,
        locked: false,
        pinned: false,
        accepted_post_id: String::new(),
    };
    let unanswered_op = Post {
        id: new_id("p"),
        thread_id: unanswered.id.clone(),
        body_md: format!("Still waiting {marker}"),
        quoted_post_id: String::new(),
        author_sub: unanswered.author_sub.clone(),
        author_email: unanswered.author_email.clone(),
        created_at: now + 2,
    };
    pg.create_thread(&unanswered, &unanswered_op).await.unwrap();

    let hits = pg
        .search_threads(
            &solution_needle,
            None,
            ThreadStatusFilter::Answered,
            10,
        )
        .await
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].thread.id, answered.id);
    assert!(hits[0].matched_in_solution);
    assert_eq!(hits[0].accepted_body_md, solution.body_md);

    let answered_list = pg
        .list_threads(
            None,
            ThreadSort::Latest,
            None,
            ThreadStatusFilter::Answered,
            10,
            now + 3,
        )
        .await
        .unwrap();
    assert!(answered_list.iter().any(|thread| thread.id == answered.id));
    assert!(answered_list.iter().all(|thread| thread.id != unanswered.id));
    let unanswered_list = pg
        .list_threads(
            None,
            ThreadSort::Latest,
            None,
            ThreadStatusFilter::Unanswered,
            10,
            now + 3,
        )
        .await
        .unwrap();
    assert!(unanswered_list.iter().any(|thread| thread.id == unanswered.id));
    assert!(unanswered_list.iter().all(|thread| thread.id != answered.id));

    pg.delete_thread(&answered.id).await.unwrap();
    pg.delete_thread(&unanswered.id).await.unwrap();
    pg.delete_category(&category_id).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg_migrate_backfills_legacy_original_body_without_overwriting_current_content() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("NOTE: TEST_DATABASE_URL not set — skipping PostgreSQL legacy backfill");
        return;
    };
    let _guard = PG_TEST_LOCK.lock().await;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect test Postgres");
    let pg = PgStore::from_pool(pool.clone());
    pg.migrate().await.expect("prepare current schema");
    ensure_category(&pg, "general", CategoryFormat::Discussion).await;

    let now = now_secs();
    let marker = new_id("legacy_search");
    let legacy_thread_id = new_id("t");
    let preserved_thread_id = new_id("t");
    let legacy_op_id = new_id("p");
    let legacy_reply_id = new_id("p");
    let preserved_op_id = new_id("p");
    let legacy_needle = format!("legacy-body-{marker}");
    let preserved_body = format!("already-indexed-{marker}");

    sqlx::query(
        "INSERT INTO threads \
         (id, category_id, title, author_sub, author_email, created_at, last_at, first_body_md, locked, pinned, accepted_post_id) \
         VALUES ($1, 'general', $2, 'u_legacy', 'legacy@holdfast.local', $3, $3, '', FALSE, FALSE, '')",
    )
    .bind(&legacy_thread_id)
    .bind(format!("Legacy search fixture {marker}"))
    .bind(now)
    .execute(&pool)
    .await
    .expect("insert legacy thread");
    sqlx::query(
        "INSERT INTO posts \
         (id, thread_id, body_md, quoted_post_id, author_sub, author_email, created_at) \
         VALUES ($1, $2, $3, '', 'u_legacy', 'legacy@holdfast.local', $4)",
    )
    .bind(&legacy_op_id)
    .bind(&legacy_thread_id)
    .bind(format!("Earliest original contains {legacy_needle}"))
    .bind(now - 10)
    .execute(&pool)
    .await
    .expect("insert legacy original post");
    sqlx::query(
        "INSERT INTO posts \
         (id, thread_id, body_md, quoted_post_id, author_sub, author_email, created_at) \
         VALUES ($1, $2, $3, '', 'u_reply', 'reply@holdfast.local', $4)",
    )
    .bind(&legacy_reply_id)
    .bind(&legacy_thread_id)
    .bind(format!("Later reply {marker}"))
    .bind(now - 5)
    .execute(&pool)
    .await
    .expect("insert later legacy reply");

    sqlx::query(
        "INSERT INTO threads \
         (id, category_id, title, author_sub, author_email, created_at, last_at, first_body_md, locked, pinned, accepted_post_id) \
         VALUES ($1, 'general', $2, 'u_current', 'current@holdfast.local', $3, $3, $4, FALSE, FALSE, '')",
    )
    .bind(&preserved_thread_id)
    .bind(format!("Current search fixture {marker}"))
    .bind(now)
    .bind(&preserved_body)
    .execute(&pool)
    .await
    .expect("insert thread with current denormalised body");
    sqlx::query(
        "INSERT INTO posts \
         (id, thread_id, body_md, quoted_post_id, author_sub, author_email, created_at) \
         VALUES ($1, $2, $3, '', 'u_current', 'current@holdfast.local', $4)",
    )
    .bind(&preserved_op_id)
    .bind(&preserved_thread_id)
    .bind(format!(
        "Source post must not replace current value {marker}"
    ))
    .bind(now)
    .execute(&pool)
    .await
    .expect("insert current original post");

    pg.migrate().await.expect("backfill legacy rows");
    pg.migrate().await.expect("legacy backfill is idempotent");

    let legacy_body: String = sqlx::query_scalar("SELECT first_body_md FROM threads WHERE id = $1")
        .bind(&legacy_thread_id)
        .fetch_one(&pool)
        .await
        .expect("read backfilled body");
    assert_eq!(
        legacy_body,
        format!("Earliest original contains {legacy_needle}")
    );
    let current_body: String =
        sqlx::query_scalar("SELECT first_body_md FROM threads WHERE id = $1")
            .bind(&preserved_thread_id)
            .fetch_one(&pool)
            .await
            .expect("read preserved body");
    assert_eq!(
        current_body, preserved_body,
        "non-empty values are preserved"
    );
    let identities: Vec<(String, String)> = sqlx::query_as(
        "SELECT id, first_post_id FROM threads WHERE id = $1 OR id = $2 ORDER BY id",
    )
    .bind(&legacy_thread_id)
    .bind(&preserved_thread_id)
    .fetch_all(&pool)
    .await
    .expect("read stable OP identities");
    for (thread_id, first_post_id) in identities {
        let expected = if thread_id == legacy_thread_id {
            &legacy_op_id
        } else {
            &preserved_op_id
        };
        assert_eq!(&first_post_id, expected, "migration backfills stable OP id");
    }
    assert!(
        pg.search_threads(&legacy_needle, None, ThreadStatusFilter::Any, 10)
            .await
            .expect("search backfilled original body")
            .iter()
            .any(|hit| hit.thread.id == legacy_thread_id),
        "backfilled legacy body participates in search"
    );

    sqlx::query("DELETE FROM posts WHERE thread_id = $1 OR thread_id = $2")
        .bind(&legacy_thread_id)
        .bind(&preserved_thread_id)
        .execute(&pool)
        .await
        .expect("remove backfill fixture posts");
    sqlx::query("DELETE FROM threads WHERE id = $1 OR id = $2")
        .bind(&legacy_thread_id)
        .bind(&preserved_thread_id)
        .execute(&pool)
    .await
    .expect("remove backfill fixture threads");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg_reply_pages_and_thread_ties_match_memory_ordering() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("NOTE: TEST_DATABASE_URL not set — skipping PostgreSQL pagination parity");
        return;
    };
    let _guard = PG_TEST_LOCK.lock().await;
    let pg = PgStore::connect(&url).await.expect("connect test Postgres");
    pg.migrate().await.expect("migrate test Postgres");

    let marker = new_id("pg_page");
    let category_id = format!("question-{marker}");
    ensure_category(&pg, &category_id, CategoryFormat::Question).await;
    let now = now_secs();
    let thread = fixture_thread(
        &format!("t_page_{marker}"),
        &category_id,
        "PG anchor parity",
        now,
    );
    let op = fixture_post(&format!("p_op_{marker}"), &thread.id, "OP", now);
    pg.create_thread(&thread, &op).await.unwrap();
    let accepted_id = format!("p_c_{marker}");
    for prefix in ["e", "c", "a", "d", "b"] {
        pg.add_reply(&fixture_post(
            &format!("p_{prefix}_{marker}"),
            &thread.id,
            prefix,
            now + 10,
        ))
        .await
        .unwrap();
    }
    pg.mutate_accepted_answer(
        &thread.id,
        AcceptedAnswerAction::Accept {
            post_id: accepted_id.clone(),
        },
    )
    .await
    .unwrap();
    let ids = |posts: Vec<Post>| posts.into_iter().map(|post| post.id).collect::<Vec<_>>();
    assert_eq!(
        ids(pg
            .replies_page(
                &thread.id,
                &op.id,
                Some(&accepted_id),
                &agora::store::ReplyAnchor::First,
                2,
            )
            .await
            .unwrap()),
        [format!("p_a_{marker}"), format!("p_b_{marker}")]
    );
    assert_eq!(
        ids(pg
            .replies_page(
                &thread.id,
                &op.id,
                Some(&accepted_id),
                &agora::store::ReplyAnchor::After(now + 10, format!("p_b_{marker}")),
                2,
            )
            .await
            .unwrap()),
        [format!("p_d_{marker}"), format!("p_e_{marker}")]
    );
    assert_eq!(
        ids(pg
            .replies_page(
                &thread.id,
                &op.id,
                Some(&accepted_id),
                &agora::store::ReplyAnchor::Before(now + 10, format!("p_e_{marker}")),
                2,
            )
            .await
            .unwrap()),
        [format!("p_d_{marker}"), format!("p_b_{marker}")]
    );
    assert_eq!(
        ids(pg
            .replies_page(
                &thread.id,
                &op.id,
                Some(&accepted_id),
                &agora::store::ReplyAnchor::Latest,
                2,
            )
            .await
            .unwrap()),
        [format!("p_e_{marker}"), format!("p_d_{marker}")]
    );

    let tied_a = fixture_thread(
        &format!("t_a_{marker}"),
        &category_id,
        "Tie A",
        now + 100,
    );
    let tied_b = fixture_thread(
        &format!("t_b_{marker}"),
        &category_id,
        "Tie B",
        now + 100,
    );
    let tied_a_op = fixture_post(&format!("p_tie_a_{marker}"), &tied_a.id, "A", now + 100);
    let tied_b_op = fixture_post(&format!("p_tie_b_{marker}"), &tied_b.id, "B", now + 100);
    pg.create_thread(&tied_a, &tied_a_op).await.unwrap();
    pg.create_thread(&tied_b, &tied_b_op).await.unwrap();
    let ordered = pg
        .list_threads(
            Some(&category_id),
            ThreadSort::Latest,
            None,
            ThreadStatusFilter::Questions,
            10,
            now + 100,
        )
        .await
        .unwrap();
    assert_eq!(ordered[0].id, tied_b.id);
    assert_eq!(ordered[1].id, tied_a.id);

    for id in [&thread.id, &tied_a.id, &tied_b.id] {
        pg.delete_thread(id).await.unwrap();
    }
    pg.delete_category(&category_id).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg_invalid_answer_migration_and_public_predicate_are_idempotent() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("NOTE: TEST_DATABASE_URL not set — skipping PostgreSQL answer migration parity");
        return;
    };
    let _guard = PG_TEST_LOCK.lock().await;
    let pg = PgStore::connect(&url).await.expect("connect test Postgres");
    pg.migrate().await.expect("migrate test Postgres");

    let marker = new_id("pg_invalid_answer");
    let question_category = format!("question-{marker}");
    let discussion_category = format!("discussion-{marker}");
    ensure_category(&pg, &question_category, CategoryFormat::Question).await;
    ensure_category(&pg, &discussion_category, CategoryFormat::Discussion).await;
    let now = now_secs();

    let target = fixture_thread(
        &format!("t_target_{marker}"),
        &question_category,
        "Target",
        now,
    );
    let target_op = fixture_post(&format!("p_target_op_{marker}"), &target.id, "Target OP", now);
    let target_reply = fixture_post(
        &format!("p_target_reply_{marker}"),
        &target.id,
        "Cross-only solution",
        now + 1,
    );
    pg.create_thread(&target, &target_op).await.unwrap();
    pg.add_reply(&target_reply).await.unwrap();

    let mut missing = fixture_thread(
        &format!("t_missing_{marker}"),
        &question_category,
        "Missing",
        now + 10,
    );
    missing.accepted_post_id = format!("p_missing_{marker}");
    let missing_op = fixture_post(
        &format!("p_missing_op_{marker}"),
        &missing.id,
        "Missing OP",
        now + 10,
    );
    pg.create_thread(&missing, &missing_op).await.unwrap();

    let mut original = fixture_thread(
        &format!("t_original_{marker}"),
        &question_category,
        "Original",
        now + 20,
    );
    let original_op = fixture_post(
        &format!("p_original_op_{marker}"),
        &original.id,
        "Original OP",
        now + 20,
    );
    original.accepted_post_id = original_op.id.clone();
    pg.create_thread(&original, &original_op).await.unwrap();

    let mut cross = fixture_thread(
        &format!("t_cross_{marker}"),
        &question_category,
        "Cross",
        now + 30,
    );
    cross.accepted_post_id = target_reply.id.clone();
    let cross_op = fixture_post(
        &format!("p_cross_op_{marker}"),
        &cross.id,
        "Cross OP",
        now + 30,
    );
    pg.create_thread(&cross, &cross_op).await.unwrap();

    let mut historical = fixture_thread(
        &format!("t_historical_{marker}"),
        &discussion_category,
        "Historical",
        now + 40,
    );
    let historical_reply_id = format!("p_historical_reply_{marker}");
    historical.accepted_post_id = historical_reply_id.clone();
    let historical_op = fixture_post(
        &format!("p_historical_op_{marker}"),
        &historical.id,
        "Historical OP",
        now + 40,
    );
    pg.create_thread(&historical, &historical_op).await.unwrap();
    pg.add_reply(&fixture_post(
        &historical_reply_id,
        &historical.id,
        &format!("legacy-solution-only-{marker}"),
        now + 41,
    ))
    .await
    .unwrap();

    assert!(pg
        .list_threads(
            Some(&question_category),
            ThreadSort::Latest,
            None,
            ThreadStatusFilter::Answered,
            20,
            now + 50,
        )
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        pg.list_threads(
            Some(&question_category),
            ThreadSort::Latest,
            None,
            ThreadStatusFilter::Unanswered,
            20,
            now + 50,
        )
        .await
        .unwrap()
        .len(),
        4
    );
    assert!(pg
        .search_threads(
            &format!("legacy-solution-only-{marker}"),
            None,
            ThreadStatusFilter::Any,
            20,
        )
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        pg.get_valid_accepted_post(&historical.id)
            .await
            .unwrap()
            .unwrap()
            .id,
        historical_reply_id
    );

    pg.migrate().await.expect("clean invalid accepted pointers");
    pg.migrate().await.expect("accepted pointer cleanup is idempotent");
    for invalid in [&missing.id, &original.id, &cross.id] {
        assert!(pg
            .get_thread(invalid)
            .await
            .unwrap()
            .unwrap()
            .accepted_post_id
            .is_empty());
    }
    assert_eq!(
        pg.get_thread(&historical.id)
            .await
            .unwrap()
            .unwrap()
            .accepted_post_id,
        historical_reply_id,
        "a structurally-valid historical discussion solution survives migration"
    );
    pg.mutate_accepted_answer(&historical.id, AcceptedAnswerAction::Clear)
        .await
        .unwrap();

    for id in [
        &target.id,
        &missing.id,
        &original.id,
        &cross.id,
        &historical.id,
    ] {
        pg.delete_thread(id).await.unwrap();
    }
    pg.delete_category(&question_category).await.unwrap();
    pg.delete_category(&discussion_category).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg_guarded_commands_serialize_conflicting_writes_without_orphans() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("NOTE: TEST_DATABASE_URL not set — skipping PostgreSQL guarded command races");
        return;
    };
    let _guard = PG_TEST_LOCK.lock().await;
    let pg = Arc::new(PgStore::connect(&url).await.expect("connect test Postgres"));
    pg.migrate().await.expect("migrate test Postgres");
    let marker = new_id("pg_guard");
    let category = |name: &str| format!("{name}-{marker}");
    let categories = [
        category("accept-format"),
        category("accept-delete"),
        category("move-source"),
        category("move-target"),
        category("reply-delete"),
        category("reply-lock"),
        category("create-delete"),
    ];
    for id in &categories {
        ensure_category(&pg, id, CategoryFormat::Question).await;
    }
    let now = now_secs();

    let accept_format = fixture_thread(
        &format!("t_accept_format_{marker}"),
        &categories[0],
        "Accept versus format",
        now,
    );
    let accept_format_op = fixture_post(
        &format!("p_accept_format_op_{marker}"),
        &accept_format.id,
        "OP",
        now,
    );
    let accept_format_reply = fixture_post(
        &format!("p_accept_format_reply_{marker}"),
        &accept_format.id,
        "answer",
        now + 1,
    );
    pg.create_thread(&accept_format, &accept_format_op)
        .await
        .unwrap();
    pg.add_reply(&accept_format_reply).await.unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let accept_task = {
        let pg = Arc::clone(&pg);
        let barrier = Arc::clone(&barrier);
        let thread_id = accept_format.id.clone();
        let post_id = accept_format_reply.id.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            pg.mutate_accepted_answer(&thread_id, AcceptedAnswerAction::Accept { post_id })
                .await
        })
    };
    let format_task = {
        let pg = Arc::clone(&pg);
        let barrier = Arc::clone(&barrier);
        let category_id = categories[0].clone();
        tokio::spawn(async move {
            barrier.wait().await;
            pg.transition_category_format(&category_id, CategoryFormat::Discussion)
                .await
        })
    };
    barrier.wait().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        (accept_task.await.unwrap(), format_task.await.unwrap())
    })
    .await
    .expect("accept/format commands must not deadlock");
    let accept_format_category = pg.get_category(&categories[0]).await.unwrap().unwrap();
    let accept_format_thread = pg.get_thread(&accept_format.id).await.unwrap().unwrap();
    assert!(
        accept_format_category.format.is_question()
            || accept_format_thread.accepted_post_id.is_empty()
    );

    let accept_delete = fixture_thread(
        &format!("t_accept_delete_{marker}"),
        &categories[1],
        "Accept versus delete",
        now + 10,
    );
    let accept_delete_op = fixture_post(
        &format!("p_accept_delete_op_{marker}"),
        &accept_delete.id,
        "OP",
        now + 10,
    );
    let accept_delete_reply = fixture_post(
        &format!("p_accept_delete_reply_{marker}"),
        &accept_delete.id,
        "answer",
        now + 11,
    );
    pg.create_thread(&accept_delete, &accept_delete_op)
        .await
        .unwrap();
    pg.add_reply(&accept_delete_reply).await.unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let accept_task = {
        let pg = Arc::clone(&pg);
        let barrier = Arc::clone(&barrier);
        let thread_id = accept_delete.id.clone();
        let post_id = accept_delete_reply.id.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            pg.mutate_accepted_answer(&thread_id, AcceptedAnswerAction::Accept { post_id })
                .await
        })
    };
    let delete_task = {
        let pg = Arc::clone(&pg);
        let barrier = Arc::clone(&barrier);
        let post_id = accept_delete_reply.id.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            pg.delete_post(&post_id).await
        })
    };
    barrier.wait().await;
    let (_, delete_result) = tokio::time::timeout(Duration::from_secs(5), async {
        (accept_task.await.unwrap(), delete_task.await.unwrap())
    })
    .await
    .expect("accept/delete commands must not deadlock");
    delete_result.unwrap();
    assert!(pg
        .get_post(&accept_delete_reply.id)
        .await
        .unwrap()
        .is_none());
    assert!(pg
        .get_thread(&accept_delete.id)
        .await
        .unwrap()
        .unwrap()
        .accepted_post_id
        .is_empty());

    let moving = fixture_thread(
        &format!("t_move_format_{marker}"),
        &categories[2],
        "Move versus format",
        now + 20,
    );
    let moving_op = fixture_post(
        &format!("p_move_format_op_{marker}"),
        &moving.id,
        "OP",
        now + 20,
    );
    let moving_reply = fixture_post(
        &format!("p_move_format_reply_{marker}"),
        &moving.id,
        "answer",
        now + 21,
    );
    pg.create_thread(&moving, &moving_op).await.unwrap();
    pg.add_reply(&moving_reply).await.unwrap();
    pg.mutate_accepted_answer(
        &moving.id,
        AcceptedAnswerAction::Accept {
            post_id: moving_reply.id.clone(),
        },
    )
    .await
    .unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let move_task = {
        let pg = Arc::clone(&pg);
        let barrier = Arc::clone(&barrier);
        let thread_id = moving.id.clone();
        let target_id = categories[3].clone();
        tokio::spawn(async move {
            barrier.wait().await;
            pg.move_thread_to_category(&thread_id, &target_id).await
        })
    };
    let format_task = {
        let pg = Arc::clone(&pg);
        let barrier = Arc::clone(&barrier);
        let target_id = categories[3].clone();
        tokio::spawn(async move {
            barrier.wait().await;
            pg.transition_category_format(&target_id, CategoryFormat::Discussion)
                .await
        })
    };
    barrier.wait().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        (move_task.await.unwrap(), format_task.await.unwrap())
    })
    .await
    .expect("move/format commands must not deadlock");
    let moved = pg.get_thread(&moving.id).await.unwrap().unwrap();
    let target = pg.get_category(&categories[3]).await.unwrap().unwrap();
    assert!(
        moved.category_id != categories[3]
            || target.format.is_question()
            || moved.accepted_post_id.is_empty()
    );

    let reply_delete = fixture_thread(
        &format!("t_reply_delete_{marker}"),
        &categories[4],
        "Reply versus delete",
        now + 30,
    );
    let reply_delete_op = fixture_post(
        &format!("p_reply_delete_op_{marker}"),
        &reply_delete.id,
        "OP",
        now + 30,
    );
    let reply_delete_race = fixture_post(
        &format!("p_reply_delete_race_{marker}"),
        &reply_delete.id,
        "reply",
        now + 31,
    );
    pg.create_thread(&reply_delete, &reply_delete_op)
        .await
        .unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let reply_task = {
        let pg = Arc::clone(&pg);
        let barrier = Arc::clone(&barrier);
        let reply = reply_delete_race.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            pg.add_reply(&reply).await
        })
    };
    let delete_task = {
        let pg = Arc::clone(&pg);
        let barrier = Arc::clone(&barrier);
        let thread_id = reply_delete.id.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            pg.delete_thread(&thread_id).await
        })
    };
    barrier.wait().await;
    let (_, delete_result) = tokio::time::timeout(Duration::from_secs(5), async {
        (reply_task.await.unwrap(), delete_task.await.unwrap())
    })
    .await
    .expect("reply/delete commands must not deadlock");
    delete_result.unwrap();
    assert!(pg.get_thread(&reply_delete.id).await.unwrap().is_none());
    assert!(pg
        .get_post(&reply_delete_race.id)
        .await
        .unwrap()
        .is_none());

    let reply_lock = fixture_thread(
        &format!("t_reply_lock_{marker}"),
        &categories[5],
        "Reply versus lock",
        now + 40,
    );
    let reply_lock_op = fixture_post(
        &format!("p_reply_lock_op_{marker}"),
        &reply_lock.id,
        "OP",
        now + 40,
    );
    let reply_lock_race = fixture_post(
        &format!("p_reply_lock_race_{marker}"),
        &reply_lock.id,
        "reply",
        now + 41,
    );
    pg.create_thread(&reply_lock, &reply_lock_op)
        .await
        .unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let reply_task = {
        let pg = Arc::clone(&pg);
        let barrier = Arc::clone(&barrier);
        let reply = reply_lock_race.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            pg.add_reply(&reply).await
        })
    };
    let lock_task = {
        let pg = Arc::clone(&pg);
        let barrier = Arc::clone(&barrier);
        let thread_id = reply_lock.id.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            pg.set_thread_locked(&thread_id, true).await
        })
    };
    barrier.wait().await;
    let (reply_result, lock_result) = tokio::time::timeout(Duration::from_secs(5), async {
        (reply_task.await.unwrap(), lock_task.await.unwrap())
    })
    .await
    .expect("reply/lock commands must not deadlock");
    lock_result.unwrap();
    assert_eq!(
        reply_result.is_ok(),
        pg.get_post(&reply_lock_race.id).await.unwrap().is_some()
    );
    assert!(pg
        .add_reply(&fixture_post(
            &format!("p_reply_after_lock_{marker}"),
            &reply_lock.id,
            "late reply",
            now + 42,
        ))
        .await
        .is_err());

    let create_delete = fixture_thread(
        &format!("t_create_delete_{marker}"),
        &categories[6],
        "Create versus category delete",
        now + 50,
    );
    let create_delete_op = fixture_post(
        &format!("p_create_delete_op_{marker}"),
        &create_delete.id,
        "OP",
        now + 50,
    );
    let barrier = Arc::new(Barrier::new(3));
    let create_task = {
        let pg = Arc::clone(&pg);
        let barrier = Arc::clone(&barrier);
        let thread = create_delete.clone();
        let op = create_delete_op.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            pg.create_thread(&thread, &op).await
        })
    };
    let delete_task = {
        let pg = Arc::clone(&pg);
        let barrier = Arc::clone(&barrier);
        let category_id = categories[6].clone();
        tokio::spawn(async move {
            barrier.wait().await;
            pg.delete_category(&category_id).await
        })
    };
    barrier.wait().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        (create_task.await.unwrap(), delete_task.await.unwrap())
    })
    .await
    .expect("create/category-delete commands must not deadlock");
    let category_exists = pg.get_category(&categories[6]).await.unwrap().is_some();
    let thread_exists = pg.get_thread(&create_delete.id).await.unwrap().is_some();
    assert_eq!(category_exists, thread_exists, "thread and category cannot orphan");

    for thread_id in [
        &accept_format.id,
        &accept_delete.id,
        &moving.id,
        &reply_lock.id,
        &create_delete.id,
    ] {
        pg.delete_thread(thread_id).await.unwrap();
    }
    for category_id in &categories {
        pg.delete_category(category_id).await.unwrap();
    }
}

async fn ensure_category(pg: &PgStore, id: &str, format: CategoryFormat) {
    pg.create_category(&Category {
        id: id.to_string(),
        name: id.to_string(),
        sort_order: 0,
        format,
    })
    .await
    .unwrap();
}

fn fixture_thread(id: &str, category_id: &str, title: &str, created_at: i64) -> Thread {
    Thread {
        id: id.to_string(),
        category_id: category_id.to_string(),
        title: title.to_string(),
        author_sub: "u_pg_fixture".to_string(),
        author_email: "pg-fixture@holdfast.local".to_string(),
        created_at,
        last_at: created_at,
        locked: false,
        pinned: false,
        accepted_post_id: String::new(),
    }
}

fn fixture_post(id: &str, thread_id: &str, body: &str, created_at: i64) -> Post {
    Post {
        id: id.to_string(),
        thread_id: thread_id.to_string(),
        body_md: body.to_string(),
        quoted_post_id: String::new(),
        author_sub: "u_pg_fixture".to_string(),
        author_email: "pg-fixture@holdfast.local".to_string(),
        created_at,
    }
}
