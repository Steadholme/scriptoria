//! Product, privacy, pagination and adversarial coverage for personal Bookmarks + Due queue.

use std::collections::HashSet;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use tower::ServiceExt;

use agora::model::{Post, Thread};
use agora::handlers::personal_counts;
use agora::store::{
    BookmarkCas, BookmarkCursor, BookmarkReminderUpdate, BookmarkState, StoreError,
    MAX_BOOKMARKS_PER_USER,
    MAX_BOOKMARK_POST_BATCH, MAX_REMINDER_HORIZON_SECS,
};
use agora::{app, build_dev_state, new_id, now_secs, AppState};

const ALICE_SUB: &str = "u_bookmark_alice";
const ALICE_EMAIL: &str = "alice@steadholme.local";
const BOB_SUB: &str = "u_bookmark_bob";
const BOB_EMAIL: &str = "bob@steadholme.local";
const TOK: &str = "bookmarkcsrftoken123";

#[tokio::test]
async fn browser_flow_is_owner_only_no_store_and_honest_about_delivery() {
    let state = build_dev_state().await;
    let (thread, op) = fixture_thread("browser", now_secs());
    state.store.create_thread(&thread, &op).await.unwrap();

    let (status, headers, page) = send(
        &state,
        get_as(&format!("/t/{}", thread.id), ALICE_SUB, ALICE_EMAIL),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(header::CACHE_CONTROL).unwrap(),
        "private, no-store"
    );
    assert!(page.contains("Bookmark this post"));

    let (status, headers, _) = send(
        &state,
        post_as(
            &format!("/t/{}/p/{}/bookmark", thread.id, op.id),
            ALICE_SUB,
            ALICE_EMAIL,
            form(&[("csrf", TOK)]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let target = headers.get(header::LOCATION).unwrap().to_str().unwrap();
    assert!(target.starts_with(&format!("/t/{}?around=", thread.id)));
    assert!(target.ends_with(&format!("#post-{}", op.id)));
    let saved = state
        .store
        .get_bookmark(ALICE_SUB, &op.id)
        .await
        .unwrap()
        .unwrap()
        .bookmark;

    let (_, _, alice_thread) = send(
        &state,
        get_as(&format!("/t/{}", thread.id), ALICE_SUB, ALICE_EMAIL),
    )
    .await;
    assert!(alice_thread.contains("ag-post-bookmark is-saved"));
    let (_, _, bob_thread) = send(
        &state,
        get_as(&format!("/t/{}", thread.id), BOB_SUB, BOB_EMAIL),
    )
    .await;
    assert!(!bob_thread.contains("ag-post-bookmark is-saved\" href"));

    let (status, _, _) = send(
        &state,
        get_as(&format!("/bookmarks/{}/edit", op.id), BOB_SUB, BOB_EMAIL),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = send(
        &state,
        get_as_groups(
            &format!("/bookmarks/{}/edit", op.id),
            "u_admin",
            "admin@steadholme.local",
            "admins",
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "admin has no personal override"
    );

    let (status, _, _) = send(
        &state,
        post_as(
            &format!("/bookmarks/{}/edit", op.id),
            ALICE_SUB,
            ALICE_EMAIL,
            form(&[
                ("csrf", TOK),
                ("expected_bookmark_id", &saved.bookmark_id),
                ("expected_version", "1"),
                ("note", "<script>alert(1)</script> private intent"),
                ("reminder_action", "tomorrow"),
                ("owner_sub", BOB_SUB),
            ]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, headers, scheduled) = send(
        &state,
        get_as("/bookmarks?state=scheduled", ALICE_SUB, ALICE_EMAIL),
    )
    .await;
    assert_eq!(
        headers.get(header::CACHE_CONTROL).unwrap(),
        "private, no-store"
    );
    assert!(scheduled.contains("&lt;script&gt;alert(1)&lt;/script&gt; private intent"));
    assert!(!scheduled.contains("<script>alert(1)</script>"));
    assert!(scheduled.contains("does not send email or push"));

    let (status, _, stale) = send(
        &state,
        post_as(
            &format!("/bookmarks/{}/edit", op.id),
            ALICE_SUB,
            ALICE_EMAIL,
            form(&[
                ("csrf", TOK),
                ("expected_bookmark_id", &saved.bookmark_id),
                ("expected_version", "1"),
                ("note", "stale overwrite"),
                ("reminder_action", "none"),
            ]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(stale.contains("Changed elsewhere"));

    let (status, _, _) = send(
        &state,
        post_as(
            &format!("/bookmarks/{}/snooze", op.id),
            ALICE_SUB,
            ALICE_EMAIL,
            form(&[
                ("csrf", TOK),
                ("expected_bookmark_id", &saved.bookmark_id),
                ("expected_version", "2"),
                ("preset", "arbitrary-seconds"),
            ]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    for custom_time in [
        "1970-01-02T00:00".to_string(),
        "2099-01-01T00:00".to_string(),
    ] {
        let (status, _, _) = send(
            &state,
            post_as(
                &format!("/bookmarks/{}/edit", op.id),
                ALICE_SUB,
                ALICE_EMAIL,
                form(&[
                    ("csrf", TOK),
                    ("expected_bookmark_id", &saved.bookmark_id),
                    ("expected_version", "2"),
                    ("note", "custom boundary"),
                    ("reminder_action", "custom"),
                    ("custom_time", &custom_time),
                ]),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let valid_custom = utc_input(now_secs() + 2 * 24 * 60 * 60);
    let (status, _, _) = send(
        &state,
        post_as(
            &format!("/bookmarks/{}/edit", op.id),
            ALICE_SUB,
            ALICE_EMAIL,
            form(&[
                ("csrf", TOK),
                ("expected_bookmark_id", &saved.bookmark_id),
                ("expected_version", "2"),
                ("note", "custom UTC works"),
                ("reminder_action", "custom"),
                ("custom_time", &valid_custom),
            ]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let current = state
        .store
        .get_bookmark(ALICE_SUB, &op.id)
        .await
        .unwrap()
        .unwrap()
        .bookmark;
    state
        .store
        .update_bookmark(
            ALICE_SUB,
            &op.id,
            cas(&current),
            &current.note,
            BookmarkReminderUpdate::Set(now_secs() + 1),
            now_secs(),
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let due_row = state
        .store
        .get_bookmark(ALICE_SUB, &op.id)
        .await
        .unwrap()
        .unwrap()
        .bookmark;
    let (_, _, due) = send(
        &state,
        get_as("/bookmarks?state=due", ALICE_SUB, ALICE_EMAIL),
    )
    .await;
    assert!(due.contains("Due ·"));
    assert!(due.contains("Bookmarks, 1 due"));
    assert!(!due.contains("notification sent"));

    let (status, _, _) = send(
        &state,
        post_as(
            &format!("/bookmarks/{}/snooze", op.id),
            ALICE_SUB,
            ALICE_EMAIL,
            form(&[
                ("csrf", TOK),
                ("expected_bookmark_id", &due_row.bookmark_id),
                ("expected_version", &due_row.version.to_string()),
                ("preset", "tomorrow"),
            ]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let snoozed = state
        .store
        .get_bookmark(ALICE_SUB, &op.id)
        .await
        .unwrap()
        .unwrap()
        .bookmark;
    assert!(snoozed.remind_at.is_some_and(|at| at > now_secs()));
    assert_eq!(
        state
            .store
            .due_bookmark_count(ALICE_SUB, now_secs())
            .await
            .unwrap(),
        0
    );
    state
        .store
        .update_bookmark(
            ALICE_SUB,
            &op.id,
            cas(&snoozed),
            &snoozed.note,
            BookmarkReminderUpdate::Set(now_secs() + 1),
            now_secs(),
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let due_row = state
        .store
        .get_bookmark(ALICE_SUB, &op.id)
        .await
        .unwrap()
        .unwrap()
        .bookmark;

    let (status, _, _) = send(
        &state,
        post_as(
            &format!("/bookmarks/{}/complete", op.id),
            ALICE_SUB,
            ALICE_EMAIL,
            form(&[
                ("csrf", TOK),
                ("expected_bookmark_id", &due_row.bookmark_id),
                ("expected_version", &due_row.version.to_string()),
            ]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let completed = state
        .store
        .get_bookmark(ALICE_SUB, &op.id)
        .await
        .unwrap()
        .unwrap()
        .bookmark;
    assert_eq!(completed.remind_at, None, "Done keeps the bookmark");

    let (status, _, _) = send(
        &state,
        post_as(
            &format!("/bookmarks/{}/remove", op.id),
            ALICE_SUB,
            ALICE_EMAIL,
            form(&[
                ("csrf", TOK),
                ("expected_bookmark_id", &completed.bookmark_id),
                ("expected_version", &completed.version.to_string()),
            ]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(state
        .store
        .get_bookmark(ALICE_SUB, &op.id)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn csrf_subject_and_cas_fail_closed() {
    let state = build_dev_state().await;
    let (thread, op) = fixture_thread("cas", now_secs());
    state.store.create_thread(&thread, &op).await.unwrap();

    let (status, _, _) = send(
        &state,
        post_without_cookie(
            &format!("/t/{}/p/{}/bookmark", thread.id, op.id),
            ALICE_SUB,
            ALICE_EMAIL,
            form(&[("csrf", TOK)]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, _) = send(
        &state,
        Request::builder()
            .method("POST")
            .uri(format!("/t/{}/p/{}/bookmark", thread.id, op.id))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, format!("__Host-csrf={TOK}"))
            .body(Body::from(form(&[("csrf", TOK)])))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let first = state
        .store
        .ensure_bookmark(ALICE_SUB, &op.id, 10)
        .await
        .unwrap();
    let updated = state
        .store
        .update_bookmark(
            ALICE_SUB,
            &op.id,
            cas(&first),
            "new",
            BookmarkReminderUpdate::Clear,
            11,
        )
        .await
        .unwrap();
    assert_eq!(updated.version, 2);
    assert!(matches!(
        state
            .store
            .update_bookmark(
                ALICE_SUB,
                &op.id,
                cas(&first),
                "stale",
                BookmarkReminderUpdate::Clear,
                12,
            )
            .await
            .unwrap_err(),
        StoreError::Conflict(_)
    ));
    assert!(matches!(
        state
            .store
            .update_bookmark(
                ALICE_SUB,
                &op.id,
                cas(&updated),
                &"x".repeat(201),
                BookmarkReminderUpdate::Clear,
                12,
            )
            .await
            .unwrap_err(),
        StoreError::InvalidOperation(_)
    ));
    assert!(matches!(
        state
            .store
            .update_bookmark(
                ALICE_SUB,
                &op.id,
                cas(&updated),
                "distant",
                BookmarkReminderUpdate::Set(12 + MAX_REMINDER_HORIZON_SECS + 1),
                12,
            )
            .await
            .unwrap_err(),
        StoreError::InvalidOperation(_)
    ));
    assert!(matches!(
        state
            .store
            .update_bookmark(
                ALICE_SUB,
                &op.id,
                cas(&updated),
                "time",
                BookmarkReminderUpdate::Set(12),
                12,
            )
            .await
            .unwrap_err(),
        StoreError::InvalidOperation(_)
    ));
    assert!(state
        .store
        .get_bookmark(BOB_SUB, &op.id)
        .await
        .unwrap()
        .is_none());

    assert!(matches!(
        state
            .store
            .snooze_bookmark(
                ALICE_SUB,
                &op.id,
                cas(&updated),
                100,
                12,
            )
            .await
            .unwrap_err(),
        StoreError::InvalidOperation(_)
    ));

    state
        .store
        .remove_bookmark(
            ALICE_SUB,
            &op.id,
            cas(&updated),
        )
        .await
        .unwrap();
    let replacement = state
        .store
        .ensure_bookmark(ALICE_SUB, &op.id, 13)
        .await
        .unwrap();
    assert_eq!(replacement.version, first.version);
    assert_ne!(replacement.bookmark_id, first.bookmark_id);

    let (status, _, _) = send(
        &state,
        post_as(
            &format!("/bookmarks/{}/edit", op.id),
            ALICE_SUB,
            ALICE_EMAIL,
            form(&[
                ("csrf", TOK),
                ("expected_version", &first.version.to_string()),
                ("note", "pre-identity legacy form"),
                ("reminder_action", "none"),
            ]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, _, _) = send(
        &state,
        post_as(
            &format!("/bookmarks/{}/edit", op.id),
            ALICE_SUB,
            ALICE_EMAIL,
            form(&[
                ("csrf", TOK),
                ("expected_bookmark_id", &first.bookmark_id),
                ("expected_version", &first.version.to_string()),
                ("note", "stale ABA overwrite"),
                ("reminder_action", "none"),
            ]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(matches!(
        state
            .store
            .remove_bookmark(
                ALICE_SUB,
                &op.id,
                cas(&first),
            )
            .await
            .unwrap_err(),
        StoreError::Conflict(_)
    ));
    let current = state
        .store
        .get_bookmark(ALICE_SUB, &op.id)
        .await
        .unwrap()
        .unwrap()
        .bookmark;
    assert_eq!(current.bookmark_id, replacement.bookmark_id);
    assert!(current.note.is_empty());
}

#[tokio::test]
async fn due_count_and_rows_share_the_same_explicit_as_of_boundary() {
    let state = build_dev_state().await;
    let (thread, op) = fixture_thread("as_of", 100);
    state.store.create_thread(&thread, &op).await.unwrap();
    let saved = state
        .store
        .ensure_bookmark(ALICE_SUB, &op.id, 200)
        .await
        .unwrap();
    state
        .store
        .update_bookmark(
            ALICE_SUB,
            &op.id,
            cas(&saved),
            "boundary",
            BookmarkReminderUpdate::Set(300),
            200,
        )
        .await
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("x-auth-subject", HeaderValue::from_static(ALICE_SUB));

    let before = personal_counts(&state, &headers, 299).await.unwrap();
    assert_eq!(before.due_bookmarks, Some(0));
    assert_eq!(
        state
            .store
            .bookmark_page(ALICE_SUB, BookmarkState::Scheduled, None, 30, 299)
            .await
            .unwrap()
            .len(),
        1
    );

    let at_boundary = personal_counts(&state, &headers, 300).await.unwrap();
    assert_eq!(at_boundary.due_bookmarks, Some(1));
    assert_eq!(
        state
            .store
            .bookmark_page(ALICE_SUB, BookmarkState::Due, None, 30, 300)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn keysets_batch_bound_and_delete_are_authoritative() {
    let state = build_dev_state().await;
    let (thread, op) = fixture_thread("keyset", 100);
    state.store.create_thread(&thread, &op).await.unwrap();
    let mut post_ids = vec![op.id.clone()];
    for index in 0..5 {
        let post = Post {
            id: format!("p_keyset_{index}"),
            thread_id: thread.id.clone(),
            body_md: format!("reply {index}"),
            quoted_post_id: String::new(),
            author_sub: BOB_SUB.to_string(),
            author_email: BOB_EMAIL.to_string(),
            created_at: 100,
        };
        state.store.add_reply(&post).await.unwrap();
        post_ids.push(post.id);
    }
    for post_id in &post_ids {
        state
            .store
            .ensure_bookmark(ALICE_SUB, post_id, 200)
            .await
            .unwrap();
    }
    let first = state
        .store
        .bookmark_page(ALICE_SUB, BookmarkState::All, None, 3, 500)
        .await
        .unwrap();
    assert_eq!(first.len(), 3);
    let last = first.last().unwrap();
    let cursor = BookmarkCursor {
        sort_at: last.bookmark.created_at,
        post_id: last.bookmark.post_id.clone(),
    };
    let second = state
        .store
        .bookmark_page(ALICE_SUB, BookmarkState::All, Some(&cursor), 10, 500)
        .await
        .unwrap();
    let ids: HashSet<&str> = first
        .iter()
        .chain(second.iter())
        .map(|item| item.bookmark.post_id.as_str())
        .collect();
    assert_eq!(ids.len(), post_ids.len());

    for post_id in post_ids.iter().take(4) {
        let row = state
            .store
            .get_bookmark(ALICE_SUB, post_id)
            .await
            .unwrap()
            .unwrap()
            .bookmark;
        state
            .store
            .update_bookmark(
                ALICE_SUB,
                post_id,
                cas(&row),
                "",
                BookmarkReminderUpdate::Set(300),
                200,
            )
            .await
            .unwrap();
    }
    let scheduled_first = state
        .store
        .bookmark_page(ALICE_SUB, BookmarkState::Scheduled, None, 2, 250)
        .await
        .unwrap();
    let scheduled_cursor = BookmarkCursor {
        sort_at: 300,
        post_id: scheduled_first.last().unwrap().bookmark.post_id.clone(),
    };
    let scheduled_second = state
        .store
        .bookmark_page(
            ALICE_SUB,
            BookmarkState::Scheduled,
            Some(&scheduled_cursor),
            10,
            250,
        )
        .await
        .unwrap();
    let scheduled_ids: HashSet<&str> = scheduled_first
        .iter()
        .chain(scheduled_second.iter())
        .map(|item| item.bookmark.post_id.as_str())
        .collect();
    assert_eq!(scheduled_ids.len(), 4);
    assert_eq!(
        state
            .store
            .bookmark_page(ALICE_SUB, BookmarkState::Due, None, 10, 300)
            .await
            .unwrap()
            .len(),
        4
    );

    state
        .store
        .update_thread(&thread.id, "Live title", &op.id, "Live body")
        .await
        .unwrap();
    let authoritative = state
        .store
        .get_bookmark(ALICE_SUB, &op.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(authoritative.thread_title, "Live title");
    assert_eq!(authoritative.post_body_md, "Live body");

    let oversized = (0..=MAX_BOOKMARK_POST_BATCH)
        .map(|index| format!("p_{index}"))
        .collect::<Vec<_>>();
    assert!(matches!(
        state
            .store
            .bookmarks_for_posts(ALICE_SUB, &oversized)
            .await
            .unwrap_err(),
        StoreError::InvalidOperation(_)
    ));

    state.store.delete_thread(&thread.id).await.unwrap();
    assert!(state
        .store
        .bookmark_page(ALICE_SUB, BookmarkState::All, None, 30, 500)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_ensure_and_complete_vs_snooze_are_linearizable() {
    let state = build_dev_state().await;
    let (thread, op) = fixture_thread("race", 100);
    state.store.create_thread(&thread, &op).await.unwrap();
    let mut ensures = Vec::new();
    for _ in 0..12 {
        let store = state.store.clone();
        let post_id = op.id.clone();
        ensures.push(tokio::spawn(async move {
            store.ensure_bookmark(ALICE_SUB, &post_id, 200).await
        }));
    }
    for task in ensures {
        assert_eq!(task.await.unwrap().unwrap().version, 1);
    }
    assert_eq!(
        state
            .store
            .bookmark_page(ALICE_SUB, BookmarkState::All, None, 30, 500)
            .await
            .unwrap()
            .len(),
        1
    );

    let race_post = Post {
        id: "p_bookmark_delete_race".to_string(),
        thread_id: thread.id.clone(),
        body_md: "race target".to_string(),
        quoted_post_id: String::new(),
        author_sub: BOB_SUB.to_string(),
        author_email: BOB_EMAIL.to_string(),
        created_at: 500,
    };
    state.store.add_reply(&race_post).await.unwrap();
    let ensure_store = state.store.clone();
    let delete_store = state.store.clone();
    let ensure_id = race_post.id.clone();
    let delete_id = race_post.id.clone();
    let ensure = tokio::spawn(async move {
        ensure_store
            .ensure_bookmark(ALICE_SUB, &ensure_id, 501)
            .await
    });
    let delete = tokio::spawn(async move { delete_store.delete_post(&delete_id).await });
    let ensure_result = ensure.await.unwrap();
    delete.await.unwrap().unwrap();
    assert!(ensure_result.is_ok() || matches!(ensure_result, Err(StoreError::NotFound(_))));
    assert!(state
        .store
        .get_bookmark(ALICE_SUB, &race_post.id)
        .await
        .unwrap()
        .is_none());
    let saved = state
        .store
        .get_bookmark(ALICE_SUB, &op.id)
        .await
        .unwrap()
        .unwrap()
        .bookmark;
    let due = state
        .store
        .update_bookmark(
            ALICE_SUB,
            &op.id,
            cas(&saved),
            "race",
            BookmarkReminderUpdate::Set(300),
            200,
        )
        .await
        .unwrap();
    let complete_store = state.store.clone();
    let snooze_store = state.store.clone();
    let complete_post = op.id.clone();
    let snooze_post = op.id.clone();
    let complete_bookmark_id = due.bookmark_id.clone();
    let snooze_bookmark_id = due.bookmark_id.clone();
    let due_version = due.version;
    let complete = tokio::spawn(async move {
        complete_store
            .complete_due_bookmark(
                ALICE_SUB,
                &complete_post,
                BookmarkCas {
                    bookmark_id: &complete_bookmark_id,
                    version: due_version,
                },
                400,
            )
            .await
    });
    let snooze = tokio::spawn(async move {
        snooze_store
            .snooze_bookmark(
                ALICE_SUB,
                &snooze_post,
                BookmarkCas {
                    bookmark_id: &snooze_bookmark_id,
                    version: due_version,
                },
                1_000,
                400,
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
}

#[tokio::test]
async fn quota_is_exact_and_duplicate_at_cap_remains_idempotent() {
    let state = build_dev_state().await;
    let (thread, op) = fixture_thread("quota", 100);
    state.store.create_thread(&thread, &op).await.unwrap();
    let mut first_id = op.id.clone();
    for index in 0..MAX_BOOKMARKS_PER_USER {
        let post_id = if index == 0 {
            op.id.clone()
        } else {
            let post = Post {
                id: format!("p_quota_{index:04}"),
                thread_id: thread.id.clone(),
                body_md: "quota".to_string(),
                quoted_post_id: String::new(),
                author_sub: BOB_SUB.to_string(),
                author_email: BOB_EMAIL.to_string(),
                created_at: 100 + index as i64,
            };
            state.store.add_reply(&post).await.unwrap();
            post.id
        };
        if index == 0 {
            first_id = post_id.clone();
        }
        state
            .store
            .ensure_bookmark(ALICE_SUB, &post_id, 200 + index as i64)
            .await
            .unwrap();
    }
    state
        .store
        .ensure_bookmark(ALICE_SUB, &first_id, 9_999)
        .await
        .expect("duplicate stays idempotent at quota");
    let extra = Post {
        id: new_id("p"),
        thread_id: thread.id.clone(),
        body_md: "over quota".to_string(),
        quoted_post_id: String::new(),
        author_sub: BOB_SUB.to_string(),
        author_email: BOB_EMAIL.to_string(),
        created_at: 10_000,
    };
    state.store.add_reply(&extra).await.unwrap();
    assert!(matches!(
        state
            .store
            .ensure_bookmark(ALICE_SUB, &extra.id, 10_000)
            .await
            .unwrap_err(),
        StoreError::InvalidOperation(_)
    ));
}

fn fixture_thread(suffix: &str, created_at: i64) -> (Thread, Post) {
    let thread_id = format!("t_bookmark_{suffix}");
    let post_id = format!("p_bookmark_{suffix}");
    (
        Thread {
            id: thread_id.clone(),
            category_id: "general".to_string(),
            title: format!("Bookmark {suffix}"),
            author_sub: ALICE_SUB.to_string(),
            author_email: ALICE_EMAIL.to_string(),
            created_at,
            last_at: created_at,
            locked: false,
            pinned: false,
            accepted_post_id: String::new(),
        },
        Post {
            id: post_id,
            thread_id,
            body_md: "Authoritative bookmark body".to_string(),
            quoted_post_id: String::new(),
            author_sub: ALICE_SUB.to_string(),
            author_email: ALICE_EMAIL.to_string(),
            created_at,
        },
    )
}

async fn send(state: &AppState, request: Request<Body>) -> (StatusCode, HeaderMap, String) {
    let response = app(state.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, headers, String::from_utf8(bytes.to_vec()).unwrap())
}

fn get_as(uri: &str, subject: &str, email: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("x-auth-subject", subject)
        .header("x-auth-email", email)
        .body(Body::empty())
        .unwrap()
}

fn get_as_groups(uri: &str, subject: &str, email: &str, groups: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("x-auth-subject", subject)
        .header("x-auth-email", email)
        .header("x-auth-groups", groups)
        .body(Body::empty())
        .unwrap()
}

fn post_as(uri: &str, subject: &str, email: &str, body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={TOK}"))
        .header("x-auth-subject", subject)
        .header("x-auth-email", email)
        .body(Body::from(body))
        .unwrap()
}

fn post_without_cookie(uri: &str, subject: &str, email: &str, body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("x-auth-subject", subject)
        .header("x-auth-email", email)
        .body(Body::from(body))
        .unwrap()
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn utc_input(epoch: i64) -> String {
    let dt = time::OffsetDateTime::from_unix_timestamp(epoch).unwrap();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}",
        dt.year(),
        dt.month() as u8,
        dt.day(),
        dt.hour(),
        dt.minute()
    )
}

fn cas(bookmark: &agora::model::Bookmark) -> BookmarkCas<'_> {
    BookmarkCas {
        bookmark_id: &bookmark.bookmark_id,
        version: bookmark.version,
    }
}
