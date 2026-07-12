//! Version-pinned external review capability contracts over the in-memory store and real router.

use axum::body::{to_bytes, Body};
use axum::http::{header, HeaderMap, Request, StatusCode};
use inkwell::store::{
    Post, RevokePostReviewLinkCommand, RevokePostReviewLinkOutcome, SavePostCommand,
    SavePostOutcome, SavePostReviewLinkCommand, SavePostReviewLinkOutcome,
};
use inkwell::{app, build_dev_state, now_secs, AppState};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

const CSRF: &str = "review-link-test-csrf";
const OWNER_SUB: &str = "u_review_owner";
const OWNER_EMAIL: &str = "review-owner@hf";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn owner_no_js_flow_pins_rotates_invalidates_and_never_leaks_the_token() {
    let state = build_dev_state();
    let create = form(&[
        ("title", "Capability Draft"),
        ("body", "first saved body"),
        ("intent", "save_draft"),
        ("csrf_token", CSRF),
    ]);
    let (status, _, _) = call(&state, post_owner("/new", &create)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let initial = state.store.get_post("capability-draft").await.unwrap();

    let (status, _, edit_html) = call(
        &state,
        get_owner("/edit/capability-draft", OWNER_SUB, OWNER_EMAIL),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(edit_html.contains(r#"href="/edit/capability-draft/review-link""#));

    let (status, _, management) = call(
        &state,
        get_owner("/edit/capability-draft/review-link", OWNER_SUB, OWNER_EMAIL),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    for contract in [
        r#"method="post" action="/edit/capability-draft/review-link""#,
        r#"name="action" value="issue""#,
        r#"name="ttl""#,
        r#"value="48h""#,
        r#"value="7d""#,
        "Issue review link",
    ] {
        assert!(
            management.contains(contract),
            "missing management contract: {contract}"
        );
    }
    assert!(!management.contains("https://blog.w33d.xyz/review/"));

    let (status, _, foreign) = call(
        &state,
        get_owner(
            "/edit/capability-draft/review-link",
            "u_foreign",
            "foreign@hf",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!foreign.contains(&initial.title));

    let issue = review_form(&initial, "issue", "48h", None);
    let (status, headers, issued_html) = call(
        &state,
        post_owner("/edit/capability-draft/review-link", &issue),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(header::CACHE_CONTROL).unwrap(),
        "private, no-store"
    );
    assert!(issued_html.contains("Shown once"));
    assert!(issued_html.contains("readonly"));
    let raw_one = issued_token(&issued_html);
    let hash_one = digest(&raw_one);
    assert_eq!(raw_one.len(), 64);
    let stored_one = state
        .store
        .get_post_review_link(&initial.id, OWNER_SUB, now_secs())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored_one.token_hash, hash_one);
    assert_ne!(stored_one.token_hash, raw_one);
    assert_eq!(stored_one.revision_version, 1);
    assert_eq!(stored_one.guard_edit_version, 1);
    assert_eq!(stored_one.generation, 1);

    let (status, headers, review_one) = call(&state, get(&format!("/review/{raw_one}"))).await;
    assert_eq!(status, StatusCode::OK);
    assert_review_security_headers(&headers);
    assert_review_head_contract(&review_one);
    assert!(review_one.contains("Saved review · v1"));
    assert!(review_one.contains("first saved body"));
    assert!(!review_one.contains(">Studio</a>"));
    assert!(!review_one.contains(r#"class="article__actions""#));
    assert!(!review_one.contains(r#"action="/delete/""#));
    assert!(
        !review_one.contains(&raw_one),
        "review page never reflects its bearer token"
    );

    let (_, _, later_management) = call(
        &state,
        get_owner("/edit/capability-draft/review-link", OWNER_SUB, OWNER_EMAIL),
    )
    .await;
    assert!(!later_management.contains(&raw_one));
    assert!(!later_management.contains(&hash_one));
    assert!(later_management.contains("Saved review v1"));
    assert!(later_management.contains("Generation"));

    let (_, _, library) = call(&state, get_owner("/library", OWNER_SUB, OWNER_EMAIL)).await;
    assert!(!library.contains(&raw_one));
    assert!(!library.contains(&hash_one));

    let edit = form(&[
        ("title", "Capability Draft"),
        ("body", "second saved body"),
        ("intent", ""),
        ("expected_version", "1"),
        ("expected_post_id", &initial.id),
        ("csrf_token", CSRF),
    ]);
    let (status, _, _) = call(&state, post_owner("/edit/capability-draft", &edit)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let edited = state.store.get_post("capability-draft").await.unwrap();
    assert_eq!(edited.edit_version, 2);
    let (_, _, pinned_after_edit) = call(&state, get(&format!("/review/{raw_one}"))).await;
    assert!(pinned_after_edit.contains("first saved body"));
    assert!(!pinned_after_edit.contains("second saved body"));
    let advanced = state
        .store
        .get_post_review_link(&edited.id, OWNER_SUB, now_secs())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(advanced.revision_version, 1);
    assert_eq!(advanced.guard_edit_version, 2);

    let refresh = review_form(&edited, "refresh", "7d", Some(advanced.generation));
    let (status, _, refreshed_html) = call(
        &state,
        post_owner("/edit/capability-draft/review-link", &refresh),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let raw_two = issued_token(&refreshed_html);
    assert_ne!(raw_two, raw_one);
    let (old_status, old_headers, old_body) =
        call(&state, get(&format!("/review/{raw_one}"))).await;
    assert_eq!(old_status, StatusCode::NOT_FOUND);
    assert_review_security_headers(&old_headers);
    assert_review_head_contract(&old_body);
    let (new_status, _, refreshed_review) = call(&state, get(&format!("/review/{raw_two}"))).await;
    assert_eq!(new_status, StatusCode::OK);
    assert!(refreshed_review.contains("Saved review · v2"));
    assert!(refreshed_review.contains("second saved body"));

    let concurrent_generation = state
        .store
        .get_post_review_link(&edited.id, OWNER_SUB, now_secs())
        .await
        .unwrap()
        .unwrap()
        .generation;
    let now = now_secs();
    let command_a = SavePostReviewLinkCommand {
        post_id: edited.id.clone(),
        owner_sub: OWNER_SUB.to_string(),
        expected_post_version: edited.edit_version,
        expected_generation: Some(concurrent_generation),
        token_hash: "1".repeat(64),
        requested_expires_at: now + inkwell::config::REVIEW_LINK_SHORT_TTL_SECS,
        now,
    };
    let command_b = SavePostReviewLinkCommand {
        token_hash: "2".repeat(64),
        ..command_a.clone()
    };
    let store_a = state.store.clone();
    let store_b = state.store.clone();
    let (outcome_a, outcome_b) = tokio::join!(
        store_a.save_post_review_link(command_a),
        store_b.save_post_review_link(command_b)
    );
    let outcomes = [outcome_a.unwrap(), outcome_b.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, SavePostReviewLinkOutcome::Saved(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, SavePostReviewLinkOutcome::Conflict))
            .count(),
        1
    );
    let concurrent = state
        .store
        .get_post_review_link(&edited.id, OWNER_SUB, now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(concurrent.generation, concurrent_generation + 1);
    assert!(
        matches!(concurrent.token_hash.as_str(), hash if hash == "1".repeat(64) || hash == "2".repeat(64))
    );

    let revoke = review_form(&edited, "revoke", "", Some(concurrent.generation));
    let (status, _, revoked_html) = call(
        &state,
        post_owner("/edit/capability-draft/review-link", &revoke),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(revoked_html.contains("Not shared"));
    assert!(state
        .store
        .get_post_review_link(&edited.id, OWNER_SUB, now_secs())
        .await
        .unwrap()
        .is_none());
    assert!(state
        .store
        .resolve_post_review(&concurrent.token_hash, now_secs())
        .await
        .unwrap()
        .is_none());

    let reissue = review_form(&edited, "issue", "7d", None);
    let (status, _, reissued_html) = call(
        &state,
        post_owner("/edit/capability-draft/review-link", &reissue),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let raw_three = issued_token(&reissued_html);
    let reissued = state
        .store
        .get_post_review_link(&edited.id, OWNER_SUB, now_secs())
        .await
        .unwrap()
        .unwrap();
    assert!(
        reissued.generation > concurrent.generation,
        "generation tombstone prevents ABA"
    );

    let publish = form(&[
        ("title", "Capability Draft"),
        ("body", "published body"),
        ("intent", "publish_now"),
        ("expected_version", "2"),
        ("expected_post_id", &edited.id),
        ("csrf_token", CSRF),
    ]);
    let (status, _, _) = call(&state, post_owner("/edit/capability-draft", &publish)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        call(&state, get(&format!("/review/{raw_three}"))).await.0,
        StatusCode::NOT_FOUND
    );

    let published = state.store.get_post("capability-draft").await.unwrap();
    let unpublish = form(&[
        ("title", "Capability Draft"),
        ("body", "draft again"),
        ("intent", "save_draft"),
        ("expected_version", &published.edit_version.to_string()),
        ("expected_post_id", &published.id),
        ("csrf_token", CSRF),
    ]);
    let (status, _, _) = call(&state, post_owner("/edit/capability-draft", &unpublish)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        call(&state, get(&format!("/review/{raw_three}"))).await.0,
        StatusCode::NOT_FOUND,
        "unpublish never revives a published capability"
    );

    let draft_again = state.store.get_post("capability-draft").await.unwrap();
    let schedule_issue = review_form(&draft_again, "issue", "7d", None);
    let (_, _, schedule_issued_html) = call(
        &state,
        post_owner("/edit/capability-draft/review-link", &schedule_issue),
    )
    .await;
    let scheduled_raw = issued_token(&schedule_issued_html);
    let publish_at = now_secs() + 3_600;
    let schedule = form(&[
        ("title", "Capability Draft"),
        ("body", "scheduled body"),
        ("intent", "schedule"),
        ("publish_at_epoch", &publish_at.to_string()),
        ("expected_version", &draft_again.edit_version.to_string()),
        ("expected_post_id", &draft_again.id),
        ("csrf_token", CSRF),
    ]);
    let (status, _, _) = call(&state, post_owner("/edit/capability-draft", &schedule)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let scheduled = state.store.get_post("capability-draft").await.unwrap();
    let scheduled_link = state
        .store
        .get_post_review_link(&scheduled.id, OWNER_SUB, now_secs())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(scheduled_link.expires_at, publish_at);
    assert!(state
        .store
        .resolve_post_review(&scheduled_link.token_hash, publish_at)
        .await
        .unwrap()
        .is_none());

    let unschedule = form(&[
        ("title", "Capability Draft"),
        ("body", "unscheduled"),
        ("intent", "save_draft"),
        ("expected_version", &scheduled.edit_version.to_string()),
        ("expected_post_id", &scheduled.id),
        ("csrf_token", CSRF),
    ]);
    let (status, _, _) = call(&state, post_owner("/edit/capability-draft", &unschedule)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        call(&state, get(&format!("/review/{scheduled_raw}")))
            .await
            .0,
        StatusCode::NOT_FOUND
    );

    let final_draft = state.store.get_post("capability-draft").await.unwrap();
    let final_issue = review_form(&final_draft, "issue", "48h", None);
    let (_, _, final_html) = call(
        &state,
        post_owner("/edit/capability-draft/review-link", &final_issue),
    )
    .await;
    let final_raw = issued_token(&final_html);
    let delete = form(&[
        ("csrf_token", CSRF),
        ("expected_post_id", &final_draft.id),
        ("expected_version", &final_draft.edit_version.to_string()),
    ]);
    let (status, _, _) = call(&state, post_owner("/delete/capability-draft", &delete)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (deleted_status, deleted_headers, deleted_body) =
        call(&state, get(&format!("/review/{final_raw}"))).await;
    assert_eq!(deleted_status, StatusCode::NOT_FOUND);
    assert_review_security_headers(&deleted_headers);
    assert_review_head_contract(&deleted_body);
}

#[tokio::test]
async fn store_expiry_owner_and_generation_boundaries_are_fail_closed() {
    let state = build_dev_state();
    let now = 1_800_000_000;
    let post = fixture_post("review-boundary", now);
    state.store.create_post(&post).await.unwrap();
    let first = state
        .store
        .save_post_review_link(SavePostReviewLinkCommand {
            post_id: post.id.clone(),
            owner_sub: post.author_sub.clone(),
            expected_post_version: 1,
            expected_generation: None,
            token_hash: "a".repeat(64),
            requested_expires_at: now + inkwell::config::REVIEW_LINK_SHORT_TTL_SECS,
            now,
        })
        .await
        .unwrap();
    let first = match first {
        SavePostReviewLinkOutcome::Saved(link) => link,
        other => panic!("unexpected issue outcome: {other:?}"),
    };
    assert!(state
        .store
        .resolve_post_review(&first.token_hash, first.expires_at - 1)
        .await
        .unwrap()
        .is_some());
    assert!(state
        .store
        .resolve_post_review(&first.token_hash, first.expires_at)
        .await
        .unwrap()
        .is_none());
    assert!(state
        .store
        .get_post_review_link(&post.id, "u_foreign", now)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        state
            .store
            .save_post_review_link(SavePostReviewLinkCommand {
                post_id: post.id.clone(),
                owner_sub: "u_foreign".to_string(),
                expected_post_version: 1,
                expected_generation: None,
                token_hash: "b".repeat(64),
                requested_expires_at: now + 100,
                now,
            })
            .await
            .unwrap(),
        SavePostReviewLinkOutcome::NotFound
    );
    assert_eq!(
        state
            .store
            .revoke_post_review_link(RevokePostReviewLinkCommand {
                post_id: post.id.clone(),
                owner_sub: "u_foreign".to_string(),
                expected_post_version: 1,
                expected_generation: first.generation,
                now,
            })
            .await
            .unwrap(),
        RevokePostReviewLinkOutcome::NotFound
    );

    let reissued = state
        .store
        .save_post_review_link(SavePostReviewLinkCommand {
            post_id: post.id.clone(),
            owner_sub: post.author_sub.clone(),
            expected_post_version: 1,
            expected_generation: None,
            token_hash: "c".repeat(64),
            requested_expires_at: first.expires_at + 100,
            now: first.expires_at,
        })
        .await
        .unwrap();
    let reissued = match reissued {
        SavePostReviewLinkOutcome::Saved(link) => link,
        other => panic!("unexpected reissue outcome: {other:?}"),
    };
    assert!(reissued.generation > first.generation);
    assert_eq!(
        state
            .store
            .revoke_post_review_link(RevokePostReviewLinkCommand {
                post_id: post.id,
                owner_sub: post.author_sub,
                expected_post_version: 1,
                expected_generation: reissued.generation,
                now: first.expires_at,
            })
            .await
            .unwrap(),
        RevokePostReviewLinkOutcome::Revoked
    );
}

#[tokio::test]
async fn scheduled_store_link_clamps_and_unpublish_cannot_resurrect_it() {
    let state = build_dev_state();
    let now = 1_800_000_000;
    let mut post = fixture_post("scheduled-review", now);
    post.published = true;
    post.publish_at = now + 600;
    state.store.create_post(&post).await.unwrap();
    let link = state
        .store
        .save_post_review_link(SavePostReviewLinkCommand {
            post_id: post.id.clone(),
            owner_sub: post.author_sub.clone(),
            expected_post_version: 1,
            expected_generation: None,
            token_hash: "d".repeat(64),
            requested_expires_at: now + inkwell::config::REVIEW_LINK_MAX_TTL_SECS,
            now,
        })
        .await
        .unwrap();
    let link = match link {
        SavePostReviewLinkOutcome::Saved(link) => link,
        other => panic!("unexpected scheduled issue outcome: {other:?}"),
    };
    assert_eq!(link.expires_at, post.publish_at);
    assert!(state
        .store
        .resolve_post_review(&link.token_hash, post.publish_at)
        .await
        .unwrap()
        .is_none());

    let mut draft = post.clone();
    draft.published = false;
    draft.publish_at = 0;
    draft.updated_at = now + 1;
    assert!(matches!(
        state
            .store
            .save_post(SavePostCommand {
                post: draft,
                expected_version: 1,
                editor_sub: post.author_sub,
                editor_email: post.author_email,
                source: "test-unpublish".to_string(),
                restored_from: None,
                consume_autosave_session: None,
            })
            .await
            .unwrap(),
        SavePostOutcome::Saved(_)
    ));
    assert!(state
        .store
        .resolve_post_review(&link.token_hash, now + 2)
        .await
        .unwrap()
        .is_none());
}

fn fixture_post(slug: &str, now: i64) -> Post {
    Post {
        id: format!("post_{slug}"),
        slug: slug.to_string(),
        title: "Review boundary".to_string(),
        body_md: "saved revision".to_string(),
        author_sub: OWNER_SUB.to_string(),
        author_email: OWNER_EMAIL.to_string(),
        created_at: now,
        updated_at: now,
        edit_version: 1,
        published: false,
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
    }
}

fn review_form(post: &Post, action: &str, ttl: &str, generation: Option<i64>) -> String {
    let version = post.edit_version.to_string();
    let generation = generation
        .map(|value| value.to_string())
        .unwrap_or_default();
    form(&[
        ("csrf_token", CSRF),
        ("action", action),
        ("ttl", ttl),
        ("expected_post_id", &post.id),
        ("expected_post_version", &version),
        ("expected_generation", &generation),
    ])
}

fn issued_token(html: &str) -> String {
    let prefix = r#"value="https://blog.w33d.xyz/review/"#;
    let tail = html
        .split_once(prefix)
        .map(|(_, tail)| tail)
        .expect("successful command exposes one review URL");
    let token = tail.split('"').next().unwrap_or_default().to_string();
    assert_eq!(token.len(), 64);
    assert!(token
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    token
}

fn digest(raw: &str) -> String {
    hex::encode(Sha256::digest(raw.as_bytes()))
}

fn assert_review_security_headers(headers: &HeaderMap) {
    assert_eq!(
        headers.get(header::CACHE_CONTROL).unwrap(),
        "private, no-store"
    );
    assert_eq!(
        headers.get("x-robots-tag").unwrap(),
        "noindex, nofollow, noarchive"
    );
    assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");
}

fn assert_review_head_contract(html: &str) {
    assert!(html.contains(r#"<meta name="referrer" content="no-referrer">"#));
    assert!(html.contains(r#"<meta name="robots" content="noindex,nofollow,noarchive">"#));
    assert!(!html.contains(r#"rel="canonical""#));
    assert!(!html.contains(r#"property="og:""#));
    assert!(!html.contains(r#"name="twitter:""#));
}

async fn call(state: &AppState, request: Request<Body>) -> (StatusCode, HeaderMap, String) {
    let response = app(state.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, headers, String::from_utf8_lossy(&bytes).to_string())
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn get_owner(uri: &str, subject: &str, email: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("x-auth-subject", subject)
        .header("x-auth-email", email)
        .body(Body::empty())
        .unwrap()
}

fn post_owner(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={CSRF}"))
        .header("x-auth-subject", OWNER_SUB)
        .header("x-auth-email", OWNER_EMAIL)
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", key, encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}
