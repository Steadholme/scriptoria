//! Writer durability: private existing-post autosaves, optimistic saves, immutable history, and
//! restore-as-a-new-version. These HTTP tests use the in-memory Store so every invariant is also
//! exercised through the real handlers and no-JavaScript form routes.

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use inkwell::{app, build_dev_state, now_secs, AppState};
use tower::ServiceExt;

const CSRF: &str = "writer-durability-csrf";

#[tokio::test]
async fn autosave_sequence_conflict_recovery_and_consume_are_owner_scoped() {
    let state = build_dev_state();
    create_post(&state, "Durable Story", "original", "publish_now", None).await;
    let post_id = state.store.get_post("durable-story").await.unwrap().id;

    let (_, edit_headers, edit) =
        call(&state, get_auth("/edit/durable-story", "u_writer", None)).await;
    assert_private_no_store(&edit_headers);
    let session = hidden(&edit, "autosave_session");
    assert_eq!(session.len(), 64);
    assert!(edit.contains(r#"name="expected_version" value="1""#));
    assert!(edit.contains(&format!(r#"name="expected_post_id" value="{post_id}""#)));

    let newer = form(&[
        ("title", "Durable Story"),
        ("body", "newest private autosave"),
        ("expected_version", "1"),
        ("expected_post_id", &post_id),
        ("autosave_session", &session),
        ("client_seq", "2"),
        ("csrf_token", CSRF),
    ]);
    assert_eq!(
        call(
            &state,
            post_auth(
                "/api/writer/autosave/durable-story",
                &newer,
                "u_writer",
                None,
                true,
            ),
        )
        .await
        .0,
        StatusCode::OK
    );

    let older = form(&[
        ("title", "Durable Story"),
        ("body", "late older request"),
        ("expected_version", "1"),
        ("expected_post_id", &post_id),
        ("autosave_session", &session),
        ("client_seq", "1"),
        ("csrf_token", CSRF),
    ]);
    let (stale_status, stale_headers, _) = call(
        &state,
        post_auth(
            "/api/writer/autosave/durable-story",
            &older,
            "u_writer",
            None,
            true,
        ),
    )
    .await;
    assert_eq!(
        stale_status,
        StatusCode::CONFLICT,
        "late client sequence is rejected"
    );
    assert_eq!(
        stale_headers.get(header::CACHE_CONTROL).unwrap(),
        "private, no-store"
    );
    let stored = state
        .store
        .get_writer_autosave(&session, "u_writer", now_secs())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.body_md, "newest private autosave");
    assert!(state
        .store
        .get_writer_autosave(&session, "u_admin", now_secs())
        .await
        .unwrap()
        .is_none());

    let recover_uri = format!("/edit/durable-story?recover={session}");
    let (_, recover_headers, recovered_editor) =
        call(&state, get_auth(&recover_uri, "u_writer", None)).await;
    assert_private_no_store(&recover_headers);
    assert!(recovered_editor.contains("newest private autosave"));
    assert!(recovered_editor.contains(r#"name="client_seq" value="2""#));

    let first_save = form(&[
        ("title", "Durable Story"),
        ("body", "first authoritative winner"),
        ("expected_version", "1"),
        ("expected_post_id", &post_id),
        ("autosave_session", &session),
        ("client_seq", "2"),
        ("csrf_token", CSRF),
    ]);
    assert_eq!(
        call(
            &state,
            post_auth("/edit/durable-story", &first_save, "u_writer", None, true),
        )
        .await
        .0,
        StatusCode::OK
    );
    assert!(
        state
            .store
            .get_writer_autosave(&session, "u_writer", now_secs())
            .await
            .unwrap()
            .is_none(),
        "successful save consumes only its private autosave"
    );

    let stale_base = form(&[
        ("title", "Durable Story"),
        ("body", "stale base autosave"),
        ("expected_version", "1"),
        ("expected_post_id", &post_id),
        ("autosave_session", &session),
        ("client_seq", "3"),
        ("csrf_token", CSRF),
    ]);
    let (stale_base_status, stale_base_headers, _) = call(
        &state,
        post_auth(
            "/api/writer/autosave/durable-story",
            &stale_base,
            "u_writer",
            None,
            true,
        ),
    )
    .await;
    assert_eq!(stale_base_status, StatusCode::CONFLICT);
    assert_eq!(
        stale_base_headers.get(header::CACHE_CONTROL).unwrap(),
        "private, no-store"
    );
    assert!(
        state
            .store
            .get_writer_autosave(&session, "u_writer", now_secs())
            .await
            .unwrap()
            .is_none(),
        "stale post version never recreates or overwrites recovery"
    );

    let (_, _, second_edit) = call(&state, get_auth("/edit/durable-story", "u_writer", None)).await;
    let stale_session = hidden(&second_edit, "autosave_session");
    let winner = form(&[
        ("title", "Durable Story"),
        ("body", "second authoritative winner"),
        ("expected_version", "2"),
        ("expected_post_id", &post_id),
        ("csrf_token", CSRF),
    ]);
    assert_eq!(
        call(
            &state,
            post_auth("/edit/durable-story", &winner, "u_writer", None, true),
        )
        .await
        .0,
        StatusCode::OK
    );

    let loser = form(&[
        ("title", "Durable Story from stale tab"),
        ("body", "stale tab text must survive"),
        ("expected_version", "2"),
        ("expected_post_id", &post_id),
        ("autosave_session", &stale_session),
        ("client_seq", "0"),
        ("csrf_token", CSRF),
    ]);
    let (status, headers, conflict) = call(
        &state,
        post_auth("/edit/durable-story", &loser, "u_writer", None, false),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        headers.get(header::CACHE_CONTROL).unwrap(),
        "private, no-store"
    );
    assert!(conflict.contains("stale tab text must survive"));
    assert!(conflict.contains(&format!("recover={stale_session}")));
    assert_eq!(
        state.store.get_post("durable-story").await.unwrap().body_md,
        "second authoritative winner",
        "stale explicit save never overwrites current"
    );
    let recovery = state
        .store
        .get_writer_autosave(&stale_session, "u_writer", now_secs())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovery.body_md, "stale tab text must survive");
    assert_eq!(recovery.base_version, 3);

    let recover_uri = format!("/edit/durable-story?recover={stale_session}");
    let (_, owner_headers, owner_recovery) =
        call(&state, get_auth(&recover_uri, "u_writer", None)).await;
    assert_private_no_store(&owner_headers);
    assert!(owner_recovery.contains("stale tab text must survive"));
    let (_, _, admin_view) = call(&state, get_auth(&recover_uri, "u_admin", Some("admins"))).await;
    assert!(!admin_view.contains("stale tab text must survive"));
    assert!(admin_view.contains("second authoritative winner"));
}

#[tokio::test]
async fn legacy_open_forms_without_post_identity_conflict_into_private_recovery() {
    let state = build_dev_state();
    create_post(
        &state,
        "Legacy Open Form",
        "authoritative original",
        "save_draft",
        None,
    )
    .await;

    // A form opened before either CAS field existed must preserve the submission, never overwrite.
    let missing_id_and_version = form(&[
        ("title", "Legacy Open Form"),
        ("body", "legacy body missing both CAS fields"),
        ("csrf_token", CSRF),
    ]);
    let (status, headers, conflict) = call(
        &state,
        post_auth(
            "/edit/legacy-open-form",
            &missing_id_and_version,
            "u_writer",
            None,
            false,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_private_no_store(&headers);
    assert!(conflict.contains("legacy body missing both CAS fields"));
    let session = recovery_session_from_html(&conflict, "legacy-open-form");
    let retained = state
        .store
        .get_writer_autosave(&session, "u_writer", now_secs())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retained.body_md, "legacy body missing both CAS fields");

    // Even a coincidentally current version cannot make an identity-less legacy form authoritative.
    let valid_version_without_id = form(&[
        ("title", "Legacy Open Form"),
        ("body", "legacy body with valid version but no identity"),
        ("expected_version", "1"),
        ("csrf_token", CSRF),
    ]);
    let (status, headers, json) = call(
        &state,
        post_auth(
            "/edit/legacy-open-form",
            &valid_version_without_id,
            "u_writer",
            None,
            true,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_private_no_store(&headers);
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(json["conflict"], true);
    assert!(json["recover"]
        .as_str()
        .is_some_and(|recover| recover.starts_with("/edit/legacy-open-form?recover=")));
    let current = state.store.get_post("legacy-open-form").await.unwrap();
    assert_eq!(current.edit_version, 1);
    assert_eq!(current.body_md, "authoritative original");
}

#[tokio::test]
async fn deleted_unreused_editor_forms_return_private_identity_recovery_not_404() {
    let state = build_dev_state();

    create_post(
        &state,
        "Deleted Legacy Editor",
        "legacy authoritative body",
        "save_draft",
        None,
    )
    .await;
    state
        .store
        .delete_post("deleted-legacy-editor")
        .await
        .unwrap();
    let legacy = form(&[
        ("title", "Deleted Legacy Editor"),
        ("body", "legacy deleted submission recovery"),
        ("csrf_token", CSRF),
    ]);
    let (status, headers, conflict) = call(
        &state,
        post_auth(
            "/edit/deleted-legacy-editor",
            &legacy,
            "u_writer",
            None,
            false,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_private_no_store(&headers);
    assert!(conflict.contains("legacy deleted submission recovery"));
    assert!(!conflict.contains("?recover="));
    assert!(state
        .store
        .get_post("deleted-legacy-editor")
        .await
        .is_none());

    create_post(
        &state,
        "Deleted Modern Editor",
        "modern authoritative body",
        "save_draft",
        None,
    )
    .await;
    let deleted = state.store.get_post("deleted-modern-editor").await.unwrap();
    state
        .store
        .delete_post("deleted-modern-editor")
        .await
        .unwrap();
    let modern = form(&[
        ("title", "Deleted Modern Editor"),
        ("body", "modern deleted submission recovery"),
        ("expected_post_id", &deleted.id),
        ("expected_version", &deleted.edit_version.to_string()),
        ("csrf_token", CSRF),
    ]);
    let (status, headers, conflict) = call(
        &state,
        post_auth(
            "/edit/deleted-modern-editor",
            &modern,
            "u_writer",
            None,
            false,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_private_no_store(&headers);
    assert!(conflict.contains("modern deleted submission recovery"));

    let (status, headers, json) = call(
        &state,
        post_auth(
            "/edit/deleted-modern-editor",
            &modern,
            "u_writer",
            None,
            true,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_private_no_store(&headers);
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(json["conflict"], true);
    assert_eq!(json["submitted_body"], "modern deleted submission recovery");
    assert!(json.get("recover").is_none());
    assert!(state
        .store
        .get_post("deleted-modern-editor")
        .await
        .is_none());
}

#[tokio::test]
async fn modern_identity_mismatch_reflects_only_submission_without_replacement_recovery() {
    let state = build_dev_state();
    create_post(
        &state,
        "Reused Identity",
        "old identity body",
        "save_draft",
        None,
    )
    .await;
    let old = state.store.get_post("reused-identity").await.unwrap();
    let (_, _, editor) = call(&state, get_auth("/edit/reused-identity", "u_writer", None)).await;
    let session = hidden(&editor, "autosave_session");
    state.store.delete_post("reused-identity").await.unwrap();

    let replacement_form = form(&[
        ("title", "Reused Identity"),
        ("body", "replacement private body"),
        ("intent", "save_draft"),
        ("csrf_token", CSRF),
    ]);
    assert_eq!(
        call(
            &state,
            post_auth("/new", &replacement_form, "u_replacement", None, false,),
        )
        .await
        .0,
        StatusCode::SEE_OTHER
    );
    let replacement = state.store.get_post("reused-identity").await.unwrap();
    assert_ne!(replacement.id, old.id);

    let stale_modern_form = form(&[
        ("title", "Old caller title"),
        ("body", "old caller submitted body"),
        ("expected_version", "1"),
        ("expected_post_id", &old.id),
        ("autosave_session", &session),
        ("client_seq", "4"),
        ("csrf_token", CSRF),
    ]);
    let (status, headers, conflict) = call(
        &state,
        post_auth(
            "/edit/reused-identity",
            &stale_modern_form,
            "u_writer",
            None,
            false,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_private_no_store(&headers);
    assert!(conflict.contains("old caller submitted body"));
    assert!(!conflict.contains("replacement private body"));
    assert!(!conflict.contains("replacement@hf"));
    assert!(!conflict.contains("?recover="));

    let (status, headers, json) = call(
        &state,
        post_auth(
            "/edit/reused-identity",
            &stale_modern_form,
            "u_writer",
            None,
            true,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_private_no_store(&headers);
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(json["conflict"], true);
    assert_eq!(json["submitted_body"], "old caller submitted body");
    assert!(!json.to_string().contains("replacement private body"));
    assert!(json.get("recover").is_none());
    assert!(json.get("current_version").is_none());

    let replacement_after = state.store.get_post("reused-identity").await.unwrap();
    assert_eq!(replacement_after.id, replacement.id);
    assert_eq!(replacement_after.body_md, "replacement private body");
    assert_eq!(
        state
            .store
            .list_post_revisions(&replacement.id, 50)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(state
        .store
        .get_writer_autosave(&session, "u_writer", now_secs())
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn history_restore_is_authorized_append_only_and_preserves_visibility() {
    let state = build_dev_state();
    let future = (now_secs() + 3_600).to_string();
    create_post(
        &state,
        "Scheduled Durable",
        "version one body",
        "schedule",
        Some(&future),
    )
    .await;
    let original = state.store.get_post("scheduled-durable").await.unwrap();
    assert!(original.published && original.publish_at > now_secs());

    let mut latest = original.clone();
    latest.body_md = "latest body before restore".to_string();
    latest.pinned = true;
    latest.featured = true;
    latest.updated_at = now_secs();
    state.store.update_post(&latest).await.unwrap();
    let before_restore = state.store.get_post("scheduled-durable").await.unwrap();
    assert_eq!(before_restore.edit_version, 2);

    let revisions = state
        .store
        .list_post_revisions(&before_restore.id, 50)
        .await
        .unwrap();
    let first = revisions
        .iter()
        .find(|revision| revision.edit_version == 1)
        .unwrap();
    let revision_id = first.id.clone();

    assert_eq!(
        call(
            &state,
            get_auth("/edit/scheduled-durable/history", "u_reader", None,),
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (status, history_headers, history) = call(
        &state,
        get_auth("/edit/scheduled-durable/history", "u_writer", None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_private_no_store(&history_headers);
    assert!(history.contains("Restore content"));
    assert!(history.contains("preserving the current Draft, Scheduled, or Published state"));
    let cookie = history_headers
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert_eq!(
        call(
            &state,
            get_auth("/edit/scheduled-durable/history", "u_admin", Some("admins"),),
        )
        .await
        .0,
        StatusCode::OK,
        "admin may inspect authoritative history"
    );

    let csrf = cookie.split_once('=').unwrap().1.to_string();
    let restore = form(&[
        ("csrf_token", &csrf),
        ("expected_version", "2"),
        ("expected_post_id", &before_restore.id),
    ]);
    let restore_uri = format!("/edit/scheduled-durable/history/{revision_id}/restore");
    let (status, _, _) = call(
        &state,
        post_with_cookie(&restore_uri, &restore, "u_writer", None, &cookie),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let restored = state.store.get_post("scheduled-durable").await.unwrap();
    assert_eq!(restored.body_md, "version one body");
    assert_eq!(restored.edit_version, 3);
    assert_eq!(restored.published, before_restore.published);
    assert_eq!(restored.publish_at, before_restore.publish_at);
    assert_eq!(restored.pinned, before_restore.pinned);
    assert_eq!(restored.featured, before_restore.featured);
    let after = state
        .store
        .list_post_revisions(&restored.id, 50)
        .await
        .unwrap();
    assert_eq!(after[0].edit_version, 3);
    assert_eq!(after[0].source, "restore");
    assert!(after.iter().any(|revision| revision.edit_version == 2));
    assert!(after.iter().any(|revision| revision.edit_version == 1));
    assert_eq!(
        call(
            &state,
            Request::builder()
                .uri("/p/scheduled-durable")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .0,
        StatusCode::NOT_FOUND,
        "restore cannot publish a scheduled post early"
    );

    let stale_restore = form(&[
        ("csrf_token", &csrf),
        ("expected_version", "2"),
        ("expected_post_id", &before_restore.id),
    ]);
    assert_eq!(
        call(
            &state,
            post_with_cookie(&restore_uri, &stale_restore, "u_writer", None, &cookie,),
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        state
            .store
            .get_post("scheduled-durable")
            .await
            .unwrap()
            .edit_version,
        3
    );
}

#[tokio::test]
async fn new_remains_local_only_while_existing_editor_exposes_no_js_durability_fields() {
    let state = build_dev_state();
    let (_, compose_headers, compose) = call(&state, get_auth("/new", "u_writer", None)).await;
    assert_private_no_store(&compose_headers);
    assert!(compose.contains(r#"data-autosave-url="""#));
    assert!(!compose.contains(r#"href="/edit//history""#));

    create_post(&state, "Existing Writer", "body", "save_draft", None).await;
    let existing_id = state.store.get_post("existing-writer").await.unwrap().id;
    let (_, edit_headers, edit) =
        call(&state, get_auth("/edit/existing-writer", "u_writer", None)).await;
    assert_private_no_store(&edit_headers);
    for contract in [
        r#"data-autosave-url="/api/writer/autosave/existing-writer""#,
        r#"name="expected_version" value="1""#,
        r#"name="autosave_session" value=""#,
        r#"href="/edit/existing-writer/history""#,
        "function persistServerAutosave()",
    ] {
        assert!(
            edit.contains(contract),
            "missing durability contract: {contract}"
        );
    }

    // The ordinary HTML form remains the authority with JavaScript absent.
    let no_js = form(&[
        ("title", "Existing Writer"),
        ("body", "saved through native form"),
        ("expected_version", "1"),
        ("expected_post_id", &existing_id),
        ("csrf_token", CSRF),
    ]);
    assert_eq!(
        call(
            &state,
            post_auth("/edit/existing-writer", &no_js, "u_writer", None, false),
        )
        .await
        .0,
        StatusCode::SEE_OTHER
    );
}

async fn create_post(
    state: &AppState,
    title: &str,
    body: &str,
    intent: &str,
    publish_at_epoch: Option<&str>,
) {
    let mut pairs = vec![
        ("title", title),
        ("body", body),
        ("intent", intent),
        ("csrf_token", CSRF),
    ];
    if let Some(epoch) = publish_at_epoch {
        pairs.push(("publish_at_epoch", epoch));
    }
    let body = form(&pairs);
    let (status, _, _) = call(state, post_auth("/new", &body, "u_writer", None, false)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
}

async fn call(
    state: &AppState,
    request: Request<Body>,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let response = app(state.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, headers, String::from_utf8_lossy(&bytes).to_string())
}

fn get_auth(uri: &str, sub: &str, groups: Option<&str>) -> Request<Body> {
    let mut request = Request::builder()
        .uri(uri)
        .header("x-auth-subject", sub)
        .header(
            "x-auth-email",
            format!("{}@hf", sub.trim_start_matches("u_")),
        );
    if let Some(groups) = groups {
        request = request.header("x-auth-groups", groups);
    }
    request.body(Body::empty()).unwrap()
}

fn post_auth(uri: &str, body: &str, sub: &str, groups: Option<&str>, json: bool) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={CSRF}"))
        .header("x-auth-subject", sub)
        .header(
            "x-auth-email",
            format!("{}@hf", sub.trim_start_matches("u_")),
        );
    if json {
        request = request.header(header::ACCEPT, "application/json");
    }
    if let Some(groups) = groups {
        request = request.header("x-auth-groups", groups);
    }
    request.body(Body::from(body.to_string())).unwrap()
}

fn post_with_cookie(
    uri: &str,
    body: &str,
    sub: &str,
    groups: Option<&str>,
    cookie: &str,
) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie)
        .header("x-auth-subject", sub)
        .header(
            "x-auth-email",
            format!("{}@hf", sub.trim_start_matches("u_")),
        );
    if let Some(groups) = groups {
        request = request.header("x-auth-groups", groups);
    }
    request.body(Body::from(body.to_string())).unwrap()
}

fn hidden(html: &str, name: &str) -> String {
    html.split(&format!(r#"name="{name}" value=""#))
        .nth(1)
        .and_then(|tail| tail.split('"').next())
        .unwrap_or_default()
        .to_string()
}

fn recovery_session_from_html(html: &str, slug: &str) -> String {
    html.split(&format!("/edit/{slug}?recover="))
        .nth(1)
        .and_then(|tail| tail.split('"').next())
        .unwrap_or_default()
        .to_string()
}

fn assert_private_no_store(headers: &axum::http::HeaderMap) {
    assert_eq!(
        headers.get(header::CACHE_CONTROL).unwrap(),
        "private, no-store"
    );
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn encode(raw: &str) -> String {
    raw.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            b' ' => "+".to_string(),
            _ => format!("%{byte:02X}"),
        })
        .collect()
}
