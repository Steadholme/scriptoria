//! The `/admin` panel: category CRUD, thread moderation (lock / pin / move / delete), any-post
//! deletion, and the author blocklist (ban / unban).
//!
//! The whole subtree is gated by [`crate::auth::require_admin`] (applied as a router middleware
//! in [`crate::app`]): an ordinary signed-in user gets a branded `403`, only members of
//! `admins` / `infra-admins` reach these handlers. Every state-changing POST is additionally
//! double-submit CSRF protected, and every mutation emits an [`AuditEvent`] (a `notice` for the
//! destructive ones). All interpolated user input is HTML-escaped; the dashboard is rendered
//! into the same enterprise shell as the rest of the app.

use axum::extract::{Form, Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth;
use crate::error::AppError;
use crate::handlers::forum::{html_response, redirect_to};
use crate::handlers::{
    category_vm, form_action, hidden_field, link_action, page_chrome, personal_counts,
    thread_row_shared,
};
use crate::model::{BannedAuthor, Category, CategoryFormat};
use crate::view_model::{
    ActionKind, AddBanFormVM, AdminCategoryVM, AdminShared, AdminThreadToolbarVM, AdminThreadVM,
    AdminView, AdminViewerState, BannedAuthorVM, CollectionState, ConsequenceVM,
    CreateCategoryFormVM, DestructiveReviewVM, MoveThreadFormVM as MoveThreadFormViewModel, NavTab,
    Opaque, RenameCategoryFormVM, Text, ThreadKind,
};
use crate::views::{admin, shell};
use crate::{now_secs, AppState};

/// Recent threads listed on the admin dashboard.
const ADMIN_THREAD_LIMIT: i64 = 100;
/// Caps on operator input (the store columns are TEXT; these just reject absurd payloads).
const MAX_CATEGORY_ID: usize = 64;
const MAX_NAME: usize = 100;
const MAX_SUB: usize = 200;
const MAX_REASON: usize = 500;

/// The acting admin's identity for the audit trail: their email, falling back to the subject.
fn actor(headers: &HeaderMap) -> String {
    auth::identity_email(headers)
        .or_else(|| auth::identity_subject(headers))
        .unwrap_or_else(|| "admin".to_string())
}

fn category_delete_action(id: &str) -> String {
    format!("admin.category.delete:{id}")
}

fn thread_delete_action(id: &str) -> String {
    format!("admin.thread.delete:{id}")
}

fn post_delete_action(id: &str) -> String {
    format!("admin.post.delete:{id}")
}

#[allow(clippy::too_many_arguments)]
async fn destructive_review_response(
    state: &AppState,
    headers: &HeaderMap,
    actor_sub: &str,
    page_title: &str,
    heading: &str,
    consequence: &str,
    action_path: &str,
    action_key: &str,
    cancel_href: &str,
) -> Result<Response, AppError> {
    let (csrf, set_cookie) = auth::ensure_csrf(headers);
    let confirm = auth::new_destructive_confirmation(
        state.config.destructive_confirmation_key(),
        &csrf,
        action_key,
        actor_sub,
    );
    let review = DestructiveReviewVM {
        heading: Text(heading.to_string()),
        consequence: ConsequenceVM {
            summary: Text(consequence.to_string()),
            detail: None,
        },
        commit: form_action(
            action_path,
            ActionKind::DeleteConfirm,
            csrf,
            vec![hidden_field("confirm", confirm)],
        ),
        cancel_href: Opaque(cancel_href.to_string()),
    };
    let content = shell::destructive_review(&review);
    let counts = personal_counts(state, headers, now_secs()).await?;
    let chrome = page_chrome(page_title, headers, NavTab::Home, counts);
    let html = shell::page(&chrome, &content);
    Ok(html_response(html, set_cookie))
}

// ===========================================================================
// GET /admin — dashboard
// ===========================================================================

pub async fn dashboard(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let now = crate::now_secs();
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let categories = state.store.list_categories().await?;
    let threads = state.store.recent_threads(ADMIN_THREAD_LIMIT).await?;
    let bans = state.store.list_bans().await?;

    let admin_categories = categories
        .iter()
        .enumerate()
        .map(|(index, category)| {
            let reorder_action = format!("/admin/categories/{}/reorder", category.id);
            AdminCategoryVM {
                category: category_vm(category),
                rename: RenameCategoryFormVM {
                    name_max_chars: MAX_NAME,
                    submit: form_action(
                        format!("/admin/categories/{}/rename", category.id),
                        ActionKind::RenameCategory,
                        csrf.clone(),
                        Vec::new(),
                    ),
                },
                set_format: form_action(
                    format!("/admin/categories/{}/format", category.id),
                    ActionKind::SetCategoryFormat,
                    csrf.clone(),
                    Vec::new(),
                ),
                move_up: (index > 0).then(|| {
                    form_action(
                        reorder_action.clone(),
                        ActionKind::MoveCategoryUp,
                        csrf.clone(),
                        vec![hidden_field("dir", "up")],
                    )
                }),
                move_down: (index + 1 < categories.len()).then(|| {
                    form_action(
                        reorder_action,
                        ActionKind::MoveCategoryDown,
                        csrf.clone(),
                        vec![hidden_field("dir", "down")],
                    )
                }),
                delete_review: link_action(
                    format!("/admin/categories/{}/delete", category.id),
                    ActionKind::DeleteAdminReview,
                ),
            }
        })
        .collect();

    let category_choices = categories
        .iter()
        .map(|category| category_vm(category).category)
        .collect::<Vec<_>>();
    let mut admin_threads = Vec::with_capacity(threads.len());
    for thread in &threads {
        let category = categories
            .iter()
            .find(|category| category.id == thread.category_id);
        let accepted = state
            .store
            .get_valid_accepted_post(&thread.id)
            .await?
            .is_some();
        admin_threads.push(AdminThreadVM {
            thread: thread_row_shared(thread, category, None, accepted),
            toolbar: AdminThreadToolbarVM {
                move_thread: Some(MoveThreadFormViewModel {
                    selected_category: Opaque(thread.category_id.clone()),
                    categories: category_choices.clone(),
                    submit: form_action(
                        format!("/admin/threads/{}/move", thread.id),
                        ActionKind::MoveThread,
                        csrf.clone(),
                        Vec::new(),
                    ),
                }),
                lock: Some(form_action(
                    format!("/admin/threads/{}/lock", thread.id),
                    if thread.locked {
                        ActionKind::Unlock
                    } else {
                        ActionKind::Lock
                    },
                    csrf.clone(),
                    vec![hidden_field(
                        "state",
                        if thread.locked { "unlocked" } else { "locked" },
                    )],
                )),
                pin: Some(form_action(
                    format!("/admin/threads/{}/pin", thread.id),
                    if thread.pinned {
                        ActionKind::Unpin
                    } else {
                        ActionKind::Pin
                    },
                    csrf.clone(),
                    vec![hidden_field(
                        "state",
                        if thread.pinned { "unpinned" } else { "pinned" },
                    )],
                )),
                delete_review: Some(link_action(
                    format!("/admin/threads/{}/delete", thread.id),
                    ActionKind::DeleteAdminReview,
                )),
            },
        });
    }

    let banned_authors = bans
        .iter()
        .map(|ban| BannedAuthorVM {
            // The handler deliberately approves the stable subject as the display label. The view
            // cannot recover the unban target from this text; authority remains sealed in `unban`.
            author_display: Text(ban.author_sub.clone()),
            reason: Text(ban.reason.clone()),
            banned_by: Text(ban.banned_by.clone()),
            created_at: ban.created_at,
            unban: form_action(
                "/admin/bans/delete",
                ActionKind::Unban,
                csrf.clone(),
                vec![hidden_field("author_sub", ban.author_sub.clone())],
            ),
        })
        .collect();

    let counts = personal_counts(&state, &headers, now).await?;
    let view = AdminView {
        chrome: page_chrome("Administration", &headers, NavTab::Home, counts),
        shared: AdminShared {
            visible_thread_bound: ADMIN_THREAD_LIMIT,
            state: if threads.is_empty() {
                CollectionState::ReadyEmpty
            } else {
                CollectionState::Ready
            },
            now,
        },
        viewer: AdminViewerState {
            create_category: CreateCategoryFormVM {
                id: Text(String::new()),
                name: Text(String::new()),
                selected_kind: ThreadKind::Discussion,
                id_max_chars: MAX_CATEGORY_ID,
                name_max_chars: MAX_NAME,
                submit: form_action(
                    "/admin/categories",
                    ActionKind::CreateCategory,
                    csrf.clone(),
                    Vec::new(),
                ),
            },
            add_ban: AddBanFormVM {
                subject_input: Text(String::new()),
                reason: Text(String::new()),
                author_sub_max_chars: MAX_SUB,
                reason_max_chars: MAX_REASON,
                submit: form_action("/admin/bans", ActionKind::AddBan, csrf, Vec::new()),
            },
            categories: admin_categories,
            threads: admin_threads,
            banned_authors,
        },
    };
    let html = admin::admin(&view);
    Ok(html_response(html, set_cookie))
}

// ===========================================================================
// Category CRUD
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct CreateCategoryForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub format: String,
}

pub async fn create_category(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateCategoryForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;

    let id = form.id.trim();
    if !is_valid_slug(id) || id.len() > MAX_CATEGORY_ID {
        return Err(AppError::InvalidRequest(
            "category id must be a slug of lowercase letters, digits and hyphens".to_string(),
        ));
    }
    let name = form.name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME {
        return Err(AppError::InvalidRequest(
            "category name is required".to_string(),
        ));
    }
    if state.store.get_category(id).await?.is_some() {
        return Err(AppError::InvalidRequest(
            "a category with that id already exists".to_string(),
        ));
    }
    let format = parse_category_format(&form.format)?;

    // Append to the end of the current ordering.
    let next_order = state
        .store
        .list_categories()
        .await?
        .iter()
        .map(|c| c.sort_order)
        .max()
        .map(|m| m + 1)
        .unwrap_or(0);
    let category = Category {
        id: id.to_string(),
        name: name.to_string(),
        sort_order: next_order,
        format,
    };
    state.store.create_category(&category).await?;
    state.audit.emit(AuditEvent::notice(
        "admin.category.create",
        &actor(&headers),
        &category.id,
        name,
    ));
    Ok(redirect_to("/admin"))
}

#[derive(Debug, Deserialize)]
pub struct RenameCategoryForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub name: String,
}

pub async fn rename_category(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<RenameCategoryForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    if state.store.get_category(&id).await?.is_none() {
        return Err(AppError::NotFound("category not found".to_string()));
    }
    let name = form.name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME {
        return Err(AppError::InvalidRequest(
            "category name is required".to_string(),
        ));
    }
    state.store.rename_category(&id, name).await?;
    state.audit.emit(AuditEvent::notice(
        "admin.category.rename",
        &actor(&headers),
        &id,
        name,
    ));
    Ok(redirect_to("/admin"))
}

#[derive(Debug, Deserialize)]
pub struct SetCategoryFormatForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub format: String,
}

pub async fn set_category_format(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<SetCategoryFormatForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let format = parse_category_format(&form.format)?;
    state.store.transition_category_format(&id, format).await?;
    state.audit.emit(AuditEvent::notice(
        "admin.category.format",
        &actor(&headers),
        &id,
        format.as_str(),
    ));
    Ok(redirect_to("/admin"))
}

fn parse_category_format(raw: &str) -> Result<CategoryFormat, AppError> {
    if raw.trim().is_empty() {
        return Ok(CategoryFormat::Discussion);
    }
    CategoryFormat::parse(raw).ok_or_else(|| {
        AppError::InvalidRequest("category format must be discussion or question".to_string())
    })
}

#[derive(Debug, Deserialize)]
pub struct ReorderForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub dir: String,
}

pub async fn reorder_category(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<ReorderForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let cats = state.store.list_categories().await?; // sorted by (sort_order, name)
    let pos = cats
        .iter()
        .position(|c| c.id == id)
        .ok_or_else(|| AppError::NotFound("category not found".to_string()))?;

    // Swap `sort_order` with the neighbor in the requested direction. Boundary moves are no-ops.
    let neighbor = match form.dir.trim() {
        "up" if pos > 0 => Some(pos - 1),
        "down" if pos + 1 < cats.len() => Some(pos + 1),
        "up" | "down" => None,
        _ => {
            return Err(AppError::InvalidRequest(
                "reorder direction must be up or down".to_string(),
            ))
        }
    };
    if let Some(n) = neighbor {
        let (a, b) = (&cats[pos], &cats[n]);
        // If two categories share a sort_order, nudge to keep the swap meaningful.
        let (ao, bo) = if a.sort_order == b.sort_order {
            (b.sort_order, a.sort_order + if n > pos { 1 } else { -1 })
        } else {
            (b.sort_order, a.sort_order)
        };
        state.store.set_category_order(&a.id, ao).await?;
        state.store.set_category_order(&b.id, bo).await?;
        state.audit.emit(AuditEvent::notice(
            "admin.category.reorder",
            &actor(&headers),
            &id,
            form.dir.trim(),
        ));
    }
    Ok(redirect_to("/admin"))
}

#[derive(Debug, Deserialize)]
pub struct CsrfForm {
    #[serde(default)]
    pub csrf: String,
}

#[derive(Debug, Deserialize)]
pub struct DeleteConfirmForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub confirm: String,
}

pub async fn delete_category_review(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let admin = auth::require_author(&headers)?;
    let category = state
        .store
        .get_category(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("category not found".to_string()))?;
    if state.store.count_threads(&id).await? > 0 {
        return Err(AppError::InvalidRequest(
            "category still has threads — move or delete them first".to_string(),
        ));
    }
    destructive_review_response(
        &state,
        &headers,
        &admin.sub,
        "Review category deletion",
        "Delete category?",
        &format!(
            "The empty category “{}” ({}) will be permanently deleted.",
            category.name, category.id
        ),
        &format!("/admin/categories/{id}/delete"),
        &category_delete_action(&id),
        "/admin",
    )
    .await
}

pub async fn delete_category(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<DeleteConfirmForm>,
) -> Result<Response, AppError> {
    let admin = auth::require_author(&headers)?;
    if state.store.get_category(&id).await?.is_none() {
        return Err(AppError::NotFound("category not found".to_string()));
    }
    // Refuse to orphan threads: a non-empty category must be emptied (or its threads moved) first.
    if state.store.count_threads(&id).await? > 0 {
        return Err(AppError::InvalidRequest(
            "category still has threads — move or delete them first".to_string(),
        ));
    }
    auth::consume_destructive_confirmation(
        state.config.destructive_confirmation_key(),
        &headers,
        &form.csrf,
        &form.confirm,
        &category_delete_action(&id),
        &admin.sub,
    )?;
    state.store.delete_category(&id).await?;
    state.audit.emit(AuditEvent::notice(
        "admin.category.delete",
        &actor(&headers),
        &id,
        "delete",
    ));
    Ok(redirect_to("/admin"))
}

// ===========================================================================
// Thread moderation
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct ThreadStateForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub state: String,
}

pub async fn lock_thread(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<ThreadStateForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let _thread = state
        .store
        .get_thread(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("thread not found".to_string()))?;
    let locked = match form.state.trim() {
        "locked" => true,
        "unlocked" => false,
        _ => {
            return Err(AppError::InvalidRequest(
                "thread lock state must be locked or unlocked".to_string(),
            ));
        }
    };
    state.store.set_thread_locked(&id, locked).await?;
    state.audit.emit(AuditEvent::notice(
        "admin.thread.lock",
        &actor(&headers),
        &id,
        if locked { "locked" } else { "unlocked" },
    ));
    Ok(redirect_to(&format!("/t/{id}")))
}

pub async fn pin_thread(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<ThreadStateForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let _thread = state
        .store
        .get_thread(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("thread not found".to_string()))?;
    let pinned = match form.state.trim() {
        "pinned" => true,
        "unpinned" => false,
        _ => {
            return Err(AppError::InvalidRequest(
                "thread pin state must be pinned or unpinned".to_string(),
            ));
        }
    };
    state.store.set_thread_pinned(&id, pinned).await?;
    state.audit.emit(AuditEvent::notice(
        "admin.thread.pin",
        &actor(&headers),
        &id,
        if pinned { "pinned" } else { "unpinned" },
    ));
    Ok(redirect_to(&format!("/t/{id}")))
}

#[derive(Debug, Deserialize)]
pub struct MoveThreadForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub category: String,
}

pub async fn move_thread(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<MoveThreadForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let category_id = form.category.trim();
    state
        .store
        .move_thread_to_category(&id, category_id)
        .await?;
    state.audit.emit(AuditEvent::notice(
        "admin.thread.move",
        &actor(&headers),
        &id,
        category_id,
    ));
    Ok(redirect_to(&format!("/t/{id}")))
}

pub async fn delete_thread_review(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let admin = auth::require_author(&headers)?;
    let thread = state
        .store
        .get_thread(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("thread not found".to_string()))?;
    let reply_count = state.store.count_posts(&id).await?.saturating_sub(1);
    destructive_review_response(
        &state,
        &headers,
        &admin.sub,
        "Review admin thread deletion",
        "Delete thread as administrator?",
        &format!(
            "The thread “{}” and its {} {} will be permanently deleted.",
            thread.title,
            reply_count,
            if reply_count == 1 { "reply" } else { "replies" }
        ),
        &format!("/admin/threads/{id}/delete"),
        &thread_delete_action(&id),
        &format!("/t/{id}"),
    )
    .await
}

pub async fn delete_thread(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<DeleteConfirmForm>,
) -> Result<Response, AppError> {
    let admin = auth::require_author(&headers)?;
    if state.store.get_thread(&id).await?.is_none() {
        return Err(AppError::NotFound("thread not found".to_string()));
    }
    auth::consume_destructive_confirmation(
        state.config.destructive_confirmation_key(),
        &headers,
        &form.csrf,
        &form.confirm,
        &thread_delete_action(&id),
        &admin.sub,
    )?;
    state.store.delete_thread(&id).await?;
    state.audit.emit(AuditEvent::notice(
        "admin.thread.delete",
        &actor(&headers),
        &id,
        "delete",
    ));
    Ok(redirect_to("/admin"))
}

// ===========================================================================
// Any-post deletion
// ===========================================================================

pub async fn delete_post_review(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let admin = auth::require_author(&headers)?;
    let post = state
        .store
        .get_post(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("post not found".to_string()))?;
    let thread_id = post.thread_id.clone();
    let op = state.store.first_post_in_thread(&thread_id).await?;
    if op.as_ref().is_some_and(|original| original.id == id) {
        return Err(AppError::InvalidRequest(
            "the original post cannot be deleted separately; delete the thread".to_string(),
        ));
    }
    destructive_review_response(
        &state,
        &headers,
        &admin.sub,
        "Review admin post deletion",
        "Delete reply as administrator?",
        &format!(
            "The reply by {} will be permanently removed from this thread.",
            post.author_email
        ),
        &format!("/admin/posts/{id}/delete"),
        &post_delete_action(&id),
        &format!("/t/{thread_id}"),
    )
    .await
}

pub async fn delete_post(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<DeleteConfirmForm>,
) -> Result<Response, AppError> {
    let admin = auth::require_author(&headers)?;
    let post = state
        .store
        .get_post(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("post not found".to_string()))?;
    let thread_id = post.thread_id.clone();
    let op = state.store.first_post_in_thread(&thread_id).await?;
    if op.as_ref().is_some_and(|original| original.id == id) {
        return Err(AppError::InvalidRequest(
            "the original post cannot be deleted separately; delete the thread".to_string(),
        ));
    }
    auth::consume_destructive_confirmation(
        state.config.destructive_confirmation_key(),
        &headers,
        &form.csrf,
        &form.confirm,
        &post_delete_action(&id),
        &admin.sub,
    )?;
    state.store.delete_post(&id).await?;
    state.audit.emit(AuditEvent::notice(
        "admin.post.delete",
        &actor(&headers),
        &id,
        &thread_id,
    ));
    Ok(redirect_to(&format!("/t/{thread_id}")))
}

// ===========================================================================
// Author blocklist
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct AddBanForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub author_sub: String,
    #[serde(default)]
    pub reason: String,
}

pub async fn add_ban(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AddBanForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let author_sub = form.author_sub.trim();
    if author_sub.is_empty() || author_sub.len() > MAX_SUB {
        return Err(AppError::InvalidRequest(
            "author subject id is required".to_string(),
        ));
    }
    let reason = form.reason.trim();
    if reason.chars().count() > MAX_REASON {
        return Err(AppError::InvalidRequest("reason is too long".to_string()));
    }
    let ban = BannedAuthor {
        author_sub: author_sub.to_string(),
        reason: reason.to_string(),
        banned_by: actor(&headers),
        created_at: now_secs(),
    };
    state.store.add_ban(&ban).await?;
    state.audit.emit(AuditEvent::notice(
        "admin.author.ban",
        &actor(&headers),
        author_sub,
        reason,
    ));
    Ok(redirect_to("/admin"))
}

#[derive(Debug, Deserialize)]
pub struct RemoveBanForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub author_sub: String,
}

pub async fn remove_ban(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RemoveBanForm>,
) -> Result<Response, AppError> {
    auth::verify_csrf(&headers, &form.csrf)?;
    let author_sub = form.author_sub.trim();
    if author_sub.is_empty() || author_sub.len() > MAX_SUB {
        return Err(AppError::InvalidRequest(
            "author subject id is required".to_string(),
        ));
    }
    state.store.remove_ban(author_sub).await?;
    state.audit.emit(AuditEvent::notice(
        "admin.author.unban",
        &actor(&headers),
        author_sub,
        "unban",
    ));
    Ok(redirect_to("/admin"))
}

/// A URL/DOM-safe category slug: non-empty, lowercase ascii letters, digits, or hyphens.
fn is_valid_slug(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}
