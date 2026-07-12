//! PostgreSQL `Store` integration test.
//!
//! Runs ONLY when `TEST_DATABASE_URL` is set (it needs an external Postgres). When unset the test
//! prints a note and returns early — it never fails the default `cargo test` run, which stays
//! database-free. Spin up a throwaway Postgres and run:
//!
//! ```text
//! docker run --rm -d --name ap-testpg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=aperture \
//!   -p 127.0.0.1:55490:5432 postgres:18-alpine
//! TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55490/aperture \
//!   cargo test --test pg_store -- --nocapture
//! docker rm -f ap-testpg
//! ```
//!
//! Uses a multi-threaded runtime (matching production); the `Store` trait is async, so the
//! handlers `.await` sqlx natively with no sync-over-async bridge. The blob store stays in-memory
//! here (Cairn is exercised at deploy), so this validates ONLY the portable SQL metadata path.

use std::sync::Arc;
use std::time::Duration;

use aperture::blobs::{BlobError, Blobs, MemoryBlobs};
use aperture::model::{
    FileRec, FolderRec, LibraryItemKind, LibraryQuery, LibraryType, LibraryView, UploadDelivery,
    UploadRequestInboxCounts, UploadRequestInboxView, UploadRequestRec, UploadReviewDisposition,
    UploadReviewDispositionState, UploadSubmission, VersionRec,
    UPLOAD_REQUEST_EXPIRING_WINDOW_SECS,
};
use aperture::store::{
    BlobDeleteClaim, BulkMutation, DriveItemRef, FolderDelete, OwnerBlobCommit,
    OwnerBlobWriteIntent, OwnerReuploadInput, OwnerVersionRestoreInput, PgStore, Store,
    TrashRootInput, UploadRecoveryClaim, UploadReserve, UploadReserveInput, MAX_BULK_ITEMS,
    OWNER_WRITE_FRESH, OWNER_WRITE_REUPLOAD,
};
use aperture::{app, build_dev_state, now_secs, recover_stale_request_uploads, AppState};
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use tower::ServiceExt;

struct FailingRecoveryDelete {
    inner: Arc<MemoryBlobs>,
}

#[async_trait::async_trait]
impl Blobs for FailingRecoveryDelete {
    fn bucket(&self) -> &str {
        self.inner.bucket()
    }

    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), BlobError> {
        self.inner.put(key, bytes).await
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, BlobError> {
        self.inner.get(key).await
    }

    async fn get_range(
        &self,
        key: &str,
        start: u64,
        end_inclusive: u64,
    ) -> Result<Vec<u8>, BlobError> {
        self.inner.get_range(key, start, end_inclusive).await
    }

    async fn delete(&self, _key: &str) -> Result<(), BlobError> {
        Err(BlobError::Backend(
            "injected recovery delete failure".to_string(),
        ))
    }
}

fn file(id: &str, owner: &str, token: &str, created_at: i64) -> FileRec {
    FileRec {
        id: id.to_string(),
        owner_sub: owner.to_string(),
        name: format!("{id}.png"),
        content_type: "image/png".to_string(),
        size: 1234,
        bucket: "aperture".to_string(),
        object_key: id.to_string(),
        share_token: Some(token.to_string()),
        created_at,
        updated_at: created_at,
        expires_at: None,
        share_password_hash: None,
        folder_id: None,
        trashed_at: 0,
        trash_entry_id: None,
        trash_ancestor_id: None,
        view_count: 0,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg_store_full_integration() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!(
            "NOTE: TEST_DATABASE_URL not set — skipping Postgres integration test (needs external \
             Postgres). This is expected for the default test run."
        );
        return;
    };

    // --- connect / migrate (idempotent: run twice) -------------------------
    let pg = PgStore::connect(&url)
        .await
        .expect("connect to TEST_DATABASE_URL");
    pg.migrate().await.expect("migrate");
    pg.migrate().await.expect("migrate is idempotent");

    // Raw pool to reset the table for a clean run.
    let raw = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    sqlx::query(
        "DROP TRIGGER IF EXISTS aperture_fail_request_receipt_trigger ON upload_submissions",
    )
    .execute(&raw)
    .await
    .unwrap();
    sqlx::query("DROP FUNCTION IF EXISTS aperture_fail_request_receipt()")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query(
        "DROP TRIGGER IF EXISTS aperture_fail_review_disposition_trigger \
         ON upload_submission_dispositions",
    )
    .execute(&raw)
    .await
    .unwrap();
    sqlx::query("DROP FUNCTION IF EXISTS aperture_fail_review_disposition()")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query(
        "DROP TRIGGER IF EXISTS aperture_fail_recovery_abandon_trigger ON upload_reservations",
    )
    .execute(&raw)
    .await
    .unwrap();
    sqlx::query("DROP FUNCTION IF EXISTS aperture_fail_recovery_abandon()")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DROP TRIGGER IF EXISTS aperture_block_legacy_backfill_trigger ON upload_requests")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION IF EXISTS aperture_block_legacy_backfill()")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query(
        "DROP TRIGGER IF EXISTS aperture_block_reservation_insert_trigger ON upload_reservations",
    )
    .execute(&raw)
    .await
    .unwrap();
    sqlx::query("DROP FUNCTION IF EXISTS aperture_block_reservation_insert()")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query(
        "DROP TRIGGER IF EXISTS aperture_block_purge_reserve_trigger ON upload_reservations",
    )
    .execute(&raw)
    .await
    .unwrap();
    sqlx::query("DROP FUNCTION IF EXISTS aperture_block_purge_reserve()")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DROP TRIGGER IF EXISTS aperture_block_purge_commit_trigger ON files")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION IF EXISTS aperture_block_purge_commit()")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DROP TRIGGER IF EXISTS aperture_block_trash_claim_trigger ON trash_entries")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION IF EXISTS aperture_block_trash_claim()")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DROP TRIGGER IF EXISTS aperture_block_folder_create_trigger ON folders")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION IF EXISTS aperture_block_folder_create()")
        .execute(&raw)
        .await
        .unwrap();
    for table in [
        "owner_blob_write_intents",
        "blob_delete_queue",
        "blob_key_guards",
        "trash_entries",
        "upload_submissions",
        "upload_deliveries",
        "upload_reservations",
        "upload_requests",
        "owner_storage_guards",
        "file_comments",
        "file_versions",
        "files",
        "folders",
        "owner_quotas",
    ] {
        sqlx::query(&format!("DELETE FROM {table}"))
            .execute(&raw)
            .await
            .unwrap();
    }

    // Simulate a v7 database whose flat submissions table predates delivery tracking. The v8
    // migration must add both the delivery table and nullable reference, and remain idempotent.
    sqlx::query("ALTER TABLE upload_submissions DROP COLUMN IF EXISTS delivery_id")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DROP TABLE upload_deliveries")
        .execute(&raw)
        .await
        .unwrap();
    pg.migrate().await.expect("v7 delivery upgrade");
    pg.migrate()
        .await
        .expect("v7 delivery upgrade is idempotent");

    let pg = Arc::new(pg);
    let store: Arc<dyn Store> = pg.clone();
    let now = now_secs();
    let owner_intent_index: i64 = sqlx::query(
        "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM pg_indexes \
         WHERE schemaname = current_schema() \
           AND indexname = 'idx_owner_blob_write_owner_kind'",
    )
    .fetch_one(&raw)
    .await
    .unwrap()
    .try_get("count")
    .unwrap();
    assert_eq!(
        owner_intent_index, 1,
        "migration installs owner quota index"
    );
    let review_hold_index: i64 = sqlx::query(
        "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM pg_indexes \
         WHERE schemaname = current_schema() \
           AND indexname = 'idx_upload_submission_dispositions_request_state'",
    )
    .fetch_one(&raw)
    .await
    .unwrap()
    .try_get("count")
    .unwrap();
    assert_eq!(review_hold_index, 1, "migration installs Review Hold index");
    let request_keyset_index: i64 = sqlx::query(
        "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM pg_indexes \
         WHERE schemaname = current_schema() \
           AND indexname = 'idx_upload_requests_owner_updated_id'",
    )
    .fetch_one(&raw)
    .await
    .unwrap()
    .try_get("count")
    .unwrap();
    assert_eq!(
        request_keyset_index, 1,
        "migration installs the full Request Inbox keyset index"
    );
    let disposition_scope_fk: bool = sqlx::query_scalar(
        "SELECT EXISTS (\
             SELECT 1 FROM information_schema.table_constraints \
             WHERE constraint_schema = current_schema() \
               AND table_name = 'upload_submission_dispositions' \
               AND constraint_name = 'fk_upload_disposition_submission_scope' \
               AND constraint_type = 'FOREIGN KEY'\
         )",
    )
    .fetch_one(&raw)
    .await
    .unwrap();
    assert!(
        disposition_scope_fk,
        "database binds disposition submission/request/file identity"
    );

    // --- create + get round-trip -------------------------------------------
    assert!(store
        .create(&file("aaaaaaaaaa", "alice", "tok-aaaa", now))
        .await
        .unwrap());
    let got = store
        .get("aaaaaaaaaa")
        .await
        .unwrap()
        .expect("file persisted");
    assert_eq!(got.name, "aaaaaaaaaa.png");
    assert_eq!(got.content_type, "image/png");
    assert_eq!(got.size, 1234);
    assert_eq!(got.bucket, "aperture");
    assert_eq!(got.object_key, "aaaaaaaaaa");
    assert_eq!(got.share_token.as_deref(), Some("tok-aaaa"));
    assert_eq!(got.view_count, 0);

    // --- id collision -> create returns false (ON CONFLICT DO NOTHING) ------
    assert!(!store
        .create(&file("aaaaaaaaaa", "alice", "tok-diff", now + 5))
        .await
        .unwrap());
    // --- share-token collision ALSO trips the no-target ON CONFLICT ---------
    assert!(!store
        .create(&file("bbbbbbbbbb", "alice", "tok-aaaa", now + 5))
        .await
        .unwrap());

    // --- fetch by share token (the public /s/{token} path) -----------------
    assert_eq!(
        store.get_by_token("tok-aaaa").await.unwrap().unwrap().id,
        "aaaaaaaaaa"
    );
    assert!(store.get_by_token("nope").await.unwrap().is_none());

    // --- public landing-page view counter is atomic and missing ids are no-op.
    store.bump_view_count("aaaaaaaaaa").await.unwrap();
    store.bump_view_count("aaaaaaaaaa").await.unwrap();
    store.bump_view_count("missing").await.unwrap();
    let viewed = store.get("aaaaaaaaaa").await.unwrap().unwrap();
    assert_eq!(viewed.view_count, 2);
    assert_eq!(
        viewed.updated_at, got.updated_at,
        "anonymous public views never reorder owner Recent"
    );

    // --- share-link lifecycle: set expiry + password, then revoke ----------
    assert!(store
        .configure_share(
            "aaaaaaaaaa",
            "alice",
            Some("tok-aaaa".into()),
            Some(now + 3600),
            Some("salt$hash".into())
        )
        .await
        .unwrap());
    let cfg = store.get("aaaaaaaaaa").await.unwrap().unwrap();
    assert_eq!(cfg.expires_at, Some(now + 3600));
    assert_eq!(cfg.share_password_hash.as_deref(), Some("salt$hash"));
    assert!(cfg.updated_at > viewed.updated_at);
    assert!(store
        .configure_share(
            "aaaaaaaaaa",
            "alice",
            Some("tok-aaaa".into()),
            Some(now + 3600),
            Some("salt$hash".into())
        )
        .await
        .unwrap());
    let cfg_again = store.get("aaaaaaaaaa").await.unwrap().unwrap();
    assert!(
        cfg_again.updated_at > cfg.updated_at,
        "same-second PostgreSQL mutations advance the activity cursor"
    );
    // Revoke clears the token to NULL; the public lookup misses and the row's token is None.
    assert!(store
        .configure_share("aaaaaaaaaa", "alice", None, None, None)
        .await
        .unwrap());
    assert!(store.get_by_token("tok-aaaa").await.unwrap().is_none());
    assert!(store
        .get("aaaaaaaaaa")
        .await
        .unwrap()
        .unwrap()
        .share_token
        .is_none());
    // A non-owner cannot configure the share link.
    assert!(!store
        .configure_share("aaaaaaaaaa", "bob", Some("tok-x".into()), None, None)
        .await
        .unwrap());

    // --- owner-scoped gallery list, newest-first ---------------------------
    store
        .create(&file("cccccccccc", "alice", "tok-cccc", now + 20))
        .await
        .unwrap();
    store
        .create(&file("dddddddddd", "bob", "tok-dddd", now + 30))
        .await
        .unwrap();
    let mine = store.list_by_owner("alice", None, None, 50).await.unwrap();
    let ids: Vec<&str> = mine.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(
        ids,
        vec!["cccccccccc", "aaaaaaaaaa"],
        "other owner excluded, newest first"
    );

    // --- keyset backward pagination over the portable SQL path -------------
    let page1 = store.list_by_owner("alice", None, None, 1).await.unwrap();
    assert_eq!(
        page1.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(),
        vec!["cccccccccc"],
        "first page = newest only"
    );
    let cur = page1.last().unwrap();
    let page2 = store
        .list_by_owner("alice", None, Some((cur.created_at, cur.id.clone())), 1)
        .await
        .unwrap();
    assert_eq!(
        page2.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(),
        vec!["aaaaaaaaaa"],
        "before-cursor pages into the older row"
    );

    // --- folders (albums): create, filter, move, rename, delete-unfiles ----
    sqlx::query("DELETE FROM file_versions")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DELETE FROM folders")
        .execute(&raw)
        .await
        .unwrap();
    let fld = |id: &str, owner: &str, name: &str| FolderRec {
        id: id.to_string(),
        owner_sub: owner.to_string(),
        parent_id: None,
        name: name.to_string(),
        created_at: now,
        updated_at: now,
        share_token: None,
        expires_at: None,
        share_password_hash: None,
        upload_token: None,
        trashed_at: 0,
        trash_entry_id: None,
        trash_ancestor_id: None,
    };
    assert!(store
        .create_folder(&fld("fold000001", "alice", "Zeta"))
        .await
        .unwrap());
    assert!(store
        .create_folder(&fld("fold000002", "alice", "alpha"))
        .await
        .unwrap());
    assert!(store
        .create_folder(&fld("fold000003", "bob", "bobs"))
        .await
        .unwrap());
    // id collision -> false.
    assert!(!store
        .create_folder(&fld("fold000001", "alice", "dup"))
        .await
        .unwrap());
    // Owner-scoped, case-insensitive name order; bob's folder excluded.
    let folder_names: Vec<String> = store
        .list_folders("alice")
        .await
        .unwrap()
        .into_iter()
        .map(|f| f.name)
        .collect();
    assert_eq!(folder_names, vec!["alpha".to_string(), "Zeta".to_string()]);
    // get_folder is ownership-scoped.
    assert!(store
        .get_folder("fold000001", "alice")
        .await
        .unwrap()
        .is_some());
    assert!(store
        .get_folder("fold000003", "alice")
        .await
        .unwrap()
        .is_none());

    // Move alice's file "cccccccccc" into a folder; the folder view returns only it.
    assert!(store
        .move_file("cccccccccc", "alice", Some("fold000001"))
        .await
        .unwrap());
    let in_folder = store
        .list_by_owner("alice", Some("fold000001"), None, 50)
        .await
        .unwrap();
    assert_eq!(
        in_folder.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(),
        vec!["cccccccccc"]
    );
    // list_files_in_folder returns the whole folder unpaginated.
    assert_eq!(
        store
            .list_files_in_folder("fold000001", "alice")
            .await
            .unwrap()
            .len(),
        1
    );
    // The ROOT view (folder=None) now EXCLUDES the filed file (the tree model).
    assert!(store
        .list_by_owner("alice", None, None, 50)
        .await
        .unwrap()
        .iter()
        .all(|f| f.id != "cccccccccc"));
    // find_file_in_folder resolves same-name-per-level (portable IS NULL vs = branch).
    assert_eq!(
        store
            .find_file_in_folder("alice", "cccccccccc.png", Some("fold000001"))
            .await
            .unwrap()
            .unwrap()
            .id,
        "cccccccccc"
    );

    // --- global owner library: Memory/Pg contract, literal search + cross-kind cursor ---------
    // Classification is mutually exclusive and follows the Rust priority order. These two MIME
    // strings intentionally contain archive-looking suffixes but are classified earlier.
    let mut priority_document = file("texttar001", "alice", "priority-doc-token", now + 800);
    priority_document.name = "Priority document".into();
    priority_document.content_type = "text/x-tar".into();
    priority_document.share_token = None;
    assert!(store.create(&priority_document).await.unwrap());
    let mut priority_image = file("imagezip01", "alice", "priority-image-token", now + 801);
    priority_image.name = "Priority image".into();
    priority_image.content_type = "image/x-zip".into();
    priority_image.share_token = None;
    assert!(store.create(&priority_image).await.unwrap());
    let priority_query = |type_filter| LibraryQuery {
        view: LibraryView::All,
        query: Some("priority".into()),
        type_filter,
        before: None,
        limit: 20,
    };
    let priority_documents = store
        .query_library("alice", &priority_query(LibraryType::Document))
        .await
        .unwrap();
    assert_eq!(priority_documents.items.len(), 1);
    assert_eq!(priority_documents.items[0].id, "texttar001");
    let priority_images = store
        .query_library("alice", &priority_query(LibraryType::Image))
        .await
        .unwrap();
    assert_eq!(priority_images.items.len(), 1);
    assert_eq!(priority_images.items[0].id, "imagezip01");
    assert!(store
        .query_library("alice", &priority_query(LibraryType::Archive))
        .await
        .unwrap()
        .items
        .is_empty());
    assert!(store.delete("texttar001", "alice").await.unwrap());
    assert!(store.delete("imagezip01", "alice").await.unwrap());

    let image_results = store
        .query_library(
            "alice",
            &LibraryQuery {
                view: LibraryView::All,
                query: Some("CCCC".into()),
                type_filter: LibraryType::Image,
                before: None,
                limit: 20,
            },
        )
        .await
        .unwrap();
    assert_eq!(image_results.items.len(), 1);
    assert_eq!(image_results.items[0].id, "cccccccccc");
    assert_eq!(
        image_results.items[0].parent_id.as_deref(),
        Some("fold000001"),
        "search crosses the folder tree"
    );

    let mut tie_file = file("tiefile001", "alice", "tie-file-token", now + 1000);
    tie_file.name = "Tie Item".into();
    assert!(store.create(&tie_file).await.unwrap());
    let mut tie_folder = fld("tiefolder1", "alice", "Tie Item");
    tie_folder.created_at = now + 1000;
    tie_folder.updated_at = now + 1000;
    assert!(store.create_folder(&tie_folder).await.unwrap());
    let tie_query = LibraryQuery {
        view: LibraryView::Recent,
        query: Some("tie item".into()),
        type_filter: LibraryType::All,
        before: None,
        limit: 1,
    };
    let tie_first = store.query_library("alice", &tie_query).await.unwrap();
    assert_eq!(tie_first.items[0].id, "tiefile001");
    let tie_second = store
        .query_library(
            "alice",
            &LibraryQuery {
                before: tie_first.next.clone(),
                ..tie_query
            },
        )
        .await
        .unwrap();
    assert_eq!(tie_second.items[0].id, "tiefolder1");
    assert!(tie_second.next.is_none());

    assert!(store
        .configure_share(
            "tiefile001",
            "alice",
            Some("tie-file-token".into()),
            Some(1),
            Some("salt$hash".into()),
        )
        .await
        .unwrap());
    assert!(store
        .configure_folder_share(
            "tiefolder1",
            "alice",
            Some("tie-folder-token".into()),
            Some(1),
            Some("salt$hash".into()),
        )
        .await
        .unwrap());
    let shared_items = store
        .query_library(
            "alice",
            &LibraryQuery {
                view: LibraryView::Shared,
                query: Some("tie item".into()),
                type_filter: LibraryType::All,
                before: None,
                limit: 20,
            },
        )
        .await
        .unwrap();
    assert_eq!(shared_items.items.len(), 2);
    assert!(shared_items.items.iter().all(|item| item.share_expired));
    assert!(shared_items.items.iter().all(|item| item.share_protected));
    sqlx::query("UPDATE files SET updated_at = $1 WHERE id = 'tiefile001'")
        .bind(i64::MAX)
        .execute(&raw)
        .await
        .unwrap();
    assert!(store
        .rename_file("tiefile001", "alice", "Tie Item saturated")
        .await
        .unwrap());
    assert_eq!(
        store.get("tiefile001").await.unwrap().unwrap().updated_at,
        i64::MAX,
        "activity touch saturates instead of overflowing BIGINT"
    );
    assert!(store.delete("tiefile001", "alice").await.unwrap());
    assert_eq!(
        store
            .delete_folder_if_empty("tiefolder1", "alice")
            .await
            .unwrap(),
        FolderDelete::Deleted
    );
    // A non-owner cannot move the file or rename/delete the folder.
    assert!(!store
        .move_file("cccccccccc", "bob", Some("fold000001"))
        .await
        .unwrap());
    assert!(!store
        .rename_folder("fold000001", "bob", "hax")
        .await
        .unwrap());
    assert_eq!(
        store
            .delete_folder_if_empty("fold000001", "bob")
            .await
            .unwrap(),
        FolderDelete::NotFound
    );
    // Rename works for the owner.
    assert!(store
        .rename_folder("fold000001", "alice", "Renamed")
        .await
        .unwrap());
    assert_eq!(
        store
            .get_folder("fold000001", "alice")
            .await
            .unwrap()
            .unwrap()
            .name,
        "Renamed"
    );

    // --- folder TREE: a child folder makes the parent non-empty --------------
    assert!(store
        .create_folder(&FolderRec {
            parent_id: Some("fold000001".to_string()),
            ..fld("fold000009", "alice", "Child")
        })
        .await
        .unwrap());
    assert_eq!(
        store
            .delete_folder_if_empty("fold000001", "alice")
            .await
            .unwrap(),
        FolderDelete::NotEmpty,
        "a folder with a subfolder AND a file is not empty"
    );

    // --- folder public share link (portable token unique index) --------------
    assert!(store
        .configure_folder_share(
            "fold000001",
            "alice",
            Some("folder-tok".into()),
            Some(now + 60),
            Some("s$h".into())
        )
        .await
        .unwrap());
    let by_tok = store
        .get_folder_by_token("folder-tok")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(by_tok.id, "fold000001");
    assert!(by_tok.share_has_password());
    assert!(store
        .configure_folder_share("fold000001", "alice", None, None, None)
        .await
        .unwrap());
    assert!(store
        .get_folder_by_token("folder-tok")
        .await
        .unwrap()
        .is_none());

    // --- cascade delete removes the subtree, keeping ccc (moved out first) ----
    // Move ccc back to the root so it survives for the later usage assertions.
    assert!(store.move_file("cccccccccc", "alice", None).await.unwrap());
    let freed = store
        .delete_folder_cascade("fold000001", "alice")
        .await
        .unwrap();
    assert!(
        freed.is_empty(),
        "no files remained in the subtree, so no blob keys are freed"
    );
    assert!(store
        .get_folder("fold000001", "alice")
        .await
        .unwrap()
        .is_none());
    assert!(
        store
            .get_folder("fold000009", "alice")
            .await
            .unwrap()
            .is_none(),
        "child removed too"
    );
    assert!(
        store
            .get("cccccccccc")
            .await
            .unwrap()
            .unwrap()
            .folder_id
            .is_none(),
        "ccc kept at root"
    );

    // Child creation owns the same lifecycle guard as subtree purge. Hold the child INSERT after
    // its provisional row exists: purge must wait, then include the committed child in its fresh
    // subtree snapshot. No dangling parent_id survives either winner ordering.
    assert!(store
        .create_folder(&fld("folderraceparent", "folder-race-owner", "Race parent",))
        .await
        .unwrap());
    sqlx::query(
        "CREATE OR REPLACE FUNCTION aperture_block_folder_create() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN \
           IF NEW.id = 'folderracechild' THEN \
             PERFORM pg_advisory_xact_lock(7300106); \
           END IF; \
           RETURN NEW; \
         END $$",
    )
    .execute(&raw)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER aperture_block_folder_create_trigger BEFORE INSERT ON folders \
         FOR EACH ROW EXECUTE FUNCTION aperture_block_folder_create()",
    )
    .execute(&raw)
    .await
    .unwrap();
    let mut folder_create_barrier = raw.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(7300106)")
        .execute(&mut *folder_create_barrier)
        .await
        .unwrap();
    let create_store = store.clone();
    let creating_child = tokio::spawn(async move {
        create_store
            .create_folder(&FolderRec {
                id: "folderracechild".into(),
                owner_sub: "folder-race-owner".into(),
                parent_id: Some("folderraceparent".into()),
                name: "Race child".into(),
                created_at: now + 100,
                updated_at: now + 100,
                share_token: None,
                expires_at: None,
                share_password_hash: None,
                upload_token: None,
                trashed_at: 0,
                trash_entry_id: None,
                trash_ancestor_id: None,
            })
            .await
    });
    let mut child_at_barrier = false;
    for _ in 0..200 {
        let blocked: i64 = sqlx::query(
            "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM pg_stat_activity \
             WHERE pid <> pg_backend_pid() AND state = 'active' AND wait_event_type = 'Lock' \
               AND query LIKE '%INSERT INTO folders%'",
        )
        .fetch_one(&raw)
        .await
        .unwrap()
        .try_get("count")
        .unwrap();
        if blocked > 0 {
            child_at_barrier = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(child_at_barrier, "child create did not reach its barrier");
    let purge_store = store.clone();
    let purging_parent = tokio::spawn(async move {
        let item = DriveItemRef {
            kind: LibraryItemKind::Folder,
            id: "folderraceparent".into(),
        };
        let trashed = purge_store
            .bulk_trash(
                "folder-race-owner",
                &[TrashRootInput {
                    item: item.clone(),
                    entry_id: "folder-race-trash".into(),
                }],
                now + 101,
                now + 10_000,
            )
            .await
            .map_err(|error| error.to_string())?;
        if trashed != (BulkMutation::Applied { changed: 1 }) {
            return Err(format!("unexpected folder trash result: {trashed:?}"));
        }
        purge_store
            .bulk_purge("folder-race-owner", &[item], now + 102)
            .await
            .map_err(|error| error.to_string())
    });
    let mut parent_purge_waited = false;
    for _ in 0..200 {
        let blocked: i64 = sqlx::query(
            "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM pg_stat_activity \
             WHERE pid <> pg_backend_pid() AND state = 'active' AND wait_event_type = 'Lock' \
               AND query LIKE '%SELECT owner_sub FROM owner_storage_guards%'",
        )
        .fetch_one(&raw)
        .await
        .unwrap()
        .try_get("count")
        .unwrap();
        if blocked > 0 {
            parent_purge_waited = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        parent_purge_waited,
        "subtree purge did not wait behind child create"
    );
    folder_create_barrier.rollback().await.unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(5), creating_child)
        .await
        .expect("child create timed out")
        .unwrap()
        .unwrap());
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), purging_parent)
            .await
            .expect("subtree purge timed out")
            .unwrap()
            .unwrap(),
        BulkMutation::Applied { changed: 1 }
    );
    assert!(store
        .get_folder_any("folderraceparent", "folder-race-owner")
        .await
        .unwrap()
        .is_none());
    assert!(store
        .get_folder_any("folderracechild", "folder-race-owner")
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        sqlx::query(
            "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM folders \
             WHERE parent_id = 'folderraceparent'",
        )
        .fetch_one(&raw)
        .await
        .unwrap()
        .try_get::<i64, _>("count")
        .unwrap(),
        0
    );
    sqlx::query("DROP TRIGGER aperture_block_folder_create_trigger ON folders")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION aperture_block_folder_create()")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DELETE FROM folders")
        .execute(&raw)
        .await
        .unwrap();

    // --- versions: add / list (newest-first) / prune / update / usage --------
    let ver = |id: &str, file_id: &str, size: i64, at: i64| VersionRec {
        id: id.to_string(),
        file_id: file_id.to_string(),
        object_key: format!("{id}-blob"),
        size,
        content_type: "image/png".to_string(),
        created_at: at,
    };
    // A throwaway file so ccc's size/type stay pristine for the usage section below.
    store
        .create(&file("verfile000", "alice", "tok-ver", now + 40))
        .await
        .unwrap();
    let base = store.usage_for_owner("alice").await.unwrap();
    assert!(store
        .add_version(&ver("ver1", "verfile000", 100, now + 1))
        .await
        .unwrap());
    assert!(store
        .add_version(&ver("ver2", "verfile000", 200, now + 2))
        .await
        .unwrap());
    assert!(store
        .add_version(&ver("ver3", "verfile000", 300, now + 3))
        .await
        .unwrap());
    let vids: Vec<String> = store
        .list_versions("verfile000")
        .await
        .unwrap()
        .into_iter()
        .map(|v| v.id)
        .collect();
    assert_eq!(vids, vec!["ver3", "ver2", "ver1"], "newest-first");
    // Version bytes (100+200+300) count toward usage on top of the file bytes.
    assert_eq!(store.usage_for_owner("alice").await.unwrap(), base + 600);
    let pruned = store.prune_versions("verfile000", 2).await.unwrap();
    assert_eq!(
        pruned.iter().map(|v| v.id.as_str()).collect::<Vec<_>>(),
        vec!["ver1"]
    );
    assert_eq!(store.list_versions("verfile000").await.unwrap().len(), 2);
    // update_file_blob repoints the current pointer (the restore/re-upload primitive).
    assert!(store
        .update_file_blob(
            "verfile000",
            "alice",
            "newkey",
            42,
            "application/pdf",
            now + 99
        )
        .await
        .unwrap());
    let repointed = store.get("verfile000").await.unwrap().unwrap();
    assert_eq!(repointed.object_key, "newkey");
    assert_eq!(repointed.content_type, "application/pdf");
    // delete_versions_for_file returns the remaining rows for blob cleanup, then remove the file.
    assert_eq!(
        store
            .delete_versions_for_file("verfile000")
            .await
            .unwrap()
            .len(),
        2
    );
    assert!(store.list_versions("verfile000").await.unwrap().is_empty());
    store.delete("verfile000", "alice").await.unwrap();
    sqlx::query("DELETE FROM file_versions")
        .execute(&raw)
        .await
        .unwrap();

    // --- ownership-scoped delete -------------------------------------------
    assert!(
        !store.delete("aaaaaaaaaa", "bob").await.unwrap(),
        "bob cannot delete alice's"
    );
    assert!(store.get("aaaaaaaaaa").await.unwrap().is_some());
    assert!(store.delete("aaaaaaaaaa", "alice").await.unwrap());
    assert!(store.get("aaaaaaaaaa").await.unwrap().is_none());

    // --- storage quotas: usage sums + override rows (portable SQL) ----------
    sqlx::query("DELETE FROM owner_quotas")
        .execute(&raw)
        .await
        .unwrap();
    // Remaining rows: cccccccccc (alice, 1234) and dddddddddd (bob, 1234).
    assert_eq!(store.usage_for_owner("alice").await.unwrap(), 1234);
    assert_eq!(store.usage_for_owner("nobody").await.unwrap(), 0);
    let agg = store.usage_by_owner().await.unwrap();
    assert_eq!(agg.len(), 2);
    assert!(agg
        .iter()
        .any(|u| u.owner_sub == "alice" && u.files == 1 && u.bytes == 1234));
    assert!(agg
        .iter()
        .any(|u| u.owner_sub == "bob" && u.files == 1 && u.bytes == 1234));
    // Overrides: missing row -> None; set is an upsert; list is owner-ordered; None clears.
    assert_eq!(store.get_quota("alice").await.unwrap(), None);
    store.set_quota("alice", Some(999)).await.unwrap();
    store.set_quota("alice", Some(2048)).await.unwrap();
    assert_eq!(store.get_quota("alice").await.unwrap(), Some(2048));
    store.set_quota("bob", Some(0)).await.unwrap();
    assert_eq!(
        store.list_quotas().await.unwrap(),
        vec![("alice".to_string(), 2048), ("bob".to_string(), 0)]
    );
    store.set_quota("alice", None).await.unwrap();
    assert_eq!(store.get_quota("alice").await.unwrap(), None);
    sqlx::query("DELETE FROM owner_quotas")
        .execute(&raw)
        .await
        .unwrap();

    // --- Request Rooms v2: migration/backfill, CRUD, receipts and concurrency ---------
    // A cross-table token collision is not idempotence. Migration must fail closed and retain the
    // legacy source instead of silently binding Alice's old capability to Bob's request.
    assert!(store
        .create_folder(&fld("bob-folder", "bob", "Bob request destination"))
        .await
        .unwrap());
    let conflicting_request = UploadRequestRec {
        id: "preexisting-request".into(),
        owner_sub: "bob".into(),
        folder_id: "bob-folder".into(),
        token: "legacy-conflict-token".into(),
        title: "Bob request".into(),
        description: String::new(),
        status: "open".into(),
        expires_at: Some(now + 10_000),
        max_file_bytes: 1024,
        max_total_bytes: 4096,
        max_files: 4,
        used_bytes: 0,
        used_files: 0,
        allowed_types: "*/*".into(),
        created_at: now + 190,
        updated_at: now + 190,
    };
    assert!(store
        .create_upload_request(&conflicting_request)
        .await
        .unwrap());
    let conflicting_folder = FolderRec {
        id: "legacyconflict".into(),
        owner_sub: "alice".into(),
        parent_id: None,
        name: "Conflicting intake".into(),
        created_at: now + 191,
        updated_at: now + 191,
        share_token: None,
        expires_at: None,
        share_password_hash: None,
        upload_token: Some("legacy-conflict-token".into()),
        trashed_at: 0,
        trash_entry_id: None,
        trash_ancestor_id: None,
    };
    assert!(store.create_folder(&conflicting_folder).await.unwrap());
    let conflict = pg
        .migrate()
        .await
        .expect_err("legacy cross-owner token conflict must fail migration");
    assert!(conflict
        .to_string()
        .contains("legacy upload request conflict for folder legacyconflict"));
    assert_eq!(
        store
            .get_folder("legacyconflict", "alice")
            .await
            .unwrap()
            .unwrap()
            .upload_token
            .as_deref(),
        Some("legacy-conflict-token"),
        "failed migration retains the source capability"
    );
    sqlx::query("DELETE FROM upload_requests WHERE id = 'preexisting-request'")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DELETE FROM folders WHERE id = 'bob-folder'")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DELETE FROM folders WHERE id = 'legacyconflict'")
        .execute(&raw)
        .await
        .unwrap();

    // Migration first locks and snapshots every legacy source row. Hold its INSERT in a trigger,
    // then start the current full revoke operation: the folder UPDATE must wait for migration to
    // commit, after which revoke sees and closes the migrated request. This prevents the old torn
    // state where validation skipped a concurrently-cleared source but kept its request open.
    let racing_folder = FolderRec {
        id: "legacyrace".into(),
        owner_sub: "alice".into(),
        parent_id: None,
        name: "Racing legacy intake".into(),
        created_at: now + 195,
        updated_at: now + 195,
        share_token: None,
        expires_at: None,
        share_password_hash: None,
        upload_token: Some("legacy-race-token".into()),
        trashed_at: 0,
        trash_entry_id: None,
        trash_ancestor_id: None,
    };
    assert!(store.create_folder(&racing_folder).await.unwrap());
    sqlx::query(
        "CREATE OR REPLACE FUNCTION aperture_block_legacy_backfill() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN \
           IF NEW.id = 'legacy_legacyrace' THEN \
             PERFORM pg_advisory_xact_lock(7300101); \
           END IF; \
           RETURN NEW; \
         END $$",
    )
    .execute(&raw)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER aperture_block_legacy_backfill_trigger \
         BEFORE INSERT ON upload_requests FOR EACH ROW \
         EXECUTE FUNCTION aperture_block_legacy_backfill()",
    )
    .execute(&raw)
    .await
    .unwrap();
    let mut legacy_barrier = raw.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(7300101)")
        .execute(&mut *legacy_barrier)
        .await
        .unwrap();
    let migrating_store = pg.clone();
    let migrating = tokio::spawn(async move { migrating_store.migrate().await });
    let mut migration_reached_insert = false;
    for _ in 0..200 {
        let blocked: i64 = sqlx::query(
            "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM pg_stat_activity \
             WHERE pid <> pg_backend_pid() AND state = 'active' AND wait_event_type = 'Lock' \
               AND query LIKE '%INSERT INTO upload_requests%'",
        )
        .fetch_one(&raw)
        .await
        .unwrap()
        .try_get("count")
        .unwrap();
        if blocked > 0 {
            migration_reached_insert = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        migration_reached_insert,
        "migration did not reach the controlled legacy INSERT barrier"
    );

    let revoke_store = store.clone();
    let revoking = tokio::spawn(async move {
        let source_token = "legacy-race-token";
        if !revoke_store
            .configure_folder_upload("legacyrace", "alice", None)
            .await
            .map_err(|error| error.to_string())?
        {
            return Err("legacy folder disappeared during revoke".to_string());
        }
        if let Some(request) = revoke_store
            .get_upload_request_by_token(source_token)
            .await
            .map_err(|error| error.to_string())?
        {
            revoke_store
                .set_upload_request_status(&request.id, "alice", "closed", now + 196)
                .await
                .map_err(|error| error.to_string())?;
        }
        for request in revoke_store
            .list_upload_requests("alice")
            .await
            .map_err(|error| error.to_string())?
        {
            if request.folder_id == "legacyrace" && request.is_open() {
                revoke_store
                    .set_upload_request_status(&request.id, "alice", "closed", now + 196)
                    .await
                    .map_err(|error| error.to_string())?;
            }
        }
        Ok::<(), String>(())
    });
    let mut revoke_waited_on_source = false;
    for _ in 0..200 {
        let blocked: i64 = sqlx::query(
            "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM pg_stat_activity \
             WHERE pid <> pg_backend_pid() AND state = 'active' AND wait_event_type = 'Lock' \
               AND query LIKE '%UPDATE folders SET upload_token%'",
        )
        .fetch_one(&raw)
        .await
        .unwrap()
        .try_get("count")
        .unwrap();
        if blocked > 0 {
            revoke_waited_on_source = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        revoke_waited_on_source,
        "revoke did not wait behind the locked legacy source"
    );
    legacy_barrier.rollback().await.unwrap();
    migrating.await.unwrap().expect("locked legacy migration");
    revoking.await.unwrap().expect("serialized legacy revoke");
    let raced_request = store
        .get_upload_request_by_token("legacy-race-token")
        .await
        .unwrap()
        .expect("migration created the deterministic request");
    assert_eq!(raced_request.status, "closed");
    assert!(store
        .get_folder("legacyrace", "alice")
        .await
        .unwrap()
        .unwrap()
        .upload_token
        .is_none());
    sqlx::query("DROP TRIGGER aperture_block_legacy_backfill_trigger ON upload_requests")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION aperture_block_legacy_backfill()")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DELETE FROM upload_requests WHERE id = 'legacy_legacyrace'")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DELETE FROM folders WHERE id = 'legacyrace'")
        .execute(&raw)
        .await
        .unwrap();

    let legacy_folder = FolderRec {
        id: "legacyfold".into(),
        owner_sub: "alice".into(),
        parent_id: None,
        name: "Legacy intake".into(),
        created_at: now + 200,
        updated_at: now + 200,
        share_token: None,
        expires_at: None,
        share_password_hash: None,
        upload_token: Some("legacy-upload-token".into()),
        trashed_at: 0,
        trash_entry_id: None,
        trash_ancestor_id: None,
    };
    assert!(store.create_folder(&legacy_folder).await.unwrap());
    assert!(store
        .get_upload_request_by_token("legacy-upload-token")
        .await
        .unwrap()
        .is_none());
    pg.migrate().await.expect("legacy request backfill");
    let legacy_request = store
        .get_upload_request_by_token("legacy-upload-token")
        .await
        .unwrap()
        .expect("legacy token remains live after migration");
    assert_eq!(legacy_request.folder_id, legacy_folder.id);
    assert_eq!(legacy_request.status, "open");
    assert_eq!(legacy_request.expires_at, None);
    assert!(legacy_request.max_files > 0 && legacy_request.max_total_bytes > 0);
    assert!(store
        .get_folder("legacyfold", "alice")
        .await
        .unwrap()
        .unwrap()
        .upload_token
        .is_none());
    pg.migrate().await.expect("legacy backfill idempotent");
    assert_eq!(
        store
            .list_upload_requests("alice")
            .await
            .unwrap()
            .iter()
            .filter(|request| request.token == "legacy-upload-token")
            .count(),
        1
    );

    let request = |id: &str, token: &str, folder_id: &str, max_files: i64| UploadRequestRec {
        id: id.to_string(),
        owner_sub: "alice".to_string(),
        folder_id: folder_id.to_string(),
        token: token.to_string(),
        title: format!("Request {id}"),
        description: "PG request".to_string(),
        status: "open".to_string(),
        expires_at: Some(now + 10_000),
        max_file_bytes: 1024,
        max_total_bytes: 4096,
        max_files,
        used_bytes: 0,
        used_files: 0,
        allowed_types: "image/*".to_string(),
        created_at: now + 201,
        updated_at: now + 201,
    };
    let single = request("request-one", "request-token-one", "legacyfold", 1);
    assert!(store.create_upload_request(&single).await.unwrap());
    assert_eq!(
        store
            .get_upload_request("request-one", "alice")
            .await
            .unwrap()
            .unwrap(),
        single
    );
    assert!(store
        .get_upload_request("request-one", "bob")
        .await
        .unwrap()
        .is_none());

    // The PostgreSQL Inbox is the same token-free, one-as_of projection as Memory. A dedicated
    // owner keeps exact counts independent from legacy fixtures in this integration database.
    let inbox_as_of = now + 50_000;
    let inbox_folder = FolderRec {
        id: "pg-request-inbox-folder".to_string(),
        owner_sub: "pg-request-inbox-owner".to_string(),
        parent_id: None,
        name: "PG request Inbox".to_string(),
        created_at: inbox_as_of - 10,
        updated_at: inbox_as_of - 10,
        share_token: None,
        expires_at: None,
        share_password_hash: None,
        upload_token: None,
        trashed_at: 0,
        trash_entry_id: None,
        trash_ancestor_id: None,
    };
    assert!(store.create_folder(&inbox_folder).await.unwrap());
    let inbox_request = |id: &str, status: &str, expires_at: Option<i64>| UploadRequestRec {
        id: id.to_string(),
        owner_sub: inbox_folder.owner_sub.clone(),
        folder_id: inbox_folder.id.clone(),
        token: format!("pg-inbox-capability-{id}"),
        title: format!("PG Inbox {id}"),
        description: format!("PG summary {id}"),
        status: status.to_string(),
        expires_at,
        max_file_bytes: 1024,
        max_total_bytes: 4096,
        max_files: 4,
        used_bytes: 1024,
        used_files: 1,
        allowed_types: "*/*".to_string(),
        created_at: inbox_as_of - 2,
        updated_at: inbox_as_of - 1,
    };
    for request in [
        inbox_request(
            "open",
            "open",
            Some(
                inbox_as_of
                    .saturating_add(UPLOAD_REQUEST_EXPIRING_WINDOW_SECS)
                    .saturating_add(1),
            ),
        ),
        inbox_request(
            "expiring",
            "open",
            Some(inbox_as_of.saturating_add(UPLOAD_REQUEST_EXPIRING_WINDOW_SECS)),
        ),
        inbox_request("expired", "open", Some(inbox_as_of)),
        inbox_request("closed", "closed", Some(inbox_as_of - 1)),
    ] {
        assert!(store.create_upload_request(&request).await.unwrap());
    }
    let pg_inbox = store
        .upload_request_inbox(
            &inbox_folder.owner_sub,
            UploadRequestInboxView::All,
            inbox_as_of,
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        pg_inbox.counts,
        UploadRequestInboxCounts {
            all: 4,
            open: 1,
            expiring: 1,
            closed: 1,
            expired: 1,
        }
    );
    assert_eq!(
        pg_inbox
            .items
            .iter()
            .map(|item| item.id.as_str())
            .collect::<Vec<_>>(),
        vec!["open", "expiring", "expired", "closed"],
        "PostgreSQL uses the same updated_at/id ordering as Memory"
    );
    assert_eq!(
        store
            .upload_request_inbox(
                &inbox_folder.owner_sub,
                UploadRequestInboxView::All,
                inbox_as_of,
                None,
            )
            .await
            .unwrap(),
        pg_inbox,
        "the same as_of is stable in one-statement PostgreSQL snapshots"
    );
    let pg_expiring = store
        .upload_request_inbox(
            &inbox_folder.owner_sub,
            UploadRequestInboxView::Expiring,
            inbox_as_of,
            None,
        )
        .await
        .unwrap();
    assert_eq!(pg_expiring.counts, pg_inbox.counts);
    assert_eq!(pg_expiring.matched_total, 1);
    assert_eq!(pg_expiring.items[0].id, "expiring");
    assert!(store
        .upload_request_inbox("alice", UploadRequestInboxView::All, inbox_as_of, None)
        .await
        .unwrap()
        .items
        .iter()
        .all(|item| !item.title.starts_with("PG Inbox")));
    let empty_pg_inbox = store
        .upload_request_inbox(
            "pg-request-inbox-missing-owner",
            UploadRequestInboxView::Expired,
            inbox_as_of,
            None,
        )
        .await
        .unwrap();
    assert_eq!(empty_pg_inbox.counts, UploadRequestInboxCounts::default());
    assert_eq!(empty_pg_inbox.matched_total, 0);
    assert!(empty_pg_inbox.items.is_empty());
    assert!(empty_pg_inbox.next.is_none());

    let cap_folder = FolderRec {
        id: "pg-request-inbox-cap-folder".to_string(),
        owner_sub: "pg-request-inbox-cap-owner".to_string(),
        parent_id: None,
        name: "PG capped request Inbox".to_string(),
        created_at: inbox_as_of,
        updated_at: inbox_as_of,
        share_token: None,
        expires_at: None,
        share_password_hash: None,
        upload_token: None,
        trashed_at: 0,
        trash_entry_id: None,
        trash_ancestor_id: None,
    };
    assert!(store.create_folder(&cap_folder).await.unwrap());
    for index in 0..=100 {
        let id = format!("pg-inbox-cap-{index:03}");
        let mut request = inbox_request(&id, "open", None);
        request.owner_sub = cap_folder.owner_sub.clone();
        request.folder_id = cap_folder.id.clone();
        request.token = format!("pg-inbox-capability-cap-{index:03}");
        request.updated_at = inbox_as_of;
        assert!(store.create_upload_request(&request).await.unwrap());
    }
    let first_capped_pg_inbox = store
        .upload_request_inbox(
            &cap_folder.owner_sub,
            UploadRequestInboxView::All,
            inbox_as_of,
            None,
        )
        .await
        .unwrap();
    assert_eq!(first_capped_pg_inbox.counts.all, 101);
    assert_eq!(first_capped_pg_inbox.matched_total, 101);
    assert_eq!(first_capped_pg_inbox.items.len(), 30);
    assert_eq!(
        first_capped_pg_inbox.items.first().unwrap().id,
        "pg-inbox-cap-100"
    );
    assert_eq!(
        first_capped_pg_inbox.items.last().unwrap().id,
        "pg-inbox-cap-071"
    );

    let mut ids = first_capped_pg_inbox
        .items
        .iter()
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();
    let mut before = first_capped_pg_inbox.next.clone();
    while let Some(cursor) = before {
        let page = store
            .upload_request_inbox(
                &cap_folder.owner_sub,
                UploadRequestInboxView::All,
                inbox_as_of,
                Some(&cursor),
            )
            .await
            .unwrap();
        assert_eq!(page.counts.all, 101);
        assert_eq!(page.matched_total, 101);
        assert!(page.items.len() <= 30);
        ids.extend(page.items.iter().map(|item| item.id.clone()));
        before = page.next;
    }
    let expected = (0..=100)
        .rev()
        .map(|index| format!("pg-inbox-cap-{index:03}"))
        .collect::<Vec<_>>();
    assert_eq!(ids, expected, "PostgreSQL keysets visit tied rows once");

    sqlx::query("DELETE FROM upload_requests WHERE id = $1 AND owner_sub = $2")
        .bind("pg-inbox-cap-070")
        .bind(&cap_folder.owner_sub)
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("UPDATE upload_requests SET updated_at = $1 WHERE id = $2 AND owner_sub = $3")
        .bind(inbox_as_of + 1)
        .bind("pg-inbox-cap-069")
        .bind(&cap_folder.owner_sub)
        .execute(&raw)
        .await
        .unwrap();
    let changed_second_page = store
        .upload_request_inbox(
            &cap_folder.owner_sub,
            UploadRequestInboxView::All,
            inbox_as_of,
            first_capped_pg_inbox.next.as_ref(),
        )
        .await
        .unwrap();
    assert_eq!(changed_second_page.counts.all, 99);
    assert_eq!(changed_second_page.matched_total, 99);
    assert_eq!(
        changed_second_page.items.first().unwrap().id,
        "pg-inbox-cap-068"
    );
    assert!(changed_second_page
        .items
        .iter()
        .all(|item| item.id != "pg-inbox-cap-070" && item.id != "pg-inbox-cap-069"));
    assert!(first_capped_pg_inbox
        .items
        .iter()
        .all(|left| changed_second_page
            .items
            .iter()
            .all(|right| left.id != right.id)));

    let rotate_request = request(
        "request-rotate",
        "request-token-before-rotate",
        "legacyfold",
        2,
    );
    assert!(store.create_upload_request(&rotate_request).await.unwrap());
    assert!(store
        .rotate_upload_request_token(
            "request-rotate",
            "alice",
            "request-token-before-rotate",
            "request-token-after-rotate",
            now + 202,
        )
        .await
        .unwrap());
    assert_eq!(
        store
            .reserve_request_upload(UploadReserveInput {
                request_id: "request-rotate",
                expected_token: "request-token-before-rotate",
                reservation_id: "pg-old-token",
                size: 10,
                content_type: "image/png",
                content_type_verified: true,
                owner_quota: None,
                now: now + 202,
            })
            .await
            .unwrap(),
        UploadReserve::Unavailable
    );

    // Rotation is an expected-token compare-and-swap: two stale owner forms cannot both win.
    let left = store.clone();
    let right = store.clone();
    let (left_rotated, right_rotated) = tokio::join!(
        left.rotate_upload_request_token(
            "request-rotate",
            "alice",
            "request-token-after-rotate",
            "request-token-left",
            now + 203,
        ),
        right.rotate_upload_request_token(
            "request-rotate",
            "alice",
            "request-token-after-rotate",
            "request-token-right",
            now + 203,
        )
    );
    assert_eq!(
        [left_rotated.unwrap(), right_rotated.unwrap()]
            .into_iter()
            .filter(|rotated| *rotated)
            .count(),
        1
    );
    let rotated_token = store
        .get_upload_request("request-rotate", "alice")
        .await
        .unwrap()
        .unwrap()
        .token;
    assert!(matches!(
        rotated_token.as_str(),
        "request-token-left" | "request-token-right"
    ));

    // Reopen mutates only lifecycle columns, so it cannot restore a stale policy snapshot.
    let mut expired = request("request-reopen", "request-token-reopen", "legacyfold", 2);
    expired.status = "closed".to_string();
    expired.expires_at = Some(now - 1);
    assert!(store.create_upload_request(&expired).await.unwrap());
    let mut new_policy = expired.clone();
    new_policy.title = "Concurrent PG policy".to_string();
    new_policy.description = "survives reopen".to_string();
    new_policy.max_total_bytes = 8192;
    new_policy.max_files = 8;
    new_policy.allowed_types = "application/pdf".to_string();
    new_policy.expires_at = Some(now + 5_000);
    new_policy.updated_at = now + 204;
    let left = store.clone();
    let right = store.clone();
    let (updated, reopened) = tokio::join!(
        left.update_upload_request(&new_policy),
        right.reopen_upload_request("request-reopen", "alice", now + 204, now + 10_000),
    );
    assert!(updated.unwrap());
    assert!(reopened.unwrap());
    let reopened = store
        .get_upload_request("request-reopen", "alice")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reopened.title, "Concurrent PG policy");
    assert_eq!(reopened.description, "survives reopen");
    assert_eq!(reopened.max_total_bytes, 8192);
    assert_eq!(reopened.max_files, 8);
    assert_eq!(reopened.allowed_types, "application/pdf");
    assert_eq!(reopened.status, "open");
    assert!(reopened.expires_at.is_some_and(|expiry| expiry > now));

    // Same-room row locking: exactly one of two concurrent reservations can consume max_files=1.
    let left = store.clone();
    let right = store.clone();
    let (a, b) = tokio::join!(
        left.reserve_request_upload(UploadReserveInput {
            request_id: "request-one",
            expected_token: "request-token-one",
            reservation_id: "pg-reserve-a",
            size: 10,
            content_type: "image/png",
            content_type_verified: true,
            owner_quota: None,
            now: now + 202,
        }),
        right.reserve_request_upload(UploadReserveInput {
            request_id: "request-one",
            expected_token: "request-token-one",
            reservation_id: "pg-reserve-b",
            size: 10,
            content_type: "image/png",
            content_type_verified: true,
            owner_quota: None,
            now: now + 202,
        })
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert_eq!(
        [a, b]
            .into_iter()
            .filter(|outcome| *outcome == UploadReserve::Reserved)
            .count(),
        1
    );
    assert!(matches!(
        [a, b]
            .into_iter()
            .find(|outcome| *outcome != UploadReserve::Reserved),
        Some(UploadReserve::FileCountExceeded)
    ));
    let winner = if a == UploadReserve::Reserved {
        "pg-reserve-a"
    } else {
        "pg-reserve-b"
    };
    assert!(store.release_request_upload(winner).await.unwrap());

    // Forced reservation-id collision with a controlled INSERT barrier. Reserve holds the request
    // row while waiting in the trigger; release must wait on that same request BEFORE touching the
    // existing reservation. The old reservation -> request order formed a real PostgreSQL deadlock
    // once the INSERT resumed and waited on the reservation row.
    let lock_order_room = request(
        "request-lock-order",
        "request-token-lock-order",
        "legacyfold",
        5,
    );
    assert!(store.create_upload_request(&lock_order_room).await.unwrap());
    assert_eq!(
        store
            .reserve_request_upload(UploadReserveInput {
                request_id: "request-lock-order",
                expected_token: "request-token-lock-order",
                reservation_id: "forced-deadlock",
                size: 10,
                content_type: "image/png",
                content_type_verified: true,
                owner_quota: None,
                now: now + 202,
            })
            .await
            .unwrap(),
        UploadReserve::Reserved
    );
    sqlx::query(
        "CREATE OR REPLACE FUNCTION aperture_block_reservation_insert() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN \
           IF NEW.id = 'forced-deadlock' THEN \
             PERFORM pg_advisory_xact_lock(7300102); \
           END IF; \
           RETURN NEW; \
         END $$",
    )
    .execute(&raw)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER aperture_block_reservation_insert_trigger \
         BEFORE INSERT ON upload_reservations FOR EACH ROW \
         EXECUTE FUNCTION aperture_block_reservation_insert()",
    )
    .execute(&raw)
    .await
    .unwrap();
    let mut insert_barrier = raw.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(7300102)")
        .execute(&mut *insert_barrier)
        .await
        .unwrap();
    let reserve_store = store.clone();
    let colliding_reserve = tokio::spawn(async move {
        reserve_store
            .reserve_request_upload(UploadReserveInput {
                request_id: "request-lock-order",
                expected_token: "request-token-lock-order",
                reservation_id: "forced-deadlock",
                size: 10,
                content_type: "image/png",
                content_type_verified: true,
                owner_quota: None,
                now: now + 203,
            })
            .await
    });
    let mut reserve_reached_insert = false;
    for _ in 0..200 {
        let blocked: i64 = sqlx::query(
            "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM pg_stat_activity \
             WHERE pid <> pg_backend_pid() AND state = 'active' AND wait_event_type = 'Lock' \
               AND query LIKE '%INSERT INTO upload_reservations%'",
        )
        .fetch_one(&raw)
        .await
        .unwrap()
        .try_get("count")
        .unwrap();
        if blocked > 0 {
            reserve_reached_insert = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        reserve_reached_insert,
        "colliding reserve did not reach the controlled INSERT barrier"
    );
    let release_store = store.clone();
    let releasing = tokio::spawn(async move {
        release_store
            .release_request_upload("forced-deadlock")
            .await
    });
    let mut release_waited_on_request = false;
    for _ in 0..200 {
        let blocked: i64 = sqlx::query(
            "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM pg_stat_activity \
             WHERE pid <> pg_backend_pid() AND state = 'active' AND wait_event_type = 'Lock' \
               AND query LIKE '%SELECT id FROM upload_requests WHERE id%'",
        )
        .fetch_one(&raw)
        .await
        .unwrap()
        .try_get("count")
        .unwrap();
        if blocked > 0 {
            release_waited_on_request = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        release_waited_on_request,
        "release touched the reservation before waiting on the request lock"
    );
    insert_barrier.rollback().await.unwrap();
    let reserve_result = tokio::time::timeout(Duration::from_secs(5), colliding_reserve)
        .await
        .expect("colliding reserve timed out")
        .unwrap()
        .unwrap();
    let release_result = tokio::time::timeout(Duration::from_secs(5), releasing)
        .await
        .expect("release timed out")
        .unwrap()
        .unwrap();
    assert_eq!(reserve_result, UploadReserve::Collision);
    assert!(release_result);
    sqlx::query("DROP TRIGGER aperture_block_reservation_insert_trigger ON upload_reservations")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION aperture_block_reservation_insert()")
        .execute(&raw)
        .await
        .unwrap();

    // Owner guard locking spans DIFFERENT request rows. With only 10 bytes of global headroom,
    // one room reserves and the other observes that reservation and fails closed.
    let room_a = request("request-room-a", "request-token-a", "legacyfold", 5);
    let room_b = request("request-room-b", "request-token-b", "legacyfold", 5);
    assert!(store.create_upload_request(&room_a).await.unwrap());
    assert!(store.create_upload_request(&room_b).await.unwrap());
    let used_before = store.usage_for_owner("alice").await.unwrap();
    let quota = used_before + 10;
    let left = store.clone();
    let right = store.clone();
    let (a, b) = tokio::join!(
        left.reserve_request_upload(UploadReserveInput {
            request_id: "request-room-a",
            expected_token: "request-token-a",
            reservation_id: "pg-owner-a",
            size: 10,
            content_type: "image/png",
            content_type_verified: true,
            owner_quota: Some(quota),
            now: now + 203,
        }),
        right.reserve_request_upload(UploadReserveInput {
            request_id: "request-room-b",
            expected_token: "request-token-b",
            reservation_id: "pg-owner-b",
            size: 10,
            content_type: "image/png",
            content_type_verified: true,
            owner_quota: Some(quota),
            now: now + 203,
        })
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert_eq!(
        [a, b]
            .into_iter()
            .filter(|outcome| *outcome == UploadReserve::Reserved)
            .count(),
        1
    );
    assert!(matches!(
        [a, b]
            .into_iter()
            .find(|outcome| *outcome != UploadReserve::Reserved),
        Some(UploadReserve::OwnerQuotaExceeded)
    ));
    let winner = if a == UploadReserve::Reserved {
        "pg-owner-a"
    } else {
        "pg-owner-b"
    };
    assert!(store.release_request_upload(winner).await.unwrap());

    // Controlled READ COMMITTED interleaving: reserve B finishes its files SUM, then blocks on the
    // versions table. Commit A must wait on the same owner guard; otherwise A can move from
    // reservations to files between B's separate snapshots and disappear from both quota sums.
    let transition_room = request(
        "request-transition-a",
        "request-token-transition-a",
        "legacyfold",
        5,
    );
    assert!(store.create_upload_request(&transition_room).await.unwrap());
    let transition_quota = store.usage_for_owner("alice").await.unwrap() + 10;
    assert_eq!(
        store
            .reserve_request_upload(UploadReserveInput {
                request_id: "request-transition-a",
                expected_token: "request-token-transition-a",
                reservation_id: "quota-transition-a",
                size: 10,
                content_type: "image/png",
                content_type_verified: true,
                owner_quota: None,
                now: now + 204,
            })
            .await
            .unwrap(),
        UploadReserve::Reserved
    );
    let mut transition_file = file(
        "quota-transition-a",
        "alice",
        "unused-transition-token",
        now + 204,
    );
    transition_file.share_token = None;
    transition_file.folder_id = Some("legacyfold".to_string());
    transition_file.size = 10;
    let transition_submission = UploadSubmission {
        id: "quota-transition-receipt".to_string(),
        request_id: "request-transition-a".to_string(),
        delivery_id: None,
        file_id: transition_file.id.clone(),
        name: transition_file.name.clone(),
        content_type: transition_file.content_type.clone(),
        size: transition_file.size,
        created_at: now + 204,
    };

    let mut versions_lock = raw.begin().await.unwrap();
    sqlx::query("LOCK TABLE file_versions IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *versions_lock)
        .await
        .unwrap();
    let reserve_store = store.clone();
    let reserve_b = tokio::spawn(async move {
        reserve_store
            .reserve_request_upload(UploadReserveInput {
                request_id: "request-room-b",
                expected_token: "request-token-b",
                reservation_id: "quota-transition-b",
                size: 1,
                content_type: "image/png",
                content_type_verified: true,
                owner_quota: Some(transition_quota),
                now: now + 204,
            })
            .await
    });
    let mut reached_versions_barrier = false;
    for _ in 0..100 {
        let blocked: i64 = sqlx::query(
            "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM pg_stat_activity \
             WHERE pid <> pg_backend_pid() AND state = 'active' AND wait_event_type = 'Lock' \
               AND query LIKE '%owner_blob_write_intents%'",
        )
        .fetch_one(&raw)
        .await
        .unwrap()
        .try_get("count")
        .unwrap();
        if blocked > 0 {
            reached_versions_barrier = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        reached_versions_barrier,
        "reserve B did not reach the controlled versions snapshot barrier"
    );

    let commit_store = store.clone();
    let commit_a = tokio::spawn(async move {
        commit_store
            .commit_request_upload(
                "quota-transition-a",
                &transition_file,
                &transition_submission,
                None,
                None,
            )
            .await
    });
    let mut commit_waiting_on_guard = false;
    for _ in 0..100 {
        let blocked: i64 = sqlx::query(
            "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM pg_stat_activity \
             WHERE pid <> pg_backend_pid() AND state = 'active' AND wait_event_type = 'Lock' \
               AND query LIKE '%SELECT owner_sub FROM owner_storage_guards%'",
        )
        .fetch_one(&raw)
        .await
        .unwrap()
        .try_get("count")
        .unwrap();
        if blocked > 0 {
            commit_waiting_on_guard = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        commit_waiting_on_guard,
        "public commit did not wait behind the in-flight owner quota decision"
    );
    versions_lock.rollback().await.unwrap();
    assert_eq!(
        reserve_b.await.unwrap().unwrap(),
        UploadReserve::OwnerQuotaExceeded
    );
    assert!(commit_a.await.unwrap().unwrap());

    // Commit creates the file + immutable owner receipt and consumes (rather than releases) budget.
    assert_eq!(
        store
            .reserve_request_upload(UploadReserveInput {
                request_id: "request-room-a",
                expected_token: "request-token-a",
                reservation_id: "receiptfile",
                size: 5,
                content_type: "image/png",
                content_type_verified: true,
                owner_quota: None,
                now: now + 204,
            })
            .await
            .unwrap(),
        UploadReserve::Reserved
    );
    let mut received = file("receiptfile", "alice", "unused-token", now + 204);
    received.share_token = None;
    received.folder_id = Some("legacyfold".to_string());
    received.size = 5;
    let receipt = UploadSubmission {
        id: "receipt-one".to_string(),
        request_id: "request-room-a".to_string(),
        delivery_id: Some("pg-delivery-one".to_string()),
        file_id: received.id.clone(),
        name: received.name.clone(),
        content_type: received.content_type.clone(),
        size: received.size,
        created_at: now + 204,
    };
    let raw_receipt_capability = "a".repeat(64);
    let delivery = UploadDelivery {
        id: "pg-delivery-one".to_string(),
        request_id: "request-room-a".to_string(),
        receipt_token_hash: "e".repeat(64),
        created_at: now + 204,
        acknowledged_at: None,
        receipt_expires_at: now + 30 * 24 * 60 * 60,
    };
    let mut wrong_blob = received.clone();
    wrong_blob.object_key = "wrong-receipt-object".to_string();
    assert!(!store
        .commit_request_upload("receiptfile", &wrong_blob, &receipt, Some(&delivery), None,)
        .await
        .unwrap());
    assert!(store
        .upload_delivery_by_receipt_hash(&delivery.receipt_token_hash, now + 204)
        .await
        .unwrap()
        .is_none());
    let rolled_back_deliveries: i64 = sqlx::query(
        "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM upload_deliveries \
         WHERE id = 'pg-delivery-one'",
    )
    .fetch_one(&raw)
    .await
    .unwrap()
    .try_get("count")
    .unwrap();
    assert_eq!(rolled_back_deliveries, 0);
    let retained_reservation: i64 = sqlx::query(
        "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM upload_reservations WHERE id = 'receiptfile'",
    )
    .fetch_one(&raw)
    .await
    .unwrap()
    .try_get("count")
    .unwrap();
    assert_eq!(retained_reservation, 1);
    assert!(store
        .commit_request_upload("receiptfile", &received, &receipt, Some(&delivery), None,)
        .await
        .unwrap());
    assert_eq!(
        store
            .list_upload_submissions("request-room-a", "alice")
            .await
            .unwrap(),
        vec![receipt]
    );
    let owner_deliveries = store
        .list_upload_deliveries("request-room-a", "alice")
        .await
        .unwrap();
    assert_eq!(owner_deliveries.len(), 1);
    assert_eq!(owner_deliveries[0].delivery, delivery);
    assert_eq!(owner_deliveries[0].submissions.len(), 1);
    assert!(store
        .list_upload_deliveries("request-room-a", "bob")
        .await
        .unwrap()
        .is_empty());

    let review_request = request(
        "request-review-hold",
        "request-token-review-hold",
        "legacyfold",
        4,
    );
    assert!(store.create_upload_request(&review_request).await.unwrap());
    assert_eq!(
        store
            .reserve_request_upload(UploadReserveInput {
                request_id: &review_request.id,
                expected_token: &review_request.token,
                reservation_id: "review-held-file",
                size: 4,
                content_type: "image/png",
                content_type_verified: true,
                owner_quota: None,
                now: now + 205,
            })
            .await
            .unwrap(),
        UploadReserve::Reserved
    );
    let mut review_file = file(
        "review-held-file",
        "alice",
        "unused-review-share",
        now + 205,
    );
    review_file.share_token = None;
    review_file.folder_id = Some("legacyfold".to_string());
    review_file.size = 4;
    let review_delivery = UploadDelivery {
        id: "review-held-delivery".to_string(),
        request_id: review_request.id.clone(),
        receipt_token_hash: "b".repeat(64),
        created_at: now + 205,
        acknowledged_at: None,
        receipt_expires_at: now + 1000,
    };
    let review_submission = UploadSubmission {
        id: "review-held-submission".to_string(),
        request_id: review_request.id.clone(),
        delivery_id: Some(review_delivery.id.clone()),
        file_id: review_file.id.clone(),
        name: review_file.name.clone(),
        content_type: review_file.content_type.clone(),
        size: review_file.size,
        created_at: now + 205,
    };
    let review_hold = UploadReviewDisposition::held(&review_submission);
    assert!(store
        .commit_request_upload(
            &review_file.id,
            &review_file,
            &review_submission,
            Some(&review_delivery),
            Some(&review_hold),
        )
        .await
        .unwrap());
    let pg_holds = store
        .upload_review_dispositions("alice", std::slice::from_ref(&review_file.id))
        .await
        .unwrap();
    assert_eq!(pg_holds, vec![review_hold.clone()]);
    assert!(store
        .upload_review_dispositions("bob", std::slice::from_ref(&review_file.id))
        .await
        .unwrap()
        .is_empty());
    assert!(
        store
            .upload_review_dispositions("alice", std::slice::from_ref(&received.id))
            .await
            .unwrap()
            .is_empty(),
        "a pre-v9 submission with no disposition stays available"
    );
    let held_reupload_intent = OwnerBlobWriteIntent {
        object_key: "review-held-file-new".into(),
        owner_sub: "alice".into(),
        size: 5,
        kind: OWNER_WRITE_REUPLOAD.into(),
        file_id: review_file.id.clone(),
        folder_id: review_file.folder_id.clone(),
        expected_object_key: Some(review_file.object_key.clone()),
        created_at: now + 206,
        attempts: 0,
    };
    assert_eq!(
        store
            .reserve_owner_blob_write(&held_reupload_intent, None)
            .await
            .unwrap(),
        OwnerBlobCommit::Conflict,
        "reserve rejects same-name replacement while the submission is held"
    );
    sqlx::query(
        "UPDATE upload_submission_dispositions \
         SET disposition_state = 'released', released_at = held_at \
         WHERE submission_id = $1",
    )
    .bind(&review_submission.id)
    .execute(&raw)
    .await
    .unwrap();
    assert_eq!(
        store
            .reserve_owner_blob_write(&held_reupload_intent, None)
            .await
            .unwrap(),
        OwnerBlobCommit::Applied
    );
    sqlx::query(
        "UPDATE upload_submission_dispositions \
         SET disposition_state = 'held', released_at = NULL \
         WHERE submission_id = $1",
    )
    .bind(&review_submission.id)
    .execute(&raw)
    .await
    .unwrap();
    assert_eq!(
        store
            .commit_owner_reupload(OwnerReuploadInput {
                owner_sub: "alice",
                file_id: &review_file.id,
                expected_object_key: &review_file.object_key,
                new_object_key: &held_reupload_intent.object_key,
                new_size: held_reupload_intent.size,
                new_content_type: "image/webp",
                snapshot_id: "review-held-version",
                changed_at: now + 206,
                owner_quota: None,
            })
            .await
            .unwrap(),
        OwnerBlobCommit::Conflict,
        "final CAS rechecks Review Hold after reserve"
    );
    assert_eq!(
        store
            .get(&review_file.id)
            .await
            .unwrap()
            .unwrap()
            .object_key,
        review_file.object_key
    );
    assert!(store
        .list_versions(&review_file.id)
        .await
        .unwrap()
        .is_empty());
    sqlx::query("DELETE FROM owner_blob_write_intents WHERE object_key = $1")
        .bind(&held_reupload_intent.object_key)
        .execute(&raw)
        .await
        .unwrap();
    assert_eq!(
        store
            .bulk_trash(
                "alice",
                &[TrashRootInput {
                    item: DriveItemRef {
                        kind: LibraryItemKind::File,
                        id: review_file.id.clone(),
                    },
                    entry_id: "review-held-trash".to_string(),
                }],
                now + 206,
                now + 10_000,
            )
            .await
            .unwrap(),
        BulkMutation::Applied { changed: 1 }
    );
    assert_eq!(
        store
            .bulk_restore(
                "alice",
                &[DriveItemRef {
                    kind: LibraryItemKind::File,
                    id: review_file.id.clone(),
                }],
            )
            .await
            .unwrap(),
        BulkMutation::Conflict
    );
    assert!(!store
        .release_upload_review_hold(&review_request.id, &review_submission.id, "bob", now + 206,)
        .await
        .unwrap());
    for released_at in [now + 207, now + 999] {
        assert!(store
            .release_upload_review_hold(
                &review_request.id,
                &review_submission.id,
                "alice",
                released_at,
            )
            .await
            .unwrap());
    }
    let released = store
        .upload_review_dispositions("alice", std::slice::from_ref(&review_file.id))
        .await
        .unwrap();
    assert_eq!(released[0].state, UploadReviewDispositionState::Released);
    assert_eq!(released[0].released_at, Some(now + 207));
    assert_eq!(
        store
            .bulk_restore(
                "alice",
                &[DriveItemRef {
                    kind: LibraryItemKind::File,
                    id: review_file.id.clone(),
                }],
            )
            .await
            .unwrap(),
        BulkMutation::Applied { changed: 1 }
    );

    assert_eq!(
        store
            .reserve_request_upload(UploadReserveInput {
                request_id: &review_request.id,
                expected_token: &review_request.token,
                reservation_id: "review-rollback-file",
                size: 5,
                content_type: "image/png",
                content_type_verified: true,
                owner_quota: None,
                now: now + 207,
            })
            .await
            .unwrap(),
        UploadReserve::Reserved
    );
    let mut rollback_file = review_file.clone();
    rollback_file.id = "review-rollback-file".to_string();
    rollback_file.object_key = rollback_file.id.clone();
    rollback_file.name = "rollback.png".to_string();
    rollback_file.size = 5;
    rollback_file.created_at = now + 207;
    rollback_file.updated_at = now + 207;
    let rollback_delivery = UploadDelivery {
        id: "review-rollback-delivery".to_string(),
        request_id: review_request.id.clone(),
        receipt_token_hash: "c".repeat(64),
        created_at: now + 207,
        acknowledged_at: None,
        receipt_expires_at: now + 1000,
    };
    let rollback_submission = UploadSubmission {
        id: "review-rollback-submission".to_string(),
        request_id: review_request.id.clone(),
        delivery_id: Some(rollback_delivery.id.clone()),
        file_id: rollback_file.id.clone(),
        name: rollback_file.name.clone(),
        content_type: rollback_file.content_type.clone(),
        size: rollback_file.size,
        created_at: now + 207,
    };
    let rollback_hold = UploadReviewDisposition::held(&rollback_submission);
    sqlx::query(
        "CREATE OR REPLACE FUNCTION aperture_fail_review_disposition() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected disposition failure'; END $$",
    )
    .execute(&raw)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER aperture_fail_review_disposition_trigger \
         BEFORE INSERT ON upload_submission_dispositions FOR EACH ROW \
         EXECUTE FUNCTION aperture_fail_review_disposition()",
    )
    .execute(&raw)
    .await
    .unwrap();
    assert!(store
        .commit_request_upload(
            &rollback_file.id,
            &rollback_file,
            &rollback_submission,
            Some(&rollback_delivery),
            Some(&rollback_hold),
        )
        .await
        .is_err());
    sqlx::query(
        "DROP TRIGGER aperture_fail_review_disposition_trigger \
         ON upload_submission_dispositions",
    )
    .execute(&raw)
    .await
    .unwrap();
    sqlx::query("DROP FUNCTION aperture_fail_review_disposition()")
        .execute(&raw)
        .await
        .unwrap();
    for (table, column, id) in [
        ("files", "id", rollback_file.id.as_str()),
        ("upload_submissions", "id", rollback_submission.id.as_str()),
        ("upload_deliveries", "id", rollback_delivery.id.as_str()),
        (
            "upload_submission_dispositions",
            "submission_id",
            rollback_submission.id.as_str(),
        ),
    ] {
        let count: i64 = sqlx::query(&format!(
            "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM {table} WHERE {column} = $1"
        ))
        .bind(id)
        .fetch_one(&raw)
        .await
        .unwrap()
        .try_get("count")
        .unwrap();
        assert_eq!(count, 0, "{table} rolled back with disposition failure");
    }
    assert!(store
        .release_request_upload(&rollback_file.id)
        .await
        .unwrap());

    assert!(!store
        .acknowledge_upload_delivery("request-room-a", "pg-delivery-one", "bob", now + 205,)
        .await
        .unwrap());
    assert!(store
        .acknowledge_upload_delivery("request-room-a", "pg-delivery-one", "alice", now + 205,)
        .await
        .unwrap());
    assert!(store
        .acknowledge_upload_delivery("request-room-a", "pg-delivery-one", "alice", now + 206,)
        .await
        .unwrap());
    let acknowledged = store
        .upload_delivery_by_receipt_hash(&delivery.receipt_token_hash, now + 206)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(acknowledged.delivery.acknowledged_at, Some(now + 205));

    // A stale public precheck may reserve + write its blob before the owner acknowledges. The
    // transaction is the authority: an append observed after acknowledgement must roll back all
    // metadata, retain its reservation for compensation, and leave the receipt readable.
    assert_eq!(
        store
            .reserve_request_upload(UploadReserveInput {
                request_id: "request-room-a",
                expected_token: "request-token-a",
                reservation_id: "receiptfile-after-ack",
                size: 4,
                content_type: "image/png",
                content_type_verified: true,
                owner_quota: None,
                now: now + 206,
            })
            .await
            .unwrap(),
        UploadReserve::Reserved
    );
    let mut after_ack_file = file(
        "receiptfile-after-ack",
        "alice",
        "unused-after-ack-token",
        now + 206,
    );
    after_ack_file.share_token = None;
    after_ack_file.folder_id = Some("legacyfold".to_string());
    after_ack_file.size = 4;
    let after_ack_submission = UploadSubmission {
        id: "receipt-after-ack".to_string(),
        request_id: "request-room-a".to_string(),
        delivery_id: Some(delivery.id.clone()),
        file_id: after_ack_file.id.clone(),
        name: after_ack_file.name.clone(),
        content_type: after_ack_file.content_type.clone(),
        size: after_ack_file.size,
        created_at: now + 206,
    };
    assert!(!store
        .commit_request_upload(
            &after_ack_file.id,
            &after_ack_file,
            &after_ack_submission,
            None,
            None,
        )
        .await
        .unwrap());
    let rejected_file_count: i64 =
        sqlx::query("SELECT CAST(COUNT(*) AS BIGINT) AS count FROM files WHERE id = $1")
            .bind(&after_ack_file.id)
            .fetch_one(&raw)
            .await
            .unwrap()
            .try_get("count")
            .unwrap();
    assert_eq!(rejected_file_count, 0);
    let rejected_submission_count: i64 = sqlx::query(
        "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM upload_submissions WHERE id = $1",
    )
    .bind(&after_ack_submission.id)
    .fetch_one(&raw)
    .await
    .unwrap()
    .try_get("count")
    .unwrap();
    assert_eq!(rejected_submission_count, 0);
    let retained_after_ack_reservation: i64 = sqlx::query(
        "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM upload_reservations WHERE id = $1",
    )
    .bind(&after_ack_file.id)
    .fetch_one(&raw)
    .await
    .unwrap()
    .try_get("count")
    .unwrap();
    assert_eq!(retained_after_ack_reservation, 1);
    assert!(store
        .release_request_upload(&after_ack_file.id)
        .await
        .unwrap());
    let after_compensation = store
        .get_upload_request("request-room-a", "alice")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after_compensation.used_files, 1);
    assert_eq!(after_compensation.used_bytes, 5);
    let after_rejected_append = store
        .upload_delivery_by_receipt_hash(&delivery.receipt_token_hash, now + 206)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        after_rejected_append.delivery.acknowledged_at,
        Some(now + 205)
    );
    assert_eq!(after_rejected_append.submissions.len(), 1);

    // Exercise the delivery row lock with the real PgStore pool. Whichever operation locks the
    // row first defines one complete serial outcome: append then acknowledge, or acknowledge then
    // a fully rolled-back append. Both must terminate without a lock cycle.
    let ack_race_request = request(
        "request-ack-race",
        "request-token-ack-race",
        "legacyfold",
        3,
    );
    assert!(store
        .create_upload_request(&ack_race_request)
        .await
        .unwrap());
    assert_eq!(
        store
            .reserve_request_upload(UploadReserveInput {
                request_id: &ack_race_request.id,
                expected_token: &ack_race_request.token,
                reservation_id: "ack-race-first",
                size: 5,
                content_type: "image/png",
                content_type_verified: true,
                owner_quota: None,
                now: now + 207,
            })
            .await
            .unwrap(),
        UploadReserve::Reserved
    );
    let mut ack_race_first_file = file(
        "ack-race-first",
        "alice",
        "unused-ack-race-first",
        now + 207,
    );
    ack_race_first_file.share_token = None;
    ack_race_first_file.folder_id = Some("legacyfold".to_string());
    ack_race_first_file.size = 5;
    let ack_race_delivery = UploadDelivery {
        id: "pg-delivery-ack-race".to_string(),
        request_id: ack_race_request.id.clone(),
        receipt_token_hash: "d".repeat(64),
        created_at: now + 207,
        acknowledged_at: None,
        receipt_expires_at: now + 30 * 24 * 60 * 60,
    };
    let ack_race_first_submission = UploadSubmission {
        id: "ack-race-submission-first".to_string(),
        request_id: ack_race_request.id.clone(),
        delivery_id: Some(ack_race_delivery.id.clone()),
        file_id: ack_race_first_file.id.clone(),
        name: ack_race_first_file.name.clone(),
        content_type: ack_race_first_file.content_type.clone(),
        size: ack_race_first_file.size,
        created_at: now + 207,
    };
    assert!(store
        .commit_request_upload(
            &ack_race_first_file.id,
            &ack_race_first_file,
            &ack_race_first_submission,
            Some(&ack_race_delivery),
            None,
        )
        .await
        .unwrap());
    assert_eq!(
        store
            .reserve_request_upload(UploadReserveInput {
                request_id: &ack_race_request.id,
                expected_token: &ack_race_request.token,
                reservation_id: "ack-race-append",
                size: 4,
                content_type: "image/png",
                content_type_verified: true,
                owner_quota: None,
                now: now + 208,
            })
            .await
            .unwrap(),
        UploadReserve::Reserved
    );
    let mut ack_race_append_file = file(
        "ack-race-append",
        "alice",
        "unused-ack-race-append",
        now + 208,
    );
    ack_race_append_file.share_token = None;
    ack_race_append_file.folder_id = Some("legacyfold".to_string());
    ack_race_append_file.size = 4;
    let ack_race_append_submission = UploadSubmission {
        id: "ack-race-submission-append".to_string(),
        request_id: ack_race_request.id.clone(),
        delivery_id: Some(ack_race_delivery.id.clone()),
        file_id: ack_race_append_file.id.clone(),
        name: ack_race_append_file.name.clone(),
        content_type: ack_race_append_file.content_type.clone(),
        size: ack_race_append_file.size,
        created_at: now + 208,
    };
    let commit_store = store.clone();
    let acknowledge_store = store.clone();
    let commit_file = ack_race_append_file.clone();
    let commit_submission = ack_race_append_submission.clone();
    let acknowledge_request_id = ack_race_request.id.clone();
    let acknowledge_delivery_id = ack_race_delivery.id.clone();
    let (committed, race_acknowledged) = tokio::time::timeout(Duration::from_secs(5), async move {
        tokio::join!(
            commit_store.commit_request_upload(
                &commit_file.id,
                &commit_file,
                &commit_submission,
                None,
                None,
            ),
            acknowledge_store.acknowledge_upload_delivery(
                &acknowledge_request_id,
                &acknowledge_delivery_id,
                "alice",
                now + 208,
            )
        )
    })
    .await
    .expect("concurrent append/acknowledge deadlocked");
    let committed = committed.unwrap();
    assert!(race_acknowledged.unwrap());
    if !committed {
        assert!(store
            .release_request_upload(&ack_race_append_file.id)
            .await
            .unwrap());
    }
    let final_race_request = store
        .get_upload_request(&ack_race_request.id, "alice")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(final_race_request.used_files, if committed { 2 } else { 1 });
    assert_eq!(final_race_request.used_bytes, if committed { 9 } else { 5 });
    let final_race_file_count: i64 =
        sqlx::query("SELECT CAST(COUNT(*) AS BIGINT) AS count FROM files WHERE id = $1")
            .bind(&ack_race_append_file.id)
            .fetch_one(&raw)
            .await
            .unwrap()
            .try_get("count")
            .unwrap();
    assert_eq!(final_race_file_count, i64::from(committed));
    let final_race_submission_count: i64 = sqlx::query(
        "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM upload_submissions WHERE id = $1",
    )
    .bind(&ack_race_append_submission.id)
    .fetch_one(&raw)
    .await
    .unwrap()
    .try_get("count")
    .unwrap();
    assert_eq!(final_race_submission_count, i64::from(committed));
    let final_race_reservation_count: i64 = sqlx::query(
        "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM upload_reservations WHERE id = $1",
    )
    .bind(&ack_race_append_file.id)
    .fetch_one(&raw)
    .await
    .unwrap()
    .try_get("count")
    .unwrap();
    assert_eq!(final_race_reservation_count, 0);
    let final_race_receipt = store
        .upload_delivery_by_receipt_hash(&ack_race_delivery.receipt_token_hash, now + 208)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(final_race_receipt.delivery.acknowledged_at, Some(now + 208));
    assert_eq!(
        final_race_receipt.submissions.len(),
        if committed { 2 } else { 1 }
    );
    assert!(store
        .upload_delivery_by_receipt_hash(&delivery.receipt_token_hash, delivery.receipt_expires_at,)
        .await
        .unwrap()
        .is_none());
    let persisted_digest: String =
        sqlx::query("SELECT receipt_token_hash FROM upload_deliveries WHERE id = $1")
            .bind(&delivery.id)
            .fetch_one(&raw)
            .await
            .unwrap()
            .try_get("receipt_token_hash")
            .unwrap();
    assert_eq!(persisted_digest, delivery.receipt_token_hash);
    assert_ne!(persisted_digest, raw_receipt_capability);
    assert!(store
        .set_upload_request_status("request-room-a", "alice", "closed", now + 207,)
        .await
        .unwrap());
    sqlx::query("UPDATE upload_requests SET expires_at = 1 WHERE id = 'request-room-a'")
        .execute(&raw)
        .await
        .unwrap();
    assert!(store
        .upload_delivery_by_receipt_hash(&delivery.receipt_token_hash, now + 207)
        .await
        .unwrap()
        .is_some());
    assert!(store
        .get("receiptfile")
        .await
        .unwrap()
        .unwrap()
        .share_token
        .is_none());
    sqlx::query("DELETE FROM upload_requests WHERE id = 'request-room-a'")
        .execute(&raw)
        .await
        .unwrap();
    assert!(store
        .upload_delivery_by_receipt_hash(&delivery.receipt_token_hash, now + 207)
        .await
        .unwrap()
        .is_none());
    let cascaded_submissions: i64 = sqlx::query(
        "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM upload_submissions \
         WHERE id = 'receipt-one'",
    )
    .fetch_one(&raw)
    .await
    .unwrap()
    .try_get("count")
    .unwrap();
    assert_eq!(cascaded_submissions, 0);

    // Reserve reaches its durable INSERT while holding owner/request/folder locks. Folder purge
    // must wait, then win before commit; commit returns a business conflict and compensation can
    // remove the blob + reservation without a deadlock or stranded budget.
    assert!(store
        .create_folder(&fld("purgereserve", "alice", "Purge reserve race"))
        .await
        .unwrap());
    let purge_reserve_request = request(
        "purge-reserve-request",
        "purge-reserve-token",
        "purgereserve",
        2,
    );
    assert!(store
        .create_upload_request(&purge_reserve_request)
        .await
        .unwrap());
    sqlx::query(
        "CREATE OR REPLACE FUNCTION aperture_block_purge_reserve() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN \
           IF NEW.id = 'purge-reserve-blob' THEN \
             PERFORM pg_advisory_xact_lock(7300103); \
           END IF; \
           RETURN NEW; \
         END $$",
    )
    .execute(&raw)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER aperture_block_purge_reserve_trigger \
         BEFORE INSERT ON upload_reservations FOR EACH ROW \
         EXECUTE FUNCTION aperture_block_purge_reserve()",
    )
    .execute(&raw)
    .await
    .unwrap();
    let mut reserve_barrier = raw.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(7300103)")
        .execute(&mut *reserve_barrier)
        .await
        .unwrap();
    let reserve_store = store.clone();
    let racing_reserve = tokio::spawn(async move {
        reserve_store
            .reserve_request_upload(UploadReserveInput {
                request_id: "purge-reserve-request",
                expected_token: "purge-reserve-token",
                reservation_id: "purge-reserve-blob",
                size: 4,
                content_type: "image/png",
                content_type_verified: true,
                owner_quota: None,
                now: now + 205,
            })
            .await
    });
    let mut reserve_at_barrier = false;
    for _ in 0..200 {
        let blocked: i64 = sqlx::query(
            "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM pg_stat_activity \
             WHERE pid <> pg_backend_pid() AND state = 'active' AND wait_event_type = 'Lock' \
               AND query LIKE '%INSERT INTO upload_reservations%'",
        )
        .fetch_one(&raw)
        .await
        .unwrap()
        .try_get("count")
        .unwrap();
        if blocked > 0 {
            reserve_at_barrier = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        reserve_at_barrier,
        "reserve did not reach its controlled barrier"
    );
    let purge_store = store.clone();
    let purge_after_reserve = tokio::spawn(async move {
        let item = DriveItemRef {
            kind: LibraryItemKind::Folder,
            id: "purgereserve".into(),
        };
        let trashed = purge_store
            .bulk_trash(
                "alice",
                &[TrashRootInput {
                    item: item.clone(),
                    entry_id: "purge-reserve-trash".into(),
                }],
                now + 206,
                now + 10_000,
            )
            .await
            .map_err(|error| error.to_string())?;
        if trashed != (BulkMutation::Applied { changed: 1 }) {
            return Err(format!("unexpected trash result: {trashed:?}"));
        }
        purge_store
            .bulk_purge("alice", &[item], now + 207)
            .await
            .map_err(|error| error.to_string())
    });
    let mut purge_waited_on_guard = false;
    for _ in 0..200 {
        let blocked: i64 = sqlx::query(
            "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM pg_stat_activity \
             WHERE pid <> pg_backend_pid() AND state = 'active' AND wait_event_type = 'Lock' \
               AND query LIKE '%SELECT owner_sub FROM owner_storage_guards%'",
        )
        .fetch_one(&raw)
        .await
        .unwrap()
        .try_get("count")
        .unwrap();
        if blocked > 0 {
            purge_waited_on_guard = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(purge_waited_on_guard, "purge did not wait behind reserve");
    reserve_barrier.rollback().await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), racing_reserve)
            .await
            .expect("reserve timed out")
            .unwrap()
            .unwrap(),
        UploadReserve::Reserved
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), purge_after_reserve)
            .await
            .expect("purge timed out")
            .unwrap()
            .unwrap(),
        BulkMutation::Applied { changed: 1 }
    );
    let race_blobs = Arc::new(MemoryBlobs::new());
    race_blobs
        .put("purge-reserve-blob", vec![1, 2, 3, 4])
        .await
        .unwrap();
    let mut losing_file = file(
        "purge-reserve-blob",
        "alice",
        "unused-purge-reserve-token",
        now + 205,
    );
    losing_file.share_token = None;
    losing_file.folder_id = Some("purgereserve".into());
    losing_file.size = 4;
    let losing_receipt = UploadSubmission {
        id: "purge-reserve-receipt".into(),
        request_id: "purge-reserve-request".into(),
        delivery_id: None,
        file_id: losing_file.id.clone(),
        name: losing_file.name.clone(),
        content_type: losing_file.content_type.clone(),
        size: losing_file.size,
        created_at: now + 205,
    };
    assert!(!store
        .commit_request_upload(
            "purge-reserve-blob",
            &losing_file,
            &losing_receipt,
            None,
            None,
        )
        .await
        .unwrap());
    race_blobs.delete("purge-reserve-blob").await.unwrap();
    assert!(store
        .release_request_upload("purge-reserve-blob")
        .await
        .unwrap());
    let closed = store
        .get_upload_request("purge-reserve-request", "alice")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (closed.status.as_str(), closed.used_files, closed.used_bytes),
        ("closed", 0, 0)
    );
    assert_eq!(race_blobs.object_count(), 0);
    sqlx::query("DROP TRIGGER aperture_block_purge_reserve_trigger ON upload_reservations")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION aperture_block_purge_reserve()")
        .execute(&raw)
        .await
        .unwrap();

    // The opposite winner is also safe: commit holds the canonical locks through file+receipt
    // insertion, purge waits, then discovers every committed key and moves it to the outbox.
    assert!(store
        .create_folder(&fld("purgecommit", "alice", "Purge commit race"))
        .await
        .unwrap());
    let purge_commit_request = request(
        "purge-commit-request",
        "purge-commit-token",
        "purgecommit",
        2,
    );
    assert!(store
        .create_upload_request(&purge_commit_request)
        .await
        .unwrap());
    assert_eq!(
        store
            .reserve_request_upload(UploadReserveInput {
                request_id: "purge-commit-request",
                expected_token: "purge-commit-token",
                reservation_id: "purge-commit-blob",
                size: 4,
                content_type: "image/png",
                content_type_verified: true,
                owner_quota: None,
                now: now + 208,
            })
            .await
            .unwrap(),
        UploadReserve::Reserved
    );
    race_blobs
        .put("purge-commit-blob", vec![5, 6, 7, 8])
        .await
        .unwrap();
    let mut winning_file = file(
        "purge-commit-blob",
        "alice",
        "unused-purge-commit-token",
        now + 208,
    );
    winning_file.share_token = None;
    winning_file.folder_id = Some("purgecommit".into());
    winning_file.size = 4;
    let winning_receipt = UploadSubmission {
        id: "purge-commit-receipt".into(),
        request_id: "purge-commit-request".into(),
        delivery_id: None,
        file_id: winning_file.id.clone(),
        name: winning_file.name.clone(),
        content_type: winning_file.content_type.clone(),
        size: winning_file.size,
        created_at: now + 208,
    };
    sqlx::query(
        "CREATE OR REPLACE FUNCTION aperture_block_purge_commit() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN \
           IF NEW.id = 'purge-commit-blob' THEN \
             PERFORM pg_advisory_xact_lock(7300104); \
           END IF; \
           RETURN NEW; \
         END $$",
    )
    .execute(&raw)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER aperture_block_purge_commit_trigger BEFORE INSERT ON files \
         FOR EACH ROW EXECUTE FUNCTION aperture_block_purge_commit()",
    )
    .execute(&raw)
    .await
    .unwrap();
    let mut commit_barrier = raw.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(7300104)")
        .execute(&mut *commit_barrier)
        .await
        .unwrap();
    let commit_store = store.clone();
    let committing = tokio::spawn(async move {
        commit_store
            .commit_request_upload(
                "purge-commit-blob",
                &winning_file,
                &winning_receipt,
                None,
                None,
            )
            .await
    });
    let mut commit_at_barrier = false;
    for _ in 0..200 {
        let blocked: i64 = sqlx::query(
            "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM pg_stat_activity \
             WHERE pid <> pg_backend_pid() AND state = 'active' AND wait_event_type = 'Lock' \
               AND query LIKE '%INSERT INTO files%'",
        )
        .fetch_one(&raw)
        .await
        .unwrap()
        .try_get("count")
        .unwrap();
        if blocked > 0 {
            commit_at_barrier = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        commit_at_barrier,
        "commit did not reach its controlled barrier"
    );
    let purge_store = store.clone();
    let purge_after_commit = tokio::spawn(async move {
        let item = DriveItemRef {
            kind: LibraryItemKind::Folder,
            id: "purgecommit".into(),
        };
        let trashed = purge_store
            .bulk_trash(
                "alice",
                &[TrashRootInput {
                    item: item.clone(),
                    entry_id: "purge-commit-trash".into(),
                }],
                now + 209,
                now + 10_000,
            )
            .await
            .map_err(|error| error.to_string())?;
        if trashed != (BulkMutation::Applied { changed: 1 }) {
            return Err(format!("unexpected trash result: {trashed:?}"));
        }
        purge_store
            .bulk_purge("alice", &[item], now + 210)
            .await
            .map_err(|error| error.to_string())
    });
    let mut purge_waited_on_commit = false;
    for _ in 0..200 {
        let blocked: i64 = sqlx::query(
            "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM pg_stat_activity \
             WHERE pid <> pg_backend_pid() AND state = 'active' AND wait_event_type = 'Lock' \
               AND query LIKE '%SELECT owner_sub FROM owner_storage_guards%'",
        )
        .fetch_one(&raw)
        .await
        .unwrap()
        .try_get("count")
        .unwrap();
        if blocked > 0 {
            purge_waited_on_commit = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(purge_waited_on_commit, "purge did not wait behind commit");
    commit_barrier.rollback().await.unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(5), committing)
        .await
        .expect("commit timed out")
        .unwrap()
        .unwrap());
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), purge_after_commit)
            .await
            .expect("purge timed out")
            .unwrap()
            .unwrap(),
        BulkMutation::Applied { changed: 1 }
    );
    assert!(store.get("purge-commit-blob").await.unwrap().is_none());
    aperture::drain_trash_lifecycle_once(store.as_ref(), race_blobs.as_ref(), now + 211)
        .await
        .unwrap();
    assert_eq!(race_blobs.object_count(), 0);
    sqlx::query("DROP TRIGGER aperture_block_purge_commit_trigger ON files")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION aperture_block_purge_commit()")
        .execute(&raw)
        .await
        .unwrap();

    // A real DB failure after the blob write triggers handler compensation: blob deleted,
    // reservation/counters released, no file row and no receipt, with a fixed public 500 shell.
    let db_fail = request("request-db-fail", "request-token-db-fail", "legacyfold", 5);
    assert!(store.create_upload_request(&db_fail).await.unwrap());
    sqlx::query(
        "CREATE OR REPLACE FUNCTION aperture_fail_request_receipt() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected receipt failure'; END $$",
    )
    .execute(&raw)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER aperture_fail_request_receipt_trigger \
         BEFORE INSERT ON upload_submissions FOR EACH ROW \
         EXECUTE FUNCTION aperture_fail_request_receipt()",
    )
    .execute(&raw)
    .await
    .unwrap();
    {
        let blobs = Arc::new(MemoryBlobs::new());
        let state = AppState {
            config: build_dev_state().config,
            store: store.clone(),
            blobs: blobs.clone(),
            audit: aperture::audit::AuditSink::disabled(),
        };
        let request_app = app(state);
        let page = request_app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/u/request-token-db-fail")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(page.status(), axum::http::StatusCode::OK);
        let cookie = page
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let csrf = cookie.trim_start_matches("__Host-csrf=");
        let boundary = "----aperturePgFailureBoundary";
        let mut multipart = Vec::new();
        multipart.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"csrf_token\"\r\n\r\n{csrf}\r\n"
            )
            .as_bytes(),
        );
        multipart.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"db-fail.png\"\r\nContent-Type: image/png\r\n\r\n"
            )
            .as_bytes(),
        );
        multipart.extend_from_slice(&[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1]);
        multipart.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let failed = request_app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/u/request-token-db-fail")
                    .header(
                        axum::http::header::CONTENT_TYPE,
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .header(axum::http::header::COOKIE, cookie)
                    .body(axum::body::Body::from(multipart))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            failed.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
        let failed_body = axum::body::to_bytes(failed.into_body(), usize::MAX)
            .await
            .unwrap();
        let failed_text = String::from_utf8_lossy(&failed_body);
        assert!(failed_text.contains("Aperture could not complete this request"));
        assert!(!failed_text.contains("injected receipt failure"));
        assert_eq!(blobs.object_count(), 0, "compensation deletes the blob");
    }
    sqlx::query("DROP TRIGGER aperture_fail_request_receipt_trigger ON upload_submissions")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION aperture_fail_request_receipt()")
        .execute(&raw)
        .await
        .unwrap();
    let after_db_failure = store
        .get_upload_request("request-db-fail", "alice")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (after_db_failure.used_files, after_db_failure.used_bytes),
        (0, 0)
    );
    assert!(store
        .list_upload_submissions("request-db-fail", "alice")
        .await
        .unwrap()
        .is_empty());
    let failed_files: i64 = sqlx::query(
        "SELECT count(*) AS n FROM files WHERE name = 'db-fail.png' OR id IN \
         (SELECT id FROM upload_reservations WHERE request_id = 'request-db-fail')",
    )
    .fetch_one(&raw)
    .await
    .unwrap()
    .try_get("n")
    .unwrap();
    assert_eq!(failed_files, 0);

    // A simulated crash after the blob write leaves both an object and a reservation. Startup
    // recovery deletes bytes first, then returns counters and clears the durable row.
    assert_eq!(
        store
            .reserve_request_upload(UploadReserveInput {
                request_id: "request-room-b",
                expected_token: "request-token-b",
                reservation_id: "stale-reservation",
                size: 7,
                content_type: "image/png",
                content_type_verified: true,
                owner_quota: None,
                now: now + 205,
            })
            .await
            .unwrap(),
        UploadReserve::Reserved
    );
    assert_eq!(
        store
            .get_upload_request("request-room-b", "alice")
            .await
            .unwrap()
            .unwrap()
            .used_files,
        1
    );
    let recovery_blobs = Arc::new(MemoryBlobs::new());
    recovery_blobs
        .put("stale-reservation", vec![1, 2, 3])
        .await
        .unwrap();
    recover_stale_request_uploads(store.as_ref(), recovery_blobs.as_ref())
        .await
        .expect("startup reservation recovery");
    assert_eq!(
        recovery_blobs.object_count(),
        0,
        "crash-after-put blob is removed"
    );
    let recovered = store
        .get_upload_request("request-room-b", "alice")
        .await
        .unwrap()
        .unwrap();
    assert_eq!((recovered.used_files, recovered.used_bytes), (0, 0));
    let stale_count: i64 = sqlx::query("SELECT count(*) AS n FROM upload_reservations")
        .fetch_one(&raw)
        .await
        .unwrap()
        .try_get("n")
        .unwrap();
    assert_eq!(stale_count, 0);

    // A blob backend failure fails startup but abandons the lease without changing counters, so a
    // subsequent healthy startup can retry the same object and reservation.
    assert_eq!(
        store
            .reserve_request_upload(UploadReserveInput {
                request_id: "request-room-b",
                expected_token: "request-token-b",
                reservation_id: "stale-delete-failure",
                size: 7,
                content_type: "image/png",
                content_type_verified: true,
                owner_quota: None,
                now: now + 206,
            })
            .await
            .unwrap(),
        UploadReserve::Reserved
    );
    let retry_blobs = Arc::new(MemoryBlobs::new());
    retry_blobs
        .put("stale-delete-failure", vec![4, 5, 6])
        .await
        .unwrap();
    let failure = recover_stale_request_uploads(
        store.as_ref(),
        &FailingRecoveryDelete {
            inner: retry_blobs.clone(),
        },
    )
    .await
    .expect_err("blob delete failure must fail startup");
    assert!(failure.contains("injected recovery delete failure"));
    assert_eq!(retry_blobs.object_count(), 1);
    let failed_recovery = store
        .get_upload_request("request-room-b", "alice")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (failed_recovery.used_files, failed_recovery.used_bytes),
        (1, 7)
    );
    let lease: Option<String> = sqlx::query(
        "SELECT recovery_lease FROM upload_reservations WHERE id = 'stale-delete-failure'",
    )
    .fetch_one(&raw)
    .await
    .unwrap()
    .try_get("recovery_lease")
    .unwrap();
    assert!(lease.is_none(), "failed recovery releases its lease");
    recover_stale_request_uploads(store.as_ref(), retry_blobs.as_ref())
        .await
        .expect("healthy recovery retries abandoned lease");
    assert_eq!(retry_blobs.object_count(), 0);

    // Two simultaneous startups may delete an idempotent blob at most once each, but the lease
    // predicate makes reservation removal/counter release exactly-once.
    assert_eq!(
        store
            .reserve_request_upload(UploadReserveInput {
                request_id: "request-room-b",
                expected_token: "request-token-b",
                reservation_id: "stale-concurrent",
                size: 9,
                content_type: "image/png",
                content_type_verified: true,
                owner_quota: None,
                now: now + 207,
            })
            .await
            .unwrap(),
        UploadReserve::Reserved
    );
    let concurrent_blobs = Arc::new(MemoryBlobs::new());
    concurrent_blobs
        .put("stale-concurrent", vec![7, 8, 9])
        .await
        .unwrap();
    let left_store = store.clone();
    let right_store = store.clone();
    let left_blobs = concurrent_blobs.clone();
    let right_blobs = concurrent_blobs.clone();
    let (left, right) = tokio::join!(
        async move { recover_stale_request_uploads(left_store.as_ref(), left_blobs.as_ref()).await },
        async move { recover_stale_request_uploads(right_store.as_ref(), right_blobs.as_ref()).await }
    );
    assert!(left.is_ok() || right.is_ok());
    for error in [left.err(), right.err()].into_iter().flatten() {
        assert!(
            error.contains("already leased"),
            "unexpected error: {error}"
        );
    }
    assert_eq!(concurrent_blobs.object_count(), 0);
    let concurrent_recovered = store
        .get_upload_request("request-room-b", "alice")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            concurrent_recovered.used_files,
            concurrent_recovered.used_bytes
        ),
        (0, 0)
    );
    let remaining_recovery_rows: i64 = sqlx::query("SELECT count(*) AS n FROM upload_reservations")
        .fetch_one(&raw)
        .await
        .unwrap()
        .try_get("n")
        .unwrap();
    assert_eq!(remaining_recovery_rows, 0);

    // A partial abandon failure can leave one old lease beside one unleased row. The next startup
    // must claim neither and return Busy; it may not clean the available subset and start serving.
    for (id, size) in [("mixed-abandon-a", 3_i64), ("mixed-abandon-b", 4_i64)] {
        assert_eq!(
            store
                .reserve_request_upload(UploadReserveInput {
                    request_id: "request-room-b",
                    expected_token: "request-token-b",
                    reservation_id: id,
                    size,
                    content_type: "image/png",
                    content_type_verified: true,
                    owner_quota: None,
                    now: now + 208,
                })
                .await
                .unwrap(),
            UploadReserve::Reserved
        );
    }
    let mixed_blobs = Arc::new(MemoryBlobs::new());
    mixed_blobs.put("mixed-abandon-a", vec![1]).await.unwrap();
    mixed_blobs.put("mixed-abandon-b", vec![2]).await.unwrap();
    sqlx::query(
        "CREATE OR REPLACE FUNCTION aperture_fail_recovery_abandon() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN \
           IF OLD.id = 'mixed-abandon-a' AND OLD.recovery_lease IS NOT NULL \
              AND NEW.recovery_lease IS NULL THEN \
             RAISE EXCEPTION 'injected abandon failure'; \
           END IF; \
           RETURN NEW; \
         END $$",
    )
    .execute(&raw)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER aperture_fail_recovery_abandon_trigger \
         BEFORE UPDATE ON upload_reservations FOR EACH ROW \
         EXECUTE FUNCTION aperture_fail_recovery_abandon()",
    )
    .execute(&raw)
    .await
    .unwrap();
    let failed = recover_stale_request_uploads(
        store.as_ref(),
        &FailingRecoveryDelete {
            inner: mixed_blobs.clone(),
        },
    )
    .await
    .expect_err("injected delete failure starts the partial-abandon path");
    assert!(failed.contains("injected recovery delete failure"));
    sqlx::query("DROP TRIGGER aperture_fail_recovery_abandon_trigger ON upload_reservations")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION aperture_fail_recovery_abandon()")
        .execute(&raw)
        .await
        .unwrap();

    let mixed_rows = sqlx::query(
        "SELECT id, recovery_lease FROM upload_reservations \
         WHERE id IN ('mixed-abandon-a', 'mixed-abandon-b') ORDER BY id ASC",
    )
    .fetch_all(&raw)
    .await
    .unwrap();
    assert_eq!(mixed_rows.len(), 2);
    assert!(mixed_rows[0]
        .try_get::<Option<String>, _>("recovery_lease")
        .unwrap()
        .is_some());
    assert!(mixed_rows[1]
        .try_get::<Option<String>, _>("recovery_lease")
        .unwrap()
        .is_none());
    let claim_now = now_secs();
    assert_eq!(
        store
            .claim_upload_recovery(
                "mixed-next-startup",
                claim_now,
                claim_now.saturating_sub(5 * 60),
            )
            .await
            .unwrap(),
        UploadRecoveryClaim::Busy
    );
    let still_unclaimed: Option<String> =
        sqlx::query("SELECT recovery_lease FROM upload_reservations WHERE id = 'mixed-abandon-b'")
            .fetch_one(&raw)
            .await
            .unwrap()
            .try_get("recovery_lease")
            .unwrap();
    assert!(still_unclaimed.is_none(), "partial claim is rolled back");

    sqlx::query(
        "UPDATE upload_reservations SET recovery_lease = NULL, recovery_leased_at = NULL \
         WHERE id IN ('mixed-abandon-a', 'mixed-abandon-b')",
    )
    .execute(&raw)
    .await
    .unwrap();
    recover_stale_request_uploads(store.as_ref(), mixed_blobs.as_ref())
        .await
        .expect("healthy startup recovers the whole mixed batch after lease repair");
    assert_eq!(mixed_blobs.object_count(), 0);

    // Owner writes persist cleanup authority on both sides of put, and finalization atomically
    // transitions that authority into current/version metadata.
    let owner_blobs = Arc::new(MemoryBlobs::new());
    let fresh_intent = OwnerBlobWriteIntent {
        object_key: "pg-owner-fresh".into(),
        owner_sub: "owner-atomic".into(),
        size: 3,
        kind: OWNER_WRITE_FRESH.into(),
        file_id: "pg-owner-fresh".into(),
        folder_id: None,
        expected_object_key: None,
        created_at: now + 2_950,
        attempts: 0,
    };
    assert_eq!(
        store
            .reserve_owner_blob_write(&fresh_intent, Some(3))
            .await
            .unwrap(),
        OwnerBlobCommit::Applied
    );
    owner_blobs
        .put(&fresh_intent.object_key, vec![1, 2, 3])
        .await
        .unwrap();
    let mut owner_file = file(
        "pg-owner-fresh",
        "owner-atomic",
        "pg-owner-atomic-token",
        now + 2_950,
    );
    owner_file.size = 3;
    assert_eq!(
        store
            .commit_owner_upload(&owner_file, Some(3))
            .await
            .unwrap(),
        OwnerBlobCommit::Applied
    );
    let reupload_intent = OwnerBlobWriteIntent {
        object_key: "pg-owner-new".into(),
        owner_sub: "owner-atomic".into(),
        size: 5,
        kind: OWNER_WRITE_REUPLOAD.into(),
        file_id: owner_file.id.clone(),
        folder_id: None,
        expected_object_key: Some(owner_file.object_key.clone()),
        created_at: now + 2_951,
        attempts: 0,
    };
    assert_eq!(
        store
            .reserve_owner_blob_write(&reupload_intent, Some(8))
            .await
            .unwrap(),
        OwnerBlobCommit::Applied
    );
    owner_blobs
        .put(&reupload_intent.object_key, vec![4, 5, 6, 7, 8])
        .await
        .unwrap();
    assert_eq!(
        store
            .commit_owner_reupload(OwnerReuploadInput {
                owner_sub: "owner-atomic",
                file_id: "pg-owner-fresh",
                expected_object_key: "pg-owner-fresh",
                new_object_key: "pg-owner-new",
                new_size: 5,
                new_content_type: "image/webp",
                snapshot_id: "pg-owner-old-version",
                changed_at: now + 2_951,
                owner_quota: Some(8),
            })
            .await
            .unwrap(),
        OwnerBlobCommit::Applied
    );
    assert_eq!(
        store
            .commit_owner_version_restore(OwnerVersionRestoreInput {
                owner_sub: "owner-atomic",
                file_id: "pg-owner-fresh",
                expected_object_key: "pg-owner-new",
                version_id: "pg-owner-old-version",
                snapshot_id: "pg-owner-new-version",
                changed_at: now + 2_952,
            })
            .await
            .unwrap(),
        OwnerBlobCommit::Applied
    );
    assert_eq!(
        store
            .get("pg-owner-fresh")
            .await
            .unwrap()
            .unwrap()
            .object_key,
        "pg-owner-fresh"
    );
    assert_eq!(
        store
            .get_version("pg-owner-new-version", "pg-owner-fresh")
            .await
            .unwrap()
            .unwrap()
            .object_key,
        "pg-owner-new"
    );

    // Missing-row FOR UPDATE is not a gap lock. Two different owner guards can choose the same
    // snapshot id concurrently; exactly one INSERT wins and the other gets a retryable Collision,
    // never a backend unique-violation 500.
    let mut snapshot_a = file(
        "pgsnapshota",
        "snapshot-owner-a",
        "pg-snapshot-a-token",
        now + 2_953,
    );
    snapshot_a.size = 3;
    let mut snapshot_b = file(
        "pgsnapshotb",
        "snapshot-owner-b",
        "pg-snapshot-b-token",
        now + 2_953,
    );
    snapshot_b.size = 3;
    assert!(store.create(&snapshot_a).await.unwrap());
    assert!(store.create(&snapshot_b).await.unwrap());
    for intent in [
        OwnerBlobWriteIntent {
            object_key: "pgsnapshotnewa".into(),
            owner_sub: snapshot_a.owner_sub.clone(),
            size: 5,
            kind: OWNER_WRITE_REUPLOAD.into(),
            file_id: snapshot_a.id.clone(),
            folder_id: None,
            expected_object_key: Some(snapshot_a.object_key.clone()),
            created_at: now + 2_954,
            attempts: 0,
        },
        OwnerBlobWriteIntent {
            object_key: "pgsnapshotnewb".into(),
            owner_sub: snapshot_b.owner_sub.clone(),
            size: 5,
            kind: OWNER_WRITE_REUPLOAD.into(),
            file_id: snapshot_b.id.clone(),
            folder_id: None,
            expected_object_key: Some(snapshot_b.object_key.clone()),
            created_at: now + 2_954,
            attempts: 0,
        },
    ] {
        assert_eq!(
            store
                .reserve_owner_blob_write(&intent, Some(8))
                .await
                .unwrap(),
            OwnerBlobCommit::Applied
        );
    }
    let left_store = store.clone();
    let right_store = store.clone();
    let (snapshot_left, snapshot_right) = tokio::join!(
        left_store.commit_owner_reupload(OwnerReuploadInput {
            owner_sub: "snapshot-owner-a",
            file_id: "pgsnapshota",
            expected_object_key: "pgsnapshota",
            new_object_key: "pgsnapshotnewa",
            new_size: 5,
            new_content_type: "image/webp",
            snapshot_id: "pg-shared-snapshot-id",
            changed_at: now + 2_955,
            owner_quota: Some(8),
        }),
        right_store.commit_owner_reupload(OwnerReuploadInput {
            owner_sub: "snapshot-owner-b",
            file_id: "pgsnapshotb",
            expected_object_key: "pgsnapshotb",
            new_object_key: "pgsnapshotnewb",
            new_size: 5,
            new_content_type: "image/webp",
            snapshot_id: "pg-shared-snapshot-id",
            changed_at: now + 2_955,
            owner_quota: Some(8),
        })
    );
    let snapshot_left = snapshot_left.unwrap();
    let snapshot_right = snapshot_right.unwrap();
    assert!(matches!(
        (snapshot_left, snapshot_right),
        (OwnerBlobCommit::Applied, OwnerBlobCommit::Collision)
            | (OwnerBlobCommit::Collision, OwnerBlobCommit::Applied)
    ));
    if snapshot_left == OwnerBlobCommit::Collision {
        assert_eq!(
            store
                .commit_owner_reupload(OwnerReuploadInput {
                    owner_sub: "snapshot-owner-a",
                    file_id: "pgsnapshota",
                    expected_object_key: "pgsnapshota",
                    new_object_key: "pgsnapshotnewa",
                    new_size: 5,
                    new_content_type: "image/webp",
                    snapshot_id: "pg-snapshot-retry-a",
                    changed_at: now + 2_956,
                    owner_quota: Some(8),
                })
                .await
                .unwrap(),
            OwnerBlobCommit::Applied
        );
    } else {
        assert_eq!(
            store
                .commit_owner_reupload(OwnerReuploadInput {
                    owner_sub: "snapshot-owner-b",
                    file_id: "pgsnapshotb",
                    expected_object_key: "pgsnapshotb",
                    new_object_key: "pgsnapshotnewb",
                    new_size: 5,
                    new_content_type: "image/webp",
                    snapshot_id: "pg-snapshot-retry-b",
                    changed_at: now + 2_956,
                    owner_quota: Some(8),
                })
                .await
                .unwrap(),
            OwnerBlobCommit::Applied
        );
    }
    assert_eq!(
        store.get("pgsnapshota").await.unwrap().unwrap().object_key,
        "pgsnapshotnewa"
    );
    assert_eq!(
        store.get("pgsnapshotb").await.unwrap().unwrap().object_key,
        "pgsnapshotnewb"
    );
    sqlx::query("DELETE FROM file_versions WHERE file_id IN ('pgsnapshota', 'pgsnapshotb')")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DELETE FROM files WHERE id IN ('pgsnapshota', 'pgsnapshotb')")
        .execute(&raw)
        .await
        .unwrap();

    for (key, wrote_blob) in [("pg-owner-pre-put", false), ("pg-owner-post-put", true)] {
        let intent = OwnerBlobWriteIntent {
            object_key: key.into(),
            owner_sub: "owner-recovery".into(),
            size: 3,
            kind: OWNER_WRITE_FRESH.into(),
            file_id: key.into(),
            folder_id: None,
            expected_object_key: None,
            created_at: now.saturating_sub(1_000),
            attempts: 0,
        };
        assert_eq!(
            store
                .reserve_owner_blob_write(&intent, Some(6))
                .await
                .unwrap(),
            OwnerBlobCommit::Applied
        );
        if wrote_blob {
            owner_blobs.put(key, vec![9, 9, 9]).await.unwrap();
        }
    }
    recover_stale_request_uploads(store.as_ref(), owner_blobs.as_ref())
        .await
        .expect("PG startup recovery owns absent and present owner writes");
    assert!(owner_blobs.get("pg-owner-post-put").await.is_err());
    let remaining_owner_intents: i64 = sqlx::query(
        "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM owner_blob_write_intents \
         WHERE owner_sub = 'owner-recovery'",
    )
    .fetch_one(&raw)
    .await
    .unwrap()
    .try_get("count")
    .unwrap();
    assert_eq!(remaining_owner_intents, 0);

    // Different owner guards do not serialize each other, so the permanent object-key mutex must
    // make cross-table reservation vs owner-intent collision exactly-one-winner.
    assert!(store
        .create_folder(&fld("keyguardfolder", "keyguard-public", "Key guard"))
        .await
        .unwrap());
    let keyguard_request = UploadRequestRec {
        id: "keyguard-request".into(),
        owner_sub: "keyguard-public".into(),
        folder_id: "keyguardfolder".into(),
        token: "keyguard-token".into(),
        title: "Key guard".into(),
        description: String::new(),
        status: "open".into(),
        expires_at: None,
        max_file_bytes: 10,
        max_total_bytes: 10,
        max_files: 1,
        used_bytes: 0,
        used_files: 0,
        allowed_types: "image/*".into(),
        created_at: now + 2_953,
        updated_at: now + 2_953,
    };
    assert!(store
        .create_upload_request(&keyguard_request)
        .await
        .unwrap());
    let cross_table_intent = OwnerBlobWriteIntent {
        object_key: "shared-cross-table-key".into(),
        owner_sub: "keyguard-private".into(),
        size: 1,
        kind: OWNER_WRITE_FRESH.into(),
        file_id: "shared-cross-table-key".into(),
        folder_id: None,
        expected_object_key: None,
        created_at: now + 2_954,
        attempts: 0,
    };
    let private_store = store.clone();
    let public_store = store.clone();
    let (private_claim, public_claim) = tokio::join!(
        private_store.reserve_owner_blob_write(&cross_table_intent, None),
        public_store.reserve_request_upload(UploadReserveInput {
            request_id: "keyguard-request",
            expected_token: "keyguard-token",
            reservation_id: "shared-cross-table-key",
            size: 1,
            content_type: "image/png",
            content_type_verified: true,
            owner_quota: None,
            now: now + 2_954,
        })
    );
    let private_claim = private_claim.unwrap();
    let public_claim = public_claim.unwrap();
    assert!(matches!(
        (private_claim, public_claim),
        (OwnerBlobCommit::Applied, UploadReserve::Collision)
            | (OwnerBlobCommit::Collision, UploadReserve::Reserved)
    ));
    if private_claim == OwnerBlobCommit::Applied {
        recover_stale_request_uploads(store.as_ref(), owner_blobs.as_ref())
            .await
            .unwrap();
    } else {
        assert!(store
            .release_request_upload("shared-cross-table-key")
            .await
            .unwrap());
    }
    sqlx::query("DELETE FROM upload_requests WHERE id = 'keyguard-request'")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DELETE FROM folders WHERE id = 'keyguardfolder'")
        .execute(&raw)
        .await
        .unwrap();
    assert_eq!(
        store
            .bulk_trash(
                "owner-atomic",
                &[TrashRootInput {
                    item: DriveItemRef {
                        kind: LibraryItemKind::File,
                        id: "pg-owner-fresh".into(),
                    },
                    entry_id: "pg-owner-atomic-trash".into(),
                }],
                now + 2_955,
                now + 20_000,
            )
            .await
            .unwrap(),
        BulkMutation::Applied { changed: 1 }
    );
    assert_eq!(
        store
            .bulk_purge(
                "owner-atomic",
                &[DriveItemRef {
                    kind: LibraryItemKind::File,
                    id: "pg-owner-fresh".into(),
                }],
                now + 2_956,
            )
            .await
            .unwrap(),
        BulkMutation::Applied { changed: 1 }
    );
    aperture::drain_trash_lifecycle_once(store.as_ref(), owner_blobs.as_ref(), now + 2_957)
        .await
        .unwrap();
    assert_eq!(owner_blobs.object_count(), 0);

    // --- Drive v4 lifecycle: migration, nested Trash, atomic batches, durable purge ----------
    // A legacy soft-deleted row inserted after the initial migration receives a deterministic
    // root entry and a fresh 30-day grace period when the idempotent migration runs again.
    let mut legacy = file("legacyv4aa", "alice", "legacy-v4-token", now + 3_000);
    legacy.trashed_at = now.saturating_sub(100);
    assert!(store.create(&legacy).await.unwrap());
    let migration_started = now_secs();
    pg.migrate()
        .await
        .expect("legacy Trash backfill reruns safely");
    let legacy = store.get("legacyv4aa").await.unwrap().unwrap();
    assert_eq!(
        legacy.trash_entry_id.as_deref(),
        Some("legacy-file-legacyv4aa")
    );
    assert!(legacy.trash_ancestor_id.is_none());
    let legacy_purge_after: i64 =
        sqlx::query("SELECT purge_after FROM trash_entries WHERE id = 'legacy-file-legacyv4aa'")
            .fetch_one(&raw)
            .await
            .unwrap()
            .try_get("purge_after")
            .unwrap();
    assert!(legacy_purge_after >= migration_started + 30 * 24 * 60 * 60);
    assert!(store
        .query_trash("alice", None, 20)
        .await
        .unwrap()
        .items
        .iter()
        .any(|item| item.id == "legacyv4aa"));
    assert_eq!(
        store
            .bulk_restore(
                "alice",
                &[DriveItemRef {
                    kind: LibraryItemKind::File,
                    id: "legacyv4aa".into(),
                }],
            )
            .await
            .unwrap(),
        BulkMutation::Applied { changed: 1 }
    );
    assert!(store.delete("legacyv4aa", "alice").await.unwrap());

    // A deterministic legacy id already owned by a different authority is corruption. Migration
    // fails closed and leaves the source unbound rather than silently accepting `ON CONFLICT`.
    let mut collision = file("legacycol1", "alice", "legacy-collision-token", now + 3_001);
    collision.trashed_at = now.saturating_sub(200);
    assert!(store.create(&collision).await.unwrap());
    sqlx::query(
        "INSERT INTO trash_entries \
             (id, owner_sub, item_kind, item_id, trashed_at, purge_after) \
         VALUES ('legacy-file-legacycol1', 'bob', 'file', 'foreign-item', $1, $2)",
    )
    .bind(collision.trashed_at)
    .bind(now + 10_000)
    .execute(&raw)
    .await
    .unwrap();
    let migration_error = pg
        .migrate()
        .await
        .expect_err("foreign deterministic authority must fail closed");
    assert!(migration_error
        .to_string()
        .contains("legacy Trash id conflict for file legacycol1"));
    assert!(store
        .get("legacycol1")
        .await
        .unwrap()
        .unwrap()
        .trash_entry_id
        .is_none());
    sqlx::query("DELETE FROM trash_entries WHERE id = 'legacy-file-legacycol1'")
        .execute(&raw)
        .await
        .unwrap();
    assert!(store.delete("legacycol1", "alice").await.unwrap());

    // A partial prior migration may already have created the exact authority under another id.
    // Re-running migration binds that row and renews the full retention window.
    let mut partial = file("legacyprt1", "alice", "legacy-partial-token", now + 3_002);
    partial.trashed_at = now.saturating_sub(300);
    assert!(store.create(&partial).await.unwrap());
    sqlx::query(
        "INSERT INTO trash_entries \
             (id, owner_sub, item_kind, item_id, trashed_at, purge_after) \
         VALUES ('partial-legacy-authority', 'alice', 'file', 'legacyprt1', $1, 1)",
    )
    .bind(partial.trashed_at)
    .execute(&raw)
    .await
    .unwrap();
    let partial_migration_started = now_secs();
    pg.migrate()
        .await
        .expect("exact partial authority is adopted atomically");
    assert_eq!(
        store
            .get("legacyprt1")
            .await
            .unwrap()
            .unwrap()
            .trash_entry_id
            .as_deref(),
        Some("partial-legacy-authority")
    );
    let partial_purge_after: i64 =
        sqlx::query("SELECT purge_after FROM trash_entries WHERE id = 'partial-legacy-authority'")
            .fetch_one(&raw)
            .await
            .unwrap()
            .try_get("purge_after")
            .unwrap();
    assert!(partial_purge_after >= partial_migration_started + 30 * 24 * 60 * 60);
    assert_eq!(
        store
            .bulk_restore(
                "alice",
                &[DriveItemRef {
                    kind: LibraryItemKind::File,
                    id: "legacyprt1".into(),
                }],
            )
            .await
            .unwrap(),
        BulkMutation::Applied { changed: 1 }
    );
    assert!(store.delete("legacyprt1", "alice").await.unwrap());

    let corrupt_file = file("pgownerbad", "alice", "pg-owner-corrupt-token", now + 3_000);
    let corrupt_folder = fld("pgownerfld", "alice", "Owner mismatch");
    assert!(store.create(&corrupt_file).await.unwrap());
    assert!(store.create_folder(&corrupt_folder).await.unwrap());
    assert_eq!(
        store
            .bulk_trash(
                "alice",
                &[
                    TrashRootInput {
                        item: DriveItemRef {
                            kind: LibraryItemKind::File,
                            id: "pgownerbad".into(),
                        },
                        entry_id: "pg-owner-file-entry".into(),
                    },
                    TrashRootInput {
                        item: DriveItemRef {
                            kind: LibraryItemKind::Folder,
                            id: "pgownerfld".into(),
                        },
                        entry_id: "pg-owner-folder-entry".into(),
                    },
                ],
                now + 3_050,
                now + 4_000,
            )
            .await
            .unwrap(),
        BulkMutation::Applied { changed: 2 }
    );
    sqlx::query("UPDATE files SET owner_sub = 'mallory' WHERE id = 'pgownerbad'")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("UPDATE folders SET owner_sub = 'mallory' WHERE id = 'pgownerfld'")
        .execute(&raw)
        .await
        .unwrap();
    assert!(store
        .query_trash("alice", None, 20)
        .await
        .unwrap()
        .items
        .iter()
        .all(|item| item.id != "pgownerbad" && item.id != "pgownerfld"));
    assert!(store
        .query_trash("mallory", None, 20)
        .await
        .unwrap()
        .items
        .iter()
        .all(|item| item.id != "pgownerbad" && item.id != "pgownerfld"));
    sqlx::query("UPDATE files SET owner_sub = 'alice' WHERE id = 'pgownerbad'")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("UPDATE folders SET owner_sub = 'alice' WHERE id = 'pgownerfld'")
        .execute(&raw)
        .await
        .unwrap();
    assert_eq!(
        store
            .bulk_restore(
                "alice",
                &[
                    DriveItemRef {
                        kind: LibraryItemKind::File,
                        id: "pgownerbad".into(),
                    },
                    DriveItemRef {
                        kind: LibraryItemKind::Folder,
                        id: "pgownerfld".into(),
                    },
                ],
            )
            .await
            .unwrap(),
        BulkMutation::Applied { changed: 2 }
    );
    assert!(store.delete("pgownerbad", "alice").await.unwrap());
    assert_eq!(
        store
            .delete_folder_if_empty("pgownerfld", "alice")
            .await
            .unwrap(),
        FolderDelete::Deleted
    );

    let mut trash_parent = fld("trashpgpar", "alice", "Trash parent");
    trash_parent.share_token = Some("trash-parent-token".into());
    assert!(store.create_folder(&trash_parent).await.unwrap());
    let mut trash_child = fld("trashpgchi", "alice", "Trash child");
    trash_child.parent_id = Some("trashpgpar".into());
    trash_child.share_token = Some("trash-child-token".into());
    assert!(store.create_folder(&trash_child).await.unwrap());
    let mut trash_file = file("trashpgfil", "alice", "trash-file-token", now + 3_001);
    trash_file.folder_id = Some("trashpgchi".into());
    assert!(store.create(&trash_file).await.unwrap());
    assert!(store
        .get_folder_by_token("trash-child-token")
        .await
        .unwrap()
        .is_some());
    assert!(store
        .get_by_token("trash-file-token")
        .await
        .unwrap()
        .is_some());

    assert_eq!(
        store
            .bulk_trash(
                "alice",
                &[TrashRootInput {
                    item: DriveItemRef {
                        kind: LibraryItemKind::Folder,
                        id: "trashpgchi".into(),
                    },
                    entry_id: "pg-child-entry".into(),
                }],
                now + 3_100,
                now + 30 * 24 * 60 * 60,
            )
            .await
            .unwrap(),
        BulkMutation::Applied { changed: 1 }
    );
    assert!(store
        .get_folder_by_token("trash-child-token")
        .await
        .unwrap()
        .is_none());
    assert!(store
        .get_by_token("trash-file-token")
        .await
        .unwrap()
        .is_none());
    assert!(store
        .list_files_in_folder("trashpgchi", "alice")
        .await
        .unwrap()
        .is_empty());
    assert!(store
        .find_file_in_folder("alice", "trashpgfil.png", Some("trashpgchi"))
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        store
            .bulk_trash(
                "alice",
                &[TrashRootInput {
                    item: DriveItemRef {
                        kind: LibraryItemKind::Folder,
                        id: "trashpgpar".into(),
                    },
                    entry_id: "pg-parent-entry".into(),
                }],
                now + 3_101,
                now + 30 * 24 * 60 * 60,
            )
            .await
            .unwrap(),
        BulkMutation::Applied { changed: 1 }
    );
    let trash_roots = store.query_trash("alice", None, 20).await.unwrap();
    assert_eq!(
        trash_roots
            .items
            .iter()
            .filter(|item| item.id == "trashpgpar" || item.id == "trashpgchi")
            .map(|item| item.id.as_str())
            .collect::<Vec<_>>(),
        vec!["trashpgpar"],
        "an independently trashed child is hidden while its parent scope is active"
    );
    assert_eq!(
        store
            .bulk_restore(
                "alice",
                &[DriveItemRef {
                    kind: LibraryItemKind::Folder,
                    id: "trashpgpar".into(),
                }],
            )
            .await
            .unwrap(),
        BulkMutation::Applied { changed: 1 }
    );
    assert!(store
        .get_folder_by_token("trash-parent-token")
        .await
        .unwrap()
        .is_some());
    assert!(store
        .get_folder_by_token("trash-child-token")
        .await
        .unwrap()
        .is_none());
    assert!(store
        .get_by_token("trash-file-token")
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        store
            .bulk_restore(
                "alice",
                &[DriveItemRef {
                    kind: LibraryItemKind::Folder,
                    id: "trashpgchi".into(),
                }],
            )
            .await
            .unwrap(),
        BulkMutation::Applied { changed: 1 }
    );
    assert!(store
        .get_folder_by_token("trash-child-token")
        .await
        .unwrap()
        .is_some());
    assert!(store
        .get_by_token("trash-file-token")
        .await
        .unwrap()
        .is_some());

    // Foreign or stale members reject the entire batch; cycle checks and the 200-item domain
    // boundary run inside Store as well as at HTTP parsing.
    let owned_atomic = file("pgatomic01", "alice", "pg-atomic-token", now + 3_010);
    let foreign_atomic = file("pgforeign1", "bob", "pg-foreign-token", now + 3_010);
    assert!(store.create(&owned_atomic).await.unwrap());
    assert!(store.create(&foreign_atomic).await.unwrap());
    let mixed_roots = [
        TrashRootInput {
            item: DriveItemRef {
                kind: LibraryItemKind::File,
                id: "pgatomic01".into(),
            },
            entry_id: "pg-atomic-entry".into(),
        },
        TrashRootInput {
            item: DriveItemRef {
                kind: LibraryItemKind::File,
                id: "pgforeign1".into(),
            },
            entry_id: "pg-foreign-entry".into(),
        },
    ];
    assert_eq!(
        store
            .bulk_trash("alice", &mixed_roots, now + 3_200, now + 4_000)
            .await
            .unwrap(),
        BulkMutation::Conflict
    );
    assert!(store
        .get("pgatomic01")
        .await
        .unwrap()
        .unwrap()
        .is_effectively_live());
    assert_eq!(
        store
            .bulk_trash(
                "alice",
                &[TrashRootInput {
                    item: DriveItemRef {
                        kind: LibraryItemKind::File,
                        id: "trashpgfil".into(),
                    },
                    entry_id: "pg-stale-entry".into(),
                }],
                now + 3_201,
                now + 4_000,
            )
            .await
            .unwrap(),
        BulkMutation::Applied { changed: 1 }
    );
    assert_eq!(
        store
            .bulk_move(
                "alice",
                &[
                    DriveItemRef {
                        kind: LibraryItemKind::File,
                        id: "pgatomic01".into(),
                    },
                    DriveItemRef {
                        kind: LibraryItemKind::File,
                        id: "trashpgfil".into(),
                    },
                ],
                None,
            )
            .await
            .unwrap(),
        BulkMutation::Conflict
    );
    assert!(store
        .get("pgatomic01")
        .await
        .unwrap()
        .unwrap()
        .is_effectively_live());
    assert!(matches!(
        store
            .bulk_restore(
                "alice",
                &[DriveItemRef {
                    kind: LibraryItemKind::File,
                    id: "trashpgfil".into(),
                }],
            )
            .await
            .unwrap(),
        BulkMutation::Applied { .. }
    ));
    assert_eq!(
        store
            .bulk_move(
                "alice",
                &[DriveItemRef {
                    kind: LibraryItemKind::Folder,
                    id: "trashpgpar".into(),
                }],
                Some("trashpgchi"),
            )
            .await
            .unwrap(),
        BulkMutation::Conflict
    );
    let oversized: Vec<DriveItemRef> = (0..=MAX_BULK_ITEMS)
        .map(|index| DriveItemRef {
            kind: LibraryItemKind::File,
            id: format!("pgoversized{index}"),
        })
        .collect();
    assert_eq!(
        store.bulk_move("alice", &oversized, None).await.unwrap(),
        BulkMutation::Conflict
    );

    // Two concurrent lifecycle writers serialize on the owner guard: exactly one commits.
    let concurrent = file("pgconcur01", "alice", "pg-concurrent-token", now + 3_020);
    assert!(store.create(&concurrent).await.unwrap());
    let left_store = store.clone();
    let right_store = store.clone();
    let (left, right) = tokio::join!(
        async move {
            left_store
                .bulk_trash(
                    "alice",
                    &[TrashRootInput {
                        item: DriveItemRef {
                            kind: LibraryItemKind::File,
                            id: "pgconcur01".into(),
                        },
                        entry_id: "pg-concurrent-left".into(),
                    }],
                    now + 3_300,
                    now + 4_000,
                )
                .await
                .unwrap()
        },
        async move {
            right_store
                .bulk_trash(
                    "alice",
                    &[TrashRootInput {
                        item: DriveItemRef {
                            kind: LibraryItemKind::File,
                            id: "pgconcur01".into(),
                        },
                        entry_id: "pg-concurrent-right".into(),
                    }],
                    now + 3_300,
                    now + 4_000,
                )
                .await
                .unwrap()
        }
    );
    assert_eq!(
        [left, right]
            .into_iter()
            .filter(|result| matches!(result, BulkMutation::Applied { .. }))
            .count(),
        1
    );
    assert!(matches!(
        store
            .bulk_restore(
                "alice",
                &[DriveItemRef {
                    kind: LibraryItemKind::File,
                    id: "pgconcur01".into(),
                }],
            )
            .await
            .unwrap(),
        BulkMutation::Applied { .. }
    ));

    // Purge commits every current/version/thumbnail key to the durable outbox in the same
    // transaction that removes metadata. A failed lease is deferred, then reclaimed and acked.
    sqlx::query("DELETE FROM blob_delete_queue")
        .execute(&raw)
        .await
        .unwrap();
    assert!(store
        .add_version(&VersionRec {
            id: "pgv4version".into(),
            file_id: "pgconcur01".into(),
            object_key: "pgv4versionblob".into(),
            size: 2,
            content_type: "image/png".into(),
            created_at: now + 3_021,
        })
        .await
        .unwrap());
    assert!(matches!(
        store
            .bulk_trash(
                "alice",
                &[TrashRootInput {
                    item: DriveItemRef {
                        kind: LibraryItemKind::File,
                        id: "pgconcur01".into(),
                    },
                    entry_id: "pg-purge-entry".into(),
                }],
                now + 3_400,
                now + 4_000,
            )
            .await
            .unwrap(),
        BulkMutation::Applied { .. }
    ));
    assert_eq!(
        store
            .bulk_purge(
                "alice",
                &[DriveItemRef {
                    kind: LibraryItemKind::File,
                    id: "pgconcur01".into(),
                }],
                now + 3_401,
            )
            .await
            .unwrap(),
        BulkMutation::Applied { changed: 1 }
    );
    assert!(store.get("pgconcur01").await.unwrap().is_none());
    let queued: i64 = sqlx::query(
        "SELECT count(*) AS n FROM blob_delete_queue WHERE object_key IN \
         ('pgconcur01', 'pgconcur01.thumb', 'pgv4versionblob', 'pgv4versionblob.thumb')",
    )
    .fetch_one(&raw)
    .await
    .unwrap()
    .try_get("n")
    .unwrap();
    assert_eq!(
        queued, 4,
        "metadata deletion cannot commit without outbox authority"
    );

    let BlobDeleteClaim::Claimed(mut claimed) = store
        .claim_blob_deletions("pg-delete-worker", now + 3_402, now, 20)
        .await
        .unwrap()
    else {
        panic!("the purge queue must be claimable");
    };
    claimed.sort_by(|left, right| left.object_key.cmp(&right.object_key));
    assert_eq!(claimed.len(), 4);
    let failed_key = claimed[0].object_key.clone();
    assert!(store
        .abandon_blob_deletion(&failed_key, "pg-delete-worker", now + 3_500)
        .await
        .unwrap());
    for item in &claimed[1..] {
        assert!(store
            .complete_blob_deletion(&item.object_key, "pg-delete-worker")
            .await
            .unwrap());
    }
    assert_eq!(
        store
            .claim_blob_deletions("pg-delete-worker-two", now + 3_499, now + 3_000, 20)
            .await
            .unwrap(),
        BlobDeleteClaim::Empty
    );
    let BlobDeleteClaim::Claimed(retry) = store
        .claim_blob_deletions("pg-delete-worker-two", now + 3_500, now + 3_000, 20)
        .await
        .unwrap()
    else {
        panic!("the deferred object must become claimable at retry time");
    };
    assert_eq!(retry.len(), 1);
    assert_eq!(retry[0].object_key, failed_key);
    assert_eq!(retry[0].attempts, 1);
    assert!(store
        .complete_blob_deletion(&failed_key, "pg-delete-worker-two")
        .await
        .unwrap());

    // Poison rows must be excluded before SQL LIMIT. More than four historical overfetch windows
    // of invalid-kind and dangling authorities cannot starve one exact valid Trash root.
    let poison_valid = file("pgpoisonok", "alice", "pg-poison-valid-token", now + 3_510);
    assert!(store.create(&poison_valid).await.unwrap());
    assert_eq!(
        store
            .bulk_trash(
                "alice",
                &[TrashRootInput {
                    item: DriveItemRef {
                        kind: LibraryItemKind::File,
                        id: "pgpoisonok".into(),
                    },
                    entry_id: "zz-valid-poison-entry".into(),
                }],
                now + 3_511,
                now + 3_512,
            )
            .await
            .unwrap(),
        BulkMutation::Applied { changed: 1 }
    );
    sqlx::query(
        "INSERT INTO trash_entries \
             (id, owner_sub, item_kind, item_id, trashed_at, purge_after) \
         SELECT 'aa-invalid-poison-' || LPAD(n::text, 3, '0'), 'alice', 'invalid', \
                'invalid-item-' || n::text, $1, $2 \
         FROM generate_series(1, 125) AS poison(n)",
    )
    .bind(now + 1)
    .bind(now + 2)
    .execute(&raw)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO trash_entries \
             (id, owner_sub, item_kind, item_id, trashed_at, purge_after) \
         SELECT 'ab-dangling-poison-' || LPAD(n::text, 3, '0'), 'alice', 'file', \
                'missing-file-' || n::text, $1, $2 \
         FROM generate_series(1, 125) AS poison(n)",
    )
    .bind(now + 1)
    .bind(now + 2)
    .execute(&raw)
    .await
    .unwrap();
    let poison_claim = store
        .claim_expired_trash("pg-poison-worker", now + 3_513, now + 3_000, 1)
        .await
        .unwrap();
    assert_eq!(poison_claim.len(), 1);
    assert_eq!(poison_claim[0].id, "zz-valid-poison-entry");
    assert!(store
        .abandon_trash_claim("zz-valid-poison-entry", "pg-poison-worker")
        .await
        .unwrap());
    assert_eq!(
        store
            .bulk_purge(
                "alice",
                &[DriveItemRef {
                    kind: LibraryItemKind::File,
                    id: "pgpoisonok".into(),
                }],
                now + 3_514,
            )
            .await
            .unwrap(),
        BulkMutation::Applied { changed: 1 }
    );
    sqlx::query("DELETE FROM trash_entries WHERE id LIKE '%-poison-%'")
        .execute(&raw)
        .await
        .unwrap();

    // Claim locks multiple authorities by entry id even though fairness was selected by expiry.
    // A reversed caller batch therefore waits on the same first row instead of holding the second
    // one and deadlocking. The trigger makes that interleaving deterministic.
    for (id, token) in [
        ("pgclaimlocka", "pg-claim-lock-a-token"),
        ("pgclaimlockz", "pg-claim-lock-z-token"),
    ] {
        assert!(store
            .create(&file(id, "claim-lock-owner", token, now + 3_520))
            .await
            .unwrap());
    }
    assert_eq!(
        store
            .bulk_trash(
                "claim-lock-owner",
                &[
                    TrashRootInput {
                        item: DriveItemRef {
                            kind: LibraryItemKind::File,
                            id: "pgclaimlocka".into(),
                        },
                        entry_id: "aa-claim-lock-entry".into(),
                    },
                    TrashRootInput {
                        item: DriveItemRef {
                            kind: LibraryItemKind::File,
                            id: "pgclaimlockz".into(),
                        },
                        entry_id: "zz-claim-lock-entry".into(),
                    },
                ],
                now + 3_521,
                now + 3_522,
            )
            .await
            .unwrap(),
        BulkMutation::Applied { changed: 2 }
    );
    sqlx::query(
        "CREATE OR REPLACE FUNCTION aperture_block_trash_claim() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN \
           IF NEW.id = 'aa-claim-lock-entry' AND NEW.recovery_lease IS NOT NULL THEN \
             PERFORM pg_advisory_xact_lock(7300105); \
           END IF; \
           RETURN NEW; \
         END $$",
    )
    .execute(&raw)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER aperture_block_trash_claim_trigger BEFORE UPDATE ON trash_entries \
         FOR EACH ROW EXECUTE FUNCTION aperture_block_trash_claim()",
    )
    .execute(&raw)
    .await
    .unwrap();
    let mut claim_barrier = raw.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(7300105)")
        .execute(&mut *claim_barrier)
        .await
        .unwrap();
    let claim_store = store.clone();
    let claiming = tokio::spawn(async move {
        claim_store
            .claim_expired_trash("ordered-trash-claim", now + 3_523, now + 3_000, 2)
            .await
    });
    let mut claim_at_barrier = false;
    for _ in 0..200 {
        let blocked: i64 = sqlx::query(
            "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM pg_stat_activity \
             WHERE pid <> pg_backend_pid() AND state = 'active' AND wait_event_type = 'Lock' \
               AND query LIKE '%UPDATE trash_entries SET recovery_lease%'",
        )
        .fetch_one(&raw)
        .await
        .unwrap()
        .try_get("count")
        .unwrap();
        if blocked > 0 {
            claim_at_barrier = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        claim_at_barrier,
        "claim did not reach its controlled barrier"
    );
    let purge_store = store.clone();
    let reversed_purge = tokio::spawn(async move {
        purge_store
            .bulk_purge(
                "claim-lock-owner",
                &[
                    DriveItemRef {
                        kind: LibraryItemKind::File,
                        id: "pgclaimlockz".into(),
                    },
                    DriveItemRef {
                        kind: LibraryItemKind::File,
                        id: "pgclaimlocka".into(),
                    },
                ],
                now + 3_524,
            )
            .await
    });
    let mut purge_waited_on_first_authority = false;
    for _ in 0..200 {
        let blocked: i64 = sqlx::query(
            "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM pg_stat_activity \
             WHERE pid <> pg_backend_pid() AND state = 'active' AND wait_event_type = 'Lock' \
               AND query LIKE '%SELECT 1 FROM trash_entries WHERE id%'",
        )
        .fetch_one(&raw)
        .await
        .unwrap()
        .try_get("count")
        .unwrap();
        if blocked > 0 {
            purge_waited_on_first_authority = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        purge_waited_on_first_authority,
        "reversed purge did not wait on the canonical first authority"
    );
    claim_barrier.rollback().await.unwrap();
    let claimed = tokio::time::timeout(Duration::from_secs(5), claiming)
        .await
        .expect("claim timed out")
        .unwrap()
        .unwrap();
    assert_eq!(claimed.len(), 2);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), reversed_purge)
            .await
            .expect("reversed purge timed out")
            .unwrap()
            .unwrap(),
        BulkMutation::Applied { changed: 2 }
    );
    sqlx::query("DROP TRIGGER aperture_block_trash_claim_trigger ON trash_entries")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION aperture_block_trash_claim()")
        .execute(&raw)
        .await
        .unwrap();

    let expired = file("pgexpired1", "alice", "pg-expired-token", now + 3_030);
    assert!(store.create(&expired).await.unwrap());
    assert!(matches!(
        store
            .bulk_trash(
                "alice",
                &[TrashRootInput {
                    item: DriveItemRef {
                        kind: LibraryItemKind::File,
                        id: "pgexpired1".into(),
                    },
                    entry_id: "pg-expired-entry".into(),
                }],
                now + 3_600,
                now + 3_601,
            )
            .await
            .unwrap(),
        BulkMutation::Applied { .. }
    ));
    let claimed_expired = store
        .claim_expired_trash("pg-trash-worker", now + 3_602, now + 3_000, 20)
        .await
        .unwrap();
    assert_eq!(claimed_expired.len(), 1);
    assert_eq!(claimed_expired[0].item_id, "pgexpired1");
    assert!(store
        .claim_expired_trash("pg-trash-worker-two", now + 3_603, now + 3_000, 20)
        .await
        .unwrap()
        .is_empty());
    assert!(store
        .abandon_trash_claim("pg-expired-entry", "pg-trash-worker")
        .await
        .unwrap());
    assert_eq!(
        store
            .claim_expired_trash("pg-trash-worker-two", now + 3_604, now + 3_000, 20)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(matches!(
        store
            .bulk_purge(
                "alice",
                &[DriveItemRef {
                    kind: LibraryItemKind::File,
                    id: "pgexpired1".into(),
                }],
                now + 3_605,
            )
            .await
            .unwrap(),
        BulkMutation::Applied { .. }
    ));
    if let BlobDeleteClaim::Claimed(items) = store
        .claim_blob_deletions("pg-final-delete-worker", now + 3_606, now + 3_000, 20)
        .await
        .unwrap()
    {
        for item in items {
            assert!(store
                .complete_blob_deletion(&item.object_key, "pg-final-delete-worker")
                .await
                .unwrap());
        }
    }

    // --- the full HTTP app boots against Postgres (healthz) ----------------
    let state = AppState {
        config: build_dev_state().config,
        store: store.clone(),
        blobs: Arc::new(MemoryBlobs::new()),
        audit: aperture::audit::AuditSink::disabled(),
    };
    let app = app(state);
    let res = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/healthz")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);

    // Confirm the remaining row count via a raw query (portable SQL path is live).
    let row = sqlx::query("SELECT count(*) AS n FROM files")
        .fetch_one(&raw)
        .await
        .unwrap();
    let n: i64 = row.try_get("n").unwrap();
    assert!(n >= 2, "expected remaining files, got {n}");

    sqlx::query("DELETE FROM files")
        .execute(&raw)
        .await
        .unwrap();
    eprintln!("pg_store integration test passed.");
}
