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
    FileRec, FolderRec, LibraryQuery, LibraryType, LibraryView, UploadRequestRec, UploadSubmission,
    VersionRec,
};
use aperture::store::{
    FolderDelete, PgStore, Store, UploadRecoveryClaim, UploadReserve, UploadReserveInput,
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
    for table in [
        "upload_submissions",
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

    let pg = Arc::new(pg);
    let store: Arc<dyn Store> = pg.clone();
    let now = now_secs();

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
               AND query LIKE '%FROM file_versions v JOIN files f%'",
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
        file_id: received.id.clone(),
        name: received.name.clone(),
        content_type: received.content_type.clone(),
        size: received.size,
        created_at: now + 204,
    };
    assert!(store
        .commit_request_upload("receiptfile", &received, &receipt)
        .await
        .unwrap());
    assert_eq!(
        store
            .list_upload_submissions("request-room-a", "alice")
            .await
            .unwrap(),
        vec![receipt]
    );
    assert!(store
        .get("receiptfile")
        .await
        .unwrap()
        .unwrap()
        .share_token
        .is_none());

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
