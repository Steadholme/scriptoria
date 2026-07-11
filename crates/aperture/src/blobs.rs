//! Blob storage abstraction.
//!
//! `Blobs` is a small async trait with two implementations, mirroring the metadata `Store` seam:
//! handlers depend only on the trait, so the object store is swappable and the DB-free test suite
//! uses the in-memory fake (no Cairn required).
//!
//! - [`MemoryBlobs`] — an in-process map; the default for dev + tests.
//! - [`S3Blobs`] — Cairn / any S3-compatible store via [`object_store`] (custom endpoint,
//!   path-style, allow-http). The S3 client is native async; handlers `.await` it on the serving
//!   runtime, so no worker thread is ever blocked on a round-trip.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use bytes::Bytes;
use object_store::aws::AmazonS3Builder;
use object_store::path::Path as ObjPath;
use object_store::{ObjectStore, PutPayload};
use thiserror::Error;

use crate::config::S3Config;

/// Blob failure surfaced to the handler layer. A missing object is distinguished so the handler
/// can map it to a 404 rather than a 500.
#[derive(Debug, Error)]
pub enum BlobError {
    #[error("blob not found")]
    NotFound,
    #[error("blob store error: {0}")]
    Backend(String),
}

/// Pluggable blob store. Keys are the `object_key` recorded on the metadata row. Bodies are
/// buffered whole (uploads are size-capped well under memory limits), which keeps the trait
/// trivial and the same on both backends.
#[async_trait]
pub trait Blobs: Send + Sync {
    /// The bucket label recorded on new files (so the metadata row is self-describing).
    fn bucket(&self) -> &str;

    /// Store `bytes` under `key`, overwriting any existing object at that key.
    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), BlobError>;

    /// Fetch the whole object at `key`. `NotFound` when it does not exist.
    async fn get(&self, key: &str) -> Result<Vec<u8>, BlobError>;

    /// Fetch an inclusive byte range from the object at `key`.
    async fn get_range(
        &self,
        key: &str,
        start: u64,
        end_inclusive: u64,
    ) -> Result<Vec<u8>, BlobError>;

    /// Remove the object at `key`. Deleting a missing object is a no-op (Ok).
    async fn delete(&self, key: &str) -> Result<(), BlobError>;
}

// --------------------------------------------------------------------------------------
// In-memory blobs (the default; keeps the whole service object-store-free for dev + tests).
// --------------------------------------------------------------------------------------

/// In-memory `Blobs`. The `Mutex<HashMap<_>>` critical sections are fully synchronous (no `.await`
/// held across the guard), so the std `Mutex` is correct here.
#[derive(Default)]
pub struct MemoryBlobs {
    objects: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryBlobs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of currently stored objects. Primarily a reconciliation/test diagnostic; callers
    /// cannot inspect keys or bytes through it.
    pub fn object_count(&self) -> usize {
        self.objects.lock().expect("objects lock poisoned").len()
    }
}

#[async_trait]
impl Blobs for MemoryBlobs {
    fn bucket(&self) -> &str {
        "memory"
    }

    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), BlobError> {
        self.objects
            .lock()
            .expect("objects lock poisoned")
            .insert(key.to_string(), bytes);
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, BlobError> {
        self.objects
            .lock()
            .expect("objects lock poisoned")
            .get(key)
            .cloned()
            .ok_or(BlobError::NotFound)
    }

    async fn get_range(
        &self,
        key: &str,
        start: u64,
        end_inclusive: u64,
    ) -> Result<Vec<u8>, BlobError> {
        let bytes = self.get(key).await?;
        let start = start as usize;
        if start >= bytes.len() {
            return Ok(Vec::new());
        }
        let end = (end_inclusive as usize).min(bytes.len() - 1);
        if end < start {
            return Ok(Vec::new());
        }
        Ok(bytes[start..=end].to_vec())
    }

    async fn delete(&self, key: &str) -> Result<(), BlobError> {
        self.objects
            .lock()
            .expect("objects lock poisoned")
            .remove(key);
        Ok(())
    }
}

// --------------------------------------------------------------------------------------
// S3 / Cairn-backed blobs (object_store: custom endpoint, path-style, allow-http).
// --------------------------------------------------------------------------------------

/// S3-compatible `Blobs` backed by [`object_store::aws`]. Selected at runtime by
/// `APERTURE_BLOBS=s3`; talks to Cairn at `S3_ENDPOINT` (path-style, plain HTTP allowed).
pub struct S3Blobs {
    inner: object_store::aws::AmazonS3,
    bucket: String,
}

impl S3Blobs {
    /// Build the client from [`S3Config`]. Path-style + allow-http suit Cairn / MinIO on the
    /// internal network; the credentials are the bucket's access key / secret.
    pub fn connect(cfg: &S3Config) -> Result<Self, String> {
        if cfg.access_key.is_empty() || cfg.secret_key.is_empty() {
            return Err("APERTURE_BLOBS=s3 requires S3_ACCESS_KEY and S3_SECRET_KEY".to_string());
        }
        let inner = AmazonS3Builder::new()
            .with_endpoint(&cfg.endpoint)
            .with_bucket_name(&cfg.bucket)
            .with_region(&cfg.region)
            .with_access_key_id(&cfg.access_key)
            .with_secret_access_key(&cfg.secret_key)
            .with_allow_http(true)
            .with_virtual_hosted_style_request(false)
            .build()
            .map_err(|e| format!("build S3 client: {e}"))?;
        Ok(Self {
            inner,
            bucket: cfg.bucket.clone(),
        })
    }
}

/// Map an [`object_store::Error`] to our [`BlobError`], surfacing a missing object distinctly.
fn map_err(e: object_store::Error) -> BlobError {
    match e {
        object_store::Error::NotFound { .. } => BlobError::NotFound,
        other => BlobError::Backend(other.to_string()),
    }
}

#[async_trait]
impl Blobs for S3Blobs {
    fn bucket(&self) -> &str {
        &self.bucket
    }

    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), BlobError> {
        let payload = PutPayload::from(Bytes::from(bytes));
        self.inner
            .put(&ObjPath::from(key), payload)
            .await
            .map(|_| ())
            .map_err(map_err)
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, BlobError> {
        let result = self.inner.get(&ObjPath::from(key)).await.map_err(map_err)?;
        let bytes = result.bytes().await.map_err(map_err)?;
        Ok(bytes.to_vec())
    }

    async fn get_range(
        &self,
        key: &str,
        start: u64,
        end_inclusive: u64,
    ) -> Result<Vec<u8>, BlobError> {
        let r = self
            .inner
            .get_range(
                &ObjPath::from(key),
                (start as usize)..(end_inclusive as usize + 1),
            )
            .await
            .map_err(map_err)?;
        Ok(r.to_vec())
    }

    async fn delete(&self, key: &str) -> Result<(), BlobError> {
        match self.inner.delete(&ObjPath::from(key)).await {
            Ok(()) => Ok(()),
            // Deleting an already-absent object is a no-op, not an error.
            Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(map_err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_blobs_round_trip_and_delete() {
        let b = MemoryBlobs::new();
        assert_eq!(b.bucket(), "memory");
        assert!(matches!(b.get("missing").await, Err(BlobError::NotFound)));
        b.put("k", b"hello".to_vec()).await.unwrap();
        assert_eq!(b.get("k").await.unwrap(), b"hello");
        b.delete("k").await.unwrap();
        assert!(matches!(b.get("k").await, Err(BlobError::NotFound)));
        // Deleting a missing key is a no-op.
        b.delete("k").await.unwrap();
    }
}
