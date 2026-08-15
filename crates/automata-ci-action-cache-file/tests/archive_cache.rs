use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use automata_ci_action_cache_file::{
    ActionArchiveCacheLimits, ActionArchiveCacheRoot, FileActionArchiveCache,
};
use automata_ci_blob::{
    BlobKey, BlobPayload, BlobStoreErrorKind, ImmutableBlobStore, MediaType, PutBlobOutcome,
};
use bytes::Bytes;

static NEXT_SCRATCH: AtomicU64 = AtomicU64::new(1);

#[tokio::test]
async fn archive_bytes_survive_reopen_and_are_verified() {
    let scratch = Scratch::new("reopen");
    let payload = payload(b"immutable action archive");
    let descriptor = payload.descriptor().clone();
    let limits = ActionArchiveCacheLimits::new(4, 4096, 1024).unwrap();
    {
        let cache = FileActionArchiveCache::open(scratch.root(), limits).unwrap();
        assert_eq!(
            cache.put_if_absent(payload).await.unwrap(),
            PutBlobOutcome::Created
        );
    }
    let reopened = FileActionArchiveCache::open(scratch.root(), limits).unwrap();
    let loaded = reopened.get_verified(&descriptor, 1024).await.unwrap();
    assert_eq!(loaded.bytes().as_ref(), b"immutable action archive");
}

#[tokio::test]
async fn archive_cache_evicts_to_both_entry_and_byte_bounds() {
    let scratch = Scratch::new("eviction");
    let cache = FileActionArchiveCache::open(
        scratch.root(),
        ActionArchiveCacheLimits::new(2, 8, 8).unwrap(),
    )
    .unwrap();
    let first = payload(b"1111");
    let first_descriptor = first.descriptor().clone();
    let second = payload(b"2222");
    let second_descriptor = second.descriptor().clone();
    let third = payload(b"3333");
    let third_descriptor = third.descriptor().clone();
    cache.put_if_absent(first).await.unwrap();
    cache.put_if_absent(second).await.unwrap();
    cache.put_if_absent(third).await.unwrap();
    assert_eq!(
        cache
            .get_verified(&first_descriptor, 8)
            .await
            .unwrap_err()
            .kind(),
        BlobStoreErrorKind::NotFound
    );
    assert_eq!(
        cache
            .get_verified(&second_descriptor, 8)
            .await
            .unwrap()
            .bytes()
            .as_ref(),
        b"2222"
    );
    assert_eq!(
        cache
            .get_verified(&third_descriptor, 8)
            .await
            .unwrap()
            .bytes()
            .as_ref(),
        b"3333"
    );
}

fn payload(bytes: &'static [u8]) -> BlobPayload {
    let preliminary = BlobPayload::from_bytes(
        BlobKey::new("actions/v1/sha256/preliminary.tar.gz").unwrap(),
        MediaType::new("application/gzip").unwrap(),
        Bytes::from_static(bytes),
    );
    BlobPayload::from_bytes(
        BlobKey::new(format!(
            "actions/v1/sha256/{}.tar.gz",
            preliminary.descriptor().digest()
        ))
        .unwrap(),
        MediaType::new("application/gzip").unwrap(),
        Bytes::from_static(bytes),
    )
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let sequence = NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed);
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("crate is inside workspace crates directory");
        let path = workspace
            .join("target/agent-scratch/action-archive-cache")
            .join(format!("{}-{label}-{sequence}", std::process::id()));
        if path.exists() {
            fs::remove_dir_all(&path).unwrap();
        }
        Self(path)
    }

    fn root(&self) -> ActionArchiveCacheRoot {
        ActionArchiveCacheRoot::explicit(self.0.clone()).unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if self.0.exists() {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
}
