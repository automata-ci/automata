mod support;

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use async_trait::async_trait;
use automata_action::{
    ActionBundleLimits, ActionReferenceIndex, ActionReferenceIndexError, ActionResolveErrorKind,
    ActionResolver, ActionSubpath, ImmutableActionReference, ImmutableActionResolver,
    IndexedActionBundle, MemoryActionReferenceIndex, PutActionReferenceOutcome,
    RepositoryActionRequest,
};
use automata_blob::{
    BlobKey, BlobPayload, BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore, MediaType,
    MemoryBlobStore, PutBlobOutcome, VerifiedBlob,
};
use automata_scm::{
    ArchiveFormat, RepositoryId, RepositorySnapshot, ResolvedRevision, RevisionSpec, ScmError,
    ScmErrorKind, ScmProvider, ScmProviderId, SnapshotRequest,
};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use static_assertions::assert_obj_safe;
use support::{SHA, TestEntry, build_archive};
use tokio::sync::Barrier;

assert_obj_safe!(ActionReferenceIndex);

#[derive(Debug)]
struct SwitchableScm {
    provider: ScmProviderId,
    archive: Bytes,
    calls: AtomicUsize,
    offline: AtomicBool,
    fill_barrier: Option<Arc<Barrier>>,
}

impl SwitchableScm {
    fn new(archive: Bytes) -> Self {
        Self {
            provider: ScmProviderId::new("github").unwrap(),
            archive,
            calls: AtomicUsize::new(0),
            offline: AtomicBool::new(false),
            fill_barrier: None,
        }
    }

    fn concurrent(archive: Bytes) -> Self {
        Self {
            fill_barrier: Some(Arc::new(Barrier::new(2))),
            ..Self::new(archive)
        }
    }
}

#[async_trait]
impl ScmProvider for SwitchableScm {
    fn provider_id(&self) -> &ScmProviderId {
        &self.provider
    }

    async fn fetch_snapshot(
        &self,
        request: SnapshotRequest<'_>,
    ) -> Result<RepositorySnapshot, ScmError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.offline.load(Ordering::SeqCst) {
            return Err(ScmError::new(ScmErrorKind::Unavailable));
        }
        if let Some(barrier) = &self.fill_barrier {
            barrier.wait().await;
        }
        Ok(RepositorySnapshot::from_bytes(
            self.provider.clone(),
            request.repository().clone(),
            request.revision().clone(),
            ResolvedRevision::new(SHA).unwrap(),
            ArchiveFormat::TarGzip,
            self.archive.clone(),
        ))
    }
}

#[derive(Debug)]
struct FixedIndex(IndexedActionBundle);

#[async_trait]
impl ActionReferenceIndex for FixedIndex {
    async fn get(
        &self,
        _reference: &ImmutableActionReference,
    ) -> Result<Option<IndexedActionBundle>, ActionReferenceIndexError> {
        Ok(Some(self.0.clone()))
    }

    async fn put_if_absent(
        &self,
        _bundle: IndexedActionBundle,
    ) -> Result<PutActionReferenceOutcome, ActionReferenceIndexError> {
        Ok(PutActionReferenceOutcome::AlreadyPresent)
    }
}

#[derive(Debug)]
struct CorruptingBlobStore;

#[async_trait]
impl ImmutableBlobStore for CorruptingBlobStore {
    async fn put_if_absent(&self, _payload: BlobPayload) -> Result<PutBlobOutcome, BlobStoreError> {
        Err(BlobStoreError::new(BlobStoreErrorKind::Integrity))
    }

    async fn get_verified(
        &self,
        _descriptor: &automata_blob::BlobDescriptor,
        _maximum_bytes: u64,
    ) -> Result<VerifiedBlob, BlobStoreError> {
        Err(BlobStoreError::new(BlobStoreErrorKind::Integrity))
    }
}

#[tokio::test]
async fn warm_full_sha_hit_works_with_scm_offline_and_preserves_provenance() {
    let archive = valid_archive();
    let scm = Arc::new(SwitchableScm::new(archive));
    let blobs = Arc::new(MemoryBlobStore::default());
    let references = Arc::new(MemoryActionReferenceIndex::new(8).unwrap());
    let resolver = ImmutableActionResolver::new(scm.clone(), blobs.clone())
        .with_reference_index(references.clone());
    let repository = RepositoryId::new("actions/example").unwrap();
    let revision = RevisionSpec::new(SHA).unwrap();
    let subpath = ActionSubpath::new("packages/action").unwrap();

    let first = resolver
        .resolve(request(&repository, &revision, &subpath))
        .await
        .unwrap();
    scm.offline.store(true, Ordering::SeqCst);
    let restarted =
        ImmutableActionResolver::new(scm.clone(), blobs).with_reference_index(references);
    let replay = restarted
        .resolve(request(&repository, &revision, &subpath))
        .await
        .unwrap();
    assert_eq!(first, replay);
    assert_eq!(replay.provider().as_str(), "github");
    assert_eq!(replay.repository(), &repository);
    assert_eq!(replay.requested_revision(), &revision);
    assert_eq!(replay.resolved_revision().as_str(), SHA);
    assert_eq!(replay.subpath(), &subpath);
    assert_eq!(scm.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn mutable_reference_is_resolved_by_scm_every_time() {
    let scm = Arc::new(SwitchableScm::new(valid_archive()));
    let resolver = ImmutableActionResolver::new(scm.clone(), Arc::new(MemoryBlobStore::default()))
        .with_reference_index(Arc::new(MemoryActionReferenceIndex::new(8).unwrap()));
    let repository = RepositoryId::new("actions/example").unwrap();
    let revision = RevisionSpec::new("v6").unwrap();
    let subpath = ActionSubpath::new("packages/action").unwrap();

    resolver
        .resolve(request(&repository, &revision, &subpath))
        .await
        .unwrap();
    resolver
        .resolve(request(&repository, &revision, &subpath))
        .await
        .unwrap();
    assert_eq!(scm.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn index_cannot_substitute_provider_repository_revision_or_subpath() {
    let archive = valid_archive();
    let payload = archive_payload(archive);
    let repository = RepositoryId::new("actions/example").unwrap();
    let revision = RevisionSpec::new(SHA).unwrap();
    let subpath = ActionSubpath::new("packages/action").unwrap();
    let wrong_references = [
        immutable("gitlab", "actions/example", SHA, "packages/action"),
        immutable("github", "attacker/example", SHA, "packages/action"),
        immutable(
            "github",
            "actions/example",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "packages/action",
        ),
        immutable("github", "actions/example", SHA, "other/action"),
    ];

    for wrong in wrong_references {
        let resolved_revision = ResolvedRevision::new(wrong.revision().as_str()).unwrap();
        let indexed =
            IndexedActionBundle::new(wrong, resolved_revision, payload.descriptor().clone())
                .unwrap();
        let scm = Arc::new(SwitchableScm::new(valid_archive()));
        scm.offline.store(true, Ordering::SeqCst);
        let resolver =
            ImmutableActionResolver::new(scm.clone(), Arc::new(MemoryBlobStore::default()))
                .with_reference_index(Arc::new(FixedIndex(indexed)));
        let error = resolver
            .resolve(request(&repository, &revision, &subpath))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ActionResolveErrorKind::ReferenceCache);
        assert_eq!(scm.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn missing_or_corrupt_indexed_blob_fails_without_scm_fallback() {
    let archive = valid_archive();
    let payload = archive_payload(archive);
    let reference = immutable("github", "actions/example", SHA, "packages/action");
    let indexed = IndexedActionBundle::new(
        reference,
        ResolvedRevision::new(SHA).unwrap(),
        payload.descriptor().clone(),
    )
    .unwrap();
    let repository = RepositoryId::new("actions/example").unwrap();
    let revision = RevisionSpec::new(SHA).unwrap();
    let subpath = ActionSubpath::new("packages/action").unwrap();

    for blobs in [
        Arc::new(MemoryBlobStore::default()) as Arc<dyn ImmutableBlobStore>,
        Arc::new(CorruptingBlobStore) as Arc<dyn ImmutableBlobStore>,
    ] {
        let scm = Arc::new(SwitchableScm::new(valid_archive()));
        scm.offline.store(true, Ordering::SeqCst);
        let resolver = ImmutableActionResolver::new(scm.clone(), blobs)
            .with_reference_index(Arc::new(FixedIndex(indexed.clone())));
        let error = resolver
            .resolve(request(&repository, &revision, &subpath))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ActionResolveErrorKind::BlobStore);
        assert_eq!(scm.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn verified_cached_bytes_are_still_reinspected_as_an_action_archive() {
    let payload = archive_payload(Bytes::from_static(b"not a gzip archive"));
    let reference = immutable("github", "actions/example", SHA, "packages/action");
    let indexed = IndexedActionBundle::new(
        reference,
        ResolvedRevision::new(SHA).unwrap(),
        payload.descriptor().clone(),
    )
    .unwrap();
    let blobs = Arc::new(MemoryBlobStore::default());
    blobs.put_if_absent(payload).await.unwrap();
    let scm = Arc::new(SwitchableScm::new(valid_archive()));
    scm.offline.store(true, Ordering::SeqCst);
    let resolver = ImmutableActionResolver::new(scm.clone(), blobs)
        .with_reference_index(Arc::new(FixedIndex(indexed)));
    let repository = RepositoryId::new("actions/example").unwrap();
    let revision = RevisionSpec::new(SHA).unwrap();
    let subpath = ActionSubpath::new("packages/action").unwrap();
    let error = resolver
        .resolve(request(&repository, &revision, &subpath))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ActionResolveErrorKind::Archive);
    assert_eq!(scm.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn concurrent_identical_fill_is_idempotent_and_then_offline() {
    let scm = Arc::new(SwitchableScm::concurrent(valid_archive()));
    let references = Arc::new(MemoryActionReferenceIndex::new(8).unwrap());
    let blobs = Arc::new(MemoryBlobStore::default());
    let resolver =
        Arc::new(ImmutableActionResolver::new(scm.clone(), blobs).with_reference_index(references));
    let repository = RepositoryId::new("actions/example").unwrap();
    let revision = RevisionSpec::new(SHA).unwrap();
    let subpath = ActionSubpath::new("packages/action").unwrap();
    let first = resolver.resolve(request(&repository, &revision, &subpath));
    let second = resolver.resolve(request(&repository, &revision, &subpath));
    let (first, second) = tokio::join!(first, second);
    assert_eq!(first.unwrap(), second.unwrap());
    assert_eq!(scm.calls.load(Ordering::SeqCst), 2);

    scm.offline.store(true, Ordering::SeqCst);
    resolver
        .resolve(request(&repository, &revision, &subpath))
        .await
        .unwrap();
    assert_eq!(scm.calls.load(Ordering::SeqCst), 2);
}

fn valid_archive() -> Bytes {
    build_archive(&[
        TestEntry::File(
            "root/packages/action/action.yml",
            b"name: cached\nruns:\n  using: node24\n  main: dist/index.js\n",
        ),
        TestEntry::File(
            "root/packages/action/dist/index.js",
            b"console.log('cached')",
        ),
    ])
}

fn request<'a>(
    repository: &'a RepositoryId,
    revision: &'a RevisionSpec,
    subpath: &'a ActionSubpath,
) -> RepositoryActionRequest<'a> {
    RepositoryActionRequest::public(repository, revision, subpath, ActionBundleLimits::default())
}

fn immutable(
    provider: &str,
    repository: &str,
    revision: &str,
    subpath: &str,
) -> ImmutableActionReference {
    ImmutableActionReference::new(
        ScmProviderId::new(provider).unwrap(),
        RepositoryId::new(repository).unwrap(),
        RevisionSpec::new(revision).unwrap(),
        ActionSubpath::new(subpath).unwrap(),
    )
    .unwrap()
}

fn archive_payload(bytes: Bytes) -> BlobPayload {
    BlobPayload::from_bytes(
        BlobKey::new(format!(
            "actions/v1/sha256/{}.tar.gz",
            automata_core::Sha256Digest::from_bytes(Sha256::digest(&bytes).into())
        ))
        .unwrap(),
        MediaType::new("application/gzip").unwrap(),
        bytes,
    )
}
