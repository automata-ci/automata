use crate::support;

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use async_trait::async_trait;
use automata_ci_action::{
    ActionBundleLimits, ActionResolver, ActionSubpath, ImmutableActionResolver,
    MemoryActionReferenceIndex, ObjectActionReferenceIndex, ReadThroughActionReferenceIndex,
    RepositoryActionRequest,
};
use automata_ci_auth::secret::SecretString;
use automata_ci_blob::{ImmutableBlobStore, ImmutableRecordStore, MemoryBlobStore};
use automata_ci_scm::{
    ArchiveFormat, RepositoryId, RepositorySnapshot, ResolvedRevision, RevisionSpec, ScmError,
    ScmProvider, ScmProviderId, SnapshotRequest,
};
use bytes::Bytes;
use support::{SHA, TestEntry, build_archive};

#[derive(Debug)]
struct CountingScm {
    provider: ScmProviderId,
    archive: Bytes,
    calls: AtomicUsize,
    available: AtomicBool,
}

#[async_trait]
impl ScmProvider for CountingScm {
    fn provider_id(&self) -> &ScmProviderId {
        &self.provider
    }

    async fn fetch_snapshot(
        &self,
        request: SnapshotRequest<'_>,
    ) -> Result<RepositorySnapshot, ScmError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if !self.available.load(Ordering::SeqCst) {
            return Err(ScmError::new(automata_ci_scm::ScmErrorKind::Unavailable));
        }
        Ok(RepositorySnapshot::from_bytes(
            self.provider.clone(),
            request.repository().clone(),
            request.revision().clone(),
            ResolvedRevision::new(request.revision().as_str()).unwrap_or_else(|_| {
                ResolvedRevision::new(SHA).expect("fixture commit is an exact revision")
            }),
            ArchiveFormat::TarGzip,
            self.archive.clone(),
        ))
    }
}

#[tokio::test]
async fn shared_manifest_runs_warm_action_on_another_node_during_scm_outage() {
    let archive = build_archive(&[
        TestEntry::File(
            "root/action.yml",
            b"name: shared\nruns:\n  using: node24\n  main: dist/index.js\n",
        ),
        TestEntry::File("root/dist/index.js", b"console.log('shared')"),
    ]);
    let scm = Arc::new(CountingScm {
        provider: ScmProviderId::new("github").unwrap(),
        archive,
        calls: AtomicUsize::new(0),
        available: AtomicBool::new(true),
    });
    let shared_store = Arc::new(MemoryBlobStore::default());
    let repository = RepositoryId::new("actions/example").unwrap();
    let revision = RevisionSpec::new(SHA).unwrap();
    let subpath = ActionSubpath::root();

    let first = resolver_node(scm.clone(), shared_store.clone());
    first
        .resolve(RepositoryActionRequest::public(
            &repository,
            &revision,
            &subpath,
            ActionBundleLimits::default(),
        ))
        .await
        .unwrap();
    scm.available.store(false, Ordering::SeqCst);

    let second = resolver_node(scm.clone(), shared_store);
    second
        .resolve(RepositoryActionRequest::public(
            &repository,
            &revision,
            &subpath,
            ActionBundleLimits::default(),
        ))
        .await
        .expect("another node must resolve the warm action without SCM");
    assert_eq!(scm.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn public_exact_commit_warm_hit_skips_scm() {
    let (resolver, scm, repository, revision, subpath) = fixture(SHA);
    resolver
        .resolve(RepositoryActionRequest::public(
            &repository,
            &revision,
            &subpath,
            ActionBundleLimits::default(),
        ))
        .await
        .unwrap();
    resolver
        .resolve(RepositoryActionRequest::public(
            &repository,
            &revision,
            &subpath,
            ActionBundleLimits::default(),
        ))
        .await
        .unwrap();
    assert_eq!(scm.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn mutable_reference_never_enters_public_cache() {
    let (resolver, scm, repository, revision, subpath) = fixture("v6");
    for _ in 0..2 {
        resolver
            .resolve(RepositoryActionRequest::public(
                &repository,
                &revision,
                &subpath,
                ActionBundleLimits::default(),
            ))
            .await
            .unwrap();
    }
    assert_eq!(scm.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn authenticated_exact_commit_never_consults_public_cache() {
    let (resolver, scm, repository, revision, subpath) = fixture(SHA);
    let credential = SecretString::new("private-job-scoped-token").unwrap();
    for _ in 0..2 {
        resolver
            .resolve(RepositoryActionRequest::authenticated(
                &repository,
                &revision,
                &subpath,
                &credential,
                ActionBundleLimits::default(),
            ))
            .await
            .unwrap();
    }
    assert_eq!(scm.calls.load(Ordering::SeqCst), 2);
}

fn fixture(
    revision: &str,
) -> (
    ImmutableActionResolver,
    Arc<CountingScm>,
    RepositoryId,
    RevisionSpec,
    ActionSubpath,
) {
    let scm = Arc::new(CountingScm {
        provider: ScmProviderId::new("github").unwrap(),
        archive: build_archive(&[
            TestEntry::File(
                "root/action.yml",
                b"name: cached\nruns:\n  using: node24\n  main: dist/index.js\n",
            ),
            TestEntry::File("root/dist/index.js", b"console.log('cached')"),
        ]),
        calls: AtomicUsize::new(0),
        available: AtomicBool::new(true),
    });
    let resolver = ImmutableActionResolver::new(scm.clone(), Arc::new(MemoryBlobStore::default()))
        .with_reference_index(Arc::new(MemoryActionReferenceIndex::new(8).unwrap()));
    (
        resolver,
        scm,
        RepositoryId::new("actions/example").unwrap(),
        RevisionSpec::new(revision).unwrap(),
        ActionSubpath::root(),
    )
}

fn resolver_node(
    scm: Arc<CountingScm>,
    shared_store: Arc<MemoryBlobStore>,
) -> ImmutableActionResolver {
    let blobs: Arc<dyn ImmutableBlobStore> = shared_store.clone();
    let records: Arc<dyn ImmutableRecordStore> = shared_store;
    let shared = Arc::new(ObjectActionReferenceIndex::new(records));
    let local = Arc::new(MemoryActionReferenceIndex::new(8).unwrap());
    ImmutableActionResolver::new(scm, blobs).with_reference_index(Arc::new(
        ReadThroughActionReferenceIndex::new(local, shared),
    ))
}
