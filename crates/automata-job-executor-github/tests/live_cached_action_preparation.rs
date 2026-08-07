use std::{
    env, fmt, fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use automata_action::{
    ActionBundleLimits, ActionReferenceIndex, ActionResolver, ActionSubpath,
    ImmutableActionReference, ImmutableActionResolver, IndexedActionBundle,
};
use automata_action_cache_file::{
    ActionReferenceIndexLimits, ActionReferenceIndexRoot, FileActionReferenceIndex,
};
use automata_action_github::{GithubActionMetadataDecoder, JavascriptRuntime};
use automata_blob::{
    BlobDescriptor, BlobKey, BlobPayload, BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore,
    MediaType, PutBlobOutcome, VerifiedBlob,
};
use automata_blob_s3::{S3BlobStore, S3BlobStoreConfig, StaticS3Credentials};
use automata_core::{ActionReference, Sha256Digest};
use automata_job_executor_github::{
    ActionPreparationPort, ActionPreparationRequest, NoRepositoryCredentials,
    ResolvedBundleActionPreparer,
};
use automata_scm::{
    RepositoryId, RepositorySnapshot, ResolvedRevision, RevisionSpec, ScmError, ScmErrorKind,
    ScmProvider, ScmProviderId, SnapshotRequest,
};
use automata_workflow_github::GithubConditionCompiler;

const SETUP_NODE_COMMIT: &str = "48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e";
const SETUP_NODE_ARCHIVE_DIGEST: &str =
    "aefc631800117b35e99f36c1395c361a2a6c6ae364ff47a3ba48c684cd3d3aff";
const SETUP_NODE_ARCHIVE_BYTES: u64 = 1_928_350;

/// Opt-in read-only regression for the exact warm-cache preparation path used
/// by the production runner. It never contacts GitHub or writes an S3 object.
#[tokio::test]
#[ignore = "requires an explicitly configured S3-compatible store containing the pinned setup-node archive"]
async fn prepares_pinned_setup_node_from_a_durable_warm_cache() {
    let endpoint = env::var("AUTOMATA_TEST_S3_ENDPOINT")
        .expect("AUTOMATA_TEST_S3_ENDPOINT")
        .parse()
        .expect("test S3 endpoint URL");
    let bucket = env::var("AUTOMATA_TEST_S3_BUCKET").expect("AUTOMATA_TEST_S3_BUCKET");
    let prefix = env::var("AUTOMATA_TEST_S3_PREFIX").expect("AUTOMATA_TEST_S3_PREFIX");
    let config = S3BlobStoreConfig::loopback_development(
        endpoint,
        "us-east-1",
        bucket,
        Some(prefix),
        Duration::from_secs(30),
    )
    .expect("test S3 configuration");
    let credentials = StaticS3Credentials::new(
        env::var("AUTOMATA_TEST_S3_ACCESS_KEY").expect("AUTOMATA_TEST_S3_ACCESS_KEY"),
        env::var("AUTOMATA_TEST_S3_SECRET_KEY").expect("AUTOMATA_TEST_S3_SECRET_KEY"),
        None,
    )
    .expect("test S3 credentials");
    let observed_blobs = Arc::new(ReadOnlyObservedBlobStore::new(S3BlobStore::new(
        config.client(credentials),
        &config,
    )));

    let scratch = Scratch::new();
    let references = Arc::new(
        FileActionReferenceIndex::open(scratch.root(), ActionReferenceIndexLimits::default())
            .expect("open isolated action reference index"),
    );
    let repository = RepositoryId::new("actions/setup-node").expect("repository");
    let revision = RevisionSpec::new(SETUP_NODE_COMMIT).expect("revision");
    let subpath = ActionSubpath::root();
    let immutable_reference = ImmutableActionReference::new(
        ScmProviderId::new("github").expect("provider"),
        repository.clone(),
        revision.clone(),
        subpath,
    )
    .expect("immutable reference");
    let archive = setup_node_archive();
    references
        .put_if_absent(
            IndexedActionBundle::new(
                immutable_reference,
                ResolvedRevision::new(SETUP_NODE_COMMIT).expect("resolved revision"),
                archive.clone(),
            )
            .expect("indexed action bundle"),
        )
        .await
        .expect("seed isolated reference index");

    let scm = Arc::new(OfflineScm::new());
    let blobs: Arc<dyn ImmutableBlobStore> = observed_blobs.clone();
    let resolver: Arc<dyn ActionResolver> = Arc::new(
        ImmutableActionResolver::new(scm.clone(), Arc::clone(&blobs))
            .with_reference_index(references),
    );
    let adapter = ResolvedBundleActionPreparer::new(
        resolver,
        blobs,
        Arc::new(NoRepositoryCredentials),
        Arc::new(GithubActionMetadataDecoder::default()),
        GithubConditionCompiler::default(),
        ActionBundleLimits::default(),
        automata_execution::MAX_COPY_BYTES as u64,
    )
    .expect("action preparer");
    let reference = ActionReference::Repository {
        repository: repository.as_str().to_owned(),
        revision: revision.as_str().to_owned(),
        subpath: None,
    };

    let prepared = adapter
        .prepare(ActionPreparationRequest::new(&reference))
        .await
        .unwrap_or_else(|error| {
            panic!(
                "warm-cache setup-node preparation failed: preparation={:?}, blob_reads={:?}",
                error.kind(),
                observed_blobs.observations()
            )
        });

    assert_eq!(scm.fetches(), 0, "warm cache must bypass GitHub");
    assert_eq!(
        observed_blobs.observations(),
        [BlobReadObservation::Verified, BlobReadObservation::Verified]
    );
    assert_eq!(prepared.archive_digest(), archive.digest());
    assert_eq!(prepared.archive().len() as u64, SETUP_NODE_ARCHIVE_BYTES);
    assert_eq!(prepared.javascript().runtime(), JavascriptRuntime::Node24);
    assert_eq!(prepared.javascript().main(), "dist/setup/index.js");
    assert_eq!(
        prepared.javascript().post(),
        Some("dist/cache-save/index.js")
    );
}

fn setup_node_archive() -> BlobDescriptor {
    let digest = SETUP_NODE_ARCHIVE_DIGEST
        .parse::<Sha256Digest>()
        .expect("archive digest");
    BlobDescriptor::new(
        BlobKey::new(format!("actions/v1/sha256/{digest}.tar.gz")).expect("archive key"),
        digest,
        SETUP_NODE_ARCHIVE_BYTES,
        MediaType::new("application/gzip").expect("archive media type"),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BlobReadObservation {
    Verified,
    Failed(BlobStoreErrorKind),
}

struct ReadOnlyObservedBlobStore {
    inner: S3BlobStore,
    observations: Mutex<Vec<BlobReadObservation>>,
}

impl ReadOnlyObservedBlobStore {
    fn new(inner: S3BlobStore) -> Self {
        Self {
            inner,
            observations: Mutex::new(Vec::new()),
        }
    }

    fn observations(&self) -> Vec<BlobReadObservation> {
        self.observations.lock().expect("observation lock").clone()
    }
}

impl fmt::Debug for ReadOnlyObservedBlobStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadOnlyObservedBlobStore")
            .field("observations", &self.observations())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl ImmutableBlobStore for ReadOnlyObservedBlobStore {
    async fn put_if_absent(&self, _payload: BlobPayload) -> Result<PutBlobOutcome, BlobStoreError> {
        Err(BlobStoreError::new(BlobStoreErrorKind::InvalidResponse))
    }

    async fn get_verified(
        &self,
        descriptor: &BlobDescriptor,
        maximum_bytes: u64,
    ) -> Result<VerifiedBlob, BlobStoreError> {
        let result = self.inner.get_verified(descriptor, maximum_bytes).await;
        let observation = match &result {
            Ok(_) => BlobReadObservation::Verified,
            Err(error) => BlobReadObservation::Failed(error.kind()),
        };
        self.observations
            .lock()
            .expect("observation lock")
            .push(observation);
        result
    }
}

#[derive(Debug)]
struct OfflineScm {
    provider: ScmProviderId,
    fetches: std::sync::atomic::AtomicUsize,
}

impl OfflineScm {
    fn new() -> Self {
        Self {
            provider: ScmProviderId::new("github").expect("provider"),
            fetches: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn fetches(&self) -> usize {
        self.fetches.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait]
impl ScmProvider for OfflineScm {
    fn provider_id(&self) -> &ScmProviderId {
        &self.provider
    }

    async fn fetch_snapshot(
        &self,
        _request: SnapshotRequest<'_>,
    ) -> Result<RepositorySnapshot, ScmError> {
        self.fetches
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(ScmError::new(ScmErrorKind::Unavailable))
    }
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("crate is inside workspace crates directory");
        Self(
            workspace
                .join("target/task-tmp/live-cached-action-preparation")
                .join(format!("{}-setup-node", std::process::id())),
        )
    }

    fn root(&self) -> ActionReferenceIndexRoot {
        ActionReferenceIndexRoot::explicit(self.0.clone()).expect("scratch root")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if self.0.exists() {
            fs::remove_dir_all(&self.0).expect("remove test scratch");
        }
    }
}
