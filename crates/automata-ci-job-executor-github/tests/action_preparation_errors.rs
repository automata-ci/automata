use std::{
    fmt,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use automata_ci_action::{
    ActionBundleLimits, ActionResolveError, ActionResolveErrorKind, ActionResolver,
    ImmutableActionResolver, RepositoryActionRequest, ResolvedActionBundle,
};
use automata_ci_action_github::GithubActionMetadataDecoder;
use automata_ci_blob::{ImmutableBlobStore, MemoryBlobStore};
use automata_ci_core::ActionReference;
use automata_ci_job_executor_github::{
    ActionPreparationErrorKind, ActionPreparationPort, ActionPreparationRequest,
    NoRepositoryCredentials, ResolvedBundleActionPreparer,
};
use automata_ci_scm::{
    ArchiveLimits, RepositorySnapshot, ScmError, ScmErrorKind, ScmProvider, ScmProviderId,
    SnapshotRequest,
};
use automata_ci_workflow_github::GithubConditionCompiler;

#[tokio::test]
async fn public_and_arbitrary_action_fetches_never_receive_an_ambient_credential() {
    let scm = Arc::new(CredentialObservingScm::new());
    let blobs: Arc<dyn ImmutableBlobStore> = Arc::new(MemoryBlobStore::default());
    let resolver: Arc<dyn ActionResolver> = Arc::new(ImmutableActionResolver::new(
        scm.clone(),
        Arc::clone(&blobs),
    ));
    let preparer = ResolvedBundleActionPreparer::new(
        resolver,
        Arc::new(NoRepositoryCredentials),
        Arc::new(GithubActionMetadataDecoder::default()),
        GithubConditionCompiler::default(),
        ActionBundleLimits::default(),
        automata_ci_execution::MAX_COPY_BYTES as u64,
    )
    .expect("action preparer");

    for repository in ["actions/checkout", "untrusted-owner/private-action"] {
        let reference = ActionReference::Repository {
            repository: repository.to_owned(),
            revision: "de0fac2e4500dabe0009e67214ff5f5447ce83dd".to_owned(),
            subpath: None,
        };
        let error = preparer
            .prepare(ActionPreparationRequest::new(&reference))
            .await
            .expect_err("SCM fixture always fails after observing the request");
        assert_eq!(error.kind(), ActionPreparationErrorKind::Resolution);
    }

    assert_eq!(
        scm.observations(),
        [
            ("actions/checkout".to_owned(), false),
            ("untrusted-owner/private-action".to_owned(), false),
        ],
        "no action reference may inherit a runner credential"
    );
}

#[tokio::test]
async fn resolver_failures_map_to_their_sanitized_preparation_layer() {
    for (resolution, preparation) in [
        (
            ActionResolveErrorKind::Scm,
            ActionPreparationErrorKind::Resolution,
        ),
        (
            ActionResolveErrorKind::Archive,
            ActionPreparationErrorKind::Content,
        ),
        (
            ActionResolveErrorKind::BlobStore,
            ActionPreparationErrorKind::Content,
        ),
        (
            ActionResolveErrorKind::Internal,
            ActionPreparationErrorKind::Internal,
        ),
    ] {
        let preparer = ResolvedBundleActionPreparer::new(
            Arc::new(FailingResolver(resolution)),
            Arc::new(NoRepositoryCredentials),
            Arc::new(GithubActionMetadataDecoder::default()),
            GithubConditionCompiler::default(),
            ActionBundleLimits::default(),
            automata_ci_execution::MAX_COPY_BYTES as u64,
        )
        .expect("action preparer");
        let reference = ActionReference::Repository {
            repository: "actions/setup-node".to_owned(),
            revision: "48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e".to_owned(),
            subpath: None,
        };

        let error = preparer
            .prepare(ActionPreparationRequest::new(&reference))
            .await
            .expect_err("resolver fixture always fails");

        assert_eq!(error.kind(), preparation, "resolver kind {resolution:?}");
    }
}

#[test]
fn preparer_rejects_incoherent_archive_transfer_limits_before_resolution() {
    assert_eq!(
        ActionBundleLimits::default().compressed().maximum_bytes(),
        automata_ci_execution::MAX_COPY_BYTES as u64
    );
    let create = |limits, maximum_archive_bytes| {
        ResolvedBundleActionPreparer::new(
            Arc::new(FailingResolver(ActionResolveErrorKind::Internal)),
            Arc::new(NoRepositoryCredentials),
            Arc::new(GithubActionMetadataDecoder::default()),
            GithubConditionCompiler::default(),
            limits,
            maximum_archive_bytes,
        )
    };
    let smaller_read_bound = ActionBundleLimits::new(
        ArchiveLimits::new(1024).unwrap(),
        10,
        4096,
        1024,
        1024,
        4096,
    )
    .unwrap();

    for (limits, maximum_archive_bytes) in [
        (smaller_read_bound, 1023),
        (ActionBundleLimits::default(), 0),
        (
            ActionBundleLimits::default(),
            automata_ci_execution::MAX_COPY_BYTES as u64 + 1,
        ),
    ] {
        assert_eq!(
            create(limits, maximum_archive_bytes)
                .expect_err("invalid transfer limits must fail before resolution")
                .kind(),
            ActionPreparationErrorKind::ResourceExhausted
        );
    }
}

struct FailingResolver(ActionResolveErrorKind);

impl fmt::Debug for FailingResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("FailingResolver")
            .field(&self.0)
            .finish()
    }
}

#[async_trait]
impl ActionResolver for FailingResolver {
    async fn resolve(
        &self,
        _request: RepositoryActionRequest<'_>,
    ) -> Result<ResolvedActionBundle, ActionResolveError> {
        Err(ActionResolveError::new(self.0))
    }
}

struct CredentialObservingScm {
    provider: ScmProviderId,
    observations: Mutex<Vec<(String, bool)>>,
}

impl CredentialObservingScm {
    fn new() -> Self {
        Self {
            provider: ScmProviderId::new("github").expect("provider"),
            observations: Mutex::new(Vec::new()),
        }
    }

    fn observations(&self) -> Vec<(String, bool)> {
        self.observations.lock().expect("observation lock").clone()
    }
}

impl fmt::Debug for CredentialObservingScm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialObservingScm")
            .field("provider", &self.provider)
            .field("observations", &self.observations())
            .finish()
    }
}

#[async_trait]
impl ScmProvider for CredentialObservingScm {
    fn provider_id(&self) -> &ScmProviderId {
        &self.provider
    }

    async fn fetch_snapshot(
        &self,
        request: SnapshotRequest<'_>,
    ) -> Result<RepositorySnapshot, ScmError> {
        self.observations.lock().expect("observation lock").push((
            request.repository().as_str().to_owned(),
            request.credential().is_some(),
        ));
        Err(ScmError::new(ScmErrorKind::Unavailable))
    }
}
