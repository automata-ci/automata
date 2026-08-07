use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_action::{
    ActionBundleLimits, ActionResolveError, ActionResolveErrorKind, ActionResolver,
    RepositoryActionRequest, ResolvedActionBundle,
};
use automata_action_github::GithubActionMetadataDecoder;
use automata_blob::MemoryBlobStore;
use automata_core::ActionReference;
use automata_job_executor_github::{
    ActionPreparationErrorKind, ActionPreparationPort, ActionPreparationRequest,
    NoRepositoryCredentials, ResolvedBundleActionPreparer,
};
use automata_workflow_github::GithubConditionCompiler;

#[tokio::test]
async fn resolver_failures_map_to_their_sanitized_preparation_layer() {
    for (resolution, preparation) in [
        (
            ActionResolveErrorKind::Scm,
            ActionPreparationErrorKind::Resolution,
        ),
        (
            ActionResolveErrorKind::ReferenceCache,
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
            Arc::new(MemoryBlobStore::default()),
            Arc::new(NoRepositoryCredentials),
            Arc::new(GithubActionMetadataDecoder::default()),
            GithubConditionCompiler::default(),
            ActionBundleLimits::default(),
            automata_execution::MAX_COPY_BYTES as u64,
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
