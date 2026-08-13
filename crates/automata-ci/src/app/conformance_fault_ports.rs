//! Typed conformance-fault wrappers for real product ports.

use std::sync::Arc;

use async_trait::async_trait;
use automata_ci_blob::{
    BlobDescriptor, BlobPayload, BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore,
    PutBlobOutcome, VerifiedBlob,
};
use automata_ci_conformance::FaultMode;
use automata_ci_credential::{
    CredentialError, CredentialErrorKind, IssuedRepositoryCredential, RepositoryCredentialBroker,
    RepositoryCredentialRequest,
};
use automata_ci_github_delivery::{
    GithubChecksCredentialProvider, GithubChecksCredentialProviderError,
    GithubChecksCredentialRequest, GithubChecksServerServiceCredential,
};
use automata_ci_results_github::{
    ArtifactBlockReservation, ArtifactFinalizationReservation, ArtifactFinalizationWork,
    ArtifactRepository, ArtifactRepositoryError, ArtifactRepositoryErrorKind,
    BeginArtifactFinalization, CommitArtifactBlocks, CommittedArtifact, CompleteArtifactBlock,
    CompleteArtifactFinalization, CreateArtifact, CreateArtifactOutcome, FinalizeArtifactOutcome,
    ListArtifacts, LoadArtifactFinalization, PublishedArtifactMetadata, RecordArtifactVerification,
    RenewArtifactFinalization, ReserveArtifactBlock, ResolveArtifactDownload,
};
use automata_ci_runner_runtime::{
    RunnerRuntimeControlClient, RuntimeControlError, RuntimeControlErrorKind, RuntimeControlFuture,
    RuntimeControlRetry,
};
use automata_ci_runner_transport::{ControlRoute, PreparedRequest};
use automata_ci_scm::{
    RepositorySource, RepositorySourcePort, RepositorySourceRequest, ScmError, ScmErrorKind,
    ScmProviderId,
};
use tokio_util::sync::CancellationToken;

use super::conformance_control::{InjectedProductFault, ProductFaultGate, ProductFaultOperation};

/// Exact-revision source adapter with a deterministic failure boundary.
#[derive(Debug)]
pub struct ConformanceRepositorySource {
    inner: Arc<dyn RepositorySourcePort>,
    faults: Arc<ProductFaultGate>,
}

impl ConformanceRepositorySource {
    /// Wraps a configured source port with an operation-specific fixture gate.
    #[must_use]
    pub const fn new(inner: Arc<dyn RepositorySourcePort>, faults: Arc<ProductFaultGate>) -> Self {
        Self { inner, faults }
    }
}

#[async_trait]
impl RepositorySourcePort for ConformanceRepositorySource {
    fn provider_id(&self) -> &ScmProviderId {
        self.inner.provider_id()
    }

    async fn fetch_repository_source(
        &self,
        request: RepositorySourceRequest<'_>,
    ) -> Result<RepositorySource, ScmError> {
        if let Some(fault) = take_or_source_error(&self.faults, ProductFaultOperation::SourceFetch)?
        {
            return Err(source_error(fault.mode()));
        }
        self.inner.fetch_repository_source(request).await
    }
}

/// Repository-credential broker with a deterministic issuance failure boundary.
#[derive(Debug)]
pub struct ConformanceRepositoryCredentialBroker {
    inner: Arc<dyn RepositoryCredentialBroker>,
    faults: Arc<ProductFaultGate>,
}

impl ConformanceRepositoryCredentialBroker {
    /// Wraps a configured credential broker with an issuance fixture gate.
    #[must_use]
    pub const fn new(
        inner: Arc<dyn RepositoryCredentialBroker>,
        faults: Arc<ProductFaultGate>,
    ) -> Self {
        Self { inner, faults }
    }
}

#[async_trait]
impl RepositoryCredentialBroker for ConformanceRepositoryCredentialBroker {
    fn provider_id(&self) -> &ScmProviderId {
        self.inner.provider_id()
    }

    async fn issue(
        &self,
        request: &RepositoryCredentialRequest,
    ) -> Result<IssuedRepositoryCredential, CredentialError> {
        if let Some(fault) = take_or_credential_error(&self.faults)? {
            return Err(credential_error(fault.mode()));
        }
        self.inner.issue(request).await
    }
}

/// Immutable object store with operation-specific read and write fault sites.
#[derive(Debug)]
pub struct ConformanceBlobStore {
    inner: Arc<dyn ImmutableBlobStore>,
    faults: Arc<ProductFaultGate>,
}

impl ConformanceBlobStore {
    /// Wraps a configured immutable store with independent read and write gates.
    #[must_use]
    pub const fn new(inner: Arc<dyn ImmutableBlobStore>, faults: Arc<ProductFaultGate>) -> Self {
        Self { inner, faults }
    }
}

#[async_trait]
impl ImmutableBlobStore for ConformanceBlobStore {
    async fn put_if_absent(&self, payload: BlobPayload) -> Result<PutBlobOutcome, BlobStoreError> {
        let fault = prepare_blob_mutation(take_or_blob_error(
            &self.faults,
            ProductFaultOperation::ObjectWrite,
        )?)?;
        finish_blob_mutation(self.inner.put_if_absent(payload).await, fault.as_ref())
    }

    async fn get_verified(
        &self,
        descriptor: &BlobDescriptor,
        maximum_bytes: u64,
    ) -> Result<VerifiedBlob, BlobStoreError> {
        if let Some(fault) = take_or_blob_error(&self.faults, ProductFaultOperation::ObjectRead)? {
            return Err(blob_error(fault.mode()));
        }
        self.inner.get_verified(descriptor, maximum_bytes).await
    }
}

/// Results artifact repository with mutation, finalization, and read fault sites.
#[derive(Debug)]
pub struct ConformanceArtifactRepository {
    inner: Arc<dyn ArtifactRepository>,
    faults: Arc<ProductFaultGate>,
}

impl ConformanceArtifactRepository {
    /// Wraps a configured repository with lifecycle-specific Results gates.
    #[must_use]
    pub const fn new(inner: Arc<dyn ArtifactRepository>, faults: Arc<ProductFaultGate>) -> Self {
        Self { inner, faults }
    }

    fn fault(
        &self,
        operation: ProductFaultOperation,
    ) -> Result<Option<InjectedProductFault>, ArtifactRepositoryError> {
        self.faults
            .take_due(operation)
            .map_err(|_| ArtifactRepositoryError::new(ArtifactRepositoryErrorKind::CorruptData))
    }
}

#[async_trait]
impl ArtifactRepository for ConformanceArtifactRepository {
    async fn create(
        &self,
        request: CreateArtifact,
    ) -> Result<CreateArtifactOutcome, ArtifactRepositoryError> {
        let fault = self.mutation()?;
        finish_artifact_mutation(self.inner.create(request).await, fault.as_ref())
    }

    async fn reserve_block(
        &self,
        request: ReserveArtifactBlock,
    ) -> Result<ArtifactBlockReservation, ArtifactRepositoryError> {
        let fault = self.mutation()?;
        finish_artifact_mutation(self.inner.reserve_block(request).await, fault.as_ref())
    }

    async fn complete_block(
        &self,
        request: CompleteArtifactBlock,
    ) -> Result<(), ArtifactRepositoryError> {
        let fault = self.mutation()?;
        finish_artifact_mutation(self.inner.complete_block(request).await, fault.as_ref())
    }

    async fn commit_blocks(
        &self,
        request: CommitArtifactBlocks,
    ) -> Result<CommittedArtifact, ArtifactRepositoryError> {
        let fault = self.mutation()?;
        finish_artifact_mutation(self.inner.commit_blocks(request).await, fault.as_ref())
    }

    async fn begin_finalization(
        &self,
        request: BeginArtifactFinalization,
    ) -> Result<ArtifactFinalizationReservation, ArtifactRepositoryError> {
        let fault = self.finalization()?;
        finish_artifact_mutation(self.inner.begin_finalization(request).await, fault.as_ref())
    }

    async fn load_finalization(
        &self,
        request: LoadArtifactFinalization,
    ) -> Result<ArtifactFinalizationWork, ArtifactRepositoryError> {
        let fault = self.finalization()?;
        finish_artifact_mutation(self.inner.load_finalization(request).await, fault.as_ref())
    }

    async fn renew_finalization(
        &self,
        request: RenewArtifactFinalization,
    ) -> Result<(), ArtifactRepositoryError> {
        let fault = self.finalization()?;
        finish_artifact_mutation(self.inner.renew_finalization(request).await, fault.as_ref())
    }

    async fn record_verification(
        &self,
        request: RecordArtifactVerification,
    ) -> Result<(), ArtifactRepositoryError> {
        let fault = self.finalization()?;
        finish_artifact_mutation(
            self.inner.record_verification(request).await,
            fault.as_ref(),
        )
    }

    async fn complete_finalization(
        &self,
        request: CompleteArtifactFinalization,
    ) -> Result<FinalizeArtifactOutcome, ArtifactRepositoryError> {
        let fault = self.finalization()?;
        finish_artifact_mutation(
            self.inner.complete_finalization(request).await,
            fault.as_ref(),
        )
    }

    async fn list(
        &self,
        request: ListArtifacts,
    ) -> Result<Vec<PublishedArtifactMetadata>, ArtifactRepositoryError> {
        self.read()?;
        self.inner.list(request).await
    }

    async fn resolve_download(
        &self,
        request: ResolveArtifactDownload,
    ) -> Result<PublishedArtifactMetadata, ArtifactRepositoryError> {
        self.read()?;
        self.inner.resolve_download(request).await
    }
}

impl ConformanceArtifactRepository {
    fn mutation(&self) -> Result<Option<InjectedProductFault>, ArtifactRepositoryError> {
        prepare_artifact_mutation(self.fault(ProductFaultOperation::ResultsMutation)?)
    }

    fn finalization(&self) -> Result<Option<InjectedProductFault>, ArtifactRepositoryError> {
        prepare_artifact_mutation(self.fault(ProductFaultOperation::ResultsFinalization)?)
    }

    fn read(&self) -> Result<(), ArtifactRepositoryError> {
        if let Some(fault) = self.fault(ProductFaultOperation::ResultsRead)? {
            return Err(artifact_error(fault.mode()));
        }
        Ok(())
    }
}

/// GitHub Checks credential boundary with deterministic publication failures.
#[derive(Debug)]
pub struct ConformanceGithubChecksCredentialProvider {
    inner: Arc<dyn GithubChecksCredentialProvider>,
    faults: Arc<ProductFaultGate>,
}

impl ConformanceGithubChecksCredentialProvider {
    /// Wraps a configured authority at the pre-publication credential boundary.
    #[must_use]
    pub const fn new(
        inner: Arc<dyn GithubChecksCredentialProvider>,
        faults: Arc<ProductFaultGate>,
    ) -> Self {
        Self { inner, faults }
    }
}

#[async_trait]
impl GithubChecksCredentialProvider for ConformanceGithubChecksCredentialProvider {
    async fn acquire(
        &self,
        request: GithubChecksCredentialRequest<'_>,
    ) -> Result<GithubChecksServerServiceCredential, GithubChecksCredentialProviderError> {
        match self
            .faults
            .take_due(ProductFaultOperation::ChecksCredential)
        {
            Ok(Some(fault)) => return Err(checks_error(fault.mode())),
            Ok(None) => {}
            Err(_) => return Err(GithubChecksCredentialProviderError::InvariantViolation),
        }
        self.inner.acquire(request).await
    }
}

/// Runner-side control client with separate handshake and synchronized-operation sites.
#[derive(Debug)]
pub struct ConformanceRunnerControlClient {
    inner: Arc<dyn RunnerRuntimeControlClient>,
    faults: Arc<ProductFaultGate>,
}

impl ConformanceRunnerControlClient {
    /// Wraps a configured runner client with handshake and sync fixture gates.
    #[must_use]
    pub const fn new(
        inner: Arc<dyn RunnerRuntimeControlClient>,
        faults: Arc<ProductFaultGate>,
    ) -> Self {
        Self { inner, faults }
    }

    fn preflight(&self, operation: ProductFaultOperation) -> Result<(), RuntimeControlError> {
        match self.faults.take_due(operation) {
            Ok(Some(fault)) => Err(runner_error(fault.mode())),
            Ok(None) => Ok(()),
            Err(_) => Err(RuntimeControlError::new(
                RuntimeControlErrorKind::InvalidResponse,
                RuntimeControlRetry::Never,
            )),
        }
    }
}

impl RunnerRuntimeControlClient for ConformanceRunnerControlClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            let operation = match request.route() {
                ControlRoute::Handshake => ProductFaultOperation::RunnerHandshake,
                ControlRoute::Sync => ProductFaultOperation::RunnerSync,
            };
            self.preflight(operation)?;
            self.inner.exchange(request, cancellation).await
        })
    }
}

fn take_or_source_error(
    faults: &ProductFaultGate,
    operation: ProductFaultOperation,
) -> Result<Option<InjectedProductFault>, ScmError> {
    faults
        .take_due(operation)
        .map_err(|_| ScmError::new(ScmErrorKind::InvalidResponse))
}

fn take_or_credential_error(
    faults: &ProductFaultGate,
) -> Result<Option<InjectedProductFault>, CredentialError> {
    faults
        .take_due(ProductFaultOperation::TokenIssue)
        .map_err(|_| CredentialError::new(CredentialErrorKind::InvalidResponse))
}

fn take_or_blob_error(
    faults: &ProductFaultGate,
    operation: ProductFaultOperation,
) -> Result<Option<InjectedProductFault>, BlobStoreError> {
    faults
        .take_due(operation)
        .map_err(|_| BlobStoreError::new(BlobStoreErrorKind::InvalidResponse))
}

fn prepare_blob_mutation(
    fault: Option<InjectedProductFault>,
) -> Result<Option<InjectedProductFault>, BlobStoreError> {
    match fault {
        Some(fault) if fault.mode() != &FaultMode::IndeterminateMutation => {
            Err(blob_error(fault.mode()))
        }
        fault => Ok(fault),
    }
}

fn finish_blob_mutation<T>(
    result: Result<T, BlobStoreError>,
    fault: Option<&InjectedProductFault>,
) -> Result<T, BlobStoreError> {
    match result {
        Ok(_) if fault.is_some_and(|fault| fault.mode() == &FaultMode::IndeterminateMutation) => {
            Err(blob_error(&FaultMode::IndeterminateMutation))
        }
        result => result,
    }
}

fn prepare_artifact_mutation(
    fault: Option<InjectedProductFault>,
) -> Result<Option<InjectedProductFault>, ArtifactRepositoryError> {
    match fault {
        Some(fault) if fault.mode() != &FaultMode::IndeterminateMutation => {
            Err(artifact_error(fault.mode()))
        }
        fault => Ok(fault),
    }
}

fn finish_artifact_mutation<T>(
    result: Result<T, ArtifactRepositoryError>,
    fault: Option<&InjectedProductFault>,
) -> Result<T, ArtifactRepositoryError> {
    match result {
        Ok(_) if fault.is_some_and(|fault| fault.mode() == &FaultMode::IndeterminateMutation) => {
            Err(artifact_error(&FaultMode::IndeterminateMutation))
        }
        result => result,
    }
}

fn source_error(mode: &FaultMode) -> ScmError {
    match mode {
        FaultMode::CredentialRejected => ScmError::new(ScmErrorKind::Unauthorized),
        FaultMode::RateLimited { retry_after_millis } => {
            ScmError::rate_limited(Some(retry_seconds(*retry_after_millis)))
        }
        FaultMode::CorruptResponse => ScmError::new(ScmErrorKind::InvalidResponse),
        FaultMode::Unavailable | FaultMode::IndeterminateMutation => {
            ScmError::new(ScmErrorKind::Unavailable)
        }
    }
}

fn credential_error(mode: &FaultMode) -> CredentialError {
    match mode {
        FaultMode::CredentialRejected => CredentialError::new(CredentialErrorKind::Unauthorized),
        FaultMode::RateLimited { retry_after_millis } => {
            CredentialError::rate_limited(Some(retry_seconds(*retry_after_millis)))
        }
        FaultMode::CorruptResponse => CredentialError::new(CredentialErrorKind::InvalidResponse),
        FaultMode::Unavailable | FaultMode::IndeterminateMutation => {
            CredentialError::new(CredentialErrorKind::Unavailable)
        }
    }
}

fn blob_error(mode: &FaultMode) -> BlobStoreError {
    let kind = match mode {
        FaultMode::CredentialRejected => BlobStoreErrorKind::Unauthorized,
        FaultMode::CorruptResponse => BlobStoreErrorKind::InvalidResponse,
        FaultMode::Unavailable
        | FaultMode::RateLimited { .. }
        | FaultMode::IndeterminateMutation => BlobStoreErrorKind::Unavailable,
    };
    BlobStoreError::new(kind)
}

fn artifact_error(mode: &FaultMode) -> ArtifactRepositoryError {
    let kind = match mode {
        FaultMode::CredentialRejected => ArtifactRepositoryErrorKind::Unauthorized,
        FaultMode::CorruptResponse => ArtifactRepositoryErrorKind::CorruptData,
        FaultMode::Unavailable
        | FaultMode::RateLimited { .. }
        | FaultMode::IndeterminateMutation => ArtifactRepositoryErrorKind::Unavailable,
    };
    ArtifactRepositoryError::new(kind)
}

fn checks_error(mode: &FaultMode) -> GithubChecksCredentialProviderError {
    match mode {
        FaultMode::CredentialRejected => GithubChecksCredentialProviderError::Rejected,
        FaultMode::CorruptResponse => GithubChecksCredentialProviderError::InvariantViolation,
        FaultMode::Unavailable
        | FaultMode::RateLimited { .. }
        | FaultMode::IndeterminateMutation => GithubChecksCredentialProviderError::Unavailable,
    }
}

fn runner_error(mode: &FaultMode) -> RuntimeControlError {
    let (kind, retry) = match mode {
        FaultMode::CredentialRejected | FaultMode::CorruptResponse => (
            RuntimeControlErrorKind::InvalidResponse,
            RuntimeControlRetry::Never,
        ),
        FaultMode::Unavailable
        | FaultMode::RateLimited { .. }
        | FaultMode::IndeterminateMutation => (
            RuntimeControlErrorKind::Unavailable,
            RuntimeControlRetry::SamePreparedRequest,
        ),
    };
    RuntimeControlError::new(kind, retry)
}

const fn retry_seconds(retry_after_millis: u64) -> u64 {
    retry_after_millis.saturating_add(999) / 1_000
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_repository_source<T: RepositorySourcePort>() {}
    fn assert_credential_broker<T: RepositoryCredentialBroker>() {}
    fn assert_blob_store<T: ImmutableBlobStore>() {}
    fn assert_artifact_repository<T: ArtifactRepository>() {}
    fn assert_checks_credentials<T: GithubChecksCredentialProvider>() {}
    fn assert_runner_client<T: RunnerRuntimeControlClient>() {}

    #[test]
    fn wrappers_implement_the_real_product_ports() {
        assert_repository_source::<ConformanceRepositorySource>();
        assert_credential_broker::<ConformanceRepositoryCredentialBroker>();
        assert_blob_store::<ConformanceBlobStore>();
        assert_artifact_repository::<ConformanceArtifactRepository>();
        assert_checks_credentials::<ConformanceGithubChecksCredentialProvider>();
        assert_runner_client::<ConformanceRunnerControlClient>();
    }

    #[test]
    fn fault_modes_map_to_closed_port_errors() {
        assert_eq!(
            source_error(&FaultMode::CredentialRejected).kind(),
            ScmErrorKind::Unauthorized
        );
        assert_eq!(
            credential_error(&FaultMode::RateLimited {
                retry_after_millis: 1_001,
            })
            .retry_after_seconds(),
            Some(2)
        );
        assert_eq!(
            blob_error(&FaultMode::CorruptResponse).kind(),
            BlobStoreErrorKind::InvalidResponse
        );
        assert_eq!(
            artifact_error(&FaultMode::IndeterminateMutation).kind(),
            ArtifactRepositoryErrorKind::Unavailable
        );
        assert_eq!(
            checks_error(&FaultMode::CredentialRejected),
            GithubChecksCredentialProviderError::Rejected
        );
        assert_eq!(
            runner_error(&FaultMode::Unavailable).kind(),
            RuntimeControlErrorKind::Unavailable
        );
    }
}
