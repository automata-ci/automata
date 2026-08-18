use std::{collections::BTreeMap, fmt, sync::Arc};

use automata_ci_auth::delegated_actor::RepositoryMutationActor;
use automata_ci_core::{
    ContextValue, GitObjectId, JobRuntimeContext, OperationId, SecretBinding, TrustActorEvidence,
    TrustActorKind, TrustAutomationKind, TrustEventKind, TrustEvidence, TrustOriginKind,
    TrustPolicy, TrustRepositoryEvidence, TrustSnapshot, TrustTokenRecursion,
    WorkflowEventProvenance, WorkflowId, canonical_git_ref,
};
use automata_ci_store::{
    AuthenticatedWorkflowDispatchSource, ResolveAuthenticatedWorkflowDispatchSource,
};
use automata_ci_store::{RepositoryId, TenantScope, WorkflowAdmissionIdempotency};
use automata_ci_workflow_actions::{
    CompilationDisposition, CompileWorkflowRequest, Diagnostic, GithubEventMetadata,
    GithubWorkflowCompiler, GithubWorkflowDispatchInputValue, GithubWorkflowDispatchInputs,
    GithubWorkflowDispatchInputsError, GithubWorkflowFrontend, ParseWorkflowRequest, SourceId,
    SourceOrigin, SourceProvenance, WorkflowFrontend as _,
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    AdmissionRepositoryCoordinates, WorkflowAdmissionError, WorkflowAdmissionRequest,
    WorkflowAdmissionRequestError, WorkflowAdmissionResult, WorkflowAdmissionService,
};

/// Immutable media type for a canonical, authenticated Automata manual-dispatch event.
pub const AUTOMATA_WORKFLOW_DISPATCH_EVIDENCE_V1_MEDIA_TYPE: &str =
    "application/vnd.automata.workflow-dispatch-evidence.v1+json";

const EVIDENCE_SCHEMA: u16 = 1;
const EVIDENCE_KIND: &str = "automata_workflow_dispatch";
const MAX_EVIDENCE_TEXT_BYTES: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkflowDispatchEvidenceLimitRejection {
    TextBytes,
}

const fn workflow_dispatch_evidence_text_byte_rejection(
    observed: usize,
) -> Option<WorkflowDispatchEvidenceLimitRejection> {
    if observed > MAX_EVIDENCE_TEXT_BYTES {
        return Some(WorkflowDispatchEvidenceLimitRejection::TextBytes);
    }
    None
}

/// Exact, authenticated target authorized for a control-plane manual dispatch.
#[derive(Clone, Eq, PartialEq)]
pub struct WorkflowDispatchAuthorization {
    actor: RepositoryMutationActor,
    repository_id: RepositoryId,
    workflow_id: WorkflowId,
}

impl fmt::Debug for WorkflowDispatchAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkflowDispatchAuthorization")
            .field("repository_id", &self.repository_id)
            .field("workflow_id", &self.workflow_id)
            .finish_non_exhaustive()
    }
}

impl WorkflowDispatchAuthorization {
    /// Creates exact repository/workflow authority supplied by authenticated ingress.
    ///
    /// # Errors
    ///
    /// Rejects nil durable target identities.
    pub fn new(
        actor: impl Into<RepositoryMutationActor>,
        repository_id: RepositoryId,
        workflow_id: WorkflowId,
    ) -> Result<Self, GithubWorkflowDispatchRequestError> {
        if repository_id.as_uuid().is_nil() || workflow_id.as_uuid().is_nil() {
            return Err(GithubWorkflowDispatchRequestError::InvalidTarget);
        }
        Ok(Self {
            actor: actor.into(),
            repository_id,
            workflow_id,
        })
    }

    /// Returns current mutation authority for transactional reauthorization.
    #[must_use]
    pub const fn actor(&self) -> &RepositoryMutationActor {
        &self.actor
    }

    /// Returns the exact durable repository target.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Returns the exact durable workflow target.
    #[must_use]
    pub const fn workflow_id(&self) -> WorkflowId {
        self.workflow_id
    }
}

/// Trusted, exact-source request to the Automata manual-dispatch application service.
#[derive(Clone)]
pub struct GithubWorkflowDispatchRequest {
    authorization: WorkflowDispatchAuthorization,
    repository: AdmissionRepositoryCoordinates,
    repository_owner_id: String,
    workflow_path: String,
    source: Bytes,
    commit_sha: GitObjectId,
    git_ref: String,
    workflow_name: String,
    inputs: GithubWorkflowDispatchInputs,
    operation_id: OperationId,
    display_title: Option<String>,
}

impl fmt::Debug for GithubWorkflowDispatchRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubWorkflowDispatchRequest")
            .field("repository_id", &self.authorization.repository_id)
            .field("workflow_id", &self.authorization.workflow_id)
            .field("operation_id", &self.operation_id)
            .field("source_size_bytes", &self.source.len())
            .field("input_count", &self.inputs.values().len())
            .finish_non_exhaustive()
    }
}

/// Exact control-plane request whose workflow bytes must be recovered from a
/// prior signed GitHub admission rather than accepted from the caller.
#[derive(Clone)]
pub struct DurableGithubWorkflowDispatchRequest {
    authorization: WorkflowDispatchAuthorization,
    git_ref: String,
    commit_sha: GitObjectId,
    inputs: GithubWorkflowDispatchInputs,
    operation_id: OperationId,
    display_title: Option<String>,
}

impl fmt::Debug for DurableGithubWorkflowDispatchRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableGithubWorkflowDispatchRequest")
            .field("repository_id", &self.authorization.repository_id)
            .field("workflow_id", &self.authorization.workflow_id)
            .field("operation_id", &self.operation_id)
            .field("input_count", &self.inputs.values().len())
            .finish_non_exhaustive()
    }
}

impl DurableGithubWorkflowDispatchRequest {
    /// Creates a durable-source dispatch request.
    #[must_use]
    pub fn new(
        authorization: WorkflowDispatchAuthorization,
        git_ref: impl Into<String>,
        commit_sha: GitObjectId,
        inputs: GithubWorkflowDispatchInputs,
        operation_id: OperationId,
    ) -> Self {
        Self {
            authorization,
            git_ref: git_ref.into(),
            commit_sha,
            inputs,
            operation_id,
            display_title: None,
        }
    }

    /// Sets an optional bounded display title.
    #[must_use]
    pub fn with_display_title(mut self, display_title: impl Into<String>) -> Self {
        self.display_title = Some(display_title.into());
        self
    }
}

impl GithubWorkflowDispatchRequest {
    /// Creates a request from a target/source pair already resolved by trusted
    /// control-plane composition.
    ///
    /// Repository authorization is not implied by construction. The durable
    /// adapter reauthorizes `runs:dispatch` transactionally.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        authorization: WorkflowDispatchAuthorization,
        repository: AdmissionRepositoryCoordinates,
        repository_owner_id: impl Into<String>,
        workflow_path: impl Into<String>,
        source: Bytes,
        commit_sha: GitObjectId,
        git_ref: impl Into<String>,
        inputs: GithubWorkflowDispatchInputs,
        operation_id: OperationId,
    ) -> Self {
        let workflow_path = workflow_path.into();
        Self {
            authorization,
            repository,
            repository_owner_id: repository_owner_id.into(),
            workflow_name: workflow_path.clone(),
            workflow_path,
            source,
            commit_sha,
            git_ref: git_ref.into(),
            inputs,
            operation_id,
            display_title: None,
        }
    }

    /// Sets the human-facing workflow name retained by the run projection.
    #[must_use]
    pub fn with_workflow_name(mut self, workflow_name: impl Into<String>) -> Self {
        self.workflow_name = workflow_name.into();
        self
    }

    /// Sets an optional bounded display title.
    #[must_use]
    pub fn with_display_title(mut self, display_title: impl Into<String>) -> Self {
        self.display_title = Some(display_title.into());
        self
    }

    fn validate(&self) -> Result<TenantScope, GithubWorkflowDispatchRequestError> {
        if self.repository.provider() != "github"
            || self.operation_id.as_uuid().is_nil()
            || !valid_text(&self.repository_owner_id)
            || !valid_text(&self.workflow_path)
            || !valid_text(&self.workflow_name)
            || self.source.is_empty()
            || !canonical_workflow_dispatch_ref(&self.git_ref)
            || !valid_text(&self.git_ref)
            || self
                .display_title
                .as_deref()
                .is_some_and(|value| !valid_text(value))
        {
            return Err(GithubWorkflowDispatchRequestError::InvalidTarget);
        }
        TenantScope::from_authenticated_tenant_id(self.authorization.actor().tenant_id().as_str())
            .map_err(|_| GithubWorkflowDispatchRequestError::InvalidAuthority)
    }
}

/// High-level, exact-source manual-dispatch application service.
#[derive(Clone, Debug)]
pub struct GithubWorkflowDispatchService {
    admission: WorkflowAdmissionService,
}

impl GithubWorkflowDispatchService {
    /// Creates the application service over durable workflow admission.
    #[must_use]
    pub const fn new(admission: WorkflowAdmissionService) -> Self {
        Self { admission }
    }

    /// Resolves exact workflow bytes only from a prior signed GitHub admission,
    /// then validates and admits a manual dispatch under current human authority.
    ///
    /// # Errors
    ///
    /// Fails closed when current authority is absent, no exact signed source
    /// exists for the repository/workflow/ref/commit tuple, immutable source
    /// verification fails, or dispatch admission rejects the request.
    pub async fn dispatch_from_durable_source(
        &self,
        request: DurableGithubWorkflowDispatchRequest,
    ) -> Result<WorkflowAdmissionResult, GithubWorkflowDispatchError> {
        if request.operation_id.as_uuid().is_nil()
            || !canonical_workflow_dispatch_ref(&request.git_ref)
            || !valid_text(&request.git_ref)
            || request
                .display_title
                .as_deref()
                .is_some_and(|value| !valid_text(value))
        {
            return Err(GithubWorkflowDispatchRequestError::InvalidTarget.into());
        }
        let lookup = ResolveAuthenticatedWorkflowDispatchSource::new(
            request.authorization.actor().clone(),
            request.authorization.repository_id(),
            request.authorization.workflow_id(),
            &request.git_ref,
            request.commit_sha,
        )
        .map_err(|_| GithubWorkflowDispatchRequestError::InvalidTarget)?;
        let Some((source, bytes)) = self
            .admission
            .resolve_authenticated_workflow_dispatch_source(lookup)
            .await?
        else {
            return Err(GithubWorkflowDispatchError::DurableSourceNotFound);
        };
        if source.repository().id() != request.authorization.repository_id()
            || source.workflow_id() != request.authorization.workflow_id()
            || source.git_ref() != request.git_ref
            || source.commit_sha() != request.commit_sha
        {
            return Err(GithubWorkflowDispatchError::DurableSourceMismatch);
        }
        self.dispatch_from_authenticated_source(
            request.authorization,
            source,
            bytes,
            request.inputs,
            request.operation_id,
            request.display_title,
        )
        .await
    }

    /// Dispatches source resolved and immutably pinned by trusted Core composition.
    ///
    /// # Errors
    ///
    /// Fails closed when the source target differs from current authorization,
    /// compilation rejects it, or durable admission fails.
    pub async fn dispatch_from_authenticated_source(
        &self,
        authorization: WorkflowDispatchAuthorization,
        source: AuthenticatedWorkflowDispatchSource,
        bytes: Bytes,
        inputs: GithubWorkflowDispatchInputs,
        operation_id: OperationId,
        display_title: Option<String>,
    ) -> Result<WorkflowAdmissionResult, GithubWorkflowDispatchError> {
        if source.repository().id() != authorization.repository_id()
            || source.workflow_id() != authorization.workflow_id()
        {
            return Err(GithubWorkflowDispatchError::DurableSourceMismatch);
        }
        let repository = AdmissionRepositoryCoordinates::new(
            source.repository().provider(),
            source.repository().provider_repository_id(),
            source.repository().owner(),
            source.repository().name(),
        )?;
        let mut dispatch = GithubWorkflowDispatchRequest::new(
            authorization,
            repository,
            source.repository_owner_id(),
            source.workflow_path(),
            bytes,
            source.commit_sha(),
            source.git_ref(),
            inputs,
            operation_id,
        );
        if let Some(display_title) = display_title {
            dispatch = dispatch.with_display_title(display_title);
        }
        Box::pin(self.dispatch(dispatch)).await
    }

    /// Validates the exact source contract and inputs, publishes canonical
    /// evidence, and transactionally reauthorizes/admit the dispatch.
    ///
    /// # Errors
    ///
    /// Fails closed on invalid target/source/input evidence, context hydration,
    /// current authorization, immutable publication, or durable replay conflict.
    pub async fn dispatch(
        &self,
        request: GithubWorkflowDispatchRequest,
    ) -> Result<WorkflowAdmissionResult, GithubWorkflowDispatchError> {
        let commit_sha = request.commit_sha;
        let tenant = request.validate()?;
        let provenance = SourceProvenance::new(
            SourceId::new(request.workflow_path.as_str()),
            SourceOrigin::Repository {
                repository: Arc::from(request.repository.slug()),
                revision: commit_sha,
                path: Arc::from(request.workflow_path.as_str()),
            },
        );
        let source = std::str::from_utf8(&request.source)
            .map_err(|_| GithubWorkflowDispatchError::InvalidSourceEncoding)?;
        let parsed =
            GithubWorkflowFrontend::default().parse(ParseWorkflowRequest::new(provenance, source));
        if !parsed.is_accepted() {
            return Err(GithubWorkflowDispatchError::FrontendRejected(
                diagnostic_codes(parsed.diagnostics()),
            ));
        }
        let event = WorkflowEventProvenance::new("github", "workflow_dispatch")
            .with_commit_sha(commit_sha)
            .with_git_ref(&request.git_ref);
        let compiled = GithubWorkflowCompiler::new().compile(
            CompileWorkflowRequest::new(
                parsed
                    .plan()
                    .ok_or(GithubWorkflowDispatchError::InvalidSourcePlan)?,
                event,
            )
            .with_event_metadata(GithubEventMetadata::workflow_dispatch(
                request.inputs.clone(),
            )),
        );
        if compiled.disposition() != CompilationDisposition::Accepted {
            return Err(GithubWorkflowDispatchError::CompilationRejected(
                diagnostic_codes(compiled.diagnostics()),
            ));
        }
        let canonical_inputs = compiled
            .workflow_dispatch_inputs()
            .cloned()
            .ok_or(GithubWorkflowDispatchError::InvalidSourcePlan)?;
        let plan = compiled
            .into_parts()
            .0
            .ok_or(GithubWorkflowDispatchError::InvalidSourcePlan)?;
        let base_context = JobRuntimeContext::new_base(
            canonical_inputs,
            ContextValue::empty_object(),
            BTreeMap::<String, SecretBinding>::new(),
        )
        .map_err(|_| GithubWorkflowDispatchError::InvalidBaseContext)?;
        let evidence = GithubWorkflowDispatchEvidence::new(&request)?;
        let event_bytes = evidence.encode()?;
        let trust_snapshot = workflow_dispatch_trust_snapshot(&request)?;
        let mut admission = WorkflowAdmissionRequest::builder(
            tenant,
            request.repository.clone(),
            &request.workflow_path,
            request.source.clone(),
            event_bytes,
            plan,
            base_context,
            WorkflowAdmissionIdempotency::operation(request.operation_id),
            commit_sha,
        )
        .trust_snapshot(trust_snapshot)
        .event_media_type(AUTOMATA_WORKFLOW_DISPATCH_EVIDENCE_V1_MEDIA_TYPE)
        .git_ref(&request.git_ref)
        .workflow_name(&request.workflow_name)
        .actor(request.authorization.actor().principal_id().as_str())
        .run_attempt(1);
        if let Some(display_title) = &request.display_title {
            admission = admission.display_title(display_title);
        }
        let admission = admission.build()?;
        Box::pin(
            self.admission
                .admit_authenticated_workflow_dispatch(admission, request.authorization),
        )
        .await
        .map_err(Into::into)
    }
}

fn workflow_dispatch_trust_snapshot(
    request: &GithubWorkflowDispatchRequest,
) -> Result<TrustSnapshot, GithubWorkflowDispatchError> {
    let commit_sha = request.commit_sha.to_string();
    let actor = TrustActorEvidence::new(
        request.authorization.actor().principal_id().as_str(),
        TrustActorKind::User,
        TrustAutomationKind::None,
    )
    .map_err(|_| GithubWorkflowDispatchError::InvalidSourcePlan)?;
    let repository = TrustRepositoryEvidence::new(
        request.repository.provider_repository_id(),
        request.repository_owner_id.as_str(),
    )
    .map_err(|_| GithubWorkflowDispatchError::InvalidSourcePlan)?;
    TrustPolicy::current()
        .evaluate(
            TrustEvidence::new(
                TrustOriginKind::WorkflowDispatch,
                TrustEventKind::WorkflowDispatch,
            )
            .with_original_actor(actor.clone())
            .with_triggering_actor(actor)
            .with_repositories(repository.clone(), repository)
            .with_refs(
                request.git_ref.as_str(),
                request.git_ref.as_str(),
                request.git_ref.as_str(),
            )
            .with_revisions(
                commit_sha.as_str(),
                commit_sha.as_str(),
                commit_sha.as_str(),
            )
            .with_fork(false)
            .with_token_recursion(TrustTokenRecursion::External),
        )
        .map_err(|_| GithubWorkflowDispatchError::InvalidSourcePlan)
}

/// Canonical synthetic event retained as authenticated dispatch evidence.
#[derive(Clone, Eq, PartialEq)]
pub struct GithubWorkflowDispatchEvidence {
    document: EvidenceDocument,
    inputs: GithubWorkflowDispatchInputs,
}

impl fmt::Debug for GithubWorkflowDispatchEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubWorkflowDispatchEvidence")
            .field("repository_id", &self.document.repository.repository_id)
            .field("workflow_id", &self.document.workflow.workflow_id)
            .field("input_count", &self.inputs.values().len())
            .finish_non_exhaustive()
    }
}

impl GithubWorkflowDispatchEvidence {
    fn new(
        request: &GithubWorkflowDispatchRequest,
    ) -> Result<Self, GithubWorkflowDispatchEvidenceError> {
        let actor = request.authorization.actor();
        let session_id = actor.correlation_session_id();
        let inputs = evidence_inputs(&request.inputs)?;
        let document = EvidenceDocument {
            schema: EVIDENCE_SCHEMA,
            kind: EVIDENCE_KIND.to_owned(),
            authority: EvidenceAuthority {
                tenant_id: actor.tenant_id().as_str().to_owned(),
                principal_id: actor.principal_id().as_str().to_owned(),
                session_id,
                authorization_revision: actor.authorization_revision(),
            },
            repository: EvidenceRepository {
                repository_id: request.authorization.repository_id().as_uuid(),
                provider: request.repository.provider().to_owned(),
                provider_repository_id: request.repository.provider_repository_id().to_owned(),
                provider_owner_id: request.repository_owner_id.clone(),
                owner: request.repository.owner().to_owned(),
                name: request.repository.name().to_owned(),
            },
            workflow: EvidenceWorkflow {
                workflow_id: request.authorization.workflow_id().as_uuid(),
                path: request.workflow_path.clone(),
                git_ref: request.git_ref.clone(),
                commit_sha: request.commit_sha,
            },
            operation_id: request.operation_id.as_uuid(),
            inputs,
        };
        Self::from_document(document, request.inputs.clone())
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, GithubWorkflowDispatchEvidenceError> {
        let document = serde_json::from_slice::<EvidenceDocument>(bytes)
            .map_err(|_| GithubWorkflowDispatchEvidenceError::InvalidEncoding)?;
        let inputs = document
            .inputs
            .iter()
            .map(|(key, value)| {
                let value = match value {
                    EvidenceInputValue::Boolean(value) => {
                        GithubWorkflowDispatchInputValue::Boolean(*value)
                    }
                    EvidenceInputValue::String(value) => {
                        GithubWorkflowDispatchInputValue::String(value.clone())
                    }
                };
                (key.clone(), value)
            })
            .collect::<Vec<_>>();
        let inputs = GithubWorkflowDispatchInputs::try_new(inputs)
            .map_err(GithubWorkflowDispatchEvidenceError::InvalidInputs)?;
        let evidence = Self::from_document(document, inputs)?;
        if evidence.encode()?.as_ref() != bytes {
            return Err(GithubWorkflowDispatchEvidenceError::NonCanonicalEncoding);
        }
        Ok(evidence)
    }

    fn from_document(
        document: EvidenceDocument,
        inputs: GithubWorkflowDispatchInputs,
    ) -> Result<Self, GithubWorkflowDispatchEvidenceError> {
        let texts = [
            document.authority.tenant_id.as_str(),
            document.authority.principal_id.as_str(),
            document.authority.session_id.as_str(),
            document.repository.provider.as_str(),
            document.repository.provider_repository_id.as_str(),
            document.repository.provider_owner_id.as_str(),
            document.repository.owner.as_str(),
            document.repository.name.as_str(),
            document.workflow.path.as_str(),
            document.workflow.git_ref.as_str(),
        ];
        if document.schema != EVIDENCE_SCHEMA
            || document.kind != EVIDENCE_KIND
            || document.authority.authorization_revision == 0
            || document.authority.authorization_revision > i64::MAX as u64
            || document.repository.repository_id.is_nil()
            || document.workflow.workflow_id.is_nil()
            || document.operation_id.is_nil()
            || document.repository.provider != "github"
            || texts.into_iter().any(|value| !valid_text(value))
            || !canonical_workflow_dispatch_ref(&document.workflow.git_ref)
            || evidence_inputs(&inputs)? != document.inputs
        {
            return Err(GithubWorkflowDispatchEvidenceError::InvalidDocument);
        }
        Ok(Self { document, inputs })
    }

    pub(crate) fn encode(&self) -> Result<Bytes, GithubWorkflowDispatchEvidenceError> {
        serde_json::to_vec(&self.document)
            .map(Bytes::from)
            .map_err(|_| GithubWorkflowDispatchEvidenceError::InvalidEncoding)
    }

    pub(crate) fn metadata(&self) -> GithubEventMetadata {
        GithubEventMetadata::workflow_dispatch(self.inputs.clone())
    }

    pub(crate) fn matches_admission(&self, request: &WorkflowAdmissionRequest) -> bool {
        self.document.authority.tenant_id == request.tenant().as_str()
            && self.document.repository.provider == request.repository().provider()
            && self.document.repository.provider_repository_id
                == request.repository().provider_repository_id()
            && request
                .trust_snapshot()
                .evidence()
                .target_repository()
                .is_some_and(|repository| {
                    repository.id() == self.document.repository.provider_repository_id.as_str()
                        && repository.owner_id()
                            == self.document.repository.provider_owner_id.as_str()
                })
            && self.document.repository.owner == request.repository().owner()
            && self.document.repository.name == request.repository().name()
            && self.document.workflow.path == request.workflow_path()
            && self.document.workflow.git_ref == request.git_ref()
            && self.document.workflow.commit_sha == request.commit_sha()
            && matches!(
                request.idempotency(),
                WorkflowAdmissionIdempotency::Operation(operation_id)
                    if operation_id.as_uuid() == self.document.operation_id
            )
    }

    pub(crate) fn repository_id(&self) -> RepositoryId {
        RepositoryId::from_uuid(self.document.repository.repository_id)
    }

    pub(crate) fn workflow_id(&self) -> WorkflowId {
        WorkflowId::from_uuid(self.document.workflow.workflow_id)
    }

    pub(crate) fn authority_matches(&self, authorization: &WorkflowDispatchAuthorization) -> bool {
        let actor = authorization.actor();
        let session_id = actor.correlation_session_id();
        self.repository_id() == authorization.repository_id()
            && self.workflow_id() == authorization.workflow_id()
            && self.document.authority.tenant_id == actor.tenant_id().as_str()
            && self.document.authority.principal_id == actor.principal_id().as_str()
            && self.document.authority.session_id == session_id
            && self.document.authority.authorization_revision == actor.authorization_revision()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceDocument {
    schema: u16,
    kind: String,
    authority: EvidenceAuthority,
    repository: EvidenceRepository,
    workflow: EvidenceWorkflow,
    operation_id: Uuid,
    inputs: BTreeMap<String, EvidenceInputValue>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceAuthority {
    tenant_id: String,
    principal_id: String,
    session_id: String,
    authorization_revision: u64,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceRepository {
    repository_id: Uuid,
    provider: String,
    provider_repository_id: String,
    provider_owner_id: String,
    owner: String,
    name: String,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceWorkflow {
    workflow_id: Uuid,
    path: String,
    git_ref: String,
    commit_sha: GitObjectId,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
enum EvidenceInputValue {
    Boolean(bool),
    String(String),
}

fn evidence_inputs(
    inputs: &GithubWorkflowDispatchInputs,
) -> Result<BTreeMap<String, EvidenceInputValue>, GithubWorkflowDispatchEvidenceError> {
    inputs
        .values()
        .iter()
        .map(|(key, value)| {
            let value = match value {
                GithubWorkflowDispatchInputValue::Boolean(value) => {
                    EvidenceInputValue::Boolean(*value)
                }
                GithubWorkflowDispatchInputValue::String(value) => {
                    EvidenceInputValue::String(value.clone())
                }
                _ => return Err(GithubWorkflowDispatchEvidenceError::InvalidDocument),
            };
            Ok((key.as_str().to_owned(), value))
        })
        .collect()
}

fn diagnostic_codes(diagnostics: &[Diagnostic]) -> String {
    let mut codes = diagnostics.iter().map(Diagnostic::code).collect::<Vec<_>>();
    codes.sort_unstable();
    codes.dedup();
    if codes.is_empty() {
        "unspecified diagnostic".to_owned()
    } else {
        codes.join(",")
    }
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && workflow_dispatch_evidence_text_byte_rejection(value.len()).is_none()
        && !value.chars().any(char::is_control)
}

fn canonical_workflow_dispatch_ref(value: &str) -> bool {
    canonical_git_ref(value)
        && ["refs/heads/", "refs/tags/"].iter().any(|prefix| {
            value
                .strip_prefix(prefix)
                .is_some_and(|suffix| !suffix.is_empty())
        })
}

/// Invalid control-plane dispatch request or exact target.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubWorkflowDispatchRequestError {
    /// The authenticated tenant could not form a durable admission scope.
    #[error("workflow dispatch authority is invalid")]
    InvalidAuthority,
    /// A repository, workflow, source, operation, commit, or ref target is invalid.
    #[error("workflow dispatch target is invalid")]
    InvalidTarget,
}

/// Invalid canonical manual-dispatch evidence.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GithubWorkflowDispatchEvidenceError {
    /// Evidence JSON could not be encoded or decoded.
    #[error("workflow dispatch evidence encoding is invalid")]
    InvalidEncoding,
    /// Evidence JSON was valid but not in the one canonical representation.
    #[error("workflow dispatch evidence is not canonical")]
    NonCanonicalEncoding,
    /// Evidence fields did not form one exact authenticated target.
    #[error("workflow dispatch evidence fields are invalid")]
    InvalidDocument,
    /// Evidence inputs exceeded their closed structural or resource bounds.
    #[error(transparent)]
    InvalidInputs(#[from] GithubWorkflowDispatchInputsError),
}

/// Fail-closed high-level manual-dispatch failure.
#[derive(Debug, Error)]
pub enum GithubWorkflowDispatchError {
    /// The exact authenticated request target was invalid.
    #[error(transparent)]
    Request(#[from] GithubWorkflowDispatchRequestError),
    /// The exact source was not valid UTF-8.
    #[error("workflow dispatch source is not valid UTF-8")]
    InvalidSourceEncoding,
    /// The loss-aware frontend rejected the exact source.
    #[error("workflow dispatch source was rejected: {0}")]
    FrontendRejected(String),
    /// The exact source did not retain a usable source plan.
    #[error("workflow dispatch source plan is unavailable")]
    InvalidSourcePlan,
    /// Typed input selection or workflow compilation failed.
    #[error("workflow dispatch compilation was rejected: {0}")]
    CompilationRejected(String),
    /// No prior signed GitHub admission proved the exact requested source.
    #[error("no authenticated durable workflow source matches the dispatch target")]
    DurableSourceNotFound,
    /// Durable source resolution returned a different exact target.
    #[error("authenticated durable workflow source does not match the dispatch target")]
    DurableSourceMismatch,
    /// Trusted variables or opaque secret bindings did not form a base context.
    #[error("workflow dispatch base context is invalid")]
    InvalidBaseContext,
    /// Canonical authenticated evidence could not be constructed.
    #[error(transparent)]
    Evidence(#[from] GithubWorkflowDispatchEvidenceError),
    /// The provider-neutral admission request was internally inconsistent.
    #[error(transparent)]
    AdmissionRequest(#[from] WorkflowAdmissionRequestError),
    /// Immutable publication, transactional authorization, or durable replay failed.
    #[error(transparent)]
    Admission(#[from] WorkflowAdmissionError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workflow_dispatch_evidence_text_byte_limit_has_exact_boundaries() {
        assert_eq!(
            workflow_dispatch_evidence_text_byte_rejection(MAX_EVIDENCE_TEXT_BYTES - 1),
            None
        );
        assert_eq!(
            workflow_dispatch_evidence_text_byte_rejection(MAX_EVIDENCE_TEXT_BYTES),
            None
        );
        assert_eq!(
            workflow_dispatch_evidence_text_byte_rejection(MAX_EVIDENCE_TEXT_BYTES + 1),
            Some(WorkflowDispatchEvidenceLimitRejection::TextBytes)
        );
    }

    #[test]
    fn workflow_dispatch_evidence_rejects_noncurrent_schemas() {
        let document = EvidenceDocument {
            schema: EVIDENCE_SCHEMA,
            kind: EVIDENCE_KIND.to_owned(),
            authority: EvidenceAuthority {
                tenant_id: "tenant-1".to_owned(),
                principal_id: "principal-1".to_owned(),
                session_id: "session-1".to_owned(),
                authorization_revision: 1,
            },
            repository: EvidenceRepository {
                repository_id: Uuid::new_v4(),
                provider: "github".to_owned(),
                provider_repository_id: "123".to_owned(),
                provider_owner_id: "456".to_owned(),
                owner: "automata-ci".to_owned(),
                name: "automata".to_owned(),
            },
            workflow: EvidenceWorkflow {
                workflow_id: Uuid::new_v4(),
                path: ".github/workflows/ci.yml".to_owned(),
                git_ref: "refs/heads/main".to_owned(),
                commit_sha: GitObjectId::from_provider_hex(
                    "0123456789abcdef0123456789abcdef01234567",
                )
                .expect("commit"),
            },
            operation_id: Uuid::new_v4(),
            inputs: BTreeMap::new(),
        };
        let current = serde_json::to_vec(&document).expect("current evidence");
        GithubWorkflowDispatchEvidence::decode(&current).expect("decode current evidence");

        let mut deleted_encoding =
            serde_json::to_value(&document).expect("deleted evidence encoding fixture");
        deleted_encoding["workflow"]["commit_sha"] =
            serde_json::Value::String(document.workflow.commit_sha.to_string());
        let deleted_encoding =
            serde_json::to_vec(&deleted_encoding).expect("deleted evidence encoding");
        assert_eq!(
            GithubWorkflowDispatchEvidence::decode(&deleted_encoding),
            Err(GithubWorkflowDispatchEvidenceError::InvalidEncoding),
            "accepted the deleted string commit identity encoding"
        );

        for schema in [0, EVIDENCE_SCHEMA.checked_add(1).expect("test schema")] {
            let mut noncurrent = document.clone();
            noncurrent.schema = schema;
            let bytes = serde_json::to_vec(&noncurrent).expect("noncurrent evidence");
            assert!(
                GithubWorkflowDispatchEvidence::decode(&bytes).is_err(),
                "accepted schema {schema}"
            );
        }
    }
}
