use std::{collections::BTreeMap, fmt, sync::Arc};

use automata_ci_auth::management::ManagementActor;
use automata_ci_core::{
    ContextValue, JobRuntimeContext, OperationId, SecretBinding, WorkflowEventProvenance,
    WorkflowId,
};
use automata_ci_store::{RepositoryId, TenantScope, WorkflowAdmissionIdempotency};
use automata_ci_store::ResolveAuthenticatedWorkflowDispatchSource;
use automata_ci_workflow_github::{
    CompilationDisposition, CompileWorkflowRequest, Diagnostic, GithubEventMetadataV1,
    GithubWorkflowCompiler, GithubWorkflowDispatchInputValue, GithubWorkflowDispatchInputsError,
    GithubWorkflowDispatchInputsV1, GithubWorkflowFrontend, ParseWorkflowRequest, SourceId,
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

/// Exact, authenticated target authorized for a control-plane manual dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowDispatchAuthorization {
    actor: ManagementActor,
    repository_id: RepositoryId,
    workflow_id: WorkflowId,
}

impl WorkflowDispatchAuthorization {
    /// Creates exact repository/workflow authority supplied by authenticated ingress.
    ///
    /// # Errors
    ///
    /// Rejects nil durable target identities.
    pub fn new(
        actor: ManagementActor,
        repository_id: RepositoryId,
        workflow_id: WorkflowId,
    ) -> Result<Self, GithubWorkflowDispatchRequestError> {
        if repository_id.as_uuid().is_nil() || workflow_id.as_uuid().is_nil() {
            return Err(GithubWorkflowDispatchRequestError::InvalidTarget);
        }
        Ok(Self {
            actor,
            repository_id,
            workflow_id,
        })
    }

    /// Returns current human-session evidence for transactional reauthorization.
    #[must_use]
    pub const fn actor(&self) -> &ManagementActor {
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
#[derive(Clone, Debug)]
pub struct GithubWorkflowDispatchRequest {
    authorization: WorkflowDispatchAuthorization,
    repository: AdmissionRepositoryCoordinates,
    workflow_path: String,
    source: Bytes,
    commit_sha: String,
    git_ref: String,
    workflow_name: String,
    inputs: GithubWorkflowDispatchInputsV1,
    operation_id: OperationId,
    vars: ContextValue,
    secrets: BTreeMap<String, SecretBinding>,
    display_title: Option<String>,
    commit_subject: Option<String>,
}

/// Exact control-plane request whose workflow bytes must be recovered from a
/// prior signed GitHub admission rather than accepted from the caller.
#[derive(Clone, Debug)]
pub struct DurableGithubWorkflowDispatchRequest {
    authorization: WorkflowDispatchAuthorization,
    git_ref: String,
    commit_sha: String,
    inputs: GithubWorkflowDispatchInputsV1,
    operation_id: OperationId,
    display_title: Option<String>,
}

impl DurableGithubWorkflowDispatchRequest {
    /// Creates a durable-source dispatch request.
    #[must_use]
    pub fn new(
        authorization: WorkflowDispatchAuthorization,
        git_ref: impl Into<String>,
        commit_sha: impl Into<String>,
        inputs: GithubWorkflowDispatchInputsV1,
        operation_id: OperationId,
    ) -> Self {
        Self {
            authorization,
            git_ref: git_ref.into(),
            commit_sha: commit_sha.into(),
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
        workflow_path: impl Into<String>,
        source: Bytes,
        commit_sha: impl Into<String>,
        git_ref: impl Into<String>,
        inputs: GithubWorkflowDispatchInputsV1,
        operation_id: OperationId,
    ) -> Self {
        let workflow_path = workflow_path.into();
        Self {
            authorization,
            repository,
            workflow_name: workflow_path.clone(),
            workflow_path,
            source,
            commit_sha: commit_sha.into(),
            git_ref: git_ref.into(),
            inputs,
            operation_id,
            vars: ContextValue::empty_object(),
            secrets: BTreeMap::new(),
            display_title: None,
            commit_subject: None,
        }
    }

    /// Sets the human-facing workflow name retained by the run projection.
    #[must_use]
    pub fn with_workflow_name(mut self, workflow_name: impl Into<String>) -> Self {
        self.workflow_name = workflow_name.into();
        self
    }

    /// Attaches a trusted repository-variable snapshot.
    #[must_use]
    pub fn with_vars(mut self, vars: ContextValue) -> Self {
        self.vars = vars;
        self
    }

    /// Attaches opaque, separately authorized repository secret bindings.
    #[must_use]
    pub fn with_secrets(mut self, secrets: BTreeMap<String, SecretBinding>) -> Self {
        self.secrets = secrets;
        self
    }

    /// Sets an optional bounded display title.
    #[must_use]
    pub fn with_display_title(mut self, display_title: impl Into<String>) -> Self {
        self.display_title = Some(display_title.into());
        self
    }

    /// Sets an optional bounded source commit subject.
    #[must_use]
    pub fn with_commit_subject(mut self, commit_subject: impl Into<String>) -> Self {
        self.commit_subject = Some(commit_subject.into());
        self
    }

    fn validate(&self) -> Result<TenantScope, GithubWorkflowDispatchRequestError> {
        if self.repository.provider() != "github"
            || self.operation_id.as_uuid().is_nil()
            || !valid_text(&self.workflow_path)
            || !valid_text(&self.workflow_name)
            || self.source.is_empty()
            || self.git_ref.strip_prefix("refs/").is_none_or(str::is_empty)
            || !valid_text(&self.git_ref)
            || !valid_commit_sha(&self.commit_sha)
            || self
                .display_title
                .as_deref()
                .is_some_and(|value| !valid_text(value))
            || self
                .commit_subject
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
            || request.git_ref.strip_prefix("refs/").is_none_or(str::is_empty)
            || !valid_text(&request.git_ref)
            || !valid_commit_sha(&request.commit_sha)
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
            &request.commit_sha,
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
        let repository = AdmissionRepositoryCoordinates::new(
            source.repository().provider(),
            source.repository().provider_repository_id(),
            source.repository().owner(),
            source.repository().name(),
        )?;
        let mut dispatch = GithubWorkflowDispatchRequest::new(
            request.authorization,
            repository,
            source.workflow_path(),
            bytes,
            request.commit_sha,
            request.git_ref,
            request.inputs,
            request.operation_id,
        );
        if let Some(display_title) = request.display_title {
            dispatch = dispatch.with_display_title(display_title);
        }
        self.dispatch(dispatch).await
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
        let tenant = request.validate()?;
        let provenance = SourceProvenance::new(
            SourceId::new(request.workflow_path.as_str()),
            SourceOrigin::Repository {
                repository: Arc::from(request.repository.slug()),
                revision: Arc::from(request.commit_sha.as_str()),
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
            .with_commit_sha(&request.commit_sha)
            .with_git_ref(&request.git_ref);
        let compiled = GithubWorkflowCompiler::new().compile(
            CompileWorkflowRequest::new(
                parsed
                    .plan()
                    .ok_or(GithubWorkflowDispatchError::InvalidSourcePlan)?,
                event,
            )
            .with_event_metadata_v1(GithubEventMetadataV1::workflow_dispatch(
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
            request.vars.clone(),
            request.secrets.clone(),
        )
        .map_err(|_| GithubWorkflowDispatchError::InvalidBaseContext)?;
        let evidence = GithubWorkflowDispatchEvidenceV1::new(&request)?;
        let event_bytes = evidence.encode()?;
        let mut admission = WorkflowAdmissionRequest::builder(
            tenant,
            request.repository.clone(),
            &request.workflow_path,
            request.source.clone(),
            event_bytes,
            plan,
            base_context,
            WorkflowAdmissionIdempotency::operation(request.operation_id),
        )
        .event_media_type(AUTOMATA_WORKFLOW_DISPATCH_EVIDENCE_V1_MEDIA_TYPE)
        .commit_sha(&request.commit_sha)
        .git_ref(&request.git_ref)
        .workflow_name(&request.workflow_name)
        .actor(request.authorization.actor().principal_id().as_str())
        .run_attempt(1);
        if let Some(display_title) = &request.display_title {
            admission = admission.display_title(display_title);
        }
        if let Some(commit_subject) = &request.commit_subject {
            admission = admission.commit_subject(commit_subject);
        }
        let admission = admission.build()?;
        self.admission
            .admit_authenticated_workflow_dispatch(admission, request.authorization)
            .await
            .map_err(Into::into)
    }
}

/// Canonical synthetic event retained as authenticated dispatch evidence.
#[derive(Clone, Eq, PartialEq)]
pub struct GithubWorkflowDispatchEvidenceV1 {
    document: EvidenceDocument,
    inputs: GithubWorkflowDispatchInputsV1,
}

impl fmt::Debug for GithubWorkflowDispatchEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubWorkflowDispatchEvidenceV1")
            .field("repository_id", &self.document.repository.repository_id)
            .field("workflow_id", &self.document.workflow.workflow_id)
            .field("input_count", &self.inputs.values().len())
            .finish_non_exhaustive()
    }
}

impl GithubWorkflowDispatchEvidenceV1 {
    fn new(
        request: &GithubWorkflowDispatchRequest,
    ) -> Result<Self, GithubWorkflowDispatchEvidenceError> {
        let actor = request.authorization.actor();
        let inputs = evidence_inputs(&request.inputs);
        let document = EvidenceDocument {
            schema: EVIDENCE_SCHEMA,
            kind: EVIDENCE_KIND.to_owned(),
            authority: EvidenceAuthority {
                tenant_id: actor.tenant_id().as_str().to_owned(),
                principal_id: actor.principal_id().as_str().to_owned(),
                session_id: actor.session_id().as_str().to_owned(),
                authorization_revision: actor.authorization_revision().value(),
            },
            repository: EvidenceRepository {
                repository_id: request.authorization.repository_id().as_uuid(),
                provider: request.repository.provider().to_owned(),
                provider_repository_id: request.repository.provider_repository_id().to_owned(),
                owner: request.repository.owner().to_owned(),
                name: request.repository.name().to_owned(),
            },
            workflow: EvidenceWorkflow {
                workflow_id: request.authorization.workflow_id().as_uuid(),
                path: request.workflow_path.clone(),
                git_ref: request.git_ref.clone(),
                commit_sha: request.commit_sha.clone(),
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
        let inputs = GithubWorkflowDispatchInputsV1::try_new(inputs)
            .map_err(GithubWorkflowDispatchEvidenceError::InvalidInputs)?;
        let evidence = Self::from_document(document, inputs)?;
        if evidence.encode()?.as_ref() != bytes {
            return Err(GithubWorkflowDispatchEvidenceError::NonCanonicalEncoding);
        }
        Ok(evidence)
    }

    fn from_document(
        document: EvidenceDocument,
        inputs: GithubWorkflowDispatchInputsV1,
    ) -> Result<Self, GithubWorkflowDispatchEvidenceError> {
        let texts = [
            document.authority.tenant_id.as_str(),
            document.authority.principal_id.as_str(),
            document.authority.session_id.as_str(),
            document.repository.provider.as_str(),
            document.repository.provider_repository_id.as_str(),
            document.repository.owner.as_str(),
            document.repository.name.as_str(),
            document.workflow.path.as_str(),
            document.workflow.git_ref.as_str(),
            document.workflow.commit_sha.as_str(),
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
            || document
                .workflow
                .git_ref
                .strip_prefix("refs/")
                .is_none_or(str::is_empty)
            || !valid_commit_sha(&document.workflow.commit_sha)
            || evidence_inputs(&inputs) != document.inputs
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

    pub(crate) fn metadata(&self) -> GithubEventMetadataV1 {
        GithubEventMetadataV1::workflow_dispatch(self.inputs.clone())
    }

    pub(crate) fn matches_admission(&self, request: &WorkflowAdmissionRequest) -> bool {
        self.document.authority.tenant_id == request.tenant().as_str()
            && self.document.repository.provider == request.repository().provider()
            && self.document.repository.provider_repository_id
                == request.repository().provider_repository_id()
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
        self.repository_id() == authorization.repository_id()
            && self.workflow_id() == authorization.workflow_id()
            && self.document.authority.tenant_id == actor.tenant_id().as_str()
            && self.document.authority.principal_id == actor.principal_id().as_str()
            && self.document.authority.session_id == actor.session_id().as_str()
            && self.document.authority.authorization_revision
                == actor.authorization_revision().value()
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
    owner: String,
    name: String,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceWorkflow {
    workflow_id: Uuid,
    path: String,
    git_ref: String,
    commit_sha: String,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
enum EvidenceInputValue {
    Boolean(bool),
    String(String),
}

fn evidence_inputs(
    inputs: &GithubWorkflowDispatchInputsV1,
) -> BTreeMap<String, EvidenceInputValue> {
    inputs
        .values()
        .iter()
        .map(|(key, value)| {
            let value = if let Some(value) = value.as_boolean() {
                EvidenceInputValue::Boolean(value)
            } else {
                EvidenceInputValue::String(value.as_string().unwrap_or_default().to_owned())
            };
            (key.as_str().to_owned(), value)
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
        && value.len() <= MAX_EVIDENCE_TEXT_BYTES
        && !value.chars().any(char::is_control)
}

fn valid_commit_sha(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
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
