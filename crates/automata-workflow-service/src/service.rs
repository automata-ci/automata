use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use automata_blob::{BlobKey, BlobPayload, BlobStoreError, ImmutableBlobStore, MediaType};
use automata_core::Sha256Digest;
use automata_protocol::ProtocolLimits;
use automata_protocol_protobuf::encode_job_ir;
use automata_store::{
    AdmissionObject, AdmissionRepository, AdmitWorkflowRun, AdmittedWorkflowJob, ObjectKey,
    RoutingDocument, WorkflowAdmissionIdempotency, WorkflowAdmissionRepository,
    WorkflowAdmissionStoreError, WorkflowAdmissionValueError,
};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    AdmissionClock, AdmissionIdGenerator, GITHUB_WORKFLOW_MEDIA_TYPE, JOB_IR_MEDIA_TYPE,
    MaterializeWorkflowRequest, Sha256AdmissionIdGenerator, SystemAdmissionClock,
    WORKFLOW_EVENT_MEDIA_TYPE, WORKFLOW_PLAN_MEDIA_TYPE, WorkflowAdmissionRequest,
    WorkflowAdmissionResult, WorkflowJobIdentity, WorkflowMaterializationError,
    WorkflowMaterializer,
};

const REQUEST_DIGEST_DOMAIN: &[u8] = b"automata.workflow-admission.request.v1\0";

/// Blob-first, provider-pluggable workflow admission application service.
#[derive(Clone)]
pub struct WorkflowAdmissionService {
    blobs: Arc<dyn ImmutableBlobStore>,
    repository: Arc<dyn WorkflowAdmissionRepository>,
    materializer: Arc<dyn WorkflowMaterializer>,
    ids: Arc<dyn AdmissionIdGenerator>,
    clock: Arc<dyn AdmissionClock>,
}

impl WorkflowAdmissionService {
    /// Creates the service with explicit infrastructure and policy ports.
    #[must_use]
    pub fn new(
        blobs: Arc<dyn ImmutableBlobStore>,
        repository: Arc<dyn WorkflowAdmissionRepository>,
        materializer: Arc<dyn WorkflowMaterializer>,
        ids: Arc<dyn AdmissionIdGenerator>,
        clock: Arc<dyn AdmissionClock>,
    ) -> Self {
        Self {
            blobs,
            repository,
            materializer,
            ids,
            clock,
        }
    }

    /// Creates the service with production ID and clock implementations.
    #[must_use]
    pub fn with_system_ports(
        blobs: Arc<dyn ImmutableBlobStore>,
        repository: Arc<dyn WorkflowAdmissionRepository>,
        materializer: Arc<dyn WorkflowMaterializer>,
    ) -> Self {
        Self::new(
            blobs,
            repository,
            materializer,
            Arc::new(Sha256AdmissionIdGenerator),
            Arc::new(SystemAdmissionClock),
        )
    }

    /// Publishes exact immutable evidence and atomically commits one run DAG.
    ///
    /// Blob publication intentionally precedes the relational transaction.
    /// A failed database commit may leave safe content-addressed orphans, but
    /// can never expose a run whose objects were not durably verified first.
    ///
    /// # Errors
    ///
    /// Fails closed on materialization diagnostics, invariant mismatches,
    /// object-store failures, encoding failures, or atomic store rejection.
    #[allow(clippy::too_many_lines)] // Linear blob-first orchestration keeps commit ordering explicit.
    pub async fn admit(
        &self,
        request: WorkflowAdmissionRequest,
    ) -> Result<WorkflowAdmissionResult, WorkflowAdmissionError> {
        let source_blob = prepare_blob(
            "workflow-source",
            GITHUB_WORKFLOW_MEDIA_TYPE,
            request.source().clone(),
        )?;
        let event_blob = prepare_blob(
            "workflow-event",
            WORKFLOW_EVENT_MEDIA_TYPE,
            request.event().clone(),
        )?;
        let plan_bytes = Bytes::from(
            serde_json::to_vec(request.plan())
                .map_err(|_| WorkflowAdmissionError::Serialization)?,
        );
        let plan_blob = prepare_blob("workflow-plan", WORKFLOW_PLAN_MEDIA_TYPE, plan_bytes)?;
        let event_reference = automata_core::JobContentReference::new(
            event_blob.metadata.object_key().as_str(),
            event_blob.metadata.digest(),
            event_blob.metadata.encoded_size(),
            event_blob.metadata.media_type(),
        );

        let repository_id = self
            .ids
            .repository_id(request.tenant(), request.repository());
        let workflow_id = self.ids.workflow_id(repository_id, request.workflow_path());
        let snapshot_id = self
            .ids
            .snapshot_id(workflow_id, source_blob.metadata.digest());
        let durable_idempotency = namespace_idempotency(&request)?;
        let run_id = self.ids.run_id(request.tenant(), &durable_idempotency);
        let job_identities = request
            .plan()
            .jobs()
            .iter()
            .map(|job| {
                let key = job.key().value().clone();
                let id = self.ids.job_id(run_id, &key);
                WorkflowJobIdentity::new(key, id)
            })
            .collect::<Vec<_>>();
        let materialized = self
            .materializer
            .materialize(&MaterializeWorkflowRequest::new(
                &request,
                repository_id,
                workflow_id,
                run_id,
                &job_identities,
                &event_reference,
            ))?;
        validate_materialized(
            &request,
            workflow_id,
            run_id,
            &job_identities,
            &materialized,
            &event_blob,
        )?;

        let limits = ProtocolLimits::default();
        let mut prepared_jobs = Vec::with_capacity(materialized.jobs().len());
        for job in materialized.jobs() {
            let encoded = encode_job_ir(job.envelope(), &limits)
                .map_err(|_| WorkflowAdmissionError::JobIrEncoding)?;
            let blob = prepare_blob("job-ir-v4", JOB_IR_MEDIA_TYPE, Bytes::from(encoded))?;
            prepared_jobs.push((job, blob));
        }
        let request_digest = canonical_request_digest(
            &request,
            &source_blob,
            &event_blob,
            &plan_blob,
            &prepared_jobs,
        );

        self.publish(&source_blob).await?;
        self.publish(&event_blob).await?;
        self.publish(&plan_blob).await?;
        for (_, blob) in &prepared_jobs {
            self.publish(blob).await?;
        }

        let job_ids = job_identities
            .iter()
            .map(|identity| (identity.key().clone(), identity.job_id()))
            .collect::<BTreeMap<_, _>>();
        let planned_jobs = request
            .plan()
            .jobs()
            .iter()
            .map(|job| (job.key().value(), job))
            .collect::<BTreeMap<_, _>>();
        let mut admitted_jobs = Vec::with_capacity(prepared_jobs.len());
        for (materialized_job, blob) in &prepared_jobs {
            let envelope = materialized_job.envelope();
            let key = materialized_job.key();
            let plan_job = planned_jobs
                .get(key)
                .ok_or(WorkflowAdmissionError::MaterializedInvariant)?;
            let prerequisites = plan_job
                .needs()
                .iter()
                .map(|dependency| {
                    job_ids
                        .get(dependency.value())
                        .copied()
                        .ok_or(WorkflowAdmissionError::MaterializedInvariant)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let requirements = RoutingDocument::new(
                serde_json::to_string(envelope.job().requirements())
                    .map_err(|_| WorkflowAdmissionError::Serialization)?,
            )?;
            admitted_jobs.push(AdmittedWorkflowJob::new(
                envelope.job().job_id(),
                self.ids.attempt_id(envelope.job().job_id()),
                key.as_str(),
                envelope.job().name(),
                blob.metadata.clone(),
                requirements,
                prerequisites,
            )?);
        }

        let repository = AdmissionRepository::new(
            repository_id,
            request.repository().provider(),
            request.repository().provider_repository_id(),
            request.repository().owner(),
            request.repository().name(),
        )?;
        let head_sha = decode_hex(request.commit_sha())?;
        let command = AdmitWorkflowRun::builder(
            request.tenant().clone(),
            durable_idempotency,
            request_digest,
            repository,
            workflow_id,
            request.workflow_path(),
            snapshot_id,
            source_blob.metadata,
            plan_blob.metadata,
            run_id,
            request.plan().event().name(),
            event_blob.metadata,
            head_sha,
            admitted_jobs,
            self.clock.now(),
        )
        .concurrency(materialized.concurrency().cloned())
        .build()?;
        let receipt = self.repository.admit_workflow(command).await?;
        Ok(WorkflowAdmissionResult::new(receipt))
    }

    async fn publish(&self, blob: &PreparedBlob) -> Result<(), WorkflowAdmissionError> {
        self.blobs
            .put_if_absent(blob.payload.clone())
            .await
            .map(|_| ())
            .map_err(WorkflowAdmissionError::Blob)
    }
}

impl std::fmt::Debug for WorkflowAdmissionService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkflowAdmissionService")
            .field("blobs", &self.blobs)
            .field("repository", &self.repository)
            .field("materializer", &self.materializer)
            .field("ids", &self.ids)
            .field("clock", &self.clock)
            .finish()
    }
}

#[derive(Clone, Debug)]
struct PreparedBlob {
    payload: BlobPayload,
    metadata: AdmissionObject,
}

fn prepare_blob(
    kind: &str,
    media_type: &str,
    bytes: Bytes,
) -> Result<PreparedBlob, WorkflowAdmissionError> {
    let digest = Sha256Digest::from_bytes(Sha256::digest(&bytes).into());
    let key_text = format!("admission/v1/{kind}/sha256/{digest}");
    let blob_key = BlobKey::new(key_text.clone()).map_err(|_| WorkflowAdmissionError::Internal)?;
    let media_type_value =
        MediaType::new(media_type).map_err(|_| WorkflowAdmissionError::Internal)?;
    let payload = BlobPayload::from_bytes(blob_key, media_type_value, bytes);
    let metadata = AdmissionObject::new(
        digest,
        ObjectKey::new(key_text).map_err(|_| WorkflowAdmissionError::Internal)?,
        payload.descriptor().size(),
        media_type,
    )?;
    Ok(PreparedBlob { payload, metadata })
}

fn namespace_idempotency(
    request: &WorkflowAdmissionRequest,
) -> Result<WorkflowAdmissionIdempotency, WorkflowAdmissionError> {
    match request.idempotency() {
        WorkflowAdmissionIdempotency::ProviderDelivery(delivery) => {
            WorkflowAdmissionIdempotency::provider_delivery(format!(
                "{}:{}:{}",
                request.repository().provider(),
                request.repository().provider_repository_id(),
                delivery
            ))
            .map_err(WorkflowAdmissionError::AdmissionValue)
        }
        WorkflowAdmissionIdempotency::Operation(operation_id) => {
            Ok(WorkflowAdmissionIdempotency::operation(*operation_id))
        }
    }
}

fn validate_materialized(
    request: &WorkflowAdmissionRequest,
    workflow_id: automata_core::WorkflowId,
    run_id: automata_core::RunId,
    identities: &[WorkflowJobIdentity],
    materialized: &crate::MaterializedWorkflow,
    event: &PreparedBlob,
) -> Result<(), WorkflowAdmissionError> {
    if identities.len() != materialized.jobs().len() {
        return Err(WorkflowAdmissionError::MaterializedInvariant);
    }
    let materialized_keys = materialized
        .jobs()
        .iter()
        .map(crate::MaterializedWorkflowJob::key)
        .collect::<BTreeSet<_>>();
    if materialized_keys.len() != identities.len()
        || identities
            .iter()
            .any(|identity| !materialized_keys.contains(identity.key()))
    {
        return Err(WorkflowAdmissionError::MaterializedInvariant);
    }
    for job in materialized.jobs() {
        let Some(identity) = identities
            .iter()
            .find(|identity| identity.key() == job.key())
        else {
            return Err(WorkflowAdmissionError::MaterializedInvariant);
        };
        let envelope = job.envelope();
        if envelope.workflow_id() != workflow_id
            || envelope.job().run_id() != run_id
            || envelope.job().job_id() != identity.job_id()
            || envelope.source().provider() != request.repository().provider()
            || envelope.source().repository() != request.repository().slug()
            || envelope.source().revision() != request.commit_sha()
            || envelope.source().workflow_path() != request.workflow_path()
            || envelope.source().event_name() != request.plan().event().name()
            || envelope.execution().workflow_name() != request.workflow_name()
            || envelope.execution().git_ref() != request.git_ref()
            || envelope.execution().workspace() != request.workspace()
            || envelope.execution().actor() != request.actor()
            || envelope.execution().run_number() != request.run_number()
            || envelope.execution().run_attempt() != request.run_attempt()
            || envelope.execution().event().object_key() != event.metadata.object_key().as_str()
            || envelope.execution().event().digest() != event.metadata.digest()
            || envelope.execution().event().encoded_size() != event.metadata.encoded_size()
            || envelope.execution().event().media_type() != event.metadata.media_type()
            || envelope.version().get() != automata_core::JOB_IR_SCHEMA_VERSION
            || envelope.job().requirements().schema_version() != 2
            || envelope.validate().is_err()
        {
            return Err(WorkflowAdmissionError::MaterializedInvariant);
        }
    }
    Ok(())
}

fn canonical_request_digest(
    request: &WorkflowAdmissionRequest,
    source: &PreparedBlob,
    event: &PreparedBlob,
    plan: &PreparedBlob,
    jobs: &[(&crate::MaterializedWorkflowJob, PreparedBlob)],
) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(REQUEST_DIGEST_DOMAIN);
    for value in [
        request.tenant().as_str(),
        request.repository().provider(),
        request.repository().provider_repository_id(),
        request.repository().owner(),
        request.repository().name(),
        request.workflow_path(),
        request.commit_sha(),
        request.git_ref(),
        request.workflow_name(),
        request.workspace(),
        request.plan().event().name(),
    ] {
        digest_field(&mut digest, value.as_bytes());
    }
    if let Some(actor) = request.actor() {
        digest_field(&mut digest, actor.as_bytes());
    }
    digest_field(
        &mut digest,
        &request.run_number().unwrap_or_default().to_be_bytes(),
    );
    digest_field(
        &mut digest,
        &request.run_attempt().unwrap_or_default().to_be_bytes(),
    );
    for blob in [source, event, plan] {
        digest_field(&mut digest, blob.metadata.digest().as_bytes());
        digest_field(&mut digest, &blob.metadata.encoded_size().to_be_bytes());
        digest_field(&mut digest, blob.metadata.media_type().as_bytes());
    }
    let mut canonical_jobs = jobs.iter().collect::<Vec<_>>();
    canonical_jobs.sort_unstable_by_key(|(job, _)| job.key());
    for (job, blob) in canonical_jobs {
        digest_field(&mut digest, job.key().as_str().as_bytes());
        digest_field(&mut digest, blob.metadata.digest().as_bytes());
        digest_field(&mut digest, &blob.metadata.encoded_size().to_be_bytes());
        digest_field(&mut digest, blob.metadata.media_type().as_bytes());
    }
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn digest_field(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

fn decode_hex(value: &str) -> Result<Vec<u8>, WorkflowAdmissionError> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or(WorkflowAdmissionError::Internal)?;
            let low = hex_nibble(pair[1]).ok_or(WorkflowAdmissionError::Internal)?;
            Ok((high << 4) | low)
        })
        .collect()
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Application-level workflow admission failure.
#[derive(Debug, Error)]
pub enum WorkflowAdmissionError {
    #[error(transparent)]
    Materialization(#[from] WorkflowMaterializationError),
    #[error("immutable blob publication failed")]
    Blob(#[source] BlobStoreError),
    #[error(transparent)]
    Store(#[from] WorkflowAdmissionStoreError),
    #[error(transparent)]
    AdmissionValue(#[from] WorkflowAdmissionValueError),
    #[error("workflow plan serialization failed")]
    Serialization,
    #[error("JobIR protobuf encoding failed")]
    JobIrEncoding,
    #[error("materialized workflow violated the admission boundary")]
    MaterializedInvariant,
    #[error("internal workflow admission invariant failed")]
    Internal,
}

impl From<automata_store::DurabilityValueError> for WorkflowAdmissionError {
    fn from(_: automata_store::DurabilityValueError) -> Self {
        Self::MaterializedInvariant
    }
}
