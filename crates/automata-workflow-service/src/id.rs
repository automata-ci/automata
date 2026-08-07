use std::time::{SystemTime, UNIX_EPOCH};

use automata_core::{
    AttemptId, JobId, RunId, Sha256Digest, UnixMillis, WorkflowId, WorkflowJobKey,
};
use automata_store::{RepositoryId, TenantScope, WorkflowAdmissionIdempotency, WorkflowSnapshotId};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::{AdmissionClock, AdmissionIdGenerator, AdmissionRepositoryCoordinates};

/// SHA-256 namespaced stable identities derived from durable idempotency.
#[derive(Clone, Copy, Debug, Default)]
pub struct Sha256AdmissionIdGenerator;

impl AdmissionIdGenerator for Sha256AdmissionIdGenerator {
    fn repository_id(
        &self,
        tenant: &TenantScope,
        repository: &AdmissionRepositoryCoordinates,
    ) -> RepositoryId {
        RepositoryId::from_uuid(derived_uuid(
            b"automata.admission.repository.v1\0",
            &[
                tenant.as_str().as_bytes(),
                repository.provider().as_bytes(),
                repository.provider_repository_id().as_bytes(),
            ],
        ))
    }

    fn workflow_id(&self, repository_id: RepositoryId, workflow_path: &str) -> WorkflowId {
        WorkflowId::from_uuid(derived_uuid(
            b"automata.admission.workflow.v1\0",
            &[repository_id.as_uuid().as_bytes(), workflow_path.as_bytes()],
        ))
    }

    fn snapshot_id(
        &self,
        workflow_id: WorkflowId,
        source_digest: Sha256Digest,
    ) -> WorkflowSnapshotId {
        WorkflowSnapshotId::from_uuid(derived_uuid(
            b"automata.admission.snapshot.v1\0",
            &[workflow_id.as_uuid().as_bytes(), source_digest.as_bytes()],
        ))
    }

    fn run_id(&self, tenant: &TenantScope, idempotency: &WorkflowAdmissionIdempotency) -> RunId {
        let key = idempotency.key();
        RunId::from_uuid(derived_uuid(
            b"automata.admission.run.v1\0",
            &[
                tenant.as_str().as_bytes(),
                idempotency.kind().as_bytes(),
                key.as_bytes(),
            ],
        ))
    }

    fn job_id(&self, run_id: RunId, job_key: &WorkflowJobKey) -> JobId {
        JobId::from_uuid(derived_uuid(
            b"automata.admission.job.v1\0",
            &[run_id.as_uuid().as_bytes(), job_key.as_str().as_bytes()],
        ))
    }

    fn attempt_id(&self, job_id: JobId) -> AttemptId {
        AttemptId::from_uuid(derived_uuid(
            b"automata.admission.attempt.v1\0",
            &[job_id.as_uuid().as_bytes(), &1_u32.to_be_bytes()],
        ))
    }
}

/// Wall clock backed by the operating system.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemAdmissionClock;

impl AdmissionClock for SystemAdmissionClock {
    fn now(&self) -> UnixMillis {
        let milliseconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis());
        UnixMillis::new(i64::try_from(milliseconds).unwrap_or(i64::MAX))
    }
}

fn derived_uuid(domain: &[u8], components: &[&[u8]]) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for component in components {
        hasher.update(
            u64::try_from(component.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hasher.update(component);
    }
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // RFC 9562 UUIDv8: implementation-specific bytes with standard variant.
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}
