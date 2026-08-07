use async_trait::async_trait;
use automata_core::{JobId, JobIrVersion, RunId};
use thiserror::Error;

use crate::{MAX_JOB_IR_BYTES, ObjectKey, Sha256Digest, StoreError};

/// Immutable object metadata needed to load and validate a planned `JobIR`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobIrMetadata {
    job_id: JobId,
    run_id: RunId,
    version: JobIrVersion,
    encoded_size: u64,
    digest: Sha256Digest,
    object_key: ObjectKey,
}

impl JobIrMetadata {
    /// Creates bounded immutable `JobIR` metadata.
    ///
    /// # Errors
    ///
    /// Rejects empty or oversized encoded plans.
    pub fn new(
        job_id: JobId,
        run_id: RunId,
        version: JobIrVersion,
        encoded_size: u64,
        digest: Sha256Digest,
        object_key: ObjectKey,
    ) -> Result<Self, JobIrMetadataError> {
        if encoded_size == 0 || encoded_size > MAX_JOB_IR_BYTES {
            return Err(JobIrMetadataError::InvalidEncodedSize {
                size: encoded_size,
                maximum: MAX_JOB_IR_BYTES,
            });
        }
        Ok(Self {
            job_id,
            run_id,
            version,
            encoded_size,
            digest,
            object_key,
        })
    }

    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    #[must_use]
    pub const fn version(&self) -> JobIrVersion {
        self.version
    }

    #[must_use]
    pub const fn encoded_size(&self) -> u64 {
        self.encoded_size
    }

    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    #[must_use]
    pub const fn object_key(&self) -> &ObjectKey {
        &self.object_key
    }
}

/// One same-run edge in the expanded job DAG.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(clippy::struct_field_names)]
pub struct JobDependency {
    run_id: RunId,
    job_id: JobId,
    prerequisite_job_id: JobId,
}

impl JobDependency {
    /// Creates a directed dependency within an explicitly named run.
    ///
    /// # Errors
    ///
    /// Rejects a direct self-edge. The durable composite foreign keys prove
    /// that both job IDs belong to `run_id`.
    pub fn new(
        run_id: RunId,
        job_id: JobId,
        prerequisite_job_id: JobId,
    ) -> Result<Self, JobDependencyError> {
        if job_id == prerequisite_job_id {
            return Err(JobDependencyError::SelfDependency(job_id));
        }
        Ok(Self {
            run_id,
            job_id,
            prerequisite_job_id,
        })
    }

    #[must_use]
    pub const fn run_id(self) -> RunId {
        self.run_id
    }

    #[must_use]
    pub const fn job_id(self) -> JobId {
        self.job_id
    }

    #[must_use]
    pub const fn prerequisite_job_id(self) -> JobId {
        self.prerequisite_job_id
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum JobIrMetadataError {
    #[error("JobIR encoded size {size} is outside 1..={maximum}")]
    InvalidEncodedSize { size: u64, maximum: u64 },
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum JobDependencyError {
    #[error("job {0} cannot depend on itself")]
    SelfDependency(JobId),
}

/// Immutable `JobIR` metadata and expanded-DAG persistence port.
#[async_trait]
pub trait WorkflowPlanRepository: Send + Sync {
    async fn get_job_ir_metadata(&self, job_id: JobId) -> Result<JobIrMetadata, StoreError>;

    async fn insert_dependency(&self, dependency: JobDependency) -> Result<(), StoreError>;
}
