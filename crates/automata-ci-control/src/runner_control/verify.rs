use automata_ci_core::{JobIrEnvelope, JobIrVersion, Sha256Digest};
use automata_ci_protocol::ProtocolLimits;
use automata_ci_protocol_protobuf::{decode_job_ir, encode_job_ir};
use automata_ci_store::JobIrMetadata;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Fail-closed reason an immutable `JobIR` object cannot be offered.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum JobIrBlobError {
    /// The object length differs from immutable metadata.
    #[error("JobIR object size does not match immutable metadata")]
    SizeMismatch,
    /// The object content digest differs from immutable metadata.
    #[error("JobIR object digest does not match immutable metadata")]
    DigestMismatch,
    /// The durable or decoded schema differs from the negotiated schema.
    #[error("JobIR schema does not match the negotiated session")]
    SchemaMismatch,
    /// The decoded job/run identity differs from immutable metadata.
    #[error("JobIR identity does not match immutable metadata")]
    IdentityMismatch,
    /// The bounded protobuf adapter rejected the object.
    #[error("JobIR object is malformed")]
    Malformed,
    /// The bytes are valid protobuf but not the deterministic canonical representation.
    #[error("JobIR object is not canonically encoded")]
    NonCanonical,
}

/// Verifies size, SHA-256, negotiated schema, identities, validation, and canonical protobuf.
///
/// # Errors
/// Returns a typed fail-closed error before a lease offer can be published.
pub fn verify_job_ir_blob(
    metadata: &JobIrMetadata,
    bytes: &[u8],
    negotiated: JobIrVersion,
    limits: &ProtocolLimits,
) -> Result<JobIrEnvelope, JobIrBlobError> {
    if u64::try_from(bytes.len()).ok() != Some(metadata.encoded_size()) {
        return Err(JobIrBlobError::SizeMismatch);
    }
    if Sha256Digest::from_bytes(Sha256::digest(bytes).into()) != metadata.digest() {
        return Err(JobIrBlobError::DigestMismatch);
    }
    if metadata.version() != negotiated {
        return Err(JobIrBlobError::SchemaMismatch);
    }
    let job = decode_job_ir(bytes, limits).map_err(|_| JobIrBlobError::Malformed)?;
    if job.version() != metadata.version() {
        return Err(JobIrBlobError::SchemaMismatch);
    }
    if job.job().job_id() != metadata.job_id() || job.job().run_id() != metadata.run_id() {
        return Err(JobIrBlobError::IdentityMismatch);
    }
    let canonical = encode_job_ir(&job, limits).map_err(|_| JobIrBlobError::Malformed)?;
    if canonical != bytes {
        return Err(JobIrBlobError::NonCanonical);
    }
    Ok(job)
}
