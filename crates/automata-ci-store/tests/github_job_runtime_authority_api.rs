use std::sync::Arc;

use automata_ci_core::{
    AttemptId, FencingToken, JobAuthorityProfile, JobId, JobIrVersion, Lease, LeaseId, RunId,
    RunnerId, RunnerSessionId, Sha256Digest, UnixMillis, WorkflowId,
};
use automata_ci_store::{
    GithubJobRuntimeAuthorityExecution, GithubJobRuntimeAuthorityRepository,
    GithubJobRuntimeAuthorityValueError, GithubRepositoryName, JobIrMetadata, ObjectKey,
    RunnerGeneration, RunnerSessionFence, SessionEpoch, StableRunnerSlot,
};
use uuid::Uuid;

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

fn metadata() -> JobIrMetadata {
    JobIrMetadata::new(
        JobId::from_uuid(Uuid::from_u128(3)),
        RunId::from_uuid(Uuid::from_u128(2)),
        JobIrVersion::current(),
        512,
        digest(7),
        ObjectKey::new("job-ir/exact.pb").expect("object key"),
    )
    .expect("metadata")
}

fn lease() -> Lease {
    Lease::new(
        LeaseId::from_uuid(Uuid::from_u128(4)),
        AttemptId::from_uuid(Uuid::from_u128(5)),
        RunnerId::from_uuid(Uuid::from_u128(6)),
        FencingToken::new(8).expect("fence"),
        UnixMillis::new(1_000),
        UnixMillis::new(10_000),
    )
    .expect("lease")
}

fn session(runner_id: RunnerId) -> RunnerSessionFence {
    RunnerSessionFence::new(
        RunnerSessionId::from_uuid(Uuid::from_u128(9)),
        runner_id,
        RunnerGeneration::new(2).expect("generation"),
        SessionEpoch::new(3).expect("epoch"),
    )
}

fn execution(
    profile: JobAuthorityProfile,
) -> Result<GithubJobRuntimeAuthorityExecution, GithubJobRuntimeAuthorityValueError> {
    let lease = lease();
    GithubJobRuntimeAuthorityExecution::new(
        WorkflowId::from_uuid(Uuid::from_u128(1)),
        GithubRepositoryName::new("owner/repository").expect("repository"),
        profile,
        metadata().digest(),
        lease.clone(),
        session(lease.runner_id()),
        StableRunnerSlot::new(1).expect("slot"),
        metadata(),
    )
}

#[test]
fn standard_and_credential_free_are_explicit_valid_inputs() {
    for profile in [
        JobAuthorityProfile::Standard,
        JobAuthorityProfile::CredentialFree,
    ] {
        let execution = execution(profile).expect("exact execution");
        assert_eq!(execution.authority_profile(), profile);
        assert_eq!(execution.permission_policy_sha256(), metadata().digest());
        assert_eq!(execution.workflow_id().as_uuid(), Uuid::from_u128(1));
        assert_eq!(
            execution.github_repository_name().as_str(),
            "owner/repository"
        );
    }
}

#[test]
fn policy_is_the_exact_immutable_job_ir_digest() {
    let lease = lease();
    let result = GithubJobRuntimeAuthorityExecution::new(
        WorkflowId::from_uuid(Uuid::from_u128(1)),
        GithubRepositoryName::new("owner/repository").expect("repository"),
        JobAuthorityProfile::Standard,
        digest(99),
        lease.clone(),
        session(lease.runner_id()),
        StableRunnerSlot::new(1).expect("slot"),
        metadata(),
    );
    assert_eq!(
        result.expect_err("foreign policy digest must fail"),
        GithubJobRuntimeAuthorityValueError::InvalidExecution
    );
}

#[test]
fn lease_and_session_runner_cannot_be_cross_bound() {
    let lease = lease();
    let result = GithubJobRuntimeAuthorityExecution::new(
        WorkflowId::from_uuid(Uuid::from_u128(1)),
        GithubRepositoryName::new("owner/repository").expect("repository"),
        JobAuthorityProfile::Standard,
        metadata().digest(),
        lease,
        session(RunnerId::from_uuid(Uuid::from_u128(66))),
        StableRunnerSlot::new(1).expect("slot"),
        metadata(),
    );
    assert_eq!(
        result.expect_err("foreign session must fail"),
        GithubJobRuntimeAuthorityValueError::InvalidExecution
    );
}

#[test]
fn nil_workflow_identity_is_rejected() {
    let lease = lease();
    let result = GithubJobRuntimeAuthorityExecution::new(
        WorkflowId::from_uuid(Uuid::nil()),
        GithubRepositoryName::new("owner/repository").expect("repository"),
        JobAuthorityProfile::Standard,
        metadata().digest(),
        lease.clone(),
        session(lease.runner_id()),
        StableRunnerSlot::new(1).expect("slot"),
        metadata(),
    );
    assert_eq!(
        result.expect_err("nil workflow must fail"),
        GithubJobRuntimeAuthorityValueError::InvalidExecution
    );
}

#[allow(dead_code)]
fn repository_port_is_object_safe(value: Arc<dyn GithubJobRuntimeAuthorityRepository>) {
    drop(value);
}
