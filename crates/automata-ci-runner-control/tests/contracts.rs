use automata_ci_core::{
    JobId, JobInstanceIdentity, JobIr, JobIrEnvelope, JobIrVersion, JobSource, RunId,
    RunValueTemplates, RunnerRequirements, RuntimeBoolean, SemanticStep, Sha256Digest,
    ShellTemplate, StepId, StepIr, ValueTemplate, WorkflowId,
};
use automata_ci_protocol::ProtocolLimits;
use automata_ci_protocol_protobuf::encode_job_ir;
use automata_ci_runner_control::{
    ControlPortError, ImmutableBlobJobIrReader, JOB_IR_PROTOBUF_MEDIA_TYPE, JobIrBlobError,
    JobIrObjectReader, MAX_HEARTBEAT_INTERVAL_MILLIS, MAX_LEASE_DURATION_MILLIS,
    MAX_NO_WORK_RETRY_AFTER_MILLIS, RunnerControlConfig, RunnerControlConfigError,
    verify_job_ir_blob,
};
use automata_ci_store::{JobIrMetadata, ObjectKey};
use sha2::{Digest as _, Sha256};
fn envelope() -> JobIrEnvelope {
    JobIrEnvelope::new(
        WorkflowId::new(),
        JobSource::new(
            "github",
            "automata-ci/automata",
            "0123456789abcdef",
            ".ci/workflows/ci.yml",
            "push",
        ),
        automata_ci_core::JobExecutionContext::new(
            "CI",
            "refs/heads/main",
            "/__w/automata/automata",
            automata_ci_core::JobContentReference::new(
                "events/push.json",
                automata_ci_core::Sha256Digest::from_bytes([0x42; 32]),
                2,
                "application/json",
            ),
            automata_ci_core::JobContentReference::new(
                "contexts/test.pb",
                automata_ci_core::Sha256Digest::from_bytes([0x43; 32]),
                2,
                "application/vnd.automata.job-runtime-context.protobuf",
            ),
        ),
        JobIr::new(
            JobId::new(),
            RunId::new(),
            "test",
            RunnerRequirements::default(),
            JobInstanceIdentity::new("test", 0, 1, Sha256Digest::from_bytes([0x44; 32]))
                .expect("job instance"),
            false,
            vec![StepIr::new(
                StepId::new("tests").expect("step ID"),
                ValueTemplate::literal("Run tests").expect("step name template"),
                RuntimeBoolean::literal(false),
                SemanticStep::run(RunValueTemplates::new(
                    ValueTemplate::literal("cargo test --workspace").expect("command template"),
                    ShellTemplate::default_shell(),
                )),
            )],
        ),
    )
}

fn fixture() -> (JobIrEnvelope, Vec<u8>, JobIrMetadata) {
    let job = envelope();
    let bytes = encode_job_ir(&job, &ProtocolLimits::default()).expect("encode JobIR");
    let digest = Sha256Digest::from_bytes(Sha256::digest(&bytes).into());
    let metadata = JobIrMetadata::new(
        job.job().job_id(),
        job.job().run_id(),
        job.version(),
        u64::try_from(bytes.len()).expect("bounded length"),
        digest,
        ObjectKey::new("job-ir/test.pb").expect("object key"),
    )
    .expect("metadata");
    (job, bytes, metadata)
}

#[test]
fn config_rejects_zero_timing_values() {
    assert_eq!(
        RunnerControlConfig::new(0, 60_000, 1_000, ProtocolLimits::default()),
        Err(RunnerControlConfigError::ZeroDuration)
    );
    assert_eq!(
        RunnerControlConfig::new(1, 0, 1_000, ProtocolLimits::default()),
        Err(RunnerControlConfigError::ZeroDuration)
    );
    assert_eq!(
        RunnerControlConfig::new(1, 2, 0, ProtocolLimits::default()),
        Err(RunnerControlConfigError::ZeroDuration)
    );
}

#[test]
fn config_enforces_g1_timing_bounds_and_two_heartbeat_lease() {
    let limits = ProtocolLimits::default();
    assert!(
        RunnerControlConfig::new(
            MAX_HEARTBEAT_INTERVAL_MILLIS,
            MAX_LEASE_DURATION_MILLIS,
            MAX_NO_WORK_RETRY_AFTER_MILLIS,
            limits,
        )
        .is_ok()
    );
    assert_eq!(
        RunnerControlConfig::new(
            MAX_HEARTBEAT_INTERVAL_MILLIS + 1,
            MAX_LEASE_DURATION_MILLIS,
            1,
            limits,
        ),
        Err(RunnerControlConfigError::HeartbeatIntervalTooLarge {
            value: MAX_HEARTBEAT_INTERVAL_MILLIS + 1,
            maximum: MAX_HEARTBEAT_INTERVAL_MILLIS,
        })
    );
    assert_eq!(
        RunnerControlConfig::new(1, MAX_LEASE_DURATION_MILLIS + 1, 1, limits),
        Err(RunnerControlConfigError::LeaseDurationTooLarge {
            value: MAX_LEASE_DURATION_MILLIS + 1,
            maximum: MAX_LEASE_DURATION_MILLIS,
        })
    );
    assert_eq!(
        RunnerControlConfig::new(1, 2, MAX_NO_WORK_RETRY_AFTER_MILLIS + 1, limits),
        Err(RunnerControlConfigError::NoWorkRetryAfterTooLarge {
            value: MAX_NO_WORK_RETRY_AFTER_MILLIS + 1,
            maximum: MAX_NO_WORK_RETRY_AFTER_MILLIS,
        })
    );
    assert_eq!(
        RunnerControlConfig::new(1_001, 2_001, 1, limits),
        Err(RunnerControlConfigError::LeaseDurationTooShort {
            heartbeat_interval_millis: 1_001,
            lease_duration_millis: 2_001,
        })
    );
}

#[tokio::test]
async fn immutable_blob_adapter_verifies_full_job_ir_descriptor() {
    let (_job, bytes, metadata) = fixture();
    let store = Arc::new(MemoryBlobStore::default());
    let payload = BlobPayload::from_bytes(
        BlobKey::new(metadata.object_key().as_str()).expect("blob key"),
        MediaType::new(JOB_IR_PROTOBUF_MEDIA_TYPE).expect("media type"),
        bytes.clone().into(),
    );
    assert_eq!(
        store.put_if_absent(payload).await.expect("put"),
        PutBlobOutcome::Created
    );
    let reader = ImmutableBlobJobIrReader::new(store);
    assert_eq!(
        reader
            .read_job_ir(&metadata, metadata.encoded_size())
            .await
            .expect("verified read"),
        bytes
    );
    assert_eq!(
        reader
            .read_job_ir(&metadata, metadata.encoded_size() - 1)
            .await,
        Err(ControlPortError::Corrupt)
    );
}

#[test]
fn immutable_job_ir_accepts_exact_canonical_object() {
    let (job, bytes, metadata) = fixture();
    assert_eq!(
        verify_job_ir_blob(
            &metadata,
            &bytes,
            JobIrVersion::current(),
            &ProtocolLimits::default()
        )
        .expect("verified JobIR"),
        job,
    );
}

#[test]
fn immutable_job_ir_rejects_size_before_decode() {
    let (_job, mut bytes, metadata) = fixture();
    bytes.push(0);
    assert_eq!(
        verify_job_ir_blob(
            &metadata,
            &bytes,
            JobIrVersion::current(),
            &ProtocolLimits::default()
        ),
        Err(JobIrBlobError::SizeMismatch),
    );
}

#[test]
fn immutable_job_ir_rejects_digest_mismatch() {
    let (job, bytes, _metadata) = fixture();
    let wrong = JobIrMetadata::new(
        job.job().job_id(),
        job.job().run_id(),
        job.version(),
        u64::try_from(bytes.len()).expect("bounded length"),
        Sha256Digest::from_bytes([7; 32]),
        ObjectKey::new("job-ir/test.pb").expect("object key"),
    )
    .expect("metadata");
    assert_eq!(
        verify_job_ir_blob(
            &wrong,
            &bytes,
            JobIrVersion::current(),
            &ProtocolLimits::default()
        ),
        Err(JobIrBlobError::DigestMismatch),
    );
}

#[test]
fn immutable_job_ir_rejects_negotiated_schema_mismatch() {
    let (_job, bytes, metadata) = fixture();
    let other = JobIrVersion::new(JobIrVersion::current().get() + 1).expect("positive version");
    assert_eq!(
        verify_job_ir_blob(&metadata, &bytes, other, &ProtocolLimits::default()),
        Err(JobIrBlobError::SchemaMismatch),
    );
}

#[test]
fn immutable_job_ir_rejects_metadata_identity_mismatch() {
    let (job, bytes, _metadata) = fixture();
    let wrong = JobIrMetadata::new(
        JobId::new(),
        job.job().run_id(),
        job.version(),
        u64::try_from(bytes.len()).expect("bounded length"),
        Sha256Digest::from_bytes(Sha256::digest(&bytes).into()),
        ObjectKey::new("job-ir/test.pb").expect("object key"),
    )
    .expect("metadata");
    assert_eq!(
        verify_job_ir_blob(
            &wrong,
            &bytes,
            JobIrVersion::current(),
            &ProtocolLimits::default()
        ),
        Err(JobIrBlobError::IdentityMismatch),
    );
}
use std::sync::Arc;

use automata_ci_blob::{
    BlobKey, BlobPayload, ImmutableBlobStore as _, MediaType, MemoryBlobStore, PutBlobOutcome,
};
