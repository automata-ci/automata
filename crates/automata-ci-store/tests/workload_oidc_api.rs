use async_trait::async_trait;
use automata_ci_core::{
    AttemptId, FencingToken, JobId, JobIrVersion, Lease, LeaseId, RunId, RunnerId, RunnerSessionId,
    Sha256Digest, UnixMillis, WorkflowId,
};
use automata_ci_store::{
    JobIrMetadata, MAXIMUM_OIDC_KEYS_PER_KEYRING, MAXIMUM_REQUEST_BEARER_CLOCK_SKEW_SECONDS,
    OIDC_JWKS_CACHE_SECONDS, ObjectKey, ReserveWorkloadOidcAuthority, RetainWorkloadOidcKey,
    RunnerGeneration, RunnerSessionFence, SessionEpoch, StableRunnerSlot,
    WORKLOAD_OIDC_REQUEST_BEARER_KEY_FINGERPRINT_DOMAIN, WorkloadOidcAuthorityProposal,
    WorkloadOidcCurrentPolicy, WorkloadOidcExecutionIdentity, WorkloadOidcKeyDeadline,
    WorkloadOidcKeyRetentionRepository, WorkloadOidcKeyUse, WorkloadOidcLoadedKey,
    WorkloadOidcStoreError, WorkloadOidcSubjectPolicyMode, WorkloadOidcSubjectPolicyRevision,
    workload_oidc_rs256_public_key_fingerprint,
};
use automata_ci_workload_oidc::{OidcAuthorityId, OidcKeyId, RsaPublicJwk};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

const RSA_MODULUS: &str = "3EB2d40ghnbyGr9du8XI5MMt_dHBRJlGaIQzk_fgMxwAxiToz5Ck540SPVcosHkRC-YjGIXjhwDSOlSJ9kxsoQRM5venRhsZeQWeuo_82S95k6CFguafVLvOSmFKltf5obDHo6DBxum_C_1jc4ZTJGEi1K7AV33qhJ_qZfAMI8K8a6xIpkXtcpTDU-yxTrdFQF5yzW7cVqyoXjHbcxIIS2UMVZTMJ3Hv5pgDxe9eYhVlxkBO0oZn89jVVMSfKnThlsj02cd9N5doFuJEKB5NTYGG9E7uWnOEq_jddN-NNa8hU1PTSqpzwIdDs1ZBet2wmNl5Wr1KI981Rkp2FTvPkw";
const RSA_EXPONENT: &str = "AQAB";

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

fn runtime_execution() -> WorkloadOidcExecutionIdentity {
    let run_id = RunId::new();
    let job_id = JobId::new();
    let runner_id = RunnerId::new();
    WorkloadOidcExecutionIdentity::new(
        WorkflowId::new(),
        automata_ci_store::GithubRepositoryName::new("octo-org/example").expect("repository"),
        run_id,
        job_id,
        Lease::new(
            LeaseId::new(),
            AttemptId::new(),
            runner_id,
            FencingToken::new(7).expect("fence"),
            UnixMillis::new(12_345),
            UnixMillis::new(3_612_345),
        )
        .expect("lease"),
        RunnerSessionFence::new(
            RunnerSessionId::new(),
            runner_id,
            RunnerGeneration::new(3).expect("generation"),
            SessionEpoch::new(4).expect("epoch"),
        ),
        StableRunnerSlot::new(2).expect("slot"),
        JobIrMetadata::new(
            job_id,
            run_id,
            JobIrVersion::current(),
            1_024,
            digest(1),
            ObjectKey::new("job-ir/v1/example").expect("object key"),
        )
        .expect("JobIR metadata"),
    )
    .expect("runtime-only execution identity")
}

fn current_policy() -> WorkloadOidcCurrentPolicy {
    WorkloadOidcCurrentPolicy::new(
        WorkloadOidcSubjectPolicyMode::StableOwnerEvidence,
        WorkloadOidcSubjectPolicyRevision::new(11).expect("policy revision"),
        digest(3),
        digest(5),
        30,
        25,
    )
    .expect("stable-owner current policy")
}

#[test]
fn authority_request_accepts_only_runtime_coordinates_and_current_policy() {
    let execution = runtime_execution();
    let proposal = WorkloadOidcAuthorityProposal::new(
        OidcAuthorityId::from_uuid(Uuid::new_v4()).expect("authority ID"),
        OidcKeyId::new("hmac-2026-08").expect("key ID"),
        digest(6),
        30,
        12,
        612,
        digest(7),
    )
    .expect("proposal");
    let request = ReserveWorkloadOidcAuthority::new(
        execution,
        current_policy(),
        proposal,
        UnixMillis::new(12_500),
    )
    .expect("runtime authority request");

    assert_eq!(request.proposal().issued_at_seconds(), 12);
    assert_eq!(
        request.execution().job_ir().version(),
        JobIrVersion::current()
    );
    assert_eq!(
        request.execution().github_repository_name().as_str(),
        "octo-org/example"
    );
    let rendered = format!("{request:?}");
    assert!(!rendered.contains("github_owner_id"));
    assert!(!rendered.contains("additional_claims"));
    assert_eq!(
        request.current_policy().subject_policy_mode(),
        WorkloadOidcSubjectPolicyMode::StableOwnerEvidence
    );
    assert!(
        ReserveWorkloadOidcAuthority::new(
            request.execution().clone(),
            request.current_policy(),
            request.proposal().clone(),
            UnixMillis::new(12_344),
        )
        .is_err(),
        "an observation before lease issuance must fail"
    );
    assert!(
        ReserveWorkloadOidcAuthority::new(
            request.execution().clone(),
            request.current_policy(),
            request.proposal().clone(),
            UnixMillis::new(612_000),
        )
        .is_err(),
        "an expired bearer proposal must fail"
    );

    let wrong_anchor = WorkloadOidcAuthorityProposal::new(
        OidcAuthorityId::from_uuid(Uuid::new_v4()).expect("authority ID"),
        OidcKeyId::new("hmac-2026-08").expect("key ID"),
        digest(6),
        30,
        13,
        613,
        digest(7),
    )
    .expect("proposal");
    assert!(
        ReserveWorkloadOidcAuthority::new(
            runtime_execution(),
            current_policy(),
            wrong_anchor,
            UnixMillis::new(12_500),
        )
        .is_err()
    );
}

#[test]
fn current_policy_is_stable_owner_only_and_bounded() {
    assert!(WorkloadOidcSubjectPolicyRevision::new(i64::MAX as u64).is_ok());
    assert!(WorkloadOidcSubjectPolicyRevision::new(i64::MAX as u64 + 1).is_err());
    let revision = WorkloadOidcSubjectPolicyRevision::new(1).expect("revision");
    assert!(
        WorkloadOidcCurrentPolicy::new(
            WorkloadOidcSubjectPolicyMode::StableOwnerEvidence,
            revision,
            digest(2),
            digest(4),
            MAXIMUM_REQUEST_BEARER_CLOCK_SKEW_SECONDS + 1,
            25,
        )
        .is_err()
    );
}

#[test]
fn retention_deadlines_cover_verifier_skew_and_the_jwks_cache_horizon() {
    assert_eq!(OIDC_JWKS_CACHE_SECONDS, 300);
    assert_eq!(MAXIMUM_OIDC_KEYS_PER_KEYRING, 16);
    assert_eq!(MAXIMUM_REQUEST_BEARER_CLOCK_SKEW_SECONDS, 300);
    let request = RetainWorkloadOidcKey::request_bearer(
        OidcKeyId::new("hmac-old").expect("key ID"),
        digest(1),
        1_000,
        25,
        900,
    )
    .expect("request retention");
    assert_eq!(request.not_after_seconds(), 1_025);

    let signing = RetainWorkloadOidcKey::id_token_signing(
        OidcKeyId::new("rsa-old").expect("key ID"),
        digest(2),
        1_000,
        25,
        900,
    )
    .expect("signing retention");
    assert_eq!(
        signing.not_after_seconds(),
        1_000 + OIDC_JWKS_CACHE_SECONDS + 25
    );
}

#[test]
fn key_fingerprints_have_one_exact_replica_stable_preimage() {
    let first = RsaPublicJwk::new(
        OidcKeyId::new("rsa-a").expect("key ID"),
        RSA_MODULUS,
        RSA_EXPONENT,
    )
    .expect("JWK");
    let same_material_new_id = RsaPublicJwk::new(
        OidcKeyId::new("rsa-b").expect("key ID"),
        RSA_MODULUS,
        RSA_EXPONENT,
    )
    .expect("JWK");
    let different_exponent =
        RsaPublicJwk::new(OidcKeyId::new("rsa-a").expect("key ID"), RSA_MODULUS, "Aw")
            .expect("JWK");
    assert_eq!(
        workload_oidc_rs256_public_key_fingerprint(&first),
        workload_oidc_rs256_public_key_fingerprint(&same_material_new_id)
    );
    assert_eq!(
        workload_oidc_rs256_public_key_fingerprint(&first).to_string(),
        "7194971377360fe51d714f5ad346c2aa6631ae54c1a74cca77f61b41d23842e6"
    );
    assert_ne!(
        workload_oidc_rs256_public_key_fingerprint(&first),
        workload_oidc_rs256_public_key_fingerprint(&different_exponent)
    );

    let raw_hmac = [9_u8; 32];
    let mut hasher = Sha256::new();
    hasher.update(WORKLOAD_OIDC_REQUEST_BEARER_KEY_FINGERPRINT_DOMAIN);
    hasher.update(
        u64::try_from(raw_hmac.len())
            .expect("bounded")
            .to_be_bytes(),
    );
    hasher.update(raw_hmac);
    assert_eq!(
        Sha256Digest::from_bytes(hasher.finalize().into()).to_string(),
        "3dbffceae0adccf9a8ca95f7c73707202e4ba9a2741c0699cebbae7176090ccd"
    );
}

#[derive(Debug)]
struct MemoryRetention {
    deadlines: Vec<WorkloadOidcKeyDeadline>,
}

#[async_trait]
impl WorkloadOidcKeyRetentionRepository for MemoryRetention {
    async fn retain_workload_oidc_key(
        &self,
        _request: RetainWorkloadOidcKey,
    ) -> Result<WorkloadOidcKeyDeadline, WorkloadOidcStoreError> {
        Err(WorkloadOidcStoreError::Unavailable)
    }

    async fn workload_oidc_key_deadline(
        &self,
        key_use: WorkloadOidcKeyUse,
        key_id: &OidcKeyId,
    ) -> Result<Option<WorkloadOidcKeyDeadline>, WorkloadOidcStoreError> {
        Ok(self
            .deadlines
            .iter()
            .find(|deadline| deadline.key_use() == key_use && deadline.key_id() == key_id)
            .cloned())
    }

    async fn required_workload_oidc_keys(
        &self,
        observed_at_seconds: u64,
    ) -> Result<Vec<WorkloadOidcKeyDeadline>, WorkloadOidcStoreError> {
        let mut required: Vec<_> = self
            .deadlines
            .iter()
            .filter(|deadline| deadline.not_after_seconds() > observed_at_seconds)
            .cloned()
            .collect();
        required.sort_by(|left, right| {
            (left.key_use(), left.key_id()).cmp(&(right.key_use(), right.key_id()))
        });
        Ok(required)
    }
}

#[tokio::test]
async fn readiness_exposes_every_old_key_until_its_deadline() {
    let old_retention = RetainWorkloadOidcKey::id_token_signing(
        OidcKeyId::new("rsa-old").expect("key ID"),
        digest(1),
        1_000,
        0,
        900,
    )
    .expect("retention");
    let deadline = WorkloadOidcKeyDeadline::from_retention(&old_retention);
    let repository = MemoryRetention {
        deadlines: vec![deadline.clone()],
    };
    let new_only = [WorkloadOidcLoadedKey::new(
        WorkloadOidcKeyUse::IdTokenSigning,
        OidcKeyId::new("rsa-new").expect("key ID"),
        digest(2),
    )];
    assert_eq!(
        repository
            .verify_workload_oidc_key_readiness(1_299, &new_only)
            .await,
        Err(WorkloadOidcStoreError::Conflict)
    );
    let loaded = [
        new_only[0].clone(),
        WorkloadOidcLoadedKey::new(
            WorkloadOidcKeyUse::IdTokenSigning,
            OidcKeyId::new("rsa-old").expect("key ID"),
            digest(1),
        ),
    ];
    repository
        .verify_workload_oidc_key_readiness(1_299, &loaded)
        .await
        .expect("old key retained");
    repository
        .verify_workload_oidc_key_readiness(deadline.not_after_seconds(), &new_only)
        .await
        .expect("deadline is exclusive");
}

#[tokio::test]
async fn readiness_rejects_unfingerprinted_durable_keys() {
    let deadline = WorkloadOidcKeyDeadline::from_durable_parts(
        WorkloadOidcKeyUse::RequestBearer,
        OidcKeyId::new("hmac-old").expect("key ID"),
        None,
        1_000,
    )
    .expect("durable deadline");
    let repository = MemoryRetention {
        deadlines: vec![deadline],
    };
    assert_eq!(
        repository
            .verify_workload_oidc_key_readiness(
                999,
                &[WorkloadOidcLoadedKey::new(
                    WorkloadOidcKeyUse::RequestBearer,
                    OidcKeyId::new("hmac-old").expect("key ID"),
                    digest(1),
                )],
            )
            .await,
        Err(WorkloadOidcStoreError::CorruptData)
    );
}
