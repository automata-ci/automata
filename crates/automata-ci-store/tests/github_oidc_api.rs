use std::sync::Arc;

use async_trait::async_trait;
use automata_ci_core::{
    AttemptId, FencingToken, JobId, JobIrVersion, Lease, LeaseId, RunId, RunnerId, RunnerSessionId,
    Sha256Digest, UnixMillis, WorkflowId,
};
use automata_ci_oidc_github::{OidcAuthorityId, OidcIssuanceRepository, OidcKeyId, RsaPublicJwk};
use automata_ci_store::{
    GITHUB_OIDC_REQUEST_BEARER_KEY_FINGERPRINT_DOMAIN, GithubOidcAuthorityProposal,
    GithubOidcAuthorityRepository, GithubOidcCurrentPolicy, GithubOidcCurrentnessClock,
    GithubOidcCurrentnessClockError, GithubOidcExecutionIdentity, GithubOidcKeyDeadline,
    GithubOidcKeyRetentionRepository, GithubOidcKeyUse, GithubOidcLoadedKey, GithubOidcStoreError,
    GithubOidcSubjectPolicyMode, GithubOidcSubjectPolicyRevision, JobIrMetadata,
    MAXIMUM_OIDC_KEYS_PER_KEYRING, MAXIMUM_REQUEST_BEARER_CLOCK_SKEW_SECONDS,
    OIDC_JWKS_CACHE_SECONDS, ObjectKey, PostgresGithubOidcAuthorityRepository,
    PostgresGithubOidcIssuanceRepository, PostgresStore, ReserveGithubOidcAuthority,
    RetainGithubOidcKey, RunnerGeneration, RunnerSessionFence, SessionEpoch, StableRunnerSlot,
    github_oidc_rs256_public_key_fingerprint,
};
use sha2::{Digest as _, Sha256};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

const RSA_MODULUS: &str = "3EB2d40ghnbyGr9du8XI5MMt_dHBRJlGaIQzk_fgMxwAxiToz5Ck540SPVcosHkRC-YjGIXjhwDSOlSJ9kxsoQRM5venRhsZeQWeuo_82S95k6CFguafVLvOSmFKltf5obDHo6DBxum_C_1jc4ZTJGEi1K7AV33qhJ_qZfAMI8K8a6xIpkXtcpTDU-yxTrdFQF5yzW7cVqyoXjHbcxIIS2UMVZTMJ3Hv5pgDxe9eYhVlxkBO0oZn89jVVMSfKnThlsj02cd9N5doFuJEKB5NTYGG9E7uWnOEq_jddN-NNa8hU1PTSqpzwIdDs1ZBet2wmNl5Wr1KI981Rkp2FTvPkw";
const RSA_EXPONENT: &str = "AQAB";

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

fn runtime_execution() -> GithubOidcExecutionIdentity {
    let run_id = RunId::new();
    let job_id = JobId::new();
    let runner_id = RunnerId::new();
    GithubOidcExecutionIdentity::new(
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
            ObjectKey::new("job-ir/v5/example").expect("object key"),
        )
        .expect("JobIR metadata"),
    )
    .expect("runtime-only execution identity")
}

fn current_policy() -> GithubOidcCurrentPolicy {
    GithubOidcCurrentPolicy::new(
        GithubOidcSubjectPolicyMode::StableOwnerEvidence,
        GithubOidcSubjectPolicyRevision::new(11).expect("policy revision"),
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
    let proposal = GithubOidcAuthorityProposal::new(
        OidcAuthorityId::from_uuid(Uuid::new_v4()).expect("authority ID"),
        OidcKeyId::new("hmac-2026-08").expect("key ID"),
        digest(6),
        30,
        12,
        612,
        digest(7),
    )
    .expect("proposal");
    let request = ReserveGithubOidcAuthority::new(
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
        GithubOidcSubjectPolicyMode::StableOwnerEvidence
    );
    assert!(
        ReserveGithubOidcAuthority::new(
            request.execution().clone(),
            request.current_policy(),
            request.proposal().clone(),
            UnixMillis::new(12_344),
        )
        .is_err(),
        "an observation before lease issuance must fail"
    );
    assert!(
        ReserveGithubOidcAuthority::new(
            request.execution().clone(),
            request.current_policy(),
            request.proposal().clone(),
            UnixMillis::new(612_000),
        )
        .is_err(),
        "an expired bearer proposal must fail"
    );

    let wrong_anchor = GithubOidcAuthorityProposal::new(
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
        ReserveGithubOidcAuthority::new(
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
    assert!(GithubOidcSubjectPolicyRevision::new(i64::MAX as u64).is_ok());
    assert!(GithubOidcSubjectPolicyRevision::new(i64::MAX as u64 + 1).is_err());
    let revision = GithubOidcSubjectPolicyRevision::new(1).expect("revision");
    assert!(
        GithubOidcCurrentPolicy::new(
            GithubOidcSubjectPolicyMode::StableOwnerEvidence,
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
    let request = RetainGithubOidcKey::request_bearer(
        OidcKeyId::new("hmac-old").expect("key ID"),
        digest(1),
        1_000,
        25,
        900,
    )
    .expect("request retention");
    assert_eq!(request.not_after_seconds(), 1_025);

    let signing = RetainGithubOidcKey::id_token_signing(
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
        github_oidc_rs256_public_key_fingerprint(&first),
        github_oidc_rs256_public_key_fingerprint(&same_material_new_id)
    );
    assert_eq!(
        github_oidc_rs256_public_key_fingerprint(&first).to_string(),
        "baf22adc358a7a8b8b68dda14984806007cdc6be4d40d10061f5c2b5f29712e5"
    );
    assert_ne!(
        github_oidc_rs256_public_key_fingerprint(&first),
        github_oidc_rs256_public_key_fingerprint(&different_exponent)
    );

    let raw_hmac = [9_u8; 32];
    let mut hasher = Sha256::new();
    hasher.update(GITHUB_OIDC_REQUEST_BEARER_KEY_FINGERPRINT_DOMAIN);
    hasher.update(
        u64::try_from(raw_hmac.len())
            .expect("bounded")
            .to_be_bytes(),
    );
    hasher.update(raw_hmac);
    assert_eq!(
        Sha256Digest::from_bytes(hasher.finalize().into()).to_string(),
        "6c34a18a6ffd168a2e7d0ef6dc1f893d4c76ff88d520917b1f3206816488ff27"
    );
}

#[derive(Debug)]
struct MemoryRetention {
    deadlines: Vec<GithubOidcKeyDeadline>,
}

#[async_trait]
impl GithubOidcKeyRetentionRepository for MemoryRetention {
    async fn retain_github_oidc_key(
        &self,
        _request: RetainGithubOidcKey,
    ) -> Result<GithubOidcKeyDeadline, GithubOidcStoreError> {
        Err(GithubOidcStoreError::Unavailable)
    }

    async fn github_oidc_key_deadline(
        &self,
        key_use: GithubOidcKeyUse,
        key_id: &OidcKeyId,
    ) -> Result<Option<GithubOidcKeyDeadline>, GithubOidcStoreError> {
        Ok(self
            .deadlines
            .iter()
            .find(|deadline| deadline.key_use() == key_use && deadline.key_id() == key_id)
            .cloned())
    }

    async fn required_github_oidc_keys(
        &self,
        observed_at_seconds: u64,
    ) -> Result<Vec<GithubOidcKeyDeadline>, GithubOidcStoreError> {
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
    let old_retention = RetainGithubOidcKey::id_token_signing(
        OidcKeyId::new("rsa-old").expect("key ID"),
        digest(1),
        1_000,
        0,
        900,
    )
    .expect("retention");
    let deadline = GithubOidcKeyDeadline::from_retention(&old_retention);
    let repository = MemoryRetention {
        deadlines: vec![deadline.clone()],
    };
    let new_only = [GithubOidcLoadedKey::new(
        GithubOidcKeyUse::IdTokenSigning,
        OidcKeyId::new("rsa-new").expect("key ID"),
        digest(2),
    )];
    assert_eq!(
        repository
            .verify_github_oidc_key_readiness(1_299, &new_only)
            .await,
        Err(GithubOidcStoreError::Conflict)
    );
    let loaded = [
        new_only[0].clone(),
        GithubOidcLoadedKey::new(
            GithubOidcKeyUse::IdTokenSigning,
            OidcKeyId::new("rsa-old").expect("key ID"),
            digest(1),
        ),
    ];
    repository
        .verify_github_oidc_key_readiness(1_299, &loaded)
        .await
        .expect("old key retained");
    repository
        .verify_github_oidc_key_readiness(deadline.not_after_seconds(), &new_only)
        .await
        .expect("deadline is exclusive");
}

#[tokio::test]
async fn readiness_rejects_unfingerprinted_durable_keys() {
    let deadline = GithubOidcKeyDeadline::from_durable_parts(
        GithubOidcKeyUse::RequestBearer,
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
            .verify_github_oidc_key_readiness(
                999,
                &[GithubOidcLoadedKey::new(
                    GithubOidcKeyUse::RequestBearer,
                    OidcKeyId::new("hmac-old").expect("key ID"),
                    digest(1),
                )],
            )
            .await,
        Err(GithubOidcStoreError::CorruptData)
    );
}

#[tokio::test]
async fn postgres_adapter_requires_bounded_signing_metadata_and_is_object_safe() {
    fn assert_ports(
        _: &dyn GithubOidcAuthorityRepository,
        _: &dyn GithubOidcKeyRetentionRepository,
        _: &dyn OidcIssuanceRepository,
    ) {
    }
    let _ = assert_ports;

    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://postgres:do-not-render@127.0.0.1/automata")
        .expect("lazy pool");
    let store = PostgresStore::from_postgres_pool(pool);
    let clock: Arc<dyn GithubOidcCurrentnessClock> = Arc::new(FixedCurrentnessClock);
    let signing = GithubOidcLoadedKey::new(
        GithubOidcKeyUse::IdTokenSigning,
        OidcKeyId::new("rsa-current").expect("key ID"),
        digest(8),
    );
    let current_policy = current_policy();
    let adapter = PostgresGithubOidcIssuanceRepository::new(
        store.clone(),
        current_policy,
        [signing.clone()],
        Arc::clone(&clock),
    )
    .expect("configured adapter");
    let authority = PostgresGithubOidcAuthorityRepository::new(store.clone(), Arc::clone(&clock));
    assert_ports(&authority, &store, &adapter);
    let rendered = format!("{adapter:?}");
    assert!(rendered.contains("rsa-current"));
    assert!(!rendered.contains("do-not-render"));
    assert!(
        PostgresGithubOidcIssuanceRepository::new(
            store.clone(),
            current_policy,
            [],
            Arc::clone(&clock),
        )
        .is_err(),
        "an empty signing set must fail closed"
    );
    assert!(
        PostgresGithubOidcIssuanceRepository::new(
            store,
            current_policy,
            [signing.clone(), signing],
            clock,
        )
        .is_err(),
        "duplicate IDs must fail closed"
    );
}

#[derive(Debug)]
struct FixedCurrentnessClock;

impl GithubOidcCurrentnessClock for FixedCurrentnessClock {
    fn now_millis(&self) -> Result<UnixMillis, GithubOidcCurrentnessClockError> {
        Ok(UnixMillis::new(12_500))
    }
}
