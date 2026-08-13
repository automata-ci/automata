use automata_ci_core::{
    AttemptId, FencingToken, JobId, JobIrVersion, LeaseId, RunId, RunnerId, RunnerSessionId,
    Sha256Digest, UnixMillis,
};
use automata_ci_key_management::{ENVELOPE_SCHEMA_V1, EncryptedEnvelope, KeyId, WrappedDataKey};
use automata_ci_store::{
    AuthenticateGithubRuntimeAuthorityUnprotectedErasure, BeginGithubRuntimeAuthorityMint,
    ClaimGithubRuntimeAuthorityMint, ClaimGithubRuntimeAuthorityRevocation,
    ClaimedGithubRuntimeAuthorityMint, ClaimedGithubRuntimeAuthorityRevocation,
    GITHUB_AUTHORITY_EXPIRY_SKEW_MILLIS, GithubRepositoryId, GithubRepositoryName,
    GithubRuntimeAuthorityActivationSelectionTail, GithubRuntimeAuthorityClaimFence,
    GithubRuntimeAuthorityCommitDisposition, GithubRuntimeAuthorityEnvelopeMetadata,
    GithubRuntimeAuthorityIdentity, GithubRuntimeAuthorityMaterializationSelectionTail,
    GithubRuntimeAuthorityNamespace, GithubRuntimeAuthorityPreparationSelectionTail,
    GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityState,
    GithubRuntimeAuthorityTerminalReason, GithubRuntimeAuthorityValueError,
    GithubRuntimeAuthorityWorkerId, GithubServerServiceAppClientId, GithubServerServiceAppId,
    GithubServerServiceJwtIssuer, LogicalActivationGeneration,
    LogicalActivationPreparationGeneration, LogicalActivationWorkerId,
    LogicalMaterializationGeneration, LogicalMaterializationWorkerId, LogicalWorkSelectionId,
    MAX_GITHUB_AUTHORITY_MINT_CLAIM_MILLIS, MAX_GITHUB_AUTHORITY_REQUEST_MILLIS,
    ProtectedGithubRuntimeAuthority, ProviderConnectionId, ProviderInstallationId,
    ReadyGithubRuntimeAuthority, RepositoryId, RevalidateGithubRuntimeAuthorityRevocation,
    RevalidatedGithubRuntimeAuthorityRevocation, RunnerGeneration, SessionEpoch, StableRunnerSlot,
    TenantScope,
};
use uuid::Uuid;

#[derive(Clone, Copy)]
struct IdentityInputs {
    tenant: &'static str,
    attempt_id: u128,
    fencing_token: u64,
    lease_id: u128,
    lease_issued_at: i64,
    lease_expires_at: i64,
    run_id: u128,
    job_id: u128,
    runner_id: u128,
    runner_session_id: u128,
    runner_session_epoch: u64,
    runner_generation: u64,
    runner_slot: u16,
    job_ir_size_bytes: u64,
    job_ir_digest_byte: u8,
    repository_id: u128,
    provider_connection_id: u128,
    provider_installation_id: u64,
    github_app_id: u64,
    github_app_client_id: &'static str,
    github_app_jwt_issuer_kind: GithubServerServiceJwtIssuer,
    github_repository_id: u64,
    github_repository_name: &'static str,
    namespace: &'static str,
    policy_digest_byte: u8,
    app_key_spki_byte: u8,
    configuration_fingerprint_byte: u8,
    preparation_selection_id: u128,
    preparation_selection_owner_id: u128,
    preparation_selection_generation: u64,
    preparation_selection_descriptor_byte: u8,
    preparation_selection_claimed_at: i64,
    preparation_selection_expires_at: i64,
    activation_selection_id: u128,
    activation_selection_owner_id: u128,
    activation_selection_generation: u64,
    activation_selection_input_byte: u8,
    activation_selection_claimed_at: i64,
    activation_selection_expires_at: i64,
    materialization_selection_id: u128,
    materialization_selection_owner_id: u128,
    materialization_selection_generation: u64,
    materialization_selection_descriptor_byte: u8,
    materialization_selection_claimed_at: i64,
    materialization_selection_expires_at: i64,
    requested_at: i64,
    request_deadline: i64,
}

impl IdentityInputs {
    const fn base() -> Self {
        Self {
            tenant: "tenant-a",
            attempt_id: 1,
            fencing_token: 7,
            lease_id: 2,
            lease_issued_at: 1_000,
            lease_expires_at: 20_000,
            run_id: 3,
            job_id: 4,
            runner_id: 5,
            runner_session_id: 6,
            runner_session_epoch: 8,
            runner_generation: 9,
            runner_slot: 1,
            job_ir_size_bytes: 1_024,
            job_ir_digest_byte: 10,
            repository_id: 11,
            provider_connection_id: 16,
            provider_installation_id: 17,
            github_app_id: 18,
            github_app_client_id: "Iv1.automata-runtime",
            github_app_jwt_issuer_kind: GithubServerServiceJwtIssuer::AppClientId,
            github_repository_id: 12,
            github_repository_name: "automata-ci/automata",
            namespace: "github.actions.runtime",
            policy_digest_byte: 10,
            app_key_spki_byte: 13,
            configuration_fingerprint_byte: 15,
            preparation_selection_id: 21,
            preparation_selection_owner_id: 22,
            preparation_selection_generation: 23,
            preparation_selection_descriptor_byte: 24,
            preparation_selection_claimed_at: 500,
            preparation_selection_expires_at: 4_500,
            activation_selection_id: 25,
            activation_selection_owner_id: 26,
            activation_selection_generation: 27,
            activation_selection_input_byte: 28,
            activation_selection_claimed_at: 600,
            activation_selection_expires_at: 4_600,
            materialization_selection_id: 29,
            materialization_selection_owner_id: 30,
            materialization_selection_generation: 31,
            materialization_selection_descriptor_byte: 32,
            materialization_selection_claimed_at: 700,
            materialization_selection_expires_at: 4_700,
            requested_at: 2_000,
            request_deadline: 3_000,
        }
    }

    fn build(self) -> GithubRuntimeAuthorityIdentity {
        self.try_build().expect("valid identity inputs")
    }

    fn try_build(self) -> Result<GithubRuntimeAuthorityIdentity, GithubRuntimeAuthorityValueError> {
        GithubRuntimeAuthorityIdentity::new(
            TenantScope::from_authenticated_tenant_id(self.tenant).expect("tenant"),
            AttemptId::from_uuid(Uuid::from_u128(self.attempt_id)),
            FencingToken::new(self.fencing_token).expect("fence"),
            LeaseId::from_uuid(Uuid::from_u128(self.lease_id)),
            UnixMillis::new(self.lease_issued_at),
            UnixMillis::new(self.lease_expires_at),
            RunId::from_uuid(Uuid::from_u128(self.run_id)),
            JobId::from_uuid(Uuid::from_u128(self.job_id)),
            RunnerId::from_uuid(Uuid::from_u128(self.runner_id)),
            RunnerSessionId::from_uuid(Uuid::from_u128(self.runner_session_id)),
            SessionEpoch::new(self.runner_session_epoch).expect("epoch"),
            RunnerGeneration::new(self.runner_generation).expect("generation"),
            StableRunnerSlot::new(self.runner_slot).expect("slot"),
            JobIrVersion::current(),
            self.job_ir_size_bytes,
            Sha256Digest::from_bytes([self.job_ir_digest_byte; 32]),
            RepositoryId::from_uuid(Uuid::from_u128(self.repository_id)),
            ProviderConnectionId::from_uuid(Uuid::from_u128(self.provider_connection_id))
                .expect("provider connection"),
            ProviderInstallationId::new(self.provider_installation_id)
                .expect("provider installation"),
            GithubServerServiceAppId::new(self.github_app_id).expect("App ID"),
            GithubServerServiceAppClientId::new(self.github_app_client_id).expect("App client ID"),
            self.github_app_jwt_issuer_kind,
            GithubRepositoryId::new(self.github_repository_id).expect("repository ID"),
            GithubRepositoryName::new(self.github_repository_name).expect("repository name"),
            GithubRuntimeAuthorityNamespace::new(self.namespace).expect("authority namespace"),
            Sha256Digest::from_bytes([self.policy_digest_byte; 32]),
            Sha256Digest::from_bytes([self.app_key_spki_byte; 32]),
            Sha256Digest::from_bytes([self.configuration_fingerprint_byte; 32]),
            GithubRuntimeAuthorityPreparationSelectionTail::new(
                LogicalWorkSelectionId::from_uuid(Uuid::from_u128(self.preparation_selection_id))
                    .expect("preparation selection"),
                LogicalActivationWorkerId::from_uuid(Uuid::from_u128(
                    self.preparation_selection_owner_id,
                ))
                .expect("preparation owner"),
                LogicalActivationPreparationGeneration::new(self.preparation_selection_generation)
                    .expect("preparation generation"),
                Sha256Digest::from_bytes([self.preparation_selection_descriptor_byte; 32]),
                UnixMillis::new(self.preparation_selection_claimed_at),
                UnixMillis::new(self.preparation_selection_expires_at),
            )
            .expect("preparation tail"),
            GithubRuntimeAuthorityActivationSelectionTail::new(
                LogicalWorkSelectionId::from_uuid(Uuid::from_u128(self.activation_selection_id))
                    .expect("activation selection"),
                LogicalActivationWorkerId::from_uuid(Uuid::from_u128(
                    self.activation_selection_owner_id,
                ))
                .expect("activation owner"),
                LogicalActivationGeneration::new(self.activation_selection_generation)
                    .expect("activation generation"),
                Sha256Digest::from_bytes([self.activation_selection_input_byte; 32]),
                UnixMillis::new(self.activation_selection_claimed_at),
                UnixMillis::new(self.activation_selection_expires_at),
            )
            .expect("activation tail"),
            GithubRuntimeAuthorityMaterializationSelectionTail::new(
                LogicalWorkSelectionId::from_uuid(Uuid::from_u128(
                    self.materialization_selection_id,
                ))
                .expect("materialization selection"),
                LogicalMaterializationWorkerId::from_uuid(Uuid::from_u128(
                    self.materialization_selection_owner_id,
                ))
                .expect("materialization owner"),
                LogicalMaterializationGeneration::new(self.materialization_selection_generation)
                    .expect("materialization generation"),
                Sha256Digest::from_bytes([self.materialization_selection_descriptor_byte; 32]),
                UnixMillis::new(self.materialization_selection_claimed_at),
                UnixMillis::new(self.materialization_selection_expires_at),
            )
            .expect("materialization tail"),
            UnixMillis::new(self.requested_at),
            UnixMillis::new(self.request_deadline),
        )
    }
}

fn identity_with(
    policy_byte: u8,
    configuration_byte: u8,
    runner_slot: u16,
    job_ir_version: JobIrVersion,
) -> Result<GithubRuntimeAuthorityIdentity, GithubRuntimeAuthorityValueError> {
    let selection = IdentityInputs::base();
    GithubRuntimeAuthorityIdentity::new(
        TenantScope::from_authenticated_tenant_id("tenant-a").expect("tenant"),
        AttemptId::from_uuid(Uuid::from_u128(1)),
        FencingToken::new(7).expect("fence"),
        LeaseId::from_uuid(Uuid::from_u128(2)),
        UnixMillis::new(1_000),
        UnixMillis::new(20_000),
        RunId::from_uuid(Uuid::from_u128(3)),
        JobId::from_uuid(Uuid::from_u128(4)),
        RunnerId::from_uuid(Uuid::from_u128(5)),
        RunnerSessionId::from_uuid(Uuid::from_u128(6)),
        SessionEpoch::new(8).expect("epoch"),
        RunnerGeneration::new(9).expect("generation"),
        StableRunnerSlot::new(runner_slot).expect("slot"),
        job_ir_version,
        1_024,
        Sha256Digest::from_bytes([policy_byte; 32]),
        RepositoryId::from_uuid(Uuid::from_u128(11)),
        ProviderConnectionId::from_uuid(Uuid::from_u128(16)).expect("provider connection"),
        ProviderInstallationId::new(17).expect("provider installation"),
        GithubServerServiceAppId::new(18).expect("App ID"),
        GithubServerServiceAppClientId::new("Iv1.automata-runtime").expect("App client ID"),
        GithubServerServiceJwtIssuer::AppClientId,
        GithubRepositoryId::new(12).expect("repository ID"),
        GithubRepositoryName::new("automata-ci/automata").expect("repository name"),
        GithubRuntimeAuthorityNamespace::new("github.actions.runtime")
            .expect("authority namespace"),
        Sha256Digest::from_bytes([policy_byte; 32]),
        Sha256Digest::from_bytes([13; 32]),
        Sha256Digest::from_bytes([configuration_byte; 32]),
        GithubRuntimeAuthorityPreparationSelectionTail::new(
            LogicalWorkSelectionId::from_uuid(Uuid::from_u128(selection.preparation_selection_id))
                .expect("preparation selection"),
            LogicalActivationWorkerId::from_uuid(Uuid::from_u128(
                selection.preparation_selection_owner_id,
            ))
            .expect("preparation owner"),
            LogicalActivationPreparationGeneration::new(selection.preparation_selection_generation)
                .expect("preparation generation"),
            Sha256Digest::from_bytes([selection.preparation_selection_descriptor_byte; 32]),
            UnixMillis::new(selection.preparation_selection_claimed_at),
            UnixMillis::new(selection.preparation_selection_expires_at),
        )?,
        GithubRuntimeAuthorityActivationSelectionTail::new(
            LogicalWorkSelectionId::from_uuid(Uuid::from_u128(selection.activation_selection_id))
                .expect("activation selection"),
            LogicalActivationWorkerId::from_uuid(Uuid::from_u128(
                selection.activation_selection_owner_id,
            ))
            .expect("activation owner"),
            LogicalActivationGeneration::new(selection.activation_selection_generation)
                .expect("activation generation"),
            Sha256Digest::from_bytes([selection.activation_selection_input_byte; 32]),
            UnixMillis::new(selection.activation_selection_claimed_at),
            UnixMillis::new(selection.activation_selection_expires_at),
        )?,
        GithubRuntimeAuthorityMaterializationSelectionTail::new(
            LogicalWorkSelectionId::from_uuid(Uuid::from_u128(
                selection.materialization_selection_id,
            ))
            .expect("materialization selection"),
            LogicalMaterializationWorkerId::from_uuid(Uuid::from_u128(
                selection.materialization_selection_owner_id,
            ))
            .expect("materialization owner"),
            LogicalMaterializationGeneration::new(selection.materialization_selection_generation)
                .expect("materialization generation"),
            Sha256Digest::from_bytes([selection.materialization_selection_descriptor_byte; 32]),
            UnixMillis::new(selection.materialization_selection_claimed_at),
            UnixMillis::new(selection.materialization_selection_expires_at),
        )?,
        UnixMillis::new(2_000),
        UnixMillis::new(3_000),
    )
}

fn protected(
    identity: GithubRuntimeAuthorityIdentity,
    plaintext_digest_byte: u8,
) -> ProtectedGithubRuntimeAuthority {
    protected_with(identity, 3_500_000, 32, plaintext_digest_byte)
}

fn protected_with(
    identity: GithubRuntimeAuthorityIdentity,
    provider_expires_at: i64,
    plaintext_size_bytes: u64,
    plaintext_digest_byte: u8,
) -> ProtectedGithubRuntimeAuthority {
    let metadata = GithubRuntimeAuthorityEnvelopeMetadata::new(
        identity,
        Some(UnixMillis::new(provider_expires_at)),
        plaintext_size_bytes,
        Sha256Digest::from_bytes([plaintext_digest_byte; 32]),
    )
    .expect("metadata");
    let wrapped = WrappedDataKey::new(
        KeyId::new("runtime-authority-test-v1").expect("key ID"),
        vec![0x44; 48],
    )
    .expect("wrapped key");
    let ciphertext_size = usize::try_from(plaintext_size_bytes + 16).expect("bounded size");
    let envelope = EncryptedEnvelope::from_parts(
        ENVELOPE_SCHEMA_V1,
        wrapped,
        [0x55; 12],
        vec![0x66; ciphertext_size],
    )
    .expect("envelope");
    ProtectedGithubRuntimeAuthority::new(metadata, envelope).expect("protected authority")
}

#[test]
fn current_identity_derives_the_full_conservative_horizon() {
    let identity = identity_with(14, 15, 1, JobIrVersion::current()).expect("identity");
    assert_eq!(identity.job_ir_version().get(), 1);
    assert_eq!(identity.conservative_expiry(), UnixMillis::new(3_783_000));
    assert_eq!(
        identity.provider_connection_id().as_uuid(),
        Uuid::from_u128(16)
    );
    assert_eq!(identity.provider_installation_id().get(), 17);
    assert_eq!(identity.github_app_id().get(), 18);
    assert_eq!(
        identity.github_app_client_id().as_str(),
        "Iv1.automata-runtime"
    );
    assert_eq!(
        identity.github_app_jwt_issuer_kind(),
        GithubServerServiceJwtIssuer::AppClientId
    );
    assert_eq!(
        identity.github_app_jwt_issuer_value(),
        "Iv1.automata-runtime"
    );
    assert_eq!(identity.github_repository_id().get(), 12);
    assert_eq!(
        identity.github_repository_name().as_str(),
        "automata-ci/automata"
    );

    assert!(matches!(
        identity_with(14, 15, 1, JobIrVersion::new(4).expect("noncurrent schema")),
        Err(GithubRuntimeAuthorityValueError::UnsupportedJobIr)
    ));
    let mut mismatched_policy = IdentityInputs::base();
    mismatched_policy.policy_digest_byte = mismatched_policy.job_ir_digest_byte + 1;
    assert!(matches!(
        mismatched_policy.try_build(),
        Err(GithubRuntimeAuthorityValueError::PolicyDigestMismatch)
    ));
}

#[test]
fn unprotected_erasure_authentication_retains_the_complete_exact_mint_claim() {
    let identity = IdentityInputs::base().build();
    let claim = ClaimedGithubRuntimeAuthorityMint::from_repository_parts(
        identity,
        GithubRuntimeAuthorityWorkerId::from_uuid(Uuid::from_u128(30)).expect("worker"),
        GithubRuntimeAuthorityClaimFence::new(1).expect("claim fence"),
        1,
        UnixMillis::new(2_000),
        UnixMillis::new(2_100),
    )
    .expect("exact mint claim");
    let request = AuthenticateGithubRuntimeAuthorityUnprotectedErasure::new(&claim);
    assert_eq!(request.claim(), &claim);
}

#[test]
fn mint_begin_persists_only_a_bounded_provider_request_duration() {
    let claim = ClaimedGithubRuntimeAuthorityMint::from_repository_parts(
        IdentityInputs::base().build(),
        GithubRuntimeAuthorityWorkerId::from_uuid(Uuid::from_u128(30)).expect("worker"),
        GithubRuntimeAuthorityClaimFence::new(1).expect("claim fence"),
        1,
        UnixMillis::new(2_000),
        UnixMillis::new(2_100),
    )
    .expect("exact mint claim");
    let begin = BeginGithubRuntimeAuthorityMint::new(
        claim.clone(),
        UnixMillis::new(2_000),
        MAX_GITHUB_AUTHORITY_REQUEST_MILLIS,
    )
    .expect("bounded duration is request evidence; Store authorizes it with DB time");
    assert_eq!(begin.provider_request_millis(), 120_000);
    assert!(
        BeginGithubRuntimeAuthorityMint::new(claim.clone(), UnixMillis::new(2_000), 0,).is_err()
    );
    assert!(
        BeginGithubRuntimeAuthorityMint::new(
            claim,
            UnixMillis::new(2_000),
            MAX_GITHUB_AUTHORITY_REQUEST_MILLIS + 1,
        )
        .is_err()
    );
}

#[test]
fn missing_provider_expiry_is_authenticated_and_uses_the_conservative_horizon() {
    let identity = IdentityInputs::base().build();
    let unknown_expiry = GithubRuntimeAuthorityEnvelopeMetadata::new(
        identity.clone(),
        None,
        32,
        Sha256Digest::from_bytes([16; 32]),
    )
    .expect("unknown-expiry metadata");
    let known_expiry = GithubRuntimeAuthorityEnvelopeMetadata::new(
        identity.clone(),
        Some(UnixMillis::new(3_500_000)),
        32,
        Sha256Digest::from_bytes([16; 32]),
    )
    .expect("known-expiry metadata");

    assert_eq!(unknown_expiry.provider_expires_at(), None);
    assert_eq!(
        unknown_expiry.safe_erase_after(),
        identity.conservative_expiry()
    );
    assert_eq!(
        known_expiry.safe_erase_after(),
        UnixMillis::new(3_500_000 + GITHUB_AUTHORITY_EXPIRY_SKEW_MILLIS)
    );
    assert_eq!(
        known_expiry.conservative_use_expires_at(),
        Some(UnixMillis::new(3_440_000))
    );
    assert_eq!(unknown_expiry.conservative_use_expires_at(), None);
    assert_ne!(unknown_expiry.aad_digest(), known_expiry.aad_digest());
    assert_ne!(
        unknown_expiry
            .encryption_context()
            .expect("unknown-expiry context")
            .record_id(),
        known_expiry
            .encryption_context()
            .expect("known-expiry context")
            .record_id()
    );

    let maximum_known_expiry = GithubRuntimeAuthorityEnvelopeMetadata::new(
        identity.clone(),
        Some(UnixMillis::new(3_663_000)),
        32,
        Sha256Digest::from_bytes([16; 32]),
    )
    .expect("provider clock-skew boundary");
    assert_eq!(
        maximum_known_expiry.safe_erase_after(),
        identity.conservative_expiry()
    );
    assert!(matches!(
        GithubRuntimeAuthorityEnvelopeMetadata::new(
            identity,
            Some(UnixMillis::new(3_663_001)),
            32,
            Sha256Digest::from_bytes([16; 32]),
        ),
        Err(GithubRuntimeAuthorityValueError::InvalidProviderExpiry)
    ));
}

#[test]
fn repository_and_namespace_shapes_reject_ambiguous_names() {
    assert_eq!(
        GithubRuntimeAuthorityNamespace::new("a")
            .expect("single-byte namespace")
            .as_str(),
        "a"
    );
    for invalid in ["./repo", "../repo", "owner/.", "owner/..", "owner/repo.git"] {
        assert!(GithubRepositoryName::new(invalid).is_err(), "{invalid}");
    }
    for valid in ["a/b", "automata-ci/automata", "owner/repo.name_v2"] {
        assert_eq!(
            GithubRepositoryName::new(valid)
                .expect("canonical repository")
                .as_str(),
            valid
        );
    }
}

#[test]
fn receipt_terminal_state_matches_the_durable_before_mint_reduction() {
    let key = IdentityInputs::base().build().key();
    for reason in [
        GithubRuntimeAuthorityTerminalReason::SupersededBeforeMint,
        GithubRuntimeAuthorityTerminalReason::RequestExpiredBeforeMint,
    ] {
        assert!(
            GithubRuntimeAuthorityReceipt::from_repository_parts(
                key,
                GithubRuntimeAuthorityState::Revoked,
                UnixMillis::new(2_000),
                Some(reason),
            )
            .is_ok()
        );
        assert!(
            GithubRuntimeAuthorityReceipt::from_repository_parts(
                key,
                GithubRuntimeAuthorityState::Rejected,
                UnixMillis::new(2_000),
                Some(reason),
            )
            .is_err()
        );
    }
}

#[test]
fn aad_changes_with_policy_configuration_slot_and_plaintext_identity() {
    let base = protected(
        identity_with(14, 15, 1, JobIrVersion::current()).expect("identity"),
        16,
    );
    let changed_policy = protected(
        identity_with(17, 15, 1, JobIrVersion::current()).expect("identity"),
        16,
    );
    let changed_configuration = protected(
        identity_with(14, 18, 1, JobIrVersion::current()).expect("identity"),
        16,
    );
    let changed_slot = protected(
        identity_with(14, 15, 2, JobIrVersion::current()).expect("identity"),
        16,
    );
    let changed_plaintext = protected(
        identity_with(14, 15, 1, JobIrVersion::current()).expect("identity"),
        19,
    );

    let base_digest = base.metadata().aad_digest();
    for changed in [
        changed_policy,
        changed_configuration,
        changed_slot,
        changed_plaintext,
    ] {
        assert_ne!(base_digest, changed.metadata().aad_digest());
        assert_ne!(
            base.metadata()
                .encryption_context()
                .expect("context")
                .record_id(),
            changed
                .metadata()
                .encryption_context()
                .expect("context")
                .record_id()
        );
    }
}

#[test]
fn aad_commits_to_every_variable_identity_and_payload_coordinate() {
    let base_inputs = IdentityInputs::base();
    let base = protected(base_inputs.build(), 16);
    let base_wrapping_context = base
        .metadata()
        .identity()
        .wrapping_encryption_context()
        .expect("identity-only wrapping context");
    let mutations: [fn(&mut IdentityInputs); 46] = [
        |value| value.tenant = "tenant-b",
        |value| value.attempt_id = 21,
        |value| value.fencing_token = 17,
        |value| value.lease_id = 22,
        |value| value.lease_issued_at = 999,
        |value| value.lease_expires_at = 20_001,
        |value| value.run_id = 23,
        |value| value.job_id = 24,
        |value| value.runner_id = 25,
        |value| value.runner_session_id = 26,
        |value| value.runner_session_epoch = 18,
        |value| value.runner_generation = 19,
        |value| value.runner_slot = 2,
        |value| value.job_ir_size_bytes = 1_025,
        |value| {
            value.job_ir_digest_byte = 20;
            value.policy_digest_byte = 20;
        },
        |value| value.repository_id = 31,
        |value| value.provider_connection_id = 33,
        |value| value.provider_installation_id = 34,
        |value| value.github_app_id = 35,
        |value| value.github_app_client_id = "Iv1.rotated-runtime",
        |value| value.github_app_jwt_issuer_kind = GithubServerServiceJwtIssuer::AppId,
        |value| value.github_repository_id = 32,
        |value| value.github_repository_name = "automata-ci/automata-2",
        |value| value.namespace = "github.actions.runtime2",
        |value| value.app_key_spki_byte = 23,
        |value| value.configuration_fingerprint_byte = 25,
        |value| value.preparation_selection_id = 121,
        |value| value.preparation_selection_owner_id = 122,
        |value| value.preparation_selection_generation = 123,
        |value| value.preparation_selection_descriptor_byte = 124,
        |value| value.preparation_selection_claimed_at += 1,
        |value| value.preparation_selection_expires_at += 1,
        |value| value.activation_selection_id = 125,
        |value| value.activation_selection_owner_id = 126,
        |value| value.activation_selection_generation = 127,
        |value| value.activation_selection_input_byte = 128,
        |value| value.activation_selection_claimed_at += 1,
        |value| value.activation_selection_expires_at += 1,
        |value| value.materialization_selection_id = 129,
        |value| value.materialization_selection_owner_id = 130,
        |value| value.materialization_selection_generation = 131,
        |value| value.materialization_selection_descriptor_byte = 132,
        |value| value.materialization_selection_claimed_at += 1,
        |value| value.materialization_selection_expires_at += 1,
        |value| value.requested_at = 2_001,
        |value| value.request_deadline = 3_001,
    ];
    for (index, mutate) in mutations.into_iter().enumerate() {
        let mut changed_inputs = base_inputs;
        mutate(&mut changed_inputs);
        let changed = protected(changed_inputs.build(), 16);
        assert_ne!(
            base.metadata().aad_digest(),
            changed.metadata().aad_digest(),
            "identity mutation {index} was not authenticated"
        );
        assert_ne!(
            base_wrapping_context.canonical_authenticated_bytes(),
            changed
                .metadata()
                .identity()
                .wrapping_encryption_context()
                .expect("changed identity-only wrapping context")
                .canonical_authenticated_bytes(),
            "identity mutation {index} was not authenticated for key wrapping"
        );
    }

    for changed in [
        protected_with(base_inputs.build(), 3_500_001, 32, 16),
        protected_with(base_inputs.build(), 3_500_000, 33, 16),
        protected_with(base_inputs.build(), 3_500_000, 32, 17),
    ] {
        assert_ne!(
            base.metadata().aad_digest(),
            changed.metadata().aad_digest()
        );
    }
}

#[test]
fn protected_envelope_and_claim_intervals_are_strictly_bounded() {
    let identity = identity_with(14, 15, 1, JobIrVersion::current()).expect("identity");
    let metadata = GithubRuntimeAuthorityEnvelopeMetadata::new(
        identity.clone(),
        Some(UnixMillis::new(3_500_000)),
        32,
        Sha256Digest::from_bytes([16; 32]),
    )
    .expect("metadata");
    let invalid_length = EncryptedEnvelope::from_parts(
        ENVELOPE_SCHEMA_V1,
        WrappedDataKey::new(KeyId::new("key-v1").expect("key ID"), vec![1; 32])
            .expect("wrapped key"),
        [2; 12],
        vec![3; 49],
    )
    .expect("generic envelope accepts the size");
    assert!(matches!(
        ProtectedGithubRuntimeAuthority::new(metadata, invalid_length),
        Err(GithubRuntimeAuthorityValueError::InvalidProtectedEnvelope)
    ));

    let owner = GithubRuntimeAuthorityWorkerId::from_uuid(Uuid::from_u128(20)).expect("owner");
    assert!(
        ClaimGithubRuntimeAuthorityMint::new(
            identity.clone(),
            owner,
            UnixMillis::new(2_100),
            UnixMillis::new(2_100 + MAX_GITHUB_AUTHORITY_MINT_CLAIM_MILLIS + 1),
        )
        .is_err()
    );
    let claim_request = ClaimGithubRuntimeAuthorityMint::new(
        identity,
        owner,
        UnixMillis::new(2_100),
        UnixMillis::new(2_900),
    )
    .expect("mint claim");
    assert_eq!(claim_request.owner(), owner);

    assert!(
        ClaimGithubRuntimeAuthorityRevocation::new(
            owner,
            UnixMillis::new(5_000),
            UnixMillis::new(5_000),
        )
        .is_err()
    );
}

#[test]
fn post_decrypt_revocation_revalidation_has_exact_claim_and_erasure_boundaries() {
    let identity = IdentityInputs::base().build();
    let owner = GithubRuntimeAuthorityWorkerId::from_uuid(Uuid::from_u128(20)).expect("owner");
    let claim = ClaimedGithubRuntimeAuthorityRevocation::from_repository_parts(
        protected(identity, 16),
        owner,
        GithubRuntimeAuthorityClaimFence::new(1).expect("claim fence"),
        1,
        UnixMillis::new(2_500),
        UnixMillis::new(2_600),
    )
    .expect("revocation claim");
    let request =
        RevalidateGithubRuntimeAuthorityRevocation::new(&claim, 100).expect("revalidation request");
    let authorized = RevalidatedGithubRuntimeAuthorityRevocation::from_repository_parts(
        request,
        UnixMillis::new(2_500),
        true,
    )
    .expect("exact claim boundary is authorized");
    assert!(authorized.provider_call_authorized());

    let insufficient = RevalidatedGithubRuntimeAuthorityRevocation::from_repository_parts(
        request,
        UnixMillis::new(2_501),
        false,
    )
    .expect("one millisecond beyond the full-call boundary is not authorized");
    assert!(!insufficient.provider_call_authorized());
    assert!(
        RevalidatedGithubRuntimeAuthorityRevocation::from_repository_parts(
            request,
            UnixMillis::new(2_501),
            true,
        )
        .is_err()
    );
    assert!(
        RevalidatedGithubRuntimeAuthorityRevocation::from_repository_parts(
            request,
            claim.expires_at(),
            false,
        )
        .is_err()
    );
    assert!(RevalidateGithubRuntimeAuthorityRevocation::new(&claim, 0).is_err());
}

#[test]
fn ready_repository_parts_require_deliverable_live_exact_lease_time() {
    let identity = IdentityInputs::base().build();
    let ready = ReadyGithubRuntimeAuthority::from_repository_parts(
        protected(identity.clone(), 16),
        GithubRuntimeAuthorityCommitDisposition::Deliverable,
        UnixMillis::new(2_500),
    )
    .expect("ready adapter value");
    assert_eq!(ready.ready_at(), UnixMillis::new(2_500));
    assert_eq!(ready.protected().metadata().identity(), &identity);

    for (disposition, ready_at) in [
        (
            GithubRuntimeAuthorityCommitDisposition::RevokeOnly,
            UnixMillis::new(2_500),
        ),
        (
            GithubRuntimeAuthorityCommitDisposition::Deliverable,
            UnixMillis::new(1_999),
        ),
        (
            GithubRuntimeAuthorityCommitDisposition::Deliverable,
            identity.lease_expires_at(),
        ),
        (
            GithubRuntimeAuthorityCommitDisposition::Deliverable,
            UnixMillis::new(3_440_000),
        ),
    ] {
        assert!(matches!(
            ReadyGithubRuntimeAuthority::from_repository_parts(
                protected(identity.clone(), 16),
                disposition,
                ready_at,
            ),
            Err(GithubRuntimeAuthorityValueError::InvalidReadyAuthority)
        ));
    }
}

#[test]
fn claim_identity_is_exact() {
    let identity = identity_with(14, 15, 1, JobIrVersion::current()).expect("identity");
    let owner = GithubRuntimeAuthorityWorkerId::from_uuid(Uuid::from_u128(20)).expect("owner");
    let request = ClaimGithubRuntimeAuthorityMint::new(
        identity.clone(),
        owner,
        UnixMillis::new(2_100),
        UnixMillis::new(2_900),
    )
    .expect("request");
    assert_eq!(request.identity(), &identity);
}
