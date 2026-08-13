use automata_ci_core::{RunId, Sha256Digest, UnixMillis};
use automata_ci_store::{
    BeginGithubCheckRunCreate, BlockGithubCheckProjectionForCredentialRejection,
    ClaimGithubCheckProjection, ClaimedGithubCheckProjection, GithubCheckAppId,
    GithubCheckConclusion, GithubCheckCreateReconciliation, GithubCheckDesiredProjection,
    GithubCheckDetailsTarget, GithubCheckHeadSha, GithubCheckName, GithubCheckProjectionAction,
    GithubCheckProjectionClaimFence, GithubCheckProjectionWorkerId, GithubCheckRunId,
    GithubCheckSubjectId, GithubCheckSubjectIdentity, GithubCheckSubjectKey,
    GithubCheckSubjectReceipt, GithubCheckSubjectTarget, GithubCheckSuiteId,
    GithubCheckTerminalCause, GithubCheckValueError, GithubRepositoryName,
    GithubServerServiceAuthorityId, GithubServerServiceAuthoritySelector,
    GithubServerServiceRevision, LinkGithubCheckWorkflowRun,
    MAX_GITHUB_CHECK_CREATE_RECONCILE_GRACE_MILLIS, MAX_GITHUB_CHECK_PROJECTION_RETRY_MILLIS,
    ProviderConnectionId, ProviderDeliveryId, ProviderInstallationId, ProviderRepositoryId,
    ReleaseUnissuedGithubCheckRunCreate, RepositoryId, ResolveGithubCheckRunCreate, TenantScope,
};
use uuid::Uuid;

#[test]
fn unknown_terminal_causes_are_never_positive() {
    assert_eq!(
        GithubCheckTerminalCause::ProviderUnknown.conclusion(),
        GithubCheckConclusion::ActionRequired
    );
    assert_eq!(
        GithubCheckTerminalCause::SystemUnknown.conclusion(),
        GithubCheckConclusion::Failure
    );
    for cause in [
        GithubCheckTerminalCause::ProviderUnknown,
        GithubCheckTerminalCause::SystemUnknown,
    ] {
        let GithubCheckDesiredProjection::Terminal(terminal_cause) =
            GithubCheckDesiredProjection::terminal(cause)
        else {
            panic!("unknown cause must be terminal");
        };
        let conclusion = terminal_cause.conclusion();
        assert!(!matches!(
            conclusion,
            GithubCheckConclusion::Success | GithubCheckConclusion::Skipped
        ));
    }
}

#[test]
fn provider_facing_values_are_bounded_and_redacted() {
    let name = GithubCheckName::new("Automata / CI").expect("valid Check name");
    let key = GithubCheckSubjectKey::new(".ci/workflows/ci.yml").expect("valid workflow key");
    assert_eq!(name.as_str(), "Automata / CI");
    assert_eq!(key.as_str(), ".ci/workflows/ci.yml");
    assert!(!format!("{name:?}").contains("Automata / CI"));
    assert!(!format!("{key:?}").contains("ci.yml"));

    assert_eq!(
        GithubCheckName::new(" bad"),
        Err(GithubCheckValueError::InvalidCheckName)
    );
    assert_eq!(
        GithubCheckSubjectKey::new("../ci.yml"),
        Err(GithubCheckValueError::InvalidSubjectKey)
    );
    assert_eq!(
        GithubCheckHeadSha::new([0; 20]),
        Err(GithubCheckValueError::InvalidHeadSha)
    );
}

#[test]
fn rerun_subject_identity_has_one_closed_physical_origin() {
    let rerun_run_id = RunId::from_uuid(Uuid::new_v4());
    let identity = GithubCheckSubjectIdentity::new_rerun(
        TenantScope::from_authenticated_tenant_id("tenant").expect("tenant"),
        RepositoryId::from_uuid(Uuid::new_v4()),
        rerun_run_id,
        GithubCheckSubjectKey::new(".ci/workflows/ci.yml").expect("subject key"),
        ProviderConnectionId::from_uuid(Uuid::new_v4()).expect("connection"),
        ProviderInstallationId::new(11).expect("installation"),
        ProviderRepositoryId::new(13).expect("provider repository"),
        GithubRepositoryName::new("automata-ci/automata").expect("repository name"),
        GithubCheckAppId::new(17).expect("App"),
        GithubCheckHeadSha::new([1; 20]).expect("head SHA"),
        GithubCheckName::new("Automata / CI").expect("name"),
    )
    .expect("rerun identity");

    assert_eq!(identity.rerun_run_id(), Some(rerun_run_id));
    assert_eq!(identity.delivery_id(), None);
    assert_eq!(identity.schedule_fire_id(), None);
}

#[test]
fn create_cutoff_is_bounded_and_fenced() {
    let subject = GithubCheckSubjectId::from_uuid(Uuid::new_v4()).expect("subject ID");
    let worker = GithubCheckProjectionWorkerId::from_uuid(Uuid::new_v4()).expect("worker ID");
    let claim = GithubCheckProjectionClaimFence::from_durable_parts(subject, worker, 7)
        .expect("positive claim fence");
    let claimed = prepare_projection(claim, 900, 1_100);
    assert_eq!(
        claimed.identity().github_repository_name().as_str(),
        "automata-ci/automata"
    );
    let cutoff = BeginGithubCheckRunCreate::new(
        &claimed,
        UnixMillis::new(1_000),
        UnixMillis::new(1_100 + MAX_GITHUB_CHECK_CREATE_RECONCILE_GRACE_MILLIS),
    )
    .expect("maximum cutoff is accepted");
    assert_eq!(cutoff.claim(), claim);
    assert_eq!(cutoff.issue_expires_at(), UnixMillis::new(1_100));
    assert_eq!(
        cutoff.fence().reconcile_not_before(),
        cutoff.reconcile_not_before()
    );
    assert!(matches!(
        BeginGithubCheckRunCreate::new(
            &claimed,
            UnixMillis::new(1_000),
            UnixMillis::new(1_101 + MAX_GITHUB_CHECK_CREATE_RECONCILE_GRACE_MILLIS),
        ),
        Err(GithubCheckValueError::InvalidReconcileDelay)
    ));
}

#[test]
fn create_release_and_missing_reconciliation_are_temporally_bounded() {
    let subject = GithubCheckSubjectId::from_uuid(Uuid::new_v4()).expect("subject ID");
    let worker = GithubCheckProjectionWorkerId::from_uuid(Uuid::new_v4()).expect("worker ID");
    let claim = GithubCheckProjectionClaimFence::from_durable_parts(subject, worker, 7)
        .expect("positive claim fence");
    let claimed = prepare_projection(claim, 900, 1_100);
    let fence =
        BeginGithubCheckRunCreate::new(&claimed, UnixMillis::new(1_000), UnixMillis::new(1_200))
            .expect("cutoff")
            .fence();
    assert!(matches!(
        ReleaseUnissuedGithubCheckRunCreate::new(
            fence,
            UnixMillis::new(999),
            UnixMillis::new(1_001),
        ),
        Err(GithubCheckValueError::InvalidRetryBackoff)
    ));
    let missing = ResolveGithubCheckRunCreate::missing(
        claim,
        UnixMillis::new(2_000),
        UnixMillis::new(2_000 + MAX_GITHUB_CHECK_PROJECTION_RETRY_MILLIS),
    )
    .expect("maximum reconcile-only retry");
    assert_eq!(missing.outcome(), GithubCheckCreateReconciliation::Missing);
    assert_eq!(
        missing.retry_at(),
        Some(UnixMillis::new(
            2_000 + MAX_GITHUB_CHECK_PROJECTION_RETRY_MILLIS
        ))
    );
    assert!(matches!(
        ResolveGithubCheckRunCreate::missing(
            claim,
            UnixMillis::new(2_000),
            UnixMillis::new(2_001 + MAX_GITHUB_CHECK_PROJECTION_RETRY_MILLIS),
        ),
        Err(GithubCheckValueError::InvalidRetryBackoff)
    ));
    assert_eq!(
        ResolveGithubCheckRunCreate::ambiguous(claim, UnixMillis::new(2_000))
            .expect("ambiguous evidence")
            .retry_at(),
        None
    );
}

#[test]
fn credential_rejection_block_retains_its_exact_claim_and_nonnegative_time() {
    let subject = GithubCheckSubjectId::from_uuid(Uuid::new_v4()).expect("subject ID");
    let worker = GithubCheckProjectionWorkerId::from_uuid(Uuid::new_v4()).expect("worker ID");
    let claim = GithubCheckProjectionClaimFence::from_durable_parts(subject, worker, 7)
        .expect("claim fence");

    let request =
        BlockGithubCheckProjectionForCredentialRejection::new(claim, UnixMillis::new(1_234))
            .expect("credential rejection block");
    assert_eq!(request.claim(), claim);
    assert_eq!(request.blocked_at(), UnixMillis::new(1_234));
    assert!(matches!(
        BlockGithubCheckProjectionForCredentialRejection::new(claim, UnixMillis::new(-1)),
        Err(GithubCheckValueError::NegativeTimestamp(
            "GitHub Check credential rejection time"
        ))
    ));
}

fn prepare_projection(
    claim: GithubCheckProjectionClaimFence,
    claimed_at: i64,
    expires_at: i64,
) -> ClaimedGithubCheckProjection {
    let tenant = TenantScope::from_authenticated_tenant_id("tenant").expect("tenant");
    let identity = GithubCheckSubjectIdentity::new(
        tenant.clone(),
        RepositoryId::from_uuid(Uuid::new_v4()),
        ProviderDeliveryId::from_uuid(Uuid::new_v4()).expect("delivery"),
        GithubCheckSubjectKey::new(".ci/workflows/ci.yml").expect("subject key"),
        ProviderConnectionId::from_uuid(Uuid::new_v4()).expect("connection"),
        ProviderInstallationId::new(11).expect("installation"),
        ProviderRepositoryId::new(13).expect("provider repository"),
        GithubRepositoryName::new("automata-ci/automata").expect("repository name"),
        GithubCheckAppId::new(17).expect("App"),
        GithubCheckHeadSha::new([1; 20]).expect("head SHA"),
        GithubCheckName::new("Automata / CI").expect("name"),
    )
    .expect("identity");
    ClaimedGithubCheckProjection::from_durable_parts(
        claim,
        GithubCheckProjectionAction::PrepareRunCreate,
        1,
        identity,
        GithubCheckDetailsTarget::Repository,
        checks_authority(&tenant),
        format!("automata-check:{}", claim.subject_id().as_uuid()),
        GithubCheckDesiredProjection::Queued,
        1,
        Some(GithubCheckSuiteId::new(19).expect("suite")),
        None,
        UnixMillis::new(claimed_at),
        UnixMillis::new(expires_at),
    )
    .expect("prepare projection")
}

#[test]
fn scoped_mutations_reject_nil_run_and_invalid_claim_window() {
    let subject = GithubCheckSubjectId::from_uuid(Uuid::new_v4()).expect("subject ID");
    let target = GithubCheckSubjectTarget::new(
        automata_ci_store::TenantScope::from_authenticated_tenant_id("tenant").expect("tenant"),
        subject,
    );
    assert!(matches!(
        LinkGithubCheckWorkflowRun::new(target, RunId::from_uuid(Uuid::nil()), UnixMillis::new(1),),
        Err(GithubCheckValueError::NilUuid(
            "GitHub Check workflow run ID"
        ))
    ));

    let connection = ProviderConnectionId::from_uuid(Uuid::new_v4()).expect("connection ID");
    let worker = GithubCheckProjectionWorkerId::from_uuid(Uuid::new_v4()).expect("worker ID");
    assert!(matches!(
        ClaimGithubCheckProjection::new(
            connection,
            worker,
            UnixMillis::new(100),
            UnixMillis::new(100),
        ),
        Err(GithubCheckValueError::InvalidClaimInterval)
    ));
    assert!(GithubCheckAppId::new(i64::MAX as u64).is_ok());
    assert!(GithubCheckSuiteId::new(i64::MAX as u64).is_ok());
}

#[test]
fn claimed_projection_rehydrates_only_complete_current_state() {
    let subject = GithubCheckSubjectId::from_uuid(Uuid::new_v4()).expect("subject ID");
    let worker = GithubCheckProjectionWorkerId::from_uuid(Uuid::new_v4()).expect("worker ID");
    let claim = GithubCheckProjectionClaimFence::from_durable_parts(subject, worker, 7)
        .expect("claim fence");
    let identity = GithubCheckSubjectIdentity::new(
        TenantScope::from_authenticated_tenant_id("tenant").expect("tenant"),
        RepositoryId::from_uuid(Uuid::new_v4()),
        ProviderDeliveryId::from_uuid(Uuid::new_v4()).expect("delivery"),
        GithubCheckSubjectKey::new(".ci/workflows/ci.yml").expect("subject key"),
        ProviderConnectionId::from_uuid(Uuid::new_v4()).expect("connection"),
        ProviderInstallationId::new(11).expect("installation"),
        ProviderRepositoryId::new(13).expect("provider repository"),
        GithubRepositoryName::new("automata-ci/automata").expect("repository name"),
        GithubCheckAppId::new(17).expect("App"),
        GithubCheckHeadSha::new([1; 20]).expect("head SHA"),
        GithubCheckName::new("Automata / CI").expect("name"),
    )
    .expect("identity");
    let suite = GithubCheckSuiteId::new(19).expect("suite");
    let run = GithubCheckRunId::new(23).expect("run");
    let external_id = format!("automata-check:{}", subject.as_uuid());
    let authority = checks_authority(identity.tenant());

    let receipt = GithubCheckSubjectReceipt::from_durable_parts(
        subject,
        external_id.clone(),
        None,
        GithubCheckDesiredProjection::Queued,
        1,
    )
    .expect("complete durable receipt");
    assert_eq!(receipt.subject_id(), subject);
    assert_eq!(
        GithubCheckSubjectReceipt::from_durable_parts(
            subject,
            external_id.clone(),
            Some(RunId::from_uuid(Uuid::nil())),
            GithubCheckDesiredProjection::Queued,
            1,
        ),
        Err(GithubCheckValueError::NilUuid(
            "GitHub Check workflow run ID"
        ))
    );

    let claimed = ClaimedGithubCheckProjection::from_durable_parts(
        claim,
        GithubCheckProjectionAction::Publish,
        1,
        identity.clone(),
        GithubCheckDetailsTarget::Repository,
        authority.clone(),
        external_id.clone(),
        GithubCheckDesiredProjection::InProgress,
        2,
        Some(suite),
        Some(run),
        UnixMillis::new(100),
        UnixMillis::new(200),
    )
    .expect("complete durable claim");
    assert_eq!(claimed.claimed_at(), UnixMillis::new(100));
    assert_eq!(claimed.expires_at(), UnixMillis::new(200));
    assert_eq!(claimed.checks_authority(), &authority);

    assert_eq!(
        ClaimedGithubCheckProjection::from_durable_parts(
            claim,
            GithubCheckProjectionAction::Publish,
            1,
            identity.clone(),
            GithubCheckDetailsTarget::Repository,
            authority.clone(),
            external_id.clone(),
            GithubCheckDesiredProjection::InProgress,
            2,
            Some(suite),
            None,
            UnixMillis::new(100),
            UnixMillis::new(200),
        ),
        Err(GithubCheckValueError::InvalidProjectionBinding)
    );
    assert_eq!(
        ClaimedGithubCheckProjection::from_durable_parts(
            claim,
            GithubCheckProjectionAction::EnsureSuite,
            1,
            identity,
            GithubCheckDetailsTarget::Repository,
            authority,
            external_id,
            GithubCheckDesiredProjection::Queued,
            (i64::MAX as u64) + 1,
            None,
            None,
            UnixMillis::new(100),
            UnixMillis::new(200),
        ),
        Err(GithubCheckValueError::InvalidDesiredRevision)
    );
}

#[test]
fn claimed_projection_rejects_cross_tenant_authority_selector() {
    let subject = GithubCheckSubjectId::from_uuid(Uuid::new_v4()).expect("subject ID");
    let worker = GithubCheckProjectionWorkerId::from_uuid(Uuid::new_v4()).expect("worker ID");
    let claim = GithubCheckProjectionClaimFence::from_durable_parts(subject, worker, 7)
        .expect("claim fence");
    let claimed = prepare_projection(claim, 100, 200);
    let authority = claimed.checks_authority().clone();
    let other_tenant =
        TenantScope::from_authenticated_tenant_id("other-tenant").expect("other tenant");
    let wrong_tenant_authority = checks_authority(&other_tenant);

    assert_eq!(
        ClaimedGithubCheckProjection::from_durable_parts(
            claim,
            claimed.action(),
            claimed.attempts(),
            claimed.identity().clone(),
            claimed.details_target(),
            wrong_tenant_authority,
            claimed.external_id().to_owned(),
            claimed.desired(),
            claimed.desired_revision(),
            claimed.suite_id(),
            claimed.run_id(),
            claimed.claimed_at(),
            claimed.expires_at(),
        ),
        Err(GithubCheckValueError::AuthoritySelectorMismatch)
    );
    assert_eq!(claimed.checks_authority(), &authority);
}

fn checks_authority(tenant: &TenantScope) -> GithubServerServiceAuthoritySelector {
    GithubServerServiceAuthoritySelector::from_durable_parts(
        tenant.clone(),
        GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(
            0x00000000_0000_4000_8000_00000000c001,
        ))
        .expect("authority ID"),
        Sha256Digest::from_bytes([9; 32]),
        GithubServerServiceRevision::new(1).expect("App configuration revision"),
        GithubServerServiceRevision::new(1).expect("policy revision"),
    )
}
