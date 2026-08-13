use std::collections::BTreeMap;

use automata_ci_core::{
    AttemptId, ContextValue, FencingToken, JobId, JobRuntimeContext, Lease, LeaseId, RunId,
    RunnerId, RunnerSessionId, SecretBinding, Sha256Digest, StrategyContext, UnixMillis,
};
use automata_ci_store::{
    MAX_MANAGED_SECRET_BINDINGS, ManagedSecretAuthorityStoreError,
    ManagedSecretAuthorityValueError, ManagedSecretBindingSet, RepositoryId,
    ResolveManagedSecretAuthority, RunnerGeneration, RunnerSessionFence, SessionEpoch,
    StableRunnerSlot, TenantScope,
};
use uuid::Uuid;

fn context(secrets: BTreeMap<String, SecretBinding>) -> JobRuntimeContext {
    let empty = || ContextValue::object(BTreeMap::new()).expect("empty context object");
    JobRuntimeContext::new(
        empty(),
        empty(),
        empty(),
        StrategyContext::new(true, 0, 1, 1).expect("single job strategy"),
        BTreeMap::new(),
        secrets,
    )
    .expect("valid runtime context")
}

fn binding(grant: Uuid, version: Uuid) -> SecretBinding {
    SecretBinding::new(grant.to_string())
        .expect("canonical binding")
        .with_version_id(version.to_string())
        .expect("canonical version")
}

#[test]
fn runtime_binding_set_requires_exact_canonical_versions_and_unique_grants() {
    let grant = Uuid::new_v4();
    let version = Uuid::new_v4();
    let exact = context(BTreeMap::from([(
        "DEPLOY_KEY".to_owned(),
        binding(grant, version),
    )]));
    let set = ManagedSecretBindingSet::from_runtime_context(&exact).expect("exact binding set");
    assert_eq!(set.len(), 1);
    assert!(!set.is_empty());

    let missing_version = context(BTreeMap::from([(
        "DEPLOY_KEY".to_owned(),
        SecretBinding::new(grant.to_string()).expect("opaque binding"),
    )]));
    assert_eq!(
        ManagedSecretBindingSet::from_runtime_context(&missing_version),
        Err(ManagedSecretAuthorityValueError::InvalidBinding)
    );

    let noncanonical = context(BTreeMap::from([(
        "DEPLOY_KEY".to_owned(),
        SecretBinding::new(grant.to_string().to_ascii_uppercase())
            .expect("core accepts opaque uppercase identity")
            .with_version_id(version.to_string())
            .expect("version"),
    )]));
    assert_eq!(
        ManagedSecretBindingSet::from_runtime_context(&noncanonical),
        Err(ManagedSecretAuthorityValueError::InvalidBinding)
    );

    let duplicate = context(BTreeMap::from([
        ("FIRST".to_owned(), binding(grant, version)),
        ("SECOND".to_owned(), binding(grant, Uuid::new_v4())),
    ]));
    assert_eq!(
        ManagedSecretBindingSet::from_runtime_context(&duplicate),
        Err(ManagedSecretAuthorityValueError::DuplicateBinding)
    );
}

#[test]
fn runtime_binding_set_enforces_the_delivery_cardinality_ceiling() {
    let secrets = (0..=MAX_MANAGED_SECRET_BINDINGS)
        .map(|index| {
            (
                format!("SECRET_{index}"),
                binding(Uuid::new_v4(), Uuid::new_v4()),
            )
        })
        .collect();
    let oversized = context(secrets);
    assert_eq!(
        ManagedSecretBindingSet::from_runtime_context(&oversized),
        Err(ManagedSecretAuthorityValueError::TooManyBindings)
    );
}

#[test]
fn request_rejects_cross_bound_or_expired_execution_identity() {
    let runner = RunnerId::new();
    let other_runner = RunnerId::new();
    let lease = Lease::new(
        LeaseId::new(),
        AttemptId::new(),
        runner,
        FencingToken::new(7).expect("positive fence"),
        UnixMillis::new(10),
        UnixMillis::new(100),
    )
    .expect("valid lease");
    let session = RunnerSessionFence::new(
        RunnerSessionId::new(),
        other_runner,
        RunnerGeneration::new(1).expect("generation"),
        SessionEpoch::new(1).expect("epoch"),
    );
    let result = ResolveManagedSecretAuthority::new(
        TenantScope::from_authenticated_tenant_id("tenant").expect("tenant"),
        RepositoryId::from_uuid(Uuid::new_v4()),
        RunId::new(),
        JobId::new(),
        lease,
        session,
        StableRunnerSlot::new(1).expect("slot"),
        Sha256Digest::from_bytes([3; 32]),
        ManagedSecretBindingSet::new([]).expect("empty exact set"),
        UnixMillis::new(100),
    );
    assert_eq!(
        result.unwrap_err(),
        ManagedSecretAuthorityValueError::InvalidExecution
    );
}

#[test]
fn request_rejects_negative_lease_times_even_when_the_interval_contains_observation() {
    let runner = RunnerId::new();
    let lease = Lease::new(
        LeaseId::new(),
        AttemptId::new(),
        runner,
        FencingToken::new(7).expect("positive fence"),
        UnixMillis::new(-10),
        UnixMillis::new(100),
    )
    .expect("core lease interval is otherwise ordered");
    let session = RunnerSessionFence::new(
        RunnerSessionId::new(),
        runner,
        RunnerGeneration::new(1).expect("generation"),
        SessionEpoch::new(1).expect("epoch"),
    );
    let result = ResolveManagedSecretAuthority::new(
        TenantScope::from_authenticated_tenant_id("tenant").expect("tenant"),
        RepositoryId::from_uuid(Uuid::new_v4()),
        RunId::new(),
        JobId::new(),
        lease,
        session,
        StableRunnerSlot::new(1).expect("slot"),
        Sha256Digest::from_bytes([3; 32]),
        ManagedSecretBindingSet::new([]).expect("empty exact set"),
        UnixMillis::new(10),
    );
    assert_eq!(
        result.unwrap_err(),
        ManagedSecretAuthorityValueError::InvalidExecution
    );
}

#[test]
fn indeterminate_contract_error_is_sanitized() {
    assert_eq!(
        ManagedSecretAuthorityStoreError::Indeterminate.to_string(),
        "managed-secret workload authority cannot be determined"
    );
}

#[test]
fn diagnostics_redact_binding_and_execution_identities() {
    let grant = Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("grant");
    let version = Uuid::parse_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").expect("version");
    let set = ManagedSecretBindingSet::from_runtime_context(&context(BTreeMap::from([(
        "DEPLOY_KEY".to_owned(),
        binding(grant, version),
    )])))
    .expect("binding set");
    let debug = format!("{set:?}");
    assert!(debug.contains("binding_count"));
    assert!(!debug.contains(&grant.to_string()));
    assert!(!debug.contains(&version.to_string()));
}
