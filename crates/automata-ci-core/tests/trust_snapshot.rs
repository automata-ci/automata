use std::num::NonZeroU64;

use automata_ci_core::{
    DispatchRecursionPolicy, ForkWritePolicy, Sha256Digest, TrustActorEvidence, TrustActorKind,
    TrustAutomationKind, TrustCacheAuthority, TrustEnvironmentAuthority, TrustEventKind,
    TrustEvidence, TrustOidcAuthority, TrustOriginKind, TrustOutputAuthority,
    TrustPermissionAuthority, TrustPolicy, TrustRepositoryEvidence, TrustResultsAuthority,
    TrustSecretAuthority, TrustSnapshot, TrustSnapshotError, TrustSourceClass, TrustTokenRecursion,
    TrustUpstreamEvidence,
};
use serde_json::Value;

fn actor(id: &str, automation: TrustAutomationKind) -> TrustActorEvidence {
    TrustActorEvidence::new(id, TrustActorKind::User, automation).expect("valid actor")
}

fn repository(id: &str, owner_id: &str) -> TrustRepositoryEvidence {
    TrustRepositoryEvidence::new(id, owner_id).expect("valid repository")
}

fn complete_evidence(
    origin: TrustOriginKind,
    event: TrustEventKind,
    source_repository: TrustRepositoryEvidence,
    target_repository: TrustRepositoryEvidence,
    is_fork: bool,
    original_actor: TrustActorEvidence,
) -> TrustEvidence {
    TrustEvidence::new(origin, event)
        .with_original_actor(original_actor)
        .with_repositories(source_repository, target_repository)
        .with_refs("refs/heads/source", "refs/heads/main", "refs/heads/main")
        .with_revisions("source-sha", "target-sha", "execution-sha")
        .with_fork(is_fork)
}

fn same_repository_push(automation: TrustAutomationKind) -> TrustEvidence {
    complete_evidence(
        TrustOriginKind::ProviderWebhook,
        TrustEventKind::Push,
        repository("42", "7"),
        repository("42", "7"),
        false,
        actor("100", automation),
    )
    .with_token_recursion(TrustTokenRecursion::Suppressed)
}

fn fork_pull_request(automation: TrustAutomationKind) -> TrustEvidence {
    complete_evidence(
        TrustOriginKind::ProviderWebhook,
        TrustEventKind::PullRequest,
        repository("84", "9"),
        repository("42", "7"),
        true,
        actor("100", TrustAutomationKind::None),
    )
    .with_source_actor(actor("101", automation))
}

fn merge_queue() -> TrustEvidence {
    complete_evidence(
        TrustOriginKind::ProviderWebhook,
        TrustEventKind::MergeGroup,
        repository("42", "7"),
        repository("42", "7"),
        false,
        actor("100", TrustAutomationKind::None),
    )
    .with_token_recursion(TrustTokenRecursion::Suppressed)
}

#[derive(Clone, Copy)]
struct ExpectedAuthority {
    permissions: TrustPermissionAuthority,
    secrets: TrustSecretAuthority,
    cache: TrustCacheAuthority,
    environment: TrustEnvironmentAuthority,
    oidc: TrustOidcAuthority,
    outputs: TrustOutputAuthority,
    results: TrustResultsAuthority,
}

fn assert_authority(snapshot: &TrustSnapshot, expected: ExpectedAuthority) {
    let authority = snapshot.authority();
    assert_eq!(authority.permissions(), expected.permissions);
    assert_eq!(authority.secrets(), expected.secrets);
    assert_eq!(authority.cache(), expected.cache);
    assert_eq!(authority.environment(), expected.environment);
    assert_eq!(authority.oidc(), expected.oidc);
    assert_eq!(authority.outputs(), expected.outputs);
    assert_eq!(authority.results(), expected.results);
}

#[test]
fn multidimensional_source_truth_table_reduces_every_consumer_coherently() {
    let policy = TrustPolicy::current();
    let cases = [
        (
            same_repository_push(TrustAutomationKind::None),
            TrustSourceClass::SameRepository,
            ExpectedAuthority {
                permissions: TrustPermissionAuthority::Requested,
                secrets: TrustSecretAuthority::Eligible,
                cache: TrustCacheAuthority::ReadWrite,
                environment: TrustEnvironmentAuthority::Eligible,
                oidc: TrustOidcAuthority::Eligible,
                outputs: TrustOutputAuthority::Standard,
                results: TrustResultsAuthority::Standard,
            },
        ),
        (
            fork_pull_request(TrustAutomationKind::None),
            TrustSourceClass::Fork,
            ExpectedAuthority {
                permissions: TrustPermissionAuthority::ReadOnly,
                secrets: TrustSecretAuthority::Denied,
                cache: TrustCacheAuthority::ReadOnly,
                environment: TrustEnvironmentAuthority::Denied,
                oidc: TrustOidcAuthority::Denied,
                outputs: TrustOutputAuthority::Untrusted,
                results: TrustResultsAuthority::Untrusted,
            },
        ),
        (
            complete_evidence(
                TrustOriginKind::ProviderWebhook,
                TrustEventKind::PullRequest,
                repository("42", "7"),
                repository("42", "7"),
                false,
                actor("100", TrustAutomationKind::None),
            )
            .with_source_actor(actor("49699333", TrustAutomationKind::Dependabot)),
            TrustSourceClass::Dependabot,
            ExpectedAuthority {
                permissions: TrustPermissionAuthority::ReadOnly,
                secrets: TrustSecretAuthority::Denied,
                cache: TrustCacheAuthority::ReadOnly,
                environment: TrustEnvironmentAuthority::Denied,
                oidc: TrustOidcAuthority::Denied,
                outputs: TrustOutputAuthority::Untrusted,
                results: TrustResultsAuthority::Untrusted,
            },
        ),
        (
            same_repository_push(TrustAutomationKind::Other),
            TrustSourceClass::Automation,
            ExpectedAuthority {
                permissions: TrustPermissionAuthority::ReadOnly,
                secrets: TrustSecretAuthority::Denied,
                cache: TrustCacheAuthority::ReadOnly,
                environment: TrustEnvironmentAuthority::Denied,
                oidc: TrustOidcAuthority::Denied,
                outputs: TrustOutputAuthority::Untrusted,
                results: TrustResultsAuthority::Untrusted,
            },
        ),
        (
            merge_queue(),
            TrustSourceClass::MergeQueue,
            ExpectedAuthority {
                permissions: TrustPermissionAuthority::ReadOnly,
                secrets: TrustSecretAuthority::Denied,
                cache: TrustCacheAuthority::ReadOnly,
                environment: TrustEnvironmentAuthority::Denied,
                oidc: TrustOidcAuthority::Denied,
                outputs: TrustOutputAuthority::Untrusted,
                results: TrustResultsAuthority::Untrusted,
            },
        ),
    ];

    for (evidence, class, expected) in cases {
        let snapshot = policy.evaluate(evidence).expect("coherent evidence");
        assert!(snapshot.evidence_complete());
        assert_eq!(snapshot.source_class(), class);
        assert_authority(&snapshot, expected);
    }
}

#[test]
fn missing_evidence_is_a_persistable_deny_all_decision_not_a_placeholder() {
    let snapshot = TrustPolicy::current()
        .evaluate(TrustEvidence::new(
            TrustOriginKind::ProviderWebhook,
            TrustEventKind::Push,
        ))
        .expect("missing dimensions fail closed");

    assert!(!snapshot.evidence_complete());
    assert!(snapshot.is_unclassified());
    assert!(!snapshot.is_construction_placeholder());
    assert_authority(
        &snapshot,
        ExpectedAuthority {
            permissions: TrustPermissionAuthority::DenyAll,
            secrets: TrustSecretAuthority::Denied,
            cache: TrustCacheAuthority::Denied,
            environment: TrustEnvironmentAuthority::Denied,
            oidc: TrustOidcAuthority::Denied,
            outputs: TrustOutputAuthority::Untrusted,
            results: TrustResultsAuthority::Denied,
        },
    );
}

#[test]
fn construction_placeholder_is_distinct_from_authenticated_incomplete_evidence() {
    let placeholder = TrustSnapshot::deny_all_unclassified();
    assert!(placeholder.is_construction_placeholder());

    let rehydrated =
        TrustSnapshot::from_canonical_bytes(placeholder.canonical_bytes(), placeholder.digest())
            .expect("canonical deny-all bytes are structurally valid");
    assert!(!rehydrated.is_construction_placeholder());
    assert!(rehydrated.is_unclassified());
}

#[test]
fn fork_and_dependabot_claims_cannot_conflict_with_repository_identity() {
    let policy = TrustPolicy::current();
    let mismatched_fork = complete_evidence(
        TrustOriginKind::ProviderWebhook,
        TrustEventKind::PullRequest,
        repository("84", "9"),
        repository("42", "7"),
        false,
        actor("100", TrustAutomationKind::None),
    )
    .with_source_actor(actor("101", TrustAutomationKind::None));
    assert_eq!(
        policy.evaluate(mismatched_fork),
        Err(TrustSnapshotError::ConflictingEvidence)
    );

    let fork_dependabot = fork_pull_request(TrustAutomationKind::Dependabot);
    assert_eq!(
        policy.evaluate(fork_dependabot),
        Err(TrustSnapshotError::ConflictingEvidence)
    );
}

#[test]
fn dispatch_recursion_requires_the_exact_pinned_policy() {
    let external = complete_evidence(
        TrustOriginKind::ProviderWebhook,
        TrustEventKind::RepositoryDispatch,
        repository("42", "7"),
        repository("42", "7"),
        false,
        actor("100", TrustAutomationKind::None),
    )
    .with_token_recursion(TrustTokenRecursion::External);
    assert!(
        TrustPolicy::current()
            .evaluate(external)
            .expect("external dispatch")
            .evidence_complete()
    );

    let explicit = complete_evidence(
        TrustOriginKind::ProviderWebhook,
        TrustEventKind::RepositoryDispatch,
        repository("42", "7"),
        repository("42", "7"),
        false,
        actor("100", TrustAutomationKind::None),
    )
    .with_token_recursion(TrustTokenRecursion::ExplicitlyAllowed);
    let denied = TrustPolicy::current()
        .evaluate(explicit.clone())
        .expect("disallowed recursion fails closed");
    assert!(!denied.evidence_complete());
    assert_eq!(
        denied.authority().permissions(),
        TrustPermissionAuthority::DenyAll
    );

    let allowing = TrustPolicy::new(
        NonZeroU64::new(2).expect("non-zero"),
        ForkWritePolicy::Deny,
        DispatchRecursionPolicy::AllowExplicitly,
    );
    assert!(
        allowing
            .evaluate(explicit)
            .expect("explicitly allowed recursion")
            .evidence_complete()
    );
}

#[test]
fn transitive_source_restrictions_survive_merge_group_and_workflow_run() {
    for (origin, event) in [
        (TrustOriginKind::ProviderWebhook, TrustEventKind::MergeGroup),
        (TrustOriginKind::WorkflowRun, TrustEventKind::WorkflowRun),
    ] {
        let mut evidence = complete_evidence(
            origin,
            event,
            repository("42", "7"),
            repository("42", "7"),
            false,
            actor("100", TrustAutomationKind::None),
        );
        if event == TrustEventKind::MergeGroup {
            evidence = evidence.with_token_recursion(TrustTokenRecursion::Suppressed);
        }
        let evidence = evidence.with_upstream(
            TrustUpstreamEvidence::new(
                Sha256Digest::from_bytes([7; 32]),
                2,
                true,
                TrustSourceClass::Fork,
            )
            .expect("valid upstream"),
        );
        let snapshot = TrustPolicy::current()
            .evaluate(evidence)
            .expect("coherent transitive evidence");
        assert_eq!(snapshot.source_class(), TrustSourceClass::Fork);
        assert_eq!(
            snapshot.authority().permissions(),
            TrustPermissionAuthority::ReadOnly
        );
        assert_eq!(snapshot.authority().secrets(), TrustSecretAuthority::Denied);
    }
}

#[test]
fn malformed_transitive_evidence_is_rejected_during_rehydration() {
    let evidence = complete_evidence(
        TrustOriginKind::WorkflowRun,
        TrustEventKind::WorkflowRun,
        repository("42", "7"),
        repository("42", "7"),
        false,
        actor("100", TrustAutomationKind::None),
    )
    .with_upstream(
        TrustUpstreamEvidence::new(
            Sha256Digest::from_bytes([7; 32]),
            1,
            true,
            TrustSourceClass::SameRepository,
        )
        .expect("valid upstream"),
    );
    let snapshot = TrustPolicy::current()
        .evaluate(evidence)
        .expect("valid snapshot");
    let mut document: Value = serde_json::from_slice(snapshot.canonical_bytes()).expect("JSON");
    document["evidence"]["upstream"]["chain_depth"] = Value::from(0);
    assert!(serde_json::from_value::<TrustSnapshot>(document).is_err());
}

#[test]
fn triggering_actor_never_upgrades_or_reclassifies_original_authority() {
    let original_dependabot = same_repository_push(TrustAutomationKind::Dependabot)
        .with_triggering_actor(actor("100", TrustAutomationKind::None));
    let snapshot = TrustPolicy::current()
        .evaluate(original_dependabot)
        .expect("trigger is audit-only");
    assert_eq!(snapshot.source_class(), TrustSourceClass::Dependabot);

    let original_human = same_repository_push(TrustAutomationKind::None)
        .with_triggering_actor(actor("49699333", TrustAutomationKind::Dependabot));
    let snapshot = TrustPolicy::current()
        .evaluate(original_human)
        .expect("trigger is audit-only");
    assert_eq!(snapshot.source_class(), TrustSourceClass::SameRepository);
}

#[test]
fn reruns_must_reuse_the_original_snapshot_instead_of_reclassification() {
    let rerun = TrustEvidence::new(TrustOriginKind::Rerun, TrustEventKind::Push);
    assert_eq!(
        TrustPolicy::current().evaluate(rerun),
        Err(TrustSnapshotError::RerunMustReuseSnapshot)
    );
}

#[test]
fn canonical_replay_is_deterministic_and_detects_tampering() {
    let policy = TrustPolicy::current();
    let first = policy
        .evaluate(same_repository_push(TrustAutomationKind::None))
        .expect("valid evidence");
    let second = policy
        .evaluate(same_repository_push(TrustAutomationKind::None))
        .expect("valid evidence");
    assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    assert_eq!(first.digest(), second.digest());

    let replay = TrustSnapshot::from_canonical_bytes(first.canonical_bytes(), first.digest())
        .expect("exact replay");
    assert_eq!(replay, first);
    assert_eq!(
        TrustSnapshot::from_canonical_bytes(
            first.canonical_bytes(),
            Sha256Digest::from_bytes([0x55; 32]),
        ),
        Err(TrustSnapshotError::DigestMismatch)
    );

    let mut padded = first.canonical_bytes().to_vec();
    padded.push(b' ');
    assert_eq!(
        TrustSnapshot::from_canonical_bytes(&padded, first.digest()),
        Err(TrustSnapshotError::NoncanonicalEncoding)
    );

    let mut decision: Value = serde_json::from_slice(first.canonical_bytes()).expect("JSON");
    decision["authority"]["permissions"] = Value::String("deny_all".into());
    assert!(serde_json::from_value::<TrustSnapshot>(decision).is_err());
}

#[test]
fn debug_output_redacts_authenticated_facts() {
    let snapshot = TrustPolicy::current()
        .evaluate(same_repository_push(TrustAutomationKind::None))
        .expect("valid evidence");
    let debug = format!("{snapshot:?}");
    assert!(debug.contains("[REDACTED]"));
    for secret_fact in ["100", "refs/heads/source", "source-sha"] {
        assert!(!debug.contains(secret_fact), "debug leaked {secret_fact}");
    }

    let actor_debug = format!("{:?}", actor("sensitive-actor", TrustAutomationKind::None));
    let repository_debug = format!("{:?}", repository("sensitive-repo", "sensitive-owner"));
    assert!(!actor_debug.contains("sensitive-actor"));
    assert!(!repository_debug.contains("sensitive-repo"));
    assert!(!repository_debug.contains("sensitive-owner"));
}
