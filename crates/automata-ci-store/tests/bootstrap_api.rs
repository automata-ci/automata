use automata_ci_core::{
    Architecture, OperatingSystem, RunnerCapabilities, RunnerGroup, RunnerId, RunnerLabel,
    RunnerPlatform, Sha256Digest, UnixMillis,
};
use automata_ci_store::{
    MAX_STATIC_RUNNERS, RunnerSlotCount, StaticBootstrapValueError, StaticRunnerFleet,
    StaticRunnerRegistration, TenantScope,
};
use uuid::Uuid;

fn registration(
    id: RunnerId,
    name: &str,
    external_identity: &str,
    digest_byte: u8,
) -> StaticRunnerRegistration {
    let label = RunnerLabel::new("linux").expect("label");
    let group = RunnerGroup::new("g1").expect("group");
    let capabilities = RunnerCapabilities::new(
        id,
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
    )
    .with_labels([label.clone()])
    .with_groups([group])
    .with_max_parallel_jobs(2)
    .expect("slots");
    StaticRunnerRegistration::try_new(
        id,
        name,
        external_identity,
        vec![label],
        capabilities,
        RunnerSlotCount::new(2).expect("slots"),
        vec![(Sha256Digest::from_bytes([digest_byte; 32]), 2_000_000_000)],
    )
    .expect("registration")
}

#[test]
fn exact_registration_rejects_duplicated_routing_facts() {
    let id = RunnerId::new();
    let label = RunnerLabel::new("linux").expect("label");
    let group = RunnerGroup::new("g1").expect("group");
    let capabilities = RunnerCapabilities::new(
        id,
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
    )
    .with_labels([label.clone()])
    .with_groups([group])
    .with_max_parallel_jobs(2)
    .expect("slots");

    assert!(matches!(
        StaticRunnerRegistration::try_new(
            id,
            "runner-a",
            "spiffe://automata/runner-a",
            vec![label.clone(), label],
            capabilities.clone(),
            RunnerSlotCount::new(2).expect("slots"),
            vec![(Sha256Digest::from_bytes([1; 32]), 2_000_000_000)],
        ),
        Err(StaticBootstrapValueError::DuplicateLabel)
    ));
    assert!(matches!(
        StaticRunnerRegistration::try_new(
            id,
            "runner-a",
            "spiffe://automata/runner-a",
            vec![RunnerLabel::new("linux").expect("label")],
            capabilities,
            RunnerSlotCount::new(1).expect("slots"),
            vec![(Sha256Digest::from_bytes([1; 32]), 2_000_000_000)],
        ),
        Err(StaticBootstrapValueError::SlotMismatch)
    ));
}

#[test]
fn fleet_is_bounded_and_has_unambiguous_machine_authority() {
    let first = registration(RunnerId::new(), "runner-a", "spiffe://automata/runner-a", 1);
    let duplicate_external =
        registration(RunnerId::new(), "runner-b", "spiffe://automata/runner-a", 2);
    let tenant = TenantScope::from_authenticated_tenant_id("automata-ci").expect("tenant");
    let group = RunnerGroup::new("g1").expect("group");
    assert!(matches!(
        StaticRunnerFleet::try_new(
            tenant.clone(),
            group.clone(),
            vec![first, duplicate_external],
            UnixMillis::new(1),
        ),
        Err(StaticBootstrapValueError::DuplicateExternalIdentity)
    ));

    let duplicate_leaf_left =
        registration(RunnerId::new(), "runner-a", "spiffe://automata/runner-a", 3);
    let duplicate_leaf_right =
        registration(RunnerId::new(), "runner-b", "spiffe://automata/runner-b", 3);
    assert!(matches!(
        StaticRunnerFleet::try_new(
            TenantScope::from_authenticated_tenant_id("automata-ci").expect("tenant"),
            RunnerGroup::new("g1").expect("group"),
            vec![duplicate_leaf_left, duplicate_leaf_right],
            UnixMillis::new(1),
        ),
        Err(StaticBootstrapValueError::DuplicateCertificate)
    ));

    assert!(matches!(
        StaticRunnerFleet::try_new(tenant, group, Vec::new(), UnixMillis::new(1)),
        Err(StaticBootstrapValueError::InvalidFleetSize)
    ));
    assert_eq!(MAX_STATIC_RUNNERS, 64);
}

#[test]
fn active_certificate_set_is_nonempty_bounded_and_unique() {
    let id = RunnerId::new();
    let label = RunnerLabel::new("linux").expect("label");
    let capabilities = RunnerCapabilities::new(
        id,
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
    )
    .with_labels([label.clone()])
    .with_groups([RunnerGroup::new("g1").expect("group")]);
    let registration_with = |certificates| {
        StaticRunnerRegistration::try_new(
            id,
            "runner-a",
            "spiffe://automata/runner-a",
            vec![label.clone()],
            capabilities.clone(),
            RunnerSlotCount::new(1).expect("slots"),
            certificates,
        )
    };

    assert!(matches!(
        registration_with(Vec::new()),
        Err(StaticBootstrapValueError::InvalidCertificateSetSize)
    ));
    assert!(matches!(
        registration_with(vec![
            (Sha256Digest::from_bytes([1; 32]), 2_000_000_000),
            (Sha256Digest::from_bytes([2; 32]), 2_000_000_000),
            (Sha256Digest::from_bytes([3; 32]), 2_000_000_000),
        ]),
        Err(StaticBootstrapValueError::InvalidCertificateSetSize)
    ));
    assert!(matches!(
        registration_with(vec![
            (Sha256Digest::from_bytes([1; 32]), 2_000_000_000),
            (Sha256Digest::from_bytes([1; 32]), 2_000_000_001),
        ]),
        Err(StaticBootstrapValueError::DuplicateCertificate)
    ));
    let overlap = registration_with(vec![
        (Sha256Digest::from_bytes([2; 32]), 2_000_000_001),
        (Sha256Digest::from_bytes([1; 32]), 2_000_000_000),
    ])
    .expect("bounded overlap");
    assert_eq!(
        overlap.active_certificates(),
        &[
            (Sha256Digest::from_bytes([1; 32]), 2_000_000_000),
            (Sha256Digest::from_bytes([2; 32]), 2_000_000_001),
        ]
    );
    assert_eq!(StaticRunnerRegistration::MAX_ACTIVE_CERTIFICATES, 2);
}

#[test]
fn fleet_requires_each_capability_document_to_name_only_its_group() {
    let id = RunnerId::new();
    let label = RunnerLabel::new("linux").expect("label");
    let capabilities = RunnerCapabilities::new(
        id,
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
    )
    .with_labels([label.clone()])
    .with_groups([RunnerGroup::new("other").expect("group")]);
    let runner = StaticRunnerRegistration::try_new(
        id,
        "runner-a",
        "spiffe://automata/runner-a",
        vec![label],
        capabilities,
        RunnerSlotCount::new(1).expect("slots"),
        vec![(Sha256Digest::from_bytes([1; 32]), 2_000_000_000)],
    )
    .expect("registration-level coherence");
    assert!(matches!(
        StaticRunnerFleet::try_new(
            TenantScope::from_authenticated_tenant_id("automata-ci").expect("tenant"),
            RunnerGroup::new("g1").expect("group"),
            vec![runner],
            UnixMillis::new(1),
        ),
        Err(StaticBootstrapValueError::GroupMismatch)
    ));
}

#[test]
fn fleet_rejects_a_certificate_that_is_not_current_at_application() {
    let runner = registration(RunnerId::new(), "runner-a", "spiffe://automata/runner-a", 1);
    assert!(matches!(
        StaticRunnerFleet::try_new(
            TenantScope::from_authenticated_tenant_id("automata-ci").expect("tenant"),
            RunnerGroup::new("g1").expect("group"),
            vec![runner],
            UnixMillis::new(2_000_000_000_000),
        ),
        Err(StaticBootstrapValueError::CertificateNotCurrent)
    ));
}

#[test]
fn registration_rejects_machine_authority_sentinels() {
    let nil_id = RunnerId::from_uuid(Uuid::nil());
    let label = RunnerLabel::new("linux").expect("label");
    let group = RunnerGroup::new("g1").expect("group");
    let nil_capabilities = RunnerCapabilities::new(
        nil_id,
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
    )
    .with_labels([label.clone()])
    .with_groups([group.clone()]);
    assert!(matches!(
        StaticRunnerRegistration::try_new(
            nil_id,
            "runner-nil",
            "spiffe://automata/runner-nil",
            vec![label.clone()],
            nil_capabilities,
            RunnerSlotCount::new(1).expect("slots"),
            vec![(Sha256Digest::from_bytes([1; 32]), 2_000_000_000)],
        ),
        Err(StaticBootstrapValueError::InvalidRunnerId)
    ));

    let runner_id = RunnerId::new();
    let capabilities = RunnerCapabilities::new(
        runner_id,
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
    )
    .with_labels([label.clone()])
    .with_groups([group]);
    assert!(matches!(
        StaticRunnerRegistration::try_new(
            runner_id,
            "runner-zero-digest",
            "spiffe://automata/runner-zero-digest",
            vec![label],
            capabilities,
            RunnerSlotCount::new(1).expect("slots"),
            vec![(Sha256Digest::from_bytes([0; 32]), 2_000_000_000)],
        ),
        Err(StaticBootstrapValueError::InvalidCertificateDigest)
    ));
}
