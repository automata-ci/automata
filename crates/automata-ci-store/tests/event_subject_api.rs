use automata_ci_core::{OperationId, RunId, Sha256Digest, UnixMillis};
use automata_ci_store::{
    EVENT_CONTROL_SUBJECT_SCHEMA, EVENT_SUBJECT_ORIGIN_REGISTRY_VERSION,
    EVENT_SUBJECT_PROGRESS_SCHEMA, EVENT_SUBJECT_SELECTION_SCHEMA, EventControlSubject,
    EventControlSubjectId, EventSubjectId, EventSubjectOrigin, EventSubjectOriginKind,
    EventSubjectOriginRegistration, EventSubjectOriginRegistry, EventSubjectProgress,
    EventSubjectSelection, EventSubjectTerminalKind, EventSubjectTerminalOutcome,
    EventSubjectValueError, GithubScheduleFireId, MAX_EVENT_SUBJECT_EVENT_NAME_BYTES,
    MAX_EVENT_SUBJECT_REASON_BYTES, MAX_EVENT_SUBJECT_SOURCE_REVISION_BYTES,
    MAX_EVENT_SUBJECT_WORKFLOW_PATH_BYTES, ProviderDeliveryId, RegisterEventSubject, RepositoryId,
    TenantScope,
};
use uuid::Uuid;

fn tenant() -> TenantScope {
    TenantScope::from_authenticated_tenant_id("tenant-private-marker").expect("tenant")
}

fn provider_origin(value: u128) -> EventSubjectOrigin {
    EventSubjectOrigin::ProviderDelivery(
        ProviderDeliveryId::from_uuid(Uuid::from_u128(value)).expect("delivery"),
    )
}

fn selection_with(
    origin: EventSubjectOrigin,
    event_name: &str,
    workflow_path: &str,
    source_revision: &str,
    selected_at: i64,
) -> EventSubjectSelection {
    let repository_id = RepositoryId::from_uuid(Uuid::from_u128(100));
    let scoped_tenant = tenant();
    let id = EventSubjectId::derive(&scoped_tenant, repository_id, origin, workflow_path)
        .expect("derived subject");
    EventSubjectSelection::new(
        id,
        scoped_tenant,
        repository_id,
        origin,
        event_name,
        workflow_path,
        source_revision,
        Sha256Digest::from_bytes([0x42; 32]),
        Sha256Digest::from_bytes([0x24; 32]),
        UnixMillis::new(selected_at),
    )
    .expect("selection")
}

fn selection(id: u128) -> EventSubjectSelection {
    selection_with(
        provider_origin(200 + id),
        "workflow_dispatch",
        ".ci/workflows/private-workflow-marker.yml",
        "private-source-revision-marker",
        1_000,
    )
}

#[test]
fn origin_registry_is_closed_complete_and_stable() {
    let entries = EventSubjectOriginRegistry::canonical_entries();
    let registry = EventSubjectOriginRegistry::from_durable_entries(
        EVENT_SUBJECT_ORIGIN_REGISTRY_VERSION,
        &entries,
    )
    .expect("complete registry");

    assert_eq!(registry, EventSubjectOriginRegistry::current());
    assert_eq!(registry.version(), 1);
    assert_eq!(entries.len(), 4);
    assert_eq!(entries[0].code(), 1);
    assert_eq!(entries[0].name(), "provider_delivery");
    assert_eq!(entries[1].name(), "schedule_fire");
    assert_eq!(entries[2].name(), "manual_operation");
    assert_eq!(entries[3].name(), "workflow_run");
    assert_eq!(EventSubjectOriginKind::ProviderDelivery.durable_code(), 1);
    assert_eq!(
        EventSubjectOriginKind::ManualOperation.as_durable_str(),
        "manual_operation"
    );
    assert_ne!(registry.digest(), Sha256Digest::from_bytes([0; 32]));
}

#[test]
fn origin_registry_rejects_duplicates_unknowns_incompleteness_and_name_drift() {
    let mut duplicate = EventSubjectOriginRegistry::canonical_entries();
    duplicate[3] = duplicate[0].clone();
    assert_eq!(
        EventSubjectOriginRegistry::from_durable_entries(1, &duplicate),
        Err(EventSubjectValueError::DuplicateOriginRegistration(
            EventSubjectOriginKind::ProviderDelivery
        ))
    );

    let mut incomplete = EventSubjectOriginRegistry::canonical_entries();
    incomplete.pop();
    assert_eq!(
        EventSubjectOriginRegistry::from_durable_entries(1, &incomplete),
        Err(EventSubjectValueError::IncompleteOriginRegistry)
    );

    let unknown = [EventSubjectOriginRegistration::new(99, "future_origin").expect("shape")];
    assert_eq!(
        EventSubjectOriginRegistry::from_durable_entries(1, &unknown),
        Err(EventSubjectValueError::UnknownOriginCode(99))
    );

    let mut renamed = EventSubjectOriginRegistry::canonical_entries();
    renamed[0] = EventSubjectOriginRegistration::new(1, "renamed_delivery").expect("shape");
    assert_eq!(
        EventSubjectOriginRegistry::from_durable_entries(1, &renamed),
        Err(EventSubjectValueError::OriginRegistrationMismatch)
    );
}

#[test]
fn origin_registry_rejects_prior_and_future_versions_instead_of_guessing() {
    let entries = EventSubjectOriginRegistry::canonical_entries();
    for actual in [0, EVENT_SUBJECT_ORIGIN_REGISTRY_VERSION + 1] {
        assert_eq!(
            EventSubjectOriginRegistry::from_durable_entries(actual, &entries),
            Err(EventSubjectValueError::UnsupportedOriginRegistryVersion {
                expected: EVENT_SUBJECT_ORIGIN_REGISTRY_VERSION,
                actual,
            })
        );
    }
}

#[test]
fn subject_and_control_ids_are_stable_domain_separated_uuid_v8_values() {
    let repository_id = RepositoryId::from_uuid(Uuid::from_u128(100));
    let origin = provider_origin(201);
    let first = EventSubjectId::derive(&tenant(), repository_id, origin, ".ci/workflows/build.yml")
        .expect("derived subject");
    let replay =
        EventSubjectId::derive(&tenant(), repository_id, origin, ".ci/workflows/build.yml")
            .expect("derived subject");
    let changed_path =
        EventSubjectId::derive(&tenant(), repository_id, origin, ".ci/workflows/test.yml")
            .expect("derived subject");
    let changed_origin = EventSubjectId::derive(
        &tenant(),
        repository_id,
        provider_origin(202),
        ".ci/workflows/build.yml",
    )
    .expect("derived subject");

    assert_eq!(first, replay);
    assert_ne!(first, changed_path);
    assert_ne!(first, changed_origin);
    assert!(!first.as_uuid().is_nil());
    assert_eq!(first.as_uuid().get_version_num(), 8);

    let control = EventControlSubjectId::derive(first);
    assert_eq!(control, EventControlSubjectId::derive(replay));
    assert_ne!(control, EventControlSubjectId::derive(changed_path));
    assert_ne!(control.as_uuid(), first.as_uuid());
    assert!(!control.as_uuid().is_nil());
    assert_eq!(control.as_uuid().get_version_num(), 8);
}

#[test]
fn subject_id_derivation_reuses_selection_validation() {
    assert_eq!(
        EventSubjectId::derive(
            &tenant(),
            RepositoryId::from_uuid(Uuid::nil()),
            provider_origin(201),
            ".ci/workflows/build.yml",
        ),
        Err(EventSubjectValueError::NilUuid("repository ID"))
    );
    assert_eq!(
        EventSubjectId::derive(
            &tenant(),
            RepositoryId::from_uuid(Uuid::from_u128(100)),
            EventSubjectOrigin::ManualOperation(OperationId::from_uuid(Uuid::nil())),
            ".ci/workflows/build.yml",
        ),
        Err(EventSubjectValueError::NilUuid("event origin ID"))
    );
    assert_eq!(
        EventSubjectId::derive(
            &tenant(),
            RepositoryId::from_uuid(Uuid::from_u128(100)),
            provider_origin(201),
            "../unsafe.yml",
        ),
        Err(EventSubjectValueError::InvalidWorkflowPath)
    );

    let repository_id = RepositoryId::from_uuid(Uuid::from_u128(100));
    let origin = provider_origin(201);
    assert_eq!(
        EventSubjectSelection::new(
            EventSubjectId::from_uuid(Uuid::from_u128(999)).expect("non-nil arbitrary ID"),
            tenant(),
            repository_id,
            origin,
            "push",
            ".ci/workflows/build.yml",
            "0123456789abcdef",
            Sha256Digest::from_bytes([0x42; 32]),
            Sha256Digest::from_bytes([0x24; 32]),
            UnixMillis::new(1_000),
        ),
        Err(EventSubjectValueError::SubjectIdDerivationMismatch)
    );
}

#[test]
fn all_origin_leaves_bind_their_kind_and_uuid_into_selection() {
    let origins = [
        provider_origin(201),
        EventSubjectOrigin::ScheduleFire(
            GithubScheduleFireId::from_uuid(Uuid::from_u128(202)).expect("fire"),
        ),
        EventSubjectOrigin::ManualOperation(OperationId::from_uuid(Uuid::from_u128(203))),
        EventSubjectOrigin::WorkflowRun(RunId::from_uuid(Uuid::from_u128(204))),
    ];
    let expected_kinds = [
        EventSubjectOriginKind::ProviderDelivery,
        EventSubjectOriginKind::ScheduleFire,
        EventSubjectOriginKind::ManualOperation,
        EventSubjectOriginKind::WorkflowRun,
    ];

    let mut digests = Vec::new();
    for (origin, expected_kind) in origins.into_iter().zip(expected_kinds) {
        assert_eq!(origin.kind(), expected_kind);
        let selected = selection_with(
            origin,
            "push",
            ".ci/workflows/build.yml",
            "0123456789abcdef",
            1_000,
        );
        assert_eq!(selected.origin(), origin);
        assert_eq!(
            selected.origin_registry_version(),
            EVENT_SUBJECT_ORIGIN_REGISTRY_VERSION
        );
        assert_eq!(
            selected.origin_registry_digest(),
            EventSubjectOriginRegistry::current().digest()
        );
        digests.push(selected.digest());
    }
    digests.sort_unstable_by_key(|digest| *digest.as_bytes());
    digests.dedup();
    assert_eq!(digests.len(), 4);
}

#[test]
fn authenticated_authority_digest_is_part_of_the_immutable_selection() {
    let original = selection(9);
    let changed_authority = EventSubjectSelection::new(
        original.id(),
        original.tenant().clone(),
        original.repository_id(),
        original.origin(),
        original.event_name(),
        original.workflow_path(),
        original.source_revision(),
        original.source_digest(),
        Sha256Digest::from_bytes([0x25; 32]),
        original.selected_at(),
    )
    .expect("selection with changed authority");

    assert_eq!(
        original.authority_digest(),
        Sha256Digest::from_bytes([0x24; 32])
    );
    assert_ne!(
        original.authority_digest(),
        changed_authority.authority_digest()
    );
    assert_ne!(original.digest(), changed_authority.digest());
}

#[test]
fn selection_rejects_nil_identity_and_unbounded_or_unsafe_text() {
    assert_eq!(
        EventSubjectId::from_uuid(Uuid::nil()),
        Err(EventSubjectValueError::NilUuid("event subject ID"))
    );
    assert_eq!(
        EventControlSubjectId::from_uuid(Uuid::nil()),
        Err(EventSubjectValueError::NilUuid("event control subject ID"))
    );

    let build = |event: &str, path: &str, revision: &str| {
        EventSubjectSelection::new(
            EventSubjectId::from_uuid(Uuid::from_u128(1)).expect("subject"),
            tenant(),
            RepositoryId::from_uuid(Uuid::from_u128(2)),
            provider_origin(3),
            event,
            path,
            revision,
            Sha256Digest::from_bytes([1; 32]),
            Sha256Digest::from_bytes([2; 32]),
            UnixMillis::new(1),
        )
    };

    for event in [
        "",
        "Push",
        "push/unsafe",
        &"x".repeat(MAX_EVENT_SUBJECT_EVENT_NAME_BYTES + 1),
    ] {
        assert_eq!(
            build(event, "a.yml", "abc"),
            Err(EventSubjectValueError::InvalidEventName)
        );
    }
    for path in [
        "",
        "/a.yml",
        "../a.yml",
        "a//b.yml",
        "a\\b.yml",
        &"x".repeat(MAX_EVENT_SUBJECT_WORKFLOW_PATH_BYTES + 1),
    ] {
        assert_eq!(
            build("push", path, "abc"),
            Err(EventSubjectValueError::InvalidWorkflowPath)
        );
    }
    for revision in [
        "",
        " leading",
        "line\nbreak",
        &"x".repeat(MAX_EVENT_SUBJECT_SOURCE_REVISION_BYTES + 1),
    ] {
        assert_eq!(
            build("push", "a.yml", revision),
            Err(EventSubjectValueError::InvalidSourceRevision)
        );
    }

    assert_eq!(
        EventSubjectSelection::new(
            EventSubjectId::from_uuid(Uuid::from_u128(1)).expect("subject"),
            tenant(),
            RepositoryId::from_uuid(Uuid::nil()),
            provider_origin(3),
            "push",
            "a.yml",
            "abc",
            Sha256Digest::from_bytes([1; 32]),
            Sha256Digest::from_bytes([2; 32]),
            UnixMillis::new(1),
        ),
        Err(EventSubjectValueError::NilUuid("repository ID"))
    );
    assert_eq!(
        selection_with_result(EventSubjectOrigin::ManualOperation(OperationId::from_uuid(
            Uuid::nil()
        ))),
        Err(EventSubjectValueError::NilUuid("event origin ID"))
    );
}

fn selection_with_result(
    origin: EventSubjectOrigin,
) -> Result<EventSubjectSelection, EventSubjectValueError> {
    EventSubjectSelection::new(
        EventSubjectId::from_uuid(Uuid::from_u128(1)).expect("subject"),
        tenant(),
        RepositoryId::from_uuid(Uuid::from_u128(2)),
        origin,
        "push",
        "a.yml",
        "abc",
        Sha256Digest::from_bytes([1; 32]),
        Sha256Digest::from_bytes([2; 32]),
        UnixMillis::new(1),
    )
}

#[test]
fn durable_rehydration_rejects_changed_selection_progress_and_control_digests() {
    let selected = selection(10);
    assert_eq!(
        EventSubjectSelection::from_durable_parts(
            selected.id(),
            selected.tenant().clone(),
            selected.repository_id(),
            selected.origin(),
            selected.event_name(),
            selected.workflow_path(),
            selected.source_revision(),
            selected.source_digest(),
            selected.authority_digest(),
            selected.selected_at(),
            Sha256Digest::from_bytes([0xff; 32]),
        ),
        Err(EventSubjectValueError::SelectionDigestMismatch)
    );

    let outcome = EventSubjectTerminalOutcome::skipped("github.workflow.disabled").expect("reason");
    let progress = EventSubjectProgress::new(&selected, outcome.clone(), UnixMillis::new(2_000))
        .expect("progress");
    assert_eq!(
        EventSubjectProgress::from_durable_parts(
            &selected,
            outcome,
            UnixMillis::new(2_000),
            Sha256Digest::from_bytes([0xee; 32]),
        ),
        Err(EventSubjectValueError::ProgressDigestMismatch)
    );
    assert_ne!(progress.digest(), Sha256Digest::from_bytes([0; 32]));

    let control_id = EventControlSubjectId::derive(selected.id());
    let control =
        EventControlSubject::new(control_id, &selected, UnixMillis::new(1_001)).expect("control");
    assert_eq!(
        EventControlSubject::from_durable_parts(
            control_id,
            &selected,
            UnixMillis::new(1_001),
            Sha256Digest::from_bytes([0xdd; 32]),
        ),
        Err(EventSubjectValueError::ControlDigestMismatch)
    );
    assert_ne!(control.digest(), Sha256Digest::from_bytes([0; 32]));
}

#[test]
fn terminal_progress_is_closed_and_only_exact_redelivery_replays() {
    let selected = selection(30);
    let admitted =
        EventSubjectTerminalOutcome::admitted(RunId::from_uuid(Uuid::from_u128(31))).expect("run");
    let skipped = EventSubjectTerminalOutcome::skipped("github.workflow.disabled").expect("skip");
    let failed = EventSubjectTerminalOutcome::failed("github.source.unavailable").expect("failure");
    assert_eq!(admitted.kind(), EventSubjectTerminalKind::Admitted);
    assert_eq!(skipped.kind(), EventSubjectTerminalKind::Skipped);
    assert_eq!(failed.kind(), EventSubjectTerminalKind::Failed);
    assert!(admitted.run_id().is_some());
    assert_eq!(skipped.reason(), Some("github.workflow.disabled"));

    let first = EventSubjectProgress::new(&selected, skipped.clone(), UnixMillis::new(2_000))
        .expect("progress");
    let exact =
        EventSubjectProgress::new(&selected, skipped, UnixMillis::new(2_000)).expect("progress");
    let changed =
        EventSubjectProgress::new(&selected, failed, UnixMillis::new(2_000)).expect("progress");
    let changed_time = EventSubjectProgress::new(
        &selected,
        EventSubjectTerminalOutcome::skipped("github.workflow.disabled").expect("skip"),
        UnixMillis::new(2_001),
    )
    .expect("progress");
    assert!(first.is_exact_replay_of(&exact));
    assert!(!first.is_exact_replay_of(&changed));
    assert!(!first.is_exact_replay_of(&changed_time));

    assert_eq!(
        EventSubjectTerminalOutcome::admitted(RunId::from_uuid(Uuid::nil())),
        Err(EventSubjectValueError::NilUuid("admitted run ID"))
    );
    for reason in [
        "",
        "UPPER",
        "space is unsafe",
        &"x".repeat(MAX_EVENT_SUBJECT_REASON_BYTES + 1),
    ] {
        assert_eq!(
            EventSubjectTerminalOutcome::failed(reason),
            Err(EventSubjectValueError::InvalidProgressReason)
        );
    }
}

#[test]
fn control_and_progress_timeline_cannot_precede_selection() {
    let selected = selection(35);
    assert_eq!(
        EventControlSubject::new(
            EventControlSubjectId::derive(selected.id()),
            &selected,
            UnixMillis::new(selected.selected_at().get() - 1),
        ),
        Err(EventSubjectValueError::TimelineOrder),
    );
    assert_eq!(
        EventSubjectProgress::new(
            &selected,
            EventSubjectTerminalOutcome::skipped("workflow.disabled").expect("reason"),
            UnixMillis::new(selected.selected_at().get() - 1),
        ),
        Err(EventSubjectValueError::TimelineOrder),
    );
}

#[test]
fn control_registration_fails_closed_across_selections() {
    let first = selection(40);
    let second = selection(41);
    assert_eq!(
        EventControlSubject::new(
            EventControlSubjectId::from_uuid(Uuid::from_u128(999)).expect("non-nil arbitrary ID"),
            &first,
            UnixMillis::new(1_001),
        ),
        Err(EventSubjectValueError::ControlIdDerivationMismatch)
    );
    let control = EventControlSubject::new(
        EventControlSubjectId::derive(first.id()),
        &first,
        UnixMillis::new(1_001),
    )
    .expect("control");
    assert!(control.matches_selection(&first));
    assert!(!control.matches_selection(&second));
    assert_eq!(
        RegisterEventSubject::new(second, control),
        Err(EventSubjectValueError::SelectionBindingMismatch)
    );
}

#[test]
fn debug_output_redacts_event_workflow_revision_reason_and_digests() {
    let selected = selection(50);
    let selected_debug = format!("{selected:?}");
    for secret in [
        "tenant-private-marker",
        "workflow_dispatch",
        "private-workflow-marker",
        "private-source-revision-marker",
    ] {
        assert!(!selected_debug.contains(secret));
    }

    let progress = EventSubjectProgress::new(
        &selected,
        EventSubjectTerminalOutcome::failed("private.failure.marker").expect("reason"),
        UnixMillis::new(2_000),
    )
    .expect("progress");
    assert!(!format!("{progress:?}").contains("private.failure.marker"));

    let control = EventControlSubject::new(
        EventControlSubjectId::derive(selected.id()),
        &selected,
        UnixMillis::new(1_001),
    )
    .expect("control");
    let control_debug = format!("{control:?}");
    assert!(control_debug.contains("[REDACTED]"));
    assert!(!control_debug.contains(&format!("{:?}", control.digest())));
}

#[test]
fn event_subject_schemas_are_explicit_and_positive() {
    assert_eq!(EVENT_SUBJECT_SELECTION_SCHEMA, 1);
    assert_eq!(EVENT_SUBJECT_PROGRESS_SCHEMA, 1);
    assert_eq!(EVENT_CONTROL_SUBJECT_SCHEMA, 1);
}

#[cfg(feature = "adapter-spi")]
#[test]
fn adapter_receipts_preserve_exact_replay_and_selection_binding() {
    let selected = selection(60);
    let control = EventControlSubject::new(
        EventControlSubjectId::derive(selected.id()),
        &selected,
        UnixMillis::new(1_001),
    )
    .expect("control");
    let receipt = automata_ci_store::adapter_spi::event_subject_registration_receipt(
        selected.clone(),
        control,
        true,
    )
    .expect("registration receipt");
    assert_eq!(receipt.selection(), &selected);
    assert!(receipt.is_replay());

    let progress = EventSubjectProgress::new(
        &selected,
        EventSubjectTerminalOutcome::skipped("github.workflow.disabled").expect("reason"),
        UnixMillis::new(2_000),
    )
    .expect("progress");
    let progress_receipt =
        automata_ci_store::adapter_spi::event_subject_progress_receipt(progress.clone(), true);
    assert_eq!(progress_receipt.progress(), &progress);
    assert!(progress_receipt.is_replay());
}
