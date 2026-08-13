use automata_ci_secret::{
    CreateSecretVersionRequest, EnvironmentScopeId, ExistingSecretVersion, ModelError,
    ProviderCapabilities, ProviderCapability, ProviderCapabilityError, ProviderError,
    ProviderErrorKind, ProviderLeaseId, ProviderOperationContext, ProviderRequestId,
    ProviderSecretLocator, ProviderVersionId, ReconcileCreateSecretVersionOutcome,
    ReconcileCreateSecretVersionRequest, RenewProviderLeaseRequest, RepositoryScopeId,
    ResolveSecretVersionRequest, SecretAtRestProtection, SecretDescriptor, SecretId, SecretName,
    SecretProviderId, SecretScope, SecretValue, TenantScopeId, WorkloadContext, WorkloadId,
};

fn tenant(value: &str) -> TenantScopeId {
    TenantScopeId::new(value).expect("tenant")
}

fn repository(value: &str) -> RepositoryScopeId {
    RepositoryScopeId::new(value).expect("repository")
}

fn environment(value: &str) -> EnvironmentScopeId {
    EnvironmentScopeId::new(value).expect("environment")
}

fn descriptor(scope: SecretScope) -> SecretDescriptor {
    SecretDescriptor::new(
        SecretId::new("secret-1").expect("secret ID"),
        SecretName::new("release_token").expect("secret name"),
        scope,
    )
}

fn context(tenant_id: TenantScopeId) -> ProviderOperationContext {
    ProviderOperationContext::new(
        tenant_id,
        ProviderRequestId::new("request-1").expect("request ID"),
    )
}

#[test]
fn secret_names_are_case_insensitive_canonical_and_reserved() {
    let lower = SecretName::new("release_token_2").expect("valid name");
    let upper = SecretName::new("RELEASE_TOKEN_2").expect("valid name");
    assert_eq!(lower, upper);
    assert_eq!(lower.as_str(), "RELEASE_TOKEN_2");

    for invalid in ["", "2FAST", "HAS-DASH", "HAS SPACE", "UNICODÉ"] {
        assert_eq!(SecretName::new(invalid), Err(ModelError::InvalidSecretName));
    }
    for reserved in [
        "github_token",
        "Actions_cache",
        "runner_secret",
        "AUTOMATA_INTERNAL",
    ] {
        assert_eq!(
            SecretName::new(reserved),
            Err(ModelError::ReservedSecretName)
        );
    }
    assert_eq!(
        SecretName::new("A".repeat(256)),
        Err(ModelError::InvalidSecretName)
    );
}

#[test]
fn identifiers_are_bounded_and_control_free() {
    assert_eq!(
        TenantScopeId::new(""),
        Err(ModelError::InvalidTenantScopeId)
    );
    assert_eq!(
        RepositoryScopeId::new("repository\nother"),
        Err(ModelError::InvalidRepositoryScopeId)
    );
    assert_eq!(
        EnvironmentScopeId::new("e".repeat(256)),
        Err(ModelError::InvalidEnvironmentScopeId)
    );
    assert!(SecretProviderId::new("built-in.postgres-1").is_ok());
    assert!(SecretProviderId::new("BuiltIn").is_err());
    assert!(SecretProviderId::new("provider-").is_err());
}

#[test]
fn secret_scopes_enclose_only_exact_descendants() {
    let tenant_a = tenant("tenant-a");
    let tenant_b = tenant("tenant-b");
    let repository_a = repository("repository-a");
    let repository_b = repository("repository-b");
    let production = environment("production");

    let tenant_scope = SecretScope::tenant(tenant_a.clone());
    let repository_scope = SecretScope::repository(tenant_a.clone(), repository_a.clone());
    let environment_scope =
        SecretScope::environment(tenant_a.clone(), repository_a.clone(), production.clone());

    assert!(tenant_scope.encloses(&tenant_scope));
    assert!(tenant_scope.encloses(&repository_scope));
    assert!(tenant_scope.encloses(&environment_scope));
    assert!(repository_scope.encloses(&environment_scope));
    assert!(environment_scope.encloses(&environment_scope));

    assert!(!repository_scope.encloses(&SecretScope::repository(tenant_a.clone(), repository_b,)));
    assert!(!environment_scope.encloses(&SecretScope::environment(
        tenant_a,
        repository_a,
        environment("staging"),
    )));
    assert!(!tenant_scope.encloses(&SecretScope::tenant(tenant_b)));
}

#[test]
fn provider_requests_reject_cross_tenant_and_cross_repository_scope() {
    let tenant_a = tenant("tenant-a");
    let repository_a = repository("repository-a");
    let secret = descriptor(SecretScope::repository(
        tenant_a.clone(),
        repository_a.clone(),
    ));
    let value = || SecretValue::from_utf8("provider-secret".to_owned()).expect("secret value");

    let create =
        CreateSecretVersionRequest::new(context(tenant("tenant-b")), secret.clone(), None, value());
    assert_eq!(create.unwrap_err(), ModelError::TenantMismatch);

    let workload = WorkloadContext::new(
        WorkloadId::new("run/job/attempt").expect("workload ID"),
        SecretScope::repository(tenant_a.clone(), repository("repository-b")),
    )
    .expect("workload");
    let resolve = ResolveSecretVersionRequest::new(
        context(tenant_a),
        workload,
        secret,
        automata_ci_secret::ProviderSecretLocator::new("opaque-locator").expect("locator"),
        automata_ci_secret::ProviderVersionId::new("version-1").expect("version"),
    );
    assert_eq!(resolve.unwrap_err(), ModelError::WorkloadScopeMismatch);

    let cross_tenant_workload = WorkloadContext::new(
        WorkloadId::new("run/job/attempt-2").expect("workload ID"),
        SecretScope::repository(tenant("tenant-b"), repository_a),
    )
    .expect("workload");
    let renew = RenewProviderLeaseRequest::new(
        context(tenant("tenant-a")),
        cross_tenant_workload,
        ProviderLeaseId::new("lease-1").expect("lease ID"),
    );
    assert_eq!(renew.unwrap_err(), ModelError::TenantMismatch);
}

#[test]
fn provider_handles_are_opaque_in_diagnostics() {
    let locator = ProviderSecretLocator::new("vault/tenant/secret-name").expect("locator");
    let version = ProviderVersionId::new("provider-version-value").expect("version");
    let rendered = format!("{locator:?} {version:?}");
    assert!(!rendered.contains("vault/tenant/secret-name"));
    assert!(!rendered.contains("provider-version-value"));
    assert!(rendered.contains("[OPAQUE]"));

    let existing = ExistingSecretVersion::new(locator, version);
    assert_eq!(existing.locator().as_str(), "vault/tenant/secret-name");
    assert_eq!(existing.version().as_str(), "provider-version-value");
    let rendered = format!("{existing:?}");
    assert!(!rendered.contains("vault/tenant/secret-name"));
    assert!(!rendered.contains("provider-version-value"));
}

#[test]
fn secret_value_diagnostics_are_redacted_and_bounded() {
    let secret = SecretValue::from_utf8("do-not-print-this".to_owned()).expect("secret");
    let rendered = format!("{secret:?}");
    assert_eq!(rendered, "SecretValue([REDACTED])");
    assert!(!rendered.contains("do-not-print-this"));
    assert_eq!(secret.expose_secret(), b"do-not-print-this");

    let expected = ExistingSecretVersion::new(
        ProviderSecretLocator::new("opaque-locator").expect("locator"),
        ProviderVersionId::new("version-7").expect("version"),
    );
    let request = CreateSecretVersionRequest::new(
        context(tenant("tenant-a")),
        descriptor(SecretScope::tenant(tenant("tenant-a"))),
        Some(expected.clone()),
        secret,
    )
    .expect("create request");
    assert_eq!(request.expected_existing_version(), Some(&expected));
    let rendered = format!("{request:?}");
    assert!(!rendered.contains("do-not-print-this"));
    assert!(!rendered.contains("opaque-locator"));
    assert!(!rendered.contains("version-7"));

    assert!(SecretValue::new(Vec::new()).is_err());
    assert!(SecretValue::new(vec![0; automata_ci_secret::MAX_SECRET_VALUE_BYTES + 1]).is_err());
}

#[test]
fn create_reconciliation_is_value_free_exact_and_opaque_in_diagnostics() {
    let tenant_id = tenant("tenant-a");
    let secret = descriptor(SecretScope::tenant(tenant_id.clone()));
    let expected = ExistingSecretVersion::new(
        ProviderSecretLocator::new("provider/opaque-predecessor").expect("locator"),
        ProviderVersionId::new("opaque-version-before").expect("version"),
    );

    let cross_tenant = ReconcileCreateSecretVersionRequest::new(
        context(tenant("tenant-b")),
        secret.clone(),
        Some(expected.clone()),
    );
    assert_eq!(cross_tenant.unwrap_err(), ModelError::TenantMismatch);

    let request = ReconcileCreateSecretVersionRequest::new(
        context(tenant_id),
        secret.clone(),
        Some(expected.clone()),
    )
    .expect("reconciliation request");
    assert_eq!(request.context().tenant_id(), secret.scope().tenant_id());
    assert_eq!(request.context().request_id().as_str(), "request-1");
    assert_eq!(request.secret(), &secret);
    assert_eq!(request.expected_existing_version(), Some(&expected));

    let first_version_request =
        ReconcileCreateSecretVersionRequest::new(context(tenant("tenant-a")), secret, None)
            .expect("first-version reconciliation request");
    assert!(first_version_request.expected_existing_version().is_none());
    assert_ne!(first_version_request, request);

    let request_debug = format!("{request:?}");
    assert!(!request_debug.contains("provider/opaque-predecessor"));
    assert!(!request_debug.contains("opaque-version-before"));
    assert!(request_debug.contains("[OPAQUE]"));

    let outcome = ReconcileCreateSecretVersionOutcome::AlreadyCommitted(
        automata_ci_secret::CreatedSecretVersion::new(
            ProviderSecretLocator::new("provider/opaque-created").expect("locator"),
            ProviderVersionId::new("opaque-version-created").expect("version"),
        ),
    );
    let committed = outcome.already_committed().expect("committed result");
    assert_eq!(committed.locator().as_str(), "provider/opaque-created");
    assert_eq!(committed.version().as_str(), "opaque-version-created");
    let outcome_debug = format!("{outcome:?}");
    assert!(!outcome_debug.contains("provider/opaque-created"));
    assert!(!outcome_debug.contains("opaque-version-created"));
    assert!(outcome_debug.contains("[OPAQUE]"));
    assert!(
        ReconcileCreateSecretVersionOutcome::DefinitivelyNotCommitted
            .already_committed()
            .is_none()
    );
}

#[test]
fn capabilities_are_unique_and_lease_dependencies_are_explicit() {
    assert_eq!(
        SecretAtRestProtection::AutomataEnvelope.as_str(),
        "automata_envelope"
    );
    assert_eq!(
        SecretAtRestProtection::ProviderManagedEncryption.as_str(),
        "provider_managed_encryption"
    );

    assert_eq!(
        ProviderCapabilities::new([
            ProviderCapability::CreateVersion,
            ProviderCapability::CreateVersion,
        ]),
        Err(ProviderCapabilityError::Duplicate)
    );
    assert_eq!(
        ProviderCapabilities::new([ProviderCapability::RenewLeases]),
        Err(ProviderCapabilityError::InvalidLeaseCapabilities)
    );
    assert_eq!(
        ProviderCapabilities::new([ProviderCapability::ReconcileCreateVersion]),
        Err(ProviderCapabilityError::InvalidCreateReconciliation)
    );

    let create_capabilities = ProviderCapabilities::new([
        ProviderCapability::CreateVersion,
        ProviderCapability::ReconcileCreateVersion,
    ])
    .expect("valid create capabilities");
    assert!(create_capabilities.supports(ProviderCapability::CreateVersion));
    assert!(create_capabilities.supports(ProviderCapability::ReconcileCreateVersion));

    let all_capabilities = ProviderCapabilities::new([
        ProviderCapability::CreateVersion,
        ProviderCapability::ReconcileCreateVersion,
        ProviderCapability::DestroyVersion,
        ProviderCapability::DynamicLeases,
        ProviderCapability::RenewLeases,
        ProviderCapability::RevokeLeases,
    ])
    .expect("complete closed capability set");
    assert_eq!(all_capabilities.values().len(), 6);
    assert_eq!(
        ProviderCapabilities::new([
            ProviderCapability::CreateVersion,
            ProviderCapability::ReconcileCreateVersion,
            ProviderCapability::DestroyVersion,
            ProviderCapability::DynamicLeases,
            ProviderCapability::RenewLeases,
            ProviderCapability::RevokeLeases,
            ProviderCapability::CreateVersion,
        ]),
        Err(ProviderCapabilityError::TooMany)
    );

    let capabilities = ProviderCapabilities::new([
        ProviderCapability::DynamicLeases,
        ProviderCapability::RenewLeases,
        ProviderCapability::RevokeLeases,
    ])
    .expect("valid capabilities");
    assert!(capabilities.supports(ProviderCapability::RenewLeases));
    assert!(!capabilities.supports(ProviderCapability::DestroyVersion));

    let error = ProviderError::retryable(ProviderErrorKind::RateLimited, Some(30));
    assert_eq!(error.kind(), ProviderErrorKind::RateLimited);
    assert_eq!(error.retry_after_seconds(), Some(30));
}

#[test]
fn capability_construction_stops_at_the_cardinality_bound() {
    let mut yielded = 0;
    let unbounded = std::iter::from_fn(|| {
        yielded += 1;
        Some(ProviderCapability::CreateVersion)
    });

    assert_eq!(
        ProviderCapabilities::new(unbounded),
        Err(ProviderCapabilityError::TooMany)
    );
    assert_eq!(yielded, 7);
}
