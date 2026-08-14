use std::{fmt::Debug, sync::Arc};

use automata_ci_key_management::{KeyId, LocalAes256GcmKeyring, LocalKeyMaterial, SecretBytes};
use automata_ci_postgres::secret::{BUILTIN_POSTGRES_PROVIDER_ID, PostgresSecretProvider};
use automata_ci_secret::{
    ProviderCapability, ProviderErrorKind, ProviderOperationContext, ProviderRequestId,
    ProviderSecretLocator, ProviderVersionId, RepositoryScopeId, ResolveSecretVersionRequest,
    SecretAtRestProtection, SecretDescriptor, SecretId, SecretName, SecretProvider, SecretScope,
    TenantScopeId, WorkloadContext, WorkloadId,
};
use sqlx::postgres::PgPoolOptions;
use static_assertions::assert_impl_all;

assert_impl_all!(PostgresSecretProvider: Debug, Send, Sync);

fn provider() -> PostgresSecretProvider {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://sentinel-user:sentinel-password@127.0.0.1:1/sentinel")
        .unwrap();
    let key = LocalKeyMaterial::new(
        KeyId::new("contract-kek-v1").unwrap(),
        SecretBytes::new(vec![0x42; 32]).unwrap(),
    )
    .unwrap();
    let keyring = LocalAes256GcmKeyring::new(key, Vec::new(), []).unwrap();
    PostgresSecretProvider::new(pool, Arc::new(keyring))
}

fn accepts_object(_provider: &dyn SecretProvider) {}

#[tokio::test]
async fn provider_is_object_safe_stable_and_redacted() {
    let provider = provider();
    accepts_object(&provider);
    assert_eq!(
        provider.provider_id().as_str(),
        BUILTIN_POSTGRES_PROVIDER_ID
    );
    assert_eq!(
        provider.at_rest_protection(),
        SecretAtRestProtection::AutomataEnvelope
    );
    assert!(
        provider
            .capabilities()
            .supports(ProviderCapability::CreateVersion)
    );
    assert!(
        provider
            .capabilities()
            .supports(ProviderCapability::DestroyVersion)
    );
    assert!(
        !provider
            .capabilities()
            .supports(ProviderCapability::DynamicLeases)
    );

    let debug = format!("{provider:?}");
    assert!(!debug.contains("sentinel-password"));
    assert!(!debug.contains(&format!("{:?}", vec![0x42_u8; 32])));
    assert!(debug.contains(BUILTIN_POSTGRES_PROVIDER_ID));
}

#[tokio::test]
async fn malformed_or_mismatched_internal_handles_fail_before_sql() {
    let provider = provider();
    let tenant = TenantScopeId::new("tenant-contract").unwrap();
    let secret_id = SecretId::new("01234567-89ab-4def-8123-456789abcdef").unwrap();
    let descriptor = SecretDescriptor::new(
        secret_id,
        SecretName::new("release_token").unwrap(),
        SecretScope::tenant(tenant.clone()),
    );
    let workload = WorkloadContext::new(
        WorkloadId::new("workload-contract").unwrap(),
        SecretScope::repository(
            tenant.clone(),
            RepositoryScopeId::new("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee").unwrap(),
        ),
    )
    .unwrap();
    let operation =
        ProviderOperationContext::new(tenant, ProviderRequestId::new("resolve-contract").unwrap());
    let request = ResolveSecretVersionRequest::new(
        operation,
        workload,
        descriptor,
        ProviderSecretLocator::new("0123456789ab4def8123456789abcdef").unwrap(),
        ProviderVersionId::new("11111111-2222-4333-8444-555555555555").unwrap(),
    )
    .unwrap();
    let error = provider.resolve_version(request).await.unwrap_err();
    assert_eq!(error.kind(), ProviderErrorKind::InvalidRequest);
    assert_eq!(
        format!("{error:?}"),
        "ProviderError { kind: InvalidRequest, retry_after_seconds: None }"
    );
}
