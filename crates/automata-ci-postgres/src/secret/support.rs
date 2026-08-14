use automata_ci_key_management::{
    EnvelopeError, KeyEncryptionContext, KeyEncryptionError, KeyPurpose,
};
use automata_ci_secret::{
    ProviderError, ProviderErrorKind, ProviderSecretLocator, ProviderVersionId, SecretDescriptor,
    SecretScope,
};
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ValidatedSecretDescriptor {
    tenant_id: String,
    secret_id: Uuid,
    canonical_name: String,
    scope_kind: &'static str,
    repository_id: Option<Uuid>,
    environment_id: Option<Uuid>,
}

impl ValidatedSecretDescriptor {
    pub(crate) fn from_domain(secret: &SecretDescriptor) -> Result<Self, ProviderError> {
        let tenant_id = secret.scope().tenant_id().as_str().to_owned();
        let secret_id = canonical_uuid(secret.id().as_str())?;
        let (scope_kind, repository_id, environment_id) = match secret.scope() {
            SecretScope::Tenant { .. } => ("tenant", None, None),
            SecretScope::Repository { repository, .. } => (
                "repository",
                Some(canonical_uuid(repository.as_str())?),
                None,
            ),
            SecretScope::Environment {
                repository,
                environment,
                ..
            } => (
                "environment",
                Some(canonical_uuid(repository.as_str())?),
                Some(canonical_uuid(environment.as_str())?),
            ),
        };
        Ok(Self {
            tenant_id,
            secret_id,
            canonical_name: secret.name().as_str().to_owned(),
            scope_kind,
            repository_id,
            environment_id,
        })
    }

    pub(crate) fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub(crate) const fn secret_id(&self) -> Uuid {
        self.secret_id
    }

    pub(crate) fn matches(
        &self,
        canonical_name: &str,
        scope_kind: &str,
        repository_id: Option<Uuid>,
        environment_id: Option<Uuid>,
    ) -> bool {
        self.canonical_name == canonical_name
            && self.scope_kind == scope_kind
            && self.repository_id == repository_id
            && self.environment_id == environment_id
    }
}

pub(crate) fn canonical_uuid(value: &str) -> Result<Uuid, ProviderError> {
    let parsed = Uuid::parse_str(value)
        .map_err(|_| ProviderError::new(ProviderErrorKind::InvalidRequest))?;
    if parsed.hyphenated().to_string() != value {
        return Err(ProviderError::new(ProviderErrorKind::InvalidRequest));
    }
    Ok(parsed)
}

pub(crate) fn locator(secret_id: Uuid) -> ProviderSecretLocator {
    ProviderSecretLocator::new(secret_id.hyphenated().to_string())
        .expect("a canonical UUID is a valid internal provider locator")
}

pub(crate) fn version_id(version_id: Uuid) -> ProviderVersionId {
    ProviderVersionId::new(version_id.hyphenated().to_string())
        .expect("a canonical UUID is a valid internal provider version ID")
}

pub(crate) fn encryption_context(
    tenant_id: &str,
    purpose: KeyPurpose,
    version_id: Uuid,
) -> Result<KeyEncryptionContext, ProviderError> {
    KeyEncryptionContext::new(tenant_id, purpose, version_id.hyphenated().to_string())
        .map_err(|_| ProviderError::new(ProviderErrorKind::InvalidRequest))
}

pub(crate) fn map_envelope_error(error: EnvelopeError) -> ProviderError {
    let kind = match error {
        EnvelopeError::RandomnessUnavailable
        | EnvelopeError::KeyEncryption(
            KeyEncryptionError::RandomnessUnavailable | KeyEncryptionError::Unavailable,
        ) => ProviderErrorKind::Unavailable,
        EnvelopeError::InvalidEnvelope
        | EnvelopeError::UnsupportedSchema
        | EnvelopeError::AuthenticationFailed
        | EnvelopeError::CryptographicFailure
        | EnvelopeError::KeyEncryption(
            KeyEncryptionError::InvalidDataKey
            | KeyEncryptionError::InvalidCiphertext
            | KeyEncryptionError::AuthenticationFailed
            | KeyEncryptionError::UnknownKey
            | KeyEncryptionError::RetiredKey,
        ) => ProviderErrorKind::IntegrityFailure,
    };
    ProviderError::new(kind)
}

#[cfg(test)]
mod tests {
    use automata_ci_key_management::KeyPurpose;
    use automata_ci_secret::{
        EnvironmentScopeId, ProviderErrorKind, RepositoryScopeId, SecretDescriptor, SecretId,
        SecretName, SecretScope, TenantScopeId,
    };
    use uuid::Uuid;

    use super::{
        ValidatedSecretDescriptor, canonical_uuid, encryption_context, locator, version_id,
    };

    fn descriptor(scope: SecretScope) -> SecretDescriptor {
        SecretDescriptor::new(
            SecretId::new("01234567-89ab-4def-8123-456789abcdef").unwrap(),
            SecretName::new("release_token").unwrap(),
            scope,
        )
    }

    #[test]
    fn internal_references_are_canonical_uuid_strings() {
        let id = Uuid::parse_str("01234567-89ab-4def-8123-456789abcdef").unwrap();
        assert_eq!(locator(id).as_str(), id.hyphenated().to_string());
        assert_eq!(version_id(id).as_str(), id.hyphenated().to_string());
        assert_eq!(canonical_uuid(&id.hyphenated().to_string()), Ok(id));
        assert_eq!(
            canonical_uuid(&id.simple().to_string()).unwrap_err().kind(),
            ProviderErrorKind::InvalidRequest
        );
        assert_eq!(
            canonical_uuid(&id.hyphenated().to_string().to_uppercase())
                .unwrap_err()
                .kind(),
            ProviderErrorKind::InvalidRequest
        );
    }

    #[test]
    fn encryption_context_binds_tenant_purpose_and_exact_version() {
        let version = Uuid::parse_str("01234567-89ab-4def-8123-456789abcdef").unwrap();
        let purpose = KeyPurpose::new("secrets/builtin-value:v1").unwrap();
        let expected = encryption_context("tenant-a", purpose.clone(), version).unwrap();
        let other_tenant = encryption_context("tenant-b", purpose.clone(), version).unwrap();
        let other_purpose = encryption_context(
            "tenant-a",
            KeyPurpose::new("secrets/other-value:v1").unwrap(),
            version,
        )
        .unwrap();
        let other_version = encryption_context("tenant-a", purpose, Uuid::new_v4()).unwrap();

        assert_ne!(
            expected.canonical_authenticated_bytes(),
            other_tenant.canonical_authenticated_bytes()
        );
        assert_ne!(
            expected.canonical_authenticated_bytes(),
            other_purpose.canonical_authenticated_bytes()
        );
        assert_ne!(
            expected.canonical_authenticated_bytes(),
            other_version.canonical_authenticated_bytes()
        );
    }

    #[test]
    fn descriptors_require_canonical_uuid_scope_identities() {
        let tenant = TenantScopeId::new("tenant-a").unwrap();
        let repository = RepositoryScopeId::new("11111111-2222-4333-8444-555555555555").unwrap();
        let environment = EnvironmentScopeId::new("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee").unwrap();
        let validated = ValidatedSecretDescriptor::from_domain(&descriptor(
            SecretScope::environment(tenant, repository, environment),
        ))
        .unwrap();
        assert_eq!(validated.tenant_id(), "tenant-a");
        assert_eq!(validated.scope_kind, "environment");
        assert_eq!(
            validated.repository_id.unwrap().hyphenated().to_string(),
            "11111111-2222-4333-8444-555555555555"
        );
        assert_eq!(
            validated.environment_id.unwrap().hyphenated().to_string(),
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        );

        let noncanonical_repository =
            RepositoryScopeId::new("11111111222243338444555555555555").unwrap();
        let invalid = descriptor(SecretScope::repository(
            TenantScopeId::new("tenant-a").unwrap(),
            noncanonical_repository,
        ));
        assert_eq!(
            ValidatedSecretDescriptor::from_domain(&invalid)
                .unwrap_err()
                .kind(),
            ProviderErrorKind::InvalidRequest
        );
    }
}
