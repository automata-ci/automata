//! Durable least-authority GitHub credentials used by server-side services.
//!
//! This domain is deliberately separate from job runtime authority. A server
//! credential is bound to one configured repository, GitHub App installation,
//! fixed service scope, and configuration revision. Provider and key-manager
//! calls happen outside repository transactions; the repository only retains
//! immutable identity, fenced lifecycle evidence, and protected envelopes.

use std::num::{NonZeroU16, NonZeroU64};

use async_trait::async_trait;
use automata_ci_core::UnixMillis;
use automata_ci_key_management::{
    ENVELOPE_SCHEMA_V1, EncryptedEnvelope, KeyEncryptionContext, KeyPurpose,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    GithubRepositoryName, ProviderConnectionId, ProviderInstallationId, ProviderRepositoryId,
    RepositoryId, RepositoryOperationError, Sha256Digest, TenantScope,
};

/// Maximum duration of one pre-mint database claim.
pub const MAX_GITHUB_SERVICE_MINT_CLAIM_MILLIS: i64 = 2 * 60 * 1_000;
/// Maximum duration of one revocation database claim.
pub const MAX_GITHUB_SERVICE_REVOKE_CLAIM_MILLIS: i64 = 2 * 60 * 1_000;
/// Maximum provider request interval admitted by the durable boundary.
pub const MAX_GITHUB_SERVICE_REQUEST_MILLIS: i64 = 2 * 60 * 1_000;
/// Maximum lifetime of a GitHub installation credential.
pub const GITHUB_SERVICE_TOKEN_LIFETIME_MILLIS: i64 = 60 * 60 * 1_000;
/// Provider clock skew removed from the credential-use horizon.
pub const GITHUB_SERVICE_PROVIDER_CLOCK_SKEW_MILLIS: i64 = 60 * 1_000;
/// Propagation and clock skew retained after provider expiry before erasure.
pub const GITHUB_SERVICE_SAFE_ERASE_SKEW_MILLIS: i64 = 2 * 60 * 1_000;
/// Maximum delay for a definitive no-token mint retry.
pub const MAX_GITHUB_SERVICE_MINT_RETRY_MILLIS: i64 = 2 * 60 * 1_000;
/// Maximum delay for a provider revocation retry.
pub const MAX_GITHUB_SERVICE_REVOKE_RETRY_MILLIS: i64 = 24 * 60 * 60 * 1_000;
/// Maximum bounded GitHub consumer request uncertainty after its durable claim.
pub const MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS: i64 = 5 * 60 * 1_000;
/// Maximum lifetime of one value-free consumer handoff.
///
/// This covers the maximum 15-minute owning consumer lease plus two bounded
/// five-minute GitHub requests for a Check publication that conditionally
/// performs a GET followed by PATCH. Other actions request their smaller exact
/// horizon. Revocation waits for the durable derivative horizon.
pub const MAX_GITHUB_SERVICE_HANDOFF_MILLIS: i64 =
    15 * 60 * 1_000 + 2 * MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS;
/// Minimum conservative use horizon required before a credential may replace current.
pub const MIN_GITHUB_SERVICE_READY_USE_MILLIS: i64 = MAX_GITHUB_SERVICE_HANDOFF_MILLIS;
/// Maximum number of provider mint attempts for one generation.
pub const MAX_GITHUB_SERVICE_MINT_ATTEMPTS: u16 = 32;
/// Maximum number of provider revocation attempts for one generation.
pub const MAX_GITHUB_SERVICE_REVOKE_ATTEMPTS: u16 = 64;
/// Maximum failed generations admitted after the last Ready credential.
pub const MAX_GITHUB_SERVICE_CONSECUTIVE_GENERATION_FAILURES: u16 = 32;
/// Fixed delay after a definitive failed generation before another mint.
pub const GITHUB_SERVICE_GENERATION_FAILURE_BACKOFF_MILLIS: i64 = 60 * 1_000;
/// Cooldown before a saturated authority-level mint breaker may rearm.
pub const GITHUB_SERVICE_FAILURE_BUDGET_REARM_MILLIS: i64 = 24 * 60 * 60 * 1_000;
/// Maximum protected credential/frame bytes accepted for custody.
pub const MAX_GITHUB_SERVICE_PLAINTEXT_BYTES: u64 = 16 * 1024;

const MAX_APP_CLIENT_ID_BYTES: usize = 128;
const MAX_FAILURE_KIND_BYTES: usize = 128;
const PROTECTED_PLAINTEXT_SCHEMA: u16 = 1;
// foundation-governance: derived-contract owner=store kind=cryptographic-context
const WRAPPING_PURPOSE: &str = "control-plane/github-server-service-authority-wrapping:v1";
// foundation-governance: derived-contract owner=store kind=cryptographic-context
const PAYLOAD_PURPOSE: &str = "control-plane/github-server-service-authority:v1";
// foundation-governance: derived-contract owner=store kind=digest-domain
const IDENTITY_DIGEST_DOMAIN: &[u8] = b"automata.store.github-server-service.identity.v1\0";
// foundation-governance: derived-contract owner=store kind=cryptographic-context
const AAD_DIGEST_DOMAIN: &[u8] = b"automata.store.github-server-service.aad.v1\0";
// foundation-governance: derived-contract owner=store kind=digest-domain
const POLICY_DIGEST_DOMAIN: &[u8] = b"automata.store.github-server-service.policy.v1\0";

macro_rules! uuid_identity {
    ($(#[$meta:meta])* $name:ident, $field:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            /// Constructs a non-nil durable UUID identity.
            ///
            /// # Errors
            ///
            /// Rejects the nil UUID sentinel.
            pub fn from_uuid(value: Uuid) -> Result<Self, GithubServerServiceValueError> {
                if value.is_nil() {
                    return Err(GithubServerServiceValueError::NilIdentity($field));
                }
                Ok(Self(value))
            }

            /// Returns the durable UUID value.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }
    };
}

uuid_identity!(/// Durable identity of one immutable server-service authority descriptor.
    GithubServerServiceAuthorityId, "server-service authority ID");
uuid_identity!(/// Durable identity of one mint or revocation worker.
    GithubServerServiceWorkerId, "server-service authority worker ID");
uuid_identity!(/// Durable identity of one value-free consumer handoff.
    GithubServerServiceHandoffId, "server-service authority handoff ID");
uuid_identity!(/// Exact durable work item consuming one handoff.
    GithubServerServiceConsumerId, "server-service authority consumer ID");

macro_rules! positive_bigint {
    ($(#[$meta:meta])* $name:ident, $error:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(NonZeroU64);

        impl $name {
            /// Constructs a positive value representable by `PostgreSQL` `BIGINT`.
            ///
            /// # Errors
            ///
            /// Rejects zero and values larger than `i64::MAX`.
            pub fn new(value: u64) -> Result<Self, GithubServerServiceValueError> {
                let value = NonZeroU64::new(value)
                    .filter(|value| i64::try_from(value.get()).is_ok())
                    .ok_or(GithubServerServiceValueError::$error)?;
                Ok(Self(value))
            }

            /// Returns the positive value.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0.get()
            }

            pub(crate) fn as_i64(self) -> i64 {
                i64::try_from(self.get()).expect("validated value fits BIGINT")
            }
        }
    };
}

positive_bigint!(/// Positive GitHub App numeric identity.
    GithubServerServiceAppId, InvalidAppId);
positive_bigint!(/// Positive immutable issuance generation.
    GithubServerServiceGeneration, InvalidGeneration);
positive_bigint!(/// Positive authority/configuration revision.
    GithubServerServiceRevision, InvalidRevision);
positive_bigint!(/// Positive claim fence.
    GithubServerServiceClaimFence, InvalidClaimFence);

/// Exact GitHub App JWT client identity, distinct from the numeric App ID.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubServerServiceAppClientId(String);

impl GithubServerServiceAppClientId {
    /// Constructs a bounded provider-issued client identity.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or noncanonical text.
    pub fn new(value: impl Into<String>) -> Result<Self, GithubServerServiceValueError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_APP_CLIENT_ID_BYTES
            || !value
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !value
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(GithubServerServiceValueError::InvalidAppClientId);
        }
        Ok(Self(value))
    }

    /// Returns the exact client identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact configured value family placed in the GitHub App JWT `iss` claim.
///
/// Both the numeric App ID and App client ID remain immutable descriptor
/// evidence. This discriminator prevents a configuration change between the
/// two GitHub-supported issuer forms from reusing an old authority.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GithubServerServiceJwtIssuer {
    /// Use the exact configured App client ID as `iss`.
    AppClientId,
    /// Use the decimal numeric App ID as `iss`.
    AppId,
}

impl GithubServerServiceJwtIssuer {
    /// Returns the durable issuer discriminator.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AppClientId => "app_client_id",
            Self::AppId => "app_id",
        }
    }

    pub(crate) fn from_durable(value: &str) -> Result<Self, GithubServerServiceValueError> {
        match value {
            "app_client_id" => Ok(Self::AppClientId),
            "app_id" => Ok(Self::AppId),
            _ => Err(GithubServerServiceValueError::InvalidJwtIssuer),
        }
    }
}

/// Closed least-authority GitHub installation credential policy.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GithubServerServiceScope {
    /// Exactly `{"checks":"write"}` for Check Suite and Check Run I/O.
    ChecksWrite,
    /// Exactly `{"contents":"read"}` for private repository source reads.
    PrivateRepositorySourceRead,
}

impl GithubServerServiceScope {
    /// Returns the durable policy discriminator.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ChecksWrite => "checks_write",
            Self::PrivateRepositorySourceRead => "private_repository_source_read",
        }
    }

    /// Returns the exact canonical GitHub permission document.
    #[must_use]
    pub const fn permissions_json(self) -> &'static str {
        match self {
            Self::ChecksWrite => "{\"checks\":\"write\"}",
            Self::PrivateRepositorySourceRead => "{\"contents\":\"read\"}",
        }
    }

    /// Returns the domain-separated digest of the fixed permission document.
    #[must_use]
    pub fn policy_digest(self) -> Sha256Digest {
        let mut digest = Sha256::new();
        digest.update(POLICY_DIGEST_DOMAIN);
        digest.update(self.as_str().as_bytes());
        digest.update([0]);
        digest.update(self.permissions_json().as_bytes());
        Sha256Digest::from_bytes(digest.finalize().into())
    }

    pub(crate) fn from_durable(value: &str) -> Result<Self, GithubServerServiceValueError> {
        match value {
            "checks_write" => Ok(Self::ChecksWrite),
            "private_repository_source_read" => Ok(Self::PrivateRepositorySourceRead),
            _ => Err(GithubServerServiceValueError::InvalidScope),
        }
    }
}

/// Immutable configured identity of one server-service authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubServerServiceAuthorityIdentity {
    tenant: TenantScope,
    authority_id: GithubServerServiceAuthorityId,
    repository_id: RepositoryId,
    connection_id: ProviderConnectionId,
    installation_id: ProviderInstallationId,
    github_app_id: GithubServerServiceAppId,
    github_repository_id: ProviderRepositoryId,
    github_repository_name: GithubRepositoryName,
    scope: GithubServerServiceScope,
    app_client_id: GithubServerServiceAppClientId,
    jwt_issuer: GithubServerServiceJwtIssuer,
    app_key_spki_sha256: Sha256Digest,
    app_configuration_revision: GithubServerServiceRevision,
    policy_revision: GithubServerServiceRevision,
    configuration_fingerprint: Sha256Digest,
}

impl GithubServerServiceAuthorityIdentity {
    /// Constructs the complete immutable authority descriptor identity.
    ///
    /// # Errors
    ///
    /// Rejects a nil internal repository identity.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: TenantScope,
        authority_id: GithubServerServiceAuthorityId,
        repository_id: RepositoryId,
        connection_id: ProviderConnectionId,
        installation_id: ProviderInstallationId,
        github_app_id: GithubServerServiceAppId,
        github_repository_id: ProviderRepositoryId,
        github_repository_name: GithubRepositoryName,
        scope: GithubServerServiceScope,
        app_client_id: GithubServerServiceAppClientId,
        jwt_issuer: GithubServerServiceJwtIssuer,
        app_key_spki_sha256: Sha256Digest,
        app_configuration_revision: GithubServerServiceRevision,
        policy_revision: GithubServerServiceRevision,
        configuration_fingerprint: Sha256Digest,
    ) -> Result<Self, GithubServerServiceValueError> {
        if repository_id.as_uuid().is_nil() {
            return Err(GithubServerServiceValueError::NilIdentity(
                "server-service repository ID",
            ));
        }
        Ok(Self {
            tenant,
            authority_id,
            repository_id,
            connection_id,
            installation_id,
            github_app_id,
            github_repository_id,
            github_repository_name,
            scope,
            app_client_id,
            jwt_issuer,
            app_key_spki_sha256,
            app_configuration_revision,
            policy_revision,
            configuration_fingerprint,
        })
    }

    /// Returns the authenticated tenant scope.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }
    /// Returns the durable authority ID.
    #[must_use]
    pub const fn authority_id(&self) -> GithubServerServiceAuthorityId {
        self.authority_id
    }
    /// Returns the internal repository ID.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }
    /// Returns the configured provider connection.
    #[must_use]
    pub const fn connection_id(&self) -> ProviderConnectionId {
        self.connection_id
    }
    /// Returns the configured App installation.
    #[must_use]
    pub const fn installation_id(&self) -> ProviderInstallationId {
        self.installation_id
    }
    /// Returns the numeric GitHub App identity.
    #[must_use]
    pub const fn github_app_id(&self) -> GithubServerServiceAppId {
        self.github_app_id
    }
    /// Returns the provider-stable numeric repository identity.
    #[must_use]
    pub const fn github_repository_id(&self) -> ProviderRepositoryId {
        self.github_repository_id
    }
    /// Returns the exact canonical `owner/repository` spelling.
    #[must_use]
    pub const fn github_repository_name(&self) -> &GithubRepositoryName {
        &self.github_repository_name
    }
    /// Returns the fixed least-authority service scope.
    #[must_use]
    pub const fn scope(&self) -> GithubServerServiceScope {
        self.scope
    }
    /// Returns the GitHub App JWT client identity.
    #[must_use]
    pub const fn app_client_id(&self) -> &GithubServerServiceAppClientId {
        &self.app_client_id
    }
    /// Returns the exact configured JWT `iss` value family.
    #[must_use]
    pub const fn jwt_issuer(&self) -> GithubServerServiceJwtIssuer {
        self.jwt_issuer
    }
    /// Returns the configured RSA public-key SPKI digest.
    #[must_use]
    pub const fn app_key_spki_sha256(&self) -> Sha256Digest {
        self.app_key_spki_sha256
    }
    /// Returns the App configuration revision.
    #[must_use]
    pub const fn app_configuration_revision(&self) -> GithubServerServiceRevision {
        self.app_configuration_revision
    }
    /// Returns the fixed policy revision.
    #[must_use]
    pub const fn policy_revision(&self) -> GithubServerServiceRevision {
        self.policy_revision
    }
    /// Returns the complete configuration fingerprint.
    #[must_use]
    pub const fn configuration_fingerprint(&self) -> Sha256Digest {
        self.configuration_fingerprint
    }
    /// Returns the derived fixed permission-policy digest.
    #[must_use]
    pub fn policy_digest(&self) -> Sha256Digest {
        self.scope.policy_digest()
    }

    /// Returns a digest of every immutable descriptor field.
    #[must_use]
    pub fn identity_digest(&self) -> Sha256Digest {
        let mut digest = Sha256::new();
        digest.update(IDENTITY_DIGEST_DOMAIN);
        update_part(&mut digest, self.tenant.as_str().as_bytes());
        update_part(&mut digest, self.authority_id.as_uuid().as_bytes());
        update_part(&mut digest, self.repository_id.as_uuid().as_bytes());
        update_part(&mut digest, self.connection_id.as_uuid().as_bytes());
        update_part(&mut digest, &self.installation_id.get().to_be_bytes());
        update_part(&mut digest, &self.github_app_id.get().to_be_bytes());
        update_part(&mut digest, &self.github_repository_id.get().to_be_bytes());
        update_part(&mut digest, self.github_repository_name.as_str().as_bytes());
        update_part(&mut digest, self.scope.as_str().as_bytes());
        update_part(&mut digest, self.app_client_id.as_str().as_bytes());
        update_part(&mut digest, self.jwt_issuer.as_str().as_bytes());
        update_part(&mut digest, self.app_key_spki_sha256.as_bytes());
        update_part(
            &mut digest,
            &self.app_configuration_revision.get().to_be_bytes(),
        );
        update_part(&mut digest, &self.policy_revision.get().to_be_bytes());
        update_part(&mut digest, self.configuration_fingerprint.as_bytes());
        Sha256Digest::from_bytes(digest.finalize().into())
    }

    /// Builds the identity-only KMS wrapping context for one generation.
    ///
    /// # Errors
    ///
    /// Fails only if the validated identity cannot fit the key-management
    /// context boundary.
    pub fn wrapping_encryption_context(
        &self,
        generation: GithubServerServiceGeneration,
    ) -> Result<KeyEncryptionContext, GithubServerServiceValueError> {
        let purpose = KeyPurpose::new(WRAPPING_PURPOSE)
            .map_err(|_| GithubServerServiceValueError::InvalidEncryptionContext)?;
        let record_id = format!(
            "github-server-service-wrapping:v1:{}:{}:{}",
            self.authority_id.as_uuid(),
            generation.get(),
            self.identity_digest()
        );
        KeyEncryptionContext::new(self.tenant.as_str(), purpose, record_id)
            .map_err(|_| GithubServerServiceValueError::InvalidEncryptionContext)
    }
}

/// Exact immutable descriptor selector required for every lifecycle mutation.
///
/// The globally unique authority UUID is an identifier, not a bearer
/// capability. The tenant and immutable digest/revisions keep stale or
/// cross-tenant supervisors from mutating a descriptor selected only by UUID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubServerServiceAuthoritySelector {
    tenant: TenantScope,
    authority_id: GithubServerServiceAuthorityId,
    identity_digest: Sha256Digest,
    app_configuration_revision: GithubServerServiceRevision,
    policy_revision: GithubServerServiceRevision,
}

impl GithubServerServiceAuthoritySelector {
    /// Derives the exact mutation selector from an immutable identity.
    #[must_use]
    pub fn from_identity(identity: &GithubServerServiceAuthorityIdentity) -> Self {
        Self {
            tenant: identity.tenant().clone(),
            authority_id: identity.authority_id(),
            identity_digest: identity.identity_digest(),
            app_configuration_revision: identity.app_configuration_revision(),
            policy_revision: identity.policy_revision(),
        }
    }

    /// Rehydrates a selector held by a durable maintenance record.
    #[must_use]
    pub const fn from_durable_parts(
        tenant: TenantScope,
        authority_id: GithubServerServiceAuthorityId,
        identity_digest: Sha256Digest,
        app_configuration_revision: GithubServerServiceRevision,
        policy_revision: GithubServerServiceRevision,
    ) -> Self {
        Self {
            tenant,
            authority_id,
            identity_digest,
            app_configuration_revision,
            policy_revision,
        }
    }

    /// Returns the authenticated tenant.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }
    /// Returns the durable descriptor ID.
    #[must_use]
    pub const fn authority_id(&self) -> GithubServerServiceAuthorityId {
        self.authority_id
    }
    /// Returns the digest of every immutable descriptor field.
    #[must_use]
    pub const fn identity_digest(&self) -> Sha256Digest {
        self.identity_digest
    }
    /// Returns the expected App configuration revision.
    #[must_use]
    pub const fn app_configuration_revision(&self) -> GithubServerServiceRevision {
        self.app_configuration_revision
    }
    /// Returns the expected fixed policy revision.
    #[must_use]
    pub const fn policy_revision(&self) -> GithubServerServiceRevision {
        self.policy_revision
    }

    pub(crate) fn matches(&self, identity: &GithubServerServiceAuthorityIdentity) -> bool {
        self.tenant == *identity.tenant()
            && self.authority_id == identity.authority_id()
            && self.identity_digest == identity.identity_digest()
            && self.app_configuration_revision == identity.app_configuration_revision()
            && self.policy_revision == identity.policy_revision()
    }
}

/// Durable lifecycle of an authority descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubServerServiceAuthorityState {
    /// New issuances and handoffs are permitted.
    Active,
    /// New handoffs and mints are closed while retained credentials retire.
    Retiring,
    /// Every generation is terminal and protected custody is erased.
    Retired,
}

impl GithubServerServiceAuthorityState {
    pub(crate) fn from_durable(value: &str) -> Result<Self, GithubServerServiceValueError> {
        match value {
            "active" => Ok(Self::Active),
            "retiring" => Ok(Self::Retiring),
            "retired" => Ok(Self::Retired),
            _ => Err(GithubServerServiceValueError::InvalidAuthorityDescriptor),
        }
    }
}

/// Complete descriptor including its mutable lifecycle pointers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubServerServiceAuthorityDescriptor {
    identity: GithubServerServiceAuthorityIdentity,
    state: GithubServerServiceAuthorityState,
    current_generation: Option<GithubServerServiceGeneration>,
    refresh_generation: Option<GithubServerServiceGeneration>,
    next_generation: GithubServerServiceGeneration,
    consecutive_generation_failures: u16,
    next_mint_not_before: Option<UnixMillis>,
    mint_gate_generation: Option<GithubServerServiceGeneration>,
    failure_budget_rearm_at: Option<UnixMillis>,
    created_at: UnixMillis,
    state_updated_at: UnixMillis,
}

impl GithubServerServiceAuthorityDescriptor {
    /// Rehydrates a descriptor returned by durable storage.
    ///
    /// # Errors
    ///
    /// Rejects invalid timestamps or pointer/state combinations.
    #[allow(clippy::too_many_arguments)]
    pub fn from_durable_parts(
        identity: GithubServerServiceAuthorityIdentity,
        state: GithubServerServiceAuthorityState,
        current_generation: Option<GithubServerServiceGeneration>,
        refresh_generation: Option<GithubServerServiceGeneration>,
        next_generation: GithubServerServiceGeneration,
        consecutive_generation_failures: u16,
        next_mint_not_before: Option<UnixMillis>,
        mint_gate_generation: Option<GithubServerServiceGeneration>,
        failure_budget_rearm_at: Option<UnixMillis>,
        created_at: UnixMillis,
        state_updated_at: UnixMillis,
    ) -> Result<Self, GithubServerServiceValueError> {
        validate_timestamp(created_at)?;
        validate_timestamp(state_updated_at)?;
        if state_updated_at < created_at
            || current_generation.is_some() && current_generation == refresh_generation
            || current_generation.is_some_and(|generation| generation >= next_generation)
            || refresh_generation.is_some_and(|generation| generation >= next_generation)
            || consecutive_generation_failures > MAX_GITHUB_SERVICE_CONSECUTIVE_GENERATION_FAILURES
            || (consecutive_generation_failures == 0) != next_mint_not_before.is_none()
            || (consecutive_generation_failures == 0) != mint_gate_generation.is_none()
            || (consecutive_generation_failures
                == MAX_GITHUB_SERVICE_CONSECUTIVE_GENERATION_FAILURES)
                != failure_budget_rearm_at.is_some()
            || mint_gate_generation.is_some_and(|generation| generation >= next_generation)
            || next_mint_not_before.is_some_and(|not_before| not_before < created_at)
            || failure_budget_rearm_at.is_some_and(|rearm_at| rearm_at < created_at)
            || state != GithubServerServiceAuthorityState::Active
                && (current_generation.is_some() || refresh_generation.is_some())
        {
            return Err(GithubServerServiceValueError::InvalidAuthorityDescriptor);
        }
        Ok(Self {
            identity,
            state,
            current_generation,
            refresh_generation,
            next_generation,
            consecutive_generation_failures,
            next_mint_not_before,
            mint_gate_generation,
            failure_budget_rearm_at,
            created_at,
            state_updated_at,
        })
    }

    /// Returns immutable configured identity.
    #[must_use]
    pub const fn identity(&self) -> &GithubServerServiceAuthorityIdentity {
        &self.identity
    }
    /// Returns descriptor lifecycle.
    #[must_use]
    pub const fn state(&self) -> GithubServerServiceAuthorityState {
        self.state
    }
    /// Returns the generation currently eligible for handoff.
    #[must_use]
    pub const fn current_generation(&self) -> Option<GithubServerServiceGeneration> {
        self.current_generation
    }
    /// Returns the sole generation currently refreshing.
    #[must_use]
    pub const fn refresh_generation(&self) -> Option<GithubServerServiceGeneration> {
        self.refresh_generation
    }
    /// Returns the next never-used generation for restart-safe reservation.
    #[must_use]
    pub const fn next_generation(&self) -> GithubServerServiceGeneration {
        self.next_generation
    }
    /// Returns failed generations admitted since the last Ready credential.
    #[must_use]
    pub const fn consecutive_generation_failures(&self) -> u16 {
        self.consecutive_generation_failures
    }
    /// Returns the earliest trusted time another generation may be reserved.
    #[must_use]
    pub const fn next_mint_not_before(&self) -> Option<UnixMillis> {
        self.next_mint_not_before
    }
    /// Returns the generation whose retained evidence currently sets the mint gate.
    #[must_use]
    pub const fn mint_gate_generation(&self) -> Option<GithubServerServiceGeneration> {
        self.mint_gate_generation
    }
    /// Returns the cooldown boundary for a saturated authority-level breaker.
    #[must_use]
    pub const fn failure_budget_rearm_at(&self) -> Option<UnixMillis> {
        self.failure_budget_rearm_at
    }
    /// Returns descriptor creation time.
    #[must_use]
    pub const fn created_at(&self) -> UnixMillis {
        self.created_at
    }
    /// Returns last lifecycle-change time.
    #[must_use]
    pub const fn state_updated_at(&self) -> UnixMillis {
        self.state_updated_at
    }
}

/// Idempotent request to create one immutable authority descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnsureGithubServerServiceAuthority {
    identity: GithubServerServiceAuthorityIdentity,
    created_at: UnixMillis,
}

impl EnsureGithubServerServiceAuthority {
    /// Constructs an exact descriptor creation request.
    ///
    /// # Errors
    ///
    /// Rejects a pre-epoch timestamp.
    pub fn new(
        identity: GithubServerServiceAuthorityIdentity,
        created_at: UnixMillis,
    ) -> Result<Self, GithubServerServiceValueError> {
        validate_timestamp(created_at)?;
        Ok(Self {
            identity,
            created_at,
        })
    }
    /// Returns immutable configured identity.
    #[must_use]
    pub const fn identity(&self) -> &GithubServerServiceAuthorityIdentity {
        &self.identity
    }
    /// Returns descriptor creation time.
    #[must_use]
    pub const fn created_at(&self) -> UnixMillis {
        self.created_at
    }
}

/// Stable key of one issuance generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubServerServiceIssuanceKey {
    authority_id: GithubServerServiceAuthorityId,
    generation: GithubServerServiceGeneration,
}

impl GithubServerServiceIssuanceKey {
    /// Constructs an issuance key.
    #[must_use]
    pub const fn new(
        authority_id: GithubServerServiceAuthorityId,
        generation: GithubServerServiceGeneration,
    ) -> Self {
        Self {
            authority_id,
            generation,
        }
    }
    /// Returns the descriptor ID.
    #[must_use]
    pub const fn authority_id(self) -> GithubServerServiceAuthorityId {
        self.authority_id
    }
    /// Returns the immutable generation.
    #[must_use]
    pub const fn generation(self) -> GithubServerServiceGeneration {
        self.generation
    }
}

/// Durable issuance lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubServerServiceIssuanceState {
    /// One worker owns a pre-mint reservation.
    Claimed,
    /// The irreversible durable start was recorded before provider I/O.
    Minting,
    /// A definitive no-token result is eligible for bounded retry.
    MintRetryPending,
    /// Provider issuance may have occurred; remint is permanently forbidden.
    Indeterminate,
    /// Protected credential is the descriptor's current generation.
    Ready,
    /// Credential awaits revocation after rotation or retirement.
    RevokePending,
    /// One worker owns the revocation call.
    RevokeClaimed,
    /// A failed revocation is eligible for bounded retry.
    RevokeRetryPending,
    /// Protected custody is corrupt and closed until safe erasure.
    Quarantined,
    /// Provider mint definitively produced no credential.
    Rejected,
    /// Provider revocation or conservative expiry permits erased custody.
    Revoked,
}

impl GithubServerServiceIssuanceState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Claimed => "claimed",
            Self::Minting => "minting",
            Self::MintRetryPending => "mint_retry",
            Self::Indeterminate => "indeterminate",
            Self::Ready => "ready",
            Self::RevokePending => "revoke_pending",
            Self::RevokeClaimed => "revoke_claimed",
            Self::RevokeRetryPending => "revoke_retry",
            Self::Quarantined => "quarantined",
            Self::Rejected => "rejected",
            Self::Revoked => "revoked",
        }
    }

    pub(crate) fn from_durable(value: &str) -> Result<Self, GithubServerServiceValueError> {
        match value {
            "claimed" => Ok(Self::Claimed),
            "minting" => Ok(Self::Minting),
            "mint_retry" => Ok(Self::MintRetryPending),
            "indeterminate" => Ok(Self::Indeterminate),
            "ready" => Ok(Self::Ready),
            "revoke_pending" => Ok(Self::RevokePending),
            "revoke_claimed" => Ok(Self::RevokeClaimed),
            "revoke_retry" => Ok(Self::RevokeRetryPending),
            "quarantined" => Ok(Self::Quarantined),
            "rejected" => Ok(Self::Rejected),
            "revoked" => Ok(Self::Revoked),
            _ => Err(GithubServerServiceValueError::InvalidIssuanceReceipt),
        }
    }
}

/// Value-free durable issuance projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubServerServiceIssuanceReceipt {
    key: GithubServerServiceIssuanceKey,
    state: GithubServerServiceIssuanceState,
    mint_attempts: u16,
    revoke_attempts: u16,
    requested_at: UnixMillis,
    request_deadline: UnixMillis,
    conservative_expiry: UnixMillis,
    provider_expires_at: Option<UnixMillis>,
    safe_erase_after: UnixMillis,
    ready_at: Option<UnixMillis>,
    state_updated_at: UnixMillis,
}

impl GithubServerServiceIssuanceReceipt {
    /// Rehydrates a value-free issuance projection.
    ///
    /// # Errors
    ///
    /// Rejects inconsistent attempt counters, time bounds, or expiry evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn from_durable_parts(
        key: GithubServerServiceIssuanceKey,
        state: GithubServerServiceIssuanceState,
        mint_attempts: u16,
        revoke_attempts: u16,
        requested_at: UnixMillis,
        request_deadline: UnixMillis,
        conservative_expiry: UnixMillis,
        provider_expires_at: Option<UnixMillis>,
        safe_erase_after: UnixMillis,
        ready_at: Option<UnixMillis>,
        state_updated_at: UnixMillis,
    ) -> Result<Self, GithubServerServiceValueError> {
        for value in [
            requested_at,
            request_deadline,
            conservative_expiry,
            safe_erase_after,
            state_updated_at,
        ] {
            validate_timestamp(value)?;
        }
        if mint_attempts == 0
            || mint_attempts > MAX_GITHUB_SERVICE_MINT_ATTEMPTS
            || revoke_attempts > MAX_GITHUB_SERVICE_REVOKE_ATTEMPTS
            || request_deadline <= requested_at
            || request_deadline.get() - requested_at.get() > MAX_GITHUB_SERVICE_REQUEST_MILLIS
            || conservative_expiry != derive_conservative_expiry(request_deadline)?
            || safe_erase_after > conservative_expiry
            || state_updated_at < requested_at
            || ready_at
                .is_some_and(|ready_at| ready_at < requested_at || ready_at > state_updated_at)
            || (state == GithubServerServiceIssuanceState::Ready
                && ready_at != Some(state_updated_at))
            || matches!(
                state,
                GithubServerServiceIssuanceState::Claimed
                    | GithubServerServiceIssuanceState::Minting
                    | GithubServerServiceIssuanceState::MintRetryPending
                    | GithubServerServiceIssuanceState::Indeterminate
                    | GithubServerServiceIssuanceState::Rejected
            ) && ready_at.is_some()
        {
            return Err(GithubServerServiceValueError::InvalidIssuanceReceipt);
        }
        if let Some(provider_expiry) = provider_expires_at {
            validate_provider_expiry(requested_at, request_deadline, provider_expiry)?;
            if safe_erase_after
                != add_millis(provider_expiry, GITHUB_SERVICE_SAFE_ERASE_SKEW_MILLIS)?
            {
                return Err(GithubServerServiceValueError::InvalidIssuanceReceipt);
            }
        } else if safe_erase_after != conservative_expiry {
            return Err(GithubServerServiceValueError::InvalidIssuanceReceipt);
        }
        Ok(Self {
            key,
            state,
            mint_attempts,
            revoke_attempts,
            requested_at,
            request_deadline,
            conservative_expiry,
            provider_expires_at,
            safe_erase_after,
            ready_at,
            state_updated_at,
        })
    }
    /// Returns the immutable issuance key.
    #[must_use]
    pub const fn key(self) -> GithubServerServiceIssuanceKey {
        self.key
    }
    /// Returns lifecycle state.
    #[must_use]
    pub const fn state(self) -> GithubServerServiceIssuanceState {
        self.state
    }
    /// Returns provider mint attempt count.
    #[must_use]
    pub const fn mint_attempts(self) -> u16 {
        self.mint_attempts
    }
    /// Returns provider revocation attempt count.
    #[must_use]
    pub const fn revoke_attempts(self) -> u16 {
        self.revoke_attempts
    }
    /// Returns original request time.
    #[must_use]
    pub const fn requested_at(self) -> UnixMillis {
        self.requested_at
    }
    /// Returns fixed provider request deadline.
    #[must_use]
    pub const fn request_deadline(self) -> UnixMillis {
        self.request_deadline
    }
    /// Returns fixed maximum uncertainty horizon.
    #[must_use]
    pub const fn conservative_expiry(self) -> UnixMillis {
        self.conservative_expiry
    }
    /// Returns provider-reported expiry when a response was committed.
    #[must_use]
    pub const fn provider_expires_at(self) -> Option<UnixMillis> {
        self.provider_expires_at
    }
    /// Returns earliest safe protected-custody erasure time.
    #[must_use]
    pub const fn safe_erase_after(self) -> UnixMillis {
        self.safe_erase_after
    }
    /// Returns the immutable time this generation first became Ready.
    #[must_use]
    pub const fn ready_at(self) -> Option<UnixMillis> {
        self.ready_at
    }
    /// Returns last state change.
    #[must_use]
    pub const fn state_updated_at(self) -> UnixMillis {
        self.state_updated_at
    }
    /// Returns the exclusive conservative provider-use horizon.
    #[must_use]
    pub fn usable_until(self) -> Option<UnixMillis> {
        self.provider_expires_at.and_then(|expiry| {
            expiry
                .get()
                .checked_sub(GITHUB_SERVICE_PROVIDER_CLOCK_SKEW_MILLIS)
                .map(UnixMillis::new)
        })
    }
}

/// Exact owner/fence proof for a mint or revocation claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubServerServiceClaim {
    selector: GithubServerServiceAuthoritySelector,
    key: GithubServerServiceIssuanceKey,
    worker: GithubServerServiceWorkerId,
    fence: GithubServerServiceClaimFence,
}

impl GithubServerServiceClaim {
    /// Rehydrates an exact claim proof.
    ///
    /// # Errors
    ///
    /// Rejects a claim whose issuance belongs to another authority.
    pub fn from_durable_parts(
        selector: GithubServerServiceAuthoritySelector,
        key: GithubServerServiceIssuanceKey,
        worker: GithubServerServiceWorkerId,
        fence: GithubServerServiceClaimFence,
    ) -> Result<Self, GithubServerServiceValueError> {
        if selector.authority_id() != key.authority_id() {
            return Err(GithubServerServiceValueError::InvalidClaim);
        }
        Ok(Self {
            selector,
            key,
            worker,
            fence,
        })
    }
    /// Returns the exact immutable descriptor selector.
    #[must_use]
    pub const fn selector(&self) -> &GithubServerServiceAuthoritySelector {
        &self.selector
    }
    /// Returns issuance key.
    #[must_use]
    pub const fn key(&self) -> GithubServerServiceIssuanceKey {
        self.key
    }
    /// Returns worker identity.
    #[must_use]
    pub const fn worker(&self) -> GithubServerServiceWorkerId {
        self.worker
    }
    /// Returns monotonic claim fence.
    #[must_use]
    pub const fn fence(&self) -> GithubServerServiceClaimFence {
        self.fence
    }
}

/// Complete immutable evidence returned under a mint claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedGithubServerServiceMint {
    identity: GithubServerServiceAuthorityIdentity,
    receipt: GithubServerServiceIssuanceReceipt,
    claim: GithubServerServiceClaim,
    claimed_at: UnixMillis,
    claim_expires_at: UnixMillis,
}

impl ClaimedGithubServerServiceMint {
    /// Rehydrates an exact live mint claim.
    ///
    /// # Errors
    ///
    /// Rejects mismatched descriptor, state, fence, or claim interval.
    pub fn from_durable_parts(
        identity: GithubServerServiceAuthorityIdentity,
        receipt: GithubServerServiceIssuanceReceipt,
        claim: GithubServerServiceClaim,
        claimed_at: UnixMillis,
        claim_expires_at: UnixMillis,
    ) -> Result<Self, GithubServerServiceValueError> {
        validate_claim_interval(
            claimed_at,
            claim_expires_at,
            MAX_GITHUB_SERVICE_MINT_CLAIM_MILLIS,
        )?;
        if receipt.state() != GithubServerServiceIssuanceState::Claimed
            || receipt.key() != claim.key()
            || !claim.selector().matches(&identity)
            || identity.authority_id() != claim.key().authority_id()
            || claimed_at != receipt.state_updated_at()
            || claimed_at < receipt.requested_at()
            || claim_expires_at > receipt.request_deadline()
        {
            return Err(GithubServerServiceValueError::InvalidClaim);
        }
        Ok(Self {
            identity,
            receipt,
            claim,
            claimed_at,
            claim_expires_at,
        })
    }
    /// Returns immutable descriptor identity.
    #[must_use]
    pub const fn identity(&self) -> &GithubServerServiceAuthorityIdentity {
        &self.identity
    }
    /// Returns value-free issuance projection.
    #[must_use]
    pub const fn receipt(&self) -> GithubServerServiceIssuanceReceipt {
        self.receipt
    }
    /// Returns exact mint claim proof.
    #[must_use]
    pub const fn claim(&self) -> &GithubServerServiceClaim {
        &self.claim
    }
    /// Returns claim acquisition time.
    #[must_use]
    pub const fn claimed_at(&self) -> UnixMillis {
        self.claimed_at
    }
    /// Returns exclusive claim expiry.
    #[must_use]
    pub const fn claim_expires_at(&self) -> UnixMillis {
        self.claim_expires_at
    }
}

/// Starts a new initial or refresh generation under one descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimGithubServerServiceMint {
    selector: GithubServerServiceAuthoritySelector,
    generation: GithubServerServiceGeneration,
    worker: GithubServerServiceWorkerId,
    requested_at: UnixMillis,
    request_deadline: UnixMillis,
    claim_expires_at: UnixMillis,
}

impl ClaimGithubServerServiceMint {
    /// Constructs a bounded new-generation claim.
    ///
    /// # Errors
    ///
    /// Rejects invalid provider-request or claim intervals.
    pub fn new(
        selector: GithubServerServiceAuthoritySelector,
        generation: GithubServerServiceGeneration,
        worker: GithubServerServiceWorkerId,
        requested_at: UnixMillis,
        request_deadline: UnixMillis,
        claim_expires_at: UnixMillis,
    ) -> Result<Self, GithubServerServiceValueError> {
        validate_claim_interval(
            requested_at,
            claim_expires_at,
            MAX_GITHUB_SERVICE_MINT_CLAIM_MILLIS,
        )?;
        validate_request_interval(requested_at, request_deadline)?;
        if claim_expires_at > request_deadline {
            return Err(GithubServerServiceValueError::InvalidTimeInterval);
        }
        Ok(Self {
            selector,
            generation,
            worker,
            requested_at,
            request_deadline,
            claim_expires_at,
        })
    }
    /// Returns the exact immutable descriptor selector.
    #[must_use]
    pub const fn selector(&self) -> &GithubServerServiceAuthoritySelector {
        &self.selector
    }
    /// Returns descriptor ID.
    #[must_use]
    pub const fn authority_id(&self) -> GithubServerServiceAuthorityId {
        self.selector.authority_id()
    }
    /// Returns the caller-pinned next generation for exact lost-response replay.
    #[must_use]
    pub const fn generation(&self) -> GithubServerServiceGeneration {
        self.generation
    }
    /// Returns claiming worker.
    #[must_use]
    pub const fn worker(&self) -> GithubServerServiceWorkerId {
        self.worker
    }
    /// Returns trusted request time.
    #[must_use]
    pub const fn requested_at(&self) -> UnixMillis {
        self.requested_at
    }
    /// Returns fixed provider deadline.
    #[must_use]
    pub const fn request_deadline(&self) -> UnixMillis {
        self.request_deadline
    }
    /// Returns exclusive claim expiry.
    #[must_use]
    pub const fn claim_expires_at(&self) -> UnixMillis {
        self.claim_expires_at
    }
}

/// Reclaims a definitively unissued retry generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReclaimGithubServerServiceMint {
    selector: GithubServerServiceAuthoritySelector,
    key: GithubServerServiceIssuanceKey,
    worker: GithubServerServiceWorkerId,
    observed_at: UnixMillis,
    claim_expires_at: UnixMillis,
}

impl ReclaimGithubServerServiceMint {
    /// Constructs a bounded retry claim.
    ///
    /// # Errors
    ///
    /// Rejects an invalid claim interval.
    pub fn new(
        selector: GithubServerServiceAuthoritySelector,
        key: GithubServerServiceIssuanceKey,
        worker: GithubServerServiceWorkerId,
        observed_at: UnixMillis,
        claim_expires_at: UnixMillis,
    ) -> Result<Self, GithubServerServiceValueError> {
        validate_claim_interval(
            observed_at,
            claim_expires_at,
            MAX_GITHUB_SERVICE_MINT_CLAIM_MILLIS,
        )?;
        if selector.authority_id() != key.authority_id() {
            return Err(GithubServerServiceValueError::InvalidClaim);
        }
        Ok(Self {
            selector,
            key,
            worker,
            observed_at,
            claim_expires_at,
        })
    }
    /// Returns the exact immutable descriptor selector.
    #[must_use]
    pub const fn selector(&self) -> &GithubServerServiceAuthoritySelector {
        &self.selector
    }
    /// Returns issuance key.
    #[must_use]
    pub const fn key(&self) -> GithubServerServiceIssuanceKey {
        self.key
    }
    /// Returns claiming worker.
    #[must_use]
    pub const fn worker(&self) -> GithubServerServiceWorkerId {
        self.worker
    }
    /// Returns trusted observation.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
    /// Returns exclusive claim expiry.
    #[must_use]
    pub const fn claim_expires_at(&self) -> UnixMillis {
        self.claim_expires_at
    }
}

/// Irreversible durable mint-start boundary recorded before provider I/O.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeginGithubServerServiceMint {
    claim: GithubServerServiceClaim,
    claimed_at: UnixMillis,
    claim_expires_at: UnixMillis,
    request_deadline: UnixMillis,
    started_at: UnixMillis,
}

impl BeginGithubServerServiceMint {
    /// Constructs a mint-start transition.
    ///
    /// # Errors
    ///
    /// Rejects a pre-epoch start time.
    pub fn new(
        claimed: &ClaimedGithubServerServiceMint,
        started_at: UnixMillis,
    ) -> Result<Self, GithubServerServiceValueError> {
        validate_timestamp(started_at)?;
        if started_at < claimed.claimed_at()
            || started_at >= claimed.claim_expires_at()
            || started_at >= claimed.receipt().request_deadline()
        {
            return Err(GithubServerServiceValueError::InvalidTimeInterval);
        }
        Ok(Self {
            claim: claimed.claim().clone(),
            claimed_at: claimed.claimed_at(),
            claim_expires_at: claimed.claim_expires_at(),
            request_deadline: claimed.receipt().request_deadline(),
            started_at,
        })
    }
    /// Returns exact claim proof.
    #[must_use]
    pub const fn claim(&self) -> &GithubServerServiceClaim {
        &self.claim
    }
    /// Returns the durable claim acquisition time.
    #[must_use]
    pub const fn claimed_at(&self) -> UnixMillis {
        self.claimed_at
    }
    /// Returns the exclusive durable claim expiry.
    #[must_use]
    pub const fn claim_expires_at(&self) -> UnixMillis {
        self.claim_expires_at
    }
    /// Returns the exclusive fixed provider request deadline.
    #[must_use]
    pub const fn request_deadline(&self) -> UnixMillis {
        self.request_deadline
    }
    /// Returns durable provider-call cutoff.
    #[must_use]
    pub const fn started_at(&self) -> UnixMillis {
        self.started_at
    }
}

/// Exact durable cutoff evidence returned when mint start is attempted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubServerServiceMintStart {
    claim: GithubServerServiceClaim,
    receipt: GithubServerServiceIssuanceReceipt,
    claim_expires_at: UnixMillis,
    request_deadline: UnixMillis,
    started_at: UnixMillis,
}

impl GithubServerServiceMintStart {
    pub(crate) fn from_request(
        request: &BeginGithubServerServiceMint,
        receipt: GithubServerServiceIssuanceReceipt,
    ) -> Result<Self, GithubServerServiceValueError> {
        if receipt.key() != request.claim().key()
            || receipt.state() != GithubServerServiceIssuanceState::Minting
            || receipt.request_deadline() != request.request_deadline()
            || receipt.state_updated_at() != request.started_at()
        {
            return Err(GithubServerServiceValueError::InvalidClaim);
        }
        Ok(Self {
            claim: request.claim().clone(),
            receipt,
            claim_expires_at: request.claim_expires_at(),
            request_deadline: request.request_deadline(),
            started_at: request.started_at(),
        })
    }
    /// Returns the exact descriptor/owner/fence proof.
    #[must_use]
    pub const fn claim(&self) -> &GithubServerServiceClaim {
        &self.claim
    }
    /// Returns the durable minting receipt.
    #[must_use]
    pub const fn receipt(&self) -> GithubServerServiceIssuanceReceipt {
        self.receipt
    }
    /// Returns the exclusive claim deadline for a final monotonic recheck.
    #[must_use]
    pub const fn claim_expires_at(&self) -> UnixMillis {
        self.claim_expires_at
    }
    /// Returns the exclusive provider request deadline.
    #[must_use]
    pub const fn request_deadline(&self) -> UnixMillis {
        self.request_deadline
    }
    /// Returns the durable irreversible cutoff time.
    #[must_use]
    pub const fn started_at(&self) -> UnixMillis {
        self.started_at
    }
}

/// Result of attempting the irreversible mint cutoff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BeginGithubServerServiceMintOutcome {
    /// This caller committed the cutoff and alone may begin one provider POST.
    Started(GithubServerServiceMintStart),
    /// The cutoff already existed; provider I/O must never be repeated.
    AlreadyStarted(GithubServerServiceMintStart),
}

/// Reconciles a mint whose durable claim or provider deadline expired.
///
/// A pre-provider [`GithubServerServiceIssuanceState::Claimed`] or definitively
/// unissued [`GithubServerServiceIssuanceState::MintRetryPending`] generation
/// is rejected. A post-cutoff [`GithubServerServiceIssuanceState::Minting`]
/// generation becomes indeterminate and can never be reminted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconcileExpiredGithubServerServiceMint {
    selector: GithubServerServiceAuthoritySelector,
    key: GithubServerServiceIssuanceKey,
    observed_at: UnixMillis,
}

impl ReconcileExpiredGithubServerServiceMint {
    /// Constructs a trusted stale-mint reconciliation request.
    ///
    /// # Errors
    ///
    /// Rejects a pre-epoch observation.
    pub fn new(
        selector: GithubServerServiceAuthoritySelector,
        key: GithubServerServiceIssuanceKey,
        observed_at: UnixMillis,
    ) -> Result<Self, GithubServerServiceValueError> {
        validate_timestamp(observed_at)?;
        if selector.authority_id() != key.authority_id() {
            return Err(GithubServerServiceValueError::InvalidClaim);
        }
        Ok(Self {
            selector,
            key,
            observed_at,
        })
    }
    /// Returns the exact immutable descriptor selector.
    #[must_use]
    pub const fn selector(&self) -> &GithubServerServiceAuthoritySelector {
        &self.selector
    }
    /// Returns the exact issuance key.
    #[must_use]
    pub const fn key(&self) -> GithubServerServiceIssuanceKey {
        self.key
    }
    /// Returns the trusted reconciliation observation.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
}

/// Canonical provider or cryptographic failure class with no credential data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubServerServiceFailureKind(String);

impl GithubServerServiceFailureKind {
    /// Constructs a bounded canonical machine failure class.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or noncanonical values.
    pub fn new(value: impl Into<String>) -> Result<Self, GithubServerServiceValueError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_FAILURE_KIND_BYTES
            && value.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || (index > 0 && matches!(byte, b'_' | b'-' | b'.' | b':'))
            })
            && value
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric);
        if !valid {
            return Err(GithubServerServiceValueError::InvalidFailureKind);
        }
        Ok(Self(value))
    }
    /// Returns sanitized machine failure class.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Authenticated metadata paired with one protected provider credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubServerServiceEnvelopeMetadata {
    identity: GithubServerServiceAuthorityIdentity,
    generation: GithubServerServiceGeneration,
    requested_at: UnixMillis,
    request_deadline: UnixMillis,
    provider_expires_at: Option<UnixMillis>,
    safe_erase_after: UnixMillis,
    plaintext_schema: NonZeroU16,
    plaintext_size_bytes: u64,
    plaintext_digest: Sha256Digest,
    aad_digest: Sha256Digest,
}

impl GithubServerServiceEnvelopeMetadata {
    /// Constructs the exact current protected-payload contract.
    ///
    /// # Errors
    ///
    /// Rejects provider expiry outside the fixed request horizon or invalid
    /// plaintext shape.
    pub fn new(
        identity: GithubServerServiceAuthorityIdentity,
        generation: GithubServerServiceGeneration,
        requested_at: UnixMillis,
        request_deadline: UnixMillis,
        provider_expires_at: UnixMillis,
        plaintext_size_bytes: u64,
        plaintext_digest: Sha256Digest,
    ) -> Result<Self, GithubServerServiceValueError> {
        validate_request_interval(requested_at, request_deadline)?;
        validate_provider_expiry(requested_at, request_deadline, provider_expires_at)?;
        let safe_erase_after =
            add_millis(provider_expires_at, GITHUB_SERVICE_SAFE_ERASE_SKEW_MILLIS)?;
        Self::build(
            identity,
            generation,
            requested_at,
            request_deadline,
            Some(provider_expires_at),
            safe_erase_after,
            plaintext_size_bytes,
            plaintext_digest,
        )
    }

    /// Constructs protected revoke-only custody when GitHub returned one
    /// unique token but no trustworthy provider expiry.
    ///
    /// The credential can never become current or enter a handoff. Its
    /// authenticated erasure horizon is the fixed conservative request expiry.
    ///
    /// # Errors
    ///
    /// Rejects an invalid request interval or plaintext shape.
    pub fn unknown_provider_expiry(
        identity: GithubServerServiceAuthorityIdentity,
        generation: GithubServerServiceGeneration,
        requested_at: UnixMillis,
        request_deadline: UnixMillis,
        plaintext_size_bytes: u64,
        plaintext_digest: Sha256Digest,
    ) -> Result<Self, GithubServerServiceValueError> {
        validate_request_interval(requested_at, request_deadline)?;
        let safe_erase_after = derive_conservative_expiry(request_deadline)?;
        Self::build(
            identity,
            generation,
            requested_at,
            request_deadline,
            None,
            safe_erase_after,
            plaintext_size_bytes,
            plaintext_digest,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        identity: GithubServerServiceAuthorityIdentity,
        generation: GithubServerServiceGeneration,
        requested_at: UnixMillis,
        request_deadline: UnixMillis,
        provider_expires_at: Option<UnixMillis>,
        safe_erase_after: UnixMillis,
        plaintext_size_bytes: u64,
        plaintext_digest: Sha256Digest,
    ) -> Result<Self, GithubServerServiceValueError> {
        if plaintext_size_bytes == 0 || plaintext_size_bytes > MAX_GITHUB_SERVICE_PLAINTEXT_BYTES {
            return Err(GithubServerServiceValueError::InvalidProtectedPayload);
        }
        if safe_erase_after > derive_conservative_expiry(request_deadline)? {
            return Err(GithubServerServiceValueError::InvalidProviderExpiry);
        }
        let plaintext_schema = NonZeroU16::new(PROTECTED_PLAINTEXT_SCHEMA)
            .ok_or(GithubServerServiceValueError::InvalidProtectedPayload)?;
        let aad_digest = compute_aad_digest(
            &identity,
            generation,
            requested_at,
            request_deadline,
            provider_expires_at,
            safe_erase_after,
            plaintext_schema.get(),
            plaintext_size_bytes,
            plaintext_digest,
        );
        Ok(Self {
            identity,
            generation,
            requested_at,
            request_deadline,
            provider_expires_at,
            safe_erase_after,
            plaintext_schema,
            plaintext_size_bytes,
            plaintext_digest,
            aad_digest,
        })
    }
    /// Returns immutable descriptor identity.
    #[must_use]
    pub const fn identity(&self) -> &GithubServerServiceAuthorityIdentity {
        &self.identity
    }
    /// Returns issuance generation.
    #[must_use]
    pub const fn generation(&self) -> GithubServerServiceGeneration {
        self.generation
    }
    /// Returns the immutable provider-request anchor.
    #[must_use]
    pub const fn requested_at(&self) -> UnixMillis {
        self.requested_at
    }
    /// Returns the immutable provider-request deadline.
    #[must_use]
    pub const fn request_deadline(&self) -> UnixMillis {
        self.request_deadline
    }
    /// Returns provider-reported expiry.
    #[must_use]
    pub const fn provider_expires_at(&self) -> Option<UnixMillis> {
        self.provider_expires_at
    }
    /// Returns safe erasure horizon.
    #[must_use]
    pub const fn safe_erase_after(&self) -> UnixMillis {
        self.safe_erase_after
    }
    /// Returns protected plaintext schema.
    #[must_use]
    pub const fn plaintext_schema(&self) -> u16 {
        self.plaintext_schema.get()
    }
    /// Returns protected plaintext byte length.
    #[must_use]
    pub const fn plaintext_size_bytes(&self) -> u64 {
        self.plaintext_size_bytes
    }
    /// Returns protected plaintext digest.
    #[must_use]
    pub const fn plaintext_digest(&self) -> Sha256Digest {
        self.plaintext_digest
    }
    /// Returns digest of every payload AAD field.
    #[must_use]
    pub const fn aad_digest(&self) -> Sha256Digest {
        self.aad_digest
    }
    /// Returns exclusive credential-use horizon.
    #[must_use]
    pub fn usable_until(&self) -> Option<UnixMillis> {
        self.provider_expires_at.map(|provider_expires_at| {
            UnixMillis::new(provider_expires_at.get() - GITHUB_SERVICE_PROVIDER_CLOCK_SKEW_MILLIS)
        })
    }
    /// Builds the payload encryption context.
    ///
    /// # Errors
    ///
    /// Fails only if validated metadata cannot fit the key-management context.
    pub fn encryption_context(
        &self,
    ) -> Result<KeyEncryptionContext, GithubServerServiceValueError> {
        let purpose = KeyPurpose::new(PAYLOAD_PURPOSE)
            .map_err(|_| GithubServerServiceValueError::InvalidEncryptionContext)?;
        let record_id = format!(
            "github-server-service:v1:{}:{}:{}",
            self.identity.authority_id.as_uuid(),
            self.generation.get(),
            self.aad_digest
        );
        KeyEncryptionContext::new(self.identity.tenant.as_str(), purpose, record_id)
            .map_err(|_| GithubServerServiceValueError::InvalidEncryptionContext)
    }
}

/// Persistence-safe provider credential; plaintext is never present.
pub struct ProtectedGithubServerServiceCredential {
    metadata: GithubServerServiceEnvelopeMetadata,
    envelope: EncryptedEnvelope,
}

impl ProtectedGithubServerServiceCredential {
    /// Pairs exact authenticated metadata with its sealed envelope.
    ///
    /// # Errors
    ///
    /// Rejects a non-current envelope or inconsistent ciphertext length.
    pub fn new(
        metadata: GithubServerServiceEnvelopeMetadata,
        envelope: EncryptedEnvelope,
    ) -> Result<Self, GithubServerServiceValueError> {
        let expected = metadata
            .plaintext_size_bytes
            .checked_add(16)
            .ok_or(GithubServerServiceValueError::InvalidProtectedPayload)?;
        if envelope.schema() != ENVELOPE_SCHEMA_V1
            || u64::try_from(envelope.ciphertext().len()).ok() != Some(expected)
        {
            return Err(GithubServerServiceValueError::InvalidProtectedEnvelope);
        }
        Ok(Self { metadata, envelope })
    }
    /// Returns authenticated value-free metadata.
    #[must_use]
    pub const fn metadata(&self) -> &GithubServerServiceEnvelopeMetadata {
        &self.metadata
    }
    /// Returns sealed persistence-safe envelope.
    #[must_use]
    pub const fn envelope(&self) -> &EncryptedEnvelope {
        &self.envelope
    }
}

impl std::fmt::Debug for ProtectedGithubServerServiceCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProtectedGithubServerServiceCredential")
            .field("metadata", &self.metadata)
            .field("envelope", &"[PROTECTED]")
            .finish()
    }
}

/// Closed result of a provider mint started under an exact claim.
#[derive(Debug)]
pub enum FinishGithubServerServiceMint {
    /// Exact provider response was protected and may become current.
    Ready {
        claim: GithubServerServiceClaim,
        protected: ProtectedGithubServerServiceCredential,
        committed_at: UnixMillis,
    },
    /// A known issued credential is retained only for revocation/expiry.
    RevokeOnly {
        claim: GithubServerServiceClaim,
        protected: ProtectedGithubServerServiceCredential,
        committed_at: UnixMillis,
    },
    /// Provider proved no token was issued and bounded retry is safe.
    Retry {
        claim: GithubServerServiceClaim,
        failure: GithubServerServiceFailureKind,
        observed_at: UnixMillis,
        retry_at: UnixMillis,
    },
    /// Provider outcome is ambiguous; this generation can never remint.
    Indeterminate {
        claim: GithubServerServiceClaim,
        failure: GithubServerServiceFailureKind,
        observed_at: UnixMillis,
    },
    /// Provider definitively rejected issuance with no usable token.
    Rejected {
        claim: GithubServerServiceClaim,
        failure: GithubServerServiceFailureKind,
        observed_at: UnixMillis,
    },
}

impl FinishGithubServerServiceMint {
    /// Constructs a protected ready commit.
    ///
    /// # Errors
    ///
    /// Rejects metadata for a different issuance or an invalid commit time.
    pub fn ready(
        claim: GithubServerServiceClaim,
        protected: ProtectedGithubServerServiceCredential,
        committed_at: UnixMillis,
    ) -> Result<Self, GithubServerServiceValueError> {
        validate_timestamp(committed_at)?;
        if !claim.selector().matches(protected.metadata.identity())
            || protected.metadata.identity.authority_id != claim.key().authority_id()
            || protected.metadata.generation != claim.key().generation()
            || committed_at
                .get()
                .checked_add(MIN_GITHUB_SERVICE_READY_USE_MILLIS)
                .is_none_or(|required| {
                    protected
                        .metadata
                        .usable_until()
                        .is_none_or(|usable_until| usable_until.get() < required)
                })
        {
            return Err(GithubServerServiceValueError::InvalidCommit);
        }
        Ok(Self::Ready {
            claim,
            protected,
            committed_at,
        })
    }
    /// Constructs an exact protected revoke-only commit.
    ///
    /// This is used when a mint response is known after the original claim or
    /// authority became undeliverable, or when its conservative usable horizon
    /// is too short for current service use. It can never become current.
    ///
    /// # Errors
    ///
    /// Rejects different immutable identity/generation evidence or custody
    /// received only after its fixed safe-erasure horizon.
    pub fn issued_revoke_only(
        claim: GithubServerServiceClaim,
        protected: ProtectedGithubServerServiceCredential,
        committed_at: UnixMillis,
    ) -> Result<Self, GithubServerServiceValueError> {
        validate_timestamp(committed_at)?;
        if !claim.selector().matches(protected.metadata.identity())
            || protected.metadata.identity.authority_id != claim.key().authority_id()
            || protected.metadata.generation != claim.key().generation()
            || committed_at >= protected.metadata.safe_erase_after()
        {
            return Err(GithubServerServiceValueError::InvalidCommit);
        }
        Ok(Self::RevokeOnly {
            claim,
            protected,
            committed_at,
        })
    }
    /// Constructs a definitive no-token retry result.
    ///
    /// # Errors
    ///
    /// Rejects an invalid bounded retry interval.
    pub fn retry(
        claim: GithubServerServiceClaim,
        failure: GithubServerServiceFailureKind,
        observed_at: UnixMillis,
        retry_at: UnixMillis,
    ) -> Result<Self, GithubServerServiceValueError> {
        validate_retry_interval(observed_at, retry_at, MAX_GITHUB_SERVICE_MINT_RETRY_MILLIS)?;
        Ok(Self::Retry {
            claim,
            failure,
            observed_at,
            retry_at,
        })
    }
    /// Constructs an ambiguous provider outcome.
    ///
    /// # Errors
    ///
    /// Rejects a pre-epoch observation.
    pub fn indeterminate(
        claim: GithubServerServiceClaim,
        failure: GithubServerServiceFailureKind,
        observed_at: UnixMillis,
    ) -> Result<Self, GithubServerServiceValueError> {
        validate_timestamp(observed_at)?;
        Ok(Self::Indeterminate {
            claim,
            failure,
            observed_at,
        })
    }
    /// Constructs a definitive terminal no-token outcome.
    ///
    /// # Errors
    ///
    /// Rejects a pre-epoch observation.
    pub fn rejected(
        claim: GithubServerServiceClaim,
        failure: GithubServerServiceFailureKind,
        observed_at: UnixMillis,
    ) -> Result<Self, GithubServerServiceValueError> {
        validate_timestamp(observed_at)?;
        Ok(Self::Rejected {
            claim,
            failure,
            observed_at,
        })
    }
}

/// Closed consumer action authorized by a server-service handoff.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GithubServerServiceAction {
    /// Ensure one exact Check Suite.
    EnsureCheckSuite,
    /// Cross the durable Check Run create cutoff and issue its POST.
    CreateCheckRun,
    /// Reconcile one possibly-created Check Run.
    ReconcileCheckRun,
    /// Publish one exact desired Check Run revision.
    PublishCheckRun,
    /// Fetch one exact private repository revision.
    FetchPrivateRepositoryRevision,
    /// Fetch one exact private repository changed-file set.
    FetchPrivateRepositoryChangedFiles,
    /// Resolve schedules from one exact claimed private default-branch revision.
    DiscoverPrivateRepositorySchedules,
}

impl GithubServerServiceAction {
    /// Returns durable action discriminator.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EnsureCheckSuite => "ensure_check_suite",
            Self::CreateCheckRun => "create_check_run",
            Self::ReconcileCheckRun => "reconcile_check_run",
            Self::PublishCheckRun => "publish_check_run",
            Self::FetchPrivateRepositoryRevision => "fetch_private_repository_revision",
            Self::FetchPrivateRepositoryChangedFiles => "fetch_private_repository_changed_files",
            Self::DiscoverPrivateRepositorySchedules => "discover_private_repository_schedules",
        }
    }
    /// Returns the only credential scope allowed for this action.
    #[must_use]
    pub const fn required_scope(self) -> GithubServerServiceScope {
        match self {
            Self::EnsureCheckSuite
            | Self::CreateCheckRun
            | Self::ReconcileCheckRun
            | Self::PublishCheckRun => GithubServerServiceScope::ChecksWrite,
            Self::FetchPrivateRepositoryRevision
            | Self::FetchPrivateRepositoryChangedFiles
            | Self::DiscoverPrivateRepositorySchedules => {
                GithubServerServiceScope::PrivateRepositorySourceRead
            }
        }
    }
    /// Returns the largest derivative lease needed by this exact action.
    ///
    /// Check publication may issue two sequential bounded provider requests;
    /// every other current action issues at most one.
    #[must_use]
    pub const fn max_handoff_millis(self) -> i64 {
        15 * 60 * 1_000 + self.provider_tail_millis()
    }
    /// Returns the maximum provider-I/O tail after the owning claim expires.
    #[must_use]
    pub const fn provider_tail_millis(self) -> i64 {
        match self {
            Self::PublishCheckRun => 2 * MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS,
            Self::EnsureCheckSuite
            | Self::CreateCheckRun
            | Self::ReconcileCheckRun
            | Self::FetchPrivateRepositoryRevision
            | Self::FetchPrivateRepositoryChangedFiles
            | Self::DiscoverPrivateRepositorySchedules => {
                MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS
            }
        }
    }
    pub(crate) fn from_durable(value: &str) -> Result<Self, GithubServerServiceValueError> {
        match value {
            "ensure_check_suite" => Ok(Self::EnsureCheckSuite),
            "create_check_run" => Ok(Self::CreateCheckRun),
            "reconcile_check_run" => Ok(Self::ReconcileCheckRun),
            "publish_check_run" => Ok(Self::PublishCheckRun),
            "fetch_private_repository_revision" => Ok(Self::FetchPrivateRepositoryRevision),
            "fetch_private_repository_changed_files" => {
                Ok(Self::FetchPrivateRepositoryChangedFiles)
            }
            "discover_private_repository_schedules" => Ok(Self::DiscoverPrivateRepositorySchedules),
            _ => Err(GithubServerServiceValueError::InvalidAction),
        }
    }
}

/// Exact value-free consumer claim bound into one credential handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubServerServiceConsumerClaim {
    consumer_id: GithubServerServiceConsumerId,
    owner: GithubServerServiceWorkerId,
    fence: GithubServerServiceClaimFence,
    action: GithubServerServiceAction,
    revision: GithubServerServiceRevision,
}

impl GithubServerServiceConsumerClaim {
    /// Constructs exact consumer claim identity.
    #[must_use]
    pub const fn new(
        consumer_id: GithubServerServiceConsumerId,
        owner: GithubServerServiceWorkerId,
        fence: GithubServerServiceClaimFence,
        action: GithubServerServiceAction,
        revision: GithubServerServiceRevision,
    ) -> Self {
        Self {
            consumer_id,
            owner,
            fence,
            action,
            revision,
        }
    }
    /// Returns durable consumer work ID.
    #[must_use]
    pub const fn consumer_id(self) -> GithubServerServiceConsumerId {
        self.consumer_id
    }
    /// Returns consumer worker.
    #[must_use]
    pub const fn owner(self) -> GithubServerServiceWorkerId {
        self.owner
    }
    /// Returns consumer's own claim fence.
    #[must_use]
    pub const fn fence(self) -> GithubServerServiceClaimFence {
        self.fence
    }
    /// Returns exact provider action.
    #[must_use]
    pub const fn action(self) -> GithubServerServiceAction {
        self.action
    }
    /// Returns exact desired/work revision.
    #[must_use]
    pub const fn revision(self) -> GithubServerServiceRevision {
        self.revision
    }
}

/// Request to borrow the current protected credential for one exact claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquireGithubServerServiceHandoff {
    selector: GithubServerServiceAuthoritySelector,
    proposed_handoff_id: GithubServerServiceHandoffId,
    consumer: GithubServerServiceConsumerClaim,
    observed_at: UnixMillis,
    required_through: UnixMillis,
}

impl AcquireGithubServerServiceHandoff {
    /// Constructs a bounded exact-or-replay credential handoff.
    ///
    /// The proposed ID is used only when this exact consumer claim has no
    /// durable handoff. A lost-response retry may propose a fresh ID; storage
    /// returns the natural-key winner and its immutable original grant while
    /// revalidating the consumer at this request's trusted observation.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized handoff interval.
    pub fn new(
        selector: GithubServerServiceAuthoritySelector,
        handoff_id: GithubServerServiceHandoffId,
        consumer: GithubServerServiceConsumerClaim,
        observed_at: UnixMillis,
        required_through: UnixMillis,
    ) -> Result<Self, GithubServerServiceValueError> {
        validate_claim_interval(
            observed_at,
            required_through,
            consumer.action().max_handoff_millis(),
        )?;
        Ok(Self {
            selector,
            proposed_handoff_id: handoff_id,
            consumer,
            observed_at,
            required_through,
        })
    }
    /// Returns the exact immutable descriptor selector.
    #[must_use]
    pub const fn selector(&self) -> &GithubServerServiceAuthoritySelector {
        &self.selector
    }
    /// Returns descriptor ID.
    #[must_use]
    pub const fn authority_id(&self) -> GithubServerServiceAuthorityId {
        self.selector.authority_id()
    }
    /// Returns the ID proposed if this consumer has no durable handoff.
    #[must_use]
    pub const fn proposed_handoff_id(&self) -> GithubServerServiceHandoffId {
        self.proposed_handoff_id
    }
    /// Returns exact consumer claim.
    #[must_use]
    pub const fn consumer(&self) -> GithubServerServiceConsumerClaim {
        self.consumer
    }
    /// Returns trusted acquisition time.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
    /// Returns exclusive required credential lifetime.
    #[must_use]
    pub const fn required_through(&self) -> UnixMillis {
        self.required_through
    }
}

/// Protected credential plus its exact value-free consumer grant.
pub struct GithubServerServiceCredentialHandoff {
    handoff_id: GithubServerServiceHandoffId,
    consumer: GithubServerServiceConsumerClaim,
    identity: GithubServerServiceAuthorityIdentity,
    receipt: GithubServerServiceIssuanceReceipt,
    required_through: UnixMillis,
    granted_at: UnixMillis,
    acquired_at: UnixMillis,
    protected: ProtectedGithubServerServiceCredential,
}

impl GithubServerServiceCredentialHandoff {
    /// Rehydrates a live exact handoff.
    ///
    /// # Errors
    ///
    /// Rejects scope, generation, expiry, or grant-time disagreement.
    #[allow(clippy::too_many_arguments)]
    pub fn from_durable_parts(
        handoff_id: GithubServerServiceHandoffId,
        consumer: GithubServerServiceConsumerClaim,
        identity: GithubServerServiceAuthorityIdentity,
        receipt: GithubServerServiceIssuanceReceipt,
        required_through: UnixMillis,
        granted_at: UnixMillis,
        acquired_at: UnixMillis,
        protected: ProtectedGithubServerServiceCredential,
    ) -> Result<Self, GithubServerServiceValueError> {
        validate_claim_interval(
            acquired_at,
            required_through,
            consumer.action().max_handoff_millis(),
        )?;
        validate_claim_interval(
            granted_at,
            required_through,
            consumer.action().max_handoff_millis(),
        )?;
        if acquired_at < granted_at
            || identity.scope != consumer.action.required_scope()
            || !matches!(
                receipt.state,
                GithubServerServiceIssuanceState::Ready
                    | GithubServerServiceIssuanceState::RevokePending
            )
            || receipt.key.authority_id != identity.authority_id
            || receipt
                .ready_at
                .is_none_or(|ready_at| ready_at > granted_at)
            || protected.metadata.identity != identity
            || protected.metadata.generation != receipt.key.generation
            || !receipt_matches_protected_metadata(receipt, &protected.metadata)
            || protected
                .metadata
                .usable_until()
                .is_none_or(|usable_until| usable_until < required_through)
        {
            return Err(GithubServerServiceValueError::InvalidHandoff);
        }
        Ok(Self {
            handoff_id,
            consumer,
            identity,
            receipt,
            required_through,
            granted_at,
            acquired_at,
            protected,
        })
    }
    /// Returns durable handoff ID.
    #[must_use]
    pub const fn handoff_id(&self) -> GithubServerServiceHandoffId {
        self.handoff_id
    }
    /// Returns exact consumer claim.
    #[must_use]
    pub const fn consumer(&self) -> GithubServerServiceConsumerClaim {
        self.consumer
    }
    /// Returns immutable authority identity.
    #[must_use]
    pub const fn identity(&self) -> &GithubServerServiceAuthorityIdentity {
        &self.identity
    }
    /// Returns issuance projection.
    #[must_use]
    pub const fn receipt(&self) -> GithubServerServiceIssuanceReceipt {
        self.receipt
    }
    /// Returns required credential lifetime.
    #[must_use]
    pub const fn required_through(&self) -> UnixMillis {
        self.required_through
    }
    /// Returns grant time.
    #[must_use]
    pub const fn granted_at(&self) -> UnixMillis {
        self.granted_at
    }
    /// Returns the trusted current acquisition/replay observation.
    #[must_use]
    pub const fn acquired_at(&self) -> UnixMillis {
        self.acquired_at
    }
    /// Returns protected credential custody.
    #[must_use]
    pub const fn protected(&self) -> &ProtectedGithubServerServiceCredential {
        &self.protected
    }
}

impl std::fmt::Debug for GithubServerServiceCredentialHandoff {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GithubServerServiceCredentialHandoff")
            .field("handoff_id", &self.handoff_id)
            .field("consumer", &self.consumer)
            .field("identity", &self.identity)
            .field("receipt", &self.receipt)
            .field("required_through", &self.required_through)
            .field("granted_at", &self.granted_at)
            .field("acquired_at", &self.acquired_at)
            .field("protected", &"[PROTECTED]")
            .finish()
    }
}

/// Idempotently releases one exact handoff after provider use ends.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseGithubServerServiceHandoff {
    selector: GithubServerServiceAuthoritySelector,
    handoff_id: GithubServerServiceHandoffId,
    consumer: GithubServerServiceConsumerClaim,
    released_at: UnixMillis,
}

impl ReleaseGithubServerServiceHandoff {
    /// Constructs an exact release request.
    ///
    /// # Errors
    ///
    /// Rejects a pre-epoch timestamp.
    pub fn new(
        selector: GithubServerServiceAuthoritySelector,
        handoff_id: GithubServerServiceHandoffId,
        consumer: GithubServerServiceConsumerClaim,
        released_at: UnixMillis,
    ) -> Result<Self, GithubServerServiceValueError> {
        validate_timestamp(released_at)?;
        Ok(Self {
            selector,
            handoff_id,
            consumer,
            released_at,
        })
    }
    /// Returns the exact immutable descriptor selector.
    #[must_use]
    pub const fn selector(&self) -> &GithubServerServiceAuthoritySelector {
        &self.selector
    }
    /// Returns handoff ID.
    #[must_use]
    pub const fn handoff_id(&self) -> GithubServerServiceHandoffId {
        self.handoff_id
    }
    /// Returns exact consumer claim.
    #[must_use]
    pub const fn consumer(&self) -> GithubServerServiceConsumerClaim {
        self.consumer
    }
    /// Returns release time.
    #[must_use]
    pub const fn released_at(&self) -> UnixMillis {
        self.released_at
    }
}

/// Requests retirement of one exact configured authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetireGithubServerServiceAuthority {
    selector: GithubServerServiceAuthoritySelector,
    observed_at: UnixMillis,
}

impl RetireGithubServerServiceAuthority {
    /// Constructs a retirement request.
    ///
    /// # Errors
    ///
    /// Rejects a pre-epoch timestamp.
    pub fn new(
        selector: GithubServerServiceAuthoritySelector,
        observed_at: UnixMillis,
    ) -> Result<Self, GithubServerServiceValueError> {
        validate_timestamp(observed_at)?;
        Ok(Self {
            selector,
            observed_at,
        })
    }
    /// Returns the exact immutable descriptor selector.
    #[must_use]
    pub const fn selector(&self) -> &GithubServerServiceAuthoritySelector {
        &self.selector
    }
    /// Returns descriptor ID.
    #[must_use]
    pub const fn authority_id(&self) -> GithubServerServiceAuthorityId {
        self.selector.authority_id()
    }
    /// Returns trusted retirement time.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
}

/// Claims one eligible generation for provider revocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimGithubServerServiceRevocation {
    selector: GithubServerServiceAuthoritySelector,
    key: GithubServerServiceIssuanceKey,
    worker: GithubServerServiceWorkerId,
    observed_at: UnixMillis,
    claim_expires_at: UnixMillis,
}

impl ClaimGithubServerServiceRevocation {
    /// Constructs a bounded revocation claim.
    ///
    /// # Errors
    ///
    /// Rejects an invalid claim interval.
    pub fn new(
        selector: GithubServerServiceAuthoritySelector,
        key: GithubServerServiceIssuanceKey,
        worker: GithubServerServiceWorkerId,
        observed_at: UnixMillis,
        claim_expires_at: UnixMillis,
    ) -> Result<Self, GithubServerServiceValueError> {
        validate_claim_interval(
            observed_at,
            claim_expires_at,
            MAX_GITHUB_SERVICE_REVOKE_CLAIM_MILLIS,
        )?;
        if selector.authority_id() != key.authority_id() {
            return Err(GithubServerServiceValueError::InvalidClaim);
        }
        Ok(Self {
            selector,
            key,
            worker,
            observed_at,
            claim_expires_at,
        })
    }
    /// Returns the exact immutable descriptor selector.
    #[must_use]
    pub const fn selector(&self) -> &GithubServerServiceAuthoritySelector {
        &self.selector
    }
    /// Returns issuance key.
    #[must_use]
    pub const fn key(&self) -> GithubServerServiceIssuanceKey {
        self.key
    }
    /// Returns claiming worker.
    #[must_use]
    pub const fn worker(&self) -> GithubServerServiceWorkerId {
        self.worker
    }
    /// Returns trusted observation.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
    /// Returns exclusive claim expiry.
    #[must_use]
    pub const fn claim_expires_at(&self) -> UnixMillis {
        self.claim_expires_at
    }
}

/// Provider-revocation claim with protected credential custody.
pub struct ClaimedGithubServerServiceRevocation {
    claim: GithubServerServiceClaim,
    identity: GithubServerServiceAuthorityIdentity,
    receipt: GithubServerServiceIssuanceReceipt,
    claimed_at: UnixMillis,
    claim_expires_at: UnixMillis,
    protected: ProtectedGithubServerServiceCredential,
}

impl ClaimedGithubServerServiceRevocation {
    /// Rehydrates an exact live revocation claim.
    ///
    /// # Errors
    ///
    /// Rejects mismatched state, identity, generation, or interval.
    #[allow(clippy::too_many_arguments)]
    pub fn from_durable_parts(
        claim: GithubServerServiceClaim,
        identity: GithubServerServiceAuthorityIdentity,
        receipt: GithubServerServiceIssuanceReceipt,
        claimed_at: UnixMillis,
        claim_expires_at: UnixMillis,
        protected: ProtectedGithubServerServiceCredential,
    ) -> Result<Self, GithubServerServiceValueError> {
        validate_claim_interval(
            claimed_at,
            claim_expires_at,
            MAX_GITHUB_SERVICE_REVOKE_CLAIM_MILLIS,
        )?;
        if receipt.state != GithubServerServiceIssuanceState::RevokeClaimed
            || receipt.key != claim.key()
            || receipt.state_updated_at != claimed_at
            || claim_expires_at > receipt.safe_erase_after
            || !claim.selector().matches(&identity)
            || identity.authority_id != claim.key().authority_id()
            || protected.metadata.identity != identity
            || protected.metadata.generation != claim.key().generation()
            || !receipt_matches_protected_metadata(receipt, &protected.metadata)
        {
            return Err(GithubServerServiceValueError::InvalidClaim);
        }
        Ok(Self {
            claim,
            identity,
            receipt,
            claimed_at,
            claim_expires_at,
            protected,
        })
    }
    /// Returns exact revocation claim proof.
    #[must_use]
    pub const fn claim(&self) -> &GithubServerServiceClaim {
        &self.claim
    }
    /// Returns immutable descriptor identity.
    #[must_use]
    pub const fn identity(&self) -> &GithubServerServiceAuthorityIdentity {
        &self.identity
    }
    /// Returns issuance projection.
    #[must_use]
    pub const fn receipt(&self) -> GithubServerServiceIssuanceReceipt {
        self.receipt
    }
    /// Returns claim time.
    #[must_use]
    pub const fn claimed_at(&self) -> UnixMillis {
        self.claimed_at
    }
    /// Returns exclusive claim expiry.
    #[must_use]
    pub const fn claim_expires_at(&self) -> UnixMillis {
        self.claim_expires_at
    }
    /// Returns protected credential needed only for revocation.
    #[must_use]
    pub const fn protected(&self) -> &ProtectedGithubServerServiceCredential {
        &self.protected
    }
}

fn receipt_matches_protected_metadata(
    receipt: GithubServerServiceIssuanceReceipt,
    metadata: &GithubServerServiceEnvelopeMetadata,
) -> bool {
    receipt.key().generation() == metadata.generation()
        && receipt.requested_at() == metadata.requested_at()
        && receipt.request_deadline() == metadata.request_deadline()
        && receipt.provider_expires_at() == metadata.provider_expires_at()
        && receipt.safe_erase_after() == metadata.safe_erase_after()
}

impl std::fmt::Debug for ClaimedGithubServerServiceRevocation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClaimedGithubServerServiceRevocation")
            .field("claim", &self.claim)
            .field("identity", &self.identity)
            .field("receipt", &self.receipt)
            .field("claimed_at", &self.claimed_at)
            .field("claim_expires_at", &self.claim_expires_at)
            .field("protected", &"[PROTECTED]")
            .finish()
    }
}

/// Closed result of one provider revocation attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FinishGithubServerServiceRevocation {
    /// GitHub returned the required successful revocation response.
    Confirmed {
        claim: GithubServerServiceClaim,
        confirmed_at: UnixMillis,
    },
    /// Revocation failed safely and is eligible for bounded retry.
    Retry {
        claim: GithubServerServiceClaim,
        failure: GithubServerServiceFailureKind,
        observed_at: UnixMillis,
        retry_at: UnixMillis,
    },
    /// Protected custody is corrupt; provider use remains closed until expiry.
    Quarantined {
        claim: GithubServerServiceClaim,
        failure: GithubServerServiceFailureKind,
        observed_at: UnixMillis,
    },
}

impl FinishGithubServerServiceRevocation {
    /// Constructs a confirmed revocation result.
    ///
    /// # Errors
    ///
    /// Rejects a pre-epoch confirmation time.
    pub fn confirmed(
        claim: GithubServerServiceClaim,
        confirmed_at: UnixMillis,
    ) -> Result<Self, GithubServerServiceValueError> {
        validate_timestamp(confirmed_at)?;
        Ok(Self::Confirmed {
            claim,
            confirmed_at,
        })
    }
    /// Constructs a bounded revocation retry result.
    ///
    /// # Errors
    ///
    /// Rejects an invalid retry interval.
    pub fn retry(
        claim: GithubServerServiceClaim,
        failure: GithubServerServiceFailureKind,
        observed_at: UnixMillis,
        retry_at: UnixMillis,
    ) -> Result<Self, GithubServerServiceValueError> {
        validate_retry_interval(
            observed_at,
            retry_at,
            MAX_GITHUB_SERVICE_REVOKE_RETRY_MILLIS,
        )?;
        Ok(Self::Retry {
            claim,
            failure,
            observed_at,
            retry_at,
        })
    }
    /// Constructs a protected-custody quarantine result.
    ///
    /// # Errors
    ///
    /// Rejects a pre-epoch observation.
    pub fn quarantined(
        claim: GithubServerServiceClaim,
        failure: GithubServerServiceFailureKind,
        observed_at: UnixMillis,
    ) -> Result<Self, GithubServerServiceValueError> {
        validate_timestamp(observed_at)?;
        Ok(Self::Quarantined {
            claim,
            failure,
            observed_at,
        })
    }
}

/// Safely erases indeterminate or quarantined custody after its fixed horizon.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EraseExpiredGithubServerServiceIssuance {
    selector: GithubServerServiceAuthoritySelector,
    key: GithubServerServiceIssuanceKey,
    observed_at: UnixMillis,
}

impl EraseExpiredGithubServerServiceIssuance {
    /// Constructs an expiry-based erasure request.
    ///
    /// # Errors
    ///
    /// Rejects a pre-epoch observation.
    pub fn new(
        selector: GithubServerServiceAuthoritySelector,
        key: GithubServerServiceIssuanceKey,
        observed_at: UnixMillis,
    ) -> Result<Self, GithubServerServiceValueError> {
        validate_timestamp(observed_at)?;
        if selector.authority_id() != key.authority_id() {
            return Err(GithubServerServiceValueError::InvalidClaim);
        }
        Ok(Self {
            selector,
            key,
            observed_at,
        })
    }
    /// Returns the exact immutable descriptor selector.
    #[must_use]
    pub const fn selector(&self) -> &GithubServerServiceAuthoritySelector {
        &self.selector
    }
    /// Returns issuance key.
    #[must_use]
    pub const fn key(&self) -> GithubServerServiceIssuanceKey {
        self.key
    }
    /// Returns trusted erasure observation.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
}

/// Closes a corrupt current credential while retaining protected custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantineGithubServerServiceCredential {
    selector: GithubServerServiceAuthoritySelector,
    key: GithubServerServiceIssuanceKey,
    aad_digest: Sha256Digest,
    failure: GithubServerServiceFailureKind,
    observed_at: UnixMillis,
}

impl QuarantineGithubServerServiceCredential {
    /// Constructs an exact authenticated-custody quarantine mutation.
    ///
    /// # Errors
    ///
    /// Rejects a mismatched authority key or pre-epoch observation.
    pub fn new(
        selector: GithubServerServiceAuthoritySelector,
        key: GithubServerServiceIssuanceKey,
        aad_digest: Sha256Digest,
        failure: GithubServerServiceFailureKind,
        observed_at: UnixMillis,
    ) -> Result<Self, GithubServerServiceValueError> {
        validate_timestamp(observed_at)?;
        if selector.authority_id() != key.authority_id() {
            return Err(GithubServerServiceValueError::InvalidClaim);
        }
        Ok(Self {
            selector,
            key,
            aad_digest,
            failure,
            observed_at,
        })
    }
    /// Returns the exact immutable descriptor selector.
    #[must_use]
    pub const fn selector(&self) -> &GithubServerServiceAuthoritySelector {
        &self.selector
    }
    /// Returns the exact current issuance key.
    #[must_use]
    pub const fn key(&self) -> GithubServerServiceIssuanceKey {
        self.key
    }
    /// Returns the authenticated envelope digest.
    #[must_use]
    pub const fn aad_digest(&self) -> Sha256Digest {
        self.aad_digest
    }
    /// Returns the sanitized corruption classification.
    #[must_use]
    pub const fn failure(&self) -> &GithubServerServiceFailureKind {
        &self.failure
    }
    /// Returns the trusted observation time.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
}

/// Requests the next due maintenance action for one authenticated tenant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimNextGithubServerServiceMaintenance {
    tenant: TenantScope,
    worker: GithubServerServiceWorkerId,
    observed_at: UnixMillis,
    claim_expires_at: UnixMillis,
}

impl ClaimNextGithubServerServiceMaintenance {
    /// Constructs one bounded maintenance claim attempt.
    ///
    /// # Errors
    ///
    /// Rejects an invalid provider-work claim interval.
    pub fn new(
        tenant: TenantScope,
        worker: GithubServerServiceWorkerId,
        observed_at: UnixMillis,
        claim_expires_at: UnixMillis,
    ) -> Result<Self, GithubServerServiceValueError> {
        validate_claim_interval(
            observed_at,
            claim_expires_at,
            MAX_GITHUB_SERVICE_REVOKE_CLAIM_MILLIS,
        )?;
        Ok(Self {
            tenant,
            worker,
            observed_at,
            claim_expires_at,
        })
    }
    /// Returns the authenticated tenant boundary.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }
    /// Returns the maintenance worker identity.
    #[must_use]
    pub const fn worker(&self) -> GithubServerServiceWorkerId {
        self.worker
    }
    /// Returns the trusted scan observation.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
    /// Returns the exclusive provider-work claim horizon.
    #[must_use]
    pub const fn claim_expires_at(&self) -> UnixMillis {
        self.claim_expires_at
    }
}

/// One atomic, restart-safe maintenance result.
#[derive(Debug)]
pub enum GithubServerServiceMaintenanceOutcome {
    /// A due definitive no-token retry was atomically reclaimed for minting.
    Mint(Box<ClaimedGithubServerServiceMint>),
    /// A due protected credential was atomically claimed for revocation.
    Revocation(Box<ClaimedGithubServerServiceRevocation>),
    /// One stale/expired generation was deterministically reduced in-store.
    Reduced {
        /// Exact immutable descriptor selector for the reduced row.
        selector: GithubServerServiceAuthoritySelector,
        /// Value-free durable lifecycle result.
        receipt: GithubServerServiceIssuanceReceipt,
    },
}

/// Portable durable server-service authority failures.
#[derive(Debug, Error)]
pub enum GithubServerServiceStoreError {
    /// Backend operation failed without exposing credential values.
    #[error(transparent)]
    Operation(#[from] RepositoryOperationError),
    /// Durable rows violate the current-only contract.
    #[error("durable GitHub server-service authority data is corrupt")]
    CorruptData,
    /// Exact descriptor ID or provider scope conflicts with immutable state.
    #[error("GitHub server-service authority immutable identity conflicts")]
    IdentityConflict,
    /// Descriptor or issuance does not exist.
    #[error("GitHub server-service authority was not found")]
    NotFound,
    /// Requested lifecycle transition lacks the exact current fence/state.
    #[error("GitHub server-service authority claim or lifecycle was rejected")]
    ClaimRejected,
    /// A current credential cannot satisfy the exact handoff request.
    #[error("GitHub server-service credential handoff was rejected")]
    HandoffRejected,
    /// One current plus one refresh generation is already retained.
    #[error("GitHub server-service authority already has an active refresh")]
    RefreshAlreadyActive,
    /// A positive durable generation or claim fence is exhausted.
    #[error("GitHub server-service authority generation or fence is exhausted")]
    FenceExhausted,
    /// Closed provider attempt bound is exhausted.
    #[error("GitHub server-service authority retry bound is exhausted")]
    RetryLimitReached,
    /// A live exact handoff still requires the credential.
    #[error("GitHub server-service credential is still borrowed")]
    HandoffStillLive,
}

impl GithubServerServiceStoreError {
    /// Wraps a backend error behind a sanitized portable boundary.
    #[must_use]
    pub fn operation(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        RepositoryOperationError::from_source(source).into()
    }
}

/// Value-construction failures at the server-service authority boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubServerServiceValueError {
    /// Required UUID used the nil sentinel.
    #[error("server-service authority identity is nil: {0}")]
    NilIdentity(&'static str),
    /// Numeric GitHub App ID is invalid.
    #[error("GitHub App ID must be a positive BIGINT")]
    InvalidAppId,
    /// App JWT client identity is invalid.
    #[error("GitHub App client ID is invalid")]
    InvalidAppClientId,
    /// Configured App JWT issuer choice is unknown.
    #[error("GitHub App JWT issuer choice is invalid")]
    InvalidJwtIssuer,
    /// Issuance generation is invalid.
    #[error("server-service issuance generation is invalid")]
    InvalidGeneration,
    /// Configuration or consumer revision is invalid.
    #[error("server-service authority revision is invalid")]
    InvalidRevision,
    /// Claim fence is invalid.
    #[error("server-service authority claim fence is invalid")]
    InvalidClaimFence,
    /// Service scope is unknown.
    #[error("server-service authority scope is invalid")]
    InvalidScope,
    /// Consumer action is unknown.
    #[error("server-service authority action is invalid")]
    InvalidAction,
    /// Timestamp is before the Unix epoch.
    #[error("server-service authority timestamp is negative")]
    NegativeTimestamp,
    /// Timestamp derivation overflowed.
    #[error("server-service authority timestamp overflowed")]
    TimestampOverflow,
    /// Claim, request, retry, or handoff interval is invalid.
    #[error("server-service authority time interval is invalid")]
    InvalidTimeInterval,
    /// Provider expiry disagrees with the fixed issuance horizon.
    #[error("server-service credential provider expiry is invalid")]
    InvalidProviderExpiry,
    /// Protected plaintext metadata is invalid.
    #[error("server-service protected credential metadata is invalid")]
    InvalidProtectedPayload,
    /// Protected envelope shape is invalid.
    #[error("server-service protected credential envelope is invalid")]
    InvalidProtectedEnvelope,
    /// Key-management context cannot be represented.
    #[error("server-service authority encryption context is invalid")]
    InvalidEncryptionContext,
    /// Descriptor projection is inconsistent.
    #[error("server-service authority descriptor is invalid")]
    InvalidAuthorityDescriptor,
    /// Issuance projection is inconsistent.
    #[error("server-service authority issuance receipt is invalid")]
    InvalidIssuanceReceipt,
    /// Claim projection is inconsistent.
    #[error("server-service authority claim is invalid")]
    InvalidClaim,
    /// Provider mint commit disagrees with its claim.
    #[error("server-service authority mint commit is invalid")]
    InvalidCommit,
    /// Failure class is invalid.
    #[error("server-service authority failure kind is invalid")]
    InvalidFailureKind,
    /// Consumer handoff projection is inconsistent.
    #[error("server-service authority handoff is invalid")]
    InvalidHandoff,
}

/// Durable current-only server-service authority repository.
#[async_trait]
pub trait GithubServerServiceAuthorityRepository: Send + Sync {
    /// Creates one immutable descriptor or returns its exact replay.
    async fn ensure_github_server_service_authority(
        &self,
        request: EnsureGithubServerServiceAuthority,
    ) -> Result<GithubServerServiceAuthorityDescriptor, GithubServerServiceStoreError>;
    /// Reads one descriptor without loading credential ciphertext.
    async fn inspect_github_server_service_authority(
        &self,
        tenant: &TenantScope,
        authority_id: GithubServerServiceAuthorityId,
    ) -> Result<GithubServerServiceAuthorityDescriptor, GithubServerServiceStoreError>;
    /// Creates and claims the sole initial/refresh generation.
    async fn claim_github_server_service_mint(
        &self,
        request: ClaimGithubServerServiceMint,
    ) -> Result<ClaimedGithubServerServiceMint, GithubServerServiceStoreError>;
    /// Reclaims a definitively unissued retry generation.
    async fn reclaim_github_server_service_mint(
        &self,
        request: ReclaimGithubServerServiceMint,
    ) -> Result<ClaimedGithubServerServiceMint, GithubServerServiceStoreError>;
    /// Persists the irreversible provider-call cutoff.
    async fn begin_github_server_service_mint(
        &self,
        request: BeginGithubServerServiceMint,
    ) -> Result<BeginGithubServerServiceMintOutcome, GithubServerServiceStoreError>;
    /// Commits exactly one closed provider mint result.
    async fn finish_github_server_service_mint(
        &self,
        request: &FinishGithubServerServiceMint,
    ) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError>;
    /// Closes an expired pre-I/O mint or quarantines an expired post-I/O mint.
    async fn reconcile_expired_github_server_service_mint(
        &self,
        request: ReconcileExpiredGithubServerServiceMint,
    ) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError>;
    /// Acquires protected current custody for one exact value-free consumer claim.
    async fn acquire_github_server_service_handoff(
        &self,
        request: AcquireGithubServerServiceHandoff,
    ) -> Result<GithubServerServiceCredentialHandoff, GithubServerServiceStoreError>;
    /// Releases one exact handoff without deleting its evidence.
    async fn release_github_server_service_handoff(
        &self,
        request: ReleaseGithubServerServiceHandoff,
    ) -> Result<(), GithubServerServiceStoreError>;
    /// Atomically closes a corrupt current envelope by exact AAD evidence.
    async fn quarantine_github_server_service_credential(
        &self,
        request: QuarantineGithubServerServiceCredential,
    ) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError>;
    /// Closes new authority use and moves retained generations toward revocation.
    async fn retire_github_server_service_authority(
        &self,
        request: RetireGithubServerServiceAuthority,
    ) -> Result<GithubServerServiceAuthorityDescriptor, GithubServerServiceStoreError>;
    /// Claims an eligible retained credential for provider revocation.
    async fn claim_github_server_service_revocation(
        &self,
        request: ClaimGithubServerServiceRevocation,
    ) -> Result<ClaimedGithubServerServiceRevocation, GithubServerServiceStoreError>;
    /// Commits one closed provider revocation result.
    async fn finish_github_server_service_revocation(
        &self,
        request: FinishGithubServerServiceRevocation,
    ) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError>;
    /// Erases indeterminate or quarantined custody only after the fixed horizon.
    async fn erase_expired_github_server_service_issuance(
        &self,
        request: EraseExpiredGithubServerServiceIssuance,
    ) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError>;
    /// Atomically discovers and claims/reduces one due tenant maintenance row.
    async fn claim_next_github_server_service_maintenance(
        &self,
        request: ClaimNextGithubServerServiceMaintenance,
    ) -> Result<Option<GithubServerServiceMaintenanceOutcome>, GithubServerServiceStoreError>;
}

fn validate_timestamp(value: UnixMillis) -> Result<(), GithubServerServiceValueError> {
    if value.get() < 0 {
        Err(GithubServerServiceValueError::NegativeTimestamp)
    } else {
        Ok(())
    }
}

fn validate_claim_interval(
    start: UnixMillis,
    end: UnixMillis,
    maximum: i64,
) -> Result<(), GithubServerServiceValueError> {
    validate_timestamp(start)?;
    validate_timestamp(end)?;
    end.get()
        .checked_sub(start.get())
        .filter(|duration| *duration > 0 && *duration <= maximum)
        .ok_or(GithubServerServiceValueError::InvalidTimeInterval)?;
    Ok(())
}

fn validate_request_interval(
    start: UnixMillis,
    deadline: UnixMillis,
) -> Result<(), GithubServerServiceValueError> {
    validate_claim_interval(start, deadline, MAX_GITHUB_SERVICE_REQUEST_MILLIS)
}

fn validate_retry_interval(
    observed_at: UnixMillis,
    retry_at: UnixMillis,
    maximum: i64,
) -> Result<(), GithubServerServiceValueError> {
    validate_claim_interval(observed_at, retry_at, maximum)
}

fn add_millis(
    value: UnixMillis,
    increment: i64,
) -> Result<UnixMillis, GithubServerServiceValueError> {
    value
        .get()
        .checked_add(increment)
        .map(UnixMillis::new)
        .ok_or(GithubServerServiceValueError::TimestampOverflow)
}

fn derive_conservative_expiry(
    request_deadline: UnixMillis,
) -> Result<UnixMillis, GithubServerServiceValueError> {
    add_millis(
        request_deadline,
        GITHUB_SERVICE_TOKEN_LIFETIME_MILLIS
            + GITHUB_SERVICE_PROVIDER_CLOCK_SKEW_MILLIS
            + GITHUB_SERVICE_SAFE_ERASE_SKEW_MILLIS,
    )
}

fn validate_provider_expiry(
    requested_at: UnixMillis,
    request_deadline: UnixMillis,
    provider_expiry: UnixMillis,
) -> Result<(), GithubServerServiceValueError> {
    validate_timestamp(provider_expiry)?;
    let maximum = add_millis(
        request_deadline,
        GITHUB_SERVICE_TOKEN_LIFETIME_MILLIS + GITHUB_SERVICE_PROVIDER_CLOCK_SKEW_MILLIS,
    )?;
    if provider_expiry <= requested_at || provider_expiry > maximum {
        return Err(GithubServerServiceValueError::InvalidProviderExpiry);
    }
    Ok(())
}

fn update_part(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

#[allow(clippy::too_many_arguments)]
fn compute_aad_digest(
    identity: &GithubServerServiceAuthorityIdentity,
    generation: GithubServerServiceGeneration,
    requested_at: UnixMillis,
    request_deadline: UnixMillis,
    provider_expiry: Option<UnixMillis>,
    safe_erase_after: UnixMillis,
    plaintext_schema: u16,
    plaintext_size: u64,
    plaintext_digest: Sha256Digest,
) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(AAD_DIGEST_DOMAIN);
    update_part(&mut digest, identity.identity_digest().as_bytes());
    update_part(&mut digest, &generation.get().to_be_bytes());
    update_part(&mut digest, &requested_at.get().to_be_bytes());
    update_part(&mut digest, &request_deadline.get().to_be_bytes());
    match provider_expiry {
        Some(provider_expiry) => {
            update_part(&mut digest, &[1]);
            update_part(&mut digest, &provider_expiry.get().to_be_bytes());
        }
        None => update_part(&mut digest, &[0]),
    }
    update_part(&mut digest, &safe_erase_after.get().to_be_bytes());
    update_part(&mut digest, &plaintext_schema.to_be_bytes());
    update_part(&mut digest, &plaintext_size.to_be_bytes());
    update_part(&mut digest, plaintext_digest.as_bytes());
    Sha256Digest::from_bytes(digest.finalize().into())
}
