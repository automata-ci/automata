//! Authenticated readiness evidence for repository-secret encryption custody.
//!
//! A durable key identifier alone cannot prove that replicas loaded identical
//! key material. This boundary binds the exact configured key set to immutable
//! envelopes that the active and every durably required key must authenticate
//! before readiness. Only a fresh decrypt-only rotation successor may be
//! prestaged before its first canary exists.
//! The schema rejects built-in ciphertext without a canary identity, but that
//! row-level fact does not prove the process loaded matching bytes. Product
//! composition must require a freshly verified receipt at each write boundary.

use std::{fmt, num::NonZeroU64};

use async_trait::async_trait;
use automata_ci_core::Sha256Digest;
use automata_ci_key_management::KeyId;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Maximum number of simultaneously configured secret-custody wrapping keys.
pub const MAX_SECRET_CUSTODY_CONFIGURED_KEYS: usize = 32;
/// The only current immutable canary generation.
pub const SECRET_CUSTODY_CANARY_GENERATION: u64 = 1;
/// Durable schema for one encrypted secret-custody key canary.
pub(crate) const SECRET_CUSTODY_CANARY_SCHEMA_VERSION: u16 = 1;

// foundation-governance: derived-contract owner=store kind=digest-domain
const KEY_SET_DIGEST_DOMAIN: &[u8] = b"automata.store.secret-custody.key-set.v1\0";
// foundation-governance: derived-contract owner=store kind=digest-domain
const REQUIREMENTS_DIGEST_DOMAIN: &[u8] = b"automata.store.secret-custody.requirements.v1\0";
const ACTIVE_PROVIDER: usize = 0;
const ENCRYPTED_ENVELOPES: usize = 1;
const OPEN_MUTATIONS: usize = 2;
const OPEN_LEASES: usize = 3;
const OPEN_CLEANUP: usize = 4;
const OPEN_RECOVERY: usize = 5;
const OPEN_ROTATION: usize = 6;
const REQUIREMENT_STATE_COUNT: usize = 7;

/// Exact active and decrypt-only key identities declared by configuration.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretCustodyKeySet {
    active_key_id: KeyId,
    key_ids: Vec<KeyId>,
    digest: Sha256Digest,
}

impl SecretCustodyKeySet {
    /// Creates one bounded, unique key set with exactly one active identity.
    /// A fresh decrypt-only successor may be declared before it has a canary;
    /// the adapter will require that canary as soon as the key is active or
    /// referenced by durable state.
    ///
    /// # Errors
    ///
    /// Rejects a repeated active/decrypt-only identity or an oversized set.
    pub fn new(
        active_key_id: KeyId,
        decrypt_only_key_ids: Vec<KeyId>,
    ) -> Result<Self, SecretCustodyValueError> {
        let mut key_ids = Vec::with_capacity(decrypt_only_key_ids.len().saturating_add(1));
        key_ids.push(active_key_id.clone());
        key_ids.extend(decrypt_only_key_ids);
        if key_ids.len() > MAX_SECRET_CUSTODY_CONFIGURED_KEYS {
            return Err(SecretCustodyValueError::TooManyConfiguredKeys);
        }
        key_ids.sort_unstable();
        if key_ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(SecretCustodyValueError::DuplicateConfiguredKey);
        }
        let digest = key_set_digest(&active_key_id, &key_ids);
        Ok(Self {
            active_key_id,
            key_ids,
            digest,
        })
    }

    /// Returns the only identity allowed to wrap a newly created canary.
    #[must_use]
    pub const fn active_key_id(&self) -> &KeyId {
        &self.active_key_id
    }

    /// Returns every configured identity in canonical sorted order.
    #[must_use]
    pub fn key_ids(&self) -> &[KeyId] {
        &self.key_ids
    }

    /// Returns the domain-separated digest of the active identity and full set.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    pub(crate) fn contains(&self, key_id: &KeyId) -> bool {
        self.key_ids.binary_search(key_id).is_ok()
    }
}

impl fmt::Debug for SecretCustodyKeySet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretCustodyKeySet")
            .field("configured_key_count", &self.key_ids.len())
            .field("key_identities", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Value-free reasons durable secret state currently requires key custody.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretCustodyRequirements {
    states: [bool; REQUIREMENT_STATE_COUNT],
    required_key_ids: Vec<KeyId>,
    digest: Sha256Digest,
}

impl SecretCustodyRequirements {
    pub(crate) fn from_durable_parts(
        states: [bool; REQUIREMENT_STATE_COUNT],
        required_key_ids: Vec<KeyId>,
    ) -> Result<Self, SecretCustodyValueError> {
        if required_key_ids.len() > MAX_SECRET_CUSTODY_CONFIGURED_KEYS {
            return Err(SecretCustodyValueError::TooManyRequiredKeys);
        }
        if required_key_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(SecretCustodyValueError::InvalidRequiredKeyOrder);
        }
        let mut requirements = Self {
            states,
            required_key_ids,
            digest: Sha256Digest::from_bytes([0; 32]),
        };
        requirements.digest = requirements_digest(&requirements);
        Ok(requirements)
    }

    /// Returns whether any current durable state requires key configuration.
    #[must_use]
    pub fn configuration_required(&self) -> bool {
        self.states.iter().any(|required| *required) || !self.required_key_ids.is_empty()
    }

    /// Returns whether at least one secret provider is active.
    #[must_use]
    pub const fn has_active_provider(&self) -> bool {
        self.states[ACTIVE_PROVIDER]
    }

    /// Returns whether any encrypted secret-custody envelope remains durable.
    #[must_use]
    pub const fn has_encrypted_envelopes(&self) -> bool {
        self.states[ENCRYPTED_ENVELOPES]
    }

    /// Returns whether a provider-crossing mutation remains open.
    #[must_use]
    pub const fn has_open_mutations(&self) -> bool {
        self.states[OPEN_MUTATIONS]
    }

    /// Returns whether a renewable or revocable provider lease remains open.
    #[must_use]
    pub const fn has_open_leases(&self) -> bool {
        self.states[OPEN_LEASES]
    }

    /// Returns whether pending, claimed, or dead-letter cleanup remains.
    #[must_use]
    pub const fn has_open_cleanup(&self) -> bool {
        self.states[OPEN_CLEANUP]
    }

    /// Returns whether mutation recovery remains pending or claimed.
    #[must_use]
    pub const fn has_open_recovery(&self) -> bool {
        self.states[OPEN_RECOVERY]
    }

    /// Returns whether incomplete or failed key-rotation work remains.
    #[must_use]
    pub const fn has_open_rotation(&self) -> bool {
        self.states[OPEN_ROTATION]
    }

    /// Returns identities required by live envelope heads or open rotations.
    #[must_use]
    pub fn required_key_ids(&self) -> &[KeyId] {
        &self.required_key_ids
    }

    /// Returns a domain-separated digest of this exact requirement snapshot.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

impl fmt::Debug for SecretCustodyRequirements {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretCustodyRequirements")
            .field("configuration_required", &self.configuration_required())
            .field("active_provider", &self.has_active_provider())
            .field("encrypted_envelopes", &self.has_encrypted_envelopes())
            .field("open_mutations", &self.has_open_mutations())
            .field("open_leases", &self.has_open_leases())
            .field("open_cleanup", &self.has_open_cleanup())
            .field("open_recovery", &self.has_open_recovery())
            .field("open_rotation", &self.has_open_rotation())
            .field("required_key_count", &self.required_key_ids.len())
            .field("key_identities", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Explicit request to verify configured custody or prove it is not required.
pub struct VerifySecretCustody {
    configured_keys: Option<SecretCustodyKeySet>,
}

impl VerifySecretCustody {
    /// Requests a value-free proof that current durable state needs no key.
    #[must_use]
    pub const fn absent() -> Self {
        Self {
            configured_keys: None,
        }
    }

    /// Requests authentication of an exact configured key set.
    #[must_use]
    pub const fn configured(configured_keys: SecretCustodyKeySet) -> Self {
        Self {
            configured_keys: Some(configured_keys),
        }
    }

    pub(crate) fn configured_keys(&self) -> Option<&SecretCustodyKeySet> {
        self.configured_keys.as_ref()
    }
}

impl fmt::Debug for VerifySecretCustody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifySecretCustody")
            .field("configured", &self.configured_keys.is_some())
            .field(
                "configured_key_count",
                &self
                    .configured_keys
                    .as_ref()
                    .map_or(0, |keys| keys.key_ids.len()),
            )
            .field("key_identities", &"[REDACTED]")
            .finish()
    }
}

/// Positive immutable generation of one authenticated canary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretCustodyCanaryGeneration(NonZeroU64);

impl SecretCustodyCanaryGeneration {
    pub(crate) fn new(value: u64) -> Result<Self, SecretCustodyValueError> {
        NonZeroU64::new(value)
            .filter(|value| value.get() == SECRET_CUSTODY_CANARY_GENERATION)
            .map(Self)
            .ok_or(SecretCustodyValueError::InvalidCanaryGeneration)
    }

    /// Returns the positive generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// One verified key identity and its exact immutable canary generation.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretCustodyCanaryBinding {
    key_id: KeyId,
    generation: SecretCustodyCanaryGeneration,
}

impl SecretCustodyCanaryBinding {
    pub(crate) const fn new(key_id: KeyId, generation: SecretCustodyCanaryGeneration) -> Self {
        Self { key_id, generation }
    }

    /// Returns the authenticated key identity.
    #[must_use]
    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// Returns the immutable canary generation that authenticated it.
    #[must_use]
    pub const fn generation(&self) -> SecretCustodyCanaryGeneration {
        self.generation
    }
}

impl fmt::Debug for SecretCustodyCanaryBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretCustodyCanaryBinding")
            .field("key_id", &"[REDACTED]")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

/// Adapter-issued proof that active and durably required material authenticated custody.
///
/// There is intentionally no public constructor. A future write boundary must
/// accept only this receipt, compare its key-set fingerprint with current
/// configuration, and refresh it against durable requirements immediately
/// before the write. Possessing this foundation receipt alone does not yet
/// make an uncomposed product write safe.
pub struct VerifiedSecretCustody {
    active_key_id: KeyId,
    configured_key_set_digest: Sha256Digest,
    requirements_digest: Sha256Digest,
    durable_state_requires_configuration: bool,
    canaries: Vec<SecretCustodyCanaryBinding>,
}

impl VerifiedSecretCustody {
    pub(crate) fn from_verified_parts(
        configured_keys: &SecretCustodyKeySet,
        requirements: &SecretCustodyRequirements,
        canaries: Vec<SecretCustodyCanaryBinding>,
    ) -> Result<Self, SecretCustodyValueError> {
        if canaries
            .windows(2)
            .any(|pair| pair[0].key_id() >= pair[1].key_id())
            || canaries
                .iter()
                .any(|binding| !configured_keys.contains(binding.key_id()))
            || !canaries
                .iter()
                .any(|binding| binding.key_id() == configured_keys.active_key_id())
            || requirements.required_key_ids().iter().any(|required| {
                !configured_keys.contains(required)
                    || !canaries.iter().any(|binding| binding.key_id() == required)
            })
        {
            return Err(SecretCustodyValueError::InvalidVerificationReceipt);
        }
        Ok(Self {
            active_key_id: configured_keys.active_key_id().clone(),
            configured_key_set_digest: configured_keys.digest(),
            requirements_digest: requirements.digest(),
            durable_state_requires_configuration: requirements.configuration_required(),
            canaries,
        })
    }

    /// Returns the only key identity authenticated for new envelope writes.
    #[must_use]
    pub const fn active_key_id(&self) -> &KeyId {
        &self.active_key_id
    }

    /// Returns the exact configured key-set fingerprint verified by the adapter.
    #[must_use]
    pub const fn configured_key_set_digest(&self) -> Sha256Digest {
        self.configured_key_set_digest
    }

    /// Returns the exact durable-requirement snapshot fingerprint.
    #[must_use]
    pub const fn requirements_digest(&self) -> Sha256Digest {
        self.requirements_digest
    }

    /// Returns whether durable state required configuration at verification.
    #[must_use]
    pub const fn durable_state_requires_configuration(&self) -> bool {
        self.durable_state_requires_configuration
    }

    /// Returns every configured identity whose immutable canary was verified.
    /// A never-referenced decrypt-only key being prestaged for rotation is the
    /// sole configured identity that may be absent from this list.
    #[must_use]
    pub fn canaries(&self) -> &[SecretCustodyCanaryBinding] {
        &self.canaries
    }
}

impl fmt::Debug for VerifiedSecretCustody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedSecretCustody")
            .field(
                "durable_state_requires_configuration",
                &self.durable_state_requires_configuration,
            )
            .field("verified_key_count", &self.canaries.len())
            .field("key_identities", &"[REDACTED]")
            .field("digests", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Closed result of one exact custody verification.
#[derive(Debug)]
pub enum VerifySecretCustodyOutcome {
    /// No configuration was supplied and exact durable state requires none.
    ///
    /// Immutable canaries alone contain only the fixed public marker and do
    /// not make key configuration necessary after all protected state drains.
    NotRequired,
    /// Active and required material authenticated every applicable canary.
    Verified(VerifiedSecretCustody),
}

/// Backend-neutral secret-custody readiness boundary.
#[async_trait]
pub trait SecretCustodyRepository: fmt::Debug + Send + Sync {
    /// Reads one exact, value-free snapshot of all custody requirements.
    async fn inspect_secret_custody_requirements(
        &self,
    ) -> Result<SecretCustodyRequirements, SecretCustodyRepositoryError>;

    /// Authenticates active and durably required configured material, creating
    /// only the fresh active key's first-writer canary. A fresh decrypt-only
    /// rotation successor may remain prestaged, and absent configuration is
    /// accepted only when exact durable state requires none.
    async fn verify_or_create_secret_custody(
        &self,
        request: VerifySecretCustody,
    ) -> Result<VerifySecretCustodyOutcome, SecretCustodyRepositoryError>;
}

/// Sanitized readiness failure with no secret, envelope, or key identity.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SecretCustodyRepositoryError {
    /// Durable requirements need key configuration, but none was supplied.
    #[error("secret custody key configuration is required")]
    ConfigurationRequired,
    /// A declared configuration has no usable key-encryption implementation.
    #[error("secret custody key configuration is unavailable")]
    ConfigurationUnavailable,
    /// At least one durable wrapping identity is absent from configuration.
    #[error("required secret custody key material is unavailable")]
    RequiredKeyUnavailable,
    /// A configured or previously referenced identity has no prior canary.
    #[error("secret custody key attestation is unavailable")]
    CanaryUnavailable,
    /// Loaded material could not authenticate its immutable canary.
    #[error("secret custody key attestation failed")]
    VerificationFailed,
    /// The encryption implementation selected a different active identity.
    #[error("secret custody active key configuration is inconsistent")]
    ActiveKeyMismatch,
    /// The durable adapter could not complete the operation.
    #[error("secret custody storage is unavailable")]
    Unavailable,
    /// Durable custody metadata violates an invariant.
    #[error("durable secret custody metadata violates an invariant")]
    CorruptData,
}

/// Closed validation failure for bounded custody values.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SecretCustodyValueError {
    /// One key identity was declared more than once.
    #[error("secret custody key identities must be unique")]
    DuplicateConfiguredKey,
    /// Configuration exceeded the hard key-count bound.
    #[error("secret custody configured key count exceeds the maximum")]
    TooManyConfiguredKeys,
    /// Durable state exceeded the supported key-count bound.
    #[error("secret custody required key count exceeds the maximum")]
    TooManyRequiredKeys,
    /// Durable key identities were not in strict canonical order.
    #[error("secret custody required key order is invalid")]
    InvalidRequiredKeyOrder,
    /// A durable canary generation is unsupported.
    #[error("secret custody canary generation is invalid")]
    InvalidCanaryGeneration,
    /// Adapter verification evidence disagreed with the exact configuration.
    #[error("secret custody verification receipt is invalid")]
    InvalidVerificationReceipt,
}

fn key_set_digest(active_key_id: &KeyId, key_ids: &[KeyId]) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(KEY_SET_DIGEST_DOMAIN);
    update_length_prefixed(&mut digest, active_key_id.as_str().as_bytes());
    digest.update(
        u32::try_from(key_ids.len())
            .expect("the configured key bound fits u32")
            .to_be_bytes(),
    );
    for key_id in key_ids {
        update_length_prefixed(&mut digest, key_id.as_str().as_bytes());
    }
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn requirements_digest(requirements: &SecretCustodyRequirements) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(REQUIREMENTS_DIGEST_DOMAIN);
    digest.update(requirements.states.map(u8::from));
    digest.update(
        u32::try_from(requirements.required_key_ids.len())
            .expect("the required key bound fits u32")
            .to_be_bytes(),
    );
    for key_id in &requirements.required_key_ids {
        update_length_prefixed(&mut digest, key_id.as_str().as_bytes());
    }
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn update_length_prefixed(digest: &mut Sha256, value: &[u8]) {
    digest.update(
        u32::try_from(value.len())
            .expect("canonical key IDs fit u32")
            .to_be_bytes(),
    );
    digest.update(value);
}
