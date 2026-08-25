//! Lease-scoped, value-free managed-secret binding overlays.

use std::{collections::BTreeSet, fmt};

use automata_ci_core::{AttemptId, FencingToken, Lease, LeaseId, SecretBinding, Sha256Digest};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

/// Schema version for the canonical managed-secret binding overlay.
pub const MANAGED_SECRET_BINDING_OVERLAY_SCHEMA_VERSION: u16 = 1;

/// Maximum value-free binding entries carried by one lease overlay.
pub const MAX_MANAGED_SECRET_BINDINGS: usize = 256;
const OVERLAY_DIGEST_DOMAIN: &[u8] = b"automata.managed-secret-binding-overlay.v1\0";

/// One canonical environment name and its value-free grant/version locator.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedManagedSecretBindingOverlayEntry")]
pub struct ManagedSecretBindingOverlayEntry {
    canonical_name: String,
    binding: SecretBinding,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedManagedSecretBindingOverlayEntry {
    canonical_name: String,
    binding: SecretBinding,
}

impl TryFrom<UncheckedManagedSecretBindingOverlayEntry> for ManagedSecretBindingOverlayEntry {
    type Error = ManagedSecretBindingOverlayError;

    fn try_from(value: UncheckedManagedSecretBindingOverlayEntry) -> Result<Self, Self::Error> {
        Self::new(value.canonical_name, value.binding)
    }
}

impl ManagedSecretBindingOverlayEntry {
    /// Creates one value-free binding entry.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical environment names, non-UUID grant identities, or
    /// bindings without one immutable, canonical UUID version identity.
    pub fn new(
        canonical_name: impl Into<String>,
        binding: SecretBinding,
    ) -> Result<Self, ManagedSecretBindingOverlayError> {
        let canonical_name = canonical_name.into();
        if !valid_canonical_name(&canonical_name) {
            return Err(ManagedSecretBindingOverlayError::InvalidCanonicalName);
        }
        if !valid_canonical_uuid(binding.binding_id()) {
            return Err(ManagedSecretBindingOverlayError::InvalidGrantId);
        }
        let version_id = binding
            .version_id()
            .ok_or(ManagedSecretBindingOverlayError::MissingVersionId)?;
        if !valid_canonical_uuid(version_id) {
            return Err(ManagedSecretBindingOverlayError::InvalidVersionId);
        }
        Ok(Self {
            canonical_name,
            binding,
        })
    }

    /// Returns the canonical environment name.
    #[must_use]
    pub fn canonical_name(&self) -> &str {
        &self.canonical_name
    }

    /// Returns the opaque grant and immutable version locator.
    #[must_use]
    pub const fn binding(&self) -> &SecretBinding {
        &self.binding
    }
}

impl fmt::Debug for ManagedSecretBindingOverlayEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedSecretBindingOverlayEntry")
            .field("canonical_name", &"[REDACTED]")
            .field("binding", &self.binding)
            .finish()
    }
}

/// Canonical value-free secret bindings for one exact leased attempt.
///
/// The overlay is separate from immutable `JobIR` and runtime-context bytes.
/// Its digest commits to the exact attempt, lease, fence, ordering, names,
/// grant identities, and immutable version identities.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct ManagedSecretBindingOverlay {
    schema_version: u16,
    attempt_id: AttemptId,
    lease_id: LeaseId,
    fencing_token: FencingToken,
    bindings: Vec<ManagedSecretBindingOverlayEntry>,
    digest: Sha256Digest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedManagedSecretBindingOverlay {
    schema_version: u16,
    attempt_id: AttemptId,
    lease_id: LeaseId,
    fencing_token: FencingToken,
    bindings: Vec<ManagedSecretBindingOverlayEntry>,
    digest: Sha256Digest,
}

impl<'de> Deserialize<'de> for ManagedSecretBindingOverlay {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let unchecked = UncheckedManagedSecretBindingOverlay::deserialize(deserializer)?;
        let overlay = Self {
            schema_version: unchecked.schema_version,
            attempt_id: unchecked.attempt_id,
            lease_id: unchecked.lease_id,
            fencing_token: unchecked.fencing_token,
            bindings: unchecked.bindings,
            digest: unchecked.digest,
        };
        overlay
            .validate_canonical()
            .map_err(serde::de::Error::custom)?;
        Ok(overlay)
    }
}

impl ManagedSecretBindingOverlay {
    /// Creates a canonical overlay for one exact lease.
    ///
    /// # Errors
    ///
    /// Rejects invalid entries, duplicate names or grants, and more than 256
    /// bindings. Input order is normalized by canonical name before hashing.
    pub fn new(
        lease: &Lease,
        bindings: impl IntoIterator<Item = (String, SecretBinding)>,
    ) -> Result<Self, ManagedSecretBindingOverlayError> {
        let mut bindings = bindings
            .into_iter()
            .map(|(name, binding)| ManagedSecretBindingOverlayEntry::new(name, binding))
            .collect::<Result<Vec<_>, _>>()?;
        bindings.sort_unstable_by(|left, right| left.canonical_name.cmp(&right.canonical_name));
        let mut overlay = Self {
            schema_version: MANAGED_SECRET_BINDING_OVERLAY_SCHEMA_VERSION,
            attempt_id: lease.attempt_id(),
            lease_id: lease.lease_id(),
            fencing_token: lease.fencing_token(),
            bindings,
            digest: Sha256Digest::from_bytes([0; 32]),
        };
        overlay.validate_bindings()?;
        overlay.digest = overlay.compute_digest();
        Ok(overlay)
    }

    /// Creates the canonical empty overlay for one exact lease.
    #[must_use]
    pub fn empty(lease: &Lease) -> Self {
        let mut overlay = Self {
            schema_version: MANAGED_SECRET_BINDING_OVERLAY_SCHEMA_VERSION,
            attempt_id: lease.attempt_id(),
            lease_id: lease.lease_id(),
            fencing_token: lease.fencing_token(),
            bindings: Vec::new(),
            digest: Sha256Digest::from_bytes([0; 32]),
        };
        overlay.digest = overlay.compute_digest();
        overlay
    }

    /// Returns the overlay schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the exact attempt bound by this overlay.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the exact lease bound by this overlay.
    #[must_use]
    pub const fn lease_id(&self) -> LeaseId {
        self.lease_id
    }

    /// Returns the exact fencing token bound by this overlay.
    #[must_use]
    pub const fn fencing_token(&self) -> FencingToken {
        self.fencing_token
    }

    /// Returns canonical name-sorted, value-free bindings.
    #[must_use]
    pub fn bindings(&self) -> &[ManagedSecretBindingOverlayEntry] {
        &self.bindings
    }

    /// Returns the digest committing to the overlay and lease coordinates.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Validates canonical form, digest, and exact lease coordinates.
    ///
    /// # Errors
    ///
    /// Rejects unsupported schema, malformed or reordered bindings, a changed
    /// digest, or any attempt/lease/fence mismatch.
    pub fn validate_for(&self, lease: &Lease) -> Result<(), ManagedSecretBindingOverlayError> {
        self.validate_canonical()?;
        if self.attempt_id != lease.attempt_id()
            || self.lease_id != lease.lease_id()
            || self.fencing_token != lease.fencing_token()
        {
            return Err(ManagedSecretBindingOverlayError::LeaseMismatch);
        }
        Ok(())
    }

    fn validate_canonical(&self) -> Result<(), ManagedSecretBindingOverlayError> {
        if self.schema_version != MANAGED_SECRET_BINDING_OVERLAY_SCHEMA_VERSION {
            return Err(ManagedSecretBindingOverlayError::UnsupportedSchema);
        }
        self.validate_bindings()?;
        if self.compute_digest() != self.digest {
            return Err(ManagedSecretBindingOverlayError::DigestMismatch);
        }
        Ok(())
    }

    fn validate_bindings(&self) -> Result<(), ManagedSecretBindingOverlayError> {
        if self.bindings.len() > MAX_MANAGED_SECRET_BINDINGS {
            return Err(ManagedSecretBindingOverlayError::TooManyBindings);
        }
        let mut previous_name: Option<&str> = None;
        let mut grants = BTreeSet::new();
        for entry in &self.bindings {
            ManagedSecretBindingOverlayEntry::new(
                entry.canonical_name.clone(),
                entry.binding.clone(),
            )?;
            if previous_name.is_some_and(|previous| previous >= entry.canonical_name()) {
                return Err(ManagedSecretBindingOverlayError::NoncanonicalOrder);
            }
            previous_name = Some(entry.canonical_name());
            if !grants.insert(entry.binding.binding_id()) {
                return Err(ManagedSecretBindingOverlayError::DuplicateGrant);
            }
        }
        Ok(())
    }

    fn compute_digest(&self) -> Sha256Digest {
        let mut hasher = Sha256::new();
        hasher.update(OVERLAY_DIGEST_DOMAIN);
        hasher.update(self.schema_version.to_be_bytes());
        hasher.update(self.attempt_id.as_uuid().as_bytes());
        hasher.update(self.lease_id.as_uuid().as_bytes());
        hasher.update(self.fencing_token.get().to_be_bytes());
        hasher.update(
            u32::try_from(self.bindings.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        for entry in &self.bindings {
            digest_text(&mut hasher, entry.canonical_name());
            digest_text(&mut hasher, entry.binding.binding_id());
            digest_text(
                &mut hasher,
                entry
                    .binding
                    .version_id()
                    .expect("validated overlay bindings have immutable versions"),
            );
        }
        Sha256Digest::from_bytes(hasher.finalize().into())
    }
}

impl fmt::Debug for ManagedSecretBindingOverlay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedSecretBindingOverlay")
            .field("schema_version", &self.schema_version)
            .field("binding_count", &self.bindings.len())
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

/// Invalid managed-secret overlay metadata.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ManagedSecretBindingOverlayError {
    /// The overlay schema is not supported.
    #[error("unsupported managed-secret binding overlay schema")]
    UnsupportedSchema,
    /// A canonical name is malformed or reserved.
    #[error("invalid managed-secret canonical name")]
    InvalidCanonicalName,
    /// A grant identity is not one canonical non-nil UUID.
    #[error("invalid managed-secret grant identity")]
    InvalidGrantId,
    /// A selected immutable version is missing.
    #[error("managed-secret binding has no immutable version")]
    MissingVersionId,
    /// A version identity is not one canonical non-nil UUID.
    #[error("invalid managed-secret version identity")]
    InvalidVersionId,
    /// More bindings were supplied than the bounded protocol permits.
    #[error("too many managed-secret bindings")]
    TooManyBindings,
    /// Names are duplicated or not in canonical ascending order.
    #[error("managed-secret bindings are not in canonical order")]
    NoncanonicalOrder,
    /// More than one name points at the same workload grant.
    #[error("managed-secret overlay contains a duplicate grant")]
    DuplicateGrant,
    /// The overlay digest does not match its canonical content.
    #[error("managed-secret binding overlay digest mismatch")]
    DigestMismatch,
    /// The overlay names another attempt, lease, or fence.
    #[error("managed-secret binding overlay lease mismatch")]
    LeaseMismatch,
}

fn valid_canonical_name(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_uppercase())
        && value.len() <= 255
        && characters.all(|character| {
            character == '_' || character.is_ascii_uppercase() || character.is_ascii_digit()
        })
        && !["GITHUB_", "ACTIONS_", "RUNNER_", "AUTOMATA_"]
            .iter()
            .any(|prefix| value.starts_with(prefix))
}

fn valid_canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value)
        .is_ok_and(|parsed| !parsed.is_nil() && parsed.hyphenated().to_string().as_str() == value)
}

fn digest_text(hasher: &mut Sha256, value: &str) {
    hasher.update(u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
    hasher.update(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use automata_ci_core::{
        AttemptId, FencingToken, Lease, LeaseId, RunnerId, SecretBinding, UnixMillis,
    };

    use super::{
        ManagedSecretBindingOverlay, ManagedSecretBindingOverlayEntry,
        ManagedSecretBindingOverlayError,
    };

    fn lease() -> Lease {
        Lease::new(
            LeaseId::new(),
            AttemptId::new(),
            RunnerId::new(),
            FencingToken::new(7).expect("fence"),
            UnixMillis::new(10),
            UnixMillis::new(20),
        )
        .expect("lease")
    }

    fn binding(grant: &str, version: &str) -> SecretBinding {
        SecretBinding::new(grant)
            .expect("grant")
            .with_version_id(version)
            .expect("version")
    }

    #[test]
    fn canonicalizes_binding_order() {
        let lease = lease();
        let overlay = ManagedSecretBindingOverlay::new(
            &lease,
            [
                (
                    "TOKEN_B".to_owned(),
                    binding(
                        "00000000-0000-4000-8000-000000000002",
                        "00000000-0000-4000-8000-000000000012",
                    ),
                ),
                (
                    "TOKEN_A".to_owned(),
                    binding(
                        "00000000-0000-4000-8000-000000000001",
                        "00000000-0000-4000-8000-000000000011",
                    ),
                ),
            ],
        )
        .expect("overlay");

        assert_eq!(
            overlay
                .bindings()
                .iter()
                .map(ManagedSecretBindingOverlayEntry::canonical_name)
                .collect::<Vec<_>>(),
            ["TOKEN_A", "TOKEN_B"]
        );
        assert!(overlay.validate_for(&lease).is_ok());
    }

    #[test]
    fn rejects_each_changed_lease_coordinate_independently() {
        let lease = lease();
        let overlay = ManagedSecretBindingOverlay::empty(&lease);
        let changed_attempt = Lease::new(
            lease.lease_id(),
            AttemptId::new(),
            lease.runner_id(),
            lease.fencing_token(),
            lease.issued_at(),
            lease.expires_at(),
        )
        .expect("changed attempt lease");
        let changed_lease = Lease::new(
            LeaseId::new(),
            lease.attempt_id(),
            lease.runner_id(),
            lease.fencing_token(),
            lease.issued_at(),
            lease.expires_at(),
        )
        .expect("changed lease identity");
        let changed_fence = Lease::new(
            lease.lease_id(),
            lease.attempt_id(),
            lease.runner_id(),
            FencingToken::new(8).expect("changed fence"),
            lease.issued_at(),
            lease.expires_at(),
        )
        .expect("changed lease fence");

        for changed in [changed_attempt, changed_lease, changed_fence] {
            assert_eq!(
                overlay.validate_for(&changed),
                Err(ManagedSecretBindingOverlayError::LeaseMismatch)
            );
        }
    }

    #[test]
    fn rejects_reordering_even_with_a_matching_digest() {
        let lease = lease();
        let mut overlay = ManagedSecretBindingOverlay::new(
            &lease,
            [
                (
                    "TOKEN_A".to_owned(),
                    binding(
                        "00000000-0000-4000-8000-000000000001",
                        "00000000-0000-4000-8000-000000000011",
                    ),
                ),
                (
                    "TOKEN_B".to_owned(),
                    binding(
                        "00000000-0000-4000-8000-000000000002",
                        "00000000-0000-4000-8000-000000000012",
                    ),
                ),
            ],
        )
        .expect("overlay");
        overlay.bindings.reverse();
        overlay.digest = overlay.compute_digest();

        assert_eq!(
            overlay.validate_canonical(),
            Err(ManagedSecretBindingOverlayError::NoncanonicalOrder)
        );
    }

    #[test]
    fn serde_rejects_digest_substitution() {
        let lease = lease();
        let overlay = ManagedSecretBindingOverlay::new(
            &lease,
            [(
                "TOKEN_A".to_owned(),
                binding(
                    "00000000-0000-4000-8000-000000000001",
                    "00000000-0000-4000-8000-000000000011",
                ),
            )],
        )
        .expect("overlay");

        let mut value = serde_json::to_value(&overlay).expect("serialize");
        value["digest"] = serde_json::Value::String("00".repeat(32));
        assert!(serde_json::from_value::<ManagedSecretBindingOverlay>(value).is_err());
    }

    #[test]
    fn serde_rejects_forward_overlay_schema() {
        let overlay = ManagedSecretBindingOverlay::empty(&lease());
        let mut value = serde_json::to_value(overlay).expect("serialize overlay");
        value["schema_version"] = serde_json::json!(
            super::MANAGED_SECRET_BINDING_OVERLAY_SCHEMA_VERSION
                .checked_add(1)
                .expect("test schema")
        );

        let error = serde_json::from_value::<ManagedSecretBindingOverlay>(value)
            .expect_err("forward schema must fail closed");
        assert!(error.to_string().contains("unsupported"));
    }
}
