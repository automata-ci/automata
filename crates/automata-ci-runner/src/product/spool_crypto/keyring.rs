use std::{collections::BTreeMap, fmt};

use automata_ci_runner_spool::{
    ContentCommitmentDomain, ContentProtectionError, ContentProtector, DurableContentRef,
    ProtectionId,
};

use super::{aes_gcm::Aes256GcmContentProtector, error::ContentProtectorConfigurationError};

/// Maximum number of old local spool keys retained for online rotation.
pub(in crate::product) const MAX_DECRYPT_ONLY_CONTENT_KEYS: usize = 8;

/// AES-256-GCM spool keyring with one active and bounded decrypt-only keys.
///
/// The active protector is the only protector permitted for new writes.
/// Existing objects are authenticated with the exact key ID recorded in their
/// [`DurableContentRef`]. Missing IDs fail closed; no key is tried speculatively.
pub(in crate::product) struct Aes256GcmContentKeyring {
    active: Aes256GcmContentProtector,
    decrypt_only: BTreeMap<ProtectionId, Aes256GcmContentProtector>,
}

impl Aes256GcmContentKeyring {
    /// Builds a bounded rotation-aware keyring from initialized protectors.
    ///
    /// # Errors
    ///
    /// Rejects more than [`MAX_DECRYPT_ONLY_CONTENT_KEYS`] old keys and any
    /// protection ID duplicated within the old set or shared with the active
    /// protector.
    pub(in crate::product) fn new(
        active: Aes256GcmContentProtector,
        decrypt_only: Vec<Aes256GcmContentProtector>,
    ) -> Result<Self, ContentProtectorConfigurationError> {
        if decrypt_only.len() > MAX_DECRYPT_ONLY_CONTENT_KEYS {
            return Err(ContentProtectorConfigurationError::TooManyDecryptOnlyKeys);
        }

        let active_id = active.protection_id();
        let mut old_by_id = BTreeMap::new();
        for protector in decrypt_only {
            if protector.protection_id() == active_id
                || old_by_id
                    .insert(protector.protection_id().clone(), protector)
                    .is_some()
            {
                return Err(ContentProtectorConfigurationError::DuplicateProtectionId);
            }
        }

        Ok(Self {
            active,
            decrypt_only: old_by_id,
        })
    }

    /// Returns the non-secret IDs retained for decrypt-only reads.
    #[cfg(test)]
    pub(super) fn decrypt_only_ids(&self) -> impl ExactSizeIterator<Item = &ProtectionId> {
        self.decrypt_only.keys()
    }

    fn protector_for(
        &self,
        protection_id: &ProtectionId,
    ) -> Result<&Aes256GcmContentProtector, ContentProtectionError> {
        if protection_id == self.active.protection_id() {
            return Ok(&self.active);
        }
        self.decrypt_only
            .get(protection_id)
            .ok_or(ContentProtectionError::KeyUnavailable)
    }
}

impl fmt::Debug for Aes256GcmContentKeyring {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Aes256GcmContentKeyring")
            .field("active_id", self.active.protection_id())
            .field(
                "decrypt_only_ids",
                &self.decrypt_only.keys().collect::<Vec<_>>(),
            )
            .field("algorithm", &"AES-256-GCM")
            .field("key_material", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl ContentProtector for Aes256GcmContentKeyring {
    fn protection_id(&self) -> &ProtectionId {
        self.active.protection_id()
    }

    fn supports_protection_id(&self, protection_id: &ProtectionId) -> bool {
        protection_id == self.active.protection_id()
            || self.decrypt_only.contains_key(protection_id)
    }

    fn keyed_commitment(
        &self,
        protection_id: &ProtectionId,
        domain: ContentCommitmentDomain,
        material_digest: &[u8; 32],
    ) -> Result<[u8; 32], ContentProtectionError> {
        self.protector_for(protection_id)?
            .keyed_commitment(protection_id, domain, material_digest)
    }

    fn endpoint_result_protected_bytes(
        &self,
        plaintext_bytes: u64,
    ) -> Result<u64, ContentProtectionError> {
        self.active.endpoint_result_protected_bytes(plaintext_bytes)
    }

    fn protect(
        &self,
        reference: &DurableContentRef,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ContentProtectionError> {
        self.active.protect(reference, plaintext)
    }

    fn unprotect(
        &self,
        reference: &DurableContentRef,
        protected: &[u8],
    ) -> Result<Vec<u8>, ContentProtectionError> {
        self.protector_for(reference.protection_id())?
            .unprotect(reference, protected)
    }
}
