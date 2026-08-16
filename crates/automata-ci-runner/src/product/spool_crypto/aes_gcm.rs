use std::fmt;

use automata_ci_runner_spool::{
    ContentCommitmentDomain, ContentKind, ContentProtectionError, ContentProtector,
    DurableContentRef, MAX_CONTENT_OBJECT_BYTES, ProtectionId, endpoint_result_allocation,
};
use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    hmac,
    rand::{SecureRandom as _, SystemRandom},
};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use super::error::ContentProtectorConfigurationError;

/// Exact key length accepted by AES-256-GCM.
pub(in crate::product) const AES_256_GCM_KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const HEADER: &[u8; 4] = b"ASP2";
const ENCODED_OVERHEAD: usize = HEADER.len() + NONCE_BYTES + TAG_BYTES;
const ENDPOINT_RESULT_ENVELOPE_HEADER: &[u8; 4] = b"EPR1";
const ENDPOINT_RESULT_ENVELOPE_BYTES: usize = ENDPOINT_RESULT_ENVELOPE_HEADER.len() + 8 + 32;
const ENDPOINT_RESULT_MATERIAL_DOMAIN: &[u8] = b"automata.runner.endpoint-result.material.v1\0";
const AAD_DOMAIN: &[u8] = b"automata.runner.spool.aes256gcm.v2\0";
const COMMITMENT_KEY_DOMAIN: &[u8] = b"automata.runner.spool.commitment-key.v1\0";

/// AES-256-GCM implementation of the runner spool protection boundary.
///
/// Each object receives a fresh 96-bit random nonce. The complete durable
/// content identity is authenticated as associated data, so ciphertext cannot
/// be substituted across kinds, digests, sizes, cache keys, or key IDs.
pub(in crate::product) struct Aes256GcmContentProtector {
    id: ProtectionId,
    key: LessSafeKey,
    commitment_key: hmac::Key,
    random: SystemRandom,
}

impl Aes256GcmContentProtector {
    /// Consumes secret key bytes and creates a protector.
    ///
    /// `key_material` is zeroized on every return path. Use a new, stable
    /// protection ID whenever rotating key material. Existing spool objects
    /// retain their original ID and can be opened only when this protector is
    /// retained as an explicit decrypt-only entry in a content keyring.
    ///
    /// # Errors
    ///
    /// Returns [`ContentProtectorConfigurationError`] for an invalid ID,
    /// non-32-byte key, or cryptographic provider rejection.
    pub(in crate::product) fn new(
        protection_id: impl Into<String>,
        key_material: Zeroizing<Vec<u8>>,
    ) -> Result<Self, ContentProtectorConfigurationError> {
        let id = ProtectionId::new(protection_id)
            .map_err(|_| ContentProtectorConfigurationError::InvalidProtectionId)?;
        if key_material.len() != AES_256_GCM_KEY_BYTES {
            return Err(ContentProtectorConfigurationError::InvalidKeyLength);
        }
        let root_key = hmac::Key::new(hmac::HMAC_SHA256, &key_material);
        let derived = hmac::sign(&root_key, COMMITMENT_KEY_DOMAIN);
        let commitment_key = hmac::Key::new(hmac::HMAC_SHA256, derived.as_ref());
        let key = UnboundKey::new(&AES_256_GCM, &key_material)
            .map(LessSafeKey::new)
            .map_err(|_| ContentProtectorConfigurationError::InvalidKey)?;
        drop(key_material);
        Ok(Self {
            id,
            key,
            commitment_key,
            random: SystemRandom::new(),
        })
    }

    fn matching_reference(&self, reference: &DurableContentRef) -> bool {
        reference.protection_id() == &self.id
            && match (
                reference.public_plaintext_bytes(),
                reference.endpoint_result_allocation_bytes(),
            ) {
                (Some(bytes), None) => bytes <= MAX_CONTENT_OBJECT_BYTES,
                (None, Some(bytes)) => bytes > 0,
                _ => false,
            }
    }

    fn associated_data(reference: &DurableContentRef) -> Vec<u8> {
        let cache_key = reference.cache_key().as_str().as_bytes();
        let protection_id = reference.protection_id().as_str().as_bytes();
        let mut data = Vec::with_capacity(
            AAD_DOMAIN.len() + 1 + 8 + 32 + 2 + cache_key.len() + 1 + protection_id.len(),
        );
        data.extend_from_slice(AAD_DOMAIN);
        data.push(match reference.kind() {
            ContentKind::JobIr => 1,
            ContentKind::TerminalResult => 2,
            ContentKind::LogSpool => 3,
            ContentKind::RuntimeAuthority => 4,
            ContentKind::EndpointRequest => 5,
            ContentKind::EndpointResult => 6,
        });
        match (
            reference.public_plaintext_bytes(),
            reference.public_plaintext_sha256(),
            reference.endpoint_result_allocation_bytes(),
            reference.endpoint_result_identity(),
        ) {
            (Some(bytes), Some(digest), None, None) => {
                data.push(1);
                data.extend_from_slice(&bytes.to_be_bytes());
                data.extend_from_slice(digest.as_bytes());
            }
            (None, None, Some(allocation), Some(identity)) => {
                data.push(2);
                data.extend_from_slice(&allocation.to_be_bytes());
                data.extend_from_slice(identity.as_bytes());
            }
            _ => unreachable!("validated durable content identities are kind coherent"),
        }
        let cache_length =
            u16::try_from(cache_key.len()).expect("cache keys are bounded below u16");
        data.extend_from_slice(&cache_length.to_be_bytes());
        data.extend_from_slice(cache_key);
        let protection_length =
            u8::try_from(protection_id.len()).expect("protection IDs are bounded below u8");
        data.push(protection_length);
        data.extend_from_slice(protection_id);
        data
    }

    fn endpoint_result_material_digest(
        plaintext: &[u8],
    ) -> Result<[u8; 32], ContentProtectionError> {
        let plaintext_bytes =
            u64::try_from(plaintext.len()).map_err(|_| ContentProtectionError::Failed)?;
        let plaintext_sha256: [u8; 32] = Sha256::digest(plaintext).into();
        let mut material = Sha256::new();
        material.update(ENDPOINT_RESULT_MATERIAL_DOMAIN);
        material.update(plaintext_bytes.to_be_bytes());
        material.update(plaintext_sha256);
        Ok(material.finalize().into())
    }

    fn plaintext_matches(
        &self,
        reference: &DurableContentRef,
        plaintext: &[u8],
    ) -> Result<bool, ContentProtectionError> {
        if let (Some(bytes), Some(digest)) = (
            reference.public_plaintext_bytes(),
            reference.public_plaintext_sha256(),
        ) {
            return Ok(u64::try_from(plaintext.len()) == Ok(bytes)
                && Sha256::digest(plaintext).as_slice() == digest.as_bytes());
        }
        let plaintext_bytes =
            u64::try_from(plaintext.len()).map_err(|_| ContentProtectionError::Failed)?;
        let allocation = endpoint_result_allocation(plaintext_bytes)
            .map_err(|_| ContentProtectionError::Failed)?;
        if reference.endpoint_result_allocation_bytes() != Some(allocation) {
            return Ok(false);
        }
        let material = Self::endpoint_result_material_digest(plaintext)?;
        let expected = self.keyed_commitment(
            &self.id,
            ContentCommitmentDomain::EndpointResultIdentity,
            &material,
        )?;
        let Some(actual) = reference.endpoint_result_identity() else {
            return Ok(false);
        };
        Ok(bool::from(expected.ct_eq(actual.as_bytes())))
    }

    fn protected_plaintext(
        reference: &DurableContentRef,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ContentProtectionError> {
        if reference.kind() != ContentKind::EndpointResult {
            return Ok(plaintext.to_vec());
        }
        let allocation = reference
            .endpoint_result_allocation_bytes()
            .ok_or(ContentProtectionError::Failed)?;
        let protected_plaintext_bytes = allocation
            .checked_sub(u64::try_from(ENCODED_OVERHEAD).expect("fixed overhead fits u64"))
            .and_then(|bytes| usize::try_from(bytes).ok())
            .ok_or(ContentProtectionError::Failed)?;
        let required = ENDPOINT_RESULT_ENVELOPE_BYTES
            .checked_add(plaintext.len())
            .ok_or(ContentProtectionError::Failed)?;
        if required > protected_plaintext_bytes {
            return Err(ContentProtectionError::Failed);
        }
        let mut enveloped = Vec::with_capacity(protected_plaintext_bytes);
        enveloped.extend_from_slice(ENDPOINT_RESULT_ENVELOPE_HEADER);
        enveloped.extend_from_slice(
            &u64::try_from(plaintext.len())
                .map_err(|_| ContentProtectionError::Failed)?
                .to_be_bytes(),
        );
        enveloped.extend_from_slice(&Sha256::digest(plaintext));
        enveloped.extend_from_slice(plaintext);
        enveloped.resize(protected_plaintext_bytes, 0);
        Ok(enveloped)
    }

    fn open_endpoint_result(
        &self,
        reference: &DurableContentRef,
        enveloped: &[u8],
    ) -> Result<Vec<u8>, ContentProtectionError> {
        if enveloped.len() < ENDPOINT_RESULT_ENVELOPE_BYTES
            || &enveloped[..ENDPOINT_RESULT_ENVELOPE_HEADER.len()]
                != ENDPOINT_RESULT_ENVELOPE_HEADER
        {
            return Err(ContentProtectionError::AuthenticationFailed);
        }
        let length_offset = ENDPOINT_RESULT_ENVELOPE_HEADER.len();
        let digest_offset = length_offset + 8;
        let payload_offset = digest_offset + 32;
        let plaintext_bytes = u64::from_be_bytes(
            enveloped[length_offset..digest_offset]
                .try_into()
                .map_err(|_| ContentProtectionError::AuthenticationFailed)?,
        );
        let plaintext_length = usize::try_from(plaintext_bytes)
            .map_err(|_| ContentProtectionError::AuthenticationFailed)?;
        let payload_end = payload_offset
            .checked_add(plaintext_length)
            .filter(|end| *end <= enveloped.len())
            .ok_or(ContentProtectionError::AuthenticationFailed)?;
        if enveloped[payload_end..].iter().any(|byte| *byte != 0) {
            return Err(ContentProtectionError::AuthenticationFailed);
        }
        let plaintext = enveloped[payload_offset..payload_end].to_vec();
        if Sha256::digest(&plaintext).as_slice() != &enveloped[digest_offset..payload_offset]
            || !self
                .plaintext_matches(reference, &plaintext)
                .map_err(|_| ContentProtectionError::AuthenticationFailed)?
        {
            return Err(ContentProtectionError::AuthenticationFailed);
        }
        Ok(plaintext)
    }
}

impl fmt::Debug for Aes256GcmContentProtector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Aes256GcmContentProtector")
            .field("protection_id", &self.id)
            .field("algorithm", &"AES-256-GCM")
            .field("key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl ContentProtector for Aes256GcmContentProtector {
    fn protection_id(&self) -> &ProtectionId {
        &self.id
    }

    fn keyed_commitment(
        &self,
        protection_id: &ProtectionId,
        domain: ContentCommitmentDomain,
        material_digest: &[u8; 32],
    ) -> Result<[u8; 32], ContentProtectionError> {
        if protection_id != &self.id {
            return Err(ContentProtectionError::KeyUnavailable);
        }
        let mut context = hmac::Context::with_key(&self.commitment_key);
        context.update(domain.separator());
        context.update(material_digest);
        let signature = context.sign();
        signature
            .as_ref()
            .try_into()
            .map_err(|_| ContentProtectionError::Failed)
    }

    fn endpoint_result_protected_bytes(
        &self,
        plaintext_bytes: u64,
    ) -> Result<u64, ContentProtectionError> {
        endpoint_result_allocation(plaintext_bytes).map_err(|_| ContentProtectionError::Failed)
    }

    fn protect(
        &self,
        reference: &DurableContentRef,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ContentProtectionError> {
        if !self.matching_reference(reference) {
            return Err(ContentProtectionError::KeyUnavailable);
        }
        if !self.plaintext_matches(reference, plaintext)? {
            return Err(ContentProtectionError::Failed);
        }
        let mut ciphertext = Self::protected_plaintext(reference, plaintext)?;
        let capacity = ciphertext
            .len()
            .checked_add(ENCODED_OVERHEAD)
            .ok_or(ContentProtectionError::Failed)?;
        let mut nonce_bytes = [0_u8; NONCE_BYTES];
        self.random
            .fill(&mut nonce_bytes)
            .map_err(|_| ContentProtectionError::Failed)?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        self.key
            .seal_in_place_append_tag(
                nonce,
                Aad::from(Self::associated_data(reference)),
                &mut ciphertext,
            )
            .map_err(|_| ContentProtectionError::Failed)?;
        let mut protected = Vec::with_capacity(capacity);
        protected.extend_from_slice(HEADER);
        protected.extend_from_slice(&nonce_bytes);
        protected.extend_from_slice(&ciphertext);
        Ok(protected)
    }

    fn unprotect(
        &self,
        reference: &DurableContentRef,
        protected: &[u8],
    ) -> Result<Vec<u8>, ContentProtectionError> {
        if !self.matching_reference(reference) {
            return Err(ContentProtectionError::KeyUnavailable);
        }
        let expected_length = match reference.endpoint_result_allocation_bytes() {
            Some(allocation) => allocation,
            None => reference
                .public_plaintext_bytes()
                .and_then(|bytes| {
                    bytes.checked_add(
                        u64::try_from(ENCODED_OVERHEAD)
                            .expect("the fixed protection overhead always fits u64"),
                    )
                })
                .ok_or(ContentProtectionError::AuthenticationFailed)?,
        };
        if u64::try_from(protected.len()) != Ok(expected_length)
            || &protected[..HEADER.len()] != HEADER
        {
            return Err(ContentProtectionError::AuthenticationFailed);
        }
        let nonce_bytes: [u8; NONCE_BYTES] = protected[HEADER.len()..HEADER.len() + NONCE_BYTES]
            .try_into()
            .map_err(|_| ContentProtectionError::AuthenticationFailed)?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut ciphertext = protected[HEADER.len() + NONCE_BYTES..].to_vec();
        let plaintext = self
            .key
            .open_in_place(
                nonce,
                Aad::from(Self::associated_data(reference)),
                &mut ciphertext,
            )
            .map_err(|_| ContentProtectionError::AuthenticationFailed)?;
        let opened_length = plaintext.len();
        ciphertext.truncate(opened_length);
        if reference.kind() == ContentKind::EndpointResult {
            return self.open_endpoint_result(reference, &ciphertext);
        }
        if !self
            .plaintext_matches(reference, &ciphertext)
            .map_err(|_| ContentProtectionError::AuthenticationFailed)?
        {
            return Err(ContentProtectionError::AuthenticationFailed);
        }
        Ok(ciphertext)
    }
}
