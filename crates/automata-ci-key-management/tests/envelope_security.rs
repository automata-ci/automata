use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use async_trait::async_trait;
use automata_ci_key_management::{
    AES_256_GCM_KEY_BYTES, ENVELOPE_SCHEMA_V1, EncryptedEnvelope, EnvelopeCodec, EnvelopeError,
    KeyEncryptionContext, KeyEncryptionError, KeyEncryptionProvider, KeyId, KeyPurpose,
    LocalAes256GcmKeyring, LocalKeyMaterial, LocalKeyringConfigurationError,
    MAX_ENVELOPE_CIPHERTEXT_BYTES, MAX_ENVELOPE_PLAINTEXT_BYTES, PreparedEnvelope, SecretBytes,
    WrappedDataKey,
};
use futures::executor::block_on;
use static_assertions::assert_not_impl_any;

fn key_id(value: &str) -> KeyId {
    KeyId::new(value).expect("key ID")
}

fn key_material(value: &str, marker: u8) -> LocalKeyMaterial {
    LocalKeyMaterial::new(
        key_id(value),
        SecretBytes::new(vec![marker; AES_256_GCM_KEY_BYTES]).expect("key bytes"),
    )
    .expect("key material")
}

fn keyring(
    active: (&str, u8),
    decrypt_only: &[(&str, u8)],
    retired: &[&str],
) -> Arc<LocalAes256GcmKeyring> {
    Arc::new(
        LocalAes256GcmKeyring::new(
            key_material(active.0, active.1),
            decrypt_only
                .iter()
                .map(|(id, marker)| key_material(id, *marker))
                .collect(),
            retired.iter().map(|id| key_id(id)),
        )
        .expect("keyring"),
    )
}

fn context(tenant: &str, purpose: &str, record: &str) -> KeyEncryptionContext {
    KeyEncryptionContext::new(tenant, KeyPurpose::new(purpose).expect("purpose"), record)
        .expect("context")
}

fn plaintext() -> SecretBytes {
    SecretBytes::from_utf8("provider refresh token and metadata".to_owned()).expect("plaintext")
}

assert_not_impl_any!(PreparedEnvelope: Clone, Copy);

fn rebuild(
    schema: u16,
    key_id: KeyId,
    wrapped_ciphertext: Vec<u8>,
    nonce: [u8; automata_ci_key_management::ENVELOPE_NONCE_BYTES],
    ciphertext: Vec<u8>,
) -> EncryptedEnvelope {
    EncryptedEnvelope::from_parts(
        schema,
        WrappedDataKey::new(key_id, wrapped_ciphertext).expect("wrapped key"),
        nonce,
        ciphertext,
    )
    .expect("envelope")
}

#[test]
fn round_trip_uses_fresh_deks_and_nonces_with_redacted_diagnostics() {
    let keyring = keyring(("key-a", 0x11), &[], &[]);
    let codec = EnvelopeCodec::new(keyring.clone());
    let context = context("tenant-a", "auth/provider-tokens:v1", "identity-1");

    let first = block_on(codec.seal(&context, plaintext())).expect("seal");
    let second = block_on(codec.seal(&context, plaintext())).expect("seal again");

    assert_eq!(first.schema(), ENVELOPE_SCHEMA_V1);
    assert_eq!(first.wrapping_key_id(), &key_id("key-a"));
    assert_ne!(first.nonce(), second.nonce(), "fresh payload nonce");
    assert_ne!(
        first.ciphertext(),
        second.ciphertext(),
        "fresh DEK and nonce"
    );
    assert_ne!(
        first.wrapped_data_key().ciphertext(),
        second.wrapped_data_key().ciphertext(),
        "fresh wrapping nonce"
    );
    assert!(
        !first
            .ciphertext()
            .windows(b"provider refresh token".len())
            .any(|window| window == b"provider refresh token")
    );

    let opened = block_on(codec.open(&context, &first)).expect("open");
    assert_eq!(
        opened.expose_secret(),
        b"provider refresh token and metadata"
    );
    for rendered in [
        format!("{keyring:?}"),
        format!("{codec:?}"),
        format!("{first:?}"),
    ] {
        assert!(!rendered.contains("provider refresh token"));
        assert!(!rendered.contains("111111111111"));
    }
}

#[test]
fn noncurrent_envelope_schema_is_rejected_before_decryption() {
    let codec = EnvelopeCodec::new(keyring(("key-a", 0x12), &[], &[]));
    let context = context("tenant-a", "auth/provider-tokens:v1", "identity-1");
    let envelope = block_on(codec.seal(&context, plaintext())).expect("seal");
    let future_schema = ENVELOPE_SCHEMA_V1.checked_add(1).expect("test schema");
    let altered = rebuild(
        future_schema,
        envelope.wrapping_key_id().clone(),
        envelope.wrapped_data_key().ciphertext().to_vec(),
        *envelope.nonce(),
        envelope.ciphertext().to_vec(),
    );

    assert_eq!(
        block_on(codec.open(&context, &altered)).unwrap_err(),
        EnvelopeError::UnsupportedSchema
    );
}

#[test]
fn prepared_seal_is_move_only_fully_redacted_and_provider_free() {
    let provider = Arc::new(CountingContextBlindProvider::new(false));
    let codec = EnvelopeCodec::new(provider.clone());
    let wrapping_context = context(
        "tenant-a",
        "auth/runtime-authority-wrapping:v1",
        "provider-identity-1",
    );
    let payload_context = context("tenant-a", "auth/runtime-authority-payload:v1", "request-1");

    let prepared = block_on(codec.prepare(&wrapping_context)).expect("prepare");
    assert_eq!(provider.wrap_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.unwrap_calls.load(Ordering::SeqCst), 0);
    assert_eq!(format!("{prepared:?}"), "PreparedEnvelope([REDACTED])");

    let envelope = prepared.seal_prepared(&payload_context, plaintext());
    assert_eq!(provider.wrap_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.unwrap_calls.load(Ordering::SeqCst), 0);

    let opened = block_on(codec.open_with_contexts(&wrapping_context, &payload_context, &envelope))
        .expect("open distinct contexts");
    assert_eq!(provider.unwrap_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        opened.expose_secret(),
        b"provider refresh token and metadata"
    );
}

#[test]
fn preparation_failure_happens_before_any_plaintext_is_accepted() {
    let provider = Arc::new(CountingContextBlindProvider::new(true));
    let codec = EnvelopeCodec::new(provider.clone());
    let wrapping_context = context(
        "tenant-a",
        "auth/runtime-authority-wrapping:v1",
        "provider-identity-1",
    );

    assert_eq!(
        block_on(codec.prepare(&wrapping_context)).unwrap_err(),
        EnvelopeError::KeyEncryption(KeyEncryptionError::Unavailable)
    );
    assert_eq!(provider.wrap_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.unwrap_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn distinct_wrapping_and_payload_contexts_fail_closed_independently() {
    let codec = EnvelopeCodec::new(keyring(("key-a", 0x1a), &[], &[]));
    let wrapping_context = context(
        "tenant-a",
        "auth/runtime-authority-wrapping:v1",
        "provider-identity-1",
    );
    let payload_context = context("tenant-a", "auth/runtime-authority-payload:v1", "request-1");
    let envelope = block_on(codec.prepare(&wrapping_context))
        .expect("prepare")
        .seal_prepared(&payload_context, plaintext());

    for wrong_wrapping_context in [
        context(
            "tenant-b",
            "auth/runtime-authority-wrapping:v1",
            "provider-identity-1",
        ),
        context(
            "tenant-a",
            "auth/runtime-authority-other:v1",
            "provider-identity-1",
        ),
        context(
            "tenant-a",
            "auth/runtime-authority-wrapping:v1",
            "provider-identity-2",
        ),
    ] {
        assert_eq!(
            block_on(codec.open_with_contexts(
                &wrong_wrapping_context,
                &payload_context,
                &envelope,
            ))
            .unwrap_err(),
            EnvelopeError::KeyEncryption(KeyEncryptionError::AuthenticationFailed)
        );
    }

    let wrong_payload_context =
        context("tenant-a", "auth/runtime-authority-payload:v1", "request-2");
    assert_eq!(
        block_on(codec.open_with_contexts(&wrapping_context, &wrong_payload_context, &envelope,))
            .unwrap_err(),
        EnvelopeError::AuthenticationFailed
    );
    assert_eq!(
        block_on(codec.open(&payload_context, &envelope)).unwrap_err(),
        EnvelopeError::KeyEncryption(KeyEncryptionError::AuthenticationFailed)
    );
}

#[test]
fn exact_maximum_envelope_round_trips_and_reconstructs_from_durable_parts() {
    let codec = EnvelopeCodec::new(keyring(("key-a", 0x19), &[], &[]));
    let context = context("tenant-a", "runner/payload:v1", "command-16-mib");
    let plaintext = SecretBytes::new(vec![0xa7; MAX_ENVELOPE_PLAINTEXT_BYTES])
        .expect("maximum-sized plaintext");

    let envelope = block_on(codec.seal(&context, plaintext)).expect("seal maximum-sized payload");
    assert_eq!(envelope.ciphertext().len(), MAX_ENVELOPE_CIPHERTEXT_BYTES);
    let (schema, wrapped, nonce, ciphertext) = envelope.into_parts();
    let reconstructed = EncryptedEnvelope::from_parts(schema, wrapped, nonce, ciphertext)
        .expect("reconstruct maximum-sized envelope");

    let opened = block_on(codec.open(&context, &reconstructed))
        .expect("open maximum-sized reconstructed envelope");
    assert_eq!(opened.len(), MAX_ENVELOPE_PLAINTEXT_BYTES);
    assert!(opened.expose_secret().iter().all(|byte| *byte == 0xa7));

    let rendered = format!("{reconstructed:?}");
    assert!(rendered.contains(&MAX_ENVELOPE_CIPHERTEXT_BYTES.to_string()));
    assert!(!rendered.contains("a7a7a7"));
}

#[test]
fn oversized_plaintext_and_reconstructed_ciphertext_are_rejected() {
    assert!(SecretBytes::new(vec![0x6c; MAX_ENVELOPE_PLAINTEXT_BYTES + 1]).is_err());

    let wrapped = WrappedDataKey::new(key_id("key-a"), vec![0x42; AES_256_GCM_KEY_BYTES])
        .expect("wrapped key");
    let oversized = EncryptedEnvelope::from_parts(
        ENVELOPE_SCHEMA_V1,
        wrapped,
        [0x24; automata_ci_key_management::ENVELOPE_NONCE_BYTES],
        vec![0x6c; MAX_ENVELOPE_CIPHERTEXT_BYTES + 1],
    );
    assert_eq!(oversized.unwrap_err(), EnvelopeError::InvalidEnvelope);
    assert!(
        !EnvelopeError::InvalidEnvelope
            .to_string()
            .contains("6c6c6c")
    );
}

#[test]
fn wrong_tenant_purpose_and_record_are_rejected() {
    let codec = EnvelopeCodec::new(keyring(("key-a", 0x21), &[], &[]));
    let original = context("tenant-a", "actions/secrets:v1", "secret-version-1");
    let envelope = block_on(codec.seal(&original, plaintext())).expect("seal");

    for wrong in [
        context("tenant-b", "actions/secrets:v1", "secret-version-1"),
        context("tenant-a", "auth/provider-tokens:v1", "secret-version-1"),
        context("tenant-a", "actions/secrets:v1", "secret-version-2"),
    ] {
        assert_eq!(
            block_on(codec.open(&wrong, &envelope)).unwrap_err(),
            EnvelopeError::KeyEncryption(KeyEncryptionError::AuthenticationFailed)
        );
    }
}

#[derive(Debug)]
struct ContextBlindTestProvider {
    key_id: KeyId,
}

#[derive(Debug)]
struct CountingContextBlindProvider {
    key_id: KeyId,
    wrap_calls: AtomicUsize,
    unwrap_calls: AtomicUsize,
    fail_wrap: bool,
}

impl CountingContextBlindProvider {
    fn new(fail_wrap: bool) -> Self {
        Self {
            key_id: key_id("counting-test-key"),
            wrap_calls: AtomicUsize::new(0),
            unwrap_calls: AtomicUsize::new(0),
            fail_wrap,
        }
    }
}

#[async_trait]
impl KeyEncryptionProvider for CountingContextBlindProvider {
    async fn wrap_data_key(
        &self,
        plaintext_key: &SecretBytes,
        _context: &KeyEncryptionContext,
    ) -> Result<WrappedDataKey, KeyEncryptionError> {
        self.wrap_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_wrap {
            return Err(KeyEncryptionError::Unavailable);
        }
        WrappedDataKey::new(self.key_id.clone(), plaintext_key.expose_secret().to_vec())
            .map_err(|_| KeyEncryptionError::InvalidCiphertext)
    }

    async fn unwrap_data_key(
        &self,
        wrapped_key: &WrappedDataKey,
        _context: &KeyEncryptionContext,
    ) -> Result<SecretBytes, KeyEncryptionError> {
        self.unwrap_calls.fetch_add(1, Ordering::SeqCst);
        SecretBytes::new(wrapped_key.ciphertext().to_vec())
            .map_err(|_| KeyEncryptionError::InvalidDataKey)
    }
}

#[async_trait]
impl KeyEncryptionProvider for ContextBlindTestProvider {
    async fn wrap_data_key(
        &self,
        plaintext_key: &SecretBytes,
        _context: &KeyEncryptionContext,
    ) -> Result<WrappedDataKey, KeyEncryptionError> {
        WrappedDataKey::new(self.key_id.clone(), plaintext_key.expose_secret().to_vec())
            .map_err(|_| KeyEncryptionError::InvalidCiphertext)
    }

    async fn unwrap_data_key(
        &self,
        wrapped_key: &WrappedDataKey,
        _context: &KeyEncryptionContext,
    ) -> Result<SecretBytes, KeyEncryptionError> {
        SecretBytes::new(wrapped_key.ciphertext().to_vec())
            .map_err(|_| KeyEncryptionError::InvalidDataKey)
    }
}

#[test]
fn payload_aad_independently_rejects_every_context_identity_swap() {
    let codec = EnvelopeCodec::new(Arc::new(ContextBlindTestProvider {
        key_id: key_id("test-key"),
    }));
    let wrapping_context = context("tenant-a", "actions/wrapping:v1", "identity-a");
    let payload_context = context("tenant-a", "actions/secrets:v1", "row-a");
    let envelope = block_on(codec.prepare(&wrapping_context))
        .expect("prepare")
        .seal_prepared(&payload_context, plaintext());

    for wrong_payload_context in [
        context("tenant-b", "actions/secrets:v1", "row-a"),
        context("tenant-a", "actions/variables:v1", "row-a"),
        context("tenant-a", "actions/secrets:v1", "row-b"),
    ] {
        assert_eq!(
            block_on(codec.open_with_contexts(
                &wrapping_context,
                &wrong_payload_context,
                &envelope,
            ))
            .unwrap_err(),
            EnvelopeError::AuthenticationFailed
        );
    }
}

#[test]
fn every_envelope_component_fails_closed_when_tampered() {
    let codec = EnvelopeCodec::new(keyring(("key-a", 0x31), &[], &[]));
    let context = context("tenant-a", "actions/secrets:v1", "row-a");
    let envelope = block_on(codec.seal(&context, plaintext())).expect("seal");
    let wrapped_bytes = envelope.wrapped_data_key().ciphertext().to_vec();
    let ciphertext = envelope.ciphertext().to_vec();
    let nonce = *envelope.nonce();

    let mut altered_ciphertext = ciphertext.clone();
    altered_ciphertext[0] ^= 0x80;
    let altered = rebuild(
        envelope.schema(),
        envelope.wrapping_key_id().clone(),
        wrapped_bytes.clone(),
        nonce,
        altered_ciphertext,
    );
    assert_eq!(
        block_on(codec.open(&context, &altered)).unwrap_err(),
        EnvelopeError::AuthenticationFailed
    );

    let mut altered_nonce = nonce;
    altered_nonce[0] ^= 0x40;
    let altered = rebuild(
        envelope.schema(),
        envelope.wrapping_key_id().clone(),
        wrapped_bytes.clone(),
        altered_nonce,
        ciphertext.clone(),
    );
    assert_eq!(
        block_on(codec.open(&context, &altered)).unwrap_err(),
        EnvelopeError::AuthenticationFailed
    );

    let mut altered_wrapped = wrapped_bytes;
    let last = altered_wrapped.len() - 1;
    altered_wrapped[last] ^= 0x20;
    let altered = rebuild(
        envelope.schema(),
        envelope.wrapping_key_id().clone(),
        altered_wrapped,
        nonce,
        ciphertext.clone(),
    );
    assert_eq!(
        block_on(codec.open(&context, &altered)).unwrap_err(),
        EnvelopeError::KeyEncryption(KeyEncryptionError::AuthenticationFailed)
    );

    let altered = rebuild(
        2,
        envelope.wrapping_key_id().clone(),
        envelope.wrapped_data_key().ciphertext().to_vec(),
        nonce,
        ciphertext,
    );
    assert_eq!(
        block_on(codec.open(&context, &altered)).unwrap_err(),
        EnvelopeError::UnsupportedSchema
    );
}

#[test]
fn unknown_and_retired_key_ids_are_distinct_failures() {
    let original_codec = EnvelopeCodec::new(keyring(("key-a", 0x41), &[], &[]));
    let context = context("tenant-a", "actions/secrets:v1", "row-a");
    let envelope = block_on(original_codec.seal(&context, plaintext())).expect("seal");

    let unknown = rebuild(
        envelope.schema(),
        key_id("unknown-key"),
        envelope.wrapped_data_key().ciphertext().to_vec(),
        *envelope.nonce(),
        envelope.ciphertext().to_vec(),
    );
    assert_eq!(
        block_on(original_codec.open(&context, &unknown)).unwrap_err(),
        EnvelopeError::KeyEncryption(KeyEncryptionError::UnknownKey)
    );

    let retired_codec = EnvelopeCodec::new(keyring(("key-b", 0x42), &[], &["key-a"]));
    assert_eq!(
        block_on(retired_codec.open(&context, &envelope)).unwrap_err(),
        EnvelopeError::KeyEncryption(KeyEncryptionError::RetiredKey)
    );
}

#[test]
fn active_key_rotation_keeps_old_reads_but_never_wraps_with_old_keys() {
    let old_codec = EnvelopeCodec::new(keyring(("key-a", 0x51), &[], &[]));
    let context = context("tenant-a", "auth/provider-tokens:v1", "identity-1");
    let old_envelope = block_on(old_codec.seal(&context, plaintext())).expect("seal old");

    let rotated_codec = EnvelopeCodec::new(keyring(("key-b", 0x52), &[("key-a", 0x51)], &[]));
    assert_eq!(
        block_on(rotated_codec.open(&context, &old_envelope))
            .expect("read old")
            .expose_secret(),
        b"provider refresh token and metadata"
    );
    let new_envelope = block_on(rotated_codec.seal(&context, plaintext())).expect("seal new");
    assert_eq!(new_envelope.wrapping_key_id(), &key_id("key-b"));
    assert_eq!(old_envelope.wrapping_key_id(), &key_id("key-a"));
    assert_eq!(
        block_on(old_codec.open(&context, &new_envelope)).unwrap_err(),
        EnvelopeError::KeyEncryption(KeyEncryptionError::UnknownKey)
    );
}

#[test]
fn local_keyring_rejects_bad_lengths_and_duplicate_or_overlapping_ids() {
    let short = LocalKeyMaterial::new(
        key_id("key-a"),
        SecretBytes::new(vec![1; AES_256_GCM_KEY_BYTES - 1]).expect("secret bytes"),
    );
    assert_eq!(
        short.unwrap_err(),
        LocalKeyringConfigurationError::InvalidKeyLength
    );

    let duplicate =
        LocalAes256GcmKeyring::new(key_material("key-a", 1), vec![key_material("key-a", 2)], []);
    assert_eq!(
        duplicate.unwrap_err(),
        LocalKeyringConfigurationError::DuplicateKeyId
    );

    let overlapping_retired =
        LocalAes256GcmKeyring::new(key_material("key-a", 1), vec![], [key_id("key-a")]);
    assert_eq!(
        overlapping_retired.unwrap_err(),
        LocalKeyringConfigurationError::DuplicateKeyId
    );
}
