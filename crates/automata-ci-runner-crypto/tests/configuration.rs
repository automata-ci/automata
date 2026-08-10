use automata_ci_runner_crypto::{AES_256_GCM_KEY_BYTES, Aes256GcmContentProtector};
use zeroize::Zeroizing;

#[test]
fn rejects_invalid_key_lengths_and_identifiers() {
    for length in [0, AES_256_GCM_KEY_BYTES - 1, AES_256_GCM_KEY_BYTES + 1] {
        assert!(Aes256GcmContentProtector::new("key-a", Zeroizing::new(vec![1; length])).is_err());
    }
    assert!(Aes256GcmContentProtector::new("../key", Zeroizing::new(vec![1; 32])).is_err());
}
