use automata_ci_key_management::KeyEncryptionProvider;

static_assertions::assert_obj_safe!(KeyEncryptionProvider);

#[test]
fn key_encryption_provider_is_object_safe() {
    fn accepts(_: &dyn KeyEncryptionProvider) {}
    let _ = accepts;
}
