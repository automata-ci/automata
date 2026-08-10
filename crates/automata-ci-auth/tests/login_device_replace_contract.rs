use automata_ci_auth::{
    human::{ProviderId, TenantId},
    login::{
        LoginBindingDigest, LoginBindingDigestKeyId, LoginTransactionAccess,
        LoginTransactionBinding, LoginTransactionId, LoginTransactionPurpose,
        LoginTransactionState, LoginTransactionValueError, LoginTransactionVersion,
        ReplaceLoginTransactionState,
    },
    secret::SecretBytes,
    time::UnixTimestamp,
};
use static_assertions::assert_not_impl_any;

assert_not_impl_any!(ReplaceLoginTransactionState: Clone, serde::Serialize);

const LOGIN_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

fn binding(key_id: &str, byte: u8) -> LoginTransactionBinding {
    LoginTransactionBinding::new(
        LoginBindingDigestKeyId::new(key_id).expect("binding key ID"),
        LoginBindingDigest::new([byte; 32]),
    )
}

fn purpose() -> LoginTransactionPurpose {
    LoginTransactionPurpose::SignIn {
        tenant_id: TenantId::new("tenant-a").expect("tenant ID"),
    }
}

fn device_request(interval_milliseconds: u64) -> ReplaceLoginTransactionState {
    ReplaceLoginTransactionState::new(
        LoginTransactionAccess::device(
            LoginTransactionId::new(LOGIN_ID).expect("login ID"),
            purpose(),
            ProviderId::new("github").expect("provider ID"),
            binding("device-poll-v1", 7),
        ),
        LoginTransactionVersion::new(4).expect("version"),
        LoginTransactionState::new(
            SecretBytes::new(b"new-encrypted-provider-state".to_vec()).expect("state"),
        ),
    )
    .next_device_poll_at(UnixTimestamp::from_seconds(180))
    .device_poll_interval_milliseconds(interval_milliseconds)
}

#[test]
fn device_poll_schedule_is_one_redacted_nonserializable_cas_command() {
    let request = device_request(10_000);

    assert_eq!(
        request.next_poll_at(),
        Some(UnixTimestamp::from_seconds(180))
    );
    assert_eq!(request.poll_interval_milliseconds(), Some(10_000));
    request.validate().expect("valid device poll metadata");

    let debug = format!("{request:?}");
    assert!(!debug.contains("new-encrypted-provider-state"));
    assert!(!debug.contains("7, 7"));
    assert!(debug.contains("LoginTransactionState([REDACTED])"));
}

#[test]
fn replacement_reuses_exact_current_device_poll_interval_bounds() {
    device_request(1_000).validate().expect("minimum interval");
    device_request(300_000)
        .validate()
        .expect("maximum interval");
    assert_eq!(
        device_request(999).validate(),
        Err(LoginTransactionValueError::InvalidPollInterval)
    );
    assert_eq!(
        device_request(300_001).validate(),
        Err(LoginTransactionValueError::InvalidPollInterval)
    );
}

#[test]
fn browser_replacements_reject_all_device_poll_metadata() {
    let browser_access = LoginTransactionAccess::browser(
        LoginTransactionId::new(LOGIN_ID).expect("login ID"),
        purpose(),
        ProviderId::new("github").expect("provider ID"),
        binding("oauth-state-v1", 1),
        binding("browser-cookie-v1", 2),
    )
    .expect("browser access");
    let replacement = || {
        ReplaceLoginTransactionState::new(
            browser_access.clone(),
            LoginTransactionVersion::new(1).expect("version"),
            LoginTransactionState::new(SecretBytes::new(vec![1]).expect("state")),
        )
    };

    assert_eq!(
        replacement()
            .device_poll_interval_milliseconds(5_000)
            .validate(),
        Err(LoginTransactionValueError::UnexpectedDevicePollMetadata)
    );
    assert_eq!(
        replacement()
            .next_device_poll_at(UnixTimestamp::from_seconds(120))
            .validate(),
        Err(LoginTransactionValueError::UnexpectedDevicePollMetadata)
    );
}
