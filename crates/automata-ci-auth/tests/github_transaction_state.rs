mod support;

use automata_ci_auth::{
    github::{
        DeviceAuthorization, DeviceAuthorizationParts, DeviceAuthorizationStatus,
        GithubDeviceTransactionMetadata, GithubTransactionStateCodec, GithubTransactionStateError,
    },
    login::LoginTransactionState,
    secret::SecretBytes,
    time::UnixTimestamp,
};
use url::Url;

use support::{DeterministicRandom, config, secret};

#[test]
fn browser_state_uses_database_authoritative_durable_times() {
    let protocol = automata_ci_auth::github::GithubAppProtocol::new(config());
    let authorization = protocol
        .begin_web(
            &DeterministicRandom::new(7),
            UnixTimestamp::from_seconds(100),
        )
        .expect("begin web flow");
    let original_state = authorization.transaction().state_secret().to_owned();
    let encoded = GithubTransactionStateCodec::encode_web(authorization.into_transaction())
        .expect("encode web state");
    let decoded = GithubTransactionStateCodec::decode_web(
        encoded,
        UnixTimestamp::from_seconds(101),
        UnixTimestamp::from_seconds(701),
    )
    .expect("decode state after database-time rebase");

    assert_eq!(decoded.state_secret(), original_state);
    assert_eq!(decoded.created_at(), UnixTimestamp::from_seconds(101));
    assert_eq!(decoded.expires_at(), UnixTimestamp::from_seconds(701));
}

#[test]
fn browser_state_rejects_trailing_and_cross_kind_bytes() {
    let protocol = automata_ci_auth::github::GithubAppProtocol::new(config());
    let authorization = protocol
        .begin_web(
            &DeterministicRandom::new(11),
            UnixTimestamp::from_seconds(100),
        )
        .expect("begin web flow");
    let encoded = GithubTransactionStateCodec::encode_web(authorization.into_transaction())
        .expect("encode web state")
        .into_secret();
    let mut trailing = encoded.expose_secret().to_vec();
    trailing.push(0);
    let trailing = LoginTransactionState::new(SecretBytes::new(trailing).expect("state bytes"));
    assert_eq!(
        GithubTransactionStateCodec::decode_web(
            trailing,
            UnixTimestamp::from_seconds(100),
            UnixTimestamp::from_seconds(700),
        )
        .expect_err("trailing byte must fail"),
        GithubTransactionStateError::InvalidState,
    );

    let metadata = metadata(100, 700, 105, 5_000);
    let cross_kind = LoginTransactionState::new(
        SecretBytes::new(encoded.expose_secret().to_vec()).expect("state bytes"),
    );
    assert_eq!(
        GithubTransactionStateCodec::decode_device(
            cross_kind,
            metadata,
            protocol.config().endpoints(),
        )
        .expect_err("browser state cannot decode as device state"),
        GithubTransactionStateError::InvalidState,
    );
}

#[test]
fn device_state_uses_database_authoritative_poll_schedule_after_rebase() {
    let endpoints =
        automata_ci_auth::github::GithubEndpoints::github_dot_com().expect("trusted endpoints");
    let authorization = device_authorization(100, 700, 105, 5);
    let (encoded, caller_metadata) = GithubTransactionStateCodec::encode_device(authorization)
        .expect("encode pending device state");
    let rendered = format!("{caller_metadata:?}");
    assert!(!rendered.contains("ABCD-EFGH"));
    let (user_code, verification_uri, _, _, _, interval) = caller_metadata.into_parts();
    let database_metadata = GithubDeviceTransactionMetadata::new(
        user_code,
        verification_uri,
        UnixTimestamp::from_seconds(100),
        UnixTimestamp::from_seconds(700),
        UnixTimestamp::from_seconds(106),
        interval,
    )
    .expect("database-rebased metadata");
    let decoded =
        GithubTransactionStateCodec::decode_device(encoded, database_metadata, &endpoints)
            .expect("decode state after database-time rebase");

    assert_eq!(decoded.user_code(), "ABCD-EFGH");
    assert_eq!(decoded.created_at(), UnixTimestamp::from_seconds(100));
    assert_eq!(decoded.expires_at(), UnixTimestamp::from_seconds(700));
    assert_eq!(decoded.next_poll_at(), UnixTimestamp::from_seconds(106));
    assert_eq!(decoded.poll_interval_seconds(), 5);
}

#[test]
fn device_state_rejects_legacy_and_trailing_encodings() {
    let endpoints =
        automata_ci_auth::github::GithubEndpoints::github_dot_com().expect("trusted endpoints");

    for mutation in ["legacy", "trailing"] {
        let authorization = device_authorization(100, 700, 105, 5);
        let (encoded, metadata) = GithubTransactionStateCodec::encode_device(authorization)
            .expect("encode pending device state");
        let mut bytes = encoded.into_secret().expose_secret().to_vec();
        if mutation == "legacy" {
            bytes[7] = b'1';
        } else {
            bytes.push(0);
        }
        let state = LoginTransactionState::new(SecretBytes::new(bytes).expect("state bytes"));
        assert_eq!(
            GithubTransactionStateCodec::decode_device(state, metadata, &endpoints)
                .expect_err("unsupported device state must fail"),
            GithubTransactionStateError::InvalidState,
        );
    }
}

#[test]
fn device_state_rejects_terminal_and_nonintegral_poll_metadata() {
    let endpoints =
        automata_ci_auth::github::GithubEndpoints::github_dot_com().expect("trusted endpoints");
    let terminal = DeviceAuthorization::from_parts(
        DeviceAuthorizationParts::new(
            secret("device-code"),
            secret("ABCD-EFGH"),
            Url::parse("https://github.com/login/device").expect("verification URL"),
            UnixTimestamp::from_seconds(100),
            UnixTimestamp::from_seconds(700),
            UnixTimestamp::from_seconds(105),
            5,
            DeviceAuthorizationStatus::Denied,
        ),
        &endpoints,
    )
    .expect("valid terminal protocol value");
    assert_eq!(
        GithubTransactionStateCodec::encode_device(terminal)
            .expect_err("terminal state is never durably pending"),
        GithubTransactionStateError::InvalidState,
    );

    assert_eq!(
        GithubDeviceTransactionMetadata::new(
            secret("ABCD-EFGH"),
            "https://github.com/login/device",
            UnixTimestamp::from_seconds(100),
            UnixTimestamp::from_seconds(700),
            UnixTimestamp::from_seconds(105),
            5_001,
        )
        .expect_err("millisecond metadata must represent whole provider seconds"),
        GithubTransactionStateError::InvalidMetadata,
    );
}

fn device_authorization(
    created: u64,
    expires: u64,
    next_poll: u64,
    interval: u64,
) -> DeviceAuthorization {
    let endpoints =
        automata_ci_auth::github::GithubEndpoints::github_dot_com().expect("trusted endpoints");
    DeviceAuthorization::from_parts(
        DeviceAuthorizationParts::new(
            secret("device-code"),
            secret("ABCD-EFGH"),
            Url::parse("https://github.com/login/device").expect("verification URL"),
            UnixTimestamp::from_seconds(created),
            UnixTimestamp::from_seconds(expires),
            UnixTimestamp::from_seconds(next_poll),
            interval,
            DeviceAuthorizationStatus::Pending,
        ),
        &endpoints,
    )
    .expect("valid device authorization")
}

fn metadata(
    created: u64,
    expires: u64,
    next_poll: u64,
    interval_milliseconds: u64,
) -> GithubDeviceTransactionMetadata {
    GithubDeviceTransactionMetadata::new(
        secret("ABCD-EFGH"),
        "https://github.com/login/device",
        UnixTimestamp::from_seconds(created),
        UnixTimestamp::from_seconds(expires),
        UnixTimestamp::from_seconds(next_poll),
        interval_milliseconds,
    )
    .expect("valid durable metadata")
}
