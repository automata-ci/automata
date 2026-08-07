mod support;

use std::collections::BTreeSet;

use automata_auth::{
    github::{
        DeviceAuthorizationStatus, DeviceCodeResponse, DevicePollOutcome, GithubAppProtocol,
        GithubDevicePollResponse, GithubEndpointError, GithubFlowError,
    },
    time::UnixTimestamp,
    vault::{
        ProviderAccessToken, ProviderGrantKind, ProviderRefreshToken, ProviderTokenMetadata,
        ProviderTokenSet,
    },
};
use futures::executor::block_on;
use url::Url;

use support::{MockGithubEndpoint, config, secret, token_response};

fn device_response(verification_uri: &str) -> DeviceCodeResponse {
    DeviceCodeResponse {
        device_code: secret("device-code"),
        user_code: secret("ABCD-EFGH"),
        verification_uri: Url::parse(verification_uri).expect("verification URL"),
        expires_in: 900,
        interval: 5,
    }
}

#[test]
fn device_flow_enforces_interval_and_slow_down() {
    let protocol = GithubAppProtocol::new(config());
    let endpoint = MockGithubEndpoint::default();
    endpoint.push_device_code(Ok(device_response("https://github.com/login/device")));
    let mut authorization =
        block_on(protocol.begin_device(&endpoint, UnixTimestamp::from_seconds(100)))
            .expect("begin device flow");
    assert_eq!(authorization.user_code(), "ABCD-EFGH");
    assert_eq!(
        authorization.next_poll_at(),
        UnixTimestamp::from_seconds(105)
    );
    assert!(!format!("{authorization:?}").contains("ABCD-EFGH"));

    let early = block_on(protocol.poll_device(
        &endpoint,
        &mut authorization,
        UnixTimestamp::from_seconds(104),
    ));
    assert!(matches!(early, Err(GithubFlowError::PollTooEarly { .. })));
    assert_eq!(
        endpoint
            .observed
            .lock()
            .expect("observations")
            .device_poll_calls,
        0
    );

    endpoint.push_device_poll(Ok(GithubDevicePollResponse::AuthorizationPending));
    let pending = block_on(protocol.poll_device(
        &endpoint,
        &mut authorization,
        UnixTimestamp::from_seconds(105),
    ))
    .expect("pending poll");
    assert!(matches!(
        pending,
        DevicePollOutcome::Pending {
            next_poll_at
        } if next_poll_at == UnixTimestamp::from_seconds(110)
    ));

    endpoint.push_device_poll(Ok(GithubDevicePollResponse::SlowDown));
    let slowed = block_on(protocol.poll_device(
        &endpoint,
        &mut authorization,
        UnixTimestamp::from_seconds(110),
    ))
    .expect("slow-down poll");
    assert!(matches!(
        slowed,
        DevicePollOutcome::Pending {
            next_poll_at
        } if next_poll_at == UnixTimestamp::from_seconds(120)
    ));
    assert_eq!(authorization.poll_interval_seconds(), 10);

    endpoint.push_device_poll(Ok(GithubDevicePollResponse::Token(token_response())));
    let complete = block_on(protocol.poll_device(
        &endpoint,
        &mut authorization,
        UnixTimestamp::from_seconds(120),
    ))
    .expect("complete poll");
    let DevicePollOutcome::Complete(tokens) = complete else {
        panic!("expected complete device authorization");
    };
    assert_eq!(
        tokens.metadata().grant_kind(),
        ProviderGrantKind::DeviceAuthorization
    );
    assert_eq!(authorization.status(), DeviceAuthorizationStatus::Complete);

    let terminal = block_on(protocol.poll_device(
        &endpoint,
        &mut authorization,
        UnixTimestamp::from_seconds(130),
    ));
    assert!(matches!(terminal, Err(GithubFlowError::DeviceFlowTerminal)));
}

#[test]
fn transient_endpoint_failure_still_advances_poll_deadline() {
    let protocol = GithubAppProtocol::new(config());
    let endpoint = MockGithubEndpoint::default();
    endpoint.push_device_code(Ok(device_response("https://github.com/login/device")));
    endpoint.push_device_poll(Err(GithubEndpointError::Unavailable));
    let mut authorization =
        block_on(protocol.begin_device(&endpoint, UnixTimestamp::from_seconds(10)))
            .expect("begin device flow");

    let failed = block_on(protocol.poll_device(
        &endpoint,
        &mut authorization,
        UnixTimestamp::from_seconds(15),
    ));
    assert!(matches!(failed, Err(GithubFlowError::Endpoint(_))));
    assert_eq!(
        authorization.next_poll_at(),
        UnixTimestamp::from_seconds(20)
    );

    let too_early = block_on(protocol.poll_device(
        &endpoint,
        &mut authorization,
        UnixTimestamp::from_seconds(19),
    ));
    assert!(matches!(
        too_early,
        Err(GithubFlowError::PollTooEarly { .. })
    ));
}

#[test]
fn device_flow_rejects_phishing_verification_origins() {
    let protocol = GithubAppProtocol::new(config());
    let endpoint = MockGithubEndpoint::default();
    endpoint.push_device_code(Ok(device_response("https://evil.example/login/device")));
    let result = block_on(protocol.begin_device(&endpoint, UnixTimestamp::from_seconds(100)));
    assert!(matches!(
        result,
        Err(GithubFlowError::InvalidProviderResponse)
    ));
}

#[test]
fn local_expiration_stops_polling_without_network_io() {
    let protocol = GithubAppProtocol::new(config());
    let endpoint = MockGithubEndpoint::default();
    endpoint.push_device_code(Ok(device_response("https://github.com/login/device")));
    let mut authorization =
        block_on(protocol.begin_device(&endpoint, UnixTimestamp::from_seconds(100)))
            .expect("begin device flow");
    let result = block_on(protocol.poll_device(
        &endpoint,
        &mut authorization,
        UnixTimestamp::from_seconds(1_000),
    ))
    .expect("local expiration outcome");
    assert!(matches!(result, DevicePollOutcome::Expired));
    assert_eq!(authorization.status(), DeviceAuthorizationStatus::Expired);
    assert_eq!(
        endpoint
            .observed
            .lock()
            .expect("observations")
            .device_poll_calls,
        0
    );
}

fn provider_tokens(grant_kind: ProviderGrantKind, refresh_expiry: u64) -> ProviderTokenSet {
    let config = config();
    ProviderTokenSet::new(
        ProviderAccessToken::new(secret("old-access")),
        Some(ProviderRefreshToken::new(secret("old-refresh"))),
        ProviderTokenMetadata::builder(
            config.provider_id().clone(),
            grant_kind,
            "bearer",
            UnixTimestamp::from_seconds(1),
        )
        .scopes(BTreeSet::default())
        .access_expires_at(Some(UnixTimestamp::from_seconds(2)))
        .refresh_expires_at(Some(UnixTimestamp::from_seconds(refresh_expiry)))
        .build()
        .expect("valid token metadata"),
    )
    .expect("valid provider token set")
}

#[test]
fn refresh_uses_grant_specific_client_auth_and_rotates_tokens() {
    let protocol = GithubAppProtocol::new(config());
    let endpoint = MockGithubEndpoint::default();
    endpoint.push_refresh(Ok(token_response()));
    let browser = provider_tokens(ProviderGrantKind::BrowserAuthorizationCode, 1_000);
    let replacement =
        block_on(protocol.refresh(&endpoint, &browser, UnixTimestamp::from_seconds(100)))
            .expect("refresh browser grant");
    assert_eq!(
        replacement.access_token().expose_secret(),
        "ghu_access_token_value"
    );
    assert_eq!(
        endpoint
            .observed
            .lock()
            .expect("observations")
            .refresh_had_client_secret,
        Some(true)
    );

    endpoint.push_refresh(Ok(token_response()));
    let device = provider_tokens(ProviderGrantKind::DeviceAuthorization, 1_000);
    block_on(protocol.refresh(&endpoint, &device, UnixTimestamp::from_seconds(100)))
        .expect("refresh device grant");
    assert_eq!(
        endpoint
            .observed
            .lock()
            .expect("observations")
            .refresh_had_client_secret,
        Some(false)
    );
}

#[test]
fn expired_refresh_is_rejected_before_network_io() {
    let protocol = GithubAppProtocol::new(config());
    let endpoint = MockGithubEndpoint::default();
    let current = provider_tokens(ProviderGrantKind::DeviceAuthorization, 100);
    let result = block_on(protocol.refresh(&endpoint, &current, UnixTimestamp::from_seconds(100)));
    assert!(matches!(result, Err(GithubFlowError::RefreshExpired)));
    assert_eq!(
        endpoint
            .observed
            .lock()
            .expect("observations")
            .refresh_calls,
        0
    );
}
