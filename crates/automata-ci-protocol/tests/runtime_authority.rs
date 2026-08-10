use automata_ci_protocol::{
    RuntimeAuthorityCredential, RuntimeAuthorityEndpoint, RuntimeAuthorityEndpointSecurity,
    RuntimeAuthorityError,
};

#[test]
fn endpoint_transport_policy_is_explicit_and_round_trips() {
    let endpoints = [
        RuntimeAuthorityEndpoint::new("https://results.example.test/").expect("TLS endpoint"),
        RuntimeAuthorityEndpoint::loopback_development("http://results.automata.localhost:8080/")
            .expect("loopback endpoint"),
        RuntimeAuthorityEndpoint::trusted_private_development(
            "http://host.containers.internal:8081/",
        )
        .expect("trusted private endpoint"),
    ];
    assert_eq!(
        endpoints[0].security(),
        RuntimeAuthorityEndpointSecurity::Tls
    );
    assert_eq!(
        endpoints[1].security(),
        RuntimeAuthorityEndpointSecurity::LoopbackDevelopment
    );
    assert_eq!(
        endpoints[2].security(),
        RuntimeAuthorityEndpointSecurity::TrustedPrivateDevelopment
    );
    for endpoint in endpoints {
        let encoded = serde_json::to_string(&endpoint).expect("serialize endpoint");
        let decoded: RuntimeAuthorityEndpoint =
            serde_json::from_str(&encoded).expect("deserialize endpoint");
        assert_eq!(decoded, endpoint);
    }
}

#[test]
fn endpoint_security_modes_cannot_be_relabelled() {
    assert_eq!(
        RuntimeAuthorityEndpoint::new("http://127.0.0.1:8080/"),
        Err(RuntimeAuthorityError::InvalidEndpoint)
    );
    assert_eq!(
        RuntimeAuthorityEndpoint::loopback_development("http://10.88.0.1:8080/"),
        Err(RuntimeAuthorityError::InvalidEndpoint)
    );
    assert_eq!(
        RuntimeAuthorityEndpoint::trusted_private_development("http://127.0.0.1:8080/"),
        Err(RuntimeAuthorityError::InvalidEndpoint)
    );
    assert_eq!(
        RuntimeAuthorityEndpoint::trusted_private_development("http://203.0.113.10:8080/"),
        Err(RuntimeAuthorityError::InvalidEndpoint)
    );
    let forged = r#"{"url":"http://host.containers.internal:8081/","security":"tls"}"#;
    assert!(serde_json::from_str::<RuntimeAuthorityEndpoint>(forged).is_err());
}

#[test]
fn credential_debug_is_redacted() {
    let secret = "eyJhbGciOiJIUzI1NiJ9.fixture.signature";
    let credential = RuntimeAuthorityCredential::new(secret).expect("credential");
    let debug = format!("{credential:?}");
    assert!(!debug.contains(secret));
    assert!(debug.contains("REDACTED"));
}
