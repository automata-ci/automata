mod support;

use std::collections::BTreeSet;

use automata_auth::{
    authorization::RoleName,
    human::{
        AuthenticatedHuman, PrincipalId, ProviderCredential, ProviderId, ProviderSubject, TenantId,
    },
    machine::{AuthenticatedMachine, ExternalRunnerIdentity, MachineIdentityError},
    secret::SessionToken,
    session::{
        AutomataSessionClaims, AutomataSessionIdentity, IssuedSession, SessionId,
        SessionValidationError,
    },
    time::UnixTimestamp,
    vault::{
        KeyEncryptionContext, KeyEncryptionPurpose, ProviderAccessToken, ProviderGrantKind,
        ProviderRefreshToken, ProviderTokenKey, ProviderTokenMetadata, ProviderTokenMetadataError,
        ProviderTokenSet, ProviderTokenSetError, TokenVersion, VersionedProviderTokens,
        WrappedDataKey,
    },
};
use serde_json::json;

use support::secret;

fn provider_id() -> ProviderId {
    ProviderId::new("github").expect("provider ID")
}

fn provider_subject() -> ProviderSubject {
    ProviderSubject::new("42").expect("provider subject")
}

fn valid_metadata() -> ProviderTokenMetadata {
    ProviderTokenMetadata::builder(
        provider_id(),
        ProviderGrantKind::BrowserAuthorizationCode,
        "bearer",
        UnixTimestamp::from_seconds(100),
    )
    .provider_subject(Some(provider_subject()))
    .scopes(BTreeSet::from(["repo:status".to_owned()]))
    .access_expires_at(Some(UnixTimestamp::from_seconds(200)))
    .refresh_expires_at(Some(UnixTimestamp::from_seconds(300)))
    .build()
    .expect("valid token metadata")
}

#[test]
fn human_identity_construction_and_deserialization_share_validation() {
    let invalid = AuthenticatedHuman::new(
        PrincipalId::new("github:42").expect("principal ID"),
        provider_id(),
        provider_subject(),
        "",
        None,
        UnixTimestamp::from_seconds(100),
    );
    assert!(invalid.is_err());

    let invalid_wire = json!({
        "principal_id": "github:42",
        "provider_id": "github",
        "provider_subject": "42",
        "login": "octo\ncat",
        "display_name": null,
        "authenticated_at": 100
    });
    assert!(serde_json::from_value::<AuthenticatedHuman>(invalid_wire).is_err());

    let human = AuthenticatedHuman::new(
        PrincipalId::new("github:42").expect("principal ID"),
        provider_id(),
        provider_subject(),
        "octocat",
        Some("The Octocat".to_owned()),
        UnixTimestamp::from_seconds(100),
    )
    .expect("valid human identity");
    let encoded = serde_json::to_value(&human).expect("serialize human identity");
    assert_eq!(encoded["login"], "octocat");
    assert_eq!(encoded["display_name"], "The Octocat");
    assert_eq!(
        serde_json::from_value::<AuthenticatedHuman>(encoded).expect("deserialize human identity"),
        human
    );
}

#[test]
fn machine_identity_requires_a_non_empty_certificate_lifetime() {
    let identity = ExternalRunnerIdentity::new("runner.example/one").expect("runner identity");
    assert_eq!(
        AuthenticatedMachine::new(
            identity.clone(),
            [7; 32],
            UnixTimestamp::from_seconds(200),
            UnixTimestamp::from_seconds(200),
        ),
        Err(MachineIdentityError::InvalidCertificateLifetime)
    );

    let invalid_wire = json!({
        "external_identity": "runner.example/one",
        "certificate_sha256": vec![7; 32],
        "authenticated_at": 200,
        "certificate_expires_at": 100
    });
    assert!(serde_json::from_value::<AuthenticatedMachine>(invalid_wire).is_err());

    let machine = AuthenticatedMachine::new(
        identity,
        [7; 32],
        UnixTimestamp::from_seconds(100),
        UnixTimestamp::from_seconds(200),
    )
    .expect("valid machine identity");
    let encoded = serde_json::to_value(&machine).expect("serialize machine identity");
    let decoded: AuthenticatedMachine =
        serde_json::from_value(encoded).expect("deserialize machine identity");
    assert_eq!(decoded, machine);
    assert_eq!(machine.certificate_sha256(), &[7; 32]);
}

#[test]
fn session_claims_reject_invalid_audiences_and_lifetimes_on_every_path() {
    let make_claims = |audience: &str, issued_at: u64, expires_at: u64| {
        AutomataSessionClaims::builder(
            AutomataSessionIdentity::new(
                SessionId::new("session-1").expect("session ID"),
                TenantId::new("tenant-1").expect("tenant ID"),
                PrincipalId::new("github:42").expect("principal ID"),
                provider_id(),
                provider_subject(),
            ),
            audience,
            UnixTimestamp::from_seconds(issued_at),
            UnixTimestamp::from_seconds(expires_at),
        )
        .roles(BTreeSet::from([RoleName::new("viewer").expect("role")]))
        .authorization_revision(9)
        .build()
    };

    assert_eq!(
        make_claims("", 100, 200),
        Err(SessionValidationError::InvalidAudience)
    );
    assert_eq!(
        make_claims("automata-api", 200, 200),
        Err(SessionValidationError::InvalidLifetime)
    );

    let claims = make_claims("automata-api", 100, 200).expect("valid claims");
    let encoded = serde_json::to_value(&claims).expect("serialize claims");
    assert_eq!(encoded["authorization_revision"], 9);
    assert_eq!(encoded["audience"], "automata-api");
    assert_eq!(
        serde_json::from_value::<AutomataSessionClaims>(encoded).expect("deserialize claims"),
        claims
    );
    let issued = IssuedSession::new(
        SessionToken::from_secret(secret("automata-session-secret")),
        claims,
    );
    assert_eq!(issued.claims().audience(), "automata-api");
    assert!(!format!("{issued:?}").contains("automata-session-secret"));

    let invalid_wire = json!({
        "session_id": "session-1",
        "tenant_id": "tenant-1",
        "principal_id": "github:42",
        "provider_id": "github",
        "provider_subject": "42",
        "roles": ["viewer"],
        "audience": "automata-api",
        "issued_at": 200,
        "expires_at": 100,
        "authorization_revision": 9
    });
    assert!(serde_json::from_value::<AutomataSessionClaims>(invalid_wire).is_err());
}

#[test]
fn token_metadata_and_secret_material_cannot_become_inconsistent() {
    assert_eq!(
        ProviderTokenMetadata::builder(
            provider_id(),
            ProviderGrantKind::DeviceAuthorization,
            "bearer token",
            UnixTimestamp::from_seconds(100),
        )
        .build(),
        Err(ProviderTokenMetadataError::InvalidTokenType)
    );
    assert_eq!(
        ProviderTokenMetadata::builder(
            provider_id(),
            ProviderGrantKind::DeviceAuthorization,
            "bearer",
            UnixTimestamp::from_seconds(100),
        )
        .scopes(BTreeSet::from(["bad scope".to_owned()]))
        .build(),
        Err(ProviderTokenMetadataError::InvalidScope)
    );
    assert_eq!(
        ProviderTokenMetadata::builder(
            provider_id(),
            ProviderGrantKind::DeviceAuthorization,
            "bearer",
            UnixTimestamp::from_seconds(100),
        )
        .access_expires_at(Some(UnixTimestamp::from_seconds(100)))
        .build(),
        Err(ProviderTokenMetadataError::InvalidAccessLifetime)
    );

    assert!(matches!(
        ProviderTokenSet::new(
            ProviderAccessToken::new(secret("access-token")),
            None,
            valid_metadata(),
        ),
        Err(ProviderTokenSetError::RefreshMetadataWithoutToken)
    ));

    let metadata = valid_metadata();
    let encoded = serde_json::to_value(&metadata).expect("serialize token metadata");
    assert_eq!(encoded["grant_kind"], "browser_authorization_code");
    assert_eq!(
        serde_json::from_value::<ProviderTokenMetadata>(encoded)
            .expect("deserialize token metadata"),
        metadata
    );

    let tokens = ProviderTokenSet::new(
        ProviderAccessToken::new(secret("access-token-value")),
        Some(ProviderRefreshToken::new(secret("refresh-token-value"))),
        metadata,
    )
    .expect("valid provider token set");
    let rendered = format!("{tokens:?}");
    assert!(!rendered.contains("access-token-value"));
    assert!(!rendered.contains("refresh-token-value"));
    let versioned = VersionedProviderTokens::new(TokenVersion::new(3), tokens);
    assert_eq!(versioned.version().value(), 3);
    assert_eq!(versioned.tokens().metadata().provider_id(), &provider_id());
    let rendered = format!("{versioned:?}");
    assert!(!rendered.contains("access-token-value"));
    assert!(!rendered.contains("refresh-token-value"));
}

#[test]
fn vault_keys_and_encryption_purposes_are_typed_and_round_trip_safely() {
    let credential = ProviderCredential::new(provider_id(), secret("provider-access-secret"));
    assert_eq!(credential.provider_id().as_str(), "github");
    assert!(!format!("{credential:?}").contains("provider-access-secret"));

    let key = ProviderTokenKey::new(
        TenantId::new("tenant-1").expect("tenant ID"),
        provider_id(),
        provider_subject(),
    );
    let encoded = serde_json::to_value(&key).expect("serialize token key");
    assert_eq!(encoded["tenant_id"], "tenant-1");
    assert_eq!(
        serde_json::from_value::<ProviderTokenKey>(encoded).expect("deserialize token key"),
        key
    );

    assert!(KeyEncryptionPurpose::new("").is_err());
    assert!(KeyEncryptionPurpose::new("provider tokens").is_err());
    let purpose = KeyEncryptionPurpose::new("auth/provider-tokens:v1").expect("encryption purpose");
    let context = KeyEncryptionContext::new(TenantId::new("tenant-1").expect("tenant ID"), purpose);
    assert_eq!(context.tenant_id().as_str(), "tenant-1");
    assert_eq!(context.purpose().as_str(), "auth/provider-tokens:v1");

    let wrapped = WrappedDataKey::new(vec![11, 22, 33]).expect("wrapped data key");
    assert!(!format!("{wrapped:?}").contains("11, 22, 33"));
    assert_eq!(wrapped.into_ciphertext(), vec![11, 22, 33]);
}
