use std::collections::BTreeSet;

use automata_auth::{
    human::{PrincipalId, ProviderId, ProviderSubject, TenantId},
    session::{AutomataSessionClaims, AutomataSessionIdentity, SessionId, SessionValidationError},
    time::UnixTimestamp,
    vault::{ProviderGrantKind, ProviderTokenMetadata, ProviderTokenMetadataError},
};

fn provider_id() -> ProviderId {
    ProviderId::new("github").expect("provider ID")
}

fn provider_subject() -> ProviderSubject {
    ProviderSubject::new("42").expect("provider subject")
}

fn session_identity() -> AutomataSessionIdentity {
    AutomataSessionIdentity::new(
        SessionId::new("session-1").expect("session ID"),
        TenantId::new("tenant-1").expect("tenant ID"),
        PrincipalId::new("github:42").expect("principal ID"),
        provider_id(),
        provider_subject(),
    )
}

#[test]
fn session_claims_builder_preserves_defaults_and_validates_required_policy() {
    let claims = AutomataSessionClaims::builder(
        session_identity(),
        "automata-api",
        UnixTimestamp::from_seconds(100),
        UnixTimestamp::from_seconds(200),
    )
    .build()
    .expect("valid claims");
    assert!(claims.roles().is_empty());
    assert_eq!(claims.authorization_revision(), 0);

    assert_eq!(
        AutomataSessionClaims::builder(
            session_identity(),
            "bad\naudience",
            UnixTimestamp::from_seconds(100),
            UnixTimestamp::from_seconds(200),
        )
        .build(),
        Err(SessionValidationError::InvalidAudience)
    );
    assert_eq!(
        AutomataSessionClaims::builder(
            session_identity(),
            "automata-api",
            UnixTimestamp::from_seconds(200),
            UnixTimestamp::from_seconds(200),
        )
        .build(),
        Err(SessionValidationError::InvalidLifetime)
    );
}

#[test]
fn token_metadata_builder_validates_each_optional_collection_and_lifetime() {
    let issued_at = UnixTimestamp::from_seconds(100);
    let metadata = ProviderTokenMetadata::builder(
        provider_id(),
        ProviderGrantKind::DeviceAuthorization,
        "bearer",
        issued_at,
    )
    .provider_subject(Some(provider_subject()))
    .scopes(BTreeSet::from(["repo:status".to_owned()]))
    .access_expires_at(Some(UnixTimestamp::from_seconds(200)))
    .build()
    .expect("valid token metadata");
    assert_eq!(metadata.provider_subject(), Some(&provider_subject()));
    assert_eq!(metadata.scopes().len(), 1);

    assert_eq!(
        ProviderTokenMetadata::builder(
            provider_id(),
            ProviderGrantKind::DeviceAuthorization,
            "bearer",
            issued_at,
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
            issued_at,
        )
        .refresh_expires_at(Some(issued_at))
        .build(),
        Err(ProviderTokenMetadataError::InvalidRefreshLifetime)
    );
}
