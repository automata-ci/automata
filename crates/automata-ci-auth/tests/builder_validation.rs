use std::collections::BTreeSet;

use automata_ci_auth::{
    human::{ProviderId, ProviderSubject},
    time::UnixTimestamp,
    vault::{ProviderGrantKind, ProviderTokenMetadata, ProviderTokenMetadataError},
};

fn provider_id() -> ProviderId {
    ProviderId::new("github").expect("provider ID")
}

fn provider_subject() -> ProviderSubject {
    ProviderSubject::new("42").expect("provider subject")
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
