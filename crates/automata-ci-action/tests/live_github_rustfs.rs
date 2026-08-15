use std::{env, sync::Arc, time::Duration};

use automata_ci_action::{
    ActionBundleLimits, ActionDefinitionKind, ActionResolver, ActionSubpath,
    ImmutableActionResolver, RepositoryActionRequest,
};
use automata_ci_blob_s3::{
    S3AtRestEncryption, S3BlobStore, S3BlobStoreConfig, StaticS3Credentials,
};
use automata_ci_github::GithubHttpEndpoint;
use automata_ci_scm::{RepositoryId, RevisionSpec};
use url::Url;

const CHECKOUT_COMMIT: &str = "de0fac2e4500dabe0009e67214ff5f5447ce83dd";

/// Opt-in contract covering GitHub resolution, archive inspection, and `RustFS`
/// immutable publication through only provider-neutral application ports.
#[tokio::test]
#[ignore = "requires public GitHub access and an explicitly configured RustFS test bucket"]
async fn resolves_pinned_checkout_from_github_into_rustfs() {
    let endpoint =
        Url::parse(&env::var("AUTOMATA_TEST_S3_ENDPOINT").expect("AUTOMATA_TEST_S3_ENDPOINT"))
            .expect("test S3 endpoint URL");
    let config = S3BlobStoreConfig::loopback_development(
        endpoint,
        "us-east-1",
        env::var("AUTOMATA_TEST_S3_BUCKET").expect("AUTOMATA_TEST_S3_BUCKET"),
        Some("contract/action-bundles-v1".to_owned()),
        Duration::from_secs(30),
    )
    .expect("test S3 configuration")
    .with_at_rest_encryption(
        S3AtRestEncryption::aws_kms(
            env::var("AUTOMATA_TEST_S3_KMS_KEY_ID").expect("AUTOMATA_TEST_S3_KMS_KEY_ID"),
        )
        .expect("test S3 KMS key identity"),
    );
    let credentials = StaticS3Credentials::new(
        env::var("AUTOMATA_TEST_S3_ACCESS_KEY").expect("AUTOMATA_TEST_S3_ACCESS_KEY"),
        env::var("AUTOMATA_TEST_S3_SECRET_KEY").expect("AUTOMATA_TEST_S3_SECRET_KEY"),
        None,
    )
    .expect("test S3 credentials");
    let store = S3BlobStore::new(
        config.client(credentials).expect("test S3 SDK client"),
        &config,
    );
    let github = GithubHttpEndpoint::github_dot_com("automata-live-test/0.1.0").unwrap();
    let repository = RepositoryId::new("actions/checkout").unwrap();
    let revision = RevisionSpec::new(CHECKOUT_COMMIT).unwrap();
    let subpath = ActionSubpath::root();
    let resolver = ImmutableActionResolver::new(Arc::new(github), Arc::new(store));
    let bundle = resolver
        .resolve(RepositoryActionRequest::public(
            &repository,
            &revision,
            &subpath,
            ActionBundleLimits::default(),
        ))
        .await
        .expect("resolve and publish checkout action");

    assert_eq!(bundle.resolved_revision().as_str(), CHECKOUT_COMMIT);
    assert_eq!(
        bundle.definition().kind(),
        ActionDefinitionKind::MetadataYaml
    );
    assert_eq!(bundle.definition().path(), "action.yml");
    assert!(bundle.definition().bytes().starts_with(b"name: 'Checkout'"));
    assert_eq!(bundle.archive().digest().to_string().len(), 64);
}
