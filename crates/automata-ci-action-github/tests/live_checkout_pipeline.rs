use std::{env, sync::Arc, time::Duration};

use automata_ci_action::{
    ActionBundleLimits, ActionResolver, ActionSubpath, ImmutableActionResolver,
    RepositoryActionRequest,
};
use automata_ci_action_github::{
    ActionExecution, ActionMetadataDecoder, GithubActionMetadataDecoder, JavascriptRuntime,
};
use automata_ci_blob_s3::{
    S3AtRestEncryption, S3BlobStore, S3BlobStoreConfig, StaticS3Credentials,
};
use automata_ci_github::GithubHttpEndpoint;
use automata_ci_scm::{RepositoryId, RevisionSpec};
use url::Url;

const CHECKOUT_COMMIT: &str = "de0fac2e4500dabe0009e67214ff5f5447ce83dd";

/// Opt-in contract covering the complete immutable action admission path:
/// GitHub revision resolution, archive validation, `RustFS` publication, and
/// generic metadata decoding. No checkout behavior is implemented specially.
#[tokio::test]
#[ignore = "requires public GitHub access and an explicitly configured RustFS test bucket"]
async fn resolves_and_decodes_the_exact_checkout_action() {
    let endpoint =
        Url::parse(&env::var("AUTOMATA_TEST_S3_ENDPOINT").expect("AUTOMATA_TEST_S3_ENDPOINT"))
            .expect("test S3 endpoint URL");
    let config = S3BlobStoreConfig::loopback_development(
        endpoint,
        "us-east-1",
        env::var("AUTOMATA_TEST_S3_BUCKET").expect("AUTOMATA_TEST_S3_BUCKET"),
        Some("contract/action-metadata-v1".to_owned()),
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
    let blobs = S3BlobStore::new(config.client(credentials), &config);
    let github =
        GithubHttpEndpoint::github_dot_com("automata-live-test/0.1.0").expect("GitHub endpoint");
    let repository = RepositoryId::new("actions/checkout").expect("repository");
    let revision = RevisionSpec::new(CHECKOUT_COMMIT).expect("revision");
    let subpath = ActionSubpath::root();
    let resolver = ImmutableActionResolver::new(Arc::new(github), Arc::new(blobs));

    let bundle = resolver
        .resolve(RepositoryActionRequest::public(
            &repository,
            &revision,
            &subpath,
            ActionBundleLimits::default(),
        ))
        .await
        .expect("resolve immutable checkout action");
    let metadata = GithubActionMetadataDecoder::default()
        .decode(bundle.definition())
        .expect("decode checkout metadata generically");

    assert_eq!(bundle.resolved_revision().as_str(), CHECKOUT_COMMIT);
    assert_eq!(metadata.inputs().len(), 20);
    let ActionExecution::Javascript(javascript) = metadata.execution() else {
        panic!("checkout must remain a JavaScript action");
    };
    assert_eq!(javascript.runtime(), JavascriptRuntime::Node24);
    assert_eq!(javascript.main().as_str(), "dist/index.js");
    assert_eq!(
        javascript.post().expect("checkout cleanup").as_str(),
        "dist/index.js"
    );
    assert_eq!(javascript.post_condition().text(), "always()");
}
