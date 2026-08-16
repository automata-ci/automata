use std::{env, time::Duration};

use automata_ci_blob::{
    BlobKey, BlobPayload, BlobStoreErrorKind, ImmutableBlobStore, MediaType, PutBlobOutcome,
};
use automata_ci_blob_s3::{S3AtRestEncryption, S3BlobStoreConfig, StaticS3Credentials};
use bytes::Bytes;
use url::Url;

#[tokio::test]
#[ignore = "requires an explicitly configured S3-compatible test service"]
async fn rustfs_conditional_put_and_verified_read_contract() {
    let endpoint = env::var("AUTOMATA_TEST_S3_ENDPOINT").expect("AUTOMATA_TEST_S3_ENDPOINT");
    let endpoint = Url::parse(&endpoint).expect("test endpoint URL");
    let bucket = env::var("AUTOMATA_TEST_S3_BUCKET").expect("AUTOMATA_TEST_S3_BUCKET");
    let access_key = env::var("AUTOMATA_TEST_S3_ACCESS_KEY").expect("AUTOMATA_TEST_S3_ACCESS_KEY");
    let secret_key = env::var("AUTOMATA_TEST_S3_SECRET_KEY").expect("AUTOMATA_TEST_S3_SECRET_KEY");
    let config = S3BlobStoreConfig::loopback_development(
        endpoint,
        "us-east-1",
        bucket.clone(),
        Some("contract/immutable-v1".to_owned()),
        Duration::from_secs(20),
    )
    .expect("test S3 config")
    .with_at_rest_encryption(
        S3AtRestEncryption::aws_kms(
            env::var("AUTOMATA_TEST_S3_KMS_KEY_ID").expect("AUTOMATA_TEST_S3_KMS_KEY_ID"),
        )
        .expect("test S3 KMS key identity"),
    );
    let store = config
        .connect(StaticS3Credentials::new(access_key, secret_key, None).expect("test credentials"))
        .expect("test S3 store");
    store
        .ensure_bucket()
        .await
        .expect("test bucket must be ready");
    let payload = BlobPayload::from_bytes(
        BlobKey::new("stable-object").expect("key"),
        MediaType::new("application/octet-stream").expect("media type"),
        Bytes::from_static(b"automata-rustfs-immutable-contract-v1"),
    );

    let first = store
        .put_if_absent(payload.clone())
        .await
        .expect("first or prior contract object");
    assert!(matches!(
        first,
        PutBlobOutcome::Created | PutBlobOutcome::AlreadyPresent
    ));
    assert_eq!(
        store
            .put_if_absent(payload.clone())
            .await
            .expect("idempotent retry"),
        PutBlobOutcome::AlreadyPresent
    );
    let loaded = store
        .get_verified(payload.descriptor(), payload.descriptor().size())
        .await
        .expect("verified read");
    assert_eq!(loaded.bytes(), payload.bytes());

    let conflict = BlobPayload::from_bytes(
        payload.descriptor().key().clone(),
        payload.descriptor().media_type().clone(),
        Bytes::from_static(b"different immutable bytes"),
    );
    let error = store
        .put_if_absent(conflict)
        .await
        .expect_err("immutable overwrite");
    assert_eq!(error.kind(), BlobStoreErrorKind::Conflict);
}
