use automata_ci_blob::{
    BlobDescriptor, BlobKey, BlobPayload, BlobStoreErrorKind, ImmutableBlobStore, MediaType,
    MemoryBlobStore, PutBlobOutcome, ReclaimableBlobStore,
};
use automata_ci_core::Sha256Digest;
use bytes::Bytes;
use static_assertions::assert_obj_safe;

assert_obj_safe!(ImmutableBlobStore);
assert_obj_safe!(ReclaimableBlobStore);

fn payload(key: &str, value: &'static [u8]) -> BlobPayload {
    BlobPayload::from_bytes(
        BlobKey::new(key).expect("key"),
        MediaType::new("application/octet-stream").expect("media type"),
        Bytes::from_static(value),
    )
}

#[test]
fn values_reject_ambiguous_keys_and_media_types() {
    for key in ["", "/absolute", "a//b", "a/./b", "a/../b", "a\\b"] {
        assert!(BlobKey::new(key).is_err(), "accepted {key:?}");
    }
    for media_type in ["", "application", "application//json", "text/plain; x=1"] {
        assert!(
            MediaType::new(media_type).is_err(),
            "accepted {media_type:?}"
        );
    }
}

#[test]
fn payload_verification_is_size_and_digest_exact() {
    let valid = payload("jobs/one", b"job-ir");
    let descriptor = valid.descriptor().clone();
    assert!(BlobPayload::verify(descriptor.clone(), valid.bytes().clone()).is_ok());

    let wrong_size = BlobDescriptor::new(
        descriptor.key().clone(),
        descriptor.digest(),
        descriptor.size() + 1,
        descriptor.media_type().clone(),
    );
    assert!(BlobPayload::verify(wrong_size, valid.bytes().clone()).is_err());

    let wrong_digest = BlobDescriptor::new(
        descriptor.key().clone(),
        Sha256Digest::from_bytes([7; 32]),
        descriptor.size(),
        descriptor.media_type().clone(),
    );
    assert!(BlobPayload::verify(wrong_digest, valid.bytes().clone()).is_err());
}

#[tokio::test]
async fn immutable_put_replays_only_an_exact_object() {
    let store = MemoryBlobStore::default();
    let first = payload("jobs/one", b"job-ir");
    assert_eq!(
        store.put_if_absent(first.clone()).await.expect("create"),
        PutBlobOutcome::Created
    );
    assert_eq!(
        store
            .put_if_absent(first.clone())
            .await
            .expect("exact retry"),
        PutBlobOutcome::AlreadyPresent
    );

    let conflict = payload("jobs/one", b"different");
    let error = store
        .put_if_absent(conflict)
        .await
        .expect_err("immutable conflict");
    assert_eq!(error.kind(), BlobStoreErrorKind::Conflict);

    let loaded = store
        .get_verified(first.descriptor(), first.descriptor().size())
        .await
        .expect("verified read");
    assert_eq!(loaded.bytes(), first.bytes());
}

#[tokio::test]
async fn reads_fail_closed_on_limits_and_metadata_mismatch() {
    let store = MemoryBlobStore::default();
    let first = payload("jobs/one", b"job-ir");
    store
        .put_if_absent(first.clone())
        .await
        .expect("create fixture");

    let error = store
        .get_verified(first.descriptor(), first.descriptor().size() - 1)
        .await
        .expect_err("read ceiling");
    assert_eq!(error.kind(), BlobStoreErrorKind::TooLarge);

    let wrong = BlobDescriptor::new(
        first.descriptor().key().clone(),
        Sha256Digest::from_bytes([9; 32]),
        first.descriptor().size(),
        first.descriptor().media_type().clone(),
    );
    let error = store
        .get_verified(&wrong, wrong.size())
        .await
        .expect_err("descriptor mismatch");
    assert_eq!(error.kind(), BlobStoreErrorKind::Integrity);
}

#[tokio::test]
async fn reclamation_is_exact_and_idempotent() {
    let store = MemoryBlobStore::default();
    let first = payload("cache/unreachable", b"cache block");
    store
        .put_if_absent(first.clone())
        .await
        .expect("create fixture");

    let wrong = BlobDescriptor::new(
        first.descriptor().key().clone(),
        Sha256Digest::from_bytes([9; 32]),
        first.descriptor().size(),
        first.descriptor().media_type().clone(),
    );
    let error = store
        .delete_if_present(&wrong)
        .await
        .expect_err("mismatched descriptor must not delete");
    assert_eq!(error.kind(), BlobStoreErrorKind::Conflict);

    store
        .delete_if_present(first.descriptor())
        .await
        .expect("delete unreachable object");
    store
        .delete_if_present(first.descriptor())
        .await
        .expect("deletion replay");
    let error = store
        .get_verified(first.descriptor(), first.descriptor().size())
        .await
        .expect_err("deleted object is absent");
    assert_eq!(error.kind(), BlobStoreErrorKind::NotFound);
}
