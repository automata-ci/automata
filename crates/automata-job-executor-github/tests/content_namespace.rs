use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use automata_blob::{
    BlobDescriptor, BlobPayload, BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore,
    PutBlobOutcome, VerifiedBlob,
};
use automata_core::{JobContentReference, Sha256Digest};
use automata_job_executor_github::{ImmutableJobContent, JobContentPort, PortErrorKind};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};

#[tokio::test]
async fn event_fetch_uses_the_exact_admitted_logical_key_without_a_second_prefix() {
    let bytes = Bytes::from_static(br#"{"ref":"refs/heads/main"}"#);
    let digest = Sha256Digest::from_bytes(Sha256::digest(&bytes).into());
    let reference = JobContentReference::new(
        "admission/v1/workflow-event/sha256/exact-event",
        digest,
        u64::try_from(bytes.len()).expect("event size"),
        "application/json",
    );
    let store = Arc::new(RecordingStore::new(bytes));
    let content = ImmutableJobContent::new(store.clone(), 1024).expect("content adapter");

    let loaded = content.load(&reference).await.expect("verified event");

    assert_eq!(loaded, br#"{"ref":"refs/heads/main"}"#.as_slice());
    let descriptor = store.requested().expect("requested descriptor");
    assert_eq!(descriptor.key().as_str(), reference.object_key());
    assert_eq!(descriptor.digest(), reference.digest());
    assert_eq!(descriptor.size(), reference.encoded_size());
    assert_eq!(descriptor.media_type().as_str(), reference.media_type());
}

#[tokio::test]
async fn namespace_mismatch_fails_closed_as_missing_content() {
    let bytes = Bytes::from_static(b"{}");
    let digest = Sha256Digest::from_bytes(Sha256::digest(&bytes).into());
    let reference = JobContentReference::new(
        "admission/v1/workflow-event/sha256/missing",
        digest,
        2,
        "application/json",
    );
    let content = ImmutableJobContent::new(Arc::new(MissingStore), 1024).expect("content adapter");

    let error = content.load(&reference).await.expect_err("missing event");

    assert_eq!(error.kind(), PortErrorKind::NotFound);
}

#[derive(Debug)]
struct RecordingStore {
    bytes: Bytes,
    requested: Mutex<Option<BlobDescriptor>>,
}

impl RecordingStore {
    fn new(bytes: Bytes) -> Self {
        Self {
            bytes,
            requested: Mutex::new(None),
        }
    }

    fn requested(&self) -> Option<BlobDescriptor> {
        self.requested.lock().expect("request lock").clone()
    }
}

#[async_trait]
impl ImmutableBlobStore for RecordingStore {
    async fn put_if_absent(&self, _payload: BlobPayload) -> Result<PutBlobOutcome, BlobStoreError> {
        unreachable!("read-only test store")
    }

    async fn get_verified(
        &self,
        descriptor: &BlobDescriptor,
        maximum_bytes: u64,
    ) -> Result<VerifiedBlob, BlobStoreError> {
        assert!(descriptor.size() <= maximum_bytes);
        *self.requested.lock().expect("request lock") = Some(descriptor.clone());
        let payload = BlobPayload::verify(descriptor.clone(), self.bytes.clone())
            .expect("fixture descriptor matches bytes");
        Ok(VerifiedBlob::from_payload(payload))
    }
}

#[derive(Debug)]
struct MissingStore;

#[async_trait]
impl ImmutableBlobStore for MissingStore {
    async fn put_if_absent(&self, _payload: BlobPayload) -> Result<PutBlobOutcome, BlobStoreError> {
        unreachable!("read-only test store")
    }

    async fn get_verified(
        &self,
        _descriptor: &BlobDescriptor,
        _maximum_bytes: u64,
    ) -> Result<VerifiedBlob, BlobStoreError> {
        Err(BlobStoreError::new(BlobStoreErrorKind::NotFound))
    }
}
