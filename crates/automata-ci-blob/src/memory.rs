use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;

use crate::{
    BlobDescriptor, BlobPayload, BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore,
    PutBlobOutcome, VerifiedBlob,
};

/// Deterministic in-memory adapter for application and contract tests.
#[derive(Clone, Debug, Default)]
pub struct MemoryBlobStore {
    objects: Arc<RwLock<BTreeMap<String, BlobPayload>>>,
}

#[async_trait]
impl ImmutableBlobStore for MemoryBlobStore {
    async fn put_if_absent(&self, payload: BlobPayload) -> Result<PutBlobOutcome, BlobStoreError> {
        let key = payload.descriptor().key().as_str().to_owned();
        let mut objects = self
            .objects
            .write()
            .map_err(|_| BlobStoreError::new(BlobStoreErrorKind::Unavailable))?;
        match objects.get(&key) {
            Some(existing) if existing == &payload => Ok(PutBlobOutcome::AlreadyPresent),
            Some(_) => Err(BlobStoreError::new(BlobStoreErrorKind::Conflict)),
            None => {
                objects.insert(key, payload);
                Ok(PutBlobOutcome::Created)
            }
        }
    }

    async fn get_verified(
        &self,
        descriptor: &BlobDescriptor,
        maximum_bytes: u64,
    ) -> Result<VerifiedBlob, BlobStoreError> {
        if descriptor.size() > maximum_bytes {
            return Err(BlobStoreError::new(BlobStoreErrorKind::TooLarge));
        }
        let objects = self
            .objects
            .read()
            .map_err(|_| BlobStoreError::new(BlobStoreErrorKind::Unavailable))?;
        let payload = objects
            .get(descriptor.key().as_str())
            .ok_or_else(|| BlobStoreError::new(BlobStoreErrorKind::NotFound))?;
        if payload.descriptor() != descriptor {
            return Err(BlobStoreError::new(BlobStoreErrorKind::Integrity));
        }
        Ok(VerifiedBlob::from_payload(payload.clone()))
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use bytes::Bytes;

    use super::*;
    use crate::{BlobKey, MediaType};

    #[tokio::test]
    async fn poisoned_lock_maps_reads_and_writes_to_unavailable() {
        let store = MemoryBlobStore::default();
        let store_to_poison = store.clone();
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _objects = store_to_poison.objects.write().expect("lock fixture");
            panic!("poison the in-memory blob lock");
        }));
        assert!(panic.is_err(), "poisoning fixture must panic");

        let payload = BlobPayload::from_bytes(
            BlobKey::new("poisoned/object").expect("valid key"),
            MediaType::new("application/octet-stream").expect("valid media type"),
            Bytes::from_static(b"payload"),
        );
        let descriptor = payload.descriptor().clone();

        let write_error = store
            .put_if_absent(payload)
            .await
            .expect_err("poisoned write must fail closed");
        assert_eq!(write_error.kind(), BlobStoreErrorKind::Unavailable);

        let read_error = store
            .get_verified(&descriptor, descriptor.size())
            .await
            .expect_err("poisoned read must fail closed");
        assert_eq!(read_error.kind(), BlobStoreErrorKind::Unavailable);
    }
}
