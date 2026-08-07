use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use tokio::sync::RwLock;

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
        let mut objects = self.objects.write().await;
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
        let objects = self.objects.read().await;
        let payload = objects
            .get(descriptor.key().as_str())
            .ok_or_else(|| BlobStoreError::new(BlobStoreErrorKind::NotFound))?;
        if payload.descriptor() != descriptor {
            return Err(BlobStoreError::new(BlobStoreErrorKind::Integrity));
        }
        Ok(VerifiedBlob::from_payload(payload.clone()))
    }
}
