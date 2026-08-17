use std::{str::FromStr as _, sync::Arc};

use async_trait::async_trait;
use automata_ci_blob::{
    BlobDescriptor, BlobKey, BlobPayload, BlobStoreError, BlobStoreErrorKind, ImmutableRecordStore,
    MediaType, PutBlobOutcome,
};
use automata_ci_core::Sha256Digest;
use automata_ci_scm::{RepositoryId, ResolvedRevision, RevisionSpec, ScmProviderId};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    ActionReferenceIndex, ActionReferenceIndexError, ActionReferenceIndexErrorKind, ActionSubpath,
    ImmutableActionReference, IndexedActionBundle, PutActionReferenceOutcome,
};

const SHARED_REFERENCE_SCHEMA_VERSION: u16 = 1;
const SHARED_REFERENCE_MEDIA_TYPE: &str = "application/vnd.automata.action-reference.v1+json";
const MAXIMUM_SHARED_REFERENCE_BYTES: u64 = 16 * 1_024;
const SHARED_REFERENCE_KEY_DOMAIN: &[u8] = b"automata.action-reference.v1\0";

/// Shared immutable reference index backed by deterministic object records.
///
/// One exact public action reference owns one write-once manifest key. The
/// manifest binds that reference to the content-addressed archive descriptor,
/// allowing any control-plane replica or runner to discover already cached
/// action bytes without contacting the SCM provider.
#[derive(Clone, Debug)]
pub struct ObjectActionReferenceIndex {
    records: Arc<dyn ImmutableRecordStore>,
}

impl ObjectActionReferenceIndex {
    /// Creates an index over one installation-wide immutable record store.
    #[must_use]
    pub fn new(records: Arc<dyn ImmutableRecordStore>) -> Self {
        Self { records }
    }
}

#[async_trait]
impl ActionReferenceIndex for ObjectActionReferenceIndex {
    async fn get(
        &self,
        reference: &ImmutableActionReference,
    ) -> Result<Option<IndexedActionBundle>, ActionReferenceIndexError> {
        let key = shared_reference_key(reference)?;
        let media_type = shared_reference_media_type()?;
        let record = match self
            .records
            .get_record(&key, &media_type, MAXIMUM_SHARED_REFERENCE_BYTES)
            .await
        {
            Ok(record) => record,
            Err(error) if error.kind() == BlobStoreErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(map_record_error(error)),
        };
        let document: SharedReferenceDocument = serde_json::from_slice(record.bytes())
            .map_err(|_| ActionReferenceIndexError::new(ActionReferenceIndexErrorKind::Corrupt))?;
        let bundle = document.try_into_bundle()?;
        if bundle.reference() != reference {
            return Err(corrupt_reference());
        }
        Ok(Some(bundle))
    }

    async fn put_if_absent(
        &self,
        bundle: IndexedActionBundle,
    ) -> Result<PutActionReferenceOutcome, ActionReferenceIndexError> {
        let key = shared_reference_key(bundle.reference())?;
        let media_type = shared_reference_media_type()?;
        let bytes = serde_json::to_vec(&SharedReferenceDocument::from_bundle(&bundle))
            .map_err(|_| corrupt_reference())?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAXIMUM_SHARED_REFERENCE_BYTES {
            return Err(ActionReferenceIndexError::new(
                ActionReferenceIndexErrorKind::ResourceExhausted,
            ));
        }
        let payload = BlobPayload::from_bytes(key, media_type, Bytes::from(bytes));
        self.records
            .put_if_absent(payload)
            .await
            .map(|outcome| match outcome {
                PutBlobOutcome::Created => PutActionReferenceOutcome::Created,
                PutBlobOutcome::AlreadyPresent => PutActionReferenceOutcome::AlreadyPresent,
            })
            .map_err(map_record_error)
    }
}

/// Local-first view over an installation-wide authoritative reference index.
///
/// Local entries preserve warm execution during a shared-store interruption.
/// Misses and local operational failures fall through to the shared index;
/// shared hits opportunistically repair the local acceleration layer.
#[derive(Clone, Debug)]
pub struct ReadThroughActionReferenceIndex {
    local: Arc<dyn ActionReferenceIndex>,
    shared: Arc<dyn ActionReferenceIndex>,
}

impl ReadThroughActionReferenceIndex {
    /// Combines one best-effort local index with one shared persistent index.
    #[must_use]
    pub fn new(
        local: Arc<dyn ActionReferenceIndex>,
        shared: Arc<dyn ActionReferenceIndex>,
    ) -> Self {
        Self { local, shared }
    }
}

#[async_trait]
impl ActionReferenceIndex for ReadThroughActionReferenceIndex {
    async fn get(
        &self,
        reference: &ImmutableActionReference,
    ) -> Result<Option<IndexedActionBundle>, ActionReferenceIndexError> {
        if let Ok(Some(bundle)) = self.local.get(reference).await {
            return Ok(Some(bundle));
        }
        let Some(bundle) = self.shared.get(reference).await? else {
            return Ok(None);
        };
        if let Err(error) = self.local.put_if_absent(bundle.clone()).await
            && error.kind() == ActionReferenceIndexErrorKind::Conflict
        {
            return Err(error);
        }
        Ok(Some(bundle))
    }

    async fn put_if_absent(
        &self,
        bundle: IndexedActionBundle,
    ) -> Result<PutActionReferenceOutcome, ActionReferenceIndexError> {
        let outcome = self.shared.put_if_absent(bundle.clone()).await?;
        if let Err(error) = self.local.put_if_absent(bundle).await
            && error.kind() == ActionReferenceIndexErrorKind::Conflict
        {
            return Err(error);
        }
        Ok(outcome)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SharedReferenceDocument {
    schema_version: u16,
    provider: String,
    repository: String,
    revision: String,
    subpath: String,
    resolved_revision: String,
    archive: SharedBlobDescriptor,
}

impl SharedReferenceDocument {
    fn from_bundle(bundle: &IndexedActionBundle) -> Self {
        let reference = bundle.reference();
        let archive = bundle.archive();
        Self {
            schema_version: SHARED_REFERENCE_SCHEMA_VERSION,
            provider: reference.provider().as_str().to_owned(),
            repository: reference.repository().as_str().to_owned(),
            revision: reference.revision().as_str().to_owned(),
            subpath: reference.subpath().as_str().to_owned(),
            resolved_revision: bundle.resolved_revision().as_str().to_owned(),
            archive: SharedBlobDescriptor {
                key: archive.key().as_str().to_owned(),
                digest: archive.digest().to_string(),
                size: archive.size(),
                media_type: archive.media_type().as_str().to_owned(),
            },
        }
    }

    fn try_into_bundle(self) -> Result<IndexedActionBundle, ActionReferenceIndexError> {
        if self.schema_version != SHARED_REFERENCE_SCHEMA_VERSION {
            return Err(corrupt_reference());
        }
        let provider = ScmProviderId::new(self.provider).map_err(|_| corrupt_reference())?;
        let repository = RepositoryId::new(self.repository).map_err(|_| corrupt_reference())?;
        let revision = RevisionSpec::new(self.revision).map_err(|_| corrupt_reference())?;
        let subpath = if self.subpath.is_empty() {
            ActionSubpath::root()
        } else {
            ActionSubpath::new(self.subpath).map_err(|_| corrupt_reference())?
        };
        let reference = ImmutableActionReference::new(provider, repository, revision, subpath)
            .map_err(|_| corrupt_reference())?;
        let resolved_revision =
            ResolvedRevision::new(self.resolved_revision).map_err(|_| corrupt_reference())?;
        let archive = BlobDescriptor::new(
            BlobKey::new(self.archive.key).map_err(|_| corrupt_reference())?,
            Sha256Digest::from_str(&self.archive.digest).map_err(|_| corrupt_reference())?,
            self.archive.size,
            MediaType::new(self.archive.media_type).map_err(|_| corrupt_reference())?,
        );
        IndexedActionBundle::new(reference, resolved_revision, archive)
            .map_err(|_| corrupt_reference())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SharedBlobDescriptor {
    key: String,
    digest: String,
    size: u64,
    media_type: String,
}

fn shared_reference_key(
    reference: &ImmutableActionReference,
) -> Result<BlobKey, ActionReferenceIndexError> {
    let mut hasher = Sha256::new();
    hasher.update(SHARED_REFERENCE_KEY_DOMAIN);
    for component in [
        reference.provider().as_str(),
        reference.repository().as_str(),
        reference.revision().as_str(),
        reference.subpath().as_str(),
    ] {
        let length = u64::try_from(component.len()).map_err(|_| corrupt_reference())?;
        hasher.update(length.to_be_bytes());
        hasher.update(component.as_bytes());
    }
    let digest = Sha256Digest::from_bytes(hasher.finalize().into());
    BlobKey::new(format!("actions/references/v1/sha256/{digest}.json"))
        .map_err(|_| corrupt_reference())
}

fn shared_reference_media_type() -> Result<MediaType, ActionReferenceIndexError> {
    MediaType::new(SHARED_REFERENCE_MEDIA_TYPE).map_err(|_| corrupt_reference())
}

fn map_record_error(error: BlobStoreError) -> ActionReferenceIndexError {
    let kind = match error.kind() {
        BlobStoreErrorKind::Conflict => ActionReferenceIndexErrorKind::Conflict,
        BlobStoreErrorKind::Integrity | BlobStoreErrorKind::InvalidResponse => {
            ActionReferenceIndexErrorKind::Corrupt
        }
        BlobStoreErrorKind::TooLarge => ActionReferenceIndexErrorKind::ResourceExhausted,
        BlobStoreErrorKind::NotFound
        | BlobStoreErrorKind::Unauthorized
        | BlobStoreErrorKind::Unavailable => ActionReferenceIndexErrorKind::Unavailable,
    };
    ActionReferenceIndexError::new(kind)
}

const fn corrupt_reference() -> ActionReferenceIndexError {
    ActionReferenceIndexError::new(ActionReferenceIndexErrorKind::Corrupt)
}
