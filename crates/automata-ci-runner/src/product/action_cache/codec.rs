use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr as _,
};

use automata_ci_action::{
    ActionReferenceIndexError, ActionReferenceIndexErrorKind, ActionSubpath,
    ImmutableActionReference, IndexedActionBundle,
};
use automata_ci_blob::{BlobDescriptor, BlobKey, MediaType};
use automata_ci_core::{GitObjectId, Sha256Digest};
use automata_ci_scm::{RepositoryId, ScmProviderId};
use serde::{Deserialize, Serialize};

use super::ACTION_REFERENCE_INDEX_SCHEMA_VERSION;

#[derive(Clone, Debug, Default)]
pub(crate) struct StoredIndex {
    generation: u64,
    entries: BTreeMap<ImmutableActionReference, SequencedBundle>,
}

#[derive(Clone, Debug)]
struct SequencedBundle {
    sequence: u64,
    bundle: IndexedActionBundle,
}

impl StoredIndex {
    pub(crate) fn decode(
        bytes: &[u8],
        maximum_entries: usize,
    ) -> Result<Self, ActionReferenceIndexError> {
        if bytes.is_empty() {
            return Err(corrupt());
        }
        let document: StoredIndexDocument = serde_json::from_slice(bytes).map_err(|_| corrupt())?;
        if document.schema_version != ACTION_REFERENCE_INDEX_SCHEMA_VERSION
            || document.entries.len() > maximum_entries
        {
            return Err(corrupt());
        }
        let mut entries = BTreeMap::new();
        let mut sequences = BTreeSet::new();
        for raw in document.entries {
            if raw.sequence == 0
                || raw.sequence > document.generation
                || !sequences.insert(raw.sequence)
            {
                return Err(corrupt());
            }
            let bundle = raw.try_into_bundle()?;
            let reference = bundle.reference().clone();
            if entries
                .insert(
                    reference,
                    SequencedBundle {
                        sequence: raw.sequence,
                        bundle,
                    },
                )
                .is_some()
            {
                return Err(corrupt());
            }
        }
        Ok(Self {
            generation: document.generation,
            entries,
        })
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, ActionReferenceIndexError> {
        let document = StoredIndexDocument {
            schema_version: ACTION_REFERENCE_INDEX_SCHEMA_VERSION,
            generation: self.generation,
            entries: self
                .entries
                .values()
                .map(StoredEntry::from_bundle)
                .collect(),
        };
        serde_json::to_vec(&document).map_err(|_| corrupt())
    }

    pub(crate) fn get(&self, reference: &ImmutableActionReference) -> Option<&IndexedActionBundle> {
        self.entries.get(reference).map(|entry| &entry.bundle)
    }

    pub(crate) fn insert(
        &mut self,
        bundle: IndexedActionBundle,
    ) -> Result<(), ActionReferenceIndexError> {
        self.generation = self.generation.checked_add(1).ok_or_else(exhausted)?;
        self.entries.insert(
            bundle.reference().clone(),
            SequencedBundle {
                sequence: self.generation,
                bundle,
            },
        );
        Ok(())
    }

    pub(crate) fn evict_to_entry_bound(
        &mut self,
        maximum_entries: usize,
    ) -> Result<(), ActionReferenceIndexError> {
        while self.entries.len() > maximum_entries {
            self.evict_oldest()?;
        }
        Ok(())
    }

    pub(crate) fn evict_oldest(&mut self) -> Result<(), ActionReferenceIndexError> {
        let reference = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.sequence)
            .map(|(reference, _)| reference.clone())
            .ok_or_else(corrupt)?;
        self.entries.remove(&reference);
        Ok(())
    }

    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredIndexDocument {
    schema_version: u16,
    generation: u64,
    entries: Vec<StoredEntry>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredEntry {
    sequence: u64,
    provider: String,
    repository: String,
    revision: GitObjectId,
    subpath: String,
    resolved_revision: GitObjectId,
    archive: StoredBlobDescriptor,
}

impl StoredEntry {
    fn from_bundle(entry: &SequencedBundle) -> Self {
        let reference = entry.bundle.reference();
        let archive = entry.bundle.archive();
        Self {
            sequence: entry.sequence,
            provider: reference.provider().as_str().to_owned(),
            repository: reference.repository().as_str().to_owned(),
            revision: *reference.revision(),
            subpath: reference.subpath().as_str().to_owned(),
            resolved_revision: entry.bundle.resolved_revision(),
            archive: StoredBlobDescriptor {
                key: archive.key().as_str().to_owned(),
                digest: archive.digest().to_string(),
                size: archive.size(),
                media_type: archive.media_type().as_str().to_owned(),
            },
        }
    }

    fn try_into_bundle(&self) -> Result<IndexedActionBundle, ActionReferenceIndexError> {
        let provider = ScmProviderId::new(self.provider.clone()).map_err(|_| corrupt())?;
        let repository = RepositoryId::new(self.repository.clone()).map_err(|_| corrupt())?;
        let subpath = if self.subpath.is_empty() {
            ActionSubpath::root()
        } else {
            ActionSubpath::new(self.subpath.clone()).map_err(|_| corrupt())?
        };
        let reference = ImmutableActionReference::new(provider, repository, self.revision, subpath);
        let resolved_revision = self.resolved_revision;
        let archive = BlobDescriptor::new(
            BlobKey::new(self.archive.key.clone()).map_err(|_| corrupt())?,
            Sha256Digest::from_str(&self.archive.digest).map_err(|_| corrupt())?,
            self.archive.size,
            MediaType::new(self.archive.media_type.clone()).map_err(|_| corrupt())?,
        );
        IndexedActionBundle::new(reference, resolved_revision, archive).map_err(|_| corrupt())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredBlobDescriptor {
    key: String,
    digest: String,
    size: u64,
    media_type: String,
}

const fn corrupt() -> ActionReferenceIndexError {
    ActionReferenceIndexError::new(ActionReferenceIndexErrorKind::Corrupt)
}

const fn exhausted() -> ActionReferenceIndexError {
    ActionReferenceIndexError::new(ActionReferenceIndexErrorKind::ResourceExhausted)
}
