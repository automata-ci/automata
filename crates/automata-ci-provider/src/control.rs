//! Provider-neutral authenticated control requests.

use std::fmt;

use automata_ci_core::{GitObjectAlgorithm, GitObjectId, Sha256Digest};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{ExternalRepositoryIdentity, ExternalSubjectIdentity, ProviderSchemaVersion};

/// Maximum adapter-owned canonical bytes retained for one provider control.
pub const MAX_PROVIDER_CONTROL_DOCUMENT_BYTES: usize = 16 * 1_024;

const CONTROL_DOCUMENT_DOMAIN: &[u8] = b"automata.provider.control-document.v1\0";
const CONTROL_DOMAIN: &[u8] = b"automata.provider.control.v1\0";

/// Common operation requested by an authenticated provider-native control.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProviderControlKind {
    /// Create a fresh processing invocation from an earlier result subject.
    Rerun,
}

/// Bounded schema-versioned canonical evidence decoded only by its adapter.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderControlDocument {
    schema: ProviderSchemaVersion,
    bytes: Vec<u8>,
    digest: Sha256Digest,
}

impl ProviderControlDocument {
    /// Stores one nonempty bounded adapter control document.
    ///
    /// # Errors
    ///
    /// Rejects empty or oversized bytes.
    pub fn new(
        schema: ProviderSchemaVersion,
        bytes: Vec<u8>,
    ) -> Result<Self, ProviderControlError> {
        if bytes.is_empty() || bytes.len() > MAX_PROVIDER_CONTROL_DOCUMENT_BYTES {
            return Err(ProviderControlError::InvalidDocument);
        }
        let mut hash = Sha256::new();
        hash.update(CONTROL_DOCUMENT_DOMAIN);
        hash.update(schema.get().to_be_bytes());
        part(&mut hash, &bytes);
        Ok(Self {
            schema,
            bytes,
            digest: Sha256Digest::from_bytes(hash.finalize().into()),
        })
    }

    /// Returns the adapter schema version.
    #[must_use]
    pub const fn schema(&self) -> ProviderSchemaVersion {
        self.schema
    }

    /// Returns exact canonical adapter bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the domain-separated document digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

impl fmt::Debug for ProviderControlDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderControlDocument")
            .field("schema", &self.schema)
            .field("bytes", &"[CANONICAL]")
            .field("byte_length", &self.bytes.len())
            .field("digest", &self.digest)
            .finish()
    }
}

/// Authenticated provider-independent control facts plus adapter evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderControl {
    kind: ProviderControlKind,
    repository: ExternalRepositoryIdentity,
    object: GitObjectId,
    actor: Option<ExternalSubjectIdentity>,
    document: ProviderControlDocument,
    digest: Sha256Digest,
}

impl ProviderControl {
    /// Constructs one instance-scoped control request.
    ///
    /// # Errors
    ///
    /// Rejects an actor from another provider instance.
    pub fn new(
        kind: ProviderControlKind,
        repository: ExternalRepositoryIdentity,
        object: GitObjectId,
        actor: Option<ExternalSubjectIdentity>,
        document: ProviderControlDocument,
    ) -> Result<Self, ProviderControlError> {
        if actor
            .as_ref()
            .is_some_and(|value| value.instance_id() != repository.instance_id())
        {
            return Err(ProviderControlError::InstanceMismatch);
        }
        let mut value = Self {
            kind,
            repository,
            object,
            actor,
            document,
            digest: Sha256Digest::from_bytes([0; 32]),
        };
        value.digest = value.calculate_digest();
        Ok(value)
    }

    fn calculate_digest(&self) -> Sha256Digest {
        let mut hash = Sha256::new();
        hash.update(CONTROL_DOMAIN);
        hash.update([match self.kind {
            ProviderControlKind::Rerun => 1,
        }]);
        hash.update(self.repository.instance_id().as_uuid().as_bytes());
        part(&mut hash, self.repository.external_id().as_str().as_bytes());
        hash.update([match self.object.algorithm() {
            GitObjectAlgorithm::Sha1 => 1,
            GitObjectAlgorithm::Sha256 => 2,
        }]);
        hash.update(self.object.as_bytes());
        match &self.actor {
            Some(actor) => {
                hash.update([1]);
                hash.update(actor.instance_id().as_uuid().as_bytes());
                hash.update([actor_kind(actor)]);
                part(&mut hash, actor.external_id().as_str().as_bytes());
            }
            None => hash.update([0]),
        }
        hash.update(self.document.digest().as_bytes());
        Sha256Digest::from_bytes(hash.finalize().into())
    }

    /// Returns the common operation.
    #[must_use]
    pub const fn kind(&self) -> ProviderControlKind {
        self.kind
    }

    /// Returns the instance-scoped target repository.
    #[must_use]
    pub const fn repository(&self) -> &ExternalRepositoryIdentity {
        &self.repository
    }

    /// Returns the exact target commit.
    #[must_use]
    pub const fn object(&self) -> GitObjectId {
        self.object
    }

    /// Returns the authenticated actor when the provider supplies one.
    #[must_use]
    pub const fn actor(&self) -> Option<&ExternalSubjectIdentity> {
        self.actor.as_ref()
    }

    /// Returns adapter-owned target and selection evidence.
    #[must_use]
    pub const fn document(&self) -> &ProviderControlDocument {
        &self.document
    }

    /// Returns the complete domain-separated control digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

fn actor_kind(actor: &ExternalSubjectIdentity) -> u8 {
    use crate::ExternalSubjectKind::{Organization, ServiceAccount, Team, User};
    match actor.kind() {
        User => 1,
        Organization => 2,
        Team => 3,
        ServiceAccount => 4,
    }
}

fn part(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

/// Invalid normalized provider control evidence.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderControlError {
    /// Adapter document bytes were empty or exceeded the common bound.
    #[error("provider control document is invalid")]
    InvalidDocument,
    /// Repository and actor identities belong to different provider instances.
    #[error("provider control identity is inconsistent")]
    InstanceMismatch,
}
