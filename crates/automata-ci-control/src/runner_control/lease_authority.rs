use std::{collections::BTreeMap, fmt, io, sync::Arc};

use async_trait::async_trait;
use automata_ci_core::{
    JobIrEnvelope, SandboxAuthorization, SandboxAuthorizations, Sha256Digest, UnixMillis,
};
use automata_ci_protocol::{
    LeaseAuthorityName, LeaseAuthorityPollContribution, LeaseAuthorityPollContributions,
    MAX_LEASE_AUTHORITY_POLL_CONTRIBUTIONS, MAX_LEASE_AUTHORITY_POLL_PAYLOAD_BYTES,
};
use automata_ci_store::RunnerSessionFence;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::lease::ClaimedLeasePoll;

use super::{
    durable::{
        CommitRuntimeAuthorityDelivery, RuntimeAuthorityDeliveryAdmission,
        RuntimeAuthorityDeliveryDisposition,
    },
    port::ControlPortError,
};

/// Schema of the provider-neutral evidence set retained with a lease offer.
pub const LEASE_AUTHORITY_EVIDENCE_SCHEMA_VERSION: u16 = 1;
/// Maximum number of independent authority extensions retained by one offer.
pub const MAX_LEASE_AUTHORITY_EVIDENCE: usize = MAX_LEASE_AUTHORITY_POLL_CONTRIBUTIONS;
/// Maximum encoded bytes reserved for authority evidence in one durable offer.
///
/// This is deliberately below the 16 MiB durable command ceiling so evidence
/// cannot consume the entire command budget needed by the verified `JobIR`,
/// lease, and secret-binding metadata.
pub const MAX_DURABLE_LEASE_AUTHORITY_EVIDENCE_BYTES: usize = 8 * 1024 * 1024;

/// One bounded, value-free provider-owned authority projection.
#[derive(Clone, Eq, PartialEq)]
pub struct LeaseAuthorityEvidence {
    name: LeaseAuthorityName,
    payload_schema_version: u16,
    payload_sha256: Sha256Digest,
    payload: Box<[u8]>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LeaseAuthorityEvidenceDocument {
    name: LeaseAuthorityName,
    payload_schema_version: u16,
    payload_sha256: Sha256Digest,
    payload: Box<[u8]>,
}

#[derive(Serialize)]
struct LeaseAuthorityEvidenceDocumentRef<'a> {
    name: &'a LeaseAuthorityName,
    payload_schema_version: u16,
    payload_sha256: Sha256Digest,
    payload: &'a [u8],
}

impl LeaseAuthorityEvidence {
    /// Creates durable evidence and commits to its exact provider-owned bytes.
    ///
    /// # Errors
    ///
    /// Rejects schema zero or an empty or oversized payload.
    pub fn new(
        name: LeaseAuthorityName,
        payload_schema_version: u16,
        payload: impl Into<Box<[u8]>>,
    ) -> Result<Self, LeaseAuthorityEvidenceError> {
        let payload = payload.into();
        let payload_sha256 = Sha256Digest::from_bytes(Sha256::digest(&payload).into());
        Self::from_parts(name, payload_schema_version, payload_sha256, payload)
    }

    /// Rehydrates exact durable evidence.
    ///
    /// # Errors
    ///
    /// Rejects invalid bounds or a substituted payload digest.
    pub fn from_parts(
        name: LeaseAuthorityName,
        payload_schema_version: u16,
        payload_sha256: Sha256Digest,
        payload: impl Into<Box<[u8]>>,
    ) -> Result<Self, LeaseAuthorityEvidenceError> {
        let payload = payload.into();
        if payload_schema_version == 0 {
            return Err(LeaseAuthorityEvidenceError::ZeroPayloadSchema);
        }
        if payload.is_empty() || payload.len() > MAX_LEASE_AUTHORITY_POLL_PAYLOAD_BYTES {
            return Err(LeaseAuthorityEvidenceError::InvalidPayloadSize);
        }
        let actual = Sha256Digest::from_bytes(Sha256::digest(&payload).into());
        if actual != payload_sha256 {
            return Err(LeaseAuthorityEvidenceError::PayloadDigestMismatch);
        }
        Ok(Self {
            name,
            payload_schema_version,
            payload_sha256,
            payload,
        })
    }

    /// Returns the owning extension namespace.
    #[must_use]
    pub const fn name(&self) -> &LeaseAuthorityName {
        &self.name
    }

    /// Returns the provider-owned evidence schema.
    #[must_use]
    pub const fn payload_schema_version(&self) -> u16 {
        self.payload_schema_version
    }

    /// Returns the digest of the exact evidence bytes.
    #[must_use]
    pub const fn payload_sha256(&self) -> Sha256Digest {
        self.payload_sha256
    }

    /// Returns the exact provider-owned evidence bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl fmt::Debug for LeaseAuthorityEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LeaseAuthorityEvidence")
            .field("name", &self.name)
            .field("payload_schema_version", &self.payload_schema_version)
            .field("payload_sha256", &self.payload_sha256)
            .field("payload_bytes", &self.payload.len())
            .finish()
    }
}

impl Serialize for LeaseAuthorityEvidence {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        LeaseAuthorityEvidenceDocumentRef {
            name: &self.name,
            payload_schema_version: self.payload_schema_version,
            payload_sha256: self.payload_sha256,
            payload: &self.payload,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for LeaseAuthorityEvidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = LeaseAuthorityEvidenceDocument::deserialize(deserializer)?;
        Self::from_parts(
            value.name,
            value.payload_schema_version,
            value.payload_sha256,
            value.payload,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// Canonically ordered durable authority evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseAuthorityEvidenceSet {
    schema_version: u16,
    evidence: Vec<LeaseAuthorityEvidence>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LeaseAuthorityEvidenceSetDocument {
    schema_version: u16,
    evidence: Vec<LeaseAuthorityEvidence>,
}

#[derive(Serialize)]
struct LeaseAuthorityEvidenceSetDocumentRef<'a> {
    schema_version: u16,
    evidence: &'a [LeaseAuthorityEvidence],
}

impl LeaseAuthorityEvidenceSet {
    /// Creates a canonical evidence set.
    ///
    /// # Errors
    ///
    /// Rejects oversized, duplicate, or noncanonically ordered evidence.
    pub fn new(evidence: Vec<LeaseAuthorityEvidence>) -> Result<Self, LeaseAuthorityEvidenceError> {
        let value = Self {
            schema_version: LEASE_AUTHORITY_EVIDENCE_SCHEMA_VERSION,
            evidence,
        };
        value.validate()?;
        Ok(value)
    }

    /// Creates an explicit empty set.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            schema_version: LEASE_AUTHORITY_EVIDENCE_SCHEMA_VERSION,
            evidence: Vec::new(),
        }
    }

    /// Returns the evidence in canonical namespace order.
    #[must_use]
    pub fn as_slice(&self) -> &[LeaseAuthorityEvidence] {
        &self.evidence
    }

    /// Finds evidence owned by one exact extension.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&LeaseAuthorityEvidence> {
        self.evidence
            .binary_search_by(|evidence| evidence.name().as_str().cmp(name))
            .ok()
            .map(|index| &self.evidence[index])
    }

    /// Validates the durable schema and canonical ordering.
    ///
    /// # Errors
    ///
    /// Rejects unsupported schema, excessive entries, duplicates, or disorder.
    pub fn validate(&self) -> Result<(), LeaseAuthorityEvidenceError> {
        if self.schema_version != LEASE_AUTHORITY_EVIDENCE_SCHEMA_VERSION {
            return Err(LeaseAuthorityEvidenceError::UnsupportedSchema);
        }
        if self.evidence.len() > MAX_LEASE_AUTHORITY_EVIDENCE {
            return Err(LeaseAuthorityEvidenceError::InvalidCount);
        }
        let mut previous: Option<&LeaseAuthorityName> = None;
        for evidence in &self.evidence {
            if previous.is_some_and(|name| name >= evidence.name()) {
                return Err(LeaseAuthorityEvidenceError::NonCanonicalOrder);
            }
            previous = Some(evidence.name());
        }
        let document = LeaseAuthorityEvidenceSetDocumentRef {
            schema_version: self.schema_version,
            evidence: &self.evidence,
        };
        if serde_json::to_writer(
            EncodedSizeWriter::new(MAX_DURABLE_LEASE_AUTHORITY_EVIDENCE_BYTES),
            &document,
        )
        .is_err()
        {
            return Err(LeaseAuthorityEvidenceError::EncodedPayloadTooLarge);
        }
        Ok(())
    }
}

impl Default for LeaseAuthorityEvidenceSet {
    fn default() -> Self {
        Self::empty()
    }
}

impl Serialize for LeaseAuthorityEvidenceSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        LeaseAuthorityEvidenceSetDocumentRef {
            schema_version: self.schema_version,
            evidence: &self.evidence,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for LeaseAuthorityEvidenceSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = LeaseAuthorityEvidenceSetDocument::deserialize(deserializer)?;
        let set = Self {
            schema_version: value.schema_version,
            evidence: value.evidence,
        };
        set.validate().map_err(serde::de::Error::custom)?;
        Ok(set)
    }
}

/// Invalid durable lease-authority evidence.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LeaseAuthorityEvidenceError {
    /// Provider-owned schema zero is reserved.
    #[error("lease authority evidence payload schema must be nonzero")]
    ZeroPayloadSchema,
    /// The evidence payload is empty or above its hard bound.
    #[error("lease authority evidence payload size is invalid")]
    InvalidPayloadSize,
    /// The exact evidence payload does not match its digest.
    #[error("lease authority evidence payload digest does not match")]
    PayloadDigestMismatch,
    /// The evidence-set schema is unsupported.
    #[error("lease authority evidence schema is unsupported")]
    UnsupportedSchema,
    /// The evidence set exceeds its hard entry limit.
    #[error("lease authority evidence count is invalid")]
    InvalidCount,
    /// The canonical durable JSON representation exceeds its reserved budget.
    #[error("lease authority evidence exceeds its durable encoded-byte budget")]
    EncodedPayloadTooLarge,
    /// Evidence is duplicated or not in canonical namespace order.
    #[error("lease authority evidence is not in canonical order")]
    NonCanonicalOrder,
}

struct EncodedSizeWriter {
    remaining: usize,
}

impl EncodedSizeWriter {
    const fn new(maximum: usize) -> Self {
        Self { remaining: maximum }
    }
}

impl io::Write for EncodedSizeWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(io::Error::other(
                "encoded evidence exceeds its durable budget",
            ));
        }
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn maximal_evidence(name: &str, byte: u8) -> LeaseAuthorityEvidence {
        LeaseAuthorityEvidence::new(
            LeaseAuthorityName::new(name).expect("authority name"),
            1,
            vec![byte; MAX_LEASE_AUTHORITY_POLL_PAYLOAD_BYTES],
        )
        .expect("maximal evidence")
    }

    #[test]
    fn one_maximal_evidence_payload_always_fits_the_durable_budget() {
        for byte in [0, u8::MAX] {
            let set = LeaseAuthorityEvidenceSet::new(vec![maximal_evidence("extension", byte)])
                .expect("one maximal evidence payload");
            assert!(
                serde_json::to_vec(&set).expect("encoded evidence").len()
                    <= MAX_DURABLE_LEASE_AUTHORITY_EVIDENCE_BYTES
            );
        }
    }

    #[test]
    fn aggregate_durable_evidence_budget_rejects_wire_valid_amplification() {
        let within_budget = LeaseAuthorityEvidenceSet::new(vec![
            maximal_evidence("extension-1", 0),
            maximal_evidence("extension-2", 0),
            maximal_evidence("extension-3", 0),
        ])
        .expect("three zero-filled payloads fit the encoded budget");
        assert!(
            serde_json::to_vec(&within_budget)
                .expect("encoded evidence")
                .len()
                <= MAX_DURABLE_LEASE_AUTHORITY_EVIDENCE_BYTES
        );

        assert_eq!(
            LeaseAuthorityEvidenceSet::new(vec![
                maximal_evidence("extension-1", 0),
                maximal_evidence("extension-2", 0),
                maximal_evidence("extension-3", 0),
                maximal_evidence("extension-4", 0),
            ]),
            Err(LeaseAuthorityEvidenceError::EncodedPayloadTooLarge)
        );
    }
}

/// Trusted server context for accepting one runner poll contribution.
#[derive(Clone, Copy, Debug)]
pub struct LeaseAuthorityPollAcceptance {
    session: RunnerSessionFence,
    observed_at: UnixMillis,
}

impl LeaseAuthorityPollAcceptance {
    /// Creates an acceptance context after durable request admission.
    #[must_use]
    pub const fn new(session: RunnerSessionFence, observed_at: UnixMillis) -> Self {
        Self {
            session,
            observed_at,
        }
    }

    /// Returns the exact authenticated session fence.
    #[must_use]
    pub const fn session(self) -> RunnerSessionFence {
        self.session
    }

    /// Returns trusted server time for freshness verification.
    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }
}

/// Verified offer inputs from which extensions may retain value-free evidence.
#[derive(Clone, Copy, Debug)]
pub struct LeaseAuthorityOfferRequest<'a> {
    session: RunnerSessionFence,
    claimed: &'a ClaimedLeasePoll,
    job: &'a JobIrEnvelope,
}

impl<'a> LeaseAuthorityOfferRequest<'a> {
    /// Creates an offer-evidence request.
    #[must_use]
    pub const fn new(
        session: RunnerSessionFence,
        claimed: &'a ClaimedLeasePoll,
        job: &'a JobIrEnvelope,
    ) -> Self {
        Self {
            session,
            claimed,
            job,
        }
    }

    /// Returns the exact authenticated session.
    #[must_use]
    pub const fn session(self) -> RunnerSessionFence {
        self.session
    }

    /// Returns the exact durable scheduler claim.
    #[must_use]
    pub const fn claimed(self) -> &'a ClaimedLeasePoll {
        self.claimed
    }

    /// Returns the verified immutable job.
    #[must_use]
    pub const fn job(self) -> &'a JobIrEnvelope {
        self.job
    }
}

/// Prepared provider authorization whose commit owns the specialized atomic path.
#[async_trait]
pub trait PreparedSandboxAuthorization: fmt::Debug + Send {
    /// Returns the exact generic authorization to protect for the runner.
    fn authorization(&self) -> &SandboxAuthorization;

    /// Atomically commits delivery through the provider-owned durable boundary.
    async fn commit(
        self: Box<Self>,
        delivery: CommitRuntimeAuthorityDelivery,
    ) -> Result<RuntimeAuthorityDeliveryDisposition, ControlPortError>;
}

/// Provider-neutral extension lifecycle for lease-bound sandbox authority.
#[async_trait]
pub trait LeaseAuthorityExtension: fmt::Debug + Send + Sync {
    /// Returns the stable namespace owned by this extension.
    fn name(&self) -> &LeaseAuthorityName;

    /// Verifies and durably accepts one exact poll contribution.
    async fn accept_poll_contribution(
        &self,
        context: LeaseAuthorityPollAcceptance,
        contribution: &LeaseAuthorityPollContribution,
    ) -> Result<(), ControlPortError>;

    /// Produces bounded value-free evidence for a claimed offer when applicable.
    async fn prepare_offer_evidence(
        &self,
        request: LeaseAuthorityOfferRequest<'_>,
    ) -> Result<Option<LeaseAuthorityEvidence>, ControlPortError>;

    /// Prepares the exact sandbox authorization and its atomic commit object.
    async fn prepare_sandbox_authorization(
        &self,
        evidence: &LeaseAuthorityEvidence,
        job: &JobIrEnvelope,
        admission: &RuntimeAuthorityDeliveryAdmission,
    ) -> Result<Box<dyn PreparedSandboxAuthorization>, ControlPortError>;
}

/// Canonical registry for independently owned lease-authority extensions.
#[derive(Default)]
pub struct LeaseAuthorityExtensionRegistry {
    extensions: BTreeMap<LeaseAuthorityName, Arc<dyn LeaseAuthorityExtension>>,
}

impl fmt::Debug for LeaseAuthorityExtensionRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LeaseAuthorityExtensionRegistry")
            .field("names", &self.extensions.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl LeaseAuthorityExtensionRegistry {
    /// Creates an explicit empty registry.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            extensions: BTreeMap::new(),
        }
    }

    /// Creates a canonical registry.
    ///
    /// # Errors
    ///
    /// Rejects duplicate namespaces or an excessive extension count.
    pub fn new(
        extensions: Vec<Arc<dyn LeaseAuthorityExtension>>,
    ) -> Result<Self, LeaseAuthorityRegistryError> {
        if extensions.len() > MAX_LEASE_AUTHORITY_EVIDENCE {
            return Err(LeaseAuthorityRegistryError::InvalidCount);
        }
        let mut by_name = BTreeMap::new();
        for extension in extensions {
            let name = extension.name().clone();
            if by_name.insert(name, extension).is_some() {
                return Err(LeaseAuthorityRegistryError::DuplicateName);
            }
        }
        Ok(Self {
            extensions: by_name,
        })
    }

    /// Accepts every contribution before any scheduling side effect.
    ///
    /// # Errors
    ///
    /// Fails closed for an unregistered namespace or adapter rejection.
    pub async fn accept_poll_contributions(
        &self,
        context: LeaseAuthorityPollAcceptance,
        contributions: &LeaseAuthorityPollContributions,
    ) -> Result<(), ControlPortError> {
        for contribution in contributions.as_slice() {
            let extension = self
                .extensions
                .get(contribution.name())
                .ok_or(ControlPortError::Conflict)?;
            extension
                .accept_poll_contribution(context, contribution)
                .await?;
        }
        Ok(())
    }

    /// Collects canonical durable evidence from all configured extensions.
    ///
    /// # Errors
    ///
    /// Rejects namespace substitution or invalid evidence.
    pub async fn prepare_offer_evidence(
        &self,
        request: LeaseAuthorityOfferRequest<'_>,
    ) -> Result<LeaseAuthorityEvidenceSet, ControlPortError> {
        let mut evidence = Vec::new();
        for (name, extension) in &self.extensions {
            if let Some(value) = extension.prepare_offer_evidence(request).await? {
                if value.name() != name {
                    return Err(ControlPortError::Corrupt);
                }
                evidence.push(value);
            }
        }
        LeaseAuthorityEvidenceSet::new(evidence).map_err(|_| ControlPortError::Corrupt)
    }

    /// Prepares at most one sandbox-provider authorization for an accepted offer.
    ///
    /// A job has exactly one sandbox provider. Multiple prepared authorization
    /// commits could not be atomic across independent repositories and therefore
    /// fail closed.
    ///
    /// # Errors
    ///
    /// Rejects unknown durable evidence, extension failures, or more than one
    /// prepared sandbox authorization.
    pub async fn prepare_sandbox_authorization(
        &self,
        evidence: &LeaseAuthorityEvidenceSet,
        job: &JobIrEnvelope,
        admission: &RuntimeAuthorityDeliveryAdmission,
    ) -> Result<Option<Box<dyn PreparedSandboxAuthorization>>, ControlPortError> {
        let mut prepared = None;
        for value in evidence.as_slice() {
            let extension = self
                .extensions
                .get(value.name())
                .ok_or(ControlPortError::Unavailable)?;
            let candidate = extension
                .prepare_sandbox_authorization(value, job, admission)
                .await?;
            if candidate.authorization().name().as_str() != value.name().as_str() {
                return Err(ControlPortError::Corrupt);
            }
            if prepared.replace(candidate).is_some() {
                return Err(ControlPortError::Corrupt);
            }
        }
        Ok(prepared)
    }

    /// Builds the canonical generic authorization set for a prepared object.
    ///
    /// # Errors
    ///
    /// Rejects an authorization that violates the core canonical set bounds.
    pub fn authorizations(
        prepared: Option<&dyn PreparedSandboxAuthorization>,
    ) -> Result<SandboxAuthorizations, ControlPortError> {
        let values = prepared
            .map(|prepared| vec![prepared.authorization().clone()])
            .unwrap_or_default();
        SandboxAuthorizations::new(values).map_err(|_| ControlPortError::Corrupt)
    }
}

/// Invalid extension registry composition.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LeaseAuthorityRegistryError {
    /// Too many independent extensions were configured.
    #[error("lease authority extension count is invalid")]
    InvalidCount,
    /// More than one extension owns the same namespace.
    #[error("lease authority extension namespace is duplicated")]
    DuplicateName,
}
