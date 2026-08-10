use std::collections::BTreeSet;

use async_trait::async_trait;
use automata_ci_core::{
    RunnerCapabilities, RunnerGroup, RunnerId, RunnerLabel, Sha256Digest, UnixMillis,
};
use thiserror::Error;

use crate::{RepositoryOperationError, RunnerSlotCount, TenantScope};

/// Maximum number of runners accepted in one declarative static fleet.
pub const MAX_STATIC_RUNNERS: usize = 64;
const MAX_RUNNER_TEXT_BYTES: usize = 255;

/// Idempotent request to make an authenticated tenant scope durable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnsureTenant {
    tenant: TenantScope,
    created_at: UnixMillis,
}

impl EnsureTenant {
    #[must_use]
    pub const fn new(tenant: TenantScope, created_at: UnixMillis) -> Self {
        Self { tenant, created_at }
    }

    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }

    #[must_use]
    pub const fn created_at(&self) -> UnixMillis {
        self.created_at
    }
}

/// One exact runner entry in a declarative static fleet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticRunnerRegistration {
    runner_id: RunnerId,
    name: String,
    external_identity: String,
    labels: BTreeSet<RunnerLabel>,
    capabilities: RunnerCapabilities,
    slots: RunnerSlotCount,
    active_certificates: Vec<(Sha256Digest, i64)>,
}

impl StaticRunnerRegistration {
    /// Maximum number of simultaneously active leaves accepted during rotation.
    pub const MAX_ACTIVE_CERTIFICATES: usize = 2;

    /// Constructs an exact registration and verifies duplicated routing facts.
    ///
    /// The separately persisted labels and slot count must be identical to the
    /// capability document. Group coherence is checked by [`StaticRunnerFleet`].
    ///
    /// # Errors
    ///
    /// Rejects malformed names and identities, duplicate labels, invalid
    /// capabilities, incoherent runner IDs/labels/slots, invalid authority
    /// sentinels, an empty or excessive active-certificate set, duplicate
    /// certificate digests, or non-positive expiry.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        runner_id: RunnerId,
        name: impl Into<String>,
        external_identity: impl Into<String>,
        labels: Vec<RunnerLabel>,
        capabilities: RunnerCapabilities,
        slots: RunnerSlotCount,
        mut active_certificates: Vec<(Sha256Digest, i64)>,
    ) -> Result<Self, StaticBootstrapValueError> {
        if runner_id.as_uuid().is_nil() {
            return Err(StaticBootstrapValueError::InvalidRunnerId);
        }
        let name = name.into();
        validate_text(&name, "runner name")?;
        if name.trim() != name {
            return Err(StaticBootstrapValueError::SurroundingWhitespace(
                "runner name",
            ));
        }
        let external_identity = external_identity.into();
        validate_text(&external_identity, "external runner identity")?;
        if external_identity.trim() != external_identity {
            return Err(StaticBootstrapValueError::SurroundingWhitespace(
                "external runner identity",
            ));
        }
        capabilities
            .validate()
            .map_err(|_| StaticBootstrapValueError::InvalidCapabilities)?;
        if capabilities.runner_id() != runner_id {
            return Err(StaticBootstrapValueError::RunnerIdMismatch);
        }
        let label_count = labels.len();
        let unique_labels = labels.into_iter().collect::<BTreeSet<_>>();
        if unique_labels.len() != label_count {
            return Err(StaticBootstrapValueError::DuplicateLabel);
        }
        if capabilities.labels() != &unique_labels {
            return Err(StaticBootstrapValueError::LabelMismatch);
        }
        if capabilities.max_parallel_jobs() != slots.get() {
            return Err(StaticBootstrapValueError::SlotMismatch);
        }
        if active_certificates.is_empty()
            || active_certificates.len() > Self::MAX_ACTIVE_CERTIFICATES
        {
            return Err(StaticBootstrapValueError::InvalidCertificateSetSize);
        }
        if active_certificates
            .iter()
            .any(|(digest, _)| digest.as_bytes().iter().all(|byte| *byte == 0))
        {
            return Err(StaticBootstrapValueError::InvalidCertificateDigest);
        }
        if active_certificates.iter().any(|(_, expiry)| *expiry <= 0) {
            return Err(StaticBootstrapValueError::InvalidCertificateExpiry);
        }
        active_certificates.sort_unstable_by_key(|(digest, _)| *digest);
        if active_certificates
            .windows(2)
            .any(|pair| pair[0].0 == pair[1].0)
        {
            return Err(StaticBootstrapValueError::DuplicateCertificate);
        }
        Ok(Self {
            runner_id,
            name,
            external_identity,
            labels: unique_labels,
            capabilities,
            slots,
            active_certificates,
        })
    }

    #[must_use]
    pub const fn runner_id(&self) -> RunnerId {
        self.runner_id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn external_identity(&self) -> &str {
        &self.external_identity
    }

    #[must_use]
    pub const fn labels(&self) -> &BTreeSet<RunnerLabel> {
        &self.labels
    }

    #[must_use]
    pub const fn capabilities(&self) -> &RunnerCapabilities {
        &self.capabilities
    }

    #[must_use]
    pub const fn slots(&self) -> RunnerSlotCount {
        self.slots
    }

    #[must_use]
    pub fn active_certificates(&self) -> &[(Sha256Digest, i64)] {
        &self.active_certificates
    }
}

/// Exact, bounded runner membership for one tenant-owned static group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticRunnerFleet {
    tenant: TenantScope,
    group: RunnerGroup,
    runners: Vec<StaticRunnerRegistration>,
    applied_at: UnixMillis,
}

impl StaticRunnerFleet {
    /// Builds an authoritative static fleet and rejects ambiguous identities.
    ///
    /// # Errors
    ///
    /// Rejects an empty or excessive fleet, a capability document that names
    /// any group other than the configured group, or duplicate IDs, names,
    /// external identities, or certificate digests.
    pub fn try_new(
        tenant: TenantScope,
        group: RunnerGroup,
        runners: Vec<StaticRunnerRegistration>,
        applied_at: UnixMillis,
    ) -> Result<Self, StaticBootstrapValueError> {
        if runners.is_empty() || runners.len() > MAX_STATIC_RUNNERS {
            return Err(StaticBootstrapValueError::InvalidFleetSize);
        }
        if applied_at.get() < 0
            || runners.iter().any(|runner| {
                runner
                    .active_certificates()
                    .iter()
                    .any(|(_, expiry)| *expiry <= applied_at.get().div_euclid(1_000))
            })
        {
            return Err(StaticBootstrapValueError::CertificateNotCurrent);
        }
        let expected_groups = BTreeSet::from([group.clone()]);
        if runners
            .iter()
            .any(|runner| runner.capabilities().groups() != &expected_groups)
        {
            return Err(StaticBootstrapValueError::GroupMismatch);
        }
        if !all_unique(runners.iter().map(StaticRunnerRegistration::runner_id)) {
            return Err(StaticBootstrapValueError::DuplicateRunnerId);
        }
        if !all_unique(runners.iter().map(|runner| runner.name().to_lowercase())) {
            return Err(StaticBootstrapValueError::DuplicateRunnerName);
        }
        if !all_unique(
            runners
                .iter()
                .map(|runner| runner.external_identity().to_owned()),
        ) {
            return Err(StaticBootstrapValueError::DuplicateExternalIdentity);
        }
        if !all_unique(
            runners
                .iter()
                .flat_map(StaticRunnerRegistration::active_certificates)
                .map(|(digest, _)| *digest),
        ) {
            return Err(StaticBootstrapValueError::DuplicateCertificate);
        }
        Ok(Self {
            tenant,
            group,
            runners,
            applied_at,
        })
    }

    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }

    #[must_use]
    pub const fn group(&self) -> &RunnerGroup {
        &self.group
    }

    #[must_use]
    pub fn runners(&self) -> &[StaticRunnerRegistration] {
        &self.runners
    }

    #[must_use]
    pub const fn applied_at(&self) -> UnixMillis {
        self.applied_at
    }
}

fn all_unique<T: Ord>(values: impl IntoIterator<Item = T>) -> bool {
    let mut seen = BTreeSet::new();
    values.into_iter().all(|value| seen.insert(value))
}

fn validate_text(value: &str, field: &'static str) -> Result<(), StaticBootstrapValueError> {
    if value.is_empty() {
        return Err(StaticBootstrapValueError::Empty(field));
    }
    if value.len() > MAX_RUNNER_TEXT_BYTES {
        return Err(StaticBootstrapValueError::TooLong(field));
    }
    if value.chars().any(char::is_control) {
        return Err(StaticBootstrapValueError::ControlCharacter(field));
    }
    Ok(())
}

/// Invalid declarative registration data rejected before storage.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StaticBootstrapValueError {
    #[error("{0} must not be empty")]
    Empty(&'static str),
    #[error("{0} must not exceed 255 UTF-8 bytes")]
    TooLong(&'static str),
    #[error("{0} must not contain control characters")]
    ControlCharacter(&'static str),
    #[error("{0} must not contain surrounding whitespace")]
    SurroundingWhitespace(&'static str),
    #[error("static runner capability document is invalid")]
    InvalidCapabilities,
    #[error("static runner ID and capability runner ID differ")]
    RunnerIdMismatch,
    #[error("static runner ID must not be nil")]
    InvalidRunnerId,
    #[error("static runner labels contain a duplicate")]
    DuplicateLabel,
    #[error("static runner labels and capability labels differ")]
    LabelMismatch,
    #[error("static runner slots and capability parallelism differ")]
    SlotMismatch,
    #[error("static runner certificate digest must not be all zero")]
    InvalidCertificateDigest,
    #[error("static runner certificate expiration must be positive")]
    InvalidCertificateExpiry,
    #[error("static runner must declare between 1 and 2 active client certificates")]
    InvalidCertificateSetSize,
    #[error("static runner certificate must expire after the fleet observation time")]
    CertificateNotCurrent,
    #[error("static runner fleet must contain between 1 and 64 runners")]
    InvalidFleetSize,
    #[error("static runner capability groups must exactly match the configured group")]
    GroupMismatch,
    #[error("static runner fleet contains a duplicate runner ID")]
    DuplicateRunnerId,
    #[error("static runner fleet contains a duplicate normalized runner name")]
    DuplicateRunnerName,
    #[error("static runner fleet contains a duplicate external identity")]
    DuplicateExternalIdentity,
    #[error("static runner fleet contains a duplicate client certificate")]
    DuplicateCertificate,
}

/// Failures from the narrow product-bootstrap storage boundary.
#[derive(Debug, Error)]
pub enum ProductBootstrapStoreError {
    #[error(transparent)]
    Operation(#[from] RepositoryOperationError),
    #[error("declarative static runner state conflicts with durable {resource}")]
    ConfigurationDrift { resource: &'static str },
    #[error("durable static runner state violates an Automata invariant")]
    CorruptData,
}

impl ProductBootstrapStoreError {
    #[must_use]
    pub fn operation(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        RepositoryOperationError::from_source(source).into()
    }

    #[must_use]
    pub const fn drift(resource: &'static str) -> Self {
        Self::ConfigurationDrift { resource }
    }
}

/// Startup-only persistence operations for product-owned bootstrap state.
#[async_trait]
pub trait ProductBootstrapRepository: Send + Sync {
    /// Verifies that every durable runner capability remains admissible to the
    /// current product before any server-owned bootstrap state can be skipped
    /// or applied.
    async fn verify_runner_capability_admission(&self) -> Result<(), ProductBootstrapStoreError>;

    /// Creates the tenant when absent and otherwise leaves it unchanged.
    async fn ensure_tenant(&self, request: EnsureTenant) -> Result<(), ProductBootstrapStoreError>;

    /// Atomically creates or verifies one exact static fleet and reconciles
    /// each runner's bounded active-certificate set by one-way revocation.
    async fn apply_static_runner_fleet(
        &self,
        fleet: StaticRunnerFleet,
    ) -> Result<(), ProductBootstrapStoreError>;
}
