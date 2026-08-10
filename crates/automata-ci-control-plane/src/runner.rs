//! Runner session identity, observations, and server-authorized effective state.

use std::{collections::BTreeSet, num::NonZeroU16};

use automata_ci_core::{
    CapabilityValidationError, ContainerFeature, EnvironmentProfile, ResourceCapacity,
    ResourceKind, RunnerCapabilities, RunnerFeature, RunnerGroup, RunnerId, RunnerLabel,
    RunnerSessionId, SandboxFeature, UnixMillis,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Exact authenticated runner session to which work may be delivered.
///
/// A transport reconnect may resume the same durable session identifier after
/// the control plane validates its command cursor. Opening a replacement
/// session receives a new identifier. Pairing either with the durable runner
/// identity prevents a different runner from entering scheduling policy as
/// that session; generation and epoch fencing remain application/store duties.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SessionGuard {
    runner_id: RunnerId,
    session_id: RunnerSessionId,
}

impl SessionGuard {
    /// Binds a durable runner identity to one authenticated connection.
    #[must_use]
    pub const fn new(runner_id: RunnerId, session_id: RunnerSessionId) -> Self {
        Self {
            runner_id,
            session_id,
        }
    }

    /// Returns the durable runner identity.
    #[must_use]
    pub const fn runner_id(self) -> RunnerId {
        self.runner_id
    }

    /// Returns the authenticated connection identity.
    #[must_use]
    pub const fn session_id(self) -> RunnerSessionId {
        self.session_id
    }
}

/// Stable one-based execution slot within a durable runner registration.
///
/// The slot remains stable across reconnects; [`SessionGuard`] separately
/// identifies the connection currently authorized to receive its work.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RunnerSlot {
    runner_id: RunnerId,
    ordinal: NonZeroU16,
}

impl RunnerSlot {
    /// Creates a stable one-based runner slot.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerSlotError::ZeroOrdinal`] when `ordinal` is zero.
    pub fn new(runner_id: RunnerId, ordinal: u16) -> Result<Self, RunnerSlotError> {
        let ordinal = NonZeroU16::new(ordinal).ok_or(RunnerSlotError::ZeroOrdinal)?;
        Ok(Self { runner_id, ordinal })
    }

    /// Returns the durable runner identity.
    #[must_use]
    pub const fn runner_id(self) -> RunnerId {
        self.runner_id
    }

    /// Returns the one-based slot ordinal.
    #[must_use]
    pub const fn ordinal(self) -> u16 {
        self.ordinal.get()
    }
}

/// Validation errors for stable slot identity.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RunnerSlotError {
    /// Slot ordinals are one-based.
    #[error("runner slot ordinal must be non-zero")]
    ZeroOrdinal,
}

/// Capabilities observed from one authenticated runner session.
///
/// Evidence is intentionally not accepted by [`crate::SchedulerPolicy`]. It
/// must first be reduced and authorized into [`EffectiveRunner`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerEvidence {
    session: SessionGuard,
    observed_capabilities: RunnerCapabilities,
    observed_at: UnixMillis,
}

impl RunnerEvidence {
    /// Validates a runner capability observation against its authenticated
    /// session identity.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerEvidenceError`] for an invalid advertisement or an
    /// advertisement belonging to a different runner.
    pub fn new(
        session: SessionGuard,
        observed_capabilities: RunnerCapabilities,
        observed_at: UnixMillis,
    ) -> Result<Self, RunnerEvidenceError> {
        observed_capabilities.validate()?;
        if observed_capabilities.runner_id() != session.runner_id() {
            return Err(RunnerEvidenceError::RunnerIdentityMismatch {
                authenticated: session.runner_id(),
                advertised: observed_capabilities.runner_id(),
            });
        }
        Ok(Self {
            session,
            observed_capabilities,
            observed_at,
        })
    }

    /// Returns the authenticated session that supplied the evidence.
    #[must_use]
    pub const fn session(&self) -> SessionGuard {
        self.session
    }

    /// Returns the runner-reported capabilities. They are evidence, not a
    /// scheduling authorization.
    #[must_use]
    pub const fn observed_capabilities(&self) -> &RunnerCapabilities {
        &self.observed_capabilities
    }

    /// Returns when the control plane observed this evidence.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
}

/// Validation errors at the authenticated runner evidence boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RunnerEvidenceError {
    /// The capability advertisement itself is malformed or unsupported.
    #[error(transparent)]
    InvalidCapabilities(#[from] CapabilityValidationError),
    /// The authenticated runner and advertisement identify different runners.
    #[error("authenticated runner {authenticated} cannot advertise capabilities for {advertised}")]
    RunnerIdentityMismatch {
        /// Durable identity established by runner authentication.
        authenticated: RunnerId,
        /// Durable identity asserted by the rejected capability advertisement.
        advertised: RunnerId,
    },
}

/// Administrative labels and groups authorized for one runner registration.
///
/// This value is constructed from control-plane registration state, never from
/// a runner handshake. Keeping it separate from [`RunnerEvidence`] prevents a
/// machine from routing privileged work to itself by advertising extra labels
/// or groups.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuthorizedRunnerRouting {
    labels: BTreeSet<RunnerLabel>,
    groups: BTreeSet<RunnerGroup>,
}

impl AuthorizedRunnerRouting {
    /// Creates routing authorization from server-owned registration data.
    #[must_use]
    pub fn new(
        labels: impl IntoIterator<Item = RunnerLabel>,
        groups: impl IntoIterator<Item = RunnerGroup>,
    ) -> Self {
        Self {
            labels: labels.into_iter().collect(),
            groups: groups.into_iter().collect(),
        }
    }

    /// Returns the labels the registration is authorized to match.
    #[must_use]
    pub const fn labels(&self) -> &BTreeSet<RunnerLabel> {
        &self.labels
    }

    /// Returns the groups the registration is authorized to match.
    #[must_use]
    pub const fn groups(&self) -> &BTreeSet<RunnerGroup> {
        &self.groups
    }
}

/// Server-authorized runner state that is safe for scheduler policies to use.
///
/// Effective execution abilities can only be equal to or weaker than observed
/// evidence. Labels and groups are administrative selectors and therefore come
/// from the server-authorized capability set rather than being trusted from the
/// runner observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveRunner {
    session: SessionGuard,
    capabilities: RunnerCapabilities,
    available_slots: BTreeSet<RunnerSlot>,
    evidence_observed_at: UnixMillis,
}

impl EffectiveRunner {
    /// Reduces runner evidence to server-authorized capabilities and slots.
    ///
    /// # Errors
    ///
    /// Returns [`EffectiveRunnerError`] if the effective state changes runner
    /// identity or platform, grants an unobserved execution ability, or names
    /// an invalid/duplicate slot.
    pub fn authorize(
        evidence: &RunnerEvidence,
        routing: AuthorizedRunnerRouting,
        mut capabilities: RunnerCapabilities,
        available_slots: impl IntoIterator<Item = RunnerSlot>,
    ) -> Result<Self, EffectiveRunnerError> {
        capabilities.validate()?;
        let observed = evidence.observed_capabilities();
        let runner_id = evidence.session().runner_id();

        if !capabilities.labels().is_empty() || !capabilities.groups().is_empty() {
            return Err(EffectiveRunnerError::SelectorsNotSeparated);
        }

        if capabilities.runner_id() != runner_id {
            return Err(EffectiveRunnerError::RunnerIdentityMismatch {
                authenticated: runner_id,
                effective: capabilities.runner_id(),
            });
        }
        if capabilities.platform() != observed.platform() {
            return Err(EffectiveRunnerError::PlatformMismatch);
        }
        if capabilities.max_parallel_jobs() > observed.max_parallel_jobs() {
            return Err(EffectiveRunnerError::SlotLimitExceedsEvidence {
                observed: observed.max_parallel_jobs(),
                effective: capabilities.max_parallel_jobs(),
            });
        }
        validate_resources(
            capabilities.resources_per_job(),
            observed.resources_per_job(),
        )?;
        if capabilities.sandbox().maximum_isolation() > observed.sandbox().maximum_isolation() {
            return Err(EffectiveRunnerError::IsolationExceedsEvidence);
        }
        if let Some(feature) = capabilities
            .sandbox()
            .features()
            .difference(observed.sandbox().features())
            .next()
        {
            return Err(EffectiveRunnerError::UnobservedSandboxFeature(
                feature.clone(),
            ));
        }
        if let Some(feature) = capabilities
            .containers()
            .features()
            .difference(observed.containers().features())
            .next()
        {
            return Err(EffectiveRunnerError::UnobservedContainerFeature(
                feature.clone(),
            ));
        }
        if let Some(feature) = capabilities
            .features()
            .difference(observed.features())
            .next()
        {
            return Err(EffectiveRunnerError::UnobservedRunnerFeature(
                feature.clone(),
            ));
        }
        if let Some(profile) = capabilities
            .environment_profiles()
            .difference(observed.environment_profiles())
            .next()
        {
            return Err(EffectiveRunnerError::UnobservedEnvironmentProfile(
                profile.clone(),
            ));
        }

        capabilities = capabilities
            .with_labels(routing.labels)
            .with_groups(routing.groups);

        let mut validated_slots = BTreeSet::new();
        for slot in available_slots {
            if slot.runner_id() != runner_id {
                return Err(EffectiveRunnerError::SlotRunnerMismatch {
                    expected: runner_id,
                    received: slot.runner_id(),
                });
            }
            if slot.ordinal() > capabilities.max_parallel_jobs() {
                return Err(EffectiveRunnerError::SlotOutOfRange {
                    ordinal: slot.ordinal(),
                    maximum: capabilities.max_parallel_jobs(),
                });
            }
            if !validated_slots.insert(slot) {
                return Err(EffectiveRunnerError::DuplicateSlot(slot));
            }
        }

        Ok(Self {
            session: evidence.session(),
            capabilities,
            available_slots: validated_slots,
            evidence_observed_at: evidence.observed_at(),
        })
    }

    /// Returns the authenticated session authorized to receive work.
    #[must_use]
    pub const fn session(&self) -> SessionGuard {
        self.session
    }

    /// Returns server-authorized capabilities used for requirement matching.
    #[must_use]
    pub const fn capabilities(&self) -> &RunnerCapabilities {
        &self.capabilities
    }

    /// Returns stable slots currently available for placement.
    #[must_use]
    pub const fn available_slots(&self) -> &BTreeSet<RunnerSlot> {
        &self.available_slots
    }

    /// Returns when the underlying runner evidence was observed.
    #[must_use]
    pub const fn evidence_observed_at(&self) -> UnixMillis {
        self.evidence_observed_at
    }
}

fn validate_resources(
    effective: ResourceCapacity,
    observed: ResourceCapacity,
) -> Result<(), EffectiveRunnerError> {
    let resources = [
        (
            ResourceKind::CpuMillis,
            u64::from(effective.cpu_millis()),
            u64::from(observed.cpu_millis()),
        ),
        (
            ResourceKind::MemoryBytes,
            effective.memory_bytes(),
            observed.memory_bytes(),
        ),
        (
            ResourceKind::EphemeralDiskBytes,
            effective.ephemeral_disk_bytes(),
            observed.ephemeral_disk_bytes(),
        ),
        (
            ResourceKind::GpuCount,
            u64::from(effective.gpu_count()),
            u64::from(observed.gpu_count()),
        ),
    ];
    if let Some((resource, effective, observed)) = resources
        .into_iter()
        .find(|(_, effective, observed)| effective > observed)
    {
        return Err(EffectiveRunnerError::ResourceExceedsEvidence {
            resource,
            observed,
            effective,
        });
    }
    Ok(())
}

/// Validation errors while reducing evidence to schedulable state.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EffectiveRunnerError {
    /// The effective capability set itself is malformed or unsupported.
    #[error(transparent)]
    InvalidCapabilities(#[from] CapabilityValidationError),
    /// Effective capabilities name a runner other than the authenticated one.
    #[error("authenticated runner {authenticated} cannot receive effective state for {effective}")]
    RunnerIdentityMismatch {
        /// Durable identity established by runner authentication.
        authenticated: RunnerId,
        /// Durable identity named by the rejected effective capability set.
        effective: RunnerId,
    },
    /// Administrative selectors were mixed into machine capability input.
    #[error(
        "effective machine capabilities must not contain labels or groups; supply authorized routing separately"
    )]
    SelectorsNotSeparated,
    /// Server policy cannot change the platform observed from the runner.
    #[error("effective runner platform differs from observed evidence")]
    PlatformMismatch,
    /// The effective concurrency limit is greater than observed capacity.
    #[error("effective slot limit {effective} exceeds observed limit {observed}")]
    SlotLimitExceedsEvidence {
        /// Maximum parallel jobs reported by the authenticated runner.
        observed: u16,
        /// Rejected maximum parallel jobs requested by server policy.
        effective: u16,
    },
    /// A quantitative effective capacity is greater than observed capacity.
    #[error("effective {resource:?} capacity {effective} exceeds observed capacity {observed}")]
    ResourceExceedsEvidence {
        /// Quantitative resource whose effective capacity exceeded evidence.
        resource: ResourceKind,
        /// Capacity reported by the authenticated runner.
        observed: u64,
        /// Rejected capacity requested by server policy.
        effective: u64,
    },
    /// Effective isolation strength is greater than the observed provider.
    #[error("effective isolation exceeds observed evidence")]
    IsolationExceedsEvidence,
    /// Effective state grants a sandbox feature absent from evidence.
    #[error("effective state grants unobserved sandbox feature {0}")]
    UnobservedSandboxFeature(SandboxFeature),
    /// Effective state grants a container feature absent from evidence.
    #[error("effective state grants unobserved container feature {0}")]
    UnobservedContainerFeature(ContainerFeature),
    /// Effective state grants a runner feature absent from evidence.
    #[error("effective state grants unobserved runner feature {0}")]
    UnobservedRunnerFeature(RunnerFeature),
    /// Effective state grants an environment profile absent from evidence.
    #[error("effective state grants unobserved environment profile {0:?}")]
    UnobservedEnvironmentProfile(EnvironmentProfile),
    /// A slot belongs to another durable runner.
    #[error("runner slot belongs to {received}; expected {expected}")]
    SlotRunnerMismatch {
        /// Authenticated runner for which effective state is being built.
        expected: RunnerId,
        /// Durable runner identity carried by the rejected slot.
        received: RunnerId,
    },
    /// A slot is beyond the server-authorized concurrency limit.
    #[error("runner slot ordinal {ordinal} exceeds effective maximum {maximum}")]
    SlotOutOfRange {
        /// One-based ordinal carried by the rejected slot.
        ordinal: u16,
        /// Greatest slot ordinal authorized by effective capabilities.
        maximum: u16,
    },
    /// The available-slot input contains the same stable slot more than once.
    #[error("runner slot {0:?} was supplied more than once")]
    DuplicateSlot(RunnerSlot),
}
