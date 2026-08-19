use std::fmt;

use automata_ci_core::ManagedTenantId;
use thiserror::Error;

use crate::{OperationId, ProvisioningAuthority, ShardId};

const MILLIS_PER_SECOND: u64 = 1_000;
const MAX_DURABLE_SECONDS: u64 = (i64::MAX as u64) / MILLIS_PER_SECOND;
const MAX_ENTITLEMENT_DURATION_SECONDS: u64 = 10 * 366 * 24 * 60 * 60;
const PROTOBUF_TIMESTAMP_MIN_SECONDS: i64 = -62_135_596_800;
const PROTOBUF_TIMESTAMP_MAX_SECONDS: i64 = 253_402_300_799;
const NANOS_PER_SECOND: u32 = 1_000_000_000;

/// Monotonically increasing version of one tenant entitlement snapshot.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EntitlementRevision(u64);

impl EntitlementRevision {
    /// Creates a positive revision representable by the durable `PostgreSQL` boundary.
    ///
    /// # Errors
    ///
    /// Rejects zero and values larger than a signed 64-bit integer.
    pub const fn new(value: u64) -> Result<Self, EntitlementValueError> {
        if value == 0 || value > i64::MAX as u64 {
            return Err(EntitlementValueError::InvalidRevision);
        }
        Ok(Self(value))
    }

    /// Returns the numeric revision.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Positive tenant compute allowance measured at whole-second granularity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ComputeSeconds(u64);

impl ComputeSeconds {
    /// Creates an allowance representable internally as durable milliseconds.
    ///
    /// # Errors
    ///
    /// Rejects zero and values whose millisecond representation would overflow.
    pub const fn new(value: u64) -> Result<Self, EntitlementValueError> {
        if value == 0 || value > MAX_DURABLE_SECONDS {
            return Err(EntitlementValueError::InvalidComputeSeconds);
        }
        Ok(Self(value))
    }

    /// Returns the whole-second allowance.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Positive relative validity period measured at whole-second granularity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EntitlementDurationSeconds(u64);

impl EntitlementDurationSeconds {
    /// Creates a duration representable internally as durable milliseconds.
    ///
    /// # Errors
    ///
    /// Rejects zero and values longer than ten conservative leap years.
    pub const fn new(value: u64) -> Result<Self, EntitlementValueError> {
        if value == 0 || value > MAX_ENTITLEMENT_DURATION_SECONDS {
            return Err(EntitlementValueError::InvalidDuration);
        }
        Ok(Self(value))
    }

    /// Returns the whole-second duration.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Complete execution policy installed for one tenant revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TenantExecutionEntitlement {
    /// Execution is bounded by aggregate tenant compute, optionally until a deadline.
    Capped {
        /// Total compute available to this entitlement revision.
        compute_seconds: ComputeSeconds,
        /// Optional validity period anchored by Core when the revision commits.
        valid_for: Option<EntitlementDurationSeconds>,
    },
    /// Execution is metered but has no Core-enforced tenant compute ceiling.
    Uncapped,
    /// New and running execution is not permitted.
    Paused,
}

impl TenantExecutionEntitlement {
    /// Creates a capped aggregate tenant allowance.
    #[must_use]
    pub const fn capped(
        compute_seconds: ComputeSeconds,
        valid_for: Option<EntitlementDurationSeconds>,
    ) -> Self {
        Self::Capped {
            compute_seconds,
            valid_for,
        }
    }
}

/// Complete validated semantic input for one tenant entitlement revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyTenantEntitlementCommand {
    operation_id: OperationId,
    shard_id: ShardId,
    tenant_id: ManagedTenantId,
    revision: EntitlementRevision,
    execution: TenantExecutionEntitlement,
}

impl ApplyTenantEntitlementCommand {
    /// Creates a complete entitlement snapshot command.
    #[must_use]
    pub const fn new(
        operation_id: OperationId,
        shard_id: ShardId,
        tenant_id: ManagedTenantId,
        revision: EntitlementRevision,
        execution: TenantExecutionEntitlement,
    ) -> Self {
        Self {
            operation_id,
            shard_id,
            tenant_id,
            revision,
            execution,
        }
    }

    /// Returns the durable caller-generated operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the expected shard identity.
    #[must_use]
    pub const fn shard_id(&self) -> &ShardId {
        &self.shard_id
    }

    /// Returns the tenant receiving this snapshot.
    #[must_use]
    pub const fn tenant_id(&self) -> ManagedTenantId {
        self.tenant_id
    }

    /// Returns the monotonic tenant revision.
    #[must_use]
    pub const fn revision(&self) -> EntitlementRevision {
        self.revision
    }

    /// Returns the complete execution policy.
    #[must_use]
    pub const fn execution(&self) -> TenantExecutionEntitlement {
        self.execution
    }
}

/// Entitlement command proven to target the authority's configured shard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedApplyTenantEntitlement {
    authority: ProvisioningAuthority,
    command: ApplyTenantEntitlementCommand,
}

impl AuthorizedApplyTenantEntitlement {
    /// Authorizes a command against the server-derived shard binding.
    ///
    /// Durable persistence additionally requires the same authority to own the
    /// tenant's external-management binding.
    ///
    /// # Errors
    ///
    /// Rejects a command for another shard.
    pub fn authorize(
        authority: ProvisioningAuthority,
        command: ApplyTenantEntitlementCommand,
    ) -> Result<Self, EntitlementAuthorizationError> {
        if authority.shard_id() != command.shard_id() {
            return Err(EntitlementAuthorizationError::Forbidden);
        }
        Ok(Self { authority, command })
    }

    /// Returns the stable server-derived authority.
    #[must_use]
    pub const fn authority(&self) -> &ProvisioningAuthority {
        &self.authority
    }

    /// Returns the validated semantic command.
    #[must_use]
    pub const fn command(&self) -> &ApplyTenantEntitlementCommand {
        &self.command
    }

    /// Consumes the request into its authority and command.
    #[must_use]
    pub fn into_parts(self) -> (ProvisioningAuthority, ApplyTenantEntitlementCommand) {
        (self.authority, self.command)
    }
}

/// Protobuf-compatible UTC instant returned by the durable entitlement transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntitlementTimestamp {
    seconds: i64,
    nanoseconds: u32,
}

impl EntitlementTimestamp {
    /// Creates an instant within the Protobuf Timestamp range.
    ///
    /// # Errors
    ///
    /// Rejects out-of-range seconds or one billion or more nanoseconds.
    pub const fn new(seconds: i64, nanoseconds: u32) -> Result<Self, EntitlementValueError> {
        if seconds < PROTOBUF_TIMESTAMP_MIN_SECONDS
            || seconds > PROTOBUF_TIMESTAMP_MAX_SECONDS
            || nanoseconds >= NANOS_PER_SECOND
        {
            return Err(EntitlementValueError::InvalidTimestamp);
        }
        Ok(Self {
            seconds,
            nanoseconds,
        })
    }

    /// Returns whole Unix seconds.
    #[must_use]
    pub const fn seconds(self) -> i64 {
        self.seconds
    }

    /// Returns fractional nanoseconds within the second.
    #[must_use]
    pub const fn nanoseconds(self) -> u32 {
        self.nanoseconds
    }
}

/// Stable result committed atomically with one entitlement revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyTenantEntitlementResult {
    operation_id: OperationId,
    shard_id: ShardId,
    tenant_id: ManagedTenantId,
    revision: EntitlementRevision,
    applied_at: EntitlementTimestamp,
    expires_at: Option<EntitlementTimestamp>,
}

impl ApplyTenantEntitlementResult {
    /// Creates a durable first-attempt or replay result.
    #[must_use]
    pub const fn new(
        operation_id: OperationId,
        shard_id: ShardId,
        tenant_id: ManagedTenantId,
        revision: EntitlementRevision,
        applied_at: EntitlementTimestamp,
        expires_at: Option<EntitlementTimestamp>,
    ) -> Self {
        Self {
            operation_id,
            shard_id,
            tenant_id,
            revision,
            applied_at,
            expires_at,
        }
    }

    /// Returns the request operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the shard that committed the operation.
    #[must_use]
    pub const fn shard_id(&self) -> &ShardId {
        &self.shard_id
    }

    /// Returns the tenant receiving the snapshot.
    #[must_use]
    pub const fn tenant_id(&self) -> ManagedTenantId {
        self.tenant_id
    }

    /// Returns the committed tenant revision.
    #[must_use]
    pub const fn revision(&self) -> EntitlementRevision {
        self.revision
    }

    /// Returns Core's canonical database commit time.
    #[must_use]
    pub const fn applied_at(&self) -> EntitlementTimestamp {
        self.applied_at
    }

    /// Returns the Core-anchored deadline, when the snapshot has one.
    #[must_use]
    pub const fn expires_at(&self) -> Option<EntitlementTimestamp> {
        self.expires_at
    }
}

/// Closed failures returned by durable entitlement application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntitlementFailureKind {
    /// The operation identity is already bound to different semantic input.
    OperationConflict,
    /// The revision is not newer than the tenant's current revision.
    StaleRevision,
    /// The tenant is not managed by this exact external authority.
    TenantUnavailable,
    /// The authority exceeded a bounded mutation rate.
    RateLimited,
    /// Core failed without a safer specific result.
    Internal,
    /// A required durable dependency is temporarily unavailable.
    TemporarilyUnavailable,
}

/// Sanitized durable entitlement failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("tenant entitlement application failed: {kind:?}")]
pub struct EntitlementFailure {
    kind: EntitlementFailureKind,
}

impl EntitlementFailure {
    /// Creates one closed application failure.
    #[must_use]
    pub const fn new(kind: EntitlementFailureKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure kind.
    #[must_use]
    pub const fn kind(self) -> EntitlementFailureKind {
        self.kind
    }
}

/// Server-derived scope rejection for a valid entitlement command.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EntitlementAuthorizationError {
    /// The authority is not bound to the requested shard.
    #[error("the management authority is outside the requested shard")]
    Forbidden,
}

/// Validation failure for an entitlement domain value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EntitlementValueError {
    /// The revision is zero or outside the durable range.
    #[error("entitlement revision is invalid")]
    InvalidRevision,
    /// The compute allowance is zero or outside the durable range.
    #[error("compute seconds are invalid")]
    InvalidComputeSeconds,
    /// The relative duration is zero or outside the durable range.
    #[error("entitlement duration is invalid")]
    InvalidDuration,
    /// The durable timestamp cannot be represented by Protobuf.
    #[error("entitlement timestamp is invalid")]
    InvalidTimestamp,
}

impl fmt::Display for EntitlementRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DelegatedActorIssuer, ProvisioningAuthorityId};

    fn authority() -> ProvisioningAuthority {
        ProvisioningAuthority::new(
            ProvisioningAuthorityId::new("automata-cloud-production").unwrap(),
            ShardId::new("prod-us-east-1-001").unwrap(),
            DelegatedActorIssuer::new("https://cloud.automata.example").unwrap(),
        )
    }

    fn command() -> ApplyTenantEntitlementCommand {
        ApplyTenantEntitlementCommand::new(
            OperationId::parse("55555555-5555-4555-8555-555555555555").unwrap(),
            ShardId::new("prod-us-east-1-001").unwrap(),
            ManagedTenantId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
            EntitlementRevision::new(1).unwrap(),
            TenantExecutionEntitlement::capped(
                ComputeSeconds::new(6_000).unwrap(),
                Some(EntitlementDurationSeconds::new(7 * 24 * 60 * 60).unwrap()),
            ),
        )
    }

    #[test]
    fn capped_snapshot_authorizes_for_exact_shard() {
        let authorized =
            AuthorizedApplyTenantEntitlement::authorize(authority(), command()).unwrap();
        assert_eq!(authorized.command().revision().get(), 1);
        assert_eq!(
            authorized.command().execution(),
            TenantExecutionEntitlement::capped(
                ComputeSeconds::new(6_000).unwrap(),
                Some(EntitlementDurationSeconds::new(604_800).unwrap())
            )
        );
    }

    #[test]
    fn another_shard_is_forbidden() {
        let mut command = command();
        command.shard_id = ShardId::new("prod-eu-west-1-001").unwrap();
        assert_eq!(
            AuthorizedApplyTenantEntitlement::authorize(authority(), command),
            Err(EntitlementAuthorizationError::Forbidden)
        );
    }

    #[test]
    fn budget_values_are_positive_and_durably_bounded() {
        assert_eq!(
            EntitlementRevision::new(0),
            Err(EntitlementValueError::InvalidRevision)
        );
        assert_eq!(
            ComputeSeconds::new(0),
            Err(EntitlementValueError::InvalidComputeSeconds)
        );
        assert_eq!(
            EntitlementDurationSeconds::new(MAX_ENTITLEMENT_DURATION_SECONDS + 1),
            Err(EntitlementValueError::InvalidDuration)
        );
    }
}
