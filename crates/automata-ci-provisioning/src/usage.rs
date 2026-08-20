use std::fmt;

use automata_ci_core::ManagedTenantId;
use thiserror::Error;
use uuid::Uuid;

use crate::{EntitlementRevision, ProvisioningAuthority, ShardId};

const MAX_CURSOR_BYTES: usize = 512;
const MAX_PAGE_SIZE: u32 = 1_000;
const PROTOBUF_TIMESTAMP_MIN_SECONDS: i64 = -62_135_596_800;
const PROTOBUF_TIMESTAMP_MAX_SECONDS: i64 = 253_402_300_799;
const NANOS_PER_SECOND: u32 = 1_000_000_000;

macro_rules! usage_uuid_identifier {
    ($name:ident, $error:ident, $label:literal) => {
        #[doc = concat!("A validated, non-nil canonical UUID identifying ", $label, ".")]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            #[doc = concat!("Parses the canonical UUID for ", $label, ".")]
            ///
            /// # Errors
            ///
            /// Rejects nil, non-hyphenated, upper-case, or otherwise
            /// non-canonical UUID text.
            pub fn parse(value: &str) -> Result<Self, UsageValueError> {
                let parsed = Uuid::parse_str(value).map_err(|_| UsageValueError::$error)?;
                if parsed.is_nil() || parsed.hyphenated().to_string() != value {
                    return Err(UsageValueError::$error);
                }
                Ok(Self(parsed))
            }

            #[doc = concat!("Creates ", $label, " from a trusted non-nil UUID.")]
            ///
            /// # Errors
            ///
            /// Rejects the nil UUID.
            pub const fn from_uuid(value: Uuid) -> Result<Self, UsageValueError> {
                if value.is_nil() {
                    return Err(UsageValueError::$error);
                }
                Ok(Self(value))
            }

            #[doc = concat!("Returns the UUID for ", $label, ".")]
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}", self.0.hyphenated())
            }
        }
    };
}

usage_uuid_identifier!(UsageEventId, InvalidEventId, "an immutable usage event");
usage_uuid_identifier!(UsageAttemptId, InvalidAttemptId, "an execution attempt");

/// Opaque position after the last usage event durably accepted by a consumer.
///
/// Cursors are scoped to the authenticated authority and shard. Consumers must
/// not inspect, synthesize, or transfer them between authorities or shards.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct UsageExportCursor(Vec<u8>);

impl UsageExportCursor {
    /// Creates a bounded opaque cursor. Empty means the start of the feed.
    ///
    /// # Errors
    ///
    /// Rejects values larger than the public contract bound.
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, UsageValueError> {
        let value = value.into();
        if value.len() > MAX_CURSOR_BYTES {
            return Err(UsageValueError::InvalidCursor);
        }
        Ok(Self(value))
    }

    /// Creates the initial position before the first event.
    #[must_use]
    pub const fn beginning() -> Self {
        Self(Vec::new())
    }

    /// Returns the opaque cursor bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the cursor into its opaque bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Positive maximum number of usage events requested in one page.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UsageExportPageSize(u32);

impl UsageExportPageSize {
    /// Largest page supported by the version-one contract.
    pub const MAX: u32 = MAX_PAGE_SIZE;

    /// Creates a bounded page size.
    ///
    /// # Errors
    ///
    /// Rejects zero and values larger than [`Self::MAX`].
    pub const fn new(value: u32) -> Result<Self, UsageValueError> {
        if value == 0 || value > Self::MAX {
            return Err(UsageValueError::InvalidPageSize);
        }
        Ok(Self(value))
    }

    /// Returns the requested event count.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Protobuf-compatible UTC instant delimiting an accounted execution interval.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UsageTimestamp {
    seconds: i64,
    nanoseconds: u32,
}

impl UsageTimestamp {
    /// Creates an instant within the Protobuf Timestamp range.
    ///
    /// # Errors
    ///
    /// Rejects out-of-range seconds or one billion or more nanoseconds.
    pub const fn new(seconds: i64, nanoseconds: u32) -> Result<Self, UsageValueError> {
        if seconds < PROTOBUF_TIMESTAMP_MIN_SECONDS
            || seconds > PROTOBUF_TIMESTAMP_MAX_SECONDS
            || nanoseconds >= NANOS_PER_SECOND
        {
            return Err(UsageValueError::InvalidTimestamp);
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

/// Positive actual compute consumption measured in milliseconds.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConsumedComputeMilliseconds(u64);

impl ConsumedComputeMilliseconds {
    /// Creates a duration representable by the durable signed boundary.
    ///
    /// # Errors
    ///
    /// Rejects zero and values larger than a signed 64-bit integer.
    pub const fn new(value: u64) -> Result<Self, UsageValueError> {
        if value == 0 || value > i64::MAX as u64 {
            return Err(UsageValueError::InvalidConsumedCompute);
        }
        Ok(Self(value))
    }

    /// Returns the consumed milliseconds.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// One immutable, idempotently consumable execution-accounting fact.
///
/// Multiple events may describe non-overlapping intervals of the same attempt.
/// The event is provider-neutral actual usage, not a price, invoice line, or
/// promise that a commercial provider will bill the interval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantUsageEvent {
    event_id: UsageEventId,
    shard_id: ShardId,
    tenant_id: ManagedTenantId,
    attempt_id: UsageAttemptId,
    entitlement_revision: EntitlementRevision,
    interval_start: UsageTimestamp,
    interval_end: UsageTimestamp,
    consumed_compute: ConsumedComputeMilliseconds,
}

impl TenantUsageEvent {
    /// Creates one positive accounted interval under an entitlement revision.
    ///
    /// # Errors
    ///
    /// Rejects an interval whose end is not strictly after its start.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_id: UsageEventId,
        shard_id: ShardId,
        tenant_id: ManagedTenantId,
        attempt_id: UsageAttemptId,
        entitlement_revision: EntitlementRevision,
        interval_start: UsageTimestamp,
        interval_end: UsageTimestamp,
        consumed_compute: ConsumedComputeMilliseconds,
    ) -> Result<Self, UsageValueError> {
        if interval_end <= interval_start {
            return Err(UsageValueError::InvalidInterval);
        }
        Ok(Self {
            event_id,
            shard_id,
            tenant_id,
            attempt_id,
            entitlement_revision,
            interval_start,
            interval_end,
            consumed_compute,
        })
    }

    /// Returns the global idempotency identity for this fact.
    #[must_use]
    pub const fn event_id(&self) -> UsageEventId {
        self.event_id
    }

    /// Returns the shard that recorded the fact.
    #[must_use]
    pub const fn shard_id(&self) -> &ShardId {
        &self.shard_id
    }

    /// Returns the tenant that consumed the compute.
    #[must_use]
    pub const fn tenant_id(&self) -> ManagedTenantId {
        self.tenant_id
    }

    /// Returns the execution attempt that consumed the compute.
    #[must_use]
    pub const fn attempt_id(&self) -> UsageAttemptId {
        self.attempt_id
    }

    /// Returns the entitlement revision charged by Core accounting.
    #[must_use]
    pub const fn entitlement_revision(&self) -> EntitlementRevision {
        self.entitlement_revision
    }

    /// Returns the inclusive beginning of the accounted interval.
    #[must_use]
    pub const fn interval_start(&self) -> UsageTimestamp {
        self.interval_start
    }

    /// Returns the exclusive end of the accounted interval.
    #[must_use]
    pub const fn interval_end(&self) -> UsageTimestamp {
        self.interval_end
    }

    /// Returns actual compute consumed during the interval.
    #[must_use]
    pub const fn consumed_compute(&self) -> ConsumedComputeMilliseconds {
        self.consumed_compute
    }
}

/// Validated request for an authority-scoped page of immutable usage events.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListTenantUsageCommand {
    shard_id: ShardId,
    cursor: UsageExportCursor,
    page_size: UsageExportPageSize,
}

impl ListTenantUsageCommand {
    /// Creates one cursor-pull request.
    #[must_use]
    pub const fn new(
        shard_id: ShardId,
        cursor: UsageExportCursor,
        page_size: UsageExportPageSize,
    ) -> Self {
        Self {
            shard_id,
            cursor,
            page_size,
        }
    }

    /// Returns the expected immutable shard identity.
    #[must_use]
    pub const fn shard_id(&self) -> &ShardId {
        &self.shard_id
    }

    /// Returns the exclusive cursor after the last durably accepted event.
    #[must_use]
    pub const fn cursor(&self) -> &UsageExportCursor {
        &self.cursor
    }

    /// Returns the maximum number of events requested.
    #[must_use]
    pub const fn page_size(&self) -> UsageExportPageSize {
        self.page_size
    }
}

/// Usage request proven to target the authenticated authority's configured shard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedListTenantUsage {
    authority: ProvisioningAuthority,
    command: ListTenantUsageCommand,
}

impl AuthorizedListTenantUsage {
    /// Authorizes a usage request against the server-derived shard binding.
    ///
    /// Durable export additionally filters events by this exact authority so
    /// two authorities sharing a shard cannot observe each other's tenants.
    ///
    /// # Errors
    ///
    /// Rejects a command for another shard.
    pub fn authorize(
        authority: ProvisioningAuthority,
        command: ListTenantUsageCommand,
    ) -> Result<Self, UsageAuthorizationError> {
        if authority.shard_id() != command.shard_id() {
            return Err(UsageAuthorizationError::Forbidden);
        }
        Ok(Self { authority, command })
    }

    /// Returns the stable server-derived authority and export namespace.
    #[must_use]
    pub const fn authority(&self) -> &ProvisioningAuthority {
        &self.authority
    }

    /// Returns the validated semantic command.
    #[must_use]
    pub const fn command(&self) -> &ListTenantUsageCommand {
        &self.command
    }

    /// Consumes the request into its authority and command.
    #[must_use]
    pub fn into_parts(self) -> (ProvisioningAuthority, ListTenantUsageCommand) {
        (self.authority, self.command)
    }
}

/// Stable page returned from the durable authority-scoped usage feed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantUsagePage {
    events: Vec<TenantUsageEvent>,
    next_cursor: UsageExportCursor,
}

impl TenantUsagePage {
    /// Creates one bounded page and its exclusive continuation cursor.
    ///
    /// # Errors
    ///
    /// Rejects more events than the version-one page bound.
    pub fn new(
        events: Vec<TenantUsageEvent>,
        next_cursor: UsageExportCursor,
    ) -> Result<Self, UsageValueError> {
        if events.len() > MAX_PAGE_SIZE as usize {
            return Err(UsageValueError::TooManyEvents);
        }
        Ok(Self {
            events,
            next_cursor,
        })
    }

    /// Returns the immutable events in stable feed order.
    #[must_use]
    pub fn events(&self) -> &[TenantUsageEvent] {
        &self.events
    }

    /// Returns the exclusive cursor to use for the next request.
    #[must_use]
    pub const fn next_cursor(&self) -> &UsageExportCursor {
        &self.next_cursor
    }

    /// Consumes the page into its events and continuation cursor.
    #[must_use]
    pub fn into_parts(self) -> (Vec<TenantUsageEvent>, UsageExportCursor) {
        (self.events, self.next_cursor)
    }
}

/// Closed failures returned by the durable usage feed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsageExportFailureKind {
    /// The cursor is unknown, malformed internally, or no longer retained.
    InvalidCursor,
    /// The authority exceeded a bounded export rate.
    RateLimited,
    /// Core failed without a safer specific result.
    Internal,
    /// A required durable dependency is temporarily unavailable.
    TemporarilyUnavailable,
}

/// Sanitized durable usage-export failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("tenant usage export failed: {kind:?}")]
pub struct UsageExportFailure {
    kind: UsageExportFailureKind,
}

impl UsageExportFailure {
    /// Creates one closed export failure.
    #[must_use]
    pub const fn new(kind: UsageExportFailureKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure kind.
    #[must_use]
    pub const fn kind(self) -> UsageExportFailureKind {
        self.kind
    }
}

/// Server-derived scope rejection for a valid usage request.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum UsageAuthorizationError {
    /// The authority is not bound to the requested shard.
    #[error("the management authority is outside the requested shard")]
    Forbidden,
}

/// Validation failure for a usage-export domain value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum UsageValueError {
    /// The immutable event UUID is invalid.
    #[error("usage event ID is invalid")]
    InvalidEventId,
    /// The execution-attempt UUID is invalid.
    #[error("usage attempt ID is invalid")]
    InvalidAttemptId,
    /// The opaque cursor exceeds the public bound.
    #[error("usage export cursor is invalid")]
    InvalidCursor,
    /// The requested page size is zero or above the public bound.
    #[error("usage export page size is invalid")]
    InvalidPageSize,
    /// The timestamp cannot be represented by Protobuf.
    #[error("usage timestamp is invalid")]
    InvalidTimestamp,
    /// The accounted interval is empty or reversed.
    #[error("usage interval is invalid")]
    InvalidInterval,
    /// The actual compute duration is zero or outside the durable range.
    #[error("consumed compute is invalid")]
    InvalidConsumedCompute,
    /// A durable adapter returned more events than the contract permits.
    #[error("usage export page contains too many events")]
    TooManyEvents,
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

    fn event() -> TenantUsageEvent {
        TenantUsageEvent::new(
            UsageEventId::parse("77777777-7777-4777-8777-777777777777").unwrap(),
            ShardId::new("prod-us-east-1-001").unwrap(),
            ManagedTenantId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
            UsageAttemptId::parse("66666666-6666-4666-8666-666666666666").unwrap(),
            EntitlementRevision::new(3).unwrap(),
            UsageTimestamp::new(1_786_500_100, 0).unwrap(),
            UsageTimestamp::new(1_786_500_105, 0).unwrap(),
            ConsumedComputeMilliseconds::new(5_000).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn cursor_pull_authorizes_for_exact_shard() {
        let command = ListTenantUsageCommand::new(
            ShardId::new("prod-us-east-1-001").unwrap(),
            UsageExportCursor::beginning(),
            UsageExportPageSize::new(250).unwrap(),
        );
        let authorized = AuthorizedListTenantUsage::authorize(authority(), command).unwrap();
        assert_eq!(authorized.command().page_size().get(), 250);
        assert!(authorized.command().cursor().as_bytes().is_empty());

        let page = TenantUsagePage::new(
            vec![event()],
            UsageExportCursor::new(vec![0, 0, 0, 1]).unwrap(),
        )
        .unwrap();
        assert_eq!(page.events().len(), 1);
        assert_eq!(page.next_cursor().as_bytes(), &[0, 0, 0, 1]);
    }

    #[test]
    fn another_shard_is_forbidden() {
        let command = ListTenantUsageCommand::new(
            ShardId::new("prod-eu-west-1-001").unwrap(),
            UsageExportCursor::beginning(),
            UsageExportPageSize::new(100).unwrap(),
        );
        assert_eq!(
            AuthorizedListTenantUsage::authorize(authority(), command),
            Err(UsageAuthorizationError::Forbidden)
        );
    }

    #[test]
    fn identifiers_cursor_and_page_size_are_bounded() {
        assert_eq!(
            UsageEventId::parse("00000000-0000-0000-0000-000000000000"),
            Err(UsageValueError::InvalidEventId)
        );
        assert_eq!(
            UsageAttemptId::parse("66666666666646668666666666666666"),
            Err(UsageValueError::InvalidAttemptId)
        );
        assert_eq!(
            UsageExportCursor::new(vec![0; MAX_CURSOR_BYTES + 1]),
            Err(UsageValueError::InvalidCursor)
        );
        assert_eq!(
            UsageExportPageSize::new(0),
            Err(UsageValueError::InvalidPageSize)
        );
        assert_eq!(
            UsageExportPageSize::new(MAX_PAGE_SIZE + 1),
            Err(UsageValueError::InvalidPageSize)
        );
        assert_eq!(
            TenantUsagePage::new(
                vec![event(); MAX_PAGE_SIZE as usize + 1],
                UsageExportCursor::beginning(),
            ),
            Err(UsageValueError::TooManyEvents)
        );
    }

    #[test]
    fn usage_intervals_and_compute_are_positive() {
        let start = UsageTimestamp::new(1_786_500_100, 0).unwrap();
        assert_eq!(
            TenantUsageEvent::new(
                UsageEventId::parse("77777777-7777-4777-8777-777777777777").unwrap(),
                ShardId::new("prod-us-east-1-001").unwrap(),
                ManagedTenantId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
                UsageAttemptId::parse("66666666-6666-4666-8666-666666666666").unwrap(),
                EntitlementRevision::new(3).unwrap(),
                start,
                start,
                ConsumedComputeMilliseconds::new(1).unwrap(),
            ),
            Err(UsageValueError::InvalidInterval)
        );
        assert_eq!(
            ConsumedComputeMilliseconds::new(0),
            Err(UsageValueError::InvalidConsumedCompute)
        );
    }
}
