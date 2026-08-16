use std::{fmt, time::Duration};

use crate::{ContentKind, ContentProtectionError, SpoolError};

/// Closed protected-spool operation domain. Values never contain content identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SpoolOperation {
    /// Protect and durably publish immutable content.
    Persist,
    /// Read, authenticate, and verify referenced content.
    Load,
    /// Authenticate and durably remove referenced content.
    Remove,
    /// Verify the complete retain set and reclaim every other object.
    Reconcile,
}

/// Closed terminal outcome for a protected-spool operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SpoolOperationOutcome {
    /// The operation reached its complete success boundary.
    Success,
    /// Idempotent removal found the validated reference already absent.
    AlreadyAbsent,
    /// The operation returned a typed failure.
    Error,
}

/// Closed cryptographic operation domain.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SpoolProtectionOperation {
    /// Compute a domain-separated keyed commitment without exposing its key.
    Commitment,
    /// Convert plaintext to authenticated protected bytes before storage.
    Protect,
    /// Authenticate protected bytes and recover plaintext after reading.
    Unprotect,
}

/// Closed cryptographic outcome domain.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SpoolProtectionOutcome {
    /// The protection adapter completed successfully.
    Success,
    /// The protection adapter returned a secret-free failure.
    Error,
}

/// Resource whose configured spool capacity rejected an operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SpoolCapacityResource {
    /// The input plaintext exceeded the per-object byte limit.
    ObjectBytes,
    /// Publishing another unique object would exceed the object-count limit.
    ObjectCount,
    /// Publishing another unique object would exceed aggregate protected bytes.
    ProtectedBytes,
}

/// Bounded, secret-free category for a protected-spool failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SpoolFailureKind {
    /// Supplied metadata, limits, or a test fault violated an input invariant.
    InvalidInput,
    /// The exact protection identifier has no available key configuration.
    ProtectionKeyUnavailable,
    /// Protected bytes failed authenticated opening.
    Authentication,
    /// The protection adapter failed without a more specific public category.
    Protection,
    /// A configured or hard resource bound was exhausted.
    Capacity,
    /// Publication, reconciliation, or retain-set capture could not proceed safely.
    Fenced,
    /// A required durable object was absent.
    Missing,
    /// A filesystem mutation may have crossed its commit boundary.
    Uncertain,
    /// The handle rejected work after an uncertain mutation.
    Poisoned,
    /// Host path validation, no-follow opening, or exclusive ownership failed.
    PathSecurity,
    /// A host-filesystem operation failed.
    Io,
    /// No secure filesystem adapter exists for the current platform.
    Unsupported,
}

impl SpoolFailureKind {
    pub(crate) const fn from_error(error: &SpoolError) -> Self {
        match error {
            SpoolError::Root(_) | SpoolError::Invariant(_) | SpoolError::InjectedFault(_) => {
                Self::InvalidInput
            }
            SpoolError::Protection(ContentProtectionError::KeyUnavailable) => {
                Self::ProtectionKeyUnavailable
            }
            SpoolError::Protection(ContentProtectionError::AuthenticationFailed) => {
                Self::Authentication
            }
            SpoolError::Protection(ContentProtectionError::Failed) => Self::Protection,
            SpoolError::CapacityExhausted => Self::Capacity,
            SpoolError::PublicationsInFlight
            | SpoolError::ReconciliationInProgress
            | SpoolError::RetainedContent(_) => Self::Fenced,
            SpoolError::ContentMissing => Self::Missing,
            SpoolError::CommitOutcomeUnknown
            | SpoolError::RemovalOutcomeUnknown { .. }
            | SpoolError::ReconciliationOutcomeUnknown => Self::Uncertain,
            SpoolError::Poisoned => Self::Poisoned,
            SpoolError::AlreadyLocked | SpoolError::PathSecurity => Self::PathSecurity,
            SpoolError::Io { .. } => Self::Io,
            SpoolError::UnsupportedPlatform => Self::Unsupported,
        }
    }
}

/// One identifier-free protected-spool observation.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SpoolEvent {
    /// An operation began before validation or filesystem work.
    OperationStarted {
        /// Closed operation category.
        operation: SpoolOperation,
    },
    /// An operation returned its terminal result.
    OperationCompleted {
        /// Closed operation category.
        operation: SpoolOperation,
        /// Semantic payload kind, or `None` for whole-spool reconciliation.
        content_kind: Option<ContentKind>,
        /// Terminal result category.
        outcome: SpoolOperationOutcome,
        /// Sanitized failure category, present exactly for an error outcome.
        failure: Option<SpoolFailureKind>,
        /// Local elapsed time spent in the operation.
        duration: Duration,
    },
    /// Logical protected-content bytes successfully persisted, loaded, or removed.
    ContentBytes {
        /// Operation that accounted the bytes.
        operation: SpoolOperation,
        /// Semantic role of the accounted content.
        content_kind: ContentKind,
        /// Exact plaintext bytes for public kinds, or the opaque padded
        /// allocation class for an endpoint result; never the bytes themselves.
        bytes: u64,
    },
    /// One protection-adapter invocation completed.
    Protection {
        /// Whether bytes were being protected or opened.
        operation: SpoolProtectionOperation,
        /// Sanitized adapter outcome.
        outcome: SpoolProtectionOutcome,
    },
    /// A configured capacity bound rejected work.
    CapacityRejected {
        /// Resource whose limit was reached.
        resource: SpoolCapacityResource,
    },
    /// Reconciliation durably reclaimed unreferenced objects.
    Reclaimed {
        /// Number of immutable objects reclaimed.
        objects: u64,
        /// Aggregate encoded bytes reclaimed from the host filesystem.
        protected_bytes: u64,
    },
    /// An uncertain mutation made the current handle unusable.
    Poisoned {
        /// Operation whose mutation outcome became uncertain.
        operation: SpoolOperation,
    },
}

/// Infallible observer for protected-spool state transitions.
pub trait SpoolObserver: fmt::Debug + Send + Sync {
    /// Records one closed, identifier-free event without affecting spool behavior.
    fn observe(&self, event: SpoolEvent);
}

/// Production default when metrics are disabled.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopSpoolObserver;

impl SpoolObserver for NoopSpoolObserver {
    fn observe(&self, _event: SpoolEvent) {}
}
