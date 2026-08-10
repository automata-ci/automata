use std::fmt;

use automata_ci_core::OperationId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::JournalInvariantError;

const MAX_PROVIDER_NAME_BYTES: usize = 64;
const MAX_SANDBOX_HANDLE_BYTES: usize = 192;

/// Validated, non-secret provider adapter identifier.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderName(String);

impl ProviderName {
    /// Validates a provider name.
    ///
    /// # Errors
    ///
    /// Names must be short ASCII identifiers beginning with a lowercase
    /// alphanumeric byte.
    pub fn new(value: impl Into<String>) -> Result<Self, JournalInvariantError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_PROVIDER_NAME_BYTES
            && value
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
            });
        if valid {
            Ok(Self(value))
        } else {
            Err(JournalInvariantError::InvalidProviderName)
        }
    }

    /// Returns the validated non-secret adapter identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProviderName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ProviderName")
            .field(&self.0)
            .finish()
    }
}

impl Serialize for ProviderName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ProviderName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Bounded opaque sandbox identifier. URL/query syntax, whitespace, path
/// separators, and assignment characters are intentionally excluded so this
/// value cannot act as a credential-bearing connection string.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SandboxHandle(String);

impl SandboxHandle {
    /// Validates an identifier-only provider handle.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, path-like, or connection-string-like values.
    pub fn new(value: impl Into<String>) -> Result<Self, JournalInvariantError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_SANDBOX_HANDLE_BYTES
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte));
        if valid {
            Ok(Self(value))
        } else {
            Err(JournalInvariantError::InvalidSandboxHandle)
        }
    }

    /// Returns the validated opaque identifier at the provider boundary.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SandboxHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SandboxHandle")
            .field("identifier_bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl Serialize for SandboxHandle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SandboxHandle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Provider mutations whose intent must precede the external side effect.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderOperationKind {
    /// Allocate the sandbox and establish its recoverable opaque identity.
    CreateSandbox,
    /// Start execution in an allocated, stopped sandbox.
    StartSandbox,
    /// Stop execution while retaining the sandbox for recovery or teardown.
    StopSandbox,
    /// Irreversibly remove the allocated sandbox.
    DestroySandbox,
}

/// Bounded, non-secret classification of a provider failure.
///
/// Adapter diagnostics and provider responses deliberately do not belong in
/// the journal because they can contain credentials or other sensitive data.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFailureKind {
    /// The provider rejected bounded request semantics.
    InvalidRequest,
    /// The adapter or provider does not implement the requested operation.
    Unsupported,
    /// Provider authorization did not permit the operation.
    PermissionDenied,
    /// A provider capacity or quota ceiling prevented the operation.
    ResourceExhausted,
    /// The named recoverable provider object does not exist.
    NotFound,
    /// Existing provider state conflicts with the requested mutation.
    Conflict,
    /// The provider could not be reached or was temporarily unavailable.
    Unavailable,
    /// The provider response did not arrive within the bounded deadline.
    TimedOut,
    /// A non-secret internal adapter or provider failure occurred.
    Internal,
}

/// Whether a failed provider call is known not to have changed external state.
///
/// An uncertain outcome remains an unresolved operation. Recovery must retry
/// or reconcile the same operation identity before recording another intent.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "snake_case",
    tag = "effect",
    content = "kind"
)]
pub enum ProviderFailureOutcome {
    /// The provider call is known not to have changed external state.
    KnownNoEffect(ProviderFailureKind),
    /// The call may have changed external state and must retain its fence.
    Uncertain(ProviderFailureKind),
}

impl ProviderFailureOutcome {
    /// Returns the bounded, secret-free failure class.
    #[must_use]
    pub const fn kind(self) -> ProviderFailureKind {
        match self {
            Self::KnownNoEffect(kind) | Self::Uncertain(kind) => kind,
        }
    }

    /// Reports whether recovery must retry or reconcile the same operation ID.
    #[must_use]
    pub const fn is_uncertain(self) -> bool {
        matches!(self, Self::Uncertain(_))
    }
}

/// Durable recovery outcome for one idempotent provider operation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "snake_case",
    tag = "state",
    content = "failure"
)]
pub enum ProviderOperationOutcome {
    /// The intent is durable but its external effect has not been resolved.
    Pending,
    /// The exact external mutation was confirmed applied.
    Applied,
    /// The provider call failed with a bounded effect classification.
    Failed(ProviderFailureOutcome),
}

impl ProviderOperationOutcome {
    /// Reports whether this intent still fences any later provider mutation.
    #[must_use]
    pub const fn is_pending(self) -> bool {
        matches!(
            self,
            Self::Pending | Self::Failed(ProviderFailureOutcome::Uncertain(_))
        )
    }
}

/// One durable provider mutation saga entry.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderOperation {
    operation_id: OperationId,
    kind: ProviderOperationKind,
    outcome: ProviderOperationOutcome,
}

impl ProviderOperation {
    /// Creates an unresolved intent that must be committed before invocation.
    #[must_use]
    pub const fn intent(operation_id: OperationId, kind: ProviderOperationKind) -> Self {
        Self {
            operation_id,
            kind,
            outcome: ProviderOperationOutcome::Pending,
        }
    }

    /// Returns the stable idempotency identity for retry and reconciliation.
    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    /// Returns the external mutation kind fixed by the intent.
    #[must_use]
    pub const fn kind(self) -> ProviderOperationKind {
        self.kind
    }

    /// Returns the latest durable resolution of the external effect.
    #[must_use]
    pub const fn outcome(self) -> ProviderOperationOutcome {
        self.outcome
    }

    /// Reports whether the saga entry still blocks a successor intent.
    #[must_use]
    pub const fn is_pending(self) -> bool {
        self.outcome.is_pending()
    }

    pub(crate) fn mark_applied(&mut self) -> Result<bool, JournalInvariantError> {
        match self.outcome {
            ProviderOperationOutcome::Applied => Ok(false),
            ProviderOperationOutcome::Pending
            | ProviderOperationOutcome::Failed(ProviderFailureOutcome::Uncertain(_)) => {
                self.outcome = ProviderOperationOutcome::Applied;
                Ok(true)
            }
            ProviderOperationOutcome::Failed(ProviderFailureOutcome::KnownNoEffect(_)) => {
                Err(JournalInvariantError::ProviderOperationReplayConflict)
            }
        }
    }

    pub(crate) fn resolve_failure(
        &mut self,
        failure: ProviderFailureOutcome,
    ) -> Result<bool, JournalInvariantError> {
        match self.outcome {
            ProviderOperationOutcome::Pending => {
                self.outcome = ProviderOperationOutcome::Failed(failure);
                Ok(true)
            }
            ProviderOperationOutcome::Failed(existing) if existing == failure => Ok(false),
            ProviderOperationOutcome::Failed(ProviderFailureOutcome::Uncertain(_))
                if !failure.is_uncertain() =>
            {
                self.outcome = ProviderOperationOutcome::Failed(failure);
                Ok(true)
            }
            ProviderOperationOutcome::Applied | ProviderOperationOutcome::Failed(_) => {
                Err(JournalInvariantError::ProviderOperationReplayConflict)
            }
        }
    }
}

/// Provider adapter and opaque identifier needed to reattach or destroy a
/// sandbox after restart.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxIdentity {
    provider: ProviderName,
    handle: SandboxHandle,
}

impl SandboxIdentity {
    /// Binds a provider adapter to its bounded opaque sandbox handle.
    #[must_use]
    pub const fn new(provider: ProviderName, handle: SandboxHandle) -> Self {
        Self { provider, handle }
    }

    /// Returns the adapter that owns the handle.
    #[must_use]
    pub const fn provider(&self) -> &ProviderName {
        &self.provider
    }

    /// Returns the opaque identity used only at that adapter boundary.
    #[must_use]
    pub const fn handle(&self) -> &SandboxHandle {
        &self.handle
    }
}
