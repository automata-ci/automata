use std::fmt;

use automata_core::OperationId;
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
    CreateSandbox,
    StartSandbox,
    StopSandbox,
    DestroySandbox,
}

/// Bounded, non-secret classification of a provider failure.
///
/// Adapter diagnostics and provider responses deliberately do not belong in
/// the journal because they can contain credentials or other sensitive data.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFailureKind {
    InvalidRequest,
    Unsupported,
    PermissionDenied,
    ResourceExhausted,
    NotFound,
    Conflict,
    Unavailable,
    TimedOut,
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
    KnownNoEffect(ProviderFailureKind),
    Uncertain(ProviderFailureKind),
}

impl ProviderFailureOutcome {
    #[must_use]
    pub const fn kind(self) -> ProviderFailureKind {
        match self {
            Self::KnownNoEffect(kind) | Self::Uncertain(kind) => kind,
        }
    }

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
    Pending,
    Applied,
    Failed(ProviderFailureOutcome),
}

impl ProviderOperationOutcome {
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
    #[must_use]
    pub const fn intent(operation_id: OperationId, kind: ProviderOperationKind) -> Self {
        Self {
            operation_id,
            kind,
            outcome: ProviderOperationOutcome::Pending,
        }
    }

    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn kind(self) -> ProviderOperationKind {
        self.kind
    }

    #[must_use]
    pub const fn outcome(self) -> ProviderOperationOutcome {
        self.outcome
    }

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
    #[must_use]
    pub const fn new(provider: ProviderName, handle: SandboxHandle) -> Self {
        Self { provider, handle }
    }

    #[must_use]
    pub const fn provider(&self) -> &ProviderName {
        &self.provider
    }

    #[must_use]
    pub const fn handle(&self) -> &SandboxHandle {
        &self.handle
    }
}
