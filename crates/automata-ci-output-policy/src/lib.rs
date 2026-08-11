//! Shared dashboard, log, and artifact publication policy for Automata.
//!
//! Repository preferences are applied through a restrictive lattice. Safety
//! classifications can always narrow publication, never broaden it.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use serde::{Deserialize, Serialize};

/// Audience allowed to discover or read one dashboard or output resource.
///
/// The declaration order is the visibility order: private is most restrictive
/// and public is least restrictive.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputVisibility {
    /// Publication policy grants no access; ordinary repository RBAC may still authorize it.
    Private,
    /// Any authenticated tenant user may discover or read the resource.
    Authenticated,
    /// The resource may be discovered or read without authentication.
    Public,
}

impl OutputVisibility {
    /// Returns the more restrictive visibility.
    #[must_use]
    pub const fn meet(self, other: Self) -> Self {
        if self as u8 <= other as u8 {
            self
        } else {
            other
        }
    }

    /// Returns the less restrictive visibility.
    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        if self as u8 >= other as u8 {
            self
        } else {
            other
        }
    }
}

/// Independently configurable repository publication policy.
///
/// Durable snapshots require every current audience and reject unknown fields,
/// so a binary cannot silently invent or ignore a security control.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryPublicationPolicy {
    dashboard: OutputVisibility,
    logs: OutputVisibility,
    artifacts: OutputVisibility,
}

impl RepositoryPublicationPolicy {
    /// Creates a policy with independent dashboard, log, and artifact audiences.
    #[must_use]
    pub const fn new(
        dashboard: OutputVisibility,
        logs: OutputVisibility,
        artifacts: OutputVisibility,
    ) -> Self {
        Self {
            dashboard,
            logs,
            artifacts,
        }
    }

    /// Returns the requested dashboard audience.
    #[must_use]
    pub const fn dashboard(self) -> OutputVisibility {
        self.dashboard
    }

    /// Returns the requested log audience.
    #[must_use]
    pub const fn logs(self) -> OutputVisibility {
        self.logs
    }

    /// Returns the requested artifact audience.
    #[must_use]
    pub const fn artifacts(self) -> OutputVisibility {
        self.artifacts
    }

    /// Selects the requested visibility for an output kind.
    #[must_use]
    pub const fn visibility(self, kind: OutputKind) -> OutputVisibility {
        match kind {
            OutputKind::Dashboard => self.dashboard,
            OutputKind::Logs => self.logs,
            OutputKind::Artifacts => self.artifacts,
        }
    }

    /// Applies the immutable secret-exposure safety ceiling.
    #[must_use]
    pub const fn effective_visibility(
        self,
        kind: OutputKind,
        exposure: SecretExposureClass,
    ) -> OutputVisibility {
        self.visibility(kind)
            .meet(exposure.maximum_visibility(kind))
    }
}

impl Default for RepositoryPublicationPolicy {
    fn default() -> Self {
        Self::new(
            OutputVisibility::Private,
            OutputVisibility::Private,
            OutputVisibility::Private,
        )
    }
}

/// Independently published resource families.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputKind {
    /// Repository and workflow-run dashboard metadata.
    Dashboard,
    /// Persisted job log output.
    Logs,
    /// Files published as run artifacts.
    Artifacts,
}

/// Whether user code can observe credential material during one attempt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretExposureClass {
    /// The attempt receives no private credential or secret.
    Secretless,
    /// The trusted runner performs a narrow operation without exposing the
    /// underlying credential to user code.
    CapabilityOnly,
    /// User code can read at least one secret value.
    ReadableSecret,
}

impl SecretExposureClass {
    /// Hard publication ceiling for the selected resource family.
    ///
    /// Repository dashboard metadata is independent of job credential access.
    /// Logs and artifacts from code that can read a secret are safety-capped at
    /// private even when a repository requests public output.
    #[must_use]
    pub const fn maximum_visibility(self, kind: OutputKind) -> OutputVisibility {
        match (self, kind) {
            (_, OutputKind::Dashboard)
            | (Self::Secretless | Self::CapabilityOnly, OutputKind::Logs | OutputKind::Artifacts) => {
                OutputVisibility::Public
            }
            (Self::ReadableSecret, OutputKind::Logs | OutputKind::Artifacts) => {
                OutputVisibility::Private
            }
        }
    }

    /// Default handling for value-redacted user-controlled stdout and stderr.
    ///
    /// The runner masks registered credential values before transmission. A
    /// readable-secret classification still caps the complete persisted stream
    /// at private visibility because masking cannot recognize transformed or
    /// split values.
    #[must_use]
    pub const fn raw_log_disposition(self) -> RawLogDisposition {
        RawLogDisposition::Persist
    }
}

/// Whether raw user-controlled output may enter persistent log storage.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RawLogDisposition {
    /// Runner-redacted user-controlled standard output and error may be persisted.
    Persist,
    /// Raw user-controlled output must not enter persistent log storage.
    ///
    /// Retained for immutable legacy snapshots and explicit fail-closed
    /// admission decisions.
    SuppressUserOutput,
}
