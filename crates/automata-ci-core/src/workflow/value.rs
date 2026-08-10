//! Provider permission snapshots and concurrency queue policy.

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize};

use super::{Located, PlanSourceSpan, WorkflowPlanError};

/// Automata concurrency queue policy. `Single` matches GitHub's one-pending-run behavior.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueuePolicy {
    /// Retains at most one pending run in addition to the active run.
    Single,
    /// Retains pending runs up to the surrounding concurrency limit.
    Max,
}

/// Token permission level requested from a provider adapter.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionLevel {
    /// Grants provider read operations for the named permission scope.
    Read,
    /// Grants provider mutation operations for the named permission scope.
    Write,
    /// Explicitly removes the named provider permission.
    None,
}

/// One provider permission name and level with source evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionGrant {
    name: Located<String>,
    level: Located<PermissionLevel>,
}

impl PermissionGrant {
    /// Preserves a permission name, level, and both source spans.
    #[must_use]
    pub const fn new(name: Located<String>, level: Located<PermissionLevel>) -> Self {
        Self { name, level }
    }

    /// Returns the permission name with its exact source evidence.
    #[must_use]
    pub const fn name(&self) -> &Located<String> {
        &self.name
    }

    /// Returns the requested level with its exact source evidence.
    #[must_use]
    pub const fn level(&self) -> &Located<PermissionLevel> {
        &self.level
    }
}

/// Provider token permissions preserved at their source layer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum WorkflowPermissions {
    /// Grants provider read access across every supported permission scope.
    ReadAll(PlanSourceSpan),
    /// Grants provider write access across every supported permission scope.
    WriteAll(PlanSourceSpan),
    /// Preserves an explicit, uniquely named permission mapping.
    Mapping(Vec<PermissionGrant>),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum UncheckedWorkflowPermissions {
    ReadAll { value: PlanSourceSpan },
    WriteAll { value: PlanSourceSpan },
    Mapping { value: Vec<PermissionGrant> },
}

impl<'de> Deserialize<'de> for WorkflowPermissions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(
            match UncheckedWorkflowPermissions::deserialize(deserializer)? {
                UncheckedWorkflowPermissions::ReadAll { value } => Self::ReadAll(value),
                UncheckedWorkflowPermissions::WriteAll { value } => Self::WriteAll(value),
                UncheckedWorkflowPermissions::Mapping { value } => Self::Mapping(value),
            },
        )
    }
}

impl WorkflowPermissions {
    pub(crate) fn validate(&self) -> Result<(), WorkflowPlanError> {
        let Self::Mapping(grants) = self else {
            return Ok(());
        };
        let mut names = BTreeSet::new();
        for grant in grants {
            if grant.name.value().is_empty() {
                return Err(WorkflowPlanError::EmptyField("permission name"));
            }
            if !names.insert(grant.name.value()) {
                return Err(WorkflowPlanError::DuplicatePermission(
                    grant.name.value().clone(),
                ));
            }
        }
        Ok(())
    }
}
