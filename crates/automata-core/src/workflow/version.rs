//! Workflow-plan envelope version.

use std::num::NonZeroU16;

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use super::WorkflowPlanError;

/// Workflow-plan schema emitted by this build.
pub const WORKFLOW_PLAN_SCHEMA_VERSION: u16 = WorkflowPlanVersion::current().get();

/// A positive workflow-plan schema version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct WorkflowPlanVersion(NonZeroU16);

impl WorkflowPlanVersion {
    /// Creates a positive workflow-plan version.
    ///
    /// # Errors
    ///
    /// Returns [`WorkflowPlanError::ZeroPlanVersion`] for the reserved zero value.
    pub fn new(version: u16) -> Result<Self, WorkflowPlanError> {
        NonZeroU16::new(version)
            .map(Self)
            .ok_or(WorkflowPlanError::ZeroPlanVersion)
    }

    /// Returns the version emitted by this build.
    #[must_use]
    pub const fn current() -> Self {
        Self(NonZeroU16::MIN)
    }

    /// Returns the numeric wire representation.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

impl<'de> Deserialize<'de> for WorkflowPlanVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let version = u16::deserialize(deserializer)?;
        Self::new(version).map_err(D::Error::custom)
    }
}
