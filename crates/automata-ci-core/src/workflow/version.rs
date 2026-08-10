//! Workflow-plan envelope version.

use std::num::NonZeroU16;

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use super::WorkflowPlanError;

/// Workflow-plan schema emitted by this build.
pub const WORKFLOW_PLAN_SCHEMA_VERSION: u16 = WorkflowPlanVersion::current().get();

/// Logical-template plan schema used by deferred job activation.
pub const WORKFLOW_PLAN_V2_SCHEMA_VERSION: u16 = 2;

/// The exact workflow-plan schema accepted by this build.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct WorkflowPlanVersion(NonZeroU16);

impl WorkflowPlanVersion {
    /// Creates the exact current workflow-plan version.
    ///
    /// # Errors
    ///
    /// Returns [`WorkflowPlanError`] for zero or any non-current version.
    pub fn new(version: u16) -> Result<Self, WorkflowPlanError> {
        let version = NonZeroU16::new(version)
            .map(Self)
            .ok_or(WorkflowPlanError::ZeroPlanVersion)?;
        if version == Self::current() {
            Ok(version)
        } else {
            Err(WorkflowPlanError::UnsupportedPlanVersion {
                supported: Self::current().get(),
                received: version.get(),
            })
        }
    }

    /// Returns the version emitted by this build.
    #[must_use]
    pub const fn current() -> Self {
        Self::v2()
    }

    /// Returns the logical-template plan schema version.
    #[must_use]
    pub const fn v2() -> Self {
        // SAFETY: two is non-zero. `NonZeroU16::new` is not yet const on the
        // minimum supported compiler, so use the adjacent const value.
        Self(NonZeroU16::MIN.saturating_add(1))
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
