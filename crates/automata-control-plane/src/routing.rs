//! Server-owned workflow routing requirements.

use automata_core::{RUNNER_REQUIREMENTS_SCHEMA_VERSION, RunnerRequirements};
use thiserror::Error;

/// Requirements accepted from the trusted workflow planner for scheduling.
///
/// Runner transports never construct or mutate this value. Keeping it distinct
/// from runner evidence prevents self-reported runner data from influencing the
/// requirements side of capability matching.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutingRequirements {
    runner: RunnerRequirements,
}

impl RoutingRequirements {
    /// Validates planner-produced runner requirements at the application edge.
    ///
    /// # Errors
    ///
    /// Returns [`RoutingRequirementsError::UnsupportedSchema`] when the
    /// requirements use a core schema this build cannot interpret.
    pub fn new(runner: RunnerRequirements) -> Result<Self, RoutingRequirementsError> {
        if runner.schema_version() != RUNNER_REQUIREMENTS_SCHEMA_VERSION {
            return Err(RoutingRequirementsError::UnsupportedSchema {
                supported: RUNNER_REQUIREMENTS_SCHEMA_VERSION,
                received: runner.schema_version(),
            });
        }
        Ok(Self { runner })
    }

    /// Returns the provider-neutral requirements consumed by capability
    /// matching.
    #[must_use]
    pub const fn runner(&self) -> &RunnerRequirements {
        &self.runner
    }
}

impl TryFrom<RunnerRequirements> for RoutingRequirements {
    type Error = RoutingRequirementsError;

    fn try_from(requirements: RunnerRequirements) -> Result<Self, Self::Error> {
        Self::new(requirements)
    }
}

/// Validation errors at the trusted planner-to-scheduler boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RoutingRequirementsError {
    /// The planner and scheduler do not agree on the core requirement schema.
    #[error("unsupported routing-requirements schema {received}; this build supports {supported}")]
    UnsupportedSchema { supported: u16, received: u16 },
}
