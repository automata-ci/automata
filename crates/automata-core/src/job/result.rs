//! Terminal job and step results committed by a runner.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::StepId;
use crate::{AttemptId, CORE_SCHEMA_VERSION, UnixMillis};

/// Terminal conclusion produced by a runner.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobConclusion {
    Success,
    Failure,
    Cancelled,
    TimedOut,
    Skipped,
}

/// Outcome and conclusion of a completed step.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StepResult {
    step_id: StepId,
    outcome: JobConclusion,
    conclusion: JobConclusion,
    started_at: UnixMillis,
    completed_at: UnixMillis,
}

impl StepResult {
    #[must_use]
    pub const fn new(
        step_id: StepId,
        outcome: JobConclusion,
        conclusion: JobConclusion,
        started_at: UnixMillis,
        completed_at: UnixMillis,
    ) -> Self {
        Self {
            step_id,
            outcome,
            conclusion,
            started_at,
            completed_at,
        }
    }

    #[must_use]
    pub const fn step_id(&self) -> &StepId {
        &self.step_id
    }

    #[must_use]
    pub const fn outcome(&self) -> JobConclusion {
        self.outcome
    }

    #[must_use]
    pub const fn conclusion(&self) -> JobConclusion {
        self.conclusion
    }

    #[must_use]
    pub const fn started_at(&self) -> UnixMillis {
        self.started_at
    }

    #[must_use]
    pub const fn completed_at(&self) -> UnixMillis {
        self.completed_at
    }
}

/// Versioned result committed for one fenced attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JobResult {
    schema_version: u16,
    attempt_id: AttemptId,
    conclusion: JobConclusion,
    outputs: BTreeMap<String, String>,
    steps: Vec<StepResult>,
    completed_at: UnixMillis,
}

impl JobResult {
    #[must_use]
    pub fn new(attempt_id: AttemptId, conclusion: JobConclusion, completed_at: UnixMillis) -> Self {
        Self {
            schema_version: CORE_SCHEMA_VERSION,
            attempt_id,
            conclusion,
            outputs: BTreeMap::new(),
            steps: Vec::new(),
            completed_at,
        }
    }

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    #[must_use]
    pub const fn conclusion(&self) -> JobConclusion {
        self.conclusion
    }

    #[must_use]
    pub const fn outputs(&self) -> &BTreeMap<String, String> {
        &self.outputs
    }

    #[must_use]
    pub fn steps(&self) -> &[StepResult] {
        &self.steps
    }

    #[must_use]
    pub const fn completed_at(&self) -> UnixMillis {
        self.completed_at
    }

    #[must_use]
    pub fn with_outputs(mut self, outputs: BTreeMap<String, String>) -> Self {
        self.outputs = outputs;
        self
    }

    #[must_use]
    pub fn with_steps(mut self, steps: Vec<StepResult>) -> Self {
        self.steps = steps;
        self
    }

    /// Validates a result after reading it from an interchange boundary.
    ///
    /// # Errors
    ///
    /// Returns [`JobResultValidationError`] for an unsupported schema,
    /// impossible timestamps, or duplicate step results.
    pub fn validate(&self) -> Result<(), JobResultValidationError> {
        if self.schema_version != CORE_SCHEMA_VERSION {
            return Err(JobResultValidationError::UnsupportedSchema {
                supported: CORE_SCHEMA_VERSION,
                received: self.schema_version,
            });
        }

        let mut step_ids = BTreeSet::new();
        for step in &self.steps {
            if step.completed_at < step.started_at {
                return Err(JobResultValidationError::StepCompletedBeforeStart(
                    step.step_id.clone(),
                ));
            }
            if step.completed_at > self.completed_at {
                return Err(JobResultValidationError::StepCompletedAfterJob(
                    step.step_id.clone(),
                ));
            }
            if !step_ids.insert(step.step_id.clone()) {
                return Err(JobResultValidationError::DuplicateStepId(
                    step.step_id.clone(),
                ));
            }
        }
        Ok(())
    }
}

/// Invalid terminal-result data received at a durable or wire boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum JobResultValidationError {
    #[error("unsupported job-result schema {received}; this build supports {supported}")]
    UnsupportedSchema { supported: u16, received: u16 },
    #[error("step {0:?} completed before it started")]
    StepCompletedBeforeStart(StepId),
    #[error("step {0:?} completed after the containing job")]
    StepCompletedAfterJob(StepId),
    #[error("job result contains duplicate step ID {0:?}")]
    DuplicateStepId(StepId),
}
