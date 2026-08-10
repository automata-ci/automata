//! Terminal job and step results committed by a runner.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{MAX_JOB_OUTPUT_DEFINITIONS, StepId, instance::validate_logical_name};
use crate::{AttemptId, CORE_SCHEMA_VERSION, OutputSensitivity, UnixMillis};

/// Maximum approximate UTF-16 bytes across the public outputs of one job.
///
/// This follows the provider-compatible one-megabyte per-job accounting rule.
/// Secret-derived output markers carry no value and consume no value budget.
pub const MAX_JOB_RESULT_OUTPUT_UTF16_BYTES: usize = 1_048_576;

/// Terminal conclusion produced by a runner.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobConclusion {
    /// Execution completed without an effective failure.
    Success,
    /// Execution completed with an effective failure.
    Failure,
    /// Execution stopped because cancellation was requested.
    Cancelled,
    /// Execution exceeded an enforced deadline.
    TimedOut,
    /// Execution was intentionally not started.
    Skipped,
}

/// Maximum credential visibility reached by user-controlled code in one job.
///
/// The order is the authority order: a later variant permits every exposure
/// represented by an earlier variant. Terminal output validation uses this
/// evidence to keep plaintext out of ordinary persistence whenever user code
/// could read a secret.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobSecretExposure {
    /// User-controlled code received no private credential or secret.
    Secretless,
    /// The trusted runner used a credential without revealing it to user code.
    CapabilityOnly,
    /// User-controlled code could read at least one secret value.
    ReadableSecret,
}

impl JobSecretExposure {
    /// Reports whether this admitted maximum permits the observed exposure.
    #[must_use]
    pub const fn permits(self, observed: Self) -> bool {
        observed as u8 <= self as u8
    }
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
    /// Records one step's raw outcome, effective conclusion, and bounded timeline.
    ///
    /// The enclosing [`JobResult::validate`] call verifies temporal ordering and
    /// step-ID uniqueness.
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

    /// Returns the stable step identity from the admitted `JobIR`.
    #[must_use]
    pub const fn step_id(&self) -> &StepId {
        &self.step_id
    }

    /// Returns the result before `continue-on-error` policy is applied.
    #[must_use]
    pub const fn outcome(&self) -> JobConclusion {
        self.outcome
    }

    /// Returns the effective result after step policy is applied.
    #[must_use]
    pub const fn conclusion(&self) -> JobConclusion {
        self.conclusion
    }

    /// Returns when execution of this step began.
    #[must_use]
    pub const fn started_at(&self) -> UnixMillis {
        self.started_at
    }

    /// Returns when execution of this step reached a terminal state.
    #[must_use]
    pub const fn completed_at(&self) -> UnixMillis {
        self.completed_at
    }
}

/// One terminal job output safe to persist in the ordinary immutable result.
///
/// Public outputs carry their value. A secret-derived output is represented by
/// a classification marker only; its plaintext is deliberately absent from
/// this durable type.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedJobResultOutput")]
pub struct JobResultOutput {
    sensitivity: OutputSensitivity,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
}

impl fmt::Debug for JobResultOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JobResultOutput")
            .field("sensitivity", &self.sensitivity)
            .field("value", &self.value.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedJobResultOutput {
    sensitivity: OutputSensitivity,
    value: Option<String>,
}

impl TryFrom<UncheckedJobResultOutput> for JobResultOutput {
    type Error = JobResultValidationError;

    fn try_from(value: UncheckedJobResultOutput) -> Result<Self, Self::Error> {
        match (value.sensitivity, value.value) {
            (OutputSensitivity::Public, Some(value)) => Self::public(value),
            (OutputSensitivity::Public, None) => {
                Err(JobResultValidationError::MissingPublicOutputValue)
            }
            (OutputSensitivity::SecretDerived, None) => Ok(Self::secret_derived()),
            (OutputSensitivity::SecretDerived, Some(_)) => {
                Err(JobResultValidationError::SecretDerivedOutputCarriesValue)
            }
        }
    }
}

impl JobResultOutput {
    /// Creates a bounded public terminal output.
    ///
    /// # Errors
    ///
    /// Rejects empty values and values exceeding the per-job output budget.
    pub fn public(value: impl Into<String>) -> Result<Self, JobResultValidationError> {
        let output = Self {
            sensitivity: OutputSensitivity::Public,
            value: Some(value.into()),
        };
        output.validate()?;
        Ok(output)
    }

    /// Creates a fail-closed marker for an output whose plaintext was derived
    /// from secret-bearing execution state.
    #[must_use]
    pub const fn secret_derived() -> Self {
        Self {
            sensitivity: OutputSensitivity::SecretDerived,
            value: None,
        }
    }

    /// Returns whether the durable output contains public text or only a secret marker.
    #[must_use]
    pub const fn sensitivity(&self) -> OutputSensitivity {
        self.sensitivity
    }

    /// Returns the value only when this output is public.
    #[must_use]
    pub fn public_value(&self) -> Option<&str> {
        self.value.as_deref()
    }

    fn validate(&self) -> Result<(), JobResultValidationError> {
        match (self.sensitivity, self.value.as_deref()) {
            (OutputSensitivity::Public, Some("")) => {
                Err(JobResultValidationError::EmptyPublicOutputValue)
            }
            (OutputSensitivity::Public, Some(value)) => {
                let bytes = utf16_bytes(value)?;
                if bytes > MAX_JOB_RESULT_OUTPUT_UTF16_BYTES {
                    return Err(JobResultValidationError::OutputValueTooLarge {
                        maximum: MAX_JOB_RESULT_OUTPUT_UTF16_BYTES,
                    });
                }
                Ok(())
            }
            (OutputSensitivity::Public, None) => {
                Err(JobResultValidationError::MissingPublicOutputValue)
            }
            (OutputSensitivity::SecretDerived, None) => Ok(()),
            (OutputSensitivity::SecretDerived, Some(_)) => {
                Err(JobResultValidationError::SecretDerivedOutputCarriesValue)
            }
        }
    }
}

/// Versioned result committed for one fenced attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobResult {
    schema_version: u16,
    attempt_id: AttemptId,
    conclusion: JobConclusion,
    secret_exposure: JobSecretExposure,
    outputs: BTreeMap<String, JobResultOutput>,
    steps: Vec<StepResult>,
    completed_at: UnixMillis,
}

impl JobResult {
    /// Creates a current-schema terminal result with no outputs or step details.
    ///
    /// Call [`Self::validate`] after adding output and step collections.
    #[must_use]
    pub fn new(
        attempt_id: AttemptId,
        conclusion: JobConclusion,
        secret_exposure: JobSecretExposure,
        completed_at: UnixMillis,
    ) -> Self {
        Self {
            schema_version: CORE_SCHEMA_VERSION,
            attempt_id,
            conclusion,
            secret_exposure,
            outputs: BTreeMap::new(),
            steps: Vec::new(),
            completed_at,
        }
    }

    /// Returns the durable result schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the exact fenced attempt that produced this result.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the effective terminal job conclusion.
    #[must_use]
    pub const fn conclusion(&self) -> JobConclusion {
        self.conclusion
    }

    /// Returns the greatest credential visibility reached by user code.
    #[must_use]
    pub const fn secret_exposure(&self) -> JobSecretExposure {
        self.secret_exposure
    }

    /// Returns the immutable, name-keyed terminal output map.
    #[must_use]
    pub const fn outputs(&self) -> &BTreeMap<String, JobResultOutput> {
        &self.outputs
    }

    /// Returns step results in their retained execution-report order.
    #[must_use]
    pub fn steps(&self) -> &[StepResult] {
        &self.steps
    }

    /// Returns when the job reached its terminal conclusion.
    #[must_use]
    pub const fn completed_at(&self) -> UnixMillis {
        self.completed_at
    }

    /// Replaces the complete terminal-output map without bypassing later validation.
    #[must_use]
    pub fn with_outputs(mut self, outputs: BTreeMap<String, JobResultOutput>) -> Self {
        self.outputs = outputs;
        self
    }

    /// Replaces the complete step-result list without bypassing later validation.
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

        if self.outputs.len() > MAX_JOB_OUTPUT_DEFINITIONS {
            return Err(JobResultValidationError::TooManyOutputs {
                maximum: MAX_JOB_OUTPUT_DEFINITIONS,
            });
        }
        let mut output_bytes = 0_usize;
        for (name, output) in &self.outputs {
            validate_logical_name(name, "job result output")
                .map_err(|_| JobResultValidationError::InvalidOutputName)?;
            output.validate()?;
            if self.secret_exposure == JobSecretExposure::ReadableSecret
                && output.sensitivity() == OutputSensitivity::Public
            {
                return Err(JobResultValidationError::PublicOutputFromReadableSecret);
            }
            if let Some(value) = output.public_value() {
                output_bytes = output_bytes.checked_add(utf16_bytes(value)?).ok_or(
                    JobResultValidationError::OutputValuesTooLarge {
                        maximum: MAX_JOB_RESULT_OUTPUT_UTF16_BYTES,
                    },
                )?;
                if output_bytes > MAX_JOB_RESULT_OUTPUT_UTF16_BYTES {
                    return Err(JobResultValidationError::OutputValuesTooLarge {
                        maximum: MAX_JOB_RESULT_OUTPUT_UTF16_BYTES,
                    });
                }
            }
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

fn utf16_bytes(value: &str) -> Result<usize, JobResultValidationError> {
    value.encode_utf16().count().checked_mul(2).ok_or(
        JobResultValidationError::OutputValuesTooLarge {
            maximum: MAX_JOB_RESULT_OUTPUT_UTF16_BYTES,
        },
    )
}

/// Invalid terminal-result data received at a durable or wire boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum JobResultValidationError {
    /// The durable result uses a schema this build cannot interpret.
    #[error("unsupported job-result schema {received}; this build supports {supported}")]
    UnsupportedSchema {
        /// Schema version understood by this build.
        supported: u16,
        /// Schema version found in the result.
        received: u16,
    },
    /// The result contains more named outputs than the `JobIR` contract permits.
    #[error("job result contains too many outputs; maximum is {maximum}")]
    TooManyOutputs {
        /// Maximum terminal output count accepted for one job.
        maximum: usize,
    },
    /// A terminal output key violated the bounded logical-name grammar.
    #[error("job result output name is invalid")]
    InvalidOutputName,
    /// A public output carried an empty value, which is not canonical.
    #[error("public job result output value is empty")]
    EmptyPublicOutputValue,
    /// A public output omitted the plaintext it promises to publish.
    #[error("public job result output is missing its value")]
    MissingPublicOutputValue,
    /// A secret-derived marker improperly retained plaintext.
    #[error("secret-derived job result output must not carry plaintext")]
    SecretDerivedOutputCarriesValue,
    /// A readable-secret execution attempted to publish ordinary output plaintext.
    #[error("readable-secret job results must not carry public output plaintext")]
    PublicOutputFromReadableSecret,
    /// One public output exceeded the provider-compatible UTF-16 budget.
    #[error("job result output value exceeds the {maximum}-byte UTF-16 limit")]
    OutputValueTooLarge {
        /// Maximum encoded UTF-16 bytes allowed for the value.
        maximum: usize,
    },
    /// Public outputs collectively exceeded the per-job UTF-16 budget.
    #[error("job result outputs exceed the {maximum}-byte UTF-16 aggregate limit")]
    OutputValuesTooLarge {
        /// Maximum aggregate encoded UTF-16 bytes allowed for the job.
        maximum: usize,
    },
    /// A step's terminal timestamp precedes its start timestamp.
    #[error("step {0:?} completed before it started")]
    StepCompletedBeforeStart(StepId),
    /// A step claims to have completed after its containing job.
    #[error("step {0:?} completed after the containing job")]
    StepCompletedAfterJob(StepId),
    /// More than one terminal result was supplied for the same admitted step.
    #[error("job result contains duplicate step ID {0:?}")]
    DuplicateStepId(StepId),
}
