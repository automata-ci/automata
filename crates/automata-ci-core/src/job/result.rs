//! Terminal job and step results committed by a runner.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use super::{
    MAX_JOB_OUTPUT_DEFINITIONS, StepId,
    instance::{job_output_definition_rejection, validate_logical_name},
};
use crate::{AttemptId, CORE_SCHEMA_VERSION, OutputSensitivity, UnixMillis};

/// Maximum approximate UTF-16 bytes across the public outputs of one job.
///
/// This follows the provider-compatible one-megabyte per-job accounting rule.
/// Secret-derived output markers carry no value and consume no value budget.
pub const MAX_JOB_RESULT_OUTPUT_UTF16_BYTES: usize = 1_048_576;

/// Maximum UTF-8 bytes retained across step summaries and annotations in one job result.
pub const MAX_JOB_RESULT_ATTACHMENT_BYTES: usize = 8_388_608;

/// Maximum structured annotations retained across one job result.
pub const MAX_JOB_RESULT_ANNOTATIONS: usize = 4_096;

/// Maximum properties retained on one structured step annotation.
pub const MAX_STEP_ANNOTATION_PROPERTIES: usize = 64;

/// Maximum UTF-8 bytes retained in one summary, annotation message, or property value.
pub const MAX_STEP_ATTACHMENT_TEXT_BYTES: usize = 1_048_576;
const MAX_STEP_ANNOTATION_PROPERTY_NAME_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JobResultLimitRejection {
    OutputUtf16Bytes,
    AttachmentBytes,
    Annotations,
    AnnotationProperties,
    StepAttachmentTextBytes,
    AnnotationPropertyNameBytes,
}

const fn job_result_output_byte_rejection(observed: usize) -> Option<JobResultLimitRejection> {
    if observed > MAX_JOB_RESULT_OUTPUT_UTF16_BYTES {
        return Some(JobResultLimitRejection::OutputUtf16Bytes);
    }
    None
}
const fn job_result_attachment_byte_rejection(observed: usize) -> Option<JobResultLimitRejection> {
    if observed > MAX_JOB_RESULT_ATTACHMENT_BYTES {
        return Some(JobResultLimitRejection::AttachmentBytes);
    }
    None
}
const fn job_result_annotation_count_rejection(observed: usize) -> Option<JobResultLimitRejection> {
    if observed > MAX_JOB_RESULT_ANNOTATIONS {
        return Some(JobResultLimitRejection::Annotations);
    }
    None
}
const fn step_annotation_property_count_rejection(
    observed: usize,
) -> Option<JobResultLimitRejection> {
    if observed > MAX_STEP_ANNOTATION_PROPERTIES {
        return Some(JobResultLimitRejection::AnnotationProperties);
    }
    None
}
const fn step_attachment_text_byte_rejection(observed: usize) -> Option<JobResultLimitRejection> {
    if observed > MAX_STEP_ATTACHMENT_TEXT_BYTES {
        return Some(JobResultLimitRejection::StepAttachmentTextBytes);
    }
    None
}
const fn step_annotation_property_name_byte_rejection(
    observed: usize,
) -> Option<JobResultLimitRejection> {
    if observed > MAX_STEP_ANNOTATION_PROPERTY_NAME_BYTES {
        return Some(JobResultLimitRejection::AnnotationPropertyNameBytes);
    }
    None
}

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
/// represented by an earlier variant. This job-level evidence narrows resource
/// visibility; each terminal output carries its own value-level sensitivity.
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

/// Severity of one structured step annotation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepAnnotationLevel {
    /// A failing diagnostic.
    Error,
    /// A warning diagnostic.
    Warning,
    /// An informational diagnostic.
    Notice,
}

/// One ordered annotation property retained for a provider presentation adapter.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct StepAnnotationProperty {
    name: String,
    value: String,
}

impl StepAnnotationProperty {
    /// Creates one annotation property.
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    /// Returns the provider-normalized property name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the redaction-safe retained property value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for StepAnnotationProperty {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StepAnnotationProperty")
            .field("name", &"[REDACTED]")
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// One structured diagnostic emitted while executing a step.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct StepAnnotation {
    level: StepAnnotationLevel,
    message: String,
    properties: Vec<StepAnnotationProperty>,
}

impl StepAnnotation {
    /// Creates a structured annotation in retained observation order.
    #[must_use]
    pub fn new(
        level: StepAnnotationLevel,
        message: impl Into<String>,
        properties: Vec<StepAnnotationProperty>,
    ) -> Self {
        Self {
            level,
            message: message.into(),
            properties,
        }
    }

    /// Returns the normalized severity.
    #[must_use]
    pub const fn level(&self) -> StepAnnotationLevel {
        self.level
    }

    /// Returns the redaction-safe retained message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns normalized properties in retained observation order.
    #[must_use]
    pub fn properties(&self) -> &[StepAnnotationProperty] {
        &self.properties
    }
}

impl fmt::Debug for StepAnnotation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StepAnnotation")
            .field("level", &self.level)
            .field("message", &"[REDACTED]")
            .field("properties", &self.properties)
            .finish()
    }
}

/// Outcome, conclusion, timeline, and bounded presentation attachments of a completed step.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct StepResult {
    step_id: StepId,
    outcome: JobConclusion,
    conclusion: JobConclusion,
    started_at: UnixMillis,
    completed_at: UnixMillis,
    #[serde(deserialize_with = "deserialize_required_option")]
    summary_markdown: Option<String>,
    annotations: Vec<StepAnnotation>,
}

fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(deserializer)
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
            summary_markdown: None,
            annotations: Vec::new(),
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

    /// Returns the masked Markdown summary emitted by this step, when non-empty.
    #[must_use]
    pub fn summary_markdown(&self) -> Option<&str> {
        self.summary_markdown.as_deref()
    }

    /// Returns structured annotations in emission order.
    #[must_use]
    pub fn annotations(&self) -> &[StepAnnotation] {
        &self.annotations
    }

    /// Replaces the step summary, canonicalizing an empty summary to absence.
    #[must_use]
    pub fn with_summary_markdown(mut self, summary: impl Into<String>) -> Self {
        let summary = summary.into();
        self.summary_markdown = (!summary.is_empty()).then_some(summary);
        self
    }

    /// Replaces the complete ordered annotation collection.
    #[must_use]
    pub fn with_annotations(mut self, annotations: Vec<StepAnnotation>) -> Self {
        self.annotations = annotations;
        self
    }
}

impl fmt::Debug for StepResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StepResult")
            .field("step_id", &self.step_id)
            .field("outcome", &self.outcome)
            .field("conclusion", &self.conclusion)
            .field("started_at", &self.started_at)
            .field("completed_at", &self.completed_at)
            .field(
                "summary_markdown",
                &self.summary_markdown.as_ref().map(|_| "[REDACTED]"),
            )
            .field("annotations", &self.annotations)
            .finish()
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
                if job_result_output_byte_rejection(bytes).is_some() {
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

        if job_output_definition_rejection(self.outputs.len()).is_some() {
            return Err(JobResultValidationError::TooManyOutputs {
                maximum: MAX_JOB_OUTPUT_DEFINITIONS,
            });
        }
        let mut output_bytes = 0_usize;
        for (name, output) in &self.outputs {
            validate_logical_name(name, "job result output")
                .map_err(|_| JobResultValidationError::InvalidOutputName)?;
            output.validate()?;
            if let Some(value) = output.public_value() {
                output_bytes = output_bytes.checked_add(utf16_bytes(value)?).ok_or(
                    JobResultValidationError::OutputValuesTooLarge {
                        maximum: MAX_JOB_RESULT_OUTPUT_UTF16_BYTES,
                    },
                )?;
                if job_result_output_byte_rejection(output_bytes).is_some() {
                    return Err(JobResultValidationError::OutputValuesTooLarge {
                        maximum: MAX_JOB_RESULT_OUTPUT_UTF16_BYTES,
                    });
                }
            }
        }

        let mut step_ids = BTreeSet::new();
        let mut attachment_bytes = 0_usize;
        let mut annotation_count = 0_usize;
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
            if let Some(summary) = step.summary_markdown() {
                charge_attachment_text(&mut attachment_bytes, summary)?;
            }
            annotation_count = annotation_count
                .checked_add(step.annotations().len())
                .ok_or(JobResultValidationError::TooManyStepAnnotations {
                    maximum: MAX_JOB_RESULT_ANNOTATIONS,
                })?;
            if job_result_annotation_count_rejection(annotation_count).is_some() {
                return Err(JobResultValidationError::TooManyStepAnnotations {
                    maximum: MAX_JOB_RESULT_ANNOTATIONS,
                });
            }
            for annotation in step.annotations() {
                charge_attachment_text(&mut attachment_bytes, annotation.message())?;
                if step_annotation_property_count_rejection(annotation.properties().len()).is_some()
                {
                    return Err(JobResultValidationError::TooManyStepAnnotationProperties {
                        maximum: MAX_STEP_ANNOTATION_PROPERTIES,
                    });
                }
                let mut property_names = BTreeSet::new();
                for property in annotation.properties() {
                    if property.name().is_empty()
                        || step_annotation_property_name_byte_rejection(property.name().len())
                            .is_some()
                        || property.name().chars().any(char::is_control)
                        || !property_names.insert(property.name().to_ascii_lowercase())
                    {
                        return Err(JobResultValidationError::InvalidStepAnnotationProperty);
                    }
                    charge_attachment_text(&mut attachment_bytes, property.name())?;
                    charge_attachment_text(&mut attachment_bytes, property.value())?;
                }
            }
        }
        Ok(())
    }
}

fn charge_attachment_text(total: &mut usize, value: &str) -> Result<(), JobResultValidationError> {
    if step_attachment_text_byte_rejection(value.len()).is_some() {
        return Err(JobResultValidationError::StepAttachmentTextTooLarge {
            maximum: MAX_STEP_ATTACHMENT_TEXT_BYTES,
        });
    }
    *total = total.checked_add(value.len()).ok_or(
        JobResultValidationError::StepAttachmentsTooLarge {
            maximum: MAX_JOB_RESULT_ATTACHMENT_BYTES,
        },
    )?;
    if job_result_attachment_byte_rejection(*total).is_some() {
        return Err(JobResultValidationError::StepAttachmentsTooLarge {
            maximum: MAX_JOB_RESULT_ATTACHMENT_BYTES,
        });
    }
    Ok(())
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
    /// One summary, annotation message, or property value exceeded its text ceiling.
    #[error("step attachment text exceeds the {maximum}-byte limit")]
    StepAttachmentTextTooLarge {
        /// Maximum UTF-8 bytes accepted for one attachment text value.
        maximum: usize,
    },
    /// Step attachment text exceeded the aggregate result budget.
    #[error("step attachments exceed the {maximum}-byte aggregate limit")]
    StepAttachmentsTooLarge {
        /// Maximum aggregate UTF-8 bytes accepted across one job result.
        maximum: usize,
    },
    /// More structured annotations were supplied than one result permits.
    #[error("job result contains too many step annotations; maximum is {maximum}")]
    TooManyStepAnnotations {
        /// Maximum annotations accepted across one job result.
        maximum: usize,
    },
    /// One annotation carried too many properties.
    #[error("step annotation contains too many properties; maximum is {maximum}")]
    TooManyStepAnnotationProperties {
        /// Maximum properties accepted on one annotation.
        maximum: usize,
    },
    /// An annotation property name was empty, duplicated, unbounded, or unsafe.
    #[error("step annotation property name is invalid")]
    InvalidStepAnnotationProperty,
}

#[cfg(test)]
mod limit_contract_tests {
    use super::*;

    #[test]
    fn job_result_output_byte_limit_has_exact_boundaries() {
        assert_eq!(
            job_result_output_byte_rejection(MAX_JOB_RESULT_OUTPUT_UTF16_BYTES - 1),
            None
        );
        assert_eq!(
            job_result_output_byte_rejection(MAX_JOB_RESULT_OUTPUT_UTF16_BYTES),
            None
        );
        assert_eq!(
            job_result_output_byte_rejection(MAX_JOB_RESULT_OUTPUT_UTF16_BYTES + 1),
            Some(JobResultLimitRejection::OutputUtf16Bytes)
        );
    }
    #[test]
    fn job_result_attachment_byte_limit_has_exact_boundaries() {
        assert_eq!(
            job_result_attachment_byte_rejection(MAX_JOB_RESULT_ATTACHMENT_BYTES - 1),
            None
        );
        assert_eq!(
            job_result_attachment_byte_rejection(MAX_JOB_RESULT_ATTACHMENT_BYTES),
            None
        );
        assert_eq!(
            job_result_attachment_byte_rejection(MAX_JOB_RESULT_ATTACHMENT_BYTES + 1),
            Some(JobResultLimitRejection::AttachmentBytes)
        );
    }
    #[test]
    fn job_result_annotation_count_limit_has_exact_boundaries() {
        assert_eq!(
            job_result_annotation_count_rejection(MAX_JOB_RESULT_ANNOTATIONS - 1),
            None
        );
        assert_eq!(
            job_result_annotation_count_rejection(MAX_JOB_RESULT_ANNOTATIONS),
            None
        );
        assert_eq!(
            job_result_annotation_count_rejection(MAX_JOB_RESULT_ANNOTATIONS + 1),
            Some(JobResultLimitRejection::Annotations)
        );
    }
    #[test]
    fn step_annotation_property_count_limit_has_exact_boundaries() {
        assert_eq!(
            step_annotation_property_count_rejection(MAX_STEP_ANNOTATION_PROPERTIES - 1),
            None
        );
        assert_eq!(
            step_annotation_property_count_rejection(MAX_STEP_ANNOTATION_PROPERTIES),
            None
        );
        assert_eq!(
            step_annotation_property_count_rejection(MAX_STEP_ANNOTATION_PROPERTIES + 1),
            Some(JobResultLimitRejection::AnnotationProperties)
        );
    }
    #[test]
    fn step_attachment_text_byte_limit_has_exact_boundaries() {
        assert_eq!(
            step_attachment_text_byte_rejection(MAX_STEP_ATTACHMENT_TEXT_BYTES - 1),
            None
        );
        assert_eq!(
            step_attachment_text_byte_rejection(MAX_STEP_ATTACHMENT_TEXT_BYTES),
            None
        );
        assert_eq!(
            step_attachment_text_byte_rejection(MAX_STEP_ATTACHMENT_TEXT_BYTES + 1),
            Some(JobResultLimitRejection::StepAttachmentTextBytes)
        );
    }
    #[test]
    fn step_annotation_property_name_byte_limit_has_exact_boundaries() {
        assert_eq!(
            step_annotation_property_name_byte_rejection(
                MAX_STEP_ANNOTATION_PROPERTY_NAME_BYTES - 1
            ),
            None
        );
        assert_eq!(
            step_annotation_property_name_byte_rejection(MAX_STEP_ANNOTATION_PROPERTY_NAME_BYTES),
            None
        );
        assert_eq!(
            step_annotation_property_name_byte_rejection(
                MAX_STEP_ANNOTATION_PROPERTY_NAME_BYTES + 1
            ),
            Some(JobResultLimitRejection::AnnotationPropertyNameBytes)
        );
    }
}
