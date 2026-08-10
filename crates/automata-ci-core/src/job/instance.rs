//! Concrete job-instance identity and terminal output definitions.

use serde::{Deserialize, Serialize};

use super::{ExpressionInstruction, JobValidationError, ValueTemplate, ValueTemplateSegment};
use crate::{OutputSensitivity, Sha256Digest};

/// Maximum UTF-8 bytes in a source-level logical job or output name.
pub const MAX_JOB_LOGICAL_NAME_BYTES: usize = 256;
/// Maximum number of terminal output definitions on one concrete job.
pub const MAX_JOB_OUTPUT_DEFINITIONS: usize = 1_024;

/// Stable identity of one concrete expansion of a logical workflow job.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedJobInstanceIdentity")]
pub struct JobInstanceIdentity {
    logical_job_key: String,
    matrix_index: u32,
    matrix_total: u32,
    matrix_digest: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedJobInstanceIdentity {
    logical_job_key: String,
    matrix_index: u32,
    matrix_total: u32,
    matrix_digest: Sha256Digest,
}

impl TryFrom<UncheckedJobInstanceIdentity> for JobInstanceIdentity {
    type Error = JobValidationError;

    fn try_from(value: UncheckedJobInstanceIdentity) -> Result<Self, Self::Error> {
        Self::new(
            value.logical_job_key,
            value.matrix_index,
            value.matrix_total,
            value.matrix_digest,
        )
    }
}

impl JobInstanceIdentity {
    /// Creates the identity of one zero-based expansion index.
    ///
    /// # Errors
    ///
    /// Rejects an invalid logical key, zero expansion total, or an index
    /// outside that total.
    pub fn new(
        logical_job_key: impl Into<String>,
        matrix_index: u32,
        matrix_total: u32,
        matrix_digest: Sha256Digest,
    ) -> Result<Self, JobValidationError> {
        let identity = Self {
            logical_job_key: logical_job_key.into(),
            matrix_index,
            matrix_total,
            matrix_digest,
        };
        identity.validate()?;
        Ok(identity)
    }

    /// Returns the validated source-level key shared by every matrix expansion.
    #[must_use]
    pub fn logical_job_key(&self) -> &str {
        &self.logical_job_key
    }

    /// Returns this expansion's zero-based position in canonical matrix order.
    #[must_use]
    pub const fn matrix_index(&self) -> u32 {
        self.matrix_index
    }

    /// Returns the total number of concrete expansions of the logical job.
    #[must_use]
    pub const fn matrix_total(&self) -> u32 {
        self.matrix_total
    }

    /// Returns the digest binding this identity to the complete expanded matrix.
    #[must_use]
    pub const fn matrix_digest(&self) -> Sha256Digest {
        self.matrix_digest
    }

    pub(super) fn validate(&self) -> Result<(), JobValidationError> {
        validate_logical_name(&self.logical_job_key, "logical job key")?;
        if self.matrix_total == 0 {
            return Err(JobValidationError::ZeroMatrixTotal);
        }
        if self.matrix_index >= self.matrix_total {
            return Err(JobValidationError::MatrixIndexOutOfRange {
                index: self.matrix_index,
                total: self.matrix_total,
            });
        }
        Ok(())
    }
}

/// One named job output evaluated after all steps have reached a terminal state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedJobOutputDefinition")]
pub struct JobOutputDefinition {
    name: String,
    value: ValueTemplate,
    sensitivity: OutputSensitivity,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedJobOutputDefinition {
    name: String,
    value: ValueTemplate,
    sensitivity: OutputSensitivity,
}

impl TryFrom<UncheckedJobOutputDefinition> for JobOutputDefinition {
    type Error = JobValidationError;

    fn try_from(value: UncheckedJobOutputDefinition) -> Result<Self, Self::Error> {
        Self::new(value.name, value.value, value.sensitivity)
    }
}

impl JobOutputDefinition {
    /// Creates a named, late-bound job output.
    ///
    /// # Errors
    ///
    /// Rejects invalid output names or malformed value templates.
    pub fn new(
        name: impl Into<String>,
        value: ValueTemplate,
        sensitivity: OutputSensitivity,
    ) -> Result<Self, JobValidationError> {
        let definition = Self {
            name: name.into(),
            value,
            sensitivity,
        };
        definition.validate()?;
        Ok(definition)
    }

    /// Returns the validated name used to publish the terminal output.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the execution-time template evaluated after all steps terminate.
    #[must_use]
    pub const fn value(&self) -> &ValueTemplate {
        &self.value
    }

    /// Returns the declared disclosure class enforced when the output is published.
    #[must_use]
    pub const fn sensitivity(&self) -> OutputSensitivity {
        self.sensitivity
    }

    pub(super) fn validate(&self) -> Result<(), JobValidationError> {
        validate_logical_name(&self.name, "job output name")?;
        self.value
            .validate()
            .map_err(|source| JobValidationError::InvalidValueTemplate {
                field: "job output",
                source,
            })?;
        if self.sensitivity == OutputSensitivity::Public
            && self.value.segments().iter().any(|segment| {
                matches!(
                    segment,
                    ValueTemplateSegment::Expression { program }
                        if program.instructions().iter().any(|instruction| {
                            matches!(
                                instruction,
                                ExpressionInstruction::NamedValue { name }
                                    if name.eq_ignore_ascii_case("secrets")
                            )
                        })
                )
            })
        {
            return Err(JobValidationError::PublicOutputReferencesSecrets);
        }
        Ok(())
    }
}

pub(super) fn validate_logical_name(
    value: &str,
    field: &'static str,
) -> Result<(), JobValidationError> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > MAX_JOB_LOGICAL_NAME_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(JobValidationError::InvalidLogicalName { field });
    }
    Ok(())
}
