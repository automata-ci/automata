//! Stable semantic identifiers inside a planned job.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use super::JobValidationError;

// foundation-governance: parity-limit
const MAX_SEMANTIC_ID_LENGTH: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JobIdentifierLimitRejection {
    StepIdBytes,
}

const fn step_id_byte_rejection(observed: usize) -> Option<JobIdentifierLimitRejection> {
    if observed > MAX_SEMANTIC_ID_LENGTH {
        return Some(JobIdentifierLimitRejection::StepIdBytes);
    }
    None
}

/// Stable step identifier used by expressions and result records.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StepId(String);

impl StepId {
    /// Creates a non-empty, whitespace-free semantic step identifier.
    ///
    /// # Errors
    ///
    /// Returns [`JobValidationError`] when the identifier is empty, too long,
    /// or contains characters outside the portable identifier alphabet.
    pub fn new(value: impl Into<String>) -> Result<Self, JobValidationError> {
        let value = value.into();
        if value.is_empty() {
            return Err(JobValidationError::EmptyStepId);
        }
        if step_id_byte_rejection(value.len()).is_some() {
            return Err(JobValidationError::StepIdTooLong {
                maximum: MAX_SEMANTIC_ID_LENGTH,
            });
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(JobValidationError::InvalidStepId(value));
        }
        Ok(Self(value))
    }

    /// Returns the exact, case-sensitive identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for StepId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for StepId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for StepId {
    type Err = JobValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for StepId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for StepId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod limit_contract_tests {
    use super::{JobIdentifierLimitRejection, MAX_SEMANTIC_ID_LENGTH, step_id_byte_rejection};

    #[test]
    fn step_id_byte_limit_has_exact_boundaries() {
        assert_eq!(step_id_byte_rejection(MAX_SEMANTIC_ID_LENGTH - 1), None);
        assert_eq!(step_id_byte_rejection(MAX_SEMANTIC_ID_LENGTH), None);
        assert_eq!(
            step_id_byte_rejection(MAX_SEMANTIC_ID_LENGTH + 1),
            Some(JobIdentifierLimitRejection::StepIdBytes)
        );
    }
}
