//! Durable GitHub-native Check identities used at adapter boundaries.

use std::{fmt, num::NonZeroU64};

use thiserror::Error;

const MAX_CHECK_NAME_BYTES: usize = 255;
const MAX_SUBJECT_KEY_BYTES: usize = 1_024;

macro_rules! positive_github_id {
    ($(#[$meta:meta])* $name:ident, $field:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(NonZeroU64);

        impl $name {
            /// Constructs a positive GitHub identifier within the signed 64-bit storage boundary.
            ///
            /// # Errors
            ///
            /// Rejects zero and values larger than `i64::MAX`.
            pub fn new(value: u64) -> Result<Self, GithubNativeCheckValueError> {
                let value = NonZeroU64::new(value)
                    .ok_or(GithubNativeCheckValueError::InvalidNumericId($field))?;
                if i64::try_from(value.get()).is_err() {
                    return Err(GithubNativeCheckValueError::InvalidNumericId($field));
                }
                Ok(Self(value))
            }

            /// Returns the positive GitHub identifier.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0.get()
            }
        }
    };
}

positive_github_id!(/// Positive GitHub App identifier.
    GithubCheckAppId, "GitHub Check App ID");
positive_github_id!(/// Positive GitHub Check Suite identifier.
    GithubCheckSuiteId, "GitHub Check Suite ID");
positive_github_id!(/// Positive GitHub Check Run identifier.
    GithubCheckRunId, "GitHub Check Run ID");

/// Bounded printable GitHub Check Run name retained by the current GitHub manifest.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubCheckName(String);

impl GithubCheckName {
    /// Constructs a printable UTF-8 Check Run name.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, edge-whitespace, or control-bearing names.
    pub fn new(value: impl Into<String>) -> Result<Self, GithubNativeCheckValueError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_CHECK_NAME_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(GithubNativeCheckValueError::InvalidCheckName);
        }
        Ok(Self(value))
    }

    /// Returns the validated provider-facing name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for GithubCheckName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GithubCheckName([REDACTED])")
    }
}

/// Stable manifest key for the workflow set previously represented by Checks.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubCheckSubjectKey(String);

impl GithubCheckSubjectKey {
    /// Constructs a safe relative subject key.
    ///
    /// # Errors
    ///
    /// Rejects unsafe, empty, untrimmed, control-bearing, or oversized values.
    pub fn new(value: impl Into<String>) -> Result<Self, GithubNativeCheckValueError> {
        let value = value.into();
        validate_text(&value, MAX_SUBJECT_KEY_BYTES)?;
        if value.starts_with('/')
            || value.contains('\\')
            || value.contains("//")
            || value
                .split('/')
                .any(|component| component.is_empty() || matches!(component, "." | ".."))
        {
            return Err(GithubNativeCheckValueError::InvalidSubjectKey);
        }
        Ok(Self(value))
    }

    /// Returns the durable subject key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for GithubCheckSubjectKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GithubCheckSubjectKey([REDACTED])")
    }
}

/// Invalid native GitHub Check identity or manifest value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubNativeCheckValueError {
    /// A numeric GitHub identity is zero or outside the signed 64-bit storage boundary.
    #[error("{0} must be a positive identifier representable by BIGINT")]
    InvalidNumericId(&'static str),
    /// The provider-facing Check name is invalid.
    #[error("the GitHub Check name is invalid")]
    InvalidCheckName,
    /// The manifest subject key is unsafe.
    #[error("the GitHub Check subject key is invalid")]
    InvalidSubjectKey,
}

fn validate_text(value: &str, maximum: usize) -> Result<(), GithubNativeCheckValueError> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > maximum
        || value.chars().any(char::is_control)
    {
        return Err(GithubNativeCheckValueError::InvalidSubjectKey);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_ids_keep_the_exact_signed_storage_boundary() {
        for value in [1, i64::MAX as u64] {
            assert_eq!(GithubCheckAppId::new(value).unwrap().get(), value);
            assert_eq!(GithubCheckSuiteId::new(value).unwrap().get(), value);
            assert_eq!(GithubCheckRunId::new(value).unwrap().get(), value);
        }
        for value in [0, i64::MAX as u64 + 1] {
            assert!(GithubCheckAppId::new(value).is_err());
            assert!(GithubCheckSuiteId::new(value).is_err());
            assert!(GithubCheckRunId::new(value).is_err());
        }
    }

    #[test]
    fn retained_manifest_text_is_bounded_safe_and_redacted() {
        let name = GithubCheckName::new("Automata CI").unwrap();
        assert_eq!(name.as_str(), "Automata CI");
        assert_eq!(format!("{name:?}"), "GithubCheckName([REDACTED])");
        assert!(GithubCheckName::new("").is_err());
        assert!(GithubCheckName::new(" padded ").is_err());
        assert!(GithubCheckName::new("x".repeat(MAX_CHECK_NAME_BYTES + 1)).is_err());

        let subject = GithubCheckSubjectKey::new(".ci/workflows").unwrap();
        assert_eq!(subject.as_str(), ".ci/workflows");
        for invalid in ["", "/root", "a//b", "a/../b", "a\\b", " padded "] {
            assert!(GithubCheckSubjectKey::new(invalid).is_err());
        }
    }
}
