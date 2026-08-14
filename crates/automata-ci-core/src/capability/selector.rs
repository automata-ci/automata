//! Validated, canonical scheduling selectors.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use thiserror::Error;

const MAX_SELECTOR_LENGTH: usize = 256;

macro_rules! canonical_selector {
    ($(#[$meta:meta])* $name:ident, $description:literal) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Validates and canonicalizes a case-insensitive selector.
            ///
            /// # Errors
            ///
            /// Returns [`SelectorError`] for empty, ambiguous, overlong, or
            /// control-character-containing input.
            pub fn new(value: impl AsRef<str>) -> Result<Self, SelectorError> {
                let value = value.as_ref();
                if value.is_empty() {
                    return Err(SelectorError::Empty($description));
                }
                if value.trim() != value {
                    return Err(SelectorError::SurroundingWhitespace($description));
                }
                if let Some(rejection) = selector_length_rejection(value.chars().count(), $description) {
                    return Err(rejection);
                }
                if value.chars().any(char::is_control) {
                    return Err(SelectorError::ControlCharacter($description));
                }
                Ok(Self(value.to_lowercase()))
            }

            /// Returns the canonical lower-case representation.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = SelectorError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl TryFrom<String> for $name {
            type Error = SelectorError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(D::Error::custom)
            }
        }
    };
}

canonical_selector!(
    /// A case-insensitive runner label, kept distinct from runner groups.
    RunnerLabel,
    "runner label"
);
canonical_selector!(
    /// A case-insensitive administrative runner-group name.
    RunnerGroup,
    "runner group"
);

/// Validation failures for labels and group names.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SelectorError {
    /// The selector value is empty.
    #[error("{0} cannot be empty")]
    Empty(&'static str),
    /// The selector contains leading or trailing whitespace.
    #[error("{0} cannot contain surrounding whitespace")]
    SurroundingWhitespace(&'static str),
    /// The selector exceeds its bounded character count.
    #[error("{kind} exceeds its maximum length of {max} characters")]
    TooLong {
        /// Human-readable selector kind.
        kind: &'static str,
        /// Maximum accepted Unicode-scalar count.
        max: usize,
    },
    /// The selector contains a terminal or protocol control character.
    #[error("{0} cannot contain control characters")]
    ControlCharacter(&'static str),
}

const fn selector_length_rejection(characters: usize, kind: &'static str) -> Option<SelectorError> {
    if characters > MAX_SELECTOR_LENGTH {
        return Some(SelectorError::TooLong {
            kind,
            max: MAX_SELECTOR_LENGTH,
        });
    }
    None
}

#[cfg(test)]
mod limit_contract_tests {
    use super::{MAX_SELECTOR_LENGTH, SelectorError, selector_length_rejection};

    #[test]
    fn selector_character_limit_has_exact_boundaries() {
        assert_eq!(
            selector_length_rejection(MAX_SELECTOR_LENGTH - 1, "runner label"),
            None
        );
        assert_eq!(
            selector_length_rejection(MAX_SELECTOR_LENGTH, "runner label"),
            None
        );
        assert_eq!(
            selector_length_rejection(MAX_SELECTOR_LENGTH + 1, "runner label"),
            Some(SelectorError::TooLong {
                kind: "runner label",
                max: MAX_SELECTOR_LENGTH,
            })
        );
    }
}
