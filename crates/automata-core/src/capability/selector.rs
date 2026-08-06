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
                if value.chars().count() > MAX_SELECTOR_LENGTH {
                    return Err(SelectorError::TooLong {
                        kind: $description,
                        max: MAX_SELECTOR_LENGTH,
                    });
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
    #[error("{0} cannot be empty")]
    Empty(&'static str),
    #[error("{0} cannot contain surrounding whitespace")]
    SurroundingWhitespace(&'static str),
    #[error("{kind} exceeds its maximum length of {max} characters")]
    TooLong { kind: &'static str, max: usize },
    #[error("{0} cannot contain control characters")]
    ControlCharacter(&'static str),
}
