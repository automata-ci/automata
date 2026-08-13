use std::{collections::BTreeMap, fmt, sync::Arc};

use thiserror::Error;

const MAX_CONSTRUCTION_ITEMS: usize = 65_536;
const MAX_KEY_BYTES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GithubValueLimitRejection {
    ConstructionItems,
    KeyBytes,
}

const fn github_value_construction_item_rejection(
    observed: usize,
) -> Option<GithubValueLimitRejection> {
    if observed > MAX_CONSTRUCTION_ITEMS {
        return Some(GithubValueLimitRejection::ConstructionItems);
    }
    None
}

const fn github_value_key_byte_rejection(observed: usize) -> Option<GithubValueLimitRejection> {
    if observed > MAX_KEY_BYTES {
        return Some(GithubValueLimitRejection::KeyBytes);
    }
    None
}

/// Invalid public expression-value construction.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubValueError {
    /// An object key exceeded the hard byte ceiling.
    #[error("invalid GitHub expression object key")]
    InvalidKey,
    /// Object keys collide under GitHub's ordinal-ignore-case lookup.
    #[error("duplicate case-insensitive GitHub expression object key")]
    DuplicateKey,
    /// A collection exceeded the hard construction ceiling.
    #[error("GitHub expression collection is too large")]
    TooManyItems,
}

/// Case-insensitive, insertion-stable GitHub expression object.
#[derive(Clone)]
pub struct GithubObject {
    entries: Arc<[(String, GithubValue)]>,
    lookup: Arc<BTreeMap<String, usize>>,
}

impl GithubObject {
    /// Creates an object, rejecting oversized or case-insensitively duplicate keys.
    ///
    /// # Errors
    ///
    /// Returns [`GithubValueError`] for oversized keys, collisions, or item count.
    pub fn new(entries: Vec<(String, GithubValue)>) -> Result<Self, GithubValueError> {
        if github_value_construction_item_rejection(entries.len()).is_some() {
            return Err(GithubValueError::TooManyItems);
        }
        let mut lookup = BTreeMap::new();
        for (index, (key, _)) in entries.iter().enumerate() {
            if github_value_key_byte_rejection(key.len()).is_some() {
                return Err(GithubValueError::InvalidKey);
            }
            if lookup
                .insert(crate::coercion::ordinal_key(key), index)
                .is_some()
            {
                return Err(GithubValueError::DuplicateKey);
            }
        }
        Ok(Self {
            entries: entries.into(),
            lookup: Arc::new(lookup),
        })
    }

    /// Looks up a property using GitHub's case-insensitive context semantics.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&GithubValue> {
        self.lookup
            .get(&crate::coercion::ordinal_key(key))
            .map(|index| &self.entries[*index].1)
    }

    /// Returns entries in their original stable order.
    #[must_use]
    pub fn entries(&self) -> &[(String, GithubValue)] {
        &self.entries
    }

    pub(crate) fn same_identity(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.entries, &other.entries)
    }
}

impl fmt::Debug for GithubObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubObject")
            .field("entry_count", &self.entries.len())
            .field("values", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Canonical value kinds supported by GitHub Actions expressions.
#[derive(Clone)]
pub enum GithubValue {
    /// Null/missing value.
    Null,
    /// Boolean value.
    Boolean(bool),
    /// Exact IEEE-754 binary64 value.
    Number(u64),
    /// UTF-8 string value.
    String(Arc<str>),
    /// Identity-bearing array value.
    Array(Arc<[GithubValue]>),
    /// Identity-bearing object value.
    Object(GithubObject),
}

impl GithubValue {
    /// Creates a canonical number, normalizing every NaN representation.
    #[must_use]
    pub const fn number(value: f64) -> Self {
        if value.is_nan() {
            Self::Number(f64::NAN.to_bits())
        } else {
            Self::Number(value.to_bits())
        }
    }

    /// Creates a string value.
    #[must_use]
    pub fn string(value: impl Into<String>) -> Self {
        Self::String(Arc::from(value.into()))
    }

    /// Creates a bounded array.
    ///
    /// # Errors
    ///
    /// Returns [`GithubValueError::TooManyItems`] beyond the hard ceiling.
    pub fn array(values: Vec<Self>) -> Result<Self, GithubValueError> {
        if github_value_construction_item_rejection(values.len()).is_some() {
            return Err(GithubValueError::TooManyItems);
        }
        Ok(Self::Array(values.into()))
    }

    /// Wraps a validated object.
    #[must_use]
    pub const fn object(value: GithubObject) -> Self {
        Self::Object(value)
    }

    /// Returns the boolean value, when this is a boolean.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Boolean(value) => Some(*value),
            _ => None,
        }
    }

    /// Returns the number value, when this is a number.
    #[must_use]
    pub const fn as_number(&self) -> Option<f64> {
        match self {
            Self::Number(bits) => Some(f64::from_bits(*bits)),
            _ => None,
        }
    }

    /// Returns the string value, when this is a string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    /// Returns whether GitHub condition coercion considers this value truthy.
    #[must_use]
    pub fn is_truthy(&self) -> bool {
        match self {
            Self::Null => false,
            Self::Boolean(value) => *value,
            Self::Number(bits) => {
                let value = f64::from_bits(*bits);
                value != 0.0 && !value.is_nan()
            }
            Self::String(value) => !value.is_empty(),
            Self::Array(_) | Self::Object(_) => true,
        }
    }

    /// Applies GitHub expression loose scalar equality.
    ///
    /// Arrays and objects retain identity equality; callers implementing a
    /// structural protocol such as matrix matching must recurse explicitly.
    #[must_use]
    pub fn loosely_equals(&self, other: &Self) -> bool {
        crate::coercion::abstract_equal(self, other)
    }

    /// Applies GitHub's runner-compatible scalar string coercion.
    ///
    /// This is an explicit exposure boundary: callers should avoid retaining
    /// or formatting the returned string when the value originated from a
    /// secret-bearing context.
    #[must_use]
    pub fn coerce_to_string(&self) -> String {
        crate::coercion::to_string(self)
    }

    pub(crate) fn is_primitive(&self) -> bool {
        !matches!(self, Self::Array(_) | Self::Object(_))
    }
}

impl fmt::Debug for GithubValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => formatter.write_str("GithubValue::Null"),
            Self::Boolean(_) => formatter.write_str("GithubValue::Boolean([REDACTED])"),
            Self::Number(_) => formatter.write_str("GithubValue::Number([REDACTED])"),
            Self::String(value) => formatter
                .debug_tuple("GithubValue::String")
                .field(&format_args!("{} bytes [REDACTED]", value.len()))
                .finish(),
            Self::Array(values) => formatter
                .debug_tuple("GithubValue::Array")
                .field(&format_args!("{} items [REDACTED]", values.len()))
                .finish(),
            Self::Object(value) => value.fmt(formatter),
        }
    }
}

#[cfg(test)]
mod limit_contract_tests {
    use super::{
        GithubValueLimitRejection, MAX_CONSTRUCTION_ITEMS, MAX_KEY_BYTES,
        github_value_construction_item_rejection, github_value_key_byte_rejection,
    };

    #[test]
    fn github_value_construction_item_limit_has_exact_boundaries() {
        assert_eq!(
            github_value_construction_item_rejection(MAX_CONSTRUCTION_ITEMS - 1),
            None
        );
        assert_eq!(
            github_value_construction_item_rejection(MAX_CONSTRUCTION_ITEMS),
            None
        );
        assert_eq!(
            github_value_construction_item_rejection(MAX_CONSTRUCTION_ITEMS + 1),
            Some(GithubValueLimitRejection::ConstructionItems)
        );
    }

    #[test]
    fn github_value_key_byte_limit_has_exact_boundaries() {
        assert_eq!(github_value_key_byte_rejection(MAX_KEY_BYTES - 1), None);
        assert_eq!(github_value_key_byte_rejection(MAX_KEY_BYTES), None);
        assert_eq!(
            github_value_key_byte_rejection(MAX_KEY_BYTES + 1),
            Some(GithubValueLimitRejection::KeyBytes)
        );
    }
}
