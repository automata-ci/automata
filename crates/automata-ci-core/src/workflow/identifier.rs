//! Stable source-level identifiers for workflow DAG nodes.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use super::WorkflowPlanError;

const MAX_PLAN_KEY_LENGTH: usize = 256;

macro_rules! plan_key {
    ($(#[$meta:meta])* $name:ident, $kind:literal) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Creates a stable source-level key.
            ///
            /// # Errors
            ///
            /// Rejects empty, overlong, whitespace-padded, or control-character keys.
            pub fn new(value: impl Into<String>) -> Result<Self, WorkflowPlanError> {
                let value = value.into();
                if value.is_empty()
                    || value.trim() != value
                    || value.len() > MAX_PLAN_KEY_LENGTH
                    || value.chars().any(char::is_control)
                {
                    return Err(WorkflowPlanError::InvalidKey {
                        kind: $kind,
                        value,
                    });
                }
                Ok(Self(value))
            }

            /// Returns the validated source-level wire key.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = WorkflowPlanError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
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

plan_key!(/// Stable source-level job identity used by DAG edges.
    WorkflowJobKey, "workflow job key");
plan_key!(/// Stable source-level step identity; explicit IDs and positions occupy separate namespaces.
    WorkflowStepKey, "workflow step key");
plan_key!(/// Stable service-container alias within one step-based job.
    WorkflowServiceKey, "workflow service key");
plan_key!(/// Stable invocation-input identity.
    WorkflowInputKey, "workflow input key");
plan_key!(/// Stable invocation-secret identity; this identifies a binding, never its value.
    WorkflowSecretKey, "workflow secret key");
plan_key!(/// Stable workflow or logical-job output identity.
    WorkflowOutputKey, "workflow output key");
