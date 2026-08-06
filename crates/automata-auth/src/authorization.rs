use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_NAME_LENGTH: usize = 128;

macro_rules! policy_name {
    ($name:ident, $label:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Creates a validated policy identifier.
            ///
            /// # Errors
            ///
            /// Returns an error when the value is empty, too long, or contains a
            /// character outside the portable policy alphabet.
            pub fn new(value: impl Into<String>) -> Result<Self, PolicyNameError> {
                let value = value.into();
                validate_policy_name(&value, $label)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = PolicyNameError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

policy_name!(RoleName, "role name");
policy_name!(Permission, "permission");

fn validate_policy_name(value: &str, label: &'static str) -> Result<(), PolicyNameError> {
    if value.is_empty() {
        return Err(PolicyNameError::Empty { label });
    }
    if value.len() > MAX_NAME_LENGTH {
        return Err(PolicyNameError::TooLong {
            label,
            maximum: MAX_NAME_LENGTH,
        });
    }
    if !value.bytes().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, b'-' | b'_' | b':' | b'.')
    }) {
        return Err(PolicyNameError::InvalidCharacter { label });
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PolicyNameError {
    #[error("{label} must not be empty")]
    Empty { label: &'static str },
    #[error("{label} must not exceed {maximum} bytes")]
    TooLong { label: &'static str, maximum: usize },
    #[error("{label} contains a character outside the portable policy-name alphabet")]
    InvalidCharacter { label: &'static str },
}

/// Explicit role-to-permission grants. There are no privileged role names and no
/// administrator bypass: even a role named `administrator` only receives grants
/// present in this policy.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RbacPolicy {
    grants: BTreeMap<RoleName, BTreeSet<Permission>>,
}

impl RbacPolicy {
    pub fn new(grants: BTreeMap<RoleName, BTreeSet<Permission>>) -> Self {
        Self { grants }
    }

    pub fn permissions_for<'a>(
        &'a self,
        roles: impl IntoIterator<Item = &'a RoleName>,
    ) -> BTreeSet<Permission> {
        roles
            .into_iter()
            .filter_map(|role| self.grants.get(role))
            .flatten()
            .cloned()
            .collect()
    }

    pub fn allows<'a>(
        &'a self,
        roles: impl IntoIterator<Item = &'a RoleName>,
        permission: &Permission,
    ) -> bool {
        roles
            .into_iter()
            .filter_map(|role| self.grants.get(role))
            .any(|permissions| permissions.contains(permission))
    }
}

/// Authorization is a separate port from authentication so deployments can replace
/// RBAC without replacing their identity provider.
pub trait Authorizer: std::fmt::Debug + Send + Sync {
    fn is_allowed(&self, roles: &BTreeSet<RoleName>, permission: &Permission) -> bool;
}

impl Authorizer for RbacPolicy {
    fn is_allowed(&self, roles: &BTreeSet<RoleName>, permission: &Permission) -> bool {
        self.allows(roles, permission)
    }
}
