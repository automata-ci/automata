//! Durable provider and provider-native identities.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Maximum encoded bytes in one provider adapter type identifier.
pub const MAX_PROVIDER_TYPE_ID_BYTES: usize = 64;
/// Maximum UTF-8 bytes in one opaque provider-native identity.
pub const MAX_EXTERNAL_ID_BYTES: usize = 512;

/// Canonical identifier of one statically registered provider adapter type.
///
/// This value identifies implementation behavior such as `github` or
/// `forgejo`. It does not identify a configured server and is never a network
/// location.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProviderTypeId(String);

impl ProviderTypeId {
    /// Validates a canonical provider adapter type identifier.
    ///
    /// # Errors
    ///
    /// Rejects values outside the lower-case ASCII grammar
    /// `[a-z][a-z0-9]*(?:-[a-z0-9]+)*` or the durable byte bound.
    pub fn new(value: impl Into<String>) -> Result<Self, ProviderIdentityError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ProviderIdentityError::EmptyProviderType);
        }
        if value.len() > MAX_PROVIDER_TYPE_ID_BYTES {
            return Err(ProviderIdentityError::ProviderTypeTooLong);
        }
        if !is_provider_type_id(&value) {
            return Err(ProviderIdentityError::InvalidProviderType);
        }
        Ok(Self(value))
    }

    /// Returns the canonical adapter registry key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the identifier and returns its canonical value.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for ProviderTypeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(formatter)
    }
}

impl FromStr for ProviderTypeId {
    type Err = ProviderIdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for ProviderTypeId {
    type Error = ProviderIdentityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ProviderTypeId> for String {
    fn from(value: ProviderTypeId) -> Self {
        value.into_string()
    }
}

fn is_provider_type_id(value: &str) -> bool {
    let mut components = value.split('-');
    let Some(first) = components.next() else {
        return false;
    };
    is_identifier_component(first, true)
        && components.all(|component| is_identifier_component(component, false))
}

fn is_identifier_component(value: &str, first_component: bool) -> bool {
    let bytes = value.as_bytes();
    let Some(first) = bytes.first() else {
        return false;
    };
    ((!first_component && first.is_ascii_digit()) || first.is_ascii_lowercase())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

macro_rules! uuid_identity {
    ($(#[$meta:meta])* $name:ident, $field:literal) => {
        $(#[$meta])*
        #[derive(
            Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Creates a new random RFC 9562 version-4 identity.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            /// Constructs a durable identity from a non-nil UUID.
            ///
            /// # Errors
            ///
            /// Rejects the nil UUID sentinel.
            pub fn from_uuid(value: Uuid) -> Result<Self, ProviderIdentityError> {
                if value.is_nil() {
                    return Err(ProviderIdentityError::NilUuid($field));
                }
                Ok(Self(value))
            }

            /// Returns the underlying UUID.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = ProviderIdentityError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value)
                    .map_err(|_| ProviderIdentityError::InvalidUuid($field))
                    .and_then(Self::from_uuid)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = Uuid::deserialize(deserializer)?;
                Self::from_uuid(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

uuid_identity!(
    /// Durable identity of one configured provider installation.
    ProviderInstanceId,
    "provider instance ID"
);
uuid_identity!(
    /// Server-owned identity of one configured provider repository connection.
    ProviderConnectionId,
    "provider connection ID"
);
uuid_identity!(
    /// Opaque public identity of one connection-bound webhook endpoint.
    ProviderWebhookEndpointId,
    "provider webhook endpoint ID"
);
uuid_identity!(
    /// Durable server-owned identity of one authenticated provider delivery.
    ProviderDeliveryId,
    "provider delivery ID"
);
uuid_identity!(
    /// Durable identity of one processing invocation derived from an immutable delivery.
    ProviderProcessingInvocationId,
    "provider processing invocation ID"
);
uuid_identity!(
    /// Durable identity of one provider processing worker.
    ProviderProcessingWorkerId,
    "provider processing worker ID"
);
uuid_identity!(
    /// Durable identity of one provider result subject.
    ProviderResultSubjectId,
    "provider result subject ID"
);
uuid_identity!(
    /// Provider-neutral identity of one workflow invocation before admission.
    ProviderWorkflowInvocationId,
    "provider workflow invocation ID"
);
uuid_identity!(
    /// Durable identity of one provider result publication worker.
    ProviderResultWorkerId,
    "provider result worker ID"
);
uuid_identity!(
    /// Durable identity of one control-credential acquisition.
    ProviderControlCredentialId,
    "provider control credential ID"
);
uuid_identity!(
    /// Durable identity of one workload credential authority.
    ProviderWorkloadCredentialId,
    "provider workload credential ID"
);

macro_rules! external_identity {
    ($(#[$meta:meta])* $name:ident, $field:literal) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Validates one opaque provider-native identity.
            ///
            /// # Errors
            ///
            /// Rejects empty, untrimmed, control-bearing, or oversized values.
            pub fn new(value: impl Into<String>) -> Result<Self, ProviderIdentityError> {
                let value = value.into();
                validate_external_id(&value, $field)?;
                Ok(Self(value))
            }

            /// Returns the exact provider-native representation.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consumes the identity and returns its provider-native value.
            #[must_use]
            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.as_str().fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = ProviderIdentityError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl TryFrom<String> for $name {
            type Error = ProviderIdentityError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.into_string()
            }
        }
    };
}

external_identity!(
    /// Provider-native repository identity, interpreted within one provider instance.
    ExternalRepositoryId,
    "external repository ID"
);
external_identity!(
    /// Provider-native subject identity, interpreted with its kind and provider instance.
    ExternalSubjectId,
    "external subject ID"
);
external_identity!(
    /// Provider-native webhook delivery identity, interpreted within one provider instance.
    ExternalDeliveryId,
    "external delivery ID"
);
external_identity!(
    /// Provider-native pull-request or merge-request identity.
    ExternalChangeId,
    "external change ID"
);
external_identity!(
    /// Provider-native merge-queue entry or candidate identity.
    ExternalMergeQueueId,
    "external merge-queue ID"
);
external_identity!(
    /// Provider-native result object identity.
    ExternalResultId,
    "external result ID"
);
external_identity!(
    /// Provider-native credential identity used for reconciliation and revocation.
    ExternalCredentialId,
    "external credential ID"
);

/// Instance-scoped provider-native repository identity.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalRepositoryIdentity {
    instance_id: ProviderInstanceId,
    external_id: ExternalRepositoryId,
}

impl ExternalRepositoryIdentity {
    /// Binds a provider-native repository ID to exactly one configured instance.
    #[must_use]
    pub const fn new(instance_id: ProviderInstanceId, external_id: ExternalRepositoryId) -> Self {
        Self {
            instance_id,
            external_id,
        }
    }

    /// Returns the configured provider installation namespace.
    #[must_use]
    pub const fn instance_id(&self) -> ProviderInstanceId {
        self.instance_id
    }

    /// Returns the exact provider-native repository ID.
    #[must_use]
    pub const fn external_id(&self) -> &ExternalRepositoryId {
        &self.external_id
    }
}

/// Instance-scoped provider-native subject identity.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalSubjectIdentity {
    instance_id: ProviderInstanceId,
    kind: ExternalSubjectKind,
    external_id: ExternalSubjectId,
}

impl ExternalSubjectIdentity {
    /// Binds a typed provider-native subject to one configured instance.
    #[must_use]
    pub const fn new(
        instance_id: ProviderInstanceId,
        kind: ExternalSubjectKind,
        external_id: ExternalSubjectId,
    ) -> Self {
        Self {
            instance_id,
            kind,
            external_id,
        }
    }

    /// Returns the configured provider installation namespace.
    #[must_use]
    pub const fn instance_id(&self) -> ProviderInstanceId {
        self.instance_id
    }

    /// Returns the provider-independent subject class.
    #[must_use]
    pub const fn kind(&self) -> ExternalSubjectKind {
        self.kind
    }

    /// Returns the exact provider-native subject ID.
    #[must_use]
    pub const fn external_id(&self) -> &ExternalSubjectId {
        &self.external_id
    }
}

/// Instance-scoped provider-native webhook delivery identity.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalDeliveryIdentity {
    instance_id: ProviderInstanceId,
    external_id: ExternalDeliveryId,
}

impl ExternalDeliveryIdentity {
    /// Binds a provider-native delivery ID to exactly one configured instance.
    #[must_use]
    pub const fn new(instance_id: ProviderInstanceId, external_id: ExternalDeliveryId) -> Self {
        Self {
            instance_id,
            external_id,
        }
    }

    /// Returns the configured provider installation namespace.
    #[must_use]
    pub const fn instance_id(&self) -> ProviderInstanceId {
        self.instance_id
    }

    /// Returns the exact provider-native delivery ID.
    #[must_use]
    pub const fn external_id(&self) -> &ExternalDeliveryId {
        &self.external_id
    }
}

fn validate_external_id(value: &str, field: &'static str) -> Result<(), ProviderIdentityError> {
    if value.is_empty() || value.trim() != value {
        return Err(ProviderIdentityError::EmptyOrUntrimmedExternalId(field));
    }
    if value.len() > MAX_EXTERNAL_ID_BYTES {
        return Err(ProviderIdentityError::ExternalIdTooLong(field));
    }
    if value.chars().any(char::is_control) {
        return Err(ProviderIdentityError::ControlCharacter(field));
    }
    Ok(())
}

/// Provider-independent class of an external identity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalSubjectKind {
    /// One human user.
    User,
    /// One organization or top-level group.
    Organization,
    /// One team or nested group.
    Team,
    /// One non-human automation identity.
    ServiceAccount,
}

/// Invalid provider identity rejected before persistence or routing.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderIdentityError {
    /// The provider adapter type was empty.
    #[error("provider type cannot be empty")]
    EmptyProviderType,
    /// The provider adapter type exceeded its durable bound.
    #[error("provider type exceeds its maximum byte length")]
    ProviderTypeTooLong,
    /// The provider adapter type did not use canonical lower-case syntax.
    #[error("provider type is not a canonical lower-case identifier")]
    InvalidProviderType,
    /// A durable provider UUID used the nil sentinel.
    #[error("{0} must not use the nil UUID sentinel")]
    NilUuid(&'static str),
    /// A durable provider UUID was malformed.
    #[error("{0} is not a valid UUID")]
    InvalidUuid(&'static str),
    /// An external identity was empty or untrimmed.
    #[error("{0} must not be empty or contain surrounding whitespace")]
    EmptyOrUntrimmedExternalId(&'static str),
    /// An external identity exceeded its durable bound.
    #[error("{0} exceeds its maximum byte length")]
    ExternalIdTooLong(&'static str),
    /// An external identity contained a control character.
    #[error("{0} must not contain control characters")]
    ControlCharacter(&'static str),
}
