//! Extensible, typed feature identifiers used during runner matching.
//!
//! Each feature is a string with the wire grammar
//! `<namespace>/<hyphenated-name>@v<major>`. `automata.core` is reserved for
//! the provider-neutral features defined here. Third-party adapters should use
//! a reverse-DNS namespace that they control. Unknown, valid identifiers are
//! deliberately retained across serialization so independently deployed
//! schedulers and runners can negotiate capabilities without lockstep upgrades.

use std::{borrow::Cow, fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use thiserror::Error;

/// Maximum encoded length of one capability identifier.
pub const MAX_CAPABILITY_ID_LENGTH: usize = 128;

/// Validation failures for namespaced capability identifiers.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CapabilityIdError {
    /// The identifier was empty.
    #[error("capability identifier cannot be empty")]
    Empty,
    /// The identifier exceeded the wire-format limit.
    #[error("capability identifier exceeds its maximum length of {max} bytes")]
    TooLong {
        /// Maximum accepted UTF-8 byte length.
        max: usize,
    },
    /// The identifier contained a non-ASCII byte.
    #[error("capability identifier must contain only ASCII characters")]
    NonAscii,
    /// The namespace did not follow the documented lower-case grammar.
    #[error("capability namespace must be dot-separated lower-case ASCII labels")]
    InvalidNamespace,
    /// The feature name did not follow the documented lower-case grammar.
    #[error("capability name must be a lower-case ASCII hyphenated name")]
    InvalidName,
    /// The identifier did not end in a canonical, nonzero major version.
    #[error("capability version must be a canonical nonzero `@v<major>` suffix")]
    InvalidVersion,
}

/// Canonical storage shared by the three public, non-interchangeable ID types.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct CapabilityId(Cow<'static, str>);

impl CapabilityId {
    const fn known(value: &'static str) -> Self {
        Self(Cow::Borrowed(value))
    }

    fn new(value: &str) -> Result<Self, CapabilityIdError> {
        validate_capability_id(value)?;
        Ok(Self(Cow::Owned(value.to_owned())))
    }

    fn from_owned(value: String) -> Result<Self, CapabilityIdError> {
        validate_capability_id(&value)?;
        Ok(Self(Cow::Owned(value)))
    }

    fn as_str(&self) -> &str {
        &self.0
    }

    fn namespace(&self) -> &str {
        self.as_str()
            .split_once('/')
            .expect("validated capability ID has a namespace")
            .0
    }

    fn name(&self) -> &str {
        let (_, qualified_name) = self
            .as_str()
            .split_once('/')
            .expect("validated capability ID has a namespace");
        qualified_name
            .rsplit_once("@v")
            .expect("validated capability ID has a version")
            .0
    }

    fn major_version(&self) -> u16 {
        self.as_str()
            .rsplit_once("@v")
            .expect("validated capability ID has a version")
            .1
            .parse()
            .expect("validated capability ID has a bounded numeric version")
    }

    fn into_string(self) -> String {
        self.0.into_owned()
    }
}

/// Validates `<namespace>/<name>@v<major>`.
///
/// Namespace labels and the feature name start with a lower-case ASCII letter,
/// end with a lower-case ASCII letter or digit, and may contain interior
/// digits or hyphens. Namespace labels are separated by dots; third-party
/// adapters should use a reverse-DNS namespace that they control. The major
/// version is in the inclusive range `1..=u16::MAX` and has no leading zero.
fn validate_capability_id(value: &str) -> Result<(), CapabilityIdError> {
    if value.is_empty() {
        return Err(CapabilityIdError::Empty);
    }
    if value.len() > MAX_CAPABILITY_ID_LENGTH {
        return Err(CapabilityIdError::TooLong {
            max: MAX_CAPABILITY_ID_LENGTH,
        });
    }
    if !value.is_ascii() {
        return Err(CapabilityIdError::NonAscii);
    }

    let (qualified_name, version) = value
        .rsplit_once("@v")
        .ok_or(CapabilityIdError::InvalidVersion)?;
    if version.is_empty()
        || version.starts_with('0')
        || !version.bytes().all(|byte| byte.is_ascii_digit())
        || version.parse::<u16>().is_err()
    {
        return Err(CapabilityIdError::InvalidVersion);
    }

    let (namespace, name) = qualified_name
        .split_once('/')
        .ok_or(CapabilityIdError::InvalidNamespace)?;
    if namespace.is_empty()
        || namespace
            .split('.')
            .any(|component| !is_identifier_component(component))
    {
        return Err(CapabilityIdError::InvalidNamespace);
    }
    if !is_identifier_component(name) {
        return Err(CapabilityIdError::InvalidName);
    }

    Ok(())
}

fn is_identifier_component(component: &str) -> bool {
    let bytes = component.as_bytes();
    let Some(first) = bytes.first() else {
        return false;
    };
    let Some(last) = bytes.last() else {
        return false;
    };
    first.is_ascii_lowercase()
        && (last.is_ascii_lowercase() || last.is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

macro_rules! capability_id_type {
    (
        $(#[$type_meta:meta])*
        $name:ident {
            $($(#[$constant_meta:meta])* $constant:ident = $value:literal),* $(,)?
        }
    ) => {
        $(#[$type_meta])*
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(CapabilityId);

        impl $name {
            $(
                $(#[$constant_meta])*
                pub const $constant: Self = Self(CapabilityId::known($value));
            )*

            /// Validates an extensible capability identifier.
            ///
            /// # Errors
            ///
            /// Returns [`CapabilityIdError`] unless `value` follows the
            /// `<namespace>/<name>@v<major>` wire grammar.
            pub fn new(value: impl AsRef<str>) -> Result<Self, CapabilityIdError> {
                CapabilityId::new(value.as_ref()).map(Self)
            }

            /// Returns the complete canonical wire identifier.
            #[must_use]
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }

            /// Returns the provider or specification namespace.
            #[must_use]
            pub fn namespace(&self) -> &str {
                self.0.namespace()
            }

            /// Returns the unversioned feature name.
            #[must_use]
            pub fn name(&self) -> &str {
                self.0.name()
            }

            /// Returns the required major capability version.
            #[must_use]
            pub fn major_version(&self) -> u16 {
                self.0.major_version()
            }

            /// Consumes the typed identifier and returns its wire value.
            #[must_use]
            pub fn into_string(self) -> String {
                self.0.into_string()
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.as_str().fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = CapabilityIdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl TryFrom<String> for $name {
            type Error = CapabilityIdError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                CapabilityId::from_owned(value).map(Self)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::try_from(value).map_err(D::Error::custom)
            }
        }
    };
}

capability_id_type! {
    /// Provider-neutral abilities of a whole-job sandbox.
    SandboxFeature {
        /// A fresh workspace is created for every job.
        CLEAN_WORKSPACE = "automata.core/clean-workspace@v1",
        /// Job network policy can be isolated from the host and other jobs.
        NETWORK_ISOLATION = "automata.core/network-isolation@v1",
        /// The sandbox root filesystem can be mounted read-only.
        READ_ONLY_ROOT = "automata.core/read-only-root@v1",
        /// The provider can snapshot a sandbox.
        SNAPSHOT = "automata.core/snapshot@v1",
        /// Nested hardware virtualization is available to the job.
        NESTED_VIRTUALIZATION = "automata.core/nested-virtualization@v1",
        /// GPU devices can be passed through the sandbox boundary.
        GPU_PASSTHROUGH = "automata.core/gpu-passthrough@v1",
        /// The job can execute with a privileged user inside its sandbox.
        PRIVILEGED_USER = "automata.core/privileged-user@v1",
        /// Explicit host paths can be mounted into the sandbox.
        HOST_PATH_MOUNTS = "automata.core/host-path-mounts@v1",
        /// Jobs launch only through the explicit Hyper-V-isolated Windows
        /// container mechanism, without process-container or full-VM fallback.
        WINDOWS_HYPERV_CONTAINER = "automata.core/windows-hyperv-container@v1",
    }
}

capability_id_type! {
    /// Provider-neutral container-runtime abilities.
    ContainerFeature {
        /// Workflows can select a job-level container.
        JOB_CONTAINERS = "automata.core/job-containers@v1",
        /// Workflows can create service containers.
        SERVICE_CONTAINERS = "automata.core/service-containers@v1",
        /// Container-based actions can execute.
        CONTAINER_ACTIONS = "automata.core/container-actions@v1",
        /// Service containers can receive stable network aliases.
        NETWORK_ALIASES = "automata.core/network-aliases@v1",
        /// Explicitly privileged containers can execute.
        PRIVILEGED_CONTAINERS = "automata.core/privileged-containers@v1",
        /// A Docker-compatible API is available inside the job boundary.
        DOCKER_COMPATIBLE_API = "automata.core/docker-compatible-api@v1",
        /// BuildKit-compatible image builds are available.
        BUILDKIT = "automata.core/buildkit@v1",
        /// Foreign-architecture containers can execute through emulation.
        ARCHITECTURE_EMULATION = "automata.core/architecture-emulation@v1",
    }
}

capability_id_type! {
    /// Workflow-runtime features implemented by the runner.
    RunnerFeature {
        /// Native shell steps can execute.
        SHELL_STEPS = "automata.core/shell-steps@v1",
        /// JavaScript actions can execute.
        JAVASCRIPT_ACTIONS = "automata.core/javascript-actions@v1",
        /// Composite actions can execute.
        COMPOSITE_ACTIONS = "automata.core/composite-actions@v1",
        /// GitHub-compatible command files are implemented.
        COMMAND_FILES = "automata.core/command-files@v1",
        /// Steps can publish job summaries.
        JOB_SUMMARIES = "automata.core/job-summaries@v1",
        /// Workflows can request OIDC identity tokens.
        OIDC_TOKENS = "automata.core/oidc-tokens@v1",
    }
}
