//! Redacted fixed-relay Docker provider failures.

use thiserror::Error;

/// Stable reason for a fixed-relay Local Docker provider failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalDockerErrorCode {
    /// An Engine API request failed or timed out.
    EngineRequestFailed,
    /// The fixed relay endpoint no longer identifies the initially pinned daemon.
    EngineIdentityChanged,
    /// The fixed relay daemon does not attest the required isolation mode.
    EngineIsolationUnavailable,
    /// The fixed relay architecture differs from the runner advertisement.
    EngineArchitectureMismatch,
    /// Docker returned an incomplete or internally inconsistent response.
    InvalidEngineResponse,
    /// A bounded Docker Engine response exceeded the adapter's hard limit.
    EngineOutputLimitExceeded,
    /// A required digest-pinned local sandbox image is absent.
    ImageUnavailable,
    /// A local sandbox image does not match its pinned digest or engine platform.
    ImageMismatch,
    /// The deterministic anchor name is occupied by a foreign resource.
    IdentityCollision,
    /// An owned-looking anchor does not satisfy the immutable contract.
    InvalidIdentityAnchor,
    /// A container is attached to the identity anchor.
    IdentityAnchorAttached,
    /// A required closed Results network or endpoint does not match its contract.
    ResultsTransportMismatch,
}

impl LocalDockerErrorCode {
    const fn message(self) -> &'static str {
        match self {
            Self::EngineRequestFailed => "the Docker Engine request failed",
            Self::EngineIdentityChanged => {
                "the fixed-relay Docker Engine identity changed after provider connection"
            }
            Self::EngineIsolationUnavailable => {
                "the Docker Engine relay does not attest required user-namespace remapping"
            }
            Self::EngineArchitectureMismatch => {
                "the Docker Engine architecture differs from the runner advertisement"
            }
            Self::InvalidEngineResponse => {
                "the Docker Engine returned an incomplete or inconsistent response"
            }
            Self::EngineOutputLimitExceeded => {
                "the Docker Engine response exceeded its hard output limit"
            }
            Self::ImageUnavailable => {
                "a required digest-pinned local sandbox image is not present in Docker"
            }
            Self::ImageMismatch => {
                "a local sandbox image does not match its pinned digest or engine platform"
            }
            Self::IdentityCollision => {
                "the deterministic installation anchor name is occupied by a foreign resource"
            }
            Self::InvalidIdentityAnchor => {
                "the installation anchor does not satisfy its immutable ownership contract"
            }
            Self::IdentityAnchorAttached => {
                "the installation identity anchor is unexpectedly attached to a container"
            }
            Self::ResultsTransportMismatch => {
                "the local Results transport does not satisfy its closed network contract"
            }
        }
    }
}

/// Redacted failure returned by the fixed-relay Local Docker provider.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("{message}")]
pub struct LocalDockerError {
    code: LocalDockerErrorCode,
    message: &'static str,
}

impl LocalDockerError {
    pub(crate) const fn new(code: LocalDockerErrorCode) -> Self {
        Self {
            code,
            message: code.message(),
        }
    }

    /// Returns the stable machine-readable reason.
    pub const fn code(self) -> LocalDockerErrorCode {
        self.code
    }

    /// Returns a non-sensitive operator-facing explanation.
    pub const fn message(self) -> &'static str {
        self.message
    }
}
