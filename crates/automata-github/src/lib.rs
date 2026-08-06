//! Hardened production HTTP adapters for GitHub authentication and membership APIs.

#![forbid(unsafe_code)]

mod config;
mod endpoint;
mod pagination;
mod response;

pub use config::{
    GITHUB_API_VERSION, GithubHttpConfigurationError, GithubHttpLimits, GithubTrustedOrigins,
};
pub use endpoint::GithubHttpEndpoint;
