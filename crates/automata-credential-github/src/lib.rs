//! GitHub App installation-token adapter for workload repository credentials.
//!
//! The App private key is used only in-process to sign a short-lived assertion.
//! It is never returned by the provider-neutral broker boundary. Every token
//! request selects exactly one stable repository ID and an exact permission map;
//! the response is rejected if GitHub reports broader or different scope.

#![forbid(unsafe_code)]

mod adapter;
mod config;
mod response;
mod signer;

pub use adapter::{GithubAppBrokerConstructionError, GithubAppCredentialBroker};
pub use config::{
    GITHUB_API_VERSION, GithubAppConfigurationError, GithubAppCredentialConfig,
    GithubAppHttpLimits, GithubInstallationId,
};
pub use signer::GithubAppKeyError;
