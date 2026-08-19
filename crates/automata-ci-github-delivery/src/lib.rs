//! GitHub adapters for Automata's common provider runtime.
//!
//! Webhook authentication, normalization, durable acceptance, processing, and
//! result scheduling are owned by provider-neutral runtime contracts. This
//! crate supplies only GitHub-specific trigger, control, result, schedule, and
//! provider credential behavior behind those contracts.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod common_runtime;
mod result_adapter;
mod schedule;
mod server_credential;
mod trigger_handler;

pub use common_runtime::GithubProviderRuntimeAdapter;
pub use result_adapter::{GithubResultProviderAdapter, GithubResultProviderAdapterError};
pub use schedule::{
    GithubScheduleClock, GithubScheduleService, GithubScheduleServiceConfig,
    GithubScheduleServiceConfigurationError, GithubScheduleServiceError, GithubScheduleServicePass,
    GithubScheduleSourceAuthorities,
};
pub use server_credential::GithubServerServiceCredentialRelease;
pub use trigger_handler::{
    GithubTriggerHandler, GithubWorkflowTriggerHandler, GithubWorkflowTriggerHandlerError,
};
