//! GitHub adapters for Automata's common provider runtime.
//!
//! Webhook authentication, normalization, durable acceptance, processing, and
//! result scheduling are owned by provider-neutral runtime contracts. This
//! crate supplies only GitHub-specific trigger, control, result, schedule, and
//! provider credential behavior behind those contracts.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod checks_presentation;
mod checks_publisher;
mod clock;
mod common_runtime;
mod result_adapter;
mod schedule;
mod server_credential;
mod trigger_handler;

pub use checks_publisher::{
    GithubChecksCredentialProvider, GithubChecksCredentialProviderError,
    GithubChecksCredentialRequest, GithubChecksCredentialValueError, GithubChecksPublisher,
    GithubChecksPublisherConfig, GithubChecksPublisherConfigurationError,
    GithubChecksPublisherError, GithubChecksPublisherOutcome, GithubChecksServerServiceCredential,
};
pub use clock::GithubDeliveryClock;
pub use common_runtime::GithubProviderRuntimeAdapter;
pub use result_adapter::{
    GithubResultCredential, GithubResultCredentialProvider, GithubResultCredentialProviderError,
    GithubResultCredentialRelease, GithubResultCredentialRequest, GithubResultCredentialValueError,
    GithubResultOperation, GithubResultProviderAdapter, GithubResultProviderAdapterError,
};
pub use schedule::{
    GithubScheduleClock, GithubScheduleService, GithubScheduleServiceConfig,
    GithubScheduleServiceConfigurationError, GithubScheduleServiceError, GithubScheduleServicePass,
    GithubScheduleSourceAuthorities, GithubScheduleSourceCredential,
    GithubScheduleSourceCredentialProvider, GithubScheduleSourceCredentialProviderError,
    GithubScheduleSourceCredentialRequest, GithubScheduleSourceCredentialValueError,
};
pub use server_credential::GithubServerServiceCredentialRelease;
pub use trigger_handler::{
    GithubTriggerCredential, GithubTriggerCredentialOperation, GithubTriggerCredentialProvider,
    GithubTriggerCredentialProviderError, GithubTriggerCredentialRelease,
    GithubTriggerCredentialRequest, GithubTriggerCredentialValueError, GithubTriggerHandler,
    GithubWorkflowTriggerHandler, GithubWorkflowTriggerHandlerError,
};
