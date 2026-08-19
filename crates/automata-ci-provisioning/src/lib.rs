#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Transport-neutral external management for an Automata Core shard.
//!
//! The external control plane authenticates independently of the human it is
//! installing. A transport maps verified workload evidence to a stable
//! [`ProvisioningAuthority`], validates a [`ProvisionTenantCommand`], and
//! constructs an [`AuthorizedProvisionTenant`] before calling the durable
//! [`TenantProvisioner`] port.
//!
//! Certificate rotations do not alter the authority ID. Durable adapters must
//! namespace idempotency by that stable authority and the operation ID, never by
//! a certificate, connection, pod, or replica. Tenant entitlement snapshots
//! and usage-export cursors use the same authority and remain independent of
//! Cloud billing concepts.

mod entitlement;
mod github_provider;
mod model;
mod port;
mod usage;

pub use entitlement::{
    ApplyTenantEntitlementCommand, ApplyTenantEntitlementResult, AuthorizedApplyTenantEntitlement,
    ComputeSeconds, EntitlementAuthorizationError, EntitlementDurationSeconds, EntitlementFailure,
    EntitlementFailureKind, EntitlementRevision, EntitlementTimestamp, EntitlementValueError,
    TenantExecutionEntitlement,
};
pub use github_provider::{
    ApplyGithubProviderConfigurationCommand, ApplyGithubProviderConfigurationResult,
    ApplyGithubProviderRunnerPolicyCommand, ApplyGithubProviderRunnerPolicyResult,
    ApplyTenantGithubRepositoriesCommand, ApplyTenantGithubRepositoriesResult,
    AuthorizedApplyGithubProviderConfiguration, AuthorizedApplyGithubProviderRunnerPolicy,
    AuthorizedApplyTenantGithubRepositories, GithubProviderConfiguration,
    GithubProviderConfigurationFailure, GithubProviderConfigurationFailureKind,
    GithubProviderConfigurationRevision, GithubProviderDesiredState,
    GithubProviderDesiredStateFailure, GithubProviderDesiredStateFailureKind,
    GithubProviderDesiredStateVersion, GithubProviderRepositorySelection,
    GithubProviderRunnerPolicyFailure, GithubProviderRunnerPolicyFailureKind,
    GithubProviderSchedulePolicy, GithubProviderSecret, GithubProviderTimestamp,
    GithubProviderValueError, MAX_GITHUB_PROVIDER_REPOSITORIES,
    TenantGithubRepositoriesDesiredState, TenantGithubRepositoriesFailure,
    TenantGithubRepositoriesFailureKind, TenantGithubRepositoriesRevision,
};
pub use model::{
    AuthorizedProvisionTenant, DelegatedActorIssuer, DisplayName, ExternalAccountSubject,
    InitialOwnerPrincipalId, OperationId, ProvisionTenantCommand, ProvisionTenantResult,
    ProvisionedAt, ProvisioningAuthority, ProvisioningAuthorityId, ProvisioningAuthorizationError,
    ProvisioningFailure, ProvisioningFailureKind, ProvisioningRequestId, ProvisioningValueError,
    ShardId,
};

pub use port::{
    EntitlementApplicationFuture, GithubProviderConfigurationApplicationFuture,
    GithubProviderConfigurationApplier, GithubProviderDesiredStateLoadFuture,
    GithubProviderDesiredStateReader, GithubProviderRunnerPolicyApplicationFuture,
    GithubProviderRunnerPolicyApplier, ProvisioningAuthenticationError,
    ProvisioningAuthenticationFuture, ProvisioningWorkloadAuthenticator, TenantEntitlementApplier,
    TenantGithubRepositoriesApplicationFuture, TenantGithubRepositoriesApplier, TenantProvisioner,
    TenantProvisioningFuture, TenantUsageExporter, UsageExportFuture,
    WorkloadAuthenticationEvidence,
};
pub use usage::{
    AuthorizedListTenantUsage, ConsumedComputeMilliseconds, ListTenantUsageCommand,
    TenantUsageEvent, TenantUsagePage, UsageAttemptId, UsageAuthorizationError, UsageEventId,
    UsageExportCursor, UsageExportFailure, UsageExportFailureKind, UsageExportPageSize,
    UsageTimestamp, UsageValueError,
};
