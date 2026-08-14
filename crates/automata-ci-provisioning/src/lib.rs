#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Transport-neutral workspace provisioning for an Automata Core shard.
//!
//! The external control plane authenticates independently of the human it is
//! installing. A transport maps verified workload evidence to a stable
//! [`ProvisioningAuthority`], validates a [`ProvisionWorkspaceCommand`], and
//! constructs an [`AuthorizedProvisionWorkspace`] before calling the durable
//! [`WorkspaceProvisioner`] port.
//!
//! Certificate rotations do not alter the authority ID. Durable adapters must
//! namespace idempotency by that stable authority and the operation ID, never by
//! a certificate, connection, pod, or replica.

mod model;
mod port;

pub use model::{
    AuthorizedProvisionWorkspace, DelegatedActorIssuer, DisplayName, ExternalAccountSubject,
    InitialOwnerPrincipalId, OperationId, ProvisionWorkspaceCommand, ProvisionWorkspaceResult,
    ProvisionedAt, ProvisioningAuthority, ProvisioningAuthorityId, ProvisioningAuthorizationError,
    ProvisioningFailure, ProvisioningFailureKind, ProvisioningRequestId, ProvisioningValueError,
    ShardId, WorkspaceId,
};
pub use port::{
    ProvisioningAuthenticationError, ProvisioningAuthenticationFuture,
    ProvisioningWorkloadAuthenticator, WorkloadAuthenticationEvidence, WorkspaceProvisioner,
    WorkspaceProvisioningFuture,
};
