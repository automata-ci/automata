#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Canonical mTLS gRPC transport for shard management and workspace provisioning.
//!
//! Protobuf remains a wire adapter. Callers cannot pass generated DTOs to the
//! application port, and application implementations cannot observe TLS or
//! gRPC values. Every method invocation re-authenticates the peer certificate
//! evidence and authorizes its configured shard and delegated-issuer bindings.

use std::{fmt, sync::Arc};

use automata_ci_core::JobAuthorityProfile;
use automata_ci_provisioning::{
    ApplyGithubProviderConfigurationCommand, ApplyGithubProviderConfigurationResult,
    ApplyWorkspaceEntitlementCommand, ApplyWorkspaceEntitlementResult,
    ApplyWorkspaceGithubRepositoriesCommand, ApplyWorkspaceGithubRepositoriesResult,
    AuthorizedApplyGithubProviderConfiguration, AuthorizedApplyWorkspaceEntitlement,
    AuthorizedApplyWorkspaceGithubRepositories, AuthorizedProvisionWorkspace, ComputeSeconds,
    DelegatedActorIssuer, DisplayName, EntitlementDurationSeconds, EntitlementFailure,
    EntitlementFailureKind, EntitlementRevision, ExternalAccountSubject,
    GithubProviderConfiguration, GithubProviderConfigurationApplier,
    GithubProviderConfigurationFailure, GithubProviderConfigurationFailureKind,
    GithubProviderConfigurationRevision, GithubProviderRepositorySelection,
    GithubProviderSchedulePolicy, GithubProviderSecret, OperationId, ProvisionWorkspaceCommand,
    ProvisionWorkspaceResult, ProvisioningAuthenticationError, ProvisioningFailure,
    ProvisioningFailureKind, ProvisioningWorkloadAuthenticator, ShardId,
    WorkloadAuthenticationEvidence, WorkspaceEntitlementApplier, WorkspaceExecutionEntitlement,
    WorkspaceGithubRepositoriesApplier, WorkspaceGithubRepositoriesFailure,
    WorkspaceGithubRepositoriesFailureKind, WorkspaceGithubRepositoriesRevision, WorkspaceId,
    WorkspaceProvisioner,
};
use automata_ci_store::{
    GithubCheckName, GithubRepositoryName, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceJwtIssuer, ProviderInstallationId,
    ProviderRepositoryId, ProviderRepositoryOwnerId, ProviderRepositoryVisibility,
};
use automata_ci_workflow_service::GithubRunnerPolicy;
use bytes::Bytes;
use prost::Message as _;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_util::sync::CancellationToken;
use tonic::{Code, Request, Response, Status};
use url::Url;
use zeroize::Zeroizing;

#[allow(clippy::all, clippy::pedantic, missing_docs)]
mod wire {
    include!(concat!(env!("OUT_DIR"), "/automata.management.v1.rs"));
}

/// Maximum decoded request and encoded response size for management v1.
pub const MAX_MANAGEMENT_MESSAGE_BYTES: usize = 256 * 1024;

const MAX_CLIENT_CA_PEM_BYTES: usize = 4 * 1024 * 1024;
const MAX_SERVER_CERTIFICATE_PEM_BYTES: usize = 4 * 1024 * 1024;
const MAX_SERVER_PRIVATE_KEY_PEM_BYTES: usize = 1024 * 1024;
const FAILURE_TYPE_URL: &str =
    "type.googleapis.com/automata.management.v1.ProvisionWorkspaceFailure";
const ENTITLEMENT_FAILURE_TYPE_URL: &str =
    "type.googleapis.com/automata.management.v1.ApplyWorkspaceEntitlementFailure";
const PROVIDER_CONFIGURATION_FAILURE_TYPE_URL: &str =
    "type.googleapis.com/automata.management.v1.ApplyGithubProviderConfigurationFailure";
const WORKSPACE_REPOSITORIES_FAILURE_TYPE_URL: &str =
    "type.googleapis.com/automata.management.v1.ApplyWorkspaceGithubRepositoriesFailure";

/// Bounded PEM inputs for an mTLS-only management listener.
pub struct ManagementServerTlsConfig {
    client_trust: Vec<u8>,
    server_certificate: Vec<u8>,
    server_private_key: Zeroizing<Vec<u8>>,
}

impl ManagementServerTlsConfig {
    /// Creates a configuration with an explicit client trust store and identity.
    ///
    /// Tonic/rustls parses and cryptographically validates the documents when
    /// the server starts. Platform roots are never loaded, and omitting a client
    /// certificate is not permitted.
    ///
    /// # Errors
    ///
    /// Rejects empty or unbounded PEM documents before retaining them.
    pub fn new(
        client_ca_pem: impl Into<Vec<u8>>,
        server_certificate_pem: impl Into<Vec<u8>>,
        server_private_key_pem: Zeroizing<Vec<u8>>,
    ) -> Result<Self, ManagementServerConfigurationError> {
        let client_ca_pem = client_ca_pem.into();
        let server_certificate_pem = server_certificate_pem.into();
        if client_ca_pem.is_empty() || client_ca_pem.len() > MAX_CLIENT_CA_PEM_BYTES {
            return Err(ManagementServerConfigurationError::InvalidClientTrust);
        }
        if server_certificate_pem.is_empty()
            || server_certificate_pem.len() > MAX_SERVER_CERTIFICATE_PEM_BYTES
            || server_private_key_pem.is_empty()
            || server_private_key_pem.len() > MAX_SERVER_PRIVATE_KEY_PEM_BYTES
        {
            return Err(ManagementServerConfigurationError::InvalidServerIdentity);
        }
        Ok(Self {
            client_trust: client_ca_pem,
            server_certificate: server_certificate_pem,
            server_private_key: server_private_key_pem,
        })
    }

    fn into_tonic(self) -> tonic::transport::ServerTlsConfig {
        let client_ca = tonic::transport::Certificate::from_pem(self.client_trust);
        let identity = tonic::transport::Identity::from_pem(
            self.server_certificate,
            self.server_private_key.as_slice(),
        );
        tonic::transport::ServerTlsConfig::new()
            .identity(identity)
            .client_ca_root(client_ca)
    }
}

impl fmt::Debug for ManagementServerTlsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagementServerTlsConfig")
            .field("client_trust", &"[REDACTED]")
            .field("server_certificate", &"[REDACTED]")
            .field("server_private_key", &"[REDACTED]")
            .finish()
    }
}

/// Dedicated pre-bound gRPC server for the private management trust domain.
pub struct ManagementGrpcServer {
    listener: TcpListener,
    tls: ManagementServerTlsConfig,
    authenticator: Arc<dyn ProvisioningWorkloadAuthenticator>,
    provisioner: Arc<dyn WorkspaceProvisioner>,
    entitlement_applier: Arc<dyn WorkspaceEntitlementApplier>,
    provider_configuration_applier: Arc<dyn GithubProviderConfigurationApplier>,
    workspace_repositories_applier: Arc<dyn WorkspaceGithubRepositoriesApplier>,
}

impl ManagementGrpcServer {
    /// Creates a server without opening a socket or starting background work.
    pub const fn new(
        listener: TcpListener,
        tls: ManagementServerTlsConfig,
        authenticator: Arc<dyn ProvisioningWorkloadAuthenticator>,
        provisioner: Arc<dyn WorkspaceProvisioner>,
        entitlement_applier: Arc<dyn WorkspaceEntitlementApplier>,
        provider_configuration_applier: Arc<dyn GithubProviderConfigurationApplier>,
        workspace_repositories_applier: Arc<dyn WorkspaceGithubRepositoriesApplier>,
    ) -> Self {
        Self {
            listener,
            tls,
            authenticator,
            provisioner,
            entitlement_applier,
            provider_configuration_applier,
            workspace_repositories_applier,
        }
    }

    /// Serves gRPC until cancellation completes graceful shutdown.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error when TLS configuration or serving fails.
    pub async fn serve(
        self,
        cancellation: CancellationToken,
    ) -> Result<(), ManagementGrpcServerError> {
        let tls = self.tls.into_tonic();
        let adapter = ManagementGrpcAdapter {
            authenticator: self.authenticator,
            provisioner: self.provisioner,
            entitlement_applier: self.entitlement_applier,
            provider_configuration_applier: self.provider_configuration_applier,
            workspace_repositories_applier: self.workspace_repositories_applier,
        };
        let service =
            wire::shard_management_service_server::ShardManagementServiceServer::new(adapter)
                .max_decoding_message_size(MAX_MANAGEMENT_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_MANAGEMENT_MESSAGE_BYTES);
        tonic::transport::Server::builder()
            .tls_config(tls)
            .map_err(|_| ManagementGrpcServerError::InvalidTls)?
            .add_service(service)
            .serve_with_incoming_shutdown(
                TcpListenerStream::new(self.listener),
                cancellation.cancelled_owned(),
            )
            .await
            .map_err(|_| ManagementGrpcServerError::Serve)
    }
}

impl fmt::Debug for ManagementGrpcServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagementGrpcServer")
            .field("local_address", &self.listener.local_addr().ok())
            .field("tls", &self.tls)
            .field("authenticator", &self.authenticator)
            .field("provisioner", &self.provisioner)
            .field("entitlement_applier", &self.entitlement_applier)
            .field(
                "provider_configuration_applier",
                &self.provider_configuration_applier,
            )
            .field(
                "workspace_repositories_applier",
                &self.workspace_repositories_applier,
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct ManagementGrpcAdapter {
    authenticator: Arc<dyn ProvisioningWorkloadAuthenticator>,
    provisioner: Arc<dyn WorkspaceProvisioner>,
    entitlement_applier: Arc<dyn WorkspaceEntitlementApplier>,
    provider_configuration_applier: Arc<dyn GithubProviderConfigurationApplier>,
    workspace_repositories_applier: Arc<dyn WorkspaceGithubRepositoriesApplier>,
}

impl fmt::Debug for ManagementGrpcAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagementGrpcAdapter")
            .field("authenticator", &self.authenticator)
            .field("provisioner", &self.provisioner)
            .field("entitlement_applier", &self.entitlement_applier)
            .field(
                "provider_configuration_applier",
                &self.provider_configuration_applier,
            )
            .field(
                "workspace_repositories_applier",
                &self.workspace_repositories_applier,
            )
            .finish()
    }
}

#[tonic::async_trait]
impl wire::shard_management_service_server::ShardManagementService for ManagementGrpcAdapter {
    async fn provision_workspace(
        &self,
        request: Request<wire::ProvisionWorkspaceRequest>,
    ) -> Result<Response<wire::ProvisionWorkspaceResponse>, Status> {
        let certificates = request
            .peer_certs()
            .ok_or_else(|| Status::unauthenticated("workload authentication is required"))?;
        let evidence = WorkloadAuthenticationEvidence::new(
            certificates
                .iter()
                .map(|certificate| certificate.as_ref().to_vec())
                .collect(),
        )
        .map_err(authentication_status)?;
        let authority = self
            .authenticator
            .authenticate(&evidence)
            .await
            .map_err(authentication_status)?;
        let command = decode_command(request.into_inner()).map_err(|()| {
            contract_status(
                Code::InvalidArgument,
                wire::ProvisionWorkspaceFailureReason::InvalidRequest,
                "workspace provisioning request is invalid",
                None,
            )
        })?;
        let authorized =
            AuthorizedProvisionWorkspace::authorize(authority, command).map_err(|_| {
                contract_status(
                    Code::PermissionDenied,
                    wire::ProvisionWorkspaceFailureReason::Forbidden,
                    "workspace provisioning is outside the workload authority",
                    None,
                )
            })?;
        let expected_operation_id = authorized.command().operation_id();
        let expected_shard_id = authorized.command().shard_id().clone();
        let expected_workspace_id = authorized.command().workspace_id();
        let result = self
            .provisioner
            .provision(authorized)
            .await
            .map_err(|error| provisioning_status(&error))?;
        if result.operation_id() != expected_operation_id
            || result.shard_id() != &expected_shard_id
            || result.workspace_id() != expected_workspace_id
        {
            return Err(contract_status(
                Code::Internal,
                wire::ProvisionWorkspaceFailureReason::InternalError,
                "workspace provisioning returned an inconsistent result",
                None,
            ));
        }
        Ok(Response::new(encode_result(&result)))
    }

    async fn apply_workspace_entitlement(
        &self,
        request: Request<wire::ApplyWorkspaceEntitlementRequest>,
    ) -> Result<Response<wire::ApplyWorkspaceEntitlementResponse>, Status> {
        let certificates = request
            .peer_certs()
            .ok_or_else(|| Status::unauthenticated("workload authentication is required"))?;
        let evidence = WorkloadAuthenticationEvidence::new(
            certificates
                .iter()
                .map(|certificate| certificate.as_ref().to_vec())
                .collect(),
        )
        .map_err(authentication_status)?;
        let authority = self
            .authenticator
            .authenticate(&evidence)
            .await
            .map_err(authentication_status)?;
        let command = decode_entitlement_command(request.into_inner()).map_err(|()| {
            entitlement_contract_status(
                Code::InvalidArgument,
                wire::ApplyWorkspaceEntitlementFailureReason::InvalidRequest,
                "workspace entitlement request is invalid",
            )
        })?;
        let authorized = AuthorizedApplyWorkspaceEntitlement::authorize(authority, command)
            .map_err(|_| {
                entitlement_contract_status(
                    Code::PermissionDenied,
                    wire::ApplyWorkspaceEntitlementFailureReason::Forbidden,
                    "workspace entitlement is outside the workload authority",
                )
            })?;
        let expected_operation_id = authorized.command().operation_id();
        let expected_shard_id = authorized.command().shard_id().clone();
        let expected_workspace_id = authorized.command().workspace_id();
        let expected_revision = authorized.command().revision();
        let result = self
            .entitlement_applier
            .apply(authorized)
            .await
            .map_err(entitlement_status)?;
        if result.operation_id() != expected_operation_id
            || result.shard_id() != &expected_shard_id
            || result.workspace_id() != expected_workspace_id
            || result.revision() != expected_revision
        {
            return Err(entitlement_contract_status(
                Code::Internal,
                wire::ApplyWorkspaceEntitlementFailureReason::InternalError,
                "workspace entitlement application returned an inconsistent result",
            ));
        }
        Ok(Response::new(encode_entitlement_result(&result)))
    }

    async fn apply_github_provider_configuration(
        &self,
        request: Request<wire::ApplyGithubProviderConfigurationRequest>,
    ) -> Result<Response<wire::ApplyGithubProviderConfigurationResponse>, Status> {
        let authority = authenticate_management_request(&self.authenticator, &request).await?;
        let command =
            decode_provider_configuration_command(request.into_inner()).map_err(|()| {
                provider_configuration_contract_status(
                    Code::InvalidArgument,
                    wire::ApplyGithubProviderConfigurationFailureReason::InvalidRequest,
                    "GitHub provider configuration request is invalid",
                )
            })?;
        let authorized = AuthorizedApplyGithubProviderConfiguration::authorize(authority, command)
            .map_err(|_| {
                provider_configuration_contract_status(
                    Code::PermissionDenied,
                    wire::ApplyGithubProviderConfigurationFailureReason::Forbidden,
                    "GitHub provider configuration is outside the workload authority",
                )
            })?;
        let expected_operation_id = authorized.command().operation_id();
        let expected_shard_id = authorized.command().shard_id().clone();
        let expected_revision = authorized.command().revision();
        let result = self
            .provider_configuration_applier
            .apply(authorized)
            .await
            .map_err(|error| provider_configuration_status(&error))?;
        if result.operation_id() != expected_operation_id
            || result.shard_id() != &expected_shard_id
            || result.revision() != expected_revision
        {
            return Err(provider_configuration_contract_status(
                Code::Internal,
                wire::ApplyGithubProviderConfigurationFailureReason::InternalError,
                "GitHub provider configuration returned an inconsistent result",
            ));
        }
        Ok(Response::new(encode_provider_configuration_result(&result)))
    }

    async fn apply_workspace_github_repositories(
        &self,
        request: Request<wire::ApplyWorkspaceGithubRepositoriesRequest>,
    ) -> Result<Response<wire::ApplyWorkspaceGithubRepositoriesResponse>, Status> {
        let authority = authenticate_management_request(&self.authenticator, &request).await?;
        let command =
            decode_workspace_repositories_command(request.into_inner()).map_err(|()| {
                workspace_repositories_contract_status(
                    Code::InvalidArgument,
                    wire::ApplyWorkspaceGithubRepositoriesFailureReason::InvalidRequest,
                    "workspace GitHub repositories request is invalid",
                )
            })?;
        let authorized = AuthorizedApplyWorkspaceGithubRepositories::authorize(authority, command)
            .map_err(|_| {
                workspace_repositories_contract_status(
                    Code::PermissionDenied,
                    wire::ApplyWorkspaceGithubRepositoriesFailureReason::Forbidden,
                    "workspace GitHub repositories are outside the workload authority",
                )
            })?;
        let expected_operation_id = authorized.command().operation_id();
        let expected_shard_id = authorized.command().shard_id().clone();
        let expected_workspace_id = authorized.command().workspace_id();
        let expected_revision = authorized.command().revision();
        let result = self
            .workspace_repositories_applier
            .apply(authorized)
            .await
            .map_err(|error| workspace_repositories_status(&error))?;
        if result.operation_id() != expected_operation_id
            || result.shard_id() != &expected_shard_id
            || result.workspace_id() != expected_workspace_id
            || result.revision() != expected_revision
        {
            return Err(workspace_repositories_contract_status(
                Code::Internal,
                wire::ApplyWorkspaceGithubRepositoriesFailureReason::InternalError,
                "workspace GitHub repositories returned an inconsistent result",
            ));
        }
        Ok(Response::new(encode_workspace_repositories_result(&result)))
    }
}

async fn authenticate_management_request<T>(
    authenticator: &Arc<dyn ProvisioningWorkloadAuthenticator>,
    request: &Request<T>,
) -> Result<automata_ci_provisioning::ProvisioningAuthority, Status> {
    let certificates = request
        .peer_certs()
        .ok_or_else(|| Status::unauthenticated("workload authentication is required"))?;
    let evidence = WorkloadAuthenticationEvidence::new(
        certificates
            .iter()
            .map(|certificate| certificate.as_ref().to_vec())
            .collect(),
    )
    .map_err(authentication_status)?;
    authenticator
        .authenticate(&evidence)
        .await
        .map_err(authentication_status)
}

fn decode_command(
    request: wire::ProvisionWorkspaceRequest,
) -> Result<ProvisionWorkspaceCommand, ()> {
    let workspace = request.workspace.ok_or(())?;
    let initial_owner = request.initial_owner.ok_or(())?;
    Ok(ProvisionWorkspaceCommand::new(
        OperationId::parse(&request.operation_id).map_err(|_| ())?,
        ShardId::new(request.shard_id).map_err(|_| ())?,
        WorkspaceId::parse(&workspace.workspace_id).map_err(|_| ())?,
        DisplayName::new(workspace.display_name).map_err(|_| ())?,
        DelegatedActorIssuer::new(initial_owner.issuer).map_err(|_| ())?,
        ExternalAccountSubject::parse(&initial_owner.subject).map_err(|_| ())?,
        DisplayName::new(initial_owner.display_name).map_err(|_| ())?,
    ))
}

fn encode_result(result: &ProvisionWorkspaceResult) -> wire::ProvisionWorkspaceResponse {
    let provisioned_at = result.provisioned_at();
    wire::ProvisionWorkspaceResponse {
        operation_id: result.operation_id().to_string(),
        shard_id: result.shard_id().as_str().to_owned(),
        workspace_id: result.workspace_id().to_string(),
        initial_owner_principal_id: result.initial_owner_principal_id().to_string(),
        provisioned_at: Some(prost_types::Timestamp {
            seconds: provisioned_at.seconds(),
            nanos: i32::try_from(provisioned_at.nanoseconds())
                .expect("validated nanoseconds fit i32"),
        }),
    }
}

fn decode_entitlement_command(
    request: wire::ApplyWorkspaceEntitlementRequest,
) -> Result<ApplyWorkspaceEntitlementCommand, ()> {
    let execution = request.execution.ok_or(())?.policy.ok_or(())?;
    let execution = match execution {
        wire::workspace_execution_entitlement::Policy::Capped(capped) => {
            let compute_seconds = ComputeSeconds::new(capped.compute_seconds).map_err(|_| ())?;
            let valid_for = capped
                .valid_for
                .map(|duration| {
                    if duration.seconds <= 0 || duration.nanos != 0 {
                        return Err(());
                    }
                    EntitlementDurationSeconds::new(
                        u64::try_from(duration.seconds).map_err(|_| ())?,
                    )
                    .map_err(|_| ())
                })
                .transpose()?;
            WorkspaceExecutionEntitlement::capped(compute_seconds, valid_for)
        }
        wire::workspace_execution_entitlement::Policy::Uncapped(_) => {
            WorkspaceExecutionEntitlement::Uncapped
        }
        wire::workspace_execution_entitlement::Policy::Paused(_) => {
            WorkspaceExecutionEntitlement::Paused
        }
    };
    Ok(ApplyWorkspaceEntitlementCommand::new(
        OperationId::parse(&request.operation_id).map_err(|_| ())?,
        ShardId::new(request.shard_id).map_err(|_| ())?,
        WorkspaceId::parse(&request.workspace_id).map_err(|_| ())?,
        EntitlementRevision::new(request.revision).map_err(|_| ())?,
        execution,
    ))
}

fn encode_entitlement_result(
    result: &ApplyWorkspaceEntitlementResult,
) -> wire::ApplyWorkspaceEntitlementResponse {
    let timestamp =
        |value: automata_ci_provisioning::EntitlementTimestamp| prost_types::Timestamp {
            seconds: value.seconds(),
            nanos: i32::try_from(value.nanoseconds()).expect("validated nanoseconds fit i32"),
        };
    wire::ApplyWorkspaceEntitlementResponse {
        operation_id: result.operation_id().to_string(),
        shard_id: result.shard_id().as_str().to_owned(),
        workspace_id: result.workspace_id().to_string(),
        revision: result.revision().get(),
        applied_at: Some(timestamp(result.applied_at())),
        expires_at: result.expires_at().map(timestamp),
    }
}

fn decode_provider_configuration_command(
    request: wire::ApplyGithubProviderConfigurationRequest,
) -> Result<ApplyGithubProviderConfigurationCommand, ()> {
    let configuration = request.configuration.ok_or(())?;
    let jwt_issuer = match wire::GithubAppJwtIssuer::try_from(configuration.jwt_issuer) {
        Ok(wire::GithubAppJwtIssuer::AppClientId) => GithubServerServiceJwtIssuer::AppClientId,
        Ok(wire::GithubAppJwtIssuer::AppId) => GithubServerServiceJwtIssuer::AppId,
        Ok(wire::GithubAppJwtIssuer::Unspecified) | Err(_) => return Err(()),
    };
    let schedule = configuration.schedule.ok_or(())?;
    let schedule = GithubProviderSchedulePolicy::new(
        i64::try_from(schedule.poll_millis).map_err(|_| ())?,
        i64::try_from(schedule.discovery_claim_millis).map_err(|_| ())?,
        i64::try_from(schedule.fire_claim_millis).map_err(|_| ())?,
        i64::try_from(schedule.retry_millis).map_err(|_| ())?,
        i64::try_from(schedule.staleness_millis).map_err(|_| ())?,
        u16::try_from(schedule.maximum_manifests).map_err(|_| ())?,
        u16::try_from(schedule.maximum_fires_per_pass).map_err(|_| ())?,
    )
    .map_err(|_| ())?;
    let configuration = GithubProviderConfiguration::new(
        Url::parse(&configuration.dashboard_url).map_err(|_| ())?,
        GithubServerServiceAppId::new(configuration.app_id).map_err(|_| ())?,
        GithubServerServiceAppClientId::new(configuration.app_client_id).map_err(|_| ())?,
        jwt_issuer,
        GithubProviderSecret::private_key(configuration.app_private_key_pem).map_err(|_| ())?,
        GithubProviderSecret::webhook(configuration.webhook_secret).map_err(|_| ())?,
        GithubCheckName::new(configuration.check_name).map_err(|_| ())?,
        GithubRunnerPolicy::decode_configuration(&configuration.runner_policy).map_err(|_| ())?,
        schedule,
    )
    .map_err(|_| ())?;
    Ok(ApplyGithubProviderConfigurationCommand::new(
        OperationId::parse(&request.operation_id).map_err(|_| ())?,
        ShardId::new(request.shard_id).map_err(|_| ())?,
        GithubProviderConfigurationRevision::new(request.revision).map_err(|_| ())?,
        configuration,
    ))
}

fn decode_workspace_repositories_command(
    request: wire::ApplyWorkspaceGithubRepositoriesRequest,
) -> Result<ApplyWorkspaceGithubRepositoriesCommand, ()> {
    let repositories = request
        .repositories
        .into_iter()
        .map(|repository| {
            let visibility = match wire::GithubRepositoryVisibility::try_from(repository.visibility)
            {
                Ok(wire::GithubRepositoryVisibility::Public) => {
                    ProviderRepositoryVisibility::Public
                }
                Ok(wire::GithubRepositoryVisibility::Private) => {
                    ProviderRepositoryVisibility::Private
                }
                Ok(wire::GithubRepositoryVisibility::Unspecified) | Err(_) => return Err(()),
            };
            let authority_profile =
                match wire::GithubJobAuthorityProfile::try_from(repository.authority_profile) {
                    Ok(wire::GithubJobAuthorityProfile::Standard) => JobAuthorityProfile::Standard,
                    Ok(wire::GithubJobAuthorityProfile::CredentialFree) => {
                        JobAuthorityProfile::CredentialFree
                    }
                    Ok(wire::GithubJobAuthorityProfile::Unspecified) | Err(_) => return Err(()),
                };
            GithubProviderRepositorySelection::new(
                ProviderInstallationId::new(repository.installation_id).map_err(|_| ())?,
                ProviderRepositoryId::new(repository.repository_id).map_err(|_| ())?,
                ProviderRepositoryOwnerId::new(repository.repository_owner_id).map_err(|_| ())?,
                GithubRepositoryName::new(repository.repository_name).map_err(|_| ())?,
                repository.default_branch,
                visibility,
                authority_profile,
            )
            .map_err(|_| ())
        })
        .collect::<Result<Vec<_>, _>>()?;
    ApplyWorkspaceGithubRepositoriesCommand::new(
        OperationId::parse(&request.operation_id).map_err(|_| ())?,
        ShardId::new(request.shard_id).map_err(|_| ())?,
        WorkspaceId::parse(&request.workspace_id).map_err(|_| ())?,
        WorkspaceGithubRepositoriesRevision::new(request.revision).map_err(|_| ())?,
        repositories,
    )
    .map_err(|_| ())
}

fn encode_provider_configuration_result(
    result: &ApplyGithubProviderConfigurationResult,
) -> wire::ApplyGithubProviderConfigurationResponse {
    let applied_at = result.applied_at();
    wire::ApplyGithubProviderConfigurationResponse {
        operation_id: result.operation_id().to_string(),
        shard_id: result.shard_id().as_str().to_owned(),
        revision: result.revision().get(),
        applied_at: Some(prost_types::Timestamp {
            seconds: applied_at.seconds(),
            nanos: i32::try_from(applied_at.nanoseconds()).expect("validated nanoseconds fit i32"),
        }),
    }
}

fn encode_workspace_repositories_result(
    result: &ApplyWorkspaceGithubRepositoriesResult,
) -> wire::ApplyWorkspaceGithubRepositoriesResponse {
    let applied_at = result.applied_at();
    wire::ApplyWorkspaceGithubRepositoriesResponse {
        operation_id: result.operation_id().to_string(),
        shard_id: result.shard_id().as_str().to_owned(),
        workspace_id: result.workspace_id().to_string(),
        revision: result.revision().get(),
        applied_at: Some(prost_types::Timestamp {
            seconds: applied_at.seconds(),
            nanos: i32::try_from(applied_at.nanoseconds()).expect("validated nanoseconds fit i32"),
        }),
    }
}

fn authentication_status(error: ProvisioningAuthenticationError) -> Status {
    match error {
        ProvisioningAuthenticationError::InvalidEvidence
        | ProvisioningAuthenticationError::Untrusted
        | ProvisioningAuthenticationError::Expired => {
            Status::unauthenticated("workload authentication failed")
        }
        ProvisioningAuthenticationError::Unavailable => {
            Status::unavailable("workload authentication is temporarily unavailable")
        }
    }
}

fn provisioning_status(error: &ProvisioningFailure) -> Status {
    let request_id = error
        .request_id()
        .map(automata_ci_provisioning::ProvisioningRequestId::as_str);
    let (code, reason, message) = match error.kind() {
        ProvisioningFailureKind::OperationConflict => (
            Code::Aborted,
            wire::ProvisionWorkspaceFailureReason::OperationConflict,
            "provisioning operation conflicts with its durable receipt",
        ),
        ProvisioningFailureKind::WorkspaceConflict => (
            Code::AlreadyExists,
            wire::ProvisionWorkspaceFailureReason::WorkspaceConflict,
            "workspace identity is already owned by another operation",
        ),
        ProvisioningFailureKind::PrincipalUnavailable => (
            Code::FailedPrecondition,
            wire::ProvisionWorkspaceFailureReason::PrincipalUnavailable,
            "initial owner principal is unavailable",
        ),
        ProvisioningFailureKind::RateLimited => (
            Code::ResourceExhausted,
            wire::ProvisionWorkspaceFailureReason::RateLimited,
            "workspace provisioning rate is exhausted",
        ),
        ProvisioningFailureKind::Internal => (
            Code::Internal,
            wire::ProvisionWorkspaceFailureReason::InternalError,
            "workspace provisioning failed internally",
        ),
        ProvisioningFailureKind::TemporarilyUnavailable => (
            Code::Unavailable,
            wire::ProvisionWorkspaceFailureReason::TemporarilyUnavailable,
            "workspace provisioning is temporarily unavailable",
        ),
    };
    contract_status(code, reason, message, request_id)
}

fn entitlement_status(error: EntitlementFailure) -> Status {
    let (code, reason, message) = match error.kind() {
        EntitlementFailureKind::OperationConflict => (
            Code::Aborted,
            wire::ApplyWorkspaceEntitlementFailureReason::OperationConflict,
            "entitlement operation conflicts with its durable receipt",
        ),
        EntitlementFailureKind::StaleRevision => (
            Code::FailedPrecondition,
            wire::ApplyWorkspaceEntitlementFailureReason::StaleRevision,
            "entitlement revision is stale",
        ),
        EntitlementFailureKind::WorkspaceUnavailable => (
            Code::PermissionDenied,
            wire::ApplyWorkspaceEntitlementFailureReason::WorkspaceUnavailable,
            "workspace is unavailable to this management authority",
        ),
        EntitlementFailureKind::RateLimited => (
            Code::ResourceExhausted,
            wire::ApplyWorkspaceEntitlementFailureReason::RateLimited,
            "workspace entitlement mutation rate is exhausted",
        ),
        EntitlementFailureKind::Internal => (
            Code::Internal,
            wire::ApplyWorkspaceEntitlementFailureReason::InternalError,
            "workspace entitlement application failed internally",
        ),
        EntitlementFailureKind::TemporarilyUnavailable => (
            Code::Unavailable,
            wire::ApplyWorkspaceEntitlementFailureReason::TemporarilyUnavailable,
            "workspace entitlement application is temporarily unavailable",
        ),
    };
    entitlement_contract_status(code, reason, message)
}

fn provider_configuration_status(error: &GithubProviderConfigurationFailure) -> Status {
    let (code, reason, message) = match error.kind() {
        GithubProviderConfigurationFailureKind::OperationConflict => (
            Code::Aborted,
            wire::ApplyGithubProviderConfigurationFailureReason::OperationConflict,
            "provider configuration operation conflicts with its durable receipt",
        ),
        GithubProviderConfigurationFailureKind::StaleRevision => (
            Code::FailedPrecondition,
            wire::ApplyGithubProviderConfigurationFailureReason::StaleRevision,
            "provider configuration revision is stale",
        ),
        GithubProviderConfigurationFailureKind::Forbidden => (
            Code::PermissionDenied,
            wire::ApplyGithubProviderConfigurationFailureReason::Forbidden,
            "provider configuration is outside the workload authority",
        ),
        GithubProviderConfigurationFailureKind::Internal => (
            Code::Internal,
            wire::ApplyGithubProviderConfigurationFailureReason::InternalError,
            "provider configuration failed internally",
        ),
        GithubProviderConfigurationFailureKind::TemporarilyUnavailable => (
            Code::Unavailable,
            wire::ApplyGithubProviderConfigurationFailureReason::TemporarilyUnavailable,
            "provider configuration is temporarily unavailable",
        ),
    };
    provider_configuration_contract_status(code, reason, message)
}

fn workspace_repositories_status(error: &WorkspaceGithubRepositoriesFailure) -> Status {
    let (code, reason, message) = match error.kind() {
        WorkspaceGithubRepositoriesFailureKind::OperationConflict => (
            Code::Aborted,
            wire::ApplyWorkspaceGithubRepositoriesFailureReason::OperationConflict,
            "workspace repository operation conflicts with its durable receipt",
        ),
        WorkspaceGithubRepositoriesFailureKind::StaleRevision => (
            Code::FailedPrecondition,
            wire::ApplyWorkspaceGithubRepositoriesFailureReason::StaleRevision,
            "workspace repository revision is stale",
        ),
        WorkspaceGithubRepositoriesFailureKind::WorkspaceUnavailable => (
            Code::PermissionDenied,
            wire::ApplyWorkspaceGithubRepositoriesFailureReason::WorkspaceUnavailable,
            "workspace is unavailable to this management authority",
        ),
        WorkspaceGithubRepositoriesFailureKind::ShardRegistryConflict => (
            Code::FailedPrecondition,
            wire::ApplyWorkspaceGithubRepositoriesFailureReason::ShardRegistryConflict,
            "workspace repositories conflict with the shard registry",
        ),
        WorkspaceGithubRepositoriesFailureKind::Internal => (
            Code::Internal,
            wire::ApplyWorkspaceGithubRepositoriesFailureReason::InternalError,
            "workspace repository configuration failed internally",
        ),
        WorkspaceGithubRepositoriesFailureKind::TemporarilyUnavailable => (
            Code::Unavailable,
            wire::ApplyWorkspaceGithubRepositoriesFailureReason::TemporarilyUnavailable,
            "workspace repository configuration is temporarily unavailable",
        ),
    };
    workspace_repositories_contract_status(code, reason, message)
}

fn contract_status(
    code: Code,
    reason: wire::ProvisionWorkspaceFailureReason,
    message: &'static str,
    request_id: Option<&str>,
) -> Status {
    let detail = wire::ProvisionWorkspaceFailure {
        reason: reason as i32,
        request_id: request_id.unwrap_or_default().to_owned(),
    };
    let rich_status = tonic_types::pb::Status {
        code: code as i32,
        message: message.to_owned(),
        details: vec![prost_types::Any {
            type_url: FAILURE_TYPE_URL.to_owned(),
            value: detail.encode_to_vec(),
        }],
    };
    Status::with_details(code, message, Bytes::from(rich_status.encode_to_vec()))
}

fn entitlement_contract_status(
    code: Code,
    reason: wire::ApplyWorkspaceEntitlementFailureReason,
    message: &'static str,
) -> Status {
    let detail = wire::ApplyWorkspaceEntitlementFailure {
        reason: reason as i32,
    };
    let rich_status = tonic_types::pb::Status {
        code: code as i32,
        message: message.to_owned(),
        details: vec![prost_types::Any {
            type_url: ENTITLEMENT_FAILURE_TYPE_URL.to_owned(),
            value: detail.encode_to_vec(),
        }],
    };
    Status::with_details(code, message, Bytes::from(rich_status.encode_to_vec()))
}

fn provider_configuration_contract_status(
    code: Code,
    reason: wire::ApplyGithubProviderConfigurationFailureReason,
    message: &'static str,
) -> Status {
    let detail = wire::ApplyGithubProviderConfigurationFailure {
        reason: reason as i32,
    };
    let rich_status = tonic_types::pb::Status {
        code: code as i32,
        message: message.to_owned(),
        details: vec![prost_types::Any {
            type_url: PROVIDER_CONFIGURATION_FAILURE_TYPE_URL.to_owned(),
            value: detail.encode_to_vec(),
        }],
    };
    Status::with_details(code, message, Bytes::from(rich_status.encode_to_vec()))
}

fn workspace_repositories_contract_status(
    code: Code,
    reason: wire::ApplyWorkspaceGithubRepositoriesFailureReason,
    message: &'static str,
) -> Status {
    let detail = wire::ApplyWorkspaceGithubRepositoriesFailure {
        reason: reason as i32,
    };
    let rich_status = tonic_types::pb::Status {
        code: code as i32,
        message: message.to_owned(),
        details: vec![prost_types::Any {
            type_url: WORKSPACE_REPOSITORIES_FAILURE_TYPE_URL.to_owned(),
            value: detail.encode_to_vec(),
        }],
    };
    Status::with_details(code, message, Bytes::from(rich_status.encode_to_vec()))
}

/// Invalid bounded TLS input supplied by product configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ManagementServerConfigurationError {
    /// The explicit client CA bundle is empty or oversized.
    #[error("management client trust configuration is invalid")]
    InvalidClientTrust,
    /// The server certificate or private key is empty or oversized.
    #[error("management server identity configuration is invalid")]
    InvalidServerIdentity,
}

/// Sanitized management listener startup or serving failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ManagementGrpcServerError {
    /// Tonic/rustls rejected the configured mTLS documents.
    #[error("management gRPC TLS configuration is invalid")]
    InvalidTls,
    /// The management gRPC server stopped with a transport failure.
    #[error("management gRPC server failed")]
    Serve,
}

#[cfg(test)]
mod tests {
    use std::{
        future,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use super::*;
    use automata_ci_provisioning::{
        EntitlementApplicationFuture, EntitlementTimestamp,
        GithubProviderConfigurationApplicationFuture, InitialOwnerPrincipalId, ProvisionedAt,
        ProvisioningAuthenticationFuture, ProvisioningAuthority,
        WorkspaceGithubRepositoriesApplicationFuture, WorkspaceProvisioningFuture,
    };
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose,
    };
    use static_assertions::assert_not_impl_any;
    use tonic::transport::{
        Certificate as TonicCertificate, ClientTlsConfig, Endpoint, Identity as TonicIdentity,
    };

    assert_not_impl_any!(ManagementServerTlsConfig: Clone);

    struct TestIdentity {
        certificate_pem: String,
        private_key_pem: String,
        leaf_der: Vec<u8>,
    }

    struct TestPki {
        root_pem: String,
        server: TestIdentity,
        client: TestIdentity,
    }

    impl TestPki {
        fn new() -> Self {
            let root_key = KeyPair::generate().expect("test CA key");
            let mut root_params =
                CertificateParams::new(Vec::<String>::new()).expect("test CA parameters");
            root_params
                .distinguished_name
                .push(DnType::CommonName, "automata management test root");
            root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let root = CertifiedIssuer::self_signed(root_params, root_key).expect("test CA");
            let server = test_leaf(
                "automata management test server",
                vec!["localhost".to_owned()],
                ExtendedKeyUsagePurpose::ServerAuth,
                &root,
            );
            let client = test_leaf(
                "automata-cloud.test",
                Vec::new(),
                ExtendedKeyUsagePurpose::ClientAuth,
                &root,
            );
            Self {
                root_pem: root.pem(),
                server,
                client,
            }
        }
    }

    fn test_leaf(
        common_name: &str,
        subject_alt_names: Vec<String>,
        purpose: ExtendedKeyUsagePurpose,
        issuer: &CertifiedIssuer<'_, KeyPair>,
    ) -> TestIdentity {
        let key = KeyPair::generate().expect("test leaf key");
        let mut params = CertificateParams::new(subject_alt_names).expect("test leaf parameters");
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.extended_key_usages = vec![purpose];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let certificate = params.signed_by(&key, issuer).expect("test leaf");
        TestIdentity {
            certificate_pem: certificate.pem(),
            private_key_pem: key.serialize_pem(),
            leaf_der: certificate.der().as_ref().to_vec(),
        }
    }

    fn test_authority() -> ProvisioningAuthority {
        ProvisioningAuthority::new(
            automata_ci_provisioning::ProvisioningAuthorityId::new("automata-cloud-production")
                .unwrap(),
            ShardId::new("prod-us-east-1-001").unwrap(),
            DelegatedActorIssuer::new("https://cloud.automata.example").unwrap(),
        )
    }

    #[derive(Debug)]
    struct RecordingAuthenticator {
        authority: ProvisioningAuthority,
        calls: AtomicUsize,
        leaf_der: Mutex<Option<Vec<u8>>>,
    }

    impl RecordingAuthenticator {
        fn new() -> Self {
            Self {
                authority: test_authority(),
                calls: AtomicUsize::new(0),
                leaf_der: Mutex::new(None),
            }
        }
    }

    impl ProvisioningWorkloadAuthenticator for RecordingAuthenticator {
        fn authenticate<'a>(
            &'a self,
            evidence: &'a WorkloadAuthenticationEvidence,
        ) -> ProvisioningAuthenticationFuture<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.leaf_der.lock().expect("leaf lock") =
                Some(evidence.certificate_chain_der()[0].clone());
            Box::pin(future::ready(Ok(self.authority.clone())))
        }
    }

    #[derive(Debug)]
    struct RecordingProvisioner {
        calls: AtomicUsize,
        result: ProvisionWorkspaceResult,
    }

    impl RecordingProvisioner {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                result: ProvisionWorkspaceResult::new(
                    OperationId::parse("55555555-5555-4555-8555-555555555555").unwrap(),
                    ShardId::new("prod-us-east-1-001").unwrap(),
                    WorkspaceId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
                    InitialOwnerPrincipalId::parse("66666666-6666-4666-8666-666666666666").unwrap(),
                    ProvisionedAt::new(1_786_500_000, 0).unwrap(),
                ),
            }
        }
    }

    impl WorkspaceProvisioner for RecordingProvisioner {
        fn provision(
            &self,
            request: AuthorizedProvisionWorkspace,
        ) -> WorkspaceProvisioningFuture<'_> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(
                request.authority().id().as_str(),
                "automata-cloud-production"
            );
            assert_eq!(
                request.command().workspace_id().to_string(),
                "22222222-2222-4222-8222-222222222222"
            );
            Box::pin(future::ready(Ok(self.result.clone())))
        }
    }

    #[derive(Debug)]
    struct RecordingEntitlementApplier {
        calls: AtomicUsize,
        result: ApplyWorkspaceEntitlementResult,
    }

    impl RecordingEntitlementApplier {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                result: ApplyWorkspaceEntitlementResult::new(
                    OperationId::parse("77777777-7777-4777-8777-777777777777").unwrap(),
                    ShardId::new("prod-us-east-1-001").unwrap(),
                    WorkspaceId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
                    EntitlementRevision::new(1).unwrap(),
                    EntitlementTimestamp::new(1_786_500_100, 0).unwrap(),
                    Some(EntitlementTimestamp::new(1_787_104_900, 0).unwrap()),
                ),
            }
        }
    }

    impl WorkspaceEntitlementApplier for RecordingEntitlementApplier {
        fn apply(
            &self,
            request: AuthorizedApplyWorkspaceEntitlement,
        ) -> EntitlementApplicationFuture<'_> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(request.command().revision().get(), 1);
            assert_eq!(
                request.command().execution(),
                WorkspaceExecutionEntitlement::capped(
                    ComputeSeconds::new(6_000).unwrap(),
                    Some(EntitlementDurationSeconds::new(604_800).unwrap())
                )
            );
            Box::pin(future::ready(Ok(self.result.clone())))
        }
    }

    #[derive(Debug)]
    struct UnusedProviderConfigurationApplier;

    impl GithubProviderConfigurationApplier for UnusedProviderConfigurationApplier {
        fn apply(
            &self,
            _request: AuthorizedApplyGithubProviderConfiguration,
        ) -> GithubProviderConfigurationApplicationFuture<'_> {
            Box::pin(future::ready(Err(GithubProviderConfigurationFailure::new(
                GithubProviderConfigurationFailureKind::Internal,
            ))))
        }
    }

    #[derive(Debug)]
    struct UnusedWorkspaceRepositoriesApplier;

    impl WorkspaceGithubRepositoriesApplier for UnusedWorkspaceRepositoriesApplier {
        fn apply(
            &self,
            _request: AuthorizedApplyWorkspaceGithubRepositories,
        ) -> WorkspaceGithubRepositoriesApplicationFuture<'_> {
            Box::pin(future::ready(Err(WorkspaceGithubRepositoriesFailure::new(
                WorkspaceGithubRepositoriesFailureKind::Internal,
            ))))
        }
    }

    fn valid_wire_request() -> wire::ProvisionWorkspaceRequest {
        wire::ProvisionWorkspaceRequest {
            operation_id: "55555555-5555-4555-8555-555555555555".to_owned(),
            shard_id: "prod-us-east-1-001".to_owned(),
            workspace: Some(wire::WorkspaceProvisioningTarget {
                workspace_id: "22222222-2222-4222-8222-222222222222".to_owned(),
                display_name: "Acme Engineering".to_owned(),
            }),
            initial_owner: Some(wire::InitialWorkspaceOwner {
                issuer: "https://cloud.automata.example".to_owned(),
                subject: "11111111-1111-4111-8111-111111111111".to_owned(),
                display_name: "The Octocat".to_owned(),
            }),
        }
    }

    fn valid_entitlement_wire_request() -> wire::ApplyWorkspaceEntitlementRequest {
        wire::ApplyWorkspaceEntitlementRequest {
            operation_id: "77777777-7777-4777-8777-777777777777".to_owned(),
            shard_id: "prod-us-east-1-001".to_owned(),
            workspace_id: "22222222-2222-4222-8222-222222222222".to_owned(),
            revision: 1,
            execution: Some(wire::WorkspaceExecutionEntitlement {
                policy: Some(wire::workspace_execution_entitlement::Policy::Capped(
                    wire::CappedWorkspaceExecution {
                        compute_seconds: 6_000,
                        valid_for: Some(prost_types::Duration {
                            seconds: 604_800,
                            nanos: 0,
                        }),
                    },
                )),
            }),
        }
    }

    fn valid_runner_policy() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "workspace": {"derivation": 1, "root": "/__w", "schema": 1},
            "mappings": [{
                "container_features": ["automata.core/job-containers@v1"],
                "architecture": "x86_64",
                "operating_system": "linux",
                "environment_profile": {
                    "manifest_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
                    "id": "automata.example/ubuntu-24-04"
                },
                "selector": "Ubuntu-24.04"
            }],
            "permissions": {
                "provider_default": {"contents": "read", "packages": "read"},
                "read_all": {"actions":"read","artifact-metadata":"read","attestations":"read","checks":"read","code-quality":"read","contents":"read","deployments":"read","discussions":"read","issues":"read","models":"read","packages":"read","pages":"read","pull-requests":"read","security-events":"read","statuses":"read","vulnerability-alerts":"read"},
                "write_all": {"actions":"write","artifact-metadata":"write","attestations":"write","checks":"write","code-quality":"write","contents":"write","deployments":"write","discussions":"write","id-token":"write","issues":"write","models":"read","packages":"write","pages":"write","pull-requests":"write","security-events":"write","statuses":"write","vulnerability-alerts":"read"}
            },
            "resources": {
                "defaults": {
                    "requests": {"cpu_millis": 100, "memory_bytes": 268_435_456, "ephemeral_disk_bytes": 0, "gpu_count": 0},
                    "limits": {"cpu_millis": 1000, "memory_bytes": 1_073_741_824, "ephemeral_disk_bytes": 0, "gpu_count": 0}
                },
                "minimum_requests": {"cpu_millis": 100, "memory_bytes": 268_435_456, "ephemeral_disk_bytes": 0, "gpu_count": 0},
                "maximum_limits": {"cpu_millis": 4000, "memory_bytes": 8_589_934_592_u64, "ephemeral_disk_bytes": 0, "gpu_count": 0}
            },
            "schema": 1
        }))
        .expect("runner policy JSON")
    }

    fn valid_provider_wire_request() -> wire::ApplyGithubProviderConfigurationRequest {
        wire::ApplyGithubProviderConfigurationRequest {
            operation_id: "88888888-8888-4888-8888-888888888888".to_owned(),
            shard_id: "prod-us-east-1-001".to_owned(),
            revision: 3,
            configuration: Some(wire::GithubProviderConfiguration {
                dashboard_url: "https://cloud.automata.example/".to_owned(),
                app_id: 42,
                app_client_id: "Iv1.automata-provider".to_owned(),
                jwt_issuer: wire::GithubAppJwtIssuer::AppClientId as i32,
                app_private_key_pem: b"test App key material".to_vec(),
                webhook_secret: b"test webhook secret".to_vec(),
                check_name: "Automata CI".to_owned(),
                runner_policy: valid_runner_policy(),
                schedule: Some(wire::GithubProviderSchedulePolicy {
                    poll_millis: 1_000,
                    discovery_claim_millis: 300_000,
                    fire_claim_millis: 300_000,
                    retry_millis: 30_000,
                    staleness_millis: 3_600_000,
                    maximum_manifests: 256,
                    maximum_fires_per_pass: 32,
                }),
            }),
        }
    }

    fn valid_workspace_repositories_wire_request() -> wire::ApplyWorkspaceGithubRepositoriesRequest
    {
        wire::ApplyWorkspaceGithubRepositoriesRequest {
            operation_id: "99999999-9999-4999-8999-999999999999".to_owned(),
            shard_id: "prod-us-east-1-001".to_owned(),
            workspace_id: "22222222-2222-4222-8222-222222222222".to_owned(),
            revision: 2,
            repositories: vec![wire::GithubRepositorySelection {
                installation_id: 100,
                repository_id: 200,
                repository_owner_id: 300,
                repository_name: "octo/repository".to_owned(),
                default_branch: "main".to_owned(),
                visibility: wire::GithubRepositoryVisibility::Public as i32,
                authority_profile: wire::GithubJobAuthorityProfile::CredentialFree as i32,
            }],
        }
    }

    #[test]
    fn wire_request_decodes_only_to_validated_domain_values() {
        let command = decode_command(valid_wire_request()).unwrap();
        assert_eq!(
            command.operation_id().to_string(),
            "55555555-5555-4555-8555-555555555555"
        );
        assert_eq!(command.shard_id().as_str(), "prod-us-east-1-001");
        assert_eq!(
            command.workspace_display_name().as_str(),
            "Acme Engineering"
        );
    }

    #[test]
    fn missing_nested_message_and_noncanonical_uuid_are_invalid() {
        let mut request = valid_wire_request();
        request.workspace = None;
        assert!(decode_command(request).is_err());

        let mut request = valid_wire_request();
        request.operation_id = "55555555555545558555555555555555".to_owned();
        assert!(decode_command(request).is_err());
    }

    #[test]
    fn entitlement_wire_request_decodes_a_workspace_aggregate() {
        let command = decode_entitlement_command(valid_entitlement_wire_request()).unwrap();
        assert_eq!(command.revision().get(), 1);
        assert_eq!(
            command.execution(),
            WorkspaceExecutionEntitlement::capped(
                ComputeSeconds::new(6_000).unwrap(),
                Some(EntitlementDurationSeconds::new(604_800).unwrap())
            )
        );
    }

    #[test]
    fn entitlement_rejects_fractional_or_missing_policy() {
        let mut request = valid_entitlement_wire_request();
        let Some(wire::workspace_execution_entitlement::Policy::Capped(capped)) = request
            .execution
            .as_mut()
            .and_then(|value| value.policy.as_mut())
        else {
            panic!("capped fixture")
        };
        capped.valid_for.as_mut().expect("duration").nanos = 1;
        assert!(decode_entitlement_command(request).is_err());

        let mut request = valid_entitlement_wire_request();
        request.execution = None;
        assert!(decode_entitlement_command(request).is_err());
    }

    #[test]
    fn provider_management_wire_requests_decode_to_validated_complete_state() {
        let provider = decode_provider_configuration_command(valid_provider_wire_request())
            .expect("provider configuration");
        assert_eq!(provider.revision().get(), 3);
        assert_eq!(provider.configuration().app_id().get(), 42);
        assert_eq!(
            provider.configuration().private_key().expose_secret(),
            b"test App key material"
        );

        let repositories =
            decode_workspace_repositories_command(valid_workspace_repositories_wire_request())
                .expect("workspace repositories");
        assert_eq!(repositories.revision().get(), 2);
        assert_eq!(repositories.repositories().len(), 1);
        assert_eq!(repositories.repositories()[0].repository_id().get(), 200);
    }

    #[test]
    fn provider_management_rejects_partial_or_incoherent_state() {
        let mut provider = valid_provider_wire_request();
        provider
            .configuration
            .as_mut()
            .expect("configuration")
            .schedule = None;
        assert!(decode_provider_configuration_command(provider).is_err());

        let mut repositories = valid_workspace_repositories_wire_request();
        repositories.repositories[0].visibility = wire::GithubRepositoryVisibility::Private as i32;
        assert!(decode_workspace_repositories_command(repositories).is_err());
    }

    #[test]
    fn result_encodes_stable_contract_fields() {
        let result = ProvisionWorkspaceResult::new(
            OperationId::parse("55555555-5555-4555-8555-555555555555").unwrap(),
            ShardId::new("prod-us-east-1-001").unwrap(),
            WorkspaceId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
            InitialOwnerPrincipalId::parse("66666666-6666-4666-8666-666666666666").unwrap(),
            ProvisionedAt::new(1_786_500_000, 123_000_000).unwrap(),
        );
        let encoded = encode_result(&result);
        assert_eq!(
            encoded.initial_owner_principal_id,
            "66666666-6666-4666-8666-666666666666"
        );
        assert_eq!(
            encoded.provisioned_at,
            Some(prost_types::Timestamp {
                seconds: 1_786_500_000,
                nanos: 123_000_000,
            })
        );
    }

    #[test]
    fn application_failure_uses_the_richer_error_model() {
        let error = ProvisioningFailure::new(
            ProvisioningFailureKind::WorkspaceConflict,
            Some(automata_ci_provisioning::ProvisioningRequestId::new("request-123").unwrap()),
        );
        let status = provisioning_status(&error);
        assert_eq!(status.code(), Code::AlreadyExists);

        let rich = tonic_types::pb::Status::decode(status.details()).unwrap();
        assert_eq!(rich.code, Code::AlreadyExists as i32);
        assert_eq!(rich.details.len(), 1);
        assert_eq!(rich.details[0].type_url, FAILURE_TYPE_URL);
        let detail =
            wire::ProvisionWorkspaceFailure::decode(rich.details[0].value.as_slice()).unwrap();
        assert_eq!(
            detail.reason,
            wire::ProvisionWorkspaceFailureReason::WorkspaceConflict as i32
        );
        assert_eq!(detail.request_id, "request-123");
    }

    #[test]
    fn tls_configuration_diagnostics_are_redacted() {
        let tls = ManagementServerTlsConfig::new(
            "ca",
            "certificate",
            Zeroizing::new(b"private-key".to_vec()),
        )
        .unwrap();
        let debug = format!("{tls:?}");
        assert!(!debug.contains("private-key"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // One live listener proves rejection and authenticated dispatch.
    async fn mtls_listener_authenticates_and_dispatches_a_valid_rpc() {
        let pki = TestPki::new();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener");
        let address = listener.local_addr().expect("listener address");
        let authenticator = Arc::new(RecordingAuthenticator::new());
        let provisioner = Arc::new(RecordingProvisioner::new());
        let entitlement_applier = Arc::new(RecordingEntitlementApplier::new());
        let server = ManagementGrpcServer::new(
            listener,
            ManagementServerTlsConfig::new(
                pki.root_pem.as_bytes(),
                pki.server.certificate_pem.as_bytes(),
                Zeroizing::new(pki.server.private_key_pem.as_bytes().to_vec()),
            )
            .unwrap(),
            authenticator.clone(),
            provisioner.clone(),
            entitlement_applier.clone(),
            Arc::new(UnusedProviderConfigurationApplier),
            Arc::new(UnusedWorkspaceRepositoriesApplier),
        );
        let cancellation = CancellationToken::new();
        let server_cancellation = cancellation.clone();
        let server_task = tokio::spawn(server.serve(server_cancellation));

        let anonymous_tls = ClientTlsConfig::new()
            .domain_name("localhost")
            .ca_certificate(TonicCertificate::from_pem(pki.root_pem.as_bytes()));
        let anonymous_channel = Endpoint::from_shared(format!("https://{address}"))
            .unwrap()
            .tls_config(anonymous_tls)
            .unwrap()
            .connect()
            .await;
        let anonymous_rejected = if let Ok(channel) = anonymous_channel {
            let mut anonymous = tonic::client::Grpc::new(channel);
            if anonymous.ready().await.is_err() {
                true
            } else {
                let response: Result<Response<wire::ProvisionWorkspaceResponse>, Status> =
                    anonymous
                        .unary(
                            Request::new(valid_wire_request()),
                            tonic::codegen::http::uri::PathAndQuery::from_static(
                                "/automata.management.v1.ShardManagementService/ProvisionWorkspace",
                            ),
                            tonic_prost::ProstCodec::<
                                wire::ProvisionWorkspaceRequest,
                                wire::ProvisionWorkspaceResponse,
                            >::default(),
                        )
                        .await;
                response.is_err()
            }
        } else {
            true
        };
        assert!(anonymous_rejected, "client certificate must be required");
        assert_eq!(authenticator.calls.load(Ordering::SeqCst), 0);

        let client_tls = ClientTlsConfig::new()
            .domain_name("localhost")
            .ca_certificate(TonicCertificate::from_pem(pki.root_pem.as_bytes()))
            .identity(TonicIdentity::from_pem(
                pki.client.certificate_pem.as_bytes(),
                pki.client.private_key_pem.as_bytes(),
            ));
        let channel = Endpoint::from_shared(format!("https://{address}"))
            .unwrap()
            .tls_config(client_tls)
            .unwrap()
            .connect()
            .await
            .expect("mTLS client channel");
        let mut client = tonic::client::Grpc::new(channel);
        client.ready().await.expect("ready gRPC client");
        let path = tonic::codegen::http::uri::PathAndQuery::from_static(
            "/automata.management.v1.ShardManagementService/ProvisionWorkspace",
        );
        let response: Response<wire::ProvisionWorkspaceResponse> = client
            .unary(
                Request::new(valid_wire_request()),
                path,
                tonic_prost::ProstCodec::<
                    wire::ProvisionWorkspaceRequest,
                    wire::ProvisionWorkspaceResponse,
                >::default(),
            )
            .await
            .expect("successful provisioning RPC");
        assert_eq!(
            response.into_inner().initial_owner_principal_id,
            "66666666-6666-4666-8666-666666666666"
        );
        assert_eq!(provisioner.calls.load(Ordering::SeqCst), 1);

        client.ready().await.expect("ready entitlement client");
        let entitlement: Response<wire::ApplyWorkspaceEntitlementResponse> = client
            .unary(
                Request::new(valid_entitlement_wire_request()),
                tonic::codegen::http::uri::PathAndQuery::from_static(
                    "/automata.management.v1.ShardManagementService/ApplyWorkspaceEntitlement",
                ),
                tonic_prost::ProstCodec::<
                    wire::ApplyWorkspaceEntitlementRequest,
                    wire::ApplyWorkspaceEntitlementResponse,
                >::default(),
            )
            .await
            .expect("successful entitlement RPC");
        assert_eq!(entitlement.into_inner().revision, 1);
        assert_eq!(entitlement_applier.calls.load(Ordering::SeqCst), 1);
        assert_eq!(authenticator.calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            *authenticator.leaf_der.lock().expect("leaf lock"),
            Some(pki.client.leaf_der)
        );

        cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(3), server_task)
            .await
            .expect("server shutdown deadline")
            .expect("server task")
            .expect("server result");
    }
}
