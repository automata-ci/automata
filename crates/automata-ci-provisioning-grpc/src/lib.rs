#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Canonical mTLS gRPC transport for shard management and tenant provisioning.
//!
//! Protobuf remains a wire adapter. Callers cannot pass generated DTOs to the
//! application port, and application implementations cannot observe TLS or
//! gRPC values. Every method invocation re-authenticates the peer certificate
//! evidence and authorizes its configured shard and delegated-issuer bindings.

use std::{fmt, sync::Arc};

use automata_ci_core::JobAuthorityProfile;
use automata_ci_core::ManagedTenantId;
use automata_ci_provisioning::{
    ApplyGithubProviderConfigurationCommand, ApplyGithubProviderConfigurationResult,
    ApplyGithubProviderRunnerPolicyCommand, ApplyGithubProviderRunnerPolicyResult,
    ApplyTenantEntitlementCommand, ApplyTenantEntitlementResult,
    ApplyTenantGithubRepositoriesCommand, ApplyTenantGithubRepositoriesResult,
    AuthorizedApplyGithubProviderConfiguration, AuthorizedApplyGithubProviderRunnerPolicy,
    AuthorizedApplyTenantEntitlement, AuthorizedApplyTenantGithubRepositories,
    AuthorizedProvisionTenant, ComputeSeconds, DelegatedActorIssuer, DisplayName,
    EntitlementDurationSeconds, EntitlementFailure, EntitlementFailureKind, EntitlementRevision,
    ExternalAccountSubject, GithubProviderConfiguration, GithubProviderConfigurationApplier,
    GithubProviderConfigurationFailure, GithubProviderConfigurationFailureKind,
    GithubProviderConfigurationRevision, GithubProviderRepositorySelection,
    GithubProviderRunnerPolicyApplier, GithubProviderRunnerPolicyFailure,
    GithubProviderRunnerPolicyFailureKind, GithubProviderSchedulePolicy, GithubProviderSecret,
    OperationId, ProvisionTenantCommand, ProvisionTenantResult, ProvisioningAuthenticationError,
    ProvisioningFailure, ProvisioningFailureKind, ProvisioningWorkloadAuthenticator, ShardId,
    TenantEntitlementApplier, TenantExecutionEntitlement, TenantGithubRepositoriesApplier,
    TenantGithubRepositoriesFailure, TenantGithubRepositoriesFailureKind,
    TenantGithubRepositoriesRevision, TenantProvisioner, WorkloadAuthenticationEvidence,
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
const FAILURE_TYPE_URL: &str = "type.googleapis.com/automata.management.v1.ProvisionTenantFailure";
const ENTITLEMENT_FAILURE_TYPE_URL: &str =
    "type.googleapis.com/automata.management.v1.ApplyTenantEntitlementFailure";
const PROVIDER_CONFIGURATION_FAILURE_TYPE_URL: &str =
    "type.googleapis.com/automata.management.v1.ApplyGithubProviderConfigurationFailure";
const RUNNER_POLICY_FAILURE_TYPE_URL: &str =
    "type.googleapis.com/automata.management.v1.ApplyGithubProviderRunnerPolicyFailure";
const TENANT_REPOSITORIES_FAILURE_TYPE_URL: &str =
    "type.googleapis.com/automata.management.v1.ApplyTenantGithubRepositoriesFailure";

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

/// Complete transport-neutral mutation ports served by the management listener.
pub struct ManagementApplicationPorts {
    provisioner: Arc<dyn TenantProvisioner>,
    entitlement_applier: Arc<dyn TenantEntitlementApplier>,
    provider_configuration_applier: Arc<dyn GithubProviderConfigurationApplier>,
    runner_policy_applier: Arc<dyn GithubProviderRunnerPolicyApplier>,
    tenant_repositories_applier: Arc<dyn TenantGithubRepositoriesApplier>,
}

impl ManagementApplicationPorts {
    /// Collects the complete application surface without opening a listener.
    #[must_use]
    pub fn new(
        provisioner: Arc<dyn TenantProvisioner>,
        entitlement_applier: Arc<dyn TenantEntitlementApplier>,
        provider_configuration_applier: Arc<dyn GithubProviderConfigurationApplier>,
        runner_policy_applier: Arc<dyn GithubProviderRunnerPolicyApplier>,
        tenant_repositories_applier: Arc<dyn TenantGithubRepositoriesApplier>,
    ) -> Self {
        Self {
            provisioner,
            entitlement_applier,
            provider_configuration_applier,
            runner_policy_applier,
            tenant_repositories_applier,
        }
    }
}

impl fmt::Debug for ManagementApplicationPorts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagementApplicationPorts")
            .field("provisioner", &self.provisioner)
            .field("entitlement_applier", &self.entitlement_applier)
            .field(
                "provider_configuration_applier",
                &self.provider_configuration_applier,
            )
            .field("runner_policy_applier", &self.runner_policy_applier)
            .field(
                "tenant_repositories_applier",
                &self.tenant_repositories_applier,
            )
            .finish()
    }
}

/// Dedicated pre-bound gRPC server for the private management trust domain.
pub struct ManagementGrpcServer {
    listener: TcpListener,
    tls: ManagementServerTlsConfig,
    authenticator: Arc<dyn ProvisioningWorkloadAuthenticator>,
    provisioner: Arc<dyn TenantProvisioner>,
    entitlement_applier: Arc<dyn TenantEntitlementApplier>,
    provider_configuration_applier: Arc<dyn GithubProviderConfigurationApplier>,
    runner_policy_applier: Arc<dyn GithubProviderRunnerPolicyApplier>,
    tenant_repositories_applier: Arc<dyn TenantGithubRepositoriesApplier>,
}

impl ManagementGrpcServer {
    /// Creates a server without opening a socket or starting background work.
    pub fn new(
        listener: TcpListener,
        tls: ManagementServerTlsConfig,
        authenticator: Arc<dyn ProvisioningWorkloadAuthenticator>,
        ports: ManagementApplicationPorts,
    ) -> Self {
        Self {
            listener,
            tls,
            authenticator,
            provisioner: ports.provisioner,
            entitlement_applier: ports.entitlement_applier,
            provider_configuration_applier: ports.provider_configuration_applier,
            runner_policy_applier: ports.runner_policy_applier,
            tenant_repositories_applier: ports.tenant_repositories_applier,
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
            runner_policy_applier: self.runner_policy_applier,
            tenant_repositories_applier: self.tenant_repositories_applier,
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
            .field("runner_policy_applier", &self.runner_policy_applier)
            .field(
                "tenant_repositories_applier",
                &self.tenant_repositories_applier,
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct ManagementGrpcAdapter {
    authenticator: Arc<dyn ProvisioningWorkloadAuthenticator>,
    provisioner: Arc<dyn TenantProvisioner>,
    entitlement_applier: Arc<dyn TenantEntitlementApplier>,
    provider_configuration_applier: Arc<dyn GithubProviderConfigurationApplier>,
    runner_policy_applier: Arc<dyn GithubProviderRunnerPolicyApplier>,
    tenant_repositories_applier: Arc<dyn TenantGithubRepositoriesApplier>,
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
            .field("runner_policy_applier", &self.runner_policy_applier)
            .field(
                "tenant_repositories_applier",
                &self.tenant_repositories_applier,
            )
            .finish()
    }
}

#[tonic::async_trait]
impl wire::shard_management_service_server::ShardManagementService for ManagementGrpcAdapter {
    async fn provision_tenant(
        &self,
        request: Request<wire::ProvisionTenantRequest>,
    ) -> Result<Response<wire::ProvisionTenantResponse>, Status> {
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
                wire::ProvisionTenantFailureReason::InvalidRequest,
                "tenant provisioning request is invalid",
                None,
            )
        })?;
        let authorized =
            AuthorizedProvisionTenant::authorize(authority, command).map_err(|_| {
                contract_status(
                    Code::PermissionDenied,
                    wire::ProvisionTenantFailureReason::Forbidden,
                    "tenant provisioning is outside the workload authority",
                    None,
                )
            })?;
        let expected_operation_id = authorized.command().operation_id();
        let expected_shard_id = authorized.command().shard_id().clone();
        let expected_tenant_id = authorized.command().tenant_id();
        let result = self
            .provisioner
            .provision(authorized)
            .await
            .map_err(|error| provisioning_status(&error))?;
        if result.operation_id() != expected_operation_id
            || result.shard_id() != &expected_shard_id
            || result.tenant_id() != expected_tenant_id
        {
            return Err(contract_status(
                Code::Internal,
                wire::ProvisionTenantFailureReason::InternalError,
                "tenant provisioning returned an inconsistent result",
                None,
            ));
        }
        Ok(Response::new(encode_result(&result)))
    }

    async fn apply_tenant_entitlement(
        &self,
        request: Request<wire::ApplyTenantEntitlementRequest>,
    ) -> Result<Response<wire::ApplyTenantEntitlementResponse>, Status> {
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
                wire::ApplyTenantEntitlementFailureReason::InvalidRequest,
                "tenant entitlement request is invalid",
            )
        })?;
        let authorized =
            AuthorizedApplyTenantEntitlement::authorize(authority, command).map_err(|_| {
                entitlement_contract_status(
                    Code::PermissionDenied,
                    wire::ApplyTenantEntitlementFailureReason::Forbidden,
                    "tenant entitlement is outside the workload authority",
                )
            })?;
        let expected_operation_id = authorized.command().operation_id();
        let expected_shard_id = authorized.command().shard_id().clone();
        let expected_tenant_id = authorized.command().tenant_id();
        let expected_revision = authorized.command().revision();
        let result = self
            .entitlement_applier
            .apply(authorized)
            .await
            .map_err(entitlement_status)?;
        if result.operation_id() != expected_operation_id
            || result.shard_id() != &expected_shard_id
            || result.tenant_id() != expected_tenant_id
            || result.revision() != expected_revision
        {
            return Err(entitlement_contract_status(
                Code::Internal,
                wire::ApplyTenantEntitlementFailureReason::InternalError,
                "tenant entitlement application returned an inconsistent result",
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

    async fn apply_github_provider_runner_policy(
        &self,
        request: Request<wire::ApplyGithubProviderRunnerPolicyRequest>,
    ) -> Result<Response<wire::ApplyGithubProviderRunnerPolicyResponse>, Status> {
        let authority = authenticate_management_request(&self.authenticator, &request).await?;
        let command = decode_runner_policy_command(request.into_inner()).map_err(|()| {
            runner_policy_contract_status(
                Code::InvalidArgument,
                wire::ApplyGithubProviderRunnerPolicyFailureReason::InvalidRequest,
                "GitHub provider runner-policy request is invalid",
            )
        })?;
        let authorized = AuthorizedApplyGithubProviderRunnerPolicy::authorize(authority, command)
            .map_err(|_| {
            runner_policy_contract_status(
                Code::PermissionDenied,
                wire::ApplyGithubProviderRunnerPolicyFailureReason::Forbidden,
                "GitHub provider runner policy is outside the workload authority",
            )
        })?;
        let expected_operation_id = authorized.command().operation_id();
        let expected_shard_id = authorized.command().shard_id().clone();
        let expected_revision = authorized.command().revision();
        let result = self
            .runner_policy_applier
            .apply(authorized)
            .await
            .map_err(|error| runner_policy_status(&error))?;
        if result.operation_id() != expected_operation_id
            || result.shard_id() != &expected_shard_id
            || result.revision() != expected_revision
        {
            return Err(runner_policy_contract_status(
                Code::Internal,
                wire::ApplyGithubProviderRunnerPolicyFailureReason::InternalError,
                "GitHub provider runner-policy update returned an inconsistent result",
            ));
        }
        Ok(Response::new(encode_runner_policy_result(&result)))
    }

    async fn apply_tenant_github_repositories(
        &self,
        request: Request<wire::ApplyTenantGithubRepositoriesRequest>,
    ) -> Result<Response<wire::ApplyTenantGithubRepositoriesResponse>, Status> {
        let authority = authenticate_management_request(&self.authenticator, &request).await?;
        let command = decode_tenant_repositories_command(request.into_inner()).map_err(|()| {
            tenant_repositories_contract_status(
                Code::InvalidArgument,
                wire::ApplyTenantGithubRepositoriesFailureReason::InvalidRequest,
                "tenant GitHub repositories request is invalid",
            )
        })?;
        let authorized = AuthorizedApplyTenantGithubRepositories::authorize(authority, command)
            .map_err(|_| {
                tenant_repositories_contract_status(
                    Code::PermissionDenied,
                    wire::ApplyTenantGithubRepositoriesFailureReason::Forbidden,
                    "tenant GitHub repositories are outside the workload authority",
                )
            })?;
        let expected_operation_id = authorized.command().operation_id();
        let expected_shard_id = authorized.command().shard_id().clone();
        let expected_tenant_id = authorized.command().tenant_id();
        let expected_revision = authorized.command().revision();
        let result = self
            .tenant_repositories_applier
            .apply(authorized)
            .await
            .map_err(|error| tenant_repositories_status(&error))?;
        if result.operation_id() != expected_operation_id
            || result.shard_id() != &expected_shard_id
            || result.tenant_id() != expected_tenant_id
            || result.revision() != expected_revision
        {
            return Err(tenant_repositories_contract_status(
                Code::Internal,
                wire::ApplyTenantGithubRepositoriesFailureReason::InternalError,
                "tenant GitHub repositories returned an inconsistent result",
            ));
        }
        Ok(Response::new(encode_tenant_repositories_result(&result)))
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

fn decode_command(request: wire::ProvisionTenantRequest) -> Result<ProvisionTenantCommand, ()> {
    let tenant = request.tenant.ok_or(())?;
    let initial_owner = request.initial_owner.ok_or(())?;
    Ok(ProvisionTenantCommand::new(
        OperationId::parse(&request.operation_id).map_err(|_| ())?,
        ShardId::new(request.shard_id).map_err(|_| ())?,
        ManagedTenantId::parse(&tenant.tenant_id).map_err(|_| ())?,
        DisplayName::new(tenant.display_name).map_err(|_| ())?,
        DelegatedActorIssuer::new(initial_owner.issuer).map_err(|_| ())?,
        ExternalAccountSubject::parse(&initial_owner.subject).map_err(|_| ())?,
        DisplayName::new(initial_owner.display_name).map_err(|_| ())?,
    ))
}

fn encode_result(result: &ProvisionTenantResult) -> wire::ProvisionTenantResponse {
    let provisioned_at = result.provisioned_at();
    wire::ProvisionTenantResponse {
        operation_id: result.operation_id().to_string(),
        shard_id: result.shard_id().as_str().to_owned(),
        tenant_id: result.tenant_id().to_string(),
        initial_owner_principal_id: result.initial_owner_principal_id().to_string(),
        provisioned_at: Some(prost_types::Timestamp {
            seconds: provisioned_at.seconds(),
            nanos: i32::try_from(provisioned_at.nanoseconds())
                .expect("validated nanoseconds fit i32"),
        }),
    }
}

fn decode_entitlement_command(
    request: wire::ApplyTenantEntitlementRequest,
) -> Result<ApplyTenantEntitlementCommand, ()> {
    let execution = request.execution.ok_or(())?.policy.ok_or(())?;
    let execution = match execution {
        wire::tenant_execution_entitlement::Policy::Capped(capped) => {
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
            TenantExecutionEntitlement::capped(compute_seconds, valid_for)
        }
        wire::tenant_execution_entitlement::Policy::Uncapped(_) => {
            TenantExecutionEntitlement::Uncapped
        }
        wire::tenant_execution_entitlement::Policy::Paused(_) => TenantExecutionEntitlement::Paused,
    };
    Ok(ApplyTenantEntitlementCommand::new(
        OperationId::parse(&request.operation_id).map_err(|_| ())?,
        ShardId::new(request.shard_id).map_err(|_| ())?,
        ManagedTenantId::parse(&request.tenant_id).map_err(|_| ())?,
        EntitlementRevision::new(request.revision).map_err(|_| ())?,
        execution,
    ))
}

fn encode_entitlement_result(
    result: &ApplyTenantEntitlementResult,
) -> wire::ApplyTenantEntitlementResponse {
    let timestamp =
        |value: automata_ci_provisioning::EntitlementTimestamp| prost_types::Timestamp {
            seconds: value.seconds(),
            nanos: i32::try_from(value.nanoseconds()).expect("validated nanoseconds fit i32"),
        };
    wire::ApplyTenantEntitlementResponse {
        operation_id: result.operation_id().to_string(),
        shard_id: result.shard_id().as_str().to_owned(),
        tenant_id: result.tenant_id().to_string(),
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

fn decode_runner_policy_command(
    request: wire::ApplyGithubProviderRunnerPolicyRequest,
) -> Result<ApplyGithubProviderRunnerPolicyCommand, ()> {
    Ok(ApplyGithubProviderRunnerPolicyCommand::new(
        OperationId::parse(&request.operation_id).map_err(|_| ())?,
        ShardId::new(request.shard_id).map_err(|_| ())?,
        GithubProviderConfigurationRevision::new(request.revision).map_err(|_| ())?,
        GithubRunnerPolicy::decode_configuration(&request.runner_policy).map_err(|_| ())?,
    ))
}

fn decode_tenant_repositories_command(
    request: wire::ApplyTenantGithubRepositoriesRequest,
) -> Result<ApplyTenantGithubRepositoriesCommand, ()> {
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
    ApplyTenantGithubRepositoriesCommand::new(
        OperationId::parse(&request.operation_id).map_err(|_| ())?,
        ShardId::new(request.shard_id).map_err(|_| ())?,
        ManagedTenantId::parse(&request.tenant_id).map_err(|_| ())?,
        TenantGithubRepositoriesRevision::new(request.revision).map_err(|_| ())?,
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

fn encode_runner_policy_result(
    result: &ApplyGithubProviderRunnerPolicyResult,
) -> wire::ApplyGithubProviderRunnerPolicyResponse {
    let applied_at = result.applied_at();
    wire::ApplyGithubProviderRunnerPolicyResponse {
        operation_id: result.operation_id().to_string(),
        shard_id: result.shard_id().as_str().to_owned(),
        revision: result.revision().get(),
        applied_at: Some(prost_types::Timestamp {
            seconds: applied_at.seconds(),
            nanos: i32::try_from(applied_at.nanoseconds()).expect("validated nanoseconds fit i32"),
        }),
    }
}

fn encode_tenant_repositories_result(
    result: &ApplyTenantGithubRepositoriesResult,
) -> wire::ApplyTenantGithubRepositoriesResponse {
    let applied_at = result.applied_at();
    wire::ApplyTenantGithubRepositoriesResponse {
        operation_id: result.operation_id().to_string(),
        shard_id: result.shard_id().as_str().to_owned(),
        tenant_id: result.tenant_id().to_string(),
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
            wire::ProvisionTenantFailureReason::OperationConflict,
            "provisioning operation conflicts with its durable receipt",
        ),
        ProvisioningFailureKind::TenantConflict => (
            Code::AlreadyExists,
            wire::ProvisionTenantFailureReason::TenantConflict,
            "tenant identity is already owned by another operation",
        ),
        ProvisioningFailureKind::PrincipalUnavailable => (
            Code::FailedPrecondition,
            wire::ProvisionTenantFailureReason::PrincipalUnavailable,
            "initial owner principal is unavailable",
        ),
        ProvisioningFailureKind::RateLimited => (
            Code::ResourceExhausted,
            wire::ProvisionTenantFailureReason::RateLimited,
            "tenant provisioning rate is exhausted",
        ),
        ProvisioningFailureKind::Internal => (
            Code::Internal,
            wire::ProvisionTenantFailureReason::InternalError,
            "tenant provisioning failed internally",
        ),
        ProvisioningFailureKind::TemporarilyUnavailable => (
            Code::Unavailable,
            wire::ProvisionTenantFailureReason::TemporarilyUnavailable,
            "tenant provisioning is temporarily unavailable",
        ),
    };
    contract_status(code, reason, message, request_id)
}

fn entitlement_status(error: EntitlementFailure) -> Status {
    let (code, reason, message) = match error.kind() {
        EntitlementFailureKind::OperationConflict => (
            Code::Aborted,
            wire::ApplyTenantEntitlementFailureReason::OperationConflict,
            "entitlement operation conflicts with its durable receipt",
        ),
        EntitlementFailureKind::StaleRevision => (
            Code::FailedPrecondition,
            wire::ApplyTenantEntitlementFailureReason::StaleRevision,
            "entitlement revision is stale",
        ),
        EntitlementFailureKind::TenantUnavailable => (
            Code::PermissionDenied,
            wire::ApplyTenantEntitlementFailureReason::TenantUnavailable,
            "tenant is unavailable to this management authority",
        ),
        EntitlementFailureKind::RateLimited => (
            Code::ResourceExhausted,
            wire::ApplyTenantEntitlementFailureReason::RateLimited,
            "tenant entitlement mutation rate is exhausted",
        ),
        EntitlementFailureKind::Internal => (
            Code::Internal,
            wire::ApplyTenantEntitlementFailureReason::InternalError,
            "tenant entitlement application failed internally",
        ),
        EntitlementFailureKind::TemporarilyUnavailable => (
            Code::Unavailable,
            wire::ApplyTenantEntitlementFailureReason::TemporarilyUnavailable,
            "tenant entitlement application is temporarily unavailable",
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

fn runner_policy_status(error: &GithubProviderRunnerPolicyFailure) -> Status {
    let (code, reason, message) = match error.kind() {
        GithubProviderRunnerPolicyFailureKind::OperationConflict => (
            Code::Aborted,
            wire::ApplyGithubProviderRunnerPolicyFailureReason::OperationConflict,
            "runner-policy operation conflicts with its durable receipt",
        ),
        GithubProviderRunnerPolicyFailureKind::StaleRevision => (
            Code::FailedPrecondition,
            wire::ApplyGithubProviderRunnerPolicyFailureReason::StaleRevision,
            "runner-policy revision is stale",
        ),
        GithubProviderRunnerPolicyFailureKind::ProviderUnavailable => (
            Code::FailedPrecondition,
            wire::ApplyGithubProviderRunnerPolicyFailureReason::ProviderUnavailable,
            "provider configuration must exist before its runner policy can be updated",
        ),
        GithubProviderRunnerPolicyFailureKind::Forbidden => (
            Code::PermissionDenied,
            wire::ApplyGithubProviderRunnerPolicyFailureReason::Forbidden,
            "runner policy is outside the workload authority",
        ),
        GithubProviderRunnerPolicyFailureKind::Internal => (
            Code::Internal,
            wire::ApplyGithubProviderRunnerPolicyFailureReason::InternalError,
            "runner-policy update failed internally",
        ),
        GithubProviderRunnerPolicyFailureKind::TemporarilyUnavailable => (
            Code::Unavailable,
            wire::ApplyGithubProviderRunnerPolicyFailureReason::TemporarilyUnavailable,
            "runner-policy update is temporarily unavailable",
        ),
    };
    runner_policy_contract_status(code, reason, message)
}

fn tenant_repositories_status(error: &TenantGithubRepositoriesFailure) -> Status {
    let (code, reason, message) = match error.kind() {
        TenantGithubRepositoriesFailureKind::OperationConflict => (
            Code::Aborted,
            wire::ApplyTenantGithubRepositoriesFailureReason::OperationConflict,
            "tenant repository operation conflicts with its durable receipt",
        ),
        TenantGithubRepositoriesFailureKind::StaleRevision => (
            Code::FailedPrecondition,
            wire::ApplyTenantGithubRepositoriesFailureReason::StaleRevision,
            "tenant repository revision is stale",
        ),
        TenantGithubRepositoriesFailureKind::TenantUnavailable => (
            Code::PermissionDenied,
            wire::ApplyTenantGithubRepositoriesFailureReason::TenantUnavailable,
            "tenant is unavailable to this management authority",
        ),
        TenantGithubRepositoriesFailureKind::ShardRegistryConflict => (
            Code::FailedPrecondition,
            wire::ApplyTenantGithubRepositoriesFailureReason::ShardRegistryConflict,
            "tenant repositories conflict with the shard registry",
        ),
        TenantGithubRepositoriesFailureKind::Internal => (
            Code::Internal,
            wire::ApplyTenantGithubRepositoriesFailureReason::InternalError,
            "tenant repository configuration failed internally",
        ),
        TenantGithubRepositoriesFailureKind::TemporarilyUnavailable => (
            Code::Unavailable,
            wire::ApplyTenantGithubRepositoriesFailureReason::TemporarilyUnavailable,
            "tenant repository configuration is temporarily unavailable",
        ),
    };
    tenant_repositories_contract_status(code, reason, message)
}

fn contract_status(
    code: Code,
    reason: wire::ProvisionTenantFailureReason,
    message: &'static str,
    request_id: Option<&str>,
) -> Status {
    let detail = wire::ProvisionTenantFailure {
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
    reason: wire::ApplyTenantEntitlementFailureReason,
    message: &'static str,
) -> Status {
    let detail = wire::ApplyTenantEntitlementFailure {
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

fn runner_policy_contract_status(
    code: Code,
    reason: wire::ApplyGithubProviderRunnerPolicyFailureReason,
    message: &'static str,
) -> Status {
    let detail = wire::ApplyGithubProviderRunnerPolicyFailure {
        reason: reason as i32,
    };
    let rich_status = tonic_types::pb::Status {
        code: code as i32,
        message: message.to_owned(),
        details: vec![prost_types::Any {
            type_url: RUNNER_POLICY_FAILURE_TYPE_URL.to_owned(),
            value: detail.encode_to_vec(),
        }],
    };
    Status::with_details(code, message, Bytes::from(rich_status.encode_to_vec()))
}

fn tenant_repositories_contract_status(
    code: Code,
    reason: wire::ApplyTenantGithubRepositoriesFailureReason,
    message: &'static str,
) -> Status {
    let detail = wire::ApplyTenantGithubRepositoriesFailure {
        reason: reason as i32,
    };
    let rich_status = tonic_types::pb::Status {
        code: code as i32,
        message: message.to_owned(),
        details: vec![prost_types::Any {
            type_url: TENANT_REPOSITORIES_FAILURE_TYPE_URL.to_owned(),
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
        TenantGithubRepositoriesApplicationFuture, TenantProvisioningFuture,
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
        result: ProvisionTenantResult,
    }

    impl RecordingProvisioner {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                result: ProvisionTenantResult::new(
                    OperationId::parse("55555555-5555-4555-8555-555555555555").unwrap(),
                    ShardId::new("prod-us-east-1-001").unwrap(),
                    ManagedTenantId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
                    InitialOwnerPrincipalId::parse("66666666-6666-4666-8666-666666666666").unwrap(),
                    ProvisionedAt::new(1_786_500_000, 0).unwrap(),
                ),
            }
        }
    }

    impl TenantProvisioner for RecordingProvisioner {
        fn provision(&self, request: AuthorizedProvisionTenant) -> TenantProvisioningFuture<'_> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(
                request.authority().id().as_str(),
                "automata-cloud-production"
            );
            assert_eq!(
                request.command().tenant_id().to_string(),
                "22222222-2222-4222-8222-222222222222"
            );
            Box::pin(future::ready(Ok(self.result.clone())))
        }
    }

    #[derive(Debug)]
    struct RecordingEntitlementApplier {
        calls: AtomicUsize,
        result: ApplyTenantEntitlementResult,
    }

    impl RecordingEntitlementApplier {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                result: ApplyTenantEntitlementResult::new(
                    OperationId::parse("77777777-7777-4777-8777-777777777777").unwrap(),
                    ShardId::new("prod-us-east-1-001").unwrap(),
                    ManagedTenantId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
                    EntitlementRevision::new(1).unwrap(),
                    EntitlementTimestamp::new(1_786_500_100, 0).unwrap(),
                    Some(EntitlementTimestamp::new(1_787_104_900, 0).unwrap()),
                ),
            }
        }
    }

    impl TenantEntitlementApplier for RecordingEntitlementApplier {
        fn apply(
            &self,
            request: AuthorizedApplyTenantEntitlement,
        ) -> EntitlementApplicationFuture<'_> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(request.command().revision().get(), 1);
            assert_eq!(
                request.command().execution(),
                TenantExecutionEntitlement::capped(
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
    struct RecordingRunnerPolicyApplier {
        calls: AtomicUsize,
        result: ApplyGithubProviderRunnerPolicyResult,
    }

    impl RecordingRunnerPolicyApplier {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                result: ApplyGithubProviderRunnerPolicyResult::new(
                    OperationId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
                    ShardId::new("prod-us-east-1-001").unwrap(),
                    GithubProviderConfigurationRevision::new(4).unwrap(),
                    automata_ci_provisioning::GithubProviderTimestamp::new(1_786_500_000, 0)
                        .unwrap(),
                ),
            }
        }
    }

    impl GithubProviderRunnerPolicyApplier for RecordingRunnerPolicyApplier {
        fn apply(
            &self,
            request: AuthorizedApplyGithubProviderRunnerPolicy,
        ) -> automata_ci_provisioning::GithubProviderRunnerPolicyApplicationFuture<'_> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(request.command().revision().get(), 4);
            Box::pin(future::ready(Ok(self.result.clone())))
        }
    }

    #[derive(Debug)]
    struct UnusedTenantRepositoriesApplier;

    impl TenantGithubRepositoriesApplier for UnusedTenantRepositoriesApplier {
        fn apply(
            &self,
            _request: AuthorizedApplyTenantGithubRepositories,
        ) -> TenantGithubRepositoriesApplicationFuture<'_> {
            Box::pin(future::ready(Err(TenantGithubRepositoriesFailure::new(
                TenantGithubRepositoriesFailureKind::Internal,
            ))))
        }
    }

    fn valid_wire_request() -> wire::ProvisionTenantRequest {
        wire::ProvisionTenantRequest {
            operation_id: "55555555-5555-4555-8555-555555555555".to_owned(),
            shard_id: "prod-us-east-1-001".to_owned(),
            tenant: Some(wire::TenantProvisioningTarget {
                tenant_id: "22222222-2222-4222-8222-222222222222".to_owned(),
                display_name: "Acme Engineering".to_owned(),
            }),
            initial_owner: Some(wire::InitialTenantOwner {
                issuer: "https://cloud.automata.example".to_owned(),
                subject: "11111111-1111-4111-8111-111111111111".to_owned(),
                display_name: "The Octocat".to_owned(),
            }),
        }
    }

    fn valid_entitlement_wire_request() -> wire::ApplyTenantEntitlementRequest {
        wire::ApplyTenantEntitlementRequest {
            operation_id: "77777777-7777-4777-8777-777777777777".to_owned(),
            shard_id: "prod-us-east-1-001".to_owned(),
            tenant_id: "22222222-2222-4222-8222-222222222222".to_owned(),
            revision: 1,
            execution: Some(wire::TenantExecutionEntitlement {
                policy: Some(wire::tenant_execution_entitlement::Policy::Capped(
                    wire::CappedTenantExecution {
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
            "workspace":{"derivation": 1, "root": "/__w", "schema": 1},
            "mappings": [{
                "runner_features": {
                    "schema": 1,
                    "supported": [
                        "automata.core/bash-shell@v1",
                        "automata.core/command-files@v1",
                        "automata.core/composite-actions@v1",
                        "automata.core/default-posix-shell@v1",
                        "automata.core/javascript-actions@v1",
                        "automata.core/job-summaries@v1",
                        "automata.core/local-actions@v1",
                        "automata.core/node24-actions@v1",
                        "automata.core/python-shell@v1",
                        "automata.core/repository-actions@v1",
                        "automata.core/sh-shell@v1",
                        "automata.core/shell-steps@v1"
                    ]
                },
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
            "schema": 2
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

    fn valid_runner_policy_wire_request() -> wire::ApplyGithubProviderRunnerPolicyRequest {
        wire::ApplyGithubProviderRunnerPolicyRequest {
            operation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            shard_id: "prod-us-east-1-001".to_owned(),
            revision: 4,
            runner_policy: valid_runner_policy(),
        }
    }

    fn valid_tenant_repositories_wire_request() -> wire::ApplyTenantGithubRepositoriesRequest {
        wire::ApplyTenantGithubRepositoriesRequest {
            operation_id: "99999999-9999-4999-8999-999999999999".to_owned(),
            shard_id: "prod-us-east-1-001".to_owned(),
            tenant_id: "22222222-2222-4222-8222-222222222222".to_owned(),
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
        assert_eq!(command.tenant_display_name().as_str(), "Acme Engineering");
    }

    #[test]
    fn missing_nested_message_and_noncanonical_uuid_are_invalid() {
        let mut request = valid_wire_request();
        request.tenant = None;
        assert!(decode_command(request).is_err());

        let mut request = valid_wire_request();
        request.operation_id = "55555555555545558555555555555555".to_owned();
        assert!(decode_command(request).is_err());
    }

    #[test]
    fn entitlement_wire_request_decodes_a_tenant_aggregate() {
        let command = decode_entitlement_command(valid_entitlement_wire_request()).unwrap();
        assert_eq!(command.revision().get(), 1);
        assert_eq!(
            command.execution(),
            TenantExecutionEntitlement::capped(
                ComputeSeconds::new(6_000).unwrap(),
                Some(EntitlementDurationSeconds::new(604_800).unwrap())
            )
        );
    }

    #[test]
    fn entitlement_rejects_fractional_or_missing_policy() {
        let mut request = valid_entitlement_wire_request();
        let Some(wire::tenant_execution_entitlement::Policy::Capped(capped)) = request
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

        let policy = decode_runner_policy_command(valid_runner_policy_wire_request())
            .expect("runner-policy update");
        assert_eq!(policy.revision().get(), 4);
        assert_eq!(policy.runner_policy().runtime_policy().mappings().len(), 1);

        let repositories =
            decode_tenant_repositories_command(valid_tenant_repositories_wire_request())
                .expect("tenant repositories");
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

        let mut policy = valid_runner_policy_wire_request();
        policy.runner_policy.clear();
        assert!(decode_runner_policy_command(policy).is_err());

        let mut repositories = valid_tenant_repositories_wire_request();
        repositories.repositories[0].visibility = wire::GithubRepositoryVisibility::Private as i32;
        assert!(decode_tenant_repositories_command(repositories).is_err());
    }

    #[test]
    fn result_encodes_stable_contract_fields() {
        let result = ProvisionTenantResult::new(
            OperationId::parse("55555555-5555-4555-8555-555555555555").unwrap(),
            ShardId::new("prod-us-east-1-001").unwrap(),
            ManagedTenantId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
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
            ProvisioningFailureKind::TenantConflict,
            Some(automata_ci_provisioning::ProvisioningRequestId::new("request-123").unwrap()),
        );
        let status = provisioning_status(&error);
        assert_eq!(status.code(), Code::AlreadyExists);

        let rich = tonic_types::pb::Status::decode(status.details()).unwrap();
        assert_eq!(rich.code, Code::AlreadyExists as i32);
        assert_eq!(rich.details.len(), 1);
        assert_eq!(rich.details[0].type_url, FAILURE_TYPE_URL);
        let detail =
            wire::ProvisionTenantFailure::decode(rich.details[0].value.as_slice()).unwrap();
        assert_eq!(
            detail.reason,
            wire::ProvisionTenantFailureReason::TenantConflict as i32
        );
        assert_eq!(detail.request_id, "request-123");
    }

    #[test]
    fn missing_provider_for_runner_policy_is_a_typed_precondition() {
        let status = runner_policy_status(&GithubProviderRunnerPolicyFailure::new(
            GithubProviderRunnerPolicyFailureKind::ProviderUnavailable,
        ));
        assert_eq!(status.code(), Code::FailedPrecondition);
        let rich = tonic_types::pb::Status::decode(status.details()).unwrap();
        assert_eq!(rich.details[0].type_url, RUNNER_POLICY_FAILURE_TYPE_URL);
        let detail =
            wire::ApplyGithubProviderRunnerPolicyFailure::decode(rich.details[0].value.as_slice())
                .unwrap();
        assert_eq!(
            detail.reason,
            wire::ApplyGithubProviderRunnerPolicyFailureReason::ProviderUnavailable as i32
        );
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
        let runner_policy_applier = Arc::new(RecordingRunnerPolicyApplier::new());
        let server = ManagementGrpcServer::new(
            listener,
            ManagementServerTlsConfig::new(
                pki.root_pem.as_bytes(),
                pki.server.certificate_pem.as_bytes(),
                Zeroizing::new(pki.server.private_key_pem.as_bytes().to_vec()),
            )
            .unwrap(),
            authenticator.clone(),
            ManagementApplicationPorts::new(
                provisioner.clone(),
                entitlement_applier.clone(),
                Arc::new(UnusedProviderConfigurationApplier),
                runner_policy_applier.clone(),
                Arc::new(UnusedTenantRepositoriesApplier),
            ),
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
                let response: Result<Response<wire::ProvisionTenantResponse>, Status> = anonymous
                    .unary(
                        Request::new(valid_wire_request()),
                        tonic::codegen::http::uri::PathAndQuery::from_static(
                            "/automata.management.v1.ShardManagementService/ProvisionTenant",
                        ),
                        tonic_prost::ProstCodec::<
                            wire::ProvisionTenantRequest,
                            wire::ProvisionTenantResponse,
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
            "/automata.management.v1.ShardManagementService/ProvisionTenant",
        );
        let response: Response<wire::ProvisionTenantResponse> = client
            .unary(
                Request::new(valid_wire_request()),
                path,
                tonic_prost::ProstCodec::<
                    wire::ProvisionTenantRequest,
                    wire::ProvisionTenantResponse,
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
        let entitlement: Response<wire::ApplyTenantEntitlementResponse> = client
            .unary(
                Request::new(valid_entitlement_wire_request()),
                tonic::codegen::http::uri::PathAndQuery::from_static(
                    "/automata.management.v1.ShardManagementService/ApplyTenantEntitlement",
                ),
                tonic_prost::ProstCodec::<
                    wire::ApplyTenantEntitlementRequest,
                    wire::ApplyTenantEntitlementResponse,
                >::default(),
            )
            .await
            .expect("successful entitlement RPC");
        assert_eq!(entitlement.into_inner().revision, 1);
        assert_eq!(entitlement_applier.calls.load(Ordering::SeqCst), 1);

        client.ready().await.expect("ready runner-policy client");
        let policy: Response<wire::ApplyGithubProviderRunnerPolicyResponse> = client
            .unary(
                Request::new(valid_runner_policy_wire_request()),
                tonic::codegen::http::uri::PathAndQuery::from_static(
                    "/automata.management.v1.ShardManagementService/ApplyGithubProviderRunnerPolicy",
                ),
                tonic_prost::ProstCodec::<
                    wire::ApplyGithubProviderRunnerPolicyRequest,
                    wire::ApplyGithubProviderRunnerPolicyResponse,
                >::default(),
            )
            .await
            .expect("successful runner-policy RPC");
        assert_eq!(policy.into_inner().revision, 4);
        assert_eq!(runner_policy_applier.calls.load(Ordering::SeqCst), 1);
        assert_eq!(authenticator.calls.load(Ordering::SeqCst), 3);
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
