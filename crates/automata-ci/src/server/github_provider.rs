//! Exact non-secret bootstrap projection for the optional GitHub provider.
//!
//! This module turns one already validated product configuration into the
//! immutable Store manifests and server-service authorities consumed by the
//! delivery pipeline. App-key and webhook fingerprints are derived from the
//! same broker and verifier instances that later perform provider I/O; the
//! authority configuration fingerprint is never accepted as configuration.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Arc,
};

use async_trait::async_trait;
use automata_ci_blob::{BlobKey, BlobPayload, MediaType};
use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_credential_github::{
    GithubAppCredentialBroker, GithubServerServiceCredentialRequestResolver,
    GithubServerServiceResolutionError, ResolvedGithubServerServiceCredentialRequest,
    github_server_service_credential_request,
};
use automata_ci_github::GithubWebhookVerifier;
use automata_ci_github_delivery::GithubDeliveryConnection;
use automata_ci_store::{
    AdmissionObject, BootstrapGithubProviderManifest, BootstrapGithubProviderRepository,
    EnsureGithubServerServiceAuthority, GITHUB_PROVIDER_API_ORIGIN,
    GITHUB_PROVIDER_REST_API_VERSION, GithubProviderManifest, GithubProviderManifestLimits,
    GithubProviderManifestRepository, GithubProviderManifestStoreError, GithubProviderOrigins,
    GithubProviderRunnerPolicyObject, GithubProviderWebhookVerifierFingerprint,
    GithubServerServiceAuthorityId, GithubServerServiceAuthorityIdentity,
    GithubServerServiceAuthorityRepository, GithubServerServiceAuthorityState,
    GithubServerServiceScope, GithubServerServiceStoreError, ObjectKey, ProviderConnectionId,
    ProviderRepositoryVisibility, RegisterWorkflowRuntimePolicy, RepositoryId,
    Sha256Digest as StoreSha256Digest, TenantScope, WorkflowRuntimePolicy,
    WorkflowRuntimePolicyRevision, github_provider_repository_id,
};
use automata_ci_workflow_service::GITHUB_RUNNER_POLICY_MEDIA_TYPE;
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

use super::{GithubProviderAuthorityConfig, GithubProviderConfig, GithubProviderRepositoryConfig};

// foundation-governance: derived-contract owner=integration kind=digest-domain
const AUTHORITY_CONFIGURATION_FINGERPRINT_DOMAIN: &[u8] =
    b"automata-ci/product/github-server-service-configuration/v1\0";

/// Deterministic bootstrap projection of one validated GitHub registry.
///
/// Constructing a plan performs no durable writes and claims no readiness. The
/// plan owns the exact delivery connections while immutable manifests and
/// authority identities are retained in stable installation/repository/scope
/// order.
pub struct GithubProviderBootstrapPlan {
    manifests: Arc<[GithubProviderManifest]>,
    runner_policies: Arc<[BlobPayload]>,
    repositories: Arc<[RepositoryBootstrap]>,
    authorities: Arc<[GithubServerServiceAuthorityIdentity]>,
    connections: Vec<GithubDeliveryConnection>,
    resolver: GithubProviderCredentialRequestResolver,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RuntimePolicyBootstrap {
    tenant: TenantScope,
    repository_id: RepositoryId,
    revision: WorkflowRuntimePolicyRevision,
    policy: WorkflowRuntimePolicy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RepositoryBootstrap {
    runtime_policy: RuntimePolicyBootstrap,
    manifest: GithubProviderManifest,
}

impl GithubProviderBootstrapPlan {
    /// Projects one validated registry using evidence derived by the live
    /// GitHub App broker and shared webhook verifier.
    ///
    /// The broker contributes both the App-key SPKI digest and an exact digest
    /// of its API origin, API version, user agent, exact resource limits, and
    /// transport mode. Each authority fingerprint additionally binds its
    /// closed least-authority scope and the Store's fixed GitHub.com origin and
    /// REST version.
    ///
    /// # Errors
    ///
    /// Returns a sanitized invariant error if validated configuration cannot be
    /// represented by the downstream immutable models.
    pub fn new(
        config: &GithubProviderConfig,
        broker: &GithubAppCredentialBroker,
        verifier: &GithubWebhookVerifier,
    ) -> Result<Self, GithubProviderBootstrapError> {
        let webhook_fingerprint = GithubProviderWebhookVerifierFingerprint::from_sha256(
            StoreSha256Digest::from_bytes(*verifier.fingerprint().as_bytes()),
        )
        .map_err(|_| GithubProviderBootstrapError::InvalidConfiguration)?;
        Self::from_derived_evidence(
            config,
            broker.app_key_spki_sha256(),
            webhook_fingerprint,
            broker.broker_policy_fingerprint(),
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one pass preserves exact repository, manifest, authority, and connection ordering"
    )]
    fn from_derived_evidence(
        config: &GithubProviderConfig,
        app_key_spki_sha256: Sha256Digest,
        webhook_fingerprint: GithubProviderWebhookVerifierFingerprint,
        broker_policy_fingerprint: Sha256Digest,
    ) -> Result<Self, GithubProviderBootstrapError> {
        let mut manifests = Vec::with_capacity(config.repositories().len());
        let mut runner_policies = Vec::with_capacity(config.repositories().len());
        let mut repositories = Vec::with_capacity(config.repositories().len());
        let mut runner_policy_digests = BTreeSet::new();
        let mut authorities = Vec::with_capacity(config.repositories().len() * 2);
        let mut connections = Vec::with_capacity(config.repositories().len());
        let mut connection_ids = BTreeSet::new();
        let mut repository_selectors = BTreeSet::new();
        let mut authority_ids = BTreeSet::new();

        for repository in config.repositories() {
            let connection_id = provider_connection_id(repository)?;
            if !connection_ids.insert(connection_id)
                || !repository_selectors
                    .insert((repository.installation_id(), repository.repository_id()))
            {
                return Err(GithubProviderBootstrapError::DuplicateSelector);
            }

            let (runner_policy_payload, runner_policy) = runner_policy_object(repository)?;
            let runtime_policy = repository.runner_policy().runtime_policy().clone();
            if runner_policy_payload.descriptor().digest().as_bytes()
                != runtime_policy.canonical_digest().as_bytes()
            {
                return Err(GithubProviderBootstrapError::InvalidConfiguration);
            }
            if runner_policy_digests.insert(runner_policy_payload.descriptor().digest()) {
                runner_policies.push(runner_policy_payload);
            }

            let manifest =
                GithubProviderManifest::new_owner_bound_with_workflow_selection_and_git_ref(
                    repository.tenant().clone(),
                    connection_id,
                    repository.installation_id(),
                    repository.repository_id(),
                    repository.repository_owner_id(),
                    repository.repository_name().clone(),
                    repository.visibility(),
                    config.app().app_id(),
                    config.app().client_id().clone(),
                    config.app().jwt_issuer(),
                    app_key_spki_sha256,
                    config.app().configuration_revision(),
                    webhook_fingerprint,
                    config.webhook().verifier_revision(),
                    repository.policy_revision(),
                    repository.authority_profile(),
                    runner_policy,
                    repository.runtime_policy_revision(),
                    runtime_policy.digest(),
                    repository.workflow_selection().clone(),
                    repository.workflow_git_ref().clone(),
                    repository.check_name().clone(),
                    GithubProviderOrigins::github_dot_com(),
                    GithubProviderManifestLimits::github_dot_com_ci(),
                    repository.manifest_revision(),
                );
            if manifest.repository_id().as_uuid().as_bytes()
                != &repository.internal_repository_id().as_bytes()
            {
                return Err(GithubProviderBootstrapError::InvalidConfiguration);
            }

            repositories.push(RepositoryBootstrap {
                runtime_policy: RuntimePolicyBootstrap {
                    tenant: repository.tenant().clone(),
                    repository_id: manifest.repository_id(),
                    revision: repository.runtime_policy_revision(),
                    policy: runtime_policy,
                },
                manifest: manifest.clone(),
            });

            let checks = authority_identity(
                config,
                repository,
                repository.checks_write_authority(),
                connection_id,
                GithubServerServiceScope::ChecksWrite,
                app_key_spki_sha256,
                broker_policy_fingerprint,
            )?;
            if !authority_ids.insert(checks.authority_id()) {
                return Err(GithubProviderBootstrapError::DuplicateSelector);
            }
            authorities.push(checks);

            match (
                repository.visibility(),
                repository.private_source_authority(),
            ) {
                (ProviderRepositoryVisibility::Public, None) => {}
                (ProviderRepositoryVisibility::Private, Some(authority)) => {
                    let private_source = authority_identity(
                        config,
                        repository,
                        authority,
                        connection_id,
                        GithubServerServiceScope::PrivateRepositorySourceRead,
                        app_key_spki_sha256,
                        broker_policy_fingerprint,
                    )?;
                    if !authority_ids.insert(private_source.authority_id()) {
                        return Err(GithubProviderBootstrapError::DuplicateSelector);
                    }
                    authorities.push(private_source);
                }
                _ => return Err(GithubProviderBootstrapError::InvalidConfiguration),
            }

            let (owner, name) = repository
                .repository_name()
                .as_str()
                .split_once('/')
                .ok_or(GithubProviderBootstrapError::InvalidConfiguration)?;
            connections.push(
                GithubDeliveryConnection::new(
                    repository.tenant().clone(),
                    connection_id,
                    repository.installation_id(),
                    repository.repository_id(),
                    repository.repository_owner_id(),
                    repository.visibility(),
                    owner,
                    name,
                )
                .and_then(|connection| {
                    connection
                        .with_default_branch_ref(repository.cache_repository().default_branch_ref())
                })
                .map_err(|_| GithubProviderBootstrapError::InvalidConfiguration)?,
            );
            manifests.push(manifest);
        }

        let resolver = GithubProviderCredentialRequestResolver::new(&authorities)?;
        Ok(Self {
            manifests: manifests.into(),
            runner_policies: runner_policies.into(),
            repositories: repositories.into(),
            authorities: authorities.into(),
            connections,
            resolver,
        })
    }

    /// Returns exact desired manifests in stable numeric repository order.
    #[must_use]
    pub fn manifests(&self) -> &[GithubProviderManifest] {
        &self.manifests
    }

    /// Returns canonical runner-policy blobs in stable first-use order.
    #[must_use]
    pub fn runner_policies(&self) -> &[BlobPayload] {
        &self.runner_policies
    }

    /// Returns exact desired authorities in stable repository then scope order.
    #[must_use]
    pub fn authorities(&self) -> &[GithubServerServiceAuthorityIdentity] {
        &self.authorities
    }

    /// Returns exact webhook delivery connections in stable repository order.
    #[must_use]
    pub fn connections(&self) -> &[GithubDeliveryConnection] {
        &self.connections
    }

    /// Consumes the projection and transfers its exact connection registry.
    ///
    /// Product composition calls this only after [`Self::bootstrap`] returned a
    /// complete readiness value. The delivery connection type is deliberately
    /// non-cloneable, so transfer cannot accidentally fork two mutable ingress
    /// registries from one projected configuration.
    #[must_use]
    pub fn into_connections(self) -> Vec<GithubDeliveryConnection> {
        self.connections
    }

    /// Converges every manifest and authority against one Store adapter.
    ///
    /// Authority identities are inspected before the first write, so known
    /// immutable authority drift cannot leave earlier manifests newly applied.
    /// The Store remains the arbiter for valid manifest succession. A readiness
    /// value is returned only after every exact response has been revalidated;
    /// an interrupted convergence can be retried because both Store operations
    /// are exact and idempotent.
    ///
    /// # Errors
    ///
    /// Returns a sanitized unavailable, drift, or inconsistent-state failure.
    pub async fn bootstrap<R>(
        &self,
        repository: &R,
        applied_at: UnixMillis,
    ) -> Result<GithubProviderBootstrapReady, GithubProviderBootstrapError>
    where
        R: GithubProviderManifestRepository + GithubServerServiceAuthorityRepository + ?Sized,
    {
        let target = StoreBootstrapTarget { repository };
        self.bootstrap_with_target(&target, applied_at).await
    }

    async fn bootstrap_with_target<T>(
        &self,
        target: &T,
        applied_at: UnixMillis,
    ) -> Result<GithubProviderBootstrapReady, GithubProviderBootstrapError>
    where
        T: GithubProviderBootstrapTarget + ?Sized,
    {
        if applied_at.get() < 0 {
            return Err(GithubProviderBootstrapError::InvalidConfiguration);
        }

        let mut existing_authorities = Vec::with_capacity(self.authorities.len());
        for authority in self.authorities.iter() {
            existing_authorities.push(target.inspect_authority(authority).await?);
        }

        let mut manifest_replays = 0_usize;
        let mut runtime_policy_replays = 0_usize;
        for repository in self.repositories.iter() {
            let (runtime_policy_replay, manifest_replay) =
                target.bootstrap_repository(repository, applied_at).await?;
            if runtime_policy_replay {
                runtime_policy_replays += 1;
            }
            if manifest_replay {
                manifest_replays += 1;
            }
        }

        let mut authority_replays = 0_usize;
        for (authority, exists) in self.authorities.iter().zip(existing_authorities) {
            if exists || target.ensure_authority(authority, applied_at).await? {
                authority_replays += 1;
            }
        }

        Ok(GithubProviderBootstrapReady {
            manifest_count: self.manifests.len(),
            manifest_replay_count: manifest_replays,
            runtime_policy_count: self.repositories.len(),
            runtime_policy_replay_count: runtime_policy_replays,
            authority_count: self.authorities.len(),
            authority_replay_count: authority_replays,
            resolver: self.resolver.clone(),
        })
    }
}

impl fmt::Debug for GithubProviderBootstrapPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubProviderBootstrapPlan")
            .field("manifest_count", &self.manifests.len())
            .field("runner_policy_count", &self.runner_policies.len())
            .field("runtime_policy_count", &self.repositories.len())
            .field("authority_count", &self.authorities.len())
            .field("connection_count", &self.connections.len())
            .field("resolver", &self.resolver)
            .finish()
    }
}

/// Proof that one complete projected registry converged without partial
/// readiness.
#[derive(Clone)]
pub struct GithubProviderBootstrapReady {
    manifest_count: usize,
    manifest_replay_count: usize,
    runtime_policy_count: usize,
    runtime_policy_replay_count: usize,
    authority_count: usize,
    authority_replay_count: usize,
    resolver: GithubProviderCredentialRequestResolver,
}

impl GithubProviderBootstrapReady {
    /// Returns the number of exact current manifests.
    #[must_use]
    pub const fn manifest_count(&self) -> usize {
        self.manifest_count
    }

    /// Returns how many exact manifests were durable replays.
    #[must_use]
    pub const fn manifest_replay_count(&self) -> usize {
        self.manifest_replay_count
    }

    /// Returns the number of exact relational runtime policies selected.
    #[must_use]
    pub const fn runtime_policy_count(&self) -> usize {
        self.runtime_policy_count
    }

    /// Returns how many exact runtime-policy registrations were durable replays.
    #[must_use]
    pub const fn runtime_policy_replay_count(&self) -> usize {
        self.runtime_policy_replay_count
    }

    /// Returns the number of exact active service authorities.
    #[must_use]
    pub const fn authority_count(&self) -> usize {
        self.authority_count
    }

    /// Returns how many authorities already existed exactly.
    #[must_use]
    pub const fn authority_replay_count(&self) -> usize {
        self.authority_replay_count
    }

    /// Returns the immutable resolver authorized by this complete bootstrap.
    #[must_use]
    pub fn credential_request_resolver(&self) -> GithubProviderCredentialRequestResolver {
        self.resolver.clone()
    }
}

impl fmt::Debug for GithubProviderBootstrapReady {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubProviderBootstrapReady")
            .field("manifest_count", &self.manifest_count)
            .field("manifest_replay_count", &self.manifest_replay_count)
            .field("runtime_policy_count", &self.runtime_policy_count)
            .field(
                "runtime_policy_replay_count",
                &self.runtime_policy_replay_count,
            )
            .field("authority_count", &self.authority_count)
            .field("authority_replay_count", &self.authority_replay_count)
            .field("resolver", &self.resolver)
            .finish()
    }
}

/// Immutable live-route resolver derived from the converged product registry.
///
/// Only exact current identities resolve.
#[derive(Clone)]
pub struct GithubProviderCredentialRequestResolver {
    authorities:
        Arc<BTreeMap<GithubServerServiceAuthorityId, GithubServerServiceAuthorityIdentity>>,
}

impl GithubProviderCredentialRequestResolver {
    pub(super) fn new(
        authorities: &[GithubServerServiceAuthorityIdentity],
    ) -> Result<Self, GithubProviderBootstrapError> {
        let mut by_id = BTreeMap::new();
        for authority in authorities {
            if by_id
                .insert(authority.authority_id(), authority.clone())
                .is_some()
            {
                return Err(GithubProviderBootstrapError::DuplicateSelector);
            }
        }
        Ok(Self {
            authorities: Arc::new(by_id),
        })
    }

    /// Returns the number of exact authority descriptors currently authorized.
    #[must_use]
    pub fn len(&self) -> usize {
        self.authorities.len()
    }

    /// Reports whether no service authority is configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.authorities.is_empty()
    }
}

impl fmt::Debug for GithubProviderCredentialRequestResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubProviderCredentialRequestResolver")
            .field("authority_count", &self.authorities.len())
            .finish()
    }
}

#[async_trait]
impl GithubServerServiceCredentialRequestResolver for GithubProviderCredentialRequestResolver {
    async fn resolve_github_server_service_credential_request(
        &self,
        identity: &GithubServerServiceAuthorityIdentity,
    ) -> Result<
        Option<ResolvedGithubServerServiceCredentialRequest>,
        GithubServerServiceResolutionError,
    > {
        let Some(configured) = self.authorities.get(&identity.authority_id()) else {
            return Ok(None);
        };
        if configured != identity {
            return Ok(None);
        }
        let request = github_server_service_credential_request(identity)
            .map_err(|_| GithubServerServiceResolutionError::Inconsistent)?;
        ResolvedGithubServerServiceCredentialRequest::new(identity.clone(), request)
            .map(Some)
            .map_err(|_| GithubServerServiceResolutionError::Inconsistent)
    }
}

/// Sanitized provider bootstrap failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubProviderBootstrapError {
    /// Validated configuration could not be represented by a downstream model.
    #[error("GitHub provider bootstrap configuration is invalid")]
    InvalidConfiguration,
    /// A duplicate durable identity or numeric selector was encountered.
    #[error("GitHub provider bootstrap contains a duplicate selector")]
    DuplicateSelector,
    /// Existing durable state conflicts with the exact desired configuration.
    #[error("GitHub provider bootstrap conflicts with durable configuration")]
    ConfigurationDrift,
    /// Owner binding needs an explicit sequential configuration revision.
    #[error("GitHub provider owner binding requires incremented manifest and policy revisions")]
    OwnerBindingRevisionRequired,
    /// Durable storage is temporarily unavailable.
    #[error("GitHub provider bootstrap storage is unavailable")]
    Unavailable,
    /// Durable storage returned contradictory or corrupt state.
    #[error("GitHub provider bootstrap storage is inconsistent")]
    InconsistentState,
}

fn runner_policy_object(
    repository: &GithubProviderRepositoryConfig,
) -> Result<(BlobPayload, GithubProviderRunnerPolicyObject), GithubProviderBootstrapError> {
    let encoded = repository
        .runner_policy()
        .canonical_bytes()
        .map_err(|_| GithubProviderBootstrapError::InvalidConfiguration)?;
    let digest = Sha256Digest::from_bytes(Sha256::digest(&encoded).into());
    let key_text = format!("github/runner-policy/v1/{digest}.json");
    let payload = BlobPayload::from_bytes(
        BlobKey::new(key_text.clone())
            .map_err(|_| GithubProviderBootstrapError::InvalidConfiguration)?,
        MediaType::new(GITHUB_RUNNER_POLICY_MEDIA_TYPE)
            .map_err(|_| GithubProviderBootstrapError::InvalidConfiguration)?,
        Bytes::from(encoded),
    );
    let object = AdmissionObject::new(
        payload.descriptor().digest(),
        ObjectKey::new(key_text).map_err(|_| GithubProviderBootstrapError::InvalidConfiguration)?,
        payload.descriptor().size(),
        payload.descriptor().media_type().as_str(),
    )
    .map_err(|_| GithubProviderBootstrapError::InvalidConfiguration)?;
    let object = GithubProviderRunnerPolicyObject::new(object)
        .map_err(|_| GithubProviderBootstrapError::InvalidConfiguration)?;
    Ok((payload, object))
}

fn provider_connection_id(
    repository: &GithubProviderRepositoryConfig,
) -> Result<ProviderConnectionId, GithubProviderBootstrapError> {
    ProviderConnectionId::from_uuid(Uuid::from_bytes(repository.connection_id().as_bytes()))
        .map_err(|_| GithubProviderBootstrapError::InvalidConfiguration)
}

#[allow(clippy::too_many_arguments)]
fn authority_identity(
    config: &GithubProviderConfig,
    repository: &GithubProviderRepositoryConfig,
    authority: &GithubProviderAuthorityConfig,
    connection_id: ProviderConnectionId,
    scope: GithubServerServiceScope,
    app_key_spki_sha256: Sha256Digest,
    broker_policy_fingerprint: Sha256Digest,
) -> Result<GithubServerServiceAuthorityIdentity, GithubProviderBootstrapError> {
    let authority_id = GithubServerServiceAuthorityId::from_uuid(Uuid::from_bytes(
        authority.authority_id().as_bytes(),
    ))
    .map_err(|_| GithubProviderBootstrapError::InvalidConfiguration)?;
    let repository_id =
        github_provider_repository_id(repository.tenant(), repository.repository_id());
    GithubServerServiceAuthorityIdentity::new(
        repository.tenant().clone(),
        authority_id,
        repository_id,
        connection_id,
        repository.installation_id(),
        config.app().app_id(),
        repository.repository_id(),
        repository.repository_name().clone(),
        scope,
        config.app().client_id().clone(),
        config.app().jwt_issuer(),
        app_key_spki_sha256,
        config.app().configuration_revision(),
        authority.policy_revision(),
        authority_configuration_fingerprint(broker_policy_fingerprint, scope),
    )
    .map_err(|_| GithubProviderBootstrapError::InvalidConfiguration)
}

pub(super) fn authority_configuration_fingerprint(
    broker_policy_fingerprint: Sha256Digest,
    scope: GithubServerServiceScope,
) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(AUTHORITY_CONFIGURATION_FINGERPRINT_DOMAIN);
    update_fingerprint_part(&mut digest, broker_policy_fingerprint.as_bytes());
    update_fingerprint_part(&mut digest, GITHUB_PROVIDER_API_ORIGIN.as_bytes());
    update_fingerprint_part(&mut digest, GITHUB_PROVIDER_REST_API_VERSION.as_bytes());
    update_fingerprint_part(&mut digest, scope.as_str().as_bytes());
    update_fingerprint_part(&mut digest, scope.permissions_json().as_bytes());
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn update_fingerprint_part(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

#[async_trait]
trait GithubProviderBootstrapTarget: Send + Sync {
    async fn bootstrap_repository(
        &self,
        repository: &RepositoryBootstrap,
        applied_at: UnixMillis,
    ) -> Result<(bool, bool), GithubProviderBootstrapError>;

    async fn inspect_authority(
        &self,
        identity: &GithubServerServiceAuthorityIdentity,
    ) -> Result<bool, GithubProviderBootstrapError>;

    async fn ensure_authority(
        &self,
        identity: &GithubServerServiceAuthorityIdentity,
        applied_at: UnixMillis,
    ) -> Result<bool, GithubProviderBootstrapError>;
}

struct StoreBootstrapTarget<'a, R: ?Sized> {
    repository: &'a R,
}

#[async_trait]
impl<R> GithubProviderBootstrapTarget for StoreBootstrapTarget<'_, R>
where
    R: GithubProviderManifestRepository + GithubServerServiceAuthorityRepository + ?Sized,
{
    async fn bootstrap_repository(
        &self,
        repository: &RepositoryBootstrap,
        applied_at: UnixMillis,
    ) -> Result<(bool, bool), GithubProviderBootstrapError> {
        let policy = &repository.runtime_policy;
        let request = RegisterWorkflowRuntimePolicy::new(
            policy.tenant.clone(),
            policy.repository_id,
            policy.revision,
            policy.policy.clone(),
            applied_at,
        )
        .map_err(|_| GithubProviderBootstrapError::InvalidConfiguration)?;
        let manifest_request =
            BootstrapGithubProviderManifest::new(repository.manifest.clone(), applied_at)
                .map_err(|_| GithubProviderBootstrapError::InvalidConfiguration)?;
        let request = BootstrapGithubProviderRepository::new(request, manifest_request)
            .map_err(|_| GithubProviderBootstrapError::InvalidConfiguration)?;
        let receipt = self
            .repository
            .bootstrap_github_provider_repository(request)
            .await
            .map_err(|error| map_manifest_store_error(&error))?;
        let policy_receipt = receipt.runtime_policy();
        let manifest_receipt = receipt.manifest();
        if policy_receipt.pin().tenant() != &policy.tenant
            || policy_receipt.pin().repository_id() != policy.repository_id
            || policy_receipt.pin().revision() != policy.revision
            || policy_receipt.pin().digest() != policy.policy.digest()
            || !manifest_receipt.current().is_current()
            || manifest_receipt.current().manifest() != &repository.manifest
        {
            return Err(GithubProviderBootstrapError::InconsistentState);
        }
        Ok((policy_receipt.is_replay(), manifest_receipt.is_replay()))
    }

    async fn inspect_authority(
        &self,
        identity: &GithubServerServiceAuthorityIdentity,
    ) -> Result<bool, GithubProviderBootstrapError> {
        match self
            .repository
            .inspect_github_server_service_authority(identity.tenant(), identity.authority_id())
            .await
        {
            Ok(descriptor) => {
                validate_authority_descriptor(&descriptor, identity)?;
                Ok(true)
            }
            Err(GithubServerServiceStoreError::NotFound) => Ok(false),
            Err(error) => Err(map_authority_store_error(&error)),
        }
    }

    async fn ensure_authority(
        &self,
        identity: &GithubServerServiceAuthorityIdentity,
        applied_at: UnixMillis,
    ) -> Result<bool, GithubProviderBootstrapError> {
        let request = EnsureGithubServerServiceAuthority::new(identity.clone(), applied_at)
            .map_err(|_| GithubProviderBootstrapError::InvalidConfiguration)?;
        match self
            .repository
            .ensure_github_server_service_authority(request)
            .await
        {
            Ok(descriptor) => {
                validate_authority_descriptor(&descriptor, identity)?;
                Ok(false)
            }
            Err(GithubServerServiceStoreError::IdentityConflict) => {
                let descriptor = self
                    .repository
                    .inspect_github_server_service_authority(
                        identity.tenant(),
                        identity.authority_id(),
                    )
                    .await
                    .map_err(|error| map_authority_store_error(&error))?;
                validate_authority_descriptor(&descriptor, identity)?;
                Ok(true)
            }
            Err(error) => Err(map_authority_store_error(&error)),
        }
    }
}

fn validate_authority_descriptor(
    descriptor: &automata_ci_store::GithubServerServiceAuthorityDescriptor,
    identity: &GithubServerServiceAuthorityIdentity,
) -> Result<(), GithubProviderBootstrapError> {
    if descriptor.identity() != identity
        || descriptor.state() != GithubServerServiceAuthorityState::Active
    {
        return Err(GithubProviderBootstrapError::ConfigurationDrift);
    }
    Ok(())
}

fn map_manifest_store_error(
    error: &GithubProviderManifestStoreError,
) -> GithubProviderBootstrapError {
    match error {
        GithubProviderManifestStoreError::Operation(_) => GithubProviderBootstrapError::Unavailable,
        GithubProviderManifestStoreError::ConfigurationDrift => {
            GithubProviderBootstrapError::ConfigurationDrift
        }
        GithubProviderManifestStoreError::OwnerBindingRevisionRequired => {
            GithubProviderBootstrapError::OwnerBindingRevisionRequired
        }
        GithubProviderManifestStoreError::CorruptData
        | GithubProviderManifestStoreError::NotFound => {
            GithubProviderBootstrapError::InconsistentState
        }
    }
}

fn map_authority_store_error(
    error: &GithubServerServiceStoreError,
) -> GithubProviderBootstrapError {
    match error {
        GithubServerServiceStoreError::Operation(_) => GithubProviderBootstrapError::Unavailable,
        GithubServerServiceStoreError::IdentityConflict
        | GithubServerServiceStoreError::ClaimRejected => {
            GithubProviderBootstrapError::ConfigurationDrift
        }
        GithubServerServiceStoreError::CorruptData
        | GithubServerServiceStoreError::NotFound
        | GithubServerServiceStoreError::HandoffRejected
        | GithubServerServiceStoreError::RefreshAlreadyActive
        | GithubServerServiceStoreError::FenceExhausted
        | GithubServerServiceStoreError::RetryLimitReached
        | GithubServerServiceStoreError::HandoffStillLive => {
            GithubProviderBootstrapError::InconsistentState
        }
    }
}

#[cfg(test)]
#[path = "github_provider_tests.rs"]
mod tests;
