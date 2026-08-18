//! Evaluation-only Docker sandbox provider behind the installation relay.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    future::Future,
    io::{Cursor, Read as _},
    net::Ipv4Addr,
    num::NonZeroU16,
    str::FromStr as _,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use automata_ci_core::{Architecture, Sha256Digest};
use automata_ci_execution::{
    Cancellation, DestroyDisposition, DestroySandbox, EnvironmentProfile, EnvironmentProfileId,
    ExecutionEndpoint, ImmutableImage, NetworkPolicy, NeverCancelled, OperationId,
    OperationOutcome, ProviderCapabilities, ProviderError, ProviderErrorKind, ProviderId,
    ProviderStage, RootFilesystemPolicy, RunnerId, SandboxCapability, SandboxCustody,
    SandboxGeneration, SandboxHandle, SandboxInspection, SandboxLaunch, SandboxPrivilegePolicy,
    SandboxProvider, SandboxRecord, SandboxSpec, SandboxState, TargetPlatform,
};
use automata_ci_sandbox_guest::{
    GUEST_PROTOCOL_VERSION, GuestRequest, GuestResponse, LOCAL_CONTROL_CLIENT,
    LOCAL_CONTROL_DIRECTORY, LOCAL_CONTROL_DIRECTORY_MODE_INITIAL, LOCAL_CONTROL_GID,
    LOCAL_CONTROL_SEAL_UID, LOCAL_CONTROL_TMPFS_BYTES, LOCAL_CONTROL_UID, MAX_GUEST_FRAME_BYTES,
    MAX_LOCAL_GUEST_BINARY_BYTES, decode_frame, encode_frame,
};
use futures::{StreamExt as _, stream};
use sha2::{Digest as _, Sha256};
use tar::{Builder as TarBuilder, EntryType, Header};

use crate::{
    Installation, InstallationBinding, InstallationId, LocalDockerError, LocalDockerErrorCode,
    LocalDockerResultsTransport, LocalImportedImage, MINIMUM_LOCAL_DOCKER_SANDBOX_CPU_MILLIS,
    MINIMUM_LOCAL_DOCKER_SANDBOX_MEMORY_BYTES, MINIMUM_LOCAL_DOCKER_SANDBOX_PIDS,
    normalize_architecture,
    results_transport::{
        ResultsTransitNetworkShape, exact_results_transit_base, results_transit_name,
    },
};

pub(crate) use crate::results_transport::RESULTS_TRANSPORT_SCHEMA;
#[cfg(test)]
use crate::results_transport::{
    LABEL_PLAN_DIGEST, LABEL_RESULTS_TRANSPORT_SCHEMA, results_transit_labels,
};

mod endpoint;
mod engine;

use engine::{
    ContainerDefinition, ContainerNetworkAttachment, CreateNetwork, EngineApiError,
    EngineContainerState, EngineExecRequest, InspectedContainer, InspectedContainerCustody,
    InspectedImage, InspectedNetwork, Ipv4Network, LOCAL_DOCKER_GUEST_ARCHIVE_BYTES,
    LOCAL_DOCKER_GUEST_IMAGE_BINARY, LOCAL_DOCKER_SANDBOX_GUEST_BINARY, NetworkEndpoint,
    PinnedDockerEngine, SandboxEngineApi, connect_host_sandbox_engine,
    connect_relay_sandbox_engine, map_engine_call, resolve_installation_binding,
    verify_installation_identity,
};

use endpoint::LocalDockerEndpoint;

#[cfg(test)]
mod tests;

pub(crate) const LOCAL_DOCKER_PROVIDER_ID: &str = "local-docker-v1";

/// Immutable IDs from the lifecycle's installation-wide discovery union.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LifecycleSiblingContainer {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) kind: String,
}

/// Immutable network IDs from the lifecycle's installation-wide discovery union.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LifecycleSiblingNetwork {
    pub(crate) id: String,
    pub(crate) name: String,
}

const MANAGED_LABEL_PREFIX: &str = "io.automata.local.";
const LABEL_MANAGED: &str = "io.automata.local.managed";
const LABEL_JOB_SCHEMA: &str = "io.automata.local.job-schema";
const LABEL_INSTALLATION_ID: &str = "io.automata.local.installation-id";
const LABEL_INSTALLATION_KEY: &str = "io.automata.local.installation-key";
const LABEL_COMPOSE_PROJECT: &str = "io.automata.local.compose-project";
const LABEL_RUNNER_ID: &str = "io.automata.local.runner-id";
const LABEL_CUSTODY_KIND: &str = "io.automata.local.custody-kind";
const LABEL_SLOT: &str = "io.automata.local.slot";
const LABEL_OPERATION_ID: &str = "io.automata.local.operation-id";
const LABEL_GENERATION: &str = "io.automata.local.generation";
const LABEL_PROFILE: &str = "io.automata.local.profile";
const LABEL_PROFILE_DIGEST: &str = "io.automata.local.profile-sha256";
const LABEL_SPEC_DIGEST: &str = "io.automata.local.spec-sha256";
const LABEL_REALIZED_DIGEST: &str = "io.automata.local.realized-sha256";
const LABEL_RESOURCE_KIND: &str = "io.automata.local.resource-kind";
const MANAGED_VALUE: &str = "true";
const JOB_SCHEMA: &str = "2";
const CUSTODY_ADMISSION: &str = "profile-admission";
const CUSTODY_JOB: &str = "job";
const KIND_JOB: &str = "job-container";
const KIND_GUEST_SOURCE: &str = "guest-source";
const KIND_RESULTS_FRONT: &str = "results-front-network";
const KIND_RESULTS_PROXY: &str = "results-proxy-container";
const RESULTS_ALIAS: &str = "results.automata.invalid";
const RESULTS_PROXY_ENTRYPOINT: &str = "/usr/libexec/automata-ci-service-proxy";
const RESULTS_PROXY_COMMAND: &str = "serve-results-v1";
const RESULTS_PROXY_IMAGE_PROTOCOL_LABEL: &str = "io.automata.service-proxy.protocol-version";
const RESULTS_PROXY_IMAGE_PROTOCOL_VERSION: &str = "2";
const RESULTS_READY_STATUS: &[u8] = b"{\"version\":1,\"mode\":\"results-v1\",\"port\":8081}\n";
const RESULTS_PROXY_MEMORY_BYTES: i64 = 64 * 1_024 * 1_024;
const RESULTS_PROXY_NANO_CPUS: i64 = 250_000_000;
// One accept loop plus, for each of the 32 bounded sessions, one coordinator
// and two directional pumps.
const RESULTS_PROXY_PIDS: i64 = 97;
const RESULTS_PROXY_USER: &str = "65532:65532";
const RESULTS_FRONT_POOL_PREFIX: u8 = 20;
const RESULTS_FRONT_NETWORK_PREFIX: u8 = 29;
const MAX_RESULTS_TRANSIT_CONVERGENCE_ATTEMPTS: usize = 8;
const MAX_RESULTS_TRANSIT_ATTESTATION_CONCURRENCY: usize = 16;
const RESULTS_TRANSPORT_ATTESTATION_TIMEOUT: Duration = Duration::from_secs(30);
const RESULTS_PROXY_READINESS_TIMEOUT: Duration = Duration::from_secs(5);
const RESULTS_PROXY_READINESS_INTERVAL: Duration = Duration::from_millis(25);
const HELPER_MEMORY_BYTES: i64 = 64 * 1024 * 1024;
const HELPER_NANO_CPUS: i64 = 500_000_000;
const HELPER_PIDS: i64 = 32;
const MAX_RESOURCE_LABELS: usize = 256;
const ENGINE_TRANSPORT_OVERHEAD: Duration = Duration::from_secs(5);

fn guest_client_user() -> String {
    format!("{LOCAL_CONTROL_UID}:{LOCAL_CONTROL_GID}")
}

fn guest_seal_user() -> String {
    format!("{LOCAL_CONTROL_SEAL_UID}:{LOCAL_CONTROL_GID}")
}

fn guest_control_tmpfs_options() -> String {
    format!(
        "rw,exec,nosuid,nodev,size={LOCAL_CONTROL_TMPFS_BYTES},mode={LOCAL_CONTROL_DIRECTORY_MODE_INITIAL:04o},uid={LOCAL_CONTROL_SEAL_UID},gid={LOCAL_CONTROL_GID}"
    )
}

fn max_guest_binary_bytes() -> usize {
    usize::try_from(MAX_LOCAL_GUEST_BINARY_BYTES)
        .expect("the protected guest binary ceiling fits usize")
}

const ENDPOINT_CAPABILITIES: [SandboxCapability; 4] = [
    SandboxCapability::Exec,
    SandboxCapability::CopyTo,
    SandboxCapability::CopyFrom,
    SandboxCapability::EnvironmentInjection,
];
// `Administrator` is intentionally the narrow provider-neutral contract: UID
// 0 owns the disposable guest filesystem only inside the daemon-remapped user
// namespace. The realized container drops every Linux capability and enables
// no-new-privileges; this provider does not promise Podman's richer chown or
// identity-switching behavior.
const PROVIDER_CAPABILITIES: [SandboxCapability; 13] = [
    SandboxCapability::WholeJob,
    SandboxCapability::Attach,
    SandboxCapability::Inspect,
    SandboxCapability::Exec,
    SandboxCapability::CopyTo,
    SandboxCapability::CopyFrom,
    SandboxCapability::EnvironmentInjection,
    SandboxCapability::PrivateEgress,
    SandboxCapability::WritableRootFilesystem,
    SandboxCapability::Administrator,
    SandboxCapability::UserNamespace,
    SandboxCapability::ResourceLimits,
    SandboxCapability::ProcessLimits,
];

/// Evaluation-only Docker Engine provider for sibling Linux job containers.
///
/// The provider connects only to the installation relay at
/// `/run/automata-engine/docker.sock`. It never reads `DOCKER_HOST`, pulls an
/// image, accepts a host bind, or exposes an Engine endpoint to a job.
#[derive(Clone)]
pub(super) struct LocalDockerProvider {
    inner: Arc<LocalDockerInner>,
}

struct LocalDockerInner {
    pinned: PinnedDockerEngine,
    engine: Arc<dyn SandboxEngineApi>,
    installation: Installation,
    guest_image: ImmutableImage,
    guest_image_id: String,
    guest_image_labels: BTreeMap<String, String>,
    guest_image_environment: Vec<String>,
    results: VerifiedResultsTransport,
    runner_id: RunnerId,
    provider_id: ProviderId,
    capabilities: ProviderCapabilities,
    handle_locks: Mutex<BTreeMap<String, Weak<HandleOperationLock>>>,
}

#[derive(Clone)]
struct VerifiedResultsTransport {
    requested: LocalDockerResultsTransport,
    transit_name: String,
    transit_network: Ipv4Network,
    transit_gateway: Ipv4Addr,
    proxy_image_id: String,
    proxy_image_labels: BTreeMap<String, String>,
}

struct FrontNetworkDefinition {
    name: String,
    labels: BTreeMap<String, String>,
    ipv4_network: Ipv4Network,
    ipv4_gateway: Ipv4Addr,
}

struct SandboxArchiveDefinition {
    directory_headers: Vec<Header>,
    guest_header: Header,
}

type HandleOperationLock = tokio::sync::Mutex<()>;

#[derive(Clone, Copy)]
struct ResultsTransportBudget {
    deadline: tokio::time::Instant,
}

impl ResultsTransportBudget {
    fn start() -> Self {
        Self {
            deadline: tokio::time::Instant::now() + RESULTS_TRANSPORT_ATTESTATION_TIMEOUT,
        }
    }

    fn bounded_deadline(self, duration: Duration) -> tokio::time::Instant {
        self.deadline.min(tokio::time::Instant::now() + duration)
    }
}

#[derive(Default)]
struct LifecycleSiblingGroup {
    names: Option<ResourceNames>,
    identity: Option<BaseIdentity>,
    job: Option<InspectedContainer>,
    helper: Option<InspectedContainer>,
    proxy: Option<InspectedContainer>,
    front: Option<InspectedNetwork>,
}

#[derive(Default)]
struct LifecycleSiblingCustodyGroup {
    names: Option<ResourceNames>,
    identity: Option<BaseIdentity>,
    containers: BTreeMap<String, String>,
    front: Option<InspectedNetwork>,
}

/// Read-only, field-for-field attestation of the `LocalDocker` sibling union
/// before lifecycle teardown. This deliberately reuses the production HTTP
/// normalizer and provider definitions instead of trusting discovery labels.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn attest_lifecycle_sibling_union(
    installation: &Installation,
    desired: &crate::DesiredSpec,
    runner_id: uuid::Uuid,
    transit_network_id: &str,
    results_container_id: &str,
    containers: &[LifecycleSiblingContainer],
    networks: &[LifecycleSiblingNetwork],
) -> Result<(), LocalDockerError> {
    if containers.is_empty() && networks.is_empty() {
        return Ok(());
    }
    let runner_id = RunnerId::from_str(&runner_id.hyphenated().to_string())
        .map_err(|_| results_transport_mismatch())?;
    let (pinned, engine) = connect_host_sandbox_engine(desired.profile().architecture()).await?;
    verify_installation_identity(engine.as_ref(), installation).await?;

    let guest = engine
        .inspect_image(desired.images().sandbox_guest().reference())
        .await
        .map_err(map_engine_call)?
        .ok_or_else(results_transport_mismatch)?;
    verify_image(&pinned, desired.images().sandbox_guest(), &guest)
        .map_err(|_| results_transport_mismatch())?;
    let proxy_image = engine
        .inspect_image(desired.images().service_proxy().reference())
        .await
        .map_err(map_engine_call)?
        .ok_or_else(results_transport_mismatch)?;
    verify_results_proxy_image(&pinned, desired.images().service_proxy(), &proxy_image)
        .map_err(|_| results_transport_mismatch())?;
    let requested = LocalDockerResultsTransport::new(
        desired.images().service_proxy().clone(),
        desired.plan_digest(),
        transit_network_id.to_owned(),
        results_container_id.to_owned(),
        desired.results_transit().results_address(),
    )?;
    let transit = inspect_exact_results_transit(engine.as_ref(), installation, &requested).await?;
    let verified_results = VerifiedResultsTransport {
        requested,
        transit_name: results_transit_name(installation),
        transit_network: transit.ipv4_network.clone(),
        transit_gateway: transit.ipv4_gateway,
        proxy_image_id: proxy_image.id.clone(),
        proxy_image_labels: proxy_image.labels.clone(),
    };

    let mut groups = BTreeMap::<String, LifecycleSiblingGroup>::new();
    let mut seen_container_ids = BTreeSet::new();
    for candidate in containers {
        if !canonical_object_id(&candidate.id) || !seen_container_ids.insert(candidate.id.clone()) {
            return Err(results_transport_mismatch());
        }
        let container = engine
            .inspect_container(&candidate.id)
            .await
            .map_err(map_engine_call)?
            .ok_or_else(results_transport_mismatch)?;
        let by_name = engine
            .inspect_container(&candidate.name)
            .await
            .map_err(map_engine_call)?
            .ok_or_else(results_transport_mismatch)?;
        if container != by_name
            || container.id != candidate.id
            || container.definition.name != candidate.name
            || !container.isolated
            || !exact_realized_container_digest(&container)
        {
            return Err(results_transport_mismatch());
        }
        let (names, identity) = lifecycle_sibling_identity(
            &container.definition.labels,
            installation,
            runner_id,
            &candidate.kind,
        )?;
        let expected_name = match candidate.kind.as_str() {
            KIND_JOB => &names.job,
            KIND_GUEST_SOURCE => &names.helper,
            KIND_RESULTS_PROXY => &names.results_proxy,
            _ => return Err(results_transport_mismatch()),
        };
        if &candidate.name != expected_name || identity.profile != *desired.profile().attestation()
        {
            return Err(results_transport_mismatch());
        }
        let group = groups.entry(names.results_front.clone()).or_default();
        merge_lifecycle_sibling_identity(group, &names, &identity)?;
        let slot = match candidate.kind.as_str() {
            KIND_JOB => &mut group.job,
            KIND_GUEST_SOURCE => &mut group.helper,
            KIND_RESULTS_PROXY => &mut group.proxy,
            _ => unreachable!("kind checked above"),
        };
        if slot.replace(container).is_some() {
            return Err(results_transport_mismatch());
        }
    }

    let mut seen_network_ids = BTreeSet::new();
    for candidate in networks {
        if !canonical_object_id(&candidate.id) || !seen_network_ids.insert(candidate.id.clone()) {
            return Err(results_transport_mismatch());
        }
        let network = engine
            .inspect_network(&candidate.id)
            .await
            .map_err(map_engine_call)?
            .ok_or_else(results_transport_mismatch)?;
        let by_name = engine
            .inspect_network(&candidate.name)
            .await
            .map_err(map_engine_call)?
            .ok_or_else(results_transport_mismatch)?;
        if network != by_name || network.id != candidate.id || network.name != candidate.name {
            return Err(results_transport_mismatch());
        }
        let (names, identity) = lifecycle_sibling_identity(
            &network.labels,
            installation,
            runner_id,
            KIND_RESULTS_FRONT,
        )?;
        if candidate.name != names.results_front
            || identity.profile != *desired.profile().attestation()
        {
            return Err(results_transport_mismatch());
        }
        let group = groups.entry(names.results_front.clone()).or_default();
        merge_lifecycle_sibling_identity(group, &names, &identity)?;
        if group.front.replace(network).is_some() {
            return Err(results_transport_mismatch());
        }
    }

    let mut expected_transit_members = BTreeMap::from([(results_container_id.to_owned(), None)]);
    let mut seen_custody = BTreeSet::new();
    for group in groups.values() {
        let names = group
            .names
            .as_ref()
            .ok_or_else(results_transport_mismatch)?;
        let identity = group
            .identity
            .as_ref()
            .ok_or_else(results_transport_mismatch)?;
        let front = group
            .front
            .as_ref()
            .ok_or_else(results_transport_mismatch)?;
        let custody_key = match identity.custody {
            SandboxCustody::ProfileAdmission { .. } => "admission".to_owned(),
            SandboxCustody::Job { slot_ordinal, .. }
                if slot_ordinal.get() <= desired.max_parallel_jobs().get() =>
            {
                format!("job:{}", slot_ordinal.get())
            }
            SandboxCustody::Job { .. } => return Err(results_transport_mismatch()),
        };
        if !seen_custody.insert(custody_key) {
            return Err(results_transport_mismatch());
        }
        let expected_front =
            front_network_definition(names, &identity.base_labels, installation, identity.custody)
                .map_err(|_| results_transport_mismatch())?;
        if front.ipv4_network != expected_front.ipv4_network
            || front.ipv4_gateway != expected_front.ipv4_gateway
            || !exact_closed_network(front, &names.results_front, &expected_front.labels)
        {
            return Err(results_transport_mismatch());
        }

        if let Some(helper) = &group.helper {
            let definition = helper_definition(
                names,
                desired.images().sandbox_guest().reference(),
                &guest.labels,
                &neutral_environment(&guest.environment_names),
                &identity.base_labels,
            );
            if verify_container(helper, &definition, &guest.id, None).is_err()
                || !matches!(
                    helper.state,
                    EngineContainerState::Created
                        | EngineContainerState::Running
                        | EngineContainerState::Exited(0)
                )
            {
                return Err(results_transport_mismatch());
            }
        }
        if let Some(job) = &group.job {
            let job_image = engine
                .inspect_image(desired.profile().image().reference())
                .await
                .map_err(map_engine_call)?
                .ok_or_else(results_transport_mismatch)?;
            if job.definition.image != desired.profile().image().reference()
                || verify_image(&pinned, desired.profile().image(), &job_image).is_err()
                || job.image_id != job_image.id
                || !matches!(
                    job.state,
                    EngineContainerState::Created | EngineContainerState::Running
                )
                || verify_job_definition(
                    job,
                    names,
                    &job_image.labels,
                    &job_image.environment_names,
                    &identity.base_labels,
                    front,
                    ProviderStage::VerifyOwnership,
                )
                .is_err()
            {
                return Err(results_transport_mismatch());
            }
        }
        if let Some(proxy) = &group.proxy {
            let transit_address = transit_proxy_address(
                &transit.ipv4_network,
                transit.ipv4_gateway,
                desired.results_transit().results_address(),
                identity.custody,
            )
            .map_err(|_| results_transport_mismatch())?;
            let definition = results_proxy_definition(
                names,
                &identity.base_labels,
                &verified_results,
                front,
                transit_address,
            )
            .map_err(|_| results_transport_mismatch())?;
            if verify_container(proxy, &definition, &proxy_image.id, None).is_err()
                || !matches!(
                    proxy.state,
                    EngineContainerState::Created | EngineContainerState::Running
                )
            {
                return Err(results_transport_mismatch());
            }
            expected_transit_members.insert(
                proxy.id.clone(),
                Some((names.results_proxy.clone(), transit_address)),
            );
        }
        attest_lifecycle_front_members(group, front)?;
    }

    if transit.containers.len() != expected_transit_members.len() {
        return Err(results_transport_mismatch());
    }
    for (id, expectation) in expected_transit_members {
        let endpoint = transit
            .containers
            .get(&id)
            .ok_or_else(results_transport_mismatch)?;
        if let Some((name, address)) = expectation
            && (endpoint.name != name
                || endpoint.ipv4_address != address
                || endpoint.ipv4_prefix != transit.ipv4_network.prefix)
        {
            return Err(results_transport_mismatch());
        }
    }
    pinned.verify().await?;
    verify_installation_identity(engine.as_ref(), installation).await
}

/// Read-only ownership-stage attestation for lifecycle teardown.
///
/// Unlike runtime admission, this deliberately does not resolve image tags or
/// require the shared Results transit. Destroy must remain possible after
/// those replaceable dependencies are damaged, while every sibling is still
/// bound to its immutable ID, deterministic name, realized custody labels,
/// profile, and exact private-front membership.
#[allow(clippy::too_many_lines)]
pub(crate) async fn attest_lifecycle_sibling_custody_union(
    installation: &Installation,
    desired: &crate::DesiredSpec,
    runner_id: uuid::Uuid,
    containers: &[LifecycleSiblingContainer],
    networks: &[LifecycleSiblingNetwork],
) -> Result<(), LocalDockerError> {
    if containers.is_empty() && networks.is_empty() {
        return Ok(());
    }
    let runner_id = RunnerId::from_str(&runner_id.hyphenated().to_string())
        .map_err(|_| results_transport_mismatch())?;
    let (pinned, engine) = connect_host_sandbox_engine(desired.profile().architecture()).await?;
    verify_installation_identity(engine.as_ref(), installation).await?;

    let mut groups = BTreeMap::<String, LifecycleSiblingCustodyGroup>::new();
    let mut seen_container_ids = BTreeSet::new();
    for candidate in containers {
        if !canonical_object_id(&candidate.id) || !seen_container_ids.insert(candidate.id.clone()) {
            return Err(results_transport_mismatch());
        }
        let container = engine
            .inspect_container_custody(&candidate.id)
            .await
            .map_err(map_engine_call)?
            .ok_or_else(results_transport_mismatch)?;
        let by_name = engine
            .inspect_container_custody(&candidate.name)
            .await
            .map_err(map_engine_call)?
            .ok_or_else(results_transport_mismatch)?;
        if container != by_name || container.id != candidate.id || container.name != candidate.name
        {
            return Err(results_transport_mismatch());
        }
        let (names, identity) = lifecycle_sibling_identity(
            &container.labels,
            installation,
            runner_id,
            &candidate.kind,
        )?;
        let expected_name = match candidate.kind.as_str() {
            KIND_JOB => &names.job,
            KIND_GUEST_SOURCE => &names.helper,
            KIND_RESULTS_PROXY => &names.results_proxy,
            _ => return Err(results_transport_mismatch()),
        };
        let expected_image = (candidate.kind == KIND_RESULTS_PROXY)
            .then(|| desired.images().service_proxy().reference());
        let verified = verify_container_custody(
            &container,
            &names,
            installation,
            runner_id,
            &candidate.kind,
            expected_image,
            ProviderStage::VerifyOwnership,
        )
        .map_err(|_| results_transport_mismatch())?;
        if &candidate.name != expected_name
            || verified != identity
            || identity.profile != *desired.profile().attestation()
        {
            return Err(results_transport_mismatch());
        }
        let group = groups.entry(names.results_front.clone()).or_default();
        merge_lifecycle_custody_identity(group, &names, &identity)?;
        if group
            .containers
            .insert(candidate.kind.clone(), candidate.id.clone())
            .is_some()
        {
            return Err(results_transport_mismatch());
        }
    }

    let mut seen_network_ids = BTreeSet::new();
    for candidate in networks {
        if !canonical_object_id(&candidate.id) || !seen_network_ids.insert(candidate.id.clone()) {
            return Err(results_transport_mismatch());
        }
        let network = engine
            .inspect_network(&candidate.id)
            .await
            .map_err(map_engine_call)?
            .ok_or_else(results_transport_mismatch)?;
        let by_name = engine
            .inspect_network(&candidate.name)
            .await
            .map_err(map_engine_call)?
            .ok_or_else(results_transport_mismatch)?;
        if network != by_name || network.id != candidate.id || network.name != candidate.name {
            return Err(results_transport_mismatch());
        }
        let (names, identity) = lifecycle_sibling_identity(
            &network.labels,
            installation,
            runner_id,
            KIND_RESULTS_FRONT,
        )?;
        if candidate.name != names.results_front
            || identity.profile != *desired.profile().attestation()
        {
            return Err(results_transport_mismatch());
        }
        let group = groups.entry(names.results_front.clone()).or_default();
        merge_lifecycle_custody_identity(group, &names, &identity)?;
        if group.front.replace(network).is_some() {
            return Err(results_transport_mismatch());
        }
    }

    let mut seen_custody = BTreeSet::new();
    for group in groups.values() {
        let names = group
            .names
            .as_ref()
            .ok_or_else(results_transport_mismatch)?;
        let identity = group
            .identity
            .as_ref()
            .ok_or_else(results_transport_mismatch)?;
        let front = group
            .front
            .as_ref()
            .ok_or_else(results_transport_mismatch)?;
        let custody_key = match identity.custody {
            SandboxCustody::ProfileAdmission { .. } => "admission".to_owned(),
            SandboxCustody::Job { slot_ordinal, .. }
                if slot_ordinal.get() <= desired.max_parallel_jobs().get() =>
            {
                format!("job:{}", slot_ordinal.get())
            }
            SandboxCustody::Job { .. } => return Err(results_transport_mismatch()),
        };
        if !seen_custody.insert(custody_key) {
            return Err(results_transport_mismatch());
        }
        let expected_front =
            front_network_definition(names, &identity.base_labels, installation, identity.custody)
                .map_err(|_| results_transport_mismatch())?;
        if front.ipv4_network != expected_front.ipv4_network
            || front.ipv4_gateway != expected_front.ipv4_gateway
            || !exact_closed_network(front, &names.results_front, &expected_front.labels)
        {
            return Err(results_transport_mismatch());
        }
        attest_lifecycle_custody_front_members(group, front)?;
    }
    pinned.verify().await?;
    verify_installation_identity(engine.as_ref(), installation).await
}

fn lifecycle_sibling_identity(
    labels: &BTreeMap<String, String>,
    installation: &Installation,
    runner_id: RunnerId,
    kind: &str,
) -> Result<(ResourceNames, BaseIdentity), LocalDockerError> {
    let managed = managed_labels(labels);
    let operation = managed
        .get(LABEL_OPERATION_ID)
        .and_then(|value| OperationId::from_str(value).ok())
        .filter(|value| value.to_string() == managed[LABEL_OPERATION_ID]);
    let generation = managed
        .get(LABEL_GENERATION)
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| value.to_string() == managed[LABEL_GENERATION]);
    let names = operation
        .zip(generation)
        .and_then(|(operation, generation)| {
            ResourceNames::new(installation, operation, generation).ok()
        })
        .ok_or_else(results_transport_mismatch)?;
    let identity = parse_identity(
        labels,
        &names,
        installation,
        runner_id,
        kind,
        ProviderStage::VerifyOwnership,
    )
    .map_err(|_| results_transport_mismatch())?;
    Ok((names, identity))
}

fn merge_lifecycle_sibling_identity(
    group: &mut LifecycleSiblingGroup,
    names: &ResourceNames,
    identity: &BaseIdentity,
) -> Result<(), LocalDockerError> {
    if group.names.as_ref().is_some_and(|current| current != names)
        || group
            .identity
            .as_ref()
            .is_some_and(|current| current != identity)
    {
        return Err(results_transport_mismatch());
    }
    group.names.get_or_insert_with(|| names.clone());
    group.identity.get_or_insert_with(|| identity.clone());
    Ok(())
}

fn merge_lifecycle_custody_identity(
    group: &mut LifecycleSiblingCustodyGroup,
    names: &ResourceNames,
    identity: &BaseIdentity,
) -> Result<(), LocalDockerError> {
    if group.names.as_ref().is_some_and(|current| current != names)
        || group
            .identity
            .as_ref()
            .is_some_and(|current| current != identity)
    {
        return Err(results_transport_mismatch());
    }
    group.names.get_or_insert_with(|| names.clone());
    group.identity.get_or_insert_with(|| identity.clone());
    Ok(())
}

fn attest_lifecycle_custody_front_members(
    group: &LifecycleSiblingCustodyGroup,
    front: &InspectedNetwork,
) -> Result<(), LocalDockerError> {
    let names = group
        .names
        .as_ref()
        .ok_or_else(results_transport_mismatch)?;
    let mut expected = BTreeMap::new();
    if let Some(proxy) = group.containers.get(KIND_RESULTS_PROXY) {
        expected.insert(
            proxy.as_str(),
            (
                names.results_proxy.as_str(),
                front_proxy_address(front).map_err(|_| results_transport_mismatch())?,
            ),
        );
    }
    if let Some(job) = group.containers.get(KIND_JOB) {
        expected.insert(
            job.as_str(),
            (
                names.job.as_str(),
                front_job_address(front).map_err(|_| results_transport_mismatch())?,
            ),
        );
    }
    if front.containers.len() != expected.len() {
        return Err(results_transport_mismatch());
    }
    for (id, (name, address)) in expected {
        if !front.containers.get(id).is_some_and(|endpoint| {
            endpoint.name == name
                && endpoint.ipv4_address == address
                && endpoint.ipv4_prefix == front.ipv4_network.prefix
        }) {
            return Err(results_transport_mismatch());
        }
    }
    Ok(())
}

fn attest_lifecycle_front_members(
    group: &LifecycleSiblingGroup,
    front: &InspectedNetwork,
) -> Result<(), LocalDockerError> {
    let names = group
        .names
        .as_ref()
        .ok_or_else(results_transport_mismatch)?;
    let mut expected = BTreeMap::new();
    if let Some(proxy) = &group.proxy {
        expected.insert(
            proxy.id.as_str(),
            (
                names.results_proxy.as_str(),
                front_proxy_address(front).map_err(|_| results_transport_mismatch())?,
            ),
        );
    }
    if let Some(job) = &group.job {
        expected.insert(
            job.id.as_str(),
            (
                names.job.as_str(),
                front_job_address(front).map_err(|_| results_transport_mismatch())?,
            ),
        );
    }
    if front.containers.len() != expected.len() {
        return Err(results_transport_mismatch());
    }
    for (id, (name, address)) in expected {
        if !front.containers.get(id).is_some_and(|endpoint| {
            endpoint.name == name
                && endpoint.ipv4_address == address
                && endpoint.ipv4_prefix == front.ipv4_network.prefix
        }) {
            return Err(results_transport_mismatch());
        }
    }
    Ok(())
}

impl LocalDockerProvider {
    /// Connects through the fixed private relay and verifies the exact
    /// installation anchor, already-present digest-pinned guest, imported
    /// Results-proxy identity, pre-provisioned plan-bound transit network, and
    /// running numeric Results target.
    ///
    /// # Errors
    ///
    /// Returns a redacted failure when daemon identity, installation binding,
    /// anchor, guest or imported Results-proxy identity, shared transit, running
    /// Results target, or attached peer-proxy identity is invalid.
    pub(super) async fn connect(
        installation: InstallationBinding,
        guest_image: ImmutableImage,
        results_transport: LocalDockerResultsTransport,
        runner_id: RunnerId,
        expected_runner_architecture: &Architecture,
    ) -> Result<Self, LocalDockerError> {
        let (pinned, engine) = connect_relay_sandbox_engine(expected_runner_architecture).await?;
        let installation = resolve_installation_binding(engine.as_ref(), &installation).await?;
        let image = engine
            .inspect_image(guest_image.reference())
            .await
            .map_err(map_engine_call)?
            .ok_or_else(|| LocalDockerError::new(LocalDockerErrorCode::ImageUnavailable))?;
        verify_image(&pinned, &guest_image, &image).map_err(LocalDockerError::new)?;
        let proxy_image = engine
            .inspect_image(results_transport.proxy_image.reference())
            .await
            .map_err(map_engine_call)?
            .ok_or_else(|| LocalDockerError::new(LocalDockerErrorCode::ImageUnavailable))?;
        verify_results_proxy_image(&pinned, &results_transport.proxy_image, &proxy_image)
            .map_err(LocalDockerError::new)?;
        let transit = verify_shared_results_transport_bounded(
            &pinned,
            engine.as_ref(),
            &installation,
            &results_transport,
            &proxy_image.id,
            &proxy_image.labels,
            runner_id,
            &NeverCancelled,
            ResultsTransportBudget::start(),
        )
        .await
        .map_err(ResultsTransportAttestationError::into_local_docker_error)?;
        let provider_id = ProviderId::new(LOCAL_DOCKER_PROVIDER_ID)
            .map_err(|_| LocalDockerError::new(LocalDockerErrorCode::InvalidEngineResponse))?;
        let capabilities = ProviderCapabilities::new(PROVIDER_CAPABILITIES)
            .map_err(|_| LocalDockerError::new(LocalDockerErrorCode::InvalidEngineResponse))?;
        pinned.verify().await?;
        verify_installation_identity(engine.as_ref(), &installation).await?;
        Ok(Self {
            inner: Arc::new(LocalDockerInner {
                pinned,
                engine,
                installation,
                guest_image,
                guest_image_id: image.id,
                guest_image_labels: image.labels,
                guest_image_environment: neutral_environment(&image.environment_names),
                results: VerifiedResultsTransport {
                    requested: results_transport,
                    transit_name: transit.name,
                    transit_network: transit.ipv4_network,
                    transit_gateway: transit.ipv4_gateway,
                    proxy_image_id: proxy_image.id,
                    proxy_image_labels: proxy_image.labels,
                },
                runner_id,
                provider_id,
                capabilities,
                handle_locks: Mutex::new(BTreeMap::new()),
            }),
        })
    }

    #[cfg(test)]
    fn with_test_engine(
        pinned: PinnedDockerEngine,
        engine: Arc<dyn SandboxEngineApi>,
        installation: Installation,
        guest_image: ImmutableImage,
        guest_image_id: String,
        results: VerifiedResultsTransport,
        runner_id: RunnerId,
    ) -> Self {
        Self {
            inner: Arc::new(LocalDockerInner {
                pinned,
                engine,
                installation,
                guest_image,
                guest_image_id,
                guest_image_labels: BTreeMap::new(),
                guest_image_environment: Vec::new(),
                results,
                runner_id,
                provider_id: ProviderId::new(LOCAL_DOCKER_PROVIDER_ID).expect("provider id"),
                capabilities: ProviderCapabilities::new(PROVIDER_CAPABILITIES)
                    .expect("capabilities"),
                handle_locks: Mutex::new(BTreeMap::new()),
            }),
        }
    }
}

impl fmt::Debug for LocalDockerProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalDockerProvider")
            .field("provider_id", &self.inner.provider_id)
            .field("installation", &self.inner.installation.id())
            .field("guest_image", &self.inner.guest_image)
            .field("results", &self.inner.results.requested)
            .field("runner_id", &self.inner.runner_id)
            .field("capabilities", &self.inner.capabilities)
            .finish_non_exhaustive()
    }
}

impl SandboxProvider for LocalDockerProvider {
    fn provider_id(&self) -> &ProviderId {
        &self.inner.provider_id
    }

    fn capabilities(&self) -> &ProviderCapabilities {
        &self.inner.capabilities
    }

    fn create(
        &self,
        spec: &SandboxSpec,
        cancellation: &dyn Cancellation,
    ) -> Result<SandboxRecord, ProviderError> {
        validate_spec(spec, self.inner.runner_id)?;
        let names = ResourceNames::for_spec(&self.inner.installation, spec)?;
        let handle = names.handle(&self.inner.provider_id)?;
        let operation_lock = self.inner.handle_lock(&handle)?;
        run_provider(ProviderStage::CreateSandbox, async {
            let _operation = lock_handle(operation_lock, cancellation)
                .await
                .ok_or_else(|| known(ProviderErrorKind::Cancelled, ProviderStage::CreateSandbox))?;
            let budget = ResultsTransportBudget::start();
            self.inner
                .create(spec, &names, &handle, cancellation, budget)
                .await
        })
    }

    fn attach(
        &self,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<Box<dyn ExecutionEndpoint>, ProviderError> {
        let names =
            ResourceNames::from_handle(&self.inner.provider_id, &self.inner.installation, handle)?;
        let operation_lock = self.inner.handle_lock(handle)?;
        let attached = run_provider(ProviderStage::Attach, async {
            let _operation = lock_handle(Arc::clone(&operation_lock), cancellation)
                .await
                .ok_or_else(|| known(ProviderErrorKind::Cancelled, ProviderStage::Attach))?;
            let budget = ResultsTransportBudget::start();
            self.inner
                .attach_identity(&names, cancellation, budget)
                .await
        })?;
        Ok(Box::new(LocalDockerEndpoint::new(
            Arc::clone(&self.inner),
            handle.clone(),
            names,
            attached,
            operation_lock,
        )))
    }

    fn inspect(
        &self,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<SandboxInspection, ProviderError> {
        let names =
            ResourceNames::from_handle(&self.inner.provider_id, &self.inner.installation, handle)?;
        let operation_lock = self.inner.handle_lock(handle)?;
        run_provider(ProviderStage::Inspect, async {
            let _operation = lock_handle(operation_lock, cancellation)
                .await
                .ok_or_else(|| known(ProviderErrorKind::Cancelled, ProviderStage::Inspect))?;
            let budget = ResultsTransportBudget::start();
            self.inner
                .inspect(handle, &names, cancellation, budget)
                .await
        })
    }

    fn destroy(
        &self,
        request: &DestroySandbox,
        cancellation: &dyn Cancellation,
    ) -> Result<DestroyDisposition, ProviderError> {
        let names = ResourceNames::from_handle(
            &self.inner.provider_id,
            &self.inner.installation,
            request.handle(),
        )?;
        if names.generation != request.generation().get() {
            return Err(known(
                ProviderErrorKind::OwnershipMismatch,
                ProviderStage::Validate,
            ));
        }
        let operation_lock = self.inner.handle_lock(request.handle())?;
        run_provider(ProviderStage::DestroySandbox, async {
            let _operation = lock_handle(operation_lock, cancellation)
                .await
                .ok_or_else(|| {
                    known(ProviderErrorKind::Cancelled, ProviderStage::DestroySandbox)
                })?;
            let budget = ResultsTransportBudget::start();
            self.inner
                .destroy(request, &names, cancellation, budget)
                .await
        })
    }
}

impl LocalDockerInner {
    async fn verify_boundary(
        &self,
        stage: ProviderStage,
        cancellation: &dyn Cancellation,
        budget: ResultsTransportBudget,
    ) -> Result<(), ProviderError> {
        self.verify_boundary_kind(cancellation, budget)
            .await
            .map_err(|kind| known(kind, stage))
    }

    pub(super) async fn verify_boundary_kind(
        &self,
        cancellation: &dyn Cancellation,
        budget: ResultsTransportBudget,
    ) -> Result<(), ProviderErrorKind> {
        self.verify_custody_boundary_kind(cancellation).await?;
        self.verified_results_proxy_image().await?;
        verify_shared_results_transport_bounded(
            &self.pinned,
            self.engine.as_ref(),
            &self.installation,
            &self.results.requested,
            &self.results.proxy_image_id,
            &self.results.proxy_image_labels,
            self.runner_id,
            cancellation,
            budget,
        )
        .await
        .map(|_| ())
        .map_err(ResultsTransportAttestationError::into_provider_kind)
    }

    async fn verify_custody_boundary(
        &self,
        stage: ProviderStage,
        cancellation: &dyn Cancellation,
        _budget: ResultsTransportBudget,
    ) -> Result<(), ProviderError> {
        self.verify_custody_boundary_kind(cancellation)
            .await
            .map_err(|kind| known(kind, stage))
    }

    async fn verify_custody_boundary_kind(
        &self,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ProviderErrorKind> {
        if cancellation.disposition().requires_termination() {
            return Err(ProviderErrorKind::Cancelled);
        }
        self.pinned
            .verify()
            .await
            .map_err(|_| ProviderErrorKind::AdapterUnavailable)?;
        verify_installation_identity(self.engine.as_ref(), &self.installation)
            .await
            .map_err(|_| ProviderErrorKind::OwnershipMismatch)
    }

    fn handle_lock(
        &self,
        handle: &SandboxHandle,
    ) -> Result<Arc<HandleOperationLock>, ProviderError> {
        let mut locks = self
            .handle_locks
            .lock()
            .map_err(|_| known(ProviderErrorKind::LocalStorage, ProviderStage::Validate))?;
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(handle.opaque()).and_then(Weak::upgrade) {
            return Ok(lock);
        }
        let lock = Arc::new(HandleOperationLock::new(()));
        locks.insert(handle.opaque().to_owned(), Arc::downgrade(&lock));
        Ok(lock)
    }

    #[allow(clippy::too_many_lines)]
    async fn create(
        &self,
        spec: &SandboxSpec,
        names: &ResourceNames,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
        budget: ResultsTransportBudget,
    ) -> Result<SandboxRecord, ProviderError> {
        ensure_not_cancelled(cancellation, ProviderStage::Validate)?;
        self.verify_boundary(ProviderStage::Validate, cancellation, budget)
            .await?;
        let SandboxLaunch::Container { image, .. } = spec.profile().launch() else {
            return Err(invalid_configuration());
        };
        let job_image = self
            .verified_image(image)
            .await
            .map_err(|kind| known(kind, ProviderStage::Validate))?;
        let guest_image = self
            .verified_image(&self.guest_image)
            .await
            .map_err(|kind| known(kind, ProviderStage::Validate))?;
        if guest_image.id != self.guest_image_id
            || guest_image.labels != self.guest_image_labels
            || neutral_environment(&guest_image.environment_names) != self.guest_image_environment
        {
            return Err(known(
                ProviderErrorKind::OwnershipMismatch,
                ProviderStage::Validate,
            ));
        }
        let fingerprint =
            spec_fingerprint(spec, &self.installation, &self.guest_image, &self.results)?;
        let base_labels = base_labels(spec, &self.installation, &fingerprint);
        let helper_definition = helper_definition(
            names,
            self.guest_image.reference(),
            &self.guest_image_labels,
            &self.guest_image_environment,
            &base_labels,
        );
        let front_definition =
            front_network_definition(names, &base_labels, &self.installation, spec.custody())?;
        if ipv4_networks_overlap(
            &front_definition.ipv4_network,
            &self.results.transit_network,
        ) {
            return Err(known(
                ProviderErrorKind::OwnershipMismatch,
                ProviderStage::VerifyOwnership,
            ));
        }
        let transit_address = transit_proxy_address(
            &self.results.transit_network,
            self.results.transit_gateway,
            self.results.requested.results_address,
            spec.custody(),
        )?;
        let mut job_definition = job_definition(
            names,
            spec,
            image.reference(),
            &job_image.labels,
            &job_image.environment_names,
            &base_labels,
            &front_definition,
        )?;
        let mut proxy_definition = planned_results_proxy_definition(
            names,
            &base_labels,
            &self.results,
            &front_definition,
            transit_address,
        )?;
        let sandbox_archive_definition = sandbox_archive_definition(spec.workspace().as_str())?;
        if [
            front_definition.labels.len(),
            job_definition.labels.len(),
            helper_definition.labels.len(),
            proxy_definition.labels.len(),
        ]
        .into_iter()
        .any(|count| count > MAX_RESOURCE_LABELS)
        {
            return Err(invalid_configuration());
        }
        let existing_job = self
            .engine
            .inspect_container(&names.job)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::CreateSandbox, None))?;
        let existing_helper = self
            .engine
            .inspect_container(&names.helper)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::CreateSandbox, None))?;
        let existing_proxy = self
            .engine
            .inspect_container(&names.results_proxy)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::CreateSandbox, None))?;
        let existing_front = self
            .engine
            .inspect_network(&names.results_front)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::CreateSandbox, None))?;
        if existing_front.is_none()
            && (existing_job.is_some() || existing_helper.is_some() || existing_proxy.is_some())
        {
            return Err(known(
                ProviderErrorKind::OwnershipMismatch,
                ProviderStage::CreateSandbox,
            ));
        }
        let front = self
            .create_or_verify_front_network(names, &front_definition, handle, cancellation, budget)
            .await?;
        bind_front_network(&mut job_definition, &front);
        bind_front_network(&mut proxy_definition, &front);

        let create_result: Result<SandboxRecord, ProviderError> = async {
            if let Some(helper) = existing_helper.as_ref() {
                verify_existing_helper(helper, &helper_definition, &guest_image.id)?;
            }
            if let Some(proxy) = existing_proxy.as_ref() {
                verify_container(proxy, &proxy_definition, &self.results.proxy_image_id, None)?;
            }

            if let Some(job) = existing_job.as_ref() {
                verify_container(job, &job_definition, &job_image.id, None)?;
                match job.state {
                    EngineContainerState::Running
                        if existing_helper.is_none()
                            && existing_proxy.as_ref().is_some_and(|proxy| {
                                proxy.state == EngineContainerState::Running
                            }) =>
                    {
                        let proxy = existing_proxy.as_ref().expect("guarded proxy");
                        self.wait_for_results_proxy_ready(
                            names,
                            proxy,
                            &proxy_definition,
                            &front,
                            Some(job),
                            handle,
                            ProviderStage::Start,
                            cancellation,
                            budget,
                        )
                        .await?;
                        if let Err(error) =
                            self.probe(names, job, handle, cancellation, budget).await
                        {
                            self.destroy_container(
                                &InspectedContainerCustody::from(job),
                                handle,
                                &NeverCancelled,
                                budget,
                            )
                            .await?;
                            return Err(error);
                        }
                        ensure_not_cancelled(cancellation, ProviderStage::CreateSandbox)?;
                        self.verify_boundary(ProviderStage::CreateSandbox, cancellation, budget)
                            .await
                            .map_err(|error| recovery(&error, handle))?;
                        self.require_exact_container(
                            job,
                            &job_definition,
                            &job_image.id,
                            EngineContainerState::Running,
                            handle,
                        )
                        .await?;
                        self.require_name_absent(&names.helper, handle).await?;
                        self.require_front_members(&front, Some(job), Some(proxy), handle)
                            .await?;
                        return Ok(record(handle, spec, SandboxState::Running));
                    }
                    EngineContainerState::Running
                    | EngineContainerState::Exited(_)
                    | EngineContainerState::Invalid => {
                        return Err(uncertain(
                            ProviderErrorKind::InvalidState,
                            ProviderStage::CreateSandbox,
                            handle,
                        ));
                    }
                    EngineContainerState::Created => {}
                }
            }

            let guest_bytes = self
                .prepare_guest(
                    existing_helper.as_ref(),
                    &helper_definition,
                    &guest_image.id,
                    handle,
                    cancellation,
                    budget,
                )
                .await?;
            let sandbox_archive = sandbox_archive(&sandbox_archive_definition, &guest_bytes)?;

            let job = if let Some(job) = existing_job {
                job
            } else {
                ensure_not_cancelled(cancellation, ProviderStage::CreateContainer)?;
                self.require_name_absent(&names.job, handle).await?;
                self.verify_boundary(ProviderStage::CreateContainer, cancellation, budget)
                    .await?;
                let _untrusted_create = self.engine.create_container(job_definition.clone()).await;
                let job = self
                    .require_container(
                        &names.job,
                        &job_definition,
                        &job_image.id,
                        EngineContainerState::Created,
                        handle,
                    )
                    .await?;
                ensure_not_cancelled_after_mutation(
                    cancellation,
                    ProviderStage::CreateContainer,
                    handle,
                )?;
                job
            };

            let job = self
                .require_exact_container(
                    &job,
                    &job_definition,
                    &job_image.id,
                    EngineContainerState::Created,
                    handle,
                )
                .await?;
            self.verify_boundary(ProviderStage::CreateContainer, cancellation, budget)
                .await
                .map_err(|error| recovery(&error, handle))?;
            let _untrusted_upload = self
                .engine
                .upload_sandbox_archive(&job.id, &sandbox_archive)
                .await;
            let job = self
                .require_exact_container(
                    &job,
                    &job_definition,
                    &job_image.id,
                    EngineContainerState::Created,
                    handle,
                )
                .await?;
            let realized_archive = self
                .engine
                .download_sandbox_guest(&job.id, LOCAL_DOCKER_GUEST_ARCHIVE_BYTES)
                .await
                .map_err(|error| {
                    map_provider_engine(error, ProviderStage::VerifyOwnership, Some(handle))
                })?;
            let realized_guest = extract_single_guest(&realized_archive)
                .map_err(|error| recovery(&error, handle))?;
            if realized_guest != guest_bytes {
                return Err(uncertain(
                    ProviderErrorKind::OwnershipMismatch,
                    ProviderStage::VerifyOwnership,
                    handle,
                ));
            }
            ensure_not_cancelled_after_mutation(
                cancellation,
                ProviderStage::CreateContainer,
                handle,
            )?;

            let proxy = if let Some(proxy) = existing_proxy {
                match proxy.state {
                    EngineContainerState::Created | EngineContainerState::Running => proxy,
                    EngineContainerState::Exited(_) | EngineContainerState::Invalid => {
                        return Err(uncertain(
                            ProviderErrorKind::InvalidState,
                            ProviderStage::CreateSandbox,
                            handle,
                        ));
                    }
                }
            } else {
                ensure_not_cancelled(cancellation, ProviderStage::CreateContainer)?;
                self.require_name_absent(&names.results_proxy, handle)
                    .await?;
                self.verify_boundary(ProviderStage::CreateContainer, cancellation, budget)
                    .await?;
                let _untrusted_create =
                    self.engine.create_container(proxy_definition.clone()).await;
                self.require_container(
                    &names.results_proxy,
                    &proxy_definition,
                    &self.results.proxy_image_id,
                    EngineContainerState::Created,
                    handle,
                )
                .await?
            };
            let proxy = if proxy.state == EngineContainerState::Created {
                self.verify_boundary(ProviderStage::Start, cancellation, budget)
                    .await
                    .map_err(|error| recovery(&error, handle))?;
                let _untrusted_start = self.engine.start_container(&proxy.id).await;
                self.require_exact_container(
                    &proxy,
                    &proxy_definition,
                    &self.results.proxy_image_id,
                    EngineContainerState::Running,
                    handle,
                )
                .await?
            } else {
                self.require_exact_container(
                    &proxy,
                    &proxy_definition,
                    &self.results.proxy_image_id,
                    EngineContainerState::Running,
                    handle,
                )
                .await?
            };
            self.wait_for_results_proxy_ready(
                names,
                &proxy,
                &proxy_definition,
                &front,
                None,
                handle,
                ProviderStage::Start,
                cancellation,
                budget,
            )
            .await?;

            let job = self
                .require_exact_container(
                    &job,
                    &job_definition,
                    &job_image.id,
                    EngineContainerState::Created,
                    handle,
                )
                .await?;
            self.verify_boundary(ProviderStage::Start, cancellation, budget)
                .await
                .map_err(|error| recovery(&error, handle))?;
            let _untrusted_start = self.engine.start_container(&job.id).await;
            let running = self
                .require_exact_container(
                    &job,
                    &job_definition,
                    &job_image.id,
                    EngineContainerState::Running,
                    handle,
                )
                .await?;
            self.require_front_members(&front, Some(&running), Some(&proxy), handle)
                .await?;
            if let Err(error) = self
                .bootstrap_client(names, &running, handle, cancellation, budget)
                .await
            {
                self.destroy_container(
                    &InspectedContainerCustody::from(&running),
                    handle,
                    &NeverCancelled,
                    budget,
                )
                .await?;
                return Err(error);
            }
            if let Err(error) = self
                .probe(names, &running, handle, cancellation, budget)
                .await
            {
                self.destroy_container(
                    &InspectedContainerCustody::from(&running),
                    handle,
                    &NeverCancelled,
                    budget,
                )
                .await?;
                return Err(error);
            }
            if let Err(error) =
                ensure_not_cancelled_after_mutation(cancellation, ProviderStage::Start, handle)
            {
                self.destroy_container(
                    &InspectedContainerCustody::from(&running),
                    handle,
                    &NeverCancelled,
                    budget,
                )
                .await?;
                return Err(error);
            }
            self.verify_boundary(ProviderStage::CreateSandbox, cancellation, budget)
                .await
                .map_err(|error| recovery(&error, handle))?;
            self.require_exact_container(
                &running,
                &job_definition,
                &job_image.id,
                EngineContainerState::Running,
                handle,
            )
            .await?;
            self.require_name_absent(&names.helper, handle).await?;
            self.require_front_members(&front, Some(&running), Some(&proxy), handle)
                .await?;
            Ok(record(handle, spec, SandboxState::Running))
        }
        .await;
        create_result.map_err(|error| recovery(&error, handle))
    }

    async fn verified_image(
        &self,
        image: &ImmutableImage,
    ) -> Result<InspectedImage, ProviderErrorKind> {
        let inspected = self
            .engine
            .inspect_image(image.reference())
            .await
            .map_err(map_engine_kind)?
            .ok_or(ProviderErrorKind::NotFound)?;
        verify_image(&self.pinned, image, &inspected)
            .map_err(|_| ProviderErrorKind::OwnershipMismatch)?;
        Ok(inspected)
    }

    async fn verified_results_proxy_image(&self) -> Result<InspectedImage, ProviderErrorKind> {
        let inspected = self
            .engine
            .inspect_image(self.results.requested.proxy_image.reference())
            .await
            .map_err(map_engine_kind)?
            .ok_or(ProviderErrorKind::NotFound)?;
        if verify_results_proxy_image(
            &self.pinned,
            &self.results.requested.proxy_image,
            &inspected,
        )
        .is_err()
            || inspected.id != self.results.proxy_image_id
            || inspected.labels != self.results.proxy_image_labels
        {
            return Err(ProviderErrorKind::OwnershipMismatch);
        }
        Ok(inspected)
    }

    async fn require_name_absent(
        &self,
        name: &str,
        handle: &SandboxHandle,
    ) -> Result<(), ProviderError> {
        if self
            .engine
            .inspect_container_custody(name)
            .await
            .map_err(|error| {
                map_provider_engine(error, ProviderStage::VerifyOwnership, Some(handle))
            })?
            .is_some()
        {
            return Err(uncertain(
                ProviderErrorKind::Conflict,
                ProviderStage::VerifyOwnership,
                handle,
            ));
        }
        Ok(())
    }

    async fn require_container(
        &self,
        name: &str,
        definition: &ContainerDefinition,
        image_id: &str,
        state: EngineContainerState,
        handle: &SandboxHandle,
    ) -> Result<InspectedContainer, ProviderError> {
        let inspected = self.engine.inspect_container(name).await.map_err(|error| {
            map_provider_engine(error, ProviderStage::VerifyOwnership, Some(handle))
        })?;
        let Some(inspected) = inspected else {
            return Err(uncertain(
                ProviderErrorKind::AdapterUnavailable,
                ProviderStage::VerifyOwnership,
                handle,
            ));
        };
        verify_container(&inspected, definition, image_id, Some(state))
            .map_err(|error| recovery(&error, handle))?;
        Ok(inspected)
    }

    async fn require_exact_container(
        &self,
        expected: &InspectedContainer,
        definition: &ContainerDefinition,
        image_id: &str,
        state: EngineContainerState,
        handle: &SandboxHandle,
    ) -> Result<InspectedContainer, ProviderError> {
        let current = self
            .require_container(&definition.name, definition, image_id, state, handle)
            .await?;
        if current.id != expected.id {
            return Err(uncertain(
                ProviderErrorKind::Conflict,
                ProviderStage::VerifyOwnership,
                handle,
            ));
        }
        Ok(current)
    }

    async fn prepare_guest(
        &self,
        existing: Option<&InspectedContainer>,
        definition: &ContainerDefinition,
        image_id: &str,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
        budget: ResultsTransportBudget,
    ) -> Result<Vec<u8>, ProviderError> {
        ensure_not_cancelled(cancellation, ProviderStage::CreateContainer)?;
        let helper = if let Some(helper) = existing {
            helper.clone()
        } else {
            self.require_name_absent(&definition.name, handle).await?;
            self.verify_boundary(ProviderStage::CreateContainer, cancellation, budget)
                .await?;
            let _untrusted_create = self.engine.create_container(definition.clone()).await;
            let helper = self
                .require_container(
                    &definition.name,
                    definition,
                    image_id,
                    EngineContainerState::Created,
                    handle,
                )
                .await?;
            ensure_not_cancelled_after_mutation(
                cancellation,
                ProviderStage::CreateContainer,
                handle,
            )?;
            helper
        };

        let helper = self
            .require_exact_container(
                &helper,
                definition,
                image_id,
                EngineContainerState::Created,
                handle,
            )
            .await?;
        let archive = self
            .engine
            .download_guest_image_binary(&helper.id, LOCAL_DOCKER_GUEST_ARCHIVE_BYTES)
            .await
            .map_err(|error| {
                map_provider_engine(error, ProviderStage::VerifyOwnership, Some(handle))
            })?;
        let guest = extract_single_guest(&archive).map_err(|error| recovery(&error, handle))?;

        let helper = self
            .require_exact_container(
                &helper,
                definition,
                image_id,
                EngineContainerState::Created,
                handle,
            )
            .await?;
        self.destroy_container(
            &InspectedContainerCustody::from(&helper),
            handle,
            cancellation,
            budget,
        )
        .await?;
        Ok(guest)
    }

    async fn create_or_verify_front_network(
        &self,
        names: &ResourceNames,
        definition: &FrontNetworkDefinition,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
        budget: ResultsTransportBudget,
    ) -> Result<InspectedNetwork, ProviderError> {
        let existing = self
            .engine
            .inspect_network(&names.results_front)
            .await
            .map_err(|error| {
                map_provider_engine(error, ProviderStage::CreateSandbox, Some(handle))
            })?;
        if let Some(network) = existing {
            verify_front_network(
                &network,
                names,
                &definition.labels,
                &definition.ipv4_network,
                handle,
            )?;
            return self
                .require_exact_front_network(
                    &network,
                    names,
                    &definition.labels,
                    &definition.ipv4_network,
                    handle,
                )
                .await;
        }
        ensure_not_cancelled(cancellation, ProviderStage::CreateSandbox)?;
        self.verify_boundary(ProviderStage::CreateSandbox, cancellation, budget)
            .await?;
        let _untrusted_create = self
            .engine
            .create_network(CreateNetwork {
                name: definition.name.clone(),
                labels: definition.labels.clone(),
                ipv4_network: definition.ipv4_network.clone(),
                ipv4_gateway: definition.ipv4_gateway,
            })
            .await;
        let network = self
            .engine
            .inspect_network(&names.results_front)
            .await
            .map_err(|error| {
                map_provider_engine(error, ProviderStage::CreateSandbox, Some(handle))
            })?
            .ok_or_else(|| {
                uncertain(
                    ProviderErrorKind::AdapterUnavailable,
                    ProviderStage::CreateSandbox,
                    handle,
                )
            })?;
        verify_front_network(
            &network,
            names,
            &definition.labels,
            &definition.ipv4_network,
            handle,
        )?;
        ensure_not_cancelled_after_mutation(cancellation, ProviderStage::CreateSandbox, handle)?;
        self.require_exact_front_network(
            &network,
            names,
            &definition.labels,
            &definition.ipv4_network,
            handle,
        )
        .await
    }

    async fn require_exact_front_network(
        &self,
        expected: &InspectedNetwork,
        names: &ResourceNames,
        labels: &BTreeMap<String, String>,
        ipv4_network: &Ipv4Network,
        handle: &SandboxHandle,
    ) -> Result<InspectedNetwork, ProviderError> {
        let by_id = self
            .engine
            .inspect_network(&expected.id)
            .await
            .map_err(|error| {
                map_provider_engine(error, ProviderStage::VerifyOwnership, Some(handle))
            })?;
        let by_name = self
            .engine
            .inspect_network(&names.results_front)
            .await
            .map_err(|error| {
                map_provider_engine(error, ProviderStage::VerifyOwnership, Some(handle))
            })?;
        if by_id.as_ref() != Some(expected) || by_name.as_ref() != Some(expected) {
            return Err(uncertain(
                ProviderErrorKind::OwnershipMismatch,
                ProviderStage::VerifyOwnership,
                handle,
            ));
        }
        verify_front_network(expected, names, labels, ipv4_network, handle)?;
        Ok(expected.clone())
    }

    async fn require_front_members(
        &self,
        network: &InspectedNetwork,
        job: Option<&InspectedContainer>,
        proxy: Option<&InspectedContainer>,
        handle: &SandboxHandle,
    ) -> Result<InspectedNetwork, ProviderError> {
        let current = self
            .engine
            .inspect_network(&network.id)
            .await
            .map_err(|error| {
                map_provider_engine(error, ProviderStage::VerifyOwnership, Some(handle))
            })?
            .ok_or_else(|| {
                uncertain(
                    ProviderErrorKind::OwnershipMismatch,
                    ProviderStage::VerifyOwnership,
                    handle,
                )
            })?;
        let mut expected = BTreeMap::new();
        if let Some(proxy) = proxy.filter(|proxy| proxy.state == EngineContainerState::Running) {
            expected.insert(
                proxy.id.clone(),
                (
                    proxy.definition.name.clone(),
                    front_proxy_address(&current)?,
                    current.ipv4_network.prefix,
                ),
            );
        }
        if let Some(job) = job.filter(|job| job.state == EngineContainerState::Running) {
            expected.insert(
                job.id.clone(),
                (
                    job.definition.name.clone(),
                    front_job_address(&current)?,
                    current.ipv4_network.prefix,
                ),
            );
        }
        let realized = current
            .containers
            .iter()
            .map(|(id, endpoint)| {
                (
                    id.clone(),
                    (
                        endpoint.name.clone(),
                        endpoint.ipv4_address,
                        endpoint.ipv4_prefix,
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut current_without_members = current.clone();
        current_without_members.containers = network.containers.clone();
        if current_without_members != *network || realized != expected {
            return Err(uncertain(
                ProviderErrorKind::OwnershipMismatch,
                ProviderStage::VerifyOwnership,
                handle,
            ));
        }
        Ok(current)
    }

    async fn destroy_front_network(
        &self,
        snapshot: &InspectedNetwork,
        names: &ResourceNames,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
        budget: ResultsTransportBudget,
    ) -> Result<(), ProviderError> {
        ensure_not_cancelled(cancellation, ProviderStage::DestroyContainer)?;
        let current = self
            .engine
            .inspect_network(&snapshot.id)
            .await
            .map_err(|error| {
                map_provider_engine(error, ProviderStage::DestroyContainer, Some(handle))
            })?
            .ok_or_else(|| {
                uncertain(
                    ProviderErrorKind::Conflict,
                    ProviderStage::DestroyContainer,
                    handle,
                )
            })?;
        let mut expected = snapshot.clone();
        expected.containers.clear();
        if current != expected || !current.containers.is_empty() {
            return Err(uncertain(
                ProviderErrorKind::OwnershipMismatch,
                ProviderStage::DestroyContainer,
                handle,
            ));
        }
        self.verify_custody_boundary(ProviderStage::DestroyContainer, cancellation, budget)
            .await
            .map_err(|error| recovery(&error, handle))?;
        let _untrusted_remove = self.engine.remove_network(&current.id).await;
        self.require_network_absent(names, Some(&current.id), handle)
            .await?;
        ensure_not_cancelled_after_mutation(cancellation, ProviderStage::DestroyContainer, handle)
    }

    async fn require_network_absent(
        &self,
        names: &ResourceNames,
        removed_id: Option<&str>,
        handle: &SandboxHandle,
    ) -> Result<(), ProviderError> {
        let by_name = self
            .engine
            .inspect_network(&names.results_front)
            .await
            .map_err(|error| {
                map_provider_engine(error, ProviderStage::DestroyContainer, Some(handle))
            })?;
        let by_id = if let Some(id) = removed_id {
            self.engine.inspect_network(id).await.map_err(|error| {
                map_provider_engine(error, ProviderStage::DestroyContainer, Some(handle))
            })?
        } else {
            None
        };
        if by_name.is_none() && by_id.is_none() {
            Ok(())
        } else {
            Err(uncertain(
                ProviderErrorKind::Conflict,
                ProviderStage::DestroyContainer,
                handle,
            ))
        }
    }

    async fn probe(
        &self,
        names: &ResourceNames,
        container: &InspectedContainer,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
        budget: ResultsTransportBudget,
    ) -> Result<(), ProviderError> {
        ensure_not_cancelled(cancellation, ProviderStage::Start)?;
        let guest_request = GuestRequest::Probe {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: format!("{}:provider-probe", handle.opaque()),
        };
        let request = EngineExecRequest {
            container_id: container.id.clone(),
            command: vec![LOCAL_CONTROL_CLIENT.to_owned(), "local-client".to_owned()],
            user: guest_client_user(),
            stdin: encode_frame(&guest_request).map_err(|_| invalid_configuration())?,
            stdout_limit: MAX_GUEST_FRAME_BYTES + 4,
            stderr_limit: 1_024,
            timeout: ENGINE_TRANSPORT_OVERHEAD,
        };
        self.verify_boundary(ProviderStage::Start, cancellation, budget)
            .await
            .map_err(|error| recovery(&error, handle))?;
        ensure_not_cancelled(cancellation, ProviderStage::Start)?;
        let prepared = self
            .engine
            .create_exec(&request.container_id, &request.command, &request.user)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::Start, Some(handle)))?;
        self.verify_boundary(ProviderStage::Start, cancellation, budget)
            .await
            .map_err(|error| recovery(&error, handle))?;
        let result = tokio::select! {
            biased;
            () = cancellation_requested(cancellation) => {
                self.stop_exact_running_job(
                    names,
                    container,
                    handle,
                    ProviderStage::Start,
                    budget,
                )
                .await?;
                return Err(uncertain(ProviderErrorKind::Cancelled, ProviderStage::Start, handle));
            }
            result = self.engine.start_exec(&prepared, &request) => result,
        };
        if cancellation.disposition().requires_termination() {
            self.stop_exact_running_job(names, container, handle, ProviderStage::Start, budget)
                .await?;
            return Err(uncertain(
                ProviderErrorKind::Cancelled,
                ProviderStage::Start,
                handle,
            ));
        }
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                self.stop_exact_running_job(names, container, handle, ProviderStage::Start, budget)
                    .await?;
                return Err(map_provider_engine(
                    error,
                    ProviderStage::Start,
                    Some(handle),
                ));
            }
        };
        if result.exit_code != 0
            || !result.stderr.is_empty()
            || decode_frame::<GuestResponse>(&result.stdout).ok()
                != Some(GuestResponse::Ready {
                    protocol: GUEST_PROTOCOL_VERSION,
                })
        {
            return Err(uncertain(
                ProviderErrorKind::BackendRejected,
                ProviderStage::Start,
                handle,
            ));
        }
        if cancellation.disposition().requires_termination() {
            self.stop_exact_running_job(names, container, handle, ProviderStage::Start, budget)
                .await?;
            return Err(uncertain(
                ProviderErrorKind::Cancelled,
                ProviderStage::Start,
                handle,
            ));
        }
        Ok(())
    }

    async fn bootstrap_client(
        &self,
        names: &ResourceNames,
        container: &InspectedContainer,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
        budget: ResultsTransportBudget,
    ) -> Result<(), ProviderError> {
        let request = EngineExecRequest {
            container_id: container.id.clone(),
            command: vec![
                LOCAL_DOCKER_SANDBOX_GUEST_BINARY.to_owned(),
                "bootstrap-local-client".to_owned(),
            ],
            user: guest_seal_user(),
            stdin: Vec::new(),
            stdout_limit: 1,
            stderr_limit: 1,
            timeout: ENGINE_TRANSPORT_OVERHEAD + Duration::from_secs(10),
        };
        self.verify_boundary(ProviderStage::Start, cancellation, budget)
            .await
            .map_err(|error| recovery(&error, handle))?;
        let prepared = self
            .engine
            .create_exec(&request.container_id, &request.command, &request.user)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::Start, Some(handle)))?;
        self.verify_boundary(ProviderStage::Start, cancellation, budget)
            .await
            .map_err(|error| recovery(&error, handle))?;
        let result = match self.engine.start_exec(&prepared, &request).await {
            Ok(result) => result,
            Err(error) => {
                self.stop_exact_running_job(names, container, handle, ProviderStage::Start, budget)
                    .await?;
                return Err(map_provider_engine(
                    error,
                    ProviderStage::Start,
                    Some(handle),
                ));
            }
        };
        if result.exit_code != 0 || !result.stdout.is_empty() || !result.stderr.is_empty() {
            return Err(uncertain(
                ProviderErrorKind::BackendRejected,
                ProviderStage::Start,
                handle,
            ));
        }
        Ok(())
    }

    async fn attach_identity(
        &self,
        names: &ResourceNames,
        cancellation: &dyn Cancellation,
        budget: ResultsTransportBudget,
    ) -> Result<AttachedIdentity, ProviderError> {
        ensure_not_cancelled(cancellation, ProviderStage::Attach)?;
        self.verify_boundary(ProviderStage::Attach, cancellation, budget)
            .await?;
        let container = self
            .engine
            .inspect_container(&names.job)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::Attach, None))?
            .ok_or_else(|| known(ProviderErrorKind::NotFound, ProviderStage::Attach))?;
        let initial_identity = self
            .verify_job(names, &container, ProviderStage::Attach)
            .await?;
        if container.state != EngineContainerState::Running {
            return Err(known(
                ProviderErrorKind::InvalidState,
                ProviderStage::Attach,
            ));
        }
        if self
            .engine
            .inspect_container(&names.helper)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::Attach, None))?
            .is_some()
        {
            return Err(known(
                ProviderErrorKind::InvalidState,
                ProviderStage::Attach,
            ));
        }
        let handle = names.handle(&self.provider_id)?;
        self.verify_results_topology(
            names,
            &container,
            &initial_identity,
            ProviderStage::Attach,
            cancellation,
            budget,
        )
        .await?;
        self.probe(names, &container, &handle, cancellation, budget)
            .await?;
        self.verify_boundary(ProviderStage::Attach, cancellation, budget)
            .await?;
        let container = self
            .require_exact_container(
                &container,
                &container.definition,
                &container.image_id,
                EngineContainerState::Running,
                &handle,
            )
            .await?;
        self.require_name_absent(&names.helper, &handle).await?;
        let identity = self
            .verify_job(names, &container, ProviderStage::Attach)
            .await?;
        let (proxy, front) = self
            .verify_results_topology(
                names,
                &container,
                &identity,
                ProviderStage::Attach,
                cancellation,
                budget,
            )
            .await?;
        ensure_not_cancelled_after_mutation(cancellation, ProviderStage::Attach, &handle)?;
        Ok(AttachedIdentity {
            container_id: container.id,
            definition: container.definition,
            base_labels: identity.base_labels,
            proxy_id: proxy.id,
            proxy_definition: proxy.definition,
            front_id: front.id,
        })
    }

    async fn verify_attached(
        &self,
        names: &ResourceNames,
        attached: &AttachedIdentity,
        cancellation: &dyn Cancellation,
        budget: ResultsTransportBudget,
    ) -> Result<InspectedContainer, ProviderErrorKind> {
        self.verify_boundary_kind(cancellation, budget).await?;
        let container = self
            .engine
            .inspect_container(&names.job)
            .await
            .map_err(map_engine_kind)?
            .ok_or(ProviderErrorKind::NotFound)?;
        if container.id != attached.container_id
            || container.definition != attached.definition
            || container.state != EngineContainerState::Running
            || !container.isolated
        {
            return Err(ProviderErrorKind::OwnershipMismatch);
        }
        if self
            .engine
            .inspect_container(&names.helper)
            .await
            .map_err(map_engine_kind)?
            .is_some()
        {
            return Err(ProviderErrorKind::InvalidState);
        }
        let identity = self
            .verify_job(names, &container, ProviderStage::VerifyOwnership)
            .await
            .map_err(|error| error.kind())?;
        if identity.base_labels != attached.base_labels {
            return Err(ProviderErrorKind::OwnershipMismatch);
        }
        let (proxy, front) = self
            .verify_results_topology(
                names,
                &container,
                &identity,
                ProviderStage::VerifyOwnership,
                cancellation,
                budget,
            )
            .await
            .map_err(|error| error.kind())?;
        if proxy.id != attached.proxy_id
            || proxy.definition != attached.proxy_definition
            || front.id != attached.front_id
        {
            return Err(ProviderErrorKind::OwnershipMismatch);
        }
        Ok(container)
    }

    async fn stop_exact_running_job(
        &self,
        names: &ResourceNames,
        expected: &InspectedContainer,
        handle: &SandboxHandle,
        stage: ProviderStage,
        budget: ResultsTransportBudget,
    ) -> Result<(), ProviderError> {
        let current = self
            .engine
            .inspect_container(&names.job)
            .await
            .map_err(|error| map_provider_engine(error, stage, Some(handle)))?
            .ok_or_else(|| uncertain(ProviderErrorKind::Conflict, stage, handle))?;
        let helper = self
            .engine
            .inspect_container(&names.helper)
            .await
            .map_err(|error| map_provider_engine(error, stage, Some(handle)))?;
        if current.id != expected.id
            || current.image_id != expected.image_id
            || current.definition != expected.definition
            || current.state != EngineContainerState::Running
            || !current.isolated
            || helper.is_some()
        {
            return Err(uncertain(
                ProviderErrorKind::OwnershipMismatch,
                stage,
                handle,
            ));
        }
        let identity = parse_identity(
            &current.definition.labels,
            names,
            &self.installation,
            self.runner_id,
            KIND_JOB,
            stage,
        )?;
        let (proxy, front) = self
            .verify_results_topology(names, &current, &identity, stage, &NeverCancelled, budget)
            .await
            .map_err(|error| recovery(&error, handle))?;
        self.verify_boundary(stage, &NeverCancelled, budget)
            .await
            .map_err(|error| recovery(&error, handle))?;
        let _untrusted_kill = self.engine.kill_container(&current.id).await;
        let stopped = self
            .engine
            .inspect_container(&names.job)
            .await
            .map_err(|error| map_provider_engine(error, stage, Some(handle)))?
            .ok_or_else(|| uncertain(ProviderErrorKind::AdapterUnavailable, stage, handle))?;
        let helper = self
            .engine
            .inspect_container(&names.helper)
            .await
            .map_err(|error| map_provider_engine(error, stage, Some(handle)))?;
        if stopped.id != current.id
            || stopped.image_id != current.image_id
            || stopped.definition != current.definition
            || !matches!(stopped.state, EngineContainerState::Exited(_))
            || !stopped.isolated
            || helper.is_some()
        {
            return Err(uncertain(
                ProviderErrorKind::OwnershipMismatch,
                stage,
                handle,
            ));
        }
        self.require_front_members(&front, Some(&stopped), Some(&proxy), handle)
            .await?;
        self.verify_boundary(stage, &NeverCancelled, budget)
            .await
            .map_err(|error| recovery(&error, handle))?;
        let final_job = self
            .engine
            .inspect_container(&names.job)
            .await
            .map_err(|error| map_provider_engine(error, stage, Some(handle)))?;
        let final_helper = self
            .engine
            .inspect_container(&names.helper)
            .await
            .map_err(|error| map_provider_engine(error, stage, Some(handle)))?;
        if final_job.as_ref() != Some(&stopped) || final_helper.is_some() {
            return Err(uncertain(
                ProviderErrorKind::OwnershipMismatch,
                stage,
                handle,
            ));
        }
        Ok(())
    }

    async fn verify_job(
        &self,
        names: &ResourceNames,
        container: &InspectedContainer,
        stage: ProviderStage,
    ) -> Result<BaseIdentity, ProviderError> {
        let identity = parse_identity(
            &container.definition.labels,
            names,
            &self.installation,
            self.runner_id,
            KIND_JOB,
            stage,
        )?;
        let image = ImmutableImage::new(container.definition.image.clone())
            .map_err(|_| known(ProviderErrorKind::OwnershipMismatch, stage))?;
        let inspected = self
            .verified_image(&image)
            .await
            .map_err(|kind| known(kind, stage))?;
        if inspected.id != container.image_id {
            return Err(known(ProviderErrorKind::OwnershipMismatch, stage));
        }
        let front = self
            .engine
            .inspect_network(&names.results_front)
            .await
            .map_err(|error| map_provider_engine(error, stage, None))?
            .ok_or_else(|| known(ProviderErrorKind::OwnershipMismatch, stage))?;
        let expected_front = front_network_definition(
            names,
            &identity.base_labels,
            &self.installation,
            identity.custody,
        )?;
        verify_front_network(
            &front,
            names,
            &expected_front.labels,
            &expected_front.ipv4_network,
            &names.handle(&self.provider_id)?,
        )?;
        verify_job_definition(
            container,
            names,
            &inspected.labels,
            &inspected.environment_names,
            &identity.base_labels,
            &front,
            stage,
        )?;
        Ok(identity)
    }

    async fn verify_results_topology(
        &self,
        names: &ResourceNames,
        job: &InspectedContainer,
        identity: &BaseIdentity,
        stage: ProviderStage,
        cancellation: &dyn Cancellation,
        budget: ResultsTransportBudget,
    ) -> Result<(InspectedContainer, InspectedNetwork), ProviderError> {
        let handle = names.handle(&self.provider_id)?;
        let front = self
            .engine
            .inspect_network(&names.results_front)
            .await
            .map_err(|error| map_provider_engine(error, stage, None))?
            .ok_or_else(|| known(ProviderErrorKind::OwnershipMismatch, stage))?;
        let expected_front = front_network_definition(
            names,
            &identity.base_labels,
            &self.installation,
            identity.custody,
        )?;
        verify_front_network(
            &front,
            names,
            &expected_front.labels,
            &expected_front.ipv4_network,
            &handle,
        )?;
        let proxy = self
            .engine
            .inspect_container(&names.results_proxy)
            .await
            .map_err(|error| map_provider_engine(error, stage, None))?
            .ok_or_else(|| known(ProviderErrorKind::OwnershipMismatch, stage))?;
        let transit_address = transit_proxy_address(
            &self.results.transit_network,
            self.results.transit_gateway,
            self.results.requested.results_address,
            identity.custody,
        )?;
        let expected = results_proxy_definition(
            names,
            &identity.base_labels,
            &self.results,
            &front,
            transit_address,
        )?;
        verify_container(
            &proxy,
            &expected,
            &self.results.proxy_image_id,
            Some(EngineContainerState::Running),
        )
        .map_err(|_| known(ProviderErrorKind::OwnershipMismatch, stage))?;
        self.wait_for_results_proxy_ready(
            names,
            &proxy,
            &expected,
            &front,
            Some(job),
            &handle,
            stage,
            cancellation,
            budget,
        )
        .await?;
        Ok((proxy, front))
    }

    #[allow(clippy::too_many_arguments)]
    async fn wait_for_results_proxy_ready(
        &self,
        names: &ResourceNames,
        expected_proxy: &InspectedContainer,
        definition: &ContainerDefinition,
        front: &InspectedNetwork,
        job: Option<&InspectedContainer>,
        handle: &SandboxHandle,
        stage: ProviderStage,
        cancellation: &dyn Cancellation,
        budget: ResultsTransportBudget,
    ) -> Result<(), ProviderError> {
        let poll = async {
            loop {
                self.require_exact_results_proxy_topology(
                    names,
                    expected_proxy,
                    definition,
                    front,
                    job,
                    handle,
                    stage,
                )
                .await?;
                let readiness = self
                    .engine
                    .container_logs(&expected_proxy.id, RESULTS_READY_STATUS.len())
                    .await
                    .map_err(|error| map_provider_engine(error, stage, Some(handle)))?;
                if readiness == RESULTS_READY_STATUS {
                    self.require_exact_results_proxy_topology(
                        names,
                        expected_proxy,
                        definition,
                        front,
                        job,
                        handle,
                        stage,
                    )
                    .await?;
                    return Ok(());
                }
                if !readiness.is_empty() {
                    return Err(uncertain(ProviderErrorKind::BackendRejected, stage, handle));
                }
                tokio::time::sleep(RESULTS_PROXY_READINESS_INTERVAL).await;
            }
        };
        tokio::select! {
            biased;
            () = cancellation_requested(cancellation) => Err(uncertain(
                ProviderErrorKind::Cancelled,
                stage,
                handle,
            )),
            result = tokio::time::timeout_at(
                budget.bounded_deadline(RESULTS_PROXY_READINESS_TIMEOUT),
                poll,
            ) => result.unwrap_or_else(|_| Err(uncertain(
                ProviderErrorKind::BackendRejected,
                stage,
                handle,
            ))),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn require_exact_results_proxy_topology(
        &self,
        names: &ResourceNames,
        expected_proxy: &InspectedContainer,
        definition: &ContainerDefinition,
        front: &InspectedNetwork,
        job: Option<&InspectedContainer>,
        handle: &SandboxHandle,
        stage: ProviderStage,
    ) -> Result<(), ProviderError> {
        let proxy = self
            .require_exact_container(
                expected_proxy,
                definition,
                &self.results.proxy_image_id,
                EngineContainerState::Running,
                handle,
            )
            .await?;
        let proxy_by_id = self
            .engine
            .inspect_container(&expected_proxy.id)
            .await
            .map_err(|error| map_provider_engine(error, stage, Some(handle)))?;
        if proxy_by_id.as_ref() != Some(&proxy) {
            return Err(uncertain(
                ProviderErrorKind::OwnershipMismatch,
                stage,
                handle,
            ));
        }
        let current_front = self
            .require_front_members(front, job, Some(&proxy), handle)
            .await?;
        let front_by_name = self
            .engine
            .inspect_network(&names.results_front)
            .await
            .map_err(|error| map_provider_engine(error, stage, Some(handle)))?;
        if front_by_name.as_ref() != Some(&current_front) {
            return Err(uncertain(
                ProviderErrorKind::OwnershipMismatch,
                stage,
                handle,
            ));
        }
        let transit = inspect_exact_results_transit(
            self.engine.as_ref(),
            &self.installation,
            &self.results.requested,
        )
        .await
        .map_err(|error| map_provider_local_docker(error, stage, Some(handle)))?;
        let transit_attachment = definition
            .networks
            .get(&self.results.transit_name)
            .ok_or_else(|| uncertain(ProviderErrorKind::OwnershipMismatch, stage, handle))?;
        let target_running =
            results_target_is_running(self.engine.as_ref(), &self.results.requested)
                .await
                .map_err(|error| map_provider_local_docker(error, stage, Some(handle)))?;
        if transit_attachment.network_id != transit.id
            || !transit.containers.get(&proxy.id).is_some_and(|endpoint| {
                endpoint.name == names.results_proxy
                    && endpoint.ipv4_address == transit_attachment.ipv4_address
                    && endpoint.ipv4_prefix == transit.ipv4_network.prefix
            })
            || !target_running
        {
            return Err(uncertain(
                ProviderErrorKind::OwnershipMismatch,
                stage,
                handle,
            ));
        }
        Ok(())
    }

    fn verify_helper(
        &self,
        names: &ResourceNames,
        helper: &InspectedContainer,
        stage: ProviderStage,
    ) -> Result<BaseIdentity, ProviderError> {
        let identity = parse_identity(
            &helper.definition.labels,
            names,
            &self.installation,
            self.runner_id,
            KIND_GUEST_SOURCE,
            stage,
        )?;
        let expected = helper_definition(
            names,
            self.guest_image.reference(),
            &self.guest_image_labels,
            &self.guest_image_environment,
            &identity.base_labels,
        );
        verify_container(helper, &expected, &self.guest_image_id, None)
            .map_err(|_| known(ProviderErrorKind::OwnershipMismatch, stage))?;
        Ok(identity)
    }

    #[allow(clippy::too_many_lines)]
    async fn inspect(
        &self,
        handle: &SandboxHandle,
        names: &ResourceNames,
        cancellation: &dyn Cancellation,
        budget: ResultsTransportBudget,
    ) -> Result<SandboxInspection, ProviderError> {
        ensure_not_cancelled(cancellation, ProviderStage::Inspect)?;
        self.verify_boundary(ProviderStage::Inspect, cancellation, budget)
            .await?;
        let job = self
            .engine
            .inspect_container(&names.job)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::Inspect, None))?;
        let proxy = self
            .engine
            .inspect_container(&names.results_proxy)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::Inspect, None))?;
        let front = self
            .engine
            .inspect_network(&names.results_front)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::Inspect, None))?;
        let helper = self
            .engine
            .inspect_container(&names.helper)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::Inspect, None))?;
        let job_identity = match job.as_ref() {
            Some(job) => Some(self.verify_job(names, job, ProviderStage::Inspect).await?),
            None => None,
        };
        let helper_identity = match helper.as_ref() {
            Some(helper) => Some(self.verify_helper(names, helper, ProviderStage::Inspect)?),
            None => None,
        };
        let proxy_identity = proxy
            .as_ref()
            .map(|proxy| {
                parse_identity(
                    &proxy.definition.labels,
                    names,
                    &self.installation,
                    self.runner_id,
                    KIND_RESULTS_PROXY,
                    ProviderStage::Inspect,
                )
            })
            .transpose()?;
        let front_identity = front
            .as_ref()
            .map(|front| {
                parse_identity(
                    &front.labels,
                    names,
                    &self.installation,
                    self.runner_id,
                    KIND_RESULTS_FRONT,
                    ProviderStage::Inspect,
                )
            })
            .transpose()?;
        let identity = matching_present_identities(
            [
                job_identity.as_ref(),
                helper_identity.as_ref(),
                proxy_identity.as_ref(),
                front_identity.as_ref(),
            ],
            ProviderStage::Inspect,
        )?;
        if let (Some(job), Some(identity)) = (job.as_ref(), identity)
            && job.state == EngineContainerState::Running
        {
            self.verify_results_topology(
                names,
                job,
                identity,
                ProviderStage::Inspect,
                cancellation,
                budget,
            )
            .await?;
        }
        let state = match (
            job.as_ref(),
            helper.as_ref(),
            proxy.as_ref(),
            front.as_ref(),
        ) {
            (None, None, None, None) => None,
            (Some(job), None, Some(proxy), Some(_))
                if proxy.state == EngineContainerState::Running =>
            {
                Some(match job.state {
                    EngineContainerState::Created => SandboxState::Created,
                    EngineContainerState::Running => SandboxState::Running,
                    EngineContainerState::Exited(_) => SandboxState::Stopped,
                    EngineContainerState::Invalid => SandboxState::Degraded,
                })
            }
            _ => Some(SandboxState::Degraded),
        };
        ensure_not_cancelled(cancellation, ProviderStage::Inspect)?;
        self.verify_boundary(ProviderStage::Inspect, cancellation, budget)
            .await?;
        let current_job = self
            .engine
            .inspect_container(&names.job)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::Inspect, None))?;
        let current_helper = self
            .engine
            .inspect_container(&names.helper)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::Inspect, None))?;
        let current_proxy = self
            .engine
            .inspect_container(&names.results_proxy)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::Inspect, None))?;
        let current_front = self
            .engine
            .inspect_network(&names.results_front)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::Inspect, None))?;
        if current_job != job
            || current_helper != helper
            || current_proxy != proxy
            || current_front != front
        {
            return Err(known(
                ProviderErrorKind::OwnershipMismatch,
                ProviderStage::Inspect,
            ));
        }
        let (Some(identity), Some(state)) = (identity, state) else {
            return Err(known(ProviderErrorKind::NotFound, ProviderStage::Inspect));
        };
        Ok(SandboxInspection::new(
            handle.clone(),
            names.generation_value()?,
            identity.custody,
            identity.profile.clone(),
            state,
        ))
    }

    #[allow(clippy::too_many_lines)]
    async fn destroy(
        &self,
        request: &DestroySandbox,
        names: &ResourceNames,
        cancellation: &dyn Cancellation,
        budget: ResultsTransportBudget,
    ) -> Result<DestroyDisposition, ProviderError> {
        ensure_not_cancelled(cancellation, ProviderStage::DestroySandbox)?;
        self.verify_custody_boundary(ProviderStage::DestroySandbox, cancellation, budget)
            .await?;
        let job = self
            .engine
            .inspect_container_custody(&names.job)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::DestroySandbox, None))?;
        let helper = self
            .engine
            .inspect_container_custody(&names.helper)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::DestroySandbox, None))?;
        let proxy = self
            .engine
            .inspect_container_custody(&names.results_proxy)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::DestroySandbox, None))?;
        let front = self
            .engine
            .inspect_network(&names.results_front)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::DestroySandbox, None))?;
        if job.is_none() && helper.is_none() && proxy.is_none() && front.is_none() {
            ensure_not_cancelled(cancellation, ProviderStage::DestroySandbox)?;
            self.verify_custody_boundary(ProviderStage::DestroySandbox, cancellation, budget)
                .await?;
            self.require_name_absent(&names.job, request.handle())
                .await?;
            self.require_name_absent(&names.helper, request.handle())
                .await?;
            self.require_name_absent(&names.results_proxy, request.handle())
                .await?;
            self.require_network_absent(names, None, request.handle())
                .await?;
            return Ok(DestroyDisposition::AlreadyAbsent);
        }
        let job_identity = match job.as_ref() {
            Some(job) => Some(verify_container_custody(
                job,
                names,
                &self.installation,
                self.runner_id,
                KIND_JOB,
                None,
                ProviderStage::VerifyOwnership,
            )?),
            None => None,
        };
        let helper_identity = match helper.as_ref() {
            Some(helper) => Some(verify_container_custody(
                helper,
                names,
                &self.installation,
                self.runner_id,
                KIND_GUEST_SOURCE,
                None,
                ProviderStage::VerifyOwnership,
            )?),
            None => None,
        };
        let proxy_identity = match proxy.as_ref() {
            Some(proxy) => Some(verify_container_custody(
                proxy,
                names,
                &self.installation,
                self.runner_id,
                KIND_RESULTS_PROXY,
                Some(self.results.requested.proxy_image.reference()),
                ProviderStage::VerifyOwnership,
            )?),
            None => None,
        };
        let front_identity = front
            .as_ref()
            .map(|front| {
                parse_identity(
                    &front.labels,
                    names,
                    &self.installation,
                    self.runner_id,
                    KIND_RESULTS_FRONT,
                    ProviderStage::VerifyOwnership,
                )
            })
            .transpose()?;
        let identity = matching_present_identities(
            [
                job_identity.as_ref(),
                helper_identity.as_ref(),
                proxy_identity.as_ref(),
                front_identity.as_ref(),
            ],
            ProviderStage::VerifyOwnership,
        )?
        .ok_or_else(|| {
            known(
                ProviderErrorKind::OwnershipMismatch,
                ProviderStage::VerifyOwnership,
            )
        })?;
        if identity.custody != request.custody() {
            return Err(known(
                ProviderErrorKind::OwnershipMismatch,
                ProviderStage::VerifyOwnership,
            ));
        }
        if let Some(front) = front.as_ref() {
            let expected_front = front_network_definition(
                names,
                &identity.base_labels,
                &self.installation,
                identity.custody,
            )?;
            verify_front_network(
                front,
                names,
                &expected_front.labels,
                &expected_front.ipv4_network,
                request.handle(),
            )?;
        }
        ensure_not_cancelled(cancellation, ProviderStage::DestroySandbox)?;

        if let Some(helper) = helper.as_ref() {
            self.destroy_container(helper, request.handle(), cancellation, budget)
                .await?;
        }
        if let Some(job) = job.as_ref() {
            self.destroy_container(job, request.handle(), cancellation, budget)
                .await?;
        }
        if let Some(proxy) = proxy.as_ref() {
            self.destroy_container(proxy, request.handle(), cancellation, budget)
                .await?;
        }
        if let Some(front) = front.as_ref() {
            self.destroy_front_network(front, names, request.handle(), cancellation, budget)
                .await?;
        }
        self.verify_custody_boundary(ProviderStage::DestroySandbox, cancellation, budget)
            .await
            .map_err(|error| recovery(&error, request.handle()))?;
        self.require_name_absent(&names.job, request.handle())
            .await?;
        self.require_name_absent(&names.helper, request.handle())
            .await?;
        self.require_name_absent(&names.results_proxy, request.handle())
            .await?;
        self.require_network_absent(names, None, request.handle())
            .await?;
        Ok(DestroyDisposition::Destroyed)
    }

    async fn destroy_container(
        &self,
        snapshot: &InspectedContainerCustody,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
        budget: ResultsTransportBudget,
    ) -> Result<(), ProviderError> {
        let mut current = self.require_exact_custody(snapshot, handle).await?;
        match current.state {
            EngineContainerState::Running => {
                self.verify_custody_boundary(ProviderStage::DestroyContainer, cancellation, budget)
                    .await
                    .map_err(|error| recovery(&error, handle))?;
                current = self.require_exact_custody(snapshot, handle).await?;
                let _untrusted_kill = self.engine.kill_container(&current.id).await;
                current = self.require_exact_custody(snapshot, handle).await?;
                if current.state == EngineContainerState::Running {
                    return Err(uncertain(
                        ProviderErrorKind::InvalidState,
                        ProviderStage::DestroyContainer,
                        handle,
                    ));
                }
                ensure_not_cancelled_after_mutation(
                    cancellation,
                    ProviderStage::DestroyContainer,
                    handle,
                )?;
            }
            EngineContainerState::Created
            | EngineContainerState::Exited(_)
            | EngineContainerState::Invalid => {}
        }
        self.verify_custody_boundary(ProviderStage::DestroyContainer, cancellation, budget)
            .await
            .map_err(|error| recovery(&error, handle))?;
        current = self.require_exact_custody(snapshot, handle).await?;
        let _untrusted_remove = self.engine.remove_container(&current.id).await;
        self.require_custody_absent(&snapshot.name, &snapshot.id, handle)
            .await?;
        self.verify_custody_boundary(ProviderStage::DestroyContainer, cancellation, budget)
            .await
            .map_err(|error| recovery(&error, handle))?;
        ensure_not_cancelled_after_mutation(cancellation, ProviderStage::DestroyContainer, handle)
    }

    async fn require_exact_custody(
        &self,
        snapshot: &InspectedContainerCustody,
        handle: &SandboxHandle,
    ) -> Result<InspectedContainerCustody, ProviderError> {
        let named = self
            .engine
            .inspect_container_custody(&snapshot.name)
            .await
            .map_err(|error| {
                map_provider_engine(error, ProviderStage::VerifyOwnership, Some(handle))
            })?;
        let identified = self
            .engine
            .inspect_container_custody(&snapshot.id)
            .await
            .map_err(|error| {
                map_provider_engine(error, ProviderStage::VerifyOwnership, Some(handle))
            })?
            .ok_or_else(|| {
                uncertain(
                    ProviderErrorKind::Conflict,
                    ProviderStage::VerifyOwnership,
                    handle,
                )
            })?;
        if !same_container_custody(snapshot, &identified)
            || named
                .as_ref()
                .is_some_and(|current| !same_container_custody(snapshot, current))
        {
            return Err(uncertain(
                ProviderErrorKind::OwnershipMismatch,
                ProviderStage::VerifyOwnership,
                handle,
            ));
        }
        Ok(identified)
    }

    async fn require_custody_absent(
        &self,
        name: &str,
        id: &str,
        handle: &SandboxHandle,
    ) -> Result<(), ProviderError> {
        let named = self
            .engine
            .inspect_container_custody(name)
            .await
            .map_err(|error| {
                map_provider_engine(error, ProviderStage::DestroyContainer, Some(handle))
            })?;
        let identified = self
            .engine
            .inspect_container_custody(id)
            .await
            .map_err(|error| {
                map_provider_engine(error, ProviderStage::DestroyContainer, Some(handle))
            })?;
        match (named, identified) {
            (None, None) => Ok(()),
            (Some(current), None) if current.id != id => Err(uncertain(
                ProviderErrorKind::Conflict,
                ProviderStage::DestroyContainer,
                handle,
            )),
            _ => Err(uncertain(
                ProviderErrorKind::AdapterUnavailable,
                ProviderStage::DestroyContainer,
                handle,
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResourceNames {
    installation_id: String,
    operation_id: OperationId,
    generation: u64,
    job: String,
    helper: String,
    results_front: String,
    results_proxy: String,
}

impl ResourceNames {
    fn for_spec(installation: &Installation, spec: &SandboxSpec) -> Result<Self, ProviderError> {
        Self::new(installation, spec.operation_id(), spec.generation().get())
    }

    fn from_handle(
        provider: &ProviderId,
        installation: &Installation,
        handle: &SandboxHandle,
    ) -> Result<Self, ProviderError> {
        if handle.provider() != provider {
            return Err(invalid_handle());
        }
        let mut fields = handle.opaque().split('.');
        if fields.next() != Some("ld") {
            return Err(invalid_handle());
        }
        let installation_text = fields.next().ok_or_else(invalid_handle)?;
        let operation_text = fields.next().ok_or_else(invalid_handle)?;
        let generation_text = fields.next().ok_or_else(invalid_handle)?;
        if fields.next().is_some()
            || InstallationId::parse_canonical(installation_text) != Some(installation.id())
        {
            return Err(invalid_handle());
        }
        let operation_id = OperationId::from_str(operation_text).map_err(|_| invalid_handle())?;
        let generation = generation_text
            .parse::<u64>()
            .ok()
            .filter(|value| value.to_string() == generation_text)
            .ok_or_else(invalid_handle)?;
        SandboxGeneration::new(generation).map_err(|_| invalid_handle())?;
        if operation_id.to_string() != operation_text {
            return Err(invalid_handle());
        }
        Self::new(installation, operation_id, generation)
    }

    fn new(
        installation: &Installation,
        operation_id: OperationId,
        generation: u64,
    ) -> Result<Self, ProviderError> {
        SandboxGeneration::new(generation).map_err(|_| invalid_handle())?;
        let base = format!(
            "automata-local-{}-{}-{generation}",
            installation.id().as_uuid().simple(),
            operation_id.as_uuid().simple()
        );
        Ok(Self {
            installation_id: installation.id().to_string(),
            operation_id,
            generation,
            job: format!("{base}-job"),
            helper: format!("{base}-guest-source"),
            results_front: format!("{base}-results-front"),
            results_proxy: format!("{base}-results-proxy"),
        })
    }

    fn handle(&self, provider: &ProviderId) -> Result<SandboxHandle, ProviderError> {
        SandboxHandle::new(
            provider.clone(),
            format!(
                "ld.{}.{}.{}",
                self.installation_id, self.operation_id, self.generation
            ),
        )
        .map_err(|_| invalid_handle())
    }

    fn generation_value(&self) -> Result<SandboxGeneration, ProviderError> {
        SandboxGeneration::new(self.generation).map_err(|_| invalid_handle())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BaseIdentity {
    base_labels: BTreeMap<String, String>,
    custody: SandboxCustody,
    profile: EnvironmentProfile,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AttachedIdentity {
    container_id: String,
    definition: ContainerDefinition,
    base_labels: BTreeMap<String, String>,
    proxy_id: String,
    proxy_definition: ContainerDefinition,
    front_id: String,
}

fn validate_spec(spec: &SandboxSpec, runner_id: RunnerId) -> Result<(), ProviderError> {
    let SandboxLaunch::Container { .. } = spec.profile().launch() else {
        return Err(known(
            ProviderErrorKind::UnsupportedPlatform,
            ProviderStage::Validate,
        ));
    };
    let profile_workspace = spec.profile().workspace();
    let workspace = spec.workspace();
    let workspace_prefix = format!("{}/", profile_workspace.as_str().trim_end_matches('/'));
    let workspace_conflicts_with_control = workspace.as_str() == "/"
        || workspace.as_str() == "/automata"
        || workspace.as_str().starts_with("/automata/")
        || workspace.as_str() == LOCAL_CONTROL_DIRECTORY
        || workspace
            .as_str()
            .starts_with(&format!("{LOCAL_CONTROL_DIRECTORY}/"));
    let custody_runner = match spec.custody() {
        SandboxCustody::ProfileAdmission { runner_id } | SandboxCustody::Job { runner_id, .. } => {
            runner_id
        }
    };
    let custody_valid = custody_runner == runner_id
        && match spec.custody() {
            SandboxCustody::ProfileAdmission { .. } => true,
            SandboxCustody::Job { slot_ordinal, .. } => {
                slot_ordinal.get() <= crate::MAXIMUM_LOCAL_DOCKER_JOB_SLOTS
            }
        };
    if !custody_valid
        || workspace.platform() != TargetPlatform::Posix
        || profile_workspace.platform() != TargetPlatform::Posix
        || (workspace != profile_workspace && !workspace.as_str().starts_with(&workspace_prefix))
        || workspace_conflicts_with_control
        || spec.scratch().is_some()
        || !spec.services().is_empty()
        || !spec.sandbox_authorizations().as_slice().is_empty()
        || !spec.runtime_service_routes().is_empty()
        || spec.network() != NetworkPolicy::PrivateEgress
        || spec.root_filesystem() != RootFilesystemPolicy::Writable
        || spec.privilege() != SandboxPrivilegePolicy::Administrator
    {
        return Err(known(
            ProviderErrorKind::UnsupportedCapability,
            ProviderStage::Validate,
        ));
    }
    if !spec.has_coherent_resource_contract() {
        return Err(invalid_configuration());
    }
    let resources = spec.resources();
    if resources.memory_bytes() < MINIMUM_LOCAL_DOCKER_SANDBOX_MEMORY_BYTES
        || resources.cpu_millis() < MINIMUM_LOCAL_DOCKER_SANDBOX_CPU_MILLIS
        || resources.pids() < MINIMUM_LOCAL_DOCKER_SANDBOX_PIDS
    {
        return Err(invalid_configuration());
    }
    if spec.resource_allocation().is_some_and(|allocation| {
        allocation.limits().ephemeral_disk_bytes() != 0
            || allocation.limits().gpu_count() != 0
            || allocation.requests().ephemeral_disk_bytes() != 0
            || allocation.requests().gpu_count() != 0
    }) {
        return Err(known(
            ProviderErrorKind::UnsupportedCapability,
            ProviderStage::Validate,
        ));
    }
    Ok(())
}

fn base_labels(
    spec: &SandboxSpec,
    installation: &Installation,
    fingerprint: &str,
) -> BTreeMap<String, String> {
    let runner_id = match spec.custody() {
        SandboxCustody::ProfileAdmission { runner_id } | SandboxCustody::Job { runner_id, .. } => {
            runner_id
        }
    };
    let mut labels = BTreeMap::from([
        (LABEL_MANAGED.to_owned(), MANAGED_VALUE.to_owned()),
        (LABEL_JOB_SCHEMA.to_owned(), JOB_SCHEMA.to_owned()),
        (
            LABEL_INSTALLATION_ID.to_owned(),
            installation.id().to_string(),
        ),
        (
            LABEL_INSTALLATION_KEY.to_owned(),
            installation.selector_key().to_string(),
        ),
        (
            LABEL_COMPOSE_PROJECT.to_owned(),
            installation.compose_project().to_string(),
        ),
        (LABEL_RUNNER_ID.to_owned(), runner_id.to_string()),
        (
            LABEL_OPERATION_ID.to_owned(),
            spec.operation_id().to_string(),
        ),
        (
            LABEL_GENERATION.to_owned(),
            spec.generation().get().to_string(),
        ),
        (
            LABEL_PROFILE.to_owned(),
            spec.profile().id().as_str().to_owned(),
        ),
        (
            LABEL_PROFILE_DIGEST.to_owned(),
            spec.profile().digest().to_string(),
        ),
        (LABEL_SPEC_DIGEST.to_owned(), fingerprint.to_owned()),
    ]);
    match spec.custody() {
        SandboxCustody::ProfileAdmission { .. } => {
            labels.insert(LABEL_CUSTODY_KIND.to_owned(), CUSTODY_ADMISSION.to_owned());
        }
        SandboxCustody::Job { slot_ordinal, .. } => {
            labels.insert(LABEL_CUSTODY_KIND.to_owned(), CUSTODY_JOB.to_owned());
            labels.insert(LABEL_SLOT.to_owned(), slot_ordinal.get().to_string());
        }
    }
    labels
}

fn resource_labels(
    image_labels: &BTreeMap<String, String>,
    base: &BTreeMap<String, String>,
    kind: &str,
) -> BTreeMap<String, String> {
    let mut labels = image_labels.clone();
    labels.extend(base.clone());
    labels.insert(LABEL_RESOURCE_KIND.to_owned(), kind.to_owned());
    labels
}

fn seal_container_definition(mut definition: ContainerDefinition) -> ContainerDefinition {
    reseal_container_definition(&mut definition);
    definition
}

fn reseal_container_definition(definition: &mut ContainerDefinition) {
    definition.labels.remove(LABEL_REALIZED_DIGEST);
    let digest = realized_container_digest(definition);
    definition
        .labels
        .insert(LABEL_REALIZED_DIGEST.to_owned(), digest.to_string());
}

fn realized_container_digest(definition: &ContainerDefinition) -> Sha256Digest {
    let mut digest = Sha256::new();
    hash_field(&mut digest, b"automata-local-docker-realized-container-v1");
    for value in [
        definition.name.as_str(),
        definition.image.as_str(),
        definition.entrypoint.as_str(),
        definition.working_directory.as_str(),
        definition.user.as_str(),
    ] {
        hash_field(&mut digest, value.as_bytes());
    }
    for value in &definition.arguments {
        hash_field(&mut digest, value.as_bytes());
    }
    for (key, value) in &definition.labels {
        if key != LABEL_REALIZED_DIGEST {
            hash_field(&mut digest, key.as_bytes());
            hash_field(&mut digest, value.as_bytes());
        }
    }
    for value in &definition.environment {
        hash_field(&mut digest, value.as_bytes());
    }
    for (path, options) in &definition.tmpfs {
        hash_field(&mut digest, path.as_bytes());
        hash_field(&mut digest, options.as_bytes());
    }
    hash_field(&mut digest, &[u8::from(definition.read_only_root)]);
    hash_field(&mut digest, &definition.memory_bytes.to_be_bytes());
    hash_field(&mut digest, &definition.nano_cpus.to_be_bytes());
    hash_field(&mut digest, &definition.pids_limit.to_be_bytes());
    hash_field(
        &mut digest,
        definition
            .primary_network
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
    );
    for (name, attachment) in &definition.networks {
        hash_field(&mut digest, name.as_bytes());
        hash_field(&mut digest, attachment.network_id.as_bytes());
        hash_field(&mut digest, &attachment.ipv4_address.octets());
        for alias in &attachment.aliases {
            hash_field(&mut digest, alias.as_bytes());
        }
    }
    hash_field(&mut digest, &[u8::from(definition.capture_logs)]);
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn exact_realized_container_digest(container: &InspectedContainer) -> bool {
    container
        .definition
        .labels
        .get(LABEL_REALIZED_DIGEST)
        .and_then(|value| Sha256Digest::from_str(value).ok())
        .is_some_and(|value| value == realized_container_digest(&container.definition))
}

fn helper_definition(
    names: &ResourceNames,
    guest_image: &str,
    image_labels: &BTreeMap<String, String>,
    environment: &[String],
    base_labels: &BTreeMap<String, String>,
) -> ContainerDefinition {
    seal_container_definition(ContainerDefinition {
        name: names.helper.clone(),
        image: guest_image.to_owned(),
        entrypoint: LOCAL_DOCKER_GUEST_IMAGE_BINARY.to_owned(),
        arguments: Vec::new(),
        labels: resource_labels(image_labels, base_labels, KIND_GUEST_SOURCE),
        environment: environment.to_vec(),
        tmpfs: BTreeMap::new(),
        working_directory: "/".to_owned(),
        user: guest_client_user(),
        read_only_root: true,
        memory_bytes: HELPER_MEMORY_BYTES,
        nano_cpus: HELPER_NANO_CPUS,
        pids_limit: HELPER_PIDS,
        primary_network: None,
        networks: BTreeMap::new(),
        capture_logs: false,
    })
}

fn job_definition(
    names: &ResourceNames,
    spec: &SandboxSpec,
    image: &str,
    image_labels: &BTreeMap<String, String>,
    environment_names: &[String],
    base_labels: &BTreeMap<String, String>,
    front: &FrontNetworkDefinition,
) -> Result<ContainerDefinition, ProviderError> {
    let resources = spec.resources();
    let memory_bytes =
        i64::try_from(resources.memory_bytes()).map_err(|_| invalid_configuration())?;
    let nano_cpus = i64::from(resources.cpu_millis())
        .checked_mul(1_000_000)
        .ok_or_else(invalid_configuration)?;
    Ok(seal_container_definition(ContainerDefinition {
        name: names.job.clone(),
        image: image.to_owned(),
        entrypoint: LOCAL_DOCKER_SANDBOX_GUEST_BINARY.to_owned(),
        arguments: vec!["serve-local".to_owned()],
        labels: resource_labels(image_labels, base_labels, KIND_JOB),
        environment: neutral_environment(environment_names),
        tmpfs: BTreeMap::from([
            (
                spec.workspace().as_str().to_owned(),
                job_tmpfs_options(memory_bytes),
            ),
            (
                LOCAL_CONTROL_DIRECTORY.to_owned(),
                guest_control_tmpfs_options(),
            ),
        ]),
        working_directory: spec.workspace().as_str().to_owned(),
        user: "0:0".to_owned(),
        read_only_root: false,
        memory_bytes,
        nano_cpus,
        pids_limit: i64::from(resources.pids()),
        primary_network: Some(front.name.clone()),
        networks: BTreeMap::from([(
            front.name.clone(),
            ContainerNetworkAttachment {
                network_id: String::new(),
                ipv4_address: network_host_address(&front.ipv4_network, 3)?,
                aliases: Vec::new(),
            },
        )]),
        capture_logs: false,
    }))
}

fn results_proxy_definition(
    names: &ResourceNames,
    base_labels: &BTreeMap<String, String>,
    results: &VerifiedResultsTransport,
    front: &InspectedNetwork,
    transit_address: Ipv4Addr,
) -> Result<ContainerDefinition, ProviderError> {
    results_proxy_definition_for_front(
        names,
        base_labels,
        results,
        &front.name,
        &front.id,
        &front.ipv4_network,
        transit_address,
    )
}

fn planned_results_proxy_definition(
    names: &ResourceNames,
    base_labels: &BTreeMap<String, String>,
    results: &VerifiedResultsTransport,
    front: &FrontNetworkDefinition,
    transit_address: Ipv4Addr,
) -> Result<ContainerDefinition, ProviderError> {
    results_proxy_definition_for_front(
        names,
        base_labels,
        results,
        &front.name,
        "",
        &front.ipv4_network,
        transit_address,
    )
}

#[allow(clippy::too_many_arguments)]
fn results_proxy_definition_for_front(
    names: &ResourceNames,
    base_labels: &BTreeMap<String, String>,
    results: &VerifiedResultsTransport,
    front_name: &str,
    front_id: &str,
    front_network: &Ipv4Network,
    transit_address: Ipv4Addr,
) -> Result<ContainerDefinition, ProviderError> {
    let front_address = network_host_address(front_network, 2)?;
    let job_address = network_host_address(front_network, 3)?;
    Ok(seal_container_definition(ContainerDefinition {
        name: names.results_proxy.clone(),
        image: results.requested.proxy_image.reference().to_owned(),
        entrypoint: RESULTS_PROXY_ENTRYPOINT.to_owned(),
        arguments: vec![
            RESULTS_PROXY_COMMAND.to_owned(),
            front_address.to_string(),
            front_network.canonical(),
            job_address.to_string(),
            results.transit_network.canonical(),
            results.requested.results_address.to_string(),
        ],
        labels: resource_labels(&results.proxy_image_labels, base_labels, KIND_RESULTS_PROXY),
        environment: vec!["PATH=".to_owned()],
        tmpfs: BTreeMap::new(),
        working_directory: "/".to_owned(),
        user: RESULTS_PROXY_USER.to_owned(),
        read_only_root: true,
        memory_bytes: RESULTS_PROXY_MEMORY_BYTES,
        nano_cpus: RESULTS_PROXY_NANO_CPUS,
        pids_limit: RESULTS_PROXY_PIDS,
        primary_network: Some(front_name.to_owned()),
        networks: BTreeMap::from([
            (
                front_name.to_owned(),
                ContainerNetworkAttachment {
                    network_id: front_id.to_owned(),
                    ipv4_address: front_address,
                    aliases: vec![RESULTS_ALIAS.to_owned()],
                },
            ),
            (
                results.transit_name.clone(),
                ContainerNetworkAttachment {
                    network_id: results.requested.transit_network_id.clone(),
                    ipv4_address: transit_address,
                    aliases: Vec::new(),
                },
            ),
        ]),
        capture_logs: true,
    }))
}

fn bind_front_network(definition: &mut ContainerDefinition, front: &InspectedNetwork) {
    let attachment = definition
        .networks
        .get_mut(&front.name)
        .expect("the precomputed definition contains the deterministic front network");
    debug_assert!(attachment.network_id.is_empty());
    attachment.network_id.clone_from(&front.id);
    reseal_container_definition(definition);
}

fn front_proxy_address(network: &InspectedNetwork) -> Result<Ipv4Addr, ProviderError> {
    network_host_address(&network.ipv4_network, 2)
}

fn front_job_address(network: &InspectedNetwork) -> Result<Ipv4Addr, ProviderError> {
    network_host_address(&network.ipv4_network, 3)
}

fn network_host_address(network: &Ipv4Network, offset: u32) -> Result<Ipv4Addr, ProviderError> {
    u32::from(network.network)
        .checked_add(offset)
        .map(Ipv4Addr::from)
        .filter(|address| network.usable(*address))
        .ok_or_else(invalid_configuration)
}

fn custody_network_index(custody: SandboxCustody) -> Result<u16, ProviderError> {
    match custody {
        SandboxCustody::ProfileAdmission { .. } => Ok(0),
        SandboxCustody::Job { slot_ordinal, .. }
            if slot_ordinal.get() <= crate::MAXIMUM_LOCAL_DOCKER_JOB_SLOTS =>
        {
            Ok(slot_ordinal.get())
        }
        SandboxCustody::Job { .. } => Err(invalid_configuration()),
    }
}

fn results_front_pool(installation: &Installation) -> Ipv4Network {
    let selector = installation.selector_key().digest();
    let bytes = selector.as_bytes();
    let bucket = (u32::from(bytes[0]) << 4) | (u32::from(bytes[1]) >> 4);
    Ipv4Network {
        network: Ipv4Addr::from((u32::from(Ipv4Addr::new(10, 0, 0, 0))) | (bucket << 12)),
        prefix: RESULTS_FRONT_POOL_PREFIX,
    }
}

fn results_front_network(
    installation: &Installation,
    custody: SandboxCustody,
) -> Result<Ipv4Network, ProviderError> {
    let pool = results_front_pool(installation);
    let index = u32::from(custody_network_index(custody)?);
    let network = u32::from(pool.network)
        .checked_add(index << (32 - RESULTS_FRONT_NETWORK_PREFIX))
        .map(Ipv4Addr::from)
        .ok_or_else(invalid_configuration)?;
    let result = Ipv4Network {
        network,
        prefix: RESULTS_FRONT_NETWORK_PREFIX,
    };
    if !pool.contains(result.network) || !pool.contains(result.broadcast()) {
        return Err(invalid_configuration());
    }
    Ok(result)
}

fn front_network_definition(
    names: &ResourceNames,
    base_labels: &BTreeMap<String, String>,
    installation: &Installation,
    custody: SandboxCustody,
) -> Result<FrontNetworkDefinition, ProviderError> {
    let ipv4_network = results_front_network(installation, custody)?;
    let ipv4_gateway = network_host_address(&ipv4_network, 1)?;
    Ok(seal_front_network_definition(FrontNetworkDefinition {
        name: names.results_front.clone(),
        labels: front_network_labels(base_labels),
        ipv4_network,
        ipv4_gateway,
    }))
}

fn transit_proxy_address(
    network: &Ipv4Network,
    gateway: Ipv4Addr,
    results_address: Ipv4Addr,
    custody: SandboxCustody,
) -> Result<Ipv4Addr, ProviderError> {
    let index = usize::from(custody_network_index(custody)?);
    let host_count = 1_u32
        .checked_shl(u32::from(32 - network.prefix))
        .and_then(|count| count.checked_sub(1))
        .ok_or_else(invalid_configuration)?;
    (1..host_count)
        .filter_map(|offset| network_host_address(network, offset).ok())
        .filter(|address| *address != gateway && *address != results_address)
        .nth(index)
        .ok_or_else(invalid_configuration)
}

fn front_network_labels(base_labels: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut labels = base_labels.clone();
    labels.insert(
        LABEL_RESOURCE_KIND.to_owned(),
        KIND_RESULTS_FRONT.to_owned(),
    );
    labels
}

fn seal_front_network_definition(mut definition: FrontNetworkDefinition) -> FrontNetworkDefinition {
    definition.labels.remove(LABEL_REALIZED_DIGEST);
    let mut digest = Sha256::new();
    hash_field(&mut digest, b"automata-local-docker-realized-network-v1");
    hash_field(&mut digest, definition.name.as_bytes());
    for (key, value) in &definition.labels {
        if key != LABEL_REALIZED_DIGEST {
            hash_field(&mut digest, key.as_bytes());
            hash_field(&mut digest, value.as_bytes());
        }
    }
    hash_field(&mut digest, &definition.ipv4_network.network.octets());
    hash_field(&mut digest, &[definition.ipv4_network.prefix]);
    hash_field(&mut digest, &definition.ipv4_gateway.octets());
    definition.labels.insert(
        LABEL_REALIZED_DIGEST.to_owned(),
        Sha256Digest::from_bytes(digest.finalize().into()).to_string(),
    );
    definition
}

fn verify_front_network(
    network: &InspectedNetwork,
    names: &ResourceNames,
    labels: &BTreeMap<String, String>,
    ipv4_network: &Ipv4Network,
    handle: &SandboxHandle,
) -> Result<(), ProviderError> {
    if !canonical_object_id(&network.id)
        || !exact_closed_network(network, &names.results_front, labels)
        || network.ipv4_network != *ipv4_network
        || network.ipv4_gateway
            != network_host_address(ipv4_network, 1).map_err(|_| {
                uncertain(
                    ProviderErrorKind::OwnershipMismatch,
                    ProviderStage::VerifyOwnership,
                    handle,
                )
            })?
        || front_proxy_address(network).is_err()
        || front_job_address(network).is_err()
    {
        return Err(uncertain(
            ProviderErrorKind::OwnershipMismatch,
            ProviderStage::VerifyOwnership,
            handle,
        ));
    }
    Ok(())
}

fn job_tmpfs_options(memory_bytes: i64) -> String {
    format!("rw,exec,nosuid,nodev,size={memory_bytes},mode=0777,uid=0,gid=0")
}

fn extract_single_guest(archive: &[u8]) -> Result<Vec<u8>, ProviderError> {
    if archive.is_empty() || archive.len() > LOCAL_DOCKER_GUEST_ARCHIVE_BYTES {
        return Err(known(
            ProviderErrorKind::OutputLimitExceeded,
            ProviderStage::VerifyOwnership,
        ));
    }
    let mut tar = tar::Archive::new(Cursor::new(archive));
    let mut entries = tar.entries().map_err(|_| {
        known(
            ProviderErrorKind::BackendRejected,
            ProviderStage::VerifyOwnership,
        )
    })?;
    let mut entry = entries
        .next()
        .transpose()
        .map_err(|_| {
            known(
                ProviderErrorKind::BackendRejected,
                ProviderStage::VerifyOwnership,
            )
        })?
        .ok_or_else(|| {
            known(
                ProviderErrorKind::BackendRejected,
                ProviderStage::VerifyOwnership,
            )
        })?;
    let path = entry.path().map_err(|_| {
        known(
            ProviderErrorKind::BackendRejected,
            ProviderStage::VerifyOwnership,
        )
    })?;
    let expected_size = usize::try_from(entry.size()).map_err(|_| {
        known(
            ProviderErrorKind::OutputLimitExceeded,
            ProviderStage::VerifyOwnership,
        )
    })?;
    let expected_path = std::path::Path::new(LOCAL_DOCKER_GUEST_IMAGE_BINARY)
        .file_name()
        .ok_or_else(invalid_configuration)?;
    if path.as_ref() != std::path::Path::new(expected_path)
        || !entry.header().entry_type().is_file()
        || expected_size == 0
        || expected_size > max_guest_binary_bytes()
    {
        return Err(known(
            ProviderErrorKind::BackendRejected,
            ProviderStage::VerifyOwnership,
        ));
    }
    let mut bytes = Vec::with_capacity(expected_size);
    (&mut entry)
        .take(MAX_LOCAL_GUEST_BINARY_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            known(
                ProviderErrorKind::BackendRejected,
                ProviderStage::VerifyOwnership,
            )
        })?;
    drop(entry);
    if entries
        .next()
        .transpose()
        .map_err(|_| {
            known(
                ProviderErrorKind::BackendRejected,
                ProviderStage::VerifyOwnership,
            )
        })?
        .is_some()
        || bytes.len() != expected_size
        || bytes.len() > max_guest_binary_bytes()
    {
        return Err(known(
            ProviderErrorKind::BackendRejected,
            ProviderStage::VerifyOwnership,
        ));
    }
    Ok(bytes)
}

fn sandbox_archive_definition(workspace: &str) -> Result<SandboxArchiveDefinition, ProviderError> {
    const TAR_BLOCK_BYTES: usize = 512;
    const TAR_END_BYTES: usize = TAR_BLOCK_BYTES * 2;

    let mut directories = BTreeSet::from(["automata".to_owned(), "automata/bin".to_owned()]);
    let mut current = String::new();
    for component in workspace.trim_start_matches('/').split('/') {
        if component.is_empty() {
            return Err(invalid_configuration());
        }
        if !current.is_empty() {
            current.push('/');
        }
        current.push_str(component);
        directories.insert(current.clone());
    }
    let mut directory_headers = Vec::with_capacity(directories.len());
    for directory in directories {
        let mode = if directory == "automata" || directory == "automata/bin" {
            0o755
        } else {
            0o777
        };
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::Directory);
        header.set_mode(mode);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(0);
        header
            .set_path(&directory)
            .map_err(|_| invalid_configuration())?;
        header.set_cksum();
        directory_headers.push(header);
    }
    let mut guest_header = Header::new_gnu();
    guest_header.set_entry_type(EntryType::Regular);
    guest_header.set_mode(0o555);
    guest_header.set_uid(0);
    guest_header.set_gid(0);
    guest_header.set_mtime(0);
    guest_header.set_size(0);
    guest_header
        .set_path(
            LOCAL_DOCKER_SANDBOX_GUEST_BINARY
                .strip_prefix('/')
                .ok_or_else(invalid_configuration)?,
        )
        .map_err(|_| invalid_configuration())?;
    guest_header.set_cksum();

    let maximum_guest_blocks = max_guest_binary_bytes()
        .checked_add(TAR_BLOCK_BYTES - 1)
        .and_then(|bytes| bytes.checked_div(TAR_BLOCK_BYTES))
        .and_then(|blocks| blocks.checked_mul(TAR_BLOCK_BYTES))
        .ok_or_else(invalid_configuration)?;
    let maximum_archive_bytes = directory_headers
        .len()
        .checked_add(1)
        .and_then(|headers| headers.checked_mul(TAR_BLOCK_BYTES))
        .and_then(|bytes| bytes.checked_add(maximum_guest_blocks))
        .and_then(|bytes| bytes.checked_add(TAR_END_BYTES))
        .ok_or_else(invalid_configuration)?;
    if maximum_archive_bytes > LOCAL_DOCKER_GUEST_ARCHIVE_BYTES {
        return Err(invalid_configuration());
    }
    Ok(SandboxArchiveDefinition {
        directory_headers,
        guest_header,
    })
}

fn sandbox_archive(
    definition: &SandboxArchiveDefinition,
    guest: &[u8],
) -> Result<Vec<u8>, ProviderError> {
    if guest.is_empty() || guest.len() > max_guest_binary_bytes() {
        return Err(invalid_configuration());
    }
    let mut builder = TarBuilder::new(Vec::new());
    for header in &definition.directory_headers {
        builder
            .append(header, std::io::empty())
            .map_err(|_| invalid_configuration())?;
    }
    let mut guest_header = definition.guest_header.clone();
    guest_header.set_size(u64::try_from(guest.len()).map_err(|_| invalid_configuration())?);
    guest_header.set_cksum();
    builder
        .append(&guest_header, guest)
        .map_err(|_| invalid_configuration())?;
    let archive = builder.into_inner().map_err(|_| invalid_configuration())?;
    if archive.len() > LOCAL_DOCKER_GUEST_ARCHIVE_BYTES {
        return Err(invalid_configuration());
    }
    Ok(archive)
}

fn spec_fingerprint(
    spec: &SandboxSpec,
    installation: &Installation,
    guest_image: &ImmutableImage,
    results: &VerifiedResultsTransport,
) -> Result<String, ProviderError> {
    let mut digest = Sha256::new();
    hash_field(&mut digest, b"automata-local-docker-sandbox-spec-v3");
    hash_field(&mut digest, installation.id().as_uuid().as_bytes());
    hash_field(
        &mut digest,
        installation.selector_key().to_string().as_bytes(),
    );
    hash_field(
        &mut digest,
        installation.compose_project().as_str().as_bytes(),
    );
    hash_field(&mut digest, spec.operation_id().as_uuid().as_bytes());
    hash_field(&mut digest, &spec.generation().get().to_be_bytes());
    hash_custody(&mut digest, spec.custody());
    hash_field(&mut digest, spec.profile().id().as_str().as_bytes());
    hash_field(&mut digest, spec.profile().digest().as_bytes());
    let SandboxLaunch::Container { image, keepalive } = spec.profile().launch() else {
        return Err(invalid_configuration());
    };
    hash_field(&mut digest, image.reference().as_bytes());
    hash_field(&mut digest, keepalive.program().as_str().as_bytes());
    for argument in keepalive.arguments() {
        hash_field(&mut digest, argument.as_bytes());
    }
    hash_field(&mut digest, spec.profile().workspace().as_str().as_bytes());
    for variable in spec.profile().default_environment().values() {
        hash_field(&mut digest, variable.name().as_str().as_bytes());
        hash_field(&mut digest, variable.value().expose().as_bytes());
        hash_field(&mut digest, &[u8::from(variable.is_secret())]);
    }
    hash_field(&mut digest, spec.workspace().as_str().as_bytes());
    hash_field(
        &mut digest,
        &[
            spec.network() as u8,
            spec.root_filesystem() as u8,
            spec.privilege() as u8,
        ],
    );
    let resources = spec.resources();
    hash_field(&mut digest, &resources.memory_bytes().to_be_bytes());
    hash_field(&mut digest, &resources.cpu_millis().to_be_bytes());
    hash_field(&mut digest, &resources.pids().to_be_bytes());
    match spec.resource_allocation() {
        Some(allocation) => {
            hash_field(&mut digest, &[1]);
            for resources in [allocation.requests(), allocation.limits()] {
                hash_field(&mut digest, &resources.cpu_millis().to_be_bytes());
                hash_field(&mut digest, &resources.memory_bytes().to_be_bytes());
                hash_field(&mut digest, &resources.ephemeral_disk_bytes().to_be_bytes());
                hash_field(&mut digest, &resources.gpu_count().to_be_bytes());
            }
        }
        None => hash_field(&mut digest, &[0]),
    }
    hash_field(&mut digest, guest_image.reference().as_bytes());
    hash_field(
        &mut digest,
        results.requested.proxy_image.reference().as_bytes(),
    );
    hash_field(
        &mut digest,
        results.requested.proxy_image.config_image_id().as_bytes(),
    );
    hash_field(
        &mut digest,
        results.requested.proxy_image.manifest_image_id().as_bytes(),
    );
    hash_field(&mut digest, results.requested.plan_digest.as_bytes());
    hash_field(&mut digest, results.requested.transit_network_id.as_bytes());
    hash_field(
        &mut digest,
        results.requested.results_container_id.as_bytes(),
    );
    hash_field(&mut digest, &results.requested.results_address.octets());
    Ok(Sha256Digest::from_bytes(digest.finalize().into()).to_string())
}

fn hash_custody(digest: &mut Sha256, custody: SandboxCustody) {
    match custody {
        SandboxCustody::ProfileAdmission { runner_id } => {
            hash_field(digest, CUSTODY_ADMISSION.as_bytes());
            hash_field(digest, runner_id.as_uuid().as_bytes());
        }
        SandboxCustody::Job {
            runner_id,
            slot_ordinal,
        } => {
            hash_field(digest, CUSTODY_JOB.as_bytes());
            hash_field(digest, runner_id.as_uuid().as_bytes());
            hash_field(digest, &slot_ordinal.get().to_be_bytes());
        }
    }
}

fn hash_field(digest: &mut Sha256, value: &[u8]) {
    digest.update(
        u64::try_from(value.len())
            .expect("sandbox fingerprint fields fit in u64")
            .to_be_bytes(),
    );
    digest.update(value);
}

fn parse_identity(
    labels: &BTreeMap<String, String>,
    names: &ResourceNames,
    installation: &Installation,
    expected_runner_id: RunnerId,
    resource_kind: &str,
    stage: ProviderStage,
) -> Result<BaseIdentity, ProviderError> {
    let managed = managed_labels(labels);
    let required = |key: &str| {
        managed
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| known(ProviderErrorKind::OwnershipMismatch, stage))
    };
    if required(LABEL_MANAGED)? != MANAGED_VALUE
        || required(LABEL_JOB_SCHEMA)? != JOB_SCHEMA
        || required(LABEL_INSTALLATION_ID)? != installation.id().to_string()
        || required(LABEL_INSTALLATION_KEY)? != installation.selector_key().to_string()
        || required(LABEL_COMPOSE_PROJECT)? != installation.compose_project().as_str()
        || required(LABEL_OPERATION_ID)? != names.operation_id.to_string()
        || required(LABEL_GENERATION)? != names.generation.to_string()
        || required(LABEL_RESOURCE_KIND)? != resource_kind
    {
        return Err(known(ProviderErrorKind::OwnershipMismatch, stage));
    }
    let runner_text = required(LABEL_RUNNER_ID)?;
    let runner_id = RunnerId::from_str(runner_text)
        .ok()
        .filter(|value| value.to_string() == runner_text)
        .filter(|value| *value == expected_runner_id)
        .ok_or_else(|| known(ProviderErrorKind::OwnershipMismatch, stage))?;
    let custody = match required(LABEL_CUSTODY_KIND)? {
        CUSTODY_ADMISSION if !managed.contains_key(LABEL_SLOT) => {
            if managed.len() != 14 {
                return Err(known(ProviderErrorKind::OwnershipMismatch, stage));
            }
            SandboxCustody::ProfileAdmission { runner_id }
        }
        CUSTODY_JOB => {
            let slot_text = required(LABEL_SLOT)?;
            let slot_ordinal = slot_text
                .parse::<u16>()
                .ok()
                .and_then(NonZeroU16::new)
                .filter(|value| value.get().to_string() == slot_text)
                .filter(|value| value.get() <= crate::MAXIMUM_LOCAL_DOCKER_JOB_SLOTS)
                .ok_or_else(|| known(ProviderErrorKind::OwnershipMismatch, stage))?;
            if managed.len() != 15 {
                return Err(known(ProviderErrorKind::OwnershipMismatch, stage));
            }
            SandboxCustody::Job {
                runner_id,
                slot_ordinal,
            }
        }
        _ => return Err(known(ProviderErrorKind::OwnershipMismatch, stage)),
    };
    let profile_id = EnvironmentProfileId::from_str(required(LABEL_PROFILE)?)
        .map_err(|_| known(ProviderErrorKind::OwnershipMismatch, stage))?;
    let profile_digest = canonical_digest(required(LABEL_PROFILE_DIGEST)?)
        .ok_or_else(|| known(ProviderErrorKind::OwnershipMismatch, stage))?;
    canonical_digest(required(LABEL_SPEC_DIGEST)?)
        .ok_or_else(|| known(ProviderErrorKind::OwnershipMismatch, stage))?;
    canonical_digest(required(LABEL_REALIZED_DIGEST)?)
        .ok_or_else(|| known(ProviderErrorKind::OwnershipMismatch, stage))?;
    let mut base_labels = managed;
    base_labels.remove(LABEL_RESOURCE_KIND);
    base_labels.remove(LABEL_REALIZED_DIGEST);
    Ok(BaseIdentity {
        base_labels,
        custody,
        profile: EnvironmentProfile::new(profile_id, profile_digest),
    })
}

fn matching_present_identities<const N: usize>(
    identities: [Option<&BaseIdentity>; N],
    stage: ProviderStage,
) -> Result<Option<&BaseIdentity>, ProviderError> {
    let mut present = identities.into_iter().flatten();
    let Some(first) = present.next() else {
        return Ok(None);
    };
    if present.all(|identity| identity == first) {
        Ok(Some(first))
    } else {
        Err(known(ProviderErrorKind::OwnershipMismatch, stage))
    }
}

fn canonical_digest(value: &str) -> Option<Sha256Digest> {
    Sha256Digest::from_str(value)
        .ok()
        .filter(|digest| digest.to_string() == value)
}

fn managed_labels(labels: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    labels
        .iter()
        .filter(|(key, _)| key.starts_with(MANAGED_LABEL_PREFIX))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn verify_container_custody(
    container: &InspectedContainerCustody,
    names: &ResourceNames,
    installation: &Installation,
    runner_id: RunnerId,
    resource_kind: &str,
    imported_image_reference: Option<&str>,
    stage: ProviderStage,
) -> Result<BaseIdentity, ProviderError> {
    let expected_name = match resource_kind {
        KIND_JOB => &names.job,
        KIND_GUEST_SOURCE => &names.helper,
        KIND_RESULTS_PROXY => &names.results_proxy,
        _ => return Err(known(ProviderErrorKind::OwnershipMismatch, stage)),
    };
    if container.name != *expected_name
        || canonical_digest(&container.id).is_none()
        || container
            .image_id
            .strip_prefix("sha256:")
            .and_then(canonical_digest)
            .is_none()
        || imported_image_reference.map_or_else(
            || ImmutableImage::new(container.image.clone()).is_err(),
            |reference| container.image != reference,
        )
    {
        return Err(known(ProviderErrorKind::OwnershipMismatch, stage));
    }
    parse_identity(
        &container.labels,
        names,
        installation,
        runner_id,
        resource_kind,
        stage,
    )
}

fn same_container_custody(
    expected: &InspectedContainerCustody,
    observed: &InspectedContainerCustody,
) -> bool {
    expected.id == observed.id
        && expected.image_id == observed.image_id
        && expected.image == observed.image
        && managed_labels(&expected.labels) == managed_labels(&observed.labels)
}

fn verify_existing_helper(
    container: &InspectedContainer,
    definition: &ContainerDefinition,
    image_id: &str,
) -> Result<(), ProviderError> {
    verify_container(
        container,
        definition,
        image_id,
        Some(EngineContainerState::Created),
    )
}

fn verify_container(
    container: &InspectedContainer,
    definition: &ContainerDefinition,
    image_id: &str,
    state: Option<EngineContainerState>,
) -> Result<(), ProviderError> {
    if container.id.is_empty()
        || container.image_id != image_id
        || !container.isolated
        || !container_definition_matches(container, definition)
        || state.is_some_and(|expected| container.state != expected)
    {
        return Err(known(
            ProviderErrorKind::Conflict,
            ProviderStage::VerifyOwnership,
        ));
    }
    Ok(())
}

fn container_definition_matches(
    container: &InspectedContainer,
    expected: &ContainerDefinition,
) -> bool {
    if container.state != EngineContainerState::Created {
        return container.definition == *expected;
    }
    let mut normalized = container.definition.clone();
    if normalized.networks.len() != expected.networks.len()
        || normalized.networks.iter().any(|(name, attachment)| {
            expected
                .networks
                .get(name)
                .is_none_or(|expected_attachment| {
                    !attachment.network_id.is_empty()
                        || attachment.ipv4_address != expected_attachment.ipv4_address
                        || attachment.aliases != expected_attachment.aliases
                })
        })
    {
        return false;
    }
    for (name, attachment) in &mut normalized.networks {
        attachment.network_id.clone_from(
            &expected
                .networks
                .get(name)
                .expect("network cardinality and names were checked")
                .network_id,
        );
    }
    normalized == *expected
}

fn verify_job_definition(
    container: &InspectedContainer,
    names: &ResourceNames,
    image_labels: &BTreeMap<String, String>,
    image_environment_names: &[String],
    base_labels: &BTreeMap<String, String>,
    front: &InspectedNetwork,
    stage: ProviderStage,
) -> Result<(), ProviderError> {
    let definition = &container.definition;
    let mut base_realized_labels = definition.labels.clone();
    base_realized_labels.remove(LABEL_REALIZED_DIGEST);
    let workspace = automata_ci_execution::TargetPath::posix(definition.working_directory.clone())
        .map_err(|_| known(ProviderErrorKind::OwnershipMismatch, stage))?;
    let resource_limits_valid = definition.memory_bytes > 0
        && definition.nano_cpus > 0
        && definition.nano_cpus % 1_000_000 == 0
        && definition.pids_limit > 0
        && u64::try_from(definition.memory_bytes)
            .ok()
            .zip(u32::try_from(definition.nano_cpus / 1_000_000).ok())
            .zip(u32::try_from(definition.pids_limit).ok())
            .is_some_and(|((memory, cpu), pids)| {
                automata_ci_execution::ResourceLimits::new(memory, cpu, pids).is_ok()
            });
    if container.id.is_empty()
        || !container.isolated
        || definition.name != names.job
        || definition.entrypoint != LOCAL_DOCKER_SANDBOX_GUEST_BINARY
        || definition.arguments != ["serve-local"]
        || base_realized_labels != resource_labels(image_labels, base_labels, KIND_JOB)
        || !exact_realized_container_digest(container)
        || definition.environment != neutral_environment(image_environment_names)
        || definition.tmpfs
            != BTreeMap::from([
                (
                    workspace.as_str().to_owned(),
                    job_tmpfs_options(definition.memory_bytes),
                ),
                (
                    LOCAL_CONTROL_DIRECTORY.to_owned(),
                    guest_control_tmpfs_options(),
                ),
            ])
        || workspace.as_str() == "/"
        || workspace.as_str() == "/automata"
        || workspace.as_str().starts_with("/automata/")
        || workspace.as_str() == LOCAL_CONTROL_DIRECTORY
        || workspace
            .as_str()
            .starts_with(&format!("{LOCAL_CONTROL_DIRECTORY}/"))
        || definition.user != "0:0"
        || definition.read_only_root
        || !resource_limits_valid
        || definition.primary_network.as_deref() != Some(front.name.as_str())
        || definition.networks
            != BTreeMap::from([(
                front.name.clone(),
                ContainerNetworkAttachment {
                    network_id: front.id.clone(),
                    ipv4_address: front_job_address(front)?,
                    aliases: Vec::new(),
                },
            )])
    {
        return Err(known(ProviderErrorKind::OwnershipMismatch, stage));
    }
    Ok(())
}

fn neutral_environment(names: &[String]) -> Vec<String> {
    names.iter().map(|name| format!("{name}=")).collect()
}

fn verify_image(
    pinned: &PinnedDockerEngine,
    image: &ImmutableImage,
    inspected: &InspectedImage,
) -> Result<(), LocalDockerErrorCode> {
    verify_image_shape(pinned, inspected)?;
    if !inspected
        .repo_digests
        .iter()
        .any(|digest| digest == image.reference())
    {
        return Err(LocalDockerErrorCode::ImageMismatch);
    }
    Ok(())
}

fn verify_image_shape(
    pinned: &PinnedDockerEngine,
    inspected: &InspectedImage,
) -> Result<(), LocalDockerErrorCode> {
    let valid_id = inspected
        .id
        .strip_prefix("sha256:")
        .and_then(canonical_digest)
        .is_some();
    if !valid_id
        || inspected.operating_system != "linux"
        || !inspected.declared_volumes.is_empty()
        || !inspected.declared_exposed_ports.is_empty()
        || inspected.has_healthcheck
        || inspected
            .labels
            .keys()
            .any(|key| key.starts_with(MANAGED_LABEL_PREFIX))
        || normalize_architecture(&inspected.architecture) != Some(pinned.architecture())
    {
        return Err(LocalDockerErrorCode::ImageMismatch);
    }
    Ok(())
}

fn verify_results_proxy_image(
    pinned: &PinnedDockerEngine,
    image: &LocalImportedImage,
    inspected: &InspectedImage,
) -> Result<(), LocalDockerErrorCode> {
    verify_image_shape(pinned, inspected)?;
    if image.accepts_live_representation(
        &inspected.id,
        &inspected.repo_tags,
        &inspected.repo_digests,
    ) && inspected.default_path_only
        && inspected.environment_names == ["PATH"]
        && inspected.user == RESULTS_PROXY_USER
        && inspected.entrypoint == [RESULTS_PROXY_ENTRYPOINT]
        && inspected.command.is_empty()
        && inspected.working_directory == "/"
        && inspected
            .labels
            .get(RESULTS_PROXY_IMAGE_PROTOCOL_LABEL)
            .is_some_and(|version| version == RESULTS_PROXY_IMAGE_PROTOCOL_VERSION)
    {
        Ok(())
    } else {
        Err(LocalDockerErrorCode::ImageMismatch)
    }
}

enum ResultsTransportAttestationError {
    Cancelled,
    Deadline,
    Verification(LocalDockerError),
}

impl ResultsTransportAttestationError {
    const fn into_local_docker_error(self) -> LocalDockerError {
        match self {
            Self::Verification(error) => error,
            Self::Cancelled | Self::Deadline => {
                LocalDockerError::new(LocalDockerErrorCode::EngineRequestFailed)
            }
        }
    }

    const fn into_provider_kind(self) -> ProviderErrorKind {
        match self {
            Self::Cancelled => ProviderErrorKind::Cancelled,
            Self::Deadline => ProviderErrorKind::AdapterUnavailable,
            Self::Verification(error) => map_local_docker_kind(error),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn verify_shared_results_transport_bounded(
    pinned: &PinnedDockerEngine,
    engine: &dyn SandboxEngineApi,
    installation: &Installation,
    transport: &LocalDockerResultsTransport,
    proxy_image_id: &str,
    proxy_image_labels: &BTreeMap<String, String>,
    runner_id: RunnerId,
    cancellation: &dyn Cancellation,
    budget: ResultsTransportBudget,
) -> Result<InspectedNetwork, ResultsTransportAttestationError> {
    if cancellation.disposition().requires_termination() {
        return Err(ResultsTransportAttestationError::Cancelled);
    }
    let verification = verify_shared_results_transport(
        pinned,
        engine,
        installation,
        transport,
        proxy_image_id,
        proxy_image_labels,
        runner_id,
    );
    tokio::select! {
        biased;
        () = cancellation_requested(cancellation) => {
            Err(ResultsTransportAttestationError::Cancelled)
        }
        result = tokio::time::timeout_at(budget.deadline, verification) => {
            match result {
                Ok(Ok(network)) => Ok(network),
                Ok(Err(error)) => Err(ResultsTransportAttestationError::Verification(error)),
                Err(_) => Err(ResultsTransportAttestationError::Deadline),
            }
        }
    }
}

async fn verify_shared_results_transport(
    pinned: &PinnedDockerEngine,
    engine: &dyn SandboxEngineApi,
    installation: &Installation,
    transport: &LocalDockerResultsTransport,
    proxy_image_id: &str,
    proxy_image_labels: &BTreeMap<String, String>,
    runner_id: RunnerId,
) -> Result<InspectedNetwork, LocalDockerError> {
    let expected_name = results_transit_name(installation);
    if !results_target_is_running(engine, transport).await? {
        return Err(LocalDockerError::new(
            LocalDockerErrorCode::ResultsTransportMismatch,
        ));
    }
    for _ in 0..MAX_RESULTS_TRANSIT_CONVERGENCE_ATTEMPTS {
        let network = inspect_exact_results_transit(engine, installation, transport).await?;
        let expected = VerifiedResultsTransport {
            requested: transport.clone(),
            transit_name: expected_name.clone(),
            transit_network: network.ipv4_network.clone(),
            transit_gateway: network.ipv4_gateway,
            proxy_image_id: proxy_image_id.to_owned(),
            proxy_image_labels: proxy_image_labels.clone(),
        };
        let peer_verifier = TransitPeerVerifier {
            pinned,
            engine,
            installation,
            runner_id,
            results: &expected,
            transit: &network,
        };
        let Some(peers) = attest_transit_snapshot(&peer_verifier, &network).await? else {
            continue;
        };
        let after_peer_scan =
            inspect_exact_results_transit(engine, installation, transport).await?;
        if after_peer_scan != network {
            continue;
        }
        if !results_target_is_running(engine, transport).await? {
            return Err(results_transport_mismatch());
        }
        if !reattest_transit_snapshot(&peer_verifier, peers).await? {
            continue;
        }
        let final_network = inspect_exact_results_transit(engine, installation, transport).await?;
        if final_network != network {
            continue;
        }
        if !results_target_is_running(engine, transport).await? {
            return Err(results_transport_mismatch());
        }
        return Ok(final_network);
    }
    Err(results_transport_mismatch())
}

async fn attest_transit_snapshot(
    verifier: &TransitPeerVerifier<'_>,
    network: &InspectedNetwork,
) -> Result<Option<Vec<TransitProxyPeerAttestation>>, LocalDockerError> {
    let inputs = network
        .containers
        .iter()
        .filter(|(id, _)| *id != &verifier.results.requested.results_container_id)
        .map(|(id, endpoint)| (id.clone(), endpoint.clone()))
        .collect::<Vec<_>>();
    let mut results = stream::iter(inputs)
        .map(|(container_id, endpoint)| async move {
            let result = verifier.verify(&container_id, &endpoint).await;
            (container_id, endpoint, result)
        })
        .buffer_unordered(MAX_RESULTS_TRANSIT_ATTESTATION_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    results.sort_by(|left, right| left.0.cmp(&right.0));
    let mut peers = Vec::with_capacity(results.len());
    let mut failures = Vec::new();
    for (container_id, endpoint, result) in results {
        match result {
            Ok(peer) => peers.push(peer),
            Err(error) => failures.push((container_id, endpoint, error)),
        }
    }
    if failures.is_empty() {
        return Ok(Some(peers));
    }
    let replay = inspect_exact_results_transit(
        verifier.engine,
        verifier.installation,
        &verifier.results.requested,
    )
    .await?;
    for (container_id, endpoint, error) in failures {
        if replay.containers.get(&container_id) == Some(&endpoint) {
            return Err(error);
        }
    }
    Ok(None)
}

async fn reattest_transit_snapshot(
    verifier: &TransitPeerVerifier<'_>,
    peers: Vec<TransitProxyPeerAttestation>,
) -> Result<bool, LocalDockerError> {
    let mut results = stream::iter(peers)
        .map(|peer| async move {
            let result = verifier
                .verify(&peer.proxy.id, &peer.transit_endpoint)
                .await;
            (peer, result)
        })
        .buffer_unordered(MAX_RESULTS_TRANSIT_ATTESTATION_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    results.sort_by(|left, right| left.0.proxy.id.cmp(&right.0.proxy.id));
    let mut changed = false;
    let mut failures = Vec::new();
    for (peer, result) in results {
        match result {
            Ok(fresh) if fresh == peer => {}
            Ok(_) => changed = true,
            Err(error) => failures.push((peer, error)),
        }
    }
    if failures.is_empty() {
        return Ok(!changed);
    }
    let replay = inspect_exact_results_transit(
        verifier.engine,
        verifier.installation,
        &verifier.results.requested,
    )
    .await?;
    for (peer, error) in failures {
        if replay.containers.get(&peer.proxy.id) == Some(&peer.transit_endpoint) {
            return Err(error);
        }
    }
    Ok(false)
}

async fn results_target_is_running(
    engine: &dyn SandboxEngineApi,
    transport: &LocalDockerResultsTransport,
) -> Result<bool, LocalDockerError> {
    engine
        .results_target_running(&transport.results_container_id)
        .await
        .map_err(map_engine_call)
}

async fn inspect_exact_results_transit(
    engine: &dyn SandboxEngineApi,
    installation: &Installation,
    transport: &LocalDockerResultsTransport,
) -> Result<InspectedNetwork, LocalDockerError> {
    let network = engine
        .inspect_network(&transport.transit_network_id)
        .await
        .map_err(map_engine_call)?
        .ok_or_else(results_transport_mismatch)?;
    if exact_results_transit(&network, installation, transport) {
        Ok(network)
    } else {
        Err(results_transport_mismatch())
    }
}

fn exact_results_transit(
    network: &InspectedNetwork,
    installation: &Installation,
    transport: &LocalDockerResultsTransport,
) -> bool {
    let shape = ResultsTransitNetworkShape {
        name: network.name.clone(),
        driver: network.driver.clone(),
        scope: network.scope.clone(),
        enable_ipv4: network.enable_ipv4,
        enable_ipv6: network.enable_ipv6,
        internal: network.internal,
        attachable: network.attachable,
        ingress: network.ingress,
        config_only: network.config_only,
        config_from_empty: network.config_from.is_empty(),
        ipam_driver: network.ipam_driver.clone(),
        ipam_options: network.ipam_options.clone(),
        options: network.options.clone(),
        labels: network.labels.clone(),
        endpoint_ids: network.containers.keys().cloned().collect(),
    };
    let unique_addresses = network
        .containers
        .values()
        .map(|endpoint| endpoint.ipv4_address)
        .collect::<BTreeSet<_>>();
    exact_results_transit_base(&shape, installation, transport.plan_digest)
        && network.id == transport.transit_network_id
        && network.ipv4_network.prefix <= 23
        && network_host_address(&network.ipv4_network, 1)
            .is_ok_and(|gateway| network.ipv4_gateway == gateway)
        && !ipv4_networks_overlap(&results_front_pool(installation), &network.ipv4_network)
        && unique_addresses.len() == network.containers.len()
        && network
            .containers
            .values()
            .all(|endpoint| endpoint.ipv4_address != network.ipv4_gateway)
        && network.ipv4_network.usable(transport.results_address)
        && transport.results_address != network.ipv4_gateway
        && network
            .containers
            .get(&transport.results_container_id)
            .is_some_and(|endpoint| {
                endpoint.ipv4_address == transport.results_address
                    && endpoint.ipv4_prefix == network.ipv4_network.prefix
            })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TransitProxyPeerAttestation {
    transit_endpoint: NetworkEndpoint,
    proxy: InspectedContainer,
    front: InspectedNetwork,
    job: Option<InspectedContainer>,
}

struct TransitPeerVerifier<'a> {
    pinned: &'a PinnedDockerEngine,
    engine: &'a dyn SandboxEngineApi,
    installation: &'a Installation,
    runner_id: RunnerId,
    results: &'a VerifiedResultsTransport,
    transit: &'a InspectedNetwork,
}

impl TransitPeerVerifier<'_> {
    async fn verify(
        &self,
        container_id: &str,
        endpoint: &NetworkEndpoint,
    ) -> Result<TransitProxyPeerAttestation, LocalDockerError> {
        let container = self
            .engine
            .inspect_container(&endpoint.name)
            .await
            .map_err(map_engine_call)?
            .ok_or_else(results_transport_mismatch)?;
        let (names, identity) =
            transit_proxy_identity(&container, self.installation, self.runner_id)?;
        let front_attachment = container
            .definition
            .networks
            .get(&names.results_front)
            .ok_or_else(results_transport_mismatch)?;
        let transit_attachment = container
            .definition
            .networks
            .get(&self.results.transit_name)
            .ok_or_else(results_transport_mismatch)?;
        let front = self
            .engine
            .inspect_network(&front_attachment.network_id)
            .await
            .map_err(map_engine_call)?
            .ok_or_else(results_transport_mismatch)?;
        let transit_address = transit_proxy_address(
            &self.transit.ipv4_network,
            self.transit.ipv4_gateway,
            self.results.requested.results_address,
            identity.custody,
        )
        .map_err(|_| results_transport_mismatch())?;
        let expected_front = front_network_definition(
            &names,
            &identity.base_labels,
            self.installation,
            identity.custody,
        )
        .map_err(|_| results_transport_mismatch())?;
        let expected_definition = results_proxy_definition(
            &names,
            &identity.base_labels,
            self.results,
            &front,
            transit_address,
        )
        .map_err(|_| results_transport_mismatch())?;
        let proxy_front_address =
            front_proxy_address(&front).map_err(|_| results_transport_mismatch())?;
        let job_front_address =
            front_job_address(&front).map_err(|_| results_transport_mismatch())?;
        if container.id != container_id
            || endpoint.name != names.results_proxy
            || endpoint.ipv4_address != transit_address
            || endpoint.ipv4_prefix != self.transit.ipv4_network.prefix
            || transit_attachment.ipv4_address != transit_address
            || container.state != EngineContainerState::Running
            || verify_container(
                &container,
                &expected_definition,
                &self.results.proxy_image_id,
                None,
            )
            .is_err()
            || front.id != front_attachment.network_id
            || front.id == self.transit.id
            || ipv4_networks_overlap(&front.ipv4_network, &self.transit.ipv4_network)
            || front.ipv4_network != expected_front.ipv4_network
            || front.ipv4_gateway != expected_front.ipv4_gateway
            || !exact_closed_network(&front, &names.results_front, &expected_front.labels)
        {
            return Err(results_transport_mismatch());
        }
        let job_member = exact_peer_front_members(
            &front,
            container_id,
            &names,
            proxy_front_address,
            job_front_address,
        )?;
        let job = self
            .verify_job(&names, &identity, &front, job_front_address, job_member)
            .await?;
        Ok(TransitProxyPeerAttestation {
            transit_endpoint: endpoint.clone(),
            proxy: container,
            front,
            job,
        })
    }

    async fn verify_job(
        &self,
        names: &ResourceNames,
        identity: &BaseIdentity,
        front: &InspectedNetwork,
        job_front_address: Ipv4Addr,
        job_member: Option<(String, NetworkEndpoint)>,
    ) -> Result<Option<InspectedContainer>, LocalDockerError> {
        let Some((job_id, job_endpoint)) = job_member else {
            return Ok(None);
        };
        let job = self
            .engine
            .inspect_container(&names.job)
            .await
            .map_err(map_engine_call)?
            .ok_or_else(results_transport_mismatch)?;
        let job_identity = parse_identity(
            &job.definition.labels,
            names,
            self.installation,
            self.runner_id,
            KIND_JOB,
            ProviderStage::VerifyOwnership,
        )
        .map_err(|_| results_transport_mismatch())?;
        let image = ImmutableImage::new(job.definition.image.clone())
            .map_err(|_| results_transport_mismatch())?;
        let inspected_image = self
            .engine
            .inspect_image(image.reference())
            .await
            .map_err(map_engine_call)?
            .ok_or_else(results_transport_mismatch)?;
        if job.id != job_id
            || job_endpoint.name != names.job
            || job_endpoint.ipv4_address != job_front_address
            || job_endpoint.ipv4_prefix != front.ipv4_network.prefix
            || job.state != EngineContainerState::Running
            || !job.isolated
            || job_identity != *identity
            || verify_image(self.pinned, &image, &inspected_image).is_err()
            || job.image_id != inspected_image.id
            || verify_job_definition(
                &job,
                names,
                &inspected_image.labels,
                &inspected_image.environment_names,
                &identity.base_labels,
                front,
                ProviderStage::VerifyOwnership,
            )
            .is_err()
        {
            return Err(results_transport_mismatch());
        }
        Ok(Some(job))
    }
}

fn transit_proxy_identity(
    container: &InspectedContainer,
    installation: &Installation,
    runner_id: RunnerId,
) -> Result<(ResourceNames, BaseIdentity), LocalDockerError> {
    let managed = managed_labels(&container.definition.labels);
    let operation_id = managed.get(LABEL_OPERATION_ID).and_then(|value| {
        OperationId::from_str(value)
            .ok()
            .filter(|parsed| parsed.to_string() == *value)
    });
    let generation = managed.get(LABEL_GENERATION).and_then(|value| {
        value
            .parse::<u64>()
            .ok()
            .filter(|parsed| parsed.to_string() == *value)
    });
    let names = operation_id
        .zip(generation)
        .and_then(|(operation_id, generation)| {
            ResourceNames::new(installation, operation_id, generation).ok()
        })
        .ok_or_else(results_transport_mismatch)?;
    let identity = parse_identity(
        &container.definition.labels,
        &names,
        installation,
        runner_id,
        KIND_RESULTS_PROXY,
        ProviderStage::VerifyOwnership,
    )
    .map_err(|_| results_transport_mismatch())?;
    Ok((names, identity))
}

fn exact_peer_front_members(
    front: &InspectedNetwork,
    proxy_id: &str,
    names: &ResourceNames,
    proxy_address: Ipv4Addr,
    job_address: Ipv4Addr,
) -> Result<Option<(String, NetworkEndpoint)>, LocalDockerError> {
    if front.containers.is_empty()
        || front.containers.len() > 2
        || !front.containers.get(proxy_id).is_some_and(|member| {
            member.name == names.results_proxy
                && member.ipv4_address == proxy_address
                && member.ipv4_prefix == front.ipv4_network.prefix
        })
    {
        return Err(results_transport_mismatch());
    }
    let mut job = front
        .containers
        .iter()
        .filter(|(id, _)| id.as_str() != proxy_id);
    let member = job.next();
    if job.next().is_some()
        || member.is_some_and(|(_, endpoint)| {
            endpoint.name != names.job
                || endpoint.ipv4_address != job_address
                || endpoint.ipv4_prefix != front.ipv4_network.prefix
        })
    {
        return Err(results_transport_mismatch());
    }
    Ok(member.map(|(id, endpoint)| (id.clone(), endpoint.clone())))
}

const fn results_transport_mismatch() -> LocalDockerError {
    LocalDockerError::new(LocalDockerErrorCode::ResultsTransportMismatch)
}

fn ipv4_networks_overlap(first: &Ipv4Network, second: &Ipv4Network) -> bool {
    first.contains(second.network) || second.contains(first.network)
}

fn exact_closed_network(
    network: &InspectedNetwork,
    expected_name: &str,
    expected_labels: &BTreeMap<String, String>,
) -> bool {
    network.name == expected_name
        && network.driver == "bridge"
        && network.scope == "local"
        && network.enable_ipv4
        && !network.enable_ipv6
        && network.internal
        && !network.attachable
        && !network.ingress
        && !network.config_only
        && network.config_from.is_empty()
        && network.ipam_driver == "default"
        && network.ipam_options.is_empty()
        && network.options
            == BTreeMap::from([(
                "com.docker.network.bridge.gateway_mode_ipv4".to_owned(),
                "isolated".to_owned(),
            )])
        && network.labels == *expected_labels
}

fn canonical_object_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn record(handle: &SandboxHandle, spec: &SandboxSpec, state: SandboxState) -> SandboxRecord {
    SandboxRecord::new(
        handle.clone(),
        spec.generation(),
        spec.profile().attestation().clone(),
        state,
    )
}

fn invalid_handle() -> ProviderError {
    known(
        ProviderErrorKind::OwnershipMismatch,
        ProviderStage::Validate,
    )
}

fn invalid_configuration() -> ProviderError {
    known(
        ProviderErrorKind::InvalidConfiguration,
        ProviderStage::Validate,
    )
}

const fn known(kind: ProviderErrorKind, stage: ProviderStage) -> ProviderError {
    ProviderError::new(kind, stage, OperationOutcome::KnownNoEffect, None)
}

fn uncertain(
    kind: ProviderErrorKind,
    stage: ProviderStage,
    handle: &SandboxHandle,
) -> ProviderError {
    ProviderError::new(
        kind,
        stage,
        OperationOutcome::Uncertain,
        Some(handle.clone()),
    )
}

fn recovery(error: &ProviderError, handle: &SandboxHandle) -> ProviderError {
    ProviderError::new(
        error.kind(),
        error.stage(),
        OperationOutcome::Uncertain,
        Some(handle.clone()),
    )
}

fn map_provider_engine(
    error: EngineApiError,
    stage: ProviderStage,
    recovery_handle: Option<&SandboxHandle>,
) -> ProviderError {
    let kind = map_engine_kind(error);
    match recovery_handle {
        Some(handle) => uncertain(kind, stage, handle),
        None => known(kind, stage),
    }
}

fn map_provider_local_docker(
    error: LocalDockerError,
    stage: ProviderStage,
    recovery_handle: Option<&SandboxHandle>,
) -> ProviderError {
    let kind = map_local_docker_kind(error);
    match recovery_handle {
        Some(handle) => uncertain(kind, stage, handle),
        None => known(kind, stage),
    }
}

const fn map_engine_kind(error: EngineApiError) -> ProviderErrorKind {
    match error {
        EngineApiError::RequestFailed => ProviderErrorKind::AdapterUnavailable,
        EngineApiError::InvalidResponse => ProviderErrorKind::BackendRejected,
        EngineApiError::OutputLimit => ProviderErrorKind::OutputLimitExceeded,
    }
}

const fn map_local_docker_kind(error: LocalDockerError) -> ProviderErrorKind {
    match error.code() {
        LocalDockerErrorCode::EngineRequestFailed
        | LocalDockerErrorCode::EngineIdentityChanged
        | LocalDockerErrorCode::EngineIsolationUnavailable
        | LocalDockerErrorCode::EngineArchitectureMismatch => ProviderErrorKind::AdapterUnavailable,
        LocalDockerErrorCode::InvalidEngineResponse => ProviderErrorKind::BackendRejected,
        LocalDockerErrorCode::EngineOutputLimitExceeded => ProviderErrorKind::OutputLimitExceeded,
        LocalDockerErrorCode::ImageUnavailable
        | LocalDockerErrorCode::ImageMismatch
        | LocalDockerErrorCode::IdentityCollision
        | LocalDockerErrorCode::InvalidIdentityAnchor
        | LocalDockerErrorCode::IdentityAnchorAttached
        | LocalDockerErrorCode::ResultsTransportMismatch => ProviderErrorKind::OwnershipMismatch,
    }
}

fn ensure_not_cancelled(
    cancellation: &dyn Cancellation,
    stage: ProviderStage,
) -> Result<(), ProviderError> {
    if cancellation.disposition().requires_termination() {
        return Err(known(ProviderErrorKind::Cancelled, stage));
    }
    Ok(())
}

fn ensure_not_cancelled_after_mutation(
    cancellation: &dyn Cancellation,
    stage: ProviderStage,
    handle: &SandboxHandle,
) -> Result<(), ProviderError> {
    if cancellation.disposition().requires_termination() {
        return Err(uncertain(ProviderErrorKind::Cancelled, stage, handle));
    }
    Ok(())
}

async fn cancellation_requested(cancellation: &dyn Cancellation) {
    while !cancellation.disposition().requires_termination() {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn lock_handle(
    operation_lock: Arc<HandleOperationLock>,
    cancellation: &dyn Cancellation,
) -> Option<tokio::sync::OwnedMutexGuard<()>> {
    if cancellation.disposition().requires_termination() {
        return None;
    }
    tokio::select! {
        biased;
        () = cancellation_requested(cancellation) => None,
        guard = operation_lock.lock_owned() => Some(guard),
    }
}

fn run_provider<T, F>(stage: ProviderStage, future: F) -> Result<T, ProviderError>
where
    T: Send,
    F: Future<Output = Result<T, ProviderError>> + Send,
{
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| known(ProviderErrorKind::AdapterUnavailable, stage))?
                    .block_on(future)
            })
            .join()
            .map_err(|_| known(ProviderErrorKind::AdapterUnavailable, stage))?
    })
}
