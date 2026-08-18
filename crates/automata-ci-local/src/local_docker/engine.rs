//! Exact-endpoint Docker Engine adapters for local installation resources.

#[cfg(unix)]
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::Ipv4Addr,
    sync::Arc,
    time::Duration,
};

#[cfg(unix)]
use async_trait::async_trait;
use automata_ci_core::Architecture;

#[cfg(unix)]
use crate::{
    ApiVersion, Installation, InstallationBinding, InstallationId, InstallationName,
    LocalDockerError, LocalDockerErrorCode, normalize_architecture,
};

#[cfg(unix)]
mod http_engine;
#[cfg(unix)]
mod transport;

#[cfg(unix)]
use http_engine::HttpEngine;

#[cfg(unix)]
const MANAGED_LABEL_PREFIX: &str = "io.automata.local.";
#[cfg(unix)]
const LABEL_MANAGED: &str = "io.automata.local.managed";
#[cfg(unix)]
const LABEL_IDENTITY_SCHEMA: &str = "io.automata.local.identity-schema";
#[cfg(unix)]
const LABEL_INSTALLATION_ID: &str = "io.automata.local.installation-id";
#[cfg(unix)]
const LABEL_INSTALLATION_KEY: &str = "io.automata.local.installation-key";
#[cfg(unix)]
const LABEL_COMPOSE_PROJECT: &str = "io.automata.local.compose-project";
#[cfg(unix)]
const LABEL_RESOURCE_KIND: &str = "io.automata.local.resource-kind";
#[cfg(unix)]
const MANAGED_VALUE: &str = "true";
#[cfg(unix)]
const IDENTITY_SCHEMA: &str = "1";
#[cfg(unix)]
const IDENTITY_ANCHOR_KIND: &str = "identity-anchor";
#[cfg(unix)]
const SECURITY_OPTION_USER_NAMESPACE: &str = "name=userns";
#[cfg(unix)]
const SECURITY_OPTION_ROOTLESS: &str = "name=rootless";
#[cfg(unix)]
const SECURITY_OPTION_SECCOMP_BUILTIN: &str = "name=seccomp,profile=builtin";
#[cfg(unix)]
const SECURITY_OPTION_CGROUP_NAMESPACE: &str = "name=cgroupns";
#[cfg(unix)]
const SECURITY_OPTION_NO_NEW_PRIVILEGES: &str = "name=no-new-privileges";
#[cfg(unix)]
pub(super) const LOCAL_DOCKER_GUEST_ARCHIVE_BYTES: usize = 32 * 1024 * 1024;
#[cfg(unix)]
pub(super) const LOCAL_DOCKER_GUEST_IMAGE_BINARY: &str = "/usr/local/bin/automata-ci-sandbox-guest";
#[cfg(unix)]
pub(super) const LOCAL_DOCKER_SANDBOX_GUEST_BINARY: &str =
    "/automata/bin/automata-ci-sandbox-guest";

#[cfg(unix)]
async fn inspect_verified_identity(
    engine: &dyn AnchorEngineApi,
    name: &InstallationName,
) -> Result<Option<Installation>, LocalDockerError> {
    let expected = Installation::expected(name);
    let Some(volume) = engine
        .inspect_volume(&expected.anchor_volume_name)
        .await
        .map_err(map_engine_call)?
    else {
        return Ok(None);
    };
    if volume.name != expected.anchor_volume_name
        || volume.driver != "local"
        || volume.scope != "local"
        || !volume.options.is_empty()
    {
        return Err(LocalDockerError::new(
            LocalDockerErrorCode::IdentityCollision,
        ));
    }
    let id = validate_identity_labels(&volume.labels, &expected)?;
    let attachments = engine
        .volume_attachments(&expected.anchor_volume_name)
        .await
        .map_err(map_engine_call)?;
    let current = engine
        .inspect_volume(&expected.anchor_volume_name)
        .await
        .map_err(map_engine_call)?;
    if current.as_ref() != Some(&volume) {
        return Err(LocalDockerError::new(
            LocalDockerErrorCode::InvalidIdentityAnchor,
        ));
    }
    if attachments.is_empty() {
        Ok(Some(Installation::verified(name.clone(), id)))
    } else {
        Err(LocalDockerError::new(
            LocalDockerErrorCode::IdentityAnchorAttached,
        ))
    }
}

#[cfg(unix)]
fn validate_identity_labels(
    labels: &BTreeMap<String, String>,
    expected: &crate::installation::ExpectedInstallation,
) -> Result<InstallationId, LocalDockerError> {
    let managed: BTreeMap<&str, &str> = labels
        .iter()
        .filter(|(key, _value)| key.starts_with(MANAGED_LABEL_PREFIX))
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    let Some(id) = managed
        .get(LABEL_INSTALLATION_ID)
        .and_then(|value| InstallationId::parse_canonical(value))
    else {
        return Err(classify_label_failure(&managed));
    };
    let selector_key = expected.selector_key.to_string();
    if managed.len() != 6
        || managed.get(LABEL_MANAGED).copied() != Some(MANAGED_VALUE)
        || managed.get(LABEL_IDENTITY_SCHEMA).copied() != Some(IDENTITY_SCHEMA)
        || managed.get(LABEL_INSTALLATION_KEY).copied() != Some(selector_key.as_str())
        || managed.get(LABEL_COMPOSE_PROJECT).copied() != Some(expected.compose_project.as_str())
        || managed.get(LABEL_RESOURCE_KIND).copied() != Some(IDENTITY_ANCHOR_KIND)
    {
        return Err(classify_label_failure(&managed));
    }
    Ok(id)
}

#[cfg(unix)]
fn classify_label_failure(managed: &BTreeMap<&str, &str>) -> LocalDockerError {
    let owned = managed.get(LABEL_MANAGED).copied() == Some(MANAGED_VALUE)
        && managed.get(LABEL_RESOURCE_KIND).copied() == Some(IDENTITY_ANCHOR_KIND);
    LocalDockerError::new(if owned {
        LocalDockerErrorCode::InvalidIdentityAnchor
    } else {
        LocalDockerErrorCode::IdentityCollision
    })
}

#[cfg(unix)]
pub(crate) fn map_engine_call(error: EngineApiError) -> LocalDockerError {
    match error {
        EngineApiError::RequestFailed => {
            LocalDockerError::new(LocalDockerErrorCode::EngineRequestFailed)
        }
        EngineApiError::InvalidResponse => {
            LocalDockerError::new(LocalDockerErrorCode::InvalidEngineResponse)
        }
        #[cfg(unix)]
        EngineApiError::OutputLimit => {
            LocalDockerError::new(LocalDockerErrorCode::EngineOutputLimitExceeded)
        }
    }
}

#[cfg(unix)]
#[allow(clippy::struct_excessive_bools)] // Exact independent Docker `/info` capability facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EngineFacts {
    pub(crate) engine_id: String,
    pub(crate) server_version: String,
    pub(crate) minimum_api_version: String,
    pub(crate) maximum_api_version: String,
    pub(crate) operating_system: String,
    pub(crate) architecture: String,
    pub(crate) security_options: Vec<String>,
    pub(crate) memory_limit: bool,
    pub(crate) swap_limit: bool,
    pub(crate) cpu_cfs_period: bool,
    pub(crate) cpu_cfs_quota: bool,
    pub(crate) pids_limit: bool,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InspectedVolume {
    pub(crate) name: String,
    pub(crate) driver: String,
    pub(crate) scope: String,
    pub(crate) options: BTreeMap<String, String>,
    pub(crate) labels: BTreeMap<String, String>,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InspectedImage {
    pub(crate) id: String,
    pub(crate) repo_tags: Vec<String>,
    pub(crate) repo_digests: Vec<String>,
    pub(crate) operating_system: String,
    pub(crate) architecture: String,
    pub(crate) declared_volumes: Vec<String>,
    pub(crate) declared_exposed_ports: Vec<String>,
    pub(crate) has_healthcheck: bool,
    pub(crate) labels: BTreeMap<String, String>,
    pub(crate) environment_names: Vec<String>,
    pub(crate) default_path_only: bool,
    pub(crate) user: String,
    pub(crate) entrypoint: Vec<String>,
    pub(crate) command: Vec<String>,
    pub(crate) working_directory: String,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContainerDefinition {
    pub(crate) name: String,
    pub(crate) image: String,
    pub(crate) entrypoint: String,
    pub(crate) arguments: Vec<String>,
    pub(crate) labels: BTreeMap<String, String>,
    pub(crate) environment: Vec<String>,
    pub(crate) tmpfs: BTreeMap<String, String>,
    pub(crate) working_directory: String,
    pub(crate) user: String,
    pub(crate) read_only_root: bool,
    pub(crate) memory_bytes: i64,
    pub(crate) nano_cpus: i64,
    pub(crate) pids_limit: i64,
    pub(crate) primary_network: Option<String>,
    pub(crate) networks: BTreeMap<String, ContainerNetworkAttachment>,
    pub(crate) capture_logs: bool,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContainerNetworkAttachment {
    pub(crate) network_id: String,
    pub(crate) ipv4_address: Ipv4Addr,
    pub(crate) aliases: Vec<String>,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Ipv4Network {
    pub(crate) network: Ipv4Addr,
    pub(crate) prefix: u8,
}

#[cfg(unix)]
impl Ipv4Network {
    pub(crate) fn contains(&self, address: Ipv4Addr) -> bool {
        let mask = u32::MAX << (32 - self.prefix);
        u32::from(address) & mask == u32::from(self.network)
    }

    pub(crate) fn broadcast(&self) -> Ipv4Addr {
        let mask = u32::MAX << (32 - self.prefix);
        Ipv4Addr::from(u32::from(self.network) | !mask)
    }

    pub(crate) fn usable(&self, address: Ipv4Addr) -> bool {
        self.contains(address) && address != self.network && address != self.broadcast()
    }

    pub(crate) fn canonical(&self) -> String {
        format!("{}/{}", self.network, self.prefix)
    }
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NetworkEndpoint {
    pub(crate) name: String,
    pub(crate) endpoint_id: String,
    pub(crate) mac_address: String,
    pub(crate) ipv4_address: Ipv4Addr,
    pub(crate) ipv4_prefix: u8,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct InspectedNetwork {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) driver: String,
    pub(crate) scope: String,
    pub(crate) enable_ipv4: bool,
    pub(crate) enable_ipv6: bool,
    pub(crate) internal: bool,
    pub(crate) attachable: bool,
    pub(crate) ingress: bool,
    pub(crate) config_only: bool,
    pub(crate) config_from: String,
    pub(crate) ipam_driver: String,
    pub(crate) ipam_options: BTreeMap<String, String>,
    pub(crate) ipv4_network: Ipv4Network,
    pub(crate) ipv4_gateway: Ipv4Addr,
    pub(crate) options: BTreeMap<String, String>,
    pub(crate) labels: BTreeMap<String, String>,
    pub(crate) containers: BTreeMap<String, NetworkEndpoint>,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CreateNetwork {
    pub(crate) name: String,
    pub(crate) labels: BTreeMap<String, String>,
    pub(crate) ipv4_network: Ipv4Network,
    pub(crate) ipv4_gateway: Ipv4Addr,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EngineContainerState {
    Created,
    Running,
    Exited(i64),
    Invalid,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InspectedContainer {
    pub(crate) id: String,
    pub(crate) image_id: String,
    pub(crate) definition: ContainerDefinition,
    pub(crate) state: EngineContainerState,
    pub(crate) isolated: bool,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InspectedContainerCustody {
    pub(crate) id: String,
    pub(crate) image_id: String,
    pub(crate) name: String,
    pub(crate) image: String,
    pub(crate) labels: BTreeMap<String, String>,
    pub(crate) state: EngineContainerState,
}

#[cfg(unix)]
impl From<&InspectedContainer> for InspectedContainerCustody {
    fn from(container: &InspectedContainer) -> Self {
        Self {
            id: container.id.clone(),
            image_id: container.image_id.clone(),
            name: container.definition.name.clone(),
            image: container.definition.image.clone(),
            labels: container.definition.labels.clone(),
            state: container.state,
        }
    }
}

#[cfg(unix)]
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct EngineExecRequest {
    pub(crate) container_id: String,
    pub(crate) command: Vec<String>,
    pub(crate) user: String,
    pub(crate) stdin: Vec<u8>,
    pub(crate) stdout_limit: usize,
    pub(crate) stderr_limit: usize,
    pub(crate) timeout: Duration,
}

#[cfg(unix)]
impl fmt::Debug for EngineExecRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EngineExecRequest")
            .field("container_id", &"[REDACTED]")
            .field("command", &"[REDACTED]")
            .field("user", &"[REDACTED]")
            .field("stdin_bytes", &self.stdin.len())
            .field("stdout_limit", &self.stdout_limit)
            .field("stderr_limit", &self.stderr_limit)
            .field("timeout", &self.timeout)
            .finish()
    }
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EngineExecOutput {
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) exit_code: i64,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedEngineExec {
    pub(crate) id: String,
    pub(crate) container_id: String,
    pub(crate) command: Vec<String>,
    pub(crate) user: String,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EngineApiError {
    RequestFailed,
    InvalidResponse,
    #[cfg(unix)]
    OutputLimit,
}

#[cfg(unix)]
#[async_trait]
pub(crate) trait EngineApi: Send + Sync {
    async fn engine_facts(&self) -> Result<EngineFacts, EngineApiError>;
}

#[cfg(unix)]
#[async_trait]
pub(crate) trait AnchorEngineApi: EngineApi {
    async fn inspect_volume(&self, name: &str) -> Result<Option<InspectedVolume>, EngineApiError>;

    async fn volume_attachments(&self, name: &str) -> Result<Vec<String>, EngineApiError>;
}

#[cfg(unix)]
#[async_trait]
pub(crate) trait SandboxEngineApi: AnchorEngineApi {
    async fn inspect_image(
        &self,
        reference: &str,
    ) -> Result<Option<InspectedImage>, EngineApiError>;

    async fn inspect_container(
        &self,
        name: &str,
    ) -> Result<Option<InspectedContainer>, EngineApiError>;

    async fn results_target_running(&self, id: &str) -> Result<bool, EngineApiError>;

    async fn inspect_container_custody(
        &self,
        name_or_id: &str,
    ) -> Result<Option<InspectedContainerCustody>, EngineApiError> {
        Ok(self
            .inspect_container(name_or_id)
            .await?
            .as_ref()
            .map(InspectedContainerCustody::from))
    }

    async fn create_container(&self, definition: ContainerDefinition)
    -> Result<(), EngineApiError>;

    async fn start_container(&self, id: &str) -> Result<(), EngineApiError>;

    async fn remove_container(&self, id: &str) -> Result<(), EngineApiError>;

    async fn kill_container(&self, id: &str) -> Result<(), EngineApiError>;

    async fn inspect_network(
        &self,
        id_or_name: &str,
    ) -> Result<Option<InspectedNetwork>, EngineApiError>;

    async fn create_network(&self, request: CreateNetwork) -> Result<String, EngineApiError>;

    async fn remove_network(&self, id: &str) -> Result<(), EngineApiError>;

    async fn container_logs(&self, id: &str, byte_limit: usize) -> Result<Vec<u8>, EngineApiError>;

    async fn download_guest_image_binary(
        &self,
        id: &str,
        byte_limit: usize,
    ) -> Result<Vec<u8>, EngineApiError>;

    async fn download_sandbox_guest(
        &self,
        id: &str,
        byte_limit: usize,
    ) -> Result<Vec<u8>, EngineApiError>;

    async fn upload_sandbox_archive(&self, id: &str, archive: &[u8]) -> Result<(), EngineApiError>;

    async fn create_exec(
        &self,
        container_id: &str,
        command: &[String],
        user: &str,
    ) -> Result<PreparedEngineExec, EngineApiError>;

    async fn start_exec(
        &self,
        prepared: &PreparedEngineExec,
        request: &EngineExecRequest,
    ) -> Result<EngineExecOutput, EngineApiError>;
}

#[cfg(unix)]
#[derive(Clone)]
pub(crate) struct PinnedDockerEngine {
    engine: Arc<dyn EngineApi>,
    facts: EngineFacts,
    api: ApiVersion,
    architecture: crate::EngineArchitecture,
}

#[cfg(unix)]
impl PinnedDockerEngine {
    #[cfg(test)]
    pub(crate) fn for_test(
        architecture: crate::EngineArchitecture,
        engine: Arc<dyn EngineApi>,
    ) -> Self {
        Self {
            engine,
            facts: EngineFacts {
                engine_id: "engine-identity".to_owned(),
                server_version: "29.7.2".to_owned(),
                minimum_api_version: "1.40".to_owned(),
                maximum_api_version: "1.55".to_owned(),
                operating_system: "linux".to_owned(),
                architecture: match architecture {
                    crate::EngineArchitecture::Amd64 => "amd64".to_owned(),
                    crate::EngineArchitecture::Arm64 => "arm64".to_owned(),
                },
                security_options: vec![
                    SECURITY_OPTION_CGROUP_NAMESPACE.to_owned(),
                    SECURITY_OPTION_SECCOMP_BUILTIN.to_owned(),
                    SECURITY_OPTION_USER_NAMESPACE.to_owned(),
                ],
                memory_limit: true,
                swap_limit: true,
                cpu_cfs_period: true,
                cpu_cfs_quota: true,
                pids_limit: true,
            },
            api: ApiVersion {
                major: 1,
                minor: 48,
            },
            architecture,
        }
    }

    pub(crate) async fn verify(&self) -> Result<(), LocalDockerError> {
        let observed = self.engine.engine_facts().await.map_err(map_engine_call)?;
        validate_relay_facts(&observed, self.api)?;
        if observed != self.facts {
            return Err(LocalDockerError::new(
                LocalDockerErrorCode::EngineIdentityChanged,
            ));
        }
        Ok(())
    }

    pub(crate) const fn architecture(&self) -> crate::EngineArchitecture {
        self.architecture
    }
}

#[cfg(unix)]
pub(crate) const LOCAL_DOCKER_RELAY_SOCKET: &str = "/run/automata-engine/docker.sock";

#[cfg(unix)]
pub(crate) async fn connect_relay_sandbox_engine(
    expected_runner_architecture: &Architecture,
) -> Result<(PinnedDockerEngine, Arc<dyn SandboxEngineApi>), LocalDockerError> {
    let api = ApiVersion {
        major: 1,
        minor: 48,
    };
    let engine = Arc::new(
        HttpEngine::connect_unix_socket(std::path::Path::new(LOCAL_DOCKER_RELAY_SOCKET), api)
            .map_err(|_| LocalDockerError::new(LocalDockerErrorCode::InvalidEngineResponse))?,
    );
    let facts = engine.engine_facts().await.map_err(map_engine_call)?;
    let architecture = validate_relay_facts(&facts, api)?;
    if !relay_matches_runner_architecture(architecture, expected_runner_architecture) {
        return Err(LocalDockerError::new(
            LocalDockerErrorCode::EngineArchitectureMismatch,
        ));
    }
    let pinned = PinnedDockerEngine {
        engine: engine.clone(),
        facts,
        api,
        architecture,
    };
    pinned.verify().await?;
    Ok((pinned, engine))
}

/// Connects to the lifecycle-qualified host Engine for a read-only exact
/// sibling audit. The caller has already pinned the same daemon through the
/// installation adapter; this boundary independently normalizes the complete
/// LocalDocker container/network bodies with the provider's production parser.
pub(crate) async fn connect_host_sandbox_engine(
    expected_architecture: crate::EngineArchitecture,
) -> Result<(PinnedDockerEngine, Arc<dyn SandboxEngineApi>), LocalDockerError> {
    let api = ApiVersion {
        major: 1,
        minor: 48,
    };
    let engine = Arc::new(
        HttpEngine::connect_unix_socket(std::path::Path::new("/var/run/docker.sock"), api)
            .map_err(|_| LocalDockerError::new(LocalDockerErrorCode::InvalidEngineResponse))?,
    );
    let facts = engine.engine_facts().await.map_err(map_engine_call)?;
    let architecture = validate_relay_facts(&facts, api)?;
    if architecture != expected_architecture {
        return Err(LocalDockerError::new(
            LocalDockerErrorCode::EngineArchitectureMismatch,
        ));
    }
    let pinned = PinnedDockerEngine {
        engine: engine.clone(),
        facts,
        api,
        architecture,
    };
    pinned.verify().await?;
    Ok((pinned, engine))
}

#[cfg(unix)]
fn relay_matches_runner_architecture(
    relay: crate::EngineArchitecture,
    runner: &Architecture,
) -> bool {
    matches!(
        (relay, runner),
        (crate::EngineArchitecture::Amd64, Architecture::X86_64)
            | (crate::EngineArchitecture::Arm64, Architecture::Aarch64)
    )
}

#[cfg(unix)]
fn validate_relay_facts(
    facts: &EngineFacts,
    api: ApiVersion,
) -> Result<crate::EngineArchitecture, LocalDockerError> {
    let minimum = ApiVersion::parse(&facts.minimum_api_version)
        .ok_or_else(|| LocalDockerError::new(LocalDockerErrorCode::InvalidEngineResponse))?;
    let maximum = ApiVersion::parse(&facts.maximum_api_version)
        .ok_or_else(|| LocalDockerError::new(LocalDockerErrorCode::InvalidEngineResponse))?;
    let architecture = normalize_architecture(&facts.architecture)
        .ok_or_else(|| LocalDockerError::new(LocalDockerErrorCode::InvalidEngineResponse))?;
    let security_options: BTreeSet<&str> =
        facts.security_options.iter().map(String::as_str).collect();
    if facts.security_options.is_empty()
        || security_options.len() != facts.security_options.len()
        || facts.security_options.iter().any(String::is_empty)
    {
        return Err(LocalDockerError::new(
            LocalDockerErrorCode::InvalidEngineResponse,
        ));
    }
    let required_security_options = BTreeSet::from([
        SECURITY_OPTION_CGROUP_NAMESPACE,
        SECURITY_OPTION_SECCOMP_BUILTIN,
        SECURITY_OPTION_USER_NAMESPACE,
    ]);
    let allowed_security_options = BTreeSet::from([
        SECURITY_OPTION_CGROUP_NAMESPACE,
        SECURITY_OPTION_NO_NEW_PRIVILEGES,
        SECURITY_OPTION_SECCOMP_BUILTIN,
        SECURITY_OPTION_USER_NAMESPACE,
    ]);
    if !required_security_options.is_subset(&security_options)
        || !security_options.is_subset(&allowed_security_options)
        || security_options.contains(SECURITY_OPTION_ROOTLESS)
        || !facts.memory_limit
        || !facts.swap_limit
        || !facts.cpu_cfs_period
        || !facts.cpu_cfs_quota
        || !facts.pids_limit
    {
        return Err(LocalDockerError::new(
            LocalDockerErrorCode::EngineIsolationUnavailable,
        ));
    }
    if facts.engine_id.is_empty()
        || !docker_engine_28_or_newer(&facts.server_version)
        || facts.operating_system != "linux"
        || minimum > api
        || maximum < api
    {
        return Err(LocalDockerError::new(
            LocalDockerErrorCode::EngineIdentityChanged,
        ));
    }
    Ok(architecture)
}

#[cfg(unix)]
fn docker_engine_28_or_newer(value: &str) -> bool {
    let mut components = value.split('.');
    let Some(major) = components.next() else {
        return false;
    };
    let Some(minor) = components.next() else {
        return false;
    };
    let Some(patch) = components.next() else {
        return false;
    };
    components.next().is_none()
        && [major, minor, patch].iter().all(|component| {
            !component.is_empty()
                && component.bytes().all(|byte| byte.is_ascii_digit())
                && (component.len() == 1 || !component.starts_with('0'))
        })
        && major.parse::<u64>().is_ok_and(|major| major >= 28)
}

#[cfg(all(test, unix))]
mod relay_tests {
    use automata_ci_core::Architecture;

    use super::{
        ApiVersion, EngineFacts, LocalDockerErrorCode, SECURITY_OPTION_CGROUP_NAMESPACE,
        SECURITY_OPTION_NO_NEW_PRIVILEGES, SECURITY_OPTION_ROOTLESS,
        SECURITY_OPTION_SECCOMP_BUILTIN, SECURITY_OPTION_USER_NAMESPACE,
        relay_matches_runner_architecture, validate_relay_facts,
    };
    use crate::EngineArchitecture;

    fn facts(security_options: &[&str]) -> EngineFacts {
        EngineFacts {
            engine_id: "relay-engine".to_owned(),
            server_version: "29.7.2".to_owned(),
            minimum_api_version: "1.40".to_owned(),
            maximum_api_version: "1.55".to_owned(),
            operating_system: "linux".to_owned(),
            architecture: "amd64".to_owned(),
            security_options: security_options
                .iter()
                .map(|option| (*option).to_owned())
                .collect(),
            memory_limit: true,
            swap_limit: true,
            cpu_cfs_period: true,
            cpu_cfs_quota: true,
            pids_limit: true,
        }
    }

    fn code(security_options: &[&str]) -> LocalDockerErrorCode {
        validate_relay_facts(
            &facts(security_options),
            ApiVersion {
                major: 1,
                minor: 48,
            },
        )
        .expect_err("security options must be rejected")
        .code()
    }

    const fn api() -> ApiVersion {
        ApiVersion {
            major: 1,
            minor: 48,
        }
    }

    fn qualified_facts() -> EngineFacts {
        facts(&[
            SECURITY_OPTION_CGROUP_NAMESPACE,
            SECURITY_OPTION_SECCOMP_BUILTIN,
            SECURITY_OPTION_USER_NAMESPACE,
        ])
    }

    #[test]
    fn relay_requires_the_closed_rootful_security_envelope() {
        assert!(validate_relay_facts(&qualified_facts(), api()).is_ok());
        assert!(
            validate_relay_facts(
                &facts(&[
                    SECURITY_OPTION_CGROUP_NAMESPACE,
                    SECURITY_OPTION_NO_NEW_PRIVILEGES,
                    SECURITY_OPTION_SECCOMP_BUILTIN,
                    SECURITY_OPTION_USER_NAMESPACE,
                ]),
                api(),
            )
            .is_ok()
        );
        assert_eq!(code(&[]), LocalDockerErrorCode::InvalidEngineResponse);
        for rejected in [
            vec![
                SECURITY_OPTION_SECCOMP_BUILTIN,
                SECURITY_OPTION_USER_NAMESPACE,
            ],
            vec![
                SECURITY_OPTION_CGROUP_NAMESPACE,
                SECURITY_OPTION_USER_NAMESPACE,
            ],
            vec![
                SECURITY_OPTION_CGROUP_NAMESPACE,
                SECURITY_OPTION_SECCOMP_BUILTIN,
            ],
            vec![
                SECURITY_OPTION_CGROUP_NAMESPACE,
                SECURITY_OPTION_ROOTLESS,
                SECURITY_OPTION_SECCOMP_BUILTIN,
                SECURITY_OPTION_USER_NAMESPACE,
            ],
            vec![
                "name=apparmor",
                SECURITY_OPTION_CGROUP_NAMESPACE,
                SECURITY_OPTION_SECCOMP_BUILTIN,
                SECURITY_OPTION_USER_NAMESPACE,
            ],
            vec![
                SECURITY_OPTION_CGROUP_NAMESPACE,
                SECURITY_OPTION_SECCOMP_BUILTIN,
                "name=selinux",
                SECURITY_OPTION_USER_NAMESPACE,
            ],
            vec![
                SECURITY_OPTION_CGROUP_NAMESPACE,
                "name=future-security-feature",
                SECURITY_OPTION_SECCOMP_BUILTIN,
                SECURITY_OPTION_USER_NAMESPACE,
            ],
        ] {
            assert_eq!(
                code(&rejected),
                LocalDockerErrorCode::EngineIsolationUnavailable
            );
        }
        assert_eq!(
            code(&[
                SECURITY_OPTION_CGROUP_NAMESPACE,
                SECURITY_OPTION_SECCOMP_BUILTIN,
                SECURITY_OPTION_USER_NAMESPACE,
                SECURITY_OPTION_USER_NAMESPACE,
            ]),
            LocalDockerErrorCode::InvalidEngineResponse
        );
        assert_eq!(
            code(&[SECURITY_OPTION_USER_NAMESPACE, ""]),
            LocalDockerErrorCode::InvalidEngineResponse
        );
    }

    #[test]
    fn relay_requires_every_advertised_resource_controller() {
        for disabled in 0..5 {
            let mut facts = qualified_facts();
            match disabled {
                0 => facts.memory_limit = false,
                1 => facts.swap_limit = false,
                2 => facts.cpu_cfs_period = false,
                3 => facts.cpu_cfs_quota = false,
                4 => facts.pids_limit = false,
                _ => unreachable!(),
            }
            assert_eq!(
                validate_relay_facts(&facts, api())
                    .expect_err("missing controller must reject the relay")
                    .code(),
                LocalDockerErrorCode::EngineIsolationUnavailable
            );
        }
    }

    #[test]
    fn relay_architecture_must_equal_the_advertised_runner_architecture() {
        assert!(relay_matches_runner_architecture(
            EngineArchitecture::Amd64,
            &Architecture::X86_64,
        ));
        assert!(relay_matches_runner_architecture(
            EngineArchitecture::Arm64,
            &Architecture::Aarch64,
        ));
        assert!(!relay_matches_runner_architecture(
            EngineArchitecture::Amd64,
            &Architecture::Aarch64,
        ));
        assert!(!relay_matches_runner_architecture(
            EngineArchitecture::Arm64,
            &Architecture::X86_64,
        ));
        assert!(!relay_matches_runner_architecture(
            EngineArchitecture::Amd64,
            &Architecture::Other("amd64".to_owned()),
        ));
    }
}

#[cfg(unix)]
pub(crate) async fn verify_installation_identity(
    engine: &dyn AnchorEngineApi,
    installation: &Installation,
) -> Result<(), LocalDockerError> {
    match inspect_verified_identity(engine, installation.name()).await? {
        Some(observed) if observed == *installation => Ok(()),
        Some(_) | None => Err(LocalDockerError::new(
            LocalDockerErrorCode::InvalidIdentityAnchor,
        )),
    }
}

#[cfg(unix)]
pub(crate) async fn resolve_installation_binding(
    engine: &dyn AnchorEngineApi,
    binding: &InstallationBinding,
) -> Result<Installation, LocalDockerError> {
    match inspect_verified_identity(engine, binding.name()).await? {
        Some(observed) if observed.id() == binding.id() => Ok(observed),
        Some(_) | None => Err(LocalDockerError::new(
            LocalDockerErrorCode::InvalidIdentityAnchor,
        )),
    }
}
