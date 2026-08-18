//! Pure resource-contract classifiers and validators used by lifecycle operations.

use super::{
    cas::{
        cas_digest_reader_labels, cas_target_for_slug, cas_volume_role, cas_writer_user,
        desired_reader_labels, validate_cas_digest_reader, validate_cas_writer,
        validate_desired_reader,
    },
    common::{
        BTreeMap, BTreeSet, CAS_DIGEST_READER_KIND, CAS_WRITER_KIND, CancellationToken,
        ContainerSummary, DESIRED_READER_KIND, DesiredSpec, ExpectedContainer,
        ExpectedLifecycleTopology, ExpectedMountSource, ExpectedNetwork, HashMap, HostConfig,
        HostConfigCgroupnsModeEnum, HostConfigIsolationEnum, ImageConfig, ImmutableEpoch,
        Installation, IpamConfig, LABEL_COMPOSE_PROJECT, LABEL_EPOCH, LABEL_INSTALLATION_ID,
        LABEL_INSTALLATION_KEY, LABEL_MANAGED, LABEL_PLAN, LABEL_RESOURCE_KIND,
        LIFECYCLE_ATTESTER_KIND, LifecycleSiblingContainer, LifecycleSiblingNetwork,
        LocalInitError, LocalInitErrorCode, MountBindOptionsPropagationEnum, MountType, Network,
        NetworkInspect, OperationId, RestartPolicyNameEnum, ResultsTransitNetworkShape,
        SealedImageStatus, Sha256Digest, VolumeRole, engine_resource_mismatch, exact_container_id,
        exact_container_id_text, exact_results_transit_base, helper_readonly_paths,
        lifecycle_material_attester_labels, lifecycle_material_attester_name, results_transit_name,
        validate_helper, volume_name,
    },
    lock::lifecycle_lock_name,
};

pub(super) struct PinnedLocalDockerContainer {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) kind: String,
    pub(super) runner_id: uuid::Uuid,
}

pub(super) struct PinnedLocalDockerNetwork {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) runner_id: uuid::Uuid,
}

pub(super) fn local_docker_container_candidates(
    containers: &[PinnedLocalDockerContainer],
) -> Vec<LifecycleSiblingContainer> {
    containers
        .iter()
        .map(|item| LifecycleSiblingContainer {
            id: item.id.clone(),
            name: item.name.clone(),
            kind: item.kind.clone(),
        })
        .collect()
}

pub(super) fn local_docker_network_candidates(
    networks: &[PinnedLocalDockerNetwork],
) -> Vec<LifecycleSiblingNetwork> {
    networks
        .iter()
        .map(|item| LifecycleSiblingNetwork {
            id: item.id.clone(),
            name: item.name.clone(),
        })
        .collect()
}

pub(super) fn sole_local_docker_runner_id(
    runner_ids: BTreeSet<uuid::Uuid>,
) -> Result<Option<uuid::Uuid>, LocalInitError> {
    if runner_ids.len() > 1 {
        Err(engine_resource_mismatch())
    } else {
        Ok(runner_ids.into_iter().next())
    }
}

pub(super) struct RenderedLiveIds {
    pub(super) control: Option<String>,
    pub(super) networks: BTreeMap<String, String>,
    pub(super) none_network: String,
}

#[derive(Eq, PartialEq)]
pub(super) struct LifecycleIdentityCensus {
    pub(super) containers: BTreeSet<(String, String, Option<String>, Option<String>)>,
    pub(super) networks: BTreeSet<(String, String)>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct PinnedLifecycleHelper {
    pub(super) id: String,
    pub(super) name: String,
}

pub(super) fn stopped_disposable_state_is_quiescent(
    container: &bollard::models::ContainerInspectResponse,
) -> bool {
    container.state.as_ref().is_some_and(|state| {
        state.running == Some(false)
            && state.pid.is_none_or(|pid| pid == 0)
            && state.paused == Some(false)
            && state.restarting == Some(false)
            && state.dead == Some(false)
            && state.oom_killed == Some(false)
            && state.error.as_deref().is_none_or(str::is_empty)
    })
}

pub(super) fn lifecycle_cancellation_checkpoint(
    cancellation: &CancellationToken,
) -> Result<(), LocalInitError> {
    if cancellation.is_cancelled() {
        Err(LocalInitError::new(LocalInitErrorCode::Cancelled))
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn validate_lifecycle_disposable_helper(
    container: &bollard::models::ContainerInspectResponse,
    name: &str,
    installation: &Installation,
    epoch: &ImmutableEpoch,
    automata: &SealedImageStatus,
    volumes: &BTreeMap<VolumeRole, String>,
) -> Result<Option<PinnedLifecycleHelper>, LocalInitError> {
    let id = exact_container_id(container)?.to_owned();
    let labels = container
        .config
        .as_ref()
        .and_then(|config| config.labels.as_ref())
        .into_iter()
        .flatten()
        .filter(|(key, _)| key.starts_with("io.automata.local."))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let kind = labels.get(LABEL_RESOURCE_KIND).map(String::as_str);
    let project = installation.compose_project();
    let recognized = match kind {
        Some(LIFECYCLE_ATTESTER_KIND) if name == lifecycle_material_attester_name(installation) => {
            let expected_labels =
                lifecycle_material_attester_labels(installation, epoch.fingerprint());
            validate_helper(
                container,
                &id,
                name,
                &automata.inspection_reference,
                &automata.image_id,
                volumes,
                &expected_labels,
            )
            .map_err(|_| engine_resource_mismatch())?;
            true
        }
        Some(DESIRED_READER_KIND) if name == format!("{project}-desired-reader") => {
            let desired_volume = volumes
                .get(&VolumeRole::Desired)
                .ok_or_else(engine_resource_mismatch)?;
            validate_desired_reader(
                container,
                &id,
                name,
                &automata.inspection_reference,
                &automata.image_id,
                desired_volume,
                &desired_reader_labels(installation, epoch.fingerprint()),
            )?;
            true
        }
        Some(CAS_DIGEST_READER_KIND) => {
            let prefix = format!("{project}-");
            let slug = name
                .strip_prefix(&prefix)
                .and_then(|name| name.strip_suffix("-cas-digest"));
            let target = slug
                .and_then(cas_target_for_slug)
                .ok_or_else(engine_resource_mismatch)?;
            let volume = volumes
                .get(&cas_volume_role(target))
                .ok_or_else(engine_resource_mismatch)?;
            validate_cas_digest_reader(
                container,
                &id,
                name,
                &automata.inspection_reference,
                &automata.image_id,
                volume,
                &cas_digest_reader_labels(installation, epoch, target),
            )?;
            true
        }
        Some(CAS_WRITER_KIND) => {
            let prefix = format!("{project}-");
            let slug = name
                .strip_prefix(&prefix)
                .and_then(|name| name.strip_suffix("-cas"));
            let target = slug
                .and_then(cas_target_for_slug)
                .ok_or_else(engine_resource_mismatch)?;
            let expected = labels
                .get("io.automata.local.cas-expected-sha256")
                .ok_or_else(engine_resource_mismatch)?;
            let replacement = labels
                .get("io.automata.local.cas-replacement-sha256")
                .ok_or_else(engine_resource_mismatch)?;
            let expected_plan = epoch.desired_plan_sha256().map(|digest| digest.to_string());
            if (expected != "absent"
                && expected
                    .parse::<Sha256Digest>()
                    .ok()
                    .is_none_or(|digest| digest.to_string() != *expected))
                || replacement
                    .parse::<Sha256Digest>()
                    .ok()
                    .is_none_or(|digest| digest.to_string() != *replacement)
                || labels.len() != 10
                || labels.get(LABEL_MANAGED).map(String::as_str) != Some("true")
                || labels.get(LABEL_INSTALLATION_ID) != Some(&installation.id().to_string())
                || labels.get(LABEL_INSTALLATION_KEY)
                    != Some(&installation.selector_key().to_string())
                || labels.get(LABEL_COMPOSE_PROJECT) != Some(&project.to_string())
                || labels.get(LABEL_EPOCH) != Some(&epoch.fingerprint().to_string())
                || labels.get(LABEL_PLAN) != expected_plan.as_ref()
                || labels
                    .get("io.automata.local.cas-target")
                    .map(String::as_str)
                    != Some(target.slug())
            {
                return Err(engine_resource_mismatch());
            }
            let volume = volumes
                .get(&cas_volume_role(target))
                .ok_or_else(engine_resource_mismatch)?;
            let user = cas_writer_user(target);
            let cap_add = if user == "0:0" {
                vec!["DAC_OVERRIDE".to_owned()]
            } else {
                Vec::new()
            };
            validate_cas_writer(
                container,
                &id,
                name,
                &automata.inspection_reference,
                &automata.image_id,
                volume,
                user,
                &cap_add,
                &labels,
            )?;
            true
        }
        _ => false,
    };
    if !recognized {
        return Ok(None);
    }
    if !stopped_disposable_state_is_quiescent(container) {
        return Err(engine_resource_mismatch());
    }
    Ok(Some(PinnedLifecycleHelper {
        id,
        name: name.to_owned(),
    }))
}

pub(super) fn lifecycle_container_candidate(
    summary: &ContainerSummary,
    installation: &Installation,
    expected_names: &BTreeMap<String, &str>,
    attachment_ids: &BTreeSet<String>,
    local_prefix: &str,
) -> bool {
    let names = summary.names.as_ref().into_iter().flatten();
    let deterministic = names.clone().any(|name| {
        let name = name.trim_start_matches('/');
        expected_names.contains_key(name)
            || name == lifecycle_lock_name(installation)
            || lifecycle_disposable_helper_name(name, installation)
            || name.starts_with(local_prefix)
    });
    let labeled = summary.labels.as_ref().is_some_and(|labels| {
        labels.get("com.docker.compose.project")
            == Some(&installation.compose_project().to_string())
            || labels.get(LABEL_INSTALLATION_ID) == Some(&installation.id().to_string())
            || labels.get(LABEL_INSTALLATION_KEY) == Some(&installation.selector_key().to_string())
            || labels.get(LABEL_COMPOSE_PROJECT)
                == Some(&installation.compose_project().to_string())
    });
    deterministic
        || labeled
        || summary
            .id
            .as_ref()
            .is_some_and(|id| attachment_ids.contains(id))
}

pub(super) fn lifecycle_disposable_helper_name(name: &str, installation: &Installation) -> bool {
    let project = installation.compose_project();
    name == format!("{project}-init-materializer")
        || name == format!("{project}-material-attester")
        || name == format!("{project}-desired-reader")
        || (name.starts_with(&format!("{project}-"))
            && (name.ends_with("-cas") || name.ends_with("-cas-digest")))
}

pub(super) fn lifecycle_network_candidate(
    network: &Network,
    installation: &Installation,
    expected: &ExpectedLifecycleTopology,
    transit_name: &str,
    local_prefix: &str,
) -> bool {
    let deterministic = network.name.as_deref().is_some_and(|name| {
        name == transit_name
            || name.starts_with(local_prefix)
            || expected
                .networks
                .values()
                .any(|expected| expected.name == name)
    });
    let labeled = network.labels.as_ref().is_some_and(|labels| {
        labels.get("com.docker.compose.project")
            == Some(&installation.compose_project().to_string())
            || labels.get(LABEL_INSTALLATION_ID) == Some(&installation.id().to_string())
            || labels.get(LABEL_INSTALLATION_KEY) == Some(&installation.selector_key().to_string())
            || labels.get(LABEL_COMPOSE_PROJECT)
                == Some(&installation.compose_project().to_string())
    });
    deterministic || labeled
}

#[allow(clippy::too_many_lines)]
pub(super) fn validate_rendered_network(
    network: &NetworkInspect,
    installation: &Installation,
    expected: &ExpectedNetwork,
    expected_container_ids: &BTreeMap<String, String>,
    expected_id: Option<&str>,
) -> Result<(), LocalInitError> {
    let id = network
        .id
        .as_deref()
        .filter(|id| exact_container_id_text(id))
        .ok_or_else(engine_resource_mismatch)?;
    if expected_id != Some(id) {
        return Err(engine_resource_mismatch());
    }
    let labels = network
        .labels
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let managed = labels
        .iter()
        .filter(|(key, _)| key.starts_with("io.automata.local."))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let options = network
        .options
        .as_ref()
        .into_iter()
        .flatten()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let ipam = network.ipam.as_ref().ok_or_else(engine_resource_mismatch)?;
    let configs = ipam
        .config
        .as_deref()
        .ok_or_else(engine_resource_mismatch)?;
    if network.name.as_deref() != Some(expected.name.as_str())
        || network.scope.as_deref() != Some("local")
        || network.driver.as_deref() != Some(expected.driver.as_str())
        || network.internal != Some(expected.internal)
        || network.attachable != Some(expected.attachable)
        || network.enable_ipv4 != Some(true)
        || network.enable_ipv6 != Some(expected.enable_ipv6)
        || network.ingress != Some(false)
        || network.config_only != Some(false)
        || network.config_from.as_ref().is_some_and(|reference| {
            reference
                .network
                .as_deref()
                .is_some_and(|network| !network.is_empty())
        })
        || options != expected.driver_options
        || ipam.driver.as_deref() != Some(expected.ipam_driver.as_str())
        || ipam
            .options
            .as_ref()
            .is_some_and(|options| !options.is_empty())
        || configs
            != [IpamConfig {
                subnet: Some(expected.subnet.clone()),
                gateway: Some(expected.gateway.clone()),
                ip_range: None,
                auxiliary_addresses: None,
            }]
        || managed != expected.labels
        || labels.get("com.docker.compose.project").map(String::as_str)
            != Some(installation.compose_project().as_str())
    {
        return Err(engine_resource_mismatch());
    }
    for endpoint in network.containers.as_ref().into_iter().flatten() {
        let name = endpoint
            .1
            .name
            .as_deref()
            .ok_or_else(engine_resource_mismatch)?;
        if !exact_container_id_text(endpoint.0)
            || expected_container_ids.get(name).map(String::as_str) != Some(endpoint.0)
        {
            return Err(engine_resource_mismatch());
        }
    }
    Ok(())
}

pub(super) fn local_docker_name_prefix(installation: &Installation) -> String {
    format!("automata-local-{}-", installation.id().as_uuid().simple())
}

pub(super) fn local_docker_candidate_container(
    summary: &ContainerSummary,
    installation: &Installation,
    prefix: &str,
) -> bool {
    summary
        .names
        .as_ref()
        .into_iter()
        .flatten()
        .any(|name| name.trim_start_matches('/').starts_with(prefix))
        || summary.labels.as_ref().is_some_and(|labels| {
            labels.get("io.automata.local.job-schema").is_some()
                && labels.get(LABEL_INSTALLATION_ID) == Some(&installation.id().to_string())
        })
}

pub(super) fn local_docker_candidate_network(
    network: &Network,
    installation: &Installation,
    prefix: &str,
) -> bool {
    network
        .name
        .as_deref()
        .is_some_and(|name| name.starts_with(prefix))
        || network.labels.as_ref().is_some_and(|labels| {
            labels.get("io.automata.local.job-schema").is_some()
                && labels.get(LABEL_INSTALLATION_ID) == Some(&installation.id().to_string())
        })
}

pub(super) fn validate_local_docker_container_summary(
    summary: &ContainerSummary,
    installation: &Installation,
) -> Result<PinnedLocalDockerContainer, LocalInitError> {
    let id = summary
        .id
        .as_deref()
        .filter(|id| exact_container_id_text(id))
        .ok_or_else(engine_resource_mismatch)?
        .to_owned();
    let names = summary
        .names
        .as_deref()
        .ok_or_else(engine_resource_mismatch)?;
    if names.len() != 1 {
        return Err(engine_resource_mismatch());
    }
    let name = names[0]
        .strip_prefix('/')
        .ok_or_else(engine_resource_mismatch)?
        .to_owned();
    let labels = summary
        .labels
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let (expected_name, kind, runner_id) = validate_local_docker_labels(labels, installation)?;
    if name != expected_name || kind == "results-front-network" {
        return Err(engine_resource_mismatch());
    }
    Ok(PinnedLocalDockerContainer {
        id,
        name,
        kind,
        runner_id,
    })
}

pub(super) fn validate_local_docker_network(
    network: &Network,
    installation: &Installation,
    _known_container_names: &BTreeSet<String>,
) -> Result<PinnedLocalDockerNetwork, LocalInitError> {
    let id = network
        .id
        .as_deref()
        .filter(|id| exact_container_id_text(id))
        .ok_or_else(engine_resource_mismatch)?
        .to_owned();
    let name = network
        .name
        .as_deref()
        .ok_or_else(engine_resource_mismatch)?
        .to_owned();
    let labels = network
        .labels
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let (expected_name, kind, runner_id) = validate_local_docker_labels(labels, installation)?;
    if name != expected_name || kind != "results-front-network" {
        return Err(engine_resource_mismatch());
    }
    Ok(PinnedLocalDockerNetwork {
        id,
        name,
        runner_id,
    })
}

pub(super) fn validate_local_docker_network_inspect(
    network: &NetworkInspect,
    pinned: &PinnedLocalDockerNetwork,
    installation: &Installation,
    known_container_names: &BTreeSet<String>,
) -> Result<(), LocalInitError> {
    let labels = network
        .labels
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let (expected_name, kind, _) = validate_local_docker_labels(labels, installation)?;
    let attached = network
        .containers
        .as_ref()
        .into_iter()
        .flatten()
        .map(|(_, endpoint)| endpoint.name.clone().ok_or_else(engine_resource_mismatch))
        .collect::<Result<BTreeSet<_>, LocalInitError>>()?;
    if network.id.as_deref() != Some(pinned.id.as_str())
        || network.name.as_deref() != Some(pinned.name.as_str())
        || expected_name != pinned.name
        || kind != "results-front-network"
        || !attached.is_subset(known_container_names)
    {
        return Err(engine_resource_mismatch());
    }
    Ok(())
}

pub(super) fn validate_local_docker_labels(
    labels: &HashMap<String, String>,
    installation: &Installation,
) -> Result<(String, String, uuid::Uuid), LocalInitError> {
    const KEYS: [&str; 15] = [
        LABEL_MANAGED,
        "io.automata.local.job-schema",
        LABEL_INSTALLATION_ID,
        LABEL_INSTALLATION_KEY,
        LABEL_COMPOSE_PROJECT,
        "io.automata.local.runner-id",
        "io.automata.local.custody-kind",
        "io.automata.local.slot",
        "io.automata.local.operation-id",
        "io.automata.local.generation",
        "io.automata.local.profile",
        "io.automata.local.profile-sha256",
        "io.automata.local.spec-sha256",
        "io.automata.local.realized-sha256",
        LABEL_RESOURCE_KIND,
    ];
    let managed = labels
        .iter()
        .filter(|(key, _)| key.starts_with("io.automata.local."))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    if managed.keys().any(|key| !KEYS.contains(&key.as_str()))
        || managed.get(LABEL_MANAGED).map(String::as_str) != Some("true")
        || managed
            .get("io.automata.local.job-schema")
            .map(String::as_str)
            != Some("2")
        || managed.get(LABEL_INSTALLATION_ID) != Some(&installation.id().to_string())
        || managed.get(LABEL_INSTALLATION_KEY) != Some(&installation.selector_key().to_string())
        || managed.get(LABEL_COMPOSE_PROJECT) != Some(&installation.compose_project().to_string())
    {
        return Err(engine_resource_mismatch());
    }
    let operation_text = managed
        .get("io.automata.local.operation-id")
        .ok_or_else(engine_resource_mismatch)?;
    let operation_id = operation_text
        .parse::<OperationId>()
        .ok()
        .filter(|value| value.to_string() == *operation_text)
        .ok_or_else(engine_resource_mismatch)?;
    let generation_text = managed
        .get("io.automata.local.generation")
        .ok_or_else(engine_resource_mismatch)?;
    let generation = generation_text
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0 && value.to_string() == *generation_text)
        .ok_or_else(engine_resource_mismatch)?;
    let runner_text = managed
        .get("io.automata.local.runner-id")
        .ok_or_else(engine_resource_mismatch)?;
    let runner_id = uuid::Uuid::parse_str(runner_text)
        .ok()
        .filter(|value| value.hyphenated().to_string() == *runner_text)
        .ok_or_else(engine_resource_mismatch)?;
    if runner_id.is_nil()
        || managed
            .get("io.automata.local.profile")
            .is_none_or(String::is_empty)
        || managed
            .get("io.automata.local.profile-sha256")
            .and_then(|value| value.parse::<Sha256Digest>().ok())
            .is_none()
        || managed
            .get("io.automata.local.spec-sha256")
            .and_then(|value| value.parse::<Sha256Digest>().ok())
            .is_none()
        || managed
            .get("io.automata.local.realized-sha256")
            .and_then(|value| value.parse::<Sha256Digest>().ok())
            .is_none()
    {
        return Err(engine_resource_mismatch());
    }
    let custody = managed
        .get("io.automata.local.custody-kind")
        .map(String::as_str)
        .ok_or_else(engine_resource_mismatch)?;
    match custody {
        "profile-admission"
            if managed.len() == 14 && !managed.contains_key("io.automata.local.slot") => {}
        "job" if managed.len() == 15 => {
            let slot = managed
                .get("io.automata.local.slot")
                .and_then(|value| value.parse::<u16>().ok())
                .filter(|value| *value > 0 && *value <= crate::MAXIMUM_LOCAL_DOCKER_JOB_SLOTS)
                .ok_or_else(engine_resource_mismatch)?;
            if slot.to_string() != managed["io.automata.local.slot"] {
                return Err(engine_resource_mismatch());
            }
        }
        _ => return Err(engine_resource_mismatch()),
    }
    let kind = managed
        .get(LABEL_RESOURCE_KIND)
        .cloned()
        .ok_or_else(engine_resource_mismatch)?;
    let suffix = match kind.as_str() {
        "job-container" => "job",
        "guest-source" => "guest-source",
        "results-proxy-container" => "results-proxy",
        "results-front-network" => "results-front",
        _ => return Err(engine_resource_mismatch()),
    };
    let expected_name = format!(
        "automata-local-{}-{}-{generation}-{suffix}",
        installation.id().as_uuid().simple(),
        operation_id.as_uuid().simple(),
    );
    Ok((expected_name, kind, runner_id))
}

pub(super) fn local_docker_delete_rank(kind: &str) -> u8 {
    match kind {
        "job-container" => 0,
        "guest-source" => 1,
        "results-proxy-container" => 2,
        _ => 3,
    }
}

pub(super) fn derive_rendered_live_ids(
    containers: &[ContainerSummary],
    networks: &[Network],
    installation: &Installation,
    expected: &ExpectedLifecycleTopology,
) -> Result<RenderedLiveIds, LocalInitError> {
    let control_name = format!("{}-automata-1", installation.compose_project());
    let mut control = None;
    for summary in containers {
        if !summary
            .names
            .as_ref()
            .into_iter()
            .flatten()
            .any(|name| name.strip_prefix('/') == Some(control_name.as_str()))
        {
            continue;
        }
        let id = summary
            .id
            .as_deref()
            .filter(|id| exact_container_id_text(id))
            .ok_or_else(engine_resource_mismatch)?;
        if control.replace(id.to_owned()).is_some() {
            return Err(engine_resource_mismatch());
        }
    }

    let transit_name = results_transit_name(installation);
    let expected_names = expected
        .networks
        .values()
        .map(|network| network.name.as_str())
        .chain(std::iter::once(transit_name.as_str()))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let mut pinned_networks = BTreeMap::new();
    let mut none_network = None;
    for network in networks {
        let Some(name) = network.name.as_deref() else {
            continue;
        };
        if name == "none" {
            let id = network
                .id
                .as_deref()
                .filter(|id| exact_container_id_text(id))
                .ok_or_else(engine_resource_mismatch)?;
            if none_network.replace(id.to_owned()).is_some() {
                return Err(engine_resource_mismatch());
            }
            continue;
        }
        if !expected_names.contains(name) {
            continue;
        }
        let id = network
            .id
            .as_deref()
            .filter(|id| exact_container_id_text(id))
            .ok_or_else(engine_resource_mismatch)?;
        if pinned_networks
            .insert(name.to_owned(), id.to_owned())
            .is_some()
        {
            return Err(engine_resource_mismatch());
        }
    }
    Ok(RenderedLiveIds {
        control,
        networks: pinned_networks,
        none_network: none_network.ok_or_else(engine_resource_mismatch)?,
    })
}

#[allow(clippy::too_many_lines)]
pub(super) fn validate_rendered_container(
    container: &bollard::models::ContainerInspectResponse,
    name: &str,
    image_id: &str,
    installation: &Installation,
    expected: &ExpectedContainer,
    expected_topology: &ExpectedLifecycleTopology,
    desired: &DesiredSpec,
    image: &ImageConfig,
    live_ids: &RenderedLiveIds,
    require_running: bool,
) -> Result<(), LocalInitError> {
    let id = container
        .id
        .as_deref()
        .filter(|id| exact_container_id_text(id))
        .ok_or_else(engine_resource_mismatch)?;
    let config = container
        .config
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let host = container
        .host_config
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let state = container
        .state
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let realized_running = if rendered_process_is_running(state) {
        true
    } else if rendered_process_is_stopped(state) {
        false
    } else {
        return Err(engine_resource_mismatch());
    };
    let network = container
        .network_settings
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let labels = config
        .labels
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let managed = labels
        .iter()
        .filter(|(key, _)| key.starts_with("io.automata.local."))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let environment = exact_environment(config.env.as_deref().unwrap_or_default())?;
    let mut expected_environment = exact_environment(image.env.as_deref().unwrap_or_default())?;
    expected_environment.extend(expected.environment.clone());
    let expected_entrypoint = expected
        .entrypoint
        .as_deref()
        .or(image.entrypoint.as_deref())
        .unwrap_or_default();
    let expected_process = expected_entrypoint
        .iter()
        .chain(expected.command.iter())
        .collect::<Vec<_>>();
    let expected_path = expected_process
        .first()
        .map(|value| value.as_str())
        .ok_or_else(engine_resource_mismatch)?;
    let expected_hostname = if expected.network_mode.as_deref() == Some("service:automata") {
        let control = live_ids
            .control
            .as_deref()
            .filter(|id| exact_container_id_text(id))
            .ok_or_else(engine_resource_mismatch)?;
        &control[..12]
    } else {
        &id[..12]
    };
    let expected_args = expected_process
        .get(1..)
        .expect("a nonempty process always has a tail")
        .iter()
        .map(|value| (*value).clone())
        .collect::<Vec<_>>();
    let expected_volumes = image
        .volumes
        .as_deref()
        .unwrap_or_default()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let realized_volumes = config
        .volumes
        .as_deref()
        .unwrap_or_default()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if container.name.as_deref() != Some(format!("/{name}").as_str())
        || container.image.as_deref() != Some(image_id)
        || container.platform.as_deref() != Some("linux")
        || container.path.as_deref() != Some(expected_path)
        || container.args.as_deref().unwrap_or_default() != expected_args
        || expected.platform != "linux/amd64"
        || config.image.as_deref() != Some(expected.image_reference.as_str())
        || config.hostname.as_deref() != Some(expected_hostname)
        || config.domainname.as_deref().unwrap_or_default() != ""
        || config.user.as_deref() != Some(expected.user.as_str())
        || config.cmd.as_deref() != Some(expected.command.as_slice())
        || config.entrypoint.as_deref().unwrap_or_default() != expected_entrypoint
        || config.working_dir.as_deref().unwrap_or_default()
            != image.working_dir.as_deref().unwrap_or_default()
        || config.stop_signal.as_deref().unwrap_or_default()
            != image.stop_signal.as_deref().unwrap_or_default()
        || config.stop_timeout.is_some()
        || config.on_build.as_deref().unwrap_or_default()
            != image.on_build.as_deref().unwrap_or_default()
        || config.shell.as_deref().unwrap_or_default() != image.shell.as_deref().unwrap_or_default()
        || config.args_escaped.unwrap_or(false)
        || realized_volumes != expected_volumes
        || environment != expected_environment
        || config.attach_stdin != Some(expected.stdin_open)
        || config.attach_stdout != Some(true)
        || config.attach_stderr != Some(true)
        || config.open_stdin != Some(expected.stdin_open)
        || config.stdin_once != Some(false)
        || config.tty != Some(expected.tty)
        || config.network_disabled.unwrap_or(false)
        || managed != expected.labels
        || labels.get("com.docker.compose.project").map(String::as_str)
            != Some(installation.compose_project().as_str())
        || labels.get("com.docker.compose.service").map(String::as_str)
            != Some(expected.service.as_str())
        || labels.get("com.docker.compose.oneoff").map(String::as_str)
            != Some(if expected.oneoff() { "True" } else { "False" })
        || host.readonly_rootfs != Some(expected.read_only_root)
        || host.privileged != Some(expected.privileged)
        || host.cap_add.as_deref().unwrap_or_default() != expected.cap_add.as_slice()
        || host.cap_drop.as_deref().unwrap_or_default() != expected.cap_drop.as_slice()
        || host.security_opt.as_deref().unwrap_or_default() != expected.security_opt.as_slice()
        || host.init != Some(expected.init)
        || host.userns_mode.as_deref().unwrap_or_default()
            != expected.userns_mode.as_deref().unwrap_or_default()
        || rendered_host_has_extra_authority(host, expected)
        || host.auto_remove != Some(false)
        || host.log_config.as_ref().and_then(|log| log.typ.as_deref())
            != Some(expected.log_driver.as_str())
        || host
            .log_config
            .as_ref()
            .and_then(|log| log.config.as_ref())
            .is_none_or(|options| {
                options.iter().collect::<BTreeMap<_, _>>()
                    != expected.log_options.iter().collect::<BTreeMap<_, _>>()
            })
        || require_running && !rendered_container_is_running(container, expected)
    {
        return Err(engine_resource_mismatch());
    }

    validate_rendered_mounts(container, host, installation, expected)?;
    validate_rendered_ports(config, host, network, expected, image, realized_running)?;
    validate_rendered_health(config, expected)?;
    validate_rendered_tmpfs(host, expected)?;
    validate_rendered_restart(host, expected)?;
    validate_rendered_networks(
        network,
        host,
        id,
        name,
        installation,
        expected,
        expected_topology,
        desired,
        live_ids,
        realized_running,
    )
}

pub(super) fn rendered_process_is_running(state: &bollard::models::ContainerState) -> bool {
    state.running == Some(true)
        && state.paused == Some(false)
        && state.restarting == Some(false)
        && state.dead == Some(false)
        && state.oom_killed == Some(false)
        && state.pid.is_some_and(|pid| pid > 0)
        && state.error.as_deref().is_none_or(str::is_empty)
}

pub(super) fn rendered_process_is_stopped(state: &bollard::models::ContainerState) -> bool {
    state.running == Some(false)
        && state.paused == Some(false)
        && state.restarting == Some(false)
        && state.dead == Some(false)
        && state.oom_killed == Some(false)
        && state.pid.is_none_or(|pid| pid == 0)
        && state.error.as_deref().is_none_or(str::is_empty)
}

pub(super) fn rendered_container_is_running(
    container: &bollard::models::ContainerInspectResponse,
    expected: &ExpectedContainer,
) -> bool {
    container.state.as_ref().is_some_and(|state| {
        rendered_process_is_running(state)
            && (expected.healthcheck.is_none()
                || state.health.as_ref().and_then(|health| health.status)
                    == Some(bollard::models::HealthStatusEnum::HEALTHY))
    })
}

pub(super) fn rendered_host_has_extra_authority(
    host: &HostConfig,
    expected: &ExpectedContainer,
) -> bool {
    let nonempty = |value: Option<&Vec<String>>| value.is_some_and(|value| !value.is_empty());
    let nonzero = |value: Option<i64>| value.is_some_and(|value| value != 0);
    let nonempty_text = |value: Option<&String>| value.is_some_and(|value| !value.is_empty());
    nonempty_text(host.cgroup_parent.as_ref())
        || nonempty_text(host.cpuset_cpus.as_ref())
        || nonempty_text(host.cpuset_mems.as_ref())
        || nonempty_text(host.container_id_file.as_ref())
        || nonempty_text(host.volume_driver.as_ref())
        || host
            .pid_mode
            .as_deref()
            .is_some_and(|mode| !mode.is_empty())
        || host.ipc_mode.as_deref() != Some(expected.ipc.as_str())
        || host
            .uts_mode
            .as_deref()
            .is_some_and(|mode| !mode.is_empty())
        || host.cgroup.as_deref().is_some_and(|mode| !mode.is_empty())
        || host.runtime.as_deref() != Some(expected.runtime.as_str())
        || expected.cgroup != "private"
        || host.cgroupns_mode != Some(HostConfigCgroupnsModeEnum::PRIVATE)
        || host.publish_all_ports == Some(true)
        || host.oom_kill_disable == Some(true)
        || nonzero(host.cpu_shares)
        || nonzero(host.cpu_period)
        || nonzero(host.cpu_quota)
        || nonzero(host.cpu_realtime_period)
        || nonzero(host.cpu_realtime_runtime)
        || host.blkio_weight.is_some_and(|value| value != 0)
        || host
            .blkio_weight_device
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || host
            .blkio_device_read_bps
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || host
            .blkio_device_write_bps
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || host
            .blkio_device_read_iops
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || host
            .blkio_device_write_iops
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || nonzero(host.cpu_count)
        || nonzero(host.cpu_percent)
        || nonzero(host.io_maximum_iops)
        || nonzero(host.io_maximum_bandwidth)
        || nonzero(host.memory)
        || nonzero(host.memory_reservation)
        || nonzero(host.memory_swap)
        || nonzero(host.memory_swappiness)
        || nonzero(host.nano_cpus)
        || host
            .pids_limit
            .is_some_and(|value| !matches!(value, -1 | 0))
        || nonzero(host.oom_score_adj)
        || host.devices.as_ref().is_some_and(|value| !value.is_empty())
        || nonempty(host.device_cgroup_rules.as_ref())
        || host
            .device_requests
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || host.ulimits.as_ref().is_some_and(|value| !value.is_empty())
        || nonempty(host.binds.as_ref())
        || nonempty(host.volumes_from.as_ref())
        || nonempty(host.dns.as_ref())
        || nonempty(host.dns_options.as_ref())
        || nonempty(host.dns_search.as_ref())
        || nonempty(host.extra_hosts.as_ref())
        || nonempty(host.group_add.as_ref())
        || nonempty(host.links.as_ref())
        || host.console_size.as_deref() != Some([0, 0].as_slice())
        || host.shm_size != i64::try_from(expected.shm_size).ok()
        || host.isolation != Some(HostConfigIsolationEnum::EMPTY)
        || host
            .storage_opt
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || host.sysctls.as_ref().is_some_and(|value| !value.is_empty())
        || host
            .annotations
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || !valid_rendered_masked_paths(host.masked_paths.as_deref())
        || host.readonly_paths.as_deref().is_none_or(|paths| {
            paths.iter().collect::<BTreeSet<_>>()
                != helper_readonly_paths().iter().collect::<BTreeSet<_>>()
        })
}

pub(super) fn valid_rendered_masked_paths(paths: Option<&[String]>) -> bool {
    const REQUIRED: [&str; 11] = [
        "/proc/acpi",
        "/proc/asound",
        "/proc/kcore",
        "/proc/keys",
        "/proc/latency_stats",
        "/proc/sched_debug",
        "/proc/scsi",
        "/proc/timer_list",
        "/proc/timer_stats",
        "/sys/devices/virtual/powercap",
        "/sys/firmware",
    ];
    let Some(paths) = paths else {
        return false;
    };
    let observed = paths.iter().map(String::as_str).collect::<BTreeSet<_>>();
    if observed.len() != paths.len() || REQUIRED.iter().any(|path| !observed.contains(path)) {
        return false;
    }
    observed.into_iter().all(|path| {
        REQUIRED.contains(&path)
            || path == "/proc/interrupts"
            || path
                .strip_prefix("/sys/devices/system/cpu/cpu")
                .and_then(|suffix| suffix.strip_suffix("/thermal_throttle"))
                .and_then(|cpu| cpu.parse::<u32>().ok().map(|index| (cpu, index)))
                .is_some_and(|(cpu, index)| cpu == index.to_string())
    })
}

pub(super) fn exact_environment(
    values: &[String],
) -> Result<BTreeMap<String, String>, LocalInitError> {
    let mut parsed = BTreeMap::new();
    for value in values {
        let (key, value) = value.split_once('=').ok_or_else(engine_resource_mismatch)?;
        if key.is_empty() || parsed.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(engine_resource_mismatch());
        }
    }
    Ok(parsed)
}

pub(super) fn validate_rendered_mounts(
    container: &bollard::models::ContainerInspectResponse,
    host: &HostConfig,
    installation: &Installation,
    expected: &ExpectedContainer,
) -> Result<(), LocalInitError> {
    let expected_mounts = expected
        .mounts
        .iter()
        .map(|mount| {
            let (kind, source) = match &mount.source {
                ExpectedMountSource::Volume(role) => (
                    "volume",
                    volume_name(installation.compose_project().as_str(), *role),
                ),
                ExpectedMountSource::Bind { source, .. } => ("bind", source.clone()),
            };
            (
                kind.to_owned(),
                source,
                mount.target.clone(),
                mount.read_only,
                mount.volume_nocopy,
            )
        })
        .collect::<BTreeSet<_>>();
    let mut realized_host = BTreeSet::new();
    for mount in host.mounts.as_deref().unwrap_or_default() {
        let kind = match mount.typ {
            Some(MountType::VOLUME) => "volume",
            Some(MountType::BIND) => "bind",
            _ => return Err(engine_resource_mismatch()),
        };
        let no_copy = if kind == "volume" {
            mount
                .volume_options
                .as_ref()
                .and_then(|options| options.no_copy)
                .unwrap_or(false)
        } else {
            if mount.volume_options.is_some() {
                return Err(engine_resource_mismatch());
            }
            false
        };
        let target = mount
            .target
            .as_deref()
            .ok_or_else(engine_resource_mismatch)?;
        let expected_mount = expected
            .mounts
            .iter()
            .find(|expected| expected.target == target)
            .ok_or_else(engine_resource_mismatch)?;
        if mount
            .consistency
            .as_deref()
            .is_some_and(|value| !value.is_empty())
            || mount.image_options.is_some()
            || mount.tmpfs_options.is_some()
        {
            return Err(engine_resource_mismatch());
        }
        match (&expected_mount.source, kind) {
            (ExpectedMountSource::Volume(_), "volume") => {
                let options = mount
                    .volume_options
                    .as_ref()
                    .ok_or_else(engine_resource_mismatch)?;
                if mount.bind_options.is_some()
                    || options.no_copy != Some(expected_mount.volume_nocopy)
                    || options
                        .labels
                        .as_ref()
                        .is_some_and(|labels| !labels.is_empty())
                    || options.driver_config.is_some()
                    || options
                        .subpath
                        .as_deref()
                        .is_some_and(|subpath| !subpath.is_empty())
                {
                    return Err(engine_resource_mismatch());
                }
            }
            (
                ExpectedMountSource::Bind {
                    create_host_path,
                    propagation,
                    ..
                },
                "bind",
            ) => {
                let options = mount
                    .bind_options
                    .as_ref()
                    .ok_or_else(engine_resource_mismatch)?;
                if mount.volume_options.is_some()
                    || propagation != "rprivate"
                    || options.propagation != Some(MountBindOptionsPropagationEnum::RPRIVATE)
                    || options.non_recursive.unwrap_or(false)
                    || options.create_mountpoint.unwrap_or(false) != *create_host_path
                    || options.read_only_non_recursive.unwrap_or(false)
                    || options.read_only_force_recursive.unwrap_or(false)
                {
                    return Err(engine_resource_mismatch());
                }
            }
            _ => return Err(engine_resource_mismatch()),
        }
        if !realized_host.insert((
            kind.to_owned(),
            mount.source.clone().ok_or_else(engine_resource_mismatch)?,
            target.to_owned(),
            mount.read_only.unwrap_or(false),
            no_copy,
        )) {
            return Err(engine_resource_mismatch());
        }
    }
    if realized_host != expected_mounts {
        return Err(engine_resource_mismatch());
    }
    let expected_realized = expected_mounts
        .iter()
        .map(|(kind, source, target, read_only, _)| {
            (kind.clone(), source.clone(), target.clone(), !*read_only)
        })
        .collect::<BTreeSet<_>>();
    let mut realized = BTreeSet::new();
    for mount in container.mounts.as_deref().unwrap_or_default() {
        let source = if mount.typ.as_deref() == Some("volume") {
            mount.name.clone()
        } else {
            mount.source.clone()
        }
        .ok_or_else(engine_resource_mismatch)?;
        if !realized.insert((
            mount.typ.clone().ok_or_else(engine_resource_mismatch)?,
            source,
            mount
                .destination
                .clone()
                .ok_or_else(engine_resource_mismatch)?,
            mount.rw.ok_or_else(engine_resource_mismatch)?,
        )) {
            return Err(engine_resource_mismatch());
        }
    }
    if realized != expected_realized {
        return Err(engine_resource_mismatch());
    }
    Ok(())
}

pub(super) fn validate_rendered_ports(
    config: &bollard::models::ContainerConfig,
    host: &HostConfig,
    network: &bollard::models::NetworkSettings,
    expected: &ExpectedContainer,
    image: &ImageConfig,
    realized_running: bool,
) -> Result<(), LocalInitError> {
    let expected_ports = expected
        .ports
        .iter()
        .map(|port| {
            (
                format!("{}/{}", port.target, port.protocol),
                port.host_ip.clone(),
                port.published.to_string(),
            )
        })
        .collect::<BTreeSet<_>>();
    let exposed = config
        .exposed_ports
        .as_deref()
        .unwrap_or_default()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected_exposed = image
        .exposed_ports
        .as_deref()
        .unwrap_or_default()
        .iter()
        .cloned()
        .chain(expected_ports.iter().map(|(port, _, _)| port.clone()))
        .collect::<BTreeSet<_>>();
    if exposed != expected_exposed {
        return Err(engine_resource_mismatch());
    }
    let mut bindings = BTreeSet::new();
    for (port, values) in host.port_bindings.as_ref().into_iter().flatten() {
        for value in values.as_deref().unwrap_or_default() {
            if !bindings.insert((
                port.clone(),
                value.host_ip.clone().unwrap_or_default(),
                value.host_port.clone().unwrap_or_default(),
            )) {
                return Err(engine_resource_mismatch());
            }
        }
    }
    if bindings != expected_ports {
        return Err(engine_resource_mismatch());
    }
    let mut realized = BTreeSet::new();
    let realized_keys = network
        .ports
        .as_ref()
        .into_iter()
        .flatten()
        .map(|(port, _)| port.clone())
        .collect::<BTreeSet<_>>();
    if if realized_running {
        realized_keys != expected_exposed
    } else {
        !realized_keys.is_empty()
    } {
        return Err(engine_resource_mismatch());
    }
    for (port, values) in network.ports.as_ref().into_iter().flatten() {
        for value in values.as_deref().unwrap_or_default() {
            realized.insert((
                port.clone(),
                value.host_ip.clone().unwrap_or_default(),
                value.host_port.clone().unwrap_or_default(),
            ));
        }
    }
    if realized != expected_ports {
        return Err(engine_resource_mismatch());
    }
    Ok(())
}

pub(super) fn validate_rendered_health(
    config: &bollard::models::ContainerConfig,
    expected: &ExpectedContainer,
) -> Result<(), LocalInitError> {
    match (&config.healthcheck, &expected.healthcheck) {
        (None, None) => Ok(()),
        (Some(actual), Some(expected))
            if actual.test.as_deref() == Some(expected.test.as_slice())
                && actual.interval == Some(rendered_duration_ns(&expected.interval)?)
                && actual.timeout == Some(rendered_duration_ns(&expected.timeout)?)
                && actual.retries == Some(i64::from(expected.retries))
                && actual.start_period == Some(rendered_duration_ns(&expected.start_period)?)
                && actual.start_interval.is_none_or(|value| value == 0) =>
        {
            Ok(())
        }
        _ => Err(engine_resource_mismatch()),
    }
}

pub(super) fn rendered_duration_ns(value: &str) -> Result<i64, LocalInitError> {
    let (number, multiplier) = if let Some(value) = value.strip_suffix("ms") {
        (value, 1_000_000_i64)
    } else if let Some(value) = value.strip_suffix('s') {
        (value, 1_000_000_000_i64)
    } else {
        return Err(engine_resource_mismatch());
    };
    number
        .parse::<i64>()
        .ok()
        .and_then(|number| number.checked_mul(multiplier))
        .filter(|number| *number > 0)
        .ok_or_else(engine_resource_mismatch)
}

pub(super) fn validate_rendered_tmpfs(
    host: &HostConfig,
    expected: &ExpectedContainer,
) -> Result<(), LocalInitError> {
    let mut rendered = BTreeMap::new();
    for value in &expected.tmpfs {
        let (target, options) = value.split_once(':').ok_or_else(engine_resource_mismatch)?;
        if target.is_empty()
            || options.is_empty()
            || rendered
                .insert(target.to_owned(), options.to_owned())
                .is_some()
        {
            return Err(engine_resource_mismatch());
        }
    }
    let actual = host
        .tmpfs
        .as_ref()
        .into_iter()
        .flatten()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    if actual == rendered {
        Ok(())
    } else {
        Err(engine_resource_mismatch())
    }
}

pub(super) fn validate_rendered_restart(
    host: &HostConfig,
    expected: &ExpectedContainer,
) -> Result<(), LocalInitError> {
    let expected_name = match expected.restart.as_deref() {
        None | Some("no") => RestartPolicyNameEnum::NO,
        Some("unless-stopped") => RestartPolicyNameEnum::UNLESS_STOPPED,
        _ => return Err(engine_resource_mismatch()),
    };
    if host.restart_policy.as_ref().is_some_and(|policy| {
        policy.name == Some(expected_name) && policy.maximum_retry_count.unwrap_or(0) == 0
    }) {
        Ok(())
    } else {
        Err(engine_resource_mismatch())
    }
}

pub(super) fn validate_rendered_networks(
    network: &bollard::models::NetworkSettings,
    host: &HostConfig,
    id: &str,
    name: &str,
    installation: &Installation,
    expected: &ExpectedContainer,
    expected_topology: &ExpectedLifecycleTopology,
    desired: &DesiredSpec,
    live_ids: &RenderedLiveIds,
    realized_running: bool,
) -> Result<(), LocalInitError> {
    if let Some(mode) = expected.network_mode.as_deref() {
        if mode == "none" {
            if host.network_mode.as_deref() != Some("none")
                || if realized_running {
                    !exact_running_none_network(network, &live_ids.none_network)
                } else {
                    !exact_stopped_none_network(network, &live_ids.none_network)
                }
            {
                return Err(engine_resource_mismatch());
            }
            return Ok(());
        }
        if mode == "service:automata" {
            let control_name = format!("{}-automata-1", installation.compose_project());
            let expected_control = live_ids
                .control
                .as_deref()
                .ok_or_else(engine_resource_mismatch)?;
            if host
                .network_mode
                .as_deref()
                .and_then(|mode| mode.strip_prefix("container:"))
                != Some(expected_control)
                || network
                    .networks
                    .as_ref()
                    .is_some_and(|networks| !networks.is_empty())
                || name == control_name
                || !exact_container_id_text(id)
            {
                return Err(engine_resource_mismatch());
            }
            return Ok(());
        }
        return Err(engine_resource_mismatch());
    }

    let actual = network
        .networks
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    if !realized_running
        && (network.sandbox_id.as_deref() != Some("")
            || network.sandbox_key.as_deref() != Some("")
            || network.ports.as_ref().is_none_or(|ports| !ports.is_empty()))
    {
        return Err(engine_resource_mismatch());
    }
    if actual.len() != expected.networks.len() {
        return Err(engine_resource_mismatch());
    }
    let expected_primary = expected
        .networks
        .keys()
        .next()
        .map(|logical| rendered_network_name(logical, installation))
        .transpose()?
        .ok_or_else(engine_resource_mismatch)?;
    if host.network_mode.as_deref() != Some(expected_primary.as_str()) {
        return Err(engine_resource_mismatch());
    }
    for (logical, expected_endpoint) in &expected.networks {
        let physical = rendered_network_name(logical, installation)?;
        let endpoint = actual.get(&physical).ok_or_else(engine_resource_mismatch)?;
        let (expected_gateway, expected_subnet) = if logical == "results-transit" {
            (
                desired.results_transit().gateway().to_string(),
                desired.results_transit().subnet(),
            )
        } else {
            let network = expected_topology
                .networks
                .get(logical)
                .ok_or_else(engine_resource_mismatch)?;
            (network.gateway.clone(), network.subnet.clone())
        };
        let expected_prefix = expected_subnet
            .rsplit_once('/')
            .and_then(|(_, prefix)| prefix.parse::<i64>().ok())
            .filter(|prefix| (1..=32).contains(prefix))
            .ok_or_else(engine_resource_mismatch)?;
        let ipam = endpoint
            .ipam_config
            .as_ref()
            .ok_or_else(engine_resource_mismatch)?;
        let aliases = endpoint
            .aliases
            .as_deref()
            .unwrap_or_default()
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut required_aliases = expected_endpoint
            .aliases
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        required_aliases.insert(name.to_owned());
        required_aliases.insert(expected.service.clone());
        let mut aliases_with_id = required_aliases.clone();
        aliases_with_id.insert(id[..12].to_owned());
        let dns_names = endpoint
            .dns_names
            .as_deref()
            .unwrap_or_default()
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let expected_network_id = live_ids
            .networks
            .get(&physical)
            .ok_or_else(engine_resource_mismatch)?;
        let configured_mismatch = ipam.ipv4_address.as_deref()
            != Some(expected_endpoint.ipv4_address.as_str())
            || ipam
                .ipv6_address
                .as_deref()
                .is_some_and(|address| !address.is_empty())
            || ipam
                .link_local_ips
                .as_ref()
                .is_some_and(|addresses| !addresses.is_empty())
            || endpoint
                .links
                .as_ref()
                .is_some_and(|links| !links.is_empty())
            || endpoint
                .driver_opts
                .as_ref()
                .is_some_and(|options| !options.is_empty())
            || endpoint
                .ipv6_gateway
                .as_deref()
                .is_some_and(|gateway| !gateway.is_empty())
            || endpoint
                .global_ipv6_address
                .as_deref()
                .is_some_and(|address| !address.is_empty())
            || endpoint.global_ipv6_prefix_len.unwrap_or(0) != 0
            || endpoint.gw_priority.unwrap_or(0) != expected_endpoint.gateway_priority
            || aliases != required_aliases && aliases != aliases_with_id
            || dns_names != aliases_with_id
            || endpoint.network_id.as_deref() != Some(expected_network_id.as_str());
        let operational_mismatch = if realized_running {
            endpoint.ip_address.as_deref() != Some(expected_endpoint.ipv4_address.as_str())
                || endpoint.gateway.as_deref() != Some(expected_gateway.as_str())
                || endpoint.ip_prefix_len != Some(expected_prefix)
                || endpoint
                    .mac_address
                    .as_deref()
                    .is_none_or(|address| !canonical_unicast_mac(address))
                || endpoint
                    .endpoint_id
                    .as_deref()
                    .is_none_or(|endpoint_id| !exact_container_id_text(endpoint_id))
        } else {
            endpoint
                .endpoint_id
                .as_deref()
                .is_some_and(|endpoint_id| !endpoint_id.is_empty())
                || endpoint
                    .gateway
                    .as_deref()
                    .is_some_and(|gateway| !gateway.is_empty())
                || endpoint
                    .ip_address
                    .as_deref()
                    .is_some_and(|address| !address.is_empty())
                || endpoint.ip_prefix_len.unwrap_or(0) != 0
                || endpoint
                    .mac_address
                    .as_deref()
                    .is_some_and(|address| !address.is_empty())
        };
        if configured_mismatch || operational_mismatch {
            return Err(engine_resource_mismatch());
        }
    }
    Ok(())
}

pub(super) fn exact_running_none_network(
    network: &bollard::models::NetworkSettings,
    none_network_id: &str,
) -> bool {
    let Some(sandbox_id) = network
        .sandbox_id
        .as_deref()
        .filter(|id| exact_container_id_text(id))
    else {
        return false;
    };
    if network.sandbox_key.as_deref()
        != Some(format!("/var/run/docker/netns/{}", &sandbox_id[..12]).as_str())
        || network.ports.as_ref().is_none_or(|ports| {
            ports.values().any(|bindings| {
                bindings
                    .as_ref()
                    .is_some_and(|bindings| !bindings.is_empty())
            })
        })
    {
        return false;
    }
    let Some(networks) = network
        .networks
        .as_ref()
        .filter(|networks| networks.len() == 1)
    else {
        return false;
    };
    let Some(endpoint) = networks.get("none") else {
        return false;
    };
    endpoint.ipam_config.is_none()
        && endpoint.links.as_ref().is_none_or(Vec::is_empty)
        && endpoint.aliases.as_ref().is_none_or(Vec::is_empty)
        && endpoint.driver_opts.as_ref().is_none_or(HashMap::is_empty)
        && endpoint.dns_names.as_ref().is_none_or(Vec::is_empty)
        && endpoint.gw_priority.unwrap_or(0) == 0
        && endpoint.network_id.as_deref() == Some(none_network_id)
        && endpoint
            .endpoint_id
            .as_deref()
            .is_some_and(exact_container_id_text)
        && endpoint.gateway.as_deref() == Some("")
        && endpoint.ip_address.as_deref() == Some("")
        && endpoint.mac_address.as_deref() == Some("")
        && endpoint.ip_prefix_len == Some(0)
        && endpoint.ipv6_gateway.as_deref() == Some("")
        && endpoint.global_ipv6_address.as_deref() == Some("")
        && endpoint.global_ipv6_prefix_len == Some(0)
}

pub(super) fn exact_stopped_none_network(
    network: &bollard::models::NetworkSettings,
    none_network_id: &str,
) -> bool {
    if network.sandbox_id.as_deref() != Some("")
        || network.sandbox_key.as_deref() != Some("")
        || network.ports.as_ref().is_none_or(|ports| !ports.is_empty())
    {
        return false;
    }
    let Some(networks) = network
        .networks
        .as_ref()
        .filter(|networks| networks.len() == 1)
    else {
        return false;
    };
    let Some(endpoint) = networks.get("none") else {
        return false;
    };
    endpoint.ipam_config.is_none()
        && endpoint.links.as_ref().is_none_or(Vec::is_empty)
        && endpoint.aliases.as_ref().is_none_or(Vec::is_empty)
        && endpoint.driver_opts.as_ref().is_none_or(HashMap::is_empty)
        && endpoint.dns_names.as_ref().is_none_or(Vec::is_empty)
        && endpoint.gw_priority.unwrap_or(0) == 0
        && endpoint.network_id.as_deref() == Some(none_network_id)
        && endpoint.endpoint_id.as_deref().is_none_or(str::is_empty)
        && endpoint.gateway.as_deref().is_none_or(str::is_empty)
        && endpoint.ip_address.as_deref().is_none_or(str::is_empty)
        && endpoint.mac_address.as_deref().is_none_or(str::is_empty)
        && endpoint.ip_prefix_len.unwrap_or(0) == 0
        && endpoint.ipv6_gateway.as_deref().is_none_or(str::is_empty)
        && endpoint
            .global_ipv6_address
            .as_deref()
            .is_none_or(str::is_empty)
        && endpoint.global_ipv6_prefix_len.unwrap_or(0) == 0
}

pub(super) fn canonical_unicast_mac(value: &str) -> bool {
    let octets = value
        .split(':')
        .map(|octet| {
            (octet.len() == 2 && octet.bytes().all(|byte| byte.is_ascii_hexdigit()))
                .then(|| u8::from_str_radix(octet, 16).ok())
                .flatten()
        })
        .collect::<Option<Vec<_>>>();
    octets.is_some_and(|octets| {
        octets.len() == 6
            && octets.iter().any(|octet| *octet != 0)
            && octets[0] & 1 == 0
            && value == value.to_ascii_lowercase()
    })
}

pub(super) fn rendered_network_name(
    logical: &str,
    installation: &Installation,
) -> Result<String, LocalInitError> {
    match logical {
        "control" => Ok(format!("{}-control", installation.compose_project())),
        "egress" => Ok(format!("{}-egress", installation.compose_project())),
        "results-transit" => Ok(results_transit_name(installation)),
        _ => Err(engine_resource_mismatch()),
    }
}

#[derive(Clone, Copy)]
pub(super) struct LifecycleOneoffContract {
    pub(super) image_role: &'static str,
}

pub(super) fn lifecycle_oneoff_contract(
    service: &'static str,
) -> Result<LifecycleOneoffContract, LocalInitError> {
    let contract = match service {
        "object-store-init" | "bootstrap-runner" => LifecycleOneoffContract {
            image_role: "automata",
        },
        "runner-enroll" => LifecycleOneoffContract {
            image_role: "runner",
        },
        _ => return Err(engine_resource_mismatch()),
    };
    Ok(contract)
}

pub(super) fn lifecycle_oneoff_name(
    installation: &Installation,
    service: &'static str,
) -> Result<String, LocalInitError> {
    lifecycle_oneoff_contract(service)?;
    Ok(format!("{}-{service}", installation.compose_project()))
}

pub(super) fn validate_egress_network(
    network: &NetworkInspect,
    installation: &Installation,
    desired: &DesiredSpec,
) -> Result<(), LocalInitError> {
    let expected_name = format!("{}-egress", installation.compose_project());
    let subnet = crate::desired_spec::egress_subnet_for_spec(desired);
    let ipam = network.ipam.as_ref().ok_or_else(engine_resource_mismatch)?;
    let labels = network
        .labels
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let managed = labels
        .iter()
        .filter(|(key, _)| key.starts_with("io.automata.local."))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let expected_labels = BTreeMap::from([
        (LABEL_MANAGED.to_owned(), "true".to_owned()),
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
        (LABEL_PLAN.to_owned(), desired.plan_digest().to_string()),
        (LABEL_RESOURCE_KIND.to_owned(), "egress-network".to_owned()),
    ]);
    let expected_options = HashMap::from([
        (
            "com.docker.network.bridge.enable_ip_masquerade".to_owned(),
            "true".to_owned(),
        ),
        (
            "com.docker.network.bridge.gateway_mode_ipv4".to_owned(),
            "nat".to_owned(),
        ),
    ]);
    let expected_container_name = format!("{}-runner-1", installation.compose_project());
    let actual_container_names = network
        .containers
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?
        .values()
        .map(|endpoint| endpoint.name.clone().ok_or_else(engine_resource_mismatch))
        .collect::<Result<BTreeSet<_>, LocalInitError>>()?;
    if network.name.as_deref() != Some(&expected_name)
        || network
            .id
            .as_deref()
            .is_none_or(|id| !exact_container_id_text(id))
        || network.scope.as_deref() != Some("local")
        || network.driver.as_deref() != Some("bridge")
        || network.internal != Some(false)
        || network.attachable != Some(false)
        || network.enable_ipv6 != Some(false)
        || network.options.as_ref() != Some(&expected_options)
        || ipam.driver.as_deref() != Some("default")
        || ipam.config.as_deref()
            != Some(
                [IpamConfig {
                    subnet: Some(subnet.to_string()),
                    gateway: Some(subnet.address(1).to_string()),
                    ip_range: None,
                    auxiliary_addresses: None,
                }]
                .as_slice(),
            )
        || managed != expected_labels
        || actual_container_names != BTreeSet::from([expected_container_name])
    {
        return Err(engine_resource_mismatch());
    }
    Ok(())
}

pub(super) fn validate_control_network(
    network: &NetworkInspect,
    installation: &Installation,
    desired: &DesiredSpec,
) -> Result<(), LocalInitError> {
    let expected_name = format!("{}-control", installation.compose_project());
    let subnet = crate::desired_spec::control_subnet_for_spec(desired);
    let ipam = network.ipam.as_ref().ok_or_else(engine_resource_mismatch)?;
    let labels = network
        .labels
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let managed = labels
        .iter()
        .filter(|(key, _)| key.starts_with("io.automata.local."))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let expected_labels = BTreeMap::from([
        (LABEL_MANAGED.to_owned(), "true".to_owned()),
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
        (LABEL_PLAN.to_owned(), desired.plan_digest().to_string()),
        (LABEL_RESOURCE_KIND.to_owned(), "control-network".to_owned()),
    ]);
    let expected_container_names = ["automata", "postgres", "runner", "rustfs"]
        .into_iter()
        .map(|service| format!("{}-{service}-1", installation.compose_project()))
        .collect::<BTreeSet<_>>();
    let actual_container_names = network
        .containers
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?
        .values()
        .map(|endpoint| endpoint.name.clone().ok_or_else(engine_resource_mismatch))
        .collect::<Result<BTreeSet<_>, LocalInitError>>()?;
    if network.name.as_deref() != Some(&expected_name)
        || network
            .id
            .as_deref()
            .is_none_or(|id| !exact_container_id_text(id))
        || network.scope.as_deref() != Some("local")
        || network.driver.as_deref() != Some("bridge")
        || network.internal != Some(true)
        || network.attachable != Some(false)
        || network.enable_ipv6 != Some(false)
        || ipam.driver.as_deref() != Some("default")
        || ipam.config.as_deref()
            != Some(
                [IpamConfig {
                    subnet: Some(subnet.to_string()),
                    gateway: Some(subnet.address(1).to_string()),
                    ip_range: None,
                    auxiliary_addresses: None,
                }]
                .as_slice(),
            )
        || managed != expected_labels
        || actual_container_names != expected_container_names
    {
        return Err(engine_resource_mismatch());
    }
    Ok(())
}
pub(super) fn validate_results_transit(
    network: &NetworkInspect,
    installation: &Installation,
    desired: &DesiredSpec,
    require_empty: bool,
) -> Result<(), LocalInitError> {
    let ipam = network.ipam.as_ref().ok_or_else(engine_resource_mismatch)?;
    let config = ipam
        .config
        .as_deref()
        .ok_or_else(engine_resource_mismatch)?;
    let labels = network
        .labels
        .clone()
        .unwrap_or_default()
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let endpoint_ids = network
        .containers
        .as_ref()
        .map(|containers| containers.keys().cloned().collect())
        .unwrap_or_default();
    let shape = ResultsTransitNetworkShape {
        name: network.name.clone().unwrap_or_default(),
        driver: network.driver.clone().unwrap_or_default(),
        scope: network.scope.clone().unwrap_or_default(),
        enable_ipv4: network.enable_ipv4 == Some(true),
        enable_ipv6: network.enable_ipv6 == Some(true),
        internal: network.internal == Some(true),
        attachable: network.attachable == Some(true),
        ingress: network.ingress == Some(true),
        config_only: network.config_only == Some(true),
        config_from_empty: network
            .config_from
            .as_ref()
            .is_none_or(|reference| reference.network.as_deref().is_none_or(str::is_empty)),
        ipam_driver: ipam.driver.clone().unwrap_or_default(),
        ipam_options: ipam
            .options
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect(),
        options: network
            .options
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect(),
        labels,
        endpoint_ids,
    };
    if !exact_results_transit_base(&shape, installation, desired.plan_digest())
        || network
            .id
            .as_deref()
            .is_none_or(|id| !exact_container_id_text(id))
        || config
            != [IpamConfig {
                subnet: Some(desired.results_transit().subnet()),
                gateway: Some(desired.results_transit().gateway().to_string()),
                ip_range: None,
                auxiliary_addresses: None,
            }]
        || require_empty && !shape.endpoint_ids.is_empty()
    {
        return Err(engine_resource_mismatch());
    }
    Ok(())
}
