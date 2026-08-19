//! Lifecycle topology inspection, reconciliation, reset, and service attestation.

use super::{
    common::{
        BTreeMap, BTreeSet, CAS_DIGEST_READER_KIND, CAS_WRITER_KIND, CancellationToken,
        ContainerSummary, DESIRED_READER_KIND, DesiredSpec, ENGINE_TIMEOUT,
        ExpectedLifecycleTopology, HELPER_TIMEOUT, HashMap, ImmutableEpoch, InitEngine,
        Installation, Ipam, IpamConfig, LABEL_COMPOSE_PROJECT, LABEL_INSTALLATION_ID,
        LABEL_INSTALLATION_KEY, LABEL_RESOURCE_KIND, LIFECYCLE_ATTESTER_KIND,
        ListContainersOptionsBuilder, ListNetworksOptionsBuilder, ListVolumesOptionsBuilder,
        LocalInitError, LocalInitErrorCode, LogOutput, LogsOptionsBuilder, MAX_ENGINE_RESOURCES,
        MAX_ONEOFF_LOG_BYTES, NetworkCreateRequest, NetworkInspect,
        RESULTS_TRANSIT_GATEWAY_MODE_KEY, RESULTS_TRANSIT_GATEWAY_MODE_VALUE,
        RemoveContainerOptionsBuilder, SealedEngineStatus, SealedVolumeStatus, StreamExt,
        VolumeRole, WaitContainerOptionsBuilder, attest_lifecycle_sibling_custody_union,
        attest_lifecycle_sibling_union, engine_resource_mismatch, engine_unavailable,
        exact_container_id, exact_container_id_text, expected_volume_labels,
        lifecycle_material_attester_name, not_found, results_transit_labels, results_transit_name,
        validate_volume, volume_names,
    },
    lock::{
        LifecycleLockHolder, LifecycleMutationFence, classify_lifecycle_lock, lifecycle_lock_image,
    },
    validation::{
        LifecycleIdentityCensus, PinnedLifecycleHelper, PinnedLocalDockerContainer,
        PinnedLocalDockerNetwork, RenderedLiveIds, derive_rendered_live_ids,
        lifecycle_cancellation_checkpoint, lifecycle_container_candidate,
        lifecycle_network_candidate, lifecycle_oneoff_contract, lifecycle_oneoff_name,
        local_docker_candidate_container, local_docker_candidate_network,
        local_docker_container_candidates, local_docker_delete_rank, local_docker_name_prefix,
        local_docker_network_candidates, rendered_container_is_running,
        sole_local_docker_runner_id, validate_control_network, validate_egress_network,
        validate_lifecycle_disposable_helper, validate_local_docker_container_summary,
        validate_local_docker_network, validate_local_docker_network_inspect,
        validate_rendered_container, validate_rendered_network, validate_results_transit,
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::init) enum LifecycleTopology {
    Empty,
    Partial,
    Running { transit_id: String },
}

impl InitEngine<'_> {
    pub(super) async fn inspect_rendered_live_ids(
        &self,
        installation: &Installation,
        expected: &ExpectedLifecycleTopology,
    ) -> Result<RenderedLiveIds, LocalInitError> {
        let containers = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.list_containers(Some(
                ListContainersOptionsBuilder::default().all(true).build(),
            )),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        let networks = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker
                .list_networks(Some(ListNetworksOptionsBuilder::default().build())),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        if containers.len() > MAX_ENGINE_RESOURCES || networks.len() > MAX_ENGINE_RESOURCES {
            return Err(engine_resource_mismatch());
        }
        derive_rendered_live_ids(&containers, &networks, installation, expected)
    }

    pub(super) async fn attest_namespace_attachment_union(
        &self,
        listed: &[ContainerSummary],
        installation: &Installation,
        expected: &ExpectedLifecycleTopology,
        lifecycle_ids: &BTreeMap<String, String>,
        live_ids: &RenderedLiveIds,
    ) -> Result<(), LocalInitError> {
        let runner_enroll = expected
            .containers
            .get("runner-enroll")
            .filter(|container| container.network_mode.as_deref() == Some("service:automata"))
            .map(|_| format!("{}-runner-enroll", installation.compose_project()))
            .ok_or_else(engine_resource_mismatch)?;
        for summary in listed {
            let id = summary
                .id
                .as_deref()
                .filter(|id| exact_container_id_text(id))
                .ok_or_else(engine_resource_mismatch)?;
            let container = self
                .inspect_container(id)
                .await?
                .ok_or_else(engine_resource_mismatch)?;
            let source_name = container
                .name
                .as_deref()
                .and_then(|name| name.strip_prefix('/'))
                .ok_or_else(engine_resource_mismatch)?;
            let host = container
                .host_config
                .as_ref()
                .ok_or_else(engine_resource_mismatch)?;
            for (namespace, mode) in [
                ("network", host.network_mode.as_deref()),
                ("pid", host.pid_mode.as_deref()),
                ("ipc", host.ipc_mode.as_deref()),
            ] {
                let Some(target) = mode.and_then(|mode| mode.strip_prefix("container:")) else {
                    continue;
                };
                let targets_lifecycle = lifecycle_ids
                    .iter()
                    .any(|(name, id)| target == name || target == id);
                if !targets_lifecycle {
                    continue;
                }
                let allowed = namespace == "network"
                    && source_name == runner_enroll
                    && live_ids.control.as_deref() == Some(target);
                if !allowed {
                    return Err(engine_resource_mismatch());
                }
            }
        }
        Ok(())
    }

    /// Non-repairing metadata preflight for the complete sealed volume set.
    ///
    /// Lifecycle attachments are permitted, but every attachment must already
    /// be an exact immutable Engine ID. The full topology census validates the
    /// attached containers before any subsequent mutation.
    pub(in crate::init) async fn preflight_lifecycle_volumes(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
    ) -> Result<SealedEngineStatus, LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let images = self.inspect_epoch_images(epoch).await?;
        if images.len() != epoch.image_expectations().count() {
            return Err(engine_resource_mismatch());
        }
        let names = volume_names(installation);
        let labels = expected_volume_labels(installation, epoch.fingerprint());
        let expected_names = names
            .values()
            .cloned()
            .chain(std::iter::once(
                installation.anchor_volume_name().to_owned(),
            ))
            .collect::<BTreeSet<_>>();
        let first_union = self
            .inspect_lifecycle_volume_union(installation, &expected_names)
            .await?;
        if first_union != expected_names {
            return Err(engine_resource_mismatch());
        }
        let mut first = BTreeMap::new();
        let mut volumes = Vec::with_capacity(VolumeRole::ALL.len());
        for role in VolumeRole::ALL {
            let name = names.get(&role).ok_or_else(engine_resource_mismatch)?;
            let volume = self
                .inspect_volume(name)
                .await?
                .ok_or_else(engine_resource_mismatch)?;
            validate_volume(
                &volume,
                name,
                labels.get(&role).ok_or_else(engine_resource_mismatch)?,
            )?;
            let attachments = self.volume_attachments(name).await?;
            if attachments
                .iter()
                .any(|attachment| !exact_container_id_text(attachment))
            {
                return Err(engine_resource_mismatch());
            }
            first.insert(role, attachments);
            volumes.push(SealedVolumeStatus {
                role,
                name: name.clone(),
                static_material: role.is_static(),
            });
        }
        let mut repeated = BTreeMap::new();
        for role in VolumeRole::ALL {
            let name = names.get(&role).ok_or_else(engine_resource_mismatch)?;
            repeated.insert(role, self.volume_attachments(name).await?);
        }
        let repeated_union = self
            .inspect_lifecycle_volume_union(installation, &expected_names)
            .await?;
        if first != repeated || repeated_union != first_union {
            return Err(engine_resource_mismatch());
        }
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await?;
        Ok(SealedEngineStatus { images, volumes })
    }

    pub(super) async fn inspect_lifecycle_volume_union(
        &self,
        installation: &Installation,
        expected_names: &BTreeSet<String>,
    ) -> Result<BTreeSet<String>, LocalInitError> {
        let listed = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker
                .list_volumes(Some(ListVolumesOptionsBuilder::default().build())),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        if listed
            .warnings
            .as_ref()
            .is_some_and(|warnings| !warnings.is_empty())
            || listed
                .volumes
                .as_ref()
                .is_some_and(|volumes| volumes.len() > MAX_ENGINE_RESOURCES)
        {
            return Err(engine_resource_mismatch());
        }
        let installation_id = installation.id().to_string();
        let installation_key = installation.selector_key().to_string();
        let project = installation.compose_project().as_str();
        let prefix = format!("{project}-");
        let mut observed = BTreeSet::new();
        for volume in listed.volumes.unwrap_or_default() {
            let related = volume.name.starts_with(&prefix)
                || volume
                    .labels
                    .get(LABEL_INSTALLATION_ID)
                    .is_some_and(|value| value == &installation_id)
                || volume
                    .labels
                    .get(LABEL_INSTALLATION_KEY)
                    .is_some_and(|value| value == &installation_key)
                || volume
                    .labels
                    .get(LABEL_COMPOSE_PROJECT)
                    .is_some_and(|value| value == project)
                || volume
                    .labels
                    .get("com.docker.compose.project")
                    .is_some_and(|value| value == project);
            if !related {
                continue;
            }
            if !expected_names.contains(&volume.name) || !observed.insert(volume.name) {
                return Err(engine_resource_mismatch());
            }
        }
        Ok(observed)
    }

    pub(super) async fn attest_reset_quiescent_union(
        &self,
        installation: &Installation,
        holder: &LifecycleLockHolder,
        expected_volumes: &BTreeSet<String>,
    ) -> Result<(), LocalInitError> {
        self.attest_reset_quiescent_lock(installation, &holder.name, &holder.id, expected_volumes)
            .await
    }

    pub(super) async fn attest_reset_quiescent_lock(
        &self,
        installation: &Installation,
        lock_name: &str,
        lock_id: &str,
        expected_volumes: &BTreeSet<String>,
    ) -> Result<(), LocalInitError> {
        let first = self
            .reset_quiescent_census(installation, lock_name, lock_id, expected_volumes)
            .await?;
        let repeated = self
            .reset_quiescent_census(installation, lock_name, lock_id, expected_volumes)
            .await?;
        if first != repeated {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await
    }

    pub(super) async fn reset_quiescent_census(
        &self,
        installation: &Installation,
        lock_name: &str,
        lock_id: &str,
        expected_volumes: &BTreeSet<String>,
    ) -> Result<(BTreeSet<String>, BTreeSet<String>, BTreeSet<String>), LocalInitError> {
        let volumes = self
            .inspect_lifecycle_volume_union(installation, expected_volumes)
            .await?;
        if &volumes != expected_volumes {
            return Err(engine_resource_mismatch());
        }
        let installation_id = installation.id().to_string();
        let installation_key = installation.selector_key().to_string();
        let project = installation.compose_project().as_str();
        let project_prefix = format!("{project}-");
        let local_prefix = local_docker_name_prefix(installation);
        let related_labels = |labels: &HashMap<String, String>| {
            labels
                .get(LABEL_INSTALLATION_ID)
                .is_some_and(|value| value == &installation_id)
                || labels
                    .get(LABEL_INSTALLATION_KEY)
                    .is_some_and(|value| value == &installation_key)
                || labels
                    .get(LABEL_COMPOSE_PROJECT)
                    .is_some_and(|value| value == project)
                || labels
                    .get("com.docker.compose.project")
                    .is_some_and(|value| value == project)
        };
        let listed = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.list_containers(Some(
                ListContainersOptionsBuilder::default().all(true).build(),
            )),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        if listed.len() > MAX_ENGINE_RESOURCES {
            return Err(engine_resource_mismatch());
        }
        let mut containers = BTreeSet::new();
        for summary in listed {
            let labels = summary.labels.clone().unwrap_or_default();
            let names = summary.names.as_deref().unwrap_or_default();
            let related = names.iter().any(|name| {
                let name = name.trim_start_matches('/');
                name.starts_with(&project_prefix) || name.starts_with(&local_prefix)
            }) || related_labels(&labels);
            if !related {
                continue;
            }
            let id = summary
                .id
                .as_deref()
                .filter(|id| exact_container_id_text(id))
                .ok_or_else(engine_resource_mismatch)?;
            if id != lock_id
                || names != [format!("/{lock_name}")]
                || !containers.insert(id.to_owned())
            {
                return Err(engine_resource_mismatch());
            }
        }
        if containers != BTreeSet::from([lock_id.to_owned()]) {
            return Err(engine_resource_mismatch());
        }

        let listed_networks = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker
                .list_networks(Some(ListNetworksOptionsBuilder::default().build())),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        if listed_networks.len() > MAX_ENGINE_RESOURCES {
            return Err(engine_resource_mismatch());
        }
        let mut networks = BTreeSet::new();
        for network in listed_networks {
            let labels = network.labels.clone().unwrap_or_default();
            let name = network.name.as_deref().unwrap_or_default();
            if name.starts_with(&project_prefix)
                || name.starts_with(&local_prefix)
                || related_labels(&labels)
            {
                let id = network
                    .id
                    .as_deref()
                    .filter(|id| exact_container_id_text(id))
                    .ok_or_else(engine_resource_mismatch)?;
                networks.insert(id.to_owned());
            }
        }
        if !networks.is_empty() {
            return Err(engine_resource_mismatch());
        }
        Ok((volumes, containers, networks))
    }
    /// Creates or adopts the lifecycle-owned schema-2 Results transit.
    pub(in crate::init) async fn ensure_results_transit(
        &self,
        installation: &Installation,
        desired: &DesiredSpec,
        mutation: &LifecycleMutationFence,
    ) -> Result<String, LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let name = results_transit_name(installation);
        if self.inspect_network_exact(&name).await?.is_none() {
            let request = NetworkCreateRequest {
                name: name.clone(),
                driver: Some("bridge".to_owned()),
                scope: Some("local".to_owned()),
                internal: Some(true),
                attachable: Some(false),
                ingress: Some(false),
                config_only: Some(false),
                config_from: None,
                ipam: Some(Ipam {
                    driver: Some("default".to_owned()),
                    config: Some(vec![IpamConfig {
                        subnet: Some(desired.results_transit().subnet()),
                        gateway: Some(desired.results_transit().gateway().to_string()),
                        ip_range: None,
                        auxiliary_addresses: None,
                    }]),
                    options: Some(HashMap::new()),
                }),
                enable_ipv4: Some(true),
                enable_ipv6: Some(false),
                options: Some(HashMap::from([(
                    RESULTS_TRANSIT_GATEWAY_MODE_KEY.to_owned(),
                    RESULTS_TRANSIT_GATEWAY_MODE_VALUE.to_owned(),
                )])),
                labels: Some(
                    results_transit_labels(installation, desired.plan_digest())
                        .into_iter()
                        .collect(),
                ),
            };
            let _untrusted = mutation
                .run(tokio::time::timeout(
                    ENGINE_TIMEOUT,
                    self.docker.create_network(request),
                ))
                .await?;
        }
        let network = self
            .inspect_network_exact(&name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        validate_results_transit(&network, installation, desired, true)?;
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await?;
        network
            .id
            .filter(|id| exact_container_id_text(id))
            .ok_or_else(engine_resource_mismatch)
    }

    /// Classifies only the closed lifecycle-owned service/network namespace.
    /// Any complete candidate is fully attested before `Running` is returned;
    /// callers decide whether a partial state is replayable for the durable
    /// phase they hold.
    pub(in crate::init) async fn inspect_lifecycle_topology(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        desired: &DesiredSpec,
        expected: &ExpectedLifecycleTopology,
        expected_runner_id: uuid::Uuid,
    ) -> Result<LifecycleTopology, LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        if expected.containers.len() != 8 || expected.networks.len() != 2 {
            return Err(engine_resource_mismatch());
        }
        let images = self
            .inspect_epoch_images(epoch)
            .await?
            .into_iter()
            .map(|image| (image.role.clone(), image))
            .collect::<BTreeMap<_, _>>();
        let lock_image = lifecycle_lock_image(self, epoch).await?;
        let volume_names = volume_names(installation);
        let mut attachment_ids = BTreeSet::new();
        for role in VolumeRole::ALL {
            let volume_name = volume_names
                .get(&role)
                .ok_or_else(engine_resource_mismatch)?;
            attachment_ids.extend(self.volume_attachments(volume_name).await?);
        }
        let expected_names = expected
            .containers
            .iter()
            .map(|(service, container)| {
                let name = if container.oneoff() {
                    format!("{}-{service}", installation.compose_project())
                } else {
                    format!("{}-{service}-1", installation.compose_project())
                };
                (name, service.as_str())
            })
            .collect::<BTreeMap<_, _>>();
        let local_prefix = local_docker_name_prefix(installation);
        let transit_name = results_transit_name(installation);
        let listed_networks = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker
                .list_networks(Some(ListNetworksOptionsBuilder::default().build())),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        if listed_networks.len() > MAX_ENGINE_RESOURCES {
            return Err(engine_resource_mismatch());
        }
        // Network attachments are a first-class discovery axis. Feeding every
        // endpoint ID from every related candidate network into the container
        // census prevents an unlabeled foreign endpoint from hiding behind an
        // otherwise exact managed network.
        for listed_network in &listed_networks {
            if !lifecycle_network_candidate(
                listed_network,
                installation,
                expected,
                &transit_name,
                &local_prefix,
            ) {
                continue;
            }
            let name = listed_network
                .name
                .as_deref()
                .ok_or_else(engine_resource_mismatch)?;
            let network = self
                .inspect_network_exact(name)
                .await?
                .ok_or_else(engine_resource_mismatch)?;
            for id in network
                .containers
                .as_ref()
                .map(HashMap::keys)
                .into_iter()
                .flatten()
            {
                if !exact_container_id_text(id) {
                    return Err(engine_resource_mismatch());
                }
                attachment_ids.insert(id.clone());
            }
        }
        let listed = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.list_containers(Some(
                ListContainersOptionsBuilder::default().all(true).build(),
            )),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        if listed.len() > MAX_ENGINE_RESOURCES {
            return Err(engine_resource_mismatch());
        }
        let live_ids = derive_rendered_live_ids(&listed, &listed_networks, installation, expected)?;
        let mut present_services = BTreeSet::new();
        let mut all_services_running = true;
        let mut present_oneoffs = BTreeSet::new();
        let mut local_children = 0_usize;
        let mut disposable_helpers = 0_usize;
        let mut discovered_ids = BTreeSet::new();
        let mut present_container_ids = BTreeMap::new();
        let mut namespace_targets = BTreeMap::new();
        for summary in &listed {
            if !lifecycle_container_candidate(
                summary,
                installation,
                &expected_names,
                &attachment_ids,
                &local_prefix,
            ) {
                continue;
            }
            let id = summary
                .id
                .as_deref()
                .filter(|id| exact_container_id_text(id))
                .ok_or_else(engine_resource_mismatch)?
                .to_owned();
            if !discovered_ids.insert(id.clone()) {
                return Err(engine_resource_mismatch());
            }
            let container = self
                .inspect_container(&id)
                .await?
                .ok_or_else(engine_resource_mismatch)?;
            let name = container
                .name
                .as_deref()
                .and_then(|name| name.strip_prefix('/'))
                .ok_or_else(engine_resource_mismatch)?;
            if namespace_targets
                .insert(name.to_owned(), id.clone())
                .is_some()
            {
                return Err(engine_resource_mismatch());
            }
            let labels = container
                .config
                .as_ref()
                .and_then(|config| config.labels.as_ref())
                .ok_or_else(engine_resource_mismatch)?;
            let kind = labels.get(LABEL_RESOURCE_KIND).map(String::as_str);
            if name == super::lifecycle_lock_name(installation) {
                classify_lifecycle_lock(
                    &container,
                    name,
                    &lock_image.inspection_reference,
                    &lock_image.image_id,
                    &lock_image.labels,
                    installation,
                )?;
                continue;
            }
            if validate_lifecycle_disposable_helper(
                &container,
                name,
                installation,
                epoch,
                images
                    .get("automata")
                    .ok_or_else(engine_resource_mismatch)?,
                &volume_names,
            )?
            .is_some()
            {
                disposable_helpers += 1;
                continue;
            }
            if name.starts_with(&local_prefix)
                || labels.contains_key("io.automata.local.job-schema")
            {
                validate_local_docker_container_summary(summary, installation)?;
                local_children += 1;
                continue;
            }
            let service = expected_names
                .get(name)
                .copied()
                .ok_or_else(engine_resource_mismatch)?;
            let rendered = expected
                .containers
                .get(service)
                .ok_or_else(engine_resource_mismatch)?;
            let image = images
                .get(rendered.image_role)
                .ok_or_else(engine_resource_mismatch)?;
            let image_config = self
                .inspect_image(&image.image_id)
                .await?
                .and_then(|image| image.config)
                .ok_or_else(engine_resource_mismatch)?;
            if kind != rendered.labels.get(LABEL_RESOURCE_KIND).map(String::as_str) {
                return Err(engine_resource_mismatch());
            }
            validate_rendered_container(
                &container,
                name,
                &image.image_id,
                installation,
                rendered,
                expected,
                desired,
                &image_config,
                &live_ids,
                false,
            )?;
            if present_container_ids
                .insert(name.to_owned(), id.clone())
                .is_some()
            {
                return Err(engine_resource_mismatch());
            }
            if rendered.oneoff() {
                if !present_oneoffs.insert(service.to_owned()) {
                    return Err(engine_resource_mismatch());
                }
            } else {
                all_services_running &= rendered_container_is_running(&container, rendered);
                if !present_services.insert(service.to_owned()) {
                    return Err(engine_resource_mismatch());
                }
            }
        }
        if !attachment_ids.is_subset(&discovered_ids) {
            return Err(engine_resource_mismatch());
        }
        self.attest_namespace_attachment_union(
            &listed,
            installation,
            expected,
            &namespace_targets,
            &live_ids,
        )
        .await?;
        // Summary/name/label validation is only a discovery filter. Bind the
        // complete LocalDocker sibling union through the production parser and
        // exact Desired/runner authority before this census can classify any
        // topology (including a stopped-lock recovery snapshot).
        self.attest_local_docker_children(installation, desired, expected_runner_id)
            .await?;

        let mut transit = None;
        let mut present_networks = BTreeSet::new();
        for listed_network in &listed_networks {
            if !lifecycle_network_candidate(
                listed_network,
                installation,
                expected,
                &transit_name,
                &local_prefix,
            ) {
                continue;
            }
            let name = listed_network
                .name
                .as_deref()
                .ok_or_else(engine_resource_mismatch)?;
            let network = self
                .inspect_network_exact(name)
                .await?
                .ok_or_else(engine_resource_mismatch)?;
            if name == transit_name {
                validate_results_transit(&network, installation, desired, false)?;
                transit = Some(network);
                continue;
            }
            if name.starts_with(&local_prefix)
                || listed_network
                    .labels
                    .as_ref()
                    .is_some_and(|labels| labels.contains_key("io.automata.local.job-schema"))
            {
                let known_names = listed
                    .iter()
                    .filter_map(|summary| summary.names.as_ref())
                    .flatten()
                    .filter_map(|name| name.strip_prefix('/'))
                    .map(str::to_owned)
                    .collect();
                let pinned =
                    validate_local_docker_network(listed_network, installation, &known_names)?;
                validate_local_docker_network_inspect(
                    &network,
                    &pinned,
                    installation,
                    &known_names,
                )?;
                continue;
            }
            let (logical, rendered) = expected
                .networks
                .iter()
                .find(|(_, rendered)| rendered.name == name)
                .ok_or_else(engine_resource_mismatch)?;
            validate_rendered_network(
                &network,
                installation,
                rendered,
                &present_container_ids,
                live_ids.networks.get(name).map(String::as_str),
            )?;
            if !present_networks.insert(logical.clone()) {
                return Err(engine_resource_mismatch());
            }
        }
        let control = present_networks.contains("control");
        let egress = present_networks.contains("egress");
        if present_services.is_empty()
            && present_oneoffs.is_empty()
            && transit.is_none()
            && !control
            && !egress
            && local_children == 0
            && disposable_helpers == 0
        {
            return Ok(LifecycleTopology::Empty);
        }
        if present_services
            == ["postgres", "rustfs", "automata", "engine-relay", "runner"]
                .into_iter()
                .map(str::to_owned)
                .collect()
            && present_oneoffs.is_empty()
            && transit.is_some()
            && control
            && egress
            && disposable_helpers == 0
        {
            if !all_services_running {
                self.verify_installation(installation).await?;
                self.verify_selected_engine().await?;
                return Ok(LifecycleTopology::Partial);
            }
            let transit_id = transit
                .and_then(|network| network.id)
                .filter(|id| exact_container_id_text(id))
                .ok_or_else(engine_resource_mismatch)?;
            self.attest_running_lifecycle(installation, epoch, desired, expected, &transit_id)
                .await?;
            return Ok(LifecycleTopology::Running { transit_id });
        }
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await?;
        Ok(LifecycleTopology::Partial)
    }

    pub(in crate::init) async fn attest_results_transit(
        &self,
        installation: &Installation,
        desired: &DesiredSpec,
        expected_id: &str,
        require_empty: bool,
    ) -> Result<NetworkInspect, LocalInitError> {
        if !exact_container_id_text(expected_id) {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await?;
        let name = results_transit_name(installation);
        let network = self
            .inspect_network_exact(&name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        validate_results_transit(&network, installation, desired, require_empty)?;
        if network.id.as_deref() != Some(expected_id) {
            return Err(engine_resource_mismatch());
        }
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await?;
        Ok(network)
    }

    /// Removes the separately managed external transit when present, after
    /// exact contract and empty-attachment validation. Absence is idempotent.
    pub(in crate::init) async fn remove_results_transit_if_present(
        &self,
        installation: &Installation,
        desired: &DesiredSpec,
        mutation: &LifecycleMutationFence,
    ) -> Result<bool, LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let name = results_transit_name(installation);
        let Some(network) = self.inspect_network_exact(&name).await? else {
            self.verify_installation(installation).await?;
            self.verify_selected_engine().await?;
            return Ok(false);
        };
        validate_results_transit(&network, installation, desired, true)?;
        let expected_id = network
            .id
            .as_deref()
            .filter(|id| exact_container_id_text(id))
            .ok_or_else(engine_resource_mismatch)?;
        let _untrusted = mutation
            .run(tokio::time::timeout(
                ENGINE_TIMEOUT,
                self.docker.remove_network(expected_id),
            ))
            .await?;
        if self.inspect_network_exact(expected_id).await?.is_some()
            || self.inspect_network_exact(&name).await?.is_some()
        {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await?;
        Ok(true)
    }

    /// Removes the fully prevalidated replaceable lifecycle topology for a
    /// confirmed reset while preserving every persistent volume.
    ///
    /// The complete discovery union is attested before the first deletion.
    /// Each subsequent deletion is pinned to the inspected immutable ID and
    /// reconciled through both ID and deterministic-name absence.
    pub(in crate::init) async fn remove_lifecycle_topology_for_reset(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        desired: &DesiredSpec,
        expected: &ExpectedLifecycleTopology,
        expected_runner_id: uuid::Uuid,
        holder: &LifecycleLockHolder,
        mutation: &LifecycleMutationFence,
    ) -> Result<(), LocalInitError> {
        self.attest_lifecycle_lock(installation, epoch, holder)
            .await?;
        self.preflight_lifecycle_volumes(installation, epoch)
            .await?;
        let holder_lost = holder.holder_lost();
        // First validate the complete union while runner admission is still
        // live, then remove and prove that exact runner absent as the positive
        // admission fence. No helper or LocalDocker deletion may precede it.
        self.inspect_lifecycle_topology(installation, epoch, desired, expected, expected_runner_id)
            .await?;
        let live_ids = self
            .inspect_rendered_live_ids(installation, expected)
            .await?;
        let images = self
            .inspect_epoch_images(epoch)
            .await?
            .into_iter()
            .map(|image| (image.role.clone(), image))
            .collect::<BTreeMap<_, _>>();
        let runner = expected
            .containers
            .get("runner")
            .ok_or_else(engine_resource_mismatch)?;
        let runner_name = format!("{}-runner-1", installation.compose_project());
        if let Some(container) = self.inspect_container(&runner_name).await? {
            let id = exact_container_id(&container)?.to_owned();
            let image = images
                .get(runner.image_role)
                .ok_or_else(engine_resource_mismatch)?;
            let image_config = self
                .inspect_image(&image.image_id)
                .await?
                .and_then(|image| image.config)
                .ok_or_else(engine_resource_mismatch)?;
            validate_rendered_container(
                &container,
                &runner_name,
                &image.image_id,
                installation,
                runner,
                expected,
                desired,
                &image_config,
                &live_ids,
                false,
            )?;
            lifecycle_cancellation_checkpoint(&holder_lost)?;
            let options = RemoveContainerOptionsBuilder::default()
                .force(true)
                .v(false)
                .link(false)
                .build();
            let _untrusted = mutation
                .run(tokio::time::timeout(
                    ENGINE_TIMEOUT,
                    self.docker.remove_container(&id, Some(options)),
                ))
                .await?;
            if self.inspect_container(&id).await?.is_some()
                || self.inspect_container(&runner_name).await?.is_some()
            {
                return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
            }
        }
        self.attest_lifecycle_lock(installation, epoch, holder)
            .await?;
        self.inspect_lifecycle_topology(installation, epoch, desired, expected, expected_runner_id)
            .await?;
        self.cleanup_lifecycle_disposable_helpers(
            installation,
            epoch,
            desired,
            expected,
            expected_runner_id,
            holder,
            &holder_lost,
            mutation,
        )
        .await?;
        self.remove_local_docker_children(installation, desired, expected_runner_id, mutation)
            .await?;
        self.attest_lifecycle_lock(installation, epoch, holder)
            .await?;
        for service in [
            "engine-relay",
            "runner-enroll",
            "bootstrap-runner",
            "object-store-init",
            "automata",
            "rustfs",
            "postgres",
        ] {
            let rendered = expected
                .containers
                .get(service)
                .ok_or_else(engine_resource_mismatch)?;
            let name = if rendered.oneoff() {
                format!("{}-{service}", installation.compose_project())
            } else {
                format!("{}-{service}-1", installation.compose_project())
            };
            if let Some(container) = self.inspect_container(&name).await? {
                let id = exact_container_id(&container)?.to_owned();
                let image = images
                    .get(rendered.image_role)
                    .ok_or_else(engine_resource_mismatch)?;
                let image_config = self
                    .inspect_image(&image.image_id)
                    .await?
                    .and_then(|image| image.config)
                    .ok_or_else(engine_resource_mismatch)?;
                validate_rendered_container(
                    &container,
                    &name,
                    &image.image_id,
                    installation,
                    rendered,
                    expected,
                    desired,
                    &image_config,
                    &live_ids,
                    false,
                )?;
                let options = RemoveContainerOptionsBuilder::default()
                    .force(true)
                    .v(false)
                    .link(false)
                    .build();
                let _untrusted = mutation
                    .run(tokio::time::timeout(
                        ENGINE_TIMEOUT,
                        self.docker.remove_container(&id, Some(options)),
                    ))
                    .await?;
                if self.inspect_container(&id).await?.is_some()
                    || self.inspect_container(&name).await?.is_some()
                {
                    return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
                }
            }
            self.attest_lifecycle_lock(installation, epoch, holder)
                .await?;
        }

        for rendered in expected.networks.values() {
            let Some(network) = self.inspect_network_exact(&rendered.name).await? else {
                continue;
            };
            validate_rendered_network(
                &network,
                installation,
                rendered,
                &BTreeMap::new(),
                live_ids.networks.get(&rendered.name).map(String::as_str),
            )?;
            if network
                .containers
                .as_ref()
                .is_some_and(|containers| !containers.is_empty())
            {
                return Err(engine_resource_mismatch());
            }
            let id = network
                .id
                .as_deref()
                .filter(|id| exact_container_id_text(id))
                .ok_or_else(engine_resource_mismatch)?
                .to_owned();
            let _untrusted = mutation
                .run(tokio::time::timeout(
                    ENGINE_TIMEOUT,
                    self.docker.remove_network(&id),
                ))
                .await?;
            if self.inspect_network_exact(&id).await?.is_some()
                || self.inspect_network_exact(&rendered.name).await?.is_some()
            {
                return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
            }
        }
        self.remove_results_transit_if_present(installation, desired, mutation)
            .await?;
        if self
            .inspect_lifecycle_topology(installation, epoch, desired, expected, expected_runner_id)
            .await?
            != LifecycleTopology::Empty
        {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        self.preflight_lifecycle_volumes(installation, epoch)
            .await?;
        self.attest_lifecycle_lock(installation, epoch, holder)
            .await
    }

    pub(super) async fn discover_local_docker_children(
        &self,
        installation: &Installation,
        expected_runner_id: uuid::Uuid,
    ) -> Result<
        (
            Vec<PinnedLocalDockerContainer>,
            Vec<PinnedLocalDockerNetwork>,
        ),
        LocalInitError,
    > {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let containers = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.list_containers(Some(
                ListContainersOptionsBuilder::default().all(true).build(),
            )),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        let networks = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker
                .list_networks(Some(ListNetworksOptionsBuilder::default().build())),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        if containers.len() > MAX_ENGINE_RESOURCES || networks.len() > MAX_ENGINE_RESOURCES {
            return Err(engine_resource_mismatch());
        }
        let prefix = local_docker_name_prefix(installation);
        let mut pinned_containers = Vec::new();
        let mut known_names = BTreeSet::new();
        for summary in &containers {
            if !local_docker_candidate_container(summary, installation, &prefix) {
                continue;
            }
            let pinned = validate_local_docker_container_summary(summary, installation)?;
            if !known_names.insert(pinned.name.clone()) {
                return Err(engine_resource_mismatch());
            }
            let by_id = self
                .inspect_container(&pinned.id)
                .await?
                .ok_or_else(engine_resource_mismatch)?;
            let by_name = self
                .inspect_container(&pinned.name)
                .await?
                .ok_or_else(engine_resource_mismatch)?;
            if exact_container_id(&by_id)? != pinned.id
                || exact_container_id(&by_name)? != pinned.id
            {
                return Err(engine_resource_mismatch());
            }
            pinned_containers.push(pinned);
        }
        let mut pinned_networks = Vec::new();
        for network in &networks {
            if !local_docker_candidate_network(network, installation, &prefix) {
                continue;
            }
            let pinned = validate_local_docker_network(network, installation, &known_names)?;
            let inspected = self
                .inspect_network_exact(&pinned.id)
                .await?
                .ok_or_else(engine_resource_mismatch)?;
            validate_local_docker_network_inspect(&inspected, &pinned, installation, &known_names)?;
            pinned_networks.push(pinned);
        }

        if !pinned_containers.is_empty() || !pinned_networks.is_empty() {
            let runner_ids = pinned_containers
                .iter()
                .map(|item| item.runner_id)
                .chain(pinned_networks.iter().map(|item| item.runner_id))
                .collect::<BTreeSet<_>>();
            if runner_ids != BTreeSet::from([expected_runner_id]) {
                return Err(engine_resource_mismatch());
            }
        }

        // Re-list before mutation to close discovery races.
        let repeated_containers = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.list_containers(Some(
                ListContainersOptionsBuilder::default().all(true).build(),
            )),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        let repeated_networks = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker
                .list_networks(Some(ListNetworksOptionsBuilder::default().build())),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        let repeated_container_ids = repeated_containers
            .iter()
            .filter(|summary| local_docker_candidate_container(summary, installation, &prefix))
            .map(|summary| {
                validate_local_docker_container_summary(summary, installation).map(|item| item.id)
            })
            .collect::<Result<BTreeSet<_>, LocalInitError>>()?;
        let repeated_network_ids = repeated_networks
            .iter()
            .filter(|network| local_docker_candidate_network(network, installation, &prefix))
            .map(|network| {
                validate_local_docker_network(network, installation, &known_names)
                    .map(|item| item.id)
            })
            .collect::<Result<BTreeSet<_>, LocalInitError>>()?;
        if repeated_container_ids
            != pinned_containers
                .iter()
                .map(|item| item.id.clone())
                .collect()
            || repeated_network_ids != pinned_networks.iter().map(|item| item.id.clone()).collect()
        {
            return Err(engine_resource_mismatch());
        }

        Ok((pinned_containers, pinned_networks))
    }

    /// Recovers the sole runner authority from already-present `LocalDocker`
    /// custody when non-authority host material is missing during reset. The
    /// full sibling parser revalidates this value before any deletion.
    pub(in crate::init) async fn discover_lifecycle_runner_id_for_reset(
        &self,
        installation: &Installation,
    ) -> Result<Option<uuid::Uuid>, LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let containers = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.list_containers(Some(
                ListContainersOptionsBuilder::default().all(true).build(),
            )),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        let networks = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker
                .list_networks(Some(ListNetworksOptionsBuilder::default().build())),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        if containers.len() > MAX_ENGINE_RESOURCES || networks.len() > MAX_ENGINE_RESOURCES {
            return Err(engine_resource_mismatch());
        }
        let prefix = local_docker_name_prefix(installation);
        let mut known_names = BTreeSet::new();
        let mut runner_ids = BTreeSet::new();
        for summary in &containers {
            if !local_docker_candidate_container(summary, installation, &prefix) {
                continue;
            }
            let pinned = validate_local_docker_container_summary(summary, installation)?;
            if !known_names.insert(pinned.name) {
                return Err(engine_resource_mismatch());
            }
            runner_ids.insert(pinned.runner_id);
        }
        for network in &networks {
            if !local_docker_candidate_network(network, installation, &prefix) {
                continue;
            }
            runner_ids.insert(
                validate_local_docker_network(network, installation, &known_names)?.runner_id,
            );
        }
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await?;
        sole_local_docker_runner_id(runner_ids)
    }

    /// Performs the production-parser `LocalDocker` union audit without repair.
    pub(in crate::init) async fn attest_local_docker_children(
        &self,
        installation: &Installation,
        desired: &DesiredSpec,
        expected_runner_id: uuid::Uuid,
    ) -> Result<(), LocalInitError> {
        let (containers, networks) = self
            .discover_local_docker_children(installation, expected_runner_id)
            .await?;
        if containers.is_empty() && networks.is_empty() {
            return Ok(());
        }
        let transit_name = results_transit_name(installation);
        let transit = self
            .inspect_network_exact(&transit_name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        validate_results_transit(&transit, installation, desired, false)?;
        let transit_id = transit
            .id
            .as_deref()
            .filter(|id| exact_container_id_text(id))
            .ok_or_else(engine_resource_mismatch)?;
        let results_name = format!("{}-automata-1", installation.compose_project());
        let results_id = self
            .inspect_container(&results_name)
            .await?
            .and_then(|container| container.id)
            .filter(|id| exact_container_id_text(id))
            .ok_or_else(engine_resource_mismatch)?;
        attest_lifecycle_sibling_union(
            installation,
            desired,
            expected_runner_id,
            transit_id,
            &results_id,
            &local_docker_container_candidates(&containers),
            &local_docker_network_candidates(&networks),
        )
        .await
        .map_err(|_| engine_resource_mismatch())
    }

    /// Discovers, validates, and removes every exact `LocalDocker` sibling for
    /// this installation. Validation of the complete container/network union
    /// finishes before the first delete, and every delete is reconciled by
    /// exact ID plus deterministic-name absence.
    pub(in crate::init) async fn remove_local_docker_children(
        &self,
        installation: &Installation,
        desired: &DesiredSpec,
        expected_runner_id: uuid::Uuid,
        mutation: &LifecycleMutationFence,
    ) -> Result<(), LocalInitError> {
        let (mut pinned_containers, pinned_networks) = self
            .discover_local_docker_children(installation, expected_runner_id)
            .await?;
        attest_lifecycle_sibling_custody_union(
            installation,
            desired,
            expected_runner_id,
            &local_docker_container_candidates(&pinned_containers),
            &local_docker_network_candidates(&pinned_networks),
        )
        .await
        .map_err(|_| engine_resource_mismatch())?;
        pinned_containers.sort_by_key(|item| local_docker_delete_rank(&item.kind));
        for pinned in &pinned_containers {
            let options = RemoveContainerOptionsBuilder::default()
                .force(true)
                .v(false)
                .link(false)
                .build();
            let _untrusted = mutation
                .run(tokio::time::timeout(
                    ENGINE_TIMEOUT,
                    self.docker.remove_container(&pinned.id, Some(options)),
                ))
                .await?;
            if self.inspect_container(&pinned.id).await?.is_some()
                || self.inspect_container(&pinned.name).await?.is_some()
            {
                return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
            }
        }
        for pinned in &pinned_networks {
            let current = self
                .inspect_network_exact(&pinned.id)
                .await?
                .ok_or_else(engine_resource_mismatch)?;
            if current
                .containers
                .as_ref()
                .is_some_and(|containers| !containers.is_empty())
            {
                return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
            }
            let _untrusted = mutation
                .run(tokio::time::timeout(
                    ENGINE_TIMEOUT,
                    self.docker.remove_network(&pinned.id),
                ))
                .await?;
            if self.inspect_network_exact(&pinned.id).await?.is_some()
                || self.inspect_network_exact(&pinned.name).await?.is_some()
            {
                return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
            }
        }
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await
    }

    /// Removes only exact stopped disposable lifecycle helpers left behind by
    /// a manager crash. Two complete discovery/validation passes must agree
    /// before the first exact-ID deletion, and the live holder is re-attested
    /// around every mutation.
    pub(in crate::init) async fn cleanup_lifecycle_disposable_helpers(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        desired: &DesiredSpec,
        expected: &ExpectedLifecycleTopology,
        expected_runner_id: uuid::Uuid,
        holder: &LifecycleLockHolder,
        cancellation: &CancellationToken,
        mutation: &LifecycleMutationFence,
    ) -> Result<(), LocalInitError> {
        lifecycle_cancellation_checkpoint(cancellation)?;
        self.attest_lifecycle_lock(installation, epoch, holder)
            .await?;
        self.preflight_lifecycle_volumes(installation, epoch)
            .await?;
        let first = self
            .discover_lifecycle_disposable_helpers(installation, epoch)
            .await?;
        lifecycle_cancellation_checkpoint(cancellation)?;
        let repeated = self
            .discover_lifecycle_disposable_helpers(installation, epoch)
            .await?;
        if first != repeated {
            return Err(engine_resource_mismatch());
        }
        // The complete topology/attachment union is the last read-only gate
        // before the first helper deletion. Re-pin the helper set afterwards
        // so the deletion loop consumes exactly the union that this census
        // validated, never an earlier snapshot.
        self.inspect_lifecycle_topology(installation, epoch, desired, expected, expected_runner_id)
            .await?;
        lifecycle_cancellation_checkpoint(cancellation)?;
        if self
            .discover_lifecycle_disposable_helpers(installation, epoch)
            .await?
            != first
        {
            return Err(engine_resource_mismatch());
        }

        for pinned in first {
            lifecycle_cancellation_checkpoint(cancellation)?;
            self.attest_lifecycle_lock(installation, epoch, holder)
                .await?;
            let current_by_id = self
                .inspect_container(&pinned.id)
                .await?
                .ok_or_else(engine_resource_mismatch)?;
            let current_by_name = self
                .inspect_container(&pinned.name)
                .await?
                .ok_or_else(engine_resource_mismatch)?;
            let images = self
                .inspect_epoch_images(epoch)
                .await?
                .into_iter()
                .map(|image| (image.role.clone(), image))
                .collect::<BTreeMap<_, _>>();
            let automata = images
                .get("automata")
                .ok_or_else(engine_resource_mismatch)?;
            let volumes = volume_names(installation);
            for current in [&current_by_id, &current_by_name] {
                if validate_lifecycle_disposable_helper(
                    current,
                    &pinned.name,
                    installation,
                    epoch,
                    automata,
                    &volumes,
                )? != Some(pinned.clone())
                {
                    return Err(engine_resource_mismatch());
                }
            }
            lifecycle_cancellation_checkpoint(cancellation)?;
            let options = RemoveContainerOptionsBuilder::default()
                .force(true)
                .v(false)
                .link(false)
                .build();
            let _untrusted = mutation
                .run(tokio::time::timeout(
                    ENGINE_TIMEOUT,
                    self.docker.remove_container(&pinned.id, Some(options)),
                ))
                .await?;
            if self.inspect_container(&pinned.id).await?.is_some()
                || self.inspect_container(&pinned.name).await?.is_some()
            {
                return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
            }
            self.attest_lifecycle_lock(installation, epoch, holder)
                .await?;
        }
        if !self
            .discover_lifecycle_disposable_helpers(installation, epoch)
            .await?
            .is_empty()
        {
            return Err(engine_resource_mismatch());
        }
        self.preflight_lifecycle_volumes(installation, epoch)
            .await?;
        self.attest_lifecycle_lock(installation, epoch, holder)
            .await
    }

    pub(super) async fn discover_lifecycle_disposable_helpers(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
    ) -> Result<BTreeSet<PinnedLifecycleHelper>, LocalInitError> {
        let images = self
            .inspect_epoch_images(epoch)
            .await?
            .into_iter()
            .map(|image| (image.role.clone(), image))
            .collect::<BTreeMap<_, _>>();
        let automata = images
            .get("automata")
            .ok_or_else(engine_resource_mismatch)?;
        let volumes = volume_names(installation);
        let project = installation.compose_project().to_string();
        let prefix = format!("{project}-");
        let listed = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.list_containers(Some(
                ListContainersOptionsBuilder::default().all(true).build(),
            )),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        if listed.len() > MAX_ENGINE_RESOURCES {
            return Err(engine_resource_mismatch());
        }
        let mut helpers = BTreeSet::new();
        for summary in listed {
            let labels = summary.labels.clone().unwrap_or_default();
            let names = summary.names.as_deref().unwrap_or_default();
            let related = labels.get(LABEL_INSTALLATION_ID) == Some(&installation.id().to_string())
                || labels.get(LABEL_INSTALLATION_KEY)
                    == Some(&installation.selector_key().to_string())
                || labels.get(LABEL_COMPOSE_PROJECT) == Some(&project)
                || names.iter().any(|name| {
                    let name = name.trim_start_matches('/');
                    name == lifecycle_material_attester_name(installation)
                        || name == format!("{project}-desired-reader")
                        || (name.starts_with(&prefix)
                            && (name.ends_with("-cas") || name.ends_with("-cas-digest")))
                });
            if !related {
                continue;
            }
            let kind = labels.get(LABEL_RESOURCE_KIND).map(String::as_str);
            let helper_kind = matches!(
                kind,
                Some(
                    LIFECYCLE_ATTESTER_KIND
                        | DESIRED_READER_KIND
                        | CAS_WRITER_KIND
                        | CAS_DIGEST_READER_KIND
                )
            );
            let helper_name = names.iter().any(|name| {
                let name = name.trim_start_matches('/');
                name == lifecycle_material_attester_name(installation)
                    || name == format!("{project}-desired-reader")
                    || (name.starts_with(&prefix)
                        && (name.ends_with("-cas") || name.ends_with("-cas-digest")))
            });
            if !helper_kind && !helper_name {
                continue;
            }
            let id = summary
                .id
                .as_deref()
                .filter(|id| exact_container_id_text(id))
                .ok_or_else(engine_resource_mismatch)?;
            if names.len() != 1 {
                return Err(engine_resource_mismatch());
            }
            let name = names[0]
                .strip_prefix('/')
                .filter(|name| !name.is_empty())
                .ok_or_else(engine_resource_mismatch)?;
            let container = self
                .inspect_container(id)
                .await?
                .ok_or_else(engine_resource_mismatch)?;
            let pinned = validate_lifecycle_disposable_helper(
                &container,
                name,
                installation,
                epoch,
                automata,
                &volumes,
            )?
            .ok_or_else(engine_resource_mismatch)?;
            if !helpers.insert(pinned) {
                return Err(engine_resource_mismatch());
            }
        }
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await?;
        Ok(helpers)
    }

    pub(super) async fn inspect_network_exact(
        &self,
        name: &str,
    ) -> Result<Option<NetworkInspect>, LocalInitError> {
        match tokio::time::timeout(ENGINE_TIMEOUT, self.docker.inspect_network(name, None)).await {
            Ok(Ok(network)) => Ok(Some(network)),
            Ok(Err(error)) if not_found(&error) => Ok(None),
            _ => Err(LocalInitError::new(LocalInitErrorCode::EngineUnavailable)),
        }
    }

    pub(super) async fn lifecycle_quiescent_identity_census(
        &self,
        installation: &Installation,
    ) -> Result<LifecycleIdentityCensus, LocalInitError> {
        self.lifecycle_identity_census(installation, true).await
    }

    pub(super) async fn lifecycle_identity_census(
        &self,
        installation: &Installation,
        require_identity: bool,
    ) -> Result<LifecycleIdentityCensus, LocalInitError> {
        let installation_id = installation.id().to_string();
        let installation_key = installation.selector_key().to_string();
        let project = installation.compose_project().to_string();
        let project_prefix = format!("{project}-");
        let local_prefix = local_docker_name_prefix(installation);
        let related = |labels: &HashMap<String, String>| {
            labels.get(LABEL_INSTALLATION_ID) == Some(&installation_id)
                || labels.get(LABEL_INSTALLATION_KEY) == Some(&installation_key)
                || labels.get(LABEL_COMPOSE_PROJECT) == Some(&project)
                || labels.get("com.docker.compose.project") == Some(&project)
        };
        let listed = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.list_containers(Some(
                ListContainersOptionsBuilder::default().all(true).build(),
            )),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        if listed.len() > MAX_ENGINE_RESOURCES {
            return Err(engine_resource_mismatch());
        }
        let mut containers = BTreeSet::new();
        for summary in listed {
            let labels = summary.labels.clone().unwrap_or_default();
            let names = summary.names.as_deref().unwrap_or_default();
            if !related(&labels)
                && !names.iter().any(|name| {
                    let name = name.trim_start_matches('/');
                    name.starts_with(&project_prefix) || name.starts_with(&local_prefix)
                })
            {
                continue;
            }
            let id = summary
                .id
                .filter(|id| exact_container_id_text(id))
                .ok_or_else(engine_resource_mismatch)?;
            if names.len() != 1 {
                return Err(engine_resource_mismatch());
            }
            let name = names[0]
                .strip_prefix('/')
                .filter(|name| !name.is_empty())
                .ok_or_else(engine_resource_mismatch)?
                .to_owned();
            if !containers.insert((
                id,
                name,
                summary.state.map(|state| state.to_string()),
                summary.status,
            )) {
                return Err(engine_resource_mismatch());
            }
        }
        let listed_networks = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker
                .list_networks(Some(ListNetworksOptionsBuilder::default().build())),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        if listed_networks.len() > MAX_ENGINE_RESOURCES {
            return Err(engine_resource_mismatch());
        }
        let mut networks = BTreeSet::new();
        for network in listed_networks {
            let labels = network.labels.clone().unwrap_or_default();
            let name = network.name.unwrap_or_default();
            if !related(&labels)
                && !name.starts_with(&project_prefix)
                && !name.starts_with(&local_prefix)
            {
                continue;
            }
            let id = network
                .id
                .filter(|id| exact_container_id_text(id))
                .ok_or_else(engine_resource_mismatch)?;
            if name.is_empty() || !networks.insert((id, name)) {
                return Err(engine_resource_mismatch());
            }
        }
        if require_identity {
            self.verify_installation(installation).await?;
        }
        self.verify_selected_engine().await?;
        Ok(LifecycleIdentityCensus {
            containers,
            networks,
        })
    }

    pub(in crate::init) async fn attest_reset_union_absent(
        &self,
        installation: &Installation,
    ) -> Result<(), LocalInitError> {
        let expected_volumes = BTreeSet::new();
        let first_volumes = self
            .inspect_lifecycle_volume_union(installation, &expected_volumes)
            .await?;
        let first = self.lifecycle_identity_census(installation, false).await?;
        let repeated_volumes = self
            .inspect_lifecycle_volume_union(installation, &expected_volumes)
            .await?;
        let repeated = self.lifecycle_identity_census(installation, false).await?;
        if !first_volumes.is_empty()
            || first_volumes != repeated_volumes
            || first != repeated
            || !first.containers.is_empty()
            || !first.networks.is_empty()
            || self
                .adapter
                .inspect_identity(installation.name())
                .await
                .map_err(|_| engine_resource_mismatch())?
                .is_some()
        {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await
    }

    /// Removes any exact prior instance of a lifecycle one-off so a replay can
    /// issue the same idempotent operation without name ambiguity.
    pub(in crate::init) async fn reconcile_lifecycle_oneoff(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        desired: &DesiredSpec,
        expected: &ExpectedLifecycleTopology,
        service: &'static str,
        mutation: &LifecycleMutationFence,
    ) -> Result<(), LocalInitError> {
        let name = lifecycle_oneoff_name(installation, service)?;
        let Some(container) = self.inspect_container(&name).await? else {
            return Ok(());
        };
        let id = exact_container_id(&container)?.to_owned();
        self.validate_lifecycle_oneoff(&container, installation, epoch, desired, expected, service)
            .await?;
        self.wait_lifecycle_oneoff(&id).await?;
        self.remove_lifecycle_oneoff_and_prove_absent(&name, &id, mutation)
            .await
    }

    /// Waits for one exact Compose-created one-off, validates its terminal
    /// status and bounded logs, then removes it by pinned ID and proves both
    /// ID and deterministic name absent.
    pub(in crate::init) async fn finish_lifecycle_oneoff(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        desired: &DesiredSpec,
        expected: &ExpectedLifecycleTopology,
        service: &'static str,
        mutation: &LifecycleMutationFence,
    ) -> Result<Vec<u8>, LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let name = lifecycle_oneoff_name(installation, service)?;
        let container = self
            .inspect_container(&name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        let id = exact_container_id(&container)?.to_owned();
        self.validate_lifecycle_oneoff(&container, installation, epoch, desired, expected, service)
            .await?;
        let status = self.wait_lifecycle_oneoff(&id).await?;
        let stopped = self
            .inspect_container(&id)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        self.validate_lifecycle_oneoff(&stopped, installation, epoch, desired, expected, service)
            .await?;
        let logs = self.lifecycle_oneoff_logs(&id).await?;
        let cleanup = self
            .remove_lifecycle_oneoff_and_prove_absent(&name, &id, mutation)
            .await;
        cleanup?;
        if status != 0 {
            return Err(LocalInitError::new(
                LocalInitErrorCode::MaterializationFailed,
            ));
        }
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await?;
        Ok(logs)
    }

    pub(super) async fn validate_lifecycle_oneoff(
        &self,
        container: &bollard::models::ContainerInspectResponse,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        desired: &DesiredSpec,
        expected: &ExpectedLifecycleTopology,
        service: &'static str,
    ) -> Result<(), LocalInitError> {
        let contract = lifecycle_oneoff_contract(service)?;
        let image = self
            .inspect_epoch_images(epoch)
            .await?
            .into_iter()
            .find(|image| image.role == contract.image_role)
            .ok_or_else(engine_resource_mismatch)?;
        let name = lifecycle_oneoff_name(installation, service)?;
        let rendered = expected
            .containers
            .get(service)
            .filter(|container| container.oneoff())
            .ok_or_else(engine_resource_mismatch)?;
        let image_config = self
            .inspect_image(&image.image_id)
            .await?
            .and_then(|image| image.config)
            .ok_or_else(engine_resource_mismatch)?;
        let live_ids = self
            .inspect_rendered_live_ids(installation, expected)
            .await?;
        validate_rendered_container(
            container,
            &name,
            &image.image_id,
            installation,
            rendered,
            expected,
            desired,
            &image_config,
            &live_ids,
            false,
        )
    }

    pub(super) async fn wait_lifecycle_oneoff(&self, id: &str) -> Result<i64, LocalInitError> {
        let options = WaitContainerOptionsBuilder::default()
            .condition("not-running")
            .build();
        let mut wait = self.docker.wait_container(id, Some(options));
        tokio::time::timeout(HELPER_TIMEOUT, async {
            let result = wait
                .next()
                .await
                .ok_or_else(engine_resource_mismatch)?
                .map_err(|_| engine_resource_mismatch())?;
            if result.error.is_some() || wait.next().await.is_some() {
                return Err(engine_resource_mismatch());
            }
            Ok(result.status_code)
        })
        .await
        .map_err(|_| engine_unavailable())?
    }

    pub(super) async fn lifecycle_oneoff_logs(&self, id: &str) -> Result<Vec<u8>, LocalInitError> {
        let options = LogsOptionsBuilder::default()
            .follow(false)
            .stdout(true)
            .stderr(true)
            .timestamps(false)
            .tail("all")
            .build();
        let mut frames = self.docker.logs(id, Some(options));
        tokio::time::timeout(ENGINE_TIMEOUT, async {
            let mut bytes = Vec::new();
            while let Some(frame) = frames.next().await {
                let frame = frame.map_err(|_| engine_resource_mismatch())?;
                if !matches!(frame, LogOutput::StdOut { .. } | LogOutput::StdErr { .. })
                    || frame.as_ref().len() > MAX_ONEOFF_LOG_BYTES.saturating_sub(bytes.len())
                {
                    return Err(engine_resource_mismatch());
                }
                bytes.extend_from_slice(frame.as_ref());
            }
            Ok(bytes)
        })
        .await
        .map_err(|_| engine_unavailable())?
    }

    pub(super) async fn remove_lifecycle_oneoff_and_prove_absent(
        &self,
        name: &str,
        id: &str,
        mutation: &LifecycleMutationFence,
    ) -> Result<(), LocalInitError> {
        let options = RemoveContainerOptionsBuilder::default()
            .force(true)
            .v(false)
            .build();
        let _untrusted = mutation
            .run(tokio::time::timeout(
                ENGINE_TIMEOUT,
                self.docker.remove_container(id, Some(options)),
            ))
            .await?;
        if self.inspect_container(id).await?.is_some()
            || self.inspect_container(name).await?.is_some()
        {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await
    }

    /// Attests one exact running Compose service and returns its pinned ID.
    pub(in crate::init) async fn attest_lifecycle_service(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        desired: &DesiredSpec,
        expected: &ExpectedLifecycleTopology,
        service: &'static str,
    ) -> Result<String, LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let name = format!("{}-{service}-1", installation.compose_project());
        let container = self
            .inspect_container(&name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        let id = exact_container_id(&container)?.to_owned();
        let rendered = expected
            .containers
            .get(service)
            .filter(|container| !container.oneoff())
            .ok_or_else(engine_resource_mismatch)?;
        let image = self
            .inspect_epoch_images(epoch)
            .await?
            .into_iter()
            .find(|image| image.role == rendered.image_role)
            .ok_or_else(engine_resource_mismatch)?;
        let image_config = self
            .inspect_image(&image.image_id)
            .await?
            .and_then(|image| image.config)
            .ok_or_else(engine_resource_mismatch)?;
        let live_ids = self
            .inspect_rendered_live_ids(installation, expected)
            .await?;
        validate_rendered_container(
            &container,
            &name,
            &image.image_id,
            installation,
            rendered,
            expected,
            desired,
            &image_config,
            &live_ids,
            true,
        )?;
        let by_id = self
            .inspect_container(&id)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        if by_id != container {
            return Err(engine_resource_mismatch());
        }
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await?;
        Ok(id)
    }

    /// Attests all five steady services and the two exact lifecycle networks.
    pub(in crate::init) async fn attest_running_lifecycle(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        desired: &DesiredSpec,
        expected: &ExpectedLifecycleTopology,
        transit_id: &str,
    ) -> Result<(), LocalInitError> {
        for service in ["postgres", "rustfs", "automata", "engine-relay", "runner"] {
            self.attest_lifecycle_service(installation, epoch, desired, expected, service)
                .await?;
        }
        self.attest_results_transit(installation, desired, transit_id, false)
            .await?;
        self.attest_control_network(installation, desired).await?;
        self.attest_egress_network(installation, desired).await?;
        Ok(())
    }

    pub(super) async fn attest_control_network(
        &self,
        installation: &Installation,
        desired: &DesiredSpec,
    ) -> Result<(), LocalInitError> {
        let name = format!("{}-control", installation.compose_project());
        let network = self
            .inspect_network_exact(&name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        validate_control_network(&network, installation, desired)
    }

    pub(super) async fn attest_egress_network(
        &self,
        installation: &Installation,
        desired: &DesiredSpec,
    ) -> Result<(), LocalInitError> {
        let name = format!("{}-egress", installation.compose_project());
        let network = self
            .inspect_network_exact(&name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        validate_egress_network(&network, installation, desired)
    }
}
