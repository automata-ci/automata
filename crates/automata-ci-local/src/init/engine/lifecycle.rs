use std::collections::{BTreeMap, BTreeSet, HashMap};

use automata_ci_core::Sha256Digest;
use bollard::{
    container::LogOutput,
    models::{
        ContainerCreateBody, HostConfig, HostConfigCgroupnsModeEnum, Ipam, IpamConfig, Mount,
        MountType, MountVolumeOptions, NetworkCreateRequest, NetworkInspect, RestartPolicy,
        RestartPolicyNameEnum, Volume, VolumeCreateRequest,
    },
    query_parameters::{
        CreateContainerOptionsBuilder, LogsOptionsBuilder, RemoveContainerOptionsBuilder,
        RemoveVolumeOptionsBuilder, WaitContainerOptionsBuilder,
    },
};
use futures::StreamExt as _;
use sha2::{Digest as _, Sha256};

use crate::{
    DesiredSpec, Installation, MAX_LOCAL_DESIRED_SPEC_BYTES,
    lifecycle_helper::{CasRequest, CasTarget},
    results_transport::{
        RESULTS_TRANSIT_GATEWAY_MODE_KEY, RESULTS_TRANSIT_GATEWAY_MODE_VALUE,
        ResultsTransitNetworkShape, exact_results_transit_base, results_transit_labels,
        results_transit_name,
    },
};

use super::{
    ENGINE_TIMEOUT, HELPER_MEMORY_BYTES, HELPER_NANO_CPUS, HELPER_PIDS, HELPER_TIMEOUT,
    HelperDriver, InitEngine, engine_resource_mismatch, engine_unavailable, exact_container_id,
    exact_container_id_text, helper_log_config, helper_masked_paths, helper_readonly_paths,
    helper_security_options, not_found, validate_volume, volume_name, volume_names,
};
use crate::init::{
    LocalInitError, LocalInitErrorCode,
    epoch::ImmutableEpoch,
    lifecycle::{LifecycleIntent, LifecycleOperationKind},
    materializer::VolumeRole,
};

const LOCK_SCHEMA: &str = "1";
const LOCK_KIND: &str = "lifecycle-lock";
const LOCK_LABEL_DIGEST_DOMAIN: &[u8] = b"automata/local/lifecycle-lock-labels/v1\0";

const LABEL_MANAGED: &str = "io.automata.local.managed";
const LABEL_INSTALLATION_ID: &str = "io.automata.local.installation-id";
const LABEL_INSTALLATION_KEY: &str = "io.automata.local.installation-key";
const LABEL_COMPOSE_PROJECT: &str = "io.automata.local.compose-project";
const LABEL_EPOCH: &str = "io.automata.local.epoch-fingerprint";
const LABEL_PLAN: &str = "io.automata.local.plan-digest";
const LABEL_RESOURCE_KIND: &str = "io.automata.local.resource-kind";
const LABEL_LOCK_SCHEMA: &str = "io.automata.local.lifecycle-lock-schema";
const LABEL_STATE_AUTHORITY: &str = "io.automata.local.state-authority-sha256";
const LABEL_OPERATION_KIND: &str = "io.automata.local.lifecycle-operation";
const LABEL_OPERATION_ID: &str = "io.automata.local.lifecycle-operation-id";
const LABEL_INTENT: &str = "io.automata.local.lifecycle-intent-sha256";
const DESIRED_READER_KIND: &str = "lifecycle-desired-reader";
const CAS_WRITER_KIND: &str = "lifecycle-cas-writer";
const CAS_MOUNT: &str = "/run/automata-lifecycle-cas";
const MAX_ONEOFF_LOG_BYTES: usize = 64 * 1024;

/// Exact Engine-side election evidence for one durable lifecycle transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::init) struct LifecycleLockBinding {
    pub(in crate::init) name: String,
    pub(in crate::init) labels_sha256: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::init) enum LifecycleTopology {
    Empty,
    Partial,
    Running { transit_id: String },
}

impl InitEngine<'_> {
    /// Creates or adopts the image-independent sticky lifecycle election volume.
    ///
    /// The create response is ignored. Success is based only on a fresh exact
    /// inspection of the deterministic name, labels, local driver/options, and
    /// zero attachment set.
    pub(in crate::init) async fn elect_lifecycle_lock(
        &self,
        installation: &Installation,
        state_authority_sha256: Sha256Digest,
        intent: &LifecycleIntent,
    ) -> Result<LifecycleLockBinding, LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let binding = lifecycle_lock_binding(installation, state_authority_sha256, intent)?;
        let labels = lifecycle_lock_labels(installation, state_authority_sha256, intent);
        if self.inspect_volume(&binding.name).await?.is_none() {
            let request = VolumeCreateRequest {
                name: Some(binding.name.clone()),
                driver: Some("local".to_owned()),
                driver_opts: Some(std::collections::HashMap::new()),
                labels: Some(labels.clone().into_iter().collect()),
                cluster_volume_spec: None,
            };
            let _untrusted =
                tokio::time::timeout(ENGINE_TIMEOUT, self.docker.create_volume(request)).await;
        }
        self.attest_lifecycle_lock_exact(&binding, &labels).await?;
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await?;
        Ok(binding)
    }

    pub(in crate::init) async fn attest_lifecycle_lock(
        &self,
        installation: &Installation,
        state_authority_sha256: Sha256Digest,
        intent: &LifecycleIntent,
        binding: &LifecycleLockBinding,
    ) -> Result<(), LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let expected = lifecycle_lock_binding(installation, state_authority_sha256, intent)?;
        if &expected != binding {
            return Err(engine_resource_mismatch());
        }
        self.attest_lifecycle_lock_exact(
            binding,
            &lifecycle_lock_labels(installation, state_authority_sha256, intent),
        )
        .await?;
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await
    }

    /// Inspects the deterministic election name without creating it. A
    /// present volume is returned only after its complete immutable label,
    /// driver, option, and zero-attachment contract is re-attested.
    pub(in crate::init) async fn inspect_lifecycle_lock(
        &self,
        installation: &Installation,
        state_authority_sha256: Sha256Digest,
        intent: &LifecycleIntent,
    ) -> Result<Option<LifecycleLockBinding>, LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let binding = lifecycle_lock_binding(installation, state_authority_sha256, intent)?;
        let labels = lifecycle_lock_labels(installation, state_authority_sha256, intent);
        if self.inspect_volume(&binding.name).await?.is_none() {
            self.verify_installation(installation).await?;
            self.verify_selected_engine().await?;
            return Ok(None);
        }
        self.attest_lifecycle_lock_exact(&binding, &labels).await?;
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await?;
        Ok(Some(binding))
    }

    /// Removes the exact election volume and reconciles an ambiguous response
    /// solely by proving the deterministic name absent.
    pub(in crate::init) async fn remove_lifecycle_lock(
        &self,
        installation: &Installation,
        state_authority_sha256: Sha256Digest,
        intent: &LifecycleIntent,
        binding: &LifecycleLockBinding,
    ) -> Result<(), LocalInitError> {
        self.attest_lifecycle_lock(installation, state_authority_sha256, intent, binding)
            .await?;
        let options = RemoveVolumeOptionsBuilder::default().force(false).build();
        let _untrusted = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.remove_volume(&binding.name, Some(options)),
        )
        .await;
        if self.inspect_volume(&binding.name).await?.is_some() {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await
    }

    /// Proves the deterministic lifecycle election name is absent without
    /// creating or adopting any replacement. This is the only valid
    /// postcondition for finalizing an already-completed durable intent.
    pub(in crate::init) async fn attest_lifecycle_lock_absent(
        &self,
        installation: &Installation,
    ) -> Result<(), LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        if self
            .inspect_volume(&lifecycle_lock_name(installation))
            .await?
            .is_some()
        {
            return Err(engine_resource_mismatch());
        }
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await
    }

    async fn attest_lifecycle_lock_exact(
        &self,
        binding: &LifecycleLockBinding,
        labels: &BTreeMap<String, String>,
    ) -> Result<(), LocalInitError> {
        let volume = self
            .inspect_volume(&binding.name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        validate_lifecycle_lock(&volume, &binding.name, labels)?;
        if lock_labels_digest(labels)? != binding.labels_sha256
            || !self.volume_attachments(&binding.name).await?.is_empty()
        {
            return Err(engine_resource_mismatch());
        }
        Ok(())
    }

    /// Reads the sealed canonical Desired bytes through one exact, disposable,
    /// networkless Automata helper and proves the helper absent on every exit.
    pub(in crate::init) async fn read_sealed_desired(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
    ) -> Result<Vec<u8>, LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let automata = self
            .inspect_epoch_images(epoch)
            .await?
            .into_iter()
            .find(|image| image.role == "automata")
            .ok_or_else(engine_resource_mismatch)?;
        let volumes = volume_names(installation);
        let desired_name = volumes
            .get(&VolumeRole::Desired)
            .ok_or_else(engine_resource_mismatch)?;
        let desired = self
            .inspect_volume(desired_name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        let expected_labels = super::expected_volume_labels(installation, epoch.fingerprint());
        validate_volume(
            &desired,
            desired_name,
            expected_labels
                .get(&VolumeRole::Desired)
                .ok_or_else(engine_resource_mismatch)?,
        )?;
        if !self.volume_attachments(desired_name).await?.is_empty() {
            return Err(engine_resource_mismatch());
        }

        let name = format!("{}-desired-reader", installation.compose_project());
        let labels = desired_reader_labels(installation, epoch.fingerprint());
        if let Some(existing) = self.inspect_container(&name).await? {
            let id = existing
                .id
                .as_deref()
                .filter(|id| exact_container_id_text(id))
                .ok_or_else(engine_resource_mismatch)?
                .to_owned();
            validate_desired_reader(
                &existing,
                &id,
                &name,
                &automata.inspection_reference,
                &automata.image_id,
                desired_name,
                &labels,
            )?;
            self.remove_desired_reader_and_prove_absent(&id, &name, desired_name)
                .await?;
        }

        let options = CreateContainerOptionsBuilder::default()
            .name(&name)
            .platform("linux/amd64")
            .build();
        let created = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.create_container(
                Some(options),
                desired_reader_body(&automata.inspection_reference, desired_name, &labels),
            ),
        )
        .await;
        let pinned = match created {
            Ok(Ok(created))
                if created.warnings.is_empty() && exact_container_id_text(&created.id) =>
            {
                created.id
            }
            _ => self
                .inspect_container(&name)
                .await?
                .and_then(|container| container.id)
                .filter(|id| exact_container_id_text(id))
                .ok_or_else(engine_resource_mismatch)?,
        };
        let operation = self
            .run_desired_reader(
                &pinned,
                &name,
                &automata.inspection_reference,
                &automata.image_id,
                desired_name,
                &labels,
            )
            .await;
        let cleanup = self
            .remove_desired_reader_and_prove_absent(&pinned, &name, desired_name)
            .await;
        match (operation, cleanup) {
            (Ok(bytes), Ok(())) => Ok(bytes),
            (Err(error), Ok(())) | (_, Err(error)) => Err(error),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_desired_reader(
        &self,
        pinned: &str,
        name: &str,
        image: &str,
        image_id: &str,
        desired_volume: &str,
        labels: &BTreeMap<String, String>,
    ) -> Result<Vec<u8>, LocalInitError> {
        let stopped = self
            .inspect_container(pinned)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        validate_desired_reader(
            &stopped,
            pinned,
            name,
            image,
            image_id,
            desired_volume,
            labels,
        )?;
        if stopped.state.as_ref().and_then(|state| state.running) != Some(false)
            || self.volume_attachments(desired_volume).await?.as_slice() != [pinned]
        {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await?;
        tokio::time::timeout(ENGINE_TIMEOUT, self.docker.start_container(pinned, None))
            .await
            .map_err(|_| engine_resource_mismatch())?
            .map_err(|_| engine_resource_mismatch())?;
        self.verify_selected_engine().await?;
        let mut wait = self.docker.wait_container(
            pinned,
            Some(
                WaitContainerOptionsBuilder::default()
                    .condition("not-running")
                    .build(),
            ),
        );
        let result = tokio::time::timeout(HELPER_TIMEOUT, async {
            let result = wait
                .next()
                .await
                .ok_or_else(engine_resource_mismatch)?
                .map_err(|_| engine_resource_mismatch())?;
            if wait.next().await.is_some() {
                return Err(engine_resource_mismatch());
            }
            Ok(result)
        })
        .await
        .map_err(|_| engine_resource_mismatch())??;
        if result.status_code != 0 || result.error.is_some() {
            return Err(engine_resource_mismatch());
        }
        let exited = self
            .inspect_container(pinned)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        validate_desired_reader(
            &exited,
            pinned,
            name,
            image,
            image_id,
            desired_volume,
            labels,
        )?;
        if exited.state.as_ref().and_then(|state| state.running) != Some(false) {
            return Err(engine_resource_mismatch());
        }
        self.desired_reader_logs(pinned).await
    }

    async fn desired_reader_logs(&self, id: &str) -> Result<Vec<u8>, LocalInitError> {
        let options = LogsOptionsBuilder::default()
            .follow(false)
            .stdout(true)
            .stderr(true)
            .timestamps(false)
            .tail("all")
            .build();
        let mut stream = self.docker.logs(id, Some(options));
        tokio::time::timeout(ENGINE_TIMEOUT, async {
            let mut stdout = Vec::new();
            while let Some(frame) = stream.next().await {
                match frame.map_err(|_| engine_resource_mismatch())? {
                    LogOutput::StdOut { message } => {
                        if stdout.len().saturating_add(message.len()) > MAX_LOCAL_DESIRED_SPEC_BYTES
                        {
                            return Err(engine_resource_mismatch());
                        }
                        stdout.extend_from_slice(&message);
                    }
                    LogOutput::StdErr { message } if message.is_empty() => {}
                    _ => return Err(engine_resource_mismatch()),
                }
            }
            if stdout.is_empty() || !stdout.ends_with(b"\n") {
                return Err(engine_resource_mismatch());
            }
            Ok(stdout)
        })
        .await
        .map_err(|_| engine_resource_mismatch())?
    }

    async fn remove_desired_reader_and_prove_absent(
        &self,
        id: &str,
        name: &str,
        desired_volume: &str,
    ) -> Result<(), LocalInitError> {
        if !exact_container_id_text(id) {
            return Err(engine_resource_mismatch());
        }
        let options = RemoveContainerOptionsBuilder::default()
            .force(true)
            .v(false)
            .link(false)
            .build();
        let _untrusted = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.remove_container(id, Some(options)),
        )
        .await;
        if self.inspect_container(id).await?.is_some()
            || self.inspect_container(name).await?.is_some()
            || !self.volume_attachments(desired_volume).await?.is_empty()
        {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await
    }

    /// Applies one exact generated-file CAS through a disposable fixed helper.
    ///
    /// The request may contain credentials, so it is carried only over the
    /// attached stdin stream after exact image, container, volume, attachment,
    /// and daemon re-attestation. Every exit removes the pinned helper and
    /// proves both its name and exact ID absent.
    pub(in crate::init) async fn apply_lifecycle_cas(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        request: &CasRequest,
    ) -> Result<Sha256Digest, LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let automata = self
            .inspect_epoch_images(epoch)
            .await?
            .into_iter()
            .find(|image| image.role == "automata")
            .ok_or_else(engine_resource_mismatch)?;
        let role = cas_volume_role(request.target());
        let volume_name = volume_name(installation.compose_project().as_str(), role);
        let volume = self
            .inspect_volume(&volume_name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        validate_volume(
            &volume,
            &volume_name,
            &super::expected_volume_labels(installation, epoch.fingerprint())[&role],
        )?;
        if !self.volume_attachments(&volume_name).await?.is_empty() {
            return Err(engine_resource_mismatch());
        }

        let name = format!(
            "{}-{}-cas",
            installation.compose_project(),
            request.target().slug()
        );
        let labels = cas_writer_labels(installation, epoch, request);
        let user = cas_writer_user(request.target());
        let cap_add = if user == "0:0" {
            vec!["DAC_OVERRIDE".to_owned()]
        } else {
            Vec::new()
        };
        if let Some(existing) = self.inspect_container(&name).await? {
            let id = existing
                .id
                .as_deref()
                .filter(|id| exact_container_id_text(id))
                .ok_or_else(engine_resource_mismatch)?
                .to_owned();
            validate_cas_writer(
                &existing,
                &id,
                &name,
                &automata.inspection_reference,
                &automata.image_id,
                &volume_name,
                user,
                &cap_add,
                &labels,
            )?;
            self.remove_cas_writer_and_prove_absent(&id, &name, &volume_name)
                .await?;
        }

        let created = self
            .driver_create(
                &name,
                cas_writer_body(
                    &automata.inspection_reference,
                    &volume_name,
                    user,
                    &cap_add,
                    &labels,
                ),
            )
            .await;
        let pinned = match &created {
            Ok(created) if exact_container_id_text(&created.id) => Some(created.id.clone()),
            _ => self
                .inspect_container(&name)
                .await?
                .and_then(|container| container.id)
                .filter(|id| exact_container_id_text(id)),
        };
        let operation = async {
            let pinned = pinned.as_deref().ok_or_else(engine_resource_mismatch)?;
            if created
                .as_ref()
                .is_ok_and(|created| !created.warnings.is_empty())
            {
                return Err(engine_resource_mismatch());
            }
            self.attest_cas_writer(
                pinned,
                &name,
                &automata.inspection_reference,
                &automata.image_id,
                &volume_name,
                user,
                &cap_add,
                &labels,
                false,
            )
            .await?;
            let mut input = self.driver_attach(pinned).await?;
            self.verify_selected_engine().await?;
            self.attest_cas_writer(
                pinned,
                &name,
                &automata.inspection_reference,
                &automata.image_id,
                &volume_name,
                user,
                &cap_add,
                &labels,
                false,
            )
            .await?;
            self.driver_start(pinned).await?;
            self.verify_selected_engine().await?;
            self.attest_cas_writer(
                pinned,
                &name,
                &automata.inspection_reference,
                &automata.image_id,
                &volume_name,
                user,
                &cap_add,
                &labels,
                true,
            )
            .await?;
            let request_bytes = zeroize::Zeroizing::new(request.canonical_bytes()?);
            self.driver_send_request(&mut input, &request_bytes).await?;
            drop(input);
            let wait = self.driver_wait(pinned).await?;
            if wait.status_code != 0 || wait.has_error {
                return Err(engine_resource_mismatch());
            }
            let (stdout, stderr) = self.driver_logs(pinned).await?;
            if !stdout.is_empty() || !stderr.is_empty() {
                return Err(engine_resource_mismatch());
            }
            self.attest_cas_writer(
                pinned,
                &name,
                &automata.inspection_reference,
                &automata.image_id,
                &volume_name,
                user,
                &cap_add,
                &labels,
                false,
            )
            .await?;
            Ok(request.replacement_sha256())
        }
        .await;
        let cleanup = match pinned.as_deref() {
            Some(id) => {
                self.remove_cas_writer_and_prove_absent(id, &name, &volume_name)
                    .await
            }
            None => match self.inspect_container(&name).await? {
                None => Ok(()),
                Some(_) => Err(engine_resource_mismatch()),
            },
        };
        match cleanup {
            Err(error) => Err(error),
            Ok(()) => operation,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn attest_cas_writer(
        &self,
        id: &str,
        name: &str,
        image: &str,
        image_id: &str,
        volume_name: &str,
        user: &str,
        cap_add: &[String],
        labels: &BTreeMap<String, String>,
        running: bool,
    ) -> Result<(), LocalInitError> {
        self.verify_selected_engine().await?;
        let by_id = self
            .inspect_container(id)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        let by_name = self
            .inspect_container(name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        for container in [&by_id, &by_name] {
            validate_cas_writer(
                container,
                id,
                name,
                image,
                image_id,
                volume_name,
                user,
                cap_add,
                labels,
            )?;
            if container.state.as_ref().and_then(|state| state.running) != Some(running) {
                return Err(engine_resource_mismatch());
            }
        }
        if self.volume_attachments(volume_name).await?.as_slice() != [id] {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await
    }

    async fn remove_cas_writer_and_prove_absent(
        &self,
        id: &str,
        name: &str,
        volume_name: &str,
    ) -> Result<(), LocalInitError> {
        if !exact_container_id_text(id) {
            return Err(engine_resource_mismatch());
        }
        let _untrusted = self.driver_force_remove(id).await;
        if self.inspect_container(id).await?.is_some()
            || self.inspect_container(name).await?.is_some()
            || !self.volume_attachments(volume_name).await?.is_empty()
        {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await
    }

    /// Creates or adopts the lifecycle-owned schema-2 Results transit.
    pub(in crate::init) async fn ensure_results_transit(
        &self,
        installation: &Installation,
        desired: &DesiredSpec,
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
            let _untrusted =
                tokio::time::timeout(ENGINE_TIMEOUT, self.docker.create_network(request)).await;
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

    /// Requires the exact lifecycle-owned Results transit to already exist and
    /// returns its pinned Engine ID without issuing a create request.
    pub(in crate::init) async fn inspect_results_transit(
        &self,
        installation: &Installation,
        desired: &DesiredSpec,
    ) -> Result<String, LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let network = self
            .inspect_network_exact(&results_transit_name(installation))
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        validate_results_transit(&network, installation, desired, false)?;
        let id = network
            .id
            .filter(|id| exact_container_id_text(id))
            .ok_or_else(engine_resource_mismatch)?;
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await?;
        Ok(id)
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
    ) -> Result<LifecycleTopology, LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let mut present_services = 0_usize;
        for service in ["postgres", "rustfs", "automata", "engine-relay", "runner"] {
            let name = format!("{}-{service}-1", installation.compose_project());
            if self.inspect_container(&name).await?.is_some() {
                present_services += 1;
            }
        }
        let mut present_oneoffs = 0_usize;
        for service in ["object-store-init", "bootstrap-runner", "runner-enroll"] {
            if self
                .inspect_container(&lifecycle_oneoff_name(installation, service)?)
                .await?
                .is_some()
            {
                present_oneoffs += 1;
            }
        }
        let transit = self
            .inspect_network_exact(&results_transit_name(installation))
            .await?;
        if let Some(network) = &transit {
            validate_results_transit(network, installation, desired, false)?;
        }
        let control = self
            .inspect_network_exact(&format!("{}-control", installation.compose_project()))
            .await?;
        let egress = self
            .inspect_network_exact(&format!("{}-egress", installation.compose_project()))
            .await?;
        if present_services == 0
            && present_oneoffs == 0
            && transit.is_none()
            && control.is_none()
            && egress.is_none()
        {
            return Ok(LifecycleTopology::Empty);
        }
        if present_services == 5
            && present_oneoffs == 0
            && transit.is_some()
            && control.is_some()
            && egress.is_some()
        {
            let transit_id = transit
                .and_then(|network| network.id)
                .filter(|id| exact_container_id_text(id))
                .ok_or_else(engine_resource_mismatch)?;
            self.attest_running_lifecycle(installation, epoch, desired, &transit_id)
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

    pub(in crate::init) async fn remove_results_transit(
        &self,
        installation: &Installation,
        desired: &DesiredSpec,
        expected_id: &str,
    ) -> Result<(), LocalInitError> {
        let _network = self
            .attest_results_transit(installation, desired, expected_id, true)
            .await?;
        let name = results_transit_name(installation);
        let _untrusted =
            tokio::time::timeout(ENGINE_TIMEOUT, self.docker.remove_network(&name)).await;
        if self.inspect_network_exact(&name).await?.is_some() {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await
    }

    async fn inspect_network_exact(
        &self,
        name: &str,
    ) -> Result<Option<NetworkInspect>, LocalInitError> {
        match tokio::time::timeout(ENGINE_TIMEOUT, self.docker.inspect_network(name, None)).await {
            Ok(Ok(network)) => Ok(Some(network)),
            Ok(Err(error)) if not_found(&error) => Ok(None),
            _ => Err(LocalInitError::new(LocalInitErrorCode::EngineUnavailable)),
        }
    }

    /// Removes any exact prior instance of a lifecycle one-off so a replay can
    /// issue the same idempotent operation without name ambiguity.
    pub(in crate::init) async fn reconcile_lifecycle_oneoff(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        desired: &DesiredSpec,
        service: &'static str,
    ) -> Result<(), LocalInitError> {
        let name = lifecycle_oneoff_name(installation, service)?;
        let Some(container) = self.inspect_container(&name).await? else {
            return Ok(());
        };
        let id = exact_container_id(&container)?.to_owned();
        self.validate_lifecycle_oneoff(&container, &id, installation, epoch, desired, service)
            .await?;
        self.wait_lifecycle_oneoff(&id).await?;
        self.remove_lifecycle_oneoff_and_prove_absent(&name, &id)
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
        service: &'static str,
    ) -> Result<Vec<u8>, LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let name = lifecycle_oneoff_name(installation, service)?;
        let container = self
            .inspect_container(&name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        let id = exact_container_id(&container)?.to_owned();
        self.validate_lifecycle_oneoff(&container, &id, installation, epoch, desired, service)
            .await?;
        let status = self.wait_lifecycle_oneoff(&id).await?;
        let stopped = self
            .inspect_container(&id)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        self.validate_lifecycle_oneoff(&stopped, &id, installation, epoch, desired, service)
            .await?;
        let logs = self.lifecycle_oneoff_logs(&id).await?;
        let cleanup = self
            .remove_lifecycle_oneoff_and_prove_absent(&name, &id)
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

    async fn validate_lifecycle_oneoff(
        &self,
        container: &bollard::models::ContainerInspectResponse,
        id: &str,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        desired: &DesiredSpec,
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
        validate_lifecycle_oneoff_container(
            container,
            id,
            &name,
            &image.inspection_reference,
            &image.image_id,
            installation,
            desired,
            contract,
        )
    }

    async fn wait_lifecycle_oneoff(&self, id: &str) -> Result<i64, LocalInitError> {
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

    async fn lifecycle_oneoff_logs(&self, id: &str) -> Result<Vec<u8>, LocalInitError> {
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

    async fn remove_lifecycle_oneoff_and_prove_absent(
        &self,
        name: &str,
        id: &str,
    ) -> Result<(), LocalInitError> {
        let options = RemoveContainerOptionsBuilder::default()
            .force(true)
            .v(false)
            .build();
        let _untrusted = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.remove_container(id, Some(options)),
        )
        .await;
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
        service: &'static str,
    ) -> Result<String, LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let contract = lifecycle_service_contract(service)?;
        let name = format!("{}-{service}-1", installation.compose_project());
        let container = self
            .inspect_container(&name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        let id = exact_container_id(&container)?.to_owned();
        let image = self
            .inspect_epoch_images(epoch)
            .await?
            .into_iter()
            .find(|image| image.role == contract.image_role)
            .ok_or_else(engine_resource_mismatch)?;
        validate_lifecycle_service_container(
            &container,
            &id,
            &name,
            &image.inspection_reference,
            &image.image_id,
            installation,
            desired,
            contract,
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
        transit_id: &str,
    ) -> Result<(), LocalInitError> {
        for service in ["postgres", "rustfs", "automata", "engine-relay", "runner"] {
            self.attest_lifecycle_service(installation, epoch, desired, service)
                .await?;
        }
        self.attest_results_transit(installation, desired, transit_id, false)
            .await?;
        self.attest_control_network(installation, desired).await?;
        self.attest_egress_network(installation, desired).await?;
        Ok(())
    }

    async fn attest_control_network(
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

    async fn attest_egress_network(
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

#[derive(Clone, Copy)]
struct LifecycleOneoffContract {
    service: &'static str,
    resource_kind: &'static str,
    image_role: &'static str,
    mounts: &'static [(VolumeRole, &'static str, bool)],
}

#[derive(Clone, Copy)]
struct LifecycleServiceContract {
    service: &'static str,
    resource_kind: &'static str,
    image_role: &'static str,
    user: &'static str,
    mounts: &'static [(VolumeRole, &'static str, bool)],
    control_host: Option<u32>,
    egress_host: Option<u32>,
    transit: bool,
    healthy: bool,
}

fn lifecycle_service_contract(
    service: &'static str,
) -> Result<LifecycleServiceContract, LocalInitError> {
    let contract = match service {
        "postgres" => LifecycleServiceContract {
            service,
            resource_kind: "postgres",
            image_role: "postgres",
            user: "999:999",
            mounts: &[
                (
                    VolumeRole::PostgresConfig,
                    "/run/automata-local/postgres",
                    true,
                ),
                (VolumeRole::PostgresData, "/var/lib/postgresql", false),
            ],
            control_host: Some(20),
            egress_host: None,
            transit: false,
            healthy: true,
        },
        "rustfs" => LifecycleServiceContract {
            service,
            resource_kind: "object-store",
            image_role: "rustfs",
            user: "10001:10001",
            mounts: &[
                (VolumeRole::ObjectData, "/data", false),
                (VolumeRole::RustfsConfig, "/run/automata-rustfs", true),
            ],
            control_host: Some(30),
            egress_host: None,
            transit: false,
            healthy: true,
        },
        "automata" => LifecycleServiceContract {
            service,
            resource_kind: "control-plane",
            image_role: "automata",
            user: "65532:65532",
            mounts: &[(VolumeRole::ControlMaterial, "/run/automata-control", true)],
            control_host: Some(10),
            egress_host: None,
            transit: true,
            healthy: true,
        },
        "engine-relay" => LifecycleServiceContract {
            service,
            resource_kind: "engine-relay",
            image_role: "automata",
            user: "0:0",
            mounts: &[
                (VolumeRole::EngineRelay, "/run/automata-engine", false),
                (
                    VolumeRole::RelayBinding,
                    "/run/automata-engine-binding",
                    true,
                ),
            ],
            control_host: None,
            egress_host: None,
            transit: false,
            healthy: true,
        },
        "runner" => LifecycleServiceContract {
            service,
            resource_kind: "runner",
            image_role: "runner",
            user: "65532:65532",
            mounts: &[
                (VolumeRole::EngineRelay, "/run/automata-engine", true),
                (
                    VolumeRole::RunnerConfig,
                    "/run/automata-runner-config",
                    true,
                ),
                (VolumeRole::RunnerData, "/var/lib/automata-runner", false),
                (
                    VolumeRole::RunnerSecrets,
                    "/run/automata-runner-secrets",
                    true,
                ),
            ],
            control_host: Some(40),
            egress_host: Some(20),
            transit: false,
            healthy: true,
        },
        _ => return Err(engine_resource_mismatch()),
    };
    Ok(contract)
}

fn lifecycle_oneoff_contract(
    service: &'static str,
) -> Result<LifecycleOneoffContract, LocalInitError> {
    let contract = match service {
        "object-store-init" => LifecycleOneoffContract {
            service,
            resource_kind: "object-store-init",
            image_role: "automata",
            mounts: &[(VolumeRole::ControlMaterial, "/run/automata-control", true)],
        },
        "bootstrap-runner" => LifecycleOneoffContract {
            service,
            resource_kind: "bootstrap-runner",
            image_role: "automata",
            mounts: &[
                (VolumeRole::BootstrapState, "/run/automata-bootstrap", false),
                (VolumeRole::ControlMaterial, "/run/automata-control", true),
            ],
        },
        "runner-enroll" => LifecycleOneoffContract {
            service,
            resource_kind: "runner-enroll",
            image_role: "runner",
            mounts: &[
                (VolumeRole::BootstrapState, "/run/automata-bootstrap", true),
                (
                    VolumeRole::RunnerConfig,
                    "/run/automata-runner-config",
                    true,
                ),
                (VolumeRole::RunnerData, "/var/lib/automata-runner", false),
            ],
        },
        _ => return Err(engine_resource_mismatch()),
    };
    Ok(contract)
}

fn lifecycle_oneoff_name(
    installation: &Installation,
    service: &'static str,
) -> Result<String, LocalInitError> {
    lifecycle_oneoff_contract(service)?;
    Ok(format!("{}-{service}", installation.compose_project()))
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn validate_lifecycle_oneoff_container(
    container: &bollard::models::ContainerInspectResponse,
    id: &str,
    name: &str,
    image_reference: &str,
    image_id: &str,
    installation: &Installation,
    desired: &DesiredSpec,
    contract: LifecycleOneoffContract,
) -> Result<(), LocalInitError> {
    let config = container
        .config
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let host = container
        .host_config
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
    let expected_managed = BTreeMap::from([
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
        (
            LABEL_RESOURCE_KIND.to_owned(),
            contract.resource_kind.to_owned(),
        ),
    ]);
    if container.id.as_deref() != Some(id)
        || !exact_container_id_text(id)
        || container.name.as_deref() != Some(format!("/{name}").as_str())
        || container.image.as_deref() != Some(image_id)
        || config.image.as_deref() != Some(image_reference)
        || config.user.as_deref() != Some("65532:65532")
        || config.working_dir.as_deref() != Some("/")
        || config.attach_stdin != Some(false)
        || config.attach_stdout != Some(false)
        || config.attach_stderr != Some(false)
        || config.open_stdin != Some(false)
        || config.tty != Some(false)
        || managed != expected_managed
        || labels.get("com.docker.compose.project")
            != Some(&installation.compose_project().to_string())
        || labels.get("com.docker.compose.service").map(String::as_str) != Some(contract.service)
        || labels.get("com.docker.compose.oneoff").map(String::as_str) != Some("True")
        || host.readonly_rootfs != Some(true)
        || host.privileged != Some(false)
        || host.cap_drop.as_deref() != Some(["ALL".to_owned()].as_slice())
        || host.cap_add.as_ref().is_some_and(|caps| !caps.is_empty())
        || host.auto_remove != Some(false)
        || host
            .security_opt
            .as_deref()
            .is_none_or(|options| options != ["no-new-privileges:true"])
    {
        return Err(engine_resource_mismatch());
    }
    let volume_names = volume_names(installation);
    let expected_mounts = contract
        .mounts
        .iter()
        .map(|(role, destination, read_only)| {
            Ok((
                volume_names
                    .get(role)
                    .ok_or_else(engine_resource_mismatch)?
                    .clone(),
                (*destination).to_owned(),
                !*read_only,
            ))
        })
        .collect::<Result<BTreeSet<_>, LocalInitError>>()?;
    let realized = container
        .mounts
        .as_deref()
        .ok_or_else(engine_resource_mismatch)?;
    let mut actual_mounts = BTreeSet::new();
    for mount in realized {
        if mount.typ.as_deref() != Some("volume")
            || mount.driver.as_deref() != Some("local")
            || !actual_mounts.insert((
                mount.name.clone().ok_or_else(engine_resource_mismatch)?,
                mount
                    .destination
                    .clone()
                    .ok_or_else(engine_resource_mismatch)?,
                mount.rw.ok_or_else(engine_resource_mismatch)?,
            ))
        {
            return Err(engine_resource_mismatch());
        }
    }
    if actual_mounts != expected_mounts {
        return Err(engine_resource_mismatch());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn validate_lifecycle_service_container(
    container: &bollard::models::ContainerInspectResponse,
    id: &str,
    name: &str,
    image_reference: &str,
    image_id: &str,
    installation: &Installation,
    desired: &DesiredSpec,
    contract: LifecycleServiceContract,
) -> Result<(), LocalInitError> {
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
    let mut expected_managed = BTreeMap::from([
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
        (
            LABEL_RESOURCE_KIND.to_owned(),
            contract.resource_kind.to_owned(),
        ),
    ]);
    if contract.service == "runner" {
        expected_managed.extend([
            (
                "io.automata.local.max-parallel-jobs".to_owned(),
                desired.max_parallel_jobs().to_string(),
            ),
            (
                "io.automata.local.profile-id".to_owned(),
                desired.profile().attestation().id().to_string(),
            ),
            (
                "io.automata.local.profile-manifest-sha256".to_owned(),
                desired.profile().attestation().digest().to_string(),
            ),
        ]);
    }
    let health_exact = if contract.healthy {
        state.health.as_ref().and_then(|health| health.status)
            == Some(bollard::models::HealthStatusEnum::HEALTHY)
    } else {
        state.health.is_none()
    };
    let cap_add_exact = if contract.service == "engine-relay" {
        host.cap_add.as_deref()
            == Some(
                [
                    "SETGID".to_owned(),
                    "SETUID".to_owned(),
                    "SETPCAP".to_owned(),
                ]
                .as_slice(),
            )
    } else {
        host.cap_add.as_ref().is_none_or(Vec::is_empty)
    };
    if container.id.as_deref() != Some(id)
        || !exact_container_id_text(id)
        || container.name.as_deref() != Some(format!("/{name}").as_str())
        || container.image.as_deref() != Some(image_id)
        || config.image.as_deref() != Some(image_reference)
        || config.user.as_deref() != Some(contract.user)
        || config.working_dir.as_deref() != Some("/")
        || managed != expected_managed
        || labels.get("com.docker.compose.project")
            != Some(&installation.compose_project().to_string())
        || labels.get("com.docker.compose.service").map(String::as_str) != Some(contract.service)
        || labels.get("com.docker.compose.oneoff").map(String::as_str) != Some("False")
        || host.readonly_rootfs != Some(true)
        || host.privileged != Some(false)
        || host.cap_drop.as_deref() != Some(["ALL".to_owned()].as_slice())
        || !cap_add_exact
        || host.auto_remove != Some(false)
        || host.restart_policy.as_ref().and_then(|policy| policy.name)
            != Some(RestartPolicyNameEnum::UNLESS_STOPPED)
        || host
            .security_opt
            .as_deref()
            .is_none_or(|options| options != ["no-new-privileges:true"])
        || state.running != Some(true)
        || !health_exact
    {
        return Err(engine_resource_mismatch());
    }
    let volume_names = volume_names(installation);
    let expected_mounts = contract
        .mounts
        .iter()
        .map(|(role, destination, read_only)| {
            Ok((
                volume_names
                    .get(role)
                    .ok_or_else(engine_resource_mismatch)?
                    .clone(),
                (*destination).to_owned(),
                !*read_only,
            ))
        })
        .collect::<Result<BTreeSet<_>, LocalInitError>>()?;
    let mut actual_mounts = BTreeSet::new();
    let mut host_socket = false;
    for mount in container
        .mounts
        .as_deref()
        .ok_or_else(engine_resource_mismatch)?
    {
        if mount.typ.as_deref() == Some("bind")
            && contract.service == "engine-relay"
            && mount.source.as_deref() == Some("/var/run/docker.sock")
            && mount.destination.as_deref() == Some("/run/automata-host-engine/docker.sock")
            && mount.rw == Some(false)
            && !host_socket
        {
            host_socket = true;
            continue;
        }
        if mount.typ.as_deref() != Some("volume")
            || mount.driver.as_deref() != Some("local")
            || !actual_mounts.insert((
                mount.name.clone().ok_or_else(engine_resource_mismatch)?,
                mount
                    .destination
                    .clone()
                    .ok_or_else(engine_resource_mismatch)?,
                mount.rw.ok_or_else(engine_resource_mismatch)?,
            ))
        {
            return Err(engine_resource_mismatch());
        }
    }
    if actual_mounts != expected_mounts || host_socket != (contract.service == "engine-relay") {
        return Err(engine_resource_mismatch());
    }
    let actual_networks = network
        .networks
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    if let Some(host) = contract.control_host {
        let control_name = format!("{}-control", installation.compose_project());
        let endpoint = actual_networks
            .get(&control_name)
            .ok_or_else(engine_resource_mismatch)?;
        if endpoint.ip_address.as_deref()
            != Some(
                crate::desired_spec::control_subnet_for_spec(desired)
                    .address(host)
                    .to_string()
                    .as_str(),
            )
            || endpoint.gw_priority.unwrap_or_default() != 0
        {
            return Err(engine_resource_mismatch());
        }
    }
    if let Some(host) = contract.egress_host {
        let egress_name = format!("{}-egress", installation.compose_project());
        let endpoint = actual_networks
            .get(&egress_name)
            .ok_or_else(engine_resource_mismatch)?;
        if endpoint.ip_address.as_deref()
            != Some(
                crate::desired_spec::egress_subnet_for_spec(desired)
                    .address(host)
                    .to_string()
                    .as_str(),
            )
            || endpoint.gw_priority != Some(100)
        {
            return Err(engine_resource_mismatch());
        }
    }
    let expected_network_count = usize::from(contract.control_host.is_some())
        + usize::from(contract.egress_host.is_some())
        + usize::from(contract.transit);
    if contract.transit {
        let transit_name = results_transit_name(installation);
        let endpoint = actual_networks
            .get(&transit_name)
            .ok_or_else(engine_resource_mismatch)?;
        if endpoint.ip_address.as_deref()
            != Some(
                desired
                    .results_transit()
                    .results_address()
                    .to_string()
                    .as_str(),
            )
            || endpoint.gw_priority.unwrap_or_default() != 0
        {
            return Err(engine_resource_mismatch());
        }
    }
    if actual_networks.len() != expected_network_count {
        return Err(engine_resource_mismatch());
    }
    Ok(())
}

fn validate_egress_network(
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

fn validate_control_network(
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

pub(super) fn lifecycle_lock_name(installation: &Installation) -> String {
    format!("{}-lifecycle-lock", installation.compose_project())
}

pub(super) fn lifecycle_lock_binding(
    installation: &Installation,
    state_authority_sha256: Sha256Digest,
    intent: &LifecycleIntent,
) -> Result<LifecycleLockBinding, LocalInitError> {
    let labels = lifecycle_lock_labels(installation, state_authority_sha256, intent);
    Ok(LifecycleLockBinding {
        name: lifecycle_lock_name(installation),
        labels_sha256: lock_labels_digest(&labels)?,
    })
}

fn lifecycle_lock_labels(
    installation: &Installation,
    state_authority_sha256: Sha256Digest,
    intent: &LifecycleIntent,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        (LABEL_MANAGED.to_owned(), "true".to_owned()),
        (LABEL_LOCK_SCHEMA.to_owned(), LOCK_SCHEMA.to_owned()),
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
        (
            LABEL_EPOCH.to_owned(),
            intent.epoch_fingerprint().to_string(),
        ),
        (LABEL_PLAN.to_owned(), intent.plan_sha256().to_string()),
        (LABEL_RESOURCE_KIND.to_owned(), LOCK_KIND.to_owned()),
        (
            LABEL_STATE_AUTHORITY.to_owned(),
            state_authority_sha256.to_string(),
        ),
        (
            LABEL_OPERATION_KIND.to_owned(),
            match intent.operation_kind() {
                LifecycleOperationKind::Up => "up",
                LifecycleOperationKind::Down => "down",
            }
            .to_owned(),
        ),
        (
            LABEL_OPERATION_ID.to_owned(),
            intent.operation_id().to_string(),
        ),
        (
            LABEL_INTENT.to_owned(),
            intent.prepared_intent_sha256().to_string(),
        ),
    ])
}

fn validate_lifecycle_lock(
    volume: &Volume,
    name: &str,
    expected_labels: &BTreeMap<String, String>,
) -> Result<(), LocalInitError> {
    let labels = volume
        .labels
        .clone()
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    if volume.name != name
        || volume.driver != "local"
        || volume.scope.as_ref().map(ToString::to_string).as_deref() != Some("local")
        || !volume.options.is_empty()
        || &labels != expected_labels
    {
        return Err(engine_resource_mismatch());
    }
    Ok(())
}

fn lock_labels_digest(labels: &BTreeMap<String, String>) -> Result<Sha256Digest, LocalInitError> {
    let bytes = serde_json::to_vec(labels).map_err(|_| engine_resource_mismatch())?;
    let mut hasher = Sha256::new();
    hasher.update(LOCK_LABEL_DIGEST_DOMAIN);
    hasher.update(
        u32::try_from(bytes.len())
            .expect("closed lifecycle labels fit u32")
            .to_be_bytes(),
    );
    hasher.update(bytes);
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

fn desired_reader_labels(
    installation: &Installation,
    epoch_fingerprint: Sha256Digest,
) -> BTreeMap<String, String> {
    BTreeMap::from([
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
        (LABEL_EPOCH.to_owned(), epoch_fingerprint.to_string()),
        (
            LABEL_RESOURCE_KIND.to_owned(),
            DESIRED_READER_KIND.to_owned(),
        ),
    ])
}

fn desired_reader_body(
    image: &str,
    desired_volume: &str,
    labels: &BTreeMap<String, String>,
) -> ContainerCreateBody {
    ContainerCreateBody {
        user: Some("65532:65532".to_owned()),
        attach_stdin: Some(false),
        attach_stdout: Some(false),
        attach_stderr: Some(false),
        tty: Some(false),
        open_stdin: Some(false),
        stdin_once: Some(false),
        env: Some(Vec::new()),
        cmd: Some(vec![
            "internal".to_owned(),
            "local".to_owned(),
            "read-desired".to_owned(),
        ]),
        image: Some(image.to_owned()),
        working_dir: Some("/".to_owned()),
        entrypoint: Some(vec!["/usr/local/bin/automata".to_owned()]),
        network_disabled: Some(true),
        labels: Some(labels.clone().into_iter().collect()),
        stop_signal: Some("SIGKILL".to_owned()),
        stop_timeout: Some(0),
        host_config: Some(HostConfig {
            memory: Some(HELPER_MEMORY_BYTES),
            memory_swap: Some(HELPER_MEMORY_BYTES),
            nano_cpus: Some(HELPER_NANO_CPUS),
            pids_limit: Some(HELPER_PIDS),
            init: Some(false),
            mounts: Some(vec![Mount {
                target: Some("/run/automata-desired".to_owned()),
                source: Some(desired_volume.to_owned()),
                typ: Some(MountType::VOLUME),
                read_only: Some(true),
                volume_options: Some(MountVolumeOptions {
                    no_copy: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            cap_add: Some(Vec::new()),
            cap_drop: Some(vec!["ALL".to_owned()]),
            network_mode: Some("none".to_owned()),
            restart_policy: Some(RestartPolicy {
                name: Some(RestartPolicyNameEnum::NO),
                maximum_retry_count: Some(0),
            }),
            auto_remove: Some(false),
            cgroupns_mode: Some(HostConfigCgroupnsModeEnum::PRIVATE),
            ipc_mode: Some("private".to_owned()),
            readonly_rootfs: Some(true),
            security_opt: Some(helper_security_options()),
            masked_paths: Some(helper_masked_paths()),
            readonly_paths: Some(helper_readonly_paths()),
            log_config: Some(helper_log_config()),
            runtime: Some("runc".to_owned()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

const fn cas_volume_role(target: CasTarget) -> VolumeRole {
    match target {
        CasTarget::BootstrapRequest | CasTarget::BootstrapToken => VolumeRole::BootstrapState,
        CasTarget::RelayBinding => VolumeRole::RelayBinding,
        CasTarget::RunnerConfig => VolumeRole::RunnerConfig,
        CasTarget::RunnerS3AccessKey
        | CasTarget::RunnerS3Ca
        | CasTarget::RunnerS3SecretKey
        | CasTarget::RunnerSpoolKey => VolumeRole::RunnerSecrets,
    }
}

const fn cas_writer_user(target: CasTarget) -> &'static str {
    match target {
        CasTarget::RelayBinding | CasTarget::RunnerConfig => "0:0",
        CasTarget::BootstrapRequest
        | CasTarget::BootstrapToken
        | CasTarget::RunnerS3AccessKey
        | CasTarget::RunnerS3Ca
        | CasTarget::RunnerS3SecretKey
        | CasTarget::RunnerSpoolKey => "65532:65532",
    }
}

fn cas_writer_labels(
    installation: &Installation,
    epoch: &ImmutableEpoch,
    request: &CasRequest,
) -> BTreeMap<String, String> {
    BTreeMap::from([
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
        (LABEL_EPOCH.to_owned(), epoch.fingerprint().to_string()),
        (
            LABEL_PLAN.to_owned(),
            epoch
                .desired_plan_sha256()
                .expect("lifecycle CAS requires epoch v2")
                .to_string(),
        ),
        (LABEL_RESOURCE_KIND.to_owned(), CAS_WRITER_KIND.to_owned()),
        (
            "io.automata.local.cas-target".to_owned(),
            request.target().slug().to_owned(),
        ),
        (
            "io.automata.local.cas-expected-sha256".to_owned(),
            request
                .expected_sha256()
                .map_or_else(|| "absent".to_owned(), |digest| digest.to_string()),
        ),
        (
            "io.automata.local.cas-replacement-sha256".to_owned(),
            request.replacement_sha256().to_string(),
        ),
    ])
}

fn cas_writer_body(
    image: &str,
    volume_name: &str,
    user: &str,
    cap_add: &[String],
    labels: &BTreeMap<String, String>,
) -> ContainerCreateBody {
    ContainerCreateBody {
        user: Some(user.to_owned()),
        attach_stdin: Some(true),
        attach_stdout: Some(false),
        attach_stderr: Some(false),
        tty: Some(false),
        open_stdin: Some(true),
        stdin_once: Some(true),
        env: Some(Vec::new()),
        cmd: Some(vec![
            "internal".to_owned(),
            "local".to_owned(),
            "write-cas".to_owned(),
        ]),
        image: Some(image.to_owned()),
        working_dir: Some("/".to_owned()),
        entrypoint: Some(vec!["/usr/local/bin/automata".to_owned()]),
        network_disabled: Some(true),
        labels: Some(labels.clone().into_iter().collect()),
        stop_signal: Some("SIGKILL".to_owned()),
        stop_timeout: Some(0),
        host_config: Some(HostConfig {
            memory: Some(HELPER_MEMORY_BYTES),
            memory_swap: Some(HELPER_MEMORY_BYTES),
            nano_cpus: Some(HELPER_NANO_CPUS),
            pids_limit: Some(HELPER_PIDS),
            init: Some(false),
            mounts: Some(vec![Mount {
                target: Some(CAS_MOUNT.to_owned()),
                source: Some(volume_name.to_owned()),
                typ: Some(MountType::VOLUME),
                read_only: Some(false),
                volume_options: Some(MountVolumeOptions {
                    no_copy: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            cap_add: Some(cap_add.to_vec()),
            cap_drop: Some(vec!["ALL".to_owned()]),
            network_mode: Some("none".to_owned()),
            restart_policy: Some(RestartPolicy {
                name: Some(RestartPolicyNameEnum::NO),
                maximum_retry_count: Some(0),
            }),
            auto_remove: Some(false),
            cgroupns_mode: Some(HostConfigCgroupnsModeEnum::PRIVATE),
            ipc_mode: Some("private".to_owned()),
            readonly_rootfs: Some(true),
            security_opt: Some(helper_security_options()),
            masked_paths: Some(helper_masked_paths()),
            readonly_paths: Some(helper_readonly_paths()),
            log_config: Some(helper_log_config()),
            runtime: Some("runc".to_owned()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_cas_writer(
    container: &bollard::models::ContainerInspectResponse,
    id: &str,
    name: &str,
    image: &str,
    image_id: &str,
    volume_name: &str,
    user: &str,
    cap_add: &[String],
    labels: &BTreeMap<String, String>,
) -> Result<(), LocalInitError> {
    let config = container
        .config
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let host = container
        .host_config
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let network = container
        .network_settings
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let managed = config
        .labels
        .as_ref()
        .into_iter()
        .flatten()
        .filter(|(key, _)| key.starts_with("io.automata.local."))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let expected_mount = Mount {
        target: Some(CAS_MOUNT.to_owned()),
        source: Some(volume_name.to_owned()),
        typ: Some(MountType::VOLUME),
        read_only: Some(false),
        volume_options: Some(MountVolumeOptions {
            no_copy: Some(true),
            ..Default::default()
        }),
        ..Default::default()
    };
    if container.id.as_deref() != Some(id)
        || !exact_container_id_text(id)
        || container.name.as_deref() != Some(format!("/{name}").as_str())
        || container.image.as_deref() != Some(image_id)
        || config.image.as_deref() != Some(image)
        || config.user.as_deref() != Some(user)
        || config.entrypoint.as_deref() != Some(["/usr/local/bin/automata".to_owned()].as_slice())
        || config.cmd.as_deref()
            != Some(
                [
                    "internal".to_owned(),
                    "local".to_owned(),
                    "write-cas".to_owned(),
                ]
                .as_slice(),
            )
        || config.working_dir.as_deref() != Some("/")
        || config.attach_stdin != Some(true)
        || config.attach_stdout != Some(false)
        || config.attach_stderr != Some(false)
        || config.open_stdin != Some(true)
        || config.stdin_once != Some(true)
        || config.tty != Some(false)
        || config.network_disabled != Some(true)
        || config.env.as_ref().is_none_or(|env| !env.is_empty())
        || managed != *labels
        || host.mounts.as_deref() != Some([expected_mount].as_slice())
        || host.readonly_rootfs != Some(true)
        || host.network_mode.as_deref() != Some("none")
        || host.cap_drop.as_deref() != Some(["ALL".to_owned()].as_slice())
        || host.cap_add.as_deref() != Some(cap_add)
        || host.auto_remove != Some(false)
        || network
            .networks
            .as_ref()
            .is_some_and(|networks| !networks.is_empty())
    {
        return Err(engine_resource_mismatch());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_desired_reader(
    container: &bollard::models::ContainerInspectResponse,
    id: &str,
    name: &str,
    image: &str,
    image_id: &str,
    desired_volume: &str,
    labels: &BTreeMap<String, String>,
) -> Result<(), LocalInitError> {
    let config = container
        .config
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let host = container
        .host_config
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let managed = config
        .labels
        .as_ref()
        .into_iter()
        .flatten()
        .filter(|(key, _)| key.starts_with("io.automata.local."))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let expected_mount = Mount {
        target: Some("/run/automata-desired".to_owned()),
        source: Some(desired_volume.to_owned()),
        typ: Some(MountType::VOLUME),
        read_only: Some(true),
        volume_options: Some(MountVolumeOptions {
            no_copy: Some(true),
            ..Default::default()
        }),
        ..Default::default()
    };
    if container.id.as_deref() != Some(id)
        || !exact_container_id_text(id)
        || container.name.as_deref() != Some(format!("/{name}").as_str())
        || container.image.as_deref() != Some(image_id)
        || config.image.as_deref() != Some(image)
        || config.user.as_deref() != Some("65532:65532")
        || config.entrypoint.as_deref() != Some(["/usr/local/bin/automata".to_owned()].as_slice())
        || config.cmd.as_deref()
            != Some(
                [
                    "internal".to_owned(),
                    "local".to_owned(),
                    "read-desired".to_owned(),
                ]
                .as_slice(),
            )
        || config.network_disabled != Some(true)
        || managed != *labels
        || host.mounts.as_deref() != Some([expected_mount].as_slice())
        || host.readonly_rootfs != Some(true)
        || host.network_mode.as_deref() != Some("none")
        || host.cap_drop.as_deref() != Some(["ALL".to_owned()].as_slice())
        || host.cap_add.as_ref().is_none_or(|caps| !caps.is_empty())
        || host.auto_remove != Some(false)
    {
        return Err(engine_resource_mismatch());
    }
    Ok(())
}

fn validate_results_transit(
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
        config_from_empty: network.config_from.is_none(),
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
