//! Sealed desired-material reads and exact lifecycle CAS helper transactions.

use super::{
    common::{
        BTreeMap, BTreeSet, CAS_DIGEST_READER_KIND, CAS_MOUNT, CAS_WRITER_KIND, CasDigestRequest,
        CasDigestResponse, CasRequest, CasTarget, ContainerCreateBody,
        CreateContainerOptionsBuilder, DESIRED_READER_KIND, ENGINE_TIMEOUT, HELPER_EXPOSED_PORT,
        HELPER_MEMORY_BYTES, HELPER_NANO_CPUS, HELPER_PIDS, HELPER_SHM_BYTES, HELPER_TIMEOUT,
        HashMap, HelperDriver, HostConfig, HostConfigCgroupnsModeEnum, HostConfigIsolationEnum,
        ImmutableEpoch, InitEngine, Installation, LABEL_COMPOSE_PROJECT, LABEL_EPOCH,
        LABEL_INSTALLATION_ID, LABEL_INSTALLATION_KEY, LABEL_MANAGED, LABEL_PLAN,
        LABEL_RESOURCE_KIND, LocalInitError, LogOutput, LogsOptionsBuilder,
        MAX_LOCAL_DESIRED_SPEC_BYTES, Mount, MountType, MountVolumeOptions,
        RemoveContainerOptionsBuilder, RestartPolicy, RestartPolicyNameEnum, Sha256Digest,
        StreamExt, VolumeRole, WaitContainerOptionsBuilder, engine_resource_mismatch,
        exact_container_id, exact_container_id_text, expected_volume_labels,
        helper_has_ambient_authority, helper_log_config, helper_masked_paths, helper_mounts_match,
        helper_readonly_paths, helper_security_options, validate_volume, volume_name, volume_names,
    },
    lock::LifecycleMutationFence,
};

async fn exact_attachment_set(
    engine: &InitEngine<'_>,
    volume_name: &str,
) -> Result<BTreeSet<String>, LocalInitError> {
    let attachments = engine.volume_attachments(volume_name).await?;
    let mut exact = BTreeSet::new();
    for id in attachments {
        if !exact_container_id_text(&id) || !exact.insert(id) {
            return Err(engine_resource_mismatch());
        }
    }
    Ok(exact)
}

impl InitEngine<'_> {
    /// Reads the sealed canonical Desired bytes through one exact, disposable,
    /// networkless Automata helper and proves the helper absent on every exit.
    pub(in crate::init) async fn read_sealed_desired(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        mutation: &LifecycleMutationFence,
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
        let expected_labels = expected_volume_labels(installation, epoch.fingerprint());
        validate_volume(
            &desired,
            desired_name,
            expected_labels
                .get(&VolumeRole::Desired)
                .ok_or_else(engine_resource_mismatch)?,
        )?;
        let name = format!("{}-desired-reader", installation.compose_project());
        let labels = desired_reader_labels(installation, epoch.fingerprint());
        let mut baseline = exact_attachment_set(self, desired_name).await?;
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
            if !baseline.remove(&id) {
                return Err(engine_resource_mismatch());
            }
            self.remove_desired_reader_and_prove_absent(
                &id,
                &name,
                desired_name,
                &baseline,
                mutation,
            )
            .await?;
        }
        baseline = exact_attachment_set(self, desired_name).await?;
        if exact_attachment_set(self, desired_name).await? != baseline {
            return Err(engine_resource_mismatch());
        }

        let options = CreateContainerOptionsBuilder::default()
            .name(&name)
            .platform("linux/amd64")
            .build();
        let created = mutation
            .run(tokio::time::timeout(
                ENGINE_TIMEOUT,
                self.docker.create_container(
                    Some(options),
                    desired_reader_body(&automata.inspection_reference, desired_name, &labels),
                ),
            ))
            .await?;
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
                &baseline,
                mutation,
            )
            .await;
        let cleanup = self
            .remove_desired_reader_and_prove_absent(
                &pinned,
                &name,
                desired_name,
                &baseline,
                mutation,
            )
            .await;
        match (operation, cleanup) {
            (Ok(bytes), Ok(())) => Ok(bytes),
            (Err(error), Ok(())) | (_, Err(error)) => Err(error),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn run_desired_reader(
        &self,
        pinned: &str,
        name: &str,
        image: &str,
        image_id: &str,
        desired_volume: &str,
        labels: &BTreeMap<String, String>,
        baseline: &BTreeSet<String>,
        mutation: &LifecycleMutationFence,
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
        let mut expected_attachments = baseline.clone();
        if !expected_attachments.insert(pinned.to_owned())
            || stopped.state.as_ref().and_then(|state| state.running) != Some(false)
            || exact_attachment_set(self, desired_volume).await? != expected_attachments
        {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await?;
        mutation
            .run(tokio::time::timeout(
                ENGINE_TIMEOUT,
                self.docker.start_container(pinned, None),
            ))
            .await?
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

    pub(super) async fn desired_reader_logs(&self, id: &str) -> Result<Vec<u8>, LocalInitError> {
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

    pub(super) async fn remove_desired_reader_and_prove_absent(
        &self,
        id: &str,
        name: &str,
        desired_volume: &str,
        baseline: &BTreeSet<String>,
        mutation: &LifecycleMutationFence,
    ) -> Result<(), LocalInitError> {
        if !exact_container_id_text(id) {
            return Err(engine_resource_mismatch());
        }
        let options = RemoveContainerOptionsBuilder::default()
            .force(true)
            .v(false)
            .link(false)
            .build();
        let _untrusted = mutation
            .run(tokio::time::timeout(
                ENGINE_TIMEOUT,
                self.docker.remove_container(id, Some(options)),
            ))
            .await?;
        if self.inspect_container(id).await?.is_some()
            || self.inspect_container(name).await?.is_some()
            || exact_attachment_set(self, desired_volume).await? != *baseline
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
        mutation: &LifecycleMutationFence,
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
            &expected_volume_labels(installation, epoch.fingerprint())[&role],
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
            self.remove_cas_writer_and_prove_absent(&id, &name, &volume_name, mutation)
                .await?;
        }

        let created = mutation
            .run(self.driver_create(
                &name,
                cas_writer_body(
                    &automata.inspection_reference,
                    &volume_name,
                    user,
                    &cap_add,
                    &labels,
                ),
            ))
            .await?;
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
            let mut input = mutation.run(self.driver_attach(pinned)).await??;
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
            mutation.run(self.driver_start(pinned)).await??;
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
            mutation
                .run(self.driver_send_request(&mut input, &request_bytes))
                .await??;
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
                self.remove_cas_writer_and_prove_absent(id, &name, &volume_name, mutation)
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

    /// Reads the current expected-old digest of one replaceable generated file
    /// through an exact disposable read-only helper.
    pub(in crate::init) async fn read_lifecycle_cas_digest(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        target: CasTarget,
        mutation: &LifecycleMutationFence,
    ) -> Result<Option<Sha256Digest>, LocalInitError> {
        self.read_lifecycle_cas_digest_with_attachments(
            installation,
            epoch,
            target,
            &BTreeSet::new(),
            mutation,
        )
        .await
    }

    /// Reads a lifecycle CAS digest while pinning the exact already-attached
    /// steady service IDs attested by the caller's complete topology census.
    pub(in crate::init) async fn read_lifecycle_cas_digest_with_attachments(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        target: CasTarget,
        expected_attachments: &BTreeSet<String>,
        mutation: &LifecycleMutationFence,
    ) -> Result<Option<Sha256Digest>, LocalInitError> {
        if expected_attachments
            .iter()
            .any(|id| !exact_container_id_text(id))
        {
            return Err(engine_resource_mismatch());
        }
        let request = CasDigestRequest::new(target);
        let target = request.target();
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let automata = self
            .inspect_epoch_images(epoch)
            .await?
            .into_iter()
            .find(|image| image.role == "automata")
            .ok_or_else(engine_resource_mismatch)?;
        let role = cas_volume_role(target);
        let volume_name = volume_name(installation.compose_project().as_str(), role);
        let volume = self
            .inspect_volume(&volume_name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        validate_volume(
            &volume,
            &volume_name,
            &expected_volume_labels(installation, epoch.fingerprint())[&role],
        )?;
        if self
            .volume_attachments(&volume_name)
            .await?
            .into_iter()
            .collect::<BTreeSet<_>>()
            != *expected_attachments
        {
            return Err(engine_resource_mismatch());
        }
        let name = format!(
            "{}-{}-cas-digest",
            installation.compose_project(),
            target.slug()
        );
        let labels = cas_digest_reader_labels(installation, epoch, target);
        if let Some(existing) = self.inspect_container(&name).await? {
            let id = exact_container_id(&existing)?.to_owned();
            validate_cas_digest_reader(
                &existing,
                &id,
                &name,
                &automata.inspection_reference,
                &automata.image_id,
                &volume_name,
                &labels,
            )?;
            self.remove_cas_reader_and_prove_absent(
                &id,
                &name,
                &volume_name,
                expected_attachments,
                mutation,
            )
            .await?;
        }
        let created = mutation
            .run(self.driver_create(
                &name,
                cas_digest_reader_body(&automata.inspection_reference, &volume_name, &labels),
            ))
            .await?;
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
            self.attest_cas_digest_reader(
                pinned,
                &name,
                &automata.inspection_reference,
                &automata.image_id,
                &volume_name,
                &labels,
                expected_attachments,
                false,
            )
            .await?;
            let mut input = mutation.run(self.driver_attach(pinned)).await??;
            self.attest_cas_digest_reader(
                pinned,
                &name,
                &automata.inspection_reference,
                &automata.image_id,
                &volume_name,
                &labels,
                expected_attachments,
                false,
            )
            .await?;
            mutation.run(self.driver_start(pinned)).await??;
            self.attest_cas_digest_reader(
                pinned,
                &name,
                &automata.inspection_reference,
                &automata.image_id,
                &volume_name,
                &labels,
                expected_attachments,
                true,
            )
            .await?;
            let request_bytes = request.canonical_bytes()?;
            mutation
                .run(self.driver_send_request(&mut input, &request_bytes))
                .await??;
            drop(input);
            let wait = self.driver_wait(pinned).await?;
            if wait.status_code != 0 || wait.has_error {
                return Err(engine_resource_mismatch());
            }
            let (stdout, stderr) = self.driver_logs(pinned).await?;
            if !stderr.is_empty() {
                return Err(engine_resource_mismatch());
            }
            let response = CasDigestResponse::from_canonical_bytes(&stdout, target)?;
            self.attest_cas_digest_reader(
                pinned,
                &name,
                &automata.inspection_reference,
                &automata.image_id,
                &volume_name,
                &labels,
                expected_attachments,
                false,
            )
            .await?;
            Ok(response.sha256())
        }
        .await;
        let cleanup = match pinned.as_deref() {
            Some(id) => {
                self.remove_cas_reader_and_prove_absent(
                    id,
                    &name,
                    &volume_name,
                    expected_attachments,
                    mutation,
                )
                .await
            }
            None => match self.inspect_container(&name).await? {
                None => Ok(()),
                Some(_) => Err(engine_resource_mismatch()),
            },
        };
        cleanup?;
        operation
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn attest_cas_digest_reader(
        &self,
        id: &str,
        name: &str,
        image: &str,
        image_id: &str,
        volume_name: &str,
        labels: &BTreeMap<String, String>,
        expected_attachments: &BTreeSet<String>,
        running: bool,
    ) -> Result<(), LocalInitError> {
        let by_id = self
            .inspect_container(id)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        let by_name = self
            .inspect_container(name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        for container in [&by_id, &by_name] {
            validate_cas_digest_reader(container, id, name, image, image_id, volume_name, labels)?;
            if container.state.as_ref().and_then(|state| state.running) != Some(running) {
                return Err(engine_resource_mismatch());
            }
        }
        let mut attached = expected_attachments.clone();
        if !attached.insert(id.to_owned())
            || self
                .volume_attachments(volume_name)
                .await?
                .into_iter()
                .collect::<BTreeSet<_>>()
                != attached
        {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn attest_cas_writer(
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

    pub(super) async fn remove_cas_writer_and_prove_absent(
        &self,
        id: &str,
        name: &str,
        volume_name: &str,
        mutation: &LifecycleMutationFence,
    ) -> Result<(), LocalInitError> {
        if !exact_container_id_text(id) {
            return Err(engine_resource_mismatch());
        }
        let _untrusted = mutation.run(self.driver_force_remove(id)).await?;
        if self.inspect_container(id).await?.is_some()
            || self.inspect_container(name).await?.is_some()
            || !self.volume_attachments(volume_name).await?.is_empty()
        {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await
    }

    pub(super) async fn remove_cas_reader_and_prove_absent(
        &self,
        id: &str,
        name: &str,
        volume_name: &str,
        expected_attachments: &BTreeSet<String>,
        mutation: &LifecycleMutationFence,
    ) -> Result<(), LocalInitError> {
        if !exact_container_id_text(id) {
            return Err(engine_resource_mismatch());
        }
        let _untrusted = mutation.run(self.driver_force_remove(id)).await?;
        if self.inspect_container(id).await?.is_some()
            || self.inspect_container(name).await?.is_some()
            || self
                .volume_attachments(volume_name)
                .await?
                .into_iter()
                .collect::<BTreeSet<_>>()
                != *expected_attachments
        {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await
    }
}

pub(super) fn cas_target_for_slug(slug: &str) -> Option<CasTarget> {
    [
        CasTarget::BootstrapRequest,
        CasTarget::BootstrapToken,
        CasTarget::RelayBinding,
        CasTarget::RunnerConfig,
        CasTarget::RunnerS3AccessKey,
        CasTarget::RunnerS3Ca,
        CasTarget::RunnerS3SecretKey,
        CasTarget::RunnerSpoolKey,
    ]
    .into_iter()
    .find(|target| target.slug() == slug)
}
pub(super) fn desired_reader_labels(
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

pub(super) fn desired_reader_body(
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
            console_size: Some(vec![0, 0]),
            shm_size: Some(HELPER_SHM_BYTES),
            isolation: Some(HostConfigIsolationEnum::EMPTY),
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
            userns_mode: Some("host".to_owned()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

pub(super) const fn cas_volume_role(target: CasTarget) -> VolumeRole {
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

pub(super) const fn cas_writer_user(target: CasTarget) -> &'static str {
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

pub(super) fn cas_writer_labels(
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

pub(super) fn cas_digest_reader_labels(
    installation: &Installation,
    epoch: &ImmutableEpoch,
    target: CasTarget,
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
            LABEL_RESOURCE_KIND.to_owned(),
            CAS_DIGEST_READER_KIND.to_owned(),
        ),
        (
            "io.automata.local.cas-target".to_owned(),
            target.slug().to_owned(),
        ),
    ])
}

pub(super) fn cas_digest_reader_body(
    image: &str,
    volume_name: &str,
    labels: &BTreeMap<String, String>,
) -> ContainerCreateBody {
    ContainerCreateBody {
        user: Some("0:0".to_owned()),
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
            "read-cas-digest".to_owned(),
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
            console_size: Some(vec![0, 0]),
            shm_size: Some(HELPER_SHM_BYTES),
            isolation: Some(HostConfigIsolationEnum::EMPTY),
            init: Some(false),
            mounts: Some(vec![Mount {
                target: Some(CAS_MOUNT.to_owned()),
                source: Some(volume_name.to_owned()),
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
            userns_mode: Some("host".to_owned()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

pub(super) fn fixed_disposable_host_is_exact(
    host: &HostConfig,
    expected_mount: &Mount,
    cap_add: &[String],
) -> bool {
    host.mounts
        .as_deref()
        .is_some_and(|actual| helper_mounts_match(actual, std::slice::from_ref(expected_mount)))
        && host.readonly_rootfs == Some(true)
        && host.network_mode.as_deref() == Some("none")
        && host.cap_drop.as_deref() == Some(["ALL".to_owned()].as_slice())
        && host.cap_add.as_deref() == Some(cap_add)
        && host.auto_remove == Some(false)
        && host.privileged == Some(false)
        && host.init == Some(false)
        && host.memory == Some(HELPER_MEMORY_BYTES)
        && host.memory_swap == Some(HELPER_MEMORY_BYTES)
        && host.nano_cpus == Some(HELPER_NANO_CPUS)
        && host.pids_limit == Some(HELPER_PIDS)
        && host.security_opt.as_deref() == Some(helper_security_options().as_slice())
        && host.masked_paths.as_deref() == Some(helper_masked_paths().as_slice())
        && host.readonly_paths.as_deref() == Some(helper_readonly_paths().as_slice())
        && host.log_config.as_ref() == Some(&helper_log_config())
        && host.binds.as_ref().is_none_or(Vec::is_empty)
        && host.tmpfs.as_ref().is_none_or(HashMap::is_empty)
        && !helper_has_ambient_authority(host)
}

pub(super) fn fixed_disposable_network_is_exact(
    network: &bollard::models::NetworkSettings,
) -> bool {
    network.sandbox_id.as_deref() == Some("")
        && network.sandbox_key.as_deref() == Some("")
        && network.ports.as_ref().is_some_and(HashMap::is_empty)
        && network.networks.as_ref().is_some_and(HashMap::is_empty)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn validate_cas_digest_reader(
    container: &bollard::models::ContainerInspectResponse,
    id: &str,
    name: &str,
    image: &str,
    image_id: &str,
    volume_name: &str,
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
        || container.platform.as_deref() != Some("linux")
        || config.image.as_deref() != Some(image)
        || config.user.as_deref() != Some("0:0")
        || config.entrypoint.as_deref() != Some(["/usr/local/bin/automata".to_owned()].as_slice())
        || config.cmd.as_deref()
            != Some(
                [
                    "internal".to_owned(),
                    "local".to_owned(),
                    "read-cas-digest".to_owned(),
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
        || config.env.as_ref().is_some_and(|env| !env.is_empty())
        || config.stop_signal.as_deref() != Some("SIGKILL")
        || config.stop_timeout != Some(0)
        || config.healthcheck.is_some()
        || config.exposed_ports.as_deref() != Some([HELPER_EXPOSED_PORT.to_owned()].as_slice())
        || config
            .volumes
            .as_ref()
            .is_some_and(|volumes| !volumes.is_empty())
        || config
            .on_build
            .as_ref()
            .is_some_and(|steps| !steps.is_empty())
        || config.shell.as_ref().is_some_and(|shell| !shell.is_empty())
        || managed != *labels
        || host.mounts.as_deref().is_none_or(|actual| {
            !helper_mounts_match(actual, std::slice::from_ref(&expected_mount))
        })
        || host.readonly_rootfs != Some(true)
        || host.network_mode.as_deref() != Some("none")
        || host.cap_drop.as_deref() != Some(["ALL".to_owned()].as_slice())
        || host.cap_add.as_ref().is_none_or(|caps| !caps.is_empty())
        || host.auto_remove != Some(false)
        || host.privileged.unwrap_or(false)
        || helper_has_ambient_authority(host)
        || host.memory != Some(HELPER_MEMORY_BYTES)
        || host.memory_swap != Some(HELPER_MEMORY_BYTES)
        || host.nano_cpus != Some(HELPER_NANO_CPUS)
        || host.pids_limit != Some(HELPER_PIDS)
        || host.security_opt.as_deref() != Some(helper_security_options().as_slice())
        || host.masked_paths.as_deref() != Some(helper_masked_paths().as_slice())
        || host.readonly_paths.as_deref() != Some(helper_readonly_paths().as_slice())
        || host.log_config.as_ref() != Some(&helper_log_config())
        || !fixed_disposable_host_is_exact(host, &expected_mount, &[])
        || !fixed_disposable_network_is_exact(network)
    {
        return Err(engine_resource_mismatch());
    }
    let realized = container
        .mounts
        .as_deref()
        .ok_or_else(engine_resource_mismatch)?;
    if realized.len() != 1
        || realized[0].typ.as_deref() != Some("volume")
        || realized[0].name.as_deref() != Some(volume_name)
        || realized[0].destination.as_deref() != Some(CAS_MOUNT)
        || realized[0].rw != Some(false)
        || realized[0].driver.as_deref() != Some("local")
    {
        return Err(engine_resource_mismatch());
    }
    Ok(())
}

pub(super) fn cas_writer_body(
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
            console_size: Some(vec![0, 0]),
            shm_size: Some(HELPER_SHM_BYTES),
            isolation: Some(HostConfigIsolationEnum::EMPTY),
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
            userns_mode: Some("host".to_owned()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn validate_cas_writer(
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
        || container.platform.as_deref() != Some("linux")
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
        || config.env.as_ref().is_some_and(|env| !env.is_empty())
        || config.stop_signal.as_deref() != Some("SIGKILL")
        || config.stop_timeout != Some(0)
        || config.healthcheck.is_some()
        || config.exposed_ports.as_deref() != Some([HELPER_EXPOSED_PORT.to_owned()].as_slice())
        || config
            .volumes
            .as_ref()
            .is_some_and(|volumes| !volumes.is_empty())
        || config
            .on_build
            .as_ref()
            .is_some_and(|steps| !steps.is_empty())
        || config.shell.as_ref().is_some_and(|shell| !shell.is_empty())
        || managed != *labels
        || host.mounts.as_deref().is_none_or(|actual| {
            !helper_mounts_match(actual, std::slice::from_ref(&expected_mount))
        })
        || host.readonly_rootfs != Some(true)
        || host.network_mode.as_deref() != Some("none")
        || host.cap_drop.as_deref() != Some(["ALL".to_owned()].as_slice())
        || host.cap_add.as_deref() != Some(cap_add)
        || host.auto_remove != Some(false)
        || !fixed_disposable_host_is_exact(host, &expected_mount, cap_add)
        || !fixed_disposable_network_is_exact(network)
    {
        return Err(engine_resource_mismatch());
    }
    let realized = container
        .mounts
        .as_deref()
        .ok_or_else(engine_resource_mismatch)?;
    if realized.len() != 1
        || realized[0].typ.as_deref() != Some("volume")
        || realized[0].name.as_deref() != Some(volume_name)
        || realized[0].destination.as_deref() != Some(CAS_MOUNT)
        || realized[0].rw != Some(true)
        || realized[0].driver.as_deref() != Some("local")
    {
        return Err(engine_resource_mismatch());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn validate_desired_reader(
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
        || container.platform.as_deref() != Some("linux")
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
        || config.working_dir.as_deref() != Some("/")
        || config.attach_stdin != Some(false)
        || config.attach_stdout != Some(false)
        || config.attach_stderr != Some(false)
        || config.open_stdin != Some(false)
        || config.stdin_once != Some(false)
        || config.tty != Some(false)
        || config.network_disabled != Some(true)
        || config.env.as_ref().is_some_and(|env| !env.is_empty())
        || config.stop_signal.as_deref() != Some("SIGKILL")
        || config.stop_timeout != Some(0)
        || config.healthcheck.is_some()
        || config.exposed_ports.as_deref() != Some([HELPER_EXPOSED_PORT.to_owned()].as_slice())
        || config
            .volumes
            .as_ref()
            .is_some_and(|volumes| !volumes.is_empty())
        || config
            .on_build
            .as_ref()
            .is_some_and(|steps| !steps.is_empty())
        || config.shell.as_ref().is_some_and(|shell| !shell.is_empty())
        || managed != *labels
        || host.mounts.as_deref().is_none_or(|actual| {
            !helper_mounts_match(actual, std::slice::from_ref(&expected_mount))
        })
        || host.readonly_rootfs != Some(true)
        || host.network_mode.as_deref() != Some("none")
        || host.cap_drop.as_deref() != Some(["ALL".to_owned()].as_slice())
        || host.cap_add.as_ref().is_none_or(|caps| !caps.is_empty())
        || host.auto_remove != Some(false)
        || !fixed_disposable_host_is_exact(host, &expected_mount, &[])
        || !fixed_disposable_network_is_exact(network)
    {
        return Err(engine_resource_mismatch());
    }
    let realized = container
        .mounts
        .as_deref()
        .ok_or_else(engine_resource_mismatch)?;
    if realized.len() != 1
        || realized[0].typ.as_deref() != Some("volume")
        || realized[0].name.as_deref() != Some(desired_volume)
        || realized[0].destination.as_deref() != Some("/run/automata-desired")
        || realized[0].rw != Some(false)
        || realized[0].driver.as_deref() != Some("local")
    {
        return Err(engine_resource_mismatch());
    }
    Ok(())
}
