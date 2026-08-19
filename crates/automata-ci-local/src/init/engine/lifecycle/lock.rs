//! Engine-backed mutation-lock acquisition, fencing, release, and recovery entry points.

use super::{
    common::{
        Arc, AsyncWrite, AsyncWriteExt, AttachContainerOptionsBuilder, AttachContainerResults,
        BTreeMap, BTreeSet, CancellationToken, ContainerCreateBody, CreateContainerOptionsBuilder,
        DesiredSpec, ENGINE_TIMEOUT, ExpectedLifecycleTopology, Future, HELPER_EXPOSED_PORT,
        HELPER_MEMORY_BYTES, HELPER_NANO_CPUS, HELPER_PIDS, HELPER_SHM_BYTES, HostConfig,
        HostConfigCgroupnsModeEnum, HostConfigIsolationEnum, ImmutableEpoch, InitEngine,
        Installation, JoinHandle, LABEL_COMPOSE_PROJECT, LABEL_ENGINE_BOOT_ID, LABEL_ENGINE_PID,
        LABEL_ENGINE_START_TICKS, LABEL_INSTALLATION_ID, LABEL_INSTALLATION_KEY, LABEL_MANAGED,
        LABEL_OPERATION_ID, LABEL_RESOURCE_KIND, LOCK_KIND, LocalInitError, LocalInitErrorCode,
        Mutex, OperationId, OwnedMutexGuard, Pin, RemoveContainerOptionsBuilder, RestartPolicy,
        RestartPolicyNameEnum, Stream, StreamExt, VolumeRole, WaitContainerOptionsBuilder,
        engine_resource_mismatch, exact_container_id_text, expected_volume_labels,
        helper_has_ambient_authority, helper_log_config, helper_masked_paths,
        helper_readonly_paths, helper_security_options, mpsc, oneshot,
        reset_progress_from_presence, reset_volume_order, validate_volume, volume_labels,
        volume_name, volume_names,
    },
    recovery::{
        EngineDaemonGeneration, current_engine_daemon_generation, daemon_generation_from_labels,
    },
    topology::LifecycleTopology,
};

/// Read-only classification of the deterministic Engine mutation lock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::init) enum LifecycleLockObservation {
    Absent,
    Live {
        id: String,
        operation_id: OperationId,
    },
    Stopped {
        id: String,
        operation_id: OperationId,
    },
}

/// Retained stdin authority for one exact live Engine mutation lock.
///
/// Dropping this value closes stdin and intentionally leaves the resulting
/// stopped container as sticky recovery evidence. Only `release_lifecycle_lock`
/// performs graceful exact-ID removal.
pub(in crate::init) struct LifecycleLockHolder {
    pub(super) name: String,
    pub(super) id: String,
    pub(super) operation_id: OperationId,
    pub(super) labels: BTreeMap<String, String>,
    pub(super) daemon_generation: EngineDaemonGeneration,
    pub(super) input: Option<Pin<Box<dyn AsyncWrite + Send>>>,
    pub(super) holder_lost: CancellationToken,
    pub(super) commands: mpsc::Sender<LifecycleLockCommand>,
    pub(super) mutation_gate: Arc<Mutex<LifecycleMutationGateState>>,
    pub(super) monitor: JoinHandle<Result<(), LocalInitError>>,
}

pub(super) enum LifecycleLockCommand {
    AuthorizeMutation(oneshot::Sender<()>),
    BeginRelease {
        acknowledged: oneshot::Sender<()>,
        frame_sent: oneshot::Receiver<()>,
    },
}

/// One live holder's mandatory per-request mutation capability.
///
/// The attach monitor acknowledges each request boundary only while the
/// holder stream is still pending. Holder loss dominates caller cancellation;
/// after either signal no later Engine or Compose mutation can obtain a
/// permit.
#[derive(Clone)]
pub(in crate::init) struct LifecycleMutationFence {
    pub(super) commands: mpsc::Sender<LifecycleLockCommand>,
    pub(super) holder_lost: CancellationToken,
    pub(super) caller: CancellationToken,
    pub(super) gate: Arc<Mutex<LifecycleMutationGateState>>,
}

#[derive(Debug, Default)]
pub(super) struct LifecycleMutationGateState {
    pub(super) closed: bool,
}

#[must_use = "the lifecycle mutation permit must be retained through the Engine request"]
pub(super) struct LifecycleMutationPermit {
    _gate: OwnedMutexGuard<LifecycleMutationGateState>,
}

impl LifecycleLockHolder {
    /// Cancels as soon as the retained attach stream ends unexpectedly.
    pub(in crate::init) fn holder_lost(&self) -> CancellationToken {
        self.holder_lost.clone()
    }

    pub(in crate::init) fn exact_identity(&self) -> (&str, &str) {
        (&self.name, &self.id)
    }

    pub(in crate::init) fn mutation_fence(
        &self,
        caller: &CancellationToken,
    ) -> LifecycleMutationFence {
        LifecycleMutationFence {
            commands: self.commands.clone(),
            holder_lost: self.holder_lost.clone(),
            caller: caller.clone(),
            gate: Arc::clone(&self.mutation_gate),
        }
    }
}

impl LifecycleMutationFence {
    pub(in crate::init) fn checkpoint(&self) -> Result<(), LocalInitError> {
        if self.holder_lost.is_cancelled() {
            Err(LocalInitError::new(LocalInitErrorCode::ResetRequired))
        } else if self.caller.is_cancelled() {
            Err(LocalInitError::new(LocalInitErrorCode::Cancelled))
        } else {
            Ok(())
        }
    }

    pub(super) async fn authorize(&self) -> Result<LifecycleMutationPermit, LocalInitError> {
        self.checkpoint()?;
        let gate = tokio::select! {
            biased;
            () = self.holder_lost.cancelled() => {
                return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
            }
            () = self.caller.cancelled() => {
                return Err(LocalInitError::new(LocalInitErrorCode::Cancelled));
            }
            gate = Arc::clone(&self.gate).lock_owned() => gate,
        };
        if gate.closed {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        let (acknowledge, acknowledged) = oneshot::channel();
        tokio::select! {
            biased;
            () = self.holder_lost.cancelled() => {
                return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
            }
            () = self.caller.cancelled() => {
                return Err(LocalInitError::new(LocalInitErrorCode::Cancelled));
            }
            result = self.commands.send(LifecycleLockCommand::AuthorizeMutation(acknowledge)) => {
                result.map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;
            }
        }
        tokio::select! {
            biased;
            () = self.holder_lost.cancelled() => {
                Err(LocalInitError::new(LocalInitErrorCode::ResetRequired))
            }
            () = self.caller.cancelled() => {
                Err(LocalInitError::new(LocalInitErrorCode::Cancelled))
            }
            result = acknowledged => {
                result.map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;
                Ok(LifecycleMutationPermit { _gate: gate })
            }
        }
    }

    /// Runs one Engine or Compose mutation while holding the single in-flight
    /// permit authorized by the retained lock-output monitor.
    pub(in crate::init) async fn run<Mutation, Output>(
        &self,
        mutation: Mutation,
    ) -> Result<Output, LocalInitError>
    where
        Mutation: Future<Output = Output>,
    {
        let _permit = self.authorize().await?;
        Ok(mutation.await)
    }
}

pub(super) async fn monitor_lifecycle_lock_output<Output>(
    mut output: Output,
    mut command_requests: mpsc::Receiver<LifecycleLockCommand>,
    holder_lost: CancellationToken,
) -> Result<(), LocalInitError>
where
    Output: Stream + Unpin,
{
    loop {
        let command = tokio::select! {
            biased;
            _unexpected = output.next() => {
                holder_lost.cancel();
                return Err(engine_resource_mismatch());
            }
            command = command_requests.recv() => {
                command.ok_or_else(engine_resource_mismatch)?
            }
        };
        match command {
            LifecycleLockCommand::AuthorizeMutation(acknowledge) => {
                let _ = acknowledge.send(());
            }
            LifecycleLockCommand::BeginRelease {
                acknowledged,
                mut frame_sent,
            } => {
                acknowledged
                    .send(())
                    .map_err(|()| engine_resource_mismatch())?;
                tokio::select! {
                    biased;
                    observed = output.next() => {
                        if observed.is_some() {
                            holder_lost.cancel();
                            return Err(engine_resource_mismatch());
                        }
                        if frame_sent.await.is_err() {
                            holder_lost.cancel();
                            return Err(engine_resource_mismatch());
                        }
                        return Ok(());
                    }
                    confirmation = &mut frame_sent => {
                        if confirmation.is_err() {
                            holder_lost.cancel();
                            return Err(engine_resource_mismatch());
                        }
                    }
                }
                if output.next().await.is_none() {
                    return Ok(());
                }
                holder_lost.cancel();
                return Err(engine_resource_mismatch());
            }
        }
    }
}

impl InitEngine<'_> {
    /// Acquires the deterministic stdin-held Engine mutation lock.
    ///
    /// An existing lock is never adopted, restarted, or automatically removed:
    /// an exact live holder reports contention and an exact stopped holder is
    /// sticky recovery evidence. Unknown configuration fails closed.
    pub(in crate::init) async fn acquire_lifecycle_lock(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        operation_id: OperationId,
    ) -> Result<LifecycleLockHolder, LocalInitError> {
        self.acquire_lifecycle_lock_inner(installation, epoch, operation_id, true)
            .await
    }

    /// Bootstrap acquisition for initialization before the identity anchor is
    /// created. The caller-selected installation UUID is already sealed in the
    /// immutable epoch; every later assertion uses the ordinary identity-bound
    /// lock attestation.
    pub(in crate::init) async fn acquire_lifecycle_lock_before_identity(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        operation_id: OperationId,
    ) -> Result<LifecycleLockHolder, LocalInitError> {
        self.acquire_lifecycle_lock_inner(installation, epoch, operation_id, false)
            .await
    }

    pub(super) async fn acquire_lifecycle_lock_inner(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        operation_id: OperationId,
        require_identity: bool,
    ) -> Result<LifecycleLockHolder, LocalInitError> {
        self.verify_selected_engine().await?;
        if require_identity {
            self.verify_installation(installation).await?;
        }
        let image = lifecycle_lock_image(self, epoch).await?;
        let name = lifecycle_lock_name(installation);
        if let Some(existing) = self.inspect_container(&name).await? {
            return Err(
                match classify_lifecycle_lock(
                    &existing,
                    &name,
                    &image.inspection_reference,
                    &image.image_id,
                    &image.labels,
                    installation,
                )? {
                    LifecycleLockObservation::Live { .. } => {
                        LocalInitError::new(LocalInitErrorCode::OperationInProgress)
                    }
                    LifecycleLockObservation::Stopped { .. } => {
                        LocalInitError::new(LocalInitErrorCode::ResetRequired)
                    }
                    LifecycleLockObservation::Absent => engine_resource_mismatch(),
                },
            );
        }

        let daemon_generation = current_engine_daemon_generation()?;
        let labels = lifecycle_lock_expected_labels(
            &image.labels,
            lifecycle_lock_labels(installation, operation_id, &daemon_generation),
        )?;
        let body = lifecycle_lock_body(&image.inspection_reference, &labels);
        let options = CreateContainerOptionsBuilder::default()
            .name(&name)
            .platform("linux/amd64")
            .build();
        let created = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.create_container(Some(options), body),
        )
        .await;
        let created = match created {
            Ok(Ok(created))
                if exact_container_id_text(&created.id) && created.warnings.is_empty() =>
            {
                created
            }
            _ => {
                return Err(self
                    .classify_lock_collision(installation, epoch, &name)
                    .await?);
            }
        };
        let id = created.id;
        self.attest_lifecycle_lock_exact(
            installation,
            &name,
            &id,
            operation_id,
            &image.inspection_reference,
            &image.image_id,
            &image.labels,
            false,
        )
        .await?;
        if current_engine_daemon_generation()? != daemon_generation {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }

        let attach_options = AttachContainerOptionsBuilder::default()
            .stdin(true)
            .stdout(true)
            .stderr(true)
            .stream(true)
            .logs(false)
            .build();
        let AttachContainerResults { output, input } = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.attach_container(&id, Some(attach_options)),
        )
        .await
        .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?
        .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;

        let holder_lost = CancellationToken::new();
        let (commands, command_requests) = mpsc::channel(1);
        let mutation_gate = Arc::new(Mutex::new(LifecycleMutationGateState::default()));
        let monitor = tokio::spawn(monitor_lifecycle_lock_output(
            output,
            command_requests,
            holder_lost.clone(),
        ));

        let start =
            tokio::time::timeout(ENGINE_TIMEOUT, self.docker.start_container(&id, None)).await;
        if !matches!(start, Ok(Ok(()))) {
            // A successful start response is not trusted, but an ambiguous
            // response may still have started the exact attached container.
            // Fresh exact inspection is the only safe reconciliation.
            let by_id = self
                .inspect_container(&id)
                .await?
                .ok_or_else(|| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;
            if classify_lifecycle_lock(
                &by_id,
                &name,
                &image.inspection_reference,
                &image.image_id,
                &image.labels,
                installation,
            )? != (LifecycleLockObservation::Live {
                id: id.clone(),
                operation_id,
            }) {
                return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
            }
        }
        self.attest_lifecycle_lock_exact(
            installation,
            &name,
            &id,
            operation_id,
            &image.inspection_reference,
            &image.image_id,
            &image.labels,
            true,
        )
        .await?;
        if holder_lost.is_cancelled() {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        if require_identity {
            self.verify_installation(installation).await?;
        }
        self.verify_selected_engine().await?;
        if current_engine_daemon_generation()? != daemon_generation {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        Ok(LifecycleLockHolder {
            name,
            id,
            operation_id,
            labels,
            daemon_generation,
            input: Some(input),
            holder_lost,
            commands,
            mutation_gate,
            monitor,
        })
    }

    /// Re-attests the exact live ID retained by this manager.
    pub(in crate::init) async fn attest_lifecycle_lock(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        holder: &LifecycleLockHolder,
    ) -> Result<(), LocalInitError> {
        self.attest_lifecycle_lock_inner(installation, epoch, holder, true)
            .await
            .map(drop)
    }

    pub(super) async fn attest_lifecycle_lock_inner(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        holder: &LifecycleLockHolder,
        require_identity: bool,
    ) -> Result<LifecycleLockImage, LocalInitError> {
        if holder.holder_lost.is_cancelled()
            || current_engine_daemon_generation()? != holder.daemon_generation
        {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        self.verify_selected_engine().await?;
        if require_identity {
            self.verify_installation(installation).await?;
        }
        let image = lifecycle_lock_image(self, epoch).await?;
        if holder.labels
            != lifecycle_lock_expected_labels(
                &image.labels,
                lifecycle_lock_labels(installation, holder.operation_id, &holder.daemon_generation),
            )?
        {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        self.attest_lifecycle_lock_exact(
            installation,
            &holder.name,
            &holder.id,
            holder.operation_id,
            &image.inspection_reference,
            &image.image_id,
            &image.labels,
            true,
        )
        .await?;
        if require_identity {
            self.verify_installation(installation).await?;
        }
        self.verify_selected_engine().await?;
        Ok(image)
    }

    /// Classifies the deterministic lock without mutating it.
    pub(in crate::init) async fn inspect_lifecycle_lock(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
    ) -> Result<LifecycleLockObservation, LocalInitError> {
        self.inspect_lifecycle_lock_inner(installation, epoch, true)
            .await
    }

    pub(in crate::init) async fn inspect_lifecycle_lock_before_identity(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
    ) -> Result<LifecycleLockObservation, LocalInitError> {
        self.inspect_lifecycle_lock_inner(installation, epoch, false)
            .await
    }

    pub(super) async fn inspect_lifecycle_lock_inner(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        require_identity: bool,
    ) -> Result<LifecycleLockObservation, LocalInitError> {
        self.verify_selected_engine().await?;
        if require_identity {
            self.verify_installation(installation).await?;
        }
        let image = lifecycle_lock_image(self, epoch).await?;
        let name = lifecycle_lock_name(installation);
        let Some(container) = self.inspect_container(&name).await? else {
            if require_identity {
                self.verify_installation(installation).await?;
            }
            self.verify_selected_engine().await?;
            return Ok(LifecycleLockObservation::Absent);
        };
        let observation = classify_lifecycle_lock(
            &container,
            &name,
            &image.inspection_reference,
            &image.image_id,
            &image.labels,
            installation,
        )?;
        if require_identity {
            self.verify_installation(installation).await?;
        }
        self.verify_selected_engine().await?;
        Ok(observation)
    }

    pub(super) async fn gracefully_stop_lifecycle_lock(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        holder: &mut LifecycleLockHolder,
        require_identity: bool,
    ) -> Result<LifecycleLockImage, LocalInitError> {
        if holder.holder_lost.is_cancelled() {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        let mut release_gate = tokio::select! {
            biased;
            () = holder.holder_lost.cancelled() => {
                return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
            }
            result = tokio::time::timeout(
                ENGINE_TIMEOUT,
                Arc::clone(&holder.mutation_gate).lock_owned(),
            ) => {
                result.map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?
            }
        };
        if release_gate.closed {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        release_gate.closed = true;
        self.attest_lifecycle_lock_inner(installation, epoch, holder, require_identity)
            .await?;
        if holder.holder_lost.is_cancelled() {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        let (acknowledged, acknowledgment) = oneshot::channel();
        let (frame_sent, frame_confirmation) = oneshot::channel();
        holder
            .commands
            .send(LifecycleLockCommand::BeginRelease {
                acknowledged,
                frame_sent: frame_confirmation,
            })
            .await
            .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;
        tokio::time::timeout(ENGINE_TIMEOUT, acknowledgment)
            .await
            .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?
            .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;

        let mut input = holder
            .input
            .take()
            .ok_or_else(|| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;
        tokio::time::timeout(
            ENGINE_TIMEOUT,
            input.write_all(&crate::LOCAL_LIFECYCLE_LOCK_RELEASE_FRAME),
        )
        .await
        .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?
        .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;
        frame_sent
            .send(())
            .map_err(|()| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;
        tokio::time::timeout(ENGINE_TIMEOUT, input.shutdown())
            .await
            .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?
            .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;
        drop(input);

        let options = WaitContainerOptionsBuilder::default()
            .condition("not-running")
            .build();
        let mut wait = self.docker.wait_container(&holder.id, Some(options));
        tokio::time::timeout(ENGINE_TIMEOUT, async {
            let result = wait
                .next()
                .await
                .ok_or_else(|| LocalInitError::new(LocalInitErrorCode::ResetRequired))?
                .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;
            if wait.next().await.is_some() || result.error.is_some() || result.status_code != 0 {
                return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
            }
            Ok(())
        })
        .await
        .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))??;

        let image = lifecycle_lock_image(self, epoch).await?;
        self.attest_lifecycle_lock_exact(
            installation,
            &holder.name,
            &holder.id,
            holder.operation_id,
            &image.inspection_reference,
            &image.image_id,
            &image.labels,
            false,
        )
        .await?;
        tokio::time::timeout(ENGINE_TIMEOUT, &mut holder.monitor)
            .await
            .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?
            .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))??;
        Ok(image)
    }

    /// Gracefully releases only this manager's retained exact live ID.
    pub(in crate::init) async fn release_lifecycle_lock(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        mut holder: LifecycleLockHolder,
    ) -> Result<(), LocalInitError> {
        self.gracefully_stop_lifecycle_lock(installation, epoch, &mut holder, true)
            .await?;

        let options = RemoveContainerOptionsBuilder::default()
            .force(false)
            .v(false)
            .build();
        let _untrusted = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.remove_container(&holder.id, Some(options)),
        )
        .await;
        if self.inspect_container(&holder.id).await?.is_some()
            || self.inspect_container(&holder.name).await?.is_some()
        {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await
    }

    /// Returns the exact number of persistent role volumes already removed by
    /// a lifecycle-aware reset while the retained live lock remains the sole
    /// related container and every related network is absent.
    pub(in crate::init) async fn inspect_lifecycle_reset_volume_progress(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        holder: &LifecycleLockHolder,
    ) -> Result<usize, LocalInitError> {
        self.attest_lifecycle_lock(installation, epoch, holder)
            .await?;
        let names = volume_names(installation);
        let all_names = names
            .values()
            .cloned()
            .chain(std::iter::once(
                installation.anchor_volume_name().to_owned(),
            ))
            .collect::<BTreeSet<_>>();
        let observed = self
            .inspect_lifecycle_volume_union(installation, &all_names)
            .await?;
        if !observed.contains(installation.anchor_volume_name()) {
            return Err(engine_resource_mismatch());
        }
        let labels = expected_volume_labels(installation, epoch.fingerprint());
        let mut presence = [false; 12];
        for (index, role) in reset_volume_order().into_iter().enumerate() {
            let name = names.get(&role).ok_or_else(engine_resource_mismatch)?;
            presence[index] = observed.contains(name);
            if !presence[index] {
                continue;
            }
            let volume = self
                .inspect_volume(name)
                .await?
                .ok_or_else(engine_resource_mismatch)?;
            validate_volume(
                &volume,
                name,
                labels.get(&role).ok_or_else(engine_resource_mismatch)?,
            )?;
            if !self.volume_attachments(name).await?.is_empty() {
                return Err(engine_resource_mismatch());
            }
        }
        let removed = reset_progress_from_presence(&presence, true)?;
        let expected_remaining = reset_volume_order()[removed..]
            .iter()
            .map(|role| {
                names
                    .get(role)
                    .cloned()
                    .ok_or_else(engine_resource_mismatch)
            })
            .chain(std::iter::once(Ok(installation
                .anchor_volume_name()
                .to_owned())))
            .collect::<Result<BTreeSet<_>, LocalInitError>>()?;
        if observed != expected_remaining {
            return Err(engine_resource_mismatch());
        }
        self.attest_reset_quiescent_union(installation, holder, &expected_remaining)
            .await?;
        self.attest_lifecycle_lock(installation, epoch, holder)
            .await?;
        Ok(removed)
    }

    /// Read-only reset progress under exact sticky stopped-lock evidence.
    /// Two complete quiescent censuses prove that no related process can race
    /// the observation; the stopped container is never removed here.
    pub(in crate::init) async fn inspect_stopped_lifecycle_reset_volume_progress(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        expected_id: &str,
    ) -> Result<usize, LocalInitError> {
        if !exact_container_id_text(expected_id) {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let image = lifecycle_lock_image(self, epoch).await?;
        let name = lifecycle_lock_name(installation);
        let container = self
            .inspect_container(expected_id)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        let operation_id = match classify_lifecycle_lock(
            &container,
            &name,
            &image.inspection_reference,
            &image.image_id,
            &image.labels,
            installation,
        )? {
            LifecycleLockObservation::Stopped { id, operation_id } if id == expected_id => {
                operation_id
            }
            LifecycleLockObservation::Absent
            | LifecycleLockObservation::Live { .. }
            | LifecycleLockObservation::Stopped { .. } => return Err(engine_resource_mismatch()),
        };
        let names = volume_names(installation);
        let all_names = names
            .values()
            .cloned()
            .chain(std::iter::once(
                installation.anchor_volume_name().to_owned(),
            ))
            .collect::<BTreeSet<_>>();
        let observed = self
            .inspect_lifecycle_volume_union(installation, &all_names)
            .await?;
        if !observed.contains(installation.anchor_volume_name()) {
            return Err(engine_resource_mismatch());
        }
        let labels = expected_volume_labels(installation, epoch.fingerprint());
        let mut presence = [false; 12];
        for (index, role) in reset_volume_order().into_iter().enumerate() {
            let volume_name = names.get(&role).ok_or_else(engine_resource_mismatch)?;
            presence[index] = observed.contains(volume_name);
            if presence[index] {
                let volume = self
                    .inspect_volume(volume_name)
                    .await?
                    .ok_or_else(engine_resource_mismatch)?;
                validate_volume(
                    &volume,
                    volume_name,
                    labels.get(&role).ok_or_else(engine_resource_mismatch)?,
                )?;
                if !self.volume_attachments(volume_name).await?.is_empty() {
                    return Err(engine_resource_mismatch());
                }
            }
        }
        let removed = reset_progress_from_presence(&presence, true)?;
        let expected_remaining = reset_volume_order()[removed..]
            .iter()
            .map(|role| {
                names
                    .get(role)
                    .cloned()
                    .ok_or_else(engine_resource_mismatch)
            })
            .chain(std::iter::once(Ok(installation
                .anchor_volume_name()
                .to_owned())))
            .collect::<Result<BTreeSet<_>, LocalInitError>>()?;
        if observed != expected_remaining {
            return Err(engine_resource_mismatch());
        }
        self.attest_reset_quiescent_lock(installation, &name, expected_id, &expected_remaining)
            .await?;
        self.attest_lifecycle_lock_exact(
            installation,
            &name,
            expected_id,
            operation_id,
            &image.inspection_reference,
            &image.image_id,
            &image.labels,
            false,
        )
        .await?;
        Ok(removed)
    }

    /// Read-only classification of the exact final stopped reset lock after
    /// the identity anchor and all persistent role volumes are absent.
    pub(in crate::init) async fn inspect_orphaned_stopped_reset_lock(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
    ) -> Result<bool, LocalInitError> {
        self.verify_selected_engine().await?;
        if self
            .adapter
            .inspect_identity(installation.name())
            .await
            .map_err(|_| engine_resource_mismatch())?
            .is_some()
        {
            return Err(engine_resource_mismatch());
        }
        let name = lifecycle_lock_name(installation);
        let Some(container) = self.inspect_container(&name).await? else {
            return Ok(false);
        };
        let image = lifecycle_lock_image(self, epoch).await?;
        let (id, operation_id) = match classify_lifecycle_lock(
            &container,
            &name,
            &image.inspection_reference,
            &image.image_id,
            &image.labels,
            installation,
        )? {
            LifecycleLockObservation::Stopped { id, operation_id } => (id, operation_id),
            LifecycleLockObservation::Live { .. } => {
                return Err(LocalInitError::new(LocalInitErrorCode::OperationInProgress));
            }
            LifecycleLockObservation::Absent => return Err(engine_resource_mismatch()),
        };
        self.attest_reset_quiescent_lock(installation, &name, &id, &BTreeSet::new())
            .await?;
        self.attest_lifecycle_lock_exact(
            installation,
            &name,
            &id,
            operation_id,
            &image.inspection_reference,
            &image.image_id,
            &image.labels,
            false,
        )
        .await?;
        Ok(true)
    }

    /// Removes the next exact persistent role volume in the closed reset order.
    pub(in crate::init) async fn remove_lifecycle_reset_volume(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        holder: &LifecycleLockHolder,
        role: VolumeRole,
        mutation: &LifecycleMutationFence,
    ) -> Result<(), LocalInitError> {
        let removed = self
            .inspect_lifecycle_reset_volume_progress(installation, epoch, holder)
            .await?;
        if reset_volume_order().get(removed).copied() != Some(role) {
            return Err(engine_resource_mismatch());
        }
        let name = volume_name(installation.compose_project().as_str(), role);
        let volume = self
            .inspect_volume(&name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        validate_volume(
            &volume,
            &name,
            &volume_labels(installation, epoch.fingerprint(), role),
        )?;
        if !self.volume_attachments(&name).await?.is_empty() {
            return Err(engine_resource_mismatch());
        }
        mutation
            .run(self.remove_volume_and_prove_absent(&name))
            .await??;
        self.attest_lifecycle_lock(installation, epoch, holder)
            .await
    }

    /// Removes the identity anchor while the retained live holder still fences
    /// every Engine mutation, then gracefully releases and deletes only that
    /// exact holder ID.
    pub(in crate::init) async fn remove_reset_anchor_and_release_lock(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        mut holder: LifecycleLockHolder,
        mutation: &LifecycleMutationFence,
    ) -> Result<(), LocalInitError> {
        if self
            .inspect_lifecycle_reset_volume_progress(installation, epoch, &holder)
            .await?
            != 12
        {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let expected = BTreeSet::from([installation.anchor_volume_name().to_owned()]);
        if self
            .inspect_lifecycle_volume_union(installation, &expected)
            .await?
            != expected
        {
            return Err(engine_resource_mismatch());
        }
        self.attest_reset_quiescent_union(installation, &holder, &expected)
            .await?;
        self.attest_lifecycle_lock(installation, epoch, &holder)
            .await?;
        mutation
            .run(self.remove_volume_and_prove_absent(installation.anchor_volume_name()))
            .await??;
        mutation.checkpoint()?;
        if self
            .adapter
            .inspect_identity(installation.name())
            .await
            .map_err(|_| engine_resource_mismatch())?
            .is_some()
        {
            return Err(engine_resource_mismatch());
        }
        let image = self
            .gracefully_stop_lifecycle_lock(installation, epoch, &mut holder, false)
            .await?;
        if current_engine_daemon_generation()? != holder.daemon_generation {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        self.attest_lifecycle_lock_exact(
            installation,
            &holder.name,
            &holder.id,
            holder.operation_id,
            &image.inspection_reference,
            &image.image_id,
            &image.labels,
            false,
        )
        .await?;
        let options = RemoveContainerOptionsBuilder::default()
            .force(false)
            .v(false)
            .link(false)
            .build();
        let _untrusted = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.remove_container(&holder.id, Some(options)),
        )
        .await;
        if self.inspect_container(&holder.id).await?.is_some()
            || self.inspect_container(&holder.name).await?.is_some()
        {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        self.attest_reset_union_absent(installation).await
    }

    /// Proves the deterministic lifecycle lock name absent without mutation.
    pub(in crate::init) async fn attest_lifecycle_lock_absent(
        &self,
        installation: &Installation,
    ) -> Result<(), LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        if self
            .inspect_container(&lifecycle_lock_name(installation))
            .await?
            .is_some()
        {
            return Err(engine_resource_mismatch());
        }
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await
    }

    /// Recovers sticky stopped-lock evidence only after a reset intent is
    /// already durable, following two stable, fully validated Engine censuses.
    pub(in crate::init) async fn recover_stopped_lifecycle_reset_lock_after_intent(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        desired: &DesiredSpec,
        expected: &ExpectedLifecycleTopology,
        expected_runner_id: uuid::Uuid,
        expected_id: &str,
    ) -> Result<usize, LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let mut recovery = self
            .begin_stopped_lock_recovery_event_fence(expected_id, None)
            .await?;
        let first = recovery
            .guard(async {
                crate::init::compose::attest_no_project_compose_processes(installation)?;
                self.inspect_stopped_lifecycle_reset_recovery_census(
                    installation,
                    epoch,
                    desired,
                    expected,
                    expected_runner_id,
                    expected_id,
                )
                .await
            })
            .await?;
        let repeated = recovery
            .guard(async {
                let census = self
                    .inspect_stopped_lifecycle_reset_recovery_census(
                        installation,
                        epoch,
                        desired,
                        expected,
                        expected_runner_id,
                        expected_id,
                    )
                    .await?;
                crate::init::compose::attest_no_project_compose_processes(installation)?;
                Ok(census)
            })
            .await?;
        if first != repeated {
            return Err(engine_resource_mismatch());
        }
        let cancellation_latched = recovery
            .delete_exact_container(&self.docker, expected_id)
            .await?;
        let name = lifecycle_lock_name(installation);
        recovery
            .guard(async {
                if self.inspect_container(expected_id).await?.is_some()
                    || self.inspect_container(&name).await?.is_some()
                {
                    return Err(engine_resource_mismatch());
                }
                self.verify_installation(installation).await?;
                self.verify_selected_engine().await
            })
            .await?;
        recovery.verify_generation()?;
        if cancellation_latched {
            return Err(engine_resource_mismatch());
        }
        Ok(first.0)
    }

    pub(super) async fn inspect_stopped_lifecycle_reset_recovery_census(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        desired: &DesiredSpec,
        expected: &ExpectedLifecycleTopology,
        expected_runner_id: uuid::Uuid,
        expected_id: &str,
    ) -> Result<(usize, Option<LifecycleTopology>), LocalInitError> {
        let names = volume_names(installation);
        let all_names = names
            .values()
            .cloned()
            .chain(std::iter::once(
                installation.anchor_volume_name().to_owned(),
            ))
            .collect::<BTreeSet<_>>();
        let observed = self
            .inspect_lifecycle_volume_union(installation, &all_names)
            .await?;
        if !observed.contains(installation.anchor_volume_name()) {
            return Err(engine_resource_mismatch());
        }
        let mut presence = [false; 12];
        for (index, role) in reset_volume_order().into_iter().enumerate() {
            presence[index] =
                observed.contains(names.get(&role).ok_or_else(engine_resource_mismatch)?);
        }
        let removed = reset_progress_from_presence(&presence, true)?;
        if removed == 0 {
            self.preflight_lifecycle_volumes(installation, epoch)
                .await?;
            let topology = self
                .inspect_lifecycle_topology(
                    installation,
                    epoch,
                    desired,
                    expected,
                    expected_runner_id,
                )
                .await?;
            Ok((removed, Some(topology)))
        } else {
            let expected_remaining = reset_volume_order()[removed..]
                .iter()
                .map(|role| {
                    names
                        .get(role)
                        .cloned()
                        .ok_or_else(engine_resource_mismatch)
                })
                .chain(std::iter::once(Ok(installation
                    .anchor_volume_name()
                    .to_owned())))
                .collect::<Result<BTreeSet<_>, LocalInitError>>()?;
            if observed != expected_remaining {
                return Err(engine_resource_mismatch());
            }
            self.attest_reset_quiescent_lock(
                installation,
                &lifecycle_lock_name(installation),
                expected_id,
                &expected_remaining,
            )
            .await?;
            Ok((removed, None))
        }
    }

    /// Exceptional, operator-authorized recovery for ordinary up/down replay.
    ///
    /// The exact stopped holder is retained while two complete, independently
    /// validated topology censuses and their immutable Engine identities agree.
    /// Only then is that same stopped ID removed. Ordinary lock acquisition
    /// never enters this boundary.
    pub(in crate::init) async fn recover_stopped_lifecycle_lock(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        desired: &DesiredSpec,
        expected: &ExpectedLifecycleTopology,
        expected_runner_id: uuid::Uuid,
        expected_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<(), LocalInitError> {
        if !exact_container_id_text(expected_id) {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let expected_operation = match self.inspect_lifecycle_lock(installation, epoch).await? {
            LifecycleLockObservation::Stopped { id, operation_id } if id == expected_id => {
                operation_id
            }
            LifecycleLockObservation::Live { .. } => {
                return Err(LocalInitError::new(LocalInitErrorCode::OperationInProgress));
            }
            LifecycleLockObservation::Absent | LifecycleLockObservation::Stopped { .. } => {
                return Err(engine_resource_mismatch());
            }
        };
        let mut recovery = self
            .begin_stopped_lock_recovery_event_fence(expected_id, Some(cancellation))
            .await?;
        recovery
            .guard(async {
                crate::init::compose::attest_no_project_compose_processes(installation)?;
                self.preflight_lifecycle_volumes(installation, epoch)
                    .await?;
                Ok(())
            })
            .await?;
        let (first_topology, first_identity) = recovery
            .guard(async {
                let topology = self
                    .inspect_lifecycle_topology(
                        installation,
                        epoch,
                        desired,
                        expected,
                        expected_runner_id,
                    )
                    .await?;
                let identity = self
                    .lifecycle_quiescent_identity_census(installation)
                    .await?;
                crate::init::compose::attest_no_project_compose_processes(installation)?;
                Ok((topology, identity))
            })
            .await?;
        let (repeated_topology, repeated_identity) = recovery
            .guard(async {
                let topology = self
                    .inspect_lifecycle_topology(
                        installation,
                        epoch,
                        desired,
                        expected,
                        expected_runner_id,
                    )
                    .await?;
                let identity = self
                    .lifecycle_quiescent_identity_census(installation)
                    .await?;
                crate::init::compose::attest_no_project_compose_processes(installation)?;
                Ok((topology, identity))
            })
            .await?;
        if first_topology != repeated_topology || first_identity != repeated_identity {
            return Err(engine_resource_mismatch());
        }
        recovery
            .guard(async {
                if self.inspect_lifecycle_lock(installation, epoch).await?
                    != (LifecycleLockObservation::Stopped {
                        id: expected_id.to_owned(),
                        operation_id: expected_operation,
                    })
                {
                    return Err(engine_resource_mismatch());
                }
                Ok(())
            })
            .await?;
        let cancellation_latched = recovery
            .delete_exact_container(&self.docker, expected_id)
            .await?;
        recovery
            .guard(async {
                if self.inspect_container(expected_id).await?.is_some()
                    || self
                        .inspect_container(&lifecycle_lock_name(installation))
                        .await?
                        .is_some()
                {
                    return Err(engine_resource_mismatch());
                }
                self.verify_installation(installation).await?;
                self.verify_selected_engine().await
            })
            .await?;
        recovery.verify_generation()?;
        if cancellation_latched {
            Err(LocalInitError::new(LocalInitErrorCode::Cancelled))
        } else {
            Ok(())
        }
    }

    /// Exceptional stopped-lock recovery for initialization before the
    /// identity anchor necessarily exists. One event subscription spans both
    /// complete init-union censuses, the exact-ID destroy, and absence proof.
    pub(in crate::init) async fn recover_stopped_initialization_lock(
        &self,
        catalog: &crate::init::catalog::VerifiedCatalog,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        expected_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<(), LocalInitError> {
        let expected_operation = match self
            .inspect_lifecycle_lock_before_identity(installation, epoch)
            .await?
        {
            LifecycleLockObservation::Stopped { id, operation_id } if id == expected_id => {
                operation_id
            }
            LifecycleLockObservation::Live { .. } => {
                return Err(LocalInitError::new(LocalInitErrorCode::OperationInProgress));
            }
            LifecycleLockObservation::Absent | LifecycleLockObservation::Stopped { .. } => {
                return Err(engine_resource_mismatch());
            }
        };
        let lock_name = lifecycle_lock_name(installation);
        let mut recovery = self
            .begin_stopped_lock_recovery_event_fence(expected_id, Some(cancellation))
            .await?;
        let first = recovery
            .guard(async {
                crate::init::compose::attest_no_project_compose_processes(installation)?;
                self.preflight_initialization_recovery_union(
                    catalog,
                    installation,
                    epoch.fingerprint(),
                    (&lock_name, expected_id),
                )
                .await
            })
            .await?;
        let repeated = recovery
            .guard(async {
                let census = self
                    .preflight_initialization_recovery_union(
                        catalog,
                        installation,
                        epoch.fingerprint(),
                        (&lock_name, expected_id),
                    )
                    .await?;
                crate::init::compose::attest_no_project_compose_processes(installation)?;
                Ok(census)
            })
            .await?;
        if first != repeated {
            return Err(engine_resource_mismatch());
        }
        recovery
            .guard(async {
                if self
                    .inspect_lifecycle_lock_before_identity(installation, epoch)
                    .await?
                    != (LifecycleLockObservation::Stopped {
                        id: expected_id.to_owned(),
                        operation_id: expected_operation,
                    })
                {
                    return Err(engine_resource_mismatch());
                }
                Ok(())
            })
            .await?;
        let cancellation_latched = recovery
            .delete_exact_container(&self.docker, expected_id)
            .await?;
        recovery
            .guard(async {
                if self.inspect_container(expected_id).await?.is_some()
                    || self.inspect_container(&lock_name).await?.is_some()
                {
                    return Err(engine_resource_mismatch());
                }
                self.verify_selected_engine().await
            })
            .await?;
        recovery.verify_generation()?;
        if cancellation_latched {
            Err(LocalInitError::new(LocalInitErrorCode::Cancelled))
        } else {
            Ok(())
        }
    }

    /// Removes the sole exact stopped reset lock after the identity anchor was
    /// already durably deleted but the final exact-ID lock removal crashed.
    pub(in crate::init) async fn recover_orphaned_stopped_reset_lock(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
    ) -> Result<bool, LocalInitError> {
        self.verify_selected_engine().await?;
        if self
            .adapter
            .inspect_identity(installation.name())
            .await
            .map_err(|_| engine_resource_mismatch())?
            .is_some()
        {
            return Err(engine_resource_mismatch());
        }
        let name = lifecycle_lock_name(installation);
        let Some(container) = self.inspect_container(&name).await? else {
            return Ok(false);
        };
        let image = lifecycle_lock_image(self, epoch).await?;
        let (id, operation_id) = match classify_lifecycle_lock(
            &container,
            &name,
            &image.inspection_reference,
            &image.image_id,
            &image.labels,
            installation,
        )? {
            LifecycleLockObservation::Stopped { id, operation_id } => (id, operation_id),
            LifecycleLockObservation::Live { .. } => {
                return Err(LocalInitError::new(LocalInitErrorCode::OperationInProgress));
            }
            LifecycleLockObservation::Absent => return Err(engine_resource_mismatch()),
        };
        let expected_volumes = BTreeSet::new();
        let mut recovery = self
            .begin_stopped_lock_recovery_event_fence(&id, None)
            .await?;
        for _ in 0..2 {
            recovery
                .guard(async {
                    crate::init::compose::attest_no_project_compose_processes(installation)?;
                    self.attest_reset_quiescent_lock(installation, &name, &id, &expected_volumes)
                        .await?;
                    let by_id = self
                        .inspect_container(&id)
                        .await?
                        .ok_or_else(engine_resource_mismatch)?;
                    if classify_lifecycle_lock(
                        &by_id,
                        &name,
                        &image.inspection_reference,
                        &image.image_id,
                        &image.labels,
                        installation,
                    )? != (LifecycleLockObservation::Stopped {
                        id: id.clone(),
                        operation_id,
                    }) {
                        return Err(engine_resource_mismatch());
                    }
                    Ok(())
                })
                .await?;
        }
        recovery.delete_exact_container(&self.docker, &id).await?;
        recovery
            .guard(async {
                if self.inspect_container(&id).await?.is_some()
                    || self.inspect_container(&name).await?.is_some()
                    || self
                        .adapter
                        .inspect_identity(installation.name())
                        .await
                        .map_err(|_| engine_resource_mismatch())?
                        .is_some()
                {
                    return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
                }
                self.verify_selected_engine().await
            })
            .await?;
        recovery.verify_generation()?;
        Ok(true)
    }

    pub(super) async fn classify_lock_collision(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        name: &str,
    ) -> Result<LocalInitError, LocalInitError> {
        let image = lifecycle_lock_image(self, epoch).await?;
        let container = self
            .inspect_container(name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        Ok(
            match classify_lifecycle_lock(
                &container,
                name,
                &image.inspection_reference,
                &image.image_id,
                &image.labels,
                installation,
            )? {
                LifecycleLockObservation::Live { .. } => {
                    LocalInitError::new(LocalInitErrorCode::OperationInProgress)
                }
                LifecycleLockObservation::Stopped { .. } => {
                    LocalInitError::new(LocalInitErrorCode::ResetRequired)
                }
                LifecycleLockObservation::Absent => engine_resource_mismatch(),
            },
        )
    }

    pub(super) async fn attest_lifecycle_lock_exact(
        &self,
        installation: &Installation,
        name: &str,
        id: &str,
        operation_id: OperationId,
        image_reference: &str,
        image_id: &str,
        image_labels: &BTreeMap<String, String>,
        running: bool,
    ) -> Result<(), LocalInitError> {
        let expected = if running {
            LifecycleLockObservation::Live {
                id: id.to_owned(),
                operation_id,
            }
        } else {
            LifecycleLockObservation::Stopped {
                id: id.to_owned(),
                operation_id,
            }
        };
        let by_id = self
            .inspect_container(id)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        if classify_lifecycle_lock(
            &by_id,
            name,
            image_reference,
            image_id,
            image_labels,
            installation,
        )? != expected
        {
            return Err(engine_resource_mismatch());
        }
        let by_name = self
            .inspect_container(name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        if classify_lifecycle_lock(
            &by_name,
            name,
            image_reference,
            image_id,
            image_labels,
            installation,
        )? != expected
        {
            return Err(engine_resource_mismatch());
        }
        Ok(())
    }
}

pub(in crate::init::engine) fn lifecycle_lock_name(installation: &Installation) -> String {
    format!("{}-lifecycle-lock", installation.compose_project())
}

pub(super) struct LifecycleLockImage {
    pub(super) inspection_reference: String,
    pub(super) image_id: String,
    pub(super) labels: BTreeMap<String, String>,
}

pub(super) async fn lifecycle_lock_image(
    engine: &InitEngine<'_>,
    epoch: &ImmutableEpoch,
) -> Result<LifecycleLockImage, LocalInitError> {
    let expectation = epoch
        .image_expectations()
        .find(|image| image.role == "automata")
        .ok_or_else(engine_resource_mismatch)?;
    let image = engine.inspect_epoch_image(expectation).await?;
    let labels = engine
        .inspect_image(&image.inspection_reference)
        .await?
        .and_then(|image| image.config)
        .and_then(|config| config.labels)
        .ok_or_else(engine_resource_mismatch)?
        .into_iter()
        .collect();
    Ok(LifecycleLockImage {
        inspection_reference: image.inspection_reference,
        image_id: image.image_id,
        labels,
    })
}

pub(super) fn lifecycle_lock_expected_labels(
    image_labels: &BTreeMap<String, String>,
    managed: BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, LocalInitError> {
    if image_labels
        .keys()
        .any(|key| key.starts_with("io.automata.local."))
    {
        return Err(engine_resource_mismatch());
    }
    let mut labels = image_labels.clone();
    labels.extend(managed);
    Ok(labels)
}

pub(super) fn lifecycle_lock_labels(
    installation: &Installation,
    operation_id: OperationId,
    daemon: &EngineDaemonGeneration,
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
        (LABEL_RESOURCE_KIND.to_owned(), LOCK_KIND.to_owned()),
        (LABEL_OPERATION_ID.to_owned(), operation_id.to_string()),
        (LABEL_ENGINE_BOOT_ID.to_owned(), daemon.boot_id.to_string()),
        (LABEL_ENGINE_PID.to_owned(), daemon.pid.to_string()),
        (
            LABEL_ENGINE_START_TICKS.to_owned(),
            daemon.start_ticks.to_string(),
        ),
    ])
}

pub(super) fn lifecycle_lock_body(
    image_reference: &str,
    labels: &BTreeMap<String, String>,
) -> ContainerCreateBody {
    ContainerCreateBody {
        user: Some("65532:65532".to_owned()),
        attach_stdin: Some(true),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        tty: Some(false),
        open_stdin: Some(true),
        stdin_once: Some(true),
        env: Some(Vec::new()),
        cmd: Some(
            crate::LOCAL_LIFECYCLE_LOCK_HOLDER_COMMAND
                .into_iter()
                .map(str::to_owned)
                .collect(),
        ),
        image: Some(image_reference.to_owned()),
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
            mounts: Some(Vec::new()),
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

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn classify_lifecycle_lock(
    container: &bollard::models::ContainerInspectResponse,
    name: &str,
    image_reference: &str,
    image_id: &str,
    image_labels: &BTreeMap<String, String>,
    installation: &Installation,
) -> Result<LifecycleLockObservation, LocalInitError> {
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
    let network = container
        .network_settings
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let labels = config
        .labels
        .as_ref()
        .into_iter()
        .flatten()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let operation_text = labels
        .get(LABEL_OPERATION_ID)
        .ok_or_else(engine_resource_mismatch)?;
    let operation_id = operation_text
        .parse::<OperationId>()
        .map_err(|_| engine_resource_mismatch())?;
    let daemon_generation = daemon_generation_from_labels(&labels)?;
    let expected_labels = lifecycle_lock_expected_labels(
        image_labels,
        lifecycle_lock_labels(installation, operation_id, &daemon_generation),
    )?;
    if operation_id.to_string() != *operation_text
        || labels != expected_labels
        || container.name.as_deref() != Some(format!("/{name}").as_str())
        || container.image.as_deref() != Some(image_id)
        || container.platform.as_deref() != Some("linux")
        || config.image.as_deref() != Some(image_reference)
        || config.user.as_deref() != Some("65532:65532")
        || config.attach_stdin != Some(true)
        || config.attach_stdout != Some(true)
        || config.attach_stderr != Some(true)
        || config.tty != Some(false)
        || config.open_stdin != Some(true)
        || config.stdin_once != Some(true)
        || config.entrypoint.as_deref() != Some(["/usr/local/bin/automata".to_owned()].as_slice())
        || config.cmd.as_deref()
            != Some(
                crate::LOCAL_LIFECYCLE_LOCK_HOLDER_COMMAND
                    .map(str::to_owned)
                    .as_slice(),
            )
        || config.env.as_ref().is_some_and(|env| !env.is_empty())
        || config.working_dir.as_deref() != Some("/")
        || config.network_disabled != Some(true)
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
        || host.network_mode.as_deref() != Some("none")
        || host.readonly_rootfs != Some(true)
        || host.privileged.unwrap_or(false)
        || host.auto_remove != Some(false)
        || helper_has_ambient_authority(host)
        || host.cap_drop.as_deref() != Some(["ALL".to_owned()].as_slice())
        || host.cap_add.as_ref().is_none_or(|caps| !caps.is_empty())
        || host.memory != Some(HELPER_MEMORY_BYTES)
        || host.memory_swap != Some(HELPER_MEMORY_BYTES)
        || host.nano_cpus != Some(HELPER_NANO_CPUS)
        || host.pids_limit != Some(HELPER_PIDS)
        || host.binds.as_ref().is_some_and(|binds| !binds.is_empty())
        || host
            .mounts
            .as_ref()
            .is_some_and(|mounts| !mounts.is_empty())
        || host.security_opt.as_deref() != Some(helper_security_options().as_slice())
        || host.masked_paths.as_deref() != Some(helper_masked_paths().as_slice())
        || host.readonly_paths.as_deref() != Some(helper_readonly_paths().as_slice())
        || host.tmpfs.as_ref().is_some_and(|tmpfs| !tmpfs.is_empty())
        || host.log_config.as_ref() != Some(&helper_log_config())
        || container
            .mounts
            .as_ref()
            .is_some_and(|mounts| !mounts.is_empty())
        || network.sandbox_id.as_deref() != Some("")
        || network.sandbox_key.as_deref() != Some("")
        || network.ports.as_ref().is_none_or(|ports| !ports.is_empty())
        || network
            .networks
            .as_ref()
            .is_none_or(|networks| !networks.is_empty())
        || state.paused != Some(false)
        || state.restarting != Some(false)
        || state.dead != Some(false)
        || state.oom_killed != Some(false)
        || state
            .error
            .as_deref()
            .is_some_and(|error| !error.is_empty())
    {
        return Err(engine_resource_mismatch());
    }

    classify_lifecycle_lock_process_state(state, id, operation_id)
}

pub(super) fn classify_lifecycle_lock_process_state(
    state: &bollard::models::ContainerState,
    id: &str,
    operation_id: OperationId,
) -> Result<LifecycleLockObservation, LocalInitError> {
    match state.running {
        Some(true) if state.pid.is_some_and(|pid| pid > 0) => Ok(LifecycleLockObservation::Live {
            id: id.to_owned(),
            operation_id,
        }),
        Some(false) if state.pid.is_none_or(|pid| pid == 0) => {
            Ok(LifecycleLockObservation::Stopped {
                id: id.to_owned(),
                operation_id,
            })
        }
        _ => Err(engine_resource_mismatch()),
    }
}
