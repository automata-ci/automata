#![cfg(windows)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Fixed Windows container-engine implementation of the privileged broker's host-compute port.
//!
//! The engine is reached only through the local Docker Engine named pipe. The
//! adapter never accepts an endpoint or isolation selector from a caller and
//! every create explicitly requests Hyper-V isolation. Docker's Windows
//! backend waits for the asynchronous HCS operation result; the broker writes
//! its durable `Creating` intent before this adapter is entered, so every
//! create/start transport failure is deliberately classified as uncertain.

use std::{
    collections::HashMap,
    fmt,
    io::{Cursor, Read as _},
    num::NonZeroU16,
    str::FromStr as _,
    sync::Arc,
    time::Duration,
};

use automata_ci_core::{EnvironmentProfile, EnvironmentProfileId, RunnerId, Sha256Digest};
use automata_ci_execution::{
    Cancellation, ExecutionOutput, ExecutionOutputRecord, ExecutionOutputStream,
    ExecutionTermination, ResourceLimits, SandboxCustody, SandboxGeneration,
};
use bollard::{
    API_DEFAULT_VERSION, Docker,
    container::LogOutput,
    errors::Error as BollardError,
    exec::{StartExecOptions, StartExecResults},
    models::{
        ContainerCreateBody, ContainerInspectResponse, ContainerStateStatusEnum, ExecConfig,
        HostConfig, HostConfigIsolationEnum, HostConfigLogConfig,
    },
    query_parameters::{
        CreateContainerOptionsBuilder, DownloadFromContainerOptionsBuilder,
        KillContainerOptionsBuilder, ListContainersOptionsBuilder, RemoveContainerOptionsBuilder,
        UploadToContainerOptionsBuilder,
    },
};
use futures::StreamExt as _;
use tar::{Archive, Builder, EntryType, Header};
use tokio::runtime::Runtime;

use automata_ci_windows_broker::{
    BrokerAdapterEffect, BrokerCopyFromRequest, BrokerCopyToRequest, BrokerExecRequest,
    HostComputeAdapterError, HostComputeCreateRequest, HostComputeInspection,
    HostComputeObservedIsolation, HostComputeObservedState, HostComputeOperation,
    HostComputeProfileObservation, HostComputeProfileRequest, WindowsHostComputeAdapter,
};

const ENGINE_PIPE: &str = "//./pipe/docker_engine";
const OWNER_LABEL: &str = "io.automata.windows-hyperv-broker.owner";
const OWNER_VALUE: &str = "v1";
const LABEL_GRANT: &str = "io.automata.windows-hyperv-broker.grant-sha256";
const LABEL_SPEC: &str = "io.automata.windows-hyperv-broker.spec-sha256";
const LABEL_GENERATION: &str = "io.automata.windows-hyperv-broker.generation";
const LABEL_CUSTODY_KIND: &str = "io.automata.windows-hyperv-broker.custody-kind";
const LABEL_CUSTODY_RUNNER: &str = "io.automata.windows-hyperv-broker.custody-runner";
const LABEL_CUSTODY_SLOT: &str = "io.automata.windows-hyperv-broker.custody-slot";
const LABEL_PROFILE_ID: &str = "io.automata.windows-hyperv-broker.profile-id";
const LABEL_PROFILE_DIGEST: &str = "io.automata.windows-hyperv-broker.profile-sha256";
const LABEL_IMAGE_DIGEST: &str = "io.automata.windows-hyperv-broker.image-sha256";
const LABEL_MEMORY: &str = "io.automata.windows-hyperv-broker.memory-bytes";
const LABEL_CPU: &str = "io.automata.windows-hyperv-broker.cpu-millis";
const LABEL_PIDS: &str = "io.automata.windows-hyperv-broker.pids";
const CONTAINER_USER: &str = "ContainerUser";
const OUTPUT_RECORD_BYTES: usize = 64 * 1024;
const MAX_ARCHIVE_OVERHEAD: usize = 1024 * 1024;

/// Production Windows host-compute adapter over the fixed local engine pipe.
///
/// It has no process-isolation, remote-engine, shell, or full-VM route.
pub struct WindowsEngineHostComputeAdapter {
    engine: Docker,
    runtime: Arc<Runtime>,
}

impl WindowsEngineHostComputeAdapter {
    /// Opens the fixed local Windows container-engine endpoint.
    ///
    /// # Errors
    ///
    /// Returns a closed adapter failure if the runtime or named-pipe client
    /// cannot be constructed. This does not make a host mutation.
    pub fn open() -> Result<Self, HostComputeAdapterError> {
        let runtime = Runtime::new().map_err(|_| {
            failure(
                HostComputeOperation::AttestProfile,
                BrokerAdapterEffect::KnownNoEffect,
            )
        })?;
        let engine = Docker::connect_with_named_pipe(ENGINE_PIPE, 120, API_DEFAULT_VERSION)
            .map_err(|_| {
                failure(
                    HostComputeOperation::AttestProfile,
                    BrokerAdapterEffect::KnownNoEffect,
                )
            })?;
        Ok(Self {
            engine,
            runtime: Arc::new(runtime),
        })
    }

    fn inspect_inner(
        &self,
        resource_id: &str,
    ) -> Result<Option<HostComputeInspection>, HostComputeAdapterError> {
        if !valid_resource_id(resource_id) {
            return Err(failure(
                HostComputeOperation::Inspect,
                BrokerAdapterEffect::KnownNoEffect,
            ));
        }
        let result = self
            .runtime
            .block_on(self.engine.inspect_container(resource_id, None));
        match result {
            Ok(observed) => inspection_from_engine(resource_id, observed).map(Some),
            Err(error) if is_not_found(&error) => Ok(None),
            Err(_) => Err(failure(
                HostComputeOperation::Inspect,
                BrokerAdapterEffect::KnownNoEffect,
            )),
        }
    }
}

impl fmt::Debug for WindowsEngineHostComputeAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsEngineHostComputeAdapter")
            .field("engine_pipe", &ENGINE_PIPE)
            .finish_non_exhaustive()
    }
}

impl WindowsHostComputeAdapter for WindowsEngineHostComputeAdapter {
    fn attest_profile(
        &self,
        request: &HostComputeProfileRequest,
    ) -> Result<HostComputeProfileObservation, HostComputeAdapterError> {
        let image = self
            .runtime
            .block_on(self.engine.inspect_image(request.image().reference()))
            .map_err(|_| {
                failure(
                    HostComputeOperation::AttestProfile,
                    BrokerAdapterEffect::KnownNoEffect,
                )
            })?;
        let exact_digest_reference = format!("@sha256:{}", request.image().digest());
        let digest_matches = image.repo_digests.as_ref().is_some_and(|digests| {
            digests.iter().any(|digest| {
                digest == request.image().reference() && digest.ends_with(&exact_digest_reference)
            })
        });
        let windows_amd64 = image
            .os
            .as_deref()
            .is_some_and(|os| os.eq_ignore_ascii_case("windows"))
            && image
                .architecture
                .as_deref()
                .is_some_and(|arch| arch.eq_ignore_ascii_case("amd64"));
        if !digest_matches || !windows_amd64 {
            return Err(failure(
                HostComputeOperation::AttestProfile,
                BrokerAdapterEffect::KnownNoEffect,
            ));
        }
        Ok(HostComputeProfileObservation::new(
            request.image().digest(),
            HostComputeObservedIsolation::HyperV,
            true,
            true,
        ))
    }

    #[allow(clippy::too_many_lines)]
    fn create(&self, request: &HostComputeCreateRequest) -> Result<(), HostComputeAdapterError> {
        if !valid_resource_id(request.resource_id()) {
            return Err(failure(
                HostComputeOperation::Create,
                BrokerAdapterEffect::KnownNoEffect,
            ));
        }
        let image = self.attest_profile(&HostComputeProfileRequest::new(
            request.profile().clone(),
            request.image().clone(),
        ))?;
        if image.image_digest() != request.image().digest() {
            return Err(failure(
                HostComputeOperation::Create,
                BrokerAdapterEffect::KnownNoEffect,
            ));
        }
        let resources = request.resources();
        let mut labels = HashMap::new();
        labels.insert(OWNER_LABEL.to_owned(), OWNER_VALUE.to_owned());
        labels.insert(LABEL_GRANT.to_owned(), request.grant_digest().to_string());
        labels.insert(LABEL_SPEC.to_owned(), request.spec_digest().to_string());
        labels.insert(
            LABEL_GENERATION.to_owned(),
            request.generation().get().to_string(),
        );
        let (custody_kind, custody_runner, custody_slot) = match request.custody() {
            SandboxCustody::ProfileAdmission { runner_id } => {
                ("profile-admission", runner_id.to_string(), "0".to_owned())
            }
            SandboxCustody::Job {
                runner_id,
                slot_ordinal,
            } => ("job", runner_id.to_string(), slot_ordinal.get().to_string()),
        };
        labels.insert(LABEL_CUSTODY_KIND.to_owned(), custody_kind.to_owned());
        labels.insert(LABEL_CUSTODY_RUNNER.to_owned(), custody_runner);
        labels.insert(LABEL_CUSTODY_SLOT.to_owned(), custody_slot);
        labels.insert(
            LABEL_PROFILE_ID.to_owned(),
            request.profile().id().as_str().to_owned(),
        );
        labels.insert(
            LABEL_PROFILE_DIGEST.to_owned(),
            request.profile().digest().to_string(),
        );
        labels.insert(
            LABEL_IMAGE_DIGEST.to_owned(),
            request.image().digest().to_string(),
        );
        labels.insert(
            LABEL_MEMORY.to_owned(),
            resources.memory_bytes().to_string(),
        );
        labels.insert(LABEL_CPU.to_owned(), resources.cpu_millis().to_string());
        labels.insert(LABEL_PIDS.to_owned(), resources.pids().to_string());

        let host_config = HostConfig {
            isolation: Some(HostConfigIsolationEnum::HYPERV),
            network_mode: Some("none".to_owned()),
            memory: i64::try_from(resources.memory_bytes()).ok(),
            nano_cpus: Some(i64::from(resources.cpu_millis()) * 1_000_000),
            pids_limit: Some(i64::from(resources.pids())),
            readonly_rootfs: Some(false),
            privileged: Some(false),
            publish_all_ports: Some(false),
            auto_remove: Some(false),
            init: Some(false),
            binds: Some(Vec::new()),
            mounts: Some(Vec::new()),
            devices: Some(Vec::new()),
            device_requests: Some(Vec::new()),
            security_opt: Some(Vec::new()),
            restart_policy: Some(bollard::models::RestartPolicy::default()),
            log_config: Some(HostConfigLogConfig {
                typ: Some("none".to_owned()),
                config: Some(HashMap::new()),
            }),
            ..Default::default()
        };
        let body = ContainerCreateBody {
            user: Some(CONTAINER_USER.to_owned()),
            attach_stdin: Some(false),
            attach_stdout: Some(false),
            attach_stderr: Some(false),
            tty: Some(false),
            open_stdin: Some(false),
            stdin_once: Some(false),
            env: Some(Vec::new()),
            cmd: Some(request.keepalive().arguments().to_vec()),
            args_escaped: Some(false),
            image: Some(request.image().reference().to_owned()),
            volumes: Some(Vec::new()),
            working_dir: Some(request.workspace().as_str().to_owned()),
            entrypoint: Some(vec![request.keepalive().program().as_str().to_owned()]),
            network_disabled: Some(true),
            labels: Some(labels),
            host_config: Some(host_config),
            ..Default::default()
        };
        let options = CreateContainerOptionsBuilder::new()
            .name(request.resource_id())
            .platform("windows/amd64")
            .build();
        self.runtime
            .block_on(self.engine.create_container(Some(options), body))
            .map_err(|_| {
                failure(
                    HostComputeOperation::Create,
                    BrokerAdapterEffect::StateMayHaveChanged,
                )
            })?;
        self.runtime
            .block_on(self.engine.start_container(request.resource_id(), None))
            .map_err(|_| {
                failure(
                    HostComputeOperation::Create,
                    BrokerAdapterEffect::StateMayHaveChanged,
                )
            })
    }

    fn inspect(
        &self,
        resource_id: &str,
    ) -> Result<Option<HostComputeInspection>, HostComputeAdapterError> {
        self.inspect_inner(resource_id)
    }

    fn attach(&self, resource_id: &str) -> Result<(), HostComputeAdapterError> {
        let observed = self.inspect_inner(resource_id)?.ok_or_else(|| {
            failure(
                HostComputeOperation::Attach,
                BrokerAdapterEffect::KnownNoEffect,
            )
        })?;
        if observed.state() != HostComputeObservedState::Running
            || observed.isolation() != HostComputeObservedIsolation::HyperV
            || !observed.has_closed_policy()
        {
            return Err(failure(
                HostComputeOperation::Attach,
                BrokerAdapterEffect::KnownNoEffect,
            ));
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn exec(
        &self,
        request: &BrokerExecRequest<'_>,
        cancellation: &dyn Cancellation,
    ) -> Result<ExecutionOutput, HostComputeAdapterError> {
        if cancellation.disposition().requires_termination() {
            return Err(failure(
                HostComputeOperation::Exec,
                BrokerAdapterEffect::KnownNoEffect,
            ));
        }
        let command = request.command();
        if command
            .environment()
            .values()
            .iter()
            .any(automata_ci_execution::EnvironmentVariable::is_secret)
        {
            return Err(failure(
                HostComputeOperation::Exec,
                BrokerAdapterEffect::KnownNoEffect,
            ));
        }
        let mut argv = Vec::with_capacity(command.argv().arguments().len().saturating_add(1));
        argv.push(command.argv().program().as_str().to_owned());
        argv.extend(command.argv().arguments().iter().cloned());
        let environment = command
            .environment()
            .values()
            .iter()
            .map(|variable| format!("{}={}", variable.name().as_str(), variable.value().expose()))
            .collect::<Vec<_>>();
        let config = ExecConfig {
            attach_stdin: Some(false),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            tty: Some(false),
            env: Some(environment),
            cmd: Some(argv),
            privileged: Some(false),
            user: Some(CONTAINER_USER.to_owned()),
            working_dir: Some(command.working_directory().as_str().to_owned()),
            ..Default::default()
        };
        let resource_id = request.resource_id().to_owned();
        let engine = self.engine.clone();
        let output_limit = command.output_limit();
        let future = async {
            let created = engine
                .create_exec(&resource_id, config)
                .await
                .map_err(|_| ())?;
            let started = engine
                .start_exec(
                    &created.id,
                    Some(StartExecOptions {
                        detach: false,
                        tty: false,
                        output_capacity: Some(OUTPUT_RECORD_BYTES),
                    }),
                )
                .await
                .map_err(|_| ())?;
            let StartExecResults::Attached { mut output, .. } = started else {
                return Err(());
            };
            let mut records = Vec::new();
            let mut captured = 0_usize;
            loop {
                let next = tokio::select! {
                    item = output.next() => item,
                    () = tokio::time::sleep(Duration::from_millis(100)) => {
                        if cancellation.disposition().requires_termination() {
                            return Err(());
                        }
                        continue;
                    }
                };
                let Some(item) = next else { break };
                let item = item.map_err(|_| ())?;
                let stream = match item {
                    LogOutput::StdErr { .. } => ExecutionOutputStream::Stderr,
                    LogOutput::StdOut { .. } | LogOutput::Console { .. } => {
                        ExecutionOutputStream::Stdout
                    }
                    LogOutput::StdIn { .. } => return Err(()),
                };
                let bytes = item.into_bytes();
                for chunk in bytes.chunks(OUTPUT_RECORD_BYTES) {
                    captured = captured.checked_add(chunk.len()).ok_or(())?;
                    if captured > output_limit {
                        return Err(());
                    }
                    if !chunk.is_empty() {
                        records.push(
                            ExecutionOutputRecord::data(stream, chunk.to_vec()).map_err(|_| ())?,
                        );
                    }
                }
            }
            let inspected = engine.inspect_exec(&created.id).await.map_err(|_| ())?;
            if inspected.running != Some(false) {
                return Err(());
            }
            let exit_code = i32::try_from(inspected.exit_code.ok_or(())?).map_err(|_| ())?;
            records.push(ExecutionOutputRecord::end_of_stream(
                ExecutionOutputStream::Stdout,
            ));
            records.push(ExecutionOutputRecord::end_of_stream(
                ExecutionOutputStream::Stderr,
            ));
            ExecutionOutput::new(ExecutionTermination::Exited(exit_code), records, false)
                .map_err(|_| ())
        };
        if let Ok(Ok(output)) = self
            .runtime
            .block_on(tokio::time::timeout(command.timeout(), future))
        {
            Ok(output)
        } else {
            let _ = self.runtime.block_on(self.engine.kill_container(
                request.resource_id(),
                Some(KillContainerOptionsBuilder::new().signal("SIGKILL").build()),
            ));
            Err(failure(
                HostComputeOperation::Exec,
                BrokerAdapterEffect::StateMayHaveChanged,
            ))
        }
    }

    fn copy_to(
        &self,
        request: &BrokerCopyToRequest<'_>,
        cancellation: &dyn Cancellation,
    ) -> Result<(), HostComputeAdapterError> {
        if cancellation.disposition().requires_termination() {
            return Err(failure(
                HostComputeOperation::CopyTo,
                BrokerAdapterEffect::KnownNoEffect,
            ));
        }
        let (directory, basename) = split_windows_target(request.request().target().as_str())
            .ok_or_else(|| {
                failure(
                    HostComputeOperation::CopyTo,
                    BrokerAdapterEffect::KnownNoEffect,
                )
            })?;
        let archive = one_file_archive(basename, request.request().content()).map_err(|()| {
            failure(
                HostComputeOperation::CopyTo,
                BrokerAdapterEffect::KnownNoEffect,
            )
        })?;
        let options = UploadToContainerOptionsBuilder::new()
            .path(directory)
            .no_overwrite_dir_non_dir("true")
            .copy_uidgid("false")
            .build();
        self.runtime
            .block_on(self.engine.upload_to_container(
                request.resource_id(),
                Some(options),
                bollard::body_full(archive.into()),
            ))
            .map_err(|_| {
                failure(
                    HostComputeOperation::CopyTo,
                    BrokerAdapterEffect::StateMayHaveChanged,
                )
            })
    }

    fn copy_from(
        &self,
        request: &BrokerCopyFromRequest<'_>,
        cancellation: &dyn Cancellation,
    ) -> Result<Vec<u8>, HostComputeAdapterError> {
        if cancellation.disposition().requires_termination() {
            return Err(failure(
                HostComputeOperation::CopyFrom,
                BrokerAdapterEffect::KnownNoEffect,
            ));
        }
        let source = request.request().source().as_str();
        let (_, basename) = split_windows_target(source).ok_or_else(|| {
            failure(
                HostComputeOperation::CopyFrom,
                BrokerAdapterEffect::KnownNoEffect,
            )
        })?;
        let options = DownloadFromContainerOptionsBuilder::new()
            .path(source)
            .build();
        let byte_limit = request.request().byte_limit();
        let stream = self
            .engine
            .download_from_container(request.resource_id(), Some(options));
        let archive = self
            .runtime
            .block_on(async {
                futures::pin_mut!(stream);
                let mut bytes = Vec::new();
                while let Some(chunk) = stream.next().await {
                    if cancellation.disposition().requires_termination() {
                        return Err(());
                    }
                    let chunk = chunk.map_err(|_| ())?;
                    let maximum = byte_limit.checked_add(MAX_ARCHIVE_OVERHEAD).ok_or(())?;
                    if bytes.len().saturating_add(chunk.len()) > maximum {
                        return Err(());
                    }
                    bytes.extend_from_slice(&chunk);
                }
                Ok::<_, ()>(bytes)
            })
            .map_err(|()| {
                failure(
                    HostComputeOperation::CopyFrom,
                    BrokerAdapterEffect::KnownNoEffect,
                )
            })?;
        extract_one_file(&archive, basename, byte_limit).map_err(|()| {
            failure(
                HostComputeOperation::CopyFrom,
                BrokerAdapterEffect::KnownNoEffect,
            )
        })
    }

    fn terminate_descendants(&self, resource_id: &str) -> Result<(), HostComputeAdapterError> {
        if self.inspect_inner(resource_id)?.is_none() {
            return Ok(());
        }
        self.runtime
            .block_on(self.engine.kill_container(
                resource_id,
                Some(KillContainerOptionsBuilder::new().signal("SIGKILL").build()),
            ))
            .or_else(|error| {
                if is_not_found(&error) {
                    Ok(())
                } else {
                    Err(error)
                }
            })
            .map_err(|_| {
                failure(
                    HostComputeOperation::TerminateDescendants,
                    BrokerAdapterEffect::StateMayHaveChanged,
                )
            })
    }

    fn destroy(&self, resource_id: &str) -> Result<(), HostComputeAdapterError> {
        let options = RemoveContainerOptionsBuilder::new()
            .force(true)
            .v(false)
            .link(false)
            .build();
        self.runtime
            .block_on(self.engine.remove_container(resource_id, Some(options)))
            .or_else(|error| {
                if is_not_found(&error) {
                    Ok(())
                } else {
                    Err(error)
                }
            })
            .map_err(|_| {
                failure(
                    HostComputeOperation::Destroy,
                    BrokerAdapterEffect::StateMayHaveChanged,
                )
            })
    }

    fn list_owned(&self) -> Result<Vec<HostComputeInspection>, HostComputeAdapterError> {
        let mut filters = HashMap::new();
        filters.insert(
            "label".to_owned(),
            vec![format!("{OWNER_LABEL}={OWNER_VALUE}")],
        );
        let options = ListContainersOptionsBuilder::new()
            .all(true)
            .filters(&filters)
            .build();
        let summaries = self
            .runtime
            .block_on(self.engine.list_containers(Some(options)))
            .map_err(|_| {
                failure(
                    HostComputeOperation::ListOwned,
                    BrokerAdapterEffect::KnownNoEffect,
                )
            })?;
        let mut result = Vec::with_capacity(summaries.len());
        for summary in summaries {
            let resource_id = summary
                .names
                .as_ref()
                .and_then(|names| names.iter().find_map(|name| name.strip_prefix('/')))
                .filter(|name| valid_resource_id(name))
                .or(summary.id.as_deref().filter(|id| valid_resource_id(id)))
                .ok_or_else(|| {
                    failure(
                        HostComputeOperation::ListOwned,
                        BrokerAdapterEffect::KnownNoEffect,
                    )
                })?;
            let observed = self.inspect_inner(resource_id)?.ok_or_else(|| {
                failure(
                    HostComputeOperation::ListOwned,
                    BrokerAdapterEffect::KnownNoEffect,
                )
            })?;
            result.push(observed);
        }
        Ok(result)
    }
}

fn inspection_from_engine(
    resource_id: &str,
    observed: ContainerInspectResponse,
) -> Result<HostComputeInspection, HostComputeAdapterError> {
    let operation = HostComputeOperation::Inspect;
    let config = observed.config.ok_or_else(|| closed(operation))?;
    let host = observed.host_config.ok_or_else(|| closed(operation))?;
    let labels = config.labels.as_ref().ok_or_else(|| closed(operation))?;
    if labels.get(OWNER_LABEL).map(String::as_str) != Some(OWNER_VALUE)
        || observed
            .name
            .as_deref()
            .map(|name| name.trim_start_matches('/'))
            != Some(resource_id)
        || observed.platform.as_deref() != Some("windows")
    {
        return Err(closed(operation));
    }
    let grant_digest = label_digest(labels, LABEL_GRANT, operation)?;
    let spec_digest = label_digest(labels, LABEL_SPEC, operation)?;
    let generation = labels
        .get(LABEL_GENERATION)
        .and_then(|value| value.parse::<u64>().ok())
        .and_then(|value| SandboxGeneration::new(value).ok())
        .ok_or_else(|| closed(operation))?;
    let custody = custody_from_labels(labels, operation)?;
    let profile_id = labels
        .get(LABEL_PROFILE_ID)
        .and_then(|value| EnvironmentProfileId::new(value.clone()).ok())
        .ok_or_else(|| closed(operation))?;
    let profile = EnvironmentProfile::new(
        profile_id,
        label_digest(labels, LABEL_PROFILE_DIGEST, operation)?,
    );
    let image_digest = label_digest(labels, LABEL_IMAGE_DIGEST, operation)?;
    let resources = ResourceLimits::new(
        label_u64(labels, LABEL_MEMORY, operation)?,
        label_u32(labels, LABEL_CPU, operation)?,
        label_u32(labels, LABEL_PIDS, operation)?,
    )
    .map_err(|_| closed(operation))?;
    let isolation = match host.isolation {
        Some(HostConfigIsolationEnum::HYPERV) => HostComputeObservedIsolation::HyperV,
        Some(HostConfigIsolationEnum::PROCESS) => HostComputeObservedIsolation::Process,
        _ => HostComputeObservedIsolation::Unknown,
    };
    let state = match observed.state.and_then(|state| state.status) {
        Some(ContainerStateStatusEnum::CREATED) => HostComputeObservedState::Created,
        Some(ContainerStateStatusEnum::RUNNING) => HostComputeObservedState::Running,
        Some(ContainerStateStatusEnum::EXITED | ContainerStateStatusEnum::DEAD) => {
            HostComputeObservedState::Stopped
        }
        _ => HostComputeObservedState::Degraded,
    };
    let mounts = observed.mounts.as_ref().map_or(0, Vec::len)
        + host.binds.as_ref().map_or(0, Vec::len)
        + host.mounts.as_ref().map_or(0, Vec::len)
        + config.volumes.as_ref().map_or(0, Vec::len);
    let devices = host.devices.as_ref().map_or(0, Vec::len)
        + host.device_requests.as_ref().map_or(0, Vec::len);
    let network_settings_empty = observed
        .network_settings
        .as_ref()
        .and_then(|settings| settings.networks.as_ref())
        .is_none_or(HashMap::is_empty);
    let exact_resources = host.memory == i64::try_from(resources.memory_bytes()).ok()
        && host.nano_cpus == Some(i64::from(resources.cpu_millis()) * 1_000_000)
        && host.pids_limit == Some(i64::from(resources.pids()));
    let network_disabled = config.network_disabled == Some(true)
        && host.network_mode.as_deref() == Some("none")
        && network_settings_empty
        && host.publish_all_ports == Some(false)
        && host.port_bindings.as_ref().is_none_or(HashMap::is_empty);
    let writable_disposable_root = host.readonly_rootfs == Some(false)
        && mounts == 0
        && host.volume_driver.as_deref().is_none_or(str::is_empty)
        && exact_resources;
    let unprivileged = config.user.as_deref() == Some(CONTAINER_USER)
        && host.privileged == Some(false)
        && host.security_opt.as_ref().is_none_or(Vec::is_empty);
    Ok(HostComputeInspection::new(
        resource_id,
        grant_digest,
        spec_digest,
        generation,
        custody,
        profile,
        image_digest,
        resources,
        isolation,
        state,
        network_disabled,
        writable_disposable_root,
        unprivileged,
        u32::try_from(mounts).unwrap_or(u32::MAX),
        0,
        u32::try_from(devices).unwrap_or(u32::MAX),
    ))
}

fn custody_from_labels(
    labels: &HashMap<String, String>,
    operation: HostComputeOperation,
) -> Result<SandboxCustody, HostComputeAdapterError> {
    let runner_id = labels
        .get(LABEL_CUSTODY_RUNNER)
        .and_then(|value| RunnerId::from_str(value).ok())
        .ok_or_else(|| closed(operation))?;
    let slot = labels
        .get(LABEL_CUSTODY_SLOT)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| closed(operation))?;
    match labels.get(LABEL_CUSTODY_KIND).map(String::as_str) {
        Some("profile-admission") if slot == 0 => {
            Ok(SandboxCustody::ProfileAdmission { runner_id })
        }
        Some("job") => NonZeroU16::new(slot)
            .map(|slot_ordinal| SandboxCustody::Job {
                runner_id,
                slot_ordinal,
            })
            .ok_or_else(|| closed(operation)),
        _ => Err(closed(operation)),
    }
}

fn one_file_archive(name: &str, content: &[u8]) -> Result<Vec<u8>, ()> {
    if !valid_archive_name(name) {
        return Err(());
    }
    let mut bytes = Vec::new();
    {
        let mut archive = Builder::new(&mut bytes);
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::Regular);
        header.set_mode(0o600);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(u64::try_from(content.len()).map_err(|_| ())?);
        header.set_cksum();
        archive
            .append_data(&mut header, name, content)
            .map_err(|_| ())?;
        archive.finish().map_err(|_| ())?;
    }
    Ok(bytes)
}

fn extract_one_file(archive: &[u8], name: &str, limit: usize) -> Result<Vec<u8>, ()> {
    if !valid_archive_name(name) {
        return Err(());
    }
    let mut archive_reader = Archive::new(Cursor::new(archive));
    let mut entries = archive_reader.entries().map_err(|_| ())?;
    let mut entry = entries.next().ok_or(())?.map_err(|_| ())?;
    if entries.next().is_some()
        || !entry.header().entry_type().is_file()
        || entry.path().map_err(|_| ())?.to_str() != Some(name)
        || usize::try_from(entry.size()).map_err(|_| ())? > limit
    {
        return Err(());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(entry.size()).map_err(|_| ())?);
    entry
        .by_ref()
        .take(u64::try_from(limit).map_err(|_| ())?.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    (bytes.len() <= limit).then_some(bytes).ok_or(())
}

fn split_windows_target(path: &str) -> Option<(&str, &str)> {
    let (directory, name) = path.rsplit_once('\\')?;
    (!directory.is_empty() && valid_archive_name(name)).then_some((directory, name))
}

fn valid_archive_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name.len() <= 255
        && !name.contains(['/', '\\', ':', '\0'])
        && !name.ends_with([' ', '.'])
}

fn valid_resource_id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn label_digest(
    labels: &HashMap<String, String>,
    name: &str,
    operation: HostComputeOperation,
) -> Result<Sha256Digest, HostComputeAdapterError> {
    labels
        .get(name)
        .and_then(|value| Sha256Digest::from_str(value).ok())
        .ok_or_else(|| closed(operation))
}

fn label_u64(
    labels: &HashMap<String, String>,
    name: &str,
    operation: HostComputeOperation,
) -> Result<u64, HostComputeAdapterError> {
    labels
        .get(name)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| closed(operation))
}

fn label_u32(
    labels: &HashMap<String, String>,
    name: &str,
    operation: HostComputeOperation,
) -> Result<u32, HostComputeAdapterError> {
    labels
        .get(name)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| closed(operation))
}

fn is_not_found(error: &BollardError) -> bool {
    matches!(
        error,
        BollardError::DockerResponseServerError {
            status_code: 404,
            ..
        }
    )
}

const fn closed(operation: HostComputeOperation) -> HostComputeAdapterError {
    failure(operation, BrokerAdapterEffect::KnownNoEffect)
}

const fn failure(
    operation: HostComputeOperation,
    effect: BrokerAdapterEffect,
) -> HostComputeAdapterError {
    HostComputeAdapterError::new(operation, effect)
}
