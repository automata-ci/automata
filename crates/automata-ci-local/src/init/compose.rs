//! Pinned, bounded Docker Compose process boundary for lifecycle convergence.

use std::{
    ffi::OsStr,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use serde::Deserialize;
use tokio::{io::AsyncWriteExt as _, process::Command as ProcessCommand, time::timeout};
use tokio_util::sync::CancellationToken;

use crate::{
    CaptureFailure, DoctorReport, EngineSelection, Installation, MAX_COMMAND_STREAM_BYTES,
    read_bounded, spawn_contained, terminate_process_tree, terminate_remaining_process_tree,
};

use super::{LocalInitError, LocalInitErrorCode};

const FIXED_DOCKER_HOST: &str = "unix:///var/run/docker.sock";
const ABSENT_CONFIG_ROOT: &str = "/nonexistent/automata-local-docker-config";
pub(super) const COMPOSE_PROJECT_DIRECTORY: &str = "/";
const MAX_COMPOSE_OUTPUT: usize = 64 * 1024;
const TERMINATION_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct QualifiedDockerCli {
    path: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    compose_version: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ComposeStep<'a> {
    Validate,
    UpDependencies,
    UpControl,
    UpRelay,
    UpRunner,
    RunOneOff {
        service: &'a str,
        container_name: &'a str,
    },
    StopRunner,
    Down,
    ProjectIds,
}

impl QualifiedDockerCli {
    pub(super) async fn qualify(report: &DoctorReport) -> Result<Self, LocalInitError> {
        if !report.ready() {
            return Err(engine_unavailable());
        }
        let selection = report.selected_engine().ok_or_else(engine_unavailable)?;
        if selection.connection_host() != FIXED_DOCKER_HOST {
            return Err(engine_unavailable());
        }
        let path = resolve_docker_executable()?;
        let metadata = exact_executable_metadata(&path)?;
        let qualified = Self {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
            compose_version: selection.compose_version().to_owned(),
        };
        qualified.verify_identity()?;
        let output = qualified
            .run_raw(
                selection,
                &["compose", "version", "--format", "json"],
                None,
                Duration::from_secs(10),
                &CancellationToken::new(),
            )
            .await?;
        let version: ComposeVersion =
            serde_json::from_slice(&output).map_err(|_| engine_unavailable())?;
        if version.version != qualified.compose_version {
            return Err(engine_unavailable());
        }
        qualified.verify_identity()?;
        Ok(qualified)
    }

    pub(super) async fn execute(
        &self,
        selection: &EngineSelection,
        installation: &Installation,
        compose_bytes: &[u8],
        step: ComposeStep<'_>,
        cancellation: &CancellationToken,
    ) -> Result<Vec<u8>, LocalInitError> {
        if compose_bytes.is_empty() || !compose_bytes.ends_with(b"\n") {
            return Err(reset_required());
        }
        self.verify_identity()?;
        if selection.connection_host() != FIXED_DOCKER_HOST {
            return Err(engine_unavailable());
        }
        let mut arguments = vec![
            "--host".to_owned(),
            FIXED_DOCKER_HOST.to_owned(),
            "--config".to_owned(),
            ABSENT_CONFIG_ROOT.to_owned(),
            "compose".to_owned(),
            "--ansi".to_owned(),
            "never".to_owned(),
            "--parallel".to_owned(),
            "1".to_owned(),
            "--project-name".to_owned(),
            installation.compose_project().to_string(),
            "--project-directory".to_owned(),
            COMPOSE_PROJECT_DIRECTORY.to_owned(),
            "--env-file".to_owned(),
            "/dev/null".to_owned(),
            "--file".to_owned(),
            "-".to_owned(),
        ];
        let operation_timeout = append_step(&step, &mut arguments);
        let arguments = arguments.iter().map(String::as_str).collect::<Vec<_>>();
        let output = self
            .run_raw(
                selection,
                &arguments,
                Some(compose_bytes),
                operation_timeout,
                cancellation,
            )
            .await?;
        self.verify_identity()?;
        Ok(output)
    }

    fn verify_identity(&self) -> Result<(), LocalInitError> {
        let metadata = exact_executable_metadata(&self.path)?;
        if metadata.dev() != self.device
            || metadata.ino() != self.inode
            || metadata.uid() != self.uid
            || metadata.gid() != self.gid
            || metadata.mode() != self.mode
        {
            return Err(engine_unavailable());
        }
        Ok(())
    }

    async fn run_raw(
        &self,
        selection: &EngineSelection,
        arguments: &[&str],
        stdin: Option<&[u8]>,
        deadline: Duration,
        cancellation: &CancellationToken,
    ) -> Result<Vec<u8>, LocalInitError> {
        if cancellation.is_cancelled() {
            return Err(LocalInitError::new(LocalInitErrorCode::Cancelled));
        }
        let mut command = ProcessCommand::new(&self.path);
        command
            .env_clear()
            .env("DOCKER_CONFIG", ABSENT_CONFIG_ROOT)
            .env("HOME", "/nonexistent")
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("PATH", "/usr/bin:/bin")
            .env("XDG_CONFIG_HOME", "/nonexistent")
            .current_dir(COMPOSE_PROJECT_DIRECTORY)
            .args(arguments)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let (mut child, mut containment) =
            spawn_contained(command).map_err(|_| engine_unavailable())?;
        let stdout = child.stdout.take().ok_or_else(engine_unavailable)?;
        let stderr = child.stderr.take().ok_or_else(engine_unavailable)?;
        let mut child_stdin = child.stdin.take();
        let mut operation = Box::pin(timeout(deadline, async {
            tokio::try_join!(
                read_bounded(stdout, MAX_COMPOSE_OUTPUT),
                read_bounded(stderr, MAX_COMMAND_STREAM_BYTES),
                async {
                    if let Some(bytes) = stdin {
                        let writer = child_stdin.as_mut().ok_or(CaptureFailure::Io)?;
                        writer
                            .write_all(bytes)
                            .await
                            .map_err(|_| CaptureFailure::Io)?;
                        writer.shutdown().await.map_err(|_| CaptureFailure::Io)?;
                    }
                    drop(child_stdin.take());
                    Ok::<(), CaptureFailure>(())
                },
                async { child.wait().await.map_err(|_| CaptureFailure::Io) },
            )
        }));
        let captured = tokio::select! {
            biased;
            () = cancellation.cancelled() => None,
            captured = &mut operation => Some(captured),
        };
        let Some(captured) = captured else {
            containment.signal();
            let settled = timeout(TERMINATION_TIMEOUT, &mut operation).await.is_ok();
            drop(operation);
            if settled {
                terminate_remaining_process_tree(&mut containment);
            } else {
                terminate_process_tree(&mut child, &mut containment).await;
            }
            return Err(LocalInitError::new(LocalInitErrorCode::Cancelled));
        };
        drop(operation);
        let (stdout, _stderr, (), status) = match captured {
            Ok(Ok(result)) => result,
            _ => {
                terminate_process_tree(&mut child, &mut containment).await;
                return Err(engine_unavailable());
            }
        };
        terminate_remaining_process_tree(&mut containment);
        if !status.success() {
            return Err(reset_required());
        }
        if selection.connection_host() != FIXED_DOCKER_HOST {
            return Err(engine_unavailable());
        }
        Ok(stdout)
    }
}

fn append_step(step: &ComposeStep<'_>, arguments: &mut Vec<String>) -> Duration {
    match step {
        ComposeStep::Validate => {
            arguments.extend(["config", "--quiet"].map(str::to_owned));
            Duration::from_secs(15)
        }
        ComposeStep::UpDependencies => {
            arguments.extend(
                [
                    "up",
                    "--detach",
                    "--pull",
                    "never",
                    "--no-build",
                    "--wait",
                    "--wait-timeout",
                    "120",
                    "--no-deps",
                    "postgres",
                    "rustfs",
                ]
                .map(str::to_owned),
            );
            Duration::from_mins(3)
        }
        ComposeStep::UpControl => {
            arguments.extend(
                [
                    "up",
                    "--detach",
                    "--pull",
                    "never",
                    "--no-build",
                    "--wait",
                    "--wait-timeout",
                    "120",
                    "--no-deps",
                    "automata",
                ]
                .map(str::to_owned),
            );
            Duration::from_mins(3)
        }
        ComposeStep::UpRelay => {
            arguments.extend(
                [
                    "up",
                    "--detach",
                    "--pull",
                    "never",
                    "--no-build",
                    "--wait",
                    "--wait-timeout",
                    "120",
                    "--no-deps",
                    "engine-relay",
                ]
                .map(str::to_owned),
            );
            Duration::from_mins(3)
        }
        ComposeStep::UpRunner => {
            arguments.extend(
                [
                    "up",
                    "--detach",
                    "--pull",
                    "never",
                    "--no-build",
                    "--wait",
                    "--wait-timeout",
                    "120",
                    "--no-deps",
                    "runner",
                ]
                .map(str::to_owned),
            );
            Duration::from_mins(3)
        }
        ComposeStep::RunOneOff {
            service,
            container_name,
        } => {
            arguments.extend(
                [
                    "--profile",
                    "automata-lifecycle",
                    "run",
                    "--detach",
                    "--pull",
                    "never",
                    "--no-build",
                    "--no-deps",
                    "--name",
                    container_name,
                    service,
                ]
                .into_iter()
                .map(ToOwned::to_owned),
            );
            Duration::from_secs(30)
        }
        ComposeStep::StopRunner => {
            arguments.extend(["stop", "--timeout", "30", "runner"].map(str::to_owned));
            Duration::from_secs(45)
        }
        ComposeStep::Down => {
            arguments.extend(["down", "--remove-orphans", "--timeout", "30"].map(str::to_owned));
            Duration::from_mins(2)
        }
        ComposeStep::ProjectIds => {
            arguments.extend(["ps", "--all", "--quiet", "--no-trunc"].map(str::to_owned));
            Duration::from_secs(15)
        }
    }
}

fn resolve_docker_executable() -> Result<PathBuf, LocalInitError> {
    let path = std::env::var_os("PATH").ok_or_else(engine_unavailable)?;
    for directory in std::env::split_paths(&path) {
        if !directory.is_absolute() {
            continue;
        }
        let candidate = directory.join(OsStr::new("docker"));
        let Ok(metadata) = candidate.metadata() else {
            continue;
        };
        if metadata.is_file() && metadata.mode() & 0o111 != 0 {
            let canonical = candidate.canonicalize().map_err(|_| engine_unavailable())?;
            exact_executable_metadata(&canonical)?;
            return Ok(canonical);
        }
    }
    Err(engine_unavailable())
}

fn exact_executable_metadata(path: &Path) -> Result<std::fs::Metadata, LocalInitError> {
    if !path.is_absolute() {
        return Err(engine_unavailable());
    }
    let metadata = path.symlink_metadata().map_err(|_| engine_unavailable())?;
    let euid = rustix::process::geteuid().as_raw();
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.uid() != 0 && metadata.uid() != euid
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(engine_unavailable());
    }
    Ok(metadata)
}

#[derive(Deserialize)]
struct ComposeVersion {
    version: String,
}

fn engine_unavailable() -> LocalInitError {
    LocalInitError::new(LocalInitErrorCode::EngineUnavailable)
}

fn reset_required() -> LocalInitError {
    LocalInitError::new(LocalInitErrorCode::ResetRequired)
}
