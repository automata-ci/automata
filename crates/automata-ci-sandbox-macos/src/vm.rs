use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::mpsc::{self, RecvTimeoutError},
    time::{Duration, Instant},
};

use automata_ci_execution::{
    Cancellation, ExecutionError, ExecutionErrorKind, ExecutionStage, OperationId, ResourceLimits,
    TargetPath,
};
use automata_ci_sandbox_guest::{
    GUEST_PROTOCOL_VERSION, GuestRequest, GuestResponse, GuestTermination, MAX_GUEST_FRAME_BYTES,
    decode_frame, encode_frame,
};
use serde::{Deserialize, Serialize};

use crate::{
    provider::MacosVirtualizationProviderOptions,
    template::{VerifiedTemplate, verify_helper},
};

const HOST_HELPER_PROTOCOL_VERSION: u16 = 2;
const CONTROL_POLL_INTERVAL: Duration = Duration::from_millis(25);
const TRANSPORT_GRACE: Duration = Duration::from_secs(10);
const PREPARE_TIMEOUT: Duration = Duration::from_secs(30);
const PREPARE_OUTPUT_BYTES: usize = 16 * 1024;

const fn current_host_helper_protocol(protocol: u16) -> bool {
    protocol == HOST_HELPER_PROTOCOL_VERSION
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct LaunchRequest<'a> {
    protocol: u16,
    attempt_id: &'a str,
    source_disk_image: &'a Path,
    source_auxiliary_storage: &'a Path,
    attempt_directory: &'a Path,
    hardware_model_base64: &'a str,
    cpu_count: u32,
    memory_bytes: u64,
    process_limit: u32,
    guest_port: u32,
    guest_protocol: u16,
    expected_profile_id: &'a str,
    guest_agent_sha256: String,
    expected_macos_version: &'a str,
    expected_macos_build: &'a str,
    expected_architecture: &'static str,
    expected_job_uid: u32,
    expected_job_gid: u32,
    expected_process_limit: u32,
    minimum_cpu_count: u32,
    minimum_memory_bytes: u64,
    handshake_nonce: &'a str,
    boot_timeout_millis: u64,
    stop_timeout_millis: u64,
    runtime_proxy_socket: Option<&'a Path>,
}

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum LaunchResponse {
    Ready {
        protocol: u16,
    },
    Rejected {
        protocol: u16,
        kind: HelperRejection,
    },
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HelperRejection {
    InvalidRequest,
    CloneFailed,
    InvalidConfiguration,
    StartFailed,
    HandshakeFailed,
    ResourceConfigurationFailed,
}

pub(crate) struct VmProcess {
    child: Child,
    input: Option<ChildStdin>,
    output: ChildStdout,
    stop_timeout: Duration,
}

struct LaunchGuard(Option<Child>);

impl LaunchGuard {
    fn child(&mut self) -> io::Result<&mut Child> {
        self.0.as_mut().ok_or_else(io_failure)
    }

    fn disarm(mut self) -> io::Result<Child> {
        self.0.take().ok_or_else(io_failure)
    }
}

impl Drop for LaunchGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl std::fmt::Debug for VmProcess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VmProcess")
            .field("process_id", &self.child.id())
            .finish_non_exhaustive()
    }
}

impl VmProcess {
    pub(crate) fn launch(
        options: &MacosVirtualizationProviderOptions,
        template: &VerifiedTemplate,
        attempt_id: &str,
        attempt_directory: &Path,
        runtime_proxy_socket: Option<&Path>,
        resources: ResourceLimits,
        cancellation: &dyn Cancellation,
    ) -> io::Result<Self> {
        verify_helper(
            options.helper_executable(),
            options.helper_digest(),
            options.helper_code_requirement(),
        )?;
        let lock_path = attempt_directory.join(".vm.lock");
        let child = Command::new(options.helper_executable())
            .args(["run", "--lock"])
            .arg(&lock_path)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let mut guard = LaunchGuard(Some(child));
        let mut input = guard.child()?.stdin.take().ok_or_else(io_failure)?;
        let mut output = guard.child()?.stdout.take().ok_or_else(io_failure)?;
        let cpu_count = resources.cpu_millis() / 1_000;
        let nonce = automata_ci_execution::OperationId::new().to_string();
        let request = LaunchRequest {
            protocol: HOST_HELPER_PROTOCOL_VERSION,
            attempt_id,
            source_disk_image: &template.disk_image,
            source_auxiliary_storage: &template.auxiliary_storage,
            attempt_directory,
            hardware_model_base64: &template.hardware_model_base64,
            cpu_count,
            memory_bytes: resources.memory_bytes(),
            process_limit: resources.pids(),
            guest_port: template.guest_port,
            guest_protocol: GUEST_PROTOCOL_VERSION,
            expected_profile_id: template.profile_id.as_str(),
            guest_agent_sha256: template.guest_agent_digest.to_string(),
            expected_macos_version: &template.macos_version,
            expected_macos_build: &template.macos_build,
            expected_architecture: "arm64",
            expected_job_uid: template.job_uid,
            expected_job_gid: template.job_gid,
            expected_process_limit: template.process_limit,
            minimum_cpu_count: template.minimum_cpu_count,
            minimum_memory_bytes: template.minimum_memory_bytes,
            handshake_nonce: &nonce,
            boot_timeout_millis: duration_millis(options.boot_timeout())?,
            stop_timeout_millis: duration_millis(options.stop_timeout())?,
            runtime_proxy_socket,
        };
        write_json_frame(&mut input, &request)?;
        let response = read_frame_controlled(
            &mut output,
            guard.child()?,
            options.boot_timeout() + TRANSPORT_GRACE,
            cancellation,
        )?;
        let response: LaunchResponse = decode_json_frame(&response)?;
        match response {
            LaunchResponse::Ready { protocol } if current_host_helper_protocol(protocol) => {
                Ok(Self {
                    child: guard.disarm()?,
                    input: Some(input),
                    output,
                    stop_timeout: options.stop_timeout(),
                })
            }
            LaunchResponse::Ready { .. } => Err(io::Error::from(io::ErrorKind::PermissionDenied)),
            LaunchResponse::Rejected { protocol, kind } => {
                let error_kind = if current_host_helper_protocol(protocol) {
                    kind.error_kind()
                } else {
                    io::ErrorKind::InvalidData
                };
                Err(io::Error::from(error_kind))
            }
        }
    }

    pub(crate) fn exchange(
        &mut self,
        request: &GuestRequest,
        timeout: Duration,
        cancellation: &dyn Cancellation,
        stage: ExecutionStage,
    ) -> Result<GuestResponse, ExecutionError> {
        let input = self
            .input
            .as_mut()
            .ok_or_else(|| execution_error(ExecutionErrorKind::InvalidState, stage))?;
        let frame = encode_frame(request)
            .map_err(|_| execution_error(ExecutionErrorKind::BackendRejected, stage))?;
        input
            .write_all(&frame)
            .and_then(|()| input.flush())
            .map_err(|_| execution_error(ExecutionErrorKind::BackendRejected, stage))?;
        let frame = read_frame_controlled(
            &mut self.output,
            &mut self.child,
            timeout + TRANSPORT_GRACE,
            cancellation,
        )
        .map_err(|error| {
            let kind = match error.kind() {
                io::ErrorKind::Interrupted => ExecutionErrorKind::Cancelled,
                io::ErrorKind::TimedOut => ExecutionErrorKind::TimedOut,
                _ => ExecutionErrorKind::BackendRejected,
            };
            execution_error(kind, stage)
        })?;
        let response: GuestResponse = decode_frame(&frame)
            .map_err(|_| execution_error(ExecutionErrorKind::BackendRejected, stage))?;
        if response.protocol() != GUEST_PROTOCOL_VERSION {
            return Err(execution_error(ExecutionErrorKind::BackendRejected, stage));
        }
        Ok(response)
    }

    pub(crate) fn prepare_directories(
        &mut self,
        workspace: &TargetPath,
        scratch: &TargetPath,
        cancellation: &dyn Cancellation,
    ) -> io::Result<()> {
        let request = GuestRequest::Exec {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: OperationId::new().to_string(),
            program: "/usr/bin/install".to_owned(),
            arguments: vec![
                "-d".to_owned(),
                "-m".to_owned(),
                "0700".to_owned(),
                "--".to_owned(),
                workspace.as_str().to_owned(),
                scratch.as_str().to_owned(),
            ],
            environment: BTreeMap::default(),
            working_directory: "/".to_owned(),
            timeout_millis: duration_millis(PREPARE_TIMEOUT)?,
            output_limit: PREPARE_OUTPUT_BYTES,
            process_limit: None,
        };
        let response = self
            .exchange(
                &request,
                PREPARE_TIMEOUT,
                cancellation,
                ExecutionStage::Exec,
            )
            .map_err(execution_io_error)?;
        match response {
            GuestResponse::Exec {
                termination: GuestTermination::Exited(0),
                truncated: false,
                ..
            } => Ok(()),
            _ => Err(io::Error::from(io::ErrorKind::PermissionDenied)),
        }
    }

    pub(crate) fn stop(&mut self) -> io::Result<()> {
        self.input.take();
        let deadline = Instant::now() + self.stop_timeout;
        loop {
            if self.child.try_wait()?.is_some() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                self.child.kill()?;
                let _ = self.child.wait()?;
                return Ok(());
            }
            std::thread::sleep(CONTROL_POLL_INTERVAL);
        }
    }
}

impl HelperRejection {
    const fn error_kind(self) -> io::ErrorKind {
        match self {
            Self::InvalidRequest | Self::InvalidConfiguration => io::ErrorKind::InvalidData,
            Self::CloneFailed => io::ErrorKind::StorageFull,
            Self::StartFailed | Self::HandshakeFailed | Self::ResourceConfigurationFailed => {
                io::ErrorKind::ConnectionAborted
            }
        }
    }
}

impl Drop for VmProcess {
    fn drop(&mut self) {
        self.input.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write_json_frame(writer: &mut impl Write, value: &impl Serialize) -> io::Result<()> {
    let payload = serde_json::to_vec(value).map_err(|_| invalid_data())?;
    if payload.is_empty() || payload.len() > 64 * 1024 {
        return Err(invalid_data());
    }
    let length = u32::try_from(payload.len()).map_err(|_| invalid_data())?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()
}

fn decode_json_frame<T: for<'de> Deserialize<'de>>(frame: &[u8]) -> io::Result<T> {
    let payload = framed_payload(frame, 64 * 1024)?;
    serde_json::from_slice(payload).map_err(|_| invalid_data())
}

fn read_frame_controlled(
    reader: &mut (impl Read + Send),
    child: &mut Child,
    timeout: Duration,
    cancellation: &dyn Cancellation,
) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    std::thread::scope(|scope| {
        let (sender, receiver) = mpsc::sync_channel(1);
        scope.spawn(move || {
            let _ = sender.send(read_frame(reader));
        });
        loop {
            match receiver.recv_timeout(CONTROL_POLL_INTERVAL) {
                Ok(result) => return result,
                Err(RecvTimeoutError::Disconnected) => return Err(io_failure()),
                Err(RecvTimeoutError::Timeout)
                    if cancellation.disposition().requires_termination() =>
                {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                Err(RecvTimeoutError::Timeout) if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(io::Error::from(io::ErrorKind::TimedOut));
                }
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
    })
}

fn read_frame(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut header = [0_u8; 4];
    reader.read_exact(&mut header)?;
    let length = usize::try_from(u32::from_be_bytes(header)).map_err(|_| invalid_data())?;
    if length == 0 || length > MAX_GUEST_FRAME_BYTES {
        return Err(invalid_data());
    }
    let mut frame = Vec::with_capacity(length + 4);
    frame.extend_from_slice(&header);
    frame.resize(length + 4, 0);
    reader.read_exact(&mut frame[4..])?;
    Ok(frame)
}

fn framed_payload(frame: &[u8], maximum: usize) -> io::Result<&[u8]> {
    let length = frame
        .get(..4)
        .and_then(|header| <[u8; 4]>::try_from(header).ok())
        .map(u32::from_be_bytes)
        .and_then(|length| usize::try_from(length).ok())
        .ok_or_else(invalid_data)?;
    if length == 0 || length > maximum || frame.len() != length + 4 {
        return Err(invalid_data());
    }
    Ok(&frame[4..])
}

fn duration_millis(duration: Duration) -> io::Result<u64> {
    u64::try_from(duration.as_millis()).map_err(|_| invalid_data())
}

fn invalid_data() -> io::Error {
    io::Error::from(io::ErrorKind::InvalidData)
}

fn io_failure() -> io::Error {
    io::Error::from(io::ErrorKind::BrokenPipe)
}

fn execution_io_error(error: ExecutionError) -> io::Error {
    let kind = match error.kind() {
        ExecutionErrorKind::Cancelled => io::ErrorKind::Interrupted,
        ExecutionErrorKind::TimedOut => io::ErrorKind::TimedOut,
        _ => io::ErrorKind::PermissionDenied,
    };
    io::Error::from(kind)
}

const fn execution_error(kind: ExecutionErrorKind, stage: ExecutionStage) -> ExecutionError {
    ExecutionError::new(kind, stage)
}

#[cfg(test)]
mod tests {
    use super::{HOST_HELPER_PROTOCOL_VERSION, current_host_helper_protocol};

    #[test]
    fn host_helper_accepts_only_the_current_protocol() {
        assert!(current_host_helper_protocol(HOST_HELPER_PROTOCOL_VERSION));
        assert!(!current_host_helper_protocol(
            HOST_HELPER_PROTOCOL_VERSION + 1
        ));
    }
}
