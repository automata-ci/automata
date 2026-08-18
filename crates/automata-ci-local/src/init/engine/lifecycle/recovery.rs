//! Daemon-generation attestation and event-fenced stopped-lock recovery primitives.

use super::{
    common::{
        AddressFamily, BTreeMap, BTreeSet, BodyExt, Bytes, CancellationToken, Deserialize, Docker,
        ENGINE_GENERATION_PROBE_TIMEOUT, ENGINE_GENERATION_REQUEST,
        ENGINE_GENERATION_RESPONSE_MAXIMUM_BYTES, ENGINE_INFO_MAXIMUM_BYTES, ENGINE_INFO_URI,
        ENGINE_TIMEOUT, Empty, ErrorKind, EventMessage, EventMessageTypeEnum, HashMap, InitEngine,
        IoSliceMut, JoinHandle, LABEL_ENGINE_BOOT_ID, LABEL_ENGINE_PID, LABEL_ENGINE_START_TICKS,
        LocalInitError, LocalInitErrorCode, MaybeUninit, RECOVERY_ENGINE_QUIET_DEADLINE,
        RECOVERY_ENGINE_QUIET_PERIOD, RECOVERY_EVENT_CHUNK_MAXIMUM_BYTES,
        RECOVERY_EVENT_MAXIMUM_BYTES, RECOVERY_EVENT_URI, Read, RecvAncillaryBuffer,
        RecvAncillaryMessage, RecvFlags, RemoveContainerOptionsBuilder, Request, SocketAddrUnix,
        SocketFlags, SocketType, StatusCode, TokioIo, TokioUnixStream, UnixStream, Write,
        engine_resource_mismatch, engine_unavailable, exact_container_id_text, fs, http1, mpsc,
    },
    validation::lifecycle_cancellation_checkpoint,
};

#[derive(Clone, Debug, Deserialize)]
pub(super) struct LifecycleDaemonInfo {
    #[serde(rename = "SecurityOptions", default)]
    pub(super) security_options: Vec<String>,
    #[serde(rename = "MemoryLimit")]
    pub(super) memory_limit: bool,
    #[serde(rename = "SwapLimit")]
    pub(super) swap_limit: bool,
    #[serde(rename = "CpuCfsPeriod")]
    pub(super) cpu_cfs_period: bool,
    #[serde(rename = "CpuCfsQuota")]
    pub(super) cpu_cfs_quota: bool,
    #[serde(rename = "PidsLimit")]
    pub(super) pids_limit: bool,
    #[serde(rename = "CgroupVersion")]
    pub(super) cgroup_version: String,
    #[serde(rename = "LiveRestoreEnabled")]
    pub(super) live_restore_enabled: bool,
    #[serde(rename = "DefaultRuntime")]
    pub(super) default_runtime: String,
    #[serde(rename = "DefaultUlimits", default)]
    pub(super) default_ulimits: Option<HashMap<String, serde_json::Value>>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct EngineDaemonGeneration {
    pub(super) boot_id: uuid::Uuid,
    pub(super) pid: u32,
    pub(super) start_ticks: u64,
}

pub(super) enum RecoveryEventSignal {
    Event(EventMessage),
    Failed,
}

/// One fixed-socket event subscription spanning an exceptional stopped-lock
/// recovery from its first census through the exact destroy/absence proof.
///
/// The subscription starts at the daemon's bounded history (`since=1`). Once
/// the HTTP response headers arrive, Moby's atomic history/live registration
/// makes every event in the header-to-subscribe interval replayable. The exact
/// destroy event is the trailing catch-up barrier for all earlier activity.
pub(super) struct RecoveryEventFence {
    events: mpsc::Receiver<RecoveryEventSignal>,
    parser: JoinHandle<()>,
    connection: JoinHandle<()>,
    stopped_generation: EngineDaemonGeneration,
    replacement_generation: EngineDaemonGeneration,
    cancellation: Option<CancellationToken>,
}

impl Drop for RecoveryEventFence {
    fn drop(&mut self) {
        self.parser.abort();
        self.connection.abort();
    }
}

impl RecoveryEventFence {
    pub(super) async fn open(
        stopped_generation: EngineDaemonGeneration,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Self, LocalInitError> {
        if let Some(cancellation) = cancellation {
            lifecycle_cancellation_checkpoint(cancellation)?;
        }
        prove_daemon_generation_absent(&stopped_generation)?;
        let replacement_generation = current_engine_daemon_generation()?;
        validate_replacement_daemon_generation(
            &stopped_generation,
            &replacement_generation,
            &replacement_generation,
        )?;

        let stream = TokioUnixStream::connect("/var/run/docker.sock")
            .await
            .map_err(|_| engine_unavailable())?;
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|_| engine_unavailable())?;
        let connection = tokio::spawn(async move {
            let _closed = connection.await;
        });
        let request = Request::builder()
            .method("GET")
            .uri(RECOVERY_EVENT_URI)
            .header("host", "docker")
            .header("connection", "close")
            .body(Empty::<Bytes>::new())
            .map_err(|_| engine_unavailable())?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| engine_unavailable())?;
        if response.status() != StatusCode::OK
            || response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .is_none_or(|value| !value.starts_with("application/json"))
        {
            return Err(engine_unavailable());
        }
        drop(sender);

        let (event_sender, events) = mpsc::channel(1);
        let parser = tokio::spawn(forward_recovery_events(response.into_body(), event_sender));
        let mut fence = Self {
            events,
            parser,
            connection,
            stopped_generation,
            replacement_generation,
            cancellation: cancellation.cloned(),
        };
        fence.await_initial_quiet().await?;
        fence.verify_generation()?;
        Ok(fence)
    }

    pub(super) async fn await_initial_quiet(&mut self) -> Result<(), LocalInitError> {
        let started = tokio::time::Instant::now();
        let mut quiet = Box::pin(tokio::time::sleep(RECOVERY_ENGINE_QUIET_PERIOD));
        let mut deadline = Box::pin(tokio::time::sleep_until(
            started + RECOVERY_ENGINE_QUIET_DEADLINE,
        ));
        loop {
            tokio::select! {
                biased;
                signal = self.events.recv() => match signal {
                    Some(RecoveryEventSignal::Event(_)) => quiet.as_mut().reset(
                        tokio::time::Instant::now() + RECOVERY_ENGINE_QUIET_PERIOD,
                    ),
                    Some(RecoveryEventSignal::Failed) | None => return Err(engine_unavailable()),
                },
                () = recovery_cancellation(self.cancellation.as_ref()) => {
                    return Err(LocalInitError::new(LocalInitErrorCode::Cancelled));
                }
                () = &mut deadline => {
                    return Err(LocalInitError::new(LocalInitErrorCode::OperationInProgress));
                }
                () = &mut quiet => return Ok(()),
            }
        }
    }

    pub(super) async fn guard<T>(
        &mut self,
        operation: impl std::future::Future<Output = Result<T, LocalInitError>>,
    ) -> Result<T, LocalInitError> {
        tokio::pin!(operation);
        tokio::select! {
            biased;
            signal = self.events.recv() => match signal {
                Some(RecoveryEventSignal::Event(_)) => {
                    Err(LocalInitError::new(LocalInitErrorCode::OperationInProgress))
                }
                Some(RecoveryEventSignal::Failed) | None => Err(engine_unavailable()),
            },
            () = recovery_cancellation(self.cancellation.as_ref()) => {
                Err(LocalInitError::new(LocalInitErrorCode::Cancelled))
            }
            result = &mut operation => result,
        }
    }

    pub(super) async fn delete_exact_container(
        &mut self,
        docker: &Docker,
        expected_id: &str,
    ) -> Result<bool, LocalInitError> {
        if !exact_container_id_text(expected_id) {
            return Err(engine_resource_mismatch());
        }
        if self
            .cancellation
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
        {
            return Err(LocalInitError::new(LocalInitErrorCode::Cancelled));
        }
        self.verify_generation()?;
        let options = RemoveContainerOptionsBuilder::default()
            .force(false)
            .v(false)
            .link(false)
            .build();
        let removal = tokio::time::timeout(
            ENGINE_TIMEOUT,
            docker.remove_container(expected_id, Some(options)),
        );
        tokio::pin!(removal);
        let mut removal_complete = false;
        let mut deadline = Box::pin(tokio::time::sleep(ENGINE_TIMEOUT));
        loop {
            tokio::select! {
                biased;
                signal = self.events.recv() => match signal {
                    Some(RecoveryEventSignal::Event(event))
                        if exact_destroy_event(&event, expected_id) => break,
                    Some(RecoveryEventSignal::Event(_)) => {
                        return Err(LocalInitError::new(LocalInitErrorCode::OperationInProgress));
                    }
                    Some(RecoveryEventSignal::Failed) | None => return Err(engine_unavailable()),
                },
                _untrusted = &mut removal, if !removal_complete => {
                    removal_complete = true;
                }
                () = &mut deadline => return Err(engine_resource_mismatch()),
            }
        }
        Ok(self
            .cancellation
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled))
    }

    pub(super) fn verify_generation(&self) -> Result<(), LocalInitError> {
        let repeated = current_engine_daemon_generation()?;
        validate_replacement_daemon_generation(
            &self.stopped_generation,
            &self.replacement_generation,
            &repeated,
        )?;
        prove_daemon_generation_absent(&self.stopped_generation)
    }
}

pub(super) async fn recovery_cancellation(cancellation: Option<&CancellationToken>) {
    match cancellation {
        Some(cancellation) => cancellation.cancelled().await,
        None => std::future::pending().await,
    }
}

pub(super) async fn forward_recovery_events(
    mut body: hyper::body::Incoming,
    sender: mpsc::Sender<RecoveryEventSignal>,
) {
    let mut buffered = Vec::new();
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else {
            let _ = sender.send(RecoveryEventSignal::Failed).await;
            return;
        };
        let Ok(data) = frame.into_data() else {
            let _ = sender.send(RecoveryEventSignal::Failed).await;
            return;
        };
        if data.len() > RECOVERY_EVENT_CHUNK_MAXIMUM_BYTES {
            let _ = sender.send(RecoveryEventSignal::Failed).await;
            return;
        }
        buffered.extend_from_slice(&data);
        while let Some(newline) = buffered.iter().position(|byte| *byte == b'\n') {
            let line = buffered.drain(..=newline).collect::<Vec<_>>();
            let payload = &line[..line.len().saturating_sub(1)];
            if payload.is_empty() || payload.len() > RECOVERY_EVENT_MAXIMUM_BYTES {
                let _ = sender.send(RecoveryEventSignal::Failed).await;
                return;
            }
            let Ok(event) = serde_json::from_slice(payload) else {
                let _ = sender.send(RecoveryEventSignal::Failed).await;
                return;
            };
            if sender
                .send(RecoveryEventSignal::Event(event))
                .await
                .is_err()
            {
                return;
            }
        }
        if buffered.len() > RECOVERY_EVENT_MAXIMUM_BYTES {
            let _ = sender.send(RecoveryEventSignal::Failed).await;
            return;
        }
    }
    let _ = sender.send(RecoveryEventSignal::Failed).await;
}

pub(super) fn exact_destroy_event(event: &EventMessage, expected_id: &str) -> bool {
    event.typ == Some(EventMessageTypeEnum::CONTAINER)
        && event.action.as_deref() == Some("destroy")
        && event.actor.as_ref().and_then(|actor| actor.id.as_deref()) == Some(expected_id)
}

pub(super) async fn load_lifecycle_daemon_info() -> Result<LifecycleDaemonInfo, LocalInitError> {
    tokio::time::timeout(ENGINE_TIMEOUT, async {
        let stream = TokioUnixStream::connect("/var/run/docker.sock")
            .await
            .map_err(|_| engine_unavailable())?;
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|_| engine_unavailable())?;
        let connection = tokio::spawn(async move {
            let _closed = connection.await;
        });
        let request = Request::builder()
            .method("GET")
            .uri(ENGINE_INFO_URI)
            .header("host", "docker")
            .header("connection", "close")
            .body(Empty::<Bytes>::new())
            .map_err(|_| engine_unavailable())?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| engine_unavailable())?;
        if response.status() != StatusCode::OK
            || response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .is_none_or(|value| !value.starts_with("application/json"))
        {
            return Err(engine_unavailable());
        }
        drop(sender);
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            let data = frame
                .map_err(|_| engine_unavailable())?
                .into_data()
                .map_err(|_| engine_unavailable())?;
            if data.len() > ENGINE_INFO_MAXIMUM_BYTES.saturating_sub(bytes.len()) {
                return Err(engine_unavailable());
            }
            bytes.extend_from_slice(&data);
        }
        connection.abort();
        serde_json::from_slice(&bytes).map_err(|_| engine_unavailable())
    })
    .await
    .map_err(|_| engine_unavailable())?
}

impl InitEngine<'_> {
    /// Qualifies daemon-wide defaults that cannot be overridden safely by the
    /// closed lifecycle topology. This runs before any lifecycle mutation.
    pub(in crate::init) async fn preflight_lifecycle_daemon(&self) -> Result<(), LocalInitError> {
        self.verify_selected_engine().await?;
        let info = load_lifecycle_daemon_info().await?;
        validate_lifecycle_daemon_info(&info)?;
        self.verify_selected_engine().await
    }

    pub(super) async fn begin_stopped_lock_recovery_event_fence(
        &self,
        stopped_lock_id: &str,
        cancellation: Option<&CancellationToken>,
    ) -> Result<RecoveryEventFence, LocalInitError> {
        if !exact_container_id_text(stopped_lock_id) {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await?;
        let stopped = self
            .inspect_container(stopped_lock_id)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        if stopped.state.as_ref().and_then(|state| state.running) != Some(false) {
            return Err(engine_resource_mismatch());
        }
        let labels = stopped
            .config
            .as_ref()
            .and_then(|config| config.labels.as_ref())
            .ok_or_else(engine_resource_mismatch)?;
        let labels = labels
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<BTreeMap<_, _>>();
        let stopped_generation = daemon_generation_from_labels(&labels)?;
        let mut fence = RecoveryEventFence::open(stopped_generation, cancellation).await?;
        fence.guard(self.verify_selected_engine()).await?;
        Ok(fence)
    }
}

pub(super) fn validate_lifecycle_daemon_info(
    info: &LifecycleDaemonInfo,
) -> Result<(), LocalInitError> {
    let security = info
        .security_options
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let required = BTreeSet::from([
        "name=cgroupns",
        "name=seccomp,profile=builtin",
        "name=userns",
    ]);
    let allowed = BTreeSet::from([
        "name=cgroupns",
        "name=no-new-privileges",
        "name=seccomp,profile=builtin",
        "name=userns",
    ]);
    if security.len() != info.security_options.len()
        || !required.is_subset(&security)
        || !security.is_subset(&allowed)
        || !info.memory_limit
        || !info.swap_limit
        || !info.cpu_cfs_period
        || !info.cpu_cfs_quota
        || !info.pids_limit
        || info.cgroup_version != "2"
        || info.live_restore_enabled
        || info.default_runtime != "runc"
        || info
            .default_ulimits
            .as_ref()
            .is_some_and(|limits| !limits.is_empty())
    {
        Err(engine_unavailable())
    } else {
        Ok(())
    }
}
pub(super) fn daemon_generation_from_labels(
    labels: &BTreeMap<String, String>,
) -> Result<EngineDaemonGeneration, LocalInitError> {
    let boot_text = labels
        .get(LABEL_ENGINE_BOOT_ID)
        .ok_or_else(engine_resource_mismatch)?;
    let boot_id = uuid::Uuid::parse_str(boot_text)
        .ok()
        .filter(|value| value.hyphenated().to_string() == *boot_text)
        .ok_or_else(engine_resource_mismatch)?;
    let pid_text = labels
        .get(LABEL_ENGINE_PID)
        .ok_or_else(engine_resource_mismatch)?;
    let pid = pid_text
        .parse::<u32>()
        .ok()
        .filter(|value| *value > 0 && value.to_string() == *pid_text)
        .ok_or_else(engine_resource_mismatch)?;
    let start_text = labels
        .get(LABEL_ENGINE_START_TICKS)
        .ok_or_else(engine_resource_mismatch)?;
    let start_ticks = start_text
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0 && value.to_string() == *start_text)
        .ok_or_else(engine_resource_mismatch)?;
    Ok(EngineDaemonGeneration {
        boot_id,
        pid,
        start_ticks,
    })
}

pub(super) fn current_engine_daemon_generation() -> Result<EngineDaemonGeneration, LocalInitError> {
    let first = probe_engine_daemon_generation()?;
    let repeated = probe_engine_daemon_generation()?;
    if first != repeated {
        return Err(engine_unavailable());
    }
    Ok(first)
}

/// Identifies the process which actually wrote a qualified Docker API
/// response. `SO_PEERCRED` is deliberately insufficient here: with systemd
/// socket activation it identifies PID 1, which owns the listening socket,
/// rather than the `dockerd` process accepting and serving the request.
pub(super) fn probe_engine_daemon_generation() -> Result<EngineDaemonGeneration, LocalInitError> {
    let socket = rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| engine_unavailable())?;
    rustix::net::sockopt::set_socket_passcred(&socket, true).map_err(|_| engine_unavailable())?;
    let address = SocketAddrUnix::new("/var/run/docker.sock").map_err(|_| engine_unavailable())?;
    rustix::net::connect(&socket, &address).map_err(|_| engine_unavailable())?;
    let mut socket = UnixStream::from(socket);
    socket
        .set_read_timeout(Some(ENGINE_GENERATION_PROBE_TIMEOUT))
        .map_err(|_| engine_unavailable())?;
    socket
        .set_write_timeout(Some(ENGINE_GENERATION_PROBE_TIMEOUT))
        .map_err(|_| engine_unavailable())?;
    socket
        .write_all(ENGINE_GENERATION_REQUEST)
        .map_err(|_| engine_unavailable())?;

    let mut response = [0_u8; ENGINE_GENERATION_RESPONSE_MAXIMUM_BYTES];
    let (received, credentials) = {
        let mut iov = [IoSliceMut::new(&mut response)];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmCredentials(1))];
        let mut ancillary = RecvAncillaryBuffer::new(&mut space);
        let received =
            rustix::net::recvmsg(&socket, &mut iov, &mut ancillary, RecvFlags::CMSG_CLOEXEC)
                .map_err(|_| engine_unavailable())?;
        let mut credentials = None;
        for message in ancillary.drain() {
            match message {
                RecvAncillaryMessage::ScmCredentials(value) if credentials.is_none() => {
                    credentials = Some(value);
                }
                _ => return Err(engine_unavailable()),
            }
        }
        (received.bytes, credentials.ok_or_else(engine_unavailable)?)
    };
    if received == 0 || received >= response.len() {
        return Err(engine_unavailable());
    }
    let mut response = response[..received].to_vec();
    let mut remaining = [0_u8; 512];
    loop {
        match socket.read(&mut remaining) {
            Ok(0) => break,
            Ok(count)
                if response
                    .len()
                    .checked_add(count)
                    .is_some_and(|length| length <= ENGINE_GENERATION_RESPONSE_MAXIMUM_BYTES) =>
            {
                response.extend_from_slice(&remaining[..count]);
            }
            Ok(_) | Err(_) => return Err(engine_unavailable()),
        }
    }
    validate_engine_generation_response(&response)?;

    let pid = u32::try_from(credentials.pid.as_raw_pid()).map_err(|_| engine_unavailable())?;
    if credentials.uid.as_raw() != 0 || credentials.gid.as_raw() != 0 || pid == 0 {
        return Err(engine_unavailable());
    }
    let boot_id = read_boot_id().map_err(|()| engine_unavailable())?;
    let start_ticks = read_process_start_ticks(pid).map_err(|_| engine_unavailable())?;
    Ok(EngineDaemonGeneration {
        boot_id,
        pid,
        start_ticks,
    })
}

pub(super) fn validate_engine_generation_response(response: &[u8]) -> Result<(), LocalInitError> {
    let (head, body) = response
        .split(|byte| *byte == b'\r')
        .next()
        .and_then(|status| {
            response
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|boundary| (status, &response[boundary + 4..]))
        })
        .ok_or_else(engine_unavailable)?;
    if !matches!(head, b"HTTP/1.0 200 OK" | b"HTTP/1.1 200 OK") || body != b"OK" {
        return Err(engine_unavailable());
    }
    Ok(())
}

pub(super) fn read_boot_id() -> Result<uuid::Uuid, ()> {
    let text = fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|_| ())?;
    let text = text.strip_suffix('\n').unwrap_or(&text);
    if text.len() != 36 {
        return Err(());
    }
    uuid::Uuid::parse_str(text)
        .ok()
        .filter(|value| value.hyphenated().to_string() == text)
        .ok_or(())
}

pub(super) fn read_process_start_ticks(pid: u32) -> Result<u64, ErrorKind> {
    let path = format!("/proc/{pid}/stat");
    let metadata = fs::metadata(&path).map_err(|error| error.kind())?;
    if metadata.len() > 16 * 1024 {
        return Err(ErrorKind::InvalidData);
    }
    let text = fs::read_to_string(path).map_err(|error| error.kind())?;
    let open = text.find(" (").ok_or(ErrorKind::InvalidData)?;
    if text[..open]
        .parse::<u32>()
        .ok()
        .is_none_or(|observed| observed != pid)
    {
        return Err(ErrorKind::InvalidData);
    }
    let close = text.rfind(") ").ok_or(ErrorKind::InvalidData)?;
    if close <= open + 1 {
        return Err(ErrorKind::InvalidData);
    }
    text[close + 2..]
        .split_ascii_whitespace()
        .nth(19)
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or(ErrorKind::InvalidData)
}

pub(super) fn prove_daemon_generation_absent(
    generation: &EngineDaemonGeneration,
) -> Result<(), LocalInitError> {
    let current_boot =
        read_boot_id().map_err(|()| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;
    daemon_generation_absence_from_observation(
        generation,
        current_boot,
        read_process_start_ticks(generation.pid),
    )
}

pub(super) fn daemon_generation_absence_from_observation(
    generation: &EngineDaemonGeneration,
    current_boot: uuid::Uuid,
    observed_start: Result<u64, ErrorKind>,
) -> Result<(), LocalInitError> {
    if current_boot != generation.boot_id {
        return Ok(());
    }
    match observed_start {
        Err(ErrorKind::NotFound) => Ok(()),
        Ok(start_ticks) if start_ticks != generation.start_ticks => Ok(()),
        Ok(_) | Err(_) => Err(LocalInitError::new(LocalInitErrorCode::ResetRequired)),
    }
}

pub(super) fn validate_replacement_daemon_generation(
    stopped: &EngineDaemonGeneration,
    replacement: &EngineDaemonGeneration,
    repeated: &EngineDaemonGeneration,
) -> Result<(), LocalInitError> {
    if replacement == stopped || repeated != replacement {
        Err(LocalInitError::new(LocalInitErrorCode::ResetRequired))
    } else {
        Ok(())
    }
}
