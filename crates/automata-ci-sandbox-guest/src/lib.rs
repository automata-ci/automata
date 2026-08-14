#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Versioned, framed transport used to keep command arguments and environment
//! values out of Kubernetes Pod specifications and exec request URLs.

use std::{collections::BTreeMap, fmt, io, path::Path};

#[cfg(unix)]
use std::{
    collections::VecDeque,
    process::Stdio,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

#[cfg(target_os = "linux")]
use std::os::{
    linux::net::SocketAddrExt as _,
    unix::net::{
        SocketAddr as StdSocketAddr, UnixListener as StdUnixListener, UnixStream as StdUnixStream,
    },
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use sha2::{Digest as _, Sha256};
use thiserror::Error;
#[cfg(unix)]
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    process::Command,
    sync::{mpsc, watch},
    task::JoinSet,
};

/// Current guest protocol version.
pub const GUEST_PROTOCOL_VERSION: u16 = 2;
/// Maximum encoded request or response frame.
pub const MAX_GUEST_FRAME_BYTES: usize = 32 * 1024 * 1024;
#[cfg(unix)]
const OUTPUT_CHUNK_BYTES: usize = 16 * 1024;
#[cfg(unix)]
const MAX_OUTPUT_DATA_RECORDS: usize = 65_534;
#[cfg(unix)]
const MAX_OPERATION_ID_BYTES: usize = 128;
#[cfg(unix)]
const MAX_TARGET_PATH_BYTES: usize = 4_096;
#[cfg(unix)]
const MAX_EXECUTION_ARGUMENTS: usize = 4_096;
#[cfg(unix)]
const MAX_EXECUTION_ARGV_BYTES: usize = 1024 * 1024;
#[cfg(unix)]
const MAX_ENVIRONMENT_VARIABLES: usize = 1_024;
#[cfg(unix)]
const MAX_ENVIRONMENT_NAME_BYTES: usize = 128;
#[cfg(unix)]
const MAX_ENVIRONMENT_VALUE_BYTES: usize = 1024 * 1024;
#[cfg(unix)]
const MAX_ENVIRONMENT_BYTES: usize = 4 * 1024 * 1024;
#[cfg(unix)]
const MAX_COMMAND_TIMEOUT_MILLIS: u64 = 24 * 60 * 60 * 1_000;
#[cfg(unix)]
const MAX_EXECUTION_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
#[cfg(unix)]
const MAX_REPLAY_ENTRIES: usize = 256;
#[cfg(unix)]
const MAX_REPLAY_BYTES: usize = 64 * 1024 * 1024;

/// One operation sent through anonymous stdin to the sandbox guest.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum GuestRequest {
    /// Proves the exact guest agent and sealed template before job traffic.
    Hello {
        /// Protocol version selected by the caller.
        protocol: u16,
        /// Idempotent operation identifier.
        operation_id: String,
        /// Fresh caller nonce returned verbatim by the guest.
        nonce: String,
    },
    /// Applies the hard process-count ceiling before any workflow command.
    Configure {
        /// Protocol version selected by the caller.
        protocol: u16,
        /// Idempotent operation identifier.
        operation_id: String,
        /// Hard per-UID process ceiling inherited by job commands.
        process_limit: u32,
    },
    /// Execute one literal argv with an ephemeral environment.
    Exec {
        /// Protocol version selected by the caller.
        protocol: u16,
        /// Idempotent operation identifier.
        operation_id: String,
        /// Absolute program path.
        program: String,
        /// Literal arguments excluding the program.
        arguments: Vec<String>,
        /// Complete process environment; values can be secret.
        environment: BTreeMap<String, String>,
        /// Absolute working directory.
        working_directory: String,
        /// Positive command deadline.
        timeout_millis: u64,
        /// Aggregate stdout/stderr byte limit.
        output_limit: usize,
    },
    /// Write one bounded file inside the sandbox.
    WriteFile {
        /// Protocol version selected by the caller.
        protocol: u16,
        /// Idempotent operation identifier.
        operation_id: String,
        /// Absolute destination path.
        path: String,
        /// Base64-encoded file content.
        content_base64: String,
    },
    /// Read one bounded file inside the sandbox.
    ReadFile {
        /// Protocol version selected by the caller.
        protocol: u16,
        /// Idempotent operation identifier.
        operation_id: String,
        /// Absolute source path.
        path: String,
        /// Maximum returned bytes.
        byte_limit: usize,
    },
}

impl fmt::Debug for GuestRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hello {
                protocol,
                operation_id,
                ..
            } => formatter
                .debug_struct("GuestRequest::Hello")
                .field("protocol", protocol)
                .field("operation_id", operation_id)
                .field("nonce", &"[REDACTED]")
                .finish(),
            Self::Configure {
                protocol,
                operation_id,
                process_limit,
            } => formatter
                .debug_struct("GuestRequest::Configure")
                .field("protocol", protocol)
                .field("operation_id", operation_id)
                .field("process_limit", process_limit)
                .finish(),
            Self::Exec {
                protocol,
                operation_id,
                arguments,
                environment,
                ..
            } => formatter
                .debug_struct("GuestRequest::Exec")
                .field("protocol", protocol)
                .field("operation_id", operation_id)
                .field("argument_count", &arguments.len())
                .field("environment_count", &environment.len())
                .field("payload", &"[REDACTED]")
                .finish(),
            Self::WriteFile {
                protocol,
                operation_id,
                content_base64,
                ..
            } => formatter
                .debug_struct("GuestRequest::WriteFile")
                .field("protocol", protocol)
                .field("operation_id", operation_id)
                .field("encoded_bytes", &content_base64.len())
                .field("payload", &"[REDACTED]")
                .finish(),
            Self::ReadFile {
                protocol,
                operation_id,
                byte_limit,
                ..
            } => formatter
                .debug_struct("GuestRequest::ReadFile")
                .field("protocol", protocol)
                .field("operation_id", operation_id)
                .field("byte_limit", byte_limit)
                .field("path", &"[REDACTED]")
                .finish(),
        }
    }
}

#[cfg(unix)]
impl GuestRequest {
    fn protocol(&self) -> u16 {
        match self {
            Self::Hello { protocol, .. }
            | Self::Configure { protocol, .. }
            | Self::Exec { protocol, .. }
            | Self::WriteFile { protocol, .. }
            | Self::ReadFile { protocol, .. } => *protocol,
        }
    }

    fn operation_id(&self) -> &str {
        match self {
            Self::Hello { operation_id, .. }
            | Self::Configure { operation_id, .. }
            | Self::Exec { operation_id, .. }
            | Self::WriteFile { operation_id, .. }
            | Self::ReadFile { operation_id, .. } => operation_id,
        }
    }
}

/// Process pipe carried by one ordered output record.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestOutputStream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// One ordered data or end-of-stream observation.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GuestOutputRecord {
    stream: GuestOutputStream,
    data_base64: String,
    end_of_stream: bool,
}

impl fmt::Debug for GuestOutputRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuestOutputRecord")
            .field("stream", &self.stream)
            .field("encoded_bytes", &self.data_base64.len())
            .field("data", &"[REDACTED]")
            .field("end_of_stream", &self.end_of_stream)
            .finish()
    }
}

impl GuestOutputRecord {
    /// Returns the observed pipe.
    pub const fn stream(&self) -> GuestOutputStream {
        self.stream
    }

    /// Decodes the record payload.
    ///
    /// # Errors
    ///
    /// Returns [`GuestProtocolError::InvalidFrame`] for invalid base64.
    pub fn data(&self) -> Result<Vec<u8>, GuestProtocolError> {
        BASE64
            .decode(&self.data_base64)
            .map_err(|_| GuestProtocolError::InvalidFrame)
    }

    /// Returns whether this closes the selected pipe.
    pub const fn is_end_of_stream(&self) -> bool {
        self.end_of_stream
    }
}

/// Sanitized command termination returned by the guest.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "code", rename_all = "snake_case")]
pub enum GuestTermination {
    /// Process exited with a platform status.
    Exited(i32),
    /// Process ended because of a signal.
    Signalled,
    /// Guest killed the process at its deadline.
    TimedOut,
}

/// Bounded response returned through the Kubernetes exec stream.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum GuestResponse {
    /// Guest identity and nonce proof returned before job operations.
    Hello {
        /// Guest protocol version.
        protocol: u16,
        /// Fresh caller nonce.
        nonce: String,
        /// Exact admitted environment-profile identifier.
        profile_id: String,
        /// SHA-256 of the installed guest-agent executable.
        guest_agent_sha256: String,
        /// macOS product version verified by the guest agent at startup.
        macos_version: String,
        /// macOS build identifier verified by the guest agent at startup.
        macos_build: String,
        /// Guest architecture verified by the guest agent at startup.
        architecture: String,
        /// Effective UID used for workflow commands.
        job_uid: u32,
        /// Effective GID used for workflow commands.
        job_gid: u32,
        /// Hard per-UID process ceiling baked into the guest service.
        process_limit: u32,
    },
    /// Guest resource configuration completed.
    Configured {
        /// Guest protocol version.
        protocol: u16,
    },
    /// Command completed or was terminated by policy.
    Exec {
        /// Guest protocol version.
        protocol: u16,
        /// Sanitized process termination.
        termination: GuestTermination,
        /// Cross-pipe output observations.
        records: Vec<GuestOutputRecord>,
        /// Whether output exceeded the caller's bound.
        truncated: bool,
    },
    /// A file write completed.
    WriteFile {
        /// Guest protocol version.
        protocol: u16,
    },
    /// A file read completed.
    ReadFile {
        /// Guest protocol version.
        protocol: u16,
        /// Base64-encoded content.
        content_base64: String,
    },
    /// The request was rejected without returning sensitive diagnostics.
    Rejected {
        /// Guest protocol version.
        protocol: u16,
        /// Stable rejection category.
        kind: GuestRejection,
    },
}

impl fmt::Debug for GuestResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hello {
                protocol,
                profile_id,
                ..
            } => formatter
                .debug_struct("GuestResponse::Hello")
                .field("protocol", protocol)
                .field("profile_id", profile_id)
                .field("attestation", &"[REDACTED]")
                .finish(),
            Self::Configured { protocol } => formatter
                .debug_struct("GuestResponse::Configured")
                .field("protocol", protocol)
                .finish(),
            Self::Exec {
                protocol,
                termination,
                records,
                truncated,
            } => formatter
                .debug_struct("GuestResponse::Exec")
                .field("protocol", protocol)
                .field("termination", termination)
                .field("record_count", &records.len())
                .field("output", &"[REDACTED]")
                .field("truncated", truncated)
                .finish(),
            Self::WriteFile { protocol } => formatter
                .debug_struct("GuestResponse::WriteFile")
                .field("protocol", protocol)
                .finish(),
            Self::ReadFile {
                protocol,
                content_base64,
            } => formatter
                .debug_struct("GuestResponse::ReadFile")
                .field("protocol", protocol)
                .field("encoded_bytes", &content_base64.len())
                .field("content", &"[REDACTED]")
                .finish(),
            Self::Rejected { protocol, kind } => formatter
                .debug_struct("GuestResponse::Rejected")
                .field("protocol", protocol)
                .field("kind", kind)
                .finish(),
        }
    }
}

/// Immutable identity baked beside the guest agent in a sealed VM template.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GuestIdentity {
    /// Exact admitted environment-profile identifier.
    pub profile_id: String,
    /// SHA-256 of the installed guest-agent executable.
    pub guest_agent_sha256: String,
    /// Exact macOS product version in the sealed image.
    pub macos_version: String,
    /// Exact macOS build identifier in the sealed image.
    pub macos_build: String,
    /// Exact guest architecture.
    pub architecture: String,
    /// Dedicated non-administrative workflow UID.
    pub job_uid: u32,
    /// Dedicated non-administrative workflow GID.
    pub job_gid: u32,
    /// Hard process ceiling applied by launchd before the guest agent starts.
    pub process_limit: u32,
}

/// Stable, non-sensitive request rejection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestRejection {
    /// Caller and guest protocol versions differ.
    UnsupportedProtocol,
    /// Request violated a path, size, argv, or environment bound.
    InvalidRequest,
    /// Process or filesystem operation failed.
    OperationFailed,
    /// An operation identifier was reused with different request material.
    OperationConflict,
}

/// Guest framing, transport, or request failure.
#[derive(Debug, Error)]
pub enum GuestProtocolError {
    /// I/O transport failed.
    #[error("guest transport failed")]
    Io(#[from] io::Error),
    /// Frame was empty, oversized, malformed, or noncanonical enough to reject.
    #[error("guest frame is invalid")]
    InvalidFrame,
}

/// Encodes one length-prefixed request or response frame.
///
/// # Errors
///
/// Rejects serialization failure or a frame over [`MAX_GUEST_FRAME_BYTES`].
pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, GuestProtocolError> {
    let payload = serde_json::to_vec(value).map_err(|_| GuestProtocolError::InvalidFrame)?;
    if payload.is_empty() || payload.len() > MAX_GUEST_FRAME_BYTES {
        return Err(GuestProtocolError::InvalidFrame);
    }
    let length = u32::try_from(payload.len()).map_err(|_| GuestProtocolError::InvalidFrame)?;
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Decodes one exact length-prefixed frame.
///
/// # Errors
///
/// Rejects trailing bytes, malformed JSON, or invalid length evidence.
pub fn decode_frame<T: for<'de> Deserialize<'de>>(frame: &[u8]) -> Result<T, GuestProtocolError> {
    let length = frame
        .get(..4)
        .and_then(|value| <[u8; 4]>::try_from(value).ok())
        .map(u32::from_be_bytes)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(GuestProtocolError::InvalidFrame)?;
    if length == 0 || length > MAX_GUEST_FRAME_BYTES || frame.len() != length + 4 {
        return Err(GuestProtocolError::InvalidFrame);
    }
    serde_json::from_slice(&frame[4..]).map_err(|_| GuestProtocolError::InvalidFrame)
}

/// Runs the guest Unix-socket server until its listener fails.
///
/// # Errors
///
/// Returns a sanitized transport error when the socket cannot be bound or accepted.
#[cfg(unix)]
pub async fn serve(socket: &Path) -> Result<(), GuestProtocolError> {
    serve_internal(socket, None).await
}

/// Runs the macOS VM guest server with its mandatory sealed-template identity.
///
/// # Errors
///
/// Returns a sanitized transport error when the socket cannot be bound or accepted.
#[cfg(unix)]
pub async fn serve_vm(socket: &Path, identity: GuestIdentity) -> Result<(), GuestProtocolError> {
    serve_internal(socket, Some(identity)).await
}

#[cfg(unix)]
async fn serve_internal(
    socket: &Path,
    identity: Option<GuestIdentity>,
) -> Result<(), GuestProtocolError> {
    let listener = bind_listener(socket).await?;
    let replay = Arc::new(Mutex::new(ReplayCache::default()));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let replay = Arc::clone(&replay);
                let identity = identity.clone();
                connections.spawn(async move {
                    let _ = serve_connection(stream, replay, identity).await;
                });
            }
            result = connections.join_next(), if !connections.is_empty() => {
                let _ = result;
            }
        }
    }
}

/// Runs the guest Unix-socket server until its listener fails.
///
/// # Errors
///
/// Returns an unsupported transport error on non-Unix platforms.
#[cfg(not(unix))]
#[allow(clippy::unused_async)]
pub async fn serve(_socket: &Path) -> Result<(), GuestProtocolError> {
    Err(unsupported_unix_transport().into())
}

/// Rejects identity-bearing guest service on non-Unix platforms.
///
/// # Errors
///
/// Always returns an unsupported transport error.
#[cfg(not(unix))]
#[allow(clippy::unused_async)]
pub async fn serve_vm(_socket: &Path, _identity: GuestIdentity) -> Result<(), GuestProtocolError> {
    Err(unsupported_unix_transport().into())
}

/// Forwards one framed request between stdio and the guest Unix socket.
///
/// # Errors
///
/// Returns a transport failure without including request data.
#[cfg(unix)]
pub async fn forward_stdio(socket: &Path) -> Result<(), GuestProtocolError> {
    let mut input = tokio::io::stdin();
    let request = read_frame(&mut input).await?;
    let mut stream = connect_stream(socket).await?;
    stream.write_all(&request).await?;
    let response = read_frame(&mut stream).await?;
    let mut output = tokio::io::stdout();
    output.write_all(&response).await?;
    output.flush().await?;
    Ok(())
}

/// Forwards one framed request between stdio and the guest Unix socket.
///
/// # Errors
///
/// Returns an unsupported transport error on non-Unix platforms.
#[cfg(not(unix))]
#[allow(clippy::unused_async)]
pub async fn forward_stdio(_socket: &Path) -> Result<(), GuestProtocolError> {
    Err(unsupported_unix_transport().into())
}

/// Checks whether the configured guest listener accepts connections.
#[must_use]
#[cfg(unix)]
pub fn probe(socket: &Path) -> bool {
    connect_probe(socket).is_ok()
}

/// Checks whether the configured guest listener accepts connections.
#[must_use]
#[cfg(not(unix))]
pub fn probe(_socket: &Path) -> bool {
    false
}

#[cfg(not(unix))]
fn unsupported_unix_transport() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "guest Unix-socket transport is unavailable",
    )
}

#[cfg(unix)]
async fn bind_listener(socket: &Path) -> io::Result<UnixListener> {
    if let Some(name) = abstract_socket_name(socket) {
        #[cfg(target_os = "linux")]
        {
            let address = StdSocketAddr::from_abstract_name(name)?;
            let listener = StdUnixListener::bind_addr(&address)?;
            listener.set_nonblocking(true)?;
            return UnixListener::from_std(listener);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = name;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "abstract Unix sockets require Linux",
            ));
        }
    }
    match tokio::fs::remove_file(socket).await {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    UnixListener::bind(socket)
}

#[cfg(unix)]
async fn connect_stream(socket: &Path) -> io::Result<UnixStream> {
    if let Some(name) = abstract_socket_name(socket) {
        #[cfg(target_os = "linux")]
        {
            let address = StdSocketAddr::from_abstract_name(name)?;
            let stream = StdUnixStream::connect_addr(&address)?;
            stream.set_nonblocking(true)?;
            return UnixStream::from_std(stream);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = name;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "abstract Unix sockets require Linux",
            ));
        }
    }
    UnixStream::connect(socket).await
}

#[cfg(unix)]
fn connect_probe(socket: &Path) -> io::Result<()> {
    if let Some(name) = abstract_socket_name(socket) {
        #[cfg(target_os = "linux")]
        {
            let address = StdSocketAddr::from_abstract_name(name)?;
            return StdUnixStream::connect_addr(&address).map(|_| ());
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = name;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "abstract Unix sockets require Linux",
            ));
        }
    }
    std::os::unix::net::UnixStream::connect(socket).map(|_| ())
}

#[cfg(unix)]
fn abstract_socket_name(socket: &Path) -> Option<&[u8]> {
    socket
        .to_str()
        .and_then(|value| value.strip_prefix('@'))
        .filter(|value| !value.is_empty())
        .map(str::as_bytes)
}

#[cfg(unix)]
async fn serve_connection(
    mut stream: UnixStream,
    replay: Arc<Mutex<ReplayCache>>,
    identity: Option<GuestIdentity>,
) -> Result<(), GuestProtocolError> {
    let frame = read_frame(&mut stream).await?;
    let request: GuestRequest = decode_frame(&frame)?;
    let immediate_response = if request.protocol() != GUEST_PROTOCOL_VERSION {
        Some(GuestResponse::Rejected {
            protocol: GUEST_PROTOCOL_VERSION,
            kind: GuestRejection::UnsupportedProtocol,
        })
    } else if !valid_operation_id(request.operation_id()) {
        Some(rejected(GuestRejection::InvalidRequest))
    } else {
        None
    };
    if let Some(response) = immediate_response {
        stream.write_all(&encode_frame(&response)?).await?;
        stream.shutdown().await?;
        return Ok(());
    }

    let (mut reader, mut writer) = stream.into_split();
    let operation = replay_request(request, replay, identity);
    tokio::pin!(operation);
    let response = tokio::select! {
        response = &mut operation => response,
        disconnected = wait_for_disconnect(&mut reader) => {
            disconnected?;
            return Ok(());
        }
    };
    writer.write_all(&encode_frame(&response)?).await?;
    writer.shutdown().await?;
    Ok(())
}

#[cfg(unix)]
async fn wait_for_disconnect<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<(), GuestProtocolError> {
    let mut unexpected = [0_u8; 1];
    match reader.read(&mut unexpected).await {
        Ok(0) => Ok(()),
        Ok(_) => Err(GuestProtocolError::InvalidFrame),
        Err(error) => Err(GuestProtocolError::Io(error)),
    }
}

#[cfg(unix)]
#[derive(Default)]
struct ReplayCache {
    entries: BTreeMap<String, ReplayEntry>,
    in_flight: BTreeMap<String, InFlightReplay>,
    order: VecDeque<String>,
    bytes: usize,
}

#[cfg(unix)]
struct InFlightReplay {
    fingerprint: [u8; 32],
    completion: watch::Sender<bool>,
}

#[cfg(unix)]
struct ReplayEntry {
    fingerprint: [u8; 32],
    response: GuestResponse,
    bytes: usize,
}

#[cfg(unix)]
impl ReplayCache {
    fn get(&self, operation_id: &str, fingerprint: &[u8; 32]) -> Option<GuestResponse> {
        self.entries.get(operation_id).map(|entry| {
            if &entry.fingerprint == fingerprint {
                entry.response.clone()
            } else {
                rejected(GuestRejection::OperationConflict)
            }
        })
    }

    fn insert(&mut self, operation_id: String, fingerprint: [u8; 32], response: GuestResponse) {
        let bytes = encode_frame(&response).map_or(MAX_REPLAY_BYTES + 1, |frame| frame.len());
        if bytes > MAX_REPLAY_BYTES {
            return;
        }
        while self.entries.len() >= MAX_REPLAY_ENTRIES
            || self.bytes.saturating_add(bytes) > MAX_REPLAY_BYTES
        {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if let Some(entry) = self.entries.remove(&oldest) {
                self.bytes = self.bytes.saturating_sub(entry.bytes);
            }
        }
        self.bytes = self.bytes.saturating_add(bytes);
        self.order.push_back(operation_id.clone());
        self.entries.insert(
            operation_id,
            ReplayEntry {
                fingerprint,
                response,
                bytes,
            },
        );
    }
}

#[cfg(unix)]
struct ReplayReservation {
    replay: Arc<Mutex<ReplayCache>>,
    operation_id: String,
    fingerprint: [u8; 32],
    completion: Option<watch::Sender<bool>>,
}

#[cfg(unix)]
impl ReplayReservation {
    fn commit(mut self, response: GuestResponse) {
        {
            let mut replay = lock_replay(&self.replay);
            replay.in_flight.remove(&self.operation_id);
            replay.insert(self.operation_id.clone(), self.fingerprint, response);
        }
        if let Some(completion) = self.completion.take() {
            let _ = completion.send(true);
        }
    }
}

#[cfg(unix)]
impl Drop for ReplayReservation {
    fn drop(&mut self) {
        let Some(completion) = self.completion.take() else {
            return;
        };
        lock_replay(&self.replay)
            .in_flight
            .remove(&self.operation_id);
        let _ = completion.send(true);
    }
}

#[cfg(unix)]
fn lock_replay(replay: &Mutex<ReplayCache>) -> MutexGuard<'_, ReplayCache> {
    replay
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(unix)]
enum ReplayDecision {
    Return(GuestResponse),
    Wait(watch::Receiver<bool>),
    Execute(ReplayReservation),
}

#[cfg(unix)]
fn replay_decision(
    replay: &Arc<Mutex<ReplayCache>>,
    operation_id: &str,
    fingerprint: &[u8; 32],
) -> ReplayDecision {
    let mut cache = lock_replay(replay);
    if let Some(response) = cache.get(operation_id, fingerprint) {
        return ReplayDecision::Return(response);
    }
    if let Some(in_flight) = cache.in_flight.get(operation_id) {
        return if &in_flight.fingerprint == fingerprint {
            ReplayDecision::Wait(in_flight.completion.subscribe())
        } else {
            ReplayDecision::Return(rejected(GuestRejection::OperationConflict))
        };
    }
    let (completion, receiver) = watch::channel(false);
    drop(receiver);
    cache.in_flight.insert(
        operation_id.to_owned(),
        InFlightReplay {
            fingerprint: *fingerprint,
            completion: completion.clone(),
        },
    );
    ReplayDecision::Execute(ReplayReservation {
        replay: Arc::clone(replay),
        operation_id: operation_id.to_owned(),
        fingerprint: *fingerprint,
        completion: Some(completion),
    })
}

#[cfg(unix)]
async fn replay_request(
    request: GuestRequest,
    replay: Arc<Mutex<ReplayCache>>,
    identity: Option<GuestIdentity>,
) -> GuestResponse {
    let fingerprint: [u8; 32] = Sha256::digest(
        serde_json::to_vec(&request).expect("validated guest request is serializable"),
    )
    .into();
    let operation_id = request.operation_id().to_owned();
    loop {
        match replay_decision(&replay, &operation_id, &fingerprint) {
            ReplayDecision::Return(response) => return response,
            ReplayDecision::Wait(mut completion) => {
                if !*completion.borrow() {
                    let _ = completion.changed().await;
                }
            }
            ReplayDecision::Execute(reservation) => {
                let response = handle_request(request, identity).await;
                reservation.commit(response.clone());
                return response;
            }
        }
    }
}

#[cfg(unix)]
async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, GuestProtocolError> {
    let mut header = [0_u8; 4];
    reader.read_exact(&mut header).await?;
    let length = usize::try_from(u32::from_be_bytes(header))
        .map_err(|_| GuestProtocolError::InvalidFrame)?;
    if length == 0 || length > MAX_GUEST_FRAME_BYTES {
        return Err(GuestProtocolError::InvalidFrame);
    }
    let mut frame = Vec::with_capacity(length + 4);
    frame.extend_from_slice(&header);
    frame.resize(length + 4, 0);
    reader.read_exact(&mut frame[4..]).await?;
    Ok(frame)
}

#[cfg(unix)]
async fn handle_request(request: GuestRequest, identity: Option<GuestIdentity>) -> GuestResponse {
    match request {
        GuestRequest::Hello { nonce, .. } => {
            if valid_attestation_value(&nonce) {
                identity.map_or_else(
                    || rejected(GuestRejection::OperationFailed),
                    |identity| GuestResponse::Hello {
                        protocol: GUEST_PROTOCOL_VERSION,
                        nonce,
                        profile_id: identity.profile_id,
                        guest_agent_sha256: identity.guest_agent_sha256,
                        macos_version: identity.macos_version,
                        macos_build: identity.macos_build,
                        architecture: identity.architecture,
                        job_uid: identity.job_uid,
                        job_gid: identity.job_gid,
                        process_limit: identity.process_limit,
                    },
                )
            } else {
                rejected(GuestRejection::InvalidRequest)
            }
        }
        GuestRequest::Configure { process_limit, .. } => {
            if identity.as_ref().map(|value| value.process_limit) != Some(process_limit) {
                rejected(GuestRejection::InvalidRequest)
            } else if configure_process_limit(process_limit).is_err() {
                rejected(GuestRejection::OperationFailed)
            } else {
                GuestResponse::Configured {
                    protocol: GUEST_PROTOCOL_VERSION,
                }
            }
        }
        GuestRequest::Exec {
            program,
            arguments,
            environment,
            working_directory,
            timeout_millis,
            output_limit,
            ..
        } => {
            execute(
                program,
                arguments,
                environment,
                working_directory,
                timeout_millis,
                output_limit,
            )
            .await
        }
        GuestRequest::WriteFile {
            path,
            content_base64,
            ..
        } => write_file(&path, &content_base64).await,
        GuestRequest::ReadFile {
            path, byte_limit, ..
        } => read_file(&path, byte_limit).await,
    }
}

#[cfg(unix)]
fn valid_attestation_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_OPERATION_ID_BYTES
        && value.is_ascii()
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

#[cfg(unix)]
fn configure_process_limit(process_limit: u32) -> io::Result<()> {
    let limit = u64::from(process_limit);
    rustix::process::setrlimit(
        rustix::process::Resource::Nproc,
        rustix::process::Rlimit {
            current: Some(limit),
            maximum: Some(limit),
        },
    )
    .map_err(Into::into)
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
async fn execute(
    program: String,
    arguments: Vec<String>,
    environment: BTreeMap<String, String>,
    working_directory: String,
    timeout_millis: u64,
    output_limit: usize,
) -> GuestResponse {
    if !valid_execution_request(
        &program,
        &arguments,
        &environment,
        &working_directory,
        timeout_millis,
        output_limit,
    ) {
        return rejected(GuestRejection::InvalidRequest);
    }
    let mut command = Command::new(program);
    command
        .args(arguments)
        .env_clear()
        .envs(environment)
        .current_dir(working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    configure_process_group(&mut command);
    let Ok(mut child) = command.spawn() else {
        return rejected(GuestRejection::OperationFailed);
    };
    let Some(process_group) = child.id() else {
        return rejected(GuestRejection::OperationFailed);
    };
    let Some(stdout) = child.stdout.take() else {
        return rejected(GuestRejection::OperationFailed);
    };
    let Some(stderr) = child.stderr.take() else {
        return rejected(GuestRejection::OperationFailed);
    };
    let (sender, mut receiver) = mpsc::channel(64);
    let stdout_task = tokio::spawn(read_output(
        stdout,
        GuestOutputStream::Stdout,
        sender.clone(),
    ));
    let stderr_task = tokio::spawn(read_output(stderr, GuestOutputStream::Stderr, sender));
    let (status, mut records, truncated) = collect_process_output(
        &mut child,
        &mut receiver,
        process_group,
        output_limit,
        Duration::from_millis(timeout_millis),
    )
    .await;
    let (termination, truncated) = match status {
        Some(Ok(status)) => {
            let termination = status
                .code()
                .map_or(GuestTermination::Signalled, GuestTermination::Exited);
            (termination, truncated)
        }
        Some(Err(_)) => {
            stdout_task.abort();
            stderr_task.abort();
            terminate_process_group(process_group);
            let _ = child.kill().await;
            let _ = child.wait().await;
            return rejected(GuestRejection::OperationFailed);
        }
        None => {
            stdout_task.abort();
            stderr_task.abort();
            terminate_process_group(process_group);
            let _ = child.kill().await;
            let _ = child.wait().await;
            (GuestTermination::TimedOut, truncated)
        }
    };
    let _ = stdout_task.await;
    let _ = stderr_task.await;
    if !truncated {
        records.push(GuestOutputRecord {
            stream: GuestOutputStream::Stdout,
            data_base64: String::new(),
            end_of_stream: true,
        });
        records.push(GuestOutputRecord {
            stream: GuestOutputStream::Stderr,
            data_base64: String::new(),
            end_of_stream: true,
        });
    }
    GuestResponse::Exec {
        protocol: GUEST_PROTOCOL_VERSION,
        termination,
        records,
        truncated,
    }
}

#[cfg(unix)]
async fn collect_process_output(
    child: &mut tokio::process::Child,
    receiver: &mut mpsc::Receiver<(GuestOutputStream, Vec<u8>)>,
    process_group: u32,
    output_limit: usize,
    deadline: Duration,
) -> (
    Option<io::Result<std::process::ExitStatus>>,
    Vec<GuestOutputRecord>,
    bool,
) {
    let mut status = None;
    let mut output_open = true;
    let mut records = Vec::new();
    let mut bytes = 0_usize;
    let mut truncated = false;
    let deadline = tokio::time::sleep(deadline);
    tokio::pin!(deadline);
    while status.is_none() || output_open {
        tokio::select! {
            () = &mut deadline => return (None, records, truncated),
            result = child.wait(), if status.is_none() => {
                status = Some(result);
                terminate_process_group(process_group);
            },
            record = receiver.recv(), if output_open => match record {
                Some((stream, data)) => {
                    let remaining = output_limit.saturating_sub(bytes);
                    let retained = data.len().min(remaining);
                    let can_store = records.len() < MAX_OUTPUT_DATA_RECORDS;
                    if retained > 0 && can_store {
                        records.push(GuestOutputRecord {
                            stream,
                            data_base64: BASE64.encode(&data[..retained]),
                            end_of_stream: false,
                        });
                    }
                    truncated |= retained != data.len()
                        || retained > 0 && !can_store;
                    bytes += retained;
                }
                None => output_open = false,
            },
        }
    }
    (status, records, truncated)
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    command.process_group(0);
}

#[cfg(unix)]
fn terminate_process_group(process_group: u32) {
    let Ok(process_group) = i32::try_from(process_group) else {
        return;
    };
    let Some(process_group) = rustix::process::Pid::from_raw(process_group) else {
        return;
    };
    let _ = rustix::process::kill_process_group(process_group, rustix::process::Signal::KILL);
}

#[cfg(unix)]
async fn read_output<R: AsyncRead + Unpin>(
    mut reader: R,
    stream: GuestOutputStream,
    sender: mpsc::Sender<(GuestOutputStream, Vec<u8>)>,
) {
    loop {
        let mut buffer = vec![0_u8; OUTPUT_CHUNK_BYTES];
        match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(length) => {
                buffer.truncate(length);
                if sender.send((stream, buffer)).await.is_err() {
                    return;
                }
            }
        }
    }
}

#[cfg(unix)]
async fn write_file(path: &str, content_base64: &str) -> GuestResponse {
    let Ok(content) = BASE64.decode(content_base64) else {
        return rejected(GuestRejection::InvalidRequest);
    };
    if !valid_absolute_path(path) || content.len() > MAX_GUEST_FRAME_BYTES / 2 {
        return rejected(GuestRejection::InvalidRequest);
    }
    match tokio::fs::write(path, content).await {
        Ok(()) => GuestResponse::WriteFile {
            protocol: GUEST_PROTOCOL_VERSION,
        },
        Err(_) => rejected(GuestRejection::OperationFailed),
    }
}

#[cfg(unix)]
async fn read_file(path: &str, byte_limit: usize) -> GuestResponse {
    if !valid_absolute_path(path) || byte_limit == 0 || byte_limit > MAX_GUEST_FRAME_BYTES / 2 {
        return rejected(GuestRejection::InvalidRequest);
    }
    let Ok(file) = tokio::fs::File::open(path).await else {
        return rejected(GuestRejection::OperationFailed);
    };
    let mut content = Vec::with_capacity(byte_limit.min(OUTPUT_CHUNK_BYTES));
    let Ok(read_limit) = u64::try_from(byte_limit.saturating_add(1)) else {
        return rejected(GuestRejection::InvalidRequest);
    };
    if file
        .take(read_limit)
        .read_to_end(&mut content)
        .await
        .is_err()
    {
        return rejected(GuestRejection::OperationFailed);
    }
    if content.len() > byte_limit {
        return rejected(GuestRejection::InvalidRequest);
    }
    GuestResponse::ReadFile {
        protocol: GUEST_PROTOCOL_VERSION,
        content_base64: BASE64.encode(content),
    }
}

#[cfg(unix)]
fn rejected(kind: GuestRejection) -> GuestResponse {
    GuestResponse::Rejected {
        protocol: GUEST_PROTOCOL_VERSION,
        kind,
    }
}

#[cfg(unix)]
fn valid_absolute_path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= MAX_TARGET_PATH_BYTES
        && !value.contains("//")
        && value
            .split('/')
            .skip(1)
            .all(|part| !matches!(part, "." | ".."))
        && !value.contains('\0')
}

#[cfg(unix)]
fn valid_operation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_OPERATION_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

#[cfg(unix)]
fn valid_execution_request(
    program: &str,
    arguments: &[String],
    environment: &BTreeMap<String, String>,
    working_directory: &str,
    timeout_millis: u64,
    output_limit: usize,
) -> bool {
    let argv_bytes = arguments.iter().try_fold(program.len(), |bytes, argument| {
        (!argument.contains('\0'))
            .then(|| bytes.checked_add(argument.len()))
            .flatten()
    });
    let environment_bytes = environment
        .iter()
        .try_fold(0_usize, |bytes, (name, value)| {
            let valid = !name.is_empty()
                && name.len() <= MAX_ENVIRONMENT_NAME_BYTES
                && !name.contains('=')
                && !name.chars().any(char::is_control)
                && value.len() <= MAX_ENVIRONMENT_VALUE_BYTES
                && !value.contains('\0');
            valid
                .then(|| bytes.checked_add(name.len())?.checked_add(value.len()))
                .flatten()
        });
    valid_absolute_path(program)
        && valid_absolute_path(working_directory)
        && arguments.len() <= MAX_EXECUTION_ARGUMENTS
        && argv_bytes.is_some_and(|bytes| bytes <= MAX_EXECUTION_ARGV_BYTES)
        && environment.len() <= MAX_ENVIRONMENT_VARIABLES
        && environment_bytes.is_some_and(|bytes| bytes <= MAX_ENVIRONMENT_BYTES)
        && (1..=MAX_COMMAND_TIMEOUT_MILLIS).contains(&timeout_millis)
        && (1..=MAX_EXECUTION_OUTPUT_BYTES).contains(&output_limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPERATION_ONE: &str = "00000000-0000-4000-8000-000000000001";

    #[test]
    fn frame_round_trip_redacts_debug() {
        let request = GuestRequest::Exec {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: OPERATION_ONE.into(),
            program: "/bin/echo".into(),
            arguments: vec!["secret-argument".into()],
            environment: BTreeMap::from([("TOKEN".into(), "secret-value".into())]),
            working_directory: "/tmp".into(),
            timeout_millis: 1_000,
            output_limit: 1_024,
        };
        let frame = encode_frame(&request).expect("frame");
        assert_eq!(
            decode_frame::<GuestRequest>(&frame).expect("decode"),
            request
        );
        let debug = format!("{request:?}");
        assert!(!debug.contains("secret-argument"));
        assert!(!debug.contains("secret-value"));
    }

    #[test]
    fn rejects_trailing_and_oversized_frames() {
        let response = GuestResponse::WriteFile {
            protocol: GUEST_PROTOCOL_VERSION,
        };
        let mut frame = encode_frame(&response).expect("frame");
        frame.push(0);
        assert!(decode_frame::<GuestResponse>(&frame).is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hello_returns_only_the_baked_identity_and_fresh_nonce() {
        let identity = GuestIdentity {
            profile_id: "automata.dev/macos-15-arm64-vm-v1".into(),
            guest_agent_sha256: "11".repeat(32),
            macos_version: "15.7".into(),
            macos_build: "24G222".into(),
            architecture: "arm64".into(),
            job_uid: 502,
            job_gid: 502,
            process_limit: 512,
        };
        let request = GuestRequest::Hello {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: OPERATION_ONE.into(),
            nonce: "fresh-nonce".into(),
        };
        assert_eq!(
            handle_request(request, Some(identity.clone())).await,
            GuestResponse::Hello {
                protocol: GUEST_PROTOCOL_VERSION,
                nonce: "fresh-nonce".into(),
                profile_id: identity.profile_id,
                guest_agent_sha256: identity.guest_agent_sha256,
                macos_version: identity.macos_version,
                macos_build: identity.macos_build,
                architecture: identity.architecture,
                job_uid: identity.job_uid,
                job_gid: identity.job_gid,
                process_limit: identity.process_limit,
            }
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn process_configuration_requires_the_exact_baked_vm_identity() {
        let identity = GuestIdentity {
            profile_id: "automata.dev/macos-15-arm64-vm-v1".into(),
            guest_agent_sha256: "11".repeat(32),
            macos_version: "15.7".into(),
            macos_build: "24G222".into(),
            architecture: "arm64".into(),
            job_uid: 502,
            job_gid: 502,
            process_limit: 512,
        };
        let request = GuestRequest::Configure {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: OPERATION_ONE.into(),
            process_limit: 511,
        };
        assert_eq!(
            handle_request(request.clone(), Some(identity)).await,
            rejected(GuestRejection::InvalidRequest)
        );
        assert_eq!(
            handle_request(request, None).await,
            rejected(GuestRejection::InvalidRequest)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn replay_is_exact_and_changed_material_fails_closed() {
        let path =
            std::env::temp_dir().join(format!("automata-guest-replay-{}", std::process::id()));
        let path = path.to_string_lossy().into_owned();
        let replay = Arc::new(Mutex::new(ReplayCache::default()));
        let request = GuestRequest::WriteFile {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: OPERATION_ONE.into(),
            path: path.clone(),
            content_base64: BASE64.encode(b"first"),
        };

        assert!(matches!(
            replay_request(request.clone(), Arc::clone(&replay), None).await,
            GuestResponse::WriteFile { .. }
        ));
        tokio::fs::write(&path, b"outside change")
            .await
            .expect("replace fixture");
        assert!(matches!(
            replay_request(request, Arc::clone(&replay), None).await,
            GuestResponse::WriteFile { .. }
        ));
        assert_eq!(
            tokio::fs::read(&path).await.expect("read fixture"),
            b"outside change"
        );

        let changed = GuestRequest::WriteFile {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: OPERATION_ONE.into(),
            path: path.clone(),
            content_base64: BASE64.encode(b"different"),
        };
        assert_eq!(
            replay_request(changed, replay, None).await,
            rejected(GuestRejection::OperationConflict)
        );
        tokio::fs::remove_file(path).await.expect("remove fixture");
    }

    #[cfg(unix)]
    #[test]
    fn execution_request_budgets_match_the_public_endpoint_contract() {
        assert!(valid_operation_id(OPERATION_ONE));
        assert!(!valid_operation_id("line\nbreak"));
        assert!(valid_execution_request(
            "/bin/true",
            &[],
            &BTreeMap::new(),
            "/tmp",
            1,
            1,
        ));
        assert!(!valid_execution_request(
            "/bin/true",
            &vec![String::new(); MAX_EXECUTION_ARGUMENTS + 1],
            &BTreeMap::new(),
            "/tmp",
            1,
            1,
        ));
        assert!(!valid_execution_request(
            "/bin/true",
            &[],
            &BTreeMap::new(),
            "/tmp",
            MAX_COMMAND_TIMEOUT_MILLIS + 1,
            1,
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_retains_output_observed_before_process_termination() {
        let response = execute(
            "/bin/sh".into(),
            vec!["-c".into(), "printf retained; exec /bin/sleep 5".into()],
            BTreeMap::new(),
            "/tmp".into(),
            100,
            1_024,
        )
        .await;
        let GuestResponse::Exec {
            termination,
            records,
            truncated,
            ..
        } = response
        else {
            panic!("command should reach a typed termination");
        };
        let output = records
            .into_iter()
            .filter(|record| !record.is_end_of_stream())
            .flat_map(|record| record.data().expect("base64 output"))
            .collect::<Vec<_>>();
        assert_eq!(termination, GuestTermination::TimedOut);
        assert!(!truncated);
        assert_eq!(output, b"retained");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bounded_read_rejects_content_past_the_requested_limit() {
        let path = std::env::temp_dir().join(format!(
            "automata-guest-bounded-read-{}",
            std::process::id()
        ));
        tokio::fs::write(&path, vec![7_u8; OUTPUT_CHUNK_BYTES * 2])
            .await
            .expect("write fixture");
        assert_eq!(
            read_file(&path.to_string_lossy(), 8).await,
            rejected(GuestRejection::InvalidRequest)
        );
        tokio::fs::remove_file(path).await.expect("remove fixture");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn abstract_listener_is_connectable_without_a_filesystem_entry() {
        let socket =
            std::path::PathBuf::from(format!("@automata-ci-guest-test-{}", std::process::id()));
        let listener = bind_listener(&socket).await.expect("abstract listener");
        assert!(probe(&socket));
        assert!(tokio::fs::metadata(&socket).await.is_err());
        drop(listener);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_exited_process_leader_cannot_leave_background_work_running() {
        let marker =
            std::env::temp_dir().join(format!("automata-guest-descendant-{}", std::process::id()));
        let _ = tokio::fs::remove_file(&marker).await;
        let command = format!(
            "(/bin/sleep 1; /usr/bin/touch '{}') & exit 0",
            marker.display()
        );
        let response = execute(
            "/bin/sh".into(),
            vec!["-c".into(), command],
            BTreeMap::new(),
            "/tmp".into(),
            5_000,
            1_024,
        )
        .await;
        assert!(matches!(
            response,
            GuestResponse::Exec {
                termination: GuestTermination::Exited(0),
                ..
            }
        ));
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        assert!(
            tokio::fs::metadata(&marker).await.is_err(),
            "the background descendant survived its process-group leader"
        );
    }
}
