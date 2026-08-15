#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Versioned, framed transport used to keep command arguments and environment
//! values out of Kubernetes Pod specifications, exec request URLs, and
//! Windows container-runtime command lines.

use std::{collections::BTreeMap, fmt, io, path::Path};

#[cfg(unix)]
use std::{
    collections::VecDeque,
    ffi::OsString,
    fs::File,
    io::{Read as _, Write as _},
    os::unix::ffi::OsStrExt as _,
    path::Component,
    sync::{Arc, Mutex, MutexGuard},
};
#[cfg(any(unix, windows))]
use std::{process::Stdio, time::Duration};

#[cfg(target_os = "linux")]
use std::os::{
    linux::net::SocketAddrExt as _,
    unix::net::{
        SocketAddr as StdSocketAddr, UnixListener as StdUnixListener, UnixStream as StdUnixStream,
    },
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
#[cfg(unix)]
use rustix::{
    fd::OwnedFd,
    fs::{
        self as unix_fs, AtFlags, FileType, FlockOperation, Mode, OFlags, flock, fstat, open,
        openat, renameat, unlinkat,
    },
    io::Errno,
};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use sha2::{Digest as _, Sha256};
use thiserror::Error;
#[cfg(any(unix, windows))]
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
    sync::mpsc,
};
#[cfg(unix)]
use tokio::{
    net::{UnixListener, UnixStream},
    sync::watch,
    task::JoinSet,
};

/// Current guest protocol version.
///
/// Version 4 adds optimistic, durable file replacement and an optional-file
/// read whose missing result is distinct from other filesystem failures.
/// Earlier versions are rejected instead of being interpreted as the current
/// wire contract.
pub const GUEST_PROTOCOL_VERSION: u16 = 4;
/// Maximum encoded request or response frame.
pub const MAX_GUEST_FRAME_BYTES: usize = 32 * 1024 * 1024;
#[cfg(any(unix, windows))]
const OUTPUT_CHUNK_BYTES: usize = 16 * 1024;
#[cfg(any(unix, windows))]
const MAX_OUTPUT_DATA_RECORDS: usize = 65_534;
#[cfg(any(unix, windows))]
const MAX_OPERATION_ID_BYTES: usize = 128;
#[cfg(any(unix, windows))]
const MAX_TARGET_PATH_BYTES: usize = 4_096;
#[cfg(any(unix, windows))]
const MAX_EXECUTION_ARGUMENTS: usize = 4_096;
#[cfg(any(unix, windows))]
const MAX_EXECUTION_ARGV_BYTES: usize = 1024 * 1024;
#[cfg(any(unix, windows))]
const MAX_ENVIRONMENT_VARIABLES: usize = 1_024;
#[cfg(any(unix, windows))]
const MAX_ENVIRONMENT_NAME_BYTES: usize = 128;
#[cfg(any(unix, windows))]
const MAX_ENVIRONMENT_VALUE_BYTES: usize = 1024 * 1024;
#[cfg(any(unix, windows))]
const MAX_ENVIRONMENT_BYTES: usize = 4 * 1024 * 1024;
#[cfg(any(unix, windows))]
const MAX_COMMAND_TIMEOUT_MILLIS: u64 = 24 * 60 * 60 * 1_000;
#[cfg(any(unix, windows))]
const MAX_EXECUTION_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
#[cfg(windows)]
const MAX_PROCESS_LIMIT: u32 = 1_000_000;
#[cfg(unix)]
const MAX_REPLAY_ENTRIES: usize = 256;
#[cfg(unix)]
const MAX_REPLAY_BYTES: usize = 64 * 1024 * 1024;
#[cfg(unix)]
const MAX_ATOMIC_STAGE_CREATE_ATTEMPTS: usize = 8;
#[cfg(unix)]
const ATOMIC_STAGE_RANDOM_BYTES: usize = 16;

/// Expected state used to fence one atomic file replacement.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GuestFileExpectation {
    /// The target must not exist.
    Absent,
    /// The target must contain bytes with this exact lowercase SHA-256 digest.
    Sha256 {
        /// Exactly 64 lowercase hexadecimal characters.
        digest: String,
    },
}

impl fmt::Debug for GuestFileExpectation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => formatter.write_str("GuestFileExpectation::Absent"),
            Self::Sha256 { .. } => formatter
                .debug_struct("GuestFileExpectation::Sha256")
                .field("digest", &"[REDACTED]")
                .finish(),
        }
    }
}

/// Result of one optimistic atomic file replacement.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestAtomicCommitOutcome {
    /// The requested bytes replaced the expected prior state durably.
    Committed,
    /// The target already contained the requested bytes and the exact file and
    /// parent directory were synchronized before acknowledgement.
    AlreadyCurrent,
    /// The target did not match the caller's expected prior state.
    Conflict,
}

/// Explicit state returned by an optional-file read.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum GuestOptionalFile {
    /// The target was absent.
    Missing {},
    /// The target was present with bounded, base64-encoded content.
    Present {
        /// Base64-encoded file content.
        content_base64: String,
    },
}

impl fmt::Debug for GuestOptionalFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing {} => formatter.write_str("GuestOptionalFile::Missing"),
            Self::Present { content_base64 } => formatter
                .debug_struct("GuestOptionalFile::Present")
                .field("encoded_bytes", &content_base64.len())
                .field("content", &"[REDACTED]")
                .finish(),
        }
    }
}

/// One operation sent through anonymous stdin to the sandbox guest.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum GuestRequest {
    /// Verifies that the exact guest executable understands this protocol.
    Probe {
        /// Protocol version selected by the caller.
        protocol: u16,
        /// Idempotent operation identifier.
        operation_id: String,
    },
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
        /// Optional whole-command-tree process ceiling.
        ///
        /// Windows Hyper-V containers require this value and enforce it with a
        /// nested Job Object. Unix guests reject it because their process limit
        /// is configured at guest-service admission instead.
        process_limit: Option<u32>,
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
    /// Durably replaces one bounded file if its prior state matches.
    ///
    /// A transport failure or rejected operation after dispatch can be
    /// ambiguous if replacement completed but the parent-directory sync or
    /// response failed. Matching optional-file readback is not durability
    /// proof: callers must issue a fresh atomic commit for the same bytes and
    /// require its synchronization-closing `Committed` or `AlreadyCurrent`
    /// outcome.
    AtomicCommitFile {
        /// Protocol version selected by the caller.
        protocol: u16,
        /// Idempotent operation identifier.
        operation_id: String,
        /// Absolute destination path whose parent already exists.
        path: String,
        /// Base64-encoded file content.
        content_base64: String,
        /// Expected prior target state used for optimistic fencing.
        expected: GuestFileExpectation,
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
    /// Reads one bounded file while representing absence explicitly.
    ReadOptionalFile {
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
            Self::Probe {
                protocol,
                operation_id,
            } => formatter
                .debug_struct("GuestRequest::Probe")
                .field("protocol", protocol)
                .field("operation_id", operation_id)
                .finish(),
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
                process_limit,
                ..
            } => formatter
                .debug_struct("GuestRequest::Exec")
                .field("protocol", protocol)
                .field("operation_id", operation_id)
                .field("argument_count", &arguments.len())
                .field("environment_count", &environment.len())
                .field("process_limit", process_limit)
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
            Self::AtomicCommitFile {
                protocol,
                operation_id,
                content_base64,
                ..
            } => formatter
                .debug_struct("GuestRequest::AtomicCommitFile")
                .field("protocol", protocol)
                .field("operation_id", operation_id)
                .field("encoded_bytes", &content_base64.len())
                .field("expected", &"[REDACTED]")
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
            Self::ReadOptionalFile {
                protocol,
                operation_id,
                byte_limit,
                ..
            } => formatter
                .debug_struct("GuestRequest::ReadOptionalFile")
                .field("protocol", protocol)
                .field("operation_id", operation_id)
                .field("byte_limit", byte_limit)
                .field("path", &"[REDACTED]")
                .finish(),
        }
    }
}

#[cfg(any(unix, windows))]
impl GuestRequest {
    fn protocol(&self) -> u16 {
        match self {
            Self::Probe { protocol, .. }
            | Self::Hello { protocol, .. }
            | Self::Configure { protocol, .. }
            | Self::Exec { protocol, .. }
            | Self::WriteFile { protocol, .. }
            | Self::AtomicCommitFile { protocol, .. }
            | Self::ReadFile { protocol, .. }
            | Self::ReadOptionalFile { protocol, .. } => *protocol,
        }
    }

    fn operation_id(&self) -> &str {
        match self {
            Self::Probe { operation_id, .. }
            | Self::Hello { operation_id, .. }
            | Self::Configure { operation_id, .. }
            | Self::Exec { operation_id, .. }
            | Self::WriteFile { operation_id, .. }
            | Self::AtomicCommitFile { operation_id, .. }
            | Self::ReadFile { operation_id, .. }
            | Self::ReadOptionalFile { operation_id, .. } => operation_id,
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
    /// The guest executable accepted the exact protocol version.
    Ready {
        /// Guest protocol version.
        protocol: u16,
    },
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
    /// An optimistic atomic file replacement completed.
    AtomicCommitFile {
        /// Guest protocol version.
        protocol: u16,
        /// Whether bytes were committed, already current, or fenced out.
        outcome: GuestAtomicCommitOutcome,
    },
    /// A file read completed.
    ReadFile {
        /// Guest protocol version.
        protocol: u16,
        /// Base64-encoded content.
        content_base64: String,
    },
    /// An optional-file read completed.
    ReadOptionalFile {
        /// Guest protocol version.
        protocol: u16,
        /// Explicit present-or-missing file state.
        file: GuestOptionalFile,
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
            Self::Ready { protocol } => formatter
                .debug_struct("GuestResponse::Ready")
                .field("protocol", protocol)
                .finish(),
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
            Self::AtomicCommitFile { protocol, outcome } => formatter
                .debug_struct("GuestResponse::AtomicCommitFile")
                .field("protocol", protocol)
                .field("outcome", outcome)
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
            Self::ReadOptionalFile { protocol, file } => formatter
                .debug_struct("GuestResponse::ReadOptionalFile")
                .field("protocol", protocol)
                .field("file", file)
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

/// Handles one framed request on standard input and writes one framed response.
///
/// This transport is used by Hyper-V-isolated Windows containers so argv,
/// environment values, and file bytes never enter the container-runtime
/// command line. It deliberately serves one request and exits; lifecycle and
/// replay fencing remain owned by the host provider.
///
/// # Errors
///
/// Returns a sanitized framing or standard-I/O failure.
#[cfg(any(unix, windows))]
pub async fn serve_stdio_once() -> Result<(), GuestProtocolError> {
    let mut input = tokio::io::stdin();
    let frame = read_frame(&mut input).await?;
    let request: GuestRequest = decode_frame(&frame)?;
    if matches!(request, GuestRequest::AtomicCommitFile { .. }) {
        require_eof(&mut input).await?;
    }
    let response = match immediate_rejection(&request) {
        Some(response) => response,
        None => handle_request(request, None).await,
    };
    let mut output = tokio::io::stdout();
    output.write_all(&encode_frame(&response)?).await?;
    output.flush().await?;
    Ok(())
}

/// Rejects the one-shot standard-I/O transport on unsupported platforms.
///
/// # Errors
///
/// Always returns an unsupported transport error.
#[cfg(not(any(unix, windows)))]
#[allow(clippy::unused_async)]
pub async fn serve_stdio_once() -> Result<(), GuestProtocolError> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "guest stdio transport is unavailable",
    )
    .into())
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
    let immediate_response = immediate_rejection(&request);
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

#[cfg(any(unix, windows))]
fn immediate_rejection(request: &GuestRequest) -> Option<GuestResponse> {
    if request.protocol() != GUEST_PROTOCOL_VERSION {
        Some(GuestResponse::Rejected {
            protocol: GUEST_PROTOCOL_VERSION,
            kind: GuestRejection::UnsupportedProtocol,
        })
    } else if !valid_operation_id(request.operation_id()) {
        Some(rejected(GuestRejection::InvalidRequest))
    } else {
        None
    }
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

#[cfg(any(unix, windows))]
async fn require_eof<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(), GuestProtocolError> {
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

#[cfg(any(unix, windows))]
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

#[cfg(any(unix, windows))]
async fn handle_request(request: GuestRequest, identity: Option<GuestIdentity>) -> GuestResponse {
    match request {
        GuestRequest::Probe { .. } => GuestResponse::Ready {
            protocol: GUEST_PROTOCOL_VERSION,
        },
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
            process_limit,
            ..
        } => {
            execute(
                program,
                arguments,
                environment,
                working_directory,
                timeout_millis,
                output_limit,
                process_limit,
            )
            .await
        }
        GuestRequest::WriteFile {
            path,
            content_base64,
            ..
        } => write_file(&path, &content_base64).await,
        GuestRequest::AtomicCommitFile {
            operation_id,
            path,
            content_base64,
            expected,
            ..
        } => atomic_commit_file(operation_id, path, content_base64, expected).await,
        GuestRequest::ReadFile {
            path, byte_limit, ..
        } => read_file(&path, byte_limit).await,
        GuestRequest::ReadOptionalFile {
            path, byte_limit, ..
        } => read_optional_file(&path, byte_limit).await,
    }
}

#[cfg(any(unix, windows))]
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

#[cfg(windows)]
fn configure_process_limit(_process_limit: u32) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows process limits are enforced by the container runtime",
    ))
}

#[cfg(any(unix, windows))]
#[allow(clippy::too_many_arguments)]
async fn execute(
    program: String,
    arguments: Vec<String>,
    environment: BTreeMap<String, String>,
    working_directory: String,
    timeout_millis: u64,
    output_limit: usize,
    process_limit: Option<u32>,
) -> GuestResponse {
    if !valid_execution_request(
        &program,
        &arguments,
        &environment,
        &working_directory,
        timeout_millis,
        output_limit,
        process_limit,
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
    let Ok((mut child, containment)) = spawn_contained(command, process_limit) else {
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
        &containment,
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
            containment.terminate();
            let _ = child.kill().await;
            let _ = child.wait().await;
            return rejected(GuestRejection::OperationFailed);
        }
        None => {
            stdout_task.abort();
            stderr_task.abort();
            containment.terminate();
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

#[cfg(any(unix, windows))]
async fn collect_process_output(
    child: &mut tokio::process::Child,
    receiver: &mut mpsc::Receiver<(GuestOutputStream, Vec<u8>)>,
    containment: &ProcessContainment,
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
                containment.terminate();
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
struct ProcessContainment {
    process_group: u32,
}

#[cfg(windows)]
struct ProcessContainment {
    job: processkit::ProcessGroup,
}

#[cfg(unix)]
fn spawn_contained(
    mut command: Command,
    process_limit: Option<u32>,
) -> Result<(tokio::process::Child, ProcessContainment), ()> {
    if process_limit.is_some() {
        return Err(());
    }
    command.process_group(0);
    let child = command.spawn().map_err(|_| ())?;
    let process_group = child.id().ok_or(())?;
    Ok((child, ProcessContainment { process_group }))
}

#[cfg(windows)]
fn spawn_contained(
    command: Command,
    process_limit: Option<u32>,
) -> Result<(tokio::process::Child, ProcessContainment), ()> {
    let process_limit = process_limit
        .filter(|value| (1..=MAX_PROCESS_LIMIT).contains(value))
        .ok_or(())?;
    let job = processkit::ProcessGroup::with_options(
        processkit::ProcessGroupOptions::default().max_processes(process_limit),
    )
    .map_err(|_| ())?;
    let child = job.spawn(command).map_err(|_| ())?;
    Ok((child, ProcessContainment { job }))
}

#[cfg(unix)]
impl ProcessContainment {
    fn terminate(&self) {
        let Ok(process_group) = i32::try_from(self.process_group) else {
            return;
        };
        let Some(process_group) = rustix::process::Pid::from_raw(process_group) else {
            return;
        };
        let _ = rustix::process::kill_process_group(process_group, rustix::process::Signal::KILL);
    }
}

#[cfg(windows)]
impl ProcessContainment {
    fn terminate(&self) {
        let _ = self.job.kill_all();
    }
}

#[cfg(any(unix, windows))]
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

#[cfg(any(unix, windows))]
async fn write_file(path: &str, content_base64: &str) -> GuestResponse {
    let Ok(content) = BASE64.decode(content_base64) else {
        return rejected(GuestRejection::InvalidRequest);
    };
    if !valid_absolute_path(path) || content.len() > MAX_GUEST_FRAME_BYTES / 2 {
        return rejected(GuestRejection::InvalidRequest);
    }
    let Some(parent) = Path::new(path).parent() else {
        return rejected(GuestRejection::InvalidRequest);
    };
    if tokio::fs::create_dir_all(parent).await.is_err() {
        return rejected(GuestRejection::OperationFailed);
    }
    match tokio::fs::write(path, content).await {
        Ok(()) => GuestResponse::WriteFile {
            protocol: GUEST_PROTOCOL_VERSION,
        },
        Err(_) => rejected(GuestRejection::OperationFailed),
    }
}

#[cfg(unix)]
#[derive(Clone, Copy)]
enum ParsedFileExpectation {
    Absent,
    Sha256([u8; 32]),
}

#[cfg(any(unix, windows))]
#[cfg_attr(windows, allow(clippy::unused_async))]
async fn atomic_commit_file(
    operation_id: String,
    path: String,
    content_base64: String,
    expected: GuestFileExpectation,
) -> GuestResponse {
    let Ok(content) = BASE64.decode(content_base64) else {
        return rejected(GuestRejection::InvalidRequest);
    };
    if !valid_operation_id(&operation_id)
        || !valid_explicit_file_path(&path)
        || content.len() > MAX_GUEST_FRAME_BYTES / 2
    {
        return rejected(GuestRejection::InvalidRequest);
    }
    #[cfg(unix)]
    {
        let expected = match expected {
            GuestFileExpectation::Absent => ParsedFileExpectation::Absent,
            GuestFileExpectation::Sha256 { digest } => {
                let Some(digest) = parse_lowercase_sha256(&digest) else {
                    return rejected(GuestRejection::InvalidRequest);
                };
                ParsedFileExpectation::Sha256(digest)
            }
        };
        match tokio::task::spawn_blocking(move || {
            atomic_commit_file_unix(&operation_id, &path, &content, expected)
        })
        .await
        {
            Ok(Ok(outcome)) => GuestResponse::AtomicCommitFile {
                protocol: GUEST_PROTOCOL_VERSION,
                outcome,
            },
            Ok(Err(())) | Err(_) => rejected(GuestRejection::OperationFailed),
        }
    }

    #[cfg(windows)]
    {
        if let GuestFileExpectation::Sha256 { digest } = &expected
            && parse_lowercase_sha256(digest).is_none()
        {
            return rejected(GuestRejection::InvalidRequest);
        }
        let _ = (operation_id, path, content, expected);
        rejected(GuestRejection::OperationFailed)
    }
}

#[cfg(any(unix, windows))]
fn parse_lowercase_sha256(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = lowercase_hex_nibble(pair[0])?;
        let low = lowercase_hex_nibble(pair[1])?;
        digest[index] = (high << 4) | low;
    }
    Some(digest)
}

#[cfg(any(unix, windows))]
const fn lowercase_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(unix)]
fn atomic_commit_file_unix(
    operation_id: &str,
    path: &str,
    content: &[u8],
    expected: ParsedFileExpectation,
) -> Result<GuestAtomicCommitOutcome, ()> {
    atomic_commit_file_unix_with_directory_sync(operation_id, path, content, expected, |parent| {
        unix_fs::fsync(parent).map_err(|_| ())
    })
}

#[cfg(unix)]
fn atomic_commit_file_unix_with_directory_sync<SyncDirectory>(
    operation_id: &str,
    path: &str,
    content: &[u8],
    expected: ParsedFileExpectation,
    sync_directory: SyncDirectory,
) -> Result<GuestAtomicCommitOutcome, ()>
where
    SyncDirectory: FnOnce(&OwnedFd) -> Result<(), ()>,
{
    atomic_commit_file_unix_with_hooks(
        operation_id,
        path,
        content,
        expected,
        |_, _| Ok(()),
        sync_directory,
    )
}

#[cfg(unix)]
fn atomic_commit_file_unix_with_hooks<BeforeRename, SyncDirectory>(
    operation_id: &str,
    path: &str,
    content: &[u8],
    expected: ParsedFileExpectation,
    before_rename: BeforeRename,
    sync_directory: SyncDirectory,
) -> Result<GuestAtomicCommitOutcome, ()>
where
    BeforeRename: FnOnce(&OwnedFd, &str) -> Result<(), ()>,
    SyncDirectory: FnOnce(&OwnedFd) -> Result<(), ()>,
{
    let (parent, target_name) = open_secure_parent(path).map_err(|_| ())?;
    flock(&parent, FlockOperation::LockExclusive).map_err(|_| ())?;

    let current = read_secure_regular_target(&parent, &target_name, MAX_GUEST_FRAME_BYTES / 2)
        .map_err(|_| ())?;
    if current.as_ref().map(|current| current.content.as_slice()) == Some(content) {
        current
            .as_ref()
            .expect("present content retains its exact descriptor")
            .descriptor
            .sync_all()
            .map_err(|_| ())?;
        sync_directory(&parent)?;
        return Ok(GuestAtomicCommitOutcome::AlreadyCurrent);
    }
    let expectation_matches = match (
        expected,
        current.as_ref().map(|current| current.content.as_slice()),
    ) {
        (ParsedFileExpectation::Absent, None) => true,
        (ParsedFileExpectation::Sha256(expected), Some(current)) => {
            <[u8; 32]>::from(Sha256::digest(current)) == expected
        }
        (ParsedFileExpectation::Absent | ParsedFileExpectation::Sha256(_), _) => false,
    };
    if !expectation_matches {
        return Ok(GuestAtomicCommitOutcome::Conflict);
    }

    let temporary_prefix = atomic_temporary_prefix(operation_id, path);
    let (mut temporary, temporary_name) =
        create_atomic_temporary(&parent, &target_name, &temporary_prefix)?;
    if temporary
        .write_all(content)
        .and_then(|()| temporary.sync_all())
        .is_err()
    {
        drop(temporary);
        cleanup_atomic_temporary(&parent, &temporary_name);
        return Err(());
    }
    drop(temporary);
    if before_rename(&parent, &temporary_name).is_err() {
        cleanup_atomic_temporary(&parent, &temporary_name);
        return Err(());
    }
    if renameat(&parent, temporary_name.as_str(), &parent, &target_name).is_err() {
        cleanup_atomic_temporary(&parent, &temporary_name);
        return Err(());
    }
    sync_directory(&parent)?;
    Ok(GuestAtomicCommitOutcome::Committed)
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
enum SecureFileError {
    NotFound,
    InvalidRequest,
    OperationFailed,
}

#[cfg(unix)]
struct SecureRegularFileRead {
    descriptor: File,
    content: Vec<u8>,
}

#[cfg(unix)]
fn open_secure_parent(path: &str) -> Result<(OwnedFd, OsString), SecureFileError> {
    let target = Path::new(path);
    let parent_path = target.parent().ok_or(SecureFileError::InvalidRequest)?;
    let target_name = target
        .file_name()
        .ok_or(SecureFileError::InvalidRequest)?
        .to_os_string();
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let mut parent =
        open("/", directory_flags, Mode::empty()).map_err(|_| SecureFileError::OperationFailed)?;
    for component in parent_path.components().skip(1) {
        let Component::Normal(name) = component else {
            return Err(SecureFileError::InvalidRequest);
        };
        parent = match openat(&parent, name, directory_flags, Mode::empty()) {
            Ok(parent) => parent,
            Err(Errno::NOENT) => return Err(SecureFileError::NotFound),
            Err(_) => return Err(SecureFileError::OperationFailed),
        };
    }
    Ok((parent, target_name))
}

#[cfg(unix)]
fn read_secure_regular_target(
    parent: &OwnedFd,
    target_name: &OsString,
    byte_limit: usize,
) -> Result<Option<SecureRegularFileRead>, SecureFileError> {
    let descriptor = match openat(
        parent,
        target_name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(Errno::NOENT) => return Ok(None),
        Err(_) => return Err(SecureFileError::OperationFailed),
    };
    let metadata = fstat(&descriptor).map_err(|_| SecureFileError::OperationFailed)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile {
        return Err(SecureFileError::OperationFailed);
    }
    if u64::try_from(metadata.st_size).map_err(|_| SecureFileError::OperationFailed)?
        > u64::try_from(byte_limit).map_err(|_| SecureFileError::InvalidRequest)?
    {
        return Err(SecureFileError::InvalidRequest);
    }
    let read_limit =
        u64::try_from(byte_limit.saturating_add(1)).map_err(|_| SecureFileError::InvalidRequest)?;
    let mut content = Vec::with_capacity(
        usize::try_from(metadata.st_size)
            .unwrap_or(OUTPUT_CHUNK_BYTES)
            .min(OUTPUT_CHUNK_BYTES),
    );
    let mut descriptor = File::from(descriptor);
    (&mut descriptor)
        .take(read_limit)
        .read_to_end(&mut content)
        .map_err(|_| SecureFileError::OperationFailed)?;
    if content.len() > byte_limit {
        return Err(SecureFileError::InvalidRequest);
    }
    Ok(Some(SecureRegularFileRead {
        descriptor,
        content,
    }))
}

#[cfg(unix)]
fn atomic_temporary_prefix(operation_id: &str, path: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut hasher = Sha256::new();
    hasher.update(operation_id.as_bytes());
    hasher.update([0]);
    hasher.update(path.as_bytes());
    let digest = hasher.finalize();
    let mut name = String::with_capacity(28 + digest.len() * 2);
    name.push_str(".automata-ci-atomic-stage-");
    for byte in digest {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    name.push('-');
    name
}

#[cfg(unix)]
fn create_atomic_temporary(
    parent: &OwnedFd,
    target_name: &OsString,
    temporary_prefix: &str,
) -> Result<(File, String), ()> {
    create_atomic_temporary_with_random(parent, target_name, temporary_prefix, |random| {
        getrandom::fill(random).map_err(|_| ())
    })
}

#[cfg(unix)]
fn create_atomic_temporary_with_random<FillRandom>(
    parent: &OwnedFd,
    target_name: &OsString,
    temporary_prefix: &str,
    mut fill_random: FillRandom,
) -> Result<(File, String), ()>
where
    FillRandom: FnMut(&mut [u8; ATOMIC_STAGE_RANDOM_BYTES]) -> Result<(), ()>,
{
    for _ in 0..MAX_ATOMIC_STAGE_CREATE_ATTEMPTS {
        let mut random = [0_u8; ATOMIC_STAGE_RANDOM_BYTES];
        fill_random(&mut random)?;
        let temporary_name = atomic_temporary_name(temporary_prefix, &random);
        if target_name.as_bytes() == temporary_name.as_bytes() {
            continue;
        }
        match openat(
            parent,
            temporary_name.as_str(),
            OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::CLOEXEC
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(temporary) => return Ok((File::from(temporary), temporary_name)),
            Err(Errno::EXIST) => {}
            Err(_) => return Err(()),
        }
    }
    Err(())
}

#[cfg(unix)]
fn atomic_temporary_name(prefix: &str, random: &[u8; ATOMIC_STAGE_RANDOM_BYTES]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut name = String::with_capacity(prefix.len() + random.len() * 2);
    name.push_str(prefix);
    for byte in random {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    name
}

#[cfg(unix)]
fn cleanup_atomic_temporary(parent: &OwnedFd, temporary_name: &str) {
    if unlinkat(parent, temporary_name, AtFlags::empty()).is_ok() {
        let _ = unix_fs::fsync(parent);
    }
}

#[cfg(any(unix, windows))]
async fn read_file(path: &str, byte_limit: usize) -> GuestResponse {
    if !valid_absolute_path(path) || byte_limit == 0 || byte_limit > MAX_GUEST_FRAME_BYTES / 2 {
        return rejected(GuestRejection::InvalidRequest);
    }
    let content = match read_bounded_file(path, byte_limit).await {
        Ok(Some(content)) => content,
        Ok(None) | Err(GuestRejection::OperationFailed) => {
            return rejected(GuestRejection::OperationFailed);
        }
        Err(kind) => return rejected(kind),
    };
    GuestResponse::ReadFile {
        protocol: GUEST_PROTOCOL_VERSION,
        content_base64: BASE64.encode(content),
    }
}

#[cfg(any(unix, windows))]
async fn read_optional_file(path: &str, byte_limit: usize) -> GuestResponse {
    if !valid_explicit_file_path(path) || byte_limit == 0 || byte_limit > MAX_GUEST_FRAME_BYTES / 2
    {
        return rejected(GuestRejection::InvalidRequest);
    }

    #[cfg(unix)]
    {
        let path = path.to_owned();
        match tokio::task::spawn_blocking(move || read_optional_file_unix(&path, byte_limit)).await
        {
            Ok(Ok(content)) => GuestResponse::ReadOptionalFile {
                protocol: GUEST_PROTOCOL_VERSION,
                file: content.map_or(GuestOptionalFile::Missing {}, |content| {
                    GuestOptionalFile::Present {
                        content_base64: BASE64.encode(content),
                    }
                }),
            },
            Ok(Err(SecureFileError::InvalidRequest)) => rejected(GuestRejection::InvalidRequest),
            Ok(Err(SecureFileError::NotFound | SecureFileError::OperationFailed)) | Err(_) => {
                rejected(GuestRejection::OperationFailed)
            }
        }
    }

    #[cfg(windows)]
    {
        match read_bounded_file(path, byte_limit).await {
            Ok(content) => GuestResponse::ReadOptionalFile {
                protocol: GUEST_PROTOCOL_VERSION,
                file: content.map_or(GuestOptionalFile::Missing {}, |content| {
                    GuestOptionalFile::Present {
                        content_base64: BASE64.encode(content),
                    }
                }),
            },
            Err(kind) => rejected(kind),
        }
    }
}

#[cfg(unix)]
fn read_optional_file_unix(
    path: &str,
    byte_limit: usize,
) -> Result<Option<Vec<u8>>, SecureFileError> {
    let (parent, target_name) = match open_secure_parent(path) {
        Ok(target) => target,
        Err(SecureFileError::NotFound) => return Ok(None),
        Err(error) => return Err(error),
    };
    read_secure_regular_target(&parent, &target_name, byte_limit)
        .map(|content| content.map(|content| content.content))
}

#[cfg(any(unix, windows))]
async fn read_bounded_file(
    path: &str,
    byte_limit: usize,
) -> Result<Option<Vec<u8>>, GuestRejection> {
    let file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(GuestRejection::OperationFailed),
    };
    let mut content = Vec::with_capacity(byte_limit.min(OUTPUT_CHUNK_BYTES));
    let Ok(read_limit) = u64::try_from(byte_limit.saturating_add(1)) else {
        return Err(GuestRejection::InvalidRequest);
    };
    if file
        .take(read_limit)
        .read_to_end(&mut content)
        .await
        .is_err()
    {
        return Err(GuestRejection::OperationFailed);
    }
    if content.len() > byte_limit {
        return Err(GuestRejection::InvalidRequest);
    }
    Ok(Some(content))
}

#[cfg(any(unix, windows))]
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
fn valid_explicit_file_path(value: &str) -> bool {
    valid_absolute_path(value) && !value.ends_with('/')
}

#[cfg(windows)]
fn valid_absolute_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes.len() <= MAX_TARGET_PATH_BYTES
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'\\'
        && !value.contains('/')
        && !value.contains("\\\\")
        && !value.contains('\0')
        && value.split('\\').skip(1).all(|component| {
            !matches!(component, "." | "..")
                && !component.ends_with([' ', '.'])
                && !component
                    .bytes()
                    .any(|byte| matches!(byte, b':' | b'*' | b'?' | b'"' | b'<' | b'>' | b'|'))
        })
}

#[cfg(windows)]
fn valid_explicit_file_path(value: &str) -> bool {
    valid_absolute_path(value) && !value.ends_with('\\')
}

#[cfg(any(unix, windows))]
fn valid_operation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_OPERATION_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

#[cfg(any(unix, windows))]
fn valid_execution_request(
    program: &str,
    arguments: &[String],
    environment: &BTreeMap<String, String>,
    working_directory: &str,
    timeout_millis: u64,
    output_limit: usize,
    process_limit: Option<u32>,
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
        && valid_process_limit(process_limit)
}

#[cfg(unix)]
const fn valid_process_limit(process_limit: Option<u32>) -> bool {
    process_limit.is_none()
}

#[cfg(windows)]
fn valid_process_limit(process_limit: Option<u32>) -> bool {
    process_limit.is_some_and(|value| (1..=MAX_PROCESS_LIMIT).contains(&value))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPERATION_ONE: &str = "00000000-0000-4000-8000-000000000001";

    #[cfg(any(unix, windows))]
    #[test]
    fn protocol_v4_rejects_every_prior_wire_version() {
        assert_eq!(GUEST_PROTOCOL_VERSION, 4);
        for protocol in [1, 2, 3] {
            let request = GuestRequest::Probe {
                protocol,
                operation_id: OPERATION_ONE.into(),
            };
            assert_eq!(
                immediate_rejection(&request),
                Some(GuestResponse::Rejected {
                    protocol: GUEST_PROTOCOL_VERSION,
                    kind: GuestRejection::UnsupportedProtocol,
                })
            );
        }
        let current = GuestRequest::Probe {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: OPERATION_ONE.into(),
        };
        assert_eq!(immediate_rejection(&current), None);
    }

    #[cfg(any(unix, windows))]
    #[tokio::test]
    async fn write_file_creates_the_attempt_scoped_parent_directory() {
        let root = std::env::temp_dir().join(format!(
            "automata-guest-write-parent-{}",
            std::process::id()
        ));
        let target = root.join("attempt").join("commands").join("probe.txt");
        let target = target.to_string_lossy();
        assert!(matches!(
            write_file(&target, &BASE64.encode(b"probe")).await,
            GuestResponse::WriteFile {
                protocol: GUEST_PROTOCOL_VERSION
            }
        ));
        assert_eq!(tokio::fs::read(target.as_ref()).await.unwrap(), b"probe");
        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn atomic_commit_is_fenced_and_an_identical_retry_is_idempotent() {
        let root = fresh_test_directory("atomic-fenced").await;
        let target = root
            .join("desired-spec.json")
            .to_string_lossy()
            .into_owned();

        let first = atomic_commit_file(
            OPERATION_ONE.into(),
            target.clone(),
            BASE64.encode(b"first"),
            GuestFileExpectation::Absent,
        )
        .await;
        assert_eq!(
            first,
            GuestResponse::AtomicCommitFile {
                protocol: GUEST_PROTOCOL_VERSION,
                outcome: GuestAtomicCommitOutcome::Committed,
            }
        );
        let retry = atomic_commit_file(
            OPERATION_ONE.into(),
            target.clone(),
            BASE64.encode(b"first"),
            GuestFileExpectation::Absent,
        )
        .await;
        assert_eq!(
            retry,
            GuestResponse::AtomicCommitFile {
                protocol: GUEST_PROTOCOL_VERSION,
                outcome: GuestAtomicCommitOutcome::AlreadyCurrent,
            }
        );

        let conflict = atomic_commit_file(
            "00000000-0000-4000-8000-000000000002".into(),
            target.clone(),
            BASE64.encode(b"conflicting"),
            GuestFileExpectation::Absent,
        )
        .await;
        assert_eq!(
            conflict,
            GuestResponse::AtomicCommitFile {
                protocol: GUEST_PROTOCOL_VERSION,
                outcome: GuestAtomicCommitOutcome::Conflict,
            }
        );
        assert_eq!(
            tokio::fs::read(&target).await.expect("read target"),
            b"first"
        );

        let replacement = atomic_commit_file(
            "00000000-0000-4000-8000-000000000003".into(),
            target.clone(),
            BASE64.encode(b"replacement"),
            GuestFileExpectation::Sha256 {
                digest: sha256_hex(b"first"),
            },
        )
        .await;
        assert_eq!(
            replacement,
            GuestResponse::AtomicCommitFile {
                protocol: GUEST_PROTOCOL_VERSION,
                outcome: GuestAtomicCommitOutcome::Committed,
            }
        );
        assert_eq!(
            tokio::fs::read(&target).await.expect("read target"),
            b"replacement"
        );
        tokio::fs::remove_dir_all(root)
            .await
            .expect("remove fixture");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn concurrent_atomic_commits_serialize_the_expected_state_check() {
        let root = fresh_test_directory("atomic-concurrent").await;
        let target = root
            .join("desired-spec.json")
            .to_string_lossy()
            .into_owned();
        let first = atomic_commit_file(
            OPERATION_ONE.into(),
            target.clone(),
            BASE64.encode(b"first"),
            GuestFileExpectation::Absent,
        );
        let second = atomic_commit_file(
            "00000000-0000-4000-8000-000000000002".into(),
            target,
            BASE64.encode(b"second"),
            GuestFileExpectation::Absent,
        );
        let (first, second) = tokio::join!(first, second);
        let outcomes = [first, second].map(|response| match response {
            GuestResponse::AtomicCommitFile { outcome, .. } => outcome,
            response => panic!("unexpected response: {response:?}"),
        });
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == GuestAtomicCommitOutcome::Committed)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == GuestAtomicCommitOutcome::Conflict)
                .count(),
            1
        );
        tokio::fs::remove_dir_all(root)
            .await
            .expect("remove fixture");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn atomic_commit_rejects_invalid_state_and_ignores_foreign_crash_stages() {
        let root = fresh_test_directory("atomic-invalid").await;
        let target = root
            .join("desired-spec.json")
            .to_string_lossy()
            .into_owned();
        assert_eq!(
            atomic_commit_file(
                OPERATION_ONE.into(),
                target.clone(),
                BASE64.encode(b"first"),
                GuestFileExpectation::Sha256 {
                    digest: "A".repeat(64),
                },
            )
            .await,
            rejected(GuestRejection::InvalidRequest)
        );
        assert!(!Path::new(&target).exists());

        let prefix = atomic_temporary_prefix(OPERATION_ONE, &target);
        let stage = root.join(atomic_temporary_name(
            &prefix,
            &[7; ATOMIC_STAGE_RANDOM_BYTES],
        ));
        tokio::fs::write(&stage, b"foreign")
            .await
            .expect("write foreign stage");
        assert_eq!(
            atomic_commit_file(
                OPERATION_ONE.into(),
                target.clone(),
                BASE64.encode(b"first"),
                GuestFileExpectation::Absent,
            )
            .await,
            GuestResponse::AtomicCommitFile {
                protocol: GUEST_PROTOCOL_VERSION,
                outcome: GuestAtomicCommitOutcome::Committed,
            }
        );
        assert_eq!(
            tokio::fs::read(&stage).await.expect("read foreign stage"),
            b"foreign"
        );

        let (parent, target_name) = open_secure_parent(&target).expect("open target parent");
        let mut calls = 0_u8;
        let (created, created_name) =
            create_atomic_temporary_with_random(&parent, &target_name, &prefix, |random| {
                calls += 1;
                random.fill(if calls == 1 { 7 } else { 8 });
                Ok(())
            })
            .expect("retry random collision");
        drop(created);
        assert_eq!(calls, 2);
        assert_ne!(root.join(&created_name), stage);
        assert_eq!(
            tokio::fs::read(&stage).await.expect("read foreign stage"),
            b"foreign"
        );
        tokio::fs::remove_dir_all(root)
            .await
            .expect("remove fixture");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn post_rename_sync_failure_requires_fresh_readback() {
        let root = fresh_test_directory("atomic-ambiguous").await;
        let target = root
            .join("desired-spec.json")
            .to_string_lossy()
            .into_owned();
        assert_eq!(
            atomic_commit_file_unix_with_directory_sync(
                OPERATION_ONE,
                &target,
                b"committed-before-sync-failure",
                ParsedFileExpectation::Absent,
                |_| Err(()),
            ),
            Err(())
        );
        assert_eq!(
            read_optional_file(&target, 64).await,
            GuestResponse::ReadOptionalFile {
                protocol: GUEST_PROTOCOL_VERSION,
                file: GuestOptionalFile::Present {
                    content_base64: BASE64.encode(b"committed-before-sync-failure"),
                },
            }
        );
        assert_eq!(
            atomic_commit_file_unix_with_directory_sync(
                OPERATION_ONE,
                &target,
                b"committed-before-sync-failure",
                ParsedFileExpectation::Absent,
                |_| Err(()),
            ),
            Err(())
        );
        assert_eq!(
            atomic_commit_file(
                OPERATION_ONE.into(),
                target,
                BASE64.encode(b"committed-before-sync-failure"),
                GuestFileExpectation::Absent,
            )
            .await,
            GuestResponse::AtomicCommitFile {
                protocol: GUEST_PROTOCOL_VERSION,
                outcome: GuestAtomicCommitOutcome::AlreadyCurrent,
            }
        );
        tokio::fs::remove_dir_all(root)
            .await
            .expect("remove fixture");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pre_rename_failure_cleans_only_its_new_random_stage() {
        let root = fresh_test_directory("atomic-pre-rename-failure").await;
        let target = root
            .join("desired-spec.json")
            .to_string_lossy()
            .into_owned();
        tokio::fs::write(&target, b"retained")
            .await
            .expect("write target fixture");

        let operation_id = "00000000-0000-4000-8000-000000000004";
        let prefix = atomic_temporary_prefix(operation_id, &target);
        let foreign_name = atomic_temporary_name(&prefix, &[7; ATOMIC_STAGE_RANDOM_BYTES]);
        let foreign_stage = root.join(&foreign_name);
        tokio::fs::write(&foreign_stage, b"foreign")
            .await
            .expect("write foreign stage");

        let created_name = std::cell::RefCell::new(None);
        assert_eq!(
            atomic_commit_file_unix_with_hooks(
                operation_id,
                &target,
                b"replacement",
                ParsedFileExpectation::Sha256(
                    parse_lowercase_sha256(&sha256_hex(b"retained")).expect("fixture digest"),
                ),
                |_, name| {
                    assert_eq!(
                        std::fs::read(root.join(name)).expect("read exact new stage"),
                        b"replacement"
                    );
                    created_name.replace(Some(name.to_owned()));
                    Err(())
                },
                |_| panic!("directory sync must not run before rename"),
            ),
            Err(())
        );

        let created_name = created_name.into_inner().expect("capture exact new stage");
        assert_ne!(created_name, foreign_name);
        assert!(!root.join(created_name).exists());
        assert_eq!(
            tokio::fs::read(&foreign_stage)
                .await
                .expect("read foreign stage"),
            b"foreign"
        );
        assert_eq!(
            tokio::fs::read(&target).await.expect("read target"),
            b"retained"
        );
        tokio::fs::remove_dir_all(root)
            .await
            .expect("remove fixture");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn atomic_commit_requires_a_preexisting_real_parent_and_regular_target() {
        let root = fresh_test_directory("atomic-paths").await;
        let missing_target = root
            .join("missing")
            .join("desired-spec.json")
            .to_string_lossy()
            .into_owned();
        assert_eq!(
            atomic_commit_file(
                OPERATION_ONE.into(),
                missing_target,
                BASE64.encode(b"first"),
                GuestFileExpectation::Absent,
            )
            .await,
            rejected(GuestRejection::OperationFailed)
        );
        assert!(!root.join("missing").exists());

        let directory_target = root.join("directory-target");
        tokio::fs::create_dir(&directory_target)
            .await
            .expect("create directory target");
        assert_eq!(
            atomic_commit_file(
                "00000000-0000-4000-8000-000000000002".into(),
                directory_target.to_string_lossy().into_owned(),
                BASE64.encode(b"first"),
                GuestFileExpectation::Absent,
            )
            .await,
            rejected(GuestRejection::OperationFailed)
        );
        assert!(directory_target.is_dir());
        tokio::fs::remove_dir_all(root)
            .await
            .expect("remove fixture");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn optional_read_distinguishes_only_a_missing_file() {
        let root = fresh_test_directory("optional-read").await;
        let missing = root.join("missing").to_string_lossy().into_owned();
        assert_eq!(
            read_optional_file(&missing, 16).await,
            GuestResponse::ReadOptionalFile {
                protocol: GUEST_PROTOCOL_VERSION,
                file: GuestOptionalFile::Missing {},
            }
        );
        let missing_parent = root
            .join("missing-parent")
            .join("missing")
            .to_string_lossy()
            .into_owned();
        assert_eq!(
            read_optional_file(&missing_parent, 16).await,
            GuestResponse::ReadOptionalFile {
                protocol: GUEST_PROTOCOL_VERSION,
                file: GuestOptionalFile::Missing {},
            }
        );

        let present = root.join("present");
        tokio::fs::write(&present, b"present")
            .await
            .expect("write fixture");
        assert_eq!(
            read_optional_file(&present.to_string_lossy(), 16).await,
            GuestResponse::ReadOptionalFile {
                protocol: GUEST_PROTOCOL_VERSION,
                file: GuestOptionalFile::Present {
                    content_base64: BASE64.encode(b"present"),
                },
            }
        );
        let symlink = root.join("symlink");
        std::os::unix::fs::symlink(&present, &symlink).expect("create target symlink");
        assert_eq!(
            read_optional_file(&symlink.to_string_lossy(), 16).await,
            rejected(GuestRejection::OperationFailed)
        );

        let real_parent = root.join("real-parent");
        tokio::fs::create_dir(&real_parent)
            .await
            .expect("create real parent");
        tokio::fs::write(real_parent.join("present"), b"present")
            .await
            .expect("write nested fixture");
        let parent_symlink = root.join("parent-symlink");
        std::os::unix::fs::symlink(&real_parent, &parent_symlink).expect("create parent symlink");
        assert_eq!(
            read_optional_file(&parent_symlink.join("present").to_string_lossy(), 16,).await,
            rejected(GuestRejection::OperationFailed)
        );
        assert_eq!(
            read_optional_file(&root.to_string_lossy(), 16).await,
            rejected(GuestRejection::OperationFailed)
        );
        tokio::fs::remove_dir_all(root)
            .await
            .expect("remove fixture");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn atomic_commit_and_optional_read_reject_trailing_slash_aliases() {
        let root = fresh_test_directory("file-trailing-slash").await;
        let target = root.join("desired-spec.json");
        tokio::fs::write(&target, b"retained")
            .await
            .expect("write target fixture");
        let alias = format!("{}/", target.to_string_lossy());

        assert_eq!(
            atomic_commit_file(
                OPERATION_ONE.into(),
                alias.clone(),
                BASE64.encode(b"replacement"),
                GuestFileExpectation::Sha256 {
                    digest: sha256_hex(b"retained"),
                },
            )
            .await,
            rejected(GuestRejection::InvalidRequest)
        );
        assert_eq!(
            read_optional_file(&alias, 16).await,
            rejected(GuestRejection::InvalidRequest)
        );
        assert_eq!(
            tokio::fs::read(&target).await.expect("read target"),
            b"retained"
        );
        tokio::fs::remove_dir_all(root)
            .await
            .expect("remove fixture");
    }

    #[cfg(unix)]
    async fn fresh_test_directory(label: &str) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("automata-guest-{label}-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&root).await;
        tokio::fs::create_dir(&root)
            .await
            .expect("create test directory");
        root
    }

    #[cfg(unix)]
    fn sha256_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";

        let digest = Sha256::digest(bytes);
        let mut encoded = String::with_capacity(digest.len() * 2);
        for byte in digest {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }

    #[cfg(windows)]
    #[test]
    fn windows_execution_requires_an_explicit_bounded_process_limit() {
        let working_directory = std::env::temp_dir().to_string_lossy().into_owned();
        let valid = |process_limit| {
            valid_execution_request(
                r"C:\Windows\System32\cmd.exe",
                &[],
                &BTreeMap::new(),
                &working_directory,
                1_000,
                1_024,
                process_limit,
            )
        };
        assert!(valid(Some(8)));
        assert!(!valid(None));
        assert!(!valid(Some(0)));
        assert!(!valid(Some(MAX_PROCESS_LIMIT + 1)));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_atomic_commit_rejects_valid_expectations_without_mutation() {
        let root = std::env::temp_dir().join(format!(
            "automata-guest-windows-atomic-valid-{}",
            std::process::id()
        ));
        let _ = tokio::fs::remove_dir_all(&root).await;
        tokio::fs::create_dir(&root)
            .await
            .expect("create test directory");

        let missing = root.join("missing.json").to_string_lossy().into_owned();
        assert_eq!(
            atomic_commit_file(
                OPERATION_ONE.into(),
                missing.clone(),
                BASE64.encode(b"new"),
                GuestFileExpectation::Absent,
            )
            .await,
            rejected(GuestRejection::OperationFailed)
        );
        assert!(!Path::new(&missing).exists());

        let target = root.join("present.json");
        tokio::fs::write(&target, b"retained")
            .await
            .expect("write target fixture");
        assert_eq!(
            atomic_commit_file(
                "00000000-0000-4000-8000-000000000002".into(),
                target.to_string_lossy().into_owned(),
                BASE64.encode(b"replacement"),
                GuestFileExpectation::Sha256 {
                    digest: "0".repeat(64),
                },
            )
            .await,
            rejected(GuestRejection::OperationFailed)
        );
        assert_eq!(
            tokio::fs::read(&target).await.expect("read target"),
            b"retained"
        );
        tokio::fs::remove_dir_all(root)
            .await
            .expect("remove fixture");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_atomic_commit_rejects_invalid_digest_and_trailing_aliases_without_mutation() {
        let root = std::env::temp_dir().join(format!(
            "automata-guest-windows-atomic-invalid-{}",
            std::process::id()
        ));
        let _ = tokio::fs::remove_dir_all(&root).await;
        tokio::fs::create_dir(&root)
            .await
            .expect("create test directory");
        let target = root.join("present.json");
        tokio::fs::write(&target, b"retained")
            .await
            .expect("write target fixture");

        assert_eq!(
            atomic_commit_file(
                OPERATION_ONE.into(),
                target.to_string_lossy().into_owned(),
                BASE64.encode(b"replacement"),
                GuestFileExpectation::Sha256 {
                    digest: "A".repeat(64),
                },
            )
            .await,
            rejected(GuestRejection::InvalidRequest)
        );

        let alias = format!("{}\\", target.to_string_lossy());
        assert_eq!(
            atomic_commit_file(
                "00000000-0000-4000-8000-000000000002".into(),
                alias.clone(),
                BASE64.encode(b"replacement"),
                GuestFileExpectation::Absent,
            )
            .await,
            rejected(GuestRejection::InvalidRequest)
        );
        assert_eq!(
            read_optional_file(&alias, 16).await,
            rejected(GuestRejection::InvalidRequest)
        );
        assert_eq!(
            tokio::fs::read(&target).await.expect("read target"),
            b"retained"
        );
        tokio::fs::remove_dir_all(root)
            .await
            .expect("remove fixture");
    }

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
            process_limit: None,
        };
        let frame = encode_frame(&request).expect("frame");
        assert_eq!(
            decode_frame::<GuestRequest>(&frame).expect("decode"),
            request
        );
        let debug = format!("{request:?}");
        assert!(!debug.contains("secret-argument"));
        assert!(!debug.contains("secret-value"));

        let atomic = GuestRequest::AtomicCommitFile {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: OPERATION_ONE.into(),
            path: "/secret/path".into(),
            content_base64: BASE64.encode(b"secret-content"),
            expected: GuestFileExpectation::Sha256 {
                digest: "a".repeat(64),
            },
        };
        assert_eq!(
            decode_frame::<GuestRequest>(&encode_frame(&atomic).expect("frame")).expect("decode"),
            atomic
        );
        let debug = format!("{atomic:?}");
        assert!(!debug.contains("/secret/path"));
        assert!(!debug.contains("secret-content"));
        assert!(!debug.contains(&"a".repeat(64)));
        assert!(
            !format!(
                "{:?}",
                GuestFileExpectation::Sha256 {
                    digest: "b".repeat(64)
                }
            )
            .contains(&"b".repeat(64))
        );
    }

    #[test]
    fn optional_file_response_requires_an_explicit_closed_state() {
        let present = GuestResponse::ReadOptionalFile {
            protocol: GUEST_PROTOCOL_VERSION,
            file: GuestOptionalFile::Present {
                content_base64: BASE64.encode(b"secret-optional-content"),
            },
        };
        assert_eq!(
            decode_frame::<GuestResponse>(&encode_frame(&present).expect("encode present"))
                .expect("decode present"),
            present
        );
        let debug = format!("{present:?}");
        assert!(!debug.contains("secret-optional-content"));
        assert!(!debug.contains(&BASE64.encode(b"secret-optional-content")));

        let missing = GuestResponse::ReadOptionalFile {
            protocol: GUEST_PROTOCOL_VERSION,
            file: GuestOptionalFile::Missing {},
        };
        assert_eq!(
            decode_frame::<GuestResponse>(&encode_frame(&missing).expect("encode missing"))
                .expect("decode missing"),
            missing
        );

        for malformed in [
            serde_json::json!({
                "result": "read_optional_file",
                "protocol": GUEST_PROTOCOL_VERSION,
            }),
            serde_json::json!({
                "result": "read_optional_file",
                "protocol": GUEST_PROTOCOL_VERSION,
                "file": { "state": "present" },
            }),
            serde_json::json!({
                "result": "read_optional_file",
                "protocol": GUEST_PROTOCOL_VERSION,
                "file": {
                    "state": "missing",
                    "content_base64": BASE64.encode(b"forbidden"),
                },
            }),
        ] {
            assert!(
                decode_frame::<GuestResponse>(
                    &encode_frame(&malformed).expect("encode malformed fixture")
                )
                .is_err()
            );
        }
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
            None,
        ));
        assert!(!valid_execution_request(
            "/bin/true",
            &vec![String::new(); MAX_EXECUTION_ARGUMENTS + 1],
            &BTreeMap::new(),
            "/tmp",
            1,
            1,
            None,
        ));
        assert!(!valid_execution_request(
            "/bin/true",
            &[],
            &BTreeMap::new(),
            "/tmp",
            MAX_COMMAND_TIMEOUT_MILLIS + 1,
            1,
            None,
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
            None,
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
            None,
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
