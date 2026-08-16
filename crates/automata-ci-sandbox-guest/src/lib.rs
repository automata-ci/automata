#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Versioned, framed transport used to keep command arguments and environment
//! values out of Kubernetes Pod specifications, exec request URLs, and
//! Windows container-runtime command lines.

use std::{collections::BTreeMap, fmt, io, path::Path};

#[cfg(unix)]
use std::{
    ffi::OsString,
    fs::File,
    io::{Read as _, Write as _},
    os::unix::ffi::OsStrExt as _,
    path::Component,
    sync::{Arc, Mutex, MutexGuard},
};
#[cfg(target_os = "linux")]
use std::{
    io::Seek as _,
    sync::atomic::{AtomicBool, Ordering},
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
#[cfg(target_os = "linux")]
use rustix::fs::{RenameFlags, StatVfsMountFlags, renameat_with};
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
/// Version 5 makes live-operation replay non-evicting for the guest lifetime
/// and rejects new operation identifiers before execution when the bounded
/// replay store cannot reserve their result. It also retains version 4's
/// optimistic durable file replacement and explicit optional-file reads.
/// Earlier versions are rejected instead of being interpreted as the current
/// wire contract.
pub const GUEST_PROTOCOL_VERSION: u16 = 5;
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
const MAX_CACHED_RESPONSE_BYTES: usize = MAX_GUEST_FRAME_BYTES + 4;
#[cfg(unix)]
const MAX_REPLAY_BYTES: usize = 64 * 1024 * 1024;
#[cfg(unix)]
const SMALL_CACHED_RESPONSE_BYTES: usize = 16 * 1024;
#[cfg(unix)]
const RESPONSE_FIXED_WIRE_BYTES: usize = 1_024;
#[cfg(unix)]
const OUTPUT_RECORD_WIRE_OVERHEAD_BYTES: usize = 96;
#[cfg(unix)]
const MAX_ATOMIC_STAGE_CREATE_ATTEMPTS: usize = 8;
#[cfg(unix)]
const ATOMIC_STAGE_RANDOM_BYTES: usize = 16;
/// Largest guest executable admitted by the protected local bootstrap contract.
pub const MAX_LOCAL_GUEST_BINARY_BYTES: u64 = 24 * 1024 * 1024;
/// Exact tmpfs byte ceiling required by the protected local bootstrap contract.
pub const LOCAL_CONTROL_TMPFS_BYTES: u64 = 64 * 1024 * 1024;
const LOCAL_CONTROL_TMPFS_MINIMUM_HEADROOM_BYTES: u64 = 8 * 1024 * 1024;
const _: () = assert!(
    LOCAL_CONTROL_TMPFS_BYTES
        >= MAX_LOCAL_GUEST_BINARY_BYTES * 2 + LOCAL_CONTROL_TMPFS_MINIMUM_HEADROOM_BYTES
);
/// Initial mode of the sealer-owned protected-control tmpfs mount.
pub const LOCAL_CONTROL_DIRECTORY_MODE_INITIAL: u32 = 0o733;
/// Final mode of the sealed protected-control directory.
pub const LOCAL_CONTROL_DIRECTORY_MODE_SEALED: u32 = 0o510;
/// Exact mode of the immutable bootstrap seed.
pub const LOCAL_CONTROL_SEED_MODE: u32 = 0o555;
/// Private construction mode used before the bootstrap seed is published.
pub const LOCAL_CONTROL_SEED_STAGE_MODE: u32 = 0o600;
/// Exact mode of the sealed protected client.
pub const LOCAL_CONTROL_CLIENT_MODE: u32 = 0o550;
/// Read-only staging mode used before the protected client is sealed.
pub const LOCAL_CONTROL_CLIENT_MODE_STAGED: u32 = 0o554;
#[cfg(target_os = "linux")]
const LOCAL_CONTROL_TMPFS_MAGIC: i64 = 0x0102_1994;
#[cfg(target_os = "linux")]
static LOCAL_EXECUTION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
#[cfg(target_os = "linux")]
const LOCAL_STAGE_REQUEST: &[u8] = b"\xff\xff\xff\xffautomata-local-client-stage-v1";
#[cfg(target_os = "linux")]
const LOCAL_STAGE_ACKNOWLEDGEMENT: &[u8] = b"automata-local-client-stage-ok-v1";
#[cfg(target_os = "linux")]
const LOCAL_SEAL_REQUEST: &[u8] = b"automata-local-client-seal-v1";
#[cfg(target_os = "linux")]
const LOCAL_SEAL_ACKNOWLEDGEMENT: &[u8] = b"automata-local-client-ready-v1";
#[cfg(target_os = "linux")]
const LOCAL_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(5);

/// Fixed Linux abstract socket used by the evaluation-only local broker.
pub const LOCAL_CONTROL_SOCKET: &str = "@automata-ci-control-v1";
/// Fixed tmpfs mount protecting the local broker client from the root job.
pub const LOCAL_CONTROL_DIRECTORY: &str = "/automata-control";
/// One-shot local broker seed executable, present only during startup.
pub const LOCAL_CONTROL_SEED: &str = "/automata-control/.seed";
/// Sealed local broker client executable used for all live operations.
pub const LOCAL_CONTROL_CLIENT: &str = "/automata-control/automata-ci-sandbox-guest";
/// Dedicated UID accepted by the Linux local broker.
pub const LOCAL_CONTROL_UID: u32 = 65_532;
/// Dedicated GID accepted by the Linux local broker.
pub const LOCAL_CONTROL_GID: u32 = 65_532;
/// One-shot UID that owns and seals the Linux local control tmpfs.
pub const LOCAL_CONTROL_SEAL_UID: u32 = 65_533;

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

impl GuestResponse {
    /// Returns the protocol version carried by this response.
    #[must_use]
    pub const fn protocol(&self) -> u16 {
        match self {
            Self::Ready { protocol }
            | Self::Hello { protocol, .. }
            | Self::Configured { protocol }
            | Self::Exec { protocol, .. }
            | Self::WriteFile { protocol }
            | Self::AtomicCommitFile { protocol, .. }
            | Self::ReadFile { protocol, .. }
            | Self::ReadOptionalFile { protocol, .. }
            | Self::Rejected { protocol, .. } => *protocol,
        }
    }
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
    /// The lifetime replay store cannot admit another operation safely.
    ReplayCapacityExceeded,
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

#[cfg(target_os = "linux")]
struct LocalBootstrap {
    control: OwnedFd,
    seed: File,
    seed_device: u64,
    seed_inode: u64,
    seed_size: i64,
    seed_digest: [u8; 32],
    ready: AtomicBool,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocalPeerRole {
    Unrestricted,
    #[cfg(target_os = "linux")]
    Sealer,
    #[cfg(target_os = "linux")]
    Client,
}

#[cfg(unix)]
#[derive(Clone)]
enum GuestServiceMode {
    Standard,
    #[cfg(target_os = "linux")]
    Local(Arc<LocalBootstrap>),
}

#[cfg(unix)]
impl GuestServiceMode {
    const fn local_pid_one(&self) -> bool {
        match self {
            Self::Standard => false,
            #[cfg(target_os = "linux")]
            Self::Local(_) => true,
        }
    }
}

#[cfg(target_os = "linux")]
impl LocalBootstrap {
    fn prepare() -> io::Result<Self> {
        if rustix::process::getpid().as_raw_pid() != 1
            || rustix::process::getuid().as_raw() != 0
            || rustix::process::geteuid().as_raw() != 0
            || rustix::process::getgid().as_raw() != 0
            || rustix::process::getegid().as_raw() != 0
        {
            return Err(local_contract_error());
        }
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)?;
        if rustix::process::dumpable_behavior()? != rustix::process::DumpableBehavior::NotDumpable
            || !valid_local_process_envelope()?
        {
            return Err(local_contract_error());
        }
        let control = open(
            LOCAL_CONTROL_DIRECTORY,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        if !valid_local_control(
            &control,
            LOCAL_CONTROL_DIRECTORY_MODE_INITIAL,
            LOCAL_CONTROL_SEAL_UID,
            LOCAL_CONTROL_GID,
        ) || !local_path_absent(&control, ".seed")?
            || !local_path_absent(&control, ".seed.stage")?
            || !local_path_absent(&control, "automata-ci-sandbox-guest")?
        {
            return Err(local_contract_error());
        }

        let seed = openat(
            &control,
            ".seed.stage",
            OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(LOCAL_CONTROL_SEED_STAGE_MODE),
        )?;
        let mut seed = File::from(seed);
        let source = File::open("/proc/self/exe")?;
        let source_size = source.metadata()?.len();
        if source_size == 0 || source_size > MAX_LOCAL_GUEST_BINARY_BYTES {
            return Err(local_contract_error());
        }
        let mut source = source.take(MAX_LOCAL_GUEST_BINARY_BYTES + 1);
        let mut digest = Sha256::new();
        let mut copied = 0_u64;
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let read = source.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            copied = copied
                .checked_add(u64::try_from(read).map_err(|_| local_contract_error())?)
                .ok_or_else(local_contract_error)?;
            if copied > MAX_LOCAL_GUEST_BINARY_BYTES {
                return Err(local_contract_error());
            }
            digest.update(&buffer[..read]);
            seed.write_all(&buffer[..read])?;
        }
        if copied != source_size {
            return Err(local_contract_error());
        }
        seed.flush()?;
        unix_fs::fchmod(&seed, Mode::from_raw_mode(LOCAL_CONTROL_SEED_MODE))?;
        unix_fs::fsync(&seed)?;
        let written = fstat(&seed)?;
        if !valid_local_seed_stat(&written, 1) {
            return Err(local_contract_error());
        }
        drop(seed);

        renameat_with(
            &control,
            ".seed.stage",
            &control,
            ".seed",
            RenameFlags::NOREPLACE,
        )?;

        let seed = openat(
            &control,
            ".seed",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let seed = File::from(seed);
        let written = fstat(&seed)?;
        if !valid_local_seed_stat(&written, 1) {
            return Err(local_contract_error());
        }
        Ok(Self {
            control,
            seed,
            seed_device: written.st_dev,
            seed_inode: written.st_ino,
            seed_size: written.st_size,
            seed_digest: digest.finalize().into(),
            ready: AtomicBool::new(false),
        })
    }

    fn verify_staged(&self) -> io::Result<File> {
        if self.is_ready() {
            return Err(local_contract_error());
        }
        let seed = fstat(&self.seed)?;
        let control_valid = valid_local_control(
            &self.control,
            LOCAL_CONTROL_DIRECTORY_MODE_INITIAL,
            LOCAL_CONTROL_SEAL_UID,
            LOCAL_CONTROL_GID,
        );
        let seed_valid = valid_local_seed_stat(&seed, 0);
        let seed_absent = local_path_absent(&self.control, ".seed")?;
        let stage_absent = local_path_absent(&self.control, ".seed.stage")?;
        if !control_valid
            || !seed_valid
            || seed.st_dev != self.seed_device
            || seed.st_ino != self.seed_inode
            || seed.st_size != self.seed_size
            || !seed_absent
            || !stage_absent
        {
            return Err(local_contract_error());
        }
        let client = openat(
            &self.control,
            "automata-ci-sandbox-guest",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let mut client = File::from(client);
        let client_valid = valid_local_staged_client_stat(&fstat(&client)?);
        let digest_valid = file_has_digest(&mut client, self.seed_size, &self.seed_digest)?;
        if !client_valid || !digest_valid {
            return Err(local_contract_error());
        }
        Ok(client)
    }

    fn verify_sealed_and_mark_ready(&self, client: &mut File) -> io::Result<()> {
        let seed = fstat(&self.seed)?;
        if !valid_local_control(
            &self.control,
            LOCAL_CONTROL_DIRECTORY_MODE_SEALED,
            LOCAL_CONTROL_SEAL_UID,
            LOCAL_CONTROL_GID,
        ) || !valid_local_client_stat(&fstat(&*client)?)
            || !file_has_digest(client, self.seed_size, &self.seed_digest)?
            || !valid_local_seed_stat(&seed, 0)
            || seed.st_dev != self.seed_device
            || seed.st_ino != self.seed_inode
            || seed.st_size != self.seed_size
        {
            return Err(local_contract_error());
        }
        self.ready.store(true, Ordering::Release);
        Ok(())
    }

    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
}

#[cfg(target_os = "linux")]
fn valid_local_process_envelope() -> io::Result<bool> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    if status.len() > 64 * 1024 {
        return Ok(false);
    }
    let field = |name: &str| {
        status.lines().find_map(|line| {
            line.strip_prefix(name)
                .and_then(|value| value.strip_prefix(':'))
                .map(str::trim)
        })
    };
    let zero_credentials = |value: &str| value.split_ascii_whitespace().eq(["0", "0", "0", "0"]);
    let zero_capability = |name: &str| field(name) == Some("0000000000000000");
    let groups = rustix::process::getgroups()?;
    Ok(field("Uid").is_some_and(zero_credentials)
        && field("Gid").is_some_and(zero_credentials)
        && field("Groups").is_some_and(|value| value.split_ascii_whitespace().eq(["0"]))
        && groups.len() == 1
        && groups[0].as_raw() == 0
        && zero_capability("CapInh")
        && zero_capability("CapPrm")
        && zero_capability("CapEff")
        && zero_capability("CapBnd")
        && zero_capability("CapAmb")
        && field("NoNewPrivs") == Some("1")
        && field("Seccomp") == Some("2"))
}

#[cfg(target_os = "linux")]
fn valid_local_control<Fd: std::os::fd::AsFd>(control: Fd, mode: u32, uid: u32, gid: u32) -> bool {
    let Ok(stat) = fstat(&control) else {
        return false;
    };
    let Ok(filesystem_stats) = unix_fs::fstatfs(&control) else {
        return false;
    };
    let Ok(mount_stats) = unix_fs::fstatvfs(control) else {
        return false;
    };
    let required_flags = StatVfsMountFlags::NOSUID | StatVfsMountFlags::NODEV;
    let rejected_flags = StatVfsMountFlags::NOEXEC | StatVfsMountFlags::RDONLY;
    FileType::from_raw_mode(stat.st_mode) == FileType::Directory
        && stat.st_uid == uid
        && stat.st_gid == gid
        && stat.st_mode & 0o7777 == mode
        && stat.st_nlink == 2
        && filesystem_stats.f_type == LOCAL_CONTROL_TMPFS_MAGIC
        && mount_stats.f_flag.contains(required_flags)
        && !mount_stats.f_flag.intersects(rejected_flags)
        && mount_stats
            .f_frsize
            .checked_mul(mount_stats.f_blocks)
            .is_some_and(|bytes| bytes == LOCAL_CONTROL_TMPFS_BYTES)
}

#[cfg(target_os = "linux")]
fn valid_local_client_stat(stat: &unix_fs::Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
        && stat.st_uid == LOCAL_CONTROL_SEAL_UID
        && stat.st_gid == LOCAL_CONTROL_GID
        && stat.st_mode & 0o7777 == LOCAL_CONTROL_CLIENT_MODE
        && stat.st_nlink == 1
        && stat.st_size > 0
        && u64::try_from(stat.st_size).is_ok_and(|size| size <= MAX_LOCAL_GUEST_BINARY_BYTES)
}

#[cfg(target_os = "linux")]
fn valid_local_staged_client_stat(stat: &unix_fs::Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
        && stat.st_uid == LOCAL_CONTROL_SEAL_UID
        && stat.st_gid == LOCAL_CONTROL_GID
        && stat.st_mode & 0o7777 == LOCAL_CONTROL_CLIENT_MODE_STAGED
        && stat.st_nlink == 1
        && stat.st_size > 0
        && u64::try_from(stat.st_size).is_ok_and(|size| size <= MAX_LOCAL_GUEST_BINARY_BYTES)
}

#[cfg(target_os = "linux")]
fn valid_local_seed_stat(stat: &unix_fs::Stat, links: u64) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
        && stat.st_uid == 0
        && stat.st_gid == 0
        && stat.st_mode & 0o7777 == LOCAL_CONTROL_SEED_MODE
        && stat.st_nlink == links
        && stat.st_size > 0
        && u64::try_from(stat.st_size).is_ok_and(|size| size <= MAX_LOCAL_GUEST_BINARY_BYTES)
}

#[cfg(target_os = "linux")]
fn file_has_digest(file: &mut File, size: i64, expected: &[u8; 32]) -> io::Result<bool> {
    file.rewind()?;
    let mut digest = Sha256::new();
    let mut observed = 0_i64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        observed = observed
            .checked_add(i64::try_from(read).map_err(|_| local_contract_error())?)
            .ok_or_else(local_contract_error)?;
        if observed > size {
            return Ok(false);
        }
        digest.update(&buffer[..read]);
    }
    Ok(observed == size && <[u8; 32]>::from(digest.finalize()) == *expected)
}

#[cfg(target_os = "linux")]
fn local_path_absent(control: &OwnedFd, name: &str) -> io::Result<bool> {
    match openat(
        control,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(_) => Ok(false),
        Err(Errno::NOENT) => Ok(true),
        Err(error) => Err(error.into()),
    }
}

#[cfg(target_os = "linux")]
fn stage_local_client() -> io::Result<OwnedFd> {
    if rustix::process::getuid().as_raw() != LOCAL_CONTROL_SEAL_UID
        || rustix::process::geteuid().as_raw() != LOCAL_CONTROL_SEAL_UID
        || rustix::process::getgid().as_raw() != LOCAL_CONTROL_GID
        || rustix::process::getegid().as_raw() != LOCAL_CONTROL_GID
    {
        return Err(local_contract_error());
    }
    let control = open(
        LOCAL_CONTROL_DIRECTORY,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    if !valid_local_control(
        &control,
        LOCAL_CONTROL_DIRECTORY_MODE_INITIAL,
        LOCAL_CONTROL_SEAL_UID,
        LOCAL_CONTROL_GID,
    ) || !local_path_absent(&control, ".seed.stage")?
        || !local_path_absent(&control, "automata-ci-sandbox-guest")?
    {
        return Err(local_contract_error());
    }
    let seed = openat(
        &control,
        ".seed",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let seed_stat = fstat(&seed)?;
    let executable = File::open("/proc/self/exe")?;
    let executable_stat = fstat(&executable)?;
    if !valid_local_seed_stat(&seed_stat, 1)
        || seed_stat.st_dev != executable_stat.st_dev
        || seed_stat.st_ino != executable_stat.st_ino
        || seed_stat.st_size != executable_stat.st_size
    {
        return Err(local_contract_error());
    }
    let client = openat(
        &control,
        "automata-ci-sandbox-guest",
        OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(LOCAL_CONTROL_CLIENT_MODE_STAGED),
    )?;
    let mut client = File::from(client);
    let mut source = executable.take(MAX_LOCAL_GUEST_BINARY_BYTES + 1);
    let copied = io::copy(&mut source, &mut client)?;
    if copied == 0
        || copied > MAX_LOCAL_GUEST_BINARY_BYTES
        || i64::try_from(copied).ok() != Some(seed_stat.st_size)
    {
        return Err(local_contract_error());
    }
    client.flush()?;
    unix_fs::fchmod(
        &client,
        Mode::from_raw_mode(LOCAL_CONTROL_CLIENT_MODE_STAGED),
    )?;
    unix_fs::fsync(&client)?;
    if !valid_local_staged_client_stat(&fstat(&client)?) {
        return Err(local_contract_error());
    }
    drop(client);
    unlinkat(&control, ".seed", AtFlags::empty())?;
    unix_fs::fsync(&control)?;
    Ok(control)
}

#[cfg(target_os = "linux")]
fn validate_local_client_state(control: &OwnedFd) -> io::Result<()> {
    if !valid_local_control(
        control,
        LOCAL_CONTROL_DIRECTORY_MODE_SEALED,
        LOCAL_CONTROL_SEAL_UID,
        LOCAL_CONTROL_GID,
    ) || !local_path_absent(control, ".seed")?
        || !local_path_absent(control, ".seed.stage")?
    {
        return Err(local_contract_error());
    }
    let client = openat(
        control,
        "automata-ci-sandbox-guest",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut client = File::from(client);
    let mut executable = File::open("/proc/self/exe")?;
    let client_stat = fstat(&client)?;
    let executable_stat = fstat(&executable)?;
    if !valid_local_client_stat(&client_stat) || client_stat.st_size != executable_stat.st_size {
        return Err(local_contract_error());
    }
    let client_digest: [u8; 32] = Sha256::digest(read_bounded_local_file(&mut client)?).into();
    let executable_digest: [u8; 32] =
        Sha256::digest(read_bounded_local_file(&mut executable)?).into();
    if client_digest != executable_digest {
        return Err(local_contract_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_bounded_local_file(file: &mut File) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(MAX_LOCAL_GUEST_BINARY_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let size = u64::try_from(bytes.len()).map_err(|_| local_contract_error())?;
    if size == 0 || size > MAX_LOCAL_GUEST_BINARY_BYTES {
        return Err(local_contract_error());
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
async fn exchange_local_seal(control: &OwnedFd) -> io::Result<()> {
    let deadline = tokio::time::Instant::now() + LOCAL_BOOTSTRAP_TIMEOUT;
    let mut stream = loop {
        match connect_stream(Path::new(LOCAL_CONTROL_SOCKET)).await {
            Ok(stream) => break stream,
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => return Err(error),
        }
    };
    stream.write_all(LOCAL_STAGE_REQUEST).await?;
    let mut staged = vec![0; LOCAL_STAGE_ACKNOWLEDGEMENT.len()];
    stream.read_exact(&mut staged).await?;
    if staged != LOCAL_STAGE_ACKNOWLEDGEMENT {
        return Err(local_contract_error());
    }
    let client = openat(
        control,
        "automata-ci-sandbox-guest",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    unix_fs::fchmod(&client, Mode::from_raw_mode(LOCAL_CONTROL_CLIENT_MODE))?;
    unix_fs::fsync(&client)?;
    unix_fs::fchmod(
        control,
        Mode::from_raw_mode(LOCAL_CONTROL_DIRECTORY_MODE_SEALED),
    )?;
    unix_fs::fsync(control)?;
    stream.write_all(LOCAL_SEAL_REQUEST).await?;
    stream.shutdown().await?;
    let mut acknowledgement = vec![0; LOCAL_SEAL_ACKNOWLEDGEMENT.len()];
    stream.read_exact(&mut acknowledgement).await?;
    require_eof(&mut stream)
        .await
        .map_err(|error| match error {
            GuestProtocolError::Io(error) => error,
            GuestProtocolError::InvalidFrame => local_contract_error(),
        })?;
    if acknowledgement != LOCAL_SEAL_ACKNOWLEDGEMENT {
        return Err(local_contract_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn local_contract_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "local guest contract rejected",
    )
}

/// Runs the guest Unix-socket server until its listener fails.
///
/// # Errors
///
/// Returns a sanitized transport error when the socket cannot be bound or accepted.
#[cfg(unix)]
pub async fn serve(socket: &Path) -> Result<(), GuestProtocolError> {
    serve_internal(socket, None, GuestServiceMode::Standard).await
}

/// Runs the fixed Linux local broker as the container's non-dumpable PID 1.
///
/// # Errors
///
/// Rejects any process, control tmpfs, or seed state outside the closed local
/// contract, and returns a sanitized transport error when serving fails.
#[cfg(target_os = "linux")]
pub async fn serve_local_broker() -> Result<(), GuestProtocolError> {
    let bootstrap = Arc::new(LocalBootstrap::prepare()?);
    serve_internal(
        Path::new(LOCAL_CONTROL_SOCKET),
        None,
        GuestServiceMode::Local(bootstrap),
    )
    .await
}

/// Atomically seals the fixed Linux local client and authenticates it to PID 1.
///
/// This command is deliberately one-shot and must be invoked by the Docker
/// manager as UID 65533 and GID 65532 from [`LOCAL_CONTROL_SEED`] before any workflow
/// process exists.
///
/// # Errors
///
/// Rejects the wrong caller, executable, tmpfs, ownership, mode, link, or
/// prior setup state, as well as a broker that does not acknowledge the seal.
#[cfg(target_os = "linux")]
pub async fn seal_local_client() -> Result<(), GuestProtocolError> {
    let control = stage_local_client()?;
    exchange_local_seal(&control).await?;
    validate_local_client_state(&control)?;
    Ok(())
}

/// Waits for PID 1's exact seed and executes its one-shot local sealing mode.
///
/// The Docker manager invokes this pre-workload bootstrap through the exact
/// overlay guest it already uploaded and read back. The sealing child itself
/// is always executed from PID 1's independently copied seed.
///
/// # Errors
///
/// Returns a sanitized failure if the seed does not appear within the fixed
/// startup deadline or its sealing child does not exit successfully.
#[cfg(target_os = "linux")]
pub async fn bootstrap_local_client() -> Result<(), GuestProtocolError> {
    if rustix::process::getuid().as_raw() != LOCAL_CONTROL_SEAL_UID
        || rustix::process::geteuid().as_raw() != LOCAL_CONTROL_SEAL_UID
        || rustix::process::getgid().as_raw() != LOCAL_CONTROL_GID
        || rustix::process::getegid().as_raw() != LOCAL_CONTROL_GID
    {
        return Err(local_contract_error().into());
    }
    let deadline = tokio::time::Instant::now() + LOCAL_BOOTSTRAP_TIMEOUT;
    loop {
        match std::fs::symlink_metadata(LOCAL_CONTROL_SEED) {
            Ok(metadata) if metadata.file_type().is_file() => break,
            Ok(_) => return Err(local_contract_error().into()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "local seed timed out").into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let status = tokio::time::timeout(
        LOCAL_BOOTSTRAP_TIMEOUT,
        Command::new(LOCAL_CONTROL_SEED)
            .arg("seal-local-client")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .status(),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "local seal timed out"))??;
    if !status.success() {
        return Err(local_contract_error().into());
    }
    Ok(())
}

/// Runs the macOS VM guest server with its mandatory sealed-template identity.
///
/// # Errors
///
/// Returns a sanitized transport error when the socket cannot be bound or accepted.
#[cfg(unix)]
pub async fn serve_vm(socket: &Path, identity: GuestIdentity) -> Result<(), GuestProtocolError> {
    serve_internal(socket, Some(identity), GuestServiceMode::Standard).await
}

#[cfg(unix)]
async fn serve_internal(
    socket: &Path,
    identity: Option<GuestIdentity>,
    service: GuestServiceMode,
) -> Result<(), GuestProtocolError> {
    let listener = bind_listener(socket).await?;
    let replay = Arc::new(Mutex::new(ReplayCache::default()));
    let mut connections = JoinSet::new();
    #[cfg(target_os = "linux")]
    if service.local_pid_one() {
        connections.spawn(reap_local_children());
    }
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                #[cfg(target_os = "linux")]
                let Some(peer_role) = local_peer_role(&stream, &service) else {
                    continue;
                };
                #[cfg(not(target_os = "linux"))]
                let peer_role = LocalPeerRole::Unrestricted;
                let replay = Arc::clone(&replay);
                let identity = identity.clone();
                let service = service.clone();
                connections.spawn(async move {
                    let _ = serve_connection(stream, replay, identity, service, peer_role).await;
                });
            }
            result = connections.join_next(), if !connections.is_empty() => {
                let _ = result;
            }
        }
    }
}

#[cfg(target_os = "linux")]
async fn reap_local_children() {
    loop {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let _execution = LOCAL_EXECUTION_LOCK.lock().await;
        while let Ok(Some(_)) = rustix::process::wait(rustix::process::WaitOptions::NOHANG) {}
    }
}

#[cfg(target_os = "linux")]
fn local_peer_role(stream: &UnixStream, service: &GuestServiceMode) -> Option<LocalPeerRole> {
    let GuestServiceMode::Local(local) = service else {
        return Some(LocalPeerRole::Unrestricted);
    };
    local_stream_peer_role(stream, local.is_ready())
}

#[cfg(target_os = "linux")]
fn local_stream_peer_role(stream: &UnixStream, ready: bool) -> Option<LocalPeerRole> {
    let credentials = stream.peer_cred().ok()?;
    local_peer_role_for_credentials(ready, credentials.uid(), credentials.gid())
}

#[cfg(target_os = "linux")]
const fn local_peer_role_for_credentials(ready: bool, uid: u32, gid: u32) -> Option<LocalPeerRole> {
    if gid != LOCAL_CONTROL_GID {
        return None;
    }
    match (ready, uid) {
        (false, LOCAL_CONTROL_SEAL_UID) => Some(LocalPeerRole::Sealer),
        (true, LOCAL_CONTROL_UID) => Some(LocalPeerRole::Client),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn local_peer_role_is_current(
    captured: LocalPeerRole,
    current: Option<LocalPeerRole>,
    required: LocalPeerRole,
) -> bool {
    captured == required && current == Some(required)
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
    require_eof(&mut input).await?;
    let mut stream = connect_stream(socket).await?;
    stream.write_all(&request).await?;
    stream.shutdown().await?;
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
        None => handle_request(request, None, false).await,
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
    service: GuestServiceMode,
    peer_role: LocalPeerRole,
) -> Result<(), GuestProtocolError> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await?;
    #[cfg(target_os = "linux")]
    if let GuestServiceMode::Local(local) = &service
        && handle_local_seal(&mut stream, &header, local, peer_role).await?
    {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if matches!(&service, GuestServiceMode::Local(_))
        && !local_peer_role_is_current(
            peer_role,
            local_peer_role(&stream, &service),
            LocalPeerRole::Client,
        )
    {
        return Err(GuestProtocolError::InvalidFrame);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = peer_role;
    let frame = read_frame_with_header(&mut stream, header).await?;
    let request: GuestRequest = decode_frame(&frame)?;
    let immediate_response = immediate_rejection(&request);
    if let Some(response) = immediate_response {
        stream.write_all(&encode_frame(&response)?).await?;
        stream.shutdown().await?;
        return Ok(());
    }

    require_eof(&mut stream).await?;
    let response = replay_request(request, replay, identity, service.local_pid_one()).await;
    stream.write_all(&encode_frame(&response)?).await?;
    stream.shutdown().await?;
    Ok(())
}

#[cfg(target_os = "linux")]
async fn handle_local_seal(
    stream: &mut UnixStream,
    header: &[u8; 4],
    local: &Arc<LocalBootstrap>,
    peer_role: LocalPeerRole,
) -> Result<bool, GuestProtocolError> {
    if header != &LOCAL_STAGE_REQUEST[..4] {
        return Ok(false);
    }
    if !local_peer_role_is_current(
        peer_role,
        local_stream_peer_role(stream, local.is_ready()),
        LocalPeerRole::Sealer,
    ) {
        return Err(GuestProtocolError::InvalidFrame);
    }
    let mut remainder = vec![0_u8; LOCAL_STAGE_REQUEST.len() - 4];
    stream.read_exact(&mut remainder).await?;
    if remainder != LOCAL_STAGE_REQUEST[4..] {
        return Err(GuestProtocolError::InvalidFrame);
    }
    let mut client = local.verify_staged()?;
    stream.write_all(LOCAL_STAGE_ACKNOWLEDGEMENT).await?;
    let mut seal = vec![0_u8; LOCAL_SEAL_REQUEST.len()];
    stream.read_exact(&mut seal).await?;
    if seal != LOCAL_SEAL_REQUEST {
        return Err(GuestProtocolError::InvalidFrame);
    }
    require_eof(stream).await?;
    local.verify_sealed_and_mark_ready(&mut client)?;
    stream.write_all(LOCAL_SEAL_ACKNOWLEDGEMENT).await?;
    stream.shutdown().await?;
    Ok(true)
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
    bytes: usize,
    reserved_bytes: usize,
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

    fn insert(
        &mut self,
        operation_id: String,
        fingerprint: [u8; 32],
        response: GuestResponse,
        bytes: usize,
    ) {
        self.bytes = self.bytes.saturating_add(bytes);
        self.entries.insert(
            operation_id,
            ReplayEntry {
                fingerprint,
                response,
            },
        );
    }
}

#[cfg(unix)]
struct ReplayReservation {
    replay: Arc<Mutex<ReplayCache>>,
    operation_id: String,
    fingerprint: [u8; 32],
    reserved_bytes: usize,
    completion: Option<watch::Sender<bool>>,
}

#[cfg(unix)]
impl ReplayReservation {
    fn commit(mut self, response: GuestResponse) -> GuestResponse {
        let (response, bytes) = cacheable_response(response, self.reserved_bytes);
        {
            let mut replay = lock_replay(&self.replay);
            replay.in_flight.remove(&self.operation_id);
            replay.reserved_bytes = replay.reserved_bytes.saturating_sub(self.reserved_bytes);
            replay.insert(
                self.operation_id.clone(),
                self.fingerprint,
                response.clone(),
                bytes,
            );
        }
        if let Some(completion) = self.completion.take() {
            let _ = completion.send(true);
        }
        response
    }
}

#[cfg(unix)]
impl Drop for ReplayReservation {
    fn drop(&mut self) {
        let Some(completion) = self.completion.take() else {
            return;
        };
        let mut replay = lock_replay(&self.replay);
        replay.in_flight.remove(&self.operation_id);
        replay.reserved_bytes = replay.reserved_bytes.saturating_sub(self.reserved_bytes);
        let response = rejected(GuestRejection::OperationFailed);
        let bytes = encode_frame(&response)
            .expect("fixed replay tombstone is encodable")
            .len();
        replay.insert(self.operation_id.clone(), self.fingerprint, response, bytes);
        let _ = completion.send(true);
    }
}

#[cfg(unix)]
fn cacheable_response(response: GuestResponse, reservation: usize) -> (GuestResponse, usize) {
    if let Ok(frame) = encode_frame(&response)
        && frame.len() <= reservation
    {
        return (response, frame.len());
    }
    let response = rejected(GuestRejection::OperationFailed);
    let bytes = encode_frame(&response)
        .expect("fixed replay failure is encodable")
        .len();
    (response, bytes)
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
    reserved_bytes: usize,
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
    if cache.entries.len().saturating_add(cache.in_flight.len()) >= MAX_REPLAY_ENTRIES
        || cache
            .bytes
            .checked_add(cache.reserved_bytes)
            .and_then(|bytes| bytes.checked_add(reserved_bytes))
            .is_none_or(|bytes| bytes > MAX_REPLAY_BYTES)
    {
        return ReplayDecision::Return(rejected(GuestRejection::ReplayCapacityExceeded));
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
    cache.reserved_bytes += reserved_bytes;
    ReplayDecision::Execute(ReplayReservation {
        replay: Arc::clone(replay),
        operation_id: operation_id.to_owned(),
        fingerprint: *fingerprint,
        reserved_bytes,
        completion: Some(completion),
    })
}

#[cfg(unix)]
async fn replay_request(
    request: GuestRequest,
    replay: Arc<Mutex<ReplayCache>>,
    identity: Option<GuestIdentity>,
    local_pid_one: bool,
) -> GuestResponse {
    let fingerprint: [u8; 32] = Sha256::digest(
        serde_json::to_vec(&request).expect("validated guest request is serializable"),
    )
    .into();
    let operation_id = request.operation_id().to_owned();
    let reserved_bytes = replay_reservation_bytes(&request);
    loop {
        match replay_decision(&replay, &operation_id, &fingerprint, reserved_bytes) {
            ReplayDecision::Return(response) => return response,
            ReplayDecision::Wait(mut completion) => {
                if !*completion.borrow() {
                    let _ = completion.changed().await;
                }
            }
            ReplayDecision::Execute(reservation) => {
                let response = handle_request(request, identity, local_pid_one).await;
                return reservation.commit(response);
            }
        }
    }
}

#[cfg(unix)]
fn replay_reservation_bytes(request: &GuestRequest) -> usize {
    match request {
        GuestRequest::Exec { output_limit, .. } => {
            let output_bytes = (*output_limit).min(MAX_EXECUTION_OUTPUT_BYTES);
            let record_count = output_bytes.min(MAX_OUTPUT_DATA_RECORDS).saturating_add(2);
            RESPONSE_FIXED_WIRE_BYTES
                .saturating_add(output_bytes.saturating_mul(4))
                .saturating_add(record_count.saturating_mul(OUTPUT_RECORD_WIRE_OVERHEAD_BYTES))
                .min(MAX_CACHED_RESPONSE_BYTES)
        }
        GuestRequest::ReadFile { byte_limit, .. }
        | GuestRequest::ReadOptionalFile { byte_limit, .. } => RESPONSE_FIXED_WIRE_BYTES
            .saturating_add(
                (*byte_limit)
                    .min(MAX_GUEST_FRAME_BYTES / 2)
                    .saturating_mul(4),
            )
            .min(MAX_CACHED_RESPONSE_BYTES),
        GuestRequest::Probe { .. }
        | GuestRequest::Hello { .. }
        | GuestRequest::Configure { .. }
        | GuestRequest::WriteFile { .. }
        | GuestRequest::AtomicCommitFile { .. } => SMALL_CACHED_RESPONSE_BYTES,
    }
}

#[cfg(any(unix, windows))]
async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, GuestProtocolError> {
    let mut header = [0_u8; 4];
    reader.read_exact(&mut header).await?;
    read_frame_with_header(reader, header).await
}

#[cfg(any(unix, windows))]
async fn read_frame_with_header<R: AsyncRead + Unpin>(
    reader: &mut R,
    header: [u8; 4],
) -> Result<Vec<u8>, GuestProtocolError> {
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
async fn handle_request(
    request: GuestRequest,
    identity: Option<GuestIdentity>,
    local_pid_one: bool,
) -> GuestResponse {
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
                local_pid_one,
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
    local_pid_one: bool,
) -> GuestResponse {
    #[cfg(target_os = "linux")]
    let _execution = if local_pid_one {
        Some(LOCAL_EXECUTION_LOCK.lock().await)
    } else {
        None
    };
    #[cfg(not(target_os = "linux"))]
    let _ = local_pid_one;
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

    #[cfg(target_os = "linux")]
    #[test]
    fn local_peer_role_is_bound_to_accept_time_credentials_and_current_readiness() {
        let sealer =
            local_peer_role_for_credentials(false, LOCAL_CONTROL_SEAL_UID, LOCAL_CONTROL_GID);
        assert_eq!(sealer, Some(LocalPeerRole::Sealer));
        assert!(local_peer_role_is_current(
            sealer.expect("unready sealer role"),
            sealer,
            LocalPeerRole::Sealer,
        ));

        let sealer_after_ready =
            local_peer_role_for_credentials(true, LOCAL_CONTROL_SEAL_UID, LOCAL_CONTROL_GID);
        assert_eq!(sealer_after_ready, None);
        assert!(!local_peer_role_is_current(
            LocalPeerRole::Sealer,
            sealer_after_ready,
            LocalPeerRole::Client,
        ));

        assert_eq!(
            local_peer_role_for_credentials(false, LOCAL_CONTROL_UID, LOCAL_CONTROL_GID),
            None
        );
        let ready_client =
            local_peer_role_for_credentials(true, LOCAL_CONTROL_UID, LOCAL_CONTROL_GID);
        assert_eq!(ready_client, Some(LocalPeerRole::Client));
        assert!(local_peer_role_is_current(
            LocalPeerRole::Client,
            ready_client,
            LocalPeerRole::Client,
        ));
        assert_eq!(
            local_peer_role_for_credentials(true, LOCAL_CONTROL_UID, LOCAL_CONTROL_GID + 1),
            None
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn protocol_v5_rejects_every_prior_wire_version() {
        assert_eq!(GUEST_PROTOCOL_VERSION, 5);
        for protocol in [1, 2, 3, 4] {
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
            handle_request(request, Some(identity.clone()), false).await,
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
            handle_request(request.clone(), Some(identity), false).await,
            rejected(GuestRejection::InvalidRequest)
        );
        assert_eq!(
            handle_request(request, None, false).await,
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
            replay_request(request.clone(), Arc::clone(&replay), None, false).await,
            GuestResponse::WriteFile { .. }
        ));
        tokio::fs::write(&path, b"outside change")
            .await
            .expect("replace fixture");
        assert!(matches!(
            replay_request(request, Arc::clone(&replay), None, false).await,
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
            replay_request(changed, replay, None, false).await,
            rejected(GuestRejection::OperationConflict)
        );
        tokio::fs::remove_file(path).await.expect("remove fixture");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn replay_capacity_is_non_evicting_and_rejects_before_execution() {
        let replay = Arc::new(Mutex::new(ReplayCache::default()));
        for index in 0..MAX_REPLAY_ENTRIES {
            let request = GuestRequest::Probe {
                protocol: GUEST_PROTOCOL_VERSION,
                operation_id: format!("00000000-0000-4000-8000-{index:012x}"),
            };
            assert_eq!(
                replay_request(request, Arc::clone(&replay), None, false).await,
                GuestResponse::Ready {
                    protocol: GUEST_PROTOCOL_VERSION
                }
            );
        }

        let first = GuestRequest::Probe {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: "00000000-0000-4000-8000-000000000000".into(),
        };
        assert_eq!(
            replay_request(first, Arc::clone(&replay), None, false).await,
            GuestResponse::Ready {
                protocol: GUEST_PROTOCOL_VERSION
            }
        );

        let path =
            std::env::temp_dir().join(format!("automata-guest-capacity-{}", std::process::id()));
        let rejected_write = GuestRequest::WriteFile {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: "00000000-0000-4000-8001-000000000000".into(),
            path: path.to_string_lossy().into_owned(),
            content_base64: BASE64.encode(b"must-not-run"),
        };
        assert_eq!(
            replay_request(rejected_write, replay, None, false).await,
            rejected(GuestRejection::ReplayCapacityExceeded)
        );
        assert!(!path.exists(), "capacity rejection must precede execution");
    }

    #[cfg(unix)]
    #[test]
    fn replay_reservations_cover_bounded_wire_shapes_without_consuming_full_frames() {
        let output_limit = 64;
        let exec = GuestRequest::Exec {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: OPERATION_ONE.into(),
            program: "/bin/true".into(),
            arguments: Vec::new(),
            environment: BTreeMap::new(),
            working_directory: "/tmp".into(),
            timeout_millis: 1,
            output_limit,
            process_limit: None,
        };
        let exec_reservation = replay_reservation_bytes(&exec);
        assert!(
            SMALL_CACHED_RESPONSE_BYTES + exec_reservation * 2 <= MAX_REPLAY_BYTES,
            "one cached probe and two ordinary execs must fit concurrently"
        );
        let mut records = (0..output_limit)
            .map(|_| GuestOutputRecord {
                stream: GuestOutputStream::Stderr,
                data_base64: BASE64.encode([0_u8]),
                end_of_stream: false,
            })
            .collect::<Vec<_>>();
        records.extend([
            GuestOutputRecord {
                stream: GuestOutputStream::Stdout,
                data_base64: String::new(),
                end_of_stream: true,
            },
            GuestOutputRecord {
                stream: GuestOutputStream::Stderr,
                data_base64: String::new(),
                end_of_stream: true,
            },
        ]);
        let response = GuestResponse::Exec {
            protocol: GUEST_PROTOCOL_VERSION,
            termination: GuestTermination::Exited(i32::MIN),
            records,
            truncated: false,
        };
        assert!(encode_frame(&response).expect("exec frame").len() <= exec_reservation);

        let read = GuestRequest::ReadOptionalFile {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: OPERATION_ONE.into(),
            path: "/tmp/read".into(),
            byte_limit: output_limit,
        };
        let read_reservation = replay_reservation_bytes(&read);
        let response = GuestResponse::ReadOptionalFile {
            protocol: GUEST_PROTOCOL_VERSION,
            file: GuestOptionalFile::Present {
                content_base64: BASE64.encode(vec![0_u8; output_limit]),
            },
        };
        assert!(encode_frame(&response).expect("read frame").len() <= read_reservation);
        assert_eq!(MAX_REPLAY_BYTES, 64 * 1024 * 1024);
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
            false,
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
            false,
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
