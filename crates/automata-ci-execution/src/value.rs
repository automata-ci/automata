use std::{
    fmt,
    num::{NonZeroU32, NonZeroU64},
    str::FromStr as _,
};

use automata_ci_core::{EnvironmentProfile, EnvironmentProfileId};

use crate::{
    MAX_IMAGE_REFERENCE_BYTES, MAX_SANDBOX_HANDLE_BYTES, Sha256Digest, ValueError,
    endpoint::{ExecutionArgv, ExecutionEnvironment},
};

const MAX_IDENTIFIER_BYTES: usize = 64;
const MAX_TARGET_PATH_BYTES: usize = 4_096;
const MAX_MEMORY_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const MIN_MEMORY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CPU_MILLIS: u32 = 1_000_000;
const MAX_PIDS: u32 = 1_000_000;

fn portable_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

/// Stable identifier of one sandbox-provider implementation.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderId(String);

impl ProviderId {
    /// Validates a portable provider identifier.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, path-like, or non-ASCII identifiers.
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();
        portable_identifier(&value)
            .then_some(Self(value))
            .ok_or(ValueError::InvalidProviderId)
    }

    /// Borrows the stable provider identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProviderId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ProviderId").field(&self.0).finish()
    }
}

/// Monotonic runner-side generation fencing reuse of an opaque handle.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SandboxGeneration(NonZeroU64);

impl SandboxGeneration {
    /// Creates a non-zero generation representable by common durable stores.
    ///
    /// # Errors
    ///
    /// Rejects zero and values larger than a signed 64-bit durable column.
    pub fn new(value: u64) -> Result<Self, ValueError> {
        if value > i64::MAX as u64 {
            return Err(ValueError::InvalidSandboxGeneration);
        }
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(ValueError::InvalidSandboxGeneration)
    }

    /// Returns the non-zero durable generation value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Provider-scoped opaque recovery handle. Backend object identifiers must not
/// appear in any other provider-neutral model.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SandboxHandle {
    provider: ProviderId,
    opaque: String,
}

impl SandboxHandle {
    /// Validates a provider-scoped opaque token.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, path-like, or non-portable tokens.
    pub fn new(provider: ProviderId, opaque: impl Into<String>) -> Result<Self, ValueError> {
        let opaque = opaque.into();
        let valid = !opaque.is_empty()
            && opaque.len() <= MAX_SANDBOX_HANDLE_BYTES
            && opaque
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte));
        valid
            .then_some(Self { provider, opaque })
            .ok_or(ValueError::InvalidSandboxHandle)
    }

    /// Returns the provider namespace that owns this handle.
    #[must_use]
    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// Borrows the provider-owned token. Callers must treat it as opaque.
    #[must_use]
    pub fn opaque(&self) -> &str {
        &self.opaque
    }
}

impl fmt::Debug for SandboxHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SandboxHandle")
            .field("provider", &self.provider)
            .field("opaque", &"[OPAQUE]")
            .finish()
    }
}

/// Immutable, registry-qualified image reference pinned to one SHA-256 digest.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ImmutableImage {
    reference: String,
    digest: Sha256Digest,
}

impl ImmutableImage {
    /// Parses `registry/repository@sha256:<64 lowercase hex>`.
    ///
    /// # Errors
    ///
    /// Rejects mutable tags, uppercase/non-hex digests, whitespace, and
    /// oversized or ambiguous references.
    pub fn new(reference: impl Into<String>) -> Result<Self, ValueError> {
        let reference = reference.into();
        if reference.is_empty()
            || reference.len() > MAX_IMAGE_REFERENCE_BYTES
            || !reference.is_ascii()
            || reference.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(ValueError::InvalidImmutableImage);
        }
        let (repository, digest) = reference
            .rsplit_once("@sha256:")
            .ok_or(ValueError::InvalidImmutableImage)?;
        if repository.is_empty()
            || repository.contains('@')
            || !repository.contains('/')
            || repository
                .split('/')
                .any(|component| component.is_empty() || matches!(component, "." | ".."))
            || !repository
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"./:_-".contains(&byte))
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(ValueError::InvalidImmutableImage);
        }
        let digest =
            Sha256Digest::from_str(digest).map_err(|_| ValueError::InvalidImmutableImage)?;
        Ok(Self { reference, digest })
    }

    /// Returns the complete registry-qualified, digest-pinned reference.
    #[must_use]
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// Returns the parsed SHA-256 content digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

impl fmt::Debug for ImmutableImage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImmutableImage")
            .field("reference", &self.reference)
            .field("digest", &self.digest)
            .finish()
    }
}

/// Filesystem syntax used by a sandbox target path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TargetPlatform {
    /// POSIX path syntax using `/` separators and one leading root slash.
    Posix,
    /// Drive-qualified Windows path syntax using `\` separators.
    Windows,
}

/// Normalized absolute path inside a sandbox, independent of host paths.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct TargetPath {
    platform: TargetPlatform,
    value: String,
}

impl TargetPath {
    /// Creates a normalized absolute POSIX target path.
    ///
    /// # Errors
    ///
    /// Rejects relative paths, traversal, duplicate separators, control bytes,
    /// and paths beyond the hard bound.
    pub fn posix(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();
        let valid = value.starts_with('/')
            && value.len() <= MAX_TARGET_PATH_BYTES
            && !value.contains("//")
            && (value == "/" || !value.ends_with('/'))
            && !value.bytes().any(|byte| byte.is_ascii_control())
            && value
                .split('/')
                .skip(1)
                .all(|component| !matches!(component, "." | ".."));
        valid
            .then_some(Self {
                platform: TargetPlatform::Posix,
                value,
            })
            .ok_or(ValueError::InvalidTargetPath)
    }

    /// Creates a normalized absolute drive-qualified Windows target path.
    ///
    /// # Errors
    ///
    /// Rejects device/UNC paths, traversal, forward slashes, controls, and
    /// paths beyond the hard bound.
    pub fn windows(value: impl Into<String>) -> Result<Self, ValueError> {
        let mut value = value.into();
        let bytes = value.as_bytes();
        let drive_letter = bytes.first().copied();
        let drive_qualified = bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && bytes[2] == b'\\';
        let valid = drive_qualified
            && value.len() <= MAX_TARGET_PATH_BYTES
            && !value.contains('/')
            && !value.contains("\\\\")
            && (value.len() == 3 || !value.ends_with('\\'))
            && !value.bytes().any(|byte| byte.is_ascii_control())
            && value.split('\\').skip(1).all(|component| {
                !matches!(component, "." | "..")
                    && !component.ends_with([' ', '.'])
                    && !component
                        .bytes()
                        .any(|byte| matches!(byte, b':' | b'*' | b'?' | b'"' | b'<' | b'>' | b'|'))
            });
        if !valid {
            return Err(ValueError::InvalidTargetPath);
        }
        if drive_letter.is_some_and(|letter| letter.is_ascii_lowercase()) {
            let uppercase = char::from(drive_letter.unwrap_or_default().to_ascii_uppercase());
            value.replace_range(..1, &uppercase.to_string());
        }
        Ok(Self {
            platform: TargetPlatform::Windows,
            value,
        })
    }

    /// Returns the filesystem syntax used by this target path.
    #[must_use]
    pub const fn platform(&self) -> TargetPlatform {
        self.platform
    }

    /// Returns the normalized absolute path inside the sandbox.
    ///
    /// This is never a host path. Providers must resolve it only within the
    /// sandbox's filesystem boundary.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for TargetPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TargetPath")
            .field("platform", &self.platform)
            .field("value", &self.value)
            .finish()
    }
}

/// Explicit network isolation requested for one sandbox.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum NetworkPolicy {
    /// Authorize no network connectivity for sandbox processes.
    Disabled,
    /// Use a sandbox-private network with provider-controlled outbound access.
    ///
    /// This policy does not authorize mounting host control sockets or joining
    /// an unrelated host network namespace.
    PrivateEgress,
}

/// Root-filesystem mutability requested by the selected profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RootFilesystemPolicy {
    /// Prevent writes to the profile's root filesystem outside explicit mounts.
    ReadOnly,
    /// Permit writes inside the sandbox's disposable root filesystem.
    ///
    /// This never permits writes to host paths outside explicit sandbox-owned
    /// mounts.
    Writable,
}

/// Privilege visible to processes inside the sandbox's isolation boundary.
///
/// `Administrator` never authorizes host privilege. A provider may advertise
/// it only when the administrative identity is confined by its sandbox (for
/// example UID 0 inside a rootless user namespace or an ephemeral VM guest).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum SandboxPrivilegePolicy {
    /// Run without an administrative identity or ambient capabilities.
    #[default]
    Unprivileged,
    /// Provide an administrative identity confined to the sandbox boundary.
    Administrator,
}

/// Required hard resource limits for a whole-job sandbox.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceLimits {
    memory_bytes: NonZeroU64,
    cpu_millis: NonZeroU32,
    pids: NonZeroU32,
}

impl ResourceLimits {
    /// Creates bounded, non-zero memory, CPU, and PID limits.
    ///
    /// # Errors
    ///
    /// Rejects memory outside 16 MiB..=1 TiB, more than 1000 CPUs, and more
    /// than one million processes.
    pub fn new(memory_bytes: u64, cpu_millis: u32, pids: u32) -> Result<Self, ValueError> {
        let memory_bytes = NonZeroU64::new(memory_bytes)
            .filter(|value| (MIN_MEMORY_BYTES..=MAX_MEMORY_BYTES).contains(&value.get()));
        let cpu_millis = NonZeroU32::new(cpu_millis).filter(|value| value.get() <= MAX_CPU_MILLIS);
        let pids = NonZeroU32::new(pids).filter(|value| value.get() <= MAX_PIDS);
        match (memory_bytes, cpu_millis, pids) {
            (Some(memory_bytes), Some(cpu_millis), Some(pids)) => Ok(Self {
                memory_bytes,
                cpu_millis,
                pids,
            }),
            _ => Err(ValueError::InvalidResourceLimits),
        }
    }

    /// Returns the hard memory limit in bytes.
    #[must_use]
    pub const fn memory_bytes(self) -> u64 {
        self.memory_bytes.get()
    }

    /// Returns the CPU quota in thousandths of one CPU.
    ///
    /// A value of `1_000` represents one CPU's worth of quota.
    #[must_use]
    pub const fn cpu_millis(self) -> u32 {
        self.cpu_millis.get()
    }

    /// Returns the hard maximum number of processes visible to the sandbox.
    #[must_use]
    pub const fn pids(self) -> u32 {
        self.pids.get()
    }
}

/// Provider launch material bound to the exact scheduler-selected environment
/// attestation. It contains no hosted-runner label interpretation or
/// credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxEnvironment {
    attestation: EnvironmentProfile,
    image: ImmutableImage,
    keepalive: ExecutionArgv,
    workspace: TargetPath,
    default_environment: ExecutionEnvironment,
}

impl SandboxEnvironment {
    /// Binds exact launch material to a content-attested environment profile.
    ///
    /// # Errors
    ///
    /// Rejects a non-POSIX absolute keepalive program or workspace path.
    pub fn new(
        attestation: EnvironmentProfile,
        image: ImmutableImage,
        keepalive: ExecutionArgv,
        workspace: TargetPath,
        default_environment: ExecutionEnvironment,
    ) -> Result<Self, ValueError> {
        if keepalive.program().platform() != TargetPlatform::Posix
            || workspace.platform() != TargetPlatform::Posix
        {
            return Err(ValueError::InvalidTargetPath);
        }
        Ok(Self {
            attestation,
            image,
            keepalive,
            workspace,
            default_environment,
        })
    }

    /// Returns the exact profile identity and manifest digest admitted by the
    /// scheduler.
    #[must_use]
    pub const fn attestation(&self) -> &EnvironmentProfile {
        &self.attestation
    }

    /// Returns the stable environment-profile identifier.
    #[must_use]
    pub const fn id(&self) -> &EnvironmentProfileId {
        self.attestation.id()
    }

    /// Returns the admitted profile manifest's content digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.attestation.digest()
    }

    /// Returns the exact digest-pinned image selected by the profile.
    #[must_use]
    pub const fn image(&self) -> &ImmutableImage {
        &self.image
    }

    /// Returns the literal command that keeps the whole-job sandbox alive.
    ///
    /// Arguments are potentially sensitive and redacted by `Debug`.
    #[must_use]
    pub const fn keepalive(&self) -> &ExecutionArgv {
        &self.keepalive
    }

    /// Returns the profile-defined absolute workspace target.
    #[must_use]
    pub const fn workspace(&self) -> &TargetPath {
        &self.workspace
    }

    /// Returns profile-bound process defaults for sandbox execution phases.
    /// Workflow and phase-specific environment layers may override these
    /// values.
    #[must_use]
    pub const fn default_environment(&self) -> &ExecutionEnvironment {
        &self.default_environment
    }
}
