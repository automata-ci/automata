use std::{
    fmt,
    net::Ipv6Addr,
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
            || !valid_registry_qualified_repository(repository)
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

fn valid_registry_qualified_repository(repository: &str) -> bool {
    let mut components = repository.split('/');
    let Some(registry) = components.next() else {
        return false;
    };
    let Some(first_repository) = components.next() else {
        return false;
    };
    valid_registry(registry)
        && valid_repository_component(first_repository)
        && components.all(valid_repository_component)
}

fn valid_registry(value: &str) -> bool {
    if let Some(rest) = value.strip_prefix('[') {
        let Some((address, port)) = rest.split_once(']') else {
            return false;
        };
        return Ipv6Addr::from_str(address).is_ok()
            && (port.is_empty() || port.strip_prefix(':').is_some_and(valid_canonical_port));
    }

    let (host, port) = match value.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (value, None),
    };
    if host.is_empty()
        || host.len() > 253
        || !host.is_ascii()
        || host.bytes().any(|byte| byte.is_ascii_uppercase())
        || port.is_some_and(|port| !valid_canonical_port(port))
    {
        return false;
    }
    let explicitly_registry_qualified = host == "localhost" || host.contains('.') || port.is_some();
    explicitly_registry_qualified
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn valid_canonical_port(value: &str) -> bool {
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .is_some_and(|port| port.to_string() == value)
}

fn valid_repository_component(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let bytes = value.as_bytes();
    let mut offset = 0;
    while offset < bytes.len() {
        let run_start = offset;
        while offset < bytes.len()
            && (bytes[offset].is_ascii_lowercase() || bytes[offset].is_ascii_digit())
        {
            offset += 1;
        }
        if offset == run_start {
            return false;
        }
        if offset == bytes.len() {
            return true;
        }
        match bytes[offset] {
            b'.' => offset += 1,
            b'_' => {
                offset += 1;
                if bytes.get(offset) == Some(&b'_') {
                    offset += 1;
                }
            }
            b'-' => {
                while bytes.get(offset) == Some(&b'-') {
                    offset += 1;
                }
            }
            _ => return false,
        }
    }
    false
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

/// Normalized absolute path in a provider's target filesystem namespace.
///
/// Container and virtual-machine providers normally resolve this inside an
/// isolated guest filesystem. A trusted native provider serving a
/// [`RootFilesystemPolicy::Host`] profile may intentionally use the same
/// absolute syntax as the host, but every operation must still enforce its
/// accepted path boundary—for example, copy operations are limited to the
/// sandbox-owned workspace and scratch roots, while executable paths come from
/// the admitted toolchain.
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

    /// Returns the normalized absolute path in the provider target namespace.
    ///
    /// Native [`RootFilesystemPolicy::Host`] providers may map this directly
    /// to host syntax only after enforcing the path boundary for the requested
    /// operation.
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
    /// Permit a trusted workload to use the host network directly.
    ///
    /// This provides no network isolation and must be matched by an explicit
    /// [`crate::SandboxCapability::HostNetwork`] declaration.
    Host,
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
    /// Permit a trusted native workload to see the host filesystem.
    ///
    /// Providers still own the admitted workspace and scratch roots, but this
    /// policy does not claim a disposable or isolated root filesystem.
    Host,
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
    /// Inherit the provider process host identity and token unchanged.
    ///
    /// This is a trusted-native policy, not privilege isolation. Providers
    /// accepting it must explicitly advertise
    /// [`crate::SandboxCapability::HostIdentity`].
    Host,
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

/// Exact provider launch mechanism selected by an environment profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SandboxLaunch {
    /// Launch inside a digest-pinned container kept alive for the whole job.
    Container {
        /// Exact immutable image selected by the admitted profile.
        image: ImmutableImage,
        /// Literal command keeping the whole-job container alive.
        keepalive: ExecutionArgv,
    },
    /// Launch inside a Windows container whose runtime is required to enforce
    /// Hyper-V isolation without a process-isolation fallback.
    WindowsHyperVContainer {
        /// Exact immutable Windows container image selected by the profile.
        image: ImmutableImage,
        /// Literal Windows command keeping the whole-job container alive.
        keepalive: ExecutionArgv,
    },
    /// Boot a disposable virtual machine from one immutable template.
    VirtualMachine {
        /// SHA-256 of the exact template manifest admitted for this profile.
        template_manifest: Sha256Digest,
    },
}

/// Provider launch material bound to the exact scheduler-selected environment
/// attestation. It contains no hosted-runner label interpretation or
/// credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxEnvironment {
    attestation: EnvironmentProfile,
    launch: SandboxLaunch,
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
            launch: SandboxLaunch::Container { image, keepalive },
            workspace,
            default_environment,
        })
    }

    /// Binds a Hyper-V-isolated Windows container launch to an exact profile.
    ///
    /// # Errors
    ///
    /// Rejects a keepalive program or workspace that does not use normalized,
    /// drive-qualified Windows syntax.
    pub fn windows_hyperv_container(
        attestation: EnvironmentProfile,
        image: ImmutableImage,
        keepalive: ExecutionArgv,
        workspace: TargetPath,
        default_environment: ExecutionEnvironment,
    ) -> Result<Self, ValueError> {
        if keepalive.program().platform() != TargetPlatform::Windows
            || workspace.platform() != TargetPlatform::Windows
        {
            return Err(ValueError::InvalidTargetPath);
        }
        Ok(Self {
            attestation,
            launch: SandboxLaunch::WindowsHyperVContainer { image, keepalive },
            workspace,
            default_environment,
        })
    }

    /// Binds a disposable virtual-machine launch to an exact scheduler-selected profile.
    ///
    /// # Errors
    ///
    /// Rejects a workspace that does not use normalized absolute POSIX syntax.
    pub fn virtual_machine(
        attestation: EnvironmentProfile,
        template_manifest: Sha256Digest,
        workspace: TargetPath,
        default_environment: ExecutionEnvironment,
    ) -> Result<Self, ValueError> {
        if workspace.platform() != TargetPlatform::Posix {
            return Err(ValueError::InvalidTargetPath);
        }
        Ok(Self {
            attestation,
            launch: SandboxLaunch::VirtualMachine { template_manifest },
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

    /// Returns the exact launch mechanism selected by the profile.
    #[must_use]
    pub const fn launch(&self) -> &SandboxLaunch {
        &self.launch
    }

    /// Returns the exact digest-pinned image for a container launch.
    #[must_use]
    pub const fn image(&self) -> Option<&ImmutableImage> {
        match &self.launch {
            SandboxLaunch::Container { image, .. }
            | SandboxLaunch::WindowsHyperVContainer { image, .. } => Some(image),
            SandboxLaunch::VirtualMachine { .. } => None,
        }
    }

    /// Returns the literal keepalive command for a container launch.
    ///
    /// Arguments are potentially sensitive and redacted by `Debug`.
    #[must_use]
    pub const fn keepalive(&self) -> Option<&ExecutionArgv> {
        match &self.launch {
            SandboxLaunch::Container { keepalive, .. }
            | SandboxLaunch::WindowsHyperVContainer { keepalive, .. } => Some(keepalive),
            SandboxLaunch::VirtualMachine { .. } => None,
        }
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
