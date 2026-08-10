//! Provider-neutral runner platform identity and isolation strength.

use serde::{Deserialize, Serialize};

/// Operating-system family relevant to workflow selection.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(
    deny_unknown_fields,
    tag = "kind",
    content = "name",
    rename_all = "snake_case"
)]
pub enum OperatingSystem {
    /// A Linux-compatible userspace and kernel interface.
    Linux,
    /// A Windows-compatible execution environment.
    Windows,
    /// A macOS-compatible execution environment.
    Macos,
    /// A canonical provider-specific operating-system family.
    Other(String),
}

/// CPU architecture relevant to workflow selection.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(
    deny_unknown_fields,
    tag = "kind",
    content = "name",
    rename_all = "snake_case"
)]
pub enum Architecture {
    /// The 64-bit x86 architecture.
    X86_64,
    /// The 64-bit Arm architecture.
    Aarch64,
    /// A canonical provider-specific CPU architecture.
    Other(String),
}

/// Target platform exposed to a job.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerPlatform {
    operating_system: OperatingSystem,
    architecture: Architecture,
}

impl RunnerPlatform {
    /// Creates a platform advertisement.
    #[must_use]
    pub const fn new(operating_system: OperatingSystem, architecture: Architecture) -> Self {
        Self {
            operating_system,
            architecture,
        }
    }

    /// Returns the advertised operating-system family.
    #[must_use]
    pub const fn operating_system(&self) -> &OperatingSystem {
        &self.operating_system
    }

    /// Returns the advertised CPU architecture.
    #[must_use]
    pub const fn architecture(&self) -> &Architecture {
        &self.architecture
    }
}

/// Increasing isolation strength, independent of any concrete provider.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationLevel {
    /// Work executes as an isolated host process without a kernel boundary.
    #[default]
    Process,
    /// Work is isolated from the host while sharing its kernel.
    SharedKernel,
    /// Work receives a dedicated guest-kernel boundary.
    VirtualMachine,
}
