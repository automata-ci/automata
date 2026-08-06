//! Provider-neutral runner platform identity and isolation strength.

use serde::{Deserialize, Serialize};

/// Operating-system family relevant to workflow selection.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", content = "name", rename_all = "snake_case")]
pub enum OperatingSystem {
    Linux,
    Windows,
    Macos,
    Other(String),
}

/// CPU architecture relevant to workflow selection.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", content = "name", rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
    Aarch64,
    Other(String),
}

/// Target platform exposed to a job.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
    #[default]
    Process,
    SharedKernel,
    VirtualMachine,
}
