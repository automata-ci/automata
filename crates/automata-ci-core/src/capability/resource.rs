//! Quantitative resources and provider capability sets.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{ContainerFeature, IsolationLevel, SandboxFeature};

/// Quantitative capacity available for one matched job.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceCapacity {
    cpu_millis: u32,
    memory_bytes: u64,
    ephemeral_disk_bytes: u64,
    gpu_count: u16,
}

impl ResourceCapacity {
    /// Creates a provider-neutral resource description.
    #[must_use]
    pub const fn new(
        cpu_millis: u32,
        memory_bytes: u64,
        ephemeral_disk_bytes: u64,
        gpu_count: u16,
    ) -> Self {
        Self {
            cpu_millis,
            memory_bytes,
            ephemeral_disk_bytes,
            gpu_count,
        }
    }

    /// Returns CPU capacity in thousandths of one logical CPU.
    #[must_use]
    pub const fn cpu_millis(self) -> u32 {
        self.cpu_millis
    }

    /// Returns enforceable memory capacity in bytes.
    #[must_use]
    pub const fn memory_bytes(self) -> u64 {
        self.memory_bytes
    }

    /// Returns enforceable ephemeral-storage capacity in bytes.
    ///
    /// Zero means no positive disk capacity is advertised; it does not mean
    /// unlimited storage.
    #[must_use]
    pub const fn ephemeral_disk_bytes(self) -> u64 {
        self.ephemeral_disk_bytes
    }

    /// Returns the number of GPU devices available to one job.
    #[must_use]
    pub const fn gpu_count(self) -> u16 {
        self.gpu_count
    }
}

/// Minimum quantitative resources requested by a job.
pub type ResourceRequirements = ResourceCapacity;

/// Sandbox abilities advertised by a runner.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxCapabilities {
    maximum_isolation: IsolationLevel,
    features: BTreeSet<SandboxFeature>,
}

impl SandboxCapabilities {
    /// Creates a sandbox advertisement from its maximum isolation and features.
    #[must_use]
    pub fn new(
        maximum_isolation: IsolationLevel,
        features: impl IntoIterator<Item = SandboxFeature>,
    ) -> Self {
        Self {
            maximum_isolation,
            features: features.into_iter().collect(),
        }
    }

    /// Returns the strongest isolation boundary this provider can enforce.
    #[must_use]
    pub const fn maximum_isolation(&self) -> IsolationLevel {
        self.maximum_isolation
    }

    /// Returns provider-neutral sandbox features available to a job.
    #[must_use]
    pub const fn features(&self) -> &BTreeSet<SandboxFeature> {
        &self.features
    }
}

/// Container abilities advertised by a runner.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerCapabilities {
    features: BTreeSet<ContainerFeature>,
}

impl ContainerCapabilities {
    /// Creates a container-runtime advertisement.
    #[must_use]
    pub fn new(features: impl IntoIterator<Item = ContainerFeature>) -> Self {
        Self {
            features: features.into_iter().collect(),
        }
    }

    /// Returns provider-neutral container features available to a job.
    #[must_use]
    pub const fn features(&self) -> &BTreeSet<ContainerFeature> {
        &self.features
    }
}
