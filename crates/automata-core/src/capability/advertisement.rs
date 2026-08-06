//! Versioned runner capability advertisements.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    ContainerCapabilities, ResourceCapacity, RunnerFeature, RunnerGroup, RunnerLabel,
    RunnerPlatform, SandboxCapabilities,
};
use crate::{CORE_SCHEMA_VERSION, RunnerId};

/// Versioned capabilities advertised by a runner.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunnerCapabilities {
    schema_version: u16,
    runner_id: RunnerId,
    platform: RunnerPlatform,
    labels: BTreeSet<RunnerLabel>,
    groups: BTreeSet<RunnerGroup>,
    max_parallel_jobs: u16,
    resources_per_job: ResourceCapacity,
    sandbox: SandboxCapabilities,
    containers: ContainerCapabilities,
    features: BTreeSet<RunnerFeature>,
}

impl RunnerCapabilities {
    /// Builds a minimal, valid advertisement with the current schema version.
    #[must_use]
    pub fn new(runner_id: RunnerId, platform: RunnerPlatform) -> Self {
        Self {
            schema_version: CORE_SCHEMA_VERSION,
            runner_id,
            platform,
            labels: BTreeSet::new(),
            groups: BTreeSet::new(),
            max_parallel_jobs: 1,
            resources_per_job: ResourceCapacity::default(),
            sandbox: SandboxCapabilities::default(),
            containers: ContainerCapabilities::default(),
            features: BTreeSet::new(),
        }
    }

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub const fn runner_id(&self) -> RunnerId {
        self.runner_id
    }

    #[must_use]
    pub const fn platform(&self) -> &RunnerPlatform {
        &self.platform
    }

    #[must_use]
    pub const fn labels(&self) -> &BTreeSet<RunnerLabel> {
        &self.labels
    }

    #[must_use]
    pub const fn groups(&self) -> &BTreeSet<RunnerGroup> {
        &self.groups
    }

    #[must_use]
    pub const fn max_parallel_jobs(&self) -> u16 {
        self.max_parallel_jobs
    }

    #[must_use]
    pub const fn resources_per_job(&self) -> ResourceCapacity {
        self.resources_per_job
    }

    #[must_use]
    pub const fn sandbox(&self) -> &SandboxCapabilities {
        &self.sandbox
    }

    #[must_use]
    pub const fn containers(&self) -> &ContainerCapabilities {
        &self.containers
    }

    #[must_use]
    pub const fn features(&self) -> &BTreeSet<RunnerFeature> {
        &self.features
    }

    /// Replaces the runner labels, canonicalized by [`RunnerLabel`].
    #[must_use]
    pub fn with_labels(mut self, labels: impl IntoIterator<Item = RunnerLabel>) -> Self {
        self.labels = labels.into_iter().collect();
        self
    }

    /// Replaces the administrative groups eligible to receive work.
    #[must_use]
    pub fn with_groups(mut self, groups: impl IntoIterator<Item = RunnerGroup>) -> Self {
        self.groups = groups.into_iter().collect();
        self
    }

    /// Sets the maximum concurrent jobs while preserving a valid advertisement.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityValidationError::NoJobSlots`] when `slots` is zero.
    pub fn with_max_parallel_jobs(mut self, slots: u16) -> Result<Self, CapabilityValidationError> {
        if slots == 0 {
            return Err(CapabilityValidationError::NoJobSlots);
        }
        self.max_parallel_jobs = slots;
        Ok(self)
    }

    #[must_use]
    pub const fn with_resources_per_job(mut self, resources: ResourceCapacity) -> Self {
        self.resources_per_job = resources;
        self
    }

    #[must_use]
    pub fn with_sandbox(mut self, sandbox: SandboxCapabilities) -> Self {
        self.sandbox = sandbox;
        self
    }

    #[must_use]
    pub fn with_containers(mut self, containers: ContainerCapabilities) -> Self {
        self.containers = containers;
        self
    }

    #[must_use]
    pub fn with_features(mut self, features: impl IntoIterator<Item = RunnerFeature>) -> Self {
        self.features = features.into_iter().collect();
        self
    }

    /// Checks invariants after reading an advertisement from a wire boundary.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityValidationError`] for an unsupported schema or an
    /// advertisement that cannot accept work.
    pub const fn validate(&self) -> Result<(), CapabilityValidationError> {
        if self.schema_version != CORE_SCHEMA_VERSION {
            Err(CapabilityValidationError::UnsupportedSchema {
                supported: CORE_SCHEMA_VERSION,
                received: self.schema_version,
            })
        } else if self.max_parallel_jobs == 0 {
            Err(CapabilityValidationError::NoJobSlots)
        } else {
            Ok(())
        }
    }
}

/// Validation failures for a runner advertisement.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CapabilityValidationError {
    #[error("unsupported capability schema {received}; this build supports {supported}")]
    UnsupportedSchema { supported: u16, received: u16 },
    #[error("runner must advertise at least one job slot")]
    NoJobSlots,
}
