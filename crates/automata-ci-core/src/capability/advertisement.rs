//! Versioned runner capability advertisements.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    ContainerCapabilities, EnvironmentProfile, ResourceCapacity, RunnerFeature, RunnerGroup,
    RunnerLabel, RunnerPlatform, SandboxCapabilities,
};
use crate::{CORE_SCHEMA_VERSION, RunnerId};

/// Versioned capabilities advertised by a runner.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
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
    environment_profiles: BTreeSet<EnvironmentProfile>,
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
            environment_profiles: BTreeSet::new(),
        }
    }

    /// Returns the capability-advertisement schema encoded by this value.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the durable identity of the advertising runner.
    #[must_use]
    pub const fn runner_id(&self) -> RunnerId {
        self.runner_id
    }

    /// Returns the operating-system and architecture exposed to jobs.
    #[must_use]
    pub const fn platform(&self) -> &RunnerPlatform {
        &self.platform
    }

    /// Returns the canonical labels available for all-of matching.
    #[must_use]
    pub const fn labels(&self) -> &BTreeSet<RunnerLabel> {
        &self.labels
    }

    /// Returns the administrative groups allowed to route work here.
    #[must_use]
    pub const fn groups(&self) -> &BTreeSet<RunnerGroup> {
        &self.groups
    }

    /// Returns the maximum number of jobs this runner may execute concurrently.
    #[must_use]
    pub const fn max_parallel_jobs(&self) -> u16 {
        self.max_parallel_jobs
    }

    /// Returns the enforceable capacity available independently to each job.
    #[must_use]
    pub const fn resources_per_job(&self) -> ResourceCapacity {
        self.resources_per_job
    }

    /// Returns the advertised sandbox isolation and feature set.
    #[must_use]
    pub const fn sandbox(&self) -> &SandboxCapabilities {
        &self.sandbox
    }

    /// Returns the advertised container-runtime feature set.
    #[must_use]
    pub const fn containers(&self) -> &ContainerCapabilities {
        &self.containers
    }

    /// Returns workflow-runtime features implemented by this runner.
    #[must_use]
    pub const fn features(&self) -> &BTreeSet<RunnerFeature> {
        &self.features
    }

    /// Returns the exact content-attested environments this runner can supply.
    #[must_use]
    pub const fn environment_profiles(&self) -> &BTreeSet<EnvironmentProfile> {
        &self.environment_profiles
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

    /// Replaces the enforceable capacity available independently to each job.
    #[must_use]
    pub const fn with_resources_per_job(mut self, resources: ResourceCapacity) -> Self {
        self.resources_per_job = resources;
        self
    }

    /// Replaces the advertised sandbox isolation and feature set.
    #[must_use]
    pub fn with_sandbox(mut self, sandbox: SandboxCapabilities) -> Self {
        self.sandbox = sandbox;
        self
    }

    /// Replaces the advertised container-runtime feature set.
    #[must_use]
    pub fn with_containers(mut self, containers: ContainerCapabilities) -> Self {
        self.containers = containers;
        self
    }

    /// Replaces workflow-runtime features implemented by this runner.
    #[must_use]
    pub fn with_features(mut self, features: impl IntoIterator<Item = RunnerFeature>) -> Self {
        self.features = features.into_iter().collect();
        self
    }

    /// Replaces the exact content-attested environments this runner can supply.
    #[must_use]
    pub fn with_environment_profiles(
        mut self,
        profiles: impl IntoIterator<Item = EnvironmentProfile>,
    ) -> Self {
        self.environment_profiles = profiles.into_iter().collect();
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
    /// The advertisement uses a schema this build cannot interpret safely.
    #[error("unsupported capability schema {received}; this build supports {supported}")]
    UnsupportedSchema {
        /// Schema understood by this build.
        supported: u16,
        /// Schema carried by the advertisement.
        received: u16,
    },
    /// The advertisement cannot accept any concurrent job.
    #[error("runner must advertise at least one job slot")]
    NoJobSlots,
}
