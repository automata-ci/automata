//! Typed scheduling requirements assembled by a workflow planner.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{
    Architecture, ContainerFeature, IsolationLevel, OperatingSystem, ResourceRequirements,
    RunnerFeature, RunnerGroup, RunnerLabel, SandboxFeature,
};
use crate::CORE_SCHEMA_VERSION;

/// Versioned job requirements used by scheduler policies.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunnerRequirements {
    schema_version: u16,
    labels: BTreeSet<RunnerLabel>,
    eligible_groups: BTreeSet<RunnerGroup>,
    operating_system: Option<OperatingSystem>,
    architecture: Option<Architecture>,
    minimum_resources: ResourceRequirements,
    minimum_isolation: IsolationLevel,
    sandbox_features: BTreeSet<SandboxFeature>,
    container_features: BTreeSet<ContainerFeature>,
    features: BTreeSet<RunnerFeature>,
}

impl RunnerRequirements {
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub const fn labels(&self) -> &BTreeSet<RunnerLabel> {
        &self.labels
    }

    #[must_use]
    pub const fn eligible_groups(&self) -> &BTreeSet<RunnerGroup> {
        &self.eligible_groups
    }

    #[must_use]
    pub const fn operating_system(&self) -> Option<&OperatingSystem> {
        self.operating_system.as_ref()
    }

    #[must_use]
    pub const fn architecture(&self) -> Option<&Architecture> {
        self.architecture.as_ref()
    }

    #[must_use]
    pub const fn minimum_resources(&self) -> ResourceRequirements {
        self.minimum_resources
    }

    #[must_use]
    pub const fn minimum_isolation(&self) -> IsolationLevel {
        self.minimum_isolation
    }

    #[must_use]
    pub const fn sandbox_features(&self) -> &BTreeSet<SandboxFeature> {
        &self.sandbox_features
    }

    #[must_use]
    pub const fn container_features(&self) -> &BTreeSet<ContainerFeature> {
        &self.container_features
    }

    #[must_use]
    pub const fn features(&self) -> &BTreeSet<RunnerFeature> {
        &self.features
    }

    #[must_use]
    pub fn with_labels(mut self, labels: impl IntoIterator<Item = RunnerLabel>) -> Self {
        self.labels = labels.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_eligible_groups(mut self, groups: impl IntoIterator<Item = RunnerGroup>) -> Self {
        self.eligible_groups = groups.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_operating_system(mut self, operating_system: OperatingSystem) -> Self {
        self.operating_system = Some(operating_system);
        self
    }

    #[must_use]
    pub fn with_architecture(mut self, architecture: Architecture) -> Self {
        self.architecture = Some(architecture);
        self
    }

    #[must_use]
    pub const fn with_minimum_resources(mut self, resources: ResourceRequirements) -> Self {
        self.minimum_resources = resources;
        self
    }

    #[must_use]
    pub const fn with_minimum_isolation(mut self, isolation: IsolationLevel) -> Self {
        self.minimum_isolation = isolation;
        self
    }

    #[must_use]
    pub fn with_sandbox_features(
        mut self,
        features: impl IntoIterator<Item = SandboxFeature>,
    ) -> Self {
        self.sandbox_features = features.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_container_features(
        mut self,
        features: impl IntoIterator<Item = ContainerFeature>,
    ) -> Self {
        self.container_features = features.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_features(mut self, features: impl IntoIterator<Item = RunnerFeature>) -> Self {
        self.features = features.into_iter().collect();
        self
    }
}

impl Default for RunnerRequirements {
    fn default() -> Self {
        Self {
            schema_version: CORE_SCHEMA_VERSION,
            labels: BTreeSet::new(),
            eligible_groups: BTreeSet::new(),
            operating_system: None,
            architecture: None,
            minimum_resources: ResourceRequirements::default(),
            minimum_isolation: IsolationLevel::Process,
            sandbox_features: BTreeSet::new(),
            container_features: BTreeSet::new(),
            features: BTreeSet::new(),
        }
    }
}
