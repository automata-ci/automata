//! Typed scheduling requirements assembled by a workflow planner.

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use super::{
    Architecture, ContainerFeature, EnvironmentProfile, IsolationLevel, OperatingSystem,
    ResourceRequirements, RunnerFeature, RunnerGroup, RunnerLabel, SandboxFeature,
};
/// Current schema of required runner constraints.
///
/// This version is independent from capability-advertisement schemas. Adding a
/// required constraint is not forward-compatible with a peer that would ignore
/// the field, so requirements advance separately from optional advertisements.
pub const RUNNER_REQUIREMENTS_SCHEMA_VERSION: u16 = 2;

/// Versioned job requirements used by scheduler policies.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    environment_profile: Option<EnvironmentProfile>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedRunnerRequirements {
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
    #[serde(default)]
    environment_profile: Option<EnvironmentProfile>,
}

impl<'de> Deserialize<'de> for RunnerRequirements {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = UncheckedRunnerRequirements::deserialize(deserializer)?;
        if value.schema_version != RUNNER_REQUIREMENTS_SCHEMA_VERSION {
            return Err(D::Error::custom(format_args!(
                "unsupported runner-requirements schema {}; this build supports {}",
                value.schema_version, RUNNER_REQUIREMENTS_SCHEMA_VERSION
            )));
        }
        Ok(Self {
            schema_version: value.schema_version,
            labels: value.labels,
            eligible_groups: value.eligible_groups,
            operating_system: value.operating_system,
            architecture: value.architecture,
            minimum_resources: value.minimum_resources,
            minimum_isolation: value.minimum_isolation,
            sandbox_features: value.sandbox_features,
            container_features: value.container_features,
            features: value.features,
            environment_profile: value.environment_profile,
        })
    }
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

    /// Returns the exact content-attested environment required by this job.
    #[must_use]
    pub const fn environment_profile(&self) -> Option<&EnvironmentProfile> {
        self.environment_profile.as_ref()
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

    /// Requires one exact content-attested execution environment.
    #[must_use]
    pub fn with_environment_profile(mut self, profile: EnvironmentProfile) -> Self {
        self.environment_profile = Some(profile);
        self
    }
}

impl Default for RunnerRequirements {
    fn default() -> Self {
        Self {
            schema_version: RUNNER_REQUIREMENTS_SCHEMA_VERSION,
            labels: BTreeSet::new(),
            eligible_groups: BTreeSet::new(),
            operating_system: None,
            architecture: None,
            minimum_resources: ResourceRequirements::default(),
            minimum_isolation: IsolationLevel::Process,
            sandbox_features: BTreeSet::new(),
            container_features: BTreeSet::new(),
            features: BTreeSet::new(),
            environment_profile: None,
        }
    }
}
