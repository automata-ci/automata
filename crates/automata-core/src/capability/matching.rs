//! Deterministic matching between requirements and advertisements.

use std::{collections::BTreeSet, error::Error, fmt, slice};

use serde::{Deserialize, Serialize};

use super::{
    Architecture, ContainerFeature, IsolationLevel, OperatingSystem, RunnerCapabilities,
    RunnerFeature, RunnerGroup, RunnerLabel, RunnerRequirements, SandboxFeature,
};
use crate::CORE_SCHEMA_VERSION;

impl RunnerCapabilities {
    /// Tests the GitHub-compatible all-of label rule in isolation.
    #[must_use]
    pub fn has_all_labels(&self, required: &BTreeSet<RunnerLabel>) -> bool {
        required.is_subset(self.labels())
    }

    /// Evaluates all typed requirements and returns every mismatch.
    ///
    /// # Errors
    ///
    /// Returns [`RequirementMismatches`] containing every unsatisfied typed
    /// requirement; ordering is deterministic.
    pub fn satisfies(
        &self,
        requirements: &RunnerRequirements,
    ) -> Result<(), RequirementMismatches> {
        let mut mismatches = Vec::new();

        if self.schema_version() != CORE_SCHEMA_VERSION {
            mismatches.push(RequirementMismatch::CapabilitiesSchemaVersion {
                supported: CORE_SCHEMA_VERSION,
                received: self.schema_version(),
            });
        }
        if requirements.schema_version() != CORE_SCHEMA_VERSION {
            mismatches.push(RequirementMismatch::RequirementsSchemaVersion {
                supported: CORE_SCHEMA_VERSION,
                received: requirements.schema_version(),
            });
        }

        for label in requirements.labels().difference(self.labels()) {
            mismatches.push(RequirementMismatch::MissingLabel(label.clone()));
        }

        if !requirements.eligible_groups().is_empty()
            && requirements.eligible_groups().is_disjoint(self.groups())
        {
            mismatches.push(RequirementMismatch::NoEligibleGroup {
                eligible: requirements.eligible_groups().clone(),
            });
        }

        if let Some(required) = requirements.operating_system()
            && required != self.platform().operating_system()
        {
            mismatches.push(RequirementMismatch::OperatingSystem {
                required: required.clone(),
                available: self.platform().operating_system().clone(),
            });
        }
        if let Some(required) = requirements.architecture()
            && required != self.platform().architecture()
        {
            mismatches.push(RequirementMismatch::Architecture {
                required: required.clone(),
                available: self.platform().architecture().clone(),
            });
        }
        if self.max_parallel_jobs() == 0 {
            mismatches.push(RequirementMismatch::NoJobSlots);
        }

        compare_resource(
            ResourceKind::CpuMillis,
            u64::from(requirements.minimum_resources().cpu_millis()),
            u64::from(self.resources_per_job().cpu_millis()),
            &mut mismatches,
        );
        compare_resource(
            ResourceKind::MemoryBytes,
            requirements.minimum_resources().memory_bytes(),
            self.resources_per_job().memory_bytes(),
            &mut mismatches,
        );
        compare_resource(
            ResourceKind::EphemeralDiskBytes,
            requirements.minimum_resources().ephemeral_disk_bytes(),
            self.resources_per_job().ephemeral_disk_bytes(),
            &mut mismatches,
        );
        compare_resource(
            ResourceKind::GpuCount,
            u64::from(requirements.minimum_resources().gpu_count()),
            u64::from(self.resources_per_job().gpu_count()),
            &mut mismatches,
        );

        if self.sandbox().maximum_isolation() < requirements.minimum_isolation() {
            mismatches.push(RequirementMismatch::Isolation {
                required: requirements.minimum_isolation(),
                available: self.sandbox().maximum_isolation(),
            });
        }
        for feature in requirements
            .sandbox_features()
            .difference(self.sandbox().features())
        {
            mismatches.push(RequirementMismatch::MissingSandboxFeature(feature.clone()));
        }
        for feature in requirements
            .container_features()
            .difference(self.containers().features())
        {
            mismatches.push(RequirementMismatch::MissingContainerFeature(
                feature.clone(),
            ));
        }
        for feature in requirements.features().difference(self.features()) {
            mismatches.push(RequirementMismatch::MissingRunnerFeature(feature.clone()));
        }

        if mismatches.is_empty() {
            Ok(())
        } else {
            Err(RequirementMismatches::new(mismatches))
        }
    }
}

fn compare_resource(
    resource: ResourceKind,
    required: u64,
    available: u64,
    mismatches: &mut Vec<RequirementMismatch>,
) {
    if available < required {
        mismatches.push(RequirementMismatch::InsufficientResource {
            resource,
            required,
            available,
        });
    }
}

/// One reason a runner cannot satisfy a job.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "details", rename_all = "snake_case")]
pub enum RequirementMismatch {
    CapabilitiesSchemaVersion {
        supported: u16,
        received: u16,
    },
    RequirementsSchemaVersion {
        supported: u16,
        received: u16,
    },
    MissingLabel(RunnerLabel),
    NoEligibleGroup {
        eligible: BTreeSet<RunnerGroup>,
    },
    OperatingSystem {
        required: OperatingSystem,
        available: OperatingSystem,
    },
    Architecture {
        required: Architecture,
        available: Architecture,
    },
    NoJobSlots,
    InsufficientResource {
        resource: ResourceKind,
        required: u64,
        available: u64,
    },
    Isolation {
        required: IsolationLevel,
        available: IsolationLevel,
    },
    MissingSandboxFeature(SandboxFeature),
    MissingContainerFeature(ContainerFeature),
    MissingRunnerFeature(RunnerFeature),
}

/// Quantitative resource names used in mismatch reporting.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    CpuMillis,
    MemoryBytes,
    EphemeralDiskBytes,
    GpuCount,
}

/// Complete, deterministic set of scheduling mismatches.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequirementMismatches(Vec<RequirementMismatch>);

impl RequirementMismatches {
    pub(super) const fn new(mismatches: Vec<RequirementMismatch>) -> Self {
        Self(mismatches)
    }

    #[must_use]
    pub fn as_slice(&self) -> &[RequirementMismatch] {
        &self.0
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> slice::Iter<'_, RequirementMismatch> {
        self.0.iter()
    }

    #[must_use]
    pub fn into_vec(self) -> Vec<RequirementMismatch> {
        self.0
    }
}

impl<'a> IntoIterator for &'a RequirementMismatches {
    type Item = &'a RequirementMismatch;
    type IntoIter = slice::Iter<'a, RequirementMismatch>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl IntoIterator for RequirementMismatches {
    type Item = RequirementMismatch;
    type IntoIter = std::vec::IntoIter<RequirementMismatch>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl fmt::Display for RequirementMismatches {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "runner failed {} requirement(s)", self.len())
    }
}

impl Error for RequirementMismatches {}
