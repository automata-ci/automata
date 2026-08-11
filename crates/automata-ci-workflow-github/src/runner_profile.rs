//! Server-attested runner profiles used when logical jobs become executable.

use std::collections::{BTreeMap, BTreeSet};

use automata_ci_core::{
    Architecture, ContainerFeature, EnvironmentProfile, OperatingSystem, RunnerLabel,
};
/// One server-owned mapping from a GitHub runner selector to an attested image profile.
///
/// Projection replaces only this selector with the exact profile requirement;
/// additional activated labels and the optional runner group remain routing
/// requirements.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubRunnerProfileMapping {
    selector: RunnerLabel,
    environment_profile: EnvironmentProfile,
    operating_system: OperatingSystem,
    architecture: Architecture,
    container_features: BTreeSet<ContainerFeature>,
}

impl GithubRunnerProfileMapping {
    /// Creates a typed mapping without resolving or inspecting an image.
    ///
    /// # Errors
    ///
    /// Rejects a non-canonical selector or custom platform value.
    pub fn new(
        selector: impl AsRef<str>,
        environment_profile: EnvironmentProfile,
        operating_system: OperatingSystem,
        architecture: Architecture,
    ) -> Result<Self, GithubRunnerProfileError> {
        let selector =
            RunnerLabel::new(selector).map_err(|_| GithubRunnerProfileError::InvalidSelector)?;
        validate_platform_value(&operating_system, &architecture)?;
        Ok(Self {
            selector,
            environment_profile,
            operating_system,
            architecture,
            container_features: BTreeSet::new(),
        })
    }

    /// Adds provider-neutral container features guaranteed by this profile.
    #[must_use]
    pub fn with_container_features(
        mut self,
        features: impl IntoIterator<Item = ContainerFeature>,
    ) -> Self {
        self.container_features = features.into_iter().collect();
        self
    }

    #[must_use]
    /// Returns the canonical GitHub `runs-on` label mapped by this entry.
    pub const fn selector(&self) -> &RunnerLabel {
        &self.selector
    }

    #[must_use]
    /// Returns the immutable, server-attested environment image profile.
    pub const fn environment_profile(&self) -> &EnvironmentProfile {
        &self.environment_profile
    }

    #[must_use]
    /// Returns the operating system guaranteed by the attested profile.
    pub const fn operating_system(&self) -> &OperatingSystem {
        &self.operating_system
    }

    #[must_use]
    /// Returns the processor architecture guaranteed by the attested profile.
    pub const fn architecture(&self) -> &Architecture {
        &self.architecture
    }

    #[must_use]
    /// Returns the provider-neutral container features guaranteed by the profile.
    pub const fn container_features(&self) -> &BTreeSet<ContainerFeature> {
        &self.container_features
    }
}

/// Validated catalog of server-attested GitHub-hosted runner profiles.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GithubRunnerProfileCatalog {
    mappings: BTreeMap<RunnerLabel, GithubRunnerProfileMapping>,
}

impl GithubRunnerProfileCatalog {
    /// Builds a catalog and rejects duplicate canonical selectors.
    ///
    /// # Errors
    ///
    /// Rejects duplicate mappings for one selector.
    pub fn new(
        mappings: impl IntoIterator<Item = GithubRunnerProfileMapping>,
    ) -> Result<Self, GithubRunnerProfileError> {
        let mut catalog = BTreeMap::new();
        for mapping in mappings {
            let selector = mapping.selector.clone();
            if catalog.insert(selector.clone(), mapping).is_some() {
                return Err(GithubRunnerProfileError::DuplicateSelector(
                    selector.as_str().to_owned(),
                ));
            }
        }
        Ok(Self { mappings: catalog })
    }

    #[must_use]
    /// Resolves an exact canonical selector to its server-attested mapping.
    pub fn get(&self, selector: &RunnerLabel) -> Option<&GithubRunnerProfileMapping> {
        self.mappings.get(selector)
    }

    #[must_use]
    /// Returns whether the catalog contains no attested selector mappings.
    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }
}

/// Invalid server-attested GitHub runner profile configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GithubRunnerProfileError {
    /// A selector is empty, non-canonical, or otherwise invalid.
    InvalidSelector,
    /// A custom operating-system or architecture value is not safely canonical.
    InvalidPlatform,
    /// More than one mapping names the same canonical selector.
    DuplicateSelector(String),
}

impl std::fmt::Display for GithubRunnerProfileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSelector => {
                formatter.write_str("runner profile selector is not canonical")
            }
            Self::InvalidPlatform => {
                formatter.write_str("runner profile platform contains an invalid custom value")
            }
            Self::DuplicateSelector(selector) => {
                write!(
                    formatter,
                    "runner profile selector `{selector}` is mapped more than once"
                )
            }
        }
    }
}

impl std::error::Error for GithubRunnerProfileError {}

fn validate_platform_value(
    operating_system: &OperatingSystem,
    architecture: &Architecture,
) -> Result<(), GithubRunnerProfileError> {
    let values = [
        match operating_system {
            OperatingSystem::Other(value) => Some(value.as_str()),
            OperatingSystem::Linux | OperatingSystem::Windows | OperatingSystem::Macos => None,
        },
        match architecture {
            Architecture::Other(value) => Some(value.as_str()),
            Architecture::X86_64 | Architecture::Aarch64 => None,
        },
    ];
    if values.into_iter().flatten().any(|value| {
        value.trim().is_empty() || value.trim() != value || value.chars().any(char::is_control)
    }) {
        return Err(GithubRunnerProfileError::InvalidPlatform);
    }
    Ok(())
}
