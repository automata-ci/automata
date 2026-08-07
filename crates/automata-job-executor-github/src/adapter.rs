use std::{collections::BTreeMap, fmt};

use automata_action_github::JavascriptRuntime;
use automata_core::EnvironmentProfile;
use automata_execution::{SandboxEnvironment, TargetPath, TargetPlatform};

use crate::{GithubToolchain, PortError, SandboxEnvironmentCatalog, error::PortErrorKind};

/// Immutable exact-attestation environment catalog.
#[derive(Clone, Default)]
pub struct ImmutableSandboxEnvironmentCatalog {
    environments: BTreeMap<EnvironmentProfile, SandboxEnvironment>,
}

impl ImmutableSandboxEnvironmentCatalog {
    /// Creates a catalog and rejects duplicate or mismatched attestations.
    ///
    /// # Errors
    ///
    /// Returns an invalid-data error when a key would collide or launch
    /// material does not carry its own exact catalog key.
    pub fn new(
        environments: impl IntoIterator<Item = SandboxEnvironment>,
    ) -> Result<Self, PortError> {
        let mut catalog = BTreeMap::new();
        for environment in environments {
            let attestation = environment.attestation().clone();
            if catalog.insert(attestation, environment).is_some() {
                return Err(PortError::new(PortErrorKind::InvalidData));
            }
        }
        Ok(Self {
            environments: catalog,
        })
    }

    /// Returns the number of exact launch profiles.
    #[must_use]
    pub fn len(&self) -> usize {
        self.environments.len()
    }

    /// Returns whether no launch profiles are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.environments.is_empty()
    }
}

impl SandboxEnvironmentCatalog for ImmutableSandboxEnvironmentCatalog {
    fn select(&self, profile: &EnvironmentProfile) -> Option<SandboxEnvironment> {
        self.environments.get(profile).cloned()
    }
}

impl fmt::Debug for ImmutableSandboxEnvironmentCatalog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImmutableSandboxEnvironmentCatalog")
            .field(
                "attestations",
                &self.environments.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// Immutable target paths for a Linux GitHub runner profile.
#[derive(Clone)]
pub struct StaticGithubToolchain {
    bash: TargetPath,
    sh: TargetPath,
    install: TargetPath,
    tar: TargetPath,
    nodes: Vec<(JavascriptRuntime, TargetPath)>,
}

impl StaticGithubToolchain {
    /// Creates base Linux tool paths without assuming any Node runtimes.
    ///
    /// # Errors
    ///
    /// Rejects non-POSIX or root executable paths.
    pub fn new(
        bash: TargetPath,
        sh: TargetPath,
        install: TargetPath,
        tar: TargetPath,
    ) -> Result<Self, PortError> {
        if [&bash, &sh, &install, &tar]
            .into_iter()
            .any(|path| !valid_tool(path))
        {
            return Err(PortError::new(PortErrorKind::InvalidData));
        }
        Ok(Self {
            bash,
            sh,
            install,
            tar,
            nodes: Vec::new(),
        })
    }

    /// Adds one metadata-selected Node executable.
    ///
    /// # Errors
    ///
    /// Rejects a duplicate runtime or invalid target path.
    pub fn with_node(
        mut self,
        runtime: JavascriptRuntime,
        path: TargetPath,
    ) -> Result<Self, PortError> {
        if !valid_tool(&path)
            || self
                .nodes
                .iter()
                .any(|(configured, _)| *configured == runtime)
        {
            return Err(PortError::new(PortErrorKind::InvalidData));
        }
        self.nodes.push((runtime, path));
        Ok(self)
    }
}

impl GithubToolchain for StaticGithubToolchain {
    fn bash(&self) -> &TargetPath {
        &self.bash
    }

    fn sh(&self) -> &TargetPath {
        &self.sh
    }

    fn install(&self) -> &TargetPath {
        &self.install
    }

    fn tar(&self) -> &TargetPath {
        &self.tar
    }

    fn node(&self, runtime: JavascriptRuntime) -> Option<&TargetPath> {
        self.nodes
            .iter()
            .find(|(configured, _)| *configured == runtime)
            .map(|(_, path)| path)
    }
}

impl fmt::Debug for StaticGithubToolchain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StaticGithubToolchain")
            .field("bash", &self.bash)
            .field("sh", &self.sh)
            .field("install", &self.install)
            .field("tar", &self.tar)
            .field(
                "node_runtimes",
                &self
                    .nodes
                    .iter()
                    .map(|(runtime, _)| runtime)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

fn valid_tool(path: &TargetPath) -> bool {
    path.platform() == TargetPlatform::Posix && path.as_str() != "/"
}
