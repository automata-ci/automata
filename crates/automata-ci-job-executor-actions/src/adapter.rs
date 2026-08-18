use std::{collections::BTreeMap, fmt};

use automata_ci_action_actions::JavascriptRuntime;
use automata_ci_core::EnvironmentProfile;
use automata_ci_execution::{ExecutionArgv, SandboxEnvironment, TargetPath, TargetPlatform};

use crate::{ActionsToolchain, PortError, SandboxEnvironmentCatalog, error::PortErrorKind};

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

/// Immutable target paths for one platform-specific GitHub runner profile.
#[derive(Clone)]
pub struct StaticActionsToolchain {
    platform: TargetPlatform,
    bash: Option<TargetPath>,
    sh: Option<TargetPath>,
    python: Option<TargetPath>,
    pwsh: Option<TargetPath>,
    powershell: Option<TargetPath>,
    cmd: Option<TargetPath>,
    install: Option<TargetPath>,
    tar: Option<TargetPath>,
    sha256: Option<ExecutionArgv>,
    nodes: Vec<(JavascriptRuntime, TargetPath)>,
}

impl StaticActionsToolchain {
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
        sha256sum: TargetPath,
    ) -> Result<Self, PortError> {
        if [&bash, &sh, &install, &tar, &sha256sum]
            .into_iter()
            .any(|path| !valid_tool(path, TargetPlatform::Posix))
        {
            return Err(PortError::new(PortErrorKind::InvalidData));
        }
        Ok(Self {
            platform: TargetPlatform::Posix,
            bash: Some(bash),
            sh: Some(sh),
            python: None,
            pwsh: None,
            powershell: None,
            cmd: None,
            install: Some(install),
            tar: Some(tar),
            sha256: Some(
                ExecutionArgv::new(sha256sum, Vec::<String>::new())
                    .map_err(|_| PortError::new(PortErrorKind::InvalidData))?,
            ),
            nodes: Vec::new(),
        })
    }

    /// Creates the required in-image shell paths for a Windows container profile.
    ///
    /// # Errors
    ///
    /// Rejects non-Windows or drive-root executable paths.
    pub fn windows(
        pwsh: TargetPath,
        powershell: TargetPath,
        cmd: TargetPath,
    ) -> Result<Self, PortError> {
        if [&pwsh, &powershell, &cmd]
            .into_iter()
            .any(|path| !valid_tool(path, TargetPlatform::Windows))
        {
            return Err(PortError::new(PortErrorKind::InvalidData));
        }
        Ok(Self {
            platform: TargetPlatform::Windows,
            bash: None,
            sh: None,
            python: None,
            pwsh: Some(pwsh),
            powershell: Some(powershell),
            cmd: Some(cmd),
            install: None,
            tar: None,
            sha256: None,
            nodes: Vec::new(),
        })
    }

    /// Adds the exact archive and SHA-256 tools used to materialize immutable
    /// repository actions inside a Windows sandbox.
    ///
    /// # Errors
    ///
    /// Rejects duplicate materializer configuration or non-Windows paths.
    pub fn with_windows_action_materializer(
        mut self,
        tar: TargetPath,
        sha256: TargetPath,
    ) -> Result<Self, PortError> {
        if self.platform != TargetPlatform::Windows
            || self.tar.is_some()
            || self.sha256.is_some()
            || !valid_tool(&tar, TargetPlatform::Windows)
            || !valid_tool(&sha256, TargetPlatform::Windows)
        {
            return Err(PortError::new(PortErrorKind::InvalidData));
        }
        self.tar = Some(tar);
        self.sha256 = Some(
            ExecutionArgv::new(sha256, Vec::<String>::new())
                .map_err(|_| PortError::new(PortErrorKind::InvalidData))?,
        );
        Ok(self)
    }

    /// Creates the required system tool paths for an ARM64 macOS runner profile.
    ///
    /// # Errors
    ///
    /// Rejects non-POSIX or root executable paths.
    pub fn macos(
        bash: TargetPath,
        sh: TargetPath,
        install: TargetPath,
        tar: TargetPath,
        shasum: TargetPath,
    ) -> Result<Self, PortError> {
        if [&bash, &sh, &install, &tar, &shasum]
            .into_iter()
            .any(|path| !valid_tool(path, TargetPlatform::Posix))
        {
            return Err(PortError::new(PortErrorKind::InvalidData));
        }
        Ok(Self {
            platform: TargetPlatform::Posix,
            bash: Some(bash),
            sh: Some(sh),
            python: None,
            pwsh: None,
            powershell: None,
            cmd: None,
            install: Some(install),
            tar: Some(tar),
            sha256: Some(
                ExecutionArgv::new(shasum, vec!["-a".to_owned(), "256".to_owned()])
                    .map_err(|_| PortError::new(PortErrorKind::InvalidData))?,
            ),
            nodes: Vec::new(),
        })
    }

    /// Adds the Python executable selected by the environment manifest.
    ///
    /// # Errors
    ///
    /// Rejects a duplicate configuration or a path for another platform.
    pub fn with_python(mut self, path: TargetPath) -> Result<Self, PortError> {
        if self.python.is_some() || !valid_tool(&path, self.platform) {
            return Err(PortError::new(PortErrorKind::InvalidData));
        }
        self.python = Some(path);
        Ok(self)
    }

    /// Adds the PowerShell Core executable selected by the environment manifest.
    ///
    /// # Errors
    ///
    /// Rejects a duplicate configuration or a path for another platform.
    pub fn with_pwsh(mut self, path: TargetPath) -> Result<Self, PortError> {
        if self.pwsh.is_some() || !valid_tool(&path, self.platform) {
            return Err(PortError::new(PortErrorKind::InvalidData));
        }
        self.pwsh = Some(path);
        Ok(self)
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
        if !valid_tool(&path, self.platform)
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

impl ActionsToolchain for StaticActionsToolchain {
    fn platform(&self) -> TargetPlatform {
        self.platform
    }

    fn bash(&self) -> Option<&TargetPath> {
        self.bash.as_ref()
    }

    fn sh(&self) -> Option<&TargetPath> {
        self.sh.as_ref()
    }

    fn python(&self) -> Option<&TargetPath> {
        self.python.as_ref()
    }

    fn pwsh(&self) -> Option<&TargetPath> {
        self.pwsh.as_ref()
    }

    fn powershell(&self) -> Option<&TargetPath> {
        self.powershell.as_ref()
    }

    fn cmd(&self) -> Option<&TargetPath> {
        self.cmd.as_ref()
    }

    fn install(&self) -> Option<&TargetPath> {
        self.install.as_ref()
    }

    fn tar(&self) -> Option<&TargetPath> {
        self.tar.as_ref()
    }

    fn sha256(&self) -> Option<&ExecutionArgv> {
        self.sha256.as_ref()
    }

    fn node(&self, runtime: JavascriptRuntime) -> Option<&TargetPath> {
        self.nodes
            .iter()
            .find(|(configured, _)| *configured == runtime)
            .map(|(_, path)| path)
    }
}

impl fmt::Debug for StaticActionsToolchain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StaticActionsToolchain")
            .field("platform", &self.platform)
            .field("bash", &self.bash)
            .field("sh", &self.sh)
            .field("python", &self.python)
            .field("pwsh", &self.pwsh)
            .field("powershell", &self.powershell)
            .field("cmd", &self.cmd)
            .field("install", &self.install)
            .field("tar", &self.tar)
            .field("sha256", &self.sha256)
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

fn valid_tool(path: &TargetPath, platform: TargetPlatform) -> bool {
    path.platform() == platform
        && match platform {
            TargetPlatform::Posix => path.as_str() != "/",
            TargetPlatform::Windows => path.as_str().len() > 3,
        }
}
