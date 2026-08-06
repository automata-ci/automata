//! Provider-neutral job and service container requests.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{JobValidationError, ValueSource};

/// Provider-independent container request for a job or service.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContainerSpec {
    image: String,
    credentials: Option<ContainerCredentials>,
    environment: BTreeMap<String, ValueSource>,
    ports: Vec<ContainerPort>,
    volumes: Vec<VolumeMount>,
    /// Compatibility-preserving engine options; interpretation is deferred.
    options: Vec<String>,
}

impl ContainerSpec {
    /// Creates a minimal container request. Empty images are rejected by job validation.
    #[must_use]
    pub fn new(image: impl Into<String>) -> Self {
        Self {
            image: image.into(),
            credentials: None,
            environment: BTreeMap::new(),
            ports: Vec::new(),
            volumes: Vec::new(),
            options: Vec::new(),
        }
    }

    #[must_use]
    pub fn image(&self) -> &str {
        &self.image
    }

    #[must_use]
    pub const fn credentials(&self) -> Option<&ContainerCredentials> {
        self.credentials.as_ref()
    }

    #[must_use]
    pub const fn environment(&self) -> &BTreeMap<String, ValueSource> {
        &self.environment
    }

    #[must_use]
    pub fn ports(&self) -> &[ContainerPort] {
        &self.ports
    }

    #[must_use]
    pub fn volumes(&self) -> &[VolumeMount] {
        &self.volumes
    }

    #[must_use]
    pub fn options(&self) -> &[String] {
        &self.options
    }

    #[must_use]
    pub fn with_credentials(mut self, credentials: ContainerCredentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    #[must_use]
    pub fn with_environment(mut self, environment: BTreeMap<String, ValueSource>) -> Self {
        self.environment = environment;
        self
    }

    #[must_use]
    pub fn with_ports(mut self, ports: impl IntoIterator<Item = ContainerPort>) -> Self {
        self.ports = ports.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_volumes(mut self, volumes: impl IntoIterator<Item = VolumeMount>) -> Self {
        self.volumes = volumes.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_options(mut self, options: impl IntoIterator<Item = String>) -> Self {
        self.options = options.into_iter().collect();
        self
    }

    pub(super) fn validate(&self, field: &'static str) -> Result<(), JobValidationError> {
        if self.image.trim().is_empty() {
            Err(JobValidationError::EmptyField(field))
        } else {
            Ok(())
        }
    }
}

/// Secret references for registry authentication; never plaintext credentials.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContainerCredentials {
    username: ValueSource,
    password: ValueSource,
}

impl ContainerCredentials {
    #[must_use]
    pub const fn new(username: ValueSource, password: ValueSource) -> Self {
        Self { username, password }
    }

    #[must_use]
    pub const fn username(&self) -> &ValueSource {
        &self.username
    }

    #[must_use]
    pub const fn password(&self) -> &ValueSource {
        &self.password
    }
}

/// Exposed service port, with host assignment left to the runtime.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContainerPort {
    container_port: u16,
    protocol: TransportProtocol,
}

impl ContainerPort {
    #[must_use]
    pub const fn new(container_port: u16, protocol: TransportProtocol) -> Self {
        Self {
            container_port,
            protocol,
        }
    }

    #[must_use]
    pub const fn container_port(self) -> u16 {
        self.container_port
    }

    #[must_use]
    pub const fn protocol(self) -> TransportProtocol {
        self.protocol
    }
}

/// Transport protocol for a container port.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProtocol {
    #[default]
    Tcp,
    Udp,
}

/// Declarative mount request, not an engine-specific mount handle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VolumeMount {
    source: MountSource,
    target: String,
    read_only: bool,
}

impl VolumeMount {
    #[must_use]
    pub fn new(source: MountSource, target: impl Into<String>, read_only: bool) -> Self {
        Self {
            source,
            target: target.into(),
            read_only,
        }
    }

    #[must_use]
    pub const fn source(&self) -> &MountSource {
        &self.source
    }

    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        self.read_only
    }
}

/// Provider-neutral source for a requested volume.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum MountSource {
    WorkspaceRelative(String),
    TemporaryVolume(String),
    HostPath(String),
}
