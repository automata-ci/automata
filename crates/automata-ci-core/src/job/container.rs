//! Provider-neutral job and service container requests.

use std::collections::{BTreeMap, BTreeSet};

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
    /// Opaque engine options whose interpretation remains deferred.
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

    /// Returns the image reference retained for provider-side resolution.
    #[must_use]
    pub fn image(&self) -> &str {
        &self.image
    }

    /// Returns registry credential references, never resolved credential bytes.
    #[must_use]
    pub const fn credentials(&self) -> Option<&ContainerCredentials> {
        self.credentials.as_ref()
    }

    /// Returns the deterministic environment mapping supplied to the container.
    #[must_use]
    pub const fn environment(&self) -> &BTreeMap<String, ValueSource> {
        &self.environment
    }

    /// Returns requested container listeners in retained source order.
    #[must_use]
    pub fn ports(&self) -> &[ContainerPort] {
        &self.ports
    }

    /// Returns declarative volume mounts in retained source order.
    #[must_use]
    pub fn volumes(&self) -> &[VolumeMount] {
        &self.volumes
    }

    /// Returns opaque engine options whose interpretation is deferred to admission.
    #[must_use]
    pub fn options(&self) -> &[String] {
        &self.options
    }

    /// Replaces the optional registry-authentication references.
    #[must_use]
    pub fn with_credentials(mut self, credentials: ContainerCredentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    /// Replaces the complete container environment mapping.
    #[must_use]
    pub fn with_environment(mut self, environment: BTreeMap<String, ValueSource>) -> Self {
        self.environment = environment;
        self
    }

    /// Replaces the requested listener set; job validation enforces nonzero uniqueness.
    #[must_use]
    pub fn with_ports(mut self, ports: impl IntoIterator<Item = ContainerPort>) -> Self {
        self.ports = ports.into_iter().collect();
        self
    }

    /// Replaces the declarative mount list.
    #[must_use]
    pub fn with_volumes(mut self, volumes: impl IntoIterator<Item = VolumeMount>) -> Self {
        self.volumes = volumes.into_iter().collect();
        self
    }

    /// Replaces the opaque engine-option list without interpreting its values.
    #[must_use]
    pub fn with_options(mut self, options: impl IntoIterator<Item = String>) -> Self {
        self.options = options.into_iter().collect();
        self
    }

    pub(super) fn validate(&self, field: &'static str) -> Result<(), JobValidationError> {
        if self.image.trim().is_empty() {
            return Err(JobValidationError::EmptyField(field));
        }
        let mut container_ports = BTreeSet::new();
        let mut requested_ports = BTreeSet::new();
        for port in &self.ports {
            if port.number == 0
                || port.requested_host_port == Some(0)
                || !container_ports.insert(port.number)
                || port
                    .requested_host_port
                    .is_some_and(|requested| !requested_ports.insert((port.protocol, requested)))
            {
                return Err(JobValidationError::InvalidContainerPorts);
            }
        }
        Ok(())
    }

    pub(super) fn validate_values(&self) -> Result<(), JobValidationError> {
        for value in self.environment.values() {
            value.validate("container environment")?;
        }
        if let Some(credentials) = &self.credentials {
            credentials
                .username
                .validate("container credential username")?;
            credentials
                .password
                .validate("container credential password")?;
        }
        Ok(())
    }
}

/// Secret references for registry authentication; never plaintext credentials.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContainerCredentials {
    username: ValueSource,
    password: ValueSource,
}

impl ContainerCredentials {
    /// Creates registry credentials from deferred value sources.
    #[must_use]
    pub const fn new(username: ValueSource, password: ValueSource) -> Self {
        Self { username, password }
    }

    /// Returns the deferred registry username source.
    #[must_use]
    pub const fn username(&self) -> &ValueSource {
        &self.username
    }

    /// Returns the deferred registry password source.
    #[must_use]
    pub const fn password(&self) -> &ValueSource {
        &self.password
    }
}

/// Exposed service port with an optional exact host-side listener request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerPort {
    #[serde(rename = "container_port")]
    number: u16,
    requested_host_port: Option<u16>,
    protocol: TransportProtocol,
}

impl ContainerPort {
    /// Creates a port request; enclosing job validation rejects zero or duplicate ports.
    #[must_use]
    pub const fn new(
        container_port: u16,
        requested_host_port: Option<u16>,
        protocol: TransportProtocol,
    ) -> Self {
        Self {
            number: container_port,
            requested_host_port,
            protocol,
        }
    }

    /// Returns the nonzero listener port expected inside the container.
    #[must_use]
    pub const fn container_port(self) -> u16 {
        self.number
    }

    /// Returns the requested listener port, or `None` for runtime assignment.
    #[must_use]
    pub const fn requested_host_port(self) -> Option<u16> {
        self.requested_host_port
    }

    /// Returns the requested transport protocol.
    #[must_use]
    pub const fn protocol(self) -> TransportProtocol {
        self.protocol
    }
}

/// Transport protocol for a container port.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProtocol {
    /// Connection-oriented Transmission Control Protocol.
    #[default]
    Tcp,
    /// Datagram-oriented User Datagram Protocol.
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
    /// Creates a declarative mount request without consulting a host filesystem.
    #[must_use]
    pub fn new(source: MountSource, target: impl Into<String>, read_only: bool) -> Self {
        Self {
            source,
            target: target.into(),
            read_only,
        }
    }

    /// Returns the provider-neutral source class and value.
    #[must_use]
    pub const fn source(&self) -> &MountSource {
        &self.source
    }

    /// Returns the requested path inside the container.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Reports whether the container must receive a read-only mount.
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        self.read_only
    }
}

/// Provider-neutral source for a requested volume.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum MountSource {
    /// A path resolved beneath the admitted job workspace.
    WorkspaceRelative(String),
    /// A provider-created ephemeral volume identified by a logical name.
    TemporaryVolume(String),
    /// An explicit host path subject to provider admission policy.
    HostPath(String),
}
