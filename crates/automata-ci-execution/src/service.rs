use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    time::Duration,
};

use crate::{ExecutionEnvironment, ImmutableImage, MAX_SANDBOX_HANDLE_BYTES, ValueError};

const MAX_SERVICE_NAME_BYTES: usize = 256;
const MAX_HEALTH_COMMAND_BYTES: usize = 64 * 1024;
const MAX_HEALTH_RETRIES: u32 = 1_000;
const MAX_HEALTH_DURATION: Duration = Duration::from_hours(24);

/// Opaque provider-owned handle for one service container.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ContainerHandle(String);

impl ContainerHandle {
    /// Creates a bounded portable container token.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or path-like tokens.
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_SANDBOX_HANDLE_BYTES
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte));
        valid
            .then_some(Self(value))
            .ok_or(ValueError::InvalidSandboxHandle)
    }

    /// Borrows the provider-owned token.
    ///
    /// Consumers must treat this value as opaque and must not derive host
    /// paths, container names, or authorization decisions from its contents.
    #[must_use]
    pub fn opaque(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ContainerHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ContainerHandle([OPAQUE])")
    }
}

/// Transport protocol for one provider-published service port.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ServiceTransportProtocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
}

/// One non-zero service-container port.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ServicePort {
    container_port: u16,
    requested_host_port: Option<u16>,
    protocol: ServiceTransportProtocol,
}

impl ServicePort {
    /// Creates one exact container port.
    ///
    /// # Errors
    ///
    /// Rejects port zero, which cannot be exposed by a container runtime.
    pub const fn new(
        container_port: u16,
        requested_host_port: Option<u16>,
        protocol: ServiceTransportProtocol,
    ) -> Result<Self, ValueError> {
        if container_port == 0 || matches!(requested_host_port, Some(0)) {
            return Err(ValueError::InvalidServiceContainer);
        }
        Ok(Self {
            container_port,
            requested_host_port,
            protocol,
        })
    }

    /// Returns the port requested inside the service container.
    #[must_use]
    pub const fn container_port(self) -> u16 {
        self.container_port
    }

    /// Returns the exact requested loopback listener, or `None` when the
    /// provider must allocate a free port.
    #[must_use]
    pub const fn requested_host_port(self) -> Option<u16> {
        self.requested_host_port
    }

    /// Returns the transport protocol for the requested port.
    #[must_use]
    pub const fn protocol(self) -> ServiceTransportProtocol {
        self.protocol
    }
}

/// Explicit overrides for an image-defined container health check.
#[derive(Clone, Eq, PartialEq)]
pub struct ServiceHealthOverrides {
    command: Option<String>,
    interval: Option<Duration>,
    timeout: Option<Duration>,
    start_period: Option<Duration>,
    retries: Option<u32>,
}

impl ServiceHealthOverrides {
    /// Creates a bounded set of health-check overrides.
    ///
    /// # Errors
    ///
    /// Rejects an empty override, invalid command text, zero or excessive
    /// durations, and zero or excessive retry counts.
    pub fn new(
        command: Option<String>,
        interval: Option<Duration>,
        timeout: Option<Duration>,
        start_period: Option<Duration>,
        retries: Option<u32>,
    ) -> Result<Self, ValueError> {
        if command.is_none()
            && interval.is_none()
            && timeout.is_none()
            && start_period.is_none()
            && retries.is_none()
        {
            return Err(ValueError::InvalidServiceContainer);
        }
        if command.as_ref().is_some_and(|command| {
            command.is_empty() || command.len() > MAX_HEALTH_COMMAND_BYTES || command.contains('\0')
        }) || [interval, timeout, start_period]
            .into_iter()
            .flatten()
            .any(|duration| duration.is_zero() || duration > MAX_HEALTH_DURATION)
            || retries.is_some_and(|retries| retries == 0 || retries > MAX_HEALTH_RETRIES)
        {
            return Err(ValueError::InvalidServiceContainer);
        }
        Ok(Self {
            command,
            interval,
            timeout,
            start_period,
            retries,
        })
    }

    /// Returns the replacement health-check command, when supplied.
    ///
    /// Command text is redacted from `Debug` because it can contain workflow
    /// data. This accessor exposes the exact value and callers must not log it.
    #[must_use]
    pub fn command(&self) -> Option<&str> {
        self.command.as_deref()
    }

    /// Returns the override between health-check attempts.
    #[must_use]
    pub const fn interval(&self) -> Option<Duration> {
        self.interval
    }

    /// Returns the per-attempt health-check timeout override.
    #[must_use]
    pub const fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Returns the initial grace-period override.
    #[must_use]
    pub const fn start_period(&self) -> Option<Duration> {
        self.start_period
    }

    /// Returns the number of failed checks permitted before unhealthy state.
    #[must_use]
    pub const fn retries(&self) -> Option<u32> {
        self.retries
    }
}

impl fmt::Debug for ServiceHealthOverrides {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceHealthOverrides")
            .field("command", &self.command.as_ref().map(|_| "[REDACTED]"))
            .field("interval", &self.interval)
            .field("timeout", &self.timeout)
            .field("start_period", &self.start_period)
            .field("retries", &self.retries)
            .finish()
    }
}

/// Health policy applied before a job can begin executing steps.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum ServiceHealthPolicy {
    /// Honor an image-defined health check, when present.
    #[default]
    Image,
    /// Disable an image-defined health check explicitly.
    Disabled,
    /// Override part or all of the image-defined health configuration.
    Override(ServiceHealthOverrides),
}

/// Exact provider-neutral service request owned by a whole-job sandbox.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceContainerSpec {
    image: ImmutableImage,
    environment: ExecutionEnvironment,
    ports: Vec<ServicePort>,
    health: ServiceHealthPolicy,
}

impl ServiceContainerSpec {
    /// Creates a service request using image-defined health behavior and no
    /// published ports.
    ///
    /// The image is immutable and the validated environment is passed only to
    /// this service container. Environment values remain potentially secret.
    #[must_use]
    pub const fn new(image: ImmutableImage, environment: ExecutionEnvironment) -> Self {
        Self {
            image,
            environment,
            ports: Vec::new(),
            health: ServiceHealthPolicy::Image,
        }
    }

    /// Returns the digest-pinned service image.
    #[must_use]
    pub const fn image(&self) -> &ImmutableImage {
        &self.image
    }

    /// Returns the service's complete process environment.
    #[must_use]
    pub const fn environment(&self) -> &ExecutionEnvironment {
        &self.environment
    }

    /// Returns requested ports in caller-supplied order.
    #[must_use]
    pub fn ports(&self) -> &[ServicePort] {
        &self.ports
    }

    /// Returns the health policy that gates job execution.
    #[must_use]
    pub const fn health(&self) -> &ServiceHealthPolicy {
        &self.health
    }

    /// Selects unique service ports.
    ///
    /// # Errors
    ///
    /// Rejects duplicate container port numbers. GitHub's `job.services`
    /// context keys ports by number, so TCP/UDP duplicates are ambiguous.
    pub fn with_ports(
        mut self,
        ports: impl IntoIterator<Item = ServicePort>,
    ) -> Result<Self, ValueError> {
        self.ports = ports.into_iter().collect();
        let mut numbers = BTreeSet::new();
        let mut requested = BTreeSet::new();
        if self.ports.iter().any(|port| {
            !numbers.insert(port.container_port())
                || port
                    .requested_host_port()
                    .is_some_and(|host| !requested.insert((port.protocol(), host)))
        }) {
            return Err(ValueError::InvalidServiceContainer);
        }
        Ok(self)
    }

    /// Selects the health policy that must pass before job steps start.
    #[must_use]
    pub fn with_health(mut self, health: ServiceHealthPolicy) -> Self {
        self.health = health;
        self
    }
}

/// Validated service set supplied atomically with a sandbox create request.
///
/// Aliases are logical workflow keys, not provider resource identifiers.
/// Adapters must not interpolate them into host paths, commands, labels, or
/// backend names without a separate provider-safe encoding.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ServiceContainerSpecs(BTreeMap<String, ServiceContainerSpec>);

impl ServiceContainerSpecs {
    /// Returns a service set containing no service requests.
    #[must_use]
    pub const fn empty() -> Self {
        Self(BTreeMap::new())
    }

    /// Validates service aliases before they cross the provider boundary.
    ///
    /// # Errors
    ///
    /// Rejects empty, control-containing, oversized, or ASCII-case-colliding
    /// names, and exact listener requests that collide across services.
    pub fn new(values: BTreeMap<String, ServiceContainerSpec>) -> Result<Self, ValueError> {
        validate_names(values.keys().map(String::as_str))?;
        let mut requested = BTreeSet::new();
        if values
            .values()
            .flat_map(ServiceContainerSpec::ports)
            .any(|port| {
                port.requested_host_port()
                    .is_some_and(|host| !requested.insert((port.protocol(), host)))
            })
        {
            return Err(ValueError::InvalidServiceContainer);
        }
        Ok(Self(values))
    }

    /// Returns the service request for an exact, case-sensitive alias.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ServiceContainerSpec> {
        self.0.get(name)
    }

    /// Iterates service aliases and requests in stable lexical alias order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &ServiceContainerSpec)> {
        self.0.iter().map(|(name, spec)| (name.as_str(), spec))
    }

    /// Returns whether the set contains no service requests.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of service requests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// Opaque provider network identifier exposed through `job.services`.
#[derive(Clone, Eq, PartialEq)]
pub struct ServiceNetwork(String);

impl ServiceNetwork {
    /// Creates a bounded portable network token.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or path-like values.
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_SANDBOX_HANDLE_BYTES
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte));
        valid
            .then_some(Self(value))
            .ok_or(ValueError::InvalidServiceContainer)
    }

    /// Exposes the provider-owned network token for service discovery.
    ///
    /// Callers must treat the returned value as opaque and must not derive
    /// host-resource access or authorization decisions from its contents.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ServiceNetwork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServiceNetwork([OPAQUE])")
    }
}

/// One runtime-assigned host port for a requested service port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServicePortBinding {
    service_port: ServicePort,
    host_port: u16,
}

impl ServicePortBinding {
    /// Creates a non-zero runtime port binding.
    ///
    /// # Errors
    ///
    /// Rejects host port zero or a binding that does not honor an exact
    /// requested listener port.
    pub const fn new(service_port: ServicePort, host_port: u16) -> Result<Self, ValueError> {
        if host_port == 0
            || matches!(service_port.requested_host_port(), Some(requested) if requested != host_port)
        {
            return Err(ValueError::InvalidServiceContainer);
        }
        Ok(Self {
            service_port,
            host_port,
        })
    }

    /// Returns the requested service-container port.
    #[must_use]
    pub const fn service_port(self) -> ServicePort {
        self.service_port
    }

    /// Returns the runtime-assigned non-zero host port.
    #[must_use]
    pub const fn host_port(self) -> u16 {
        self.host_port
    }
}

/// Runtime discovery values for one healthy service container.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceContainerBinding {
    container: ContainerHandle,
    network: ServiceNetwork,
    ports: Vec<ServicePortBinding>,
}

impl ServiceContainerBinding {
    /// Creates one validated service discovery record.
    ///
    /// # Errors
    ///
    /// Rejects duplicate requested ports or protocol-aware duplicate host
    /// bindings.
    pub fn new(
        container: ContainerHandle,
        network: ServiceNetwork,
        ports: impl IntoIterator<Item = ServicePortBinding>,
    ) -> Result<Self, ValueError> {
        let ports = ports.into_iter().collect::<Vec<_>>();
        let mut requested = BTreeSet::new();
        let mut published = BTreeSet::new();
        if ports.iter().any(|binding| {
            !requested.insert(binding.service_port())
                || !published.insert((binding.host_port(), binding.service_port().protocol()))
        }) {
            return Err(ValueError::InvalidServiceContainer);
        }
        Ok(Self {
            container,
            network,
            ports,
        })
    }

    /// Returns the exact opaque container handle for this service.
    #[must_use]
    pub const fn container(&self) -> &ContainerHandle {
        &self.container
    }

    /// Returns the shared private network on which this service is reachable.
    #[must_use]
    pub const fn network(&self) -> &ServiceNetwork {
        &self.network
    }

    /// Returns runtime port bindings in caller-supplied order.
    #[must_use]
    pub fn ports(&self) -> &[ServicePortBinding] {
        &self.ports
    }
}

/// Complete healthy-service discovery view for one exact sandbox generation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ServiceContainerBindings(BTreeMap<String, ServiceContainerBinding>);

impl ServiceContainerBindings {
    /// Returns a discovery view containing no services.
    #[must_use]
    pub const fn empty() -> Self {
        Self(BTreeMap::new())
    }

    /// Validates aliases and cross-service discovery invariants.
    ///
    /// # Errors
    ///
    /// Rejects case-colliding aliases, reused container handles, inconsistent
    /// networks, or colliding published ports.
    pub fn new(values: BTreeMap<String, ServiceContainerBinding>) -> Result<Self, ValueError> {
        validate_names(values.keys().map(String::as_str))?;
        let mut containers = BTreeSet::new();
        let mut network = None;
        let mut published = BTreeSet::new();
        for binding in values.values() {
            if !containers.insert(binding.container().opaque().to_owned()) {
                return Err(ValueError::InvalidServiceContainer);
            }
            match &network {
                None => network = Some(binding.network().expose()),
                Some(expected) if *expected == binding.network().expose() => {}
                Some(_) => return Err(ValueError::InvalidServiceContainer),
            }
            for port in binding.ports() {
                if !published.insert((port.host_port(), port.service_port().protocol())) {
                    return Err(ValueError::InvalidServiceContainer);
                }
            }
        }
        Ok(Self(values))
    }

    /// Returns discovery data for an exact, case-sensitive service alias.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ServiceContainerBinding> {
        self.0.get(name)
    }

    /// Iterates aliases and discovery records in stable lexical alias order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &ServiceContainerBinding)> {
        self.0
            .iter()
            .map(|(name, binding)| (name.as_str(), binding))
    }

    /// Returns whether the discovery view contains no services.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of healthy discovered services.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

fn validate_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<(), ValueError> {
    let mut normalized = BTreeSet::new();
    for name in names {
        if name.is_empty()
            || name.len() > MAX_SERVICE_NAME_BYTES
            || name.chars().any(char::is_control)
            || !normalized.insert(name.to_ascii_lowercase())
        {
            return Err(ValueError::InvalidServiceContainer);
        }
    }
    Ok(())
}
