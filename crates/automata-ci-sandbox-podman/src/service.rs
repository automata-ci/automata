use std::collections::BTreeSet;

use automata_ci_core::Sha256Digest;
use automata_ci_execution::ServiceHealthPolicy;
use automata_ci_execution::{
    ImmutableImage, ServiceContainerSpecs, ServicePort, ServiceTransportProtocol,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::naming::ResourceNames;

const MANIFEST_SCHEMA: u64 = 4;
const MAX_SERVICES: usize = 64;
const MAX_PORTS_PER_SERVICE: usize = 256;
const MAX_AGGREGATE_PIDS: u32 = 1_000_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ServiceManifest {
    fingerprint: String,
    network: String,
    aggregate_pids: u32,
    proxy_container: String,
    proxy_identifier: Option<String>,
    proxy_image: Option<String>,
    proxy_transition: bool,
    entries: Vec<ServiceManifestEntry>,
}

impl ServiceManifest {
    pub(crate) fn from_specs(
        names: &ResourceNames,
        fingerprint: &str,
        aggregate_pids: u32,
        specs: &ServiceContainerSpecs,
        proxy_image: Option<&ImmutableImage>,
    ) -> Option<Self> {
        if specs.len() > MAX_SERVICES
            || !valid_digest(fingerprint)
            || aggregate_pids == 0
            || aggregate_pids > MAX_AGGREGATE_PIDS
        {
            return None;
        }
        let entries = specs
            .iter()
            .map(|(alias, spec)| {
                if !valid_network_alias(alias) || spec.ports().len() > MAX_PORTS_PER_SERVICE {
                    return None;
                }
                Some(ServiceManifestEntry {
                    alias: alias.to_owned(),
                    container: names.service(alias),
                    identifier: None,
                    transition: false,
                    address: None,
                    image: spec.image().reference().to_owned(),
                    ports: spec.ports().to_vec(),
                    host_ports: vec![None; spec.ports().len()],
                    health: ServiceHealthExpectation::from_policy(spec.health()),
                    health_configuration: ServiceHealthConfiguration::from_policy(spec.health())
                        .ok()?,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        let has_ports = entries.iter().any(|entry| !entry.ports.is_empty());
        let proxy_image = match (has_ports, proxy_image) {
            (true, Some(image)) => Some(image.reference().to_owned()),
            (false, _) => None,
            (true, None) => return None,
        };
        Some(Self {
            fingerprint: fingerprint.to_owned(),
            network: names.network(),
            aggregate_pids,
            proxy_container: names.service_proxy(),
            proxy_identifier: None,
            proxy_image,
            proxy_transition: false,
            entries,
        })
    }

    pub(crate) fn encode(&self, names: &ResourceNames) -> Option<Vec<u8>> {
        let services = self
            .entries
            .iter()
            .map(|entry| {
                let ports = entry
                    .ports
                    .iter()
                    .zip(&entry.host_ports)
                    .map(|(port, host)| {
                        json!({
                            "container": port.container_port(),
                            "host": host,
                            "requested_host": port.requested_host_port(),
                            "protocol": protocol_name(port.protocol()),
                        })
                    })
                    .collect::<Vec<_>>();
                json!({
                    "alias": entry.alias,
                    "address": entry.address.as_deref(),
                    "container": entry.container,
                    "health": entry.health.as_str(),
                    "health_configuration": entry.health_configuration.as_ref().map(ServiceHealthConfiguration::to_json),
                    "identifier": entry.identifier.as_deref(),
                    "transition": entry.transition,
                    "image": entry.image,
                    "ports": ports,
                })
            })
            .collect::<Vec<_>>();
        serde_json::to_vec(&json!({
            "schema": MANIFEST_SCHEMA,
            "handle": names.handle().opaque(),
            "fingerprint": self.fingerprint,
            "network": self.network,
            "aggregate_pids": self.aggregate_pids,
            "proxy_container": self.proxy_container,
            "proxy_identifier": self.proxy_identifier.as_deref(),
            "proxy_image": self.proxy_image.as_deref(),
            "proxy_transition": self.proxy_transition,
            "services": services,
        }))
        .ok()
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn decode(bytes: &[u8], names: &ResourceNames) -> Option<Self> {
        let Value::Object(root) = serde_json::from_slice(bytes).ok()? else {
            return None;
        };
        if !exact_keys(
            &root,
            &[
                "schema",
                "handle",
                "fingerprint",
                "network",
                "aggregate_pids",
                "proxy_container",
                "proxy_identifier",
                "proxy_image",
                "proxy_transition",
                "services",
            ],
        ) || root.get("schema")?.as_u64()? != MANIFEST_SCHEMA
            || root.get("handle")?.as_str()? != names.handle().opaque()
            || root.get("network")?.as_str()? != names.network()
            || root.get("proxy_container")?.as_str()? != names.service_proxy()
        {
            return None;
        }
        let fingerprint = root.get("fingerprint")?.as_str()?.to_owned();
        let aggregate_pids = u32::try_from(root.get("aggregate_pids")?.as_u64()?).ok()?;
        let proxy_identifier = match root.get("proxy_identifier")? {
            Value::Null => None,
            Value::String(value) if valid_digest(value) => Some(value.clone()),
            _ => return None,
        };
        let proxy_image = match root.get("proxy_image")? {
            Value::Null => None,
            Value::String(value) => {
                ImmutableImage::new(value.clone()).ok()?;
                Some(value.clone())
            }
            _ => return None,
        };
        let proxy_transition = root.get("proxy_transition")?.as_bool()?;
        if !valid_digest(&fingerprint) || aggregate_pids == 0 || aggregate_pids > MAX_AGGREGATE_PIDS
        {
            return None;
        }
        let services = root.get("services")?.as_array()?;
        if services.len() > MAX_SERVICES {
            return None;
        }
        let mut aliases = BTreeSet::new();
        let mut containers = BTreeSet::new();
        let mut entries = Vec::with_capacity(services.len());
        for service in services {
            let Value::Object(service) = service else {
                return None;
            };
            if !exact_keys(
                service,
                &[
                    "alias",
                    "address",
                    "container",
                    "health",
                    "health_configuration",
                    "identifier",
                    "transition",
                    "image",
                    "ports",
                ],
            ) {
                return None;
            }
            let alias = service.get("alias")?.as_str()?;
            let address = match service.get("address")? {
                Value::Null => None,
                Value::String(value) => {
                    let parsed = value.parse::<std::net::Ipv4Addr>().ok()?;
                    Some(
                        (parsed.to_string() == *value
                            && !parsed.is_unspecified()
                            && !parsed.is_loopback()
                            && !parsed.is_multicast()
                            && !parsed.is_broadcast())
                        .then(|| value.clone())?,
                    )
                }
                _ => return None,
            };
            let container = service.get("container")?.as_str()?;
            let health = ServiceHealthExpectation::parse(service.get("health")?.as_str()?)?;
            let health_configuration = match service.get("health_configuration")? {
                Value::Null => None,
                value => Some(ServiceHealthConfiguration::from_json(value)?),
            };
            if (health == ServiceHealthExpectation::Override) != health_configuration.is_some() {
                return None;
            }
            let identifier = match service.get("identifier")? {
                Value::Null => None,
                Value::String(value) if valid_digest(value) => Some(value.clone()),
                _ => return None,
            };
            let transition = service.get("transition")?.as_bool()?;
            let image = service.get("image")?.as_str()?.to_owned();
            ImmutableImage::new(image.clone()).ok()?;
            if !valid_network_alias(alias)
                || !aliases.insert(alias.to_ascii_lowercase())
                || container != names.service(alias)
                || !containers.insert(container.to_owned())
            {
                return None;
            }
            let values = service.get("ports")?.as_array()?;
            if values.len() > MAX_PORTS_PER_SERVICE {
                return None;
            }
            let mut requested = BTreeSet::new();
            let mut ports = Vec::with_capacity(values.len());
            let mut host_ports = Vec::with_capacity(values.len());
            for value in values {
                let Value::Object(value) = value else {
                    return None;
                };
                if !exact_keys(value, &["container", "host", "requested_host", "protocol"]) {
                    return None;
                }
                let container_port = u16::try_from(value.get("container")?.as_u64()?).ok()?;
                let protocol = parse_protocol(value.get("protocol")?.as_str()?)?;
                let requested_host = match value.get("requested_host")? {
                    Value::Null => None,
                    Value::Number(value) => {
                        let value = u16::try_from(value.as_u64()?).ok()?;
                        Some((value != 0).then_some(value)?)
                    }
                    _ => return None,
                };
                let port = ServicePort::new(container_port, requested_host, protocol).ok()?;
                let host = match value.get("host")? {
                    Value::Null => None,
                    Value::Number(value) => {
                        let value = u16::try_from(value.as_u64()?).ok()?;
                        Some((value != 0).then_some(value)?)
                    }
                    _ => return None,
                };
                if requested_host
                    .is_some_and(|requested| host.is_some_and(|host| host != requested))
                {
                    return None;
                }
                if !requested.insert(port.container_port()) {
                    return None;
                }
                ports.push(port);
                host_ports.push(host);
            }
            entries.push(ServiceManifestEntry {
                alias: alias.to_owned(),
                address,
                container: container.to_owned(),
                identifier,
                transition,
                image,
                ports,
                host_ports,
                health,
                health_configuration,
            });
        }
        if entries
            .windows(2)
            .any(|pair| pair[0].alias >= pair[1].alias)
        {
            return None;
        }
        let port_count = entries.iter().map(|entry| entry.ports.len()).sum::<usize>();
        let bound_count = entries
            .iter()
            .flat_map(|entry| &entry.host_ports)
            .filter(|host| host.is_some())
            .count();
        if (bound_count != 0 && bound_count != port_count)
            || (proxy_identifier.is_none() && bound_count != 0 && !proxy_transition)
            || (port_count == 0 && proxy_identifier.is_some())
            || (port_count == 0) != proxy_image.is_none()
            || (proxy_transition
                && (port_count == 0 || (bound_count != 0 && bound_count != port_count)))
            || (bound_count != 0
                && entries
                    .iter()
                    .any(|entry| !entry.ports.is_empty() && entry.address.is_none()))
        {
            return None;
        }
        Some(Self {
            fingerprint,
            network: names.network(),
            aggregate_pids,
            proxy_container: names.service_proxy(),
            proxy_identifier,
            proxy_image,
            proxy_transition,
            entries,
        })
    }

    pub(crate) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub(crate) fn network(&self) -> &str {
        &self.network
    }

    pub(crate) const fn aggregate_pids(&self) -> u32 {
        self.aggregate_pids
    }

    pub(crate) fn proxy_container(&self) -> &str {
        &self.proxy_container
    }

    pub(crate) fn proxy_identifier(&self) -> Option<&str> {
        self.proxy_identifier.as_deref()
    }

    pub(crate) fn proxy_image(&self) -> Option<&str> {
        self.proxy_image.as_deref()
    }

    pub(crate) const fn proxy_transition(&self) -> bool {
        self.proxy_transition
    }

    pub(crate) fn entries(&self) -> &[ServiceManifestEntry] {
        &self.entries
    }

    pub(crate) fn record_pending_identifier(
        &mut self,
        alias: &str,
        identifier: &str,
    ) -> Option<bool> {
        if !valid_digest(identifier) {
            return None;
        }
        let entry = self.entries.iter_mut().find(|entry| entry.alias == alias)?;
        if !entry.transition {
            return None;
        }
        let changed = entry.identifier.as_deref() != Some(identifier);
        entry.identifier = Some(identifier.to_owned());
        Some(changed)
    }

    pub(crate) fn finish_service_create(&mut self, alias: &str, identifier: &str) -> Option<bool> {
        if !valid_digest(identifier) {
            return None;
        }
        let entry = self.entries.iter_mut().find(|entry| entry.alias == alias)?;
        if !entry.transition {
            return (entry.identifier.as_deref() == Some(identifier)).then_some(false);
        }
        entry.identifier = Some(identifier.to_owned());
        entry.transition = false;
        Some(true)
    }

    pub(crate) fn begin_service_create(&mut self, alias: &str) -> bool {
        let Some(entry) = self.entries.iter_mut().find(|entry| entry.alias == alias) else {
            return false;
        };
        if entry.identifier.is_some() {
            return false;
        }
        entry.transition = true;
        true
    }

    pub(crate) fn record_address(&mut self, alias: &str, address: &str) -> Option<bool> {
        let parsed = address.parse::<std::net::Ipv4Addr>().ok()?;
        if parsed.to_string() != address
            || parsed.is_unspecified()
            || parsed.is_loopback()
            || parsed.is_multicast()
            || parsed.is_broadcast()
        {
            return None;
        }
        let entry = self.entries.iter_mut().find(|entry| entry.alias == alias)?;
        if let Some(current) = entry.address.as_deref() {
            Some(current == address)
        } else {
            entry.address = Some(address.to_owned());
            Some(true)
        }
    }

    pub(crate) fn record_pending_proxy_identifier(&mut self, identifier: &str) -> Option<bool> {
        if !valid_digest(identifier) {
            return None;
        }
        if !self.proxy_transition {
            return None;
        }
        let changed = self.proxy_identifier.as_deref() != Some(identifier);
        self.proxy_identifier = Some(identifier.to_owned());
        Some(changed)
    }

    pub(crate) fn finish_proxy_replacement(&mut self, identifier: &str) -> Option<bool> {
        if !valid_digest(identifier) {
            return None;
        }
        if !self.proxy_transition {
            return (self.proxy_identifier.as_deref() == Some(identifier)).then_some(false);
        }
        self.proxy_identifier = Some(identifier.to_owned());
        self.proxy_transition = false;
        Some(true)
    }

    pub(crate) fn begin_proxy_replacement(&mut self) -> bool {
        let port_count = self.port_count();
        let bound_count = self.host_ports().filter(|port| port.is_some()).count();
        if port_count == 0 || (bound_count != 0 && bound_count != port_count) {
            return false;
        }
        self.proxy_identifier = None;
        self.proxy_transition = true;
        true
    }

    pub(crate) fn record_host_ports(&mut self, values: &[u16]) -> Option<bool> {
        let expected = self
            .entries
            .iter()
            .map(|entry| entry.ports.len())
            .sum::<usize>();
        if values.len() != expected || values.contains(&0) {
            return None;
        }
        let mut changed = false;
        let mut values = values.iter().copied();
        for entry in &mut self.entries {
            for (port, host) in entry.ports.iter().zip(&mut entry.host_ports) {
                let value = values.next()?;
                if port
                    .requested_host_port()
                    .is_some_and(|requested| requested != value)
                {
                    return None;
                }
                match *host {
                    Some(current) if current != value => return None,
                    Some(_) => {}
                    None => {
                        *host = Some(value);
                        changed = true;
                    }
                }
            }
        }
        values.next().is_none().then_some(changed)
    }

    pub(crate) fn port_count(&self) -> usize {
        self.entries.iter().map(|entry| entry.ports.len()).sum()
    }

    fn host_ports(&self) -> impl Iterator<Item = &Option<u16>> {
        self.entries.iter().flat_map(|entry| &entry.host_ports)
    }

    pub(crate) fn same_request(&self, other: &Self) -> bool {
        self.fingerprint == other.fingerprint
            && self.network == other.network
            && self.aggregate_pids == other.aggregate_pids
            && self.proxy_container == other.proxy_container
            && self.proxy_image == other.proxy_image
            && self.entries.len() == other.entries.len()
            && self
                .entries
                .iter()
                .zip(&other.entries)
                .all(|(left, right)| {
                    left.alias == right.alias
                        && left.container == right.container
                        && left.image == right.image
                        && left.ports == right.ports
                        && left.health == right.health
                        && left.health_configuration == right.health_configuration
                })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ServiceManifestEntry {
    alias: String,
    address: Option<String>,
    container: String,
    identifier: Option<String>,
    transition: bool,
    image: String,
    ports: Vec<ServicePort>,
    host_ports: Vec<Option<u16>>,
    health: ServiceHealthExpectation,
    health_configuration: Option<ServiceHealthConfiguration>,
}

impl ServiceManifestEntry {
    pub(crate) fn alias(&self) -> &str {
        &self.alias
    }

    pub(crate) fn address(&self) -> Option<&str> {
        self.address.as_deref()
    }

    pub(crate) fn container(&self) -> &str {
        &self.container
    }

    pub(crate) fn identifier(&self) -> Option<&str> {
        self.identifier.as_deref()
    }

    pub(crate) const fn transition(&self) -> bool {
        self.transition
    }

    pub(crate) fn image(&self) -> &str {
        &self.image
    }

    pub(crate) fn ports(&self) -> &[ServicePort] {
        &self.ports
    }

    pub(crate) fn host_ports(&self) -> &[Option<u16>] {
        &self.host_ports
    }

    pub(crate) const fn health(&self) -> ServiceHealthExpectation {
        self.health
    }

    pub(crate) const fn health_configuration(&self) -> Option<&ServiceHealthConfiguration> {
        self.health_configuration.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ServiceHealthConfiguration {
    mask: u8,
    digest: String,
}

impl ServiceHealthConfiguration {
    const COMMAND: u8 = 1;
    const INTERVAL: u8 = 1 << 1;
    const TIMEOUT: u8 = 1 << 2;
    const START_PERIOD: u8 = 1 << 3;
    const RETRIES: u8 = 1 << 4;
    const ALL: u8 =
        Self::COMMAND | Self::INTERVAL | Self::TIMEOUT | Self::START_PERIOD | Self::RETRIES;

    fn from_policy(policy: &ServiceHealthPolicy) -> Result<Option<Self>, ()> {
        let ServiceHealthPolicy::Override(overrides) = policy else {
            return Ok(None);
        };
        let command = overrides.command();
        let interval = overrides.interval().map(duration_nanos).transpose()?;
        let timeout = overrides.timeout().map(duration_nanos).transpose()?;
        let start_period = overrides.start_period().map(duration_nanos).transpose()?;
        let retries = overrides.retries().map(u64::from);
        let (mask, digest) =
            health_configuration_digest(command, interval, timeout, start_period, retries);
        Ok(Some(Self { mask, digest }))
    }

    fn to_json(&self) -> Value {
        json!({"mask": self.mask, "digest": self.digest})
    }

    fn from_json(value: &Value) -> Option<Self> {
        let Value::Object(value) = value else {
            return None;
        };
        if !exact_keys(value, &["mask", "digest"]) {
            return None;
        }
        let mask = u8::try_from(value.get("mask")?.as_u64()?).ok()?;
        let digest = value.get("digest")?.as_str()?.to_owned();
        (mask != 0 && mask & !Self::ALL == 0 && valid_digest(&digest))
            .then_some(Self { mask, digest })
    }

    pub(crate) fn matches_inspection(&self, bytes: &[u8]) -> bool {
        let Ok(Value::Object(health)) = serde_json::from_slice::<Value>(bytes) else {
            return false;
        };
        let command = if self.mask & Self::COMMAND != 0 {
            let Some(test) = health.get("Test").and_then(Value::as_array) else {
                return false;
            };
            let [Value::String(kind), Value::String(command)] = test.as_slice() else {
                return false;
            };
            if kind != "CMD-SHELL" {
                return false;
            }
            Some(command.as_str())
        } else {
            None
        };
        let field = |mask, name| {
            (self.mask & mask != 0)
                .then(|| health.get(name)?.as_u64())
                .flatten()
        };
        let interval = field(Self::INTERVAL, "Interval");
        let timeout = field(Self::TIMEOUT, "Timeout");
        let start_period = field(Self::START_PERIOD, "StartPeriod");
        let retries = field(Self::RETRIES, "Retries");
        if (self.mask & Self::INTERVAL != 0) != interval.is_some()
            || (self.mask & Self::TIMEOUT != 0) != timeout.is_some()
            || (self.mask & Self::START_PERIOD != 0) != start_period.is_some()
            || (self.mask & Self::RETRIES != 0) != retries.is_some()
        {
            return false;
        }
        let (mask, digest) =
            health_configuration_digest(command, interval, timeout, start_period, retries);
        mask == self.mask && digest == self.digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ServiceHealthExpectation {
    Image,
    Disabled,
    Override,
}

impl ServiceHealthExpectation {
    const fn from_policy(policy: &ServiceHealthPolicy) -> Self {
        match policy {
            ServiceHealthPolicy::Image => Self::Image,
            ServiceHealthPolicy::Disabled => Self::Disabled,
            ServiceHealthPolicy::Override(_) => Self::Override,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Disabled => "disabled",
            Self::Override => "override",
        }
    }

    const fn parse(value: &str) -> Option<Self> {
        match value.as_bytes() {
            b"image" => Some(Self::Image),
            b"disabled" => Some(Self::Disabled),
            b"override" => Some(Self::Override),
            _ => None,
        }
    }
}

fn duration_nanos(value: std::time::Duration) -> Result<u64, ()> {
    u64::try_from(value.as_nanos()).map_err(|_| ())
}

fn health_configuration_digest(
    command: Option<&str>,
    interval: Option<u64>,
    timeout: Option<u64>,
    start_period: Option<u64>,
    retries: Option<u64>,
) -> (u8, String) {
    let mut mask = 0_u8;
    let mut hasher = Sha256::new();
    hasher.update(b"automata-ci-service-health-v1");
    if let Some(value) = command {
        mask |= ServiceHealthConfiguration::COMMAND;
        hash_health_field(
            &mut hasher,
            ServiceHealthConfiguration::COMMAND,
            value.as_bytes(),
        );
    }
    for (field, value) in [
        (ServiceHealthConfiguration::INTERVAL, interval),
        (ServiceHealthConfiguration::TIMEOUT, timeout),
        (ServiceHealthConfiguration::START_PERIOD, start_period),
        (ServiceHealthConfiguration::RETRIES, retries),
    ] {
        if let Some(value) = value {
            mask |= field;
            hash_health_field(&mut hasher, field, &value.to_be_bytes());
        }
    }
    (
        mask,
        Sha256Digest::from_bytes(hasher.finalize().into()).to_string(),
    )
}

fn hash_health_field(hasher: &mut Sha256, field: u8, value: &[u8]) {
    hasher.update([field]);
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn exact_keys(object: &serde_json::Map<String, Value>, expected: &[&str]) -> bool {
    object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
}

fn valid_network_alias(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

const fn protocol_name(protocol: ServiceTransportProtocol) -> &'static str {
    match protocol {
        ServiceTransportProtocol::Tcp => "tcp",
        ServiceTransportProtocol::Udp => "udp",
    }
}

const fn parse_protocol(value: &str) -> Option<ServiceTransportProtocol> {
    match value.as_bytes() {
        b"tcp" => Some(ServiceTransportProtocol::Tcp),
        b"udp" => Some(ServiceTransportProtocol::Udp),
        _ => None,
    }
}
