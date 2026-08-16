use std::{collections::BTreeSet, time::Duration};

use automata_ci_core::JobIrEnvelope;
use automata_ci_execution::{
    ExecutionEnvironment, ImmutableImage, NetworkPolicy, ProviderCapabilities, ResourceLimits,
    RootFilesystemPolicy, SandboxCapability, SandboxGeneration, SandboxLaunch,
    SandboxPrivilegePolicy, SandboxSpec, ServiceContainerBindings, ServiceContainerSpec,
    ServiceContainerSpecs, ServiceHealthOverrides, ServiceHealthPolicy, ServicePort,
    ServiceTransportProtocol, TargetPath,
};
use automata_ci_runner_runtime::{AdmissionRejection, ExecutionRequest};

use crate::{
    GithubJobExecutorConfig,
    error::{ExecutorAdapterError, ExecutorAdapterErrorKind},
};

pub(super) fn service_image(
    service: &automata_ci_core::ContainerSpec,
) -> Result<ImmutableImage, ExecutorAdapterError> {
    ImmutableImage::new(service.image()).map_err(|_| invalid_job())
}

pub(super) fn service_ports(
    service: &automata_ci_core::ContainerSpec,
) -> Result<Vec<ServicePort>, ExecutorAdapterError> {
    service
        .ports()
        .iter()
        .map(|port| {
            let protocol = match port.protocol() {
                automata_ci_core::TransportProtocol::Tcp => ServiceTransportProtocol::Tcp,
                automata_ci_core::TransportProtocol::Udp => ServiceTransportProtocol::Udp,
            };
            ServicePort::new(port.container_port(), port.requested_host_port(), protocol)
                .map_err(|_| invalid_job())
        })
        .collect()
}

pub(super) fn service_health_policy(
    options: &[String],
) -> Result<ServiceHealthPolicy, ExecutorAdapterError> {
    if options.is_empty() {
        return Ok(ServiceHealthPolicy::Image);
    }
    let mut command = None;
    let mut interval = None;
    let mut timeout = None;
    let mut start_period = None;
    let mut retries = None;
    let mut disabled = false;
    let mut seen = BTreeSet::new();
    let mut index = 0;
    while index < options.len() {
        let token = &options[index];
        if token == "--no-healthcheck" {
            if !seen.insert("disabled") {
                return Err(invalid_service());
            }
            disabled = true;
            index += 1;
            continue;
        }
        let (name, inline) = token
            .split_once('=')
            .map_or((token.as_str(), None), |(name, value)| (name, Some(value)));
        let field = match name {
            "--health-cmd" => "command",
            "--health-interval" => "interval",
            "--health-timeout" => "timeout",
            "--health-start-period" => "start_period",
            "--health-retries" => "retries",
            _ => return Err(invalid_service()),
        };
        if !seen.insert(field) {
            return Err(invalid_service());
        }
        let value = if let Some(value) = inline {
            value
        } else {
            index += 1;
            options
                .get(index)
                .map(String::as_str)
                .ok_or_else(invalid_service)?
        };
        if value.is_empty() {
            return Err(invalid_service());
        }
        match field {
            "command" => command = Some(value.to_owned()),
            "interval" => interval = Some(parse_container_duration(value)?),
            "timeout" => timeout = Some(parse_container_duration(value)?),
            "start_period" => start_period = Some(parse_container_duration(value)?),
            "retries" => {
                retries = Some(value.parse::<u32>().map_err(|_| invalid_service())?);
            }
            _ => return Err(invalid_service()),
        }
        index += 1;
    }
    if disabled || command.as_deref() == Some("none") {
        if seen.len() != 1 {
            return Err(invalid_service());
        }
        return Ok(ServiceHealthPolicy::Disabled);
    }
    ServiceHealthOverrides::new(command, interval, timeout, start_period, retries)
        .map(ServiceHealthPolicy::Override)
        .map_err(|_| invalid_service())
}

pub(super) fn service_spec(
    image: ImmutableImage,
    environment: ExecutionEnvironment,
    ports: Vec<ServicePort>,
    health: ServiceHealthPolicy,
) -> Result<ServiceContainerSpec, ExecutorAdapterError> {
    ServiceContainerSpec::new(image, environment)
        .with_ports(ports)
        .map_err(|_| invalid_job())
        .map(|spec| spec.with_health(health))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn sandbox_spec(
    config: &GithubJobExecutorConfig,
    request: &ExecutionRequest,
    operation_id: automata_ci_core::OperationId,
    generation: SandboxGeneration,
    workspace: &TargetPath,
    scratch: &TargetPath,
    service_specs: &ServiceContainerSpecs,
) -> Result<SandboxSpec, ExecutorAdapterError> {
    if matches!(
        request.environment().launch(),
        SandboxLaunch::WindowsHyperVContainer { .. }
    ) && !valid_windows_hyperv_contract(config, service_specs)
    {
        return Err(invalid_job());
    }
    let resources = sandbox_resources(config, request)?;
    let mut spec = SandboxSpec::new(
        operation_id,
        generation,
        request.sandbox_custody(),
        request.environment().clone(),
        workspace.clone(),
        config.network(),
        config.root_filesystem(),
        resources,
    )
    .with_privilege(config.privilege())
    .with_services(service_specs.clone())
    .with_resource_allocation(
        request
            .job()
            .job()
            .requirements()
            .resource_allocation()
            .ok_or_else(invalid_job)?,
    );
    if matches!(
        request.environment().launch(),
        SandboxLaunch::VirtualMachine { .. }
    ) {
        spec = spec.with_scratch(scratch.clone());
    }
    Ok(spec)
}

fn valid_windows_hyperv_contract(
    config: &GithubJobExecutorConfig,
    service_specs: &ServiceContainerSpecs,
) -> bool {
    config.network() == NetworkPolicy::Disabled
        && config.root_filesystem() == RootFilesystemPolicy::Writable
        && config.privilege() == SandboxPrivilegePolicy::Unprivileged
        && service_specs.is_empty()
}

pub(super) fn sandbox_resources(
    config: &GithubJobExecutorConfig,
    request: &ExecutionRequest,
) -> Result<ResourceLimits, ExecutorAdapterError> {
    let allocation = request
        .job()
        .job()
        .requirements()
        .resource_allocation()
        .ok_or_else(invalid_job)?;
    let limits = allocation.limits();
    ResourceLimits::new(
        limits.memory_bytes(),
        limits.cpu_millis(),
        config.resources().pids(),
    )
    .map_err(|_| invalid_job())
}

pub(super) fn validate_service_admission(
    job: &JobIrEnvelope,
    capabilities: &ProviderCapabilities,
) -> Result<(), AdmissionRejection> {
    if job.job().services().is_empty() {
        return Ok(());
    }
    if !capabilities.supports(SandboxCapability::ServiceContainers) {
        return Err(AdmissionRejection::CapabilityChanged);
    }
    let declarations = job
        .job()
        .services()
        .iter()
        .map(|(name, service)| {
            if service.credentials().is_some() || !service.volumes().is_empty() {
                return Err(());
            }
            let image = service_image(service).map_err(|_| ())?;
            let ports = service_ports(service).map_err(|_| ())?;
            let health = service_health_policy(service.options()).map_err(|_| ())?;
            let spec = service_spec(image, ExecutionEnvironment::empty(), ports, health)
                .map_err(|_| ())?;
            Ok((name.clone(), spec))
        })
        .collect::<Result<std::collections::BTreeMap<_, _>, ()>>();
    if declarations
        .ok()
        .and_then(|values| ServiceContainerSpecs::new(values).ok())
        .is_none()
    {
        return Err(AdmissionRejection::InvalidJob);
    }
    Ok(())
}

pub(super) fn validate_service_bindings(
    specs: &ServiceContainerSpecs,
    bindings: &ServiceContainerBindings,
) -> Result<(), ExecutorAdapterError> {
    if specs.len() != bindings.len() {
        return Err(internal());
    }
    for (name, spec) in specs.iter() {
        let binding = bindings.get(name).ok_or_else(internal)?;
        let expected = spec.ports().iter().copied().collect::<BTreeSet<_>>();
        let actual = binding
            .ports()
            .iter()
            .map(|port| port.service_port())
            .collect::<BTreeSet<_>>();
        if expected != actual {
            return Err(internal());
        }
    }
    Ok(())
}

fn parse_container_duration(value: &str) -> Result<Duration, ExecutorAdapterError> {
    if value.is_empty() || !value.is_ascii() {
        return Err(invalid_service());
    }
    let bytes = value.as_bytes();
    let mut index = 0;
    let mut total = Duration::ZERO;
    while index < bytes.len() {
        let number_start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if number_start == index {
            return Err(invalid_service());
        }
        let number = value[number_start..index]
            .parse::<u64>()
            .map_err(|_| invalid_service())?;
        let remaining = &value[index..];
        let (unit, duration) = if remaining.starts_with("ms") {
            (2, Duration::from_millis(number))
        } else if remaining.starts_with("us") {
            (2, Duration::from_micros(number))
        } else if remaining.starts_with("ns") {
            (2, Duration::from_nanos(number))
        } else if remaining.starts_with('h') {
            (
                1,
                Duration::from_secs(number.checked_mul(3_600).ok_or_else(invalid_service)?),
            )
        } else if remaining.starts_with('m') {
            (
                1,
                Duration::from_secs(number.checked_mul(60).ok_or_else(invalid_service)?),
            )
        } else if remaining.starts_with('s') {
            (1, Duration::from_secs(number))
        } else {
            return Err(invalid_service());
        };
        index += unit;
        total = total.checked_add(duration).ok_or_else(invalid_service)?;
    }
    if total.is_zero() {
        return Err(invalid_service());
    }
    Ok(total)
}

const fn internal() -> ExecutorAdapterError {
    ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal)
}

const fn invalid_job() -> ExecutorAdapterError {
    ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob)
}

const fn invalid_service() -> ExecutorAdapterError {
    ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn config(
        network: NetworkPolicy,
        root_filesystem: RootFilesystemPolicy,
        privilege: SandboxPrivilegePolicy,
    ) -> GithubJobExecutorConfig {
        GithubJobExecutorConfig::new(
            ResourceLimits::new(256 * 1024 * 1024, 1_000, 8).expect("resource limits"),
            network,
            root_filesystem,
            privilege,
            Duration::from_secs(1),
            1024,
            TargetPath::windows(r"C:\automata\runner").expect("runner root"),
        )
        .expect("executor config")
    }

    #[test]
    fn windows_hyperv_policy_has_no_weaker_executor_fallback() {
        let services = ServiceContainerSpecs::empty();
        assert!(valid_windows_hyperv_contract(
            &config(
                NetworkPolicy::Disabled,
                RootFilesystemPolicy::Writable,
                SandboxPrivilegePolicy::Unprivileged,
            ),
            &services,
        ));
        for candidate in [
            config(
                NetworkPolicy::Host,
                RootFilesystemPolicy::Writable,
                SandboxPrivilegePolicy::Unprivileged,
            ),
            config(
                NetworkPolicy::Disabled,
                RootFilesystemPolicy::Host,
                SandboxPrivilegePolicy::Unprivileged,
            ),
            config(
                NetworkPolicy::Disabled,
                RootFilesystemPolicy::Writable,
                SandboxPrivilegePolicy::Host,
            ),
        ] {
            assert!(!valid_windows_hyperv_contract(&candidate, &services));
        }

        let service = ServiceContainerSpec::new(
            ImmutableImage::new(format!(
                "registry.example/service@sha256:{}",
                "a".repeat(64)
            ))
            .expect("service image"),
            ExecutionEnvironment::empty(),
        );
        let services = ServiceContainerSpecs::new(BTreeMap::from([("database".into(), service)]))
            .expect("service set");
        assert!(!valid_windows_hyperv_contract(
            &config(
                NetworkPolicy::Disabled,
                RootFilesystemPolicy::Writable,
                SandboxPrivilegePolicy::Unprivileged,
            ),
            &services,
        ));
    }
}
