use automata_ci_execution::{ResourceLimits, SandboxHandle};

use crate::{PodmanConfigurationError, PodmanOptions, state::JobEnginePaths};

pub(crate) const DOCKER_SOCKET_DIRECTORY_TARGET: &str = "/run/automata-engine";

#[derive(Debug)]
pub(crate) struct JobDockerListener;

pub(crate) fn bind_public_socket(
    _path: &std::path::Path,
) -> Result<JobDockerListener, PodmanConfigurationError> {
    Err(PodmanConfigurationError::UnsupportedPlatform)
}

#[derive(Debug)]
pub(crate) struct JobDockerService;

impl JobDockerService {
    pub(crate) fn start(
        _options: &PodmanOptions,
        _paths: &JobEnginePaths,
        _listener: JobDockerListener,
        _sandbox: &SandboxHandle,
        _outer_process_id: u32,
        _outer_cgroup: String,
        _resources: ResourceLimits,
    ) -> Result<Self, PodmanConfigurationError> {
        Err(PodmanConfigurationError::UnsupportedPlatform)
    }

    pub(crate) fn stop(&mut self) {}
}
