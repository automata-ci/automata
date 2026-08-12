use std::{convert::Infallible, sync::Arc};

pub(crate) use crate::docker_contract::{DOCKER_SOCKET_DIRECTORY_TARGET, JobDockerLaunch};

use crate::{PodmanConfigurationError, PodmanObserver, PodmanOptions, state::JobEnginePaths};

#[derive(Debug)]
pub(crate) struct JobDockerListener;

pub(crate) fn bind_public_socket(
    _path: &std::path::Path,
) -> Result<JobDockerListener, PodmanConfigurationError> {
    Err(PodmanConfigurationError::UnsupportedPlatform)
}

#[derive(Debug)]
pub(crate) struct JobDockerService(Box<Infallible>);

impl JobDockerService {
    pub(crate) fn start(
        _options: &PodmanOptions,
        _paths: &JobEnginePaths,
        _listener: JobDockerListener,
        launch: JobDockerLaunch<'_>,
        _observer: Arc<dyn PodmanObserver>,
    ) -> Result<Self, PodmanConfigurationError> {
        let JobDockerLaunch {
            sandbox,
            outer_process_id,
            outer_cgroup,
            resources,
        } = launch;
        let _ = (sandbox, outer_process_id, outer_cgroup, resources);
        Err(PodmanConfigurationError::UnsupportedPlatform)
    }

    pub(crate) fn stop(&mut self) {
        match *self.0 {}
    }
}
