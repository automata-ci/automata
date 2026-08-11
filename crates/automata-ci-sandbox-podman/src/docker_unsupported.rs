// These methods intentionally mirror the Linux adapter so shared provider code
// retains one closed interface while every operation fails unsupported.
#![allow(clippy::unused_self)]

use std::sync::Arc;

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
pub(crate) struct JobDockerService;

impl JobDockerService {
    pub(crate) fn start(
        _options: &PodmanOptions,
        _paths: &JobEnginePaths,
        _listener: JobDockerListener,
        _launch: JobDockerLaunch<'_>,
        _observer: Arc<dyn PodmanObserver>,
    ) -> Result<Self, PodmanConfigurationError> {
        Err(PodmanConfigurationError::UnsupportedPlatform)
    }

    pub(crate) fn stop(&mut self) {}
}
