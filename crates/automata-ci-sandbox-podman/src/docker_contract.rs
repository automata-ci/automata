use automata_ci_execution::{ResourceLimits, SandboxHandle};

pub(crate) const DOCKER_SOCKET_DIRECTORY_TARGET: &str = "/run/automata-engine";

pub(crate) struct JobDockerLaunch<'a> {
    pub(crate) sandbox: &'a SandboxHandle,
    pub(crate) outer_process_id: u32,
    pub(crate) outer_cgroup: String,
    pub(crate) resources: ResourceLimits,
}

impl<'a> JobDockerLaunch<'a> {
    pub(crate) const fn new(
        sandbox: &'a SandboxHandle,
        outer_process_id: u32,
        outer_cgroup: String,
        resources: ResourceLimits,
    ) -> Self {
        Self {
            sandbox,
            outer_process_id,
            outer_cgroup,
            resources,
        }
    }
}
