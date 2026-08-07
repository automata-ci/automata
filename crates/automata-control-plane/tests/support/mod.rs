#![allow(dead_code)]

use std::{fmt::Debug, str::FromStr};

use automata_control_plane::{
    AuthorizedRunnerRouting, EffectiveRunner, RoutingRequirements, RunnableCandidate,
    RunnerEvidence, RunnerSlot, SessionGuard,
};
use automata_core::{
    Architecture, AttemptId, ContainerCapabilities, ContainerFeature, JobId, OperatingSystem,
    OperationId, ResourceCapacity, RunnerCapabilities, RunnerFeature, RunnerGroup, RunnerId,
    RunnerLabel, RunnerPlatform, RunnerRequirements, RunnerSessionId, SandboxCapabilities,
    SandboxFeature, UnixMillis,
};

pub fn typed_id<T>(tail: u64) -> T
where
    T: FromStr,
    T::Err: Debug,
{
    format!("00000000-0000-0000-0000-{tail:012x}")
        .parse()
        .expect("test UUID must be valid")
}

pub fn runner_id(tail: u64) -> RunnerId {
    typed_id(tail)
}

pub fn session_id(tail: u64) -> RunnerSessionId {
    typed_id(10_000 + tail)
}

pub fn attempt_id(tail: u64) -> AttemptId {
    typed_id(20_000 + tail)
}

pub fn job_id(tail: u64) -> JobId {
    typed_id(30_000 + tail)
}

pub fn operation_id(tail: u64) -> OperationId {
    typed_id(40_000 + tail)
}

pub fn label(value: &str) -> RunnerLabel {
    RunnerLabel::new(value).expect("test label must be valid")
}

pub fn group(value: &str) -> RunnerGroup {
    RunnerGroup::new(value).expect("test group must be valid")
}

pub fn observed_capabilities(runner_id: RunnerId, maximum_slots: u16) -> RunnerCapabilities {
    RunnerCapabilities::new(
        runner_id,
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
    )
    .with_max_parallel_jobs(maximum_slots)
    .expect("test runner must advertise slots")
    .with_resources_per_job(ResourceCapacity::new(
        4_000,
        8 * 1024 * 1024 * 1024,
        50 * 1024 * 1024 * 1024,
        1,
    ))
    .with_sandbox(SandboxCapabilities::new(
        automata_core::IsolationLevel::SharedKernel,
        [
            SandboxFeature::CLEAN_WORKSPACE,
            SandboxFeature::NETWORK_ISOLATION,
        ],
    ))
    .with_containers(ContainerCapabilities::new([
        ContainerFeature::JOB_CONTAINERS,
        ContainerFeature::CONTAINER_ACTIONS,
    ]))
    .with_features([RunnerFeature::SHELL_STEPS, RunnerFeature::COMPOSITE_ACTIONS])
}

pub fn effective_runner(
    tail: u64,
    labels: &[&str],
    groups: &[&str],
    available_ordinals: &[u16],
) -> EffectiveRunner {
    let runner_id = runner_id(tail);
    let observed = observed_capabilities(runner_id, 4);
    let evidence = RunnerEvidence::new(
        SessionGuard::new(runner_id, session_id(tail)),
        observed,
        UnixMillis::new(1_000),
    )
    .expect("test evidence must be valid");
    let effective = observed_capabilities(runner_id, 4);
    let routing = AuthorizedRunnerRouting::new(
        labels.iter().map(|value| label(value)),
        groups.iter().map(|value| group(value)),
    );
    let slots = available_ordinals.iter().map(|ordinal| {
        RunnerSlot::new(runner_id, *ordinal).expect("test slot ordinal must be valid")
    });
    EffectiveRunner::authorize(&evidence, routing, effective, slots)
        .expect("test effective runner must be valid")
}

pub fn routing(labels: &[&str]) -> RoutingRequirements {
    RoutingRequirements::new(
        RunnerRequirements::default()
            .with_labels(labels.iter().map(|value| label(value)))
            .with_operating_system(OperatingSystem::Linux)
            .with_architecture(Architecture::X86_64),
    )
    .expect("test routing requirements must be valid")
}

pub fn candidate(tail: u64, queued_at: i64, labels: &[&str]) -> RunnableCandidate {
    RunnableCandidate::new(
        attempt_id(tail),
        job_id(tail),
        UnixMillis::new(queued_at),
        routing(labels),
    )
}
