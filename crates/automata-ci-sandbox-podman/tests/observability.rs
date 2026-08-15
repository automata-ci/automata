#![cfg(target_os = "linux")]

use crate::support;

use std::sync::{Arc, Mutex, PoisonError};

use automata_ci_execution::{
    EnvironmentName, EnvironmentValue, EnvironmentVariable, ExecutionArgv, ExecutionCommand,
    ExecutionEnvironment, ExecutionErrorKind, ExecutionStage, NeverCancelled, OperationId,
    SandboxProvider, TargetPath,
};
use automata_ci_sandbox_podman::{
    CommandOutput, CommandTermination, PodmanCommandExecutor, PodmanCommandOutcome,
    PodmanCommandStage, PodmanEvent, PodmanObserver, RootlessPodmanProvider,
};
use static_assertions::assert_obj_safe;
use support::{FakePodman, ScratchRoot, options, sample_spec};

assert_obj_safe!(PodmanObserver);

#[derive(Debug, Default)]
struct CapturingObserver {
    events: Mutex<Vec<PodmanEvent>>,
}

impl CapturingObserver {
    fn events(&self) -> Vec<PodmanEvent> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl PodmanObserver for CapturingObserver {
    fn observe(&self, event: PodmanEvent) {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(event);
    }
}

#[test]
fn every_local_command_has_one_typed_identifier_free_terminal_event() {
    let scratch = ScratchRoot::new("observability");
    let fake = Arc::new(FakePodman::default());
    let observer = Arc::new(CapturingObserver::default());
    let provider = RootlessPodmanProvider::open_with_executor_and_observer(
        options(scratch.path()),
        fake as Arc<dyn PodmanCommandExecutor>,
        observer.clone(),
    )
    .expect("open observed fake provider");
    let spec = sample_spec(OperationId::new());
    let created = provider
        .create(&spec, &NeverCancelled)
        .expect("create sandbox through observed commands");
    provider
        .inspect(created.handle(), &NeverCancelled)
        .expect("inspect sandbox through observed commands");

    let events = observer.events();
    let starts = events
        .iter()
        .filter(|event| matches!(event, PodmanEvent::CommandStarted { .. }))
        .count();
    let completions = events
        .iter()
        .filter(|event| matches!(event, PodmanEvent::CommandCompleted { .. }))
        .count();
    assert!(starts > 0);
    assert_eq!(starts, completions);
    assert!(events.iter().any(|event| matches!(
        event,
        PodmanEvent::CommandCompleted {
            outcome: PodmanCommandOutcome::Success,
            ..
        }
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        PodmanEvent::CommandCompleted {
            outcome: PodmanCommandOutcome::NonzeroExit,
            ..
        }
    )));
    let debug = format!("{events:?}");
    assert!(!debug.contains(created.handle().opaque()));
    assert!(!debug.contains("arguments"));
    assert!(!debug.contains("/usr/bin/podman"));
    assert!(!debug.contains("operation_id"));
}

#[test]
fn exited_zero_with_incomplete_environment_input_is_never_observed_as_success() {
    let scratch = ScratchRoot::new("observability-incomplete-input");
    let fake = Arc::new(FakePodman::default());
    let observer = Arc::new(CapturingObserver::default());
    let provider = RootlessPodmanProvider::open_with_executor_and_observer(
        options(scratch.path()),
        fake.clone() as Arc<dyn PodmanCommandExecutor>,
        observer.clone(),
    )
    .expect("open observed fake provider");
    let created = provider
        .create(&sample_spec(OperationId::new()), &NeverCancelled)
        .expect("create observed sandbox");
    let endpoint = provider
        .attach(created.handle(), &NeverCancelled)
        .expect("attach observed sandbox");
    fake.set_exec_output(CommandOutput::terminated_with_incomplete_stdin(
        CommandTermination::Exited(Some(0)),
    ));
    let environment = ExecutionEnvironment::new(vec![EnvironmentVariable::secret(
        EnvironmentName::new("TOKEN").expect("environment name"),
        EnvironmentValue::new("observation-sentinel").expect("environment value"),
    )])
    .expect("execution environment");
    let command = ExecutionCommand::new(
        OperationId::new(),
        ExecutionArgv::new(TargetPath::posix("/bin/true").expect("program"), Vec::new())
            .expect("argv"),
        TargetPath::posix("/__w").expect("working directory"),
        environment,
        std::time::Duration::from_secs(1),
        1_024,
    )
    .expect("execution command");

    let error = endpoint
        .exec(&command, &NeverCancelled)
        .expect_err("incomplete environment input must fail closed");
    assert_eq!(error.kind(), ExecutionErrorKind::BackendRejected);
    assert!(observer.events().iter().any(|event| matches!(
        event,
        PodmanEvent::CommandCompleted {
            stage: PodmanCommandStage::Endpoint(ExecutionStage::Exec),
            outcome: PodmanCommandOutcome::InputIncomplete,
            ..
        }
    )));
    assert!(!observer.events().iter().any(|event| matches!(
        event,
        PodmanEvent::CommandCompleted {
            stage: PodmanCommandStage::Endpoint(ExecutionStage::Exec),
            outcome: PodmanCommandOutcome::Success,
            ..
        }
    )));
    assert!(!format!("{:?}", observer.events()).contains("observation-sentinel"));
}
