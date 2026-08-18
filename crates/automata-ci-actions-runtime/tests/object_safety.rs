use automata_ci_actions_runtime::{
    ActionsCommandFileDecoder, ActionsCompletedStepApplicator, ActionsWorkflowCommandSession,
    CommandFileDecoder, CommandFileKind, CommandFilePlatform, CommandNotice,
    CompletedStepApplicator, WorkflowCommandEvent, WorkflowCommandProcessor, WorkflowLine,
};
use static_assertions::assert_impl_all;

assert_impl_all!(ActionsCommandFileDecoder: Send, Sync);
assert_impl_all!(ActionsCompletedStepApplicator: Send, Sync);
assert_impl_all!(ActionsWorkflowCommandSession: Send);

#[test]
fn ports_are_usable_through_trait_objects() {
    let decoder: Box<dyn CommandFileDecoder> = Box::new(ActionsCommandFileDecoder::default());
    let parsed_file = decoder
        .decode(
            CommandFileKind::Output,
            b"result=ok\n",
            CommandFilePlatform::Unix,
        )
        .expect("object-safe decoder");
    assert!(matches!(
        parsed_file,
        automata_ci_actions_runtime::ParsedCommandFile::Output(_)
    ));

    let mut processor: Box<dyn WorkflowCommandProcessor> =
        Box::new(ActionsWorkflowCommandSession::default());
    assert_eq!(
        processor
            .process_line(b"::add-matcher::")
            .expect("object-safe workflow-command processor"),
        WorkflowLine::Command(WorkflowCommandEvent::Notice(
            CommandNotice::MissingMatcherPath,
        ))
    );
    assert!(!processor.echo_enabled());
    assert!(!processor.commands_stopped());

    let applicator: Box<dyn CompletedStepApplicator> =
        Box::new(ActionsCompletedStepApplicator::default());
    let _ = applicator;
}
