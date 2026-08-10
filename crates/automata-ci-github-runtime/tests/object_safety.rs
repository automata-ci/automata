use automata_ci_github_runtime::{
    CommandFileDecoder, CommandFileKind, CommandFilePlatform, CompletedStepApplicator,
    GithubCommandFileDecoder, GithubCompletedStepApplicator, GithubWorkflowCommandSession,
    WorkflowCommandProcessor,
};
use static_assertions::assert_impl_all;

assert_impl_all!(GithubCommandFileDecoder: Send, Sync);
assert_impl_all!(GithubCompletedStepApplicator: Send, Sync);
assert_impl_all!(GithubWorkflowCommandSession: Send);

#[test]
fn ports_are_object_safe() {
    let decoder: Box<dyn CommandFileDecoder> = Box::new(GithubCommandFileDecoder::default());
    let parsed_file = decoder
        .decode(
            CommandFileKind::Output,
            b"result=ok\n",
            CommandFilePlatform::Unix,
        )
        .expect("object-safe decoder");
    assert!(matches!(
        parsed_file,
        automata_ci_github_runtime::ParsedCommandFile::Output(_)
    ));

    let mut processor: Box<dyn WorkflowCommandProcessor> =
        Box::new(GithubWorkflowCommandSession::default());
    assert!(processor.process_line(b"::debug::message").is_ok());

    let applicator: Box<dyn CompletedStepApplicator> =
        Box::new(GithubCompletedStepApplicator::default());
    let _ = applicator;
}
