use automata_ci_github_runtime::{
    ActionInvocationId, CommandFileDecoder, CommandFileKind, CommandFilePlatform,
    CompletedStepApplicator, CompletedStepCommands, GithubCommandFileDecoder,
    GithubCompletedStepApplicator, JobCommandState, ParsedCommandFile, PhaseApplicationNotice,
    StepId, StepPhase, StepScope,
};

fn commands(
    environment: &[u8],
    output: &[u8],
    path: &[u8],
    state: &[u8],
    summary: &[u8],
) -> CompletedStepCommands {
    let parser = GithubCommandFileDecoder::default();
    let ParsedCommandFile::Environment(environment) = parser
        .decode(
            CommandFileKind::Environment,
            environment,
            CommandFilePlatform::Unix,
        )
        .expect("valid environment file")
    else {
        panic!("wrong environment kind");
    };
    let ParsedCommandFile::Output(output) = parser
        .decode(CommandFileKind::Output, output, CommandFilePlatform::Unix)
        .expect("valid output file")
    else {
        panic!("wrong output kind");
    };
    let ParsedCommandFile::Path(path) = parser
        .decode(CommandFileKind::Path, path, CommandFilePlatform::Unix)
        .expect("valid PATH file")
    else {
        panic!("wrong PATH kind");
    };
    let ParsedCommandFile::State(state) = parser
        .decode(CommandFileKind::State, state, CommandFilePlatform::Unix)
        .expect("valid state file")
    else {
        panic!("wrong state kind");
    };
    let ParsedCommandFile::StepSummary(summary) = parser
        .decode(
            CommandFileKind::StepSummary,
            summary,
            CommandFilePlatform::Unix,
        )
        .expect("valid summary file")
    else {
        panic!("wrong summary kind");
    };
    CompletedStepCommands::new(environment, output, path, state, summary)
}

fn value<'a>(
    values: &'a [automata_ci_github_runtime::NameValueCommand],
    name: &str,
) -> Option<&'a str> {
    values
        .iter()
        .find(|value| value.name() == name)
        .map(automata_ci_github_runtime::NameValueCommand::value)
}

#[test]
fn completed_step_boundary_delays_environment_and_path_but_scopes_outputs() {
    let initial = JobCommandState::new(CommandFilePlatform::Unix);
    let step_id = StepId::new("compile").expect("valid step ID");
    let scope = StepScope::new(step_id.clone(), StepPhase::Run);
    let files = commands(
        b"MODE=release\n",
        b"artifact=target/app\n",
        b"/one\n/two\n",
        b"",
        b"## compile\n",
    );

    assert!(initial.environment().is_empty());
    assert!(initial.prepend_path().next().is_none());
    assert!(initial.outputs(&step_id).is_none());

    let applied = GithubCompletedStepApplicator::default()
        .apply_completed_step(&initial, &scope, &files)
        .expect("bounded state");
    let next = applied.next_state();
    assert_eq!(value(next.environment(), "MODE"), Some("release"));
    assert_eq!(next.prepend_path().collect::<Vec<_>>(), ["/two", "/one"]);
    assert_eq!(
        value(next.outputs(&step_id).expect("step outputs"), "artifact"),
        Some("target/app")
    );
    assert_eq!(applied.summary().markdown(), "## compile\n");

    // Application is immutable: the state used to launch the completed step
    // still has none of its own mutations.
    assert!(initial.environment().is_empty());
    assert!(initial.outputs(&step_id).is_none());
}

#[test]
fn action_state_is_visible_only_to_the_exact_paired_post_action() {
    let invocation = ActionInvocationId::new("checkout-main-42").expect("valid invocation ID");
    let other = ActionInvocationId::new("checkout-main-43").expect("valid invocation ID");
    let scope = StepScope::new(
        StepId::new("checkout").expect("valid step ID"),
        StepPhase::ActionMain(invocation.clone()),
    );
    let files = commands(b"", b"", b"", b"repository=/work/repo\n", b"");
    let next = GithubCompletedStepApplicator::default()
        .apply_completed_step(
            &JobCommandState::new(CommandFilePlatform::Unix),
            &scope,
            &files,
        )
        .expect("bounded state")
        .into_next_state();

    let post_environment = next.post_action_environment(&invocation);
    assert_eq!(
        value(&post_environment, "STATE_repository"),
        Some("/work/repo")
    );
    assert!(next.post_action_environment(&other).is_empty());
    assert_eq!(value(next.environment(), "STATE_repository"), None);
}

#[test]
fn action_pre_applies_job_and_invocation_state_without_publishing_outputs() {
    let invocation = ActionInvocationId::new("setup-42").expect("valid invocation ID");
    let step_id = StepId::new("setup").expect("valid step ID");
    let applied = GithubCompletedStepApplicator::default()
        .apply_completed_step(
            &JobCommandState::new(CommandFilePlatform::Unix),
            &StepScope::new(step_id.clone(), StepPhase::ActionPre(invocation.clone())),
            &commands(
                b"MODE=ready\n",
                b"must_not_escape=pre\n",
                b"/from-pre\n",
                b"saved=value\n",
                b"pre summary\n",
            ),
        )
        .expect("bounded pre state");
    let next = applied.next_state();

    assert_eq!(value(next.environment(), "MODE"), Some("ready"));
    assert_eq!(next.prepend_path().collect::<Vec<_>>(), ["/from-pre"]);
    assert!(next.outputs(&step_id).is_none());
    assert_eq!(
        value(&next.post_action_environment(&invocation), "STATE_saved"),
        Some("value")
    );
    assert_eq!(applied.summary().markdown(), "pre summary\n");
}

#[test]
fn action_post_preserves_main_outputs_and_merges_exact_updates() {
    let invocation = ActionInvocationId::new("artifact-main-42").expect("valid invocation ID");
    let step_id = StepId::new("artifact").expect("valid step ID");
    let initial = JobCommandState::new(CommandFilePlatform::Unix);
    let main = GithubCompletedStepApplicator::default()
        .apply_completed_step(
            &initial,
            &StepScope::new(step_id.clone(), StepPhase::ActionMain(invocation.clone())),
            &commands(b"", b"url=main\ndigest=one\n", b"", b"", b""),
        )
        .expect("bounded main state")
        .into_next_state();

    let empty_post = GithubCompletedStepApplicator::default()
        .apply_completed_step(
            &main,
            &StepScope::new(step_id.clone(), StepPhase::ActionPost(invocation.clone())),
            &commands(b"", b"", b"", b"", b""),
        )
        .expect("bounded empty post state")
        .into_next_state();
    assert_eq!(
        value(empty_post.outputs(&step_id).expect("main outputs"), "url"),
        Some("main")
    );

    let updated_post = GithubCompletedStepApplicator::default()
        .apply_completed_step(
            &main,
            &StepScope::new(step_id.clone(), StepPhase::ActionPost(invocation)),
            &commands(b"", b"URL=post\nextra=two\n", b"", b"", b""),
        )
        .expect("bounded updated post state")
        .into_next_state();
    let outputs = updated_post.outputs(&step_id).expect("merged outputs");
    assert_eq!(value(outputs, "url"), Some("post"));
    assert_eq!(value(outputs, "digest"), Some("one"));
    assert_eq!(value(outputs, "extra"), Some("two"));
}

#[test]
fn run_step_state_is_ignored_and_node_options_is_blocked() {
    let files = commands(
        b"NODE_OPTIONS=--require=payload\nSAFE=yes\n",
        b"",
        b"",
        b"private=state\n",
        b"",
    );
    let applied = GithubCompletedStepApplicator::default()
        .apply_completed_step(
            &JobCommandState::new(CommandFilePlatform::Unix),
            &StepScope::new(
                StepId::new("script").expect("valid step ID"),
                StepPhase::Run,
            ),
            &files,
        )
        .expect("bounded state");

    assert_eq!(
        value(applied.next_state().environment(), "SAFE"),
        Some("yes")
    );
    assert_eq!(
        value(applied.next_state().environment(), "NODE_OPTIONS"),
        None
    );
    assert_eq!(
        applied.notices(),
        [
            PhaseApplicationNotice::BlockedNodeOptions,
            PhaseApplicationNotice::StateIgnoredForRunStep,
        ]
    );
}

#[test]
fn environment_key_semantics_follow_target_platform() {
    let first = commands(b"Name=one\n", b"", b"", b"", b"");
    let second = commands(b"NAME=two\n", b"", b"", b"", b"");
    let applicator = GithubCompletedStepApplicator::default();
    let scope_one = StepScope::new(StepId::new("one").expect("valid step ID"), StepPhase::Run);
    let scope_two = StepScope::new(StepId::new("two").expect("valid step ID"), StepPhase::Run);

    let unix = applicator
        .apply_completed_step(
            &JobCommandState::new(CommandFilePlatform::Unix),
            &scope_one,
            &first,
        )
        .expect("bounded state")
        .into_next_state();
    let unix = applicator
        .apply_completed_step(&unix, &scope_two, &second)
        .expect("bounded state")
        .into_next_state();
    assert_eq!(unix.environment().len(), 2);

    let windows = applicator
        .apply_completed_step(
            &JobCommandState::new(CommandFilePlatform::Windows),
            &scope_one,
            &first,
        )
        .expect("bounded state")
        .into_next_state();
    let windows = applicator
        .apply_completed_step(&windows, &scope_two, &second)
        .expect("bounded state")
        .into_next_state();
    assert_eq!(windows.environment().len(), 1);
    // Ordinal-ignore-case dictionaries retain the first key's spelling when
    // a later assignment replaces its value.
    assert_eq!(windows.environment()[0].name(), "Name");
    assert_eq!(windows.environment()[0].value(), "two");
}
