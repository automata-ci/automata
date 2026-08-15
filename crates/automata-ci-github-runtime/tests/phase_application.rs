use automata_ci_github_runtime::{
    ActionInvocationId, CommandFileDecoder, CommandFileKind, CommandFilePlatform,
    CompletedStepApplicator, CompletedStepCommands, EnvironmentMutationBlockReason,
    GithubCommandFileDecoder, GithubCompletedStepApplicator, GithubWorkflowCommandSession,
    JobCommandState, LegacyStepMutation, ParsedCommandFile, PhaseApplicationNotice,
    ReservedEnvironmentNamespace, StepId, StepPhase, StepScope, WorkflowCommandEvent,
    WorkflowCommandLimits, WorkflowCommandPolicy, WorkflowCommandProcessor, WorkflowLine,
    classify_environment_mutation,
};

const GITHUB_PROTECTED_ENVIRONMENT_NAMES: &[&str] = &[
    "GITHUB_ACTION",
    "GITHUB_ACTION_PATH",
    "GITHUB_ACTION_REF",
    "GITHUB_ACTION_REPOSITORY",
    "GITHUB_ACTIONS",
    "GITHUB_ACTOR",
    "GITHUB_ACTOR_ID",
    "GITHUB_API_URL",
    "GITHUB_ARTIFACTS",
    "GITHUB_ARTIFACTS_LIST",
    "GITHUB_BASE_REF",
    "GITHUB_ENV",
    "GITHUB_EVENT_NAME",
    "GITHUB_EVENT_PATH",
    "GITHUB_GRAPHQL_URL",
    "GITHUB_HEAD_REF",
    "GITHUB_JOB",
    "GITHUB_OUTPUT",
    "GITHUB_PATH",
    "GITHUB_REF",
    "GITHUB_REF_NAME",
    "GITHUB_REF_PROTECTED",
    "GITHUB_REF_TYPE",
    "GITHUB_REPOSITORY",
    "GITHUB_REPOSITORY_ID",
    "GITHUB_REPOSITORY_OWNER",
    "GITHUB_REPOSITORY_OWNER_ID",
    "GITHUB_RETENTION_DAYS",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_RUN_ID",
    "GITHUB_RUN_NUMBER",
    "GITHUB_SERVER_URL",
    "GITHUB_SHA",
    "GITHUB_STATE",
    "GITHUB_STEP_SUMMARY",
    "GITHUB_TRIGGERING_ACTOR",
    "GITHUB_WORKFLOW",
    "GITHUB_WORKFLOW_REF",
    "GITHUB_WORKFLOW_SHA",
    "GITHUB_WORKSPACE",
];

const RUNNER_PROTECTED_ENVIRONMENT_NAMES: &[&str] = &[
    "RUNNER_ARCH",
    "RUNNER_DEBUG",
    "RUNNER_ENVIRONMENT",
    "RUNNER_NAME",
    "RUNNER_OS",
    "RUNNER_TEMP",
    "RUNNER_TOOL_CACHE",
];

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
fn duplicate_name_value_records_apply_in_order_with_the_last_value_winning() {
    let invocation = ActionInvocationId::new("duplicate-action").expect("valid invocation ID");
    let step_id = StepId::new("duplicate").expect("valid step ID");
    let applied = GithubCompletedStepApplicator::default()
        .apply_completed_step(
            &JobCommandState::new(CommandFilePlatform::Unix),
            &StepScope::new(step_id.clone(), StepPhase::ActionMain(invocation.clone())),
            &commands(
                b"ENVIRONMENT=first\nENVIRONMENT=second\n",
                b"OUTPUT=first\nOUTPUT=second\n",
                b"/first\n/second\n/first\n",
                b"STATE=first\nSTATE=second\n",
                b"",
            ),
        )
        .expect("bounded duplicate records");

    assert_eq!(
        value(applied.next_state().environment(), "ENVIRONMENT"),
        Some("second")
    );
    assert_eq!(
        value(
            applied.next_state().outputs(&step_id).expect("step output"),
            "OUTPUT"
        ),
        Some("second")
    );
    assert_eq!(
        value(
            &applied.next_state().post_action_environment(&invocation),
            "STATE_STATE"
        ),
        Some("second")
    );
    assert_eq!(
        applied.next_state().prepend_path().collect::<Vec<_>>(),
        ["/first", "/second"]
    );
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

#[test]
fn protected_environment_classifier_covers_case_and_namespace_boundaries() {
    for (catalog, namespace) in [
        (
            GITHUB_PROTECTED_ENVIRONMENT_NAMES,
            ReservedEnvironmentNamespace::Github,
        ),
        (
            RUNNER_PROTECTED_ENVIRONMENT_NAMES,
            ReservedEnvironmentNamespace::Runner,
        ),
    ] {
        for canonical in catalog {
            assert_eq!(
                classify_environment_mutation(CommandFilePlatform::Unix, canonical),
                Some(EnvironmentMutationBlockReason::Reserved(namespace)),
                "Unix must protect exact canonical name {canonical}"
            );
            for variant in [
                canonical.to_ascii_lowercase(),
                alternating_ascii_case(canonical),
            ] {
                assert_eq!(
                    classify_environment_mutation(CommandFilePlatform::Windows, &variant),
                    Some(EnvironmentMutationBlockReason::Reserved(namespace)),
                    "Windows must protect case variant {variant}"
                );
                assert_eq!(
                    classify_environment_mutation(CommandFilePlatform::Unix, &variant),
                    None,
                    "Unix must preserve distinct case variant {variant}"
                );
            }
            assert_eq!(
                classify_environment_mutation(CommandFilePlatform::Windows, canonical),
                Some(EnvironmentMutationBlockReason::Reserved(namespace)),
                "Windows must protect exact canonical name {canonical}"
            );
        }
    }

    for variant in ascii_case_variants("NODE_OPTIONS") {
        for platform in [CommandFilePlatform::Unix, CommandFilePlatform::Windows] {
            assert_eq!(
                classify_environment_mutation(platform, &variant),
                Some(EnvironmentMutationBlockReason::NodeOptions),
                "NODE_OPTIONS protection must ignore ASCII case for {variant}"
            );
        }
    }

    for allowed in [
        "CI",
        "ci",
        "Ci",
        "cI",
        "GITHUB",
        "GITHUBX",
        "GITHUB_TOKEN",
        "GITHUB_CUSTOM",
        "RUNNER",
        "RUNNERX",
        "RUNNER_DIGEST",
        "RUNNER_CUSTOM",
    ] {
        for platform in [CommandFilePlatform::Unix, CommandFilePlatform::Windows] {
            assert_eq!(
                classify_environment_mutation(platform, allowed),
                None,
                "{allowed} is outside the protected default-variable catalog"
            );
        }
    }
}

#[test]
fn github_env_ignores_reserved_names_and_preserves_the_ci_exception() {
    let files = commands(
        b"GITHUB_ENV=attacker\nRUNNER_TEMP=attacker\nCI=custom\nGITHUB_TOKEN=token\nGITHUB_CUSTOM=github\nRUNNER_DIGEST=digest\nRUNNER_CUSTOM=runner\n",
        b"",
        b"",
        b"",
        b"",
    );
    let applied = GithubCompletedStepApplicator::default()
        .apply_completed_step(
            &JobCommandState::new(CommandFilePlatform::Unix),
            &StepScope::new(
                StepId::new("environment").expect("valid step ID"),
                StepPhase::Run,
            ),
            &files,
        )
        .expect("bounded state");

    assert_eq!(
        value(applied.next_state().environment(), "GITHUB_ENV"),
        None
    );
    assert_eq!(
        value(applied.next_state().environment(), "RUNNER_TEMP"),
        None
    );
    assert_eq!(
        value(applied.next_state().environment(), "CI"),
        Some("custom")
    );
    assert_eq!(
        value(applied.next_state().environment(), "GITHUB_TOKEN"),
        Some("token")
    );
    assert_eq!(
        value(applied.next_state().environment(), "GITHUB_CUSTOM"),
        Some("github")
    );
    assert_eq!(
        value(applied.next_state().environment(), "RUNNER_DIGEST"),
        Some("digest")
    );
    assert_eq!(
        value(applied.next_state().environment(), "RUNNER_CUSTOM"),
        Some("runner")
    );
    assert_eq!(
        applied.notices(),
        [
            PhaseApplicationNotice::BlockedReservedEnvironment(
                ReservedEnvironmentNamespace::Github,
            ),
            PhaseApplicationNotice::BlockedReservedEnvironment(
                ReservedEnvironmentNamespace::Runner,
            ),
        ]
    );
}

#[test]
fn github_env_default_name_case_follows_the_target_platform() {
    let files = commands(
        b"gItHuB_eNv=attacker\nrUnNeR_tEmP=attacker\nnode_options=attacker\nci=custom\n",
        b"",
        b"",
        b"",
        b"",
    );
    let scope = StepScope::new(
        StepId::new("environment").expect("valid step ID"),
        StepPhase::Run,
    );
    let applicator = GithubCompletedStepApplicator::default();

    let unix = applicator
        .apply_completed_step(
            &JobCommandState::new(CommandFilePlatform::Unix),
            &scope,
            &files,
        )
        .expect("bounded Unix state");
    assert_eq!(
        value(unix.next_state().environment(), "gItHuB_eNv"),
        Some("attacker")
    );
    assert_eq!(
        value(unix.next_state().environment(), "rUnNeR_tEmP"),
        Some("attacker")
    );
    assert_eq!(value(unix.next_state().environment(), "node_options"), None);
    assert_eq!(value(unix.next_state().environment(), "ci"), Some("custom"));
    assert_eq!(unix.notices(), [PhaseApplicationNotice::BlockedNodeOptions]);

    let windows = applicator
        .apply_completed_step(
            &JobCommandState::new(CommandFilePlatform::Windows),
            &scope,
            &files,
        )
        .expect("bounded Windows state");
    assert_eq!(windows.next_state().environment().len(), 1);
    assert_eq!(
        value(windows.next_state().environment(), "ci"),
        Some("custom")
    );
    assert_eq!(
        windows.notices(),
        [
            PhaseApplicationNotice::BlockedReservedEnvironment(
                ReservedEnvironmentNamespace::Github,
            ),
            PhaseApplicationNotice::BlockedReservedEnvironment(
                ReservedEnvironmentNamespace::Runner,
            ),
            PhaseApplicationNotice::BlockedNodeOptions,
        ]
    );
}

#[test]
fn legacy_set_env_default_names_are_applied_with_target_platform_semantics() {
    let mutations = [
        legacy_environment_mutation("GITHUB_ENV", "attacker"),
        legacy_environment_mutation("RUNNER_TEMP", "attacker"),
        legacy_environment_mutation("github_path", "unix-value"),
        legacy_environment_mutation("runner_arch", "unix-value"),
        legacy_environment_mutation("CI", "custom"),
    ];
    let files = commands(b"", b"", b"", b"", b"").with_legacy_mutations(&mutations);
    let scope = StepScope::new(
        StepId::new("legacy-environment").expect("valid step ID"),
        StepPhase::Run,
    );
    let applicator = GithubCompletedStepApplicator::default();

    let unix = applicator
        .apply_completed_step(
            &JobCommandState::new(CommandFilePlatform::Unix),
            &scope,
            &files,
        )
        .expect("bounded Unix state");
    assert_eq!(
        value(unix.next_state().environment(), "github_path"),
        Some("unix-value")
    );
    assert_eq!(
        value(unix.next_state().environment(), "runner_arch"),
        Some("unix-value")
    );
    assert_eq!(value(unix.next_state().environment(), "CI"), Some("custom"));
    assert_eq!(
        unix.notices(),
        [
            PhaseApplicationNotice::BlockedReservedEnvironment(
                ReservedEnvironmentNamespace::Github,
            ),
            PhaseApplicationNotice::BlockedReservedEnvironment(
                ReservedEnvironmentNamespace::Runner,
            ),
        ]
    );

    let windows = applicator
        .apply_completed_step(
            &JobCommandState::new(CommandFilePlatform::Windows),
            &scope,
            &files,
        )
        .expect("bounded Windows state");
    assert_eq!(windows.next_state().environment().len(), 1);
    assert_eq!(
        value(windows.next_state().environment(), "CI"),
        Some("custom")
    );
    assert_eq!(
        windows.notices(),
        [
            PhaseApplicationNotice::BlockedReservedEnvironment(
                ReservedEnvironmentNamespace::Github,
            ),
            PhaseApplicationNotice::BlockedReservedEnvironment(
                ReservedEnvironmentNamespace::Runner,
            ),
            PhaseApplicationNotice::BlockedReservedEnvironment(
                ReservedEnvironmentNamespace::Github,
            ),
            PhaseApplicationNotice::BlockedReservedEnvironment(
                ReservedEnvironmentNamespace::Runner,
            ),
        ]
    );
}

fn legacy_environment_mutation(name: &str, value: &str) -> LegacyStepMutation {
    let mut session = GithubWorkflowCommandSession::new(
        WorkflowCommandLimits::default(),
        WorkflowCommandPolicy::new(true, true),
    );
    let line = format!("::set-env name={name}::{value}");
    let event = session
        .process_line(line.as_bytes())
        .expect("valid legacy environment command");
    let WorkflowLine::Command(WorkflowCommandEvent::LegacyMutation(mutation)) = event else {
        panic!("expected a deferred legacy mutation for {name}");
    };
    mutation
}

fn ascii_case_variants(value: &str) -> Vec<String> {
    value
        .chars()
        .fold(vec![String::new()], |variants, character| {
            if character.is_ascii_alphabetic() {
                variants
                    .into_iter()
                    .flat_map(|variant| {
                        let mut lowercase = variant.clone();
                        lowercase.push(character.to_ascii_lowercase());
                        let mut uppercase = variant;
                        uppercase.push(character.to_ascii_uppercase());
                        [lowercase, uppercase]
                    })
                    .collect()
            } else {
                variants
                    .into_iter()
                    .map(|mut variant| {
                        variant.push(character);
                        variant
                    })
                    .collect()
            }
        })
}

fn alternating_ascii_case(value: &str) -> String {
    value
        .chars()
        .enumerate()
        .map(|(index, character)| {
            if index.is_multiple_of(2) {
                character.to_ascii_lowercase()
            } else {
                character.to_ascii_uppercase()
            }
        })
        .collect()
}
