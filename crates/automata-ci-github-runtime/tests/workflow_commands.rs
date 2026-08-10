use automata_ci_github_runtime::{
    AnnotationLevel, CommandNotice, GithubWorkflowCommandSession, LegacyStepMutation,
    MatcherCommand, SecretMask, WorkflowCommandError, WorkflowCommandEvent, WorkflowCommandLimits,
    WorkflowCommandPolicy, WorkflowCommandProcessor, WorkflowLine,
};

fn render(line: WorkflowLine) -> String {
    match line {
        WorkflowLine::Output(line) => format!("output:{}", line.as_str()),
        WorkflowLine::Command(WorkflowCommandEvent::Annotation(annotation)) => {
            let level = match annotation.level() {
                AnnotationLevel::Error => "error",
                AnnotationLevel::Warning => "warning",
                AnnotationLevel::Notice => "notice",
            };
            let mut rendered = format!(
                "annotation:{level}:{}",
                annotation
                    .message()
                    .chars()
                    .flat_map(char::escape_default)
                    .collect::<String>()
            );
            for (index, property) in annotation.properties().iter().enumerate() {
                rendered.push(if index == 0 { ':' } else { ',' });
                rendered.push_str(property.name());
                rendered.push('=');
                rendered.push_str(property.value());
            }
            rendered
        }
        WorkflowLine::Command(WorkflowCommandEvent::BeginGroup(group)) => {
            format!("group:{}", group.title())
        }
        WorkflowLine::Command(WorkflowCommandEvent::EndGroup) => "endgroup".to_owned(),
        WorkflowLine::Command(WorkflowCommandEvent::Debug(message)) => {
            format!("debug:{}", message.message())
        }
        WorkflowLine::Command(WorkflowCommandEvent::Matcher(matcher)) => match matcher {
            MatcherCommand::Add(file) => format!("matcher:add:{}", file.as_str()),
            MatcherCommand::RemoveOwner(owner) => {
                format!("matcher:remove-owner:{}", owner.as_str())
            }
            MatcherCommand::RemoveFile(file) => {
                format!("matcher:remove-file:{}", file.as_str())
            }
        },
        other @ WorkflowLine::Command(_) => panic!("unexpected fixture event: {other:?}"),
    }
}

#[test]
fn reviewed_command_fixture_matches_golden() {
    let mut session = GithubWorkflowCommandSession::default();
    let rendered = include_str!("fixtures/workflow_commands.txt")
        .lines()
        .map(|line| {
            render(
                session
                    .process_line(line.as_bytes())
                    .expect("valid fixture line"),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    assert_eq!(rendered, include_str!("fixtures/workflow_commands.golden"));
}

#[test]
fn current_and_legacy_grammars_use_their_exact_escape_maps() {
    let mut session = GithubWorkflowCommandSession::default();
    let current = session
        .process_line(b"::warning title=a%2Cb%3Ac::x%0Ay%252C")
        .expect("valid current command");
    let WorkflowLine::Command(WorkflowCommandEvent::Annotation(current)) = current else {
        panic!("expected annotation");
    };
    assert_eq!(current.property("title"), Some("a,b:c"));
    assert_eq!(current.message(), "x\ny%2C");

    let legacy = session
        .process_line(b"prefix ##[warning title=a%3B%5D;]x%0Ay%253B")
        .expect("valid legacy command");
    let WorkflowLine::Command(WorkflowCommandEvent::Annotation(legacy)) = legacy else {
        panic!("expected annotation");
    };
    assert_eq!(legacy.property("title"), Some("a;]"));
    assert_eq!(legacy.message(), "x\ny%3B");
}

#[test]
fn multiline_masks_register_full_and_trimmed_line_values_without_debug_leaks() {
    let secret = "abc\rdef\nghi\r\njkl";
    let mut session = GithubWorkflowCommandSession::default();
    let line = session
        .process_line(b"::add-mask::abc%0Ddef%0Aghi%0D%0Ajkl")
        .expect("valid mask command");
    let WorkflowLine::Command(WorkflowCommandEvent::RegisterMask(registration)) = line else {
        panic!("expected mask registration");
    };
    let values = registration
        .masks()
        .iter()
        .map(SecretMask::expose_secret)
        .collect::<Vec<_>>();
    assert_eq!(values, [secret, "abc", "def", "ghi", "jkl"]);
    assert!(!format!("{registration:?}").contains(secret));
    assert!(!format!("{session:?}").contains(secret));
}

#[test]
fn stop_commands_suppresses_known_commands_until_exact_dynamic_resume() {
    let token = "resume-token-123";
    let mut session = GithubWorkflowCommandSession::default();
    let stopped = session
        .process_line(format!("::stop-commands::{token}").as_bytes())
        .expect("valid stop command");
    let WorkflowLine::Command(WorkflowCommandEvent::StopCommands(stopped)) = stopped else {
        panic!("expected stop event");
    };
    assert_eq!(
        stopped
            .token_mask()
            .expect("long token is masked")
            .expose_secret(),
        token
    );
    assert!(session.commands_stopped());
    assert!(!format!("{stopped:?}").contains(token));
    assert!(matches!(
        session
            .process_line(b"::error::must remain ordinary output")
            .expect("suppressed line"),
        WorkflowLine::Output(_)
    ));
    assert!(matches!(
        session
            .process_line(format!("::{token}::").as_bytes())
            .expect("resume line"),
        WorkflowLine::Command(WorkflowCommandEvent::ResumeCommands)
    ));
    assert!(!session.commands_stopped());
    assert!(!format!("{session:?}").contains(token));
}

#[test]
fn annotation_locations_follow_upstream_normalization_rules() {
    let mut session = GithubWorkflowCommandSession::default();
    let line = session
        .process_line(b"::warning line=1,endLine=2,col=1,endColumn=2::message")
        .expect("valid warning");
    let WorkflowLine::Command(WorkflowCommandEvent::Annotation(annotation)) = line else {
        panic!("expected annotation");
    };
    assert_eq!(annotation.property("line"), Some("1"));
    assert_eq!(annotation.property("endLine"), Some("2"));
    assert_eq!(annotation.property("col"), None);
    assert_eq!(annotation.property("endColumn"), None);

    let line = session
        .process_line(b"::error endLine=3,endColumn=7::message")
        .expect("valid error");
    let WorkflowLine::Command(WorkflowCommandEvent::Annotation(annotation)) = line else {
        panic!("expected annotation");
    };
    assert_eq!(annotation.property("line"), Some("3"));
    assert_eq!(annotation.property("col"), Some("7"));

    let line = session
        .process_line(b"::error endLine=-1,endColumn=-1::message")
        .expect("syntactically valid error");
    let WorkflowLine::Command(WorkflowCommandEvent::Annotation(annotation)) = line else {
        panic!("expected annotation");
    };
    assert_eq!(annotation.property("line"), None);
    assert_eq!(annotation.property("endLine"), None);
    assert_eq!(annotation.property("col"), None);
    assert_eq!(annotation.property("endColumn"), None);
}

#[test]
fn matcher_echo_and_deprecated_mutations_are_typed() {
    let mut session = GithubWorkflowCommandSession::default();
    assert!(matches!(
        session
            .process_line(b"::remove-matcher owner=rustc::")
            .expect("valid matcher removal"),
        WorkflowLine::Command(WorkflowCommandEvent::Matcher(MatcherCommand::RemoveOwner(
            _
        )))
    ));
    assert!(matches!(
        session
            .process_line(b"::echo::ON")
            .expect("valid echo command"),
        WorkflowLine::Command(WorkflowCommandEvent::EchoChanged(true))
    ));
    assert!(session.echo_enabled());
    let output = session
        .process_line(b"::set-output name=result::yes")
        .expect("legacy output remains supported");
    let WorkflowLine::Command(WorkflowCommandEvent::LegacyMutation(LegacyStepMutation::Output(
        output,
    ))) = output
    else {
        panic!("expected legacy output");
    };
    assert_eq!(output.name(), "result");
    assert_eq!(output.value(), "yes");
}

#[test]
fn insecure_legacy_env_and_path_commands_require_explicit_policy() {
    let mut default_session = GithubWorkflowCommandSession::default();
    assert_eq!(
        default_session.process_line(b"::set-env name=KEY::value"),
        Err(WorkflowCommandError::LegacyCommandDisabled)
    );

    let mut enabled = GithubWorkflowCommandSession::new(
        WorkflowCommandLimits::default(),
        WorkflowCommandPolicy::new(true, true),
    );
    assert!(matches!(
        enabled
            .process_line(b"::set-env name=NODE_OPTIONS::unsafe")
            .expect("blocked value is a notice"),
        WorkflowLine::Command(WorkflowCommandEvent::Notice(
            CommandNotice::BlockedNodeOptions
        ))
    ));
    let path = enabled
        .process_line(b"::add-path::/tool/bin")
        .expect("opted-in add-path");
    let WorkflowLine::Command(WorkflowCommandEvent::LegacyMutation(LegacyStepMutation::Path(path))) =
        path
    else {
        panic!("expected PATH mutation");
    };
    assert_eq!(path.as_str(), "/tool/bin");
}

#[test]
fn v2_only_trims_leading_space_while_legacy_can_have_a_prefix() {
    let mut session = GithubWorkflowCommandSession::default();
    assert!(matches!(
        session
            .process_line(b"  ::debug::yes")
            .expect("leading whitespace is valid"),
        WorkflowLine::Command(WorkflowCommandEvent::Debug(_))
    ));
    assert!(matches!(
        session
            .process_line(b"prefix ::debug::no")
            .expect("not a current command"),
        WorkflowLine::Output(_)
    ));
    assert!(matches!(
        session
            .process_line(b"prefix ##[debug]yes")
            .expect("legacy prefix is valid"),
        WorkflowLine::Command(WorkflowCommandEvent::Debug(_))
    ));
}
