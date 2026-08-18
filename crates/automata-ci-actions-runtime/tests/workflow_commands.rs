use automata_ci_actions_runtime::{
    ActionsWorkflowCommandSession, AnnotationLevel, MatcherCommand, SecretMask,
    WorkflowCommandEvent, WorkflowCommandProcessor, WorkflowLine,
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
    let mut session = ActionsWorkflowCommandSession::default();
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
    assert_eq!(
        rendered,
        include_str!("fixtures/workflow_commands.golden").replace("\r\n", "\n")
    );
}

#[test]
fn current_grammar_uses_its_exact_escape_map_and_old_syntax_is_output() {
    let mut session = ActionsWorkflowCommandSession::default();
    let current = session
        .process_line(b"::warning title=a%2Cb%3Ac::x%0Ay%252C")
        .expect("valid current command");
    let WorkflowLine::Command(WorkflowCommandEvent::Annotation(current)) = current else {
        panic!("expected annotation");
    };
    assert_eq!(current.property("title"), Some("a,b:c"));
    assert_eq!(current.message(), "x\ny%2C");

    let removed = session
        .process_line(b"prefix ##[warning title=a%3B%5D;]x%0Ay%253B")
        .expect("removed syntax is ordinary output");
    let WorkflowLine::Output(removed) = removed else {
        panic!("removed syntax was still recognized");
    };
    assert_eq!(
        removed.as_str(),
        "prefix ##[warning title=a%3B%5D;]x%0Ay%253B"
    );
}

#[test]
fn multiline_masks_register_full_and_trimmed_line_values_without_debug_leaks() {
    let secret = "abc\rdef\nghi\r\njkl";
    let mut session = ActionsWorkflowCommandSession::default();
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
    let mut session = ActionsWorkflowCommandSession::default();
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
    let mut session = ActionsWorkflowCommandSession::default();
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
fn matcher_and_echo_commands_are_typed() {
    let mut session = ActionsWorkflowCommandSession::default();
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
}

#[test]
fn removed_stdout_mutations_are_plain_output() {
    let mut session = ActionsWorkflowCommandSession::default();
    for line in [
        "::set-output name=result::yes",
        "::save-state name=token::value",
        "::set-env name=KEY::value",
        "::add-path::/tool/bin",
    ] {
        let parsed = session
            .process_line(line.as_bytes())
            .expect("removed commands are ordinary output");
        let WorkflowLine::Output(output) = parsed else {
            panic!("removed stdout mutation was still recognized");
        };
        assert_eq!(output.as_str(), line);
    }
}

#[test]
fn current_syntax_trims_leading_space_but_rejects_prefixes() {
    let mut session = ActionsWorkflowCommandSession::default();
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
            .expect("removed syntax is output"),
        WorkflowLine::Output(_)
    ));
}
