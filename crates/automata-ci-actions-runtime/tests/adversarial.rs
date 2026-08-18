use automata_ci_actions_runtime::{
    ActionsCommandFileDecoder, ActionsWorkflowCommandSession, CommandFileDecoder, CommandFileError,
    CommandFileKind, CommandFileLimits, CommandFilePlatform, WorkflowCommandError,
    WorkflowCommandLimits, WorkflowCommandPolicy, WorkflowCommandProcessor,
};

#[test]
fn command_files_and_output_lines_reject_non_utf8() {
    let parser = ActionsCommandFileDecoder::default();
    assert_eq!(
        parser.decode(CommandFileKind::Output, &[0xff], CommandFilePlatform::Unix,),
        Err(CommandFileError::NonUtf8 {
            kind: CommandFileKind::Output
        })
    );

    let mut session = ActionsWorkflowCommandSession::default();
    assert_eq!(
        session.process_line(&[0xff]),
        Err(WorkflowCommandError::NonUtf8)
    );
}

#[test]
fn heredoc_requires_a_delimiter_and_newline_terminated_value_lines() {
    let parser = ActionsCommandFileDecoder::default();
    assert_eq!(
        parser.decode(
            CommandFileKind::State,
            b"KEY<<EOF\nvalue\n",
            CommandFilePlatform::Unix,
        ),
        Err(CommandFileError::MissingDelimiter {
            kind: CommandFileKind::State
        })
    );
    assert_eq!(
        parser.decode(
            CommandFileKind::State,
            b"KEY<<EOF\nvalue",
            CommandFilePlatform::Unix,
        ),
        Err(CommandFileError::HeredocValueMissingNewline {
            kind: CommandFileKind::State
        })
    );
}

#[test]
fn record_line_and_summary_limits_are_independent() {
    let limits = CommandFileLimits::new(64, 12, 8, 1, 8, 16).expect("valid limits");
    let parser = ActionsCommandFileDecoder::new(limits);
    assert_eq!(
        parser.decode(
            CommandFileKind::Environment,
            b"A=1\nB=2\n",
            CommandFilePlatform::Unix,
        ),
        Err(CommandFileError::TooManyRecords {
            kind: CommandFileKind::Environment,
            maximum: 1,
        })
    );
    assert_eq!(
        parser.decode(
            CommandFileKind::Path,
            b"123456789\n",
            CommandFilePlatform::Unix,
        ),
        Err(CommandFileError::LineTooLong {
            kind: CommandFileKind::Path,
            maximum: 8,
        })
    );
    assert_eq!(
        parser.decode(
            CommandFileKind::StepSummary,
            b"1234567890123",
            CommandFilePlatform::Unix,
        ),
        Err(CommandFileError::SummaryTooLarge {
            maximum: 12,
            received: 13,
        })
    );

    assert_eq!(
        parser.decode(
            CommandFileKind::StepSummary,
            b"123456789",
            CommandFilePlatform::Unix,
        ),
        Err(CommandFileError::LineTooLong {
            kind: CommandFileKind::StepSummary,
            maximum: 8,
        })
    );
}

#[test]
fn stream_limits_count_plain_output_as_well_as_commands() {
    let limits = WorkflowCommandLimits::builder()
        .maximum_stream_bytes(12)
        .maximum_line_bytes(8)
        .maximum_stream_lines(2)
        .maximum_commands(1)
        .maximum_properties(2)
        .maximum_name_bytes(8)
        .maximum_data_bytes(8)
        .maximum_masks(4)
        .build()
        .expect("valid workflow limits");
    let mut session = ActionsWorkflowCommandSession::new(limits, WorkflowCommandPolicy::default());
    session.process_line(b"plain").expect("first line");
    session.process_line(b"text").expect("second line");
    assert_eq!(
        session.process_line(b"x"),
        Err(WorkflowCommandError::TooManyLines { maximum: 2 })
    );
}

#[test]
fn invalid_stop_token_errors_never_include_the_token() {
    let token = "pause-logging";
    let mut session = ActionsWorkflowCommandSession::default();
    let error = session
        .process_line(format!("::stop-commands::{token}").as_bytes())
        .expect_err("reserved token must fail");
    assert_eq!(error, WorkflowCommandError::InvalidStopToken);
    assert!(!format!("{error:?}").contains(token));
    assert!(!error.to_string().contains(token));
    assert!(!format!("{session:?}").contains(token));
}

#[test]
fn malformed_names_and_scope_identifiers_fail_closed() {
    let parser = ActionsCommandFileDecoder::default();
    assert_eq!(
        parser.decode(
            CommandFileKind::Environment,
            b"=secret\n",
            CommandFilePlatform::Unix,
        ),
        Err(CommandFileError::EmptyName {
            kind: CommandFileKind::Environment
        })
    );
    assert!(automata_ci_actions_runtime::StepId::new("").is_err());
    assert!(automata_ci_actions_runtime::StepId::new("has whitespace").is_err());
    assert!(automata_ci_actions_runtime::ActionInvocationId::new("line\nbreak").is_err());
}
