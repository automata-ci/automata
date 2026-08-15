use automata_ci_github_runtime::{
    CommandFileDecoder, CommandFileError, CommandFileKind, CommandFileLimits, CommandFilePlatform,
    GithubCommandFileDecoder, ParsedCommandFile,
};

fn render_name_values(file: &ParsedCommandFile) -> String {
    let commands = match file {
        ParsedCommandFile::Environment(file) => file.commands(),
        ParsedCommandFile::Output(file) => file.commands(),
        ParsedCommandFile::State(file) => file.commands(),
        ParsedCommandFile::Path(_)
        | ParsedCommandFile::StepSummary(_)
        | ParsedCommandFile::Artifacts(_) => {
            panic!("fixture must decode as a name/value command file")
        }
    };
    let mut rendered = String::new();
    for command in commands {
        rendered.push_str(command.name());
        rendered.push('=');
        rendered.extend(command.value().chars().flat_map(char::escape_default));
        rendered.push('\n');
    }
    rendered
}

#[test]
fn env_fixture_matches_reviewed_runner_golden() {
    let parser = GithubCommandFileDecoder::default();
    let source =
        String::from_utf8_lossy(include_bytes!("fixtures/command_files.env")).replace("\r\n", "\n");
    let parsed = parser
        .decode(
            CommandFileKind::Environment,
            source.as_bytes(),
            CommandFilePlatform::Unix,
        )
        .expect("valid fixture");

    assert_eq!(
        render_name_values(&parsed),
        include_str!("fixtures/command_files.golden").replace("\r\n", "\n")
    );
}

#[test]
fn all_name_value_files_share_the_exact_grammar() {
    let parser = GithubCommandFileDecoder::default();
    for kind in [
        CommandFileKind::Environment,
        CommandFileKind::Output,
        CommandFileKind::State,
    ] {
        let parsed = parser
            .decode(kind, b"name=value\n", CommandFilePlatform::Unix)
            .expect("valid command file");
        assert_eq!(render_name_values(&parsed), "name=value\n");
    }
}

#[test]
fn heredoc_newlines_follow_the_selected_runner_platform() {
    let parser = GithubCommandFileDecoder::default();
    let source = b"VALUE<<EOF\r\none\r\nEOF\r\n";

    let unix = parser
        .decode(CommandFileKind::Output, source, CommandFilePlatform::Unix)
        .expect("valid Unix heredoc");
    let windows = parser
        .decode(
            CommandFileKind::Output,
            source,
            CommandFilePlatform::Windows,
        )
        .expect("valid Windows heredoc");

    assert_eq!(render_name_values(&unix), "VALUE=one\\r\n");
    assert_eq!(render_name_values(&windows), "VALUE=one\n");
}

#[test]
fn ordinary_records_follow_the_selected_runner_platform_line_reader() {
    let parser = GithubCommandFileDecoder::default();
    let source = b"FIRST=one\r\nSECOND=two\n";

    let unix = parser
        .decode(CommandFileKind::Output, source, CommandFilePlatform::Unix)
        .expect("valid Unix records");
    let windows = parser
        .decode(
            CommandFileKind::Output,
            source,
            CommandFilePlatform::Windows,
        )
        .expect("valid Windows records");

    assert_eq!(render_name_values(&unix), "FIRST=one\\r\nSECOND=two\n");
    assert_eq!(render_name_values(&windows), "FIRST=one\nSECOND=two\n");
}

#[test]
fn heredoc_delimiters_match_only_an_exact_complete_line() {
    let parser = GithubCommandFileDecoder::default();
    let parsed = parser
        .decode(
            CommandFileKind::Output,
            b"VALUE<<EOF\nfirst\nEOF suffix\nprefix EOF\nEOF\nAFTER=next\n",
            CommandFilePlatform::Unix,
        )
        .expect("delimiter substrings remain value bytes");

    assert_eq!(
        render_name_values(&parsed),
        "VALUE=first\\nEOF suffix\\nprefix EOF\nAFTER=next\n"
    );
}

#[test]
fn duplicate_records_are_retained_in_source_order_for_later_last_write_wins_application() {
    let parser = GithubCommandFileDecoder::default();
    for kind in [
        CommandFileKind::Environment,
        CommandFileKind::Output,
        CommandFileKind::State,
    ] {
        let parsed = parser
            .decode(
                kind,
                b"NAME=first\nNAME=second\n",
                CommandFilePlatform::Unix,
            )
            .expect("duplicate records use the runner grammar");
        assert_eq!(render_name_values(&parsed), "NAME=first\nNAME=second\n");
    }
}

#[test]
fn empty_names_and_delimiters_are_rejected_for_every_name_value_file() {
    let parser = GithubCommandFileDecoder::default();
    for kind in [
        CommandFileKind::Environment,
        CommandFileKind::Output,
        CommandFileKind::State,
    ] {
        assert_eq!(
            parser.decode(kind, b"=value\n", CommandFilePlatform::Unix),
            Err(CommandFileError::EmptyName { kind })
        );
        assert_eq!(
            parser.decode(kind, b"<<EOF\nvalue\nEOF\n", CommandFilePlatform::Unix),
            Err(CommandFileError::EmptyName { kind })
        );
        assert_eq!(
            parser.decode(kind, b"NAME<<\n", CommandFilePlatform::Unix),
            Err(CommandFileError::EmptyDelimiter { kind })
        );
    }
}

#[test]
fn path_file_uses_universal_line_endings_and_preserves_order() {
    let parser = GithubCommandFileDecoder::default();
    let source = include_bytes!("fixtures/path_file.txt");
    let ParsedCommandFile::Path(path) = parser
        .decode(CommandFileKind::Path, source, CommandFilePlatform::Unix)
        .expect("valid PATH file")
    else {
        panic!("wrong decoded file kind");
    };
    let rendered = path.paths().collect::<Vec<_>>().join("\n") + "\n";
    assert_eq!(
        rendered,
        include_str!("fixtures/path_file.golden").replace("\r\n", "\n")
    );

    let ParsedCommandFile::Path(mixed) = parser
        .decode(
            CommandFileKind::Path,
            b"one\r\ntwo\rthree\n",
            CommandFilePlatform::Unix,
        )
        .expect("mixed line endings are supported for GITHUB_PATH")
    else {
        panic!("wrong decoded file kind");
    };
    assert_eq!(mixed.paths().collect::<Vec<_>>(), ["one", "two", "three"]);
}

#[test]
fn utf8_bom_is_consumed_and_summary_content_is_preserved() {
    let parser = GithubCommandFileDecoder::default();
    let parsed = parser
        .decode(
            CommandFileKind::Environment,
            b"\xEF\xBB\xBFNAME=value\n",
            CommandFilePlatform::Unix,
        )
        .expect("UTF-8 BOM is accepted");
    assert_eq!(render_name_values(&parsed), "NAME=value\n");

    let ParsedCommandFile::StepSummary(summary) = parser
        .decode(
            CommandFileKind::StepSummary,
            b"# title\r\n\r\nbody\n",
            CommandFilePlatform::Unix,
        )
        .expect("valid summary")
    else {
        panic!("wrong decoded file kind");
    };
    assert_eq!(summary.markdown(), "# title\r\n\r\nbody\n");

    let ParsedCommandFile::StepSummary(summary) = parser
        .decode(
            CommandFileKind::StepSummary,
            b"\xEF\xBB\xBF# title\n",
            CommandFilePlatform::Unix,
        )
        .expect("summary BOM is accepted")
    else {
        panic!("wrong decoded file kind");
    };
    assert_eq!(summary.markdown(), "# title\n");
}

#[test]
fn malformed_heredocs_fail_without_echoing_contents() {
    let parser = GithubCommandFileDecoder::default();
    let secret = "not-for-diagnostics";
    let source = format!("VALUE<<EOF\n{secret}");
    let error = parser
        .decode(
            CommandFileKind::Output,
            source.as_bytes(),
            CommandFilePlatform::Unix,
        )
        .expect_err("unterminated heredoc must fail");

    assert_eq!(
        error,
        CommandFileError::HeredocValueMissingNewline {
            kind: CommandFileKind::Output
        }
    );
    assert!(!format!("{error:?}").contains(secret));
    assert!(!error.to_string().contains(secret));
}

#[test]
fn custom_limits_reject_oversized_files_before_parsing() {
    let limits = CommandFileLimits::new(8, 8, 8, 2, 4, 4).expect("valid limits");
    let parser = GithubCommandFileDecoder::new(limits);
    assert_eq!(
        parser.decode(
            CommandFileKind::Environment,
            b"NAME=value",
            CommandFilePlatform::Unix,
        ),
        Err(CommandFileError::FileTooLarge {
            kind: CommandFileKind::Environment,
            maximum: 8,
            received: 10,
        })
    );
}
