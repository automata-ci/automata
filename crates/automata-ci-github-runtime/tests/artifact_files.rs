use automata_ci_github_runtime::{
    ArtifactDeclaration, ArtifactSubject, ArtifactSubjectCommandFile, ArtifactSubjectKind,
    CommandFileDecoder, CommandFileError, CommandFileKind, CommandFilePlatform,
    CompletedStepApplicator, CompletedStepCommands, EnvironmentCommandFile,
    GithubCommandFileDecoder, GithubCompletedStepApplicator, JobCommandState,
    MAX_ARTIFACT_DECLARATION_FILE_BYTES, MAX_ARTIFACT_SUBJECTS, OutputCommandFile,
    ParsedCommandFile, PathCommandFile, PhaseApplicationError, StateCommandFile, StepId, StepPhase,
    StepScope, StepSummaryCommandFile,
};

fn decode(source: &[u8]) -> automata_ci_github_runtime::ArtifactDeclarationCommandFile {
    let ParsedCommandFile::Artifacts(file) = GithubCommandFileDecoder::default()
        .decode(
            CommandFileKind::Artifacts,
            source,
            CommandFilePlatform::Unix,
        )
        .expect("valid artifact declarations")
    else {
        panic!("artifact decoder returned the wrong channel")
    };
    file
}

fn completed(subjects: Vec<ArtifactSubject>) -> CompletedStepCommands {
    CompletedStepCommands::new(
        EnvironmentCommandFile::default(),
        OutputCommandFile::default(),
        PathCommandFile::default(),
        StateCommandFile::default(),
        StepSummaryCommandFile::default(),
    )
    .with_artifacts(ArtifactSubjectCommandFile::new(subjects))
}

fn subject(name: impl Into<String>, byte: char, kind: ArtifactSubjectKind) -> ArtifactSubject {
    ArtifactSubject::new(
        name,
        format!("sha256:{}", byte.to_string().repeat(64)),
        kind,
    )
    .expect("valid subject")
}

fn scope(id: &str) -> StepScope {
    StepScope::new(StepId::new(id).expect("step ID"), StepPhase::Run)
}

#[test]
fn declaration_grammar_matches_the_reviewed_upstream_delta() {
    let upper = "A".repeat(64);
    let sha384 = "b".repeat(96);
    let sha512 = "c".repeat(128);
    let source = format!(
        "  # ignored\n\nOCI://registry.example/app:v1@sha256:{upper}\nregistry.example/b@sha384:{sha384}\nregistry.example/c@sha512:{sha512}\nfile://dist/app\nrelative/path\n"
    );
    let declarations = decode(source.as_bytes());
    assert_eq!(declarations.declarations().len(), 5);

    for (index, expected) in [
        (0, format!("sha256:{}", "a".repeat(64))),
        (1, format!("sha384:{sha384}")),
        (2, format!("sha512:{sha512}")),
    ] {
        let ArtifactDeclaration::Oci(subject) = &declarations.declarations()[index] else {
            panic!("expected OCI subject")
        };
        assert_eq!(subject.digest(), expected);
        assert_eq!(subject.kind(), ArtifactSubjectKind::Oci);
    }
    for (index, expected) in [(3, "dist/app"), (4, "relative/path")] {
        let ArtifactDeclaration::File(file) = &declarations.declarations()[index] else {
            panic!("expected file declaration")
        };
        assert_eq!(file.path(), expected);
    }
}

#[test]
fn malformed_explicit_oci_equals_and_unsupported_schemes_fail_without_leaking_data() {
    let decoder = GithubCommandFileDecoder::default();
    for source in [
        "oci://registry.example/app@sha256:abc",
        "name=registry.example/app@sha256:abc",
        "https://example.invalid/artifact",
    ] {
        let error = decoder
            .decode(
                CommandFileKind::Artifacts,
                source.as_bytes(),
                CommandFilePlatform::Unix,
            )
            .expect_err("invalid declaration must fail");
        assert_eq!(
            error,
            CommandFileError::InvalidArtifactDeclaration { line: 1 }
        );
        assert!(!format!("{error:?}").contains(source));
    }

    let implicit_wrong_length = decode(b"registry.example/app@sha256:abc");
    assert!(matches!(
        implicit_wrong_length.declarations(),
        [ArtifactDeclaration::File(_)]
    ));
}

#[test]
fn declaration_file_has_the_fixed_one_mibibyte_ceiling() {
    let decoder = GithubCommandFileDecoder::default();
    let accepted = vec![b'#'; MAX_ARTIFACT_DECLARATION_FILE_BYTES];
    assert!(
        decoder
            .decode(
                CommandFileKind::Artifacts,
                &accepted,
                CommandFilePlatform::Unix,
            )
            .is_ok()
    );
    let rejected = vec![b'#'; MAX_ARTIFACT_DECLARATION_FILE_BYTES + 1];
    assert_eq!(
        decoder.decode(
            CommandFileKind::Artifacts,
            &rejected,
            CommandFilePlatform::Unix,
        ),
        Err(CommandFileError::FileTooLarge {
            kind: CommandFileKind::Artifacts,
            maximum: MAX_ARTIFACT_DECLARATION_FILE_BYTES,
            received: MAX_ARTIFACT_DECLARATION_FILE_BYTES + 1,
        })
    );
}

#[test]
fn aggregation_is_atomic_sorted_deduplicated_and_conflict_checked() {
    let applicator = GithubCompletedStepApplicator::default();
    let initial = JobCommandState::new(CommandFilePlatform::Unix);
    let first = completed(vec![
        subject("zeta", 'a', ArtifactSubjectKind::File),
        subject("alpha", 'b', ArtifactSubjectKind::Oci),
    ]);
    let state = applicator
        .apply_completed_step(&initial, &scope("first"), &first)
        .expect("first declarations")
        .into_next_state();
    assert_eq!(
        state
            .artifact_subjects()
            .iter()
            .map(ArtifactSubject::name)
            .collect::<Vec<_>>(),
        ["alpha", "zeta"]
    );
    assert_eq!(
        String::from_utf8(state.artifact_list_json().expect("artifact JSON")).expect("UTF-8"),
        format!(
            "{{\"version\":1,\"subjects\":[{{\"name\":\"alpha\",\"digest\":\"sha256:{}\",\"kind\":\"oci\"}},{{\"name\":\"zeta\",\"digest\":\"sha256:{}\",\"kind\":\"file\"}}]}}",
            "b".repeat(64),
            "a".repeat(64)
        )
    );

    let conflicting = completed(vec![
        subject("new", 'c', ArtifactSubjectKind::File),
        subject("alpha", 'd', ArtifactSubjectKind::Oci),
    ]);
    assert_eq!(
        applicator.apply_completed_step(&state, &scope("second"), &conflicting),
        Err(PhaseApplicationError::ArtifactConflict)
    );
    assert!(
        state
            .artifact_subjects()
            .iter()
            .all(|subject| subject.name() != "new")
    );

    let duplicate = completed(vec![subject("alpha", 'b', ArtifactSubjectKind::File)]);
    let deduplicated = applicator
        .apply_completed_step(&state, &scope("third"), &duplicate)
        .expect("same name and digest deduplicates")
        .into_next_state();
    assert_eq!(deduplicated.artifact_subjects(), state.artifact_subjects());
}

#[test]
fn aggregate_cap_allows_identical_duplicates_but_rejects_distinct_overflow() {
    let applicator = GithubCompletedStepApplicator::default();
    let all = (0..MAX_ARTIFACT_SUBJECTS)
        .map(|index| subject(format!("subject-{index:03}"), 'a', ArtifactSubjectKind::Oci))
        .collect();
    let state = applicator
        .apply_completed_step(
            &JobCommandState::new(CommandFilePlatform::Unix),
            &scope("fill"),
            &completed(all),
        )
        .expect("fill exact cap")
        .into_next_state();
    assert_eq!(state.artifact_subjects().len(), MAX_ARTIFACT_SUBJECTS);

    assert!(
        applicator
            .apply_completed_step(
                &state,
                &scope("duplicate"),
                &completed(vec![
                    subject("subject-000", 'a', ArtifactSubjectKind::File,)
                ]),
            )
            .is_ok()
    );
    assert_eq!(
        applicator.apply_completed_step(
            &state,
            &scope("overflow"),
            &completed(vec![subject("overflow", 'a', ArtifactSubjectKind::Oci)]),
        ),
        Err(PhaseApplicationError::TooManyArtifactSubjects {
            maximum: MAX_ARTIFACT_SUBJECTS,
        })
    );
}
