mod support;

use automata_ci_core::{GitObjectId, UnixMillis};
use automata_ci_provider::{
    ExternalRepositoryId, ExternalRepositoryIdentity, NormalizedTrigger, ProviderGitRef,
    ProviderGitRefKind, ProviderInstanceId, ProviderLifecycleState, ProviderRepository,
    ProviderRepositoryPath, PushTrigger, RepositoryVisibility,
};
use automata_ci_scm::{
    ChangedFile, ChangedFileIncompleteReason, ChangedFileLimits, ChangedFileNotApplicableReason,
    ChangedFilePageAccumulator, ChangedFilePageEvidence, ChangedFileRead, ChangedFileReadError,
    ChangedFileReader, ChangedFileRequest, ChangedFileRequestError,
};
use bytes::Bytes;
use static_assertions::assert_obj_safe;

use support::{active_connection, connection_with_state};

assert_obj_safe!(ChangedFileReader);

fn page_evidence(
    request: &ChangedFileRequest<'_>,
    pages: &[&'static [u8]],
) -> ChangedFilePageEvidence {
    let mut evidence = ChangedFilePageAccumulator::new(request);
    for page in pages {
        evidence.begin_page().unwrap();
        let split = page.len() / 2;
        evidence
            .push_chunk(&Bytes::copy_from_slice(&page[..split]))
            .unwrap();
        evidence
            .push_chunk(&Bytes::copy_from_slice(&page[split..]))
            .unwrap();
        evidence.finish_page().unwrap();
    }
    evidence.finish().unwrap()
}

fn push(repository: ExternalRepositoryIdentity) -> automata_ci_provider::SealedNormalizedTrigger {
    NormalizedTrigger::Push(
        PushTrigger::new(
            ProviderRepository::new(
                repository,
                ProviderRepositoryPath::new("org/repository").unwrap(),
                RepositoryVisibility::Private,
            ),
            ProviderGitRef::new("refs/heads/main", ProviderGitRefKind::Branch).unwrap(),
            Some(
                GitObjectId::from_provider_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            ),
            Some(
                GitObjectId::from_provider_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap(),
            ),
            false,
            None,
        )
        .unwrap(),
    )
    .seal()
    .unwrap()
}

#[test]
fn request_is_connection_repository_and_trigger_bound() {
    let connection = active_connection("repository-42");
    let trigger = push(connection.configuration().repository().clone());
    let request = ChangedFileRequest::public(
        &connection,
        &trigger,
        ChangedFileLimits::new(10, 2, 4_096).unwrap(),
        UnixMillis::new(2_000),
    )
    .unwrap();
    assert_eq!(request.connection(), &connection);
    assert_eq!(
        request.repository(),
        connection.configuration().repository()
    );
    assert_eq!(request.trigger().digest(), trigger.digest());

    let disabled = connection_with_state("repository-42", ProviderLifecycleState::Disabled);
    let disabled_trigger = push(disabled.configuration().repository().clone());
    assert_eq!(
        ChangedFileRequest::public(
            &disabled,
            &disabled_trigger,
            ChangedFileLimits::new(10, 2, 4_096).unwrap(),
            UnixMillis::new(2_000),
        )
        .unwrap_err(),
        ChangedFileRequestError::InactiveConnection
    );

    assert_eq!(
        ChangedFileRequest::public(
            &connection,
            &trigger,
            ChangedFileLimits::new(10, 2, 4_096).unwrap(),
            UnixMillis::new(-1),
        )
        .unwrap_err(),
        ChangedFileRequestError::InvalidObservationTime
    );

    let foreign = push(ExternalRepositoryIdentity::new(
        "44444444-4444-4444-8444-444444444444"
            .parse::<ProviderInstanceId>()
            .unwrap(),
        ExternalRepositoryId::new("repository-42").unwrap(),
    ));
    assert_eq!(
        ChangedFileRequest::public(
            &connection,
            &foreign,
            ChangedFileLimits::new(10, 2, 4_096).unwrap(),
            UnixMillis::new(2_000),
        )
        .unwrap_err(),
        ChangedFileRequestError::RepositoryMismatch
    );
}

#[test]
fn complete_files_are_canonical_unique_and_evidence_bound() {
    let connection = active_connection("repository-42");
    let trigger = push(connection.configuration().repository().clone());
    let request = ChangedFileRequest::public(
        &connection,
        &trigger,
        ChangedFileLimits::new(10, 2, 4_096).unwrap(),
        UnixMillis::new(2_000),
    )
    .unwrap();
    let renamed = ChangedFile::renamed(
        ProviderRepositoryPath::new("old/name.rs").unwrap(),
        ProviderRepositoryPath::new("src/name.rs").unwrap(),
    )
    .unwrap();
    let pages = page_evidence(&request, &[b"page one"]);
    let stale_pages = page_evidence(&request, &[b"page one"]);
    let read = ChangedFileRead::complete(
        &request,
        vec![
            renamed,
            ChangedFile::changed(ProviderRepositoryPath::new("README.md").unwrap()),
        ],
        2,
        pages,
    )
    .unwrap();
    let ChangedFileRead::Complete { files, evidence } = read else {
        panic!("expected complete files");
    };
    assert_eq!(files[0].current_path().as_str(), "README.md");
    assert_eq!(files[1].current_path().as_str(), "src/name.rs");
    assert_eq!(evidence.connection_digest(), connection.digest());
    assert_eq!(evidence.trigger_digest(), trigger.digest());
    assert_eq!(evidence.observed_file_count(), 2);
    assert_eq!(evidence.page_count(), 1);
    assert_eq!(evidence.response_bytes(), 8);

    let later_request = ChangedFileRequest::public(
        &connection,
        &trigger,
        ChangedFileLimits::new(10, 2, 4_096).unwrap(),
        UnixMillis::new(2_001),
    )
    .unwrap();
    assert_eq!(
        ChangedFileRead::complete(
            &later_request,
            vec![
                ChangedFile::changed(ProviderRepositoryPath::new("README.md").unwrap()),
                ChangedFile::changed(ProviderRepositoryPath::new("src/name.rs").unwrap()),
            ],
            2,
            stale_pages,
        ),
        Err(ChangedFileReadError::InvalidPageEvidence)
    );

    let duplicate = ProviderRepositoryPath::new("README.md").unwrap();
    assert_eq!(
        ChangedFileRead::complete(
            &request,
            vec![
                ChangedFile::changed(duplicate.clone()),
                ChangedFile::changed(duplicate),
            ],
            2,
            page_evidence(&request, &[]),
        ),
        Err(ChangedFileReadError::DuplicatePath)
    );
}

#[test]
fn incompleteness_is_durable_and_never_exposes_partial_paths_as_complete() {
    let connection = active_connection("repository-42");
    let trigger = push(connection.configuration().repository().clone());
    let request = ChangedFileRequest::public(
        &connection,
        &trigger,
        ChangedFileLimits::new(10, 1, 4_096).unwrap(),
        UnixMillis::new(2_000),
    )
    .unwrap();
    let incomplete = ChangedFileRead::incomplete(
        &request,
        ChangedFileIncompleteReason::ProviderTruncated,
        300,
        page_evidence(&request, &[b"partial page"]),
    )
    .unwrap();
    assert!(incomplete.complete_files().is_none());
    let ChangedFileRead::Incomplete { reason, evidence } = incomplete else {
        panic!("expected incomplete evidence");
    };
    assert_eq!(reason, ChangedFileIncompleteReason::ProviderTruncated);
    assert_eq!(evidence.observed_file_count(), 300);

    let mut excessive_pages = ChangedFilePageAccumulator::new(&request);
    excessive_pages.begin_page().unwrap();
    excessive_pages
        .push_chunk(&Bytes::from_static(b"first"))
        .unwrap();
    excessive_pages.finish_page().unwrap();
    assert_eq!(
        excessive_pages.begin_page(),
        Err(ChangedFileReadError::TooManyPages)
    );
    assert_eq!(
        excessive_pages.finish(),
        Err(ChangedFileReadError::InvalidPageEvidence)
    );

    let not_applicable =
        ChangedFileRead::not_applicable(ChangedFileNotApplicableReason::EventClass);
    assert!(not_applicable.complete_files().is_none());
}

#[test]
fn limits_and_renames_fail_at_exact_boundaries() {
    assert!(ChangedFileLimits::new(1, 1, 1).is_ok());
    assert!(ChangedFileLimits::new(0, 1, 1).is_err());
    assert!(ChangedFileLimits::new(1, 0, 1).is_err());
    assert!(ChangedFileLimits::new(1, 1, 0).is_err());
    let path = ProviderRepositoryPath::new("same.rs").unwrap();
    assert_eq!(
        ChangedFile::renamed(path.clone(), path),
        Err(ChangedFileReadError::InvalidRename)
    );
}

#[test]
fn zero_changed_files_can_be_proven_complete() {
    let connection = active_connection("repository-42");
    let trigger = push(connection.configuration().repository().clone());
    let request = ChangedFileRequest::public(
        &connection,
        &trigger,
        ChangedFileLimits::new(10, 1, 4_096).unwrap(),
        UnixMillis::new(2_000),
    )
    .unwrap();
    let result = ChangedFileRead::complete(
        &request,
        Vec::new(),
        0,
        page_evidence(&request, &[b"empty comparison"]),
    )
    .unwrap();
    assert_eq!(result.complete_files(), Some([].as_slice()));
}

#[test]
fn page_streaming_fails_closed_at_state_and_byte_boundaries() {
    let connection = active_connection("repository-42");
    let trigger = push(connection.configuration().repository().clone());
    let request = ChangedFileRequest::public(
        &connection,
        &trigger,
        ChangedFileLimits::new(10, 2, 5).unwrap(),
        UnixMillis::new(2_000),
    )
    .unwrap();

    let mut unopened = ChangedFilePageAccumulator::new(&request);
    assert_eq!(
        unopened.push_chunk(&Bytes::from_static(b"data")),
        Err(ChangedFileReadError::InvalidPageState)
    );
    assert_eq!(
        unopened.finish(),
        Err(ChangedFileReadError::InvalidPageEvidence)
    );

    let mut empty = ChangedFilePageAccumulator::new(&request);
    empty.begin_page().unwrap();
    assert_eq!(empty.finish_page(), Err(ChangedFileReadError::EmptyPage));

    let mut oversized = ChangedFilePageAccumulator::new(&request);
    oversized.begin_page().unwrap();
    oversized.push_chunk(&Bytes::from_static(b"123")).unwrap();
    assert_eq!(
        oversized.push_chunk(&Bytes::from_static(b"456")),
        Err(ChangedFileReadError::ResponseTooLarge)
    );
    assert_eq!(
        oversized.finish(),
        Err(ChangedFileReadError::InvalidPageEvidence)
    );
}
