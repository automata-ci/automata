use std::io::Write as _;

use automata_ci_workflow_github::{
    MAX_REPOSITORY_WORKFLOW_PATH_BYTES, RepositoryWorkflowDiscoveryError as DiscoveryError,
    RepositoryWorkflowDiscoveryFailure as DiscoveryFailure, RepositoryWorkflowDiscoveryLimits,
    RepositoryWorkflowDiscoveryOutcome, discover_repository_workflows,
};
use flate2::{Compression, write::GzEncoder};

const ROOT: &[u8] = b"repository-deadbeef/";
const MIB: u64 = 1_024 * 1_024;

#[test]
fn discovers_exact_direct_workflows_in_deterministic_path_order() {
    let archive = archive(&[
        directory(ROOT),
        directory(b"repository-deadbeef/.github/"),
        directory(b"repository-deadbeef/.ci/workflows/"),
        regular(b"repository-deadbeef/.ci/workflows/z.yaml", b"z\0exact"),
        regular(b"repository-deadbeef/.ci/workflows/a.yml", b"name: a\n"),
        regular(
            b"repository-deadbeef/.ci/workflows/nested/ignored.yml",
            b"ignored",
        ),
        regular(b"repository-deadbeef/.ci/workflows/ignored.YML", b"ignored"),
        regular(b"repository-deadbeef/README.md", b"read me"),
    ]);

    let discovered = discover_repository_workflows(&archive, limits()).expect("valid archive");
    assert_eq!(discovered.len(), 2);
    assert_eq!(discovered[0].path(), ".ci/workflows/a.yml");
    assert_eq!(discovered[0].result(), Ok(b"name: a\n".as_slice()));
    assert_eq!(discovered[1].path(), ".ci/workflows/z.yaml");
    assert_eq!(discovered[1].result(), Ok(b"z\0exact".as_slice()));
}

#[test]
fn a_root_only_repository_has_no_workflows() {
    let archive = archive(&[directory(ROOT)]);
    assert!(
        discover_repository_workflows(&archive, limits())
            .expect("root-only archive")
            .is_empty()
    );
}

#[test]
fn requires_one_explicit_directory_root() {
    let implicit_root = archive(&[regular(b"repository-deadbeef/README", b"body")]);
    assert_eq!(discover(&implicit_root), Err(DiscoveryError::UnsafePath));

    let second_root = archive(&[directory(ROOT), regular(b"other-root/README", b"body")]);
    assert_eq!(discover(&second_root), Err(DiscoveryError::UnsafePath));

    let empty = gzip(&tar_bytes(&[], 2, &[]));
    assert_eq!(discover(&empty), Err(DiscoveryError::MissingArchiveRoot));
}

#[test]
fn rejects_unsafe_or_non_utf8_entry_paths() {
    for path in [
        b"/absolute".as_slice(),
        b"repository-deadbeef//file",
        b"repository-deadbeef/./file",
        b"repository-deadbeef/../file",
        b"repository-deadbeef\\file",
        b"repository-deadbeef/control\nfile",
        b"repository-deadbeef/non-utf8-\xff",
    ] {
        let archive = archive(&[directory(ROOT), regular(path, b"body")]);
        assert_eq!(discover(&archive), Err(DiscoveryError::UnsafePath));
    }
}

#[test]
fn rejects_duplicate_and_trailing_slash_aliased_paths() {
    let duplicate = archive(&[
        directory(ROOT),
        regular(b"repository-deadbeef/file", b"one"),
        regular(b"repository-deadbeef/file", b"two"),
    ]);
    assert_eq!(discover(&duplicate), Err(DiscoveryError::DuplicatePath));

    let alias = archive(&[
        directory(ROOT),
        directory(b"repository-deadbeef/path/"),
        regular(b"repository-deadbeef/path", b"body"),
    ]);
    assert_eq!(discover(&alias), Err(DiscoveryError::DuplicatePath));
}

#[test]
fn rejects_directories_and_special_entries_at_workflow_paths() {
    for kind in *b"34567" {
        let workflow = entry(b"repository-deadbeef/.ci/workflows/ci.yml", kind, b"");
        let archive = archive(&[directory(ROOT), workflow]);
        assert_eq!(
            discover(&archive),
            Err(DiscoveryError::UnsupportedWorkflowEntry)
        );
    }
}

#[test]
fn rejects_every_symlink_and_hard_link_even_outside_workflow_paths() {
    for kind in *b"12" {
        for path in [
            b"repository-deadbeef/safe-looking-link".as_slice(),
            b"repository-deadbeef/.ci/workflows/ci.yml",
        ] {
            let archive = archive(&[
                directory(ROOT),
                link(path, kind, b"repository-deadbeef/regular-target"),
            ]);
            assert_eq!(
                discover(&archive),
                Err(DiscoveryError::UnsupportedArchiveEntry),
                "entry type {kind:?} at {}",
                String::from_utf8_lossy(path)
            );
        }
    }
}

#[test]
fn rejects_every_special_entry_even_outside_workflow_paths() {
    for kind in *b"3467" {
        let archive = archive(&[
            directory(ROOT),
            entry(b"repository-deadbeef/special", kind, b""),
        ]);
        assert_eq!(
            discover(&archive),
            Err(DiscoveryError::UnsupportedArchiveEntry),
            "entry type {kind:?}"
        );
    }
}

#[test]
fn isolates_empty_and_oversized_workflows_from_valid_siblings() {
    let archive = archive(&[
        directory(ROOT),
        regular(b"repository-deadbeef/.ci/workflows/z-valid.yaml", b"good"),
        regular(
            b"repository-deadbeef/.ci/workflows/a-oversized.yml",
            b"12345",
        ),
        regular(b"repository-deadbeef/.ci/workflows/m-empty.yml", b""),
    ]);
    let outcomes =
        discover_repository_workflows(&archive, configured(MIB, MIB, 10, MIB, 4_096, 10, 4))
            .expect("path-local failures do not reject valid siblings");

    assert_eq!(
        outcomes
            .iter()
            .map(RepositoryWorkflowDiscoveryOutcome::path)
            .collect::<Vec<_>>(),
        vec![
            ".ci/workflows/a-oversized.yml",
            ".ci/workflows/m-empty.yml",
            ".ci/workflows/z-valid.yaml",
        ]
    );
    assert_eq!(outcomes[0].result(), Err(DiscoveryFailure::Oversized));
    assert_eq!(outcomes[1].result(), Err(DiscoveryFailure::Empty));
    assert_eq!(outcomes[2].result(), Ok(b"good".as_slice()));
}

#[test]
fn archive_wide_failures_override_all_path_local_outcomes() {
    let unsafe_sibling = archive(&[
        directory(ROOT),
        regular(b"repository-deadbeef/.ci/workflows/empty.yml", b""),
        regular(b"repository-deadbeef/.ci/workflows/valid.yml", b"ok"),
        regular(b"repository-deadbeef/../escape", b"unsafe"),
    ]);
    assert_eq!(discover(&unsafe_sibling), Err(DiscoveryError::UnsafePath));

    let special_sibling = archive(&[
        directory(ROOT),
        regular(b"repository-deadbeef/.ci/workflows/oversized.yml", b"12345"),
        regular(b"repository-deadbeef/.ci/workflows/valid.yml", b"ok"),
        entry(b"repository-deadbeef/device", b'3', b""),
    ]);
    assert_eq!(
        discover_repository_workflows(
            &special_sibling,
            configured(MIB, MIB, 10, MIB, 4_096, 10, 4),
        ),
        Err(DiscoveryError::UnsupportedArchiveEntry)
    );

    let entries = [
        directory(ROOT),
        regular(b"repository-deadbeef/.ci/workflows/oversized.yml", b"12345"),
        regular(b"repository-deadbeef/.ci/workflows/valid.yml", b"ok"),
    ];
    let mut corrupt_padding = tar_bytes(&entries, 2, &[]);
    let oversized_body_offset = 512 + 512;
    corrupt_padding[oversized_body_offset + 5] = 1;
    assert_eq!(
        discover_repository_workflows(
            &gzip(&corrupt_padding),
            configured(MIB, MIB, 10, MIB, 4_096, 10, 4),
        ),
        Err(DiscoveryError::Malformed)
    );
}

#[test]
fn path_local_failures_are_exactly_bounded_and_redacted() {
    let archive = archive(&[
        directory(ROOT),
        regular(b"repository-deadbeef/.ci/workflows/exact.yml", b"1234"),
        regular(
            b"repository-deadbeef/.ci/workflows/too-large.yml",
            b"secret-body",
        ),
        regular(b"repository-deadbeef/.ci/workflows/zero.yml", b""),
    ]);
    let outcomes =
        discover_repository_workflows(&archive, configured(MIB, MIB, 10, MIB, 4_096, 10, 4))
            .expect("per-path byte outcomes");

    assert_eq!(outcomes[0].result(), Ok(b"1234".as_slice()));
    assert_eq!(outcomes[1].result(), Err(DiscoveryFailure::Oversized));
    assert_eq!(outcomes[2].result(), Err(DiscoveryFailure::Empty));
    for failure in [DiscoveryFailure::Empty, DiscoveryFailure::Oversized] {
        let display = failure.to_string();
        assert!(!display.contains("secret-body"));
        assert!(!display.contains("too-large.yml"));
        assert!(!display.contains('4'));
    }
}

#[test]
fn workflow_count_and_expanded_byte_limits_remain_archive_wide() {
    let two_workflows = archive(&[
        directory(ROOT),
        regular(b"repository-deadbeef/.ci/workflows/empty.yml", b""),
        regular(b"repository-deadbeef/.ci/workflows/valid.yml", b"ok"),
    ]);
    assert_eq!(
        discover_repository_workflows(&two_workflows, configured(MIB, MIB, 10, MIB, 4_096, 1, 4),),
        Err(DiscoveryError::ResourceLimit)
    );

    let oversized = archive(&[
        directory(ROOT),
        regular(b"repository-deadbeef/.ci/workflows/oversized.yml", b"12345"),
    ]);
    assert_eq!(
        discover_repository_workflows(&oversized, configured(MIB, MIB, 10, 4, 4_096, 10, 4),),
        Err(DiscoveryError::ResourceLimit)
    );
}

#[test]
fn workflow_path_bound_matches_the_durable_provider_outcome_contract() {
    assert_eq!(MAX_REPOSITORY_WORKFLOW_PATH_BYTES, 1_024);
    let archive = archive(&[
        directory(ROOT),
        regular(b"repository-deadbeef/.ci/workflows/ci.yml", b"ci"),
    ]);
    let outcomes = discover(&archive).expect("bounded workflow path");
    assert!(
        outcomes
            .iter()
            .all(|outcome| outcome.path().len() <= MAX_REPOSITORY_WORKFLOW_PATH_BYTES)
    );
}

#[test]
fn enforces_each_independent_resource_limit() {
    let one_workflow = archive(&[
        directory(ROOT),
        regular(b"repository-deadbeef/.ci/workflows/ci.yml", b"1234"),
    ]);
    let compressed_limit = configured(
        u64::try_from(one_workflow.len()).expect("length") - 1,
        MIB,
        10,
        MIB,
        4_096,
        10,
        16,
    );
    assert_eq!(
        discover_repository_workflows(&one_workflow, compressed_limit),
        Err(DiscoveryError::ResourceLimit)
    );

    let raw_length = u64::try_from(
        tar_bytes(
            &[
                directory(ROOT),
                regular(b"repository-deadbeef/.ci/workflows/ci.yml", b"1234"),
            ],
            2,
            &[],
        )
        .len(),
    )
    .expect("length");
    let decompressed_limit = configured(MIB, raw_length - 1, 10, MIB, 4_096, 10, 16);
    assert_eq!(
        discover_repository_workflows(&one_workflow, decompressed_limit),
        Err(DiscoveryError::ResourceLimit)
    );

    let entry_limit = configured(MIB, MIB, 1, MIB, 4_096, 10, 16);
    assert_eq!(
        discover_repository_workflows(&one_workflow, entry_limit),
        Err(DiscoveryError::ResourceLimit)
    );

    let expanded = archive(&[directory(ROOT), regular(b"repository-deadbeef/data", b"12")]);
    let expanded_limit = configured(MIB, MIB, 10, 1, 4_096, 10, 1);
    assert_eq!(
        discover_repository_workflows(&expanded, expanded_limit),
        Err(DiscoveryError::ResourceLimit)
    );

    let path_limit = configured(MIB, MIB, 10, MIB, ROOT.len(), 10, 16);
    assert_eq!(
        discover_repository_workflows(&one_workflow, path_limit),
        Err(DiscoveryError::ResourceLimit)
    );

    let two_workflows = archive(&[
        directory(ROOT),
        regular(b"repository-deadbeef/.ci/workflows/a.yml", b"a"),
        regular(b"repository-deadbeef/.ci/workflows/b.yml", b"b"),
    ]);
    let workflow_count_limit = configured(MIB, MIB, 10, MIB, 4_096, 1, 16);
    assert_eq!(
        discover_repository_workflows(&two_workflows, workflow_count_limit),
        Err(DiscoveryError::ResourceLimit)
    );

    let workflow_size_limit = configured(MIB, MIB, 10, MIB, 4_096, 10, 3);
    let outcomes = discover_repository_workflows(&one_workflow, workflow_size_limit)
        .expect("per-workflow size exhaustion is path-local");
    assert_eq!(outcomes[0].result(), Err(DiscoveryFailure::Oversized));
}

#[test]
fn rejects_malformed_truncated_or_non_tar_gzip_inputs() {
    assert_eq!(discover(b"not gzip"), Err(DiscoveryError::Malformed));

    let mut truncated_gzip = archive(&[directory(ROOT)]);
    truncated_gzip.truncate(truncated_gzip.len() - 3);
    assert_eq!(discover(&truncated_gzip), Err(DiscoveryError::Malformed));

    let mut compressed_trailing_data = archive(&[directory(ROOT)]);
    compressed_trailing_data.extend_from_slice(b"not another gzip member");
    assert_eq!(
        discover(&compressed_trailing_data),
        Err(DiscoveryError::Malformed)
    );

    let mut bad_checksum = tar_bytes(&[directory(ROOT)], 2, &[]);
    bad_checksum[100] ^= 1;
    assert_eq!(
        discover(&gzip(&bad_checksum)),
        Err(DiscoveryError::Malformed)
    );

    let missing_second_end_block = gzip(&tar_bytes(&[directory(ROOT)], 1, &[]));
    assert_eq!(
        discover(&missing_second_end_block),
        Err(DiscoveryError::Malformed)
    );

    let nonzero_trailing_data = gzip(&tar_bytes(&[directory(ROOT)], 2, b"not another tar"));
    assert_eq!(
        discover(&nonzero_trailing_data),
        Err(DiscoveryError::Malformed)
    );

    let misaligned_zero_padding = gzip(&tar_bytes(&[directory(ROOT)], 2, &[0]));
    assert_eq!(
        discover(&misaligned_zero_padding),
        Err(DiscoveryError::Malformed)
    );
}

#[test]
fn validates_every_entry_and_trailer_after_the_last_workflow() {
    let entries = [
        directory(ROOT),
        regular(b"repository-deadbeef/.ci/workflows/ci.yml", b"ci"),
        regular(b"repository-deadbeef/after-workflow", b"later"),
    ];
    let mut damaged_later_header = tar_bytes(&entries, 2, &[]);
    let later_header_offset = 512 + 512 + 512;
    damaged_later_header[later_header_offset + 100] ^= 1;
    assert_eq!(
        discover(&gzip(&damaged_later_header)),
        Err(DiscoveryError::Malformed)
    );

    let mut nonzero_entry_padding = tar_bytes(&entries[..2], 2, &[]);
    let workflow_body_offset = 512 + 512;
    nonzero_entry_padding[workflow_body_offset + 2] = 1;
    assert_eq!(
        discover(&gzip(&nonzero_entry_padding)),
        Err(DiscoveryError::Malformed)
    );

    let nonzero_trailer = gzip(&tar_bytes(&entries[..2], 2, b"after the archive"));
    assert_eq!(discover(&nonzero_trailer), Err(DiscoveryError::Malformed));
}

#[test]
fn rejects_path_overrides_and_sparse_metadata() {
    for kind in *b"LKxS" {
        let archive = archive(&[
            directory(ROOT),
            entry(b"metadata", kind, b"repository-deadbeef/overridden\0"),
        ]);
        assert_eq!(
            discover(&archive),
            Err(DiscoveryError::UnsupportedArchiveEntry),
            "entry type {kind:?}"
        );
    }
}

#[test]
fn accepts_only_bounded_benign_global_pax_metadata() {
    let benign_metadata = archive(&[
        entry(b"pax-global", b'g', b"16 comment=test\n"),
        directory(ROOT),
        regular(b"repository-deadbeef/.ci/workflows/ci.yml", b"ci"),
    ]);
    let discovered = discover(&benign_metadata).expect("benign global metadata");
    assert_eq!(discovered[0].path(), ".ci/workflows/ci.yml");

    let malformed_short_record = archive(&[entry(b"pax-global", b'g', b"1 "), directory(ROOT)]);
    assert_eq!(
        discover(&malformed_short_record),
        Err(DiscoveryError::Malformed)
    );
}

#[test]
fn invalid_limit_sets_are_rejected() {
    assert!(RepositoryWorkflowDiscoveryLimits::new(0, 1, 1, 1, 1, 1, 1).is_err());
    assert!(RepositoryWorkflowDiscoveryLimits::new(1, 1, 1, 1, 1, 1, 2).is_err());
}

fn discover(bytes: &[u8]) -> Result<Vec<RepositoryWorkflowDiscoveryOutcome>, DiscoveryError> {
    discover_repository_workflows(bytes, limits())
}

fn limits() -> RepositoryWorkflowDiscoveryLimits {
    configured(MIB, MIB, 100, MIB, 4_096, 16, 4_096)
}

fn configured(
    compressed: u64,
    decompressed: u64,
    entries: usize,
    expanded: u64,
    path: usize,
    workflows: usize,
    workflow: u64,
) -> RepositoryWorkflowDiscoveryLimits {
    RepositoryWorkflowDiscoveryLimits::new(
        compressed,
        decompressed,
        entries,
        expanded,
        path,
        workflows,
        workflow,
    )
    .expect("valid test limits")
}

#[derive(Clone)]
struct TestEntry {
    path: Vec<u8>,
    kind: u8,
    body: Vec<u8>,
    link: Option<Vec<u8>>,
}

fn regular(path: &[u8], body: &[u8]) -> TestEntry {
    entry(path, b'0', body)
}

fn directory(path: &[u8]) -> TestEntry {
    entry(path, b'5', b"")
}

fn link(path: &[u8], kind: u8, target: &[u8]) -> TestEntry {
    let mut entry = entry(path, kind, b"");
    entry.link = Some(target.to_vec());
    entry
}

fn entry(path: &[u8], kind: u8, body: &[u8]) -> TestEntry {
    TestEntry {
        path: path.to_vec(),
        kind,
        body: body.to_vec(),
        link: None,
    }
}

fn archive(entries: &[TestEntry]) -> Vec<u8> {
    gzip(&tar_bytes(entries, 2, &[]))
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(bytes).expect("write gzip fixture");
    encoder.finish().expect("finish gzip fixture")
}

fn tar_bytes(entries: &[TestEntry], end_blocks: usize, trailing: &[u8]) -> Vec<u8> {
    let mut archive = Vec::new();
    for entry in entries {
        let mut header = [0_u8; 512];
        assert!(entry.path.len() <= 100, "test path must fit old tar name");
        header[..entry.path.len()].copy_from_slice(&entry.path);
        write_octal(&mut header[100..108], 0o644);
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(
            &mut header[124..136],
            u64::try_from(entry.body.len()).expect("body length"),
        );
        write_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = entry.kind;
        if let Some(link) = &entry.link {
            assert!(link.len() <= 100, "test link must fit tar header");
            header[157..157 + link.len()].copy_from_slice(link);
        }
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum = header.iter().map(|byte| u64::from(*byte)).sum::<u64>();
        let checksum = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(checksum.as_bytes());
        archive.extend_from_slice(&header);
        archive.extend_from_slice(&entry.body);
        let padding = (512 - entry.body.len() % 512) % 512;
        archive.resize(archive.len() + padding, 0);
    }
    archive.resize(archive.len() + end_blocks * 512, 0);
    archive.extend_from_slice(trailing);
    archive
}

fn write_octal(field: &mut [u8], value: u64) {
    field.fill(b'0');
    let terminator = field.len() - 1;
    field[terminator] = 0;
    let value = format!("{value:o}");
    let start = terminator - value.len();
    field[start..terminator].copy_from_slice(value.as_bytes());
}
