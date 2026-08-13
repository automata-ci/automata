mod support;

use std::io::{self, Cursor, Read as _};

use automata_ci_action::{
    ActionArchiveError, ActionBundleLimits, ActionDefinitionKind, ActionSubpath, inspect_archive,
};
use automata_ci_scm::ArchiveLimits;
use bytes::Bytes;
use flate2::{Compression, write::GzEncoder};
use support::{TestEntry, build_archive, snapshot, snapshot_from_bytes};
use tar::{Builder, EntryType, Header};

const ACTION_DEFINITION: &[u8] = b"name: x";
const TRAILING_TAR_TERMINATOR_BYTES: u64 = 512;

fn inspection_limits(maximum_expanded_bytes: u64) -> ActionBundleLimits {
    ActionBundleLimits::new(
        ArchiveLimits::new(1024 * 1024).unwrap(),
        10,
        maximum_expanded_bytes,
        u64::try_from(ACTION_DEFINITION.len()).unwrap(),
        1024,
        4096,
    )
    .unwrap()
}

fn append_entry<W: io::Write>(
    archive: &mut Builder<W>,
    path: &str,
    entry_type: EntryType,
    link_name: Option<&str>,
    payload: &[u8],
) {
    let mut header = Header::new_gnu();
    header.set_mode(0o644);
    header.set_size(u64::try_from(payload.len()).unwrap());
    header.set_entry_type(entry_type);
    header.set_path(path).unwrap();
    if let Some(link_name) = link_name {
        header.set_link_name(link_name).unwrap();
    }
    header.set_cksum();
    archive.append(&header, Cursor::new(payload)).unwrap();
}

fn build_archive_with_typed_payload(entry_type: EntryType, payload: &[u8]) -> Bytes {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut archive = Builder::new(&mut encoder);
        append_entry(
            &mut archive,
            "root/action.yml",
            EntryType::Regular,
            None,
            ACTION_DEFINITION,
        );
        let (path, link_name) = if entry_type.is_symlink() {
            ("root/payload-link", Some("action.yml"))
        } else {
            ("root/payload-directory", None)
        };
        append_entry(&mut archive, path, entry_type, link_name, payload);
        archive.finish().unwrap();
    }
    Bytes::from(encoder.finish().unwrap())
}

fn build_archive_with_gnu_long_name() -> Bytes {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut archive = Builder::new(&mut encoder);
        append_entry(
            &mut archive,
            "././@LongLink",
            EntryType::GNULongName,
            None,
            b"root/action.yml\0",
        );
        append_entry(
            &mut archive,
            "placeholder",
            EntryType::Regular,
            None,
            ACTION_DEFINITION,
        );
        archive.finish().unwrap();
    }
    Bytes::from(encoder.finish().unwrap())
}

fn append_zero_gzip_member(archive: &Bytes, expanded_bytes: u64) -> Bytes {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    io::copy(&mut io::repeat(0).take(expanded_bytes), &mut encoder).unwrap();
    let mut combined = archive.to_vec();
    combined.extend_from_slice(&encoder.finish().unwrap());
    Bytes::from(combined)
}

fn decode_gzip(archive: &Bytes) -> Vec<u8> {
    let mut decoded = Vec::new();
    flate2::read::GzDecoder::new(archive.as_ref())
        .read_to_end(&mut decoded)
        .unwrap();
    decoded
}

fn gzip(bytes: &[u8]) -> Bytes {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    io::copy(&mut Cursor::new(bytes), &mut encoder).unwrap();
    Bytes::from(encoder.finish().unwrap())
}

fn valid_global_pax_record(encoded_length: usize) -> Vec<u8> {
    let mut record = format!("{encoded_length} comment=").into_bytes();
    assert!(record.len() < encoded_length);
    record.resize(encoded_length - 1, b'x');
    record.push(b'\n');
    assert_eq!(record.len(), encoded_length);
    record
}

#[test]
fn metadata_precedence_and_subpaths_match_the_runner_contract() {
    let archive = snapshot(&[
        TestEntry::PaxGlobal(b"52 comment=de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"),
        TestEntry::File("root/action.yaml", b"name: fallback"),
        TestEntry::File("root/Dockerfile", b"FROM scratch"),
        TestEntry::File("root/action.yml", b"name: preferred"),
        TestEntry::File("root/nested/action.yaml", b"name: nested"),
    ]);

    let root = inspect_archive(
        &archive,
        &ActionSubpath::root(),
        ActionBundleLimits::default(),
    )
    .unwrap();
    assert_eq!(root.kind(), ActionDefinitionKind::MetadataYaml);
    assert_eq!(root.path(), "action.yml");
    assert_eq!(root.bytes().as_ref(), b"name: preferred");

    let nested = inspect_archive(
        &archive,
        &ActionSubpath::new("nested").unwrap(),
        ActionBundleLimits::default(),
    )
    .unwrap();
    assert_eq!(nested.path(), "nested/action.yaml");
    assert_eq!(nested.bytes().as_ref(), b"name: nested");
}

#[test]
fn global_pax_metadata_is_narrowly_allowlisted() {
    let malicious = snapshot(&[
        TestEntry::PaxGlobal(b"19 path=../../evil\n"),
        TestEntry::File("root/action.yml", b"name: x"),
    ]);
    assert_eq!(
        inspect_archive(
            &malicious,
            &ActionSubpath::root(),
            ActionBundleLimits::default(),
        )
        .unwrap_err(),
        ActionArchiveError::UnsafePath
    );
}

#[test]
fn undersized_global_pax_record_is_typed_as_malformed() {
    let malformed = snapshot(&[
        TestEntry::PaxGlobal(b"1 \n"),
        TestEntry::File("root/action.yml", ACTION_DEFINITION),
    ]);

    assert_eq!(
        inspect_archive(
            &malformed,
            &ActionSubpath::root(),
            ActionBundleLimits::default(),
        )
        .unwrap_err(),
        ActionArchiveError::Malformed
    );
}

#[test]
fn global_pax_metadata_is_rejected_before_allocation_at_one_over_the_byte_limit() {
    const MAXIMUM_METADATA_BYTES: usize = 64;

    let limits = ActionBundleLimits::new(
        ArchiveLimits::new(1024 * 1024).unwrap(),
        10,
        1024,
        u64::try_from(MAXIMUM_METADATA_BYTES).unwrap(),
        1024,
        4096,
    )
    .unwrap();
    let exact_record = valid_global_pax_record(MAXIMUM_METADATA_BYTES);
    let exact = snapshot(&[
        TestEntry::PaxGlobal(&exact_record),
        TestEntry::File("root/action.yml", ACTION_DEFINITION),
    ]);
    assert_eq!(
        inspect_archive(&exact, &ActionSubpath::root(), limits)
            .unwrap()
            .bytes()
            .as_ref(),
        ACTION_DEFINITION
    );

    let oversized_record = valid_global_pax_record(MAXIMUM_METADATA_BYTES + 1);
    let oversized = snapshot(&[
        TestEntry::PaxGlobal(&oversized_record),
        TestEntry::File("root/action.yml", ACTION_DEFINITION),
    ]);
    assert_eq!(
        inspect_archive(&oversized, &ActionSubpath::root(), limits).unwrap_err(),
        ActionArchiveError::ResourceLimit
    );
}

#[test]
fn dockerfile_is_the_legacy_fallback_only_when_metadata_is_absent() {
    let archive = snapshot(&[
        TestEntry::File("root/dockerfile", b"FROM busybox"),
        TestEntry::File("root/Dockerfile", b"FROM scratch"),
    ]);
    let definition = inspect_archive(
        &archive,
        &ActionSubpath::root(),
        ActionBundleLimits::default(),
    )
    .unwrap();
    assert_eq!(definition.kind(), ActionDefinitionKind::Dockerfile);
    assert_eq!(definition.path(), "Dockerfile");
    assert_eq!(definition.bytes().as_ref(), b"FROM scratch");
}

#[test]
fn archive_budgets_are_independent_and_fail_closed() {
    let archive = snapshot(&[
        TestEntry::File("root/action.yml", b"name: x"),
        TestEntry::File("root/payload", &[7; 128]),
    ]);
    let expanded = ActionBundleLimits::new(
        ArchiveLimits::new(1024 * 1024).unwrap(),
        10,
        64,
        32,
        1024,
        4096,
    )
    .unwrap();
    assert_eq!(
        inspect_archive(&archive, &ActionSubpath::root(), expanded).unwrap_err(),
        ActionArchiveError::ResourceLimit
    );

    let entry_count = ActionBundleLimits::new(
        ArchiveLimits::new(1024 * 1024).unwrap(),
        1,
        1024,
        32,
        1024,
        4096,
    )
    .unwrap();
    assert_eq!(
        inspect_archive(&archive, &ActionSubpath::root(), entry_count).unwrap_err(),
        ActionArchiveError::ResourceLimit
    );
}

#[test]
fn retained_path_index_is_bounded_independently_of_entry_payloads() {
    let archive = snapshot(&[
        TestEntry::File("root/action.yml", ACTION_DEFINITION),
        TestEntry::File("root/aaa", b""),
        TestEntry::File("root/bbb", b""),
    ]);
    let exact_path_bytes = "action.yml".len() + "aaa".len() + "bbb".len();
    let limits = |maximum_path_index_bytes| {
        ActionBundleLimits::new(
            ArchiveLimits::new(1024 * 1024).unwrap(),
            10,
            1024,
            32,
            1024,
            maximum_path_index_bytes,
        )
        .unwrap()
    };

    assert_eq!(
        inspect_archive(&archive, &ActionSubpath::root(), limits(exact_path_bytes),)
            .unwrap()
            .bytes()
            .as_ref(),
        ACTION_DEFINITION
    );
    assert_eq!(
        inspect_archive(
            &archive,
            &ActionSubpath::root(),
            limits(exact_path_bytes - 1),
        )
        .unwrap_err(),
        ActionArchiveError::ResourceLimit
    );
}

#[test]
fn directory_and_symlink_payloads_are_charged_and_consumed() {
    let payload = [0x5a; 32];
    let exact_expanded_bytes = u64::try_from(ACTION_DEFINITION.len() + payload.len()).unwrap()
        + TRAILING_TAR_TERMINATOR_BYTES;
    for entry_type in [EntryType::Directory, EntryType::Symlink] {
        let archive = snapshot_from_bytes(build_archive_with_typed_payload(entry_type, &payload));
        let definition = inspect_archive(
            &archive,
            &ActionSubpath::root(),
            inspection_limits(exact_expanded_bytes),
        )
        .unwrap();
        assert_eq!(definition.bytes().as_ref(), ACTION_DEFINITION);

        assert_eq!(
            inspect_archive(
                &archive,
                &ActionSubpath::root(),
                inspection_limits(exact_expanded_bytes - 1),
            )
            .unwrap_err(),
            ActionArchiveError::ResourceLimit
        );
    }
}

#[test]
fn hidden_tar_extensions_are_rejected_before_their_payload_is_decoded() {
    let archive = snapshot_from_bytes(build_archive_with_gnu_long_name());
    assert_eq!(
        inspect_archive(
            &archive,
            &ActionSubpath::root(),
            ActionBundleLimits::default(),
        )
        .unwrap_err(),
        ActionArchiveError::UnsupportedEntry
    );
}

#[test]
fn concatenated_gzip_zero_tail_is_bounded_at_the_exact_expanded_boundary() {
    const ZERO_TAIL_BYTES: u64 = 1024 * 1024;

    let base_archive = build_archive(&[TestEntry::File("root/action.yml", ACTION_DEFINITION)]);
    let archive = append_zero_gzip_member(&base_archive, ZERO_TAIL_BYTES);
    let archive = snapshot_from_bytes(archive);
    let exact_expanded_bytes = u64::try_from(ACTION_DEFINITION.len()).unwrap()
        + TRAILING_TAR_TERMINATOR_BYTES
        + ZERO_TAIL_BYTES;
    let definition = inspect_archive(
        &archive,
        &ActionSubpath::root(),
        inspection_limits(exact_expanded_bytes),
    )
    .unwrap();
    assert_eq!(definition.bytes().as_ref(), ACTION_DEFINITION);

    assert_eq!(
        inspect_archive(
            &archive,
            &ActionSubpath::root(),
            inspection_limits(exact_expanded_bytes - 1),
        )
        .unwrap_err(),
        ActionArchiveError::ResourceLimit
    );
}

#[test]
fn tar_termination_requires_two_complete_zero_blocks() {
    let archive = build_archive(&[TestEntry::File("root/action.yml", ACTION_DEFINITION)]);
    let mut decoded = decode_gzip(&archive);
    assert!(decoded.len() >= 2 * 512);
    assert!(
        decoded[decoded.len() - 2 * 512..]
            .iter()
            .all(|byte| *byte == 0)
    );

    decoded.truncate(decoded.len() - 512);
    let truncated = snapshot_from_bytes(gzip(&decoded));
    assert_eq!(
        inspect_archive(
            &truncated,
            &ActionSubpath::root(),
            ActionBundleLimits::default(),
        )
        .unwrap_err(),
        ActionArchiveError::Malformed
    );

    decoded.extend_from_slice(&[0; 513]);
    let unaligned = snapshot_from_bytes(gzip(&decoded));
    assert_eq!(
        inspect_archive(
            &unaligned,
            &ActionSubpath::root(),
            ActionBundleLimits::default(),
        )
        .unwrap_err(),
        ActionArchiveError::Malformed
    );
}

#[test]
fn traversal_links_special_entries_duplicates_and_multiple_roots_are_rejected() {
    let unsafe_link = snapshot(&[
        TestEntry::File("root/action.yml", b"name: x"),
        TestEntry::Symlink("root/bin/tool", "../../../outside"),
    ]);
    assert_eq!(
        inspect_archive(
            &unsafe_link,
            &ActionSubpath::root(),
            ActionBundleLimits::default(),
        )
        .unwrap_err(),
        ActionArchiveError::UnsafePath
    );

    let fifo = snapshot(&[
        TestEntry::File("root/action.yml", b"name: x"),
        TestEntry::Fifo("root/pipe"),
    ]);
    assert_eq!(
        inspect_archive(&fifo, &ActionSubpath::root(), ActionBundleLimits::default(),).unwrap_err(),
        ActionArchiveError::UnsupportedEntry
    );

    let duplicate = snapshot(&[
        TestEntry::File("root/action.yml", b"name: first"),
        TestEntry::File("root/action.yml", b"name: second"),
    ]);
    assert_eq!(
        inspect_archive(
            &duplicate,
            &ActionSubpath::root(),
            ActionBundleLimits::default(),
        )
        .unwrap_err(),
        ActionArchiveError::DuplicatePath
    );

    let roots = snapshot(&[
        TestEntry::File("first/action.yml", b"name: first"),
        TestEntry::File("second/data", b"x"),
    ]);
    assert_eq!(
        inspect_archive(
            &roots,
            &ActionSubpath::root(),
            ActionBundleLimits::default(),
        )
        .unwrap_err(),
        ActionArchiveError::UnsafePath
    );
}

#[test]
fn missing_definition_and_corrupt_gzip_are_typed() {
    let missing = snapshot(&[TestEntry::File("root/README.md", b"hello")]);
    assert_eq!(
        inspect_archive(
            &missing,
            &ActionSubpath::root(),
            ActionBundleLimits::default(),
        )
        .unwrap_err(),
        ActionArchiveError::MissingDefinition
    );

    let mut corrupt = build_archive(&[TestEntry::File("root/action.yml", b"name: x")]).to_vec();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0xff;
    let corrupt = snapshot_from_bytes(corrupt.into());
    assert_eq!(
        inspect_archive(
            &corrupt,
            &ActionSubpath::root(),
            ActionBundleLimits::default(),
        )
        .unwrap_err(),
        ActionArchiveError::Malformed
    );
}

#[test]
fn subpaths_and_limit_construction_reject_ambiguous_inputs() {
    for invalid in [
        "",
        "/nested",
        "nested/",
        "nested//child",
        "nested/../child",
        "a\\b",
    ] {
        assert!(ActionSubpath::new(invalid).is_err());
    }
    assert!(ActionBundleLimits::new(ArchiveLimits::new(1).unwrap(), 0, 1, 1, 1, 1).is_err());
}

#[test]
fn bundle_limit_defaults_and_supported_maxima_are_exact() {
    const MIB: u64 = 1024 * 1024;
    let limits = ActionBundleLimits::default();
    assert_eq!(limits.compressed().maximum_bytes(), 16 * MIB);
    assert_eq!(limits.maximum_entries(), 10_000);
    assert_eq!(limits.maximum_expanded_bytes(), 256 * MIB);
    assert_eq!(limits.maximum_definition_bytes(), MIB);
    assert_eq!(limits.maximum_entry_path_bytes(), 4 * 1024);
    assert_eq!(limits.maximum_path_index_bytes(), 16 * 1024 * 1024);

    assert!(
        ActionBundleLimits::new(
            ArchiveLimits::new(16 * MIB).unwrap(),
            10_000,
            256 * MIB,
            MIB,
            4 * 1024,
            16 * 1024 * 1024,
        )
        .is_ok()
    );
    for rejected in [
        ActionBundleLimits::new(
            ArchiveLimits::new(16 * MIB + 1).unwrap(),
            10_000,
            256 * MIB,
            MIB,
            4 * 1024,
            16 * 1024 * 1024,
        ),
        ActionBundleLimits::new(
            ArchiveLimits::new(16 * MIB).unwrap(),
            10_001,
            256 * MIB,
            MIB,
            4 * 1024,
            16 * 1024 * 1024,
        ),
        ActionBundleLimits::new(
            ArchiveLimits::new(16 * MIB).unwrap(),
            10_000,
            256 * MIB + 1,
            MIB,
            4 * 1024,
            16 * 1024 * 1024,
        ),
        ActionBundleLimits::new(
            ArchiveLimits::new(16 * MIB).unwrap(),
            10_000,
            256 * MIB,
            MIB + 1,
            4 * 1024,
            16 * 1024 * 1024,
        ),
        ActionBundleLimits::new(
            ArchiveLimits::new(16 * MIB).unwrap(),
            10_000,
            256 * MIB,
            MIB,
            4 * 1024 + 1,
            16 * 1024 * 1024,
        ),
        ActionBundleLimits::new(
            ArchiveLimits::new(16 * MIB).unwrap(),
            10_000,
            256 * MIB,
            MIB,
            4 * 1024,
            16 * 1024 * 1024 + 1,
        ),
    ] {
        assert!(rejected.is_err());
    }
}
