use std::io::Write as _;

use automata_ci_workflow_github::{
    MAX_REPOSITORY_WORKFLOW_PATH_BYTES, RepositoryWorkflowDiscoveryError as DiscoveryError,
    RepositoryWorkflowDiscoveryFailure as DiscoveryFailure, RepositoryWorkflowDiscoveryLimits,
    RepositoryWorkflowDiscoveryOutcome, RepositoryWorkflowDiscoveryPolicy,
    RepositoryWorkflowLocation, discover_repository_workflows,
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

    let discovered = discover_automata_workflows(&archive, limits()).expect("valid archive");
    assert_eq!(discovered.len(), 2);
    assert_eq!(discovered[0].path(), ".ci/workflows/a.yml");
    assert_eq!(discovered[0].result(), Ok(b"name: a\n".as_slice()));
    assert_eq!(discovered[1].path(), ".ci/workflows/z.yaml");
    assert_eq!(discovered[1].result(), Ok(b"z\0exact".as_slice()));
}

#[test]
fn discovery_accepts_only_exact_lowercase_yml_and_yaml_extensions() {
    let archive = archive(&[
        directory(ROOT),
        regular(b"repository-deadbeef/.ci/workflows/a.yml", b"a"),
        regular(b"repository-deadbeef/.ci/workflows/b.yaml", b"b"),
        regular(b"repository-deadbeef/.ci/workflows/c.YML", b"c"),
        regular(b"repository-deadbeef/.ci/workflows/d.Yaml", b"d"),
        regular(b"repository-deadbeef/.ci/workflows/e.yaml.bak", b"e"),
        regular(b"repository-deadbeef/.ci/workflows/f", b"f"),
    ]);

    let discovered = discover_automata_workflows(&archive, limits()).expect("valid archive");
    assert_eq!(
        discovered
            .iter()
            .map(RepositoryWorkflowDiscoveryOutcome::path)
            .collect::<Vec<_>>(),
        vec![".ci/workflows/a.yml", ".ci/workflows/b.yaml"]
    );
}

#[test]
fn rejects_the_github_actions_workflow_directory_as_a_second_runtime_authority() {
    for entries in [
        vec![
            directory(ROOT),
            directory(b"repository-deadbeef/.github/"),
            directory(b"repository-deadbeef/.github/workflows/"),
        ],
        vec![
            directory(ROOT),
            regular(
                b"repository-deadbeef/.github/workflows/ci.yml",
                b"name: forbidden\n",
            ),
        ],
        vec![
            directory(ROOT),
            regular(
                b"repository-deadbeef/.github/workflows/nested/ci.yaml",
                b"name: forbidden\n",
            ),
        ],
    ] {
        assert_eq!(
            discover(&archive(&entries)),
            Err(DiscoveryError::UnsupportedWorkflowLocation)
        );
    }
}

#[test]
fn workflow_locations_are_explicit_and_never_fall_back() {
    let github_archive = archive(&[
        directory(ROOT),
        regular(
            b"repository-deadbeef/.github/workflows/ci.yml",
            b"name: github\n",
        ),
    ]);
    let discovered = discover_repository_workflows(
        &github_archive,
        limits(),
        RepositoryWorkflowDiscoveryPolicy::LocalSnapshot {
            workflow_location: Some(RepositoryWorkflowLocation::Github),
        },
    )
    .expect("explicit GitHub workflow location");
    assert_eq!(discovered.len(), 1);
    assert_eq!(discovered[0].path(), ".github/workflows/ci.yml");
    assert_eq!(discovered[0].result(), Ok(b"name: github\n".as_slice()));
    assert_eq!(
        discover_automata_workflows(&github_archive, limits()),
        Err(DiscoveryError::UnsupportedWorkflowLocation)
    );

    let automata_archive = archive(&[
        directory(ROOT),
        regular(
            b"repository-deadbeef/.ci/workflows/ci.yml",
            b"name: automata\n",
        ),
    ]);
    assert_eq!(
        discover_repository_workflows(
            &automata_archive,
            limits(),
            RepositoryWorkflowDiscoveryPolicy::LocalSnapshot {
                workflow_location: Some(RepositoryWorkflowLocation::Github),
            },
        ),
        Err(DiscoveryError::UnsupportedWorkflowLocation)
    );
    assert_eq!(
        discover_automata_workflows(&automata_archive, limits())
            .expect("explicit Automata workflow location")[0]
            .path(),
        ".ci/workflows/ci.yml"
    );
    assert_eq!(
        discover_repository_workflows(
            &automata_archive,
            limits(),
            RepositoryWorkflowDiscoveryPolicy::LocalSnapshot {
                workflow_location: None,
            },
        ),
        Err(DiscoveryError::UnsupportedWorkflowLocation)
    );
}

#[test]
fn a_root_only_repository_has_no_workflows() {
    let archive = archive(&[directory(ROOT)]);
    assert!(
        discover_automata_workflows(&archive, limits())
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
fn rejects_duplicate_paths_and_exact_path_type_conflicts() {
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
    assert_eq!(discover(&alias), Err(DiscoveryError::PathTypeConflict));
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
fn remote_archives_reject_links_while_local_archives_validate_contained_targets() {
    let safe = archive(&[
        directory(ROOT),
        link(b"repository-deadbeef/dir/link", b'2', b"../target"),
    ]);
    assert_eq!(
        discover(&safe),
        Err(DiscoveryError::UnsupportedArchiveEntry)
    );
    assert!(
        discover_local(&safe, RepositoryWorkflowLocation::Automata)
            .expect("contained local symlink")
            .is_empty()
    );

    let workflow = archive(&[
        directory(ROOT),
        link(
            b"repository-deadbeef/.ci/workflows/ci.yml",
            b'2',
            b"../source.yml",
        ),
    ]);
    assert_eq!(
        discover(&workflow),
        Err(DiscoveryError::UnsupportedArchiveEntry)
    );
    assert_eq!(
        discover_local(&workflow, RepositoryWorkflowLocation::Automata),
        Err(DiscoveryError::UnsupportedWorkflowEntry)
    );

    let hardlink = archive(&[
        directory(ROOT),
        link(b"repository-deadbeef/link", b'1', b"target"),
    ]);
    assert_eq!(
        discover(&hardlink),
        Err(DiscoveryError::UnsupportedArchiveEntry)
    );

    for target in [
        b"../../outside".as_slice(),
        b"/absolute",
        b"bad\\target",
        b"non-utf8-\xff",
        b"",
    ] {
        let archive = archive(&[
            directory(ROOT),
            link(b"repository-deadbeef/link", b'2', target),
        ]);
        assert_eq!(
            discover_local(&archive, RepositoryWorkflowLocation::Automata),
            Err(DiscoveryError::UnsafeLink)
        );
    }
}

#[test]
fn rejects_prefix_type_conflicts_and_portable_path_aliases() {
    for entries in [
        vec![
            directory(ROOT),
            regular(b"repository-deadbeef/node", b"file"),
            regular(b"repository-deadbeef/node/child", b"child"),
        ],
        vec![
            directory(ROOT),
            regular(b"repository-deadbeef/node/child", b"child"),
            link(b"repository-deadbeef/node", b'2', b"target"),
        ],
    ] {
        assert_eq!(
            discover_local(&archive(&entries), RepositoryWorkflowLocation::Automata),
            Err(DiscoveryError::PathTypeConflict)
        );
    }

    let case_alias = archive(&[
        directory(ROOT),
        regular(b"repository-deadbeef/Directory/one", b"one"),
        regular(b"repository-deadbeef/directory/two", b"two"),
    ]);
    assert_eq!(discover(&case_alias), Err(DiscoveryError::PathAlias));

    let sigma_alias = archive(&[
        directory(ROOT),
        regular("repository-deadbeef/Σ/one".as_bytes(), b"one"),
        regular("repository-deadbeef/ς/two".as_bytes(), b"two"),
    ]);
    assert_eq!(discover(&sigma_alias), Err(DiscoveryError::PathAlias));

    let normalization_alias = archive(&[
        directory(ROOT),
        regular("repository-deadbeef/caf\u{e9}/one".as_bytes(), b"one"),
        regular("repository-deadbeef/cafe\u{301}/two".as_bytes(), b"two"),
    ]);
    assert_eq!(
        discover(&normalization_alias),
        Err(DiscoveryError::PathAlias)
    );
}

#[test]
fn workflow_namespace_components_require_one_canonical_spelling() {
    for path in [
        b"repository-deadbeef/.CI/workflows/ci.yml".as_slice(),
        b"repository-deadbeef/.github/WORKFLOWS/ci.yml",
        b"repository-deadbeef/.ci/Workflows/ci.yml",
    ] {
        assert_eq!(
            discover(&archive(&[directory(ROOT), regular(path, b"workflow")])),
            Err(DiscoveryError::UnsafePath),
            "namespace spelling {path:?}"
        );
    }
}

#[test]
fn derived_path_graph_node_limit_has_an_exact_amplification_boundary() {
    let exact = archive(&[
        directory(ROOT),
        regular(b"repository-deadbeef/a/b/c/d/e/f/g/h", b"body"),
    ]);
    let exact_limits = configured(MIB, MIB, 2, MIB, 100, 1, 16);
    assert!(
        discover_automata_workflows(&exact, exact_limits)
            .expect("eight derived nodes fit the four-per-entry budget")
            .is_empty()
    );

    let amplified = archive(&[
        directory(ROOT),
        regular(b"repository-deadbeef/a/b/c/d/e/f/g/h/i", b"body"),
    ]);
    assert_eq!(
        discover_automata_workflows(&amplified, exact_limits),
        Err(DiscoveryError::ResourceLimit)
    );
}

#[test]
fn local_link_graph_rejects_namespace_aliases_case_aliases_and_cycles() {
    let namespace_alias = archive(&[
        directory(ROOT),
        directory(b"repository-deadbeef/.ci/"),
        directory(b"repository-deadbeef/.ci/workflows/"),
        regular(b"repository-deadbeef/.ci/workflows/ci.yml", b"name: ci\n"),
        link(b"repository-deadbeef/alternate", b'2', b".ci"),
    ]);
    assert_eq!(
        discover_local(&namespace_alias, RepositoryWorkflowLocation::Automata),
        Err(DiscoveryError::NamespaceAlias)
    );

    let namespace_descendant_alias = archive(&[
        directory(ROOT),
        regular(b"repository-deadbeef/.ci/workflows/ci.yml", b"name: ci\n"),
        link(
            b"repository-deadbeef/alternate",
            b'2',
            b".ci/workflows/ci.yml",
        ),
    ]);
    assert_eq!(
        discover_local(
            &namespace_descendant_alias,
            RepositoryWorkflowLocation::Automata
        ),
        Err(DiscoveryError::NamespaceAlias)
    );

    let target_case_alias = archive(&[
        directory(ROOT),
        regular(b"repository-deadbeef/Target", b"target"),
        link(b"repository-deadbeef/link", b'2', b"target"),
    ]);
    assert_eq!(
        discover_local(&target_case_alias, RepositoryWorkflowLocation::Automata),
        Err(DiscoveryError::PathAlias)
    );

    let cycle = archive(&[
        directory(ROOT),
        link(b"repository-deadbeef/one", b'2', b"two"),
        link(b"repository-deadbeef/two", b'2', b"one"),
    ]);
    assert_eq!(
        discover_local(&cycle, RepositoryWorkflowLocation::Automata),
        Err(DiscoveryError::UnsafeLink)
    );

    let target_traverses_file = archive(&[
        directory(ROOT),
        regular(b"repository-deadbeef/file", b"file"),
        link(b"repository-deadbeef/link", b'2', b"file/child"),
    ]);
    assert_eq!(
        discover_local(&target_traverses_file, RepositoryWorkflowLocation::Automata),
        Err(DiscoveryError::PathTypeConflict)
    );

    let suffix = "x".repeat(94);
    let first_target = format!("two/{suffix}");
    let second_target = format!("three/{suffix}");
    let third_target = format!("four/{suffix}");
    let expanding_chain = archive(&[
        directory(ROOT),
        link(b"repository-deadbeef/one", b'2', first_target.as_bytes()),
        link(b"repository-deadbeef/two", b'2', second_target.as_bytes()),
        link(b"repository-deadbeef/three", b'2', third_target.as_bytes()),
        link(b"repository-deadbeef/four", b'2', b"target"),
    ]);
    assert_eq!(
        discover_local(&expanding_chain, RepositoryWorkflowLocation::Automata),
        Err(DiscoveryError::ResourceLimit)
    );
}

#[test]
fn local_link_graph_rejects_directory_containment_cycles() {
    let directory_self_cycle = archive(&[
        directory(ROOT),
        directory(b"repository-deadbeef/dir/"),
        link(b"repository-deadbeef/dir/self", b'2', b"."),
    ]);
    assert_eq!(
        discover_local(&directory_self_cycle, RepositoryWorkflowLocation::Automata),
        Err(DiscoveryError::UnsafeLink)
    );

    let indirect_directory_cycle = archive(&[
        directory(ROOT),
        directory(b"repository-deadbeef/dir/"),
        link(b"repository-deadbeef/bridge", b'2', b"dir"),
        link(b"repository-deadbeef/dir/self", b'2', b"../bridge"),
    ]);
    assert_eq!(
        discover_local(
            &indirect_directory_cycle,
            RepositoryWorkflowLocation::Automata
        ),
        Err(DiscoveryError::UnsafeLink)
    );

    let mutual_directory_cycle = archive(&[
        directory(ROOT),
        directory(b"repository-deadbeef/one/"),
        directory(b"repository-deadbeef/two/"),
        link(b"repository-deadbeef/one/to-two", b'2', b"../two"),
        link(b"repository-deadbeef/two/to-one", b'2', b"../one"),
    ]);
    assert_eq!(
        discover_local(
            &mutual_directory_cycle,
            RepositoryWorkflowLocation::Automata
        ),
        Err(DiscoveryError::UnsafeLink)
    );
}

#[test]
fn parent_components_apply_after_intermediate_link_expansion() {
    let namespace_alias = archive(&[
        directory(ROOT),
        directory(b"repository-deadbeef/safe/"),
        directory(b"repository-deadbeef/target/"),
        link(b"repository-deadbeef/safe/alias", b'2', b"../target"),
        link(
            b"repository-deadbeef/safe/link",
            b'2',
            b"alias/../.ci/workflows",
        ),
    ]);
    assert_eq!(
        discover_local(&namespace_alias, RepositoryWorkflowLocation::Automata),
        Err(DiscoveryError::NamespaceAlias)
    );

    let escape = archive(&[
        directory(ROOT),
        directory(b"repository-deadbeef/safe/"),
        directory(b"repository-deadbeef/target/"),
        link(b"repository-deadbeef/safe/alias", b'2', b"../target"),
        link(
            b"repository-deadbeef/safe/link",
            b'2',
            b"alias/../../outside",
        ),
    ]);
    assert_eq!(
        discover_local(&escape, RepositoryWorkflowLocation::Automata),
        Err(DiscoveryError::UnsafeLink)
    );
}

#[test]
fn each_link_resolution_has_an_independent_hop_bound() {
    let shared_chain = archive(&[
        directory(ROOT),
        directory(b"repository-deadbeef/destination/"),
        regular(b"repository-deadbeef/destination/a", b"a"),
        regular(b"repository-deadbeef/destination/b", b"b"),
        regular(b"repository-deadbeef/destination/c", b"c"),
        link(b"repository-deadbeef/bridge-one", b'2', b"bridge-two"),
        link(b"repository-deadbeef/bridge-two", b'2', b"destination"),
        link(b"repository-deadbeef/one", b'2', b"bridge-one/a"),
        link(b"repository-deadbeef/two", b'2', b"bridge-one/b"),
        link(b"repository-deadbeef/three", b'2', b"bridge-one/c"),
    ]);
    assert!(
        discover_local(&shared_chain, RepositoryWorkflowLocation::Automata)
            .expect("independent valid link chains")
            .is_empty()
    );
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
        discover_automata_workflows(&archive, configured(MIB, MIB, 10, MIB, 4_096, 10, 4))
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
        discover_automata_workflows(
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
        discover_automata_workflows(
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
        discover_automata_workflows(&archive, configured(MIB, MIB, 10, MIB, 4_096, 10, 4))
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
        discover_automata_workflows(&two_workflows, configured(MIB, MIB, 10, MIB, 4_096, 1, 4),),
        Err(DiscoveryError::ResourceLimit)
    );

    let oversized = archive(&[
        directory(ROOT),
        regular(b"repository-deadbeef/.ci/workflows/oversized.yml", b"12345"),
    ]);
    assert_eq!(
        discover_automata_workflows(&oversized, configured(MIB, MIB, 10, 4, 4_096, 10, 4),),
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
        discover_automata_workflows(&one_workflow, compressed_limit),
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
        discover_automata_workflows(&one_workflow, decompressed_limit),
        Err(DiscoveryError::ResourceLimit)
    );

    let entry_limit = configured(MIB, MIB, 1, MIB, 4_096, 10, 16);
    assert_eq!(
        discover_automata_workflows(&one_workflow, entry_limit),
        Err(DiscoveryError::ResourceLimit)
    );

    let expanded = archive(&[directory(ROOT), regular(b"repository-deadbeef/data", b"12")]);
    let expanded_limit = configured(MIB, MIB, 10, 1, 4_096, 10, 1);
    assert_eq!(
        discover_automata_workflows(&expanded, expanded_limit),
        Err(DiscoveryError::ResourceLimit)
    );

    let path_limit = configured(MIB, MIB, 10, MIB, ROOT.len(), 10, 16);
    assert_eq!(
        discover_automata_workflows(&one_workflow, path_limit),
        Err(DiscoveryError::ResourceLimit)
    );

    let two_workflows = archive(&[
        directory(ROOT),
        regular(b"repository-deadbeef/.ci/workflows/a.yml", b"a"),
        regular(b"repository-deadbeef/.ci/workflows/b.yml", b"b"),
    ]);
    let workflow_count_limit = configured(MIB, MIB, 10, MIB, 4_096, 1, 16);
    assert_eq!(
        discover_automata_workflows(&two_workflows, workflow_count_limit),
        Err(DiscoveryError::ResourceLimit)
    );

    let workflow_size_limit = configured(MIB, MIB, 10, MIB, 4_096, 10, 3);
    let outcomes = discover_automata_workflows(&one_workflow, workflow_size_limit)
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
    discover_automata_workflows(bytes, limits())
}

fn discover_automata_workflows(
    bytes: &[u8],
    limits: RepositoryWorkflowDiscoveryLimits,
) -> Result<Vec<RepositoryWorkflowDiscoveryOutcome>, DiscoveryError> {
    discover_repository_workflows(
        bytes,
        limits,
        RepositoryWorkflowDiscoveryPolicy::GithubDelivery,
    )
}

fn discover_local(
    bytes: &[u8],
    location: RepositoryWorkflowLocation,
) -> Result<Vec<RepositoryWorkflowDiscoveryOutcome>, DiscoveryError> {
    discover_repository_workflows(
        bytes,
        limits(),
        RepositoryWorkflowDiscoveryPolicy::LocalSnapshot {
            workflow_location: Some(location),
        },
    )
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
