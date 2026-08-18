use super::*;
use std::io::Write as _;

#[test]
fn closed_role_set_remains_exact() {
    assert_eq!(ALL_ROLES.len(), 7);
    assert_eq!(
        CANDIDATE_BASENAME,
        CANDIDATE_PATH.rsplit('/').next().unwrap()
    );
}

#[test]
fn generated_five_field_registry_binding_is_consumed_exactly() {
    let source: RawSourceCatalog = serde_json::from_slice(include_bytes!(
        "../../../../../images/local-installation/catalog-v1.json"
    ))
    .unwrap();
    let postgres_source = &source.images.get("postgres").unwrap().source;
    let binding = serde_json::json!({
        "config_digest": "sha256:526573c93ea530a230b553cc513075ab9d70b63bfd2300ef5eb5ad1cafbbc595",
        "kind": "registry",
        "platform_manifest_digest": "sha256:7e6103cf85f88f7a0eddb3ec0b1ba8940eba098ed118ade25a729ca9daee5568",
        "reference": "docker.io/library/postgres:18.4-bookworm@sha256:7e6103cf85f88f7a0eddb3ec0b1ba8940eba098ed118ade25a729ca9daee5568",
        "top_level_digest": "sha256:7e6103cf85f88f7a0eddb3ec0b1ba8940eba098ed118ade25a729ca9daee5568"
    });
    assert!(validate_registry_source("postgres", &binding, postgres_source).is_ok());

    let mut extra = binding.as_object().unwrap().clone();
    extra.insert(
        "distribution_directory".to_owned(),
        Value::String("fallback".to_owned()),
    );
    assert!(validate_registry_source("postgres", &Value::Object(extra), postgres_source).is_err());
}

#[test]
#[allow(clippy::too_many_lines)]
fn generated_catalog_keeps_release_provenance_distinct_from_the_local_import_name() {
    let source: Value = serde_json::from_slice(include_bytes!(
        "../../../../../images/local-installation/catalog-v1.json"
    ))
    .unwrap();
    let source_images = source.get("images").and_then(Value::as_object).unwrap();
    let top_digest = format!("sha256:{}", "11".repeat(32));
    let platform_digest = format!("sha256:{}", "22".repeat(32));
    let config_digest = format!("sha256:{}", "33".repeat(32));
    let candidate_manifest = format!("sha256:{}", "44".repeat(32));
    let candidate_config = format!("sha256:{}", "55".repeat(32));
    let mut images = serde_json::Map::new();
    for role in ALL_ROLES {
        let expected = source_images.get(role).unwrap();
        let expected_source = expected.get("source").and_then(Value::as_object).unwrap();
        let binding = if role == "service-proxy" {
            serde_json::json!({
                "candidate_provenance_sha256": "66".repeat(32),
                "config_digest": &candidate_config,
                "image_digest": &candidate_manifest,
                "image_name": "ghcr.io/automata-ci/automata-service-proxy",
                "kind": "release-candidate",
                "oci_archive_sha256": "77".repeat(32),
                "path": CANDIDATE_PATH,
                "sha256": "88".repeat(32),
                "source_provenance_sha256": "99".repeat(32)
            })
        } else if RELEASE_REGISTRY_ROLES.contains(&role) {
            let repository = expected_source
                .get("repository")
                .and_then(Value::as_str)
                .unwrap();
            serde_json::json!({
                "config_digest": &config_digest,
                "kind": "registry",
                "platform_manifest_digest": &platform_digest,
                "reference": format!("{repository}:v1.0.0@{top_digest}"),
                "top_level_digest": &top_digest
            })
        } else {
            let reference = expected_source
                .get("reference")
                .and_then(Value::as_str)
                .unwrap();
            serde_json::json!({
                "config_digest": expected_source.get("config_digest").unwrap(),
                "kind": "registry",
                "platform_manifest_digest": expected_source
                    .get("platform_manifest_digest")
                    .unwrap(),
                "reference": reference,
                "top_level_digest": reference.rsplit_once('@').unwrap().1
            })
        };
        images.insert(
            role.to_owned(),
            serde_json::json!({
                "canonical_repository": expected.get("canonical_repository").unwrap(),
                "config": expected.get("config").unwrap(),
                "runtime": expected.get("runtime").unwrap(),
                "source": binding
            }),
        );
    }
    let source_profile = source.get("profile").and_then(Value::as_object).unwrap();
    let catalog = serde_json::json!({
        "images": images,
        "platform": source.get("platform").unwrap(),
        "profile": {
            "compatibility_label": source_profile.get("compatibility_label").unwrap(),
            "id": source_profile.get("id").unwrap(),
            "image_role": "profile",
            "lock": {
                "path": source_profile.get("lock_path").unwrap(),
                "sha256": source_profile.get("lock_sha256").unwrap()
            },
            "manifest": {
                "path": source_profile.get("manifest_path").unwrap(),
                "sha256": source_profile.get("manifest_sha256").unwrap()
            }
        },
        "release": {
            "commit": "aa".repeat(20),
            "created": "2026-08-17T12:34:56Z",
            "prerelease": false,
            "source_date_epoch": 1_786_970_096_u64,
            "tag": "v1.0.0",
            "tag_object": "bb".repeat(20),
            "version": "1.0.0"
        },
        "schema": CATALOG_SCHEMA,
        "scope": source.get("scope").unwrap(),
        "services": source.get("services").unwrap(),
        "source_contract_sha256": SOURCE_SHA256
    });
    let mut bytes = serde_json::to_vec_pretty(&catalog).unwrap();
    bytes.push(b'\n');
    let verified = VerifiedCatalog::parse(&bytes).unwrap();
    let candidate = verified.image("service-proxy");
    assert_eq!(
        candidate.source_reference(),
        format!("ghcr.io/automata-ci/automata-service-proxy@{candidate_manifest}")
    );
    assert_eq!(
        candidate.inspection_reference(),
        format!(
            "automata.local/automata-ci-service-proxy:manifest-{}",
            candidate_manifest.strip_prefix("sha256:").unwrap()
        )
    );

    let mut wrong_provenance = catalog;
    wrong_provenance["images"]["service-proxy"]["source"]["image_name"] =
        Value::String("ghcr.io/foreign/service-proxy".to_owned());
    let mut wrong_bytes = serde_json::to_vec_pretty(&wrong_provenance).unwrap();
    wrong_bytes.push(b'\n');
    assert!(VerifiedCatalog::parse(&wrong_bytes).is_err());
}

#[test]
fn release_timestamp_is_canonical_second_precision_and_epoch_bound() {
    assert!(canonical_rfc3339_seconds("2026-08-17T12:34:56Z"));
    assert!(canonical_rfc3339_seconds("2026-08-17T15:34:56+03:00"));
    assert!(!canonical_rfc3339_seconds("2026-08-17t12:34:56Z"));
    assert!(!canonical_rfc3339_seconds("2026-08-17T12:34:56.000Z"));

    let mut release = Release {
        commit: "1".repeat(40),
        created: "2026-08-17T12:34:56Z".to_owned(),
        prerelease: false,
        source_date_epoch: 1_786_970_096,
        tag: "v1.0.0".to_owned(),
        tag_object: "2".repeat(40),
        version: "1.0.0".to_owned(),
    };
    assert!(validate_release(&release).is_ok());
    release.source_date_epoch += 1;
    assert!(validate_release(&release).is_err());
}

#[test]
fn payload_json_rejects_duplicate_keys_and_gzip_uses_all_members() {
    assert!(parse_payload_json(br#"{"key":1,"key":2}"#).is_err());

    let mut first = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    first.write_all(b"first").unwrap();
    let mut compressed = first.finish().unwrap();
    let mut second = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    second.write_all(b"second").unwrap();
    compressed.extend(second.finish().unwrap());
    assert_eq!(
        expand_candidate_layer(&compressed, OCI_GZIP_LAYER_MEDIA_TYPE).unwrap(),
        b"firstsecond"
    );
    compressed.extend_from_slice(b"trailing");
    assert!(expand_candidate_layer(&compressed, OCI_GZIP_LAYER_MEDIA_TYPE).is_err());
}

#[test]
fn python_tar_termination_is_exact_and_rejects_trailing_or_nonzero_padding() {
    let mut canonical = vec![0_u8; 10_240];
    assert!(canonical_python_tar_termination(&canonical, 1024));
    canonical[1024] = 1;
    assert!(!canonical_python_tar_termination(&canonical, 1024));
    canonical[1024] = 0;
    canonical.push(0);
    assert!(!canonical_python_tar_termination(&canonical, 1024));
}

#[test]
fn portable_docker_load_archive_retains_oci_authority_and_adds_exact_diff_ids() {
    let local_repository = "automata.local/automata-ci-service-proxy";
    let config_hex = "11".repeat(32);
    let manifest_hex = "22".repeat(32);
    let diff_hex = digest_hex(b"expanded layer");
    let diff_name = format!("blobs/sha256/{diff_hex}");
    let members = BTreeMap::from([
        (format!("blobs/sha256/{config_hex}"), b"config".to_vec()),
        (format!("blobs/sha256/{manifest_hex}"), b"manifest".to_vec()),
        ("index.json".to_owned(), b"index".to_vec()),
        ("oci-layout".to_owned(), b"layout".to_vec()),
    ]);
    let binding = CandidateBinding {
        reference: format!("automata.local/automata-ci-service-proxy@sha256:{manifest_hex}"),
        candidate_provenance_sha256: "33".repeat(32),
        config_digest: format!("sha256:{config_hex}"),
        image_digest: format!("sha256:{manifest_hex}"),
        image_name: "ghcr.io/automata-ci/automata-service-proxy".to_owned(),
        oci_archive_sha256: "44".repeat(32),
        sha256: "55".repeat(32),
        source_provenance_sha256: "66".repeat(32),
    };
    let reference = binding.local_reference(local_repository);
    let archive = build_docker_load_archive(
        members,
        ValidatedCandidateLayers {
            payload: BTreeMap::new(),
            docker_layer_names: vec![diff_name.clone()],
            expanded_blobs: BTreeMap::from([(diff_name.clone(), b"expanded layer".to_vec())]),
        },
        &binding,
        &reference,
        1_786_970_096,
        10_240,
    )
    .unwrap();
    assert!(archive.len() <= MAX_DOCKER_LOAD_ARCHIVE_BYTES);
    let derived = oci_tar_members(&archive, 1_786_970_096).unwrap();
    assert_eq!(derived.get(&diff_name).unwrap(), b"expanded layer");
    assert_eq!(derived.get("index.json").unwrap(), b"index");
    assert_eq!(
        derived.get("manifest.json").unwrap(),
        format!(
            "[{{\"Config\":\"blobs/sha256/{config_hex}\",\"Layers\":[\"{diff_name}\"],\"RepoTags\":[\"{reference}\"]}}]\n"
        )
        .as_bytes()
    );

    let image = VerifiedImage {
        canonical_repository: local_repository.to_owned(),
        config: Value::Null,
        runtime: Value::Null,
        source: ImageSource::Candidate(binding.clone()),
    };
    let tags = vec![reference.clone()];
    let no_digests = Vec::new();
    let digest_reference = vec![format!("{local_repository}@{}", binding.image_digest)];
    assert_eq!(
        image.local_import_collision_references(),
        Some([
            digest_reference[0].clone(),
            binding.image_digest.clone(),
            binding.config_digest.clone(),
        ])
    );
    assert!(image.accepts_live_id(&binding.config_digest));
    assert!(image.accepts_live_id(&binding.image_digest));
    assert!(image.accepts_live_references(&binding.config_digest, Some(&tags), Some(&no_digests)));
    assert!(image.accepts_live_references(
        &binding.image_digest,
        Some(&tags),
        Some(&digest_reference)
    ));
    assert!(!image.accepts_live_references(
        &binding.config_digest,
        Some(&tags),
        Some(&digest_reference)
    ));
    assert!(!image.accepts_live_references(&binding.image_digest, Some(&tags), Some(&no_digests)));
    assert!(!image.accepts_live_references(&binding.config_digest, Some(&tags), None));
    assert!(!image.accepts_live_references(&binding.config_digest, Some(&[]), Some(&no_digests)));
}

#[test]
#[ignore = "loads and removes one exact synthetic image on an explicitly selected local Docker Engine"]
#[allow(clippy::too_many_lines)]
fn live_portable_docker_load_archive_qualifies_the_daemon_representation() {
    use std::{fs, path::PathBuf, process::Command};

    struct Cleanup {
        docker: String,
        references: Vec<String>,
        archive: PathBuf,
    }

    impl Cleanup {
        fn remove(&mut self) {
            for reference in &self.references {
                let _ = Command::new(&self.docker)
                    .args(["image", "rm", "--force", reference])
                    .output();
            }
            self.references.clear();
            let _ = fs::remove_file(&self.archive);
        }
    }

    impl Drop for Cleanup {
        fn drop(&mut self) {
            self.remove();
        }
    }

    let epoch = 1_786_970_096;
    let local_repository = "automata.local/automata-ci-service-proxy";
    let release = Release {
        commit: "a".repeat(40),
        created: "2026-08-17T12:34:56Z".to_owned(),
        prerelease: false,
        source_date_epoch: epoch,
        tag: "v1.0.0".to_owned(),
        tag_object: "b".repeat(40),
        version: "1.0.0".to_owned(),
    };
    let layer = vec![0_u8; 10_240];
    let diff_id = format!("sha256:{}", digest_hex(&layer));
    let config = serde_json::to_vec(&serde_json::json!({
        "architecture": "amd64",
        "config": {
            "Cmd": ["true"],
            "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            "Labels": {
                "org.opencontainers.image.created": &release.created,
                "org.opencontainers.image.revision": &release.commit,
                "org.opencontainers.image.version": &release.version
            },
            "WorkingDir": "/"
        },
        "created": "2026-08-17T12:34:56Z",
        "history": [{"created": "2026-08-17T12:34:56Z", "created_by": "fixture"}],
        "os": "linux",
        "rootfs": {"diff_ids": [&diff_id], "type": "layers"}
    }))
    .unwrap();
    let config_digest = format!("sha256:{}", digest_hex(&config));
    let manifest = serde_json::to_vec(&serde_json::json!({
        "config": {
            "digest": &config_digest,
            "mediaType": OCI_CONFIG_MEDIA_TYPE,
            "size": config.len()
        },
        "layers": [{
            "digest": &diff_id,
            "mediaType": OCI_LAYER_MEDIA_TYPE,
            "size": layer.len()
        }],
        "mediaType": OCI_MANIFEST_MEDIA_TYPE,
        "schemaVersion": 2
    }))
    .unwrap();
    let manifest_digest = format!("sha256:{}", digest_hex(&manifest));
    let binding = CandidateBinding {
        reference: format!("ghcr.io/automata-ci/automata-service-proxy@{manifest_digest}"),
        candidate_provenance_sha256: "33".repeat(32),
        config_digest: config_digest.clone(),
        image_digest: manifest_digest.clone(),
        image_name: "ghcr.io/automata-ci/automata-service-proxy".to_owned(),
        oci_archive_sha256: "44".repeat(32),
        sha256: "55".repeat(32),
        source_provenance_sha256: "66".repeat(32),
    };
    let reference = binding.local_reference(local_repository);
    let digest_reference = format!("{local_repository}@{manifest_digest}");
    let config_name = format!(
        "blobs/sha256/{}",
        config_digest.strip_prefix("sha256:").unwrap()
    );
    let manifest_name = format!(
        "blobs/sha256/{}",
        manifest_digest.strip_prefix("sha256:").unwrap()
    );
    let layer_name = format!("blobs/sha256/{}", diff_id.strip_prefix("sha256:").unwrap());
    let index = serde_json::to_vec(&serde_json::json!({
        "manifests": [{
            "annotations": {(OCI_REFERENCE_ANNOTATION): &reference},
            "digest": &manifest_digest,
            "mediaType": OCI_MANIFEST_MEDIA_TYPE,
            "size": manifest.len()
        }],
        "mediaType": OCI_INDEX_MEDIA_TYPE,
        "schemaVersion": 2
    }))
    .unwrap();
    let archive = build_docker_load_archive(
        BTreeMap::from([
            (config_name, config),
            (manifest_name, manifest),
            (layer_name.clone(), layer.clone()),
            ("index.json".to_owned(), index),
            (
                "oci-layout".to_owned(),
                br#"{"imageLayoutVersion":"1.0.0"}"#.to_vec(),
            ),
        ]),
        ValidatedCandidateLayers {
            payload: BTreeMap::new(),
            docker_layer_names: vec![layer_name.clone()],
            expanded_blobs: BTreeMap::from([(layer_name, layer)]),
        },
        &binding,
        &reference,
        epoch,
        20_480,
    )
    .unwrap();

    let docker =
        std::env::var("AUTOMATA_LOCAL_INIT_TEST_DOCKER").unwrap_or_else(|_| "docker".to_owned());
    assert!(
        Command::new(&docker)
            .args(["version", "--format", "{{.Server.Version}}"])
            .status()
            .unwrap()
            .success(),
        "live Docker must be explicitly available"
    );
    let exact_references = vec![
        reference.clone(),
        digest_reference.clone(),
        manifest_digest.clone(),
        config_digest.clone(),
    ];
    for exact in &exact_references {
        assert!(
            !Command::new(&docker)
                .args(["image", "inspect", exact])
                .output()
                .unwrap()
                .status
                .success(),
            "live qualification refuses to mutate a preexisting exact fixture"
        );
    }

    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap();
    let scratch = workspace.join("target/task-tmp/automata-ci-local");
    fs::create_dir_all(&scratch).unwrap();
    let archive_path = scratch.join(format!(
        "automata-local-init-portable-image-{}.tar",
        std::process::id()
    ));
    fs::write(&archive_path, archive).unwrap();
    let mut cleanup = Cleanup {
        docker: docker.clone(),
        references: exact_references.clone(),
        archive: archive_path.clone(),
    };
    assert!(
        Command::new(&docker)
            .args(["load", "--input"])
            .arg(&archive_path)
            .status()
            .unwrap()
            .success(),
        "Docker must load the derived portable archive"
    );
    let output = Command::new(&docker)
        .args(["image", "inspect", "--format", "{{json .}}", &reference])
        .output()
        .unwrap();
    assert!(output.status.success());
    let inspected: Value = serde_json::from_slice(&output.stdout).unwrap();
    let imported_id = inspected.get("Id").and_then(Value::as_str).unwrap();
    let operating_system = inspected.get("Os").and_then(Value::as_str).unwrap();
    let architecture = inspected
        .get("Architecture")
        .and_then(Value::as_str)
        .unwrap();
    let live_config = inspected.get("Config").unwrap();
    let repository_tags: Vec<String> =
        serde_json::from_value(inspected.get("RepoTags").unwrap().clone()).unwrap();
    let repository_digests: Vec<String> =
        serde_json::from_value(inspected.get("RepoDigests").unwrap().clone()).unwrap();
    assert_eq!(repository_tags.as_slice(), std::slice::from_ref(&reference));
    match imported_id {
        id if id == config_digest => assert!(repository_digests.is_empty()),
        id if id == manifest_digest => {
            assert_eq!(
                repository_digests.as_slice(),
                std::slice::from_ref(&digest_reference)
            );
        }
        other => panic!("unexpected Docker image ID {other}"),
    }

    let expected_process = serde_json::json!({
        "command": ["true"],
        "entrypoint": [],
        "required_environment": {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        },
        "required_labels": {},
        "user": "",
        "working_directory": "/"
    });
    let catalog = VerifiedCatalog {
        bytes_sha256: Sha256Digest::from_bytes([0x77; 32]),
        release,
        profile: ProfileBinding {
            id: "fixture".to_owned(),
            manifest_sha256: Sha256Digest::from_bytes([0x88; 32]),
            lock_sha256: Sha256Digest::from_bytes([0x99; 32]),
        },
        images: BTreeMap::from([(
            "service-proxy".to_owned(),
            VerifiedImage {
                canonical_repository: local_repository.to_owned(),
                config: expected_process,
                runtime: Value::Null,
                source: ImageSource::Candidate(binding),
            },
        )]),
        maximum_parallel_jobs: 1,
        human_port: 8080,
        results_port: 8081,
        runner_control_port: 9090,
    };
    catalog
        .validate_live_image(
            "service-proxy",
            &LiveImageEvidence {
                image_id: imported_id,
                operating_system,
                architecture,
                config: live_config,
                repository_tags: Some(&repository_tags),
                repository_digests: Some(&repository_digests),
            },
        )
        .unwrap();
    cleanup.remove();
    for exact in &exact_references {
        assert!(
            !Command::new(&docker)
                .args(["image", "inspect", exact])
                .output()
                .unwrap()
                .status
                .success(),
            "live qualification must remove every exact fixture identity"
        );
    }
}
