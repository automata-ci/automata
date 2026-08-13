use automata_ci_conformance::{
    CatalogError, ContentLock, EvidenceClass, ExternalPrerequisite, FixtureCatalog,
    FixtureCatalogEntry, FixtureProvider, OperatingSystem, RepositorySourceLock,
};

fn digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn entry(id: &str, class: EvidenceClass) -> FixtureCatalogEntry {
    FixtureCatalogEntry {
        id: id.to_owned(),
        upstream_version: "actions-runner-2.330.0".to_owned(),
        source: RepositorySourceLock {
            remote: "https://github.com/example/project.git".to_owned(),
            commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            archive_sha256: digest('a'),
        },
        workflows: vec![ContentLock {
            identity: ".github/workflows/ci.yml".to_owned(),
            sha256: digest('b'),
        }],
        actions: vec![ContentLock {
            identity: "actions/checkout@v4".to_owned(),
            sha256: digest('c'),
        }],
        operating_system: OperatingSystem::Linux,
        provider: FixtureProvider::Github,
        evidence_class: class,
        external_prerequisites: Vec::new(),
        expected_evidence_sha256: digest('d'),
    }
}

#[test]
fn catalog_has_stable_canonical_bytes_and_digest() {
    let catalog = FixtureCatalog::new(vec![
        entry("chalk-push", EvidenceClass::HermeticProduct),
        entry("testify-push", EvidenceClass::LiveGithub),
    ])
    .expect("catalog");
    let bytes = catalog.canonical_json().expect("canonical JSON");
    assert_eq!(bytes.last(), Some(&b'\n'));
    assert_eq!(
        catalog,
        FixtureCatalog::from_json(&bytes).expect("round trip")
    );
    assert_eq!(catalog.canonical_sha256().expect("digest").len(), 64);
}

#[test]
fn catalog_rejects_mutability_drift_and_ambiguous_order() {
    let mut mutable = entry("mutable", EvidenceClass::LiveGithub);
    mutable.source.commit = "main".to_owned();
    assert!(matches!(
        FixtureCatalog::new(vec![mutable]),
        Err(CatalogError::InvalidCommit)
    ));

    let duplicate = entry("same", EvidenceClass::Contract);
    assert!(matches!(
        FixtureCatalog::new(vec![duplicate.clone(), duplicate]),
        Err(CatalogError::EntriesNotSorted)
    ));

    let mut unsorted_locks = entry("locks", EvidenceClass::Contract);
    unsorted_locks.workflows = vec![
        ContentLock {
            identity: "z.yml".to_owned(),
            sha256: digest('e'),
        },
        ContentLock {
            identity: "a.yml".to_owned(),
            sha256: digest('f'),
        },
    ];
    assert!(matches!(
        FixtureCatalog::new(vec![unsorted_locks]),
        Err(CatalogError::LocksNotSorted)
    ));

    let mut unsorted_prerequisites = entry("prerequisites", EvidenceClass::LiveAutomata);
    unsorted_prerequisites.external_prerequisites = vec![
        ExternalPrerequisite {
            identity: "zeta".to_owned(),
            immutable_revision: "revision-1".to_owned(),
        },
        ExternalPrerequisite {
            identity: "alpha".to_owned(),
            immutable_revision: "revision-2".to_owned(),
        },
    ];
    assert!(matches!(
        FixtureCatalog::new(vec![unsorted_prerequisites]),
        Err(CatalogError::PrerequisitesNotSorted)
    ));
}

#[test]
fn hermetic_evidence_cannot_claim_live_prerequisites() {
    let mut hermetic = entry("hermetic", EvidenceClass::HermeticProduct);
    hermetic.external_prerequisites.push(ExternalPrerequisite {
        identity: "github-app".to_owned(),
        immutable_revision: "installation-42".to_owned(),
    });
    assert!(matches!(
        FixtureCatalog::new(vec![hermetic]),
        Err(CatalogError::HermeticFixtureHasExternalPrerequisite)
    ));

    let mut live = entry("live", EvidenceClass::LiveAutomata);
    live.external_prerequisites.push(ExternalPrerequisite {
        identity: "github-app".to_owned(),
        immutable_revision: "installation-42".to_owned(),
    });
    FixtureCatalog::new(vec![live]).expect("live prerequisite remains explicit");
}

#[test]
fn unknown_and_foreign_schema_fields_fail_closed() {
    let catalog =
        FixtureCatalog::new(vec![entry("fixture", EvidenceClass::Contract)]).expect("catalog");
    let mut json: serde_json::Value =
        serde_json::from_slice(&catalog.canonical_json().expect("JSON")).expect("value");
    json["schemaVersion"] = serde_json::json!(2);
    assert!(matches!(
        FixtureCatalog::from_json(&serde_json::to_vec(&json).expect("JSON")),
        Err(CatalogError::UnsupportedSchema(2))
    ));
    json["schemaVersion"] = serde_json::json!(1);
    json["unknown"] = serde_json::json!(true);
    assert!(matches!(
        FixtureCatalog::from_json(&serde_json::to_vec(&json).expect("JSON")),
        Err(CatalogError::Json(_))
    ));
}
