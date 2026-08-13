use std::{cell::Cell, collections::BTreeMap, fmt::Write as _};

use automata_ci_conformance::{
    AdmissionOutcome, AvailabilityReason, ContentLock, EvidenceAvailability, EvidenceClass,
    EvidenceEnvelope, EvidenceError, EvidenceMismatchKind, EvidenceProvenance,
    ExternalPrerequisite, FixtureCatalog, FixtureCatalogEntry, FixtureProvider, OperatingSystem,
    PrerequisiteState, ProductBuildIdentity, RawWebhookFixture, RawWebhookFixtureError,
    RepositorySourceLock, ScenarioAdmission, compare_evidence,
};
use serde::ser::SerializeStruct as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

fn digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn sort_json_objects(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(sort_json_objects).collect()),
        Value::Object(values) => {
            let mut sorted = values.into_iter().collect::<Vec<_>>();
            sorted.sort_unstable_by(|left, right| left.0.cmp(&right.0));
            Value::Object(
                sorted
                    .into_iter()
                    .map(|(key, value)| (key, sort_json_objects(value)))
                    .collect(),
            )
        }
        scalar => scalar,
    }
}

fn canonical_evidence_digest<T: Serialize>(evidence: &T) -> String {
    let value = serde_json::to_value(evidence).expect("evidence value");
    let bytes = serde_json::to_vec(&sort_json_objects(value)).expect("canonical evidence");
    let mut encoded = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut encoded, "{byte:02x}").expect("writing to String");
    }
    encoded
}

fn fixture_catalog<T: Serialize>(
    evidence: &T,
    class: EvidenceClass,
    external_prerequisites: Vec<ExternalPrerequisite>,
) -> FixtureCatalog {
    FixtureCatalog::new(vec![FixtureCatalogEntry {
        id: "fixture".to_owned(),
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
        actions: Vec::new(),
        operating_system: OperatingSystem::Linux,
        provider: FixtureProvider::Github,
        evidence_class: class,
        external_prerequisites,
        expected_evidence_sha256: canonical_evidence_digest(evidence),
    }])
    .expect("fixture catalog")
}

fn provenance(catalog: &FixtureCatalog) -> EvidenceProvenance {
    EvidenceProvenance {
        suite_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        build: ProductBuildIdentity {
            automata_commit: "89abcdef0123456789abcdef0123456789abcdef".to_owned(),
            source_tree_clean: true,
            automata_binary_sha256: digest('a'),
            runner_binary_sha256: digest('b'),
            profile_manifest_sha256: digest('d'),
            profile_image_digest: format!("sha256:{}", digest('e')),
            database_image_digest: format!("sha256:{}", digest('f')),
            object_store_image_digest: format!("sha256:{}", digest('1')),
            protocol_version: 1,
            job_ir_schema_version: 1,
            runner_requirements_schema_version: 1,
            conformance_export_schema_version: 2,
            fixture_schema_version: 3,
        },
        fixture_catalog_sha256: catalog.canonical_sha256().expect("catalog digest"),
        fixture_id: "fixture".to_owned(),
        scenario_id: "push".to_owned(),
        shard_id: "shard-000".to_owned(),
        provider: "github".to_owned(),
        operating_system: "linux".to_owned(),
        architecture: "x86_64".to_owned(),
    }
}

#[test]
fn admission_is_bound_to_every_catalog_prerequisite() {
    let catalog = fixture_catalog(
        &serde_json::json!({"ok": true}),
        EvidenceClass::LiveGithub,
        vec![
            ExternalPrerequisite {
                identity: "github-app".to_owned(),
                immutable_revision: "installation:42".to_owned(),
            },
            ExternalPrerequisite {
                identity: "mirror-repository".to_owned(),
                immutable_revision: "repository:42".to_owned(),
            },
        ],
    );
    let fixture = &catalog.entries()[0];
    assert!(matches!(
        ScenarioAdmission::for_fixture(fixture, Vec::new()),
        Err(EvidenceError::PrerequisiteSetMismatch)
    ));
    assert!(matches!(
        ScenarioAdmission::for_fixture(
            fixture,
            vec![
                (
                    "github-app".to_owned(),
                    PrerequisiteState::Available {
                        immutable_revision: "installation:43".to_owned(),
                    },
                ),
                (
                    "mirror-repository".to_owned(),
                    PrerequisiteState::Available {
                        immutable_revision: "repository:42".to_owned(),
                    },
                ),
            ],
        ),
        Err(EvidenceError::PrerequisiteRevisionMismatch)
    ));

    let admission = ScenarioAdmission::for_fixture(
        fixture,
        vec![
            (
                "github-app".to_owned(),
                PrerequisiteState::Unavailable {
                    reason: "credential not configured".to_owned(),
                },
            ),
            (
                "mirror-repository".to_owned(),
                PrerequisiteState::Available {
                    immutable_revision: "repository:42".to_owned(),
                },
            ),
        ],
    )
    .expect("catalog-bound admission");
    assert_eq!(admission.fixture_id(), "fixture");
    assert_eq!(
        admission
            .evaluate(EvidenceClass::LiveGithub)
            .expect("admission"),
        AdmissionOutcome::Skipped {
            missing: vec!["github-app".to_owned()]
        }
    );
    assert!(matches!(
        admission.evaluate(EvidenceClass::ProviderEmulator),
        Err(EvidenceError::EvidenceClassMismatch)
    ));
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Evidence {
    step_outputs: EvidenceAvailability<BTreeMap<String, String>>,
}

#[derive(Deserialize, Serialize)]
struct OutOfOrderEvidence {
    zeta: u8,
    alpha: u8,
}

struct SequencedEvidence(Cell<u8>);

impl Serialize for SequencedEvidence {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let call = self.0.get();
        self.0.set(call + 1);
        let mut state = serializer.serialize_struct("SequencedEvidence", 1)?;
        state.serialize_field("value", if call < 2 { "locked" } else { "mutated" })?;
        state.end()
    }
}

#[test]
fn missing_step_outputs_are_not_synthesized_as_empty() {
    let evidence = Evidence {
        step_outputs: EvidenceAvailability::unavailable(AvailabilityReason::NotRetainedBySchema),
    };
    let catalog = fixture_catalog(&evidence, EvidenceClass::HermeticProduct, Vec::new());
    let envelope = EvidenceEnvelope::for_fixture(&catalog, provenance(&catalog), evidence)
        .expect("bound envelope");
    let json = serde_json::to_value(&envelope).expect("JSON");
    assert_eq!(json["evidence"]["stepOutputs"]["state"], "unavailable");
    assert!(json["evidence"]["stepOutputs"].get("value").is_none());
}

#[test]
fn envelope_is_canonical_and_bound_to_catalog_provenance_and_expected_evidence() {
    let evidence = Evidence {
        step_outputs: EvidenceAvailability::present(BTreeMap::from([(
            "digest".to_owned(),
            "public".to_owned(),
        )])),
    };
    let catalog = fixture_catalog(&evidence, EvidenceClass::ProviderEmulator, Vec::new());
    let envelope =
        EvidenceEnvelope::for_fixture(&catalog, provenance(&catalog), evidence).expect("envelope");
    assert_eq!(envelope.canonical_sha256().expect("digest").len(), 64);
    let bytes = envelope.canonical_json().expect("canonical JSON");
    assert_eq!(
        envelope,
        EvidenceEnvelope::<Evidence>::from_json(&catalog, &bytes).expect("round trip")
    );

    let out_of_order = OutOfOrderEvidence { zeta: 2, alpha: 1 };
    let second_catalog = fixture_catalog(&out_of_order, EvidenceClass::Contract, Vec::new());
    let out_of_order =
        EvidenceEnvelope::for_fixture(&second_catalog, provenance(&second_catalog), out_of_order)
            .expect("out-of-order envelope");
    let canonical = String::from_utf8(out_of_order.canonical_json().expect("canonical JSON"))
        .expect("UTF-8 JSON");
    assert!(canonical.contains(r#""evidence":{"alpha":1,"zeta":2}"#));

    let mut json = serde_json::to_value(&envelope).expect("JSON");
    json["schemaVersion"] = serde_json::json!(2);
    assert!(matches!(
        EvidenceEnvelope::<Evidence>::from_json(
            &catalog,
            &serde_json::to_vec(&json).expect("JSON")
        ),
        Err(EvidenceError::UnsupportedSchema(2))
    ));
    json["schemaVersion"] = serde_json::json!(1);
    json["provenance"]["fixtureCatalogSha256"] = serde_json::json!(digest('9'));
    assert!(matches!(
        EvidenceEnvelope::<Evidence>::from_json(
            &catalog,
            &serde_json::to_vec(&json).expect("JSON")
        ),
        Err(EvidenceError::CatalogDigestMismatch)
    ));
    assert!(matches!(
        EvidenceEnvelope::<Evidence>::from_json(
            &catalog,
            &serde_json::to_vec_pretty(&serde_json::to_value(&envelope).expect("value"))
                .expect("pretty")
        ),
        Err(EvidenceError::NonCanonicalEncoding)
    ));
}

#[test]
fn canonical_serialization_uses_the_exact_value_that_was_digest_checked() {
    let evidence = SequencedEvidence(Cell::new(0));
    let catalog = fixture_catalog(&evidence, EvidenceClass::Contract, Vec::new());
    evidence.0.set(0);
    let envelope = EvidenceEnvelope::for_fixture(&catalog, provenance(&catalog), evidence)
        .expect("initial evidence matches catalog");
    let bytes = envelope
        .canonical_json()
        .expect("single checked serialization");
    assert!(
        String::from_utf8(bytes)
            .expect("UTF-8")
            .contains(r#""value":"locked""#)
    );
    assert_eq!(envelope.evidence().0.get(), 2);
}

#[test]
fn structural_evidence_comparison_never_coerces_or_ignores_fields() {
    let expected = serde_json::json!({
        "outputs": {"state": "unavailable", "reason": "not_produced"},
        "steps": [1, 2]
    });
    let missing = serde_json::json!({"steps": [1, 2]});
    let error = compare_evidence(&expected, &missing).expect_err("missing output must differ");
    assert!(matches!(
        error,
        EvidenceError::EvidenceMismatch(ref mismatch)
            if mismatch.path == "$/outputs"
                && mismatch.kind == EvidenceMismatchKind::MissingField
    ));

    let wrong_type = serde_json::json!({
        "outputs": {"state": "unavailable", "reason": "not_produced"},
        "steps": [1, "2"]
    });
    assert!(matches!(
        compare_evidence(&expected, &wrong_type),
        Err(EvidenceError::EvidenceMismatch(ref mismatch))
            if mismatch.path == "$/steps[1]"
                && mismatch.kind == EvidenceMismatchKind::TypeMismatch
    ));

    let extra = serde_json::json!({
        "outputs": {"state": "unavailable", "reason": "not_produced"},
        "steps": [1, 2],
        "invented": true
    });
    assert!(matches!(
        compare_evidence(&expected, &extra),
        Err(EvidenceError::EvidenceMismatch(ref mismatch))
            if mismatch.path == "$/invented"
                && mismatch.kind == EvidenceMismatchKind::UnexpectedField
    ));
}

#[test]
fn null_cannot_stand_in_for_explicit_unavailability() {
    let evidence = serde_json::json!({"outputs": null});
    let catalog = fixture_catalog(&evidence, EvidenceClass::Contract, Vec::new());
    assert!(matches!(
        EvidenceEnvelope::for_fixture(&catalog, provenance(&catalog), evidence),
        Err(EvidenceError::ImplicitUnavailableEvidence)
    ));
}

#[test]
fn raw_webhook_locks_exact_body_signature_and_canonical_encoding() {
    let body = br#"{"ref":"refs/heads/main"}"#.to_vec();
    let fixture = RawWebhookFixture::new(
        "push",
        "delivery-1",
        format!("sha256={}", digest('a')),
        body.clone(),
    )
    .expect("webhook");
    assert_eq!(fixture.body(), body);
    assert_eq!(fixture.body_sha256().len(), 64);
    assert_eq!(fixture.delivery_id(), "delivery-1");
    assert_eq!(fixture.event(), "push");
    let canonical = fixture.canonical_json().expect("canonical webhook");
    assert_eq!(
        fixture,
        RawWebhookFixture::from_json(&canonical).expect("validated round trip")
    );
    let mut forged: serde_json::Value = serde_json::from_slice(&canonical).expect("value");
    forged["bodySha256"] = serde_json::json!(digest('0'));
    let mut forged = serde_json::to_vec(&forged).expect("forged JSON");
    forged.push(b'\n');
    assert_eq!(
        RawWebhookFixture::from_json(&forged),
        Err(RawWebhookFixtureError::BodyDigestMismatch)
    );
    assert_eq!(
        RawWebhookFixture::new("push", "delivery-1", "sha256=main", body),
        Err(RawWebhookFixtureError::InvalidSignature)
    );
}
