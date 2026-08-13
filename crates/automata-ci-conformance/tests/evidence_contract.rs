use std::collections::BTreeMap;

use automata_ci_conformance::{
    AdmissionOutcome, AvailabilityReason, EvidenceAvailability, EvidenceClass, EvidenceEnvelope,
    EvidenceError, EvidenceProvenance, PrerequisiteState, ProductBuildIdentity, RawWebhookFixture,
    RawWebhookFixtureError, ScenarioAdmission,
};
use serde::{Deserialize, Serialize};

fn provenance() -> EvidenceProvenance {
    EvidenceProvenance {
        suite_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        build: ProductBuildIdentity {
            automata_commit: "89abcdef0123456789abcdef0123456789abcdef".to_owned(),
            source_tree_clean: true,
            automata_binary_sha256: "a".repeat(64),
            runner_binary_sha256: "b".repeat(64),
            profile_manifest_sha256: "d".repeat(64),
            profile_image_digest: format!("sha256:{}", "e".repeat(64)),
            database_image_digest: format!("sha256:{}", "f".repeat(64)),
            object_store_image_digest: format!("sha256:{}", "1".repeat(64)),
            protocol_version: 1,
            job_ir_schema_version: 1,
            runner_requirements_schema_version: 1,
            conformance_export_schema_version: 2,
            fixture_schema_version: 3,
        },
        fixture_catalog_sha256: "c".repeat(64),
        fixture_id: "chalk".to_owned(),
        scenario_id: "push".to_owned(),
        shard_id: "shard-000".to_owned(),
        provider: "github".to_owned(),
        operating_system: "linux".to_owned(),
        architecture: "x86_64".to_owned(),
    }
}

#[test]
fn missing_live_prerequisites_skip_explicitly_and_never_pass() {
    let admission = ScenarioAdmission {
        required_class: EvidenceClass::LiveGithub,
        prerequisites: vec![
            (
                "github-app".to_owned(),
                PrerequisiteState::Unavailable {
                    reason: "credential not configured".to_owned(),
                },
            ),
            (
                "mirror-repository".to_owned(),
                PrerequisiteState::Available {
                    immutable_revision: "repository-42".to_owned(),
                },
            ),
        ],
    };
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

#[derive(Serialize)]
struct OutOfOrderEvidence {
    zeta: u8,
    alpha: u8,
}

#[test]
fn missing_step_outputs_are_not_synthesized_as_empty() {
    let evidence = Evidence {
        step_outputs: EvidenceAvailability::unavailable(AvailabilityReason::NotRetainedBySchema),
    };
    let envelope = EvidenceEnvelope::new(EvidenceClass::HermeticProduct, provenance(), evidence)
        .expect("envelope");
    let json = serde_json::to_value(&envelope).expect("JSON");
    assert_eq!(json["evidence"]["stepOutputs"]["state"], "unavailable");
    assert!(json["evidence"]["stepOutputs"].get("value").is_none());
}

#[test]
fn evidence_class_is_immutable_and_foreign_schemas_fail_closed() {
    let envelope = EvidenceEnvelope::new(
        EvidenceClass::ProviderEmulator,
        provenance(),
        Evidence {
            step_outputs: EvidenceAvailability::present(BTreeMap::from([(
                "digest".to_owned(),
                "public".to_owned(),
            )])),
        },
    )
    .expect("envelope");
    assert_eq!(envelope.canonical_sha256().expect("digest").len(), 64);
    let out_of_order = EvidenceEnvelope::new(
        EvidenceClass::Contract,
        provenance(),
        OutOfOrderEvidence { zeta: 2, alpha: 1 },
    )
    .expect("out-of-order envelope");
    let canonical = String::from_utf8(out_of_order.canonical_json().expect("canonical JSON"))
        .expect("UTF-8 JSON");
    assert!(canonical.contains(r#""evidence":{"alpha":1,"zeta":2}"#));
    let mut json = serde_json::to_value(&envelope).expect("JSON");
    json["schemaVersion"] = serde_json::json!(2);
    assert!(matches!(
        EvidenceEnvelope::<Evidence>::from_json(&serde_json::to_vec(&json).expect("JSON")),
        Err(EvidenceError::UnsupportedSchema(2))
    ));
}

#[test]
fn raw_webhook_locks_exact_body_and_signature() {
    let body = br#"{"ref":"refs/heads/main"}"#.to_vec();
    let fixture = RawWebhookFixture::new(
        "push",
        "delivery-1",
        format!("sha256={}", "a".repeat(64)),
        body.clone(),
    )
    .expect("webhook");
    assert_eq!(fixture.body(), body);
    assert_eq!(fixture.body_sha256().len(), 64);
    assert_eq!(fixture.delivery_id(), "delivery-1");
    assert_eq!(fixture.event(), "push");
    assert_eq!(
        RawWebhookFixture::new("push", "delivery-1", "sha256=main", body),
        Err(RawWebhookFixtureError::InvalidSignature)
    );
}
