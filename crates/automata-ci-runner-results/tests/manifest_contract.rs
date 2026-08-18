use automata_ci_runner_results::{
    ARTIFACT_MANIFEST_MEDIA_TYPE, ARTIFACT_MANIFEST_SCHEMA_VERSION, ArtifactManifest,
    ArtifactManifestBlock, MAXIMUM_ARTIFACT_MANIFEST_BYTES,
};

const UPLOAD_ID: &str = "018f8f4a-54f2-7a8d-9d3a-7f5bd5f6f501";
const RUN_ID: &str = "018f8f4a-54f2-7a8d-9d3a-7f5bd5f6f502";
const JOB_ID: &str = "018f8f4a-54f2-7a8d-9d3a-7f5bd5f6f503";
const ATTEMPT_ID: &str = "018f8f4a-54f2-7a8d-9d3a-7f5bd5f6f504";
const CONTENT_DIGEST: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const BLOCK_DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn representative_manifest() -> ArtifactManifest {
    ArtifactManifest {
        schema: 1,
        artifact_id: i64::MAX,
        upload_id: UPLOAD_ID.to_owned(),
        run_id: RUN_ID.to_owned(),
        job_id: JOB_ID.to_owned(),
        attempt_id: ATTEMPT_ID.to_owned(),
        fencing_token: u64::MAX,
        name: "linux-release-x86_64".to_owned(),
        mime_type: "application/gzip".to_owned(),
        size: u64::MAX - 1,
        sha256: CONTENT_DIGEST.to_owned(),
        blocks: vec![ArtifactManifestBlock {
            block_id: "MDAwMDAwMDA=".to_owned(),
            object_key: "artifacts/immutable/block-00000000".to_owned(),
            size: u64::MAX,
            sha256: BLOCK_DIGEST.to_owned(),
            media_type: "application/octet-stream".to_owned(),
        }],
    }
}

#[test]
fn canonical_manifest_round_trips_without_losing_identifiers_or_large_integers() {
    let manifest = representative_manifest();
    let encoded = serde_json::to_vec(&manifest).expect("manifest serialization");
    let expected = r#"{"schema":1,"artifact_id":9223372036854775807,"upload_id":"018f8f4a-54f2-7a8d-9d3a-7f5bd5f6f501","run_id":"018f8f4a-54f2-7a8d-9d3a-7f5bd5f6f502","job_id":"018f8f4a-54f2-7a8d-9d3a-7f5bd5f6f503","attempt_id":"018f8f4a-54f2-7a8d-9d3a-7f5bd5f6f504","fencing_token":18446744073709551615,"name":"linux-release-x86_64","mime_type":"application/gzip","size":18446744073709551614,"sha256":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789","blocks":[{"block_id":"MDAwMDAwMDA=","object_key":"artifacts/immutable/block-00000000","size":18446744073709551615,"sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","media_type":"application/octet-stream"}]}"#;

    assert_eq!(encoded, expected.as_bytes());

    let decoded: ArtifactManifest =
        serde_json::from_slice(&encoded).expect("manifest deserialization");
    assert_eq!(decoded, manifest);
    assert_eq!(decoded.artifact_id, i64::MAX);
    assert_eq!(decoded.fencing_token, u64::MAX);
    assert_eq!(decoded.size, u64::MAX - 1);
    assert_eq!(decoded.upload_id, UPLOAD_ID);
    assert_eq!(decoded.run_id, RUN_ID);
    assert_eq!(decoded.job_id, JOB_ID);
    assert_eq!(decoded.attempt_id, ATTEMPT_ID);
    assert_eq!(decoded.sha256, CONTENT_DIGEST);
    assert_eq!(decoded.blocks[0].size, u64::MAX);
    assert_eq!(decoded.blocks[0].sha256, BLOCK_DIGEST);
    assert_eq!(
        serde_json::to_vec(&decoded).expect("round-trip serialization"),
        encoded
    );
}

#[test]
fn manifest_and_block_reject_unknown_fields() {
    let encoded = serde_json::to_string(&representative_manifest()).expect("manifest JSON");
    let manifest_with_unknown_field = format!(
        "{},\"unexpected\":true}}",
        encoded.strip_suffix('}').expect("manifest object")
    );
    let block_with_unknown_field = encoded.replacen(
        r#""media_type":"application/octet-stream""#,
        r#""media_type":"application/octet-stream","unexpected":true"#,
        1,
    );

    assert!(serde_json::from_str::<ArtifactManifest>(&manifest_with_unknown_field).is_err());
    assert!(serde_json::from_str::<ArtifactManifest>(&block_with_unknown_field).is_err());
}

#[test]
fn artifact_manifest_reader_rejects_noncurrent_schema_versions() {
    for schema in [0, ARTIFACT_MANIFEST_SCHEMA_VERSION + 1] {
        let mut manifest = representative_manifest();
        manifest.schema = schema;
        assert!(manifest.validate_schema().is_err());
    }
    assert!(representative_manifest().validate_schema().is_ok());
}

#[test]
fn exported_manifest_media_type_and_size_ceiling_are_stable() {
    assert_eq!(
        ARTIFACT_MANIFEST_MEDIA_TYPE,
        "application/vnd.automata.artifact-manifest+json"
    );
    assert_eq!(MAXIMUM_ARTIFACT_MANIFEST_BYTES, 1024 * 1024);
}
