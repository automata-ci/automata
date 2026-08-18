use std::{fmt::Write as _, fs, path::Path, path::PathBuf};

use sha2::{Digest as _, Sha384};

use crate::migration::MIGRATOR;

const FROZEN_MIGRATIONS: &[(&str, &str)] = &[
    (
        "0001_baseline_routines_01.sql",
        "a88f5c285d9d0286eb5f9d3812c06e254ff22ded8041b014ce666f73c29436d92f2ba0ec3633fdb59d779da6918e7a2a",
    ),
    (
        "0002_baseline_routines_02.sql",
        "4c898ae75d418faa47c31ad38b55369130c571ddcc6b7961112d9ee024faaa04e329ba8741b872f59a65608fe3e8dda3",
    ),
    (
        "0003_baseline_routines_03.sql",
        "6094bc86a6b041c70c8cfd3e04d202bf03272e94b39ea7131b61e7c67e30a6bb307a89771a3325e4a15a2b215237381f",
    ),
    (
        "0004_baseline_routines_04.sql",
        "e4161674d25811f9da1e1f6152ad6eb9c1086edb85e3f3791588450c1678105b0a799b3780c8272b4f8ad9eb364017be",
    ),
    (
        "0005_baseline_routines_05.sql",
        "4f796ebcfcf8390bf9b40843fe25e91bb935ac29730959cbee0830d2e96bbb8175253fc32ffbbc25792bb5894a7398f4",
    ),
    (
        "0006_baseline_routines_06.sql",
        "57d00fe6cd4a68825eeea8b964a28801bfba2c4e13b8b8112e1cec5b5ec655fe15b3e236e03fa8add09945ced1534625",
    ),
    (
        "0007_baseline_routines_07.sql",
        "39206936cadbfabef47a775440353367eaa1e9737f3a79c4da360c71511093f0c5e2c4fcb42b67a133d6f93ea4d333b7",
    ),
    (
        "0008_baseline_routines_08.sql",
        "bd208061cc3d0c296656fd50514fbbf6b2bca8eb6d7b8e07d25c2892923295f4b63348383b1b0fed8656c5d04da51def",
    ),
    (
        "0009_baseline_routines_09.sql",
        "4e1a8df6e6a29b5aa5faf1e501b33336db04e8bcc18cffe473b969f4bb5c7921f257cbf4e3093c370f11d3e49560ced1",
    ),
    (
        "0010_baseline_routines_10.sql",
        "5e1c67bd3d713fc9521d147a31fd0965c18f2f86ee27f4ac899c0db239e33f3d11e212ee6004877aa2c7c59b23229a86",
    ),
    (
        "0011_baseline_routines_11.sql",
        "92de743ed564db5d9abf3600c6c1e5f1c219b4a8cd8650a73683dc9c89cab30f87eead7526718388276a4f6545476c7c",
    ),
    (
        "0012_baseline_routines_12.sql",
        "22fe7a4a46350513482df3c314e700c0bc677087edbcb6510cbf45e9ed6020fb7ed6f30da0fb9a5bc8755e83a04f5042",
    ),
    (
        "0013_baseline_routines_13.sql",
        "83830f456686e1c70e489035dca32ab3591a653a3052c5153760a4a41df7b27155b4b7c93cbb3826e357a0f7d09a36e9",
    ),
    (
        "0014_baseline_routines_14.sql",
        "660156bf9bea050692a63cef6a7e945b8d8644ae03cf4993d6282b3c838b1db198af8ec190b927e47c82a089436dd387",
    ),
    (
        "0015_baseline_routines_15.sql",
        "04721f411fc6aa8aaba893b879d7a1ec42ed49d1d95bdfe0966db2584bc502cc55955dca8573ec3f0bb4ce4bd43336d0",
    ),
    (
        "0016_baseline_routines_16.sql",
        "d61dafdca2d3484583642b6f1faa7730b0f104ac46243c617e32f2ab89c1082557e309f727ea2ed5692947dbd415033d",
    ),
    (
        "0017_baseline_relations_execution.sql",
        "9d80766241d5b07160607c4e90fcd30d9ee2ac341e89576f1033fd7072e466c0364a10a4479e8eb919bb39979a1603b9",
    ),
    (
        "0018_baseline_relations_auth_and_delivery.sql",
        "5f9baeeea0fa3fa3c3abac2846b0228a8076a63b9dadb7fb8a6a203ec45021258574b1f81f587c396599058eb6c0a99b",
    ),
    (
        "0019_baseline_relations_access_runners_and_secrets.sql",
        "e6b47696f5959411fb0b63704044eab3c5f10b9ee8727a92e669179bd7b9abc20392c3f370c5e5c1e6709ede5e1a25b7",
    ),
    (
        "0020_baseline_relations_tenants_and_workflows.sql",
        "6245e235c08bd6ccd7aa1bc7d99ca003633bf3951b79f239f1b0710a3eba783ba86dd36970e7999ea15a67c08c110a61",
    ),
    (
        "0021_baseline_catalog_rows.sql",
        "44f3fe98a0d5df90196fac954b67fc321d5ddde3aec32a1e23804415ea96379e3775a76a718be6264aeef79f78bb6cc3",
    ),
    (
        "0022_baseline_keys_and_constraints.sql",
        "811561232385a17a9630e8534d98e0538af044ce0ec09f3abddb33a992301245264ceaf16831a92056c2bd82843340d7",
    ),
    (
        "0023_baseline_indexes.sql",
        "9b45a8ae13c283e0b42848782e912df82b0712b9cfdccf7656260cd23151ad27520e2c6e9ed9b65d70a98ca4ab338b59",
    ),
    (
        "0024_baseline_triggers_control_plane.sql",
        "b297b80748236be8b1bb1c1793de1d24be4b24bddb1ae628a93cca616457027658fc582c0560500e7331ce02e0a6a7ef",
    ),
    (
        "0025_baseline_triggers_orchestration.sql",
        "fae94404f5fcdb6283ea690189bf5fcebd46bcaefe11f030029851670d6da3281da0bf089a0abab3f58d69e0005247e5",
    ),
    (
        "0026_baseline_foreign_keys.sql",
        "57e7e93dcdc0ee7568393785b30774259dcf5300f9a8df99ac7795d9799c60b97dec36479976ae99e5c4bd320080a977",
    ),
    (
        "0027_workspace_usage_feed.sql",
        "23d9d52552f960e0b8015cedacf8bbe591773dbb82856e73eb4e436c4840be5475887da0ebbe6330185fee13f835734f",
    ),
    (
        "0028_allow_queued_cancellation_after_lease_retry.sql",
        "4841124d150802cd51308c78f1f9607e9ca04c4b077e08eb89936ed5aa7ab527fc1add96b34bb95b0825286191a17d0e",
    ),
    (
        "0029_align_artifact_protocol_version.sql",
        "00d51644b2bed927c55fbd7bfa6ba84efe66526d59adb0accd3ab2b4b27d11fec73a62e6d4ae7af159a0b2c522e2eea2",
    ),
    (
        "0030_finalize_expired_lease_claims.sql",
        "68a3755eb8e238649342c7e19a99c467351a6f735cd01a55846e3451e6eabf812ddd922192a3c2a4b9f6fcb3c65cb8a5",
    ),
    (
        "0031_human_live_log_tickets.sql",
        "63fba5e432f071d107bfa0b28859bca6396054890ee2c0f448a4a06b44c323ba1ead27056e1d7d4e60306a54920bc968",
    ),
    (
        "0032_logical_activation_scheduling_policy.sql",
        "a1344c653b8d8b115265dfbe92caab6e4253167d68ee3cf996e368dfaffa7c39f61e7a81cd437bf73d11c7ce86ea2a7f",
    ),
    (
        "0033_github_workflow_permission_defaults.sql",
        "0725af95c311d20f756f738e8828ed178f043c6e4fdf503f01bf3d82530c6d966319811f3a55a4ab8d20d28cf15b9b56",
    ),
    (
        "0034_event_trust_control_contracts.sql",
        "dcab5d4aaf66e00528388c84782384156a6817e90de281591072c283c0feeb9282a77b8177c2d9808a92b6100eba2bc5",
    ),
    (
        "0035_workflow_run_trust_snapshots.sql",
        "d089ea8658be480cef856ac775dae5c9612ac9bf2306d0a636938398c6f79bc88f6f11b05e23debd1d165df543fd50d7",
    ),
    (
        "0036_align_github_workflow_limit.sql",
        "91ad604671bb15fa5ae6d593161a443427bfa77e8f50cb6267290f919742d15793659c94318044371d5e6bf22b51a9e7",
    ),
    (
        "0037_runtime_authority_deliveries.sql",
        "bf752f9a883c773e4f1ea10f9290f2b41a0ab44db50f7b7d68874014f88c0343fc223ac9948ed11c64b7748deb3a26a0",
    ),
    (
        "0038_restore_github_manifest_digest_part.sql",
        "02fda663c53f99897dfc8671541df9120fd5e9d196f0536c6e1d5dad5515935d8afd8ff196f7f8947f5c3d8be8ef97fa",
    ),
    (
        "0039_qualify_workflow_permission_guard.sql",
        "2dc845db52210db4a44a41232845bb7e5ddff10663b8977ce087f6699b80376e5643f7b09b880446abc6a4beced44d80",
    ),
    (
        "0040_provider_delivery_event_envelope.sql",
        "939ba465bb389fbe4c3ed2066e4e86cd46102664e35451ea182af3f49d10e142fcdc046c1f957c28d9eb1747309793e0",
    ),
    (
        "0041_private_pull_request_files_authority.sql",
        "a458499937bd5133caeee8271f961e0d8c96e2db9d58ac0cd538ed1e6f99687aa03cdae3ea111bbe526a18075d56d5ba",
    ),
    (
        "0042_github_provider_desired_state.sql",
        "5276d0877686f09d9c05c50b4675c2b82a9b93588d7865f3e4910d1daf7d39bd01c2826eb15edfcfd41b42e14269df98",
    ),
    (
        "0043_terminalize_expired_active_leases.sql",
        "b4caf908ce785d736293e16c864320e9ea098e3cc76843539e91339f85c859f1482f57609ed865060e43aad0183c0ce1",
    ),
    (
        "0044_publish_runner_redacted_logs.sql",
        "c507be6b296266570b3a3d35708c95376ebb1fd07f8bcbbf1bf40ef1d4bbcf058dfbde58e4c02992100a8d13d27e17fc",
    ),
    (
        "0045_runner_certificate_renewal.sql",
        "ee79d5ee0481d72ba62d527da49817cf97b8340203ec8fa8be2cc0abcf615fade1f5854bf155487535666cd956e1181a",
    ),
    (
        "0046_github_actions_cache_garbage.sql",
        "be9b180b7b989138962eb7e9f945611ecc2a6da1d7c89a2addf79c3651075f0e73f2e63c4492395788ce1a699df9b4ad",
    ),
    (
        "0047_workflow_runtime_runner_feature_policy.sql",
        "20d15f4f2c8280a1dd5c87be8fd4d0fedd50a9c77f97eee1ef7f3bec845996aede57145e2ef294bff0b35c449f103b38",
    ),
    (
        "0048_windows_runner_admission.sql",
        "a80284bf98fcbbdd2516fdddbfd17ecd0981f8dc41fc874f670718e740ff702239a73695ad0a942af2275893b23994ca",
    ),
    (
        "0049_delegated_workflow_dispatch.sql",
        "df17f7d6396ca08d57594ca0411301a9ed3ea4d8c8e8d3f9acae5aba2592bff5ba0a7c26a78766bc23106d9a9f3d6f0c",
    ),
    (
        "0050_structured_live_logs.sql",
        "43e00572f617031aff81bcfb6711c9712a6b755038bc6f662a6f801665eadbc4069178d57642cc14b8b25f1cf08939dd",
    ),
    (
        "0051_provider_configuration_registry.sql",
        "314b9c9aa3ab29764b579c1e61f2fa33dedee2acd7e6198838fc00f74643774230fd4bf1b45a614d2288ae0ad6bcdf2c",
    ),
    (
        "0052_canonical_git_object_ids.sql",
        "c3cfa4f85f13f8385bf6edd2c997018eb6e8542dc01a0821456d1caf33d062d404bc902810429315318c40a305feb0cc",
    ),
    (
        "0053_provider_delivery_foundation.sql",
        "52a3ab7e1e78fedee448882f0f400f3b4ae9ef0accf02b2f990543fdacb261a3f280774ba7787f4a9a1c4cd99c0d93f1",
    ),
    (
        "0054_provider_neutral_workload_oidc.sql",
        "6bcb92936a5882ee9d085e8bef4da2c95903d0e75860d08dd52a140c18b94351dccb4263e0f0dd40964b337c3101dc53",
    ),
];

const BASELINE_MIGRATION_COUNT: u32 = 26;
const MAX_MIGRATION_LINES: usize = 2_000;

#[test]
fn applied_migration_lineage_is_frozen() {
    let migrations = migration_paths();
    assert!(
        !MIGRATOR.ignore_missing,
        "the deployed migrator must reject missing applied versions"
    );
    assert_eq!(
        migrations.len(),
        FROZEN_MIGRATIONS.len(),
        "append each new migration to the frozen inventory; never remove an applied migration"
    );
    assert_eq!(
        MIGRATOR.iter().count(),
        FROZEN_MIGRATIONS.len(),
        "the embedded migrator must contain the complete frozen inventory"
    );

    for (index, ((path, embedded), (expected_name, expected_checksum))) in migrations
        .iter()
        .zip(MIGRATOR.iter())
        .zip(FROZEN_MIGRATIONS)
        .enumerate()
    {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("migration file name is UTF-8");
        let version = u32::try_from(index + 1).expect("migration count fits u32");
        assert_eq!(file_name, *expected_name, "applied migration was renamed");
        assert_eq!(migration_version(path), version);
        assert_eq!(embedded.version, i64::from(version));

        let source = fs::read(path).expect("read migration bytes");
        let checksum = Sha384::digest(source);
        assert_eq!(
            checksum_hex(&checksum),
            *expected_checksum,
            "applied migration {file_name} changed; restore its exact bytes and append a new migration"
        );
        assert_eq!(
            embedded.checksum.as_ref(),
            &checksum[..],
            "embedded migration {file_name} differs from its source bytes"
        );
    }
}

#[test]
fn migrations_are_bounded_and_the_baseline_is_explicit() {
    let migrations = migration_paths();

    assert!(
        migrations.len() >= BASELINE_MIGRATION_COUNT as usize,
        "the complete split baseline must be present"
    );
    for (index, path) in migrations.iter().enumerate() {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("migration file name is UTF-8");
        let version = migration_version(path);
        assert_eq!(
            version,
            u32::try_from(index + 1).expect("migration count fits u32"),
            "migrations use gap-free sequential versions"
        );
        if version <= BASELINE_MIGRATION_COUNT {
            assert!(
                file_name.contains("_baseline_"),
                "baseline migration {file_name} must be named explicitly"
            );
        }

        let source = fs::read_to_string(path).expect("read migration source");
        let lines = source.lines().count();
        assert!(
            lines <= MAX_MIGRATION_LINES,
            "migration {file_name} has {lines} lines; maximum is {MAX_MIGRATION_LINES}"
        );
    }
}

#[test]
fn logical_activation_scheduling_policy_is_relationally_exact() {
    let source = include_str!("../migrations/0032_logical_activation_scheduling_policy.sql");

    for required in [
        "ADD COLUMN scheduling_policy_schema smallint NOT NULL",
        "ADD COLUMN requested_max_parallel bigint",
        "ADD COLUMN effective_max_parallel integer NOT NULL",
        "CHECK (scheduling_policy_schema = 1)",
        "requested_max_parallel BETWEEN 1 AND 4294967295",
        "instance_count = 0 AND effective_max_parallel = 0",
        "instance_count > 0",
        "effective_max_parallel BETWEEN 1 AND instance_count",
        "requested_max_parallel IS NULL",
        "effective_max_parallel = instance_count",
        "requested_max_parallel IS NOT NULL",
        "effective_max_parallel = LEAST(requested_max_parallel, instance_count)",
    ] {
        assert!(
            source.contains(required),
            "logical scheduling-policy migration lost required contract: {required}"
        );
    }
}

#[test]
fn github_workflow_limit_matches_the_product_manifest_contract() {
    let source = include_str!("../migrations/0036_align_github_workflow_limit.sql");

    for required in [
        "DROP CONSTRAINT github_provider_manifest_revisions_archive_limits",
        "ADD CONSTRAINT github_provider_manifest_revisions_archive_limits",
        "workflow_max_bytes = 512000",
    ] {
        assert!(
            source.contains(required),
            "GitHub workflow-limit migration lost required contract: {required}"
        );
    }

    assert_eq!(
        automata_ci_store::GITHUB_PROVIDER_WORKFLOW_MAX_BYTES,
        512_000,
        "product and durable GitHub workflow byte limits diverged"
    );
}

#[test]
fn runtime_authority_delivery_is_post_accept_exact_and_value_free() {
    let source = include_str!("../migrations/0037_runtime_authority_deliveries.sql");

    for required in [
        "CREATE TABLE runner_runtime_authority_deliveries",
        "DROP CONSTRAINT runner_sessions_protocol_current",
        "ADD CONSTRAINT runner_sessions_protocol_known",
        "CHECK (protocol_version IN (1, 2))",
        "PRIMARY KEY (attempt_id, fencing_token, delivery_generation)",
        "UNIQUE (runner_session_id, request_operation_id)",
        "CHECK (delivery_generation = 1)",
        "CHECK (protocol_version = 2)",
        "job_id uuid NOT NULL",
        "run_id uuid NOT NULL",
        "job_ir_schema integer NOT NULL",
        "job_ir_size_bytes bigint NOT NULL",
        "octet_length(job_ir_digest) = 32",
        "job_ir_object_key text NOT NULL",
        "octet_length(request_digest) = 32",
        "octet_length(bundle_digest) = 32",
        "acknowledgement_operation_id IS NULL",
        "acknowledgement_digest IS NULL",
        "acknowledged_at_ms IS NULL",
        "acknowledged_at_ms >= committed_at_ms",
        "lease_offer_publications_runtime_authority_binding_unique",
        "runner_command_outbox_authority_binding_unique",
        "runtime_authority_deliveries_exact_offer_publication",
        "runtime_authority_deliveries_exact_offer_command",
        "REFERENCES runner_lease_offer_publications",
        "REFERENCES runner_command_outbox",
    ] {
        assert!(
            source.contains(required),
            "runtime-authority migration lost required contract: {required}"
        );
    }

    for forbidden in [
        "runner_runtime_authority_deliveries_attempt_fkey",
        "runner_runtime_authority_deliveries_session_fence",
        "runner_runtime_authority_deliveries_offer_publication",
        "runner_runtime_authority_deliveries_offer_command",
    ] {
        assert!(
            !source.contains(forbidden),
            "runtime-authority migration must not use independent existence-only binding: {forbidden}"
        );
    }

    for forbidden in [
        "credential bytea",
        "token bytea",
        "secret bytea",
        "payload bytea",
        "response bytea",
        "ciphertext bytea",
        "wrapped_data_key",
        "nonce bytea",
    ] {
        assert!(
            !source.contains(forbidden),
            "runtime-authority migration must not persist grant material: {forbidden}"
        );
    }
}

#[test]
fn provider_delivery_event_envelope_is_complete_bounded_and_legacy_nullable() {
    let source = include_str!("../migrations/0040_provider_delivery_event_envelope.sql");

    for required in [
        "ADD COLUMN event_envelope_schema SMALLINT",
        "ADD COLUMN event_registry_schema SMALLINT",
        "ADD COLUMN event_envelope_digest BYTEA",
        "ADD COLUMN event_envelope_bytes BYTEA",
        "ADD COLUMN event_envelope_media_type TEXT COLLATE \"C\"",
        "CONSTRAINT provider_delivery_inbox_event_envelope_complete CHECK",
        "event_envelope_schema IS NULL",
        "event_registry_schema IS NULL",
        "event_envelope_digest IS NULL",
        "event_envelope_bytes IS NULL",
        "event_envelope_media_type IS NULL",
        "event_envelope_schema IS NOT NULL",
        "event_registry_schema IS NOT NULL",
        "event_envelope_digest IS NOT NULL",
        "event_envelope_bytes IS NOT NULL",
        "event_envelope_media_type IS NOT NULL",
        "event_envelope_schema > 0",
        "event_registry_schema > 0",
        "octet_length(event_envelope_digest) = 32",
        "octet_length(event_envelope_bytes) BETWEEN 1 AND 32768",
        "octet_length(event_envelope_media_type) BETWEEN 1 AND 128",
        "event_envelope_media_type LIKE '%/%'",
        "event_envelope_media_type ~ '^[!-~]+$'",
        "event_envelope_media_type !~ '[[:space:][:cntrl:];]'",
        ") NOT VALID",
        "VALIDATE CONSTRAINT provider_delivery_inbox_event_envelope_complete",
        "CREATE OR REPLACE FUNCTION automata_enforce_provider_delivery_lifecycle()",
        "NEW.event_envelope_schema IS DISTINCT FROM OLD.event_envelope_schema",
        "NEW.event_registry_schema IS DISTINCT FROM OLD.event_registry_schema",
        "NEW.event_envelope_digest IS DISTINCT FROM OLD.event_envelope_digest",
        "NEW.event_envelope_bytes IS DISTINCT FROM OLD.event_envelope_bytes",
        "NEW.event_envelope_media_type IS DISTINCT FROM OLD.event_envelope_media_type",
        "OLD.event_envelope_schema IS NULL",
        "OLD.state IN ('pending', 'retry', 'claimed')",
        "NEW.state = 'rejected'",
        "NEW.claim_fence <> OLD.claim_fence + 1",
        "NEW.attempt_count <> GREATEST(OLD.attempt_count, 1)",
        "IS DISTINCT FROM 'provider_delivery.legacy_unsealed'",
        "CONSTRAINT = 'provider_delivery_inbox_legacy_unsealed_transition'",
    ] {
        assert!(
            source.contains(required),
            "provider-delivery envelope migration lost required contract: {required}"
        );
    }

    assert_eq!(
        automata_ci_store::MAX_PROVIDER_DELIVERY_EVENT_ENVELOPE_BYTES,
        32_768,
        "product and durable provider-envelope byte limits diverged"
    );
}

#[test]
fn runner_certificate_renewal_is_bounded_exact_and_immutable_while_replayable() {
    let source = include_str!("../migrations/0045_runner_certificate_renewal.sql");

    for required in [
        "UNIQUE (runner_id, leaf_sha256)",
        "CREATE TABLE runner_certificate_renewal_receipts",
        "operation_id uuid PRIMARY KEY",
        "UNIQUE (presented_leaf_sha256)",
        "UNIQUE (renewed_leaf_sha256)",
        "octet_length(response) BETWEEN 1 AND 524288",
        "FOREIGN KEY (runner_id, presented_leaf_sha256)",
        "FOREIGN KEY (runner_id, renewed_leaf_sha256)",
        "REFERENCES security_audit_events (event_id)",
        "runner_certificate_renewal_receipts_immutable",
        "runner_certificate_renewal_receipts_live_delete",
        "BEFORE TRUNCATE ON runner_certificate_renewal_receipts",
    ] {
        assert!(
            source.contains(required),
            "runner-certificate renewal migration lost required contract: {required}"
        );
    }
    for forbidden in ["IF NOT EXISTS", "DEFAULT", "ON DELETE CASCADE"] {
        assert!(
            !source.contains(forbidden),
            "runner-certificate renewal migration retained compatibility surface: {forbidden}"
        );
    }
}

#[test]
fn github_actions_cache_garbage_is_exact_bounded_and_durable() {
    let source = include_str!("../migrations/0046_github_actions_cache_garbage.sql");

    for required in [
        "CREATE TABLE github_actions_cache_garbage",
        "object_key text PRIMARY KEY",
        "octet_length(digest) = 32",
        "size_bytes BETWEEN 0 AND 134217728",
        "queued_at_seconds >= 0",
        "CREATE INDEX gha_cache_garbage_order",
        "(queued_at_seconds, object_key)",
    ] {
        assert!(
            source.contains(required),
            "cache-garbage migration lost required contract: {required}"
        );
    }
    for forbidden in ["IF NOT EXISTS", "ON DELETE", "DEFAULT"] {
        assert!(
            !source.contains(forbidden),
            "cache-garbage migration retained compatibility surface: {forbidden}"
        );
    }
}

#[test]
fn workflow_runtime_runner_feature_policy_is_relationally_exact() {
    let source = include_str!("../migrations/0047_workflow_runtime_runner_feature_policy.sql");

    for required in [
        "ADD COLUMN runner_feature_schema smallint",
        "ADD COLUMN runner_feature_count integer NOT NULL DEFAULT 0",
        "runner_feature_schema IS NULL AND runner_feature_count = 0",
        "runner_feature_schema = 1 AND runner_feature_count BETWEEN 0 AND 64",
        "policy_schema IN (1, 2)",
        "CREATE TABLE workflow_runtime_policy_runner_features",
        "workflow_runtime_policy_runner_features_pk PRIMARY KEY",
        "workflow_runtime_policy_runner_features_mapping_fk FOREIGN KEY",
        "feature IN (",
        "'automata.core/node24-actions@v1'",
        "automata_require_staging_workflow_runtime_runner_feature()",
        "automata_reject_workflow_runtime_policy_retained_mutation()",
        "CREATE OR REPLACE FUNCTION automata_workflow_runtime_policy_canonical",
        "CREATE OR REPLACE FUNCTION automata_workflow_runtime_policy_digest",
        "WHEN 1 THEN container.runner_feature_schema IS NULL",
        "WHEN 2 THEN container.runner_feature_schema = 1",
        "'runner-features'",
        "runner.actual_feature_count = container.runner_feature_count",
        "runner.profile_exact",
    ] {
        assert!(
            source.contains(required),
            "runner-feature policy migration lost required contract: {required}"
        );
    }
    assert!(
        !source.contains(
            "FOR EACH ROW EXECUTE FUNCTION automata_require_staging_workflow_runtime_policy();"
        ),
        "runner features must not reuse the container-feature census trigger"
    );
}

#[test]
fn structured_live_logs_are_a_current_only_destructive_cutover() {
    let source = include_str!("../migrations/0050_structured_live_logs.sql");

    for required in [
        "DELETE FROM human_live_log_tickets",
        "DELETE FROM attempt_log_streams",
        "WHERE log_schema <> 2",
        "DROP CONSTRAINT attempt_log_streams_schema_range",
        "ADD CONSTRAINT attempt_log_streams_schema_current",
        "CHECK (log_schema = 2)",
        "CHECK (protocol_version = 2)",
    ] {
        assert!(
            source.contains(required),
            "structured-log migration lost hard-cutover contract: {required}"
        );
    }
    for forbidden in ["IF NOT EXISTS", "IN (1, 2)"] {
        assert!(
            !source.contains(forbidden),
            "structured-log migration retained compatibility surface: {forbidden}"
        );
    }
}

#[test]
fn canonical_git_object_ids_are_a_forward_only_exact_transition() {
    let source = include_str!("../migrations/0052_canonical_git_object_ids.sql");

    assert_eq!(
        source
            .matches("ALTER COLUMN source_revision TYPE bytea")
            .count(),
        5,
        "every persisted textual Git revision must transition exactly once",
    );
    for required in [
        "DROP CONSTRAINT github_schedule_check_evidence_registry",
        "DROP CONSTRAINT event_subject_selections_digest_canonical",
        "DROP CONSTRAINT event_control_subjects_tenant_id_subject_id_selection_dige_fkey",
        "DROP CONSTRAINT event_subject_progress_tenant_id_subject_id_selection_dige_fkey",
        "DROP TRIGGER event_subject_selections_immutable ON event_subject_selections",
        "DROP TRIGGER event_control_subjects_immutable ON event_control_subjects",
        "DROP TRIGGER event_subject_progress_immutable ON event_subject_progress",
        "DROP VIEW github_workflow_run_manifest_origins",
        "DROP VIEW github_workflow_run_base_manifest_origins",
        "DROP FUNCTION automata_event_subject_selection_digest(",
        "USING pg_catalog.decode(source_revision, 'hex')",
        "octet_length(source_revision) = ANY (ARRAY[20, 32])",
        "CREATE OR REPLACE FUNCTION automata_github_check_subject_insert_guard()",
        "CREATE OR REPLACE FUNCTION automata_github_schedule_check_evidence_insert_guard()",
        "CREATE OR REPLACE FUNCTION automata_validate_reusable_workflow_expansion()",
        "CREATE OR REPLACE FUNCTION automata_guard_provider_delivery_workflow_inventory()",
        "UPDATE event_subject_selections",
        "UPDATE event_control_subjects AS control",
        "UPDATE event_subject_progress AS progress",
        "SET selection_digest = selection.selection_digest",
        "ADD CONSTRAINT event_control_subjects_tenant_id_subject_id_selection_dige_fkey",
        "ADD CONSTRAINT event_subject_progress_tenant_id_subject_id_selection_dige_fkey",
        "CREATE TRIGGER event_subject_selections_immutable",
        "CREATE TRIGGER event_control_subjects_immutable",
        "CREATE TRIGGER event_subject_progress_immutable",
        "CREATE VIEW github_workflow_run_base_manifest_origins AS",
        "CREATE VIEW github_workflow_run_manifest_origins AS",
    ] {
        assert!(
            source.contains(required),
            "canonical Git object migration lost required contract: {required}",
        );
    }
    for forbidden in [
        " CASCADE",
        "DROP VIEW IF EXISTS",
        "DROP FUNCTION IF EXISTS",
        "DROP CONSTRAINT IF EXISTS",
        "ADD CONSTRAINT IF NOT EXISTS",
    ] {
        assert!(
            !source.contains(forbidden),
            "canonical Git object migration retained ambiguous transition surface: {forbidden}",
        );
    }
}

fn migration_paths() -> Vec<PathBuf> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let mut migrations = fs::read_dir(directory)
        .expect("read PostgreSQL migrations")
        .map(|entry| entry.expect("read migration entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "sql"))
        .collect::<Vec<_>>();
    migrations.sort_by_key(|path| migration_version(path));
    migrations
}

fn checksum_hex(checksum: &[u8]) -> String {
    let mut encoded = String::with_capacity(checksum.len() * 2);
    for byte in checksum {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn migration_version(path: &Path) -> u32 {
    path.file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.split_once('_'))
        .and_then(|(version, _description)| version.parse().ok())
        .expect("migration starts with a numeric version")
}
