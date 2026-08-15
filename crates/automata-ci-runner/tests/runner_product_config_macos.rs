#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use automata_ci_core::SandboxFeature;
use automata_ci_runner::product::{RunnerProductConfig, RunnerProductConfigError};

fn baseline() -> serde_json::Value {
    serde_json::from_slice(include_bytes!("../config/runner.macos.example.json"))
        .expect("checked-in macOS runner configuration JSON")
}

fn parse(value: &serde_json::Value) -> Result<RunnerProductConfig, RunnerProductConfigError> {
    RunnerProductConfig::from_json(
        &serde_json::to_vec(value).expect("serialize mutated macOS configuration"),
    )
}

#[test]
fn legacy_schema_and_native_provider_are_rejected() {
    let mut schema_one = baseline();
    schema_one["schema_version"] = serde_json::json!(1);
    assert!(
        parse(&schema_one).is_err(),
        "schema v1 must not be migrated"
    );

    let mut native = baseline();
    native
        .as_object_mut()
        .expect("configuration object")
        .remove("macos_virtualization");
    native["macos_native"] = serde_json::json!({});
    assert!(parse(&native).is_err(), "macos_native must be unknown");
}

#[test]
fn macos_vm_does_not_advertise_the_windows_hyperv_container_launch_kind() {
    let config = parse(&baseline()).expect("checked-in macOS runner configuration");
    assert!(
        !config
            .inventory()
            .sandbox()
            .features()
            .contains(&SandboxFeature::WINDOWS_HYPERV_CONTAINER)
    );
}

#[test]
fn macos_configuration_rejects_every_weaker_boundary() {
    let mut no_provider = baseline();
    no_provider
        .as_object_mut()
        .expect("configuration object")
        .remove("macos_virtualization");
    assert_eq!(
        parse(&no_provider).expect_err("a provider is required"),
        RunnerProductConfigError::InvalidProvider
    );

    for (field, invalid) in [
        ("network", serde_json::json!("private_egress")),
        ("network", serde_json::json!("host")),
        ("root_filesystem", serde_json::json!("read_only")),
        ("root_filesystem", serde_json::json!("host")),
        ("privilege", serde_json::json!("host")),
        ("privilege", serde_json::json!("administrator")),
    ] {
        let mut value = baseline();
        value["executor"][field] = invalid;
        assert_eq!(
            parse(&value).expect_err("macOS VM isolation policy is mandatory"),
            RunnerProductConfigError::InvalidExecutor
        );
    }

    let mut parallel = baseline();
    parallel["inventory"]["max_parallel_jobs"] = serde_json::json!(2);
    assert_eq!(
        parse(&parallel).expect_err("one template provider is one-slot"),
        RunnerProductConfigError::InvalidInventory
    );

    let mut fractional_cpu = baseline();
    fractional_cpu["executor"]["resources"]["cpu_millis"] = serde_json::json!(1500);
    fractional_cpu["inventory"]["resources_per_job"]["cpu_millis"] = serde_json::json!(1500);
    assert_eq!(
        parse(&fractional_cpu).expect_err("Virtualization.framework uses whole vCPUs"),
        RunnerProductConfigError::InvalidProvider
    );

    let mut javascript = baseline();
    javascript["executor"]["toolchain"]["node20"] = serde_json::json!("/usr/local/bin/node");
    assert_eq!(
        parse(&javascript).expect_err("JavaScript actions are not supported"),
        RunnerProductConfigError::InvalidExecutor
    );

    for field in ["ephemeral_disk_bytes", "gpu_count"] {
        let mut value = baseline();
        value["executor"]["resources"][field] = serde_json::json!(1);
        value["inventory"]["resources_per_job"][field] = serde_json::json!(1);
        assert!(parse(&value).is_err(), "nonzero {field} must fail closed");
    }
}

#[test]
fn macos_template_and_state_boundaries_are_pinned_and_disjoint() {
    let mut digest_mismatch = baseline();
    digest_mismatch["macos_virtualization"]["template_manifest_sha256"] =
        serde_json::json!("66".repeat(32));
    assert_eq!(
        parse(&digest_mismatch).expect_err("profile and template pins must match"),
        RunnerProductConfigError::InvalidProvider
    );

    let mut guest_overlap = baseline();
    guest_overlap["executor"]["runner_root"] =
        serde_json::json!("/Users/automata-job/workspaces/runner");
    assert_eq!(
        parse(&guest_overlap).expect_err("guest roots must be disjoint"),
        RunnerProductConfigError::InvalidInventory
    );

    let mut state_overlap = baseline();
    state_overlap["state"]["journal"] = serde_json::json!("/Volumes/AutomataVM/state/journal");
    assert_eq!(
        parse(&state_overlap).expect_err("durable and provider roots cannot overlap"),
        RunnerProductConfigError::InvalidStateRoots
    );

    let mut mutable_helper = baseline();
    mutable_helper["macos_virtualization"]["helper_executable"] =
        serde_json::json!("/Volumes/AutomataVM/state/helper");
    assert_eq!(
        parse(&mutable_helper).expect_err("helper cannot reside in writable state"),
        RunnerProductConfigError::InvalidProvider
    );

    for invalid_uuid in ["not-a-uuid", "01234567-89AB-CDEF-0123-456789ABCDEG"] {
        let mut invalid_storage = baseline();
        invalid_storage["macos_virtualization"]["storage_volume_uuid"] =
            serde_json::json!(invalid_uuid);
        assert_eq!(
            parse(&invalid_storage).expect_err("storage UUID must be exact"),
            RunnerProductConfigError::InvalidProvider
        );
    }

    for invalid_quota in [
        63 * 1024 * 1024 * 1024_u64,
        256 * 1024 * 1024 * 1024_u64 + 1,
        1025 * 1024 * 1024 * 1024_u64,
    ] {
        let mut invalid_storage = baseline();
        invalid_storage["macos_virtualization"]["storage_quota_bytes"] =
            serde_json::json!(invalid_quota);
        assert_eq!(
            parse(&invalid_storage).expect_err("storage quota must be bounded whole GiB"),
            RunnerProductConfigError::InvalidProvider
        );
    }

    for weak_requirement in [
        "identifier \"dev.automata.macos-vm-helper\" and anchor apple generic",
        "identifier \"dev.automata.macos-vm-helper\" or anchor apple generic and certificate leaf[subject.OU] = \"ABCDEFGHIJ\"",
    ] {
        let mut weak_helper = baseline();
        weak_helper["macos_virtualization"]["helper_code_requirement"] =
            serde_json::json!(weak_requirement);
        assert_eq!(
            parse(&weak_helper).expect_err("helper signature requirement must be conjunctive"),
            RunnerProductConfigError::InvalidProvider
        );
    }
}
