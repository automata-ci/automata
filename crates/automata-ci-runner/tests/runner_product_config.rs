#![cfg(target_os = "linux")]

use automata_ci_core::{
    Architecture, ContainerFeature, OperatingSystem, ResourceCapacity, RunnerFeature,
    RunnerRequirements, SandboxFeature, Sha256Digest,
};
use automata_ci_execution::SandboxPrivilegePolicy;
use automata_ci_runner::product::{
    RUNNER_PRODUCT_CONFIG_SCHEMA_VERSION, RunnerProductConfig, RunnerProductConfigError,
};
#[cfg(unix)]
use std::{fs, os::unix::fs::PermissionsExt as _, path::PathBuf};

#[cfg(unix)]
use automata_ci_core::OperationId;
#[cfg(unix)]
use automata_ci_runner::product::{RunnerProductError, load_spool_keyring};

const RUNNER_ID: &str = "6e561f8b-9098-418d-b573-d82f5c73006e";
const MAX_DECRYPT_ONLY_CONTENT_KEYS: usize = 8;
const PROFILE_ID: &str = "automata.dev/github-hosted-ubuntu-24-04-x64-v1";
const PROFILE_DIGEST: &str = "f7a6f8e592a484f59330bf2cedd839adc75488618ee58efcc3c3d4957d186e21";
const IMAGE: &str = "ghcr.io/automata-ci/automata-ubuntu-24.04-x64@sha256:e2c20ad25ff71fb61d9609e84daf8384a122b8f26a047836ac50d832c632e194";
const SERVICE_PROXY_IMAGE: &str = "registry.example.test/automata/service-proxy@sha256:4d7a838e047d65bbf708d4fc315db9b3b91ae73c0d50459b519089c0713ff34b";
const BUILDKIT_RUNTIME_IMAGE: &str = "registry.example.test/buildkit/runtime@sha256:7777777777777777777777777777777777777777777777777777777777777777";

#[allow(clippy::too_many_lines)] // One canonical JSON fixture keeps cross-field defaults coherent.
fn valid_configuration() -> String {
    format!(
        r#"{{
  "schema_version": {RUNNER_PRODUCT_CONFIG_SCHEMA_VERSION},
  "runner_id": "{RUNNER_ID}",
  "control_endpoint": "https://127.0.0.1:8443/",
  "state": {{
    "journal": "/home/runner/automata-state/journal",
    "spool": "/home/runner/automata-state/spool",
    "podman": "/run/automata-runner/automata-ci-podman/state"
  }},
  "tls": {{
    "server_roots": {{"kind": "file", "path": "/home/runner/secrets/server-ca.pem"}},
    "certificate_chain": {{"kind": "file", "path": "/home/runner/secrets/runner.pem"}},
    "private_key": {{"kind": "environment", "name": "AUTOMATA_RUNNER_TLS_KEY_PEM"}}
  }},
  "spool": {{
    "protection_id": "runner-key-v1",
    "key_hex": {{"kind": "environment", "name": "AUTOMATA_RUNNER_SPOOL_KEY_HEX"}}
  }},
  "inventory": {{
    "labels": ["self-hosted", "linux", "x64", "ubuntu-24.04"],
    "groups": ["default"],
    "max_parallel_jobs": 2,
    "resources_per_job": {{
      "cpu_millis": 4000,
      "memory_bytes": 17179869184,
      "ephemeral_disk_bytes": 0,
      "pids": 4096
    }},
    "environment_profiles": [{{
      "id": "{PROFILE_ID}",
      "manifest_sha256": "{PROFILE_DIGEST}",
      "image": "{IMAGE}",
      "keepalive_program": "/bin/sleep",
      "keepalive_arguments": ["infinity"],
      "workspace": "/__w",
      "default_environment": {{
        "CARGO_HOME": "/opt/cargo",
        "RUSTUP_HOME": "/opt/rustup"
      }}
    }}]
  }},
  "podman": {{
    "binary": "/usr/bin/podman",
    "home": "/home/runner",
    "runtime_directory": "/run/automata-runner",
    "approved_helper_directory": "/opt/automata/private/usr/sbin",
    "conmon_path": "/usr/bin/conmon",
    "oci_runtime_path": "/usr/bin/crun",
    "init_path": "/usr/bin/catatonit",
    "seccomp_profile_path": "/usr/share/containers/seccomp.json",
    "job_container_engine": "attempt_scoped_docker_api"
  }},
  "executor": {{
    "resources": {{
      "cpu_millis": 4000,
      "memory_bytes": 17179869184,
      "ephemeral_disk_bytes": 0,
      "pids": 4096
    }},
    "network": "private_egress",
    "root_filesystem": "writable",
    "privilege": "administrator",
    "default_step_timeout_seconds": 3600,
    "maximum_output_bytes": 16777216,
    "runner_root": "/__automata",
    "home": "/root",
    "path": "/opt/automata/externals/node24/bin:/opt/cargo/bin:/usr/local/bin:/usr/bin:/bin",
    "temp": "/var/lib/automata-transient",
    "tool_cache": "/opt/hostedtoolcache",
    "toolchain": {{
      "bash": "/usr/bin/bash",
      "sh": "/usr/bin/sh",
      "python": "/usr/bin/python3",
      "pwsh": "/usr/bin/pwsh",
      "install": "/usr/bin/install",
      "tar": "/usr/bin/tar",
      "sha256sum": "/usr/bin/sha256sum",
      "node12": "/__e/node12/bin/node",
      "node16": "/__e/node16/bin/node",
      "node20": "/__e/node20/bin/node",
      "node24": "/__e/node24/bin/node"
    }}
  }},
  "object_store": {{
    "endpoint": "http://127.0.0.1:9000/",
    "region": "us-east-1",
    "bucket": "automata-dev",
    "prefix": "automata/v1",
    "loopback_development": true,
    "tls_trust": {{"mode": "web_pki"}},
    "operation_timeout_seconds": 30,
    "access_key_id": {{"kind": "environment", "name": "AUTOMATA_S3_ACCESS_KEY_ID"}},
    "secret_access_key": {{"kind": "environment", "name": "AUTOMATA_S3_SECRET_ACCESS_KEY"}}
  }},
  "github": {{
    "user_agent": "automata-runner/{version}",
    "server_url": "https://github.com/",
    "api_url": "https://api.github.com/",
    "graphql_url": "https://api.github.com/graphql"
  }}
}}"#,
        version = env!("CARGO_PKG_VERSION"),
    )
}

#[test]
#[allow(clippy::too_many_lines)] // One exact product-inventory contract keeps cross-field assertions together.
fn validated_config_preserves_exact_runner_and_profile_inventory() {
    let config = RunnerProductConfig::from_json(valid_configuration().as_bytes())
        .expect("configuration must validate");

    assert_eq!(config.runner_id().to_string(), RUNNER_ID);
    assert_eq!(
        config.control_endpoint().to_string(),
        "https://127.0.0.1:8443/"
    );
    assert_eq!(config.inventory().max_parallel_jobs(), 2);
    assert_eq!(
        config
            .inventory()
            .resources_per_job()
            .ephemeral_disk_bytes(),
        0,
        "the Podman runner must not advertise an unenforced disk quota"
    );
    let requires_disk =
        RunnerRequirements::default().with_minimum_resources(ResourceCapacity::new(0, 0, 1, 0));
    assert!(
        config.inventory().satisfies(&requires_disk).is_err(),
        "a job requiring ephemeral disk must not match the Podman runner"
    );
    assert!(
        config
            .inventory()
            .labels()
            .iter()
            .any(|label| label.as_str() == "ubuntu-24.04")
    );
    assert_eq!(
        config.inventory().platform().operating_system(),
        &OperatingSystem::Linux
    );
    assert_eq!(
        config.inventory().platform().architecture(),
        &Architecture::X86_64
    );
    assert!(
        config
            .inventory()
            .features()
            .contains(&RunnerFeature::JAVASCRIPT_ACTIONS)
    );
    assert!(
        config
            .inventory()
            .sandbox()
            .features()
            .contains(&SandboxFeature::NETWORK_ISOLATION)
    );
    assert!(
        config
            .inventory()
            .sandbox()
            .features()
            .contains(&SandboxFeature::PRIVILEGED_USER)
    );
    assert!(
        config
            .inventory()
            .containers()
            .features()
            .contains(&ContainerFeature::DOCKER_COMPATIBLE_API)
    );
    assert!(
        !config
            .inventory()
            .sandbox()
            .features()
            .contains(&SandboxFeature::READ_ONLY_ROOT)
    );
    assert!(
        !config
            .inventory()
            .sandbox()
            .features()
            .contains(&SandboxFeature::WINDOWS_HYPERV_CONTAINER)
    );
    assert!(
        config
            .podman()
            .expect("Linux fixture selects Podman")
            .github_server_host_gateway_alias()
            .is_none(),
        "host-gateway routing must remain disabled by default"
    );
    assert_eq!(config.spool().protection_id(), "runner-key-v1");
    assert_eq!(config.spool().decrypt_only_keys().len(), 0);
    assert_eq!(
        config
            .executor()
            .toolchain()
            .python()
            .map(automata_ci_execution::TargetPath::as_str),
        Some("/usr/bin/python3")
    );
    assert_eq!(
        config
            .executor()
            .toolchain()
            .pwsh()
            .map(automata_ci_execution::TargetPath::as_str),
        Some("/usr/bin/pwsh")
    );

    let (profile, environment) = config
        .environments()
        .first_key_value()
        .expect("one exact environment");
    assert_eq!(profile.id().as_str(), PROFILE_ID);
    assert_eq!(profile.digest().to_string(), PROFILE_DIGEST);
    assert_eq!(
        environment.image().expect("container image").reference(),
        IMAGE
    );
    assert_eq!(
        environment
            .keepalive()
            .expect("container keepalive")
            .program()
            .as_str(),
        "/bin/sleep"
    );
    assert_eq!(
        environment
            .keepalive()
            .expect("container keepalive")
            .arguments(),
        ["infinity"]
    );
    assert_eq!(environment.workspace().as_str(), "/__w");
    assert_eq!(
        environment_value(environment, "CARGO_HOME"),
        Some("/opt/cargo")
    );
    assert_eq!(
        environment_value(environment, "RUSTUP_HOME"),
        Some("/opt/rustup")
    );
    assert_eq!(
        profile.digest(),
        PROFILE_DIGEST
            .parse::<Sha256Digest>()
            .expect("digest fixture")
    );
}

#[test]
fn object_store_tls_trust_is_mandatory_current_and_transport_exact() {
    let original: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");

    let mut missing = original.clone();
    missing["object_store"]
        .as_object_mut()
        .expect("object-store object")
        .remove("tls_trust");
    assert_eq!(
        parse_value(&missing).expect_err("TLS trust must be explicit"),
        RunnerProductConfigError::InvalidDocument
    );

    let mut obsolete = original.clone();
    obsolete["schema_version"] = serde_json::json!(3);
    assert_eq!(
        parse_value(&obsolete).expect_err("schema 3 must not be interpreted as current"),
        RunnerProductConfigError::UnsupportedSchema
    );

    for invalid in [
        serde_json::json!({}),
        serde_json::json!({"mode": "private_ca"}),
        serde_json::json!({
            "mode": "web_pki",
            "certificate_source": {"kind": "file", "path": "/run/secrets/s3-ca.pem"}
        }),
        serde_json::json!({"mode": "private-ca", "certificate_source": {"kind": "file", "path": "/run/secrets/s3-ca.pem"}}),
        serde_json::json!({"mode": "private_ca", "certificate_source": "inline CA"}),
    ] {
        let mut changed = original.clone();
        changed["object_store"]["tls_trust"] = invalid;
        assert_eq!(
            parse_value(&changed).expect_err("noncurrent trust shape must fail closed"),
            RunnerProductConfigError::InvalidDocument
        );
    }

    let private_ca = serde_json::json!({
        "mode": "private_ca",
        "certificate_source": {"kind": "file", "path": "/run/secrets/s3-ca.pem"}
    });
    let mut private_https = original.clone();
    private_https["object_store"]["endpoint"] =
        serde_json::json!("https://objects.internal.example/");
    private_https["object_store"]["loopback_development"] = serde_json::json!(false);
    private_https["object_store"]["tls_trust"] = private_ca.clone();
    parse_value(&private_https).expect("exact private CA over HTTPS");

    let mut private_http = original.clone();
    private_http["object_store"]["tls_trust"] = private_ca;
    assert_eq!(
        parse_value(&private_http).expect_err("private CA cannot configure plaintext"),
        RunnerProductConfigError::InvalidObjectStore
    );

    let mut inert_loopback = private_https;
    inert_loopback["object_store"]["tls_trust"] = serde_json::json!({"mode": "web_pki"});
    inert_loopback["object_store"]["loopback_development"] = serde_json::json!(true);
    assert_eq!(
        parse_value(&inert_loopback).expect_err("loopback plaintext mode cannot be inert on HTTPS"),
        RunnerProductConfigError::InvalidObjectStore
    );
}

#[test]
fn spool_rotation_configuration_is_bounded_unique_and_role_explicit() {
    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    value["spool"]["protection_id"] = serde_json::json!("runner-key-v3");
    value["spool"]["decrypt_only"] = serde_json::json!([
        {
            "protection_id": "runner-key-v2",
            "key_hex": {"kind": "environment", "name": "AUTOMATA_RUNNER_SPOOL_KEY_V2_HEX"}
        },
        {
            "protection_id": "runner-key-v1",
            "key_hex": {"kind": "file", "path": "/home/runner/secrets/spool-key-v1.hex"}
        }
    ]);
    let config = parse_value(&value).expect("bounded unique rotation config");
    assert_eq!(config.spool().protection_id(), "runner-key-v3");
    assert_eq!(
        config
            .spool()
            .decrypt_only_keys()
            .map(|(id, _)| id)
            .collect::<Vec<_>>(),
        ["runner-key-v2", "runner-key-v1"]
    );

    for duplicate_ids in [
        vec!["runner-key-v3"],
        vec!["runner-key-v2", "runner-key-v2"],
    ] {
        let mut invalid: serde_json::Value =
            serde_json::from_str(&valid_configuration()).expect("configuration JSON");
        invalid["spool"]["protection_id"] = serde_json::json!("runner-key-v3");
        invalid["spool"]["decrypt_only"] = serde_json::Value::Array(
            duplicate_ids
                .into_iter()
                .enumerate()
                .map(|(index, id)| {
                    serde_json::json!({
                        "protection_id": id,
                        "key_hex": {
                            "kind": "environment",
                            "name": format!("AUTOMATA_RUNNER_OLD_SPOOL_KEY_{index}")
                        }
                    })
                })
                .collect(),
        );
        assert_eq!(
            parse_value(&invalid).expect_err("duplicate key IDs fail closed"),
            RunnerProductConfigError::InvalidSpoolProtection
        );
    }

    let mut invalid_id: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    invalid_id["spool"]["decrypt_only"] = serde_json::json!([{
        "protection_id": "../runner-key-v0",
        "key_hex": {"kind": "environment", "name": "AUTOMATA_RUNNER_OLD_SPOOL_KEY"}
    }]);
    assert_eq!(
        parse_value(&invalid_id).expect_err("path-like old key ID fails closed"),
        RunnerProductConfigError::InvalidSpoolProtection
    );

    let mut oversized: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    oversized["spool"]["decrypt_only"] = serde_json::Value::Array(
        (0..=MAX_DECRYPT_ONLY_CONTENT_KEYS)
            .map(|index| {
                serde_json::json!({
                    "protection_id": format!("runner-key-old-{index}"),
                    "key_hex": {
                        "kind": "environment",
                        "name": format!("AUTOMATA_RUNNER_OLD_SPOOL_KEY_{index}")
                    }
                })
            })
            .collect(),
    );
    assert_eq!(
        parse_value(&oversized).expect_err("old key list must be bounded"),
        RunnerProductConfigError::InvalidSpoolProtection
    );
}

#[cfg(unix)]
#[test]
fn spool_keyring_loading_rejects_any_invalid_old_key_file_without_secret_errors() {
    struct KeyFiles(PathBuf);

    impl KeyFiles {
        fn new() -> Self {
            let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .and_then(std::path::Path::parent)
                .expect("workspace root")
                .to_path_buf();
            let root = workspace
                .join("target")
                .join("runner-keyring-tests")
                .join(OperationId::new().to_string());
            fs::create_dir_all(&root).expect("create key fixture directory");
            Self(fs::canonicalize(root).expect("canonical fixture directory"))
        }

        fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, bytes).expect("write key fixture");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("restrict key fixture");
            path
        }
    }

    impl Drop for KeyFiles {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.0);
        }
    }

    let files = KeyFiles::new();
    let active_path = files.write("active.hex", format!("{}\n", "12".repeat(32)).as_bytes());
    let old_path = files.write("old.hex", format!("{}\r\n", "34".repeat(32)).as_bytes());
    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    value["spool"] = serde_json::json!({
        "protection_id": "runner-key-v2",
        "key_hex": {"kind": "file", "path": active_path},
        "decrypt_only": [{
            "protection_id": "runner-key-v1",
            "key_hex": {"kind": "file", "path": old_path}
        }]
    });
    let config = parse_value(&value).expect("rotation config");
    let keyring = load_spool_keyring(config.spool()).expect("load exact active and old keys");
    assert_eq!(keyring.protection_id().as_str(), "runner-key-v2");
    let old_id = automata_ci_runner_spool::ProtectionId::new("runner-key-v1")
        .expect("valid old protection ID");
    assert!(keyring.supports_protection_id(&old_id));
    let unknown_id = automata_ci_runner_spool::ProtectionId::new("runner-key-unknown")
        .expect("valid unknown protection ID");
    assert!(!keyring.supports_protection_id(&unknown_id));

    let invalid_sentinel = b"invalid-old-spool-key-secret";
    fs::write(&old_path, invalid_sentinel).expect("replace old key with invalid fixture");
    let error = load_spool_keyring(config.spool())
        .err()
        .expect("one invalid old key fails all load");
    assert!(matches!(error, RunnerProductError::InvalidSpoolKey));
    assert!(!format!("{error:?}").contains("invalid-old-spool-key-secret"));
}

#[test]
fn metrics_listener_is_optional_nonzero_and_literal_loopback_only() {
    let disabled = RunnerProductConfig::from_json(valid_configuration().as_bytes())
        .expect("configuration without metrics");
    assert!(
        disabled.metrics().is_none(),
        "metrics must remain disabled when the optional configuration is omitted"
    );

    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    value["metrics"] = serde_json::json!({"listen": "127.0.0.1:9464"});

    let config = parse_value(&value).expect("explicit IPv4 loopback metrics listener");
    let metrics = config.metrics().expect("metrics enabled");
    assert!(metrics.listen().ip().is_loopback());
    assert_eq!(metrics.listen().port(), 9464);

    value["metrics"] = serde_json::json!({"listen": "[::1]:9464"});
    let config = parse_value(&value).expect("explicit IPv6 loopback metrics listener");
    assert!(
        config
            .metrics()
            .expect("metrics enabled")
            .listen()
            .ip()
            .is_loopback()
    );

    for denied in [
        "127.0.0.1:0",
        "[::1]:0",
        "0.0.0.0:9464",
        "192.0.2.8:9464",
        "localhost:9464",
    ] {
        value["metrics"] = serde_json::json!({"listen": denied});
        assert_eq!(
            parse_value(&value).expect_err("metrics listener must fail closed"),
            RunnerProductConfigError::InvalidMetrics
        );
    }

    value["metrics"] = serde_json::json!({
        "listen": "127.0.0.1:9464",
        "runner_id": "must-not-be-a-metric-label"
    });
    assert_eq!(
        parse_value(&value).expect_err("unknown metrics fields must fail closed"),
        RunnerProductConfigError::InvalidDocument
    );
}

#[test]
fn github_host_gateway_opt_in_derives_only_the_exact_validated_server_hostname() {
    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    value["podman"]["map_github_server_to_host_gateway"] = serde_json::Value::Bool(true);
    value["github"]["server_url"] =
        serde_json::Value::String("http://automata-git.invalid:8088/".to_owned());
    value["github"]["api_url"] =
        serde_json::Value::String("http://automata-git.invalid:8088/api/v3/".to_owned());
    value["github"]["graphql_url"] =
        serde_json::Value::String("http://automata-git.invalid:8088/api/graphql".to_owned());
    value["github"]["allow_insecure_http"] = serde_json::Value::Bool(true);

    let config = parse_value(&value).expect("explicit local hostname mapping must validate");
    assert_eq!(
        config
            .podman()
            .expect("Linux fixture selects Podman")
            .github_server_host_gateway_alias()
            .expect("mapping")
            .as_str(),
        config
            .github()
            .server_url()
            .host_str()
            .expect("validated GitHub hostname")
    );
    assert_eq!(
        config
            .podman()
            .expect("Linux fixture selects Podman")
            .github_server_host_gateway_alias()
            .expect("mapping")
            .port(),
        8088
    );

    value["executor"]["network"] = serde_json::json!("disabled");
    assert_eq!(
        parse_value(&value)
            .expect_err("disabled networking must not expose the mapped GitHub transport"),
        RunnerProductConfigError::InvalidGithub
    );
    value["executor"]["network"] = serde_json::json!("private_egress");

    value["podman"]["map_github_server_to_host_gateway"] = serde_json::Value::Bool(false);
    assert_eq!(
        parse_value(&value).expect_err("mapped HTTP requires the explicit Podman gateway opt-in"),
        RunnerProductConfigError::InvalidGithub
    );
    value["podman"]["map_github_server_to_host_gateway"] = serde_json::Value::Bool(true);

    value["github"]["api_url"] =
        serde_json::Value::String("http://different.invalid:8088/api/v3/".to_owned());
    assert_eq!(
        parse_value(&value).expect_err("mapped emulator authorities must agree"),
        RunnerProductConfigError::InvalidGithub
    );
    value["github"]["api_url"] =
        serde_json::Value::String("http://automata-git.invalid:8088/api/v3/".to_owned());

    value["github"]["graphql_url"] =
        serde_json::Value::String("https://automata-git.invalid:8088/api/graphql".to_owned());
    assert_eq!(
        parse_value(&value).expect_err("mapped emulator schemes must agree"),
        RunnerProductConfigError::InvalidGithub
    );

    value["github"]["graphql_url"] =
        serde_json::Value::String("http://automata-git.invalid:8089/api/graphql".to_owned());
    assert_eq!(
        parse_value(&value).expect_err("mapped emulator ports must agree"),
        RunnerProductConfigError::InvalidGithub
    );
    value["github"]["graphql_url"] =
        serde_json::Value::String("http://automata-git.invalid:8088/api/graphql".to_owned());

    value["github"]["server_url"] = serde_json::Value::String("https://github.com/".to_owned());
    value["github"]["api_url"] = serde_json::Value::String("https://api.github.com/".to_owned());
    value["github"]["graphql_url"] =
        serde_json::Value::String("https://api.github.com/graphql".to_owned());
    value["github"]["allow_insecure_http"] = serde_json::Value::Bool(false);
    assert_eq!(
        parse_value(&value).expect_err("gateway opt-in is exclusive to mapped emulator HTTP"),
        RunnerProductConfigError::InvalidGithub
    );

    value["github"]["server_url"] =
        serde_json::Value::String("http://automata-git.invalid:8088/".to_owned());
    value["github"]["api_url"] =
        serde_json::Value::String("http://automata-git.invalid:8088/api/v3/".to_owned());
    value["github"]["graphql_url"] =
        serde_json::Value::String("http://automata-git.invalid:8088/api/graphql".to_owned());
    value["github"]["allow_insecure_http"] = serde_json::Value::Bool(true);

    for invalid_server_url in [
        "http://localhost:8088/",
        "http://automata-git.localhost:8088/",
        "http://127.0.0.1:8088/",
    ] {
        value["github"]["server_url"] = serde_json::Value::String(invalid_server_url.to_owned());
        value["github"]["api_url"] =
            serde_json::Value::String(format!("{invalid_server_url}api/v3/"));
        value["github"]["graphql_url"] =
            serde_json::Value::String(format!("{invalid_server_url}api/graphql"));
        assert_eq!(
            parse_value(&value).expect_err("non-DNS alias must fail closed"),
            RunnerProductConfigError::InvalidPodman
        );
    }
}

#[test]
fn service_proxy_image_is_optional_strict_and_bounds_registration_authority() {
    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    let absent = parse_value(&value).expect("service proxy may be disabled");
    assert!(
        absent
            .podman()
            .expect("Linux fixture selects Podman")
            .service_proxy_image()
            .is_none()
    );
    assert!(
        !absent
            .inventory()
            .containers()
            .features()
            .contains(&ContainerFeature::SERVICE_CONTAINERS),
        "an absent proxy image cannot authorize service containers"
    );

    value["podman"]["service_proxy_image"] = serde_json::json!(SERVICE_PROXY_IMAGE);
    let configured = parse_value(&value).expect("immutable service proxy image");
    assert_eq!(
        configured
            .podman()
            .expect("Linux fixture selects Podman")
            .service_proxy_image()
            .expect("configured image")
            .reference(),
        SERVICE_PROXY_IMAGE
    );
    assert!(
        configured
            .inventory()
            .containers()
            .features()
            .contains(&ContainerFeature::SERVICE_CONTAINERS),
        "an immutable proxy pin must authorize the durable registration ceiling"
    );

    for invalid in [
        "registry.example.test/automata/service-proxy:latest",
        "registry.example.test/automata/service-proxy:reviewed@sha256:4d7a838e047d65bbf708d4fc315db9b3b91ae73c0d50459b519089c0713ff34b",
        "registry.example.test/automata/service-proxy@sha256:4D7A838E047D65BBF708D4FC315DB9B3B91AE73C0D50459B519089C0713FF34B",
        "registry.example.test/automata/service-proxy@sha256:short",
        "registry.example.test/automata/service-proxy @sha256:4d7a838e047d65bbf708d4fc315db9b3b91ae73c0d50459b519089c0713ff34b",
    ] {
        value["podman"]["service_proxy_image"] = serde_json::json!(invalid);
        let error = parse_value(&value).expect_err("invalid helper image must fail closed");
        assert_eq!(error, RunnerProductConfigError::InvalidPodman);
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains(invalid));
    }
}

#[test]
fn buildkit_runtime_is_optional_pinned_and_requires_the_attempt_api() {
    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    let absent = parse_value(&value).expect("BuildKit may be disabled");
    assert!(
        absent
            .podman()
            .expect("Podman config")
            .buildkit_runtime()
            .is_none()
    );
    assert!(
        !absent
            .inventory()
            .containers()
            .features()
            .contains(&ContainerFeature::BUILDKIT)
    );

    value["podman"]["buildkit_runtime_image"] = serde_json::json!(BUILDKIT_RUNTIME_IMAGE);
    let configured = parse_value(&value).expect("immutable BuildKit runtime image");
    assert_eq!(
        configured
            .podman()
            .expect("Podman config")
            .buildkit_runtime()
            .expect("configured BuildKit runtime")
            .image()
            .reference(),
        BUILDKIT_RUNTIME_IMAGE
    );
    assert!(
        configured
            .inventory()
            .containers()
            .features()
            .contains(&ContainerFeature::BUILDKIT)
    );

    value["podman"]["job_container_engine"] = serde_json::json!("disabled");
    assert_eq!(
        parse_value(&value).expect_err("BuildKit without the attempt API must fail closed"),
        RunnerProductConfigError::InvalidPodman
    );
    value["podman"]["job_container_engine"] = serde_json::json!("attempt_scoped_docker_api");

    for invalid in [
        "registry.example.test/buildkit/runtime:latest",
        "registry.example.test/buildkit/runtime:reviewed@sha256:7777777777777777777777777777777777777777777777777777777777777777",
        "registry.example.test/buildkit/runtime@sha256:short",
        "registry.example.test/buildkit/runtime@sha256:777777777777777777777777777777777777777777777777777777777777777G",
    ] {
        value["podman"]["buildkit_runtime_image"] = serde_json::json!(invalid);
        let error = parse_value(&value).expect_err("invalid BuildKit pin must fail closed");
        assert_eq!(error, RunnerProductConfigError::InvalidPodman);
        assert!(!format!("{error:?} {error}").contains(invalid));
    }
}

#[test]
fn rootless_runtime_directory_is_explicit_and_required() {
    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    let config = parse_value(&value).expect("explicit runtime directory must validate");
    assert_eq!(
        config
            .podman()
            .expect("Linux fixture selects Podman")
            .runtime_directory(),
        std::path::Path::new("/run/automata-runner")
    );

    value["podman"]
        .as_object_mut()
        .expect("Podman object")
        .remove("runtime_directory");
    assert_eq!(
        parse_value(&value).expect_err("missing runtime directory must fail closed"),
        RunnerProductConfigError::InvalidDocument
    );

    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    value["podman"]["runtime_directory"] = serde_json::Value::Null;
    assert_eq!(
        parse_value(&value).expect_err("null runtime directory must fail closed"),
        RunnerProductConfigError::InvalidDocument
    );
}

#[test]
fn podman_state_is_the_exact_dedicated_runtime_state_child() {
    let value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    let parsed = parse_value(&value).expect("exact one-mount Podman layout");
    assert_eq!(
        parsed.state().podman().expect("Podman state"),
        std::path::Path::new("/run/automata-runner/automata-ci-podman/state")
    );

    for invalid in [
        "/var/lib/automata-runner/podman",
        "/run/automata-runner/automata-ci-podman",
        "/run/automata-runner/automata-ci-podman/state-other",
        "/run/automata-runner/automata-ci-podman/state/child",
        "/run/automata-runner/automata-ci-podman/state/",
        "/run/automata-runner//automata-ci-podman/state",
    ] {
        let mut changed = value.clone();
        changed["state"]["podman"] = serde_json::json!(invalid);
        assert_eq!(
            parse_value(&changed).expect_err("two-mount or inexact state layout must fail"),
            RunnerProductConfigError::InvalidPodman
        );
    }
}

#[test]
fn durable_journal_and_spool_cannot_overlap_the_transient_runtime_mount() {
    let value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    for (field, path) in [
        ("journal", "/run/automata-runner/journal"),
        ("spool", "/run/automata-runner/spool"),
        ("journal", "/run"),
        ("spool", "/run/automata-runner"),
    ] {
        let mut changed = value.clone();
        changed["state"][field] = serde_json::json!(path);
        assert_eq!(
            parse_value(&changed).expect_err("durable state/runtime overlap must fail"),
            RunnerProductConfigError::InvalidStateRoots
        );
    }
}

#[test]
fn podman_system_inputs_are_explicit_current_only_and_helper_resolution_is_closed() {
    let parsed = RunnerProductConfig::from_json(valid_configuration().as_bytes())
        .expect("explicit Podman system inputs");
    assert_eq!(
        parsed
            .podman()
            .expect("Linux fixture selects Podman")
            .approved_helper_directory(),
        std::path::Path::new("/opt/automata/private/usr/sbin")
    );
    assert_eq!(
        parsed
            .podman()
            .expect("Linux fixture selects Podman")
            .conmon_path(),
        std::path::Path::new("/usr/bin/conmon")
    );
    assert_eq!(
        parsed
            .podman()
            .expect("Linux fixture selects Podman")
            .oci_runtime_path(),
        std::path::Path::new("/usr/bin/crun")
    );
    assert_eq!(
        parsed
            .podman()
            .expect("Linux fixture selects Podman")
            .init_path(),
        std::path::Path::new("/usr/bin/catatonit")
    );
    assert_eq!(
        parsed
            .podman()
            .expect("Linux fixture selects Podman")
            .seccomp_profile_path(),
        std::path::Path::new("/usr/share/containers/seccomp.json")
    );

    for field in [
        "approved_helper_directory",
        "conmon_path",
        "oci_runtime_path",
        "init_path",
        "seccomp_profile_path",
    ] {
        let mut value: serde_json::Value =
            serde_json::from_str(&valid_configuration()).expect("configuration JSON");
        value["podman"]
            .as_object_mut()
            .expect("Podman object")
            .remove(field);
        assert_eq!(
            parse_value(&value).expect_err("missing Podman system input must fail closed"),
            RunnerProductConfigError::InvalidDocument
        );
    }

    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    value["podman"]["approved_helper_directory"] = serde_json::json!("/usr/bin");
    assert_eq!(
        parse_value(&value).expect_err("ordinary host PATH must fail closed"),
        RunnerProductConfigError::InvalidPodman
    );

    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    value["podman"]["executable_search_path"] = serde_json::json!("/usr/bin:/bin");
    assert_eq!(
        parse_value(&value).expect_err("removed search-path alias must fail closed"),
        RunnerProductConfigError::InvalidDocument
    );
}

#[test]
fn unknown_fields_and_inline_secrets_are_rejected() {
    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    value["spool"]["key"] = serde_json::Value::String("not-allowed-inline".to_owned());

    assert_eq!(
        RunnerProductConfig::from_json(
            serde_json::to_vec(&value)
                .expect("serialize modified config")
                .as_slice()
        )
        .expect_err("unknown inline key must fail"),
        RunnerProductConfigError::InvalidDocument
    );

    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    value["github"]["results_token"] = serde_json::json!({
        "kind": "environment",
        "name": "AUTOMATA_ACTIONS_RESULTS_TOKEN"
    });
    assert_eq!(
        parse_value(&value).expect_err("runner-scoped Results token must fail"),
        RunnerProductConfigError::InvalidDocument
    );

    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    value["github"]["workflow_token"] = serde_json::json!({
        "kind": "environment",
        "name": "AUTOMATA_GITHUB_WORKFLOW_TOKEN"
    });
    assert_eq!(
        parse_value(&value).expect_err("runner-static workflow token must fail"),
        RunnerProductConfigError::InvalidDocument
    );

    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    value["github"]["repository_credential"] = serde_json::json!({
        "kind": "environment",
        "name": "AUTOMATA_GITHUB_TOKEN"
    });
    assert_eq!(
        parse_value(&value).expect_err("runner-static repository token must fail"),
        RunnerProductConfigError::InvalidDocument
    );

    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    value["tls"]["allow_legacy_tls12"] = serde_json::Value::Bool(true);
    assert_eq!(
        parse_value(&value).expect_err("TLS 1.2 compatibility must fail closed"),
        RunnerProductConfigError::InvalidDocument
    );
}

#[test]
fn mutable_images_and_overlapping_state_roots_fail_closed() {
    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    value["inventory"]["environment_profiles"][0]["image"] =
        serde_json::Value::String("ubuntu:24.04".to_owned());
    assert_eq!(
        parse_value(&value).expect_err("mutable image must fail"),
        RunnerProductConfigError::InvalidInventory
    );

    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    value["state"]["spool"] =
        serde_json::Value::String("/home/runner/automata-state/journal/spool".to_owned());
    assert_eq!(
        parse_value(&value).expect_err("overlapping roots must fail"),
        RunnerProductConfigError::InvalidStateRoots
    );
}

#[test]
fn unenforced_extended_resource_capacity_fails_closed() {
    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    value["inventory"]["resources_per_job"]["ephemeral_disk_bytes"] =
        serde_json::json!(20_u64 * 1024 * 1024 * 1024);
    assert_eq!(
        parse_value(&value).expect_err("unenforced advertised disk capacity must fail"),
        RunnerProductConfigError::InvalidInventory
    );

    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    value["executor"]["resources"]["ephemeral_disk_bytes"] =
        serde_json::json!(20_u64 * 1024 * 1024 * 1024);
    assert_eq!(
        parse_value(&value).expect_err("unenforced executor disk limit must fail"),
        RunnerProductConfigError::InvalidExecutor
    );

    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    value["inventory"]["resources_per_job"]["gpu_count"] = serde_json::json!(1);
    assert_eq!(
        parse_value(&value).expect_err("unenforced advertised GPU capacity must fail"),
        RunnerProductConfigError::InvalidInventory
    );

    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    value["executor"]["resources"]["gpu_count"] = serde_json::json!(1);
    assert_eq!(
        parse_value(&value).expect_err("unenforced executor GPU limit must fail"),
        RunnerProductConfigError::InvalidExecutor
    );
}

#[test]
fn profile_default_environment_names_and_values_are_validated() {
    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    value["inventory"]["environment_profiles"][0]["default_environment"] =
        serde_json::json!({"INVALID=NAME": "/tmp"});
    assert_eq!(
        parse_value(&value).expect_err("invalid profile environment name must fail"),
        RunnerProductConfigError::InvalidInventory
    );

    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    value["inventory"]["environment_profiles"][0]["default_environment"] =
        serde_json::json!({"VALID_NAME": "contains\0nul"});
    assert_eq!(
        parse_value(&value).expect_err("invalid profile environment value must fail"),
        RunnerProductConfigError::InvalidInventory
    );
}

#[test]
fn capability_inventory_cannot_diverge_from_execution_policy() {
    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    value["executor"]["resources"]["cpu_millis"] = serde_json::Value::from(2_000);
    assert_eq!(
        parse_value(&value).expect_err("resource inventory must be exact"),
        RunnerProductConfigError::InvalidInventory
    );

    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    value["executor"]["root_filesystem"] = serde_json::Value::from("read_only");
    value["executor"]["privilege"] = serde_json::Value::from("unprivileged");
    let config = parse_value(&value).expect("alternate policy must validate");
    let features = config.inventory().sandbox().features();
    assert!(features.contains(&SandboxFeature::READ_ONLY_ROOT));
    assert!(!features.contains(&SandboxFeature::PRIVILEGED_USER));

    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    value["executor"]["privilege"] = serde_json::Value::from("host");
    assert_eq!(
        parse_value(&value).expect_err("Podman cannot inherit an unisolated host identity"),
        RunnerProductConfigError::InvalidExecutor
    );

    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    value["podman"]["job_container_engine"] = serde_json::Value::from("disabled");
    let config = parse_value(&value).expect("disabled job engine policy must validate");
    assert!(
        !config
            .inventory()
            .containers()
            .features()
            .contains(&ContainerFeature::DOCKER_COMPATIBLE_API)
    );
}

#[test]
fn temporary_hierarchies_and_noncanonical_environment_names_are_rejected() {
    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    value["state"]["journal"] = serde_json::Value::String("/var/tmp/automata/journal".to_owned());
    assert_eq!(
        parse_value(&value).expect_err("temporary root must fail"),
        RunnerProductConfigError::InvalidStateRoots
    );

    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    value["spool"]["key_hex"]["name"] =
        serde_json::Value::String("lowercase-secret-name".to_owned());
    assert!(matches!(
        parse_value(&value),
        Err(RunnerProductConfigError::SecureInput(_))
    ));
}

fn parse_value(value: &serde_json::Value) -> Result<RunnerProductConfig, RunnerProductConfigError> {
    let bytes = serde_json::to_vec(value).expect("serialize modified config");
    RunnerProductConfig::from_json(&bytes)
}

#[test]
fn kubernetes_provider_configuration_is_exact_and_mutually_exclusive() {
    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    let podman = value["podman"].clone();
    value
        .as_object_mut()
        .expect("configuration object")
        .remove("podman");
    value["state"]
        .as_object_mut()
        .expect("state object")
        .remove("podman");
    value["executor"]["network"] = serde_json::json!("disabled");
    value["executor"]["privilege"] = serde_json::json!("unprivileged");
    value["executor"]["resources"]["ephemeral_disk_bytes"] = serde_json::json!(2_147_483_648_u64);
    value["executor"]["resources"]["gpu_count"] = serde_json::json!(1);
    value["inventory"]["resources_per_job"]["ephemeral_disk_bytes"] =
        serde_json::json!(2_147_483_648_u64);
    value["inventory"]["resources_per_job"]["gpu_count"] = serde_json::json!(1);
    value["kubernetes"] = serde_json::json!({
        "namespace": "automata-runners",
        "guest_image": format!(
            "registry.example/automata/guest@sha256:{}",
            "ab".repeat(32)
        ),
        "network_isolation_verified": true,
        "ephemeral_storage_enforcement_verified": true,
        "process_limit_enforcement": 4096,
        "gpu_resource_name": "nvidia.com/gpu",
        "node_selector": {"automata.dev/pool": "jobs"},
        "runtime_class_name": "kata"
    });

    let configured = parse_value(&value).expect("Kubernetes configuration");
    assert!(configured.podman().is_none());
    assert!(configured.state().podman().is_none());
    let kubernetes = configured.kubernetes().expect("Kubernetes config");
    assert_eq!(kubernetes.adapter().namespace(), "automata-runners");
    assert_eq!(kubernetes.adapter().process_limit(), Some(4096));
    assert!(kubernetes.adapter().ephemeral_storage_enforced());
    assert_eq!(
        kubernetes.adapter().gpu_resource_name(),
        Some("nvidia.com/gpu")
    );
    assert_eq!(kubernetes.adapter().runtime_class_name(), Some("kata"));
    assert_eq!(
        configured
            .inventory()
            .resources_per_job()
            .ephemeral_disk_bytes(),
        2_147_483_648
    );
    assert_eq!(configured.inventory().resources_per_job().gpu_count(), 1);

    let mut unverified_storage = value.clone();
    unverified_storage["kubernetes"]["ephemeral_storage_enforcement_verified"] =
        serde_json::json!(false);
    assert_eq!(
        parse_value(&unverified_storage).expect_err("storage evidence is required"),
        RunnerProductConfigError::InvalidKubernetes
    );

    let mut ambiguous = value;
    ambiguous["podman"] = podman;
    assert_eq!(
        parse_value(&ambiguous).expect_err("providers are mutually exclusive"),
        RunnerProductConfigError::InvalidProvider
    );
}

fn local_docker_configuration() -> serde_json::Value {
    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    value
        .as_object_mut()
        .expect("configuration object")
        .remove("podman");
    value["state"]
        .as_object_mut()
        .expect("state object")
        .remove("podman");
    value["executor"]["network"] = serde_json::json!("disabled");
    value["local_docker"] = serde_json::json!({
        "installation_name": "evaluation",
        "installation_id": "6e561f8b-9098-418d-b573-d82f5c73006e",
        "guest_image": format!(
            "registry.example/automata/guest@sha256:{}",
            "ab".repeat(32)
        )
    });
    value
}

#[test]
fn local_docker_configuration_is_closed_current_only_and_mutually_exclusive() {
    let value = local_docker_configuration();
    let configured = parse_value(&value).expect("local Docker configuration");
    assert!(configured.podman().is_none());
    assert!(configured.kubernetes().is_none());
    assert!(configured.state().provider().is_none());
    let local = configured.local_docker().expect("local Docker policy");
    assert_eq!(local.installation_binding().name().as_str(), "evaluation");
    assert_eq!(
        local.installation_binding().id().to_string(),
        "6e561f8b-9098-418d-b573-d82f5c73006e"
    );
    assert!(local.guest_image().reference().ends_with(&"ab".repeat(32)));
    assert!(configured.inventory().containers().features().is_empty());
    assert_eq!(
        configured.executor().privilege(),
        SandboxPrivilegePolicy::Administrator
    );
    assert!(
        configured
            .inventory()
            .sandbox()
            .features()
            .contains(&SandboxFeature::PRIVILEGED_USER)
    );

    for field in ["endpoint", "socket", "docker_host"] {
        let mut open = value.clone();
        open["local_docker"][field] = serde_json::json!("unix:///var/run/docker.sock");
        assert_eq!(
            parse_value(&open).expect_err("transport selection must stay closed"),
            RunnerProductConfigError::InvalidDocument
        );
    }

    let mut invalid_id = value.clone();
    invalid_id["local_docker"]["installation_id"] =
        serde_json::json!("00000000-0000-0000-0000-000000000000");
    assert_eq!(
        parse_value(&invalid_id).expect_err("installation identity is canonical UUIDv4"),
        RunnerProductConfigError::InvalidLocalDocker
    );

    let mut egress = value.clone();
    egress["executor"]["network"] = serde_json::json!("private_egress");
    assert_eq!(
        parse_value(&egress).expect_err("local Docker is network-disabled only"),
        RunnerProductConfigError::InvalidExecutor
    );

    let mut unprivileged = value.clone();
    unprivileged["executor"]["privilege"] = serde_json::json!("unprivileged");
    assert_eq!(
        parse_value(&unprivileged)
            .expect_err("local Docker uses the attenuated confined administrator identity"),
        RunnerProductConfigError::InvalidExecutor
    );

    for reserved_path in [
        "/automata".to_owned(),
        "/automata/job".to_owned(),
        automata_ci_local::LOCAL_DOCKER_CONTROL_DIRECTORY.to_owned(),
        format!("{}/job", automata_ci_local::LOCAL_DOCKER_CONTROL_DIRECTORY),
    ] {
        let mut runner_root = value.clone();
        runner_root["executor"]["runner_root"] = serde_json::json!(&reserved_path);
        assert_eq!(
            parse_value(&runner_root).expect_err("runner root must avoid reserved paths"),
            RunnerProductConfigError::InvalidInventory
        );

        let mut workspace = value.clone();
        workspace["inventory"]["environment_profiles"][0]["workspace"] =
            serde_json::json!(&reserved_path);
        assert_eq!(
            parse_value(&workspace).expect_err("workspace must avoid reserved paths"),
            RunnerProductConfigError::InvalidInventory
        );
    }

    let mut ambiguous = value;
    ambiguous["podman"] = serde_json::from_str::<serde_json::Value>(&valid_configuration())
        .expect("Podman configuration")
        .get("podman")
        .expect("Podman field")
        .clone();
    assert_eq!(
        parse_value(&ambiguous).expect_err("providers are mutually exclusive"),
        RunnerProductConfigError::InvalidProvider
    );
}

#[test]
fn local_docker_resource_minima_are_current_and_exact() {
    let value = local_docker_configuration();
    for (field, minimum) in [
        (
            "memory_bytes",
            automata_ci_local::MINIMUM_LOCAL_DOCKER_SANDBOX_MEMORY_BYTES,
        ),
        (
            "cpu_millis",
            u64::from(automata_ci_local::MINIMUM_LOCAL_DOCKER_SANDBOX_CPU_MILLIS),
        ),
        (
            "pids",
            u64::from(automata_ci_local::MINIMUM_LOCAL_DOCKER_SANDBOX_PIDS),
        ),
    ] {
        let mut undersized = value.clone();
        undersized["executor"]["resources"][field] = serde_json::json!(minimum - 1);
        assert_eq!(
            parse_value(&undersized).expect_err("local Docker infrastructure minimum"),
            RunnerProductConfigError::InvalidLocalDocker
        );
    }

    let mut minimum = value;
    minimum["executor"]["resources"]["memory_bytes"] =
        serde_json::json!(automata_ci_local::MINIMUM_LOCAL_DOCKER_SANDBOX_MEMORY_BYTES);
    minimum["executor"]["resources"]["cpu_millis"] =
        serde_json::json!(automata_ci_local::MINIMUM_LOCAL_DOCKER_SANDBOX_CPU_MILLIS);
    minimum["executor"]["resources"]["pids"] =
        serde_json::json!(automata_ci_local::MINIMUM_LOCAL_DOCKER_SANDBOX_PIDS);
    minimum["inventory"]["resources_per_job"]["memory_bytes"] =
        serde_json::json!(automata_ci_local::MINIMUM_LOCAL_DOCKER_SANDBOX_MEMORY_BYTES);
    minimum["inventory"]["resources_per_job"]["cpu_millis"] =
        serde_json::json!(automata_ci_local::MINIMUM_LOCAL_DOCKER_SANDBOX_CPU_MILLIS);
    minimum["inventory"]["resources_per_job"]["pids"] =
        serde_json::json!(automata_ci_local::MINIMUM_LOCAL_DOCKER_SANDBOX_PIDS);
    let configured = parse_value(&minimum).expect("exact local Docker minimum");
    let resources = configured.executor().resources();
    assert_eq!(
        resources.memory_bytes(),
        automata_ci_local::MINIMUM_LOCAL_DOCKER_SANDBOX_MEMORY_BYTES
    );
    assert_eq!(
        resources.cpu_millis(),
        automata_ci_local::MINIMUM_LOCAL_DOCKER_SANDBOX_CPU_MILLIS
    );
    assert_eq!(
        resources.pids(),
        automata_ci_local::MINIMUM_LOCAL_DOCKER_SANDBOX_PIDS
    );
}

#[test]
fn only_the_current_product_schema_is_accepted() {
    let current: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    assert!(parse_value(&current).is_ok());
    for unsupported in [0, 1, 2, 3, 4, u16::MAX] {
        let mut document = current.clone();
        document["schema_version"] = serde_json::json!(unsupported);
        assert_eq!(
            parse_value(&document).expect_err("noncurrent schema must fail closed"),
            RunnerProductConfigError::UnsupportedSchema
        );
    }
}

#[test]
fn previous_product_schema_is_rejected() {
    let mut document: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    let unsupported = RUNNER_PRODUCT_CONFIG_SCHEMA_VERSION - 1;
    document["schema_version"] = serde_json::json!(unsupported);
    assert_eq!(
        parse_value(&document).expect_err("previous schema must fail closed"),
        RunnerProductConfigError::UnsupportedSchema
    );
}

fn environment_value<'a>(
    environment: &'a automata_ci_execution::SandboxEnvironment,
    name: &str,
) -> Option<&'a str> {
    environment
        .default_environment()
        .values()
        .iter()
        .find(|variable| variable.name().as_str() == name)
        .map(|variable| variable.value().expose())
}
