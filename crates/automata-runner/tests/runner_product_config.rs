use automata_core::{
    Architecture, ContainerFeature, OperatingSystem, RunnerFeature, SandboxFeature, Sha256Digest,
};
use automata_runner::product::{
    RUNNER_PRODUCT_CONFIG_SCHEMA_VERSION, RunnerProductConfig, RunnerProductConfigError,
};

const RUNNER_ID: &str = "6e561f8b-9098-418d-b573-d82f5c73006e";
const PROFILE_ID: &str = "automata.dev/github-hosted-ubuntu-24-04-x64-v1";
const PROFILE_DIGEST: &str = "b0c2f5c0cad341e34c422a1b69bcc70bb82224f24d8512026cab9346dd1c6087";
const IMAGE: &str = "localhost/automata/ubuntu-24.04-x64@sha256:40c952578a042ce6333c3965420068dad0a08ec8acd6514de03807dbe5cf3de8";

#[test]
fn checked_in_local_dogfood_configuration_is_valid_and_pinned() {
    let config =
        RunnerProductConfig::from_json(include_bytes!("../config/runner.local.example.json"))
            .expect("checked-in local runner configuration must remain valid");

    let (profile, environment) = config
        .environments()
        .first_key_value()
        .expect("dogfood configuration must select one exact environment");
    assert_eq!(profile.id().as_str(), PROFILE_ID);
    assert_eq!(profile.digest().to_string(), PROFILE_DIGEST);
    assert_eq!(environment.image().reference(), IMAGE);
    assert_eq!(
        environment_value(environment, "CARGO_HOME"),
        Some("/opt/cargo")
    );
    assert_eq!(
        environment_value(environment, "RUSTUP_HOME"),
        Some("/opt/rustup")
    );
    assert_eq!(
        environment_value(environment, "WASI_SDK"),
        None,
        "the renderer must opt into the attested SDK root explicitly"
    );
    assert_eq!(
        config.github().server_url().host_str(),
        Some("automata-git.ghe.com")
    );
    assert_eq!(
        config
            .podman()
            .github_server_host_gateway_alias()
            .expect("local dogfood config must opt into its exact GitHub hostname")
            .as_str(),
        "automata-git.ghe.com"
    );
}

fn valid_configuration() -> String {
    format!(
        r#"{{
  "schema_version": {RUNNER_PRODUCT_CONFIG_SCHEMA_VERSION},
  "runner_id": "{RUNNER_ID}",
  "control_endpoint": "https://127.0.0.1:8443/",
  "state": {{
    "journal": "/home/runner/automata-state/journal",
    "spool": "/home/runner/automata-state/spool",
    "podman": "/home/runner/automata-state/podman"
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
      "ephemeral_disk_bytes": 21474836480,
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
    "runtime_directory": "/run/user/1000",
    "executable_search_path": "/usr/local/bin:/usr/bin:/bin",
    "job_container_engine": "attempt_scoped_docker_api"
  }},
  "executor": {{
    "resources": {{
      "cpu_millis": 4000,
      "memory_bytes": 17179869184,
      "ephemeral_disk_bytes": 21474836480,
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
      "install": "/usr/bin/install",
      "tar": "/usr/bin/tar",
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
    "operation_timeout_seconds": 30,
    "access_key_id": {{"kind": "environment", "name": "AUTOMATA_S3_ACCESS_KEY_ID"}},
    "secret_access_key": {{"kind": "environment", "name": "AUTOMATA_S3_SECRET_ACCESS_KEY"}}
  }},
  "github": {{
    "user_agent": "automata-runner/{version}",
    "repository_credential": {{"kind": "environment", "name": "AUTOMATA_GITHUB_TOKEN"}},
    "workflow_token": {{"kind": "environment", "name": "AUTOMATA_GITHUB_WORKFLOW_TOKEN"}},
    "server_url": "https://github.com/",
    "api_url": "https://api.github.com/",
    "graphql_url": "https://api.github.com/graphql"
  }}
}}"#,
        version = env!("CARGO_PKG_VERSION"),
    )
}

#[test]
fn validated_config_preserves_exact_runner_and_profile_inventory() {
    let config = RunnerProductConfig::from_json(valid_configuration().as_bytes())
        .expect("configuration must validate");

    assert_eq!(config.runner_id().to_string(), RUNNER_ID);
    assert_eq!(
        config.control_endpoint().to_string(),
        "https://127.0.0.1:8443/"
    );
    assert_eq!(config.inventory().max_parallel_jobs(), 2);
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
    assert!(config.object_store().force_path_style());
    assert!(
        config.podman().github_server_host_gateway_alias().is_none(),
        "host-gateway routing must remain disabled by default"
    );

    let (profile, environment) = config
        .environments()
        .first_key_value()
        .expect("one exact environment");
    assert_eq!(profile.id().as_str(), PROFILE_ID);
    assert_eq!(profile.digest().to_string(), PROFILE_DIGEST);
    assert_eq!(environment.image().reference(), IMAGE);
    assert_eq!(environment.keepalive().program().as_str(), "/bin/sleep");
    assert_eq!(environment.keepalive().arguments(), ["infinity"]);
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
fn github_host_gateway_opt_in_derives_only_the_exact_validated_server_hostname() {
    let mut value: serde_json::Value =
        serde_json::from_str(&valid_configuration()).expect("configuration JSON");
    value["podman"]["map_github_server_to_host_gateway"] = serde_json::Value::Bool(true);
    value["github"]["server_url"] =
        serde_json::Value::String("http://automata-git.localhost:8088/".to_owned());
    value["github"]["api_url"] =
        serde_json::Value::String("http://automata-git.localhost:8088/api/v3/".to_owned());
    value["github"]["graphql_url"] =
        serde_json::Value::String("http://automata-git.localhost:8088/api/graphql".to_owned());
    value["github"]["allow_insecure_http"] = serde_json::Value::Bool(true);

    let config = parse_value(&value).expect("explicit local hostname mapping must validate");
    assert_eq!(
        config
            .podman()
            .github_server_host_gateway_alias()
            .expect("mapping")
            .as_str(),
        config
            .github()
            .server_url()
            .host_str()
            .expect("validated GitHub hostname")
    );

    for invalid_server_url in ["http://localhost:8088/", "http://127.0.0.1:8088/"] {
        value["github"]["server_url"] = serde_json::Value::String(invalid_server_url.to_owned());
        assert_eq!(
            parse_value(&value).expect_err("non-DNS alias must fail closed"),
            RunnerProductConfigError::InvalidPodman
        );
    }
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

fn environment_value<'a>(
    environment: &'a automata_execution::SandboxEnvironment,
    name: &str,
) -> Option<&'a str> {
    environment
        .default_environment()
        .values()
        .iter()
        .find(|variable| variable.name().as_str() == name)
        .map(|variable| variable.value().expose())
}
