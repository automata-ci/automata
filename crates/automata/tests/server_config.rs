use std::{fs, path::PathBuf, str::FromStr as _};

use automata::{
    cli::{Cli, Command},
    server::{SecretLoadError, SecretSource, ServerConfig, ServerConfigError},
};
use clap::Parser as _;

fn test_file(name: &str) -> PathBuf {
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("server-config");
    fs::create_dir_all(&directory).expect("target-local test directory must be creatable");
    directory.join(name)
}

#[test]
fn source_debug_output_redacts_environment_names_and_paths() {
    let marker = "AUTOMATA_SENSITIVE_REFERENCE_MARKER";
    for source in [
        SecretSource::from_str(&format!("env:{marker}")),
        SecretSource::from_str(&format!("file:target/{marker}")),
    ] {
        let source = source.expect("reference syntax must be valid");
        let debug = format!("{source:?}");
        assert!(!debug.contains(marker));
        assert!(debug.contains("[redacted]"));
    }
}

#[test]
fn scalar_file_loading_is_bounded_and_removes_only_one_terminal_newline() {
    let scalar_path = test_file("scalar.txt");
    fs::write(&scalar_path, b"exact-value\r\n").expect("test scalar must be writable");
    let source = SecretSource::File(scalar_path);
    let scalar = source.load_scalar(64).expect("bounded scalar must load");
    assert_eq!(scalar.as_str(), "exact-value");

    let oversized_path = test_file("oversized.txt");
    fs::write(&oversized_path, b"12345").expect("oversized fixture must be writable");
    let error = SecretSource::File(oversized_path)
        .load_bytes(4)
        .expect_err("oversized source must be rejected before use");
    assert!(matches!(error, SecretLoadError::TooLarge { maximum: 4 }));
}

#[test]
fn server_configuration_validates_non_secret_endpoint_fields() {
    let cli = Cli::try_parse_from(["automata", "server", "--s3-endpoint", "not an endpoint"])
        .expect("endpoint validation belongs to server configuration");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::InvalidS3Endpoint)
    ));
}

#[test]
fn local_admission_is_opt_in_and_loopback_only() {
    let cli = Cli::try_parse_from([
        "automata",
        "server",
        "--listen",
        "0.0.0.0:8080",
        "--local-admission-token-source",
        "env:AUTOMATA_LOCAL_ADMISSION_TOKEN",
    ])
    .expect("CLI syntax must parse");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::LocalAdmissionRequiresLoopback)
    ));

    let cli = Cli::try_parse_from([
        "automata",
        "server",
        "--local-admission-token-source",
        "file:target/local-admission-token",
        "--results-public-url",
        "https://results.example.test/",
    ])
    .expect("loopback local ingress must parse");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    assert!(ServerConfig::from_args(&args).is_ok());
}

#[test]
fn local_admission_tenant_is_validated_before_adapter_composition() {
    let cli = Cli::try_parse_from([
        "automata",
        "server",
        "--local-admission-tenant",
        "not a tenant",
    ])
    .expect("CLI syntax must parse");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::InvalidLocalAdmissionTenant)
    ));
}

#[test]
fn maintenance_policy_has_bounded_resumable_defaults() {
    let cli = Cli::try_parse_from([
        "automata",
        "server",
        "--results-public-url",
        "https://results.example.test/",
    ])
    .expect("CLI syntax must parse");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    assert_eq!(args.maintenance_interval_seconds, 5);
    assert_eq!(args.maintenance_batch_size, 100);
    assert_eq!(args.maximum_lease_failures, 3);
    assert_eq!(args.stale_runner_session_timeout_seconds, 300);
    assert!(ServerConfig::from_args(&args).is_ok());
}

#[test]
fn results_endpoint_is_mandatory_and_plain_http_is_explicitly_scoped() {
    let cli = Cli::try_parse_from(["automata", "server"]).expect("CLI syntax must parse");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::MissingResultsEndpoint)
    ));

    let cli = Cli::try_parse_from([
        "automata",
        "server",
        "--results-listen",
        "192.168.0.8:8081",
        "--results-public-url",
        "http://host.containers.internal:8081/",
    ])
    .expect("CLI syntax must parse");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::InvalidResultsEndpoint)
    ));

    let cli = Cli::try_parse_from([
        "automata",
        "server",
        "--results-listen",
        "192.168.0.8:8081",
        "--results-public-url",
        "http://host.containers.internal:8081/",
        "--results-allow-development-http",
        "--results-trusted-private-host",
        "host.containers.internal",
    ])
    .expect("CLI syntax must parse");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    assert!(ServerConfig::from_args(&args).is_ok());
}

#[test]
fn results_development_endpoint_rejects_wildcards_and_host_mismatch() {
    for arguments in [
        [
            "0.0.0.0:8081",
            "http://host.containers.internal:8081/",
            "host.containers.internal",
        ],
        [
            "192.168.0.8:8081",
            "http://host.containers.internal:8081/",
            "different.internal",
        ],
        [
            "192.168.0.8:8081",
            "http://host.containers.internal:9090/",
            "host.containers.internal",
        ],
    ] {
        let cli = Cli::try_parse_from([
            "automata",
            "server",
            "--results-listen",
            arguments[0],
            "--results-public-url",
            arguments[1],
            "--results-allow-development-http",
            "--results-trusted-private-host",
            arguments[2],
        ])
        .expect("CLI syntax must parse");
        let Command::Server(args) = cli.command else {
            panic!("server command expected");
        };
        assert!(matches!(
            ServerConfig::from_args(&args),
            Err(ServerConfigError::InvalidResultsEndpoint)
        ));
    }
}

#[test]
fn maintenance_policy_rejects_unbounded_values_and_a_one_tick_resume_window() {
    let cli = Cli::try_parse_from(["automata", "server"]).expect("CLI syntax must parse");
    let Command::Server(mut args) = cli.command else {
        panic!("server command expected");
    };
    args.maintenance_batch_size = 0;
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::InvalidMaintenancePolicy)
    ));

    args.maintenance_batch_size = 100;
    args.maintenance_interval_seconds = 30;
    args.stale_runner_session_timeout_seconds = 30;
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::InvalidMaintenancePolicy)
    ));
}
