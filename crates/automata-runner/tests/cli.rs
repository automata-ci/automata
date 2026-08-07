use automata_runner::cli::{Cli, Command};
use clap::Parser as _;

#[test]
fn run_accepts_only_a_configuration_path() {
    let cli = Cli::try_parse_from([
        "automata-runner",
        "run",
        "--config",
        "/var/lib/automata/runner.json",
    ])
    .expect("run CLI must parse");

    let Command::Run(args) = cli.command else {
        panic!("run command must parse as run");
    };
    assert_eq!(
        args.config,
        std::path::PathBuf::from("/var/lib/automata/runner.json")
    );
}

#[test]
fn run_has_no_inline_secret_arguments() {
    for option in ["--spool-key", "--tls-private-key", "--github-token"] {
        let error = Cli::try_parse_from([
            "automata-runner",
            "run",
            "--config",
            "/var/lib/automata/runner.json",
            option,
            "should-never-be-accepted",
        ])
        .expect_err("secret-bearing arguments must not exist");
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }
}

#[test]
fn doctor_defaults_to_human_output_without_a_server_probe() {
    let cli = Cli::try_parse_from(["automata-runner", "doctor"]).expect("CLI must parse");

    let Command::Doctor(args) = cli.command else {
        panic!("doctor command must parse as doctor");
    };
    assert!(args.server.is_none());
    assert!(!args.json);
    assert!(!args.active);
}

#[test]
fn doctor_accepts_json_and_server_options() {
    let cli = Cli::try_parse_from([
        "automata-runner",
        "doctor",
        "--server",
        "http://127.0.0.1:8080",
        "--json",
    ])
    .expect("CLI must parse");

    let Command::Doctor(args) = cli.command else {
        panic!("doctor command must parse as doctor");
    };
    assert_eq!(args.server.as_deref(), Some("http://127.0.0.1:8080"));
    assert!(args.json);
    assert!(!args.active);
}

#[test]
fn doctor_requires_an_explicit_flag_for_active_probes() {
    let cli = Cli::try_parse_from(["automata-runner", "doctor", "--active"])
        .expect("active doctor CLI must parse");

    let Command::Doctor(args) = cli.command else {
        panic!("doctor command must parse as doctor");
    };
    assert!(args.active);
}
