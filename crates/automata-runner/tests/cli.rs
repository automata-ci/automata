use automata_runner::cli::{Cli, Command};
use clap::Parser as _;

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
