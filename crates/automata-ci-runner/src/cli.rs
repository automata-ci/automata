use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "automata-runner",
    version,
    long_version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("AUTOMATA_BUILD_GIT_SHA"), ")"),
    about = "Automata runner for rootless Linux and trusted native Windows/macOS execution hosts"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Connect to the control plane and execute assigned jobs.
    Run(RunArgs),
    /// Render the canonical durable-registration ceiling without loading credentials.
    Capabilities(CapabilitiesArgs),
    /// Inspect local capabilities; read-only unless --active is supplied.
    Doctor(DoctorArgs),
    /// Internal one-shot readiness server used by the isolated network probe.
    #[command(name = "__probe-http-ready", hide = true)]
    InternalProbeHttp(InternalProbeHttpArgs),
    /// Internal same-binary supervisor for one trusted native macOS command.
    #[command(name = "__macos-job-supervisor", hide = true)]
    InternalMacosJobSupervisor,
}

#[derive(Debug, Args)]
pub(crate) struct RunArgs {
    /// Strict JSON product configuration. Secrets must use file or environment sources.
    #[arg(long, env = "AUTOMATA_RUNNER_CONFIG", value_name = "PATH")]
    pub(crate) config: PathBuf,
}

#[derive(Debug, Args)]
pub(crate) struct CapabilitiesArgs {
    /// Strict JSON product configuration; referenced credentials are not loaded.
    ///
    /// Configured optional abilities are an administrative ceiling. The live
    /// runner advertises them only after its provider proves them at startup.
    #[arg(long, env = "AUTOMATA_RUNNER_CONFIG", value_name = "PATH")]
    pub(crate) config: PathBuf,
}

#[derive(Debug, Args)]
pub(crate) struct DoctorArgs {
    /// Optionally verify an Automata server at an HTTPS root origin.
    ///
    /// Plain HTTP is accepted only when the host is a literal loopback IP.
    #[arg(long, env = "AUTOMATA_SERVER_URL")]
    pub(crate) server: Option<String>,
    /// Render the report as JSON.
    #[arg(long)]
    pub(crate) json: bool,
    /// Create short-lived, isolated resources to verify Podman networking.
    #[arg(long)]
    pub(crate) active: bool,
}

#[derive(Debug, Args)]
pub(crate) struct InternalProbeHttpArgs {
    /// Container port for the one-shot readiness listener.
    #[arg(long, hide = true)]
    pub(crate) port: u16,
    /// Collision-resistant token required in the readiness request path.
    #[arg(long, hide = true)]
    pub(crate) token: String,
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::{Cli, Command};

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
    fn capabilities_accepts_only_a_configuration_path() {
        let cli = Cli::try_parse_from([
            "automata-runner",
            "capabilities",
            "--config",
            "/var/lib/automata/runner.json",
        ])
        .expect("capabilities CLI must parse");

        let Command::Capabilities(args) = cli.command else {
            panic!("capabilities command must parse as capabilities");
        };
        assert_eq!(
            args.config,
            std::path::PathBuf::from("/var/lib/automata/runner.json")
        );
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
}
