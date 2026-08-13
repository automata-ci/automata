use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "automata-runner",
    version,
    long_version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("AUTOMATA_BUILD_GIT_SHA"), ")"),
    about = "Automata runner for Linux, Windows, and isolated macOS execution hosts"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Connect to the control plane and execute assigned jobs.
    Run(RunArgs),
    /// Enroll this host with a short-lived one-time control-plane token.
    Enroll(EnrollArgs),
    /// Render the canonical durable-registration ceiling without loading credentials.
    Capabilities(CapabilitiesArgs),
    /// Inspect local capabilities; read-only unless --active is supplied.
    Doctor(DoctorArgs),
    /// Internal one-shot readiness server used by the isolated network probe.
    #[command(name = "__probe-http-ready", hide = true)]
    InternalProbeHttp(InternalProbeHttpArgs),
}

#[derive(Debug, Args)]
pub(crate) struct EnrollArgs {
    /// Strict JSON product configuration whose file-backed TLS destinations will be populated.
    #[arg(long, env = "AUTOMATA_RUNNER_CONFIG", value_name = "PATH")]
    pub(crate) config: PathBuf,
    /// Human API HTTPS origin, such as <https://ci.example.com>.
    #[arg(long, env = "AUTOMATA_SERVER_URL", value_name = "URL")]
    pub(crate) server: String,
    /// Human-readable runner name, unique within its tenant.
    #[arg(long, value_name = "NAME")]
    pub(crate) name: String,
    /// Owner-only file containing the one-time token. If omitted, the token is read from
    /// `AUTOMATA_RUNNER_ENROLLMENT_TOKEN` or redirected stdin, in that order.
    #[arg(long, value_name = "PATH")]
    pub(crate) token_file: Option<PathBuf>,
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
    fn enroll_accepts_safe_token_sources_but_no_inline_token() {
        let cli = Cli::try_parse_from([
            "automata-runner",
            "enroll",
            "--config",
            "/var/lib/automata/runner.json",
            "--server",
            "https://ci.example.test",
            "--name",
            "linux-amd64-1",
            "--token-file",
            "/run/secrets/automata-enrollment-token",
        ])
        .expect("enroll CLI must parse");
        let Command::Enroll(args) = cli.command else {
            panic!("enroll command expected");
        };
        assert_eq!(args.name, "linux-amd64-1");
        assert_eq!(
            args.token_file.as_deref(),
            Some(std::path::Path::new(
                "/run/secrets/automata-enrollment-token"
            ))
        );

        let error = Cli::try_parse_from([
            "automata-runner",
            "enroll",
            "--config",
            "/var/lib/automata/runner.json",
            "--server",
            "https://ci.example.test",
            "--name",
            "linux-amd64-1",
            "--token",
            "must-not-enter-argv",
        ])
        .expect_err("inline enrollment tokens must not be accepted");
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
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
