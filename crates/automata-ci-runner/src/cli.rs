use std::{convert::Infallible, fmt, path::PathBuf, str::FromStr};

use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand, error::ErrorKind};

use crate::product::{validate_absolute_path, validate_environment_name};

#[derive(Debug, Parser)]
#[command(
    name = "automata-runner",
    version,
    long_version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("AUTOMATA_BUILD_GIT_SHA"), ")"),
    about = "Automata runner for Linux, Windows, and isolated macOS execution hosts"
)]
struct ParsedCli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug)]
pub(crate) struct Cli {
    pub(crate) command: Command,
}

impl CommandFactory for Cli {
    fn command() -> clap::Command {
        ParsedCli::command()
    }

    fn command_for_update() -> clap::Command {
        ParsedCli::command_for_update()
    }
}

impl FromArgMatches for Cli {
    fn from_arg_matches(matches: &clap::ArgMatches) -> Result<Self, clap::Error> {
        let parsed = ParsedCli::from_arg_matches(matches)?;
        validate_command(&parsed.command)?;
        Ok(Self {
            command: parsed.command,
        })
    }

    fn update_from_arg_matches(&mut self, matches: &clap::ArgMatches) -> Result<(), clap::Error> {
        *self = Self::from_arg_matches(matches)?;
        Ok(())
    }
}

impl Parser for Cli {}

fn validate_command(command: &Command) -> Result<(), clap::Error> {
    if matches!(
        command,
        Command::Enroll(EnrollArgs {
            token_source: EnrollmentTokenSource::Invalid,
            ..
        })
    ) {
        return Err(clap::Error::raw(
            ErrorKind::InvalidValue,
            "runner enrollment token source must be file:PATH, env:NAME, or stdin",
        ));
    }
    Ok(())
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
    /// Internal fixed local-lifecycle readiness check.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[command(name = automata_ci_local::LOCAL_RUNNER_READY_COMMAND, hide = true)]
    InternalLocalCheckReady,
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
    /// Explicit one-time token source. File input must be absolute and owner-only; stdin must reach EOF.
    #[arg(long, value_name = "file:PATH|env:NAME|stdin")]
    pub(crate) token_source: EnrollmentTokenSource,
}

#[derive(Clone)]
pub(crate) enum EnrollmentTokenSource {
    File(PathBuf),
    Environment(String),
    Stdin,
    Invalid,
}

impl FromStr for EnrollmentTokenSource {
    type Err = Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let source = if value == "stdin" {
            Self::Stdin
        } else if let Some(path) = value.strip_prefix("file:") {
            let path = PathBuf::from(path);
            if validate_absolute_path(&path).is_ok() {
                Self::File(path)
            } else {
                Self::Invalid
            }
        } else if let Some(name) = value.strip_prefix("env:") {
            let name = name.to_owned();
            if validate_environment_name(&name).is_ok() {
                Self::Environment(name)
            } else {
                Self::Invalid
            }
        } else {
            Self::Invalid
        };
        Ok(source)
    }
}

impl fmt::Debug for EnrollmentTokenSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::File(_) => "file",
            Self::Environment(_) => "environment",
            Self::Stdin => "stdin",
            Self::Invalid => "invalid",
        };
        formatter
            .debug_struct("EnrollmentTokenSource")
            .field("kind", &kind)
            .field("reference", &"[REDACTED]")
            .finish()
    }
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
    use clap::{CommandFactory as _, Parser as _, error::ErrorKind};

    use super::{Cli, Command, EnrollmentTokenSource};

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
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn local_readiness_is_a_hidden_argument_free_command() {
        let cli = Cli::try_parse_from(["automata-runner", "__local-check-ready"])
            .expect("fixed local readiness command must parse");
        assert!(matches!(cli.command, Command::InternalLocalCheckReady));
        assert_eq!(
            Cli::try_parse_from(["automata-runner", "__local-check-ready", "unexpected"])
                .unwrap_err()
                .kind(),
            ErrorKind::UnknownArgument
        );
        let help = Cli::command().render_help().to_string();
        assert!(!help.contains("__local-check-ready"));
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
    fn enroll_requires_one_explicit_redacted_token_source() {
        let marker = "private-enrollment-source-marker";
        let cli = Cli::try_parse_from([
            "automata-runner",
            "enroll",
            "--config",
            "/var/lib/automata/runner.json",
            "--server",
            "https://ci.example.test",
            "--name",
            "linux-amd64-1",
            "--token-source",
            &format!("file:/run/secrets/{marker}"),
        ])
        .expect("enroll CLI must parse");
        let Command::Enroll(args) = cli.command else {
            panic!("enroll command expected");
        };
        assert_eq!(args.name, "linux-amd64-1");
        assert!(matches!(&args.token_source, EnrollmentTokenSource::File(_)));
        let rendered = format!("{:?}", args.token_source);
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains(marker));

        for (source, reference) in [
            (
                "env:PRIVATE_ENROLLMENT_SOURCE_MARKER",
                Some("PRIVATE_ENROLLMENT_SOURCE_MARKER"),
            ),
            ("stdin", None),
        ] {
            let cli = Cli::try_parse_from([
                "automata-runner",
                "enroll",
                "--config",
                "/var/lib/automata/runner.json",
                "--server",
                "https://ci.example.test",
                "--name",
                "linux-amd64-1",
                "--token-source",
                source,
            ])
            .expect("each explicit token source must parse");
            let rendered = format!("{cli:?}");
            assert!(rendered.contains("[REDACTED]"));
            if let Some(reference) = reference {
                assert!(!rendered.contains(reference));
            }
        }

        let omitted = Cli::try_parse_from([
            "automata-runner",
            "enroll",
            "--config",
            "/var/lib/automata/runner.json",
            "--server",
            "https://ci.example.test",
            "--name",
            "linux-amd64-1",
        ])
        .expect_err("the token source must be required");
        assert_eq!(omitted.kind(), ErrorKind::MissingRequiredArgument);

        for removed in ["--token", "--token-file"] {
            let error = Cli::try_parse_from([
                "automata-runner",
                "enroll",
                "--config",
                "/var/lib/automata/runner.json",
                "--server",
                "https://ci.example.test",
                "--name",
                "linux-amd64-1",
                removed,
                marker,
            ])
            .expect_err("removed token arguments must not be accepted");
            assert_eq!(error.kind(), ErrorKind::UnknownArgument);
            assert!(!error.to_string().contains(marker));
        }

        for invalid_source in [
            marker.to_owned(),
            format!("file:relative-{marker}"),
            format!("env:lowercase_{marker}"),
        ] {
            let invalid = Cli::try_parse_from([
                "automata-runner",
                "enroll",
                "--config",
                "/var/lib/automata/runner.json",
                "--server",
                "https://ci.example.test",
                "--name",
                "linux-amd64-1",
                "--token-source",
                invalid_source.as_str(),
            ])
            .expect_err("invalid token sources must fail without being retained");
            assert_eq!(invalid.kind(), ErrorKind::InvalidValue);
            assert!(!invalid.to_string().contains(&invalid_source));
        }
    }

    #[test]
    fn enroll_help_exposes_only_the_current_explicit_source_contract() {
        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("enroll")
            .expect("enroll command")
            .render_long_help()
            .to_string();
        assert!(help.contains("--token-source"));
        assert!(help.contains("file:PATH|env:NAME|stdin"));
        assert!(!help.contains("--token-file"));
        assert!(!help.contains("AUTOMATA_RUNNER_ENROLLMENT_TOKEN"));
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
