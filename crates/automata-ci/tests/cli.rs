#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use automata_ci::cli::InternalLocalCommand;
use automata_ci::cli::{
    AuthCommand, Cli, Command, DatabaseTransport, EnvironmentReviewDecision, InternalCommand,
    InternalObjectStoreArgs, InternalObjectStoreCommand, LocalCommand, LocalContainerEngine,
    OutputFormat, RepositoryRef, RerunSelection, S3TlsTrustMode, SecretCommand,
    SecretProviderCommand, SecretScope,
};
use automata_ci::server::{SecretSource, ServerConfig, ServerConfigError};
use clap::{CommandFactory as _, Parser as _};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn expect_internal_object_store(command: InternalCommand) -> Box<InternalObjectStoreArgs> {
    match command {
        InternalCommand::ObjectStore(args) => args,
        InternalCommand::Local(_) => panic!("expected object-store command"),
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn expect_internal_object_store(command: InternalCommand) -> Box<InternalObjectStoreArgs> {
    let InternalCommand::ObjectStore(args) = command;
    args
}

#[test]
fn server_uses_a_loopback_default() {
    let cli = Cli::try_parse_from(["automata", "server"]).expect("CLI must parse");

    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    assert_eq!(args.listen.to_string(), "127.0.0.1:8080");
    assert_eq!(args.database_transport, DatabaseTransport::WebPkiVerifyFull);
    assert!(args.database_private_ca_source.is_none());
}

#[test]
fn local_doctor_is_an_explicit_read_only_preflight() {
    let cli = Cli::try_parse_from([
        "automata", "local", "doctor", "--engine", "docker", "--json",
    ])
    .expect("local doctor must parse");

    let Command::Local(local) = cli.command else {
        panic!("local command expected");
    };
    let LocalCommand::Doctor(args) = local.command else {
        panic!("local doctor command expected");
    };
    assert_eq!(args.engine, LocalContainerEngine::Docker);
    assert!(args.json);

    assert!(
        Cli::try_parse_from(["automata", "local", "doctor", "--engine", "podman"]).is_err(),
        "an unqualified engine must not enter the local installation contract"
    );
    assert!(
        Cli::try_parse_from([
            "automata",
            "local",
            "doctor",
            "--server-url",
            "https://ci.example.test",
        ])
        .is_err(),
        "local lifecycle commands must not inherit the remote operator endpoint"
    );
    assert!(
        Cli::try_parse_from(["automata", "local", "doctor", "--output", "json"]).is_err(),
        "local lifecycle output must remain an explicit command contract"
    );
    assert!(
        Cli::try_parse_from([
            "automata",
            "local",
            "doctor",
            "--state-dir",
            "/tmp/automata-local",
        ])
        .is_err(),
        "engine-owned local state must not expose a host state-directory option"
    );
}

#[test]
fn local_check_is_explicit_source_only_workflow_dispatch_validation() {
    let cli = Cli::try_parse_from([
        "automata",
        "local",
        "check",
        ".github/workflows/ci.yml",
        "--input",
        "target=staging",
        "--json",
    ])
    .expect("local check must parse");
    let Command::Local(local) = cli.command else {
        panic!("local command expected");
    };
    let LocalCommand::Check(args) = local.command else {
        panic!("local check command expected");
    };
    assert_eq!(args.workflow.as_deref(), Some(".github/workflows/ci.yml"));
    assert_eq!(args.inputs.len(), 1);
    assert_eq!(args.inputs[0].name(), "target");
    assert!(args.json);
    assert!(format!("{args:?}").contains("target"));
    assert!(!format!("{args:?}").contains("staging"));

    assert!(
        Cli::try_parse_from(["automata", "local", "check", "--event", "push"]).is_err(),
        "local check must not fabricate provider event evidence"
    );
    assert!(
        Cli::try_parse_from(["automata", "local", "check", "--input", "missing-separator"])
            .is_err()
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn local_init_requires_explicit_canonical_host_custody_and_catalog_evidence() {
    let cli = Cli::try_parse_from([
        "automata",
        "local",
        "init",
        "--state-directory",
        "/var/lib/automata-local/team",
        "--installation",
        "team-2",
        "--workers",
        "3",
        "--catalog-source",
        "file:/srv/releases/catalog.json",
    ])
    .expect("complete local init syntax must parse");
    let Command::Local(local) = cli.command else {
        panic!("local command expected");
    };
    let LocalCommand::Init(args) = local.command else {
        panic!("local init command expected");
    };
    assert_eq!(
        args.state_directory,
        std::path::Path::new("/var/lib/automata-local/team")
    );
    assert_eq!(args.installation.as_str(), "team-2");
    assert_eq!(args.workers.get(), 3);
    assert_eq!(args.catalog_source, "file:/srv/releases/catalog.json");

    for invalid in [
        vec![
            "automata",
            "local",
            "init",
            "--catalog-source",
            "file:/srv/catalog.json",
        ],
        vec![
            "automata",
            "local",
            "init",
            "--state-directory",
            "relative",
            "--catalog-source",
            "file:/srv/catalog.json",
        ],
        vec![
            "automata",
            "local",
            "init",
            "--state-directory",
            "/var/lib/automata",
            "--catalog-source",
            "https://example.test/catalog.json",
        ],
        vec![
            "automata",
            "local",
            "init",
            "--state-directory",
            "/var/lib/automata",
            "--catalog-source",
            "file:/srv/catalog.json",
            "--image",
            "foreign",
        ],
    ] {
        assert!(Cli::try_parse_from(invalid).is_err());
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn local_init_status_and_reset_stop_before_service_lifecycle_commands() {
    let mut command = Cli::command();
    let local = command.find_subcommand_mut("local").expect("local command");
    let names = local
        .get_subcommands()
        .map(clap::Command::get_name)
        .collect::<Vec<_>>();
    assert_eq!(names, ["doctor", "check", "init", "status", "reset"]);

    let init = local.find_subcommand_mut("init").expect("init command");
    let help = init.render_long_help().to_string();
    assert!(help.contains("without starting services"));
    let status = local.find_subcommand_mut("status").expect("status command");
    let help = status.render_long_help().to_string();
    assert!(help.contains("recorded custody or reset progress"));
    let reset = local.find_subcommand_mut("reset").expect("reset command");
    let help = reset.render_long_help().to_string();
    assert!(help.contains("retaining images and the state root"));
    for hidden_lifecycle in ["up", "down", "bootstrap", "relay"] {
        assert!(
            Cli::try_parse_from(["automata", "local", hidden_lifecycle]).is_err(),
            "{hidden_lifecycle} must not leak into the current sealed-custody boundary"
        );
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn local_status_and_reset_require_explicit_state_and_reset_confirmation() {
    let cli = Cli::try_parse_from([
        "automata",
        "local",
        "status",
        "--state-directory",
        "/var/lib/automata-local/team",
        "--json",
    ])
    .unwrap();
    let Command::Local(local) = cli.command else {
        panic!("local command expected");
    };
    let LocalCommand::Status(args) = local.command else {
        panic!("local status expected");
    };
    assert_eq!(
        args.state_directory,
        std::path::Path::new("/var/lib/automata-local/team")
    );
    assert!(args.json);

    let cli = Cli::try_parse_from([
        "automata",
        "local",
        "reset",
        "--state-directory",
        "/var/lib/automata-local/team",
        "--yes",
    ])
    .unwrap();
    let Command::Local(local) = cli.command else {
        panic!("local command expected");
    };
    let LocalCommand::Reset(args) = local.command else {
        panic!("local reset expected");
    };
    assert!(args.yes);

    for invalid in [
        vec!["automata", "local", "status"],
        vec![
            "automata",
            "local",
            "status",
            "--state-directory",
            "relative",
        ],
        vec![
            "automata",
            "local",
            "reset",
            "--state-directory",
            "/var/lib/automata-local/team",
        ],
    ] {
        assert!(Cli::try_parse_from(invalid).is_err());
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn internal_local_materializer_is_one_fixed_argument_free_operation() {
    let cli = Cli::try_parse_from(["automata", "internal", "local", "materialize"])
        .expect("fixed internal materializer must parse");
    let Command::Internal(internal) = cli.command else {
        panic!("internal command expected");
    };
    let InternalCommand::Local(local) = internal.command else {
        panic!("internal local command expected");
    };
    assert!(matches!(local.command, InternalLocalCommand::Materialize));
    assert!(
        Cli::try_parse_from([
            "automata",
            "internal",
            "local",
            "materialize",
            "--path",
            "/tmp/foreign",
        ])
        .is_err()
    );
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
#[test]
fn linux_x86_64_local_mutations_and_internal_materializer_are_not_advertised() {
    let mut command = Cli::command();
    let local = command.find_subcommand_mut("local").expect("local command");
    let names = local
        .get_subcommands()
        .map(clap::Command::get_name)
        .collect::<Vec<_>>();
    assert_eq!(names, ["doctor", "check"]);
    for command in ["init", "status", "reset"] {
        assert!(Cli::try_parse_from(["automata", "local", command]).is_err());
    }
    assert!(Cli::try_parse_from(["automata", "internal", "local", "materialize"]).is_err());
}

#[test]
fn internal_object_store_bucket_initialization_is_hidden_exact_and_redacted() {
    let marker = "AUTOMATA_INTERNAL_PRIVATE_CA_MARKER";
    let cli = Cli::try_parse_from([
        "automata",
        "internal",
        "object-store",
        "ensure-bucket",
        "--s3-endpoint",
        "https://objects.example.test/",
        "--s3-bucket",
        "automata-local",
        "--s3-tls-trust",
        "private-ca",
        "--s3-private-ca-source",
        &format!("env:{marker}"),
        "--s3-access-key-source",
        "file:/run/secrets/s3-access-key",
        "--s3-secret-key-source",
        "file:/run/secrets/s3-secret-key",
    ])
    .expect("internal ensure-bucket command must parse");
    let Command::Internal(internal) = cli.command else {
        panic!("internal command expected");
    };
    let object_store = expect_internal_object_store(internal.command);
    let InternalObjectStoreCommand::EnsureBucket(args) = object_store.command;
    assert_eq!(args.s3.s3_tls_trust, S3TlsTrustMode::PrivateCa);
    let debug = format!("{args:?}");
    assert!(debug.contains("[redacted]"));
    assert!(!debug.contains(marker));

    let mut command = Cli::command();
    let internal = command
        .find_subcommand_mut("internal")
        .expect("internal namespace");
    assert!(internal.is_hide_set());
    assert!(
        !Cli::command()
            .render_long_help()
            .to_string()
            .contains("internal")
    );

    for unsupported in [
        vec!["automata", "__local-service-init"],
        vec!["automata", "internal", "object-store", "init"],
        vec!["automata", "internal", "ensure-bucket"],
    ] {
        assert!(Cli::try_parse_from(unsupported).is_err());
    }
    assert!(
        Cli::try_parse_from([
            "automata",
            "internal",
            "object-store",
            "ensure-bucket",
            "--s3-access-key",
            "raw-secret",
        ])
        .is_err(),
        "the internal command must not accept raw credential arguments"
    );
}

#[test]
fn internal_private_ca_raw_values_become_redacted_invalid_sources() {
    let marker = "raw-private-ca-secret-marker";
    let cli = Cli::try_parse_from([
        "automata",
        "internal",
        "object-store",
        "ensure-bucket",
        "--s3-tls-trust",
        "private-ca",
        "--s3-private-ca-source",
        marker,
    ])
    .expect("raw input must become a redacted invalid source sentinel");
    let Command::Internal(internal) = cli.command else {
        panic!("internal command expected");
    };
    let object_store = expect_internal_object_store(internal.command);
    let InternalObjectStoreCommand::EnsureBucket(args) = object_store.command;
    assert!(matches!(
        args.s3.s3_private_ca_source,
        Some(SecretSource::Invalid)
    ));
    assert!(!format!("{args:?}").contains(marker));
}

#[test]
fn server_rejects_an_invalid_socket_address_during_parsing() {
    let result = Cli::try_parse_from(["automata", "server", "--listen", "not-an-address"]);

    assert!(result.is_err());
}

#[test]
fn obsolete_service_alias_is_not_part_of_the_current_contract() {
    assert!(Cli::try_parse_from(["automata", "serve"]).is_err());
}

#[test]
fn server_credentials_must_be_references_not_values() {
    let cli = Cli::try_parse_from([
        "automata",
        "server",
        "--database-url-source",
        "postgres://operator:plaintext-secret@database/automata",
    ])
    .expect("invalid credential text must become a redacted configuration sentinel");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };

    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::InvalidSecretSource)
    ));
}

#[test]
fn server_help_distinguishes_human_and_app_credential_custody() {
    let mut command = Cli::command();
    let server = command
        .find_subcommand_mut("server")
        .expect("server command");
    let help = server.render_long_help().to_string();

    assert!(help.contains("durable human GitHub OAuth tokens"));
    assert!(help.contains("GitHub App service credentials"));
    assert!(!help.contains("durable GitHub provider credentials"));
}

#[test]
fn server_help_states_the_maintenance_timeout_ordering() {
    let mut command = Cli::command();
    let server = command
        .find_subcommand_mut("server")
        .expect("server command");
    let help = server.render_long_help().to_string();

    assert!(help.contains("Must be greater than the maintenance interval"));
}

#[test]
fn auth_login_is_the_exact_github_device_flow() {
    let cli = Cli::try_parse_from(["automata", "auth", "login"]).expect("CLI must parse");

    let Command::Auth(auth) = cli.command else {
        panic!("auth command expected");
    };
    let AuthCommand::Login = auth.command else {
        panic!("login command expected");
    };

    for unsupported in ["--mode", "--provider"] {
        assert!(
            Cli::try_parse_from(["automata", "auth", "login", unsupported, "value"]).is_err(),
            "unsupported login switches must not remain in the public CLI"
        );
    }
}

#[test]
fn only_operational_top_level_commands_are_advertised() {
    let command = Cli::command();
    let names = command
        .get_subcommands()
        .filter(|command| !command.is_hide_set())
        .map(clap::Command::get_name)
        .collect::<Vec<_>>();

    assert_eq!(
        names,
        [
            "server",
            "local",
            "auth",
            "secret",
            "environment-review",
            "rerun",
            "runner",
            "admin"
        ]
    );
    for unavailable in [
        "preview",
        "workflow",
        "run",
        "job",
        "runner-group",
        "artifact",
        "cache",
    ] {
        assert!(!names.contains(&unavailable));
    }
    assert!(Cli::try_parse_from(["automata", "preview"]).is_err());
}

#[test]
fn admin_advertises_only_operational_status() {
    let mut command = Cli::command();
    let admin = command.find_subcommand_mut("admin").expect("admin command");
    let names = admin
        .get_subcommands()
        .map(clap::Command::get_name)
        .collect::<Vec<_>>();

    assert_eq!(names, ["status"]);

    let status = admin.find_subcommand_mut("status").expect("status command");
    let help = status.render_long_help().to_string();
    assert!(help.contains("separate process-health identity"));
    assert!(help.contains("dependency-readiness observations"));
    assert!(!help.contains("version skew"));
    assert!(!help.contains("replica status"));
}

#[test]
fn stale_runner_session_timeout_help_states_its_maintenance_constraint() {
    let mut command = Cli::command();
    let server = command
        .find_subcommand_mut("server")
        .expect("server command");
    let timeout = server
        .get_arguments()
        .find(|argument| argument.get_long() == Some("stale-runner-session-timeout-seconds"))
        .expect("stale runner-session timeout option");

    assert_eq!(
        timeout.get_help().map(ToString::to_string).as_deref(),
        Some(
            "Missing-heartbeat duration after which a runner session is closed. Must be greater than the maintenance interval"
        )
    );
}

#[test]
fn nested_operator_options_are_retained_for_every_operator_tree() {
    let cases: [&[&str]; 5] = [
        &[
            "automata",
            "auth",
            "--server-url",
            "https://ci.example.test",
            "status",
            "--output",
            "json",
        ],
        &[
            "automata",
            "secret",
            "--server-url",
            "https://ci.example.test",
            "provider",
            "status",
            "--output",
            "json",
        ],
        &[
            "automata",
            "admin",
            "--server-url",
            "https://ci.example.test",
            "status",
            "--output",
            "json",
        ],
        &[
            "automata",
            "environment-review",
            "aaaaaaaa-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
            "--decision",
            "approve",
            "--server-url",
            "https://ci.example.test",
            "--output",
            "json",
        ],
        &[
            "automata",
            "rerun",
            "automata-ci/automata",
            "20000000-0000-4000-8000-000000000002",
            "--selection",
            "entire-workflow",
            "--server-url",
            "https://ci.example.test",
            "--output",
            "json",
        ],
    ];
    for arguments in cases {
        let cli = Cli::try_parse_from(arguments).expect("nested operator syntax must parse");
        let operator = cli.command.operator().expect("operator options");
        assert_eq!(operator.server_url, "https://ci.example.test");
        assert_eq!(operator.output, OutputFormat::Json);
    }
}

#[test]
fn environment_review_parses_both_exact_decisions() {
    for (decision, expected) in [
        ("approve", EnvironmentReviewDecision::Approve),
        ("reject", EnvironmentReviewDecision::Reject),
    ] {
        let cli = Cli::try_parse_from([
            "automata",
            "environment-review",
            "aaaaaaaa-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
            "--decision",
            decision,
        ])
        .expect("environment review must parse");
        let Command::EnvironmentReview(args) = cli.command else {
            panic!("environment-review command expected");
        };
        assert_eq!(
            args.repository_id.to_string(),
            "aaaaaaaa-1111-4111-8111-111111111111"
        );
        assert_eq!(
            args.attempt_id.to_string(),
            "22222222-2222-4222-8222-222222222222"
        );
        assert_eq!(args.decision, expected);
    }
}

#[test]
fn environment_review_rejects_ambiguous_or_missing_arguments() {
    for arguments in [
        [
            "00000000-0000-0000-0000-000000000000",
            "22222222-2222-4222-8222-222222222222",
            "approve",
        ],
        [
            "AAAAAAAA-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
            "approve",
        ],
        [
            "aaaaaaaa111141118111111111111111",
            "22222222-2222-4222-8222-222222222222",
            "approve",
        ],
        [
            "aaaaaaaa-1111-4111-8111-111111111111",
            "{22222222-2222-4222-8222-222222222222}",
            "approve",
        ],
        [
            "aaaaaaaa-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
            "allow",
        ],
    ] {
        assert!(
            Cli::try_parse_from([
                "automata",
                "environment-review",
                arguments[0],
                arguments[1],
                "--decision",
                arguments[2],
            ])
            .is_err()
        );
    }
    assert!(
        Cli::try_parse_from([
            "automata",
            "environment-review",
            "aaaaaaaa-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
        ])
        .is_err()
    );
}

#[test]
fn rerun_parses_exact_selection_and_retry_identity() {
    let cli = Cli::try_parse_from([
        "automata",
        "rerun",
        "Automata-CI/Automata",
        "20000000-0000-4000-8000-000000000002",
        "--selection",
        "job-and-dependents",
        "--job-id",
        "30000000-0000-4000-8000-000000000003",
        "--operation-id",
        "40000000-0000-4000-8000-000000000004",
    ])
    .expect("rerun command must parse");
    let Command::Rerun(args) = cli.command else {
        panic!("rerun command expected");
    };
    assert_eq!(args.selection, RerunSelection::JobAndDependents);
    assert_eq!(args.repository.owner(), "Automata-CI");
    assert_eq!(args.repository.name(), "Automata");
    assert_eq!(
        args.source_run_id.to_string(),
        "20000000-0000-4000-8000-000000000002"
    );
    assert_eq!(
        args.job_id.expect("job ID").to_string(),
        "30000000-0000-4000-8000-000000000003"
    );
    assert_eq!(
        args.operation_id.expect("operation ID").to_string(),
        "40000000-0000-4000-8000-000000000004"
    );
}

#[test]
fn runner_token_has_safe_scoped_defaults() {
    let cli = Cli::try_parse_from(["automata", "runner", "token"])
        .expect("runner token command must parse");
    let Command::Runner(args) = cli.command else {
        panic!("runner command expected");
    };
    let automata_ci::cli::RunnerCommand::Token(token) = args.command;
    assert!(!token.discard_pending);
    assert_eq!(token.group, "default");
    assert_eq!(token.expires_in_seconds, 900);

    let cli = Cli::try_parse_from(["automata", "runner", "token", "--discard-pending"])
        .expect("pending runner token discard must parse");
    let Command::Runner(args) = cli.command else {
        panic!("runner command expected");
    };
    let automata_ci::cli::RunnerCommand::Token(token) = args.command;
    assert!(token.discard_pending);

    assert!(
        Cli::try_parse_from([
            "automata",
            "runner",
            "token",
            "--expires-in-seconds",
            "3601"
        ])
        .is_err()
    );
}

#[test]
fn rerun_parses_all_three_exact_selection_modes() {
    for (mode, job_id, expected) in [
        ("entire-workflow", None, RerunSelection::EntireWorkflow),
        (
            "failed-jobs-and-dependents",
            None,
            RerunSelection::FailedJobsAndDependents,
        ),
        (
            "job-and-dependents",
            Some("30000000-0000-4000-8000-000000000003"),
            RerunSelection::JobAndDependents,
        ),
    ] {
        let mut arguments = vec![
            "automata",
            "rerun",
            "automata-ci/automata",
            "20000000-0000-4000-8000-000000000002",
            "--selection",
            mode,
        ];
        if let Some(job_id) = job_id {
            arguments.extend(["--job-id", job_id]);
        }
        let cli = Cli::try_parse_from(arguments).expect("selection must parse");
        let Command::Rerun(args) = cli.command else {
            panic!("rerun command expected");
        };
        assert_eq!(args.selection, expected);
        assert_eq!(args.job_id.is_some(), job_id.is_some());
        assert!(args.operation_id.is_none());
    }
}

#[test]
fn rerun_rejects_ambiguous_identifiers_and_inconsistent_job_selection() {
    let invalid_arguments: [&[&str]; 6] = [
        &[
            "owner/repository/extra",
            "20000000-0000-4000-8000-000000000002",
            "--selection",
            "entire-workflow",
        ],
        &[
            "owner only",
            "20000000-0000-4000-8000-000000000002",
            "--selection",
            "entire-workflow",
        ],
        &[
            "automata-ci/automata",
            "00000000-0000-0000-0000-000000000000",
            "--selection",
            "entire-workflow",
        ],
        &[
            "automata-ci/automata",
            "AAAAAAAA-1111-4111-8111-111111111111",
            "--selection",
            "entire-workflow",
        ],
        &[
            "automata-ci/automata",
            "20000000-0000-4000-8000-000000000002",
            "--selection",
            "job-and-dependents",
            "--job-id",
            "30000000000040008000000000000003",
        ],
        &[
            "automata-ci/automata",
            "20000000-0000-4000-8000-000000000002",
            "--selection",
            "entire-workflow",
            "--operation-id",
            "{40000000-0000-4000-8000-000000000004}",
        ],
    ];
    for arguments in invalid_arguments {
        let mut command = vec!["automata", "rerun"];
        command.extend_from_slice(arguments);
        assert!(
            Cli::try_parse_from(command).is_err(),
            "ambiguous rerun coordinate or UUID must fail"
        );
    }
    assert!(
        Cli::try_parse_from([
            "automata",
            "rerun",
            "automata-ci/automata",
            "20000000-0000-4000-8000-000000000002",
            "--selection",
            "job-and-dependents",
        ])
        .is_err()
    );
    for selection in ["entire-workflow", "failed-jobs-and-dependents"] {
        assert!(
            Cli::try_parse_from([
                "automata",
                "rerun",
                "automata-ci/automata",
                "20000000-0000-4000-8000-000000000002",
                "--selection",
                selection,
                "--job-id",
                "30000000-0000-4000-8000-000000000003",
            ])
            .is_err()
        );
    }
}

#[test]
fn operator_options_are_scoped_to_operator_commands() {
    assert!(
        Cli::try_parse_from([
            "automata",
            "--server-url",
            "https://ci.example.test",
            "--output",
            "json",
            "admin",
            "status",
        ])
        .is_err()
    );

    let cli = Cli::try_parse_from([
        "automata",
        "admin",
        "--server-url",
        "https://ci.example.test",
        "--output",
        "json",
        "status",
    ])
    .expect("nested operator options must parse");
    let operator = cli.command.operator().expect("operator options");
    assert_eq!(operator.server_url, "https://ci.example.test");
    assert_eq!(operator.output, OutputFormat::Json);

    let root_help = Cli::command().render_long_help().to_string();
    assert!(!root_help.contains("--server-url"));
    assert!(!root_help.contains("--output"));
}

#[test]
fn operator_options_are_not_advertised_or_accepted_by_non_operator_commands() {
    let mut command = Cli::command();
    for service in ["server", "local"] {
        let help = command
            .find_subcommand_mut(service)
            .expect("service command")
            .render_long_help()
            .to_string();
        assert!(!help.contains("--server-url"), "{service} help");
        assert!(!help.contains("--output"), "{service} help");
    }

    assert!(
        Cli::try_parse_from([
            "automata",
            "server",
            "--server-url",
            "https://ci.example.test"
        ])
        .is_err()
    );

    let admin_help = Cli::command()
        .find_subcommand_mut("admin")
        .expect("admin command")
        .render_long_help()
        .to_string();
    assert!(admin_help.contains("--server-url"));
    assert!(admin_help.contains("--output"));
    assert!(admin_help.contains("Output format for this operator command"));
    assert!(!admin_help.contains("Machine-readable output"));
}

#[test]
fn server_exposes_only_the_fallback_tenant_option() {
    let mut command = Cli::command();
    let help = command
        .find_subcommand_mut("server")
        .expect("server command")
        .render_long_help()
        .to_string();

    assert!(help.contains("--fallback-tenant-id"));
    assert!(!help.contains("--local-admission-token-source"));
    assert!(!help.contains("--local-admission-tenant"));
    assert!(
        Cli::try_parse_from([
            "automata",
            "server",
            "--local-admission-token-source",
            "env:AUTOMATA_LOCAL_ADMISSION_TOKEN",
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from(["automata", "server", "--local-admission-tenant", "legacy",]).is_err()
    );
}

#[test]
fn secret_values_are_not_accepted_as_command_arguments() {
    let result = Cli::try_parse_from([
        "automata",
        "secret",
        "create",
        "TOKEN",
        "--scope",
        "repo:automata/automata",
        "plaintext-value",
    ]);

    assert!(
        result.is_err(),
        "secret material must never be read from argv"
    );
}

#[test]
fn secret_create_accepts_a_scoped_file_source() {
    let cli = Cli::try_parse_from([
        "automata",
        "secret",
        "create",
        "TOKEN",
        "--scope",
        "repo:automata/automata",
        "--from-file",
        "/secure/token",
    ])
    .expect("CLI must parse");

    let Command::Secret(secret) = cli.command else {
        panic!("secret command expected");
    };
    let SecretCommand::Create(create) = secret.command else {
        panic!("secret create command expected");
    };
    assert_eq!(create.name, "TOKEN");
    assert!(matches!(create.scope, SecretScope::Repository(_)));
}

#[test]
fn built_in_secret_provider_status_and_activation_are_explicit_commands() {
    for (operation, expected) in [
        ("status", SecretProviderCommand::Status),
        ("activate", SecretProviderCommand::Activate),
    ] {
        let cli = Cli::try_parse_from(["automata", "secret", "provider", operation])
            .expect("provider command must parse");
        let Command::Secret(secret) = cli.command else {
            panic!("secret command expected");
        };
        let SecretCommand::Provider(provider) = secret.command else {
            panic!("provider command expected");
        };
        assert_eq!(
            std::mem::discriminant(&provider.command),
            std::mem::discriminant(&expected)
        );
    }
}

#[test]
fn secret_mutation_help_states_the_current_combined_authority_contract() {
    let mut command = Cli::command();
    let secret = command
        .find_subcommand_mut("secret")
        .expect("secret command");
    let create = secret
        .find_subcommand_mut("create")
        .expect("create command");
    let create_help = create.render_long_help().to_string();
    assert!(create_help.contains("secrets:metadata:read"));
    assert!(create_help.contains("secrets:create"));

    let delete = secret
        .find_subcommand_mut("delete")
        .expect("delete command");
    let delete_help = delete.render_long_help().to_string();
    assert!(delete_help.contains("secrets:metadata:read"));
    assert!(delete_help.contains("secrets:delete"));

    let provider = secret
        .find_subcommand_mut("provider")
        .expect("provider command");
    let activate = provider
        .find_subcommand_mut("activate")
        .expect("activate command");
    let activate_help = activate.render_long_help().to_string();
    assert!(activate_help.contains("secret-providers:read"));
    assert!(activate_help.contains("secret-providers:manage"));
}

#[test]
fn repository_references_reject_ambiguous_paths() {
    assert!("owner/name".parse::<RepositoryRef>().is_ok());
    assert!("owner/name/extra".parse::<RepositoryRef>().is_err());
    assert!("owner only".parse::<RepositoryRef>().is_err());
    assert!("./name".parse::<RepositoryRef>().is_err());
    assert!("owner/..".parse::<RepositoryRef>().is_err());
}

#[test]
fn only_operational_repository_secret_scopes_are_advertised() {
    let value = "repo:owner/repository";
    let scope = value.parse::<SecretScope>().expect("scope must parse");
    assert_eq!(scope.to_string(), value);
    assert!("org:organization".parse::<SecretScope>().is_err());
    assert!(
        "env:owner/repository/production"
            .parse::<SecretScope>()
            .is_err()
    );
}

#[test]
fn workflow_commands_are_not_part_of_the_operator_contract() {
    assert!(
        Cli::try_parse_from(["automata", "workflow", "admit"]).is_err(),
        "workflow admission is authenticated provider ingress, not an operator command"
    );
}
