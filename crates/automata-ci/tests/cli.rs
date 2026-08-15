use automata_ci::cli::{
    AuthCommand, Cli, Command, EnvironmentReviewDecision, LocalCommand, LocalContainerEngine,
    OutputFormat, RepositoryRef, RerunSelection, SecretCommand, SecretProviderCommand, SecretScope,
};
use automata_ci::server::{ServerConfig, ServerConfigError};
use clap::{CommandFactory as _, Parser as _};

#[test]
fn server_uses_a_loopback_default() {
    let cli = Cli::try_parse_from(["automata", "server"]).expect("CLI must parse");

    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    assert_eq!(args.listen.to_string(), "127.0.0.1:8080");
}

#[test]
fn preview_is_an_explicit_dependency_free_mode() {
    let cli = Cli::try_parse_from(["automata", "preview"]).expect("CLI must parse");

    let Command::Preview(args) = cli.command else {
        panic!("preview command expected");
    };
    assert_eq!(args.listen.to_string(), "127.0.0.1:8080");
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
    let LocalCommand::Doctor(args) = local.command;
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
        .map(clap::Command::get_name)
        .collect::<Vec<_>>();

    assert_eq!(
        names,
        [
            "server",
            "preview",
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
        "workflow",
        "run",
        "job",
        "runner-group",
        "artifact",
        "cache",
    ] {
        assert!(!names.contains(&unavailable));
    }
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
    for service in ["server", "preview", "local"] {
        let help = command
            .find_subcommand_mut(service)
            .expect("service command")
            .render_long_help()
            .to_string();
        assert!(!help.contains("--server-url"), "{service} help");
        assert!(!help.contains("--output"), "{service} help");
    }

    assert!(Cli::try_parse_from(["automata", "preview", "--output", "json"]).is_err());
    assert!(
        Cli::try_parse_from([
            "automata",
            "server",
            "--server-url",
            "https://ci.example.test"
        ])
        .is_err()
    );

    assert!(Cli::try_parse_from(["automata", "--output", "json", "preview"]).is_err());

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
