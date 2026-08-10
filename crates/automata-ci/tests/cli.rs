use automata_ci::cli::{
    AuthCommand, Cli, Command, OutputFormat, RepositoryRef, SecretCommand, SecretProviderCommand,
    SecretScope, WorkflowCommand,
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
fn github_provider_configuration_is_one_redacted_source_reference() {
    let marker = "AUTOMATA_SENSITIVE_GITHUB_PROVIDER_CONFIG";
    let cli = Cli::try_parse_from([
        "automata",
        "server",
        "--github-provider-config-source",
        &format!("env:{marker}"),
    ])
    .expect("GitHub provider source syntax must parse");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    assert!(args.github_provider_config_source.is_some());
    let debug = format!("{args:?}");
    assert!(debug.contains("[redacted]"));
    assert!(!debug.contains(marker));

    let raw_marker = "raw-github-provider-secret-marker";
    let raw = Cli::try_parse_from([
        "automata",
        "server",
        "--github-provider-config-source",
        raw_marker,
    ])
    .expect("raw value becomes a redacted invalid sentinel");
    let Command::Server(raw_args) = raw.command else {
        panic!("server command expected");
    };
    assert!(!format!("{raw_args:?}").contains(raw_marker));
    assert!(matches!(
        ServerConfig::from_args(&raw_args),
        Err(ServerConfigError::InvalidSecretSource)
    ));
}

#[test]
fn github_provider_help_describes_the_exact_optional_runtime() {
    let mut command = Cli::command();
    let server = command
        .find_subcommand_mut("server")
        .expect("server command");
    let help = server.render_long_help().to_string();

    assert!(help.contains("signed webhook route"));
    assert!(help.contains("supervising source delivery, Checks publication"));
    assert!(!help.contains("does not currently install"));
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
        ["server", "preview", "auth", "workflow", "secret", "admin"]
    );
    for unavailable in ["run", "job", "runner", "runner-group", "artifact", "cache"] {
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
fn operator_json_output_is_accepted_after_a_nested_subcommand() {
    let cli = Cli::try_parse_from(["automata", "admin", "status", "--output", "json"])
        .expect("CLI must parse");

    assert_eq!(
        cli.command.operator().expect("operator options").output,
        OutputFormat::Json
    );
}

#[test]
fn leading_operator_options_remain_compatible_and_override_nested_defaults() {
    let cli = Cli::try_parse_from([
        "automata",
        "--server-url",
        "https://ci.example.test",
        "--output",
        "json",
        "admin",
        "status",
    ])
    .expect("leading operator options must parse");

    assert_eq!(
        cli.operator_options(),
        Some(("https://ci.example.test", OutputFormat::Json))
    );
    assert!(!cli.service_has_operator_options());
}

#[test]
fn operator_options_are_not_advertised_or_accepted_by_service_commands() {
    let mut command = Cli::command();
    for service in ["server", "preview"] {
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

    let leading_service = Cli::try_parse_from(["automata", "--output", "json", "preview"])
        .expect("leading compatibility option parses before validation");
    assert!(leading_service.service_has_operator_options());

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
fn workflow_admission_help_describes_supervised_logical_progress() {
    let mut command = Cli::command();
    let workflow = command
        .find_subcommand_mut("workflow")
        .expect("workflow command");
    let admission = workflow
        .find_subcommand_mut("admit")
        .expect("workflow admission command");
    let help = admission.render_long_help().to_string();

    assert!(help.contains("supervises logical preparation, activation, and materialization"));
    assert!(help.contains("does not mean a job has finished"));
}

#[test]
fn workflow_admission_uses_exact_source_event_and_secret_references() {
    assert!(
        Cli::try_parse_from(["automata", "workflow", "dispatch"]).is_err(),
        "the CLI must not imply that admission executes a workflow"
    );
    let cli = Cli::try_parse_from([
        "automata",
        "workflow",
        "admit",
        "-R",
        "automata-ci/automata",
        "--provider-repository-id",
        "repository-automata",
        "--source-file",
        ".github/workflows/ci.yml",
        "--event-file",
        "target/dogfood-event.json",
        "--delivery-id",
        "delivery-7",
        "--commit-sha",
        "0123456789abcdef0123456789abcdef01234567",
        "--local-admission-token-source",
        "file:target/local-admission-token",
    ])
    .expect("workflow admission must parse");

    let Command::Workflow(workflow) = cli.command else {
        panic!("workflow command expected");
    };
    let WorkflowCommand::Admit(admission) = workflow.command;
    assert_eq!(admission.repository.to_string(), "automata-ci/automata");
    assert_eq!(admission.delivery_id, "delivery-7");
    assert_eq!(admission.event_name, "workflow_dispatch");
    assert_eq!(admission.git_ref, "refs/heads/main");
    let debug = format!("{:?}", admission.token_source);
    assert!(debug.contains("[redacted]"));
    assert!(!debug.contains("local-admission-token"));
}
