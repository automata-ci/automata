use automata::cli::{
    AuthCommand, AuthLoginMode, Cli, Command, OutputFormat, RepositoryRef, SecretCommand,
    SecretScope, WorkflowCommand,
};
use automata::server::{ServerConfig, ServerConfigError};
use clap::Parser as _;

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
    assert_eq!(Command::Preview(args).operation_name(), "preview");
}

#[test]
fn server_rejects_an_invalid_socket_address_during_parsing() {
    let result = Cli::try_parse_from(["automata", "server", "--listen", "not-an-address"]);

    assert!(result.is_err());
}

#[test]
fn serve_alias_uses_the_same_full_server_configuration() {
    let cli = Cli::try_parse_from(["automata", "serve"]).expect("serve alias must parse");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    assert_eq!(args.runner_listen.to_string(), "127.0.0.1:9090");
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
fn github_device_login_is_the_cli_default() {
    let cli = Cli::try_parse_from(["automata", "auth", "login"]).expect("CLI must parse");

    let Command::Auth(auth) = cli.command else {
        panic!("auth command expected");
    };
    let AuthCommand::Login(login) = auth.command else {
        panic!("login command expected");
    };
    assert_eq!(login.provider, "github");
    assert_eq!(login.mode, AuthLoginMode::Device);
}

#[test]
fn global_json_output_is_accepted_after_a_subcommand() {
    let cli = Cli::try_parse_from(["automata", "admin", "status", "--output", "json"])
        .expect("CLI must parse");

    assert_eq!(cli.output, OutputFormat::Json);
}

#[test]
fn secret_values_are_not_accepted_as_command_arguments() {
    let result = Cli::try_parse_from([
        "automata",
        "secret",
        "set",
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
fn secret_set_accepts_a_scoped_file_source() {
    let cli = Cli::try_parse_from([
        "automata",
        "secret",
        "set",
        "TOKEN",
        "--scope",
        "env:automata/automata/production",
        "--from-file",
        "/secure/token",
    ])
    .expect("CLI must parse");

    let Command::Secret(secret) = cli.command else {
        panic!("secret command expected");
    };
    let SecretCommand::Set(set) = secret.command else {
        panic!("secret set command expected");
    };
    assert_eq!(set.name, "TOKEN");
    assert!(matches!(set.scope, SecretScope::Environment { .. }));
}

#[test]
fn repository_references_reject_ambiguous_paths() {
    assert!("owner/name".parse::<RepositoryRef>().is_ok());
    assert!("owner/name/extra".parse::<RepositoryRef>().is_err());
    assert!("owner only".parse::<RepositoryRef>().is_err());
}

#[test]
fn all_secret_scope_forms_round_trip() {
    for value in [
        "repo:owner/repository",
        "org:organization",
        "env:owner/repository/production",
    ] {
        let scope = value.parse::<SecretScope>().expect("scope must parse");
        assert_eq!(scope.to_string(), value);
    }
}

#[test]
fn workflow_dispatch_uses_exact_source_event_and_secret_references() {
    let cli = Cli::try_parse_from([
        "automata",
        "workflow",
        "dispatch",
        "-R",
        "GoNeuralAI/automata",
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
    .expect("workflow dispatch must parse");

    let Command::Workflow(workflow) = cli.command else {
        panic!("workflow command expected");
    };
    let WorkflowCommand::Dispatch(dispatch) = workflow.command;
    assert_eq!(dispatch.repository.to_string(), "GoNeuralAI/automata");
    assert_eq!(dispatch.delivery_id, "delivery-7");
    assert_eq!(dispatch.event_name, "workflow_dispatch");
    assert_eq!(dispatch.git_ref, "refs/heads/main");
    let debug = format!("{:?}", dispatch.token_source);
    assert!(debug.contains("[redacted]"));
    assert!(!debug.contains("local-admission-token"));
}
