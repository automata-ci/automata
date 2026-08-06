use automata::cli::{
    AuthCommand, AuthLoginMode, Cli, Command, OutputFormat, RepositoryRef, SecretCommand,
    SecretScope,
};
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
fn server_rejects_an_invalid_socket_address_during_parsing() {
    let result = Cli::try_parse_from(["automata", "server", "--listen", "not-an-address"]);

    assert!(result.is_err());
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
