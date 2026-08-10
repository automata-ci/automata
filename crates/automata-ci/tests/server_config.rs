use std::{fs, path::PathBuf, str::FromStr as _};

use automata_ci::{
    cli::{Cli, Command},
    server::{
        SecretEncryptionLoadError, SecretLoadError, SecretSource, ServerConfig, ServerConfigError,
        VersionedSecretSource,
    },
};
use automata_ci_key_management::KeyId;
use clap::Parser as _;

fn test_file(name: &str) -> PathBuf {
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("server-config");
    fs::create_dir_all(&directory).expect("target-local test directory must be creatable");
    directory.join(name)
}

fn write_secret_file(path: &PathBuf, contents: impl AsRef<[u8]>) {
    fs::write(path, contents).expect("secret fixture must be writable");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("secret fixture permissions must be owner-only");
    }
}

fn configured_human_auth_args() -> automata_ci::cli::ServerArgs {
    let cli = Cli::try_parse_from([
        "automata",
        "server",
        "--results-public-url",
        "https://results.example.test/",
        "--external-url",
        "https://ci.example.test/",
        "--github-client-id",
        "Iv1AutomataTest",
        "--github-client-secret-source",
        "env:AUTOMATA_TEST_GITHUB_CLIENT_SECRET",
        "--auth-session-hash-key-source",
        "file:target/auth-session-key",
        "--auth-encryption-key-source",
        "file:target/auth-encryption-key",
    ])
    .expect("complete human-auth syntax must parse");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    *args
}

const TEST_OIDC_RSA_MODULUS: &str = "3EB2d40ghnbyGr9du8XI5MMt_dHBRJlGaIQzk_fgMxwAxiToz5Ck540SPVcosHkRC-YjGIXjhwDSOlSJ9kxsoQRM5venRhsZeQWeuo_82S95k6CFguafVLvOSmFKltf5obDHo6DBxum_C_1jc4ZTJGEi1K7AV33qhJ_qZfAMI8K8a6xIpkXtcpTDU-yxTrdFQF5yzW7cVqyoXjHbcxIIS2UMVZTMJ3Hv5pgDxe9eYhVlxkBO0oZn89jVVMSfKnThlsj02cd9N5doFuJEKB5NTYGG9E7uWnOEq_jddN-NNa8hU1PTSqpzwIdDs1ZBet2wmNl5Wr1KI981Rkp2FTvPkw";
const TEST_OIDC_REPLACEMENT_RSA_MODULUS: &str = "o1A6wARhTiKLU_SKTdxcBDZK2gGqMoFS-fLEh_4fL-14V0JW5xRjwbzAO8m3oqzjCT9sDU1AZh-czgZ7QQQ8njEYrVykYLkapZOffcQvFt7rzsc2C9pbrkOnmbBq0b3_U53NPM1Fy1B3s1C_CRuOP7urc0VELeFaaEy3JFMTUpZDC-sti-JzY768ZfgwrcWkp703jEl2N7kkUoBQPZjpyymfm4ABPQJ6gObx95gAmV3p4XBIYxaxhoh7oSLUyF4solYC7N3mDCHmdf2CIbb8INdMfiqhLqOafdm9qCHT4wDNya94v7U7pHiggHyIkSa3RfMWomjDIEY39LSDgaFYSw";

fn oidc_manifest(mode: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema": 1,
        "subject_policy": {
            "mode": mode,
            "revision": 7
        },
        "supported_claims": [
            "event_name",
            "ref",
            "repository",
            "repository_owner",
            "run_attempt",
            "run_number",
            "runner_environment",
            "sha",
            "workflow",
            "workflow_ref",
            "workflow_sha"
        ],
        "request_bearer": {
            "maximum_lifetime_seconds": 600,
            "allowed_clock_skew_seconds": 30,
            "keys": [
                {
                    "key_id": "hmac-current",
                    "lifecycle": "active",
                    "source": "env:AUTOMATA_TEST_OIDC_HMAC_CURRENT"
                },
                {
                    "key_id": "hmac-old",
                    "lifecycle": "retained",
                    "source": "file:/run/keys/oidc-hmac-old"
                }
            ]
        },
        "id_token": {
            "lifetime_seconds": 300,
            "verifier_skew_seconds": 30,
            "keys": [
                {
                    "key_id": "rsa-current",
                    "lifecycle": "active",
                    "private_key_source": "env:AUTOMATA_TEST_OIDC_RSA_CURRENT",
                    "modulus": TEST_OIDC_RSA_MODULUS,
                    "exponent": "AQAB"
                },
                {
                    "key_id": "rsa-next",
                    "lifecycle": "prepublished",
                    "private_key_source": "file:/run/keys/oidc-rsa-next",
                    "modulus": TEST_OIDC_REPLACEMENT_RSA_MODULUS,
                    "exponent": "AQAB"
                }
            ]
        }
    }))
    .expect("OIDC manifest fixture")
}

#[test]
fn source_debug_output_redacts_environment_names_and_paths() {
    let marker = "AUTOMATA_SENSITIVE_REFERENCE_MARKER";
    for source in [
        SecretSource::from_str(&format!("env:{marker}")),
        SecretSource::from_str(&format!("file:target/{marker}")),
    ] {
        let source = source.expect("reference syntax must be valid");
        let debug = format!("{source:?}");
        assert!(!debug.contains(marker));
        assert!(debug.contains("[redacted]"));
    }
}

#[test]
fn scalar_file_loading_is_bounded_and_removes_only_one_terminal_newline() {
    let scalar_path = test_file("scalar.txt");
    write_secret_file(&scalar_path, b"exact-value\r\n");
    let source = SecretSource::File(scalar_path);
    let scalar = source.load_scalar(64).expect("bounded scalar must load");
    assert_eq!(scalar.as_str(), "exact-value");

    let oversized_path = test_file("oversized.txt");
    write_secret_file(&oversized_path, b"12345");
    let error = SecretSource::File(oversized_path)
        .load_bytes(4)
        .expect_err("oversized source must be rejected before use");
    assert!(matches!(error, SecretLoadError::TooLarge { maximum: 4 }));
}

#[test]
fn scalar_file_normalization_preserves_bound_and_rejects_embedded_line_endings() {
    let exact_path = test_file("exact-scalar-with-newline.txt");
    write_secret_file(&exact_path, b"1234\r\n");
    assert_eq!(
        SecretSource::File(exact_path)
            .load_scalar(4)
            .expect("a file line ending is outside the scalar bound")
            .as_str(),
        "1234"
    );

    for (name, content) in [
        ("embedded-newline.txt", b"one\ntwo".as_slice()),
        ("repeated-newline.txt", b"value\n\n".as_slice()),
    ] {
        let path = test_file(name);
        write_secret_file(&path, content);
        assert!(matches!(
            SecretSource::File(path).load_scalar(64),
            Err(SecretLoadError::InvalidScalar)
        ));
    }
}

#[cfg(unix)]
#[test]
fn secret_file_loading_rejects_unsafe_paths_and_permissions() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let public_path = test_file("public-secret.txt");
    fs::write(&public_path, b"must-not-load").expect("fixture must be writable");
    fs::set_permissions(&public_path, fs::Permissions::from_mode(0o644))
        .expect("fixture permissions must be configurable");
    assert!(matches!(
        SecretSource::File(public_path).load_bytes(64),
        Err(SecretLoadError::FileSecurity)
    ));

    let target_path = test_file("symlink-target-secret.txt");
    write_secret_file(&target_path, b"must-not-follow");
    let symlink_path = test_file("symlink-secret.txt");
    let _ = fs::remove_file(&symlink_path);
    symlink(&target_path, &symlink_path).expect("fixture symlink must be creatable");
    assert!(matches!(
        SecretSource::File(symlink_path).load_bytes(64),
        Err(SecretLoadError::FileSecurity)
    ));

    assert!(matches!(
        SecretSource::File(PathBuf::from("relative-secret.txt")).load_bytes(64),
        Err(SecretLoadError::FileSecurity)
    ));
}

#[test]
fn server_configuration_validates_non_secret_endpoint_fields() {
    let cli = Cli::try_parse_from(["automata", "server", "--s3-endpoint", "not an endpoint"])
        .expect("endpoint validation belongs to server configuration");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::InvalidS3Endpoint)
    ));
}

#[test]
fn human_auth_configuration_is_atomic_and_derives_a_fixed_callback() {
    let args = configured_human_auth_args();
    let config = ServerConfig::from_args(&args).expect("complete secure auth configuration");
    let auth = config.human_auth().expect("human auth must be enabled");
    assert_eq!(auth.external_url().as_str(), "https://ci.example.test/");
    assert_eq!(
        auth.callback_url().as_str(),
        "https://ci.example.test/auth/github/callback"
    );
    assert_eq!(auth.github_client_id().as_str(), "Iv1AutomataTest");
    assert_eq!(auth.encryption_key_id(), "primary");
    assert_eq!(auth.browser_session_ttl().as_secs(), 28_800);
    assert_eq!(auth.cli_session_ttl().as_secs(), 2_592_000);
    assert!(auth.bootstrap().is_none());

    let mut partial = configured_human_auth_args();
    partial.github_client_secret_source = None;
    assert!(matches!(
        ServerConfig::from_args(&partial),
        Err(ServerConfigError::IncompleteHumanAuth)
    ));
}

#[test]
fn github_provider_is_disabled_without_its_single_config_source() {
    let cli = Cli::try_parse_from([
        "automata",
        "server",
        "--results-public-url",
        "https://results.example.test/",
    ])
    .expect("provider-disabled syntax");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    assert!(
        ServerConfig::from_args(&args)
            .expect("provider configuration is optional")
            .github_provider()
            .is_none()
    );
}

#[test]
fn raw_github_webhook_secret_configuration_is_not_exposed() {
    assert!(
        Cli::try_parse_from([
            "automata",
            "server",
            "--github-webhook-secret-source",
            "env:AUTOMATA_TEST_GITHUB_WEBHOOK_SECRET",
        ])
        .is_err()
    );
}

#[test]
fn github_oidc_configuration_is_one_strict_https_results_bound_manifest() {
    let disabled = Cli::try_parse_from([
        "automata",
        "server",
        "--results-public-url",
        "https://results.example.test/",
    ])
    .expect("OIDC-disabled syntax");
    let Command::Server(disabled) = disabled.command else {
        panic!("server command expected");
    };
    assert!(
        ServerConfig::from_args(&disabled)
            .expect("OIDC is optional")
            .github_oidc()
            .is_none()
    );

    let manifest_path = test_file("github-oidc.json");
    write_secret_file(&manifest_path, oidc_manifest("stable_owner_evidence"));
    let manifest_source = format!("file:{}", manifest_path.display());
    let cli = Cli::try_parse_from([
        "automata",
        "server",
        "--results-public-url",
        "https://results.example.test/",
        "--github-oidc-config-source",
        &manifest_source,
    ])
    .expect("complete OIDC configuration syntax");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    let config = ServerConfig::from_args(&args).expect("complete OIDC manifest");
    assert_eq!(
        config
            .github_oidc()
            .expect("OIDC enabled")
            .issuer()
            .as_str(),
        "https://results.example.test/"
    );

    write_secret_file(&manifest_path, oidc_manifest("repository_evidence"));
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::InvalidGithubOidcConfiguration)
    ));

    write_secret_file(&manifest_path, oidc_manifest("stable_owner_evidence"));
    let development = Cli::try_parse_from([
        "automata",
        "server",
        "--results-public-url",
        "http://127.0.0.1:8081/",
        "--results-allow-development-http",
        "--github-oidc-config-source",
        &manifest_source,
    ])
    .expect("explicit Results development syntax");
    let Command::Server(development) = development.command else {
        panic!("server command expected");
    };
    assert!(matches!(
        ServerConfig::from_args(&development),
        Err(ServerConfigError::InvalidGithubOidcConfiguration)
    ));
}

#[test]
fn human_auth_external_origin_is_exact_and_loopback_http_is_explicit() {
    for invalid in [
        "https://ci.example.test/base/",
        "https://user@ci.example.test/",
        "https://ci.example.test/?return=/admin",
        "http://127.0.0.1:8080/",
    ] {
        let mut args = configured_human_auth_args();
        args.external_url = Some(invalid.into());
        assert!(matches!(
            ServerConfig::from_args(&args),
            Err(ServerConfigError::InvalidExternalUrl)
        ));
    }

    let mut loopback = configured_human_auth_args();
    loopback.external_url = Some("http://127.0.0.1:8080/".into());
    loopback.auth_allow_loopback_http = true;
    assert!(ServerConfig::from_args(&loopback).is_ok());

    loopback.external_url = Some("http://localhost:8080/".into());
    assert!(matches!(
        ServerConfig::from_args(&loopback),
        Err(ServerConfigError::InvalidExternalUrl)
    ));

    loopback.external_url = Some("http://127.0.0.1:8080/".into());
    loopback.listen = "0.0.0.0:8080".parse().expect("socket address");
    assert!(matches!(
        ServerConfig::from_args(&loopback),
        Err(ServerConfigError::InvalidExternalUrl)
    ));
}

#[test]
fn non_loopback_human_listener_requires_an_explicit_trusted_proxy() {
    let mut args = configured_human_auth_args();
    args.listen = "192.168.0.8:8080".parse().expect("socket address");
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::InvalidHumanListenerPolicy)
    ));

    args.human_trusted_reverse_proxy = true;
    assert!(ServerConfig::from_args(&args).is_ok());

    assert!(
        Cli::try_parse_from([
            "automata",
            "server",
            "--results-public-url",
            "https://results.example.test/",
            "--human-trusted-reverse-proxy",
            "--auth-allow-loopback-http",
        ])
        .is_err(),
        "trusted-proxy and literal-loopback development policies must be disjoint"
    );
}

#[test]
fn mandatory_service_listeners_reject_ephemeral_ports() {
    for (flag, listen) in [
        ("--listen", "127.0.0.1:0"),
        ("--results-listen", "127.0.0.1:0"),
        ("--runner-listen", "127.0.0.1:0"),
    ] {
        let cli = Cli::try_parse_from([
            "automata",
            "server",
            "--results-public-url",
            "https://results.example.test/",
            flag,
            listen,
        ])
        .expect("socket syntax must parse before configuration validation");
        let Command::Server(args) = cli.command else {
            panic!("server command expected");
        };
        assert!(matches!(
            ServerConfig::from_args(&args),
            Err(ServerConfigError::InvalidServiceListener)
        ));
    }
}

#[test]
fn installation_bootstrap_requires_proof_identity_and_exact_tenant() {
    let mut args = configured_human_auth_args();
    args.bootstrap_token_source = Some(
        SecretSource::from_str("env:AUTOMATA_TEST_BOOTSTRAP_TOKEN")
            .expect("valid bootstrap source"),
    );
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::InvalidBootstrapConfiguration)
    ));

    args.bootstrap_github_user_id = Some(42);
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::InvalidBootstrapConfiguration)
    ));

    args.bootstrap_tenant_id = Some("automata-main".into());
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::InvalidBootstrapConfiguration)
    ));

    args.bootstrap_tenant_display_name = Some("Automata CI".into());
    let config = ServerConfig::from_args(&args).expect("complete bootstrap authority");
    let bootstrap = config
        .human_auth()
        .and_then(|auth| auth.bootstrap())
        .expect("bootstrap configuration");
    assert_eq!(bootstrap.github_user_id(), 42);
    assert_eq!(bootstrap.tenant().tenant_id().as_str(), "automata-main");
    assert_eq!(bootstrap.tenant().display_name(), "Automata CI");

    args.bootstrap_github_user_id = Some(0);
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::InvalidBootstrapConfiguration)
    ));

    args.bootstrap_github_user_id = Some(42);
    args.bootstrap_tenant_id = Some("bad\ntenant".into());
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::InvalidBootstrapConfiguration)
    ));

    args.bootstrap_tenant_id = Some("automata-main".into());
    args.bootstrap_tenant_display_name = Some("\n".into());
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::InvalidBootstrapConfiguration)
    ));
}

#[test]
fn human_session_and_key_policies_remain_bounded_after_cli_parsing() {
    let mut args = configured_human_auth_args();
    args.auth_browser_session_ttl_seconds = 299;
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::InvalidAuthSessionLifetime)
    ));

    args.auth_browser_session_ttl_seconds = 28_800;
    args.auth_cli_session_ttl_seconds = 7_776_001;
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::InvalidAuthSessionLifetime)
    ));

    args.auth_cli_session_ttl_seconds = 2_592_000;
    args.auth_key_id = "invalid key id".into();
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::InvalidAuthKeyId)
    ));
}

#[test]
fn human_auth_hash_and_envelope_keys_are_exact_length_and_rotation_aware() {
    let active_path = test_file("auth-kek-active.bin");
    let old_path = test_file("auth-kek-old.bin");
    let session_path = test_file("auth-session-hash.bin");
    write_secret_file(&active_path, [0x61; 32]);
    write_secret_file(&old_path, [0x62; 32]);
    write_secret_file(&session_path, [0x63; 32]);

    let mut args = configured_human_auth_args();
    args.auth_encryption_key_source = Some(SecretSource::File(active_path));
    args.auth_key_id = "auth-current-2026".into();
    args.auth_decryption_keys = vec![
        VersionedSecretSource::from_str(&format!("auth-old-2025=file:{}", old_path.display()))
            .expect("versioned old auth key"),
    ];
    args.auth_session_hash_key_source = Some(SecretSource::File(session_path.clone()));

    let config = ServerConfig::from_args(&args).expect("rotation-aware auth configuration");
    let auth = config.human_auth().expect("human auth configured");
    assert_eq!(auth.encryption_key_id(), "auth-current-2026");
    assert_eq!(
        auth.encryption()
            .decrypt_only_key_ids()
            .map(KeyId::as_str)
            .collect::<Vec<_>>(),
        ["auth-old-2025"]
    );
    assert_eq!(
        auth.encryption()
            .load_local_keyring()
            .expect("auth keyring")
            .active_key_id()
            .as_str(),
        "auth-current-2026"
    );
    assert_eq!(
        auth.load_session_hash_key()
            .expect("exact session hash key")
            .len(),
        32
    );

    write_secret_file(&session_path, [0x63; 31]);
    assert!(matches!(
        auth.load_session_hash_key(),
        Err(SecretLoadError::InvalidLength { expected: 32 })
    ));

    args.auth_decryption_keys = vec![
        VersionedSecretSource::from_str(&format!("auth-current-2026=file:{}", old_path.display()))
            .expect("duplicate auth key identity"),
    ];
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::InvalidAuthKeyId)
    ));
}

#[test]
fn bootstrap_proof_requires_high_entropy_length_before_use() {
    let token_path = test_file("bootstrap-token-short.txt");
    write_secret_file(&token_path, b"short-bootstrap-proof");
    let mut args = configured_human_auth_args();
    args.bootstrap_token_source = Some(SecretSource::File(token_path));
    args.bootstrap_github_user_id = Some(42);
    args.bootstrap_tenant_id = Some("automata-main".into());
    args.bootstrap_tenant_display_name = Some("Automata CI".into());

    let config = ServerConfig::from_args(&args).expect("syntactically complete bootstrap");
    let bootstrap = config
        .human_auth()
        .and_then(|auth| auth.bootstrap())
        .expect("bootstrap configured");
    assert!(matches!(
        bootstrap.load_token(),
        Err(SecretLoadError::TooShort { minimum: 32 })
    ));
}

#[test]
fn built_in_secret_provider_is_opt_in_and_loads_a_rotation_keyring() {
    let active_path = test_file("secret-kek-active.bin");
    let old_path = test_file("secret-kek-old.bin");
    write_secret_file(&active_path, [0x41; 32]);
    write_secret_file(&old_path, [0x42; 32]);
    let active_source = format!("file:{}", active_path.display());
    let old_source = format!("old-2025=file:{}", old_path.display());
    let cli = Cli::try_parse_from([
        "automata",
        "server",
        "--results-public-url",
        "https://results.example.test/",
        "--secret-encryption-key-source",
        &active_source,
        "--secret-encryption-key-id",
        "current-2026",
        "--secret-decryption-key",
        &old_source,
    ])
    .expect("secret encryption syntax");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    let config = ServerConfig::from_args(&args).expect("secret encryption configuration");
    let encryption = config
        .secret_encryption()
        .expect("built-in provider must be configured");
    assert_eq!(encryption.active_key_id().as_str(), "current-2026");
    assert_eq!(
        encryption
            .decrypt_only_key_ids()
            .map(KeyId::as_str)
            .collect::<Vec<_>>(),
        ["old-2025"]
    );
    let keyring = encryption
        .load_local_keyring()
        .expect("exact-length key material");
    assert_eq!(keyring.active_key_id().as_str(), "current-2026");

    let cli = Cli::try_parse_from([
        "automata",
        "server",
        "--results-public-url",
        "https://results.example.test/",
    ])
    .expect("server syntax");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    assert!(
        ServerConfig::from_args(&args)
            .expect("default server configuration")
            .secret_encryption()
            .is_none()
    );
}

#[test]
fn built_in_secret_key_sources_are_redacted_exact_length_and_unique() {
    let marker = "AUTOMATA_SENSITIVE_OLD_SECRET_KEY";
    let versioned = VersionedSecretSource::from_str(&format!("old-key=env:{marker}"))
        .expect("versioned source");
    let rendered = format!("{versioned:?}");
    assert!(rendered.contains("old-key"));
    assert!(!rendered.contains(marker));
    assert!(rendered.contains("[redacted]"));

    let short_path = test_file("secret-kek-short.bin");
    write_secret_file(&short_path, [0x51; 31]);
    let short_source = format!("file:{}", short_path.display());
    let cli = Cli::try_parse_from([
        "automata",
        "server",
        "--results-public-url",
        "https://results.example.test/",
        "--secret-encryption-key-source",
        &short_source,
    ])
    .expect("key source syntax");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    let config = ServerConfig::from_args(&args).expect("syntactically valid key source");
    assert!(matches!(
        config
            .secret_encryption()
            .expect("configured provider")
            .load_local_keyring(),
        Err(SecretEncryptionLoadError::InvalidKeyConfiguration)
    ));

    let mut duplicate = configured_human_auth_args();
    duplicate.secret_encryption_key_source =
        Some(SecretSource::from_str("env:AUTOMATA_TEST_SECRET_KEK").expect("active key source"));
    duplicate.secret_encryption_key_id = "same-key".into();
    duplicate.secret_decryption_keys = vec![
        VersionedSecretSource::from_str("same-key=env:AUTOMATA_TEST_OLD_SECRET_KEK")
            .expect("old key source"),
    ];
    assert!(matches!(
        ServerConfig::from_args(&duplicate),
        Err(ServerConfigError::InvalidSecretEncryptionConfiguration)
    ));
}

#[test]
fn control_plane_payload_keys_are_mandatory_exact_length_and_rotation_aware() {
    let active_path = test_file("control-plane-kek-active.bin");
    let old_path = test_file("control-plane-kek-old.bin");
    write_secret_file(&active_path, [0x71; 32]);
    write_secret_file(&old_path, [0x72; 32]);
    let active_source = format!("file:{}", active_path.display());
    let old_source = format!("control-old=file:{}", old_path.display());
    let cli = Cli::try_parse_from([
        "automata",
        "server",
        "--results-public-url",
        "https://results.example.test/",
        "--control-plane-encryption-key-source",
        &active_source,
        "--control-plane-encryption-key-id",
        "control-current",
        "--control-plane-decryption-key",
        &old_source,
    ])
    .expect("control-plane encryption syntax");
    let Command::Server(mut args) = cli.command else {
        panic!("server command expected");
    };
    let config = ServerConfig::from_args(&args).expect("control-plane encryption configuration");
    let encryption = config.control_plane_encryption();
    assert_eq!(encryption.active_key_id().as_str(), "control-current");
    assert_eq!(
        encryption
            .decrypt_only_key_ids()
            .map(KeyId::as_str)
            .collect::<Vec<_>>(),
        ["control-old"]
    );
    assert_eq!(
        encryption
            .load_local_keyring()
            .expect("exact-length control-plane key material")
            .active_key_id()
            .as_str(),
        "control-current"
    );

    write_secret_file(&active_path, [0x71; 31]);
    assert!(matches!(
        encryption.load_local_keyring(),
        Err(SecretEncryptionLoadError::InvalidKeyConfiguration)
    ));

    args.control_plane_decryption_keys = vec![
        VersionedSecretSource::from_str(&format!("control-current=file:{}", old_path.display()))
            .expect("duplicate control-plane key identity"),
    ];
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::InvalidControlPlaneEncryptionConfiguration)
    ));
}

#[test]
fn local_admission_is_rejected_before_product_composition() {
    let cli = Cli::try_parse_from([
        "automata",
        "server",
        "--listen",
        "0.0.0.0:8080",
        "--local-admission-token-source",
        "env:AUTOMATA_LOCAL_ADMISSION_TOKEN",
    ])
    .expect("CLI syntax must parse");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::UnsupportedLocalAdmission)
    ));

    let cli = Cli::try_parse_from([
        "automata",
        "server",
        "--local-admission-token-source",
        "file:target/local-admission-token",
        "--results-public-url",
        "https://results.example.test/",
    ])
    .expect("loopback local ingress must parse");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::UnsupportedLocalAdmission)
    ));
}

#[test]
fn local_admission_tenant_is_validated_before_adapter_composition() {
    let cli = Cli::try_parse_from([
        "automata",
        "server",
        "--local-admission-tenant",
        "not a tenant",
    ])
    .expect("CLI syntax must parse");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::InvalidLocalAdmissionTenant)
    ));
}

#[test]
fn static_runner_registration_is_optional_and_requires_an_absolute_path() {
    let cli = Cli::try_parse_from([
        "automata",
        "server",
        "--results-public-url",
        "https://results.example.test/",
    ])
    .expect("server syntax");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    assert!(args.static_runner_registration_file.is_none());
    assert!(ServerConfig::from_args(&args).is_ok());

    let cli = Cli::try_parse_from([
        "automata",
        "server",
        "--results-public-url",
        "https://results.example.test/",
        "--static-runner-registration-file",
        "relative/static-runners.json",
    ])
    .expect("path syntax");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::InvalidStaticRunnerRegistrationPath)
    ));

    let cli = Cli::try_parse_from([
        "automata",
        "server",
        "--results-public-url",
        "https://results.example.test/",
        "--static-runner-registration-file",
        "/etc/automata/static-runners.json",
    ])
    .expect("absolute path syntax");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    assert_eq!(
        args.static_runner_registration_file.as_deref(),
        Some(std::path::Path::new("/etc/automata/static-runners.json"))
    );
    assert!(ServerConfig::from_args(&args).is_ok());
}

#[test]
fn maintenance_policy_has_bounded_resumable_defaults() {
    let cli = Cli::try_parse_from([
        "automata",
        "server",
        "--results-public-url",
        "https://results.example.test/",
    ])
    .expect("CLI syntax must parse");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    assert_eq!(args.maintenance_interval_seconds, 5);
    assert_eq!(args.maintenance_batch_size, 100);
    assert_eq!(args.maximum_lease_failures, 3);
    assert_eq!(args.stale_runner_session_timeout_seconds, 300);
    assert!(ServerConfig::from_args(&args).is_ok());
}

#[test]
fn metrics_are_opt_in_and_restricted_to_literal_loopback() {
    let cli = Cli::try_parse_from([
        "automata",
        "server",
        "--results-public-url",
        "https://results.example.test/",
    ])
    .expect("server syntax");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    assert!(args.metrics_listen.is_none());
    assert!(ServerConfig::from_args(&args).is_ok());

    for listen in [
        "0.0.0.0:9464",
        "192.0.2.10:9464",
        "[::]:9464",
        "127.0.0.1:0",
        "[::1]:0",
    ] {
        let cli = Cli::try_parse_from([
            "automata",
            "server",
            "--results-public-url",
            "https://results.example.test/",
            "--metrics-listen",
            listen,
        ])
        .expect("socket syntax");
        let Command::Server(args) = cli.command else {
            panic!("server command expected");
        };
        assert!(matches!(
            ServerConfig::from_args(&args),
            Err(ServerConfigError::MetricsRequiresLoopback)
        ));
    }

    for listen in ["127.0.0.1:9464", "[::1]:9464"] {
        let cli = Cli::try_parse_from([
            "automata",
            "server",
            "--results-public-url",
            "https://results.example.test/",
            "--metrics-listen",
            listen,
        ])
        .expect("socket syntax");
        let Command::Server(args) = cli.command else {
            panic!("server command expected");
        };
        assert!(ServerConfig::from_args(&args).is_ok());
    }
}

#[test]
fn results_endpoint_is_mandatory_and_plain_http_is_explicitly_scoped() {
    let cli = Cli::try_parse_from(["automata", "server"]).expect("CLI syntax must parse");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::MissingResultsEndpoint)
    ));

    let cli = Cli::try_parse_from([
        "automata",
        "server",
        "--results-listen",
        "192.168.0.8:8081",
        "--results-public-url",
        "http://host.containers.internal:8081/",
    ])
    .expect("CLI syntax must parse");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::InvalidResultsEndpoint)
    ));

    let cli = Cli::try_parse_from([
        "automata",
        "server",
        "--results-listen",
        "192.168.0.8:8081",
        "--results-public-url",
        "http://host.containers.internal:8081/",
        "--results-allow-development-http",
        "--results-trusted-private-host",
        "host.containers.internal",
    ])
    .expect("CLI syntax must parse");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    assert!(ServerConfig::from_args(&args).is_ok());
}

#[test]
fn non_loopback_https_results_requires_an_explicit_trusted_proxy() {
    let arguments = [
        "automata",
        "server",
        "--results-listen",
        "192.168.0.8:8081",
        "--results-public-url",
        "https://results.example.test/",
    ];
    let cli = Cli::try_parse_from(arguments).expect("CLI syntax must parse");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::InvalidResultsEndpoint)
    ));

    let cli = Cli::try_parse_from(
        arguments
            .into_iter()
            .chain(["--results-trusted-reverse-proxy"]),
    )
    .expect("trusted proxy assertion must parse");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    assert!(ServerConfig::from_args(&args).is_ok());

    assert!(
        Cli::try_parse_from([
            "automata",
            "server",
            "--results-public-url",
            "https://results.example.test/",
            "--results-trusted-reverse-proxy",
            "--results-allow-development-http",
        ])
        .is_err(),
        "production proxy and development HTTP policies must be disjoint"
    );
}

#[test]
fn results_development_endpoint_rejects_wildcards_and_host_mismatch() {
    for arguments in [
        [
            "0.0.0.0:8081",
            "http://host.containers.internal:8081/",
            "host.containers.internal",
        ],
        [
            "192.168.0.8:8081",
            "http://host.containers.internal:8081/",
            "different.internal",
        ],
        [
            "192.168.0.8:8081",
            "http://host.containers.internal:9090/",
            "host.containers.internal",
        ],
    ] {
        let cli = Cli::try_parse_from([
            "automata",
            "server",
            "--results-listen",
            arguments[0],
            "--results-public-url",
            arguments[1],
            "--results-allow-development-http",
            "--results-trusted-private-host",
            arguments[2],
        ])
        .expect("CLI syntax must parse");
        let Command::Server(args) = cli.command else {
            panic!("server command expected");
        };
        assert!(matches!(
            ServerConfig::from_args(&args),
            Err(ServerConfigError::InvalidResultsEndpoint)
        ));
    }
}

#[test]
fn maintenance_policy_rejects_unbounded_values_and_a_one_tick_resume_window() {
    let cli = Cli::try_parse_from(["automata", "server"]).expect("CLI syntax must parse");
    let Command::Server(mut args) = cli.command else {
        panic!("server command expected");
    };
    args.maintenance_batch_size = 0;
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::InvalidMaintenancePolicy)
    ));

    args.maintenance_batch_size = 100;
    args.maintenance_interval_seconds = 30;
    args.stale_runner_session_timeout_seconds = 30;
    assert!(matches!(
        ServerConfig::from_args(&args),
        Err(ServerConfigError::InvalidMaintenancePolicy)
    ));
}
