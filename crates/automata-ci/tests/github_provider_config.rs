use std::{
    fs,
    path::{Path, PathBuf},
};

use automata_ci::{
    cli::{Cli, Command},
    server::{
        GithubProviderConfig, GithubProviderConfigError, GithubProviderTransport,
        MAX_GITHUB_PROVIDER_CONFIG_BYTES, MAX_GITHUB_PROVIDER_REPOSITORIES, SecretSource,
        ServerConfig,
    },
};
use automata_ci_core::JobAuthorityProfile;
use automata_ci_store::{
    GithubProviderWorkflowSelection, GithubServerServiceJwtIssuer,
    MAX_WORKFLOW_RUNTIME_POLICY_BYTES, ProviderRepositoryVisibility, WorkflowRuntimePolicy,
    github_provider_repository_id,
};
use clap::Parser as _;
use serde_json::{Value, json};

const PRIVATE_KEY_MARKER: &str = "AUTOMATA_TEST_PROVIDER_PRIVATE_KEY_MARKER";
const HMAC_MARKER: &str = "AUTOMATA_TEST_PROVIDER_HMAC_MARKER";
const RUNNER_POLICY_CONFIGURATION: &[u8] = br#"{
  "workspace":{"derivation":1,"root":"/__w","schema":1},
  "mappings":[{
    "container_features":["automata.core/job-containers@v1"],
    "architecture":"x86_64","operating_system":"linux",
    "environment_profile":{"manifest_sha256":"1111111111111111111111111111111111111111111111111111111111111111","id":"automata.example/ubuntu-24-04"},
    "selector":"Ubuntu-24.04"
  }],"permissions":{"provider_default":{"contents":"read"},"read_all":{"actions":"read","artifact-metadata":"read","attestations":"read","checks":"read","code-quality":"read","contents":"read","deployments":"read","discussions":"read","issues":"read","models":"read","packages":"read","pages":"read","pull-requests":"read","security-events":"read","statuses":"read","vulnerability-alerts":"read"},"write_all":{"actions":"write","artifact-metadata":"write","attestations":"write","checks":"write","code-quality":"write","contents":"write","deployments":"write","discussions":"write","id-token":"write","issues":"write","models":"read","packages":"write","pages":"write","pull-requests":"write","security-events":"write","statuses":"write","vulnerability-alerts":"read"}},"resources":{"defaults":{"requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"limits":{"cpu_millis":1000,"memory_bytes":1073741824,"ephemeral_disk_bytes":0,"gpu_count":0}},"minimum_requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"maximum_limits":{"cpu_millis":4000,"memory_bytes":8589934592,"ephemeral_disk_bytes":0,"gpu_count":0}},"schema":1
}"#;

fn test_file(name: &str) -> PathBuf {
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("github-provider-config");
    fs::create_dir_all(&directory).expect("target-local test directory");
    directory.join(name)
}

fn write_private_file(path: &Path, contents: impl AsRef<[u8]>) {
    fs::write(path, contents).expect("configuration fixture must be writable");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("configuration fixture must be owner-only");
    }
}

fn uuid(value: u128) -> String {
    let encoded = format!("{value:032x}");
    format!(
        "{}-{}-{}-{}-{}",
        &encoded[0..8],
        &encoded[8..12],
        &encoded[12..16],
        &encoded[16..20],
        &encoded[20..32]
    )
}

fn authority(id: u128, policy_revision: u64) -> Value {
    json!({
        "authority_id": uuid(id),
        "policy_revision": policy_revision
    })
}

fn runner_policy() -> Value {
    serde_json::from_slice(RUNNER_POLICY_CONFIGURATION).expect("runner-policy fixture")
}

#[allow(clippy::too_many_arguments)]
fn repository(
    tenant_id: &str,
    connection_id: u128,
    installation_id: u64,
    repository_id: u64,
    repository_owner_id: u64,
    name: &str,
    visibility: &str,
    authority_profile: &str,
    checks_authority_id: u128,
    private_authority_id: Option<u128>,
) -> Value {
    json!({
        "tenant_id": tenant_id,
        "connection_id": uuid(connection_id),
        "installation_id": installation_id,
        "installation_binding_generation": 1,
        "repository_id": repository_id,
        "repository_owner_id": repository_owner_id,
        "repository": name,
        "default_branch": "main",
        "visibility": visibility,
        "manifest_revision": 3,
        "policy_revision": 7,
        "runtime_policy_revision": 9,
        "authority_profile": authority_profile,
        "runner_policy": runner_policy(),
        "check_name": "Automata CI",
        "authorities": {
            "checks_write": authority(checks_authority_id, 7),
            "private_repository_source_read": private_authority_id
                .map_or(Value::Null, |id| authority(id, 7))
        }
    })
}

fn public_repository() -> Value {
    repository(
        "tenant-public",
        0x201,
        202,
        302,
        402,
        "octo/public-repository",
        "public",
        "standard",
        0x501,
        None,
    )
}

fn private_repository() -> Value {
    repository(
        "tenant-private",
        0x202,
        101,
        301,
        401,
        "octo/private-repository",
        "private",
        "standard",
        0x502,
        Some(0x602),
    )
}

fn manifest(repositories: Vec<Value>) -> Value {
    let repositories = Value::Array(repositories);
    json!({
        "schema": 2,
        "transport": {"mode": "github_dot_com"},
        "dashboard_url": "https://ci.automata.example/",
        "app": {
            "id": 42,
            "client_id": "Iv1.automata-provider",
            "jwt_issuer": "app_client_id",
            "private_key_source": format!("env:{PRIVATE_KEY_MARKER}"),
            "configuration_revision": 5
        },
        "webhook": {
            "hmac_secret_source": format!("env:{HMAC_MARKER}"),
            "verifier_revision": 11
        },
        "repositories": repositories
    })
}

fn load_value(
    name: &str,
    value: &Value,
) -> Result<GithubProviderConfig, GithubProviderConfigError> {
    let path = test_file(name);
    write_private_file(
        &path,
        serde_json::to_vec(value).expect("configuration JSON fixture"),
    );
    GithubProviderConfig::load(&SecretSource::File(path))
}

fn load_bytes(
    name: &str,
    encoded: impl AsRef<[u8]>,
) -> Result<GithubProviderConfig, GithubProviderConfigError> {
    let path = test_file(name);
    write_private_file(&path, encoded);
    GithubProviderConfig::load(&SecretSource::File(path))
}

#[test]
fn runner_policy_preserves_raw_evidence_and_matches_store_codec_golden_values() {
    let expected = WorkflowRuntimePolicy::decode_configuration(RUNNER_POLICY_CONFIGURATION)
        .expect("Store runner-policy codec");
    let config = load_value(
        "runner-policy-cross-layer.json",
        &manifest(vec![private_repository()]),
    )
    .expect("provider runner policy");
    let repository = &config.repositories()[0];
    assert_eq!(repository.runtime_policy_revision().get(), 9);
    assert_eq!(repository.runner_policy().runtime_policy(), &expected);
    assert_eq!(
        expected.digest().to_string(),
        "77998494a655c8905d4378272c2376c35e6e5361d73a798d7841aa5af9854e00"
    );
    assert_eq!(
        expected.canonical_digest().to_string(),
        "c8e2a58f8b6281d8201ca232634acf7d18b6a5d7e37a34949135d361c4e0451d"
    );
    assert_ne!(expected.digest(), expected.canonical_digest());

    let encoded =
        serde_json::to_string(&manifest(vec![private_repository()])).expect("raw provider fixture");
    let selector = r#""selector":"Ubuntu-24.04""#;
    assert_eq!(encoded.matches(selector).count(), 1);
    let duplicate = encoded.replacen(
        selector,
        r#""selector":"Ubuntu-24.04","selector":"Ubuntu-24.04""#,
        1,
    );
    assert_eq!(
        load_bytes("runner-policy-duplicate.json", duplicate),
        Err(GithubProviderConfigError)
    );
    let kelvin = encoded.replacen(selector, r#""selector":"\u212aernel""#, 1);
    assert_eq!(
        load_bytes("runner-policy-kelvin.json", kelvin),
        Err(GithubProviderConfigError)
    );
    let oversized = encoded.replacen(
        selector,
        &format!(
            "\"selector\":\"{}\"",
            "a".repeat(MAX_WORKFLOW_RUNTIME_POLICY_BYTES)
        ),
        1,
    );
    assert_eq!(
        load_bytes("runner-policy-oversized.json", oversized),
        Err(GithubProviderConfigError)
    );
}

#[test]
fn provider_transport_is_closed_between_github_dot_com_and_loopback_emulation() {
    let production = load_value(
        "transport-production.json",
        &manifest(vec![public_repository()]),
    )
    .expect("production transport");
    assert!(matches!(
        production.transport(),
        GithubProviderTransport::GithubDotCom
    ));

    let mut isolated = manifest(vec![public_repository()]);
    isolated["transport"] = json!({
        "mode": "loopback_emulator",
        "api_base": "http://automata-git.localhost:18088/api/v3/",
        "job_runtime_origin": "http://automata-git.invalid:18088/"
    });
    let isolated = load_value("transport-isolated.json", &isolated).expect("isolated transport");
    assert_eq!(
        isolated
            .transport()
            .loopback_api_base()
            .expect("loopback base")
            .as_str(),
        "http://automata-git.localhost:18088/api/v3/"
    );
    assert_eq!(
        isolated
            .transport()
            .job_runtime_origin()
            .expect("job runtime origin")
            .as_str(),
        "http://automata-git.invalid:18088/"
    );

    for (name, api_base) in [
        ("external-http", "http://github.example.test/api/v3/"),
        ("loopback-https", "https://127.0.0.1:18088/api/v3/"),
        ("credentials", "http://user@127.0.0.1:18088/api/v3/"),
        ("query", "http://127.0.0.1:18088/api/v3/?secret=x"),
    ] {
        let mut invalid = manifest(vec![public_repository()]);
        invalid["transport"] = json!({
            "mode": "loopback_emulator",
            "api_base": api_base,
            "job_runtime_origin": "http://automata-git.invalid:18088/"
        });
        assert_eq!(
            load_value(&format!("transport-{name}.json"), &invalid),
            Err(GithubProviderConfigError)
        );
    }

    for (name, job_runtime_origin) in [
        ("runtime-loopback", "http://127.0.0.1:18088/"),
        ("runtime-localhost", "http://automata-git.localhost:18088/"),
        ("runtime-https", "https://automata-git.invalid:18088/"),
        ("runtime-port", "http://automata-git.invalid:18089/"),
        ("runtime-path", "http://automata-git.invalid:18088/api/v3/"),
    ] {
        let mut invalid = manifest(vec![public_repository()]);
        invalid["transport"] = json!({
            "mode": "loopback_emulator",
            "api_base": "http://automata-git.localhost:18088/api/v3/",
            "job_runtime_origin": job_runtime_origin
        });
        assert_eq!(
            load_value(&format!("transport-{name}.json"), &invalid),
            Err(GithubProviderConfigError)
        );
    }
}

#[test]
fn dashboard_url_is_a_canonical_public_automata_origin() {
    let production = load_value(
        "dashboard-production.json",
        &manifest(vec![public_repository()]),
    )
    .expect("production dashboard");
    assert_eq!(
        production.dashboard_url().as_str(),
        "https://ci.automata.example/"
    );

    for (name, dashboard_url) in [
        ("missing-host", "https:/dashboard"),
        ("http-production", "http://ci.automata.example/"),
        ("path", "https://ci.automata.example/actions"),
        ("credentials", "https://user@ci.automata.example/"),
        ("query", "https://ci.automata.example/?token=value"),
        ("fragment", "https://ci.automata.example/#fragment"),
    ] {
        let mut invalid = manifest(vec![public_repository()]);
        invalid["dashboard_url"] = json!(dashboard_url);
        assert_eq!(
            load_value(&format!("dashboard-{name}.json"), &invalid),
            Err(GithubProviderConfigError)
        );
    }

    let mut loopback = manifest(vec![public_repository()]);
    loopback["transport"] = json!({
        "mode": "loopback_emulator",
        "api_base": "http://127.0.0.1:18088/api/v3/",
        "job_runtime_origin": "http://automata-git.invalid:18088/"
    });
    loopback["dashboard_url"] = json!("http://127.0.0.1:18089/");
    let loopback = load_value("dashboard-loopback.json", &loopback).expect("loopback dashboard");
    assert_eq!(loopback.dashboard_url().as_str(), "http://127.0.0.1:18089/");

    let mut non_loopback_http = manifest(vec![public_repository()]);
    non_loopback_http["transport"] = json!({
        "mode": "loopback_emulator",
        "api_base": "http://127.0.0.1:18088/api/v3/",
        "job_runtime_origin": "http://automata-git.invalid:18088/"
    });
    non_loopback_http["dashboard_url"] = json!("http://ci.automata.example/");
    assert_eq!(
        load_value("dashboard-non-loopback-http.json", &non_loopback_http),
        Err(GithubProviderConfigError)
    );
}

#[test]
fn dashboard_url_uses_an_explicit_schema_two_migration() {
    let explicit = manifest(vec![public_repository()]);
    let configured = load_value("dashboard-schema-two.json", &explicit)
        .expect("schema 2 requires and accepts an explicit trusted dashboard origin");
    assert_eq!(
        configured.dashboard_url().as_str(),
        "https://ci.automata.example/"
    );

    let mut legacy = explicit.clone();
    legacy["schema"] = json!(1);
    assert_eq!(
        load_value("dashboard-schema-one.json", &legacy),
        Err(GithubProviderConfigError)
    );

    let mut missing = explicit;
    missing
        .as_object_mut()
        .expect("provider manifest object")
        .remove("dashboard_url");
    assert_eq!(
        load_value("dashboard-schema-two-missing.json", &missing),
        Err(GithubProviderConfigError)
    );
}

#[test]
fn schedule_policy_is_optional_but_bounded_when_configured() {
    let defaults = load_value(
        "schedule-defaults.json",
        &manifest(vec![public_repository()]),
    )
    .expect("schedule defaults");
    assert_eq!(defaults.schedule().service_config().poll_millis(), 1_000);
    assert_eq!(
        defaults
            .schedule()
            .service_config()
            .maximum_fires_per_pass(),
        32
    );

    let mut configured = manifest(vec![public_repository()]);
    configured["schedule"] = json!({
        "poll_millis": 2000,
        "discovery_claim_millis": 120_000,
        "fire_claim_millis": 120_000,
        "retry_millis": 15_000,
        "staleness_millis": 60_000,
        "maximum_manifests": 64,
        "maximum_fires_per_pass": 8
    });
    let configured =
        load_value("schedule-configured.json", &configured).expect("explicit schedule policy");
    let policy = configured.schedule().service_config();
    assert_eq!(policy.poll_millis(), 2_000);
    assert_eq!(policy.maximum_manifests(), 64);
    assert_eq!(policy.maximum_fires_per_pass(), 8);

    let mut invalid = manifest(vec![public_repository()]);
    invalid["schedule"] = json!({"maximum_fires_per_pass": 0});
    assert_eq!(
        load_value("schedule-invalid.json", &invalid),
        Err(GithubProviderConfigError)
    );
}

#[test]
fn all_direct_selection_uses_the_configured_default_branch() {
    let mut all_direct_repository = public_repository();
    let repository = all_direct_repository
        .as_object_mut()
        .expect("repository object");
    repository.insert("default_branch".to_owned(), json!("refs/release"));
    let all_direct = load_value("all-direct.json", &manifest(vec![all_direct_repository]))
        .expect("all-direct configuration");
    assert_eq!(
        all_direct.repositories()[0].workflow_selection(),
        &GithubProviderWorkflowSelection::all_direct()
    );
    assert_eq!(
        all_direct.repositories()[0].workflow_git_ref().as_str(),
        "refs/heads/refs/release"
    );
}

#[test]
fn visibility_and_job_authority_profile_are_orthogonal() {
    let repositories = vec![
        repository(
            "tenant-public-credential-free",
            0x211,
            211,
            311,
            411,
            "octo/public-credential-free",
            "public",
            "credential_free",
            0x511,
            None,
        ),
        repository(
            "tenant-public-standard",
            0x212,
            212,
            312,
            412,
            "octo/public-standard",
            "public",
            "standard",
            0x512,
            None,
        ),
        repository(
            "tenant-private-credential-free",
            0x213,
            213,
            313,
            413,
            "octo/private-credential-free",
            "private",
            "credential_free",
            0x513,
            Some(0x613),
        ),
        repository(
            "tenant-private-standard",
            0x214,
            214,
            314,
            414,
            "octo/private-standard",
            "private",
            "standard",
            0x514,
            Some(0x614),
        ),
    ];
    let config = load_value("visibility-profile-matrix.json", &manifest(repositories))
        .expect("all visibility/profile combinations are valid");

    let expected = [
        (
            "octo/public-credential-free",
            ProviderRepositoryVisibility::Public,
            JobAuthorityProfile::CredentialFree,
            false,
        ),
        (
            "octo/public-standard",
            ProviderRepositoryVisibility::Public,
            JobAuthorityProfile::Standard,
            false,
        ),
        (
            "octo/private-credential-free",
            ProviderRepositoryVisibility::Private,
            JobAuthorityProfile::CredentialFree,
            true,
        ),
        (
            "octo/private-standard",
            ProviderRepositoryVisibility::Private,
            JobAuthorityProfile::Standard,
            true,
        ),
    ];
    for (name, visibility, profile, private_source) in expected {
        let repository = config
            .repositories()
            .iter()
            .find(|repository| repository.repository_name().as_str() == name)
            .expect("configured repository");
        assert_eq!(repository.visibility(), visibility);
        assert_eq!(repository.authority_profile(), profile);
        assert_eq!(
            repository.private_source_authority().is_some(),
            private_source
        );
    }
}

#[test]
fn server_loads_one_sorted_mixed_visibility_registry_without_loading_nested_secrets() {
    let path = test_file("mixed.json");
    write_private_file(
        &path,
        serde_json::to_vec(&manifest(vec![public_repository(), private_repository()]))
            .expect("mixed configuration"),
    );
    let source = format!("file:{}", path.display());
    let cli = Cli::try_parse_from([
        "automata",
        "server",
        "--results-public-url",
        "https://results.example.test/",
        "--github-provider-config-source",
        &source,
    ])
    .expect("provider configuration CLI");
    let Command::Server(args) = cli.command else {
        panic!("server command expected");
    };
    let server = ServerConfig::from_args(&args).expect("mixed provider configuration");
    let provider = server.github_provider().expect("provider enabled");

    assert_eq!(provider.app().app_id().get(), 42);
    assert_eq!(provider.app().client_id().as_str(), "Iv1.automata-provider");
    assert_eq!(
        provider.app().jwt_issuer(),
        GithubServerServiceJwtIssuer::AppClientId
    );
    assert_eq!(provider.app().configuration_revision().get(), 5);
    assert_eq!(provider.webhook().verifier_revision().get(), 11);
    assert_eq!(provider.repositories().len(), 2);
    let private = &provider.repositories()[0];
    let public = &provider.repositories()[1];
    assert_eq!(private.installation_id().get(), 101);
    assert_eq!(private.installation_binding_generation().get(), 1);
    assert_eq!(
        private.internal_repository_id().as_bytes(),
        *github_provider_repository_id(private.tenant(), private.repository_id())
            .as_uuid()
            .as_bytes()
    );
    assert_eq!(private.visibility(), ProviderRepositoryVisibility::Private);
    assert!(private.private_source_authority().is_some());
    assert_eq!(public.installation_id().get(), 202);
    assert_eq!(public.visibility(), ProviderRepositoryVisibility::Public);
    assert!(public.private_source_authority().is_none());
    assert_eq!(public.repository_owner_id().get(), 402);
    assert_eq!(public.repository_name().as_str(), "octo/public-repository");

    let debug = format!("{provider:?}");
    assert!(debug.contains("repository_count: 2"));
    assert!(debug.contains("[redacted]"));
    for sensitive in [
        PRIVATE_KEY_MARKER,
        HMAC_MARKER,
        "tenant-private",
        "private-repository",
    ] {
        assert!(!debug.contains(sensitive));
    }
}

#[test]
fn visibility_requires_an_explicit_exact_private_authority_shape() {
    let mut public_with_private = public_repository();
    public_with_private["authorities"]["private_repository_source_read"] = authority(0x701, 7);
    assert_eq!(
        load_value(
            "public-with-private.json",
            &manifest(vec![public_with_private])
        ),
        Err(GithubProviderConfigError)
    );

    let mut private_without_private = private_repository();
    private_without_private["authorities"]["private_repository_source_read"] = Value::Null;
    assert_eq!(
        load_value(
            "private-without-private.json",
            &manifest(vec![private_without_private])
        ),
        Err(GithubProviderConfigError)
    );

    let mut public_missing_null = public_repository();
    public_missing_null["authorities"]
        .as_object_mut()
        .expect("authorities object")
        .remove("private_repository_source_read");
    assert_eq!(
        load_value(
            "public-missing-private-field.json",
            &manifest(vec![public_missing_null])
        ),
        Err(GithubProviderConfigError)
    );
}

#[test]
fn every_repository_and_authority_identity_is_unique() {
    let base = private_repository();
    let duplicates = [
        ("connection", "connection_id"),
        ("repository", "repository_id"),
        ("canonical-name", "repository"),
    ];
    for (case, field) in duplicates {
        let mut second = public_repository();
        second[field] = base[field].clone();
        assert_eq!(
            load_value(
                &format!("duplicate-{case}.json"),
                &manifest(vec![base.clone(), second])
            ),
            Err(GithubProviderConfigError)
        );
    }

    let mut selector = public_repository();
    selector["installation_id"] = base["installation_id"].clone();
    selector["repository_id"] = base["repository_id"].clone();
    let mut authority_id = public_repository();
    authority_id["authorities"]["checks_write"]["authority_id"] =
        base["authorities"]["checks_write"]["authority_id"].clone();
    let mut canonical_case = public_repository();
    canonical_case["repository"] = json!("OCTO/PRIVATE-REPOSITORY");
    let mut same_repository_authorities = private_repository();
    same_repository_authorities["authorities"]["private_repository_source_read"]["authority_id"] =
        same_repository_authorities["authorities"]["checks_write"]["authority_id"].clone();
    for (case, repositories) in [
        ("selector", vec![base.clone(), selector]),
        ("authority", vec![base.clone(), authority_id]),
        ("canonical-case", vec![base.clone(), canonical_case]),
        (
            "same-repository-authorities",
            vec![same_repository_authorities],
        ),
    ] {
        assert_eq!(
            load_value(&format!("duplicate-{case}.json"), &manifest(repositories)),
            Err(GithubProviderConfigError)
        );
    }
}

fn generated_repositories(count: usize) -> Vec<Value> {
    (0..count)
        .map(|index| {
            let ordinal = u64::try_from(index).expect("fixture count fits u64") + 1;
            repository(
                "tenant-bounded",
                0x20_000 + u128::from(ordinal),
                30_000,
                40_000 + ordinal,
                50_000,
                &format!("octo/repository-{ordinal}"),
                if ordinal & 1 == 0 {
                    "public"
                } else {
                    "private"
                },
                "standard",
                0x60_000 + u128::from(ordinal) * 2,
                (ordinal & 1 == 1).then_some(0x60_001 + u128::from(ordinal) * 2),
            )
        })
        .collect()
}

#[test]
fn document_and_repository_bounds_are_exact() {
    assert_eq!(
        load_value("empty.json", &manifest(Vec::new())),
        Err(GithubProviderConfigError)
    );
    let exact = load_value(
        "exact-repository-limit.json",
        &manifest(generated_repositories(MAX_GITHUB_PROVIDER_REPOSITORIES)),
    )
    .expect("exact repository limit");
    assert_eq!(exact.repositories().len(), MAX_GITHUB_PROVIDER_REPOSITORIES);

    let exact_document_path = test_file("exact-document-limit.json");
    let mut exact_document =
        serde_json::to_vec(&manifest(vec![private_repository()])).expect("bounded fixture JSON");
    exact_document.resize(MAX_GITHUB_PROVIDER_CONFIG_BYTES, b' ');
    write_private_file(&exact_document_path, exact_document);
    GithubProviderConfig::load(&SecretSource::File(exact_document_path))
        .expect("exact document byte limit");

    assert_eq!(
        load_value(
            "excessive-repositories.json",
            &manifest(generated_repositories(MAX_GITHUB_PROVIDER_REPOSITORIES + 1))
        ),
        Err(GithubProviderConfigError)
    );

    let path = test_file("excessive-document.json");
    write_private_file(&path, vec![b'x'; MAX_GITHUB_PROVIDER_CONFIG_BYTES + 1]);
    assert_eq!(
        GithubProviderConfig::load(&SecretSource::File(path)),
        Err(GithubProviderConfigError)
    );
}

fn invalid_scalar_configuration_cases() -> Vec<(&'static str, Value)> {
    let mut cases = Vec::new();
    let mut value = manifest(vec![private_repository()]);
    value["schema"] = json!(3);
    cases.push(("schema", value));
    for (case, path) in [
        ("app-id", vec!["app", "id"]),
        ("app-revision", vec!["app", "configuration_revision"]),
        ("verifier-revision", vec!["webhook", "verifier_revision"]),
        ("installation", vec!["repositories", "0", "installation_id"]),
        (
            "installation-binding-generation",
            vec!["repositories", "0", "installation_binding_generation"],
        ),
        ("repository", vec!["repositories", "0", "repository_id"]),
        ("owner", vec!["repositories", "0", "repository_owner_id"]),
        (
            "manifest-revision",
            vec!["repositories", "0", "manifest_revision"],
        ),
        (
            "policy-revision",
            vec!["repositories", "0", "policy_revision"],
        ),
        (
            "runtime-policy-revision",
            vec!["repositories", "0", "runtime_policy_revision"],
        ),
    ] {
        let mut value = manifest(vec![private_repository()]);
        set_path(&mut value, &path, json!(0));
        cases.push((case, value));
    }
    let mut invalid_uuid = manifest(vec![private_repository()]);
    invalid_uuid["repositories"][0]["connection_id"] =
        json!("00000000-0000-0000-0000-000000000000");
    cases.push(("nil-uuid", invalid_uuid));
    let mut noncanonical_uuid = manifest(vec![private_repository()]);
    noncanonical_uuid["repositories"][0]["connection_id"] =
        json!("00000000-0000-0000-0000-0000000000AB");
    cases.push(("noncanonical-uuid", noncanonical_uuid));
    let mut nil_authority = manifest(vec![private_repository()]);
    nil_authority["repositories"][0]["authorities"]["checks_write"]["authority_id"] =
        json!("00000000-0000-0000-0000-000000000000");
    cases.push(("nil-authority", nil_authority));
    let mut invalid_tenant = manifest(vec![private_repository()]);
    invalid_tenant["repositories"][0]["tenant_id"] = json!("");
    cases.push(("tenant", invalid_tenant));
    let mut invalid_visibility = manifest(vec![private_repository()]);
    invalid_visibility["repositories"][0]["visibility"] = json!("internal");
    cases.push(("visibility", invalid_visibility));
    let mut invalid_authority_profile = manifest(vec![private_repository()]);
    invalid_authority_profile["repositories"][0]["authority_profile"] = json!("default");
    cases.push(("authority-profile", invalid_authority_profile));
    let mut missing_authority_profile = manifest(vec![private_repository()]);
    missing_authority_profile["repositories"][0]
        .as_object_mut()
        .expect("repository object")
        .remove("authority_profile");
    cases.push(("missing-authority-profile", missing_authority_profile));
    let mut missing_installation_generation = manifest(vec![private_repository()]);
    missing_installation_generation["repositories"][0]
        .as_object_mut()
        .expect("repository object")
        .remove("installation_binding_generation");
    cases.push((
        "missing-installation-binding-generation",
        missing_installation_generation,
    ));
    let mut invalid_issuer = manifest(vec![private_repository()]);
    invalid_issuer["app"]["jwt_issuer"] = json!("repository_id");
    cases.push(("jwt-issuer", invalid_issuer));
    let mut invalid_client = manifest(vec![private_repository()]);
    invalid_client["app"]["client_id"] = json!(" invalid client ");
    cases.push(("client", invalid_client));
    let mut invalid_name = manifest(vec![private_repository()]);
    invalid_name["repositories"][0]["repository"] = json!("owner/repository.git");
    cases.push(("name", invalid_name));
    let mut invalid_default_branch = manifest(vec![private_repository()]);
    invalid_default_branch["repositories"][0]["default_branch"] = json!("refs//heads/main");
    cases.push(("default-branch", invalid_default_branch));
    let mut invalid_check = manifest(vec![private_repository()]);
    invalid_check["repositories"][0]["check_name"] = json!("\n");
    cases.push(("check", invalid_check));
    cases
}

#[test]
fn typed_values_and_nested_sources_fail_closed() {
    let mut cases = invalid_scalar_configuration_cases();
    let mut nested_workflow = manifest(vec![private_repository()]);
    nested_workflow["repositories"][0]["workflow_path"] = json!(".ci/workflows/nested/main.yml");
    cases.push(("nested-workflow", nested_workflow));
    let mut non_workflow = manifest(vec![private_repository()]);
    non_workflow["repositories"][0]["workflow_path"] = json!("ci/main.yml");
    cases.push(("non-workflow", non_workflow));
    let mut ambiguous_workflow_selection = manifest(vec![private_repository()]);
    ambiguous_workflow_selection["repositories"][0]["workflow_selection"] =
        json!({"mode": "all_direct"});
    cases.push(("ambiguous-workflow-selection", ambiguous_workflow_selection));
    let mut unknown_workflow_selection = manifest(vec![private_repository()]);
    unknown_workflow_selection["repositories"][0]
        .as_object_mut()
        .expect("repository object")
        .remove("workflow_path");
    unknown_workflow_selection["repositories"][0]["workflow_selection"] =
        json!({"mode": "recursive"});
    cases.push(("unknown-workflow-selection", unknown_workflow_selection));
    let mut verbose_workflow_selection = manifest(vec![private_repository()]);
    verbose_workflow_selection["repositories"][0]
        .as_object_mut()
        .expect("repository object")
        .remove("workflow_path");
    verbose_workflow_selection["repositories"][0]["workflow_selection"] =
        json!({"mode": "all_direct", "path": ".ci/workflows/main.yml"});
    cases.push(("verbose-workflow-selection", verbose_workflow_selection));
    let mut plaintext_key = manifest(vec![private_repository()]);
    plaintext_key["app"]["private_key_source"] = json!("plaintext-private-key");
    cases.push(("plaintext-key", plaintext_key));
    let mut plaintext_hmac = manifest(vec![private_repository()]);
    plaintext_hmac["webhook"]["hmac_secret_source"] = json!("plaintext-hmac");
    cases.push(("plaintext-hmac", plaintext_hmac));
    let mut authority_revision = manifest(vec![private_repository()]);
    authority_revision["repositories"][0]["authorities"]["checks_write"]["policy_revision"] =
        json!(8);
    cases.push(("authority-policy", authority_revision));

    for (case, value) in cases {
        assert_eq!(
            load_value(&format!("invalid-{case}.json"), &value),
            Err(GithubProviderConfigError),
            "case {case}"
        );
    }
}

#[test]
fn noncurrent_provider_config_schema_fails_closed() {
    let expected = Err(GithubProviderConfigError);
    for unsupported in [0, 1, 3, u16::MAX] {
        let mut value = manifest(vec![private_repository()]);
        value["schema"] = json!(unsupported);
        assert_eq!(load_value("schema.json", &value), expected);
    }
}

fn set_path(value: &mut Value, path: &[&str], replacement: Value) {
    let mut current = value;
    for component in &path[..path.len() - 1] {
        current = if let Ok(index) = component.parse::<usize>() {
            &mut current[index]
        } else {
            &mut current[*component]
        };
    }
    current[*path.last().expect("nonempty fixture path")] = replacement;
}

#[test]
fn unknown_or_independently_supplied_policy_fields_are_rejected() {
    let paths = [
        ("top", vec!["fixed_workflow_path"]),
        ("app", vec!["app", "api_origin"]),
        ("webhook", vec!["webhook", "verifier_fingerprint"]),
        (
            "caller-supplied-internal-repository",
            vec!["repositories", "0", "internal_repository_id"],
        ),
        ("repository-event", vec!["repositories", "0", "event"]),
        (
            "repository-verifier-revision",
            vec!["repositories", "0", "verifier_revision"],
        ),
        (
            "repository-verifier-fingerprint",
            vec!["repositories", "0", "webhook_verifier_fingerprint"],
        ),
        (
            "authority-scope",
            vec!["repositories", "0", "authorities", "scope"],
        ),
        (
            "authority-digest",
            vec![
                "repositories",
                "0",
                "authorities",
                "checks_write",
                "identity_digest",
            ],
        ),
    ];
    for (case, path) in paths {
        let mut value = manifest(vec![private_repository()]);
        set_path(&mut value, &path, json!("caller-controlled"));
        assert_eq!(
            load_value(&format!("unknown-{case}.json"), &value),
            Err(GithubProviderConfigError)
        );
    }
}
