#![cfg(target_os = "linux")]

mod support;

use std::{collections::BTreeMap, fs, path::PathBuf, sync::Arc, time::Duration};

use automata_ci_execution::{
    DestroySandbox, EnvironmentName, EnvironmentValue, EnvironmentVariable, ExecutionEnvironment,
    ImmutableImage, NeverCancelled, OperationId, OperationOutcome, ProviderErrorKind,
    SandboxCapability, SandboxProvider, ServiceContainerSpec, ServiceContainerSpecs,
    ServiceHealthOverrides, ServiceHealthPolicy, ServicePort, ServiceTransportProtocol,
};
use automata_ci_sandbox_podman::{
    CommandOutput, PodmanCommandExecutor, PodmanConfigurationError, PodmanLimits, PodmanOpenError,
    RootlessPodmanProvider,
};

use support::{FakePodman, Fixture, ScratchRoot, options, options_with_service_proxy, sample_spec};

const ENVIRONMENT_VALUE: &str = "synthetic-service-environment-value";
const HEALTH_FORMAT: &str = "{{.State.Status}}\n{{if .Config.Healthcheck}}configured{{else}}none{{end}}\n{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}";

#[test]
fn service_capability_is_not_advertised_until_the_local_helper_is_verified() {
    let scratch = ScratchRoot::new("service-proxy-open-verification");
    let fake = Arc::new(FakePodman::default());
    fake.fail_once(&["image", "inspect"]);
    let error = RootlessPodmanProvider::open_with_executor(
        options_with_service_proxy(scratch.path()),
        Arc::clone(&fake) as Arc<dyn PodmanCommandExecutor>,
    )
    .expect_err("provider must not open with an unverified helper");
    assert_eq!(
        error,
        PodmanOpenError::Configuration(PodmanConfigurationError::ServiceProxyUnavailable)
    );
    assert_only_helper_image_verification(&fake);
    assert!(fake.is_empty());
}

#[test]
fn services_use_one_job_network_hardened_argv_and_restart_durable_bindings() {
    let Fixture {
        provider,
        fake,
        scratch,
    } = Fixture::new_with_service_proxy("service-contract");
    assert!(
        provider
            .capabilities()
            .supports(SandboxCapability::ServiceContainers)
    );
    let operation_id = OperationId::new();
    let spec = service_spec(operation_id);
    let record = provider
        .create(&spec, &NeverCancelled)
        .expect("create sandbox with services");
    let bindings = provider
        .service_bindings(record.handle(), &NeverCancelled)
        .expect("discover healthy services");
    assert_eq!(bindings.len(), 2);
    let database = bindings.get("database").expect("database binding");
    let resolver = bindings.get("resolver").expect("resolver binding");
    assert_eq!(database.network(), resolver.network());
    assert_eq!(database.ports().len(), 1);
    assert_eq!(resolver.ports().len(), 1);
    assert_eq!(database.ports()[0].host_port(), 5_432);
    assert_ne!(
        database.ports()[0].host_port(),
        resolver.ports()[0].host_port()
    );
    assert_eq!(fake.aggregate_pids(), Some(512));
    assert!(fake.no_swap_verifications() >= 3);

    assert_service_commands(&fake);
    let manifest = service_manifest_path(scratch.path(), operation_id);
    assert_manifest_is_private_and_secret_free(&manifest);

    let handle = record.handle().clone();
    let generation = record.generation();
    drop(provider);
    let reopened = RootlessPodmanProvider::open_with_executor(
        options_with_service_proxy(scratch.path()),
        Arc::clone(&fake) as Arc<dyn PodmanCommandExecutor>,
    )
    .expect("reopen provider");
    let recovered = reopened
        .service_bindings(&handle, &NeverCancelled)
        .expect("recover bindings from durable manifest");
    assert_eq!(recovered, bindings);

    reopened
        .destroy(
            &DestroySandbox::new(OperationId::new(), handle, generation),
            &NeverCancelled,
        )
        .expect("destroy services and sandbox");
    assert!(fake.is_empty());
    assert!(!manifest.exists());
    assert_exact_service_deletion_fences(&fake.commands());
}

#[test]
fn stopped_proxy_is_recreated_with_fresh_logs_and_the_durable_listener_ports() {
    let fixture = Fixture::new_with_service_proxy("service-proxy-restart");
    let spec = service_spec(OperationId::new());
    let first_record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("initial service create");
    let first = fixture
        .provider
        .service_bindings(first_record.handle(), &NeverCancelled)
        .expect("initial bindings");
    let old_proxy = fixture.fake.stop_service_proxy();

    let replayed = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("stopped proxy recreation");
    let second = fixture
        .provider
        .service_bindings(replayed.handle(), &NeverCancelled)
        .expect("recovered bindings");
    assert_eq!(second, first);
    let commands = fixture.fake.commands();
    assert!(commands.iter().any(|command| {
        let command = podman_command(command);
        command.starts_with(&["rm", "--force"])
            && command.last().copied() == Some(old_proxy.as_str())
    }));
    let proxy_creates = commands
        .iter()
        .filter(|command| {
            command
                .iter()
                .any(|argument| argument == "/usr/libexec/automata-ci-service-proxy")
        })
        .count();
    assert_eq!(proxy_creates, 2);

    fixture
        .provider
        .destroy(
            &DestroySandbox::new(
                OperationId::new(),
                replayed.handle().clone(),
                replayed.generation(),
            ),
            &NeverCancelled,
        )
        .expect("destroy replayed sandbox");
    assert!(fixture.fake.is_empty());
}

#[test]
fn durable_helper_identity_allows_exact_destroy_after_configuration_is_removed() {
    let Fixture {
        provider,
        fake,
        scratch,
    } = Fixture::new_with_service_proxy("service-helper-drift-destroy");
    let spec = service_spec(OperationId::new());
    let record = provider
        .create(&spec, &NeverCancelled)
        .expect("create services with configured helper");
    let handle = record.handle().clone();
    drop(provider);

    let reopened = RootlessPodmanProvider::open_with_executor(
        options(scratch.path()),
        Arc::clone(&fake) as Arc<dyn PodmanCommandExecutor>,
    )
    .expect("reopen without advertising new service jobs");
    assert!(
        !reopened
            .capabilities()
            .supports(SandboxCapability::ServiceContainers)
    );
    reopened
        .destroy(
            &DestroySandbox::new(OperationId::new(), handle, record.generation()),
            &NeverCancelled,
        )
        .expect("manifest-pinned helper identity remains destroyable");
    assert!(fake.is_empty());
}

fn assert_service_commands(fake: &support::FakePodman) {
    let commands = fake.commands();
    let network_creates = commands
        .iter()
        .map(|command| podman_command(command))
        .filter(|command| command.starts_with(&["network", "create"]))
        .count();
    assert_eq!(network_creates, 1, "services must reuse the job network");
    let pod_create = commands
        .iter()
        .find(|command| podman_command(command).starts_with(&["pod", "create"]))
        .expect("job pod create");
    assert_eq!(
        option(pod_create, "--sysctl"),
        Some("net.ipv4.ip_unprivileged_port_start=0")
    );
    let service_creates = commands
        .iter()
        .filter(|command| command.iter().any(|value| value == "--network-alias"))
        .collect::<Vec<_>>();
    assert_eq!(service_creates.len(), 2);
    for command in &service_creates {
        for required in [
            "--pull=never",
            "--cap-drop=all",
            "--security-opt=no-new-privileges",
            "--restart=no",
            "--init",
            "--image-volume=tmpfs",
            "--network",
            "--network-alias",
            "--sysctl",
            "--cgroup-parent",
            "--memory-swap",
        ] {
            assert!(command.iter().any(|value| value == required), "{required}");
        }
        assert!(!command.iter().any(|value| value == "--privileged"));
        assert!(command.iter().any(|value| value.contains("@sha256:")));
        assert_eq!(
            option(command, "--cgroup-parent"),
            Some("/automata-runner.service/automata-job-services.slice")
        );
    }
    let database = service_creates
        .iter()
        .find(|command| option(command, "--network-alias") == Some("database"))
        .expect("database create");
    assert_eq!(option(database, "--publish"), None);
    assert_eq!(option(database, "--health-cmd"), Some("true"));
    assert_eq!(option(database, "--health-interval"), Some("1000000000ns"));
    assert_eq!(option(database, "--health-retries"), Some("3"));
    let resolver = service_creates
        .iter()
        .find(|command| option(command, "--network-alias") == Some("resolver"))
        .expect("resolver create");
    assert_eq!(option(resolver, "--publish"), None);
    assert!(resolver.iter().any(|value| value == "--no-healthcheck"));
    let proxy = commands
        .iter()
        .find(|command| {
            option(command, "--entrypoint") == Some("/usr/libexec/automata-ci-service-proxy")
        })
        .expect("namespace-local service proxy create");
    assert_eq!(option(proxy, "--network"), None);
    assert!(option(proxy, "--pod").is_some_and(|value| {
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    }));
    for forbidden in ["--userns", "--cgroup-parent", "--cpus", "--memory-swap"] {
        assert_eq!(option(proxy, forbidden), None, "{forbidden}");
    }
    assert!(
        proxy
            .iter()
            .any(|value| value == "tcp|10.89.0.11|5432|5432")
    );
    assert!(proxy.iter().any(|value| value == "udp|10.89.0.12|53|0"));
    assert!(!proxy.iter().any(|value| value == "--publish"));
    assert!(
        commands
            .iter()
            .flatten()
            .all(|argument| !argument.contains(ENVIRONMENT_VALUE)),
        "environment values must not enter durable or observable argv"
    );
    assert!(fake.child_environments().iter().any(|environment| {
        environment.get("SERVICE_TOKEN").map(String::as_str) == Some(ENVIRONMENT_VALUE)
    }));
}

#[test]
fn exact_low_tcp_and_udp_ports_are_bound_only_after_the_job_netns_sysctl() {
    let fixture = Fixture::new_with_service_proxy("service-low-listeners");
    let tcp = ServiceContainerSpec::new(service_image(0x71), ExecutionEnvironment::empty())
        .with_ports([
            ServicePort::new(80, Some(80), ServiceTransportProtocol::Tcp).expect("TCP port"),
        ])
        .expect("TCP service")
        .with_health(ServiceHealthPolicy::Disabled);
    let udp = ServiceContainerSpec::new(service_image(0x72), ExecutionEnvironment::empty())
        .with_ports([
            ServicePort::new(53, Some(53), ServiceTransportProtocol::Udp).expect("UDP port"),
        ])
        .expect("UDP service")
        .with_health(ServiceHealthPolicy::Disabled);
    let spec = sample_spec(OperationId::new()).with_services(
        ServiceContainerSpecs::new(BTreeMap::from([
            ("tcp".to_owned(), tcp),
            ("udp".to_owned(), udp),
        ]))
        .expect("low-port services"),
    );
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create exact low listeners");
    let proxy_create = fixture
        .fake
        .commands()
        .into_iter()
        .find(|command| {
            command
                .iter()
                .any(|argument| argument == "/usr/libexec/automata-ci-service-proxy")
        })
        .expect("proxy create");
    assert!(
        proxy_create
            .iter()
            .any(|argument| argument.ends_with("|80|80"))
    );
    assert!(
        proxy_create
            .iter()
            .any(|argument| argument.ends_with("|53|53"))
    );
    fixture
        .provider
        .destroy(
            &DestroySandbox::new(
                OperationId::new(),
                record.handle().clone(),
                record.generation(),
            ),
            &NeverCancelled,
        )
        .expect("destroy low-port services");
    assert!(fixture.fake.is_empty());
}

fn service_manifest_path(root: &std::path::Path, operation_id: OperationId) -> PathBuf {
    root.join("service-manifests")
        .join(format!("job-{}", operation_id.as_uuid().simple()))
}

fn assert_manifest_is_private_and_secret_free(manifest: &std::path::Path) {
    let manifest_bytes = fs::read(manifest).expect("durable service manifest");
    assert!(!contains(&manifest_bytes, ENVIRONMENT_VALUE.as_bytes()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::symlink_metadata(manifest)
                .expect("manifest metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn cancellation_during_health_readiness_is_uncertain_and_exactly_recoverable() {
    let fixture = Fixture::new_with_service_proxy("service-cancellation");
    fixture
        .fake
        .cancel_once(&["container", "inspect", "--format", HEALTH_FORMAT]);
    let spec = service_spec(OperationId::new());
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("health inspection cancellation must fail create");
    assert_eq!(error.kind(), ProviderErrorKind::Cancelled);
    assert_eq!(error.outcome(), OperationOutcome::Uncertain);
    let handle = error
        .recovery_handle()
        .expect("mutated service create retains recovery fence")
        .clone();
    fixture
        .provider
        .destroy(
            &DestroySandbox::new(OperationId::new(), handle, spec.generation()),
            &NeverCancelled,
        )
        .expect("exact recovery destroy");
    assert!(fixture.fake.is_empty());
    assert!(
        fixture
            .fake
            .commands()
            .iter()
            .flatten()
            .all(|argument| { !matches!(argument.as_str(), "prune" | "system" | "--all") })
    );
}

#[test]
fn cancellation_before_first_service_create_is_exactly_recoverable() {
    let fixture = Fixture::new_with_service_proxy("service-pre-create-cancellation");
    fixture.fake.cancel_service_create_once();
    let spec = service_spec(OperationId::new());
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("service create cancellation must retain the whole-job fence");
    assert_eq!(error.kind(), ProviderErrorKind::Cancelled);
    assert_eq!(error.outcome(), OperationOutcome::Uncertain);
    let handle = error.recovery_handle().expect("recovery handle").clone();
    fixture
        .provider
        .destroy(
            &DestroySandbox::new(OperationId::new(), handle, spec.generation()),
            &NeverCancelled,
        )
        .expect("destroy manifest entries whose containers were never created");
    assert!(fixture.fake.is_empty());
}

#[test]
fn created_service_with_unparseable_identifier_is_adopted_only_for_exact_destroy() {
    let fixture = Fixture::new_with_service_proxy("service-identifier-recovery");
    fixture.fake.malformed_service_identifier_once();
    let spec = service_spec(OperationId::new());
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("malformed create output must retain an exact recovery handle");
    assert_eq!(error.kind(), ProviderErrorKind::InvalidState);
    assert_eq!(error.outcome(), OperationOutcome::Uncertain);
    let handle = error.recovery_handle().expect("recovery handle").clone();
    fixture
        .provider
        .destroy(
            &DestroySandbox::new(OperationId::new(), handle, spec.generation()),
            &NeverCancelled,
        )
        .expect("fully verified deterministic service name can be removed by captured ID");
    assert!(fixture.fake.is_empty());
}

#[test]
fn created_service_with_wrong_valid_identifier_recovers_by_the_fenced_name() {
    let fixture = Fixture::new_with_service_proxy("service-wrong-identifier-recovery");
    fixture.fake.wrong_service_identifier_once();
    let spec = service_spec(OperationId::new());
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("wrong create identifier must leave the transition fence active");
    assert_eq!(error.kind(), ProviderErrorKind::InvalidState);
    assert_eq!(error.outcome(), OperationOutcome::Uncertain);
    let handle = error.recovery_handle().expect("recovery handle").clone();
    fixture
        .provider
        .destroy(
            &DestroySandbox::new(OperationId::new(), handle, spec.generation()),
            &NeverCancelled,
        )
        .expect("the verified deterministic service name remains exactly recoverable");
    assert!(fixture.fake.is_empty());
}

#[test]
fn proxy_transition_rejects_wrong_argv_after_a_wrong_valid_identifier() {
    let fixture = Fixture::new_with_service_proxy("proxy-wrong-identifier-recovery");
    fixture.fake.wrong_proxy_identifier_once();
    let spec = service_spec(OperationId::new());
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("wrong proxy identifier must leave the transition fence active");
    assert_eq!(error.kind(), ProviderErrorKind::InvalidState);
    assert_eq!(error.outcome(), OperationOutcome::Uncertain);
    let handle = error.recovery_handle().expect("recovery handle").clone();

    let original_command = fixture.fake.drift_service_proxy_command();
    let replay_error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("transition adoption must compare the exact proxy command");
    assert_eq!(replay_error.kind(), ProviderErrorKind::OwnershipMismatch);
    fixture.fake.restore_service_proxy_command(original_command);

    fixture
        .provider
        .destroy(
            &DestroySandbox::new(OperationId::new(), handle, spec.generation()),
            &NeverCancelled,
        )
        .expect("restored exact proxy command permits fenced recovery");
    assert!(fixture.fake.is_empty());
}

#[test]
fn primary_container_must_remain_in_the_captured_job_pod() {
    let fixture = Fixture::new_with_service_proxy("primary-pod-fence");
    let spec = service_spec(OperationId::new());
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create services");
    let pod_identifier = fixture.fake.drift_primary_pod();
    let error = fixture
        .provider
        .service_bindings(record.handle(), &NeverCancelled)
        .expect_err("lookup must verify that the primary still shares the exact pod");
    assert_eq!(error.kind(), ProviderErrorKind::OwnershipMismatch);
    fixture.fake.restore_primary_pod(pod_identifier);
    fixture
        .provider
        .destroy(
            &DestroySandbox::new(
                OperationId::new(),
                record.handle().clone(),
                record.generation(),
            ),
            &NeverCancelled,
        )
        .expect("restore exact pod relation before cleanup");
    assert!(fixture.fake.is_empty());
}

#[test]
fn cancellation_after_proxy_start_is_uncertain_and_exactly_recoverable() {
    let fixture = Fixture::new_with_service_proxy("service-proxy-cancellation");
    fixture.fake.cancel_once(&["logs"]);
    let spec = service_spec(OperationId::new());
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("proxy status cancellation must fail create");
    assert_eq!(error.kind(), ProviderErrorKind::Cancelled);
    assert_eq!(error.outcome(), OperationOutcome::Uncertain);
    let handle = error.recovery_handle().expect("recovery handle").clone();
    fixture
        .provider
        .destroy(
            &DestroySandbox::new(OperationId::new(), handle, spec.generation()),
            &NeverCancelled,
        )
        .expect("exact proxy recovery destroy");
    assert!(fixture.fake.is_empty());
}

#[test]
fn cancellation_after_one_service_deletion_retains_the_exact_recovery_fence() {
    let fixture = Fixture::new_with_service_proxy("service-destroy-cancellation");
    let spec = service_spec(OperationId::new());
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create service sandbox");
    let bindings = fixture
        .provider
        .service_bindings(record.handle(), &NeverCancelled)
        .expect("service bindings");
    let database = bindings
        .get("database")
        .expect("database binding")
        .container()
        .opaque()
        .to_owned();
    fixture
        .fake
        .cancel_once(&["container", "exists", database.as_str()]);
    let error = fixture
        .provider
        .destroy(
            &DestroySandbox::new(
                OperationId::new(),
                record.handle().clone(),
                record.generation(),
            ),
            &NeverCancelled,
        )
        .expect_err("partial service cleanup cancellation is uncertain");
    assert_eq!(error.kind(), ProviderErrorKind::Cancelled);
    assert_eq!(error.outcome(), OperationOutcome::Uncertain);
    assert_eq!(error.recovery_handle(), Some(record.handle()));

    fixture
        .provider
        .destroy(
            &DestroySandbox::new(
                OperationId::new(),
                record.handle().clone(),
                record.generation(),
            ),
            &NeverCancelled,
        )
        .expect("retry exact service cleanup");
    assert!(fixture.fake.is_empty());
}

#[test]
fn secret_service_environment_is_rejected_before_podman_or_durable_state() {
    let fixture = Fixture::new_with_service_proxy("service-secret-rejection");
    let spec = secret_service_spec(OperationId::new());
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("service secrets require a non-durable transport");
    assert_eq!(error.kind(), ProviderErrorKind::InvalidConfiguration);
    assert_eq!(error.outcome(), OperationOutcome::KnownNoEffect);
    assert!(error.recovery_handle().is_none());
    assert_only_helper_image_verification(&fixture.fake);
    assert!(
        fs::read_dir(fixture.scratch.path().join("service-manifests"))
            .expect("service manifest directory")
            .next()
            .is_none()
    );
}

#[test]
fn unsupported_or_oversized_service_environment_is_rejected_before_mutation() {
    for (label, name, value) in [
        (
            "service-control-environment",
            "XDG_FUTURE_CONTROL",
            "value".to_owned(),
        ),
        (
            "service-oversized-environment",
            "SERVICE_VALUE",
            "x".repeat(49 * 1024),
        ),
    ] {
        let fixture = Fixture::new_with_service_proxy(label);
        let variable = EnvironmentVariable::new(
            EnvironmentName::new(name).expect("environment name"),
            EnvironmentValue::new(value).expect("environment value"),
        );
        let spec = service_spec_with_database_variable(OperationId::new(), variable);
        let error = fixture
            .provider
            .create(&spec, &NeverCancelled)
            .expect_err("unsupported client environment must fail validation");
        assert_eq!(error.kind(), ProviderErrorKind::InvalidConfiguration);
        assert_eq!(error.outcome(), OperationOutcome::KnownNoEffect);
        assert_only_helper_image_verification(&fixture.fake);
    }
}

#[test]
fn service_proxy_image_must_be_locally_verified_before_any_mutation() {
    let fixture = Fixture::new_with_service_proxy("service-proxy-image-verification");
    fixture.fake.fail_once(&["image", "inspect"]);
    let spec = service_spec(OperationId::new());
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("unverified helper image must fail closed");
    assert_eq!(error.outcome(), OperationOutcome::KnownNoEffect);
    assert!(error.recovery_handle().is_none());
    assert_only_helper_image_verification(&fixture.fake);
    assert!(fixture.fake.is_empty());
}

#[test]
fn missing_delegated_job_cgroup_is_rejected_before_any_podman_mutation() {
    let fixture = Fixture::new_with_service_proxy("service-cgroup-preflight");
    fixture.fake.fail_delegated_cgroup();
    let error = fixture
        .provider
        .create(&service_spec(OperationId::new()), &NeverCancelled)
        .expect_err("unprovable aggregate cgroup must fail closed");
    assert_eq!(error.kind(), ProviderErrorKind::InvalidState);
    assert_eq!(error.outcome(), OperationOutcome::KnownNoEffect);
    assert!(error.recovery_handle().is_none());
    assert_only_helper_image_verification(&fixture.fake);
    assert!(fixture.fake.is_empty());
}

fn assert_only_helper_image_verification(fake: &support::FakePodman) {
    assert!(fake.commands().iter().all(|command| {
        let command = podman_command(command);
        command.starts_with(&["image", "exists"]) || command.starts_with(&["image", "inspect"])
    }));
}

#[test]
fn health_readiness_obeys_the_aggregate_deadline_and_retains_recovery() {
    let fixture = Fixture::new_with_service_proxy_options("service-health-timeout", |options| {
        options.with_limits(
            PodmanLimits::new(
                Duration::from_millis(80),
                Duration::from_millis(20),
                64 * 1024,
            )
            .expect("test limits"),
        )
    });
    fixture.fake.keep_health_starting();
    let spec = service_spec(OperationId::new());
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("starting health state must time out");
    assert_eq!(error.kind(), ProviderErrorKind::TimedOut);
    assert_eq!(error.outcome(), OperationOutcome::Uncertain);
    let handle = error.recovery_handle().expect("recovery handle").clone();
    fixture
        .provider
        .destroy(
            &DestroySandbox::new(OperationId::new(), handle, spec.generation()),
            &NeverCancelled,
        )
        .expect("cleanup timed-out services");
    assert!(fixture.fake.is_empty());
}

#[test]
fn override_health_policy_fails_closed_when_backend_omits_the_healthcheck() {
    let fixture = Fixture::new_with_service_proxy("service-health-config-drift");
    fixture.fake.omit_health_configuration();
    let spec = service_spec(OperationId::new());
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("a required override healthcheck cannot disappear");
    assert_eq!(error.kind(), ProviderErrorKind::OwnershipMismatch);
    assert_eq!(error.outcome(), OperationOutcome::Uncertain);
    let handle = error.recovery_handle().expect("recovery handle").clone();
    fixture
        .provider
        .destroy(
            &DestroySandbox::new(OperationId::new(), handle, spec.generation()),
            &NeverCancelled,
        )
        .expect("cleanup health-config drift");
    assert!(fixture.fake.is_empty());
}

#[test]
fn override_health_policy_requires_the_exact_requested_backend_configuration() {
    let fixture = Fixture::new_with_service_proxy("service-health-config-mismatch");
    fixture.fake.drift_health_configuration_once();
    let spec = service_spec(OperationId::new());
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("normalized or replaced health overrides must fail closed");
    assert_eq!(error.kind(), ProviderErrorKind::OwnershipMismatch);
    assert_eq!(error.outcome(), OperationOutcome::Uncertain);
    let handle = error.recovery_handle().expect("recovery handle").clone();
    fixture
        .provider
        .destroy(
            &DestroySandbox::new(OperationId::new(), handle, spec.generation()),
            &NeverCancelled,
        )
        .expect("exact-ID cleanup does not require a healthy workload");
    assert!(fixture.fake.is_empty());
}

#[test]
fn noncanonical_or_ambiguous_proxy_status_fails_closed() {
    let fixture = Fixture::new_with_service_proxy("service-port-validation");
    let spec = service_spec(OperationId::new());
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create service sandbox");
    for output in [
        b"{\"ports\":[5432,41000],\"version\":1}\n".as_slice(),
        b"{\"version\":1,\"ports\":[5432,41000]}\nextra\n",
    ] {
        fixture
            .fake
            .set_port_output(Some(CommandOutput::success(output.to_vec())));
        let error = fixture
            .provider
            .service_bindings(record.handle(), &NeverCancelled)
            .expect_err("untrusted port output must fail closed");
        assert_eq!(error.kind(), ProviderErrorKind::InvalidState);
        assert_eq!(error.outcome(), OperationOutcome::KnownNoEffect);
    }
    fixture.fake.set_port_output(None);
    fixture
        .provider
        .destroy(
            &DestroySandbox::new(
                OperationId::new(),
                record.handle().clone(),
                record.generation(),
            ),
            &NeverCancelled,
        )
        .expect("cleanup port-validation sandbox");
}

#[test]
fn stale_service_manifest_fingerprint_is_rejected_before_destroy_mutation() {
    let fixture = Fixture::new_with_service_proxy("service-manifest-fingerprint");
    let operation_id = OperationId::new();
    let spec = service_spec(operation_id);
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create service sandbox");
    let path = service_manifest_path(fixture.scratch.path(), operation_id);
    let original = fs::read(&path).expect("original manifest");
    let mut document =
        serde_json::from_slice::<serde_json::Value>(&original).expect("valid service manifest");
    document["fingerprint"] = serde_json::Value::String("ab".repeat(32));
    fs::write(
        &path,
        serde_json::to_vec(&document).expect("encode changed manifest"),
    )
    .expect("replace manifest fixture");

    let error = fixture
        .provider
        .service_bindings(record.handle(), &NeverCancelled)
        .expect_err("manifest must be bound to the core realization");
    assert_eq!(error.kind(), ProviderErrorKind::InvalidState);
    let before_destroy = fixture.fake.commands().len();
    let error = fixture
        .provider
        .destroy(
            &DestroySandbox::new(
                OperationId::new(),
                record.handle().clone(),
                record.generation(),
            ),
            &NeverCancelled,
        )
        .expect_err("mismatched manifest must fence teardown");
    assert_eq!(error.kind(), ProviderErrorKind::InvalidState);
    assert_eq!(error.outcome(), OperationOutcome::KnownNoEffect);
    assert!(
        fixture.fake.commands()[before_destroy..]
            .iter()
            .all(|command| !podman_command(command).starts_with(&["rm"]))
    );

    fs::write(&path, original).expect("restore exact manifest fixture");
    fixture
        .provider
        .destroy(
            &DestroySandbox::new(
                OperationId::new(),
                record.handle().clone(),
                record.generation(),
            ),
            &NeverCancelled,
        )
        .expect("cleanup restored sandbox");
}

#[test]
fn network_name_replacement_is_never_deleted_after_the_owned_id_is_captured() {
    let fixture = Fixture::new_with_service_proxy("service-network-replacement");
    let spec = service_spec(OperationId::new());
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create sandbox");
    fixture.fake.replace_network_before_remove();
    let error = fixture
        .provider
        .destroy(
            &DestroySandbox::new(
                OperationId::new(),
                record.handle().clone(),
                record.generation(),
            ),
            &NeverCancelled,
        )
        .expect_err("same-name replacement must remain untouched");
    assert_eq!(error.kind(), ProviderErrorKind::OwnershipMismatch);
    assert_eq!(error.outcome(), OperationOutcome::Uncertain);
    assert!(fixture.fake.only_network_remains());
    let removal = fixture
        .fake
        .commands()
        .into_iter()
        .find(|command| podman_command(command).starts_with(&["network", "rm"]))
        .expect("owned network removal");
    let identifier = removal.last().expect("immutable network ID");
    assert_eq!(identifier.len(), 64);
    assert!(!identifier.starts_with("automata-job-network-"));
}

fn service_spec(operation_id: OperationId) -> automata_ci_execution::SandboxSpec {
    let variable = EnvironmentVariable::new(
        EnvironmentName::new("SERVICE_TOKEN").expect("environment name"),
        EnvironmentValue::new(ENVIRONMENT_VALUE).expect("environment value"),
    );
    service_spec_with_database_variable(operation_id, variable)
}

fn secret_service_spec(operation_id: OperationId) -> automata_ci_execution::SandboxSpec {
    let variable = EnvironmentVariable::secret(
        EnvironmentName::new("SERVICE_TOKEN").expect("environment name"),
        EnvironmentValue::new(ENVIRONMENT_VALUE).expect("environment value"),
    );
    service_spec_with_database_variable(operation_id, variable)
}

fn service_spec_with_database_variable(
    operation_id: OperationId,
    variable: EnvironmentVariable,
) -> automata_ci_execution::SandboxSpec {
    let database_environment =
        ExecutionEnvironment::new(vec![variable]).expect("service environment");
    let health = ServiceHealthOverrides::new(
        Some("true".to_owned()),
        Some(Duration::from_secs(1)),
        Some(Duration::from_secs(1)),
        Some(Duration::from_secs(1)),
        Some(3),
    )
    .expect("health overrides");
    let database = ServiceContainerSpec::new(service_image(0x33), database_environment)
        .with_ports([
            ServicePort::new(5_432, Some(5_432), ServiceTransportProtocol::Tcp).expect("TCP port"),
        ])
        .expect("database ports")
        .with_health(ServiceHealthPolicy::Override(health));
    let resolver = ServiceContainerSpec::new(service_image(0x44), ExecutionEnvironment::empty())
        .with_ports([ServicePort::new(53, None, ServiceTransportProtocol::Udp).expect("UDP port")])
        .expect("resolver ports")
        .with_health(ServiceHealthPolicy::Disabled);
    sample_spec(operation_id).with_services(
        ServiceContainerSpecs::new(BTreeMap::from([
            ("database".to_owned(), database),
            ("resolver".to_owned(), resolver),
        ]))
        .expect("service specs"),
    )
}

fn service_image(byte: u8) -> ImmutableImage {
    ImmutableImage::new(format!(
        "registry.example.invalid/synthetic/service@sha256:{}",
        format!("{byte:02x}").repeat(32)
    ))
    .expect("immutable service image")
}

fn podman_command(arguments: &[String]) -> Vec<&str> {
    arguments
        .iter()
        .skip_while(|argument| argument.starts_with("--"))
        .map(String::as_str)
        .collect()
}

fn option<'a>(arguments: &'a [String], name: &str) -> Option<&'a str> {
    arguments
        .windows(2)
        .find(|window| window[0] == name)
        .map(|window| window[1].as_str())
}

fn assert_exact_service_deletion_fences(commands: &[Vec<String>]) {
    let network_removal = commands
        .iter()
        .position(|command| podman_command(command).starts_with(&["network", "rm"]))
        .expect("job network is removed");
    let mut service_removals = 0;
    let mut removed_names = Vec::new();
    for (index, command) in commands.iter().enumerate() {
        let command = podman_command(command);
        if !command.starts_with(&["rm", "--force", "--ignore", "--time", "0", "--volumes"]) {
            continue;
        }
        service_removals += 1;
        let identifier = command.last().expect("service identifier");
        assert_eq!(identifier.len(), 64);
        assert!(identifier.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let previous = commands[..index]
            .iter()
            .rev()
            .map(|value| podman_command(value))
            .find(|candidate| {
                candidate.starts_with(&["container", "inspect", "--format"])
                    && candidate
                        .last()
                        .is_some_and(|name| name.starts_with("automata-job-service-"))
            })
            .expect("service deletion has an ownership inspection");
        assert!(previous.starts_with(&["container", "inspect", "--format"]));
        assert!(
            previous
                .last()
                .is_some_and(|name| name.starts_with("automata-job-service-"))
        );
        removed_names.push(previous.last().expect("owned removal name").to_string());
        assert!(
            index < network_removal,
            "services are removed before the network"
        );
    }
    assert_eq!(service_removals, 3);
    assert!(
        removed_names
            .first()
            .is_some_and(|name| name.starts_with("automata-job-service-proxy-")),
        "the loopback proxy is removed before target services"
    );
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
