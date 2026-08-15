use std::sync::Arc;

use automata_ci_execution::{ProviderId, ResourceLimits, SandboxHandle};
use serde_json::{Value, json};

use super::{
    BUILDX_DEFAULT_IMAGE, BufferedResponse, ContainerOperation, DockerLaunchValidator, DockerRoute,
    ExecOperation, ProxyPolicy, ResponseTransform, validate_build_query,
    validate_buildkit_config_archive, validate_buildkit_exec_create,
};

#[derive(Debug)]
struct ValidLaunch;

impl DockerLaunchValidator for ValidLaunch {
    fn validate(&self) -> bool {
        true
    }
}

#[test]
fn build_query_accepts_the_distribution_parameter_names() {
    let accepted = [
        ("empty query", ""),
        ("Dockerfile", "dockerfile=Containerfile"),
        ("quiet", "q=1"),
        ("tag", "t=automata-docker-live%3Aone"),
        ("legacy builder", "version=1"),
        ("percent-encoded name", "%74=automata-docker-live%3Aone"),
        (
            "distribution request",
            "dockerfile=Containerfile&q=1&t=automata-docker-live%3Aone&version=1",
        ),
    ];

    for (case, query) in accepted {
        assert_eq!(validate_build_query(query), Ok(()), "{case}: {query}");
    }
}

#[test]
fn build_query_rejects_every_other_parameter_name() {
    let rejected = [
        ("labels", "labels=%7B%7D"),
        ("remote context", "remote=https%3A%2F%2Fexample.invalid"),
        ("network mode", "networkmode=default"),
        ("cgroup parent", "cgroupparent=default"),
        ("memory", "memory=0"),
        ("CPU period", "cpuperiod=0"),
        ("CPU quota", "cpuquota=0"),
        ("output", "output=type%3Dlocal"),
        ("unknown", "unknown=1"),
        ("case variant", "Dockerfile=Containerfile"),
        ("encoded case variant", "%54=automata-docker-live%3Aone"),
        ("absolute Dockerfile", "dockerfile=%2Fetc%2Fpasswd"),
        ("parent Dockerfile", "dockerfile=..%2FContainerfile"),
        (
            "nested parent Dockerfile",
            "dockerfile=build%2F..%2FContainerfile",
        ),
        ("backslash Dockerfile", "dockerfile=build%5CContainerfile"),
        ("empty Dockerfile", "dockerfile="),
        ("noncanonical quiet", "q=true"),
        ("empty tag", "t="),
        ("tag option injection", "t=--output"),
        ("digest target", "t=image%40sha256%3Adeadbeef"),
        ("nonlegacy version", "version=2"),
    ];

    for (case, query) in rejected {
        assert_eq!(validate_build_query(query), Err(()), "{case}: {query}");
    }
}

#[test]
fn build_query_rejects_duplicates_and_malformed_form_encoding() {
    let rejected = [
        ("duplicate", "t=one&t=two"),
        ("encoded duplicate", "t=one&%74=two"),
        ("missing equals", "q"),
        ("empty name", "=1"),
        ("leading separator", "&q=1"),
        ("trailing separator", "q=1&"),
        ("empty parameter", "q=1&&version=1"),
        ("short escape in name", "%7=1"),
        ("invalid escape in name", "%GG=1"),
        ("short escape in value", "q=%"),
        ("invalid escape in value", "q=%GG"),
        ("encoded control in value", "q=%00"),
        ("empty value", "q="),
    ];

    for (case, query) in rejected {
        assert_eq!(validate_build_query(query), Err(()), "{case}: {query}");
    }
}

#[test]
fn container_create_forces_the_job_local_log_driver() {
    let accepted = [
        ("omitted", json!({"Image": "local/image"})),
        ("null", json!({"HostConfig": {"LogConfig": null}})),
        ("empty", json!({"HostConfig": {"LogConfig": {}}})),
        (
            "Docker default",
            json!({"HostConfig": {"LogConfig": {"Type": "", "Config": {}}}}),
        ),
        (
            "already job-local",
            json!({"HostConfig": {"LogConfig": {"Type": "json-file", "Config": {}}}}),
        ),
    ];

    for (case, request) in accepted {
        let rewritten = rewrite_container_create(&request).unwrap_or_else(|()| panic!("{case}"));
        assert_eq!(
            rewritten["HostConfig"]["LogConfig"],
            json!({"Type": "json-file", "Config": {}}),
            "{case}"
        );
    }
}

#[test]
fn container_create_rejects_external_log_drivers_and_options() {
    let rejected = [
        ("journald", json!({"Type": "journald", "Config": {}})),
        ("syslog", json!({"Type": "syslog", "Config": {}})),
        (
            "Podman native file",
            json!({"Type": "k8s-file", "Config": {}}),
        ),
        (
            "JSON file",
            json!({"Type": "json-file", "Config": {"max-size": "10m"}}),
        ),
        (
            "default with options",
            json!({"Type": "", "Config": {"tag": "{{.Name}}"}}),
        ),
        (
            "job-local with options",
            json!({"Type": "json-file", "Config": {"tag": "secret-bearing"}}),
        ),
        ("no logging", json!({"Type": "none", "Config": {}})),
        ("invalid driver type", json!({"Type": false, "Config": {}})),
        (
            "invalid options type",
            json!({"Type": "json-file", "Config": []}),
        ),
        (
            "unknown field",
            json!({"Type": "json-file", "Config": {}, "Destination": "/var/log"}),
        ),
    ];

    for (case, log_config) in rejected {
        let request = json!({"HostConfig": {"LogConfig": log_config}});
        assert!(
            proxy_policy()
                .rewrite_container_create(&encoded(&request))
                .is_err(),
            "{case}"
        );
    }
}

fn rewrite_container_create(request: &Value) -> Result<Value, ()> {
    let (rewritten, ports) = proxy_policy().rewrite_container_create(&encoded(request))?;
    assert!(ports.is_empty());
    serde_json::from_slice(&rewritten).map_err(|_| ())
}

fn proxy_policy() -> ProxyPolicy {
    let provider = ProviderId::new("podman").expect("test provider ID");
    let sandbox = SandboxHandle::new(provider, "test-sandbox").expect("test sandbox handle");
    let resources =
        ResourceLimits::new(512 * 1024 * 1024, 1_000, 256).expect("test resource limits");
    ProxyPolicy::new_with_validator(
        &sandbox,
        42,
        "test.slice".to_owned(),
        resources,
        Arc::new(ValidLaunch),
        None,
    )
}

fn buildkit_proxy_policy() -> ProxyPolicy {
    buildkit_proxy_policy_for("test-sandbox")
}

fn buildkit_proxy_policy_for(sandbox_opaque: &str) -> ProxyPolicy {
    let provider = ProviderId::new("podman").expect("test provider ID");
    let sandbox = SandboxHandle::new(provider, sandbox_opaque).expect("test sandbox handle");
    let resources =
        ResourceLimits::new(512 * 1024 * 1024, 1_000, 256).expect("test resource limits");
    ProxyPolicy::new_with_validator(
        &sandbox,
        42,
        "test.slice".to_owned(),
        resources,
        Arc::new(ValidLaunch),
        Some(format!(
            "registry.example.invalid/buildkit/runtime@sha256:{}",
            "66".repeat(32)
        )),
    )
}

fn buildkit_create(name: &str) -> Value {
    json!({
        "Image": BUILDX_DEFAULT_IMAGE,
        "Cmd": [
            "--allow-insecure-entitlement",
            "security.insecure",
            "--allow-insecure-entitlement",
            "network.host"
        ],
        "HostConfig": {
            "Privileged": true,
            "Init": true,
            "NetworkMode": "",
            "CgroupParent": "/docker/buildx",
            "ConsoleSize": [0, 0],
            "RestartPolicy": {"Name": "unless-stopped", "MaximumRetryCount": 0},
            "Mounts": [{
                "Type": "volume",
                "Source": format!("{name}_state"),
                "Target": "/var/lib/buildkit",
                "ReadOnly": false
            }]
        }
    })
}

#[test]
fn buildkit_pull_is_a_closed_local_alias_not_a_registry_surface() {
    let policy = buildkit_proxy_policy();
    let accepted = policy
        .authorize(
            "POST",
            "/v1.44/images/create?fromImage=docker.io%2Fmoby%2Fbuildkit&tag=buildx-stable-1",
            &[],
        )
        .expect("default Buildx image alias");
    assert!(matches!(
        accepted.response,
        ResponseTransform::SyntheticImagePull
    ));

    for target in [
        "/v1.44/images/create?fromImage=docker.io%2Fmoby%2Fbuildkit&tag=latest",
        "/v1.44/images/create?fromImage=registry.example.invalid%2Fcustom&tag=latest",
        "/v1.44/images/create?fromImage=docker.io%2Fmoby%2Fbuildkit&tag=buildx-stable-1&platform=linux%2Famd64",
    ] {
        assert!(policy.authorize("POST", target, &[]).is_err(), "{target}");
    }
    assert!(
        policy
            .authorize(
                "POST",
                "/v1.44/images/create?fromImage=docker.io%2Fmoby%2Fbuildkit&tag=buildx-stable-1",
                b"unexpected body",
            )
            .is_err()
    );
    assert!(
        proxy_policy()
            .authorize(
                "POST",
                "/v1.44/images/create?fromImage=docker.io%2Fmoby%2Fbuildkit&tag=buildx-stable-1",
                &[],
            )
            .is_err()
    );
}

#[test]
fn buildkit_info_is_opt_in_and_scrubs_only_rootless_engine_markers() {
    assert!(proxy_policy().authorize("GET", "/info", &[]).is_err());

    let policy = buildkit_proxy_policy();
    let authorized = policy
        .authorize("GET", "/v1.44/info", &[])
        .expect("BuildKit-scoped info request");
    assert!(matches!(
        authorized.response,
        ResponseTransform::RewriteInfo
    ));
    assert!(policy.authorize("GET", "/info?verbose=1", &[]).is_err());
    assert!(policy.authorize("GET", "/info", b"unexpected").is_err());

    let rewritten = ProxyPolicy::rewrite_info(&encoded(&json!({
        "CgroupDriver": "systemd",
        "SecurityOptions": [
            "name=seccomp,profile=builtin",
            "name=userns",
            "name=rootless"
        ],
        "ServerVersion": "test-version"
    })))
    .expect("valid info response");
    let rewritten: Value = serde_json::from_slice(&rewritten).expect("rewritten info JSON");
    assert_eq!(rewritten["CgroupDriver"], "cgroupfs");
    assert_eq!(
        rewritten["SecurityOptions"],
        json!(["name=seccomp,profile=builtin"])
    );
    assert_eq!(rewritten["ServerVersion"], "test-version");
}

#[test]
fn buildkit_image_alias_rewrites_the_target_and_hides_the_private_reference() {
    let policy = buildkit_proxy_policy();
    let private_reference = format!(
        "registry.example.invalid/buildkit/runtime@sha256:{}",
        "66".repeat(32)
    );
    let authorized = policy
        .authorize(
            "GET",
            "/v1.44/images/moby%2Fbuildkit%3Abuildx-stable-1/json",
            &[],
        )
        .expect("default Buildx image alias");
    assert_eq!(
        authorized.target,
        format!(
            "/v1.44/images/registry.example.invalid%2Fbuildkit%2Fruntime%40sha256%3A{}/json",
            "66".repeat(32)
        )
    );
    assert!(matches!(
        authorized.response,
        ResponseTransform::RewriteBuildKitImageInspect
    ));

    let mut response = BufferedResponse {
        status_line: format!("HTTP/1.1 200 private {private_reference}"),
        fields: vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            (
                "Docker-Content-Digest".to_owned(),
                private_reference.clone(),
            ),
        ],
        body: encoded(&json!({
            "Id": format!("sha256:{}", "66".repeat(32)),
            "RepoTags": ["registry.example.invalid/private:tag"],
            "RepoDigests": [format!(
                "registry.example.invalid/private@sha256:{}",
                "66".repeat(32)
            )],
            "Descriptor": {
                "digest": format!("sha256:{}", "66".repeat(32)),
                "annotations": {"private.reference": private_reference}
            },
            "NamesHistory": [private_reference],
            "ImageName": private_reference,
            "Config": {"Labels": {"private.reference": private_reference}}
        })),
    };
    policy
        .rewrite_buildkit_image_inspect_response(&mut response)
        .expect("valid image response");
    assert_eq!(response.status_line, "HTTP/1.1 200 BuildKit image response");
    assert_eq!(
        response.fields,
        [("Content-Type".to_owned(), "application/json".to_owned())]
    );
    let document: Value = serde_json::from_slice(&response.body).expect("rewritten image JSON");
    assert_eq!(
        document,
        json!({
            "Id": format!("sha256:{}", "66".repeat(32)),
            "RepoTags": [BUILDX_DEFAULT_IMAGE],
            "RepoDigests": [],
        })
    );
    assert!(!format!("{response:?}").contains("registry.example.invalid"));
}

#[test]
fn buildkit_image_alias_replaces_backend_errors_and_headers_without_exposing_the_target() {
    let policy = buildkit_proxy_policy();
    let private_reference = format!(
        "registry.example.invalid/buildkit/runtime@sha256:{}",
        "66".repeat(32)
    );
    let mut response = BufferedResponse {
        status_line: format!("HTTP/1.1 404 missing {private_reference}"),
        fields: vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("Location".to_owned(), private_reference.clone()),
        ],
        body: encoded(&json!({"message": format!("no such image {private_reference}")})),
    };

    policy
        .rewrite_buildkit_image_inspect_response(&mut response)
        .expect("bounded backend error response");

    assert_eq!(response.status_line, "HTTP/1.1 404 BuildKit image response");
    assert_eq!(
        response.fields,
        [("Content-Type".to_owned(), "application/json".to_owned())]
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&response.body).expect("synthetic error JSON"),
        json!({"message": "BuildKit image is unavailable"})
    );
    assert!(!format!("{response:?}").contains("registry.example.invalid"));
}

#[test]
fn buildkit_container_is_rewritten_to_the_pinned_attempt_runtime() {
    let name = "buildx_buildkit_builder-0123456789abcdef0";
    let policy = buildkit_proxy_policy();
    let request = buildkit_create(name);
    let authorized = policy
        .authorize(
            "POST",
            &format!("/v1.44/containers/create?name={name}"),
            &encoded(&request),
        )
        .expect("exact Buildx helper");
    let rewritten: Value = serde_json::from_slice(&authorized.body).expect("rewritten JSON");
    assert_eq!(
        rewritten["Image"],
        json!(format!(
            "registry.example.invalid/buildkit/runtime@sha256:{}",
            "66".repeat(32)
        ))
    );
    assert_eq!(rewritten["HostConfig"]["Privileged"], true);
    assert_eq!(rewritten["HostConfig"]["NetworkMode"], "ns:/proc/42/ns/net");
    assert_eq!(rewritten["HostConfig"]["CgroupParent"], "test.slice");
    assert_eq!(rewritten["HostConfig"]["Memory"], 512 * 1024 * 1024_u64);
    assert_eq!(rewritten["HostConfig"]["CpuPeriod"], 100_000);
    assert_eq!(rewritten["HostConfig"]["CpuQuota"], 100_000);
    assert_eq!(
        rewritten["HostConfig"]["Mounts"],
        json!([{
            "Type": "volume",
            "Source": format!("{name}_state"),
            "Target": "/var/lib/buildkit",
            "ReadOnly": false
        }])
    );
    assert_eq!(rewritten["Labels"]["io.automata.owner"], "automata-runner");
    assert_eq!(
        rewritten["Labels"]["io.automata.job-engine"],
        "test-sandbox"
    );
}

#[test]
fn buildkit_container_retry_adopts_only_the_exact_owned_runtime() {
    let name = "buildx_buildkit_builder-0123456789abcdef0";
    let identifier = "aa".repeat(32);
    let inspect = json!({
        "Id": identifier,
        "Name": format!("/{name}"),
        "Config": {
            "Image": format!(
                "registry.example.invalid/buildkit/runtime@sha256:{}",
                "66".repeat(32)
            ),
            "Labels": {
                "io.automata.owner": "automata-runner",
                "io.automata.job-engine": "test-sandbox"
            }
        },
        "HostConfig": {
            "Privileged": true,
            "NetworkMode": "ns:/proc/42/ns/net",
            "CgroupParent": "test.slice"
        },
        "Mounts": [{
            "Name": format!("{name}_state"),
            "Destination": "/var/lib/buildkit",
            "RW": true
        }]
    });

    let policy = buildkit_proxy_policy();
    let candidate = policy
        .authorize("GET", &format!("/v1.44/containers/{name}/json"), &[])
        .expect("untracked owned-name candidate");
    assert!(matches!(
        candidate.response,
        ResponseTransform::InspectBuildKitCandidate { .. }
    ));
    policy
        .adopt_buildkit_container(name, &encoded(&inspect))
        .expect("exact owned BuildKit container");
    let adopted = policy
        .authorize("GET", &format!("/v1.44/containers/{name}/json"), &[])
        .expect("adopted BuildKit container");
    assert!(matches!(adopted.response, ResponseTransform::Passthrough));

    for (case, pointer, replacement) in [
        (
            "foreign owner",
            "/Config/Labels/io.automata.owner",
            json!("someone-else"),
        ),
        (
            "wrong runtime",
            "/Config/Image",
            json!("registry.example.invalid/unverified:latest"),
        ),
        ("wrong network", "/HostConfig/NetworkMode", json!("host")),
        ("host mount", "/Mounts/0/Destination", json!("/")),
    ] {
        let mut forged = inspect.clone();
        set_json_pointer(&mut forged, pointer, replacement);
        assert!(
            buildkit_proxy_policy()
                .adopt_buildkit_container(name, &encoded(&forged))
                .is_err(),
            "{case}"
        );
    }
}

#[test]
fn buildkit_special_policy_rejects_custom_images_driver_resources_and_host_access() {
    let name = "buildx_buildkit_builder-0123456789abcdef0";
    let mutations = [
        ("custom image", "/Image", json!("moby/buildkit:master")),
        ("entrypoint", "/Entrypoint", json!(["/bin/sh"])),
        ("memory driver opt", "/HostConfig/Memory", json!(1024)),
        ("CPU driver opt", "/HostConfig/CpuQuota", json!(10_000)),
        (
            "network driver opt",
            "/HostConfig/NetworkMode",
            json!("bridge"),
        ),
        (
            "cgroup driver opt",
            "/HostConfig/CgroupParent",
            json!("custom.slice"),
        ),
        (
            "restart driver opt",
            "/HostConfig/RestartPolicy/Name",
            json!("no"),
        ),
        ("host bind", "/HostConfig/Binds", json!(["/:/host"])),
        (
            "device",
            "/HostConfig/Devices",
            json!([{"PathOnHost": "/dev/kvm", "PathInContainer": "/dev/kvm"}]),
        ),
        ("unprivileged shape", "/HostConfig/Privileged", json!(false)),
        ("unknown config field", "/FutureHostAccess", json!(true)),
        (
            "unknown host field",
            "/HostConfig/FutureHostAccess",
            json!(true),
        ),
    ];
    for (case, pointer, replacement) in mutations {
        let mut request = buildkit_create(name);
        set_json_pointer(&mut request, pointer, replacement);
        assert!(
            buildkit_proxy_policy()
                .authorize(
                    "POST",
                    &format!("/v1.44/containers/create?name={name}"),
                    &encoded(&request),
                )
                .is_err(),
            "{case}"
        );
    }
}

fn set_json_pointer(document: &mut Value, pointer: &str, replacement: Value) {
    if let Some(value) = document.pointer_mut(pointer) {
        *value = replacement;
        return;
    }
    let (parent, field) = pointer.rsplit_once('/').expect("pointer field");
    document
        .pointer_mut(parent)
        .and_then(Value::as_object_mut)
        .expect("pointer parent")
        .insert(field.to_owned(), replacement);
}

#[test]
fn buildkit_routes_cover_only_the_required_container_and_exec_lifecycle() {
    let accepted = [
        ("GET", "/info"),
        ("POST", "/images/create"),
        ("GET", "/images/moby%2Fbuildkit%3Abuildx-stable-1/json"),
        ("POST", "/containers/buildx_buildkit_builder0/start"),
        ("GET", "/containers/buildx_buildkit_builder0/logs"),
        ("POST", "/containers/buildx_buildkit_builder0/stop"),
        ("PUT", "/containers/buildx_buildkit_builder0/archive"),
        ("POST", "/containers/buildx_buildkit_builder0/exec"),
        (
            "POST",
            "/exec/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/start",
        ),
        (
            "GET",
            "/exec/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/json",
        ),
        ("DELETE", "/volumes/buildx_buildkit_builder0_state"),
    ];
    for (method, target) in accepted {
        assert!(
            DockerRoute::parse(method, target).is_ok(),
            "{method} {target}"
        );
    }
    assert!(DockerRoute::parse("POST", "/containers/example/kill").is_err());
    assert!(DockerRoute::parse("POST", "/containers/example/rename").is_err());

    assert!(matches!(
        DockerRoute::parse("PUT", "/containers/example/archive"),
        Ok(DockerRoute::ContainerOperation {
            operation: ContainerOperation::Archive,
            ..
        })
    ));
    assert!(matches!(
        DockerRoute::parse("GET", "/exec/example/json"),
        Ok(DockerRoute::ExecOperation {
            operation: ExecOperation::Inspect,
            ..
        })
    ));
}

#[test]
fn buildkit_exec_policy_allows_only_driver_health_version_and_stdio_commands() {
    for command in [
        json!(["buildctl", "debug", "workers"]),
        json!(["buildkitd", "--version"]),
        json!(["buildctl", "dial-stdio"]),
    ] {
        let request = json!({
            "AttachStdin": true,
            "AttachStdout": true,
            "AttachStderr": true,
            "Cmd": command
        });
        assert_eq!(validate_buildkit_exec_create(&encoded(&request)), Ok(()));
    }
    for request in [
        json!({
            "AttachStdin": true,
            "AttachStdout": true,
            "AttachStderr": true,
            "Cmd": ["sh", "-c", "id"]
        }),
        json!({
            "AttachStdin": true,
            "AttachStdout": true,
            "AttachStderr": true,
            "Privileged": true,
            "Cmd": ["buildctl", "dial-stdio"]
        }),
    ] {
        assert_eq!(validate_buildkit_exec_create(&encoded(&request)), Err(()));
    }
}

#[test]
fn buildkit_archive_accepts_only_the_generated_gha_provenance_file() {
    assert_eq!(validate_buildkit_config_archive(&tar_archive(None)), Ok(()));
    assert_eq!(
        validate_buildkit_config_archive(&tar_archive(Some((
            "buildkit/provenance.d/github_actions_context.json",
            br#"{"repository":"public/example"}"#,
        )))),
        Ok(())
    );
    assert_eq!(
        validate_buildkit_config_archive(&tar_archive(Some((
            "buildkit/buildkitd.toml",
            b"insecure-entitlements = [\"device\"]",
        )))),
        Err(())
    );
}

#[test]
fn buildkit_lifecycle_cleanup_is_exact_and_cross_attempt_state_is_denied() {
    let name = "buildx_buildkit_neutral-0123456789abcdef0";
    let volume = format!("{name}_state");
    let container_id = "aa".repeat(32);
    let exec_id = "bb".repeat(32);
    let first = buildkit_proxy_policy_for("attempt-first");
    let second = buildkit_proxy_policy_for("attempt-second");

    first
        .authorize(
            "POST",
            &format!("/v1.44/containers/create?name={name}"),
            &encoded(&buildkit_create(name)),
        )
        .expect("reserve exact first-attempt helper");
    first
        .finish_buildkit_container_create(name, Some(container_id.clone()))
        .expect("record exact first-attempt helper");
    first
        .record_buildkit_exec(&exec_id)
        .expect("record exact first-attempt exec");

    for (method, target, body) in [
        (
            "POST",
            format!("/v1.44/containers/{container_id}/stop"),
            Vec::new(),
        ),
        (
            "DELETE",
            format!("/v1.44/containers/{container_id}?v=1"),
            Vec::new(),
        ),
        ("DELETE", format!("/v1.44/volumes/{volume}"), Vec::new()),
        (
            "POST",
            format!("/v1.44/exec/{exec_id}/start"),
            encoded(&json!({"Detach": false, "Tty": false})),
        ),
    ] {
        assert!(
            first.authorize(method, &target, &body).is_ok(),
            "owned lifecycle request {method} {target}"
        );
    }

    let foreign_inspect = json!({
        "Id": container_id,
        "Name": format!("/{name}"),
        "Config": {
            "Image": format!(
                "registry.example.invalid/buildkit/runtime@sha256:{}",
                "66".repeat(32)
            ),
            "Labels": {
                "io.automata.owner": "automata-runner",
                "io.automata.job-engine": "attempt-first"
            }
        },
        "HostConfig": {
            "Privileged": true,
            "NetworkMode": "ns:/proc/42/ns/net",
            "CgroupParent": "test.slice"
        },
        "Mounts": [{
            "Name": volume,
            "Destination": "/var/lib/buildkit",
            "RW": true
        }]
    });
    assert_eq!(
        second.adopt_buildkit_container(name, &encoded(&foreign_inspect)),
        Err(())
    );
    assert!(
        second
            .authorize("POST", &format!("/v1.44/containers/{name}/stop"), &[],)
            .is_err()
    );
    assert!(
        second
            .authorize("DELETE", &format!("/v1.44/volumes/{volume}"), &[])
            .is_err()
    );
    assert!(
        second
            .authorize(
                "POST",
                &format!("/v1.44/exec/{exec_id}/start"),
                &encoded(&json!({"Detach": false, "Tty": false})),
            )
            .is_err()
    );
    assert!(
        first
            .authorize(
                "DELETE",
                "/v1.44/volumes/buildx_buildkit_unowned_state",
                &[],
            )
            .is_err()
    );
}

#[test]
fn buildkit_failed_create_releases_only_its_exact_reservation() {
    let name = "buildx_buildkit_neutral-0123456789abcdef0";
    let policy = buildkit_proxy_policy();
    let create = || {
        policy.authorize(
            "POST",
            &format!("/v1.44/containers/create?name={name}"),
            &encoded(&buildkit_create(name)),
        )
    };
    create().expect("initial helper reservation");
    assert!(
        create().is_err(),
        "parallel helper reservation must be denied"
    );
    policy
        .finish_buildkit_container_create(name, None)
        .expect("failed backend create clears reservation");
    assert!(
        create().is_ok(),
        "exact failed reservation must be retryable"
    );
}

fn tar_archive(file: Option<(&str, &[u8])>) -> Vec<u8> {
    let mut result = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut result);
        if let Some((name, content)) = file {
            for directory in if name.contains("provenance.d") {
                ["buildkit", "buildkit/provenance.d"].as_slice()
            } else {
                ["buildkit"].as_slice()
            } {
                let mut header = tar::Header::new_ustar();
                header.set_entry_type(tar::EntryType::Directory);
                header.set_mode(0o755);
                header.set_uid(0);
                header.set_gid(0);
                header.set_size(0);
                header.set_cksum();
                builder
                    .append_data(&mut header, *directory, std::io::empty())
                    .expect("directory entry");
            }
            let mut header = tar::Header::new_ustar();
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_size(u64::try_from(content.len()).expect("content length"));
            header.set_cksum();
            builder
                .append_data(&mut header, name, content)
                .expect("file entry");
        }
        builder.finish().expect("finish tar");
    }
    result
}

fn encoded(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("test request JSON")
}
