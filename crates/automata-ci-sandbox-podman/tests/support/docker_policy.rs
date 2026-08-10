use std::sync::Arc;

use automata_ci_execution::{ProviderId, ResourceLimits, SandboxHandle};
use serde_json::{Value, json};

use super::{DockerLaunchValidator, ProxyPolicy, validate_build_query};

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
    )
}

fn encoded(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("test request JSON")
}
