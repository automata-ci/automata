//! Pure canonical Docker Compose document for the sealed local lifecycle.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::{Value, json};

use crate::{
    DesiredSpec, EngineArchitecture, LIFECYCLE_ENGINE_ID_MAXIMUM_BYTES,
    LIFECYCLE_SERVER_VERSION_MAXIMUM_BYTES, valid_lifecycle_engine_id,
    valid_lifecycle_server_version,
};

use super::{engine::volume_name, materializer::VolumeRole};

const PLATFORM: &str = "linux/amd64";
const AUTOMATA_USER: &str = "65532:65532";
const ROOT_USER: &str = "0:0";
const LIFECYCLE_PROFILE: &str = "automata-lifecycle";

const CONTROL_ROOT: &str = "/run/automata-control";
pub(super) const POSTGRES_CONFIG_MOUNT: &str = "/run/automata-local/postgres";
pub(super) const POSTGRES_DATA_MOUNT: &str = "/var/lib/postgresql";
pub(super) const POSTGRES_PGDATA: &str = "/var/lib/postgresql/18/docker";
pub(super) const POSTGRES_BINARY: &str = "/usr/lib/postgresql/18/bin/postgres";
pub(super) const POSTGRES_LAUNCH_COMMAND: &str = "postgres";
pub(super) const POSTGRES_USER: &str = "999:999";
pub(super) const POSTGRES_TMPFS: [&str; 2] = [
    "/var/run/postgresql:size=16777216,uid=999,gid=999,mode=03775,noexec,nosuid,nodev",
    "/tmp:size=67108864,uid=999,gid=999,mode=01770,noexec,nosuid,nodev",
];
pub(super) const POSTGRES_READY_BINARY: &str = "/usr/bin/pg_isready";
pub(super) const POSTGRES_SERVER_CERTIFICATE: &str = "/run/automata-local/postgres/tls/server.pem";
pub(super) const POSTGRES_SERVER_PRIVATE_KEY: &str =
    "/run/automata-local/postgres/tls/server-key.pem";
const RUSTFS_ROOT: &str = "/run/automata-rustfs";
const BOOTSTRAP_ROOT: &str = "/run/automata-bootstrap";
const RELAY_ROOT: &str = "/run/automata-engine";
const RELAY_BINDING_ROOT: &str = "/run/automata-engine-binding";
const RUNNER_CONFIG_ROOT: &str = "/run/automata-runner-config";
const RUNNER_SECRETS_ROOT: &str = "/run/automata-runner-secrets";
const RUNNER_DATA_ROOT: &str = "/var/lib/automata-runner";
const RUNNER_TLS_ROOT: &str = "/var/lib/automata-runner/tls";
const RUNNER_SPOOL_KEY: &str = "/run/automata-runner-secrets/spool-key-v1.hex";
const RUNNER_S3_ACCESS_KEY: &str = "/run/automata-runner-secrets/s3-access-key";
const RUNNER_S3_SECRET_KEY: &str = "/run/automata-runner-secrets/s3-secret-key";
const RUNNER_S3_CA: &str = "/run/automata-runner-secrets/s3-ca.pem";
pub(super) const RUNNER_BINARY: &str = "/usr/local/bin/automata-runner";

const OBJECTS_HOST: &str = "objects.automata.invalid";
const DATABASE_HOST: &str = "postgres.automata.invalid";
const RUNNER_HOST: &str = "runner.automata.invalid";
const RESULTS_HOST: &str = "results.automata.invalid";
pub(super) const RUSTFS_SHELL: &str = "/bin/sh";
pub(super) const RUSTFS_CAT: &str = "/usr/bin/cat";
pub(super) const RUSTFS_SERVER: &str = "/usr/bin/rustfs";
pub(super) const RUSTFS_ENTRYPOINT: &str = "/entrypoint.sh";
pub(super) const RUSTFS_HEALTH_CLIENT: &str = "/usr/bin/curl";
pub(super) const RUSTFS_USER: &str = "10001:10001";
pub(super) const RUSTFS_TMPFS: [&str; 2] = [
    "/logs:size=67108864,uid=10001,gid=10001,mode=0750,noexec,nosuid,nodev",
    "/tmp:size=67108864,uid=10001,gid=10001,mode=01770,noexec,nosuid,nodev",
];

/// Exact deterministic names and addresses consumed by Engine convergence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RenderedTopology {
    pub(super) compose_bytes: Vec<u8>,
    pub(super) expected: ExpectedLifecycleTopology,
    pub(super) control_network_name: String,
    pub(super) egress_network_name: String,
    pub(super) results_transit_name: String,
    pub(super) control_container_name: String,
    pub(super) results_address: String,
}

/// Typed Engine contract mechanically decoded from the exact rendered
/// Compose document. Engine convergence consumes this value instead of a
/// second handwritten service/network allowlist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ExpectedLifecycleTopology {
    pub(super) containers: BTreeMap<String, ExpectedContainer>,
    pub(super) networks: BTreeMap<String, ExpectedNetwork>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub(super) struct ExpectedContainer {
    pub(super) service: String,
    pub(super) image_role: &'static str,
    pub(super) image_reference: String,
    pub(super) platform: String,
    pub(super) command: Vec<String>,
    pub(super) entrypoint: Option<Vec<String>>,
    pub(super) environment: BTreeMap<String, String>,
    pub(super) labels: BTreeMap<String, String>,
    pub(super) user: String,
    pub(super) mounts: Vec<ExpectedMount>,
    pub(super) networks: BTreeMap<String, ExpectedEndpoint>,
    pub(super) network_mode: Option<String>,
    pub(super) userns_mode: Option<String>,
    pub(super) ports: Vec<ExpectedPort>,
    pub(super) healthcheck: Option<ExpectedHealthcheck>,
    pub(super) tmpfs: Vec<String>,
    pub(super) restart: Option<String>,
    pub(super) profiles: Vec<String>,
    pub(super) read_only_root: bool,
    pub(super) cap_add: Vec<String>,
    pub(super) cap_drop: Vec<String>,
    pub(super) security_opt: Vec<String>,
    pub(super) init: bool,
    pub(super) ipc: String,
    pub(super) cgroup: String,
    pub(super) runtime: String,
    pub(super) shm_size: u64,
    pub(super) privileged: bool,
    pub(super) stdin_open: bool,
    pub(super) tty: bool,
    pub(super) log_driver: String,
    pub(super) log_options: BTreeMap<String, String>,
}

impl ExpectedContainer {
    pub(super) fn oneoff(&self) -> bool {
        self.profiles.as_slice() == [LIFECYCLE_PROFILE]
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) enum ExpectedMountSource {
    Volume(VolumeRole),
    Bind {
        source: String,
        create_host_path: bool,
        propagation: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct ExpectedMount {
    pub(super) source: ExpectedMountSource,
    pub(super) target: String,
    pub(super) read_only: bool,
    pub(super) volume_nocopy: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ExpectedEndpoint {
    pub(super) ipv4_address: String,
    pub(super) aliases: Vec<String>,
    pub(super) gateway_priority: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct ExpectedPort {
    pub(super) target: u16,
    pub(super) published: u16,
    pub(super) host_ip: String,
    pub(super) protocol: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ExpectedHealthcheck {
    pub(super) test: Vec<String>,
    pub(super) interval: String,
    pub(super) timeout: String,
    pub(super) retries: u32,
    pub(super) start_period: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ExpectedNetwork {
    pub(super) logical_name: String,
    pub(super) name: String,
    pub(super) driver: String,
    pub(super) driver_options: BTreeMap<String, String>,
    pub(super) internal: bool,
    pub(super) attachable: bool,
    pub(super) enable_ipv6: bool,
    pub(super) ipam_driver: String,
    pub(super) subnet: String,
    pub(super) gateway: String,
    pub(super) labels: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RelayEngineFacts<'a> {
    pub(super) id: &'a str,
    pub(super) api_version: &'a str,
    pub(super) server_version: &'a str,
    pub(super) architecture: EngineArchitecture,
}

#[derive(Serialize)]
struct RenderedRelayBinding<'a> {
    schema: u32,
    installation: RenderedRelayInstallation,
    engine: RenderedRelayEngine<'a>,
}

#[derive(Serialize)]
struct RenderedRelayInstallation {
    id: String,
    selector_key: String,
    compose_project: String,
    plan_digest: String,
}

#[derive(Serialize)]
struct RenderedRelayEngine<'a> {
    id: &'a str,
    api_version: &'a str,
    server_version: &'a str,
    operating_system: &'static str,
    architecture: &'static str,
}

pub(super) fn render_relay_binding(
    spec: &DesiredSpec,
    engine: &RelayEngineFacts<'_>,
) -> Result<Vec<u8>, super::LocalInitError> {
    if engine.api_version != "1.48"
        || engine.architecture != EngineArchitecture::Amd64
        || !valid_lifecycle_engine_id(engine.id)
        || !valid_lifecycle_server_version(engine.server_version)
        || engine.id.len() > LIFECYCLE_ENGINE_ID_MAXIMUM_BYTES
        || engine.server_version.len() > LIFECYCLE_SERVER_VERSION_MAXIMUM_BYTES
    {
        return Err(super::LocalInitError::new(
            super::LocalInitErrorCode::ResetRequired,
        ));
    }
    canonical_json(&RenderedRelayBinding {
        schema: 1,
        installation: RenderedRelayInstallation {
            id: spec.installation_id().to_string(),
            selector_key: spec.installation_key().to_string(),
            compose_project: spec.compose_project().to_string(),
            plan_digest: spec.plan_digest().to_string(),
        },
        engine: RenderedRelayEngine {
            id: engine.id,
            api_version: engine.api_version,
            server_version: engine.server_version,
            operating_system: "linux",
            architecture: "amd64",
        },
    })
}

pub(super) fn render_runner_config(
    spec: &DesiredSpec,
    installation: &crate::Installation,
    runner_id: uuid::Uuid,
    transit_network_id: &str,
    results_container_id: &str,
) -> Result<Vec<u8>, super::LocalInitError> {
    if installation.id() != spec.installation_id()
        || installation.selector_key() != spec.installation_key()
        || installation.compose_project() != spec.compose_project()
        || runner_id.is_nil()
        || !canonical_engine_object_id(transit_network_id)
        || !canonical_engine_object_id(results_container_id)
    {
        return Err(super::LocalInitError::new(
            super::LocalInitErrorCode::ResetRequired,
        ));
    }
    canonical_json(&json!({
        "schema_version": 7,
        "runner_id": runner_id.to_string(),
        "control_endpoint": "https://runner.automata.invalid:9090/",
        "state": {
            "journal": format!("{RUNNER_DATA_ROOT}/journal"),
            "spool": format!("{RUNNER_DATA_ROOT}/spool"),
        },
        "tls": {
            "server_roots": {"kind": "file", "path": format!("{RUNNER_TLS_ROOT}/server-ca.pem")},
            "certificate_chain": {"kind": "file", "path": format!("{RUNNER_TLS_ROOT}/runner.pem")},
            "private_key": {"kind": "file", "path": format!("{RUNNER_TLS_ROOT}/runner-key.pem")},
        },
        "spool": {
            "protection_id": "local-runner-spool-v1",
            "key_hex": {"kind": "file", "path": RUNNER_SPOOL_KEY},
            "decrypt_only": [],
        },
        "inventory": runner_inventory(spec),
        "local_docker": {
            "installation_name": installation.name().as_str(),
            "installation_id": spec.installation_id().to_string(),
            "guest_image": spec.images().sandbox_guest().reference(),
            "results_transport": {
                "proxy_image": {
                    "reference": spec.images().service_proxy().reference(),
                    "config_image_id": spec.images().service_proxy().config_image_id(),
                    "manifest_image_id": spec.images().service_proxy().manifest_image_id(),
                },
                "plan_sha256": spec.plan_digest().to_string(),
                "transit_network_id": transit_network_id,
                "results_container_id": results_container_id,
                "results_address": spec.results_transit().results_address().to_string(),
            },
        },
        "executor": runner_executor(),
        "object_store": runner_object_store(),
        "github": {
            "user_agent": "automata-local-runner/1",
            "server_url": "https://github.com/",
            "api_url": "https://api.github.com/",
            "graphql_url": "https://api.github.com/graphql",
            "allow_insecure_http": false,
        },
        "metrics": {"listen": crate::LOCAL_RUNNER_READY_LISTEN},
    }))
}

fn runner_inventory(spec: &DesiredSpec) -> Value {
    json!({
        "labels": ["self-hosted", "linux", "x64", "ubuntu-24.04"],
        "groups": ["default"],
        "max_parallel_jobs": spec.max_parallel_jobs().get(),
        "resources_per_job": {
            "cpu_millis": 1000,
            "memory_bytes": 268_435_456_u64,
            "ephemeral_disk_bytes": 0,
            "gpu_count": 0,
            "pids": 4096,
        },
        "environment_profiles": [{
            "id": spec.profile().attestation().id().as_str(),
            "manifest_sha256": spec.profile().attestation().digest().to_string(),
            "image": spec.profile().image().reference(),
            "keepalive_program": "/bin/sleep",
            "keepalive_arguments": ["infinity"],
            "workspace": "/__w",
            "default_environment": {
                "AUTOMATA_ENVIRONMENT_PROFILE_ID": spec.profile().attestation().id().as_str(),
                "CARGO_HOME": "/opt/cargo",
                "RUNNER_TOOL_CACHE": "/opt/hostedtoolcache",
                "RUSTUP_HOME": "/opt/rustup",
            },
        }],
    })
}

fn runner_executor() -> Value {
    json!({
        "resources": {
            "cpu_millis": 1000,
            "memory_bytes": 268_435_456_u64,
            "ephemeral_disk_bytes": 0,
            "gpu_count": 0,
            "pids": 4096,
        },
        "network": "private_egress",
        "root_filesystem": "writable",
        "privilege": "administrator",
        "default_step_timeout_seconds": 3600,
        "maximum_output_bytes": 16_777_216,
        "runner_root": "/__automata",
        "home": "/root",
        "path": "/opt/automata/externals/node24/bin:/opt/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "temp": "/var/lib/automata-transient",
        "tool_cache": "/opt/hostedtoolcache",
        "toolchain": {
            "bash": "/usr/bin/bash",
            "sh": "/usr/bin/sh",
            "python": "/usr/bin/python3",
            "pwsh": null,
            "install": "/usr/bin/install",
            "tar": "/usr/bin/tar",
            "sha256sum": "/usr/bin/sha256sum",
            "node24": "/opt/automata/externals/node24/bin/node",
        },
    })
}

fn runner_object_store() -> Value {
    json!({
        "endpoint": "https://objects.automata.invalid:9000/",
        "region": "us-east-1",
        "bucket": "automata",
        "prefix": "objects/v1",
        "force_path_style": true,
        "loopback_development": false,
        "tls_trust": {
            "mode": "private_ca",
            "certificate_source": {"kind": "file", "path": RUNNER_S3_CA},
        },
        "operation_timeout_seconds": 30,
        "access_key_id": {"kind": "file", "path": RUNNER_S3_ACCESS_KEY},
        "secret_access_key": {"kind": "file", "path": RUNNER_S3_SECRET_KEY},
        "session_token": null,
    })
}

/// Renders the sole current Compose document from the canonical Desired plan.
pub(super) fn render_compose(spec: &DesiredSpec) -> RenderedTopology {
    let project = spec.compose_project().as_str();
    let control_network_name = format!("{project}-control");
    let egress_network_name = format!("{project}-egress");
    let results_transit_name = format!("{project}-results-transit");
    let control_container_name = format!("{project}-automata-1");
    let results_address = spec.results_transit().results_address().to_string();
    let control_subnet = crate::desired_spec::control_subnet_for_spec(spec);
    let egress_subnet = crate::desired_spec::egress_subnet_for_spec(spec);

    let document = ComposeDocument {
        name: project,
        services: services(spec, &results_address),
        networks: BTreeMap::from([
            (
                "control".to_owned(),
                json!({
                    "name": control_network_name,
                    "driver": "bridge",
                    "internal": true,
                    "attachable": false,
                    "enable_ipv6": false,
                    "ipam": {
                        "driver": "default",
                        "config": [{
                            "subnet": control_subnet.to_string(),
                            "gateway": control_subnet.address(1).to_string(),
                        }],
                    },
                    "labels": replaceable_labels(spec, "control-network"),
                }),
            ),
            (
                "egress".to_owned(),
                json!({
                    "name": egress_network_name,
                    "driver": "bridge",
                    "driver_opts": {
                        "com.docker.network.bridge.enable_ip_masquerade": "true",
                        "com.docker.network.bridge.gateway_mode_ipv4": "nat",
                    },
                    "internal": false,
                    "attachable": false,
                    "enable_ipv6": false,
                    "ipam": {
                        "driver": "default",
                        "config": [{
                            "subnet": egress_subnet.to_string(),
                            "gateway": egress_subnet.address(1).to_string(),
                        }],
                    },
                    "labels": replaceable_labels(spec, "egress-network"),
                }),
            ),
            (
                "results-transit".to_owned(),
                json!({
                    "name": results_transit_name,
                    "external": true,
                }),
            ),
        ]),
        volumes: VolumeRole::ALL
            .into_iter()
            .map(|role| {
                (
                    role.name().to_owned(),
                    json!({
                        "name": volume_name(project, role),
                        "external": true,
                    }),
                )
            })
            .collect(),
    };
    let expected = expected_lifecycle_topology(&document);
    let mut compose_bytes =
        serde_json::to_vec(&document).expect("the closed Compose document is serializable");
    compose_bytes.push(b'\n');
    RenderedTopology {
        compose_bytes,
        expected,
        control_network_name,
        egress_network_name,
        results_transit_name,
        control_container_name,
        results_address,
    }
}

fn expected_lifecycle_topology(document: &ComposeDocument<'_>) -> ExpectedLifecycleTopology {
    ExpectedLifecycleTopology {
        containers: document
            .services
            .iter()
            .map(|(service, value)| {
                (
                    service.clone(),
                    expected_container(service, image_role_for_service(service), value),
                )
            })
            .collect(),
        networks: document
            .networks
            .iter()
            .filter(|(_, value)| value.get("external").is_none())
            .map(|(logical_name, value)| {
                (logical_name.clone(), expected_network(logical_name, value))
            })
            .collect(),
    }
}

fn image_role_for_service(service: &str) -> &'static str {
    match service {
        "automata" | "bootstrap-runner" | "engine-relay" | "object-store-init" => "automata",
        "postgres" => "postgres",
        "runner" | "runner-enroll" => "runner",
        "rustfs" => "rustfs",
        _ => panic!("closed renderer contains an unknown service"),
    }
}

#[allow(clippy::too_many_lines)]
fn expected_container(service: &str, image_role: &'static str, value: &Value) -> ExpectedContainer {
    let object = value
        .as_object()
        .expect("every closed Compose service is an object");
    let expected_keys = [
        "cap_add",
        "cap_drop",
        "cgroup",
        "command",
        "entrypoint",
        "environment",
        "healthcheck",
        "image",
        "init",
        "ipc",
        "labels",
        "logging",
        "network_mode",
        "networks",
        "platform",
        "ports",
        "privileged",
        "profiles",
        "pull_policy",
        "read_only",
        "restart",
        "runtime",
        "security_opt",
        "shm_size",
        "stdin_open",
        "tmpfs",
        "tty",
        "user",
        "userns_mode",
        "volumes",
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    assert!(
        object
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            .is_subset(&expected_keys),
        "every rendered service field must be represented in the Engine contract"
    );
    assert_eq!(
        object.get("pull_policy").and_then(Value::as_str),
        Some("never")
    );
    let strings = |field: &str| {
        object
            .get(field)
            .and_then(Value::as_array)
            .expect("closed string-array field")
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .expect("closed string-array member")
                    .to_owned()
            })
            .collect::<Vec<_>>()
    };
    let string_map = |field: &str| {
        object
            .get(field)
            .and_then(Value::as_object)
            .expect("closed string-map field")
            .iter()
            .map(|(key, value)| {
                (
                    key.clone(),
                    value.as_str().expect("closed string-map value").to_owned(),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };
    let mounts = object
        .get("volumes")
        .and_then(Value::as_array)
        .expect("closed mount array")
        .iter()
        .map(expected_mount)
        .collect();
    let networks = object
        .get("networks")
        .and_then(Value::as_object)
        .expect("closed network map")
        .iter()
        .map(|(name, endpoint)| {
            let endpoint = endpoint.as_object().expect("closed endpoint object");
            (
                name.clone(),
                ExpectedEndpoint {
                    ipv4_address: endpoint
                        .get("ipv4_address")
                        .and_then(Value::as_str)
                        .expect("closed endpoint address")
                        .to_owned(),
                    aliases: endpoint
                        .get("aliases")
                        .and_then(Value::as_array)
                        .expect("closed endpoint aliases")
                        .iter()
                        .map(|alias| alias.as_str().expect("closed endpoint alias").to_owned())
                        .collect(),
                    gateway_priority: endpoint.get("gw_priority").map_or(0, |priority| {
                        priority.as_i64().expect("closed gateway priority")
                    }),
                },
            )
        })
        .collect();
    let ports = object
        .get("ports")
        .map_or(&[][..], |ports| {
            ports.as_array().expect("closed ports array").as_slice()
        })
        .iter()
        .map(|port| {
            let port = port.as_object().expect("closed port object");
            ExpectedPort {
                target: exact_u16(port.get("target").expect("closed target port")),
                published: exact_u16(port.get("published").expect("closed published port")),
                host_ip: port
                    .get("host_ip")
                    .and_then(Value::as_str)
                    .expect("closed host IP")
                    .to_owned(),
                protocol: port
                    .get("protocol")
                    .and_then(Value::as_str)
                    .expect("closed port protocol")
                    .to_owned(),
            }
        })
        .collect();
    let healthcheck = object.get("healthcheck").map(|healthcheck| {
        let healthcheck = healthcheck.as_object().expect("closed healthcheck object");
        ExpectedHealthcheck {
            test: healthcheck
                .get("test")
                .and_then(Value::as_array)
                .expect("closed health test")
                .iter()
                .map(|part| part.as_str().expect("closed health test part").to_owned())
                .collect(),
            interval: healthcheck
                .get("interval")
                .and_then(Value::as_str)
                .expect("closed health interval")
                .to_owned(),
            timeout: healthcheck
                .get("timeout")
                .and_then(Value::as_str)
                .expect("closed health timeout")
                .to_owned(),
            retries: u32::try_from(
                healthcheck
                    .get("retries")
                    .and_then(Value::as_u64)
                    .expect("closed health retries"),
            )
            .expect("closed health retry count fits u32"),
            start_period: healthcheck
                .get("start_period")
                .and_then(Value::as_str)
                .expect("closed health start period")
                .to_owned(),
        }
    });
    let logging = object
        .get("logging")
        .and_then(Value::as_object)
        .expect("closed logging object");
    ExpectedContainer {
        service: service.to_owned(),
        image_role,
        image_reference: object
            .get("image")
            .and_then(Value::as_str)
            .expect("closed image reference")
            .to_owned(),
        platform: object
            .get("platform")
            .and_then(Value::as_str)
            .expect("closed platform")
            .to_owned(),
        command: strings("command")
            .into_iter()
            .map(|value| value.replace("$$", "$"))
            .collect(),
        entrypoint: object.get("entrypoint").map(|_| {
            strings("entrypoint")
                .into_iter()
                .map(|value| value.replace("$$", "$"))
                .collect()
        }),
        environment: string_map("environment"),
        labels: string_map("labels"),
        user: object
            .get("user")
            .and_then(Value::as_str)
            .expect("closed service user")
            .to_owned(),
        mounts,
        networks,
        network_mode: object
            .get("network_mode")
            .map(|mode| mode.as_str().expect("closed network mode").to_owned()),
        userns_mode: object.get("userns_mode").map(|mode| {
            mode.as_str()
                .expect("closed user namespace mode")
                .to_owned()
        }),
        ports,
        healthcheck,
        tmpfs: object
            .get("tmpfs")
            .map_or_else(Vec::new, |_| strings("tmpfs")),
        restart: object
            .get("restart")
            .map(|restart| restart.as_str().expect("closed restart policy").to_owned()),
        profiles: object
            .get("profiles")
            .map_or_else(Vec::new, |_| strings("profiles")),
        read_only_root: object
            .get("read_only")
            .and_then(Value::as_bool)
            .expect("closed read-only root flag"),
        cap_add: strings("cap_add"),
        cap_drop: strings("cap_drop"),
        security_opt: strings("security_opt"),
        init: object
            .get("init")
            .and_then(Value::as_bool)
            .expect("closed init flag"),
        ipc: object
            .get("ipc")
            .and_then(Value::as_str)
            .expect("closed IPC mode")
            .to_owned(),
        cgroup: object
            .get("cgroup")
            .and_then(Value::as_str)
            .expect("closed cgroup namespace mode")
            .to_owned(),
        runtime: object
            .get("runtime")
            .and_then(Value::as_str)
            .expect("closed runtime")
            .to_owned(),
        shm_size: object
            .get("shm_size")
            .and_then(Value::as_u64)
            .expect("closed shared-memory size"),
        privileged: object
            .get("privileged")
            .and_then(Value::as_bool)
            .expect("closed privileged flag"),
        stdin_open: object
            .get("stdin_open")
            .and_then(Value::as_bool)
            .expect("closed stdin flag"),
        tty: object
            .get("tty")
            .and_then(Value::as_bool)
            .expect("closed tty flag"),
        log_driver: logging
            .get("driver")
            .and_then(Value::as_str)
            .expect("closed log driver")
            .to_owned(),
        log_options: logging
            .get("options")
            .and_then(Value::as_object)
            .expect("closed log options")
            .iter()
            .map(|(key, value)| {
                (
                    key.clone(),
                    value.as_str().expect("closed log option").to_owned(),
                )
            })
            .collect(),
    }
}

fn expected_mount(value: &Value) -> ExpectedMount {
    let object = value.as_object().expect("closed mount object");
    let kind = object
        .get("type")
        .and_then(Value::as_str)
        .expect("closed mount type");
    let source = object
        .get("source")
        .and_then(Value::as_str)
        .expect("closed mount source");
    let (source, volume_nocopy) = match kind {
        "volume" => {
            let role = VolumeRole::ALL
                .into_iter()
                .find(|role| role.name() == source)
                .expect("closed named volume role");
            assert_eq!(
                object.get("volume"),
                Some(&json!({"nocopy": true})),
                "every named volume uses no-copy"
            );
            (ExpectedMountSource::Volume(role), true)
        }
        "bind" => {
            let bind = object
                .get("bind")
                .and_then(Value::as_object)
                .expect("closed bind options");
            (
                ExpectedMountSource::Bind {
                    source: source.to_owned(),
                    create_host_path: bind
                        .get("create_host_path")
                        .and_then(Value::as_bool)
                        .expect("closed create-host-path flag"),
                    propagation: bind
                        .get("propagation")
                        .and_then(Value::as_str)
                        .expect("closed bind propagation")
                        .to_owned(),
                },
                false,
            )
        }
        _ => panic!("closed renderer emitted an unknown mount type"),
    };
    ExpectedMount {
        source,
        target: object
            .get("target")
            .and_then(Value::as_str)
            .expect("closed mount target")
            .to_owned(),
        read_only: object
            .get("read_only")
            .and_then(Value::as_bool)
            .expect("closed mount access"),
        volume_nocopy,
    }
}

fn expected_network(logical_name: &str, value: &Value) -> ExpectedNetwork {
    let object = value.as_object().expect("closed network object");
    let ipam = object
        .get("ipam")
        .and_then(Value::as_object)
        .expect("closed network IPAM");
    let config = ipam
        .get("config")
        .and_then(Value::as_array)
        .filter(|config| config.len() == 1)
        .and_then(|config| config.first())
        .and_then(Value::as_object)
        .expect("closed single-subnet IPAM");
    ExpectedNetwork {
        logical_name: logical_name.to_owned(),
        name: object
            .get("name")
            .and_then(Value::as_str)
            .expect("closed network name")
            .to_owned(),
        driver: object
            .get("driver")
            .and_then(Value::as_str)
            .expect("closed network driver")
            .to_owned(),
        driver_options: object
            .get("driver_opts")
            .and_then(Value::as_object)
            .map_or_else(BTreeMap::new, |options| {
                options
                    .iter()
                    .map(|(key, value)| {
                        (
                            key.clone(),
                            value.as_str().expect("closed network option").to_owned(),
                        )
                    })
                    .collect()
            }),
        internal: object
            .get("internal")
            .and_then(Value::as_bool)
            .expect("closed internal flag"),
        attachable: object
            .get("attachable")
            .and_then(Value::as_bool)
            .expect("closed attachable flag"),
        enable_ipv6: object
            .get("enable_ipv6")
            .and_then(Value::as_bool)
            .expect("closed IPv6 flag"),
        ipam_driver: ipam
            .get("driver")
            .and_then(Value::as_str)
            .expect("closed IPAM driver")
            .to_owned(),
        subnet: config
            .get("subnet")
            .and_then(Value::as_str)
            .expect("closed subnet")
            .to_owned(),
        gateway: config
            .get("gateway")
            .and_then(Value::as_str)
            .expect("closed gateway")
            .to_owned(),
        labels: object
            .get("labels")
            .and_then(Value::as_object)
            .expect("closed network labels")
            .iter()
            .map(|(key, value)| {
                (
                    key.clone(),
                    value.as_str().expect("closed network label").to_owned(),
                )
            })
            .collect(),
    }
}

fn exact_u16(value: &Value) -> u16 {
    u16::try_from(value.as_u64().expect("closed unsigned 16-bit value"))
        .expect("closed unsigned 16-bit value fits")
}

fn services(spec: &DesiredSpec, results_address: &str) -> BTreeMap<String, Value> {
    BTreeMap::from([
        (
            "automata".to_owned(),
            control_service(spec, results_address),
        ),
        (
            "bootstrap-runner".to_owned(),
            bootstrap_runner_service(spec),
        ),
        ("engine-relay".to_owned(), relay_service(spec)),
        (
            "object-store-init".to_owned(),
            object_store_init_service(spec),
        ),
        ("postgres".to_owned(), postgres_service(spec)),
        ("runner".to_owned(), runner_service(spec)),
        ("runner-enroll".to_owned(), runner_enroll_service(spec)),
        ("rustfs".to_owned(), rustfs_service(spec)),
    ])
}

fn control_service(spec: &DesiredSpec, results_address: &str) -> Value {
    let mut service = hardened_service(
        spec.images().automata().reference(),
        AUTOMATA_USER,
        control_command(results_address),
        vec![mount(VolumeRole::ControlMaterial, CONTROL_ROOT, true)],
        BTreeMap::from([
            (
                "control".to_owned(),
                json!({"ipv4_address": control_address(spec, 10), "aliases": [RUNNER_HOST], "gw_priority": 0}),
            ),
            (
                "results-transit".to_owned(),
                json!({"ipv4_address": results_address, "aliases": [], "gw_priority": 0}),
            ),
        ]),
        replaceable_labels(spec, "control-plane"),
    );
    insert(
        &mut service,
        "ports",
        json!([{
            "target": 8080,
            "published": spec.human_port().get(),
            "host_ip": "127.0.0.1",
            "protocol": "tcp",
        }]),
    );
    insert(
        &mut service,
        "healthcheck",
        json!({
            "test": ["CMD", "/usr/local/bin/automata", crate::LOCAL_CONTROL_READY_COMMAND[0], crate::LOCAL_CONTROL_READY_COMMAND[1], crate::LOCAL_CONTROL_READY_COMMAND[2]],
            "interval": "2s",
            "timeout": "5s",
            "retries": 30,
            "start_period": "2s",
        }),
    );
    insert(&mut service, "restart", json!("unless-stopped"));
    service
}

fn control_command(results_address: &str) -> Vec<String> {
    [
        "server",
        "--listen",
        "0.0.0.0:8080",
        "--human-trusted-reverse-proxy",
        "--runner-listen",
        "0.0.0.0:9090",
        "--runner-public-url",
        "https://runner.automata.invalid:9090/",
        "--results-listen",
        &format!("{results_address}:8081"),
        "--results-public-url",
        "http://results.automata.invalid:8081/",
        "--results-allow-development-http",
        "--results-trusted-private-host",
        RESULTS_HOST,
        "--results-signing-key-source",
        "file:/run/automata-control/results-signing-key",
        "--control-plane-encryption-key-source",
        "file:/run/automata-control/control-plane-encryption-key",
        "--control-plane-encryption-key-id",
        "local-v1",
        "--secret-encryption-key-source",
        "file:/run/automata-control/secret-provider-encryption-key",
        "--secret-encryption-key-id",
        "local-v1",
        "--database-url-source",
        "file:/run/automata-control/database-url",
        "--database-transport",
        "web-pki-plus-private-ca-verify-full",
        "--database-private-ca-source",
        "file:/run/automata-control/postgres-ca.pem",
        "--s3-endpoint",
        "https://objects.automata.invalid:9000/",
        "--s3-region",
        "us-east-1",
        "--s3-bucket",
        "automata",
        "--s3-prefix",
        "objects/v1",
        "--s3-force-path-style",
        "--s3-tls-trust",
        "private-ca",
        "--s3-private-ca-source",
        "file:/run/automata-control/s3-ca.pem",
        "--s3-access-key-source",
        "file:/run/automata-control/s3-access-key",
        "--s3-secret-key-source",
        "file:/run/automata-control/s3-secret-key",
        "--runner-client-ca-cert-source",
        "file:/run/automata-control/tls/runner-ca.pem",
        "--runner-client-ca-key-source",
        "file:/run/automata-control/tls/runner-ca-key.pem",
        "--runner-server-ca-source",
        "file:/run/automata-control/tls/runner-ca.pem",
        "--runner-server-cert-source",
        "file:/run/automata-control/tls/server.pem",
        "--runner-server-key-source",
        "file:/run/automata-control/tls/server-key.pem",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect()
}

fn postgres_service(spec: &DesiredSpec) -> Value {
    let mut service = hardened_service(
        spec.images().postgres().reference(),
        POSTGRES_USER,
        vec![
            POSTGRES_LAUNCH_COMMAND.to_owned(),
            "-c".to_owned(),
            "ssl=on".to_owned(),
            "-c".to_owned(),
            format!("ssl_cert_file={POSTGRES_SERVER_CERTIFICATE}"),
            "-c".to_owned(),
            format!("ssl_key_file={POSTGRES_SERVER_PRIVATE_KEY}"),
        ],
        vec![
            mount(VolumeRole::PostgresConfig, POSTGRES_CONFIG_MOUNT, true),
            mount(VolumeRole::PostgresData, POSTGRES_DATA_MOUNT, false),
        ],
        BTreeMap::from([(
            "control".to_owned(),
            json!({"ipv4_address": control_address(spec, 20), "aliases": [DATABASE_HOST]}),
        )]),
        replaceable_labels(spec, "postgres"),
    );
    insert(
        &mut service,
        "environment",
        json!({
            "POSTGRES_DB": "automata",
            "PGDATA": POSTGRES_PGDATA,
            "POSTGRES_USER": "automata",
            "POSTGRES_PASSWORD_FILE": format!("{POSTGRES_CONFIG_MOUNT}/password"),
        }),
    );
    insert(
        &mut service,
        "healthcheck",
        json!({
            "test": ["CMD", POSTGRES_READY_BINARY, "--host=127.0.0.1", "--dbname=automata", "--username=automata"],
            "interval": "2s",
            "timeout": "3s",
            "retries": 30,
            "start_period": "2s",
        }),
    );
    insert(&mut service, "restart", json!("unless-stopped"));
    insert(&mut service, "tmpfs", json!(POSTGRES_TMPFS));
    service
}

fn rustfs_service(spec: &DesiredSpec) -> Value {
    let mut service = hardened_service(
        spec.images().rustfs().reference(),
        RUSTFS_USER,
        vec![format!(
            "RUSTFS_SSE_S3_MASTER_KEY=\"$$({RUSTFS_CAT} /run/automata-rustfs/sse-s3-master-key)\"; export RUSTFS_SSE_S3_MASTER_KEY; exec {RUSTFS_ENTRYPOINT} {RUSTFS_SERVER}"
        )],
        vec![
            mount(VolumeRole::RustfsConfig, RUSTFS_ROOT, true),
            mount(VolumeRole::ObjectData, "/data", false),
        ],
        BTreeMap::from([(
            "control".to_owned(),
            json!({"ipv4_address": control_address(spec, 30), "aliases": [OBJECTS_HOST]}),
        )]),
        replaceable_labels(spec, "object-store"),
    );
    insert(&mut service, "entrypoint", json!([RUSTFS_SHELL, "-euc"]));
    insert(
        &mut service,
        "environment",
        json!({
            "RUSTFS_ACCESS_KEY_FILE": "/run/automata-rustfs/access-key",
            "RUSTFS_ADDRESS": format!("{}:9000", control_address(spec, 30)),
            "RUSTFS_CONSOLE_ENABLE": "false",
            "RUSTFS_SECRET_KEY_FILE": "/run/automata-rustfs/secret-key",
            "RUSTFS_TLS_PATH": "/run/automata-rustfs/tls",
        }),
    );
    insert(
        &mut service,
        "healthcheck",
        json!({
            "test": ["CMD", RUSTFS_HEALTH_CLIENT, "--fail", "--silent", "--cacert", "/run/automata-rustfs/tls/ca.crt", "https://objects.automata.invalid:9000/health"],
            "interval": "2s",
            "timeout": "3s",
            "retries": 30,
            "start_period": "2s",
        }),
    );
    insert(&mut service, "restart", json!("unless-stopped"));
    insert(&mut service, "tmpfs", json!(RUSTFS_TMPFS));
    service
}

fn object_store_init_service(spec: &DesiredSpec) -> Value {
    let mut service = hardened_service(
        spec.images().automata().reference(),
        AUTOMATA_USER,
        [
            "internal",
            "object-store",
            "ensure-bucket",
            "--s3-endpoint",
            "https://objects.automata.invalid:9000/",
            "--s3-region",
            "us-east-1",
            "--s3-bucket",
            "automata",
            "--s3-force-path-style",
            "--s3-tls-trust",
            "private-ca",
            "--s3-private-ca-source",
            "file:/run/automata-control/s3-ca.pem",
            "--s3-access-key-source",
            "file:/run/automata-control/s3-access-key",
            "--s3-secret-key-source",
            "file:/run/automata-control/s3-secret-key",
        ]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect(),
        vec![mount(VolumeRole::ControlMaterial, CONTROL_ROOT, true)],
        BTreeMap::from([(
            "control".to_owned(),
            json!({"ipv4_address": control_address(spec, 31), "aliases": []}),
        )]),
        replaceable_labels(spec, "object-store-init"),
    );
    insert(&mut service, "profiles", json!([LIFECYCLE_PROFILE]));
    service
}

fn bootstrap_runner_service(spec: &DesiredSpec) -> Value {
    let mut service = hardened_service(
        spec.images().automata().reference(),
        AUTOMATA_USER,
        [
            "internal",
            "local",
            "bootstrap-runner",
            "--database-url-source",
            "file:/run/automata-control/database-url",
            "--database-private-ca-source",
            "file:/run/automata-control/postgres-ca.pem",
            "--request-source",
            "file:/run/automata-bootstrap/request.json",
            "--runner-enrollment-token-source",
            "file:/run/automata-bootstrap/runner-enrollment-token",
            "--runner-enrollment-token-target",
            "file:/run/automata-bootstrap/active-runner-enrollment-token",
            "--receipt-target",
            "file:/run/automata-bootstrap/receipt.json",
        ]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect(),
        vec![
            mount(VolumeRole::ControlMaterial, CONTROL_ROOT, true),
            mount(VolumeRole::BootstrapState, BOOTSTRAP_ROOT, false),
        ],
        BTreeMap::from([(
            "control".to_owned(),
            json!({"ipv4_address": control_address(spec, 32), "aliases": []}),
        )]),
        replaceable_labels(spec, "bootstrap-runner"),
    );
    insert(&mut service, "profiles", json!([LIFECYCLE_PROFILE]));
    service
}

fn relay_service(spec: &DesiredSpec) -> Value {
    let mut service = hardened_service(
        spec.images().automata().reference(),
        ROOT_USER,
        vec![
            "internal".to_owned(),
            "engine".to_owned(),
            "relay".to_owned(),
        ],
        vec![
            json!({
                "type": "bind",
                "source": "/var/run/docker.sock",
                "target": "/run/automata-host-engine/docker.sock",
                "read_only": true,
                "bind": {
                    "create_host_path": false,
                    "propagation": "rprivate",
                },
            }),
            mount(VolumeRole::EngineRelay, RELAY_ROOT, false),
            mount(VolumeRole::RelayBinding, RELAY_BINDING_ROOT, true),
        ],
        BTreeMap::new(),
        replaceable_labels(spec, "engine-relay"),
    );
    insert(&mut service, "network_mode", json!("none"));
    insert(
        &mut service,
        "cap_add",
        json!(["SETGID", "SETUID", "SETPCAP"]),
    );
    insert(
        &mut service,
        "healthcheck",
        json!({
            "test": ["CMD", "/usr/local/bin/automata", "internal", "engine", "check"],
            "interval": "2s",
            "timeout": "5s",
            "retries": 30,
            "start_period": "2s",
        }),
    );
    insert(&mut service, "restart", json!("unless-stopped"));
    service
}

fn runner_enroll_service(spec: &DesiredSpec) -> Value {
    let mut service = hardened_service(
        spec.images().runner().reference(),
        AUTOMATA_USER,
        [
            "enroll",
            "--config",
            "/run/automata-runner-config/runner.json",
            "--server",
            "http://127.0.0.1:8080/",
            "--name",
            "local-runner",
            "--token-source",
            "file:/run/automata-bootstrap/active-runner-enrollment-token",
        ]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect(),
        vec![
            mount(VolumeRole::RunnerConfig, RUNNER_CONFIG_ROOT, true),
            mount(VolumeRole::RunnerData, RUNNER_DATA_ROOT, false),
            mount(VolumeRole::BootstrapState, BOOTSTRAP_ROOT, true),
        ],
        BTreeMap::new(),
        replaceable_labels(spec, "runner-enroll"),
    );
    insert(&mut service, "profiles", json!([LIFECYCLE_PROFILE]));
    insert(&mut service, "network_mode", json!("service:automata"));
    service
}

fn runner_service(spec: &DesiredSpec) -> Value {
    let mut labels = replaceable_labels(spec, "runner");
    labels.extend([
        (
            "io.automata.local.max-parallel-jobs".to_owned(),
            spec.max_parallel_jobs().to_string(),
        ),
        (
            "io.automata.local.profile-id".to_owned(),
            spec.profile().attestation().id().to_string(),
        ),
        (
            "io.automata.local.profile-manifest-sha256".to_owned(),
            spec.profile().attestation().digest().to_string(),
        ),
    ]);
    let mut service = hardened_service(
        spec.images().runner().reference(),
        AUTOMATA_USER,
        vec![
            "run".to_owned(),
            "--config".to_owned(),
            "/run/automata-runner-config/runner.json".to_owned(),
        ],
        vec![
            mount(VolumeRole::RunnerConfig, RUNNER_CONFIG_ROOT, true),
            mount(VolumeRole::RunnerSecrets, RUNNER_SECRETS_ROOT, true),
            mount(VolumeRole::RunnerData, RUNNER_DATA_ROOT, false),
            mount(VolumeRole::EngineRelay, RELAY_ROOT, true),
        ],
        BTreeMap::from([
            (
                "control".to_owned(),
                json!({"ipv4_address": control_address(spec, 40), "aliases": [], "gw_priority": 0}),
            ),
            (
                "egress".to_owned(),
                json!({"ipv4_address": egress_address(spec, 20), "aliases": [], "gw_priority": 100}),
            ),
        ]),
        labels,
    );
    insert(
        &mut service,
        "healthcheck",
        json!({
            "test": [
                "CMD",
                RUNNER_BINARY,
                crate::LOCAL_RUNNER_READY_COMMAND,
                "--config",
                "/run/automata-runner-config/runner.json"
            ],
            "interval": "2s",
            "timeout": "5s",
            "retries": 30,
            "start_period": "2s",
        }),
    );
    insert(&mut service, "restart", json!("unless-stopped"));
    service
}

fn hardened_service(
    image: &str,
    user: &str,
    command: Vec<String>,
    volumes: Vec<Value>,
    networks: BTreeMap<String, Value>,
    labels: BTreeMap<String, String>,
) -> Value {
    let mut value = base_service(image, command, volumes, networks, labels);
    insert(&mut value, "user", json!(user));
    insert(&mut value, "read_only", json!(true));
    insert(&mut value, "cap_drop", json!(["ALL"]));
    insert(
        &mut value,
        "security_opt",
        json!(["no-new-privileges:true", "seccomp=builtin"]),
    );
    value
}

fn base_service(
    image: &str,
    command: Vec<String>,
    volumes: Vec<Value>,
    networks: BTreeMap<String, Value>,
    labels: BTreeMap<String, String>,
) -> Value {
    let command = Value::Array(command.into_iter().map(Value::String).collect());
    let volumes = Value::Array(volumes);
    let networks = Value::Object(networks.into_iter().collect());
    let labels = Value::Object(
        labels
            .into_iter()
            .map(|(key, value)| (key, Value::String(value)))
            .collect(),
    );
    json!({
        "image": image,
        "platform": PLATFORM,
        "pull_policy": "never",
        "command": command,
        "environment": {},
        "networks": networks,
        "volumes": volumes,
        "read_only": false,
        "init": false,
        "ipc": "private",
        "cgroup": "private",
        "runtime": "runc",
        "userns_mode": "host",
        "shm_size": 67_108_864_u64,
        "cap_add": [],
        "cap_drop": [],
        "security_opt": ["no-new-privileges:true", "seccomp=builtin"],
        "privileged": false,
        "stdin_open": false,
        "tty": false,
        "logging": {
            "driver": "json-file",
            "options": {"max-file": "3", "max-size": "10m"},
        },
        "labels": labels,
    })
}

fn mount(role: VolumeRole, target: &'static str, read_only: bool) -> Value {
    json!({
        "type": "volume",
        "source": role.name(),
        "target": target,
        "read_only": read_only,
        "volume": {"nocopy": true},
    })
}

fn control_address(spec: &DesiredSpec, host: u32) -> String {
    crate::desired_spec::control_subnet_for_spec(spec)
        .address(host)
        .to_string()
}

fn egress_address(spec: &DesiredSpec, host: u32) -> String {
    crate::desired_spec::egress_subnet_for_spec(spec)
        .address(host)
        .to_string()
}

fn replaceable_labels(spec: &DesiredSpec, role: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("io.automata.local.managed".to_owned(), "true".to_owned()),
        (
            "io.automata.local.installation-id".to_owned(),
            spec.installation_id().to_string(),
        ),
        (
            "io.automata.local.installation-key".to_owned(),
            spec.installation_key().to_string(),
        ),
        (
            "io.automata.local.compose-project".to_owned(),
            spec.compose_project().to_string(),
        ),
        (
            "io.automata.local.plan-digest".to_owned(),
            spec.plan_digest().to_string(),
        ),
        (
            "io.automata.local.resource-kind".to_owned(),
            role.to_owned(),
        ),
    ])
}

fn insert(target: &mut Value, key: &str, value: Value) {
    target
        .as_object_mut()
        .expect("closed service is an object")
        .insert(key.to_owned(), value);
}

fn canonical_json(value: &impl Serialize) -> Result<Vec<u8>, super::LocalInitError> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|_| super::LocalInitError::new(super::LocalInitErrorCode::ResetRequired))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn canonical_engine_object_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Serialize)]
struct ComposeDocument<'a> {
    name: &'a str,
    services: BTreeMap<String, Value>,
    networks: BTreeMap<String, Value>,
    volumes: BTreeMap<String, Value>,
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::{
        POSTGRES_CONFIG_MOUNT, POSTGRES_DATA_MOUNT, POSTGRES_LAUNCH_COMMAND, POSTGRES_PGDATA,
        POSTGRES_READY_BINARY, POSTGRES_SERVER_CERTIFICATE, POSTGRES_SERVER_PRIVATE_KEY,
        POSTGRES_TMPFS, POSTGRES_USER, RELAY_ROOT, RUNNER_DATA_ROOT, RUNNER_SECRETS_ROOT,
        RUNNER_TLS_ROOT, RUSTFS_CAT, RUSTFS_ENTRYPOINT, RUSTFS_HEALTH_CLIENT, RUSTFS_SERVER,
        RUSTFS_SHELL, RUSTFS_TMPFS, RUSTFS_USER, render_compose,
    };
    use crate::{desired_spec::tests::spec, init::materializer::VolumeRole};

    #[test]
    fn only_the_relay_can_write_the_engine_relay_volume() {
        let rendered = render_compose(&spec());
        let document: Value = serde_json::from_slice(&rendered.compose_bytes)
            .expect("closed Compose document is JSON");
        let services = document["services"]
            .as_object()
            .expect("closed services object");
        let mut consumers = Vec::new();

        for (service_name, service) in services {
            for volume in service["volumes"]
                .as_array()
                .expect("every closed service has a volume array")
            {
                if volume["source"] == VolumeRole::EngineRelay.name() {
                    assert_eq!(volume["target"], RELAY_ROOT);
                    consumers.push((
                        service_name.as_str(),
                        volume["read_only"]
                            .as_bool()
                            .expect("closed volume access is a boolean"),
                    ));
                }
            }
        }

        assert_eq!(
            consumers,
            vec![("engine-relay", false), ("runner", true)],
            "the relay is the sole writer and every socket consumer is read-only"
        );
        for service in services.values() {
            for mount in service["volumes"]
                .as_array()
                .expect("every closed service has a volume array")
            {
                if mount["type"] == "volume" {
                    assert_eq!(mount["volume"], serde_json::json!({"nocopy": true}));
                }
            }
        }
    }

    #[test]
    fn relay_starts_with_only_the_three_drop_capabilities() {
        let rendered = render_compose(&spec());
        let document: Value = serde_json::from_slice(&rendered.compose_bytes)
            .expect("closed Compose document is JSON");
        let relay = &document["services"]["engine-relay"];

        assert_eq!(relay["user"], "0:0");
        assert_eq!(relay["cap_drop"], serde_json::json!(["ALL"]));
        assert_eq!(
            relay["cap_add"],
            serde_json::json!(["SETGID", "SETUID", "SETPCAP"])
        );
        assert_eq!(
            relay["security_opt"],
            serde_json::json!(["no-new-privileges:true", "seccomp=builtin"])
        );
        let host_socket = relay["volumes"]
            .as_array()
            .expect("closed relay volume array")
            .iter()
            .find(|mount| mount["type"] == "bind")
            .expect("exact host socket bind");
        assert_eq!(host_socket["source"], "/var/run/docker.sock");
        assert_eq!(host_socket["read_only"], true);
    }

    #[test]
    fn every_trusted_lifecycle_unit_uses_the_host_user_namespace() {
        let rendered = render_compose(&spec());
        let document: Value = serde_json::from_slice(&rendered.compose_bytes)
            .expect("closed Compose document is JSON");
        let services = document["services"].as_object().expect("closed services");
        assert_eq!(services.len(), 8);
        for (name, service) in services {
            assert_eq!(
                service["userns_mode"], "host",
                "trusted lifecycle service {name} must see sealed host ownership"
            );
            assert_eq!(
                rendered.expected.containers[name].userns_mode.as_deref(),
                Some("host")
            );
        }
    }

    #[test]
    fn enrollment_is_the_only_runner_tls_writer_and_steady_secrets_are_read_only() {
        let rendered = render_compose(&spec());
        let document: Value = serde_json::from_slice(&rendered.compose_bytes)
            .expect("closed Compose document is JSON");
        let enroll = &document["services"]["runner-enroll"];
        let runner = &document["services"]["runner"];

        let enroll_mounts = enroll["volumes"].as_array().expect("enroll mounts");
        assert!(
            enroll_mounts
                .iter()
                .all(|mount| mount["target"] != RUNNER_SECRETS_ROOT)
        );
        assert!(
            enroll_mounts.iter().any(|mount| {
                mount["target"] == RUNNER_DATA_ROOT && mount["read_only"] == false
            })
        );
        let runner_mounts = runner["volumes"].as_array().expect("runner mounts");
        assert!(
            runner_mounts.iter().any(|mount| {
                mount["target"] == RUNNER_SECRETS_ROOT && mount["read_only"] == true
            })
        );
        assert!(RUNNER_TLS_ROOT.starts_with(&format!("{RUNNER_DATA_ROOT}/")));
    }

    #[test]
    fn rustfs_uses_only_catalog_pinned_runtime_paths() {
        let rendered = render_compose(&spec());
        let document: Value = serde_json::from_slice(&rendered.compose_bytes)
            .expect("closed Compose document is JSON");
        let rustfs = &document["services"]["rustfs"];

        assert_eq!(
            rustfs["entrypoint"],
            serde_json::json!([RUSTFS_SHELL, "-euc"])
        );
        let command = rustfs["command"][0].as_str().expect("shell command");
        for path in [RUSTFS_CAT, RUSTFS_ENTRYPOINT, RUSTFS_SERVER] {
            assert!(command.contains(path));
        }
        assert_eq!(rustfs["healthcheck"]["test"][1], RUSTFS_HEALTH_CLIENT);
        assert_eq!(rustfs["user"], RUSTFS_USER);
        assert_eq!(rustfs["read_only"], true);
        assert_eq!(rustfs["cap_drop"], serde_json::json!(["ALL"]));
        assert_eq!(rustfs["tmpfs"], serde_json::json!(RUSTFS_TMPFS));
    }

    #[test]
    fn postgres_persists_the_catalog_pgdata_beneath_the_exact_parent_mount() {
        let rendered = render_compose(&spec());
        let document: Value = serde_json::from_slice(&rendered.compose_bytes)
            .expect("closed Compose document is JSON");
        let postgres = &document["services"]["postgres"];

        assert_eq!(postgres["environment"]["PGDATA"], POSTGRES_PGDATA);
        assert_eq!(postgres["command"][0], POSTGRES_LAUNCH_COMMAND);
        assert!(
            postgres["command"]
                .as_array()
                .expect("closed Postgres command")
                .contains(&Value::String(format!(
                    "ssl_cert_file={POSTGRES_SERVER_CERTIFICATE}"
                )))
        );
        assert!(
            postgres["command"]
                .as_array()
                .expect("closed Postgres command")
                .contains(&Value::String(format!(
                    "ssl_key_file={POSTGRES_SERVER_PRIVATE_KEY}"
                )))
        );
        assert_eq!(postgres["healthcheck"]["test"][1], POSTGRES_READY_BINARY);
        assert_eq!(postgres["user"], POSTGRES_USER);
        assert_eq!(postgres["read_only"], true);
        assert_eq!(postgres["cap_drop"], serde_json::json!(["ALL"]));
        assert_eq!(postgres["tmpfs"], serde_json::json!(POSTGRES_TMPFS));
        let config_mounts = postgres["volumes"]
            .as_array()
            .expect("closed Postgres volume array")
            .iter()
            .filter(|mount| mount["source"] == VolumeRole::PostgresConfig.name())
            .collect::<Vec<_>>();
        assert_eq!(config_mounts.len(), 1);
        assert_eq!(config_mounts[0]["target"], POSTGRES_CONFIG_MOUNT);
        assert_eq!(config_mounts[0]["read_only"], true);
        let data_mounts = postgres["volumes"]
            .as_array()
            .expect("closed Postgres volume array")
            .iter()
            .filter(|mount| mount["source"] == VolumeRole::PostgresData.name())
            .collect::<Vec<_>>();
        assert_eq!(data_mounts.len(), 1);
        assert_eq!(data_mounts[0]["target"], POSTGRES_DATA_MOUNT);
        assert_eq!(data_mounts[0]["read_only"], false);
        assert!(
            POSTGRES_PGDATA.starts_with(&format!("{POSTGRES_DATA_MOUNT}/")),
            "the image PGDATA must remain inside the sole persistent parent mount"
        );
        assert_eq!(
            postgres["volumes"]
                .as_array()
                .expect("closed Postgres volume array")
                .iter()
                .filter(|mount| mount["target"] == POSTGRES_DATA_MOUNT)
                .count(),
            1,
            "no second volume may shadow the catalog persistence root"
        );
    }

    #[test]
    fn egress_is_the_only_default_route_and_runner_health_requires_admission() {
        let spec = spec();
        let rendered = render_compose(&spec);
        let document: Value = serde_json::from_slice(&rendered.compose_bytes)
            .expect("closed Compose document is JSON");
        let egress = &document["networks"]["egress"];
        let subnet = crate::desired_spec::egress_subnet_for_spec(&spec);

        assert_eq!(egress["name"], rendered.egress_network_name);
        assert_eq!(egress["internal"], false);
        assert_eq!(egress["attachable"], false);
        assert_eq!(egress["enable_ipv6"], false);
        assert_eq!(egress["ipam"]["config"][0]["subnet"], subnet.to_string());
        assert_eq!(
            egress["ipam"]["config"][0]["gateway"],
            subnet.address(1).to_string()
        );
        assert_eq!(
            egress["driver_opts"],
            serde_json::json!({
                "com.docker.network.bridge.enable_ip_masquerade": "true",
                "com.docker.network.bridge.gateway_mode_ipv4": "nat",
            })
        );

        let services = document["services"].as_object().expect("closed services");
        let egress_consumers = services
            .iter()
            .filter(|(_, service)| service["networks"].get("egress").is_some())
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(egress_consumers, ["runner"]);
        assert_eq!(
            services["runner"]["networks"]["egress"]["ipv4_address"],
            subnet.address(20).to_string()
        );
        assert_eq!(services["runner"]["networks"]["egress"]["gw_priority"], 100);
        assert_eq!(services["runner"]["networks"]["control"]["gw_priority"], 0);
        assert!(services["automata"]["networks"].get("egress").is_none());
        assert!(
            services["runner-enroll"]["networks"]
                .as_object()
                .is_some_and(serde_json::Map::is_empty)
        );
        assert_eq!(
            services["runner"]["healthcheck"]["test"],
            serde_json::json!([
                "CMD",
                "/usr/local/bin/automata-runner",
                "__local-check-ready",
                "--config",
                "/run/automata-runner-config/runner.json"
            ])
        );
    }
}
