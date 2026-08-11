use std::{collections::BTreeMap, time::Duration};

use automata_ci_execution::{
    ContainerHandle, ExecutionEnvironment, ImmutableImage, ServiceContainerBinding,
    ServiceContainerBindings, ServiceContainerSpec, ServiceContainerSpecs, ServiceHealthOverrides,
    ServiceNetwork, ServicePort, ServicePortBinding, ServiceTransportProtocol, ValueError,
};

const MAX_HEALTH_COMMAND_BYTES: usize = 64 * 1024;
const MAX_HEALTH_RETRIES: u32 = 1_000;
const MAX_HEALTH_DURATION: Duration = Duration::from_hours(24);
const MAX_SERVICE_NAME_BYTES: usize = 256;

fn image() -> ImmutableImage {
    ImmutableImage::new(format!(
        "docker.io/library/service@sha256:{}",
        "d".repeat(64)
    ))
    .expect("fixed digest-pinned service image")
}

fn service(ports: impl IntoIterator<Item = ServicePort>) -> ServiceContainerSpec {
    ServiceContainerSpec::new(image(), ExecutionEnvironment::empty())
        .with_ports(ports)
        .expect("test service ports")
}

fn binding(
    container: &str,
    network: &str,
    service_port: ServicePort,
    host_port: u16,
) -> ServiceContainerBinding {
    ServiceContainerBinding::new(
        ContainerHandle::new(container).expect("test container handle"),
        ServiceNetwork::new(network).expect("test network"),
        [ServicePortBinding::new(service_port, host_port).expect("test port binding")],
    )
    .expect("test service binding")
}

#[test]
fn health_overrides_accept_exact_limits_and_reject_each_invalid_boundary() {
    let exact = ServiceHealthOverrides::new(
        Some("x".repeat(MAX_HEALTH_COMMAND_BYTES)),
        Some(MAX_HEALTH_DURATION),
        Some(MAX_HEALTH_DURATION),
        Some(MAX_HEALTH_DURATION),
        Some(MAX_HEALTH_RETRIES),
    )
    .expect("exact health override limits");
    assert_eq!(
        exact.command().map(str::len),
        Some(MAX_HEALTH_COMMAND_BYTES)
    );
    assert_eq!(exact.interval(), Some(MAX_HEALTH_DURATION));
    assert_eq!(exact.timeout(), Some(MAX_HEALTH_DURATION));
    assert_eq!(exact.start_period(), Some(MAX_HEALTH_DURATION));
    assert_eq!(exact.retries(), Some(MAX_HEALTH_RETRIES));

    let invalid = [
        (
            "no override",
            ServiceHealthOverrides::new(None, None, None, None, None),
        ),
        (
            "empty command",
            ServiceHealthOverrides::new(Some(String::new()), None, None, None, None),
        ),
        (
            "NUL command",
            ServiceHealthOverrides::new(Some("contains\0nul".to_owned()), None, None, None, None),
        ),
        (
            "oversized command",
            ServiceHealthOverrides::new(
                Some("x".repeat(MAX_HEALTH_COMMAND_BYTES + 1)),
                None,
                None,
                None,
                None,
            ),
        ),
        (
            "zero interval",
            ServiceHealthOverrides::new(None, Some(Duration::ZERO), None, None, None),
        ),
        (
            "oversized timeout",
            ServiceHealthOverrides::new(
                None,
                None,
                Some(MAX_HEALTH_DURATION + Duration::from_nanos(1)),
                None,
                None,
            ),
        ),
        (
            "zero start period",
            ServiceHealthOverrides::new(None, None, None, Some(Duration::ZERO), None),
        ),
        (
            "zero retries",
            ServiceHealthOverrides::new(None, None, None, None, Some(0)),
        ),
        (
            "oversized retries",
            ServiceHealthOverrides::new(None, None, None, None, Some(MAX_HEALTH_RETRIES + 1)),
        ),
    ];
    for (case, result) in invalid {
        assert_eq!(
            result,
            Err(ValueError::InvalidServiceContainer),
            "health override accepted {case}"
        );
    }
}

#[test]
fn requested_ports_are_protocol_aware_but_container_numbers_are_unambiguous() {
    assert_eq!(
        ServicePort::new(0, None, ServiceTransportProtocol::Tcp),
        Err(ValueError::InvalidServiceContainer)
    );
    assert_eq!(
        ServicePort::new(80, Some(0), ServiceTransportProtocol::Tcp),
        Err(ValueError::InvalidServiceContainer)
    );

    let tcp = ServicePort::new(53, Some(10_053), ServiceTransportProtocol::Tcp)
        .expect("TCP service port");
    let udp_same_container = ServicePort::new(53, Some(10_053), ServiceTransportProtocol::Udp)
        .expect("UDP service port");
    assert!(matches!(
        ServiceContainerSpec::new(image(), ExecutionEnvironment::empty())
            .with_ports([tcp, udp_same_container]),
        Err(ValueError::InvalidServiceContainer)
    ));

    let udp = ServicePort::new(54, Some(10_053), ServiceTransportProtocol::Udp)
        .expect("distinct UDP service port");
    let protocol_pair = service([tcp, udp]);
    assert_eq!(protocol_pair.ports(), &[tcp, udp]);

    let duplicate_tcp_listener = ServicePort::new(55, Some(10_053), ServiceTransportProtocol::Tcp)
        .expect("second TCP service port");
    assert!(matches!(
        ServiceContainerSpec::new(image(), ExecutionEnvironment::empty())
            .with_ports([tcp, duplicate_tcp_listener]),
        Err(ValueError::InvalidServiceContainer)
    ));
}

#[test]
fn service_aliases_enforce_exact_bounds_and_cross_service_listener_uniqueness() {
    let exact_name = "s".repeat(MAX_SERVICE_NAME_BYTES);
    let exact = ServiceContainerSpecs::new(BTreeMap::from([(exact_name.clone(), service([]))]))
        .expect("maximum service alias");
    assert_eq!(exact.len(), 1);
    assert!(exact.get(&exact_name).is_some());
    assert_eq!(
        exact.iter().map(|(name, _)| name).collect::<Vec<_>>(),
        [exact_name]
    );

    for invalid_name in [
        String::new(),
        "x".repeat(MAX_SERVICE_NAME_BYTES + 1),
        "bad\nname".to_owned(),
    ] {
        assert!(matches!(
            ServiceContainerSpecs::new(BTreeMap::from([(invalid_name, service([]))])),
            Err(ValueError::InvalidServiceContainer)
        ));
    }
    assert!(matches!(
        ServiceContainerSpecs::new(BTreeMap::from([
            ("cache".to_owned(), service([])),
            ("CACHE".to_owned(), service([])),
        ])),
        Err(ValueError::InvalidServiceContainer)
    ));

    let tcp =
        ServicePort::new(80, Some(8_080), ServiceTransportProtocol::Tcp).expect("TCP listener");
    let other_tcp = ServicePort::new(81, Some(8_080), ServiceTransportProtocol::Tcp)
        .expect("colliding TCP listener");
    assert!(matches!(
        ServiceContainerSpecs::new(BTreeMap::from([
            ("first".to_owned(), service([tcp])),
            ("second".to_owned(), service([other_tcp])),
        ])),
        Err(ValueError::InvalidServiceContainer)
    ));

    let udp = ServicePort::new(81, Some(8_080), ServiceTransportProtocol::Udp)
        .expect("same-number UDP listener");
    let protocol_pair = ServiceContainerSpecs::new(BTreeMap::from([
        ("first".to_owned(), service([tcp])),
        ("second".to_owned(), service([udp])),
    ]))
    .expect("TCP and UDP may use the same host port");
    assert_eq!(protocol_pair.len(), 2);
}

#[test]
fn discovered_topology_rejects_reused_resources_and_accepts_protocol_pairs() {
    let tcp = ServicePort::new(80, None, ServiceTransportProtocol::Tcp).expect("TCP port");
    let udp = ServicePort::new(81, None, ServiceTransportProtocol::Udp).expect("UDP port");

    let valid = ServiceContainerBindings::new(BTreeMap::from([
        (
            "tcp".to_owned(),
            binding("container-tcp", "job-network", tcp, 30_000),
        ),
        (
            "udp".to_owned(),
            binding("container-udp", "job-network", udp, 30_000),
        ),
    ]))
    .expect("same host number is valid for different protocols");
    assert_eq!(valid.len(), 2);
    assert_eq!(
        valid.iter().map(|(name, _)| name).collect::<Vec<_>>(),
        ["tcp", "udp"]
    );

    assert!(matches!(
        ServiceContainerBindings::new(BTreeMap::from([
            (
                "first".to_owned(),
                binding("reused", "job-network", tcp, 30_001),
            ),
            (
                "second".to_owned(),
                binding("reused", "job-network", udp, 30_002),
            ),
        ])),
        Err(ValueError::InvalidServiceContainer)
    ));
    assert!(matches!(
        ServiceContainerBindings::new(BTreeMap::from([
            (
                "first".to_owned(),
                binding("container-a", "network-a", tcp, 30_003),
            ),
            (
                "second".to_owned(),
                binding("container-b", "network-b", udp, 30_004),
            ),
        ])),
        Err(ValueError::InvalidServiceContainer)
    ));

    let other_tcp =
        ServicePort::new(82, None, ServiceTransportProtocol::Tcp).expect("second TCP port");
    assert!(matches!(
        ServiceContainerBindings::new(BTreeMap::from([
            (
                "first".to_owned(),
                binding("container-a", "job-network", tcp, 30_005),
            ),
            (
                "second".to_owned(),
                binding("container-b", "job-network", other_tcp, 30_005),
            ),
        ])),
        Err(ValueError::InvalidServiceContainer)
    ));
}

#[test]
fn one_service_binding_rejects_duplicate_requests_and_published_sockets() {
    let network = || ServiceNetwork::new("job-network").expect("network");
    let container = || ContainerHandle::new("container").expect("container");
    let tcp = ServicePort::new(80, None, ServiceTransportProtocol::Tcp).expect("TCP port");
    let other_tcp =
        ServicePort::new(81, None, ServiceTransportProtocol::Tcp).expect("second TCP port");

    assert_eq!(
        ServicePortBinding::new(tcp, 0),
        Err(ValueError::InvalidServiceContainer)
    );
    assert!(matches!(
        ServiceContainerBinding::new(
            container(),
            network(),
            [
                ServicePortBinding::new(tcp, 31_000).expect("first binding"),
                ServicePortBinding::new(tcp, 31_001).expect("duplicate request"),
            ],
        ),
        Err(ValueError::InvalidServiceContainer)
    ));
    assert!(matches!(
        ServiceContainerBinding::new(
            container(),
            network(),
            [
                ServicePortBinding::new(tcp, 31_002).expect("first binding"),
                ServicePortBinding::new(other_tcp, 31_002).expect("duplicate socket"),
            ],
        ),
        Err(ValueError::InvalidServiceContainer)
    ));
}
