use std::ffi::OsString;
use std::net::{Ipv4Addr, SocketAddrV4};

use crate::error::ProxyError;

pub(crate) const MAX_LISTENERS: usize = 128;
pub(crate) const SERVICE_PROXY_SERVE_COMMAND: &str = "serve-v1";
pub(crate) const RESULTS_PROXY_SERVE_COMMAND: &str = "serve-results-v1";
const MAX_MAPPING_BYTES: usize = 64;
const RESULTS_FRONT_NETWORK_PREFIX: u8 = 29;
const RESULTS_TRANSIT_MAXIMUM_PREFIX: u8 = 23;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProxyCommand {
    Services(Vec<Mapping>),
    Results(ResultsConfiguration),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Ipv4Network {
    network: Ipv4Addr,
    prefix: u8,
}

impl Ipv4Network {
    fn contains(self, address: Ipv4Addr) -> bool {
        let mask = u32::MAX << (32 - self.prefix);
        u32::from(address) & mask == u32::from(self.network)
    }

    fn broadcast(self) -> Ipv4Addr {
        let mask = u32::MAX << (32 - self.prefix);
        Ipv4Addr::from(u32::from(self.network) | !mask)
    }

    fn contains_usable(self, address: Ipv4Addr) -> bool {
        self.contains(address) && address != self.network && address != self.broadcast()
    }

    fn usable_host(self, offset: u32) -> Option<Ipv4Addr> {
        u32::from(self.network)
            .checked_add(offset)
            .map(Ipv4Addr::from)
            .filter(|address| self.contains_usable(*address))
    }

    fn overlaps(self, other: Self) -> bool {
        self.contains(other.network) || other.contains(self.network)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResultsConfiguration {
    front_address: Ipv4Addr,
    front_network: Ipv4Network,
    job_address: Ipv4Addr,
    transit_network: Ipv4Network,
    target_address: Ipv4Addr,
}

impl ResultsConfiguration {
    pub(crate) const fn front_address(self) -> Ipv4Addr {
        self.front_address
    }

    pub(crate) const fn job_address(self) -> Ipv4Addr {
        self.job_address
    }

    pub(crate) const fn target_address(self) -> Ipv4Addr {
        self.target_address
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Transport {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Mapping {
    transport: Transport,
    target: SocketAddrV4,
    listen_port: u16,
}

impl Mapping {
    pub(crate) const fn new(transport: Transport, target: SocketAddrV4, listen_port: u16) -> Self {
        Self {
            transport,
            target,
            listen_port,
        }
    }

    pub(crate) const fn transport(self) -> Transport {
        self.transport
    }

    pub(crate) const fn target(self) -> SocketAddrV4 {
        self.target
    }

    pub(crate) const fn listen_port(self) -> u16 {
        self.listen_port
    }
}

pub(crate) fn parse_command_line(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<ProxyCommand, ProxyError> {
    let mut arguments = arguments.into_iter();
    let command = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or(ProxyError::Usage)?;
    if command == RESULTS_PROXY_SERVE_COMMAND {
        return parse_results(arguments).map(ProxyCommand::Results);
    }
    if command != SERVICE_PROXY_SERVE_COMMAND {
        return Err(ProxyError::Usage);
    }

    let mut mappings = Vec::new();
    for argument in arguments {
        if mappings.len() == MAX_LISTENERS {
            return Err(ProxyError::Configuration);
        }
        let argument = argument
            .into_string()
            .map_err(|_| ProxyError::Configuration)?;
        mappings.push(parse_mapping(&argument)?);
    }

    if mappings.is_empty() {
        return Err(ProxyError::Configuration);
    }
    Ok(ProxyCommand::Services(mappings))
}

fn parse_results(
    mut arguments: impl Iterator<Item = OsString>,
) -> Result<ResultsConfiguration, ProxyError> {
    let front_address = parse_canonical_private_ipv4(&next_argument(&mut arguments)?)?;
    let front_network = parse_canonical_private_network(&next_argument(&mut arguments)?)?;
    let job_address = parse_canonical_private_ipv4(&next_argument(&mut arguments)?)?;
    let transit_network = parse_canonical_private_network(&next_argument(&mut arguments)?)?;
    let target_address = parse_canonical_private_ipv4(&next_argument(&mut arguments)?)?;
    if arguments.next().is_some()
        || front_network.prefix != RESULTS_FRONT_NETWORK_PREFIX
        || front_network.usable_host(2) != Some(front_address)
        || front_network.usable_host(3) != Some(job_address)
        || transit_network.prefix > RESULTS_TRANSIT_MAXIMUM_PREFIX
        || !transit_network.contains_usable(target_address)
        || transit_network.usable_host(1) == Some(target_address)
        || front_network.overlaps(transit_network)
    {
        return Err(ProxyError::Configuration);
    }
    Ok(ResultsConfiguration {
        front_address,
        front_network,
        job_address,
        transit_network,
        target_address,
    })
}

fn next_argument(arguments: &mut impl Iterator<Item = OsString>) -> Result<String, ProxyError> {
    arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or(ProxyError::Configuration)
}

fn parse_canonical_ipv4(value: &str) -> Result<Ipv4Addr, ProxyError> {
    if value.is_empty() || value.len() > 15 || !value.is_ascii() {
        return Err(ProxyError::Configuration);
    }
    let address = value
        .parse::<Ipv4Addr>()
        .map_err(|_| ProxyError::Configuration)?;
    if address.to_string() != value || !is_valid_service_ip(address) {
        return Err(ProxyError::Configuration);
    }
    Ok(address)
}

fn parse_canonical_private_ipv4(value: &str) -> Result<Ipv4Addr, ProxyError> {
    parse_canonical_ipv4(value).and_then(|address| {
        address
            .is_private()
            .then_some(address)
            .ok_or(ProxyError::Configuration)
    })
}

fn parse_canonical_private_network(value: &str) -> Result<Ipv4Network, ProxyError> {
    let (address, prefix) = value.split_once('/').ok_or(ProxyError::Configuration)?;
    let address = parse_canonical_private_ipv4(address)?;
    if prefix.is_empty()
        || prefix.len() > 2
        || !prefix.bytes().all(|byte| byte.is_ascii_digit())
        || (prefix.len() > 1 && prefix.starts_with('0'))
    {
        return Err(ProxyError::Configuration);
    }
    let prefix = prefix
        .parse::<u8>()
        .ok()
        .filter(|prefix| (8..=30).contains(prefix))
        .ok_or(ProxyError::Configuration)?;
    let mask = u32::MAX << (32 - prefix);
    if u32::from(address) & mask != u32::from(address) {
        return Err(ProxyError::Configuration);
    }
    let network = Ipv4Network {
        network: address,
        prefix,
    };
    if !network.broadcast().is_private() {
        return Err(ProxyError::Configuration);
    }
    Ok(network)
}

fn parse_mapping(value: &str) -> Result<Mapping, ProxyError> {
    if value.is_empty() || value.len() > MAX_MAPPING_BYTES || !value.is_ascii() {
        return Err(ProxyError::Configuration);
    }

    let mut fields = value.split('|');
    let transport = match fields.next() {
        Some("tcp") => Transport::Tcp,
        Some("udp") => Transport::Udp,
        _ => return Err(ProxyError::Configuration),
    };
    let ip_text = fields.next().ok_or(ProxyError::Configuration)?;
    let target_port_text = fields.next().ok_or(ProxyError::Configuration)?;
    let listen_port_text = fields.next().ok_or(ProxyError::Configuration)?;
    if fields.next().is_some() {
        return Err(ProxyError::Configuration);
    }

    let ip = ip_text
        .parse::<Ipv4Addr>()
        .map_err(|_| ProxyError::Configuration)?;
    if ip.to_string() != ip_text || !is_valid_service_ip(ip) {
        return Err(ProxyError::Configuration);
    }
    let target_port = parse_canonical_port(target_port_text, false)?;
    let listen_port = parse_canonical_port(listen_port_text, true)?;

    Ok(Mapping::new(
        transport,
        SocketAddrV4::new(ip, target_port),
        listen_port,
    ))
}

fn parse_canonical_port(value: &str, allow_zero: bool) -> Result<u16, ProxyError> {
    if value.is_empty()
        || value.len() > 5
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(ProxyError::Configuration);
    }
    let port = value
        .parse::<u16>()
        .map_err(|_| ProxyError::Configuration)?;
    if port == 0 && !allow_zero {
        return Err(ProxyError::Configuration);
    }
    Ok(port)
}

fn is_valid_service_ip(ip: Ipv4Addr) -> bool {
    let first_octet = ip.octets()[0];
    first_octet != 0 && !ip.is_loopback() && !ip.is_multicast() && ip != Ipv4Addr::BROADCAST
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(values: &[&str]) -> Result<Vec<Mapping>, ProxyError> {
        match parse_command_line(values.iter().map(OsString::from))? {
            ProxyCommand::Services(mappings) => Ok(mappings),
            ProxyCommand::Results(_) => Err(ProxyError::Configuration),
        }
    }

    #[test]
    fn accepts_only_current_canonical_protocol() {
        let mappings = parse(&[
            SERVICE_PROXY_SERVE_COMMAND,
            "tcp|10.20.0.4|5432|0",
            "udp|192.168.2.9|53|5300",
        ])
        .expect("valid mappings");

        assert_eq!(mappings.len(), 2);
        assert_eq!(mappings[0].transport(), Transport::Tcp);
        assert_eq!(mappings[0].target().to_string(), "10.20.0.4:5432");
        assert_eq!(mappings[0].listen_port(), 0);
        assert_eq!(mappings[1].transport(), Transport::Udp);
        assert_eq!(mappings[1].listen_port(), 5300);
    }

    #[test]
    fn rejects_noncurrent_command_protocol() {
        assert_eq!(
            parse(&["serve-v2", "tcp|10.0.0.2|80|0"]),
            Err(ProxyError::Usage)
        );
    }

    #[test]
    fn rejects_obsolete_or_ambiguous_syntax() {
        for values in [
            vec!["serve", "tcp|10.0.0.2|80|0"],
            vec![SERVICE_PROXY_SERVE_COMMAND],
            vec![SERVICE_PROXY_SERVE_COMMAND, "TCP|10.0.0.2|80|0"],
            vec![SERVICE_PROXY_SERVE_COMMAND, "tcp|010.0.0.2|80|0"],
            vec![SERVICE_PROXY_SERVE_COMMAND, "tcp|10.0.0.2|080|0"],
            vec![SERVICE_PROXY_SERVE_COMMAND, "tcp|10.0.0.2|80|00"],
            vec![SERVICE_PROXY_SERVE_COMMAND, "tcp|10.0.0.2|0|0"],
            vec![SERVICE_PROXY_SERVE_COMMAND, "tcp|10.0.0.2|80|0|extra"],
            vec![SERVICE_PROXY_SERVE_COMMAND, "tcp:10.0.0.2:80:0"],
        ] {
            assert!(parse(&values).is_err(), "accepted {values:?}");
        }
    }

    #[test]
    fn rejects_non_service_ipv4_targets() {
        for ip in [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "127.9.8.7",
            "224.0.0.1",
            "239.255.255.255",
            "255.255.255.255",
        ] {
            assert!(
                parse(&[SERVICE_PROXY_SERVE_COMMAND, &format!("tcp|{ip}|80|0")]).is_err(),
                "accepted {ip}"
            );
        }
    }

    #[test]
    fn enforces_listener_bound_before_allocation_grows_unbounded() {
        let mut values = vec![SERVICE_PROXY_SERVE_COMMAND.to_owned()];
        values.extend((0..=MAX_LISTENERS).map(|_| "tcp|10.0.0.2|80|0".to_owned()));
        let result = parse_command_line(values.into_iter().map(OsString::from));
        assert_eq!(result, Err(ProxyError::Configuration));
    }

    #[test]
    fn accepts_only_the_closed_results_contract() {
        let command = parse_command_line(
            [
                RESULTS_PROXY_SERVE_COMMAND,
                "172.31.8.2",
                "172.31.8.0/29",
                "172.31.8.3",
                "10.91.0.0/23",
                "10.91.0.2",
            ]
            .into_iter()
            .map(OsString::from),
        )
        .expect("closed Results transport");
        assert_eq!(
            command,
            ProxyCommand::Results(ResultsConfiguration {
                front_address: Ipv4Addr::new(172, 31, 8, 2),
                front_network: Ipv4Network {
                    network: Ipv4Addr::new(172, 31, 8, 0),
                    prefix: 29,
                },
                job_address: Ipv4Addr::new(172, 31, 8, 3),
                transit_network: Ipv4Network {
                    network: Ipv4Addr::new(10, 91, 0, 0),
                    prefix: 23,
                },
                target_address: Ipv4Addr::new(10, 91, 0, 2),
            })
        );
    }

    #[test]
    fn accepts_each_current_results_transit_capacity() {
        for (network, target) in [
            ("10.0.0.0/8", "10.91.0.2"),
            ("10.91.0.0/16", "10.91.0.2"),
            ("10.91.0.0/22", "10.91.0.2"),
            ("10.91.0.0/23", "10.91.1.254"),
        ] {
            parse_command_line(
                [
                    RESULTS_PROXY_SERVE_COMMAND,
                    "172.31.8.2",
                    "172.31.8.0/29",
                    "172.31.8.3",
                    network,
                    target,
                ]
                .into_iter()
                .map(OsString::from),
            )
            .expect("current transit capacity");
        }
    }

    fn assert_results_rejected(cases: impl IntoIterator<Item = Vec<&'static str>>) {
        for values in cases {
            assert!(
                parse_command_line(values.into_iter().map(OsString::from)).is_err(),
                "accepted invalid Results arguments"
            );
        }
    }

    #[test]
    fn rejects_results_noncurrent_front_topology_or_arity() {
        assert_results_rejected([
            vec![RESULTS_PROXY_SERVE_COMMAND],
            vec![
                RESULTS_PROXY_SERVE_COMMAND,
                "172.31.8.2",
                "172.31.8.0/29",
                "172.31.8.2",
                "10.91.0.0/23",
                "10.91.0.2",
            ],
            vec![
                RESULTS_PROXY_SERVE_COMMAND,
                "172.31.8.2",
                "172.31.8.1/29",
                "172.31.8.3",
                "10.91.0.0/23",
                "10.91.0.2",
            ],
            vec![
                RESULTS_PROXY_SERVE_COMMAND,
                "172.31.8.2",
                "172.31.8.0/29",
                "172.31.8.3",
                "10.91.0.0/23",
                "10.91.0.2",
                "extra",
            ],
            vec![
                RESULTS_PROXY_SERVE_COMMAND,
                "172.31.8.2",
                "172.31.8.0/24",
                "172.31.8.3",
                "10.91.0.0/23",
                "10.91.0.2",
            ],
            vec![
                RESULTS_PROXY_SERVE_COMMAND,
                "172.31.8.4",
                "172.31.8.0/29",
                "172.31.8.3",
                "10.91.0.0/23",
                "10.91.0.2",
            ],
            vec![
                RESULTS_PROXY_SERVE_COMMAND,
                "172.31.8.2",
                "172.31.8.0/29",
                "172.31.8.4",
                "10.91.0.0/23",
                "10.91.0.2",
            ],
        ]);
    }

    #[test]
    fn rejects_results_invalid_transit_or_target() {
        assert_results_rejected([
            vec![
                RESULTS_PROXY_SERVE_COMMAND,
                "172.31.8.2",
                "172.31.8.0/29",
                "172.31.8.3",
                "172.31.8.0/23",
                "172.31.8.8",
            ],
            vec![
                RESULTS_PROXY_SERVE_COMMAND,
                "172.31.8.2",
                "172.31.8.0/29",
                "172.31.8.3",
                "192.0.0.0/23",
                "192.0.0.2",
            ],
            vec![
                RESULTS_PROXY_SERVE_COMMAND,
                "172.31.8.2",
                "172.31.8.0/29",
                "172.31.8.3",
                "10.91.0.0/24",
                "10.91.0.2",
            ],
            vec![
                RESULTS_PROXY_SERVE_COMMAND,
                "172.31.8.2",
                "172.31.8.0/29",
                "172.31.8.3",
                "10.91.0.0/23",
                "10.91.0.1",
            ],
            vec![
                RESULTS_PROXY_SERVE_COMMAND,
                "172.31.8.2",
                "172.31.8.0/29",
                "172.31.8.3",
                "10.91.0.0/23",
                "10.91.0.0",
            ],
            vec![
                RESULTS_PROXY_SERVE_COMMAND,
                "172.31.8.2",
                "172.31.8.0/29",
                "172.31.8.3",
                "10.91.0.0/23",
                "10.91.1.255",
            ],
            vec![
                RESULTS_PROXY_SERVE_COMMAND,
                "172.31.8.2",
                "172.31.8.0/29",
                "172.31.8.3",
                "192.168.0.0/15",
                "192.168.0.2",
            ],
        ]);
    }
}
