use std::ffi::OsString;
use std::net::{Ipv4Addr, SocketAddrV4};

use crate::error::ProxyError;

pub(crate) const MAX_LISTENERS: usize = 128;
const MAX_MAPPING_BYTES: usize = 64;

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
) -> Result<Vec<Mapping>, ProxyError> {
    let mut arguments = arguments.into_iter();
    if arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .as_deref()
        != Some("serve-v1")
    {
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
    Ok(mappings)
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
        parse_command_line(values.iter().map(OsString::from))
    }

    #[test]
    fn accepts_only_current_canonical_protocol() {
        let mappings = parse(&[
            "serve-v1",
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
    fn rejects_obsolete_or_ambiguous_syntax() {
        for values in [
            vec!["serve", "tcp|10.0.0.2|80|0"],
            vec!["serve-v2", "tcp|10.0.0.2|80|0"],
            vec!["serve-v1"],
            vec!["serve-v1", "TCP|10.0.0.2|80|0"],
            vec!["serve-v1", "tcp|010.0.0.2|80|0"],
            vec!["serve-v1", "tcp|10.0.0.2|080|0"],
            vec!["serve-v1", "tcp|10.0.0.2|80|00"],
            vec!["serve-v1", "tcp|10.0.0.2|0|0"],
            vec!["serve-v1", "tcp|10.0.0.2|80|0|extra"],
            vec!["serve-v1", "tcp:10.0.0.2:80:0"],
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
                parse(&["serve-v1", &format!("tcp|{ip}|80|0")]).is_err(),
                "accepted {ip}"
            );
        }
    }

    #[test]
    fn enforces_listener_bound_before_allocation_grows_unbounded() {
        let mut values = vec!["serve-v1".to_owned()];
        values.extend((0..=MAX_LISTENERS).map(|_| "tcp|10.0.0.2|80|0".to_owned()));
        let result = parse_command_line(values.into_iter().map(OsString::from));
        assert_eq!(result, Err(ProxyError::Configuration));
    }
}
