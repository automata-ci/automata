use std::net::Ipv4Addr;

use automata_ci_execution::{ServicePort, ServiceTransportProtocol};
use serde_json::Value;

pub(crate) const ENTRYPOINT: &str = "/usr/libexec/automata-ci-service-proxy";
pub(crate) const SERVE_COMMAND: &str = "serve-v1";

pub(crate) fn mapping_argument(
    address: Ipv4Addr,
    port: ServicePort,
    listen_port: Option<u16>,
) -> String {
    format!(
        "{}|{}|{}|{}",
        match port.protocol() {
            ServiceTransportProtocol::Tcp => "tcp",
            ServiceTransportProtocol::Udp => "udp",
        },
        address,
        port.container_port(),
        listen_port.unwrap_or(0)
    )
}

pub(crate) fn parse_service_address(bytes: &[u8]) -> Option<Ipv4Addr> {
    let value = std::str::from_utf8(bytes).ok()?;
    let value = value.strip_suffix('\n').unwrap_or(value);
    if value.contains(['\n', '\r']) {
        return None;
    }
    let address = value.parse::<Ipv4Addr>().ok()?;
    if address.to_string() != value
        || address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || address.is_broadcast()
    {
        return None;
    }
    Some(address)
}

pub(crate) fn parse_status(bytes: &[u8], expected_ports: usize) -> Option<Vec<u16>> {
    let document = bytes.strip_suffix(b"\n")?;
    if document.is_empty() || document.contains(&b'\n') || document.contains(&b'\r') {
        return None;
    }
    let Value::Object(root) = serde_json::from_slice(document).ok()? else {
        return None;
    };
    if root.len() != 2 || root.get("version")?.as_u64()? != 1 || !root.contains_key("ports") {
        return None;
    }
    let values = root.get("ports")?.as_array()?;
    if values.len() != expected_ports {
        return None;
    }
    let ports = values
        .iter()
        .map(|value| {
            let port = u16::try_from(value.as_u64()?).ok()?;
            (port != 0).then_some(port)
        })
        .collect::<Option<Vec<_>>>()?;
    let canonical = format!(
        "{{\"version\":1,\"ports\":[{}]}}",
        ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );
    if canonical.as_bytes() != document {
        return None;
    }
    Some(ports)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use automata_ci_execution::{ServicePort, ServiceTransportProtocol};

    use super::{mapping_argument, parse_service_address, parse_status};

    #[test]
    fn mapping_arguments_are_canonical_and_secret_free() {
        let port = ServicePort::new(5432, None, ServiceTransportProtocol::Tcp).expect("port");
        assert_eq!(
            mapping_argument(Ipv4Addr::new(10, 89, 0, 4), port, None),
            "tcp|10.89.0.4|5432|0"
        );
    }

    #[test]
    fn service_addresses_require_one_canonical_non_loopback_ipv4_literal() {
        assert_eq!(
            parse_service_address(b"10.89.0.4\n"),
            Some(Ipv4Addr::new(10, 89, 0, 4))
        );
        for value in [
            b"127.0.0.1\n".as_slice(),
            b"0.0.0.0\n",
            b"224.0.0.1\n",
            b"010.089.0.4\n",
            b"10.89.0.4\nextra\n",
            b"::1\n",
        ] {
            assert!(parse_service_address(value).is_none(), "{value:?}");
        }
    }

    #[test]
    fn status_is_current_only_canonical_and_exactly_sized() {
        assert_eq!(
            parse_status(b"{\"version\":1,\"ports\":[41001,41002]}\n", 2),
            Some(vec![41001, 41002])
        );
        for value in [
            b"{\"ports\":[41001,41002],\"version\":1}\n".as_slice(),
            b"{\"ports\":[0,41002],\"version\":1}\n",
            b"{\"ports\":[41001],\"version\":1}\n",
            b"{\"ports\":[41001,41002],\"version\":2}\n",
            b"{\"extra\":0,\"ports\":[41001,41002],\"version\":1}\n",
            b"{\"ports\":[41001,41002],\"version\":1}\nextra\n",
        ] {
            assert!(parse_status(value, 2).is_none(), "{value:?}");
        }
    }
}
