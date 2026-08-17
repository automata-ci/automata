use std::fmt::Write as _;

pub(crate) const SERVICE_PROXY_STATUS_SCHEMA_VERSION: u64 = 1;
pub(crate) const RESULTS_READY_STATUS: &str =
    "{\"version\":1,\"mode\":\"results-v1\",\"port\":8081}\n";

pub(crate) fn encode_startup_status(ports: &[u16]) -> String {
    let mut status = String::with_capacity(32 + ports.len() * 6);
    write!(
        status,
        "{{\"version\":{SERVICE_PROXY_STATUS_SCHEMA_VERSION},\"ports\":["
    )
    .expect("writing to a String cannot fail");
    for (index, port) in ports.iter().enumerate() {
        if index != 0 {
            status.push(',');
        }
        write!(status, "{port}").expect("writing to a String cannot fail");
    }
    status.push_str("]}\n");
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_is_one_compact_current_version_line_in_input_order() {
        assert_eq!(
            encode_startup_status(&[49152, 53, 65535]),
            "{\"version\":1,\"ports\":[49152,53,65535]}\n"
        );
    }
}
