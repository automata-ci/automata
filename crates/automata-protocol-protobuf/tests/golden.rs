mod common;

use std::fmt::Write as _;

use automata_protocol::ProtocolLimits;
use automata_protocol_protobuf::{encode_runner_frame, encode_server_frame};
use sha2::{Digest as _, Sha256};

fn sha256(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(output, "{byte:02x}").expect("writing to a String is infallible");
    }
    output
}

#[test]
fn protobuf_v1_encoding_matches_checked_in_golden_digests() {
    let limits = ProtocolLimits::default();
    let mut actual = Vec::new();
    for (name, message) in common::runner_messages() {
        let bytes = encode_runner_frame(&message, &limits).expect("encode runner golden fixture");
        actual.push(format!("{digest}  runner/{name}", digest = sha256(&bytes)));
    }
    for (name, message) in common::server_messages() {
        let bytes = encode_server_frame(&message, &limits).expect("encode server golden fixture");
        actual.push(format!("{digest}  server/{name}", digest = sha256(&bytes)));
    }

    let expected = include_str!("fixtures/runner-v1.sha256")
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
}

#[test]
fn simple_no_work_frame_has_an_exact_byte_fixture() {
    let message = common::server_messages()
        .into_iter()
        .find_map(|(name, message)| (name == "no_work").then_some(message))
        .expect("no-work fixture");
    let actual = encode_server_frame(&message, &ProtocolLimits::default()).expect("encode fixture");
    let expected = [
        66, 63, 10, 58, 8, 3, 16, 4, 26, 16, 18, 52, 86, 120, 154, 188, 222, 240, 0, 0, 0, 0, 0, 0,
        0, 2, 34, 16, 18, 52, 86, 120, 154, 188, 222, 240, 0, 0, 0, 0, 0, 0, 0, 63, 42, 16, 18, 52,
        86, 120, 154, 188, 222, 240, 0, 0, 0, 0, 0, 0, 0, 64, 16, 226, 9,
    ];
    assert_eq!(actual, expected);
}
