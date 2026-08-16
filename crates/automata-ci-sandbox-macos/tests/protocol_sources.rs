#![forbid(unsafe_code)]

use std::{fs, path::Path};

use automata_ci_sandbox_guest::GUEST_PROTOCOL_VERSION;

const SWIFT_PROTOCOL_DECLARATION: &str = "private let guestProtocol: UInt16 = ";

fn swift_protocol(path: &Path) -> u16 {
    let source = fs::read_to_string(path).expect("read Swift protocol consumer");
    let declarations = source
        .lines()
        .filter_map(|line| line.strip_prefix(SWIFT_PROTOCOL_DECLARATION))
        .collect::<Vec<_>>();
    assert_eq!(
        declarations.len(),
        1,
        "Swift source must contain one canonical guest-protocol declaration: {}",
        path.display()
    );
    declarations[0]
        .parse()
        .expect("Swift guest protocol is an unsigned 16-bit integer")
}

#[test]
fn swift_tools_match_the_rust_guest_protocol() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for relative in [
        "swift/Sources/AutomataMacOSTemplateTool/main.swift",
        "swift/Sources/AutomataMacOSVsockBridge/main.swift",
    ] {
        assert_eq!(
            swift_protocol(&crate_root.join(relative)),
            GUEST_PROTOCOL_VERSION,
            "{relative} must advance in lockstep with the Rust guest protocol"
        );
    }
}
