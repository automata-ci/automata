use automata_ui_renderer::{MAX_RENDER_REQUEST_UTF8_BYTES, MAX_RENDERED_HTML_UTF8_BYTES};
use serde_json::Value;

#[test]
fn generated_rust_limits_match_the_canonical_ui_contract() {
    let contract: Value = serde_json::from_str(include_str!("../../../ui/renderer/contract.json"))
        .expect("renderer contract is valid JSON");

    assert_eq!(contract["schemaVersion"], 1);
    assert_eq!(
        contract["maxRequestUtf8Bytes"].as_u64(),
        Some(MAX_RENDER_REQUEST_UTF8_BYTES as u64)
    );
    assert_eq!(
        contract["maxRenderedHtmlUtf8Bytes"].as_u64(),
        Some(MAX_RENDERED_HTML_UTF8_BYTES as u64)
    );
}
