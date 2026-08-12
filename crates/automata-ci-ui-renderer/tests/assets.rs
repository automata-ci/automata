use automata_ci_core::Sha256Digest;
use automata_ci_ui_renderer::{AssetContentType, client_assets, find_asset};
use sha2::{Digest, Sha256};

#[test]
fn exposes_only_exact_immutable_client_assets() {
    let manifest = client_assets();
    let script = find_asset(manifest.script_path).expect("script is embedded");
    assert_eq!(script.content_type, AssetContentType::JavaScript);
    assert_eq!(
        script.content_type.as_str(),
        "text/javascript; charset=utf-8"
    );
    assert!(!script.bytes.is_empty());
    assert_eq!(script.sha256.len(), 64);
    assert_eq!(hex_sha256(script.bytes), script.sha256);

    assert_eq!(manifest.stylesheet_paths.len(), 1);
    let stylesheet = find_asset(manifest.stylesheet_paths[0]).expect("stylesheet is embedded");
    assert_eq!(stylesheet.content_type, AssetContentType::Css);
    assert_eq!(stylesheet.content_type.as_str(), "text/css; charset=utf-8");
    assert!(!stylesheet.bytes.is_empty());
    assert_eq!(stylesheet.sha256.len(), 64);
    assert_eq!(hex_sha256(stylesheet.bytes), stylesheet.sha256);

    assert!(find_asset("/assets/../renderer.wasm").is_none());
    assert!(find_asset(&format!("{}?v=1", manifest.script_path)).is_none());
    assert!(find_asset("https://example.invalid/client.js").is_none());
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into()).to_string()
}
