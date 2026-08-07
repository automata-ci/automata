mod support;

use automata_action_github::{JavascriptRuntime, MetadataScalarKind};
use support::decode;

#[test]
fn exact_checkout_v6_metadata_decodes_as_node24_with_post_cleanup() {
    let source = include_str!("fixtures/checkout-v6.0.2-de0fac2-action.yml");
    let metadata = decode(source).unwrap();

    assert_eq!(metadata.name(), Some("Checkout"));
    assert_eq!(metadata.inputs().len(), 20);
    assert_eq!(metadata.outputs().len(), 2);
    let javascript = metadata.javascript().unwrap();
    assert_eq!(javascript.runtime(), JavascriptRuntime::Node24);
    assert_eq!(javascript.main().as_str(), "dist/index.js");
    assert_eq!(javascript.post().unwrap().as_str(), "dist/index.js");
    assert_eq!(javascript.pre_condition().text(), "always()");
    assert_eq!(javascript.post_condition().text(), "always()");

    let token = metadata
        .inputs()
        .iter()
        .find(|input| input.name() == "token")
        .unwrap();
    assert_eq!(token.default().unwrap().text(), "${{ github.token }}");
    let filter = metadata
        .inputs()
        .iter()
        .find(|input| input.name() == "filter")
        .unwrap();
    assert_eq!(filter.default().unwrap().kind(), MetadataScalarKind::Null);
    let strict = metadata
        .inputs()
        .iter()
        .find(|input| input.name() == "ssh-strict")
        .unwrap();
    assert_eq!(
        strict.default().unwrap().kind(),
        MetadataScalarKind::Boolean
    );
}

#[test]
fn setup_node_and_upload_artifact_shapes_retain_defaults_and_deprecations() {
    let setup = decode(include_str!("fixtures/setup-node-v6-representative.yml")).unwrap();
    let javascript = setup.javascript().unwrap();
    assert_eq!(javascript.runtime(), JavascriptRuntime::Node24);
    assert_eq!(javascript.main().as_str(), "dist/setup/index.js");
    assert_eq!(
        javascript.post().unwrap().as_str(),
        "dist/cache-save/index.js"
    );
    assert_eq!(javascript.post_condition().text(), "success()");
    let cache = setup
        .inputs()
        .iter()
        .find(|input| input.name() == "package-manager-cache")
        .unwrap();
    assert_eq!(cache.default().unwrap().text(), "true");
    assert_eq!(
        cache.deprecation_message().unwrap().text(),
        "Use cache instead"
    );

    let upload = decode(include_str!(
        "fixtures/upload-artifact-v7-representative.yml"
    ))
    .unwrap();
    assert_eq!(
        upload.javascript().unwrap().main().as_str(),
        "dist/index.js"
    );
    assert_eq!(upload.outputs().len(), 3);
    assert_eq!(
        upload
            .inputs()
            .iter()
            .find(|input| input.name() == "compression-level")
            .unwrap()
            .default()
            .unwrap()
            .text(),
        "6"
    );
}
