use crate::support;

use automata_ci_action_github::{
    ActionMetadataDecoder, GITHUB_ACTION_METADATA_BASELINE, GITHUB_ACTION_METADATA_BASELINE_COMMIT,
    GithubActionMetadataDecoder, JavascriptRuntime,
};
use static_assertions::assert_obj_safe;
use support::metadata_document;

assert_obj_safe!(ActionMetadataDecoder);

#[test]
fn decoder_is_usable_behind_a_send_sync_trait_object() {
    assert_eq!(GITHUB_ACTION_METADATA_BASELINE, "actions/runner@v2.336.0");
    assert_eq!(
        GITHUB_ACTION_METADATA_BASELINE_COMMIT,
        "98aabcd429c4e8402406c56ce2d26387fed3b9ce"
    );
    let decoder: Box<dyn ActionMetadataDecoder> = Box::new(GithubActionMetadataDecoder::default());
    let document = metadata_document(
        b"name: object safe\ndescription: object safe\nruns:\n  using: node24\n  main: ./dist/index.js\n",
    );
    let metadata = decoder.decode(&document).unwrap();
    let javascript = metadata.javascript().unwrap();
    assert_eq!(javascript.runtime(), JavascriptRuntime::Node24);
    assert_eq!(javascript.main().declared(), "./dist/index.js");
    assert_eq!(javascript.main().as_str(), "dist/index.js");
}
