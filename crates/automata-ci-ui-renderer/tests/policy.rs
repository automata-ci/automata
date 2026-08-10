use std::time::Duration;

use automata_ci_ui_renderer::{
    MAX_RENDER_REQUEST_UTF8_BYTES, MAX_RENDERED_HTML_UTF8_BYTES, PolicyError, RenderPolicy,
};

#[test]
fn rejects_zero_and_inconsistent_limits() {
    assert_eq!(
        RenderPolicy::builder().fuel(0).build(),
        Err(PolicyError::ZeroLimit { name: "fuel" })
    );
    assert_eq!(
        RenderPolicy::builder().timeout(Duration::ZERO).build(),
        Err(PolicyError::ZeroLimit { name: "timeout" })
    );
    assert_eq!(
        RenderPolicy::builder()
            .max_input_bytes(MAX_RENDER_REQUEST_UTF8_BYTES + 1)
            .build(),
        Err(PolicyError::InputExceedsContract {
            max_bytes: MAX_RENDER_REQUEST_UTF8_BYTES,
        })
    );
    assert_eq!(
        RenderPolicy::builder()
            .max_output_bytes(MAX_RENDERED_HTML_UTF8_BYTES + 1)
            .build(),
        Err(PolicyError::OutputExceedsContract {
            max_bytes: MAX_RENDERED_HTML_UTF8_BYTES,
        })
    );
    assert_eq!(
        RenderPolicy::builder()
            .max_total_memory_bytes(1024)
            .max_output_bytes(1025)
            .build(),
        Err(PolicyError::OutputExceedsMemory)
    );
}

#[test]
fn exposes_operational_limits_without_mutability() {
    let policy = RenderPolicy::default();
    assert_eq!(policy.max_input_bytes(), MAX_RENDER_REQUEST_UTF8_BYTES);
    assert_eq!(policy.max_output_bytes(), MAX_RENDERED_HTML_UTF8_BYTES);
    assert!(policy.max_total_memory_bytes() >= policy.max_output_bytes());
    assert_eq!(policy.max_memories(), 1);
    assert!(policy.fuel() > 0);
    assert!(!policy.timeout().is_zero());
    assert!(policy.max_concurrent_renders() > 0);
}
