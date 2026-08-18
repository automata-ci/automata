use automata_ci_actions_runtime::{
    WorkflowCommandLimits, WorkflowCommandLimitsBuilder, WorkflowCommandLimitsError,
};

#[test]
fn workflow_limit_builder_starts_safe_and_applies_overrides() {
    let limits = WorkflowCommandLimits::builder()
        .maximum_stream_bytes(1_024)
        .maximum_line_bytes(128)
        .maximum_stream_lines(32)
        .maximum_commands(16)
        .maximum_properties(8)
        .maximum_name_bytes(64)
        .maximum_data_bytes(512)
        .maximum_masks(4)
        .build()
        .expect("valid workflow-command limits");

    assert_eq!(limits.maximum_stream_bytes(), 1_024);
    assert_eq!(limits.maximum_line_bytes(), 128);
    assert_eq!(limits.maximum_stream_lines(), 32);
    assert_eq!(limits.maximum_commands(), 16);
    assert_eq!(limits.maximum_properties(), 8);
    assert_eq!(limits.maximum_name_bytes(), 64);
    assert_eq!(limits.maximum_data_bytes(), 512);
    assert_eq!(limits.maximum_masks(), 4);
    assert_eq!(
        WorkflowCommandLimits::builder()
            .build()
            .expect("default builder policy"),
        WorkflowCommandLimits::default()
    );
}

#[test]
fn workflow_limit_builder_rejects_zero_for_every_dimension() {
    let zero_limit_setters: [fn(WorkflowCommandLimitsBuilder) -> WorkflowCommandLimitsBuilder; 8] = [
        |builder| builder.maximum_stream_bytes(0),
        |builder| builder.maximum_line_bytes(0),
        |builder| builder.maximum_stream_lines(0),
        |builder| builder.maximum_commands(0),
        |builder| builder.maximum_properties(0),
        |builder| builder.maximum_name_bytes(0),
        |builder| builder.maximum_data_bytes(0),
        |builder| builder.maximum_masks(0),
    ];

    for set_zero in zero_limit_setters {
        assert_eq!(
            set_zero(WorkflowCommandLimits::builder()).build(),
            Err(WorkflowCommandLimitsError)
        );
    }
}
