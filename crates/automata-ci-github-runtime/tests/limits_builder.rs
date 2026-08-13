use automata_ci_github_runtime::{
    WorkflowCommandLimits, WorkflowCommandLimitsBuilder, WorkflowCommandLimitsError,
};

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
