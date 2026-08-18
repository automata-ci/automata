use automata_ci_actions_runtime::{
    ACTIONS_RUNTIME_ARTIFACTS_DELTA_COMMIT, ACTIONS_RUNTIME_ARTIFACTS_DELTA_UPSTREAM_SOURCES,
    ACTIONS_RUNTIME_PROTOCOL_BASELINE, ACTIONS_RUNTIME_PROTOCOL_BASELINE_COMMIT,
};

#[test]
fn artifacts_support_is_a_reviewed_delta_not_a_silent_baseline_move() {
    assert_eq!(ACTIONS_RUNTIME_PROTOCOL_BASELINE, "actions/runner@v2.336.0");
    assert_eq!(
        ACTIONS_RUNTIME_PROTOCOL_BASELINE_COMMIT,
        "98aabcd429c4e8402406c56ce2d26387fed3b9ce"
    );
    assert_eq!(
        ACTIONS_RUNTIME_ARTIFACTS_DELTA_COMMIT,
        "35e45850b519df66a669e2c91e0917804a33d0c7"
    );
    assert_eq!(
        ACTIONS_RUNTIME_ARTIFACTS_DELTA_UPSTREAM_SOURCES,
        [
            "src/Runner.Common/Constants.cs",
            "src/Runner.Common/ExtensionManager.cs",
            "src/Runner.Worker/ArtifactSubject.cs",
            "src/Runner.Worker/ArtifactsListFileCommand.cs",
            "src/Runner.Worker/CreateArtifactsFileCommand.cs",
            "src/Runner.Worker/ExecutionContext.cs",
            "src/Runner.Worker/FileCommandManager.cs",
            "src/Runner.Worker/GitHubContext.cs",
            "src/Runner.Worker/GlobalContext.cs",
            "src/Test/L0/Worker/ArtifactsListFileCommandL0.cs",
            "src/Test/L0/Worker/CreateArtifactsFileCommandL0.cs",
            "src/Test/L0/Worker/FileCommandManagerL0.cs",
        ]
    );
}
