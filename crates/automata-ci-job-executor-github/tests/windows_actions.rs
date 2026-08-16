mod support;

use std::sync::Arc;

use automata_ci_core::JobConclusion;
use automata_ci_execution::{SandboxCapability, SandboxProvider};
use automata_ci_runner_runtime::{
    AdmissionRejection, ExecutionCancellation, ExecutionEvents, JobExecutor,
};

use support::{
    Fixture, PhaseResponse, action_step, local_action_step, prepared_node24_action,
    prepared_windows_namespace_unsafe_node24_action, windows_envelope,
    windows_envelope_with_action_graph, windows_repository_action_graph,
};

#[tokio::test]
async fn admitted_windows_javascript_action_uses_one_pre_execution_sealed_graph() {
    let action = prepared_node24_action();
    let graph = windows_repository_action_graph("actions/example", &action);
    let fixture = Fixture::windows_actions(vec![action], vec![PhaseResponse::success()]);
    let job =
        windows_envelope_with_action_graph(vec![action_step("checkout", "actions/example")], graph);
    fixture.executor.admit(&job).expect("Windows action admits");
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(fixture.request(job), events, ExecutionCancellation::new())
        .await
        .expect("sealed Windows action executes");

    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert_eq!(result.conclusion(), JobConclusion::Success, "{result:?}");
    assert_eq!(state.materialized_action_graphs.len(), 1);
    let request = &state.materialized_action_graphs[0];
    assert_eq!(request.archives().len(), 1);
    assert_eq!(request.archives()[0].ordinal(), 0);
    assert_eq!(
        state.sealed_action_execs.len(),
        2,
        "main and post are sealed"
    );
    assert!(state.sealed_action_execs.iter().all(|(command, tree)| {
        command
            .argv()
            .program()
            .as_str()
            .eq_ignore_ascii_case(r"C:\automata\externals\node24\node.exe")
            && tree.graph_sha256() == request.graph_sha256()
            && tree.sandbox() == request.sandbox()
            && tree.generation() == request.generation()
    }));
    assert!(state.commands.iter().all(|command| {
        let program = command.argv().program().as_str();
        !program.eq_ignore_ascii_case(r"C:\automata\tools\hash\automata-sha256.exe")
            && !program.eq_ignore_ascii_case(r"C:\automata\tools\tar\tar.exe")
            && !command
                .argv()
                .arguments()
                .iter()
                .any(|argument| argument.contains("FileAttributes]::ReparsePoint"))
    }));
    assert!(
        fixture
            .provider
            .capabilities()
            .supports(SandboxCapability::SealedActionTrees)
    );
}

#[test]
fn windows_workspace_local_javascript_action_is_rejected_before_lease() {
    let fixture = Fixture::windows_actions(Vec::new(), Vec::new());
    let job = windows_envelope(vec![local_action_step("local", "./local-action")]);

    assert_eq!(
        fixture.executor.admit(&job),
        Err(AdmissionRejection::InvalidJob)
    );
    assert_eq!(fixture.provider.counts(), (0, 0, 0));
    assert!(
        fixture
            .endpoint_state
            .lock()
            .expect("endpoint lock")
            .commands
            .is_empty()
    );
}

#[test]
fn windows_workspace_local_composite_is_rejected_before_lease() {
    let fixture = Fixture::windows_actions(Vec::new(), Vec::new());
    let job = windows_envelope(vec![local_action_step(
        "local-composite",
        "./local-composite",
    )]);

    assert_eq!(
        fixture.executor.admit(&job),
        Err(AdmissionRejection::InvalidJob)
    );
    assert_eq!(fixture.provider.counts(), (0, 0, 0));
}

#[test]
fn windows_repository_action_without_complete_graph_is_rejected_before_lease() {
    let fixture = Fixture::windows_actions(vec![prepared_node24_action()], Vec::new());
    let job = windows_envelope(vec![action_step("checkout", "actions/example")]);

    assert_eq!(
        fixture.executor.admit(&job),
        Err(AdmissionRejection::InvalidJob)
    );
    assert_eq!(fixture.provider.counts(), (0, 0, 0));
}

#[tokio::test]
async fn windows_namespace_aliased_entrypoints_fail_before_provider_mutation() {
    for (phase, main, pre, post) in [
        ("main", "CONOUT$.js", None, None),
        ("main-leading-space", " dist/index.js", None, None),
        ("pre", "dist/index.js", Some("LONGFI~1.JS"), None),
        (
            "pre-leading-space",
            "dist/index.js",
            Some(" dist/pre.js"),
            None,
        ),
        ("post", "dist/index.js", None, Some("CON .txt")),
        (
            "post-leading-space",
            "dist/index.js",
            None,
            Some(" dist/post.js"),
        ),
    ] {
        let action = prepared_windows_namespace_unsafe_node24_action(main, pre, post);
        let graph = windows_repository_action_graph("actions/example", &action);
        let fixture = Fixture::windows_actions(vec![action], Vec::new());
        let job = windows_envelope_with_action_graph(
            vec![action_step("action", "actions/example")],
            graph,
        );
        let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

        let result = fixture
            .executor
            .execute(fixture.request(job), events, ExecutionCancellation::new())
            .await
            .expect("namespace rejection is a terminal job result");

        assert_eq!(result.conclusion(), JobConclusion::Failure, "{phase}");
        assert_eq!(fixture.provider.counts(), (0, 0, 0), "{phase}");
        let state = fixture.endpoint_state.lock().expect("endpoint lock");
        assert!(state.materialized_action_graphs.is_empty(), "{phase}");
        assert!(state.commands.is_empty(), "{phase}");
    }
}
