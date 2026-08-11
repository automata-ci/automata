mod support;

use std::sync::Arc;

use automata_ci_execution::{ExecutionCommand, ExecutionEnvironment};
use automata_ci_github_runtime::CommandFileKind;
use automata_ci_runner_runtime::{
    ExecutionCancellation, ExecutionEvents, ExecutorErrorKind, JobExecutor,
};
use serde_json::Value;

use support::{
    EndpointState, Fixture, PhaseResponse, envelope, environment_map, run_step,
    run_step_with_working_directory, sha256_hex,
};

const WORKSPACE: &str = "/__w/automata/automata";

fn assert_sandbox_hash_commands(state: &EndpointState) {
    let hashes = state
        .commands
        .iter()
        .filter(|command| {
            command
                .argv()
                .arguments()
                .get(1)
                .is_some_and(|argument| argument.contains("automata-artifact-sha256"))
        })
        .collect::<Vec<_>>();
    assert_eq!(hashes.len(), 2);
    let relative = hashes
        .iter()
        .find(|command| command.argv().arguments()[3] == "dist/app.bin")
        .expect("runner executed the relative sandbox hash command");
    assert_eq!(relative.working_directory().as_str(), WORKSPACE);
    assert_eq!(relative.argv().arguments()[2], "/usr/bin/sha256sum");
    assert!(
        hashes
            .iter()
            .any(|command| command.argv().arguments()[3] == "/sandbox-only/release.sig"),
        "absolute declarations must be resolved by the sandbox endpoint"
    );
}

fn assert_artifact_lists(
    state: &EndpointState,
    phases: &[&ExecutionCommand],
    file_bytes: &[u8],
    absolute_file_bytes: &[u8],
) {
    let first_environment = environment_map(phases[0]);
    let first_list = first_environment
        .get("GITHUB_ARTIFACTS_LIST")
        .expect("first list path");
    assert_eq!(
        state.files.get(first_list).map(Vec::as_slice),
        Some(br#"{"version":1,"subjects":[]}"#.as_slice())
    );
    let second_environment = environment_map(phases[1]);
    let second_list = second_environment
        .get("GITHUB_ARTIFACTS_LIST")
        .expect("second list path");
    assert_eq!(
        state.files.get(second_list).map(Vec::as_slice),
        Some(b"caller mutation".as_slice())
    );
    let third_environment = environment_map(phases[2]);
    let third_list = third_environment
        .get("GITHUB_ARTIFACTS_LIST")
        .expect("third list path");
    let payload: Value = serde_json::from_slice(state.files.get(third_list).expect("third list"))
        .expect("valid list JSON");
    let file_digest = sha256_hex(file_bytes);
    let absolute_file_digest = sha256_hex(absolute_file_bytes);
    assert_eq!(payload["version"], 1);
    assert_eq!(
        payload["subjects"],
        serde_json::json!([
            {
                "name": "app.bin",
                "digest": format!("sha256:{file_digest}"),
                "kind": "file"
            },
            {
                "name": "registry.example/app:v1",
                "digest": format!("sha256:{}", "a".repeat(64)),
                "kind": "oci"
            },
            {
                "name": "release.sig",
                "digest": format!("sha256:{absolute_file_digest}"),
                "kind": "file"
            }
        ])
    );
}

#[tokio::test]
async fn declarations_are_hashed_in_the_workspace_and_list_is_read_only_and_deterministic() {
    let oci_hex = "A".repeat(64);
    let fixture = Fixture::with_default_environment(
        Vec::new(),
        vec![
            PhaseResponse::success().with_file(
                CommandFileKind::Artifacts,
                format!(
                    "# file and OCI subjects\ndist/app.bin\n/sandbox-only/release.sig\noci://registry.example/app:v1@sha256:{oci_hex}\n"
                ),
            ),
            PhaseResponse::success().with_artifacts_list_write(b"caller mutation".to_vec()),
            PhaseResponse::success(),
        ],
        ExecutionEnvironment::empty(),
    );
    let file_bytes = b"synthetic artifact bytes";
    fixture
        .endpoint_state
        .lock()
        .expect("endpoint lock")
        .files
        .insert(format!("{WORKSPACE}/dist/app.bin"), file_bytes.to_vec());
    let absolute_file_bytes = b"sandbox-only signature";
    fixture
        .endpoint_state
        .lock()
        .expect("endpoint lock")
        .files
        .insert(
            "/sandbox-only/release.sig".to_owned(),
            absolute_file_bytes.to_vec(),
        );
    let job = envelope(vec![
        run_step_with_working_directory("declare", "Declare", "true", "subdir"),
        run_step("mutate-list", "Mutate list", "true"),
        run_step("observe-list", "Observe list", "true"),
    ]);
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(fixture.request(job), events, ExecutionCancellation::new())
        .await
        .expect("artifact declaration job executes");
    assert_eq!(
        result.conclusion(),
        automata_ci_core::JobConclusion::Success
    );

    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    let phases = state
        .commands
        .iter()
        .filter(|command| command.argv().program().as_str() == "/usr/bin/bash")
        .collect::<Vec<_>>();
    assert_eq!(phases.len(), 3);
    for command in &phases {
        let environment = environment_map(command);
        assert!(environment.contains_key("GITHUB_ARTIFACTS"));
        assert!(environment.contains_key("GITHUB_ARTIFACTS_LIST"));
    }
    assert_eq!(
        phases[0].working_directory().as_str(),
        format!("{WORKSPACE}/subdir")
    );

    assert_sandbox_hash_commands(&state);
    assert_artifact_lists(&state, &phases, file_bytes, absolute_file_bytes);
}

#[tokio::test]
async fn malformed_declaration_file_is_rejected_before_any_subject_is_hashed() {
    let fixture = Fixture::new(
        Vec::new(),
        vec![PhaseResponse::success().with_file(
            CommandFileKind::Artifacts,
            b"dist/valid.bin\nname=reserved\n".to_vec(),
        )],
    );
    fixture
        .endpoint_state
        .lock()
        .expect("endpoint lock")
        .files
        .insert(format!("{WORKSPACE}/dist/valid.bin"), b"valid".to_vec());
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let error = fixture
        .executor
        .execute(
            fixture.request(envelope(vec![run_step("declare", "Declare", "true")])),
            events,
            ExecutionCancellation::new(),
        )
        .await
        .expect_err("malformed declaration must fail closed");
    assert_eq!(error.kind(), ExecutorErrorKind::InvalidJob);
    assert!(
        fixture
            .endpoint_state
            .lock()
            .expect("endpoint lock")
            .commands
            .iter()
            .all(|command| !command
                .argv()
                .arguments()
                .iter()
                .any(|argument| argument.contains("automata-artifact-sha256")))
    );
}

#[tokio::test]
async fn missing_file_declaration_fails_after_real_sandbox_resolution() {
    let fixture = Fixture::new(
        Vec::new(),
        vec![PhaseResponse::success().with_file(
            CommandFileKind::Artifacts,
            b"file://dist/missing.bin\n".to_vec(),
        )],
    );
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let error = fixture
        .executor
        .execute(
            fixture.request(envelope(vec![run_step("declare", "Declare", "true")])),
            events,
            ExecutionCancellation::new(),
        )
        .await
        .expect_err("missing file must fail during sandbox hashing");
    assert_eq!(error.kind(), ExecutorErrorKind::InvalidJob);
    assert!(
        fixture
            .endpoint_state
            .lock()
            .expect("endpoint lock")
            .commands
            .iter()
            .any(|command| command
                .argv()
                .arguments()
                .get(3)
                .is_some_and(|argument| argument == "dist/missing.bin"))
    );
}
