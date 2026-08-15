use std::{fs, path::Path, process::Command};

use serde_json::Value;
use uuid::Uuid;

#[test]
fn local_check_process_is_deterministic_read_only_and_redacts_input_values() {
    let fixture = Fixture::new();
    fixture.write(
        ".github/workflows/check.yml",
        r"on:
  workflow_dispatch:
    inputs:
      token_hint:
        type: string
        required: true
jobs:
  check:
    runs-on: linux
    steps:
      - run: echo '${{ secrets.api_token }}' '${{ vars.region }}'
",
    );
    fixture.commit_all();
    fixture.write("dirty.txt", "uncommitted exact bytes\n");
    let status_before = fixture.git_stdout(&["status", "--porcelain=v2", "--untracked-files=all"]);
    let sensitive = "local-input-value-must-not-appear";
    let environment_marker = "local-environment-value-must-not-appear";

    let first = fixture.automata_with_hostile_service_environment(&[
        "local",
        "check",
        "--input",
        &format!("token_hint={sensitive}"),
        "--json",
    ]);
    let repeated = fixture.automata_with_hostile_service_environment(&[
        "local",
        "check",
        "--input",
        &format!("token_hint={sensitive}"),
        "--json",
    ]);

    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(repeated.status.success());
    assert_eq!(first.stdout, repeated.stdout);
    assert!(
        !first
            .stdout
            .windows(sensitive.len())
            .any(|window| window == sensitive.as_bytes())
    );
    assert!(!String::from_utf8_lossy(&first.stdout).contains(environment_marker));
    assert!(!String::from_utf8_lossy(&first.stderr).contains(environment_marker));
    assert!(
        !first
            .stderr
            .windows(sensitive.len())
            .any(|window| window == sensitive.as_bytes())
    );
    assert!(
        !first
            .stdout
            .windows(fixture.path().as_os_str().len())
            .any(|window| window == fixture.path().to_string_lossy().as_bytes())
    );
    let document: Value = serde_json::from_slice(&first.stdout).expect("one JSON document");
    assert_eq!(document["schema"], 1);
    assert_eq!(document["valid"], true);
    assert_eq!(document["source"]["dirty"], true);
    assert_eq!(document["required_root_secrets"][0], "API_TOKEN");
    assert_eq!(
        document["workflows"][0]["jobs"][0]["secrets"][0],
        "API_TOKEN"
    );
    assert_eq!(
        document["workflows"][0]["jobs"][0]["variables"][0],
        "REGION"
    );
    assert_eq!(
        fixture.git_stdout(&["status", "--porcelain=v2", "--untracked-files=all"]),
        status_before,
        "local check must not mutate Git or the worktree"
    );

    let human = fixture.automata_with_hostile_service_environment(&[
        "local",
        "check",
        "--input",
        &format!("token_hint={sensitive}"),
    ]);
    assert!(human.status.success());
    let human_stdout = String::from_utf8_lossy(&human.stdout);
    let human_stderr = String::from_utf8_lossy(&human.stderr);
    assert!(!human_stdout.contains(sensitive));
    assert!(!human_stderr.contains(sensitive));
    assert!(!human_stdout.contains(environment_marker));
    assert!(!human_stderr.contains(environment_marker));
    assert!(!human_stdout.contains(fixture.path().to_string_lossy().as_ref()));
}

#[test]
fn invalid_workflow_still_emits_one_value_free_json_report() {
    let fixture = Fixture::new();
    fixture.write(
        ".ci/workflows/check.yml",
        "on: push\njobs:\n  check:\n    runs-on: linux\n    steps:\n      - run: true\n",
    );
    fixture.commit_all();
    let output = fixture.automata(&["local", "check", "--json"]);

    assert!(!output.status.success());
    let document: Value = serde_json::from_slice(&output.stdout).expect("failure JSON document");
    assert_eq!(document["schema"], 1);
    assert_eq!(document["valid"], false);
    assert_eq!(document["issue"]["code"], "compilation");
    assert!(
        !String::from_utf8_lossy(&output.stderr)
            .contains(fixture.path().to_string_lossy().as_ref())
    );
}

struct Fixture {
    root: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "automata-local-check-process-{}",
            Uuid::new_v4().simple()
        ));
        fs::create_dir(&root).expect("create fixture");
        let fixture = Self { root };
        fixture.git(&["init", "--quiet"]);
        fixture.git(&["config", "user.name", "Automata Test"]);
        fixture.git(&["config", "user.email", "automata@example.invalid"]);
        fixture
    }

    fn path(&self) -> &Path {
        &self.root
    }

    fn write(&self, path: &str, value: &str) {
        let path = self.root.join(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create fixture parent");
        }
        fs::write(path, value).expect("write fixture");
    }

    fn commit_all(&self) {
        self.git(&["add", "--all"]);
        self.git(&["commit", "--quiet", "--message", "fixture"]);
    }

    fn git(&self, arguments: &[&str]) {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&self.root)
                .args(arguments)
                .status()
                .expect("run Git")
                .success()
        );
    }

    fn git_stdout(&self, arguments: &[&str]) -> Vec<u8> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(arguments)
            .output()
            .expect("run Git");
        assert!(output.status.success());
        output.stdout
    }

    fn automata(&self, arguments: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_automata"))
            .current_dir(&self.root)
            .args(arguments)
            .output()
            .expect("run automata")
    }

    fn automata_with_hostile_service_environment(
        &self,
        arguments: &[&str],
    ) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_automata"))
            .current_dir(&self.root)
            .args(arguments)
            .env("DOCKER_HOST", "tcp://127.0.0.1:1")
            .env("GITHUB_TOKEN", "local-environment-value-must-not-appear")
            .env("GH_TOKEN", "local-environment-value-must-not-appear")
            .env("HTTP_PROXY", "http://127.0.0.1:1")
            .env("HTTPS_PROXY", "http://127.0.0.1:1")
            .output()
            .expect("run service-independent local check")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
