use std::{
    collections::BTreeSet,
    fmt::Write as _,
    path::{Path, PathBuf},
    process::Command,
};

use serde::Deserialize;

const MATRIX_JSON: &str = include_str!("fixtures/exact-client-matrix-v1.json");
const README: &str = include_str!("../README.md");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExactClientMatrix {
    schema: u16,
    node_major: u8,
    network_policy: String,
    clients: Vec<ExactClient>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExactClient {
    id: String,
    repository: String,
    release: String,
    commit: String,
    manifest_version: String,
    action_entries: Vec<String>,
    action_root_environment: String,
    embedded_package: String,
    embedded_version: String,
    embedded_integrity: String,
    module_entry: String,
    module_environment: String,
    operations: Vec<String>,
    support_status: String,
}

fn matrix() -> ExactClientMatrix {
    serde_json::from_str(MATRIX_JSON).expect("exact-client matrix must use its closed v1 schema")
}

fn is_lower_hex_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_safe_relative_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with(['/', '\\'])
        && !value.contains("..")
        && !value.contains('\\')
}

fn markdown_matrix(clients: &[ExactClient]) -> String {
    let mut table = String::from(
        "<!-- exact-client-matrix:start -->\n\
| Action | Release | Commit | Embedded client | Status |\n\
| --- | --- | --- | --- | --- |\n",
    );
    for client in clients {
        writeln!(
            table,
            "| `{}` | `{}` | `{}` | `{}` `{}` | `{}` |",
            client.repository,
            client.release,
            client.commit,
            client.embedded_package,
            client.embedded_version,
            client.support_status,
        )
        .expect("render exact-client matrix");
    }
    table.push_str("<!-- exact-client-matrix:end -->");
    table
}

#[test]
fn exact_client_matrix_is_closed_pinned_and_network_independent() {
    let matrix = matrix();
    assert_eq!(matrix.schema, 1);
    assert_eq!(matrix.node_major, 24);
    assert_eq!(matrix.network_policy, "loopback-only-no-downloads");
    assert_eq!(matrix.clients.len(), 3);

    let mut ids = BTreeSet::new();
    let mut repositories = BTreeSet::new();
    for client in &matrix.clients {
        assert!(ids.insert(client.id.as_str()), "duplicate client ID");
        assert!(
            repositories.insert(client.repository.as_str()),
            "duplicate repository"
        );
        assert!(client.release.starts_with('v'));
        assert!(is_lower_hex_sha(&client.commit));
        assert!(!client.manifest_version.is_empty());
        assert!(!client.action_entries.is_empty());
        let mut action_entries = BTreeSet::new();
        for action_entry in &client.action_entries {
            assert!(is_safe_relative_path(action_entry));
            assert!(
                action_entries.insert(action_entry),
                "duplicate action entry for {}",
                client.id
            );
        }
        assert!(is_safe_relative_path(&client.module_entry));
        assert!(client.action_root_environment.starts_with("AUTOMATA_TEST_"));
        assert!(client.module_environment.starts_with("AUTOMATA_TEST_"));
        assert!(client.embedded_package.starts_with("@actions/"));
        assert!(client.embedded_integrity.starts_with("sha512-"));
        assert!(!client.operations.is_empty());
        assert!(matches!(
            client.support_status.as_str(),
            "candidate" | "component" | "product-accepted"
        ));
    }

    assert_eq!(
        ids,
        BTreeSet::from(["cache", "download-artifact", "upload-artifact"])
    );
}

#[test]
fn documentation_matrix_is_rendered_from_the_exact_fixture() {
    let matrix = matrix();
    let expected = markdown_matrix(&matrix.clients);
    let readme = README.replace("\r\n", "\n");
    assert!(
        readme.contains(&expected),
        "README exact-client table must match tests/fixtures/exact-client-matrix-v1.json"
    );
}

fn canonical_child(root: &Path, relative: &str) -> PathBuf {
    let child = root
        .join(relative)
        .canonicalize()
        .expect("pinned action entry must exist");
    assert!(child.starts_with(root), "action entry escaped its root");
    child
}

fn git_output(root: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()
        .expect("run local git verification");
    assert!(output.status.success(), "local git verification failed");
    String::from_utf8(output.stdout)
        .expect("git verification output must be UTF-8")
        .trim()
        .to_owned()
}

#[test]
#[ignore = "requires the three offline action roots named by exact-client-matrix-v1.json"]
fn supplied_action_roots_match_every_immutable_client_pin() {
    let matrix = matrix();
    let node_version = Command::new("node")
        .arg("--version")
        .output()
        .expect("Node must be installed for exact-client acceptance");
    assert!(node_version.status.success());
    let node_version = String::from_utf8(node_version.stdout).expect("Node version is UTF-8");
    assert!(
        node_version.starts_with(&format!("v{}.", matrix.node_major)),
        "exact-client acceptance requires Node {}",
        matrix.node_major
    );

    for client in matrix.clients {
        let root = std::env::var_os(&client.action_root_environment)
            .map_or_else(
                || panic!("set {}", client.action_root_environment),
                PathBuf::from,
            )
            .canonicalize()
            .expect("canonical pinned action root");
        assert_eq!(git_output(&root, &["rev-parse", "HEAD"]), client.commit);
        assert_eq!(
            git_output(&root, &["status", "--short", "--untracked-files=no"]),
            "",
            "pinned action checkout contains tracked mutations"
        );

        let manifest: serde_json::Value = serde_json::from_slice(
            &std::fs::read(canonical_child(&root, "package.json"))
                .expect("read action package manifest"),
        )
        .expect("parse action package manifest");
        assert_eq!(manifest["name"], client.id);
        assert_eq!(manifest["version"], client.manifest_version);

        let lock: serde_json::Value = serde_json::from_slice(
            &std::fs::read(canonical_child(&root, "package-lock.json"))
                .expect("read action package lock"),
        )
        .expect("parse action package lock");
        assert_eq!(lock["lockfileVersion"], 3);
        let embedded_key = format!("node_modules/{}", client.embedded_package);
        let embedded = &lock["packages"][&embedded_key];
        assert_eq!(embedded["version"], client.embedded_version);
        assert_eq!(embedded["integrity"], client.embedded_integrity);

        for action_entry in &client.action_entries {
            assert!(
                canonical_child(&root, action_entry).is_file(),
                "pinned wrapper entry is missing for {}",
                client.id
            );
        }
        let module = canonical_child(&root, &client.module_entry);
        assert!(module.is_file());
        let configured_module = std::env::var_os(&client.module_environment)
            .map_or_else(
                || panic!("set {}", client.module_environment),
                PathBuf::from,
            )
            .canonicalize()
            .expect("canonical exact client module");
        assert_eq!(
            configured_module, module,
            "exact client module must come from the verified action root"
        );
    }
}
