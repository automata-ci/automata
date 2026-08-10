#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Build-time provenance helpers for Automata product binaries.

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

const SHA1_HEX_LENGTH: usize = 40;
const SHA256_HEX_LENGTH: usize = 64;
const UNKNOWN_COMMIT: &str = "unknown";
const CARGO_VCS_INFO_FILE: &str = ".cargo_vcs_info.json";

#[derive(Debug, Eq, PartialEq)]
enum PackagedCommit {
    Absent,
    Clean(String),
    Dirty,
}

/// Emits Cargo directives that embed the current Git commit in a product binary.
///
/// Development builds outside a Git checkout use `unknown`. Packaged builds use
/// Cargo's clean `.cargo_vcs_info.json` provenance before consulting the ambient
/// Git checkout. Distribution builds must opt in with
/// `AUTOMATA_RELEASE_BUILD=1` and provide a trustworthy commit through an
/// explicit `AUTOMATA_BUILD_GIT_SHA`, clean Cargo package metadata, or a readable
/// committed `HEAD`.
///
/// # Panics
///
/// Panics when a provenance environment variable is malformed, when Git returns
/// a malformed object ID, or when a distribution build has no trustworthy commit
/// identity. Panicking is intentional here: continuing would produce a release
/// artifact with ambiguous or misleading provenance.
pub fn emit_build_commit() {
    println!("cargo:rerun-if-env-changed=AUTOMATA_BUILD_GIT_SHA");
    println!("cargo:rerun-if-env-changed=AUTOMATA_RELEASE_BUILD");
    println!("cargo:rerun-if-changed=build.rs");
    emit_git_rerun_paths();

    let commit = configured_commit().unwrap_or_else(|| {
        assert!(
            !release_provenance_required(),
            "a distribution build requires AUTOMATA_BUILD_GIT_SHA, clean Cargo package provenance, or a committed Git HEAD"
        );
        UNKNOWN_COMMIT.to_owned()
    });
    println!("cargo:rustc-env=AUTOMATA_BUILD_GIT_SHA={commit}");
}

fn release_provenance_required() -> bool {
    match env::var("AUTOMATA_RELEASE_BUILD") {
        Ok(value) if value == "1" || value.eq_ignore_ascii_case("true") => true,
        Ok(value) if value == "0" || value.eq_ignore_ascii_case("false") => false,
        Ok(_) => panic!("AUTOMATA_RELEASE_BUILD must be true, false, 1, or 0"),
        Err(env::VarError::NotPresent) => false,
        Err(env::VarError::NotUnicode(_)) => {
            panic!("AUTOMATA_RELEASE_BUILD must contain valid UTF-8")
        }
    }
}

fn configured_commit() -> Option<String> {
    match env::var("AUTOMATA_BUILD_GIT_SHA") {
        Ok(value) => Some(
            normalize_object_id(&value).unwrap_or_else(|| {
                panic!(
                    "AUTOMATA_BUILD_GIT_SHA must be a complete 40- or 64-character hexadecimal Git object ID"
                );
            }),
        ),
        Err(env::VarError::NotPresent) => match packaged_commit() {
            PackagedCommit::Clean(commit) => Some(commit),
            PackagedCommit::Dirty => None,
            PackagedCommit::Absent => git_commit(),
        },
        Err(env::VarError::NotUnicode(_)) => {
            panic!("AUTOMATA_BUILD_GIT_SHA must contain valid UTF-8")
        }
    }
}

fn packaged_commit() -> PackagedCommit {
    let manifest_directory = env::var_os("CARGO_MANIFEST_DIR").map_or_else(
        || panic!("Cargo did not provide CARGO_MANIFEST_DIR"),
        PathBuf::from,
    );
    let path = manifest_directory.join(CARGO_VCS_INFO_FILE);
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return PackagedCommit::Absent;
        }
        Err(error) => panic!("Cargo package provenance could not be read: {error}"),
    };
    parse_packaged_commit(&bytes)
}

fn parse_packaged_commit(bytes: &[u8]) -> PackagedCommit {
    let document: serde_json::Value = serde_json::from_slice(bytes)
        .unwrap_or_else(|_| panic!("Cargo package provenance is malformed"));
    let git = document
        .get("git")
        .and_then(serde_json::Value::as_object)
        .unwrap_or_else(|| panic!("Cargo package provenance has no Git identity"));
    let sha = git
        .get("sha1")
        .and_then(serde_json::Value::as_str)
        .and_then(normalize_object_id)
        .unwrap_or_else(|| panic!("Cargo package provenance has an invalid Git object ID"));
    let dirty = match git.get("dirty") {
        Some(value) => value
            .as_bool()
            .unwrap_or_else(|| panic!("Cargo package provenance has an invalid dirty marker")),
        None => false,
    };
    if dirty {
        PackagedCommit::Dirty
    } else {
        PackagedCommit::Clean(sha)
    }
}

fn git_commit() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--verify", "HEAD^{commit}"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let value = String::from_utf8(output.stdout).ok()?;
    Some(normalize_object_id(&value).unwrap_or_else(|| {
        panic!("git rev-parse returned an invalid full commit object ID");
    }))
}

fn normalize_object_id(value: &str) -> Option<String> {
    let value = value.trim();
    let has_valid_length = matches!(value.len(), SHA1_HEX_LENGTH | SHA256_HEX_LENGTH);
    (has_valid_length && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

fn emit_git_rerun_paths() {
    let Some(git_dir) = git_directory() else {
        return;
    };
    let common_dir = git_common_directory().unwrap_or_else(|| git_dir.clone());

    let head = git_dir.join("HEAD");
    println!("cargo:rerun-if-changed={}", head.display());
    let packed_refs = common_dir.join("packed-refs");
    if packed_refs.exists() {
        println!("cargo:rerun-if-changed={}", packed_refs.display());
    }

    if let Some(reference) = symbolic_head_reference(&head) {
        emit_reference_rerun_path(&common_dir, &common_dir.join(reference));
    }
}

fn git_directory() -> Option<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--absolute-git-dir"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let path = String::from_utf8(output.stdout).ok()?;
    Some(PathBuf::from(path.trim()))
}

fn git_common_directory() -> Option<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let path = String::from_utf8(output.stdout).ok()?;
    Some(PathBuf::from(path.trim()))
}

fn emit_reference_rerun_path(common_dir: &Path, reference: &Path) {
    let mut watched_path = reference;
    while !watched_path.exists() && watched_path != common_dir {
        let Some(parent) = watched_path.parent() else {
            return;
        };
        watched_path = parent;
    }
    println!("cargo:rerun-if-changed={}", watched_path.display());
}

fn symbolic_head_reference(head: &Path) -> Option<String> {
    let contents = fs::read_to_string(head).ok()?;
    contents.trim().strip_prefix("ref: ").map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMIT: &str = "26713A895EB6744012DA74726E59230A259357C4";

    #[test]
    fn clean_cargo_package_provenance_is_normalized() {
        let provenance = format!(
            r#"{{"git":{{"sha1":"{COMMIT}","dirty":false}},"path_in_vcs":"crates/automata-ci"}}"#
        );
        assert_eq!(
            parse_packaged_commit(provenance.as_bytes()),
            PackagedCommit::Clean(COMMIT.to_ascii_lowercase())
        );
    }

    #[test]
    fn dirty_cargo_package_provenance_is_not_attributed_to_head() {
        let provenance = format!(r#"{{"git":{{"sha1":"{COMMIT}","dirty":true}}}}"#);
        assert_eq!(
            parse_packaged_commit(provenance.as_bytes()),
            PackagedCommit::Dirty
        );
    }

    #[test]
    #[should_panic(expected = "invalid Git object ID")]
    fn malformed_cargo_package_commit_is_rejected() {
        let _ = parse_packaged_commit(br#"{"git":{"sha1":"not-a-commit"}}"#);
    }
}
