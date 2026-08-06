use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

const SHA1_HEX_LENGTH: usize = 40;
const SHA256_HEX_LENGTH: usize = 64;
const UNKNOWN_COMMIT: &str = "unknown";

pub fn emit_build_commit() {
    println!("cargo:rerun-if-env-changed=AUTOMATA_BUILD_GIT_SHA");
    println!("cargo:rerun-if-env-changed=AUTOMATA_RELEASE_BUILD");
    println!("cargo:rerun-if-changed=../build-support/git_provenance.rs");
    emit_git_rerun_paths();

    let commit = configured_commit().unwrap_or_else(|| {
        assert!(
            !release_provenance_required(),
            "a distribution build requires AUTOMATA_BUILD_GIT_SHA or a committed Git HEAD"
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
        Err(env::VarError::NotPresent) => git_commit(),
        Err(env::VarError::NotUnicode(_)) => {
            panic!("AUTOMATA_BUILD_GIT_SHA must contain valid UTF-8")
        }
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
