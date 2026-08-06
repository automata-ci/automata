#![forbid(unsafe_code)]

#[path = "../build-support/git_provenance.rs"]
mod git_provenance;

fn main() {
    git_provenance::emit_build_commit();
}
