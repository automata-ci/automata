use serde::Serialize;

const SHA1_HEX_LENGTH: usize = 40;
const SHA256_HEX_LENGTH: usize = 64;

/// Immutable provenance embedded into this executable at build time.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct BuildInfo {
    pub version: &'static str,
    pub commit: &'static str,
}

impl BuildInfo {
    pub const fn current() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION"),
            commit: env!("AUTOMATA_BUILD_GIT_SHA"),
        }
    }

    pub fn has_verifiable_commit(self) -> bool {
        is_full_git_object_id(self.commit)
    }
}

pub fn is_full_git_object_id(value: &str) -> bool {
    matches!(value.len(), SHA1_HEX_LENGTH | SHA256_HEX_LENGTH)
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
