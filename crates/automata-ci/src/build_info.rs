use serde::Serialize;

const SHA1_HEX_LENGTH: usize = 40;
const SHA256_HEX_LENGTH: usize = 64;

/// Immutable provenance embedded into this executable at build time.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct BuildInfo {
    /// Cargo package version embedded in the executable.
    pub version: &'static str,
    /// Source Git object identifier supplied by the trusted build boundary.
    pub commit: &'static str,
}

impl BuildInfo {
    /// Returns the version and source revision embedded in the current executable.
    pub const fn current() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION"),
            commit: env!("AUTOMATA_BUILD_GIT_SHA"),
        }
    }

    /// Reports whether the embedded revision has a full SHA-1 or SHA-256 Git object shape.
    ///
    /// This is a syntactic provenance check; it does not prove that the object is
    /// present in, or trusted by, any particular repository.
    pub fn has_verifiable_commit(self) -> bool {
        is_full_git_object_id(self.commit)
    }
}

/// Reports whether `value` is a full hexadecimal SHA-1 or SHA-256 Git object identifier.
pub fn is_full_git_object_id(value: &str) -> bool {
    matches!(value.len(), SHA1_HEX_LENGTH | SHA256_HEX_LENGTH)
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
