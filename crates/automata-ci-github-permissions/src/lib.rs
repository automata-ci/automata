//! Closed, versioned GitHub Actions workflow permission catalog.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use serde::Serialize;
use sha2::{Digest as _, Sha256};

/// Current schema of the canonical catalog representation.
pub const GITHUB_WORKFLOW_PERMISSION_CATALOG_SCHEMA: u16 = 1;
/// Monotonic reviewed catalog revision.
pub const GITHUB_WORKFLOW_PERMISSION_CATALOG_REVISION: u64 = 1;
/// Official source reviewed for the current catalog revision.
pub const GITHUB_WORKFLOW_PERMISSION_CATALOG_SOURCE: &str = "https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions";

/// One permission name and the non-denied levels accepted by workflow syntax.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GithubWorkflowPermission {
    name: &'static str,
    read: bool,
    write: bool,
}

impl GithubWorkflowPermission {
    const fn new(name: &'static str, read: bool, write: bool) -> Self {
        Self { name, read, write }
    }

    /// Returns the exact workflow permission name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Returns whether the permission accepts `read`.
    #[must_use]
    pub const fn allows_read(self) -> bool {
        self.read
    }

    /// Returns whether the permission accepts `write`.
    #[must_use]
    pub const fn allows_write(self) -> bool {
        self.write
    }
}

/// Current closed GitHub Actions workflow permission catalog, sorted by name.
pub const GITHUB_WORKFLOW_PERMISSIONS: &[GithubWorkflowPermission] = &[
    GithubWorkflowPermission::new("actions", true, true),
    GithubWorkflowPermission::new("artifact-metadata", true, true),
    GithubWorkflowPermission::new("attestations", true, true),
    GithubWorkflowPermission::new("checks", true, true),
    GithubWorkflowPermission::new("code-quality", true, true),
    GithubWorkflowPermission::new("contents", true, true),
    GithubWorkflowPermission::new("deployments", true, true),
    GithubWorkflowPermission::new("discussions", true, true),
    GithubWorkflowPermission::new("id-token", false, true),
    GithubWorkflowPermission::new("issues", true, true),
    GithubWorkflowPermission::new("models", true, false),
    GithubWorkflowPermission::new("packages", true, true),
    GithubWorkflowPermission::new("pages", true, true),
    GithubWorkflowPermission::new("pull-requests", true, true),
    GithubWorkflowPermission::new("security-events", true, true),
    GithubWorkflowPermission::new("statuses", true, true),
    GithubWorkflowPermission::new("vulnerability-alerts", true, false),
];

/// Finds one exact permission definition in the current closed catalog.
#[must_use]
pub fn github_workflow_permission(name: &str) -> Option<GithubWorkflowPermission> {
    GITHUB_WORKFLOW_PERMISSIONS
        .binary_search_by_key(&name, |permission| permission.name)
        .ok()
        .map(|index| GITHUB_WORKFLOW_PERMISSIONS[index])
}

/// Returns the canonical JSON bytes for the current catalog.
///
/// The representation is generated from a statically bounded value containing
/// only primitive fields and therefore cannot fail serialization.
#[must_use]
pub fn github_workflow_permission_catalog_bytes() -> Vec<u8> {
    serde_json_infallible(&CanonicalCatalog {
        schema: GITHUB_WORKFLOW_PERMISSION_CATALOG_SCHEMA,
        revision: GITHUB_WORKFLOW_PERMISSION_CATALOG_REVISION,
        source: GITHUB_WORKFLOW_PERMISSION_CATALOG_SOURCE,
        permissions: GITHUB_WORKFLOW_PERMISSIONS,
    })
}

/// Returns SHA-256 over the exact canonical catalog bytes.
#[must_use]
pub fn github_workflow_permission_catalog_sha256() -> [u8; 32] {
    Sha256::digest(github_workflow_permission_catalog_bytes()).into()
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalCatalog<'a> {
    schema: u16,
    revision: u64,
    source: &'static str,
    permissions: &'a [GithubWorkflowPermission],
}

fn serde_json_infallible(value: &CanonicalCatalog<'_>) -> Vec<u8> {
    // Serialization of this closed primitive-only structure has no data-dependent
    // failure path. Keep the invariant local instead of exposing serde as API.
    serde_json::to_vec(value).expect("closed primitive catalog must serialize")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_sorted_unique_and_has_exact_exception_levels() {
        assert!(
            GITHUB_WORKFLOW_PERMISSIONS
                .windows(2)
                .all(|pair| pair[0].name() < pair[1].name())
        );
        assert_eq!(GITHUB_WORKFLOW_PERMISSIONS.len(), 17);

        let id_token = github_workflow_permission("id-token").expect("id-token");
        assert!(!id_token.allows_read());
        assert!(id_token.allows_write());

        let alerts =
            github_workflow_permission("vulnerability-alerts").expect("vulnerability alerts");
        assert!(alerts.allows_read());
        assert!(!alerts.allows_write());

        let models = github_workflow_permission("models").expect("models");
        assert!(models.allows_read());
        assert!(!models.allows_write());
    }

    #[test]
    fn canonical_bytes_bind_schema_revision_source_and_every_permission() {
        let encoded = github_workflow_permission_catalog_bytes();
        let value: serde_json::Value = serde_json::from_slice(&encoded).expect("catalog JSON");
        assert_eq!(value["schema"], GITHUB_WORKFLOW_PERMISSION_CATALOG_SCHEMA);
        assert_eq!(
            value["revision"],
            GITHUB_WORKFLOW_PERMISSION_CATALOG_REVISION
        );
        assert_eq!(value["source"], GITHUB_WORKFLOW_PERMISSION_CATALOG_SOURCE);
        assert_eq!(
            value["permissions"].as_array().map(Vec::len),
            Some(GITHUB_WORKFLOW_PERMISSIONS.len())
        );
        assert_eq!(
            github_workflow_permission_catalog_sha256(),
            [
                0xc6, 0xdf, 0x0d, 0xed, 0xf0, 0x7f, 0x24, 0x82, 0xbc, 0x19, 0x3f, 0x2c, 0xb4, 0xfd,
                0x46, 0xcd, 0x7b, 0x5d, 0xd9, 0xe7, 0x8c, 0xd9, 0x14, 0x86, 0x04, 0x0b, 0xa0, 0x9f,
                0xce, 0x1a, 0x48, 0x5e,
            ]
        );
    }
}
