//! Immutable repository-action archives committed before runner scheduling.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use super::{ActionReference, JobContentReference};
use crate::Sha256Digest;

/// Schema version of the sealed Windows repository-action graph.
pub const WINDOWS_ACTION_GRAPH_SCHEMA_VERSION: u16 = 1;
/// Media type of one immutable gzip-compressed repository snapshot.
pub const WINDOWS_ACTION_ARCHIVE_MEDIA_TYPE: &str = "application/vnd.automata.action-archive+gzip";
/// Maximum distinct immutable action archives in one job graph.
pub const MAX_WINDOWS_ACTION_GRAPH_ARCHIVES: usize = 256;
/// Maximum aggregate compressed bytes fetched for one job graph.
pub const MAX_WINDOWS_ACTION_GRAPH_COMPRESSED_BYTES: u64 = 16 * 1024 * 1024;
/// Maximum aggregate expanded bytes across a complete job graph.
pub const MAX_WINDOWS_ACTION_GRAPH_EXPANDED_BYTES: u64 = 512 * 1024 * 1024;
/// Maximum aggregate regular files across a complete job graph.
pub const MAX_WINDOWS_ACTION_GRAPH_REGULAR_FILES: u64 = 20_000;
/// Maximum entries in one action archive.
pub const MAX_WINDOWS_ACTION_ARCHIVE_ENTRIES: u32 = 10_000;
/// Maximum regular-file bytes in one action archive.
pub const MAX_WINDOWS_ACTION_ARCHIVE_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum expanded bytes in one action archive.
pub const MAX_WINDOWS_ACTION_ARCHIVE_EXPANDED_BYTES: u64 = 256 * 1024 * 1024;
/// Maximum path depth below a repository archive root.
pub const MAX_WINDOWS_ACTION_ARCHIVE_DEPTH: u16 = 64;
/// Maximum encoded bytes in one archive member path.
pub const MAX_WINDOWS_ACTION_ARCHIVE_PATH_BYTES: u16 = 4_096;

const GRAPH_DOMAIN: &[u8] = b"automata.windows-action-graph.v1\0";
const POLICY_DOMAIN: &[u8] = b"automata.windows-action-archive-policy.v1\0";
const ACTION_KEY_DOMAIN: &[u8] = b"automata.repository-action-key.v1\0";

/// Expansion facts reproduced by pre-scheduling and broker validation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsActionArchiveFacts {
    entry_count: u32,
    regular_file_count: u32,
    expanded_bytes: u64,
    maximum_regular_file_bytes: u64,
    maximum_depth: u16,
}

impl WindowsActionArchiveFacts {
    /// Creates bounded archive expansion facts.
    ///
    /// # Errors
    ///
    /// Rejects empty or internally inconsistent facts and every value above
    /// the fixed Windows materialization policy.
    pub fn new(
        entry_count: u32,
        regular_file_count: u32,
        expanded_bytes: u64,
        maximum_regular_file_bytes: u64,
        maximum_depth: u16,
    ) -> Result<Self, WindowsActionGraphError> {
        if entry_count == 0
            || entry_count > MAX_WINDOWS_ACTION_ARCHIVE_ENTRIES
            || regular_file_count == 0
            || regular_file_count > entry_count
            || expanded_bytes == 0
            || expanded_bytes > MAX_WINDOWS_ACTION_ARCHIVE_EXPANDED_BYTES
            || maximum_regular_file_bytes == 0
            || maximum_regular_file_bytes > MAX_WINDOWS_ACTION_ARCHIVE_FILE_BYTES
            || maximum_regular_file_bytes > expanded_bytes
            || maximum_depth == 0
            || maximum_depth > MAX_WINDOWS_ACTION_ARCHIVE_DEPTH
        {
            return Err(WindowsActionGraphError::InvalidArchiveFacts);
        }
        Ok(Self {
            entry_count,
            regular_file_count,
            expanded_bytes,
            maximum_regular_file_bytes,
            maximum_depth,
        })
    }

    /// Returns the total tar-entry count.
    #[must_use]
    pub const fn entry_count(self) -> u32 {
        self.entry_count
    }

    /// Returns the regular-file count.
    #[must_use]
    pub const fn regular_file_count(self) -> u32 {
        self.regular_file_count
    }

    /// Returns the total declared expanded bytes.
    #[must_use]
    pub const fn expanded_bytes(self) -> u64 {
        self.expanded_bytes
    }

    /// Returns the largest declared regular file.
    #[must_use]
    pub const fn maximum_regular_file_bytes(self) -> u64 {
        self.maximum_regular_file_bytes
    }

    /// Returns the deepest materialized member below the archive root.
    #[must_use]
    pub const fn maximum_depth(self) -> u16 {
        self.maximum_depth
    }

    fn validate(self) -> Result<(), WindowsActionGraphError> {
        Self::new(
            self.entry_count,
            self.regular_file_count,
            self.expanded_bytes,
            self.maximum_regular_file_bytes,
            self.maximum_depth,
        )
        .map(|_| ())
    }
}

/// One immutable repository archive in first-discovery graph order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsRepositoryActionArchive {
    ordinal: u32,
    action_key_sha256: Sha256Digest,
    subpath: String,
    archive: JobContentReference,
    facts: WindowsActionArchiveFacts,
}

impl WindowsRepositoryActionArchive {
    /// Creates one pre-scheduling archive descriptor.
    ///
    /// # Errors
    ///
    /// Rejects placeholder identity, unsafe/noncanonical subpaths, invalid
    /// content references, or facts outside the fixed archive policy.
    pub fn new(
        ordinal: u32,
        action_key_sha256: Sha256Digest,
        subpath: impl Into<String>,
        archive: JobContentReference,
        facts: WindowsActionArchiveFacts,
    ) -> Result<Self, WindowsActionGraphError> {
        let value = Self {
            ordinal,
            action_key_sha256,
            subpath: subpath.into(),
            archive,
            facts,
        };
        value.validate()?;
        Ok(value)
    }

    /// Returns the contiguous zero-based graph ordinal.
    #[must_use]
    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    /// Returns the digest of the canonical repository action key.
    #[must_use]
    pub const fn action_key_sha256(&self) -> Sha256Digest {
        self.action_key_sha256
    }

    /// Returns the canonical forward-slash action subpath, or empty root.
    #[must_use]
    pub fn subpath(&self) -> &str {
        &self.subpath
    }

    /// Returns the immutable archive content reference.
    #[must_use]
    pub const fn archive(&self) -> &JobContentReference {
        &self.archive
    }

    /// Returns the expansion facts the broker must reproduce exactly.
    #[must_use]
    pub const fn facts(&self) -> WindowsActionArchiveFacts {
        self.facts
    }

    fn validate(&self) -> Result<(), WindowsActionGraphError> {
        if zero_digest(self.action_key_sha256)
            || !valid_subpath(&self.subpath)
            || !valid_archive_reference(&self.archive)
        {
            return Err(WindowsActionGraphError::InvalidArchive);
        }
        self.facts.validate()
    }
}

/// Complete immutable action graph committed into `JobIR` before scheduling.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsRepositoryActionGraph {
    schema_version: u16,
    policy_sha256: Sha256Digest,
    graph_sha256: Sha256Digest,
    archives: Vec<WindowsRepositoryActionArchive>,
}

impl WindowsRepositoryActionGraph {
    /// Creates and hashes a complete first-discovery-ordered graph.
    ///
    /// # Errors
    ///
    /// Rejects empty/oversized graphs, noncontiguous ordinals, duplicate action
    /// identities, or aggregate compressed/expanded/file limits.
    pub fn new(
        archives: Vec<WindowsRepositoryActionArchive>,
    ) -> Result<Self, WindowsActionGraphError> {
        let mut value = Self {
            schema_version: WINDOWS_ACTION_GRAPH_SCHEMA_VERSION,
            policy_sha256: windows_action_archive_policy_sha256(),
            graph_sha256: Sha256Digest::from_bytes([0; 32]),
            archives,
        };
        value.graph_sha256 = graph_digest(&value.archives);
        value.validate()?;
        Ok(value)
    }

    /// Returns the exact graph schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the digest of every fixed archive and graph bound.
    #[must_use]
    pub const fn policy_sha256(&self) -> Sha256Digest {
        self.policy_sha256
    }

    /// Returns the canonical complete graph digest.
    #[must_use]
    pub const fn graph_sha256(&self) -> Sha256Digest {
        self.graph_sha256
    }

    /// Returns archives in exact first-discovery order.
    #[must_use]
    pub fn archives(&self) -> &[WindowsRepositoryActionArchive] {
        &self.archives
    }

    /// Revalidates a deserialized graph at the `JobIR` boundary.
    ///
    /// # Errors
    ///
    /// Returns an error for any malformed field, aggregate limit, policy
    /// mismatch, or graph-digest mismatch.
    pub fn validate(&self) -> Result<(), WindowsActionGraphError> {
        if self.schema_version != WINDOWS_ACTION_GRAPH_SCHEMA_VERSION
            || self.policy_sha256 != windows_action_archive_policy_sha256()
            || self.graph_sha256 != graph_digest(&self.archives)
            || self.archives.is_empty()
            || self.archives.len() > MAX_WINDOWS_ACTION_GRAPH_ARCHIVES
        {
            return Err(WindowsActionGraphError::InvalidGraph);
        }
        let mut identities = BTreeSet::new();
        let mut compressed = 0_u64;
        let mut expanded = 0_u64;
        let mut regular_files = 0_u64;
        for (index, archive) in self.archives.iter().enumerate() {
            archive.validate()?;
            if usize::try_from(archive.ordinal) != Ok(index)
                || !identities.insert(archive.action_key_sha256)
            {
                return Err(WindowsActionGraphError::InvalidGraph);
            }
            compressed = compressed
                .checked_add(archive.archive.encoded_size())
                .ok_or(WindowsActionGraphError::ResourceLimit)?;
            expanded = expanded
                .checked_add(archive.facts.expanded_bytes)
                .ok_or(WindowsActionGraphError::ResourceLimit)?;
            regular_files = regular_files
                .checked_add(u64::from(archive.facts.regular_file_count))
                .ok_or(WindowsActionGraphError::ResourceLimit)?;
        }
        if compressed > MAX_WINDOWS_ACTION_GRAPH_COMPRESSED_BYTES
            || expanded > MAX_WINDOWS_ACTION_GRAPH_EXPANDED_BYTES
            || regular_files > MAX_WINDOWS_ACTION_GRAPH_REGULAR_FILES
        {
            return Err(WindowsActionGraphError::ResourceLimit);
        }
        Ok(())
    }
}

/// Returns the exact fixed archive/graph expansion-policy digest.
#[must_use]
pub fn windows_action_archive_policy_sha256() -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(POLICY_DOMAIN);
    digest.update(
        u64::try_from(MAX_WINDOWS_ACTION_GRAPH_ARCHIVES)
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    digest.update(MAX_WINDOWS_ACTION_GRAPH_COMPRESSED_BYTES.to_be_bytes());
    digest.update(MAX_WINDOWS_ACTION_GRAPH_EXPANDED_BYTES.to_be_bytes());
    digest.update(MAX_WINDOWS_ACTION_GRAPH_REGULAR_FILES.to_be_bytes());
    digest.update(MAX_WINDOWS_ACTION_ARCHIVE_ENTRIES.to_be_bytes());
    digest.update(MAX_WINDOWS_ACTION_ARCHIVE_FILE_BYTES.to_be_bytes());
    digest.update(MAX_WINDOWS_ACTION_ARCHIVE_EXPANDED_BYTES.to_be_bytes());
    digest.update(MAX_WINDOWS_ACTION_ARCHIVE_DEPTH.to_be_bytes());
    digest.update(MAX_WINDOWS_ACTION_ARCHIVE_PATH_BYTES.to_be_bytes());
    Sha256Digest::from_bytes(digest.finalize().into())
}

/// Returns the canonical identity of one immutable repository action.
///
/// # Errors
///
/// Rejects non-repository references, mutable revisions, control bytes, or a
/// Windows-ambiguous/noncanonical action subpath.
pub fn windows_repository_action_key_sha256(
    reference: &ActionReference,
) -> Result<Sha256Digest, WindowsActionGraphError> {
    let ActionReference::Repository {
        repository,
        revision,
        subpath,
    } = reference
    else {
        return Err(WindowsActionGraphError::InvalidArchive);
    };
    let subpath = subpath.as_deref().unwrap_or_default();
    if repository.is_empty()
        || repository.len() > 1_024
        || repository.chars().any(char::is_control)
        || revision.len() != 40
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        || !valid_subpath(subpath)
    {
        return Err(WindowsActionGraphError::InvalidArchive);
    }
    let mut digest = Sha256::new();
    digest.update(ACTION_KEY_DOMAIN);
    update_string(&mut digest, repository);
    update_string(&mut digest, revision);
    update_string(&mut digest, subpath);
    Ok(Sha256Digest::from_bytes(digest.finalize().into()))
}

/// Fail-closed action-graph validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WindowsActionGraphError {
    /// One archive expansion report is invalid or inconsistent.
    #[error("invalid Windows action archive facts")]
    InvalidArchiveFacts,
    /// One archive descriptor or path is invalid.
    #[error("invalid Windows action archive descriptor")]
    InvalidArchive,
    /// The graph schema, policy, order, identity set, or digest is invalid.
    #[error("invalid Windows action graph")]
    InvalidGraph,
    /// Aggregate graph resources exceed the fixed broker contract.
    #[error("Windows action graph resource limit exceeded")]
    ResourceLimit,
}

fn graph_digest(archives: &[WindowsRepositoryActionArchive]) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(GRAPH_DOMAIN);
    digest.update(windows_action_archive_policy_sha256().as_bytes());
    digest.update(
        u64::try_from(archives.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for archive in archives {
        digest.update(archive.ordinal.to_be_bytes());
        digest.update(archive.action_key_sha256.as_bytes());
        update_string(&mut digest, &archive.subpath);
        update_string(&mut digest, archive.archive.object_key());
        digest.update(archive.archive.digest().as_bytes());
        digest.update(archive.archive.encoded_size().to_be_bytes());
        update_string(&mut digest, archive.archive.media_type());
        digest.update(archive.facts.entry_count.to_be_bytes());
        digest.update(archive.facts.regular_file_count.to_be_bytes());
        digest.update(archive.facts.expanded_bytes.to_be_bytes());
        digest.update(archive.facts.maximum_regular_file_bytes.to_be_bytes());
        digest.update(archive.facts.maximum_depth.to_be_bytes());
    }
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn update_string(digest: &mut Sha256, value: &str) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
}

fn valid_archive_reference(reference: &JobContentReference) -> bool {
    let key = reference.object_key();
    !key.is_empty()
        && key.len() <= 1_024
        && !key.starts_with('/')
        && !key.contains('\\')
        && !key.chars().any(char::is_control)
        && key
            .split('/')
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
        && !zero_digest(reference.digest())
        && (1..=MAX_WINDOWS_ACTION_GRAPH_COMPRESSED_BYTES).contains(&reference.encoded_size())
        && reference.media_type() == WINDOWS_ACTION_ARCHIVE_MEDIA_TYPE
}

fn valid_subpath(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    if value.len() > usize::from(MAX_WINDOWS_ACTION_ARCHIVE_PATH_BYTES)
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\\')
        || value.chars().any(char::is_control)
    {
        return false;
    }
    value.split('/').all(valid_windows_action_path_component)
}

/// Returns whether one Windows action-path component has one unambiguous
/// filesystem identity under the sealed action archive policy.
///
/// This deliberately rejects DOS device names, 8.3 aliases, alternate-stream
/// syntax, path separators, controls, and trailing-dot/space aliases. Callers
/// remain responsible for splitting and bounding the complete path.
#[must_use]
pub fn valid_windows_action_path_component(component: &str) -> bool {
    if component.is_empty()
        || matches!(component, "." | "..")
        || !component.is_ascii()
        || component.ends_with([' ', '.'])
        || component.bytes().any(|byte| {
            byte.is_ascii_control()
                || matches!(
                    byte,
                    b'/' | b'\\' | b'<' | b'>' | b':' | b'"' | b'|' | b'?' | b'*'
                )
        })
    {
        return false;
    }
    if component.starts_with('.') {
        return true;
    }
    let stem = component
        .split('.')
        .next()
        .unwrap_or(component)
        .trim_end_matches([' ', '.']);
    if stem.is_empty() {
        return false;
    }
    if short_name_shaped(stem) {
        return false;
    }
    let upper = stem.to_ascii_uppercase();
    !matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    ) && !upper
        .strip_prefix("COM")
        .or_else(|| upper.strip_prefix("LPT"))
        .is_some_and(|suffix| suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9'))
}

fn short_name_shaped(stem: &str) -> bool {
    let Some((prefix, digits)) = stem.rsplit_once('~') else {
        return false;
    };
    !prefix.is_empty()
        && prefix.len() <= 6
        && !digits.is_empty()
        && matches!(digits.as_bytes()[0], b'1'..=b'9')
        && digits.bytes().skip(1).all(|byte| byte.is_ascii_digit())
}

fn zero_digest(digest: Sha256Digest) -> bool {
    digest.as_bytes().iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use super::valid_windows_action_path_component;

    #[test]
    fn windows_action_components_reject_every_namespace_alias() {
        for component in [
            "CON",
            "con.txt",
            "CON .txt",
            "CONIN$.js",
            "conout$.JS",
            "COM1.log",
            "lpt9",
            "LONGFI~1.JS",
            "A~999.txt",
            "name:stream",
            "trailing.",
            "trailing ",
            ".",
            "..",
            "nested/path",
            r"nested\path",
            "control\u{1f}.js",
            "naïve.js",
        ] {
            assert!(
                !valid_windows_action_path_component(component),
                "unexpectedly accepted {component:?}"
            );
        }

        for component in [
            "dist",
            "index.js",
            ".github",
            ".gitignore",
            "long-file-name.js",
            "COM10.txt",
            "LPT0.txt",
        ] {
            assert!(
                valid_windows_action_path_component(component),
                "unexpectedly rejected {component:?}"
            );
        }
    }
}
