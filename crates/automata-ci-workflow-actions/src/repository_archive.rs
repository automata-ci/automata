use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, VecDeque},
    error::Error,
    fmt,
    io::{self, Cursor, Read as _},
    rc::Rc,
};

use flate2::read::MultiGzDecoder;

use crate::repository_path::PortablePathKey;
use crate::{RepositoryPathValidationError, RepositoryPathValidator};

const TAR_BLOCK_BYTES: usize = 512;
const TAR_BLOCK_BYTES_U64: u64 = 512;
const MAX_COMPRESSED_BYTES: u64 = 4_294_967_296;
const MAX_DECOMPRESSED_BYTES: u64 = 17_179_869_184;
const MAX_ENTRY_COUNT: usize = 1_000_000;
const MAX_EXPANDED_BYTES: u64 = 17_179_869_184;
const MAX_ENTRY_PATH_BYTES: usize = 16_384;
const MAX_WORKFLOW_COUNT: usize = 1_024;
const MAX_WORKFLOW_BYTES: u64 = 16_777_216;
const MAX_GLOBAL_PAX_BYTES: u64 = 65_536;
// Each link gets an independent bound; archive ordering never consumes budget
// needed by a later valid link.
const MAX_SYMLINK_RESOLUTION_HOPS: usize = 256;
const MAX_PATH_GRAPH_NODES: usize = 1_000_000;
const MAX_PATH_GRAPH_COMPONENT_BYTES: usize = 64 * 1_024 * 1_024;
const PATH_GRAPH_NODES_PER_ENTRY: usize = 4;
const PATH_GRAPH_BYTES_PER_SOURCE_BYTE: usize = 4;
const PORTABLE_USTAR_PATH_BYTES: usize = 256;
const OBSERVED_STREAM_TAIL_BYTES: usize = 2 * 1_024;

use crate::MAX_GITHUB_WORKFLOW_SOURCE_BYTES;

/// Maximum byte length of a workflow path returned by repository discovery.
///
/// This must remain exactly aligned with the durable provider-delivery
/// workflow-outcome path bound. It is defined here as well because this
/// source-level frontend must not depend on the persistence crate.
pub const MAX_REPOSITORY_WORKFLOW_PATH_BYTES: usize = 1_024;

/// One explicit repository namespace from which direct workflow files may be
/// discovered.
///
/// Callers choose the namespace from their source-authority policy. Discovery
/// never falls back to the other namespace, and the presence of the other
/// workflow authority fails closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryWorkflowLocation {
    /// Automata-owned workflows under `.ci/workflows`.
    Automata,
    /// GitHub Actions workflows under `.github/workflows`.
    Github,
}

impl RepositoryWorkflowLocation {
    const fn directory(self) -> &'static str {
        match self {
            Self::Automata => ".ci",
            Self::Github => ".github",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RepositoryWorkflowDiscoveryPolicy {
    GithubDelivery,
    LocalGithubArchive,
}

impl RepositoryWorkflowDiscoveryPolicy {
    const fn workflow_location(self) -> RepositoryWorkflowLocation {
        match self {
            Self::GithubDelivery => RepositoryWorkflowLocation::Automata,
            Self::LocalGithubArchive => RepositoryWorkflowLocation::Github,
        }
    }

    const fn allows_symlinks(self) -> bool {
        matches!(self, Self::LocalGithubArchive)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RepositoryArchiveLimitRejection {
    CompressedBytes,
    DecompressedBytes,
    EntryCount,
    ExpandedBytes,
    EntryPathBytes,
    WorkflowCount,
    WorkflowBytes,
    GlobalPaxBytes,
    WorkflowPathBytes,
}

const fn archive_policy_limit_rejection(
    compressed_bytes: u64,
    decompressed_bytes: u64,
    entries: usize,
    expanded_bytes: u64,
    entry_path_bytes: usize,
    workflows: usize,
    workflow_bytes: u64,
) -> Option<RepositoryArchiveLimitRejection> {
    if compressed_bytes > MAX_COMPRESSED_BYTES {
        return Some(RepositoryArchiveLimitRejection::CompressedBytes);
    }
    if decompressed_bytes > MAX_DECOMPRESSED_BYTES {
        return Some(RepositoryArchiveLimitRejection::DecompressedBytes);
    }
    if entries > MAX_ENTRY_COUNT {
        return Some(RepositoryArchiveLimitRejection::EntryCount);
    }
    if expanded_bytes > MAX_EXPANDED_BYTES {
        return Some(RepositoryArchiveLimitRejection::ExpandedBytes);
    }
    if entry_path_bytes > MAX_ENTRY_PATH_BYTES {
        return Some(RepositoryArchiveLimitRejection::EntryPathBytes);
    }
    if workflows > MAX_WORKFLOW_COUNT {
        return Some(RepositoryArchiveLimitRejection::WorkflowCount);
    }
    if workflow_bytes > MAX_WORKFLOW_BYTES {
        return Some(RepositoryArchiveLimitRejection::WorkflowBytes);
    }
    None
}

const fn global_pax_byte_rejection(observed: u64) -> Option<RepositoryArchiveLimitRejection> {
    if observed > MAX_GLOBAL_PAX_BYTES {
        return Some(RepositoryArchiveLimitRejection::GlobalPaxBytes);
    }
    None
}

const fn repository_workflow_path_byte_rejection(
    observed: usize,
) -> Option<RepositoryArchiveLimitRejection> {
    if observed > MAX_REPOSITORY_WORKFLOW_PATH_BYTES {
        return Some(RepositoryArchiveLimitRejection::WorkflowPathBytes);
    }
    None
}

/// Independent resource ceilings for repository workflow discovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepositoryWorkflowDiscoveryLimits {
    compressed_bytes: u64,
    decompressed_bytes: u64,
    entries: usize,
    expanded_bytes: u64,
    entry_path_bytes: usize,
    workflows: usize,
    workflow_bytes: u64,
}

impl RepositoryWorkflowDiscoveryLimits {
    /// Creates a bounded repository-archive policy.
    ///
    /// # Errors
    ///
    /// Rejects zero, inconsistent, or unreasonably large limits.
    pub const fn new(
        maximum_compressed_bytes: u64,
        maximum_decompressed_bytes: u64,
        maximum_entries: usize,
        maximum_expanded_bytes: u64,
        maximum_entry_path_bytes: usize,
        maximum_workflows: usize,
        maximum_workflow_bytes: u64,
    ) -> Result<Self, RepositoryWorkflowDiscoveryLimitsError> {
        if maximum_compressed_bytes == 0
            || maximum_decompressed_bytes == 0
            || maximum_entries == 0
            || maximum_expanded_bytes == 0
            || maximum_entry_path_bytes == 0
            || maximum_workflows == 0
            || maximum_workflow_bytes == 0
            || maximum_workflow_bytes > maximum_expanded_bytes
            || archive_policy_limit_rejection(
                maximum_compressed_bytes,
                maximum_decompressed_bytes,
                maximum_entries,
                maximum_expanded_bytes,
                maximum_entry_path_bytes,
                maximum_workflows,
                maximum_workflow_bytes,
            )
            .is_some()
        {
            return Err(RepositoryWorkflowDiscoveryLimitsError);
        }
        Ok(Self {
            compressed_bytes: maximum_compressed_bytes,
            decompressed_bytes: maximum_decompressed_bytes,
            entries: maximum_entries,
            expanded_bytes: maximum_expanded_bytes,
            entry_path_bytes: maximum_entry_path_bytes,
            workflows: maximum_workflows,
            workflow_bytes: maximum_workflow_bytes,
        })
    }

    #[must_use]
    /// Returns the maximum accepted compressed archive byte length.
    pub const fn maximum_compressed_bytes(self) -> u64 {
        self.compressed_bytes
    }

    #[must_use]
    /// Returns the maximum number of bytes produced by gzip decoding.
    pub const fn maximum_decompressed_bytes(self) -> u64 {
        self.decompressed_bytes
    }

    #[must_use]
    /// Returns the maximum number of tar entries inspected.
    pub const fn maximum_entries(self) -> usize {
        self.entries
    }

    #[must_use]
    /// Returns the maximum sum of declared tar entry sizes.
    pub const fn maximum_expanded_bytes(self) -> u64 {
        self.expanded_bytes
    }

    #[must_use]
    /// Returns the maximum byte length of any archive entry path.
    pub const fn maximum_entry_path_bytes(self) -> usize {
        self.entry_path_bytes
    }

    #[must_use]
    /// Returns the maximum number of direct workflow files discovered.
    pub const fn maximum_workflows(self) -> usize {
        self.workflows
    }

    #[must_use]
    /// Returns the maximum accepted byte length of one workflow file.
    pub const fn maximum_workflow_bytes(self) -> u64 {
        self.workflow_bytes
    }

    /// Returns the maximum number of derived component-trie nodes admitted
    /// while validating archive and local path graphs.
    #[must_use]
    pub const fn maximum_path_graph_nodes(self) -> usize {
        match self.entries.checked_mul(PATH_GRAPH_NODES_PER_ENTRY) {
            Some(value) if value < MAX_PATH_GRAPH_NODES => value,
            _ => MAX_PATH_GRAPH_NODES,
        }
    }

    /// Returns the maximum cumulative bytes retained by derived component
    /// spellings and portable identity keys.
    #[must_use]
    pub const fn maximum_path_graph_component_bytes(self) -> usize {
        let path_bytes = if self.entry_path_bytes < PORTABLE_USTAR_PATH_BYTES {
            self.entry_path_bytes
        } else {
            PORTABLE_USTAR_PATH_BYTES
        };
        let Some(source_bytes) = self.entries.checked_mul(path_bytes) else {
            return MAX_PATH_GRAPH_COMPONENT_BYTES;
        };
        match source_bytes.checked_mul(PATH_GRAPH_BYTES_PER_SOURCE_BYTE) {
            Some(value) if value < MAX_PATH_GRAPH_COMPONENT_BYTES => value,
            _ => MAX_PATH_GRAPH_COMPONENT_BYTES,
        }
    }
}

impl Default for RepositoryWorkflowDiscoveryLimits {
    fn default() -> Self {
        Self {
            compressed_bytes: 256 * 1_024 * 1_024,
            decompressed_bytes: 2 * 1_024 * 1_024 * 1_024,
            entries: 100_000,
            expanded_bytes: 1024 * 1_024 * 1_024,
            entry_path_bytes: 4 * 1_024,
            workflows: 256,
            workflow_bytes: MAX_GITHUB_WORKFLOW_SOURCE_BYTES as u64,
        }
    }
}

/// One deterministic, path-local workflow discovery failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RepositoryWorkflowDiscoveryFailure {
    /// The workflow file contains no bytes.
    Empty,
    /// The workflow file exceeds the configured per-workflow byte ceiling.
    Oversized,
}

impl fmt::Display for RepositoryWorkflowDiscoveryFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "repository workflow is empty",
            Self::Oversized => "repository workflow exceeds its byte limit",
        })
    }
}

impl Error for RepositoryWorkflowDiscoveryFailure {}

/// One exact path outcome selected from an immutable repository archive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryWorkflowDiscoveryOutcome {
    path: String,
    result: Result<Vec<u8>, RepositoryWorkflowDiscoveryFailure>,
}

impl RepositoryWorkflowDiscoveryOutcome {
    /// Returns the canonical repository-relative workflow path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the exact accepted bytes or the closed path-local failure.
    ///
    /// Archive-wide integrity and resource failures are returned by
    /// [`discover_github_delivery_workflows`] instead of appearing here.
    ///
    /// # Errors
    ///
    /// Returns the deterministic reason this individual workflow file was
    /// rejected.
    pub fn result(&self) -> Result<&[u8], RepositoryWorkflowDiscoveryFailure> {
        self.result.as_deref().map_err(|failure| *failure)
    }

    /// Consumes the path outcome into its canonical path and result.
    pub fn into_parts(self) -> (String, Result<Vec<u8>, RepositoryWorkflowDiscoveryFailure>) {
        (self.path, self.result)
    }
}

/// Validates one authenticated GitHub-delivery archive and discovers direct
/// Automata workflow files.
///
/// The archive is never extracted. It must contain one explicit, safe root
/// directory and only canonical paths beneath that root. Every entry and all
/// trailing tar/gzip data are consumed before any workflows are returned.
/// Results are ordered by canonical repository-relative path. Empty and
/// individually oversized regular workflow files are returned as path-local
/// failures, allowing valid sibling workflows to proceed.
///
/// # Errors
///
/// Returns a fail-closed error for a non-tar.gz or malformed archive; unsafe,
/// aliased, duplicate, or type-conflicting paths; a prohibited or unsafe link;
/// unsupported archive metadata; a non-regular workflow entry; a workflow
/// namespace that conflicts with `policy`; or archive-wide resource exhaustion.
pub fn discover_github_delivery_workflows(
    archive_bytes: &[u8],
    limits: RepositoryWorkflowDiscoveryLimits,
) -> Result<Vec<RepositoryWorkflowDiscoveryOutcome>, RepositoryWorkflowDiscoveryError> {
    discover_repository_workflows(
        archive_bytes,
        limits,
        RepositoryWorkflowDiscoveryPolicy::GithubDelivery,
        &|| false,
    )
}

pub(crate) fn discover_local_github_workflows(
    archive_bytes: &[u8],
    limits: RepositoryWorkflowDiscoveryLimits,
    cancellation: &dyn Fn() -> bool,
) -> Result<Vec<RepositoryWorkflowDiscoveryOutcome>, RepositoryWorkflowDiscoveryError> {
    discover_repository_workflows(
        archive_bytes,
        limits,
        RepositoryWorkflowDiscoveryPolicy::LocalGithubArchive,
        cancellation,
    )
}

fn discover_repository_workflows(
    archive_bytes: &[u8],
    limits: RepositoryWorkflowDiscoveryLimits,
    policy: RepositoryWorkflowDiscoveryPolicy,
    cancellation: &dyn Fn() -> bool,
) -> Result<Vec<RepositoryWorkflowDiscoveryOutcome>, RepositoryWorkflowDiscoveryError> {
    if cancellation() {
        return Err(RepositoryWorkflowDiscoveryError::Cancelled);
    }
    let compressed_bytes = u64::try_from(archive_bytes.len())
        .map_err(|_| RepositoryWorkflowDiscoveryError::ResourceLimit)?;
    if compressed_bytes > limits.maximum_compressed_bytes() {
        return Err(RepositoryWorkflowDiscoveryError::ResourceLimit);
    }

    let limit_state = ReadLimitState::default();
    let decoder = MultiGzDecoder::new(Cursor::new(archive_bytes));
    let reader = BoundedReader::new(
        decoder,
        limits.maximum_decompressed_bytes(),
        limit_state.clone(),
        cancellation,
    );
    let mut archive = tar::Archive::new(reader);
    let workflows =
        inspect_archive_entries(&mut archive, limits, policy, &limit_state, cancellation)?;
    let mut reader = archive.into_inner();
    verify_tar_termination(&mut reader, &limit_state)?;

    if cancellation() {
        return Err(RepositoryWorkflowDiscoveryError::Cancelled);
    }
    Ok(workflows
        .into_iter()
        .map(|(path, result)| RepositoryWorkflowDiscoveryOutcome { path, result })
        .collect())
}

fn inspect_archive_entries<R: io::Read>(
    archive: &mut tar::Archive<R>,
    limits: RepositoryWorkflowDiscoveryLimits,
    policy: RepositoryWorkflowDiscoveryPolicy,
    limit_state: &ReadLimitState,
    cancellation: &dyn Fn() -> bool,
) -> Result<
    BTreeMap<String, Result<Vec<u8>, RepositoryWorkflowDiscoveryFailure>>,
    RepositoryWorkflowDiscoveryError,
> {
    let mut inspection = ArchiveInspection::new(policy, limits);
    let entries = archive
        .entries()
        .map_err(|_| read_error(limit_state))?
        .raw(true);
    for entry in entries {
        if cancellation() {
            return Err(RepositoryWorkflowDiscoveryError::Cancelled);
        }
        let entry = entry.map_err(|_| read_error(limit_state))?;
        inspection.inspect_entry(entry, limits, limit_state)?;
    }
    inspection.finish(limit_state, cancellation)
}

struct ArchiveInspection {
    policy: RepositoryWorkflowDiscoveryPolicy,
    root: Option<String>,
    path_validator: Option<RepositoryPathValidator>,
    graph: ArchivePathGraph,
    workflows: BTreeMap<String, Result<Vec<u8>, RepositoryWorkflowDiscoveryFailure>>,
    entry_count: usize,
    expanded_bytes: u64,
    saw_global_pax: bool,
    pending_data_end: Option<u64>,
}

impl ArchiveInspection {
    fn new(
        policy: RepositoryWorkflowDiscoveryPolicy,
        limits: RepositoryWorkflowDiscoveryLimits,
    ) -> Self {
        Self {
            policy,
            root: None,
            path_validator: None,
            graph: ArchivePathGraph::new(limits),
            workflows: BTreeMap::new(),
            entry_count: 0,
            expanded_bytes: 0,
            saw_global_pax: false,
            pending_data_end: None,
        }
    }

    fn inspect_entry<R: io::Read>(
        &mut self,
        mut entry: tar::Entry<'_, R>,
        limits: RepositoryWorkflowDiscoveryLimits,
        limit_state: &ReadLimitState,
    ) -> Result<(), RepositoryWorkflowDiscoveryError> {
        self.entry_count = self
            .entry_count
            .checked_add(1)
            .ok_or(RepositoryWorkflowDiscoveryError::ResourceLimit)?;
        if self.entry_count > limits.maximum_entries() {
            return Err(RepositoryWorkflowDiscoveryError::ResourceLimit);
        }

        let header_position = entry.raw_header_position();
        self.validate_previous_padding(header_position, limit_state)?;
        let file_position = entry.raw_file_position();
        if file_position
            != header_position
                .checked_add(TAR_BLOCK_BYTES_U64)
                .ok_or(RepositoryWorkflowDiscoveryError::ResourceLimit)?
        {
            return Err(RepositoryWorkflowDiscoveryError::Malformed);
        }

        let entry_type = entry.header().entry_type();
        let declared_size = entry
            .header()
            .entry_size()
            .map_err(|_| RepositoryWorkflowDiscoveryError::Malformed)?;
        self.expanded_bytes = checked_expanded_size(self.expanded_bytes, declared_size, limits)?;
        self.pending_data_end = Some(
            file_position
                .checked_add(declared_size)
                .ok_or(RepositoryWorkflowDiscoveryError::ResourceLimit)?,
        );

        if entry_type.is_pax_global_extensions() {
            if self.root.is_some() || self.saw_global_pax {
                return Err(RepositoryWorkflowDiscoveryError::UnsupportedArchiveEntry);
            }
            validate_global_pax(&mut entry, declared_size, limit_state)?;
            self.saw_global_pax = true;
            return Ok(());
        }
        if entry_type.is_gnu_longname()
            || entry_type.is_gnu_longlink()
            || entry_type.is_pax_local_extensions()
            || entry_type.is_gnu_sparse()
            || entry_type.is_hard_link()
        {
            return Err(RepositoryWorkflowDiscoveryError::UnsupportedArchiveEntry);
        }
        if entry_type.is_dir() && declared_size != 0 {
            return Err(RepositoryWorkflowDiscoveryError::Malformed);
        }

        let raw_path = entry.path_bytes();
        let (archive_root, relative_path) = archive_path_parts(
            raw_path.as_ref(),
            limits.maximum_entry_path_bytes(),
            entry_type,
        )?;
        let Some(relative_path) =
            self.validate_root(archive_root, relative_path, entry_type, limits)?
        else {
            consume_entry(&mut entry, declared_size, limit_state)?;
            return Ok(());
        };
        let relative_components = relative_path.split('/').collect::<Vec<_>>();

        if workflow_location_conflicts(&relative_components, self.policy.workflow_location()) {
            return Err(RepositoryWorkflowDiscoveryError::UnsupportedWorkflowLocation);
        }
        if entry_type.is_symlink() && !self.policy.allows_symlinks() {
            return Err(RepositoryWorkflowDiscoveryError::UnsupportedArchiveEntry);
        }

        let is_workflow = is_direct_workflow(&relative_components, self.policy.workflow_location());
        if is_workflow && !entry_type.is_file() {
            return Err(RepositoryWorkflowDiscoveryError::UnsupportedWorkflowEntry);
        }
        let node_kind = self.classify_node(&entry, entry_type, declared_size)?;
        self.graph.insert(&relative_path, node_kind)?;

        if is_workflow {
            if repository_workflow_path_byte_rejection(relative_path.len()).is_some() {
                return Err(RepositoryWorkflowDiscoveryError::ResourceLimit);
            }
            self.insert_workflow(
                relative_path,
                &mut entry,
                declared_size,
                limits,
                limit_state,
            )
        } else {
            consume_entry(&mut entry, declared_size, limit_state)
        }
    }

    fn classify_node<R: io::Read>(
        &self,
        entry: &tar::Entry<'_, R>,
        entry_type: tar::EntryType,
        declared_size: u64,
    ) -> Result<ArchiveNodeKind, RepositoryWorkflowDiscoveryError> {
        if entry_type.is_symlink() {
            let validator = self
                .path_validator
                .ok_or(RepositoryWorkflowDiscoveryError::MissingArchiveRoot)?;
            return validate_symlink(entry, declared_size, validator).map(ArchiveNodeKind::Symlink);
        }
        if entry_type.is_file() {
            return Ok(ArchiveNodeKind::File);
        }
        if entry_type.is_dir() {
            return Ok(ArchiveNodeKind::Directory);
        }
        Err(RepositoryWorkflowDiscoveryError::UnsupportedArchiveEntry)
    }

    fn validate_root(
        &mut self,
        archive_root: &str,
        relative_path: Option<&str>,
        entry_type: tar::EntryType,
        limits: RepositoryWorkflowDiscoveryLimits,
    ) -> Result<Option<String>, RepositoryWorkflowDiscoveryError> {
        if let Some(expected_root) = self.root.as_deref() {
            if archive_root != expected_root {
                return Err(RepositoryWorkflowDiscoveryError::UnsafePath);
            }
            if relative_path.is_none() {
                return Err(RepositoryWorkflowDiscoveryError::DuplicatePath);
            }
        } else {
            if relative_path.is_some() || !entry_type.is_dir() {
                return Err(RepositoryWorkflowDiscoveryError::UnsafePath);
            }
            let validator =
                RepositoryPathValidator::new(archive_root, limits.maximum_entry_path_bytes())
                    .map_err(path_validation_error)?;
            self.root = Some(archive_root.to_owned());
            self.path_validator = Some(validator);
        }
        let Some(relative_path) = relative_path else {
            return Ok(None);
        };
        let validator = self
            .path_validator
            .ok_or(RepositoryWorkflowDiscoveryError::MissingArchiveRoot)?;
        let relative_path = validator
            .validate_entry(relative_path.as_bytes())
            .map_err(path_validation_error)?;
        Ok(Some(relative_path.to_owned()))
    }

    fn validate_previous_padding(
        &self,
        next_header_position: u64,
        limit_state: &ReadLimitState,
    ) -> Result<(), RepositoryWorkflowDiscoveryError> {
        let Some(data_end) = self.pending_data_end else {
            return if next_header_position == 0 {
                Ok(())
            } else {
                Err(RepositoryWorkflowDiscoveryError::Malformed)
            };
        };
        let expected_header = next_tar_block(data_end)?;
        if next_header_position != expected_header
            || !limit_state.observed_zeros(data_end, expected_header)
        {
            return Err(RepositoryWorkflowDiscoveryError::Malformed);
        }
        Ok(())
    }

    fn insert_workflow<R: io::Read>(
        &mut self,
        path: String,
        entry: &mut tar::Entry<'_, R>,
        declared_size: u64,
        limits: RepositoryWorkflowDiscoveryLimits,
        limit_state: &ReadLimitState,
    ) -> Result<(), RepositoryWorkflowDiscoveryError> {
        if self.workflows.len() >= limits.maximum_workflows() {
            return Err(RepositoryWorkflowDiscoveryError::ResourceLimit);
        }
        let result = if declared_size == 0 {
            consume_entry(entry, declared_size, limit_state)?;
            Err(RepositoryWorkflowDiscoveryFailure::Empty)
        } else if declared_size > limits.maximum_workflow_bytes() {
            consume_entry(entry, declared_size, limit_state)?;
            Err(RepositoryWorkflowDiscoveryFailure::Oversized)
        } else {
            Ok(read_entry(
                entry,
                declared_size,
                declared_size,
                limit_state,
            )?)
        };
        self.workflows.insert(path, result);
        Ok(())
    }

    fn finish(
        self,
        limit_state: &ReadLimitState,
        cancellation: &dyn Fn() -> bool,
    ) -> Result<
        BTreeMap<String, Result<Vec<u8>, RepositoryWorkflowDiscoveryFailure>>,
        RepositoryWorkflowDiscoveryError,
    > {
        if let Some(data_end) = self.pending_data_end {
            let end_header = next_tar_block(data_end)?;
            let after_end_header = end_header
                .checked_add(TAR_BLOCK_BYTES_U64)
                .ok_or(RepositoryWorkflowDiscoveryError::ResourceLimit)?;
            if !limit_state.observed_zeros(data_end, after_end_header) {
                return Err(RepositoryWorkflowDiscoveryError::Malformed);
            }
        }
        if self.root.is_none() {
            return Err(RepositoryWorkflowDiscoveryError::MissingArchiveRoot);
        }
        let validator = self
            .path_validator
            .ok_or(RepositoryWorkflowDiscoveryError::MissingArchiveRoot)?;
        self.graph.validate_links(validator, cancellation)?;
        Ok(self.workflows)
    }
}

fn next_tar_block(offset: u64) -> Result<u64, RepositoryWorkflowDiscoveryError> {
    offset
        .checked_add(TAR_BLOCK_BYTES_U64 - 1)
        .map(|value| value / TAR_BLOCK_BYTES_U64 * TAR_BLOCK_BYTES_U64)
        .ok_or(RepositoryWorkflowDiscoveryError::ResourceLimit)
}

fn checked_expanded_size(
    current: u64,
    additional: u64,
    limits: RepositoryWorkflowDiscoveryLimits,
) -> Result<u64, RepositoryWorkflowDiscoveryError> {
    let next = current
        .checked_add(additional)
        .ok_or(RepositoryWorkflowDiscoveryError::ResourceLimit)?;
    if next > limits.maximum_expanded_bytes() {
        return Err(RepositoryWorkflowDiscoveryError::ResourceLimit);
    }
    Ok(next)
}

fn archive_path_parts(
    raw: &[u8],
    maximum_path_bytes: usize,
    entry_type: tar::EntryType,
) -> Result<(&str, Option<&str>), RepositoryWorkflowDiscoveryError> {
    if raw.is_empty()
        || raw.len() > maximum_path_bytes
        || raw.starts_with(b"/")
        || raw.contains(&b'\\')
        || raw.iter().any(u8::is_ascii_control)
    {
        return Err(if raw.len() > maximum_path_bytes {
            RepositoryWorkflowDiscoveryError::ResourceLimit
        } else {
            RepositoryWorkflowDiscoveryError::UnsafePath
        });
    }
    let path =
        std::str::from_utf8(raw).map_err(|_| RepositoryWorkflowDiscoveryError::UnsafePath)?;
    let path = if let Some(path) = path.strip_suffix('/') {
        if !entry_type.is_dir() || path.ends_with('/') {
            return Err(RepositoryWorkflowDiscoveryError::UnsafePath);
        }
        path
    } else {
        path
    };
    if path.is_empty() {
        return Err(RepositoryWorkflowDiscoveryError::UnsafePath);
    }
    let (root, relative) = path
        .split_once('/')
        .map_or((path, None), |(root, relative)| (root, Some(relative)));
    if root.is_empty() || relative.is_some_and(str::is_empty) {
        return Err(RepositoryWorkflowDiscoveryError::UnsafePath);
    }
    Ok((root, relative))
}

fn is_direct_workflow(relative_components: &[&str], location: RepositoryWorkflowLocation) -> bool {
    relative_components.len() == 3
        && relative_components[0] == location.directory()
        && relative_components[1] == "workflows"
        && relative_components[2]
            .rsplit_once('.')
            .is_some_and(|(_, extension)| matches!(extension, "yml" | "yaml"))
}

fn workflow_location_conflicts(
    relative_components: &[&str],
    location: RepositoryWorkflowLocation,
) -> bool {
    if relative_components.len() < 2 || relative_components[1] != "workflows" {
        return false;
    }
    let actual = match relative_components[0] {
        ".ci" => Some(RepositoryWorkflowLocation::Automata),
        ".github" => Some(RepositoryWorkflowLocation::Github),
        _ => None,
    };
    actual.is_some_and(|actual| actual != location)
}

fn validate_symlink<R: io::Read>(
    entry: &tar::Entry<'_, R>,
    declared_size: u64,
    validator: RepositoryPathValidator,
) -> Result<String, RepositoryWorkflowDiscoveryError> {
    if declared_size != 0 {
        return Err(RepositoryWorkflowDiscoveryError::Malformed);
    }
    let target = entry
        .link_name_bytes()
        .ok_or(RepositoryWorkflowDiscoveryError::UnsafeLink)?;
    validator
        .validate_symlink_target(target.as_ref())
        .map(str::to_owned)
        .map_err(link_validation_error)
}

fn path_validation_error(error: RepositoryPathValidationError) -> RepositoryWorkflowDiscoveryError {
    match error {
        RepositoryPathValidationError::ResourceLimit => {
            RepositoryWorkflowDiscoveryError::ResourceLimit
        }
        RepositoryPathValidationError::NonUnicode | RepositoryPathValidationError::Unsafe => {
            RepositoryWorkflowDiscoveryError::UnsafePath
        }
    }
}

fn link_validation_error(error: RepositoryPathValidationError) -> RepositoryWorkflowDiscoveryError {
    match error {
        RepositoryPathValidationError::ResourceLimit => {
            RepositoryWorkflowDiscoveryError::ResourceLimit
        }
        RepositoryPathValidationError::NonUnicode | RepositoryPathValidationError::Unsafe => {
            RepositoryWorkflowDiscoveryError::UnsafeLink
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ArchiveNodeKind {
    ImplicitDirectory,
    Directory,
    File,
    Symlink(String),
}

impl ArchiveNodeKind {
    const fn is_directory(&self) -> bool {
        matches!(self, Self::ImplicitDirectory | Self::Directory)
    }

    const fn same_explicit_type(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::Directory, Self::Directory)
                | (Self::File, Self::File)
                | (Self::Symlink(_), Self::Symlink(_))
        )
    }
}

struct ArchiveGraphNode {
    parent: usize,
    spelling: String,
    kind: ArchiveNodeKind,
    children: BTreeMap<PortablePathKey, usize>,
}

struct ArchivePathGraph {
    nodes: Vec<ArchiveGraphNode>,
    maximum_nodes: usize,
    maximum_component_bytes: usize,
    component_bytes: usize,
}

impl ArchivePathGraph {
    fn new(limits: RepositoryWorkflowDiscoveryLimits) -> Self {
        Self::with_limits(
            limits.maximum_path_graph_nodes(),
            limits.maximum_path_graph_component_bytes(),
        )
    }

    fn with_limits(maximum_nodes: usize, maximum_component_bytes: usize) -> Self {
        Self {
            nodes: vec![ArchiveGraphNode {
                parent: 0,
                spelling: String::new(),
                kind: ArchiveNodeKind::ImplicitDirectory,
                children: BTreeMap::new(),
            }],
            maximum_nodes,
            maximum_component_bytes,
            component_bytes: 0,
        }
    }

    fn insert(
        &mut self,
        path: &str,
        kind: ArchiveNodeKind,
    ) -> Result<(), RepositoryWorkflowDiscoveryError> {
        if matches!(kind, ArchiveNodeKind::Symlink(_)) && workflow_namespace_anchor(path) {
            return Err(RepositoryWorkflowDiscoveryError::NamespaceAlias);
        }
        let mut components = path.split('/').peekable();
        let mut leaf_kind = Some(kind);
        let mut parent = 0_usize;
        while let Some(component) = components.next() {
            let leaf = components.peek().is_none();
            let key = RepositoryPathValidator::portable_key(component);
            let existing = self.nodes[parent].children.get(&key).copied();
            let node = if let Some(node) = existing {
                if self.nodes[node].spelling != component {
                    return Err(RepositoryWorkflowDiscoveryError::PathAlias);
                }
                if leaf {
                    let kind = leaf_kind
                        .take()
                        .ok_or(RepositoryWorkflowDiscoveryError::PathTypeConflict)?;
                    match &self.nodes[node].kind {
                        ArchiveNodeKind::ImplicitDirectory
                            if matches!(kind, ArchiveNodeKind::Directory) =>
                        {
                            self.nodes[node].kind = kind;
                        }
                        ArchiveNodeKind::ImplicitDirectory => {
                            return Err(RepositoryWorkflowDiscoveryError::PathTypeConflict);
                        }
                        existing if existing.same_explicit_type(&kind) => {
                            return Err(RepositoryWorkflowDiscoveryError::DuplicatePath);
                        }
                        _ => return Err(RepositoryWorkflowDiscoveryError::PathTypeConflict),
                    }
                } else if !self.nodes[node].kind.is_directory() {
                    return Err(RepositoryWorkflowDiscoveryError::PathTypeConflict);
                }
                node
            } else {
                let kind = if leaf {
                    leaf_kind
                        .take()
                        .ok_or(RepositoryWorkflowDiscoveryError::PathTypeConflict)?
                } else {
                    ArchiveNodeKind::ImplicitDirectory
                };
                self.insert_node(parent, component, key, kind)?
            };
            parent = node;
        }
        Ok(())
    }

    fn insert_node(
        &mut self,
        parent: usize,
        component: &str,
        key: PortablePathKey,
        kind: ArchiveNodeKind,
    ) -> Result<usize, RepositoryWorkflowDiscoveryError> {
        if self.nodes.len().saturating_sub(1) >= self.maximum_nodes {
            return Err(RepositoryWorkflowDiscoveryError::ResourceLimit);
        }
        let additional_bytes = component
            .len()
            .checked_add(key.storage_bytes())
            .ok_or(RepositoryWorkflowDiscoveryError::ResourceLimit)?;
        let component_bytes = self
            .component_bytes
            .checked_add(additional_bytes)
            .ok_or(RepositoryWorkflowDiscoveryError::ResourceLimit)?;
        if component_bytes > self.maximum_component_bytes {
            return Err(RepositoryWorkflowDiscoveryError::ResourceLimit);
        }
        let node = self.nodes.len();
        self.nodes.push(ArchiveGraphNode {
            parent,
            spelling: component.to_owned(),
            kind,
            children: BTreeMap::new(),
        });
        if self.nodes[parent].children.insert(key, node).is_some() {
            return Err(RepositoryWorkflowDiscoveryError::PathAlias);
        }
        self.component_bytes = component_bytes;
        Ok(node)
    }

    fn validate_links(
        &self,
        validator: RepositoryPathValidator,
        cancellation: &dyn Fn() -> bool,
    ) -> Result<(), RepositoryWorkflowDiscoveryError> {
        let hop_limit = self
            .nodes
            .iter()
            .filter(|node| matches!(node.kind, ArchiveNodeKind::Symlink(_)))
            .count()
            .min(MAX_SYMLINK_RESOLUTION_HOPS);
        let mut directory_aliases = Vec::new();
        for node in 1..self.nodes.len() {
            if cancellation() {
                return Err(RepositoryWorkflowDiscoveryError::Cancelled);
            }
            let ArchiveNodeKind::Symlink(target) = &self.nodes[node].kind else {
                continue;
            };
            let path = self.node_components(node);
            let resolved = self.resolve_link(&path, target, validator, hop_limit)?;
            if workflow_namespace_anchor_components(&resolved) {
                return Err(RepositoryWorkflowDiscoveryError::NamespaceAlias);
            }
            if let Some(target) = self.lookup_exact(&resolved)?
                && self.nodes[target].kind.is_directory()
            {
                directory_aliases.push((self.nodes[node].parent, target));
            }
        }
        self.validate_directory_containment(&directory_aliases, cancellation)
    }

    fn validate_directory_containment(
        &self,
        aliases: &[(usize, usize)],
        cancellation: &dyn Fn() -> bool,
    ) -> Result<(), RepositoryWorkflowDiscoveryError> {
        let mut outgoing = vec![Vec::new(); self.nodes.len()];
        let mut incoming = vec![0_usize; self.nodes.len()];
        let mut directory_count = 0_usize;
        for (parent, node) in self.nodes.iter().enumerate() {
            if cancellation() {
                return Err(RepositoryWorkflowDiscoveryError::Cancelled);
            }
            if !node.kind.is_directory() {
                continue;
            }
            directory_count += 1;
            for child in node.children.values().copied() {
                if self.nodes[child].kind.is_directory() {
                    outgoing[parent].push(child);
                    incoming[child] += 1;
                }
            }
        }
        for &(parent, target) in aliases {
            outgoing[parent].push(target);
            incoming[target] += 1;
        }
        let mut ready = self
            .nodes
            .iter()
            .enumerate()
            .filter_map(|(node, entry)| {
                (entry.kind.is_directory() && incoming[node] == 0).then_some(node)
            })
            .collect::<VecDeque<_>>();
        let mut visited = 0_usize;
        while let Some(node) = ready.pop_front() {
            if cancellation() {
                return Err(RepositoryWorkflowDiscoveryError::Cancelled);
            }
            visited += 1;
            for child in outgoing[node].iter().copied() {
                incoming[child] -= 1;
                if incoming[child] == 0 {
                    ready.push_back(child);
                }
            }
        }
        if visited != directory_count {
            return Err(RepositoryWorkflowDiscoveryError::UnsafeLink);
        }
        Ok(())
    }

    fn resolve_link(
        &self,
        link_path: &[String],
        target: &str,
        validator: RepositoryPathValidator,
        hop_limit: usize,
    ) -> Result<Vec<String>, RepositoryWorkflowDiscoveryError> {
        let mut resolved = link_path[..link_path.len().saturating_sub(1)].to_vec();
        let mut pending = VecDeque::new();
        prepend_target_components(&mut pending, target);
        let mut followed = BTreeSet::new();
        let mut remaining_hops = hop_limit;
        while let Some(component) = pending.pop_front() {
            match component.as_str() {
                "." => self.require_resolution_directory(&resolved)?,
                ".." => {
                    self.require_resolution_directory(&resolved)?;
                    resolved
                        .pop()
                        .ok_or(RepositoryWorkflowDiscoveryError::UnsafeLink)?;
                }
                component => {
                    resolved.push(component.to_owned());
                    validator
                        .validate_resolved_components(&resolved, pending.is_empty())
                        .map_err(link_validation_error)?;
                    if workflow_namespace_components(&resolved) {
                        return Err(RepositoryWorkflowDiscoveryError::NamespaceAlias);
                    }
                    match self.lookup_exact(&resolved)? {
                        Some(node)
                            if matches!(self.nodes[node].kind, ArchiveNodeKind::Symlink(_)) =>
                        {
                            if !followed.insert(node) {
                                return Err(RepositoryWorkflowDiscoveryError::UnsafeLink);
                            }
                            remaining_hops = remaining_hops
                                .checked_sub(1)
                                .ok_or(RepositoryWorkflowDiscoveryError::ResourceLimit)?;
                            let ArchiveNodeKind::Symlink(target) = &self.nodes[node].kind else {
                                unreachable!("matched symbolic-link node")
                            };
                            resolved.pop();
                            prepend_target_components(&mut pending, target);
                        }
                        Some(node)
                            if matches!(self.nodes[node].kind, ArchiveNodeKind::File)
                                && !pending.is_empty() =>
                        {
                            return Err(RepositoryWorkflowDiscoveryError::PathTypeConflict);
                        }
                        _ => {}
                    }
                }
            }
        }
        if resolved.is_empty() {
            return Err(RepositoryWorkflowDiscoveryError::UnsafeLink);
        }
        validator
            .validate_resolved_components(&resolved, true)
            .map_err(link_validation_error)?;
        Ok(resolved)
    }

    fn require_resolution_directory(
        &self,
        resolved: &[String],
    ) -> Result<(), RepositoryWorkflowDiscoveryError> {
        if resolved.is_empty() {
            return Ok(());
        }
        match self.lookup_exact(resolved)? {
            Some(node) if self.nodes[node].kind.is_directory() => Ok(()),
            Some(node) if matches!(self.nodes[node].kind, ArchiveNodeKind::File) => {
                Err(RepositoryWorkflowDiscoveryError::PathTypeConflict)
            }
            Some(_) | None => Err(RepositoryWorkflowDiscoveryError::UnsafeLink),
        }
    }

    fn lookup_exact(
        &self,
        components: &[String],
    ) -> Result<Option<usize>, RepositoryWorkflowDiscoveryError> {
        let mut node = 0_usize;
        for component in components {
            let key = RepositoryPathValidator::portable_key(component);
            let Some(child) = self.nodes[node].children.get(&key).copied() else {
                return Ok(None);
            };
            if self.nodes[child].spelling != *component {
                return Err(RepositoryWorkflowDiscoveryError::PathAlias);
            }
            node = child;
        }
        Ok(Some(node))
    }

    fn node_components(&self, mut node: usize) -> Vec<String> {
        let mut components = Vec::new();
        while node != 0 {
            components.push(self.nodes[node].spelling.clone());
            node = self.nodes[node].parent;
        }
        components.reverse();
        components
    }
}

fn prepend_target_components(pending: &mut VecDeque<String>, target: &str) {
    for component in target.split('/').rev() {
        pending.push_front(component.to_owned());
    }
}

fn workflow_namespace_components(components: &[String]) -> bool {
    components.len() >= 2
        && [".ci", ".github"]
            .iter()
            .any(|root| RepositoryPathValidator::portable_equivalent(&components[0], root))
        && RepositoryPathValidator::portable_equivalent(&components[1], "workflows")
}

fn workflow_namespace_anchor_components(components: &[String]) -> bool {
    components.len() == 1
        && [".ci", ".github"]
            .iter()
            .any(|root| RepositoryPathValidator::portable_equivalent(&components[0], root))
        || workflow_namespace_components(components)
}

fn workflow_namespace_anchor(path: &str) -> bool {
    let components = path.split('/').map(str::to_owned).collect::<Vec<_>>();
    workflow_namespace_anchor_components(&components)
}

fn consume_entry<R: io::Read>(
    entry: &mut tar::Entry<'_, R>,
    declared_size: u64,
    limit_state: &ReadLimitState,
) -> Result<(), RepositoryWorkflowDiscoveryError> {
    let copied = io::copy(entry, &mut io::sink()).map_err(|_| read_error(limit_state))?;
    if copied != declared_size {
        return Err(RepositoryWorkflowDiscoveryError::Malformed);
    }
    Ok(())
}

fn read_entry<R: io::Read>(
    entry: &mut tar::Entry<'_, R>,
    declared_size: u64,
    maximum_bytes: u64,
    limit_state: &ReadLimitState,
) -> Result<Vec<u8>, RepositoryWorkflowDiscoveryError> {
    if declared_size > maximum_bytes {
        return Err(RepositoryWorkflowDiscoveryError::ResourceLimit);
    }
    let capacity = usize::try_from(declared_size)
        .map_err(|_| RepositoryWorkflowDiscoveryError::ResourceLimit)?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut limited = entry.take(maximum_bytes.saturating_add(1));
    limited
        .read_to_end(&mut bytes)
        .map_err(|_| read_error(limit_state))?;
    let actual_size =
        u64::try_from(bytes.len()).map_err(|_| RepositoryWorkflowDiscoveryError::ResourceLimit)?;
    if actual_size > maximum_bytes {
        return Err(RepositoryWorkflowDiscoveryError::ResourceLimit);
    }
    if actual_size != declared_size {
        return Err(RepositoryWorkflowDiscoveryError::Malformed);
    }
    Ok(bytes)
}

fn validate_global_pax<R: io::Read>(
    entry: &mut tar::Entry<'_, R>,
    declared_size: u64,
    limit_state: &ReadLimitState,
) -> Result<(), RepositoryWorkflowDiscoveryError> {
    if global_pax_byte_rejection(declared_size).is_some() {
        return Err(RepositoryWorkflowDiscoveryError::ResourceLimit);
    }
    let bytes = read_entry(entry, declared_size, MAX_GLOBAL_PAX_BYTES, limit_state)?;
    let mut offset = 0_usize;
    let mut keys = BTreeSet::new();
    while offset < bytes.len() {
        let remainder = &bytes[offset..];
        let space = remainder
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or(RepositoryWorkflowDiscoveryError::Malformed)?;
        let length_text = &remainder[..space];
        if length_text.is_empty()
            || (length_text.len() > 1 && length_text[0] == b'0')
            || !length_text.iter().all(u8::is_ascii_digit)
        {
            return Err(RepositoryWorkflowDiscoveryError::Malformed);
        }
        let length = std::str::from_utf8(length_text)
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or(RepositoryWorkflowDiscoveryError::Malformed)?;
        let record_start = offset
            .checked_add(space + 1)
            .ok_or(RepositoryWorkflowDiscoveryError::Malformed)?;
        let end = offset
            .checked_add(length)
            .filter(|end| record_start <= *end && *end <= bytes.len())
            .ok_or(RepositoryWorkflowDiscoveryError::Malformed)?;
        let record = &bytes[record_start..end];
        let record = record
            .strip_suffix(b"\n")
            .ok_or(RepositoryWorkflowDiscoveryError::Malformed)?;
        let separator = record
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or(RepositoryWorkflowDiscoveryError::Malformed)?;
        let key = &record[..separator];
        let value = &record[separator + 1..];
        if key.is_empty()
            || !key
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || !matches!(
                key,
                b"atime" | b"comment" | b"ctime" | b"gid" | b"gname" | b"mtime" | b"uid" | b"uname"
            )
            || value.iter().any(|byte| matches!(byte, 0 | b'\n' | b'\r'))
            || !keys.insert(key.to_vec())
        {
            return Err(RepositoryWorkflowDiscoveryError::UnsupportedArchiveEntry);
        }
        offset = end;
    }
    Ok(())
}

fn verify_tar_termination<R: io::Read>(
    reader: &mut R,
    limit_state: &ReadLimitState,
) -> Result<(), RepositoryWorkflowDiscoveryError> {
    let mut second_end_block = [0_u8; TAR_BLOCK_BYTES];
    reader
        .read_exact(&mut second_end_block)
        .map_err(|_| read_error(limit_state))?;
    if second_end_block.iter().any(|byte| *byte != 0) {
        return Err(RepositoryWorkflowDiscoveryError::Malformed);
    }

    let trailing_bytes =
        io::copy(reader, &mut ZeroPaddingVerifier).map_err(|_| read_error(limit_state))?;
    if trailing_bytes % TAR_BLOCK_BYTES_U64 != 0 {
        return Err(RepositoryWorkflowDiscoveryError::Malformed);
    }
    Ok(())
}

struct ZeroPaddingVerifier;

impl io::Write for ZeroPaddingVerifier {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.iter().any(|byte| *byte != 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "nonzero bytes follow the tar end marker",
            ));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Default)]
struct ReadLimitState(Rc<ReadState>);

#[derive(Default)]
struct ReadState {
    exceeded: Cell<bool>,
    cancelled: Cell<bool>,
    stream_tail: RefCell<StreamTail>,
}

impl ReadLimitState {
    fn mark_exceeded(&self) {
        self.0.exceeded.set(true);
    }

    fn mark_cancelled(&self) {
        self.0.cancelled.set(true);
    }

    fn cancelled(&self) -> bool {
        self.0.cancelled.get()
    }

    fn exceeded(&self) -> bool {
        self.0.exceeded.get()
    }

    fn observe(&self, bytes: &[u8]) {
        self.0.stream_tail.borrow_mut().observe(bytes);
    }

    fn observed_zeros(&self, start: u64, end: u64) -> bool {
        self.0.stream_tail.borrow().observed_zeros(start, end)
    }
}

#[derive(Default)]
struct StreamTail {
    start: u64,
    end: u64,
    bytes: Vec<u8>,
}

impl StreamTail {
    fn observe(&mut self, observed: &[u8]) {
        let observed_len = u64::try_from(observed.len()).unwrap_or(u64::MAX);
        self.end = self.end.saturating_add(observed_len);
        if observed.len() >= OBSERVED_STREAM_TAIL_BYTES {
            self.bytes.clear();
            self.bytes.extend_from_slice(
                &observed[observed.len().saturating_sub(OBSERVED_STREAM_TAIL_BYTES)..],
            );
        } else {
            self.bytes.extend_from_slice(observed);
            let excess = self.bytes.len().saturating_sub(OBSERVED_STREAM_TAIL_BYTES);
            self.bytes.drain(..excess);
        }
        self.start = self
            .end
            .saturating_sub(u64::try_from(self.bytes.len()).unwrap_or(u64::MAX));
    }

    fn observed_zeros(&self, start: u64, end: u64) -> bool {
        if start == end {
            return true;
        }
        if start > end || start < self.start || end > self.end {
            return false;
        }
        let Ok(start) = usize::try_from(start - self.start) else {
            return false;
        };
        let Ok(end) = usize::try_from(end - self.start) else {
            return false;
        };
        self.bytes[start..end].iter().all(|byte| *byte == 0)
    }
}

struct BoundedReader<'a, R> {
    inner: R,
    remaining: u64,
    limit_state: ReadLimitState,
    cancellation: &'a dyn Fn() -> bool,
}

impl<'a, R> BoundedReader<'a, R> {
    fn new(
        inner: R,
        maximum_bytes: u64,
        limit_state: ReadLimitState,
        cancellation: &'a dyn Fn() -> bool,
    ) -> Self {
        Self {
            inner,
            remaining: maximum_bytes,
            limit_state,
            cancellation,
        }
    }
}

impl<R: io::Read> io::Read for BoundedReader<'_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if (self.cancellation)() {
            self.limit_state.mark_cancelled();
            return Err(io::Error::other("cancelled"));
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut probe = [0_u8; 1];
            return if self.inner.read(&mut probe)? == 0 {
                Ok(0)
            } else {
                self.limit_state.mark_exceeded();
                Err(io::Error::other("decompressed byte limit exceeded"))
            };
        }
        let maximum = usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        let read = self.inner.read(&mut bytes[..maximum])?;
        self.limit_state.observe(&bytes[..read]);
        self.remaining = self
            .remaining
            .saturating_sub(u64::try_from(read).unwrap_or(u64::MAX));
        Ok(read)
    }
}

fn read_error(limit_state: &ReadLimitState) -> RepositoryWorkflowDiscoveryError {
    if limit_state.cancelled() {
        RepositoryWorkflowDiscoveryError::Cancelled
    } else if limit_state.exceeded() {
        RepositoryWorkflowDiscoveryError::ResourceLimit
    } else {
        RepositoryWorkflowDiscoveryError::Malformed
    }
}

/// Indicates that repository discovery limits are zero, inconsistent, or above
/// the implementation's closed safety ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepositoryWorkflowDiscoveryLimitsError;

impl fmt::Display for RepositoryWorkflowDiscoveryLimitsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("repository workflow discovery limits are invalid")
    }
}

impl Error for RepositoryWorkflowDiscoveryLimitsError {}

/// Sanitized, archive-wide failure from repository workflow discovery.
///
/// Variants deliberately omit archive bytes and entry paths so untrusted
/// repository content is not copied into operational diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RepositoryWorkflowDiscoveryError {
    /// Cooperative local analysis cancellation interrupted archive inspection.
    Cancelled,
    /// Gzip or tar framing, sizes, padding, or termination are invalid.
    Malformed,
    /// A configured or implementation-wide resource ceiling was exceeded.
    ResourceLimit,
    /// An archive path is non-canonical, escaping, absolute, or otherwise unsafe.
    UnsafePath,
    /// A symbolic-link target is escaping, cyclic, nonportable, or otherwise unsafe.
    UnsafeLink,
    /// Two archive entries resolve to the same canonical relative path.
    DuplicatePath,
    /// Two archive path spellings alias under the portable case policy.
    PathAlias,
    /// An archive path is both a non-directory node and an ancestor of another node.
    PathTypeConflict,
    /// A symbolic link aliases a workflow namespace authority.
    NamespaceAlias,
    /// The archive uses an unsupported entry type or metadata extension.
    UnsupportedArchiveEntry,
    /// A direct workflow path is not represented by a regular file.
    UnsupportedWorkflowEntry,
    /// The repository contains a workflow authority other than the explicitly
    /// selected location.
    UnsupportedWorkflowLocation,
    /// The archive did not begin with the required single explicit root directory.
    MissingArchiveRoot,
}

impl fmt::Display for RepositoryWorkflowDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Cancelled => "repository archive inspection was cancelled",
            Self::Malformed => "repository archive is malformed",
            Self::ResourceLimit => "repository archive exceeds a configured resource limit",
            Self::UnsafePath => "repository archive contains an unsafe path",
            Self::UnsafeLink => "repository archive contains an unsafe symbolic link",
            Self::DuplicatePath => "repository archive contains a duplicate path",
            Self::PathAlias => "repository archive contains nonportable path aliases",
            Self::PathTypeConflict => "repository archive contains conflicting path node types",
            Self::NamespaceAlias => {
                "repository archive contains a symbolic-link workflow namespace alias"
            }
            Self::UnsupportedArchiveEntry => {
                "repository archive contains unsupported metadata or an entry type"
            }
            Self::UnsupportedWorkflowEntry => "repository workflow path is not a regular file",
            Self::UnsupportedWorkflowLocation => {
                "repository archive contains a conflicting workflow location"
            }
            Self::MissingArchiveRoot => "repository archive root is missing",
        })
    }
}

impl Error for RepositoryWorkflowDiscoveryError {}

#[cfg(test)]
mod limit_contract_tests {
    use super::{
        ArchiveNodeKind, ArchivePathGraph, BoundedReader, MAX_COMPRESSED_BYTES,
        MAX_DECOMPRESSED_BYTES, MAX_ENTRY_COUNT, MAX_ENTRY_PATH_BYTES, MAX_EXPANDED_BYTES,
        MAX_GLOBAL_PAX_BYTES, MAX_REPOSITORY_WORKFLOW_PATH_BYTES, MAX_WORKFLOW_BYTES,
        MAX_WORKFLOW_COUNT, ReadLimitState, RepositoryArchiveLimitRejection,
        RepositoryWorkflowDiscoveryError, archive_policy_limit_rejection,
        global_pax_byte_rejection, read_error, repository_workflow_path_byte_rejection,
    };

    #[test]
    fn cancellation_stops_standard_readers_instead_of_requesting_a_retry() {
        use std::io::Read as _;

        let state = ReadLimitState::default();
        let cancelled = || true;
        let mut reader = BoundedReader::new(
            std::io::Cursor::new(b"payload"),
            64,
            state.clone(),
            &cancelled,
        );
        let error = reader
            .read_to_end(&mut Vec::new())
            .expect_err("cancellation must terminate the read");
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert_eq!(
            read_error(&state),
            RepositoryWorkflowDiscoveryError::Cancelled
        );
    }

    #[test]
    fn derived_component_storage_has_an_exact_cumulative_byte_boundary() {
        let mut graph = ArchivePathGraph::with_limits(3, 4);
        graph
            .insert("a/b", ArchiveNodeKind::File)
            .expect("two spellings and two keys use four bytes");
        assert_eq!(
            graph.insert("c", ArchiveNodeKind::File),
            Err(RepositoryWorkflowDiscoveryError::ResourceLimit)
        );
    }

    #[test]
    fn archive_compressed_byte_limit_has_exact_boundaries() {
        assert_eq!(
            archive_policy_limit_rejection(MAX_COMPRESSED_BYTES - 1, 1, 1, 1, 1, 1, 1),
            None
        );
        assert_eq!(
            archive_policy_limit_rejection(MAX_COMPRESSED_BYTES, 1, 1, 1, 1, 1, 1),
            None
        );
        assert_eq!(
            archive_policy_limit_rejection(MAX_COMPRESSED_BYTES + 1, 1, 1, 1, 1, 1, 1),
            Some(RepositoryArchiveLimitRejection::CompressedBytes)
        );
    }

    #[test]
    fn archive_decompressed_byte_limit_has_exact_boundaries() {
        assert_eq!(
            archive_policy_limit_rejection(1, MAX_DECOMPRESSED_BYTES - 1, 1, 1, 1, 1, 1),
            None
        );
        assert_eq!(
            archive_policy_limit_rejection(1, MAX_DECOMPRESSED_BYTES, 1, 1, 1, 1, 1),
            None
        );
        assert_eq!(
            archive_policy_limit_rejection(1, MAX_DECOMPRESSED_BYTES + 1, 1, 1, 1, 1, 1),
            Some(RepositoryArchiveLimitRejection::DecompressedBytes)
        );
    }

    #[test]
    fn archive_entry_count_limit_has_exact_boundaries() {
        assert_eq!(
            archive_policy_limit_rejection(1, 1, MAX_ENTRY_COUNT - 1, 1, 1, 1, 1),
            None
        );
        assert_eq!(
            archive_policy_limit_rejection(1, 1, MAX_ENTRY_COUNT, 1, 1, 1, 1),
            None
        );
        assert_eq!(
            archive_policy_limit_rejection(1, 1, MAX_ENTRY_COUNT + 1, 1, 1, 1, 1),
            Some(RepositoryArchiveLimitRejection::EntryCount)
        );
    }

    #[test]
    fn archive_expanded_byte_limit_has_exact_boundaries() {
        assert_eq!(
            archive_policy_limit_rejection(1, 1, 1, MAX_EXPANDED_BYTES - 1, 1, 1, 1),
            None
        );
        assert_eq!(
            archive_policy_limit_rejection(1, 1, 1, MAX_EXPANDED_BYTES, 1, 1, 1),
            None
        );
        assert_eq!(
            archive_policy_limit_rejection(1, 1, 1, MAX_EXPANDED_BYTES + 1, 1, 1, 1),
            Some(RepositoryArchiveLimitRejection::ExpandedBytes)
        );
    }

    #[test]
    fn archive_entry_path_byte_limit_has_exact_boundaries() {
        assert_eq!(
            archive_policy_limit_rejection(1, 1, 1, 1, MAX_ENTRY_PATH_BYTES - 1, 1, 1),
            None
        );
        assert_eq!(
            archive_policy_limit_rejection(1, 1, 1, 1, MAX_ENTRY_PATH_BYTES, 1, 1),
            None
        );
        assert_eq!(
            archive_policy_limit_rejection(1, 1, 1, 1, MAX_ENTRY_PATH_BYTES + 1, 1, 1),
            Some(RepositoryArchiveLimitRejection::EntryPathBytes)
        );
    }

    #[test]
    fn archive_workflow_count_limit_has_exact_boundaries() {
        assert_eq!(
            archive_policy_limit_rejection(1, 1, 1, 1, 1, MAX_WORKFLOW_COUNT - 1, 1),
            None
        );
        assert_eq!(
            archive_policy_limit_rejection(1, 1, 1, 1, 1, MAX_WORKFLOW_COUNT, 1),
            None
        );
        assert_eq!(
            archive_policy_limit_rejection(1, 1, 1, 1, 1, MAX_WORKFLOW_COUNT + 1, 1),
            Some(RepositoryArchiveLimitRejection::WorkflowCount)
        );
    }

    #[test]
    fn archive_workflow_byte_limit_has_exact_boundaries() {
        assert_eq!(
            archive_policy_limit_rejection(
                1,
                1,
                1,
                MAX_EXPANDED_BYTES,
                1,
                1,
                MAX_WORKFLOW_BYTES - 1
            ),
            None
        );
        assert_eq!(
            archive_policy_limit_rejection(1, 1, 1, MAX_EXPANDED_BYTES, 1, 1, MAX_WORKFLOW_BYTES),
            None
        );
        assert_eq!(
            archive_policy_limit_rejection(
                1,
                1,
                1,
                MAX_EXPANDED_BYTES,
                1,
                1,
                MAX_WORKFLOW_BYTES + 1
            ),
            Some(RepositoryArchiveLimitRejection::WorkflowBytes)
        );
    }

    #[test]
    fn archive_global_pax_byte_limit_has_exact_boundaries() {
        assert_eq!(global_pax_byte_rejection(MAX_GLOBAL_PAX_BYTES - 1), None);
        assert_eq!(global_pax_byte_rejection(MAX_GLOBAL_PAX_BYTES), None);
        assert_eq!(
            global_pax_byte_rejection(MAX_GLOBAL_PAX_BYTES + 1),
            Some(RepositoryArchiveLimitRejection::GlobalPaxBytes)
        );
    }

    #[test]
    fn repository_workflow_path_byte_limit_has_exact_boundaries() {
        assert_eq!(
            repository_workflow_path_byte_rejection(MAX_REPOSITORY_WORKFLOW_PATH_BYTES - 1),
            None
        );
        assert_eq!(
            repository_workflow_path_byte_rejection(MAX_REPOSITORY_WORKFLOW_PATH_BYTES),
            None
        );
        assert_eq!(
            repository_workflow_path_byte_rejection(MAX_REPOSITORY_WORKFLOW_PATH_BYTES + 1),
            Some(RepositoryArchiveLimitRejection::WorkflowPathBytes)
        );
    }
}
