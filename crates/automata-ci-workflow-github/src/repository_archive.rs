use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    io::{self, Cursor, Read as _},
    rc::Rc,
};

use flate2::read::MultiGzDecoder;

const TAR_BLOCK_BYTES: usize = 512;
const TAR_BLOCK_BYTES_U64: u64 = 512;
const MAX_COMPRESSED_BYTES: u64 = 4 * 1_024 * 1_024 * 1_024;
const MAX_DECOMPRESSED_BYTES: u64 = 16 * 1_024 * 1_024 * 1_024;
const MAX_ENTRY_COUNT: usize = 1_000_000;
const MAX_EXPANDED_BYTES: u64 = 16 * 1_024 * 1_024 * 1_024;
const MAX_ENTRY_PATH_BYTES: usize = 16 * 1_024;
const MAX_WORKFLOW_COUNT: usize = 1_024;
const MAX_WORKFLOW_BYTES: u64 = 16 * 1_024 * 1_024;
const MAX_GLOBAL_PAX_BYTES: u64 = 64 * 1_024;
const OBSERVED_STREAM_TAIL_BYTES: usize = 2 * 1_024;

/// Maximum byte length of a workflow path returned by repository discovery.
///
/// This must remain exactly aligned with the durable provider-delivery
/// workflow-outcome path bound. It is defined here as well because this
/// source-level frontend must not depend on the persistence crate.
pub const MAX_REPOSITORY_WORKFLOW_PATH_BYTES: usize = 1_024;

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
            || maximum_compressed_bytes > MAX_COMPRESSED_BYTES
            || maximum_decompressed_bytes == 0
            || maximum_decompressed_bytes > MAX_DECOMPRESSED_BYTES
            || maximum_entries == 0
            || maximum_entries > MAX_ENTRY_COUNT
            || maximum_expanded_bytes == 0
            || maximum_expanded_bytes > MAX_EXPANDED_BYTES
            || maximum_entry_path_bytes == 0
            || maximum_entry_path_bytes > MAX_ENTRY_PATH_BYTES
            || maximum_workflows == 0
            || maximum_workflows > MAX_WORKFLOW_COUNT
            || maximum_workflow_bytes == 0
            || maximum_workflow_bytes > MAX_WORKFLOW_BYTES
            || maximum_workflow_bytes > maximum_expanded_bytes
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
            workflow_bytes: 1_024 * 1_024,
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
    /// [`discover_repository_workflows`] instead of appearing here.
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

/// Validates one exact tar.gz repository archive and discovers direct GitHub
/// workflow files.
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
/// Returns a fail-closed error for a non-tar.gz or malformed archive, unsafe or
/// duplicate paths, unsupported archive metadata, non-regular workflow
/// entries, or any archive-wide configured resource-limit exhaustion.
pub fn discover_repository_workflows(
    archive_bytes: &[u8],
    limits: RepositoryWorkflowDiscoveryLimits,
) -> Result<Vec<RepositoryWorkflowDiscoveryOutcome>, RepositoryWorkflowDiscoveryError> {
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
    );
    let mut archive = tar::Archive::new(reader);
    let workflows = inspect_archive_entries(&mut archive, limits, &limit_state)?;
    let mut reader = archive.into_inner();
    verify_tar_termination(&mut reader, &limit_state)?;

    Ok(workflows
        .into_iter()
        .map(|(path, result)| RepositoryWorkflowDiscoveryOutcome { path, result })
        .collect())
}

fn inspect_archive_entries<R: io::Read>(
    archive: &mut tar::Archive<R>,
    limits: RepositoryWorkflowDiscoveryLimits,
    limit_state: &ReadLimitState,
) -> Result<
    BTreeMap<String, Result<Vec<u8>, RepositoryWorkflowDiscoveryFailure>>,
    RepositoryWorkflowDiscoveryError,
> {
    let mut inspection = ArchiveInspection::default();
    let entries = archive
        .entries()
        .map_err(|_| read_error(limit_state))?
        .raw(true);
    for entry in entries {
        let entry = entry.map_err(|_| read_error(limit_state))?;
        inspection.inspect_entry(entry, limits, limit_state)?;
    }
    inspection.finish(limit_state)
}

#[derive(Default)]
struct ArchiveInspection {
    root: Option<String>,
    seen_paths: BTreeSet<String>,
    portable_workflow_filenames: BTreeSet<String>,
    native_workflow_filenames: BTreeSet<String>,
    workflows: BTreeMap<String, Result<Vec<u8>, RepositoryWorkflowDiscoveryFailure>>,
    entry_count: usize,
    expanded_bytes: u64,
    saw_global_pax: bool,
    pending_data_end: Option<u64>,
}

impl ArchiveInspection {
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
            || entry_type.is_symlink()
            || entry_type.is_hard_link()
        {
            return Err(RepositoryWorkflowDiscoveryError::UnsupportedArchiveEntry);
        }

        let path = entry.path_bytes();
        let components = canonical_components(path.as_ref(), limits.maximum_entry_path_bytes())?;
        let (archive_root, relative_components) = components
            .split_first()
            .ok_or(RepositoryWorkflowDiscoveryError::UnsafePath)?;
        self.validate_root(archive_root, relative_components, entry_type)?;

        let relative_path = relative_components.join("/");
        if !self.seen_paths.insert(relative_path.clone()) {
            return Err(RepositoryWorkflowDiscoveryError::DuplicatePath);
        }

        if let Some(filename) = direct_workflow_filename(relative_components, ".ci") {
            let collision_key = workflow_collision_key(filename);
            if self.native_workflow_filenames.contains(&collision_key) {
                return Err(RepositoryWorkflowDiscoveryError::WorkflowPathCollision);
            }
            self.portable_workflow_filenames.insert(collision_key);
        }
        if let Some(filename) = direct_filename(relative_components, ".github") {
            let collision_key = workflow_collision_key(filename);
            if self.portable_workflow_filenames.contains(&collision_key) {
                return Err(RepositoryWorkflowDiscoveryError::WorkflowPathCollision);
            }
            self.native_workflow_filenames.insert(collision_key);
        }

        let is_workflow = is_direct_workflow(relative_components);
        if is_workflow && !entry_type.is_file() {
            return Err(RepositoryWorkflowDiscoveryError::UnsupportedWorkflowEntry);
        }
        if !entry_type.is_file() && !entry_type.is_dir() {
            return Err(RepositoryWorkflowDiscoveryError::UnsupportedArchiveEntry);
        }

        if is_workflow {
            if relative_path.len() > MAX_REPOSITORY_WORKFLOW_PATH_BYTES {
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

    fn validate_root(
        &mut self,
        archive_root: &str,
        relative_components: &[&str],
        entry_type: tar::EntryType,
    ) -> Result<(), RepositoryWorkflowDiscoveryError> {
        if let Some(expected_root) = self.root.as_deref() {
            if archive_root != expected_root {
                return Err(RepositoryWorkflowDiscoveryError::UnsafePath);
            }
        } else {
            if !relative_components.is_empty() || !entry_type.is_dir() {
                return Err(RepositoryWorkflowDiscoveryError::UnsafePath);
            }
            self.root = Some(archive_root.to_owned());
        }
        Ok(())
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

fn canonical_components(
    raw: &[u8],
    maximum_path_bytes: usize,
) -> Result<Vec<&str>, RepositoryWorkflowDiscoveryError> {
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
    let mut components = path.split('/').collect::<Vec<_>>();
    if components
        .last()
        .is_some_and(|component| component.is_empty())
    {
        components.pop();
    }
    if components.is_empty()
        || components
            .iter()
            .any(|component| component.is_empty() || matches!(*component, "." | ".."))
    {
        return Err(RepositoryWorkflowDiscoveryError::UnsafePath);
    }
    Ok(components)
}

fn is_direct_workflow(relative_components: &[&str]) -> bool {
    direct_workflow_filename(relative_components, ".ci").is_some()
}

fn direct_workflow_filename<'path>(
    relative_components: &'path [&'path str],
    owner_directory: &str,
) -> Option<&'path str> {
    let filename = direct_filename(relative_components, owner_directory)?;
    if !filename
        .rsplit_once('.')
        .is_some_and(|(_, extension)| matches!(extension, "yml" | "yaml"))
    {
        return None;
    }
    Some(filename)
}

fn direct_filename<'path>(
    relative_components: &'path [&'path str],
    owner_directory: &str,
) -> Option<&'path str> {
    if relative_components.len() != 3
        || relative_components[0] != owner_directory
        || relative_components[1] != "workflows"
    {
        return None;
    }
    Some(relative_components[2])
}

fn workflow_collision_key(filename: &str) -> String {
    filename.to_ascii_lowercase()
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
    stream_tail: RefCell<StreamTail>,
}

impl ReadLimitState {
    fn mark_exceeded(&self) {
        self.0.exceeded.set(true);
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

struct BoundedReader<R> {
    inner: R,
    remaining: u64,
    limit_state: ReadLimitState,
}

impl<R> BoundedReader<R> {
    fn new(inner: R, maximum_bytes: u64, limit_state: ReadLimitState) -> Self {
        Self {
            inner,
            remaining: maximum_bytes,
            limit_state,
        }
    }
}

impl<R: io::Read> io::Read for BoundedReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
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
    if limit_state.exceeded() {
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
    /// Gzip or tar framing, sizes, padding, or termination are invalid.
    Malformed,
    /// A configured or implementation-wide resource ceiling was exceeded.
    ResourceLimit,
    /// An archive path is non-canonical, escaping, absolute, or otherwise unsafe.
    UnsafePath,
    /// Two archive entries resolve to the same canonical relative path.
    DuplicatePath,
    /// Portable and native workflow directories contain the same direct filename.
    WorkflowPathCollision,
    /// The archive uses an unsupported entry type or metadata extension.
    UnsupportedArchiveEntry,
    /// A direct workflow path is not represented by a regular file.
    UnsupportedWorkflowEntry,
    /// The archive did not begin with the required single explicit root directory.
    MissingArchiveRoot,
}

impl fmt::Display for RepositoryWorkflowDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "repository archive is malformed",
            Self::ResourceLimit => "repository archive exceeds a configured resource limit",
            Self::UnsafePath => "repository archive contains an unsafe path or link",
            Self::DuplicatePath => "repository archive contains a duplicate path",
            Self::WorkflowPathCollision => {
                "portable and native repository workflows have a filename collision"
            }
            Self::UnsupportedArchiveEntry => {
                "repository archive contains unsupported metadata or an entry type"
            }
            Self::UnsupportedWorkflowEntry => "repository workflow path is not a regular file",
            Self::MissingArchiveRoot => "repository archive root is missing",
        })
    }
}

impl Error for RepositoryWorkflowDiscoveryError {}
