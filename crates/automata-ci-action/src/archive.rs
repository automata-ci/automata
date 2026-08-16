use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Cursor, Read as _},
};

use automata_ci_scm::RepositorySnapshot;
use bytes::Bytes;
use flate2::read::MultiGzDecoder;

use crate::{
    ActionArchiveError, ActionBundleLimits, ActionDefinitionDocument, ActionDefinitionKind,
    ActionSubpath,
};

const ACTION_YML: &[u8] = b"action.yml";
const ACTION_YAML: &[u8] = b"action.yaml";
const DOCKERFILE: &[u8] = b"Dockerfile";
const DOCKERFILE_LOWER: &[u8] = b"dockerfile";
const TAR_BLOCK_BYTES: usize = 512;
const TAR_BLOCK_BYTES_U64: u64 = TAR_BLOCK_BYTES as u64;
const WINDOWS_MAX_ENTRY_DEPTH: usize = 64;
const WINDOWS_MAX_REGULAR_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// Exact bounded expansion facts reproduced while validating a Windows action
/// archive before scheduling and again by the privileged materializer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsActionArchiveReport {
    entry_count: u32,
    regular_file_count: u32,
    expanded_bytes: u64,
    maximum_regular_file_bytes: u64,
    maximum_depth: u16,
}

impl WindowsActionArchiveReport {
    /// Returns every tar entry counted against the archive ceiling.
    #[must_use]
    pub const fn entry_count(self) -> u32 {
        self.entry_count
    }

    /// Returns the number of regular files in the archive.
    #[must_use]
    pub const fn regular_file_count(self) -> u32 {
        self.regular_file_count
    }

    /// Returns the aggregate declared expanded bytes consumed by all entries.
    #[must_use]
    pub const fn expanded_bytes(self) -> u64 {
        self.expanded_bytes
    }

    /// Returns the largest declared regular-file size.
    #[must_use]
    pub const fn maximum_regular_file_bytes(self) -> u64 {
        self.maximum_regular_file_bytes
    }

    /// Returns the deepest materialized path below the archive root.
    #[must_use]
    pub const fn maximum_depth(self) -> u16 {
        self.maximum_depth
    }
}

/// Validates a compressed SCM archive and selects one action definition.
///
/// The archive is never extracted to the control-plane filesystem. Every
/// regular file is consumed so gzip/tar integrity and aggregate expansion
/// limits are checked even when the file is unrelated to the selected action.
/// `action.yml` takes precedence over `action.yaml`; metadata takes precedence
/// over `Dockerfile`, matching the reviewed GitHub runner behavior.
/// The snapshot is expected to have crossed an SCM boundary that enforced
/// [`ActionBundleLimits::compressed`]; this function enforces the remaining
/// expanded-archive limits.
///
/// # Errors
///
/// Returns a fail-closed archive error for malformed encodings, unsafe paths or
/// links, duplicates, unsupported entry types, resource-limit exhaustion, or a
/// missing definition.
pub fn inspect_archive(
    snapshot: &RepositorySnapshot,
    subpath: &ActionSubpath,
    limits: ActionBundleLimits,
) -> Result<ActionDefinitionDocument, ActionArchiveError> {
    inspect_archive_bytes(snapshot.bytes(), subpath, limits)
}

/// Validates that an already-inspected repository archive can be materialized
/// into a Windows job workspace without entering an ambiguous NTFS namespace.
///
/// This is deliberately narrower than the provider-neutral archive contract.
/// Windows materialization rejects every link, reparse-capable entry type,
/// case-insensitive collision, alternate-data-stream separator, reserved DOS
/// name, trailing space or dot, and non-ASCII member name. The initial Windows
/// profile therefore fails closed instead of guessing about Unicode
/// normalization or link-creation privileges.
///
/// Callers must invoke this before creating or attaching a sandbox. The
/// archive is decoded independently so a prepared-action object cannot bypass
/// the target-platform materialization policy.
///
/// # Errors
///
/// Returns a bounded archive error for malformed input, unsafe Windows paths,
/// links or special entries, case-fold collisions, or resource exhaustion.
#[allow(clippy::too_many_lines)]
pub fn validate_windows_materialization_archive(
    bytes: &[u8],
    limits: ActionBundleLimits,
) -> Result<WindowsActionArchiveReport, ActionArchiveError> {
    if u64::try_from(bytes.len())
        .ok()
        .is_none_or(|length| length > limits.compressed().maximum_bytes())
    {
        return Err(ActionArchiveError::ResourceLimit);
    }
    let decoder = MultiGzDecoder::new(Cursor::new(bytes));
    let mut archive = tar::Archive::new(decoder);
    let mut root = None::<Vec<u8>>;
    let mut namespace_paths = BTreeMap::<String, WindowsNamespaceEntry>::new();
    let mut entry_count = 0_usize;
    let mut expanded_bytes = 0_u64;
    let mut path_index_bytes = 0_usize;
    let mut saw_repository_entry = false;
    let mut regular_file_count = 0_u32;
    let mut maximum_regular_file_bytes = 0_u64;
    let mut maximum_depth = 0_u16;
    let entries = archive
        .entries()
        .map_err(|_| ActionArchiveError::Malformed)?
        .raw(true);
    for entry in entries {
        entry_count = entry_count
            .checked_add(1)
            .ok_or(ActionArchiveError::ResourceLimit)?;
        if entry_count > limits.maximum_entries() {
            return Err(ActionArchiveError::ResourceLimit);
        }
        let mut entry = entry.map_err(|_| ActionArchiveError::Malformed)?;
        let entry_type = entry.header().entry_type();
        if entry_type.is_pax_global_extensions() {
            if saw_repository_entry {
                return Err(ActionArchiveError::Malformed);
            }
            let declared_size = declared_size(&entry)?;
            expanded_bytes = checked_expanded_size(expanded_bytes, declared_size, limits)?;
            validate_global_pax(&mut entry, declared_size, limits.maximum_definition_bytes())?;
            continue;
        }
        if entry_type.is_gnu_longname()
            || entry_type.is_gnu_longlink()
            || entry_type.is_pax_local_extensions()
        {
            return Err(ActionArchiveError::UnsupportedEntry);
        }
        saw_repository_entry = true;
        if !(entry_type.is_dir() || entry_type.is_file()) {
            return Err(ActionArchiveError::UnsupportedEntry);
        }

        let path = entry.path_bytes();
        if path.len() > limits.maximum_entry_path_bytes() {
            return Err(ActionArchiveError::ResourceLimit);
        }
        let components = archive_components(&path)?;
        if components
            .iter()
            .any(|component| !valid_windows_archive_component(component))
        {
            return Err(ActionArchiveError::UnsafePath);
        }
        let (archive_root, relative) = components
            .split_first()
            .ok_or(ActionArchiveError::UnsafePath)?;
        if relative.len() > WINDOWS_MAX_ENTRY_DEPTH {
            return Err(ActionArchiveError::ResourceLimit);
        }
        maximum_depth = maximum_depth
            .max(u16::try_from(relative.len()).map_err(|_| ActionArchiveError::ResourceLimit)?);
        if let Some(expected_root) = &root {
            if expected_root != archive_root {
                return Err(ActionArchiveError::UnsafePath);
            }
        } else {
            root = Some(archive_root.clone());
        }
        record_windows_relative_namespace(
            relative,
            entry_type.is_dir(),
            &mut namespace_paths,
            &mut path_index_bytes,
            limits,
        )?;

        let declared_size = declared_size(&entry)?;
        if entry_type.is_file() && declared_size > WINDOWS_MAX_REGULAR_FILE_BYTES {
            return Err(ActionArchiveError::ResourceLimit);
        }
        if entry_type.is_file() {
            regular_file_count = regular_file_count
                .checked_add(1)
                .ok_or(ActionArchiveError::ResourceLimit)?;
            maximum_regular_file_bytes = maximum_regular_file_bytes.max(declared_size);
        }
        expanded_bytes = checked_expanded_size(expanded_bytes, declared_size, limits)?;
        consume_entry(&mut entry, declared_size)?;
    }
    let mut decoder = archive.into_inner();
    let remaining_bytes = limits
        .maximum_expanded_bytes()
        .checked_sub(expanded_bytes)
        .ok_or(ActionArchiveError::ResourceLimit)?;
    verify_trailing_zeros(&mut decoder, remaining_bytes)?;
    Ok(WindowsActionArchiveReport {
        entry_count: u32::try_from(entry_count).map_err(|_| ActionArchiveError::ResourceLimit)?,
        regular_file_count,
        expanded_bytes,
        maximum_regular_file_bytes,
        maximum_depth,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsNamespaceKind {
    ImplicitDirectory,
    Directory,
    File,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WindowsNamespaceEntry {
    spelling: String,
    kind: WindowsNamespaceKind,
}

fn record_windows_relative_namespace(
    relative: &[Vec<u8>],
    entry_is_directory: bool,
    namespace_paths: &mut BTreeMap<String, WindowsNamespaceEntry>,
    path_index_bytes: &mut usize,
    limits: ActionBundleLimits,
) -> Result<(), ActionArchiveError> {
    let components = relative
        .iter()
        .map(|component| std::str::from_utf8(component))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ActionArchiveError::UnsafePath)?;
    record_windows_namespace_path(
        namespace_paths,
        String::new(),
        String::new(),
        if components.is_empty() {
            if entry_is_directory {
                WindowsNamespaceKind::Directory
            } else {
                WindowsNamespaceKind::File
            }
        } else {
            WindowsNamespaceKind::ImplicitDirectory
        },
        path_index_bytes,
        limits,
    )?;
    let mut spelling = String::new();
    let mut folded = String::new();
    for (index, component) in components.iter().enumerate() {
        if index > 0 {
            spelling.push('\\');
            folded.push('\\');
        }
        spelling.push_str(component);
        folded.push_str(&component.to_ascii_lowercase());
        record_windows_namespace_path(
            namespace_paths,
            folded.clone(),
            spelling.clone(),
            if index + 1 != components.len() {
                WindowsNamespaceKind::ImplicitDirectory
            } else if entry_is_directory {
                WindowsNamespaceKind::Directory
            } else {
                WindowsNamespaceKind::File
            },
            path_index_bytes,
            limits,
        )?;
    }
    Ok(())
}

fn record_windows_namespace_path(
    namespace_paths: &mut BTreeMap<String, WindowsNamespaceEntry>,
    folded: String,
    spelling: String,
    kind: WindowsNamespaceKind,
    path_index_bytes: &mut usize,
    limits: ActionBundleLimits,
) -> Result<(), ActionArchiveError> {
    if let Some(existing) = namespace_paths.get_mut(&folded) {
        if existing.spelling != spelling {
            return Err(ActionArchiveError::DuplicatePath);
        }
        return match (existing.kind, kind) {
            (
                WindowsNamespaceKind::ImplicitDirectory | WindowsNamespaceKind::Directory,
                WindowsNamespaceKind::ImplicitDirectory,
            ) => Ok(()),
            (WindowsNamespaceKind::ImplicitDirectory, WindowsNamespaceKind::Directory) => {
                existing.kind = WindowsNamespaceKind::Directory;
                Ok(())
            }
            _ => Err(ActionArchiveError::DuplicatePath),
        };
    }
    *path_index_bytes = path_index_bytes
        .checked_add(folded.len())
        .ok_or(ActionArchiveError::ResourceLimit)?;
    if *path_index_bytes > limits.maximum_path_index_bytes() {
        return Err(ActionArchiveError::ResourceLimit);
    }
    namespace_paths.insert(folded, WindowsNamespaceEntry { spelling, kind });
    Ok(())
}

fn valid_windows_archive_component(component: &[u8]) -> bool {
    if component.is_empty()
        || !component.is_ascii()
        || component.ends_with(b" ")
        || component.ends_with(b".")
        || component.iter().any(|byte| {
            byte.is_ascii_control()
                || matches!(byte, b'<' | b'>' | b':' | b'"' | b'|' | b'?' | b'*')
        })
    {
        return false;
    }
    if component == b"." || component == b".." {
        return false;
    }
    if component.starts_with(b".") {
        return true;
    }
    let stem = component
        .split(|byte| *byte == b'.')
        .next()
        .unwrap_or(component);
    let stem = stem
        .iter()
        .rposition(|byte| !matches!(byte, b' ' | b'.'))
        .map_or(&[][..], |last| &stem[..=last]);
    if stem.is_empty() || windows_short_name_shaped(stem) {
        return false;
    }
    let upper = stem.iter().map(u8::to_ascii_uppercase).collect::<Vec<_>>();
    !matches!(
        upper.as_slice(),
        b"CON" | b"PRN" | b"AUX" | b"NUL" | b"CLOCK$" | b"CONIN$" | b"CONOUT$"
    ) && !upper
        .strip_prefix(b"COM")
        .or_else(|| upper.strip_prefix(b"LPT"))
        .is_some_and(|suffix| suffix.len() == 1 && matches!(suffix[0], b'1'..=b'9'))
}

fn windows_short_name_shaped(stem: &[u8]) -> bool {
    let Some(tilde) = stem.iter().rposition(|byte| *byte == b'~') else {
        return false;
    };
    let (prefix, suffix) = stem.split_at(tilde);
    let digits = &suffix[1..];
    !prefix.is_empty()
        && prefix.len() <= 6
        && !digits.is_empty()
        && matches!(digits[0], b'1'..=b'9')
        && digits[1..].iter().all(u8::is_ascii_digit)
}

/// Validates immutable archive bytes and selects one action definition.
///
/// Callers must verify immutable content identity and enforce
/// [`ActionBundleLimits::compressed`] before invoking this function. The
/// inspector applies entry-count, expanded-byte, definition-byte, and path-byte
/// limits plus an aggregate canonical-path-index budget, but does not truncate
/// the already-materialized compressed input.
///
/// # Errors
///
/// Returns the same fail-closed errors as [`inspect_archive`].
pub fn inspect_archive_bytes(
    bytes: &Bytes,
    subpath: &ActionSubpath,
    limits: ActionBundleLimits,
) -> Result<ActionDefinitionDocument, ActionArchiveError> {
    let decoder = MultiGzDecoder::new(Cursor::new(bytes.as_ref()));
    let mut archive = tar::Archive::new(decoder);
    let target = target_paths(subpath)?;
    let (definitions, expanded_bytes) = inspect_entries(&mut archive, &target, limits)?;

    let mut decoder = archive.into_inner();
    let remaining_bytes = limits
        .maximum_expanded_bytes()
        .checked_sub(expanded_bytes)
        .ok_or(ActionArchiveError::ResourceLimit)?;
    verify_trailing_zeros(&mut decoder, remaining_bytes)?;
    definitions
        .into_iter()
        .next()
        .map(|(_, document)| document)
        .ok_or(ActionArchiveError::MissingDefinition)
}

type DefinitionCandidates = BTreeMap<DefinitionRank, ActionDefinitionDocument>;
type DefinitionTargets = BTreeMap<Vec<u8>, TargetDefinition>;

fn inspect_entries<R: io::Read>(
    archive: &mut tar::Archive<R>,
    target: &DefinitionTargets,
    limits: ActionBundleLimits,
) -> Result<(DefinitionCandidates, u64), ActionArchiveError> {
    let mut root = None::<Vec<u8>>;
    let mut seen = BTreeSet::<Vec<u8>>::new();
    let mut definitions = DefinitionCandidates::new();
    let mut entry_count = 0_usize;
    let mut expanded_bytes = 0_u64;
    let mut path_index_bytes = 0_usize;
    let mut saw_repository_entry = false;
    let entries = archive
        .entries()
        .map_err(|_| ActionArchiveError::Malformed)?
        .raw(true);
    for entry in entries {
        entry_count = entry_count
            .checked_add(1)
            .ok_or(ActionArchiveError::ResourceLimit)?;
        if entry_count > limits.maximum_entries() {
            return Err(ActionArchiveError::ResourceLimit);
        }
        let mut entry = entry.map_err(|_| ActionArchiveError::Malformed)?;
        let entry_type = entry.header().entry_type();
        if entry_type.is_pax_global_extensions() {
            if saw_repository_entry {
                return Err(ActionArchiveError::Malformed);
            }
            let declared_size = declared_size(&entry)?;
            expanded_bytes = checked_expanded_size(expanded_bytes, declared_size, limits)?;
            validate_global_pax(&mut entry, declared_size, limits.maximum_definition_bytes())?;
            continue;
        }
        if entry_type.is_gnu_longname()
            || entry_type.is_gnu_longlink()
            || entry_type.is_pax_local_extensions()
        {
            return Err(ActionArchiveError::UnsupportedEntry);
        }
        saw_repository_entry = true;
        let path = entry.path_bytes();
        if path.len() > limits.maximum_entry_path_bytes() {
            return Err(ActionArchiveError::ResourceLimit);
        }
        let components = archive_components(&path)?;
        let (archive_root, relative) = components
            .split_first()
            .ok_or(ActionArchiveError::UnsafePath)?;
        if let Some(expected_root) = &root {
            if expected_root.as_slice() != archive_root.as_slice() {
                return Err(ActionArchiveError::UnsafePath);
            }
        } else {
            root = Some(archive_root.clone());
        }
        let relative_path = join_components(relative);
        if !seen.insert(relative_path.clone()) {
            return Err(ActionArchiveError::DuplicatePath);
        }
        path_index_bytes = path_index_bytes
            .checked_add(relative_path.len())
            .ok_or(ActionArchiveError::ResourceLimit)?;
        if path_index_bytes > limits.maximum_path_index_bytes() {
            return Err(ActionArchiveError::ResourceLimit);
        }

        let declared_size = declared_size(&entry)?;
        expanded_bytes = checked_expanded_size(expanded_bytes, declared_size, limits)?;

        if entry_type.is_dir() {
            consume_entry(&mut entry, declared_size)?;
            continue;
        }
        if entry_type.is_symlink() {
            validate_link(&mut entry, relative, limits.maximum_entry_path_bytes())?;
            consume_entry(&mut entry, declared_size)?;
            continue;
        }
        if entry_type.is_hard_link() {
            return Err(ActionArchiveError::UnsupportedEntry);
        }
        if !entry_type.is_file() {
            return Err(ActionArchiveError::UnsupportedEntry);
        }

        if let Some(candidate) = target.get(&relative_path) {
            let bytes =
                read_definition(&mut entry, declared_size, limits.maximum_definition_bytes())?;
            definitions.insert(
                candidate.rank,
                ActionDefinitionDocument::new(
                    candidate.kind,
                    candidate.display_path.clone(),
                    bytes,
                ),
            );
        } else {
            consume_entry(&mut entry, declared_size)?;
        }
    }
    Ok((definitions, expanded_bytes))
}

fn declared_size<R: io::Read>(entry: &tar::Entry<'_, R>) -> Result<u64, ActionArchiveError> {
    entry
        .header()
        .size()
        .map_err(|_| ActionArchiveError::Malformed)
}

fn consume_entry<R: io::Read>(
    entry: &mut tar::Entry<'_, R>,
    declared_size: u64,
) -> Result<(), ActionArchiveError> {
    let copied = io::copy(entry, &mut io::sink()).map_err(|_| ActionArchiveError::Malformed)?;
    if copied != declared_size {
        return Err(ActionArchiveError::Malformed);
    }
    Ok(())
}

fn checked_expanded_size(
    current: u64,
    additional: u64,
    limits: ActionBundleLimits,
) -> Result<u64, ActionArchiveError> {
    let next = current
        .checked_add(additional)
        .ok_or(ActionArchiveError::ResourceLimit)?;
    if next > limits.maximum_expanded_bytes() {
        return Err(ActionArchiveError::ResourceLimit);
    }
    Ok(next)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum DefinitionRank {
    ActionYml,
    ActionYaml,
    Dockerfile,
    DockerfileLower,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TargetDefinition {
    rank: DefinitionRank,
    kind: ActionDefinitionKind,
    display_path: String,
}

fn target_paths(subpath: &ActionSubpath) -> Result<DefinitionTargets, ActionArchiveError> {
    let prefix: Vec<&[u8]> = subpath.components().collect();
    let mut targets = BTreeMap::new();
    for (name, rank, kind) in [
        (
            ACTION_YML,
            DefinitionRank::ActionYml,
            ActionDefinitionKind::MetadataYaml,
        ),
        (
            ACTION_YAML,
            DefinitionRank::ActionYaml,
            ActionDefinitionKind::MetadataYaml,
        ),
        (
            DOCKERFILE,
            DefinitionRank::Dockerfile,
            ActionDefinitionKind::Dockerfile,
        ),
        (
            DOCKERFILE_LOWER,
            DefinitionRank::DockerfileLower,
            ActionDefinitionKind::Dockerfile,
        ),
    ] {
        let mut components = prefix.clone();
        components.push(name);
        let path = join_borrowed_components(&components);
        let display =
            String::from_utf8(path.clone()).map_err(|_| ActionArchiveError::UnsafePath)?;
        targets.insert(
            path,
            TargetDefinition {
                rank,
                kind,
                display_path: display,
            },
        );
    }
    Ok(targets)
}

fn archive_components(raw: &[u8]) -> Result<Vec<Vec<u8>>, ActionArchiveError> {
    if raw.is_empty()
        || raw.starts_with(b"/")
        || raw.contains(&b'\\')
        || raw.iter().any(u8::is_ascii_control)
    {
        return Err(ActionArchiveError::UnsafePath);
    }
    let mut components: Vec<Vec<u8>> = raw
        .split(|byte| *byte == b'/')
        .map(<[u8]>::to_vec)
        .collect();
    if components.last().is_some_and(Vec::is_empty) {
        components.pop();
    }
    if components.is_empty()
        || components
            .iter()
            .any(|component| component.is_empty() || component == b"." || component == b"..")
    {
        return Err(ActionArchiveError::UnsafePath);
    }
    Ok(components)
}

fn validate_link<R: io::Read>(
    entry: &mut tar::Entry<'_, R>,
    relative_path: &[Vec<u8>],
    maximum_path_bytes: usize,
) -> Result<(), ActionArchiveError> {
    let target = entry
        .link_name_bytes()
        .ok_or(ActionArchiveError::UnsafePath)?;
    if target.is_empty()
        || target.len() > maximum_path_bytes
        || target.starts_with(b"/")
        || target.contains(&b'\\')
        || target.iter().any(u8::is_ascii_control)
    {
        return Err(ActionArchiveError::UnsafePath);
    }

    let mut resolved = relative_path
        .get(..relative_path.len().saturating_sub(1))
        .unwrap_or_default()
        .to_vec();
    for component in target.split(|byte| *byte == b'/') {
        match component {
            b"" | b"." => {}
            b".." => {
                resolved.pop().ok_or(ActionArchiveError::UnsafePath)?;
            }
            value => resolved.push(value.to_vec()),
        }
    }
    if resolved.is_empty() {
        return Err(ActionArchiveError::UnsafePath);
    }
    Ok(())
}

fn validate_global_pax<R: io::Read>(
    entry: &mut tar::Entry<'_, R>,
    declared_size: u64,
    maximum_bytes: u64,
) -> Result<(), ActionArchiveError> {
    let bytes = read_definition(entry, declared_size, maximum_bytes)?;
    let mut offset = 0_usize;
    let mut keys = BTreeSet::new();
    while offset < bytes.len() {
        let remainder = &bytes[offset..];
        let space = remainder
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or(ActionArchiveError::Malformed)?;
        let length_text = &remainder[..space];
        if length_text.is_empty()
            || (length_text.len() > 1 && length_text[0] == b'0')
            || !length_text.iter().all(u8::is_ascii_digit)
        {
            return Err(ActionArchiveError::Malformed);
        }
        let length = std::str::from_utf8(length_text)
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or(ActionArchiveError::Malformed)?;
        let record_start = offset
            .checked_add(space + 1)
            .ok_or(ActionArchiveError::Malformed)?;
        let end = offset
            .checked_add(length)
            .filter(|end| record_start <= *end && *end <= bytes.len())
            .ok_or(ActionArchiveError::Malformed)?;
        let record = &bytes[record_start..end];
        let record = record
            .strip_suffix(b"\n")
            .ok_or(ActionArchiveError::Malformed)?;
        let separator = record
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or(ActionArchiveError::Malformed)?;
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
            return Err(ActionArchiveError::UnsafePath);
        }
        offset = end;
    }
    Ok(())
}

fn read_definition<R: io::Read>(
    entry: &mut tar::Entry<'_, R>,
    declared_size: u64,
    maximum_bytes: u64,
) -> Result<Bytes, ActionArchiveError> {
    if declared_size > maximum_bytes {
        return Err(ActionArchiveError::ResourceLimit);
    }
    let capacity = usize::try_from(declared_size).map_err(|_| ActionArchiveError::ResourceLimit)?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut limited = entry.take(maximum_bytes.saturating_add(1));
    limited
        .read_to_end(&mut bytes)
        .map_err(|_| ActionArchiveError::Malformed)?;
    let actual_size = u64::try_from(bytes.len()).map_err(|_| ActionArchiveError::ResourceLimit)?;
    if actual_size > maximum_bytes {
        return Err(ActionArchiveError::ResourceLimit);
    }
    if actual_size != declared_size {
        return Err(ActionArchiveError::Malformed);
    }
    Ok(Bytes::from(bytes))
}

fn join_components(components: &[Vec<u8>]) -> Vec<u8> {
    join_borrowed_components(&components.iter().map(Vec::as_slice).collect::<Vec<_>>())
}

fn join_borrowed_components(components: &[&[u8]]) -> Vec<u8> {
    let size = components
        .iter()
        .map(|component| component.len())
        .sum::<usize>()
        .saturating_add(components.len().saturating_sub(1));
    let mut path = Vec::with_capacity(size);
    for (index, component) in components.iter().enumerate() {
        if index > 0 {
            path.push(b'/');
        }
        path.extend_from_slice(component);
    }
    path
}

fn verify_trailing_zeros<R: io::Read>(
    reader: &mut R,
    maximum_bytes: u64,
) -> Result<(), ActionArchiveError> {
    if maximum_bytes < TAR_BLOCK_BYTES_U64 {
        return Err(ActionArchiveError::ResourceLimit);
    }
    let mut second_end_block = [0_u8; TAR_BLOCK_BYTES];
    reader
        .read_exact(&mut second_end_block)
        .map_err(|_| ActionArchiveError::Malformed)?;
    if second_end_block.iter().any(|byte| *byte != 0) {
        return Err(ActionArchiveError::Malformed);
    }

    let maximum_trailing_bytes = maximum_bytes - TAR_BLOCK_BYTES_U64;
    let mut limited = reader.take(maximum_trailing_bytes.saturating_add(1));
    let copied = io::copy(&mut limited, &mut ZeroPaddingVerifier)
        .map_err(|_| ActionArchiveError::Malformed)?;
    if copied > maximum_trailing_bytes {
        return Err(ActionArchiveError::ResourceLimit);
    }
    if copied % TAR_BLOCK_BYTES_U64 != 0 {
        return Err(ActionArchiveError::Malformed);
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
