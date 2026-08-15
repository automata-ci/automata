use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Cursor, Read as _, Write},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use automata_ci_core::Sha256Digest;
use automata_ci_workflow_github::{
    RepositoryPathValidationError, RepositoryPathValidator, RepositoryWorkflowDiscoveryLimits,
};
use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _, ambient_authority};
use cap_std::fs::{Dir, File, Metadata, OpenOptions};
use flate2::{Compression, GzBuilder};
use sha2::{Digest as _, Sha256};
use tar::{Builder as TarBuilder, EntryType, Header};
use thiserror::Error;
use tokio::{io::AsyncWriteExt as _, process::Command as ProcessCommand, time::timeout};
use tokio_util::sync::CancellationToken;

use super::{
    CaptureFailure, CommandFailure, MAX_COMMAND_STREAM_BYTES, read_bounded,
    snapshot_limits::local_snapshot_limits, spawn_contained, terminate_process_tree,
    terminate_remaining_process_tree,
};

const SNAPSHOT_ROOT: &str = "worktree";
const GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_GIT_COORDINATE_FIELD_BYTES: usize = 16 * 1_024;
const MAX_GIT_COORDINATES_BYTES: usize = 4 * (MAX_GIT_COORDINATE_FIELD_BYTES + 2);
const MAX_GIT_LOCATOR_BYTES: usize = MAX_GIT_COORDINATE_FIELD_BYTES;
const MAX_GIT_HEAD_BYTES: usize = 128;
const TRUSTED_GIT_EXECUTABLE: &str = "/usr/bin/git";
const GIT_NULL_DEVICE: &str = "/dev/null";

#[derive(Debug)]
struct GitExecutable {
    path: PathBuf,
    identity: ExecutableIdentity,
    #[cfg(test)]
    fixture: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecutableIdentity {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    mode: u32,
    owner: u32,
}

impl GitExecutable {
    fn resolve() -> Result<Self, LocalSnapshotError> {
        let path = PathBuf::from(TRUSTED_GIT_EXECUTABLE);
        let metadata = trusted_executable_metadata(&path)?;
        Ok(Self {
            path,
            identity: ExecutableIdentity::new(&metadata),
            #[cfg(test)]
            fixture: false,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn verify(&self) -> Result<(), LocalSnapshotError> {
        #[cfg(test)]
        if self.fixture {
            return Ok(());
        }
        let metadata = trusted_executable_metadata(&self.path)?;
        if ExecutableIdentity::new(&metadata) != self.identity {
            return Err(LocalSnapshotError::new(
                LocalSnapshotErrorCode::GitExecutableChanged,
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    fn fixture(path: &Path) -> Self {
        Self {
            path: path.to_owned(),
            identity: ExecutableIdentity {
                device: 0,
                inode: 0,
                length: 0,
                modified_seconds: 0,
                modified_nanoseconds: 0,
                changed_seconds: 0,
                changed_nanoseconds: 0,
                mode: 0,
                owner: 0,
            },
            fixture: true,
        }
    }
}

impl ExecutableIdentity {
    fn new(metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;

        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
            mode: metadata.mode(),
            owner: metadata.uid(),
        }
    }
}

#[cfg(unix)]
fn trusted_executable_metadata(path: &Path) -> Result<fs::Metadata, LocalSnapshotError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if !path.is_absolute() {
        return Err(LocalSnapshotError::new(
            LocalSnapshotErrorCode::GitUnavailable,
        ));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::GitUnavailable))?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o111 == 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(LocalSnapshotError::new(
            LocalSnapshotErrorCode::GitUnavailable,
        ));
    }
    Ok(metadata)
}

fn check_cancelled(cancellation: &CancellationToken) -> Result<(), LocalSnapshotError> {
    if cancellation.is_cancelled() {
        Err(LocalSnapshotError::new(LocalSnapshotErrorCode::Cancelled))
    } else {
        Ok(())
    }
}

fn validate_local_snapshot_limits(
    limits: RepositoryWorkflowDiscoveryLimits,
) -> Result<(), LocalSnapshotError> {
    let maximum = local_snapshot_limits();
    if limits.maximum_compressed_bytes() > maximum.maximum_compressed_bytes()
        || limits.maximum_decompressed_bytes() > maximum.maximum_decompressed_bytes()
        || limits.maximum_entries() > maximum.maximum_entries()
        || limits.maximum_expanded_bytes() > maximum.maximum_expanded_bytes()
        || limits.maximum_entry_path_bytes() > maximum.maximum_entry_path_bytes()
        || limits.maximum_workflows() > maximum.maximum_workflows()
        || limits.maximum_workflow_bytes() > maximum.maximum_workflow_bytes()
    {
        return Err(LocalSnapshotError::new(
            LocalSnapshotErrorCode::ResourceLimit,
        ));
    }
    Ok(())
}

/// Request to seal one live Git worktree into a bounded immutable snapshot.
#[derive(Clone, Debug)]
pub(crate) struct LocalSnapshotRequest {
    directory: PathBuf,
    limits: RepositoryWorkflowDiscoveryLimits,
}

impl LocalSnapshotRequest {
    /// Creates a request rooted at a worktree or any directory beneath it.
    #[must_use]
    pub(crate) fn new(
        directory: impl Into<PathBuf>,
        limits: RepositoryWorkflowDiscoveryLimits,
    ) -> Self {
        Self {
            directory: directory.into(),
            limits,
        }
    }

    /// Returns the caller-supplied worktree search directory.
    #[must_use]
    pub(crate) fn directory(&self) -> &Path {
        &self.directory
    }

    /// Returns the shared snapshot-construction and workflow-discovery limits.
    #[must_use]
    pub(crate) const fn limits(&self) -> RepositoryWorkflowDiscoveryLimits {
        self.limits
    }
}

/// One private sealed local source archive.
///
/// The inventory is Git's tracked index names plus non-ignored untracked names.
/// Tracked deletions are absent, staged additions are present, and all regular
/// file bytes come from the live worktree rather than the index. Git's tracked
/// mode determines executable and symbolic-link representation, including the
/// ordinary-file placeholders used by Windows checkouts. Index conflicts and
/// submodules fail closed, as do sparse-checkout and assume-unchanged flags
/// that can hide live state. No source operation updates the index or invokes
/// hooks or automatic maintenance.
pub(crate) struct LocalSnapshot {
    head: String,
    dirty: bool,
    digest: Sha256Digest,
    archive: Vec<u8>,
    entry_count: usize,
    expanded_bytes: u64,
}

impl std::fmt::Debug for LocalSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalSnapshot")
            .field("head", &self.head)
            .field("dirty", &self.dirty)
            .field("digest", &self.digest)
            .field("entry_count", &self.entry_count)
            .field("expanded_bytes", &self.expanded_bytes)
            .finish_non_exhaustive()
    }
}

impl LocalSnapshot {
    /// Returns the exact commit at `HEAD` while the worktree was sealed.
    #[must_use]
    pub(crate) fn head(&self) -> &str {
        &self.head
    }

    /// Returns whether Git reported staged, unstaged, or non-ignored untracked
    /// worktree state while the snapshot was sealed.
    #[must_use]
    pub(crate) const fn dirty(&self) -> bool {
        self.dirty
    }

    /// Returns SHA-256 over the exact deterministic gzip bytes retained here.
    #[must_use]
    pub(crate) const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Returns the exact immutable tar.gz bytes consumed by workflow discovery.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn archive_bytes(&self) -> &[u8] {
        &self.archive
    }

    /// Consumes the private snapshot into the exact archive passed to the
    /// sealed workflow-analysis boundary.
    pub(crate) fn into_archive(self) -> Vec<u8> {
        self.archive
    }

    /// Returns the number of regular-file and symbolic-link entries in the
    /// sealed live-worktree inventory.
    #[must_use]
    pub(crate) const fn entry_count(&self) -> usize {
        self.entry_count
    }

    /// Returns the sum of regular-file bytes retained in the archive.
    #[must_use]
    pub(crate) const fn expanded_bytes(&self) -> u64 {
        self.expanded_bytes
    }
}

/// Seals a bounded, deterministic snapshot without changing Git or the
/// worktree.
///
/// # Errors
///
/// Fails closed when the requested directory cannot be pinned before Git runs,
/// Git's reported root and repository authority do not resolve back to that
/// directory, the `.git` locator is not a no-follow directory or an exact
/// linked-worktree gitfile, Git state is ambiguous, an ancestor cannot be
/// opened without following a link, a path or file type is unsafe, a resource
/// bound is exceeded, or the inventory mutates while it is being read. Windows
/// reparse points, including junctions, are not admitted.
pub(crate) async fn capture_snapshot(
    request: LocalSnapshotRequest,
    cancellation: &CancellationToken,
) -> Result<LocalSnapshot, LocalSnapshotError> {
    let git = GitExecutable::resolve()?;
    capture_snapshot_with_executable(request, &git, cancellation).await
}

async fn capture_snapshot_with_executable(
    request: LocalSnapshotRequest,
    git: &GitExecutable,
    cancellation: &CancellationToken,
) -> Result<LocalSnapshot, LocalSnapshotError> {
    check_cancelled(cancellation)?;
    validate_local_snapshot_limits(request.limits())?;
    let requested_path = std::path::absolute(request.directory())
        .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::NotGitWorktree))?;
    let requested = PinnedDirectory::open(&requested_path)?;
    let coordinates = discover_git_coordinates(git, &requested_path, cancellation).await?;
    requested.verify_ambient_path(&requested_path)?;
    let authority = GitAuthority::pin(coordinates, &requested)?;
    verify_bound_git_coordinates(
        git,
        &authority,
        LocalSnapshotErrorCode::NotGitWorktree,
        cancellation,
    )
    .await?;
    let path_validator =
        RepositoryPathValidator::new(SNAPSHOT_ROOT, request.limits().maximum_entry_path_bytes())
            .map_err(local_path_validation_error)?;
    let initial = capture_git_state(git, &authority, request.limits(), cancellation).await?;
    let inventory = parse_inventory(&initial, request.limits(), path_validator)?;
    let initial_scan = scan_worktree(
        git,
        &authority,
        request.limits(),
        path_validator,
        cancellation,
    )
    .await?;
    let capture_worktree = authority.worktree.clone_pinned()?;
    let capture_cancellation = cancellation.clone();
    let limits = request.limits();
    let captured = run_blocking(LocalSnapshotErrorCode::ConcurrentMutation, move || {
        capture_entries(
            &capture_worktree,
            &inventory,
            limits,
            path_validator,
            &capture_cancellation,
        )
    })
    .await?;
    let final_state = capture_git_state(git, &authority, request.limits(), cancellation).await?;
    let final_scan = scan_worktree(
        git,
        &authority,
        request.limits(),
        path_validator,
        cancellation,
    )
    .await?;
    verify_git_state(&initial, &final_state)?;
    if initial_scan != final_scan {
        return Err(LocalSnapshotError::new(
            LocalSnapshotErrorCode::ConcurrentMutation,
        ));
    }
    let CapturedInventory {
        entries,
        deleted_paths,
        expanded_bytes,
    } = captured;
    let deletion_worktree = authority.worktree.clone_pinned()?;
    let deletion_cancellation = cancellation.clone();
    run_blocking(LocalSnapshotErrorCode::ConcurrentMutation, move || {
        verify_deleted_paths(&deletion_worktree, &deleted_paths, &deletion_cancellation)
    })
    .await?;
    verify_bound_git_coordinates(
        git,
        &authority,
        LocalSnapshotErrorCode::ConcurrentMutation,
        cancellation,
    )
    .await?;
    requested.verify_ambient_path(&requested_path)?;
    authority.verify(LocalSnapshotErrorCode::ConcurrentMutation)?;
    git.verify()?;
    check_cancelled(cancellation)?;

    let entry_count = entries.len();
    let archive_cancellation = cancellation.clone();
    let limits = request.limits();
    let (archive, digest) = run_blocking(LocalSnapshotErrorCode::ArchiveEncoding, move || {
        let archive = build_archive(&entries, limits, &archive_cancellation)?;
        let digest = Sha256Digest::from_bytes(Sha256::digest(&archive).into());
        Ok((archive, digest))
    })
    .await?;
    Ok(LocalSnapshot {
        head: initial.head,
        dirty: !initial.status.is_empty(),
        digest,
        archive,
        entry_count,
        expanded_bytes,
    })
}

#[cfg(test)]
async fn capture_snapshot_with_git(
    request: LocalSnapshotRequest,
    git: &Path,
) -> Result<LocalSnapshot, LocalSnapshotError> {
    capture_snapshot_with_executable(
        request,
        &GitExecutable::fixture(git),
        &CancellationToken::new(),
    )
    .await
}

#[derive(Debug)]
struct GitState {
    head: String,
    index: Vec<u8>,
    inventory: Vec<u8>,
    status: Vec<u8>,
}

async fn capture_git_state(
    git: &GitExecutable,
    authority: &GitAuthority,
    limits: RepositoryWorkflowDiscoveryLimits,
    cancellation: &CancellationToken,
) -> Result<GitState, LocalSnapshotError> {
    let inventory_limit = git_inventory_output_limit(limits)?;
    let index_limit = git_index_output_limit(limits)?;
    let status_limit = git_status_output_limit(limits)?;
    let head = capture_bound_git(
        git,
        authority,
        &["rev-parse", "--verify", "HEAD^{commit}"],
        MAX_GIT_HEAD_BYTES,
        cancellation,
    )
    .await?;
    let index = capture_bound_git(
        git,
        authority,
        &["ls-files", "--cached", "--stage", "-v", "-z"],
        index_limit,
        cancellation,
    )
    .await?;
    let inventory = capture_bound_git(
        git,
        authority,
        &[
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
        inventory_limit,
        cancellation,
    )
    .await?;
    let status = capture_bound_git(
        git,
        authority,
        &["status", "--porcelain=v2", "--untracked-files=all", "-z"],
        status_limit,
        cancellation,
    )
    .await?;
    Ok(GitState {
        head: parse_head(&head)?,
        index,
        inventory,
        status,
    })
}

async fn capture_bound_git(
    git: &GitExecutable,
    authority: &GitAuthority,
    arguments: &[&str],
    maximum_stdout_bytes: usize,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>, LocalSnapshotError> {
    capture_bound_git_request(
        git,
        authority,
        arguments,
        None,
        maximum_stdout_bytes,
        false,
        cancellation,
    )
    .await
}

async fn capture_bound_git_with_input(
    git: &GitExecutable,
    authority: &GitAuthority,
    arguments: &[&str],
    input: &[u8],
    maximum_stdout_bytes: usize,
    allow_no_matches: bool,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>, LocalSnapshotError> {
    capture_bound_git_request(
        git,
        authority,
        arguments,
        Some(input),
        maximum_stdout_bytes,
        allow_no_matches,
        cancellation,
    )
    .await
}

async fn capture_bound_git_request(
    git: &GitExecutable,
    authority: &GitAuthority,
    arguments: &[&str],
    input: Option<&[u8]>,
    maximum_stdout_bytes: usize,
    allow_no_matches: bool,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>, LocalSnapshotError> {
    check_cancelled(cancellation)?;
    git.verify()?;
    authority.verify(LocalSnapshotErrorCode::ConcurrentMutation)?;
    let captured = capture_git_request(
        git,
        GitInvocation::Bound(authority),
        arguments,
        input,
        maximum_stdout_bytes,
        allow_no_matches,
        cancellation,
    )
    .await;
    authority.verify(LocalSnapshotErrorCode::ConcurrentMutation)?;
    git.verify()?;
    captured
}

async fn capture_discovery_git(
    git: &GitExecutable,
    directory: &Path,
    arguments: &[&str],
    maximum_stdout_bytes: usize,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>, LocalSnapshotError> {
    capture_git_request(
        git,
        GitInvocation::Discovery(directory),
        arguments,
        None,
        maximum_stdout_bytes,
        false,
        cancellation,
    )
    .await
}

#[derive(Clone, Copy)]
enum GitInvocation<'a> {
    Discovery(&'a Path),
    Bound(&'a GitAuthority),
}

async fn capture_git_request(
    git: &GitExecutable,
    invocation: GitInvocation<'_>,
    arguments: &[&str],
    input: Option<&[u8]>,
    maximum_stdout_bytes: usize,
    allow_no_matches: bool,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>, LocalSnapshotError> {
    check_cancelled(cancellation)?;
    git.verify()?;
    let command = configured_git_command(git, invocation, arguments, input.is_some());
    let (mut child, mut containment) = spawn_contained(command).map_err(|failure| {
        LocalSnapshotError::new(if failure == CommandFailure::NotFound {
            LocalSnapshotErrorCode::GitUnavailable
        } else {
            LocalSnapshotErrorCode::GitCommand
        })
    })?;
    let Some(stdout) = child.stdout.take() else {
        terminate_process_tree(&mut child, &mut containment).await;
        return Err(LocalSnapshotError::new(LocalSnapshotErrorCode::GitCommand));
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_process_tree(&mut child, &mut containment).await;
        return Err(LocalSnapshotError::new(LocalSnapshotErrorCode::GitCommand));
    };
    let mut stdin = child.stdin.take();
    let mut operation = Box::pin(timeout(GIT_COMMAND_TIMEOUT, async {
        tokio::try_join!(
            read_bounded(stdout, maximum_stdout_bytes),
            read_bounded(stderr, MAX_COMMAND_STREAM_BYTES),
            async {
                if let Some(input) = input {
                    let mut writer = stdin.take().ok_or(CaptureFailure::Io)?;
                    writer
                        .write_all(input)
                        .await
                        .map_err(|_error| CaptureFailure::Io)?;
                    writer
                        .shutdown()
                        .await
                        .map_err(|_error| CaptureFailure::Io)?;
                }
                Ok::<(), CaptureFailure>(())
            },
            async { child.wait().await.map_err(|_error| CaptureFailure::Io) }
        )
    }));
    let captured = tokio::select! {
        biased;
        () = cancellation.cancelled() => None,
        captured = &mut operation => Some(captured),
    };
    drop(operation);
    let Some(captured) = captured else {
        terminate_process_tree(&mut child, &mut containment).await;
        return Err(LocalSnapshotError::new(LocalSnapshotErrorCode::Cancelled));
    };
    let (stdout, stderr, (), status) = match captured {
        Ok(Ok(value)) => value,
        Ok(Err(CaptureFailure::OutputTooLarge)) => {
            terminate_process_tree(&mut child, &mut containment).await;
            return Err(LocalSnapshotError::new(
                LocalSnapshotErrorCode::ResourceLimit,
            ));
        }
        Ok(Err(CaptureFailure::Io)) => {
            terminate_process_tree(&mut child, &mut containment).await;
            return Err(LocalSnapshotError::new(LocalSnapshotErrorCode::GitCommand));
        }
        Err(_) => {
            terminate_process_tree(&mut child, &mut containment).await;
            return Err(LocalSnapshotError::new(LocalSnapshotErrorCode::GitTimeout));
        }
    };
    terminate_remaining_process_tree(&mut containment);
    if !(status.success() || allow_no_matches && status.code() == Some(1)) {
        return Err(LocalSnapshotError::new(LocalSnapshotErrorCode::GitCommand));
    }
    drop(stderr);
    git.verify()?;
    check_cancelled(cancellation)?;
    Ok(stdout)
}

fn configured_git_command(
    git: &GitExecutable,
    invocation: GitInvocation<'_>,
    arguments: &[&str],
    input_present: bool,
) -> ProcessCommand {
    let mut command = ProcessCommand::new(git.path());
    let hooks_path = format!("core.hooksPath={GIT_NULL_DEVICE}");
    let excludes_file = format!("core.excludesFile={GIT_NULL_DEVICE}");
    let attributes_file = format!("core.attributesFile={GIT_NULL_DEVICE}");
    command
        .env_clear()
        .arg("--no-optional-locks")
        .arg("--no-pager")
        .arg("--no-replace-objects")
        .args(["-c", "core.fsmonitor=false"])
        .args(["-c", "core.untrackedCache=false"])
        .args(["-c", "core.preloadIndex=false"])
        .args(["-c", hooks_path.as_str()])
        .args(["-c", excludes_file.as_str()])
        .args(["-c", attributes_file.as_str()])
        .args(["-c", "credential.helper="])
        .args(["-c", "credential.interactive=never"])
        .args(["-c", "protocol.allow=never"])
        .args(["-c", "protocol.file.allow=never"])
        .args(["-c", "core.useReplaceRefs=false"])
        .args(["-c", "gc.auto=0"])
        .args(["-c", "maintenance.auto=false"])
        .env("LC_ALL", "C")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", GIT_NULL_DEVICE)
        .env("GIT_CONFIG_GLOBAL", GIT_NULL_DEVICE)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_PROTOCOL_FROM_USER", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_PAGER", "")
        .env("GIT_TRACE", "0")
        .env("GIT_TRACE_PACKET", "0")
        .env("GIT_TRACE_PERFORMANCE", "0")
        .env("GIT_TRACE_SETUP", "0")
        .env("GIT_TRACE_SHALLOW", "0")
        .env("GIT_TRACE_CURL", "0")
        .env("GIT_TRACE_FSMONITOR", "0")
        .env("GIT_TRACE_PACK_ACCESS", "0")
        .env("GIT_TRACE_REFS", "0")
        .env("GIT_TRACE2", "0")
        .env("GIT_TRACE2_EVENT", "0")
        .env("GIT_TRACE2_PERF", "0")
        .stdin(if input_present {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    configure_git_invocation(&mut command, invocation);
    command.args(arguments);
    command
}

fn configure_git_invocation(command: &mut ProcessCommand, invocation: GitInvocation<'_>) {
    match invocation {
        GitInvocation::Discovery(directory) => {
            command.arg("-C").arg(directory);
        }
        GitInvocation::Bound(authority) => {
            command
                .arg("--git-dir")
                .arg(&authority.git_directory_path)
                .arg("--work-tree")
                .arg(&authority.worktree_path)
                .arg("-C")
                .arg(&authority.worktree_path);
        }
    }
}

#[derive(Debug)]
struct GitCoordinates {
    worktree_root: PathBuf,
    git_directory: PathBuf,
    common_directory: PathBuf,
    prefix: Vec<String>,
}

async fn discover_git_coordinates(
    git: &GitExecutable,
    directory: &Path,
    cancellation: &CancellationToken,
) -> Result<GitCoordinates, LocalSnapshotError> {
    let output = capture_discovery_git(
        git,
        directory,
        &[
            "rev-parse",
            "--path-format=absolute",
            "--show-toplevel",
            "--absolute-git-dir",
            "--git-common-dir",
            "--show-prefix",
        ],
        MAX_GIT_COORDINATES_BYTES,
        cancellation,
    )
    .await?;
    parse_git_coordinates(&output)
}

fn parse_git_coordinates(output: &[u8]) -> Result<GitCoordinates, LocalSnapshotError> {
    let text = std::str::from_utf8(output)
        .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::NonUnicodePath))?;
    if text.contains('\0') {
        return Err(LocalSnapshotError::new(
            LocalSnapshotErrorCode::NotGitWorktree,
        ));
    }
    let text = text
        .strip_suffix('\n')
        .ok_or_else(|| LocalSnapshotError::new(LocalSnapshotErrorCode::NotGitWorktree))?;
    let mut fields = text
        .split('\n')
        .map(|field| field.strip_suffix('\r').unwrap_or(field));
    let (Some(worktree_root), Some(git_directory), Some(common_directory), Some(prefix)) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return Err(LocalSnapshotError::new(
            LocalSnapshotErrorCode::NotGitWorktree,
        ));
    };
    if fields.next().is_some() {
        return Err(LocalSnapshotError::new(
            LocalSnapshotErrorCode::NotGitWorktree,
        ));
    }
    Ok(GitCoordinates {
        worktree_root: parse_git_coordinate_path(worktree_root)?,
        git_directory: parse_git_coordinate_path(git_directory)?,
        common_directory: parse_git_coordinate_path(common_directory)?,
        prefix: parse_git_prefix(prefix)?,
    })
}

fn parse_git_coordinate_path(value: &str) -> Result<PathBuf, LocalSnapshotError> {
    if value.is_empty()
        || value.len() > MAX_GIT_COORDINATE_FIELD_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(LocalSnapshotError::new(
            LocalSnapshotErrorCode::NotGitWorktree,
        ));
    }
    let path = PathBuf::from(value);
    if !path.is_absolute()
        || path.components().any(|component| {
            !matches!(
                component,
                std::path::Component::Prefix(_)
                    | std::path::Component::RootDir
                    | std::path::Component::Normal(_)
            )
        })
    {
        return Err(LocalSnapshotError::new(
            LocalSnapshotErrorCode::NotGitWorktree,
        ));
    }
    Ok(path)
}

fn parse_git_prefix(value: &str) -> Result<Vec<String>, LocalSnapshotError> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    if value.len() > MAX_GIT_COORDINATE_FIELD_BYTES {
        return Err(LocalSnapshotError::new(
            LocalSnapshotErrorCode::NotGitWorktree,
        ));
    }
    let Some(value) = value.strip_suffix('/') else {
        return Err(LocalSnapshotError::new(
            LocalSnapshotErrorCode::NotGitWorktree,
        ));
    };
    let mut components = Vec::new();
    for component in value.split('/') {
        if component.is_empty()
            || matches!(component, "." | "..")
            || component.contains('\\')
            || component.chars().any(char::is_control)
        {
            return Err(LocalSnapshotError::new(
                LocalSnapshotErrorCode::NotGitWorktree,
            ));
        }
        components.push(component.to_owned());
    }
    Ok(components)
}

async fn verify_bound_git_coordinates(
    git: &GitExecutable,
    authority: &GitAuthority,
    failure: LocalSnapshotErrorCode,
    cancellation: &CancellationToken,
) -> Result<(), LocalSnapshotError> {
    let output = capture_bound_git(
        git,
        authority,
        &[
            "rev-parse",
            "--path-format=absolute",
            "--show-toplevel",
            "--absolute-git-dir",
            "--git-common-dir",
            "--show-prefix",
        ],
        MAX_GIT_COORDINATES_BYTES,
        cancellation,
    )
    .await?;
    let coordinates = parse_git_coordinates(&output)?;
    if !coordinates.prefix.is_empty() {
        return Err(LocalSnapshotError::new(failure));
    }
    let reported_worktree = PinnedDirectory::open_for(&coordinates.worktree_root, failure)?;
    let reported_git_directory = PinnedDirectory::open_for(&coordinates.git_directory, failure)?;
    let reported_common_directory =
        PinnedDirectory::open_for(&coordinates.common_directory, failure)?;
    authority
        .worktree
        .verify_same_identity(&reported_worktree, failure)?;
    authority
        .git_directory
        .verify_same_identity(&reported_git_directory, failure)?;
    authority
        .common_directory
        .verify_same_identity(&reported_common_directory, failure)
}

fn parse_head(output: &[u8]) -> Result<String, LocalSnapshotError> {
    let head = parse_one_git_line(output, LocalSnapshotErrorCode::GitOutput)?;
    if !matches!(head.len(), 40 | 64)
        || !head
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(LocalSnapshotError::new(LocalSnapshotErrorCode::GitOutput));
    }
    Ok(head.to_owned())
}

fn parse_one_git_line(
    output: &[u8],
    code: LocalSnapshotErrorCode,
) -> Result<&str, LocalSnapshotError> {
    let text = std::str::from_utf8(output).map_err(|_| LocalSnapshotError::new(code))?;
    let text = text
        .strip_suffix('\n')
        .and_then(|line| line.strip_suffix('\r').or(Some(line)))
        .ok_or_else(|| LocalSnapshotError::new(code))?;
    if text.is_empty() || text.contains(['\r', '\n', '\0']) {
        return Err(LocalSnapshotError::new(code));
    }
    Ok(text)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TrackedMode {
    Regular,
    Executable,
    Symlink,
}

#[derive(Debug)]
struct GitInventory {
    paths: Vec<String>,
    tracked_modes: BTreeMap<String, TrackedMode>,
}

fn parse_inventory(
    state: &GitState,
    limits: RepositoryWorkflowDiscoveryLimits,
    path_validator: RepositoryPathValidator,
) -> Result<GitInventory, LocalSnapshotError> {
    let tracked_modes = parse_index(&state.index, limits, path_validator)?;
    let records = nul_records(&state.inventory)?;
    if records.len() >= limits.maximum_entries() {
        return Err(LocalSnapshotError::new(
            LocalSnapshotErrorCode::ResourceLimit,
        ));
    }
    let mut paths = BTreeSet::new();
    for raw in records {
        let path = parse_repository_path(raw, path_validator)?;
        if !paths.insert(path) {
            return Err(LocalSnapshotError::new(LocalSnapshotErrorCode::GitOutput));
        }
    }
    Ok(GitInventory {
        paths: paths.into_iter().collect(),
        tracked_modes,
    })
}

fn parse_index(
    output: &[u8],
    limits: RepositoryWorkflowDiscoveryLimits,
    path_validator: RepositoryPathValidator,
) -> Result<BTreeMap<String, TrackedMode>, LocalSnapshotError> {
    let records = nul_records(output)?;
    if records.len() > limits.maximum_entries() {
        return Err(LocalSnapshotError::new(
            LocalSnapshotErrorCode::ResourceLimit,
        ));
    }
    let mut modes = BTreeMap::new();
    for record in records {
        let Some(tab) = record.iter().position(|byte| *byte == b'\t') else {
            return Err(LocalSnapshotError::new(LocalSnapshotErrorCode::GitOutput));
        };
        let metadata = std::str::from_utf8(&record[..tab])
            .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::GitOutput))?;
        let (tag, metadata) = metadata
            .split_once(' ')
            .ok_or_else(|| LocalSnapshotError::new(LocalSnapshotErrorCode::GitOutput))?;
        if tag.len() != 1 {
            return Err(LocalSnapshotError::new(LocalSnapshotErrorCode::GitOutput));
        }
        match tag.as_bytes()[0] {
            b'H' => {}
            b'S' | b's' => {
                return Err(LocalSnapshotError::new(
                    LocalSnapshotErrorCode::SparseCheckout,
                ));
            }
            byte if byte.is_ascii_lowercase() => {
                return Err(LocalSnapshotError::new(
                    LocalSnapshotErrorCode::AssumeUnchanged,
                ));
            }
            _ => {
                return Err(LocalSnapshotError::new(
                    LocalSnapshotErrorCode::IndexAmbiguity,
                ));
            }
        }
        let mut fields = metadata.split(' ');
        let mode = fields
            .next()
            .ok_or_else(|| LocalSnapshotError::new(LocalSnapshotErrorCode::GitOutput))?;
        let object = fields
            .next()
            .ok_or_else(|| LocalSnapshotError::new(LocalSnapshotErrorCode::GitOutput))?;
        let stage = fields
            .next()
            .ok_or_else(|| LocalSnapshotError::new(LocalSnapshotErrorCode::GitOutput))?;
        if fields.next().is_some()
            || !matches!(object.len(), 40 | 64)
            || !object.bytes().all(|byte| byte.is_ascii_hexdigit())
            || stage != "0"
        {
            return Err(LocalSnapshotError::new(
                LocalSnapshotErrorCode::IndexAmbiguity,
            ));
        }
        let mode = match mode {
            "100644" => TrackedMode::Regular,
            "100755" => TrackedMode::Executable,
            "120000" => TrackedMode::Symlink,
            "160000" => {
                return Err(LocalSnapshotError::new(LocalSnapshotErrorCode::Submodule));
            }
            _ => {
                return Err(LocalSnapshotError::new(
                    LocalSnapshotErrorCode::IndexAmbiguity,
                ));
            }
        };
        let path = parse_repository_path(&record[tab + 1..], path_validator)?;
        if modes.insert(path, mode).is_some() {
            return Err(LocalSnapshotError::new(
                LocalSnapshotErrorCode::IndexAmbiguity,
            ));
        }
    }
    Ok(modes)
}

fn nul_records(output: &[u8]) -> Result<Vec<&[u8]>, LocalSnapshotError> {
    if output.is_empty() {
        return Ok(Vec::new());
    }
    if !output.ends_with(&[0]) {
        return Err(LocalSnapshotError::new(LocalSnapshotErrorCode::GitOutput));
    }
    Ok(output[..output.len() - 1]
        .split(|byte| *byte == 0)
        .collect())
}

fn parse_repository_path(
    raw: &[u8],
    validator: RepositoryPathValidator,
) -> Result<String, LocalSnapshotError> {
    validator
        .validate_entry(raw)
        .map(str::to_owned)
        .map_err(local_path_validation_error)
}

fn local_path_validation_error(error: RepositoryPathValidationError) -> LocalSnapshotError {
    LocalSnapshotError::new(match error {
        RepositoryPathValidationError::NonUnicode => LocalSnapshotErrorCode::NonUnicodePath,
        RepositoryPathValidationError::ResourceLimit => LocalSnapshotErrorCode::ResourceLimit,
        RepositoryPathValidationError::Unsafe => LocalSnapshotErrorCode::UnsafePath,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WorktreeScanEntry {
    path: String,
    kind: WorktreeScanEntryKind,
    stamp: MetadataStamp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorktreeScanEntryKind {
    Directory,
    File,
    Symlink,
    Unsupported,
}

struct ScanDirectory {
    handle: Dir,
    path: Option<String>,
}

struct PinnedDirectory {
    handle: Dir,
    identity: DirectoryIdentity,
}

impl PinnedDirectory {
    fn open(path: &Path) -> Result<Self, LocalSnapshotError> {
        Self::open_for(path, LocalSnapshotErrorCode::NotGitWorktree)
    }

    fn open_for(path: &Path, failure: LocalSnapshotErrorCode) -> Result<Self, LocalSnapshotError> {
        let handle = open_absolute_directory_nofollow(path, failure)?;
        let opened = handle
            .dir_metadata()
            .map_err(|_| LocalSnapshotError::new(failure))?;
        require_directory(&opened, failure)?;
        let identity = DirectoryIdentity::new(&opened);
        let current_handle = open_absolute_directory_nofollow(path, failure)?;
        let current = current_handle
            .dir_metadata()
            .map_err(|_| LocalSnapshotError::new(failure))?;
        require_directory(&current, failure)?;
        if identity != DirectoryIdentity::new(&current) {
            return Err(LocalSnapshotError::new(failure));
        }
        Ok(Self { handle, identity })
    }

    fn verify_same_identity(
        &self,
        other: &Self,
        failure: LocalSnapshotErrorCode,
    ) -> Result<(), LocalSnapshotError> {
        let own = self
            .handle
            .dir_metadata()
            .map_err(|_| LocalSnapshotError::new(failure))?;
        let reported = other
            .handle
            .dir_metadata()
            .map_err(|_| LocalSnapshotError::new(failure))?;
        require_directory(&own, failure)?;
        require_directory(&reported, failure)?;
        if DirectoryIdentity::new(&own) != self.identity
            || DirectoryIdentity::new(&reported) != other.identity
            || self.identity != other.identity
        {
            return Err(LocalSnapshotError::new(failure));
        }
        Ok(())
    }

    fn verify_descendant(
        &self,
        components: &[String],
        expected: &Self,
        failure: LocalSnapshotErrorCode,
    ) -> Result<(), LocalSnapshotError> {
        let mut current = self.clone_handle(failure)?;
        for component in components {
            let before = current
                .symlink_metadata(component)
                .map_err(|_| LocalSnapshotError::new(failure))?;
            require_directory(&before, failure)?;
            let child = current
                .open_dir_nofollow(component)
                .map_err(|_| LocalSnapshotError::new(failure))?;
            let opened = child
                .dir_metadata()
                .map_err(|_| LocalSnapshotError::new(failure))?;
            require_directory(&opened, failure)?;
            if DirectoryIdentity::new(&before) != DirectoryIdentity::new(&opened) {
                return Err(LocalSnapshotError::new(failure));
            }
            current = child;
        }
        let resolved = Self {
            identity: DirectoryIdentity::new(
                &current
                    .dir_metadata()
                    .map_err(|_| LocalSnapshotError::new(failure))?,
            ),
            handle: current,
        };
        self.verify_handle_identity(failure)?;
        expected.verify_same_identity(&resolved, failure)
    }

    fn verify_handle_identity(
        &self,
        failure: LocalSnapshotErrorCode,
    ) -> Result<(), LocalSnapshotError> {
        let metadata = self
            .handle
            .dir_metadata()
            .map_err(|_| LocalSnapshotError::new(failure))?;
        require_directory(&metadata, failure)?;
        if DirectoryIdentity::new(&metadata) != self.identity {
            return Err(LocalSnapshotError::new(failure));
        }
        Ok(())
    }

    fn verify_ambient_path(&self, path: &Path) -> Result<(), LocalSnapshotError> {
        self.verify_ambient_path_for(path, LocalSnapshotErrorCode::ConcurrentMutation)
    }

    fn verify_ambient_path_for(
        &self,
        path: &Path,
        failure: LocalSnapshotErrorCode,
    ) -> Result<(), LocalSnapshotError> {
        let opened = self
            .handle
            .dir_metadata()
            .map_err(|_| LocalSnapshotError::new(failure))?;
        require_directory(&opened, failure)?;
        let current_handle = open_absolute_directory_nofollow(path, failure)?;
        let current = current_handle
            .dir_metadata()
            .map_err(|_| LocalSnapshotError::new(failure))?;
        require_directory(&current, failure)?;
        if DirectoryIdentity::new(&current) != self.identity
            || DirectoryIdentity::new(&opened) != self.identity
        {
            return Err(LocalSnapshotError::new(failure));
        }
        Ok(())
    }

    fn root_handle(&self) -> Result<Dir, LocalSnapshotError> {
        self.clone_handle(LocalSnapshotErrorCode::ConcurrentMutation)
    }

    fn clone_pinned(&self) -> Result<Self, LocalSnapshotError> {
        Ok(Self {
            handle: self.clone_handle(LocalSnapshotErrorCode::ConcurrentMutation)?,
            identity: self.identity,
        })
    }

    fn clone_handle(&self, failure: LocalSnapshotErrorCode) -> Result<Dir, LocalSnapshotError> {
        self.handle
            .try_clone()
            .map_err(|_| LocalSnapshotError::new(failure))
    }

    fn locate_parent<'a>(
        &self,
        path: &'a str,
    ) -> Result<Option<(Dir, &'a str)>, LocalSnapshotError> {
        let mut components = path.split('/').peekable();
        let mut current = self.root_handle()?;
        while let Some(component) = components.next() {
            if components.peek().is_none() {
                return Ok(Some((current, component)));
            }
            let before = match current.symlink_metadata(component) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(_) => {
                    return Err(LocalSnapshotError::new(
                        LocalSnapshotErrorCode::ConcurrentMutation,
                    ));
                }
            };
            require_directory(&before, LocalSnapshotErrorCode::UnsafeAncestor)?;
            let child = current
                .open_dir_nofollow(component)
                .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::ConcurrentMutation))?;
            let opened = child
                .dir_metadata()
                .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::ConcurrentMutation))?;
            require_directory(&opened, LocalSnapshotErrorCode::UnsafeAncestor)?;
            if DirectoryIdentity::new(&before) != DirectoryIdentity::new(&opened) {
                return Err(LocalSnapshotError::new(
                    LocalSnapshotErrorCode::ConcurrentMutation,
                ));
            }
            current = child;
        }
        Err(LocalSnapshotError::new(LocalSnapshotErrorCode::UnsafePath))
    }
}

async fn run_blocking<T, F>(
    join_failure: LocalSnapshotErrorCode,
    operation: F,
) -> Result<T, LocalSnapshotError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, LocalSnapshotError> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| LocalSnapshotError::new(join_failure))?
}

struct GitAuthority {
    worktree_path: PathBuf,
    git_directory_path: PathBuf,
    common_directory_path: PathBuf,
    worktree: PinnedDirectory,
    git_directory: PinnedDirectory,
    common_directory: PinnedDirectory,
    locator: GitLocator,
}

impl GitAuthority {
    fn pin(
        coordinates: GitCoordinates,
        requested: &PinnedDirectory,
    ) -> Result<Self, LocalSnapshotError> {
        let worktree = PinnedDirectory::open(&coordinates.worktree_root)?;
        worktree.verify_descendant(
            &coordinates.prefix,
            requested,
            LocalSnapshotErrorCode::NotGitWorktree,
        )?;
        let git_directory = PinnedDirectory::open(&coordinates.git_directory)?;
        let common_directory = PinnedDirectory::open(&coordinates.common_directory)?;
        let locator = GitLocator::pin(&worktree, &git_directory, &common_directory)?;
        let authority = Self {
            worktree_path: coordinates.worktree_root,
            git_directory_path: coordinates.git_directory,
            common_directory_path: coordinates.common_directory,
            worktree,
            git_directory,
            common_directory,
            locator,
        };
        authority.verify(LocalSnapshotErrorCode::NotGitWorktree)?;
        Ok(authority)
    }

    fn verify(&self, failure: LocalSnapshotErrorCode) -> Result<(), LocalSnapshotError> {
        self.worktree
            .verify_ambient_path_for(&self.worktree_path, failure)?;
        self.locator.verify(&self.worktree, failure)?;
        self.git_directory
            .verify_ambient_path_for(&self.git_directory_path, failure)?;
        self.common_directory
            .verify_ambient_path_for(&self.common_directory_path, failure)
    }
}

enum GitLocator {
    Directory(PinnedDirectory),
    LinkedWorktreeFile(GitFileEvidence),
}

impl GitLocator {
    fn pin(
        worktree: &PinnedDirectory,
        git_directory: &PinnedDirectory,
        common_directory: &PinnedDirectory,
    ) -> Result<Self, LocalSnapshotError> {
        let metadata = worktree
            .handle
            .symlink_metadata(".git")
            .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::NotGitWorktree))?;
        if metadata.is_dir() {
            let directory = open_git_locator_directory(
                worktree,
                &metadata,
                LocalSnapshotErrorCode::NotGitWorktree,
            )?;
            directory
                .verify_same_identity(git_directory, LocalSnapshotErrorCode::NotGitWorktree)?;
            git_directory
                .verify_same_identity(common_directory, LocalSnapshotErrorCode::NotGitWorktree)?;
            return Ok(Self::Directory(directory));
        }
        if !metadata.is_file() {
            return Err(LocalSnapshotError::new(
                LocalSnapshotErrorCode::NotGitWorktree,
            ));
        }
        let evidence = capture_git_file(worktree, LocalSnapshotErrorCode::NotGitWorktree)?;
        let target = parse_git_file_target(&evidence.bytes)?;
        let target_directory = PinnedDirectory::open(&target)?;
        target_directory
            .verify_same_identity(git_directory, LocalSnapshotErrorCode::NotGitWorktree)?;
        git_directory.verify_handle_identity(LocalSnapshotErrorCode::NotGitWorktree)?;
        common_directory.verify_handle_identity(LocalSnapshotErrorCode::NotGitWorktree)?;
        if git_directory.identity == common_directory.identity {
            return Err(LocalSnapshotError::new(
                LocalSnapshotErrorCode::NotGitWorktree,
            ));
        }
        Ok(Self::LinkedWorktreeFile(evidence))
    }

    fn verify(
        &self,
        worktree: &PinnedDirectory,
        failure: LocalSnapshotErrorCode,
    ) -> Result<(), LocalSnapshotError> {
        match self {
            Self::Directory(expected) => {
                let metadata = worktree
                    .handle
                    .symlink_metadata(".git")
                    .map_err(|_| LocalSnapshotError::new(failure))?;
                if !metadata.is_dir() {
                    return Err(LocalSnapshotError::new(failure));
                }
                let current = open_git_locator_directory(worktree, &metadata, failure)?;
                expected.verify_same_identity(&current, failure)
            }
            Self::LinkedWorktreeFile(expected) => {
                let current = capture_git_file(worktree, failure)?;
                if &current != expected {
                    return Err(LocalSnapshotError::new(failure));
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct GitFileEvidence {
    stamp: MetadataStamp,
    bytes: Vec<u8>,
}

fn open_git_locator_directory(
    worktree: &PinnedDirectory,
    before: &Metadata,
    failure: LocalSnapshotErrorCode,
) -> Result<PinnedDirectory, LocalSnapshotError> {
    require_directory(before, failure)?;
    let handle = worktree
        .handle
        .open_dir_nofollow(".git")
        .map_err(|_| LocalSnapshotError::new(failure))?;
    let opened = handle
        .dir_metadata()
        .map_err(|_| LocalSnapshotError::new(failure))?;
    require_directory(&opened, failure)?;
    let identity = DirectoryIdentity::new(&opened);
    if identity != DirectoryIdentity::new(before) {
        return Err(LocalSnapshotError::new(failure));
    }
    Ok(PinnedDirectory { handle, identity })
}

fn capture_git_file(
    worktree: &PinnedDirectory,
    failure: LocalSnapshotErrorCode,
) -> Result<GitFileEvidence, LocalSnapshotError> {
    let before = worktree
        .handle
        .symlink_metadata(".git")
        .map_err(|_| LocalSnapshotError::new(failure))?;
    if !before.is_file() {
        return Err(LocalSnapshotError::new(failure));
    }
    let stamp = MetadataStamp::new(&before);
    let mut options = OpenOptions::new();
    options.read(true);
    options.follow(FollowSymlinks::No);
    let mut file = worktree
        .handle
        .open_with(".git", &options)
        .map_err(|_| LocalSnapshotError::new(failure))?;
    let opened = file
        .metadata()
        .map_err(|_| LocalSnapshotError::new(failure))?;
    if !opened.is_file() || MetadataStamp::new(&opened) != stamp {
        return Err(LocalSnapshotError::new(failure));
    }
    let maximum = u64::try_from(MAX_GIT_LOCATOR_BYTES)
        .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::ResourceLimit))?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| LocalSnapshotError::new(failure))?;
    if bytes.len() > MAX_GIT_LOCATOR_BYTES {
        return Err(LocalSnapshotError::new(
            LocalSnapshotErrorCode::ResourceLimit,
        ));
    }
    let opened_after = file
        .metadata()
        .map_err(|_| LocalSnapshotError::new(failure))?;
    let ambient_after = worktree
        .handle
        .symlink_metadata(".git")
        .map_err(|_| LocalSnapshotError::new(failure))?;
    if !opened_after.is_file()
        || !ambient_after.is_file()
        || MetadataStamp::new(&opened_after) != stamp
        || MetadataStamp::new(&ambient_after) != stamp
    {
        return Err(LocalSnapshotError::new(failure));
    }
    Ok(GitFileEvidence { stamp, bytes })
}

fn parse_git_file_target(bytes: &[u8]) -> Result<PathBuf, LocalSnapshotError> {
    let line = parse_one_git_line(bytes, LocalSnapshotErrorCode::NotGitWorktree)?;
    let target = line
        .strip_prefix("gitdir: ")
        .ok_or_else(|| LocalSnapshotError::new(LocalSnapshotErrorCode::NotGitWorktree))?;
    parse_git_coordinate_path(target)
}

fn open_absolute_directory_nofollow(
    path: &Path,
    failure: LocalSnapshotErrorCode,
) -> Result<Dir, LocalSnapshotError> {
    if !path.is_absolute() {
        return Err(LocalSnapshotError::new(failure));
    }
    let anchor = path
        .ancestors()
        .last()
        .filter(|ancestor| ancestor.has_root())
        .ok_or_else(|| LocalSnapshotError::new(failure))?;
    let relative = path
        .strip_prefix(anchor)
        .map_err(|_| LocalSnapshotError::new(failure))?;
    let ambient = fs::symlink_metadata(anchor).map_err(|_| LocalSnapshotError::new(failure))?;
    require_ambient_directory(&ambient, failure)?;
    let mut current = Dir::open_ambient_dir(anchor, ambient_authority())
        .map_err(|_| LocalSnapshotError::new(failure))?;
    let opened = current
        .dir_metadata()
        .map_err(|_| LocalSnapshotError::new(failure))?;
    require_directory(&opened, failure)?;
    let confirmed = Dir::open_ambient_dir(anchor, ambient_authority())
        .and_then(|directory| directory.dir_metadata())
        .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::ConcurrentMutation))?;
    require_directory(&confirmed, failure)?;
    if DirectoryIdentity::new(&opened) != DirectoryIdentity::new(&confirmed) {
        return Err(LocalSnapshotError::new(
            LocalSnapshotErrorCode::ConcurrentMutation,
        ));
    }

    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(LocalSnapshotError::new(failure));
        };
        let component_path = Path::new(name);
        let before = current
            .symlink_metadata(component_path)
            .map_err(|_| LocalSnapshotError::new(failure))?;
        require_directory(&before, LocalSnapshotErrorCode::UnsafeAncestor)?;
        let child = current
            .open_dir_nofollow(component_path)
            .map_err(|_| LocalSnapshotError::new(failure))?;
        let after = child
            .dir_metadata()
            .map_err(|_| LocalSnapshotError::new(failure))?;
        require_directory(&after, LocalSnapshotErrorCode::UnsafeAncestor)?;
        if DirectoryIdentity::new(&before) != DirectoryIdentity::new(&after) {
            return Err(LocalSnapshotError::new(
                LocalSnapshotErrorCode::ConcurrentMutation,
            ));
        }
        current = child;
    }
    Ok(current)
}

fn require_directory(
    metadata: &Metadata,
    code: LocalSnapshotErrorCode,
) -> Result<(), LocalSnapshotError> {
    if !metadata.is_dir() {
        return Err(LocalSnapshotError::new(code));
    }
    Ok(())
}

fn require_ambient_directory(
    metadata: &fs::Metadata,
    code: LocalSnapshotErrorCode,
) -> Result<(), LocalSnapshotError> {
    if !metadata.is_dir() {
        return Err(LocalSnapshotError::new(code));
    }
    Ok(())
}

async fn scan_worktree(
    git: &GitExecutable,
    authority: &GitAuthority,
    limits: RepositoryWorkflowDiscoveryLimits,
    path_validator: RepositoryPathValidator,
    cancellation: &CancellationToken,
) -> Result<Vec<WorktreeScanEntry>, LocalSnapshotError> {
    check_cancelled(cancellation)?;
    let worktree = authority.worktree.clone_pinned()?;
    let worker_cancellation = cancellation.clone();
    let mut scanned = run_blocking(LocalSnapshotErrorCode::ConcurrentMutation, move || {
        scan_worktree_filesystem(&worktree, limits, path_validator, &worker_cancellation)
    })
    .await?;
    let ignored = ignored_paths(git, authority, &scanned, limits, cancellation).await?;
    scanned.retain(|entry| !ignored.contains(&entry.path));
    if scanned
        .iter()
        .any(|entry| entry.kind == WorktreeScanEntryKind::Unsupported)
    {
        return Err(LocalSnapshotError::new(
            LocalSnapshotErrorCode::UnsupportedEntry,
        ));
    }
    Ok(scanned)
}

fn scan_worktree_filesystem(
    worktree: &PinnedDirectory,
    limits: RepositoryWorkflowDiscoveryLimits,
    path_validator: RepositoryPathValidator,
    cancellation: &CancellationToken,
) -> Result<Vec<WorktreeScanEntry>, LocalSnapshotError> {
    check_cancelled(cancellation)?;
    let maximum_observed = limits.maximum_path_graph_nodes();
    let mut observed = 0_usize;
    let mut directories = vec![ScanDirectory {
        handle: worktree.root_handle()?,
        path: None,
    }];
    let mut scanned = Vec::new();
    while let Some(directory) = directories.pop() {
        check_cancelled(cancellation)?;
        let children = directory
            .handle
            .entries()
            .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::ConcurrentMutation))?;
        for child in children {
            check_cancelled(cancellation)?;
            let child = child
                .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::ConcurrentMutation))?;
            let name = child.file_name();
            if directory.path.is_none() && name == std::ffi::OsStr::new(".git") {
                continue;
            }
            observed = observed
                .checked_add(1)
                .ok_or_else(|| LocalSnapshotError::new(LocalSnapshotErrorCode::ResourceLimit))?;
            if observed > maximum_observed {
                return Err(LocalSnapshotError::new(
                    LocalSnapshotErrorCode::ResourceLimit,
                ));
            }
            let name_text = name
                .to_str()
                .ok_or_else(|| LocalSnapshotError::new(LocalSnapshotErrorCode::NonUnicodePath))?;
            let path = directory.path.as_ref().map_or_else(
                || name_text.to_owned(),
                |parent| format!("{parent}/{name_text}"),
            );
            let metadata = directory
                .handle
                .symlink_metadata(&name)
                .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::ConcurrentMutation))?;
            validate_scanned_path(&path, &metadata, path_validator)?;
            let file_type = metadata.file_type();
            let stamp = MetadataStamp::new(&metadata);
            let kind = if file_type.is_dir() {
                let child = directory.handle.open_dir_nofollow(&name).map_err(|_| {
                    LocalSnapshotError::new(LocalSnapshotErrorCode::ConcurrentMutation)
                })?;
                let opened = child.dir_metadata().map_err(|_| {
                    LocalSnapshotError::new(LocalSnapshotErrorCode::ConcurrentMutation)
                })?;
                require_directory(&opened, LocalSnapshotErrorCode::UnsafeAncestor)?;
                if DirectoryIdentity::new(&opened) != DirectoryIdentity::new(&metadata) {
                    return Err(LocalSnapshotError::new(
                        LocalSnapshotErrorCode::ConcurrentMutation,
                    ));
                }
                directories.push(ScanDirectory {
                    handle: child,
                    path: Some(path.clone()),
                });
                WorktreeScanEntryKind::Directory
            } else if file_type.is_file() {
                WorktreeScanEntryKind::File
            } else if file_type.is_symlink() {
                WorktreeScanEntryKind::Symlink
            } else {
                WorktreeScanEntryKind::Unsupported
            };
            scanned.push(WorktreeScanEntry { path, kind, stamp });
        }
    }
    scanned.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(scanned)
}

fn validate_scanned_path(
    path: &str,
    metadata: &Metadata,
    validator: RepositoryPathValidator,
) -> Result<(), LocalSnapshotError> {
    if metadata.is_dir() {
        validator
            .validate_entry_ancestor(path.as_bytes())
            .map_err(local_path_validation_error)?;
    } else {
        parse_repository_path(path.as_bytes(), validator)?;
    }
    Ok(())
}

async fn ignored_paths(
    git: &GitExecutable,
    authority: &GitAuthority,
    scanned: &[WorktreeScanEntry],
    limits: RepositoryWorkflowDiscoveryLimits,
    cancellation: &CancellationToken,
) -> Result<BTreeSet<String>, LocalSnapshotError> {
    if scanned.is_empty() {
        return Ok(BTreeSet::new());
    }
    let mut input = Vec::new();
    let maximum_input_bytes = checked_output_limit(limits, 1)?;
    for entry in scanned {
        check_cancelled(cancellation)?;
        let next_length = input
            .len()
            .checked_add(entry.path.len())
            .and_then(|length| length.checked_add(1))
            .ok_or_else(|| LocalSnapshotError::new(LocalSnapshotErrorCode::ResourceLimit))?;
        if next_length > maximum_input_bytes {
            return Err(LocalSnapshotError::new(
                LocalSnapshotErrorCode::ResourceLimit,
            ));
        }
        input.extend_from_slice(entry.path.as_bytes());
        input.push(0);
    }
    let output = capture_bound_git_with_input(
        git,
        authority,
        &["check-ignore", "--stdin", "-z"],
        &input,
        input.len(),
        true,
        cancellation,
    )
    .await?;
    let candidates = scanned
        .iter()
        .map(|entry| entry.path.as_str())
        .collect::<BTreeSet<_>>();
    let mut ignored = BTreeSet::new();
    for raw in nul_records(&output)? {
        let path = std::str::from_utf8(raw)
            .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::NonUnicodePath))?;
        if !candidates.contains(path) || !ignored.insert(path.to_owned()) {
            return Err(LocalSnapshotError::new(LocalSnapshotErrorCode::GitOutput));
        }
    }
    Ok(ignored)
}

#[derive(Debug)]
struct CapturedInventory {
    entries: Vec<CapturedEntry>,
    deleted_paths: Vec<String>,
    expanded_bytes: u64,
}

#[derive(Debug)]
struct CapturedEntry {
    path: String,
    payload: CapturedPayload,
}

#[derive(Debug)]
enum CapturedPayload {
    File { bytes: Vec<u8>, executable: bool },
    Symlink { target: String },
}

fn capture_entries(
    worktree: &PinnedDirectory,
    inventory: &GitInventory,
    limits: RepositoryWorkflowDiscoveryLimits,
    path_validator: RepositoryPathValidator,
    cancellation: &CancellationToken,
) -> Result<CapturedInventory, LocalSnapshotError> {
    let mut entries = Vec::with_capacity(inventory.paths.len());
    let mut deleted_paths = Vec::new();
    let mut expanded_bytes = 0_u64;
    for path in &inventory.paths {
        check_cancelled(cancellation)?;
        let tracked = inventory.tracked_modes.get(path).copied();
        let Some((parent, name)) = worktree.locate_parent(path)? else {
            if tracked.is_some() {
                deleted_paths.push(path.clone());
                continue;
            }
            return Err(LocalSnapshotError::new(
                LocalSnapshotErrorCode::ConcurrentMutation,
            ));
        };
        let before = match parent.symlink_metadata(name) {
            Ok(metadata) => metadata,
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    && inventory.tracked_modes.contains_key(path) =>
            {
                deleted_paths.push(path.clone());
                continue;
            }
            Err(_) => {
                return Err(LocalSnapshotError::new(
                    LocalSnapshotErrorCode::ConcurrentMutation,
                ));
            }
        };
        let before_stamp = MetadataStamp::new(&before);
        let payload = match tracked {
            Some(TrackedMode::Symlink) if before.file_type().is_symlink() => {
                capture_filesystem_symlink(&parent, name, path_validator)?
            }
            Some(TrackedMode::Symlink) if before.is_file() => capture_symlink_placeholder(
                &parent,
                name,
                &before,
                before_stamp,
                path_validator,
                cancellation,
            )?,
            Some(TrackedMode::Symlink) => {
                return Err(LocalSnapshotError::new(
                    LocalSnapshotErrorCode::UnsupportedEntry,
                ));
            }
            Some(TrackedMode::Regular | TrackedMode::Executable)
                if before.file_type().is_symlink() =>
            {
                return Err(LocalSnapshotError::new(
                    LocalSnapshotErrorCode::IndexAmbiguity,
                ));
            }
            _ if before.file_type().is_symlink() => {
                capture_filesystem_symlink(&parent, name, path_validator)?
            }
            _ if before.is_file() => {
                let (payload, read_bytes) = capture_regular_file(
                    &parent,
                    name,
                    &before,
                    before_stamp,
                    remaining_expanded_bytes(limits, expanded_bytes)?,
                    tracked,
                    cancellation,
                )?;
                expanded_bytes = expanded_bytes.checked_add(read_bytes).ok_or_else(|| {
                    LocalSnapshotError::new(LocalSnapshotErrorCode::ResourceLimit)
                })?;
                payload
            }
            _ => {
                return Err(LocalSnapshotError::new(
                    LocalSnapshotErrorCode::UnsupportedEntry,
                ));
            }
        };
        let after = parent
            .symlink_metadata(name)
            .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::ConcurrentMutation))?;
        if MetadataStamp::new(&after) != before_stamp {
            return Err(LocalSnapshotError::new(
                LocalSnapshotErrorCode::ConcurrentMutation,
            ));
        }
        entries.push(CapturedEntry {
            path: path.clone(),
            payload,
        });
    }
    Ok(CapturedInventory {
        entries,
        deleted_paths,
        expanded_bytes,
    })
}

fn remaining_expanded_bytes(
    limits: RepositoryWorkflowDiscoveryLimits,
    expanded_bytes: u64,
) -> Result<u64, LocalSnapshotError> {
    limits
        .maximum_expanded_bytes()
        .checked_sub(expanded_bytes)
        .ok_or_else(|| LocalSnapshotError::new(LocalSnapshotErrorCode::ResourceLimit))
}

fn capture_regular_file(
    parent: &Dir,
    name: &str,
    before: &Metadata,
    before_stamp: MetadataStamp,
    remaining: u64,
    tracked: Option<TrackedMode>,
    cancellation: &CancellationToken,
) -> Result<(CapturedPayload, u64), LocalSnapshotError> {
    if before.len() > remaining {
        return Err(LocalSnapshotError::new(
            LocalSnapshotErrorCode::ResourceLimit,
        ));
    }
    let mut file = open_regular_nofollow(parent, name)?;
    let opened = file
        .metadata()
        .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::ConcurrentMutation))?;
    if !opened.is_file() || MetadataStamp::new(&opened) != before_stamp {
        return Err(LocalSnapshotError::new(
            LocalSnapshotErrorCode::ConcurrentMutation,
        ));
    }
    let maximum_read = remaining
        .checked_add(1)
        .ok_or_else(|| LocalSnapshotError::new(LocalSnapshotErrorCode::ResourceLimit))?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(before.len())
            .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::ResourceLimit))?,
    );
    read_file_cancellable(&mut file, maximum_read, &mut bytes, cancellation)?;
    let read_bytes = u64::try_from(bytes.len())
        .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::ResourceLimit))?;
    if read_bytes > remaining {
        return Err(LocalSnapshotError::new(
            LocalSnapshotErrorCode::ResourceLimit,
        ));
    }
    let after_open = file
        .metadata()
        .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::ConcurrentMutation))?;
    if MetadataStamp::new(&after_open) != before_stamp {
        return Err(LocalSnapshotError::new(
            LocalSnapshotErrorCode::ConcurrentMutation,
        ));
    }
    Ok((
        CapturedPayload::File {
            bytes,
            executable: executable(before, tracked),
        },
        read_bytes,
    ))
}

fn read_file_cancellable(
    file: &mut File,
    maximum_bytes: u64,
    output: &mut Vec<u8>,
    cancellation: &CancellationToken,
) -> Result<(), LocalSnapshotError> {
    const READ_CHUNK_BYTES: usize = 64 * 1_024;

    let mut buffer = vec![0_u8; READ_CHUNK_BYTES].into_boxed_slice();
    while u64::try_from(output.len())
        .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::ResourceLimit))?
        < maximum_bytes
    {
        check_cancelled(cancellation)?;
        let remaining = maximum_bytes
            .checked_sub(
                u64::try_from(output.len())
                    .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::ResourceLimit))?,
            )
            .ok_or_else(|| LocalSnapshotError::new(LocalSnapshotErrorCode::ResourceLimit))?;
        let read_limit = usize::try_from(remaining.min(READ_CHUNK_BYTES as u64))
            .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::ResourceLimit))?;
        let read = file
            .read(&mut buffer[..read_limit])
            .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::ConcurrentMutation))?;
        if read == 0 {
            break;
        }
        output.extend_from_slice(&buffer[..read]);
    }
    check_cancelled(cancellation)
}

fn capture_filesystem_symlink(
    parent: &Dir,
    name: &str,
    validator: RepositoryPathValidator,
) -> Result<CapturedPayload, LocalSnapshotError> {
    let target = parent
        .read_link_contents(name)
        .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::ConcurrentMutation))?;
    let target = target
        .to_str()
        .ok_or_else(|| LocalSnapshotError::new(LocalSnapshotErrorCode::NonUnicodePath))?;
    captured_symlink(target.as_bytes(), validator)
}

fn capture_symlink_placeholder(
    parent: &Dir,
    name: &str,
    before: &Metadata,
    before_stamp: MetadataStamp,
    validator: RepositoryPathValidator,
    cancellation: &CancellationToken,
) -> Result<CapturedPayload, LocalSnapshotError> {
    let mut file = open_regular_nofollow(parent, name)?;
    let opened = file
        .metadata()
        .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::ConcurrentMutation))?;
    if !opened.is_file() || MetadataStamp::new(&opened) != before_stamp {
        return Err(LocalSnapshotError::new(
            LocalSnapshotErrorCode::ConcurrentMutation,
        ));
    }
    let maximum = u64::try_from(automata_ci_workflow_github::USTAR_LINK_NAME_BYTES)
        .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::ResourceLimit))?;
    let mut bytes = Vec::new();
    read_file_cancellable(&mut file, maximum + 1, &mut bytes, cancellation)?;
    if bytes.len() > automata_ci_workflow_github::USTAR_LINK_NAME_BYTES {
        return Err(LocalSnapshotError::new(
            LocalSnapshotErrorCode::ResourceLimit,
        ));
    }
    let after = file
        .metadata()
        .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::ConcurrentMutation))?;
    if MetadataStamp::new(&after) != before_stamp || before.len() != after.len() {
        return Err(LocalSnapshotError::new(
            LocalSnapshotErrorCode::ConcurrentMutation,
        ));
    }
    captured_symlink(&bytes, validator)
}

fn captured_symlink(
    raw_target: &[u8],
    validator: RepositoryPathValidator,
) -> Result<CapturedPayload, LocalSnapshotError> {
    let target = validator
        .validate_symlink_target(raw_target)
        .map_err(local_link_validation_error)?;
    Ok(CapturedPayload::Symlink {
        target: target.to_owned(),
    })
}

fn local_link_validation_error(error: RepositoryPathValidationError) -> LocalSnapshotError {
    LocalSnapshotError::new(match error {
        RepositoryPathValidationError::NonUnicode => LocalSnapshotErrorCode::NonUnicodePath,
        RepositoryPathValidationError::ResourceLimit => LocalSnapshotErrorCode::ResourceLimit,
        RepositoryPathValidationError::Unsafe => LocalSnapshotErrorCode::UnsafeSymlink,
    })
}

fn verify_git_state(initial: &GitState, final_state: &GitState) -> Result<(), LocalSnapshotError> {
    if initial.head != final_state.head
        || initial.index != final_state.index
        || initial.inventory != final_state.inventory
        || initial.status != final_state.status
    {
        return Err(LocalSnapshotError::new(
            LocalSnapshotErrorCode::ConcurrentMutation,
        ));
    }
    Ok(())
}

fn verify_deleted_paths(
    worktree: &PinnedDirectory,
    deleted_paths: &[String],
    cancellation: &CancellationToken,
) -> Result<(), LocalSnapshotError> {
    for path in deleted_paths {
        check_cancelled(cancellation)?;
        if let Some((parent, name)) = worktree.locate_parent(path)? {
            match parent.symlink_metadata(name) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                _ => {
                    return Err(LocalSnapshotError::new(
                        LocalSnapshotErrorCode::ConcurrentMutation,
                    ));
                }
            }
        }
    }
    Ok(())
}

fn build_archive(
    entries: &[CapturedEntry],
    limits: RepositoryWorkflowDiscoveryLimits,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>, LocalSnapshotError> {
    check_cancelled(cancellation)?;
    if entries.len() >= limits.maximum_entries() {
        return Err(LocalSnapshotError::new(
            LocalSnapshotErrorCode::ResourceLimit,
        ));
    }
    let maximum_archive_bytes = usize::try_from(limits.maximum_compressed_bytes())
        .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::ResourceLimit))?;
    let compressed = Vec::with_capacity(maximum_archive_bytes.min(64 * 1_024));
    let writer = BoundedWriter::new(compressed, maximum_archive_bytes);
    let encoder = GzBuilder::new()
        .mtime(0)
        .operating_system(255)
        .write(writer, Compression::new(6));
    let maximum_decompressed_bytes = usize::try_from(limits.maximum_decompressed_bytes())
        .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::ResourceLimit))?;
    let writer = BoundedWriter::new(encoder, maximum_decompressed_bytes);
    let mut archive = TarBuilder::new(writer);
    append_root(&mut archive).map_err(|error| archive_error(&error, cancellation))?;
    for entry in entries {
        check_cancelled(cancellation)?;
        append_entry(&mut archive, entry, cancellation)
            .map_err(|error| archive_error(&error, cancellation))?;
    }
    let writer = archive
        .into_inner()
        .map_err(|error| archive_error(&error, cancellation))?;
    let encoder = writer.into_inner();
    let writer = encoder
        .finish()
        .map_err(|error| archive_error(&error, cancellation))?;
    check_cancelled(cancellation)?;
    Ok(writer.into_inner())
}

fn append_root<W: Write>(archive: &mut TarBuilder<W>) -> io::Result<()> {
    let mut header = deterministic_header(EntryType::Directory, 0, 0o755);
    header.set_path(SNAPSHOT_ROOT)?;
    header.set_cksum();
    archive.append(&header, io::empty())
}

fn append_entry<W: Write>(
    archive: &mut TarBuilder<W>,
    entry: &CapturedEntry,
    cancellation: &CancellationToken,
) -> io::Result<()> {
    let archive_path = format!("{SNAPSHOT_ROOT}/{}", entry.path);
    match &entry.payload {
        CapturedPayload::File { bytes, executable } => {
            let size = u64::try_from(bytes.len())
                .map_err(|_| io::Error::from(io::ErrorKind::FileTooLarge))?;
            let mode = if *executable { 0o755 } else { 0o644 };
            let mut header = deterministic_header(EntryType::Regular, size, mode);
            header.set_path(archive_path)?;
            header.set_cksum();
            archive.append(
                &header,
                CancellableReader::new(Cursor::new(bytes), cancellation),
            )
        }
        CapturedPayload::Symlink { target } => {
            let mut header = deterministic_header(EntryType::Symlink, 0, 0o777);
            header.set_path(archive_path)?;
            header.set_link_name_literal(target.as_bytes())?;
            header.set_cksum();
            archive.append(&header, io::empty())
        }
    }
}

struct CancellableReader<'a, R> {
    inner: R,
    cancellation: &'a CancellationToken,
}

impl<'a, R> CancellableReader<'a, R> {
    const fn new(inner: R, cancellation: &'a CancellationToken) -> Self {
        Self {
            inner,
            cancellation,
        }
    }
}

impl<R: io::Read> io::Read for CancellableReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.cancellation.is_cancelled() {
            return Err(io::Error::other("cancelled"));
        }
        self.inner.read(buffer)
    }
}

fn deterministic_header(entry_type: EntryType, size: u64, mode: u32) -> Header {
    let mut header = Header::new_ustar();
    header.set_entry_type(entry_type);
    header.set_size(size);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header
}

fn archive_error(error: &io::Error, cancellation: &CancellationToken) -> LocalSnapshotError {
    LocalSnapshotError::new(if cancellation.is_cancelled() {
        LocalSnapshotErrorCode::Cancelled
    } else if error.kind() == io::ErrorKind::FileTooLarge {
        LocalSnapshotErrorCode::ResourceLimit
    } else {
        LocalSnapshotErrorCode::ArchiveEncoding
    })
}

#[derive(Debug)]
struct BoundedWriter<W> {
    inner: W,
    maximum_bytes: usize,
    written_bytes: usize,
}

impl<W> BoundedWriter<W> {
    const fn new(inner: W, maximum_bytes: usize) -> Self {
        Self {
            inner,
            maximum_bytes,
            written_bytes: 0,
        }
    }

    fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for BoundedWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.len() > self.maximum_bytes.saturating_sub(self.written_bytes) {
            return Err(io::Error::from(io::ErrorKind::FileTooLarge));
        }
        let written = self.inner.write(buffer)?;
        self.written_bytes = self
            .written_bytes
            .checked_add(written)
            .ok_or_else(|| io::Error::from(io::ErrorKind::FileTooLarge))?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn git_inventory_output_limit(
    limits: RepositoryWorkflowDiscoveryLimits,
) -> Result<usize, LocalSnapshotError> {
    checked_output_limit(limits, 1)
}

fn git_index_output_limit(
    limits: RepositoryWorkflowDiscoveryLimits,
) -> Result<usize, LocalSnapshotError> {
    checked_output_limit(limits, 96)
}

fn git_status_output_limit(
    limits: RepositoryWorkflowDiscoveryLimits,
) -> Result<usize, LocalSnapshotError> {
    checked_output_limit(
        limits,
        limits
            .maximum_entry_path_bytes()
            .checked_add(256)
            .ok_or_else(|| LocalSnapshotError::new(LocalSnapshotErrorCode::ResourceLimit))?,
    )
}

fn checked_output_limit(
    limits: RepositoryWorkflowDiscoveryLimits,
    overhead_per_entry: usize,
) -> Result<usize, LocalSnapshotError> {
    limits
        .maximum_entry_path_bytes()
        .checked_add(overhead_per_entry)
        .and_then(|per_entry| per_entry.checked_mul(limits.maximum_entries()))
        .and_then(|total| total.checked_add(1))
        .ok_or_else(|| LocalSnapshotError::new(LocalSnapshotErrorCode::ResourceLimit))
}

fn open_regular_nofollow(parent: &Dir, name: &str) -> Result<File, LocalSnapshotError> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    configure_regular_open(&mut options);
    let file = parent
        .open_with(name, &options)
        .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::ConcurrentMutation))?;
    let metadata = file
        .metadata()
        .map_err(|_| LocalSnapshotError::new(LocalSnapshotErrorCode::ConcurrentMutation))?;
    if !metadata.is_file() {
        return Err(LocalSnapshotError::new(
            LocalSnapshotErrorCode::ConcurrentMutation,
        ));
    }
    Ok(file)
}

fn configure_regular_open(options: &mut OpenOptions) {
    use cap_std::fs::OpenOptionsExt as _;

    let flags = i32::try_from(rustix::fs::OFlags::NONBLOCK.bits())
        .expect("Unix nonblocking flag must fit c_int");
    options.custom_flags(flags);
}

fn executable(metadata: &Metadata, tracked: Option<TrackedMode>) -> bool {
    tracked.map_or_else(
        || untracked_executable(metadata),
        |mode| mode == TrackedMode::Executable,
    )
}

fn untracked_executable(metadata: &Metadata) -> bool {
    use cap_std::fs::MetadataExt as _;

    metadata.mode() & 0o111 != 0
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

impl DirectoryIdentity {
    fn new(metadata: &Metadata) -> Self {
        use cap_fs_ext::MetadataExt as _;

        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MetadataStamp {
    device: u64,
    inode: u64,
    mode: u32,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl MetadataStamp {
    fn new(metadata: &Metadata) -> Self {
        use cap_std::fs::MetadataExt as _;

        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            length: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

/// Stable fail-closed class for local snapshot construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LocalSnapshotErrorCode {
    /// This checkpoint has not qualified exact mutation evidence on the host platform.
    /// Cooperative shutdown interrupted snapshot construction.
    Cancelled,
    /// The Git executable was unavailable.
    GitUnavailable,
    /// The pinned trusted Git executable changed during capture.
    GitExecutableChanged,
    /// Git did not complete a required read-only query.
    GitCommand,
    /// A Git query exceeded its deadline.
    GitTimeout,
    /// Git emitted a malformed response.
    GitOutput,
    /// The requested directory did not resolve to one pinned worktree and Git authority.
    NotGitWorktree,
    /// One path cannot be represented as deterministic UTF-8 archive evidence.
    NonUnicodePath,
    /// One repository-relative path is noncanonical or reserved.
    UnsafePath,
    /// The requested directory or one selected path has an unsafe ancestor.
    UnsafeAncestor,
    /// A symlink target is noncanonical, absolute, or nonportable.
    UnsafeSymlink,
    /// An index conflict or unsupported staged mode made the source ambiguous.
    IndexAmbiguity,
    /// A tracked entry was hidden from the live tree by sparse checkout.
    SparseCheckout,
    /// A tracked entry was marked assume-unchanged and could hide live bytes.
    AssumeUnchanged,
    /// Gitlinks are not accepted as sealed local source.
    Submodule,
    /// A requested ancestor or selected entry is a socket, device, FIFO,
    /// Windows reparse point, or another unsafe filesystem type.
    UnsupportedEntry,
    /// A pinned directory, Git authority, index, inventory, status, or `HEAD`
    /// changed during capture.
    ConcurrentMutation,
    /// A configured entry, path, expanded-byte, command-output, or archive bound was exceeded.
    ResourceLimit,
    /// Deterministic tar.gz encoding failed.
    ArchiveEncoding,
}

impl LocalSnapshotErrorCode {
    /// Returns one sanitized actionable failure description.
    #[must_use]
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::Cancelled => "local snapshot construction was cancelled",
            Self::GitUnavailable => "install Git at the trusted system executable path",
            Self::GitExecutableChanged => {
                "the trusted Git executable changed while the worktree was inspected"
            }
            Self::GitCommand => "Git could not inspect the requested worktree",
            Self::GitTimeout => "Git worktree inspection timed out",
            Self::GitOutput => "Git returned an unsupported worktree response",
            Self::NotGitWorktree => {
                "run this command from one direct or standard linked Git worktree"
            }
            Self::NonUnicodePath => "the worktree contains a path that is not valid Unicode",
            Self::UnsafePath => "the worktree contains a noncanonical or reserved path",
            Self::UnsafeAncestor => {
                "the requested directory or a selected path has an unsafe ancestor"
            }
            Self::UnsafeSymlink => "the worktree contains a noncanonical or unsafe symlink target",
            Self::IndexAmbiguity => "resolve the Git index conflict or unsupported staged mode",
            Self::SparseCheckout => {
                "disable sparse checkout before sealing an exact local snapshot"
            }
            Self::AssumeUnchanged => {
                "clear every assume-unchanged index flag before sealing a local snapshot"
            }
            Self::Submodule => "local snapshots do not admit ambiguous submodule content",
            Self::UnsupportedEntry => {
                "the requested path or worktree contains a reparse point or unsupported entry"
            }
            Self::ConcurrentMutation => {
                "the worktree or Git authority changed while its snapshot was being sealed"
            }
            Self::ResourceLimit => "the worktree snapshot exceeds a configured resource limit",
            Self::ArchiveEncoding => "the worktree could not be encoded deterministically",
        }
    }
}

impl std::fmt::Display for LocalSnapshotErrorCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message())
    }
}

/// Sanitized local snapshot failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("{code}")]
pub(crate) struct LocalSnapshotError {
    code: LocalSnapshotErrorCode,
}

impl LocalSnapshotError {
    const fn new(code: LocalSnapshotErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable failure class.
    #[must_use]
    pub(crate) const fn code(self) -> LocalSnapshotErrorCode {
        self.code
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        path::{Path, PathBuf},
        process::Command,
    };

    use automata_ci_core::Sha256Digest;
    use automata_ci_workflow_github::{
        GithubWorkflowDispatchInputs, RepositoryWorkflowDiscoveryLimits,
    };
    use automata_ci_workflow_service::{
        LocalGithubArchiveAnalysisFailureKind, ReusableWorkflowLimits, analyze_local_github_archive,
    };
    use flate2::read::MultiGzDecoder;
    use sha2::{Digest as _, Sha256};
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    #[cfg(unix)]
    use super::capture_snapshot_with_git;
    use super::{
        LocalSnapshotErrorCode, LocalSnapshotRequest, capture_snapshot, local_snapshot_limits,
        validate_local_snapshot_limits,
    };

    const WORKFLOW: &str =
        "on: push\njobs:\n  check:\n    runs-on: linux\n    steps:\n      - run: true\n";

    #[test]
    fn archive_cancellation_is_terminal_not_retryable_io() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let mut reader =
            super::CancellableReader::new(std::io::Cursor::new(b"payload"), &cancellation);
        let error = std::io::copy(&mut reader, &mut std::io::sink())
            .expect_err("cancellation must terminate the copy");
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert_eq!(
            super::archive_error(&error, &cancellation).code(),
            LocalSnapshotErrorCode::Cancelled
        );
    }

    fn assert_archive_policy_rejects(snapshot: &super::LocalSnapshot) {
        let error = analyze_local_github_archive(
            snapshot.archive_bytes(),
            None,
            GithubWorkflowDispatchInputs::try_new(std::iter::empty::<(String, String)>())
                .expect("empty dispatch inputs"),
            local_snapshot_limits(),
            ReusableWorkflowLimits::default(),
            &|| false,
        )
        .expect_err("unsafe archive graph must fail before workflow selection");
        assert_eq!(error.kind(), LocalGithubArchiveAnalysisFailureKind::Archive);
    }

    #[test]
    fn local_snapshot_peak_shape_has_fixed_materially_lower_bounds() {
        let limits = local_snapshot_limits();
        assert_eq!(limits.maximum_compressed_bytes(), 32 * 1024 * 1024);
        assert_eq!(limits.maximum_decompressed_bytes(), 64 * 1024 * 1024);
        assert_eq!(limits.maximum_expanded_bytes(), 32 * 1024 * 1024);
        assert_eq!(limits.maximum_entries(), 20_000);
        assert_eq!(limits.maximum_workflow_bytes(), 1024 * 1024);
        assert!(validate_local_snapshot_limits(limits).is_ok());
        assert_eq!(
            validate_local_snapshot_limits(RepositoryWorkflowDiscoveryLimits::default()),
            Err(super::LocalSnapshotError::new(
                LocalSnapshotErrorCode::ResourceLimit
            ))
        );
    }

    #[tokio::test]
    async fn clean_dirty_ignored_and_cloned_worktrees_have_deterministic_exact_archives() {
        let fixture = Fixture::new();
        fixture.write(".gitignore", "ignored/\n");
        fixture.write(".github/workflows/ci.yml", WORKFLOW);
        fixture.write("tracked.txt", "clean\n");
        fixture.commit_all("initial");
        let git_before = fixture.git_tree_evidence();

        let clean = fixture.capture().await.expect("clean snapshot");
        let repeated = fixture.capture().await.expect("repeated clean snapshot");
        assert_eq!(clean.digest(), repeated.digest());
        assert_eq!(clean.archive_bytes(), repeated.archive_bytes());
        assert!(!clean.dirty());
        assert_eq!(
            clean.digest(),
            Sha256Digest::from_bytes(Sha256::digest(clean.archive_bytes()).into())
        );
        assert_eq!(&clean.archive_bytes()[4..8], &[0, 0, 0, 0]);
        assert_eq!(clean.archive_bytes()[9], 255);
        assert_eq!(fixture.git_tree_evidence(), git_before);

        let clone = Fixture::clone_from(fixture.path());
        let cloned = clone.capture().await.expect("cloned clean snapshot");
        assert_eq!(cloned.digest(), clean.digest());
        assert_eq!(cloned.archive_bytes(), clean.archive_bytes());

        fixture.write("tracked.txt", "dirty tracked bytes\n");
        fixture.write("untracked.txt", "untracked bytes\n");
        fixture.write("ignored/cache.bin", "ignored one\n");
        let dirty = fixture.capture().await.expect("dirty snapshot");
        let repeated_dirty = fixture.capture().await.expect("repeated dirty snapshot");
        assert!(dirty.dirty());
        assert_ne!(dirty.digest(), clean.digest());
        assert_eq!(dirty.digest(), repeated_dirty.digest());
        assert_eq!(dirty.archive_bytes(), repeated_dirty.archive_bytes());

        fixture.write("ignored/cache.bin", "ignored content changed completely\n");
        let ignored_change = fixture.capture().await.expect("ignored change snapshot");
        assert_eq!(ignored_change.digest(), dirty.digest());
        assert_eq!(ignored_change.archive_bytes(), dirty.archive_bytes());
    }

    #[tokio::test]
    async fn requested_subdirectories_are_bound_to_the_reported_worktree_root() {
        let fixture = Fixture::new();
        fixture.write("nested/file.txt", "tracked\n");
        fixture.commit_all("subdirectory invocation");

        let root = fixture.capture().await.expect("root snapshot");
        let nested = capture_snapshot(
            LocalSnapshotRequest::new(fixture.path().join("nested"), local_snapshot_limits()),
            &CancellationToken::new(),
        )
        .await
        .expect("nested invocation");
        assert_eq!(nested.archive_bytes(), root.archive_bytes());

        let nested_repository = fixture.path().join("nested");
        fixture.git(&["-C", "nested", "init", "--quiet"]);
        fixture.git(&["-C", "nested", "config", "user.name", "Automata Test"]);
        fixture.git(&[
            "-C",
            "nested",
            "config",
            "user.email",
            "automata@example.invalid",
        ]);
        fixture.git(&["-C", "nested", "add", "--all"]);
        fixture.git(&[
            "-C",
            "nested",
            "commit",
            "--quiet",
            "--message",
            "nested repository",
        ]);
        let nested_authority = capture_snapshot(
            LocalSnapshotRequest::new(&nested_repository, local_snapshot_limits()),
            &CancellationToken::new(),
        )
        .await
        .expect("nested repository authority");
        assert!(!nested_authority.archive_bytes().is_empty());

        fixture.git(&[
            "-C",
            "nested",
            "config",
            "core.worktree",
            fixture.path().to_str().expect("Unicode fixture path"),
        ]);
        assert_eq!(
            capture_snapshot(
                LocalSnapshotRequest::new(&nested_repository, local_snapshot_limits(),),
                &CancellationToken::new(),
            )
            .await
            .unwrap_err()
            .code(),
            LocalSnapshotErrorCode::NotGitWorktree
        );

        let redirected = Fixture::new();
        let other_worktree = Fixture::new();
        redirected.git(&[
            "config",
            "core.worktree",
            other_worktree
                .path()
                .to_str()
                .expect("Unicode fixture path"),
        ]);
        assert_eq!(
            redirected.capture().await.unwrap_err().code(),
            LocalSnapshotErrorCode::NotGitWorktree
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn git_locator_accepts_only_direct_or_linked_worktree_authority() {
        use std::os::unix::fs::symlink;

        let primary = Fixture::new();
        primary.write("tracked.txt", "tracked\n");
        primary.commit_all("linked worktree fixture");
        let linked_root = std::env::temp_dir().join(format!(
            "automata-local-snapshot-linked-{}",
            Uuid::new_v4().simple()
        ));
        primary.git(&[
            "worktree",
            "add",
            "--quiet",
            linked_root.to_str().expect("Unicode fixture path"),
            "HEAD",
        ]);
        let linked = Fixture { root: linked_root };
        let primary_snapshot = primary.capture().await.expect("primary worktree snapshot");
        let linked_snapshot = linked.capture().await.expect("linked worktree snapshot");
        assert_eq!(linked_snapshot.digest(), primary_snapshot.digest());

        let symlink_locator = Fixture::new();
        symlink_locator.write("tracked.txt", "tracked\n");
        symlink_locator.commit_all("symlink locator fixture");
        fs::rename(
            symlink_locator.path().join(".git"),
            symlink_locator.path().join(".git-real"),
        )
        .expect("move Git directory");
        symlink(".git-real", symlink_locator.path().join(".git"))
            .expect("create Git locator symlink");
        assert_eq!(
            symlink_locator.capture().await.unwrap_err().code(),
            LocalSnapshotErrorCode::NotGitWorktree
        );

        let separate_git_directory = Fixture::new();
        separate_git_directory.write("tracked.txt", "tracked\n");
        separate_git_directory.commit_all("separate Git directory fixture");
        let storage = separate_git_directory.path().join(".git-storage");
        fs::rename(separate_git_directory.path().join(".git"), &storage)
            .expect("move separate Git directory");
        fs::write(
            separate_git_directory.path().join(".git"),
            format!("gitdir: {}\n", storage.display()),
        )
        .expect("write separate Git locator");
        assert_eq!(
            separate_git_directory.capture().await.unwrap_err().code(),
            LocalSnapshotErrorCode::NotGitWorktree
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn linked_worktree_gitfile_mutation_is_detected() {
        use std::os::unix::fs::PermissionsExt as _;

        let primary = Fixture::new();
        primary.write("tracked.txt", "tracked\n");
        primary.commit_all("linked mutation fixture");
        let linked_root = std::env::temp_dir().join(format!(
            "automata-local-snapshot-linked-mutation-{}",
            Uuid::new_v4().simple()
        ));
        primary.git(&[
            "worktree",
            "add",
            "--quiet",
            linked_root.to_str().expect("Unicode fixture path"),
            "HEAD",
        ]);
        let linked = Fixture { root: linked_root };
        let linked_wrapper = primary.path().join(".git/fake-linked-git");
        fs::write(
            &linked_wrapper,
            format!(
                "#!/bin/sh\nset -eu\ncase \" $* \" in\n  *' status '*)\n    git \"$@\"\n    result=$?\n    printf 'gitdir: %s\\n' '{}' > '{}'\n    exit \"$result\"\n    ;;\nesac\nexec git \"$@\"\n",
                primary.path().join(".git").display(),
                linked.path().join(".git").display()
            ),
        )
        .expect("write linked-worktree Git wrapper");
        fs::set_permissions(&linked_wrapper, fs::Permissions::from_mode(0o700))
            .expect("make linked-worktree Git wrapper executable");
        let linked_error = capture_snapshot_with_git(
            LocalSnapshotRequest::new(linked.path(), local_snapshot_limits()),
            &linked_wrapper,
        )
        .await
        .unwrap_err();
        assert_eq!(
            linked_error.code(),
            LocalSnapshotErrorCode::ConcurrentMutation
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn linked_worktree_git_directory_retargeting_is_detected() {
        use std::os::unix::fs::PermissionsExt as _;

        let admin_primary = Fixture::new();
        admin_primary.write("tracked.txt", "tracked\n");
        admin_primary.commit_all("linked Git directory mutation fixture");
        let admin_linked_root = std::env::temp_dir().join(format!(
            "automata-local-snapshot-linked-admin-mutation-{}",
            Uuid::new_v4().simple()
        ));
        admin_primary.git(&[
            "worktree",
            "add",
            "--quiet",
            admin_linked_root.to_str().expect("Unicode fixture path"),
            "HEAD",
        ]);
        let admin_linked = Fixture {
            root: admin_linked_root,
        };
        let admin_directory = PathBuf::from(admin_linked.git_stdout(&[
            "rev-parse",
            "--path-format=absolute",
            "--absolute-git-dir",
        ]));
        let moved_admin_directory = admin_directory.with_extension("original");
        let admin_wrapper = admin_primary.path().join(".git/fake-admin-git");
        fs::write(
            &admin_wrapper,
            format!(
                "#!/bin/sh\nset -eu\ncase \" $* \" in\n  *' status '*)\n    git \"$@\"\n    result=$?\n    mv '{}' '{}'\n    mkdir '{}'\n    exit \"$result\"\n    ;;\nesac\nexec git \"$@\"\n",
                admin_directory.display(),
                moved_admin_directory.display(),
                admin_directory.display()
            ),
        )
        .expect("write linked Git-directory wrapper");
        fs::set_permissions(&admin_wrapper, fs::Permissions::from_mode(0o700))
            .expect("make linked Git-directory wrapper executable");
        let admin_error = capture_snapshot_with_git(
            LocalSnapshotRequest::new(admin_linked.path(), local_snapshot_limits()),
            &admin_wrapper,
        )
        .await
        .unwrap_err();
        assert_eq!(
            admin_error.code(),
            LocalSnapshotErrorCode::ConcurrentMutation
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn direct_worktree_git_directory_retargeting_is_detected() {
        use std::os::unix::fs::PermissionsExt as _;

        let direct = Fixture::new();
        direct.write("tracked.txt", "tracked\n");
        direct.commit_all("directory mutation fixture");
        let direct_wrapper = direct.path().join(".git/fake-direct-git");
        fs::write(
            &direct_wrapper,
            format!(
                "#!/bin/sh\nset -eu\ncase \" $* \" in\n  *' status '*)\n    git \"$@\"\n    result=$?\n    mv '{}' '{}'\n    mkdir '{}'\n    exit \"$result\"\n    ;;\nesac\nexec git \"$@\"\n",
                direct.path().join(".git").display(),
                direct.path().join(".git-original").display(),
                direct.path().join(".git").display()
            ),
        )
        .expect("write direct-worktree Git wrapper");
        fs::set_permissions(&direct_wrapper, fs::Permissions::from_mode(0o700))
            .expect("make direct-worktree Git wrapper executable");
        let direct_error = capture_snapshot_with_git(
            LocalSnapshotRequest::new(direct.path(), local_snapshot_limits()),
            &direct_wrapper,
        )
        .await
        .unwrap_err();
        assert_eq!(
            direct_error.code(),
            LocalSnapshotErrorCode::ConcurrentMutation
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn caller_symlink_ancestor_is_rejected_before_git_runs() {
        use std::os::unix::fs::symlink;

        let repository = Fixture::new();
        repository.write("nested/tracked", "tracked\n");
        repository.commit_all("caller symlink fixture");
        let alias_host = Fixture::new();
        symlink(repository.path(), alias_host.path().join("alias"))
            .expect("create caller path alias");

        let error = capture_snapshot_with_git(
            LocalSnapshotRequest::new(
                alias_host.path().join("alias/nested"),
                local_snapshot_limits(),
            ),
            Path::new("/definitely-not-an-automata-test-git"),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), LocalSnapshotErrorCode::UnsafeAncestor);
    }

    #[tokio::test]
    async fn live_worktree_bytes_and_deletions_win_over_index_content() {
        let fixture = Fixture::new();
        fixture.write(".github/workflows/ci.yml", WORKFLOW);
        fixture.write("deleted.txt", "delete me\n");
        fixture.write("staged.txt", "committed\n");
        fixture.commit_all("initial");

        fixture.write("staged.txt", "staged bytes\n");
        fixture.git(&["add", "staged.txt"]);
        fixture.write("staged.txt", "live bytes after staging\n");
        fs::remove_file(fixture.path().join("deleted.txt")).expect("delete tracked file");

        let snapshot = fixture.capture().await.expect("dirty source snapshot");
        let files = archive_files(snapshot.archive_bytes());
        assert_eq!(
            files.get("staged.txt").unwrap(),
            b"live bytes after staging\n"
        );
        assert!(!files.contains_key("deleted.txt"));
        assert_eq!(
            files.get(".github/workflows/ci.yml").unwrap(),
            WORKFLOW.as_bytes()
        );
    }

    #[tokio::test]
    async fn sparse_and_assume_unchanged_index_flags_fail_closed_while_clean() {
        let sparse = Fixture::new();
        sparse.write("included/keep.txt", "keep\n");
        sparse.write("excluded/hidden.txt", "hidden\n");
        sparse.commit_all("sparse source");
        sparse.git(&["sparse-checkout", "init", "--cone"]);
        sparse.git(&["sparse-checkout", "set", "included"]);
        assert!(!sparse.path().join("excluded/hidden.txt").exists());
        assert_eq!(sparse.git_stdout(&["status", "--porcelain"]), "");
        assert_eq!(
            sparse.capture().await.unwrap_err().code(),
            LocalSnapshotErrorCode::SparseCheckout
        );

        let assumed = Fixture::new();
        assumed.write("tracked.txt", "committed\n");
        assumed.commit_all("assume-unchanged source");
        assumed.git(&["update-index", "--assume-unchanged", "tracked.txt"]);
        assumed.write("tracked.txt", "live bytes hidden from status\n");
        assert_eq!(assumed.git_stdout(&["status", "--porcelain"]), "");
        assert_eq!(
            assumed.capture().await.unwrap_err().code(),
            LocalSnapshotErrorCode::AssumeUnchanged
        );
    }

    #[tokio::test]
    async fn noncanonical_workflow_namespace_spelling_fails_closed() {
        let namespace_spelling = Fixture::new();
        namespace_spelling.write(".github/WORKFLOWS/ci.yml", WORKFLOW);
        namespace_spelling.commit_all("noncanonical workflow namespace");
        assert_eq!(
            namespace_spelling.capture().await.unwrap_err().code(),
            LocalSnapshotErrorCode::UnsafePath
        );
    }

    #[tokio::test]
    async fn expanded_entry_and_encoded_archive_bounds_are_independent() {
        let fixture = Fixture::new();
        fixture.write("file.txt", "12345");
        fixture.commit_all("bounded");

        let expanded = limits(1_024 * 1_024, 4, 10);
        assert_eq!(
            capture_snapshot(
                LocalSnapshotRequest::new(fixture.path(), expanded),
                &CancellationToken::new(),
            )
            .await
            .unwrap_err()
            .code(),
            LocalSnapshotErrorCode::ResourceLimit
        );

        let exact_entries = limits(1_024 * 1_024, 1_024 * 1_024, 2);
        fixture
            .capture_with_limits(exact_entries)
            .await
            .expect("one root and one file fit the exact entry bound");
        fixture.write("second.txt", "x");
        assert_eq!(
            capture_snapshot(
                LocalSnapshotRequest::new(fixture.path(), exact_entries),
                &CancellationToken::new(),
            )
            .await
            .unwrap_err()
            .code(),
            LocalSnapshotErrorCode::ResourceLimit
        );

        fs::remove_file(fixture.path().join("second.txt")).expect("remove bound fixture");
        let decompressed = RepositoryWorkflowDiscoveryLimits::new(
            1_024 * 1_024,
            1,
            10,
            1_024 * 1_024,
            4_096,
            10,
            1_024 * 1_024,
        )
        .expect("decompressed-byte test limits");
        assert_eq!(
            capture_snapshot(
                LocalSnapshotRequest::new(fixture.path(), decompressed),
                &CancellationToken::new(),
            )
            .await
            .unwrap_err()
            .code(),
            LocalSnapshotErrorCode::ResourceLimit
        );

        let encoded = limits(1, 1_024 * 1_024, 10);
        assert_eq!(
            capture_snapshot(
                LocalSnapshotRequest::new(fixture.path(), encoded),
                &CancellationToken::new(),
            )
            .await
            .unwrap_err()
            .code(),
            LocalSnapshotErrorCode::ResourceLimit
        );
    }

    #[tokio::test]
    async fn gitlink_submodules_are_rejected_before_filesystem_capture() {
        let fixture = Fixture::new();
        fixture.write("tracked.txt", "tracked\n");
        fixture.commit_all("submodule base");
        let head = fixture.git_stdout(&["rev-parse", "HEAD"]);
        let cache_info = format!("160000,{head},module");
        fixture.git(&["update-index", "--add", "--cacheinfo", &cache_info]);

        assert_eq!(
            fixture.capture().await.unwrap_err().code(),
            LocalSnapshotErrorCode::Submodule
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinks_are_captured_exactly_and_archive_policy_rejects_escapes() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new();
        fixture.write(".github/workflows/ci.yml", WORKFLOW);
        fixture.write("data/value.txt", "value\n");
        fs::create_dir(fixture.path().join("links")).expect("create symlink directory");
        symlink("../data/value.txt", fixture.path().join("links/value"))
            .expect("create safe symlink");
        fixture.commit_all("safe symlink");
        let snapshot = fixture.capture().await.expect("safe symlink snapshot");
        let links = archive_symlinks(snapshot.archive_bytes());
        assert_eq!(
            links.get("links/value").map(String::as_str),
            Some("../data/value.txt")
        );

        fs::remove_file(fixture.path().join("links/value")).expect("remove safe symlink");
        symlink("../../../outside", fixture.path().join("links/value"))
            .expect("create escaping symlink");
        let escaping = fixture
            .capture()
            .await
            .expect("exact escaping-link snapshot");
        assert_archive_policy_rejects(&escaping);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn git_symlink_mode_normalizes_placeholders_and_rejects_regular_file_type_changes() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new();
        fixture.write("data/value.txt", "value\n");
        fs::create_dir(fixture.path().join("links")).expect("create link parent");
        symlink("../data/value.txt", fixture.path().join("links/value"))
            .expect("create tracked symlink");
        fixture.commit_all("tracked symlink");
        let native = fixture.capture().await.expect("native symlink snapshot");

        fs::remove_file(fixture.path().join("links/value")).expect("remove native symlink");
        fixture.write("links/value", "../data/value.txt");
        let placeholder = fixture
            .capture()
            .await
            .expect("Git-mode symlink placeholder snapshot");
        assert_eq!(placeholder.archive_bytes(), native.archive_bytes());
        assert_eq!(placeholder.digest(), native.digest());

        let type_change = Fixture::new();
        type_change.write("regular", "regular\n");
        type_change.write("target", "target\n");
        type_change.commit_all("tracked regular file");
        fs::remove_file(type_change.path().join("regular")).expect("remove regular file");
        symlink("target", type_change.path().join("regular")).expect("replace with symlink");
        assert_eq!(
            type_change.capture().await.unwrap_err().code(),
            LocalSnapshotErrorCode::IndexAmbiguity
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_ancestors_and_workflow_namespace_aliases_fail_closed() {
        use std::os::unix::fs::symlink;

        let ancestor = Fixture::new();
        ancestor.write("directory/file", "tracked\n");
        ancestor.commit_all("tracked directory");
        fs::remove_dir_all(ancestor.path().join("directory")).expect("remove tracked directory");
        symlink("replacement", ancestor.path().join("directory"))
            .expect("replace ancestor with symlink");
        assert_eq!(
            ancestor.capture().await.unwrap_err().code(),
            LocalSnapshotErrorCode::UnsafeAncestor
        );

        let nondirectory = Fixture::new();
        nondirectory.write("directory/file", "tracked\n");
        nondirectory.commit_all("tracked directory");
        fs::remove_dir_all(nondirectory.path().join("directory"))
            .expect("remove tracked directory");
        nondirectory.write("directory", "replacement file\n");
        assert_eq!(
            nondirectory.capture().await.unwrap_err().code(),
            LocalSnapshotErrorCode::UnsafeAncestor
        );

        let namespace = Fixture::new();
        namespace.write(".ci/workflows/ci.yml", WORKFLOW);
        symlink(".ci", namespace.path().join("alternate")).expect("alias workflow namespace");
        namespace.commit_all("namespace alias");
        let namespace = namespace
            .capture()
            .await
            .expect("exact namespace-link snapshot");
        assert_archive_policy_rejects(&namespace);

        let cycle = Fixture::new();
        symlink("two", cycle.path().join("one")).expect("first cycle link");
        symlink("one", cycle.path().join("two")).expect("second cycle link");
        cycle.write("tracked", "tracked\n");
        cycle.commit_all("symlink cycle");
        let cycle = cycle.capture().await.expect("exact cyclic-link snapshot");
        assert_archive_policy_rejects(&cycle);
    }

    #[tokio::test]
    async fn ustar_path_shape_component_aliases_and_nested_deletions_are_exact() {
        let exact = Fixture::new();
        exact.write(&"a".repeat(100), "exact ustar name field\n");
        exact.write(
            &format!("{}/{}", "p".repeat(146), "n".repeat(100)),
            "exact ustar prefix and name fields\n",
        );
        exact.commit_all("exact ustar path");
        exact.capture().await.expect("exact ustar path boundary");

        let oversized = Fixture::new();
        oversized.write(&"a".repeat(101), "unsplittable ustar path\n");
        oversized.write(
            &format!("{}/{}", "p".repeat(147), "n".repeat(100)),
            "oversized ustar prefix field\n",
        );
        oversized.commit_all("oversized ustar path");
        assert_eq!(
            oversized.capture().await.unwrap_err().code(),
            LocalSnapshotErrorCode::ResourceLimit
        );

        let aliases = Fixture::new();
        aliases.write("Directory/one", "one\n");
        aliases.write("directory/two", "two\n");
        aliases.commit_all("component aliases");
        let alias_snapshot = aliases.capture().await.expect("exact alias archive");
        let alias_files = archive_files(alias_snapshot.archive_bytes());
        assert_eq!(alias_files.get("Directory/one").unwrap(), b"one\n");
        assert_eq!(alias_files.get("directory/two").unwrap(), b"two\n");

        let deletion = Fixture::new();
        deletion.write("nested/deleted", "delete me\n");
        deletion.write("retained", "retain me\n");
        deletion.commit_all("nested deletion");
        fs::remove_dir_all(deletion.path().join("nested")).expect("delete tracked directory");
        let snapshot = deletion.capture().await.expect("nested deletion snapshot");
        let files = archive_files(snapshot.archive_bytes());
        assert!(!files.contains_key("nested/deleted"));
        assert_eq!(files.get("retained").unwrap(), b"retain me\n");
    }

    #[cfg(unix)]
    #[test]
    fn absolute_directory_open_pins_each_ancestor_without_following_links() {
        use std::os::unix::fs::symlink;

        use super::open_absolute_directory_nofollow;

        let fixture = Fixture::new();
        fs::create_dir_all(fixture.path().join("real/leaf")).expect("create real directories");
        symlink("real", fixture.path().join("alias")).expect("create ancestor symlink");
        open_absolute_directory_nofollow(
            &fixture.path().join("real/leaf"),
            LocalSnapshotErrorCode::NotGitWorktree,
        )
        .expect("ordinary ancestors");
        assert_eq!(
            open_absolute_directory_nofollow(
                &fixture.path().join("alias/leaf"),
                LocalSnapshotErrorCode::NotGitWorktree,
            )
            .unwrap_err()
            .code(),
            LocalSnapshotErrorCode::UnsafeAncestor
        );
    }

    #[test]
    fn pinned_directory_identity_ignores_mutable_directory_metadata() {
        use super::{MetadataStamp, PinnedDirectory};

        let fixture = Fixture::new();
        let pinned = PinnedDirectory::open(fixture.path()).expect("pin fixture directory");
        let before = MetadataStamp::new(
            &pinned
                .handle
                .dir_metadata()
                .expect("read initial directory metadata"),
        );
        fs::write(fixture.path().join("transient"), b"mutation")
            .expect("mutate directory metadata");
        let after = MetadataStamp::new(
            &pinned
                .handle
                .dir_metadata()
                .expect("read changed directory metadata"),
        );
        assert_ne!(
            before, after,
            "fixture must change a mutable directory stamp"
        );
        pinned
            .verify_ambient_path(fixture.path())
            .expect("stable directory identity survives metadata changes");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn non_unicode_fifo_and_socket_entries_fail_closed() {
        use std::{
            ffi::OsString,
            os::unix::{ffi::OsStringExt as _, net::UnixListener},
        };

        let non_unicode = Fixture::new();
        let invalid = OsString::from_vec(b"invalid-\xff".to_vec());
        fs::write(non_unicode.path().join(invalid), b"bytes").expect("write non-Unicode path");
        non_unicode.write("tracked.txt", "tracked\n");
        non_unicode.commit_all("non-Unicode fixture");
        assert_eq!(
            non_unicode.capture().await.unwrap_err().code(),
            LocalSnapshotErrorCode::NonUnicodePath
        );

        let fifo = Fixture::new();
        fifo.write("tracked.txt", "tracked\n");
        fifo.commit_all("fifo fixture");
        let fifo_status = Command::new("mkfifo")
            .arg(fifo.path().join("pipe"))
            .status()
            .expect("run mkfifo");
        assert!(fifo_status.success(), "create FIFO fixture");
        assert_eq!(
            fifo.capture().await.unwrap_err().code(),
            LocalSnapshotErrorCode::UnsupportedEntry
        );

        let ignored_fifo = Fixture::new();
        ignored_fifo.write(".gitignore", "ignored-pipe\n");
        ignored_fifo.write("tracked.txt", "tracked\n");
        ignored_fifo.commit_all("ignored FIFO fixture");
        let ignored_fifo_status = Command::new("mkfifo")
            .arg(ignored_fifo.path().join("ignored-pipe"))
            .status()
            .expect("run mkfifo for ignored fixture");
        assert!(ignored_fifo_status.success(), "create ignored FIFO fixture");
        ignored_fifo
            .capture()
            .await
            .expect("ignored special entries are outside the selected inventory");

        let socket = Fixture::new();
        socket.write("tracked.txt", "tracked\n");
        socket.commit_all("socket fixture");
        let _listener =
            UnixListener::bind(socket.path().join("service.sock")).expect("create Unix socket");
        assert_eq!(
            socket.capture().await.unwrap_err().code(),
            LocalSnapshotErrorCode::UnsupportedEntry
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn mutation_between_git_inventory_and_file_capture_is_detected() {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = Fixture::new();
        fixture.write("tracked.txt", "initial\n");
        fixture.commit_all("mutation fixture");
        let wrapper = fixture.path().join(".git/fake-git");
        let marker = fixture.path().join(".git/mutation-marker");
        let target = fixture.path().join("tracked.txt");
        fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\nset -eu\ncase \" $* \" in\n  *' status '*)\n    if [ ! -e '{}' ]; then\n      git \"$@\"\n      result=$?\n      : > '{}'\n      printf '%s\\n' mutation >> '{}'\n      exit \"$result\"\n    fi\n    ;;\nesac\nexec git \"$@\"\n",
                marker.display(),
                marker.display(),
                target.display()
            ),
        )
        .expect("write fake Git wrapper");
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700))
            .expect("make fake Git executable");

        let error = capture_snapshot_with_git(
            LocalSnapshotRequest::new(fixture.path(), local_snapshot_limits()),
            &wrapper,
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), LocalSnapshotErrorCode::ConcurrentMutation);
    }

    fn limits(compressed: u64, expanded: u64, entries: usize) -> RepositoryWorkflowDiscoveryLimits {
        RepositoryWorkflowDiscoveryLimits::new(
            compressed,
            expanded.max(1),
            entries,
            expanded,
            4_096,
            entries,
            expanded,
        )
        .expect("test limits")
    }

    fn archive_files(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
        use std::io::Read as _;

        let mut archive = tar::Archive::new(MultiGzDecoder::new(bytes));
        let mut files = BTreeMap::new();
        for entry in archive.entries().expect("archive entries") {
            let mut entry = entry.expect("archive entry");
            if !entry.header().entry_type().is_file() {
                continue;
            }
            let path = entry.path().expect("archive path").into_owned();
            let path = path
                .strip_prefix("worktree")
                .expect("snapshot root")
                .to_str()
                .expect("Unicode archive path")
                .trim_start_matches('/')
                .to_owned();
            let mut contents = Vec::new();
            entry.read_to_end(&mut contents).expect("archive contents");
            files.insert(path, contents);
        }
        files
    }

    #[cfg(unix)]
    fn archive_symlinks(bytes: &[u8]) -> BTreeMap<String, String> {
        let mut archive = tar::Archive::new(MultiGzDecoder::new(bytes));
        let mut links = BTreeMap::new();
        for entry in archive.entries().expect("archive entries") {
            let entry = entry.expect("archive entry");
            if !entry.header().entry_type().is_symlink() {
                continue;
            }
            let path = entry.path().expect("archive path").into_owned();
            let path = path
                .strip_prefix("worktree")
                .expect("snapshot root")
                .to_str()
                .expect("Unicode archive path")
                .trim_start_matches('/')
                .to_owned();
            let target = entry
                .link_name()
                .expect("symlink target")
                .expect("present symlink target")
                .into_owned()
                .to_str()
                .expect("Unicode symlink target")
                .to_owned();
            links.insert(path, target);
        }
        links
    }

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "automata-local-snapshot-{}",
                Uuid::new_v4().simple()
            ));
            fs::create_dir(&root).expect("create fixture root");
            let fixture = Self { root };
            fixture.git(&["init", "--quiet"]);
            fixture.git(&["config", "user.name", "Automata Test"]);
            fixture.git(&["config", "user.email", "automata@example.invalid"]);
            fixture
        }

        fn clone_from(source: &Path) -> Self {
            let root = std::env::temp_dir().join(format!(
                "automata-local-snapshot-clone-{}",
                Uuid::new_v4().simple()
            ));
            let output = Command::new("git")
                .args(["clone", "--quiet"])
                .arg(source)
                .arg(&root)
                .output()
                .expect("clone fixture");
            assert!(output.status.success(), "git clone failed");
            Self { root }
        }

        fn path(&self) -> &Path {
            &self.root
        }

        fn write(&self, path: &str, contents: &str) {
            let path = self.root.join(path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create fixture parent");
            }
            fs::write(path, contents).expect("write fixture file");
        }

        fn git(&self, arguments: &[&str]) {
            let output = Command::new("git")
                .arg("--no-optional-locks")
                .args(["-c", "maintenance.auto=false"])
                .arg("-C")
                .arg(&self.root)
                .args(arguments)
                .output()
                .expect("run fixture Git command");
            assert!(
                output.status.success(),
                "git {arguments:?} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        fn git_stdout(&self, arguments: &[&str]) -> String {
            let output = Command::new("git")
                .arg("--no-optional-locks")
                .args(["-c", "maintenance.auto=false"])
                .arg("-C")
                .arg(&self.root)
                .args(arguments)
                .output()
                .expect("run fixture Git command");
            assert!(output.status.success(), "git {arguments:?} failed");
            String::from_utf8(output.stdout)
                .expect("Git fixture output must be UTF-8")
                .trim()
                .to_owned()
        }

        fn commit_all(&self, message: &str) {
            self.git(&["add", "--all"]);
            self.git(&["commit", "--quiet", "--message", message]);
        }

        async fn capture(&self) -> Result<super::LocalSnapshot, super::LocalSnapshotError> {
            self.capture_with_limits(local_snapshot_limits()).await
        }

        async fn capture_with_limits(
            &self,
            limits: RepositoryWorkflowDiscoveryLimits,
        ) -> Result<super::LocalSnapshot, super::LocalSnapshotError> {
            capture_snapshot(
                LocalSnapshotRequest::new(&self.root, limits),
                &CancellationToken::new(),
            )
            .await
        }

        fn git_tree_evidence(&self) -> Vec<(String, Vec<u8>, Option<std::time::SystemTime>)> {
            let mut evidence = Vec::new();
            collect_git_evidence(
                &self.root.join(".git"),
                &self.root.join(".git"),
                &mut evidence,
            );
            evidence.sort_by(|left, right| left.0.cmp(&right.0));
            evidence
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.root);
        }
    }

    fn collect_git_evidence(
        root: &Path,
        directory: &Path,
        evidence: &mut Vec<(String, Vec<u8>, Option<std::time::SystemTime>)>,
    ) {
        let mut entries = fs::read_dir(directory)
            .expect("read Git evidence directory")
            .map(|entry| entry.expect("read Git evidence entry"))
            .collect::<Vec<_>>();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).expect("Git evidence metadata");
            if metadata.is_dir() {
                collect_git_evidence(root, &path, evidence);
            } else if metadata.is_file() {
                evidence.push((
                    path.strip_prefix(root)
                        .expect("Git evidence root")
                        .to_string_lossy()
                        .into_owned(),
                    fs::read(&path).expect("read Git evidence file"),
                    metadata.modified().ok(),
                ));
            }
        }
    }
}
