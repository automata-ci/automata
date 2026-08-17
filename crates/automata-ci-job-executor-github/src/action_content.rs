use std::time::Duration;

use automata_ci_core::OperationId;
use automata_ci_execution::{
    CopyToRequest, ExecutionArgv, ExecutionCommand, ExecutionEnvironment, TargetPath,
    TargetPlatform,
};

use crate::error::{ExecutorAdapterError, ExecutorAdapterErrorKind};

const DIRECTORY_MODE: &str = "0700";

#[allow(clippy::too_many_arguments)]
pub(super) fn prepare_directory_command(
    operation_id: OperationId,
    install: TargetPath,
    workspace: &TargetPath,
    base: &TargetPath,
    extracted: &TargetPath,
    timeout: Duration,
    output_limit: usize,
) -> Result<ExecutionCommand, ExecutorAdapterError> {
    let argv = ExecutionArgv::new(
        install,
        vec![
            "-d".to_owned(),
            "-m".to_owned(),
            DIRECTORY_MODE.to_owned(),
            "--".to_owned(),
            base.as_str().to_owned(),
            extracted.as_str().to_owned(),
        ],
    )
    .map_err(|_| internal())?;
    ExecutionCommand::new(
        operation_id,
        argv,
        workspace.clone(),
        ExecutionEnvironment::empty(),
        timeout,
        output_limit,
    )
    .map_err(|_| internal())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn prepare_windows_directory_command(
    operation_id: OperationId,
    pwsh: TargetPath,
    workspace: &TargetPath,
    base: &TargetPath,
    extracted: &TargetPath,
    timeout: Duration,
    output_limit: usize,
) -> Result<ExecutionCommand, ExecutorAdapterError> {
    if [workspace, base, extracted]
        .into_iter()
        .any(|path| path.platform() != TargetPlatform::Windows)
    {
        return Err(internal());
    }
    let quote = |path: &TargetPath| path.as_str().replace('\'', "''");
    let script = format!(
        "$ErrorActionPreference='Stop';$base='{}';$tree='{}';if(Test-Path -LiteralPath $base){{throw 'action directory already exists'}};[System.IO.Directory]::CreateDirectory($tree)|Out-Null",
        quote(base),
        quote(extracted),
    );
    let argv = ExecutionArgv::new(
        pwsh,
        vec![
            "-NoLogo".to_owned(),
            "-NoProfile".to_owned(),
            "-NonInteractive".to_owned(),
            "-Command".to_owned(),
            script,
        ],
    )
    .map_err(|_| internal())?;
    ExecutionCommand::new(
        operation_id,
        argv,
        workspace.clone(),
        ExecutionEnvironment::empty(),
        timeout,
        output_limit,
    )
    .map_err(|_| internal())
}

pub(super) fn copy_archive_request(
    operation_id: OperationId,
    archive_path: &TargetPath,
    archive: &[u8],
) -> Result<CopyToRequest, ExecutorAdapterError> {
    CopyToRequest::new(operation_id, archive_path.clone(), archive.to_vec())
        .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::ResourceExhausted))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn extract_archive_command(
    operation_id: OperationId,
    tar: TargetPath,
    workspace: &TargetPath,
    extracted: &TargetPath,
    archive_path: &TargetPath,
    timeout: Duration,
    output_limit: usize,
) -> Result<ExecutionCommand, ExecutorAdapterError> {
    let argv = ExecutionArgv::new(
        tar,
        vec![
            "-xzf".to_owned(),
            archive_path.as_str().to_owned(),
            "--directory".to_owned(),
            extracted.as_str().to_owned(),
            "--strip-components=1".to_owned(),
            "--no-same-owner".to_owned(),
            "--no-same-permissions".to_owned(),
        ],
    )
    .map_err(|_| internal())?;
    ExecutionCommand::new(
        operation_id,
        argv,
        workspace.clone(),
        ExecutionEnvironment::empty(),
        timeout,
        output_limit,
    )
    .map_err(|_| internal())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn verify_archive_command(
    operation_id: OperationId,
    sha256: &ExecutionArgv,
    workspace: &TargetPath,
    archive_path: &TargetPath,
    timeout: Duration,
    output_limit: usize,
) -> Result<ExecutionCommand, ExecutorAdapterError> {
    if sha256.program().platform() != workspace.platform()
        || archive_path.platform() != workspace.platform()
    {
        return Err(internal());
    }
    let mut arguments = sha256.arguments().to_vec();
    arguments.push(archive_path.as_str().to_owned());
    let argv = ExecutionArgv::new(sha256.program().clone(), arguments).map_err(|_| internal())?;
    ExecutionCommand::new(
        operation_id,
        argv,
        workspace.clone(),
        ExecutionEnvironment::empty(),
        timeout,
        output_limit,
    )
    .map_err(|_| internal())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn verify_windows_tree_command(
    operation_id: OperationId,
    pwsh: TargetPath,
    workspace: &TargetPath,
    extracted: &TargetPath,
    timeout: Duration,
    output_limit: usize,
) -> Result<ExecutionCommand, ExecutorAdapterError> {
    if workspace.platform() != TargetPlatform::Windows
        || extracted.platform() != TargetPlatform::Windows
    {
        return Err(internal());
    }
    let tree = extracted.as_str().replace('\'', "''");
    let script = format!(
        "$ErrorActionPreference='Stop';$tree='{tree}';$root=[System.IO.Path]::GetFullPath($tree).TrimEnd('\\')+'\\';foreach($entry in Get-ChildItem -LiteralPath $tree -Force -Recurse){{$full=[System.IO.Path]::GetFullPath($entry.FullName);if(-not $full.StartsWith($root,[System.StringComparison]::OrdinalIgnoreCase)){{throw 'action path escaped'}};if(($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint)-ne 0){{throw 'action reparse point'}}}}",
    );
    let argv = ExecutionArgv::new(
        pwsh,
        vec![
            "-NoLogo".to_owned(),
            "-NoProfile".to_owned(),
            "-NonInteractive".to_owned(),
            "-Command".to_owned(),
            script,
        ],
    )
    .map_err(|_| internal())?;
    ExecutionCommand::new(
        operation_id,
        argv,
        workspace.clone(),
        ExecutionEnvironment::empty(),
        timeout,
        output_limit,
    )
    .map_err(|_| internal())
}

const fn internal() -> ExecutorAdapterError {
    ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal)
}
