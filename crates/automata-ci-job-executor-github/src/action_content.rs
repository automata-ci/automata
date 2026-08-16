use std::time::Duration;

use automata_ci_core::OperationId;
use automata_ci_execution::{
    CopyToRequest, ExecutionArgv, ExecutionCommand, ExecutionEnvironment, TargetPath,
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

const fn internal() -> ExecutorAdapterError {
    ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal)
}
