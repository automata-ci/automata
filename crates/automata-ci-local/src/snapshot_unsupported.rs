use std::path::PathBuf;

use automata_ci_core::Sha256Digest;
use automata_ci_workflow_github::RepositoryWorkflowDiscoveryLimits;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug)]
pub(crate) struct LocalSnapshotRequest;

impl LocalSnapshotRequest {
    #[must_use]
    pub(crate) fn new(
        directory: impl Into<PathBuf>,
        limits: RepositoryWorkflowDiscoveryLimits,
    ) -> Self {
        let _ = (directory.into(), limits);
        Self
    }
}

pub(crate) enum LocalSnapshot {}

impl LocalSnapshot {
    pub(crate) fn head(&self) -> &str {
        match *self {}
    }

    pub(crate) const fn dirty(&self) -> bool {
        match *self {}
    }

    pub(crate) const fn digest(&self) -> Sha256Digest {
        match *self {}
    }

    pub(crate) fn into_archive(self) -> Vec<u8> {
        match self {}
    }

    pub(crate) const fn entry_count(&self) -> usize {
        match *self {}
    }

    pub(crate) const fn expanded_bytes(&self) -> u64 {
        match *self {}
    }
}

pub(crate) async fn capture_snapshot(
    request: LocalSnapshotRequest,
    cancellation: &CancellationToken,
) -> Result<LocalSnapshot, LocalSnapshotError> {
    let _ = (request, cancellation);
    Err(LocalSnapshotError {
        code: LocalSnapshotErrorCode::UnsupportedPlatform,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LocalSnapshotErrorCode {
    UnsupportedPlatform,
    Cancelled,
}

impl LocalSnapshotErrorCode {
    #[must_use]
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => {
                "exact local snapshot mutation evidence is not qualified on this platform"
            }
            Self::Cancelled => "local snapshot construction was cancelled",
        }
    }
}

impl std::fmt::Display for LocalSnapshotErrorCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message())
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("{code}")]
pub(crate) struct LocalSnapshotError {
    code: LocalSnapshotErrorCode,
}

impl LocalSnapshotError {
    #[must_use]
    pub(crate) const fn code(self) -> LocalSnapshotErrorCode {
        self.code
    }
}
