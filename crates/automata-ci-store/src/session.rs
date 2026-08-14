use automata_ci_core::{JobIrVersion, RunnerId, RunnerSessionId, UnixMillis};

use crate::{
    CommandCursor, RoutingDocument, RunnerGeneration, RunnerProtocolVersion, SessionEpoch,
};

/// Immutable identity fence for one authenticated runner connection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RunnerSessionFence {
    session_id: RunnerSessionId,
    runner_id: RunnerId,
    runner_generation: RunnerGeneration,
    session_epoch: SessionEpoch,
}

impl RunnerSessionFence {
    #[must_use]
    pub const fn new(
        session_id: RunnerSessionId,
        runner_id: RunnerId,
        runner_generation: RunnerGeneration,
        session_epoch: SessionEpoch,
    ) -> Self {
        Self {
            session_id,
            runner_id,
            runner_generation,
            session_epoch,
        }
    }

    #[must_use]
    pub const fn session_id(self) -> RunnerSessionId {
        self.session_id
    }

    #[must_use]
    pub const fn runner_id(self) -> RunnerId {
        self.runner_id
    }

    #[must_use]
    pub const fn runner_generation(self) -> RunnerGeneration {
        self.runner_generation
    }

    #[must_use]
    pub const fn session_epoch(self) -> SessionEpoch {
        self.session_epoch
    }
}

/// Request from an authenticated runner boundary to establish a new epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenRunnerSession {
    session_id: RunnerSessionId,
    runner_id: RunnerId,
    expected_generation: RunnerGeneration,
    protocol_version: RunnerProtocolVersion,
    job_ir_version: JobIrVersion,
    capability_snapshot: RoutingDocument,
    observed_at: UnixMillis,
}

impl OpenRunnerSession {
    #[must_use]
    pub const fn new(
        session_id: RunnerSessionId,
        runner_id: RunnerId,
        expected_generation: RunnerGeneration,
        protocol_version: RunnerProtocolVersion,
        job_ir_version: JobIrVersion,
        capability_snapshot: RoutingDocument,
        observed_at: UnixMillis,
    ) -> Self {
        Self {
            session_id,
            runner_id,
            expected_generation,
            protocol_version,
            job_ir_version,
            capability_snapshot,
            observed_at,
        }
    }

    #[must_use]
    pub const fn session_id(&self) -> RunnerSessionId {
        self.session_id
    }

    #[must_use]
    pub const fn runner_id(&self) -> RunnerId {
        self.runner_id
    }

    #[must_use]
    pub const fn expected_generation(&self) -> RunnerGeneration {
        self.expected_generation
    }

    #[must_use]
    pub const fn protocol_version(&self) -> RunnerProtocolVersion {
        self.protocol_version
    }

    #[must_use]
    pub const fn job_ir_version(&self) -> JobIrVersion {
        self.job_ir_version
    }

    #[must_use]
    pub const fn capability_snapshot(&self) -> &RoutingDocument {
        &self.capability_snapshot
    }

    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
}

/// Trusted control-plane request to end exactly one fenced session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloseRunnerSession {
    fence: RunnerSessionFence,
    observed_at: UnixMillis,
}

/// Exact-fence heartbeat and cumulative command acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeartbeatRunnerSession {
    fence: RunnerSessionFence,
    command_cursor: CommandCursor,
    observed_at: UnixMillis,
}

impl HeartbeatRunnerSession {
    #[must_use]
    pub const fn new(
        fence: RunnerSessionFence,
        command_cursor: CommandCursor,
        observed_at: UnixMillis,
    ) -> Self {
        Self {
            fence,
            command_cursor,
            observed_at,
        }
    }

    #[must_use]
    pub const fn fence(self) -> RunnerSessionFence {
        self.fence
    }

    #[must_use]
    pub const fn command_cursor(self) -> CommandCursor {
        self.command_cursor
    }

    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }
}

/// Authenticated request to resume an existing live epoch without replacing it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResumeRunnerSession {
    runner_id: RunnerId,
    expected_generation: RunnerGeneration,
    session_id: RunnerSessionId,
    command_cursor: CommandCursor,
    observed_at: UnixMillis,
}

impl ResumeRunnerSession {
    #[must_use]
    pub const fn new(
        runner_id: RunnerId,
        expected_generation: RunnerGeneration,
        session_id: RunnerSessionId,
        command_cursor: CommandCursor,
        observed_at: UnixMillis,
    ) -> Self {
        Self {
            runner_id,
            expected_generation,
            session_id,
            command_cursor,
            observed_at,
        }
    }

    #[must_use]
    pub const fn runner_id(self) -> RunnerId {
        self.runner_id
    }

    #[must_use]
    pub const fn expected_generation(self) -> RunnerGeneration {
        self.expected_generation
    }

    #[must_use]
    pub const fn session_id(self) -> RunnerSessionId {
        self.session_id
    }

    #[must_use]
    pub const fn command_cursor(self) -> CommandCursor {
        self.command_cursor
    }

    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }
}

impl CloseRunnerSession {
    #[must_use]
    pub const fn new(fence: RunnerSessionFence, observed_at: UnixMillis) -> Self {
        Self { fence, observed_at }
    }

    #[must_use]
    pub const fn fence(self) -> RunnerSessionFence {
        self.fence
    }

    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }
}

/// Durable snapshot of a runner session and its negotiated schemas.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerSessionSnapshot {
    fence: RunnerSessionFence,
    protocol_version: RunnerProtocolVersion,
    job_ir_version: JobIrVersion,
    capability_snapshot: RoutingDocument,
    connected_at: UnixMillis,
    heartbeat_at: UnixMillis,
    disconnected_at: Option<UnixMillis>,
    command_cursor: CommandCursor,
}

impl RunnerSessionSnapshot {
    /// Builds a snapshot decoded by a storage adapter.
    ///
    /// # Errors
    ///
    /// Rejects timestamp regressions.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        fence: RunnerSessionFence,
        protocol_version: RunnerProtocolVersion,
        job_ir_version: JobIrVersion,
        capability_snapshot: RoutingDocument,
        connected_at: UnixMillis,
        heartbeat_at: UnixMillis,
        disconnected_at: Option<UnixMillis>,
        command_cursor: CommandCursor,
    ) -> Result<Self, RunnerSessionSnapshotError> {
        if heartbeat_at < connected_at {
            return Err(RunnerSessionSnapshotError::HeartbeatBeforeConnection);
        }
        if disconnected_at.is_some_and(|value| value < heartbeat_at) {
            return Err(RunnerSessionSnapshotError::DisconnectBeforeHeartbeat);
        }
        Ok(Self {
            fence,
            protocol_version,
            job_ir_version,
            capability_snapshot,
            connected_at,
            heartbeat_at,
            disconnected_at,
            command_cursor,
        })
    }

    #[must_use]
    pub const fn fence(&self) -> RunnerSessionFence {
        self.fence
    }

    #[must_use]
    pub const fn protocol_version(&self) -> RunnerProtocolVersion {
        self.protocol_version
    }

    #[must_use]
    pub const fn job_ir_version(&self) -> JobIrVersion {
        self.job_ir_version
    }

    #[must_use]
    pub const fn capability_snapshot(&self) -> &RoutingDocument {
        &self.capability_snapshot
    }

    #[must_use]
    pub const fn connected_at(&self) -> UnixMillis {
        self.connected_at
    }

    #[must_use]
    pub const fn heartbeat_at(&self) -> UnixMillis {
        self.heartbeat_at
    }

    #[must_use]
    pub const fn disconnected_at(&self) -> Option<UnixMillis> {
        self.disconnected_at
    }

    #[must_use]
    pub const fn command_cursor(&self) -> CommandCursor {
        self.command_cursor
    }

    #[must_use]
    pub const fn is_live(&self) -> bool {
        self.disconnected_at.is_none()
    }
}

/// Invalid durable runner-session timestamps.
#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
pub enum RunnerSessionSnapshotError {
    #[error("runner session heartbeat precedes connection")]
    HeartbeatBeforeConnection,
    #[error("runner session disconnect precedes its last heartbeat")]
    DisconnectBeforeHeartbeat,
}
