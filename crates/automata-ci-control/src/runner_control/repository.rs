use async_trait::async_trait;
use automata_ci_core::UnixMillis;
use automata_ci_store::{
    AcknowledgeRunnerCommands, CloseRunnerSession, CommandCursor, CommandReplayLimit,
    CommandReplayPage, DurableRunnerCommand, EnqueueRunnerCommand, HeartbeatRunnerSession,
    OpenRunnerSession, ResumeRunnerSession, RunnerOperationReceipt, RunnerOperationRequest,
    RunnerOperationResponse, RunnerSessionFence, RunnerSessionSnapshot, StoreError,
};

/// Durable server-command delivery and cumulative acknowledgement port.
#[async_trait]
pub trait RunnerCommandOutbox: Send + Sync {
    /// Enqueues a command for one exact live runner session.
    async fn enqueue_command(
        &self,
        command: EnqueueRunnerCommand,
    ) -> Result<DurableRunnerCommand, StoreError>;

    /// Replays bounded commands after a durable acknowledgement cursor.
    async fn replay_commands(
        &self,
        session: RunnerSessionFence,
        after: CommandCursor,
        limit: CommandReplayLimit,
    ) -> Result<CommandReplayPage, StoreError>;

    /// Advances the cumulative cursor. Duplicate/older cursors are idempotent;
    /// a cursor beyond the largest allocated sequence is rejected.
    async fn acknowledge_commands(
        &self,
        acknowledgement: AcknowledgeRunnerCommands,
    ) -> Result<CommandCursor, StoreError>;
}

/// Durable session lifecycle port used after runner machine authentication.
#[async_trait]
pub trait RunnerSessionRepository: Send + Sync {
    /// Atomically replaces any prior live connection and allocates a new epoch.
    async fn open_session(
        &self,
        request: OpenRunnerSession,
    ) -> Result<RunnerSessionSnapshot, StoreError>;

    /// Ends the exact authenticated epoch; stale epochs cannot close a newer one.
    async fn close_session(&self, request: CloseRunnerSession) -> Result<(), StoreError>;

    /// Updates the exact live fence without allocating a new session epoch.
    ///
    /// Implementations keep the durable heartbeat monotonic when concurrent
    /// trusted observations acquire the fence in reverse sampling order.
    async fn heartbeat_session(
        &self,
        request: HeartbeatRunnerSession,
    ) -> Result<RunnerSessionSnapshot, StoreError>;

    /// Resumes an already-live durable epoch by authenticated runner identity.
    async fn resume_session(
        &self,
        request: ResumeRunnerSession,
    ) -> Result<RunnerSessionSnapshot, StoreError>;

    /// Loads the exact durable session identified by its complete fence.
    async fn get_session(
        &self,
        fence: RunnerSessionFence,
    ) -> Result<RunnerSessionSnapshot, StoreError>;
}

/// Generic exact-response ledger for runner RPC mutations.
///
/// Callers must look up a receipt before executing a side effect and must use
/// the same operation ID at the provider boundary. This generic two-call seam
/// cannot by itself make an unrelated external side effect atomic with durable
/// repository state. Specialized repositories use a single transaction where
/// that stronger guarantee is required.
#[async_trait]
pub trait RunnerOperationReceiptRepository: Send + Sync {
    /// Looks up the response already committed for the exact runner request.
    async fn lookup_operation(
        &self,
        request: &RunnerOperationRequest,
    ) -> Result<Option<RunnerOperationReceipt>, StoreError>;

    /// Persists the first exact response. A same-request retry returns the
    /// original response; a different digest or kind for the key conflicts.
    async fn record_operation(
        &self,
        request: RunnerOperationRequest,
        response: RunnerOperationResponse,
        committed_at: UnixMillis,
    ) -> Result<RunnerOperationReceipt, StoreError>;
}
