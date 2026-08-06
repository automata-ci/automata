#![forbid(unsafe_code)]
//! Durable control-plane storage ports and their `PostgreSQL` adapter.

mod attempt;
mod error;
mod migration;
mod postgres;
mod snapshot;
mod tenant;

pub use attempt::{
    AcquireLease, ConcludeQueuedAttempt, InternalAttemptRepository, QueuedAttempt, RenewLease,
    TenantAttemptQuery, TransitionAttempt,
};
pub use error::{
    AttemptCommandError, AttemptSnapshotError, AttemptStoreError, RepositoryOperationError,
};
pub use postgres::{PostgresStore, PostgresStoreError};
pub use snapshot::{AttemptSnapshot, AttemptSnapshotBuilder};
pub use tenant::{TenantScope, TenantScopeError};
