//! Production-path `PostgreSQL` integration tests.

#[cfg(feature = "test-support")]
mod support;

#[cfg(feature = "test-support")]
#[path = "auth/delegated_actor.rs"]
mod delegated_actor;
#[cfg(feature = "test-support")]
#[path = "store/execution/runner_control.rs"]
mod runner_control;
#[cfg(feature = "test-support")]
#[path = "auth/sign_in.rs"]
mod sign_in;
#[cfg(feature = "test-support")]
#[path = "store/orchestration/web_reads.rs"]
mod web_reads;
