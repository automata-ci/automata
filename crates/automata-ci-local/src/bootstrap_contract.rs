//! Canonical file contract between local lifecycle bootstrap and the product CLI.

use std::fmt;

use automata_ci_core::{RunnerGroup, Sha256Digest};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Current schema of the one-shot local runner bootstrap request.
pub const LOCAL_BOOTSTRAP_RUNNER_REQUEST_SCHEMA: &str =
    "automata.local/bootstrap-runner-request/v1";

/// Canonical outer request shared by the lifecycle producer and bootstrap consumer.
///
/// The tenant representation is generic because the producer owns a fixed
/// serializable tenant projection while the consumer decodes directly into its
/// validated installation-authority type.
#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalBootstrapRunnerRequest<Tenant> {
    /// Exact request schema.
    pub schema: String,
    /// Idempotency identity for the bootstrap transaction.
    pub bootstrap_operation_id: Uuid,
    /// Tenant authority to create or replay.
    pub tenant: Tenant,
    /// Digest binding the request to the installation authority source.
    pub installation_authority_source_sha256: Sha256Digest,
    /// Durable runner identity.
    pub runner_id: Uuid,
    /// Initial enrollment identity.
    pub enrollment_id: Uuid,
    /// Sole runner group admitted by the local topology.
    pub runner_group: RunnerGroup,
    /// Requested initial token lifetime in seconds.
    pub token_lifetime_seconds: u64,
}

impl<Tenant: fmt::Debug> fmt::Debug for LocalBootstrapRunnerRequest<Tenant> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalBootstrapRunnerRequest")
            .field("schema", &self.schema)
            .field("bootstrap_operation_id", &self.bootstrap_operation_id)
            .field("tenant", &self.tenant)
            .field("installation_authority_source_sha256", &"[redacted]")
            .field("runner_id", &self.runner_id)
            .field("enrollment_id", &self.enrollment_id)
            .field("runner_group", &self.runner_group)
            .field("token_lifetime_seconds", &self.token_lifetime_seconds)
            .finish()
    }
}
