use std::fmt;

use async_trait::async_trait;
use automata_auth::{machine::ExternalRunnerIdentity, time::UnixTimestamp};
use automata_core::{RunnerId, Sha256Digest};
use automata_runner_auth::{
    RunnerMachineDirectory, RunnerMachineDirectoryError, RunnerMachineRecord,
};
use automata_runner_control::DesiredRunnerState;
use automata_store::RunnerGeneration;
use sqlx::{PgPool, Row as _};
use uuid::Uuid;

/// Fresh PostgreSQL-backed runner-machine authority lookup.
#[derive(Clone)]
pub struct PostgresRunnerMachineDirectory {
    pool: PgPool,
}

impl PostgresRunnerMachineDirectory {
    /// Creates an adapter over a shared `PostgreSQL` pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl fmt::Debug for PostgresRunnerMachineDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresRunnerMachineDirectory")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl RunnerMachineDirectory for PostgresRunnerMachineDirectory {
    async fn find_by_leaf_sha256(
        &self,
        leaf_sha256: Sha256Digest,
    ) -> Result<Option<RunnerMachineRecord>, RunnerMachineDirectoryError> {
        let row = sqlx::query(
            r"
            SELECT CASE
                       WHEN octet_length(runner.external_identity) BETWEEN 1 AND 255
                       THEN runner.external_identity
                   END AS external_identity,
                   runner.id AS runner_id,
                   runner.generation,
                   certificate.leaf_sha256,
                   certificate.expires_at_seconds,
                   CASE
                       WHEN octet_length(runner.desired_state) <= 8
                       THEN runner.desired_state
                   END AS desired_state
            FROM runner_machine_certificates AS certificate
            JOIN runners AS runner ON runner.id = certificate.runner_id
            WHERE certificate.leaf_sha256 = $1
              AND certificate.revoked_at_seconds IS NULL
            ",
        )
        .bind(leaf_sha256.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| RunnerMachineDirectoryError::Unavailable)?;

        row.as_ref().map(decode_record).transpose()
    }
}

fn decode_record(
    row: &sqlx::postgres::PgRow,
) -> Result<RunnerMachineRecord, RunnerMachineDirectoryError> {
    let external_identity = row
        .try_get::<Option<String>, _>("external_identity")
        .map_err(|_| RunnerMachineDirectoryError::Corrupt)?
        .ok_or(RunnerMachineDirectoryError::Corrupt)
        .and_then(|value| {
            ExternalRunnerIdentity::new(value).map_err(|_| RunnerMachineDirectoryError::Corrupt)
        })?;
    let runner_id = RunnerId::from_uuid(
        row.try_get::<Uuid, _>("runner_id")
            .map_err(|_| RunnerMachineDirectoryError::Corrupt)?,
    );
    let generation = positive_u64(
        row.try_get::<i64, _>("generation")
            .map_err(|_| RunnerMachineDirectoryError::Corrupt)?,
    )
    .and_then(|value| {
        RunnerGeneration::new(value).map_err(|_| RunnerMachineDirectoryError::Corrupt)
    })?;
    let certificate_sha256 = exact_sha256(
        row.try_get::<Vec<u8>, _>("leaf_sha256")
            .map_err(|_| RunnerMachineDirectoryError::Corrupt)?,
    )?;
    let certificate_expires_at = UnixTimestamp::from_seconds(positive_u64(
        row.try_get::<i64, _>("expires_at_seconds")
            .map_err(|_| RunnerMachineDirectoryError::Corrupt)?,
    )?);
    let desired_state = parse_desired_state(
        &row.try_get::<Option<String>, _>("desired_state")
            .map_err(|_| RunnerMachineDirectoryError::Corrupt)?
            .ok_or(RunnerMachineDirectoryError::Corrupt)?,
    )?;

    RunnerMachineRecord::new(
        external_identity,
        runner_id,
        generation,
        certificate_sha256,
        certificate_expires_at,
        desired_state,
    )
    .map_err(|_| RunnerMachineDirectoryError::Corrupt)
}

fn positive_u64(value: i64) -> Result<u64, RunnerMachineDirectoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(RunnerMachineDirectoryError::Corrupt)
}

fn exact_sha256(value: Vec<u8>) -> Result<Sha256Digest, RunnerMachineDirectoryError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| RunnerMachineDirectoryError::Corrupt)?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn parse_desired_state(value: &str) -> Result<DesiredRunnerState, RunnerMachineDirectoryError> {
    match value {
        "active" => Ok(DesiredRunnerState::Active),
        "draining" => Ok(DesiredRunnerState::Draining),
        "disabled" => Ok(DesiredRunnerState::Disabled),
        _ => Err(RunnerMachineDirectoryError::Corrupt),
    }
}
