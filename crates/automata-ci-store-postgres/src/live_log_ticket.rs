use async_trait::async_trait;
use automata_ci_core::{AttemptId, JobId, LogStreamId, RunId, UnixMillis};
use automata_ci_store::{
    HumanLiveLogScope, HumanLiveLogTicketRepository, IssueHumanLiveLogTicket,
    IssueHumanLiveLogTicketOutcome, IssuedHumanLiveLogTicket, RedeemHumanLiveLogTicket,
    RedeemedHumanLiveLogTicket, RepositoryId, StoreError, TenantScope,
};
use sqlx::{PgPool, Row as _};

const EXPIRED_TICKET_DELETE_BATCH: i64 = 64;

/// PostgreSQL-backed, cross-replica one-time live-log ticket repository.
#[derive(Clone, Debug)]
pub struct PostgresLiveLogTicketRepository {
    pool: PgPool,
}

impl PostgresLiveLogTicketRepository {
    /// Creates a repository over the shard's shared `PostgreSQL` pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl HumanLiveLogTicketRepository for PostgresLiveLogTicketRepository {
    async fn issue(
        &self,
        request: &IssueHumanLiveLogTicket,
    ) -> Result<IssueHumanLiveLogTicketOutcome, StoreError> {
        let lifetime_ms = i64::try_from(request.lifetime().as_millis())
            .map_err(|_| StoreError::corrupt_data("live-log ticket lifetime exceeds bigint"))?;
        let row =
            sqlx::query(
                r"
            WITH database_clock AS (
                SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms
            ), expired AS (
                SELECT ticket.token_sha256
                FROM human_live_log_tickets AS ticket, database_clock
                WHERE ticket.expires_at_ms <= database_clock.now_ms
                ORDER BY ticket.expires_at_ms, ticket.token_sha256
                LIMIT $11
                FOR UPDATE SKIP LOCKED
            ), deleted AS (
                DELETE FROM human_live_log_tickets AS ticket
                USING expired
                WHERE ticket.token_sha256 = expired.token_sha256
            )
            INSERT INTO human_live_log_tickets (
                token_sha256, tenant_id, repository_id, run_id, job_id,
                attempt_id, stream_id, browser_origin, protocol_version,
                issued_at_ms, expires_at_ms
            )
            SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9,
                   database_clock.now_ms, database_clock.now_ms + $10
            FROM database_clock
            ON CONFLICT (token_sha256) DO NOTHING
            RETURNING issued_at_ms, expires_at_ms
            ",
            )
            .bind(request.token_sha256().as_slice())
            .bind(request.scope().tenant().as_str())
            .bind(request.scope().repository_id().as_uuid())
            .bind(request.scope().run_id().as_uuid())
            .bind(request.scope().job_id().as_uuid())
            .bind(request.scope().attempt_id().as_uuid())
            .bind(request.scope().stream_id().as_uuid())
            .bind(request.browser_origin().as_str())
            .bind(i16::try_from(request.protocol_version()).map_err(|_| {
                StoreError::corrupt_data("live-log ticket protocol exceeds smallint")
            })?)
            .bind(lifetime_ms)
            .bind(EXPIRED_TICKET_DELETE_BATCH)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::operation)?;
        let Some(row) = row else {
            return Ok(IssueHumanLiveLogTicketOutcome::DigestCollision);
        };
        let issued_at =
            UnixMillis::new(row.try_get("issued_at_ms").map_err(StoreError::operation)?);
        let expires_at = UnixMillis::new(
            row.try_get("expires_at_ms")
                .map_err(StoreError::operation)?,
        );
        if expires_at.get() <= issued_at.get() || expires_at.get() - issued_at.get() != lifetime_ms
        {
            return Err(StoreError::corrupt_data(
                "live-log ticket timestamps violate the requested lifetime",
            ));
        }
        Ok(IssueHumanLiveLogTicketOutcome::Issued(
            IssuedHumanLiveLogTicket::new(issued_at, expires_at),
        ))
    }

    async fn redeem(
        &self,
        request: &RedeemHumanLiveLogTicket,
    ) -> Result<Option<RedeemedHumanLiveLogTicket>, StoreError> {
        let row =
            sqlx::query(
                r"
            WITH database_clock AS (
                SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms
            )
            UPDATE human_live_log_tickets AS ticket
            SET consumed_at_ms = database_clock.now_ms
            FROM database_clock
            WHERE ticket.token_sha256 = $1
              AND ticket.browser_origin = $2
              AND ticket.protocol_version = $3
              AND ticket.consumed_at_ms IS NULL
              AND ticket.expires_at_ms > database_clock.now_ms
            RETURNING ticket.tenant_id, ticket.repository_id, ticket.run_id,
                      ticket.job_id, ticket.attempt_id, ticket.stream_id,
                      ticket.consumed_at_ms, ticket.expires_at_ms
            ",
            )
            .bind(request.token_sha256().as_slice())
            .bind(request.browser_origin().as_str())
            .bind(i16::try_from(request.protocol_version()).map_err(|_| {
                StoreError::corrupt_data("live-log ticket protocol exceeds smallint")
            })?)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::operation)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let tenant_id: String = row.try_get("tenant_id").map_err(StoreError::operation)?;
        let tenant = TenantScope::from_authenticated_tenant_id(tenant_id)
            .map_err(|_| StoreError::corrupt_data("live-log ticket tenant is invalid"))?;
        let scope = HumanLiveLogScope::new(
            tenant,
            RepositoryId::from_uuid(
                row.try_get("repository_id")
                    .map_err(StoreError::operation)?,
            ),
            RunId::from_uuid(row.try_get("run_id").map_err(StoreError::operation)?),
            JobId::from_uuid(row.try_get("job_id").map_err(StoreError::operation)?),
            AttemptId::from_uuid(row.try_get("attempt_id").map_err(StoreError::operation)?),
            LogStreamId::from_uuid(row.try_get("stream_id").map_err(StoreError::operation)?),
        )
        .map_err(|_| StoreError::corrupt_data("live-log ticket scope is invalid"))?;
        let consumed_at = UnixMillis::new(
            row.try_get("consumed_at_ms")
                .map_err(StoreError::operation)?,
        );
        let expires_at = UnixMillis::new(
            row.try_get("expires_at_ms")
                .map_err(StoreError::operation)?,
        );
        if consumed_at.get() >= expires_at.get() {
            return Err(StoreError::corrupt_data(
                "consumed live-log ticket is not inside its lifetime",
            ));
        }
        Ok(Some(RedeemedHumanLiveLogTicket::new(
            scope,
            consumed_at,
            expires_at,
        )))
    }
}
