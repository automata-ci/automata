use async_trait::async_trait;
use automata_ci_core::{LogSequence, LogStreamId};
use automata_ci_store::{HumanLogCommitHint, HumanLogCommitNotificationSource, StoreError};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Transaction, postgres::PgListener};
use uuid::Uuid;

pub(crate) const LOG_COMMIT_NOTIFICATION_CHANNEL: &str = "automata_log_commit_v1";
const LOG_COMMIT_NOTIFICATION_VERSION: u8 = 1;
const MAX_LOG_COMMIT_NOTIFICATION_BYTES: usize = 256;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LogCommitNotificationV1 {
    version: u8,
    stream_id: Uuid,
    committed_through: u64,
    stream_closed: bool,
}

/// One replica-level `PostgreSQL` listener for durable log-commit wake hints.
///
/// The listener consumes one connection from `pool` while active. `SQLx`
/// transparently reconnects and restores the fixed `LISTEN` subscription;
/// notifications lost during that interval are recovered by periodic durable
/// reads above this adapter.
#[derive(Debug)]
pub struct PostgresLogCommitListener {
    inner: PgListener,
}

impl PostgresLogCommitListener {
    /// Connects and subscribes to the fixed versioned log-commit channel.
    ///
    /// # Errors
    ///
    /// Returns a sanitized store operation error if `PostgreSQL` cannot allocate
    /// the listener connection or establish the subscription.
    pub async fn connect(pool: &PgPool) -> Result<Self, StoreError> {
        let mut inner = PgListener::connect_with(pool)
            .await
            .map_err(StoreError::operation)?;
        inner
            .listen(LOG_COMMIT_NOTIFICATION_CHANNEL)
            .await
            .map_err(StoreError::operation)?;
        Ok(Self { inner })
    }
}

#[async_trait]
impl HumanLogCommitNotificationSource for PostgresLogCommitListener {
    async fn receive(&mut self) -> Result<HumanLogCommitHint, StoreError> {
        let notification = self.inner.recv().await.map_err(StoreError::operation)?;
        if notification.channel() != LOG_COMMIT_NOTIFICATION_CHANNEL {
            return Err(StoreError::corrupt_data(
                "log commit notification arrived on the wrong channel",
            ));
        }
        decode_notification(notification.payload())
    }
}

pub(crate) async fn publish_log_commit_notification(
    transaction: &mut Transaction<'_, Postgres>,
    hint: HumanLogCommitHint,
) -> Result<(), StoreError> {
    let payload = encode_notification(hint)?;
    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(LOG_COMMIT_NOTIFICATION_CHANNEL)
        .bind(payload)
        .execute(&mut **transaction)
        .await
        .map_err(StoreError::operation)?;
    Ok(())
}

fn encode_notification(hint: HumanLogCommitHint) -> Result<String, StoreError> {
    let payload = LogCommitNotificationV1 {
        version: LOG_COMMIT_NOTIFICATION_VERSION,
        stream_id: hint.stream_id().as_uuid(),
        committed_through: hint.committed_through().get(),
        stream_closed: hint.stream_closed(),
    };
    let encoded = serde_json::to_string(&payload).map_err(StoreError::operation)?;
    if encoded.len() > MAX_LOG_COMMIT_NOTIFICATION_BYTES {
        return Err(StoreError::corrupt_data(
            "log commit notification exceeded its encoded bound",
        ));
    }
    Ok(encoded)
}

fn decode_notification(payload: &str) -> Result<HumanLogCommitHint, StoreError> {
    if payload.is_empty() || payload.len() > MAX_LOG_COMMIT_NOTIFICATION_BYTES {
        return Err(StoreError::corrupt_data(
            "log commit notification size is invalid",
        ));
    }
    let decoded: LogCommitNotificationV1 = serde_json::from_str(payload)
        .map_err(|_| StoreError::corrupt_data("log commit notification is malformed"))?;
    if decoded.version != LOG_COMMIT_NOTIFICATION_VERSION
        || decoded.stream_id.is_nil()
        || i64::try_from(decoded.committed_through).is_err()
    {
        return Err(StoreError::corrupt_data(
            "log commit notification values are invalid",
        ));
    }
    Ok(HumanLogCommitHint::new(
        LogStreamId::from_uuid(decoded.stream_id),
        LogSequence::new(decoded.committed_through),
        decoded.stream_closed,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_round_trips_exactly_and_rejects_noncurrent_or_unbounded_input() {
        let hint = HumanLogCommitHint::new(
            LogStreamId::from_uuid(Uuid::from_u128(1)),
            LogSequence::new(i64::MAX as u64),
            true,
        );
        let encoded = encode_notification(hint).expect("bounded notification");
        assert_eq!(
            decode_notification(&encoded).expect("current payload"),
            hint
        );

        for invalid in [
            r#"{"version":2,"stream_id":"00000000-0000-0000-0000-000000000001","committed_through":0,"stream_closed":false}"#.to_owned(),
            r#"{"version":1,"stream_id":"00000000-0000-0000-0000-000000000000","committed_through":0,"stream_closed":false}"#.to_owned(),
            r#"{"version":1,"stream_id":"00000000-0000-0000-0000-000000000001","committed_through":9223372036854775808,"stream_closed":false}"#.to_owned(),
            "x".repeat(MAX_LOG_COMMIT_NOTIFICATION_BYTES + 1),
        ] {
            assert!(decode_notification(&invalid).is_err());
        }
    }
}
