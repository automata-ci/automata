//! Canonical scheduler-owned GitHub event evidence.

use automata_ci_core::UnixMillis;
use automata_ci_schedule::CronExpression;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Immutable media type of scheduler-owned GitHub schedule evidence.
pub const AUTOMATA_GITHUB_SCHEDULE_EVIDENCE_V1_MEDIA_TYPE: &str =
    "application/vnd.automata.github-schedule-evidence.v1+json";

const SCHEMA: u16 = 1;
const KIND: &str = "automata_github_schedule";

/// Canonical evidence for one trusted scheduled invocation.
///
/// This is not a webhook payload and never carries a provider delivery ID.
/// The durable schedule-fire claim supplies the authoritative repository,
/// source, and Check binding at admission time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubScheduleEvidence {
    cron: String,
    scheduled_at: UnixMillis,
}

impl GithubScheduleEvidence {
    /// Creates evidence for one validated cron occurrence.
    ///
    /// # Errors
    ///
    /// Rejects an unsupported cron expression or a pre-epoch occurrence.
    pub fn new(
        cron: impl Into<String>,
        scheduled_at: UnixMillis,
    ) -> Result<Self, GithubScheduleEvidenceError> {
        let cron = cron.into();
        if CronExpression::parse(&cron).is_err() || scheduled_at.get() < 0 {
            return Err(GithubScheduleEvidenceError);
        }
        Ok(Self { cron, scheduled_at })
    }

    /// Decodes exact canonical schedule evidence.
    ///
    /// # Errors
    ///
    /// Rejects malformed, future-schema, or semantically invalid bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, GithubScheduleEvidenceError> {
        let raw: RawEvidence =
            serde_json::from_slice(bytes).map_err(|_| GithubScheduleEvidenceError)?;
        if raw.schema != SCHEMA || raw.kind != KIND {
            return Err(GithubScheduleEvidenceError);
        }
        Self::new(raw.cron, UnixMillis::new(raw.scheduled_at_ms))
    }

    /// Returns canonical JSON bytes for immutable event retention.
    ///
    /// # Errors
    ///
    /// Returns an error only if the bounded evidence could not be serialized.
    pub fn encode(&self) -> Result<Vec<u8>, GithubScheduleEvidenceError> {
        serde_json::to_vec(&RawEvidence {
            schema: SCHEMA,
            kind: KIND.to_owned(),
            cron: self.cron.clone(),
            scheduled_at_ms: self.scheduled_at.get(),
        })
        .map_err(|_| GithubScheduleEvidenceError)
    }

    /// Returns the exact configured cron spelling exposed as `github.event.schedule`.
    #[must_use]
    pub fn cron(&self) -> &str {
        &self.cron
    }

    /// Returns the exact due instant represented by this invocation.
    #[must_use]
    pub const fn scheduled_at(&self) -> UnixMillis {
        self.scheduled_at
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawEvidence {
    schema: u16,
    kind: String,
    cron: String,
    scheduled_at_ms: i64,
}

/// Invalid scheduler-owned GitHub event evidence.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub schedule evidence is invalid")]
pub struct GithubScheduleEvidenceError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_evidence_is_canonical_and_never_uses_a_delivery_identity() {
        let evidence = GithubScheduleEvidence::new("0/5 * * * *", UnixMillis::new(42_000))
            .expect("valid schedule evidence");
        let bytes = evidence.encode().expect("canonical JSON");
        assert_eq!(
            bytes,
            br#"{"schema":1,"kind":"automata_github_schedule","cron":"0/5 * * * *","scheduled_at_ms":42000}"#
        );
        assert_eq!(GithubScheduleEvidence::decode(&bytes), Ok(evidence));
        assert!(
            !std::str::from_utf8(&bytes)
                .expect("JSON")
                .contains("delivery")
        );
    }

    #[test]
    fn schedule_evidence_rejects_invalid_cron_and_unknown_fields() {
        assert!(GithubScheduleEvidence::new("* * * * *", UnixMillis::new(1)).is_err());
        assert!(GithubScheduleEvidence::decode(
            br#"{"schema":1,"kind":"automata_github_schedule","cron":"0/5 * * * *","scheduled_at_ms":1,"delivery_id":"no"}"#
        )
        .is_err());
    }
}
