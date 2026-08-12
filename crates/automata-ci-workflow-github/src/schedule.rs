//! GitHub schedule extraction over the shared cron and timezone contract.

use automata_ci_core::UnixMillis;
use automata_ci_schedule::{
    CronExpression, MAX_CRON_EXPRESSION_BYTES, MAX_IANA_TIMEZONE_BYTES, ScheduleError,
    validate_iana_timezone,
};
use thiserror::Error;

use crate::{GithubWorkflowSourcePlan, TriggerConfiguration, YamlMappingEntry, YamlNode};

/// Maximum schedule entries accepted from one workflow.
pub const MAX_GITHUB_SCHEDULE_ENTRIES: usize = 64;
/// Maximum decoded bytes in one exact five-field cron expression.
pub const MAX_GITHUB_SCHEDULE_EXPRESSION_BYTES: usize = MAX_CRON_EXPRESSION_BYTES;
/// Maximum bytes in one IANA timezone identifier.
pub const MAX_GITHUB_SCHEDULE_TIMEZONE_BYTES: usize = MAX_IANA_TIMEZONE_BYTES;

/// One validated five-field GitHub schedule expression.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubCronExpression(CronExpression);

impl GithubCronExpression {
    /// Parses the shared POSIX five-field syntax and minimum interval.
    ///
    /// Numeric values, ASCII three-letter month and weekday names, `*`,
    /// lists, inclusive ranges, and positive `/` steps are supported.
    /// Provider-specific `@` aliases and non-POSIX operators are rejected.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, out-of-range, excessive, or
    /// sub-five-minute expressions.
    pub fn parse(exact: impl Into<String>) -> Result<Self, GithubScheduleError> {
        CronExpression::parse(exact)
            .map(Self)
            .map_err(GithubScheduleError::from)
    }

    /// Returns the exact decoded source spelling used in `github.event.schedule`.
    #[must_use]
    pub fn exact(&self) -> &str {
        self.0.exact()
    }

    /// Reports whether one exact UTC instant matches in the supplied timezone.
    ///
    /// # Errors
    ///
    /// Rejects an unavailable timezone database entry or out-of-range instant.
    pub fn matches_at(
        &self,
        instant: UnixMillis,
        timezone: &str,
    ) -> Result<bool, GithubScheduleError> {
        self.0
            .matches_at(instant, timezone)
            .map_err(GithubScheduleError::from)
    }

    /// Finds the first matching minute strictly after one UTC instant.
    ///
    /// Calendar candidates are generated in local time. Nonexistent local
    /// minutes in a daylight-saving gap are skipped; both real instants in a
    /// repeated local minute remain eligible and are ordered by UTC time.
    ///
    /// # Errors
    ///
    /// Rejects an unavailable timezone, out-of-range timestamp, or an
    /// expression with no real calendar match inside the bounded ten-year
    /// search horizon.
    pub fn next_after(
        &self,
        instant: UnixMillis,
        timezone: &str,
    ) -> Result<UnixMillis, GithubScheduleError> {
        self.0
            .next_after(instant, timezone)
            .map_err(GithubScheduleError::from)
    }
}

/// One source-ordered validated scheduled invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubScheduleEntry {
    expression: GithubCronExpression,
    timezone: String,
    ordinal: u16,
}

impl GithubScheduleEntry {
    /// Returns the validated cron expression.
    #[must_use]
    pub const fn expression(&self) -> &GithubCronExpression {
        &self.expression
    }

    /// Returns the exact validated IANA timezone, defaulting to `UTC`.
    #[must_use]
    pub fn timezone(&self) -> &str {
        &self.timezone
    }

    /// Returns this entry's zero-based source order.
    #[must_use]
    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }
}

/// Extracts validated schedule entries from one accepted source plan.
///
/// # Errors
///
/// Rejects invalid shapes, duplicate fields, excessive entries, cron syntax,
/// timezone identifiers, or unsupported schedule fields.
pub fn extract_github_schedule_entries(
    plan: &GithubWorkflowSourcePlan,
) -> Result<Vec<GithubScheduleEntry>, GithubScheduleError> {
    let mut output = Vec::new();
    let Some(triggers) = plan.workflow().triggers() else {
        return Ok(output);
    };
    for trigger in triggers.events() {
        let TriggerConfiguration::Schedule(configuration) = trigger.configuration() else {
            continue;
        };
        let entries = configuration
            .as_sequence()
            .ok_or(GithubScheduleError::InvalidConfiguration)?;
        if entries.is_empty() || entries.len() > MAX_GITHUB_SCHEDULE_ENTRIES {
            return Err(GithubScheduleError::InvalidConfiguration);
        }
        for entry in entries {
            let ordinal = u16::try_from(output.len())
                .map_err(|_| GithubScheduleError::InvalidConfiguration)?;
            output.push(extract_entry(entry, ordinal)?);
        }
    }
    Ok(output)
}

/// Validates one bounded IANA timezone identifier against the runtime database.
///
/// # Errors
///
/// Rejects empty, non-ASCII, control-bearing, padded, excessive, or unavailable
/// names.
pub fn validate_github_schedule_timezone(source: &str) -> Result<(), GithubScheduleError> {
    validate_iana_timezone(source).map_err(GithubScheduleError::from)
}

/// Closed schedule validation and evaluation failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum GithubScheduleError {
    /// The schedule mapping or entry count is invalid.
    #[error("GitHub schedule configuration is invalid")]
    InvalidConfiguration,
    /// The cron expression is not supported POSIX five-field syntax.
    #[error("GitHub schedule cron expression is invalid")]
    InvalidExpression,
    /// The cron expression may fire more frequently than every five minutes.
    #[error("GitHub schedule interval is shorter than five minutes")]
    IntervalTooShort,
    /// The timezone is not a bounded available IANA identifier.
    #[error("GitHub schedule timezone is invalid")]
    InvalidTimezone,
    /// The supplied instant is outside the supported timestamp range.
    #[error("GitHub schedule timestamp is outside the supported range")]
    TimestampOutOfRange,
    /// No real calendar occurrence exists inside the bounded search horizon.
    #[error("GitHub schedule has no future calendar match")]
    NoFutureMatch,
}

impl From<ScheduleError> for GithubScheduleError {
    fn from(error: ScheduleError) -> Self {
        match error {
            ScheduleError::InvalidExpression => Self::InvalidExpression,
            ScheduleError::IntervalTooShort => Self::IntervalTooShort,
            ScheduleError::InvalidTimezone => Self::InvalidTimezone,
            ScheduleError::TimestampOutOfRange => Self::TimestampOutOfRange,
            ScheduleError::NoFutureMatch => Self::NoFutureMatch,
        }
    }
}

fn extract_entry(
    node: &YamlNode,
    ordinal: u16,
) -> Result<GithubScheduleEntry, GithubScheduleError> {
    let fields = node
        .as_mapping()
        .ok_or(GithubScheduleError::InvalidConfiguration)?;
    let mut cron = None;
    let mut timezone = None;
    for field in fields {
        match mapping_key(field) {
            Some("cron") if cron.is_none() => cron = scalar_text(field.value()),
            Some("timezone") if timezone.is_none() => timezone = scalar_text(field.value()),
            _ => return Err(GithubScheduleError::InvalidConfiguration),
        }
    }
    let expression =
        GithubCronExpression::parse(cron.ok_or(GithubScheduleError::InvalidConfiguration)?)?;
    let timezone = timezone.unwrap_or("UTC").to_owned();
    validate_github_schedule_timezone(&timezone)?;
    Ok(GithubScheduleEntry {
        expression,
        timezone,
        ordinal,
    })
}

fn scalar_text(node: &YamlNode) -> Option<&str> {
    node.as_scalar()
        .filter(|scalar| !scalar.is_null())
        .map(crate::YamlScalar::decoded)
}

fn mapping_key(entry: &YamlMappingEntry) -> Option<&str> {
    scalar_text(entry.key())
}
