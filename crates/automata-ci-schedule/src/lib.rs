//! Provider-neutral, bounded cron and IANA timezone contracts.
//!
//! [`CronExpression`] accepts a deliberately small POSIX-compatible
//! five-field grammar. Evaluation is calendar based: day-of-month and
//! day-of-week use the POSIX restricted-field OR rule, daylight-saving gaps
//! are skipped, and both real instants in a daylight-saving fold are retained.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use automata_ci_core::UnixMillis;
use jiff::{
    Timestamp,
    civil::Date,
    tz::{AmbiguousOffset, TimeZone},
};
use thiserror::Error;

/// Maximum decoded bytes in one exact five-field cron expression.
// foundation-governance: parity-limit
pub const MAX_CRON_EXPRESSION_BYTES: usize = 256;
/// Maximum bytes in one IANA timezone identifier.
// foundation-governance: parity-limit
pub const MAX_IANA_TIMEZONE_BYTES: usize = 255;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScheduleLimitRejection {
    ExpressionBytes,
    TimezoneBytes,
    IntervalMinutes,
}

const fn cron_expression_byte_rejection(observed: usize) -> Option<ScheduleLimitRejection> {
    if observed > MAX_CRON_EXPRESSION_BYTES {
        return Some(ScheduleLimitRejection::ExpressionBytes);
    }
    None
}

const fn timezone_byte_rejection(observed: usize) -> Option<ScheduleLimitRejection> {
    if observed > MAX_IANA_TIMEZONE_BYTES {
        return Some(ScheduleLimitRejection::TimezoneBytes);
    }
    None
}
/// Minimum supported interval between selected wall-clock minutes.
// foundation-governance: parity-limit
pub const MINIMUM_CRON_INTERVAL_MINUTES: u16 = 5;

const fn cron_interval_rejection(observed: u16) -> Option<ScheduleLimitRejection> {
    if observed < MINIMUM_CRON_INTERVAL_MINUTES {
        return Some(ScheduleLimitRejection::IntervalMinutes);
    }
    None
}

// foundation-governance: operational-limit
const MAXIMUM_CALENDAR_SEARCH_DAYS: usize = 3_660;

/// One validated, exact five-field cron expression.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CronExpression {
    exact: String,
    minutes: Field,
    hours: Field,
    days_of_month: Field,
    months: Field,
    days_of_week: Field,
}

impl CronExpression {
    /// Parses the supported POSIX five-field syntax and minimum interval.
    ///
    /// Numeric values, ASCII three-letter month and weekday names, `*`,
    /// lists, inclusive ranges, and positive `/` steps are supported. `@`
    /// aliases, wrapping ranges, and non-POSIX operators are rejected.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, out-of-range, excessive, or
    /// sub-five-minute expressions.
    pub fn parse(exact: impl Into<String>) -> Result<Self, ScheduleError> {
        let exact = exact.into();
        validate_expression_text(&exact)?;
        let fields = exact.split_ascii_whitespace().collect::<Vec<_>>();
        let [minute, hour, calendar_day, month, weekday] = fields.as_slice() else {
            return Err(ScheduleError::InvalidExpression);
        };
        let minutes = parse_field(minute, FieldKind::Minute)?;
        let hours = parse_field(hour, FieldKind::Hour)?;
        let days_of_month = parse_field(calendar_day, FieldKind::DayOfMonth)?;
        let months = parse_field(month, FieldKind::Month)?;
        let days_of_week = parse_field(weekday, FieldKind::DayOfWeek)?;
        let expression = Self {
            exact,
            minutes,
            hours,
            days_of_month,
            months,
            days_of_week,
        };
        if cron_interval_rejection(expression.minimum_daily_interval()).is_some() {
            return Err(ScheduleError::IntervalTooShort);
        }
        Ok(expression)
    }

    /// Returns the exact decoded source spelling.
    #[must_use]
    pub fn exact(&self) -> &str {
        &self.exact
    }

    /// Reports whether one exact UTC instant matches in the supplied timezone.
    ///
    /// # Errors
    ///
    /// Rejects an unavailable timezone database entry or out-of-range instant.
    pub fn matches_at(&self, instant: UnixMillis, timezone: &str) -> Result<bool, ScheduleError> {
        let timezone = parse_timezone(timezone)?;
        let timestamp = Timestamp::from_millisecond(instant.get())
            .map_err(|_| ScheduleError::TimestampOutOfRange)?;
        let local = timestamp.to_zoned(timezone);
        Ok(local.second() == 0
            && local.subsec_nanosecond() == 0
            && self.matches_components(
                local.minute(),
                local.hour(),
                local.day(),
                local.month(),
                local.weekday().to_sunday_zero_offset(),
            ))
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
    ) -> Result<UnixMillis, ScheduleError> {
        let timezone = parse_timezone(timezone)?;
        let timestamp = Timestamp::from_millisecond(instant.get())
            .map_err(|_| ScheduleError::TimestampOutOfRange)?;
        let mut date = timestamp.to_zoned(timezone.clone()).date();
        for _ in 0..MAXIMUM_CALENDAR_SEARCH_DAYS {
            if self.matches_date(date)
                && let Some(candidate) = self.first_candidate_on(date, &timezone, timestamp)?
            {
                return Ok(UnixMillis::new(candidate.as_millisecond()));
            }
            date = date
                .tomorrow()
                .map_err(|_| ScheduleError::TimestampOutOfRange)?;
        }
        Err(ScheduleError::NoFutureMatch)
    }

    fn minimum_daily_interval(&self) -> u16 {
        let mut times = Vec::with_capacity(24 * 12);
        for hour in 0_u16..24 {
            if !self.hours.contains(hour) {
                continue;
            }
            for minute in 0_u16..60 {
                if self.minutes.contains(minute) {
                    times.push(hour * 60 + minute);
                }
            }
        }
        let mut minimum = 24 * 60;
        for pair in times.windows(2) {
            minimum = minimum.min(pair[1] - pair[0]);
        }
        if let (Some(first), Some(last)) = (times.first(), times.last()) {
            minimum = minimum.min(24 * 60 - last + first);
        }
        minimum
    }

    fn matches_components(&self, minute: i8, hour: i8, day: i8, month: i8, weekday: i8) -> bool {
        let (Ok(minute), Ok(hour)) = (u16::try_from(minute), u16::try_from(hour)) else {
            return false;
        };
        self.minutes.contains(minute)
            && self.hours.contains(hour)
            && self.matches_date_components(day, month, weekday)
    }

    fn matches_date(&self, date: Date) -> bool {
        self.matches_date_components(
            date.day(),
            date.month(),
            date.weekday().to_sunday_zero_offset(),
        )
    }

    fn matches_date_components(&self, day: i8, month: i8, weekday: i8) -> bool {
        let (Ok(day), Ok(month), Ok(weekday)) = (
            u16::try_from(day),
            u16::try_from(month),
            u16::try_from(weekday),
        ) else {
            return false;
        };
        if !self.months.contains(month) {
            return false;
        }
        let day_matches = self.days_of_month.contains(day);
        let weekday_matches = self.days_of_week.contains(weekday);
        match (
            self.days_of_month.is_unrestricted(),
            self.days_of_week.is_unrestricted(),
        ) {
            (true, true) => true,
            (true, false) => weekday_matches,
            (false, true) => day_matches,
            (false, false) => day_matches || weekday_matches,
        }
    }

    fn first_candidate_on(
        &self,
        date: Date,
        timezone: &TimeZone,
        after: Timestamp,
    ) -> Result<Option<Timestamp>, ScheduleError> {
        let mut best = None;
        for hour in 0_u16..24 {
            if !self.hours.contains(hour) {
                continue;
            }
            for minute in 0_u16..60 {
                if !self.minutes.contains(minute) {
                    continue;
                }
                let local_hour =
                    i8::try_from(hour).map_err(|_| ScheduleError::TimestampOutOfRange)?;
                let local_minute =
                    i8::try_from(minute).map_err(|_| ScheduleError::TimestampOutOfRange)?;
                let local = date.at(local_hour, local_minute, 0, 0);
                let ambiguous = timezone.to_ambiguous_zoned(local);
                match ambiguous.offset() {
                    AmbiguousOffset::Gap { .. } => {}
                    AmbiguousOffset::Unambiguous { .. } => {
                        let candidate = ambiguous
                            .unambiguous()
                            .map_err(|_| ScheduleError::TimestampOutOfRange)?
                            .timestamp();
                        retain_candidate(&mut best, candidate, after);
                    }
                    AmbiguousOffset::Fold { .. } => {
                        let earlier = ambiguous
                            .clone()
                            .earlier()
                            .map_err(|_| ScheduleError::TimestampOutOfRange)?
                            .timestamp();
                        let later = ambiguous
                            .later()
                            .map_err(|_| ScheduleError::TimestampOutOfRange)?
                            .timestamp();
                        retain_candidate(&mut best, earlier, after);
                        retain_candidate(&mut best, later, after);
                    }
                }
            }
        }
        Ok(best)
    }
}

/// Validates one bounded IANA timezone identifier against the runtime database.
///
/// # Errors
///
/// Rejects empty, non-ASCII, control-bearing, padded, excessive, or unavailable
/// identifiers.
pub fn validate_iana_timezone(source: &str) -> Result<(), ScheduleError> {
    parse_timezone(source).map(drop)
}

/// Closed schedule validation and evaluation failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ScheduleError {
    /// The cron expression is not supported POSIX five-field syntax.
    #[error("cron expression is invalid")]
    InvalidExpression,
    /// The cron expression may fire more frequently than every five minutes.
    #[error("cron interval is shorter than five minutes")]
    IntervalTooShort,
    /// The timezone is not a bounded available IANA identifier.
    #[error("timezone is invalid")]
    InvalidTimezone,
    /// The supplied instant is outside the supported timestamp range.
    #[error("timestamp is outside the supported range")]
    TimestampOutOfRange,
    /// No real calendar occurrence exists inside the bounded search horizon.
    #[error("schedule has no future calendar match")]
    NoFutureMatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Field {
    bits: u64,
    minimum: u16,
    maximum: u16,
}

impl Field {
    const fn contains(self, value: u16) -> bool {
        value >= self.minimum
            && value <= self.maximum
            && self.bits & (1_u64 << (value - self.minimum)) != 0
    }

    const fn is_unrestricted(self) -> bool {
        let width = self.maximum - self.minimum + 1;
        let all = if width == 64 {
            u64::MAX
        } else {
            (1_u64 << width) - 1
        };
        self.bits == all
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FieldKind {
    Minute,
    Hour,
    DayOfMonth,
    Month,
    DayOfWeek,
}

impl FieldKind {
    const fn bounds(self) -> (u16, u16) {
        match self {
            Self::Minute => (0, 59),
            Self::Hour => (0, 23),
            Self::DayOfMonth => (1, 31),
            Self::Month => (1, 12),
            Self::DayOfWeek => (0, 6),
        }
    }
}

fn validate_expression_text(expression: &str) -> Result<(), ScheduleError> {
    if expression.is_empty()
        || cron_expression_byte_rejection(expression.len()).is_some()
        || expression.trim() != expression
        || !expression.is_ascii()
        || expression.starts_with('@')
        || expression
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || b"*,-/ ".contains(&byte)))
    {
        return Err(ScheduleError::InvalidExpression);
    }
    Ok(())
}

fn parse_field(source: &str, kind: FieldKind) -> Result<Field, ScheduleError> {
    if source.is_empty() {
        return Err(ScheduleError::InvalidExpression);
    }
    let (minimum, maximum) = kind.bounds();
    let mut field = Field {
        bits: 0,
        minimum,
        maximum,
    };
    for item in source.split(',') {
        if item.is_empty() {
            return Err(ScheduleError::InvalidExpression);
        }
        let (base, step, stepped) = split_step(item, maximum - minimum + 1)?;
        let (start, end) = parse_base(base, kind, minimum, maximum, stepped)?;
        let mut value = start;
        while value <= end {
            field.bits |= 1_u64 << (normalize_value(value, kind)? - minimum);
            let Some(next) = value.checked_add(step) else {
                break;
            };
            value = next;
        }
    }
    if field.bits == 0 {
        return Err(ScheduleError::InvalidExpression);
    }
    Ok(field)
}

fn split_step(source: &str, maximum: u16) -> Result<(&str, u16, bool), ScheduleError> {
    let Some((base, step)) = source.split_once('/') else {
        return Ok((source, 1, false));
    };
    if base.is_empty() || step.is_empty() || step.contains('/') {
        return Err(ScheduleError::InvalidExpression);
    }
    let step = step
        .parse::<u16>()
        .ok()
        .filter(|step| *step > 0 && *step <= maximum)
        .ok_or(ScheduleError::InvalidExpression)?;
    Ok((base, step, true))
}

fn parse_base(
    source: &str,
    kind: FieldKind,
    minimum: u16,
    maximum: u16,
    stepped: bool,
) -> Result<(u16, u16), ScheduleError> {
    if source == "*" {
        return Ok((minimum, maximum));
    }
    if let Some((start, end)) = source.split_once('-') {
        if start.is_empty() || end.is_empty() || end.contains('-') {
            return Err(ScheduleError::InvalidExpression);
        }
        let start = parse_value(start, kind)?;
        let end = parse_value(end, kind)?;
        let syntax_maximum = if kind == FieldKind::DayOfWeek {
            7
        } else {
            maximum
        };
        if start > end || start < minimum || end > syntax_maximum {
            return Err(ScheduleError::InvalidExpression);
        }
        return Ok((start, end));
    }
    let start = normalize_value(parse_value(source, kind)?, kind)?;
    if start < minimum || start > maximum {
        return Err(ScheduleError::InvalidExpression);
    }
    Ok((start, if stepped { maximum } else { start }))
}

fn parse_value(source: &str, kind: FieldKind) -> Result<u16, ScheduleError> {
    if let Ok(value) = source.parse::<u16>() {
        return Ok(value);
    }
    match kind {
        FieldKind::Month => named_value(source, &MONTH_NAMES).map(|value| value + 1),
        FieldKind::DayOfWeek => named_value(source, &WEEKDAY_NAMES),
        _ => None,
    }
    .ok_or(ScheduleError::InvalidExpression)
}

fn normalize_value(value: u16, kind: FieldKind) -> Result<u16, ScheduleError> {
    if kind == FieldKind::DayOfWeek && value == 7 {
        return Ok(0);
    }
    let (minimum, maximum) = kind.bounds();
    (value >= minimum && value <= maximum)
        .then_some(value)
        .ok_or(ScheduleError::InvalidExpression)
}

fn named_value(source: &str, names: &[&str]) -> Option<u16> {
    names
        .iter()
        .position(|name| source.eq_ignore_ascii_case(name))
        .and_then(|index| u16::try_from(index).ok())
}

fn parse_timezone(source: &str) -> Result<TimeZone, ScheduleError> {
    if source.is_empty()
        || timezone_byte_rejection(source.len()).is_some()
        || source.trim() != source
        || !source.is_ascii()
        || source.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ScheduleError::InvalidTimezone);
    }
    TimeZone::get(source).map_err(|_| ScheduleError::InvalidTimezone)
}

fn retain_candidate(best: &mut Option<Timestamp>, candidate: Timestamp, after: Timestamp) {
    if candidate > after && best.is_none_or(|current| candidate < current) {
        *best = Some(candidate);
    }
}

const MONTH_NAMES: [&str; 12] = [
    "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
];
const WEEKDAY_NAMES: [&str; 7] = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"];

#[cfg(test)]
mod limit_contract_tests {
    use super::*;

    #[test]
    fn cron_expression_byte_limit_has_exact_boundaries() {
        assert_eq!(
            cron_expression_byte_rejection(MAX_CRON_EXPRESSION_BYTES - 1),
            None
        );
        assert_eq!(
            cron_expression_byte_rejection(MAX_CRON_EXPRESSION_BYTES),
            None
        );
        assert_eq!(
            cron_expression_byte_rejection(MAX_CRON_EXPRESSION_BYTES + 1),
            Some(ScheduleLimitRejection::ExpressionBytes)
        );
    }

    #[test]
    fn iana_timezone_byte_limit_has_exact_boundaries() {
        assert_eq!(timezone_byte_rejection(MAX_IANA_TIMEZONE_BYTES - 1), None);
        assert_eq!(timezone_byte_rejection(MAX_IANA_TIMEZONE_BYTES), None);
        assert_eq!(
            timezone_byte_rejection(MAX_IANA_TIMEZONE_BYTES + 1),
            Some(ScheduleLimitRejection::TimezoneBytes)
        );
    }

    #[test]
    fn minimum_cron_interval_limit_has_exact_boundaries() {
        assert_eq!(
            cron_interval_rejection(MINIMUM_CRON_INTERVAL_MINUTES - 1),
            Some(ScheduleLimitRejection::IntervalMinutes)
        );
        assert_eq!(cron_interval_rejection(MINIMUM_CRON_INTERVAL_MINUTES), None);
        assert_eq!(
            cron_interval_rejection(MINIMUM_CRON_INTERVAL_MINUTES + 1),
            None
        );
    }
}
