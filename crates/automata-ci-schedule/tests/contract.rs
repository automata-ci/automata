use automata_ci_core::UnixMillis;
use automata_ci_schedule::{CronExpression, ScheduleError, validate_iana_timezone};
use jiff::Timestamp;

fn millis(timestamp: &str) -> UnixMillis {
    UnixMillis::new(
        timestamp
            .parse::<Timestamp>()
            .expect("valid test timestamp")
            .as_millisecond(),
    )
}

#[test]
fn grammar_is_bounded_and_preserves_exact_spelling() {
    for source in [
        "*/5 * * * *",
        "7/10 2,8-12/2 * JAN,MAR MON-FRI",
        "0 0 1 1 *",
        "0 12 * * 0,7",
        "0 12 * * 5-7",
    ] {
        assert_eq!(CronExpression::parse(source).expect(source).exact(), source);
    }

    for source in [
        "@daily",
        "* * * * *",
        "*/4 * * * *",
        "0 0 0 * *",
        "0 0 1 13 *",
        "0 0 * * MON-SUN",
        "0 0 * * ?",
        "0 0 * * * *",
        "0/0 * * * *",
        "0//5 * * * *",
        "0 0 * * MON#2",
        "0\t6\t*\t*\tSUN",
        " 0 6 * * SUN",
        "0 6 * * SUN ",
    ] {
        assert!(CronExpression::parse(source).is_err(), "{source}");
    }
    assert_eq!(
        CronExpression::parse("*/2 * * * *"),
        Err(ScheduleError::IntervalTooShort)
    );
}

#[test]
fn posix_day_fields_use_the_restricted_or_rule() {
    let expression = CronExpression::parse("0 9 15 * MON").expect("valid expression");
    assert!(
        expression
            .matches_at(millis("2026-06-08T09:00:00Z"), "UTC")
            .expect("timezone")
    );
    assert!(
        expression
            .matches_at(millis("2026-07-15T09:00:00Z"), "UTC")
            .expect("timezone")
    );
    assert!(
        !expression
            .matches_at(millis("2026-07-14T09:00:00Z"), "UTC")
            .expect("timezone")
    );
}

#[test]
fn timezone_evaluation_skips_gaps_and_retains_both_fold_instants() {
    let gap = CronExpression::parse("30 2 * * *").expect("valid expression");
    assert_eq!(
        gap.next_after(millis("2026-03-07T07:30:00Z"), "America/New_York")
            .expect("next real local occurrence"),
        millis("2026-03-09T06:30:00Z")
    );

    let fold = CronExpression::parse("30 1 * * *").expect("valid expression");
    assert_eq!(
        fold.next_after(millis("2026-11-01T05:30:00Z"), "America/New_York")
            .expect("second repeated local occurrence"),
        millis("2026-11-01T06:30:00Z")
    );
}

#[test]
fn timezone_validation_uses_the_runtime_iana_database() {
    for timezone in ["UTC", "Europe/Sofia", "America/New_York"] {
        validate_iana_timezone(timezone).expect(timezone);
    }
    for timezone in ["", " Invalid/Zone", "Invalid/Zone", "+03:00"] {
        assert!(validate_iana_timezone(timezone).is_err(), "{timezone}");
    }
}
