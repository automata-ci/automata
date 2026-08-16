use crate::support;

use automata_ci_core::UnixMillis;
use automata_ci_workflow_github::{
    GithubCronExpression, GithubScheduleError, extract_github_schedule_entries,
};
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
fn supported_posix_fields_are_bounded_and_preserve_exact_spelling() {
    for source in [
        "*/5 * * * *",
        "7/10 2,8-12/2 * JAN,MAR MON-FRI",
        "0 0 1 1 *",
        "0 12 * * 0,7",
        "0 12 * * 5-7",
    ] {
        let parsed = GithubCronExpression::parse(source).expect(source);
        assert_eq!(parsed.exact(), source);
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
    ] {
        assert!(GithubCronExpression::parse(source).is_err(), "{source}");
    }
    assert_eq!(
        GithubCronExpression::parse("*/2 * * * *"),
        Err(GithubScheduleError::IntervalTooShort)
    );
}

#[test]
fn posix_day_fields_use_the_standard_restricted_or_rule() {
    let expression = GithubCronExpression::parse("0 9 15 * MON").expect("valid expression");
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
    let gap = GithubCronExpression::parse("30 2 * * *").expect("valid expression");
    assert_eq!(
        gap.next_after(millis("2026-03-07T07:30:00Z"), "America/New_York")
            .expect("next real local occurrence"),
        millis("2026-03-09T06:30:00Z")
    );

    let fold = GithubCronExpression::parse("30 1 * * *").expect("valid expression");
    assert_eq!(
        fold.next_after(millis("2026-11-01T05:30:00Z"), "America/New_York")
            .expect("second repeated local occurrence"),
        millis("2026-11-01T06:30:00Z")
    );
}

#[test]
fn extraction_preserves_order_and_defaults_timezone_to_utc() {
    let source = "on:\n  schedule:\n    - cron: '15 4 * * MON-FRI'\n    - cron: '45 16 * * 2,4'\n      timezone: Europe/Sofia\njobs:\n  verify:\n    runs-on: linux\n    steps:\n      - run: true\n";
    let parsed = support::parse_accepted(source);
    let entries = extract_github_schedule_entries(parsed.plan().expect("source plan"))
        .expect("valid schedules");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].ordinal(), 0);
    assert_eq!(entries[0].timezone(), "UTC");
    assert_eq!(entries[0].expression().exact(), "15 4 * * MON-FRI");
    assert_eq!(entries[1].ordinal(), 1);
    assert_eq!(entries[1].timezone(), "Europe/Sofia");
}
