use std::fmt::Write as _;

use automata_ci_core::{JobConclusion, JobResult, StepResult};
use automata_ci_github::{GithubCheckModelError, GithubCheckOutput};

const MAX_PRESENTATION_TEXT_BYTES: usize = 60 * 1_024;
const TRUNCATION_MARKER: &str = "\n\n_Additional step detail was truncated._";

pub(super) fn terminal_output(
    result: &JobResult,
    details_url: &str,
) -> Result<GithubCheckOutput, GithubCheckModelError> {
    let mut counts = ConclusionCounts::default();
    for step in result.steps() {
        counts.observe(step.conclusion());
    }
    let summary = format!(
        "{}\n\n{}\n\n[Open this job in Automata]({details_url})",
        conclusion_summary(result.conclusion()),
        counts.summary(result.steps().len()),
    );
    let text = render_step_details(result.steps());
    GithubCheckOutput::new(
        conclusion_title(result.conclusion()),
        summary,
        (!text.is_empty()).then_some(text),
    )
}

#[derive(Default)]
struct ConclusionCounts {
    succeeded: usize,
    failed: usize,
    cancelled: usize,
    timed_out: usize,
    skipped: usize,
}

impl ConclusionCounts {
    fn observe(&mut self, conclusion: JobConclusion) {
        match conclusion {
            JobConclusion::Success => self.succeeded += 1,
            JobConclusion::Failure => self.failed += 1,
            JobConclusion::Cancelled => self.cancelled += 1,
            JobConclusion::TimedOut => self.timed_out += 1,
            JobConclusion::Skipped => self.skipped += 1,
        }
    }

    fn summary(&self, total: usize) -> String {
        format!(
            "**{}** — {} passed, {} failed, {} timed out, {} cancelled, {} skipped.",
            pluralized(total, "step", "steps"),
            self.succeeded,
            self.failed,
            self.timed_out,
            self.cancelled,
            self.skipped,
        )
    }
}

fn render_step_details(steps: &[StepResult]) -> String {
    if steps.is_empty() {
        return String::new();
    }
    let mut output = String::from(
        "### Step results\n\n| Step | Outcome | Conclusion | Duration |\n| --- | --- | --- | ---: |\n",
    );
    let mut truncated = false;
    for step in steps {
        let duration = step
            .completed_at()
            .get()
            .saturating_sub(step.started_at().get());
        let row = format!(
            "| `{}` | {} | {} | {} |\n",
            step.step_id().as_str(),
            conclusion_label(step.outcome()),
            conclusion_label(step.conclusion()),
            duration_label(duration),
        );
        if !push_bounded(&mut output, &row) {
            truncated = true;
            break;
        }
    }
    if !truncated {
        for step in steps {
            let Some(summary) = step.summary_markdown() else {
                continue;
            };
            let heading = format!("\n### `{}` summary\n\n", step.step_id().as_str());
            if !push_bounded(&mut output, &heading)
                || !push_canonical_markdown_bounded(&mut output, summary)
            {
                truncated = true;
                break;
            }
        }
    }
    if truncated {
        append_truncation_marker(&mut output);
    }
    output
}

fn push_bounded(output: &mut String, value: &str) -> bool {
    if output
        .len()
        .checked_add(value.len())
        .and_then(|size| size.checked_add(TRUNCATION_MARKER.len()))
        .is_some_and(|size| size <= MAX_PRESENTATION_TEXT_BYTES)
    {
        output.push_str(value);
        true
    } else {
        false
    }
}

fn push_canonical_markdown_bounded(output: &mut String, value: &str) -> bool {
    let mut complete = true;
    for character in value.chars() {
        let character = if character.is_control() && !matches!(character, '\n' | '\t') {
            complete = false;
            '\u{fffd}'
        } else {
            character
        };
        if output
            .len()
            .checked_add(character.len_utf8())
            .and_then(|size| size.checked_add(TRUNCATION_MARKER.len()))
            .is_none_or(|size| size > MAX_PRESENTATION_TEXT_BYTES)
        {
            return false;
        }
        output.push(character);
    }
    complete
}

fn append_truncation_marker(output: &mut String) {
    while output.len() + TRUNCATION_MARKER.len() > MAX_PRESENTATION_TEXT_BYTES {
        output.pop();
    }
    output.push_str(TRUNCATION_MARKER);
}

const fn conclusion_title(conclusion: JobConclusion) -> &'static str {
    match conclusion {
        JobConclusion::Success => "Passed",
        JobConclusion::Failure => "Failed",
        JobConclusion::Cancelled => "Cancelled",
        JobConclusion::TimedOut => "Timed out",
        JobConclusion::Skipped => "Skipped",
    }
}

const fn conclusion_summary(conclusion: JobConclusion) -> &'static str {
    match conclusion {
        JobConclusion::Success => "The job completed successfully.",
        JobConclusion::Failure => "The job failed.",
        JobConclusion::Cancelled => "The job was cancelled.",
        JobConclusion::TimedOut => "The job timed out.",
        JobConclusion::Skipped => "The job was skipped.",
    }
}

const fn conclusion_label(conclusion: JobConclusion) -> &'static str {
    match conclusion {
        JobConclusion::Success => "passed",
        JobConclusion::Failure => "failed",
        JobConclusion::Cancelled => "cancelled",
        JobConclusion::TimedOut => "timed out",
        JobConclusion::Skipped => "skipped",
    }
}

fn duration_label(milliseconds: i64) -> String {
    let seconds = milliseconds / 1_000;
    let hours = seconds / 3_600;
    let minutes = seconds % 3_600 / 60;
    let seconds = seconds % 60;
    let mut value = String::new();
    if hours > 0 {
        write!(&mut value, "{hours}h ").expect("writing to a String cannot fail");
    }
    if minutes > 0 || hours > 0 {
        write!(&mut value, "{minutes}m ").expect("writing to a String cannot fail");
    }
    write!(&mut value, "{seconds}s").expect("writing to a String cannot fail");
    value
}

fn pluralized(count: usize, singular: &str, plural: &str) -> String {
    format!("{count} {}", if count == 1 { singular } else { plural })
}

#[cfg(test)]
mod tests {
    use automata_ci_core::{
        AttemptId, JobConclusion, JobResult, JobSecretExposure, StepId, StepResult, UnixMillis,
    };

    use super::*;

    #[test]
    fn terminal_output_contains_counts_timelines_summaries_and_exact_link() {
        let result = JobResult::new(
            AttemptId::new(),
            JobConclusion::Failure,
            JobSecretExposure::Secretless,
            UnixMillis::new(65_000),
        )
        .with_steps(vec![
            StepResult::new(
                StepId::new("checkout").expect("step"),
                JobConclusion::Success,
                JobConclusion::Success,
                UnixMillis::new(1_000),
                UnixMillis::new(3_000),
            ),
            StepResult::new(
                StepId::new("test").expect("step"),
                JobConclusion::Failure,
                JobConclusion::Failure,
                UnixMillis::new(3_000),
                UnixMillis::new(65_000),
            )
            .with_summary_markdown("### Failure\n\nAssertion output was masked."),
        ]);
        result.validate().expect("result");

        let output =
            terminal_output(&result, "https://ci.example/runs/1/jobs/2").expect("GitHub output");
        assert_eq!(output.title(), "Failed");
        assert!(output.summary().contains("2 steps"));
        assert!(output.summary().contains("1 passed, 1 failed"));
        assert!(
            output
                .summary()
                .contains("https://ci.example/runs/1/jobs/2")
        );
        let text = output.text().expect("step details");
        assert!(text.contains("| `checkout` | passed | passed | 2s |"));
        assert!(text.contains("| `test` | failed | failed | 1m 2s |"));
        assert!(text.contains("Assertion output was masked."));
    }

    #[test]
    fn presentation_truncates_on_a_unicode_scalar_boundary() {
        let result = JobResult::new(
            AttemptId::new(),
            JobConclusion::Success,
            JobSecretExposure::Secretless,
            UnixMillis::new(2_000),
        )
        .with_steps(vec![
            StepResult::new(
                StepId::new("large_summary").expect("step"),
                JobConclusion::Success,
                JobConclusion::Success,
                UnixMillis::new(1_000),
                UnixMillis::new(2_000),
            )
            .with_summary_markdown("🚀".repeat(20_000)),
        ]);
        result.validate().expect("result");

        let output = terminal_output(&result, "https://ci.example/job").expect("output");
        let text = output.text().expect("details");
        assert!(text.len() <= MAX_PRESENTATION_TEXT_BYTES);
        assert!(text.ends_with(TRUNCATION_MARKER));
        assert!(std::str::from_utf8(text.as_bytes()).is_ok());
    }
}
