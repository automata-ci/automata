use std::fmt::Write as _;

use automata_ci_core::{
    JobConclusion, JobResult, Sha256Digest, StepAnnotation, StepAnnotationLevel,
    StepAnnotationProperty, StepResult,
};
use automata_ci_github::{
    GithubCheckAnnotation, GithubCheckAnnotationLevel, GithubCheckModelError, GithubCheckOutput,
};
use sha2::{Digest as _, Sha256};

const MAX_PRESENTATION_TEXT_BYTES: usize = 60 * 1_024;
const TRUNCATION_MARKER: &str = "\n\n_Additional step detail was truncated._";
const PRESENTATION_DIGEST_DOMAIN: &[u8] = b"automata.github-check-presentation.v1\0";

pub(super) struct GithubTerminalPresentation {
    output: GithubCheckOutput,
    annotations: Vec<GithubCheckAnnotation>,
    digest: Sha256Digest,
}

impl GithubTerminalPresentation {
    pub(super) const fn output(&self) -> &GithubCheckOutput {
        &self.output
    }

    pub(super) fn annotations(&self) -> &[GithubCheckAnnotation] {
        &self.annotations
    }

    pub(super) const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

pub(super) fn terminal_presentation(
    result: &JobResult,
    details_url: &str,
) -> Result<GithubTerminalPresentation, GithubCheckModelError> {
    let mut counts = ConclusionCounts::default();
    for step in result.steps() {
        counts.observe(step.conclusion());
    }
    let (annotations, omitted_annotations) = render_annotations(result.steps());
    let omission = if omitted_annotations == 0 {
        String::new()
    } else {
        format!(
            "\n\n{omitted_annotations} {} could not be attached to a canonical source location and remain visible in Automata.",
            if omitted_annotations == 1 {
                "diagnostic"
            } else {
                "diagnostics"
            }
        )
    };
    let summary = format!(
        "{}\n\n{}{}\n\n[Open this job in Automata]({details_url})",
        conclusion_summary(result.conclusion()),
        counts.summary(result.steps().len()),
        omission,
    );
    let text = render_step_details(result.steps());
    let output = GithubCheckOutput::new(
        conclusion_title(result.conclusion()),
        summary,
        (!text.is_empty()).then_some(text),
    )?;
    let digest = presentation_digest(&output, &annotations, omitted_annotations);
    Ok(GithubTerminalPresentation {
        output,
        annotations,
        digest,
    })
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

fn render_annotations(steps: &[StepResult]) -> (Vec<GithubCheckAnnotation>, usize) {
    let mut converted = Vec::new();
    let mut omitted = 0_usize;
    for step in steps {
        for annotation in step.annotations() {
            match render_annotation(annotation) {
                Some(annotation) => converted.push(annotation),
                None => omitted = omitted.saturating_add(1),
            }
        }
    }
    (converted, omitted)
}

fn render_annotation(annotation: &StepAnnotation) -> Option<GithubCheckAnnotation> {
    let path = annotation_property(annotation, "file")?.replace('\\', "/");
    if path.as_bytes().get(1) == Some(&b':') {
        return None;
    }
    let start_line = positive_decimal(annotation_property(annotation, "line")?)?;
    let end_line = optional_positive_property(annotation, "endLine")
        .ok()?
        .unwrap_or(start_line);
    let start_column = optional_positive_property(annotation, "col").ok()?;
    let end_column = optional_positive_property(annotation, "endColumn").ok()?;
    let level = match annotation.level() {
        StepAnnotationLevel::Error => GithubCheckAnnotationLevel::Failure,
        StepAnnotationLevel::Warning => GithubCheckAnnotationLevel::Warning,
        StepAnnotationLevel::Notice => GithubCheckAnnotationLevel::Notice,
    };
    GithubCheckAnnotation::new(
        path,
        start_line,
        end_line,
        start_column,
        end_column,
        level,
        annotation.message().to_owned(),
        annotation_property(annotation, "title").map(str::to_owned),
    )
    .ok()
}

fn annotation_property<'a>(annotation: &'a StepAnnotation, name: &str) -> Option<&'a str> {
    annotation
        .properties()
        .iter()
        .find(|property| property.name().eq_ignore_ascii_case(name))
        .map(StepAnnotationProperty::value)
}

fn positive_decimal(value: &str) -> Option<u32> {
    let parsed = value.parse::<u32>().ok()?;
    (parsed > 0 && parsed.to_string() == value).then_some(parsed)
}

fn optional_positive_property(annotation: &StepAnnotation, name: &str) -> Result<Option<u32>, ()> {
    match annotation_property(annotation, name) {
        None => Ok(None),
        Some(value) => positive_decimal(value).map(Some).ok_or(()),
    }
}

fn presentation_digest(
    output: &GithubCheckOutput,
    annotations: &[GithubCheckAnnotation],
    omitted_annotations: usize,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(PRESENTATION_DIGEST_DOMAIN);
    hash_text(&mut hasher, output.title());
    hash_text(&mut hasher, output.summary());
    hash_text(&mut hasher, output.text().unwrap_or_default());
    hasher.update(
        u64::try_from(omitted_annotations)
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for annotation in annotations {
        let encoded = serde_json::to_vec(annotation)
            .expect("validated GitHub annotations always serialize to JSON");
        hasher.update(
            u64::try_from(encoded.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hasher.update(encoded);
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn hash_text(hasher: &mut Sha256, value: &str) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value.as_bytes());
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
        AttemptId, JobConclusion, JobResult, JobSecretExposure, StepAnnotation,
        StepAnnotationLevel, StepAnnotationProperty, StepId, StepResult, UnixMillis,
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

        let presentation = terminal_presentation(&result, "https://ci.example/runs/1/jobs/2")
            .expect("GitHub output");
        let output = presentation.output();
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

        let presentation =
            terminal_presentation(&result, "https://ci.example/job").expect("output");
        let text = presentation.output().text().expect("details");
        assert!(text.len() <= MAX_PRESENTATION_TEXT_BYTES);
        assert!(text.ends_with(TRUNCATION_MARKER));
        assert!(std::str::from_utf8(text.as_bytes()).is_ok());
    }

    #[test]
    fn annotations_are_ordered_normalized_and_invalid_locations_are_counted() {
        let result = JobResult::new(
            AttemptId::new(),
            JobConclusion::Failure,
            JobSecretExposure::Secretless,
            UnixMillis::new(2_000),
        )
        .with_steps(vec![
            StepResult::new(
                StepId::new("test").expect("step"),
                JobConclusion::Failure,
                JobConclusion::Failure,
                UnixMillis::new(1_000),
                UnixMillis::new(2_000),
            )
            .with_annotations(vec![
                StepAnnotation::new(
                    StepAnnotationLevel::Error,
                    "masked failure",
                    vec![
                        StepAnnotationProperty::new("file", "src\\lib.rs"),
                        StepAnnotationProperty::new("line", "7"),
                        StepAnnotationProperty::new("col", "2"),
                        StepAnnotationProperty::new("endColumn", "9"),
                        StepAnnotationProperty::new("title", "compiler"),
                    ],
                ),
                StepAnnotation::new(
                    StepAnnotationLevel::Warning,
                    "outside repository",
                    vec![
                        StepAnnotationProperty::new("file", "../secret"),
                        StepAnnotationProperty::new("line", "1"),
                    ],
                ),
            ]),
        ]);
        result.validate().expect("result");

        let presentation =
            terminal_presentation(&result, "https://ci.example/job").expect("presentation");
        assert_eq!(presentation.annotations().len(), 1);
        let annotation = &presentation.annotations()[0];
        assert_eq!(annotation.path(), "src/lib.rs");
        assert_eq!(annotation.start_line(), 7);
        assert_eq!(annotation.start_column(), Some(2));
        assert_eq!(annotation.end_column(), Some(9));
        assert_eq!(annotation.level(), GithubCheckAnnotationLevel::Failure);
        assert!(presentation.output().summary().contains("1 diagnostic"));
        assert_ne!(presentation.digest(), Sha256Digest::from_bytes([0; 32]));
    }

    #[test]
    fn maximum_annotation_fixture_is_complete_deterministic_and_ordered() {
        let annotations = (1..=automata_ci_core::MAX_JOB_RESULT_ANNOTATIONS)
            .map(|line| {
                StepAnnotation::new(
                    StepAnnotationLevel::Notice,
                    format!("diagnostic {line}"),
                    vec![
                        StepAnnotationProperty::new("file", "src/generated.rs"),
                        StepAnnotationProperty::new("line", line.to_string()),
                    ],
                )
            })
            .collect();
        let result = JobResult::new(
            AttemptId::new(),
            JobConclusion::Failure,
            JobSecretExposure::Secretless,
            UnixMillis::new(2_000),
        )
        .with_steps(vec![
            StepResult::new(
                StepId::new("diagnostics").expect("step"),
                JobConclusion::Failure,
                JobConclusion::Failure,
                UnixMillis::new(1_000),
                UnixMillis::new(2_000),
            )
            .with_annotations(annotations),
        ]);
        result.validate().expect("maximum result fixture");

        let first =
            terminal_presentation(&result, "https://ci.example/job").expect("first presentation");
        let second =
            terminal_presentation(&result, "https://ci.example/job").expect("second presentation");
        assert_eq!(
            first.annotations().len(),
            automata_ci_core::MAX_JOB_RESULT_ANNOTATIONS
        );
        assert_eq!(first.annotations()[0].start_line(), 1);
        assert_eq!(
            first.annotations()[automata_ci_core::MAX_JOB_RESULT_ANNOTATIONS - 1].start_line(),
            u32::try_from(automata_ci_core::MAX_JOB_RESULT_ANNOTATIONS).expect("fixture fits u32")
        );
        assert_eq!(first.digest(), second.digest());
        assert_eq!(first.annotations(), second.annotations());
    }
}
