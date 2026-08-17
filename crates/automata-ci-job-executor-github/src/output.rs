use std::{collections::BTreeSet, fmt, sync::Arc};

use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};
use automata_ci_auth::output_policy::SecretExposureClass;
use automata_ci_core::{JobSecretExposure, LogChannel, LogGroupId, MAX_LOG_FRAME_BYTES};
use automata_ci_execution::{ExecutionOutputRecord, ExecutionOutputStream};
use automata_ci_github_runtime::{
    Annotation, GithubWorkflowCommandSession, WorkflowCommandEvent, WorkflowCommandLimits,
    WorkflowCommandPolicy, WorkflowCommandProcessor, WorkflowLine,
};
use automata_ci_runner_runtime::{ExecutionEvents, LogEvent};
use zeroize::Zeroize as _;

use crate::{ExecutorAdapterError, error::ExecutorAdapterErrorKind};

const MAX_MASKS: usize = 4_096;
const MAX_MASK_BYTES: usize = 1_048_576;
const MASK_REPLACEMENT: &[u8] = b"***";
pub(crate) const DIAGNOSTICS_LOG_GROUP_ID: &str = "job/diagnostics";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MaskLimitRejection {
    Count,
    AggregateBytes,
}

const fn mask_count_rejection(projected: usize) -> Option<MaskLimitRejection> {
    if projected > MAX_MASKS {
        return Some(MaskLimitRejection::Count);
    }
    None
}

const fn mask_aggregate_bytes_rejection(projected: usize) -> Option<MaskLimitRejection> {
    if projected > MAX_MASK_BYTES {
        return Some(MaskLimitRejection::AggregateBytes);
    }
    None
}

pub(crate) struct SecretMasker {
    masks: BTreeSet<Vec<u8>>,
    aggregate_bytes: usize,
    matcher: Option<AhoCorasick>,
    exposure: SecretExposureClass,
    #[cfg(test)]
    matcher_builds: usize,
}

impl Drop for SecretMasker {
    fn drop(&mut self) {
        self.matcher = None;
        for mut mask in std::mem::take(&mut self.masks) {
            mask.zeroize();
        }
    }
}

impl SecretMasker {
    pub(crate) const fn new() -> Self {
        Self {
            masks: BTreeSet::new(),
            aggregate_bytes: 0,
            matcher: None,
            exposure: SecretExposureClass::Secretless,
            #[cfg(test)]
            matcher_builds: 0,
        }
    }

    pub(crate) fn register(&mut self, value: &str) -> Result<(), ExecutorAdapterError> {
        if value.is_empty() {
            return Ok(());
        }
        // Record the maximum observed exposure independently from value-level
        // redaction. Publication policy keeps readable-secret logs private,
        // while exact masks preserve ordinary diagnostic output.
        self.exposure = SecretExposureClass::ReadableSecret;
        self.register_bytes(value.as_bytes())?;
        for line in value
            .split(['\r', '\n'])
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            self.register_bytes(line.as_bytes())?;
        }
        Ok(())
    }

    fn register_bytes(&mut self, value: &[u8]) -> Result<(), ExecutorAdapterError> {
        if self.masks.contains(value) {
            return Ok(());
        }
        let aggregate = self
            .aggregate_bytes
            .checked_add(value.len())
            .ok_or_else(resource_exhausted)?;
        let mask_count = self
            .masks
            .len()
            .checked_add(1)
            .ok_or_else(resource_exhausted)?;
        if mask_count_rejection(mask_count).is_some()
            || mask_aggregate_bytes_rejection(aggregate).is_some()
        {
            return Err(resource_exhausted());
        }
        self.aggregate_bytes = aggregate;
        self.masks.insert(value.to_vec());
        self.matcher = None;
        Ok(())
    }

    pub(crate) fn mask(&mut self, source: &[u8]) -> Result<Vec<u8>, ExecutorAdapterError> {
        if source.is_empty() || self.masks.is_empty() {
            return Ok(source.to_vec());
        }

        let matcher = self.matcher()?;
        if matcher.find(source).is_none() {
            return Ok(source.to_vec());
        }

        let mut output = Vec::with_capacity(source.len());
        let mut cursor = 0;
        for matched in matcher.find_iter(source) {
            output.extend_from_slice(&source[cursor..matched.start()]);
            output.extend_from_slice(MASK_REPLACEMENT);
            cursor = matched.end();
        }
        output.extend_from_slice(&source[cursor..]);

        // A replacement can join surrounding bytes into another registered
        // mask, and the conventional marker can itself be a mask. Fall back
        // to a whole-line marker (or an empty line) rather than leak either.
        if matcher.find(&output).is_some() {
            if matcher.find(MASK_REPLACEMENT).is_none() {
                return Ok(MASK_REPLACEMENT.to_vec());
            }
            return Ok(Vec::new());
        }
        Ok(output)
    }

    /// Returns whether an evaluated value contains any registered secret.
    ///
    /// This is used to fail closed before a terminal output can enter ordinary
    /// result persistence. The value itself is never retained by the masker.
    pub(crate) fn contains_secret(&mut self, value: &str) -> Result<bool, ExecutorAdapterError> {
        if value.is_empty() || self.masks.is_empty() {
            return Ok(false);
        }
        Ok(self.matcher()?.find(value.as_bytes()).is_some())
    }

    #[cfg(test)]
    #[allow(
        dead_code,
        reason = "used by the external source-level regression harness"
    )]
    pub(crate) const fn exposure_class(&self) -> SecretExposureClass {
        self.exposure
    }

    pub(crate) const fn job_secret_exposure(&self) -> JobSecretExposure {
        match self.exposure {
            SecretExposureClass::Secretless => JobSecretExposure::Secretless,
            SecretExposureClass::CapabilityOnly => JobSecretExposure::CapabilityOnly,
            SecretExposureClass::ReadableSecret => JobSecretExposure::ReadableSecret,
        }
    }

    fn matcher(&mut self) -> Result<&AhoCorasick, ExecutorAdapterError> {
        if self.matcher.is_none() {
            let matcher = AhoCorasick::builder()
                .kind(Some(AhoCorasickKind::ContiguousNFA))
                .match_kind(MatchKind::LeftmostLongest)
                .build(self.masks.iter().map(Vec::as_slice))
                .map_err(|_| resource_exhausted())?;
            self.matcher = Some(matcher);
            #[cfg(test)]
            {
                self.matcher_builds += 1;
            }
        }
        Ok(self.matcher.as_ref().expect("mask matcher initialized"))
    }

    #[cfg(test)]
    #[allow(
        dead_code,
        reason = "used by the external source-level regression harness"
    )]
    pub(crate) const fn matcher_builds(&self) -> usize {
        self.matcher_builds
    }
}

impl fmt::Debug for SecretMasker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("SecretMasker");
        debug
            .field("mask_count", &self.masks.len())
            .field("aggregate_bytes", &self.aggregate_bytes)
            .field("matcher_built", &self.matcher.is_some())
            .field("exposure", &self.exposure);
        #[cfg(test)]
        debug.field("matcher_builds", &self.matcher_builds);
        debug.finish()
    }
}

pub(crate) struct ParsedOutput {
    lines: Vec<ParsedOutputLine>,
}

#[cfg(test)]
#[allow(
    dead_code,
    reason = "used by the external source-level regression harness"
)]
impl ParsedOutput {
    pub(crate) fn output_lines(&self) -> Vec<(LogChannel, bool, String)> {
        self.lines
            .iter()
            .filter_map(|line| match &line.parsed {
                WorkflowLine::Output(output) => {
                    Some((line.channel, line.newline, output.as_str().to_owned()))
                }
                WorkflowLine::Command(_) => None,
            })
            .collect()
    }
}

struct ParsedOutputLine {
    channel: LogChannel,
    newline: bool,
    parsed: WorkflowLine,
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn parse_output(
    records: &[ExecutionOutputRecord],
    limits: WorkflowCommandLimits,
    policy: WorkflowCommandPolicy,
    masker: &mut SecretMasker,
) -> Result<ParsedOutput, ExecutorAdapterError> {
    parse_output_with_cancellation(records, limits, policy, masker, &|| false)
}

pub(crate) fn parse_output_with_cancellation(
    records: &[ExecutionOutputRecord],
    limits: WorkflowCommandLimits,
    policy: WorkflowCommandPolicy,
    masker: &mut SecretMasker,
    cancellation: &dyn Fn() -> bool,
) -> Result<ParsedOutput, ExecutorAdapterError> {
    let mut session = GithubWorkflowCommandSession::new(limits, policy);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut parsed = Vec::new();
    for record in records {
        require_not_cancelled(cancellation)?;
        let (buffer, channel) = match record.stream() {
            ExecutionOutputStream::Stdout => (&mut stdout, LogChannel::Stdout),
            ExecutionOutputStream::Stderr => (&mut stderr, LogChannel::Stderr),
        };
        if record.is_end_of_stream() {
            if !buffer.is_empty() {
                require_not_cancelled(cancellation)?;
                parse_line(buffer, false, channel, &mut session, masker, &mut parsed)?;
                require_not_cancelled(cancellation)?;
                buffer.clear();
            }
            continue;
        }
        buffer.extend_from_slice(record.bytes());
        parse_complete_lines(
            buffer,
            channel,
            &mut session,
            masker,
            &mut parsed,
            cancellation,
        )?;
        if buffer.len() > limits.maximum_line_bytes() {
            return Err(ExecutorAdapterError::new(
                ExecutorAdapterErrorKind::InvalidJob,
            ));
        }
    }
    require_not_cancelled(cancellation)?;
    Ok(ParsedOutput { lines: parsed })
}

pub(crate) fn process_output(
    parsed: ParsedOutput,
    group_id: &LogGroupId,
    masker: &mut SecretMasker,
    events: &Arc<dyn ExecutionEvents>,
    annotations: &mut Vec<Annotation>,
    cancellation: &dyn Fn() -> bool,
) -> Result<(), ExecutorAdapterError> {
    for line in parsed.lines {
        require_not_cancelled(cancellation)?;
        match line.parsed {
            WorkflowLine::Output(output) => {
                emit_line_with_cancellation(
                    output.as_str().as_bytes(),
                    line.newline,
                    group_id,
                    line.channel,
                    masker,
                    events,
                    Some(cancellation),
                )?;
            }
            WorkflowLine::Command(command) => match command {
                WorkflowCommandEvent::Annotation(annotation) => {
                    emit_line_with_cancellation(
                        annotation.message().as_bytes(),
                        true,
                        group_id,
                        line.channel,
                        masker,
                        events,
                        Some(cancellation),
                    )?;
                    annotations.push(annotation);
                }
                WorkflowCommandEvent::BeginGroup(group) => {
                    emit_line_with_cancellation(
                        group.title().as_bytes(),
                        true,
                        group_id,
                        line.channel,
                        masker,
                        events,
                        Some(cancellation),
                    )?;
                }
                WorkflowCommandEvent::RegisterMask(_)
                | WorkflowCommandEvent::Debug(_)
                | WorkflowCommandEvent::EndGroup
                | WorkflowCommandEvent::StopCommands(_)
                | WorkflowCommandEvent::ResumeCommands
                | WorkflowCommandEvent::Matcher(_)
                | WorkflowCommandEvent::EchoChanged(_)
                | WorkflowCommandEvent::Notice(_) => {}
            },
        }
        require_not_cancelled(cancellation)?;
    }
    Ok(())
}

fn require_not_cancelled(cancellation: &dyn Fn() -> bool) -> Result<(), ExecutorAdapterError> {
    if cancellation() {
        Err(ExecutorAdapterError::new(
            ExecutorAdapterErrorKind::Cancelled,
        ))
    } else {
        Ok(())
    }
}

fn parse_complete_lines(
    buffer: &mut Vec<u8>,
    channel: LogChannel,
    processor: &mut dyn WorkflowCommandProcessor,
    masker: &mut SecretMasker,
    parsed: &mut Vec<ParsedOutputLine>,
    cancellation: &dyn Fn() -> bool,
) -> Result<(), ExecutorAdapterError> {
    let mut consumed = 0;
    while let Some(relative) = buffer[consumed..].iter().position(|byte| *byte == b'\n') {
        require_not_cancelled(cancellation)?;
        let newline = consumed + relative;
        parse_line(
            &buffer[consumed..newline],
            true,
            channel,
            processor,
            masker,
            parsed,
        )?;
        require_not_cancelled(cancellation)?;
        consumed = newline + 1;
    }
    if consumed != 0 {
        buffer.drain(..consumed);
    }
    Ok(())
}

fn parse_line(
    mut content: &[u8],
    newline: bool,
    channel: LogChannel,
    processor: &mut dyn WorkflowCommandProcessor,
    masker: &mut SecretMasker,
    parsed: &mut Vec<ParsedOutputLine>,
) -> Result<(), ExecutorAdapterError> {
    if newline && content.last() == Some(&b'\r') {
        content = &content[..content.len() - 1];
    }
    let line = processor
        .process_line(content)
        .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))?;
    register_dynamic_masks(&line, masker)?;
    parsed.push(ParsedOutputLine {
        channel,
        newline,
        parsed: line,
    });
    Ok(())
}

fn register_dynamic_masks(
    line: &WorkflowLine,
    masker: &mut SecretMasker,
) -> Result<(), ExecutorAdapterError> {
    let WorkflowLine::Command(command) = line else {
        return Ok(());
    };
    match command {
        WorkflowCommandEvent::RegisterMask(registration) => {
            for mask in registration.masks() {
                masker.register(mask.expose_secret())?;
            }
        }
        WorkflowCommandEvent::StopCommands(stopped) => {
            if let Some(mask) = stopped.token_mask() {
                masker.register(mask.expose_secret())?;
            }
        }
        WorkflowCommandEvent::Annotation(_)
        | WorkflowCommandEvent::BeginGroup(_)
        | WorkflowCommandEvent::Debug(_)
        | WorkflowCommandEvent::EchoChanged(_)
        | WorkflowCommandEvent::EndGroup
        | WorkflowCommandEvent::Matcher(_)
        | WorkflowCommandEvent::Notice(_)
        | WorkflowCommandEvent::ResumeCommands => {}
    }
    Ok(())
}

fn emit_synthetic(
    value: &str,
    group_id: &LogGroupId,
    channel: LogChannel,
    masker: &mut SecretMasker,
    events: &Arc<dyn ExecutionEvents>,
) -> Result<(), ExecutorAdapterError> {
    emit_line(value.as_bytes(), true, group_id, channel, masker, events)
}

pub(crate) fn emit_system(
    value: &str,
    masker: &mut SecretMasker,
    events: &Arc<dyn ExecutionEvents>,
) -> Result<(), ExecutorAdapterError> {
    let group_id = LogGroupId::new(DIAGNOSTICS_LOG_GROUP_ID)
        .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
    emit_synthetic(value, &group_id, LogChannel::System, masker, events)
}

pub(crate) fn emit_system_for_group(
    value: &str,
    group_id: &LogGroupId,
    masker: &mut SecretMasker,
    events: &Arc<dyn ExecutionEvents>,
) -> Result<(), ExecutorAdapterError> {
    emit_synthetic(value, group_id, LogChannel::System, masker, events)
}

fn emit_line(
    content: &[u8],
    newline: bool,
    group_id: &LogGroupId,
    channel: LogChannel,
    masker: &mut SecretMasker,
    events: &Arc<dyn ExecutionEvents>,
) -> Result<(), ExecutorAdapterError> {
    emit_line_with_cancellation(content, newline, group_id, channel, masker, events, None)
}

fn emit_line_with_cancellation(
    content: &[u8],
    newline: bool,
    group_id: &LogGroupId,
    channel: LogChannel,
    masker: &mut SecretMasker,
    events: &Arc<dyn ExecutionEvents>,
    cancellation: Option<&dyn Fn() -> bool>,
) -> Result<(), ExecutorAdapterError> {
    if cancellation.is_some_and(|check| check()) {
        return Err(ExecutorAdapterError::new(
            ExecutorAdapterErrorKind::Cancelled,
        ));
    }
    let mut payload = masker.mask(content)?;
    if newline {
        payload.push(b'\n');
    }
    if payload.is_empty() {
        return Ok(());
    }
    for chunk in payload.chunks(MAX_LOG_FRAME_BYTES) {
        if cancellation.is_some_and(|check| check()) {
            return Err(ExecutorAdapterError::new(
                ExecutorAdapterErrorKind::Cancelled,
            ));
        }
        let emitted = events
            .emit_log(LogEvent::new(group_id.clone(), channel, chunk.to_vec()))
            .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal));
        if cancellation.is_some_and(|check| check()) {
            return Err(ExecutorAdapterError::new(
                ExecutorAdapterErrorKind::Cancelled,
            ));
        }
        emitted?;
    }
    Ok(())
}

const fn resource_exhausted() -> ExecutorAdapterError {
    ExecutorAdapterError::new(ExecutorAdapterErrorKind::ResourceExhausted)
}

#[cfg(test)]
mod cancellation_tests {
    use std::cell::Cell;

    use super::*;

    #[test]
    fn registered_mask_count_limit_has_exact_boundaries() {
        assert_eq!(mask_count_rejection(MAX_MASKS - 1), None);
        assert_eq!(mask_count_rejection(MAX_MASKS), None);
        assert_eq!(
            mask_count_rejection(MAX_MASKS + 1),
            Some(MaskLimitRejection::Count)
        );
    }

    #[test]
    fn registered_mask_byte_limit_has_exact_boundaries() {
        assert_eq!(mask_aggregate_bytes_rejection(MAX_MASK_BYTES - 1), None);
        assert_eq!(mask_aggregate_bytes_rejection(MAX_MASK_BYTES), None);
        assert_eq!(
            mask_aggregate_bytes_rejection(MAX_MASK_BYTES + 1),
            Some(MaskLimitRejection::AggregateBytes)
        );
    }

    #[test]
    fn parsing_stops_before_the_next_line_and_mask_after_cancellation() {
        let records = [ExecutionOutputRecord::data(
            ExecutionOutputStream::Stdout,
            b"::add-mask::first-secret\n::add-mask::second-secret\n".to_vec(),
        )
        .expect("bounded output record")];
        let checks = Cell::new(0_usize);
        let cancellation = || {
            let observed = checks.get();
            checks.set(observed + 1);
            observed >= 2
        };
        let mut masker = SecretMasker::new();

        let error = parse_output_with_cancellation(
            &records,
            WorkflowCommandLimits::default(),
            WorkflowCommandPolicy::new(false),
            &mut masker,
            &cancellation,
        )
        .err()
        .expect("the cancellation boundary stops parsing");

        let _ = error;
        assert!(masker.contains_secret("first-secret").expect("first mask"));
        assert!(
            !masker
                .contains_secret("second-secret")
                .expect("second mask remains absent")
        );
    }
}
