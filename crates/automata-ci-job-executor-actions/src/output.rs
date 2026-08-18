use std::{
    collections::BTreeSet,
    fmt,
    sync::{Arc, Mutex},
};

use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};
use automata_ci_actions_runtime::{
    ActionsWorkflowCommandSession, Annotation, WorkflowCommandEvent, WorkflowCommandLimits,
    WorkflowCommandPolicy, WorkflowCommandProcessor, WorkflowLine,
};
use automata_ci_auth::output_policy::SecretExposureClass;
use automata_ci_core::{JobSecretExposure, LogChannel, LogGroupId, MAX_LOG_FRAME_BYTES};
use automata_ci_execution::{
    ExecutionOutputRecord, ExecutionOutputSink, ExecutionOutputSinkError, ExecutionOutputStream,
};
use automata_ci_runner_runtime::{ExecutionEvents, LogEvent};
use zeroize::Zeroize as _;

use crate::{ExecutorAdapterError, error::ExecutorAdapterErrorKind};

const MAX_MASKS: usize = 4_096;
const MAX_MASK_BYTES: usize = 1_048_576;
const MASK_REPLACEMENT: &[u8] = b"***";
pub(crate) const DIAGNOSTICS_LOG_GROUP_ID: &str = "job/diagnostics";

pub(crate) struct PhaseOutputSink {
    state: Mutex<PhaseOutputState>,
}

struct PhaseOutputState {
    session: ActionsWorkflowCommandSession,
    maximum_line_bytes: usize,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    masker: SecretMasker,
    group_id: LogGroupId,
    events: Arc<dyn ExecutionEvents>,
    cancellation: Arc<dyn Fn() -> bool + Send + Sync>,
    annotations: Vec<Annotation>,
    failure: Option<ExecutorAdapterError>,
    finished: bool,
}

pub(crate) struct PhaseOutputCompletion {
    pub(crate) masker: SecretMasker,
    pub(crate) annotations: Vec<Annotation>,
    pub(crate) failure: Option<ExecutorAdapterError>,
}

impl PhaseOutputSink {
    pub(crate) fn new(
        limits: WorkflowCommandLimits,
        policy: WorkflowCommandPolicy,
        masker: SecretMasker,
        group_id: LogGroupId,
        events: Arc<dyn ExecutionEvents>,
        cancellation: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Self {
        let maximum_line_bytes = limits.maximum_line_bytes();
        Self {
            state: Mutex::new(PhaseOutputState {
                session: ActionsWorkflowCommandSession::new(limits, policy),
                maximum_line_bytes,
                stdout: Vec::new(),
                stderr: Vec::new(),
                masker,
                group_id,
                events,
                cancellation,
                annotations: Vec::new(),
                failure: None,
                finished: false,
            }),
        }
    }

    pub(crate) fn finish(&self) -> PhaseOutputCompletion {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.finished
            && state.failure.is_none()
            && let Err(error) = state.finish_streams()
        {
            state.failure = Some(error);
        }
        state.finished = true;
        PhaseOutputCompletion {
            masker: std::mem::replace(&mut state.masker, SecretMasker::new()),
            annotations: std::mem::take(&mut state.annotations),
            failure: state.failure,
        }
    }
}

impl fmt::Debug for PhaseOutputSink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PhaseOutputSink")
            .finish_non_exhaustive()
    }
}

impl ExecutionOutputSink for PhaseOutputSink {
    fn observe(&self, record: &ExecutionOutputRecord) -> Result<(), ExecutionOutputSinkError> {
        let mut state = self.state.lock().map_err(|_| ExecutionOutputSinkError)?;
        if state.finished || state.failure.is_some() {
            return Err(ExecutionOutputSinkError);
        }
        if let Err(error) = state.observe(record) {
            state.failure = Some(error);
            return Err(ExecutionOutputSinkError);
        }
        Ok(())
    }
}

impl PhaseOutputState {
    fn observe(&mut self, record: &ExecutionOutputRecord) -> Result<(), ExecutorAdapterError> {
        self.ensure_active()?;
        let channel = match record.stream() {
            ExecutionOutputStream::Stdout => LogChannel::Stdout,
            ExecutionOutputStream::Stderr => LogChannel::Stderr,
        };
        if record.is_end_of_stream() {
            return self.finish_stream(record.stream(), channel);
        }
        let buffer = match record.stream() {
            ExecutionOutputStream::Stdout => &mut self.stdout,
            ExecutionOutputStream::Stderr => &mut self.stderr,
        };
        buffer.extend_from_slice(record.bytes());
        self.process_complete_lines(record.stream(), channel)?;
        let buffer = match record.stream() {
            ExecutionOutputStream::Stdout => &self.stdout,
            ExecutionOutputStream::Stderr => &self.stderr,
        };
        if buffer.len() > self.maximum_line_bytes {
            return Err(ExecutorAdapterError::new(
                ExecutorAdapterErrorKind::InvalidJob,
            ));
        }
        Ok(())
    }

    fn process_complete_lines(
        &mut self,
        stream: ExecutionOutputStream,
        channel: LogChannel,
    ) -> Result<(), ExecutorAdapterError> {
        loop {
            self.ensure_active()?;
            let newline = match stream {
                ExecutionOutputStream::Stdout => self.stdout.iter().position(|byte| *byte == b'\n'),
                ExecutionOutputStream::Stderr => self.stderr.iter().position(|byte| *byte == b'\n'),
            };
            let Some(newline) = newline else {
                return Ok(());
            };
            let mut line = match stream {
                ExecutionOutputStream::Stdout => self.stdout.drain(..=newline).collect::<Vec<_>>(),
                ExecutionOutputStream::Stderr => self.stderr.drain(..=newline).collect::<Vec<_>>(),
            };
            line.pop();
            self.process_line(&line, true, channel)?;
        }
    }

    fn finish_stream(
        &mut self,
        stream: ExecutionOutputStream,
        channel: LogChannel,
    ) -> Result<(), ExecutorAdapterError> {
        let line = match stream {
            ExecutionOutputStream::Stdout => std::mem::take(&mut self.stdout),
            ExecutionOutputStream::Stderr => std::mem::take(&mut self.stderr),
        };
        if !line.is_empty() {
            self.process_line(&line, false, channel)?;
        }
        Ok(())
    }

    fn finish_streams(&mut self) -> Result<(), ExecutorAdapterError> {
        self.finish_stream(ExecutionOutputStream::Stdout, LogChannel::Stdout)?;
        self.finish_stream(ExecutionOutputStream::Stderr, LogChannel::Stderr)
    }

    fn process_line(
        &mut self,
        mut content: &[u8],
        newline: bool,
        channel: LogChannel,
    ) -> Result<(), ExecutorAdapterError> {
        self.ensure_active()?;
        if newline && content.last() == Some(&b'\r') {
            content = &content[..content.len() - 1];
        }
        let line = self
            .session
            .process_line(content)
            .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))?;
        register_dynamic_masks(&line, &mut self.masker)?;
        let result = match line {
            WorkflowLine::Output(output) => emit_line(
                output.as_str().as_bytes(),
                newline,
                &self.group_id,
                channel,
                &mut self.masker,
                &self.events,
            ),
            WorkflowLine::Command(WorkflowCommandEvent::Annotation(annotation)) => {
                emit_line(
                    annotation.message().as_bytes(),
                    true,
                    &self.group_id,
                    channel,
                    &mut self.masker,
                    &self.events,
                )?;
                self.ensure_active()?;
                self.annotations.push(annotation);
                Ok(())
            }
            WorkflowLine::Command(WorkflowCommandEvent::BeginGroup(group)) => emit_line(
                group.title().as_bytes(),
                true,
                &self.group_id,
                channel,
                &mut self.masker,
                &self.events,
            ),
            WorkflowLine::Command(_) => Ok(()),
        };
        result?;
        self.ensure_active()
    }

    fn ensure_active(&self) -> Result<(), ExecutorAdapterError> {
        if (self.cancellation)() {
            Err(ExecutorAdapterError::new(
                ExecutorAdapterErrorKind::Cancelled,
            ))
        } else {
            Ok(())
        }
    }
}

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
    let mut payload = masker.mask(content)?;
    if newline {
        payload.push(b'\n');
    }
    if payload.is_empty() {
        return Ok(());
    }
    for chunk in payload.chunks(MAX_LOG_FRAME_BYTES) {
        events
            .emit_log(LogEvent::new(group_id.clone(), channel, chunk.to_vec()))
            .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
    }
    Ok(())
}

const fn resource_exhausted() -> ExecutorAdapterError {
    ExecutorAdapterError::new(ExecutorAdapterErrorKind::ResourceExhausted)
}

#[cfg(test)]
mod cancellation_tests {
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
}
