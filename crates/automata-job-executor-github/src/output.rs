use std::{collections::BTreeSet, fmt, sync::Arc};

use automata_core::{LogChannel, MAX_LOG_FRAME_BYTES};
use automata_github_runtime::{
    LegacyStepMutation, WorkflowCommandEvent, WorkflowCommandProcessor, WorkflowLine,
};
use automata_runner_runtime::{ExecutionEvents, LogEvent};

use crate::{ExecutorAdapterError, error::ExecutorAdapterErrorKind};

const MAX_INITIAL_MASKS: usize = 65_536;
const MAX_INITIAL_MASK_BYTES: usize = 16 * 1_024 * 1_024;

pub(crate) struct SecretMasker {
    masks: BTreeSet<Vec<u8>>,
    aggregate_bytes: usize,
}

impl SecretMasker {
    pub(crate) const fn new() -> Self {
        Self {
            masks: BTreeSet::new(),
            aggregate_bytes: 0,
        }
    }

    pub(crate) fn register(&mut self, value: &str) -> Result<(), ExecutorAdapterError> {
        if value.is_empty() {
            return Ok(());
        }
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
        if self.masks.len() >= MAX_INITIAL_MASKS || aggregate > MAX_INITIAL_MASK_BYTES {
            return Err(resource_exhausted());
        }
        self.aggregate_bytes = aggregate;
        self.masks.insert(value.to_vec());
        Ok(())
    }

    pub(crate) fn mask(&self, source: &[u8]) -> Vec<u8> {
        let mut result = source.to_vec();
        let mut masks = self.masks.iter().collect::<Vec<_>>();
        masks.sort_by_key(|mask| std::cmp::Reverse(mask.len()));
        for mask in masks {
            result = replace_all(&result, mask, b"***");
        }
        result
    }
}

impl fmt::Debug for SecretMasker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretMasker")
            .field("mask_count", &self.masks.len())
            .field("aggregate_bytes", &self.aggregate_bytes)
            .finish()
    }
}

pub(crate) fn process_output(
    bytes: &[u8],
    channel: LogChannel,
    processor: &mut dyn WorkflowCommandProcessor,
    masker: &mut SecretMasker,
    events: &Arc<dyn ExecutionEvents>,
    legacy: &mut Vec<LegacyStepMutation>,
) -> Result<(), ExecutorAdapterError> {
    for line in lines(bytes) {
        let parsed = processor
            .process_line(line.content)
            .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))?;
        match parsed {
            WorkflowLine::Output(output) => {
                emit_line(
                    output.as_str().as_bytes(),
                    line.newline,
                    channel,
                    masker,
                    events,
                )?;
            }
            WorkflowLine::Command(command) => match command {
                WorkflowCommandEvent::RegisterMask(registration) => {
                    for mask in registration.masks() {
                        masker.register(mask.expose_secret())?;
                    }
                }
                WorkflowCommandEvent::LegacyMutation(mutation) => legacy.push(mutation),
                WorkflowCommandEvent::Annotation(annotation) => {
                    emit_synthetic(annotation.message(), channel, masker, events)?;
                }
                WorkflowCommandEvent::BeginGroup(group) => {
                    emit_synthetic(group.title(), channel, masker, events)?;
                }
                WorkflowCommandEvent::Debug(_)
                | WorkflowCommandEvent::EndGroup
                | WorkflowCommandEvent::StopCommands(_)
                | WorkflowCommandEvent::ResumeCommands
                | WorkflowCommandEvent::Matcher(_)
                | WorkflowCommandEvent::EchoChanged(_)
                | WorkflowCommandEvent::Notice(_) => {}
            },
        }
    }
    Ok(())
}

fn emit_synthetic(
    value: &str,
    channel: LogChannel,
    masker: &SecretMasker,
    events: &Arc<dyn ExecutionEvents>,
) -> Result<(), ExecutorAdapterError> {
    emit_line(value.as_bytes(), true, channel, masker, events)
}

pub(crate) fn emit_system(
    value: &str,
    masker: &SecretMasker,
    events: &Arc<dyn ExecutionEvents>,
) -> Result<(), ExecutorAdapterError> {
    emit_synthetic(value, LogChannel::System, masker, events)
}

fn emit_line(
    content: &[u8],
    newline: bool,
    channel: LogChannel,
    masker: &SecretMasker,
    events: &Arc<dyn ExecutionEvents>,
) -> Result<(), ExecutorAdapterError> {
    let mut payload = masker.mask(content);
    if newline {
        payload.push(b'\n');
    }
    if payload.is_empty() {
        return Ok(());
    }
    for chunk in payload.chunks(MAX_LOG_FRAME_BYTES) {
        events
            .emit_log(LogEvent::new(channel, chunk.to_vec()))
            .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
    }
    Ok(())
}

struct Line<'a> {
    content: &'a [u8],
    newline: bool,
}

fn lines(mut bytes: &[u8]) -> Vec<Line<'_>> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        if let Some(index) = bytes.iter().position(|byte| *byte == b'\n') {
            let mut content = &bytes[..index];
            if content.last() == Some(&b'\r') {
                content = &content[..content.len() - 1];
            }
            result.push(Line {
                content,
                newline: true,
            });
            bytes = &bytes[index + 1..];
        } else {
            result.push(Line {
                content: bytes,
                newline: false,
            });
            break;
        }
    }
    result
}

fn replace_all(source: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() || source.len() < needle.len() {
        return source.to_vec();
    }
    let mut output = Vec::with_capacity(source.len());
    let mut cursor = 0;
    while cursor < source.len() {
        if source[cursor..].starts_with(needle) {
            output.extend_from_slice(replacement);
            cursor += needle.len();
        } else {
            output.push(source[cursor]);
            cursor += 1;
        }
    }
    output
}

const fn resource_exhausted() -> ExecutorAdapterError {
    ExecutorAdapterError::new(ExecutorAdapterErrorKind::ResourceExhausted)
}
