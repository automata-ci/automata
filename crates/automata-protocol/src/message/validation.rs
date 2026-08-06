//! Complete local validation for decoded wire messages.

use std::collections::BTreeMap;

use automata_core::{
    ActionReference, Architecture, CapabilityValidationError, ContainerSpec, JobIrEnvelope,
    JobResult, JobResultValidationError, JobValidationError, LeaseError, LogValidationError,
    MountSource, OperatingSystem, OperationId, RunnerRequirements, SemanticStep, ShellSpec,
    ValueSource,
};
use thiserror::Error;

use super::{ErrorMessage, LogBatch, ProtocolLimits, RunnerToServer, ServerToRunner};
use crate::{MESSAGE_SCHEMA_VERSION, ProtocolRange, ProtocolRangeError, ProtocolVersion};

const MAX_CONTROL_TEXT_BYTES: usize = 4 * 1024;

pub(super) fn validate_schema(received: u16) -> Result<(), MessageValidationError> {
    if received == MESSAGE_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(MessageValidationError::UnsupportedMessageSchema {
            received,
            supported: MESSAGE_SCHEMA_VERSION,
        })
    }
}

pub(super) fn validate_runner_message(
    message: &RunnerToServer,
    limits: &ProtocolLimits,
) -> Result<(), MessageValidationError> {
    match message {
        RunnerToServer::Hello(hello) => {
            hello.validate()?;
            validate_capabilities(hello.runner(), limits)
        }
        RunnerToServer::LeaseRequest(request) => {
            request.header().validate()?;
            if request.available_slots() == 0 {
                return Err(MessageValidationError::ZeroValue("available_slots"));
            }
            Ok(())
        }
        RunnerToServer::LeaseResponse(response) => response.header().validate(),
        RunnerToServer::Heartbeat(heartbeat) => heartbeat.header().validate(),
        RunnerToServer::JobState(update) => update.header().validate(),
        RunnerToServer::JobResult(message) => {
            message.header().validate()?;
            validate_job_result(message.result(), limits)
        }
        RunnerToServer::LogBatch(batch) => {
            batch.header().validate()?;
            validate_log_batch(batch, limits)
        }
    }
}

pub(super) fn validate_server_message(
    message: &ServerToRunner,
    limits: &ProtocolLimits,
) -> Result<(), MessageValidationError> {
    match message {
        ServerToRunner::Hello(hello) => hello.validate(),
        ServerToRunner::HandshakeRejected(rejection) => {
            validate_schema(rejection.message_schema_version())?;
            rejection.supported_protocol().validate()?;
            validate_control_text("handshake rejection message", rejection.message(), limits)
        }
        ServerToRunner::LeaseOffer(offer) => {
            offer.header().validate()?;
            offer.lease().validate()?;
            validate_job(offer.job(), limits)
        }
        ServerToRunner::LeaseRenewal(renewal) => renewal.header().validate(),
        ServerToRunner::CancelJob(cancel) => {
            cancel.header().validate()?;
            validate_control_text("cancellation reason", cancel.reason(), limits)
        }
        ServerToRunner::LogAck(acknowledgement) => {
            acknowledgement.header().validate()?;
            acknowledgement.ack().validate()?;
            Ok(())
        }
        ServerToRunner::NoWork(no_work) => {
            no_work.header().validate()?;
            if no_work.retry_after_millis() == 0 {
                return Err(MessageValidationError::ZeroValue("retry_after_millis"));
            }
            Ok(())
        }
        ServerToRunner::Error(error) => validate_error(error, limits),
    }
}

fn validate_capabilities(
    capabilities: &automata_core::RunnerCapabilities,
    limits: &ProtocolLimits,
) -> Result<(), MessageValidationError> {
    capabilities.validate()?;
    for (field, length) in [
        ("runner labels", capabilities.labels().len()),
        ("runner groups", capabilities.groups().len()),
        ("runner features", capabilities.features().len()),
        ("sandbox features", capabilities.sandbox().features().len()),
        (
            "container features",
            capabilities.containers().features().len(),
        ),
    ] {
        validate_collection(field, length, limits.max_collection_items())?;
    }
    for label in capabilities.labels() {
        validate_nonempty_text("runner label", label.as_str(), limits)?;
    }
    for group in capabilities.groups() {
        validate_nonempty_text("runner group", group.as_str(), limits)?;
    }
    for feature in capabilities.features() {
        validate_nonempty_text("runner feature", feature.as_str(), limits)?;
    }
    for feature in capabilities.sandbox().features() {
        validate_nonempty_text("sandbox feature", feature.as_str(), limits)?;
    }
    for feature in capabilities.containers().features() {
        validate_nonempty_text("container feature", feature.as_str(), limits)?;
    }
    match capabilities.platform().operating_system() {
        OperatingSystem::Other(name) => {
            validate_nonempty_text("operating system", name, limits)?;
        }
        OperatingSystem::Linux | OperatingSystem::Windows | OperatingSystem::Macos => {}
    }
    match capabilities.platform().architecture() {
        Architecture::Other(name) => validate_nonempty_text("architecture", name, limits)?,
        Architecture::X86_64 | Architecture::Aarch64 => {}
    }
    Ok(())
}

fn validate_job(
    envelope: &JobIrEnvelope,
    limits: &ProtocolLimits,
) -> Result<(), MessageValidationError> {
    envelope.validate()?;
    let source = envelope.source();
    for (field, value) in [
        ("source provider", source.provider()),
        ("source repository", source.repository()),
        ("source revision", source.revision()),
        ("workflow path", source.workflow_path()),
        ("event name", source.event_name()),
        ("job name", envelope.job().name()),
    ] {
        validate_nonempty_text(field, value, limits)?;
    }

    let job = envelope.job();
    validate_requirements(job.requirements(), limits)?;
    validate_collection(
        "job steps",
        job.steps().len(),
        limits.max_collection_items(),
    )?;
    validate_value_map("job environment", job.environment(), limits)?;
    validate_collection(
        "job services",
        job.services().len(),
        limits.max_collection_items(),
    )?;
    if let Some(condition) = job.condition() {
        validate_text("job condition", condition.as_str(), limits)?;
    }
    if let Some(directory) = job.working_directory() {
        validate_text("job working directory", directory, limits)?;
    }
    if let Some(container) = job.container() {
        validate_container("job container", container, limits)?;
    }
    for (service_name, service) in job.services() {
        validate_nonempty_text("service name", service_name, limits)?;
        validate_container("service container", service, limits)?;
    }
    for step in job.steps() {
        validate_nonempty_text("step ID", step.id().as_str(), limits)?;
        validate_text("step name", step.name(), limits)?;
        if let Some(condition) = step.condition() {
            validate_text("step condition", condition.as_str(), limits)?;
        }
        validate_value_map("step environment", step.environment(), limits)?;
        match step.kind() {
            SemanticStep::Run {
                command,
                shell,
                working_directory,
            } => {
                validate_nonempty_text("run command", command, limits)?;
                match shell {
                    ShellSpec::Named(value) | ShellSpec::CommandTemplate(value) => {
                        validate_nonempty_text("shell", value, limits)?;
                    }
                    ShellSpec::Default => {}
                }
                if let Some(directory) = working_directory {
                    validate_text("step working directory", directory, limits)?;
                }
            }
            SemanticStep::Action { reference, inputs } => {
                validate_action_reference(reference, limits)?;
                validate_value_map("action inputs", inputs, limits)?;
            }
        }
    }
    Ok(())
}

fn validate_requirements(
    requirements: &RunnerRequirements,
    limits: &ProtocolLimits,
) -> Result<(), MessageValidationError> {
    for (field, length) in [
        ("required runner labels", requirements.labels().len()),
        (
            "eligible runner groups",
            requirements.eligible_groups().len(),
        ),
        (
            "required sandbox features",
            requirements.sandbox_features().len(),
        ),
        (
            "required container features",
            requirements.container_features().len(),
        ),
        ("required runner features", requirements.features().len()),
    ] {
        validate_collection(field, length, limits.max_collection_items())?;
    }
    for label in requirements.labels() {
        validate_nonempty_text("required runner label", label.as_str(), limits)?;
    }
    for group in requirements.eligible_groups() {
        validate_nonempty_text("eligible runner group", group.as_str(), limits)?;
    }
    for feature in requirements.sandbox_features() {
        validate_nonempty_text("required sandbox feature", feature.as_str(), limits)?;
    }
    for feature in requirements.container_features() {
        validate_nonempty_text("required container feature", feature.as_str(), limits)?;
    }
    for feature in requirements.features() {
        validate_nonempty_text("required runner feature", feature.as_str(), limits)?;
    }
    if let Some(OperatingSystem::Other(name)) = requirements.operating_system() {
        validate_nonempty_text("required operating system", name, limits)?;
    }
    if let Some(Architecture::Other(name)) = requirements.architecture() {
        validate_nonempty_text("required architecture", name, limits)?;
    }
    Ok(())
}

fn validate_action_reference(
    reference: &ActionReference,
    limits: &ProtocolLimits,
) -> Result<(), MessageValidationError> {
    match reference {
        ActionReference::Repository {
            repository,
            revision,
            subpath,
        } => {
            validate_nonempty_text("action repository", repository, limits)?;
            validate_nonempty_text("action revision", revision, limits)?;
            if let Some(path) = subpath {
                validate_text("action subpath", path, limits)?;
            }
        }
        ActionReference::Local { path } => {
            validate_nonempty_text("local action path", path, limits)?;
        }
        ActionReference::Container { image } => {
            validate_nonempty_text("container action image", image, limits)?;
        }
    }
    Ok(())
}

fn validate_container(
    field: &'static str,
    container: &ContainerSpec,
    limits: &ProtocolLimits,
) -> Result<(), MessageValidationError> {
    validate_nonempty_text(field, container.image(), limits)?;
    validate_value_map("container environment", container.environment(), limits)?;
    for (collection, length) in [
        ("container ports", container.ports().len()),
        ("container volumes", container.volumes().len()),
        ("container options", container.options().len()),
    ] {
        validate_collection(collection, length, limits.max_collection_items())?;
    }
    if let Some(credentials) = container.credentials() {
        validate_value("container username", credentials.username(), limits)?;
        validate_value("container password", credentials.password(), limits)?;
    }
    for volume in container.volumes() {
        validate_nonempty_text("volume target", volume.target(), limits)?;
        let source = match volume.source() {
            MountSource::WorkspaceRelative(value)
            | MountSource::TemporaryVolume(value)
            | MountSource::HostPath(value) => value,
        };
        validate_nonempty_text("volume source", source, limits)?;
    }
    for option in container.options() {
        validate_nonempty_text("container option", option, limits)?;
    }
    Ok(())
}

fn validate_job_result(
    result: &JobResult,
    limits: &ProtocolLimits,
) -> Result<(), MessageValidationError> {
    result.validate()?;
    validate_collection(
        "job outputs",
        result.outputs().len(),
        limits.max_collection_items(),
    )?;
    validate_collection(
        "step results",
        result.steps().len(),
        limits.max_collection_items(),
    )?;
    for (name, value) in result.outputs() {
        validate_nonempty_text("job output name", name, limits)?;
        validate_text("job output value", value, limits)?;
    }
    for step in result.steps() {
        validate_nonempty_text("step-result ID", step.step_id().as_str(), limits)?;
    }
    Ok(())
}

fn validate_log_batch(
    batch: &LogBatch,
    limits: &ProtocolLimits,
) -> Result<(), MessageValidationError> {
    if batch.frames().is_empty() {
        return Err(MessageValidationError::EmptyCollection("log frames"));
    }
    validate_collection(
        "log frames",
        batch.frames().len(),
        limits.max_log_frames_per_batch(),
    )?;
    let attempt_id = batch.frames()[0].attempt_id();
    let stream_id = batch.frames()[0].stream_id();
    let mut payload_bytes = 0_usize;
    for (index, frame) in batch.frames().iter().enumerate() {
        frame.validate()?;
        if frame.attempt_id() != attempt_id {
            return Err(MessageValidationError::MixedLogAttempts);
        }
        if frame.stream_id() != stream_id {
            return Err(MessageValidationError::MixedLogStreams);
        }
        if index > 0 {
            let previous = &batch.frames()[index - 1];
            if previous.is_end_of_stream() {
                return Err(MessageValidationError::LogFrameAfterEndOfStream);
            }
            if previous.sequence().get().checked_add(1) != Some(frame.sequence().get()) {
                return Err(MessageValidationError::NonContiguousLogSequence {
                    previous: previous.sequence().get(),
                    received: frame.sequence().get(),
                });
            }
        }
        payload_bytes = payload_bytes
            .checked_add(frame.payload().len())
            .ok_or(MessageValidationError::LogPayloadSizeOverflow)?;
        if payload_bytes > limits.max_log_payload_bytes_per_batch() {
            return Err(MessageValidationError::LogBatchPayloadTooLarge {
                size: payload_bytes,
                maximum: limits.max_log_payload_bytes_per_batch(),
            });
        }
    }
    Ok(())
}

fn validate_error(
    error: &ErrorMessage,
    limits: &ProtocolLimits,
) -> Result<(), MessageValidationError> {
    error.header().validate()?;
    validate_control_text("error message", error.message(), limits)?;
    validate_collection(
        "error details",
        error.details().len(),
        limits.max_collection_items(),
    )?;
    for (key, value) in error.details() {
        validate_control_text("error detail key", key, limits)?;
        validate_control_value("error detail value", value, limits)?;
    }
    Ok(())
}

fn validate_value_map(
    field: &'static str,
    values: &BTreeMap<String, ValueSource>,
    limits: &ProtocolLimits,
) -> Result<(), MessageValidationError> {
    validate_collection(field, values.len(), limits.max_collection_items())?;
    for (key, value) in values {
        validate_nonempty_text("map key", key, limits)?;
        validate_value(field, value, limits)?;
    }
    Ok(())
}

fn validate_value(
    field: &'static str,
    value: &ValueSource,
    limits: &ProtocolLimits,
) -> Result<(), MessageValidationError> {
    let text = match value {
        ValueSource::Literal(value) | ValueSource::SecretReference(value) => value,
        ValueSource::Expression(expression) => expression.as_str(),
    };
    validate_text(field, text, limits)
}

fn validate_control_text(
    field: &'static str,
    value: &str,
    limits: &ProtocolLimits,
) -> Result<(), MessageValidationError> {
    validate_nonempty_text(field, value, limits)?;
    let maximum = limits.max_text_bytes().min(MAX_CONTROL_TEXT_BYTES);
    if value.len() > maximum {
        return Err(MessageValidationError::TextTooLong {
            field,
            length: value.len(),
            maximum,
        });
    }
    Ok(())
}

fn validate_control_value(
    field: &'static str,
    value: &str,
    limits: &ProtocolLimits,
) -> Result<(), MessageValidationError> {
    let maximum = limits.max_text_bytes().min(MAX_CONTROL_TEXT_BYTES);
    if value.len() > maximum {
        return Err(MessageValidationError::TextTooLong {
            field,
            length: value.len(),
            maximum,
        });
    }
    Ok(())
}

fn validate_nonempty_text(
    field: &'static str,
    value: &str,
    limits: &ProtocolLimits,
) -> Result<(), MessageValidationError> {
    if value.is_empty() {
        return Err(MessageValidationError::EmptyText(field));
    }
    validate_text(field, value, limits)
}

fn validate_text(
    field: &'static str,
    value: &str,
    limits: &ProtocolLimits,
) -> Result<(), MessageValidationError> {
    if value.len() > limits.max_text_bytes() {
        return Err(MessageValidationError::TextTooLong {
            field,
            length: value.len(),
            maximum: limits.max_text_bytes(),
        });
    }
    Ok(())
}

fn validate_collection(
    field: &'static str,
    length: usize,
    maximum: usize,
) -> Result<(), MessageValidationError> {
    if length > maximum {
        Err(MessageValidationError::CollectionTooLarge {
            field,
            length,
            maximum,
        })
    } else {
        Ok(())
    }
}

/// Local validation errors before a message is acted upon.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MessageValidationError {
    #[error("unsupported message schema {received}; this build supports {supported}")]
    UnsupportedMessageSchema { received: u16, supported: u16 },
    #[error("unsupported protocol version {received:?}; supported range is {supported:?}")]
    UnsupportedProtocol {
        received: ProtocolVersion,
        supported: ProtocolRange,
    },
    #[error("unsupported core schema {received}; this build supports {supported}")]
    UnsupportedCoreSchema { received: u16, supported: u16 },
    #[error("runner must advertise at least one job slot")]
    NoRunnerSlots,
    #[error("server hello operation mismatch: expected {expected}, received {received}")]
    HandshakeCorrelationMismatch {
        expected: OperationId,
        received: OperationId,
    },
    #[error("selected protocol {selected:?} is outside runner range {offered:?}")]
    SelectionOutsideRunnerRange {
        selected: ProtocolVersion,
        offered: ProtocolRange,
    },
    #[error("server heartbeat and lease durations must be non-zero")]
    InvalidServerTiming,
    #[error("{0} must be nonzero")]
    ZeroValue(&'static str),
    #[error("{0} must not be empty")]
    EmptyText(&'static str),
    #[error("{0} must contain at least one item")]
    EmptyCollection(&'static str),
    #[error("{field} has {length} bytes; maximum is {maximum}")]
    TextTooLong {
        field: &'static str,
        length: usize,
        maximum: usize,
    },
    #[error("{field} has {length} items; maximum is {maximum}")]
    CollectionTooLarge {
        field: &'static str,
        length: usize,
        maximum: usize,
    },
    #[error("log batch mixes attempts")]
    MixedLogAttempts,
    #[error("log batch mixes streams")]
    MixedLogStreams,
    #[error("log batch contains a frame after an end-of-stream marker")]
    LogFrameAfterEndOfStream,
    #[error("log sequence after {previous} is {received}, not the next contiguous value")]
    NonContiguousLogSequence { previous: u64, received: u64 },
    #[error("log batch payload size overflowed")]
    LogPayloadSizeOverflow,
    #[error("log batch has {size} payload bytes; maximum is {maximum}")]
    LogBatchPayloadTooLarge { size: usize, maximum: usize },
    #[error(transparent)]
    ProtocolRange(#[from] ProtocolRangeError),
    #[error(transparent)]
    Capabilities(#[from] CapabilityValidationError),
    #[error(transparent)]
    Job(#[from] JobValidationError),
    #[error(transparent)]
    JobResult(#[from] JobResultValidationError),
    #[error(transparent)]
    Lease(#[from] LeaseError),
    #[error(transparent)]
    Log(#[from] LogValidationError),
}
