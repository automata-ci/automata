//! Complete local validation for decoded wire messages.

use std::collections::BTreeMap;

use automata_ci_core::{
    ActionReference, Architecture, AttemptId, CapabilityValidationError, ContainerSpec,
    JobIrEnvelope, JobIrVersion, JobIrVersionRange, JobResult, JobResultValidationError,
    JobValidationError, LeaseError, LeaseGuard, LogValidationError, MountSource, OperatingSystem,
    OperationId, RunValueTemplates, RunnerRequirements, RunnerSessionId, SemanticStep, ValueSource,
};
use thiserror::Error;

use super::{
    ErrorMessage, LogBatch, ProtocolLimits, RunnerSlotOrdinal, RunnerToServer, ServerToRunner,
};
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
        RunnerToServer::LeaseRequest(request) => request.validate(),
        RunnerToServer::LeaseResponse(response) => response.header().validate_request(),
        RunnerToServer::Heartbeat(heartbeat) => heartbeat.header().validate_request(),
        RunnerToServer::JobState(update) => update.header().validate_request(),
        RunnerToServer::JobResult(message) => {
            message.header().validate_request()?;
            validate_job_result(message.result(), limits)
        }
        RunnerToServer::LogBatch(batch) => {
            batch.header().validate_request()?;
            validate_log_batch(batch, limits)
        }
        RunnerToServer::CommandAck(acknowledgement) => {
            acknowledgement.header().validate_request()?;
            if acknowledgement
                .command_cursor()
                .acknowledged_through()
                .is_none()
            {
                return Err(MessageValidationError::EmptyCommandAcknowledgement);
            }
            Ok(())
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
            rejection.validate()?;
            validate_control_text("handshake rejection message", rejection.message(), limits)
        }
        ServerToRunner::LeaseOffer(offer) => {
            offer.header().validate()?;
            offer.lease().validate()?;
            validate_job(offer.job(), limits)?;
            offer
                .runtime_authorities()
                .ok_or(MessageValidationError::MissingRuntimeAuthorities)?
                .validate_for(offer.job(), offer.lease())?;
            Ok(())
        }
        ServerToRunner::LeaseRenewal(renewal) => renewal.header().validate_reply(),
        ServerToRunner::CancelJob(cancel) => {
            cancel.header().validate()?;
            validate_control_text("cancellation reason", cancel.reason(), limits)
        }
        ServerToRunner::LogAck(acknowledgement) => {
            acknowledgement.header().validate_reply()?;
            acknowledgement.ack().validate()?;
            Ok(())
        }
        ServerToRunner::OperationAck(acknowledgement) => acknowledgement.header().validate_reply(),
        ServerToRunner::NoWork(no_work) => {
            no_work.header().validate_reply()?;
            if no_work.retry_after_millis() == 0 {
                return Err(MessageValidationError::ZeroValue("retry_after_millis"));
            }
            Ok(())
        }
        ServerToRunner::Error(error) => validate_error(error, limits),
    }
}

/// Validates a standalone durable `JobIR` envelope with transport resource limits.
///
/// # Errors
///
/// Returns a typed domain or resource-limit error before the envelope is stored
/// or sent independently of a lease offer.
pub fn validate_job_ir_envelope(
    envelope: &JobIrEnvelope,
    limits: &ProtocolLimits,
) -> Result<(), MessageValidationError> {
    validate_job(envelope, limits)
}

fn validate_capabilities(
    capabilities: &automata_ci_core::RunnerCapabilities,
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
        (
            "environment profiles",
            capabilities.environment_profiles().len(),
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
    for profile in capabilities.environment_profiles() {
        validate_nonempty_text("environment profile ID", profile.id().as_str(), limits)?;
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
        ("workflow name", envelope.execution().workflow_name()),
        ("Git ref", envelope.execution().git_ref()),
        ("workspace", envelope.execution().workspace()),
        (
            "event object key",
            envelope.execution().event().object_key(),
        ),
        (
            "event media type",
            envelope.execution().event().media_type(),
        ),
    ] {
        validate_nonempty_text(field, value, limits)?;
    }
    if let Some(actor) = envelope.execution().actor() {
        validate_nonempty_text("actor", actor, limits)?;
    }
    let runtime_context = envelope.execution().runtime_context();
    validate_nonempty_text(
        "runtime context object key",
        runtime_context.object_key(),
        limits,
    )?;
    validate_nonempty_text(
        "runtime context media type",
        runtime_context.media_type(),
        limits,
    )?;

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
    validate_nonempty_text(
        "logical job key",
        job.instance_identity().logical_job_key(),
        limits,
    )?;
    validate_collection(
        "job output definitions",
        job.output_definitions().len(),
        limits.max_collection_items(),
    )?;
    if let Some(grants) = job.permission_request().grants() {
        validate_collection(
            "job permission grants",
            grants.len(),
            limits.max_collection_items(),
        )?;
        for grant in grants {
            validate_nonempty_text("job permission name", grant.name(), limits)?;
        }
    }
    for output in job.output_definitions() {
        validate_nonempty_text("job output name", output.name(), limits)?;
        validate_value_template("job output value", output.value(), limits)?;
    }
    if let Some(directory) = job.working_directory_template() {
        validate_value_template("job working directory", directory, limits)?;
    }
    if let Some(container) = job.container() {
        validate_container("job container", container, limits)?;
    }
    for (service_name, service) in job.services() {
        validate_nonempty_text("service name", service_name, limits)?;
        validate_container("service container", service, limits)?;
    }
    for step in job.steps() {
        validate_step(step, limits)?;
    }
    Ok(())
}

fn validate_step(
    step: &automata_ci_core::StepIr,
    limits: &ProtocolLimits,
) -> Result<(), MessageValidationError> {
    validate_nonempty_text("step ID", step.id().as_str(), limits)?;
    validate_value_template("step name", step.name_template(), limits)?;
    if let Some(condition) = step.condition() {
        validate_expression_program("step condition", condition, limits)?;
    }
    if let Some(expression) = step.continue_on_error().expression_program() {
        validate_expression_program("step continue-on-error", expression, limits)?;
    }
    if let Some(expression) = step
        .timeout()
        .and_then(|timeout| timeout.value().expression_program())
    {
        validate_expression_program("step timeout", expression, limits)?;
    }
    validate_value_map("step environment", step.environment(), limits)?;
    match step.kind() {
        SemanticStep::Run { values } => validate_run_step(values, limits),
        SemanticStep::Action { reference, inputs } => {
            validate_action_reference(reference, limits)?;
            validate_value_map("action inputs", inputs, limits)
        }
    }
}

fn validate_run_step(
    values: &RunValueTemplates,
    limits: &ProtocolLimits,
) -> Result<(), MessageValidationError> {
    validate_value_template("run command", values.command(), limits)?;
    if let Some(shell) = values.shell().value() {
        validate_value_template("shell", shell, limits)?;
    }
    if let Some(directory) = values.working_directory() {
        validate_value_template("step working directory", directory, limits)?;
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
    if let Some(profile) = requirements.environment_profile() {
        validate_nonempty_text(
            "required environment profile ID",
            profile.id().as_str(),
            limits,
        )?;
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
        if let Some(value) = value.public_value() {
            validate_text("job output value", value, limits)?;
        }
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
    error.header().validate_reply()?;
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
    match value {
        ValueSource::Literal(value) | ValueSource::SecretReference(value) => {
            validate_text(field, value, limits)
        }
        ValueSource::Expression(expression) => {
            validate_expression_program(field, expression, limits)
        }
        ValueSource::Template(template) => validate_value_template(field, template, limits),
    }
}

fn validate_value_template(
    field: &'static str,
    template: &automata_ci_core::ValueTemplate,
    limits: &ProtocolLimits,
) -> Result<(), MessageValidationError> {
    validate_collection(
        "value template segments",
        template.segments().len(),
        limits.max_collection_items(),
    )?;
    for segment in template.segments() {
        if let Some(literal) = segment.literal_value() {
            validate_text(field, literal, limits)?;
        }
        if let Some(expression) = segment.expression_program() {
            validate_expression_program(field, expression, limits)?;
        }
    }
    Ok(())
}

fn validate_expression_program(
    field: &'static str,
    expression: &automata_ci_core::ExpressionProgram,
    limits: &ProtocolLimits,
) -> Result<(), MessageValidationError> {
    validate_text(field, expression.source(), limits)?;
    validate_nonempty_text("expression dialect", expression.dialect().name(), limits)?;
    validate_collection(
        "expression instructions",
        expression.instructions().len(),
        limits.max_collection_items(),
    )?;
    for instruction in expression.instructions() {
        match instruction {
            automata_ci_core::ExpressionInstruction::Literal {
                value: automata_ci_core::ExpressionLiteral::String { value },
            } => validate_text("expression literal", value, limits)?,
            automata_ci_core::ExpressionInstruction::NamedValue { name }
            | automata_ci_core::ExpressionInstruction::Call { name, .. } => {
                validate_nonempty_text("expression identifier", name, limits)?;
            }
            automata_ci_core::ExpressionInstruction::Literal { .. }
            | automata_ci_core::ExpressionInstruction::Wildcard
            | automata_ci_core::ExpressionInstruction::Index
            | automata_ci_core::ExpressionInstruction::Not
            | automata_ci_core::ExpressionInstruction::Compare { .. }
            | automata_ci_core::ExpressionInstruction::Logical { .. } => {}
        }
    }
    Ok(())
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

/// Local validation errors returned before a decoded message is acted upon.
///
/// Variants preserve enough typed context for local policy and diagnostics.
/// Their formatted text is not a public transport error contract: callers
/// crossing a trust boundary must map failures to a stable
/// [`super::RemoteErrorCode`] and a sanitized message.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MessageValidationError {
    /// The message-structure schema is not the one understood by this build.
    #[error("unsupported message schema {received}; this build supports {supported}")]
    UnsupportedMessageSchema {
        /// Schema number decoded from the message.
        received: u16,
        /// Only schema number supported by this build.
        supported: u16,
    },
    /// A post-handshake message does not use a locally supported protocol.
    #[error("unsupported protocol version {received:?}; supported range is {supported:?}")]
    UnsupportedProtocol {
        /// Protocol version decoded from the message.
        received: ProtocolVersion,
        /// Inclusive protocol range supported by this build.
        supported: ProtocolRange,
    },
    /// A nested core-domain value uses an unsupported schema.
    #[error("unsupported core schema {received}; this build supports {supported}")]
    UnsupportedCoreSchema {
        /// Core schema decoded from the message.
        received: u16,
        /// Core schema required by this build.
        supported: u16,
    },
    /// The runner advertised zero executable slots.
    #[error("runner must advertise at least one job slot")]
    NoRunnerSlots,
    /// A handshake response does not answer the initiating hello operation.
    #[error("server hello operation mismatch: expected {expected}, received {received}")]
    HandshakeCorrelationMismatch {
        /// Operation identity of the initiating runner hello.
        expected: OperationId,
        /// Correlation identity carried by the response.
        received: OperationId,
    },
    /// The server selected a protocol outside the runner's advertised range.
    #[error("selected protocol {selected:?} is outside runner range {offered:?}")]
    SelectionOutsideRunnerRange {
        /// Protocol version selected by the server.
        selected: ProtocolVersion,
        /// Inclusive protocol range advertised by the runner.
        offered: ProtocolRange,
    },
    /// A selected or embedded `JobIR` schema is unsupported by this build.
    #[error("unsupported JobIR schema {received:?}; supported range is {supported:?}")]
    UnsupportedJobIr {
        /// `JobIR` schema decoded from the message.
        received: JobIrVersion,
        /// Inclusive `JobIR` schema range supported by this build.
        supported: JobIrVersionRange,
    },
    /// The server selected a `JobIR` schema outside the runner's offer.
    #[error("selected JobIR schema {selected:?} is outside runner range {offered:?}")]
    JobIrSelectionOutsideRunnerRange {
        /// `JobIR` schema selected by the server.
        selected: JobIrVersion,
        /// Inclusive `JobIR` schema range advertised by the runner.
        offered: JobIrVersionRange,
    },
    /// A successful hello carries a zero heartbeat or lease duration.
    #[error("server heartbeat and lease durations must be non-zero")]
    InvalidServerTiming,
    /// A newly opened session incorrectly starts after command sequence zero.
    #[error("a newly opened session must begin before command sequence one")]
    NewSessionHasCommandCursor,
    /// A resumed session identity or cursor contradicts the runner's claim.
    #[error("server resumed-session acknowledgement does not match the runner claim")]
    SessionResumeMismatch,
    /// Orphan-delivery authority was sent without an old-session claim.
    #[error("orphan-recovery authority requires an initiating resume claim")]
    OrphanRecoveryWithoutResume,
    /// Orphan-delivery authority accompanies a rejection that cannot grant it.
    #[error("orphan-recovery authority is invalid for this handshake rejection")]
    UnexpectedOrphanRecoveryAuthorization,
    /// Orphan-delivery authority targets a session other than the claimed one.
    #[error("orphan-recovery session mismatch: expected {expected}, received {received}")]
    OrphanRecoverySessionMismatch {
        /// Old session claimed by the initiating hello.
        expected: RunnerSessionId,
        /// Old session named by the recovery authorization.
        received: RunnerSessionId,
    },
    /// A runner request incorrectly claims to answer another operation.
    #[error("runner request headers must not carry response correlation")]
    UnexpectedResponseCorrelation,
    /// A lease request incorrectly acknowledges its own operation identity.
    #[error("lease request {operation_id} must not acknowledge itself")]
    LeaseRequestSelfAcknowledgement {
        /// Self-referential lease-request operation identity.
        operation_id: OperationId,
    },
    /// A server response omits the request operation it answers.
    #[error("server response headers must carry request correlation")]
    MissingResponseCorrelation,
    /// A response uses a different negotiated protocol than its request.
    #[error("response protocol mismatch: expected {expected:?}, received {received:?}")]
    ResponseProtocolMismatch {
        /// Protocol version carried by the initiating request.
        expected: ProtocolVersion,
        /// Protocol version carried by the response.
        received: ProtocolVersion,
    },
    /// A response belongs to a different authenticated runner session.
    #[error("response session mismatch: expected {expected}, received {received}")]
    ResponseSessionMismatch {
        /// Session identity carried by the initiating request.
        expected: RunnerSessionId,
        /// Session identity carried by the response.
        received: RunnerSessionId,
    },
    /// A response does not correlate to the initiating operation identity.
    #[error("response operation mismatch: expected {expected}, received {received}")]
    ResponseOperationMismatch {
        /// Operation identity of the initiating request.
        expected: OperationId,
        /// Correlation identity carried by the response.
        received: OperationId,
    },
    /// A response or state update names a different execution attempt.
    #[error("attempt correlation mismatch: expected {expected}, received {received}")]
    AttemptCorrelationMismatch {
        /// Attempt identity established by the lease.
        expected: AttemptId,
        /// Attempt identity carried by the related message.
        received: AttemptId,
    },
    /// A lease response names a different stable runner slot than its offer.
    #[error("runner slot correlation mismatch: expected {expected:?}, received {received:?}")]
    SlotCorrelationMismatch {
        /// Slot selected by the lease offer.
        expected: RunnerSlotOrdinal,
        /// Slot claimed by the runner response.
        received: RunnerSlotOrdinal,
    },
    /// A related message carries a different lease identity or fencing token.
    #[error("lease guard correlation mismatch: expected {expected:?}, received {received:?}")]
    LeaseGuardCorrelationMismatch {
        /// Lease guard established by the authoritative message.
        expected: LeaseGuard,
        /// Lease guard supplied by the related message.
        received: LeaseGuard,
    },
    /// A command acknowledgement carries the initial empty cursor.
    #[error("command acknowledgement must advance through at least one command")]
    EmptyCommandAcknowledgement,
    /// A protocol-v4 lease offer omits its protected runtime-authority bundle.
    #[error("protocol v4 lease offers require protected runtime authority")]
    MissingRuntimeAuthorities,
    /// A named scalar whose protocol contract requires a positive value is zero.
    #[error("{0} must be nonzero")]
    ZeroValue(&'static str),
    /// A named text field whose protocol contract requires content is empty.
    #[error("{0} must not be empty")]
    EmptyText(&'static str),
    /// A named collection whose protocol contract requires entries is empty.
    #[error("{0} must contain at least one item")]
    EmptyCollection(&'static str),
    /// A decoded text field exceeds the trusted transport byte budget.
    #[error("{field} has {length} bytes; maximum is {maximum}")]
    TextTooLong {
        /// Stable field classification, never attacker-controlled field text.
        field: &'static str,
        /// UTF-8 byte length observed during validation.
        length: usize,
        /// Configured maximum UTF-8 byte length.
        maximum: usize,
    },
    /// A decoded collection exceeds its trusted item-count budget.
    #[error("{field} has {length} items; maximum is {maximum}")]
    CollectionTooLarge {
        /// Stable collection classification, never attacker-controlled text.
        field: &'static str,
        /// Number of items observed during validation.
        length: usize,
        /// Configured maximum number of items.
        maximum: usize,
    },
    /// One log batch contains frames from different attempts.
    #[error("log batch mixes attempts")]
    MixedLogAttempts,
    /// One log batch contains frames from different output streams.
    #[error("log batch mixes streams")]
    MixedLogStreams,
    /// A log frame follows an end-of-stream marker in the same batch.
    #[error("log batch contains a frame after an end-of-stream marker")]
    LogFrameAfterEndOfStream,
    /// Adjacent log frames do not have exactly contiguous sequence numbers.
    #[error("log sequence after {previous} is {received}, not the next contiguous value")]
    NonContiguousLogSequence {
        /// Sequence of the preceding frame.
        previous: u64,
        /// Non-successor sequence carried by the next frame.
        received: u64,
    },
    /// Summing log-frame payload sizes overflowed the host integer type.
    #[error("log batch payload size overflowed")]
    LogPayloadSizeOverflow,
    /// Aggregate bytes in a log batch exceed the configured batch budget.
    #[error("log batch has {size} payload bytes; maximum is {maximum}")]
    LogBatchPayloadTooLarge {
        /// Aggregate payload bytes observed during validation.
        size: usize,
        /// Configured maximum aggregate payload bytes.
        maximum: usize,
    },
    /// A protocol range contains zero or has inverted endpoints.
    #[error(transparent)]
    ProtocolRange(#[from] ProtocolRangeError),
    /// Runner capabilities violate core-domain invariants.
    #[error(transparent)]
    Capabilities(#[from] CapabilityValidationError),
    /// The immutable job envelope violates core-domain invariants.
    #[error(transparent)]
    Job(#[from] JobValidationError),
    /// A terminal job result violates core-domain invariants.
    #[error(transparent)]
    JobResult(#[from] JobResultValidationError),
    /// A lease violates core-domain identity, time, or fence invariants.
    #[error(transparent)]
    Lease(#[from] LeaseError),
    /// A log frame or acknowledgement violates core-domain invariants.
    #[error(transparent)]
    Log(#[from] LogValidationError),
    /// A runtime-authority bundle violates schema, bounds, or execution binding.
    #[error(transparent)]
    RuntimeAuthority(#[from] super::RuntimeAuthorityError),
}
