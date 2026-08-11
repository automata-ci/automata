//! Validated domain-to-protobuf conversion.

use std::collections::BTreeMap;

use automata_ci_core as core;
use automata_ci_protocol as protocol;
use uuid::Uuid;
use zeroize::Zeroize as _;

use crate::{EncodeError, wire};

/// Validates and canonically encodes one runner-to-server message.
///
/// # Errors
///
/// Returns [`EncodeError`] when domain validation fails or the deterministic
/// protobuf representation exceeds `limits.max_frame_bytes()`.
pub fn encode_runner_frame(
    message: &protocol::RunnerToServer,
    limits: &protocol::ProtocolLimits,
) -> Result<Vec<u8>, EncodeError> {
    message
        .validate(limits)
        .map_err(EncodeError::InvalidMessage)?;
    encode_message(&runner_frame(message), limits)
}

/// Validates and canonically encodes one server-to-runner message.
///
/// # Errors
///
/// Returns [`EncodeError`] when domain validation fails or the deterministic
/// protobuf representation exceeds `limits.max_frame_bytes()`.
pub fn encode_server_frame(
    message: &protocol::ServerToRunner,
    limits: &protocol::ProtocolLimits,
) -> Result<Vec<u8>, EncodeError> {
    message
        .validate(limits)
        .map_err(EncodeError::InvalidMessage)?;
    let mut frame = server_frame(message);
    let encoded = encode_message(&frame, limits);
    zeroize_server_authorities(&mut frame);
    encoded
}

/// Validates and deterministically encodes one standalone `JobIR` envelope.
///
/// This is the storage/object-transfer representation used when `JobIR` is not
/// nested in a lease offer. It has the same conversion and resource limits as
/// the nested representation.
///
/// # Errors
///
/// Returns [`EncodeError`] when domain validation fails or the encoded envelope
/// exceeds `limits.max_frame_bytes()`.
pub fn encode_job_ir(
    envelope: &core::JobIrEnvelope,
    limits: &protocol::ProtocolLimits,
) -> Result<Vec<u8>, EncodeError> {
    protocol::validate_job_ir_envelope(envelope, limits).map_err(EncodeError::InvalidMessage)?;
    encode_message(&job_ir_envelope(envelope), limits)
}

/// Validates and deterministically encodes one immutable job runtime context.
///
/// The protobuf representation is a canonical flat tree, so decoding an
/// untrusted context never recurses through attacker-controlled protobuf
/// messages. Secret bindings contain only opaque authorized identifiers.
/// Prerequisite outputs retain their explicit public or secret-derived
/// classification; callers must preserve that classification at every later
/// expression and storage boundary.
///
/// # Errors
///
/// Returns [`EncodeError`] when the context is invalid or its canonical bytes
/// exceed `limits.max_frame_bytes()`.
pub fn encode_job_runtime_context(
    context: &core::JobRuntimeContext,
    limits: &protocol::ProtocolLimits,
) -> Result<Vec<u8>, EncodeError> {
    context
        .validate()
        .map_err(EncodeError::InvalidRuntimeContext)?;
    let wire = job_runtime_context(context).map_err(EncodeError::InvalidRuntimeContext)?;
    encode_message(&wire, limits)
}

/// Validates and canonically encodes one protected runtime-authority object.
///
/// The returned plaintext must be handed directly to a mandatory
/// [`automata_ci_runner_spool::ContentProtector`](https://docs.rs/automata-ci-runner-spool/latest/automata_ci_runner_spool/trait.ContentProtector.html)
/// boundary by the caller; this adapter keeps no credential copy after encoding.
///
/// # Errors
///
/// Returns [`EncodeError`] for an invalid execution binding or size overflow.
pub fn encode_runtime_authorities(
    authorities: &protocol::JobRuntimeAuthorities,
    job: &core::JobIrEnvelope,
    lease: &core::Lease,
    limits: &protocol::ProtocolLimits,
) -> Result<Vec<u8>, EncodeError> {
    authorities
        .validate_for(job, lease)
        .map_err(protocol::MessageValidationError::from)
        .map_err(EncodeError::InvalidMessage)?;
    let mut wire = runtime_authorities(authorities);
    let encoded = encode_message(&wire, limits);
    zeroize_runtime_authorities(&mut wire);
    encoded
}

fn encode_message<M: prost::Message>(
    message: &M,
    limits: &protocol::ProtocolLimits,
) -> Result<Vec<u8>, EncodeError> {
    let size = message.encoded_len();
    if size > limits.max_frame_bytes() {
        return Err(EncodeError::FrameTooLarge {
            size,
            maximum: limits.max_frame_bytes(),
        });
    }
    Ok(message.encode_to_vec())
}

fn runner_frame(message: &protocol::RunnerToServer) -> wire::RunnerFrame {
    use protocol::RunnerToServer as Domain;
    use wire::runner_frame::Payload;

    let payload = match message {
        Domain::Hello(value) => Payload::Hello(runner_hello(value)),
        Domain::LeaseRequest(value) => Payload::LeaseRequest(lease_request(value)),
        Domain::LeaseResponse(value) => Payload::LeaseResponse(lease_response(value)),
        Domain::Heartbeat(value) => Payload::Heartbeat(lease_heartbeat(value)),
        Domain::JobState(value) => Payload::JobState(job_state_update(value)),
        Domain::JobResult(value) => Payload::JobResult(job_result_message(value)),
        Domain::LogBatch(value) => Payload::LogBatch(log_batch(value)),
        Domain::CommandAck(value) => Payload::CommandAck(command_ack(*value)),
    };
    wire::RunnerFrame {
        payload: Some(payload),
    }
}

fn server_frame(message: &protocol::ServerToRunner) -> wire::ServerFrame {
    use protocol::ServerToRunner as Domain;
    use wire::server_frame::Payload;

    let payload = match message {
        Domain::Hello(value) => Payload::Hello(server_hello(value)),
        Domain::HandshakeRejected(value) => Payload::HandshakeRejected(handshake_rejected(value)),
        Domain::LeaseOffer(value) => Payload::LeaseOffer(lease_offer(value)),
        Domain::LeaseRenewal(value) => Payload::LeaseRenewal(lease_renewal(value)),
        Domain::CancelJob(value) => Payload::CancelJob(cancel_job(value)),
        Domain::LogAck(value) => Payload::LogAck(log_ack_message(value)),
        Domain::OperationAck(value) => Payload::OperationAck(operation_ack(*value)),
        Domain::NoWork(value) => Payload::NoWork(no_work(value)),
        Domain::Error(value) => Payload::Error(error_message(value)),
    };
    wire::ServerFrame {
        payload: Some(payload),
    }
}

fn runner_hello(value: &protocol::RunnerHello) -> wire::RunnerHello {
    wire::RunnerHello {
        message_schema_version: u32::from(value.message_schema_version()),
        operation_id: uuid_bytes(value.operation_id().as_uuid()),
        supported_protocol: Some(protocol_range(value.supported_protocol())),
        supported_job_ir: Some(job_ir_version_range(value.supported_job_ir())),
        runner: Some(runner_capabilities(value.runner())),
        resume: value.resume().map(session_resume),
        sent_at_unix_millis: value.sent_at().get(),
    }
}

fn server_hello(value: &protocol::ServerHello) -> wire::ServerHello {
    wire::ServerHello {
        message_schema_version: u32::from(value.message_schema_version()),
        operation_id: uuid_bytes(value.operation_id().as_uuid()),
        in_reply_to: uuid_bytes(value.in_reply_to().as_uuid()),
        session: Some(negotiated_session(value.session())),
        timing: Some(server_timing(value.timing())),
    }
}

fn negotiated_session(value: protocol::NegotiatedSession) -> wire::NegotiatedSession {
    wire::NegotiatedSession {
        selected_protocol: u32::from(value.selected_protocol().get()),
        selected_job_ir: u32::from(value.selected_job_ir().get()),
        session_id: uuid_bytes(value.session_id().as_uuid()),
        session_disposition: match value.session_disposition() {
            protocol::SessionDisposition::Opened => wire::SessionDisposition::Opened as i32,
            protocol::SessionDisposition::Resumed => wire::SessionDisposition::Resumed as i32,
        },
        command_cursor: Some(command_cursor(value.command_cursor())),
    }
}

const fn server_timing(value: protocol::ServerTiming) -> wire::ServerTiming {
    wire::ServerTiming {
        server_time_unix_millis: value.server_time().get(),
        heartbeat_interval_millis: value.heartbeat_interval_millis(),
        lease_duration_millis: value.lease_duration_millis(),
    }
}

fn handshake_rejected(value: &protocol::HandshakeRejected) -> wire::HandshakeRejected {
    wire::HandshakeRejected {
        message_schema_version: u32::from(value.message_schema_version()),
        operation_id: uuid_bytes(value.operation_id().as_uuid()),
        in_reply_to: uuid_bytes(value.in_reply_to().as_uuid()),
        code: handshake_error_code(value.code()),
        supported_protocol: Some(protocol_range(value.supported_protocol())),
        message: value.message().to_owned(),
        orphan_recovery: value.orphan_recovery().map(session_orphan_authorization),
    }
}

fn session_orphan_authorization(
    value: protocol::SessionOrphanAuthorization,
) -> wire::SessionOrphanAuthorization {
    wire::SessionOrphanAuthorization {
        session_id: uuid_bytes(value.session_id().as_uuid()),
        permissions: Some(orphan_delivery_permissions(value.permissions())),
    }
}

const fn orphan_delivery_permissions(
    value: protocol::OrphanDeliveryPermissions,
) -> wire::OrphanDeliveryPermissions {
    wire::OrphanDeliveryPermissions {
        terminal_result: value.terminal_result(),
        log_delivery: value.log_delivery(),
        lease_rejection: value.lease_rejection(),
    }
}

const fn handshake_error_code(value: protocol::HandshakeErrorCode) -> i32 {
    match value {
        protocol::HandshakeErrorCode::InvalidHello => wire::HandshakeErrorCode::InvalidHello as i32,
        protocol::HandshakeErrorCode::UnsupportedProtocol => {
            wire::HandshakeErrorCode::UnsupportedProtocol as i32
        }
        protocol::HandshakeErrorCode::UnsupportedJobIr => {
            wire::HandshakeErrorCode::UnsupportedJobIr as i32
        }
        protocol::HandshakeErrorCode::Unauthenticated => {
            wire::HandshakeErrorCode::Unauthenticated as i32
        }
        protocol::HandshakeErrorCode::Unauthorized => wire::HandshakeErrorCode::Unauthorized as i32,
        protocol::HandshakeErrorCode::SessionNotResumable => {
            wire::HandshakeErrorCode::SessionNotResumable as i32
        }
    }
}

const fn protocol_range(value: protocol::ProtocolRange) -> wire::ProtocolRange {
    wire::ProtocolRange {
        minimum: value.min().get() as u32,
        maximum: value.max().get() as u32,
    }
}

const fn job_ir_version_range(value: core::JobIrVersionRange) -> wire::JobIrVersionRange {
    wire::JobIrVersionRange {
        minimum: value.minimum().get() as u32,
        maximum: value.maximum().get() as u32,
    }
}

fn session_resume(value: protocol::SessionResume) -> wire::SessionResume {
    wire::SessionResume {
        session_id: uuid_bytes(value.session_id().as_uuid()),
        command_cursor: Some(command_cursor(value.command_cursor())),
    }
}

const fn command_cursor(value: protocol::CommandCursor) -> wire::CommandCursor {
    wire::CommandCursor {
        acknowledged_through: match value.acknowledged_through() {
            Some(sequence) => Some(sequence.get()),
            None => None,
        },
    }
}

fn message_header(value: protocol::MessageHeader) -> wire::MessageHeader {
    wire::MessageHeader {
        message_schema_version: u32::from(value.message_schema_version()),
        protocol_version: u32::from(value.protocol_version().get()),
        session_id: uuid_bytes(value.session_id().as_uuid()),
        operation_id: uuid_bytes(value.operation_id().as_uuid()),
        in_reply_to: value
            .in_reply_to()
            .map(|operation| uuid_bytes(operation.as_uuid())),
    }
}

fn server_command_header(value: protocol::ServerCommandHeader) -> wire::ServerCommandHeader {
    wire::ServerCommandHeader {
        message_schema_version: u32::from(value.message_schema_version()),
        protocol_version: u32::from(value.protocol_version().get()),
        session_id: uuid_bytes(value.session_id().as_uuid()),
        operation_id: uuid_bytes(value.operation_id().as_uuid()),
        sequence: value.sequence().get(),
    }
}

fn runner_capabilities(value: &core::RunnerCapabilities) -> wire::RunnerCapabilities {
    wire::RunnerCapabilities {
        schema_version: u32::from(value.schema_version()),
        runner_id: uuid_bytes(value.runner_id().as_uuid()),
        platform: Some(runner_platform(value.platform())),
        labels: value
            .labels()
            .iter()
            .map(|item| item.as_str().to_owned())
            .collect(),
        groups: value
            .groups()
            .iter()
            .map(|item| item.as_str().to_owned())
            .collect(),
        max_parallel_jobs: u32::from(value.max_parallel_jobs()),
        resources_per_job: Some(resource_capacity(value.resources_per_job())),
        sandbox: Some(sandbox_capabilities(value.sandbox())),
        containers: Some(container_capabilities(value.containers())),
        features: value
            .features()
            .iter()
            .map(|item| item.as_str().to_owned())
            .collect(),
        environment_profiles: value
            .environment_profiles()
            .iter()
            .map(environment_profile)
            .collect(),
    }
}

fn environment_profile(value: &core::EnvironmentProfile) -> wire::EnvironmentProfile {
    wire::EnvironmentProfile {
        id: value.id().as_str().to_owned(),
        sha256_digest: value.digest().as_bytes().to_vec(),
    }
}

fn runner_platform(value: &core::RunnerPlatform) -> wire::RunnerPlatform {
    wire::RunnerPlatform {
        operating_system: Some(operating_system(value.operating_system())),
        architecture: Some(architecture(value.architecture())),
    }
}

fn operating_system(value: &core::OperatingSystem) -> wire::OperatingSystem {
    use wire::operating_system::Value;
    let value = match value {
        core::OperatingSystem::Linux => Value::Linux(wire::Unit {}),
        core::OperatingSystem::Windows => Value::Windows(wire::Unit {}),
        core::OperatingSystem::Macos => Value::Macos(wire::Unit {}),
        core::OperatingSystem::Other(name) => Value::Other(name.clone()),
    };
    wire::OperatingSystem { value: Some(value) }
}

fn architecture(value: &core::Architecture) -> wire::Architecture {
    use wire::architecture::Value;
    let value = match value {
        core::Architecture::X86_64 => Value::X8664(wire::Unit {}),
        core::Architecture::Aarch64 => Value::Aarch64(wire::Unit {}),
        core::Architecture::Other(name) => Value::Other(name.clone()),
    };
    wire::Architecture { value: Some(value) }
}

const fn resource_capacity(value: core::ResourceCapacity) -> wire::ResourceCapacity {
    wire::ResourceCapacity {
        cpu_millis: value.cpu_millis(),
        memory_bytes: value.memory_bytes(),
        ephemeral_disk_bytes: value.ephemeral_disk_bytes(),
        gpu_count: value.gpu_count() as u32,
    }
}

fn sandbox_capabilities(value: &core::SandboxCapabilities) -> wire::SandboxCapabilities {
    wire::SandboxCapabilities {
        maximum_isolation: isolation_level(value.maximum_isolation()),
        features: value
            .features()
            .iter()
            .map(|item| item.as_str().to_owned())
            .collect(),
    }
}

fn container_capabilities(value: &core::ContainerCapabilities) -> wire::ContainerCapabilities {
    wire::ContainerCapabilities {
        features: value
            .features()
            .iter()
            .map(|item| item.as_str().to_owned())
            .collect(),
    }
}

const fn isolation_level(value: core::IsolationLevel) -> i32 {
    match value {
        core::IsolationLevel::Process => wire::IsolationLevel::Process as i32,
        core::IsolationLevel::SharedKernel => wire::IsolationLevel::SharedKernel as i32,
        core::IsolationLevel::VirtualMachine => wire::IsolationLevel::VirtualMachine as i32,
    }
}

fn runner_requirements(value: &core::RunnerRequirements) -> wire::RunnerRequirements {
    wire::RunnerRequirements {
        schema_version: u32::from(value.schema_version()),
        labels: value
            .labels()
            .iter()
            .map(|item| item.as_str().to_owned())
            .collect(),
        eligible_groups: value
            .eligible_groups()
            .iter()
            .map(|item| item.as_str().to_owned())
            .collect(),
        operating_system: value.operating_system().map(operating_system),
        architecture: value.architecture().map(architecture),
        minimum_resources: Some(resource_capacity(value.minimum_resources())),
        minimum_isolation: isolation_level(value.minimum_isolation()),
        sandbox_features: value
            .sandbox_features()
            .iter()
            .map(|item| item.as_str().to_owned())
            .collect(),
        container_features: value
            .container_features()
            .iter()
            .map(|item| item.as_str().to_owned())
            .collect(),
        features: value
            .features()
            .iter()
            .map(|item| item.as_str().to_owned())
            .collect(),
        environment_profile: value.environment_profile().map(environment_profile),
        resource_allocation: value.resource_allocation().map(job_resource_allocation),
    }
}

fn job_resource_allocation(value: core::JobResourceAllocation) -> wire::JobResourceAllocation {
    wire::JobResourceAllocation {
        requests: Some(resource_capacity(value.requests())),
        limits: Some(resource_capacity(value.limits())),
    }
}

fn lease_request(value: &protocol::LeaseRequest) -> wire::LeaseRequest {
    wire::LeaseRequest {
        header: Some(message_header(value.header())),
        slot: u32::from(value.slot().get()),
        acknowledges_operation_id: value
            .acknowledges_operation_id()
            .map(|operation_id| uuid_bytes(operation_id.as_uuid())),
    }
}

fn lease_offer(value: &protocol::LeaseOffer) -> wire::LeaseOffer {
    wire::LeaseOffer {
        header: Some(server_command_header(value.header())),
        slot: u32::from(value.slot().get()),
        lease: Some(lease(value.lease())),
        job: Some(job_ir_envelope(value.job())),
        runtime_authorities: value.runtime_authorities().map(runtime_authorities),
        managed_secret_bindings: value
            .managed_secret_bindings()
            .map(managed_secret_binding_overlay),
    }
}

fn managed_secret_binding_overlay(
    value: &protocol::ManagedSecretBindingOverlay,
) -> wire::ManagedSecretBindingOverlay {
    wire::ManagedSecretBindingOverlay {
        schema_version: u32::from(value.schema_version()),
        attempt_id: uuid_bytes(value.attempt_id().as_uuid()),
        lease_id: uuid_bytes(value.lease_id().as_uuid()),
        fencing_token: value.fencing_token().get(),
        bindings: value
            .bindings()
            .iter()
            .map(|entry| wire::ManagedSecretBindingOverlayEntry {
                canonical_name: entry.canonical_name().to_owned(),
                grant_id: entry.binding().binding_id().to_owned(),
                version_id: entry
                    .binding()
                    .version_id()
                    .expect("validated overlay entries have immutable versions")
                    .to_owned(),
            })
            .collect(),
        sha256_digest: value.digest().as_bytes().to_vec(),
    }
}

fn runtime_authorities(value: &protocol::JobRuntimeAuthorities) -> wire::JobRuntimeAuthorities {
    wire::JobRuntimeAuthorities {
        schema_version: u32::from(value.schema_version()),
        authorities: value.as_slice().iter().map(runtime_authority).collect(),
    }
}

fn runtime_authority(value: &protocol::JobRuntimeAuthority) -> wire::JobRuntimeAuthority {
    wire::JobRuntimeAuthority {
        name: value.name().as_str().to_owned(),
        run_id: uuid_bytes(value.run_id().as_uuid()),
        job_id: uuid_bytes(value.job_id().as_uuid()),
        attempt_id: uuid_bytes(value.attempt_id().as_uuid()),
        fencing_token: value.fencing_token().get(),
        endpoint: value.endpoint().as_str().to_owned(),
        credential: value.credential().expose_secret().to_owned(),
        issued_at_unix_millis: value.issued_at().get(),
        expires_at_unix_millis: value.expires_at().get(),
        endpoint_security: match value.endpoint().security() {
            protocol::RuntimeAuthorityEndpointSecurity::Tls => {
                wire::RuntimeAuthorityEndpointSecurity::Tls as i32
            }
            protocol::RuntimeAuthorityEndpointSecurity::LoopbackDevelopment => {
                wire::RuntimeAuthorityEndpointSecurity::LoopbackDevelopment as i32
            }
            protocol::RuntimeAuthorityEndpointSecurity::TrustedPrivateDevelopment => {
                wire::RuntimeAuthorityEndpointSecurity::TrustedPrivateDevelopment as i32
            }
        },
    }
}

fn zeroize_server_authorities(frame: &mut wire::ServerFrame) {
    if let Some(wire::server_frame::Payload::LeaseOffer(offer)) = frame.payload.as_mut()
        && let Some(authorities) = offer.runtime_authorities.as_mut()
    {
        zeroize_runtime_authorities(authorities);
    }
}

fn zeroize_runtime_authorities(authorities: &mut wire::JobRuntimeAuthorities) {
    for authority in &mut authorities.authorities {
        authority.credential.zeroize();
    }
}

fn lease(value: &core::Lease) -> wire::Lease {
    wire::Lease {
        schema_version: u32::from(value.schema_version()),
        lease_id: uuid_bytes(value.lease_id().as_uuid()),
        attempt_id: uuid_bytes(value.attempt_id().as_uuid()),
        runner_id: uuid_bytes(value.runner_id().as_uuid()),
        fencing_token: value.fencing_token().get(),
        issued_at_unix_millis: value.issued_at().get(),
        expires_at_unix_millis: value.expires_at().get(),
    }
}

fn lease_guard(value: core::LeaseGuard) -> wire::LeaseGuard {
    wire::LeaseGuard {
        lease_id: uuid_bytes(value.lease_id().as_uuid()),
        fencing_token: value.fencing_token().get(),
    }
}

fn lease_response(value: &protocol::LeaseResponse) -> wire::LeaseResponse {
    wire::LeaseResponse {
        header: Some(message_header(value.header())),
        attempt_id: uuid_bytes(value.attempt_id().as_uuid()),
        slot: u32::from(value.slot().get()),
        guard: Some(lease_guard(value.guard())),
        disposition: Some(lease_disposition(value.disposition())),
    }
}

const fn lease_disposition(value: &protocol::LeaseDisposition) -> wire::LeaseDisposition {
    use wire::lease_disposition::Value;
    let value = match value {
        protocol::LeaseDisposition::Accepted => Value::Accepted(wire::Unit {}),
        protocol::LeaseDisposition::Rejected(reason) => Value::Rejected(match reason {
            protocol::LeaseRejectionReason::CapacityChanged => {
                wire::LeaseRejectionReason::CapacityChanged as i32
            }
            protocol::LeaseRejectionReason::CapabilityChanged => {
                wire::LeaseRejectionReason::CapabilityChanged as i32
            }
            protocol::LeaseRejectionReason::ShuttingDown => {
                wire::LeaseRejectionReason::ShuttingDown as i32
            }
            protocol::LeaseRejectionReason::InvalidJob => {
                wire::LeaseRejectionReason::InvalidJob as i32
            }
        }),
    };
    wire::LeaseDisposition { value: Some(value) }
}

fn lease_heartbeat(value: &protocol::LeaseHeartbeat) -> wire::LeaseHeartbeat {
    wire::LeaseHeartbeat {
        header: Some(message_header(value.header())),
        attempt_id: uuid_bytes(value.attempt_id().as_uuid()),
        guard: Some(lease_guard(value.guard())),
        lifecycle: job_lifecycle(value.lifecycle()),
        sent_at_unix_millis: value.sent_at().get(),
    }
}

fn lease_renewal(value: &protocol::LeaseRenewal) -> wire::LeaseRenewal {
    wire::LeaseRenewal {
        header: Some(message_header(value.header())),
        attempt_id: uuid_bytes(value.attempt_id().as_uuid()),
        guard: Some(lease_guard(value.guard())),
        expires_at_unix_millis: value.expires_at().get(),
    }
}

fn job_state_update(value: &protocol::JobStateUpdate) -> wire::JobStateUpdate {
    wire::JobStateUpdate {
        header: Some(message_header(value.header())),
        attempt_id: uuid_bytes(value.attempt_id().as_uuid()),
        guard: Some(lease_guard(value.guard())),
        lifecycle: job_lifecycle(value.lifecycle()),
        occurred_at_unix_millis: value.occurred_at().get(),
    }
}

const fn job_lifecycle(value: core::JobLifecycle) -> i32 {
    match value {
        core::JobLifecycle::Queued => wire::JobLifecycle::Queued as i32,
        core::JobLifecycle::Leased => wire::JobLifecycle::Leased as i32,
        core::JobLifecycle::Preparing => wire::JobLifecycle::Preparing as i32,
        core::JobLifecycle::Running => wire::JobLifecycle::Running as i32,
        core::JobLifecycle::Cancelling => wire::JobLifecycle::Cancelling as i32,
        core::JobLifecycle::Finalizing => wire::JobLifecycle::Finalizing as i32,
        core::JobLifecycle::Succeeded => wire::JobLifecycle::Succeeded as i32,
        core::JobLifecycle::Failed => wire::JobLifecycle::Failed as i32,
        core::JobLifecycle::Cancelled => wire::JobLifecycle::Cancelled as i32,
        core::JobLifecycle::TimedOut => wire::JobLifecycle::TimedOut as i32,
        core::JobLifecycle::Skipped => wire::JobLifecycle::Skipped as i32,
        core::JobLifecycle::Lost => wire::JobLifecycle::Lost as i32,
    }
}

fn cancel_job(value: &protocol::CancelJob) -> wire::CancelJob {
    wire::CancelJob {
        header: Some(server_command_header(value.header())),
        attempt_id: uuid_bytes(value.attempt_id().as_uuid()),
        guard: Some(lease_guard(value.guard())),
        reason: value.reason().to_owned(),
        requested_at_unix_millis: value.requested_at().get(),
    }
}

fn job_ir_envelope(value: &core::JobIrEnvelope) -> wire::JobIrEnvelope {
    wire::JobIrEnvelope {
        schema_version: u32::from(value.version().get()),
        workflow_id: uuid_bytes(value.workflow_id().as_uuid()),
        source: Some(job_source(value.source())),
        job: Some(job_ir(value.job())),
        execution: Some(job_execution_context(value.execution())),
    }
}

fn job_source(value: &core::JobSource) -> wire::JobSource {
    wire::JobSource {
        provider: value.provider().to_owned(),
        repository: value.repository().to_owned(),
        revision: value.revision().to_owned(),
        workflow_path: value.workflow_path().to_owned(),
        event_name: value.event_name().to_owned(),
    }
}

fn job_execution_context(value: &core::JobExecutionContext) -> wire::JobExecutionContext {
    wire::JobExecutionContext {
        workflow_name: value.workflow_name().to_owned(),
        git_ref: value.git_ref().to_owned(),
        workspace: value.workspace().to_owned(),
        actor: value.actor().map(str::to_owned),
        run_number: value.run_number(),
        run_attempt: value.run_attempt(),
        event: Some(job_content_reference(value.event())),
        runtime_context: Some(job_content_reference(value.runtime_context())),
        run_id_alias: value.run_id_alias().map(core::RunIdAlias::get),
        triggering_actor: value.triggering_actor().map(str::to_owned),
    }
}

fn job_content_reference(value: &core::JobContentReference) -> wire::JobContentReference {
    wire::JobContentReference {
        object_key: value.object_key().to_owned(),
        sha256: value.digest().as_bytes().to_vec(),
        encoded_size: value.encoded_size(),
        media_type: value.media_type().to_owned(),
    }
}

fn job_runtime_context(
    value: &core::JobRuntimeContext,
) -> Result<wire::JobRuntimeContext, core::RuntimeContextError> {
    let mut nodes = Vec::new();
    let inputs_index = context_value(value.inputs(), &mut nodes)?;
    let vars_index = context_value(value.vars(), &mut nodes)?;
    let matrix_index = context_value(value.matrix(), &mut nodes)?;
    Ok(wire::JobRuntimeContext {
        schema_version: u32::from(value.schema_version()),
        nodes,
        inputs_index,
        vars_index,
        matrix_index,
        strategy: Some(strategy_context(value.strategy())),
        needs: value
            .needs()
            .iter()
            .map(|(key, need)| wire::NeedContextEntry {
                key: key.clone(),
                value: Some(need_context(need)),
            })
            .collect(),
        secrets: value
            .secrets()
            .iter()
            .map(|(key, binding)| wire::SecretBindingEntry {
                key: key.clone(),
                value: Some(secret_binding(binding)),
            })
            .collect(),
    })
}

fn context_value(
    value: &core::ContextValue,
    nodes: &mut Vec<wire::ContextValueNode>,
) -> Result<u32, core::RuntimeContextError> {
    use wire::context_value_node::Value;

    let value = match value {
        core::ContextValue::Null => Value::Null(wire::Unit {}),
        core::ContextValue::Boolean { value } => Value::Boolean(*value),
        core::ContextValue::Number { ieee754_bits } => Value::NumberIeee754Bits(*ieee754_bits),
        core::ContextValue::String { value } => Value::StringValue(value.clone()),
        core::ContextValue::Array { values } => Value::Array(wire::ContextValueArray {
            child_indices: values
                .iter()
                .map(|value| context_value(value, nodes))
                .collect::<Result<Vec<_>, _>>()?,
        }),
        core::ContextValue::Object { values } => Value::Object(wire::ContextValueObject {
            entries: values
                .iter()
                .map(|(key, value)| {
                    Ok(wire::ContextValueEntry {
                        key: key.clone(),
                        value_index: context_value(value, nodes)?,
                    })
                })
                .collect::<Result<Vec<_>, core::RuntimeContextError>>()?,
        }),
    };
    let index =
        u32::try_from(nodes.len()).map_err(|_| core::RuntimeContextError::TooManyValueNodes {
            maximum: core::MAX_CONTEXT_VALUE_NODES,
        })?;
    nodes.push(wire::ContextValueNode { value: Some(value) });
    Ok(index)
}

const fn strategy_context(value: core::StrategyContext) -> wire::StrategyContext {
    wire::StrategyContext {
        fail_fast: value.fail_fast(),
        job_index: value.job_index(),
        job_total: value.job_total(),
        max_parallel: value.max_parallel(),
    }
}

fn need_context(value: &core::NeedContext) -> wire::NeedContext {
    wire::NeedContext {
        result: job_conclusion(value.result()),
        outputs: value
            .outputs()
            .iter()
            .map(|(key, output)| wire::NeedOutputEntry {
                key: key.clone(),
                value: Some(need_output(output)),
            })
            .collect(),
    }
}

fn need_output(value: &core::NeedOutput) -> wire::NeedOutput {
    wire::NeedOutput {
        value: value.expose_value().to_owned(),
        sensitivity: output_sensitivity(value.sensitivity()),
    }
}

const fn output_sensitivity(value: core::OutputSensitivity) -> i32 {
    match value {
        core::OutputSensitivity::Public => wire::OutputSensitivity::Public as i32,
        core::OutputSensitivity::SecretDerived => wire::OutputSensitivity::SecretDerived as i32,
    }
}

fn secret_binding(value: &core::SecretBinding) -> wire::SecretBinding {
    wire::SecretBinding {
        binding_id: value.binding_id().to_owned(),
        version_id: value.version_id().map(str::to_owned),
    }
}

fn job_ir(value: &core::JobIr) -> wire::JobIr {
    wire::JobIr {
        job_id: uuid_bytes(value.job_id().as_uuid()),
        run_id: uuid_bytes(value.run_id().as_uuid()),
        name: value.name().to_owned(),
        requirements: Some(runner_requirements(value.requirements())),
        instance: Some(job_instance_identity(value.instance_identity())),
        continue_on_error: value.continue_on_error(),
        timeout_seconds: value.timeout_seconds(),
        environment: value_entries(value.environment()),
        working_directory: value.working_directory_template().map(value_template),
        container: value.container().map(container_spec),
        services: value
            .services()
            .iter()
            .map(|(key, item)| wire::ContainerEntry {
                key: key.clone(),
                value: Some(container_spec(item)),
            })
            .collect(),
        steps: value.steps().iter().map(step_ir).collect(),
        outputs: value
            .output_definitions()
            .iter()
            .map(job_output_definition)
            .collect(),
        permission_request: Some(job_permission_request(value.permission_request())),
        authority_profile: Some(job_authority_profile(value.authority_profile())),
    }
}

const fn job_authority_profile(value: core::JobAuthorityProfile) -> i32 {
    match value {
        core::JobAuthorityProfile::Standard => wire::JobAuthorityProfile::Standard as i32,
        core::JobAuthorityProfile::CredentialFree => {
            wire::JobAuthorityProfile::CredentialFree as i32
        }
    }
}

fn job_permission_request(value: &core::JobPermissionRequest) -> wire::JobPermissionRequest {
    use wire::job_permission_request::Request;

    let request = match value {
        core::JobPermissionRequest::ProviderDefault => Request::ProviderDefault(wire::Unit {}),
        core::JobPermissionRequest::ReadAll => Request::ReadAll(wire::Unit {}),
        core::JobPermissionRequest::WriteAll => Request::WriteAll(wire::Unit {}),
        core::JobPermissionRequest::Mapping(grants) => {
            Request::Mapping(wire::JobPermissionMapping {
                grants: grants.iter().map(job_permission_grant).collect(),
            })
        }
    };
    wire::JobPermissionRequest {
        request: Some(request),
    }
}

fn job_permission_grant(value: &core::JobPermissionGrant) -> wire::JobPermissionGrant {
    wire::JobPermissionGrant {
        name: value.name().to_owned(),
        level: permission_level(value.level()),
    }
}

const fn permission_level(value: core::PermissionLevel) -> i32 {
    match value {
        core::PermissionLevel::Read => wire::PermissionLevel::Read as i32,
        core::PermissionLevel::Write => wire::PermissionLevel::Write as i32,
        core::PermissionLevel::None => wire::PermissionLevel::None as i32,
    }
}

fn value_entries(values: &BTreeMap<String, core::ValueSource>) -> Vec<wire::ValueEntry> {
    values
        .iter()
        .map(|(key, value)| wire::ValueEntry {
            key: key.clone(),
            value: Some(value_source(value)),
        })
        .collect()
}

fn value_source(value: &core::ValueSource) -> wire::ValueSource {
    use wire::value_source::Value;
    let value = match value {
        core::ValueSource::Literal(item) => Value::Literal(item.clone()),
        core::ValueSource::Expression(item) => Value::Expression(expression_program(item)),
        core::ValueSource::SecretReference(item) => Value::SecretReference(item.clone()),
        core::ValueSource::Template(item) => Value::Template(value_template(item)),
    };
    wire::ValueSource { value: Some(value) }
}

fn job_instance_identity(value: &core::JobInstanceIdentity) -> wire::JobInstanceIdentity {
    wire::JobInstanceIdentity {
        logical_job_key: value.logical_job_key().to_owned(),
        matrix_index: value.matrix_index(),
        matrix_total: value.matrix_total(),
        matrix_digest: value.matrix_digest().as_bytes().to_vec(),
    }
}

fn job_output_definition(value: &core::JobOutputDefinition) -> wire::JobOutputDefinition {
    wire::JobOutputDefinition {
        name: value.name().to_owned(),
        value: Some(value_template(value.value())),
        sensitivity: output_sensitivity(value.sensitivity()),
    }
}

fn value_template(value: &core::ValueTemplate) -> wire::ValueTemplate {
    wire::ValueTemplate {
        segments: value
            .segments()
            .iter()
            .map(|segment| {
                use wire::value_template_segment::Value;
                let value = match segment {
                    core::ValueTemplateSegment::Literal { value } => Value::Literal(value.clone()),
                    core::ValueTemplateSegment::Expression { program } => {
                        Value::Expression(expression_program(program))
                    }
                };
                wire::ValueTemplateSegment { value: Some(value) }
            })
            .collect(),
    }
}

fn step_ir(value: &core::StepIr) -> wire::StepIr {
    wire::StepIr {
        id: value.id().as_str().to_owned(),
        name: Some(value_template(value.name_template())),
        condition: value.condition().map(expression_program),
        continue_on_error: Some(runtime_boolean(value.continue_on_error())),
        timeout: value.timeout().map(runtime_timeout_template),
        environment: value_entries(value.environment()),
        kind: Some(semantic_step(value)),
    }
}

fn runtime_timeout_template(value: &core::RuntimeTimeoutTemplate) -> wire::RuntimeTimeoutTemplate {
    wire::RuntimeTimeoutTemplate {
        value: Some(runtime_positive_integer(value.value())),
        unit: match value.unit() {
            core::RuntimeTimeoutUnit::Seconds => wire::RuntimeTimeoutUnit::Seconds as i32,
            core::RuntimeTimeoutUnit::Minutes => wire::RuntimeTimeoutUnit::Minutes as i32,
        },
    }
}

fn runtime_positive_integer(value: &core::RuntimePositiveInteger) -> wire::RuntimePositiveInteger {
    use wire::runtime_positive_integer::Value;
    let value = match value {
        core::RuntimePositiveInteger::Literal { value } => Value::Literal(*value),
        core::RuntimePositiveInteger::Expression { program } => {
            Value::Expression(expression_program(program))
        }
    };
    wire::RuntimePositiveInteger { value: Some(value) }
}

fn expression_program(value: &core::ExpressionProgram) -> wire::ExpressionProgram {
    wire::ExpressionProgram {
        schema_version: u32::from(value.schema_version()),
        dialect: Some(wire::ExpressionDialect {
            name: value.dialect().name().to_owned(),
            version: u32::from(value.dialect().version()),
        }),
        source: value.source().to_owned(),
        instructions: value
            .instructions()
            .iter()
            .map(expression_instruction)
            .collect(),
    }
}

fn expression_instruction(value: &core::ExpressionInstruction) -> wire::ExpressionInstruction {
    use wire::expression_instruction::Value;
    let value = match value {
        core::ExpressionInstruction::Literal { value } => Value::Literal(expression_literal(value)),
        core::ExpressionInstruction::NamedValue { name } => Value::NamedValue(name.clone()),
        core::ExpressionInstruction::Wildcard => Value::Wildcard(wire::Unit {}),
        core::ExpressionInstruction::Index => Value::Index(wire::Unit {}),
        core::ExpressionInstruction::Not => Value::Not(wire::Unit {}),
        core::ExpressionInstruction::Compare { operator } => {
            Value::Compare(wire::ExpressionComparisonInstruction {
                operator: expression_comparison(*operator),
            })
        }
        core::ExpressionInstruction::Logical {
            operator,
            operand_count,
        } => Value::Logical(wire::ExpressionLogicalInstruction {
            operator: expression_logical(*operator),
            operand_count: u32::from(*operand_count),
        }),
        core::ExpressionInstruction::Call {
            name,
            argument_count,
        } => Value::Call(wire::ExpressionCallInstruction {
            name: name.clone(),
            argument_count: u32::from(*argument_count),
        }),
    };
    wire::ExpressionInstruction { value: Some(value) }
}

fn expression_literal(value: &core::ExpressionLiteral) -> wire::ExpressionLiteral {
    use wire::expression_literal::Value;
    let value = match value {
        core::ExpressionLiteral::Null => Value::Null(wire::Unit {}),
        core::ExpressionLiteral::Boolean { value } => Value::Boolean(*value),
        core::ExpressionLiteral::Number { ieee754_bits } => Value::NumberIeee754Bits(*ieee754_bits),
        core::ExpressionLiteral::String { value } => Value::StringValue(value.clone()),
    };
    wire::ExpressionLiteral { value: Some(value) }
}

const fn expression_comparison(value: core::ExpressionComparison) -> i32 {
    match value {
        core::ExpressionComparison::Equal => wire::ExpressionComparisonOperator::Equal as i32,
        core::ExpressionComparison::NotEqual => wire::ExpressionComparisonOperator::NotEqual as i32,
        core::ExpressionComparison::GreaterThan => {
            wire::ExpressionComparisonOperator::GreaterThan as i32
        }
        core::ExpressionComparison::GreaterThanOrEqual => {
            wire::ExpressionComparisonOperator::GreaterThanOrEqual as i32
        }
        core::ExpressionComparison::LessThan => wire::ExpressionComparisonOperator::LessThan as i32,
        core::ExpressionComparison::LessThanOrEqual => {
            wire::ExpressionComparisonOperator::LessThanOrEqual as i32
        }
    }
}

const fn expression_logical(value: core::ExpressionLogical) -> i32 {
    match value {
        core::ExpressionLogical::And => wire::ExpressionLogicalOperator::And as i32,
        core::ExpressionLogical::Or => wire::ExpressionLogicalOperator::Or as i32,
    }
}

fn runtime_boolean(value: &core::RuntimeBoolean) -> wire::RuntimeBoolean {
    use wire::runtime_boolean::Value;
    let value = match value {
        core::RuntimeBoolean::Literal { value } => Value::Literal(*value),
        core::RuntimeBoolean::Expression { program } => {
            Value::Expression(expression_program(program))
        }
    };
    wire::RuntimeBoolean { value: Some(value) }
}

fn semantic_step(step: &core::StepIr) -> wire::SemanticStep {
    use wire::semantic_step::Value;
    let value = match step.kind() {
        core::SemanticStep::Run { values } => Value::Run(wire::RunStep {
            command: Some(value_template(values.command())),
            shell: Some(shell_template(values.shell())),
            working_directory: values.working_directory().map(value_template),
        }),
        core::SemanticStep::Action { reference, inputs } => Value::Action(wire::ActionStep {
            reference: Some(action_reference(reference)),
            inputs: value_entries(inputs),
        }),
    };
    wire::SemanticStep { value: Some(value) }
}

fn shell_template(value: &core::ShellTemplate) -> wire::ShellTemplate {
    use wire::shell_template::Value;
    let value = match value {
        core::ShellTemplate::Default => Value::DefaultShell(wire::Unit {}),
        core::ShellTemplate::Named { value } => Value::Named(value_template(value)),
        core::ShellTemplate::CommandTemplate { value } => {
            Value::CommandTemplate(value_template(value))
        }
        core::ShellTemplate::Dynamic { value } => Value::Dynamic(value_template(value)),
    };
    wire::ShellTemplate { value: Some(value) }
}

fn action_reference(value: &core::ActionReference) -> wire::ActionReference {
    use wire::action_reference::Value;
    let value = match value {
        core::ActionReference::Repository {
            repository,
            revision,
            subpath,
        } => Value::Repository(wire::RepositoryAction {
            repository: repository.clone(),
            revision: revision.clone(),
            subpath: subpath.clone(),
        }),
        core::ActionReference::Local { path } => Value::LocalPath(path.clone()),
        core::ActionReference::Container { image } => Value::ContainerImage(image.clone()),
    };
    wire::ActionReference { value: Some(value) }
}

fn container_spec(value: &core::ContainerSpec) -> wire::ContainerSpec {
    wire::ContainerSpec {
        image: value.image().to_owned(),
        credentials: value.credentials().map(container_credentials),
        environment: value_entries(value.environment()),
        ports: value.ports().iter().copied().map(container_port).collect(),
        volumes: value.volumes().iter().map(volume_mount).collect(),
        options: value.options().to_vec(),
    }
}

fn container_credentials(value: &core::ContainerCredentials) -> wire::ContainerCredentials {
    wire::ContainerCredentials {
        username: Some(value_source(value.username())),
        password: Some(value_source(value.password())),
    }
}

const fn container_port(value: core::ContainerPort) -> wire::ContainerPort {
    wire::ContainerPort {
        container_port: value.container_port() as u32,
        protocol: match value.protocol() {
            core::TransportProtocol::Tcp => wire::TransportProtocol::Tcp as i32,
            core::TransportProtocol::Udp => wire::TransportProtocol::Udp as i32,
        },
        requested_host_port: match value.requested_host_port() {
            Some(port) => Some(port as u32),
            None => None,
        },
    }
}

fn volume_mount(value: &core::VolumeMount) -> wire::VolumeMount {
    wire::VolumeMount {
        source: Some(mount_source(value.source())),
        target: value.target().to_owned(),
        read_only: value.is_read_only(),
    }
}

fn mount_source(value: &core::MountSource) -> wire::MountSource {
    use wire::mount_source::Value;
    let value = match value {
        core::MountSource::WorkspaceRelative(item) => Value::WorkspaceRelative(item.clone()),
        core::MountSource::TemporaryVolume(item) => Value::TemporaryVolume(item.clone()),
        core::MountSource::HostPath(item) => Value::HostPath(item.clone()),
    };
    wire::MountSource { value: Some(value) }
}

fn job_result_message(value: &protocol::JobResultMessage) -> wire::JobResultMessage {
    wire::JobResultMessage {
        header: Some(message_header(value.header())),
        guard: Some(lease_guard(value.guard())),
        result: Some(job_result(value.result())),
    }
}

fn job_result(value: &core::JobResult) -> wire::JobResult {
    wire::JobResult {
        schema_version: u32::from(value.schema_version()),
        attempt_id: uuid_bytes(value.attempt_id().as_uuid()),
        conclusion: job_conclusion(value.conclusion()),
        outputs: value
            .outputs()
            .iter()
            .map(|(key, output)| wire::JobResultOutputEntry {
                key: key.clone(),
                value: Some(job_result_output(output)),
            })
            .collect(),
        steps: value.steps().iter().map(step_result).collect(),
        completed_at_unix_millis: value.completed_at().get(),
        secret_exposure: job_secret_exposure(value.secret_exposure()),
    }
}

fn job_result_output(value: &core::JobResultOutput) -> wire::JobResultOutput {
    wire::JobResultOutput {
        sensitivity: output_sensitivity(value.sensitivity()),
        value: value.public_value().map(str::to_owned),
    }
}

const fn job_conclusion(value: core::JobConclusion) -> i32 {
    match value {
        core::JobConclusion::Success => wire::JobConclusion::Success as i32,
        core::JobConclusion::Failure => wire::JobConclusion::Failure as i32,
        core::JobConclusion::Cancelled => wire::JobConclusion::Cancelled as i32,
        core::JobConclusion::TimedOut => wire::JobConclusion::TimedOut as i32,
        core::JobConclusion::Skipped => wire::JobConclusion::Skipped as i32,
    }
}

const fn job_secret_exposure(value: core::JobSecretExposure) -> i32 {
    match value {
        core::JobSecretExposure::Secretless => wire::JobSecretExposure::Secretless as i32,
        core::JobSecretExposure::CapabilityOnly => wire::JobSecretExposure::CapabilityOnly as i32,
        core::JobSecretExposure::ReadableSecret => wire::JobSecretExposure::ReadableSecret as i32,
    }
}

fn step_result(value: &core::StepResult) -> wire::StepResult {
    wire::StepResult {
        step_id: value.step_id().as_str().to_owned(),
        outcome: job_conclusion(value.outcome()),
        conclusion: job_conclusion(value.conclusion()),
        started_at_unix_millis: value.started_at().get(),
        completed_at_unix_millis: value.completed_at().get(),
        summary_markdown: value.summary_markdown().map(str::to_owned),
        annotations: value.annotations().iter().map(step_annotation).collect(),
    }
}

fn step_annotation(value: &core::StepAnnotation) -> wire::StepAnnotation {
    wire::StepAnnotation {
        level: match value.level() {
            core::StepAnnotationLevel::Error => wire::StepAnnotationLevel::Error as i32,
            core::StepAnnotationLevel::Warning => wire::StepAnnotationLevel::Warning as i32,
            core::StepAnnotationLevel::Notice => wire::StepAnnotationLevel::Notice as i32,
        },
        message: value.message().to_owned(),
        properties: value
            .properties()
            .iter()
            .map(|property| wire::StepAnnotationProperty {
                name: property.name().to_owned(),
                value: property.value().to_owned(),
            })
            .collect(),
    }
}

fn string_entries(values: &BTreeMap<String, String>) -> Vec<wire::StringEntry> {
    values
        .iter()
        .map(|(key, value)| wire::StringEntry {
            key: key.clone(),
            value: value.clone(),
        })
        .collect()
}

fn log_batch(value: &protocol::LogBatch) -> wire::LogBatch {
    wire::LogBatch {
        header: Some(message_header(value.header())),
        guard: Some(lease_guard(value.guard())),
        frames: value.frames().iter().map(log_frame).collect(),
    }
}

fn log_frame(value: &core::LogFrame) -> wire::LogFrame {
    wire::LogFrame {
        schema_version: u32::from(value.schema_version()),
        stream_id: uuid_bytes(value.stream_id().as_uuid()),
        attempt_id: uuid_bytes(value.attempt_id().as_uuid()),
        sequence: value.sequence().get(),
        emitted_at_unix_millis: value.emitted_at().get(),
        channel: match value.channel() {
            core::LogChannel::Stdout => wire::LogChannel::Stdout as i32,
            core::LogChannel::Stderr => wire::LogChannel::Stderr as i32,
            core::LogChannel::System => wire::LogChannel::System as i32,
        },
        payload: value.payload().to_vec(),
        end_of_stream: value.is_end_of_stream(),
    }
}

fn log_ack_message(value: &protocol::LogAckMessage) -> wire::LogAckMessage {
    wire::LogAckMessage {
        header: Some(message_header(value.header())),
        ack: Some(log_ack(value.ack())),
    }
}

fn log_ack(value: &core::LogAck) -> wire::LogAck {
    wire::LogAck {
        schema_version: u32::from(value.schema_version()),
        stream_id: uuid_bytes(value.stream_id().as_uuid()),
        contiguous_through: value.contiguous_through().map(core::LogSequence::get),
    }
}

fn command_ack(value: protocol::CommandAck) -> wire::CommandAck {
    wire::CommandAck {
        header: Some(message_header(value.header())),
        command_cursor: Some(command_cursor(value.command_cursor())),
    }
}

fn operation_ack(value: protocol::OperationAck) -> wire::OperationAck {
    wire::OperationAck {
        header: Some(message_header(value.header())),
    }
}

fn no_work(value: &protocol::NoWork) -> wire::NoWork {
    wire::NoWork {
        header: Some(message_header(value.header())),
        retry_after_millis: value.retry_after_millis(),
    }
}

fn error_message(value: &protocol::ErrorMessage) -> wire::ErrorMessage {
    wire::ErrorMessage {
        header: Some(message_header(value.header())),
        code: remote_error_code(value.code()),
        message: value.message().to_owned(),
        retryable: value.is_retryable(),
        details: string_entries(value.details()),
    }
}

const fn remote_error_code(value: protocol::RemoteErrorCode) -> i32 {
    match value {
        protocol::RemoteErrorCode::InvalidMessage => wire::RemoteErrorCode::InvalidMessage as i32,
        protocol::RemoteErrorCode::UnsupportedProtocol => {
            wire::RemoteErrorCode::UnsupportedProtocol as i32
        }
        protocol::RemoteErrorCode::UnsupportedJobIr => {
            wire::RemoteErrorCode::UnsupportedJobIr as i32
        }
        protocol::RemoteErrorCode::Unauthenticated => wire::RemoteErrorCode::Unauthenticated as i32,
        protocol::RemoteErrorCode::Unauthorized => wire::RemoteErrorCode::Unauthorized as i32,
        protocol::RemoteErrorCode::SessionNotFound => wire::RemoteErrorCode::SessionNotFound as i32,
        protocol::RemoteErrorCode::StaleSession => wire::RemoteErrorCode::StaleSession as i32,
        protocol::RemoteErrorCode::InvalidSlot => wire::RemoteErrorCode::InvalidSlot as i32,
        protocol::RemoteErrorCode::OperationKeyReused => {
            wire::RemoteErrorCode::OperationKeyReused as i32
        }
        protocol::RemoteErrorCode::CommandCursorConflict => {
            wire::RemoteErrorCode::CommandCursorConflict as i32
        }
        protocol::RemoteErrorCode::LeaseNotFound => wire::RemoteErrorCode::LeaseNotFound as i32,
        protocol::RemoteErrorCode::StaleFencingToken => {
            wire::RemoteErrorCode::StaleFencingToken as i32
        }
        protocol::RemoteErrorCode::Conflict => wire::RemoteErrorCode::Conflict as i32,
        protocol::RemoteErrorCode::RetryLater => wire::RemoteErrorCode::RetryLater as i32,
        protocol::RemoteErrorCode::Internal => wire::RemoteErrorCode::Internal as i32,
    }
}

fn uuid_bytes(value: Uuid) -> Vec<u8> {
    value.as_bytes().to_vec()
}
