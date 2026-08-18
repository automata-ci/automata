//! Size-first protobuf-to-domain conversion.

use std::{cmp::Ordering, collections::BTreeMap};

use automata_ci_core as core;
use automata_ci_protocol as protocol;
use prost::Message as _;
use uuid::Uuid;

use crate::{DecodeError, wire};

/// Decodes, converts, and validates one runner-to-server protobuf frame.
///
/// The byte ceiling is checked before protobuf parsing can allocate nested
/// values. Canonical collection rules and narrower domain representations are
/// checked during conversion; the complete message then passes through
/// [`protocol::ValidatedRunnerToServer`].
///
/// # Errors
///
/// Returns [`DecodeError`] for empty or oversized input, malformed protobuf,
/// non-canonical representations, unsupported values, or domain validation.
pub fn decode_runner_frame(
    frame: &[u8],
    limits: &protocol::ProtocolLimits,
) -> Result<protocol::ValidatedRunnerToServer, DecodeError> {
    check_frame_size(frame, limits)?;
    let frame = wire::RunnerFrame::decode(frame).map_err(DecodeError::MalformedProtobuf)?;
    let message = runner_frame(frame, limits)?;
    protocol::ValidatedRunnerToServer::new(message, limits).map_err(DecodeError::InvalidMessage)
}

/// Decodes, converts, and validates one server-to-runner protobuf frame.
///
/// # Errors
///
/// Returns [`DecodeError`] under the same trust-boundary policy as
/// [`decode_runner_frame`].
pub fn decode_server_frame(
    frame: &[u8],
    limits: &protocol::ProtocolLimits,
) -> Result<protocol::ValidatedServerToRunner, DecodeError> {
    check_frame_size(frame, limits)?;
    let frame = wire::ServerFrame::decode(frame).map_err(DecodeError::MalformedProtobuf)?;
    let message = server_frame(frame, limits)?;
    protocol::ValidatedServerToRunner::new(message, limits).map_err(DecodeError::InvalidMessage)
}

/// Size-checks, decodes, converts, and validates one standalone `JobIR` envelope.
///
/// # Errors
///
/// Returns [`DecodeError`] before protobuf allocation for an empty or oversized
/// input, or after conversion for a malformed, unsupported, or invalid `JobIR`.
pub fn decode_job_ir(
    encoded: &[u8],
    limits: &protocol::ProtocolLimits,
) -> Result<core::JobIrEnvelope, DecodeError> {
    check_frame_size(encoded, limits)?;
    let value = wire::JobIrEnvelope::decode(encoded).map_err(DecodeError::MalformedProtobuf)?;
    let envelope = job_ir_envelope(value, limits)?;
    protocol::validate_job_ir_envelope(&envelope, limits).map_err(DecodeError::InvalidMessage)?;
    Ok(envelope)
}

/// Size-checks and decodes one immutable job runtime-context blob.
///
/// The flat wire tree is validated for canonical post-order, single ownership,
/// distinct roots, complete reachability, and collection bounds before domain
/// values are constructed.
///
/// # Errors
///
/// Returns [`DecodeError`] for empty or oversized input, malformed protobuf,
/// a noncanonical flat tree or map, unsupported schema, or invalid context.
pub fn decode_job_runtime_context(
    encoded: &[u8],
    limits: &protocol::ProtocolLimits,
) -> Result<core::JobRuntimeContext, DecodeError> {
    check_frame_size(encoded, limits)?;
    let value = wire::JobRuntimeContext::decode(encoded).map_err(DecodeError::MalformedProtobuf)?;
    job_runtime_context(value, limits)
}

/// Size-checks, decodes, and validates one protected runtime-authority object.
///
/// # Errors
///
/// Rejects malformed credentials, non-canonical ordering, unsupported schema,
/// and any run/job/attempt/fence mismatch with `job` and `lease`.
pub fn decode_runtime_authorities(
    encoded: &[u8],
    job: &core::JobIrEnvelope,
    lease: &core::Lease,
    limits: &protocol::ProtocolLimits,
) -> Result<protocol::JobRuntimeAuthorities, DecodeError> {
    check_frame_size(encoded, limits)?;
    let value =
        wire::JobRuntimeAuthorities::decode(encoded).map_err(DecodeError::MalformedProtobuf)?;
    runtime_authorities(value, job, lease, limits)
}

fn check_frame_size(frame: &[u8], limits: &protocol::ProtocolLimits) -> Result<(), DecodeError> {
    if frame.is_empty() {
        return Err(DecodeError::EmptyFrame);
    }
    if frame.len() > limits.max_frame_bytes() {
        return Err(DecodeError::FrameTooLarge {
            size: frame.len(),
            maximum: limits.max_frame_bytes(),
        });
    }
    Ok(())
}

fn runner_frame(
    frame: wire::RunnerFrame,
    limits: &protocol::ProtocolLimits,
) -> Result<protocol::RunnerToServer, DecodeError> {
    use protocol::RunnerToServer as Domain;
    use wire::runner_frame::Payload;

    match required_variant(frame.payload, "runner_frame.payload")? {
        Payload::Hello(value) => runner_hello(value, limits).map(Domain::Hello),
        Payload::LeaseRequest(value) => lease_request(value).map(Domain::LeaseRequest),
        Payload::LeaseResponse(value) => lease_response(value).map(Domain::LeaseResponse),
        Payload::RuntimeAuthorityRequest(value) => {
            runtime_authority_request(value).map(Domain::RuntimeAuthorityRequest)
        }
        Payload::RuntimeAuthorityAck(value) => {
            runtime_authority_ack(value).map(Domain::RuntimeAuthorityAck)
        }
        Payload::Heartbeat(value) => lease_heartbeat(value).map(Domain::Heartbeat),
        Payload::JobState(value) => job_state_update(value).map(Domain::JobState),
        Payload::JobResult(value) => job_result_message(value, limits).map(Domain::JobResult),
        Payload::LogBatch(value) => log_batch(value, limits).map(Domain::LogBatch),
        Payload::CommandAck(value) => command_ack(value).map(Domain::CommandAck),
    }
}

fn server_frame(
    frame: wire::ServerFrame,
    limits: &protocol::ProtocolLimits,
) -> Result<protocol::ServerToRunner, DecodeError> {
    use protocol::ServerToRunner as Domain;
    use wire::server_frame::Payload;

    match required_variant(frame.payload, "server_frame.payload")? {
        Payload::Hello(value) => server_hello(value).map(Domain::Hello),
        Payload::HandshakeRejected(value) => {
            handshake_rejected(value).map(Domain::HandshakeRejected)
        }
        Payload::LeaseOffer(value) => {
            lease_offer(value, limits).map(|item| Domain::LeaseOffer(Box::new(item)))
        }
        Payload::RuntimeAuthorityGrant(value) => runtime_authority_grant(value, limits)
            .map(|item| Domain::RuntimeAuthorityGrant(Box::new(item))),
        Payload::LeaseRenewal(value) => lease_renewal(value).map(Domain::LeaseRenewal),
        Payload::CancelJob(value) => cancel_job(value).map(Domain::CancelJob),
        Payload::LogAck(value) => log_ack_message(value).map(Domain::LogAck),
        Payload::OperationAck(value) => operation_ack(value).map(Domain::OperationAck),
        Payload::NoWork(value) => no_work(value).map(Domain::NoWork),
        Payload::Error(value) => error_message(value, limits).map(Domain::Error),
    }
}

fn runner_hello(
    value: wire::RunnerHello,
    limits: &protocol::ProtocolLimits,
) -> Result<protocol::RunnerHello, DecodeError> {
    check_schema(
        value.message_schema_version,
        protocol::MESSAGE_SCHEMA_VERSION,
        "runner_hello.message_schema_version",
    )?;
    let mut hello = protocol::RunnerHello::new(
        core::OperationId::from_uuid(uuid(value.operation_id, "runner_hello.operation_id")?),
        protocol_range(required(
            value.supported_protocol,
            "runner_hello.supported_protocol",
        )?)?,
        job_ir_version_range(required(
            value.supported_job_ir,
            "runner_hello.supported_job_ir",
        )?)?,
        runner_capabilities(required(value.runner, "runner_hello.runner")?, limits)?,
        core::UnixMillis::new(value.sent_at_unix_millis),
    );
    if let Some(resume) = value.resume {
        hello = hello.with_resume(session_resume(resume)?);
    }
    Ok(hello)
}

fn server_hello(value: wire::ServerHello) -> Result<protocol::ServerHello, DecodeError> {
    check_schema(
        value.message_schema_version,
        protocol::MESSAGE_SCHEMA_VERSION,
        "server_hello.message_schema_version",
    )?;
    Ok(protocol::ServerHello::new(
        core::OperationId::from_uuid(uuid(value.operation_id, "server_hello.operation_id")?),
        core::OperationId::from_uuid(uuid(value.in_reply_to, "server_hello.in_reply_to")?),
        negotiated_session(required(value.session, "server_hello.session")?)?,
        server_timing(required(value.timing, "server_hello.timing")?),
    ))
}

fn negotiated_session(
    value: wire::NegotiatedSession,
) -> Result<protocol::NegotiatedSession, DecodeError> {
    Ok(protocol::NegotiatedSession::new(
        protocol_version(
            value.selected_protocol,
            "negotiated_session.selected_protocol",
        )?,
        job_ir_version(value.selected_job_ir, "negotiated_session.selected_job_ir")?,
        core::RunnerSessionId::from_uuid(uuid(value.session_id, "negotiated_session.session_id")?),
        session_disposition(value.session_disposition)?,
        command_cursor(required(
            value.command_cursor,
            "negotiated_session.command_cursor",
        )?)?,
    ))
}

const fn server_timing(value: wire::ServerTiming) -> protocol::ServerTiming {
    protocol::ServerTiming::new(
        core::UnixMillis::new(value.server_time_unix_millis),
        value.heartbeat_interval_millis,
        value.lease_duration_millis,
    )
}

fn handshake_rejected(
    value: wire::HandshakeRejected,
) -> Result<protocol::HandshakeRejected, DecodeError> {
    check_schema(
        value.message_schema_version,
        protocol::MESSAGE_SCHEMA_VERSION,
        "handshake_rejected.message_schema_version",
    )?;
    let orphan_recovery = value
        .orphan_recovery
        .map(session_orphan_authorization)
        .transpose()?;
    let rejection = protocol::HandshakeRejected::new(
        core::OperationId::from_uuid(uuid(value.operation_id, "handshake_rejected.operation_id")?),
        core::OperationId::from_uuid(uuid(value.in_reply_to, "handshake_rejected.in_reply_to")?),
        handshake_error_code(value.code)?,
        protocol_range(required(
            value.supported_protocol,
            "handshake_rejected.supported_protocol",
        )?)?,
        value.message,
    );
    Ok(match orphan_recovery {
        Some(authorization) => rejection.with_orphan_recovery(authorization),
        None => rejection,
    })
}

fn session_orphan_authorization(
    value: wire::SessionOrphanAuthorization,
) -> Result<protocol::SessionOrphanAuthorization, DecodeError> {
    Ok(protocol::SessionOrphanAuthorization::new(
        core::RunnerSessionId::from_uuid(uuid(
            value.session_id,
            "session_orphan_authorization.session_id",
        )?),
        orphan_delivery_permissions(required(
            value.permissions,
            "session_orphan_authorization.permissions",
        )?),
    ))
}

const fn orphan_delivery_permissions(
    value: wire::OrphanDeliveryPermissions,
) -> protocol::OrphanDeliveryPermissions {
    protocol::OrphanDeliveryPermissions::new(
        value.terminal_result,
        value.log_delivery,
        value.lease_rejection,
    )
}

fn handshake_error_code(value: i32) -> Result<protocol::HandshakeErrorCode, DecodeError> {
    match wire::HandshakeErrorCode::try_from(value) {
        Ok(wire::HandshakeErrorCode::InvalidHello) => {
            Ok(protocol::HandshakeErrorCode::InvalidHello)
        }
        Ok(wire::HandshakeErrorCode::UnsupportedProtocol) => {
            Ok(protocol::HandshakeErrorCode::UnsupportedProtocol)
        }
        Ok(wire::HandshakeErrorCode::UnsupportedJobIr) => {
            Ok(protocol::HandshakeErrorCode::UnsupportedJobIr)
        }
        Ok(wire::HandshakeErrorCode::Unauthenticated) => {
            Ok(protocol::HandshakeErrorCode::Unauthenticated)
        }
        Ok(wire::HandshakeErrorCode::Unauthorized) => {
            Ok(protocol::HandshakeErrorCode::Unauthorized)
        }
        Ok(wire::HandshakeErrorCode::SessionNotResumable) => {
            Ok(protocol::HandshakeErrorCode::SessionNotResumable)
        }
        Ok(wire::HandshakeErrorCode::Unspecified) | Err(_) => Err(DecodeError::UnknownEnum {
            field: "handshake_rejected.code",
            value,
        }),
    }
}

fn session_disposition(value: i32) -> Result<protocol::SessionDisposition, DecodeError> {
    match wire::SessionDisposition::try_from(value) {
        Ok(wire::SessionDisposition::Opened) => Ok(protocol::SessionDisposition::Opened),
        Ok(wire::SessionDisposition::Resumed) => Ok(protocol::SessionDisposition::Resumed),
        Ok(wire::SessionDisposition::Unspecified) | Err(_) => Err(DecodeError::UnknownEnum {
            field: "negotiated_session.session_disposition",
            value,
        }),
    }
}

fn protocol_range(value: wire::ProtocolRange) -> Result<protocol::ProtocolRange, DecodeError> {
    protocol::ProtocolRange::new(
        protocol_version(value.minimum, "protocol_range.minimum")?,
        protocol_version(value.maximum, "protocol_range.maximum")?,
    )
    .map_err(|_| DecodeError::InvalidValue {
        field: "protocol_range",
    })
}

fn protocol_version(
    value: u32,
    field: &'static str,
) -> Result<protocol::ProtocolVersion, DecodeError> {
    protocol::ProtocolVersion::new(narrow_u16(value, field)?)
        .map_err(|_| DecodeError::InvalidValue { field })
}

fn job_ir_version_range(
    value: wire::JobIrVersionRange,
) -> Result<core::JobIrVersionRange, DecodeError> {
    core::JobIrVersionRange::new(
        job_ir_version(value.minimum, "job_ir_version_range.minimum")?,
        job_ir_version(value.maximum, "job_ir_version_range.maximum")?,
    )
    .map_err(|_| DecodeError::InvalidValue {
        field: "job_ir_version_range",
    })
}

fn job_ir_version(value: u32, field: &'static str) -> Result<core::JobIrVersion, DecodeError> {
    let version = core::JobIrVersion::new(narrow_u16(value, field)?)
        .map_err(|_| DecodeError::InvalidValue { field })?;
    if version != core::JobIrVersion::current() {
        return Err(DecodeError::UnsupportedSchema {
            field,
            received: value,
            supported: u32::from(core::JOB_IR_SCHEMA_VERSION),
        });
    }
    Ok(version)
}

fn session_resume(value: wire::SessionResume) -> Result<protocol::SessionResume, DecodeError> {
    Ok(protocol::SessionResume::new(
        core::RunnerSessionId::from_uuid(uuid(value.session_id, "session_resume.session_id")?),
        command_cursor(required(
            value.command_cursor,
            "session_resume.command_cursor",
        )?)?,
    ))
}

fn command_cursor(value: wire::CommandCursor) -> Result<protocol::CommandCursor, DecodeError> {
    match value.acknowledged_through {
        Some(sequence) => protocol::CommandSequence::new(sequence)
            .map(protocol::CommandCursor::through)
            .map_err(|_| DecodeError::InvalidValue {
                field: "command_cursor.acknowledged_through",
            }),
        None => Ok(protocol::CommandCursor::initial()),
    }
}

fn message_header(value: wire::MessageHeader) -> Result<protocol::MessageHeader, DecodeError> {
    check_schema(
        value.message_schema_version,
        protocol::MESSAGE_SCHEMA_VERSION,
        "message_header.message_schema_version",
    )?;
    let version = protocol_version(value.protocol_version, "message_header.protocol_version")?;
    let session_id =
        core::RunnerSessionId::from_uuid(uuid(value.session_id, "message_header.session_id")?);
    let operation_id =
        core::OperationId::from_uuid(uuid(value.operation_id, "message_header.operation_id")?);
    match value.in_reply_to {
        Some(correlation) => Ok(protocol::MessageHeader::reply(
            version,
            session_id,
            operation_id,
            core::OperationId::from_uuid(uuid(correlation, "message_header.in_reply_to")?),
        )),
        None => Ok(protocol::MessageHeader::request(
            version,
            session_id,
            operation_id,
        )),
    }
}

fn server_command_header(
    value: wire::ServerCommandHeader,
) -> Result<protocol::ServerCommandHeader, DecodeError> {
    check_schema(
        value.message_schema_version,
        protocol::MESSAGE_SCHEMA_VERSION,
        "server_command_header.message_schema_version",
    )?;
    Ok(protocol::ServerCommandHeader::new(
        protocol_version(
            value.protocol_version,
            "server_command_header.protocol_version",
        )?,
        core::RunnerSessionId::from_uuid(uuid(
            value.session_id,
            "server_command_header.session_id",
        )?),
        core::OperationId::from_uuid(uuid(
            value.operation_id,
            "server_command_header.operation_id",
        )?),
        protocol::CommandSequence::new(value.sequence).map_err(|_| DecodeError::InvalidValue {
            field: "server_command_header.sequence",
        })?,
    ))
}

fn runner_capabilities(
    value: wire::RunnerCapabilities,
    limits: &protocol::ProtocolLimits,
) -> Result<core::RunnerCapabilities, DecodeError> {
    check_schema(
        value.schema_version,
        core::CORE_SCHEMA_VERSION,
        "runner_capabilities.schema_version",
    )?;
    check_collection(
        value.labels.len(),
        limits.max_collection_items(),
        "runner_capabilities.labels",
    )?;
    check_collection(
        value.groups.len(),
        limits.max_collection_items(),
        "runner_capabilities.groups",
    )?;
    check_collection(
        value.features.len(),
        limits.max_collection_items(),
        "runner_capabilities.features",
    )?;
    ensure_canonical_strings(&value.labels, "runner_capabilities.labels")?;
    ensure_canonical_strings(&value.groups, "runner_capabilities.groups")?;
    ensure_canonical_strings(&value.features, "runner_capabilities.features")?;

    let labels = value
        .labels
        .into_iter()
        .map(|item| {
            let parsed = core::RunnerLabel::new(&item).map_err(|_| DecodeError::InvalidValue {
                field: "runner_capabilities.labels",
            })?;
            if parsed.as_str() != item {
                return Err(DecodeError::NonCanonicalValue {
                    field: "runner_capabilities.labels",
                });
            }
            Ok(parsed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let groups = value
        .groups
        .into_iter()
        .map(|item| {
            let parsed = core::RunnerGroup::new(&item).map_err(|_| DecodeError::InvalidValue {
                field: "runner_capabilities.groups",
            })?;
            if parsed.as_str() != item {
                return Err(DecodeError::NonCanonicalValue {
                    field: "runner_capabilities.groups",
                });
            }
            Ok(parsed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let features = value
        .features
        .into_iter()
        .map(|item| {
            core::RunnerFeature::try_from(item).map_err(|_| DecodeError::InvalidValue {
                field: "runner_capabilities.features",
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let environment_profiles = decode_environment_profiles(value.environment_profiles, limits)?;

    let resources = resource_capacity(
        required(
            value.resources_per_job,
            "runner_capabilities.resources_per_job",
        )?,
        "runner_capabilities.resources_per_job.gpu_count",
    )?;
    let sandbox = sandbox_capabilities(
        required(value.sandbox, "runner_capabilities.sandbox")?,
        limits,
    )?;
    let containers = container_capabilities(
        required(value.containers, "runner_capabilities.containers")?,
        limits,
    )?;
    let capabilities = core::RunnerCapabilities::new(
        core::RunnerId::from_uuid(uuid(value.runner_id, "runner_capabilities.runner_id")?),
        runner_platform(required(value.platform, "runner_capabilities.platform")?)?,
    )
    .with_labels(labels)
    .with_groups(groups)
    .with_max_parallel_jobs(narrow_u16(
        value.max_parallel_jobs,
        "runner_capabilities.max_parallel_jobs",
    )?)
    .map_err(|_| DecodeError::InvalidValue {
        field: "runner_capabilities.max_parallel_jobs",
    })?;
    Ok(capabilities
        .with_resources_per_job(resources)
        .with_sandbox(sandbox)
        .with_containers(containers)
        .with_features(features)
        .with_environment_profiles(environment_profiles))
}

fn environment_profile(
    value: wire::EnvironmentProfile,
) -> Result<core::EnvironmentProfile, DecodeError> {
    let id = core::EnvironmentProfileId::new(value.id).map_err(|_| DecodeError::InvalidValue {
        field: "environment_profile.id",
    })?;
    let digest = value
        .sha256_digest
        .try_into()
        .map_err(|_| DecodeError::InvalidValue {
            field: "environment_profile.sha256_digest",
        })?;
    Ok(core::EnvironmentProfile::new(
        id,
        core::Sha256Digest::from_bytes(digest),
    ))
}

fn decode_environment_profiles(
    values: Vec<wire::EnvironmentProfile>,
    limits: &protocol::ProtocolLimits,
) -> Result<Vec<core::EnvironmentProfile>, DecodeError> {
    check_collection(
        values.len(),
        limits.max_collection_items(),
        "runner_capabilities.environment_profiles",
    )?;
    ensure_canonical_environment_profiles(&values, "runner_capabilities.environment_profiles")?;
    values.into_iter().map(environment_profile).collect()
}

fn runner_platform(value: wire::RunnerPlatform) -> Result<core::RunnerPlatform, DecodeError> {
    Ok(core::RunnerPlatform::new(
        operating_system(required(
            value.operating_system,
            "runner_platform.operating_system",
        )?)?,
        architecture(required(
            value.architecture,
            "runner_platform.architecture",
        )?)?,
    ))
}

fn operating_system(value: wire::OperatingSystem) -> Result<core::OperatingSystem, DecodeError> {
    use wire::operating_system::Value;
    match required_variant(value.value, "operating_system.value")? {
        Value::Linux(_) => Ok(core::OperatingSystem::Linux),
        Value::Windows(_) => Ok(core::OperatingSystem::Windows),
        Value::Macos(_) => Ok(core::OperatingSystem::Macos),
        Value::Other(name) => Ok(core::OperatingSystem::Other(name)),
    }
}

fn architecture(value: wire::Architecture) -> Result<core::Architecture, DecodeError> {
    use wire::architecture::Value;
    match required_variant(value.value, "architecture.value")? {
        Value::X8664(_) => Ok(core::Architecture::X86_64),
        Value::Aarch64(_) => Ok(core::Architecture::Aarch64),
        Value::Other(name) => Ok(core::Architecture::Other(name)),
    }
}

fn resource_capacity(
    value: wire::ResourceCapacity,
    gpu_field: &'static str,
) -> Result<core::ResourceCapacity, DecodeError> {
    Ok(core::ResourceCapacity::new(
        value.cpu_millis,
        value.memory_bytes,
        value.ephemeral_disk_bytes,
        narrow_u16(value.gpu_count, gpu_field)?,
    ))
}

fn sandbox_capabilities(
    value: wire::SandboxCapabilities,
    limits: &protocol::ProtocolLimits,
) -> Result<core::SandboxCapabilities, DecodeError> {
    check_collection(
        value.features.len(),
        limits.max_collection_items(),
        "sandbox_capabilities.features",
    )?;
    ensure_canonical_strings(&value.features, "sandbox_capabilities.features")?;
    let features = value
        .features
        .into_iter()
        .map(|item| {
            core::SandboxFeature::try_from(item).map_err(|_| DecodeError::InvalidValue {
                field: "sandbox_capabilities.features",
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(core::SandboxCapabilities::new(
        isolation_level(
            value.maximum_isolation,
            "sandbox_capabilities.maximum_isolation",
        )?,
        features,
    ))
}

fn container_capabilities(
    value: wire::ContainerCapabilities,
    limits: &protocol::ProtocolLimits,
) -> Result<core::ContainerCapabilities, DecodeError> {
    check_collection(
        value.features.len(),
        limits.max_collection_items(),
        "container_capabilities.features",
    )?;
    ensure_canonical_strings(&value.features, "container_capabilities.features")?;
    let features = value
        .features
        .into_iter()
        .map(|item| {
            core::ContainerFeature::try_from(item).map_err(|_| DecodeError::InvalidValue {
                field: "container_capabilities.features",
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(core::ContainerCapabilities::new(features))
}

fn isolation_level(value: i32, field: &'static str) -> Result<core::IsolationLevel, DecodeError> {
    match wire::IsolationLevel::try_from(value) {
        Ok(wire::IsolationLevel::Process) => Ok(core::IsolationLevel::Process),
        Ok(wire::IsolationLevel::SharedKernel) => Ok(core::IsolationLevel::SharedKernel),
        Ok(wire::IsolationLevel::VirtualMachine) => Ok(core::IsolationLevel::VirtualMachine),
        Ok(wire::IsolationLevel::Unspecified) | Err(_) => {
            Err(DecodeError::UnknownEnum { field, value })
        }
    }
}

fn runner_requirements(
    value: wire::RunnerRequirements,
    limits: &protocol::ProtocolLimits,
) -> Result<core::RunnerRequirements, DecodeError> {
    check_schema(
        value.schema_version,
        core::RUNNER_REQUIREMENTS_SCHEMA_VERSION,
        "runner_requirements.schema_version",
    )?;
    validate_runner_requirement_collections(&value, limits)?;

    let labels = decode_labels(value.labels, "runner_requirements.labels")?;
    let groups = decode_groups(value.eligible_groups, "runner_requirements.eligible_groups")?;
    let operating_system = value
        .operating_system
        .map(self::operating_system)
        .transpose()?;
    let minimum_isolation = isolation_level(
        value.minimum_isolation,
        "runner_requirements.minimum_isolation",
    )?;
    let sandbox_features = value
        .sandbox_features
        .into_iter()
        .map(|item| {
            core::SandboxFeature::try_from(item).map_err(|_| DecodeError::InvalidValue {
                field: "runner_requirements.sandbox_features",
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let container_features = value
        .container_features
        .into_iter()
        .map(|item| {
            core::ContainerFeature::try_from(item).map_err(|_| DecodeError::InvalidValue {
                field: "runner_requirements.container_features",
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let features = value
        .features
        .into_iter()
        .map(|item| {
            core::RunnerFeature::try_from(item).map_err(|_| DecodeError::InvalidValue {
                field: "runner_requirements.features",
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    validate_windows_hyperv_requirement(
        operating_system.as_ref(),
        minimum_isolation,
        &sandbox_features,
    )?;

    let mut requirements = core::RunnerRequirements::default()
        .with_labels(labels)
        .with_eligible_groups(groups)
        .with_minimum_resources(resource_capacity(
            required(
                value.minimum_resources,
                "runner_requirements.minimum_resources",
            )?,
            "runner_requirements.minimum_resources.gpu_count",
        )?)
        .with_minimum_isolation(minimum_isolation)
        .with_sandbox_features(sandbox_features)
        .with_container_features(container_features)
        .with_features(features);
    if let Some(operating_system) = operating_system {
        requirements = requirements.with_operating_system(operating_system);
    }
    if let Some(architecture) = value.architecture {
        requirements = requirements.with_architecture(self::architecture(architecture)?);
    }
    if let Some(profile) = value.environment_profile {
        requirements = requirements.with_environment_profile(environment_profile(profile)?);
    }
    if let Some(allocation) = value.resource_allocation {
        let allocation = decode_resource_allocation(allocation)?;
        if allocation.requests() != requirements.minimum_resources() {
            return Err(DecodeError::InvalidValue {
                field: "runner_requirements.minimum_resources",
            });
        }
        requirements = requirements.with_resource_allocation(allocation);
    }
    Ok(requirements)
}

fn validate_windows_hyperv_requirement(
    operating_system: Option<&core::OperatingSystem>,
    minimum_isolation: core::IsolationLevel,
    sandbox_features: &[core::SandboxFeature],
) -> Result<(), DecodeError> {
    let exact_launch = sandbox_features.contains(&core::SandboxFeature::WINDOWS_HYPERV_CONTAINER);
    if matches!(operating_system, Some(core::OperatingSystem::Windows)) {
        if minimum_isolation < core::IsolationLevel::VirtualMachine {
            return Err(DecodeError::InvalidValue {
                field: "runner_requirements.minimum_isolation",
            });
        }
        if !exact_launch {
            return Err(DecodeError::InvalidValue {
                field: "runner_requirements.sandbox_features",
            });
        }
    } else if exact_launch {
        return Err(DecodeError::InvalidValue {
            field: "runner_requirements.sandbox_features",
        });
    }
    Ok(())
}

fn validate_runner_requirement_collections(
    value: &wire::RunnerRequirements,
    limits: &protocol::ProtocolLimits,
) -> Result<(), DecodeError> {
    for (length, field) in [
        (value.labels.len(), "runner_requirements.labels"),
        (
            value.eligible_groups.len(),
            "runner_requirements.eligible_groups",
        ),
        (
            value.sandbox_features.len(),
            "runner_requirements.sandbox_features",
        ),
        (
            value.container_features.len(),
            "runner_requirements.container_features",
        ),
        (value.features.len(), "runner_requirements.features"),
    ] {
        check_collection(length, limits.max_collection_items(), field)?;
    }
    ensure_canonical_strings(&value.labels, "runner_requirements.labels")?;
    ensure_canonical_strings(
        &value.eligible_groups,
        "runner_requirements.eligible_groups",
    )?;
    ensure_canonical_strings(
        &value.sandbox_features,
        "runner_requirements.sandbox_features",
    )?;
    ensure_canonical_strings(
        &value.container_features,
        "runner_requirements.container_features",
    )?;
    ensure_canonical_strings(&value.features, "runner_requirements.features")?;
    Ok(())
}

fn decode_resource_allocation(
    allocation: wire::JobResourceAllocation,
) -> Result<core::JobResourceAllocation, DecodeError> {
    let requests = resource_capacity(
        required(allocation.requests, "job_resource_allocation.requests")?,
        "job_resource_allocation.requests.gpu_count",
    )?;
    let limits = resource_capacity(
        required(allocation.limits, "job_resource_allocation.limits")?,
        "job_resource_allocation.limits.gpu_count",
    )?;
    core::JobResourceAllocation::new(requests, limits).map_err(|_| DecodeError::InvalidValue {
        field: "job_resource_allocation",
    })
}

fn decode_labels(
    values: Vec<String>,
    field: &'static str,
) -> Result<Vec<core::RunnerLabel>, DecodeError> {
    values
        .into_iter()
        .map(|item| {
            let parsed =
                core::RunnerLabel::new(&item).map_err(|_| DecodeError::InvalidValue { field })?;
            if parsed.as_str() != item {
                return Err(DecodeError::NonCanonicalValue { field });
            }
            Ok(parsed)
        })
        .collect()
}

fn decode_groups(
    values: Vec<String>,
    field: &'static str,
) -> Result<Vec<core::RunnerGroup>, DecodeError> {
    values
        .into_iter()
        .map(|item| {
            let parsed =
                core::RunnerGroup::new(&item).map_err(|_| DecodeError::InvalidValue { field })?;
            if parsed.as_str() != item {
                return Err(DecodeError::NonCanonicalValue { field });
            }
            Ok(parsed)
        })
        .collect()
}

fn lease_request(value: wire::LeaseRequest) -> Result<protocol::LeaseRequest, DecodeError> {
    let header = message_header(required(value.header, "lease_request.header")?)?;
    let slot = runner_slot(value.slot, "lease_request.slot")?;
    value.acknowledges_operation_id.map_or_else(
        || Ok(protocol::LeaseRequest::first(header, slot)),
        |operation_id| {
            Ok(protocol::LeaseRequest::successor(
                header,
                slot,
                core::OperationId::from_uuid(uuid(
                    operation_id,
                    "lease_request.acknowledges_operation_id",
                )?),
            ))
        },
    )
}

fn lease_offer(
    value: wire::LeaseOffer,
    limits: &protocol::ProtocolLimits,
) -> Result<protocol::LeaseOffer, DecodeError> {
    let header = server_command_header(required(value.header, "lease_offer.header")?)?;
    let slot = runner_slot(value.slot, "lease_offer.slot")?;
    let lease = lease(required(value.lease, "lease_offer.lease")?)?;
    let job = job_ir_envelope(required(value.job, "lease_offer.job")?, limits)?;
    let managed_secret_bindings = value
        .managed_secret_bindings
        .map(|overlay| managed_secret_binding_overlay(overlay, &lease, limits))
        .transpose()?;
    let offer = protocol::LeaseOffer::new(header, slot, lease, job);
    match managed_secret_bindings {
        Some(overlay) => {
            offer
                .with_managed_secret_bindings(overlay)
                .map_err(|_| DecodeError::InvalidValue {
                    field: "lease_offer.managed_secret_bindings",
                })
        }
        None => Ok(offer),
    }
}

fn runtime_authority_delivery_binding(
    value: wire::RuntimeAuthorityDeliveryBinding,
) -> Result<protocol::RuntimeAuthorityDeliveryBinding, DecodeError> {
    let job_ir_digest = value
        .job_ir_sha256
        .try_into()
        .map_err(|_| DecodeError::InvalidValue {
            field: "runtime_authority_delivery_binding.job_ir_sha256",
        })?;
    Ok(protocol::RuntimeAuthorityDeliveryBinding::new(
        core::AttemptId::from_uuid(uuid(
            value.attempt_id,
            "runtime_authority_delivery_binding.attempt_id",
        )?),
        runner_slot(value.slot, "runtime_authority_delivery_binding.slot")?,
        lease_guard(required(
            value.guard,
            "runtime_authority_delivery_binding.guard",
        )?)?,
        core::OperationId::from_uuid(uuid(
            value.offer_operation_id,
            "runtime_authority_delivery_binding.offer_operation_id",
        )?),
        protocol::CommandSequence::new(value.offer_sequence).map_err(|_| {
            DecodeError::InvalidValue {
                field: "runtime_authority_delivery_binding.offer_sequence",
            }
        })?,
        core::Sha256Digest::from_bytes(job_ir_digest),
        protocol::RuntimeAuthorityGeneration::new(value.generation).map_err(|_| {
            DecodeError::InvalidValue {
                field: "runtime_authority_delivery_binding.generation",
            }
        })?,
    ))
}

fn runtime_authority_request(
    value: wire::RuntimeAuthorityRequest,
) -> Result<protocol::RuntimeAuthorityRequest, DecodeError> {
    Ok(protocol::RuntimeAuthorityRequest::new(
        message_header(required(value.header, "runtime_authority_request.header")?)?,
        runtime_authority_delivery_binding(required(
            value.binding,
            "runtime_authority_request.binding",
        )?)?,
    ))
}

fn runtime_authority_grant(
    value: wire::RuntimeAuthorityGrant,
    limits: &protocol::ProtocolLimits,
) -> Result<protocol::RuntimeAuthorityGrant, DecodeError> {
    let bundle_digest = value
        .bundle_sha256
        .try_into()
        .map_err(|_| DecodeError::InvalidValue {
            field: "runtime_authority_grant.bundle_sha256",
        })?;
    let authorities = runtime_authorities_unbound(
        required(value.authorities, "runtime_authority_grant.authorities")?,
        limits,
    )?;
    Ok(protocol::RuntimeAuthorityGrant::new(
        message_header(required(value.header, "runtime_authority_grant.header")?)?,
        runtime_authority_delivery_binding(required(
            value.binding,
            "runtime_authority_grant.binding",
        )?)?,
        core::Sha256Digest::from_bytes(bundle_digest),
        authorities,
    ))
}

fn runtime_authority_ack(
    value: wire::RuntimeAuthorityAck,
) -> Result<protocol::RuntimeAuthorityAck, DecodeError> {
    let bundle_digest = value
        .bundle_sha256
        .try_into()
        .map_err(|_| DecodeError::InvalidValue {
            field: "runtime_authority_ack.bundle_sha256",
        })?;
    Ok(protocol::RuntimeAuthorityAck::new(
        message_header(required(value.header, "runtime_authority_ack.header")?)?,
        runtime_authority_delivery_binding(required(
            value.binding,
            "runtime_authority_ack.binding",
        )?)?,
        core::Sha256Digest::from_bytes(bundle_digest),
    ))
}

fn managed_secret_binding_overlay(
    value: wire::ManagedSecretBindingOverlay,
    lease: &core::Lease,
    limits: &protocol::ProtocolLimits,
) -> Result<protocol::ManagedSecretBindingOverlay, DecodeError> {
    check_schema(
        value.schema_version,
        protocol::MANAGED_SECRET_BINDING_OVERLAY_SCHEMA_VERSION,
        "managed_secret_binding_overlay.schema_version",
    )?;
    check_collection(
        value.bindings.len(),
        protocol::MAX_MANAGED_SECRET_BINDINGS.min(limits.max_collection_items()),
        "managed_secret_binding_overlay.bindings",
    )?;
    ensure_order(
        value
            .bindings
            .windows(2)
            .map(|pair| pair[0].canonical_name.cmp(&pair[1].canonical_name)),
        "managed_secret_binding_overlay.bindings",
    )?;
    let attempt_id = core::AttemptId::from_uuid(uuid(
        value.attempt_id,
        "managed_secret_binding_overlay.attempt_id",
    )?);
    let lease_id = core::LeaseId::from_uuid(uuid(
        value.lease_id,
        "managed_secret_binding_overlay.lease_id",
    )?);
    let fencing_token = fencing_token(
        value.fencing_token,
        "managed_secret_binding_overlay.fencing_token",
    )?;
    if attempt_id != lease.attempt_id()
        || lease_id != lease.lease_id()
        || fencing_token != lease.fencing_token()
    {
        return Err(DecodeError::InvalidValue {
            field: "managed_secret_binding_overlay.lease_binding",
        });
    }
    let bindings = value
        .bindings
        .into_iter()
        .map(|entry| {
            let binding = core::SecretBinding::new(entry.grant_id)
                .and_then(|binding| binding.with_version_id(entry.version_id))
                .map_err(|_| DecodeError::InvalidValue {
                    field: "managed_secret_binding_overlay.binding",
                })?;
            Ok((entry.canonical_name, binding))
        })
        .collect::<Result<Vec<_>, DecodeError>>()?;
    let overlay = protocol::ManagedSecretBindingOverlay::new(lease, bindings).map_err(|_| {
        DecodeError::InvalidValue {
            field: "managed_secret_binding_overlay",
        }
    })?;
    if value.sha256_digest.as_slice() != overlay.digest().as_bytes() {
        return Err(DecodeError::InvalidValue {
            field: "managed_secret_binding_overlay.sha256_digest",
        });
    }
    Ok(overlay)
}

fn runtime_authorities(
    value: wire::JobRuntimeAuthorities,
    job: &core::JobIrEnvelope,
    lease: &core::Lease,
    limits: &protocol::ProtocolLimits,
) -> Result<protocol::JobRuntimeAuthorities, DecodeError> {
    check_schema(
        value.schema_version,
        protocol::RUNTIME_AUTHORITY_SCHEMA_VERSION,
        "runtime_authorities.schema_version",
    )?;
    check_collection(
        value.authorities.len(),
        protocol::MAX_RUNTIME_AUTHORITIES.min(limits.max_collection_items()),
        "runtime_authorities.authorities",
    )?;
    let authorities = value
        .authorities
        .into_iter()
        .map(runtime_authority)
        .collect::<Result<Vec<_>, _>>()?;
    protocol::JobRuntimeAuthorities::new(authorities, job, lease).map_err(|_| {
        DecodeError::InvalidValue {
            field: "runtime_authorities",
        }
    })
}

fn runtime_authorities_unbound(
    value: wire::JobRuntimeAuthorities,
    limits: &protocol::ProtocolLimits,
) -> Result<protocol::JobRuntimeAuthorities, DecodeError> {
    check_schema(
        value.schema_version,
        protocol::RUNTIME_AUTHORITY_SCHEMA_VERSION,
        "runtime_authorities.schema_version",
    )?;
    check_collection(
        value.authorities.len(),
        protocol::MAX_RUNTIME_AUTHORITIES.min(limits.max_collection_items()),
        "runtime_authorities.authorities",
    )?;
    let authorities = value
        .authorities
        .into_iter()
        .map(runtime_authority)
        .collect::<Result<Vec<_>, _>>()?;
    protocol::JobRuntimeAuthorities::from_unbound(authorities).map_err(|_| {
        DecodeError::InvalidValue {
            field: "runtime_authorities",
        }
    })
}

fn runtime_authority(
    value: wire::JobRuntimeAuthority,
) -> Result<protocol::JobRuntimeAuthority, DecodeError> {
    let endpoint =
        match wire::RuntimeAuthorityEndpointSecurity::try_from(value.endpoint_security) {
            Ok(wire::RuntimeAuthorityEndpointSecurity::Tls) => {
                protocol::RuntimeAuthorityEndpoint::new(value.endpoint)
            }
            Ok(wire::RuntimeAuthorityEndpointSecurity::LoopbackDevelopment) => {
                protocol::RuntimeAuthorityEndpoint::loopback_development(value.endpoint)
            }
            Ok(wire::RuntimeAuthorityEndpointSecurity::TrustedPrivateDevelopment) => {
                protocol::RuntimeAuthorityEndpoint::trusted_private_development(value.endpoint)
            }
            Ok(wire::RuntimeAuthorityEndpointSecurity::Unspecified) | Err(_) => {
                return Err(DecodeError::UnknownEnum {
                    field: "runtime_authority.endpoint_security",
                    value: value.endpoint_security,
                });
            }
        }
        .map_err(|_| DecodeError::InvalidValue {
            field: "runtime_authority.endpoint",
        })?;
    protocol::JobRuntimeAuthority::new(
        protocol::RuntimeAuthorityName::new(value.name).map_err(|_| DecodeError::InvalidValue {
            field: "runtime_authority.name",
        })?,
        core::RunId::from_uuid(uuid(value.run_id, "runtime_authority.run_id")?),
        core::JobId::from_uuid(uuid(value.job_id, "runtime_authority.job_id")?),
        core::AttemptId::from_uuid(uuid(value.attempt_id, "runtime_authority.attempt_id")?),
        fencing_token(value.fencing_token, "runtime_authority.fencing_token")?,
        endpoint,
        protocol::RuntimeAuthorityCredential::new(value.credential).map_err(|_| {
            DecodeError::InvalidValue {
                field: "runtime_authority.credential",
            }
        })?,
        core::UnixMillis::new(value.issued_at_unix_millis),
        core::UnixMillis::new(value.expires_at_unix_millis),
    )
    .map_err(|_| DecodeError::InvalidValue {
        field: "runtime_authority",
    })
}

fn lease(value: wire::Lease) -> Result<core::Lease, DecodeError> {
    check_schema(
        value.schema_version,
        core::CORE_SCHEMA_VERSION,
        "lease.schema_version",
    )?;
    core::Lease::new(
        core::LeaseId::from_uuid(uuid(value.lease_id, "lease.lease_id")?),
        core::AttemptId::from_uuid(uuid(value.attempt_id, "lease.attempt_id")?),
        core::RunnerId::from_uuid(uuid(value.runner_id, "lease.runner_id")?),
        fencing_token(value.fencing_token, "lease.fencing_token")?,
        core::UnixMillis::new(value.issued_at_unix_millis),
        core::UnixMillis::new(value.expires_at_unix_millis),
    )
    .map_err(|_| DecodeError::InvalidValue { field: "lease" })
}

fn lease_guard(value: wire::LeaseGuard) -> Result<core::LeaseGuard, DecodeError> {
    Ok(core::LeaseGuard::new(
        core::LeaseId::from_uuid(uuid(value.lease_id, "lease_guard.lease_id")?),
        fencing_token(value.fencing_token, "lease_guard.fencing_token")?,
    ))
}

fn lease_response(value: wire::LeaseResponse) -> Result<protocol::LeaseResponse, DecodeError> {
    Ok(protocol::LeaseResponse::new(
        message_header(required(value.header, "lease_response.header")?)?,
        core::AttemptId::from_uuid(uuid(value.attempt_id, "lease_response.attempt_id")?),
        runner_slot(value.slot, "lease_response.slot")?,
        lease_guard(required(value.guard, "lease_response.guard")?)?,
        lease_disposition(required(value.disposition, "lease_response.disposition")?)?,
    ))
}

fn lease_disposition(
    value: wire::LeaseDisposition,
) -> Result<protocol::LeaseDisposition, DecodeError> {
    use wire::lease_disposition::Value;
    match required_variant(value.value, "lease_disposition.value")? {
        Value::Accepted(_) => Ok(protocol::LeaseDisposition::Accepted),
        Value::Rejected(reason) => {
            lease_rejection_reason(reason).map(protocol::LeaseDisposition::Rejected)
        }
    }
}

fn lease_rejection_reason(value: i32) -> Result<protocol::LeaseRejectionReason, DecodeError> {
    match wire::LeaseRejectionReason::try_from(value) {
        Ok(wire::LeaseRejectionReason::CapacityChanged) => {
            Ok(protocol::LeaseRejectionReason::CapacityChanged)
        }
        Ok(wire::LeaseRejectionReason::CapabilityChanged) => {
            Ok(protocol::LeaseRejectionReason::CapabilityChanged)
        }
        Ok(wire::LeaseRejectionReason::ShuttingDown) => {
            Ok(protocol::LeaseRejectionReason::ShuttingDown)
        }
        Ok(wire::LeaseRejectionReason::InvalidJob) => {
            Ok(protocol::LeaseRejectionReason::InvalidJob)
        }
        Ok(wire::LeaseRejectionReason::Unspecified) | Err(_) => Err(DecodeError::UnknownEnum {
            field: "lease_disposition.rejected",
            value,
        }),
    }
}

fn lease_heartbeat(value: wire::LeaseHeartbeat) -> Result<protocol::LeaseHeartbeat, DecodeError> {
    Ok(protocol::LeaseHeartbeat::new(
        message_header(required(value.header, "lease_heartbeat.header")?)?,
        core::AttemptId::from_uuid(uuid(value.attempt_id, "lease_heartbeat.attempt_id")?),
        lease_guard(required(value.guard, "lease_heartbeat.guard")?)?,
        job_lifecycle(value.lifecycle, "lease_heartbeat.lifecycle")?,
        core::UnixMillis::new(value.sent_at_unix_millis),
    ))
}

fn lease_renewal(value: wire::LeaseRenewal) -> Result<protocol::LeaseRenewal, DecodeError> {
    Ok(protocol::LeaseRenewal::new(
        message_header(required(value.header, "lease_renewal.header")?)?,
        core::AttemptId::from_uuid(uuid(value.attempt_id, "lease_renewal.attempt_id")?),
        lease_guard(required(value.guard, "lease_renewal.guard")?)?,
        core::UnixMillis::new(value.expires_at_unix_millis),
    ))
}

fn job_state_update(value: wire::JobStateUpdate) -> Result<protocol::JobStateUpdate, DecodeError> {
    Ok(protocol::JobStateUpdate::new(
        message_header(required(value.header, "job_state_update.header")?)?,
        core::AttemptId::from_uuid(uuid(value.attempt_id, "job_state_update.attempt_id")?),
        lease_guard(required(value.guard, "job_state_update.guard")?)?,
        job_lifecycle(value.lifecycle, "job_state_update.lifecycle")?,
        core::UnixMillis::new(value.occurred_at_unix_millis),
    ))
}

fn job_lifecycle(value: i32, field: &'static str) -> Result<core::JobLifecycle, DecodeError> {
    match wire::JobLifecycle::try_from(value) {
        Ok(wire::JobLifecycle::Queued) => Ok(core::JobLifecycle::Queued),
        Ok(wire::JobLifecycle::Leased) => Ok(core::JobLifecycle::Leased),
        Ok(wire::JobLifecycle::Preparing) => Ok(core::JobLifecycle::Preparing),
        Ok(wire::JobLifecycle::Running) => Ok(core::JobLifecycle::Running),
        Ok(wire::JobLifecycle::Cancelling) => Ok(core::JobLifecycle::Cancelling),
        Ok(wire::JobLifecycle::Finalizing) => Ok(core::JobLifecycle::Finalizing),
        Ok(wire::JobLifecycle::Succeeded) => Ok(core::JobLifecycle::Succeeded),
        Ok(wire::JobLifecycle::Failed) => Ok(core::JobLifecycle::Failed),
        Ok(wire::JobLifecycle::Cancelled) => Ok(core::JobLifecycle::Cancelled),
        Ok(wire::JobLifecycle::TimedOut) => Ok(core::JobLifecycle::TimedOut),
        Ok(wire::JobLifecycle::Skipped) => Ok(core::JobLifecycle::Skipped),
        Ok(wire::JobLifecycle::Lost) => Ok(core::JobLifecycle::Lost),
        Ok(wire::JobLifecycle::Unspecified) | Err(_) => {
            Err(DecodeError::UnknownEnum { field, value })
        }
    }
}

fn cancel_job(value: wire::CancelJob) -> Result<protocol::CancelJob, DecodeError> {
    Ok(protocol::CancelJob::new(
        server_command_header(required(value.header, "cancel_job.header")?)?,
        core::AttemptId::from_uuid(uuid(value.attempt_id, "cancel_job.attempt_id")?),
        lease_guard(required(value.guard, "cancel_job.guard")?)?,
        value.reason,
        core::UnixMillis::new(value.requested_at_unix_millis),
    ))
}

fn job_ir_envelope(
    value: wire::JobIrEnvelope,
    limits: &protocol::ProtocolLimits,
) -> Result<core::JobIrEnvelope, DecodeError> {
    check_schema(
        value.schema_version,
        core::JOB_IR_SCHEMA_VERSION,
        "job_ir_envelope.schema_version",
    )?;
    Ok(core::JobIrEnvelope::new(
        core::WorkflowId::from_uuid(uuid(value.workflow_id, "job_ir_envelope.workflow_id")?),
        job_source(required(value.source, "job_ir_envelope.source")?)?,
        job_execution_context(required(value.execution, "job_ir_envelope.execution")?)?,
        job_ir(required(value.job, "job_ir_envelope.job")?, limits)?,
    ))
}

fn job_source(value: wire::JobSource) -> Result<core::JobSource, DecodeError> {
    Ok(core::JobSource::new(
        value.provider,
        value.repository,
        git_object_id(&required(value.revision, "job_source.revision")?)?,
        value.workflow_path,
        value.event_name,
    ))
}

fn git_object_id(value: &wire::GitObjectId) -> Result<core::GitObjectId, DecodeError> {
    let algorithm = match wire::GitObjectAlgorithm::try_from(value.algorithm) {
        Ok(wire::GitObjectAlgorithm::Sha1) => core::GitObjectAlgorithm::Sha1,
        Ok(wire::GitObjectAlgorithm::Sha256) => core::GitObjectAlgorithm::Sha256,
        Ok(wire::GitObjectAlgorithm::Unspecified) | Err(_) => {
            return Err(DecodeError::UnknownEnum {
                field: "git_object_id.algorithm",
                value: value.algorithm,
            });
        }
    };
    core::GitObjectId::from_bytes(algorithm, &value.digest).map_err(|_| DecodeError::InvalidValue {
        field: "git_object_id.digest",
    })
}

fn job_execution_context(
    value: wire::JobExecutionContext,
) -> Result<core::JobExecutionContext, DecodeError> {
    let mut context = core::JobExecutionContext::new(
        value.workflow_name,
        value.git_ref,
        value.workspace,
        job_content_reference(required(value.event, "job_execution_context.event")?)?,
        job_content_reference(required(
            value.runtime_context,
            "job_execution_context.runtime_context",
        )?)?,
    );
    if let Some(actor) = value.actor {
        context = context.with_actor(actor);
    }
    if let Some(actor) = value.triggering_actor {
        context = context.with_triggering_actor(actor);
    }
    if let Some(run_id_alias) = value.run_id_alias {
        context = context.with_run_id_alias(core::RunIdAlias::new(run_id_alias).map_err(|_| {
            DecodeError::InvalidValue {
                field: "job_execution_context.run_id_alias",
            }
        })?);
    }
    if let Some(run_number) = value.run_number {
        context = context.with_run_number(run_number);
    }
    if let Some(run_attempt) = value.run_attempt {
        context = context.with_run_attempt(run_attempt);
    }
    Ok(context)
}

fn job_content_reference(
    value: wire::JobContentReference,
) -> Result<core::JobContentReference, DecodeError> {
    let digest = value
        .sha256
        .try_into()
        .map_err(|_| DecodeError::InvalidValue {
            field: "job_content_reference.sha256",
        })?;
    Ok(core::JobContentReference::new(
        value.object_key,
        core::Sha256Digest::from_bytes(digest),
        value.encoded_size,
        value.media_type,
    ))
}

fn job_runtime_context(
    value: wire::JobRuntimeContext,
    limits: &protocol::ProtocolLimits,
) -> Result<core::JobRuntimeContext, DecodeError> {
    check_schema(
        value.schema_version,
        core::JOB_RUNTIME_CONTEXT_SCHEMA_VERSION,
        "job_runtime_context.schema_version",
    )?;
    let maximum_nodes = limits
        .max_collection_items()
        .min(core::MAX_CONTEXT_VALUE_NODES);
    check_collection(
        value.nodes.len(),
        maximum_nodes,
        "job_runtime_context.nodes",
    )?;
    check_collection(
        value.needs.len(),
        limits.max_collection_items(),
        "job_runtime_context.needs",
    )?;
    check_collection(
        value.secrets.len(),
        limits.max_collection_items(),
        "job_runtime_context.secrets",
    )?;
    if value.nodes.len() < 3 {
        return Err(DecodeError::InvalidValue {
            field: "job_runtime_context.nodes",
        });
    }

    validate_context_tree(
        &value.nodes,
        [value.inputs_index, value.vars_index, value.matrix_index],
        limits,
    )?;
    let mut nodes = build_context_tree(value.nodes)?;
    let inputs = take_context_root(&mut nodes, value.inputs_index)?;
    let vars = take_context_root(&mut nodes, value.vars_index)?;
    let matrix = take_context_root(&mut nodes, value.matrix_index)?;

    ensure_canonical_keys(&value.needs, "job_runtime_context.needs", |entry| {
        entry.key.as_str()
    })?;
    let needs = value
        .needs
        .into_iter()
        .map(|entry| {
            Ok((
                entry.key,
                need_context_value(
                    required(entry.value, "job_runtime_context.need.value")?,
                    limits,
                )?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, DecodeError>>()?;

    ensure_canonical_keys(&value.secrets, "job_runtime_context.secrets", |entry| {
        entry.key.as_str()
    })?;
    let secrets = value
        .secrets
        .into_iter()
        .map(|entry| {
            Ok((
                entry.key,
                secret_binding_value(required(entry.value, "job_runtime_context.secret.value")?)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, DecodeError>>()?;

    core::JobRuntimeContext::new(
        inputs,
        vars,
        matrix,
        strategy_context_value(required(value.strategy, "job_runtime_context.strategy")?)?,
        needs,
        secrets,
    )
    .map_err(DecodeError::InvalidRuntimeContext)
}

fn validate_context_tree(
    nodes: &[wire::ContextValueNode],
    roots: [u32; 3],
    limits: &protocol::ProtocolLimits,
) -> Result<(), DecodeError> {
    let mut references = vec![0_u8; nodes.len()];
    for root in roots {
        charge_context_reference(&mut references, root, nodes.len())?;
    }
    for (parent, node) in nodes.iter().enumerate() {
        use wire::context_value_node::Value;
        match required_variant(node.value.as_ref(), "context_value_node.value")? {
            Value::Array(array) => {
                check_collection(
                    array.child_indices.len(),
                    limits.max_collection_items(),
                    "context_value_array.child_indices",
                )?;
                for child in &array.child_indices {
                    let child = context_index(*child, nodes.len())?;
                    if child >= parent {
                        return Err(DecodeError::NonCanonicalOrder {
                            field: "job_runtime_context.nodes",
                        });
                    }
                    charge_context_reference_index(&mut references, child)?;
                }
            }
            Value::Object(object) => {
                check_collection(
                    object.entries.len(),
                    limits.max_collection_items(),
                    "context_value_object.entries",
                )?;
                ensure_canonical_keys(&object.entries, "context_value_object.entries", |entry| {
                    entry.key.as_str()
                })?;
                for entry in &object.entries {
                    let child = context_index(entry.value_index, nodes.len())?;
                    if child >= parent {
                        return Err(DecodeError::NonCanonicalOrder {
                            field: "job_runtime_context.nodes",
                        });
                    }
                    charge_context_reference_index(&mut references, child)?;
                }
            }
            Value::Null(_)
            | Value::Boolean(_)
            | Value::NumberIeee754Bits(_)
            | Value::StringValue(_) => {}
        }
    }
    if references.iter().any(|count| *count != 1) {
        return Err(DecodeError::InvalidValue {
            field: "job_runtime_context.nodes",
        });
    }
    Ok(())
}

fn charge_context_reference(
    references: &mut [u8],
    index: u32,
    node_count: usize,
) -> Result<(), DecodeError> {
    let index = context_index(index, node_count)?;
    charge_context_reference_index(references, index)
}

fn charge_context_reference_index(references: &mut [u8], index: usize) -> Result<(), DecodeError> {
    let count = references.get_mut(index).ok_or(DecodeError::InvalidValue {
        field: "job_runtime_context.node_index",
    })?;
    *count = count.checked_add(1).ok_or(DecodeError::DuplicateEntry {
        field: "job_runtime_context.nodes",
    })?;
    if *count != 1 {
        return Err(DecodeError::DuplicateEntry {
            field: "job_runtime_context.nodes",
        });
    }
    Ok(())
}

fn context_index(index: u32, node_count: usize) -> Result<usize, DecodeError> {
    let index = usize::try_from(index).map_err(|_| DecodeError::IntegerOutOfRange {
        field: "job_runtime_context.node_index",
    })?;
    if index >= node_count {
        return Err(DecodeError::InvalidValue {
            field: "job_runtime_context.node_index",
        });
    }
    Ok(index)
}

fn build_context_tree(
    nodes: Vec<wire::ContextValueNode>,
) -> Result<Vec<Option<core::ContextValue>>, DecodeError> {
    let node_count = nodes.len();
    let mut values = Vec::with_capacity(node_count);
    for node in nodes {
        use wire::context_value_node::Value;
        let value = match required_variant(node.value, "context_value_node.value")? {
            Value::Null(_) => core::ContextValue::Null,
            Value::Boolean(value) => core::ContextValue::Boolean { value },
            Value::NumberIeee754Bits(ieee754_bits) => core::ContextValue::Number { ieee754_bits },
            Value::StringValue(value) => core::ContextValue::String { value },
            Value::Array(array) => core::ContextValue::Array {
                values: array
                    .child_indices
                    .into_iter()
                    .map(|index| take_context_value(&mut values, index, node_count))
                    .collect::<Result<Vec<_>, _>>()?,
            },
            Value::Object(object) => core::ContextValue::Object {
                values: object
                    .entries
                    .into_iter()
                    .map(|entry| {
                        Ok((
                            entry.key,
                            take_context_value(&mut values, entry.value_index, node_count)?,
                        ))
                    })
                    .collect::<Result<BTreeMap<_, _>, DecodeError>>()?,
            },
        };
        values.push(Some(value));
    }
    Ok(values)
}

fn take_context_value(
    values: &mut [Option<core::ContextValue>],
    index: u32,
    node_count: usize,
) -> Result<core::ContextValue, DecodeError> {
    let index = context_index(index, node_count)?;
    values
        .get_mut(index)
        .and_then(Option::take)
        .ok_or(DecodeError::InvalidValue {
            field: "job_runtime_context.nodes",
        })
}

fn take_context_root(
    values: &mut [Option<core::ContextValue>],
    index: u32,
) -> Result<core::ContextValue, DecodeError> {
    take_context_value(values, index, values.len())
}

fn strategy_context_value(
    value: wire::StrategyContext,
) -> Result<core::StrategyContext, DecodeError> {
    core::StrategyContext::new(
        value.fail_fast,
        value.job_index,
        value.job_total,
        value.max_parallel,
    )
    .map_err(DecodeError::InvalidRuntimeContext)
}

fn need_context_value(
    value: wire::NeedContext,
    limits: &protocol::ProtocolLimits,
) -> Result<core::NeedContext, DecodeError> {
    core::NeedContext::new(
        job_conclusion(value.result, "need_context.result")?,
        need_output_map(value.outputs, limits)?,
    )
    .map_err(DecodeError::InvalidRuntimeContext)
}

fn need_output_map(
    values: Vec<wire::NeedOutputEntry>,
    limits: &protocol::ProtocolLimits,
) -> Result<BTreeMap<String, core::NeedOutput>, DecodeError> {
    check_collection(
        values.len(),
        limits.max_collection_items(),
        "need_context.outputs",
    )?;
    ensure_canonical_keys(&values, "need_context.outputs", |entry| entry.key.as_str())?;
    values
        .into_iter()
        .map(|entry| {
            let output = required(entry.value, "need_output_entry.value")?;
            Ok((
                entry.key,
                core::NeedOutput::new(
                    output.value,
                    output_sensitivity(output.sensitivity, "need_output.sensitivity")?,
                )
                .map_err(DecodeError::InvalidRuntimeContext)?,
            ))
        })
        .collect()
}

fn output_sensitivity(
    value: i32,
    field: &'static str,
) -> Result<core::OutputSensitivity, DecodeError> {
    match wire::OutputSensitivity::try_from(value) {
        Ok(wire::OutputSensitivity::Public) => Ok(core::OutputSensitivity::Public),
        Ok(wire::OutputSensitivity::SecretDerived) => Ok(core::OutputSensitivity::SecretDerived),
        Ok(wire::OutputSensitivity::Unspecified) | Err(_) => {
            Err(DecodeError::UnknownEnum { field, value })
        }
    }
}

fn secret_binding_value(value: wire::SecretBinding) -> Result<core::SecretBinding, DecodeError> {
    let mut binding =
        core::SecretBinding::new(value.binding_id).map_err(DecodeError::InvalidRuntimeContext)?;
    if let Some(version_id) = value.version_id {
        binding = binding
            .with_version_id(version_id)
            .map_err(DecodeError::InvalidRuntimeContext)?;
    }
    Ok(binding)
}

fn job_ir(
    value: wire::JobIr,
    limits: &protocol::ProtocolLimits,
) -> Result<core::JobIr, DecodeError> {
    check_collection(
        value.environment.len(),
        limits.max_collection_items(),
        "job_ir.environment",
    )?;
    check_collection(
        value.services.len(),
        limits.max_collection_items(),
        "job_ir.services",
    )?;
    check_collection(
        value.steps.len(),
        limits.max_collection_items(),
        "job_ir.steps",
    )?;
    check_collection(
        value.outputs.len(),
        limits
            .max_collection_items()
            .min(core::MAX_JOB_OUTPUT_DEFINITIONS),
        "job_ir.outputs",
    )?;
    ensure_canonical_keys(&value.outputs, "job_ir.outputs", |entry| {
        entry.name.as_str()
    })?;
    let permission_request = job_permission_request(
        required(value.permission_request, "job_ir.permission_request")?,
        limits,
    )?;
    let authority_profile = job_authority_profile(required(
        value.authority_profile,
        "job_ir.authority_profile",
    )?)?;
    let trust_snapshot_digest =
        value
            .trust_snapshot_digest
            .try_into()
            .map_err(|_| DecodeError::InvalidValue {
                field: "job_ir.trust_snapshot_digest",
            })?;
    let trust_snapshot = core::TrustSnapshot::from_canonical_bytes(
        &value.trust_snapshot,
        core::Sha256Digest::from_bytes(trust_snapshot_digest),
    )
    .map_err(|_| DecodeError::InvalidValue {
        field: "job_ir.trust_snapshot",
    })?;
    let environment = value_map(value.environment, limits, "job_ir.environment")?;
    let services = container_map(value.services, limits, "job_ir.services")?;
    let steps = value
        .steps
        .into_iter()
        .map(|item| step_ir(item, limits))
        .collect::<Result<Vec<_>, _>>()?;
    let mut job = core::JobIr::new(
        core::JobId::from_uuid(uuid(value.job_id, "job_ir.job_id")?),
        core::RunId::from_uuid(uuid(value.run_id, "job_ir.run_id")?),
        value.name,
        runner_requirements(required(value.requirements, "job_ir.requirements")?, limits)?,
        job_instance_identity(required(value.instance, "job_ir.instance")?)?,
        value.continue_on_error,
        steps,
    )
    .with_authority_profile(authority_profile)
    .with_permission_request(permission_request)
    .with_trust_snapshot(trust_snapshot)
    .with_environment(environment)
    .with_services(services);
    if let Some(timeout) = value.timeout_seconds {
        job = job.with_timeout_seconds(timeout);
    }
    if let Some(directory) = value.working_directory {
        job = job.with_working_directory(value_template(directory, limits)?);
    }
    if let Some(container) = value.container {
        job = job.with_container(container_spec(container, limits)?);
    }
    let outputs = value
        .outputs
        .into_iter()
        .map(|output| {
            core::JobOutputDefinition::new(
                output.name,
                value_template(
                    required(output.value, "job_output_definition.value")?,
                    limits,
                )?,
                output_sensitivity(output.sensitivity, "job_output_definition.sensitivity")?,
            )
            .map_err(|_| DecodeError::InvalidValue {
                field: "job_output_definition",
            })
        })
        .collect::<Result<Vec<_>, DecodeError>>()?;
    if !outputs.is_empty() {
        job = job.with_output_definitions(outputs);
    }
    Ok(job)
}

fn job_authority_profile(value: i32) -> Result<core::JobAuthorityProfile, DecodeError> {
    match wire::JobAuthorityProfile::try_from(value) {
        Ok(wire::JobAuthorityProfile::Standard) => Ok(core::JobAuthorityProfile::Standard),
        Ok(wire::JobAuthorityProfile::CredentialFree) => {
            Ok(core::JobAuthorityProfile::CredentialFree)
        }
        Ok(wire::JobAuthorityProfile::Unspecified) | Err(_) => Err(DecodeError::InvalidValue {
            field: "job_ir.authority_profile",
        }),
    }
}

fn job_permission_request(
    value: wire::JobPermissionRequest,
    limits: &protocol::ProtocolLimits,
) -> Result<core::JobPermissionRequest, DecodeError> {
    use wire::job_permission_request::Request;

    match required_variant(value.request, "job_permission_request.request")? {
        Request::ProviderDefault(_) => Ok(core::JobPermissionRequest::ProviderDefault),
        Request::ReadAll(_) => Ok(core::JobPermissionRequest::ReadAll),
        Request::WriteAll(_) => Ok(core::JobPermissionRequest::WriteAll),
        Request::Mapping(mapping) => {
            check_collection(
                mapping.grants.len(),
                limits
                    .max_collection_items()
                    .min(core::MAX_JOB_PERMISSION_GRANTS),
                "job_permission_mapping.grants",
            )?;
            ensure_canonical_keys(&mapping.grants, "job_permission_mapping.grants", |grant| {
                grant.name.as_str()
            })?;
            let grants = mapping
                .grants
                .into_iter()
                .map(|grant| {
                    Ok(core::JobPermissionGrant::new(
                        grant.name,
                        permission_level(grant.level)?,
                    ))
                })
                .collect::<Result<Vec<_>, DecodeError>>()?;
            Ok(core::JobPermissionRequest::Mapping(grants))
        }
    }
}

fn permission_level(value: i32) -> Result<core::PermissionLevel, DecodeError> {
    match wire::PermissionLevel::try_from(value) {
        Ok(wire::PermissionLevel::Read) => Ok(core::PermissionLevel::Read),
        Ok(wire::PermissionLevel::Write) => Ok(core::PermissionLevel::Write),
        Ok(wire::PermissionLevel::None) => Ok(core::PermissionLevel::None),
        Ok(wire::PermissionLevel::Unspecified) | Err(_) => Err(DecodeError::UnknownEnum {
            field: "job_permission_grant.level",
            value,
        }),
    }
}

fn job_instance_identity(
    value: wire::JobInstanceIdentity,
) -> Result<core::JobInstanceIdentity, DecodeError> {
    let digest = value
        .matrix_digest
        .try_into()
        .map_err(|_| DecodeError::InvalidValue {
            field: "job_instance_identity.matrix_digest",
        })?;
    core::JobInstanceIdentity::new(
        value.logical_job_key,
        value.matrix_index,
        value.matrix_total,
        core::Sha256Digest::from_bytes(digest),
    )
    .map_err(|_| DecodeError::InvalidValue {
        field: "job_instance_identity",
    })
}

fn value_map(
    values: Vec<wire::ValueEntry>,
    limits: &protocol::ProtocolLimits,
    field: &'static str,
) -> Result<BTreeMap<String, core::ValueSource>, DecodeError> {
    check_collection(values.len(), limits.max_collection_items(), field)?;
    ensure_canonical_keys(&values, field, |entry| entry.key.as_str())?;
    values
        .into_iter()
        .map(|entry| {
            Ok((
                entry.key,
                value_source(required(entry.value, "value_entry.value")?, limits)?,
            ))
        })
        .collect()
}

fn value_source(
    value: wire::ValueSource,
    limits: &protocol::ProtocolLimits,
) -> Result<core::ValueSource, DecodeError> {
    use wire::value_source::Value;
    match required_variant(value.value, "value_source.value")? {
        Value::Literal(item) => Ok(core::ValueSource::Literal(item)),
        Value::Expression(item) => Ok(core::ValueSource::Expression(expression_program(
            item, limits,
        )?)),
        Value::SecretReference(item) => Ok(core::ValueSource::SecretReference(item)),
        Value::Template(item) => Ok(core::ValueSource::Template(value_template(item, limits)?)),
    }
}

fn value_template(
    value: wire::ValueTemplate,
    limits: &protocol::ProtocolLimits,
) -> Result<core::ValueTemplate, DecodeError> {
    check_collection(
        value.segments.len(),
        limits
            .max_collection_items()
            .min(core::MAX_VALUE_TEMPLATE_SEGMENTS),
        "value_template.segments",
    )?;
    let segments = value
        .segments
        .into_iter()
        .map(|segment| {
            use wire::value_template_segment::Value;
            match required_variant(segment.value, "value_template_segment.value")? {
                Value::Literal(value) => Ok(core::ValueTemplateSegment::literal(value)),
                Value::Expression(program) => Ok(core::ValueTemplateSegment::expression(
                    expression_program(program, limits)?,
                )),
            }
        })
        .collect::<Result<Vec<_>, DecodeError>>()?;
    core::ValueTemplate::new(segments).map_err(DecodeError::InvalidValueTemplate)
}

fn container_map(
    values: Vec<wire::ContainerEntry>,
    limits: &protocol::ProtocolLimits,
    field: &'static str,
) -> Result<BTreeMap<String, core::ContainerSpec>, DecodeError> {
    check_collection(values.len(), limits.max_collection_items(), field)?;
    ensure_canonical_keys(&values, field, |entry| entry.key.as_str())?;
    values
        .into_iter()
        .map(|entry| {
            Ok((
                entry.key,
                container_spec(required(entry.value, "container_entry.value")?, limits)?,
            ))
        })
        .collect()
}

fn step_ir(
    value: wire::StepIr,
    limits: &protocol::ProtocolLimits,
) -> Result<core::StepIr, DecodeError> {
    let mut step = core::StepIr::new(
        core::StepId::new(value.id).map_err(|_| DecodeError::InvalidValue {
            field: "step_ir.id",
        })?,
        value_template(required(value.name, "step_ir.name")?, limits)?,
        runtime_boolean(
            required(value.continue_on_error, "step_ir.continue_on_error")?,
            limits,
        )?,
        semantic_step(required(value.kind, "step_ir.kind")?, limits)?,
    )
    .with_environment(value_map(value.environment, limits, "step_ir.environment")?);
    if let Some(condition) = value.condition {
        step = step.with_condition(expression_program(condition, limits)?);
    }
    if let Some(timeout) = value.timeout {
        step = step.with_timeout(runtime_timeout_template(timeout, limits)?);
    }
    Ok(step)
}

fn runtime_timeout_template(
    value: wire::RuntimeTimeoutTemplate,
    limits: &protocol::ProtocolLimits,
) -> Result<core::RuntimeTimeoutTemplate, DecodeError> {
    let value_template = runtime_positive_integer(
        required(value.value, "runtime_timeout_template.value")?,
        limits,
    )?;
    match wire::RuntimeTimeoutUnit::try_from(value.unit) {
        Ok(wire::RuntimeTimeoutUnit::Seconds) => {
            Ok(core::RuntimeTimeoutTemplate::seconds(value_template))
        }
        Ok(wire::RuntimeTimeoutUnit::Minutes) => {
            Ok(core::RuntimeTimeoutTemplate::minutes(value_template))
        }
        Ok(wire::RuntimeTimeoutUnit::Unspecified) | Err(_) => Err(DecodeError::UnknownEnum {
            field: "runtime_timeout_template.unit",
            value: value.unit,
        }),
    }
}

fn runtime_positive_integer(
    value: wire::RuntimePositiveInteger,
    limits: &protocol::ProtocolLimits,
) -> Result<core::RuntimePositiveInteger, DecodeError> {
    use wire::runtime_positive_integer::Value;
    match required_variant(value.value, "runtime_positive_integer.value")? {
        Value::Literal(value) => Ok(core::RuntimePositiveInteger::literal(value)),
        Value::Expression(program) => Ok(core::RuntimePositiveInteger::expression(
            expression_program(program, limits)?,
        )),
    }
}

fn runtime_boolean(
    value: wire::RuntimeBoolean,
    limits: &protocol::ProtocolLimits,
) -> Result<core::RuntimeBoolean, DecodeError> {
    use wire::runtime_boolean::Value;
    match required_variant(value.value, "runtime_boolean.value")? {
        Value::Literal(value) => Ok(core::RuntimeBoolean::literal(value)),
        Value::Expression(program) => Ok(core::RuntimeBoolean::expression(expression_program(
            program, limits,
        )?)),
    }
}

fn expression_program(
    value: wire::ExpressionProgram,
    limits: &protocol::ProtocolLimits,
) -> Result<core::ExpressionProgram, DecodeError> {
    check_schema(
        value.schema_version,
        core::EXPRESSION_PROGRAM_SCHEMA_VERSION,
        "expression_program.schema_version",
    )?;
    check_collection(
        value.instructions.len(),
        limits
            .max_collection_items()
            .min(core::MAX_EXPRESSION_INSTRUCTIONS),
        "expression_program.instructions",
    )?;
    let dialect = required(value.dialect, "expression_program.dialect")?;
    let dialect = core::ExpressionDialect::new(
        dialect.name,
        narrow_u16(dialect.version, "expression_program.dialect.version")?,
    )
    .map_err(|_| DecodeError::InvalidValue {
        field: "expression_program.dialect",
    })?;
    let instructions = value
        .instructions
        .into_iter()
        .map(expression_instruction)
        .collect::<Result<Vec<_>, _>>()?;
    core::ExpressionProgram::new(dialect, value.source, instructions).map_err(|_| {
        DecodeError::InvalidValue {
            field: "expression_program",
        }
    })
}

fn expression_instruction(
    value: wire::ExpressionInstruction,
) -> Result<core::ExpressionInstruction, DecodeError> {
    use wire::expression_instruction::Value;
    match required_variant(value.value, "expression_instruction.value")? {
        Value::Literal(value) => Ok(core::ExpressionInstruction::Literal {
            value: expression_literal(value)?,
        }),
        Value::NamedValue(name) => Ok(core::ExpressionInstruction::NamedValue { name }),
        Value::Wildcard(_) => Ok(core::ExpressionInstruction::Wildcard),
        Value::Index(_) => Ok(core::ExpressionInstruction::Index),
        Value::Not(_) => Ok(core::ExpressionInstruction::Not),
        Value::Compare(value) => Ok(core::ExpressionInstruction::Compare {
            operator: expression_comparison(value.operator)?,
        }),
        Value::Logical(value) => Ok(core::ExpressionInstruction::Logical {
            operator: expression_logical(value.operator)?,
            operand_count: narrow_u16(
                value.operand_count,
                "expression_logical_instruction.operand_count",
            )?,
        }),
        Value::Call(value) => Ok(core::ExpressionInstruction::Call {
            name: value.name,
            argument_count: narrow_u16(
                value.argument_count,
                "expression_call_instruction.argument_count",
            )?,
        }),
    }
}

fn expression_literal(
    value: wire::ExpressionLiteral,
) -> Result<core::ExpressionLiteral, DecodeError> {
    use wire::expression_literal::Value;
    match required_variant(value.value, "expression_literal.value")? {
        Value::Null(_) => Ok(core::ExpressionLiteral::Null),
        Value::Boolean(value) => Ok(core::ExpressionLiteral::Boolean { value }),
        Value::NumberIeee754Bits(ieee754_bits) => {
            Ok(core::ExpressionLiteral::Number { ieee754_bits })
        }
        Value::StringValue(value) => Ok(core::ExpressionLiteral::String { value }),
    }
}

fn expression_comparison(value: i32) -> Result<core::ExpressionComparison, DecodeError> {
    match wire::ExpressionComparisonOperator::try_from(value) {
        Ok(wire::ExpressionComparisonOperator::Equal) => Ok(core::ExpressionComparison::Equal),
        Ok(wire::ExpressionComparisonOperator::NotEqual) => {
            Ok(core::ExpressionComparison::NotEqual)
        }
        Ok(wire::ExpressionComparisonOperator::GreaterThan) => {
            Ok(core::ExpressionComparison::GreaterThan)
        }
        Ok(wire::ExpressionComparisonOperator::GreaterThanOrEqual) => {
            Ok(core::ExpressionComparison::GreaterThanOrEqual)
        }
        Ok(wire::ExpressionComparisonOperator::LessThan) => {
            Ok(core::ExpressionComparison::LessThan)
        }
        Ok(wire::ExpressionComparisonOperator::LessThanOrEqual) => {
            Ok(core::ExpressionComparison::LessThanOrEqual)
        }
        Ok(wire::ExpressionComparisonOperator::Unspecified) | Err(_) => {
            Err(DecodeError::UnknownEnum {
                field: "expression_comparison_instruction.operator",
                value,
            })
        }
    }
}

fn expression_logical(value: i32) -> Result<core::ExpressionLogical, DecodeError> {
    match wire::ExpressionLogicalOperator::try_from(value) {
        Ok(wire::ExpressionLogicalOperator::And) => Ok(core::ExpressionLogical::And),
        Ok(wire::ExpressionLogicalOperator::Or) => Ok(core::ExpressionLogical::Or),
        Ok(wire::ExpressionLogicalOperator::Unspecified) | Err(_) => {
            Err(DecodeError::UnknownEnum {
                field: "expression_logical_instruction.operator",
                value,
            })
        }
    }
}

fn semantic_step(
    value: wire::SemanticStep,
    limits: &protocol::ProtocolLimits,
) -> Result<core::SemanticStep, DecodeError> {
    use wire::semantic_step::Value;
    match required_variant(value.value, "semantic_step.value")? {
        Value::Run(run) => run_step(run, limits),
        Value::Action(action) => Ok(core::SemanticStep::Action {
            reference: action_reference(required(action.reference, "action_step.reference")?)?,
            inputs: value_map(action.inputs, limits, "action_step.inputs")?,
        }),
    }
}

fn run_step(
    run: wire::RunStep,
    limits: &protocol::ProtocolLimits,
) -> Result<core::SemanticStep, DecodeError> {
    let mut values = core::RunValueTemplates::new(
        value_template(required(run.command, "run_step.command")?, limits)?,
        shell_template(required(run.shell, "run_step.shell")?, limits)?,
    );
    if let Some(working_directory) = run.working_directory {
        values = values.with_working_directory(value_template(working_directory, limits)?);
    }
    Ok(core::SemanticStep::run(values))
}

fn shell_template(
    value: wire::ShellTemplate,
    limits: &protocol::ProtocolLimits,
) -> Result<core::ShellTemplate, DecodeError> {
    use wire::shell_template::Value;
    match required_variant(value.value, "shell_template.value")? {
        Value::DefaultShell(_) => Ok(core::ShellTemplate::default_shell()),
        Value::Named(value) => Ok(core::ShellTemplate::named(value_template(value, limits)?)),
        Value::CommandTemplate(value) => Ok(core::ShellTemplate::command_template(value_template(
            value, limits,
        )?)),
        Value::Dynamic(value) => Ok(core::ShellTemplate::dynamic(value_template(value, limits)?)),
    }
}

fn action_reference(value: wire::ActionReference) -> Result<core::ActionReference, DecodeError> {
    use wire::action_reference::Value;
    match required_variant(value.value, "action_reference.value")? {
        Value::Repository(item) => Ok(core::ActionReference::Repository {
            repository: item.repository,
            selector: item.selector,
            subpath: item.subpath,
        }),
        Value::LocalPath(path) => Ok(core::ActionReference::Local { path }),
        Value::ContainerImage(image) => Ok(core::ActionReference::Container { image }),
    }
}

fn container_spec(
    value: wire::ContainerSpec,
    limits: &protocol::ProtocolLimits,
) -> Result<core::ContainerSpec, DecodeError> {
    for (length, field) in [
        (value.environment.len(), "container_spec.environment"),
        (value.ports.len(), "container_spec.ports"),
        (value.volumes.len(), "container_spec.volumes"),
        (value.options.len(), "container_spec.options"),
    ] {
        check_collection(length, limits.max_collection_items(), field)?;
    }
    let environment = value_map(value.environment, limits, "container_spec.environment")?;
    let ports = value
        .ports
        .into_iter()
        .map(container_port)
        .collect::<Result<Vec<_>, _>>()?;
    let volumes = value
        .volumes
        .into_iter()
        .map(volume_mount)
        .collect::<Result<Vec<_>, _>>()?;
    let mut spec = core::ContainerSpec::new(value.image)
        .with_environment(environment)
        .with_ports(ports)
        .with_volumes(volumes)
        .with_options(value.options);
    if let Some(credentials) = value.credentials {
        spec = spec.with_credentials(container_credentials(credentials, limits)?);
    }
    Ok(spec)
}

fn container_credentials(
    value: wire::ContainerCredentials,
    limits: &protocol::ProtocolLimits,
) -> Result<core::ContainerCredentials, DecodeError> {
    Ok(core::ContainerCredentials::new(
        value_source(
            required(value.username, "container_credentials.username")?,
            limits,
        )?,
        value_source(
            required(value.password, "container_credentials.password")?,
            limits,
        )?,
    ))
}

fn container_port(value: wire::ContainerPort) -> Result<core::ContainerPort, DecodeError> {
    Ok(core::ContainerPort::new(
        narrow_u16(value.container_port, "container_port.container_port")?,
        value
            .requested_host_port
            .map(|port| narrow_u16(port, "container_port.requested_host_port"))
            .transpose()?,
        transport_protocol(value.protocol)?,
    ))
}

fn transport_protocol(value: i32) -> Result<core::TransportProtocol, DecodeError> {
    match wire::TransportProtocol::try_from(value) {
        Ok(wire::TransportProtocol::Tcp) => Ok(core::TransportProtocol::Tcp),
        Ok(wire::TransportProtocol::Udp) => Ok(core::TransportProtocol::Udp),
        Ok(wire::TransportProtocol::Unspecified) | Err(_) => Err(DecodeError::UnknownEnum {
            field: "container_port.protocol",
            value,
        }),
    }
}

fn volume_mount(value: wire::VolumeMount) -> Result<core::VolumeMount, DecodeError> {
    Ok(core::VolumeMount::new(
        mount_source(required(value.source, "volume_mount.source")?)?,
        value.target,
        value.read_only,
    ))
}

fn mount_source(value: wire::MountSource) -> Result<core::MountSource, DecodeError> {
    use wire::mount_source::Value;
    match required_variant(value.value, "mount_source.value")? {
        Value::WorkspaceRelative(item) => Ok(core::MountSource::WorkspaceRelative(item)),
        Value::TemporaryVolume(item) => Ok(core::MountSource::TemporaryVolume(item)),
        Value::HostPath(item) => Ok(core::MountSource::HostPath(item)),
    }
}

fn job_result_message(
    value: wire::JobResultMessage,
    limits: &protocol::ProtocolLimits,
) -> Result<protocol::JobResultMessage, DecodeError> {
    Ok(protocol::JobResultMessage::new(
        message_header(required(value.header, "job_result_message.header")?)?,
        lease_guard(required(value.guard, "job_result_message.guard")?)?,
        job_result(required(value.result, "job_result_message.result")?, limits)?,
    ))
}

fn job_result(
    value: wire::JobResult,
    limits: &protocol::ProtocolLimits,
) -> Result<core::JobResult, DecodeError> {
    check_schema(
        value.schema_version,
        core::CORE_SCHEMA_VERSION,
        "job_result.schema_version",
    )?;
    check_collection(
        value.outputs.len(),
        limits.max_collection_items(),
        "job_result.outputs",
    )?;
    check_collection(
        value.steps.len(),
        limits.max_collection_items(),
        "job_result.steps",
    )?;
    let outputs = job_result_output_map(value.outputs, limits)?;
    let steps = value
        .steps
        .into_iter()
        .map(|step| step_result(step, limits))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(core::JobResult::new(
        core::AttemptId::from_uuid(uuid(value.attempt_id, "job_result.attempt_id")?),
        job_conclusion(value.conclusion, "job_result.conclusion")?,
        job_secret_exposure(value.secret_exposure, "job_result.secret_exposure")?,
        core::UnixMillis::new(value.completed_at_unix_millis),
    )
    .with_outputs(outputs)
    .with_steps(steps))
}

fn job_result_output_map(
    values: Vec<wire::JobResultOutputEntry>,
    limits: &protocol::ProtocolLimits,
) -> Result<BTreeMap<String, core::JobResultOutput>, DecodeError> {
    check_collection(
        values.len(),
        limits.max_collection_items(),
        "job_result.outputs",
    )?;
    ensure_canonical_keys(&values, "job_result.outputs", |entry| entry.key.as_str())?;
    values
        .into_iter()
        .map(|entry| {
            let output = required(entry.value, "job_result_output_entry.value")?;
            let sensitivity =
                output_sensitivity(output.sensitivity, "job_result_output.sensitivity")?;
            let output = match (sensitivity, output.value) {
                (core::OutputSensitivity::Public, Some(value)) => {
                    core::JobResultOutput::public(value).map_err(|_| DecodeError::InvalidValue {
                        field: "job_result_output.value",
                    })?
                }
                (core::OutputSensitivity::Public, None) => {
                    return Err(DecodeError::MissingField {
                        field: "job_result_output.value",
                    });
                }
                (core::OutputSensitivity::SecretDerived, None) => {
                    core::JobResultOutput::secret_derived()
                }
                (core::OutputSensitivity::SecretDerived, Some(_)) => {
                    return Err(DecodeError::InvalidValue {
                        field: "job_result_output.value",
                    });
                }
            };
            Ok((entry.key, output))
        })
        .collect()
}

fn job_conclusion(value: i32, field: &'static str) -> Result<core::JobConclusion, DecodeError> {
    match wire::JobConclusion::try_from(value) {
        Ok(wire::JobConclusion::Success) => Ok(core::JobConclusion::Success),
        Ok(wire::JobConclusion::Failure) => Ok(core::JobConclusion::Failure),
        Ok(wire::JobConclusion::Cancelled) => Ok(core::JobConclusion::Cancelled),
        Ok(wire::JobConclusion::TimedOut) => Ok(core::JobConclusion::TimedOut),
        Ok(wire::JobConclusion::Skipped) => Ok(core::JobConclusion::Skipped),
        Ok(wire::JobConclusion::Unspecified) | Err(_) => {
            Err(DecodeError::UnknownEnum { field, value })
        }
    }
}

fn job_secret_exposure(
    value: i32,
    field: &'static str,
) -> Result<core::JobSecretExposure, DecodeError> {
    match wire::JobSecretExposure::try_from(value) {
        Ok(wire::JobSecretExposure::Secretless) => Ok(core::JobSecretExposure::Secretless),
        Ok(wire::JobSecretExposure::CapabilityOnly) => Ok(core::JobSecretExposure::CapabilityOnly),
        Ok(wire::JobSecretExposure::ReadableSecret) => Ok(core::JobSecretExposure::ReadableSecret),
        Ok(wire::JobSecretExposure::Unspecified) | Err(_) => {
            Err(DecodeError::UnknownEnum { field, value })
        }
    }
}

fn step_result(
    value: wire::StepResult,
    limits: &protocol::ProtocolLimits,
) -> Result<core::StepResult, DecodeError> {
    check_collection(
        value.annotations.len(),
        limits.max_collection_items(),
        "step_result.annotations",
    )?;
    let annotations = value
        .annotations
        .into_iter()
        .map(|annotation| step_annotation(annotation, limits))
        .collect::<Result<Vec<_>, _>>()?;
    let mut result = core::StepResult::new(
        core::StepId::new(value.step_id).map_err(|_| DecodeError::InvalidValue {
            field: "step_result.step_id",
        })?,
        job_conclusion(value.outcome, "step_result.outcome")?,
        job_conclusion(value.conclusion, "step_result.conclusion")?,
        core::UnixMillis::new(value.started_at_unix_millis),
        core::UnixMillis::new(value.completed_at_unix_millis),
    )
    .with_annotations(annotations);
    if let Some(summary) = value.summary_markdown {
        result = result.with_summary_markdown(summary);
    }
    Ok(result)
}

fn step_annotation(
    value: wire::StepAnnotation,
    limits: &protocol::ProtocolLimits,
) -> Result<core::StepAnnotation, DecodeError> {
    check_collection(
        value.properties.len(),
        limits.max_collection_items(),
        "step_annotation.properties",
    )?;
    let level = match wire::StepAnnotationLevel::try_from(value.level) {
        Ok(wire::StepAnnotationLevel::Error) => core::StepAnnotationLevel::Error,
        Ok(wire::StepAnnotationLevel::Warning) => core::StepAnnotationLevel::Warning,
        Ok(wire::StepAnnotationLevel::Notice) => core::StepAnnotationLevel::Notice,
        Ok(wire::StepAnnotationLevel::Unspecified) | Err(_) => {
            return Err(DecodeError::UnknownEnum {
                field: "step_annotation.level",
                value: value.level,
            });
        }
    };
    Ok(core::StepAnnotation::new(
        level,
        value.message,
        value
            .properties
            .into_iter()
            .map(|property| core::StepAnnotationProperty::new(property.name, property.value))
            .collect(),
    ))
}

fn string_map(
    values: Vec<wire::StringEntry>,
    limits: &protocol::ProtocolLimits,
    field: &'static str,
) -> Result<BTreeMap<String, String>, DecodeError> {
    check_collection(values.len(), limits.max_collection_items(), field)?;
    ensure_canonical_keys(&values, field, |entry| entry.key.as_str())?;
    Ok(values
        .into_iter()
        .map(|entry| (entry.key, entry.value))
        .collect())
}

fn log_batch(
    value: wire::LogBatch,
    limits: &protocol::ProtocolLimits,
) -> Result<protocol::LogBatch, DecodeError> {
    check_collection(
        value.frames.len(),
        limits.max_log_frames_per_batch(),
        "log_batch.frames",
    )?;
    let payload_bytes = value.frames.iter().try_fold(0_usize, |total, frame| {
        let payload = match frame.record.as_ref() {
            Some(wire::log_frame::Record::Output(output)) => output.payload.len(),
            Some(
                wire::log_frame::Record::GroupStarted(_)
                | wire::log_frame::Record::GroupFinished(_)
                | wire::log_frame::Record::StreamFinished(_),
            )
            | None => 0,
        };
        total.checked_add(payload).ok_or(DecodeError::InvalidValue {
            field: "log_batch.payload_bytes",
        })
    })?;
    if payload_bytes > limits.max_log_payload_bytes_per_batch() {
        return Err(DecodeError::LogPayloadTooLarge {
            size: payload_bytes,
            maximum: limits.max_log_payload_bytes_per_batch(),
        });
    }
    let frames = value
        .frames
        .into_iter()
        .map(log_frame)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(protocol::LogBatch::new(
        message_header(required(value.header, "log_batch.header")?)?,
        lease_guard(required(value.guard, "log_batch.guard")?)?,
        frames,
    ))
}

fn log_frame(value: wire::LogFrame) -> Result<core::LogFrame, DecodeError> {
    check_schema(
        value.schema_version,
        core::LOG_SCHEMA_VERSION,
        "log_frame.schema_version",
    )?;
    let stream_id = core::LogStreamId::from_uuid(uuid(value.stream_id, "log_frame.stream_id")?);
    let attempt_id = core::AttemptId::from_uuid(uuid(value.attempt_id, "log_frame.attempt_id")?);
    let sequence = core::LogSequence::new(value.sequence);
    let emitted_at = core::UnixMillis::new(value.emitted_at_unix_millis);
    match required(value.record, "log_frame.record")? {
        wire::log_frame::Record::GroupStarted(group) => core::LogFrame::group_started(
            stream_id,
            attempt_id,
            sequence,
            emitted_at,
            log_group(group)?,
        ),
        wire::log_frame::Record::Output(output) => core::LogFrame::output(
            stream_id,
            attempt_id,
            sequence,
            emitted_at,
            log_group_id(output.group_id)?,
            log_channel(output.channel)?,
            output.payload,
        ),
        wire::log_frame::Record::GroupFinished(group) => core::LogFrame::group_finished(
            stream_id,
            attempt_id,
            sequence,
            emitted_at,
            log_group_id(group.group_id)?,
            job_conclusion(group.conclusion, "log_frame.group_finished.conclusion")?,
        ),
        wire::log_frame::Record::StreamFinished(_) => {
            core::LogFrame::stream_finished(stream_id, attempt_id, sequence, emitted_at)
        }
    }
    .map_err(|_| DecodeError::InvalidValue { field: "log_frame" })
}

fn log_group(value: wire::LogGroup) -> Result<core::LogGroup, DecodeError> {
    core::LogGroup::new(
        log_group_id(value.id)?,
        value.parent_id.map(log_group_id).transpose()?,
        value.name,
        log_group_kind(value.kind)?,
        value.ordinal,
    )
    .map_err(|_| DecodeError::InvalidValue {
        field: "log_frame.group_started",
    })
}

fn log_group_id(value: String) -> Result<core::LogGroupId, DecodeError> {
    core::LogGroupId::new(value).map_err(|_| DecodeError::InvalidValue {
        field: "log_frame.group_id",
    })
}

fn log_group_kind(value: i32) -> Result<core::LogGroupKind, DecodeError> {
    match wire::LogGroupKind::try_from(value) {
        Ok(wire::LogGroupKind::Setup) => Ok(core::LogGroupKind::Setup),
        Ok(wire::LogGroupKind::Step) => Ok(core::LogGroupKind::Step),
        Ok(wire::LogGroupKind::ActionPre) => Ok(core::LogGroupKind::ActionPre),
        Ok(wire::LogGroupKind::ActionPost) => Ok(core::LogGroupKind::ActionPost),
        Ok(wire::LogGroupKind::Cleanup) => Ok(core::LogGroupKind::Cleanup),
        Ok(wire::LogGroupKind::Unspecified) | Err(_) => Err(DecodeError::UnknownEnum {
            field: "log_frame.group_kind",
            value,
        }),
    }
}

fn log_channel(value: i32) -> Result<core::LogChannel, DecodeError> {
    match wire::LogChannel::try_from(value) {
        Ok(wire::LogChannel::Stdout) => Ok(core::LogChannel::Stdout),
        Ok(wire::LogChannel::Stderr) => Ok(core::LogChannel::Stderr),
        Ok(wire::LogChannel::System) => Ok(core::LogChannel::System),
        Ok(wire::LogChannel::Unspecified) | Err(_) => Err(DecodeError::UnknownEnum {
            field: "log_frame.channel",
            value,
        }),
    }
}

fn log_ack_message(value: wire::LogAckMessage) -> Result<protocol::LogAckMessage, DecodeError> {
    Ok(protocol::LogAckMessage::new(
        message_header(required(value.header, "log_ack_message.header")?)?,
        log_ack(required(value.ack, "log_ack_message.ack")?)?,
    ))
}

fn log_ack(value: wire::LogAck) -> Result<core::LogAck, DecodeError> {
    check_schema(
        value.schema_version,
        core::LOG_SCHEMA_VERSION,
        "log_ack.schema_version",
    )?;
    Ok(core::LogAck::new(
        core::LogStreamId::from_uuid(uuid(value.stream_id, "log_ack.stream_id")?),
        value.contiguous_through.map(core::LogSequence::new),
    ))
}

fn command_ack(value: wire::CommandAck) -> Result<protocol::CommandAck, DecodeError> {
    Ok(protocol::CommandAck::new(
        message_header(required(value.header, "command_ack.header")?)?,
        command_cursor(required(
            value.command_cursor,
            "command_ack.command_cursor",
        )?)?,
    ))
}

fn operation_ack(value: wire::OperationAck) -> Result<protocol::OperationAck, DecodeError> {
    Ok(protocol::OperationAck::new(message_header(required(
        value.header,
        "operation_ack.header",
    )?)?))
}

fn no_work(value: wire::NoWork) -> Result<protocol::NoWork, DecodeError> {
    Ok(protocol::NoWork::new(
        message_header(required(value.header, "no_work.header")?)?,
        value.retry_after_millis,
    ))
}

fn error_message(
    value: wire::ErrorMessage,
    limits: &protocol::ProtocolLimits,
) -> Result<protocol::ErrorMessage, DecodeError> {
    let details = string_map(value.details, limits, "error_message.details")?;
    Ok(protocol::ErrorMessage::new(
        message_header(required(value.header, "error_message.header")?)?,
        remote_error_code(value.code)?,
        value.message,
        value.retryable,
    )
    .with_details(details))
}

fn remote_error_code(value: i32) -> Result<protocol::RemoteErrorCode, DecodeError> {
    match wire::RemoteErrorCode::try_from(value) {
        Ok(wire::RemoteErrorCode::InvalidMessage) => Ok(protocol::RemoteErrorCode::InvalidMessage),
        Ok(wire::RemoteErrorCode::UnsupportedProtocol) => {
            Ok(protocol::RemoteErrorCode::UnsupportedProtocol)
        }
        Ok(wire::RemoteErrorCode::UnsupportedJobIr) => {
            Ok(protocol::RemoteErrorCode::UnsupportedJobIr)
        }
        Ok(wire::RemoteErrorCode::Unauthenticated) => {
            Ok(protocol::RemoteErrorCode::Unauthenticated)
        }
        Ok(wire::RemoteErrorCode::Unauthorized) => Ok(protocol::RemoteErrorCode::Unauthorized),
        Ok(wire::RemoteErrorCode::SessionNotFound) => {
            Ok(protocol::RemoteErrorCode::SessionNotFound)
        }
        Ok(wire::RemoteErrorCode::StaleSession) => Ok(protocol::RemoteErrorCode::StaleSession),
        Ok(wire::RemoteErrorCode::InvalidSlot) => Ok(protocol::RemoteErrorCode::InvalidSlot),
        Ok(wire::RemoteErrorCode::OperationKeyReused) => {
            Ok(protocol::RemoteErrorCode::OperationKeyReused)
        }
        Ok(wire::RemoteErrorCode::CommandCursorConflict) => {
            Ok(protocol::RemoteErrorCode::CommandCursorConflict)
        }
        Ok(wire::RemoteErrorCode::LeaseNotFound) => Ok(protocol::RemoteErrorCode::LeaseNotFound),
        Ok(wire::RemoteErrorCode::StaleFencingToken) => {
            Ok(protocol::RemoteErrorCode::StaleFencingToken)
        }
        Ok(wire::RemoteErrorCode::Conflict) => Ok(protocol::RemoteErrorCode::Conflict),
        Ok(wire::RemoteErrorCode::RetryLater) => Ok(protocol::RemoteErrorCode::RetryLater),
        Ok(wire::RemoteErrorCode::Internal) => Ok(protocol::RemoteErrorCode::Internal),
        Ok(wire::RemoteErrorCode::Unspecified) | Err(_) => Err(DecodeError::UnknownEnum {
            field: "error_message.code",
            value,
        }),
    }
}

fn runner_slot(
    value: u32,
    field: &'static str,
) -> Result<protocol::RunnerSlotOrdinal, DecodeError> {
    protocol::RunnerSlotOrdinal::new(narrow_u16(value, field)?)
        .map_err(|_| DecodeError::InvalidValue { field })
}

fn fencing_token(value: u64, field: &'static str) -> Result<core::FencingToken, DecodeError> {
    core::FencingToken::new(value).map_err(|_| DecodeError::InvalidValue { field })
}

fn uuid(value: impl AsRef<[u8]>, field: &'static str) -> Result<Uuid, DecodeError> {
    let value = value.as_ref();
    if value.len() != 16 {
        return Err(DecodeError::InvalidUuidLength {
            field,
            received: value.len(),
        });
    }
    Uuid::from_slice(value).map_err(|_| DecodeError::InvalidValue { field })
}

fn narrow_u16(value: u32, field: &'static str) -> Result<u16, DecodeError> {
    u16::try_from(value).map_err(|_| DecodeError::IntegerOutOfRange { field })
}

fn check_schema(received: u32, supported: u16, field: &'static str) -> Result<(), DecodeError> {
    if received == u32::from(supported) {
        Ok(())
    } else {
        Err(DecodeError::UnsupportedSchema {
            field,
            received,
            supported: u32::from(supported),
        })
    }
}

fn check_collection(length: usize, maximum: usize, field: &'static str) -> Result<(), DecodeError> {
    if length > maximum {
        Err(DecodeError::CollectionTooLarge {
            field,
            length,
            maximum,
        })
    } else {
        Ok(())
    }
}

fn ensure_canonical_strings(values: &[String], field: &'static str) -> Result<(), DecodeError> {
    ensure_order(values.windows(2).map(|pair| pair[0].cmp(&pair[1])), field)
}

fn ensure_canonical_environment_profiles(
    values: &[wire::EnvironmentProfile],
    field: &'static str,
) -> Result<(), DecodeError> {
    ensure_order(
        values.windows(2).map(|pair| {
            pair[0]
                .id
                .cmp(&pair[1].id)
                .then_with(|| pair[0].sha256_digest.cmp(&pair[1].sha256_digest))
        }),
        field,
    )
}

fn ensure_canonical_keys<T, F>(values: &[T], field: &'static str, key: F) -> Result<(), DecodeError>
where
    F: Fn(&T) -> &str,
{
    ensure_order(
        values
            .windows(2)
            .map(|pair| key(&pair[0]).cmp(key(&pair[1]))),
        field,
    )
}

fn ensure_order(
    comparisons: impl IntoIterator<Item = Ordering>,
    field: &'static str,
) -> Result<(), DecodeError> {
    for ordering in comparisons {
        match ordering {
            Ordering::Less => {}
            Ordering::Equal => return Err(DecodeError::DuplicateEntry { field }),
            Ordering::Greater => return Err(DecodeError::NonCanonicalOrder { field }),
        }
    }
    Ok(())
}

fn required<T>(value: Option<T>, field: &'static str) -> Result<T, DecodeError> {
    value.ok_or(DecodeError::MissingField { field })
}

fn required_variant<T>(value: Option<T>, field: &'static str) -> Result<T, DecodeError> {
    value.ok_or(DecodeError::MissingVariant { field })
}
