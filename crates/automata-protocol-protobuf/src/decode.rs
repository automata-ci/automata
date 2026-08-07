//! Size-first protobuf-to-domain conversion.

use std::{cmp::Ordering, collections::BTreeMap};

use automata_core as core;
use automata_protocol as protocol;
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
    core::JobIrVersion::new(narrow_u16(value, field)?)
        .map_err(|_| DecodeError::InvalidValue { field })
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

    let labels = decode_labels(value.labels, "runner_requirements.labels")?;
    let groups = decode_groups(value.eligible_groups, "runner_requirements.eligible_groups")?;
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
        .with_minimum_isolation(isolation_level(
            value.minimum_isolation,
            "runner_requirements.minimum_isolation",
        )?)
        .with_sandbox_features(sandbox_features)
        .with_container_features(container_features)
        .with_features(features);
    if let Some(operating_system) = value.operating_system {
        requirements =
            requirements.with_operating_system(self::operating_system(operating_system)?);
    }
    if let Some(architecture) = value.architecture {
        requirements = requirements.with_architecture(self::architecture(architecture)?);
    }
    if let Some(profile) = value.environment_profile {
        requirements = requirements.with_environment_profile(environment_profile(profile)?);
    }
    Ok(requirements)
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
    let authorities = runtime_authorities(
        required(value.runtime_authorities, "lease_offer.runtime_authorities")?,
        &job,
        &lease,
        limits,
    )?;
    Ok(protocol::LeaseOffer::new(
        header,
        slot,
        lease,
        job,
        authorities,
    ))
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
        job_source(required(value.source, "job_ir_envelope.source")?),
        job_execution_context(required(value.execution, "job_ir_envelope.execution")?)?,
        job_ir(required(value.job, "job_ir_envelope.job")?, limits)?,
    ))
}

fn job_source(value: wire::JobSource) -> core::JobSource {
    core::JobSource::new(
        value.provider,
        value.repository,
        value.revision,
        value.workflow_path,
        value.event_name,
    )
}

fn job_execution_context(
    value: wire::JobExecutionContext,
) -> Result<core::JobExecutionContext, DecodeError> {
    let mut context = core::JobExecutionContext::new(
        value.workflow_name,
        value.git_ref,
        value.workspace,
        job_content_reference(required(value.event, "job_execution_context.event")?)?,
    );
    if let Some(actor) = value.actor {
        context = context.with_actor(actor);
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
        steps,
    )
    .with_environment(environment)
    .with_services(services);
    if let Some(condition) = value.condition {
        job = job.with_condition(expression_program(condition, limits)?);
    }
    if let Some(timeout) = value.timeout_seconds {
        job = job.with_timeout_seconds(timeout);
    }
    if let Some(directory) = value.working_directory {
        job = job.with_working_directory(directory);
    }
    if let Some(container) = value.container {
        job = job.with_container(container_spec(container, limits)?);
    }
    Ok(job)
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
    }
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
        value.name,
        semantic_step(required(value.kind, "step_ir.kind")?, limits)?,
    )
    .with_continue_on_error(value.continue_on_error)
    .with_environment(value_map(value.environment, limits, "step_ir.environment")?);
    if let Some(condition) = value.condition {
        step = step.with_condition(expression_program(condition, limits)?);
    }
    if let Some(timeout) = value.timeout_seconds {
        step = step.with_timeout_seconds(timeout);
    }
    Ok(step)
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
        Value::Run(run) => Ok(core::SemanticStep::Run {
            command: run.command,
            shell: shell_spec(required(run.shell, "run_step.shell")?)?,
            working_directory: run.working_directory,
        }),
        Value::Action(action) => Ok(core::SemanticStep::Action {
            reference: action_reference(required(action.reference, "action_step.reference")?)?,
            inputs: value_map(action.inputs, limits, "action_step.inputs")?,
        }),
    }
}

fn shell_spec(value: wire::ShellSpec) -> Result<core::ShellSpec, DecodeError> {
    use wire::shell_spec::Value;
    match required_variant(value.value, "shell_spec.value")? {
        Value::DefaultShell(_) => Ok(core::ShellSpec::Default),
        Value::Named(item) => Ok(core::ShellSpec::Named(item)),
        Value::CommandTemplate(item) => Ok(core::ShellSpec::CommandTemplate(item)),
    }
}

fn action_reference(value: wire::ActionReference) -> Result<core::ActionReference, DecodeError> {
    use wire::action_reference::Value;
    match required_variant(value.value, "action_reference.value")? {
        Value::Repository(item) => Ok(core::ActionReference::Repository {
            repository: item.repository,
            revision: item.revision,
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
    let outputs = string_map(value.outputs, limits, "job_result.outputs")?;
    let steps = value
        .steps
        .into_iter()
        .map(step_result)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(core::JobResult::new(
        core::AttemptId::from_uuid(uuid(value.attempt_id, "job_result.attempt_id")?),
        job_conclusion(value.conclusion, "job_result.conclusion")?,
        core::UnixMillis::new(value.completed_at_unix_millis),
    )
    .with_outputs(outputs)
    .with_steps(steps))
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

fn step_result(value: wire::StepResult) -> Result<core::StepResult, DecodeError> {
    Ok(core::StepResult::new(
        core::StepId::new(value.step_id).map_err(|_| DecodeError::InvalidValue {
            field: "step_result.step_id",
        })?,
        job_conclusion(value.outcome, "step_result.outcome")?,
        job_conclusion(value.conclusion, "step_result.conclusion")?,
        core::UnixMillis::new(value.started_at_unix_millis),
        core::UnixMillis::new(value.completed_at_unix_millis),
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
        total
            .checked_add(frame.payload.len())
            .ok_or(DecodeError::InvalidValue {
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
        core::CORE_SCHEMA_VERSION,
        "log_frame.schema_version",
    )?;
    core::LogFrame::new(
        core::LogStreamId::from_uuid(uuid(value.stream_id, "log_frame.stream_id")?),
        core::AttemptId::from_uuid(uuid(value.attempt_id, "log_frame.attempt_id")?),
        core::LogSequence::new(value.sequence),
        core::UnixMillis::new(value.emitted_at_unix_millis),
        log_channel(value.channel)?,
        value.payload,
        value.end_of_stream,
    )
    .map_err(|_| DecodeError::InvalidValue { field: "log_frame" })
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
        core::CORE_SCHEMA_VERSION,
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
