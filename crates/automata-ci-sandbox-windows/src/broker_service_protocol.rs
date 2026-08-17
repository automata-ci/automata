//! Strict, versioned protocol hosted by the privileged Windows broker service.

use std::{sync::Arc, time::Duration};

use automata_ci_core::{
    EnvironmentProfile, JobResourceAllocation, OperationId, ResourceCapacity, Sha256Digest,
    UnixMillis, WindowsHyperVBrokerGrant,
};
use automata_ci_execution::{
    CopyFromRequest, CopyToRequest, DestroyDisposition, EnvironmentName, EnvironmentValue,
    EnvironmentVariable, ExecutionArgv, ExecutionCommand, ExecutionEnvironment, ExecutionOutput,
    ExecutionOutputStream, ExecutionTermination, ImmutableImage, NetworkPolicy, NeverCancelled,
    ResourceLimits, RootFilesystemPolicy, SandboxCustody, SandboxEnvironment, SandboxGeneration,
    SandboxPrivilegePolicy, SandboxSpec, TargetPath,
};
use automata_ci_protocol::WindowsRunnerAdmissionIssueRequest;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    BrokerAdapterEffect, BrokerError, BrokerLifecyclePhase, BrokerSandboxInspection,
    BrokerSandboxTicket, RestrictedWindowsHyperVBroker, WindowsBrokerAdmissionAuthority,
    WindowsBrokerAdmissionError, WindowsBrokerAdmissionReceipt, WindowsBrokerCustodyError,
    WindowsBrokerCustodyHandle, WindowsBrokerHostInputAttestor, WindowsBrokerHostInputError,
    WindowsBrokerHostInputRequest, WindowsBrokerPlacementRenewalReceipt,
};

const WIRE_SCHEMA: u16 = 1;
const PROFILE_ATTESTATION_LIFETIME_MILLIS: i64 = 5 * 60 * 1_000;
const HOST_INPUT_ATTESTATION_LIFETIME_MILLIS: i64 = 5 * 60 * 1_000;

#[derive(Clone, Debug)]
pub(crate) struct BrokerServiceProtocol {
    broker: Arc<RestrictedWindowsHyperVBroker>,
    host_input_attestor: Arc<dyn WindowsBrokerHostInputAttestor>,
    admissions: Arc<dyn WindowsBrokerAdmissionAuthority>,
}

impl BrokerServiceProtocol {
    pub(crate) fn new(
        broker: Arc<RestrictedWindowsHyperVBroker>,
        host_input_attestor: Arc<dyn WindowsBrokerHostInputAttestor>,
        admissions: Arc<dyn WindowsBrokerAdmissionAuthority>,
    ) -> Self {
        Self {
            broker,
            host_input_attestor,
            admissions,
        }
    }

    pub(crate) fn dispatch(&self, encoded: &[u8]) -> Vec<u8> {
        let result = self.decode_and_dispatch(encoded);
        let response = match result {
            Ok(payload) => WireResponse {
                schema: WIRE_SCHEMA,
                ok: true,
                effect: None,
                payload: Some(payload),
            },
            Err(error) => WireResponse {
                schema: WIRE_SCHEMA,
                ok: false,
                effect: Some(error.effect.as_wire()),
                payload: None,
            },
        };
        serde_json::to_vec(&response).unwrap_or_else(|_| {
            br#"{"schema":1,"ok":false,"effect":"state_may_have_changed","payload":null}"#.to_vec()
        })
    }

    fn decode_and_dispatch(&self, encoded: &[u8]) -> ServiceResult<Value> {
        let request: WireRequest =
            serde_json::from_slice(encoded).map_err(|_| ServiceError::known())?;
        if request.schema != WIRE_SCHEMA {
            return Err(ServiceError::known());
        }
        let now = system_unix_millis().ok_or_else(ServiceError::uncertain)?;
        match request.operation.as_str() {
            "create" => self.create(request.payload, now),
            "attach" => self.attach(request.payload, now),
            "inspect" => self.inspect(request.payload, now),
            "exec" => self.exec(request.payload, now),
            "copy_to" => self.copy_to(request.payload, now),
            "copy_from" => self.copy_from(request.payload, now),
            "destroy" => self.destroy(request.payload, now),
            "attest_profile" => self.attest_profile(request.payload, now),
            "attest_host_inputs" => self.attest_host_inputs(request.payload, now),
            "admission_issue" => self.admission_issue(request.payload, now),
            "admission_resume" => self.admission_resume(request.payload, now),
            "admission_complete" => self.admission_complete(request.payload),
            "admission_renew" => self.admission_renew(request.payload, now),
            "admission_renew_ack" => self.admission_renew_ack(request.payload),
            _ => Err(ServiceError::known()),
        }
    }

    fn create(&self, payload: Value, now: UnixMillis) -> ServiceResult<Value> {
        let payload: CreatePayload = decode(payload)?;
        let spec = payload.into_spec()?;
        let ticket = self
            .broker
            .create(&spec, now)
            .map_err(ServiceError::broker)?;
        let inspection = self
            .broker
            .inspect_ticket(&ticket, now)
            .map_err(ServiceError::broker)?;
        Ok(sandbox_value(&ticket, &inspection))
    }

    fn attach(&self, payload: Value, now: UnixMillis) -> ServiceResult<Value> {
        let payload: HandlePayload = decode(payload)?;
        let ticket =
            BrokerSandboxTicket::from_opaque(&payload.handle).map_err(ServiceError::broker)?;
        self.broker
            .attach(&ticket, now)
            .map_err(ServiceError::broker)?;
        Ok(json!({}))
    }

    fn inspect(&self, payload: Value, now: UnixMillis) -> ServiceResult<Value> {
        let payload: HandlePayload = decode(payload)?;
        let ticket =
            BrokerSandboxTicket::from_opaque(&payload.handle).map_err(ServiceError::broker)?;
        let inspection = self
            .broker
            .inspect_ticket(&ticket, now)
            .map_err(ServiceError::broker)?;
        Ok(sandbox_value(&ticket, &inspection))
    }

    fn exec(&self, payload: Value, now: UnixMillis) -> ServiceResult<Value> {
        let payload: ExecPayload = decode(payload)?;
        let ticket = payload.ticket()?;
        let output_limit = payload.output_limit;
        let command = payload.into_command()?;
        let output = self
            .broker
            .exec(&ticket, &command, now, &NeverCancelled)
            .map_err(ServiceError::broker)?;
        if output.stdout().len().saturating_add(output.stderr().len()) > output_limit {
            return Err(ServiceError::uncertain());
        }
        Ok(output_value(&output))
    }

    fn copy_to(&self, payload: Value, now: UnixMillis) -> ServiceResult<Value> {
        let payload: CopyToPayload = decode(payload)?;
        let ticket = payload.ticket()?;
        let request = payload.into_request()?;
        self.broker
            .copy_to(&ticket, &request, now, &NeverCancelled)
            .map_err(ServiceError::broker)?;
        Ok(json!({}))
    }

    fn copy_from(&self, payload: Value, now: UnixMillis) -> ServiceResult<Value> {
        let payload: CopyFromPayload = decode(payload)?;
        let ticket = payload.ticket()?;
        let request = payload.into_request()?;
        let bytes = self
            .broker
            .copy_from(&ticket, &request, now, &NeverCancelled)
            .map_err(ServiceError::broker)?;
        Ok(json!({"content_base64": BASE64.encode(bytes)}))
    }

    fn destroy(&self, payload: Value, now: UnixMillis) -> ServiceResult<Value> {
        let payload: DestroyPayload = decode(payload)?;
        let ticket = payload.ticket()?;
        let generation =
            SandboxGeneration::new(payload.generation).map_err(|_| ServiceError::known())?;
        let inspection = self
            .broker
            .inspect_ticket(&ticket, now)
            .map_err(ServiceError::broker)?;
        if inspection.generation() != generation || inspection.custody() != payload.custody {
            return Err(ServiceError::known());
        }
        let already_absent = matches!(inspection.phase(), BrokerLifecyclePhase::Destroyed);
        self.broker
            .destroy(&ticket, payload.operation_id, generation, payload.custody)
            .map_err(ServiceError::broker)?;
        let disposition = if already_absent {
            DestroyDisposition::AlreadyAbsent
        } else {
            DestroyDisposition::Destroyed
        };
        Ok(json!({
            "disposition": match disposition {
                DestroyDisposition::Destroyed => "destroyed",
                DestroyDisposition::AlreadyAbsent => "already_absent",
            }
        }))
    }

    fn attest_profile(&self, payload: Value, now: UnixMillis) -> ServiceResult<Value> {
        let payload: AttestProfilePayload = decode(payload)?;
        let image = payload.image()?;
        let valid_until = UnixMillis::new(
            now.get()
                .checked_add(PROFILE_ATTESTATION_LIFETIME_MILLIS)
                .ok_or_else(ServiceError::uncertain)?,
        );
        let attestation = self
            .broker
            .attest_profile(&payload.profile, &image, now, valid_until)
            .map_err(ServiceError::broker)?;
        Ok(json!({
            "host_id": attestation.host_id(),
            "profile": attestation.profile(),
            "image_digest": attestation.image_digest(),
            "isolation": attestation.isolation(),
            "network_disabled": attestation.network_disabled(),
            "issued_at": attestation.issued_at(),
            "valid_until": attestation.valid_until(),
            "digest": attestation.digest(),
        }))
    }

    fn attest_host_inputs(&self, payload: Value, now: UnixMillis) -> ServiceResult<Value> {
        let request: WindowsBrokerHostInputRequest = decode(payload)?;
        request.validate().map_err(ServiceError::host_input)?;
        let valid_until = UnixMillis::new(
            now.get()
                .checked_add(HOST_INPUT_ATTESTATION_LIFETIME_MILLIS)
                .ok_or_else(ServiceError::uncertain)?,
        );
        let attestation = self
            .host_input_attestor
            .attest(&request, now, valid_until)
            .map_err(ServiceError::host_input)?;
        serde_json::to_value(attestation).map_err(|_| ServiceError::uncertain())
    }

    fn admission_issue(&self, payload: Value, now: UnixMillis) -> ServiceResult<Value> {
        let payload: AdmissionIssuePayload = decode(payload)?;
        let mut canonical = Zeroizing::new(
            BASE64
                .decode(payload.request_base64)
                .map_err(|_| ServiceError::known())?,
        );
        let request = WindowsRunnerAdmissionIssueRequest::from_canonical_bytes(&canonical)
            .map_err(|_| ServiceError::known())?;
        canonical.zeroize();
        let receipt = self
            .admissions
            .issue(&request, now)
            .map_err(ServiceError::admission)?;
        Ok(admission_value(&receipt))
    }

    fn admission_resume(&self, payload: Value, now: UnixMillis) -> ServiceResult<Value> {
        let payload: AdmissionResumePayload = decode(payload)?;
        let handle = payload.handle()?;
        let receipt = self
            .admissions
            .resume(&handle, payload.request_sha256, now)
            .map_err(ServiceError::admission)?;
        Ok(admission_value(&receipt))
    }

    fn admission_complete(&self, payload: Value) -> ServiceResult<Value> {
        let payload: AdmissionCompletePayload = decode(payload)?;
        let handle = payload.handle()?;
        self.admissions
            .complete(&handle, payload.envelope_sha256)
            .map_err(ServiceError::admission)?;
        Ok(json!({}))
    }

    fn admission_renew(&self, payload: Value, now: UnixMillis) -> ServiceResult<Value> {
        let payload: AdmissionRenewPayload = decode(payload)?;
        let handle = payload.handle()?;
        let receipt = self
            .admissions
            .renew(&handle, payload.enrollment_envelope_sha256, now)
            .map_err(ServiceError::admission)?;
        Ok(placement_renewal_value(&receipt))
    }

    fn admission_renew_ack(&self, payload: Value) -> ServiceResult<Value> {
        let payload: AdmissionRenewAckPayload = decode(payload)?;
        let handle = payload.handle()?;
        self.admissions
            .acknowledge_renewal(&handle, payload.renewal_envelope_sha256)
            .map_err(ServiceError::admission)?;
        Ok(json!({}))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    schema: u16,
    operation: String,
    payload: Value,
}

#[derive(Debug, Serialize)]
struct WireResponse {
    schema: u16,
    ok: bool,
    effect: Option<&'static str>,
    payload: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HandlePayload {
    handle: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArgvPayload {
    program: String,
    platform: String,
    arguments: Vec<String>,
}

impl ArgvPayload {
    fn into_argv(self) -> ServiceResult<ExecutionArgv> {
        if self.platform != "windows" {
            return Err(ServiceError::known());
        }
        let program = TargetPath::windows(self.program).map_err(|_| ServiceError::known())?;
        ExecutionArgv::new(program, self.arguments).map_err(|_| ServiceError::known())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentPayload {
    name: String,
    value: String,
    secret: bool,
}

fn environment(values: Vec<EnvironmentPayload>) -> ServiceResult<ExecutionEnvironment> {
    let values = values
        .into_iter()
        .map(|value| {
            // This broker has no post-isolation secret relay. The ordinary
            // exec environment is limited to non-secret job data even when a
            // compromised client sets the wire marker directly.
            if value.secret {
                return Err(ServiceError::known());
            }
            let name = EnvironmentName::new(value.name).map_err(|_| ServiceError::known())?;
            let value = EnvironmentValue::new(value.value).map_err(|_| ServiceError::known())?;
            Ok(EnvironmentVariable::new(name, value))
        })
        .collect::<ServiceResult<Vec<_>>>()?;
    ExecutionEnvironment::new(values).map_err(|_| ServiceError::known())
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourcePayload {
    memory_bytes: u64,
    cpu_millis: u32,
    pids: u32,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapacityPayload {
    memory_bytes: u64,
    cpu_millis: u32,
    ephemeral_disk_bytes: u64,
    gpu_count: u16,
}

impl CapacityPayload {
    const fn into_capacity(self) -> ResourceCapacity {
        ResourceCapacity::new(
            self.cpu_millis,
            self.memory_bytes,
            self.ephemeral_disk_bytes,
            self.gpu_count,
        )
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreatePayload {
    operation_id: OperationId,
    generation: u64,
    custody: SandboxCustody,
    profile: EnvironmentProfile,
    image_reference: String,
    image_digest: Sha256Digest,
    keepalive: ArgvPayload,
    profile_workspace: String,
    default_environment: Vec<EnvironmentPayload>,
    workspace: String,
    network: String,
    root_filesystem: String,
    privilege: String,
    resources: ResourcePayload,
    resource_requests: CapacityPayload,
    resource_limits: CapacityPayload,
    windows_action_graph_sha256: Option<Sha256Digest>,
    grant: WindowsHyperVBrokerGrant,
}

impl CreatePayload {
    fn into_spec(self) -> ServiceResult<SandboxSpec> {
        if self.network != "disabled"
            || self.root_filesystem != "writable"
            || self.privilege != "unprivileged"
        {
            return Err(ServiceError::known());
        }
        let image = image(self.image_reference, self.image_digest)?;
        let generation =
            SandboxGeneration::new(self.generation).map_err(|_| ServiceError::known())?;
        let profile_workspace =
            TargetPath::windows(self.profile_workspace).map_err(|_| ServiceError::known())?;
        let workspace = TargetPath::windows(self.workspace).map_err(|_| ServiceError::known())?;
        let profile = SandboxEnvironment::windows_hyperv_container(
            self.profile,
            image,
            self.keepalive.into_argv()?,
            profile_workspace,
            environment(self.default_environment)?,
        )
        .map_err(|_| ServiceError::known())?;
        let resources = ResourceLimits::new(
            self.resources.memory_bytes,
            self.resources.cpu_millis,
            self.resources.pids,
        )
        .map_err(|_| ServiceError::known())?;
        let allocation = JobResourceAllocation::new(
            self.resource_requests.into_capacity(),
            self.resource_limits.into_capacity(),
        )
        .map_err(|_| ServiceError::known())?;
        let mut spec = SandboxSpec::new(
            self.operation_id,
            generation,
            self.custody,
            profile,
            workspace,
            NetworkPolicy::Disabled,
            RootFilesystemPolicy::Writable,
            resources,
        )
        .with_privilege(SandboxPrivilegePolicy::Unprivileged)
        .with_resource_allocation(allocation)
        .with_windows_hyperv_broker_grant(self.grant);
        if let Some(graph_sha256) = self.windows_action_graph_sha256 {
            spec = spec.with_windows_action_graph_sha256(Some(graph_sha256));
        }
        Ok(spec)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecPayload {
    handle: String,
    operation_id: OperationId,
    argv: ArgvPayload,
    working_directory: String,
    environment: Vec<EnvironmentPayload>,
    timeout_millis: u64,
    output_limit: usize,
}

impl ExecPayload {
    fn ticket(&self) -> ServiceResult<BrokerSandboxTicket> {
        BrokerSandboxTicket::from_opaque(&self.handle).map_err(ServiceError::broker)
    }

    fn into_command(self) -> ServiceResult<ExecutionCommand> {
        let timeout = Duration::from_millis(self.timeout_millis);
        ExecutionCommand::new(
            self.operation_id,
            self.argv.into_argv()?,
            TargetPath::windows(self.working_directory).map_err(|_| ServiceError::known())?,
            environment(self.environment)?,
            timeout,
            self.output_limit,
        )
        .map_err(|_| ServiceError::known())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CopyToPayload {
    handle: String,
    operation_id: OperationId,
    target: String,
    content_base64: String,
}

impl CopyToPayload {
    fn ticket(&self) -> ServiceResult<BrokerSandboxTicket> {
        BrokerSandboxTicket::from_opaque(&self.handle).map_err(ServiceError::broker)
    }

    fn into_request(self) -> ServiceResult<CopyToRequest> {
        let mut bytes = Zeroizing::new(
            BASE64
                .decode(self.content_base64)
                .map_err(|_| ServiceError::known())?,
        );
        let request = CopyToRequest::new(
            self.operation_id,
            TargetPath::windows(self.target).map_err(|_| ServiceError::known())?,
            bytes.to_vec(),
        )
        .map_err(|_| ServiceError::known());
        bytes.zeroize();
        request
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CopyFromPayload {
    handle: String,
    operation_id: OperationId,
    source: String,
    byte_limit: usize,
}

impl CopyFromPayload {
    fn ticket(&self) -> ServiceResult<BrokerSandboxTicket> {
        BrokerSandboxTicket::from_opaque(&self.handle).map_err(ServiceError::broker)
    }

    fn into_request(self) -> ServiceResult<CopyFromRequest> {
        CopyFromRequest::new(
            self.operation_id,
            TargetPath::windows(self.source).map_err(|_| ServiceError::known())?,
            self.byte_limit,
        )
        .map_err(|_| ServiceError::known())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DestroyPayload {
    handle: String,
    operation_id: OperationId,
    generation: u64,
    custody: SandboxCustody,
}

impl DestroyPayload {
    fn ticket(&self) -> ServiceResult<BrokerSandboxTicket> {
        BrokerSandboxTicket::from_opaque(&self.handle).map_err(ServiceError::broker)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestProfilePayload {
    profile: EnvironmentProfile,
    image_reference: String,
    image_digest: Sha256Digest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionIssuePayload {
    request_base64: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionResumePayload {
    handle: String,
    request_sha256: Sha256Digest,
}

impl AdmissionResumePayload {
    fn handle(&self) -> ServiceResult<WindowsBrokerCustodyHandle> {
        WindowsBrokerCustodyHandle::parse(&self.handle).map_err(ServiceError::custody)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionCompletePayload {
    handle: String,
    envelope_sha256: Sha256Digest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionRenewPayload {
    handle: String,
    enrollment_envelope_sha256: Sha256Digest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionRenewAckPayload {
    handle: String,
    renewal_envelope_sha256: Sha256Digest,
}

impl AdmissionRenewPayload {
    fn handle(&self) -> ServiceResult<WindowsBrokerCustodyHandle> {
        WindowsBrokerCustodyHandle::parse(&self.handle).map_err(ServiceError::custody)
    }
}

impl AdmissionRenewAckPayload {
    fn handle(&self) -> ServiceResult<WindowsBrokerCustodyHandle> {
        WindowsBrokerCustodyHandle::parse(&self.handle).map_err(ServiceError::custody)
    }
}

impl AdmissionCompletePayload {
    fn handle(&self) -> ServiceResult<WindowsBrokerCustodyHandle> {
        WindowsBrokerCustodyHandle::parse(&self.handle).map_err(ServiceError::custody)
    }
}

impl AttestProfilePayload {
    fn image(&self) -> ServiceResult<ImmutableImage> {
        image(self.image_reference.clone(), self.image_digest)
    }
}

fn image(reference: String, expected: Sha256Digest) -> ServiceResult<ImmutableImage> {
    let image = ImmutableImage::new(reference).map_err(|_| ServiceError::known())?;
    if image.digest() != expected {
        return Err(ServiceError::known());
    }
    Ok(image)
}

fn sandbox_value(ticket: &BrokerSandboxTicket, inspection: &BrokerSandboxInspection) -> Value {
    json!({
        "handle": ticket.opaque(),
        "generation": inspection.generation().get(),
        "custody": inspection.custody(),
        "profile": inspection.profile(),
        "state": match inspection.phase() {
            BrokerLifecyclePhase::Ready => "created",
            BrokerLifecyclePhase::Attached => "running",
            BrokerLifecyclePhase::Destroyed | BrokerLifecyclePhase::ConsumedFailed => "absent",
            BrokerLifecyclePhase::Creating
            | BrokerLifecyclePhase::Destroying
            | BrokerLifecyclePhase::Quarantined => "degraded",
        },
    })
}

fn output_value(output: &ExecutionOutput) -> Value {
    let (termination, exit_code) = match output.termination() {
        ExecutionTermination::Exited(code) => ("exited", Some(code)),
        ExecutionTermination::Signalled => ("signalled", None),
        ExecutionTermination::TimedOut => ("timed_out", None),
        ExecutionTermination::Cancelled => ("cancelled", None),
    };
    let records = output
        .records()
        .iter()
        .map(|record| {
            json!({
                "stream": match record.stream() {
                    ExecutionOutputStream::Stdout => "stdout",
                    ExecutionOutputStream::Stderr => "stderr",
                },
                "bytes_base64": (!record.is_end_of_stream()).then(|| BASE64.encode(record.bytes())),
                "end_of_stream": record.is_end_of_stream(),
            })
        })
        .collect::<Vec<_>>();
    json!({
        "termination": termination,
        "exit_code": exit_code,
        "records": records,
        "truncated": output.was_truncated(),
    })
}

fn admission_value(receipt: &WindowsBrokerAdmissionReceipt) -> Value {
    json!({
        "handle": receipt.handle().opaque(),
        "envelope": receipt.envelope(),
        "envelope_sha256": receipt.envelope_sha256(),
    })
}

fn placement_renewal_value(receipt: &WindowsBrokerPlacementRenewalReceipt) -> Value {
    json!({
        "envelope": receipt.envelope(),
        "envelope_sha256": receipt.envelope_sha256(),
    })
}

fn decode<T: for<'de> Deserialize<'de>>(value: Value) -> ServiceResult<T> {
    serde_json::from_value(value).map_err(|_| ServiceError::known())
}

fn system_unix_millis() -> Option<UnixMillis> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_millis();
    i64::try_from(millis).ok().map(UnixMillis::new)
}

type ServiceResult<T> = Result<T, ServiceError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ServiceError {
    effect: ServiceEffect,
}

impl ServiceError {
    const fn known() -> Self {
        Self {
            effect: ServiceEffect::KnownNoEffect,
        }
    }

    const fn uncertain() -> Self {
        Self {
            effect: ServiceEffect::StateMayHaveChanged,
        }
    }

    const fn broker(error: BrokerError) -> Self {
        let uncertain = match error {
            BrokerError::Adapter(adapter) => {
                matches!(adapter.effect(), BrokerAdapterEffect::StateMayHaveChanged)
            }
            BrokerError::Ledger(_) | BrokerError::EffectiveStateMismatch => true,
            _ => false,
        };
        if uncertain {
            Self::uncertain()
        } else {
            Self::known()
        }
    }

    const fn custody(error: WindowsBrokerCustodyError) -> Self {
        if matches!(
            error,
            WindowsBrokerCustodyError::Io | WindowsBrokerCustodyError::Protector
        ) {
            Self::uncertain()
        } else {
            Self::known()
        }
    }

    const fn host_input(error: WindowsBrokerHostInputError) -> Self {
        if matches!(error, WindowsBrokerHostInputError::File) {
            Self::uncertain()
        } else {
            Self::known()
        }
    }

    const fn admission(error: WindowsBrokerAdmissionError) -> Self {
        if matches!(
            error,
            WindowsBrokerAdmissionError::InvalidRequest
                | WindowsBrokerAdmissionError::EvidenceRejected
                | WindowsBrokerAdmissionError::InvalidReceipt
        ) {
            Self::known()
        } else {
            Self::uncertain()
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServiceEffect {
    KnownNoEffect,
    StateMayHaveChanged,
}

impl ServiceEffect {
    const fn as_wire(self) -> &'static str {
        match self {
            Self::KnownNoEffect => "known_no_effect",
            Self::StateMayHaveChanged => "state_may_have_changed",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;

    use automata_ci_core::RunnerId;

    use super::*;

    #[test]
    fn top_level_and_operation_payload_reject_unknown_fields() {
        let top = serde_json::from_slice::<WireRequest>(
            br#"{"schema":1,"operation":"inspect","payload":{},"unknown":true}"#,
        );
        assert!(top.is_err());
        let payload = serde_json::from_value::<HandlePayload>(json!({
            "handle": "v1-a-b",
            "unknown": true,
        }));
        assert!(payload.is_err());
    }

    #[test]
    fn client_and_service_codecs_round_trip_an_exact_frame() {
        let encoded_request =
            br#"{"schema":1,"operation":"inspect","payload":{"handle":"v2-a-b"}}"#;
        let request: WireRequest =
            serde_json::from_slice(encoded_request).expect("client request decodes at service");
        assert_eq!(request.schema, WIRE_SCHEMA);
        assert_eq!(request.operation, "inspect");
        let payload: HandlePayload =
            serde_json::from_value(request.payload).expect("operation payload");
        assert_eq!(payload.handle, "v2-a-b");

        let encoded_response = serde_json::to_vec(&WireResponse {
            schema: WIRE_SCHEMA,
            ok: true,
            effect: None,
            payload: Some(json!({"handle": "v2-a-b"})),
        })
        .expect("service response encodes");
        let (schema, ok, effect, payload) =
            crate::broker_provider::decode_client_wire_response_for_test(&encoded_response)
                .expect("service response decodes at client");
        assert_eq!(schema, WIRE_SCHEMA);
        assert!(ok);
        assert_eq!(effect, None);
        assert_eq!(payload, Some(json!({"handle": "v2-a-b"})));
    }

    #[test]
    fn fixed_policy_and_digest_qualified_image_fail_closed() {
        let zero = Sha256Digest::from_bytes([0_u8; 32]);
        assert!(image("registry.example/windows@sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(), zero).is_ok());
        assert!(image("registry.example/windows:latest".to_owned(), zero).is_err());
        let different = Sha256Digest::from_bytes([1_u8; 32]);
        assert!(image("registry.example/windows@sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(), different).is_err());
    }

    #[test]
    fn generic_sandbox_custody_wire_is_required_and_exact() {
        let runner_id = RunnerId::new();
        for custody in [
            SandboxCustody::ProfileAdmission { runner_id },
            SandboxCustody::Job {
                runner_id,
                slot_ordinal: NonZeroU16::new(3).expect("one-based slot"),
            },
        ] {
            let payload = serde_json::from_value::<DestroyPayload>(json!({
                "handle": "v2-a-b",
                "operation_id": OperationId::new(),
                "generation": 7,
                "custody": custody,
            }))
            .expect("exact custody payload");
            assert_eq!(payload.custody, custody);
        }
        assert!(
            serde_json::from_value::<DestroyPayload>(json!({
                "handle": "v2-a-b",
                "operation_id": OperationId::new(),
                "generation": 7,
            }))
            .is_err(),
            "custody must never be defaulted or reconstructed"
        );
    }

    #[test]
    fn signal_wait_and_caller_selected_engine_operations_do_not_exist() {
        for operation in [
            "signal",
            "wait",
            "create_process",
            "create_vm",
            "raw_hcs",
            "custody_put",
            "custody_inspect",
            "custody_get",
            "custody_remove",
        ] {
            let request = WireRequest {
                schema: WIRE_SCHEMA,
                operation: operation.to_owned(),
                payload: json!({}),
            };
            assert!(!matches!(
                request.operation.as_str(),
                "create"
                    | "attach"
                    | "inspect"
                    | "exec"
                    | "copy_to"
                    | "copy_from"
                    | "destroy"
                    | "attest_profile"
                    | "attest_host_inputs"
                    | "admission_issue"
                    | "admission_resume"
                    | "admission_complete"
                    | "admission_renew"
                    | "admission_renew_ack"
            ));
        }
    }

    #[test]
    fn ordinary_exec_environment_rejects_secret_markers_before_broker_dispatch() {
        let secret = environment(vec![EnvironmentPayload {
            name: "TOKEN".to_owned(),
            value: "not-forwarded".to_owned(),
            secret: true,
        }]);
        assert!(secret.is_err());

        let public = environment(vec![EnvironmentPayload {
            name: "CI".to_owned(),
            value: "true".to_owned(),
            secret: false,
        }])
        .expect("bounded non-secret environment");
        assert_eq!(public.values().len(), 1);
        assert!(!public.values()[0].is_secret());
    }
}
