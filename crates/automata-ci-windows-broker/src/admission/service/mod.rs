//! Broker admission application state machine.

use std::{
    fmt,
    sync::{Arc, Mutex, PoisonError},
};

use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_execution::{
    EnvironmentName, EnvironmentValue, EnvironmentVariable, ExecutionArgv, ExecutionEnvironment,
    ImmutableImage, SandboxEnvironment, TargetPath,
};
use automata_ci_protocol::{
    WindowsAdmissionValidity, WindowsRunnerAdmissionBinding, WindowsRunnerAdmissionClaims,
    WindowsRunnerAdmissionEnvelope, WindowsRunnerPlacementRenewalClaims,
    WindowsRunnerPlacementRenewalEnvelope,
};
use automata_ci_windows_broker_core::{
    admission::{
        WindowsBrokerAdmissionError, WindowsBrokerAdmissionEvaluation,
        WindowsBrokerAdmissionEvaluator, floor_windows_admission_issued_at,
    },
    request::{WindowsAdmissionLaunchContract, WindowsBrokerAdmissionRequest},
};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    BrokerError, BrokerProfileContractResolver, WindowsHyperVAdmittedProfileContract,
    custody::{
        WindowsBrokerAdmissionCustody, WindowsBrokerCustodyError, WindowsBrokerCustodyHandle,
        WindowsBrokerCustodyKind,
    },
};

use super::{
    authority::{
        WindowsBrokerAdmissionAuthority, WindowsBrokerAdmissionReceipt,
        WindowsBrokerPlacementRenewalReceipt, custody_handle_commitment,
    },
    repository::{
        AdmissionCustodyRecord, AdmissionRecordPhase, AdmissionRenewalState, AdmissionStateRecord,
        MAX_ADMISSION_RECORDS, PromotionHead, WindowsBrokerAdmissionRepository,
        WindowsBrokerAdmissionSnapshot,
    },
    signing::WindowsBrokerAdmissionSigningKey,
};

const ADMISSION_LIFETIME_MILLIS: i64 = 15 * 60 * 1_000;
const CUSTODY_RECORD_SCHEMA: u16 = 1;

/// Crash-recoverable broker admission application service.
pub struct WindowsBrokerAdmissionService {
    repository: Arc<dyn WindowsBrokerAdmissionRepository>,
    custody: Arc<dyn WindowsBrokerAdmissionCustody>,
    evaluator: Arc<dyn WindowsBrokerAdmissionEvaluator>,
    signing_key: Arc<WindowsBrokerAdmissionSigningKey>,
    state: Mutex<WindowsBrokerAdmissionSnapshot>,
}

impl WindowsBrokerAdmissionService {
    /// Composes and reconciles one broker admission application service.
    ///
    /// # Errors
    ///
    /// Rejects malformed durable state, custody mismatch, or an incomplete
    /// publication which cannot be recovered exactly.
    pub fn new(
        repository: Arc<dyn WindowsBrokerAdmissionRepository>,
        custody: Arc<dyn WindowsBrokerAdmissionCustody>,
        evaluator: Arc<dyn WindowsBrokerAdmissionEvaluator>,
        signing_key: Arc<WindowsBrokerAdmissionSigningKey>,
    ) -> Result<Self, WindowsBrokerAdmissionError> {
        let state = repository.load()?;
        let authority = Self {
            repository,
            custody,
            evaluator,
            signing_key,
            state: Mutex::new(state),
        };
        authority.reconcile()?;
        Ok(authority)
    }

    fn reconcile(&self) -> Result<(), WindowsBrokerAdmissionError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let mut changed = false;
        for record in state.records.values_mut() {
            let handle = WindowsBrokerCustodyHandle::parse(&record.handle)
                .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
            let encoded = encode_custody_record(&record.custody)?;
            if sha256(&encoded) != record.custody_content_sha256 {
                return Err(WindowsBrokerAdmissionError::InvalidState);
            }
            match record.phase {
                AdmissionRecordPhase::Issuing => {
                    self.custody
                        .put_reserved(
                            &handle,
                            WindowsBrokerCustodyKind::AdmissionReceipt,
                            &encoded,
                            record.created_at,
                        )
                        .map_err(map_custody)?;
                    record.phase = AdmissionRecordPhase::Issued;
                    changed = true;
                }
                AdmissionRecordPhase::Issued => {
                    match self.custody.get_admission_receipt(&handle, false) {
                        Ok(observed) if observed.as_slice() == encoded => {}
                        Ok(_) => return Err(WindowsBrokerAdmissionError::InvalidState),
                        Err(WindowsBrokerCustodyError::Absent) => {
                            let completed = self
                                .custody
                                .get_admission_receipt(&handle, true)
                                .map_err(map_custody)?;
                            if completed.as_slice() != encoded {
                                return Err(WindowsBrokerAdmissionError::InvalidState);
                            }
                            record.phase = AdmissionRecordPhase::Completed;
                            changed = true;
                        }
                        Err(error) => return Err(map_custody(error)),
                    }
                }
                AdmissionRecordPhase::Completed => {
                    let observed = self
                        .custody
                        .get_admission_receipt(&handle, true)
                        .map_err(map_custody)?;
                    if observed.as_slice() != encoded {
                        return Err(WindowsBrokerAdmissionError::InvalidState);
                    }
                }
            }
        }
        if changed {
            self.repository.store(&state)?;
        }
        Ok(())
    }

    fn receipt_from_record(
        &self,
        record: &AdmissionStateRecord,
        expected_request_sha256: Sha256Digest,
        now: UnixMillis,
        completed: bool,
    ) -> Result<WindowsBrokerAdmissionReceipt, WindowsBrokerAdmissionError> {
        let handle = WindowsBrokerCustodyHandle::parse(&record.handle)
            .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
        let observed = self
            .custody
            .get_admission_receipt(&handle, completed)
            .map_err(map_custody)?;
        let decoded: AdmissionCustodyRecord = serde_json::from_slice(&observed)
            .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
        if decoded != record.custody
            || sha256(&observed) != record.custody_content_sha256
            || decoded.request_sha256 != expected_request_sha256
        {
            return Err(WindowsBrokerAdmissionError::InvalidState);
        }
        WindowsBrokerAdmissionReceipt::from_wire(
            handle,
            decoded.envelope,
            expected_request_sha256,
            now,
        )
    }

    fn checked_evaluation(
        &self,
        request: &WindowsBrokerAdmissionRequest,
        now: UnixMillis,
    ) -> Result<WindowsBrokerAdmissionEvaluation, WindowsBrokerAdmissionError> {
        let evaluation = self.evaluator.evaluate(request, now)?;
        let request_sha256 = request
            .request_sha256()
            .map_err(|_| WindowsBrokerAdmissionError::InvalidRequest)?;
        let binding = evaluation.binding();
        if binding.transaction() != request.transaction()
            || binding.broker_profile().request_binding_sha256() != request_sha256
            || binding.broker_profile().broker_host_id() != request.broker_host_id()
            || binding.broker_profile().sandbox_provider_id() != request.sandbox_provider_id()
            || binding.capabilities().runner_id() != request.transaction().runner_id()
            || !request
                .capability_ceiling()
                .environment_profiles()
                .is_superset(binding.capabilities().environment_profiles())
            || !request
                .capability_ceiling()
                .features()
                .is_superset(binding.capabilities().features())
        {
            return Err(WindowsBrokerAdmissionError::EvidenceRejected);
        }
        Ok(evaluation)
    }

    pub(super) fn enforce_and_advance_high_water(
        state: &mut WindowsBrokerAdmissionSnapshot,
        binding: &WindowsRunnerAdmissionBinding,
    ) -> Result<(), WindowsBrokerAdmissionError> {
        let promotion = binding.promotion();
        let key = promotion_head_key(binding);
        let proposed = PromotionHead {
            promotion_serial: promotion.promotion_serial(),
            revocation_generation: promotion.revocation_generation(),
            payload_sha256: promotion.payload_sha256(),
            envelope_sha256: promotion.envelope_sha256(),
        };
        if let Some(current) = state.promotion_heads.get(&key)
            && (proposed.promotion_serial < current.promotion_serial
                || proposed.revocation_generation < current.revocation_generation
                || (proposed.promotion_serial == current.promotion_serial && proposed != *current))
        {
            return Err(WindowsBrokerAdmissionError::EvidenceRejected);
        }
        state.promotion_heads.insert(key, proposed);
        Ok(())
    }
}

impl fmt::Debug for WindowsBrokerAdmissionService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsBrokerAdmissionService")
            .field("repository", &self.repository)
            .field("issuer_key_id", &self.signing_key.issuer_key_id())
            .finish_non_exhaustive()
    }
}

impl WindowsBrokerAdmissionAuthority for WindowsBrokerAdmissionService {
    #[allow(clippy::too_many_lines)]
    fn issue(
        &self,
        request: &WindowsBrokerAdmissionRequest,
        now: UnixMillis,
    ) -> Result<WindowsBrokerAdmissionReceipt, WindowsBrokerAdmissionError> {
        let request_sha256 = request
            .request_sha256()
            .map_err(|_| WindowsBrokerAdmissionError::InvalidRequest)?;
        let request_key = request_sha256.to_string();
        {
            let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(record) = state.records.get(&request_key) {
                if record.phase == AdmissionRecordPhase::Completed {
                    return Err(WindowsBrokerAdmissionError::InvalidState);
                }
                return self.receipt_from_record(record, request_sha256, now, false);
            }
        }

        let evaluation = self.checked_evaluation(request, now)?;
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(record) = state.records.get(&request_key) {
            if record.phase == AdmissionRecordPhase::Completed {
                return Err(WindowsBrokerAdmissionError::InvalidState);
            }
            return self.receipt_from_record(record, request_sha256, now, false);
        }
        if state.records.len() >= MAX_ADMISSION_RECORDS {
            return Err(WindowsBrokerAdmissionError::InvalidState);
        }
        Self::enforce_and_advance_high_water(&mut state, evaluation.binding())?;

        let issued_at = floor_windows_admission_issued_at(now)?;
        let promotion_expiry = i64::try_from(
            evaluation
                .binding()
                .promotion()
                .validity()
                .expires_at_unix_millis(),
        )
        .map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)?;
        let expires_at = UnixMillis::new(
            issued_at
                .get()
                .checked_add(ADMISSION_LIFETIME_MILLIS)
                .ok_or(WindowsBrokerAdmissionError::InvalidRequest)?
                .min(promotion_expiry),
        );
        if expires_at <= issued_at {
            return Err(WindowsBrokerAdmissionError::EvidenceRejected);
        }
        let validity = WindowsAdmissionValidity::new(
            u64::try_from(issued_at.get())
                .map_err(|_| WindowsBrokerAdmissionError::InvalidRequest)?,
            u64::try_from(expires_at.get())
                .map_err(|_| WindowsBrokerAdmissionError::InvalidRequest)?,
        )
        .map_err(|_| WindowsBrokerAdmissionError::InvalidRequest)?;
        let handle = self
            .custody
            .reserve_handle(WindowsBrokerCustodyKind::AdmissionReceipt)
            .map_err(map_custody)?;
        let claims = WindowsRunnerAdmissionClaims::new(
            self.signing_key.issuer_key_id(),
            random_digest()?,
            custody_handle_commitment(&handle),
            random_digest()?,
            evaluation.binding().clone(),
            evaluation.evidence(),
            validity,
        )
        .map_err(|_| WindowsBrokerAdmissionError::InvalidReceipt)?;
        let payload = Zeroizing::new(
            claims
                .canonical_bytes()
                .map_err(|_| WindowsBrokerAdmissionError::InvalidReceipt)?,
        );
        let envelope = WindowsRunnerAdmissionEnvelope::new(
            self.signing_key.issuer_key_id(),
            payload.to_vec(),
            self.signing_key.sign_admission(&payload),
        )
        .map_err(|_| WindowsBrokerAdmissionError::InvalidReceipt)?;
        let custody = AdmissionCustodyRecord {
            schema: CUSTODY_RECORD_SCHEMA,
            request_sha256,
            request: request.clone(),
            envelope: envelope.clone(),
            launch: evaluation.launch().clone(),
            profile_valid_until: evaluation.profile_valid_until(),
        };
        let mut encoded = Zeroizing::new(encode_custody_record(&custody)?);
        let record = AdmissionStateRecord {
            request_sha256,
            handle: handle.opaque().to_owned(),
            custody_content_sha256: sha256(&encoded),
            created_at: issued_at,
            phase: AdmissionRecordPhase::Issuing,
            custody,
            current_renewal: None,
        };
        state.records.insert(request_key.clone(), record);
        self.repository.store(&state)?;
        self.custody
            .put_reserved(
                &handle,
                WindowsBrokerCustodyKind::AdmissionReceipt,
                &encoded,
                issued_at,
            )
            .map_err(map_custody)?;
        encoded.zeroize();
        let record = state
            .records
            .get_mut(&request_key)
            .ok_or(WindowsBrokerAdmissionError::InvalidState)?;
        record.phase = AdmissionRecordPhase::Issued;
        self.repository.store(&state)?;
        WindowsBrokerAdmissionReceipt::from_wire(handle, envelope, request_sha256, now)
    }

    fn resume(
        &self,
        handle: &WindowsBrokerCustodyHandle,
        request_sha256: Sha256Digest,
        now: UnixMillis,
    ) -> Result<WindowsBrokerAdmissionReceipt, WindowsBrokerAdmissionError> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let record = state
            .records
            .get(&request_sha256.to_string())
            .filter(|record| {
                record.handle == handle.opaque() && record.phase == AdmissionRecordPhase::Issued
            })
            .ok_or(WindowsBrokerAdmissionError::InvalidState)?;
        self.receipt_from_record(record, request_sha256, now, false)
    }

    fn complete(
        &self,
        handle: &WindowsBrokerCustodyHandle,
        envelope_sha256: Sha256Digest,
    ) -> Result<(), WindowsBrokerAdmissionError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let record = state
            .records
            .values_mut()
            .find(|record| record.handle == handle.opaque())
            .ok_or(WindowsBrokerAdmissionError::InvalidState)?;
        if record.custody.envelope.envelope_sha256() != envelope_sha256 {
            return Err(WindowsBrokerAdmissionError::InvalidReceipt);
        }
        self.custody
            .complete_admission_receipt(handle, record.custody_content_sha256)
            .map_err(map_custody)?;
        if record.phase != AdmissionRecordPhase::Completed {
            record.phase = AdmissionRecordPhase::Completed;
            self.repository.store(&state)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn renew(
        &self,
        completed_handle: &WindowsBrokerCustodyHandle,
        enrollment_envelope_sha256: Sha256Digest,
        now: UnixMillis,
    ) -> Result<WindowsBrokerPlacementRenewalReceipt, WindowsBrokerAdmissionError> {
        let (request, original_binding) = {
            let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            let record = state
                .records
                .values()
                .find(|record| {
                    record.handle == completed_handle.opaque()
                        && record.phase == AdmissionRecordPhase::Completed
                })
                .ok_or(WindowsBrokerAdmissionError::InvalidState)?;
            if record.custody.envelope.envelope_sha256() != enrollment_envelope_sha256 {
                return Err(WindowsBrokerAdmissionError::InvalidReceipt);
            }
            if let Some(current) = &record.current_renewal
                && !current.acknowledged
            {
                let claims = current
                    .envelope
                    .claims()
                    .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
                if now.get()
                    >= i64::try_from(claims.validity().expires_at_unix_millis())
                        .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?
                {
                    return Err(WindowsBrokerAdmissionError::InvalidState);
                }
                return WindowsBrokerPlacementRenewalReceipt::from_wire(
                    current.envelope.clone(),
                    enrollment_envelope_sha256,
                    now,
                );
            }
            let claims = record
                .custody
                .envelope
                .claims()
                .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
            (record.custody.request.clone(), claims.binding().clone())
        };
        let evaluation = self.checked_evaluation(&request, now)?;
        if evaluation.binding() != &original_binding {
            return Err(WindowsBrokerAdmissionError::EvidenceRejected);
        }
        let issued_at = floor_windows_admission_issued_at(now)?;
        let promotion_expiry = i64::try_from(
            original_binding
                .promotion()
                .validity()
                .expires_at_unix_millis(),
        )
        .map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)?;
        let expires_at = UnixMillis::new(
            issued_at
                .get()
                .checked_add(ADMISSION_LIFETIME_MILLIS)
                .ok_or(WindowsBrokerAdmissionError::InvalidRequest)?
                .min(promotion_expiry),
        );
        if expires_at <= issued_at {
            return Err(WindowsBrokerAdmissionError::EvidenceRejected);
        }

        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let record = state
            .records
            .values_mut()
            .find(|record| {
                record.handle == completed_handle.opaque()
                    && record.phase == AdmissionRecordPhase::Completed
            })
            .ok_or(WindowsBrokerAdmissionError::InvalidState)?;
        if record.custody.envelope.envelope_sha256() != enrollment_envelope_sha256 {
            return Err(WindowsBrokerAdmissionError::InvalidReceipt);
        }
        if let Some(current) = &record.current_renewal
            && !current.acknowledged
        {
            let claims = current
                .envelope
                .claims()
                .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
            if now.get()
                >= i64::try_from(claims.validity().expires_at_unix_millis())
                    .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?
            {
                return Err(WindowsBrokerAdmissionError::InvalidState);
            }
            return WindowsBrokerPlacementRenewalReceipt::from_wire(
                current.envelope.clone(),
                enrollment_envelope_sha256,
                now,
            );
        }
        let serial = record
            .current_renewal
            .as_ref()
            .map_or(1, |current| current.serial.saturating_add(1));
        if serial == 0 {
            return Err(WindowsBrokerAdmissionError::InvalidState);
        }
        let validity = WindowsAdmissionValidity::new(
            u64::try_from(issued_at.get())
                .map_err(|_| WindowsBrokerAdmissionError::InvalidRequest)?,
            u64::try_from(expires_at.get())
                .map_err(|_| WindowsBrokerAdmissionError::InvalidRequest)?,
        )
        .map_err(|_| WindowsBrokerAdmissionError::InvalidRequest)?;
        let claims = WindowsRunnerPlacementRenewalClaims::new(
            self.signing_key.issuer_key_id(),
            original_binding.transaction().runner_id(),
            serial,
            random_digest()?,
            enrollment_envelope_sha256,
            original_binding,
            // Evidence is freshly re-evaluated. Keep the original value only
            // to make the non-use explicit in case the evaluator changes it.
            evaluation.evidence(),
            validity,
        )
        .map_err(|_| WindowsBrokerAdmissionError::InvalidReceipt)?;
        let payload = claims
            .canonical_bytes()
            .map_err(|_| WindowsBrokerAdmissionError::InvalidReceipt)?;
        let envelope = WindowsRunnerPlacementRenewalEnvelope::new(
            self.signing_key.issuer_key_id(),
            payload,
            self.signing_key.sign_renewal(&claims)?,
        )
        .map_err(|_| WindowsBrokerAdmissionError::InvalidReceipt)?;
        record.current_renewal = Some(AdmissionRenewalState {
            serial,
            envelope: envelope.clone(),
            acknowledged: false,
        });
        self.repository.store(&state)?;
        WindowsBrokerPlacementRenewalReceipt::from_wire(envelope, enrollment_envelope_sha256, now)
    }

    fn acknowledge_renewal(
        &self,
        completed_handle: &WindowsBrokerCustodyHandle,
        renewal_envelope_sha256: Sha256Digest,
    ) -> Result<(), WindowsBrokerAdmissionError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let record = state
            .records
            .values_mut()
            .find(|record| {
                record.handle == completed_handle.opaque()
                    && record.phase == AdmissionRecordPhase::Completed
            })
            .ok_or(WindowsBrokerAdmissionError::InvalidState)?;
        let renewal = record
            .current_renewal
            .as_mut()
            .filter(|renewal| renewal.envelope.envelope_sha256() == renewal_envelope_sha256)
            .ok_or(WindowsBrokerAdmissionError::InvalidReceipt)?;
        if !renewal.acknowledged {
            renewal.acknowledged = true;
            self.repository.store(&state)?;
        }
        Ok(())
    }
}

impl BrokerProfileContractResolver for WindowsBrokerAdmissionService {
    fn resolve(
        &self,
        profile_contract_sha256: Sha256Digest,
    ) -> Result<Option<WindowsHyperVAdmittedProfileContract>, BrokerError> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(record) = state.records.values().find(|record| {
            if record.phase != AdmissionRecordPhase::Completed {
                return false;
            }
            record.custody.envelope.claims().is_ok_and(|claims| {
                claims.evidence().broker().profile_contract_sha256() == profile_contract_sha256
            })
        }) else {
            return Ok(None);
        };
        let claims = record
            .custody
            .envelope
            .claims()
            .map_err(|_| BrokerError::InvalidProfileContract)?;
        let host_id = claims
            .binding()
            .broker_profile()
            .broker_host_id()
            .parse()
            .map_err(|_| BrokerError::InvalidProfileContract)?;
        WindowsHyperVAdmittedProfileContract::new(
            host_id,
            profile_contract_sha256,
            admitted_environment(&record.custody.launch)?,
            record.custody.profile_valid_until,
        )
        .map(Some)
    }
}

fn admitted_environment(
    launch: &WindowsAdmissionLaunchContract,
) -> Result<SandboxEnvironment, BrokerError> {
    let image = ImmutableImage::new(launch.image().reference().to_owned())
        .map_err(|_| BrokerError::InvalidProfileContract)?;
    if image.digest() != launch.image().digest() {
        return Err(BrokerError::InvalidProfileContract);
    }
    let keepalive = ExecutionArgv::new(
        TargetPath::windows(launch.keepalive().program().to_owned())
            .map_err(|_| BrokerError::InvalidProfileContract)?,
        launch.keepalive().arguments().to_vec(),
    )
    .map_err(|_| BrokerError::InvalidProfileContract)?;
    let workspace = TargetPath::windows(launch.workspace().to_owned())
        .map_err(|_| BrokerError::InvalidProfileContract)?;
    let environment = launch
        .default_environment()
        .iter()
        .map(|variable| {
            let name = EnvironmentName::new(variable.name().to_owned())
                .map_err(|_| BrokerError::InvalidProfileContract)?;
            let value = EnvironmentValue::new(variable.value().to_owned())
                .map_err(|_| BrokerError::InvalidProfileContract)?;
            Ok(EnvironmentVariable::new(name, value))
        })
        .collect::<Result<Vec<_>, BrokerError>>()?;
    let environment =
        ExecutionEnvironment::new(environment).map_err(|_| BrokerError::InvalidProfileContract)?;
    SandboxEnvironment::windows_hyperv_container(
        launch.profile().clone(),
        image,
        keepalive,
        workspace,
        environment,
    )
    .map_err(|_| BrokerError::InvalidProfileContract)
}

fn encode_custody_record(
    record: &AdmissionCustodyRecord,
) -> Result<Vec<u8>, WindowsBrokerAdmissionError> {
    if record.schema != CUSTODY_RECORD_SCHEMA
        || record.request_sha256
            != record
                .request
                .request_sha256()
                .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?
        || record
            .envelope
            .claims()
            .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?
            .binding()
            .broker_profile()
            .request_binding_sha256()
            != record.request_sha256
    {
        return Err(WindowsBrokerAdmissionError::InvalidState);
    }
    serde_json::to_vec(record).map_err(|_| WindowsBrokerAdmissionError::InvalidState)
}

fn promotion_head_key(binding: &WindowsRunnerAdmissionBinding) -> String {
    format!(
        "{}\0{}\0{}\0{}",
        binding.broker_profile().broker_host_id(),
        binding.promotion().trust_bundle_id(),
        binding.promotion().key_id(),
        binding.broker_profile().profile().digest(),
    )
}

fn map_custody(_error: WindowsBrokerCustodyError) -> WindowsBrokerAdmissionError {
    WindowsBrokerAdmissionError::InvalidState
}

fn random_digest() -> Result<Sha256Digest, WindowsBrokerAdmissionError> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(WindowsBrokerAdmissionError::InvalidState);
    }
    let digest = Sha256Digest::from_bytes(*bytes);
    bytes.zeroize();
    Ok(digest)
}

pub(super) fn sha256(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

#[cfg(test)]
mod tests;
