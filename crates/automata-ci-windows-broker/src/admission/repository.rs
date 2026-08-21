//! Durable state port and file-snapshot adapter for broker admission.

use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_protocol::{WindowsRunnerAdmissionEnvelope, WindowsRunnerPlacementRenewalEnvelope};
use automata_ci_windows_broker_core::{
    admission::WindowsBrokerAdmissionError,
    request::{WindowsAdmissionLaunchContract, WindowsBrokerAdmissionRequest},
};
use serde::{Deserialize, Serialize};

use crate::custody::WindowsBrokerCustodyHandle;

const STATE_SCHEMA: u16 = 1;
const MAX_STATE_BYTES: u64 = 64 * 1024 * 1024;
pub(super) const MAX_ADMISSION_RECORDS: usize = 256;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdmissionCustodyRecord {
    pub(super) schema: u16,
    pub(super) request_sha256: Sha256Digest,
    pub(super) request: WindowsBrokerAdmissionRequest,
    pub(super) envelope: WindowsRunnerAdmissionEnvelope,
    pub(super) launch: WindowsAdmissionLaunchContract,
    pub(super) profile_valid_until: UnixMillis,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum AdmissionRecordPhase {
    Issuing,
    Issued,
    Completed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdmissionRenewalState {
    pub(super) serial: u64,
    pub(super) envelope: WindowsRunnerPlacementRenewalEnvelope,
    pub(super) acknowledged: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdmissionStateRecord {
    pub(super) request_sha256: Sha256Digest,
    pub(super) handle: String,
    pub(super) custody_content_sha256: Sha256Digest,
    pub(super) created_at: UnixMillis,
    pub(super) phase: AdmissionRecordPhase,
    pub(super) custody: AdmissionCustodyRecord,
    pub(super) current_renewal: Option<AdmissionRenewalState>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PromotionHead {
    pub(super) promotion_serial: u64,
    pub(super) revocation_generation: u64,
    pub(super) payload_sha256: Sha256Digest,
    pub(super) envelope_sha256: Sha256Digest,
}

/// Opaque, validated application snapshot passed through repository adapters.
///
/// Repository implementations may serialize this value through
/// [`Self::canonical_bytes`] and restore it through
/// [`Self::from_canonical_bytes`]. Its internal state remains owned by the
/// broker application service.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsBrokerAdmissionSnapshot {
    pub(super) schema: u16,
    pub(super) records: BTreeMap<String, AdmissionStateRecord>,
    pub(super) promotion_heads: BTreeMap<String, PromotionHead>,
}

impl Default for WindowsBrokerAdmissionSnapshot {
    fn default() -> Self {
        Self {
            schema: STATE_SCHEMA,
            records: BTreeMap::new(),
            promotion_heads: BTreeMap::new(),
        }
    }
}

impl WindowsBrokerAdmissionSnapshot {
    /// Decodes one exact canonical snapshot.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, noncanonical, schema-invalid, or
    /// internally inconsistent bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, WindowsBrokerAdmissionError> {
        if bytes.is_empty() || bytes.len() as u64 > MAX_STATE_BYTES {
            return Err(WindowsBrokerAdmissionError::InvalidState);
        }
        let state: Self =
            serde_json::from_slice(bytes).map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
        state.validate()?;
        if state.canonical_bytes()?.as_slice() != bytes {
            return Err(WindowsBrokerAdmissionError::InvalidState);
        }
        Ok(state)
    }

    /// Encodes the unique bounded repository representation.
    ///
    /// # Errors
    ///
    /// Rejects invalid internal state or an oversized snapshot.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WindowsBrokerAdmissionError> {
        self.validate()?;
        let encoded =
            serde_json::to_vec(self).map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
        if encoded.is_empty() || encoded.len() as u64 > MAX_STATE_BYTES {
            return Err(WindowsBrokerAdmissionError::InvalidState);
        }
        Ok(encoded)
    }

    fn validate(&self) -> Result<(), WindowsBrokerAdmissionError> {
        if self.schema != STATE_SCHEMA
            || self.records.len() > MAX_ADMISSION_RECORDS
            || self.records.iter().any(|(key, record)| {
                key != &record.request_sha256.to_string()
                    || WindowsBrokerCustodyHandle::parse(&record.handle).is_err()
                    || record.custody.request_sha256 != record.request_sha256
            })
        {
            return Err(WindowsBrokerAdmissionError::InvalidState);
        }
        Ok(())
    }
}

/// Durable snapshot boundary used by the broker admission application service.
pub trait WindowsBrokerAdmissionRepository: fmt::Debug + Send + Sync {
    /// Loads the last durably committed snapshot, or an empty snapshot for a
    /// newly initialized repository.
    ///
    /// # Errors
    ///
    /// Fails closed on unavailable, malformed, or inconsistent state.
    fn load(&self) -> Result<WindowsBrokerAdmissionSnapshot, WindowsBrokerAdmissionError>;

    /// Atomically replaces the last durable snapshot.
    ///
    /// # Errors
    ///
    /// Fails closed unless the complete validated snapshot is durable.
    fn store(
        &self,
        snapshot: &WindowsBrokerAdmissionSnapshot,
    ) -> Result<(), WindowsBrokerAdmissionError>;
}

/// Atomic file-snapshot implementation of [`WindowsBrokerAdmissionRepository`].
pub struct FileWindowsBrokerAdmissionRepository {
    path: PathBuf,
}

impl FileWindowsBrokerAdmissionRepository {
    /// Opens and reconciles one absolute service-owned snapshot path.
    ///
    /// # Errors
    ///
    /// Rejects relative paths and unrecoverable or malformed snapshot state.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, WindowsBrokerAdmissionError> {
        let path = path.into();
        if !path.is_absolute() || path.parent().is_none() {
            return Err(WindowsBrokerAdmissionError::InvalidState);
        }
        recover_state_snapshot(&path)?;
        let repository = Self { path };
        let _ = repository.load()?;
        Ok(repository)
    }
}

impl fmt::Debug for FileWindowsBrokerAdmissionRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileWindowsBrokerAdmissionRepository")
            .field("path", &"[SERVICE_OWNED]")
            .finish()
    }
}

impl WindowsBrokerAdmissionRepository for FileWindowsBrokerAdmissionRepository {
    fn load(&self) -> Result<WindowsBrokerAdmissionSnapshot, WindowsBrokerAdmissionError> {
        read_admission_state(&self.path)
    }

    fn store(
        &self,
        snapshot: &WindowsBrokerAdmissionSnapshot,
    ) -> Result<(), WindowsBrokerAdmissionError> {
        persist_admission_state(&self.path, snapshot)
    }
}

fn read_admission_state(
    path: &Path,
) -> Result<WindowsBrokerAdmissionSnapshot, WindowsBrokerAdmissionError> {
    if !path.exists() {
        return Ok(WindowsBrokerAdmissionSnapshot::default());
    }
    let mut file = File::open(path).map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
    if file
        .metadata()
        .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?
        .len()
        > MAX_STATE_BYTES
    {
        return Err(WindowsBrokerAdmissionError::InvalidState);
    }
    let mut encoded = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_STATE_BYTES.saturating_add(1))
        .read_to_end(&mut encoded)
        .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
    if encoded.is_empty() || encoded.len() as u64 > MAX_STATE_BYTES {
        return Err(WindowsBrokerAdmissionError::InvalidState);
    }
    WindowsBrokerAdmissionSnapshot::from_canonical_bytes(&encoded)
}

fn persist_admission_state(
    path: &Path,
    state: &WindowsBrokerAdmissionSnapshot,
) -> Result<(), WindowsBrokerAdmissionError> {
    let encoded = state.canonical_bytes()?;
    let (temporary, previous) = state_sidecars(path)?;
    if temporary.exists() || previous.exists() {
        return Err(WindowsBrokerAdmissionError::InvalidState);
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
    file.write_all(&encoded)
        .and_then(|()| file.sync_all())
        .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
    drop(file);
    if path.exists() {
        fs::rename(path, &previous).map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
    }
    if fs::rename(&temporary, path).is_err() {
        if previous.exists() && !path.exists() {
            let _ = fs::rename(&previous, path);
        }
        return Err(WindowsBrokerAdmissionError::InvalidState);
    }
    if previous.exists() {
        fs::remove_file(previous).map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
    }
    Ok(())
}

fn recover_state_snapshot(path: &Path) -> Result<(), WindowsBrokerAdmissionError> {
    let (temporary, previous) = state_sidecars(path)?;
    if path.exists() {
        let _ = read_admission_state(path)?;
        if temporary.exists() {
            fs::remove_file(&temporary).map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
        }
        if previous.exists() {
            fs::remove_file(&previous).map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
        }
        return Ok(());
    }
    if temporary.exists() {
        let _ = read_admission_state(&temporary)?;
        fs::rename(&temporary, path).map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
        if previous.exists() {
            fs::remove_file(previous).map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
        }
        return Ok(());
    }
    if previous.exists() {
        let _ = read_admission_state(&previous)?;
        fs::rename(previous, path).map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
    }
    Ok(())
}

fn state_sidecars(path: &Path) -> Result<(PathBuf, PathBuf), WindowsBrokerAdmissionError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(WindowsBrokerAdmissionError::InvalidState)?;
    Ok((
        path.with_file_name(format!("{name}.write.tmp")),
        path.with_file_name(format!("{name}.previous")),
    ))
}
