use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{EvidenceClass, catalog::hex_digest};

/// Current canonical conformance-evidence envelope schema.
pub const EVIDENCE_SCHEMA_VERSION: u16 = 1;

/// Closed reason that a semantic field is absent from retained evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityReason {
    NotProduced,
    NotRetainedBySchema,
    RedactedByPolicy,
    UnsupportedForEvidenceClass,
}

/// Presence-aware evidence field. Absence can never deserialize as an empty value.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvidenceAvailability<T> {
    Present { value: T },
    Unavailable { reason: AvailabilityReason },
}

impl<T> EvidenceAvailability<T> {
    #[must_use]
    pub const fn present(value: T) -> Self {
        Self::Present { value }
    }

    #[must_use]
    pub const fn unavailable(reason: AvailabilityReason) -> Self {
        Self::Unavailable { reason }
    }
}

/// Exact source, binary, catalog, and environment identity for one evidence record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EvidenceProvenance {
    pub suite_commit: String,
    pub build: ProductBuildIdentity,
    pub fixture_catalog_sha256: String,
    pub fixture_id: String,
    pub scenario_id: String,
    pub shard_id: String,
    pub provider: String,
    pub operating_system: String,
    pub architecture: String,
}

/// Exact source, executable, schema, profile, and service-image build identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProductBuildIdentity {
    pub automata_commit: String,
    pub source_tree_clean: bool,
    pub automata_binary_sha256: String,
    pub runner_binary_sha256: String,
    pub profile_manifest_sha256: String,
    pub profile_image_digest: String,
    pub database_image_digest: String,
    pub object_store_image_digest: String,
    pub protocol_version: u16,
    pub job_ir_schema_version: u16,
    pub runner_requirements_schema_version: u16,
    pub conformance_export_schema_version: u16,
    pub fixture_schema_version: u16,
}

/// State of one live-only external prerequisite.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum PrerequisiteState {
    Available { immutable_revision: String },
    Unavailable { reason: String },
}

/// Admission request for one evidence-producing scenario.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScenarioAdmission {
    pub required_class: EvidenceClass,
    pub prerequisites: Vec<(String, PrerequisiteState)>,
}

/// Explicit result of checking external prerequisites and evidence class.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionOutcome {
    Admitted,
    Skipped { missing: Vec<String> },
}

impl ScenarioAdmission {
    /// Evaluates admission without converting unavailable live prerequisites
    /// into a passing record.
    ///
    /// # Errors
    ///
    /// Rejects a mismatched evidence class or malformed/duplicate prerequisites.
    pub fn evaluate(&self, actual_class: EvidenceClass) -> Result<AdmissionOutcome, EvidenceError> {
        if !actual_class.satisfies(self.required_class) {
            return Err(EvidenceError::EvidenceClassMismatch);
        }
        let mut previous = None;
        let mut missing = Vec::new();
        for (identity, state) in &self.prerequisites {
            validate_text(identity)?;
            if previous.is_some_and(|value: &str| value >= identity.as_str()) {
                return Err(EvidenceError::PrerequisitesNotSorted);
            }
            previous = Some(identity.as_str());
            match state {
                PrerequisiteState::Available { immutable_revision } => {
                    validate_text(immutable_revision)?;
                }
                PrerequisiteState::Unavailable { reason } => {
                    validate_text(reason)?;
                    missing.push(identity.clone());
                }
            }
        }
        if missing.is_empty() {
            Ok(AdmissionOutcome::Admitted)
        } else {
            Ok(AdmissionOutcome::Skipped { missing })
        }
    }
}

/// Versioned canonical evidence wrapper used by every execution class.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EvidenceEnvelope<T> {
    schema_version: u16,
    evidence_class: EvidenceClass,
    provenance: EvidenceProvenance,
    evidence: T,
}

impl<T> EvidenceEnvelope<T>
where
    T: Serialize,
{
    /// Creates a current-schema evidence envelope after validating provenance.
    ///
    /// # Errors
    ///
    /// Rejects mutable or malformed provenance.
    pub fn new(
        evidence_class: EvidenceClass,
        provenance: EvidenceProvenance,
        evidence: T,
    ) -> Result<Self, EvidenceError> {
        validate_provenance(&provenance)?;
        Ok(Self {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            evidence_class,
            provenance,
            evidence,
        })
    }

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub const fn evidence_class(&self) -> EvidenceClass {
        self.evidence_class
    }

    #[must_use]
    pub const fn provenance(&self) -> &EvidenceProvenance {
        &self.provenance
    }

    #[must_use]
    pub const fn evidence(&self) -> &T {
        &self.evidence
    }

    /// Encodes this record as compact JSON with recursively sorted object keys.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization fails.
    pub fn canonical_json(&self) -> Result<Vec<u8>, EvidenceError> {
        let value = serde_json::to_value(self).map_err(EvidenceError::Json)?;
        serde_json::to_vec(&sort_json_objects(value)).map_err(EvidenceError::Json)
    }

    /// Canonically encodes and digests this record.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization fails.
    pub fn canonical_sha256(&self) -> Result<String, EvidenceError> {
        Ok(hex_digest(&Sha256::digest(self.canonical_json()?)))
    }
}

fn sort_json_objects(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(sort_json_objects).collect()),
        Value::Object(values) => {
            let mut sorted = values.into_iter().collect::<Vec<_>>();
            sorted.sort_unstable_by(|left, right| left.0.cmp(&right.0));
            Value::Object(
                sorted
                    .into_iter()
                    .map(|(key, value)| (key, sort_json_objects(value)))
                    .collect(),
            )
        }
        scalar => scalar,
    }
}

impl<T> EvidenceEnvelope<T>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    /// Parses a strict current-schema evidence envelope.
    ///
    /// # Errors
    ///
    /// Rejects unknown fields, unsupported schemas, and malformed provenance.
    pub fn from_json(bytes: &[u8]) -> Result<Self, EvidenceError> {
        let envelope: Self = serde_json::from_slice(bytes).map_err(EvidenceError::Json)?;
        if envelope.schema_version != EVIDENCE_SCHEMA_VERSION {
            return Err(EvidenceError::UnsupportedSchema(envelope.schema_version));
        }
        validate_provenance(&envelope.provenance)?;
        Ok(envelope)
    }
}

fn validate_provenance(value: &EvidenceProvenance) -> Result<(), EvidenceError> {
    for commit in [&value.suite_commit, &value.build.automata_commit] {
        if commit.len() != 40 || !lower_hex(commit) {
            return Err(EvidenceError::InvalidCommit);
        }
    }
    for digest in [
        &value.build.automata_binary_sha256,
        &value.build.runner_binary_sha256,
        &value.build.profile_manifest_sha256,
        &value.fixture_catalog_sha256,
    ] {
        if digest.len() != 64 || !lower_hex(digest) {
            return Err(EvidenceError::InvalidDigest);
        }
    }
    for digest in [
        &value.build.profile_image_digest,
        &value.build.database_image_digest,
        &value.build.object_store_image_digest,
    ] {
        let Some(digest) = digest.strip_prefix("sha256:") else {
            return Err(EvidenceError::InvalidDigest);
        };
        if digest.len() != 64 || !lower_hex(digest) {
            return Err(EvidenceError::InvalidDigest);
        }
    }
    if !value.build.source_tree_clean
        || [
            value.build.protocol_version,
            value.build.job_ir_schema_version,
            value.build.runner_requirements_schema_version,
            value.build.conformance_export_schema_version,
            value.build.fixture_schema_version,
        ]
        .contains(&0)
    {
        return Err(EvidenceError::InvalidBuildIdentity);
    }
    for text in [
        &value.fixture_id,
        &value.scenario_id,
        &value.shard_id,
        &value.provider,
        &value.operating_system,
        &value.architecture,
    ] {
        if text.is_empty()
            || text.len() > 256
            || text.trim() != text
            || text.chars().any(char::is_control)
        {
            return Err(EvidenceError::InvalidIdentity);
        }
    }
    Ok(())
}

fn validate_text(value: &str) -> Result<(), EvidenceError> {
    if value.is_empty()
        || value.len() > 1_024
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(EvidenceError::InvalidIdentity);
    }
    Ok(())
}

fn lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("conformance evidence JSON is invalid: {0}")]
    Json(serde_json::Error),
    #[error("unsupported evidence schema {0}")]
    UnsupportedSchema(u16),
    #[error("evidence provenance commit is invalid")]
    InvalidCommit,
    #[error("evidence provenance digest is invalid")]
    InvalidDigest,
    #[error("evidence provenance identity is invalid")]
    InvalidIdentity,
    #[error("evidence build identity is incomplete, dirty, or unversioned")]
    InvalidBuildIdentity,
    #[error("observed evidence class cannot satisfy the requested class")]
    EvidenceClassMismatch,
    #[error("scenario prerequisites are not strictly identity sorted")]
    PrerequisitesNotSorted,
}
