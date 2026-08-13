use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    EvidenceClass, FixtureCatalog, FixtureCatalogEntry, FixtureProvider, OperatingSystem,
    catalog::{CatalogError, hex_digest},
};

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
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScenarioAdmission {
    fixture_id: String,
    required_class: EvidenceClass,
    prerequisites: Vec<(String, PrerequisiteState)>,
}

/// Explicit result of checking external prerequisites and evidence class.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionOutcome {
    Admitted,
    Skipped { missing: Vec<String> },
}

impl ScenarioAdmission {
    /// Binds an admission decision to every prerequisite locked by one fixture.
    ///
    /// # Errors
    ///
    /// Rejects omitted, extra, reordered, or revision-mismatched prerequisite
    /// observations. An unavailable prerequisite must still be represented.
    pub fn for_fixture(
        fixture: &FixtureCatalogEntry,
        prerequisites: Vec<(String, PrerequisiteState)>,
    ) -> Result<Self, EvidenceError> {
        if prerequisites.len() != fixture.external_prerequisites.len() {
            return Err(EvidenceError::PrerequisiteSetMismatch);
        }
        for ((identity, state), expected) in
            prerequisites.iter().zip(&fixture.external_prerequisites)
        {
            validate_text(identity)?;
            if identity != &expected.identity {
                return Err(EvidenceError::PrerequisiteSetMismatch);
            }
            match state {
                PrerequisiteState::Available { immutable_revision } => {
                    if immutable_revision != &expected.immutable_revision {
                        return Err(EvidenceError::PrerequisiteRevisionMismatch);
                    }
                }
                PrerequisiteState::Unavailable { reason } => validate_text(reason)?,
            }
        }
        Ok(Self {
            fixture_id: fixture.id.clone(),
            required_class: fixture.evidence_class,
            prerequisites,
        })
    }

    #[must_use]
    pub fn fixture_id(&self) -> &str {
        &self.fixture_id
    }

    #[must_use]
    pub const fn required_class(&self) -> EvidenceClass {
        self.required_class
    }

    #[must_use]
    pub fn prerequisites(&self) -> &[(String, PrerequisiteState)] {
        &self.prerequisites
    }

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
        let mut missing = Vec::new();
        for (identity, state) in &self.prerequisites {
            match state {
                PrerequisiteState::Available { .. } => {}
                PrerequisiteState::Unavailable { .. } => {
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceEnvelope<T> {
    schema_version: u16,
    evidence_class: EvidenceClass,
    provenance: EvidenceProvenance,
    evidence: T,
    expected_evidence_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct EvidenceEnvelopeWire<T> {
    schema_version: u16,
    evidence_class: EvidenceClass,
    provenance: EvidenceProvenance,
    evidence: T,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceEnvelopeRef<'a> {
    schema_version: u16,
    evidence_class: EvidenceClass,
    provenance: &'a EvidenceProvenance,
    evidence: &'a Value,
}

impl<T: Serialize> Serialize for EvidenceEnvelope<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        validate_provenance(&self.provenance).map_err(serde::ser::Error::custom)?;
        let evidence = serde_json::to_value(&self.evidence).map_err(serde::ser::Error::custom)?;
        validate_expected_evidence(&evidence, &self.expected_evidence_sha256)
            .map_err(serde::ser::Error::custom)?;
        EvidenceEnvelopeRef {
            schema_version: self.schema_version,
            evidence_class: self.evidence_class,
            provenance: &self.provenance,
            evidence: &evidence,
        }
        .serialize(serializer)
    }
}

impl<T> EvidenceEnvelope<T>
where
    T: Serialize,
{
    /// Creates a current-schema envelope bound to its immutable catalog entry.
    ///
    /// # Errors
    ///
    /// Rejects mutable or malformed provenance, a catalog mismatch, and evidence
    /// whose canonical digest differs from the catalog lock.
    pub fn for_fixture(
        catalog: &FixtureCatalog,
        provenance: EvidenceProvenance,
        evidence: T,
    ) -> Result<Self, EvidenceError> {
        validate_provenance(&provenance)?;
        let fixture = catalog
            .entry(&provenance.fixture_id)
            .ok_or(EvidenceError::FixtureNotFound)?;
        let envelope = Self {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            evidence_class: fixture.evidence_class,
            provenance,
            evidence,
            expected_evidence_sha256: fixture.expected_evidence_sha256.clone(),
        };
        envelope.validate_catalog_binding(catalog)?;
        Ok(envelope)
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

    /// Revalidates that this envelope names the exact immutable fixture,
    /// catalog digest, provider, operating system, class, and expected evidence.
    ///
    /// # Errors
    ///
    /// Returns a specific binding error for any provenance or evidence drift.
    pub fn validate_catalog_binding(&self, catalog: &FixtureCatalog) -> Result<(), EvidenceError> {
        let catalog_digest = catalog.canonical_sha256().map_err(EvidenceError::Catalog)?;
        if self.provenance.fixture_catalog_sha256 != catalog_digest {
            return Err(EvidenceError::CatalogDigestMismatch);
        }
        let fixture = catalog
            .entry(&self.provenance.fixture_id)
            .ok_or(EvidenceError::FixtureNotFound)?;
        if self.evidence_class != fixture.evidence_class {
            return Err(EvidenceError::EvidenceClassMismatch);
        }
        if self.provenance.provider != provider_name(fixture.provider)
            || self.provenance.operating_system != operating_system_name(fixture.operating_system)
        {
            return Err(EvidenceError::FixtureEnvironmentMismatch);
        }
        if self.expected_evidence_sha256 != fixture.expected_evidence_sha256 {
            return Err(EvidenceError::ExpectedEvidenceDigestMismatch);
        }
        self.validate_expected_evidence()
    }

    fn validate_expected_evidence(&self) -> Result<(), EvidenceError> {
        let evidence = serde_json::to_value(&self.evidence).map_err(EvidenceError::Json)?;
        validate_expected_evidence(&evidence, &self.expected_evidence_sha256)
    }
}

fn validate_expected_evidence(value: &Value, expected_sha256: &str) -> Result<(), EvidenceError> {
    let encoded =
        serde_json::to_vec(&sort_json_objects(value.clone())).map_err(EvidenceError::Json)?;
    if hex_digest(&Sha256::digest(encoded)) != expected_sha256 {
        return Err(EvidenceError::ExpectedEvidenceDigestMismatch);
    }
    Ok(())
}

fn provider_name(provider: FixtureProvider) -> &'static str {
    match provider {
        FixtureProvider::Github => "github",
    }
}

fn operating_system_name(operating_system: OperatingSystem) -> &'static str {
    match operating_system {
        OperatingSystem::Linux => "linux",
        OperatingSystem::Windows => "windows",
        OperatingSystem::Macos => "macos",
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
    pub fn from_json(catalog: &FixtureCatalog, bytes: &[u8]) -> Result<Self, EvidenceError> {
        let wire: EvidenceEnvelopeWire<T> =
            serde_json::from_slice(bytes).map_err(EvidenceError::Json)?;
        let fixture = catalog
            .entry(&wire.provenance.fixture_id)
            .ok_or(EvidenceError::FixtureNotFound)?;
        let envelope = Self {
            schema_version: wire.schema_version,
            evidence_class: wire.evidence_class,
            provenance: wire.provenance,
            evidence: wire.evidence,
            expected_evidence_sha256: fixture.expected_evidence_sha256.clone(),
        };
        if envelope.schema_version != EVIDENCE_SCHEMA_VERSION {
            return Err(EvidenceError::UnsupportedSchema(envelope.schema_version));
        }
        validate_provenance(&envelope.provenance)?;
        envelope.validate_catalog_binding(catalog)?;
        if envelope.canonical_json()?.as_slice() != bytes {
            return Err(EvidenceError::NonCanonicalEncoding);
        }
        Ok(envelope)
    }
}

/// Kind of exact structural difference between expected and observed evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceMismatchKind {
    MissingField,
    UnexpectedField,
    TypeMismatch,
    ArrayLengthMismatch,
    ValueMismatch,
}

/// Exact first difference found by [`compare_evidence`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceMismatch {
    pub path: String,
    pub kind: EvidenceMismatchKind,
}

/// Strictly compares serialized evidence without coercion or missing-field defaults.
///
/// Object key order is irrelevant; array order, scalar types, availability states,
/// and every field are exact.
///
/// # Errors
///
/// Returns serialization errors or the first deterministic structural mismatch.
pub fn compare_evidence<E: Serialize, A: Serialize>(
    expected: &E,
    actual: &A,
) -> Result<(), EvidenceError> {
    let expected = serde_json::to_value(expected).map_err(EvidenceError::Json)?;
    let actual = serde_json::to_value(actual).map_err(EvidenceError::Json)?;
    compare_values(&expected, &actual, "$")
}

fn compare_values(expected: &Value, actual: &Value, path: &str) -> Result<(), EvidenceError> {
    let mismatch = |kind| {
        Err(EvidenceError::EvidenceMismatch(EvidenceMismatch {
            path: path.to_owned(),
            kind,
        }))
    };
    match (expected, actual) {
        (Value::Object(expected), Value::Object(actual)) => {
            for (key, expected_value) in expected {
                let child_path = json_path(path, key);
                let Some(actual_value) = actual.get(key) else {
                    return Err(EvidenceError::EvidenceMismatch(EvidenceMismatch {
                        path: child_path,
                        kind: EvidenceMismatchKind::MissingField,
                    }));
                };
                compare_values(expected_value, actual_value, &child_path)?;
            }
            if let Some(key) = actual.keys().find(|key| !expected.contains_key(*key)) {
                return Err(EvidenceError::EvidenceMismatch(EvidenceMismatch {
                    path: json_path(path, key),
                    kind: EvidenceMismatchKind::UnexpectedField,
                }));
            }
            Ok(())
        }
        (Value::Array(expected), Value::Array(actual)) => {
            if expected.len() != actual.len() {
                return mismatch(EvidenceMismatchKind::ArrayLengthMismatch);
            }
            for (index, (expected, actual)) in expected.iter().zip(actual).enumerate() {
                compare_values(expected, actual, &format!("{path}[{index}]"))?;
            }
            Ok(())
        }
        (Value::Null, Value::Null)
        | (Value::Bool(_), Value::Bool(_))
        | (Value::Number(_), Value::Number(_))
        | (Value::String(_), Value::String(_)) => {
            if expected == actual {
                Ok(())
            } else {
                mismatch(EvidenceMismatchKind::ValueMismatch)
            }
        }
        _ => mismatch(EvidenceMismatchKind::TypeMismatch),
    }
}

fn json_path(parent: &str, key: &str) -> String {
    let escaped = key.replace('~', "~0").replace('/', "~1");
    format!("{parent}/{escaped}")
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
    #[error("fixture catalog cannot be used for evidence binding: {0}")]
    Catalog(CatalogError),
    #[error("conformance evidence JSON is not its exact canonical encoding")]
    NonCanonicalEncoding,
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
    #[error("scenario prerequisite observations do not exactly match the fixture catalog")]
    PrerequisiteSetMismatch,
    #[error("an available scenario prerequisite revision differs from its catalog lock")]
    PrerequisiteRevisionMismatch,
    #[error("evidence fixture does not exist in the bound catalog")]
    FixtureNotFound,
    #[error("evidence catalog digest differs from its exact canonical catalog")]
    CatalogDigestMismatch,
    #[error("evidence provider or operating system differs from the fixture catalog")]
    FixtureEnvironmentMismatch,
    #[error("evidence digest differs from the fixture catalog expectation")]
    ExpectedEvidenceDigestMismatch,
    #[error("evidence structures differ at {0:?}")]
    EvidenceMismatch(EvidenceMismatch),
}
