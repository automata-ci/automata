use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Current immutable fixture-catalog schema.
pub const FIXTURE_CATALOG_SCHEMA_VERSION: u16 = 1;

// foundation-governance: operational-limit
const MAX_CATALOG_ENTRIES: usize = 4_096;
// foundation-governance: operational-limit
const MAX_LOCKS_PER_FIXTURE: usize = 4_096;
// foundation-governance: operational-limit
const MAX_EXTERNAL_PREREQUISITES: usize = 128;

/// Evidence class produced by one fixture execution.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    /// Bounded component or adapter contract evidence.
    Contract,
    /// Protocol behavior from the loopback provider emulator.
    ProviderEmulator,
    /// Real Automata processes with hermetic dependencies and no external network.
    HermeticProduct,
    /// GitHub-hosted execution observed through live GitHub APIs.
    LiveGithub,
    /// Real GitHub ingress and authority driving Automata.
    LiveAutomata,
}

impl EvidenceClass {
    /// Reports whether an observed class satisfies an exact gate class.
    ///
    /// Evidence classes are deliberately non-substitutable: emulator evidence
    /// cannot satisfy a live gate, and live evidence cannot conceal a missing
    /// hermetic or emulator result.
    #[must_use]
    pub const fn satisfies(self, required: Self) -> bool {
        self as u8 == required as u8
    }
}

/// Closed provider identity attached to an immutable fixture.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureProvider {
    Github,
}

/// Closed operating-system family required by a fixture.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatingSystem {
    Linux,
    Windows,
    Macos,
}

/// Immutable repository source coordinate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RepositorySourceLock {
    pub remote: String,
    pub commit: String,
    pub archive_sha256: String,
}

/// Digest lock for one workflow, action, or other fixture input.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ContentLock {
    pub identity: String,
    pub sha256: String,
}

/// Exact external prerequisite for a live-provider fixture.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExternalPrerequisite {
    pub identity: String,
    pub immutable_revision: String,
}

/// One immutable and independently auditable fixture.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FixtureCatalogEntry {
    pub id: String,
    pub upstream_version: String,
    pub source: RepositorySourceLock,
    pub workflows: Vec<ContentLock>,
    pub actions: Vec<ContentLock>,
    pub operating_system: OperatingSystem,
    pub provider: FixtureProvider,
    pub evidence_class: EvidenceClass,
    pub external_prerequisites: Vec<ExternalPrerequisite>,
    pub expected_evidence_sha256: String,
}

/// Versioned fixture catalog with a deterministic canonical encoding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FixtureCatalog {
    schema_version: u16,
    entries: Vec<FixtureCatalogEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FixtureCatalogWire {
    schema_version: u16,
    entries: Vec<FixtureCatalogEntry>,
}

impl FixtureCatalog {
    /// Builds and validates one current-schema catalog.
    ///
    /// # Errors
    ///
    /// Rejects unbounded, unsorted, duplicate, mutable, or malformed locks and
    /// rejects external prerequisites on non-live evidence.
    pub fn new(entries: Vec<FixtureCatalogEntry>) -> Result<Self, CatalogError> {
        let catalog = Self {
            schema_version: FIXTURE_CATALOG_SCHEMA_VERSION,
            entries,
        };
        catalog.validate()?;
        Ok(catalog)
    }

    /// Reads a catalog while rejecting unknown fields and non-current schemas.
    ///
    /// # Errors
    ///
    /// Returns a parse or validation error for any non-canonical document.
    pub fn from_json(bytes: &[u8]) -> Result<Self, CatalogError> {
        let wire: FixtureCatalogWire = serde_json::from_slice(bytes).map_err(CatalogError::Json)?;
        let catalog = Self {
            schema_version: wire.schema_version,
            entries: wire.entries,
        };
        catalog.validate()?;
        if catalog.canonical_json()?.as_slice() != bytes {
            return Err(CatalogError::NonCanonicalEncoding);
        }
        Ok(catalog)
    }

    /// Returns the current schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns catalog entries in canonical identity order.
    #[must_use]
    pub fn entries(&self) -> &[FixtureCatalogEntry] {
        &self.entries
    }

    /// Finds an immutable fixture by its exact catalog identity.
    #[must_use]
    pub fn entry(&self, identity: &str) -> Option<&FixtureCatalogEntry> {
        self.entries
            .binary_search_by(|entry| entry.id.as_str().cmp(identity))
            .ok()
            .map(|index| &self.entries[index])
    }

    /// Produces the canonical compact JSON representation with one trailing newline.
    ///
    /// # Errors
    ///
    /// Returns an error only if an already validated catalog cannot serialize.
    pub fn canonical_json(&self) -> Result<Vec<u8>, CatalogError> {
        self.validate()?;
        let mut encoded = serde_json::to_vec(self).map_err(CatalogError::Json)?;
        encoded.push(b'\n');
        Ok(encoded)
    }

    /// Returns the SHA-256 of the canonical catalog bytes.
    ///
    /// # Errors
    ///
    /// Propagates canonical encoding failures.
    pub fn canonical_sha256(&self) -> Result<String, CatalogError> {
        Ok(hex_digest(&Sha256::digest(self.canonical_json()?)))
    }

    fn validate(&self) -> Result<(), CatalogError> {
        if self.schema_version != FIXTURE_CATALOG_SCHEMA_VERSION {
            return Err(CatalogError::UnsupportedSchema(self.schema_version));
        }
        if self.entries.is_empty() || self.entries.len() > MAX_CATALOG_ENTRIES {
            return Err(CatalogError::InvalidEntryCount);
        }
        let mut previous = None;
        for entry in &self.entries {
            validate_identifier(&entry.id)?;
            if previous.is_some_and(|value: &str| value >= entry.id.as_str()) {
                return Err(CatalogError::EntriesNotSorted);
            }
            previous = Some(entry.id.as_str());
            validate_text(&entry.upstream_version)?;
            validate_source(&entry.source)?;
            validate_locks(&entry.workflows, true)?;
            validate_locks(&entry.actions, false)?;
            validate_sha256(&entry.expected_evidence_sha256)?;
            validate_prerequisites(&entry.external_prerequisites)?;
            if !matches!(
                entry.evidence_class,
                EvidenceClass::LiveGithub | EvidenceClass::LiveAutomata
            ) && !entry.external_prerequisites.is_empty()
            {
                return Err(CatalogError::NonLiveFixtureHasExternalPrerequisite);
            }
        }
        Ok(())
    }
}

fn validate_source(source: &RepositorySourceLock) -> Result<(), CatalogError> {
    if !valid_https_remote(&source.remote) {
        return Err(CatalogError::InvalidRemote);
    }
    validate_commit(&source.commit)?;
    validate_sha256(&source.archive_sha256)
}

fn valid_https_remote(value: &str) -> bool {
    let Some(coordinate) = value.strip_prefix("https://") else {
        return false;
    };
    let Some((host, path)) = coordinate.split_once('/') else {
        return false;
    };
    if host.is_empty()
        || !host.contains('.')
        || host.contains(['@', ':'])
        || host.split('.').any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        || path.is_empty()
        || path.starts_with('/')
        || path.ends_with('/')
        || path.split('/').any(|component| {
            component.is_empty()
                || matches!(component, "." | "..")
                || !component.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'@' | b'+')
                })
        })
        || value.contains(['?', '#', '\\'])
    {
        return false;
    }
    true
}

fn validate_locks(locks: &[ContentLock], required: bool) -> Result<(), CatalogError> {
    if (required && locks.is_empty()) || locks.len() > MAX_LOCKS_PER_FIXTURE {
        return Err(CatalogError::InvalidLockCount);
    }
    let mut previous = None;
    for lock in locks {
        validate_text(&lock.identity)?;
        validate_sha256(&lock.sha256)?;
        if previous.is_some_and(|value: &str| value >= lock.identity.as_str()) {
            return Err(CatalogError::LocksNotSorted);
        }
        previous = Some(lock.identity.as_str());
    }
    Ok(())
}

fn validate_prerequisites(values: &[ExternalPrerequisite]) -> Result<(), CatalogError> {
    if values.len() > MAX_EXTERNAL_PREREQUISITES {
        return Err(CatalogError::InvalidPrerequisiteCount);
    }
    let mut identities = BTreeSet::new();
    let mut previous = None;
    for value in values {
        validate_identifier(&value.identity)?;
        validate_immutable_revision(&value.immutable_revision)?;
        if !identities.insert(value.identity.as_str()) {
            return Err(CatalogError::DuplicatePrerequisite);
        }
        if previous.is_some_and(|identity: &str| identity > value.identity.as_str()) {
            return Err(CatalogError::PrerequisitesNotSorted);
        }
        previous = Some(value.identity.as_str());
    }
    Ok(())
}

fn validate_immutable_revision(value: &str) -> Result<(), CatalogError> {
    validate_text(value)?;
    let Some((kind, revision)) = value.split_once(':') else {
        return Err(CatalogError::InvalidImmutableRevision);
    };
    validate_identifier(kind).map_err(|_| CatalogError::InvalidImmutableRevision)?;
    let decimal = !revision.is_empty()
        && revision.bytes().all(|byte| byte.is_ascii_digit())
        && !revision.starts_with('0');
    let digest = matches!(revision.len(), 40 | 64)
        && revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
    if !decimal && !digest {
        return Err(CatalogError::InvalidImmutableRevision);
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), CatalogError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
    {
        return Err(CatalogError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_text(value: &str) -> Result<(), CatalogError> {
    if value.is_empty()
        || value.len() > 1_024
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(CatalogError::InvalidText);
    }
    Ok(())
}

fn validate_commit(value: &str) -> Result<(), CatalogError> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(CatalogError::InvalidCommit);
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), CatalogError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(CatalogError::InvalidSha256);
    }
    Ok(())
}

pub(crate) fn hex_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

/// Invalid immutable fixture-catalog data.
#[derive(Debug, Error)]
pub enum CatalogError {
    #[error("fixture catalog JSON is invalid: {0}")]
    Json(serde_json::Error),
    #[error("fixture catalog JSON is not its exact canonical encoding")]
    NonCanonicalEncoding,
    #[error("unsupported fixture catalog schema {0}")]
    UnsupportedSchema(u16),
    #[error("fixture catalog entry count is invalid")]
    InvalidEntryCount,
    #[error("fixture catalog entries are not strictly identity sorted")]
    EntriesNotSorted,
    #[error("fixture identifier is invalid")]
    InvalidIdentifier,
    #[error("fixture text is empty, unsafe, or oversized")]
    InvalidText,
    #[error("fixture source remote is not immutable-safe HTTPS")]
    InvalidRemote,
    #[error("fixture source commit is not an exact lowercase SHA-1")]
    InvalidCommit,
    #[error("fixture SHA-256 is invalid")]
    InvalidSha256,
    #[error("fixture content-lock count is invalid")]
    InvalidLockCount,
    #[error("fixture content locks are not strictly identity sorted")]
    LocksNotSorted,
    #[error("fixture external-prerequisite count is invalid")]
    InvalidPrerequisiteCount,
    #[error("fixture external prerequisites contain duplicate identities")]
    DuplicatePrerequisite,
    #[error("fixture external prerequisites are not identity sorted")]
    PrerequisitesNotSorted,
    #[error("fixture external prerequisite revision is not immutable")]
    InvalidImmutableRevision,
    #[error("non-live fixture declares an external prerequisite")]
    NonLiveFixtureHasExternalPrerequisite,
}
