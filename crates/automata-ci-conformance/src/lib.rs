//! Product-owned contracts for deterministic, auditable conformance fixtures.

mod catalog;
mod control;
mod evidence;
mod provider_stub;
mod webhook;

pub use catalog::{
    CatalogError, ContentLock, EvidenceClass, ExternalPrerequisite, FIXTURE_CATALOG_SCHEMA_VERSION,
    FixtureCatalog, FixtureCatalogEntry, FixtureProvider, OperatingSystem, RepositorySourceLock,
};
pub use control::{
    ConformanceClock, DurableTransition, FaultMode, FaultPlan, FaultTarget, FixtureControl,
    FixtureControlError, MAX_CONFORMANCE_SHARDS, ManualConformanceClock, ProductService,
    RestartRecord, ServiceObservation, ServiceRestartProbe, ServiceState, ShardIdentity, ShardPlan,
};
pub use evidence::{
    AdmissionOutcome, AvailabilityReason, EVIDENCE_SCHEMA_VERSION, EvidenceAvailability,
    EvidenceEnvelope, EvidenceError, EvidenceMismatch, EvidenceMismatchKind, EvidenceProvenance,
    PrerequisiteState, ProductBuildIdentity, ScenarioAdmission, compare_evidence,
};
pub use provider_stub::{
    GithubMutationOutcome, GithubStubError, GithubStubExchange, GithubStubRequest,
    GithubStubResponse, GithubStubScript, MAX_STUB_AGGREGATE_RESPONSE_BYTES,
};
pub use webhook::{RawWebhookFixture, RawWebhookFixtureError};
