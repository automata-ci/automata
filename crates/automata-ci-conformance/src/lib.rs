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
    RestartRecord, ShardIdentity, ShardPlan,
};
pub use evidence::{
    AdmissionOutcome, AvailabilityReason, EVIDENCE_SCHEMA_VERSION, EvidenceAvailability,
    EvidenceEnvelope, EvidenceError, EvidenceProvenance, PrerequisiteState, ProductBuildIdentity,
    ScenarioAdmission,
};
pub use provider_stub::{
    GithubMutationOutcome, GithubStubError, GithubStubExchange, GithubStubRequest,
    GithubStubResponse, GithubStubScript,
};
pub use webhook::{RawWebhookFixture, RawWebhookFixtureError};
