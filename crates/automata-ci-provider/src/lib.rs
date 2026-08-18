//! Provider-neutral source-hosting identities and capabilities.
//!
//! A [`ProviderTypeId`] selects an adapter implementation. A
//! [`ProviderInstanceId`] selects one configured installation of that provider,
//! and all provider-native identities are interpreted within that instance.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod capability;
mod identity;

pub use capability::{
    AuthorizationCodeLoginCapability, ChangedFileCapability, ChangedFileCompleteness,
    CommitStatusCapability, CommitStatusState, MembershipEvidenceCapability, PkceSupport,
    ProviderCapabilities, ProviderCapabilitiesError, ProviderCapability, ProviderCapabilityKind,
    RepositoryEventCapability, RepositoryEventKind, RichCheckCapability, SourceReadCapability,
    StatusHistoryModel, WorkloadCredentialCapability, WorkloadCredentialProfile,
    WorkloadCredentialRevocation,
};
pub use identity::{
    ExternalDeliveryId, ExternalDeliveryIdentity, ExternalRepositoryId, ExternalRepositoryIdentity,
    ExternalSubjectId, ExternalSubjectIdentity, ExternalSubjectKind, MAX_EXTERNAL_ID_BYTES,
    MAX_PROVIDER_TYPE_ID_BYTES, ProviderConnectionId, ProviderIdentityError, ProviderInstanceId,
    ProviderTypeId,
};
