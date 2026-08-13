//! Resolved provider permission requests carried by executable jobs.

use serde::{Deserialize, Serialize};

use super::JobValidationError;
use crate::PermissionLevel;

/// Maximum number of explicitly named permission grants in one job request.
// foundation-governance: parity-limit
pub const MAX_JOB_PERMISSION_GRANTS: usize = 64;
/// Maximum UTF-8 bytes in one canonical provider permission name.
// foundation-governance: parity-limit
pub const MAX_JOB_PERMISSION_NAME_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JobPermissionLimitRejection {
    Grants,
    NameBytes,
}

const fn job_permission_grant_rejection(observed: usize) -> Option<JobPermissionLimitRejection> {
    if observed > MAX_JOB_PERMISSION_GRANTS {
        return Some(JobPermissionLimitRejection::Grants);
    }
    None
}

const fn job_permission_name_byte_rejection(
    observed: usize,
) -> Option<JobPermissionLimitRejection> {
    if observed > MAX_JOB_PERMISSION_NAME_BYTES {
        return Some(JobPermissionLimitRejection::NameBytes);
    }
    None
}

const ID_TOKEN_PERMISSION: &str = "id-token";

/// One source-span-free provider permission grant retained in executable `JobIR`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobPermissionGrant {
    name: String,
    level: PermissionLevel,
}

impl JobPermissionGrant {
    /// Creates one named provider permission grant.
    ///
    /// Canonical name, ordering, and security invariants remain enforced at the
    /// enclosing [`super::JobIrEnvelope`] validation boundary.
    #[must_use]
    pub fn new(name: impl Into<String>, level: PermissionLevel) -> Self {
        Self {
            name: name.into(),
            level,
        }
    }

    /// Returns the canonical provider permission name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the requested access level.
    #[must_use]
    pub const fn level(&self) -> PermissionLevel {
        self.level
    }
}

/// Provider permission request carried by one executable job.
///
/// Resolution chooses the job declaration over the workflow declaration. An
/// absent declaration at both layers is represented as [`Self::ProviderDefault`]
/// until a provider adapter expands it from immutable repository policy.
/// Provider activation must likewise expand `read-all` and `write-all` before
/// runtime credential issuance. An explicit mapping is complete: omitted names
/// are denied, and an empty mapping denies every provider permission. Mappings
/// are canonical, strictly name-sorted vectors independent of source spans.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    tag = "mode",
    content = "permissions",
    rename_all = "snake_case"
)]
pub enum JobPermissionRequest {
    /// Requests the provider's default permissions because neither source layer declared any.
    ProviderDefault,
    /// Requests read access across all permissions supported by the provider.
    ReadAll,
    /// Requests write access across all permissions supported by the provider.
    WriteAll,
    /// Requests a total canonical map; omitted names, including every name in an empty map, are denied.
    Mapping(Vec<JobPermissionGrant>),
}

impl JobPermissionRequest {
    /// Creates an explicit mapping and sorts it into canonical name order.
    ///
    /// Duplicate, malformed, excessive, or security-invalid entries remain
    /// visible and are rejected by `JobIR` validation.
    #[must_use]
    pub fn mapping(grants: impl IntoIterator<Item = JobPermissionGrant>) -> Self {
        let mut grants = grants.into_iter().collect::<Vec<_>>();
        grants.sort_by(|left, right| left.name.cmp(&right.name));
        Self::Mapping(grants)
    }

    /// Returns the complete explicit grant map when present.
    ///
    /// Consumers must deny names omitted from this slice. An empty slice denies
    /// every provider permission.
    #[must_use]
    pub fn grants(&self) -> Option<&[JobPermissionGrant]> {
        match self {
            Self::Mapping(grants) => Some(grants),
            Self::ProviderDefault | Self::ReadAll | Self::WriteAll => None,
        }
    }

    /// Resolves the explicitly requested level for one provider permission.
    ///
    /// Provider defaults remain unresolved and therefore return `None`.
    /// `read-all` and `write-all` resolve to their respective levels, while an
    /// explicit mapping is total and returns `None` for an omitted name. An
    /// invalid mapping also returns `None`, so authorization consumers fail
    /// closed even if they are handed a value before the enclosing `JobIR`
    /// validation boundary.
    #[must_use]
    pub fn requested_level(&self, name: &str) -> Option<PermissionLevel> {
        match self {
            Self::ProviderDefault => None,
            Self::ReadAll => Some(PermissionLevel::Read),
            Self::WriteAll => Some(PermissionLevel::Write),
            Self::Mapping(grants) => {
                if self.validate().is_err() {
                    return None;
                }
                grants
                    .binary_search_by(|grant| grant.name.as_str().cmp(name))
                    .ok()
                    .map(|index| grants[index].level)
            }
        }
    }

    pub(super) fn validate(&self) -> Result<(), JobValidationError> {
        let Self::Mapping(grants) = self else {
            return Ok(());
        };
        if job_permission_grant_rejection(grants.len()).is_some() {
            return Err(JobValidationError::TooManyPermissionGrants {
                maximum: MAX_JOB_PERMISSION_GRANTS,
            });
        }

        let mut previous = None;
        for grant in grants {
            if !canonical_permission_name(&grant.name) {
                return Err(JobValidationError::InvalidPermissionName);
            }
            if previous.is_some_and(|name| name >= grant.name.as_str()) {
                return Err(JobValidationError::NonCanonicalPermissionMapping);
            }
            if grant.name == ID_TOKEN_PERMISSION && grant.level == PermissionLevel::Read {
                return Err(JobValidationError::IdTokenReadPermission);
            }
            previous = Some(grant.name.as_str());
        }
        Ok(())
    }
}

fn canonical_permission_name(value: &str) -> bool {
    if value.is_empty() || job_permission_name_byte_rejection(value.len()).is_some() {
        return false;
    }
    let mut bytes = value.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase()) {
        return false;
    }
    let mut previous_hyphen = false;
    for byte in bytes {
        if byte == b'-' {
            if previous_hyphen {
                return false;
            }
            previous_hyphen = true;
        } else if byte.is_ascii_lowercase() || byte.is_ascii_digit() {
            previous_hyphen = false;
        } else {
            return false;
        }
    }
    !previous_hyphen
}

#[cfg(test)]
mod limit_contract_tests {
    use super::{
        JobPermissionLimitRejection, MAX_JOB_PERMISSION_GRANTS, MAX_JOB_PERMISSION_NAME_BYTES,
        job_permission_grant_rejection, job_permission_name_byte_rejection,
    };

    #[test]
    fn job_permission_grant_limit_has_exact_boundaries() {
        assert_eq!(
            job_permission_grant_rejection(MAX_JOB_PERMISSION_GRANTS - 1),
            None
        );
        assert_eq!(
            job_permission_grant_rejection(MAX_JOB_PERMISSION_GRANTS),
            None
        );
        assert_eq!(
            job_permission_grant_rejection(MAX_JOB_PERMISSION_GRANTS + 1),
            Some(JobPermissionLimitRejection::Grants)
        );
    }

    #[test]
    fn job_permission_name_byte_limit_has_exact_boundaries() {
        assert_eq!(
            job_permission_name_byte_rejection(MAX_JOB_PERMISSION_NAME_BYTES - 1),
            None
        );
        assert_eq!(
            job_permission_name_byte_rejection(MAX_JOB_PERMISSION_NAME_BYTES),
            None
        );
        assert_eq!(
            job_permission_name_byte_rejection(MAX_JOB_PERMISSION_NAME_BYTES + 1),
            Some(JobPermissionLimitRejection::NameBytes)
        );
    }
}
