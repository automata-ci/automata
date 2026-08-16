//! Handle-bound Windows file custody checks.
//!
//! The production reader is available only on Windows. Its policy model is
//! platform-neutral so the access-control decisions remain testable on every
//! authoring host.

#![forbid(unsafe_code)]

use thiserror::Error;

#[cfg(any(windows, test))]
mod policy;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::read_attested_file;

#[cfg(all(windows, feature = "test-support"))]
pub use windows::restrict_file_to_current_user_for_test;

/// Whether principals outside the trusted owner set may read file contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadAccess {
    /// Only the current principal, approved service principals, `LocalSystem`,
    /// and builtin Administrators may receive any file access grant.
    Private,
    /// Other principals may receive read-only access, but never mutation,
    /// deletion, or security-descriptor authority.
    PublicRead,
}

/// A canonical Windows virtual-service SID approved as a file owner.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TrustedServiceSid(String);

impl TrustedServiceSid {
    /// Parses one `NT SERVICE` virtual-account SID.
    ///
    /// # Errors
    ///
    /// Rejects every value outside the canonical `S-1-5-80-a-b-c-d-e`
    /// representation.
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidTrustedServiceSid> {
        let value = value.into();
        let Some(suffix) = value.strip_prefix("S-1-5-80-") else {
            return Err(InvalidTrustedServiceSid);
        };
        let components = suffix.split('-').collect::<Vec<_>>();
        if components.len() != 5
            || components.iter().any(|component| {
                component.is_empty()
                    || component
                        .parse::<u32>()
                        .ok()
                        .is_none_or(|parsed| parsed.to_string() != *component)
            })
        {
            return Err(InvalidTrustedServiceSid);
        }
        Ok(Self(value))
    }

    #[cfg(any(windows, test))]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// A malformed trusted Windows service SID.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("trusted Windows service identity is invalid")]
pub struct InvalidTrustedServiceSid;

/// Fixed policy for one handle-bound Windows file read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadOptions {
    maximum_bytes: usize,
    allow_empty: bool,
    access: ReadAccess,
    trusted_service_sids: Vec<TrustedServiceSid>,
}

impl ReadOptions {
    /// Creates a read policy. A zero byte limit is rejected by the reader.
    #[must_use]
    pub const fn new(maximum_bytes: usize, allow_empty: bool, access: ReadAccess) -> Self {
        Self {
            maximum_bytes,
            allow_empty,
            access,
            trusted_service_sids: Vec::new(),
        }
    }

    /// Adds an explicitly approved virtual-service owner or reader.
    #[must_use]
    pub fn with_trusted_service_sid(mut self, sid: TrustedServiceSid) -> Self {
        if !self.trusted_service_sids.contains(&sid) {
            self.trusted_service_sids.push(sid);
        }
        self
    }

    #[cfg(windows)]
    pub(crate) const fn maximum_bytes(&self) -> usize {
        self.maximum_bytes
    }

    #[cfg(windows)]
    pub(crate) const fn allow_empty(&self) -> bool {
        self.allow_empty
    }

    #[cfg(windows)]
    pub(crate) const fn access(&self) -> ReadAccess {
        self.access
    }

    #[cfg(windows)]
    pub(crate) fn trusted_service_sids(&self) -> &[TrustedServiceSid] {
        &self.trusted_service_sids
    }
}

/// Sanitized failure from the Windows file-custody boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AttestedFileError {
    /// The caller supplied a zero byte ceiling.
    #[error("secure file byte limit is invalid")]
    InvalidLimit,
    /// The path is not one canonical local drive-qualified Windows path.
    #[error("secure file path is invalid")]
    InvalidPath,
    /// An ancestor, volume, reparse, link, or file-identity check failed.
    #[error("secure file path custody check failed")]
    PathSecurity,
    /// Ownership or the protected DACL failed the exact access policy.
    #[error("secure file access-control check failed")]
    AccessSecurity,
    /// The file was empty when forbidden or exceeded its fixed byte ceiling.
    #[error("secure file size is invalid")]
    InvalidSize,
    /// The same locked handle did not yield one stable file and byte sequence.
    #[error("secure file changed while being read")]
    Unstable,
}
