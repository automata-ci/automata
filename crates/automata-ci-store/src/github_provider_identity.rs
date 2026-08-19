//! GitHub-native numeric identities retained by provider configuration.

use std::num::NonZeroU64;

use thiserror::Error;

macro_rules! github_numeric_id {
    ($(#[$meta:meta])* $name:ident, $field:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(NonZeroU64);

        impl $name {
            /// Constructs a positive GitHub numeric identity representable by
            /// the signed 64-bit durable-storage boundary.
            ///
            /// # Errors
            ///
            /// Rejects zero and values larger than `i64::MAX`.
            pub fn new(value: u64) -> Result<Self, GithubProviderIdentityError> {
                let value = NonZeroU64::new(value)
                    .ok_or(GithubProviderIdentityError::InvalidNumericId($field))?;
                if i64::try_from(value.get()).is_err() {
                    return Err(GithubProviderIdentityError::InvalidNumericId($field));
                }
                Ok(Self(value))
            }

            /// Returns the positive numeric identity.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0.get()
            }
        }
    };
}

github_numeric_id!(/// Positive GitHub App installation identity.
    GithubInstallationId, "GitHub installation ID");
github_numeric_id!(/// Positive GitHub repository identity.
    GithubRepositoryId, "GitHub repository ID");
github_numeric_id!(/// Positive GitHub repository-owner identity.
    GithubRepositoryOwnerId, "GitHub repository owner ID");

/// Closed authenticated visibility supported by the GitHub.com provider.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GithubRepositoryVisibility {
    /// Repository contents are available without authentication.
    Public,
    /// Repository contents require explicit authorization.
    Private,
}

impl GithubRepositoryVisibility {
    pub(crate) const fn as_durable_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
        }
    }
}

/// Invalid GitHub-native provider identity.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubProviderIdentityError {
    /// A numeric GitHub identity is zero or exceeds the durable boundary.
    #[error("invalid {0}")]
    InvalidNumericId(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_id_domains_share_the_durable_boundary() {
        assert_eq!(GithubInstallationId::new(1).expect("installation").get(), 1);
        assert_eq!(GithubRepositoryId::new(2).expect("repository").get(), 2);
        assert_eq!(
            GithubRepositoryOwnerId::new(3)
                .expect("repository owner")
                .get(),
            3
        );

        assert_eq!(
            GithubInstallationId::new(0),
            Err(GithubProviderIdentityError::InvalidNumericId(
                "GitHub installation ID"
            ))
        );
        assert!(GithubRepositoryId::new(i64::MAX as u64 + 1).is_err());
        assert!(GithubRepositoryOwnerId::new(u64::MAX).is_err());
    }
}
