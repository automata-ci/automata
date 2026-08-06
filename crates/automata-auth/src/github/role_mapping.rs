use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::authorization::RoleName;

const MAX_GITHUB_NAME_LENGTH: usize = 255;

macro_rules! github_name {
    ($name:ident, $label:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Creates a normalized GitHub organization or team name.
            ///
            /// # Errors
            ///
            /// Returns an error when the name is empty, oversized, or contains an
            /// unsupported character.
            pub fn new(value: impl Into<String>) -> Result<Self, GithubRoleMappingError> {
                let normalized = value.into().to_ascii_lowercase();
                if normalized.is_empty()
                    || normalized.len() > MAX_GITHUB_NAME_LENGTH
                    || !normalized.bytes().all(|character| {
                        character.is_ascii_alphanumeric() || matches!(character, b'-' | b'_')
                    })
                {
                    return Err(GithubRoleMappingError::InvalidGithubName { label: $label });
                }
                Ok(Self(normalized))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = GithubRoleMappingError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

github_name!(GithubOrganizationName, "GitHub organization name");
github_name!(GithubTeamSlug, "GitHub team slug");

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct GithubTeam {
    pub organization: GithubOrganizationName,
    pub slug: GithubTeamSlug,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GithubMembershipSnapshot {
    organizations: BTreeSet<GithubOrganizationName>,
    teams: BTreeSet<GithubTeam>,
}

impl GithubMembershipSnapshot {
    /// Creates a self-consistent membership snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when a team is present without its containing organization.
    pub fn new(
        organizations: BTreeSet<GithubOrganizationName>,
        teams: BTreeSet<GithubTeam>,
    ) -> Result<Self, GithubRoleMappingError> {
        if teams
            .iter()
            .any(|team| !organizations.contains(&team.organization))
        {
            return Err(GithubRoleMappingError::TeamWithoutOrganization);
        }
        Ok(Self {
            organizations,
            teams,
        })
    }

    pub fn organizations(&self) -> &BTreeSet<GithubOrganizationName> {
        &self.organizations
    }

    pub fn teams(&self) -> &BTreeSet<GithubTeam> {
        &self.teams
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GithubRoleSource {
    Organization {
        organization: GithubOrganizationName,
    },
    Team {
        organization: GithubOrganizationName,
        team: GithubTeamSlug,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubRoleMapping {
    source: GithubRoleSource,
    roles: BTreeSet<RoleName>,
}

impl GithubRoleMapping {
    /// Creates one explicit membership-to-role mapping.
    ///
    /// # Errors
    ///
    /// Returns an error when no role is assigned.
    pub fn new(
        source: GithubRoleSource,
        roles: BTreeSet<RoleName>,
    ) -> Result<Self, GithubRoleMappingError> {
        if roles.is_empty() {
            return Err(GithubRoleMappingError::EmptyRoles);
        }
        Ok(Self { source, roles })
    }

    pub const fn source(&self) -> &GithubRoleSource {
        &self.source
    }

    pub const fn roles(&self) -> &BTreeSet<RoleName> {
        &self.roles
    }

    pub fn into_parts(self) -> (GithubRoleSource, BTreeSet<RoleName>) {
        (self.source, self.roles)
    }
}

/// Resolves only configured organization/team mappings. Membership in GitHub, org
/// ownership, and a role's spelling never grant an implicit Automata role.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GithubRoleMapper {
    mappings: BTreeMap<GithubRoleSource, BTreeSet<RoleName>>,
}

impl GithubRoleMapper {
    /// Indexes validated explicit role mappings.
    ///
    /// # Errors
    ///
    /// Returns an error when any supplied mapping has no role.
    pub fn new(
        mappings: impl IntoIterator<Item = GithubRoleMapping>,
    ) -> Result<Self, GithubRoleMappingError> {
        let mut indexed = BTreeMap::<GithubRoleSource, BTreeSet<RoleName>>::new();
        for mapping in mappings {
            if mapping.roles.is_empty() {
                return Err(GithubRoleMappingError::EmptyRoles);
            }
            indexed
                .entry(mapping.source)
                .or_default()
                .extend(mapping.roles);
        }
        Ok(Self { mappings: indexed })
    }

    pub fn roles_for(&self, memberships: &GithubMembershipSnapshot) -> BTreeSet<RoleName> {
        let organization_roles = memberships.organizations.iter().filter_map(|organization| {
            self.mappings.get(&GithubRoleSource::Organization {
                organization: organization.clone(),
            })
        });
        let team_roles = memberships.teams.iter().filter_map(|team| {
            self.mappings.get(&GithubRoleSource::Team {
                organization: team.organization.clone(),
                team: team.slug.clone(),
            })
        });
        organization_roles
            .chain(team_roles)
            .flatten()
            .cloned()
            .collect()
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GithubRoleMappingError {
    #[error("{label} is invalid")]
    InvalidGithubName { label: &'static str },
    #[error("a GitHub role mapping must grant at least one explicit role")]
    EmptyRoles,
    #[error("a team membership must include its organization membership")]
    TeamWithoutOrganization,
}
