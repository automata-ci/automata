use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::authorization::RoleName;

const MAX_GITHUB_DISPLAY_NAME_LENGTH: usize = 255;

macro_rules! github_id {
    ($name:ident, $label:literal) => {
        #[doc = concat!("A validated positive ", $label, ".")]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(i64);

        impl $name {
            /// Creates a stable positive GitHub numeric identifier.
            ///
            /// # Errors
            ///
            /// Returns an error when the identifier is not positive.
            pub const fn new(value: i64) -> Result<Self, GithubRoleMappingError> {
                if value <= 0 {
                    return Err(GithubRoleMappingError::InvalidGithubId { label: $label });
                }
                Ok(Self(value))
            }

            /// Returns the stable numeric identifier.
            pub const fn get(self) -> i64 {
                self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = i64::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }

        impl TryFrom<i64> for $name {
            type Error = GithubRoleMappingError;

            fn try_from(value: i64) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for i64 {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

github_id!(GithubOrganizationId, "GitHub organization ID");
github_id!(GithubTeamId, "GitHub team ID");

macro_rules! github_display_name {
    ($name:ident, $label:literal) => {
        #[doc = concat!("Normalized display metadata for a ", $label, ".")]
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Creates normalized, non-authoritative GitHub display metadata.
            ///
            /// # Errors
            ///
            /// Returns an error when the value is empty, oversized, or contains an
            /// unsupported character.
            pub fn new(value: impl Into<String>) -> Result<Self, GithubRoleMappingError> {
                let normalized = value.into().to_ascii_lowercase();
                if normalized.is_empty()
                    || normalized.len() > MAX_GITHUB_DISPLAY_NAME_LENGTH
                    || !normalized.bytes().all(|character| {
                        character.is_ascii_alphanumeric() || matches!(character, b'-' | b'_')
                    })
                {
                    return Err(GithubRoleMappingError::InvalidGithubName { label: $label });
                }
                Ok(Self(normalized))
            }

            /// Returns the normalized display value.
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

github_display_name!(GithubOrganizationLogin, "GitHub organization login");
github_display_name!(GithubTeamSlug, "GitHub team slug");

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
/// GitHub's role for a user within an organization.
pub enum GithubOrganizationMembershipRole {
    /// A regular organization member.
    Member,
    /// An organization administrator.
    Admin,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
/// One observed GitHub organization membership keyed by stable identity.
pub struct GithubOrganizationMembership {
    id: GithubOrganizationId,
    login: GithubOrganizationLogin,
    role: GithubOrganizationMembershipRole,
}

impl GithubOrganizationMembership {
    /// Creates an observed organization membership.
    pub const fn new(
        id: GithubOrganizationId,
        login: GithubOrganizationLogin,
        role: GithubOrganizationMembershipRole,
    ) -> Self {
        Self { id, login, role }
    }

    /// Returns the stable organization identifier.
    pub const fn id(&self) -> GithubOrganizationId {
        self.id
    }

    /// Returns the organization's current display login.
    pub const fn login(&self) -> &GithubOrganizationLogin {
        &self.login
    }

    /// Returns the user's GitHub role in the organization.
    pub const fn role(&self) -> GithubOrganizationMembershipRole {
        self.role
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
/// One observed GitHub team keyed by stable team and organization identities.
pub struct GithubTeam {
    id: GithubTeamId,
    organization_id: GithubOrganizationId,
    organization_login: GithubOrganizationLogin,
    slug: GithubTeamSlug,
}

impl GithubTeam {
    /// Creates an observed GitHub team.
    pub const fn new(
        id: GithubTeamId,
        organization_id: GithubOrganizationId,
        organization_login: GithubOrganizationLogin,
        slug: GithubTeamSlug,
    ) -> Self {
        Self {
            id,
            organization_id,
            organization_login,
            slug,
        }
    }

    /// Returns the stable team identifier.
    pub const fn id(&self) -> GithubTeamId {
        self.id
    }

    /// Returns the stable identifier of the containing organization.
    pub const fn organization_id(&self) -> GithubOrganizationId {
        self.organization_id
    }

    /// Returns the containing organization's current display login.
    pub const fn organization_login(&self) -> &GithubOrganizationLogin {
        &self.organization_login
    }

    /// Returns the team's current display slug.
    pub const fn slug(&self) -> &GithubTeamSlug {
        &self.slug
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
/// A self-consistent snapshot of GitHub organization and team memberships.
pub struct GithubMembershipSnapshot {
    organizations: BTreeMap<GithubOrganizationId, GithubOrganizationMembership>,
    teams: BTreeMap<GithubTeamId, GithubTeam>,
}

impl GithubMembershipSnapshot {
    /// Creates a self-consistent membership snapshot keyed only by stable IDs.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate identities, conflicting mutable metadata,
    /// or a team whose containing organization is absent or inconsistent.
    pub fn new(
        organizations: impl IntoIterator<Item = GithubOrganizationMembership>,
        teams: impl IntoIterator<Item = GithubTeam>,
    ) -> Result<Self, GithubRoleMappingError> {
        let mut organizations_by_id = BTreeMap::new();
        let mut organization_ids_by_login = BTreeMap::new();
        for membership in organizations {
            if organizations_by_id.contains_key(&membership.id) {
                return Err(GithubRoleMappingError::DuplicateOrganizationId);
            }
            if organization_ids_by_login
                .insert(membership.login.clone(), membership.id)
                .is_some_and(|existing_id| existing_id != membership.id)
            {
                return Err(GithubRoleMappingError::ConflictingOrganizationLogin);
            }
            organizations_by_id.insert(membership.id, membership);
        }

        let mut teams_by_id = BTreeMap::new();
        let mut team_ids_by_parent_and_slug = BTreeMap::new();
        for team in teams {
            let organization = organizations_by_id
                .get(&team.organization_id)
                .ok_or(GithubRoleMappingError::TeamWithoutOrganization)?;
            if organization.login != team.organization_login {
                return Err(GithubRoleMappingError::TeamOrganizationMismatch);
            }
            if teams_by_id.contains_key(&team.id) {
                return Err(GithubRoleMappingError::DuplicateTeamId);
            }
            let display_key = (team.organization_id, team.slug.clone());
            if team_ids_by_parent_and_slug
                .insert(display_key, team.id)
                .is_some_and(|existing_id| existing_id != team.id)
            {
                return Err(GithubRoleMappingError::ConflictingTeamSlug);
            }
            teams_by_id.insert(team.id, team);
        }

        Ok(Self {
            organizations: organizations_by_id,
            teams: teams_by_id,
        })
    }

    /// Iterates over organization memberships in stable identifier order.
    pub fn organizations(&self) -> impl ExactSizeIterator<Item = &GithubOrganizationMembership> {
        self.organizations.values()
    }

    /// Iterates over teams in stable identifier order.
    pub fn teams(&self) -> impl ExactSizeIterator<Item = &GithubTeam> {
        self.teams.values()
    }

    /// Looks up an organization membership by its stable identifier.
    pub fn organization(&self, id: GithubOrganizationId) -> Option<&GithubOrganizationMembership> {
        self.organizations.get(&id)
    }

    /// Looks up a team by its stable identifier.
    pub fn team(&self, id: GithubTeamId) -> Option<&GithubTeam> {
        self.teams.get(&id)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
/// A stable GitHub membership source that may grant configured Automata roles.
pub enum GithubRoleSource {
    /// Membership in one GitHub organization.
    Organization {
        /// The stable organization identifier.
        organization_id: GithubOrganizationId,
    },
    /// Membership in one team within a GitHub organization.
    Team {
        /// The stable identifier of the containing organization.
        organization_id: GithubOrganizationId,
        /// The stable team identifier.
        team_id: GithubTeamId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// An explicit mapping from a stable GitHub membership source to Automata roles.
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

    /// Returns the stable GitHub membership source.
    pub const fn source(&self) -> &GithubRoleSource {
        &self.source
    }

    /// Returns the explicitly granted Automata roles.
    pub const fn roles(&self) -> &BTreeSet<RoleName> {
        &self.roles
    }

    /// Splits the mapping into its source and granted roles.
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

    /// Resolves the union of explicitly configured roles for a membership snapshot.
    pub fn roles_for(&self, memberships: &GithubMembershipSnapshot) -> BTreeSet<RoleName> {
        let organization_roles = memberships
            .organizations
            .keys()
            .filter_map(|organization_id| {
                self.mappings.get(&GithubRoleSource::Organization {
                    organization_id: *organization_id,
                })
            });
        let team_roles = memberships.teams.values().filter_map(|team| {
            self.mappings.get(&GithubRoleSource::Team {
                organization_id: team.organization_id,
                team_id: team.id,
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
/// A validation failure in GitHub membership metadata or role mapping.
pub enum GithubRoleMappingError {
    /// A GitHub numeric identity is not positive.
    #[error("{label} must be a positive integer")]
    InvalidGithubId {
        /// The kind of identifier that failed validation.
        label: &'static str,
    },
    /// Mutable GitHub display metadata is empty, oversized, or malformed.
    #[error("{label} is invalid")]
    InvalidGithubName {
        /// The kind of display name that failed validation.
        label: &'static str,
    },
    /// A role mapping grants no Automata roles.
    #[error("a GitHub role mapping must grant at least one explicit role")]
    EmptyRoles,
    /// A snapshot contains the same organization ID more than once.
    #[error("a membership snapshot contains a duplicate organization ID")]
    DuplicateOrganizationId,
    /// One organization login is associated with conflicting stable IDs.
    #[error("a membership snapshot maps one organization login to conflicting IDs")]
    ConflictingOrganizationLogin,
    /// A snapshot contains the same team ID more than once.
    #[error("a membership snapshot contains a duplicate team ID")]
    DuplicateTeamId,
    /// One organization-scoped team slug is associated with conflicting stable IDs.
    #[error("a membership snapshot maps one team slug to conflicting IDs")]
    ConflictingTeamSlug,
    /// A team is present without its containing organization membership.
    #[error("a team membership must include its organization membership")]
    TeamWithoutOrganization,
    /// A team's organization login disagrees with its organization membership.
    #[error("a team membership's organization metadata is inconsistent")]
    TeamOrganizationMismatch,
}
