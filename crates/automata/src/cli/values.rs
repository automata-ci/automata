use std::{fmt, str::FromStr};

/// A repository in `OWNER/NAME` form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryRef {
    owner: String,
    name: String,
}

impl RepositoryRef {
    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for RepositoryRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.owner, self.name)
    }
}

impl FromStr for RepositoryRef {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (owner, name) = value
            .split_once('/')
            .ok_or_else(|| "repository must use OWNER/NAME form".to_owned())?;
        if name.contains('/') || !is_safe_segment(owner, 100) || !is_safe_segment(name, 100) {
            return Err("repository must contain one non-empty, printable OWNER/NAME pair".into());
        }
        Ok(Self {
            owner: owner.to_owned(),
            name: name.to_owned(),
        })
    }
}

/// Scope of an encrypted Actions-compatible secret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecretScope {
    Repository(RepositoryRef),
    Organization(String),
    Environment {
        repository: RepositoryRef,
        environment: String,
    },
}

impl fmt::Display for SecretScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Repository(repository) => write!(formatter, "repo:{repository}"),
            Self::Organization(organization) => write!(formatter, "org:{organization}"),
            Self::Environment {
                repository,
                environment,
            } => write!(formatter, "env:{repository}/{environment}"),
        }
    }
}

impl FromStr for SecretScope {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Some(repository) = value.strip_prefix("repo:") {
            return repository.parse().map(Self::Repository);
        }
        if let Some(organization) = value.strip_prefix("org:") {
            if is_safe_segment(organization, 100) {
                return Ok(Self::Organization(organization.to_owned()));
            }
            return Err("organization secret scope must be org:NAME".into());
        }
        if let Some(environment) = value.strip_prefix("env:") {
            let mut parts = environment.splitn(3, '/');
            let owner = parts.next().unwrap_or_default();
            let repository_name = parts.next().unwrap_or_default();
            let environment_name = parts.next().unwrap_or_default();
            let repository = format!("{owner}/{repository_name}").parse()?;
            if is_safe_segment(environment_name, 255) {
                return Ok(Self::Environment {
                    repository,
                    environment: environment_name.to_owned(),
                });
            }
            return Err("environment secret scope must be env:OWNER/REPO/ENVIRONMENT".into());
        }
        Err("scope must be repo:OWNER/REPO, org:NAME, or env:OWNER/REPO/ENVIRONMENT".into())
    }
}

fn is_safe_segment(value: &str, maximum_length: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_length
        && value
            .chars()
            .all(|character| !character.is_control() && !character.is_whitespace())
}
