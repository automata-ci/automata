use std::{fmt, str::FromStr};

/// A repository in `OWNER/NAME` form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryRef {
    owner: String,
    name: String,
}

impl RepositoryRef {
    /// Returns the provider repository owner's exact parsed spelling.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Returns the provider repository name's exact parsed spelling.
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

/// Operational repository scope of an encrypted Actions-compatible secret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecretScope {
    /// A secret available to one exact repository.
    Repository(RepositoryRef),
}

impl fmt::Display for SecretScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Repository(repository) => write!(formatter, "repo:{repository}"),
        }
    }
}

impl FromStr for SecretScope {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Some(repository) = value.strip_prefix("repo:") {
            return repository.parse().map(Self::Repository);
        }
        Err("scope must be repo:OWNER/REPOSITORY".into())
    }
}

fn is_safe_segment(value: &str, maximum_length: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_length
        && value
            .chars()
            .all(|character| !character.is_control() && !character.is_whitespace())
}
