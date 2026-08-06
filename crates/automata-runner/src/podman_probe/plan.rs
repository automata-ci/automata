use std::{
    ffi::OsString,
    path::{Component, Path, PathBuf},
};

const SCRATCH_OVERRIDE: &str = "AUTOMATA_RUNNER_SCRATCH_DIR";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveProbePlan {
    executable: PathBuf,
    identifier: String,
    network_name: String,
    container_name: String,
    image_name: String,
    scratch_root: PathBuf,
    context_path: PathBuf,
}

impl ActiveProbePlan {
    /// Builds a collision-resistant, ownership-scoped active-probe plan using
    /// an explicit runner scratch directory or an XDG runtime/state directory.
    ///
    /// # Errors
    ///
    /// Returns an error if no safe absolute scratch root is available or if
    /// `identifier` is not exactly 32 lowercase hexadecimal characters.
    pub fn new(executable: PathBuf, identifier: impl Into<String>) -> Result<Self, String> {
        Self::new_in(executable, identifier, resolve_scratch_root()?)
    }

    /// Builds a plan under a caller-selected scratch root.
    ///
    /// # Errors
    ///
    /// Returns an error unless the normalized root is absolute, is outside
    /// `/tmp`, and the identifier is exactly 32 lowercase hexadecimal
    /// characters.
    pub fn new_in(
        executable: PathBuf,
        identifier: impl Into<String>,
        scratch_root: impl AsRef<Path>,
    ) -> Result<Self, String> {
        let identifier = identifier.into();
        if identifier.len() != 32
            || !identifier
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(
                "active probe identifier must be 32 lowercase hexadecimal characters".to_owned(),
            );
        }
        let scratch_root = normalize_and_validate_scratch_root(scratch_root.as_ref())?;

        let context_path = scratch_root.join(format!("automata-podman-probe-{identifier}"));
        Ok(Self {
            executable,
            network_name: format!("automata-probe-net-{identifier}"),
            container_name: format!("automata-probe-ctr-{identifier}"),
            image_name: format!("localhost/automata-probe:{identifier}"),
            scratch_root,
            context_path,
            identifier,
        })
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }

    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    pub fn scratch_root(&self) -> &Path {
        &self.scratch_root
    }

    pub(super) fn network_name(&self) -> &str {
        &self.network_name
    }

    pub(super) fn container_name(&self) -> &str {
        &self.container_name
    }

    pub(super) fn image_name(&self) -> &str {
        &self.image_name
    }

    pub(super) fn context_path(&self) -> &Path {
        &self.context_path
    }

    pub(super) fn context_path_in(&self, scratch_root: &Path) -> PathBuf {
        scratch_root.join(format!("automata-podman-probe-{}", self.identifier))
    }
}

fn resolve_scratch_root() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os(SCRATCH_OVERRIDE) {
        return checked_environment_root(SCRATCH_OVERRIDE, path);
    }
    if let Some(path) = std::env::var_os("XDG_RUNTIME_DIR") {
        return checked_environment_root("XDG_RUNTIME_DIR", path)
            .map(|path| path.join("automata-runner"));
    }
    if let Some(path) = std::env::var_os("XDG_STATE_HOME") {
        return checked_environment_root("XDG_STATE_HOME", path)
            .map(|path| path.join("automata-runner/scratch"));
    }
    if let Some(path) = std::env::var_os("HOME") {
        return checked_environment_root("HOME", path)
            .map(|path| path.join(".local/state/automata-runner/scratch"));
    }
    Err(format!(
        "no safe runner scratch root is available; set {SCRATCH_OVERRIDE} or an absolute XDG_RUNTIME_DIR/XDG_STATE_HOME"
    ))
}

fn checked_environment_root(variable: &str, value: OsString) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(format!("{variable} must be an absolute path"));
    }
    normalize_and_validate_scratch_root(&path)
}

fn normalize_and_validate_scratch_root(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("runner scratch root must be an absolute path".to_owned());
    }
    let normalized = normalize_absolute_path(path)?;
    validate_normalized_scratch_root(&normalized)?;
    Ok(normalized)
}

fn normalize_absolute_path(path: &Path) -> Result<PathBuf, String> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(
                        "runner scratch root must not traverse above a filesystem root".to_owned(),
                    );
                }
            }
            Component::Normal(segment) => normalized.push(segment),
        }
    }
    Ok(normalized)
}

pub(super) fn validate_resolved_scratch_root(path: &Path) -> Result<(), String> {
    let normalized = normalize_and_validate_scratch_root(path)?;
    if normalized != path {
        return Err("resolved runner scratch root was not normalized".to_owned());
    }
    Ok(())
}

fn validate_normalized_scratch_root(path: &Path) -> Result<(), String> {
    if path.parent().is_none() {
        return Err("runner scratch root must not be a filesystem root".to_owned());
    }
    #[cfg(unix)]
    if path.starts_with("/tmp") {
        return Err("runner scratch root must not use /tmp".to_owned());
    }
    Ok(())
}
