use std::{
    ffi::OsStr,
    path::{Component, Path, PathBuf},
};

use crate::StateRootError;

/// Validated state-root policy for a runner journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateRoot {
    path: PathBuf,
}

impl StateRoot {
    /// Validates an explicitly configured state root.
    ///
    /// # Errors
    ///
    /// Rejects relative paths, the filesystem root, traversal/prefix
    /// components, and the system temporary hierarchy.
    pub fn explicit(path: impl Into<PathBuf>) -> Result<Self, StateRootError> {
        let path = path.into();
        validate(&path)?;
        Ok(Self { path })
    }

    /// Derives the application state root from an explicitly supplied XDG
    /// state-home directory. Environment lookup remains a binary/configuration
    /// concern rather than hidden library behavior.
    ///
    /// # Errors
    ///
    /// Rejects an empty or otherwise unsafe XDG state-home path.
    pub fn from_xdg_state_home(xdg_state_home: impl Into<PathBuf>) -> Result<Self, StateRootError> {
        let home = xdg_state_home.into();
        if home.as_os_str().is_empty() {
            return Err(StateRootError::MissingXdgStateHome);
        }
        Self::explicit(home.join("automata").join("runner"))
    }

    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.path
    }
}

fn validate(path: &Path) -> Result<(), StateRootError> {
    if !path.is_absolute() {
        return Err(StateRootError::Relative);
    }
    let mut normal_count = 0_usize;
    let mut temporary_component = false;
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) => {}
            Component::Normal(value) => {
                normal_count += 1;
                temporary_component |= value == OsStr::new("tmp");
            }
            Component::CurDir | Component::ParentDir => {
                return Err(StateRootError::Traversal);
            }
        }
    }
    if normal_count == 0 {
        return Err(StateRootError::FilesystemRoot);
    }
    if temporary_component {
        return Err(StateRootError::TemporaryHierarchy);
    }
    Ok(())
}
