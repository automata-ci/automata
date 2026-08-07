use std::{
    ffi::OsStr,
    path::{Component, Path, PathBuf},
};

use crate::SpoolRootError;

/// Validated root policy for protected runner content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpoolRoot {
    path: PathBuf,
}

impl SpoolRoot {
    /// Validates an explicitly configured content-spool root.
    ///
    /// # Errors
    ///
    /// Rejects relative paths, the filesystem root, traversal/prefix
    /// components, and the system temporary hierarchy.
    pub fn explicit(path: impl Into<PathBuf>) -> Result<Self, SpoolRootError> {
        let path = path.into();
        validate(&path)?;
        Ok(Self { path })
    }

    /// Derives the spool root from an explicitly supplied XDG state home.
    ///
    /// # Errors
    ///
    /// Rejects an empty or otherwise unsafe XDG state-home path.
    pub fn from_xdg_state_home(xdg_state_home: impl Into<PathBuf>) -> Result<Self, SpoolRootError> {
        let home = xdg_state_home.into();
        if home.as_os_str().is_empty() {
            return Err(SpoolRootError::MissingXdgStateHome);
        }
        Self::explicit(home.join("automata").join("runner").join("content"))
    }

    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.path
    }
}

fn validate(path: &Path) -> Result<(), SpoolRootError> {
    if !path.is_absolute() {
        return Err(SpoolRootError::Relative);
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
                return Err(SpoolRootError::Traversal);
            }
        }
    }
    if normal_count == 0 {
        return Err(SpoolRootError::FilesystemRoot);
    }
    if temporary_component {
        return Err(SpoolRootError::TemporaryHierarchy);
    }
    Ok(())
}
