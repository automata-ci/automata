use std::{
    ffi::OsStr,
    path::{Component, Path, PathBuf},
};

use automata_ci_action::{ActionReferenceIndexError, ActionReferenceIndexErrorKind};

/// Validated non-temporary root for the durable action-reference index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionReferenceIndexRoot(PathBuf);

impl ActionReferenceIndexRoot {
    /// Validates one explicitly configured state root.
    ///
    /// # Errors
    ///
    /// Rejects relative paths, filesystem root, traversal components, and any
    /// system temporary hierarchy.
    pub fn explicit(path: impl Into<PathBuf>) -> Result<Self, ActionReferenceIndexError> {
        let path = path.into();
        validate(&path)?;
        Ok(Self(path))
    }

    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

fn validate(path: &Path) -> Result<(), ActionReferenceIndexError> {
    if !path.is_absolute() {
        return Err(unsupported());
    }
    let mut normal_components = 0_usize;
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) => {}
            Component::Normal(value) => {
                normal_components += 1;
                if value == OsStr::new("tmp") {
                    return Err(unsupported());
                }
            }
            Component::CurDir | Component::ParentDir => return Err(unsupported()),
        }
    }
    if normal_components == 0 {
        return Err(unsupported());
    }
    Ok(())
}

const fn unsupported() -> ActionReferenceIndexError {
    ActionReferenceIndexError::new(ActionReferenceIndexErrorKind::Unsupported)
}
