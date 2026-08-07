use std::fmt;

use automata_action_github::JavascriptRuntime;
use automata_core::{ExpressionProgram, Sha256Digest};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const MAX_PREPARED_ARCHIVE_BYTES: usize = automata_execution::MAX_COPY_BYTES;
const MAX_PREPARED_INPUTS: usize = 1_024;
const MAX_ACTION_PATH_BYTES: usize = 4_096;

/// One already-compiled action input default.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedValue {
    /// Exact literal metadata text.
    Literal(String),
    /// Runner-phase expression compiled with the pinned GitHub dialect.
    Expression(ExpressionProgram),
}

/// One metadata-declared action input and its optional default.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedInput {
    name: String,
    default: Option<PreparedValue>,
}

impl PreparedInput {
    /// Creates an action input declaration.
    ///
    /// # Errors
    ///
    /// Rejects empty, control-containing, or oversized input names.
    pub fn new(
        name: impl Into<String>,
        default: Option<PreparedValue>,
    ) -> Result<Self, PreparedActionError> {
        let name = name.into();
        if name.is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
            return Err(PreparedActionError::InvalidInput);
        }
        Ok(Self { name, default })
    }

    /// Returns the metadata input name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the compiled default, when declared.
    #[must_use]
    pub const fn default(&self) -> Option<&PreparedValue> {
        self.default.as_ref()
    }
}

/// Validated metadata-driven JavaScript execution plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedJavascriptAction {
    runtime: JavascriptRuntime,
    main: String,
    pre: Option<String>,
    pre_condition: ExpressionProgram,
    post: Option<String>,
    post_condition: ExpressionProgram,
}

impl PreparedJavascriptAction {
    /// Creates a JavaScript action from already-decoded metadata.
    ///
    /// # Errors
    ///
    /// Rejects any path that is absolute, aliased, backslash-containing, or
    /// otherwise unsafe beneath the immutable action root.
    pub fn new(
        runtime: JavascriptRuntime,
        main: impl Into<String>,
        pre: Option<String>,
        pre_condition: ExpressionProgram,
        post: Option<String>,
        post_condition: ExpressionProgram,
    ) -> Result<Self, PreparedActionError> {
        let main = validate_relative_path(main.into())?;
        let pre = pre.map(validate_relative_path).transpose()?;
        let post = post.map(validate_relative_path).transpose()?;
        Ok(Self {
            runtime,
            main,
            pre,
            pre_condition,
            post,
            post_condition,
        })
    }

    /// Returns the metadata-selected Node runtime.
    #[must_use]
    pub const fn runtime(&self) -> JavascriptRuntime {
        self.runtime
    }

    /// Returns the canonical action-relative main entry path.
    #[must_use]
    pub fn main(&self) -> &str {
        &self.main
    }

    /// Returns the canonical action-relative pre entry path.
    #[must_use]
    pub fn pre(&self) -> Option<&str> {
        self.pre.as_deref()
    }

    /// Returns the compiled pre condition.
    #[must_use]
    pub const fn pre_condition(&self) -> &ExpressionProgram {
        &self.pre_condition
    }

    /// Returns the canonical action-relative post entry path.
    #[must_use]
    pub fn post(&self) -> Option<&str> {
        self.post.as_deref()
    }

    /// Returns the compiled post condition.
    #[must_use]
    pub const fn post_condition(&self) -> &ExpressionProgram {
        &self.post_condition
    }
}

/// Immutable action archive and its validated executable contract.
#[derive(Clone, Eq, PartialEq)]
pub struct PreparedAction {
    archive_digest: Sha256Digest,
    archive: Bytes,
    subpath: String,
    inputs: Vec<PreparedInput>,
    javascript: PreparedJavascriptAction,
}

impl PreparedAction {
    /// Creates an immutable action plan returned by an action-preparation port.
    ///
    /// # Errors
    ///
    /// Rejects empty or oversized archives, unsafe subpaths, duplicate input
    /// names ignoring case, or an excessive input count.
    pub fn new(
        archive_digest: Sha256Digest,
        archive: Bytes,
        subpath: impl Into<String>,
        inputs: Vec<PreparedInput>,
        javascript: PreparedJavascriptAction,
    ) -> Result<Self, PreparedActionError> {
        if archive.is_empty() || archive.len() > MAX_PREPARED_ARCHIVE_BYTES {
            return Err(PreparedActionError::ArchiveSize);
        }
        let computed = Sha256Digest::from_bytes(Sha256::digest(&archive).into());
        if computed != archive_digest {
            return Err(PreparedActionError::DigestMismatch);
        }
        let subpath = subpath.into();
        if !subpath.is_empty() {
            validate_relative_path(subpath.clone())?;
        }
        if inputs.len() > MAX_PREPARED_INPUTS {
            return Err(PreparedActionError::TooManyInputs);
        }
        let mut names = std::collections::BTreeSet::new();
        if inputs
            .iter()
            .any(|input| !names.insert(input.name().to_ascii_lowercase()))
        {
            return Err(PreparedActionError::DuplicateInput);
        }
        Ok(Self {
            archive_digest,
            archive,
            subpath,
            inputs,
            javascript,
        })
    }

    /// Returns the verified archive digest.
    #[must_use]
    pub const fn archive_digest(&self) -> Sha256Digest {
        self.archive_digest
    }

    /// Returns verified compressed archive bytes. Callers must retain the copy bound.
    #[must_use]
    pub const fn archive(&self) -> &Bytes {
        &self.archive
    }

    /// Returns the action directory beneath the single repository archive root.
    #[must_use]
    pub fn subpath(&self) -> &str {
        &self.subpath
    }

    /// Returns metadata-declared inputs in source order.
    #[must_use]
    pub fn inputs(&self) -> &[PreparedInput] {
        &self.inputs
    }

    /// Returns the supported JavaScript execution plan.
    #[must_use]
    pub const fn javascript(&self) -> &PreparedJavascriptAction {
        &self.javascript
    }
}

impl fmt::Debug for PreparedAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedAction")
            .field("archive_digest", &self.archive_digest)
            .field("archive_bytes", &self.archive.len())
            .field("subpath", &self.subpath)
            .field("inputs", &self.inputs)
            .field("javascript", &self.javascript)
            .finish()
    }
}

/// Invalid prepared action returned across a trust boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PreparedActionError {
    /// Archive is empty or exceeds one bounded endpoint copy.
    #[error("prepared action archive has an invalid size")]
    ArchiveSize,
    /// Declared archive identity did not match the exact returned bytes.
    #[error("prepared action archive digest does not match its content")]
    DigestMismatch,
    /// An action-relative path escapes or exceeds its root.
    #[error("prepared action contains an unsafe path")]
    UnsafePath,
    /// An action input name is invalid.
    #[error("prepared action contains an invalid input")]
    InvalidInput,
    /// Input count exceeds the configured hard ceiling.
    #[error("prepared action contains too many inputs")]
    TooManyInputs,
    /// Input names collide under GitHub's case-insensitive lookup.
    #[error("prepared action contains duplicate inputs")]
    DuplicateInput,
}

fn validate_relative_path(value: String) -> Result<String, PreparedActionError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_ACTION_PATH_BYTES
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
        && value
            .split('/')
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."));
    valid
        .then_some(value)
        .ok_or(PreparedActionError::UnsafePath)
}
