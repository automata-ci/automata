use std::{collections::BTreeMap, fmt, sync::Arc};

use crate::{GithubExpressionEvaluationError, GithubValue};

/// Current aggregate status visible to status-check functions.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum GithubStatus {
    /// No prior non-continuable failure or cancellation occurred.
    #[default]
    Success,
    /// A prior dependency or step failed.
    Failure,
    /// The workflow/job was cancelled.
    Cancelled,
}

/// Optional result returned by an extension-function provider.
pub type ExtensionFunctionResult = Option<Result<GithubValue, GithubExpressionEvaluationError>>;

/// Pluggable boundary for runtime functions with external side effects, such
/// as runner-local `hashFiles`.
pub trait GithubExpressionFunctionProvider: fmt::Debug + Send + Sync {
    /// Invokes a canonical lower-case extension name, or returns `None` when
    /// this provider does not implement it.
    fn call(&self, name: &str, arguments: &[GithubValue]) -> ExtensionFunctionResult;
}

/// Provider that implements no extension functions.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoExtensionFunctions;

impl GithubExpressionFunctionProvider for NoExtensionFunctions {
    fn call(&self, _name: &str, _arguments: &[GithubValue]) -> ExtensionFunctionResult {
        None
    }
}

/// Read-only late context supplied to the evaluator.
pub trait GithubEvaluationContext: fmt::Debug + Send + Sync {
    /// Resolves a canonical lower-case top-level named value.
    fn named_value(&self, name: &str) -> Option<GithubValue>;
    /// Returns the current status-function state.
    fn status(&self) -> GithubStatus;
    /// Returns the extension-function provider.
    fn functions(&self) -> &dyn GithubExpressionFunctionProvider;
}

/// Bounded map-backed context suitable for runner execution.
#[derive(Clone)]
pub struct MapContext {
    named: Arc<BTreeMap<String, GithubValue>>,
    status: GithubStatus,
    functions: Arc<dyn GithubExpressionFunctionProvider>,
}

impl MapContext {
    /// Creates a context and canonicalizes top-level names to ASCII lower case.
    ///
    /// # Errors
    ///
    /// Returns [`MapContextError`] when a name is invalid or collides ignoring
    /// case.
    pub fn new(
        named: BTreeMap<String, GithubValue>,
        status: GithubStatus,
        functions: Arc<dyn GithubExpressionFunctionProvider>,
    ) -> Result<Self, MapContextError> {
        if named.len() > 128 {
            return Err(MapContextError);
        }
        let mut canonical = BTreeMap::new();
        for (name, value) in named {
            if name.is_empty()
                || name.len() > 64
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            {
                return Err(MapContextError);
            }
            if canonical.insert(name.to_ascii_lowercase(), value).is_some() {
                return Err(MapContextError);
            }
        }
        Ok(Self {
            named: Arc::new(canonical),
            status,
            functions,
        })
    }

    /// Creates a context without external functions.
    ///
    /// # Errors
    ///
    /// Returns [`MapContextError`] for invalid/colliding top-level names.
    pub fn without_extensions(
        named: BTreeMap<String, GithubValue>,
        status: GithubStatus,
    ) -> Result<Self, MapContextError> {
        Self::new(named, status, Arc::new(NoExtensionFunctions))
    }
}

impl GithubEvaluationContext for MapContext {
    fn named_value(&self, name: &str) -> Option<GithubValue> {
        self.named.get(&name.to_ascii_lowercase()).cloned()
    }

    fn status(&self) -> GithubStatus {
        self.status
    }

    fn functions(&self) -> &dyn GithubExpressionFunctionProvider {
        self.functions.as_ref()
    }
}

impl fmt::Debug for MapContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MapContext")
            .field("named_value_count", &self.named.len())
            .field("values", &"[REDACTED]")
            .field("status", &self.status)
            .field("functions", &self.functions)
            .finish()
    }
}

/// Invalid map-context construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MapContextError;

impl fmt::Display for MapContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid GitHub expression context")
    }
}

impl std::error::Error for MapContextError {}
