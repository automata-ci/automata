use thiserror::Error;

/// A policy rejected unsafe or internally inconsistent limits.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PolicyError {
    /// A resource limit was configured as zero.
    #[error("render policy limit `{name}` must be greater than zero")]
    ZeroLimit {
        /// Stable name of the rejected policy limit.
        name: &'static str,
    },
    /// The input limit exceeds the shared renderer request contract.
    #[error("maximum input size cannot exceed the renderer contract of {max_bytes} UTF-8 bytes")]
    InputExceedsContract {
        /// Largest input size permitted by the shared contract.
        max_bytes: usize,
    },
    /// The output limit exceeds the shared rendered-HTML contract.
    #[error("maximum output size cannot exceed the renderer contract of {max_bytes} UTF-8 bytes")]
    OutputExceedsContract {
        /// Largest output size permitted by the shared contract.
        max_bytes: usize,
    },
    /// The output limit exceeds the aggregate guest-memory limit.
    #[error("maximum output size cannot exceed the aggregate WebAssembly memory limit")]
    OutputExceedsMemory,
}

/// Failure while compiling or linking the trusted embedded component.
#[derive(Debug, Error)]
pub enum RendererInitError {
    /// The supplied renderer policy is invalid.
    #[error(transparent)]
    InvalidPolicy(#[from] PolicyError),
    /// Wasmtime could not create the execution engine or deadline ticker.
    #[error("failed to initialize the WebAssembly engine: {message}")]
    Engine {
        /// Description returned by the failing engine operation.
        message: String,
    },
    /// The embedded renderer bytes are not a valid component.
    #[error("the embedded renderer component is invalid: {message}")]
    Component {
        /// Description returned by Wasmtime's component compiler.
        message: String,
    },
    /// The restricted WASI imports could not be linked.
    #[error("failed to link the renderer's restricted WASI imports: {message}")]
    Linker {
        /// Description returned by Wasmtime's component linker.
        message: String,
    },
}

/// The bounded resource that terminated a render.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceLimit {
    /// The per-render WebAssembly instruction fuel was consumed.
    Fuel,
    /// The per-render elapsed-time deadline was reached.
    Deadline,
    /// Guest linear-memory allocation exceeded its configured bound.
    Memory,
    /// Guest table allocation exceeded its configured bound.
    Table,
}

/// A fail-closed rendering failure suitable for mapping at the HTTP boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RenderError {
    /// The serialized request exceeds the configured input-size limit.
    #[error("render request is {actual_bytes} bytes; maximum is {max_bytes} bytes")]
    InputTooLarge {
        /// Actual UTF-8 byte length of the serialized request.
        actual_bytes: usize,
        /// Configured maximum request size in UTF-8 bytes.
        max_bytes: usize,
    },
    /// The request is not syntactically valid JSON.
    #[error("render request is not valid JSON at line {line}, column {column}")]
    MalformedRequest {
        /// One-based line reported by the JSON parser.
        line: usize,
        /// One-based column reported by the JSON parser.
        column: usize,
    },
    /// All configured renderer concurrency permits are in use.
    #[error("renderer is at its configured concurrency limit")]
    AtCapacity,
    /// The isolated guest exhausted a configured resource limit.
    #[error("renderer exhausted its {0:?} limit")]
    ResourceExhausted(ResourceLimit),
    /// The guest trapped, rejected the request, or otherwise failed execution.
    #[error("renderer component rejected or failed to render the request")]
    GuestExecution,
    /// The rendered HTML exceeds the configured output-size limit.
    #[error("rendered output exceeds the maximum of {max_bytes} bytes")]
    OutputTooLarge {
        /// Configured maximum rendered HTML size in UTF-8 bytes.
        max_bytes: usize,
    },
}
