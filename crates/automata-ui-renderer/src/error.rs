use thiserror::Error;

/// A policy rejected unsafe or internally inconsistent limits.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PolicyError {
    #[error("render policy limit `{name}` must be greater than zero")]
    ZeroLimit { name: &'static str },
    #[error("maximum input size cannot exceed the renderer contract of {max_bytes} UTF-8 bytes")]
    InputExceedsContract { max_bytes: usize },
    #[error("maximum output size cannot exceed the renderer contract of {max_bytes} UTF-8 bytes")]
    OutputExceedsContract { max_bytes: usize },
    #[error("maximum output size cannot exceed the aggregate WebAssembly memory limit")]
    OutputExceedsMemory,
}

/// Failure while compiling or linking the trusted embedded component.
#[derive(Debug, Error)]
pub enum RendererInitError {
    #[error(transparent)]
    InvalidPolicy(#[from] PolicyError),
    #[error("failed to initialize the WebAssembly engine: {message}")]
    Engine { message: String },
    #[error("the embedded renderer component is invalid: {message}")]
    Component { message: String },
    #[error("failed to link the renderer's restricted WASI imports: {message}")]
    Linker { message: String },
}

/// The bounded resource that terminated a render.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceLimit {
    Fuel,
    Deadline,
    Memory,
    Table,
}

/// A fail-closed rendering failure suitable for mapping at the HTTP boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RenderError {
    #[error("render request is {actual_bytes} bytes; maximum is {max_bytes} bytes")]
    InputTooLarge {
        actual_bytes: usize,
        max_bytes: usize,
    },
    #[error("render request is not valid JSON at line {line}, column {column}")]
    MalformedRequest { line: usize, column: usize },
    #[error("renderer is at its configured concurrency limit")]
    AtCapacity,
    #[error("renderer exhausted its {0:?} limit")]
    ResourceExhausted(ResourceLimit),
    #[error("renderer component rejected or failed to render the request")]
    GuestExecution,
    #[error("rendered output exceeds the maximum of {max_bytes} bytes")]
    OutputTooLarge { max_bytes: usize },
}
