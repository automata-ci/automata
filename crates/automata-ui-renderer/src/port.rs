use crate::RenderError;

/// The control-plane boundary for producing a complete HTML document.
///
/// Implementations must be safe to call concurrently. The method is blocking;
/// asynchronous HTTP adapters should invoke it on their blocking executor.
pub trait Renderer: Send + Sync {
    /// Render one serialized UI request into a complete HTML document.
    ///
    /// # Errors
    ///
    /// Returns [`RenderError`] when input is invalid, admission or resource
    /// limits are reached, or the isolated component rejects the model.
    fn render(&self, request_json: &str) -> Result<RenderedPage, RenderError>;
}

/// A complete server-rendered HTML document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderedPage(String);

impl RenderedPage {
    /// Wrap a complete HTML document produced by a renderer implementation.
    ///
    /// This constructor deliberately does not parse or sanitize HTML. The
    /// implementing renderer is responsible for returning a complete document
    /// and for safely escaping all untrusted values before construction. HTTP
    /// adapters may treat the wrapped value as `text/html; charset=utf-8`.
    pub fn from_complete_html(html: String) -> Self {
        Self(html)
    }

    /// Borrow the rendered document.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the wrapper and return the rendered document.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<str> for RenderedPage {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
