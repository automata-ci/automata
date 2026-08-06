use automata_ui_renderer::{RenderError, RenderedPage, Renderer};

#[derive(Debug)]
struct FakeRenderer;

impl Renderer for FakeRenderer {
    fn render(&self, _request_json: &str) -> Result<RenderedPage, RenderError> {
        Ok(RenderedPage::from_complete_html(
            "<!doctype html><html><body>fake</body></html>".to_owned(),
        ))
    }
}

#[test]
fn external_renderer_implementations_can_return_complete_documents() {
    let page = FakeRenderer.render("{}").expect("fake renderer succeeds");
    assert_eq!(
        page.as_str(),
        "<!doctype html><html><body>fake</body></html>"
    );
    assert_eq!(
        page.into_string(),
        "<!doctype html><html><body>fake</body></html>"
    );
}
