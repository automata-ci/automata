use std::sync::Mutex;

use automata_ci_ui_renderer::{RenderError, RenderedPage, Renderer};

#[derive(Debug)]
pub struct RecordingRenderer {
    html: String,
    requests: Mutex<Vec<String>>,
}

impl RecordingRenderer {
    pub fn new(html: impl Into<String>) -> Self {
        Self {
            html: html.into(),
            requests: Mutex::new(Vec::new()),
        }
    }

    pub fn requests(&self) -> Vec<String> {
        self.requests
            .lock()
            .expect("recording renderer lock must not be poisoned")
            .clone()
    }
}

impl Renderer for RecordingRenderer {
    fn render(&self, request_json: &str) -> Result<RenderedPage, RenderError> {
        self.requests
            .lock()
            .expect("recording renderer lock must not be poisoned")
            .push(request_json.to_owned());
        Ok(RenderedPage::from_complete_html(self.html.clone()))
    }
}
