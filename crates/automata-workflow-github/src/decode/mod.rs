mod event;
mod job;
mod value;
mod workflow;

pub(crate) use workflow::decode_workflow;

use crate::{
    Diagnostic, DiagnosticKind, PreservedField, SourceSpan, Spanned, YamlMappingEntry, YamlNode,
    YamlScalar,
};

#[derive(Debug)]
pub(super) struct DecodeContext<'diagnostics> {
    diagnostics: &'diagnostics mut Vec<Diagnostic>,
}

impl<'diagnostics> DecodeContext<'diagnostics> {
    pub fn new(diagnostics: &'diagnostics mut Vec<Diagnostic>) -> Self {
        Self { diagnostics }
    }

    pub fn semantic(&mut self, code: &str, message: impl Into<String>, span: SourceSpan) {
        self.diagnostics.push(Diagnostic::error(
            DiagnosticKind::Semantic,
            code,
            message,
            span,
        ));
    }

    pub fn unsupported(&mut self, code: &str, message: impl Into<String>, span: SourceSpan) {
        self.diagnostics.push(Diagnostic::error(
            DiagnosticKind::Unsupported,
            code,
            message,
            span,
        ));
    }

    pub fn expect_mapping<'node>(
        &mut self,
        node: &'node YamlNode,
        path: &str,
    ) -> Option<&'node [YamlMappingEntry]> {
        let mapping = node.as_mapping();
        if mapping.is_none() {
            self.semantic(
                "github.expected_mapping",
                format!("`{path}` must be a mapping"),
                node.span.clone(),
            );
        }
        mapping
    }

    pub fn scalar<'node>(
        &mut self,
        node: &'node YamlNode,
        path: &str,
    ) -> Option<&'node YamlScalar> {
        let scalar = node.as_scalar();
        if scalar.is_none() {
            self.semantic(
                "github.expected_scalar",
                format!("`{path}` must be a scalar"),
                node.span.clone(),
            );
        }
        scalar
    }

    pub fn text(&mut self, node: &YamlNode, path: &str) -> Option<Spanned<String>> {
        let scalar = self.scalar(node, path)?;
        if scalar.is_null() {
            self.semantic(
                "github.expected_text",
                format!("`{path}` must not be null"),
                node.span.clone(),
            );
            return None;
        }
        Some(Spanned::new(scalar.decoded.clone(), node.span.clone()))
    }

    pub fn preserve_unknown(
        &mut self,
        parent_path: &str,
        entry: &YamlMappingEntry,
    ) -> PreservedField {
        let key = entry
            .key
            .as_scalar()
            .map_or("<complex-key>", |scalar| scalar.decoded.as_str());
        let path = format!("{parent_path}.{key}");
        self.unsupported(
            "github.unsupported_field",
            format!("`{path}` is preserved but not supported by this frontend version"),
            entry.key.span.clone(),
        );
        PreservedField {
            path,
            entry: entry.clone(),
        }
    }
}

pub(super) fn field_name(entry: &YamlMappingEntry) -> Option<&str> {
    entry.key.as_scalar().map(|scalar| scalar.decoded.as_str())
}

pub(super) fn sequence_text(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Vec<Spanned<String>> {
    let Some(items) = node.as_sequence() else {
        context.semantic(
            "github.expected_sequence",
            format!("`{path}` must be a sequence"),
            node.span.clone(),
        );
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| context.text(item, path))
        .collect()
}

pub(super) fn valid_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && characters
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
}
