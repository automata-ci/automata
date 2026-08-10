mod container;
mod event;
mod job;
mod strategy;
mod value;
mod workflow;

pub(crate) use workflow::decode_workflow;

use std::{fmt::Write as _, mem::size_of};

use crate::{
    Diagnostic, DiagnosticKind, PreservedField, SourceSpan, Spanned, YamlMappingEntry, YamlNode,
    YamlScalar,
};

// Parsing already bounds source bytes and AST nodes. This separate budget keeps
// repeated fully qualified paths and diagnostics linear in a small multiple of
// the accepted source size, even when one very long key has many descendants.
const MAX_DERIVED_TEXT_BYTES: usize = 16 * 1024 * 1024;
const DERIVED_TEXT_LIMIT_CODE: &str = "github.decode.derived_text_limit";
const DERIVED_TEXT_LIMIT_MESSAGE: &str =
    "workflow decoding exceeded the 16 MiB derived-text and diagnostic budget";

#[derive(Debug)]
pub(super) struct DecodeContext<'diagnostics> {
    diagnostics: &'diagnostics mut Vec<Diagnostic>,
    remaining_derived_text_bytes: usize,
    exhausted: bool,
}

impl<'diagnostics> DecodeContext<'diagnostics> {
    pub(super) fn new(diagnostics: &'diagnostics mut Vec<Diagnostic>) -> Self {
        Self {
            diagnostics,
            remaining_derived_text_bytes: MAX_DERIVED_TEXT_BYTES,
            exhausted: false,
        }
    }

    pub(super) const fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    pub(super) fn semantic(&mut self, code: &str, message: impl Into<String>, span: SourceSpan) {
        self.diagnostic(DiagnosticKind::Semantic, code, message, span);
    }

    pub(super) fn unsupported(&mut self, code: &str, message: impl Into<String>, span: SourceSpan) {
        self.diagnostic(DiagnosticKind::Unsupported, code, message, span);
    }

    pub(super) fn child_path(
        &mut self,
        parent: &str,
        child: &str,
        span: &SourceSpan,
    ) -> Option<String> {
        let bytes = parent
            .len()
            .checked_add(1)
            .and_then(|bytes| bytes.checked_add(child.len()));
        let bytes = self.reserve_length(bytes, span)?;
        let mut path = String::with_capacity(bytes);
        path.push_str(parent);
        path.push('.');
        path.push_str(child);
        Some(path)
    }

    pub(super) fn indexed_path(
        &mut self,
        parent: &str,
        index: usize,
        span: &SourceSpan,
    ) -> Option<String> {
        let digits = decimal_digits(index);
        let bytes = parent
            .len()
            .checked_add(2)
            .and_then(|bytes| bytes.checked_add(digits));
        let bytes = self.reserve_length(bytes, span)?;
        let mut path = String::with_capacity(bytes);
        path.push_str(parent);
        write!(&mut path, "[{index}]").expect("writing to a String cannot fail");
        Some(path)
    }

    pub(super) fn invalid_key_path(
        &mut self,
        parent: &str,
        index: usize,
        span: &SourceSpan,
    ) -> Option<String> {
        let digits = decimal_digits(index);
        let bytes = parent
            .len()
            .checked_add(".<invalid-key->".len())
            .and_then(|bytes| bytes.checked_add(digits));
        let bytes = self.reserve_length(bytes, span)?;
        let mut path = String::with_capacity(bytes);
        path.push_str(parent);
        write!(&mut path, ".<invalid-key-{index}>").expect("writing to a String cannot fail");
        Some(path)
    }

    pub(super) fn expect_mapping<'node>(
        &mut self,
        node: &'node YamlNode,
        path: &str,
    ) -> Option<&'node [YamlMappingEntry]> {
        if self.exhausted {
            return None;
        }
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

    pub(super) fn scalar<'node>(
        &mut self,
        node: &'node YamlNode,
        path: &str,
    ) -> Option<&'node YamlScalar> {
        if self.exhausted {
            return None;
        }
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

    pub(super) fn text(&mut self, node: &YamlNode, path: &str) -> Option<Spanned<String>> {
        if self.exhausted {
            return None;
        }
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

    pub(super) fn preserve_unknown(
        &mut self,
        parent_path: &str,
        entry: &YamlMappingEntry,
    ) -> Option<PreservedField> {
        if self.exhausted {
            return None;
        }
        let key = entry
            .key
            .as_scalar()
            .map_or("<complex-key>", |scalar| scalar.decoded.as_str());
        let path = self.child_path(parent_path, key, &entry.key.span)?;
        self.unsupported(
            "github.unsupported_field",
            format!("`{path}` is preserved but not supported by this frontend version"),
            entry.key.span.clone(),
        );
        if self.exhausted {
            return None;
        }
        Some(PreservedField {
            path,
            entry: entry.clone(),
        })
    }

    fn diagnostic(
        &mut self,
        kind: DiagnosticKind,
        code: &str,
        message: impl Into<String>,
        span: SourceSpan,
    ) {
        if self.exhausted {
            return;
        }
        let message = message.into();
        let bytes = size_of::<Diagnostic>()
            .checked_add(code.len())
            .and_then(|bytes| bytes.checked_add(message.len()));
        if self.reserve_length(bytes, &span).is_none() {
            return;
        }
        self.diagnostics
            .push(Diagnostic::error(kind, code, message, span));
    }

    fn reserve_length(&mut self, bytes: Option<usize>, span: &SourceSpan) -> Option<usize> {
        if self.exhausted {
            return None;
        }
        let Some(bytes) = bytes else {
            self.exhaust(span);
            return None;
        };
        let Some(remaining) = self.remaining_derived_text_bytes.checked_sub(bytes) else {
            self.exhaust(span);
            return None;
        };
        self.remaining_derived_text_bytes = remaining;
        Some(bytes)
    }

    fn exhaust(&mut self, span: &SourceSpan) {
        if self.exhausted {
            return;
        }
        self.exhausted = true;
        self.diagnostics.push(Diagnostic::error(
            DiagnosticKind::ResourceLimit,
            DERIVED_TEXT_LIMIT_CODE,
            DERIVED_TEXT_LIMIT_MESSAGE,
            span.clone(),
        ));
    }
}

fn decimal_digits(value: usize) -> usize {
    if value == 0 {
        1
    } else {
        value.ilog10() as usize + 1
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
    if context.is_exhausted() {
        return Vec::new();
    }
    let Some(items) = node.as_sequence() else {
        context.semantic(
            "github.expected_sequence",
            format!("`{path}` must be a sequence"),
            node.span.clone(),
        );
        return Vec::new();
    };
    let mut values = Vec::with_capacity(items.len());
    for item in items {
        if context.is_exhausted() {
            break;
        }
        if let Some(value) = context.text(item, path) {
            values.push(value);
        }
    }
    values
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
