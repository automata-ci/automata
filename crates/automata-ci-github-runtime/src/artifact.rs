use crate::{
    ArtifactDeclaration, ArtifactDeclarationCommandFile, ArtifactFileDeclaration, ArtifactSubject,
    ArtifactSubjectKind, CommandFileError, CommandFileKind, CommandFileLimits,
};

const FILE_SCHEME: &str = "file://";
const OCI_SCHEME: &str = "oci://";

pub(crate) fn parse_artifact_declarations(
    text: &str,
    limits: CommandFileLimits,
) -> Result<ArtifactDeclarationCommandFile, CommandFileError> {
    let mut declarations = Vec::new();
    for (index, raw) in text.split('\n').enumerate() {
        let line_number = index.saturating_add(1);
        if line_number > limits.maximum_records() {
            return Err(CommandFileError::TooManyRecords {
                kind: CommandFileKind::Artifacts,
                maximum: limits.maximum_records(),
            });
        }
        if raw.len() > limits.maximum_line_bytes() {
            return Err(CommandFileError::LineTooLong {
                kind: CommandFileKind::Artifacts,
                maximum: limits.maximum_line_bytes(),
            });
        }
        let declaration = raw.trim();
        if declaration.is_empty() || declaration.starts_with('#') {
            continue;
        }
        let parsed = parse_declaration(declaration)
            .ok_or(CommandFileError::InvalidArtifactDeclaration { line: line_number })?;
        declarations.push(parsed);
    }
    Ok(ArtifactDeclarationCommandFile { declarations })
}

fn parse_declaration(value: &str) -> Option<ArtifactDeclaration> {
    if value.contains('=') {
        return None;
    }
    if let Some(path) = strip_prefix_ignore_ascii_case(value, FILE_SCHEME) {
        return (!path.trim().is_empty())
            .then(|| ArtifactDeclaration::File(ArtifactFileDeclaration::new(path.to_owned())));
    }
    if let Some(reference) = strip_prefix_ignore_ascii_case(value, OCI_SCHEME) {
        return parse_oci(reference);
    }
    if has_uri_scheme(value) {
        return None;
    }
    parse_oci(value).or_else(|| {
        Some(ArtifactDeclaration::File(ArtifactFileDeclaration::new(
            value.to_owned(),
        )))
    })
}

fn parse_oci(value: &str) -> Option<ArtifactDeclaration> {
    let Some((name, digest)) = value.rsplit_once('@') else {
        return None;
    };
    if name.is_empty() {
        return None;
    }
    let (algorithm, hexadecimal, expected) =
        if let Some(hexadecimal) = digest.strip_prefix("sha256:") {
            ("sha256", hexadecimal, 64)
        } else if let Some(hexadecimal) = digest.strip_prefix("sha384:") {
            ("sha384", hexadecimal, 96)
        } else if let Some(hexadecimal) = digest.strip_prefix("sha512:") {
            ("sha512", hexadecimal, 128)
        } else {
            return None;
        };
    if hexadecimal.is_empty()
        || !hexadecimal.bytes().all(|byte| byte.is_ascii_hexdigit())
        || hexadecimal.len() != expected
    {
        return None;
    }
    let subject = ArtifactSubject::new(
        name,
        format!("{algorithm}:{}", hexadecimal.to_ascii_lowercase()),
        ArtifactSubjectKind::Oci,
    )
    .ok()?;
    Some(ArtifactDeclaration::Oci(subject))
}

fn strip_prefix_ignore_ascii_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    let candidate = value.get(..prefix.len())?;
    candidate
        .eq_ignore_ascii_case(prefix)
        .then(|| &value[prefix.len()..])
}

fn has_uri_scheme(value: &str) -> bool {
    let Some((scheme, _)) = value.split_once("://") else {
        return false;
    };
    let mut bytes = scheme.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}
