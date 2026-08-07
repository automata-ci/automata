use crate::{
    DockerImage, MetadataDecodeError, MetadataDecodeErrorKind, MetadataEntryPath, MetadataScalar,
    MetadataScalarKind,
};

const MAX_ENTRY_PATH_BYTES: usize = 4 * 1_024;
const MAX_IMAGE_REFERENCE_BYTES: usize = 4 * 1_024;

pub(crate) fn scalar_string(value: &MetadataScalar) -> String {
    match value.kind() {
        MetadataScalarKind::Null => String::new(),
        MetadataScalarKind::Boolean => value.text().to_ascii_lowercase(),
        MetadataScalarKind::String | MetadataScalarKind::Integer | MetadataScalarKind::Float => {
            value.text().to_owned()
        }
    }
}

pub(crate) fn entry_path(
    value: &MetadataScalar,
    field: &'static str,
) -> Result<MetadataEntryPath, MetadataDecodeError> {
    let declared = scalar_string(value);
    if declared.is_empty()
        || declared.len() > MAX_ENTRY_PATH_BYTES
        || declared.starts_with('/')
        || declared.starts_with("//")
        || declared.ends_with('/')
        || declared.contains('\\')
        || declared.contains("${{")
        || declared.chars().any(char::is_control)
    {
        return Err(unsafe_path(field, value));
    }

    let mut canonical_components = Vec::new();
    for component in declared.split('/') {
        match component {
            "" | ".." => return Err(unsafe_path(field, value)),
            "." => {}
            component => {
                if canonical_components.is_empty() && component.contains(':') {
                    return Err(unsafe_path(field, value));
                }
                canonical_components.push(component);
            }
        }
    }
    if canonical_components.is_empty() {
        return Err(unsafe_path(field, value));
    }
    let canonical = canonical_components.join("/");
    Ok(MetadataEntryPath::from_validated(declared, canonical))
}

pub(crate) fn docker_image(value: &MetadataScalar) -> Result<DockerImage, MetadataDecodeError> {
    let declared = scalar_string(value);
    if let Some(reference) = strip_prefix_ignore_ascii_case(&declared, "docker://") {
        if reference.is_empty()
            || reference.len() > MAX_IMAGE_REFERENCE_BYTES
            || reference.contains("${{")
            || reference.chars().any(char::is_whitespace)
            || reference.chars().any(char::is_control)
        {
            return Err(unsafe_path("runs.image", value));
        }
        return Ok(DockerImage::registry(declared));
    }
    let path = entry_path(value, "runs.image")?;
    Ok(DockerImage::local(declared, path))
}

fn strip_prefix_ignore_ascii_case<'value>(value: &'value str, prefix: &str) -> Option<&'value str> {
    value
        .get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
        .then(|| &value[prefix.len()..])
}

fn unsafe_path(field: &'static str, value: &MetadataScalar) -> MetadataDecodeError {
    MetadataDecodeError::new(
        MetadataDecodeErrorKind::UnsafeEntryPath,
        field,
        value.location(),
    )
}
