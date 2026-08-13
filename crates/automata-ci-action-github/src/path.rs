use crate::{
    DockerImage, MetadataDecodeError, MetadataDecodeErrorKind, MetadataEntryPath, MetadataScalar,
    MetadataScalarKind,
};

// foundation-governance: parity-limit
const MAX_ENTRY_PATH_BYTES: usize = 4_096;
// foundation-governance: parity-limit
const MAX_IMAGE_REFERENCE_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GithubActionPathLimitRejection {
    EntryPathBytes,
    ImageReferenceBytes,
}

const fn entry_path_byte_rejection(observed: usize) -> Option<GithubActionPathLimitRejection> {
    if observed > MAX_ENTRY_PATH_BYTES {
        return Some(GithubActionPathLimitRejection::EntryPathBytes);
    }
    None
}

const fn image_reference_byte_rejection(observed: usize) -> Option<GithubActionPathLimitRejection> {
    if observed > MAX_IMAGE_REFERENCE_BYTES {
        return Some(GithubActionPathLimitRejection::ImageReferenceBytes);
    }
    None
}

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
        || entry_path_byte_rejection(declared.len()).is_some()
        || declared.starts_with('/')
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
            || image_reference_byte_rejection(reference.len()).is_some()
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

#[cfg(test)]
mod limit_contract_tests {
    use super::{
        GithubActionPathLimitRejection, MAX_ENTRY_PATH_BYTES, MAX_IMAGE_REFERENCE_BYTES,
        entry_path_byte_rejection, image_reference_byte_rejection,
    };

    #[test]
    fn entry_path_byte_limit_has_exact_boundaries() {
        assert_eq!(entry_path_byte_rejection(MAX_ENTRY_PATH_BYTES - 1), None);
        assert_eq!(entry_path_byte_rejection(MAX_ENTRY_PATH_BYTES), None);
        assert_eq!(
            entry_path_byte_rejection(MAX_ENTRY_PATH_BYTES + 1),
            Some(GithubActionPathLimitRejection::EntryPathBytes)
        );
    }

    #[test]
    fn image_reference_byte_limit_has_exact_boundaries() {
        assert_eq!(
            image_reference_byte_rejection(MAX_IMAGE_REFERENCE_BYTES - 1),
            None
        );
        assert_eq!(
            image_reference_byte_rejection(MAX_IMAGE_REFERENCE_BYTES),
            None
        );
        assert_eq!(
            image_reference_byte_rejection(MAX_IMAGE_REFERENCE_BYTES + 1),
            Some(GithubActionPathLimitRejection::ImageReferenceBytes)
        );
    }
}
