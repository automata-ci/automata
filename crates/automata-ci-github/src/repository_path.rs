const MAX_REPOSITORY_COMPONENT_BYTES: usize = 100;

pub(crate) fn split(repository: &str) -> Option<(&str, &str)> {
    let (owner, name) = repository.split_once('/')?;
    if name.contains('/')
        || !is_valid_component(owner)
        || !is_valid_component(name)
        || has_ascii_case_insensitive_suffix(name, ".git")
    {
        return None;
    }
    Some((owner, name))
}

pub(crate) fn is_valid_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REPOSITORY_COMPONENT_BYTES
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub(crate) fn has_ascii_case_insensitive_suffix(value: &str, suffix: &str) -> bool {
    value
        .get(value.len().saturating_sub(suffix.len())..)
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(suffix))
}
