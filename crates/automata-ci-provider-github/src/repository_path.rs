const MAX_REPOSITORY_COMPONENT_BYTES: usize = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RepositoryPathLimitRejection {
    ComponentBytes,
}

const fn repository_component_byte_rejection(
    observed: usize,
) -> Option<RepositoryPathLimitRejection> {
    if observed > MAX_REPOSITORY_COMPONENT_BYTES {
        return Some(RepositoryPathLimitRejection::ComponentBytes);
    }
    None
}

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
        && repository_component_byte_rejection(value.len()).is_none()
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

#[cfg(test)]
mod limit_contract_tests {
    use super::{
        MAX_REPOSITORY_COMPONENT_BYTES, RepositoryPathLimitRejection,
        repository_component_byte_rejection,
    };

    #[test]
    fn repository_component_byte_limit_has_exact_boundaries() {
        assert_eq!(
            repository_component_byte_rejection(MAX_REPOSITORY_COMPONENT_BYTES - 1),
            None
        );
        assert_eq!(
            repository_component_byte_rejection(MAX_REPOSITORY_COMPONENT_BYTES),
            None
        );
        assert_eq!(
            repository_component_byte_rejection(MAX_REPOSITORY_COMPONENT_BYTES + 1),
            Some(RepositoryPathLimitRejection::ComponentBytes)
        );
    }
}
