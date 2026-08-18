use std::{cmp::Ordering, fmt};

use focaccia::unicode_full_casecmp;
use unicode_normalization::UnicodeNormalization as _;

const USTAR_NAME_BYTES: usize = 100;
const USTAR_PREFIX_BYTES: usize = 155;
const USTAR_PATH_BYTES: usize = USTAR_PREFIX_BYTES + 1 + USTAR_NAME_BYTES;

/// Maximum link-name byte length representable by a POSIX ustar header.
pub const USTAR_LINK_NAME_BYTES: usize = 100;

#[derive(Clone, Debug)]
pub(crate) struct PortablePathKey(String);

impl PortablePathKey {
    pub(crate) fn storage_bytes(&self) -> usize {
        self.0.len()
    }
}

impl PartialEq for PortablePathKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for PortablePathKey {}

impl PartialOrd for PortablePathKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PortablePathKey {
    fn cmp(&self, other: &Self) -> Ordering {
        unicode_full_casecmp(&self.0, &other.0)
    }
}

/// One archive-root-relative portable repository-path policy.
///
/// The validator applies one canonical policy to live-worktree paths, archive
/// entry paths, and symbolic-link targets. It rejects forms that acquire
/// different meanings on Unix and Windows, including drive prefixes, NTFS
/// alternate streams, reserved device names, trailing dots or spaces, and
/// paths that the deterministic ustar encoder cannot represent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepositoryPathValidator {
    archive_root_bytes: usize,
    maximum_archive_path_bytes: usize,
}

impl RepositoryPathValidator {
    /// Creates a validator for entries beneath one explicit archive root.
    ///
    /// # Errors
    ///
    /// Rejects an unsafe root or a configured path ceiling that cannot contain
    /// the root itself.
    pub fn new(
        archive_root: &str,
        maximum_archive_path_bytes: usize,
    ) -> Result<Self, RepositoryPathValidationError> {
        if archive_root.as_bytes().contains(&b'/') || archive_root.as_bytes().contains(&b'\\') {
            return Err(RepositoryPathValidationError::Unsafe);
        }
        validate_component(archive_root)?;
        if archive_root.chars().any(char::is_control) {
            return Err(RepositoryPathValidationError::Unsafe);
        }
        if archive_root.len() > maximum_archive_path_bytes || archive_root.len() > USTAR_NAME_BYTES
        {
            return Err(RepositoryPathValidationError::ResourceLimit);
        }
        Ok(Self {
            archive_root_bytes: archive_root.len(),
            maximum_archive_path_bytes,
        })
    }

    /// Validates one nonempty repository-relative entry path.
    ///
    /// # Errors
    ///
    /// Rejects non-Unicode, over-limit, noncanonical, nonportable, or
    /// ustar-unrepresentable paths.
    pub fn validate_entry(self, raw: &[u8]) -> Result<&str, RepositoryPathValidationError> {
        let path = self.validate_relative_shape(raw)?;
        if !ustar_path_representable(self.archive_root_bytes, raw) {
            return Err(RepositoryPathValidationError::ResourceLimit);
        }
        Ok(path)
    }

    /// Validates a repository-relative directory used only as an ancestor of
    /// encoded entries.
    ///
    /// Such a directory is not emitted as its own tar entry, but its complete
    /// rooted spelling must fit the ustar prefix field available to every
    /// descendant.
    ///
    /// # Errors
    ///
    /// Rejects non-Unicode, over-limit, noncanonical, or nonportable paths.
    pub fn validate_entry_ancestor(
        self,
        raw: &[u8],
    ) -> Result<&str, RepositoryPathValidationError> {
        let path = self.validate_relative_shape(raw)?;
        if self.full_length(raw)? > USTAR_PREFIX_BYTES {
            return Err(RepositoryPathValidationError::ResourceLimit);
        }
        Ok(path)
    }

    /// Validates one relative symbolic-link target without resolving it.
    ///
    /// `.` and `..` components are retained for graph-aware resolution because
    /// an intermediate symbolic link changes the directory to which a later
    /// parent component applies.
    ///
    /// # Errors
    ///
    /// Rejects non-Unicode, over-limit, absolute, malformed, or nonportable
    /// targets. Containment, cycles, case aliases, and namespace aliases are
    /// decided later against the complete archive graph.
    pub fn validate_symlink_target(
        self,
        raw: &[u8],
    ) -> Result<&str, RepositoryPathValidationError> {
        if raw.is_empty() || raw.starts_with(b"/") || raw.contains(&b'\\') {
            return Err(RepositoryPathValidationError::Unsafe);
        }
        if raw.len() > self.maximum_archive_path_bytes.min(USTAR_LINK_NAME_BYTES) {
            return Err(RepositoryPathValidationError::ResourceLimit);
        }
        let target =
            std::str::from_utf8(raw).map_err(|_| RepositoryPathValidationError::NonUnicode)?;
        if target.chars().any(char::is_control) {
            return Err(RepositoryPathValidationError::Unsafe);
        }

        for component in target.split('/') {
            match component {
                "" => return Err(RepositoryPathValidationError::Unsafe),
                "." | ".." => {}
                component => {
                    validate_component(component)?;
                }
            }
        }
        Ok(target)
    }

    #[must_use]
    pub(crate) fn portable_key(path: &str) -> PortablePathKey {
        PortablePathKey(path.nfkd().collect())
    }

    pub(crate) fn portable_equivalent(left: &str, right: &str) -> bool {
        Self::portable_key(left) == Self::portable_key(right)
    }

    pub(crate) fn validate_resolved_components(
        self,
        components: &[String],
        terminal: bool,
    ) -> Result<(), RepositoryPathValidationError> {
        let relative_bytes = components
            .iter()
            .try_fold(components.len().saturating_sub(1), |total, component| {
                total.checked_add(component.len())
            })
            .ok_or(RepositoryPathValidationError::ResourceLimit)?;
        let full_length = self
            .archive_root_bytes
            .checked_add(1)
            .and_then(|length| length.checked_add(relative_bytes))
            .ok_or(RepositoryPathValidationError::ResourceLimit)?;
        if components.is_empty()
            || full_length > self.maximum_archive_path_bytes
            || full_length > USTAR_PATH_BYTES
        {
            return Err(RepositoryPathValidationError::ResourceLimit);
        }
        if !terminal {
            return if full_length <= USTAR_PREFIX_BYTES {
                Ok(())
            } else {
                Err(RepositoryPathValidationError::ResourceLimit)
            };
        }
        if full_length <= USTAR_NAME_BYTES
            || self.archive_root_bytes <= USTAR_PREFIX_BYTES && relative_bytes <= USTAR_NAME_BYTES
        {
            return Ok(());
        }
        let mut left_bytes = 0_usize;
        for (index, component) in components.iter().enumerate() {
            left_bytes = left_bytes
                .checked_add(component.len())
                .ok_or(RepositoryPathValidationError::ResourceLimit)?;
            if index + 1 == components.len() {
                break;
            }
            let prefix = self
                .archive_root_bytes
                .checked_add(1)
                .and_then(|bytes| bytes.checked_add(left_bytes))
                .and_then(|bytes| bytes.checked_add(index))
                .ok_or(RepositoryPathValidationError::ResourceLimit)?;
            let name = relative_bytes
                .checked_sub(left_bytes)
                .and_then(|bytes| bytes.checked_sub(index + 1))
                .ok_or(RepositoryPathValidationError::ResourceLimit)?;
            if prefix <= USTAR_PREFIX_BYTES && name <= USTAR_NAME_BYTES {
                return Ok(());
            }
        }
        Err(RepositoryPathValidationError::ResourceLimit)
    }

    fn validate_relative_shape(self, raw: &[u8]) -> Result<&str, RepositoryPathValidationError> {
        if raw.is_empty() || raw.starts_with(b"/") || raw.contains(&b'\\') {
            return Err(RepositoryPathValidationError::Unsafe);
        }
        if self.full_length(raw)? > USTAR_PATH_BYTES {
            return Err(RepositoryPathValidationError::ResourceLimit);
        }
        let path =
            std::str::from_utf8(raw).map_err(|_| RepositoryPathValidationError::NonUnicode)?;
        validate_repository_path(path)?;
        Ok(path)
    }

    fn full_length(self, relative_path: &[u8]) -> Result<usize, RepositoryPathValidationError> {
        let full_length = self
            .archive_root_bytes
            .checked_add(1)
            .and_then(|length| length.checked_add(relative_path.len()))
            .ok_or(RepositoryPathValidationError::ResourceLimit)?;
        if full_length > self.maximum_archive_path_bytes {
            return Err(RepositoryPathValidationError::ResourceLimit);
        }
        Ok(full_length)
    }
}

fn validate_repository_path(path: &str) -> Result<(), RepositoryPathValidationError> {
    if path.chars().any(char::is_control) {
        return Err(RepositoryPathValidationError::Unsafe);
    }
    let mut components = path.split('/');
    let first = components
        .next()
        .ok_or(RepositoryPathValidationError::Unsafe)?;
    validate_component(first)?;
    let namespace = canonical_namespace(first)?;
    if let Some(second) = components.next() {
        validate_component(second)?;
        if namespace && portable_equivalent(second, "workflows") && second != "workflows" {
            return Err(RepositoryPathValidationError::Unsafe);
        }
    }
    for component in components {
        validate_component(component)?;
    }
    Ok(())
}

fn validate_component(component: &str) -> Result<(), RepositoryPathValidationError> {
    if component.is_empty()
        || matches!(component, "." | "..")
        || component.ends_with('.')
        || component.ends_with(' ')
        || portable_equivalent(component, ".git")
        || component
            .chars()
            .any(|character| matches!(character, ':' | '<' | '>' | '"' | '|' | '?' | '*'))
        || windows_reserved_component(component)
    {
        return Err(RepositoryPathValidationError::Unsafe);
    }
    Ok(())
}

fn canonical_namespace(component: &str) -> Result<bool, RepositoryPathValidationError> {
    let canonical = [".ci", ".github"]
        .into_iter()
        .find(|candidate| portable_equivalent(component, candidate));
    if canonical.is_some_and(|candidate| component != candidate) {
        return Err(RepositoryPathValidationError::Unsafe);
    }
    Ok(canonical.is_some())
}

fn portable_equivalent(left: &str, right: &str) -> bool {
    RepositoryPathValidator::portable_equivalent(left, right)
}

fn windows_reserved_component(component: &str) -> bool {
    let stem = component
        .split('.')
        .next()
        .unwrap_or(component)
        .trim_end_matches(' ');
    if matches_ignore_ascii_case(
        stem,
        &["CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$"],
    ) {
        return true;
    }
    let Some((prefix, suffix)) = stem.as_bytes().split_at_checked(3) else {
        return false;
    };
    (prefix.eq_ignore_ascii_case(b"COM") || prefix.eq_ignore_ascii_case(b"LPT"))
        && (matches!(suffix, [b'1'..=b'9'])
            || suffix == "¹".as_bytes()
            || suffix == "²".as_bytes()
            || suffix == "³".as_bytes())
}

fn matches_ignore_ascii_case(value: &str, candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
}

fn ustar_path_representable(root_bytes: usize, relative_path: &[u8]) -> bool {
    let full_length = root_bytes
        .checked_add(1)
        .and_then(|length| length.checked_add(relative_path.len()));
    let Some(full_length) = full_length else {
        return false;
    };
    if full_length <= USTAR_NAME_BYTES {
        return true;
    }
    if full_length > USTAR_PATH_BYTES {
        return false;
    }

    if root_bytes <= USTAR_PREFIX_BYTES && relative_path.len() <= USTAR_NAME_BYTES {
        return true;
    }
    relative_path
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'/')
        .any(|(slash, _)| {
            let prefix = root_bytes + 1 + slash;
            let name = relative_path.len() - slash - 1;
            prefix <= USTAR_PREFIX_BYTES && name <= USTAR_NAME_BYTES
        })
}

/// Stable failure class for portable repository-path validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryPathValidationError {
    /// The path is not valid UTF-8.
    NonUnicode,
    /// The path or target exceeds its configured or ustar byte ceiling.
    ResourceLimit,
    /// The path has an absolute, escaping, reserved, or nonportable form.
    Unsafe,
}

impl fmt::Display for RepositoryPathValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NonUnicode => "repository path is not valid Unicode",
            Self::ResourceLimit => "repository path exceeds its byte limit",
            Self::Unsafe => "repository path is unsafe or nonportable",
        })
    }
}

impl std::error::Error for RepositoryPathValidationError {}

#[cfg(test)]
mod tests {
    use super::{
        RepositoryPathValidationError as Error, RepositoryPathValidator, USTAR_LINK_NAME_BYTES,
    };

    #[test]
    fn root_and_ustar_path_bounds_are_exact() {
        assert_eq!(
            RepositoryPathValidator::new("nested/root", usize::MAX),
            Err(Error::Unsafe)
        );
        assert_eq!(
            RepositoryPathValidator::new(r"nested\root", usize::MAX),
            Err(Error::Unsafe)
        );
        assert_eq!(
            RepositoryPathValidator::new("worktree", 7),
            Err(Error::ResourceLimit)
        );
        let root_only = RepositoryPathValidator::new("worktree", 8).expect("exact root bound");
        assert_eq!(root_only.validate_entry(b"x"), Err(Error::ResourceLimit));

        let validator = RepositoryPathValidator::new("worktree", usize::MAX).expect("validator");
        let one_name = vec![b'a'; 100];
        assert!(validator.validate_entry(&one_name).is_ok());
        let unsplittable = vec![b'a'; 101];
        assert_eq!(
            validator.validate_entry(&unsplittable),
            Err(Error::ResourceLimit)
        );
        let splittable = format!("{}/{}", "a".repeat(146), "b".repeat(100));
        assert!(validator.validate_entry(splittable.as_bytes()).is_ok());
        assert!(
            validator
                .validate_entry_ancestor("a".repeat(146).as_bytes())
                .is_ok()
        );
        assert_eq!(
            validator.validate_entry_ancestor("a".repeat(147).as_bytes()),
            Err(Error::ResourceLimit)
        );
        let oversized_prefix = format!("{}/{}", "a".repeat(147), "b".repeat(100));
        assert_eq!(
            validator.validate_entry(oversized_prefix.as_bytes()),
            Err(Error::ResourceLimit)
        );
    }

    #[test]
    fn portable_entry_policy_rejects_windows_alias_forms() {
        let validator = RepositoryPathValidator::new("worktree", 4_096).expect("validator");
        for path in [
            b"C:/source".as_slice(),
            b"file:stream",
            b"CON",
            b"aux.txt",
            b"COM1.log",
            "LPT¹.txt".as_bytes(),
            b"CON .txt",
            b"Lpt9",
            b"trailing.",
            b"trailing ",
            b"bad?name",
            b".GITHUB/workflows/ci.yml",
            b"path/.git/config",
        ] {
            assert_eq!(
                validator.validate_entry(path),
                Err(Error::Unsafe),
                "{path:?}"
            );
        }
    }

    #[test]
    fn portable_identity_uses_normalization_and_full_case_folding() {
        let key = RepositoryPathValidator::portable_key;
        assert_eq!(key("Σ"), key("σ"));
        assert_eq!(key("Σ"), key("ς"));
        assert_eq!(key("caf\u{e9}"), key("cafe\u{301}"));
        assert_eq!(key("\u{fb03}"), key("ffi"));

        let validator = RepositoryPathValidator::new("worktree", 4_096).expect("validator");
        for path in [
            ".CI/workflows/ci.yml",
            ".github/WORKFLOWS/ci.yml",
            ".github/Workflows/ci.yml",
            ".\u{ff27}\u{ff29}\u{ff34}/config",
        ] {
            assert_eq!(
                validator.validate_entry(path.as_bytes()),
                Err(Error::Unsafe),
                "namespace or Git spelling {path:?}"
            );
        }
    }

    #[test]
    fn symlink_target_has_exact_ustar_boundary_and_preserves_graph_components() {
        let validator = RepositoryPathValidator::new("worktree", 4_096).expect("validator");
        let exact = vec![b'a'; USTAR_LINK_NAME_BYTES];
        assert_eq!(
            validator
                .validate_symlink_target(&exact)
                .expect("exact target"),
            std::str::from_utf8(&exact).expect("ASCII target")
        );
        let oversized = vec![b'a'; USTAR_LINK_NAME_BYTES + 1];
        assert_eq!(
            validator.validate_symlink_target(&oversized),
            Err(Error::ResourceLimit)
        );
        assert_eq!(
            validator
                .validate_symlink_target(b"../data/value")
                .expect("graph-sensitive target"),
            "../data/value"
        );
        for target in [b"../../outside".as_slice(), b"../.GITHUB/workflows"] {
            assert_eq!(
                validator
                    .validate_symlink_target(target)
                    .expect("graph decides containment and top-level spelling"),
                std::str::from_utf8(target).expect("ASCII target")
            );
        }
        for target in [
            b"C:/outside".as_slice(),
            b"file:stream",
            b"../CON",
            b"../trailing.",
            b"bad//target",
        ] {
            assert_eq!(
                validator.validate_symlink_target(target),
                Err(Error::Unsafe),
                "{target:?}"
            );
        }
    }
}
