use std::path::{Component, Path};

use automata_ci_execution::{TargetPath, TargetPlatform};

pub(crate) fn validate_posix_path(path: &TargetPath) -> bool {
    path.platform() == TargetPlatform::Posix
        && path.as_str() != "/"
        && Path::new(path.as_str())
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

pub(crate) fn is_strict_descendant(path: &TargetPath, root: &TargetPath) -> bool {
    if !validate_posix_path(path) || !validate_posix_path(root) || path == root {
        return false;
    }
    Path::new(path.as_str())
        .strip_prefix(Path::new(root.as_str()))
        .is_ok_and(|relative| {
            relative
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
        })
}

pub(crate) fn overlaps(left: &TargetPath, right: &TargetPath) -> bool {
    left == right || is_strict_descendant(left, right) || is_strict_descendant(right, left)
}

#[cfg(test)]
mod tests {
    use automata_ci_execution::TargetPath;

    use super::{is_strict_descendant, overlaps};

    #[test]
    fn component_boundaries_prevent_prefix_confusion() {
        let root = TargetPath::posix("/private/runner").expect("root");
        let child = TargetPath::posix("/private/runner/jobs/a").expect("child");
        let prefix = TargetPath::posix("/private/runner-evil/a").expect("prefix");

        assert!(is_strict_descendant(&child, &root));
        assert!(!is_strict_descendant(&prefix, &root));
        assert!(overlaps(&root, &child));
        assert!(!overlaps(&root, &prefix));
    }
}
