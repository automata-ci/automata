use automata_ci_execution::{TargetPath, TargetPlatform};

const RESERVED_NAMES: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

pub(crate) fn validate_windows_path(path: &TargetPath) -> bool {
    if path.platform() != TargetPlatform::Windows || !path.as_str().is_ascii() {
        return false;
    }
    let mut components = path.as_str().split('\\');
    let Some(drive) = components.next() else {
        return false;
    };
    if drive.len() != 2 || !drive.as_bytes()[0].is_ascii_alphabetic() || drive.as_bytes()[1] != b':'
    {
        return false;
    }
    let Some(first) = components.next() else {
        return false;
    };
    valid_component(first) && components.all(valid_component)
}

fn valid_component(component: &str) -> bool {
    if component.is_empty()
        || component.ends_with([' ', '.'])
        || component
            .bytes()
            .any(|byte| byte < b' ' || b"/<>:\"|?*".contains(&byte))
    {
        return false;
    }
    let basename = component
        .split_once('.')
        .map_or(component, |(basename, _)| basename)
        .to_ascii_uppercase();
    !RESERVED_NAMES.contains(&basename.as_str())
}

pub(crate) fn normalized(path: &TargetPath) -> String {
    path.as_str().to_ascii_lowercase()
}

pub(crate) fn is_within(path: &TargetPath, root: &TargetPath) -> bool {
    let path = normalized(path);
    let root = normalized(root);
    path == root
        || path
            .strip_prefix(&root)
            .is_some_and(|remainder| remainder.starts_with('\\'))
}

pub(crate) fn is_strict_descendant(path: &TargetPath, root: &TargetPath) -> bool {
    normalized(path) != normalized(root) && is_within(path, root)
}

pub(crate) fn overlaps(left: &TargetPath, right: &TargetPath) -> bool {
    is_within(left, right) || is_within(right, left)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn windows(path: &str) -> TargetPath {
        TargetPath::windows(path.to_owned()).expect("Windows target path")
    }

    #[test]
    fn validation_rejects_drive_relative_and_mixed_separator_paths() {
        assert!(TargetPath::windows("C:".to_owned()).is_err());
        for path in ["C:\\root/workspace", "C:\\root\\workspace/../../escape"] {
            if let Ok(path) = TargetPath::windows(path.to_owned()) {
                assert!(!validate_windows_path(&path));
            }
        }
        assert!(validate_windows_path(&windows("C:\\root\\workspace")));
    }
}
