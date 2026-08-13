#![cfg(target_os = "macos")]
#![forbid(unsafe_code)]

use std::{path::PathBuf, time::Duration};

use automata_ci_execution::{ProviderErrorKind, Sha256Digest};
use automata_ci_sandbox_macos::{MacosVirtualizationProvider, MacosVirtualizationProviderOptions};
use static_assertions::assert_impl_all;

assert_impl_all!(MacosVirtualizationProvider: Send, Sync, Clone);

fn options(
    root: impl Into<PathBuf>,
) -> Result<MacosVirtualizationProviderOptions, automata_ci_execution::ProviderError> {
    options_with_storage(
        root,
        "01234567-89AB-CDEF-0123-456789ABCDEF",
        256 * 1024 * 1024 * 1024,
    )
}

fn options_with_storage(
    root: impl Into<PathBuf>,
    storage_volume_uuid: &str,
    storage_quota_bytes: u64,
) -> Result<MacosVirtualizationProviderOptions, automata_ci_execution::ProviderError> {
    MacosVirtualizationProviderOptions::new(
        root,
        "/Library/Automata/bin/automata-macos-vm-helper",
        Sha256Digest::from_bytes([0x11; 32]),
        "identifier \"dev.automata.macos-vm-helper\" and anchor apple generic and certificate leaf[subject.OU] = \"ABCDEFGHIJ\"".to_owned(),
        "/Library/Automata/templates/macos-15-arm64-v1/manifest.json",
        Sha256Digest::from_bytes([0x22; 32]),
        storage_volume_uuid,
        storage_quota_bytes,
        Duration::from_mins(5),
        Duration::from_secs(10),
    )
}

#[test]
fn virtualization_options_require_a_pinned_bounded_apfs_quota() {
    let root = "/Volumes/AutomataVM/state";
    for uuid in ["", "not-a-uuid", "01234567-89AB-CDEF-0123-456789ABCDEG"] {
        assert_eq!(
            options_with_storage(root, uuid, 256 * 1024 * 1024 * 1024)
                .expect_err("invalid UUID must fail")
                .kind(),
            ProviderErrorKind::InvalidConfiguration
        );
    }
    for quota in [
        63 * 1024 * 1024 * 1024,
        256 * 1024 * 1024 * 1024 + 1,
        1025 * 1024 * 1024 * 1024,
    ] {
        assert_eq!(
            options_with_storage(root, "01234567-89AB-CDEF-0123-456789ABCDEF", quota,)
                .expect_err("invalid quota must fail")
                .kind(),
            ProviderErrorKind::InvalidConfiguration
        );
    }
}

#[test]
fn virtualization_options_require_absolute_normalized_paths_and_bounded_timeouts() {
    let valid = options("/Users/automata-runner/Library/Application Support/Automata/vm")
        .expect("valid VM provider options");
    assert_eq!(
        valid.provider_root(),
        std::path::Path::new("/Users/automata-runner/Library/Application Support/Automata/vm")
    );

    for invalid in ["relative", "/", "/Users/runner/../runner/vm"] {
        assert_eq!(
            options(invalid).expect_err("invalid root must fail").kind(),
            ProviderErrorKind::InvalidConfiguration
        );
    }
}

#[test]
fn provider_open_fails_closed_before_accepting_unpinned_artifacts() {
    let error = MacosVirtualizationProvider::open(
        options("/Users/automata-runner/Library/Application Support/Automata/test-vm")
            .expect("syntactically valid options"),
    )
    .expect_err("uninstalled pinned helper and template must be rejected");
    assert_eq!(error.kind(), ProviderErrorKind::InvalidConfiguration);
}
