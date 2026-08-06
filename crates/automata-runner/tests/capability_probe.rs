use std::path::PathBuf;

use automata_runner::capability_probe::{
    CGROUP_V2, KernelModuleReadiness, PODMAN_NETWORK_ISOLATION, PROCESS_EXECUTION, ProbeReasonCode,
    ProbeStatus, USER_NAMESPACE, assess_podman_network_isolation, probe_capabilities,
    usable_capabilities,
};

#[test]
fn actively_verifies_process_execution_before_advertising_it() {
    let probes = probe_capabilities();
    let process_probe = probes
        .iter()
        .find(|probe| probe.capability() == PROCESS_EXECUTION)
        .expect("process execution must be probed");

    assert_eq!(process_probe.status(), ProbeStatus::Usable);
    assert!(usable_capabilities(&probes).contains(PROCESS_EXECUTION));
}

#[test]
fn missing_running_kernel_module_tree_is_a_structured_degraded_result() {
    let probe = assess_podman_network_isolation(
        true,
        KernelModuleReadiness::ModuleTreeMissing {
            release: "7.1.5-arch1-1".to_owned(),
            path: PathBuf::from("/usr/lib/modules/7.1.5-arch1-1"),
        },
    );

    assert_eq!(probe.status(), ProbeStatus::Degraded);
    assert_eq!(
        probe
            .reason()
            .expect("degraded probe needs a reason")
            .code(),
        ProbeReasonCode::KernelModuleTreeMissing
    );
    assert!(!usable_capabilities(&[probe]).contains(PODMAN_NETWORK_ISOLATION));
}

#[test]
fn unavailable_nftables_modules_degrade_podman_networking() {
    let probe = assess_podman_network_isolation(
        true,
        KernelModuleReadiness::RequiredModulesMissing {
            modules: vec!["nft_ct", "nft_masq"],
        },
    );

    assert_eq!(probe.status(), ProbeStatus::Degraded);
    let reason = probe.reason().expect("degraded probe needs a reason");
    assert_eq!(
        reason.code(),
        ProbeReasonCode::RequiredKernelModulesUnavailable
    );
    assert!(reason.detail().contains("nft_ct"));
    assert!(reason.detail().contains("nft_masq"));
}

#[test]
fn missing_module_dependency_index_degrades_podman_networking() {
    let probe = assess_podman_network_isolation(
        true,
        KernelModuleReadiness::DependencyIndexMissing {
            path: PathBuf::from("/usr/lib/modules/7.1.5-arch1-1/modules.dep"),
        },
    );

    assert_eq!(probe.status(), ProbeStatus::Degraded);
    assert_eq!(
        probe
            .reason()
            .expect("degraded probe needs a reason")
            .code(),
        ProbeReasonCode::ModuleDependencyIndexMissing
    );
    assert!(!usable_capabilities(&[probe]).contains(PODMAN_NETWORK_ISOLATION));
}

#[test]
fn read_only_prerequisite_detection_does_not_claim_network_usability() {
    let probe = assess_podman_network_isolation(
        true,
        KernelModuleReadiness::Ready {
            release: "7.1.5-arch1-1".to_owned(),
        },
    );

    assert_eq!(probe.status(), ProbeStatus::Detected);
    assert_eq!(
        probe
            .reason()
            .expect("detection limit needs a reason")
            .code(),
        ProbeReasonCode::ActiveNetworkVerificationNotPerformed
    );
    assert!(!usable_capabilities(&[probe]).contains(PODMAN_NETWORK_ISOLATION));
}

#[cfg(target_os = "linux")]
#[test]
fn interface_presence_is_not_advertised_as_usable() {
    let probes = probe_capabilities();
    let capabilities = usable_capabilities(&probes);

    for capability in [CGROUP_V2, USER_NAMESPACE] {
        let probe = probes
            .iter()
            .find(|probe| probe.capability() == capability)
            .expect("Linux interface must be probed");
        assert_ne!(probe.status(), ProbeStatus::Usable);
        assert!(!capabilities.contains(capability));
        assert!(!probe.detail().is_empty());
    }
}
