#![cfg(windows)]

use automata_ci_core::{IsolationLevel, OperatingSystem, RunnerFeature, SandboxFeature};
use automata_ci_runner::product::{RunnerProductConfig, RunnerProductConfigError};

#[test]
fn checked_in_windows_configuration_selects_real_native_execution() {
    let config =
        RunnerProductConfig::from_json(include_bytes!("../config/runner.windows.example.json"))
            .expect("checked-in Windows runner configuration");

    assert!(config.windows_native().is_some());
    assert!(config.podman().is_none());
    assert_eq!(
        config.executor().privilege(),
        automata_ci_execution::SandboxPrivilegePolicy::Host
    );
    assert_eq!(
        config.inventory().platform().operating_system(),
        &OperatingSystem::Windows
    );
    assert_eq!(
        config.inventory().sandbox().maximum_isolation(),
        IsolationLevel::Process
    );
    assert_eq!(
        config.inventory().sandbox().features(),
        &std::collections::BTreeSet::from([SandboxFeature::CLEAN_WORKSPACE])
    );
    assert!(
        config
            .inventory()
            .features()
            .contains(&RunnerFeature::SHELL_STEPS)
    );
    assert!(
        !config
            .inventory()
            .features()
            .contains(&RunnerFeature::JAVASCRIPT_ACTIONS)
    );
    let environment = config
        .environments()
        .first_key_value()
        .expect("native environment")
        .1;
    assert!(matches!(
        environment.launch(),
        automata_ci_execution::SandboxLaunch::Native
    ));
    assert_eq!(
        environment.workspace().as_str(),
        r"C:\automata\native\workspaces"
    );
    let default_environment = environment.default_environment();
    for (name, value) in [
        ("SystemRoot", r"C:\Windows"),
        ("WINDIR", r"C:\Windows"),
        ("ComSpec", r"C:\Windows\System32\cmd.exe"),
        ("TEMP", r"C:\automata\temp"),
        ("TMP", r"C:\automata\temp"),
        ("PATHEXT", ".COM;.EXE;.BAT;.CMD"),
    ] {
        let variable = default_environment
            .values()
            .iter()
            .find(|variable| variable.name().as_str() == name)
            .unwrap_or_else(|| panic!("missing required Windows environment variable {name}"));
        assert_eq!(variable.value().expose(), value);
    }
    assert_eq!(
        config.executor().toolchain().cmd().expect("cmd").as_str(),
        r"C:\Windows\System32\cmd.exe"
    );
}

#[test]
fn windows_configuration_requires_one_provider_and_native_process_invariants() {
    let baseline = || {
        serde_json::from_slice::<serde_json::Value>(include_bytes!(
            "../config/runner.windows.example.json"
        ))
        .expect("checked-in Windows configuration JSON")
    };
    let parse = |value: &serde_json::Value| {
        let bytes = serde_json::to_vec(value).expect("serialize mutated configuration");
        RunnerProductConfig::from_json(&bytes)
    };

    let mut no_provider = baseline();
    no_provider
        .as_object_mut()
        .expect("configuration object")
        .remove("windows_native");
    assert_eq!(
        parse(&no_provider).expect_err("a provider is required"),
        RunnerProductConfigError::InvalidProvider
    );

    let linux = serde_json::from_slice::<serde_json::Value>(include_bytes!(
        "../config/runner.local-1.example.json"
    ))
    .expect("checked-in Linux configuration JSON");
    let mut two_providers = baseline();
    two_providers["podman"] = linux["podman"].clone();
    assert_eq!(
        parse(&two_providers).expect_err("multiple providers must fail closed"),
        RunnerProductConfigError::InvalidProvider
    );

    for (field, invalid_value) in [
        ("network", serde_json::json!("private_egress")),
        ("root_filesystem", serde_json::json!("writable")),
        ("privilege", serde_json::json!("administrator")),
        ("privilege", serde_json::json!("unprivileged")),
    ] {
        let mut value = baseline();
        value["executor"][field] = invalid_value;
        assert_eq!(
            parse(&value).expect_err("native host policy must remain explicit"),
            RunnerProductConfigError::InvalidExecutor
        );
    }

    let mut javascript_runtime = baseline();
    javascript_runtime["executor"]["toolchain"]["node20"] =
        serde_json::json!(r"C:\Program Files\nodejs\node.exe");
    assert_eq!(
        parse(&javascript_runtime).expect_err("JavaScript actions are not supported"),
        RunnerProductConfigError::InvalidExecutor
    );

    let mut configured_python = baseline();
    configured_python["executor"]["toolchain"]["python"] =
        serde_json::json!(r"C:\hostedtoolcache\windows\Python\3.13.0\x64\python.exe");
    let configured_python =
        parse(&configured_python).expect("configured Python is admitted and probed at startup");
    assert_eq!(
        configured_python
            .executor()
            .toolchain()
            .python()
            .expect("configured Python")
            .as_str(),
        r"C:\hostedtoolcache\windows\Python\3.13.0\x64\python.exe"
    );

    let mut packaged_shell = baseline();
    packaged_shell["executor"]["toolchain"]["pwsh"] =
        serde_json::json!(r"C:\Users\runner\AppData\Local\Microsoft\WindowsApps\pwsh.exe");
    assert_eq!(
        parse(&packaged_shell).expect_err("packaged shells cannot share the whole-job Job Object"),
        RunnerProductConfigError::InvalidExecutor
    );

    let mut parallel_native_jobs = baseline();
    parallel_native_jobs["inventory"]["max_parallel_jobs"] = serde_json::json!(2);
    assert_eq!(
        parse(&parallel_native_jobs)
            .expect_err("the static native workspace mapping is currently single-slot"),
        RunnerProductConfigError::InvalidInventory
    );

    let mut expanded_runner_root = baseline();
    expanded_runner_root["executor"]["runner_root"] =
        serde_json::json!(r"C:\automata\native\%RUNNER_ROOT%");
    assert_eq!(
        parse(&expanded_runner_root)
            .expect_err("cmd-expanding native runner roots must fail closed"),
        RunnerProductConfigError::InvalidExecutor
    );

    let mut expanded_workspace = baseline();
    expanded_workspace["inventory"]["environment_profiles"][0]["workspace"] =
        serde_json::json!(r"C:\automata\native\%WORKSPACE%");
    assert_eq!(
        parse(&expanded_workspace)
            .expect_err("cmd-expanding native workspace roots must fail closed"),
        RunnerProductConfigError::InvalidInventory
    );
}

#[test]
fn windows_configuration_requires_an_explicit_launch_environment() {
    let baseline = serde_json::from_slice::<serde_json::Value>(include_bytes!(
        "../config/runner.windows.example.json"
    ))
    .expect("checked-in Windows configuration JSON");
    let parse = |value: &serde_json::Value| {
        let bytes = serde_json::to_vec(value).expect("serialize mutated configuration");
        RunnerProductConfig::from_json(&bytes)
    };

    for required in ["SystemRoot", "WINDIR", "ComSpec", "TEMP", "TMP", "PATHEXT"] {
        let mut value = baseline.clone();
        value["inventory"]["environment_profiles"][0]["default_environment"]
            .as_object_mut()
            .expect("default environment object")
            .remove(required);
        assert_eq!(
            parse(&value).expect_err("cleared native launch environment must be complete"),
            RunnerProductConfigError::InvalidInventory,
            "missing {required}"
        );
    }

    for (name, value) in [
        (
            "ComSpec",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        ),
        ("TEMP", r"C:\different-temp"),
        ("TMP", r"C:\different-temp"),
        ("PATHEXT", ".COM;.EXE;.BAT"),
    ] {
        let mut config = baseline.clone();
        config["inventory"]["environment_profiles"][0]["default_environment"][name] =
            serde_json::json!(value);
        assert_eq!(
            parse(&config).expect_err("native launch environment must match executor policy"),
            RunnerProductConfigError::InvalidInventory,
            "invalid {name}"
        );
    }
}

#[test]
fn windows_state_roots_reject_case_aliases_and_non_disk_namespaces() {
    let baseline = serde_json::from_slice::<serde_json::Value>(include_bytes!(
        "../config/runner.windows.example.json"
    ))
    .expect("checked-in Windows configuration JSON");
    let parse = |value: &serde_json::Value| {
        let bytes = serde_json::to_vec(value).expect("serialize mutated configuration");
        RunnerProductConfig::from_json(&bytes)
    };

    let mut aliased = baseline.clone();
    aliased["state"]["journal"] = serde_json::json!(r"c:\AUTOMATA\STATE\SPOOL\journal-alias");
    assert_eq!(
        parse(&aliased).expect_err("case-insensitive root descendants overlap"),
        RunnerProductConfigError::InvalidStateRoots
    );

    for invalid in [
        r"\\server\share\automata\journal",
        r"\\?\C:\automata\state\journal",
        r"\\.\C:\automata\state\journal",
        r"C:\automata\state\CON",
    ] {
        let mut value = baseline.clone();
        value["state"]["journal"] = serde_json::json!(invalid);
        assert_eq!(
            parse(&value).expect_err("ambiguous Windows state path must fail closed"),
            RunnerProductConfigError::InvalidStateRoots,
            "invalid root {invalid}"
        );
    }

    for (section, field, invalid) in [
        ("executor", "runner_root", r"C:\outside-provider\runner"),
        ("inventory", "workspace", r"C:\outside-provider\workspaces"),
        (
            "inventory",
            "workspace",
            r"C:\automata\native\runner\nested-workspaces",
        ),
    ] {
        let mut value = baseline.clone();
        match section {
            "executor" => value[section][field] = serde_json::json!(invalid),
            "inventory" => {
                value[section]["environment_profiles"][0][field] = serde_json::json!(invalid);
            }
            _ => unreachable!(),
        }
        assert_eq!(
            parse(&value).expect_err("provider-owned roots require disjoint descendants"),
            RunnerProductConfigError::InvalidInventory,
            "invalid {field} {invalid}"
        );
    }
}
