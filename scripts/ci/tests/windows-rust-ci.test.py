#!/usr/bin/env python3
"""Fail closed when CI loses the native Windows sandbox/runner lane."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".ci" / "workflows" / "ci.yml"
PULL_REQUEST_WORKFLOW = ROOT / ".ci" / "workflows" / "pull-request.yml"
CHECKOUT_ACTION = (
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"
)
CACHE_ACTION = (
    "actions/cache@27d5ce7f107fe9357f9df03efb73ab90386fccae # v5.0.5"
)
TARGET = "x86_64-pc-windows-msvc"


def job_body(workflow: str, job: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job)}:\n(?P<body>.*?)(?=^  [a-z][a-z0-9_]*:\n|\Z)",
        workflow,
    )
    if match is None:
        raise AssertionError(f"missing CI job: {job}")
    return match.group("body")


def step_body(job: str, step: str) -> str:
    match = re.search(
        rf"(?ms)^      - name: {re.escape(step)}\n"
        rf"(?P<body>.*?)(?=^      - name: |\Z)",
        job,
    )
    if match is None:
        raise AssertionError(f"missing Windows CI step: {step}")
    return match.group("body")


def command(body: str) -> str:
    return " ".join(body.split())


def main() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    windows = job_body(workflow, "windows")
    assert "name: Windows sandbox and runner boundary" in windows
    assert "runs-on: windows-2025" in windows
    assert "shell: pwsh" in windows
    assert 'CARGO_BUILD_JOBS: "1"' in windows
    assert "continue-on-error:" not in windows
    assert CHECKOUT_ACTION in windows
    assert "persist-credentials: false" in windows
    assert CACHE_ACTION in windows
    assert "cargo-windows-2025-msvc-rust-1.97.1-" in windows

    toolchain = step_body(windows, "Show pinned Windows MSVC toolchain")
    assert f"if ($rustHostTriple -ne '{TARGET}')" in toolchain

    compile_step = command(
        step_body(windows, "Compile Windows sandbox and runner boundary")
    )
    for required in (
        "cargo check",
        "--locked",
        "-p automata-ci-sandbox-windows",
        "-p automata-ci-runner",
        "--all-targets",
        "--all-features",
        f"--target {TARGET}",
    ):
        assert required in compile_step, f"Windows compilation lost {required}"

    lint = command(
        step_body(windows, "Lint Windows sandbox and runner boundary")
    )
    for required in (
        "cargo clippy",
        "--locked",
        "-p automata-ci-sandbox-windows",
        "-p automata-ci-runner",
        "--all-targets",
        "--all-features",
        f"--target {TARGET}",
        "--no-deps",
        "-- -D warnings",
    ):
        assert required in lint, f"Windows Clippy lost {required}"
    assert " -A " not in f" {lint} "
    assert "--cap-lints allow" not in lint

    sandbox_tests = command(step_body(windows, "Test Windows sandbox boundary"))
    for required in (
        "cargo test",
        "--locked",
        "-p automata-ci-sandbox-windows",
        "--all-targets",
        "--all-features",
        f"--target {TARGET}",
    ):
        assert required in sandbox_tests, f"Windows sandbox tests lost {required}"

    runner_tests = command(step_body(windows, "Test Windows runner boundary"))
    assert runner_tests.count("cargo test --locked") == 2
    assert runner_tests.count("-p automata-ci-runner") == 2
    assert runner_tests.count(f"--target {TARGET}") == 2
    assert f"--lib ` --target {TARGET} ` windows_tests" in runner_tests
    assert (
        f"--test runner ` --target {TARGET} ` "
        "'runner_product_config_windows::'"
    ) in runner_tests

    pull_request_workflow = PULL_REQUEST_WORKFLOW.read_text(encoding="utf-8")
    pull_request_checks = job_body(pull_request_workflow, "critical_rust")
    assert "python3 scripts/ci/tests/windows-rust-ci.test.py" in pull_request_checks
    assert "python3 scripts/ci/tests/windows-image-pipeline.test.py" in pull_request_checks
    pull_request_windows = job_body(pull_request_workflow, "windows")
    assert pull_request_windows.strip() == windows.strip(), (
        "pull-request Windows sandbox/runner lane must match the protected main lane"
    )

    distribution = job_body(workflow, "dist")
    assert "- windows" in distribution
    assert "WINDOWS_RESULT: ${{ needs.windows.result }}" in distribution
    assert '[[ "$WINDOWS_RESULT" == success ]]' in distribution
    print(
        "verified native Windows sandbox/runner compilation, strict lint, tests, PR coverage, "
        "and release gate"
    )


if __name__ == "__main__":
    main()
