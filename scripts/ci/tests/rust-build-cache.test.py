#!/usr/bin/env python3
"""Fail closed when CI loses the bounded Rust build-cache contract."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".." / ".ci" / "workflows" / "ci.yml"
SCCACHE_ACTION = (
    "mozilla-actions/sccache-action@"
    "fc920bf0ec8de6ee65d409111f7ec508035751ba # v0.0.11"
)
CACHE_ACTION = (
    "actions/cache@27d5ce7f107fe9357f9df03efb73ab90386fccae # v5.0.5"
)
SCRATCH_PREPARATION = 'run: install -d -m 0700 -- "$TMPDIR"'
SHORT_ABSTRACT_SOCKET = "SCCACHE_SERVER_UDS: '\\x00automata-sccache'"
SHORT_STARTUP = "run: env TMPDIR=/tmp sccache --start-server"
RUST_JOBS = (
    "verify",
    "rust_lint",
    "rust_docs",
    "dependency_audit",
    "rust_coverage",
    "renderer_tests",
    "dist_build",
)


def job_body(workflow: str, job: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job)}:\n(?P<body>.*?)(?=^  [a-z][a-z0-9_]*:\n|\Z)",
        workflow,
    )
    if match is None:
        raise AssertionError(f"missing CI job: {job}")
    return match.group("body")


def main() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert workflow.count(SHORT_ABSTRACT_SOCKET) == 1, (
        "sccache must use one short abstract socket independent of workspace depth"
    )
    assert workflow.count('SCCACHE_IDLE_TIMEOUT: "0"') == 1, (
        "the job-scoped sccache server must survive until post-job statistics"
    )
    for job in RUST_JOBS:
        body = job_body(workflow, job)
        assert "RUSTC_WRAPPER: sccache" in body, f"{job} lost the rustc wrapper"
        assert "SCCACHE_GHA_ENABLED: \"true\"" in body, (
            f"{job} lost the repository compiler-cache backend"
        )
        assert SCCACHE_ACTION in body, f"{job} lost the pinned sccache installer"
        assert "version: v0.17.0" in body, f"{job} changed the sccache binary"
        assert body.count(SCRATCH_PREPARATION) == 1, (
            f"{job} must prepare its private scratch directory exactly once"
        )
        assert body.index(SCRATCH_PREPARATION) < body.index(SCCACHE_ACTION), (
            f"{job} must prepare its scratch directory before sccache starts"
        )
        assert body.count(SHORT_STARTUP) == 1, (
            f"{job} must start sccache once with a path-length-safe notifier"
        )
        assert body.index(SCCACHE_ACTION) < body.index(SHORT_STARTUP), (
            f"{job} must install sccache before starting it"
        )
        assert CACHE_ACTION in body, f"{job} lost the pinned Cargo cache action"
        assert body.index(SHORT_STARTUP) < body.index(CACHE_ACTION), (
            f"{job} must start sccache before restoring build inputs"
        )
        assert "~/.cargo/registry/cache" in body
        assert "~/.cargo/registry/index" in body
        assert "~/.cargo/registry/src" in body
        assert "target/" not in "\n".join(
            line.strip()
            for line in body.splitlines()
            if line.strip().startswith("~/.cargo/")
        )

    for job in ("verify", "rust_lint", "rust_docs", "rust_coverage", "renderer_tests"):
        assert (
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS: "
            "-C link-arg=-fuse-ld=lld"
        ) in job_body(workflow, job), f"{job} lost the fast GNU/Linux linker"

    distribution = job_body(workflow, "dist")
    for gate in ("rust_lint", "rust_docs", "dependency_audit"):
        assert f"- {gate}" in distribution, f"distribution no longer requires {gate}"
    assert "cargo-deny --version 0.20.2" in workflow
    assert "cargo-llvm-cov --version 0.8.7" in workflow
    assert "cargo-cyclonedx --version 0.5.9" in workflow
    print("verified parallel Rust gates and bounded shared compiler caches")


if __name__ == "__main__":
    main()
