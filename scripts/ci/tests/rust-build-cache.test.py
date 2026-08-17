#!/usr/bin/env python3
"""Fail closed when CI loses the shared Rust build-cache contract."""

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
    "rust",
    "postgres",
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
    assert workflow.count("SCCACHE_BASEDIRS: ${{ github.workspace }}") == 1, (
        "sccache must normalize each ephemeral checkout to a stable source path"
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
        assert "/opt/cargo/registry/cache" in body
        assert "/opt/cargo/registry/index" in body
        assert "/opt/cargo/registry/src" in body
        assert "target/" not in "\n".join(
            line.strip()
            for line in body.splitlines()
            if line.strip().startswith("/opt/cargo/")
        )

    for job in RUST_JOBS:
        assert (
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS: "
            "-C link-arg=-fuse-ld=lld"
        ) in job_body(workflow, job), f"{job} lost the fast GNU/Linux linker"

    service_images = re.findall(r"(?m)^\s+image: (?P<image>\S+)$", workflow)
    assert service_images, "CI must retain its service-container coverage"
    for image in service_images:
        if image.startswith("${{"):
            continue
        name, separator, digest = image.partition("@sha256:")
        assert separator and re.fullmatch(r"[0-9a-f]{64}", digest), (
            f"service image is not pinned by a canonical SHA-256 digest: {image}"
        )
        assert ":" not in name.rsplit("/", 1)[-1], (
            f"service image must use canonical name@digest identity without a tag: {image}"
        )
    print("verified Rust jobs and shared compiler caches")


if __name__ == "__main__":
    main()
