#!/usr/bin/env python3
"""Verify that release publication remains native to Automata."""

from __future__ import annotations

import pathlib


ROOT = pathlib.Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".ci/workflows/release.yml"

github_workflows = ROOT / ".github/workflows"
if github_workflows.exists() and any(github_workflows.glob("*.y*ml")):
    raise SystemExit("release-native-test: GitHub Actions workflows are forbidden")

source = WORKFLOW.read_text(encoding="utf-8")
required = (
    "name: Release\n",
    'tags:\n      - "v*"',
    "python3 scripts/ci/verify-release-authority.py",
    "check_name=Automata CI / required",
    "AUTOMATA_SCRATCH_RUNTIME=none",
    "AUTOMATA_SERVICE_PROXY_OCI_BUILDER: buildah-chroot",
    "AUTOMATA_SERVICE_PROXY_PROCESS_PROBE: metadata-only",
    "CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}",
    "run: docker buildx inspect --bootstrap",
)
for value in required:
    if value not in source:
        raise SystemExit(f"release-native-test: missing native release contract: {value}")

forbidden = (
    "environment:",
    "id-token:",
    "actions/attest@",
    "gh attestation",
    "rust-lang/crates-io-auth-action@",
    "actions/setup-node@",
    "cargo install cargo-cyclonedx",
    "AUTOMATA_SCRATCH_RUNTIME=docker",
    "AUTOMATA_SCRATCH_RUNTIME=podman",
    "verify-service-proxy-candidate-load.py",
)
for value in forbidden:
    if value in source:
        raise SystemExit(f"release-native-test: forbidden release dependency: {value}")

print("native Automata release workflow contract verified")
