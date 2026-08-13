#!/usr/bin/env python3
"""Mutation tests for the fail-closed GitHub Actions capability registry."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/ci/verify-github-actions-capabilities.py"
REGISTRY = ROOT / "docs/governance/github-actions-capabilities-v1.json"


class CapabilityRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = json.loads(REGISTRY.read_text(encoding="utf-8"))

    def verify(self, registry: Path = REGISTRY) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--repository-root",
                str(ROOT),
                "--registry",
                str(registry),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def reject(self, mutate: Callable[[dict[str, Any]], None], expected: str) -> None:
        value = copy.deepcopy(self.registry)
        mutate(value)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.json"
            path.write_text(
                json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            result = self.verify(path)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(expected, result.stderr)

    def test_checked_in_registry_is_valid(self) -> None:
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_decoder_field_without_registry_entry_is_rejected(self) -> None:
        self.reject(
            lambda value: value["decoder_inventory"][0]["fields"].pop("args"),
            "decoder coverage drifted",
        )

    def test_compatibility_claim_without_attributed_acceptance_is_rejected(self) -> None:
        self.reject(
            lambda value: value["features"][0]["acceptance"].update(
                {"function": "not_a_real_test"}
            ),
            "must bind exactly one attributed Rust test",
        )

    def test_compatibility_status_drift_is_rejected(self) -> None:
        self.reject(
            lambda value: value["features"][0].update({"status": "Experimental"}),
            "compatibility linkage drifted",
        )

    def test_stage_cannot_disappear_from_a_profile(self) -> None:
        self.reject(
            lambda value: value["stage_profiles"]["source-component"].pop("results"),
            "must contain exactly",
        )

    def test_decoder_mapping_to_unknown_feature_is_rejected(self) -> None:
        self.reject(
            lambda value: value["decoder_inventory"][0]["fields"].update(
                {"args": "unregistered-feature"}
            ),
            "references unknown features",
        )


if __name__ == "__main__":
    unittest.main()
