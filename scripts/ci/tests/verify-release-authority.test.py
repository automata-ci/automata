#!/usr/bin/env python3
"""Black-box tests for the public-release authority verifier."""

from __future__ import annotations

import copy
import json
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[3]
VERIFIER = ROOT / "scripts/ci/verify-release-authority.py"
COMMIT = "1" * 40


def documents() -> tuple[dict, dict]:
    comparison = {
        "status": "ahead",
        "merge_base_commit": {"sha": COMMIT},
    }
    checks = {
        "total_count": 1,
        "check_runs": [
            {
                "name": "Automata CI / required",
                "head_sha": COMMIT,
                "status": "completed",
                "conclusion": "success",
                "external_id": "automata-check:12345678-1234-4abc-8def-123456789abc",
                "details_url": (
                    "https://ci.automata-ci.com/automata-ci/automata/actions/"
                    "runs/12345678-1234-4abc-8def-123456789abc"
                ),
                "check_suite": {"id": 17},
                "app": {
                    "id": 4558711,
                    "slug": "automata-ci",
                    "owner": {"login": "automata-ci", "type": "Organization"},
                },
            }
        ],
    }
    return comparison, checks


def run(comparison: dict, checks: dict) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        comparison_path = root / "comparison.json"
        checks_path = root / "checks.json"
        comparison_path.write_text(json.dumps(comparison), encoding="utf-8")
        checks_path.write_text(json.dumps(checks), encoding="utf-8")
        return subprocess.run(
            [
                "python3",
                str(VERIFIER),
                "--commit",
                COMMIT,
                "--comparison",
                str(comparison_path),
                "--checks",
                str(checks_path),
            ],
            check=False,
            capture_output=True,
            text=True,
        )


def rejected(comparison: dict, checks: dict, message: str) -> None:
    result = run(comparison, checks)
    if result.returncode == 0 or message not in result.stderr:
        raise AssertionError(
            f"expected rejection containing {message!r}: "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )


comparison, checks = documents()
accepted = run(comparison, checks)
if accepted.returncode != 0:
    raise AssertionError(accepted.stderr)

for status in ("behind", "diverged"):
    changed = copy.deepcopy(comparison)
    changed["status"] = status
    rejected(changed, checks, "not an ancestor")

changed = copy.deepcopy(comparison)
changed["merge_base_commit"]["sha"] = "2" * 40
rejected(changed, checks, "main merge base")

for field, value, message in (
    ("name", "Automata CI", "identity does not match"),
    ("head_sha", "2" * 40, "identity does not match"),
    ("status", "in_progress", "did not complete successfully"),
    ("conclusion", "failure", "did not complete successfully"),
    ("external_id", "caller-controlled", "external identity is invalid"),
    ("details_url", "https://example.com/run/17", "origin is not trusted"),
):
    changed = copy.deepcopy(checks)
    changed["check_runs"][0][field] = value
    rejected(comparison, changed, message)

for field, value in (("id", 1), ("slug", "other")):
    changed = copy.deepcopy(checks)
    changed["check_runs"][0]["app"][field] = value
    rejected(comparison, changed, "trusted Automata App")

changed = copy.deepcopy(checks)
changed["check_runs"].append(copy.deepcopy(changed["check_runs"][0]))
rejected(comparison, changed, "one latest required Automata Check")

print("release authority verifier contract verified")
