#!/usr/bin/env python3
"""Independently validate a publishable failed Rust coverage guard manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from pathlib import Path
from typing import Any


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--lcov", required=True, type=Path)
    parser.add_argument("--lane", action="append", dest="lanes", required=True)
    parser.add_argument("--source-head", required=True)
    parser.add_argument("--source-content-digest", required=True)
    parser.add_argument("--source-state-token", required=True)
    parser.add_argument("--source-entry-count", required=True, type=int)
    return parser.parse_args()


def object_field(value: object, field: str, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    nested = value.get(field)
    if not isinstance(nested, dict):
        raise ValueError(f"{label}.{field} must be an object")
    return nested


def nonnegative_integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def metric(value: object, label: str) -> None:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    files = nonnegative_integer(value.get("files"), f"{label}.files")
    covered = nonnegative_integer(value.get("covered_lines"), f"{label}.covered_lines")
    measured = nonnegative_integer(value.get("measured_lines"), f"{label}.measured_lines")
    percent = value.get("line_percent")
    if (
        not isinstance(percent, (int, float))
        or isinstance(percent, bool)
        or not math.isfinite(percent)
        or not 0 <= percent <= 100
    ):
        raise ValueError(f"{label}.line_percent must be finite and between zero and 100")
    expected_percent = 0.0 if measured == 0 else covered * 100.0 / measured
    if covered > measured or not math.isclose(
        float(percent), expected_percent, rel_tol=0, abs_tol=1e-9
    ):
        raise ValueError(f"{label} has inconsistent counts")


def reviewed_baseline(value: object) -> None:
    if not isinstance(value, dict):
        raise ValueError("failed-guard manifest reviewed baseline must be an object")
    covered = nonnegative_integer(
        value.get("covered_lines"), "reviewed baseline covered lines"
    )
    measured = nonnegative_integer(
        value.get("measured_lines"), "reviewed baseline measured lines"
    )
    percent = value.get("line_percent")
    if (
        covered > measured
        or not isinstance(percent, (int, float))
        or isinstance(percent, bool)
        or not math.isfinite(percent)
        or not math.isclose(
            float(percent),
            0.0 if measured == 0 else covered * 100.0 / measured,
            rel_tol=0,
            abs_tol=1e-9,
        )
        or not isinstance(value.get("report_date"), str)
        or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value["report_date"])
    ):
        raise ValueError("failed-guard manifest has an invalid reviewed baseline")


def validate_artifact(value: object, path: Path, label: str) -> None:
    if not isinstance(value, dict):
        raise ValueError(f"{label} artifact metadata must be an object")
    digest = value.get("sha256")
    size = nonnegative_integer(value.get("bytes"), f"{label} artifact bytes")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError(f"{label} artifact digest must be a lowercase SHA-256 value")
    raw = path.read_bytes()
    if size != len(raw) or digest != hashlib.sha256(raw).hexdigest():
        raise ValueError(f"{label} artifact metadata does not match its report")


def main() -> int:
    arguments = parse_arguments()
    try:
        manifest = json.loads(arguments.manifest.read_bytes())
    except json.JSONDecodeError as error:
        raise ValueError(f"failed-guard manifest is not valid JSON: {error}") from error
    if not isinstance(manifest, dict):
        raise ValueError("failed-guard manifest must be an object")
    required = {
        "schema_version",
        "cargo_llvm_cov_version",
        "source_snapshot",
        "artifacts",
        "test_bundles",
        "report",
        "guard",
    }
    if not required.issubset(manifest):
        raise ValueError("failed-guard manifest is incomplete")
    if manifest["schema_version"] != 1 or manifest["cargo_llvm_cov_version"] != "0.8.7":
        raise ValueError("failed-guard manifest has the wrong schema or coverage tool")

    source = object_field(manifest, "source_snapshot", "manifest")
    expected_source = {
        "head": arguments.source_head,
        "content_sha256": arguments.source_content_digest,
        "state_token_sha256": arguments.source_state_token,
        "paths": arguments.source_entry_count,
    }
    if any(source.get(field) != value for field, value in expected_source.items()):
        raise ValueError("failed-guard manifest does not bind the collected source snapshot")
    for field in [
        "content_algorithm",
        "content_scope",
        "state_token_algorithm",
        "state_token_scope",
    ]:
        if not isinstance(source.get(field), str) or not source[field]:
            raise ValueError(f"failed-guard manifest source_snapshot.{field} is missing")

    artifacts = object_field(manifest, "artifacts", "manifest")
    validate_artifact(artifacts.get("summary_json"), arguments.summary, "summary JSON")
    validate_artifact(artifacts.get("lcov"), arguments.lcov, "LCOV")

    bundles = object_field(manifest, "test_bundles", "manifest")
    if arguments.lanes != ["ordinary"]:
        raise ValueError("a failed coverage guard is only valid for the ordinary bundle")
    if bundles.get("requested") != arguments.lanes:
        raise ValueError("failed-guard manifest names the wrong requested bundles")
    not_requested = bundles.get("not_requested")
    requirements = bundles.get("service_requirements")
    if (
        not isinstance(not_requested, list)
        or any(not isinstance(lane, str) or not lane for lane in not_requested)
        or len(not_requested) != len(set(not_requested))
        or set(not_requested).intersection(arguments.lanes)
        or bundles.get("profiles_merged") is not False
        or not isinstance(requirements, dict)
        or set(requirements) != set(arguments.lanes)
        or any(
            not isinstance(value, list)
            or any(not isinstance(requirement, str) or not requirement for requirement in value)
            for value in requirements.values()
        )
    ):
        raise ValueError("failed-guard manifest has incomplete test-bundle provenance")

    report = object_field(manifest, "report", "manifest")
    if not isinstance(report.get("scope"), dict):
        raise ValueError("failed-guard manifest report scope is missing")
    metric(report.get("in_scope_compiled_source"), "in-scope report")
    metric(report.get("ordinary_owned_source"), "ordinary-owned report")
    service_owned = report.get("service_owned_source")
    if not isinstance(service_owned, dict):
        raise ValueError("failed-guard manifest service-owned report must be an object")
    for lane, value in service_owned.items():
        if not isinstance(lane, str) or not lane:
            raise ValueError("failed-guard manifest has an invalid service-owned bundle")
        metric(value, f"service-owned report {lane}")

    guard = object_field(manifest, "guard", "manifest")
    if guard.get("status") != "failed":
        raise ValueError("failed-guard manifest status must be exactly failed")
    if (
        not isinstance(guard.get("scope"), str)
        or not guard["scope"]
        or not isinstance(guard.get("line_percent_floor"), (int, float))
        or isinstance(guard.get("line_percent_floor"), bool)
        or not 0 <= guard["line_percent_floor"] <= 100
        or nonnegative_integer(
            guard.get("minimum_measured_lines"), "guard minimum measured lines"
        )
        < 1
    ):
        raise ValueError("failed-guard manifest has incomplete guard policy")
    reviewed_baseline(guard.get("reviewed_baseline"))
    ordinary = report["ordinary_owned_source"]
    if (
        ordinary["line_percent"] >= guard["line_percent_floor"]
        and ordinary["measured_lines"] >= guard["minimum_measured_lines"]
    ):
        raise ValueError("failed-guard manifest does not describe a coverage regression")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2) from error
