#!/usr/bin/env python3
"""Validate and describe one service-aware cargo-llvm-cov report."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--lcov", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--lane", action="append", dest="lanes", required=True)
    parser.add_argument("--source-head", required=True)
    parser.add_argument("--source-content-digest", required=True)
    parser.add_argument("--source-state-token", required=True)
    parser.add_argument("--source-entry-count", required=True, type=int)
    return parser.parse_args()


def load_object_artifact(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"could not read {label} {path}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value, raw


def load_object(path: Path, label: str) -> dict[str, Any]:
    return load_object_artifact(path, label)[0]


def nonnegative_integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def normalize_source(filename: object, workspace_root: str) -> str:
    if not isinstance(filename, str) or not filename:
        raise ValueError("coverage filename must be a non-empty string")
    normalized = filename.replace("\\", "/")
    root = workspace_root.rstrip("/")
    if root and root != "." and normalized.startswith(f"{root}/"):
        normalized = normalized[len(root) + 1 :]
    elif PurePosixPath(normalized).is_absolute():
        raise ValueError(f"coverage source is outside workspace {workspace_root}: {filename}")
    if not normalized.startswith("crates/"):
        raise ValueError(f"coverage source is outside crates/: {filename}")
    path = PurePosixPath(normalized)
    if ".." in path.parts:
        raise ValueError(f"coverage source traverses its root: {filename}")
    nonproduction_directories = {"tests", "examples", "benches"}
    if nonproduction_directories.intersection(path.parts[2:]):
        raise ValueError(f"coverage summary contains nonproduction source: {filename}")
    basename = path.name
    if basename == "tests.rs" or basename.endswith(("_tests.rs", "-tests.rs")):
        raise ValueError(f"coverage summary contains nonproduction source: {filename}")
    return path.as_posix()


def load_lcov(
    path: Path,
    workspace_root: str,
    excluded_source_pattern: re.Pattern[str],
) -> tuple[dict[str, tuple[int, int]], str, int]:
    try:
        raw = path.read_bytes()
        lines = raw.decode("utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise ValueError(f"could not read LCOV report {path}: {error}") from error
    records: dict[str, tuple[int, int]] = {}
    source: str | None = None
    found: int | None = None
    hit: int | None = None
    data_lines: set[int] = set()
    for line_number, line in enumerate(lines, start=1):
        if line.startswith("SF:"):
            if source is not None:
                raise ValueError(f"LCOV line {line_number} starts a nested source record")
            source = normalize_source(line[3:], workspace_root)
            if excluded_source_pattern.search(f"/{source}"):
                raise ValueError(f"LCOV retained globally excluded source: {source}")
            if source in records:
                raise ValueError(f"LCOV source appears more than once: {source}")
            found = None
            hit = None
            data_lines = set()
        elif line.startswith("DA:"):
            if source is None:
                raise ValueError(f"LCOV line {line_number} has a DA field outside a source record")
            match = re.fullmatch(r"([1-9][0-9]*),([0-9]+)(?:,([^,\r\n]+))?", line[3:])
            if match is None:
                raise ValueError(f"LCOV line {line_number} has an invalid DA value")
            measured_line = int(match.group(1))
            if measured_line in data_lines:
                raise ValueError(
                    f"LCOV source has duplicate DA line {measured_line}: {source}"
                )
            data_lines.add(measured_line)
        elif line.startswith("LF:"):
            if source is None or found is not None:
                raise ValueError(f"LCOV line {line_number} has an invalid LF field")
            if not re.fullmatch(r"[0-9]+", line[3:]):
                raise ValueError(f"LCOV line {line_number} has an invalid LF value")
            found = int(line[3:])
        elif line.startswith("LH:"):
            if source is None or hit is not None:
                raise ValueError(f"LCOV line {line_number} has an invalid LH field")
            if not re.fullmatch(r"[0-9]+", line[3:]):
                raise ValueError(f"LCOV line {line_number} has an invalid LH value")
            hit = int(line[3:])
        elif line == "end_of_record":
            if source is None or found is None or hit is None:
                raise ValueError(f"LCOV line {line_number} ends an incomplete source record")
            if hit > found:
                raise ValueError(f"LCOV source covers more lines than it measures: {source}")
            if found > 0 and not data_lines:
                raise ValueError(f"LCOV source has positive LF but no DA records: {source}")
            records[source] = (hit, found)
            source = None
            found = None
            hit = None
    if source is not None:
        raise ValueError("LCOV report ends with an incomplete source record")
    if not records:
        raise ValueError("LCOV report contains no source records")
    return records, hashlib.sha256(raw).hexdigest(), len(raw)


def line_counts(files: list[dict[str, Any]]) -> tuple[int, int]:
    covered = 0
    measured = 0
    for index, file in enumerate(files):
        try:
            lines = file["summary"]["lines"]
            file_covered = nonnegative_integer(lines["covered"], f"files[{index}] covered lines")
            file_measured = nonnegative_integer(lines["count"], f"files[{index}] measured lines")
        except (KeyError, TypeError) as error:
            raise ValueError(f"files[{index}] has no line summary") from error
        if file_covered > file_measured:
            raise ValueError(f"files[{index}] covers more lines than it measures")
        covered += file_covered
        measured += file_measured
    return covered, measured


def percentage(covered: int, measured: int) -> float:
    return 0.0 if measured == 0 else covered * 100.0 / measured


def summarized(covered: int, measured: int, files: int) -> dict[str, int | float]:
    return {
        "files": files,
        "covered_lines": covered,
        "measured_lines": measured,
        "line_percent": percentage(covered, measured),
    }


def validate_prefix(prefix: object, lane: str) -> str:
    if not isinstance(prefix, str) or not prefix.startswith("crates/"):
        raise ValueError(f"{lane} source prefix must start with crates/")
    if ".." in PurePosixPath(prefix).parts:
        raise ValueError(f"{lane} source prefix traverses its root")
    return prefix


def source_matches(source: str, prefix: str) -> bool:
    if prefix.endswith("/"):
        return source.startswith(prefix)
    return source == prefix


def prefixes_overlap(first: str, second: str) -> bool:
    return (
        first == second
        or (first.endswith("/") and second.startswith(first))
        or (second.endswith("/") and first.startswith(second))
    )


def validate_reviewed_baseline(value: object) -> dict[str, int | float | str]:
    if not isinstance(value, dict):
        raise ValueError("ordinary reviewed baseline must be an object")
    covered = nonnegative_integer(value.get("covered_lines"), "baseline covered lines")
    measured = nonnegative_integer(value.get("measured_lines"), "baseline measured lines")
    if covered > measured:
        raise ValueError("baseline covers more lines than it measures")
    line_percent = value.get("line_percent")
    if (
        not isinstance(line_percent, (int, float))
        or isinstance(line_percent, bool)
        or not math.isfinite(line_percent)
        or not 0 <= line_percent <= 100
    ):
        raise ValueError("baseline line percent must be finite and between zero and 100")
    if not math.isclose(
        float(line_percent), percentage(covered, measured), rel_tol=0, abs_tol=1e-9
    ):
        raise ValueError("baseline line percent does not match its line counts")
    report_date = value.get("report_date")
    if not isinstance(report_date, str):
        raise ValueError("baseline report date must be an ISO date")
    try:
        dt.date.fromisoformat(report_date)
    except ValueError as error:
        raise ValueError("baseline report date must be an ISO date") from error
    return {
        "covered_lines": covered,
        "measured_lines": measured,
        "line_percent": float(line_percent),
        "report_date": report_date,
    }


def main() -> int:
    arguments = parse_arguments()
    try:
        arguments.manifest.unlink(missing_ok=True)
    except OSError as error:
        raise ValueError(f"could not clear coverage manifest {arguments.manifest}: {error}") from error
    policy = load_object(arguments.policy, "coverage policy")
    summary, summary_raw = load_object_artifact(arguments.summary, "coverage summary")
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", arguments.source_head):
        raise ValueError("coverage source HEAD must be a lowercase Git object ID")
    if not re.fullmatch(r"[0-9a-f]{64}", arguments.source_content_digest):
        raise ValueError("coverage source content digest must be a lowercase SHA-256 value")
    if not re.fullmatch(r"[0-9a-f]{64}", arguments.source_state_token):
        raise ValueError("coverage source state token must be a lowercase SHA-256 value")
    if arguments.source_entry_count < 0:
        raise ValueError("coverage source entry count must be non-negative")
    if policy.get("schema_version") != 1:
        raise ValueError("unsupported coverage policy schema")
    report_scope = policy.get("report_scope")
    if not isinstance(report_scope, dict):
        raise ValueError("coverage policy must describe its report scope")
    scope_description = report_scope.get("description")
    ignore_regex = report_scope.get("ignore_filename_regex")
    scope_exclusions = report_scope.get("exclusions")
    if not isinstance(scope_description, str) or not scope_description:
        raise ValueError("coverage report scope must have a description")
    if not isinstance(ignore_regex, str) or not ignore_regex or "\n" in ignore_regex:
        raise ValueError("coverage report scope must define one-line filename exclusions")
    try:
        excluded_source_pattern = re.compile(ignore_regex)
    except re.error as error:
        raise ValueError("coverage filename exclusions must be a valid regular expression") from error
    if not isinstance(scope_exclusions, list) or not scope_exclusions:
        raise ValueError("coverage report scope must inventory its exclusions")
    for exclusion in scope_exclusions:
        if (
            not isinstance(exclusion, dict)
            or not isinstance(exclusion.get("name"), str)
            or not exclusion["name"]
            or not isinstance(exclusion.get("description"), str)
            or not exclusion["description"]
        ):
            raise ValueError("coverage scope exclusions need names and descriptions")
    lane_policy = policy.get("lanes")
    if not isinstance(lane_policy, dict) or not lane_policy:
        raise ValueError("coverage policy must inventory lanes")
    if "ordinary" not in lane_policy:
        raise ValueError("coverage policy must define the ordinary lane")
    lanes = arguments.lanes
    if len(lanes) != len(set(lanes)):
        raise ValueError("coverage lanes must be unique")
    unknown = sorted(set(lanes) - set(lane_policy))
    if unknown:
        raise ValueError(f"unknown coverage lanes: {', '.join(unknown)}")

    tool = summary.get("cargo_llvm_cov")
    expected_tool = policy.get("cargo_llvm_cov_version")
    expected_export = policy.get("llvm_coverage_export_version")
    if not isinstance(expected_tool, str) or not expected_tool:
        raise ValueError("coverage policy must pin cargo-llvm-cov")
    if not isinstance(expected_export, str) or not expected_export:
        raise ValueError("coverage policy must pin the LLVM coverage export version")
    if summary.get("type") != "llvm.coverage.json.export":
        raise ValueError("coverage summary has the wrong LLVM export type")
    if summary.get("version") != expected_export:
        raise ValueError(f"coverage summary must use LLVM export version {expected_export}")
    if not isinstance(tool, dict) or tool.get("version") != expected_tool:
        raise ValueError(f"coverage summary must come from cargo-llvm-cov {expected_tool}")
    manifest_path = tool.get("manifest_path")
    normalized_manifest = (
        manifest_path.replace("\\", "/") if isinstance(manifest_path, str) else ""
    )
    if normalized_manifest != "Cargo.toml" and not normalized_manifest.endswith("/Cargo.toml"):
        raise ValueError("coverage summary must identify the workspace manifest")
    workspace_root = PurePosixPath(normalized_manifest).parent.as_posix()
    data = summary.get("data")
    if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
        raise ValueError("coverage summary must contain exactly one data object")
    raw_files = data[0].get("files")
    if not isinstance(raw_files, list) or not raw_files:
        raise ValueError("coverage summary contains no source files")

    files: list[dict[str, Any]] = []
    seen_sources: set[str] = set()
    for raw_file in raw_files:
        if not isinstance(raw_file, dict):
            raise ValueError("coverage file entry must be an object")
        source = normalize_source(raw_file.get("filename"), workspace_root)
        if excluded_source_pattern.search(f"/{source}"):
            raise ValueError(f"coverage summary retained globally excluded source: {source}")
        if source in seen_sources:
            raise ValueError(f"coverage source appears more than once: {source}")
        seen_sources.add(source)
        files.append({"source": source, "summary": raw_file.get("summary")})

    all_covered, all_measured = line_counts(files)
    json_line_counts = {
        file["source"]: line_counts([file])
        for file in files
    }
    lcov_line_counts, lcov_sha256, lcov_size = load_lcov(
        arguments.lcov, workspace_root, excluded_source_pattern
    )
    json_sources = set(json_line_counts)
    lcov_sources = set(lcov_line_counts)
    if json_sources != lcov_sources:
        missing = sorted(json_sources - lcov_sources)
        extra = sorted(lcov_sources - json_sources)
        details = []
        if missing:
            details.append(f"missing {', '.join(missing[:3])}")
        if extra:
            details.append(f"extra {', '.join(extra[:3])}")
        raise ValueError(f"LCOV and JSON source sets differ ({'; '.join(details)})")
    for source in sorted(json_sources):
        if lcov_line_counts[source] != json_line_counts[source]:
            raise ValueError(f"LCOV and JSON line totals differ for {source}")
    lcov_covered = sum(covered for covered, _ in lcov_line_counts.values())
    lcov_measured = sum(measured for _, measured in lcov_line_counts.values())
    if (lcov_covered, lcov_measured) != (all_covered, all_measured):
        raise ValueError("LCOV and JSON aggregate line totals differ")
    total_summary = data[0].get("totals")
    if not isinstance(total_summary, dict):
        raise ValueError("coverage summary totals must be an object")
    total_lines = total_summary.get("lines")
    if not isinstance(total_lines, dict):
        raise ValueError("coverage summary total lines must be an object")
    if (
        nonnegative_integer(total_lines.get("covered"), "total covered lines") != all_covered
        or nonnegative_integer(total_lines.get("count"), "total measured lines") != all_measured
    ):
        raise ValueError("coverage file totals do not match aggregate totals")

    external_prefixes: list[str] = []
    external_by_lane: dict[str, list[str]] = {}
    requirements_by_lane: dict[str, list[str]] = {}
    owned_prefixes: list[tuple[str, str]] = []
    for lane, configuration in lane_policy.items():
        if not isinstance(configuration, dict):
            raise ValueError(f"{lane} lane policy must be an object")
        description = configuration.get("description")
        requirements = configuration.get("service_requirements")
        if not isinstance(description, str) or not description:
            raise ValueError(f"{lane} lane policy must have a description")
        if (
            not isinstance(requirements, list)
            or any(
                not isinstance(requirement, str) or not requirement
                for requirement in requirements
            )
            or len(requirements) != len(set(requirements))
        ):
            raise ValueError(f"{lane} lane policy must list unique service requirements")
        requirements_by_lane[lane] = requirements
        prefixes = configuration.get("source_prefixes")
        if not isinstance(prefixes, list):
            raise ValueError(f"{lane} lane policy must list source prefixes")
        validated = [validate_prefix(prefix, lane) for prefix in prefixes]
        if len(validated) != len(set(validated)):
            raise ValueError(f"{lane} lane policy repeats a source prefix")
        if lane == "ordinary" and validated:
            raise ValueError("ordinary lane cannot own externally excluded source")
        external_by_lane[lane] = validated
        if lane != "ordinary":
            for prefix in validated:
                for existing_lane, existing_prefix in owned_prefixes:
                    if prefixes_overlap(prefix, existing_prefix):
                        raise ValueError(
                            f"source ownership overlaps between {existing_lane} and {lane}"
                        )
                owned_prefixes.append((lane, prefix))
            external_prefixes.extend(validated)

    def is_external(source: str) -> bool:
        return any(source_matches(source, prefix) for prefix in external_prefixes)

    ordinary_files = [file for file in files if not is_external(file["source"])]
    ordinary_covered, ordinary_measured = line_counts(ordinary_files)
    guard_policy = policy.get("ordinary_guard")
    if not isinstance(guard_policy, dict):
        raise ValueError("coverage policy must define the ordinary guard")
    floor = guard_policy.get("line_percent_floor")
    minimum_measured = guard_policy.get("minimum_measured_lines")
    if not isinstance(floor, (int, float)) or isinstance(floor, bool) or not 0 <= floor <= 100:
        raise ValueError("ordinary line floor must be between zero and 100")
    minimum_measured = nonnegative_integer(minimum_measured, "ordinary minimum measured lines")
    reviewed_baseline = validate_reviewed_baseline(guard_policy.get("reviewed_baseline"))
    if reviewed_baseline["line_percent"] < float(floor):
        raise ValueError("ordinary floor exceeds its reviewed baseline")
    if reviewed_baseline["measured_lines"] < minimum_measured:
        raise ValueError("ordinary minimum measured lines exceed the reviewed baseline")

    guard_applies = lanes == ["ordinary"]
    if guard_applies:
        for lane, prefixes in external_by_lane.items():
            for prefix in prefixes:
                if not any(source_matches(file["source"], prefix) for file in files):
                    raise ValueError(f"{lane} source prefix matched no ordinary report file")
    ordinary_percent = percentage(ordinary_covered, ordinary_measured)
    guard_passed = ordinary_percent >= float(floor) and ordinary_measured >= minimum_measured
    if guard_applies:
        guard_status = "passed" if guard_passed else "failed"
    else:
        guard_status = "report-only"

    excluded_reports: dict[str, dict[str, int | float]] = {}
    for lane, prefixes in external_by_lane.items():
        if lane == "ordinary" or not prefixes:
            continue
        lane_files = [
            file
            for file in files
            if any(
                source_matches(file["source"], prefix) for prefix in prefixes
            )
        ]
        covered, measured = line_counts(lane_files)
        excluded_reports[lane] = summarized(covered, measured, len(lane_files))

    manifest = {
        "schema_version": 1,
        "cargo_llvm_cov_version": expected_tool,
        "source_snapshot": {
            "content_algorithm": "sha256-framed-git-head-and-nonignored-worktree-content-v1",
            "content_scope": "Git HEAD plus tracked and unignored working-tree paths, types, modes, and contents",
            "state_token_algorithm": "sha256-framed-git-head-and-nonignored-worktree-state-v1",
            "state_token_scope": "Content scope plus working-tree modification and change timestamps",
            "head": arguments.source_head,
            "content_sha256": arguments.source_content_digest,
            "state_token_sha256": arguments.source_state_token,
            "paths": arguments.source_entry_count,
        },
        "artifacts": {
            "summary_json": {
                "sha256": hashlib.sha256(summary_raw).hexdigest(),
                "bytes": len(summary_raw),
            },
            "lcov": {
                "sha256": lcov_sha256,
                "bytes": lcov_size,
            },
        },
        "test_bundles": {
            "requested": lanes,
            "not_requested": [lane for lane in lane_policy if lane not in lanes],
            "profiles_merged": len(lanes) > 1,
            "service_requirements": {
                lane: requirements_by_lane[lane] for lane in lanes
            },
        },
        "report": {
            "scope": report_scope,
            "in_scope_compiled_source": summarized(all_covered, all_measured, len(files)),
            "ordinary_owned_source": summarized(
                ordinary_covered, ordinary_measured, len(ordinary_files)
            ),
            "service_owned_source": excluded_reports,
        },
        "guard": {
            "status": guard_status,
            "scope": "ordinary-owned source after explicit service-owned exclusions",
            "line_percent_floor": float(floor),
            "minimum_measured_lines": minimum_measured,
            "reviewed_baseline": reviewed_baseline,
        },
    }
    arguments.manifest.parent.mkdir(parents=True, exist_ok=True)
    arguments.manifest.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        f"Rust coverage bundles={','.join(lanes)} "
        f"in-scope={percentage(all_covered, all_measured):.2f}% "
        f"ordinary-owned={ordinary_percent:.2f}% guard={guard_status}"
    )
    if guard_applies and not guard_passed:
        print(
            f"ordinary coverage requires >= {float(floor):.2f}% across at least "
            f"{minimum_measured} measured lines",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2) from error
