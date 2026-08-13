#!/usr/bin/env python3
"""Fail closed on GitHub Actions capability, compatibility, and reference drift."""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REGISTRY = Path("docs/governance/github-actions-capabilities-v1.json")
STAGES = {
    "admission",
    "compile",
    "decode",
    "differential",
    "kubernetes",
    "linux",
    "projection",
    "publication",
    "results",
    "scheduler",
    "windows",
}
STAGE_STATUSES = {
    "available",
    "component",
    "not-applicable",
    "partial",
    "rejected",
    "unverified",
}
COMPATIBILITY_STATUSES = {
    "Component complete",
    "Experimental",
    "Partial",
    "Unsupported",
}
EVALUATION_PHASES = {
    "admission",
    "compile",
    "job-activation",
    "job-execution",
    "job-finalization",
    "publication",
    "runner-admission",
    "scheduler",
}
REFERENCE_CATEGORIES = {
    "action_runtimes",
    "contexts",
    "default_variables",
    "events",
    "limits",
    "permissions",
    "syntax",
    "variables",
}
REVIEW_DECISIONS = {
    "approved-baseline",
    "approved-delta-without-baseline-advance",
}
CAPABILITY = re.compile(
    r"^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*/"
    r"[a-z][a-z0-9-]*@v[1-9][0-9]*$"
)
IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GITHUB_OWNER = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
GITHUB_REPOSITORY = r"[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?"
GITHUB_REVISION = rf"{GITHUB_OWNER}/{GITHUB_REPOSITORY}@[0-9a-f]{{40}}"
GITHUB_SOURCE_REVISIONS = re.compile(rf"^{GITHUB_REVISION}(?:\+{GITHUB_REVISION})*$")
TEST_ATTRIBUTE = re.compile(r"#\[\s*(?:[A-Za-z_][A-Za-z0-9_]*::)*test(?:\([^]]*\))?\s*\]")


class CapabilityError(ValueError):
    """The checked-in capability contract is malformed or incomplete."""


def fail(message: str) -> None:
    raise CapabilityError(message)


def load_canonical(path: Path) -> Any:
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        fail(f"cannot read {path}: {error}")

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                fail(f"{path} contains duplicate key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(source, object_pairs_hook=no_duplicates)
    except (json.JSONDecodeError, UnicodeError) as error:
        fail(f"{path} is not UTF-8 JSON: {error}")
    expected = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if source.replace("\r\n", "\n") != expected:
        fail(f"{path} is not canonical sorted JSON")
    return value


def exact_object(value: Any, keys: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{context} must contain exactly {sorted(keys)}")
    return value


def string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        fail(f"{context} must be a non-empty trimmed string")
    return value


def array(value: Any, context: str, *, nonempty: bool = False) -> list[Any]:
    if not isinstance(value, list) or (nonempty and not value):
        fail(f"{context} must be {'a non-empty' if nonempty else 'an'} array")
    return value


def repository_file(root: Path, value: Any, context: str) -> Path:
    relative = string(value, context)
    if "\\" in relative or relative.startswith("/") or ".." in Path(relative).parts:
        fail(f"{context} must be a canonical repository-relative path")
    path = (root / relative).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError:
        fail(f"{context} escapes the repository")
    if not path.is_file():
        fail(f"{context} does not name a file: {relative}")
    return path


def git_text(root: Path, revision: str, relative: str, context: str) -> str:
    result = subprocess.run(
        ["git", "show", f"{revision}:{relative}"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if result.returncode != 0:
        fail(f"cannot read {context} from {revision}: {result.stderr.strip()}")
    return result.stdout


def diagnostic_baseline_revision(root: Path) -> str:
    candidates: list[str] = []
    github_base = os.environ.get("GITHUB_BASE_REF")
    if github_base:
        candidates.extend([f"origin/{github_base}", github_base])
    candidates.extend(["upstream/main", "origin/main", "main"])
    for candidate in candidates:
        result = subprocess.run(
            ["git", "merge-base", "HEAD", candidate],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    shallow = subprocess.run(
        ["git", "rev-parse", "--is-shallow-repository"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if shallow.stdout.strip() == "true":
        fail(
            "cannot resolve the main-branch merge base for diagnostic history: "
            "the checkout is shallow; use actions/checkout with fetch-depth: 0"
        )
    fail("cannot resolve the main-branch merge base for diagnostic history")


def initial_capability_registry_revision(root: Path) -> str:
    result = subprocess.run(
        ["git", "log", "--format=%H", "--reverse", "HEAD", "--", REGISTRY.as_posix()],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    revisions = result.stdout.splitlines() if result.returncode == 0 else []
    if not revisions:
        fail("cannot resolve the initial capability-registry revision")
    return revisions[0]


def some_match_fields(source: str) -> set[str]:
    fields: set[str] = set()
    pattern = re.compile(
        r"Some\(\s*((?:\"[A-Za-z][A-Za-z0-9-]*\"\s*\|\s*)*"
        r"\"[A-Za-z][A-Za-z0-9-]*\")\s*\)\s*(?:if\b.*?)?=>",
        re.DOTALL,
    )
    for match in pattern.finditer(source):
        fields.update(re.findall(r'\"([A-Za-z][A-Za-z0-9-]*)\"', match.group(1)))
    return fields


def rust_function_source(source: str, function: str, context: str) -> str:
    declaration = re.search(
        rf"(?ms)^fn {re.escape(function)}\(.*?(?=^fn |\Z)", source
    )
    if declaration is None:
        fail(f"{context} function {function!r} is missing")
    return declaration.group(0)


def action_metadata_fields(source: str) -> set[str]:
    fields = set(re.findall(r"key_eq\([^,]+,\s*\"([A-Za-z][A-Za-z0-9-]*)\"", source))
    for match in re.finditer(r"validate_allowed\(\s*&\[(.*?)\]", source, re.DOTALL):
        fields.update(re.findall(r'\"([A-Za-z][A-Za-z0-9-]*)\"', match.group(1)))
    fields.update(
        re.findall(
            r"(?:has_exact|take_exact)\(\"([A-Za-z][A-Za-z0-9-]*)\"\)", source
        )
    )
    fields.update(
        re.findall(
            r"(?:required_exact_scalar|optional_exact_scalar)\(\s*&mut fields,\s*"
            r"\"([A-Za-z][A-Za-z0-9-]*)\"",
            source,
        )
    )
    return fields


def action_runtime_values(source: str) -> set[str]:
    return set(re.findall(r'runtime\.eq_ignore_ascii_case\("([a-z0-9]+)"\)', source))


def trigger_names(source: str) -> set[str]:
    constant = re.search(
        r"const OTHER_GITHUB_EVENTS: &\[&str\] = &\[(?P<body>.*?)\];",
        source,
        re.DOTALL,
    )
    parser = re.search(
        r"fn parse_event_name\(.*?\{(?P<body>.*?)\n\}", source, re.DOTALL
    )
    if constant is None or parser is None:
        return set()
    names = set(re.findall(r'"([a-z][a-z0-9_]*)"', constant["body"]))
    names.update(re.findall(r'^\s*"([a-z][a-z0-9_]*)"\s*=>', parser["body"], re.MULTILINE))
    return names


def rust_enum_variants(source: str, enum_name: str, context: str) -> set[str]:
    declaration = re.search(
        rf"(?m)^pub enum {re.escape(enum_name)}\s*\{{(?P<body>.*?)^\}}",
        source,
        re.DOTALL,
    )
    if declaration is None:
        fail(f"{context} enum is missing")
    return set(
        re.findall(
            r"^\s{4}([A-Z][A-Za-z0-9]+)\s*(?:,|\(|\{)",
            declaration["body"],
            re.MULTILINE,
        )
    )


def rust_block(source: str, opening: int, context: str) -> str:
    """Return one balanced Rust block while ignoring literals and comments."""
    if opening >= len(source) or source[opening] != "{":
        fail(f"{context} has no function body")
    depth = 0
    index = opening
    state = "code"
    block_comment_depth = 0
    raw_hashes = 0
    while index < len(source):
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "line-comment":
            if character == "\n":
                state = "code"
        elif state == "block-comment":
            if character == "/" and following == "*":
                block_comment_depth += 1
                index += 1
            elif character == "*" and following == "/":
                block_comment_depth -= 1
                index += 1
                if block_comment_depth == 0:
                    state = "code"
        elif state == "string":
            if character == "\\":
                index += 1
            elif character == '"':
                state = "code"
        elif state == "character":
            if character == "\\":
                index += 1
            elif character == "'":
                state = "code"
        elif state == "raw-string":
            terminator = '"' + ("#" * raw_hashes)
            if source.startswith(terminator, index):
                index += len(terminator) - 1
                state = "code"
        else:
            if character == "/" and following == "/":
                state = "line-comment"
                index += 1
            elif character == "/" and following == "*":
                state = "block-comment"
                block_comment_depth = 1
                index += 1
            elif character == '"':
                state = "string"
            elif character == "'" and re.match(r"(?:\\.|[^\\'])'", source[index + 1 :]):
                state = "character"
            elif character == "r":
                raw = re.match(r'r(?P<hashes>#{0,255})"', source[index:])
                if raw is not None:
                    raw_hashes = len(raw.group("hashes"))
                    index += raw.end() - 1
                    state = "raw-string"
            if state == "code":
                if character == "{":
                    depth += 1
                elif character == "}":
                    depth -= 1
                    if depth == 0:
                        return source[opening : index + 1]
        index += 1
    fail(f"{context} has an unbalanced function body")


def attributed_test(
    source: str,
    function: str,
    context: str,
    required_fragments: list[str],
    *,
    allow_ignored: bool = False,
) -> None:
    matches = list(
        re.finditer(
            rf"(?m)^(?P<attrs>(?:\s*#\[[^\r\n]+\][^\r\n]*\r?\n)+)"
            rf"\s*(?:pub\s+)?(?:async\s+)?fn\s+{re.escape(function)}\s*\(",
            source,
        )
    )
    if len(matches) != 1 or TEST_ATTRIBUTE.search(matches[0].group("attrs")) is None:
        fail(f"{context} must bind exactly one attributed Rust test")
    attributes = matches[0].group("attrs")
    ignored = re.search(r"#\[\s*ignore(?:\s*=|\s*\])", attributes) is not None
    if ignored and not allow_ignored:
        fail(
            f"{context} must bind a normally executed Rust test or declare its "
            "machine-checked CI lane"
        )
    if allow_ignored and not ignored:
        fail(f"{context} declares an ignored-test CI lane for a normal Rust test")
    if re.search(r"#\[\s*cfg(?:_attr)?\s*\(", attributes):
        fail(f"{context} must not bind a cfg-disabled Rust test")
    body_open = source.find("{", matches[0].end())
    body = rust_block(source, body_open, context)
    body_without_comments = re.sub(r"(?s)/\*.*?\*/|//[^\r\n]*", "", body[1:-1]).strip()
    if not body_without_comments:
        fail(f"{context} must not bind an empty no-op Rust test")
    if re.fullmatch(
        r"(?:todo|unimplemented)!\s*\([^)]*\)\s*;?", body_without_comments
    ):
        fail(f"{context} must not bind an unimplemented Rust test")
    for fragment in required_fragments:
        if fragment not in body:
            fail(f"{context} is missing required semantic fragment {fragment!r}")


def acceptance_ci_lane(root: Path, value: Any, context: str) -> None:
    lane = exact_object(
        value,
        {"package", "runner", "selection", "workflow"},
        context,
    )
    package = string(lane["package"], f"{context}.package")
    selection = string(lane["selection"], f"{context}.selection")
    if selection != "--tests" and re.fullmatch(r"--test [A-Za-z0-9_-]+", selection) is None:
        fail(f"{context}.selection must be --tests or one exact --test target")
    runner = repository_file(root, lane["runner"], f"{context}.runner")
    workflow = repository_file(root, lane["workflow"], f"{context}.workflow")
    runner_source = runner.read_text(encoding="utf-8")
    commands = re.findall(
        r"(?ms)^run_bounded_tests cargo test \\\n(?P<body>.*?)(?=\n\n|\Z)",
        runner_source,
    )
    package_flag = re.compile(
        rf"(?m)^\s*-p\s+{re.escape(package)}\s*(?:\\)?$"
    )
    selection_flag = re.compile(
        rf"(?m)^\s*{re.escape(selection)}\s*(?:\\)?$"
    )
    if not any(
        package_flag.search(command)
        and selection_flag.search(command)
        and re.search(r"(?m)^\s*--ignored\s*(?:\\)?$", command)
        for command in commands
    ):
        fail(f"{context} does not run {package} {selection} with --ignored")
    invocation = f"run: ./{runner.relative_to(root).as_posix()}"
    if invocation not in workflow.read_text(encoding="utf-8"):
        fail(f"{context}.workflow does not invoke the declared runner")


def acceptance_fixtures(root: Path, value: Any, context: str) -> None:
    acceptance = value if isinstance(value, dict) else {}
    allowed = {"additional", "ci_lane", "function", "path", "required_fragments"}
    required = {"function", "path", "required_fragments"}
    if not required.issubset(acceptance) or not set(acceptance).issubset(allowed):
        fail(
            f"{context} must contain function, path, required_fragments, and only "
            "optional additional/ci_lane evidence"
        )
    fixtures = [acceptance]
    additional = acceptance.get("additional", [])
    if not isinstance(additional, list):
        fail(f"{context}.additional must be an array")
    fixtures.extend(additional)
    identities: set[tuple[str, str]] = set()
    for index, raw in enumerate(fixtures):
        fixture_context = context if index == 0 else f"{context}.additional[{index - 1}]"
        fixture = raw
        if index > 0:
            if not isinstance(raw, dict):
                fail(f"{fixture_context} must be an object")
            fixture_allowed = {"ci_lane", "function", "path", "required_fragments"}
            if not required.issubset(raw) or not set(raw).issubset(fixture_allowed):
                fail(
                    f"{fixture_context} must contain function, path, required_fragments, "
                    "and optional ci_lane"
                )
        test_path = repository_file(root, fixture["path"], f"{fixture_context}.path")
        function = string(fixture["function"], f"{fixture_context}.function")
        identity = (test_path.relative_to(root).as_posix(), function)
        if identity in identities:
            fail(f"{context} contains duplicate acceptance fixtures")
        identities.add(identity)
        fragments = [
            string(fragment, f"{fixture_context}.required_fragments")
            for fragment in array(
                fixture["required_fragments"],
                f"{fixture_context}.required_fragments",
                nonempty=True,
            )
        ]
        if fragments != sorted(set(fragments)):
            fail(f"{fixture_context}.required_fragments must be sorted and unique")
        ci_lane = fixture.get("ci_lane")
        attributed_test(
            test_path.read_text(encoding="utf-8"),
            function,
            fixture_context,
            fragments,
            allow_ignored=ci_lane is not None,
        )
        if ci_lane is not None:
            acceptance_ci_lane(root, ci_lane, f"{fixture_context}.ci_lane")


def compatibility_rows(source: str) -> dict[str, str]:
    start = source.find("## v0.1 implementation status")
    if start < 0:
        fail("compatibility document lacks its implementation-status section")
    section = source[start:]
    next_section = section.find("\n## ", 1)
    if next_section >= 0:
        section = section[:next_section]
    rows: dict[str, str] = {}
    for line in section.splitlines():
        if not line.startswith("| ") or line.startswith("| Area ") or line.startswith("| ---"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 4:
            continue
        area, status = cells[:2]
        if area in rows:
            fail(f"compatibility table contains duplicate area {area!r}")
        rows[area] = status
    return rows


def validate_snapshot(root: Path, path: Path) -> dict[str, Any]:
    snapshot = exact_object(
        load_canonical(path),
        {
            "catalog_version",
            "parser_version",
            "reference_groups",
            "replacement_policy",
            "retrieved_at",
            "runner",
            "schema_version",
        },
        "reference snapshot",
    )
    if snapshot["schema_version"] != 1:
        fail("reference snapshot schema_version must be integer 1")
    if snapshot["parser_version"] != "raw-bytes-sha256-v1":
        fail("reference snapshot parser version is not supported")
    replacement = exact_object(
        snapshot["replacement_policy"],
        {"approval_registry", "minimum_human_reviewers", "procedure"},
        "replacement_policy",
    )
    if replacement["minimum_human_reviewers"] < 2:
        fail("reference replacement requires at least two human reviewers")
    repository_file(root, replacement["approval_registry"], "replacement approval registry")
    references = array(snapshot["reference_groups"], "reference_groups", nonempty=True)
    ids: list[str] = []
    urls: list[str] = []
    categories: set[str] = set()
    for index, raw in enumerate(references):
        reference = exact_object(
            raw, {"bytes", "categories", "id", "sha256", "url"}, f"reference_groups[{index}]"
        )
        identifier = string(reference["id"], f"reference_groups[{index}].id")
        if IDENTIFIER.fullmatch(identifier) is None:
            fail(f"reference id is not canonical: {identifier}")
        if not isinstance(reference["bytes"], int) or isinstance(reference["bytes"], bool):
            fail(f"reference_groups[{index}].bytes must be an integer")
        if reference["bytes"] < 1 or reference["bytes"] > 1_048_576:
            fail(f"reference_groups[{index}].bytes is outside the bounded detector range")
        if SHA256.fullmatch(string(reference["sha256"], "reference sha256")) is None:
            fail(f"reference_groups[{index}].sha256 is invalid")
        url = string(reference["url"], f"reference_groups[{index}].url")
        if not url.startswith("https://raw.githubusercontent.com/"):
            fail(f"reference_groups[{index}].url must be an immutable raw GitHub URL")
        if re.fullmatch(
            r"https://raw\.githubusercontent\.com/[^/]+/[^/]+/[0-9a-f]{40}/.+",
            url,
        ) is None:
            fail(f"reference_groups[{index}].url must contain an immutable commit")
        reference_categories = array(reference["categories"], "reference categories", nonempty=True)
        if any(category not in REFERENCE_CATEGORIES for category in reference_categories):
            fail(f"reference_groups[{index}] contains an unknown review category")
        if reference_categories != sorted(set(reference_categories)):
            fail(f"reference_groups[{index}].categories must be sorted and unique")
        categories.update(reference_categories)
        ids.append(identifier)
        urls.append(url)
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        fail("reference IDs must be sorted and unique")
    if len(urls) != len(set(urls)):
        fail("reference URLs must be unique")
    if categories != REFERENCE_CATEGORIES:
        fail(f"reference snapshot categories differ: {sorted(REFERENCE_CATEGORIES ^ categories)}")
    runner = exact_object(
        snapshot["runner"],
        {
            "baseline_commit",
            "baseline_release",
            "javascript_runtime",
            "release_url",
            "repository",
        },
        "runner baseline",
    )
    if runner["repository"] != "actions/runner":
        fail("runner baseline must identify actions/runner")
    commit = string(runner["baseline_commit"], "runner baseline commit")
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        fail("runner baseline commit must be an immutable Git object ID")
    return snapshot


def validate_reviewed_deltas(path: Path, reference_ids: set[str]) -> None:
    document = exact_object(
        load_canonical(path), {"reviewed_deltas", "schema_version"}, "reviewed deltas"
    )
    if document["schema_version"] != 1:
        fail("reviewed delta schema_version must be integer 1")
    covered: set[str] = set()
    identifiers: list[str] = []
    for index, raw in enumerate(array(document["reviewed_deltas"], "reviewed_deltas", nonempty=True)):
        delta = exact_object(
            raw,
            {
                "categories",
                "decision",
                "id",
                "reference_ids",
                "reviewed_at",
                "reviewers",
                "source_revision",
            },
            f"reviewed_deltas[{index}]",
        )
        context = f"reviewed_deltas[{index}]"
        identifier = string(delta["id"], f"{context}.id")
        if IDENTIFIER.fullmatch(identifier) is None:
            fail(f"{context}.id is not canonical")
        identifiers.append(identifier)
        decision = string(delta["decision"], f"{context}.decision")
        if decision not in REVIEW_DECISIONS:
            fail(f"{context}.decision is not an allowed reviewed decision")
        reviewed_at = string(delta["reviewed_at"], f"{context}.reviewed_at")
        try:
            if datetime.date.fromisoformat(reviewed_at).isoformat() != reviewed_at:
                raise ValueError
        except ValueError:
            fail(f"{context}.reviewed_at must be a canonical ISO 8601 date")
        source_revision = string(delta["source_revision"], f"{context}.source_revision")
        if GITHUB_SOURCE_REVISIONS.fullmatch(source_revision) is None:
            fail(
                f"{context}.source_revision must contain canonical immutable GitHub revisions"
            )
        reviewers = [
            string(reviewer, f"{context}.reviewers")
            for reviewer in array(delta["reviewers"], f"{context}.reviewers", nonempty=True)
        ]
        if any(IDENTIFIER.fullmatch(reviewer) is None for reviewer in reviewers):
            fail(f"{context}.reviewers must be canonical human reviewer IDs")
        if len(reviewers) < 2 or reviewers != sorted(set(reviewers)):
            fail(f"{context} requires two distinct sorted reviewers")
        categories = [
            string(category, f"{context}.categories")
            for category in array(delta["categories"], f"{context}.categories", nonempty=True)
        ]
        if any(category not in REFERENCE_CATEGORIES for category in categories):
            fail(f"{context} contains an unknown category")
        if categories != sorted(set(categories)):
            fail(f"{context}.categories must be sorted and unique")
        reference_values = [
            string(reference, f"{context}.reference_ids")
            for reference in array(
                delta["reference_ids"], f"{context}.reference_ids", nonempty=True
            )
        ]
        if reference_values != sorted(set(reference_values)):
            fail(f"{context}.reference_ids must be sorted and unique")
        references = set(reference_values)
        if not references <= reference_ids:
            fail(f"{context} references an unknown source")
        covered.update(references)
    if identifiers != sorted(identifiers) or len(identifiers) != len(set(identifiers)):
        fail("reviewed delta IDs must be sorted and unique")
    if covered != reference_ids:
        fail(f"reviewed deltas do not cover references: {sorted(reference_ids - covered)}")


def verify(root: Path, registry_path: Path) -> None:
    registry = exact_object(
        load_canonical(registry_path),
        {
            "compatibility_document",
            "decoder_inventory",
            "diagnostic_history",
            "diagnostic_migrations",
            "features",
            "late_rejections",
            "provider_event_inventory",
            "reference_snapshot",
            "reviewed_deltas",
            "runner_runtime_inventories",
            "schema_version",
            "stage_profiles",
            "unsupported_diagnostics",
        },
        "capability registry",
    )
    if registry["schema_version"] != 1 or isinstance(registry["schema_version"], bool):
        fail("capability registry schema_version must be integer 1")

    profiles = registry["stage_profiles"]
    if not isinstance(profiles, dict) or not profiles:
        fail("stage_profiles must be a non-empty object")
    for name, raw_profile in profiles.items():
        if IDENTIFIER.fullmatch(name) is None:
            fail(f"invalid stage profile ID {name!r}")
        profile = exact_object(raw_profile, STAGES, f"stage_profiles.{name}")
        if any(status not in STAGE_STATUSES for status in profile.values()):
            fail(f"stage_profiles.{name} contains an invalid status")

    features = array(registry["features"], "features", nonempty=True)
    feature_ids: set[str] = set()
    claims: dict[str, str] = {}
    feature_sources: dict[str, str] = {}
    feature_unsupported: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(features):
        feature = exact_object(
            raw,
            {
                "acceptance",
                "area",
                "capabilities",
                "evaluation_phase",
                "id",
                "source",
                "stage_profile",
                "status",
                "unsupported",
            },
            f"features[{index}]",
        )
        identifier = string(feature["id"], f"features[{index}].id")
        if IDENTIFIER.fullmatch(identifier) is None or identifier in feature_ids:
            fail(f"invalid or duplicate feature ID {identifier!r}")
        feature_ids.add(identifier)
        area = string(feature["area"], f"features[{index}].area")
        status = string(feature["status"], f"features[{index}].status")
        if status not in COMPATIBILITY_STATUSES:
            fail(f"{identifier} contains unknown compatibility status {status!r}")
        evaluation_phase = string(
            feature["evaluation_phase"], f"features[{index}].evaluation_phase"
        )
        if evaluation_phase not in EVALUATION_PHASES:
            fail(f"{identifier} contains unknown evaluation phase {evaluation_phase!r}")
        if area in claims:
            fail(f"multiple feature entries claim compatibility area {area!r}")
        claims[area] = status
        if feature["stage_profile"] not in profiles:
            fail(f"{identifier} references an unknown stage profile")
        if feature["stage_profile"] != identifier:
            fail(f"{identifier} must use its own stage profile")
        for capability in array(feature["capabilities"], f"{identifier}.capabilities"):
            if CAPABILITY.fullmatch(string(capability, "capability identifier")) is None:
                fail(f"{identifier} contains invalid capability {capability!r}")
        source_binding = exact_object(feature["source"], {"contains", "path"}, f"{identifier}.source")
        source_path = repository_file(root, source_binding["path"], f"{identifier}.source.path")
        feature_sources[identifier] = source_path.relative_to(root).as_posix()
        source = source_path.read_text(encoding="utf-8")
        fragment = string(source_binding["contains"], f"{identifier}.source.contains")
        if source.count(fragment) != 1:
            fail(f"{identifier} source fragment must occur exactly once")
        acceptance_fixtures(root, feature["acceptance"], f"{identifier}.acceptance")
        unsupported = feature["unsupported"]
        if unsupported is not None:
            unsupported = exact_object(
                unsupported, {"code", "span_policy"}, f"{identifier}.unsupported"
            )
            string(unsupported["code"], f"{identifier}.unsupported.code")
            string(unsupported["span_policy"], f"{identifier}.unsupported.span_policy")
            feature_unsupported[identifier] = unsupported

    if set(profiles) != feature_ids:
        fail(
            "stage profile inventory drifted: "
            f"missing={sorted(feature_ids - set(profiles))}, "
            f"stale={sorted(set(profiles) - feature_ids)}"
        )

    compatibility_path = repository_file(
        root, registry["compatibility_document"], "compatibility_document"
    )
    documented = compatibility_rows(compatibility_path.read_text(encoding="utf-8"))
    if claims != documented:
        missing = sorted(documented.keys() - claims.keys())
        extra = sorted(claims.keys() - documented.keys())
        changed = sorted(area for area in claims.keys() & documented.keys() if claims[area] != documented[area])
        fail(f"compatibility linkage drifted: missing={missing}, extra={extra}, changed={changed}")

    inventories = array(registry["decoder_inventory"], "decoder_inventory", nonempty=True)
    inventory_ids: set[str] = set()
    inventory_paths: set[str] = set()
    trigger_feature_mapping: dict[str, str] | None = None
    for index, raw in enumerate(inventories):
        extractor = raw.get("extractor") if isinstance(raw, dict) else None
        keys = {"extractor", "fields", "id", "path"}
        if extractor == "function-some-match-arms":
            keys.add("function")
        inventory = exact_object(
            raw, keys, f"decoder_inventory[{index}]"
        )
        identifier = string(inventory["id"], f"decoder_inventory[{index}].id")
        if identifier in inventory_ids:
            fail(f"duplicate decoder inventory ID {identifier!r}")
        inventory_ids.add(identifier)
        fields = inventory["fields"]
        if not isinstance(fields, dict) or not fields:
            fail(f"decoder_inventory[{index}].fields must be a non-empty object")
        unknown_features = set(fields.values()) - feature_ids
        if unknown_features:
            fail(f"{identifier} references unknown features {sorted(unknown_features)}")
        path = repository_file(root, inventory["path"], f"{identifier}.path")
        inventory_paths.add(path.relative_to(root).as_posix())
        source = path.read_text(encoding="utf-8")
        if extractor == "some-match-arms":
            actual = some_match_fields(source)
        elif extractor == "function-some-match-arms":
            function = string(inventory["function"], f"{identifier}.function")
            actual = some_match_fields(
                rust_function_source(source, function, identifier)
            )
        elif extractor == "action-metadata":
            actual = action_metadata_fields(source)
        elif extractor == "action-runtimes":
            actual = action_runtime_values(source)
        elif extractor == "trigger-names":
            actual = trigger_names(source)
        else:
            fail(f"{identifier} uses unknown extractor {extractor!r}")
        expected = set(fields)
        if actual != expected:
            fail(
                f"{identifier} decoder coverage drifted: "
                f"missing={sorted(actual - expected)}, stale={sorted(expected - actual)}"
            )
        if extractor == "trigger-names":
            if trigger_feature_mapping is not None:
                fail("trigger names may be inventoried only once")
            trigger_feature_mapping = dict(fields)

    workflow_decoder_root = root / "crates/automata-ci-workflow-github/src/decode"
    governed_decoder_paths = {
        path.relative_to(root).as_posix()
        for path in workflow_decoder_root.glob("*.rs")
        if path.name != "mod.rs"
    }
    governed_decoder_paths.add("crates/automata-ci-action-github/src/decoder.rs")
    if inventory_paths != governed_decoder_paths:
        fail(
            "governed decoder source inventory drifted: "
            f"missing={sorted(governed_decoder_paths - inventory_paths)}, "
            f"stale={sorted(inventory_paths - governed_decoder_paths)}"
        )

    provider_inventory = exact_object(
        registry["provider_event_inventory"],
        {"events", "path"},
        "provider_event_inventory",
    )
    provider_events = provider_inventory["events"]
    if not isinstance(provider_events, dict) or not provider_events:
        fail("provider_event_inventory.events must be a non-empty object")
    if set(provider_events.values()) - feature_ids:
        fail("provider_event_inventory references an unknown feature")
    provider_path = repository_file(
        root, provider_inventory["path"], "provider_event_inventory.path"
    )
    provider_source = provider_path.read_text(encoding="utf-8")
    normalize = re.search(
        r"pub fn normalize\(self\).*?\{(?P<body>.*?)\n    \}\n\n    fn into_verified_push",
        provider_source,
        re.DOTALL,
    )
    if normalize is None:
        fail("provider webhook normalize function is missing")
    actual_provider_events = set(
        re.findall(r'^\s*"([a-z][a-z0-9_]*)"\s*=>', normalize["body"], re.MULTILINE)
    )
    if actual_provider_events != set(provider_events):
        fail(
            "provider event inventory drifted: "
            f"missing={sorted(actual_provider_events - set(provider_events))}, "
            f"stale={sorted(set(provider_events) - actual_provider_events)}"
        )
    if trigger_feature_mapping is None:
        fail("trigger event inventory is missing")
    required_trigger_features = dict(provider_events)
    required_trigger_features.update(
        {
            "schedule": "scheduled-workflows",
            "workflow_call": "reusable-workflows",
            "workflow_dispatch": "workflow-dispatch-inputs-and-base-context",
        }
    )
    for event in set(trigger_feature_mapping) - set(required_trigger_features):
        required_trigger_features[event] = "decoder-only-provider-events"
    changed_trigger_features = sorted(
        event
        for event, feature in trigger_feature_mapping.items()
        if required_trigger_features.get(event) != feature
    )
    if changed_trigger_features:
        fail(
            "trigger feature partition drifted for events "
            f"{changed_trigger_features}"
        )

    diagnostics = array(
        registry["unsupported_diagnostics"], "unsupported_diagnostics", nonempty=True
    )
    registered_diagnostics: dict[str, str] = {}
    diagnostic_codes: list[str] = []
    for index, raw in enumerate(diagnostics):
        diagnostic = exact_object(
            raw,
            {"code", "feature", "source", "span_policy"},
            f"unsupported_diagnostics[{index}]",
        )
        code = string(diagnostic["code"], "unsupported diagnostic code")
        diagnostic_codes.append(code)
        if diagnostic["feature"] not in feature_ids:
            fail(f"unsupported diagnostic {code} references an unknown feature")
        source_path = repository_file(root, diagnostic["source"], "diagnostic source")
        registered_diagnostics[code] = source_path.relative_to(root).as_posix()
        string(diagnostic["span_policy"], "unsupported diagnostic span policy")
    if diagnostic_codes != sorted(diagnostic_codes) or len(diagnostic_codes) != len(
        set(diagnostic_codes)
    ):
        fail("unsupported diagnostic codes must be sorted and unique")

    emitted_diagnostics: dict[str, set[str]] = {}
    frontend = root / "crates/automata-ci-workflow-github/src"
    for source_path in sorted(frontend.rglob("*.rs")):
        source = source_path.read_text(encoding="utf-8")
        for match in re.finditer(r'\.unsupported\(\s*"([^"]+)"', source):
            emitted_diagnostics.setdefault(match.group(1), set()).add(
                source_path.relative_to(root).as_posix()
            )
    if set(registered_diagnostics) != set(emitted_diagnostics):
        fail(
            "unsupported diagnostic inventory drifted: "
            f"missing={sorted(set(emitted_diagnostics) - set(registered_diagnostics))}, "
            f"stale={sorted(set(registered_diagnostics) - set(emitted_diagnostics))}"
        )
    for code, source in registered_diagnostics.items():
        if emitted_diagnostics[code] != {source}:
            fail(f"unsupported diagnostic {code} moved without a registry update")

    diagnostics_by_code = {diagnostic["code"]: diagnostic for diagnostic in diagnostics}
    for feature_id, unsupported in feature_unsupported.items():
        code = unsupported["code"]
        diagnostic = diagnostics_by_code.get(code)
        if diagnostic is None:
            fail(f"{feature_id}.unsupported references unregistered diagnostic {code}")
        if diagnostic["feature"] != feature_id:
            fail(
                f"{feature_id}.unsupported diagnostic {code} belongs to "
                f"{diagnostic['feature']}"
            )
        if diagnostic["source"] != feature_sources[feature_id]:
            fail(f"{feature_id}.unsupported source differs from diagnostic {code}")
        if diagnostic["span_policy"] != unsupported["span_policy"]:
            fail(f"{feature_id}.unsupported span policy differs from diagnostic {code}")

    runtime_inventories = array(
        registry["runner_runtime_inventories"],
        "runner_runtime_inventories",
        nonempty=True,
    )
    inventory_ids: list[str] = []
    inventory_enums: set[tuple[str, str]] = set()
    for index, raw in enumerate(runtime_inventories):
        inventory = exact_object(
            raw,
            {"enum", "id", "path", "variants"},
            f"runner_runtime_inventories[{index}]",
        )
        inventory_id = string(inventory["id"], "runner runtime inventory ID")
        if IDENTIFIER.fullmatch(inventory_id) is None:
            fail(f"invalid runner runtime inventory ID {inventory_id!r}")
        inventory_ids.append(inventory_id)
        enum_name = string(inventory["enum"], f"{inventory_id}.enum")
        source_path = repository_file(root, inventory["path"], f"{inventory_id}.path")
        enum_binding = (source_path.relative_to(root).as_posix(), enum_name)
        if enum_binding in inventory_enums:
            fail(f"runner runtime enum {enum_name} is inventoried more than once")
        inventory_enums.add(enum_binding)
        variants = inventory["variants"]
        if not isinstance(variants, dict) or not variants:
            fail(f"{inventory_id}.variants must be a non-empty object")
        for variant, raw_classification in variants.items():
            if re.fullmatch(r"[A-Z][A-Za-z0-9]+", variant) is None:
                fail(f"{inventory_id} contains invalid Rust variant {variant!r}")
            classification = exact_object(
                raw_classification,
                {"classification", "feature"},
                f"{inventory_id}.variants.{variant}",
            )
            stable_classification = string(
                classification["classification"],
                f"{inventory_id}.variants.{variant}.classification",
            )
            if IDENTIFIER.fullmatch(stable_classification) is None:
                fail(
                    f"{inventory_id}.variants.{variant}.classification is not canonical"
                )
            if classification["feature"] not in feature_ids:
                fail(
                    f"{inventory_id}.variants.{variant} references unknown feature "
                    f"{classification['feature']!r}"
                )
        actual_variants = rust_enum_variants(
            source_path.read_text(encoding="utf-8"), enum_name, inventory_id
        )
        expected_variants = set(variants)
        if actual_variants != expected_variants:
            fail(
                f"{inventory_id} enum coverage drifted: "
                f"missing={sorted(actual_variants - expected_variants)}, "
                f"stale={sorted(expected_variants - actual_variants)}"
            )
    if inventory_ids != sorted(inventory_ids) or len(inventory_ids) != len(
        set(inventory_ids)
    ):
        fail("runner runtime inventory IDs must be sorted and unique")

    migrations = array(registry["diagnostic_migrations"], "diagnostic_migrations")
    migrated_codes: list[str] = []
    for index, raw in enumerate(migrations):
        migration = exact_object(
            raw, {"from", "note", "to"}, f"diagnostic_migrations[{index}]"
        )
        old = string(migration["from"], "diagnostic migration source")
        migrated_codes.append(old)
        if old in registered_diagnostics:
            fail(f"diagnostic migration source remains active: {old}")
        replacement = migration["to"]
        if replacement is not None and replacement not in registered_diagnostics:
            fail(f"diagnostic migration replacement is not active: {replacement}")
        string(migration["note"], "diagnostic migration note")
    if migrated_codes != sorted(migrated_codes) or len(migrated_codes) != len(
        set(migrated_codes)
    ):
        fail("diagnostic migration sources must be sorted and unique")

    diagnostic_history_path = repository_file(
        root, registry["diagnostic_history"], "diagnostic_history"
    )
    diagnostic_history_document = exact_object(
        load_canonical(diagnostic_history_path),
        {"codes", "schema_version"},
        "diagnostic history",
    )
    if diagnostic_history_document["schema_version"] != 1:
        fail("diagnostic history schema_version must be integer 1")
    diagnostic_history = array(
        diagnostic_history_document["codes"], "diagnostic history codes", nonempty=True
    )
    for index, code in enumerate(diagnostic_history):
        string(code, f"diagnostic_history[{index}]")
    if diagnostic_history != sorted(set(diagnostic_history)):
        fail("diagnostic_history must be sorted and unique")
    history_relative = diagnostic_history_path.relative_to(root).as_posix()
    baseline_revision = diagnostic_baseline_revision(root)
    try:
        baseline_history = json.loads(
            git_text(root, baseline_revision, history_relative, "diagnostic history")
        )
        baseline_codes_value = baseline_history.get("codes")
        baseline_context = "baseline diagnostic history codes"
    except json.JSONDecodeError as error:
        fail(f"baseline diagnostic history is invalid JSON: {error}")
    except CapabilityError:
        registry_revision = baseline_revision
        try:
            baseline_registry = json.loads(
                git_text(
                    root,
                    registry_revision,
                    REGISTRY.as_posix(),
                    "capability registry",
                )
            )
        except CapabilityError:
            registry_revision = initial_capability_registry_revision(root)
            try:
                baseline_registry = json.loads(
                    git_text(
                        root,
                        registry_revision,
                        REGISTRY.as_posix(),
                        "initial capability registry",
                    )
                )
            except json.JSONDecodeError as error:
                fail(f"initial capability registry is invalid JSON: {error}")
        except json.JSONDecodeError as error:
            fail(f"baseline capability registry is invalid JSON: {error}")
        baseline_codes_value = [
            diagnostic["code"]
            for diagnostic in baseline_registry.get("unsupported_diagnostics", [])
        ]
        baseline_context = "baseline active diagnostic codes"
    baseline_codes = set(array(baseline_codes_value, baseline_context))
    removed_history = baseline_codes - set(diagnostic_history)
    if removed_history:
        fail(
            "diagnostic_history is append-only; restored or migrated codes required: "
            f"{sorted(removed_history)}"
        )
    accounted_diagnostics = set(registered_diagnostics) | set(migrated_codes)
    if set(diagnostic_history) != accounted_diagnostics:
        fail(
            "diagnostic history is not fully accounted for: "
            f"missing_migration={sorted(set(diagnostic_history) - accounted_diagnostics)}, "
            f"unrecorded={sorted(accounted_diagnostics - set(diagnostic_history))}"
        )

    late_rejections = array(registry["late_rejections"], "late_rejections", nonempty=True)
    rejection_ids: list[str] = []
    registered_variants: set[str] = set()
    for index, raw in enumerate(late_rejections):
        rejection = exact_object(
            raw,
            {"disposition", "early_diagnostic", "id", "source", "variant"},
            f"late_rejections[{index}]",
        )
        rejection_ids.append(string(rejection["id"], "late rejection ID"))
        variant = string(rejection["variant"], "late rejection variant")
        registered_variants.add(variant)
        source_path = repository_file(root, rejection["source"], "late rejection source")
        if source_path.read_text(encoding="utf-8").count(f"    {variant},") != 1:
            fail(f"late rejection variant {variant} is not uniquely declared")
        string(rejection["disposition"], "late rejection disposition")
        diagnostic = rejection["early_diagnostic"]
        if diagnostic is not None:
            code = string(diagnostic, "late rejection early diagnostic")
            compiler = repository_file(
                root,
                "crates/automata-ci-workflow-github/src/compiler/logical.rs",
                "GitHub compiler",
            ).read_text(encoding="utf-8")
            if compiler.count(f'"{code}"') != 1:
                fail(f"late rejection diagnostic {code} is not uniquely emitted by the compiler")
    if rejection_ids != sorted(rejection_ids) or len(rejection_ids) != len(set(rejection_ids)):
        fail("late rejection IDs must be sorted and unique")
    projection_source = repository_file(
        root,
        "crates/automata-ci-workflow-service/src/logical_projection.rs",
        "logical projection source",
    ).read_text(encoding="utf-8")
    enum_match = re.search(
        r"pub enum UnsupportedLogicalJobSemantics\s*\{(?P<body>.*?)\n\}",
        projection_source,
        re.DOTALL,
    )
    if enum_match is None:
        fail("logical projection unsupported-semantics enum is missing")
    actual_variants = set(re.findall(r"^\s{4}([A-Z][A-Za-z0-9]+),", enum_match["body"], re.MULTILINE))
    if registered_variants != actual_variants:
        fail(
            "late projection rejection inventory drifted: "
            f"missing={sorted(actual_variants - registered_variants)}, "
            f"stale={sorted(registered_variants - actual_variants)}"
        )

    snapshot_path = repository_file(root, registry["reference_snapshot"], "reference_snapshot")
    snapshot = validate_snapshot(root, snapshot_path)
    reviewed_path = repository_file(root, registry["reviewed_deltas"], "reviewed_deltas")
    reference_ids = {reference["id"] for reference in snapshot["reference_groups"]}
    validate_reviewed_deltas(reviewed_path, reference_ids)

    baseline = snapshot["runner"]
    baseline_fragments = {
        "crates/automata-ci-action-github/src/lib.rs": [
            f'"actions/runner@{baseline["baseline_release"]}"',
            f'"{baseline["baseline_commit"]}"',
        ],
        "crates/automata-ci-expression-github/src/lib.rs": [
            f'"actions/runner@{baseline["baseline_release"]}"',
            f'"{baseline["baseline_commit"]}"',
        ],
        "crates/automata-ci-github-runtime/src/lib.rs": [
            f'"actions/runner@{baseline["baseline_release"]}"',
            f'"{baseline["baseline_commit"]}"',
        ],
        "docs/compatibility.md": [baseline["baseline_release"], baseline["baseline_commit"]],
    }
    for relative, fragments in baseline_fragments.items():
        source = repository_file(root, relative, "runner baseline binding").read_text(encoding="utf-8")
        for fragment in fragments:
            if fragment not in source:
                fail(f"runner baseline {fragment!r} is not bound in {relative}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, default=REPOSITORY_ROOT)
    parser.add_argument("--registry", type=Path)
    args = parser.parse_args()
    root = args.repository_root.resolve()
    registry = args.registry.resolve() if args.registry else root / REGISTRY
    try:
        verify(root, registry)
    except CapabilityError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print("GitHub Actions capability registry and pinned reference contract verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
