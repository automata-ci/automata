#!/usr/bin/env python3
"""Fail closed on GitHub Actions capability, compatibility, and reference drift."""

from __future__ import annotations

import argparse
import json
import re
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
CAPABILITY = re.compile(
    r"^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*/"
    r"[a-z][a-z0-9-]*@v[1-9][0-9]*$"
)
IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
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


def attributed_test(source: str, function: str, context: str) -> None:
    matches = list(
        re.finditer(
            rf"(?m)^(?P<attrs>(?:\s*#\[[^\r\n]+\][^\r\n]*\r?\n)+)"
            rf"\s*(?:pub\s+)?(?:async\s+)?fn\s+{re.escape(function)}\s*\(",
            source,
        )
    )
    if len(matches) != 1 or TEST_ATTRIBUTE.search(matches[0].group("attrs")) is None:
        fail(f"{context} must bind exactly one attributed Rust test")


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
        identifiers.append(string(delta["id"], "reviewed delta id"))
        reviewers = array(delta["reviewers"], "reviewers", nonempty=True)
        if len(reviewers) < 2 or len(reviewers) != len(set(reviewers)):
            fail(f"reviewed_deltas[{index}] requires two distinct reviewers")
        categories = array(delta["categories"], "delta categories", nonempty=True)
        if any(category not in REFERENCE_CATEGORIES for category in categories):
            fail(f"reviewed_deltas[{index}] contains an unknown category")
        references = set(array(delta["reference_ids"], "delta reference_ids"))
        if not references <= reference_ids:
            fail(f"reviewed_deltas[{index}] references an unknown source")
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
            "diagnostic_migrations",
            "features",
            "late_rejections",
            "reference_snapshot",
            "reviewed_deltas",
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
        if area in claims:
            fail(f"multiple feature entries claim compatibility area {area!r}")
        claims[area] = status
        if feature["stage_profile"] not in profiles:
            fail(f"{identifier} references an unknown stage profile")
        for capability in array(feature["capabilities"], f"{identifier}.capabilities"):
            if CAPABILITY.fullmatch(string(capability, "capability identifier")) is None:
                fail(f"{identifier} contains invalid capability {capability!r}")
        source_binding = exact_object(feature["source"], {"contains", "path"}, f"{identifier}.source")
        source_path = repository_file(root, source_binding["path"], f"{identifier}.source.path")
        source = source_path.read_text(encoding="utf-8")
        fragment = string(source_binding["contains"], f"{identifier}.source.contains")
        if source.count(fragment) != 1:
            fail(f"{identifier} source fragment must occur exactly once")
        acceptance = exact_object(feature["acceptance"], {"function", "path"}, f"{identifier}.acceptance")
        test_path = repository_file(root, acceptance["path"], f"{identifier}.acceptance.path")
        attributed_test(
            test_path.read_text(encoding="utf-8"),
            string(acceptance["function"], f"{identifier}.acceptance.function"),
            f"{identifier}.acceptance",
        )
        unsupported = feature["unsupported"]
        if unsupported is not None:
            unsupported = exact_object(
                unsupported, {"code", "span_policy"}, f"{identifier}.unsupported"
            )
            string(unsupported["code"], f"{identifier}.unsupported.code")
            string(unsupported["span_policy"], f"{identifier}.unsupported.span_policy")

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
    for index, raw in enumerate(inventories):
        inventory = exact_object(
            raw, {"extractor", "fields", "id", "path"}, f"decoder_inventory[{index}]"
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
        source = path.read_text(encoding="utf-8")
        extractor = inventory["extractor"]
        if extractor == "some-match-arms":
            actual = some_match_fields(source)
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
