#!/usr/bin/env python3
"""Verify the machine-readable foundation governance contract."""

from __future__ import annotations

import argparse
import ast
import functools
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = PurePosixPath("docs/governance/foundation-governance-v1.json")
STORE_MIGRATION_FORMAT_MAP_PATH = PurePosixPath(
    "docs/governance/store-migration-format-map-v1.json"
)
TOP_LEVEL_KEYS = {
    "format_exclusions",
    "format_scope",
    "formats",
    "github_limits",
    "limit_aliases",
    "limit_exclusions",
    "limit_surfaces",
    "limits",
    "migrations",
    "owners",
    "schema_version",
    "shared_surfaces",
    "status",
}
IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$")
REASON_CODE = re.compile(
    r"^(?:[a-z][a-z0-9_]*(?:[.-][a-z0-9_]+)*|"
    r"[A-Z][A-Za-z0-9_]*(?:::[A-Z][A-Za-z0-9_]*)+)$"
)
RUST_TEST_FUNCTION = (
    r"(?m)^(?P<attributes>(?:\s*#\[[^]]+\]\s*)+)"
    r"\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+{name}\s*(?:<[^>]*>)?\s*\("
)
RUST_FUNCTION = (
    r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+{name}\s*"
    r"(?:<[^>]*>)?\s*\("
)
RUST_TEST_ATTRIBUTE = re.compile(
    r"#\[\s*(?:[A-Za-z_][A-Za-z0-9_]*::)*test(?:\s*\([^]]*\))?\s*\]"
)
TYPESCRIPT_TEST_FUNCTION = (
    r"(?m)^\s*(?:export\s+)?(?:async\s+)?function\s+{name}\s*"
    r"(?:<[^>]*>)?\s*\("
)
FORMAT_COMPATIBILITY_POLICIES = {
    "backward-compatible",
    "exact-current-only",
    "generated-v1-package",
}
GITHUB_LIMIT_IDS = {
    "github.cache.deletes-per-minute",
    "github.cache.downloads-per-minute",
    "github.cache.uploads-per-minute",
    "github.checks.per-suite",
    "github.concurrency.group-queue",
    "github.hosted.enterprise.jobs",
    "github.hosted.enterprise.macos-jobs",
    "github.hosted.free.jobs",
    "github.hosted.free.macos-jobs",
    "github.hosted.larger-enterprise.gpu-jobs",
    "github.hosted.larger-enterprise.jobs",
    "github.hosted.larger-enterprise.macos-jobs",
    "github.hosted.larger-team.gpu-jobs",
    "github.hosted.larger-team.jobs",
    "github.hosted.larger-team.macos-jobs",
    "github.hosted.pro.jobs",
    "github.hosted.pro.macos-jobs",
    "github.hosted.static-ips",
    "github.hosted.team.jobs",
    "github.hosted.team.macos-jobs",
    "github.job.hosted-hours",
    "github.job.queue-hours",
    "github.job.self-hosted-hours",
    "github.provider.changed-files.actions-push-commits",
    "github.provider.path-filter-commits",
    "github.provider.push-commits",
    "github.provider.repository-dispatch.event-type-characters",
    "github.provider.repository-dispatch.payload-characters",
    "github.provider.repository-dispatch.payload-properties",
    "github.provider.webhook-body-bytes",
    "github.runner.artifact-subjects",
    "github.runner.composite-action-depth",
    "github.runner.download-retry-attempts",
    "github.runner.private-ip-buffer-percent",
    "github.runner.registrations-per-five-minutes",
    "github.runner.runners-per-group",
    "github.workflow.approval-days",
    "github.workflow.dispatch-definition-inputs",
    "github.workflow.dispatch-input-characters",
    "github.workflow.dispatch-payload-inputs",
    "github.workflow.file-kilobytes",
    "github.workflow.matrix-jobs",
    "github.workflow.queued-per-ten-seconds",
    "github.workflow.reruns",
    "github.workflow.run-days",
    "github.workflow.schedule-minutes",
    "github.workflow.trigger-events-per-ten-seconds",
}
LIMIT_ENFORCEMENT_PHASES = {
    "admission",
    "compile",
    "external",
    "executor-admission",
    "fleet",
    "provider-ingress",
    "results",
    "runtime",
    "scheduler",
}
RUST_CONSTANT_DECLARATION = re.compile(
    r"(?m)^[ \t]*(?:pub(?:\([^)]*\))?\s+)?const\s+"
    r"(?P<name>[A-Z][A-Z0-9_]*)\s*:[^=\r\n]+="
)
RUST_LIMIT_DECLARATION = re.compile(
    r"(?mx)^[ \t]*(?:\#\[[^\r\n]+\]\s*)*"
    r"(?:pub(?:\([^)]*\))?\s+)?const\s+"
    r"(?P<name>[A-Z][A-Z0-9_]*)\s*:\s*"
    r"(?P<type>[^=\r\n]+?)\s*="
)
LIMIT_NAME_TOKEN = re.compile(
    r"(?:^|_)(?:MAX|MAXIMUM|MIN|MINIMUM|LIMIT|CEILING|CAP|BOUND|BUDGET|QUOTA|"
    r"PAGE_SIZE|BATCH_SIZE)(?:_|$)"
)
RUST_LIMIT_TYPE_TOKEN = re.compile(
    r"(?:^|::)(?:[A-Za-z0-9_]*(?:Limit|Limits|Maximum|Minimum|Bound|Bounds|"
    r"Budget|Quota|Ceiling|Cap|Capacity)[A-Za-z0-9_]*)$"
)
TYPESCRIPT_CONSTANT_DECLARATION = re.compile(
    r"(?m)^(?:export\s+)?const\s+(?P<name>[A-Z][A-Z0-9_]*)\s*(?::[^=\r\n]+)?="
)
MIGRATION_FORMAT_IDENTIFIER = re.compile(
    r"(?i)\b(?P<identifier>[a-z][a-z0-9_]*(?:schema|version|epoch)[a-z0-9_]*)"
    r"\s*(?:<>|!=|(?<![<>!=])=(?!=))\s*(?P<value>\d+)\b"
)
MIGRATION_FORMAT_DEFAULT = re.compile(
    r"(?i)\b(?P<identifier>[a-z][a-z0-9_]*(?:schema|version|epoch)[a-z0-9_]*)"
    r"\s+(?:smallint|integer|bigint)\b[^,;\r\n]*\bdefault\s+(?P<value>1)\b"
)
MIGRATION_EMBEDDED_JSON_LITERAL = re.compile(
    r'(?i)"(?P<identifier>schema|schema_version|version|derivation)"'
    r"\s*:\s*(?P<value>\d+)\b"
)
MIGRATION_MEDIA_TYPE_LITERAL = re.compile(
    r"(?i)\b(?P<identifier>[a-z][a-z0-9_]*_media_type)"
    r"\s*=\s*'(?P<value>(?:application|text)/[^']+)'"
)
PRODUCTION_FORMAT_COMPARISON = re.compile(
    r"(?i)\b(?P<identifier>[a-z][a-z0-9_]*(?:schema|version|epoch)[a-z0-9_]*)"
    r"\s*(?:==|!=|<>|(?<![<>!=])=(?!=))\s*"
    r"\d+(?:_[a-z0-9]+|[a-z][a-z0-9]*)?\b"
)
PRODUCTION_JSON_FORMAT_LITERAL = re.compile(
    r"(?i)(?:\\?[\"'])"
    r"(?P<identifier>schema|schema_version|version)"
    r"(?:\\?[\"'])\s*:\s*\d+\b"
)
PRODUCTION_MEDIA_COMPARISON = re.compile(
    r"(?i)(?:\b[a-z][a-z0-9_]*_media_type|\.media_type\(\))"
    r"\s*(?:==|!=|<>|=)\s*(?:\\?[\"'])(?:application|text)/"
)
PRODUCTION_TEST_CFG = re.compile(
    r"(?m)^\s*#\[\s*cfg\s*\([^]]*\btest\b[^]]*\)\s*\]"
)


class GovernanceError(ValueError):
    """The foundation governance registry is malformed or has drifted."""


def _fail(message: str) -> None:
    raise GovernanceError(message)


def _object(
    value: Any,
    keys: set[str],
    context: str,
    *,
    optional: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{context} must be an object")
    optional = optional or set()
    actual = set(value)
    if not keys.issubset(actual) or not actual.issubset(keys | optional):
        missing = sorted(keys - actual)
        unknown = sorted(actual - keys - optional)
        details: list[str] = []
        if missing:
            details.append(f"missing {missing}")
        if unknown:
            details.append(f"unknown {unknown}")
        _fail(f"{context} has invalid keys: {', '.join(details)}")
    return value


def _array(value: Any, context: str, *, nonempty: bool = False) -> list[Any]:
    if not isinstance(value, list):
        _fail(f"{context} must be an array")
    if nonempty and not value:
        _fail(f"{context} must not be empty")
    return value


def _string(value: Any, context: str, *, identifier: bool = False) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        _fail(f"{context} must be a non-empty trimmed string")
    if any(ord(character) < 0x20 for character in value):
        _fail(f"{context} must not contain control characters")
    if identifier and IDENTIFIER.fullmatch(value) is None:
        _fail(f"{context} must be a lowercase dotted or hyphenated identifier")
    return value


def _positive_integer(value: Any, context: str, *, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        _fail(f"{context} must be a positive integer")
    if maximum is not None and value > maximum:
        _fail(f"{context} must be at most {maximum}")
    return value


def _sorted_unique(values: list[str], context: str) -> None:
    if len(values) != len(set(values)):
        _fail(f"{context} must be unique")
    if values != sorted(values):
        _fail(f"{context} must be sorted")


def _relative_path(value: Any, context: str) -> PurePosixPath:
    text = _string(value, context)
    if "\\" in text:
        _fail(f"{context} must use forward slashes")
    path = PurePosixPath(text)
    if path.is_absolute() or path.as_posix() != text or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        _fail(f"{context} must be a canonical repository-relative path")
    return path


def _existing_path(
    repository_root: Path,
    value: Any,
    context: str,
    *,
    kind: str | None = None,
) -> Path:
    relative = _relative_path(value, context)
    candidate = repository_root.joinpath(*relative.parts)
    try:
        resolved = candidate.resolve(strict=True)
    except (FileNotFoundError, OSError) as error:
        _fail(f"{context} does not exist: {relative.as_posix()} ({error})")
    try:
        resolved.relative_to(repository_root)
    except ValueError:
        _fail(f"{context} escapes the repository: {relative.as_posix()}")

    cursor = repository_root
    for part in relative.parts:
        cursor /= part
        if cursor.is_symlink():
            _fail(f"{context} must not traverse a symlink: {relative.as_posix()}")
    if kind == "file" and not resolved.is_file():
        _fail(f"{context} must name a regular file: {relative.as_posix()}")
    if kind == "directory" and not resolved.is_dir():
        _fail(f"{context} must name a directory: {relative.as_posix()}")
    return resolved


def _load_registry(path: Path) -> dict[str, Any]:
    try:
        source = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeError) as error:
        _fail(f"cannot read {REGISTRY_PATH.as_posix()}: {error}")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                _fail(f"registry contains duplicate JSON key {key!r}")
            result[key] = value
        return result

    normalized_source = source.replace("\r\n", "\n")
    if "\r" in normalized_source:
        _fail("registry contains an unsupported carriage return")

    try:
        document = json.loads(normalized_source, object_pairs_hook=reject_duplicate_keys)
    except GovernanceError:
        raise
    except (json.JSONDecodeError, UnicodeError) as error:
        _fail(f"registry is not valid UTF-8 JSON: {error}")

    canonical = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if normalized_source != canonical:
        _fail(
            "registry is not canonical JSON; use indent=2, sort_keys=True, and one final newline"
        )
    return _object(document, TOP_LEVEL_KEYS, "registry")


def _load_store_migration_format_map(path: Path) -> dict[str, Any]:
    try:
        source = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeError) as error:
        _fail(
            "cannot read "
            f"{STORE_MIGRATION_FORMAT_MAP_PATH.as_posix()}: {error}"
        )

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                _fail(f"store migration format map contains duplicate JSON key {key!r}")
            result[key] = value
        return result

    normalized_source = source.replace("\r\n", "\n")
    if "\r" in normalized_source:
        _fail("store migration format map contains an unsupported carriage return")
    try:
        document = json.loads(normalized_source, object_pairs_hook=reject_duplicate_keys)
    except GovernanceError:
        raise
    except (json.JSONDecodeError, UnicodeError) as error:
        _fail(f"store migration format map is not valid UTF-8 JSON: {error}")

    canonical = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if normalized_source != canonical:
        _fail(
            "store migration format map is not canonical JSON; use indent=2, "
            "sort_keys=True, and one final newline"
        )
    return _object(
        document,
        {
            "contracts",
            "embedded_json_contracts",
            "expected_value",
            "media_type_contracts",
            "migration",
            "schema_version",
        },
        "store migration format map",
    )


def _validate_owner_reference(owner: Any, owner_ids: set[str], context: str) -> None:
    identifier = _string(owner, context, identifier=True)
    if identifier not in owner_ids:
        _fail(f"{context} references unknown owner {identifier!r}")


def _validate_sources(
    repository_root: Path,
    values: Any,
    context: str,
) -> list[str]:
    sources = _array(values, context, nonempty=True)
    fragments: list[str] = []
    identities: list[tuple[str, str]] = []
    for index, raw_source in enumerate(sources):
        source_context = f"{context}[{index}]"
        source = _object(raw_source, {"contains", "path"}, source_context)
        relative = _string(source["path"], f"{source_context}.path")
        path = _existing_path(
            repository_root,
            relative,
            f"{source_context}.path",
            kind="file",
        )
        fragment = _string(source["contains"], f"{source_context}.contains")
        try:
            contents = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            _fail(f"cannot read source binding {relative}: {error}")
        occurrences = contents.count(fragment)
        if occurrences != 1:
            _fail(
                f"{source_context} fragment must occur exactly once in {relative}; "
                f"found {occurrences}"
            )
        fragments.append(fragment)
        identities.append((relative, fragment))
    if len(identities) != len(set(identities)):
        _fail(f"{context} contains duplicate source bindings")
    return fragments


def _fragment_binds_integer(fragment: str, value: int) -> bool:
    if value == 1 and "NonZeroU16::MIN" in fragment:
        return True
    normalized = fragment.replace("_", "")
    numeric_literal = re.search(
        rf"(?<![A-Za-z0-9_]){value}(?![A-Za-z0-9_])",
        normalized,
    )
    version_identifier = re.search(
        rf"(?<![A-Za-z0-9_])v{value}(?![A-Za-z0-9_])",
        normalized,
        flags=re.IGNORECASE,
    )
    if numeric_literal is not None or version_identifier is not None:
        return True
    if "const" not in fragment or "=" not in fragment:
        return False
    expression = fragment.partition("=")[2].rsplit(";", 1)[0].strip()
    expression = re.sub(
        r"(?<=\d)_(?:u|i)(?:8|16|32|64|128|size)\b|"
        r"(?<=\d)(?:u|i)(?:8|16|32|64|128|size)\b",
        "",
        expression,
    )
    expression = re.sub(r"(?<=\d)_(?=\d)", "", expression)
    try:
        parsed = ast.parse(expression, mode="eval")
    except SyntaxError:
        return False

    def evaluate(node: ast.AST) -> int | None:
        if isinstance(node, ast.Expression):
            return evaluate(node.body)
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
            operand = evaluate(node.operand)
            if operand is None:
                return None
            return operand if isinstance(node.op, ast.UAdd) else -operand
        if isinstance(node, ast.BinOp) and isinstance(
            node.op, (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv)
        ):
            left = evaluate(node.left)
            right = evaluate(node.right)
            if left is None or right is None:
                return None
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            return None if right == 0 else left // right
        return None

    return evaluate(parsed) == value


def _format_version(value: Any, context: str) -> int | str:
    if isinstance(value, bool):
        _fail(f"{context} must be a positive integer or canonical version token")
    if isinstance(value, int):
        return _positive_integer(value, context, maximum=65535)
    token = _string(value, context)
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:+/-]{0,127}", token) is None:
        _fail(f"{context} must be a positive integer or canonical version token")
    return token


def _prior_format_versions(version: int | str) -> list[int | str] | None:
    """Returns every required prior token for a monotonically versioned format."""

    if isinstance(version, int):
        return list(range(1, version))
    match = re.fullmatch(
        r"(?P<prefix>(?:v|.*[-_.+/]v))(?P<ordinal>[1-9][0-9]*)"
        r"(?P<suffix>(?:[-_.+/].*)?)",
        version,
        flags=re.IGNORECASE,
    )
    if match is None:
        return None
    ordinal = int(match.group("ordinal"))
    return [
        f"{match.group('prefix')}{prior}{match.group('suffix')}"
        for prior in range(1, ordinal)
    ]


def _fragment_binds_version(fragment: str, version: int | str) -> bool:
    if isinstance(version, int):
        return _fragment_binds_integer(fragment, version)
    return f'"{version}"' in fragment


def _fragment_binds_reason(fragment: str, reason_code: str) -> bool:
    if "::" not in reason_code:
        return f'"{reason_code}"' in fragment
    return (
        re.search(
            rf"(?<![A-Za-z0-9_]){re.escape(reason_code)}(?![A-Za-z0-9_])",
            fragment,
        )
        is not None
    )


def _braced_function_section(
    source: str,
    match: re.Match[str],
    function: str,
    context: str,
) -> str:
    body_start = source.find("{", match.end())
    if body_start < 0:
        _fail(f"{context} cannot locate body for test function {function!r}")

    depth = 1
    index = body_start + 1
    while index < len(source) and depth:
        if source.startswith("//", index):
            newline = source.find("\n", index + 2)
            index = len(source) if newline < 0 else newline + 1
            continue
        if source.startswith("/*", index):
            comment_depth = 1
            index += 2
            while index < len(source) and comment_depth:
                if source.startswith("/*", index):
                    comment_depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    comment_depth -= 1
                    index += 2
                else:
                    index += 1
            continue

        raw_string = re.match(r'(?:b)?r(?P<hashes>#{0,255})"', source[index:])
        if raw_string is not None:
            terminator = '"' + raw_string.group("hashes")
            end = source.find(terminator, index + raw_string.end())
            index = len(source) if end < 0 else end + len(terminator)
            continue
        if source.startswith('b"', index) or source[index] == '"':
            index += 2 if source.startswith('b"', index) else 1
            while index < len(source):
                if source[index] == "\\":
                    index += 2
                elif source[index] == '"':
                    index += 1
                    break
                else:
                    index += 1
            continue
        character = re.match(r"(?:b)?'(?:\\.|[^\\'\r\n])'", source[index:])
        if character is not None:
            index += character.end()
            continue

        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
        index += 1
    if depth:
        _fail(f"{context} cannot locate body end for test function {function!r}")
    end = index
    return source[match.start() : end]


def _rust_test_section(source: str, function: str, context: str) -> str:
    pattern = re.compile(RUST_TEST_FUNCTION.format(name=re.escape(function)))
    match = pattern.search(source)
    if match is None or RUST_TEST_ATTRIBUTE.search(match.group("attributes")) is None:
        _fail(f"{context} names missing test function {function!r} with a test attribute")
    return _braced_function_section(source, match, function, context)


def _typescript_test_section(source: str, function: str, context: str) -> str:
    pattern = re.compile(TYPESCRIPT_TEST_FUNCTION.format(name=re.escape(function)))
    match = pattern.search(source)
    registration = re.compile(
        rf"\b(?:it|test)\s*\(\s*(['\"]).*?\1\s*,\s*{re.escape(function)}\s*,?\s*\)",
        re.DOTALL,
    )
    if match is None or registration.search(source) is None:
        _fail(
            f"{context} names missing TypeScript test function {function!r} "
            "registered with it() or test()"
        )
    return _braced_function_section(source, match, function, context)


def _bound_test_section(path: Path, source: str, function: str, context: str) -> str:
    if path.suffix == ".rs":
        return _rust_test_section(source, function, context)
    if path.suffix in {".ts", ".tsx"}:
        return _typescript_test_section(source, function, context)
    _fail(f"{context}.path must name a Rust or TypeScript test source")


def _mask_source_comments(source: str, *, typescript: bool = False) -> str:
    """Mask comments while retaining byte offsets, strings, and line endings."""

    masked = list(source)
    index = 0
    while index < len(source):
        raw_string = re.match(r'(?:b|c)?r(?P<hashes>#{0,255})"', source[index:])
        if raw_string is not None:
            terminator = '"' + raw_string.group("hashes")
            end = source.find(terminator, index + raw_string.end())
            index = len(source) if end < 0 else end + len(terminator)
            continue
        rust_character = re.match(r"(?:b)?'(?:\\.|[^\\'\r\n])'", source[index:])
        if rust_character is not None and not typescript:
            index += rust_character.end()
            continue
        is_quoted = (
            source.startswith('b"', index)
            or source[index] in {'"', "`"}
            or (typescript and source[index] == "'")
        )
        if is_quoted:
            quote = source[index + 1] if source.startswith('b"', index) else source[index]
            index += 2 if source.startswith('b"', index) else 1
            while index < len(source):
                if source[index] == "\\":
                    index += 2
                elif source[index] == quote:
                    index += 1
                    break
                else:
                    index += 1
            continue
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            end = len(source) if end < 0 else end
            for offset in range(index, end):
                if masked[offset] not in {"\r", "\n"}:
                    masked[offset] = " "
            index = end
            continue
        if source.startswith("/*", index):
            start = index
            depth = 1
            index += 2
            while index < len(source) and depth:
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            for offset in range(start, index):
                if masked[offset] not in {"\r", "\n"}:
                    masked[offset] = " "
            continue
        index += 1
    return "".join(masked)


def _validate_test_bindings(repository_root: Path, values: Any, context: str) -> None:
    bindings = _array(values, context, nonempty=True)
    identities: list[str] = []
    for index, raw_binding in enumerate(bindings):
        binding_context = f"{context}[{index}]"
        binding = _object(raw_binding, {"contains", "function", "path"}, binding_context)
        relative = _string(binding["path"], f"{binding_context}.path")
        function = _string(binding["function"], f"{binding_context}.function")
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", function) is None:
            _fail(f"{binding_context}.function must be a function name")
        path = _existing_path(
            repository_root,
            relative,
            f"{binding_context}.path",
            kind="file",
        )
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            _fail(f"cannot read format test {relative}: {error}")
        section = _bound_test_section(path, source, function, binding_context)
        fragment = _string(binding["contains"], f"{binding_context}.contains")
        if section.count(fragment) != 1:
            _fail(
                f"{binding_context}.contains must occur exactly once in test "
                f"{function!r}"
            )
        identities.append(f"{relative}::{function}")
    _sorted_unique(identities, context)


def _validate_prior_reader_tests(
    repository_root: Path,
    values: Any,
    version: int | str,
    reader_symbol: str,
    context: str,
) -> None:
    bindings = _array(values, context, nonempty=True)
    identities: list[str] = []
    for index, raw_binding in enumerate(bindings):
        binding_context = f"{context}[{index}]"
        binding = _object(
            raw_binding,
            {"function", "outcome", "path", "reader_call", "version"},
            binding_context,
        )
        relative = _string(binding["path"], f"{binding_context}.path")
        function = _string(binding["function"], f"{binding_context}.function")
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", function) is None:
            _fail(f"{binding_context}.function must be a function name")
        path = _existing_path(
            repository_root,
            relative,
            f"{binding_context}.path",
            kind="file",
        )
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            _fail(f"cannot read compatibility-reader test {relative}: {error}")
        section = _bound_test_section(path, source, function, binding_context)
        version_fragment = _string(binding["version"], f"{binding_context}.version")
        reader_call = _string(binding["reader_call"], f"{binding_context}.reader_call")
        outcome = _string(binding["outcome"], f"{binding_context}.outcome")
        if len({version_fragment, reader_call, outcome}) != 3:
            _fail(
                f"{binding_context} must use distinct version, reader_call, and "
                "outcome fragments"
            )
        if not _fragment_binds_version(version_fragment, version):
            _fail(f"{binding_context}.version must bind prior version {version}")
        if re.search(rf"\b{re.escape(reader_symbol)}\s*\(", reader_call) is None:
            _fail(
                f"{binding_context}.reader_call must invoke declared reader "
                f"{reader_symbol!r}"
            )
        if reader_call not in outcome or re.search(
            r"(?:\bassert(?:_[A-Za-z0-9_]+)?!\s*\(|\bmatches!\s*\(|"
            r"\.expect(?:_err)?\s*\()",
            outcome,
        ) is None:
            _fail(
                f"{binding_context}.outcome must assert the declared reader_call result"
            )
        if path.suffix == ".rs":
            pattern = re.compile(RUST_TEST_FUNCTION.format(name=re.escape(function)))
            match = pattern.search(source)
            if match is None:
                _fail(f"{binding_context} names missing Rust test function {function!r}")
            attributes = match.group("attributes")
            if re.search(r"#\[\s*(?:ignore|cfg(?:_attr)?\b)", attributes):
                _fail(
                    f"{binding_context} compatibility-reader test must not be ignored "
                    "or cfg-gated"
                )
        body_start = section.find("{")
        body = section[body_start + 1 : -1] if body_start >= 0 else ""
        code = _mask_source_comments(body, typescript=path.suffix in {".ts", ".tsx"})
        for label, fragment in (
            ("version", version_fragment),
            ("reader_call", reader_call),
            ("outcome", outcome),
        ):
            if code.count(fragment) != 1:
                _fail(
                    f"{binding_context}.{label} must occur exactly once inside the "
                    "compatibility-reader test body outside comments"
                )
        identities.append(f"{relative}::{function}")
    _sorted_unique(identities, context)


def _validate_prior_version_readers(
    repository_root: Path,
    values: Any,
    expected_versions: list[int | str],
    context: str,
) -> None:
    readers = _array(values, context, nonempty=True)
    actual_versions: list[int | str] = []
    for index, raw_reader in enumerate(readers):
        reader_context = f"{context}[{index}]"
        reader = _object(raw_reader, {"reader", "tests", "version"}, reader_context)
        version = _format_version(reader["version"], f"{reader_context}.version")
        actual_versions.append(version)
        source = _object(
            reader["reader"],
            {"contains", "path", "symbol"},
            f"{reader_context}.reader",
        )
        symbol = _string(source["symbol"], f"{reader_context}.reader.symbol")
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", symbol) is None:
            _fail(f"{reader_context}.reader.symbol must be a Rust function name")
        fragment = _validate_sources(
            repository_root,
            [{"contains": source["contains"], "path": source["path"]}],
            f"{reader_context}.reader",
        )[0]
        if not _fragment_binds_version(fragment, version):
            _fail(f"{reader_context}.reader must bind prior version {version}")
        reader_path = _existing_path(
            repository_root,
            _string(source["path"], f"{reader_context}.reader.path"),
            f"{reader_context}.reader.path",
            kind="file",
        )
        try:
            reader_source = reader_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            _fail(f"cannot read compatibility reader source {reader_path}: {error}")
        reader_match = re.compile(RUST_FUNCTION.format(name=re.escape(symbol))).search(
            reader_source
        )
        if reader_match is None:
            _fail(f"{reader_context}.reader.symbol names no Rust function {symbol!r}")
        reader_section = _braced_function_section(
            reader_source,
            reader_match,
            symbol,
            f"{reader_context}.reader",
        )
        if _mask_source_comments(reader_section).count(fragment) != 1:
            _fail(
                f"{reader_context}.reader fragment must occur exactly once inside "
                f"declared reader {symbol!r} outside comments"
            )
        _validate_prior_reader_tests(
            repository_root,
            reader["tests"],
            version,
            symbol,
            f"{reader_context}.tests",
        )
    if actual_versions != expected_versions:
        _fail(
            f"{context} must cover every prior version: expected {expected_versions}, "
            f"found {actual_versions}"
        )


def _validate_format_sources(
    repository_root: Path,
    values: Any,
    version: int | str,
    context: str,
) -> None:
    sources = _array(values, context, nonempty=True)
    identities: list[tuple[str, str]] = []
    version_binding_count = 0
    for index, raw_source in enumerate(sources):
        source_context = f"{context}[{index}]"
        source = _object(raw_source, {"contains", "path", "role"}, source_context)
        role = _string(source["role"], f"{source_context}.role", identifier=True)
        if role not in {"evidence", "version"}:
            _fail(f"{source_context}.role must be 'evidence' or 'version'")
        fragments = _validate_sources(
            repository_root,
            [{"contains": source["contains"], "path": source["path"]}],
            source_context,
        )
        fragment = fragments[0]
        if role == "version":
            version_binding_count += 1
            if not _fragment_binds_version(fragment, version):
                _fail(f"{source_context} does not bind declared version {version}")
        identities.append((_string(source["path"], f"{source_context}.path"), fragment))
    if version_binding_count == 0:
        _fail(f"{context} must contain at least one version binding")
    if len(identities) != len(set(identities)):
        _fail(f"{context} contains duplicate source bindings")


def _validate_owners(values: Any) -> set[str]:
    owners = _array(values, "owners", nonempty=True)
    owner_ids: list[str] = []
    for index, raw_owner in enumerate(owners):
        context = f"owners[{index}]"
        owner = _object(raw_owner, {"description", "id"}, context)
        owner_ids.append(_string(owner["id"], f"{context}.id", identifier=True))
        _string(owner["description"], f"{context}.description")
    _sorted_unique(owner_ids, "owner IDs")
    return set(owner_ids)


def _validate_format_scope(repository_root: Path, value: Any) -> None:
    scope = _object(
        value,
        {
            "declaration_roots",
            "includes",
            "migration_map",
            "unversioned_public_json_apis",
        },
        "format_scope",
    )
    declaration_roots = [
        _string(item, f"format_scope.declaration_roots[{index}]")
        for index, item in enumerate(
            _array(scope["declaration_roots"], "format_scope.declaration_roots", nonempty=True)
        )
    ]
    if declaration_roots != ["crates/*/src/**/*.rs", "ui/src/**/*.{ts,tsx}"]:
        _fail("format_scope.declaration_roots must match the validator's governed roots")
    includes = [
        _string(item, f"format_scope.includes[{index}]", identifier=True)
        for index, item in enumerate(_array(scope["includes"], "format_scope.includes", nonempty=True))
    ]
    if includes != [
        "named-versioned-internal-durable-formats",
        "named-versioned-internal-wire-formats",
    ]:
        _fail("format_scope.includes must state the complete governed format classes")
    migration_map = _string(scope["migration_map"], "format_scope.migration_map")
    if migration_map != STORE_MIGRATION_FORMAT_MAP_PATH.as_posix():
        _fail("format_scope.migration_map must name the canonical Store format map")
    _existing_path(repository_root, migration_map, "format_scope.migration_map", kind="file")
    if scope["unversioned_public_json_apis"] != "out-of-scope":
        _fail("format_scope.unversioned_public_json_apis must be 'out-of-scope'")


def _validate_formats(repository_root: Path, values: Any, owner_ids: set[str]) -> None:
    formats = _array(values, "formats", nonempty=True)
    format_ids: list[str] = []
    for index, raw_format in enumerate(formats):
        context = f"formats[{index}]"
        format_contract = _object(
            raw_format,
            {"compatibility_policy", "id", "owner", "sources", "tests", "version"},
            context,
            optional={"prior_version_readers"},
        )
        format_ids.append(_string(format_contract["id"], f"{context}.id", identifier=True))
        _validate_owner_reference(format_contract["owner"], owner_ids, f"{context}.owner")
        compatibility_policy = _string(
            format_contract["compatibility_policy"],
            f"{context}.compatibility_policy",
            identifier=True,
        )
        if compatibility_policy not in FORMAT_COMPATIBILITY_POLICIES:
            _fail(
                f"{context}.compatibility_policy must be one of "
                f"{sorted(FORMAT_COMPATIBILITY_POLICIES)}"
            )
        version = _format_version(format_contract["version"], f"{context}.version")
        _validate_format_sources(
            repository_root,
            format_contract["sources"],
            version,
            f"{context}.sources",
        )
        prior_versions = _prior_format_versions(version)
        if prior_versions:
            if compatibility_policy != "backward-compatible":
                _fail(
                    f"{context}.compatibility_policy {compatibility_policy!r} cannot "
                    f"declare sequenced version {version}; use 'backward-compatible' "
                    "and bind readers for every prior version"
                )
            if "prior_version_readers" not in format_contract:
                _fail(
                    f"{context} version {version} requires prior_version_readers "
                    f"for {prior_versions}"
                )
            _validate_prior_version_readers(
                repository_root,
                format_contract["prior_version_readers"],
                prior_versions,
                f"{context}.prior_version_readers",
            )
        else:
            if compatibility_policy == "backward-compatible":
                _fail(
                    f"{context}.compatibility_policy 'backward-compatible' requires "
                    "a sequenced version greater than v1"
                )
            if "prior_version_readers" in format_contract:
                _fail(
                    f"{context}.prior_version_readers is only valid for a sequenced "
                    "version greater than v1"
                )
        _validate_test_bindings(repository_root, format_contract["tests"], f"{context}.tests")
    _sorted_unique(format_ids, "format IDs")


def _constant_declaration_fragment(source: str, match: re.Match[str]) -> str:
    end = source.find(";", match.end())
    if end < 0:
        end = source.find("\n", match.end())
    if end < 0:
        end = len(source)
    else:
        end += 1
    return source[match.start() : end]


def _is_format_declaration(name: str, declaration: str = "") -> bool:
    components = name.split("_")
    return (
        "SCHEMA" in components
        or "VERSION" in components
        or any(component.startswith("SCHEMA") for component in components)
        or name.endswith("_MEDIA_TYPE")
        or name.endswith("_FORMAT")
        or (
            name.endswith("_COMMAND")
            and re.search(
                r"=\s*['\"][A-Za-z0-9._:+/-]*[-_.]v[1-9][0-9]*['\"]\s*;?",
                declaration,
                flags=re.IGNORECASE,
            )
            is not None
        )
    )


def _format_declarations(repository_root: Path) -> set[tuple[str, str]]:
    declarations: set[tuple[str, str]] = set()
    crates = repository_root / "crates"
    for path in sorted(crates.glob("*/src/**/*.rs")):
        if path.is_symlink() or not path.is_file():
            _fail(f"format discovery encountered a non-regular Rust source: {path}")
        if _is_test_only_rust_source(path):
            continue
        source = _production_source(path)
        relative = path.relative_to(repository_root).as_posix()
        for match in RUST_CONSTANT_DECLARATION.finditer(source):
            name = match.group("name")
            declaration = _constant_declaration_fragment(source, match)
            if _is_format_declaration(name, declaration):
                declarations.add((relative, name))
    ui = repository_root / "ui" / "src"
    if ui.exists():
        for path in sorted([*ui.rglob("*.ts"), *ui.rglob("*.tsx")]):
            if path.is_symlink() or not path.is_file():
                _fail(f"format discovery encountered a non-regular TypeScript source: {path}")
            if path.name.endswith((".test.ts", ".test.tsx", ".spec.ts", ".spec.tsx")):
                continue
            source = path.read_text(encoding="utf-8")
            relative = path.relative_to(repository_root).as_posix()
            for match in TYPESCRIPT_CONSTANT_DECLARATION.finditer(source):
                name = match.group("name")
                declaration = _constant_declaration_fragment(source, match)
                if _is_format_declaration(name, declaration):
                    declarations.add((relative, name))
    return declarations


def _registered_format_declarations(values: Any) -> set[tuple[str, str]]:
    declarations: set[tuple[str, str]] = set()
    for raw_format in values:
        for source in raw_format["sources"]:
            fragment = source["contains"]
            match = RUST_CONSTANT_DECLARATION.search(fragment)
            if match is None:
                match = TYPESCRIPT_CONSTANT_DECLARATION.search(fragment)
            if match is not None and _is_format_declaration(match.group("name"), fragment):
                declarations.add((source["path"], match.group("name")))
    return declarations


def _validate_format_exclusions(
    repository_root: Path,
    values: Any,
    formats: Any,
) -> None:
    exclusions = _array(values, "format_exclusions")
    excluded: list[tuple[str, str]] = []
    for index, raw_exclusion in enumerate(exclusions):
        context = f"format_exclusions[{index}]"
        exclusion = _object(raw_exclusion, {"constant", "path", "reason"}, context)
        relative = _string(exclusion["path"], f"{context}.path")
        path = _existing_path(
            repository_root,
            relative,
            f"{context}.path",
            kind="file",
        )
        constant = _string(exclusion["constant"], f"{context}.constant")
        if re.fullmatch(r"[A-Z][A-Z0-9_]*", constant) is None:
            _fail(f"{context}.constant must be an uppercase Rust constant name")
        _string(exclusion["reason"], f"{context}.reason")
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            _fail(f"cannot read format exclusion source {relative}: {error}")
        declaration_pattern = (
            TYPESCRIPT_CONSTANT_DECLARATION
            if path.suffix in {".ts", ".tsx"}
            else RUST_CONSTANT_DECLARATION
        )
        if not any(
            match.group("name") == constant
            and _is_format_declaration(
                match.group("name"),
                _constant_declaration_fragment(source, match),
            )
            for match in declaration_pattern.finditer(source)
        ):
            _fail(f"{context} does not bind a discovered format declaration")
        excluded.append((relative, constant))
    if len(excluded) != len(set(excluded)):
        _fail("format exclusions must be unique")
    if excluded != sorted(excluded):
        _fail("format exclusions must be sorted by path and constant")

    registered = _registered_format_declarations(formats)
    overlap = registered.intersection(excluded)
    if overlap:
        _fail(f"format declarations cannot be both registered and excluded: {sorted(overlap)}")
    discovered = _format_declarations(repository_root)
    accounted = registered.union(excluded)
    missing = sorted(discovered - accounted)
    stale = sorted(accounted - discovered)
    if missing:
        _fail(f"unregistered format declarations: {missing}")
    if stale:
        _fail(f"stale registered or excluded format declarations: {stale}")


def _is_test_only_rust_source(path: Path) -> bool:
    stem = path.stem.lower()
    return stem in {"test", "tests"} or stem.endswith(("_test", "_tests")) or any(
        part.lower() == "tests" for part in path.parts
    )


def _validate_migrations(repository_root: Path, value: Any, owner_ids: set[str]) -> None:
    migrations = _object(
        value,
        {
            "current",
            "directory",
            "mode",
            "next_sequence",
            "owner",
            "reservations",
            "sha256",
        },
        "migrations",
    )
    _validate_owner_reference(migrations["owner"], owner_ids, "migrations.owner")
    mode = _string(migrations["mode"], "migrations.mode", identifier=True)
    if mode != "greenfield-canonical-baseline":
        _fail("migrations.mode must be 'greenfield-canonical-baseline'")
    if migrations["directory"] != "crates/automata-ci-store/migrations":
        _fail("migrations.directory must be 'crates/automata-ci-store/migrations'")
    directory = _existing_path(
        repository_root,
        migrations["directory"],
        "migrations.directory",
        kind="directory",
    )

    current_values = _array(migrations["current"], "migrations.current", nonempty=True)
    current = [
        _string(item, f"migrations.current[{index}]")
        for index, item in enumerate(current_values)
    ]
    _sorted_unique(current, "migrations.current")
    if current != ["0001_initial_schema.sql"]:
        _fail("greenfield migration inventory must be exactly ['0001_initial_schema.sql']")

    actual: list[str] = []
    for entry in directory.iterdir():
        if entry.is_symlink() or not entry.is_file():
            _fail(f"migration directory contains a non-regular entry: {entry.name}")
        actual.append(entry.name)
    actual.sort()
    if actual != current:
        _fail(f"migration inventory drift: registry has {current}, filesystem has {actual}")

    expected_sha256 = _string(migrations["sha256"], "migrations.sha256")
    if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        _fail("migrations.sha256 must be lowercase hexadecimal SHA-256")
    migration_path = directory / current[0]
    try:
        migration_bytes = migration_path.read_bytes().replace(b"\r\n", b"\n")
    except OSError as error:
        _fail(f"cannot hash canonical migration {current[0]}: {error}")
    if b"\r" in migration_bytes:
        _fail(f"canonical migration {current[0]} contains an unsupported carriage return")
    actual_sha256 = hashlib.sha256(migration_bytes).hexdigest()
    if actual_sha256 != expected_sha256:
        _fail(
            "canonical migration content drift: "
            f"registry has {expected_sha256}, filesystem has {actual_sha256}"
        )

    reservations = _array(migrations["reservations"], "migrations.reservations")
    if reservations:
        _fail("greenfield canonical baseline must not reserve migration numbers")
    if migrations["next_sequence"] is not None:
        _fail("greenfield canonical baseline migrations.next_sequence must be null")


def _validate_store_migration_format_map(
    repository_root: Path,
    formats: Any,
    migrations: Any,
) -> set[str]:
    map_path = _existing_path(
        repository_root,
        STORE_MIGRATION_FORMAT_MAP_PATH.as_posix(),
        "store migration format map path",
        kind="file",
    )
    document = _load_store_migration_format_map(map_path)
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        _fail("store migration format map schema_version must be integer 1")
    expected_value = _positive_integer(
        document["expected_value"],
        "store migration format map.expected_value",
    )

    migration_contract = _object(
        migrations,
        {
            "current",
            "directory",
            "mode",
            "next_sequence",
            "owner",
            "reservations",
            "sha256",
        },
        "migrations",
    )
    current = _array(migration_contract["current"], "migrations.current", nonempty=True)
    migration_name = _string(document["migration"], "store migration format map.migration")
    if current != [migration_name]:
        _fail(
            "store migration format map must name the hash-pinned canonical migration"
        )
    migration_path = _existing_path(
        repository_root,
        f"{migration_contract['directory']}/{migration_name}",
        "store migration format map migration",
        kind="file",
    )
    try:
        migration_source = migration_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        _fail(f"cannot read mapped canonical migration {migration_name}: {error}")

    format_versions = {
        _string(raw_format["id"], f"formats[{index}].id", identifier=True): raw_format[
            "version"
        ]
        for index, raw_format in enumerate(_array(formats, "formats", nonempty=True))
    }
    contracts = _array(document["contracts"], "store migration format map.contracts")
    identifiers: list[str] = []
    mapped_identifiers: set[str] = set()
    for index, raw_contract in enumerate(contracts):
        context = f"store migration format map.contracts[{index}]"
        contract = _object(raw_contract, {"format_ids", "identifier", "reason"}, context)
        identifier = _string(contract["identifier"], f"{context}.identifier")
        if (
            identifier != identifier.lower()
            or re.fullmatch(
                r"[a-z][a-z0-9_]*(?:schema|version|epoch)[a-z0-9_]*",
                identifier,
            )
            is None
        ):
            _fail(f"{context}.identifier must be a lowercase schema/version/epoch name")
        identifiers.append(identifier)

        raw_format_ids = _array(contract["format_ids"], f"{context}.format_ids")
        bound_format_ids = [
            _string(value, f"{context}.format_ids[{format_index}]", identifier=True)
            for format_index, value in enumerate(raw_format_ids)
        ]
        _sorted_unique(bound_format_ids, f"{context}.format_ids")
        unknown = sorted(set(bound_format_ids) - set(format_versions))
        if unknown:
            _fail(f"{context}.format_ids references unknown formats {unknown}")
        wrong_versions = sorted(
            format_id
            for format_id in bound_format_ids
            if format_versions[format_id] != expected_value
        )
        if wrong_versions:
            _fail(
                f"{context}.format_ids do not bind migration value {expected_value}: "
                f"{wrong_versions}"
            )
        reason = _string(contract["reason"], f"{context}.reason")
        if len(reason) < 24:
            _fail(f"{context}.reason must explain the migration binding")
        if bound_format_ids:
            mapped_identifiers.add(identifier)
        elif "not " not in reason.lower():
            _fail(f"{context} without formats must explicitly explain why it is not a format")

    _sorted_unique(identifiers, "store migration format map identifiers")
    discovered_values: dict[str, set[int]] = {}
    for pattern in (MIGRATION_FORMAT_IDENTIFIER, MIGRATION_FORMAT_DEFAULT):
        for match in pattern.finditer(migration_source):
            discovered_values.setdefault(match.group("identifier").lower(), set()).add(
                int(match.group("value"))
            )
    for identifier, value in _migration_insert_format_values(migration_source):
        discovered_values.setdefault(identifier, set()).add(value)
    discovered = set(discovered_values)
    wrong_literals = {
        identifier: sorted(values)
        for identifier, values in discovered_values.items()
        if values != {expected_value}
    }
    if wrong_literals:
        _fail(
            "canonical migration format literals do not match mapped value "
            f"{expected_value}: {wrong_literals}"
        )
    registered = set(identifiers)
    missing = sorted(discovered - registered)
    stale = sorted(registered - discovered)
    if missing or stale:
        _fail(
            "store migration format map is incomplete: "
            f"missing {missing}, stale {stale}"
        )

    embedded_discovered = Counter(
        (f"json.{match.group('identifier').lower()}", int(match.group("value")))
        for match in MIGRATION_EMBEDDED_JSON_LITERAL.finditer(migration_source)
    )
    embedded_contracts = _array(
        document["embedded_json_contracts"],
        "store migration format map.embedded_json_contracts",
    )
    embedded_registered: Counter[tuple[str, int]] = Counter()
    embedded_identifiers: list[str] = []
    for index, raw_contract in enumerate(embedded_contracts):
        context = f"store migration format map.embedded_json_contracts[{index}]"
        contract = _object(
            raw_contract,
            {"format_ids", "identifier", "occurrences", "reason", "value"},
            context,
        )
        identifier = _string(contract["identifier"], f"{context}.identifier")
        if re.fullmatch(r"json\.(?:schema|schema_version|version|derivation)", identifier) is None:
            _fail(f"{context}.identifier is unsupported")
        embedded_identifiers.append(identifier)
        value = _positive_integer(contract["value"], f"{context}.value")
        if value != expected_value:
            _fail(f"{context}.value must equal mapped value {expected_value}")
        occurrences = _positive_integer(contract["occurrences"], f"{context}.occurrences")
        embedded_registered[(identifier, value)] = occurrences
        bound_format_ids = [
            _string(item, f"{context}.format_ids[{format_index}]", identifier=True)
            for format_index, item in enumerate(
                _array(contract["format_ids"], f"{context}.format_ids", nonempty=True)
            )
        ]
        _sorted_unique(bound_format_ids, f"{context}.format_ids")
        unknown = sorted(set(bound_format_ids) - set(format_versions))
        if unknown:
            _fail(f"{context}.format_ids references unknown formats {unknown}")
        wrong_versions = sorted(
            format_id
            for format_id in bound_format_ids
            if format_versions[format_id] != value
        )
        if wrong_versions:
            _fail(f"{context}.format_ids do not bind JSON value {value}: {wrong_versions}")
        if len(_string(contract["reason"], f"{context}.reason")) < 24:
            _fail(f"{context}.reason must explain the embedded JSON binding")
    _sorted_unique(
        embedded_identifiers,
        "store migration embedded JSON identifiers",
    )
    if embedded_registered != embedded_discovered:
        _fail(
            "store migration embedded JSON format map is incomplete: "
            f"registered {dict(embedded_registered)}, discovered {dict(embedded_discovered)}"
        )

    media_discovered = Counter(
        (match.group("identifier").lower(), match.group("value"))
        for match in MIGRATION_MEDIA_TYPE_LITERAL.finditer(migration_source)
    )
    media_contracts = _array(
        document["media_type_contracts"],
        "store migration format map.media_type_contracts",
    )
    media_registered: Counter[tuple[str, str]] = Counter()
    media_identifiers: list[str] = []
    for index, raw_contract in enumerate(media_contracts):
        context = f"store migration format map.media_type_contracts[{index}]"
        contract = _object(
            raw_contract,
            {"format_ids", "identifier", "occurrences", "reason", "value"},
            context,
        )
        identifier = _string(contract["identifier"], f"{context}.identifier")
        if re.fullmatch(r"[a-z][a-z0-9_]*_media_type", identifier) is None:
            _fail(f"{context}.identifier must be a lowercase media-type column")
        media_identifiers.append(identifier)
        value = _string(contract["value"], f"{context}.value")
        if re.fullmatch(r"(?:application|text)/[^\s]+", value) is None:
            _fail(f"{context}.value must be a canonical application/* or text/* media type")
        occurrences = _positive_integer(contract["occurrences"], f"{context}.occurrences")
        media_registered[(identifier, value)] = occurrences
        bound_format_ids = [
            _string(item, f"{context}.format_ids[{format_index}]", identifier=True)
            for format_index, item in enumerate(
                _array(contract["format_ids"], f"{context}.format_ids", nonempty=True)
            )
        ]
        _sorted_unique(bound_format_ids, f"{context}.format_ids")
        unknown = sorted(set(bound_format_ids) - set(format_versions))
        if unknown:
            _fail(f"{context}.format_ids references unknown formats {unknown}")
        string_versions = {
            format_versions[format_id]
            for format_id in bound_format_ids
            if isinstance(format_versions[format_id], str)
        }
        if string_versions and value not in string_versions:
            _fail(f"{context}.value does not match its registered string format version")
        if len(_string(contract["reason"], f"{context}.reason")) < 24:
            _fail(f"{context}.reason must explain the media-type binding")
    _sorted_unique(media_identifiers, "store migration media-type identifiers")
    if media_registered != media_discovered:
        _fail(
            "store migration media-type map is incomplete: "
            f"registered {dict(media_registered)}, discovered {dict(media_discovered)}"
        )
    return mapped_identifiers


def _production_format_sources(repository_root: Path) -> list[Path]:
    sources: list[Path] = []
    crates = repository_root / "crates"
    if crates.is_dir():
        for path in crates.glob("*/src/**/*.rs"):
            relative_parts = path.relative_to(repository_root).parts
            if (
                "tests" in relative_parts
                or path.name in {"test.rs", "tests.rs"}
                or path.name.endswith("_tests.rs")
            ):
                continue
            sources.append(path)
    ui = repository_root / "ui" / "src"
    if ui.is_dir():
        for suffix in ("*.ts", "*.tsx"):
            for path in ui.rglob(suffix):
                if path.name.endswith((".test.ts", ".test.tsx", ".spec.ts", ".spec.tsx")):
                    continue
                sources.append(path)
    return sorted(set(sources))


def _production_source(path: Path) -> str:
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        _fail(f"cannot read production format surface {path}: {error}")
    if path.suffix == ".rs":
        source = _mask_rust_test_modules(source)
        source = _mask_rust_test_functions(source)
    return source


def _matching_rust_brace(source: str, opening: int) -> int | None:
    depth = 1
    index = opening + 1
    while index < len(source):
        if source.startswith("//", index):
            newline = source.find("\n", index + 2)
            index = len(source) if newline < 0 else newline + 1
            continue
        if source.startswith("/*", index):
            comment_depth = 1
            index += 2
            while index < len(source) and comment_depth:
                if source.startswith("/*", index):
                    comment_depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    comment_depth -= 1
                    index += 2
                else:
                    index += 1
            continue

        raw_string = re.match(r'(?:b|c)?r(?P<hashes>#{0,255})"', source[index:])
        if raw_string is not None:
            terminator = '"' + raw_string.group("hashes")
            end = source.find(terminator, index + raw_string.end())
            index = len(source) if end < 0 else end + len(terminator)
            continue
        if source[index] == '"':
            index += 1
            while index < len(source):
                if source[index] == "\\":
                    index += 2
                elif source[index] == '"':
                    index += 1
                    break
                else:
                    index += 1
            continue
        character_literal = re.match(r"'(?:\\.|[^\\'\r\n])'", source[index:])
        if character_literal is not None:
            index += character_literal.end()
            continue
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _mask_rust_test_modules(source: str) -> str:
    spans: list[tuple[int, int]] = []
    module_pattern = re.compile(
        r"\s*(?:#\[[^]]+\]\s*)*(?:pub(?:\([^)]*\))?\s+)?"
        r"mod\s+[A-Za-z_][A-Za-z0-9_]*\s*(?P<delimiter>[{;])",
        flags=re.MULTILINE,
    )
    for configuration in PRODUCTION_TEST_CFG.finditer(source):
        module = module_pattern.match(source, configuration.end())
        if module is None:
            continue
        if module.group("delimiter") == ";":
            end = module.end()
        else:
            closing = _matching_rust_brace(source, module.end() - 1)
            if closing is None:
                _fail("cannot locate the end of a cfg(test) Rust module")
            end = closing + 1
        spans.append((configuration.start(), end))

    if not spans:
        return source
    masked = list(source)
    for start, end in spans:
        for index in range(start, end):
            if masked[index] not in {"\r", "\n"}:
                masked[index] = " "
    return "".join(masked)


def _mask_rust_test_functions(source: str) -> str:
    spans: list[tuple[int, int]] = []
    function_pattern = re.compile(
        r"(?m)^(?P<attributes>(?:[ \t]*#\[[^]]+\][ \t]*\r?\n)+)"
        r"[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>]*>)?\s*\("
    )
    for function in function_pattern.finditer(source):
        if RUST_TEST_ATTRIBUTE.search(function.group("attributes")) is None:
            continue
        opening = source.find("{", function.end())
        if opening < 0:
            _fail(
                f"cannot locate the body of Rust test function "
                f"{function.group('name')!r}"
            )
        closing = _matching_rust_brace(source, opening)
        if closing is None:
            _fail(
                f"cannot locate the end of Rust test function "
                f"{function.group('name')!r}"
            )
        spans.append((function.start(), closing + 1))

    if not spans:
        return source
    masked = list(source)
    for start, end in spans:
        for index in range(start, end):
            if masked[index] not in {"\r", "\n"}:
                masked[index] = " "
    return "".join(masked)


def _matching_parenthesis(source: str, opening: int) -> int | None:
    depth = 0
    quote: str | None = None
    index = opening
    while index < len(source):
        character = source[index]
        if quote is not None:
            if character == quote:
                if index + 1 < len(source) and source[index + 1] == quote:
                    index += 2
                    continue
                quote = None
            elif character == "\\":
                index += 2
                continue
        elif character in {"'", '"'}:
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _split_sql_list(source: str) -> list[tuple[str, int]]:
    items: list[tuple[str, int]] = []
    start = 0
    depth = 0
    quote: str | None = None
    index = 0
    while index < len(source):
        character = source[index]
        if quote is not None:
            if character == quote:
                if index + 1 < len(source) and source[index + 1] == quote:
                    index += 2
                    continue
                quote = None
            elif character == "\\":
                index += 2
                continue
        elif character in {"'", '"'}:
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        elif character == "," and depth == 0:
            items.append((source[start:index], start))
            start = index + 1
        index += 1
    items.append((source[start:], start))
    return items


def _migration_insert_format_values(source: str) -> list[tuple[str, int]]:
    bindings: list[tuple[str, int]] = []
    insert_pattern = re.compile(r'(?is)\binsert\s+into\s+[a-z0-9_."]+\s*\(')
    for insert in insert_pattern.finditer(source):
        columns_open = insert.end() - 1
        columns_close = _matching_parenthesis(source, columns_open)
        if columns_close is None:
            continue
        values = re.match(r"(?is)\s*values\s*\(", source[columns_close + 1 :])
        if values is None:
            continue
        values_open = columns_close + 1 + values.end() - 1
        values_close = _matching_parenthesis(source, values_open)
        if values_close is None:
            continue
        columns = _split_sql_list(source[columns_open + 1 : columns_close])
        expressions = _split_sql_list(source[values_open + 1 : values_close])
        if len(columns) != len(expressions):
            continue
        for (raw_column, _), (raw_expression, _) in zip(columns, expressions, strict=True):
            column_names = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", raw_column)
            if not column_names:
                continue
            column = column_names[-1].lower()
            if re.fullmatch(
                r"[a-z][a-z0-9_]*(?:schema|version|epoch)[a-z0-9_]*",
                column,
            ) is None:
                continue
            numeric = re.fullmatch(
                r"\s*(\d+)(?:\s*::\s*[a-zA-Z0-9_]+)?\s*",
                raw_expression,
            )
            if numeric is not None:
                bindings.append((column, int(numeric.group(1))))
    return bindings


def _hardcoded_insert_literals(
    source: str,
    durable_identifiers: set[str],
) -> list[tuple[int, str]]:
    findings: list[tuple[int, str]] = []
    insert_pattern = re.compile(r"(?is)\binsert\s+into\s+[a-z0-9_.\"]+\s*\(")
    for insert in insert_pattern.finditer(source):
        columns_open = insert.end() - 1
        columns_close = _matching_parenthesis(source, columns_open)
        if columns_close is None:
            continue
        values = re.match(r"(?is)\s*values\s*\(", source[columns_close + 1 :])
        if values is None:
            continue
        values_open = columns_close + 1 + values.end() - 1
        values_close = _matching_parenthesis(source, values_open)
        if values_close is None:
            continue
        columns = _split_sql_list(source[columns_open + 1 : columns_close])
        expressions = _split_sql_list(source[values_open + 1 : values_close])
        if len(columns) != len(expressions):
            continue
        for (raw_column, _), (raw_expression, expression_offset) in zip(
            columns, expressions, strict=True
        ):
            column_names = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", raw_column)
            if not column_names:
                continue
            column = column_names[-1].lower()
            expression = raw_expression.strip()
            durable = (
                "schema" in column
                or column in {"version", "schema_version"}
                or column in durable_identifiers
            )
            if durable and re.fullmatch(
                r"\d+(?:_[a-zA-Z0-9]+|[a-zA-Z][a-zA-Z0-9]*)?(?:\s*::\s*[a-zA-Z0-9_]+)?",
                expression,
            ):
                findings.append(
                    (values_open + 1 + expression_offset, f"INSERT {column} numeric literal")
                )
            if column.endswith("media_type") and re.fullmatch(
                r"[\"'](?:application|text)/[^\"']+[\"'](?:\s*::\s*[a-zA-Z0-9_]+)?",
                expression,
                flags=re.IGNORECASE,
            ):
                findings.append(
                    (values_open + 1 + expression_offset, f"INSERT {column} media literal")
                )
    return findings


def _validate_production_durable_format_literals(
    repository_root: Path,
    durable_identifiers: set[str],
) -> None:
    findings: list[str] = []
    for path in _production_format_sources(repository_root):
        source = _production_source(path)
        relative = path.relative_to(repository_root).as_posix()
        matches: list[tuple[int, str]] = []
        for match in PRODUCTION_FORMAT_COMPARISON.finditer(source):
            identifier = match.group("identifier").lower()
            line_start = source.rfind("\n", 0, match.start()) + 1
            declaration_prefix = source[line_start : match.start()]
            if re.search(r"\bconst\s+$", declaration_prefix, flags=re.IGNORECASE):
                continue
            if (
                "schema" in identifier
                or identifier in {"version", "schema_version"}
                or identifier in durable_identifiers
            ):
                matches.append((match.start(), f"numeric {identifier} comparison"))
        matches.extend(
            (match.start(), "numeric JSON schema/version literal")
            for match in PRODUCTION_JSON_FORMAT_LITERAL.finditer(source)
        )
        matches.extend(
            (match.start(), "hardcoded media-type comparison")
            for match in PRODUCTION_MEDIA_COMPARISON.finditer(source)
        )
        matches.extend(_hardcoded_insert_literals(source, durable_identifiers))
        for offset, description in sorted(set(matches)):
            line = source.count("\n", 0, offset) + 1
            findings.append(f"{relative}:{line} ({description})")

    if findings:
        preview = findings[:24]
        suffix = "" if len(findings) <= len(preview) else f"; and {len(findings) - len(preview)} more"
        _fail(
            "hardcoded production durable format literals must use registered constants: "
            + "; ".join(preview)
            + suffix
        )


def _validate_limits(repository_root: Path, values: Any, owner_ids: set[str]) -> None:
    limits = _array(values, "limits", nonempty=True)
    limit_ids: list[str] = []
    reason_codes: list[str] = []
    for index, raw_limit in enumerate(limits):
        context = f"limits[{index}]"
        limit_contract = _object(
            raw_limit,
            {
                "boundary_tests",
                "classification",
                "enforcement_phase",
                "id",
                "owner",
                "reason_code",
                "reason_source",
                "source",
                "unit",
                "value",
            },
            context,
        )
        limit_ids.append(_string(limit_contract["id"], f"{context}.id", identifier=True))
        _validate_owner_reference(limit_contract["owner"], owner_ids, f"{context}.owner")
        classification = _string(
            limit_contract["classification"], f"{context}.classification", identifier=True
        )
        if classification not in {"automata-stricter", "github"}:
            _fail(f"{context}.classification must be 'github' or 'automata-stricter'")
        enforcement_phase = _string(
            limit_contract["enforcement_phase"],
            f"{context}.enforcement_phase",
            identifier=True,
        )
        if enforcement_phase not in LIMIT_ENFORCEMENT_PHASES - {"external"}:
            _fail(f"{context}.enforcement_phase is unsupported")
        reason_code = _string(limit_contract["reason_code"], f"{context}.reason_code")
        if REASON_CODE.fullmatch(reason_code) is None:
            _fail(
                f"{context}.reason_code must be a dotted reason identifier "
                "or a typed Rust error variant"
            )
        reason_codes.append(reason_code)
        reason_fragments = _validate_sources(
            repository_root,
            [limit_contract["reason_source"]],
            f"{context}.reason_source_bindings",
        )
        if not _fragment_binds_reason(reason_fragments[0], reason_code):
            _fail(f"{context}.reason_source does not bind declared reason code {reason_code!r}")
        _string(limit_contract["unit"], f"{context}.unit", identifier=True)
        value = _positive_integer(limit_contract["value"], f"{context}.value")

        fragments = _validate_sources(
            repository_root,
            [limit_contract["source"]],
            f"{context}.source_bindings",
        )
        if not _fragment_binds_integer(fragments[0], value):
            _fail(f"{context}.source does not bind declared value {value}")
        boundaries = _object(
            limit_contract["boundary_tests"],
            {"at", "minus_one", "plus_one"},
            f"{context}.boundary_tests",
        )
        boundary_identities: list[tuple[str, str, str]] = []
        for label in ("minus_one", "at", "plus_one"):
            boundary_context = f"{context}.boundary_tests.{label}"
            binding = _object(
                boundaries[label],
                {"contains", "function", "path"},
                boundary_context,
            )
            function = _string(binding["function"], f"{boundary_context}.function")
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", function) is None:
                _fail(f"{boundary_context}.function must be a function name")
            relative = _string(binding["path"], f"{boundary_context}.path")
            path = _existing_path(
                repository_root,
                relative,
                f"{boundary_context}.path",
                kind="file",
            )
            try:
                source = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as error:
                _fail(f"cannot read boundary test {relative}: {error}")
            section = _rust_test_section(source, function, boundary_context)
            fragment = _string(binding["contains"], f"{boundary_context}.contains")
            if section.count(fragment) != 1:
                _fail(
                    f"{boundary_context}.contains must occur exactly once in test "
                    f"{function!r}"
                )
            boundary_identities.append((relative, function, fragment))
        if len(set(boundary_identities)) != 3:
            _fail(f"{context}.boundary_tests must use three distinct bindings")
    _sorted_unique(limit_ids, "limit IDs")
    if len(reason_codes) != len(set(reason_codes)):
        _fail("limit reason codes must be unique")


def _limit_candidate(name: str, rust_type: str) -> bool:
    normalized_type = re.sub(r"\s+", "", rust_type)
    return (
        LIMIT_NAME_TOKEN.search(name) is not None
        or RUST_LIMIT_TYPE_TOKEN.search(normalized_type) is not None
    )


def _rust_impl_namespace(header: str) -> str:
    body = re.sub(r"^\s*impl\s*", "", header).strip()
    if body.startswith("<"):
        depth = 0
        for index, character in enumerate(body):
            if character == "<":
                depth += 1
            elif character == ">":
                depth -= 1
                if depth == 0:
                    body = body[index + 1 :].strip()
                    break
    body = re.split(r"\bwhere\b", body, maxsplit=1)[0].strip()
    trait_and_target = re.split(r"\s+for\s+", body, maxsplit=1)

    def type_name(value: str) -> str:
        value = value.strip().lstrip("&").strip()
        value = re.sub(r"^\([^)]*\)\s*", "", value)
        value = value.split("<", 1)[0].strip()
        names = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", value)
        return names[-1] if names else "impl"

    if len(trait_and_target) == 2:
        trait = type_name(trait_and_target[0])
        target = type_name(trait_and_target[1])
        return f"<{target} as {trait}>"
    return type_name(body)


@functools.lru_cache(maxsize=None)
def _rust_namespace_ranges(source: str) -> tuple[tuple[int, int, str], ...]:
    """Return named Rust scopes that can own a constant declaration."""

    patterns: list[tuple[re.Pattern[str], str]] = [
        (
            re.compile(
                r"(?m)^[ \t]*(?:pub(?:\([^)]*\))?\s+)?mod\s+"
                r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)[^;{]*\{"
            ),
            "name",
        ),
        (
            re.compile(
                r"(?m)^[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?trait\s+"
                r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)[^;{]*\{"
            ),
            "name",
        ),
        (
            re.compile(
                r"(?ms)^[ \t]*(?P<header>impl\b[^;{]*?)\{"
            ),
            "impl",
        ),
        (
            re.compile(
                r"(?ms)^[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?"
                r"(?:async\s+)?(?:unsafe\s+)?fn\s+"
                r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b[^;{]*\{"
            ),
            "name",
        ),
    ]
    ranges: list[tuple[int, int, str]] = []
    for pattern, kind in patterns:
        for match in pattern.finditer(source):
            opening = source.rfind("{", match.start(), match.end())
            closing = _matching_rust_brace(source, opening)
            if closing is None:
                continue
            namespace = (
                _rust_impl_namespace(match.group("header"))
                if kind == "impl"
                else match.group("name")
            )
            ranges.append((opening, closing, namespace))
    return tuple(sorted(set(ranges)))


def _rust_qualified_constant(
    match: re.Match[str], namespace_ranges: tuple[tuple[int, int, str], ...]
) -> str:
    owners = [
        (opening, closing, namespace)
        for opening, closing, namespace in namespace_ranges
        if opening < match.start() < closing
    ]
    owners.sort(key=lambda item: item[0])
    namespaces = [namespace for _, _, namespace in owners]
    namespaces.append(match.group("name"))
    return "::".join(namespaces)


def _limit_constant_leaf(symbol: str) -> str:
    return symbol.rsplit("::", 1)[-1]


def _limit_declarations(
    repository_root: Path,
    surfaces: Any,
) -> dict[tuple[str, str], str]:
    """Discover candidate limits before consulting governance dispositions."""

    declarations: dict[tuple[str, str], str] = {}
    surface_paths = _array(surfaces, "limit_surfaces", nonempty=True)
    normalized_surfaces: list[str] = []
    for index, raw_surface in enumerate(surface_paths):
        context = f"limit_surfaces[{index}]"
        relative = _string(raw_surface, context)
        surface = _existing_path(repository_root, relative, context)
        normalized_surfaces.append(relative)
        paths = [surface] if surface.is_file() else sorted(surface.rglob("*.rs"))
        for path in paths:
            if path.is_symlink() or not path.is_file():
                _fail(f"{context} contains a non-regular Rust source: {path}")
            if _is_test_only_rust_source(path):
                continue
            source = _production_source(path)
            namespace_ranges = _rust_namespace_ranges(source)
            path_relative = path.relative_to(repository_root).as_posix()
            for match in RUST_LIMIT_DECLARATION.finditer(source):
                name = match.group("name")
                rust_type = match.group("type").strip()
                if not _limit_candidate(name, rust_type):
                    continue
                symbol = _rust_qualified_constant(match, namespace_ranges)
                identity = (path_relative, symbol)
                if identity in declarations:
                    _fail(f"duplicate qualified limit declaration identity: {identity}")
                declarations[identity] = _constant_declaration_fragment(source, match)
    _sorted_unique(normalized_surfaces, "limit discovery surfaces")
    return declarations


def _registered_limit_declarations(
    values: Any,
    candidates: dict[tuple[str, str], str],
) -> set[tuple[str, str]]:
    declarations: set[tuple[str, str]] = set()
    for raw_limit in values:
        source = raw_limit["source"]
        match = RUST_LIMIT_DECLARATION.search(source["contains"])
        if match is None:
            _fail(f"limit {raw_limit['id']} source must bind a discoverable limit declaration")
        matches = [
            identity
            for identity, declaration in candidates.items()
            if identity[0] == source["path"] and declaration == source["contains"]
        ]
        if len(matches) != 1:
            _fail(
                f"limit {raw_limit['id']} source must bind exactly one qualified "
                f"limit declaration; found {matches}"
            )
        declarations.add(matches[0])
    return declarations


def _limit_integer_value(
    identity: tuple[str, str],
    candidates: dict[tuple[str, str], str],
    *,
    resolving: set[tuple[str, str]] | None = None,
) -> int:
    """Evaluate the small integer-expression subset used by limit constants."""

    resolving = set() if resolving is None else set(resolving)
    if identity in resolving:
        _fail(f"cyclic limit constant expression involving {identity}")
    resolving.add(identity)
    declaration = candidates[identity]
    expression = declaration.partition("=")[2].rsplit(";", 1)[0].strip()
    expression = re.sub(
        r"(?<=\d)_(?:u|i)(?:8|16|32|64|128|size)\b|(?<=\d)(?:u|i)(?:8|16|32|64|128|size)\b",
        "",
        expression,
    )
    expression = re.sub(r"(?<=\d)_(?=\d)", "", expression)
    try:
        parsed = ast.parse(expression, mode="eval")
    except SyntaxError as error:
        _fail(f"limit alias expression for {identity} is not statically checkable: {error.msg}")

    def evaluate(node: ast.AST) -> int:
        if isinstance(node, ast.Expression):
            return evaluate(node.body)
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
            value = evaluate(node.operand)
            return value if isinstance(node.op, ast.UAdd) else -value
        if isinstance(node, ast.BinOp) and isinstance(
            node.op, (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv)
        ):
            left = evaluate(node.left)
            right = evaluate(node.right)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if right == 0:
                _fail(f"limit alias expression for {identity} divides by zero")
            return left // right
        if isinstance(node, ast.Name):
            matches = [
                candidate
                for candidate in candidates
                if _limit_constant_leaf(candidate[1]) == node.id
            ]
            same_file = [candidate for candidate in matches if candidate[0] == identity[0]]
            if len(same_file) == 1:
                matches = same_file
            if len(matches) != 1:
                _fail(
                    f"limit alias expression for {identity} references ambiguous or "
                    f"missing constant {node.id!r}"
                )
            return _limit_integer_value(matches[0], candidates, resolving=resolving)
        _fail(f"limit alias expression for {identity} uses unsupported syntax")

    value = evaluate(parsed)
    if value < 0:
        _fail(f"limit alias expression for {identity} must be non-negative")
    return value


def _validate_limit_aliases(
    repository_root: Path,
    values: Any,
    candidates: dict[tuple[str, str], str],
    owner_ids: set[str],
) -> dict[tuple[str, str], tuple[str, str]]:
    aliases = _array(values, "limit_aliases")
    identities: list[tuple[str, str]] = []
    targets: list[tuple[str, str]] = []
    for index, raw_alias in enumerate(aliases):
        context = f"limit_aliases[{index}]"
        alias = _object(
            raw_alias,
            {"owner", "phase", "relation", "source", "target", "tests"},
            context,
        )
        _validate_owner_reference(alias["owner"], owner_ids, f"{context}.owner")
        phase = _string(alias["phase"], f"{context}.phase", identifier=True)
        if phase not in LIMIT_ENFORCEMENT_PHASES:
            _fail(f"{context}.phase is unsupported")
        source = _object(alias["source"], {"constant", "path"}, f"{context}.source")
        source_identity = (
            _string(source["path"], f"{context}.source.path"),
            _string(source["constant"], f"{context}.source.constant"),
        )
        if source_identity not in candidates:
            _fail(f"{context}.source is not a discovered limit candidate: {source_identity}")
        target = _object(alias["target"], {"constant", "path"}, f"{context}.target")
        target_identity = (
            _string(target["path"], f"{context}.target.path"),
            _string(target["constant"], f"{context}.target.constant"),
        )
        if target_identity not in candidates:
            _fail(f"{context}.target is not a discovered limit candidate")
        if source_identity == target_identity:
            _fail(f"{context} cannot alias a declaration to itself")
        relation = _object(alias["relation"], {"kind", "offset"}, f"{context}.relation")
        kind = _string(relation["kind"], f"{context}.relation.kind", identifier=True)
        offset = relation["offset"]
        if kind not in {"equal", "offset"} or type(offset) is not int:
            _fail(f"{context}.relation must be equal/offset with an integer offset")
        if (kind == "equal" and offset != 0) or (kind == "offset" and offset == 0):
            _fail(f"{context}.relation kind and offset disagree")
        source_value = _limit_integer_value(source_identity, candidates)
        target_value = _limit_integer_value(target_identity, candidates)
        if source_value != target_value + offset:
            _fail(
                f"{context}.relation drift: {source_identity} is {source_value}, "
                f"expected {target_value} + {offset}"
            )
        tests = _array(alias["tests"], f"{context}.tests", nonempty=True)
        _validate_test_bindings(repository_root, tests, f"{context}.tests")
        source_name = _limit_constant_leaf(source_identity[1])
        bound = False
        for test in tests:
            path = _existing_path(
                repository_root,
                _string(test["path"], f"{context}.tests.path"),
                f"{context}.tests.path",
                kind="file",
            )
            source_text = path.read_text(encoding="utf-8")
            section = _bound_test_section(
                path,
                source_text,
                _string(test["function"], f"{context}.tests.function"),
                f"{context}.tests",
            )
            bound = bound or re.search(
                rf"\b{re.escape(source_name)}\b", _mask_source_comments(section)
            ) is not None
        if not bound:
            _fail(f"{context}.tests do not exercise the alias source")
        identities.append(source_identity)
        targets.append(target_identity)
    if identities != sorted(identities):
        _fail("limit aliases must be sorted by path and constant")
    if len(identities) != len(set(identities)):
        _fail("limit aliases must be unique")
    return dict(zip(identities, targets, strict=True))


def _validate_limit_exclusions(
    repository_root: Path,
    values: Any,
    surfaces: Any,
    limits: Any,
    aliases: Any,
    owner_ids: set[str],
) -> None:
    discovered = _limit_declarations(repository_root, surfaces)
    exclusions = _array(values, "limit_exclusions")
    excluded: list[tuple[str, str]] = []
    exclusion_order: list[tuple[str, str, str]] = []
    operational: set[tuple[str, str]] = set()
    for index, raw_exclusion in enumerate(exclusions):
        context = f"limit_exclusions[{index}]"
        exclusion = _object(
            raw_exclusion,
            {"classification", "constants", "owner", "path", "phase", "reason", "uses"},
            context,
        )
        relative = _string(exclusion["path"], f"{context}.path")
        path = _existing_path(repository_root, relative, f"{context}.path", kind="file")
        reason = _string(exclusion["reason"], f"{context}.reason")
        if len(reason) < 24:
            _fail(f"{context}.reason must explain why the declarations are out of scope")
        constants = _array(exclusion["constants"], f"{context}.constants", nonempty=True)
        names = [
            _string(value, f"{context}.constants[{item}]")
            for item, value in enumerate(constants)
        ]
        _sorted_unique(names, f"{context}.constants")
        classification = _string(
            exclusion["classification"], f"{context}.classification", identifier=True
        )
        if classification not in {"operational", "non-limit"}:
            _fail(f"{context}.classification must be 'operational' or 'non-limit'")
        _validate_owner_reference(exclusion["owner"], owner_ids, f"{context}.owner")
        phase = _string(exclusion["phase"], f"{context}.phase", identifier=True)
        if phase not in LIMIT_ENFORCEMENT_PHASES:
            _fail(f"{context}.phase is unsupported")
        uses = _array(exclusion["uses"], f"{context}.uses")
        if classification == "operational" and not uses:
            _fail(f"{context}.uses must prove at least one production use")
        if classification == "non-limit" and uses:
            _fail(f"{context}.uses must be empty for a lexical non-limit exclusion")
        used_constants: list[str] = []
        for use_index, raw_use in enumerate(uses):
            use_context = f"{context}.uses[{use_index}]"
            use = _object(
                raw_use,
                {"constant", "contains", "path"},
                use_context,
                optional={"scope"},
            )
            constant = _string(use["constant"], f"{use_context}.constant")
            leaf = _limit_constant_leaf(constant)
            fragment = _string(use["contains"], f"{use_context}.contains")
            use_path = _existing_path(
                repository_root,
                _string(use["path"], f"{use_context}.path"),
                f"{use_context}.path",
                kind="file",
            )
            production = _production_source(use_path)
            qualified_scope = use.get("scope")
            if qualified_scope is not None:
                qualified_scope = _string(qualified_scope, f"{use_context}.scope")
                ranges = _rust_namespace_ranges(production)
                matching_scopes: list[str] = []
                matching_sections: list[str] = []
                for opening, closing, _ in ranges:
                    scope = "::".join(
                        namespace
                        for owner_opening, owner_closing, namespace in ranges
                        if owner_opening <= opening and closing <= owner_closing
                    )
                    if scope == qualified_scope:
                        matching_scopes.append(scope)
                        matching_sections.append(production[opening + 1 : closing])
                if len(matching_scopes) != 1:
                    _fail(
                        f"{use_context}.scope must name exactly one production Rust scope"
                    )
                production_sections = matching_sections
            else:
                production_sections = [production]
            if not any(
                any(fragment in line for line in section.splitlines())
                for section in production_sections
            ):
                _fail(
                    f"{use_context} must bind at least one production use outside test-only cfgs"
                )
            if "::" in constant:
                owner_scope = constant.rsplit("::", 1)[0]
                explicitly_qualified = constant in fragment
                owner_bound_scope = qualified_scope is not None and (
                    qualified_scope == owner_scope
                    or qualified_scope.startswith(owner_scope + "::")
                )
                if not explicitly_qualified and not owner_bound_scope:
                    _fail(
                        f"{use_context} must qualify {constant!r} or bind its owner "
                        f"scope {owner_scope!r}"
                    )
            token = re.compile(
                rf"(?<![A-Za-z0-9_]){re.escape(leaf)}(?![A-Za-z0-9_])"
            )
            if token.search(_mask_source_comments(fragment)) is None:
                _fail(f"{use_context}.contains does not reference {constant}")
            if re.search(rf"\bconst\s+{re.escape(leaf)}\b", fragment):
                _fail(f"{use_context}.contains must bind a use, not the declaration")
            used_constants.append(constant)
        if classification == "operational":
            _sorted_unique(used_constants, f"{context}.uses constants")
            if used_constants != names:
                _fail(
                    f"{context}.uses must prove exactly one production use for every "
                    f"constant: expected {names}, found {used_constants}"
                )
        for name in names:
            if (relative, name) not in discovered:
                _fail(f"{context} excludes missing limit declaration {name}")
            excluded.append((relative, name))
            if classification == "operational":
                operational.add((relative, name))
        exclusion_order.append((relative, classification, names[0]))
    if exclusion_order != sorted(exclusion_order):
        _fail("limit exclusions must be sorted by path, classification, and constant")
    if len(excluded) != len(set(excluded)):
        _fail("limit exclusions must be unique")

    registered = _registered_limit_declarations(limits, discovered)
    alias_bindings = _validate_limit_aliases(
        repository_root, aliases, discovered, owner_ids
    )
    alias_identities = set(alias_bindings)
    excluded_set = set(excluded)
    invalid_targets = sorted(
        target
        for target in alias_bindings.values()
        if target not in registered | excluded_set or target in alias_identities
    )
    if invalid_targets:
        _fail(
            "limit aliases must target a canonical registered or excluded declaration: "
            f"{invalid_targets}"
        )
    overlap = (registered & excluded_set) | (registered & alias_identities) | (
        excluded_set & alias_identities
    )
    if overlap:
        _fail(f"limit declarations cannot be both registered and excluded: {sorted(overlap)}")
    accounted = registered | excluded_set | alias_identities
    missing = sorted(set(discovered) - accounted)
    stale = sorted(accounted - set(discovered))
    if missing:
        _fail(f"unregistered limit declarations: {missing}")
    if stale:
        _fail(f"stale registered or excluded limit declarations: {stale}")

def _github_limit_references(repository_root: Path) -> set[str]:
    path = _existing_path(
        repository_root,
        "docs/governance/github-actions-reference-snapshot-v1.json",
        "GitHub reference snapshot",
        kind="file",
    )
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        _fail(f"cannot read GitHub reference snapshot: {error}")
    groups = document.get("reference_groups")
    if not isinstance(groups, list):
        _fail("GitHub reference snapshot must contain reference_groups")
    references: set[str] = set()
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("id"), str):
            _fail("GitHub reference snapshot contains an invalid reference group")
        categories = group.get("categories")
        if isinstance(categories, list) and "limits" in categories:
            references.add(group["id"])
    return references


def _validate_github_limits(
    repository_root: Path,
    values: Any,
    owner_ids: set[str],
    implemented_limits: Any,
) -> None:
    contracts = _array(values, "github_limits", nonempty=True)
    limit_by_id = {contract["id"]: contract for contract in implemented_limits}
    reference_ids = _github_limit_references(repository_root)
    identifiers: list[str] = []
    reasons: list[str] = []
    for index, raw_contract in enumerate(contracts):
        context = f"github_limits[{index}]"
        contract = _object(
            raw_contract,
            {
                "automata",
                "id",
                "owner",
                "scope",
                "source_excerpt",
                "source_reference",
                "unit",
                "value",
                "window_seconds",
            },
            context,
        )
        identifier = _string(contract["id"], f"{context}.id", identifier=True)
        identifiers.append(identifier)
        _validate_owner_reference(contract["owner"], owner_ids, f"{context}.owner")
        _string(contract["scope"], f"{context}.scope")
        _string(contract["source_excerpt"], f"{context}.source_excerpt")
        source_reference = _string(
            contract["source_reference"],
            f"{context}.source_reference",
            identifier=True,
        )
        if source_reference not in reference_ids:
            _fail(f"{context}.source_reference is not a pinned limits reference")
        _string(contract["unit"], f"{context}.unit", identifier=True)
        _positive_integer(contract["value"], f"{context}.value")
        window_seconds = contract["window_seconds"]
        if window_seconds is not None:
            _positive_integer(window_seconds, f"{context}.window_seconds")

        automata_value = contract["automata"]
        automata_context = f"{context}.automata"
        if not isinstance(automata_value, dict):
            _fail(f"{automata_context} must be an object")
        required_automata_keys = {
            "enforcement_phase",
            "limit_id",
            "reason_code",
            "status",
        }
        allowed_automata_keys = required_automata_keys | {"relation"}
        actual_automata_keys = set(automata_value)
        missing_automata_keys = required_automata_keys - actual_automata_keys
        unknown_automata_keys = actual_automata_keys - allowed_automata_keys
        if missing_automata_keys or unknown_automata_keys:
            details: list[str] = []
            if missing_automata_keys:
                details.append(f"missing {sorted(missing_automata_keys)}")
            if unknown_automata_keys:
                details.append(f"unknown {sorted(unknown_automata_keys)}")
            _fail(f"{automata_context} has invalid keys: {', '.join(details)}")
        automata = automata_value
        relation_value = automata.get("relation")
        status = _string(automata["status"], f"{context}.automata.status", identifier=True)
        if status not in {"implemented", "planned", "not-applicable"}:
            _fail(
                f"{context}.automata.status must be 'implemented', 'planned', "
                "or 'not-applicable'"
            )
        phase = _string(
            automata["enforcement_phase"],
            f"{context}.automata.enforcement_phase",
            identifier=True,
        )
        if phase not in LIMIT_ENFORCEMENT_PHASES:
            _fail(f"{context}.automata.enforcement_phase is unsupported")
        if status == "not-applicable":
            if (
                phase != "external"
                or automata["limit_id"] is not None
                or automata["reason_code"] is not None
                or relation_value is not None
            ):
                _fail(f"{context}.automata not-applicable entries must be external and unbound")
            continue

        reason = _string(automata["reason_code"], f"{context}.automata.reason_code")
        if REASON_CODE.fullmatch(reason) is None:
            _fail(f"{context}.automata.reason_code is not a stable reason identifier")
        reasons.append(reason)
        if phase == "external":
            _fail(f"{context}.automata {status} entries cannot use external enforcement")
        limit_id = automata["limit_id"]
        if status == "planned":
            if limit_id is not None or relation_value is not None:
                _fail(
                    f"{context}.automata planned entries cannot claim an implemented "
                    "limit or value relation"
                )
            continue
        limit_identifier = _string(limit_id, f"{context}.automata.limit_id", identifier=True)
        implemented = limit_by_id.get(limit_identifier)
        if implemented is None:
            _fail(f"{context}.automata.limit_id references an unknown implemented limit")
        if implemented["owner"] != contract["owner"]:
            _fail(f"{context} owner differs from its implemented limit")
        if implemented["enforcement_phase"] != phase:
            _fail(f"{context} enforcement phase differs from its implemented limit")
        if implemented["reason_code"] != reason:
            _fail(f"{context} reason code differs from its implemented limit")
        relation = _object(
            relation_value,
            {"kind", "offset", "unit"},
            f"{context}.automata.relation",
        )
        relation_kind = _string(
            relation["kind"],
            f"{context}.automata.relation.kind",
            identifier=True,
        )
        if relation_kind not in {"exact", "offset"}:
            _fail(f"{context}.automata.relation.kind must be 'exact' or 'offset'")
        offset = relation["offset"]
        if type(offset) is not int:
            _fail(f"{context}.automata.relation.offset must be an integer")
        if relation_kind == "exact" and offset != 0:
            _fail(f"{context}.automata exact relations must have offset 0")
        if relation_kind == "offset" and offset == 0:
            _fail(f"{context}.automata offset relations must have a nonzero offset")
        relation_unit = _string(
            relation["unit"],
            f"{context}.automata.relation.unit",
            identifier=True,
        )
        if implemented["unit"] != relation_unit:
            _fail(f"{context} relation unit differs from its implemented limit")
        expected_value = contract["value"] + offset
        if expected_value <= 0 or implemented["value"] != expected_value:
            _fail(
                f"{context} value relation does not match its implemented limit: "
                f"expected {expected_value} {relation_unit}, found "
                f"{implemented['value']} {implemented['unit']}"
            )

    _sorted_unique(identifiers, "GitHub limit IDs")
    if set(identifiers) != GITHUB_LIMIT_IDS:
        missing = sorted(GITHUB_LIMIT_IDS - set(identifiers))
        unknown = sorted(set(identifiers) - GITHUB_LIMIT_IDS)
        _fail(f"GitHub limits inventory is incomplete: missing {missing}, unknown {unknown}")
    if len(reasons) != len(set(reasons)):
        _fail("GitHub limit reason codes must be unique")
    mapped_limits = {
        contract["automata"]["limit_id"]
        for contract in contracts
        if contract["automata"]["status"] == "implemented"
    }
    github_classified_limits = {
        limit["id"] for limit in implemented_limits if limit["classification"] == "github"
    }
    if mapped_limits != github_classified_limits:
        missing = sorted(github_classified_limits - mapped_limits)
        unknown = sorted(mapped_limits - github_classified_limits)
        _fail(
            "GitHub-classified Automata limits require exact reverse mappings: "
            f"missing {missing}, unknown {unknown}"
        )


def _validate_shared_surfaces(repository_root: Path, values: Any, owner_ids: set[str]) -> None:
    surfaces = _array(values, "shared_surfaces", nonempty=True)
    paths: list[str] = []
    for index, raw_surface in enumerate(surfaces):
        context = f"shared_surfaces[{index}]"
        surface = _object(raw_surface, {"description", "owner", "path"}, context)
        _string(surface["description"], f"{context}.description")
        _validate_owner_reference(surface["owner"], owner_ids, f"{context}.owner")
        path = _string(surface["path"], f"{context}.path")
        _existing_path(repository_root, path, f"{context}.path")
        paths.append(path)
    _sorted_unique(paths, "shared surface paths")


def validate_repository(
    repository_root: Path,
    registry_path: PurePosixPath = REGISTRY_PATH,
) -> None:
    """Validate one repository against its foundation governance registry."""

    try:
        root = repository_root.resolve(strict=True)
    except (FileNotFoundError, OSError) as error:
        _fail(f"repository root does not exist: {error}")
    if not root.is_dir():
        _fail("repository root must be a directory")
    registry = _existing_path(root, registry_path.as_posix(), "registry path", kind="file")
    document = _load_registry(registry)

    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        _fail("schema_version must be integer 1")
    status = _string(document["status"], "status", identifier=True)
    if status != "active":
        _fail("schema version 1 status must be 'active'")

    owner_ids = _validate_owners(document["owners"])
    _validate_format_scope(root, document["format_scope"])
    _validate_formats(root, document["formats"], owner_ids)
    _validate_format_exclusions(
        root,
        document["format_exclusions"],
        document["formats"],
    )
    _validate_migrations(root, document["migrations"], owner_ids)
    durable_identifiers = _validate_store_migration_format_map(
        root,
        document["formats"],
        document["migrations"],
    )
    _validate_production_durable_format_literals(root, durable_identifiers)
    _validate_limits(root, document["limits"], owner_ids)
    _validate_limit_exclusions(
        root,
        document["limit_exclusions"],
        document["limit_surfaces"],
        document["limits"],
        document["limit_aliases"],
        owner_ids,
    )
    _validate_github_limits(
        root,
        document["github_limits"],
        owner_ids,
        document["limits"],
    )
    _validate_shared_surfaces(root, document["shared_surfaces"], owner_ids)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=REPOSITORY_ROOT,
        help="repository root to validate (defaults to the script's repository)",
    )
    arguments = parser.parse_args(argv)
    try:
        validate_repository(arguments.repository_root)
    except GovernanceError as error:
        print(f"error: foundation governance: {error}", file=sys.stderr)
        return 1
    print("foundation governance verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
