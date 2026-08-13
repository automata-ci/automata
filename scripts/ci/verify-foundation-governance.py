#!/usr/bin/env python3
"""Verify the machine-readable foundation governance contract."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = PurePosixPath("docs/governance/foundation-governance-v1.json")
TOP_LEVEL_KEYS = {
    "formats",
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
    r"(?m)^(?P<attributes>(?:\s*#\[[^\r\n]+\]\s*\r?\n)+)"
    r"\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+{name}\s*(?:<[^>]*>)?\s*\("
)
RUST_TEST_ATTRIBUTE = re.compile(
    r"#\[\s*(?:[A-Za-z_][A-Za-z0-9_]*::)*test(?:\s*\([^]]*\))?\s*\]"
)
FORMAT_COMPATIBILITY_POLICIES = {"exact-current-only", "generated-v1-package"}


class GovernanceError(ValueError):
    """The foundation governance registry is malformed or has drifted."""


def _fail(message: str) -> None:
    raise GovernanceError(message)


def _object(value: Any, keys: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{context} must be an object")
    actual = set(value)
    if actual != keys:
        missing = sorted(keys - actual)
        unknown = sorted(actual - keys)
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
    normalized = fragment.replace("_", "")
    numeric_literal = re.search(
        rf"(?<![A-Za-z0-9_]){value}(?![A-Za-z0-9_])",
        normalized,
    )
    version_identifier = re.search(
        rf"(?<![A-Za-z0-9_])v{value}(?![A-Za-z0-9_])",
        normalized,
    )
    return numeric_literal is not None or version_identifier is not None


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


def _rust_test_section(source: str, function: str, context: str) -> str:
    pattern = re.compile(RUST_TEST_FUNCTION.format(name=re.escape(function)))
    match = pattern.search(source)
    if match is None or RUST_TEST_ATTRIBUTE.search(match.group("attributes")) is None:
        _fail(f"{context} names missing test function {function!r} with a test attribute")

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
        section = _rust_test_section(source, function, binding_context)
        fragment = _string(binding["contains"], f"{binding_context}.contains")
        if section.count(fragment) != 1:
            _fail(
                f"{binding_context}.contains must occur exactly once in test "
                f"{function!r}"
            )
        identities.append(f"{relative}::{function}")
    _sorted_unique(identities, context)


def _validate_format_sources(
    repository_root: Path,
    values: Any,
    version: int,
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
            if not _fragment_binds_integer(fragment, version):
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


def _validate_formats(repository_root: Path, values: Any, owner_ids: set[str]) -> None:
    formats = _array(values, "formats", nonempty=True)
    format_ids: list[str] = []
    for index, raw_format in enumerate(formats):
        context = f"formats[{index}]"
        format_contract = _object(
            raw_format,
            {"compatibility_policy", "id", "owner", "sources", "tests", "version"},
            context,
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
        version = _positive_integer(format_contract["version"], f"{context}.version", maximum=65535)
        _validate_format_sources(
            repository_root,
            format_contract["sources"],
            version,
            f"{context}.sources",
        )
        _validate_test_bindings(repository_root, format_contract["tests"], f"{context}.tests")
    _sorted_unique(format_ids, "format IDs")


def _validate_migrations(repository_root: Path, value: Any, owner_ids: set[str]) -> None:
    migrations = _object(
        value,
        {"current", "directory", "mode", "next_sequence", "owner", "reservations"},
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

    reservations = _array(migrations["reservations"], "migrations.reservations")
    if reservations:
        _fail("greenfield canonical baseline must not reserve migration numbers")
    if migrations["next_sequence"] is not None:
        _fail("greenfield canonical baseline migrations.next_sequence must be null")


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
        if enforcement_phase not in {"compile", "executor-admission", "runtime"}:
            _fail(
                f"{context}.enforcement_phase must be 'compile', "
                "'executor-admission', or 'runtime'"
            )
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
    if status != "bootstrap":
        _fail("schema version 1 status must remain 'bootstrap'")

    owner_ids = _validate_owners(document["owners"])
    _validate_formats(root, document["formats"], owner_ids)
    _validate_migrations(root, document["migrations"], owner_ids)
    _validate_limits(root, document["limits"], owner_ids)
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
