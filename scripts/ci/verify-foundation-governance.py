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


def _validate_owner_reference(owner: Any, owner_ids: set[str], context: str) -> str:
    identifier = _string(owner, context, identifier=True)
    if identifier not in owner_ids:
        _fail(f"{context} references unknown owner {identifier!r}")
    return identifier


def _validate_string_paths(
    repository_root: Path,
    values: Any,
    context: str,
) -> list[Path]:
    paths = _array(values, context, nonempty=True)
    texts = [_string(value, f"{context}[{index}]") for index, value in enumerate(paths)]
    _sorted_unique(texts, context)
    return [
        _existing_path(repository_root, value, f"{context}[{index}]", kind="file")
        for index, value in enumerate(texts)
    ]


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
        _string(
            format_contract["compatibility_policy"],
            f"{context}.compatibility_policy",
            identifier=True,
        )
        version = _positive_integer(format_contract["version"], f"{context}.version", maximum=65535)
        fragments = _validate_sources(repository_root, format_contract["sources"], f"{context}.sources")
        if not any(_fragment_binds_integer(fragment, version) for fragment in fragments):
            _fail(f"{context}.sources do not bind declared version {version}")
        _validate_string_paths(repository_root, format_contract["tests"], f"{context}.tests")
    _sorted_unique(format_ids, "format IDs")


def _validate_reservations(values: Any, owner_ids: set[str]) -> list[int]:
    reservations = _array(values, "migrations.reservations")
    numbers: list[int] = []
    for index, raw_reservation in enumerate(reservations):
        context = f"migrations.reservations[{index}]"
        reservation = _object(raw_reservation, {"issue", "number", "owner"}, context)
        number = _positive_integer(reservation["number"], f"{context}.number")
        if number < 2:
            _fail(f"{context}.number must be 2 or greater")
        numbers.append(number)
        _string(reservation["issue"], f"{context}.issue")
        _validate_owner_reference(reservation["owner"], owner_ids, f"{context}.owner")
    if len(numbers) != len(set(numbers)):
        _fail("migration reservation numbers must be unique")
    if numbers != sorted(numbers):
        _fail("migration reservations must be sorted by number")
    return numbers


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

    _validate_reservations(migrations["reservations"], owner_ids)
    if migrations["reservations"]:
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
                "tests",
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
        if reason_code not in reason_fragments[0]:
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
        test_paths = _validate_string_paths(
            repository_root, limit_contract["tests"], f"{context}.tests"
        )
        test_sources: list[tuple[Path, str]] = []
        for path in test_paths:
            try:
                test_sources.append((path, path.read_text(encoding="utf-8")))
            except (OSError, UnicodeError) as error:
                _fail(f"cannot read boundary test {path}: {error}")

        boundaries = _object(
            limit_contract["boundary_tests"],
            {"at", "minus_one", "plus_one"},
            f"{context}.boundary_tests",
        )
        for label in ("minus_one", "at", "plus_one"):
            function = _string(
                boundaries[label], f"{context}.boundary_tests.{label}"
            )
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", function) is None:
                _fail(f"{context}.boundary_tests.{label} must be a function name")
            pattern = re.compile(RUST_TEST_FUNCTION.format(name=re.escape(function)))
            matches = []
            for path, source in test_sources:
                match = pattern.search(source)
                if match is not None and RUST_TEST_ATTRIBUTE.search(match.group("attributes")):
                    matches.append(str(path))
            if not matches:
                _fail(
                    f"{context}.boundary_tests.{label} names missing test function "
                    f"{function!r} with a test attribute in the listed tests"
                )
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

    if document["schema_version"] != 1 or isinstance(document["schema_version"], bool):
        _fail("schema_version must be integer 1")
    status = _string(document["status"], "status", identifier=True)
    if status not in {"active", "bootstrap", "retired"}:
        _fail("status must be 'bootstrap', 'active', or 'retired'")

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
