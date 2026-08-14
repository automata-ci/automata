#!/usr/bin/env python3
"""Fail closed on GitHub Actions capability, compatibility, and reference drift."""

from __future__ import annotations

import argparse
import datetime
import hashlib
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


def feature_owners(value: Any, feature_ids: set[str], context: str) -> frozenset[str]:
    if isinstance(value, str):
        owners = [string(value, context)]
    else:
        owners = [
            string(owner, context)
            for owner in array(value, context, nonempty=True)
        ]
        if owners != sorted(set(owners)):
            fail(f"{context} feature owners must be sorted and unique")
    unknown = set(owners) - feature_ids
    if unknown:
        fail(f"{context} references unknown features {sorted(unknown)}")
    return frozenset(owners)


def decoder_field_owners(
    value: Any, feature_ids: set[str], context: str
) -> dict[str, frozenset[str]]:
    if not isinstance(value, dict) or not value:
        fail(f"{context} must be a non-empty object")
    return {
        string(field, f"{context} field"): feature_owners(
            owners, feature_ids, f"{context}.{field}"
        )
        for field, owners in value.items()
    }


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


def baseline_capability_registry(root: Path) -> tuple[str, dict[str, Any]]:
    revision = diagnostic_baseline_revision(root)
    try:
        source = git_text(root, revision, REGISTRY.as_posix(), "capability registry")
    except CapabilityError:
        previous = subprocess.run(
            [
                "git",
                "log",
                "-1",
                "--format=%H",
                "HEAD^",
                "--",
                REGISTRY.as_posix(),
            ],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        revision = previous.stdout.strip() or initial_capability_registry_revision(root)
        source = git_text(
            root, revision, REGISTRY.as_posix(), "previous capability registry"
        )
    try:
        value = json.loads(source)
    except json.JSONDecodeError as error:
        fail(f"baseline capability registry is invalid JSON: {error}")
    if not isinstance(value, dict):
        fail("baseline capability registry is not an object")
    return revision, value


def baseline_governance_document(
    root: Path, revision: str, registry: dict[str, Any], key: str
) -> dict[str, Any]:
    relative = registry.get(key)
    if not isinstance(relative, str):
        fail(f"baseline capability registry has no {key}")
    try:
        value = json.loads(git_text(root, revision, relative, f"baseline {key}"))
    except json.JSONDecodeError as error:
        fail(f"baseline {key} is invalid JSON: {error}")
    if not isinstance(value, dict):
        fail(f"baseline {key} is not an object")
    return value


def normalized_historical_reviewed_delta(
    value: dict[str, Any], baseline_snapshot: dict[str, Any]
) -> dict[str, Any]:
    normalized = dict(value)
    if "runner_baseline" not in normalized:
        normalized["runner_baseline"] = (
            baseline_snapshot.get("runner")
            if normalized.get("decision") == "approved-baseline"
            else None
        )
    return normalized


def some_match_fields(
    source: str, module_constants: dict[str, str | None] | None = None
) -> set[str]:
    return field_name_match_fields(source, module_constants)


def rust_function_source(source: str, function: str, context: str) -> str:
    functions = rust_top_level_functions(source, context)
    if function not in functions:
        fail(f"{context} function {function!r} is missing")
    return functions[function]


def action_metadata_fields(
    source: str,
    scope_name: str | None = None,
    module_constants: dict[str, str | None] | None = None,
) -> set[str]:
    return censused_action_metadata_fields(
        source,
        scope_name=scope_name,
        module_constants=module_constants,
    )


def matching_parenthesis(source: str, opening: int, context: str) -> int:
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "(":
            depth += 1
        elif source[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    fail(f"{context} has an unbalanced call")


def action_runtime_dispatches(source: str) -> dict[str, str]:
    runs = rust_function_source(source, "decode_runs", "action decoder")
    structural = rust_source_mask(runs, mask_strings=True)
    dispatches: dict[str, str] = {}
    comparison_pattern = re.compile(
        r"\b(?P<receiver>[A-Za-z_][A-Za-z0-9_]*)\."
        r"eq_ignore_ascii_case\s*\("
    )
    calls = list(comparison_pattern.finditer(structural))
    if not calls:
        fail("action runtime dispatch has no runtime comparisons")
    noncanonical_receivers = sorted(
        {call["receiver"] for call in calls if call["receiver"] != "runtime"}
    )
    if noncanonical_receivers:
        fail(
            "action runtime dispatch has noncanonical comparison receivers "
            f"{noncanonical_receivers}"
        )
    scalar_calls = rust_call_arguments(runs, "scalar_string")
    if scalar_calls != [["&using"]]:
        fail(
            "action runtime dispatch must derive its value through exactly one "
            "scalar_string(&using) call"
        )
    using_bindings = list(
        re.finditer(
            r"\blet\s+(?P<using>using)\s*=\s*required_exact_scalar\s*\(",
            structural,
        )
    )
    if len(using_bindings) != 1:
        fail("action runtime dispatch must have one canonical using-value binding")
    using_locations = list(
        re.finditer(r"\b(?P<using>using)\.location\s*\(\s*\)", structural)
    )
    if len(using_locations) != 1:
        fail("action runtime dispatch must have one canonical using.location diagnostic")
    scalar_sites = rust_call_sites(runs, "scalar_string")
    allowed_using_spans = [
        using_bindings[0].span("using"),
        using_locations[0].span("using"),
    ]
    for start, end, _ in scalar_sites:
        allowed_using_spans.extend(
            (use.start() + start, use.end() + start)
            for use in re.finditer(r"\busing\b", structural[start:end])
        )
    unsupported_using_uses = [
        use.start()
        for use in re.finditer(r"\busing\b", structural)
        if not any(start <= use.start() < end for start, end in allowed_using_spans)
    ]
    if unsupported_using_uses:
        fail(
            "action runtime using value is used outside the closed "
            "scalar_string extraction/diagnostic grammar"
        )
    bindings = list(
        re.finditer(
            r"\blet\s+(?:mut\s+)?(?P<runtime>runtime)\s*=\s*"
            r"scalar_string\s*\(\s*&using\s*\)\s*;",
            structural,
        )
    )
    if len(bindings) != 1:
        fail("action runtime dispatch must have one canonical runtime binding")
    allowed_runtime_spans = [bindings[0].span("runtime")]
    for index, call in enumerate(calls):
        opening = structural.find("(", call.start(), call.end())
        closing = matching_parenthesis(
            structural, opening, f"action runtime dispatch call {index}"
        )
        allowed_runtime_spans.append((call.start(), closing + 1))
        argument = runs[opening + 1 : closing].strip()
        literal = re.fullmatch(
            r'"([a-z0-9](?:[a-z0-9._-]*[a-z0-9])?)"', argument
        )
        if literal is None:
            fail(
                f"action runtime dispatch call {index} must use one canonical "
                "normal string literal"
            )
        runtime = literal[1]
        if runtime in dispatches:
            fail(f"action runtime dispatch contains duplicate token {runtime!r}")
        target = re.match(
            r"\s*\{\s*([a-z_][A-Za-z0-9_]*)\s*\(\s*fields\b",
            structural[closing + 1 :],
        )
        if target is None:
            fail(f"action runtime {runtime!r} has no directly bound decoder target")
        dispatches[runtime] = target[1]
    unexpected_runtime_uses = [
        use.start()
        for use in re.finditer(r"\bruntime\b", structural)
        if not any(start <= use.start() < end for start, end in allowed_runtime_spans)
    ]
    if unexpected_runtime_uses:
        fail(
            "action runtime value is used outside canonical "
            "eq_ignore_ascii_case dispatch comparisons"
        )
    return dispatches


def action_runtime_values(source: str) -> set[str]:
    return set(action_runtime_dispatches(source))


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


def rust_source_mask(source: str, *, mask_strings: bool) -> str:
    """Mask Rust comments and optionally literals without changing offsets."""
    masked = list(source)
    index = 0
    state = "code"
    block_comment_depth = 0
    raw_hashes = 0

    def hide(position: int) -> None:
        if masked[position] not in {"\r", "\n"}:
            masked[position] = " "

    while index < len(source):
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "line-comment":
            hide(index)
            if character == "\n":
                state = "code"
        elif state == "block-comment":
            hide(index)
            if character == "/" and following == "*":
                hide(index + 1)
                block_comment_depth += 1
                index += 1
            elif character == "*" and following == "/":
                hide(index + 1)
                block_comment_depth -= 1
                index += 1
                if block_comment_depth == 0:
                    state = "code"
        elif state == "string":
            if mask_strings:
                hide(index)
            if character == "\\":
                if index + 1 < len(source):
                    if mask_strings:
                        hide(index + 1)
                    index += 1
            elif character == '"':
                state = "code"
        elif state == "character":
            if mask_strings:
                hide(index)
            if character == "\\":
                if index + 1 < len(source):
                    if mask_strings:
                        hide(index + 1)
                    index += 1
            elif character == "'":
                state = "code"
        elif state == "raw-string":
            hide(index)
            terminator = '"' + ("#" * raw_hashes)
            if source.startswith(terminator, index):
                for offset in range(1, len(terminator)):
                    hide(index + offset)
                index += len(terminator) - 1
                state = "code"
        else:
            if character == "/" and following == "/":
                hide(index)
                hide(index + 1)
                state = "line-comment"
                index += 1
            elif character == "/" and following == "*":
                hide(index)
                hide(index + 1)
                state = "block-comment"
                block_comment_depth = 1
                index += 1
            elif character == '"':
                if mask_strings:
                    hide(index)
                state = "string"
            elif character == "'" and re.match(
                r"(?:\\.|[^\\'])'", source[index + 1 :]
            ):
                if mask_strings:
                    hide(index)
                state = "character"
            elif character == "r":
                raw = re.match(r'r(?P<hashes>#{0,255})"', source[index:])
                if raw is not None:
                    raw_hashes = len(raw.group("hashes"))
                    for offset in range(raw.end()):
                        hide(index + offset)
                    index += raw.end() - 1
                    state = "raw-string"
        index += 1
    return "".join(masked)


FIELD_TOKEN = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")


def split_rust_arguments(source: str) -> list[str]:
    structural = rust_source_mask(source, mask_strings=True)
    arguments: list[str] = []
    start = 0
    round_depth = 0
    square_depth = 0
    brace_depth = 0
    for index, character in enumerate(structural):
        if character == "(":
            round_depth += 1
        elif character == ")":
            round_depth -= 1
        elif character == "[":
            square_depth += 1
        elif character == "]":
            square_depth -= 1
        elif character == "{":
            brace_depth += 1
        elif character == "}":
            brace_depth -= 1
        elif (
            character == ","
            and round_depth == 0
            and square_depth == 0
            and brace_depth == 0
        ):
            arguments.append(source[start:index].strip())
            start = index + 1
    trailing = source[start:].strip()
    if trailing:
        arguments.append(trailing)
    return arguments


def rust_call_arguments(source: str, function: str) -> list[list[str]]:
    structural = rust_source_mask(source, mask_strings=True)
    calls: list[list[str]] = []
    pattern = re.compile(rf"\b{re.escape(function)}\s*\(")
    for call in pattern.finditer(structural):
        prefix = structural[max(0, call.start() - 16) : call.start()]
        if re.search(r"\bfn\s+$", prefix):
            continue
        opening = structural.find("(", call.start(), call.end())
        closing = matching_parenthesis(
            structural, opening, f"{function} call at offset {call.start()}"
        )
        calls.append(split_rust_arguments(source[opening + 1 : closing]))
    return calls


def rust_call_sites(source: str, function: str) -> list[tuple[int, int, list[str]]]:
    structural = rust_source_mask(source, mask_strings=True)
    calls: list[tuple[int, int, list[str]]] = []
    pattern = re.compile(rf"\b{re.escape(function)}\s*\(")
    for call in pattern.finditer(structural):
        prefix = structural[max(0, call.start() - 16) : call.start()]
        if re.search(r"\bfn\s+$", prefix):
            continue
        opening = structural.find("(", call.start(), call.end())
        closing = matching_parenthesis(
            structural, opening, f"{function} call at offset {call.start()}"
        )
        calls.append(
            (
                call.start(),
                closing + 1,
                split_rust_arguments(source[opening + 1 : closing]),
            )
        )
    return calls


def canonical_field_literal(value: str, context: str) -> str:
    match = re.fullmatch(r'"([A-Za-z][A-Za-z0-9-]*)"', value.strip())
    if match is None or FIELD_TOKEN.fullmatch(match[1]) is None:
        fail(f"{context} must use a canonical normal string literal field")
    return match[1]


def rust_string_constants(
    source: str, context: str, *, top_level_only: bool = False
) -> dict[str, str | None]:
    """Return typed string constants without treating arbitrary identifiers as fields."""

    structural = rust_source_mask(source, mask_strings=True)
    depths: list[int] = []
    depth = 0
    for character in structural:
        depths.append(depth)
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
    constants: dict[str, str | None] = {}
    for declaration in re.finditer(
        r"(?m)^\s*const\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*"
        r"&\s*(?:'static\s+)?str\s*=([^;]+);",
        structural,
    ):
        if top_level_only and depths[declaration.start()] != 0:
            continue
        name = declaration[1]
        if name in constants:
            constants[name] = None
        else:
            constants[name] = source[
                declaration.start(2) : declaration.end(2)
            ].strip()
    return constants


def resolved_field_expression(
    value: str,
    constants: dict[str, str | None],
    context: str,
    resolving: tuple[str, ...] = (),
) -> str:
    expression = value.strip()
    literal = re.fullmatch(r'"([A-Za-z][A-Za-z0-9-]*)"', expression)
    if literal is not None and FIELD_TOKEN.fullmatch(literal[1]) is not None:
        return literal[1]
    identifier = re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", expression)
    if identifier is not None and identifier[0] in constants:
        name = identifier[0]
        if name in resolving:
            fail(f"{context} resolves through a cyclic string constant {name!r}")
        if constants[name] is None:
            fail(f"{context} refers to an ambiguously declared string constant {name!r}")
        return resolved_field_expression(
            constants[name] or "", constants, context, (*resolving, name)
        )
    fail(
        f"{context} must use a canonical normal string literal field "
        "or a typed string constant that resolves to one"
    )


def rust_right_expression(source: str, start: int) -> str | None:
    position = start
    while position < len(source) and source[position].isspace():
        position += 1
    normal = re.match(r'"(?:\\.|[^"\\])*"', source[position:])
    if normal is not None:
        return normal[0]
    raw_start = re.match(r'r(?P<hashes>#{0,255})"', source[position:])
    if raw_start is not None:
        terminator = '"' + raw_start["hashes"]
        ending = source.find(terminator, position + raw_start.end())
        if ending >= 0:
            return source[position : ending + len(terminator)]
    identifier = re.match(r"[A-Za-z_][A-Za-z0-9_]*", source[position:])
    return identifier[0] if identifier is not None else None


def rust_left_expression(source: str, end: int) -> str | None:
    prefix = source[:end].rstrip()
    normal = re.search(r'"(?:\\.|[^"\\])*"$', prefix)
    if normal is not None:
        return normal[0]
    raw = re.search(r'r(?P<hashes>#{0,255})".*"(?P=hashes)$', prefix, re.DOTALL)
    if raw is not None:
        return raw[0]
    identifier = re.search(r"[A-Za-z_][A-Za-z0-9_]*$", prefix)
    return identifier[0] if identifier is not None else None


def equality_field_expressions(
    source: str, constants: dict[str, str | None]
) -> list[str]:
    structural = rust_source_mask(source, mask_strings=True)
    expressions: list[str] = []
    for equality in re.finditer(r"(?<![=!<>])==(?!=)", structural):
        adjacent = (
            rust_left_expression(source, equality.start()),
            rust_right_expression(source, equality.end()),
        )
        expressions.extend(
            expression
            for expression in adjacent
            if expression is not None
            and (
                expression.startswith('"')
                or re.match(r'r#{0,255}"', expression) is not None
                or expression in constants
            )
        )
    return expressions


def validate_action_selector_use_grammar(
    source: str,
    constants: dict[str, str | None],
    known_fields: set[str],
    scope_name: str | None,
) -> None:
    structural = rust_source_mask(source, mask_strings=True)
    key_sites = rust_call_sites(source, "key_eq")
    derivations = list(
        re.finditer(
            r"\blet\s+(?:mut\s+)?(?P<child>[a-z_][A-Za-z0-9_]*)\s*=\s*"
            r"[a-z_][A-Za-z0-9_]*\.key\s*\(\s*\)\.to_owned\s*\(\s*\)\s*;",
            structural,
        )
    )
    selectors = {derivation["child"] for derivation in derivations}
    propagations = list(
        re.finditer(
            r"\blet\s+(?:mut\s+)?(?P<child>[a-z_][A-Za-z0-9_]*)\s*=\s*"
            r"(?P<parent>[a-z_][A-Za-z0-9_]*)\.as_str\s*\(\s*\)\s*;",
            structural,
        )
    )
    changed = True
    while changed:
        changed = False
        for propagation in propagations:
            child = propagation["child"]
            parent = propagation["parent"]
            if child in selectors and parent not in selectors:
                selectors.add(parent)
                changed = True
            if parent in selectors and child not in selectors:
                selectors.add(child)
                changed = True

    governed_selectors: set[str] = set()
    governed_selector_spans: list[tuple[int, int]] = []
    dynamic_key_site_spans: list[tuple[int, int]] = []
    for start, end, arguments in key_sites:
        if len(arguments) != 2:
            continue
        first_argument = arguments[0].strip()
        selector = re.fullmatch(r"&?\s*([a-z_][A-Za-z0-9_]*)", first_argument)
        if selector is not None:
            selector_name = selector[1]
            if selector_name not in selectors:
                fail(
                    f"action key_eq in {scope_name or 'unknown scope'} uses "
                    f"selector {selector_name!r} without exact YAML-key provenance"
                )
            governed_selectors.add(selector_name)
            selector_uses = list(
                re.finditer(
                    rf"\b{re.escape(selector_name)}\b", structural[start:end]
                )
            )
            if len(selector_uses) != 1:
                fail(
                    f"action key_eq in {scope_name or 'unknown scope'} must use "
                    "its proven selector exactly once"
                )
            governed_selector_spans.append(
                (
                    selector_uses[0].start() + start,
                    selector_uses[0].end() + start,
                )
            )
        elif (
            scope_name in {"Fields::validate_allowed", "Fields::take_insensitive"}
            and first_argument == "entry.key()"
        ):
            dynamic_key_site_spans.append((start, end))
        else:
            fail(
                f"action key_eq in {scope_name or 'unknown scope'} must use an "
                "exact proven selector or the reviewed Fields helper key accessor"
            )
    changed = True
    while changed:
        changed = False
        for propagation in propagations:
            child = propagation["child"]
            parent = propagation["parent"]
            if child in governed_selectors and parent not in governed_selectors:
                governed_selectors.add(parent)
                changed = True
            if parent in governed_selectors and child not in governed_selectors:
                governed_selectors.add(child)
                changed = True

    key_accessors = list(re.finditer(r"\.key\s*\(\s*\)", structural))
    allowed_key_accessor_spans = dynamic_key_site_spans + [
        derivation.span() for derivation in derivations
    ]
    if scope_name in {
        "Fields::has_exact",
        "Fields::location_exact",
        "Fields::take_exact",
    }:
        allowed_key_accessor_spans.extend(
            comparison.span()
            for comparison in re.finditer(
                r"\bentry\.key\s*\(\s*\)\s*==\s*key\b", structural
            )
        )
    if any(
        not any(
            start <= accessor.start() < end
            for start, end in allowed_key_accessor_spans
        )
        for accessor in key_accessors
    ):
        fail(
            f"action decoder scope {scope_name or '<unknown>'!r} uses a YAML "
            "key accessor outside the closed declaration/key_eq helper grammar"
        )
    scalar_key_accessors = list(
        re.finditer(
            r"\b[A-Za-z_][A-Za-z0-9_]*\.key_scalar\s*\(\s*\)",
            structural,
        )
    )
    allowed_scalar_key_spans = [
        diagnostic.span()
        for diagnostic in re.finditer(
            r"\bentry\.key_scalar\s*\(\s*\)\.location\s*\(\s*\)",
            structural,
        )
    ]
    if scope_name == "require_nonempty_key":
        allowed_scalar_key_spans.extend(
            validation.span()
            for validation in re.finditer(
                r"\bscalar_string\s*\(\s*entry\.key_scalar\s*\(\s*\)\s*\)"
                r"\.is_empty\s*\(\s*\)",
                structural,
            )
        )
    if any(
        not any(
            start <= accessor.start() < end
            for start, end in allowed_scalar_key_spans
        )
        for accessor in scalar_key_accessors
    ):
        fail(
            f"action decoder scope {scope_name or '<unknown>'!r} reads key_scalar "
            "outside the closed nonempty-key validation/diagnostic grammar"
        )
    if not selectors:
        return

    allowed_spans = list(governed_selector_spans)
    allowed_spans.extend(
        derivation.span("child") for derivation in derivations
    )
    for propagation in propagations:
        if (
            propagation["child"] in selectors
            or propagation["parent"] in selectors
        ):
            allowed_spans.extend(
                (propagation.span("child"), propagation.span("parent"))
            )
    for selector in selectors:
        allowed_spans.extend(
            sink.span("selector")
            for sink in re.finditer(
                rf"\bignored\.push\s*\(\s*(?P<selector>"
                rf"{re.escape(selector)})\s*\)",
                structural,
            )
        )
        allowed_spans.extend(
            sink.span("selector")
            for sink in re.finditer(
                rf"\b(?:ActionInput|ActionOutput|MetadataKeyValue)::new\s*"
                rf"\(\s*(?P<selector>{re.escape(selector)})\b",
                structural,
            )
        )

    other_operand = (
        r'(?P<other>r#{0,255}".*?"#{0,255}|'
        r'"(?:\\.|[^"\\])*"|[A-Za-z_][A-Za-z0-9_]*)'
    )
    for selector in selectors:
        comparisons = [
            *re.finditer(
                rf"\b{re.escape(selector)}\b\s*==\s*{other_operand}",
                source,
                re.DOTALL,
            ),
            *re.finditer(
                rf"{other_operand}\s*==\s*\b{re.escape(selector)}\b",
                source,
                re.DOTALL,
            ),
        ]
        for comparison in comparisons:
            operator = source.find("==", comparison.start(), comparison.end())
            if operator < 0 or structural[operator : operator + 2] != "==":
                continue
            if selector not in governed_selectors:
                fail(
                    f"action decoded key {selector!r} in "
                    f"{scope_name or 'unknown scope'} is compared outside key_eq"
                )
            field = resolved_field_expression(
                comparison["other"],
                constants,
                f"action selector comparison in {scope_name or 'unknown scope'}",
            )
            if field not in known_fields:
                fail(
                    f"action selector comparison in {scope_name or 'unknown scope'} "
                    f"uses field {field!r} outside its governed key_eq call"
                )
            allowed_spans.append(comparison.span())

    unsupported = sorted(
        {
            selector
            for selector in selectors
            for use in re.finditer(rf"\b{re.escape(selector)}\b", structural)
            if not structural[: use.start()].rstrip().endswith(".")
            if not any(start <= use.start() < end for start, end in allowed_spans)
        }
    )
    if unsupported:
        fail(
            f"action decoder scope {scope_name or '<unknown>'!r} uses field "
            f"selectors {unsupported} outside the closed key_eq/exact-comparison grammar"
        )


def field_name_match_fields(
    source: str, module_constants: dict[str, str | None] | None = None
) -> set[str]:
    structural = rust_source_mask(source, mask_strings=True)
    constants = dict(module_constants or {})
    local_constants = rust_string_constants(source, "field-name match")
    constants.update(local_constants)
    aliases = set(
        re.findall(
            r"\blet\s+([a-z_][A-Za-z0-9_]*)\s*=\s*field_name\s*\([^;]*\)\s*;",
            structural,
        )
    )
    scrutinees = [r"field_name\s*\([^)]*\)", *map(re.escape, sorted(aliases))]
    match_pattern = re.compile(
        rf"\bmatch\s+(?:{'|'.join(scrutinees)})\s*\{{"
    )
    fields: set[str] = set()
    for declaration in match_pattern.finditer(structural):
        opening = structural.find("{", declaration.start(), declaration.end())
        block = rust_block(source, opening, "field-name match")
        block_structural = rust_source_mask(block, mask_strings=True)
        nesting: list[tuple[int, int, int]] = []
        brace_depth = 0
        round_depth = 0
        square_depth = 0
        for character in block_structural:
            nesting.append((brace_depth, round_depth, square_depth))
            if character == "{":
                brace_depth += 1
            elif character == "}":
                brace_depth -= 1
            elif character == "(":
                round_depth += 1
            elif character == ")":
                round_depth -= 1
            elif character == "[":
                square_depth += 1
            elif character == "]":
                square_depth -= 1
        governed_arms: list[tuple[int, list[str]]] = []
        for arm_index, arm in enumerate(
            re.finditer(
                r"(?:^|[{},])\s*(?P<some>\bSome\s*\()",
                block_structural,
            )
        ):
            some_start = arm.start("some")
            if nesting[some_start] != (1, 0, 0):
                continue
            arm_opening = block_structural.find(
                "(", some_start, arm.end("some")
            )
            arm_closing = matching_parenthesis(
                block_structural,
                arm_opening,
                f"field-name match arm {arm_index}",
            )
            tail = block_structural[arm_closing + 1 :]
            if re.match(r"\s*(?:if\b(?:(?!=>).)*?)?=>", tail, re.DOTALL) is None:
                fail(
                    f"field-name match arm {arm_index} must use a direct "
                    "Some(field-pattern) arm"
                )
            pattern = block[arm_opening + 1 : arm_closing].strip()
            literals = split_rust_arguments(pattern.replace("|", ","))
            if not literals:
                fail(f"field-name match arm {arm_index} has no field patterns")
            governed_arms.append((arm_index, literals))
        if not governed_arms:
            continue
        has_field_pattern = any(
            re.fullmatch(r"[a-z_][A-Za-z0-9_]*", literal.strip()) is None
            or literal.strip() in constants
            for _, literals in governed_arms
            for literal in literals
        )
        if not has_field_pattern:
            # `Some(name)` is a binding match, not a governed field match.
            continue
        if re.search(r"\bpreserve_unknown\s*\(", block_structural) is None:
            fail("field-name match with field patterns must directly call preserve_unknown")
        for arm_index, literals in governed_arms:
            fields.update(
                resolved_field_expression(
                    literal,
                    constants,
                    f"field-name match arm {arm_index}",
                )
                for literal in literals
            )
    return fields


ACTION_DYNAMIC_FIELD_ARGUMENTS = {
    "condition_or_always": {
        ("optional_exact_scalar", 1, "key"),
    },
    "required_exact_scalar": {
        ("take_exact", 0, "key"),
    },
    "optional_exact_scalar": {
        ("take_exact", 0, "key"),
    },
    "Fields::validate_allowed": {
        ("key_eq", 1, "known"),
    },
    "Fields::take_insensitive": {
        ("key_eq", 1, "key"),
    },
}


def action_field_expression(
    expression: str,
    constants: dict[str, str | None],
    scope_name: str | None,
    function: str,
    argument_index: int,
    context: str,
) -> str | None:
    stripped = expression.strip()
    identifier = re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", stripped)
    if identifier is not None and identifier[0] not in constants:
        allowed = ACTION_DYNAMIC_FIELD_ARGUMENTS.get(scope_name or "", set())
        if (function, argument_index, identifier[0]) in allowed:
            return None
    return resolved_field_expression(stripped, constants, context)


def censused_action_metadata_fields(
    source: str,
    *,
    scope_name: str | None = None,
    module_constants: dict[str, str | None] | None = None,
) -> set[str]:
    fields: set[str] = set()
    constants = dict(module_constants or {})
    constants.update(rust_string_constants(source, scope_name or "action decoder"))
    key_calls = rust_call_arguments(source, "key_eq")
    allowed_calls = rust_call_arguments(source, "validate_allowed")
    direct_calls = {
        function: rust_call_arguments(source, function)
        for function in ("has_exact", "take_exact", "take_insensitive")
    }
    scalar_calls = {
        function: rust_call_arguments(source, function)
        for function in (
            "required_exact_scalar",
            "optional_exact_scalar",
            "condition_or_always",
        )
    }
    for call_index, arguments in enumerate(key_calls):
        if len(arguments) != 2:
            fail(f"action key_eq call {call_index} must have exactly two arguments")
        field = action_field_expression(
            arguments[1],
            constants,
            scope_name,
            "key_eq",
            1,
            f"action key_eq call {call_index}",
        )
        if field is not None:
            fields.add(field)
    for call_index, arguments in enumerate(allowed_calls):
        if not arguments:
            fail(f"action validate_allowed call {call_index} has no allowed-field list")
        allowed = arguments[0].strip()
        if not allowed.startswith("&[") or not allowed.endswith("]"):
            fail(
                f"action validate_allowed call {call_index} must use an inline field list"
            )
        entries = split_rust_arguments(allowed[2:-1])
        if not entries:
            fail(f"action validate_allowed call {call_index} has an empty field list")
        for entry in entries:
            field = action_field_expression(
                entry,
                constants,
                scope_name,
                "validate_allowed",
                0,
                f"action validate_allowed call {call_index}",
            )
            if field is not None:
                fields.add(field)
    for function in ("has_exact", "take_exact", "take_insensitive"):
        for call_index, arguments in enumerate(direct_calls[function]):
            if len(arguments) != 1:
                fail(f"action {function} call {call_index} must have one argument")
            field = action_field_expression(
                arguments[0],
                constants,
                scope_name,
                function,
                0,
                f"action {function} call {call_index}",
            )
            if field is not None:
                fields.add(field)
    for function in (
        "required_exact_scalar",
        "optional_exact_scalar",
        "condition_or_always",
    ):
        for call_index, arguments in enumerate(scalar_calls[function]):
            if len(arguments) < 2:
                fail(f"action {function} call {call_index} lacks its field argument")
            field = action_field_expression(
                arguments[1],
                constants,
                scope_name,
                function,
                1,
                f"action {function} call {call_index}",
            )
            if field is not None:
                fields.add(field)
    for comparison_index, expression in enumerate(
        equality_field_expressions(source, constants)
    ):
        compared_field = resolved_field_expression(
            expression,
            constants,
            f"action direct field comparison {comparison_index}",
        )
        if compared_field not in fields:
            fail(
                f"action direct comparison uses field {compared_field!r} "
                "outside the closed governed field-call grammar"
            )
    validate_action_selector_use_grammar(
        source, constants, fields, scope_name
    )
    return fields


RUST_TOP_LEVEL_FUNCTION = re.compile(
    r"(?m)^(?:pub(?:\([^\r\n)]*\))?\s+)?(?:async\s+)?fn\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^\r\n{}]*>)?\s*\("
)
RUST_METHOD = re.compile(
    r"(?m)^\s{4}(?:pub(?:\([^\r\n)]*\))?\s+)?(?:const\s+)?(?:async\s+)?fn\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^\r\n{}]*>)?\s*\("
)
RUST_IMPL = re.compile(
    r"(?m)^impl(?:<[^\r\n{}]*>)?\s+"
    r"(?:(?:[A-Za-z_][A-Za-z0-9_:]*(?:<[^\r\n{}]*>)?)\s+for\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:<[^\r\n{}]*>)?\s*\{"
)


def rust_declaration_block(source: str, declaration: re.Match[str], context: str) -> str:
    opening = rust_source_mask(source, mask_strings=True).find("{", declaration.end())
    if opening < 0:
        fail(f"{context} has no function body")
    return source[declaration.start() : opening] + rust_block(source, opening, context)


def rust_top_level_functions(source: str, context: str) -> dict[str, str]:
    functions: dict[str, str] = {}
    structural = rust_source_mask(source, mask_strings=True)
    for declaration in RUST_TOP_LEVEL_FUNCTION.finditer(structural):
        name = declaration["name"]
        if name in functions:
            fail(f"{context} contains duplicate top-level function {name!r}")
        functions[name] = rust_declaration_block(
            source, declaration, f"{context} function {name!r}"
        )
    return functions


def rust_named_scopes(source: str, context: str) -> dict[str, str]:
    scopes = rust_top_level_functions(source, context)
    structural = rust_source_mask(source, mask_strings=True)
    for implementation in RUST_IMPL.finditer(structural):
        type_name = implementation["name"]
        opening = structural.find("{", implementation.start(), implementation.end())
        body = rust_block(source, opening, f"{context} impl {type_name!r}")
        structural_body = rust_source_mask(body, mask_strings=True)
        for method in RUST_METHOD.finditer(structural_body):
            qualified = f"{type_name}::{method['name']}"
            if qualified in scopes:
                fail(f"{context} contains duplicate function scope {qualified!r}")
            method_source = body[method.start() :]
            structural_method = structural_body[method.start() :]
            opening = structural_method.find("{", method.end() - method.start())
            if opening < 0:
                fail(f"{context} method {qualified!r} has no function body")
            scopes[qualified] = method_source[:opening] + rust_block(
                method_source, opening, f"{context} method {qualified!r}"
            )
    return scopes


def action_decoder_field_scopes(source: str) -> dict[str, set[str]]:
    module_constants = rust_string_constants(
        source, "action decoder", top_level_only=True
    )
    return {
        name: fields
        for name, scope in rust_named_scopes(source, "action decoder").items()
        if (
            fields := action_metadata_fields(
                scope,
                scope_name=name,
                module_constants=module_constants,
            )
        )
    }


def validate_action_surface_coverage(
    source: str, inventoried: set[str]
) -> dict[str, set[str]]:
    actual = action_decoder_field_scopes(source)
    if inventoried != set(actual):
        fail(
            "action decoder field-surface inventory drifted: "
            f"missing={sorted(set(actual) - inventoried)}, "
            f"stale={sorted(inventoried - set(actual))}"
        )
    return actual


def action_runtime_targets(source: str) -> dict[str, str]:
    return action_runtime_dispatches(source)


def validate_action_runtime_target_coverage(
    source: str, inventoried: set[str]
) -> dict[str, str]:
    targets = action_runtime_targets(source)
    if set(targets) != inventoried:
        fail(
            "action runtime target inventory drifted: "
            f"missing={sorted(set(targets) - inventoried)}, "
            f"stale={sorted(inventoried - set(targets))}"
        )
    return targets


def rust_token_fingerprint(source: str) -> str:
    """Return Rust tokens without trivia while retaining literal bytes and boundaries."""

    tokens: list[str] = []
    index = 0
    punctuation = (
        "<<=",
        ">>=",
        "...",
        "..=",
        "::",
        "->",
        "=>",
        "==",
        "!=",
        "<=",
        ">=",
        "&&",
        "||",
        "+=",
        "-=",
        "*=",
        "/=",
        "%=",
        "^=",
        "&=",
        "|=",
        "<<",
        ">>",
        "..",
        "##",
    )
    while index < len(source):
        if source[index].isspace():
            index += 1
            continue
        if source.startswith("//", index):
            newline = source.find("\n", index + 2)
            index = len(source) if newline < 0 else newline + 1
            continue
        if source.startswith("/*", index):
            depth = 1
            position = index + 2
            while position < len(source) and depth:
                if source.startswith("/*", position):
                    depth += 1
                    position += 2
                elif source.startswith("*/", position):
                    depth -= 1
                    position += 2
                else:
                    position += 1
            if depth:
                fail("unterminated Rust block comment in governed source")
            index = position
            continue

        raw_literal = re.match(
            r'(?:br|cr|r)(?P<hashes>#{0,255})"', source[index:]
        )
        if raw_literal is not None:
            terminator = '"' + raw_literal["hashes"]
            ending = source.find(terminator, index + raw_literal.end())
            if ending < 0:
                fail("unterminated Rust raw literal in governed source")
            ending += len(terminator)
            tokens.append(source[index:ending])
            index = ending
            continue

        normal_literal = re.match(r'(?:b|c)?"', source[index:])
        if normal_literal is not None:
            position = index + normal_literal.end()
            while position < len(source):
                if source[position] == "\\":
                    position += 2
                    continue
                if source[position] == '"':
                    position += 1
                    break
                position += 1
            else:
                fail("unterminated Rust string literal in governed source")
            tokens.append(source[index:position])
            index = position
            continue

        character_literal = re.match(
            r"(?:b)?'(?:[^\\'\r\n]|\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]+\}|[^\r\n]))'",
            source[index:],
        )
        if character_literal is not None:
            tokens.append(character_literal[0])
            index += character_literal.end()
            continue

        raw_identifier = re.match(r"r#[A-Za-z_][A-Za-z0-9_]*", source[index:])
        if raw_identifier is not None:
            tokens.append(raw_identifier[0])
            index += raw_identifier.end()
            continue
        lifetime = re.match(r"'[A-Za-z_][A-Za-z0-9_]*", source[index:])
        if lifetime is not None:
            tokens.append(lifetime[0])
            index += lifetime.end()
            continue
        identifier = re.match(r"[A-Za-z_][A-Za-z0-9_]*", source[index:])
        if identifier is not None:
            tokens.append(identifier[0])
            index += identifier.end()
            continue
        number = re.match(
            r"(?:0[bB][01_]+|0[oO][0-7_]+|0[xX][0-9A-Fa-f_]+|"
            r"[0-9][0-9_]*(?:\.(?!\.)[0-9_]*)?(?:[eE][+-]?[0-9_]+)?)"
            r"(?:[A-Za-z_][A-Za-z0-9_]*)?",
            source[index:],
        )
        if number is not None:
            tokens.append(number[0])
            index += number.end()
            continue

        operator = next(
            (value for value in punctuation if source.startswith(value, index)), None
        )
        if operator is not None:
            tokens.append(operator)
            index += len(operator)
            continue
        tokens.append(source[index])
        index += 1

    return json.dumps(tokens, ensure_ascii=False, separators=(",", ":"))


def rust_token_digest(source: str) -> str:
    return hashlib.sha256(rust_token_fingerprint(source).encode("utf-8")).hexdigest()


def validate_semantic_key_helpers(
    action_parser_source: str, workflow_decode_source: str
) -> None:
    expected_key_eq = """
pub(crate) fn key_eq(actual: &str, expected: &str) -> bool {
    actual.eq_ignore_ascii_case(expected)
}
"""
    actual_key_eq = rust_function_source(
        action_parser_source, "key_eq", "action key_eq helper"
    )
    if rust_token_fingerprint(actual_key_eq) != rust_token_fingerprint(
        expected_key_eq
    ):
        fail("action key_eq helper definition drifted from its governed semantics")

    expected_field_name = """
pub(super) fn field_name(entry: &YamlMappingEntry) -> Option<&str> {
    entry.key.as_scalar().map(|scalar| scalar.decoded.as_str())
}
"""
    actual_field_name = rust_function_source(
        workflow_decode_source, "field_name", "workflow field_name helper"
    )
    if rust_token_fingerprint(actual_field_name) != rust_token_fingerprint(
        expected_field_name
    ):
        fail("workflow field_name helper definition drifted from its governed semantics")

    action_scopes = rust_named_scopes(action_parser_source, "action parser")
    expected_action_key_scopes = {
        "YamlNode::into_mapping",
        "YamlMappingEntry::key",
        "YamlMappingEntry::key_scalar",
        "Receiver::attach",
    }
    actual_action_key_scopes = {
        name
        for name, scope in action_scopes.items()
        if name in {"YamlMappingEntry::key", "YamlMappingEntry::key_scalar"}
        or re.search(
            r"\bYamlMappingEntry\b|\.key\s*\(|::key\s*\(|\bkey_scalar\s*\(",
            rust_source_mask(scope, mask_strings=True),
        )
    }
    if actual_action_key_scopes != expected_action_key_scopes:
        fail(
            "action parser YAML-key helper surface drifted: "
            f"missing={sorted(expected_action_key_scopes - actual_action_key_scopes)}, "
            f"extra={sorted(actual_action_key_scopes - expected_action_key_scopes)}"
        )

    expected_action_key_scope_digests = {
        "YamlNode::into_mapping": "db4ac0ee1ed00250a68ac5752d9113d930dbf8b87783c2724fc748bc2f369f6c",
        "YamlMappingEntry::key": "cd382e45f85c6c3e94b146b0d6ba2ca2c85b837a5f0312c71d1f64329d03944f",
        "YamlMappingEntry::key_scalar": "1ab1ef3c4ee79df5a7d5bc6472fd828e830997b275fda3c9b7f88c5ce34dbaf2",
        "Receiver::attach": "cc9069deffd19558d72a7a482be3632040a077eb23a131a2c9a0a71b89040066",
    }
    for name, expected_digest in expected_action_key_scope_digests.items():
        if rust_token_digest(action_scopes[name]) != expected_digest:
            fail(
                f"action parser key-bearing scope {name!r} drifted from governed semantics"
            )

    workflow_scopes = rust_named_scopes(workflow_decode_source, "workflow decoder")
    expected_workflow_key_scopes = {
        "field_name",
        "DecodeContext::expect_mapping",
        "DecodeContext::preserve_unknown",
    }
    actual_workflow_key_scopes = {
        name
        for name, scope in workflow_scopes.items()
        if re.search(
            r"\bYamlMappingEntry\b|\.key\b|::key\s*\(|\bfield_name\s*\(",
            rust_source_mask(scope, mask_strings=True),
        )
    }
    if actual_workflow_key_scopes != expected_workflow_key_scopes:
        fail(
            "workflow YAML-key helper surface drifted: "
            f"missing={sorted(expected_workflow_key_scopes - actual_workflow_key_scopes)}, "
            f"extra={sorted(actual_workflow_key_scopes - expected_workflow_key_scopes)}"
        )

    expected_workflow_key_scope_digests = {
        "field_name": "b51e3c6c4df8808936881889ec7a852735fdffaa09862571290068ef0a2196bb",
        "DecodeContext::expect_mapping": "2f6a636aa023aae5579d31de7facc019a596fb85ad4b11753ca85d2871a61afb",
        "DecodeContext::preserve_unknown": "85de09bd450f5f9bd2307d5e319df06a9ee17aa71e7bdbdad6c0334cc026ad5e",
    }
    for name, expected_digest in expected_workflow_key_scope_digests.items():
        if rust_token_digest(workflow_scopes[name]) != expected_digest:
            fail(
                f"workflow key-bearing scope {name!r} drifted from governed semantics"
            )


def action_function_calls(source: str) -> dict[str, set[str]]:
    functions = rust_named_scopes(source, "action decoder")
    names = set(functions)
    return {
        caller: {
            callee
            for callee in names
            if callee != caller
            and re.search(
                rf"\b{re.escape(callee.rsplit('::', maxsplit=1)[-1])}\s*\(",
                rust_source_mask(scope, mask_strings=True),
            )
        }
        for caller, scope in functions.items()
    }


def validate_field_name_use_grammar(scope: str, scope_name: str) -> None:
    structural = rust_source_mask(scope, mask_strings=True)
    identifiers = list(re.finditer(r"\bfield_name\b", structural))
    calls = list(re.finditer(r"\bfield_name\s*\(", structural))
    if re.search(r"\bYamlMappingEntry\s*\{", structural):
        fail(
            f"container decoder scope {scope_name!r} destructures "
            "YamlMappingEntry outside the governed field_name helper"
        )
    if re.search(r"::key\s*\(", structural):
        fail(
            f"container decoder scope {scope_name!r} calls a UFCS key "
            "accessor outside the governed field_name helper"
        )
    if scope_name not in {"job_services", "container_environment"}:
        for access in re.finditer(r"\.key\b", structural):
            if re.match(r"\s*\.span\b", structural[access.end() :]) is None:
                fail(
                    f"container decoder scope {scope_name!r} reads a mapping .key "
                    "outside field_name(entry); only diagnostic span access is allowed"
                )
    if len(identifiers) != len(calls):
        fail(
            f"container decoder scope {scope_name!r} uses field_name "
            "outside a direct call"
        )
    direct_matches = list(
        re.finditer(r"\bmatch\s+field_name\s*\(", structural)
    )
    aliases = list(
        re.finditer(
            r"\blet\s+([a-z_][A-Za-z0-9_]*)\s*=\s*"
            r"field_name\s*\([^;]*\)\s*;",
            structural,
        )
    )
    matched_aliases: list[re.Match[str]] = []
    for alias in aliases:
        alias_name = alias[1]
        matches = list(
            re.finditer(
                rf"\bmatch\s+(?P<alias>{re.escape(alias_name)})\s*\{{",
                structural,
            )
        )
        if len(matches) != 1:
            fail(
                f"container decoder scope {scope_name!r} must use field_name "
                f"alias {alias_name!r} in exactly one governed match"
            )
        allowed_alias_spans = [alias.span(1), matches[0].span("alias")]
        if any(
            not any(start <= use.start() < end for start, end in allowed_alias_spans)
            for use in re.finditer(rf"\b{re.escape(alias_name)}\b", structural)
        ):
            fail(
                f"container decoder scope {scope_name!r} uses field_name alias "
                f"{alias_name!r} outside its declaration and governed match"
            )
        matched_aliases.append(alias)
    if len(calls) != len(direct_matches) + len(matched_aliases):
        fail(
            f"container decoder scope {scope_name!r} must use every field_name "
            "call directly as a governed match scrutinee"
        )


def container_decoder_field_scopes(source: str) -> dict[str, set[str]]:
    module_constants = rust_string_constants(
        source, "container decoder", top_level_only=True
    )
    field_scopes: dict[str, set[str]] = {}
    for name, scope in rust_named_scopes(source, "container decoder").items():
        validate_field_name_use_grammar(scope, name)
        fields = some_match_fields(scope, module_constants)
        if fields:
            field_scopes[name] = fields
    return field_scopes


def rust_container_kind_constants(
    source: str, *, top_level_only: bool = False
) -> dict[str, str | None]:
    structural = rust_source_mask(source, mask_strings=True)
    depths: list[int] = []
    depth = 0
    for character in structural:
        depths.append(depth)
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
    constants: dict[str, str | None] = {}
    for declaration in re.finditer(
        r"(?m)^\s*const\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*"
        r"ContainerKind\s*=\s*([^;]+);",
        structural,
    ):
        if top_level_only and depths[declaration.start()] != 0:
            continue
        name = declaration[1]
        if name in constants:
            constants[name] = None
        else:
            constants[name] = source[
                declaration.start(2) : declaration.end(2)
            ].strip()
    return constants


def resolved_container_kind_expression(
    expression: str,
    constants: dict[str, str | None],
    context: str,
    resolving: tuple[str, ...] = (),
) -> str:
    value = expression.strip()
    direct = re.fullmatch(r"ContainerKind::([A-Z][A-Za-z0-9_]*)", value)
    if direct is not None:
        return direct[1]
    identifier = re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value)
    if identifier is not None and identifier[0] in constants:
        name = identifier[0]
        if name in resolving:
            fail(f"{context} resolves through a cyclic ContainerKind constant {name!r}")
        if constants[name] is None:
            fail(f"{context} refers to an ambiguously declared ContainerKind constant {name!r}")
        return resolved_container_kind_expression(
            constants[name] or "", constants, context, (*resolving, name)
        )
    fail(
        f"{context} must use a canonical ContainerKind variant, a typed constant "
        "that resolves to one, or a propagated ContainerKind parameter"
    )


def container_kind_parameters(scope: str) -> set[str]:
    structural = rust_source_mask(scope, mask_strings=True)
    declaration = re.search(r"\bfn\s+[A-Za-z_][A-Za-z0-9_]*[^({]*\(", structural)
    if declaration is None:
        return set()
    opening = structural.find("(", declaration.start(), declaration.end())
    closing = matching_parenthesis(
        structural, opening, "container decoder function parameters"
    )
    parameters: set[str] = set()
    for parameter in split_rust_arguments(scope[opening + 1 : closing]):
        typed = re.fullmatch(
            r"(?:mut\s+)?([a-z_][A-Za-z0-9_]*)\s*:\s*ContainerKind",
            parameter.strip(),
        )
        if typed is not None:
            parameters.add(typed[1])
    return parameters


def container_decoder_surface_edges(source: str) -> set[tuple[str, str]]:
    scopes = rust_named_scopes(source, "container decoder")
    module_kind_constants = rust_container_kind_constants(
        source, top_level_only=True
    )

    seed_kinds: dict[str, set[str]] = {}
    dynamic_parse_callers: set[str] = set()
    for function, scope in scopes.items():
        structural_scope = rust_source_mask(scope, mask_strings=True)
        kind_constants = dict(module_kind_constants)
        kind_constants.update(rust_container_kind_constants(scope))
        kinds = set(
            re.findall(
                r"\bContainerKind::([A-Z][A-Za-z0-9_]*)\b",
                structural_scope,
            )
        )
        for name in kind_constants:
            if re.search(rf"\b{re.escape(name)}\b", structural_scope):
                kinds.add(
                    resolved_container_kind_expression(
                        name,
                        kind_constants,
                        f"container kind use in {function}",
                    )
                )
        if kinds:
            seed_kinds[function] = kinds
        kind_parameters = container_kind_parameters(scope)
        for call_index, arguments in enumerate(
            rust_call_arguments(scope, "parse_container")
        ):
            if len(arguments) != 4:
                fail(
                    f"container parse call {function}[{call_index}] must have four arguments"
                )
            kind_expression = arguments[2].strip()
            direct = re.fullmatch(
                r"ContainerKind::([A-Z][A-Za-z0-9_]*)", kind_expression
            )
            if direct is not None:
                seed_kinds.setdefault(function, set()).add(direct[1])
            elif kind_expression in kind_constants:
                seed_kinds.setdefault(function, set()).add(
                    resolved_container_kind_expression(
                        kind_expression,
                        kind_constants,
                        f"container parse call {function}[{call_index}]",
                    )
                )
            elif kind_expression in kind_parameters:
                dynamic_parse_callers.add(function)
            else:
                fail(
                    f"container parse call {function}[{call_index}] has an "
                    "unresolved kind expression"
                )
    calls = {
        caller: {
            callee
            for callee in scopes
            if callee != caller
            and re.search(
                rf"\b{re.escape(callee.rsplit('::', maxsplit=1)[-1])}\s*\(",
                rust_source_mask(scope, mask_strings=True),
            )
        }
        for caller, scope in scopes.items()
    }
    surface_kinds = {
        function: set(kinds) for function, kinds in seed_kinds.items()
    }
    changed = True
    while changed:
        changed = False
        for caller, callees in calls.items():
            inherited = set().union(
                *(surface_kinds.get(callee, set()) for callee in callees)
            )
            current = surface_kinds.setdefault(caller, set())
            if not inherited <= current:
                current.update(inherited)
                changed = True
    flow_kinds = {function: set(kinds) for function, kinds in seed_kinds.items()}
    changed = True
    while changed:
        changed = False
        for caller, callees in calls.items():
            for callee in callees:
                inherited = flow_kinds.get(caller, set())
                current = flow_kinds.setdefault(callee, set())
                if not inherited <= current:
                    current.update(inherited)
                    changed = True
    unresolved_dynamic_callers = sorted(
        function
        for function in dynamic_parse_callers
        if not flow_kinds.get(function)
    )
    if unresolved_dynamic_callers:
        fail(
            "container parse calls have dynamically unbound kinds in functions "
            f"{unresolved_dynamic_callers}"
        )
    return {
        (function, kind)
        for function, kinds in surface_kinds.items()
        for kind in kinds
    }


def validate_container_surface_coverage(
    source: str, inventoried: set[tuple[str, str, str]]
) -> tuple[dict[str, set[str]], set[tuple[str, str]]]:
    field_scopes = container_decoder_field_scopes(source)
    surface_edges = container_decoder_surface_edges(source)
    expected = {
        (surface, kind, function)
        for surface, kind in surface_edges
        for function in field_scopes
    }
    if inventoried != expected:
        fail(
            "container decoder surface inventory drifted: "
            f"missing={sorted(expected - inventoried)}, "
            f"stale={sorted(inventoried - expected)}"
        )
    return field_scopes, surface_edges


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
        {"driver", "package", "runner", "selection", "workflow"},
        context,
    )
    package = string(lane["package"], f"{context}.package")
    selection = string(lane["selection"], f"{context}.selection")
    if selection != "--tests" and re.fullmatch(r"--test [A-Za-z0-9_-]+", selection) is None:
        fail(f"{context}.selection must be --tests or one exact --test target")
    runner = repository_file(root, lane["runner"], f"{context}.runner")
    driver = repository_file(root, lane["driver"], f"{context}.driver")
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
    runner_invocation = f"./{runner.relative_to(root).as_posix()}"
    if re.search(
        rf"(?m)^\s*{re.escape(runner_invocation)}(?:\s|$)",
        driver.read_text(encoding="utf-8"),
    ) is None:
        fail(f"{context}.driver does not invoke the declared runner")
    driver_invocation = f"./{driver.relative_to(root).as_posix()}"
    if re.search(
        rf"(?m)^\s*{re.escape(driver_invocation)}(?:\s|$)",
        workflow.read_text(encoding="utf-8"),
    ) is None:
        fail(f"{context}.workflow does not invoke the declared driver")


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


RUNNER_BASELINE_KEYS = {
    "baseline_commit",
    "baseline_release",
    "javascript_runtime",
    "release_url",
    "repository",
}


def validate_runner_baseline(value: Any, context: str) -> dict[str, Any]:
    runner = exact_object(value, RUNNER_BASELINE_KEYS, context)
    if runner["repository"] != "actions/runner":
        fail(f"{context} must identify actions/runner")
    commit = string(runner["baseline_commit"], f"{context} commit")
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        fail(f"{context} commit must be an immutable Git object ID")
    release = string(runner["baseline_release"], f"{context} release")
    if re.fullmatch(r"v[1-9][0-9]*\.[0-9]+\.[0-9]+", release) is None:
        fail(f"{context} release must be a canonical runner release")
    string(runner["javascript_runtime"], f"{context} JavaScript runtime")
    release_url = string(runner["release_url"], f"{context} release URL")
    expected_release_url = f"https://github.com/actions/runner/releases/tag/{release}"
    if release_url != expected_release_url:
        fail(f"{context} release URL must exactly bind {release}")
    return runner


def reference_source_revision(reference: dict[str, Any]) -> tuple[str, str]:
    match = re.fullmatch(
        r"https://raw\.githubusercontent\.com/([^/]+/[^/]+)/([0-9a-f]{40})/.+",
        reference["url"],
    )
    if match is None:
        fail(f"reference {reference['id']!r} does not expose an immutable source revision")
    return match[1], match[2]


def snapshot_source_revisions(snapshot: dict[str, Any]) -> set[str]:
    return {
        f"{repository}@{commit}"
        for reference in snapshot["reference_groups"]
        for repository, commit in [reference_source_revision(reference)]
    }


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
    runner = validate_runner_baseline(snapshot["runner"], "runner baseline")
    commit = runner["baseline_commit"]
    reference_revisions = {
        reference["id"]: reference_source_revision(reference)
        for reference in references
    }
    runner_references = [
        reference
        for reference in references
        if reference_revisions[reference["id"]][0] == "actions/runner"
    ]
    if not runner_references:
        fail("reference snapshot must contain runner references")
    changed_runner_references = sorted(
        reference["id"]
        for reference in runner_references
        if reference_revisions[reference["id"]][1] != commit
    )
    if changed_runner_references:
        fail(
            "runner reference URLs do not bind the exact baseline commit: "
            f"{changed_runner_references}"
        )
    misleading_runner_ids = sorted(
        reference["id"]
        for reference in references
        if reference["id"].startswith("runner-")
        and reference_revisions[reference["id"]][0] != "actions/runner"
    )
    if misleading_runner_ids:
        fail(f"runner reference IDs point outside actions/runner: {misleading_runner_ids}")
    return snapshot


def validate_reviewed_deltas(
    path: Path, snapshot: dict[str, Any]
) -> tuple[dict[str, Any], str]:
    document = exact_object(
        load_canonical(path), {"reviewed_deltas", "schema_version"}, "reviewed deltas"
    )
    if document["schema_version"] != 1:
        fail("reviewed delta schema_version must be integer 1")
    covered: set[str] = set()
    identifiers: list[str] = []
    matching_runner_baselines: list[str] = []
    reference_ids = {reference["id"] for reference in snapshot["reference_groups"]}
    required_source_revisions = snapshot_source_revisions(snapshot)
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
                "runner_baseline",
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
        source_revisions = source_revision.split("+")
        if len(source_revisions) != len(set(source_revisions)):
            fail(f"{context}.source_revision must contain unique revisions")
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
        if decision == "approved-baseline":
            runner = validate_runner_baseline(
                delta["runner_baseline"], f"{context}.runner_baseline"
            )
            runner_revision = f"actions/runner@{runner['baseline_commit']}"
            if runner_revision not in set(source_revisions):
                fail(
                    f"{context}.source_revision does not bind its exact runner baseline commit"
                )
            if (
                runner == snapshot["runner"]
                and references == reference_ids
                and set(categories) == REFERENCE_CATEGORIES
                and set(source_revisions) == required_source_revisions
            ):
                matching_runner_baselines.append(identifier)
        elif delta["runner_baseline"] is not None:
            fail(f"{context} non-baseline decision cannot authorize a runner baseline")
    if identifiers != sorted(identifiers) or len(identifiers) != len(set(identifiers)):
        fail("reviewed delta IDs must be sorted and unique")
    if covered != reference_ids:
        fail(f"reviewed deltas do not cover references: {sorted(reference_ids - covered)}")
    if len(matching_runner_baselines) != 1:
        fail(
            "exactly one approved-baseline reviewed delta must match the current "
            "runner baseline and all snapshot references"
        )
    return document, matching_runner_baselines[0]


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

    validate_semantic_key_helpers(
        repository_file(
            root,
            "crates/automata-ci-action-github/src/parser.rs",
            "action key helper source",
        ).read_text(encoding="utf-8"),
        repository_file(
            root,
            "crates/automata-ci-workflow-github/src/decode/mod.rs",
            "workflow field-name helper source",
        ).read_text(encoding="utf-8"),
    )

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
    inventory_mappings: dict[str, dict[str, frozenset[str]]] = {}
    action_function_inventories: dict[str, dict[str, frozenset[str]]] = {}
    action_runtime_mapping: dict[str, frozenset[str]] | None = None
    container_function_inventories: dict[
        tuple[str, str, str], dict[str, frozenset[str]]
    ] = {}
    named_scope_cache: dict[Path, dict[str, str]] = {}
    for index, raw in enumerate(inventories):
        extractor = raw.get("extractor") if isinstance(raw, dict) else None
        keys = {"extractor", "fields", "id", "path"}
        if extractor in {"action-function-fields", "function-some-match-arms"}:
            keys.add("function")
        elif extractor == "container-kind-function-fields":
            keys.update({"function", "kind", "surface_function"})
        inventory = exact_object(
            raw, keys, f"decoder_inventory[{index}]"
        )
        identifier = string(inventory["id"], f"decoder_inventory[{index}].id")
        if identifier in inventory_ids:
            fail(f"duplicate decoder inventory ID {identifier!r}")
        inventory_ids.add(identifier)
        fields = decoder_field_owners(
            inventory["fields"], feature_ids, f"decoder_inventory[{index}].fields"
        )
        inventory_mappings[identifier] = fields
        path = repository_file(root, inventory["path"], f"{identifier}.path")
        inventory_paths.add(path.relative_to(root).as_posix())
        source = path.read_text(encoding="utf-8")
        if extractor == "some-match-arms":
            actual = some_match_fields(source)
        elif extractor == "function-some-match-arms":
            function = string(inventory["function"], f"{identifier}.function")
            actual = some_match_fields(
                rust_function_source(source, function, identifier),
                rust_string_constants(source, identifier, top_level_only=True),
            )
        elif extractor == "action-function-fields":
            function = string(inventory["function"], f"{identifier}.function")
            if path not in named_scope_cache:
                named_scope_cache[path] = rust_named_scopes(source, identifier)
            scopes = named_scope_cache[path]
            if function not in scopes:
                fail(f"{identifier} function scope {function!r} is missing")
            actual = action_metadata_fields(
                scopes[function],
                scope_name=function,
                module_constants=rust_string_constants(
                    source, identifier, top_level_only=True
                ),
            )
            if function in action_function_inventories:
                fail(f"action decoder function {function!r} is inventoried more than once")
            action_function_inventories[function] = fields
        elif extractor == "container-kind-function-fields":
            function = string(inventory["function"], f"{identifier}.function")
            kind = string(inventory["kind"], f"{identifier}.kind")
            surface = string(
                inventory["surface_function"], f"{identifier}.surface_function"
            )
            if path not in named_scope_cache:
                named_scope_cache[path] = rust_named_scopes(source, identifier)
            scopes = named_scope_cache[path]
            if function not in scopes:
                fail(f"{identifier} function scope {function!r} is missing")
            actual = some_match_fields(
                scopes[function],
                rust_string_constants(source, identifier, top_level_only=True),
            )
            key = (surface, kind, function)
            if key in container_function_inventories:
                fail(f"container decoder scope {key!r} is inventoried more than once")
            container_function_inventories[key] = fields
        elif extractor == "action-metadata":
            actual = action_metadata_fields(source)
        elif extractor == "action-runtimes":
            actual = action_runtime_values(source)
            if action_runtime_mapping is not None:
                fail("action runtime values may be inventoried only once")
            action_runtime_mapping = fields
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
            if any(len(owners) != 1 for owners in fields.values()):
                fail("trigger names must each have exactly one feature owner")
            trigger_feature_mapping = {
                field: next(iter(owners)) for field, owners in fields.items()
            }

    action_decoder_relative = "crates/automata-ci-action-github/src/decoder.rs"
    action_source = repository_file(
        root, action_decoder_relative, "action decoder"
    ).read_text(encoding="utf-8")
    actual_action_scopes = validate_action_surface_coverage(
        action_source, set(action_function_inventories)
    )
    if action_runtime_mapping is None:
        fail("action runtime inventory is missing")
    runtime_targets = validate_action_runtime_target_coverage(
        action_source, set(action_runtime_mapping)
    )
    missing_target_scopes = sorted(set(runtime_targets.values()) - set(actual_action_scopes))
    if missing_target_scopes:
        fail(f"action runtime decoder targets lack field scopes: {missing_target_scopes}")
    required_runtime_owners = {
        "composite": frozenset({"javascript-and-local-composite-actions"}),
        "docker": frozenset({"container-actions"}),
        "node12": frozenset({"javascript-and-local-composite-actions"}),
        "node16": frozenset({"javascript-and-local-composite-actions"}),
        "node20": frozenset({"javascript-and-local-composite-actions"}),
        "node24": frozenset({"javascript-and-local-composite-actions"}),
    }
    if set(runtime_targets) != set(required_runtime_owners):
        fail(
            "action runtime set changed without a reviewed ownership rule: "
            f"missing={sorted(set(runtime_targets) - set(required_runtime_owners))}, "
            f"stale={sorted(set(required_runtime_owners) - set(runtime_targets))}"
        )
    changed_runtime_owners = sorted(
        runtime
        for runtime, required in required_runtime_owners.items()
        if action_runtime_mapping.get(runtime) != required
    )
    if changed_runtime_owners:
        fail(f"action runtime feature ownership drifted for {changed_runtime_owners}")
    if any(len(owners) != 1 for owners in action_runtime_mapping.values()):
        fail("each action runtime must have exactly one feature owner")

    calls = action_function_calls(action_source)
    concrete_function_owners: dict[str, set[str]] = {}
    for runtime, target in runtime_targets.items():
        owners = set(action_runtime_mapping[runtime])
        pending = [target]
        visited: set[str] = set()
        while pending:
            function = pending.pop()
            if function in visited:
                continue
            visited.add(function)
            if function in actual_action_scopes:
                concrete_function_owners.setdefault(function, set()).update(owners)
            pending.extend(calls.get(function, set()) - visited)
    all_runtime_owners = frozenset().union(*action_runtime_mapping.values())
    for function, mapping in action_function_inventories.items():
        if function == "decode_runs":
            expected_by_field: dict[str, frozenset[str]] = {}
            for field in actual_action_scopes[function]:
                owners = frozenset().union(
                    *(
                        action_runtime_mapping[runtime]
                        for runtime, target in runtime_targets.items()
                        if field in actual_action_scopes[target]
                    )
                )
                expected_by_field[field] = owners or all_runtime_owners
        else:
            expected = frozenset(concrete_function_owners.get(function, all_runtime_owners))
            expected_by_field = {field: expected for field in mapping}
        changed = sorted(
            field
            for field, owners in mapping.items()
            if owners != expected_by_field[field]
        )
        if changed:
            fail(
                f"action decoder function {function!r} feature ownership drifted "
                f"for fields {changed}"
            )

    container_decoder_relative = (
        "crates/automata-ci-workflow-github/src/decode/container.rs"
    )
    container_source = repository_file(
        root, container_decoder_relative, "container decoder"
    ).read_text(encoding="utf-8")
    validate_container_surface_coverage(
        container_source, set(container_function_inventories)
    )
    container_kind_owners = {
        "Job": frozenset({"job-containers"}),
        "Service": frozenset({"service-containers"}),
    }
    for (surface, kind, function), mapping in container_function_inventories.items():
        required = container_kind_owners.get(kind)
        if required is None:
            fail(f"container decoder surface {surface!r} uses unreviewed kind {kind!r}")
        changed = sorted(field for field, owners in mapping.items() if owners != required)
        if changed:
            fail(
                f"container decoder {kind} surface {surface!r} function {function!r} "
                f"feature ownership drifted for fields {changed}"
            )
    job_fields = inventory_mappings.get("job-fields")
    if job_fields is None:
        fail("job field inventory is missing")
    required_job_container_edges = {
        "container": frozenset({"job-containers"}),
        "services": frozenset({"service-containers"}),
    }
    changed_job_container_edges = sorted(
        field
        for field, required in required_job_container_edges.items()
        if job_fields.get(field) != required
    )
    if changed_job_container_edges:
        fail(
            "job container/service caller feature ownership drifted for fields "
            f"{changed_job_container_edges}"
        )

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
    snapshot_reviewed_path = repository_file(
        root,
        snapshot["replacement_policy"]["approval_registry"],
        "snapshot replacement approval registry",
    )
    if reviewed_path != snapshot_reviewed_path:
        fail("capability registry and reference snapshot name different approval registries")
    reviewed_document, matching_baseline_delta = validate_reviewed_deltas(
        reviewed_path, snapshot
    )

    governance_revision, baseline_registry = baseline_capability_registry(root)
    baseline_snapshot = baseline_governance_document(
        root, governance_revision, baseline_registry, "reference_snapshot"
    )
    baseline_reviewed = baseline_governance_document(
        root, governance_revision, baseline_registry, "reviewed_deltas"
    )
    baseline_deltas = {
        delta.get("id"): normalized_historical_reviewed_delta(
            delta, baseline_snapshot
        )
        for delta in baseline_reviewed.get("reviewed_deltas", [])
        if isinstance(delta, dict) and isinstance(delta.get("id"), str)
    }
    current_deltas = {
        delta["id"]: delta for delta in reviewed_document["reviewed_deltas"]
    }
    if (
        baseline_snapshot.get("runner") != snapshot["runner"]
        and matching_baseline_delta in baseline_deltas
    ):
        fail(
            "runner baseline changed without a newly added approved-baseline "
            "reviewed delta tied to the exact baseline and references"
        )
    missing_historical_deltas = sorted(set(baseline_deltas) - set(current_deltas))
    if missing_historical_deltas:
        fail(
            "reviewed delta history is append-only; missing historical records "
            f"{missing_historical_deltas}"
        )
    changed_historical_deltas = sorted(
        identifier
        for identifier, delta in baseline_deltas.items()
        if current_deltas[identifier] != delta
    )
    if changed_historical_deltas:
        fail(
            "reviewed delta history is append-only; changed historical records "
            f"{changed_historical_deltas}"
        )
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
