#!/usr/bin/env python3
"""Verify that aggregate integration targets own every Rust test source."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]

# A reviewed entry prevents either implicit targets or an unreviewed aggregate
# rename from silently changing the workspace test topology.
AGGREGATES = {
    "automata-ci-action": "action",
    "automata-ci-action-github": "action_github",
    "automata-ci-blob-s3": "blob_s3",
    "automata-ci-control": "control",
    "automata-ci-core": "core",
    "automata-ci-credential": "credential",
    "automata-ci-execution": "execution",
    "automata-ci-expression-github": "expression_github",
    "automata-ci-github": "github",
    "automata-ci-github-delivery": "github_delivery",
    "automata-ci-github-runtime": "github_runtime",
    "automata-ci-key-management": "key_management",
    "automata-ci-metrics": "metrics",
    "automata-ci-oidc-github": "oidc_github",
    "automata-ci-postgres": "postgres",
    "automata-ci-protocol": "protocol",
    "automata-ci-protocol-protobuf": "protocol_protobuf",
    "automata-ci-runner": "runner",
    "automata-ci-runner-crypto": "runner_crypto",
    "automata-ci-runner-journal": "runner_journal",
    "automata-ci-runner-runtime": "runner_runtime",
    "automata-ci-runner-spool": "runner_spool",
    "automata-ci-runner-transport": "runner_transport",
    "automata-ci-sandbox-kubernetes": "sandbox_kubernetes",
    "automata-ci-sandbox-podman": "sandbox_podman",
    "automata-ci-secret": "secret",
    "automata-ci-store": "store_contracts",
    "automata-ci-ui-renderer": "ui_renderer",
    "automata-ci-workflow-github": "workflow_github",
    "automata-ci-workflow-service": "workflow_service",
}

# Live service probes retain process and credential isolation while hermetic
# siblings consolidate into the package aggregate named above.
LIVE_TARGETS = {
    "automata-ci-action": "live_github_rustfs",
    "automata-ci-action-github": "live_checkout_pipeline",
    "automata-ci-github": "live_repository_snapshot",
    "automata-ci-sandbox-podman": "live_rootless",
    "automata-ci-workflow-service": "live_admission",
}

# These reviewed support modules are intentionally compiled by both their
# hermetic and live targets. Every other source must have exactly one owner.
SHARED_SOURCE_OWNERS = {
    "automata-ci-sandbox-podman": {
        "support/mod.rs": frozenset({"sandbox_podman", "live_rootless"}),
    },
    "automata-ci-workflow-service": {
        "support/mod.rs": frozenset({"workflow_service", "live_admission"}),
    },
}

# These source-level gates are intentional platform contracts. Pinning the
# exact file and expression prevents a newly disabled test source from being
# mistaken for ordinary aggregate ownership.
INNER_CFG_EXCEPTIONS = {
    "crates/automata-ci-sandbox-podman/tests/command_executor.rs":
        '#![cfg(target_os = "linux")]',
    "crates/automata-ci-sandbox-podman/tests/lifecycle.rs":
        '#![cfg(target_os = "linux")]',
    "crates/automata-ci-sandbox-podman/tests/live_rootless.rs":
        '#![cfg(target_os = "linux")]',
    "crates/automata-ci-sandbox-podman/tests/observability.rs":
        '#![cfg(target_os = "linux")]',
    "crates/automata-ci-sandbox-podman/tests/service_containers.rs":
        '#![cfg(target_os = "linux")]',
    "crates/automata-ci-sandbox-podman/tests/state_security.rs":
        '#![cfg(target_os = "linux")]',
    "crates/automata-ci-sandbox-podman/tests/support/mod.rs":
        '#![cfg(target_os = "linux")]',
    "crates/automata-ci-runner/tests/macos_vm_runner_process_e2e.rs":
        '#![cfg(target_os = "macos")]',
    "crates/automata-ci-runner/tests/podman_active_probe.rs":
        '#![cfg(target_os = "linux")]',
    "crates/automata-ci-runner/tests/product_context.rs":
        '#![cfg(any(target_os = "linux", target_os = "macos", windows))]',
    "crates/automata-ci-runner/tests/product_secret_sources.rs": "#![cfg(unix)]",
    "crates/automata-ci-runner/tests/runner_product_config.rs":
        '#![cfg(target_os = "linux")]',
    "crates/automata-ci-runner/tests/runner_product_config_macos.rs":
        '#![cfg(all(target_os = "macos", target_arch = "aarch64"))]',
    "crates/automata-ci-runner/tests/runner_product_config_windows.rs":
        "#![cfg(windows)]",
}

INCLUDE_SOURCE_EXCEPTIONS = {
    "crates/automata-ci-protocol-protobuf/tests/boundary.rs":
        'include!("../src/generated/automata.runner.v1.rs");',
    "crates/automata-ci-protocol-protobuf/tests/job_ir.rs":
        'include!("../src/generated/automata.runner.v1.rs");',
    "crates/automata-ci-protocol-protobuf/tests/job_runtime_context.rs":
        'include!("../src/generated/automata.runner.v1.rs");',
}

ASCII_RUST_WHITESPACE = " \t\n\r\x0b\x0c"
ASCII_RUST_WHITESPACE_PATTERN = r"[\x09-\x0d\x20]"
EXOTIC_RUST_WHITESPACE = "\x85\u200e\u200f\u2028\u2029"
IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_]*"
MODULE_HEAD = (
    rf"(?<![A-Za-z0-9_])(?:pub(?:{ASCII_RUST_WHITESPACE_PATTERN}+|"
    rf"{ASCII_RUST_WHITESPACE_PATTERN}*\([^)]*\)"
    rf"{ASCII_RUST_WHITESPACE_PATTERN}*))?"
    rf"mod\b{ASCII_RUST_WHITESPACE_PATTERN}+"
    rf"(?:r#)?(?P<name>{IDENTIFIER})"
    rf"{ASCII_RUST_WHITESPACE_PATTERN}*"
)
MODULE = re.compile(rf"{MODULE_HEAD};")
INLINE_MODULE = re.compile(rf"{MODULE_HEAD}\{{")
MOD_KEYWORD = re.compile(r"(?<![A-Za-z0-9_])mod\b")
ATTRIBUTE_HEAD = re.compile(
    rf"^#{ASCII_RUST_WHITESPACE_PATTERN}*\["
    rf"{ASCII_RUST_WHITESPACE_PATTERN}*(?P<raw>r#)?"
    rf"(?P<name>{IDENTIFIER})\b"
)
CANONICAL_PATH = re.compile(
    rf'^#\[{ASCII_RUST_WHITESPACE_PATTERN}*path'
    rf'{ASCII_RUST_WHITESPACE_PATTERN}*='
    rf'{ASCII_RUST_WHITESPACE_PATTERN}*"(?P<path>[^"\\\r\n]+)"'
    rf'{ASCII_RUST_WHITESPACE_PATTERN}*\]$'
)
INNER_CONDITIONAL = re.compile(
    rf"#{ASCII_RUST_WHITESPACE_PATTERN}*!"
    rf"{ASCII_RUST_WHITESPACE_PATTERN}*\["
    rf"{ASCII_RUST_WHITESPACE_PATTERN}*(?:r#)?cfg(?:_attr)?\b"
)
INCLUDE_SOURCE = re.compile(
    rf"(?<![A-Za-z0-9_])(?:r#)?include"
    rf"{ASCII_RUST_WHITESPACE_PATTERN}*!"
)
MACRO_RULES = re.compile(r"(?<![A-Za-z0-9_])macro_rules\s*!")
USE_ITEM = re.compile(r"(?<![A-Za-z0-9_])use\b(?P<body>[^;]*);")
INCLUDE_IDENTIFIER = re.compile(r"(?<![A-Za-z0-9_])(?:r#)?include\b")


def fail(message: str) -> None:
    raise SystemExit(message)


def display(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def skip_rust_trivia(source: str, start: int) -> int:
    """Skip Rust whitespace and comments from one source offset."""

    cursor = start
    whitespace = ASCII_RUST_WHITESPACE + EXOTIC_RUST_WHITESPACE
    while cursor < len(source):
        if source[cursor] in whitespace:
            cursor += 1
            continue
        if source.startswith("//", cursor):
            end = source.find("\n", cursor + 2)
            cursor = len(source) if end == -1 else end + 1
            continue
        if source.startswith("/*", cursor):
            depth = 1
            cursor += 2
            while cursor < len(source) and depth:
                if source.startswith("/*", cursor):
                    depth += 1
                    cursor += 2
                elif source.startswith("*/", cursor):
                    depth -= 1
                    cursor += 2
                else:
                    cursor += 1
            continue
        break
    return cursor


def mask_non_code(source: str) -> str:
    """Mask comments and strings while preserving source positions and newlines."""

    masked = list(source)
    length = len(source)

    def blank(start: int, end: int) -> None:
        for index in range(start, end):
            if masked[index] != "\n":
                masked[index] = " "

    index = 1 if source.startswith("\ufeff") else 0
    if index:
        blank(0, 1)
    inner_start = skip_rust_trivia(source, index + 2)
    if source.startswith("#!", index) and (
        inner_start == length or source[inner_start] != "["
    ):
        end = source.find("\n", index + 2)
        end = length if end == -1 else end
        blank(index, end)
        index = end

    while index < length:
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            end = length if end == -1 else end
            blank(index, end)
            index = end
            continue

        if source.startswith("/*", index):
            start = index
            depth = 1
            index += 2
            while index < length and depth:
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            blank(start, index)
            continue

        raw = re.match(r'(?:br|cr|r)(?P<hashes>#{0,255})"', source[index:])
        if raw is not None:
            start = index
            hashes = raw.group("hashes")
            index += raw.end()
            closing = f'"{hashes}'
            end = source.find(closing, index)
            index = length if end == -1 else end + len(closing)
            blank(start, index)
            continue

        if source[index] == '"':
            start = index
            index += 1
            escaped = False
            while index < length:
                character = source[index]
                index += 1
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    break
            blank(start, index)
            continue

        character = re.match(
            r"(?:b)?'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]+\}|.)|[^'\\\n])'",
            source[index:],
        )
        if character is not None:
            end = index + character.end()
            blank(index, end)
            index = end
            continue

        index += 1

    return "".join(masked)


def top_level_offsets(masked: str) -> bytearray:
    """Return source offsets outside balanced Rust token-tree delimiters."""

    top_level = bytearray(len(masked))
    stack = []
    opening = {"(": ")", "[": "]", "{": "}"}
    closing = set(opening.values())
    for index, character in enumerate(masked):
        top_level[index] = not stack
        if character in opening:
            stack.append(opening[character])
        elif character in closing:
            if not stack or stack.pop() != character:
                fail("unbalanced Rust token-tree delimiter")
    if stack:
        fail("unbalanced Rust token-tree delimiter")
    return top_level


def is_ascii_rust_whitespace(character: str) -> bool:
    return character in ASCII_RUST_WHITESPACE


def leading_attributes(masked: str, source: str, start: int) -> list[str]:
    """Return the contiguous outer attributes before a declaration."""

    attributes = []
    cursor = start
    while True:
        while cursor > 0 and is_ascii_rust_whitespace(masked[cursor - 1]):
            cursor -= 1
        if cursor == 0 or masked[cursor - 1] != "]":
            break

        end = cursor
        depth = 0
        cursor -= 1
        while cursor >= 0:
            if masked[cursor] == "]":
                depth += 1
            elif masked[cursor] == "[":
                depth -= 1
                if depth == 0:
                    break
            cursor -= 1
        while cursor > 0 and is_ascii_rust_whitespace(masked[cursor - 1]):
            cursor -= 1
        if cursor <= 0 or masked[cursor - 1] != "#":
            break

        cursor -= 1
        attributes.append(source[cursor:end])

    return list(reversed(attributes))


def module_declarations(source: str) -> list[tuple[str, list[str]]]:
    """Parse top-level external-module declarations from Rust source."""

    masked = mask_non_code(source)
    if any(ord(character) > 127 for character in masked):
        fail("non-ASCII Rust code is not allowed in aggregate test routing")
    offsets = top_level_offsets(masked)
    external = list(MODULE.finditer(masked))
    inline = list(INLINE_MODULE.finditer(masked))
    recognized = [*external, *inline]
    for keyword in MOD_KEYWORD.finditer(masked):
        start = keyword.start()
        raw_prefix = masked[max(0, start - 2):start] == "r#"
        identifier_characters = (
            "_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        )
        raw_boundary = start == 2 or masked[start - 3] not in identifier_characters
        raw_identifier = raw_prefix and raw_boundary
        if raw_identifier:
            continue
        if not any(
            declaration.start() <= start < declaration.end()
            for declaration in recognized
        ):
            fail("unsupported Rust mod token in aggregate test source")
    declarations = []
    for declaration in external:
        if not offsets[declaration.start()]:
            fail("nested or macro-generated external modules are not allowed")
        declarations.append(
            (
                declaration.group("name"),
                leading_attributes(masked, source, declaration.start()),
            )
        )
    return declarations


def module_path(name: str, attributes: list[str], source: Path) -> str | None:
    """Return one canonical path override and reject other module attributes."""

    paths = []
    for attribute in attributes:
        masked = mask_non_code(attribute)
        head = ATTRIBUTE_HEAD.match(masked)
        if head is None:
            fail(f"unsupported attribute on {name} in {display(source)}")
        if head.group("raw") is not None or head.group("name") != "path":
            fail(f"unsupported attribute on {name} in {display(source)}")
        path = CANONICAL_PATH.fullmatch(attribute)
        if path is None:
            fail(f"noncanonical path attribute for {name} in {display(source)}")
        paths.append(path.group("path"))
    if len(paths) > 1:
        fail(f"multiple path attributes for {name} in {display(source)}")
    return paths[0] if paths else None


def validate_inner_conditionals(source: str, path: Path) -> None:
    """Allow only the exact reviewed platform-level source gates."""

    matches = list(INNER_CONDITIONAL.finditer(mask_non_code(source)))
    expected = INNER_CFG_EXCEPTIONS.get(display(path))
    if expected is None:
        if matches:
            fail(f"unreviewed conditional inner attribute in {display(path)}")
        return
    if len(matches) != 1 or not source.startswith(f"{expected}\n"):
        fail(f"reviewed inner attribute changed in {display(path)}")


def validate_source_expansion(source: str, path: Path) -> None:
    """Allow only exact fixture includes, without alias or local macro indirection."""

    masked = mask_non_code(source)
    if MACRO_RULES.search(masked):
        fail(f"macro_rules! is not allowed in aggregate test routing: {display(path)}")
    for item in USE_ITEM.finditer(masked):
        if INCLUDE_IDENTIFIER.search(item.group("body")):
            fail(f"include! aliases are not allowed in {display(path)}")

    matches = list(INCLUDE_SOURCE.finditer(masked))
    expected = INCLUDE_SOURCE_EXCEPTIONS.get(display(path))
    if expected is None:
        if matches:
            fail(f"unreviewed include! source in {display(path)}")
        return
    if len(matches) != 1 or not source.startswith(expected, matches[0].start()):
        fail(f"reviewed include! source changed in {display(path)}")


def verify_module_parser() -> None:
    declaration_fixture = '''\ufeff#!/usr/bin/env mod shebang_token;
mod owned;
pub
mod split_visibility;
pub (crate)
mod scoped_visibility;
const OPEN_BRACE: char = '{';
const CLOSE_PAREN: u8 = b')';
mod inline_fixture {}
const r#mod: u8 = 0;
mod r#type;
mod after_characters;
'''
    declarations = module_declarations(declaration_fixture)
    names = [name for name, _ in declarations]
    if names != [
        "owned",
        "split_visibility",
        "scoped_visibility",
        "type",
        "after_characters",
    ]:
        fail(f"Rust module parser contract changed: {names!r}")

    masking_fixture = '''
/*
mod block_comment;
/* mod nested_block_comment; */
*/
// mod carriage_return_comment;\rmod still_carriage_return_comment;
const NORMAL: &str = "\nmod normal_string;";
const RAW: &str = r#"\nmod raw_string;"#;
'''
    if MODULE.search(mask_non_code(masking_fixture)) is not None:
        fail("comment or string escaped Rust module masking contract")

    rejected_fixtures = [
        "const TEXT: &str = stringify!(mod macro_token;);",
        "macro_rules! unused { () => { mod macro_token; }; }",
        "macro_rules! routed { ($name:ident) => { mod $name; }; }",
        "macro_rules! routed { (# $k:ident) => { $k escaped; }; } routed!(#mod);",
        "macro_rules! routed { ($d:tt $k:ident) => { $k escaped; }; } routed!($mod);",
        "fn nested() { mod nested_module; }",
        "mod\u200eexotic_whitespace;",
        "mod \u2118;",
    ]
    for fixture in rejected_fixtures:
        try:
            module_declarations(fixture)
        except SystemExit:
            continue
        fail(f"unsupported Rust module routing was accepted: {fixture!r}")

    fixture_path = ROOT / "crates/fixture/tests/root.rs"
    if module_path("owned", ['#[path = "owned.rs"]'], fixture_path) != "owned.rs":
        fail("canonical Rust path attribute escaped parser contract")
    rejected_attributes = [
        "#[cfg(any())]",
        "#[r#cfg(any())]",
        '#[path = r"owned.rs"]',
        '#[path/**/ = "owned.rs"]',
        '#[r#path = "owned.rs"]',
        '#[path = "owned\\x2ers"]',
        '#[doc = r#"#[path = "owned.rs"]"#]',
    ]
    for attribute in rejected_attributes:
        try:
            module_path("owned", [attribute], fixture_path)
        except SystemExit:
            continue
        fail(f"unsupported Rust module attribute was accepted: {attribute!r}")

    try:
        validate_inner_conditionals(
            "#![cfg(any())]\nmod hidden;\n",
            ROOT / "crates/fixture/tests/hidden.rs",
        )
    except SystemExit:
        pass
    else:
        fail("unreviewed conditional inner attribute escaped parser contract")

    rejected_expansions = [
        'include!("../src/hidden.rs");\n',
        'r#include!("../src/hidden.rs");\n',
        'use std::include as load; load!("../src/hidden.rs");\n',
        (
            "macro_rules! load { ($name:ident) => "
            '{ $name!("../src/hidden.rs"); }; } load!(include);\n'
        ),
    ]
    for fixture in rejected_expansions:
        try:
            validate_source_expansion(
                fixture,
                ROOT / "crates/fixture/tests/hidden.rs",
            )
        except SystemExit:
            continue
        fail(f"unreviewed source expansion was accepted: {fixture!r}")


def children(
    source: Path,
    module_dir: Path,
    tests_dir: Path,
) -> list[tuple[Path, Path]]:
    found = []
    source_text = source.read_bytes().decode("utf-8")
    validate_inner_conditionals(source_text, source)
    validate_source_expansion(source_text, source)
    for name, attrs in module_declarations(source_text):
        path = module_path(name, attrs, source)
        if path is not None:
            candidates = [source.parent / path]
            next_module_dir = None
        else:
            candidates = [module_dir / f"{name}.rs", module_dir / name / "mod.rs"]
            next_module_dir = (module_dir / name).resolve()
        existing = [candidate.resolve() for candidate in candidates if candidate.is_file()]
        if len(existing) != 1:
            fail(
                f"{name} in {display(source)} resolves to {len(existing)} files; "
                f"candidates={[display(path) for path in candidates]}"
            )
        child = existing[0]
        if not child.is_relative_to(tests_dir.resolve()):
            fail(f"{name} in {display(source)} escapes {display(tests_dir)}")
        if next_module_dir is None:
            next_module_dir = child.parent
        found.append((child, next_module_dir))
    return found


def owned_sources(root: Path, tests_dir: Path) -> set[Path]:
    owned: set[Path] = set()
    root = root.resolve()
    pending = [(root, root.parent)]
    queued = {root}
    while pending:
        source, module_dir = pending.pop()
        queued.remove(source)
        owned.add(source)
        for child, child_module_dir in children(source, module_dir, tests_dir):
            if child in owned or child in queued:
                fail(f"{display(child)} is referenced by more than one module")
            pending.append((child, child_module_dir))
            queued.add(child)
    return owned


def main() -> None:
    verify_module_parser()
    manifests = {}
    configured = set()
    for manifest in sorted((ROOT / "crates").glob("*/Cargo.toml")):
        cargo = tomllib.loads(manifest.read_text(encoding="utf-8"))
        package = cargo.get("package", {})
        name = package.get("name")
        if not isinstance(name, str):
            fail(f"missing package name in {display(manifest)}")
        manifests[name] = (manifest, cargo)
        if package.get("autotests") is False:
            configured.add(name)

    reviewed = set(AGGREGATES)
    if configured != reviewed:
        fail(
            "reviewed aggregate set changed; "
            f"added={sorted(configured - reviewed)}, removed={sorted(reviewed - configured)}"
        )

    source_count = 0
    target_count = 0
    for package, aggregate_name in AGGREGATES.items():
        manifest, cargo = manifests[package]
        target_names = [aggregate_name]
        live_name = LIVE_TARGETS.get(package)
        if live_name is not None:
            target_names.append(live_name)
        targets = cargo.get("test", [])
        expected = [
            {"name": name, "path": f"tests/{name}.rs"}
            for name in target_names
        ]
        actual = targets
        if actual != expected:
            fail(f"{package} integration targets changed: {actual!r} != {expected!r}")

        tests_dir = manifest.parent / "tests"
        if tests_dir.is_symlink():
            fail(f"{package} tests directory must not be a symlink")
        symlinks = [entry for entry in tests_dir.rglob("*") if entry.is_symlink()]
        if symlinks:
            fail(
                f"{package} test tree contains symlinks: "
                f"{sorted(display(path) for path in symlinks)}"
            )
        owners: dict[Path, set[str]] = {}
        for target_name in target_names:
            target_path = f"tests/{target_name}.rs"
            root_path = manifest.parent / target_path
            root = root_path.resolve()
            if not root.is_file():
                fail(f"{package} target root is missing: {display(root_path)}")
            if not root.is_relative_to(tests_dir.resolve()):
                fail(f"{package} target root escapes {display(tests_dir)}")
            for source in owned_sources(root, tests_dir):
                owners.setdefault(source, set()).add(target_name)

        inventory = {source.resolve() for source in tests_dir.rglob("*.rs")}
        owned = set(owners)
        if owned != inventory:
            fail(
                f"{package} has unowned test sources: "
                f"{sorted(display(path) for path in inventory - owned)}; "
                f"non-inventory sources: "
                f"{sorted(display(path) for path in owned - inventory)}"
            )
        tests_root = tests_dir.resolve()
        actual_shared = {
            source.relative_to(tests_root).as_posix(): frozenset(source_owners)
            for source, source_owners in owners.items()
            if len(source_owners) > 1
        }
        expected_shared = SHARED_SOURCE_OWNERS.get(package, {})
        if actual_shared != expected_shared:
            fail(
                f"{package} shared test-source ownership changed: "
                f"{actual_shared!r} != {expected_shared!r}"
            )
        source_count += len(inventory)
        target_count += len(target_names)

    print(
        f"verified {len(AGGREGATES)} aggregate packages own "
        f"{source_count} Rust test source files across {target_count} targets"
    )


if __name__ == "__main__":
    main()
