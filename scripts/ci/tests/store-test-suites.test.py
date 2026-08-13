#!/usr/bin/env python3
"""Fail-closed inventory contract for consolidated PostgreSQL test suites."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
STORE = ROOT / "crates" / "automata-ci-store"
TESTS = STORE / "tests"
MANIFEST = STORE / "Cargo.toml"

SUITES = (
    "store_contracts",
    "store_migration_contracts",
    "store_postgres_execution",
    "store_postgres_orchestration",
    "store_postgres_provider",
    "store_postgres_security",
)
CURRENT_SUITES = set(SUITES[2:])
SUPPORT_MODULES = {"github_manifest_fixture"}
EXPECTED_SUITE_INVENTORY = {
    "store_contracts": (34, 194, 0),
    "store_migration_contracts": (1, 1, 0),
    "store_postgres_execution": (9, 118, 117),
    "store_postgres_orchestration": (11, 53, 52),
    "store_postgres_provider": (11, 91, 91),
    "store_postgres_security": (9, 43, 38),
}
ADAPTER_SUITE_INVENTORY = {
    "automata-ci-auth-postgres": ("auth_postgres", 10, 68, 67, 2),
    "automata-ci-runner-auth-postgres": (
        "runner_auth_postgres",
        1,
        5,
        5,
        1,
    ),
    "automata-ci-secret-postgres": ("secret_postgres", 2, 6, 6, 2),
}
TEST_ATTRIBUTE = re.compile(r"#\[(?:tokio::)?test\]")
PATH_MODULE = re.compile(
    r'^#\[path = "(?P<path>[^"]+)"\]\s*\nmod (?P<module>[a-z0-9_]+);$',
    re.MULTILINE,
)
MANIFEST_TEST = re.compile(
    r'\[\[test\]\]\s*\nname = "(?P<name>[^"]+)"\s*\npath = "(?P<path>[^"]+)"',
)


def fail(message: str) -> None:
    raise SystemExit(f"PostgreSQL test-suite inventory error: {message}")


def validate_adapter_suites() -> tuple[int, int, int]:
    total_leaves = 0
    total_tests = 0
    total_ignored = 0
    for package, expected in ADAPTER_SUITE_INVENTORY.items():
        suite, expected_leaves, expected_tests, expected_ignored, expected_contracts = (
            expected
        )
        package_root = ROOT / "crates" / package
        tests = package_root / "tests"
        manifest = (package_root / "Cargo.toml").read_text(encoding="utf-8")
        if "autotests = false" not in manifest:
            fail(f"{package} must disable Cargo autotest discovery")

        declared = {
            match.group("name"): match.group("path")
            for match in MANIFEST_TEST.finditer(manifest)
        }
        expected_declarations = {
            "contracts": "tests/contracts.rs",
            suite: f"tests/{suite}.rs",
        }
        if declared != expected_declarations:
            fail(
                f"{package} explicit Cargo targets differ from the reviewed suites: "
                f"{declared!r}"
            )

        root_source = (tests / f"{suite}.rs").read_text(encoding="utf-8")
        if root_source.count("mod support;") != 1:
            fail(f"{package}/{suite} must own exactly one support module")
        if TEST_ATTRIBUTE.search(root_source) or "#[ignore" in root_source:
            fail(f"{package}/{suite} must contain only module assignments")

        assignments: dict[str, str] = {}
        for match in PATH_MODULE.finditer(root_source):
            relative = Path(match.group("path"))
            module = match.group("module")
            if relative.parent != Path(".") or relative.suffix != ".rs":
                fail(f"{package}/{suite} has a non-local Rust module path: {relative}")
            if relative.stem != module:
                fail(
                    f"{package}/{suite} maps module {module!r} to mismatched path "
                    f"{relative}"
                )
            if module in assignments:
                fail(f"{package}/{suite} assigns {module}.rs more than once")
            assignments[module] = suite

        roots = {"contracts.rs", f"{suite}.rs"}
        leaves = {
            path.stem for path in tests.glob("*.rs") if path.name not in roots
        }
        non_postgres = sorted(leaf for leaf in leaves if not leaf.startswith("postgres_"))
        missing = sorted(leaves - assignments.keys())
        stale = sorted(assignments.keys() - leaves)
        if non_postgres or missing or stale:
            fail(
                f"{package}/{suite} non-PostgreSQL leaves={non_postgres!r}; "
                f"missing leaves={missing!r}; stale assignments={stale!r}"
            )

        test_count = 0
        ignored_count = 0
        for leaf in sorted(leaves):
            source = (tests / f"{leaf}.rs").read_text(encoding="utf-8")
            if "mod support;" in source:
                fail(f"{package}/{leaf}.rs still owns a duplicate support module")
            if source.count("use super::support::") != 1:
                fail(f"{package}/{leaf}.rs must import its suite support module once")
            leaf_tests = len(TEST_ATTRIBUTE.findall(source))
            if leaf_tests == 0:
                fail(f"{package}/{leaf}.rs contains no tests")
            test_count += leaf_tests
            ignored_count += source.count("#[ignore")

        contract_source = (tests / "contracts.rs").read_text(encoding="utf-8")
        contract_tests = len(TEST_ATTRIBUTE.findall(contract_source))
        if "#[ignore" in contract_source:
            fail(f"{package}/contracts.rs must remain an ordinary target")
        actual = (len(leaves), test_count, ignored_count, contract_tests)
        if actual != (
            expected_leaves,
            expected_tests,
            expected_ignored,
            expected_contracts,
        ):
            fail(f"{package} reviewed inventory changed: actual={actual!r}")

        total_leaves += len(leaves)
        total_tests += test_count + contract_tests
        total_ignored += ignored_count

    return total_leaves, total_tests, total_ignored


def main() -> None:
    manifest = MANIFEST.read_text(encoding="utf-8")
    if "autotests = false" not in manifest:
        fail("Cargo autotest discovery must remain disabled")

    declared = {
        match.group("name"): match.group("path")
        for match in MANIFEST_TEST.finditer(manifest)
    }
    expected_declarations = {
        suite: f"tests/{suite}.rs" for suite in SUITES
    }
    if declared != expected_declarations:
        fail(
            "explicit Cargo test targets differ from the six reviewed suites: "
            f"{declared!r}"
        )

    assignments: dict[str, str] = {}
    support_owners: Counter[str] = Counter()
    for suite in SUITES:
        source = (TESTS / f"{suite}.rs").read_text(encoding="utf-8")
        for match in PATH_MODULE.finditer(source):
            relative = Path(match.group("path"))
            module = match.group("module")
            if relative.parent != Path(".") or relative.suffix != ".rs":
                fail(f"{suite} has a non-local Rust module path: {relative}")
            if relative.stem != module:
                fail(
                    f"{suite} maps module {module!r} to mismatched path {relative}"
                )
            if module in SUPPORT_MODULES:
                support_owners[module] += 1
                continue
            if module in assignments:
                fail(
                    f"{module}.rs is assigned more than once: "
                    f"{assignments[module]} and {suite}"
                )
            assignments[module] = suite

    if set(support_owners) != SUPPORT_MODULES:
        fail(f"support-module set differs: {set(support_owners)!r}")
    if any(count == 0 for count in support_owners.values()):
        fail(f"a support module has no suite owner: {support_owners!r}")

    roots = {f"{suite}.rs" for suite in SUITES}
    leaves = {
        path.stem
        for path in TESTS.glob("*.rs")
        if path.name not in roots and path.stem not in SUPPORT_MODULES
    }
    missing = sorted(leaves - assignments.keys())
    stale = sorted(assignments.keys() - leaves)
    if missing or stale:
        fail(f"missing leaves={missing!r}; stale assignments={stale!r}")

    for leaf, suite in sorted(assignments.items()):
        if leaf == "migration_inventory":
            if suite != "store_migration_contracts":
                fail(f"migration inventory is owned by {suite}")
        elif leaf.startswith("postgres_") and suite not in CURRENT_SUITES:
            fail(f"current PostgreSQL leaf {leaf}.rs is owned by {suite}")
        elif not leaf.startswith("postgres_") and suite != "store_contracts":
            fail(f"source-only contract leaf {leaf}.rs is owned by {suite}")

    inventory = {suite: [0, 0, 0] for suite in SUITES}
    for leaf in sorted(leaves):
        source = (TESTS / f"{leaf}.rs").read_text(encoding="utf-8")
        tests = len(TEST_ATTRIBUTE.findall(source))
        if tests == 0:
            fail(f"executable leaf {leaf}.rs contains no tests")
        suite_inventory = inventory[assignments[leaf]]
        suite_inventory[0] += 1
        suite_inventory[1] += tests
        suite_inventory[2] += source.count("#[ignore")

    actual_inventory = {
        suite: tuple(counts) for suite, counts in inventory.items()
    }
    if actual_inventory != EXPECTED_SUITE_INVENTORY:
        fail(
            "reviewed per-suite inventory changed: "
            f"actual={actual_inventory!r}"
        )

    test_count = sum(counts[1] for counts in actual_inventory.values())
    ignored_count = sum(counts[2] for counts in actual_inventory.values())
    adapter_leaves, adapter_tests, adapter_ignored = validate_adapter_suites()
    print(
        "verified six Store suites: "
        f"{len(leaves)} leaves, {test_count} tests, {ignored_count} PostgreSQL tests; "
        "verified three adapter packages: "
        f"{adapter_leaves} leaves, {adapter_tests} tests, "
        f"{adapter_ignored} PostgreSQL tests"
    )


if __name__ == "__main__":
    main()
