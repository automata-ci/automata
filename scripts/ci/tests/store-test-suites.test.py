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
POSTGRES = ROOT / "crates" / "automata-ci-postgres"
POSTGRES_TESTS = POSTGRES / "tests"
POSTGRES_MANIFEST = POSTGRES / "Cargo.toml"

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
    "store_contracts": (34, 196, 0),
    "store_migration_contracts": (1, 1, 0),
    "store_postgres_execution": (9, 118, 117),
    "store_postgres_orchestration": (11, 53, 52),
    "store_postgres_provider": (11, 92, 92),
    "store_postgres_security": (9, 43, 38),
}
ADAPTER_DOMAIN_INVENTORY = {
    "auth": (12, 71, 68),
    "provisioning": (1, 3, 3),
    "runner_auth": (2, 6, 5),
    "secret": (3, 8, 6),
}
TEST_ATTRIBUTE = re.compile(r"#\[(?:tokio::)?test(?:\([^\]]*\))?\]")
PATH_MODULE = re.compile(
    r'^#\[path = "(?P<path>[^"]+)"\]\s*\nmod (?P<module>[a-z0-9_]+);$',
    re.MULTILINE,
)
MANIFEST_TEST = re.compile(
    r'\[\[test\]\]\s*\nname = "(?P<name>[^"]+)"\s*\npath = "(?P<path>[^"]+)"',
)


def fail(message: str) -> None:
    raise SystemExit(f"PostgreSQL test-suite inventory error: {message}")


MODULE = re.compile(r"^mod (?P<module>[a-z0-9_]+);$", re.MULTILINE)


def validate_adapter_suite() -> tuple[int, int, int]:
    manifest = POSTGRES_MANIFEST.read_text(encoding="utf-8")
    if "autotests = false" not in manifest:
        fail("automata-ci-postgres must disable Cargo autotest discovery")

    declared = {
        match.group("name"): match.group("path")
        for match in MANIFEST_TEST.finditer(manifest)
    }
    expected_declarations = {"postgres": "tests/postgres.rs"}
    if declared != expected_declarations:
        fail(
            "automata-ci-postgres explicit Cargo targets differ from the reviewed "
            f"suite: {declared!r}"
        )

    root_source = (POSTGRES_TESTS / "postgres.rs").read_text(encoding="utf-8")
    root_modules = set(MODULE.findall(root_source))
    expected_root_modules = {"support", *ADAPTER_DOMAIN_INVENTORY}
    if root_modules != expected_root_modules:
        fail(
            "automata-ci-postgres root modules differ: "
            f"actual={root_modules!r}"
        )
    if TEST_ATTRIBUTE.search(root_source) or "#[ignore" in root_source:
        fail("automata-ci-postgres/postgres must contain only module assignments")

    owned_files = {Path("postgres.rs"), Path("support/mod.rs")}
    total_leaves = 0
    total_tests = 0
    total_ignored = 0
    for domain, expected in ADAPTER_DOMAIN_INVENTORY.items():
        expected_leaves, expected_tests, expected_ignored = expected
        domain_root = POSTGRES_TESTS / domain
        owned_files.add(Path(domain) / "mod.rs")
        module_source = (domain_root / "mod.rs").read_text(encoding="utf-8")
        assignments = set(MODULE.findall(module_source))
        leaves = {
            path.stem for path in domain_root.glob("*.rs") if path.name != "mod.rs"
        }
        missing = sorted(leaves - assignments)
        stale = sorted(assignments - leaves)
        if missing or stale:
            fail(
                f"automata-ci-postgres/{domain} missing leaves={missing!r}; "
                f"stale assignments={stale!r}"
            )
        owned_files.update(Path(domain) / f"{leaf}.rs" for leaf in leaves)

        test_count = 0
        ignored_count = 0
        for leaf in sorted(leaves):
            source = (domain_root / f"{leaf}.rs").read_text(encoding="utf-8")
            if "mod support;" in source:
                fail(
                    f"automata-ci-postgres/{domain}/{leaf}.rs owns duplicate support"
                )
            if leaf != "contracts" and source.count("use crate::support::") != 1:
                fail(
                    f"automata-ci-postgres/{domain}/{leaf}.rs must import shared "
                    "support once"
                )
            leaf_tests = len(TEST_ATTRIBUTE.findall(source))
            if leaf_tests == 0:
                fail(f"automata-ci-postgres/{domain}/{leaf}.rs contains no tests")
            test_count += leaf_tests
            ignored_count += source.count("#[ignore")

        contract = domain_root / "contracts.rs"
        if contract.exists() and "#[ignore" in contract.read_text(encoding="utf-8"):
            fail(f"automata-ci-postgres/{domain}/contracts.rs must remain ordinary")
        actual = (len(leaves), test_count, ignored_count)
        if actual != expected:
            fail(
                f"automata-ci-postgres/{domain} reviewed inventory changed: "
                f"actual={actual!r}"
            )

        total_leaves += len(leaves)
        total_tests += test_count
        total_ignored += ignored_count

    actual_files = {
        path.relative_to(POSTGRES_TESTS)
        for path in POSTGRES_TESTS.rglob("*.rs")
    }
    missing_files = sorted(owned_files - actual_files)
    orphaned_files = sorted(actual_files - owned_files)
    if missing_files or orphaned_files:
        fail(
            "automata-ci-postgres Rust test ownership differs: "
            f"missing={missing_files!r}; orphaned={orphaned_files!r}"
        )

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
    adapter_leaves, adapter_tests, adapter_ignored = validate_adapter_suite()
    print(
        "verified six Store suites: "
        f"{len(leaves)} leaves, {test_count} tests, {ignored_count} PostgreSQL tests; "
        "verified the consolidated PostgreSQL adapter: "
        f"{adapter_leaves} leaves, {adapter_tests} tests, "
        f"{adapter_ignored} PostgreSQL tests"
    )


if __name__ == "__main__":
    main()
