#!/usr/bin/env python3
"""Mutation tests for the foundation governance validator."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[3]
VALIDATOR_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "verify-foundation-governance.py"
SPEC = importlib.util.spec_from_file_location("verify_foundation_governance", VALIDATOR_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not load {VALIDATOR_PATH}")
governance = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = governance
SPEC.loader.exec_module(governance)


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


class FoundationGovernanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = pathlib.Path(self.scratch.name)

        files = {
            "Cargo.toml": "[workspace]\nmembers = []\n",
            "crates/automata-ci-core/src/version.rs": "pub const FORMAT_VERSION: u16 = 1;\n",
            "crates/automata-ci-core/tests/version.rs": "fn exact_current_version_is_accepted() {}\n",
            "crates/automata-ci-runtime/src/limits.rs": (
                "pub const TEST_LIMIT: usize = 5;\n"
                "return Err(TestLimitError::Exceeded);\n"
            ),
            "crates/automata-ci-runtime/tests/limits.rs": (
                "#[test]\nfn test_limit_boundaries() {}\n"
            ),
            "crates/automata-ci-store/migrations/0001_initial_schema.sql": "SELECT 1;\n",
        }
        for relative, contents in files.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")

        self.registry = {
            "formats": [
                {
                    "compatibility_policy": "exact-current-only",
                    "id": "test-format",
                    "owner": "integration",
                    "sources": [
                        {
                            "contains": "pub const FORMAT_VERSION: u16 = 1;",
                            "path": "crates/automata-ci-core/src/version.rs",
                        }
                    ],
                    "tests": ["crates/automata-ci-core/tests/version.rs"],
                    "version": 1,
                }
            ],
            "limits": [
                {
                    "boundary_tests": {
                        "at": "test_limit_boundaries",
                        "minus_one": "test_limit_boundaries",
                        "plus_one": "test_limit_boundaries",
                    },
                    "classification": "automata-stricter",
                    "enforcement_phase": "runtime",
                    "id": "test.limit",
                    "owner": "integration",
                    "reason_code": "TestLimitError::Exceeded",
                    "reason_source": {
                        "contains": "return Err(TestLimitError::Exceeded);",
                        "path": "crates/automata-ci-runtime/src/limits.rs",
                    },
                    "source": {
                        "contains": "pub const TEST_LIMIT: usize = 5;",
                        "path": "crates/automata-ci-runtime/src/limits.rs",
                    },
                    "tests": ["crates/automata-ci-runtime/tests/limits.rs"],
                    "unit": "items",
                    "value": 5,
                }
            ],
            "migrations": {
                "current": ["0001_initial_schema.sql"],
                "directory": "crates/automata-ci-store/migrations",
                "mode": "greenfield-canonical-baseline",
                "next_sequence": None,
                "owner": "store",
                "reservations": [],
            },
            "owners": [
                {"description": "Shared integration surfaces", "id": "integration"},
                {"description": "PostgreSQL schema", "id": "store"},
            ],
            "schema_version": 1,
            "shared_surfaces": [
                {
                    "description": "Workspace manifest",
                    "owner": "integration",
                    "path": "Cargo.toml",
                }
            ],
            "status": "bootstrap",
        }
        self.registry_path = self.root / "docs" / "governance" / "foundation-governance-v1.json"
        self.registry_path.parent.mkdir(parents=True)
        self.write_registry()

    def write_registry(self, *, canonical: bool = True) -> None:
        contents = (
            canonical_json(self.registry)
            if canonical
            else json.dumps(self.registry, separators=(",", ":"))
        )
        self.registry_path.write_bytes(contents.encode("utf-8"))

    def assert_invalid(self, pattern: str) -> None:
        with self.assertRaisesRegex(governance.GovernanceError, pattern):
            governance.validate_repository(self.root)

    def test_valid_minimal_repository_passes(self) -> None:
        governance.validate_repository(self.root)

    def test_canonical_crlf_checkout_passes(self) -> None:
        contents = canonical_json(self.registry).replace("\n", "\r\n")
        self.registry_path.write_bytes(contents.encode("utf-8"))

        governance.validate_repository(self.root)

    def test_source_fragment_drift_is_rejected(self) -> None:
        source = self.root / "crates" / "automata-ci-core" / "src" / "version.rs"
        source.write_text("pub const FORMAT_VERSION: u16 = 2;\n", encoding="utf-8")

        self.assert_invalid(r"fragment must occur exactly once.*found 0")

    def test_duplicate_migration_reservation_is_rejected_before_mode_policy(self) -> None:
        self.registry["migrations"]["reservations"] = [
            {"issue": "#101", "number": 2, "owner": "store"},
            {"issue": "#102", "number": 2, "owner": "store"},
        ]
        self.write_registry()

        self.assert_invalid("migration reservation numbers must be unique")

    def test_migration_inventory_drift_is_rejected(self) -> None:
        migration = (
            self.root
            / "crates"
            / "automata-ci-store"
            / "migrations"
            / "0002_unregistered.sql"
        )
        migration.write_text("SELECT 2;\n", encoding="utf-8")

        self.assert_invalid("migration inventory drift")

    def test_limit_value_must_match_its_source_binding(self) -> None:
        self.registry["limits"][0]["value"] = 6
        self.write_registry()

        self.assert_invalid(r"source does not bind declared value 6")

    def test_reason_code_must_match_its_source_binding(self) -> None:
        self.registry["limits"][0]["reason_code"] = "TestLimitError::Other"
        self.write_registry()

        self.assert_invalid(r"reason_source does not bind declared reason code")

    def test_enforcement_phase_is_closed(self) -> None:
        self.registry["limits"][0]["enforcement_phase"] = "somewhere"
        self.write_registry()

        self.assert_invalid(r"enforcement_phase must be 'compile'")

    def test_rust_integer_type_does_not_bind_a_declared_version(self) -> None:
        self.registry["formats"][0]["version"] = 16
        self.write_registry()

        self.assert_invalid(r"sources do not bind declared version 16")

    def test_noncanonical_registry_is_rejected(self) -> None:
        self.write_registry(canonical=False)

        self.assert_invalid("registry is not canonical JSON")

    def test_boundary_function_must_exist_in_a_listed_test(self) -> None:
        self.registry["limits"][0]["boundary_tests"]["plus_one"] = "missing_boundary"
        self.write_registry()

        self.assert_invalid(r"names missing test function 'missing_boundary'")

    def test_boundary_function_must_have_a_test_attribute(self) -> None:
        test = self.root / "crates" / "automata-ci-runtime" / "tests" / "limits.rs"
        test.write_text("fn test_limit_boundaries() {}\n", encoding="utf-8")

        self.assert_invalid(r"names missing test function 'test_limit_boundaries'")

    def test_unknown_schema_key_is_rejected(self) -> None:
        self.registry["limits"][0]["unexpected"] = True
        self.write_registry()

        self.assert_invalid(r"limits\[0\] has invalid keys.*unknown \['unexpected'\]")


if __name__ == "__main__":
    unittest.main()
