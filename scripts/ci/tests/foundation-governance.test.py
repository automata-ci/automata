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
            "crates/automata-ci-core/tests/version.rs": (
                "#[test]\nfn exact_current_version_is_accepted() {}\n"
            ),
            "crates/automata-ci-runtime/src/limits.rs": (
                "pub const TEST_LIMIT: usize = 5;\n"
                "return Err(TestLimitError::Exceeded);\n"
            ),
            "crates/automata-ci-runtime/tests/limits.rs": (
                "#[test]\nfn test_limit_boundaries() {\n"
                "    assert!(accept(TEST_LIMIT - 1));\n"
                "    assert!(accept(TEST_LIMIT));\n"
                "    assert!(!accept(TEST_LIMIT + 1));\n"
                "}\n"
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
                            "role": "version",
                        }
                    ],
                    "tests": [
                        {
                            "contains": "fn exact_current_version_is_accepted() {}",
                            "function": "exact_current_version_is_accepted",
                            "path": "crates/automata-ci-core/tests/version.rs",
                        }
                    ],
                    "version": 1,
                }
            ],
            "limits": [
                {
                    "boundary_tests": {
                        "at": {
                            "contains": "assert!(accept(TEST_LIMIT));",
                            "function": "test_limit_boundaries",
                            "path": "crates/automata-ci-runtime/tests/limits.rs",
                        },
                        "minus_one": {
                            "contains": "assert!(accept(TEST_LIMIT - 1));",
                            "function": "test_limit_boundaries",
                            "path": "crates/automata-ci-runtime/tests/limits.rs",
                        },
                        "plus_one": {
                            "contains": "assert!(!accept(TEST_LIMIT + 1));",
                            "function": "test_limit_boundaries",
                            "path": "crates/automata-ci-runtime/tests/limits.rs",
                        },
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

    def test_greenfield_rejects_any_migration_reservation(self) -> None:
        self.registry["migrations"]["reservations"] = [
            {"issue": "#101", "number": 2, "owner": "store"}
        ]
        self.write_registry()

        self.assert_invalid("must not reserve migration numbers")

    def test_greenfield_rejects_a_next_migration_sequence(self) -> None:
        self.registry["migrations"]["next_sequence"] = 2
        self.write_registry()

        self.assert_invalid("migrations.next_sequence must be null")

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

    def test_reason_code_prefix_does_not_bind_a_longer_variant(self) -> None:
        self.registry["limits"][0]["reason_code"] = "TestLimitError::Exceed"
        self.write_registry()

        self.assert_invalid(r"reason_source does not bind declared reason code")

    def test_enforcement_phase_is_closed(self) -> None:
        self.registry["limits"][0]["enforcement_phase"] = "somewhere"
        self.write_registry()

        self.assert_invalid(r"enforcement_phase must be 'compile'")

    def test_rust_integer_type_does_not_bind_a_declared_version(self) -> None:
        self.registry["formats"][0]["version"] = 16
        self.write_registry()

        self.assert_invalid(r"does not bind declared version 16")

    def test_every_version_source_must_bind_the_declared_version(self) -> None:
        evidence = self.root / "crates" / "automata-ci-core" / "src" / "other.rs"
        evidence.write_text("pub const OTHER_VERSION: u16 = 2;\n", encoding="utf-8")
        self.registry["formats"][0]["sources"].append(
            {
                "contains": "pub const OTHER_VERSION: u16 = 2;",
                "path": "crates/automata-ci-core/src/other.rs",
                "role": "version",
            }
        )
        self.write_registry()

        self.assert_invalid(r"does not bind declared version 1")

    def test_compatibility_policy_is_closed(self) -> None:
        self.registry["formats"][0]["compatibility_policy"] = "banana"
        self.write_registry()

        self.assert_invalid(r"compatibility_policy must be one of")

    def test_registry_cannot_claim_active_before_completeness_is_defined(self) -> None:
        self.registry["status"] = "active"
        self.write_registry()

        self.assert_invalid(r"status must remain 'bootstrap'")

    def test_schema_version_must_be_an_integer(self) -> None:
        self.registry["schema_version"] = 1.0
        self.write_registry()

        self.assert_invalid("schema_version must be integer 1")

    def test_noncanonical_registry_is_rejected(self) -> None:
        self.write_registry(canonical=False)

        self.assert_invalid("registry is not canonical JSON")

    def test_duplicate_json_key_is_rejected(self) -> None:
        contents = canonical_json(self.registry).replace(
            '  "schema_version": 1,',
            '  "schema_version": 1,\n  "schema_version": 1,',
            1,
        )
        self.registry_path.write_text(contents, encoding="utf-8")

        self.assert_invalid("duplicate JSON key 'schema_version'")

    def test_boundary_function_must_exist_in_a_listed_test(self) -> None:
        self.registry["limits"][0]["boundary_tests"]["plus_one"]["function"] = (
            "missing_boundary"
        )
        self.write_registry()

        self.assert_invalid(r"names missing test function 'missing_boundary'")

    def test_boundary_function_must_have_a_test_attribute(self) -> None:
        test = self.root / "crates" / "automata-ci-runtime" / "tests" / "limits.rs"
        test.write_text("fn test_limit_boundaries() {}\n", encoding="utf-8")

        self.assert_invalid(r"names missing test function 'test_limit_boundaries'")

    def test_each_boundary_fragment_must_remain_in_the_test(self) -> None:
        self.registry["limits"][0]["boundary_tests"]["plus_one"]["contains"] = (
            "assert!(!accept(TEST_LIMIT + 2));"
        )
        self.write_registry()

        self.assert_invalid(r"contains must occur exactly once")

    def test_boundary_bindings_must_be_distinct(self) -> None:
        at = self.registry["limits"][0]["boundary_tests"]["at"]
        self.registry["limits"][0]["boundary_tests"]["minus_one"] = dict(at)
        self.registry["limits"][0]["boundary_tests"]["plus_one"] = dict(at)
        self.write_registry()

        self.assert_invalid(r"must use three distinct bindings")

    def test_boundary_fragment_cannot_live_in_a_following_helper(self) -> None:
        test = self.root / "crates" / "automata-ci-runtime" / "tests" / "limits.rs"
        test.write_text(
            "#[test]\nfn test_limit_boundaries() {}\n"
            "fn helper() {\n"
            "    assert!(accept(TEST_LIMIT - 1));\n"
            "    assert!(accept(TEST_LIMIT));\n"
            "    assert!(!accept(TEST_LIMIT + 1));\n"
            "}\n",
            encoding="utf-8",
        )

        self.assert_invalid(r"contains must occur exactly once")

    def test_format_test_must_be_an_attributed_test_function(self) -> None:
        test = self.root / "crates" / "automata-ci-core" / "tests" / "version.rs"
        test.write_text("fn exact_current_version_is_accepted() {}\n", encoding="utf-8")

        self.assert_invalid(r"names missing test function 'exact_current_version_is_accepted'")

    def test_format_test_must_bind_its_declared_evidence(self) -> None:
        self.registry["formats"][0]["tests"][0]["contains"] = "assert!(false);"
        self.write_registry()

        self.assert_invalid(r"contains must occur exactly once")

    def test_unknown_schema_key_is_rejected(self) -> None:
        self.registry["limits"][0]["unexpected"] = True
        self.write_registry()

        self.assert_invalid(r"limits\[0\] has invalid keys.*unknown \['unexpected'\]")


if __name__ == "__main__":
    unittest.main()
