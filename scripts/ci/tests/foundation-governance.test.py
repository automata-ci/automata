#!/usr/bin/env python3
"""Mutation tests for the foundation governance validator."""

from __future__ import annotations

import importlib.util
import hashlib
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
                "#[test]\nfn exact_current_version_is_accepted() {\n"
                "    assert!(decode(FORMAT_VERSION).is_ok());\n"
                "    assert!(decode(FORMAT_VERSION + 1).is_err());\n"
                "}\n"
            ),
            "crates/automata-ci-runtime/src/limits.rs": (
                "pub const MAX_TEST_ITEMS: usize = 5;\n"
                "return Err(TestLimitError::Exceeded);\n"
            ),
            "crates/automata-ci-runtime/tests/limits.rs": (
                "#[test]\nfn test_limit_boundaries() {\n"
                "    assert!(accept(MAX_TEST_ITEMS - 1));\n"
                "    assert!(accept(MAX_TEST_ITEMS));\n"
                "    assert!(!accept(MAX_TEST_ITEMS + 1));\n"
                "}\n"
            ),
            "crates/automata-ci-postgres/migrations/0001_initial_schema.sql": "SELECT 1;\n",
        }
        for relative, contents in files.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")

        self.registry = {
            "format_exclusions": [],
            "format_scope": {
                "declaration_roots": ["crates/*/src/**/*.rs", "ui/src/**/*.{ts,tsx}"],
                "includes": [
                    "named-versioned-internal-durable-formats",
                    "named-versioned-internal-wire-formats",
                ],
                "migration_map": "docs/governance/store-migration-format-map-v1.json",
                "unversioned_public_json_apis": "out-of-scope",
            },
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
                            "contains": "assert!(decode(FORMAT_VERSION + 1).is_err());",
                            "function": "exact_current_version_is_accepted",
                            "path": "crates/automata-ci-core/tests/version.rs",
                        }
                    ],
                    "version": 1,
                }
            ],
            "github_limits": [
                {
                    "automata": {
                        "enforcement_phase": "scheduler",
                        "limit_id": None,
                        "reason_code": f"planned.{identifier}",
                        "relation": None,
                        "status": "planned",
                    },
                    "id": identifier,
                    "owner": "integration",
                    "scope": "Synthetic complete inventory entry.",
                    "source_excerpt": "Pinned Actions limits reference.",
                    "source_reference": "github-docs-limits",
                    "unit": "items",
                    "value": 5,
                    "window_seconds": None,
                }
                for identifier in sorted(governance.GITHUB_LIMIT_IDS)
            ],
            "limit_exclusions": [],
            "limit_aliases": [],
            "limit_surfaces": ["crates"],
            "limits": [
                {
                    "boundary_tests": {
                        "at": {
                            "contains": "assert!(accept(MAX_TEST_ITEMS));",
                            "function": "test_limit_boundaries",
                            "path": "crates/automata-ci-runtime/tests/limits.rs",
                        },
                        "minus_one": {
                            "contains": "assert!(accept(MAX_TEST_ITEMS - 1));",
                            "function": "test_limit_boundaries",
                            "path": "crates/automata-ci-runtime/tests/limits.rs",
                        },
                        "plus_one": {
                            "contains": "assert!(!accept(MAX_TEST_ITEMS + 1));",
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
                        "contains": "pub const MAX_TEST_ITEMS: usize = 5;",
                        "path": "crates/automata-ci-runtime/src/limits.rs",
                    },
                    "unit": "items",
                    "value": 5,
                }
            ],
            "migrations": {
                "current": ["0001_initial_schema.sql"],
                "directory": "crates/automata-ci-postgres/migrations",
                "mode": "greenfield-canonical-baseline",
                "next_sequence": None,
                "owner": "store",
                "reservations": [],
                "sha256": hashlib.sha256(b"SELECT 1;\n").hexdigest(),
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
            "status": "active",
        }
        snapshot = {
            "reference_groups": [
                {
                    "categories": ["limits"],
                    "id": "github-docs-limits",
                }
            ]
        }
        snapshot_path = (
            self.root
            / "docs"
            / "governance"
            / "github-actions-reference-snapshot-v1.json"
        )
        snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
        self.registry_path = self.root / "docs" / "governance" / "foundation-governance-v1.json"
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        self.migration_format_map_path = (
            self.root
            / "docs"
            / "governance"
            / "store-migration-format-map-v1.json"
        )
        self.migration_format_map_path.write_text(
            canonical_json(
                {
                    "contracts": [],
                    "embedded_json_contracts": [],
                    "expected_value": 1,
                    "media_type_contracts": [],
                    "migration": "0001_initial_schema.sql",
                    "schema_version": 1,
                }
            ),
            encoding="utf-8",
        )
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

    def set_format_version(self, version: int) -> None:
        declaration = f"pub const FORMAT_VERSION: u16 = {version};"
        source = self.root / "crates" / "automata-ci-core" / "src" / "version.rs"
        source.write_text(f"{declaration}\n", encoding="utf-8")
        self.registry["formats"][0]["sources"][0]["contains"] = declaration
        self.registry["formats"][0]["version"] = version

    def set_string_format_version(self, version: str) -> None:
        declaration = f'pub const FORMAT_VERSION: &str = "{version}";'
        source = self.root / "crates" / "automata-ci-core" / "src" / "version.rs"
        source.write_text(f"{declaration}\n", encoding="utf-8")
        self.registry["formats"][0]["sources"][0]["contains"] = declaration
        self.registry["formats"][0]["version"] = version

    def prior_reader(
        self, version: int | str, *, ignored: bool = False
    ) -> dict[str, object]:
        literal = str(version) if isinstance(version, int) else json.dumps(version)
        rust_type = "u16" if isinstance(version, int) else "&str"
        function_suffix = f"v{version}"
        source = self.root / "crates" / "automata-ci-core" / "src" / "compatibility.rs"
        source.write_text(
            f"fn decode_prior(version: {rust_type}) {{ if version == {literal} {{}} }}\n",
            encoding="utf-8",
        )
        test = self.root / "crates" / "automata-ci-core" / "tests" / "compatibility.rs"
        attributes = "#[test]\n#[ignore]\n" if ignored else "#[test]\n"
        test.write_text(
            f"{attributes}fn reads_prior_{function_suffix}() {{\n"
            f"    let prior_version: {rust_type} = {literal};\n"
            "    assert!(decode_prior(prior_version).is_ok());\n"
            "}\n",
            encoding="utf-8",
        )
        return {
            "reader": {
                "contains": f"version == {literal}",
                "path": "crates/automata-ci-core/src/compatibility.rs",
                "symbol": "decode_prior",
            },
            "tests": [
                {
                    "function": f"reads_prior_{function_suffix}",
                    "outcome": "assert!(decode_prior(prior_version).is_ok());",
                    "path": "crates/automata-ci-core/tests/compatibility.rs",
                    "reader_call": "decode_prior(prior_version)",
                    "version": f"let prior_version: {rust_type} = {literal};",
                }
            ],
            "version": version,
        }

    def prior_rejection(
        self, version: int, *, ignored: bool = False
    ) -> dict[str, object]:
        source = self.root / "crates" / "automata-ci-core" / "src" / "version.rs"
        source.write_text(
            source.read_text(encoding="utf-8")
            + "fn decode_current(version: u16) -> Result<(), ()> {\n"
            + "    if version != FORMAT_VERSION { return Err(()); }\n"
            + "    Ok(())\n"
            + "}\n",
            encoding="utf-8",
        )
        test = self.root / "crates" / "automata-ci-core" / "tests" / "rejection.rs"
        attributes = "#[test]\n#[ignore]\n" if ignored else "#[test]\n"
        test.write_text(
            f"{attributes}fn rejects_prior_v{version}() {{\n"
            f"    let prior_version: u16 = {version};\n"
            "    assert!(decode_current(prior_version).is_err());\n"
            "}\n",
            encoding="utf-8",
        )
        return {
            "rejection": {
                "contains": "if version != FORMAT_VERSION { return Err(()); }",
                "path": "crates/automata-ci-core/src/version.rs",
                "symbol": "decode_current",
            },
            "tests": [
                {
                    "function": f"rejects_prior_v{version}",
                    "outcome": "assert!(decode_current(prior_version).is_err());",
                    "path": "crates/automata-ci-core/tests/rejection.rs",
                    "reader_call": "decode_current(prior_version)",
                    "reader_symbol": "decode_current",
                    "version": f"let prior_version: u16 = {version};",
                }
            ],
            "version": version,
        }

    def add_limit_alias(self, *, value: int = 6) -> None:
        source = self.root / "crates" / "automata-ci-runtime" / "src" / "limits.rs"
        source.write_text(
            source.read_text(encoding="utf-8")
            + f"const TEST_ITEM_CENSUS_LIMIT: usize = {value};\n",
            encoding="utf-8",
        )
        test = self.root / "crates" / "automata-ci-runtime" / "tests" / "limits.rs"
        test.write_text(
            test.read_text(encoding="utf-8")
            + "#[test]\nfn census_alias_matches_limit() {\n"
            + "    assert_eq!(TEST_ITEM_CENSUS_LIMIT, MAX_TEST_ITEMS + 1);\n}\n",
            encoding="utf-8",
        )
        self.registry["limit_aliases"] = [
            {
                "owner": "integration",
                "phase": "runtime",
                "relation": {"kind": "offset", "offset": 1},
                "source": {
                    "constant": "TEST_ITEM_CENSUS_LIMIT",
                    "path": "crates/automata-ci-runtime/src/limits.rs",
                },
                "target": {
                    "constant": "MAX_TEST_ITEMS",
                    "path": "crates/automata-ci-runtime/src/limits.rs",
                },
                "tests": [
                    {
                        "contains": (
                            "assert_eq!(TEST_ITEM_CENSUS_LIMIT, MAX_TEST_ITEMS + 1);"
                        ),
                        "function": "census_alias_matches_limit",
                        "path": "crates/automata-ci-runtime/tests/limits.rs",
                    }
                ],
            }
        ]

    def test_valid_minimal_repository_passes(self) -> None:
        governance.validate_repository(self.root)

    def test_format_scope_cannot_claim_unversioned_public_json_apis(self) -> None:
        self.registry["format_scope"]["unversioned_public_json_apis"] = "included"
        self.write_registry()

        self.assert_invalid(
            r"format_scope.unversioned_public_json_apis must be 'out-of-scope'"
        )

    def test_canonical_crlf_checkout_passes(self) -> None:
        contents = canonical_json(self.registry).replace("\n", "\r\n")
        self.registry_path.write_bytes(contents.encode("utf-8"))

        governance.validate_repository(self.root)

    def test_source_fragment_drift_is_rejected(self) -> None:
        source = self.root / "crates" / "automata-ci-core" / "src" / "version.rs"
        source.write_text("pub const FORMAT_VERSION: u16 = 2;\n", encoding="utf-8")

        self.assert_invalid(r"fragment must occur exactly once.*found 0")

    def test_new_format_declaration_requires_registration_or_exclusion(self) -> None:
        source = self.root / "crates" / "automata-ci-core" / "src" / "untracked.rs"
        source.write_text("pub const NEW_WIRE_SCHEMA: u16 = 1;\n", encoding="utf-8")

        self.assert_invalid(r"unregistered format declarations.*NEW_WIRE_SCHEMA")

    def test_indented_production_format_declaration_cannot_escape_discovery(self) -> None:
        source = self.root / "crates" / "automata-ci-core" / "src" / "untracked.rs"
        source.write_text(
            "pub mod wire {\n    const NESTED_WIRE_SCHEMA: u16 = 1;\n}\n",
            encoding="utf-8",
        )

        self.assert_invalid(r"unregistered format declarations.*NESTED_WIRE_SCHEMA")

    def test_named_versioned_command_protocol_requires_governance(self) -> None:
        source = self.root / "crates" / "automata-ci-core" / "src" / "command.rs"
        source.write_text(
            'pub const SERVE_COMMAND: &str = "serve-v1";\n',
            encoding="utf-8",
        )

        self.assert_invalid(r"unregistered format declarations.*SERVE_COMMAND")

    def test_unversioned_internal_command_is_outside_format_discovery(self) -> None:
        source = self.root / "crates" / "automata-ci-core" / "src" / "command.rs"
        source.write_text(
            'pub const HEALTH_COMMAND: &str = "health";\n',
            encoding="utf-8",
        )

        governance.validate_repository(self.root)

    def test_test_only_format_constants_are_not_production_contracts(self) -> None:
        source = self.root / "crates" / "new-derived-adapter" / "src" / "fixture.rs"
        source.parent.mkdir(parents=True)
        source.write_text(
            "#[cfg(test)]\n"
            "mod tests {\n"
            "    const TEST_WIRE_SCHEMA: u16 = 1;\n"
            "}\n"
            "#[test]\n"
            "fn inline_fixture() {\n"
            "    const LOCAL_WIRE_SCHEMA: u16 = 1;\n"
            "}\n",
            encoding="utf-8",
        )

        governance.validate_repository(self.root)

    def test_new_media_type_and_named_format_require_governance(self) -> None:
        source = self.root / "crates" / "automata-ci-core" / "src" / "wire.rs"
        source.write_text(
            'pub const EVENT_MEDIA_TYPE: &str = "application/vnd.example.event+json";\n'
            'pub const ARCHIVE_FORMAT: &str = "tar_gzip";\n',
            encoding="utf-8",
        )

        self.assert_invalid(r"unregistered format declarations.*ARCHIVE_FORMAT.*EVENT_MEDIA_TYPE")

    def test_new_typescript_schema_requires_governance(self) -> None:
        source = self.root / "ui" / "src" / "wire.ts"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(
            "export const UI_WIRE_SCHEMA_VERSION = 1 as const;\n",
            encoding="utf-8",
        )

        self.assert_invalid(r"unregistered format declarations.*UI_WIRE_SCHEMA_VERSION")

    def test_rust_raw_string_declarations_are_not_censused_as_formats(self) -> None:
        source = self.root / "crates" / "automata-ci-core" / "src" / "bait.rs"
        source.write_text(
            'const BAIT: &str = r#"\n'
            "pub const FAKE_WIRE_VERSION: u16 = 1;\n"
            '"#;\n',
            encoding="utf-8",
        )

        governance.validate_repository(self.root)

    def test_top_level_cfg_test_format_constant_is_not_a_production_contract(self) -> None:
        source = self.root / "crates" / "new-derived-adapter" / "src" / "fixture.rs"
        source.parent.mkdir(parents=True)
        source.write_text(
            "#[cfg(test)]\npub const HIDDEN_WIRE_SCHEMA_VERSION: u16 = 1;\n",
            encoding="utf-8",
        )

        governance.validate_repository(self.root)

    def test_cfg_all_requiring_test_is_not_a_production_contract(self) -> None:
        source = self.root / "crates" / "new-derived-adapter" / "src" / "fixture.rs"
        source.parent.mkdir(parents=True)
        source.write_text(
            "#[cfg(all(test, unix))]\npub const HIDDEN_WIRE_SCHEMA_VERSION: u16 = 1;\n",
            encoding="utf-8",
        )

        governance.validate_repository(self.root)

    def test_cfg_any_with_a_production_branch_remains_censused(self) -> None:
        source = self.root / "crates" / "new-derived-adapter" / "src" / "fixture.rs"
        source.parent.mkdir(parents=True)
        source.write_text(
            "#[cfg(any(test, unix))]\npub const LIVE_WIRE_SCHEMA_VERSION: u16 = 1;\n",
            encoding="utf-8",
        )

        self.assert_invalid(r"unregistered format declarations.*LIVE_WIRE_SCHEMA_VERSION")

    def test_cfg_not_test_format_constant_remains_censused(self) -> None:
        source = self.root / "crates" / "new-derived-adapter" / "src" / "fixture.rs"
        source.parent.mkdir(parents=True)
        source.write_text(
            "#[cfg(not(test))]\npub const LIVE_WIRE_SCHEMA_VERSION: u16 = 1;\n",
            encoding="utf-8",
        )

        self.assert_invalid(r"unregistered format declarations.*LIVE_WIRE_SCHEMA_VERSION")

    def test_cfg_test_field_does_not_mask_following_production_items(self) -> None:
        source = self.root / "crates" / "new-derived-adapter" / "src" / "fixture.rs"
        source.parent.mkdir(parents=True)
        source.write_text(
            "struct Probe {\n"
            "    #[cfg(test)]\n"
            "    test_field: bool,\n"
            "}\n"
            "pub const LIVE_WIRE_SCHEMA_VERSION: u16 = 1;\n",
            encoding="utf-8",
        )

        self.assert_invalid(r"unregistered format declarations.*LIVE_WIRE_SCHEMA_VERSION")

    def test_explicit_path_cfg_test_module_file_is_not_censused(self) -> None:
        source_root = self.root / "crates" / "new-derived-adapter" / "src"
        source_root.mkdir(parents=True)
        (source_root / "lib.rs").write_text(
            '#[cfg(test)]\n#[path = "fixture.rs"]\nmod hidden;\n',
            encoding="utf-8",
        )
        (source_root / "fixture.rs").write_text(
            "pub const HIDDEN_WIRE_SCHEMA_VERSION: u16 = 1;\n",
            encoding="utf-8",
        )

        governance.validate_repository(self.root)

    def test_typescript_templates_are_not_censused_as_formats(self) -> None:
        source = self.root / "ui" / "src" / "bait.ts"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(
            "const bait = `\nexport const FAKE_UI_SCHEMA_VERSION = 1;\n`;\n",
            encoding="utf-8",
        )

        governance.validate_repository(self.root)

    def test_rust_raw_string_cannot_supply_a_registered_format_source(self) -> None:
        source = self.root / "crates" / "automata-ci-core" / "src" / "version.rs"
        source.write_text(
            'const BAIT: &str = r#"\n'
            "pub const FORMAT_VERSION: u16 = 1;\n"
            '"#;\n',
            encoding="utf-8",
        )

        self.assert_invalid(r"source.*fragment must occur exactly once.*outside comments")

    def test_rust_raw_string_declarations_are_not_censused_as_limits(self) -> None:
        source = self.root / "crates" / "automata-ci-runtime" / "src" / "bait.rs"
        source.write_text(
            'const BAIT: &str = r#"\n'
            "pub const MAX_FAKE_ITEMS: usize = 99;\n"
            '"#;\n',
            encoding="utf-8",
        )

        governance.validate_repository(self.root)

    def test_non_format_version_constant_can_be_explicitly_excluded(self) -> None:
        source = self.root / "crates" / "automata-ci-core" / "src" / "external.rs"
        source.write_text(
            'pub const EXTERNAL_API_VERSION: &str = "2026-03-10";\n',
            encoding="utf-8",
        )
        self.registry["format_exclusions"] = [
            {
                "constant": "EXTERNAL_API_VERSION",
                "path": "crates/automata-ci-core/src/external.rs",
                "reason": "Version of an upstream API, not an Automata durable or wire format.",
            }
        ]
        self.write_registry()

        governance.validate_repository(self.root)

    def test_stale_format_exclusion_is_rejected(self) -> None:
        source = self.root / "crates" / "automata-ci-core" / "src" / "external.rs"
        source.write_text("pub const SOMETHING_ELSE: u16 = 1;\n", encoding="utf-8")
        self.registry["format_exclusions"] = [
            {
                "constant": "EXTERNAL_API_VERSION",
                "path": "crates/automata-ci-core/src/external.rs",
                "reason": "Version of an upstream API, not an Automata durable or wire format.",
            }
        ]
        self.write_registry()

        self.assert_invalid(r"does not bind a discovered format declaration")

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
            / "automata-ci-postgres"
            / "migrations"
            / "0002_unregistered.sql"
        )
        migration.write_text("SELECT 2;\n", encoding="utf-8")

        self.assert_invalid("migration inventory drift")

    def test_canonical_migration_content_drift_is_rejected(self) -> None:
        migration = (
            self.root
            / "crates"
            / "automata-ci-postgres"
            / "migrations"
            / "0001_initial_schema.sql"
        )
        migration.write_text("SELECT 2;\n", encoding="utf-8")

        self.assert_invalid("canonical migration content drift")

    def test_unmapped_canonical_migration_format_literal_is_rejected(self) -> None:
        migration = (
            self.root
            / "crates"
            / "automata-ci-postgres"
            / "migrations"
            / "0001_initial_schema.sql"
        )
        contents = "SELECT 1 WHERE payload_schema = 1;\n"
        migration.write_text(contents, encoding="utf-8")
        self.registry["migrations"]["sha256"] = hashlib.sha256(
            contents.encode("utf-8")
        ).hexdigest()
        self.write_registry()

        self.assert_invalid(r"store migration format map is incomplete.*payload_schema")

    def test_mapped_canonical_migration_value_drift_is_rejected(self) -> None:
        migration = (
            self.root
            / "crates"
            / "automata-ci-postgres"
            / "migrations"
            / "0001_initial_schema.sql"
        )
        contents = "SELECT 1 WHERE payload_schema = 2;\n"
        migration.write_text(contents, encoding="utf-8")
        self.registry["migrations"]["sha256"] = hashlib.sha256(
            contents.encode("utf-8")
        ).hexdigest()
        self.write_registry()
        self.migration_format_map_path.write_text(
            canonical_json(
                {
                    "contracts": [
                        {
                            "format_ids": ["test-format"],
                            "identifier": "payload_schema",
                            "reason": "Synthetic mapping to the registered test format schema.",
                        }
                    ],
                    "embedded_json_contracts": [],
                    "expected_value": 1,
                    "media_type_contracts": [],
                    "migration": "0001_initial_schema.sql",
                    "schema_version": 1,
                }
            ),
            encoding="utf-8",
        )

        self.assert_invalid(r"canonical migration format literals do not match mapped value 1")

    def test_mapped_canonical_migration_insert_value_drift_is_rejected(self) -> None:
        migration = (
            self.root
            / "crates"
            / "automata-ci-postgres"
            / "migrations"
            / "0001_initial_schema.sql"
        )
        contents = "INSERT INTO objects (payload_schema) VALUES (2);\n"
        migration.write_text(contents, encoding="utf-8")
        self.registry["migrations"]["sha256"] = hashlib.sha256(
            contents.encode("utf-8")
        ).hexdigest()
        self.write_registry()
        self.migration_format_map_path.write_text(
            canonical_json(
                {
                    "contracts": [
                        {
                            "format_ids": ["test-format"],
                            "identifier": "payload_schema",
                            "reason": "Synthetic mapping to the registered test format schema.",
                        }
                    ],
                    "embedded_json_contracts": [],
                    "expected_value": 1,
                    "media_type_contracts": [],
                    "migration": "0001_initial_schema.sql",
                    "schema_version": 1,
                }
            ),
            encoding="utf-8",
        )

        self.assert_invalid(r"canonical migration format literals do not match mapped value 1")

    def test_unmapped_canonical_migration_embedded_json_is_rejected(self) -> None:
        migration = (
            self.root
            / "crates"
            / "automata-ci-postgres"
            / "migrations"
            / "0001_initial_schema.sql"
        )
        contents = "SELECT '{\"schema_version\": 1}'::JSONB;\n"
        migration.write_text(contents, encoding="utf-8")
        self.registry["migrations"]["sha256"] = hashlib.sha256(
            contents.encode("utf-8")
        ).hexdigest()
        self.write_registry()

        self.assert_invalid(r"embedded JSON format map is incomplete")

    def test_unmapped_canonical_migration_media_type_is_rejected(self) -> None:
        migration = (
            self.root
            / "crates"
            / "automata-ci-postgres"
            / "migrations"
            / "0001_initial_schema.sql"
        )
        contents = (
            "SELECT 1 WHERE payload_media_type = "
            "'application/vnd.example.payload+json';\n"
        )
        migration.write_text(contents, encoding="utf-8")
        self.registry["migrations"]["sha256"] = hashlib.sha256(
            contents.encode("utf-8")
        ).hexdigest()
        self.write_registry()

        self.assert_invalid(r"media-type map is incomplete")

    def test_hardcoded_production_sql_schema_comparison_is_rejected(self) -> None:
        source = self.root / "crates" / "automata-ci-runtime" / "src" / "reader.rs"
        source.write_text(
            'fn read() { sqlx::query("SELECT payload_schema WHERE payload_schema = 1"); }\n',
            encoding="utf-8",
        )

        self.assert_invalid(r"hardcoded production durable format literals.*payload_schema")

    def test_hardcoded_production_json_schema_literal_is_rejected(self) -> None:
        source = self.root / "crates" / "automata-ci-runtime" / "src" / "writer.rs"
        source.write_text(
            'fn write() { let _ = serde_json::json!({"schema": 1}); }\n',
            encoding="utf-8",
        )

        self.assert_invalid(r"hardcoded production durable format literals.*JSON")

    def test_hardcoded_production_sql_media_literal_is_rejected(self) -> None:
        source = self.root / "crates" / "automata-ci-runtime" / "src" / "reader.rs"
        source.write_text(
            "fn read() { sqlx::query(\"SELECT 1 WHERE payload_media_type = 'application/vnd.example+json'\"); }\n",
            encoding="utf-8",
        )

        self.assert_invalid(r"hardcoded production durable format literals.*media-type")

    def test_hardcoded_production_insert_schema_literal_is_rejected(self) -> None:
        source = self.root / "crates" / "automata-ci-runtime" / "src" / "writer.rs"
        source.write_text(
            'fn write() { sqlx::query("INSERT INTO objects (payload_schema) VALUES (1)"); }\n',
            encoding="utf-8",
        )

        self.assert_invalid(r"hardcoded production durable format literals.*INSERT payload_schema")

    def test_test_only_format_literals_do_not_trigger_production_guard(self) -> None:
        source = self.root / "crates" / "automata-ci-runtime" / "src" / "fixture.rs"
        source.write_text(
            '#[cfg(test)]\nmod tests { const FIXTURE: &str = "{\\"schema\\":1}"; }\n',
            encoding="utf-8",
        )

        governance.validate_repository(self.root)

    def test_production_after_test_module_is_still_guarded(self) -> None:
        source = self.root / "crates" / "automata-ci-runtime" / "src" / "reader.rs"
        source.write_text(
            '#[cfg(test)]\nmod tests { const FIXTURE: &str = "{\\"schema\\":1}"; }\n'
            'fn read() { sqlx::query("SELECT 1 WHERE payload_schema = 1"); }\n',
            encoding="utf-8",
        )

        self.assert_invalid(r"hardcoded production durable format literals.*payload_schema")

    def test_limit_value_must_match_its_source_binding(self) -> None:
        self.registry["limits"][0]["value"] = 6
        self.write_registry()

        self.assert_invalid(r"source does not bind declared value 6")

    def test_new_limit_on_a_governed_surface_requires_registration_or_exclusion(self) -> None:
        source = self.root / "crates" / "new-parity-adapter" / "src" / "new.rs"
        source.parent.mkdir(parents=True)
        source.write_text(
            "const MAX_NEW_ITEMS: usize = 9;\n",
            encoding="utf-8",
        )

        self.assert_invalid(r"unregistered limit declarations.*MAX_NEW_ITEMS")

    def test_unannotated_leading_hard_max_limit_is_discovered(self) -> None:
        source = self.root / "crates" / "new-parity-adapter" / "src" / "hard.rs"
        source.parent.mkdir(parents=True)
        source.write_text("const HARD_MAX_ROWS: usize = 9;\n", encoding="utf-8")

        self.assert_invalid(r"unregistered limit declarations.*HARD_MAX_ROWS")

    def test_unannotated_infix_max_limit_is_discovered(self) -> None:
        source = self.root / "crates" / "new-parity-adapter" / "src" / "github.rs"
        source.parent.mkdir(parents=True)
        source.write_text("const GITHUB_EVENT_MAX_BYTES: u64 = 9;\n", encoding="utf-8")

        self.assert_invalid(r"unregistered limit declarations.*GITHUB_EVENT_MAX_BYTES")

    def test_unannotated_infix_limit_token_is_discovered(self) -> None:
        source = self.root / "crates" / "new-parity-adapter" / "src" / "retry.rs"
        source.parent.mkdir(parents=True)
        source.write_text("const RETRY_LIMIT_ATTEMPTS: u16 = 9;\n", encoding="utf-8")

        self.assert_invalid(r"unregistered limit declarations.*RETRY_LIMIT_ATTEMPTS")

    def test_limit_semantic_type_is_discovered_without_a_name_token(self) -> None:
        source = self.root / "crates" / "new-parity-adapter" / "src" / "typed.rs"
        source.parent.mkdir(parents=True)
        source.write_text(
            "struct RetryLimit;\nconst RETRY_POLICY: RetryLimit = RetryLimit;\n",
            encoding="utf-8",
        )

        self.assert_invalid(r"unregistered limit declarations.*RETRY_POLICY")

    def test_limit_words_require_token_boundaries(self) -> None:
        source = self.root / "crates" / "new-internal-adapter" / "src" / "lexical.rs"
        source.parent.mkdir(parents=True)
        source.write_text(
            "const MAXIMIZED_RETRIES: usize = 3;\n"
            "const UNLIMITED_RETRIES: usize = 3;\n",
            encoding="utf-8",
        )

        governance.validate_repository(self.root)

    def test_unannotated_internal_limit_requires_a_disposition(self) -> None:
        source = self.root / "crates" / "new-internal-adapter" / "src" / "retry.rs"
        source.parent.mkdir(parents=True)
        source.write_text("const MAX_RETRY_ATTEMPTS: usize = 3;\n", encoding="utf-8")

        self.assert_invalid(r"unregistered limit declarations.*MAX_RETRY_ATTEMPTS")

    def test_operational_limit_can_be_explicitly_excluded(self) -> None:
        source = self.root / "crates" / "automata-ci-runtime" / "src" / "retry.rs"
        source.write_text(
            "const MAX_RETRY_ATTEMPTS: usize = 3;\n"
            "fn retry() { let _attempts = MAX_RETRY_ATTEMPTS; }\n",
            encoding="utf-8",
        )
        self.registry["limit_exclusions"] = [
            {
                "classification": "operational",
                "constants": ["MAX_RETRY_ATTEMPTS"],
                "owner": "integration",
                "path": "crates/automata-ci-runtime/src/retry.rs",
                "phase": "runtime",
                "reason": "Internal retry budget, not a GitHub-visible compatibility limit.",
                "uses": [
                    {
                        "constant": "MAX_RETRY_ATTEMPTS",
                        "contains": "fn retry() { let _attempts = MAX_RETRY_ATTEMPTS; }",
                        "path": "crates/automata-ci-runtime/src/retry.rs",
                    }
                ],
            }
        ]
        self.write_registry()

        governance.validate_repository(self.root)

    def test_raw_string_cannot_supply_an_operational_limit_use(self) -> None:
        source = self.root / "crates" / "automata-ci-runtime" / "src" / "retry.rs"
        binding = 'let bait = r#"let _attempts = MAX_RETRY_ATTEMPTS;"#;'
        source.write_text(
            "const MAX_RETRY_ATTEMPTS: usize = 3;\n"
            f"fn retry() {{ {binding} }}\n",
            encoding="utf-8",
        )
        self.registry["limit_exclusions"] = [
            {
                "classification": "operational",
                "constants": ["MAX_RETRY_ATTEMPTS"],
                "owner": "integration",
                "path": "crates/automata-ci-runtime/src/retry.rs",
                "phase": "runtime",
                "reason": "Internal retry budget, not a GitHub-visible compatibility limit.",
                "uses": [
                    {
                        "constant": "MAX_RETRY_ATTEMPTS",
                        "contains": binding,
                        "path": "crates/automata-ci-runtime/src/retry.rs",
                    }
                ],
            }
        ]
        self.write_registry()

        self.assert_invalid(r"contains does not reference MAX_RETRY_ATTEMPTS")

    def test_ordinary_string_cannot_supply_an_operational_limit_use(self) -> None:
        source = self.root / "crates" / "automata-ci-runtime" / "src" / "retry.rs"
        binding = 'let bait = "MAX_RETRY_ATTEMPTS";'
        source.write_text(
            "const MAX_RETRY_ATTEMPTS: usize = 3;\n"
            f"fn retry() {{ {binding} }}\n",
            encoding="utf-8",
        )
        self.registry["limit_exclusions"] = [
            {
                "classification": "operational",
                "constants": ["MAX_RETRY_ATTEMPTS"],
                "owner": "integration",
                "path": "crates/automata-ci-runtime/src/retry.rs",
                "phase": "runtime",
                "reason": "Internal retry budget, not a GitHub-visible compatibility limit.",
                "uses": [
                    {
                        "constant": "MAX_RETRY_ATTEMPTS",
                        "contains": binding,
                        "path": "crates/automata-ci-runtime/src/retry.rs",
                    }
                ],
            }
        ]
        self.write_registry()

        self.assert_invalid(r"contains does not reference MAX_RETRY_ATTEMPTS")

    def test_duplicate_associated_limit_names_require_qualified_dispositions(self) -> None:
        source = self.root / "crates" / "automata-ci-runtime" / "src" / "associated.rs"
        source.write_text(
            "struct Alpha;\n"
            "impl Alpha {\n"
            "    const MAX: usize = 3;\n"
            "    fn accepts(value: usize) -> bool { value < Self::MAX }\n"
            "}\n"
            "struct Beta;\n"
            "impl Beta {\n"
            "    const MAX: usize = 7;\n"
            "    fn accepts(value: usize) -> bool { value <= Self::MAX }\n"
            "}\n",
            encoding="utf-8",
        )
        self.registry["limit_exclusions"] = [
            {
                "classification": "operational",
                "constants": ["Alpha::MAX", "Beta::MAX"],
                "owner": "integration",
                "path": "crates/automata-ci-runtime/src/associated.rs",
                "phase": "runtime",
                "reason": (
                    "Synthetic associated constants prove that declaration identity "
                    "includes the owning type."
                ),
                "uses": [
                    {
                        "constant": "Alpha::MAX",
                        "contains": "value < Self::MAX",
                        "path": "crates/automata-ci-runtime/src/associated.rs",
                        "scope": "Alpha::accepts",
                    },
                    {
                        "constant": "Beta::MAX",
                        "contains": "value <= Self::MAX",
                        "path": "crates/automata-ci-runtime/src/associated.rs",
                        "scope": "Beta::accepts",
                    },
                ],
            }
        ]
        self.write_registry()

        governance.validate_repository(self.root)

        self.registry["limit_exclusions"][0]["constants"] = ["Alpha::MAX"]
        self.registry["limit_exclusions"][0]["uses"] = [
            self.registry["limit_exclusions"][0]["uses"][0]
        ]
        self.write_registry()

        self.assert_invalid(r"unregistered limit declarations.*Beta::MAX")

    def test_operational_limit_requires_an_exclusion(self) -> None:
        source = self.root / "crates" / "automata-ci-runtime" / "src" / "retry.rs"
        source.write_text(
            "const MAX_RETRY_ATTEMPTS: usize = 3;\n",
            encoding="utf-8",
        )

        self.assert_invalid(r"unregistered limit declarations.*MAX_RETRY_ATTEMPTS")

    def test_stale_limit_exclusion_is_rejected(self) -> None:
        source = self.root / "crates" / "automata-ci-runtime" / "src" / "retry.rs"
        source.write_text(
            "const MAX_OTHER_ATTEMPTS: usize = 3;\n"
            "fn retry() { let _attempts = MAX_RETRY_ATTEMPTS; }\n",
            encoding="utf-8",
        )
        self.registry["limit_exclusions"] = [
            {
                "classification": "operational",
                "constants": ["MAX_RETRY_ATTEMPTS"],
                "owner": "integration",
                "path": "crates/automata-ci-runtime/src/retry.rs",
                "phase": "runtime",
                "reason": "Internal retry budget, not a GitHub-visible compatibility limit.",
                "uses": [
                    {
                        "constant": "MAX_RETRY_ATTEMPTS",
                        "contains": "fn retry() { let _attempts = MAX_RETRY_ATTEMPTS; }",
                        "path": "crates/automata-ci-runtime/src/retry.rs",
                    }
                ],
            }
        ]
        self.write_registry()

        self.assert_invalid(r"excludes missing limit declaration MAX_RETRY_ATTEMPTS")

    def test_structured_limit_alias_with_checked_offset_is_accepted(self) -> None:
        self.add_limit_alias()
        self.write_registry()

        governance.validate_repository(self.root)

    def test_limit_alias_name_inside_a_string_does_not_prove_test_coverage(self) -> None:
        self.add_limit_alias()
        test = self.root / "crates" / "automata-ci-runtime" / "tests" / "limits.rs"
        test.write_text(
            test.read_text(encoding="utf-8").replace(
                "assert_eq!(TEST_ITEM_CENSUS_LIMIT, MAX_TEST_ITEMS + 1);",
                'let bait = "TEST_ITEM_CENSUS_LIMIT";\n    assert!(true);',
            ),
            encoding="utf-8",
        )
        self.registry["limit_aliases"][0]["tests"][0]["contains"] = "assert!(true);"
        self.write_registry()

        self.assert_invalid(r"tests do not exercise the alias source")

    def test_limit_alias_value_drift_is_rejected(self) -> None:
        self.add_limit_alias(value=7)
        self.write_registry()

        self.assert_invalid(r"relation drift.*TEST_ITEM_CENSUS_LIMIT.*expected 5 \+ 1")

    def test_stale_limit_alias_source_is_rejected(self) -> None:
        self.add_limit_alias()
        self.registry["limit_aliases"][0]["source"]["constant"] = "GONE_LIMIT"
        self.write_registry()

        self.assert_invalid(r"source is not a discovered limit candidate.*GONE_LIMIT")

    def test_limit_declaration_cannot_have_multiple_dispositions(self) -> None:
        self.add_limit_alias()
        self.registry["limit_exclusions"] = [
            {
                "classification": "non-limit",
                "constants": ["TEST_ITEM_CENSUS_LIMIT"],
                "owner": "integration",
                "path": "crates/automata-ci-runtime/src/limits.rs",
                "phase": "runtime",
                "reason": (
                    "Synthetic overlap proves that one declaration cannot receive two "
                    "governance dispositions."
                ),
                "uses": [],
            }
        ]
        self.write_registry()

        self.assert_invalid(r"cannot be both registered and excluded.*TEST_ITEM_CENSUS_LIMIT")

    def test_reason_code_must_match_its_source_binding(self) -> None:
        self.registry["limits"][0]["reason_code"] = "TestLimitError::Other"
        self.write_registry()

        self.assert_invalid(r"reason_source does not bind declared reason code")

    def test_reason_code_prefix_does_not_bind_a_longer_variant(self) -> None:
        self.registry["limits"][0]["reason_code"] = "TestLimitError::Exceed"
        self.write_registry()

        self.assert_invalid(r"reason_source does not bind declared reason code")

    def test_dotted_reason_must_be_the_designated_first_call_argument(self) -> None:
        source = self.root / "crates" / "automata-ci-runtime" / "src" / "limits.rs"
        source.write_text(
            "pub const MAX_TEST_ITEMS: usize = 5;\n"
            'context.semantic("wrong.reason", "test.limit.exceeded");\n',
            encoding="utf-8",
        )
        self.registry["limits"][0]["reason_code"] = "test.limit.exceeded"
        self.registry["limits"][0]["reason_source"]["contains"] = "context.semantic("
        self.write_registry()

        self.assert_invalid(r"reason_source does not bind declared reason code")

    def test_limit_type_width_does_not_bind_the_declared_value(self) -> None:
        declaration = "pub const MAX_TEST_ITEMS: [u8; 64] = OTHER;"
        source = self.root / "crates" / "automata-ci-runtime" / "src" / "limits.rs"
        source.write_text(
            f"const OTHER: [u8; 64] = [0; 64];\n{declaration}\n"
            "return Err(TestLimitError::Exceeded);\n",
            encoding="utf-8",
        )
        self.registry["limits"][0]["source"]["contains"] = declaration
        self.registry["limits"][0]["value"] = 64
        self.write_registry()

        self.assert_invalid(r"source does not bind declared value 64")

    def test_enforcement_phase_is_closed(self) -> None:
        self.registry["limits"][0]["enforcement_phase"] = "somewhere"
        self.write_registry()

        self.assert_invalid(r"enforcement_phase is unsupported")

    def test_rust_integer_type_does_not_bind_a_declared_version(self) -> None:
        self.registry["formats"][0]["version"] = 16
        self.write_registry()

        self.assert_invalid(r"does not bind declared version 16")

    def test_inactive_numeric_initializer_branch_does_not_bind_a_version(self) -> None:
        declaration = "pub const FORMAT_VERSION: u16 = if false { 2 } else { 1 };"
        source = self.root / "crates" / "automata-ci-core" / "src" / "version.rs"
        source.write_text(f"{declaration}\n", encoding="utf-8")
        self.registry["formats"][0]["sources"][0]["contains"] = declaration
        self.registry["formats"][0]["version"] = 2
        self.write_registry()

        self.assert_invalid(r"does not bind declared version 2")

    def test_canonical_string_format_version_is_supported_and_exact(self) -> None:
        source = self.root / "crates" / "automata-ci-core" / "src" / "version.rs"
        source.write_text('pub const FORMAT_VERSION: &str = "v1";\n', encoding="utf-8")
        self.registry["formats"][0]["sources"][0]["contains"] = (
            'pub const FORMAT_VERSION: &str = "v1";'
        )
        self.registry["formats"][0]["version"] = "v1"
        self.write_registry()

        governance.validate_repository(self.root)

        self.registry["formats"][0]["version"] = "v2"
        self.write_registry()
        self.assert_invalid(r"does not bind declared version v2")

    def test_conditional_string_initializer_cannot_bind_an_inactive_version(self) -> None:
        declaration = (
            'pub const FORMAT_VERSION: &str = if false { "bw2" } else { "bw1" };'
        )
        source = self.root / "crates" / "automata-ci-core" / "src" / "version.rs"
        source.write_text(f"{declaration}\n", encoding="utf-8")
        self.registry["formats"][0]["sources"][0]["contains"] = declaration
        self.registry["formats"][0]["version"] = "bw2"
        self.write_registry()

        self.assert_invalid(r"does not bind declared version bw2")

    def test_explicit_compact_ordinal_v1_tokens_are_supported(self) -> None:
        for prefix in ("bw", "dp", "p"):
            with self.subTest(prefix=prefix):
                self.set_string_format_version(f"{prefix}1")
                self.registry["formats"][0]["version_sequence"] = {
                    "kind": "prefix-ordinal",
                    "prefix": prefix,
                }
                self.write_registry()

                governance.validate_repository(self.root)

    def test_compact_ordinal_tokens_cannot_silently_advance_to_v2(self) -> None:
        for prefix in ("bw", "dp", "p"):
            with self.subTest(prefix=prefix):
                version = f"{prefix}2"
                self.set_string_format_version(version)
                self.registry["formats"][0]["version_sequence"] = {
                    "kind": "prefix-ordinal",
                    "prefix": prefix,
                }
                self.write_registry()

                self.assert_invalid(
                    rf"exact-current-only.*cannot declare sequenced version {version}"
                )

    def test_governed_compact_sequence_marker_cannot_be_removed_on_bump(self) -> None:
        governed = (
            (
                "github-browser-proof",
                "bw",
                "crates/automata-ci-auth/src/github/login_service.rs",
                "BROWSER_PROOF_VERSION",
            ),
            (
                "github-device-proof",
                "dp",
                "crates/automata-ci-auth/src/github/login_service.rs",
                "DEVICE_PROOF_VERSION",
            ),
            (
                "podman-sandbox-handle",
                "p",
                "crates/automata-ci-sandbox-podman/src/naming.rs",
                "HANDLE_VERSION",
            ),
        )
        for format_id, prefix, relative, constant in governed:
            with self.subTest(format_id=format_id):
                version = f"{prefix}2"
                self.registry["formats"][0]["id"] = f"renamed-{format_id}"
                self.set_string_format_version(version)
                original_source = (
                    self.root / "crates" / "automata-ci-core" / "src" / "version.rs"
                )
                original_source.write_text("", encoding="utf-8")
                declaration = f'const {constant}: &str = "{version}";'
                governed_source = self.root / relative
                governed_source.parent.mkdir(parents=True, exist_ok=True)
                governed_source.write_text(f"{declaration}\n", encoding="utf-8")
                self.registry["formats"][0]["sources"][0] = {
                    "contains": declaration,
                    "path": relative,
                    "role": "version",
                }
                self.registry["formats"][0]["version_sequence"] = {
                    "kind": "prefix-ordinal",
                    "prefix": prefix,
                }
                self.registry["formats"][0].pop("version_sequence")
                self.write_registry()

                self.assert_invalid(
                    rf"version_sequence is required with prefix '{prefix}'"
                )

    def test_governed_compact_sequence_cannot_move_to_format_exclusions(self) -> None:
        relative = "crates/automata-ci-auth/src/github/login_service.rs"
        declaration = 'const BROWSER_PROOF_VERSION: &str = "bw2";'
        source = self.root / relative
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(f"{declaration}\n", encoding="utf-8")
        self.registry["format_exclusions"] = [
            {
                "constant": "BROWSER_PROOF_VERSION",
                "path": relative,
                "reason": "Mutation attempts to disguise a governed sequence as opaque.",
            }
        ]
        self.write_registry()

        self.assert_invalid(
            r"cannot exclude reserved compact ordinal token 'bw2'"
        )

    def test_combined_compact_identity_refactor_cannot_move_to_an_exclusion(self) -> None:
        original = self.root / "crates" / "automata-ci-core" / "src" / "version.rs"
        original.write_text("", encoding="utf-8")
        ordinary_relative = "crates/automata-ci-core/src/ordinary.rs"
        ordinary = self.root / ordinary_relative
        ordinary_declaration = 'pub const OTHER_FORMAT_VERSION: &str = "v1";'
        ordinary.write_text(f"{ordinary_declaration}\n", encoding="utf-8")
        self.registry["formats"][0]["id"] = "renamed-browser-proof"
        self.registry["formats"][0]["sources"][0] = {
            "contains": ordinary_declaration,
            "path": ordinary_relative,
            "role": "version",
        }
        self.registry["formats"][0]["version"] = "v1"

        compact_relative = "crates/automata-ci-auth/src/github/renamed_login.rs"
        compact = self.root / compact_relative
        compact.parent.mkdir(parents=True, exist_ok=True)
        compact.write_text(
            'pub const RENAMED_PROOF_VERSION: &str = "bw2";\n',
            encoding="utf-8",
        )
        self.registry["format_exclusions"] = [
            {
                "constant": "RENAMED_PROOF_VERSION",
                "path": compact_relative,
                "reason": "Mutation attempts to disguise a governed sequence as opaque.",
            }
        ]
        self.write_registry()

        self.assert_invalid(r"cannot exclude reserved compact ordinal token 'bw2'")

    def test_compact_sequence_id_anchor_survives_source_refactor(self) -> None:
        version = "bw2"
        relative = "crates/automata-ci-auth/src/github/renamed_login_service.rs"
        declaration = f'const RENAMED_BROWSER_PROOF_VERSION: &str = "{version}";'
        self.registry["formats"][0]["id"] = "github-browser-proof"
        self.set_string_format_version(version)
        original_source = (
            self.root / "crates" / "automata-ci-core" / "src" / "version.rs"
        )
        original_source.write_text("", encoding="utf-8")
        moved_source = self.root / relative
        moved_source.parent.mkdir(parents=True, exist_ok=True)
        moved_source.write_text(f"{declaration}\n", encoding="utf-8")
        self.registry["formats"][0]["sources"][0] = {
            "contains": declaration,
            "path": relative,
            "role": "version",
        }
        self.registry["formats"][0]["version_sequence"] = {
            "kind": "prefix-ordinal",
            "prefix": "bw",
        }
        self.registry["formats"][0].pop("version_sequence")
        self.write_registry()

        self.assert_invalid(r"version_sequence is required with prefix 'bw'")

    def test_compact_token_anchor_survives_combined_id_and_source_refactor(self) -> None:
        version = "bw2"
        relative = "crates/automata-ci-auth/src/github/renamed_login_service.rs"
        declaration = f'const RENAMED_BROWSER_PROOF_VERSION: &str = "{version}";'
        self.registry["formats"][0]["id"] = "renamed-browser-proof"
        self.set_string_format_version(version)
        original_source = (
            self.root / "crates" / "automata-ci-core" / "src" / "version.rs"
        )
        original_source.write_text("", encoding="utf-8")
        moved_source = self.root / relative
        moved_source.parent.mkdir(parents=True, exist_ok=True)
        moved_source.write_text(f"{declaration}\n", encoding="utf-8")
        self.registry["formats"][0]["sources"][0] = {
            "contains": declaration,
            "path": relative,
            "role": "version",
        }
        self.registry["formats"][0].pop("version_sequence", None)
        self.write_registry()

        self.assert_invalid(r"version_sequence is required with prefix 'bw'")

    def test_compact_ordinal_policy_bumps_require_v1_evidence(self) -> None:
        cases = (
            (
                "backward-compatible",
                r"version bw2 requires prior_version_readers for \['bw1'\]",
            ),
            (
                "breaking-current-only",
                r"breaking version bw2 requires prior_version_rejections for \['bw1'\]",
            ),
        )
        for policy, error in cases:
            with self.subTest(policy=policy):
                self.set_string_format_version("bw2")
                self.registry["formats"][0]["compatibility_policy"] = policy
                self.registry["formats"][0]["version_sequence"] = {
                    "kind": "prefix-ordinal",
                    "prefix": "bw",
                }
                self.write_registry()

                self.assert_invalid(error)

    def test_compact_ordinal_v3_requires_v1_and_v2_reader_coverage(self) -> None:
        self.set_string_format_version("bw3")
        self.registry["formats"][0]["compatibility_policy"] = "backward-compatible"
        self.registry["formats"][0]["version_sequence"] = {
            "kind": "prefix-ordinal",
            "prefix": "bw",
        }
        self.registry["formats"][0]["prior_version_readers"] = [
            self.prior_reader("bw1")
        ]
        self.write_registry()

        self.assert_invalid(
            r"prior_version_readers must cover every prior version: "
            r"expected \['bw1', 'bw2'\], found \['bw1'\]"
        )

    def test_compact_ordinal_sequence_prefix_must_match_current_version(self) -> None:
        self.set_string_format_version("bw1")
        self.registry["formats"][0]["version_sequence"] = {
            "kind": "prefix-ordinal",
            "prefix": "dp",
        }
        self.write_registry()

        self.assert_invalid(r"prefix 'dp' must match declared version 'bw1'")

    def test_compact_ordinal_sequence_schema_is_closed(self) -> None:
        self.set_string_format_version("bw1")
        self.registry["formats"][0]["version_sequence"] = {
            "kind": "prefix-ordinal",
            "prefix": "bw",
            "suffix": "opaque",
        }
        self.write_registry()

        self.assert_invalid(r"version_sequence has invalid keys: unknown \['suffix'\]")

    def test_opaque_digit_ending_token_is_not_guessed_to_be_an_ordinal(self) -> None:
        self.set_string_format_version("sha256")
        self.write_registry()

        governance.validate_repository(self.root)

    def test_implicit_v_ordinal_is_capped_before_prior_inventory_allocation(self) -> None:
        self.set_string_format_version("v65536")
        self.write_registry()

        self.assert_invalid(r"sequenced format ordinal must be at most 65535")

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

    def test_exact_current_only_cannot_silently_advance_to_v2(self) -> None:
        self.set_format_version(2)
        self.write_registry()

        self.assert_invalid(r"exact-current-only.*cannot declare sequenced version 2")

    def test_breaking_current_only_requires_prior_rejection_evidence(self) -> None:
        self.set_format_version(2)
        self.registry["formats"][0]["compatibility_policy"] = "breaking-current-only"
        self.write_registry()

        self.assert_invalid(
            r"breaking version 2 requires prior_version_rejections for \[1\]"
        )

    def test_breaking_current_only_with_complete_rejection_is_accepted(self) -> None:
        self.set_format_version(2)
        self.registry["formats"][0]["compatibility_policy"] = "breaking-current-only"
        self.registry["formats"][0]["prior_version_rejections"] = [
            self.prior_rejection(1)
        ]
        self.write_registry()

        governance.validate_repository(self.root)

    def test_breaking_rejection_inventory_must_cover_every_prior_version(self) -> None:
        self.set_format_version(3)
        self.registry["formats"][0]["compatibility_policy"] = "breaking-current-only"
        self.registry["formats"][0]["prior_version_rejections"] = [
            self.prior_rejection(1)
        ]
        self.write_registry()

        self.assert_invalid(
            r"prior_version_rejections must cover every rejected prior version: "
            r"expected \[1, 2\], found \[1\]"
        )

    def test_breaking_rejection_test_must_not_be_ignored(self) -> None:
        self.set_format_version(2)
        self.registry["formats"][0]["compatibility_policy"] = "breaking-current-only"
        self.registry["formats"][0]["prior_version_rejections"] = [
            self.prior_rejection(1, ignored=True)
        ]
        self.write_registry()

        self.assert_invalid(
            r"prior-version rejection test must not be ignored or cfg-gated"
        )

    def test_prior_rejection_raw_string_cannot_satisfy_evidence(self) -> None:
        self.set_format_version(2)
        self.registry["formats"][0]["compatibility_policy"] = "breaking-current-only"
        rejection = self.prior_rejection(1)
        test = self.root / "crates" / "automata-ci-core" / "tests" / "rejection.rs"
        test.write_text(
            "#[test]\nfn rejects_prior_v1() {\n"
            "    let bait = r#\"\n"
            "    let prior_version: u16 = 1;\n"
            "    assert!(decode_current(prior_version).is_err());\n"
            "    \"#;\n"
            "}\n",
            encoding="utf-8",
        )
        self.registry["formats"][0]["prior_version_rejections"] = [rejection]
        self.write_registry()

        self.assert_invalid(r"version must occur exactly once inside.*comments and literals")

    def test_prior_rejection_bindings_cannot_wrap_claimed_evidence_in_raw_strings(
        self,
    ) -> None:
        self.set_format_version(2)
        self.registry["formats"][0]["compatibility_policy"] = "breaking-current-only"
        rejection = self.prior_rejection(1)
        test = self.root / "crates" / "automata-ci-core" / "tests" / "rejection.rs"
        version_bait = 'let version_bait = r#"let prior_version: u16 = 1;"#;'
        call_bait = 'let call_bait = r#"decode_current(prior_version)"#;'
        outcome_bait = (
            'let outcome_bait = r#"assert!(decode_current(prior_version).is_err());"#;'
        )
        test.write_text(
            "#[test]\nfn rejects_prior_v1() {\n"
            f"    {version_bait}\n"
            f"    {call_bait}\n"
            f"    {outcome_bait}\n"
            "}\n",
            encoding="utf-8",
        )
        binding = rejection["tests"][0]
        binding["version"] = version_bait
        binding["reader_call"] = call_bait
        binding["outcome"] = outcome_bait
        self.registry["formats"][0]["prior_version_rejections"] = [rejection]
        self.write_registry()

        self.assert_invalid(r"version must bind prior version 1")

    def test_rejection_source_cannot_wrap_control_in_a_raw_string(self) -> None:
        self.set_format_version(2)
        self.registry["formats"][0]["compatibility_policy"] = "breaking-current-only"
        rejection = self.prior_rejection(1)
        bait = (
            'let bait = r#"if version != FORMAT_VERSION { return Err(()); }"#;'
        )
        source = self.root / "crates" / "automata-ci-core" / "src" / "version.rs"
        source.write_text(
            "pub const FORMAT_VERSION: u16 = 2;\n"
            "fn decode_current(_version: u16) -> Result<(), ()> {\n"
            f"    {bait}\n"
            "    Ok(())\n"
            "}\n",
            encoding="utf-8",
        )
        rejection["rejection"]["contains"] = bait
        self.registry["formats"][0]["prior_version_rejections"] = [rejection]
        self.write_registry()

        self.assert_invalid(r"rejection must contain executable fail-closed comparison")

    def test_prior_rejection_cannot_assert_acceptance(self) -> None:
        self.set_format_version(2)
        self.registry["formats"][0]["compatibility_policy"] = "breaking-current-only"
        rejection = self.prior_rejection(1)
        outcome = "assert!(decode_current(prior_version).is_ok());"
        test = self.root / "crates" / "automata-ci-core" / "tests" / "rejection.rs"
        test.write_text(
            "#[test]\nfn rejects_prior_v1() {\n"
            "    let prior_version: u16 = 1;\n"
            f"    {outcome}\n"
            "}\n",
            encoding="utf-8",
        )
        rejection["tests"][0]["outcome"] = outcome
        self.registry["formats"][0]["prior_version_rejections"] = [rejection]
        self.write_registry()

        self.assert_invalid(r"outcome must prove prior-version rejection")

    def test_module_raw_string_cannot_supply_rejection_function(self) -> None:
        self.set_format_version(2)
        self.registry["formats"][0]["compatibility_policy"] = "breaking-current-only"
        rejection = self.prior_rejection(1)
        source = self.root / "crates" / "automata-ci-core" / "src" / "version.rs"
        source.write_text(
            "pub const FORMAT_VERSION: u16 = 2;\n"
            'const BAIT: &str = r#"fn decode_current(version: u16) -> Result<(), ()> {\n'
            "    if version != FORMAT_VERSION { return Err(()); }\n"
            "    Ok(())\n"
            '}"#;\n',
            encoding="utf-8",
        )
        self.registry["formats"][0]["prior_version_rejections"] = [rejection]
        self.write_registry()

        self.assert_invalid(r"rejection.*fragment must occur exactly once.*outside comments")

    def test_breaking_rejection_requires_the_declared_reader_call(self) -> None:
        self.set_format_version(2)
        self.registry["formats"][0]["compatibility_policy"] = "breaking-current-only"
        rejection = self.prior_rejection(1)
        rejection["tests"][0]["reader_symbol"] = "decode_other"
        self.registry["formats"][0]["prior_version_rejections"] = [rejection]
        self.write_registry()

        self.assert_invalid(r"reader_call must invoke declared test reader 'decode_other'")

    def test_named_exact_current_protocol_cannot_silently_advance_to_v2(self) -> None:
        source = self.root / "crates" / "automata-ci-core" / "src" / "version.rs"
        source.write_text(
            'pub const FORMAT_VERSION: &str = "serve-v2";\n',
            encoding="utf-8",
        )
        self.registry["formats"][0]["sources"][0]["contains"] = (
            'pub const FORMAT_VERSION: &str = "serve-v2";'
        )
        self.registry["formats"][0]["version"] = "serve-v2"
        self.write_registry()

        self.assert_invalid(r"exact-current-only.*cannot declare sequenced version serve-v2")

    def test_versioned_media_token_cannot_silently_advance_to_v2(self) -> None:
        version = "application/vnd.example.contract.v2+json"
        source = self.root / "crates" / "automata-ci-core" / "src" / "version.rs"
        source.write_text(
            f'pub const FORMAT_VERSION: &str = "{version}";\n',
            encoding="utf-8",
        )
        self.registry["formats"][0]["sources"][0]["contains"] = (
            f'pub const FORMAT_VERSION: &str = "{version}";'
        )
        self.registry["formats"][0]["version"] = version
        self.write_registry()

        self.assert_invalid(r"exact-current-only.*cannot declare sequenced version.*v2\+json")

    def test_version_bump_without_prior_reader_is_rejected(self) -> None:
        self.set_format_version(2)
        self.registry["formats"][0]["compatibility_policy"] = "backward-compatible"
        self.write_registry()

        self.assert_invalid(r"version 2 requires prior_version_readers for \[1\]")

    def test_prior_reader_inventory_must_cover_every_older_version(self) -> None:
        self.set_format_version(3)
        self.registry["formats"][0]["compatibility_policy"] = "backward-compatible"
        self.registry["formats"][0]["prior_version_readers"] = [self.prior_reader(1)]
        self.write_registry()

        self.assert_invalid(
            r"prior_version_readers must cover every prior version: expected \[1, 2\], found \[1\]"
        )

    def test_prior_reader_test_must_not_be_ignored(self) -> None:
        self.set_format_version(2)
        self.registry["formats"][0]["compatibility_policy"] = "backward-compatible"
        self.registry["formats"][0]["prior_version_readers"] = [
            self.prior_reader(1, ignored=True)
        ]
        self.write_registry()

        self.assert_invalid(r"compatibility-reader test must not be ignored or cfg-gated")

    def test_prior_reader_test_must_not_be_empty(self) -> None:
        self.set_format_version(2)
        self.registry["formats"][0]["compatibility_policy"] = "backward-compatible"
        source = self.root / "crates" / "automata-ci-core" / "src" / "compatibility.rs"
        source.write_text(
            "fn decode_prior(version: u16) { if version == 1 {} }\n",
            encoding="utf-8",
        )
        test = self.root / "crates" / "automata-ci-core" / "tests" / "compatibility.rs"
        test.write_text("#[test]\nfn v1() {}\n", encoding="utf-8")
        self.registry["formats"][0]["prior_version_readers"] = [
            {
                "reader": {
                    "contains": "version == 1",
                    "path": "crates/automata-ci-core/src/compatibility.rs",
                    "symbol": "decode_prior",
                },
                "tests": [
                    {
                        "function": "v1",
                        "outcome": "assert!(decode_prior(prior_version).is_ok());",
                        "path": "crates/automata-ci-core/tests/compatibility.rs",
                        "reader_call": "decode_prior(prior_version)",
                        "version": "let prior_version: u16 = 1;",
                    }
                ],
                "version": 1,
            }
        ]
        self.write_registry()

        self.assert_invalid(
            r"version must occur exactly once inside the compatibility-reader test body"
        )

    def test_prior_reader_version_only_noop_cannot_satisfy_evidence(self) -> None:
        self.set_format_version(2)
        self.registry["formats"][0]["compatibility_policy"] = "backward-compatible"
        reader = self.prior_reader(1)
        test = self.root / "crates" / "automata-ci-core" / "tests" / "compatibility.rs"
        test.write_text(
            "#[test]\nfn reads_prior_v1() {\n"
            "    let prior_version: u16 = 1;\n"
            "}\n",
            encoding="utf-8",
        )
        self.registry["formats"][0]["prior_version_readers"] = [reader]
        self.write_registry()

        self.assert_invalid(r"reader_call must occur exactly once inside")

    def test_prior_reader_helper_outside_attributed_test_cannot_satisfy_evidence(self) -> None:
        self.set_format_version(2)
        self.registry["formats"][0]["compatibility_policy"] = "backward-compatible"
        reader = self.prior_reader(1)
        test = self.root / "crates" / "automata-ci-core" / "tests" / "compatibility.rs"
        test.write_text(
            "fn helper() { assert!(decode_prior(prior_version).is_ok()); }\n"
            "#[test]\nfn reads_prior_v1() {\n"
            "    let prior_version: u16 = 1;\n"
            "}\n",
            encoding="utf-8",
        )
        self.registry["formats"][0]["prior_version_readers"] = [reader]
        self.write_registry()

        self.assert_invalid(r"reader_call must occur exactly once inside")

    def test_prior_reader_comment_cannot_satisfy_call_or_outcome_evidence(self) -> None:
        self.set_format_version(2)
        self.registry["formats"][0]["compatibility_policy"] = "backward-compatible"
        reader = self.prior_reader(1)
        test = self.root / "crates" / "automata-ci-core" / "tests" / "compatibility.rs"
        test.write_text(
            "#[test]\nfn reads_prior_v1() {\n"
            "    let prior_version: u16 = 1;\n"
            "    // assert!(decode_prior(prior_version).is_ok());\n"
            "}\n",
            encoding="utf-8",
        )
        self.registry["formats"][0]["prior_version_readers"] = [reader]
        self.write_registry()

        self.assert_invalid(r"reader_call must occur exactly once inside.*outside comments")

    def test_prior_reader_raw_string_cannot_satisfy_evidence(self) -> None:
        self.set_format_version(2)
        self.registry["formats"][0]["compatibility_policy"] = "backward-compatible"
        reader = self.prior_reader(1)
        test = self.root / "crates" / "automata-ci-core" / "tests" / "compatibility.rs"
        test.write_text(
            "#[test]\nfn reads_prior_v1() {\n"
            "    let bait = r#\"\n"
            "    let prior_version: u16 = 1;\n"
            "    assert!(decode_prior(prior_version).is_ok());\n"
            "    \"#;\n"
            "}\n",
            encoding="utf-8",
        )
        self.registry["formats"][0]["prior_version_readers"] = [reader]
        self.write_registry()

        self.assert_invalid(r"version must occur exactly once inside.*comments and literals")

    def test_prior_reader_bindings_cannot_wrap_claimed_evidence_in_raw_strings(self) -> None:
        self.set_format_version(2)
        self.registry["formats"][0]["compatibility_policy"] = "backward-compatible"
        reader = self.prior_reader(1)
        test = self.root / "crates" / "automata-ci-core" / "tests" / "compatibility.rs"
        version_bait = 'let version_bait = r#"let prior_version: u16 = 1;"#;'
        call_bait = 'let call_bait = r#"decode_prior(prior_version)"#;'
        outcome_bait = (
            'let outcome_bait = r#"assert!(decode_prior(prior_version).is_ok());"#;'
        )
        test.write_text(
            "#[test]\nfn reads_prior_v1() {\n"
            f"    {version_bait}\n"
            f"    {call_bait}\n"
            f"    {outcome_bait}\n"
            "}\n",
            encoding="utf-8",
        )
        binding = reader["tests"][0]
        binding["version"] = version_bait
        binding["reader_call"] = call_bait
        binding["outcome"] = outcome_bait
        self.registry["formats"][0]["prior_version_readers"] = [reader]
        self.write_registry()

        self.assert_invalid(r"version must bind prior version 1")

    def test_prior_reader_call_must_be_nested_in_the_outcome_assertion(self) -> None:
        self.set_format_version(2)
        self.registry["formats"][0]["compatibility_policy"] = "backward-compatible"
        reader = self.prior_reader(1)
        outcome = "decode_prior(prior_version); assert!(true);"
        test = self.root / "crates" / "automata-ci-core" / "tests" / "compatibility.rs"
        test.write_text(
            "#[test]\nfn reads_prior_v1() {\n"
            "    let prior_version: u16 = 1;\n"
            f"    {outcome}\n"
            "}\n",
            encoding="utf-8",
        )
        reader["tests"][0]["outcome"] = outcome
        self.registry["formats"][0]["prior_version_readers"] = [reader]
        self.write_registry()

        self.assert_invalid(r"outcome must assert the declared reader_call result")

    def test_reader_status_cannot_be_bypassed_by_an_always_true_predicate(self) -> None:
        self.set_format_version(2)
        self.registry["formats"][0]["compatibility_policy"] = "backward-compatible"
        reader = self.prior_reader(1)
        outcome = "assert!(decode_prior(prior_version).is_ok() || true);"
        test = self.root / "crates" / "automata-ci-core" / "tests" / "compatibility.rs"
        test.write_text(
            "#[test]\nfn reads_prior_v1() {\n"
            "    let prior_version: u16 = 1;\n"
            f"    {outcome}\n"
            "}\n",
            encoding="utf-8",
        )
        reader["tests"][0]["outcome"] = outcome
        self.registry["formats"][0]["prior_version_readers"] = [reader]
        self.write_registry()

        self.assert_invalid(r"outcome must assert the declared reader_call result")

    def test_unused_prior_token_cannot_prove_reader_compatibility(self) -> None:
        self.set_format_version(2)
        self.registry["formats"][0]["compatibility_policy"] = "backward-compatible"
        reader = self.prior_reader(1)
        test = self.root / "crates" / "automata-ci-core" / "tests" / "compatibility.rs"
        test.write_text(
            "#[test]\nfn reads_prior_v1() {\n"
            "    let claimed_prior: u16 = 1;\n"
            "    let current_version: u16 = 2;\n"
            "    assert!(decode_prior(current_version).is_ok());\n"
            "}\n",
            encoding="utf-8",
        )
        binding = reader["tests"][0]
        binding["version"] = "let claimed_prior: u16 = 1;"
        binding["reader_call"] = "decode_prior(current_version)"
        binding["outcome"] = "assert!(decode_prior(current_version).is_ok());"
        self.registry["formats"][0]["prior_version_readers"] = [reader]
        self.write_registry()

        self.assert_invalid(r"version identifier 'claimed_prior' must flow into reader_call")

    def test_prior_identifier_noop_inside_reader_argument_does_not_prove_dataflow(
        self,
    ) -> None:
        self.set_format_version(2)
        self.registry["formats"][0]["compatibility_policy"] = "backward-compatible"
        reader = self.prior_reader(1)
        reader_call = "decode_prior({ let _ = prior_version; FORMAT_VERSION })"
        outcome = f"assert!({reader_call}.is_ok());"
        test = self.root / "crates" / "automata-ci-core" / "tests" / "compatibility.rs"
        test.write_text(
            "#[test]\nfn reads_prior_v1() {\n"
            "    let prior_version: u16 = 1;\n"
            f"    {outcome}\n"
            "}\n",
            encoding="utf-8",
        )
        binding = reader["tests"][0]
        binding["reader_call"] = reader_call
        binding["outcome"] = outcome
        self.registry["formats"][0]["prior_version_readers"] = [reader]
        self.write_registry()

        self.assert_invalid(r"version identifier 'prior_version' must flow into reader_call")

    def test_prior_version_input_cannot_use_the_token_as_a_noop_side_expression(
        self,
    ) -> None:
        self.set_format_version(2)
        self.registry["formats"][0]["compatibility_policy"] = "breaking-current-only"
        rejection = self.prior_rejection(1)
        version_input = "let document = { let _ = prior_version; current_version };"
        test = self.root / "crates" / "automata-ci-core" / "tests" / "rejection.rs"
        test.write_text(
            "#[test]\nfn rejects_prior_v1() {\n"
            "    let prior_version: u16 = 1;\n"
            "    let current_version: u16 = 2;\n"
            f"    {version_input}\n"
            "    assert!(decode_current(document).is_err());\n"
            "}\n",
            encoding="utf-8",
        )
        binding = rejection["tests"][0]
        binding["reader_call"] = "decode_current(document)"
        binding["outcome"] = "assert!(decode_current(document).is_err());"
        binding["version_input"] = {
            "contains": version_input,
            "identifier": "document",
            "reader_argument": 0,
        }
        self.registry["formats"][0]["prior_version_rejections"] = [rejection]
        self.write_registry()

        self.assert_invalid(r"version_input.contains value must be derived directly")

    def test_unrelated_success_marker_cannot_supply_reader_outcome_polarity(self) -> None:
        self.set_format_version(2)
        self.registry["formats"][0]["compatibility_policy"] = "backward-compatible"
        reader = self.prior_reader(1)
        outcome = (
            "assert!({ let _ = decode_prior(prior_version); "
            "Ok::<bool, ()>(true).is_ok() });"
        )
        test = self.root / "crates" / "automata-ci-core" / "tests" / "compatibility.rs"
        test.write_text(
            "#[test]\nfn reads_prior_v1() {\n"
            "    let prior_version: u16 = 1;\n"
            f"    {outcome}\n"
            "}\n",
            encoding="utf-8",
        )
        reader["tests"][0]["outcome"] = outcome
        self.registry["formats"][0]["prior_version_readers"] = [reader]
        self.write_registry()

        self.assert_invalid(r"outcome must assert the declared reader_call result")

    def test_unrelated_error_marker_cannot_supply_rejection_outcome_polarity(self) -> None:
        self.set_format_version(2)
        self.registry["formats"][0]["compatibility_policy"] = "breaking-current-only"
        rejection = self.prior_rejection(1)
        outcome = (
            "assert!({ let _ = decode_current(prior_version); "
            "Err::<bool, ()>(()).is_err() });"
        )
        test = self.root / "crates" / "automata-ci-core" / "tests" / "rejection.rs"
        test.write_text(
            "#[test]\nfn rejects_prior_v1() {\n"
            "    let prior_version: u16 = 1;\n"
            f"    {outcome}\n"
            "}\n",
            encoding="utf-8",
        )
        rejection["tests"][0]["outcome"] = outcome
        self.registry["formats"][0]["prior_version_rejections"] = [rejection]
        self.write_registry()

        self.assert_invalid(r"outcome must assert the declared reader_call is rejected")

    def test_compatibility_reader_cannot_assert_rejection(self) -> None:
        self.set_format_version(2)
        self.registry["formats"][0]["compatibility_policy"] = "backward-compatible"
        reader = self.prior_reader(1)
        outcome = "assert!(decode_prior(prior_version).is_err());"
        test = self.root / "crates" / "automata-ci-core" / "tests" / "compatibility.rs"
        test.write_text(
            "#[test]\nfn reads_prior_v1() {\n"
            "    let prior_version: u16 = 1;\n"
            f"    {outcome}\n"
            "}\n",
            encoding="utf-8",
        )
        reader["tests"][0]["outcome"] = outcome
        self.registry["formats"][0]["prior_version_readers"] = [reader]
        self.write_registry()

        self.assert_invalid(r"must prove successful prior-version reader acceptance")

    def test_module_raw_string_cannot_supply_prior_reader_function(self) -> None:
        self.set_format_version(2)
        self.registry["formats"][0]["compatibility_policy"] = "backward-compatible"
        reader = self.prior_reader(1)
        source = self.root / "crates" / "automata-ci-core" / "src" / "compatibility.rs"
        source.write_text(
            'const BAIT: &str = r#"fn decode_prior(version: u16) '
            '{ if version == 1 {} }"#;\n',
            encoding="utf-8",
        )
        self.registry["formats"][0]["prior_version_readers"] = [reader]
        self.write_registry()

        self.assert_invalid(r"reader.*fragment must occur exactly once.*outside comments")

    def test_prior_reader_evidence_cannot_call_a_different_reader(self) -> None:
        self.set_format_version(2)
        self.registry["formats"][0]["compatibility_policy"] = "backward-compatible"
        reader = self.prior_reader(1)
        binding = reader["tests"][0]
        binding["reader_call"] = "decode_something_else(prior_version)"
        binding["outcome"] = "assert!(decode_something_else(prior_version).is_ok());"
        self.registry["formats"][0]["prior_version_readers"] = [reader]
        self.write_registry()

        self.assert_invalid(r"reader_call must invoke declared reader 'decode_prior'")

    def test_bootstrap_registry_cannot_claim_active_enforcement(self) -> None:
        self.registry["status"] = "bootstrap"
        self.write_registry()

        self.assert_invalid(r"status must be 'active'")

    def test_registry_status_is_closed(self) -> None:
        self.registry["status"] = "retired"
        self.write_registry()

        self.assert_invalid(r"status must be 'active'")

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
            "assert!(!accept(MAX_TEST_ITEMS + 2));"
        )
        self.write_registry()

        self.assert_invalid(r"contains must occur exactly once")

    def test_boundary_bindings_must_be_distinct(self) -> None:
        at = self.registry["limits"][0]["boundary_tests"]["at"]
        self.registry["limits"][0]["boundary_tests"]["minus_one"] = dict(at)
        self.registry["limits"][0]["boundary_tests"]["plus_one"] = dict(at)
        self.write_registry()

        self.assert_invalid(r"must use three distinct bindings")

    def test_boundary_relations_accept_source_bound_local_initializers(self) -> None:
        test = self.root / "crates" / "automata-ci-runtime" / "tests" / "limits.rs"
        fragments = {
            "minus_one": "let minus_one = MAX_TEST_ITEMS - 1;",
            "at": "let at = MAX_TEST_ITEMS;",
            "plus_one": "let plus_one = MAX_TEST_ITEMS + 1;",
        }
        test.write_text(
            "#[test]\nfn test_limit_boundaries() {\n"
            f"    {fragments['minus_one']}\n"
            f"    {fragments['at']}\n"
            f"    {fragments['plus_one']}\n"
            "}\n",
            encoding="utf-8",
        )
        boundaries = self.registry["limits"][0]["boundary_tests"]
        for label, fragment in fragments.items():
            boundaries[label]["contains"] = fragment
        self.write_registry()

        governance.validate_repository(self.root)

    def test_minus_one_and_plus_one_boundary_evidence_cannot_be_swapped(self) -> None:
        boundaries = self.registry["limits"][0]["boundary_tests"]
        minus_one = dict(boundaries["minus_one"])
        plus_one = dict(boundaries["plus_one"])
        boundaries["minus_one"] = plus_one
        boundaries["plus_one"] = minus_one
        self.write_registry()

        self.assert_invalid(
            r"boundary_tests.minus_one.contains must bind MAX_TEST_ITEMS at offset -1"
        )

    def test_minus_one_and_at_boundary_evidence_cannot_be_swapped(self) -> None:
        boundaries = self.registry["limits"][0]["boundary_tests"]
        minus_one = dict(boundaries["minus_one"])
        at = dict(boundaries["at"])
        boundaries["minus_one"] = at
        boundaries["at"] = minus_one
        self.write_registry()

        self.assert_invalid(
            r"boundary_tests.minus_one.contains must bind MAX_TEST_ITEMS at offset -1"
        )

    def test_three_distinct_but_mislabeled_boundary_bindings_are_rejected(self) -> None:
        boundaries = self.registry["limits"][0]["boundary_tests"]
        minus_one = dict(boundaries["minus_one"])
        at = dict(boundaries["at"])
        plus_one = dict(boundaries["plus_one"])
        boundaries["minus_one"] = plus_one
        boundaries["at"] = minus_one
        boundaries["plus_one"] = at
        self.write_registry()

        self.assert_invalid(
            r"boundary_tests.minus_one.contains must bind MAX_TEST_ITEMS at offset -1"
        )

    def test_boundary_relation_must_cover_the_complete_arithmetic_expression(self) -> None:
        test = self.root / "crates" / "automata-ci-runtime" / "tests" / "limits.rs"
        misleading = "assert!(accept(MAX_TEST_ITEMS - 1 + 100));"
        test.write_text(
            test.read_text(encoding="utf-8").replace(
                "assert!(accept(MAX_TEST_ITEMS - 1));",
                misleading,
            ),
            encoding="utf-8",
        )
        self.registry["limits"][0]["boundary_tests"]["minus_one"]["contains"] = (
            misleading
        )
        self.write_registry()

        self.assert_invalid(r"minus_one.contains must bind MAX_TEST_ITEMS at offset -1")

    def test_boundary_relation_cannot_use_a_decoy_statement(self) -> None:
        test = self.root / "crates" / "automata-ci-runtime" / "tests" / "limits.rs"
        misleading = (
            "assert!(accept(MAX_TEST_ITEMS + 99)); "
            "let bait = MAX_TEST_ITEMS - 1;"
        )
        test.write_text(
            test.read_text(encoding="utf-8").replace(
                "assert!(accept(MAX_TEST_ITEMS - 1));",
                misleading,
            ),
            encoding="utf-8",
        )
        self.registry["limits"][0]["boundary_tests"]["minus_one"]["contains"] = (
            misleading
        )
        self.write_registry()

        self.assert_invalid(r"minus_one.contains must be one boundary expression")

    def test_comment_only_boundary_evidence_is_rejected(self) -> None:
        test = self.root / "crates" / "automata-ci-runtime" / "tests" / "limits.rs"
        test.write_text(
            "#[test]\nfn test_limit_boundaries() {\n"
            "    assert!(accept(MAX_TEST_ITEMS - 1));\n"
            "    assert!(accept(MAX_TEST_ITEMS));\n"
            "    // assert!(!accept(MAX_TEST_ITEMS + 1));\n"
            "}\n",
            encoding="utf-8",
        )

        self.assert_invalid(r"plus_one.contains must occur exactly once.*outside comments")

    def test_raw_string_only_boundary_evidence_is_rejected(self) -> None:
        test = self.root / "crates" / "automata-ci-runtime" / "tests" / "limits.rs"
        test.write_text(
            "#[test]\nfn test_limit_boundaries() {\n"
            "    let bait = r#\"\n"
            "    assert!(accept(MAX_TEST_ITEMS - 1));\n"
            "    assert!(accept(MAX_TEST_ITEMS));\n"
            "    assert!(!accept(MAX_TEST_ITEMS + 1));\n"
            "    \"#;\n"
            "}\n",
            encoding="utf-8",
        )

        self.assert_invalid(
            r"minus_one.contains must occur exactly once.*outside comments and literals"
        )

    def test_raw_string_only_boundary_alias_is_rejected(self) -> None:
        test = self.root / "crates" / "automata-ci-runtime" / "tests" / "limits.rs"
        test.write_text(
            "#[test]\nfn test_limit_boundaries() {\n"
            '    let bait = r#"let boundary = MAX_TEST_ITEMS;"#;\n'
            "    assert!(accept(boundary - 1));\n"
            "    assert!(accept(boundary));\n"
            "    assert!(!accept(boundary + 1));\n"
            "}\n",
            encoding="utf-8",
        )
        boundaries = self.registry["limits"][0]["boundary_tests"]
        boundaries["minus_one"]["contains"] = "assert!(accept(boundary - 1));"
        boundaries["at"]["contains"] = "assert!(accept(boundary));"
        boundaries["plus_one"]["contains"] = "assert!(!accept(boundary + 1));"
        boundaries["value_alias"] = {
            "contains": "let boundary = MAX_TEST_ITEMS;",
            "identifier": "boundary",
        }
        self.write_registry()

        self.assert_invalid(
            r"value_alias.contains must occur exactly once.*outside comments and literals"
        )

    def test_raw_string_only_successor_base_is_rejected(self) -> None:
        test = self.root / "crates" / "automata-ci-runtime" / "tests" / "limits.rs"
        test.write_text(
            "#[test]\nfn test_limit_boundaries() {\n"
            "    assert!(accept(MAX_TEST_ITEMS - 1));\n"
            "    assert!(accept(MAX_TEST_ITEMS));\n"
            '    let bait = r#"assert_eq!(budget.len(), MAX_TEST_ITEMS);"#;\n'
            "    assert!(!budget.enter());\n"
            "}\n",
            encoding="utf-8",
        )
        plus_one = self.registry["limits"][0]["boundary_tests"]["plus_one"]
        plus_one["contains"] = "assert!(!budget.enter());"
        plus_one["relation"] = {
            "base": "assert_eq!(budget.len(), MAX_TEST_ITEMS);",
            "kind": "successor-attempt",
            "operation": "budget.enter",
        }
        self.write_registry()

        self.assert_invalid(
            r"relation.base must be a distinct fragment occurring exactly once.*literals"
        )

    def test_boundary_value_alias_is_source_bound(self) -> None:
        test = self.root / "crates" / "automata-ci-runtime" / "tests" / "limits.rs"
        test.write_text(
            "#[test]\nfn test_limit_boundaries() {\n"
            "    let boundary = MAX_TEST_ITEMS;\n"
            "    assert!(accept(boundary - 1));\n"
            "    assert!(accept(boundary));\n"
            "    assert!(!accept(boundary + 1));\n"
            "}\n",
            encoding="utf-8",
        )
        boundaries = self.registry["limits"][0]["boundary_tests"]
        boundaries["minus_one"]["contains"] = "assert!(accept(boundary - 1));"
        boundaries["at"]["contains"] = "assert!(accept(boundary));"
        boundaries["plus_one"]["contains"] = "assert!(!accept(boundary + 1));"
        boundaries["value_alias"] = {
            "contains": "let boundary = MAX_TEST_ITEMS;",
            "identifier": "boundary",
        }
        self.write_registry()

        governance.validate_repository(self.root)

        shadowed = (
            "let boundary = MAX_TEST_ITEMS;\n"
            "    let boundary = MAX_TEST_ITEMS + 1;"
        )
        test.write_text(
            test.read_text(encoding="utf-8").replace(
                "let boundary = MAX_TEST_ITEMS;", shadowed
            ),
            encoding="utf-8",
        )

        self.assert_invalid(r"value_alias identifier 'boundary' must not be shadowed")

        test.write_text(
            test.read_text(encoding="utf-8").replace(
                shadowed, "let boundary = MAX_TEST_ITEMS;"
            ),
            encoding="utf-8",
        )
        mismatched = "let boundary = MAX_TEST_ITEMS + 1;"
        test.write_text(
            test.read_text(encoding="utf-8").replace(
                "let boundary = MAX_TEST_ITEMS;", mismatched
            ),
            encoding="utf-8",
        )
        boundaries["value_alias"]["contains"] = mismatched
        self.write_registry()

        self.assert_invalid(r"value_alias.contains must bind 'boundary' exactly")

    def test_boundary_value_alias_cannot_be_shadowed_by_a_for_pattern(self) -> None:
        test = self.root / "crates" / "automata-ci-runtime" / "tests" / "limits.rs"
        test.write_text(
            "#[test]\nfn test_limit_boundaries() {\n"
            "    let boundary = MAX_TEST_ITEMS;\n"
            "    assert!(accept(boundary - 1));\n"
            "    for boundary in [0] { assert!(accept(boundary)); }\n"
            "    assert!(!accept(boundary + 1));\n"
            "}\n",
            encoding="utf-8",
        )
        boundaries = self.registry["limits"][0]["boundary_tests"]
        boundaries["minus_one"]["contains"] = "assert!(accept(boundary - 1));"
        boundaries["at"]["contains"] = "assert!(accept(boundary));"
        boundaries["plus_one"]["contains"] = "assert!(!accept(boundary + 1));"
        boundaries["value_alias"] = {
            "contains": "let boundary = MAX_TEST_ITEMS;",
            "identifier": "boundary",
        }
        self.write_registry()

        self.assert_invalid(r"value_alias identifier 'boundary' must not be shadowed")

    def test_boundary_value_alias_cannot_hide_a_second_statement(self) -> None:
        test = self.root / "crates" / "automata-ci-runtime" / "tests" / "limits.rs"
        alias = "let boundary = MAX_TEST_ITEMS; let boundary = 999;"
        test.write_text(
            "#[test]\nfn test_limit_boundaries() {\n"
            f"    {alias}\n"
            "    assert!(accept(boundary - 1));\n"
            "    assert!(accept(boundary));\n"
            "    assert!(!accept(boundary + 1));\n"
            "}\n",
            encoding="utf-8",
        )
        boundaries = self.registry["limits"][0]["boundary_tests"]
        boundaries["minus_one"]["contains"] = "assert!(accept(boundary - 1));"
        boundaries["at"]["contains"] = "assert!(accept(boundary));"
        boundaries["plus_one"]["contains"] = "assert!(!accept(boundary + 1));"
        boundaries["value_alias"] = {
            "contains": alias,
            "identifier": "boundary",
        }
        self.write_registry()

        self.assert_invalid(r"value_alias.contains must be the immutable alias declaration")

    def test_successor_attempt_relation_requires_source_bound_at_evidence(self) -> None:
        test = self.root / "crates" / "automata-ci-runtime" / "tests" / "limits.rs"
        test.write_text(
            "#[test]\nfn test_limit_boundaries() {\n"
            "    assert!(accept(MAX_TEST_ITEMS - 1));\n"
            "    assert_eq!(budget.len(), MAX_TEST_ITEMS);\n"
            "    assert!(!budget.enter());\n"
            "}\n",
            encoding="utf-8",
        )
        boundaries = self.registry["limits"][0]["boundary_tests"]
        boundaries["at"]["contains"] = "assert_eq!(budget.len(), MAX_TEST_ITEMS);"
        plus_one = boundaries["plus_one"]
        plus_one["contains"] = "assert!(!budget.enter());"
        plus_one["relation"] = {
            "base": "assert_eq!(budget.len(), MAX_TEST_ITEMS);",
            "kind": "successor-attempt",
            "operation": "budget.enter",
        }
        self.write_registry()

        governance.validate_repository(self.root)

        test.write_text(
            test.read_text(encoding="utf-8").replace(
                "assert!(!budget.enter());", "assert!(true);"
            ),
            encoding="utf-8",
        )
        plus_one["contains"] = "assert!(true);"
        self.write_registry()

        self.assert_invalid(r"must negatively assert.*'budget.enter'")

        test.write_text(
            test.read_text(encoding="utf-8").replace(
                "assert!(true);", "assert!(!budget.enter());"
            ),
            encoding="utf-8",
        )
        plus_one["contains"] = "assert!(!budget.enter());"
        plus_one["relation"]["base"] = "assert!(accept(MAX_TEST_ITEMS - 1));"
        self.write_registry()

        self.assert_invalid(r"relation.base must bind the declared at-limit value")

    def test_successor_base_must_tie_the_same_receiver_to_the_limit(self) -> None:
        test = self.root / "crates" / "automata-ci-runtime" / "tests" / "limits.rs"
        base = "assert_eq!(other.len(), MAX_TEST_ITEMS); let _ = &budget;"
        test.write_text(
            "#[test]\nfn test_limit_boundaries() {\n"
            "    assert!(accept(MAX_TEST_ITEMS - 1));\n"
            f"    {base}\n"
            "    assert!(!budget.enter());\n"
            "}\n",
            encoding="utf-8",
        )
        boundaries = self.registry["limits"][0]["boundary_tests"]
        boundaries["at"]["contains"] = base
        plus_one = boundaries["plus_one"]
        plus_one["contains"] = "assert!(!budget.enter());"
        plus_one["relation"] = {
            "base": base,
            "kind": "successor-attempt",
            "operation": "budget.enter",
        }
        self.write_registry()

        self.assert_invalid(r"at.contains must be one boundary expression")

    def test_successor_receiver_cannot_be_rebound_after_the_at_limit_base(self) -> None:
        test = self.root / "crates" / "automata-ci-runtime" / "tests" / "limits.rs"
        base = "assert_eq!(budget.len(), MAX_TEST_ITEMS);"
        successor = "assert!(!budget.enter());"
        test.write_text(
            "#[test]\nfn test_limit_boundaries() {\n"
            "    assert!(accept(MAX_TEST_ITEMS - 1));\n"
            f"    {base}\n"
            f"    for budget in budgets {{ {successor} }}\n"
            "}\n",
            encoding="utf-8",
        )
        boundaries = self.registry["limits"][0]["boundary_tests"]
        boundaries["at"]["contains"] = base
        plus_one = boundaries["plus_one"]
        plus_one["contains"] = successor
        plus_one["relation"] = {
            "base": base,
            "kind": "successor-attempt",
            "operation": "budget.enter",
        }
        self.write_registry()

        self.assert_invalid(r"operation receiver 'budget' must not be rebound")

    def test_successor_attempt_must_be_the_entire_negative_predicate(self) -> None:
        test = self.root / "crates" / "automata-ci-runtime" / "tests" / "limits.rs"
        test.write_text(
            "#[test]\nfn test_limit_boundaries() {\n"
            "    assert!(accept(MAX_TEST_ITEMS - 1));\n"
            "    assert_eq!(budget.len(), MAX_TEST_ITEMS);\n"
            "    assert!(!budget.enter() || true);\n"
            "}\n",
            encoding="utf-8",
        )
        boundaries = self.registry["limits"][0]["boundary_tests"]
        boundaries["at"]["contains"] = "assert_eq!(budget.len(), MAX_TEST_ITEMS);"
        plus_one = boundaries["plus_one"]
        plus_one["contains"] = "assert!(!budget.enter() || true);"
        plus_one["relation"] = {
            "base": "assert_eq!(budget.len(), MAX_TEST_ITEMS);",
            "kind": "successor-attempt",
            "operation": "budget.enter",
        }
        self.write_registry()

        self.assert_invalid(r"must negatively assert only.*'budget.enter'")

    def test_boundary_fragment_cannot_live_in_a_following_helper(self) -> None:
        test = self.root / "crates" / "automata-ci-runtime" / "tests" / "limits.rs"
        test.write_text(
            "#[test]\nfn test_limit_boundaries() {}\n"
            "fn helper() {\n"
            "    assert!(accept(MAX_TEST_ITEMS - 1));\n"
            "    assert!(accept(MAX_TEST_ITEMS));\n"
            "    assert!(!accept(MAX_TEST_ITEMS + 1));\n"
            "}\n",
            encoding="utf-8",
        )

        self.assert_invalid(r"contains must occur exactly once")

    def test_format_test_must_be_an_attributed_test_function(self) -> None:
        test = self.root / "crates" / "automata-ci-core" / "tests" / "version.rs"
        test.write_text("fn exact_current_version_is_accepted() {}\n", encoding="utf-8")

        self.assert_invalid(r"names missing test function 'exact_current_version_is_accepted'")

    def test_module_raw_string_cannot_supply_an_entire_format_test(self) -> None:
        test = self.root / "crates" / "automata-ci-core" / "tests" / "version.rs"
        test.write_text(
            'const BAIT: &str = r#"\n'
            "#[test]\nfn exact_current_version_is_accepted() {\n"
            "    assert!(decode(FORMAT_VERSION + 1).is_err());\n"
            "}\n"
            '"#;\n',
            encoding="utf-8",
        )

        self.assert_invalid(r"names missing test function 'exact_current_version_is_accepted'")

    def test_in_test_raw_string_cannot_supply_current_format_evidence(self) -> None:
        test = self.root / "crates" / "automata-ci-core" / "tests" / "version.rs"
        test.write_text(
            "#[test]\nfn exact_current_version_is_accepted() {\n"
            '    let bait = r#"assert!(decode(FORMAT_VERSION + 1).is_err());"#;\n'
            "}\n",
            encoding="utf-8",
        )

        self.assert_invalid(r"contains must occur exactly once.*outside comments and literals")

    def test_format_binding_cannot_wrap_claimed_evidence_in_a_raw_string(self) -> None:
        test = self.root / "crates" / "automata-ci-core" / "tests" / "version.rs"
        bait = (
            'let bait = r#"assert!(decode(FORMAT_VERSION + 1).is_err());"#;'
        )
        test.write_text(
            "#[test]\nfn exact_current_version_is_accepted() {\n"
            f"    {bait}\n"
            "}\n",
            encoding="utf-8",
        )
        self.registry["formats"][0]["tests"][0]["contains"] = bait
        self.write_registry()

        self.assert_invalid(r"claimed evidence exists only inside a literal")

    def test_format_binding_cannot_widen_literal_evidence_with_wrapper_tokens(self) -> None:
        claimed = "assert!(decode(FORMAT_VERSION + 1).is_err());"
        wrappers = (
            f'let bait = (r#"{claimed}"#, 0);',
            f'let bait = Some(r#"{claimed}"#);',
            f'std::hint::black_box(r#"{claimed}"#);',
        )
        test = self.root / "crates" / "automata-ci-core" / "tests" / "version.rs"
        for wrapper in wrappers:
            with self.subTest(wrapper=wrapper):
                test.write_text(
                    "#[test]\nfn exact_current_version_is_accepted() {\n"
                    f"    {wrapper}\n"
                    "}\n",
                    encoding="utf-8",
                )
                self.registry["formats"][0]["tests"][0]["contains"] = wrapper
                self.write_registry()

                self.assert_invalid(r"claimed evidence exists only inside a literal")

    def test_format_test_must_bind_its_declared_evidence(self) -> None:
        self.registry["formats"][0]["tests"][0]["contains"] = "assert!(false);"
        self.write_registry()

        self.assert_invalid(r"contains must occur exactly once")

    def test_typescript_format_test_must_be_registered_and_bind_evidence(self) -> None:
        test = self.root / "ui" / "tests" / "format.test.ts"
        test.parent.mkdir(parents=True, exist_ok=True)
        body = (
            "function rejects_forward_schema(): void {\n"
            "  set_version(input, 2);\n"
            "  expect(() => decode(input)).toThrow();\n"
            "}\n"
        )
        test.write_text(
            'import { expect, it } from "vitest";\n'
            + body
            + 'it("rejects forward schema", rejects_forward_schema);\n',
            encoding="utf-8",
        )
        self.registry["formats"][0]["tests"] = [
            {
                "contains": "set_version(input, 2);",
                "function": "rejects_forward_schema",
                "path": "ui/tests/format.test.ts",
            }
        ]
        self.write_registry()
        governance.validate_repository(self.root)

        test.write_text(body, encoding="utf-8")
        self.assert_invalid(r"missing TypeScript test function 'rejects_forward_schema'")

    def test_typescript_template_cannot_supply_test_declaration_or_evidence(self) -> None:
        test = self.root / "ui" / "tests" / "format.test.ts"
        test.parent.mkdir(parents=True, exist_ok=True)
        test.write_text(
            "const bait = `function rejects_forward_schema(): void {\n"
            "  set_version(input, 2);\n"
            "}`;\n"
            "function rejects_forward_schema(): void {}\n"
            'it("rejects forward schema", rejects_forward_schema);\n',
            encoding="utf-8",
        )
        self.registry["formats"][0]["tests"] = [
            {
                "contains": "set_version(input, 2);",
                "function": "rejects_forward_schema",
                "path": "ui/tests/format.test.ts",
            }
        ]
        self.write_registry()

        self.assert_invalid(r"contains must occur exactly once.*outside comments and literals")

    def test_typescript_template_cannot_supply_test_registration(self) -> None:
        test = self.root / "ui" / "tests" / "format.test.ts"
        test.parent.mkdir(parents=True, exist_ok=True)
        test.write_text(
            "function rejects_forward_schema(): void {\n"
            "  set_version(input, 2);\n"
            "}\n"
            'const bait = `it("rejects forward schema", rejects_forward_schema);`;\n',
            encoding="utf-8",
        )
        self.registry["formats"][0]["tests"] = [
            {
                "contains": "set_version(input, 2);",
                "function": "rejects_forward_schema",
                "path": "ui/tests/format.test.ts",
            }
        ]
        self.write_registry()

        self.assert_invalid(r"missing TypeScript test function 'rejects_forward_schema'")

    def test_typescript_registration_cannot_cross_into_a_later_literal(self) -> None:
        test = self.root / "ui" / "tests" / "format.test.ts"
        test.parent.mkdir(parents=True, exist_ok=True)
        test.write_text(
            "function rejects_forward_schema(): void {\n"
            "  set_version(input, 2);\n"
            "}\n"
            'it("different callback", other);\n'
            'const bait = ", rejects_forward_schema)";\n',
            encoding="utf-8",
        )
        self.registry["formats"][0]["tests"] = [
            {
                "contains": "set_version(input, 2);",
                "function": "rejects_forward_schema",
                "path": "ui/tests/format.test.ts",
            }
        ]
        self.write_registry()

        self.assert_invalid(r"missing TypeScript test function 'rejects_forward_schema'")

    def test_typescript_regex_literal_cannot_supply_test_registration(self) -> None:
        test = self.root / "ui" / "tests" / "format.test.ts"
        test.parent.mkdir(parents=True, exist_ok=True)
        test.write_text(
            "function rejects_forward_schema(): void {\n"
            "  set_version(input, 2);\n"
            "}\n"
            "const bait = /it(, rejects_forward_schema)/;\n",
            encoding="utf-8",
        )
        self.registry["formats"][0]["tests"] = [
            {
                "contains": "set_version(input, 2);",
                "function": "rejects_forward_schema",
                "path": "ui/tests/format.test.ts",
            }
        ]
        self.write_registry()

        self.assert_invalid(r"missing TypeScript test function 'rejects_forward_schema'")

    def test_typescript_template_cannot_supply_in_test_evidence(self) -> None:
        test = self.root / "ui" / "tests" / "format.test.ts"
        test.parent.mkdir(parents=True, exist_ok=True)
        test.write_text(
            "function rejects_forward_schema(): void {\n"
            "  const bait = `set_version(input, 2);`;\n"
            "}\n"
            'it("rejects forward schema", rejects_forward_schema);\n',
            encoding="utf-8",
        )
        self.registry["formats"][0]["tests"] = [
            {
                "contains": "set_version(input, 2);",
                "function": "rejects_forward_schema",
                "path": "ui/tests/format.test.ts",
            }
        ]
        self.write_registry()

        self.assert_invalid(r"contains must occur exactly once.*outside comments and literals")

    def test_github_limit_inventory_must_remain_complete(self) -> None:
        self.registry["github_limits"].pop()
        self.write_registry()

        self.assert_invalid(r"GitHub limits inventory is incomplete")

    def test_implemented_github_limit_must_bind_exact_enforcement(self) -> None:
        contract = self.registry["github_limits"][0]
        contract["automata"] = {
            "enforcement_phase": "runtime",
            "limit_id": "test.limit",
            "reason_code": "TestLimitError::Different",
            "relation": {"kind": "exact", "offset": 0, "unit": "items"},
            "status": "implemented",
        }
        self.write_registry()

        self.assert_invalid(r"reason code differs from its implemented limit")

    def test_implemented_github_limit_must_bind_exact_value_relation(self) -> None:
        contract = self.registry["github_limits"][0]
        contract["automata"] = {
            "enforcement_phase": "runtime",
            "limit_id": "test.limit",
            "reason_code": "TestLimitError::Exceeded",
            "relation": {"kind": "exact", "offset": 0, "unit": "items"},
            "status": "implemented",
        }
        contract["value"] = 4
        self.registry["limits"][0]["classification"] = "github"
        self.write_registry()

        self.assert_invalid(r"value relation does not match its implemented limit")

    def test_implemented_github_limit_must_bind_exact_unit(self) -> None:
        contract = self.registry["github_limits"][0]
        contract["automata"] = {
            "enforcement_phase": "runtime",
            "limit_id": "test.limit",
            "reason_code": "TestLimitError::Exceeded",
            "relation": {"kind": "exact", "offset": 0, "unit": "bytes"},
            "status": "implemented",
        }
        self.registry["limits"][0]["classification"] = "github"
        self.write_registry()

        self.assert_invalid(r"relation unit differs from its implemented limit")

    def test_every_github_classified_limit_requires_reverse_mapping(self) -> None:
        self.registry["limits"][0]["classification"] = "github"
        self.write_registry()

        self.assert_invalid(r"GitHub-classified Automata limits require exact reverse mappings")

    def test_github_limit_source_must_be_pinned_as_a_limits_reference(self) -> None:
        self.registry["github_limits"][0]["source_reference"] = "unreviewed-limits"
        self.write_registry()

        self.assert_invalid(r"is not a pinned limits reference")

    def test_unknown_schema_key_is_rejected(self) -> None:
        self.registry["limits"][0]["unexpected"] = True
        self.write_registry()

        self.assert_invalid(r"limits\[0\] has invalid keys.*unknown \['unexpected'\]")

    def test_stringify_macro_cannot_supply_generic_test_evidence(self) -> None:
        test = self.root / "crates" / "automata-ci-core" / "tests" / "version.rs"
        test.write_text(
            "#[test]\nfn exact_current_version_is_accepted() {\n"
            "    stringify!(assert!(decode(FORMAT_VERSION + 1).is_err()));\n"
            "}\n",
            encoding="utf-8",
        )
        self.write_registry()

        self.assert_invalid(r"contains must occur exactly once.*outside comments and literals")

    def test_stringify_macro_cannot_supply_limit_alias_coverage(self) -> None:
        self.add_limit_alias()
        test = self.root / "crates" / "automata-ci-runtime" / "tests" / "limits.rs"
        test.write_text(
            test.read_text(encoding="utf-8").replace(
                "assert_eq!(TEST_ITEM_CENSUS_LIMIT, MAX_TEST_ITEMS + 1);",
                "stringify!(TEST_ITEM_CENSUS_LIMIT);\n    assert!(true);",
            ),
            encoding="utf-8",
        )
        self.registry["limit_aliases"][0]["tests"][0]["contains"] = "assert!(true);"
        self.write_registry()

        self.assert_invalid(r"tests do not exercise the alias source")

    def test_stringify_macro_cannot_supply_operational_limit_use(self) -> None:
        source = self.root / "crates" / "automata-ci-runtime" / "src" / "retry.rs"
        binding = "stringify!(MAX_RETRY_ATTEMPTS);"
        source.write_text(
            "const MAX_RETRY_ATTEMPTS: usize = 3;\n"
            f"fn retry() {{ {binding} }}\n",
            encoding="utf-8",
        )
        self.registry["limit_exclusions"] = [
            {
                "classification": "operational",
                "constants": ["MAX_RETRY_ATTEMPTS"],
                "owner": "integration",
                "path": "crates/automata-ci-runtime/src/retry.rs",
                "phase": "runtime",
                "reason": "Internal retry budget, not a GitHub-visible compatibility limit.",
                "uses": [
                    {
                        "constant": "MAX_RETRY_ATTEMPTS",
                        "contains": binding,
                        "path": "crates/automata-ci-runtime/src/retry.rs",
                    }
                ],
            }
        ]
        self.write_registry()

        self.assert_invalid(r"must bind at least one executable production use")

    def test_arbitrary_acceptance_macro_cannot_prove_prior_reader_outcome(self) -> None:
        self.set_format_version(2)
        self.registry["formats"][0]["compatibility_policy"] = "backward-compatible"
        reader = self.prior_reader(1)
        outcome = "assert_accepts!(decode_prior(prior_version), false);"
        test = self.root / "crates" / "automata-ci-core" / "tests" / "compatibility.rs"
        test.write_text(
            "macro_rules! assert_accepts { ($reader:expr, $value:expr) => "
            "{ assert!(!$value) } }\n"
            "#[test]\nfn reads_prior_v1() {\n"
            "    let prior_version: u16 = 1;\n"
            f"    {outcome}\n"
            "}\n",
            encoding="utf-8",
        )
        reader["tests"][0]["outcome"] = outcome
        self.registry["formats"][0]["prior_version_readers"] = [reader]
        self.write_registry()

        self.assert_invalid(r"outcome must assert the declared reader_call result")

    def test_typed_reason_decoy_cannot_bind_the_emitted_variant(self) -> None:
        source = self.root / "crates" / "automata-ci-runtime" / "src" / "limits.rs"
        fragment = (
            "let _ = TestLimitError::Exceeded; "
            "return Err(TestLimitError::Different);"
        )
        source.write_text(
            "pub const MAX_TEST_ITEMS: usize = 5;\n" + fragment + "\n",
            encoding="utf-8",
        )
        self.registry["limits"][0]["reason_source"]["contains"] = fragment
        self.write_registry()

        self.assert_invalid(r"reason_source does not bind declared reason code")

    def test_boundary_relation_cannot_live_in_an_unrelated_boolean_branch(self) -> None:
        test = self.root / "crates" / "automata-ci-runtime" / "tests" / "limits.rs"
        attack = (
            "assert!(accept(0) || black_box(MAX_TEST_ITEMS - 1) == 999);"
        )
        test.write_text(
            test.read_text(encoding="utf-8").replace(
                "assert!(accept(MAX_TEST_ITEMS - 1));", attack
            ),
            encoding="utf-8",
        )
        self.registry["limits"][0]["boundary_tests"]["minus_one"]["contains"] = attack
        self.write_registry()

        self.assert_invalid(r"minus_one.contains must bind MAX_TEST_ITEMS at offset -1")

    def test_production_capable_tests_module_remains_in_format_census(self) -> None:
        crate = self.root / "crates" / "new-derived-adapter" / "src"
        crate.mkdir(parents=True)
        (crate / "lib.rs").write_text(
            "#[cfg(any(test, unix))]\nmod tests;\n",
            encoding="utf-8",
        )
        (crate / "tests.rs").write_text(
            "pub const LIVE_WIRE_SCHEMA_VERSION: u16 = 1;\n",
            encoding="utf-8",
        )

        self.assert_invalid(r"unregistered format declarations.*LIVE_WIRE_SCHEMA_VERSION")

    def test_transforming_const_function_cannot_bind_declared_version(self) -> None:
        declaration = "pub const FORMAT_VERSION: u16 = predecessor(1);"
        source = self.root / "crates" / "automata-ci-core" / "src" / "version.rs"
        source.write_text(
            "const fn predecessor(value: u16) -> u16 { value - 1 }\n"
            + declaration
            + "\n",
            encoding="utf-8",
        )
        self.registry["formats"][0]["sources"][0]["contains"] = declaration
        self.write_registry()

        self.assert_invalid(r"does not bind declared version 1")

    def test_nonzero_decoy_inside_block_initializer_cannot_bind_limit(self) -> None:
        declaration = (
            "pub const MAX_TEST_ITEMS: usize = { "
            "let _ = NonZeroU16::MIN; 2 };"
        )
        source = self.root / "crates" / "automata-ci-runtime" / "src" / "limits.rs"
        source.write_text(
            declaration + "\nreturn Err(TestLimitError::Exceeded);\n",
            encoding="utf-8",
        )
        self.registry["limits"][0]["source"]["contains"] = declaration
        self.registry["limits"][0]["value"] = 1
        self.write_registry()

        self.assert_invalid(r"source does not bind declared value 1")

    def test_named_version_helper_body_must_construct_the_declared_value(self) -> None:
        source = self.root / "crates" / "automata-ci-core" / "src" / "version.rs"
        source.write_text(
            "struct FormatVersion(u16);\n"
            "impl FormatVersion {\n"
            "    pub const fn v1() -> Self { Self(2) }\n"
            "    pub const fn current() -> Self { Self::v1() }\n"
            "}\n",
            encoding="utf-8",
        )
        self.registry["formats"][0]["sources"][0]["contains"] = "Self::v1()"
        self.write_registry()

        self.assert_invalid(r"does not bind declared version 1")


if __name__ == "__main__":
    unittest.main()
