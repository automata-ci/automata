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
                "// foundation-governance: parity-limit\n"
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
            "crates/automata-ci-store/migrations/0001_initial_schema.sql": "SELECT 1;\n",
        }
        for relative, contents in files.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")

        self.registry = {
            "derived_contract_exclusions": [],
            "derived_contract_registry": {
                "annotation": (
                    "foundation-governance: derived-contract "
                    "owner=<owner> kind=<kind>"
                ),
                "declaration_roots": ["crates/*/src/**/*.rs"],
                "evolution_policy": "append-only-token-or-coordinated-migration",
                "includes": ["named-versioned-derived-contract-tokens"],
                "reader_policy": "separate-from-serialization-compatibility",
                "registration_mode": "source-annotation",
            },
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
                "directory": "crates/automata-ci-store/migrations",
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

    def prior_reader(self, version: int, *, ignored: bool = False) -> dict[str, object]:
        source = self.root / "crates" / "automata-ci-core" / "src" / "compatibility.rs"
        source.write_text(
            f"fn decode_prior(version: u16) {{ if version == {version} {{}} }}\n",
            encoding="utf-8",
        )
        test = self.root / "crates" / "automata-ci-core" / "tests" / "compatibility.rs"
        attributes = "#[test]\n#[ignore]\n" if ignored else "#[test]\n"
        test.write_text(
            f"{attributes}fn reads_prior_v{version}() {{\n"
            f"    let prior_version: u16 = {version};\n"
            "    assert!(decode_prior(prior_version).is_ok());\n"
            "}\n",
            encoding="utf-8",
        )
        return {
            "reader": {
                "contains": f"version == {version}",
                "path": "crates/automata-ci-core/src/compatibility.rs",
                "symbol": "decode_prior",
            },
            "tests": [
                {
                    "function": f"reads_prior_v{version}",
                    "outcome": "assert!(decode_prior(prior_version).is_ok());",
                    "path": "crates/automata-ci-core/tests/compatibility.rs",
                    "reader_call": "decode_prior(prior_version)",
                    "version": f"let prior_version: u16 = {version};",
                }
            ],
            "version": version,
        }

    def add_limit_alias(self, *, value: int = 6, annotated: bool = True) -> None:
        source = self.root / "crates" / "automata-ci-runtime" / "src" / "limits.rs"
        source.write_text(
            source.read_text(encoding="utf-8")
            + ("// foundation-governance: limit-alias\n" if annotated else "")
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

    def test_versioned_derived_contract_in_new_crate_cannot_escape_discovery(self) -> None:
        source = self.root / "crates" / "new-derived-adapter" / "src" / "digest.rs"
        source.parent.mkdir(parents=True)
        source.write_text(
            'const PAYLOAD_DIGEST_DOMAIN: &[u8] = b"example.payload.v1\\0";\n',
            encoding="utf-8",
        )

        self.assert_invalid(
            r"versioned derived contract declarations require annotations.*"
            r"PAYLOAD_DIGEST_DOMAIN"
        )

    def test_arbitrarily_named_versioned_contract_in_new_crate_cannot_escape(self) -> None:
        source = self.root / "crates" / "new-derived-adapter" / "src" / "capability.rs"
        source.parent.mkdir(parents=True)
        source.write_text(
            'const PROCESS_EXECUTION: &str = "core.process-exec/v1";\n',
            encoding="utf-8",
        )

        self.assert_invalid(
            r"versioned derived contract declarations require annotations.*"
            r"PROCESS_EXECUTION"
        )

    def test_terminal_contract_version_disambiguates_versioned_value(self) -> None:
        source = self.root / "crates" / "new-derived-adapter" / "src" / "capability.rs"
        source.parent.mkdir(parents=True)
        source.write_text(
            "// foundation-governance: derived-contract "
            "owner=integration kind=wire-discriminator\n"
            'const CGROUP_V2: &str = "linux.cgroup-v2/v1";\n',
            encoding="utf-8",
        )

        governance.validate_repository(self.root)

    def test_indented_derived_contract_in_new_crate_cannot_escape_discovery(self) -> None:
        source = self.root / "crates" / "new-derived-adapter" / "src" / "digest.rs"
        source.parent.mkdir(parents=True)
        source.write_text(
            "pub mod nested {\n"
            '    const PAYLOAD_DIGEST_DOMAIN: &[u8] = b"example.payload.v1\\0";\n'
            "}\n",
            encoding="utf-8",
        )

        self.assert_invalid(
            r"versioned derived contract declarations require annotations.*"
            r"PAYLOAD_DIGEST_DOMAIN"
        )

    def test_test_only_format_and_derived_constants_are_not_production_contracts(self) -> None:
        source = self.root / "crates" / "new-derived-adapter" / "src" / "fixture.rs"
        source.parent.mkdir(parents=True)
        source.write_text(
            "#[cfg(test)]\n"
            "mod tests {\n"
            "    const TEST_WIRE_SCHEMA: u16 = 1;\n"
            '    const TEST_DIGEST_DOMAIN: &[u8] = b"fixture.v1";\n'
            "}\n"
            "#[test]\n"
            "fn inline_fixture() {\n"
            "    const LOCAL_WIRE_SCHEMA: u16 = 1;\n"
            '    const LOCAL_DIGEST_DOMAIN: &[u8] = b"fixture.v1";\n'
            "}\n",
            encoding="utf-8",
        )

        governance.validate_repository(self.root)

    def test_versioned_cryptographic_label_in_new_crate_cannot_escape_discovery(self) -> None:
        source = self.root / "crates" / "new-derived-adapter" / "src" / "crypto.rs"
        source.parent.mkdir(parents=True)
        source.write_text(
            'const PAYLOAD_DERIVATION_LABEL: &[u8] = b"example/payload/v1";\n',
            encoding="utf-8",
        )

        self.assert_invalid(
            r"versioned derived contract declarations require annotations.*"
            r"PAYLOAD_DERIVATION_LABEL"
        )

    def test_annotated_derived_contract_in_new_crate_is_registered(self) -> None:
        source = self.root / "crates" / "new-derived-adapter" / "src" / "digest.rs"
        source.parent.mkdir(parents=True)
        source.write_text(
            "// foundation-governance: derived-contract "
            "owner=integration kind=digest-domain\n"
            'const PAYLOAD_DIGEST_DOMAIN: &[u8] = b"example.payload.v1\\0";\n',
            encoding="utf-8",
        )

        governance.validate_repository(self.root)

    def test_derived_contract_annotation_requires_known_owner_and_kind(self) -> None:
        source = self.root / "crates" / "new-derived-adapter" / "src" / "digest.rs"
        source.parent.mkdir(parents=True)
        source.write_text(
            "// foundation-governance: derived-contract "
            "owner=missing kind=banana\n"
            'const PAYLOAD_DIGEST_DOMAIN: &[u8] = b"example.payload.v1\\0";\n',
            encoding="utf-8",
        )

        self.assert_invalid(r"names unknown owner 'missing'")

    def test_derived_contract_exclusion_is_exact_source_bound(self) -> None:
        source = self.root / "crates" / "new-derived-adapter" / "src" / "probe.rs"
        source.parent.mkdir(parents=True)
        declaration = 'const PROBE_BYTES: &[u8] = b"internal-probe-v1";'
        source.write_text(
            "// foundation-governance: derived-contract-exclusion\n"
            f"{declaration}\n",
            encoding="utf-8",
        )
        self.registry["derived_contract_exclusions"] = [
            {
                "constant": "PROBE_BYTES",
                "path": "crates/new-derived-adapter/src/probe.rs",
                "reason": "Synthetic internal probe outside durable and wire contracts.",
                "source": declaration,
            }
        ]
        self.write_registry()

        governance.validate_repository(self.root)

        self.registry["derived_contract_exclusions"][0]["source"] = declaration[:-1]
        self.write_registry()
        self.assert_invalid(r"must bind the exact complete constant declaration")

        self.registry["derived_contract_exclusions"][0]["source"] = (
            'const PROBE_BYTES: &[u8] = b"internal-probe-v2";'
        )
        self.write_registry()
        self.assert_invalid(r"fragment must occur exactly once.*found 0")

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
            / "automata-ci-store"
            / "migrations"
            / "0002_unregistered.sql"
        )
        migration.write_text("SELECT 2;\n", encoding="utf-8")

        self.assert_invalid("migration inventory drift")

    def test_canonical_migration_content_drift_is_rejected(self) -> None:
        migration = (
            self.root
            / "crates"
            / "automata-ci-store"
            / "migrations"
            / "0001_initial_schema.sql"
        )
        migration.write_text("SELECT 2;\n", encoding="utf-8")

        self.assert_invalid("canonical migration content drift")

    def test_unmapped_canonical_migration_format_literal_is_rejected(self) -> None:
        migration = (
            self.root
            / "crates"
            / "automata-ci-store"
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
            / "automata-ci-store"
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
            / "automata-ci-store"
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
            / "automata-ci-store"
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
            / "automata-ci-store"
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
            "// foundation-governance: parity-limit\n"
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
            "// foundation-governance: operational-limit\n"
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

    def test_annotated_operational_limit_requires_an_exclusion(self) -> None:
        source = self.root / "crates" / "automata-ci-runtime" / "src" / "retry.rs"
        source.write_text(
            "// foundation-governance: operational-limit\n"
            "const MAX_RETRY_ATTEMPTS: usize = 3;\n",
            encoding="utf-8",
        )

        self.assert_invalid(r"unregistered limit declarations.*MAX_RETRY_ATTEMPTS")

    def test_stale_limit_exclusion_is_rejected(self) -> None:
        source = self.root / "crates" / "automata-ci-runtime" / "src" / "retry.rs"
        source.write_text(
            "// foundation-governance: operational-limit\n"
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

    def test_limit_alias_value_drift_is_rejected(self) -> None:
        self.add_limit_alias(value=7)
        self.write_registry()

        self.assert_invalid(r"relation drift.*TEST_ITEM_CENSUS_LIMIT.*expected 5 \+ 1")

    def test_limit_alias_requires_a_source_annotation(self) -> None:
        self.add_limit_alias(annotated=False)
        self.write_registry()

        self.assert_invalid(r"structured aliases need limit-alias annotations")

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

    def test_enforcement_phase_is_closed(self) -> None:
        self.registry["limits"][0]["enforcement_phase"] = "somewhere"
        self.write_registry()

        self.assert_invalid(r"enforcement_phase is unsupported")

    def test_rust_integer_type_does_not_bind_a_declared_version(self) -> None:
        self.registry["formats"][0]["version"] = 16
        self.write_registry()

        self.assert_invalid(r"does not bind declared version 16")

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


if __name__ == "__main__":
    unittest.main()
