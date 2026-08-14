#!/usr/bin/env python3
"""Mutation tests for the fail-closed GitHub Actions capability registry."""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/ci/verify-github-actions-capabilities.py"
REGISTRY = ROOT / "docs/governance/github-actions-capabilities-v1.json"
REVIEWED_DELTAS = ROOT / "docs/governance/github-actions-reviewed-deltas-v1.json"
REFERENCE_SNAPSHOT = ROOT / "docs/governance/github-actions-reference-snapshot-v1.json"


class CapabilityRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
        spec = importlib.util.spec_from_file_location("capability_validator", SCRIPT)
        if spec is None or spec.loader is None:
            raise RuntimeError("cannot load the capability validator")
        cls.validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.validator)

    def verify(self, registry: Path = REGISTRY) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--repository-root",
                str(ROOT),
                "--registry",
                str(registry),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def reject(self, mutate: Callable[[dict[str, Any]], None], expected: str) -> None:
        value = copy.deepcopy(self.registry)
        mutate(value)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.json"
            path.write_text(
                json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            result = self.verify(path)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(expected, result.stderr)

    def reject_reviewed_delta(
        self, mutate: Callable[[dict[str, Any]], None], expected: str
    ) -> None:
        def mutate_governance(
            _snapshot: dict[str, Any], reviewed: dict[str, Any]
        ) -> None:
            mutate(reviewed)

        self.reject_reference_governance(mutate_governance, expected)

    def reject_reference_governance(
        self,
        mutate: Callable[[dict[str, Any], dict[str, Any]], None],
        expected: str,
    ) -> None:
        result = self.run_reference_governance(mutate)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(expected, result.stderr)

    def run_reference_governance(
        self, mutate: Callable[[dict[str, Any], dict[str, Any]], None]
    ) -> subprocess.CompletedProcess[str]:
        registry = copy.deepcopy(self.registry)
        snapshot = json.loads(REFERENCE_SNAPSHOT.read_text(encoding="utf-8"))
        reviewed = json.loads(REVIEWED_DELTAS.read_text(encoding="utf-8"))
        mutate(snapshot, reviewed)
        temporary_paths: list[Path] = []

        def write_document(prefix: str, value: dict[str, Any]) -> Path:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".json",
                prefix=prefix,
                dir=ROOT / "docs/governance",
                encoding="utf-8",
                delete=False,
            ) as temporary_file:
                path = Path(temporary_file.name)
                json.dump(
                    value,
                    temporary_file,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                temporary_file.write("\n")
            temporary_paths.append(path)
            return path

        try:
            reviewed_path = write_document("reviewed-delta-mutation-", reviewed)
            reviewed_relative = reviewed_path.relative_to(ROOT).as_posix()
            snapshot["replacement_policy"]["approval_registry"] = reviewed_relative
            snapshot_path = write_document("reference-snapshot-mutation-", snapshot)
            registry["reviewed_deltas"] = reviewed_relative
            registry["reference_snapshot"] = snapshot_path.relative_to(ROOT).as_posix()
            with tempfile.TemporaryDirectory() as directory:
                registry_path = Path(directory) / "registry.json"
                registry_path.write_text(
                    json.dumps(registry, ensure_ascii=False, indent=2, sort_keys=True)
                    + "\n",
                    encoding="utf-8",
                )
                result = self.verify(registry_path)
            return result
        finally:
            for path in temporary_paths:
                path.unlink(missing_ok=True)

    def test_checked_in_registry_is_valid(self) -> None:
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_action_key_normalizer_semantics_are_anchored(self) -> None:
        action_parser = (
            ROOT / "crates/automata-ci-action-github/src/parser.rs"
        ).read_text(encoding="utf-8")
        workflow_decode = (
            ROOT / "crates/automata-ci-workflow-github/src/decode/mod.rs"
        ).read_text(encoding="utf-8")
        mutated = action_parser.replace(
            "    actual.eq_ignore_ascii_case(expected)\n",
            "    actual.eq_ignore_ascii_case(expected)\n"
            '        || (actual == "preview" && expected == "name")\n',
            1,
        )
        self.assertNotEqual(mutated, action_parser)
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "action key_eq helper definition drifted",
        ):
            self.validator.validate_semantic_key_helpers(mutated, workflow_decode)

    def test_workflow_field_name_semantics_are_anchored(self) -> None:
        action_parser = (
            ROOT / "crates/automata-ci-action-github/src/parser.rs"
        ).read_text(encoding="utf-8")
        workflow_decode = (
            ROOT / "crates/automata-ci-workflow-github/src/decode/mod.rs"
        ).read_text(encoding="utf-8")
        mutated = workflow_decode.replace(
            "    entry.key.as_scalar().map(|scalar| scalar.decoded.as_str())\n",
            "    entry.key.as_scalar().map(|scalar| match scalar.decoded.as_str() {\n"
            '        "preview" => "image",\n'
            "        other => other,\n"
            "    })\n",
            1,
        )
        self.assertNotEqual(mutated, workflow_decode)
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "workflow field_name helper definition drifted",
        ):
            self.validator.validate_semantic_key_helpers(action_parser, mutated)

    def test_action_attach_cannot_rewrite_mapping_keys(self) -> None:
        action_parser = (
            ROOT / "crates/automata-ci-action-github/src/parser.rs"
        ).read_text(encoding="utf-8")
        workflow_decode = (
            ROOT / "crates/automata-ci-workflow-github/src/decode/mod.rs"
        ).read_text(encoding="utf-8")
        mutated = action_parser.replace(
            "                    entries.push(YamlMappingEntry { key, value: node });\n",
            "                    entries.push(YamlMappingEntry {\n"
            '                        key: if key.text() == "preview" {\n'
            '                            MetadataScalar::synthetic("name")\n'
            "                        } else {\n"
            "                            key\n"
            "                        },\n"
            "                        value: node,\n"
            "                    });\n",
            1,
        )
        self.assertNotEqual(mutated, action_parser)
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "action parser key-bearing scope 'Receiver::attach' drifted",
        ):
            self.validator.validate_semantic_key_helpers(mutated, workflow_decode)

    def test_action_key_scope_fingerprint_preserves_literal_whitespace(self) -> None:
        action_parser = (
            ROOT / "crates/automata-ci-action-github/src/parser.rs"
        ).read_text(encoding="utf-8")
        workflow_decode = (
            ROOT / "crates/automata-ci-workflow-github/src/decode/mod.rs"
        ).read_text(encoding="utf-8")
        mutated = action_parser.replace(
            '                            "yaml.mapping.key",\n',
            '                            "yaml.mapping. key",\n',
            1,
        )
        self.assertNotEqual(mutated, action_parser)
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "action parser key-bearing scope 'Receiver::attach' drifted",
        ):
            self.validator.validate_semantic_key_helpers(mutated, workflow_decode)

    def test_workflow_preserve_unknown_key_flow_is_anchored(self) -> None:
        action_parser = (
            ROOT / "crates/automata-ci-action-github/src/parser.rs"
        ).read_text(encoding="utf-8")
        workflow_decode = (
            ROOT / "crates/automata-ci-workflow-github/src/decode/mod.rs"
        ).read_text(encoding="utf-8")
        mutated = workflow_decode.replace(
            '            .map_or("<complex-key>", |scalar| scalar.decoded.as_str());\n',
            '            .map_or("<complex-key>", |scalar| match scalar.decoded.as_str() {\n'
            '                "preview" => "name",\n'
            "                other => other,\n"
            "            });\n",
            1,
        )
        self.assertNotEqual(mutated, workflow_decode)
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "workflow key-bearing scope 'DecodeContext::preserve_unknown' drifted",
        ):
            self.validator.validate_semantic_key_helpers(action_parser, mutated)

    def test_new_cross_file_action_key_helper_is_rejected(self) -> None:
        action_parser = (
            ROOT / "crates/automata-ci-action-github/src/parser.rs"
        ).read_text(encoding="utf-8")
        workflow_decode = (
            ROOT / "crates/automata-ci-workflow-github/src/decode/mod.rs"
        ).read_text(encoding="utf-8")
        mutated = action_parser + """

pub(crate) fn key_is_preview(entry: &YamlMappingEntry) -> bool {
    entry.key() == "preview"
}
"""
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "action parser YAML-key helper surface drifted",
        ):
            self.validator.validate_semantic_key_helpers(mutated, workflow_decode)

    def test_new_cross_file_workflow_key_helper_is_rejected(self) -> None:
        action_parser = (
            ROOT / "crates/automata-ci-action-github/src/parser.rs"
        ).read_text(encoding="utf-8")
        workflow_decode = (
            ROOT / "crates/automata-ci-workflow-github/src/decode/mod.rs"
        ).read_text(encoding="utf-8")
        mutated = workflow_decode + """

pub(super) fn accepts_preview(entry: &YamlMappingEntry) -> bool {
    field_name(entry) == Some("preview")
}
"""
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "workflow YAML-key helper surface drifted",
        ):
            self.validator.validate_semantic_key_helpers(action_parser, mutated)

    def test_decoder_field_without_registry_entry_is_rejected(self) -> None:
        def mutate(value: dict[str, Any]) -> None:
            inventory = next(
                inventory
                for inventory in value["decoder_inventory"]
                if inventory["id"] == "action-docker-fields"
            )
            inventory["fields"].pop("args")

        self.reject(
            mutate,
            "decoder coverage drifted",
        )

    def test_governed_decoder_source_cannot_disappear_from_inventory(self) -> None:
        def mutate(value: dict[str, Any]) -> None:
            value["decoder_inventory"] = [
                inventory
                for inventory in value["decoder_inventory"]
                if inventory["path"]
                != "crates/automata-ci-workflow-github/src/decode/container.rs"
            ]

        self.reject(mutate, "container decoder surface inventory drifted")

    def test_compatibility_claim_without_attributed_acceptance_is_rejected(self) -> None:
        self.reject(
            lambda value: value["features"][0]["acceptance"].update(
                {"function": "not_a_real_test"}
            ),
            "must bind exactly one attributed Rust test",
        )

    def test_compatibility_status_drift_is_rejected(self) -> None:
        self.reject(
            lambda value: value["features"][0].update({"status": "Experimental"}),
            "compatibility linkage drifted",
        )

    def test_stage_cannot_disappear_from_a_profile(self) -> None:
        self.reject(
            lambda value: value["stage_profiles"]["workflow-parsing-and-planning"].pop(
                "results"
            ),
            "must contain exactly",
        )

    def test_features_cannot_share_a_stage_profile(self) -> None:
        self.reject(
            lambda value: value["features"][0].update(
                {"stage_profile": value["features"][1]["stage_profile"]}
            ),
            "must use its own stage profile",
        )

    def test_unknown_compatibility_status_is_rejected(self) -> None:
        self.reject(
            lambda value: value["features"][0].update({"status": "Complete"}),
            "unknown compatibility status",
        )

    def test_unknown_evaluation_phase_is_rejected(self) -> None:
        self.reject(
            lambda value: value["features"][0].update(
                {"evaluation_phase": "whenever"}
            ),
            "unknown evaluation phase",
        )

    def test_feature_unsupported_mapping_must_resolve_to_its_diagnostic(self) -> None:
        def mutate(value: dict[str, Any]) -> None:
            feature = next(
                feature
                for feature in value["features"]
                if feature["id"] == "job-containers"
            )
            feature["unsupported"]["code"] = "github.compile.not_registered"

        self.reject(mutate, "references unregistered diagnostic")

    def test_feature_unsupported_span_policy_must_match_the_diagnostic(self) -> None:
        def mutate(value: dict[str, Any]) -> None:
            feature = next(
                feature
                for feature in value["features"]
                if feature["id"] == "job-containers"
            )
            feature["unsupported"]["span_policy"] = "different-span"

        self.reject(mutate, "span policy differs")

    def test_feature_unsupported_source_must_match_the_diagnostic(self) -> None:
        def mutate(value: dict[str, Any]) -> None:
            feature = next(
                feature
                for feature in value["features"]
                if feature["id"] == "job-containers"
            )
            feature["source"] = {
                "contains": "pub struct WorkflowRerunService {",
                "path": "crates/automata-ci-workflow-service/src/workflow_rerun.rs",
            }

        self.reject(mutate, "source differs")

    def test_runner_runtime_enum_variant_without_inventory_is_rejected(self) -> None:
        self.reject(
            lambda value: value["runner_runtime_inventories"][0]["variants"].pop(
                "Internal"
            ),
            "enum coverage drifted",
        )

    def test_runner_commit_change_cannot_rewrite_the_old_baseline_review(self) -> None:
        def mutate(snapshot: dict[str, Any], reviewed: dict[str, Any]) -> None:
            old_commit = snapshot["runner"]["baseline_commit"]
            new_commit = "0123456789abcdef0123456789abcdef01234567"
            snapshot["runner"]["baseline_commit"] = new_commit
            for reference in snapshot["reference_groups"]:
                if reference["id"].startswith("runner-"):
                    reference["url"] = reference["url"].replace(
                        old_commit, new_commit
                    )
            delta = next(
                delta
                for delta in reviewed["reviewed_deltas"]
                if delta["decision"] == "approved-baseline"
            )
            delta["runner_baseline"] = copy.deepcopy(snapshot["runner"])
            delta["source_revision"] = delta["source_revision"].replace(
                old_commit, new_commit
            )

        self.reject_reference_governance(
            mutate,
            "runner baseline changed without a newly added approved-baseline reviewed delta",
        )

    def test_runner_release_change_cannot_rewrite_the_old_baseline_review(self) -> None:
        def mutate(snapshot: dict[str, Any], reviewed: dict[str, Any]) -> None:
            snapshot["runner"]["baseline_release"] = "v2.337.0"
            snapshot["runner"]["release_url"] = (
                "https://github.com/actions/runner/releases/tag/v2.337.0"
            )
            delta = next(
                delta
                for delta in reviewed["reviewed_deltas"]
                if delta["decision"] == "approved-baseline"
            )
            delta["runner_baseline"] = copy.deepcopy(snapshot["runner"])

        self.reject_reference_governance(
            mutate,
            "runner baseline changed without a newly added approved-baseline reviewed delta",
        )

    def test_runner_change_cannot_rename_the_old_baseline_review(self) -> None:
        def mutate(snapshot: dict[str, Any], reviewed: dict[str, Any]) -> None:
            snapshot["runner"]["baseline_release"] = "v2.337.0"
            snapshot["runner"]["release_url"] = (
                "https://github.com/actions/runner/releases/tag/v2.337.0"
            )
            delta = next(
                delta
                for delta in reviewed["reviewed_deltas"]
                if delta["decision"] == "approved-baseline"
            )
            delta["id"] = "new-runner-baseline-2026-08-14"
            delta["runner_baseline"] = copy.deepcopy(snapshot["runner"])

        self.reject_reference_governance(
            mutate,
            "reviewed delta history is append-only; missing historical records",
        )

    def test_renamed_runner_reference_still_binds_the_baseline_commit(self) -> None:
        def mutate(snapshot: dict[str, Any], reviewed: dict[str, Any]) -> None:
            old_id = "runner-node-action-handler"
            new_id = "action-handler"
            old_commit = snapshot["runner"]["baseline_commit"]
            new_commit = "0123456789abcdef0123456789abcdef01234567"
            reference = next(
                reference
                for reference in snapshot["reference_groups"]
                if reference["id"] == old_id
            )
            reference["id"] = new_id
            reference["url"] = reference["url"].replace(old_commit, new_commit)
            snapshot["reference_groups"].sort(key=lambda value: value["id"])
            for delta in reviewed["reviewed_deltas"]:
                delta["reference_ids"] = sorted(
                    new_id if reference_id == old_id else reference_id
                    for reference_id in delta["reference_ids"]
                )
            baseline = next(
                delta
                for delta in reviewed["reviewed_deltas"]
                if delta["decision"] == "approved-baseline"
            )
            baseline["source_revision"] += f"+actions/runner@{new_commit}"

        self.reject_reference_governance(
            mutate,
            "runner reference URLs do not bind the exact baseline commit",
        )

    def test_docs_refresh_can_retain_same_runner_historical_baseline(self) -> None:
        def mutate(snapshot: dict[str, Any], reviewed: dict[str, Any]) -> None:
            reference = next(
                reference
                for reference in snapshot["reference_groups"]
                if reference["id"] == "github-docs-contexts"
            )
            old_docs_commit = reference["url"].split("/")[5]
            new_docs_commit = "89abcdef" * 5
            reference["url"] = reference["url"].replace(
                old_docs_commit, new_docs_commit
            )
            reference["sha256"] = "1" * 64
            runner_commit = snapshot["runner"]["baseline_commit"]
            reviewed["reviewed_deltas"].append(
                {
                    "categories": [
                        "action_runtimes",
                        "contexts",
                        "default_variables",
                        "events",
                        "limits",
                        "permissions",
                        "syntax",
                        "variables",
                    ],
                    "decision": "approved-baseline",
                    "id": "syntax-reference-refresh-2026-08-14",
                    "reference_ids": sorted(
                        reference["id"]
                        for reference in snapshot["reference_groups"]
                    ),
                    "reviewed_at": "2026-08-14",
                    "reviewers": [
                        "foundation-integration-owner",
                        "workflow-language-owner",
                    ],
                    "runner_baseline": copy.deepcopy(snapshot["runner"]),
                    "source_revision": (
                        f"actions/runner@{runner_commit}"
                        f"+github/docs@{old_docs_commit}"
                        f"+github/docs@{new_docs_commit}"
                    ),
                }
            )

        result = self.run_reference_governance(mutate)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_reviewed_delta_decision_is_closed(self) -> None:
        self.reject_reviewed_delta(
            lambda value: value["reviewed_deltas"][0].update(
                {"decision": "looks-good-to-me"}
            ),
            "decision is not an allowed reviewed decision",
        )

    def test_reviewed_delta_reviewers_are_typed_human_ids(self) -> None:
        self.reject_reviewed_delta(
            lambda value: value["reviewed_deltas"][0].update(
                {"reviewers": [1, 2]}
            ),
            "reviewers must be a non-empty trimmed string",
        )

    def test_reviewed_delta_date_is_canonical_and_real(self) -> None:
        self.reject_reviewed_delta(
            lambda value: value["reviewed_deltas"][0].update(
                {"reviewed_at": "2026-02-31"}
            ),
            "reviewed_at must be a canonical ISO 8601 date",
        )

    def test_reviewed_delta_source_revision_is_immutable(self) -> None:
        self.reject_reviewed_delta(
            lambda value: value["reviewed_deltas"][0].update(
                {"source_revision": "github/docs@main"}
            ),
            "source_revision must contain canonical immutable GitHub revisions",
        )

    def test_reviewed_delta_requires_a_reference_binding(self) -> None:
        self.reject_reviewed_delta(
            lambda value: value["reviewed_deltas"][0].update(
                {"reference_ids": []}
            ),
            "reference_ids must be a non-empty array",
        )

    def test_diagnostic_history_lock_is_required(self) -> None:
        self.reject(
            lambda value: value.update(
                {"diagnostic_history": "docs/governance/not-present.json"}
            ),
            "does not name a file",
        )

    def test_diagnostic_history_cannot_remove_a_baseline_code(self) -> None:
        value = copy.deepcopy(self.registry)
        history = json.loads(
            (ROOT / value["diagnostic_history"]).read_text(encoding="utf-8")
        )
        history["codes"].remove("github.compile.job_container")
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            prefix="capability-history-mutation-",
            dir=ROOT / "docs/governance",
            encoding="utf-8",
            delete=False,
        ) as history_file:
            history_path = Path(history_file.name)
            json.dump(history, history_file, ensure_ascii=False, indent=2, sort_keys=True)
            history_file.write("\n")
        try:
            value["diagnostic_history"] = history_path.relative_to(ROOT).as_posix()
            with tempfile.TemporaryDirectory() as directory:
                registry_path = Path(directory) / "registry.json"
                registry_path.write_text(
                    json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                result = self.verify(registry_path)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("append-only", result.stderr)
        finally:
            history_path.unlink(missing_ok=True)

    def test_ignored_acceptance_test_is_rejected(self) -> None:
        self.reject(
            lambda value: value["features"][0]["acceptance"].update(
                {
                    "function": "official_actions_artifact_6_2_client_completes_the_full_protocol",
                    "path": "crates/automata-ci-results-github/tests/http_compatibility.rs",
                }
            ),
            "machine-checked CI lane",
        )

    def test_acceptance_fixture_must_retain_its_semantic_fragments(self) -> None:
        self.reject(
            lambda value: value["features"][0]["acceptance"].update(
                {"required_fragments": ["unrelated semantic claim"]}
            ),
            "missing required semantic fragment",
        )

    def test_ignored_acceptance_lane_must_run_the_exact_package(self) -> None:
        def mutate(value: dict[str, Any]) -> None:
            feature = next(
                feature for feature in value["features"] if feature["id"] == "managed-secrets"
            )
            feature["acceptance"]["ci_lane"]["package"] = "automata-ci-secret"

        self.reject(
            mutate,
            "does not run automata-ci-secret --test postgres with --ignored",
        )

    def test_result_returning_empty_acceptance_test_is_rejected(self) -> None:
        value = copy.deepcopy(self.registry)
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".rs",
            prefix="capability-noop-",
            dir=ROOT / "docs/governance",
            encoding="utf-8",
            delete=False,
        ) as source_file:
            source_path = Path(source_file.name)
            source_file.write(
                "#[test]\nfn empty_result_test() -> Result<(), ()> {}\n"
            )
        try:
            value["features"][0]["acceptance"] = {
                "function": "empty_result_test",
                "path": source_path.relative_to(ROOT).as_posix(),
                "required_fragments": ["Result"],
            }
            with tempfile.TemporaryDirectory() as directory:
                registry_path = Path(directory) / "registry.json"
                registry_path.write_text(
                    json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                result = self.verify(registry_path)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("empty no-op Rust test", result.stderr)
        finally:
            source_path.unlink(missing_ok=True)

    def test_decoder_mapping_to_unknown_feature_is_rejected(self) -> None:
        def mutate(value: dict[str, Any]) -> None:
            inventory = next(
                inventory
                for inventory in value["decoder_inventory"]
                if inventory["id"] == "action-docker-fields"
            )
            inventory["fields"]["args"] = "unregistered-feature"

        self.reject(
            mutate,
            "references unknown features",
        )

    def test_job_container_field_cannot_be_assigned_to_service_containers(self) -> None:
        def mutate(value: dict[str, Any]) -> None:
            inventory = next(
                inventory
                for inventory in value["decoder_inventory"]
                if inventory["id"] == "job-container-fields"
            )
            inventory["fields"]["image"] = "service-containers"

        self.reject(mutate, "container decoder Job surface")

    def test_docker_field_cannot_be_assigned_to_javascript_actions(self) -> None:
        def mutate(value: dict[str, Any]) -> None:
            inventory = next(
                inventory
                for inventory in value["decoder_inventory"]
                if inventory["id"] == "action-docker-fields"
            )
            inventory["fields"]["image"] = (
                "javascript-and-local-composite-actions"
            )

        self.reject(mutate, "action decoder function 'decode_docker'")

    def test_docker_runtime_cannot_be_assigned_to_javascript_actions(self) -> None:
        def mutate(value: dict[str, Any]) -> None:
            inventory = next(
                inventory
                for inventory in value["decoder_inventory"]
                if inventory["id"] == "action-runtime-values"
            )
            inventory["fields"]["docker"] = (
                "javascript-and-local-composite-actions"
            )

        self.reject(mutate, "action runtime feature ownership drifted")

    def test_hyphenated_runtime_dispatch_is_discovered(self) -> None:
        source = (
            ROOT / "crates/automata-ci-action-github/src/decoder.rs"
        ).read_text(encoding="utf-8")
        needle = """    } else if runtime.eq_ignore_ascii_case("composite") {
        decode_composite(fields).map(ActionExecution::Composite)
    } else {
"""
        replacement = """    } else if runtime.eq_ignore_ascii_case("composite") {
        decode_composite(fields).map(ActionExecution::Composite)
    } else if runtime.eq_ignore_ascii_case("node24-preview") {
        decode_javascript(fields, JavascriptRuntime::Node24)
            .map(ActionExecution::Javascript)
    } else {
"""
        mutated = source.replace(needle, replacement, 1)
        self.assertNotEqual(mutated, source)
        runtime_inventory = next(
            inventory
            for inventory in self.registry["decoder_inventory"]
            if inventory["id"] == "action-runtime-values"
        )
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "action runtime target inventory drifted",
        ):
            self.validator.validate_action_runtime_target_coverage(
                mutated, set(runtime_inventory["fields"])
            )

    def test_runtime_dispatch_requires_unique_normal_string_literals(self) -> None:
        source = (
            ROOT / "crates/automata-ci-action-github/src/decoder.rs"
        ).read_text(encoding="utf-8")
        branch = """    } else if runtime.eq_ignore_ascii_case("composite") {
        decode_composite(fields).map(ActionExecution::Composite)
    } else {
"""
        runtime_inventory = next(
            inventory
            for inventory in self.registry["decoder_inventory"]
            if inventory["id"] == "action-runtime-values"
        )
        cases = (
            (
                "PREVIEW_RUNTIME",
                '    const PREVIEW_RUNTIME: &str = "node24-preview";\n',
                "must use one canonical normal string literal",
            ),
            (
                'r#"node24-preview"#',
                "",
                "must use one canonical normal string literal",
            ),
            ('"node24"', "", "duplicate token 'node24'"),
        )
        for argument, prelude, expected in cases:
            with self.subTest(argument=argument):
                mutated = source.replace(
                    "    if runtime.eq_ignore_ascii_case(\"docker\") {\n",
                    prelude + "    if runtime.eq_ignore_ascii_case(\"docker\") {\n",
                    1,
                ).replace(
                    branch,
                    """    } else if runtime.eq_ignore_ascii_case("composite") {
        decode_composite(fields).map(ActionExecution::Composite)
    } else if runtime.eq_ignore_ascii_case("""
                    + argument
                    + """) {
        decode_javascript(fields, JavascriptRuntime::Node24)
            .map(ActionExecution::Javascript)
    } else {
""",
                    1,
                )
                self.assertNotEqual(mutated, source)
                with self.assertRaisesRegex(
                    self.validator.CapabilityError, expected
                ):
                    self.validator.validate_action_runtime_target_coverage(
                        mutated, set(runtime_inventory["fields"])
                    )

    def test_alternate_runtime_comparison_is_rejected(self) -> None:
        source = (
            ROOT / "crates/automata-ci-action-github/src/decoder.rs"
        ).read_text(encoding="utf-8")
        needle = """    } else if runtime.eq_ignore_ascii_case("composite") {
        decode_composite(fields).map(ActionExecution::Composite)
    } else {
"""
        replacement = """    } else if runtime.eq_ignore_ascii_case("composite") {
        decode_composite(fields).map(ActionExecution::Composite)
    } else if runtime == "node28" {
        decode_javascript(fields, JavascriptRuntime::Node24)
            .map(ActionExecution::Javascript)
    } else {
"""
        mutated = source.replace(needle, replacement, 1)
        self.assertNotEqual(mutated, source)
        runtime_inventory = next(
            inventory
            for inventory in self.registry["decoder_inventory"]
            if inventory["id"] == "action-runtime-values"
        )
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "used outside canonical eq_ignore_ascii_case",
        ):
            self.validator.validate_action_runtime_target_coverage(
                mutated, set(runtime_inventory["fields"])
            )

    def test_runtime_alias_dispatch_is_rejected(self) -> None:
        source = (
            ROOT / "crates/automata-ci-action-github/src/decoder.rs"
        ).read_text(encoding="utf-8")
        mutated = source.replace(
            "    let runtime = scalar_string(&using);\n"
            '    if runtime.eq_ignore_ascii_case("docker") {\n',
            "    let runtime = scalar_string(&using);\n"
            "    let runtime_alias = scalar_string(&using);\n"
            '    if runtime_alias.eq_ignore_ascii_case("node28") {\n'
            "        decode_javascript(fields, JavascriptRuntime::Node24)\n"
            "            .map(ActionExecution::Javascript)\n"
            '    } else if runtime.eq_ignore_ascii_case("docker") {\n',
            1,
        )
        self.assertNotEqual(mutated, source)
        runtime_inventory = next(
            inventory
            for inventory in self.registry["decoder_inventory"]
            if inventory["id"] == "action-runtime-values"
        )
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "noncanonical comparison receivers",
        ):
            self.validator.validate_action_runtime_target_coverage(
                mutated, set(runtime_inventory["fields"])
            )

    def test_using_value_alternate_runtime_dispatch_is_rejected(self) -> None:
        source = (
            ROOT / "crates/automata-ci-action-github/src/decoder.rs"
        ).read_text(encoding="utf-8")
        mutated = source.replace(
            '    if runtime.eq_ignore_ascii_case("docker") {\n',
            '    if matches!(using.text(), "node28") {\n'
            "        decode_javascript(fields, JavascriptRuntime::Node24)\n"
            "            .map(ActionExecution::Javascript)\n"
            '    } else if runtime.eq_ignore_ascii_case("docker") {\n',
            1,
        )
        self.assertNotEqual(mutated, source)
        runtime_inventory = next(
            inventory
            for inventory in self.registry["decoder_inventory"]
            if inventory["id"] == "action-runtime-values"
        )
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "using value is used outside the closed",
        ):
            self.validator.validate_action_runtime_target_coverage(
                mutated, set(runtime_inventory["fields"])
            )

    def test_new_same_named_action_surface_is_discovered(self) -> None:
        source = (
            ROOT / "crates/automata-ci-action-github/src/decoder.rs"
        ).read_text(encoding="utf-8")
        mutated = source + """

fn decode_shadow_surface(fields: Fields) -> Result<(), MetadataDecodeError> {
    fields.validate_allowed(&["image"], "runs.property")?;
    Ok(())
}
"""
        inventoried = {
            inventory["function"]
            for inventory in self.registry["decoder_inventory"]
            if inventory["extractor"] == "action-function-fields"
        }
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "action decoder field-surface inventory drifted",
        ):
            self.validator.validate_action_surface_coverage(mutated, inventoried)

    def test_action_raw_field_literal_is_rejected(self) -> None:
        source = (
            ROOT / "crates/automata-ci-action-github/src/decoder.rs"
        ).read_text(encoding="utf-8")
        mutated = source.replace(
            '            "image",\n',
            '            r#"preview-field"#,\n            "image",\n',
            1,
        )
        self.assertNotEqual(mutated, source)
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "must use a canonical normal string literal field",
        ):
            self.validator.action_decoder_field_scopes(mutated)

    def test_action_typed_field_constants_are_resolved(self) -> None:
        source = (
            ROOT / "crates/automata-ci-action-github/src/decoder.rs"
        ).read_text(encoding="utf-8")
        cases = (
            (
                'const preview_field: &str = "preview-field";\n',
                "",
            ),
            (
                "",
                '    const preview_field: &str = "preview-field";\n',
            ),
        )
        for module_prelude, function_prelude in cases:
            with self.subTest(module_constant=bool(module_prelude)):
                docker_prefix = (
                    "fn decode_docker(mut fields: Fields) "
                    "-> Result<DockerAction, MetadataDecodeError> {\n"
                    "    fields.validate_allowed(\n"
                    "        &[\n"
                    '            "using",\n'
                )
                mutated = module_prelude + source.replace(
                    docker_prefix,
                    "fn decode_docker(mut fields: Fields) "
                    "-> Result<DockerAction, MetadataDecodeError> {\n"
                    + function_prelude
                    + "    fields.validate_allowed(\n"
                    + "        &[\n"
                    + '            "using",\n'
                    + "            preview_field,\n",
                    1,
                )
                self.assertNotEqual(mutated, source)
                actual = self.validator.action_decoder_field_scopes(mutated)
                self.assertIn("preview-field", actual["decode_docker"])

    def test_action_local_field_alias_is_rejected(self) -> None:
        source = (
            ROOT / "crates/automata-ci-action-github/src/decoder.rs"
        ).read_text(encoding="utf-8")
        docker_prefix = (
            "fn decode_docker(mut fields: Fields) "
            "-> Result<DockerAction, MetadataDecodeError> {\n"
            "    fields.validate_allowed(\n"
            "        &[\n"
            '            "using",\n'
        )
        mutated = source.replace(
            docker_prefix,
            "fn decode_docker(mut fields: Fields) "
            "-> Result<DockerAction, MetadataDecodeError> {\n"
            '    let preview_field = "preview-field";\n'
            "    fields.validate_allowed(\n"
            "        &[\n"
            '            "using",\n'
            "            preview_field,\n",
            1,
        )
        self.assertNotEqual(mutated, source)
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "typed string constant",
        ):
            self.validator.action_decoder_field_scopes(mutated)

    def test_new_dynamic_action_field_wrapper_is_rejected(self) -> None:
        source = (
            ROOT / "crates/automata-ci-action-github/src/decoder.rs"
        ).read_text(encoding="utf-8")
        mutated = source.replace(
            "fn decode_docker(mut fields: Fields) "
            "-> Result<DockerAction, MetadataDecodeError> {\n",
            "fn decode_docker(mut fields: Fields) "
            "-> Result<DockerAction, MetadataDecodeError> {\n"
            '    take_preview(&mut fields, "preview-field");\n',
            1,
        ) + """

fn take_preview(fields: &mut Fields, key: &str) {
    let _ = fields.take_exact(key);
}
"""
        self.assertNotEqual(mutated, source)
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "typed string constant",
        ):
            self.validator.action_decoder_field_scopes(mutated)

    def test_direct_action_field_comparisons_outside_grammar_are_rejected(self) -> None:
        source = (
            ROOT / "crates/automata-ci-action-github/src/decoder.rs"
        ).read_text(encoding="utf-8")
        required_branch = """            } else if key_eq(&key, "required") {
                required = value.into_scalar();
            }
"""
        mutated_key = source.replace(
            required_branch,
            """            } else if key_eq(&key, "required") {
                required = value.into_scalar();
            } else if key == "preview" {
                description = value.into_scalar();
            }
""",
            1,
        )
        self.assertNotEqual(mutated_key, source)
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "outside the closed governed field-call grammar",
        ):
            self.validator.action_decoder_field_scopes(mutated_key)

        mutated_entry = source + """

fn accepts_preview(entry: &YamlMappingEntry) -> bool {
    entry.key() == "preview"
}
"""
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "outside the closed governed field-call grammar",
        ):
            self.validator.action_decoder_field_scopes(mutated_entry)

    def test_action_selector_alternate_comparison_forms_are_rejected(self) -> None:
        source = (
            ROOT / "crates/automata-ci-action-github/src/decoder.rs"
        ).read_text(encoding="utf-8")
        required_branch = """            } else if key_eq(&key, "required") {
                required = value.into_scalar();
            }
"""
        cases = (
            'key.as_str().eq("preview")',
            'matches!(key.as_str(), "preview")',
        )
        for condition in cases:
            with self.subTest(condition=condition):
                mutated = source.replace(
                    required_branch,
                    """            } else if key_eq(&key, "required") {
                required = value.into_scalar();
            } else if """
                    + condition
                    + """ {
                description = value.into_scalar();
            }
""",
                    1,
                )
                self.assertNotEqual(mutated, source)
                with self.assertRaisesRegex(
                    self.validator.CapabilityError,
                    "outside the closed key_eq/exact-comparison grammar",
                ):
                    self.validator.action_decoder_field_scopes(mutated)

    def test_action_selector_equality_rejects_unresolved_aliases(self) -> None:
        source = (
            ROOT / "crates/automata-ci-action-github/src/decoder.rs"
        ).read_text(encoding="utf-8")
        required_branch = """            } else if key_eq(&key, "required") {
                required = value.into_scalar();
            }
"""
        cases = (
            ('let preview = "preview";\n            ', "preview"),
            ('static PREVIEW: &str = "preview";\n            ', "PREVIEW"),
        )
        for declaration, alias in cases:
            with self.subTest(alias=alias):
                mutated = source.replace(
                    "            let value = property.into_value();\n",
                    "            " + declaration
                    + "let value = property.into_value();\n",
                    1,
                ).replace(
                    required_branch,
                    """            } else if key_eq(&key, "required") {
                required = value.into_scalar();
            } else if key == """
                    + alias
                    + """ {
                description = value.into_scalar();
            }
""",
                    1,
                )
                self.assertNotEqual(mutated, source)
                with self.assertRaisesRegex(
                    self.validator.CapabilityError,
                    "typed string constant",
                ):
                    self.validator.action_decoder_field_scopes(mutated)

    def test_action_selector_initializer_grammar_is_closed(self) -> None:
        source = (
            ROOT / "crates/automata-ci-action-github/src/decoder.rs"
        ).read_text(encoding="utf-8")
        mutated = source.replace(
            "        let key = entry.key().to_owned();\n",
            '        let key = if entry.key().eq("preview") {\n'
            '            "name".to_owned()\n'
            "        } else {\n"
            "            entry.key().to_owned()\n"
            "        };\n",
            1,
        )
        self.assertNotEqual(mutated, source)
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "without exact YAML-key provenance",
        ):
            self.validator.action_decoder_field_scopes(mutated)

    def test_action_key_eq_selector_argument_grammar_is_closed(self) -> None:
        source = (
            ROOT / "crates/automata-ci-action-github/src/decoder.rs"
        ).read_text(encoding="utf-8")
        mutated = source.replace(
            '        if key_eq(exact, "name") {\n',
            '        if key_eq(if key.eq("preview") { "name" } else { exact }, "name") {\n',
            1,
        )
        self.assertNotEqual(mutated, source)
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "must use an exact proven selector",
        ):
            self.validator.action_decoder_field_scopes(mutated)

    def test_action_key_scalar_semantic_read_is_rejected(self) -> None:
        source = (
            ROOT / "crates/automata-ci-action-github/src/decoder.rs"
        ).read_text(encoding="utf-8")
        mutated = source.replace(
            '        require_nonempty_key(&entry, "action.key")?;\n',
            '        require_nonempty_key(&entry, "action.key")?;\n'
            '        if entry.key_scalar().text().eq("preview") {\n'
            "            name = Some(scalar_string(\n"
            '                &expect_scalar(entry.into_value(), "name")?,\n'
            "            ));\n"
            "            continue;\n"
            "        }\n",
            1,
        )
        self.assertNotEqual(mutated, source)
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "reads key_scalar outside the closed",
        ):
            self.validator.action_decoder_field_scopes(mutated)

    def test_container_raw_field_pattern_is_rejected(self) -> None:
        source = (
            ROOT / "crates/automata-ci-workflow-github/src/decode/container.rs"
        ).read_text(encoding="utf-8")
        mutated = source.replace(
            "        match field_name(entry) {\n",
            '        match field_name(entry) { Some(r#"preview-field"#) => true,\n',
            1,
        )
        self.assertNotEqual(mutated, source)
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "must use a canonical normal string literal field",
        ):
            self.validator.container_decoder_field_scopes(mutated)

    def test_container_field_name_comparison_outside_match_is_rejected(self) -> None:
        source = (
            ROOT / "crates/automata-ci-workflow-github/src/decode/container.rs"
        ).read_text(encoding="utf-8")
        mutated = source.replace(
            "    ) -> bool {\n        match field_name(entry) {\n",
            "    ) -> bool {\n"
            '        if field_name(entry) == Some("preview") {\n'
            "            return true;\n"
            "        }\n"
            "        match field_name(entry) {\n",
            1,
        )
        self.assertNotEqual(mutated, source)
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "must use every field_name call directly",
        ):
            self.validator.container_decoder_field_scopes(mutated)

    def test_container_field_name_alias_side_use_is_rejected(self) -> None:
        source = (
            ROOT / "crates/automata-ci-workflow-github/src/decode/container.rs"
        ).read_text(encoding="utf-8")
        mutated = source.replace(
            "        match field_name(entry) {\n",
            "        let candidate = field_name(entry);\n"
            '        if candidate == Some("preview") {\n'
            "            return true;\n"
            "        }\n"
            "        match candidate {\n",
            1,
        )
        self.assertNotEqual(mutated, source)
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "outside its declaration and governed match",
        ):
            self.validator.container_decoder_field_scopes(mutated)

    def test_container_direct_yaml_key_semantic_read_is_rejected(self) -> None:
        source = (
            ROOT / "crates/automata-ci-workflow-github/src/decode/container.rs"
        ).read_text(encoding="utf-8")
        mutated = source.replace(
            "        match field_name(entry) {\n",
            "        if entry.key.as_scalar()\n"
            "            .map(|scalar| scalar.decoded.as_str())\n"
            '            == Some("preview")\n'
            "        {\n"
            "            return true;\n"
            "        }\n"
            "        match field_name(entry) {\n",
            1,
        )
        self.assertNotEqual(mutated, source)
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            r"reads a mapping \.key outside field_name",
        ):
            self.validator.container_decoder_field_scopes(mutated)

    def test_container_aliased_yaml_key_semantic_read_is_rejected(self) -> None:
        source = (
            ROOT / "crates/automata-ci-workflow-github/src/decode/container.rs"
        ).read_text(encoding="utf-8")
        mutated = source.replace(
            "        match field_name(entry) {\n",
            "        let item = entry;\n"
            "        if item.key.as_scalar()\n"
            "            .map(|scalar| scalar.decoded.as_str())\n"
            '            == Some("preview")\n'
            "        {\n"
            "            return true;\n"
            "        }\n"
            "        match field_name(entry) {\n",
            1,
        )
        self.assertNotEqual(mutated, source)
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            r"reads a mapping \.key outside field_name",
        ):
            self.validator.container_decoder_field_scopes(mutated)

    def test_container_yaml_entry_key_destructuring_is_rejected(self) -> None:
        source = (
            ROOT / "crates/automata-ci-workflow-github/src/decode/container.rs"
        ).read_text(encoding="utf-8")
        mutated = source.replace(
            "        match field_name(entry) {\n",
            "        let YamlMappingEntry { key: candidate, .. } = entry;\n"
            "        if candidate.as_scalar()\n"
            "            .map(|scalar| scalar.decoded.as_str())\n"
            '            == Some("preview")\n'
            "        {\n"
            "            return true;\n"
            "        }\n"
            "        match field_name(entry) {\n",
            1,
        )
        self.assertNotEqual(mutated, source)
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "destructures YamlMappingEntry outside",
        ):
            self.validator.container_decoder_field_scopes(mutated)

    def test_container_ufcs_yaml_key_read_is_rejected(self) -> None:
        source = (
            ROOT / "crates/automata-ci-workflow-github/src/decode/container.rs"
        ).read_text(encoding="utf-8")
        mutated = source.replace(
            "        match field_name(entry) {\n",
            "        if YamlMappingEntry::key(entry).as_scalar()\n"
            "            .map(|scalar| scalar.decoded.as_str())\n"
            '            == Some("preview")\n'
            "        {\n"
            "            return true;\n"
            "        }\n"
            "        match field_name(entry) {\n",
            1,
        )
        self.assertNotEqual(mutated, source)
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "calls a UFCS key accessor outside",
        ):
            self.validator.container_decoder_field_scopes(mutated)

    def test_container_local_key_helper_is_rejected(self) -> None:
        source = (
            ROOT / "crates/automata-ci-workflow-github/src/decode/container.rs"
        ).read_text(encoding="utf-8")
        mutated = source.replace(
            "        match field_name(entry) {\n",
            "        if accepts_preview(entry) {\n"
            "            return true;\n"
            "        }\n"
            "        match field_name(entry) {\n",
            1,
        ) + """

fn accepts_preview(entry: &YamlMappingEntry) -> bool {
    entry.key.as_scalar().map(|scalar| scalar.decoded.as_str()) == Some("preview")
}
"""
        self.assertNotEqual(mutated, source)
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            r"reads a mapping \.key outside field_name",
        ):
            self.validator.container_decoder_field_scopes(mutated)

    def test_container_unknown_preservation_cannot_move_behind_helper(self) -> None:
        source = (
            ROOT / "crates/automata-ci-workflow-github/src/decode/container.rs"
        ).read_text(encoding="utf-8")
        mutated = source.replace(
            "context.preserve_unknown(path, entry)",
            "preserve_unknown_field(context, path, entry)",
            1,
        ) + """

fn preserve_unknown_field(
    context: &mut DecodeContext<'_>,
    path: &str,
    entry: &YamlMappingEntry,
) -> Option<PreservedField> {
    context.preserve_unknown(path, entry)
}
"""
        self.assertNotEqual(mutated, source)
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "must directly call preserve_unknown",
        ):
            self.validator.container_decoder_field_scopes(mutated)

    def test_container_typed_field_constant_is_resolved(self) -> None:
        source = (
            ROOT / "crates/automata-ci-workflow-github/src/decode/container.rs"
        ).read_text(encoding="utf-8")
        mutated = (
            'const preview_field: &str = "preview-field";\n' + source
        ).replace(
            '            Some("image") if self.mark_first(IMAGE_FIELD) => {\n',
            "            Some(preview_field) "
            "if self.mark_first(IMAGE_FIELD) => {\n",
            1,
        )
        self.assertNotEqual(mutated, source)
        actual = self.validator.container_decoder_field_scopes(mutated)
        self.assertIn("preview-field", actual["ContainerFields::decode_entry"])

    def test_module_container_kind_constant_preserves_surface(self) -> None:
        source = (
            ROOT / "crates/automata-ci-workflow-github/src/decode/container.rs"
        ).read_text(encoding="utf-8")
        mutated = (
            "const job_kind: ContainerKind = ContainerKind::Job;\n" + source
        ).replace(
            "parse_container(node, path, ContainerKind::Job, context)",
            "parse_container(node, path, job_kind, context)",
            1,
        )
        self.assertNotEqual(mutated, source)
        self.assertEqual(
            self.validator.container_decoder_surface_edges(mutated),
            self.validator.container_decoder_surface_edges(source),
        )

    def test_untyped_container_kind_alias_is_rejected(self) -> None:
        source = (
            ROOT / "crates/automata-ci-workflow-github/src/decode/container.rs"
        ).read_text(encoding="utf-8")
        mutated = source.replace(
            "    parse_container(node, path, ContainerKind::Job, context)\n",
            "    let job_kind = ContainerKind::Job;\n"
            "    parse_container(node, path, job_kind, context)\n",
            1,
        )
        self.assertNotEqual(mutated, source)
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "unresolved kind expression",
        ):
            self.validator.container_decoder_surface_edges(mutated)

    def test_new_same_named_container_caller_is_discovered(self) -> None:
        source = (
            ROOT / "crates/automata-ci-workflow-github/src/decode/container.rs"
        ).read_text(encoding="utf-8")
        mutated = source + """

fn shadow_job_container(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Option<JobContainer> {
    job_container(node, path, context)
}
"""
        inventoried = {
            (
                inventory["surface_function"],
                inventory["kind"],
                inventory["function"],
            )
            for inventory in self.registry["decoder_inventory"]
            if inventory["extractor"] == "container-kind-function-fields"
        }
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "container decoder surface inventory drifted",
        ):
            self.validator.validate_container_surface_coverage(mutated, inventoried)

    def test_underscore_container_kind_is_discovered(self) -> None:
        source = (
            ROOT / "crates/automata-ci-workflow-github/src/decode/container.rs"
        ).read_text(encoding="utf-8")
        mutated = source + """

fn preview_job_container(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Option<JobContainer> {
    parse_container(node, path, ContainerKind::Preview_Job, context)
}
"""
        inventoried = {
            (
                inventory["surface_function"],
                inventory["kind"],
                inventory["function"],
            )
            for inventory in self.registry["decoder_inventory"]
            if inventory["extractor"] == "container-kind-function-fields"
        }
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "container decoder surface inventory drifted",
        ):
            self.validator.validate_container_surface_coverage(mutated, inventoried)

    def test_container_kind_through_pass_through_helper_is_discovered(self) -> None:
        source = (
            ROOT / "crates/automata-ci-workflow-github/src/decode/container.rs"
        ).read_text(encoding="utf-8")
        mutated = source + """

fn preview_container(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Option<JobContainer> {
    pass_through_container(node, path, ContainerKind::Preview, context)
}

fn pass_through_container(
    node: &YamlNode,
    path: &str,
    kind: ContainerKind,
    context: &mut DecodeContext<'_>,
) -> Option<JobContainer> {
    parse_container(node, path, kind, context)
}
"""
        inventoried = {
            (
                inventory["surface_function"],
                inventory["kind"],
                inventory["function"],
            )
            for inventory in self.registry["decoder_inventory"]
            if inventory["extractor"] == "container-kind-function-fields"
        }
        with self.assertRaisesRegex(
            self.validator.CapabilityError,
            "container decoder surface inventory drifted",
        ):
            self.validator.validate_container_surface_coverage(mutated, inventoried)

    def test_commented_and_stringified_surfaces_cannot_spoof_inventory(self) -> None:
        action_source = (
            ROOT / "crates/automata-ci-action-github/src/decoder.rs"
        ).read_text(encoding="utf-8")
        action_mutated = action_source + r'''

/* fn fake_action_surface(fields: Fields) {
    fields.validate_allowed(&["image"], "runs.property");
} */
const FAKE_ACTION_SURFACE: &str = r#"fn fake_action_surface(fields: Fields) {
    fields.validate_allowed(&["image"], "runs.property");
}"#;
'''
        action_inventoried = {
            inventory["function"]
            for inventory in self.registry["decoder_inventory"]
            if inventory["extractor"] == "action-function-fields"
        }
        self.validator.validate_action_surface_coverage(
            action_mutated, action_inventoried
        )

        container_source = (
            ROOT / "crates/automata-ci-workflow-github/src/decode/container.rs"
        ).read_text(encoding="utf-8")
        container_mutated = container_source + r'''

/* fn fake_container_surface() {
    parse_container(node, path, ContainerKind::Job, context);
} */
const FAKE_CONTAINER_SURFACE: &str = r#"fn fake_container_surface() {
    parse_container(node, path, ContainerKind::Job, context);
}"#;
'''
        container_inventoried = {
            (
                inventory["surface_function"],
                inventory["kind"],
                inventory["function"],
            )
            for inventory in self.registry["decoder_inventory"]
            if inventory["extractor"] == "container-kind-function-fields"
        }
        self.validator.validate_container_surface_coverage(
            container_mutated, container_inventoried
        )

    def test_decoder_only_event_cannot_inherit_the_provider_profile(self) -> None:
        def mutate(value: dict[str, Any]) -> None:
            triggers = next(
                inventory
                for inventory in value["decoder_inventory"]
                if inventory["id"] == "trigger-event-names"
            )
            triggers["fields"]["issues"] = "github-provider"

        self.reject(mutate, "trigger feature partition drifted")

    def test_governance_ci_checkout_has_merge_base_history(self) -> None:
        workflow = (ROOT / ".ci/workflows/ci.yml").read_text(encoding="utf-8")
        policy_job = workflow.split("verify-product-targets.sh", maxsplit=1)[0]
        self.assertRegex(
            policy_job,
            r"(?m)^\s+fetch-depth:\s+0\s*$",
            "the policy checkout must retain merge-base history",
        )

    def test_shallow_checkout_without_base_ref_has_actionable_failure(self) -> None:
        spec = importlib.util.spec_from_file_location("capability_validator", SCRIPT)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory)
            source = scratch / "source"
            shallow = scratch / "shallow"

            def git(*arguments: str, cwd: Path | None = None) -> None:
                subprocess.run(
                    ["git", *arguments],
                    cwd=cwd,
                    check=True,
                    capture_output=True,
                    text=True,
                )

            git("init", "--initial-branch=topic", str(source))
            git("config", "user.email", "capability-test@example.invalid", cwd=source)
            git("config", "user.name", "Capability Test", cwd=source)
            (source / "sentinel").write_text("one\n", encoding="utf-8")
            git("add", "sentinel", cwd=source)
            git("commit", "-m", "sentinel", cwd=source)
            git("clone", "--depth", "1", "--branch", "topic", source.as_uri(), str(shallow))
            git("checkout", "--detach", cwd=shallow)
            git("branch", "--delete", "--force", "topic", cwd=shallow)
            git("remote", "remove", "origin", cwd=shallow)

            with self.assertRaisesRegex(module.CapabilityError, "checkout is shallow"):
                module.diagnostic_baseline_revision(shallow)


if __name__ == "__main__":
    unittest.main()
