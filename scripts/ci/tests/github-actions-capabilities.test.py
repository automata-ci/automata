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


class CapabilityRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = json.loads(REGISTRY.read_text(encoding="utf-8"))

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
        registry = copy.deepcopy(self.registry)
        reviewed = json.loads(REVIEWED_DELTAS.read_text(encoding="utf-8"))
        mutate(reviewed)
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            prefix="reviewed-delta-mutation-",
            dir=ROOT / "docs/governance",
            encoding="utf-8",
            delete=False,
        ) as reviewed_file:
            reviewed_path = Path(reviewed_file.name)
            json.dump(reviewed, reviewed_file, ensure_ascii=False, indent=2, sort_keys=True)
            reviewed_file.write("\n")
        try:
            registry["reviewed_deltas"] = reviewed_path.relative_to(ROOT).as_posix()
            with tempfile.TemporaryDirectory() as directory:
                registry_path = Path(directory) / "registry.json"
                registry_path.write_text(
                    json.dumps(registry, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                result = self.verify(registry_path)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn(expected, result.stderr)
        finally:
            reviewed_path.unlink(missing_ok=True)

    def test_checked_in_registry_is_valid(self) -> None:
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_decoder_field_without_registry_entry_is_rejected(self) -> None:
        self.reject(
            lambda value: value["decoder_inventory"][0]["fields"].pop("args"),
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

        self.reject(mutate, "governed decoder source inventory drifted")

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
            "does not run automata-ci-secret --test secret_postgres with --ignored",
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
        self.reject(
            lambda value: value["decoder_inventory"][0]["fields"].update(
                {"args": "unregistered-feature"}
            ),
            "references unknown features",
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
