#!/usr/bin/env python3

import os
import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[3]
RUNNER = ROOT / "scripts" / "ci" / "run-macos-physical-checks.sh"


class MacosPhysicalChecksTest(unittest.TestCase):
    def run_script(
        self, *arguments: str, environment: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        merged_environment = os.environ.copy()
        if environment is not None:
            merged_environment.update(environment)
        return subprocess.run(
            [str(RUNNER), *arguments],
            cwd=ROOT,
            check=False,
            text=True,
            capture_output=True,
            env=merged_environment,
        )

    def test_plan_is_complete_serial_and_secret_safe(self) -> None:
        result = self.run_script("--plan")
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = [line for line in result.stdout.splitlines() if line.startswith("RUN ")]
        self.assertEqual(len(commands), 6, result.stdout)
        for identity in (
            "automata-ci-runner --test runner",
            "automata-ci-sandbox-macos --test macos_provider",
            "automata-ci-sandbox-macos --lib",
        ):
            self.assertTrue(any(identity in command for command in commands), identity)
        for command in commands:
            self.assertIn("--test-threads=1", command)
        self.assertIn("macos_vm_runner_process_e2e::", commands[0])
        self.assertIn(
            "provider_recovers_an_interrupted_launch_and_reuses_the_slot", commands[1]
        )
        self.assertIn("provider_cleans_up_and_reuses_slot_after_live_helper_loss", commands[2])
        self.assertIn(
            "provider_completes_destroy_when_the_helper_dies_during_quiescence",
            commands[3],
        )
        self.assertIn("provider_reconciles_a_live_orphan", commands[4])
        self.assertIn("physical_guest_reaches_an_allowlisted_origin", commands[5])
        self.assertNotIn("HELPER_REQUIREMENT=", result.stdout)
        self.assertNotIn("STORAGE_QUOTA_BYTES=", result.stdout)

    def test_plan_repeats_only_the_shipped_runner_matrix(self) -> None:
        result = self.run_script(
            "--plan", environment={"AUTOMATA_MACOS_PHYSICAL_REPETITIONS": "2"}
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = [line for line in result.stdout.splitlines() if line.startswith("RUN ")]
        self.assertEqual(len(commands), 7, result.stdout)
        self.assertEqual(
            sum("automata-ci-runner --test runner" in command for command in commands), 2
        )
        self.assertEqual(
            sum("--test macos_provider" in command for command in commands), 4
        )

    def test_invalid_repetition_count_fails_closed(self) -> None:
        result = self.run_script(
            "--plan", environment={"AUTOMATA_MACOS_PHYSICAL_REPETITIONS": "0"}
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("integer from 1 through 10", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_unknown_arguments_fail_closed(self) -> None:
        result = self.run_script("--unknown")
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
