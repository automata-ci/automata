#!/usr/bin/env python3

import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[3]
RUNNER = ROOT / "scripts" / "ci" / "run-macos-integration-checks.sh"


class MacosIntegrationChecksTest(unittest.TestCase):
    def run_script(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(RUNNER), *arguments],
            cwd=ROOT,
            check=False,
            text=True,
            capture_output=True,
        )

    def test_plan_is_complete_bounded_and_secret_safe(self) -> None:
        result = self.run_script("--plan")
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = [line for line in result.stdout.splitlines() if line.startswith("RUN ")]
        self.assertEqual(len(commands), 7, result.stdout)
        for identity in (
            "automata-ci-blob-s3 --test blob_s3",
            "automata-ci-action --test live_github_rustfs",
            "automata-ci-action-actions --test live_checkout_pipeline",
            "automata-ci-runner-results --test rustfs_results",
            "automata-ci-runner-results --test cache_rustfs",
            "automata-ci-workflow-service --test live_admission",
            "automata-ci-runner-results --test exact_client_real_store",
        ):
            self.assertTrue(any(identity in command for command in commands), identity)
        for command in commands:
            self.assertIn("--test-threads=1", command)
        self.assertNotIn("ACCESS_KEY=", result.stdout)
        self.assertNotIn("SECRET_KEY=", result.stdout)

    def test_unknown_arguments_fail_closed(self) -> None:
        result = self.run_script("--unknown")
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
