#!/usr/bin/env python3
"""Contract tests for the service-aware Rust coverage policy."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHECK = ROOT / "ci" / "check-rust-coverage.py"
RUN = ROOT / "ci" / "run-rust-coverage.sh"
CHECK_IGNORED = ROOT / "ci" / "check-ignored-test-list.py"
FINGERPRINT = ROOT / "ci" / "fingerprint-workspace.py"


def policy(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "cargo_llvm_cov_version": "0.8.7",
                "llvm_coverage_export_version": "3.1.0",
                "report_scope": {
                    "description": "production source",
                    "ignore_filename_regex": "(/generated/)",
                    "exclusions": [
                        {"name": "generated", "description": "generated source"}
                    ],
                },
                "lanes": {
                    "ordinary": {
                        "description": "ordinary",
                        "service_requirements": [],
                        "source_prefixes": [],
                    },
                    "postgres": {
                        "description": "postgres",
                        "service_requirements": ["PostgreSQL"],
                        "source_prefixes": ["crates/database/src/adapter.rs"],
                    },
                },
                "ordinary_guard": {
                    "line_percent_floor": 82.0,
                    "minimum_measured_lines": 100,
                    "reviewed_baseline": {
                        "covered_lines": 90,
                        "measured_lines": 100,
                        "line_percent": 90.0,
                        "report_date": "2026-08-11",
                    },
                },
            }
        ),
        encoding="utf-8",
    )


def summary(path: Path, ordinary_covered: int) -> None:
    files = [
        {
            "filename": "/checkout/crates/project/crates/core/src/lib.rs",
            "summary": {"lines": {"covered": ordinary_covered, "count": 100}},
        },
        {
            "filename": "/checkout/crates/project/crates/database/src/adapter.rs",
            "summary": {"lines": {"covered": 0, "count": 1000}},
        },
        {
            "filename": "/checkout/crates/project/crates/database/src/adapter.rs_extra",
            "summary": {"lines": {"covered": 0, "count": 0}},
        },
    ]
    path.write_text(
        json.dumps(
            {
                "type": "llvm.coverage.json.export",
                "version": "3.1.0",
                "cargo_llvm_cov": {
                    "version": "0.8.7",
                    "manifest_path": "/checkout/crates/project/Cargo.toml",
                },
                "data": [
                    {
                        "files": files,
                        "totals": {
                            "lines": {"covered": ordinary_covered, "count": 1100}
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def lcov(path: Path, ordinary_covered: int) -> None:
    path.write_text(
        "\n".join(
            [
                "SF:crates/core/src/lib.rs",
                "DA:1,1",
                f"DA:2,{1 if ordinary_covered else 0}",
                f"LF:100",
                f"LH:{ordinary_covered}",
                "end_of_record",
                "SF:crates/database/src/adapter.rs",
                "DA:1,0",
                "LF:1000",
                "LH:0",
                "end_of_record",
                "SF:crates/database/src/adapter.rs_extra",
                "LF:0",
                "LH:0",
                "end_of_record",
                "",
            ]
        ),
        encoding="utf-8",
    )


def synthetic_workspace_reports(
    policy_path: Path,
    summary_path: Path,
    lcov_path: Path,
    ordinary_covered: int,
) -> None:
    configuration = json.loads(policy_path.read_text(encoding="utf-8"))
    sources = [("crates/core/src/lib.rs", ordinary_covered, 172_000)]
    for lane, lane_policy in configuration["lanes"].items():
        if lane == "ordinary":
            continue
        for prefix in lane_policy["source_prefixes"]:
            source = f"{prefix}coverage_contract.rs" if prefix.endswith("/") else prefix
            sources.append((source, 0, 1))
    assert len({source for source, _, _ in sources}) == len(sources)
    summary_path.write_text(
        json.dumps(
            {
                "type": "llvm.coverage.json.export",
                "version": configuration["llvm_coverage_export_version"],
                "cargo_llvm_cov": {
                    "version": configuration["cargo_llvm_cov_version"],
                    "manifest_path": "Cargo.toml",
                },
                "data": [
                    {
                        "files": [
                            {
                                "filename": source,
                                "summary": {
                                    "lines": {"covered": covered, "count": measured}
                                },
                            }
                            for source, covered, measured in sources
                        ],
                        "totals": {
                            "lines": {
                                "covered": sum(covered for _, covered, _ in sources),
                                "count": sum(measured for _, _, measured in sources),
                            }
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    lcov_path.write_text(
        "".join(
            f"SF:{source}\nDA:1,{1 if covered else 0}\n"
            f"LF:{measured}\nLH:{covered}\nend_of_record\n"
            for source, covered, measured in sources
        ),
        encoding="utf-8",
    )


def check(
    policy_path: Path,
    summary_path: Path,
    lcov_path: Path,
    manifest_path: Path,
    lane: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "python3",
            str(CHECK),
            "--policy",
            str(policy_path),
            "--summary",
            str(summary_path),
            "--lcov",
            str(lcov_path),
            "--manifest",
            str(manifest_path),
            "--lane",
            lane,
            "--source-head",
            "0123456789abcdef0123456789abcdef01234567",
            "--source-content-digest",
            "89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567",
            "--source-state-token",
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            "--source-entry-count",
            "3",
        ],
        check=False,
        text=True,
        capture_output=True,
    )


def fingerprint(repository: Path) -> tuple[str, str, str, str]:
    completed = subprocess.run(
        ["python3", str(FINGERPRINT), "--repository", str(repository)],
        check=True,
        text=True,
        capture_output=True,
    )
    fields = completed.stdout.split()
    assert len(fields) == 4, completed.stdout
    return fields[0], fields[1], fields[2], fields[3]


def main() -> None:
    scratch_root = ROOT.parent / "target" / "task-tmp"
    scratch_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="rust-coverage-contract-", dir=scratch_root) as raw:
        scratch = Path(raw)
        policy_path = scratch / "policy.json"
        summary_path = scratch / "summary.json"
        lcov_path = scratch / "coverage.lcov"
        manifest_path = scratch / "manifest.json"
        policy(policy_path)

        summary(summary_path, 90)
        lcov(lcov_path, 90)
        passed = check(policy_path, summary_path, lcov_path, manifest_path, "ordinary")
        assert passed.returncode == 0, passed.stderr
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert manifest["report"]["in_scope_compiled_source"]["line_percent"] < 10
        assert manifest["report"]["ordinary_owned_source"]["line_percent"] == 90
        assert manifest["report"]["ordinary_owned_source"]["files"] == 2
        assert manifest["guard"]["status"] == "passed"
        assert manifest["test_bundles"]["not_requested"] == ["postgres"]
        assert manifest["artifacts"]["summary_json"] == {
            "bytes": summary_path.stat().st_size,
            "sha256": hashlib.sha256(summary_path.read_bytes()).hexdigest(),
        }
        assert manifest["artifacts"]["lcov"] == {
            "bytes": lcov_path.stat().st_size,
            "sha256": hashlib.sha256(lcov_path.read_bytes()).hexdigest(),
        }
        assert manifest["source_snapshot"]["paths"] == 3
        assert manifest["source_snapshot"]["content_algorithm"] == (
            "sha256-framed-git-head-and-nonignored-worktree-content-v1"
        )

        manifest_parent_file = scratch / "manifest-parent-file"
        manifest_parent_file.write_text("not a directory\n", encoding="utf-8")
        failed_manifest_path = manifest_parent_file / "manifest.json"
        failed_write = check(
            policy_path,
            summary_path,
            lcov_path,
            failed_manifest_path,
            "ordinary",
        )
        assert failed_write.returncode == 2
        assert "error:" in failed_write.stderr
        assert "Traceback" not in failed_write.stderr
        assert not failed_manifest_path.exists()

        mismatched_lcov = lcov_path.read_text(encoding="utf-8").replace(
            "LH:90", "LH:89", 1
        )
        lcov_path.write_text(mismatched_lcov, encoding="utf-8")
        mismatch = check(
            policy_path, summary_path, lcov_path, manifest_path, "ordinary"
        )
        assert mismatch.returncode == 2
        assert "LCOV and JSON line totals differ" in mismatch.stderr
        assert not manifest_path.exists()
        lcov(lcov_path, 90)
        lcov_path.write_text(
            lcov_path.read_text(encoding="utf-8").replace(
                "SF:crates/core/src/lib.rs",
                "SF:crates/core/src/other.rs",
                1,
            ),
            encoding="utf-8",
        )
        source_mismatch = check(
            policy_path, summary_path, lcov_path, manifest_path, "ordinary"
        )
        assert source_mismatch.returncode == 2
        assert "LCOV and JSON source sets differ" in source_mismatch.stderr
        assert not manifest_path.exists()
        lcov(lcov_path, 90)
        canonical_lcov = lcov_path.read_text(encoding="utf-8")
        malformed_lcov_documents = [
            (canonical_lcov.replace("LF:100", "LF:+100", 1), "invalid LF value"),
            (canonical_lcov.replace("DA:1,1", "DA:0,1", 1), "invalid DA value"),
            (canonical_lcov.replace("DA:1,1", "DA:1,-1", 1), "invalid DA value"),
            (
                canonical_lcov.replace("DA:1,1\n", "DA:1,1\nDA:1,0\n", 1),
                "duplicate DA line 1",
            ),
            (
                canonical_lcov.replace("LF:100\n", "LF:100\nLF:100\n", 1),
                "invalid LF field",
            ),
            (
                canonical_lcov.replace("DA:1,1\nDA:2,1\n", "", 1),
                "positive LF but no DA records",
            ),
            (canonical_lcov.replace("LH:90\n", "", 1), "incomplete source record"),
            (
                canonical_lcov
                + "SF:crates/core/src/lib.rs\nLF:100\nLH:90\nend_of_record\n",
                "source appears more than once",
            ),
        ]
        for malformed_lcov, expected_error in malformed_lcov_documents:
            lcov_path.write_text(malformed_lcov, encoding="utf-8")
            malformed = check(
                policy_path, summary_path, lcov_path, manifest_path, "ordinary"
            )
            assert malformed.returncode == 2
            assert expected_error in malformed.stderr
            assert not manifest_path.exists()
        lcov(lcov_path, 90)

        # Real LLVM region accounting can report fewer LH lines than positive
        # DA records and fewer DA records than LF. This purpose-built fixture
        # has two positive DA records, LH=1, and LF=100. The checker validates
        # DA structure and binds its bytes, while SF/LF/LH remain the exact
        # cross-format contract with the JSON summary.
        summary(summary_path, 1)
        lcov(lcov_path, 1)
        aggregate_divergence = check(
            policy_path, summary_path, lcov_path, manifest_path, "postgres"
        )
        assert aggregate_divergence.returncode == 0, aggregate_divergence.stderr
        summary(summary_path, 90)
        lcov(lcov_path, 90)

        valid_summary = json.loads(summary_path.read_text(encoding="utf-8"))
        invalid_documents = []
        wrong_type = json.loads(json.dumps(valid_summary))
        wrong_type["type"] = "not.llvm.coverage"
        invalid_documents.append((wrong_type, "wrong LLVM export type"))
        wrong_version = json.loads(json.dumps(valid_summary))
        wrong_version["version"] = "0.0.0"
        invalid_documents.append((wrong_version, "LLVM export version"))
        missing_totals = json.loads(json.dumps(valid_summary))
        missing_totals["data"][0]["totals"] = None
        invalid_documents.append((missing_totals, "totals must be an object"))
        for invalid_document, expected_error in invalid_documents:
            summary_path.write_text(json.dumps(invalid_document), encoding="utf-8")
            invalid_summary = check(
                policy_path, summary_path, lcov_path, manifest_path, "ordinary"
            )
            assert invalid_summary.returncode == 2
            assert expected_error in invalid_summary.stderr
            assert not manifest_path.exists(), "invalid recheck retained an old manifest"

        summary(summary_path, 90)

        nonproduction_summary = json.loads(summary_path.read_text(encoding="utf-8"))
        nonproduction_summary["data"][0]["files"].append(
            {
                "filename": "/checkout/crates/project/crates/core/tests/smoke.rs",
                "summary": {"lines": {"covered": 5, "count": 5}},
            }
        )
        nonproduction_summary["data"][0]["totals"]["lines"] = {
            "covered": 95,
            "count": 1105,
        }
        summary_path.write_text(json.dumps(nonproduction_summary), encoding="utf-8")
        nonproduction = check(
            policy_path, summary_path, lcov_path, manifest_path, "ordinary"
        )
        assert nonproduction.returncode == 2
        assert "contains nonproduction source" in nonproduction.stderr

        summary(summary_path, 81)
        lcov(lcov_path, 81)
        failed = check(policy_path, summary_path, lcov_path, manifest_path, "ordinary")
        assert failed.returncode == 1
        assert json.loads(manifest_path.read_text(encoding="utf-8"))["guard"]["status"] == "failed"

        report_only = check(
            policy_path, summary_path, lcov_path, manifest_path, "postgres"
        )
        assert report_only.returncode == 0, report_only.stderr
        assert (
            json.loads(manifest_path.read_text(encoding="utf-8"))["guard"]["status"]
            == "report-only"
        )

        invalid_policy = json.loads(policy_path.read_text(encoding="utf-8"))
        invalid_policy["ordinary_guard"]["reviewed_baseline"]["line_percent"] = 91.0
        policy_path.write_text(json.dumps(invalid_policy), encoding="utf-8")
        invalid = check(policy_path, summary_path, lcov_path, manifest_path, "ordinary")
        assert invalid.returncode == 2
        assert "baseline line percent does not match" in invalid.stderr
        assert not manifest_path.exists()

        selected = subprocess.run(
            ["python3", str(CHECK_IGNORED)],
            input="suite::first: test\nsuite::second: test\n2 tests, 0 benchmarks\n",
            check=False,
            text=True,
            capture_output=True,
        )
        assert selected.returncode == 0, selected.stderr
        assert selected.stdout == "2\n"
        duplicate_names_across_binaries = subprocess.run(
            ["python3", str(CHECK_IGNORED)],
            input="same_name: test\nsame_name: test\n",
            check=False,
            text=True,
            capture_output=True,
        )
        assert duplicate_names_across_binaries.returncode == 0
        assert duplicate_names_across_binaries.stdout == "2\n"
        empty = subprocess.run(
            ["python3", str(CHECK_IGNORED)],
            input="suite::benchmark: benchmark\n0 tests, 1 benchmark\n",
            check=False,
            text=True,
            capture_output=True,
        )
        assert empty.returncode == 2
        assert "selected zero tests" in empty.stderr

        fingerprint_repository = scratch / "fingerprint-repository"
        fingerprint_repository.mkdir()
        subprocess.run(
            ["git", "init", "--quiet", str(fingerprint_repository)], check=True
        )
        subprocess.run(
            ["git", "-C", str(fingerprint_repository), "config", "user.name", "Test"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(fingerprint_repository),
                "config",
                "user.email",
                "test@example.invalid",
            ],
            check=True,
        )
        (fingerprint_repository / ".gitignore").write_text("ignored/\n", encoding="utf-8")
        tracked = fingerprint_repository / "tracked.txt"
        tracked.write_text("tracked\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(fingerprint_repository), "add", ".gitignore", "tracked.txt"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(fingerprint_repository), "commit", "--quiet", "-m", "base"],
            check=True,
        )
        initial_fingerprint = fingerprint(fingerprint_repository)
        ignored_directory = fingerprint_repository / "ignored"
        ignored_directory.mkdir()
        (ignored_directory / "runtime.bin").write_bytes(b"ignored")
        assert fingerprint(fingerprint_repository) == initial_fingerprint
        untracked = fingerprint_repository / "untracked.txt"
        untracked.write_text("new\n", encoding="utf-8")
        assert fingerprint(fingerprint_repository) != initial_fingerprint
        untracked.unlink()
        assert fingerprint(fingerprint_repository) == initial_fingerprint
        tracked.write_text("changed\n", encoding="utf-8")
        assert fingerprint(fingerprint_repository) != initial_fingerprint
        tracked.write_text("tracked\n", encoding="utf-8")
        restored_fingerprint = fingerprint(fingerprint_repository)
        assert restored_fingerprint[0] == initial_fingerprint[0]
        assert restored_fingerprint[1] == initial_fingerprint[1]
        assert restored_fingerprint[2] != initial_fingerprint[2]
        assert restored_fingerprint[3] == initial_fingerprint[3]
        fingerprint_clone = scratch / "fingerprint-clone"
        subprocess.run(
            [
                "git",
                "clone",
                "--quiet",
                str(fingerprint_repository),
                str(fingerprint_clone),
            ],
            check=True,
        )
        cloned_fingerprint = fingerprint(fingerprint_clone)
        assert cloned_fingerprint[0] == restored_fingerprint[0]
        assert cloned_fingerprint[1] == restored_fingerprint[1]
        subprocess.run(
            [
                "git",
                "-C",
                str(fingerprint_repository),
                "commit",
                "--quiet",
                "--allow-empty",
                "-m",
                "new head",
            ],
            check=True,
        )
        assert fingerprint(fingerprint_repository) != initial_fingerprint

        runner_repository = scratch / "runner-repository"
        runner_ci = runner_repository / "scripts" / "ci"
        runner_ci.mkdir(parents=True)
        for script_name in [
            "check-ignored-test-list.py",
            "check-rust-coverage.py",
            "fingerprint-workspace.py",
            "postgres-test-environment.sh",
            "run-postgres-tests.sh",
            "run-rust-coverage.sh",
            "rust-coverage-policy.json",
            "validate-rust-coverage-failure.py",
        ]:
            shutil.copy2(ROOT / "ci" / script_name, runner_ci / script_name)
        (runner_repository / ".gitignore").write_text("/target/\n", encoding="utf-8")
        subprocess.run(["git", "init", "--quiet", str(runner_repository)], check=True)
        subprocess.run(
            ["git", "-C", str(runner_repository), "config", "user.name", "Test"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(runner_repository),
                "config",
                "user.email",
                "test@example.invalid",
            ],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(runner_repository), "add", "."], check=True
        )
        subprocess.run(
            ["git", "-C", str(runner_repository), "commit", "--quiet", "-m", "runner"],
            check=True,
        )
        runner_fake_bin = scratch / "runner-fake-bin"
        runner_fake_bin.mkdir()
        runner_fake_cargo = runner_fake_bin / "cargo"
        runner_fake_cargo.write_text(
            """#!/usr/bin/env python3
import os
import json
import re
import shutil
import sys
from pathlib import Path

arguments = sys.argv[1:]
log_path = os.environ.get("AUTOMATA_COVERAGE_CARGO_LOG")
if log_path:
    with Path(log_path).open("a", encoding="utf-8") as log:
        log.write(json.dumps(arguments) + "\\n")
if arguments == ["llvm-cov", "--version"]:
    print("cargo-llvm-cov 0.8.7")
elif arguments[:2] == ["llvm-cov", "show-env"]:
    Path(os.environ["AUTOMATA_COVERAGE_TARGET_CAPTURE"]).write_text(
        os.environ.get("CARGO_TARGET_DIR", ""), encoding="utf-8"
    )
    print("export LLVM_PROFILE_FILE=/dev/null")
elif arguments[:2] == ["llvm-cov", "clean"]:
    pass
elif arguments and arguments[0] == "test":
    mutation = os.environ.get("AUTOMATA_COVERAGE_MUTATION")
    if mutation:
        Path(mutation).write_text("changed during coverage\\n", encoding="utf-8")
    postgres_mutation = os.environ.get("AUTOMATA_COVERAGE_POSTGRES_MUTATION")
    if postgres_mutation and "automata-ci-postgres" in arguments:
        Path(postgres_mutation).write_text(
            "changed during PostgreSQL coverage\\n", encoding="utf-8"
        )
    if (
        os.environ.get("AUTOMATA_COVERAGE_FAIL_POSTGRES") == "1"
        and "automata-ci-postgres" in arguments
    ):
        raise SystemExit(88)
elif arguments and arguments[0] == "run":
    pass
elif arguments[:2] == ["llvm-cov", "report"]:
    ignore_argument = next(
        (
            argument
            for argument in arguments
            if argument.startswith("--ignore-filename-regex=")
        ),
        None,
    )
    generated_source = (
        "target/llvm-cov-target/debug/build/automata-ci-provisioning-grpc-"
        "303a492b5e06c8cb/out/automata.management.v1.rs"
    )
    if ignore_argument is None or re.search(
        ignore_argument.removeprefix("--ignore-filename-regex="), generated_source
    ) is None:
        raise SystemExit(98)
    output = Path(arguments[arguments.index("--output-path") + 1])
    fixture = (
        os.environ["AUTOMATA_COVERAGE_JSON_FIXTURE"]
        if "--json" in arguments
        else os.environ["AUTOMATA_COVERAGE_LCOV_FIXTURE"]
    )
    shutil.copyfile(fixture, output)
else:
    raise SystemExit(99)
""",
            encoding="utf-8",
        )
        runner_fake_cargo.chmod(0o755)
        real_mv = shutil.which("mv")
        assert real_mv is not None
        runner_fake_mv = runner_fake_bin / "mv"
        runner_fake_mv.write_text(
            f"""#!/usr/bin/env python3
import os
import sys
from pathlib import Path

counter_path = os.environ.get("AUTOMATA_COVERAGE_MV_COUNTER")
if counter_path:
    counter = Path(counter_path)
    invocation = int(counter.read_text(encoding="utf-8")) + 1 if counter.exists() else 1
    counter.write_text(str(invocation), encoding="utf-8")
    fail_at = int(os.environ.get("AUTOMATA_COVERAGE_MV_FAIL_AT", "2"))
    if invocation == fail_at:
        raise SystemExit(74)
os.execv({real_mv!r}, [{real_mv!r}, *sys.argv[1:]])
""",
            encoding="utf-8",
        )
        runner_fake_mv.chmod(0o755)
        synthetic_summary = scratch / "synthetic-summary.json"
        synthetic_lcov = scratch / "synthetic-coverage.lcov"
        synthetic_workspace_reports(
            runner_ci / "rust-coverage-policy.json",
            synthetic_summary,
            synthetic_lcov,
            141_040,
        )
        runner_environment = dict(os.environ)
        runner_environment["PATH"] = f"{runner_fake_bin}:{runner_environment['PATH']}"
        runner_environment["AUTOMATA_COVERAGE_JSON_FIXTURE"] = str(synthetic_summary)
        runner_environment["AUTOMATA_COVERAGE_LCOV_FIXTURE"] = str(synthetic_lcov)
        runner_target_capture = scratch / "runner-target.txt"
        runner_environment["AUTOMATA_COVERAGE_TARGET_CAPTURE"] = str(
            runner_target_capture
        )
        runner_under_test = runner_ci / "run-rust-coverage.sh"

        successful_output = runner_repository / "target" / "coverage-success"
        successful_runner = subprocess.run(
            [str(runner_under_test), str(successful_output), "ordinary"],
            cwd=runner_repository,
            env=runner_environment,
            check=False,
            text=True,
            capture_output=True,
        )
        assert successful_runner.returncode == 0, successful_runner.stderr
        assert runner_target_capture.read_text(encoding="utf-8") == str(
            runner_repository / "target" / "llvm-cov-target"
        )
        successful_manifest = json.loads(
            (successful_output / "manifest.json").read_text(encoding="utf-8")
        )
        assert successful_manifest["guard"]["status"] == "passed"
        for artifact_name, manifest_name in [
            ("summary.json", "summary_json"),
            ("coverage.lcov", "lcov"),
        ]:
            artifact = successful_output / artifact_name
            assert successful_manifest["artifacts"][manifest_name]["sha256"] == (
                hashlib.sha256(artifact.read_bytes()).hexdigest()
            )
        assert not list(successful_output.glob(".rust-coverage-stage.*"))

        failed_summary = scratch / "synthetic-failed-summary.json"
        failed_lcov = scratch / "synthetic-failed-coverage.lcov"
        synthetic_workspace_reports(
            runner_ci / "rust-coverage-policy.json",
            failed_summary,
            failed_lcov,
            140_000,
        )
        combined_environment = dict(runner_environment)
        combined_environment["AUTOMATA_TEST_DATABASE_URL"] = (
            "postgresql://unused.invalid/coverage"
        )
        combined_log = scratch / "combined-cargo.jsonl"
        combined_environment["AUTOMATA_COVERAGE_CARGO_LOG"] = str(combined_log)
        combined_output = runner_repository / "target" / "coverage-combined"
        combined_runner = subprocess.run(
            [
                str(runner_under_test),
                str(combined_output),
                "ordinary",
                "postgres",
            ],
            cwd=runner_repository,
            env=combined_environment,
            check=False,
            text=True,
            capture_output=True,
        )
        assert combined_runner.returncode == 0, combined_runner.stderr
        ordinary_manifest = json.loads(
            (combined_output / "manifest.json").read_text(encoding="utf-8")
        )
        combined_manifest = json.loads(
            (combined_output / "combined-manifest.json").read_text(
                encoding="utf-8"
            )
        )
        assert ordinary_manifest["test_bundles"]["requested"] == ["ordinary"]
        assert ordinary_manifest["guard"]["status"] == "passed"
        assert combined_manifest["test_bundles"]["requested"] == [
            "ordinary",
            "postgres",
        ]
        assert combined_manifest["guard"]["status"] == "report-only"
        assert all(
            (combined_output / name).is_file()
            for name in [
                "summary.json",
                "coverage.lcov",
                "manifest.json",
                "combined-summary.json",
                "combined-coverage.lcov",
                "combined-manifest.json",
            ]
        )
        combined_commands = [
            json.loads(line)
            for line in combined_log.read_text(encoding="utf-8").splitlines()
        ]
        assert any(
            command[:2] == ["test", "--workspace"]
            for command in combined_commands
        )
        assert any(
            command and command[0] == "test" and "automata-ci-postgres" in command
            for command in combined_commands
        )
        workspace_index = next(
            index
            for index, command in enumerate(combined_commands)
            if command[:2] == ["test", "--workspace"]
        )
        report_indices = [
            index
            for index, command in enumerate(combined_commands)
            if command[:2] == ["llvm-cov", "report"]
        ]
        postgres_index = next(
            index
            for index, command in enumerate(combined_commands)
            if command and command[0] == "test" and "automata-ci-postgres" in command
        )
        cleanup_index = next(
            index
            for index, command in enumerate(combined_commands)
            if command and command[0] == "run"
        )
        assert len(report_indices) == 4
        assert (
            workspace_index
            < report_indices[0]
            < report_indices[1]
            < postgres_index
            < cleanup_index
            < report_indices[2]
            < report_indices[3]
        )

        failed_combined_environment = dict(combined_environment)
        failed_combined_environment["AUTOMATA_COVERAGE_JSON_FIXTURE"] = str(
            failed_summary
        )
        failed_combined_environment["AUTOMATA_COVERAGE_LCOV_FIXTURE"] = str(
            failed_lcov
        )
        failed_combined_log = scratch / "failed-combined-cargo.jsonl"
        failed_combined_environment["AUTOMATA_COVERAGE_CARGO_LOG"] = str(
            failed_combined_log
        )
        failed_combined_output = (
            runner_repository / "target" / "coverage-combined-guard-failed"
        )
        failed_combined_runner = subprocess.run(
            [
                str(runner_under_test),
                str(failed_combined_output),
                "ordinary",
                "postgres",
            ],
            cwd=runner_repository,
            env=failed_combined_environment,
            check=False,
            text=True,
            capture_output=True,
        )
        assert failed_combined_runner.returncode == 1
        failed_combined_manifest = json.loads(
            (failed_combined_output / "manifest.json").read_text(encoding="utf-8")
        )
        assert failed_combined_manifest["test_bundles"]["requested"] == [
            "ordinary"
        ]
        assert failed_combined_manifest["guard"]["status"] == "failed"
        assert not any(
            (failed_combined_output / name).exists()
            for name in [
                "combined-summary.json",
                "combined-coverage.lcov",
                "combined-manifest.json",
            ]
        )
        failed_combined_commands = [
            json.loads(line)
            for line in failed_combined_log.read_text(encoding="utf-8").splitlines()
        ]
        assert not any(
            command and command[0] == "test" and "automata-ci-postgres" in command
            for command in failed_combined_commands
        )

        postgres_mutation_path = runner_repository / "postgres-mutation.txt"
        postgres_mutation_environment = dict(combined_environment)
        postgres_mutation_environment["AUTOMATA_COVERAGE_POSTGRES_MUTATION"] = str(
            postgres_mutation_path
        )
        postgres_mutation_output = (
            runner_repository / "target" / "coverage-postgres-mutation"
        )
        postgres_mutation_runner = subprocess.run(
            [
                str(runner_under_test),
                str(postgres_mutation_output),
                "ordinary",
                "postgres",
            ],
            cwd=runner_repository,
            env=postgres_mutation_environment,
            check=False,
            text=True,
            capture_output=True,
        )
        assert postgres_mutation_runner.returncode == 2
        assert "workspace source changed" in postgres_mutation_runner.stderr
        assert not any(
            (postgres_mutation_output / name).exists()
            for name in [
                "summary.json",
                "coverage.lcov",
                "manifest.json",
                "combined-summary.json",
                "combined-coverage.lcov",
                "combined-manifest.json",
            ]
        )
        postgres_mutation_path.unlink()

        postgres_failure_log = scratch / "postgres-failure-cargo.jsonl"
        postgres_failure_environment = dict(combined_environment)
        postgres_failure_environment["AUTOMATA_COVERAGE_CARGO_LOG"] = str(
            postgres_failure_log
        )
        postgres_failure_environment["AUTOMATA_COVERAGE_FAIL_POSTGRES"] = "1"
        postgres_failure_output = (
            runner_repository / "target" / "coverage-postgres-failure"
        )
        postgres_failure_runner = subprocess.run(
            [
                str(runner_under_test),
                str(postgres_failure_output),
                "ordinary",
                "postgres",
            ],
            cwd=runner_repository,
            env=postgres_failure_environment,
            check=False,
            text=True,
            capture_output=True,
        )
        assert postgres_failure_runner.returncode == 88
        postgres_failure_commands = [
            json.loads(line)
            for line in postgres_failure_log.read_text(encoding="utf-8").splitlines()
        ]
        assert sum(
            command and command[0] == "run"
            for command in postgres_failure_commands
        ) == 1
        assert not any(
            (postgres_failure_output / name).exists()
            for name in [
                "summary.json",
                "coverage.lcov",
                "manifest.json",
                "combined-summary.json",
                "combined-coverage.lcov",
                "combined-manifest.json",
            ]
        )

        combined_publication_output = (
            runner_repository / "target" / "coverage-combined-publication"
        )
        combined_publication_counter = scratch / "combined-mv-counter.txt"
        combined_publication_environment = dict(combined_environment)
        combined_publication_environment["AUTOMATA_COVERAGE_MV_COUNTER"] = str(
            combined_publication_counter
        )
        combined_publication_environment["AUTOMATA_COVERAGE_MV_FAIL_AT"] = "6"
        combined_publication_runner = subprocess.run(
            [
                str(runner_under_test),
                str(combined_publication_output),
                "ordinary",
                "postgres",
            ],
            cwd=runner_repository,
            env=combined_publication_environment,
            check=False,
            text=True,
            capture_output=True,
        )
        assert combined_publication_runner.returncode == 74
        assert combined_publication_counter.read_text(encoding="utf-8") == "6"
        assert not any(
            (combined_publication_output / name).exists()
            for name in [
                "summary.json",
                "coverage.lcov",
                "manifest.json",
                "combined-summary.json",
                "combined-coverage.lcov",
                "combined-manifest.json",
            ]
        )

        reversed_plan = subprocess.run(
            [
                str(runner_under_test),
                "--plan",
                str(runner_repository / "target" / "coverage-reversed"),
                "postgres",
                "ordinary",
            ],
            cwd=runner_repository,
            check=False,
            text=True,
            capture_output=True,
        )
        assert reversed_plan.returncode == 2
        assert "ordinary must be the first lane" in reversed_plan.stderr

        mutation_output = runner_repository / "target" / "coverage-mutation"
        mutation_path = runner_repository / "source-mutation.txt"
        mutation_environment = dict(runner_environment)
        mutation_environment["AUTOMATA_COVERAGE_MUTATION"] = str(mutation_path)
        mutated_runner = subprocess.run(
            [str(runner_under_test), str(mutation_output), "ordinary"],
            cwd=runner_repository,
            env=mutation_environment,
            check=False,
            text=True,
            capture_output=True,
        )
        assert mutated_runner.returncode == 2
        assert "workspace source changed" in mutated_runner.stderr
        assert not any(
            (mutation_output / name).exists()
            for name in ["summary.json", "coverage.lcov", "manifest.json"]
        )
        assert not list(mutation_output.glob(".rust-coverage-stage.*"))
        mutation_path.unlink()

        invalid_lcov = scratch / "synthetic-invalid.lcov"
        invalid_lcov.write_text(
            synthetic_lcov.read_text(encoding="utf-8").replace("LH:141040", "LH:1", 1),
            encoding="utf-8",
        )
        invalid_environment = dict(runner_environment)
        invalid_environment["AUTOMATA_COVERAGE_LCOV_FIXTURE"] = str(invalid_lcov)
        invalid_output = runner_repository / "target" / "coverage-invalid"
        invalid_runner = subprocess.run(
            [str(runner_under_test), str(invalid_output), "ordinary"],
            cwd=runner_repository,
            env=invalid_environment,
            check=False,
            text=True,
            capture_output=True,
        )
        assert invalid_runner.returncode == 2
        assert "LCOV and JSON line totals differ" in invalid_runner.stderr
        assert not any(
            (invalid_output / name).exists()
            for name in ["summary.json", "coverage.lcov", "manifest.json"]
        )

        failed_environment = dict(runner_environment)
        failed_environment["AUTOMATA_COVERAGE_JSON_FIXTURE"] = str(failed_summary)
        failed_environment["AUTOMATA_COVERAGE_LCOV_FIXTURE"] = str(failed_lcov)
        guard_output = runner_repository / "target" / "coverage-guard-failed"
        guard_runner = subprocess.run(
            [str(runner_under_test), str(guard_output), "ordinary"],
            cwd=runner_repository,
            env=failed_environment,
            check=False,
            text=True,
            capture_output=True,
        )
        assert guard_runner.returncode == 1
        assert json.loads(
            (guard_output / "manifest.json").read_text(encoding="utf-8")
        )["guard"]["status"] == "failed"
        assert all(
            (guard_output / name).is_file()
            for name in ["summary.json", "coverage.lcov", "manifest.json"]
        )

        publication_output = runner_repository / "target" / "coverage-publication"
        publication_counter = scratch / "mv-counter.txt"
        publication_environment = dict(runner_environment)
        publication_environment["AUTOMATA_COVERAGE_MV_COUNTER"] = str(
            publication_counter
        )
        publication_runner = subprocess.run(
            [str(runner_under_test), str(publication_output), "ordinary"],
            cwd=runner_repository,
            env=publication_environment,
            check=False,
            text=True,
            capture_output=True,
        )
        assert publication_runner.returncode == 74
        assert not any(
            (publication_output / name).exists()
            for name in ["summary.json", "coverage.lcov", "manifest.json"]
        )
        assert not list(publication_output.glob(".rust-coverage-stage.*"))

        checker_under_test = runner_ci / "check-rust-coverage.py"
        real_checker = runner_ci / "real-check-rust-coverage.py"
        shutil.copy2(checker_under_test, real_checker)
        checker_under_test.write_text(
            """#!/usr/bin/env python3
import json
import os
import subprocess
import sys
from pathlib import Path

arguments = sys.argv[1:]
manifest = Path(arguments[arguments.index("--manifest") + 1])
mode = os.environ["AUTOMATA_FAKE_CHECKER_MODE"]
if mode == "malformed":
    manifest.write_text("{", encoding="utf-8")
elif mode == "partial":
    manifest.write_text(
        json.dumps({"schema_version": 1, "guard": {"status": "failed"}}),
        encoding="utf-8",
    )
elif mode == "passed":
    completed = subprocess.run(
        [sys.executable, str(Path(__file__).with_name("real-check-rust-coverage.py")), *arguments],
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)
elif mode != "missing":
    raise SystemExit(99)
raise SystemExit(1)
""",
            encoding="utf-8",
        )
        checker_under_test.chmod(0o755)
        for fake_checker_mode in ["missing", "malformed", "partial", "passed"]:
            fake_checker_environment = dict(runner_environment)
            fake_checker_environment["AUTOMATA_FAKE_CHECKER_MODE"] = fake_checker_mode
            fake_checker_output = (
                runner_repository
                / "target"
                / f"coverage-checker-{fake_checker_mode}"
            )
            fake_checker_runner = subprocess.run(
                [str(runner_under_test), str(fake_checker_output), "ordinary"],
                cwd=runner_repository,
                env=fake_checker_environment,
                check=False,
                text=True,
                capture_output=True,
            )
            assert fake_checker_runner.returncode == 2, (
                fake_checker_mode,
                fake_checker_runner.stdout,
                fake_checker_runner.stderr,
            )
            assert (
                "coverage checker exited 1 without a complete failed-guard manifest"
                in fake_checker_runner.stderr
            )
            assert not any(
                (fake_checker_output / name).exists()
                for name in ["summary.json", "coverage.lcov", "manifest.json"]
            )
            assert not list(fake_checker_output.glob(".rust-coverage-stage.*"))

        locked_output = scratch / "locked-output"
        locked_output.mkdir()
        for locked_name in ["coverage.lcov", "manifest.json", "summary.json"]:
            (locked_output / locked_name).write_text("owned", encoding="utf-8")
        lock_path = ROOT.parent / "target" / "llvm-cov-target.lock"
        with lock_path.open("a+", encoding="utf-8") as coverage_lock:
            fcntl.flock(coverage_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked_probe = subprocess.run(
                [str(RUN), str(locked_output), "ordinary"],
                cwd=ROOT.parent,
                check=False,
                text=True,
                capture_output=True,
            )
        assert locked_probe.returncode == 2
        assert "another Rust coverage run" in locked_probe.stderr
        assert all(
            (locked_output / locked_name).read_text(encoding="utf-8") == "owned"
            for locked_name in ["coverage.lcov", "manifest.json", "summary.json"]
        )

        stale_output = scratch / "stale-output"
        stale_output.mkdir()
        for stale_name in ["coverage.lcov", "manifest.json", "summary.json"]:
            (stale_output / stale_name).write_text("stale", encoding="utf-8")
        missing_environment = dict(os.environ)
        missing_environment.pop("AUTOMATA_TEST_DATABASE_URL", None)
        failed_preflight = subprocess.run(
            [str(RUN), str(stale_output), "postgres"],
            cwd=ROOT.parent,
            env=missing_environment,
            check=False,
            text=True,
            capture_output=True,
        )
        assert failed_preflight.returncode == 2
        assert "requires AUTOMATA_TEST_DATABASE_URL" in failed_preflight.stderr
        assert not any(
            (stale_output / stale_name).exists()
            for stale_name in ["coverage.lcov", "manifest.json", "summary.json"]
        )
        assert not list(stale_output.glob(".rust-coverage-stage.*"))

        missing_kms_environment = dict(os.environ)
        missing_kms_environment.update(
            {
                "AUTOMATA_TEST_DATABASE_URL": "postgresql://unused.invalid/test",
                "AUTOMATA_TEST_S3_ENDPOINT": "http://127.0.0.1:9000/",
                "AUTOMATA_TEST_S3_BUCKET": "coverage-contract",
                "AUTOMATA_TEST_S3_ACCESS_KEY": "local-access",
                "AUTOMATA_TEST_S3_SECRET_KEY": "local-secret",
            }
        )
        missing_kms_environment.pop("AUTOMATA_TEST_S3_KMS_KEY_ID", None)
        missing_kms_output = scratch / "missing-s3-kms-output"
        missing_kms_probe = subprocess.run(
            [str(RUN), str(missing_kms_output), "s3"],
            cwd=ROOT.parent,
            env=missing_kms_environment,
            check=False,
            text=True,
            capture_output=True,
        )
        assert missing_kms_probe.returncode == 2
        assert (
            "requires AUTOMATA_TEST_S3_KMS_KEY_ID" in missing_kms_probe.stderr
        )
        assert not any(
            (missing_kms_output / name).exists()
            for name in ["coverage.lcov", "manifest.json", "summary.json"]
        )
        assert not list(missing_kms_output.glob(".rust-coverage-stage.*"))

        podman_environment = dict(os.environ)
        podman_environment.update(
            {
                name: "/unused/coverage-contract"
                for name in [
                    "HOME",
                    "XDG_RUNTIME_DIR",
                    "AUTOMATA_PODMAN_APPROVED_HELPERS",
                    "AUTOMATA_PODMAN_TEST_IMAGE",
                    "AUTOMATA_PODMAN_TEST_SERVICE_IMAGE",
                    "AUTOMATA_PODMAN_TEST_SERVICE_PROXY_IMAGE",
                    "AUTOMATA_TEST_STATIC_RUNNER",
                    "AUTOMATA_TEST_PODMAN_BINARY",
                    "AUTOMATA_TEST_PODMAN_STATE_ROOT",
                    "AUTOMATA_TEST_PODMAN_HOME",
                    "AUTOMATA_TEST_PODMAN_RUNTIME",
                    "AUTOMATA_TEST_PODMAN_APPROVED_HELPERS",
                    "AUTOMATA_TEST_CONMON",
                    "AUTOMATA_TEST_OCI_RUNTIME",
                    "AUTOMATA_TEST_CATATONIT",
                    "AUTOMATA_TEST_SECCOMP_PROFILE",
                ]
            }
        )
        podman_environment["AUTOMATA_LIVE_ROOTLESS_PODMAN"] = "1"
        podman_environment["AUTOMATA_LIVE_ROOTLESS_BUILDX"] = "1"
        podman_environment.pop("AUTOMATA_PODMAN_TEST_BUILDKIT_IMAGE", None)
        missing_buildkit_output = scratch / "missing-podman-buildkit-output"
        missing_buildkit_probe = subprocess.run(
            [str(RUN), str(missing_buildkit_output), "podman"],
            cwd=ROOT.parent,
            env=podman_environment,
            check=False,
            text=True,
            capture_output=True,
        )
        assert missing_buildkit_probe.returncode == 2
        assert (
            "requires AUTOMATA_PODMAN_TEST_BUILDKIT_IMAGE"
            in missing_buildkit_probe.stderr
        )
        assert not any(
            (missing_buildkit_output / name).exists()
            for name in ["summary.json", "coverage.lcov", "manifest.json"]
        )
        assert not list(missing_buildkit_output.glob(".rust-coverage-stage.*"))

        podman_environment["AUTOMATA_PODMAN_TEST_BUILDKIT_IMAGE"] = (
            "unused.invalid/buildkit@sha256:" + "0" * 64
        )
        podman_environment["AUTOMATA_LIVE_ROOTLESS_BUILDX"] = "0"
        disabled_buildx_output = scratch / "disabled-podman-buildx-output"
        disabled_buildx_probe = subprocess.run(
            [str(RUN), str(disabled_buildx_output), "podman"],
            cwd=ROOT.parent,
            env=podman_environment,
            check=False,
            text=True,
            capture_output=True,
        )
        assert disabled_buildx_probe.returncode == 2
        assert (
            "requires AUTOMATA_LIVE_ROOTLESS_BUILDX=1"
            in disabled_buildx_probe.stderr
        )
        assert not any(
            (disabled_buildx_output / name).exists()
            for name in ["summary.json", "coverage.lcov", "manifest.json"]
        )
        assert not list(disabled_buildx_output.glob(".rust-coverage-stage.*"))

        fake_bin = scratch / "fake-bin"
        fake_bin.mkdir()
        target_capture = scratch / "coverage-target.txt"
        fake_cargo = fake_bin / "cargo"
        fake_cargo.write_text(
            """#!/bin/sh
set -eu
if [ "$1" = llvm-cov ] && [ "$2" = --version ]; then
  printf '%s\\n' 'cargo-llvm-cov 0.8.7'
  exit 0
fi
if [ "$1" = llvm-cov ] && [ "$2" = show-env ]; then
  printf '%s\\n' "${CARGO_TARGET_DIR-}" >"$AUTOMATA_COVERAGE_TARGET_CAPTURE"
  exit 23
fi
exit 99
""",
            encoding="utf-8",
        )
        fake_cargo.chmod(0o755)
        isolated_environment = dict(os.environ)
        isolated_environment["PATH"] = f"{fake_bin}:{isolated_environment['PATH']}"
        isolated_environment["AUTOMATA_COVERAGE_TARGET_CAPTURE"] = str(target_capture)
        isolated_output = runner_repository / "target" / "isolated-output"
        isolated_probe = subprocess.run(
            [str(runner_under_test), str(isolated_output), "ordinary"],
            cwd=runner_repository,
            env=isolated_environment,
            check=False,
            text=True,
            capture_output=True,
        )
        assert isolated_probe.returncode == 23, isolated_probe.stderr
        assert target_capture.read_text(encoding="utf-8").strip() == str(
            runner_repository / "target" / "llvm-cov-target"
        )
        assert not list(isolated_output.glob(".rust-coverage-stage.*"))
        assert not any(
            (isolated_output / name).exists()
            for name in ["coverage.lcov", "manifest.json", "summary.json"]
        )

        bundles = [
            "ordinary",
            "postgres",
            "s3",
            "podman",
            "github-live",
            "node-live",
        ]
        planned = subprocess.run(
            [str(RUN), "--plan", str(scratch / "planned"), *bundles],
            cwd=ROOT.parent,
            check=True,
            text=True,
            capture_output=True,
        )
        commands = planned.stdout.splitlines()
        assert len(commands) == 16, planned.stdout
        expected_inventory = [
            "cargo test --workspace",
            "-p automata-ci-postgres --test postgres",
            "-p automata-ci-postgres --lib",
            "-p automata-ci-results-github --test postgres_artifacts --test postgres_cache",
            "--test github_provider_end_to_end_matrix",
            "--test blob_s3",
            "--test live_github_rustfs",
            "--test live_checkout_pipeline",
            "--test rustfs_results",
            "--test cache_rustfs",
            "--test live_admission",
            "--test live_rootless",
            "podman_probe::tests::",
            "--test live_repository_snapshot",
            "--test http_compatibility",
            "--test cache_http",
        ]
        for expected, command in zip(expected_inventory, commands, strict=True):
            assert expected in command, command
        assert all("--ignored" in command for command in commands[1:])
        assert "--test-threads=4" in commands[1]
        assert "--test-threads=1" in commands[2]
        assert "test_support::tests::" in commands[2]
        assert "--tests" not in commands[1]
        assert sum(
            command.count("-p automata-ci-postgres-test-support")
            for command in commands
        ) == 0
        postgres_prefixes = json.loads(
            (ROOT / "ci" / "rust-coverage-policy.json").read_text(encoding="utf-8")
        )["lanes"]["postgres"]["source_prefixes"]
        assert {
            "crates/automata-ci-auth-postgres/src/",
            "crates/automata-ci-postgres/src/",
            "crates/automata-ci-provisioning-postgres/src/",
            "crates/automata-ci-runner-auth-postgres/src/",
            "crates/automata-ci-secret-postgres/src/",
            "crates/automata-ci-store-postgres/src/",
        }.issubset(postgres_prefixes)
        assert "crates/automata-ci-postgres-test-support/src/" not in postgres_prefixes
        assert all("-p automata-ci-store" not in command for command in commands)
        unknown_plan = subprocess.run(
            [str(RUN), "--plan", str(scratch / "unknown-plan"), "ordinary", "policy-only"],
            cwd=ROOT.parent,
            check=False,
            text=True,
            capture_output=True,
        )
        assert unknown_plan.returncode == 2
    print("verified service-aware Rust coverage policy")


if __name__ == "__main__":
    main()
