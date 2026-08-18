#!/usr/bin/env python3
"""Adversarial tests for the Windows image build and promotion pipeline."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[3]
SCRIPT = REPOSITORY_ROOT / "scripts" / "ci" / "windows-image-pipeline.py"
SPEC = importlib.util.spec_from_file_location("windows_image_pipeline", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not load {SCRIPT}")
pipeline = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = pipeline
SPEC.loader.exec_module(pipeline)


def digest(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def rust_struct_fields(source: str, struct_name: str) -> tuple[str, ...]:
    match = re.search(
        rf"struct {re.escape(struct_name)} \{{(?P<body>.*?)^\}}",
        source,
        flags=re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"could not find Rust struct {struct_name}")
    return tuple(
        field.group(1)
        for field in re.finditer(
            r"^\s{4}([a-z][a-z0-9_]*):\s",
            match.group("body"),
            flags=re.MULTILINE,
        )
    )


class WindowsImagePipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.repository = self.root / "repository"
        self.recipe = self.repository / "images" / "windows-server-2025-hyperv"
        self.recipe.mkdir(parents=True)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir()
        self.source_contents = {
            "pwsh": b"reviewed-pwsh-archive",
            "node24": b"reviewed-node24-archive",
        }
        self.source_filenames = {
            "pwsh": "PowerShell-7.6.5-win-x64.zip",
            "node24": "node-v24.19.0-win-x64.zip",
        }
        for kind, contents in self.source_contents.items():
            (self.artifacts / self.source_filenames[kind]).write_bytes(contents)
        self.base_image = (
            "mcr.microsoft.com/windows/servercore@sha256:"
            "2cd01bf7793879d5e1756b46045ea5dd61d040837e36d48c340f6e17d3263507"
        )
        self.image = (
            "ghcr.io/automata-ci/windows-runner@sha256:"
            + digest(b"promoted-image")
        )
        self.commit = ""
        self.lock_path = self.recipe / "sources.lock.json"
        self.write_lock()
        (self.recipe / "Containerfile").write_text(
            f"FROM {self.base_image}\n", encoding="utf-8"
        )
        (self.recipe / "install-image.ps1").write_text(
            "Set-StrictMode -Version Latest\n", encoding="utf-8"
        )
        self.initialize_repository()
        self.guest = self.root / "automata-ci-sandbox-guest.exe"
        self.helper = self.root / "automata-sha256.exe"
        self.guest.write_bytes(b"reviewed-guest-agent")
        self.helper.write_bytes(b"reviewed-hash-helper")
        self.context = self.root / "context"
        self.prepare_context()
        self.qualification = self.root / "qualification.json"
        self.write_qualification()
        self.issued = 1_780_000_000_000
        self.expires = self.issued + 24 * 60 * 60 * 1000
        self.revocations = self.root / "revocations.input.json"
        self.write_revocations()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def initialize_repository(self) -> None:
        subprocess.run(["git", "init", "--quiet", self.repository], check=True)
        subprocess.run(
            ["git", "-C", self.repository, "config", "user.name", "Automata Test"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", self.repository, "config", "user.email", "test@automata.invalid"],
            check=True,
        )
        subprocess.run(["git", "-C", self.repository, "add", "."], check=True)
        subprocess.run(
            ["git", "-C", self.repository, "commit", "--quiet", "-m", "fixture"],
            check=True,
        )
        self.commit = subprocess.check_output(
            ["git", "-C", self.repository, "rev-parse", "HEAD"], text=True
        ).strip()

    def write_lock(self, **changes: object) -> None:
        lock = {
            "architecture": "x86_64",
            "base_image": self.base_image,
            "profile_id": pipeline.PROFILE_ID,
            "schema_version": 1,
            "sources": [
                {
                    "filename": self.source_filenames[kind],
                    "kind": kind,
                    "sha256": digest(self.source_contents[kind]),
                    "url": (
                        "https://nodejs.org/download/release/v24.19.0/"
                        if kind == "node24"
                        else "https://github.com/automata-ci/fixtures/"
                    )
                    + self.source_filenames[kind],
                    "version": {
                        "pwsh": "7.6.5",
                        "node24": "24.19.0",
                    }[kind],
                }
                for kind in pipeline.EXPECTED_SOURCES
            ],
            "variant": "server-core-2025",
        }
        lock.update(changes)
        self.lock_path.write_bytes(pipeline.canonical_json(lock))

    def prepare_context(self) -> None:
        pipeline.prepare_context(
            argparse.Namespace(
                lock=self.lock_path,
                recipe_directory=self.recipe,
                source_tree=self.repository,
                guest_agent=self.guest,
                guest_agent_sha256=digest(self.guest.read_bytes()),
                hash_helper=self.helper,
                hash_helper_sha256=digest(self.helper.read_bytes()),
                source_commit=self.commit,
                artifact_directory=self.artifacts,
                output=self.context,
            )
        )

    def write_qualification(self) -> None:
        versions = {
            "pwsh": "PowerShell 7.6.5",
            "powershell": "5.1.26100.33296",
            "cmd": "Microsoft Windows [Version 10.0.26100.33296]",
            "sha256": "automata-sha256 1.0.0",
            "node24": "v24.19.0",
        }
        qualification = {
            "architecture": "amd64",
            "container_user": r"User Manager\ContainerUser",
            "guest_agent_sha256": digest(self.guest.read_bytes()),
            "hash_helper_sha256": digest(self.helper.read_bytes()),
            "image": self.image,
            "isolation": "hyperv",
            "network_disabled": True,
            "os": {
                "build": "26100",
                "display_version": "24H2",
                "edition_id": "ServerStandardEvalCor",
                "installation_type": "Server Core",
                "ubr": 33296,
            },
            "profile_id": pipeline.PROFILE_ID,
            "schema_version": 1,
            "tools": [
                {
                    "kind": kind,
                    "path": path,
                    "sha256": digest(kind.encode()),
                    "version": versions[kind],
                }
                for kind, path in pipeline.EXPECTED_TOOLS
            ],
            "workspace": r"C:\__w",
        }
        self.qualification.write_bytes(pipeline.canonical_json(qualification))

    def write_revocations(self, **changes: object) -> None:
        value = {
            "expires_at_unix_millis": self.expires + 1000,
            "generation": 9,
            "issued_at_unix_millis": self.issued - 1000,
            "revoked_images": [],
            "schema_version": 1,
        }
        value.update(changes)
        self.revocations.write_bytes(pipeline.canonical_json(value))

    def assemble(self, output: pathlib.Path | None = None, **changes: object) -> pathlib.Path:
        if output is None:
            output = self.root / "bundle"
        arguments = {
            "lock": self.lock_path,
            "build_inputs": self.context / "build-inputs.json",
            "qualification": self.qualification,
            "revocations": self.revocations,
            "image": self.image,
            "source_commit": self.commit,
            "builder_id": "https://builders.automata.dev/windows-hyperv/v1",
            "issued_at_unix_millis": self.issued,
            "promotion_serial": 17,
            "revocation_generation": 9,
            "output": output,
        }
        arguments.update(changes)
        pipeline.assemble(argparse.Namespace(**arguments))
        return output

    def sign_arguments(
        self, bundle: pathlib.Path, signer: pathlib.Path, output: pathlib.Path
    ) -> argparse.Namespace:
        return argparse.Namespace(
            bundle=bundle,
            key_id="windows-promotion-2026",
            key_handle="kh:windows:17",
            signer=signer.resolve(),
            signer_sha256=digest(signer.read_bytes()),
            output=output,
        )

    def test_checked_in_lock_and_recipe_are_exact_and_non_placeholder(self) -> None:
        directory = (
            REPOSITORY_ROOT / "images" / "windows-server-2025-hyperv"
        )
        lock, _ = pipeline.load_source_lock(directory / "sources.lock.json")
        self.assertEqual(
            [source["kind"] for source in lock["sources"]],
            ["pwsh", "node24"],
        )
        containerfile = (directory / "Containerfile").read_text(encoding="utf-8")
        self.assertIn(lock["base_image"], containerfile)
        self.assertNotIn("sha256:" + "0" * 64, containerfile)
        self.assertNotIn("candidate_fixture", containerfile)
        build = (directory / "build-candidate.ps1").read_text(encoding="utf-8")
        qualification = (directory / "collect-qualification.ps1").read_text(
            encoding="utf-8"
        )
        installer = (directory / "install-image.ps1").read_text(encoding="utf-8")
        candidate_manifest = json.loads(
            (
                REPOSITORY_ROOT
                / "images"
                / "windows-server-2025-hyperv-candidate"
                / "manifest.candidate.json"
            ).read_bytes()
        )
        runner_fixture = json.loads(
            (
                REPOSITORY_ROOT
                / "crates"
                / "automata-ci-runner"
                / "tests"
                / "fixtures"
                / "runner.windows.product.json"
            ).read_bytes()
        )
        attributes = (REPOSITORY_ROOT / ".gitattributes").read_text(
            encoding="utf-8"
        ).splitlines()
        self.assertIn("--pull=false", build)
        self.assertNotIn("docker push", build.lower())
        self.assertIn("--isolation hyperv", qualification)
        self.assertIn("--network none", qualification)
        self.assertIn(
            "images/windows-server-2025-hyperv/Containerfile text eol=lf",
            attributes,
        )
        self.assertIn(
            "images/windows-server-2025-hyperv/*.ps1 text eol=lf",
            attributes,
        )
        cleanup_check = "$removeExitCode = $LASTEXITCODE"
        output_write = "[IO.File]::WriteAllText($outputPath"
        self.assertIn(cleanup_check, qualification)
        self.assertIn("could not remove the qualification container", qualification)
        self.assertGreater(
            qualification.index(output_write), qualification.index(cleanup_check)
        )
        self.assertNotIn("MinGit", installer)
        self.assertNotIn(r"C:\automata\tools\tar", installer)
        inheritance_checks = re.findall(
            r"& icacls\.exe \$root /inheritance:r \| Out-Null\s+"
            r"if \(\$LASTEXITCODE -ne 0\) \{\s+"
            r'throw "could not remove inherited image ACL: \$root"\s+\}',
            installer,
        )
        self.assertEqual(len(inheritance_checks), 2)
        self.assertNotIn("Tool 'tar'", qualification)
        self.assertIsNone(runner_fixture["executor"]["toolchain"]["tar"])
        self.assertEqual(
            [(tool["kind"], tool["path"]) for tool in candidate_manifest["tools"]],
            list(pipeline.EXPECTED_TOOLS),
        )

    def test_prepared_context_binds_every_local_and_remote_input(self) -> None:
        inputs = json.loads((self.context / "build-inputs.json").read_bytes())
        self.assertEqual(inputs["source_commit"], self.commit)
        self.assertEqual(inputs["guest_agent"]["sha256"], digest(self.guest.read_bytes()))
        self.assertEqual(inputs["hash_helper"]["sha256"], digest(self.helper.read_bytes()))
        for kind in pipeline.EXPECTED_SOURCES:
            filename = self.source_filenames[kind]
            self.assertEqual(
                digest((self.context / filename).read_bytes()),
                digest(self.source_contents[kind]),
            )

    def test_prepared_context_rejects_a_dirty_or_different_source_checkout(self) -> None:
        shutil.rmtree(self.context)
        (self.recipe / "install-image.ps1").write_text(
            "Set-StrictMode -Version Latest\n# uncommitted substitution\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(SystemExit, "not clean"):
            self.prepare_context()

    def test_bundle_is_canonical_digest_bound_and_has_no_fixture_escape(self) -> None:
        bundle = self.assemble()
        payload = pipeline.verify_bundle(bundle)
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["revocation_generation"], 9)
        for removed in (
            "promotion_serial",
            "issued_at_unix_millis",
            "expires_at_unix_millis",
        ):
            self.assertNotIn(removed, payload)
        revocations = json.loads((bundle / "revocations.json").read_bytes())
        self.assertNotIn("issued_at_unix_millis", revocations)
        self.assertNotIn("expires_at_unix_millis", revocations)
        revocation_subject = json.loads(
            (bundle / "revocations.subject.json").read_bytes()
        )
        self.assertEqual(
            revocation_subject["issued_at_unix_millis"], self.issued - 1000
        )
        self.assertEqual(
            revocation_subject["expires_at_unix_millis"], self.expires + 1000
        )
        for path in bundle.iterdir():
            self.assertNotIn(b"candidate_fixture", path.read_bytes())
        pairs = json.loads(
            (bundle / "promotion.payload.json").read_bytes(),
            object_pairs_hook=lambda value: value,
        )
        self.assertEqual(
            [name for name, _ in pairs],
            [
                "schema_version",
                "decision",
                "profile_id",
                "base_image",
                "image",
                "manifest_sha256",
                "lock_sha256",
                "provenance_sha256",
                "sbom_sha256",
                "patch_report_sha256",
                "revocations_sha256",
                "revocation_generation",
                "provenance_accepted",
                "sbom_accepted",
                "patch_accepted",
                "revocations_accepted",
            ],
        )

    def test_generated_payload_matches_the_runner_verifier_schema(self) -> None:
        bundle = self.assemble()
        payload = json.loads((bundle / "promotion.payload.json").read_bytes())
        verifier = (
            REPOSITORY_ROOT
            / "crates"
            / "automata-ci-runner"
            / "src"
            / "product"
            / "windows_image.rs"
        ).read_text(encoding="utf-8")

        self.assertEqual(
            tuple(payload), rust_struct_fields(verifier, "PromotionPayload")
        )
        self.assertIn("#[serde(deny_unknown_fields)]", verifier)
        self.assertEqual(tuple(payload), pipeline.PROMOTION_PAYLOAD_FIELDS)

    def test_fixture_marker_is_rejected_even_after_every_digest_is_nonzero(self) -> None:
        bundle = self.assemble()
        reference_path = bundle / "provenance.json"
        reference = json.loads(reference_path.read_bytes())
        reference["candidate_fixture"] = True
        reference_path.write_bytes(pipeline.canonical_json(reference))
        with self.assertRaisesRegex(SystemExit, "candidate fixture marker"):
            pipeline.verify_bundle(bundle)

    def test_reordered_payload_and_rebound_untyped_subject_fail_closed(self) -> None:
        reordered = self.assemble(output=self.root / "reordered")
        payload_path = reordered / "promotion.payload.json"
        payload = json.loads(payload_path.read_bytes())
        reordered_payload = {"decision": payload["decision"]}
        reordered_payload.update(
            (name, value) for name, value in payload.items() if name != "decision"
        )
        payload_path.write_bytes(pipeline.compact_json(reordered_payload))
        with self.assertRaisesRegex(SystemExit, "field order"):
            pipeline.verify_bundle(reordered)

        rebound = self.assemble(output=self.root / "rebound")
        subject_path = rebound / "provenance.intoto.json"
        subject = json.loads(subject_path.read_bytes())
        subject["predicateType"] = "https://attacker.invalid/untyped/v1"
        subject_bytes = pipeline.canonical_json(subject)
        subject_path.write_bytes(subject_bytes)

        reference_path = rebound / "provenance.json"
        reference = json.loads(reference_path.read_bytes())
        reference["subject"]["sha256"] = digest(subject_bytes)
        reference_bytes = pipeline.canonical_json(reference)
        reference_path.write_bytes(reference_bytes)

        manifest_path = rebound / "manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["evidence"]["provenance"]["sha256"] = digest(reference_bytes)
        manifest_bytes = pipeline.canonical_json(manifest)
        manifest_path.write_bytes(manifest_bytes)

        image_lock_path = rebound / "image.lock.json"
        image_lock = json.loads(image_lock_path.read_bytes())
        image_lock["manifest_sha256"] = digest(manifest_bytes)
        image_lock_bytes = pipeline.canonical_json(image_lock)
        image_lock_path.write_bytes(image_lock_bytes)

        payload_path = rebound / "promotion.payload.json"
        payload = json.loads(payload_path.read_bytes())
        payload["provenance_sha256"] = digest(reference_bytes)
        payload["manifest_sha256"] = digest(manifest_bytes)
        payload["lock_sha256"] = digest(image_lock_bytes)
        payload_path.write_bytes(pipeline.compact_json(payload))
        with self.assertRaisesRegex(SystemExit, "typed evidence subject"):
            pipeline.verify_bundle(rebound)

    def test_mutable_placeholder_unknown_and_stale_inputs_fail_closed(self) -> None:
        for change in (
            {"base_image": "mcr.microsoft.com/windows/servercore:ltsc2025"},
            {"base_image": "mcr.microsoft.com/windows/servercore@sha256:" + "0" * 64},
            {"unknown": True},
        ):
            self.write_lock(**change)
            with self.assertRaises(SystemExit):
                pipeline.load_source_lock(self.lock_path)
        self.write_lock()
        self.write_revocations(expires_at_unix_millis=self.issued)
        with self.assertRaisesRegex(SystemExit, "revocation input"):
            self.assemble(output=self.root / "stale")
        self.write_revocations()
        with self.assertRaisesRegex(SystemExit, "serial"):
            self.assemble(output=self.root / "rollback", promotion_serial=0)

    def test_external_signer_receives_only_opaque_handle_and_exact_payload(
        self,
    ) -> None:
        bundle = self.assemble()
        signer = self.root / "approved-signer.exe"
        signer_bytes = b"approved external signer executable"
        signer.write_bytes(signer_bytes)
        payload_bytes = (bundle / "promotion.payload.json").read_bytes()
        output = self.root / "promotion.envelope.json"

        def invoke(command: list[str], **_: object) -> subprocess.CompletedProcess:
            self.assertIn("sign-windows-image-v1", command)
            self.assertEqual(
                command[command.index("--key-handle") + 1], "kh:windows:17"
            )
            staged_signer = pathlib.Path(command[0])
            staged_payload = pathlib.Path(command[command.index("--payload") + 1])
            self.assertNotEqual(staged_signer.resolve(), signer.resolve())
            self.assertNotEqual(
                staged_payload.resolve(),
                (bundle / "promotion.payload.json").resolve(),
            )
            self.assertEqual(staged_signer.read_bytes(), signer_bytes)
            self.assertEqual(staged_payload.read_bytes(), payload_bytes)
            self.assertEqual(
                command[command.index("--payload-sha256") + 1],
                digest(payload_bytes),
            )
            pathlib.Path(command[command.index("--signature-output") + 1]).write_bytes(
                bytes(range(64))
            )
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with mock.patch.object(pipeline.subprocess, "run", side_effect=invoke):
            pipeline.sign(self.sign_arguments(bundle, signer, output))
        envelope = json.loads(output.read_bytes())
        self.assertEqual(envelope["key_id"], "windows-promotion-2026")
        self.assertEqual(
            base64.b64decode(envelope["payload_base64"]),
            payload_bytes,
        )
        self.assertEqual(len(base64.b64decode(envelope["signature_base64"])), 64)
        self.assertNotIn(
            "kh:windows:17", (bundle / "promotion.payload.json").read_text()
        )

    def test_signer_source_replacement_cannot_change_retained_executable(
        self,
    ) -> None:
        bundle = self.assemble()
        signer = self.root / "approved-signer.exe"
        signer_bytes = b"approved external signer executable"
        signer.write_bytes(signer_bytes)
        arguments = self.sign_arguments(
            bundle, signer, self.root / "promotion.envelope.json"
        )

        def replace_source(
            command: list[str], **_: object
        ) -> subprocess.CompletedProcess:
            signer.write_bytes(b"replacement executable")
            staged_signer = pathlib.Path(command[0])
            self.assertNotEqual(staged_signer.resolve(), signer.resolve())
            self.assertEqual(staged_signer.read_bytes(), signer_bytes)
            if os.name == "nt":
                with self.assertRaises(OSError):
                    staged_signer.write_bytes(b"replacement executable")
            pathlib.Path(command[command.index("--signature-output") + 1]).write_bytes(
                bytes(range(64))
            )
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with mock.patch.object(pipeline.subprocess, "run", side_effect=replace_source):
            pipeline.sign(arguments)
        self.assertEqual(signer.read_bytes(), b"replacement executable")
        self.assertTrue(arguments.output.is_file())

    def test_payload_replacement_cannot_change_signature_input_or_envelope(
        self,
    ) -> None:
        bundle = self.assemble()
        signer = self.root / "approved-signer.exe"
        signer.write_bytes(b"approved external signer executable")
        payload_path = bundle / "promotion.payload.json"
        payload_bytes = payload_path.read_bytes()
        output = self.root / "promotion.envelope.json"

        def replace_payload(
            command: list[str], **_: object
        ) -> subprocess.CompletedProcess:
            payload_path.write_bytes(b'{"attacker":true}')
            staged_payload = pathlib.Path(command[command.index("--payload") + 1])
            self.assertNotEqual(staged_payload.resolve(), payload_path.resolve())
            self.assertEqual(staged_payload.read_bytes(), payload_bytes)
            if os.name == "nt":
                with self.assertRaises(OSError):
                    staged_payload.write_bytes(b'{"attacker":true}')
            self.assertEqual(
                command[command.index("--payload-sha256") + 1], digest(payload_bytes)
            )
            pathlib.Path(command[command.index("--signature-output") + 1]).write_bytes(
                bytes(range(64))
            )
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with mock.patch.object(pipeline.subprocess, "run", side_effect=replace_payload):
            pipeline.sign(self.sign_arguments(bundle, signer, output))
        envelope = json.loads(output.read_bytes())
        self.assertEqual(base64.b64decode(envelope["payload_base64"]), payload_bytes)
        self.assertEqual(payload_path.read_bytes(), b'{"attacker":true}')

    def test_payload_replacement_after_verification_fails_before_signing(self) -> None:
        bundle = self.assemble()
        signer = self.root / "approved-signer.exe"
        signer.write_bytes(b"approved external signer executable")
        payload_path = bundle / "promotion.payload.json"
        verify_bundle = pipeline.verify_bundle

        def verify_then_replace(directory: pathlib.Path) -> dict:
            payload = verify_bundle(directory)
            payload_path.write_bytes(b'{"attacker":true}')
            return payload

        with mock.patch.object(
            pipeline, "verify_bundle", side_effect=verify_then_replace
        ), mock.patch.object(pipeline.subprocess, "run") as invoke:
            with self.assertRaisesRegex(
                SystemExit, "promotion payload changed after verification"
            ):
                pipeline.sign(
                    self.sign_arguments(
                        bundle, signer, self.root / "promotion.envelope.json"
                    )
                )
        invoke.assert_not_called()

    def test_output_replacement_race_never_overwrites_existing_file(self) -> None:
        bundle = self.assemble()
        signer = self.root / "approved-signer.exe"
        signer.write_bytes(b"approved external signer executable")
        output = self.root / "promotion.envelope.json"
        attacker_contents = b"attacker-owned-output"

        def replace_output(
            command: list[str], **_: object
        ) -> subprocess.CompletedProcess:
            output.write_bytes(attacker_contents)
            pathlib.Path(command[command.index("--signature-output") + 1]).write_bytes(
                bytes(range(64))
            )
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with mock.patch.object(pipeline.subprocess, "run", side_effect=replace_output):
            with self.assertRaisesRegex(
                SystemExit, "refusing to overwrite promotion envelope"
            ):
                pipeline.sign(self.sign_arguments(bundle, signer, output))
        self.assertEqual(output.read_bytes(), attacker_contents)


if __name__ == "__main__":
    unittest.main()
