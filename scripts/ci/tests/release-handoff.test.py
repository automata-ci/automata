#!/usr/bin/env python3
"""Fail-closed tests for the cross-job release handoff."""

from __future__ import annotations

import importlib.util
import io
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[3]
HANDOFF_SCRIPT = REPOSITORY_ROOT / "scripts" / "ci" / "release-handoff.py"
SPEC = importlib.util.spec_from_file_location("release_handoff", HANDOFF_SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not load {HANDOFF_SCRIPT}")
release_handoff = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release_handoff
SPEC.loader.exec_module(release_handoff)


class ReleaseHandoffContract(unittest.TestCase):
    def setUp(self) -> None:
        scratch_root = REPOSITORY_ROOT / "target" / "task-tmp" / "release-handoff-tests"
        scratch_root.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="case.", dir=scratch_root)
        self.root = pathlib.Path(self.temporary.name)
        distribution = self.root / "target" / "distribution"
        packages = self.root / "target" / "package"
        distribution.mkdir(parents=True)
        packages.mkdir(parents=True)
        self.archive = distribution / "automata-x86_64-unknown-linux-musl.tar.gz"
        self.archive.write_bytes(b"release archive\n")
        archive_digest = release_handoff.file_digest(self.archive, "fixture archive")
        (distribution / "automata-x86_64-unknown-linux-musl.tar.gz.sha256").write_text(
            f"{archive_digest}  {self.archive.name}\n", encoding="ascii"
        )
        (packages / "automata-ci-1.2.3.crate").write_bytes(b"crate one\n")
        (packages / "automata-ci-runner-1.2.3.crate").write_bytes(b"crate two\n")
        (self.root / release_handoff.CATALOG_PATH).write_bytes(b"{}\n")
        candidate = self.root / release_handoff.SERVICE_PROXY_CANDIDATE_PATH
        candidate.parent.mkdir(parents=True)
        candidate.write_bytes(b"service proxy candidate\n")
        self.identity = release_handoff.ReleaseIdentity(
            tag="v1.2.3",
            tag_object="a" * 40,
            commit="b" * 40,
            version="1.2.3",
            prerelease=False,
            source_date_epoch=1_700_000_000,
            created="2023-11-14T22:13:20+00:00",
        )
        self.automata_digest = f"sha256:{'c' * 64}"
        self.runner_digest = f"sha256:{'d' * 64}"
        self.sandbox_guest_digest = f"sha256:{'e' * 64}"
        self.expected_crates = ["automata-ci", "automata-ci-runner"]
        self.catalog_validation = mock.patch.object(
            release_handoff.local_catalog,
            "validate_catalog",
            return_value=(
                {
                    "automata": self.automata_digest,
                    "runner": self.runner_digest,
                    "sandbox-guest": self.sandbox_guest_digest,
                },
                [release_handoff.SERVICE_PROXY_CANDIDATE_PATH],
            ),
        )
        self.catalog_validation.start()

    def tearDown(self) -> None:
        self.catalog_validation.stop()
        self.temporary.cleanup()

    def create(self, name: str = "handoff.tar") -> tuple[pathlib.Path, pathlib.Path, str]:
        manifest_path = self.root / release_handoff.MANIFEST_PATH
        handoff_path = self.root / "target" / "release-handoff" / name
        manifest = release_handoff.build_manifest(
            self.root,
            self.identity,
            self.automata_digest,
            self.runner_digest,
            self.sandbox_guest_digest,
            self.expected_crates,
        )
        _, digest = release_handoff.create_handoff(
            self.root,
            manifest_path,
            handoff_path,
            manifest,
            self.identity,
            self.expected_crates,
        )
        return manifest_path, handoff_path, digest

    def rewrite_member(
        self,
        source: pathlib.Path,
        destination: pathlib.Path,
        mutate,
    ) -> None:
        with tarfile.open(source, "r:") as archive:
            members = archive.getmembers()
            payload = {
                member.name: archive.extractfile(member).read()  # type: ignore[union-attr]
                for member in members
            }
        with tarfile.open(destination, "w", format=tarfile.USTAR_FORMAT) as archive:
            for member in members:
                contents = mutate(member, payload[member.name])
                member.size = len(contents)
                archive.addfile(member, io.BytesIO(contents))

    def test_create_is_deterministic_and_round_trips_exact_files(self) -> None:
        manifest_path, handoff_path, digest = self.create("one.tar")
        first = handoff_path.read_bytes()
        manifest_path.unlink()
        _, second_path, second_digest = self.create("two.tar")
        self.assertEqual(first, second_path.read_bytes())
        self.assertEqual(digest, second_digest)
        packed_path = second_path.with_name("packed.tar")
        _, packed_digest = release_handoff.pack_handoff(
            self.root,
            manifest_path,
            packed_path,
            self.identity,
            self.expected_crates,
        )
        self.assertEqual(second_path.read_bytes(), packed_path.read_bytes())
        self.assertEqual(second_digest, packed_digest)

        _, contents = release_handoff.verify_handoff(
            handoff_path,
            self.identity,
            self.automata_digest,
            self.runner_digest,
            self.sandbox_guest_digest,
        )
        extraction_root = self.root / "consumer"
        extraction_root.mkdir()
        release_handoff.extract_handoff(contents, extraction_root)
        for relative_path, expected in contents.items():
            self.assertEqual((extraction_root / relative_path).read_bytes(), expected)

    def test_manifest_binds_identity_images_assets_and_every_crate(self) -> None:
        manifest_path, _, _ = self.create()
        manifest, _ = release_handoff.load_manifest(manifest_path)
        automata, runner, sandbox_guest, paths = release_handoff.validate_manifest(
            manifest, self.identity, self.root
        )
        self.assertEqual(automata, self.automata_digest)
        self.assertEqual(runner, self.runner_digest)
        self.assertEqual(sandbox_guest, self.sandbox_guest_digest)
        self.assertEqual(
            paths,
            [
                release_handoff.ARCHIVE_PATH,
                release_handoff.CHECKSUM_PATH,
                release_handoff.CATALOG_PATH,
                release_handoff.SERVICE_PROXY_CANDIDATE_PATH,
                "target/package/automata-ci-1.2.3.crate",
                "target/package/automata-ci-runner-1.2.3.crate",
            ],
        )

        manifest["release"]["commit"] = "e" * 40
        with self.assertRaisesRegex(SystemExit, "identity differs"):
            release_handoff.validate_manifest(manifest, self.identity, self.root)

    def test_handoff_rejects_missing_or_private_crate_archives(self) -> None:
        private_archive = (
            self.root / "target" / "package" / "automata-ci-private-1.2.3.crate"
        )
        private_archive.write_bytes(b"private crate\n")
        with self.assertRaisesRegex(SystemExit, "non-publishable package"):
            release_handoff.build_manifest(
                self.root,
                self.identity,
                self.automata_digest,
                self.runner_digest,
                self.sandbox_guest_digest,
                self.expected_crates,
            )

        private_archive.unlink()
        (
            self.root / "target" / "package" / "automata-ci-runner-1.2.3.crate"
        ).unlink()
        with self.assertRaisesRegex(SystemExit, "archives are missing"):
            release_handoff.build_manifest(
                self.root,
                self.identity,
                self.automata_digest,
                self.runner_digest,
                self.sandbox_guest_digest,
                self.expected_crates,
            )

    def test_crate_limit_accounts_for_every_fixed_handoff_member(self) -> None:
        package_directory = self.root / "target" / "package"
        for archive in package_directory.glob("*.crate"):
            archive.unlink()
        expected = []
        for index in range(release_handoff.MAX_CRATE_ENTRIES):
            name = f"crate-{index:03d}"
            expected.append(name)
            (package_directory / f"{name}-1.2.3.crate").write_bytes(b"x")
        entries = release_handoff.package_entries(
            self.root, self.identity.version, expected
        )
        self.assertEqual(len(entries), release_handoff.MAX_CRATE_ENTRIES)

        overflow = "crate-overflow"
        (package_directory / f"{overflow}-1.2.3.crate").write_bytes(b"x")
        with self.assertRaisesRegex(SystemExit, "too many crate archives"):
            release_handoff.package_entries(
                self.root, self.identity.version, [*expected, overflow]
            )

    def test_manifest_rejects_json_type_confusion(self) -> None:
        manifest_path, _, _ = self.create()
        manifest, _ = release_handoff.load_manifest(manifest_path)
        manifest["schema_version"] = True
        with self.assertRaisesRegex(SystemExit, "schema version"):
            release_handoff.validate_manifest(manifest, self.identity, self.root)

        manifest["schema_version"] = release_handoff.SCHEMA_VERSION
        manifest["release"]["prerelease"] = 0
        with self.assertRaisesRegex(SystemExit, "must be a boolean"):
            release_handoff.validate_manifest(manifest, self.identity, self.root)

        manifest["release"]["prerelease"] = False
        manifest["release"]["source_date_epoch"] = False
        with self.assertRaisesRegex(SystemExit, "non-negative integer"):
            release_handoff.validate_manifest(manifest, self.identity, self.root)

    def test_changed_payload_and_unexpected_member_fail_closed(self) -> None:
        _, handoff_path, _ = self.create()
        changed = handoff_path.with_name("changed.tar")
        self.rewrite_member(
            handoff_path,
            changed,
            lambda member, contents: (
                b"changed\n"
                if member.name == "target/package/automata-ci-1.2.3.crate"
                else contents
            ),
        )
        with self.assertRaisesRegex(SystemExit, "handoff digest mismatch"):
            release_handoff.verify_handoff(
                changed,
                self.identity,
                self.automata_digest,
                self.runner_digest,
                self.sandbox_guest_digest,
            )

        extra = handoff_path.with_name("extra.tar")
        with tarfile.open(handoff_path, "r:") as archive:
            members = archive.getmembers()
            payload = {
                member.name: archive.extractfile(member).read()  # type: ignore[union-attr]
                for member in members
            }
        with tarfile.open(extra, "w", format=tarfile.USTAR_FORMAT) as archive:
            for member in members:
                archive.addfile(member, io.BytesIO(payload[member.name]))
            unexpected = tarfile.TarInfo("target/package/unexpected-1.2.3.crate")
            unexpected.size = 1
            unexpected.mode = 0o444
            unexpected.uid = unexpected.gid = 0
            unexpected.mtime = self.identity.source_date_epoch
            archive.addfile(unexpected, io.BytesIO(b"x"))
        with self.assertRaisesRegex(SystemExit, "canonical order|exact manifest set"):
            release_handoff.verify_handoff(
                extra,
                self.identity,
                self.automata_digest,
                self.runner_digest,
                self.sandbox_guest_digest,
            )

    def test_non_regular_or_noncanonical_tar_metadata_fails_closed(self) -> None:
        _, handoff_path, _ = self.create()
        unsafe = handoff_path.with_name("unsafe.tar")
        with tarfile.open(handoff_path, "r:") as archive:
            members = archive.getmembers()
            payload = {
                member.name: archive.extractfile(member).read()  # type: ignore[union-attr]
                for member in members
            }
        with tarfile.open(unsafe, "w", format=tarfile.USTAR_FORMAT) as archive:
            for member in members:
                if member.name == release_handoff.MANIFEST_PATH:
                    member.mode = 0o644
                archive.addfile(member, io.BytesIO(payload[member.name]))
        with self.assertRaisesRegex(SystemExit, "metadata is not canonical"):
            release_handoff.verify_handoff(
                unsafe,
                self.identity,
                self.automata_digest,
                self.runner_digest,
                self.sandbox_guest_digest,
            )

        trailing = handoff_path.with_name("trailing.tar")
        trailing.write_bytes(handoff_path.read_bytes() + b"unexpected trailing data")
        with self.assertRaisesRegex(SystemExit, "trailing data"):
            release_handoff.load_handoff(trailing, self.identity)

        original_limit = release_handoff.MAX_HANDOFF_MEMBERS
        release_handoff.MAX_HANDOFF_MEMBERS = 1
        try:
            with self.assertRaisesRegex(SystemExit, "too many members"):
                release_handoff.load_handoff(handoff_path, self.identity)
        finally:
            release_handoff.MAX_HANDOFF_MEMBERS = original_limit

    def test_outer_digest_rejects_jointly_rewritten_handoff_before_parsing(self) -> None:
        _, handoff_path, digest = self.create()
        changed = handoff_path.with_name("jointly-rewritten.tar")
        self.rewrite_member(
            handoff_path,
            changed,
            lambda _member, contents: contents.replace(b"crate one", b"crate evil"),
        )
        command = [
            sys.executable,
            str(HANDOFF_SCRIPT),
            "verify-handoff",
            "--tag",
            self.identity.tag,
            "--tag-object",
            self.identity.tag_object,
            "--commit",
            self.identity.commit,
            "--version",
            self.identity.version,
            "--prerelease",
            "false",
            "--source-date-epoch",
            str(self.identity.source_date_epoch),
            "--created",
            self.identity.created,
            "--handoff",
            str(changed),
            "--handoff-sha256",
            digest,
            "--automata-digest",
            self.automata_digest,
            "--runner-digest",
            self.runner_digest,
            "--sandbox-guest-digest",
            self.sandbox_guest_digest,
        ]
        result = subprocess.run(command, check=False, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("differs from the staging job", result.stderr)

    def test_outer_digest_and_parser_share_one_open_file_identity(self) -> None:
        _, handoff_path, digest = self.create()
        replacement = handoff_path.with_name("replacement.tar")
        replacement.write_bytes(b"not a handoff")
        original_open = release_handoff.os.open
        original_digest = release_handoff.sha256_stream

        def swap_path_after_digest(stream):
            actual = original_digest(stream)
            release_handoff.os.replace(replacement, handoff_path)
            return actual

        with (
            mock.patch.object(
                release_handoff.os, "open", wraps=original_open
            ) as opened,
            mock.patch.object(
                release_handoff, "sha256_stream", side_effect=swap_path_after_digest
            ),
        ):
            with self.assertRaisesRegex(SystemExit, "changed while it was verified"):
                release_handoff.verify_handoff(
                    handoff_path,
                    self.identity,
                    self.automata_digest,
                    self.runner_digest,
                    self.sandbox_guest_digest,
                    expected_handoff_digest=digest,
                )
        self.assertEqual(opened.call_count, 1)
        self.assertEqual(handoff_path.read_bytes(), b"not a handoff")

    def test_extraction_refuses_to_overwrite_or_follow_parent_symlink(self) -> None:
        _, handoff_path, _ = self.create()
        _, contents = release_handoff.verify_handoff(
            handoff_path,
            self.identity,
            self.automata_digest,
            self.runner_digest,
            self.sandbox_guest_digest,
        )
        extraction_root = self.root / "consumer"
        extraction_root.mkdir()
        occupied = extraction_root / release_handoff.MANIFEST_PATH
        occupied.parent.mkdir(parents=True)
        occupied.write_text("occupied\n", encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "refusing to overwrite"):
            release_handoff.extract_handoff(contents, extraction_root)

        clean_root = self.root / "symlink-consumer"
        clean_root.mkdir()
        (clean_root / "target").symlink_to(self.root / "outside")
        (self.root / "outside").mkdir()
        with self.assertRaisesRegex(SystemExit, "parent is unsafe"):
            release_handoff.extract_handoff(contents, clean_root)
        self.assertFalse((self.root / "outside" / "distribution").exists())


if __name__ == "__main__":
    unittest.main()
