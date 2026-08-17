#!/usr/bin/env python3
"""Contract tests for the unpublished service-proxy OCI candidate."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import pathlib
import sys
import tarfile
import tempfile
import unittest


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[3]
SCRIPT = REPOSITORY_ROOT / "scripts" / "ci" / "service-proxy-candidate.py"
SPEC = importlib.util.spec_from_file_location("service_proxy_candidate", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not load {SCRIPT}")
candidate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = candidate
SPEC.loader.exec_module(candidate)


class CandidateContract(unittest.TestCase):
    def setUp(self) -> None:
        scratch = REPOSITORY_ROOT / "target" / "service-proxy-candidate-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="case.", dir=scratch)
        self.root = pathlib.Path(self.temporary.name)
        self.context = self.root / "context"
        (self.context / "sbom").mkdir(parents=True)
        (self.context / "automata-ci-service-proxy").write_bytes(b"static helper")
        (self.context / "Containerfile").write_bytes(b"FROM scratch\n")
        self.sbom = b'{"bomFormat":"CycloneDX"}\n'
        (self.context / "sbom" / candidate.SBOM_NAME).write_bytes(self.sbom)
        self.release = {
            "created": "2026-08-09T00:00:00+00:00",
            "revision": "a" * 40,
            "source_date_epoch": 1_775_865_600,
            "version": "1.2.3",
        }
        self.source = {
            "artifacts": {
                "binary_sha256": self.file_digest("automata-ci-service-proxy"),
                "containerfile_sha256": self.file_digest("Containerfile"),
                "sbom_sha256": self.file_digest(f"sbom/{candidate.SBOM_NAME}"),
            },
            "release": self.release,
            "schema_version": 1,
        }
        self.source_bytes = candidate.canonical_json(self.source)
        (self.context / candidate.SOURCE_NAME).write_bytes(self.source_bytes)
        self.oci = self.root / "image.oci.tar"
        self.write_oci()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def file_digest(self, relative: str) -> str:
        return hashlib.sha256((self.context / relative).read_bytes()).hexdigest()

    @staticmethod
    def descriptor(contents: bytes, media_type: str) -> dict:
        return {
            "digest": f"sha256:{hashlib.sha256(contents).hexdigest()}",
            "mediaType": media_type,
            "size": len(contents),
        }

    def write_oci(
        self,
        *,
        revision: str | None = None,
        reference_name: str | None = None,
        archive_mtime: int = 0,
        extra_member: bool = False,
        include_index_media_type: bool = True,
        index_media_type: object = "application/vnd.oci.image.index.v1+json",
    ) -> None:
        source_sha = hashlib.sha256(self.source_bytes).hexdigest()
        labels = {
            "org.opencontainers.image.created": self.release["created"],
            "org.opencontainers.image.revision": revision or self.release["revision"],
            "org.opencontainers.image.version": self.release["version"],
            "io.automata.service-proxy.protocol-version": "2",
            "io.automata.service-proxy.binary.sha256": self.source["artifacts"]["binary_sha256"],
            "io.automata.service-proxy.sbom.sha256": self.source["artifacts"]["sbom_sha256"],
            "io.automata.service-proxy.source.sha256": source_sha,
        }
        config = json.dumps(
            {
                "config": {
                    "Entrypoint": ["/usr/libexec/automata-ci-service-proxy"],
                    "Labels": labels,
                    "User": "65532:65532",
                }
            },
            separators=(",", ":"),
        ).encode()
        layer = b"fixture layer"
        config_descriptor = self.descriptor(
            config, "application/vnd.oci.image.config.v1+json"
        )
        layer_descriptor = self.descriptor(
            layer, "application/vnd.oci.image.layer.v1.tar"
        )
        manifest = json.dumps(
            {
                "config": config_descriptor,
                "layers": [layer_descriptor],
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "schemaVersion": 2,
            },
            separators=(",", ":"),
        ).encode()
        manifest_descriptor = self.descriptor(
            manifest, "application/vnd.oci.image.manifest.v1+json"
        )
        if reference_name is not None:
            manifest_descriptor["annotations"] = {
                "org.opencontainers.image.ref.name": reference_name
            }
        index_document = {
            "manifests": [manifest_descriptor],
            "schemaVersion": 2,
        }
        if include_index_media_type:
            index_document["mediaType"] = index_media_type
        index = json.dumps(index_document, separators=(",", ":")).encode()
        members = {
            "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
            "index.json": index,
            f"blobs/sha256/{config_descriptor['digest'].removeprefix('sha256:')}": config,
            f"blobs/sha256/{layer_descriptor['digest'].removeprefix('sha256:')}": layer,
            f"blobs/sha256/{manifest_descriptor['digest'].removeprefix('sha256:')}": manifest,
        }
        if extra_member:
            members["unreferenced"] = b"must not survive"
        with tarfile.open(self.oci, "w") as archive:
            for name, contents in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(contents)
                info.mtime = archive_mtime
                archive.addfile(info, io.BytesIO(contents))

    def test_candidate_binds_exact_oci_source_and_sbom(self) -> None:
        output = self.root / "candidate.tar"
        candidate.create(
            argparse.Namespace(
                context=self.context,
                oci_archive=self.oci,
                output=output,
                github_output=None,
            )
        )
        with tarfile.open(output, "r:") as archive:
            names = sorted(member.name for member in archive.getmembers())
            self.assertEqual(
                names,
                sorted(
                    [
                        candidate.IDENTITY_NAME,
                        candidate.IMAGE_ARCHIVE_NAME,
                        candidate.SBOM_NAME,
                        candidate.SOURCE_NAME,
                    ]
                ),
            )
            identity = json.load(archive.extractfile(candidate.IDENTITY_NAME))
            oci_bytes = archive.extractfile(candidate.IMAGE_ARCHIVE_NAME).read()
        with tarfile.open(fileobj=io.BytesIO(oci_bytes), mode="r:") as archive:
            members = {member.name: member for member in archive.getmembers()}
        self.assertEqual(members["blobs"].mode, 0o755)
        self.assertEqual(members["blobs/sha256"].mode, 0o755)
        self.assertEqual(identity["image"]["name"], candidate.IMAGE_NAME)
        self.assertRegex(identity["image"]["manifest_digest"], candidate.OCI_DIGEST)
        self.assertEqual(identity["release"], self.release)

    def test_mismatched_image_provenance_fails_before_candidate_output(self) -> None:
        self.write_oci(revision="b" * 40)
        output = self.root / "candidate.tar"
        with self.assertRaisesRegex(SystemExit, "labels do not bind"):
            candidate.create(
                argparse.Namespace(
                    context=self.context,
                    oci_archive=self.oci,
                    output=output,
                    github_output=None,
                )
            )
        self.assertFalse(output.exists())

    def test_changed_context_fails_closed(self) -> None:
        (self.context / "automata-ci-service-proxy").write_bytes(b"changed")
        with self.assertRaisesRegex(SystemExit, "does not match"):
            candidate.create(
                argparse.Namespace(
                    context=self.context,
                    oci_archive=self.oci,
                    output=self.root / "candidate.tar",
                    github_output=None,
                )
            )

    def test_candidate_canonicalizes_transport_metadata_and_local_reference(self) -> None:
        first = self.root / "first.tar"
        candidate.create(
            argparse.Namespace(
                context=self.context,
                oci_archive=self.oci,
                output=first,
                github_output=None,
            )
        )
        self.write_oci(
            reference_name="localhost/automata-ci/service-proxy:different-local-tag",
            archive_mtime=123456,
        )
        second = self.root / "second.tar"
        candidate.create(
            argparse.Namespace(
                context=self.context,
                oci_archive=self.oci,
                output=second,
                github_output=None,
            )
        )
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_optional_index_media_type_canonicalizes_to_explicit_media_type(self) -> None:
        first = self.root / "first.tar"
        candidate.create(
            argparse.Namespace(
                context=self.context,
                oci_archive=self.oci,
                output=first,
                github_output=None,
            )
        )
        self.write_oci(
            include_index_media_type=False,
            reference_name="localhost/automata-ci/service-proxy:podman-4-transport",
            archive_mtime=123456,
        )
        second = self.root / "second.tar"
        candidate.create(
            argparse.Namespace(
                context=self.context,
                oci_archive=self.oci,
                output=second,
                github_output=None,
            )
        )
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_invalid_index_media_type_fails_closed(self) -> None:
        invalid_media_types = (
            None,
            "application/vnd.docker.distribution.manifest.list.v2+json",
        )
        for media_type in invalid_media_types:
            with self.subTest(media_type=media_type):
                self.write_oci(index_media_type=media_type)
                output = self.root / "candidate.tar"
                with self.assertRaisesRegex(SystemExit, "index media type differs"):
                    candidate.create(
                        argparse.Namespace(
                            context=self.context,
                            oci_archive=self.oci,
                            output=output,
                            github_output=None,
                        )
                    )
                self.assertFalse(output.exists())

    def test_unreferenced_oci_member_fails_closed(self) -> None:
        self.write_oci(extra_member=True)
        output = self.root / "candidate.tar"
        with self.assertRaisesRegex(SystemExit, "unreferenced member"):
            candidate.create(
                argparse.Namespace(
                    context=self.context,
                    oci_archive=self.oci,
                    output=output,
                    github_output=None,
                )
            )
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
