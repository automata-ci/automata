#!/usr/bin/env python3
"""Contract tests for the unpublished service-proxy OCI candidate."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import pathlib
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[3]
SCRIPT = REPOSITORY_ROOT / "scripts" / "ci" / "service-proxy-candidate.py"
SPEC = importlib.util.spec_from_file_location("service_proxy_candidate", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not load {SCRIPT}")
candidate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = candidate
SPEC.loader.exec_module(candidate)

LOAD_SCRIPT = (
    REPOSITORY_ROOT / "scripts" / "ci" / "verify-service-proxy-candidate-load.py"
)
LOAD_SPEC = importlib.util.spec_from_file_location(
    "service_proxy_candidate_load", LOAD_SCRIPT
)
if LOAD_SPEC is None or LOAD_SPEC.loader is None:
    raise RuntimeError(f"could not load {LOAD_SCRIPT}")
candidate_load = importlib.util.module_from_spec(LOAD_SPEC)
sys.modules[LOAD_SPEC.name] = candidate_load
LOAD_SPEC.loader.exec_module(candidate_load)


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
        gzip_layer: bool = False,
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
        expanded_layer = b"fixture layer"
        layer = gzip.compress(expanded_layer, mtime=0) if gzip_layer else expanded_layer
        config = json.dumps(
            {
                "config": {
                    "Entrypoint": ["/usr/libexec/automata-ci-service-proxy"],
                    "Labels": labels,
                    "User": "65532:65532",
                },
                "rootfs": {
                    "diff_ids": [
                        f"sha256:{hashlib.sha256(expanded_layer).hexdigest()}"
                    ],
                    "type": "layers",
                },
            },
            separators=(",", ":"),
        ).encode()
        config_descriptor = self.descriptor(
            config, "application/vnd.oci.image.config.v1+json"
        )
        layer_descriptor = self.descriptor(
            layer,
            (
                "application/vnd.oci.image.layer.v1.tar+gzip"
                if gzip_layer
                else "application/vnd.oci.image.layer.v1.tar"
            ),
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
            index = json.load(archive.extractfile("index.json"))
        self.assertEqual(members["blobs"].mode, 0o755)
        self.assertEqual(members["blobs/sha256"].mode, 0o755)
        self.assertEqual(identity["image"]["name"], candidate.IMAGE_NAME)
        self.assertRegex(identity["image"]["manifest_digest"], candidate.OCI_DIGEST)
        self.assertEqual(
            index["manifests"][0]["annotations"],
            {
                "org.opencontainers.image.ref.name": candidate.local_reference(
                    identity["image"]["manifest_digest"]
                )
            },
        )
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

    def test_local_reference_is_manifest_bound(self) -> None:
        digest = "sha256:" + "a" * 64
        self.assertEqual(
            candidate.local_reference(digest),
            "automata.local/automata-ci-service-proxy:manifest-" + "a" * 64,
        )
        with self.assertRaisesRegex(SystemExit, "manifest digest is invalid"):
            candidate.local_reference("sha256:not-a-digest")

    def test_docker_absence_requires_the_exact_daemon_response(self) -> None:
        reference = candidate.local_reference("sha256:" + "a" * 64)
        absent = candidate_load.subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="[]\n",
            stderr=f"Error response from daemon: No such image: {reference}\n",
        )
        with mock.patch.object(candidate_load, "docker_command", return_value=absent):
            self.assertIsNone(candidate_load.inspect_optional("docker", reference))

        unavailable = candidate_load.subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="[]\n",
            stderr="Cannot connect to the Docker daemon\n",
        )
        with mock.patch.object(
            candidate_load, "docker_command", return_value=unavailable
        ):
            with self.assertRaisesRegex(SystemExit, "could not prove image absence"):
                candidate_load.inspect_optional("docker", reference)

    def test_docker_load_archive_is_exactly_derived_from_the_oci_image(self) -> None:
        self.write_oci(gzip_layer=True)
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
            oci_bytes = archive.extractfile(candidate.IMAGE_ARCHIVE_NAME).read()
            identity = json.load(archive.extractfile(candidate.IDENTITY_NAME))
        manifest_digest = identity["image"]["manifest_digest"]
        docker_bytes, config_digest = candidate.docker_load_archive(
            oci_bytes, manifest_digest, self.release["source_date_epoch"]
        )
        with tarfile.open(fileobj=io.BytesIO(docker_bytes), mode="r:") as archive:
            index = json.load(archive.extractfile("index.json"))
            docker_manifest = json.load(archive.extractfile("manifest.json"))
            names = {member.name for member in archive.getmembers()}
        self.assertEqual(index["manifests"][0]["digest"], manifest_digest)
        self.assertEqual(
            docker_manifest,
            [
                {
                    "Config": f"blobs/sha256/{config_digest.removeprefix('sha256:')}",
                    "Layers": [
                        "blobs/sha256/"
                        + hashlib.sha256(b"fixture layer").hexdigest()
                    ],
                    "RepoTags": [candidate.local_reference(manifest_digest)],
                }
            ],
        )
        self.assertIn(docker_manifest[0]["Layers"][0], names)

    def test_docker_store_identity_branches_are_exact(self) -> None:
        manifest_digest = "sha256:" + "a" * 64
        config_digest = "sha256:" + "b" * 64
        reference = candidate.local_reference(manifest_digest)
        digest_reference = f"{candidate.LOCAL_IMAGE_NAME}@{manifest_digest}"
        classic = {
            "Id": config_digest,
            "RepoDigests": [],
            "RepoTags": [reference],
        }
        with (
            mock.patch.object(
                candidate_load, "inspect_image", side_effect=[classic, classic]
            ),
            mock.patch.object(candidate_load, "inspect_optional", return_value=None),
            mock.patch.object(candidate_load, "require_absent") as require_absent,
        ):
            candidate_load.verify_imported(
                "docker",
                reference,
                digest_reference,
                manifest_digest,
                config_digest,
            )
            require_absent.assert_called_once_with("docker", manifest_digest)

        containerd = {
            "Id": manifest_digest,
            "RepoDigests": [digest_reference],
            "RepoTags": [reference],
        }
        with (
            mock.patch.object(
                candidate_load,
                "inspect_image",
                side_effect=[containerd, containerd],
            ),
            mock.patch.object(
                candidate_load, "inspect_optional", return_value=containerd
            ),
            mock.patch.object(candidate_load, "require_absent") as require_absent,
        ):
            candidate_load.verify_imported(
                "docker",
                reference,
                digest_reference,
                manifest_digest,
                config_digest,
            )
            require_absent.assert_called_once_with("docker", config_digest)

        mixed = dict(classic, RepoDigests=[digest_reference])
        with (
            mock.patch.object(
                candidate_load, "inspect_image", side_effect=[mixed, mixed]
            ),
            mock.patch.object(candidate_load, "inspect_optional", return_value=mixed),
            mock.patch.object(candidate_load, "require_absent"),
        ):
            with self.assertRaisesRegex(SystemExit, "classic Docker"):
                candidate_load.verify_imported(
                    "docker",
                    reference,
                    digest_reference,
                    manifest_digest,
                    config_digest,
                )

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
