#!/usr/bin/env python3
"""Fail-closed tests for service-proxy image publication."""

from __future__ import annotations

import argparse
import contextlib
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
PUBLICATION_SCRIPT = (
    REPOSITORY_ROOT / "scripts" / "ci" / "service-proxy-publication.py"
)
SPEC = importlib.util.spec_from_file_location(
    "service_proxy_publication", PUBLICATION_SCRIPT
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not load {PUBLICATION_SCRIPT}")
publication = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = publication
SPEC.loader.exec_module(publication)
candidate = publication.candidate


class PublicationContract(unittest.TestCase):
    def setUp(self) -> None:
        scratch = REPOSITORY_ROOT / "target" / "service-proxy-publication-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="case.", dir=scratch)
        self.root = pathlib.Path(self.temporary.name)
        self.context = self.root / "context"
        (self.context / "sbom").mkdir(parents=True)
        (self.context / "automata-ci-service-proxy").write_bytes(b"static helper")
        (self.context / "Containerfile").write_bytes(b"FROM scratch\n")
        (self.context / "LICENSE").write_bytes(b"fixture license\n")
        (self.context / "THIRD_PARTY_LICENSES.txt").write_bytes(
            b"fixture third-party licenses\n"
        )
        (self.context / "THIRD_PARTY_NOTICES.txt").write_bytes(
            b"fixture third-party notices\n"
        )
        (self.context / "VERSION").write_bytes(b"1.2.3\n")
        self.sbom = {
            "bomFormat": "CycloneDX",
            "components": [],
            "dependencies": [],
            "metadata": {
                "component": {
                    "hashes": [
                        {
                            "alg": "SHA-256",
                            "content": self.file_digest(
                                "automata-ci-service-proxy"
                            ),
                        }
                    ],
                    "name": "automata-ci-service-proxy",
                    "type": "application",
                    "version": "1.2.3",
                }
            },
            "specVersion": "1.5",
            "version": 1,
        }
        self.sbom_bytes = publication.canonical_json(self.sbom)
        (self.context / "sbom" / candidate.SBOM_NAME).write_bytes(self.sbom_bytes)
        self.candidate_commit = "a" * 40
        self.publisher_commit = "b" * 40
        self.release = {
            "created": "2023-11-14T22:13:20+00:00",
            "revision": self.candidate_commit,
            "source_date_epoch": 1_700_000_000,
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
        self.source_bytes = publication.canonical_json(self.source)
        (self.context / candidate.SOURCE_NAME).write_bytes(self.source_bytes)
        self.source_directory = self.root / "source"
        (self.source_directory / "images/service-proxy").mkdir(parents=True)
        (self.source_directory / "images/service-proxy/Containerfile").write_bytes(
            (self.context / "Containerfile").read_bytes()
        )
        (self.source_directory / "LICENSE").write_bytes(
            (self.context / "LICENSE").read_bytes()
        )
        (self.source_directory / "Cargo.toml").write_text(
            '[workspace]\n[workspace.package]\nversion = "1.2.3"\n',
            encoding="utf-8",
        )
        self.oci = self.root / "image.oci.tar"
        self.write_oci()
        self.candidate = self.root / "candidate.tar"
        with contextlib.redirect_stdout(io.StringIO()):
            candidate.create(
                argparse.Namespace(
                    context=self.context,
                    oci_archive=self.oci,
                    output=self.candidate,
                    github_output=None,
                )
            )

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

    def write_oci(self, directory_pax_headers: dict[str, str] | None = None) -> None:
        source_sha = hashlib.sha256(self.source_bytes).hexdigest()
        layer_stream = io.BytesIO()
        with tarfile.open(
            fileobj=layer_stream,
            mode="w",
            format=(
                tarfile.PAX_FORMAT
                if directory_pax_headers is not None
                else tarfile.USTAR_FORMAT
            ),
        ) as layer_archive:
            directories = (
                "usr",
                "usr/libexec",
                "usr/share",
                "usr/share/doc",
                "usr/share/doc/automata-ci-service-proxy",
                "usr/share/licenses",
                "usr/share/licenses/automata-ci-service-proxy",
                "usr/share/sbom",
            )
            for name in directories:
                info = tarfile.TarInfo(name)
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                info.mtime = self.release["source_date_epoch"]
                if name == "usr" and directory_pax_headers is not None:
                    info.pax_headers = directory_pax_headers
                layer_archive.addfile(info)
            files = {
                "usr/libexec/automata-ci-service-proxy": (
                    0o555,
                    (self.context / "automata-ci-service-proxy").read_bytes(),
                ),
                "usr/share/doc/automata-ci-service-proxy/VERSION": (
                    0o444,
                    (self.context / "VERSION").read_bytes(),
                ),
                "usr/share/doc/automata-ci-service-proxy/source-provenance.json": (
                    0o444,
                    self.source_bytes,
                ),
                "usr/share/licenses/automata-ci-service-proxy/LICENSE": (
                    0o444,
                    (self.context / "LICENSE").read_bytes(),
                ),
                (
                    "usr/share/licenses/automata-ci-service-proxy/"
                    "THIRD_PARTY_LICENSES.txt"
                ): (
                    0o444,
                    (self.context / "THIRD_PARTY_LICENSES.txt").read_bytes(),
                ),
                (
                    "usr/share/licenses/automata-ci-service-proxy/"
                    "THIRD_PARTY_NOTICES.txt"
                ): (
                    0o444,
                    (self.context / "THIRD_PARTY_NOTICES.txt").read_bytes(),
                ),
                "usr/share/sbom/automata-ci-service-proxy.cdx.json": (
                    0o444,
                    self.sbom_bytes,
                ),
            }
            for name, (mode, contents) in files.items():
                info = tarfile.TarInfo(name)
                info.mode = mode
                info.mtime = self.release["source_date_epoch"]
                info.size = len(contents)
                layer_archive.addfile(info, io.BytesIO(contents))
        layer = layer_stream.getvalue()
        config = json.dumps(
            {
                "architecture": "amd64",
                "config": {
                    "Entrypoint": ["/usr/libexec/automata-ci-service-proxy"],
                    "Env": [
                        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:"
                        "/sbin:/bin"
                    ],
                    "Labels": publication.expected_labels(self.source),
                    "User": "65532:65532",
                    "WorkingDir": "/",
                },
                "os": "linux",
                "rootfs": {
                    "diff_ids": [f"sha256:{hashlib.sha256(layer).hexdigest()}"],
                    "type": "layers",
                },
            },
            separators=(",", ":"),
        ).encode()
        self.assertEqual(
            publication.expected_labels(self.source)[
                "io.automata.service-proxy.source.sha256"
            ],
            source_sha,
        )
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
        index = json.dumps(
            {
                "manifests": [manifest_descriptor],
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "schemaVersion": 2,
            },
            separators=(",", ":"),
        ).encode()
        members = {
            "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
            "index.json": index,
            f"blobs/sha256/{config_descriptor['digest'][7:]}": config,
            f"blobs/sha256/{layer_descriptor['digest'][7:]}": layer,
            f"blobs/sha256/{manifest_descriptor['digest'][7:]}": manifest,
        }
        with tarfile.open(self.oci, "w") as archive:
            for name, contents in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(contents)
                archive.addfile(info, io.BytesIO(contents))

    def prepare(self, output_name: str = "review") -> pathlib.Path:
        output = self.root / output_name
        with contextlib.redirect_stdout(io.StringIO()):
            publication.prepare_candidate(
                argparse.Namespace(
                    candidate=self.candidate,
                    context=None,
                    source_directory=self.source_directory,
                    candidate_commit=self.candidate_commit,
                    publisher_commit=self.publisher_commit,
                    run_id="12345",
                    run_attempt="2",
                    output=output,
                    github_output=None,
                )
            )
        return output

    def load_review(self) -> tuple[pathlib.Path, dict, dict]:
        output = self.prepare()
        lock_path = output / "service-proxy-lock.proposed.json"
        identity_path = output / "service-proxy-source-identity.json"
        lock = publication.load_lock(lock_path)
        identity = json.loads(identity_path.read_bytes())
        return lock_path, lock, identity

    def test_candidate_preparation_emits_exact_review_lock_and_identity(self) -> None:
        output = self.prepare()
        lock = publication.load_lock(output / "service-proxy-lock.proposed.json")
        identity_bytes = (output / "service-proxy-source-identity.json").read_bytes()
        identity = publication.validate_source_identity(
            publication.load_canonical_json(identity_bytes, "identity"), lock
        )

        self.assertEqual(lock["candidate_commit"], self.candidate_commit)
        self.assertEqual(lock["publisher_commit"], self.publisher_commit)
        self.assertEqual(
            lock["source_identity_sha256"], hashlib.sha256(identity_bytes).hexdigest()
        )
        self.assertEqual(identity["image"]["name"], publication.IMAGE_NAME)
        self.assertTrue(lock["image"].startswith(f"{publication.IMAGE_NAME}@sha256:"))
        self.assertEqual(
            sorted(path.name for path in output.iterdir()),
            sorted(
                [
                    candidate.IMAGE_ARCHIVE_NAME,
                    candidate.SBOM_NAME,
                    candidate.SOURCE_NAME,
                    "service-proxy-lock.proposed.json",
                    "service-proxy-source-identity.json",
                ]
            ),
        )

    def test_candidate_archive_and_requested_commit_fail_closed(self) -> None:
        trailing = self.root / "trailing.tar"
        trailing.write_bytes(self.candidate.read_bytes() + b"unexpected")
        with self.assertRaisesRegex(SystemExit, "bytes are not canonical"):
            publication.prepare_candidate(
                argparse.Namespace(
                    candidate=trailing,
                    source_directory=self.source_directory,
                    candidate_commit=self.candidate_commit,
                    publisher_commit=self.publisher_commit,
                    run_id="1",
                    run_attempt="1",
                    output=self.root / "trailing-output",
                    github_output=None,
                )
            )
        with self.assertRaisesRegex(SystemExit, "revision differs"):
            publication.prepare_candidate(
                argparse.Namespace(
                    candidate=self.candidate,
                    source_directory=self.source_directory,
                    candidate_commit="c" * 40,
                    publisher_commit=self.publisher_commit,
                    run_id="1",
                    run_attempt="1",
                    output=self.root / "wrong-commit-output",
                    github_output=None,
                )
            )

    def test_cyclonedx_sbom_binds_the_binary_and_release(self) -> None:
        invalid_documents = []
        for path, value in (
            (("version",), 0),
            (("components",), {}),
            (("dependencies",), {}),
            (("metadata", "component", "name"), "different"),
            (("metadata", "component", "version"), "9.9.9"),
            (("metadata", "component", "type"), "library"),
            (("metadata", "component", "hashes", 0, "content"), "f" * 64),
        ):
            document = json.loads(json.dumps(self.sbom))
            target = document
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            invalid_documents.append(document)

        for document in invalid_documents:
            with self.subTest(document=document), self.assertRaisesRegex(
                SystemExit, "SBOM"
            ):
                publication.validate_cyclonedx(
                    document,
                    self.source["artifacts"]["binary_sha256"],
                    self.release["version"],
                    "test SBOM",
                )

    def test_layer_expansion_rejects_unknown_corrupt_and_oversize_payloads(self) -> None:
        payload = b"bounded layer contents"
        compressed = gzip.compress(payload, mtime=0)
        self.assertEqual(
            publication.expanded_layer(
                compressed, "application/vnd.oci.image.layer.v1.tar+gzip"
            ),
            payload,
        )
        with self.assertRaisesRegex(SystemExit, "media type differs"):
            publication.expanded_layer(payload, "application/octet-stream")
        with self.assertRaisesRegex(SystemExit, "compression is invalid"):
            publication.expanded_layer(
                b"not gzip", "application/vnd.oci.image.layer.v1.tar+gzip"
            )
        with mock.patch.object(publication, "MAX_EXPANDED_LAYER_SIZE", 8):
            for contents, media_type in (
                (payload, "application/vnd.oci.image.layer.v1.tar"),
                (compressed, "application/vnd.oci.image.layer.v1.tar+gzip"),
            ):
                with self.subTest(media_type=media_type), self.assertRaisesRegex(
                    SystemExit, "expanded size limit"
                ):
                    publication.expanded_layer(contents, media_type)

    def test_overlay_storage_pax_metadata_remains_forbidden(self) -> None:
        for index, headers in enumerate(
            (
                {"SCHILY.xattr.user.overlay.origin": ""},
                {"SCHILY.xattr.user.overlay.impure": "y"},
            )
        ):
            with self.subTest(headers=headers):
                self.write_oci(headers)
                tainted_candidate = self.root / f"overlay-{index}.tar"
                candidate.create(
                    argparse.Namespace(
                        context=self.context,
                        oci_archive=self.oci,
                        output=tainted_candidate,
                        github_output=None,
                    )
                )
                with self.assertRaisesRegex(SystemExit, "unsafe entry"):
                    publication.prepare_candidate(
                        argparse.Namespace(
                            candidate=tainted_candidate,
                            source_directory=self.source_directory,
                            candidate_commit=self.candidate_commit,
                            publisher_commit=self.publisher_commit,
                            run_id="1",
                            run_attempt="1",
                            output=self.root / f"overlay-output-{index}",
                            github_output=None,
                        )
                    )

    def test_credentialed_publisher_requires_exact_candidate_source(self) -> None:
        containerfile = self.source_directory / "images/service-proxy/Containerfile"
        containerfile.write_bytes(
            b"FROM changed\n"
        )
        with self.assertRaisesRegex(SystemExit, "exact source checkout"):
            self.prepare("changed-source-output")
        containerfile.write_bytes((self.context / "Containerfile").read_bytes())

        license_path = self.source_directory / "LICENSE"
        license_path.write_bytes(b"changed license\n")
        with self.assertRaisesRegex(SystemExit, "license differs"):
            self.prepare("changed-license-output")
        license_path.write_bytes((self.context / "LICENSE").read_bytes())

        (self.source_directory / "Cargo.toml").write_text(
            '[workspace]\n[workspace.package]\nversion = "9.9.9"\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(SystemExit, "version differs"):
            self.prepare("changed-version-output")

    def test_reviewed_lock_and_dispatch_inputs_are_exact(self) -> None:
        lock_path, lock, _ = self.load_review()
        digest = lock["image"].rsplit("@", 1)[1]
        publication.validate_request(
            argparse.Namespace(
                operation="promote-locked",
                default_branch="main",
                dispatch_ref="refs/heads/main",
                candidate_commit="",
                confirmed_digest=digest,
                lock=lock_path,
                github_output=None,
            )
        )
        with self.assertRaisesRegex(SystemExit, "pasted digest"):
            publication.validate_request(
                argparse.Namespace(
                    operation="promote-locked",
                    default_branch="main",
                    dispatch_ref="refs/heads/main",
                    candidate_commit="",
                    confirmed_digest=f"sha256:{'f' * 64}",
                    lock=lock_path,
                    github_output=None,
                )
            )
        with self.assertRaisesRegex(SystemExit, "must be dispatched"):
            publication.validate_request(
                argparse.Namespace(
                    operation="build-candidate",
                    default_branch="main",
                    dispatch_ref="refs/heads/topic",
                    candidate_commit=self.candidate_commit,
                    confirmed_digest="",
                    lock=lock_path,
                    github_output=None,
                )
            )

    def test_unpopulated_and_noncanonical_locks_fail_closed(self) -> None:
        waiting = self.root / "waiting.json"
        waiting.write_bytes(
            publication.canonical_json(
                {
                    "binary_sha256": None,
                    "candidate_commit": None,
                    "containerfile_sha256": None,
                    "image": None,
                    "publisher_commit": None,
                    "sbom_sha256": None,
                    "schema_version": 1,
                    "source_identity_sha256": None,
                    "source_provenance_sha256": None,
                }
            )
        )
        with self.assertRaisesRegex(SystemExit, "awaiting a candidate"):
            publication.load_lock(waiting)

        lock_path, lock, _ = self.load_review()
        lock["schema_version"] = True
        lock_path.chmod(0o644)
        lock_path.write_bytes(publication.canonical_json(lock))
        with self.assertRaisesRegex(SystemExit, "schema"):
            publication.load_lock(lock_path)

        duplicate = self.root / "duplicate.json"
        duplicate.write_text(
            '{"schema_version":1,"schema_version":1}\n', encoding="utf-8"
        )
        with self.assertRaisesRegex(SystemExit, "invalid JSON"):
            publication.load_lock(duplicate)

        symlink = self.root / "lock-link.json"
        symlink.symlink_to(lock_path)
        with self.assertRaisesRegex(SystemExit, "accessible regular file"):
            publication.load_lock(symlink)

    def test_attestation_verification_fails_closed_for_automata_jobs(self) -> None:
        with self.assertRaisesRegex(
            SystemExit,
            "GitHub-hosted Actions provenance cannot authenticate a self-hosted Automata job",
        ):
            publication.verify_attestations(argparse.Namespace())

    def image_config(self, identity: dict) -> dict:
        artifacts = identity["artifacts"]
        release = identity["release"]
        return {
            "architecture": "amd64",
            "config": {
                "Entrypoint": identity["runtime"]["entrypoint"],
                "Env": [
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                ],
                "Labels": {
                    "io.automata.service-proxy.binary.sha256": artifacts[
                        "binary_sha256"
                    ],
                    "io.automata.service-proxy.protocol-version": "1",
                    "io.automata.service-proxy.sbom.sha256": artifacts[
                        "sbom_sha256"
                    ],
                    "io.automata.service-proxy.source.sha256": artifacts[
                        "source_provenance_sha256"
                    ],
                    "org.opencontainers.image.created": release["created"],
                    "org.opencontainers.image.description": (
                        "Namespace-local bounded TCP and UDP proxy for job service "
                        "containers"
                    ),
                    "org.opencontainers.image.licenses": "MIT",
                    "org.opencontainers.image.revision": identity["build"][
                        "candidate_commit"
                    ],
                    "org.opencontainers.image.source": (
                        "https://github.com/automata-ci/automata"
                    ),
                    "org.opencontainers.image.title": "Automata CI service proxy",
                    "org.opencontainers.image.version": release["version"],
                },
                "User": identity["runtime"]["user"],
                "WorkingDir": "/",
            },
            "os": "linux",
        }

    def test_image_config_requires_every_exact_label_and_runtime_field(self) -> None:
        output = self.prepare()
        identity_path = output / "service-proxy-source-identity.json"
        identity = json.loads(identity_path.read_bytes())
        config_path = self.root / "config.json"
        config_path.write_text(
            json.dumps(self.image_config(identity)), encoding="utf-8"
        )
        publication.verify_image_config(
            argparse.Namespace(config=config_path, identity=identity_path)
        )

        changed = self.image_config(identity)
        changed["config"]["Labels"]["unexpected"] = "label"
        config_path.write_text(json.dumps(changed), encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "labels differ"):
            publication.verify_image_config(
                argparse.Namespace(config=config_path, identity=identity_path)
            )

    def test_default_branch_remote_head_is_singular_and_current(self) -> None:
        remote = self.root / "remote.txt"
        remote.write_text(
            f"{self.publisher_commit}\trefs/heads/main\n", encoding="ascii"
        )
        publication.verify_remote_head(
            argparse.Namespace(
                remote_output=remote,
                expected_ref="refs/heads/main",
                expected_sha=self.publisher_commit,
            )
        )
        with self.assertRaisesRegex(SystemExit, "moved after dispatch"):
            publication.verify_remote_head(
                argparse.Namespace(
                    remote_output=remote,
                    expected_ref="refs/heads/main",
                    expected_sha="c" * 40,
                )
            )


if __name__ == "__main__":
    unittest.main()
