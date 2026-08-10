#!/usr/bin/env python3
"""Fail-closed package-license regression tests using repository-local scratch."""

from __future__ import annotations

import contextlib
import http.client
import http.server
import importlib.util
import io
import json
import pathlib
import struct
import sys
import tarfile
import tempfile
import threading
import unittest
from unittest import mock


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[3]
PUBLISH_SCRIPT = REPOSITORY_ROOT / "scripts" / "ci" / "publish-crates.py"
SPEC = importlib.util.spec_from_file_location("publish_crates", PUBLISH_SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not load {PUBLISH_SCRIPT}")
publish_crates = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = publish_crates
SPEC.loader.exec_module(publish_crates)


def add_regular(archive: tarfile.TarFile, name: str, contents: bytes) -> None:
    member = tarfile.TarInfo(name)
    member.size = len(contents)
    member.mode = 0o644
    archive.addfile(member, io.BytesIO(contents))


def publish_metadata() -> dict:
    return {
        "name": "automata-ci-test",
        "readme": "# test\n",
        "readme_file": "README.md",
        "vers": "0.1.0",
    }


def metadata_for(names: list[str]) -> dict:
    packages = [
        {
            "id": name,
            "name": name,
            "publish": ["crates-io"],
        }
        for name in names
    ]
    return {
        "packages": packages,
        "resolve": {
            "nodes": [{"deps": [], "id": name} for name in names],
        },
        "workspace_members": names,
    }


def metadata_with_private_member(*, dependency_kind: str = "dev") -> dict:
    return {
        "packages": [
            {
                "id": "public-id",
                "name": "automata-ci-public",
                "publish": ["crates-io"],
            },
            {
                "id": "private-id",
                "name": "automata-ci-private",
                "publish": [],
            },
        ],
        "resolve": {
            "nodes": [
                {
                    "deps": [
                        {
                            "dep_kinds": [
                                {"kind": dependency_kind, "target": None}
                            ],
                            "pkg": "private-id",
                        }
                    ],
                    "id": "public-id",
                },
                {"deps": [], "id": "private-id"},
            ],
        },
        "workspace_members": ["public-id", "private-id"],
    }


def local_connection(
    target,
) -> http.client.HTTPConnection:
    return http.client.HTTPConnection(target.hostname, target.port, timeout=60)


@contextlib.contextmanager
def capture_server(status: int = 200, body: bytes = b'{"warnings":{}}'):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_PUT(self) -> None:
            length = int(self.headers["Content-Length"])
            self.server.requests.append(  # type: ignore[attr-defined]
                (self.path, dict(self.headers), self.rfile.read(length))
            )
            self.send_response(self.server.response_status)  # type: ignore[attr-defined]
            if self.server.redirect_location:  # type: ignore[attr-defined]
                self.send_header(
                    "Location", self.server.redirect_location  # type: ignore[attr-defined]
                )
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(self.server.response_body)  # type: ignore[attr-defined]

        def log_message(self, format: str, *arguments: object) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.requests = []
    server.response_status = status
    server.response_body = body
    server.redirect_location = None
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, f"http://127.0.0.1:{server.server_port}/api/v1/crates/new"
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


class PackageLicenseContract(unittest.TestCase):
    def setUp(self) -> None:
        scratch_root = REPOSITORY_ROOT / "target" / "task-tmp" / "publish-crates-tests"
        scratch_root.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="case.", dir=scratch_root)
        self.root = pathlib.Path(self.temporary.name)
        self.license_bytes = b"canonical license\n"
        (self.root / "LICENSE").write_bytes(self.license_bytes)
        self.package_directory = self.root / "automata-ci-test"
        self.package_directory.mkdir()
        (self.package_directory / "Cargo.toml").write_text(
            '[package]\nname = "automata-ci-test"\nversion = "0.1.0"\n',
            encoding="utf-8",
        )
        (self.package_directory / "README.md").write_text("# test\n", encoding="utf-8")
        (self.package_directory / "LICENSE").write_bytes(self.license_bytes)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_cargo_metadata_resolves_every_feature_before_publication(self) -> None:
        completed = mock.Mock(stdout='{"packages": []}')
        with mock.patch.object(
            publish_crates.subprocess, "run", return_value=completed
        ) as run:
            self.assertEqual(publish_crates.cargo_metadata(self.root), {"packages": []})

        command = run.call_args.args[0]
        self.assertIn("--all-features", command)
        self.assertIn("--locked", command)
        self.assertNotIn("--no-deps", command)

    def test_private_workspace_members_are_never_published(self) -> None:
        ordered = publish_crates.publication_order(metadata_with_private_member())
        self.assertEqual(
            [package["name"] for package in ordered],
            ["automata-ci-public"],
        )

        with self.assertRaisesRegex(
            SystemExit,
            "non-development dependency on private workspace crate",
        ):
            publish_crates.publication_order(
                metadata_with_private_member(dependency_kind="normal")
            )

    def test_mutated_and_symbolic_source_licenses_fail_closed(self) -> None:
        publish_crates.validate_source_license(
            "automata-ci-test", self.package_directory, self.license_bytes
        )

        license_path = self.package_directory / "LICENSE"
        license_path.write_bytes(b"mutated\n")
        with self.assertRaisesRegex(SystemExit, "differs from the repository LICENSE"):
            publish_crates.validate_source_license(
                "automata-ci-test", self.package_directory, self.license_bytes
            )

        license_path.unlink()
        license_path.symlink_to(self.root / "LICENSE")
        with self.assertRaisesRegex(SystemExit, "regular, non-symbolic-link file"):
            publish_crates.validate_source_license(
                "automata-ci-test", self.package_directory, self.license_bytes
            )

    def test_archive_license_must_be_a_regular_file(self) -> None:
        archive_directory = self.root / "target" / "package"
        archive_directory.mkdir(parents=True)
        archive_path = archive_directory / "automata-ci-test-0.1.0.crate"
        prefix = "automata-ci-test-0.1.0"
        with tarfile.open(archive_path, "w:gz") as archive:
            add_regular(archive, f"{prefix}/Cargo.toml", b"[package]\n")
            add_regular(archive, f"{prefix}/Cargo.toml.orig", b"[package]\n")
            add_regular(archive, f"{prefix}/README.md", b"# test\n")
            license_member = tarfile.TarInfo(f"{prefix}/LICENSE")
            license_member.type = tarfile.SYMTYPE
            license_member.linkname = "README.md"
            archive.addfile(license_member)

        package = {
            "name": "automata-ci-test",
            "version": "0.1.0",
            "manifest_path": str(self.package_directory / "Cargo.toml"),
        }
        with self.assertRaisesRegex(SystemExit, "non-regular entry"):
            publish_crates.crate_checksum(self.root, package)

    def test_hidden_gnu_longname_expansion_is_bounded(self) -> None:
        archive_directory = self.root / "target" / "package"
        archive_directory.mkdir(parents=True)
        archive_path = archive_directory / "automata-ci-test-0.1.0.crate"
        prefix = "automata-ci-test-0.1.0"
        with tarfile.open(
            archive_path, "w:gz", format=tarfile.GNU_FORMAT
        ) as archive:
            add_regular(archive, f"{prefix}/{'x' * 4096}", b"x")
        package = {
            "name": "automata-ci-test",
            "version": "0.1.0",
            "manifest_path": str(self.package_directory / "Cargo.toml"),
        }
        original_limit = publish_crates.MAX_CRATE_STREAM_SIZE
        publish_crates.MAX_CRATE_STREAM_SIZE = 1024
        try:
            with self.assertRaisesRegex(SystemExit, "decompressed stream exceeds"):
                publish_crates.crate_checksum(self.root, package)
        finally:
            publish_crates.MAX_CRATE_STREAM_SIZE = original_limit

    def test_archive_expansion_and_prepared_plan_are_bounded_and_bound(self) -> None:
        archive_directory = self.root / "target" / "package"
        archive_directory.mkdir(parents=True)
        archive_path = archive_directory / "automata-ci-test-0.1.0.crate"
        prefix = "automata-ci-test-0.1.0"
        with tarfile.open(archive_path, "w:gz") as archive:
            add_regular(archive, f"{prefix}/Cargo.toml", b"[package]\n")
            add_regular(archive, f"{prefix}/Cargo.toml.orig", b"[package]\n")
            add_regular(archive, f"{prefix}/README.md", b"# test\n")
            add_regular(archive, f"{prefix}/LICENSE", self.license_bytes)
        package = {
            "name": "automata-ci-test",
            "version": "0.1.0",
            "manifest_path": str(self.package_directory / "Cargo.toml"),
        }
        original_limit = publish_crates.MAX_CRATE_CONTENT_SIZE
        publish_crates.MAX_CRATE_CONTENT_SIZE = 1
        try:
            with self.assertRaisesRegex(SystemExit, "expands beyond"):
                publish_crates.crate_checksum(self.root, package)
        finally:
            publish_crates.MAX_CRATE_CONTENT_SIZE = original_limit

        checksum = publish_crates.sha256_bytes(archive_path.read_bytes())
        plan = {
            "packages": [
                {
                    "metadata": publish_metadata(),
                    "name": "automata-ci-test",
                    "sha256": checksum,
                    "version": "0.1.0",
                }
            ],
            "publish_required": True,
            "release_manifest_sha256": "a" * 64,
            "schema_version": 1,
        }
        plan_path = self.root / "plan.json"
        plan_bytes = publish_crates.canonical_json(plan)
        plan_path.write_bytes(plan_bytes)
        loaded = publish_crates.load_plan(
            plan_path, publish_crates.sha256_bytes(plan_bytes)
        )
        self.assertEqual(loaded, plan)
        plan_path.write_text(json.dumps(plan), encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "digest changed"):
            publish_crates.load_plan(
                plan_path, publish_crates.sha256_bytes(plan_bytes)
            )

    def test_normalized_manifest_binds_minimal_crates_io_metadata(self) -> None:
        archive_directory = self.root / "target" / "package"
        archive_directory.mkdir(parents=True)
        archive_path = archive_directory / "automata-ci-test-0.1.0.crate"
        prefix = "automata-ci-test-0.1.0"
        manifest = b"""[package]
name = "automata-ci-test"
version = "0.1.0"
readme = "README.md"
publish = ["crates-io"]
license = "MIT"
repository = "https://github.com/automata-ci/automata"

[dependencies.serde]
version = "1"

[build-dependencies.cc]
version = "1"

[dev-dependencies.tempfile]
version = "3"

[target.'cfg(unix)'.dependencies.libc]
version = "0.2"
"""
        with tarfile.open(archive_path, "w:gz") as archive:
            add_regular(archive, f"{prefix}/Cargo.toml", manifest)
            add_regular(archive, f"{prefix}/Cargo.toml.orig", manifest)
            add_regular(archive, f"{prefix}/README.md", b"# test\n")
            add_regular(archive, f"{prefix}/LICENSE", self.license_bytes)
        package = {
            "name": "automata-ci-test",
            "version": "0.1.0",
            "manifest_path": str(self.package_directory / "Cargo.toml"),
        }
        checksum, metadata = publish_crates.inspect_crate(self.root, package)
        self.assertEqual(checksum, publish_crates.sha256_bytes(archive_path.read_bytes()))
        self.assertEqual(metadata, publish_metadata())

        unsupported = manifest.replace(
            b'license = "MIT"', b'license-file = "LICENSE"'
        )
        with tarfile.open(archive_path, "w:gz") as archive:
            add_regular(archive, f"{prefix}/Cargo.toml", unsupported)
            add_regular(archive, f"{prefix}/Cargo.toml.orig", unsupported)
            add_regular(archive, f"{prefix}/README.md", b"# test\n")
            add_regular(archive, f"{prefix}/LICENSE", self.license_bytes)
        with self.assertRaisesRegex(SystemExit, "differs from Cargo metadata"):
            publish_crates.inspect_crate(self.root, package)

    def test_initial_name_capacity_and_owner_allowlist_fail_closed(self) -> None:
        names = [f"automata-ci-test-{index}" for index in range(6)]
        metadata = metadata_for(names)
        with mock.patch.object(publish_crates, "crate_exists", return_value=False):
            with self.assertRaisesRegex(SystemExit, "initial burst"):
                publish_crates.check_initial_capacity(
                    metadata, {"expected-owner"}, "false"
                )
            self.assertEqual(
                publish_crates.check_initial_capacity(
                    metadata, {"expected-owner"}, "true"
                ),
                names,
            )

        with (
            mock.patch.object(publish_crates, "crate_exists", return_value=True),
            mock.patch.object(
                publish_crates,
                "crate_owner_logins",
                return_value={"unexpected-owner"},
            ),
        ):
            with self.assertRaisesRegex(SystemExit, "configured allowlist"):
                publish_crates.check_initial_capacity(
                    metadata_for([names[0]]), {"expected-owner"}, "false"
                )

        self.assertEqual(
            publish_crates.parse_owner_allowlist("automata-ci,release-owner"),
            {"automata-ci", "release-owner"},
        )
        with self.assertRaisesRegex(SystemExit, "sorted, comma-separated"):
            publish_crates.parse_owner_allowlist("release-owner,automata-ci")

    def test_publication_order_rejects_ambiguous_registry_policy(self) -> None:
        metadata = metadata_for(["automata-ci-public"])
        metadata["packages"][0]["publish"] = None
        with self.assertRaisesRegex(
            SystemExit, "set publish = false or restrict publishing to crates.io"
        ):
            publish_crates.publication_order(metadata)

    def test_existing_version_must_be_exact_and_not_yanked(self) -> None:
        checksum = "a" * 64
        response = {
            "version": {
                "checksum": checksum,
                "crate": "automata-ci-test",
                "num": "0.1.0",
                "yanked": False,
            }
        }
        with mock.patch.object(
            publish_crates, "crates_io_document", return_value=response
        ):
            self.assertEqual(
                publish_crates.published_checksum("automata-ci-test", "0.1.0"),
                checksum,
            )

        response["version"]["yanked"] = True
        with mock.patch.object(
            publish_crates, "crates_io_document", return_value=response
        ):
            with self.assertRaisesRegex(SystemExit, "as yanked"):
                publish_crates.published_checksum("automata-ci-test", "0.1.0")

        response["version"]["yanked"] = False
        response["version"]["num"] = "0.2.0"
        with mock.patch.object(
            publish_crates, "crates_io_document", return_value=response
        ):
            with self.assertRaisesRegex(SystemExit, "wrong identity"):
                publish_crates.published_checksum("automata-ci-test", "0.1.0")

    def test_exact_publish_framing_and_token_header(self) -> None:
        archive = b"exact prepared crate bytes"
        with capture_server() as (server, endpoint):
            publish_crates.upload_exact_archive(
                publish_metadata(),
                archive,
                "secret-token",
                endpoint=endpoint,
                connection_factory=local_connection,
            )
        self.assertEqual(len(server.requests), 1)
        path, headers, body = server.requests[0]
        self.assertEqual(path, "/api/v1/crates/new")
        self.assertEqual(headers["Authorization"], "secret-token")
        metadata_size = struct.unpack("<I", body[:4])[0]
        metadata_end = 4 + metadata_size
        crate_size = struct.unpack("<I", body[metadata_end : metadata_end + 4])[0]
        self.assertEqual(
            json.loads(body[4:metadata_end]),
            publish_metadata(),
        )
        self.assertEqual(crate_size, len(archive))
        self.assertEqual(body[metadata_end + 4 :], archive)

    def test_publish_refuses_redirects_and_oversized_responses(self) -> None:
        with capture_server(status=307) as (server, endpoint):
            server.redirect_location = endpoint + "/redirected"
            with self.assertRaisesRegex(
                publish_crates.AmbiguousUpload, "redirect HTTP 307"
            ):
                publish_crates.upload_exact_archive(
                    publish_metadata(),
                    b"crate",
                    "token",
                    endpoint=endpoint,
                    connection_factory=local_connection,
                )
        self.assertEqual(len(server.requests), 1)

        oversized = b"x" * (publish_crates.MAX_API_RESPONSE_SIZE + 1)
        with capture_server(body=oversized) as (_, endpoint):
            with self.assertRaisesRegex(
                publish_crates.AmbiguousUpload, "oversized response"
            ):
                publish_crates.upload_exact_archive(
                    publish_metadata(),
                    b"crate",
                    "token",
                    endpoint=endpoint,
                    connection_factory=local_connection,
                )

        with capture_server(status=403, body=b"private rejection detail") as (
            _,
            endpoint,
        ):
            with self.assertRaisesRegex(publish_crates.AmbiguousUpload, "HTTP 403"):
                publish_crates.upload_exact_archive(
                    publish_metadata(),
                    b"crate",
                    "token",
                    endpoint=endpoint,
                    connection_factory=local_connection,
                )

        with capture_server(body=b"not-json") as (_, endpoint):
            with self.assertRaisesRegex(
                publish_crates.AmbiguousUpload, "invalid JSON"
            ):
                publish_crates.upload_exact_archive(
                    publish_metadata(),
                    b"crate",
                    "token",
                    endpoint=endpoint,
                    connection_factory=local_connection,
                )

        with capture_server(body=b'{"errors":{}}') as (_, endpoint):
            with self.assertRaisesRegex(
                publish_crates.AmbiguousUpload, "error response"
            ):
                publish_crates.upload_exact_archive(
                    publish_metadata(),
                    b"crate",
                    "token",
                    endpoint=endpoint,
                    connection_factory=local_connection,
                )

    def test_ambiguous_upload_is_reconciled_without_retry(self) -> None:
        archive_directory = self.root / "target" / "package"
        archive_directory.mkdir(parents=True)
        archive = b"exact archive"
        archive_path = archive_directory / "automata-ci-test-0.1.0.crate"
        archive_path.write_bytes(archive)
        checksum = publish_crates.sha256_bytes(archive)
        plan = {
            "packages": [
                {
                    "metadata": publish_metadata(),
                    "name": "automata-ci-test",
                    "sha256": checksum,
                    "version": "0.1.0",
                }
            ]
        }

        class FailingConnection:
            calls = 0

            def request(self, method, path, body, headers):
                self.calls += 1
                raise ConnectionResetError("connection reset")

            def close(self):
                pass

        connection = FailingConnection()
        with (
            mock.patch.object(
                publish_crates,
                "published_checksum",
                side_effect=[None, checksum],
            ),
            mock.patch.object(publish_crates, "crate_exists", return_value=False),
            mock.patch.object(
                publish_crates, "require_expected_owners"
            ) as owners,
        ):
            publish_crates.execute_plan(
                self.root,
                plan,
                "token",
                {"expected-owner"},
                "true",
                endpoint="http://unused.invalid/api/v1/crates/new",
                connection_factory=lambda _: connection,
            )
        self.assertEqual(connection.calls, 1)
        owners.assert_called_once_with("automata-ci-test", {"expected-owner"})

    def test_existing_crate_rate_pacing_and_per_upload_visibility(self) -> None:
        archive = b"exact archive"
        checksum = publish_crates.sha256_bytes(archive)
        packages = []
        for index in range(publish_crates.EXISTING_CRATE_BURST + 1):
            name = f"automata-ci-test-{index:02d}"
            metadata = publish_metadata()
            metadata["name"] = name
            packages.append(
                {
                    "metadata": metadata,
                    "name": name,
                    "sha256": checksum,
                    "version": "0.1.0",
                }
            )
        plan = {"packages": packages}
        with (
            mock.patch.object(
                publish_crates, "artifact_bytes", return_value=archive
            ),
            mock.patch.object(
                publish_crates, "published_checksum", return_value=None
            ),
            mock.patch.object(publish_crates, "crate_exists", return_value=True),
            mock.patch.object(publish_crates, "require_expected_owners"),
            mock.patch.object(publish_crates, "upload_exact_archive") as upload,
            mock.patch.object(publish_crates, "wait_until_visible") as visible,
            mock.patch.object(publish_crates.time, "monotonic", return_value=0.0),
            mock.patch.object(publish_crates.time, "sleep") as sleep,
        ):
            publish_crates.execute_plan(
                self.root, plan, "token", {"expected-owner"}, "false"
            )
        self.assertEqual(upload.call_count, len(packages))
        self.assertEqual(visible.call_count, len(packages))
        sleep.assert_called_once_with(
            publish_crates.EXISTING_CRATE_INTERVAL_SECONDS
        )

    def test_new_claims_verify_visibility_and_owner_before_the_next_put(self) -> None:
        archive = b"exact archive"
        checksum = publish_crates.sha256_bytes(archive)
        packages = []
        for index in range(2):
            name = f"automata-ci-new-{index}"
            metadata = publish_metadata()
            metadata["name"] = name
            packages.append(
                {
                    "metadata": metadata,
                    "name": name,
                    "sha256": checksum,
                    "version": "0.1.0",
                }
            )
        events = []

        def upload(metadata, *_arguments, **_keywords):
            events.append(f"upload:{metadata['name']}")

        def visible(name, *_arguments, **_keywords):
            events.append(f"visible:{name}")

        def owned(name, _expected):
            events.append(f"owner:{name}")

        with (
            mock.patch.object(
                publish_crates, "artifact_bytes", return_value=archive
            ),
            mock.patch.object(
                publish_crates, "published_checksum", return_value=None
            ),
            mock.patch.object(publish_crates, "crate_exists", return_value=False),
            mock.patch.object(
                publish_crates, "upload_exact_archive", side_effect=upload
            ),
            mock.patch.object(
                publish_crates, "wait_until_visible", side_effect=visible
            ),
            mock.patch.object(
                publish_crates, "require_expected_owners", side_effect=owned
            ),
        ):
            publish_crates.execute_plan(
                self.root,
                {"packages": packages},
                "token",
                {"expected-owner"},
                "true",
            )
        self.assertEqual(
            events,
            [
                "upload:automata-ci-new-0",
                "visible:automata-ci-new-0",
                "owner:automata-ci-new-0",
                "upload:automata-ci-new-1",
                "visible:automata-ci-new-1",
                "owner:automata-ci-new-1",
            ],
        )

    def test_executor_requires_the_bound_initial_burst_override(self) -> None:
        archive = b"exact archive"
        checksum = publish_crates.sha256_bytes(archive)
        packages = []
        for index in range(publish_crates.NEW_CRATE_BURST + 1):
            name = f"automata-ci-new-{index}"
            metadata = publish_metadata()
            metadata["name"] = name
            packages.append(
                {
                    "metadata": metadata,
                    "name": name,
                    "sha256": checksum,
                    "version": "0.1.0",
                }
            )
        with (
            mock.patch.object(
                publish_crates, "artifact_bytes", return_value=archive
            ),
            mock.patch.object(
                publish_crates, "published_checksum", return_value=None
            ),
            mock.patch.object(publish_crates, "crate_exists", return_value=False),
            mock.patch.object(publish_crates, "upload_exact_archive") as upload,
        ):
            with self.assertRaisesRegex(SystemExit, "override is not approved"):
                publish_crates.execute_plan(
                    self.root,
                    {"packages": packages},
                    "token",
                    {"expected-owner"},
                    "false",
                )
        upload.assert_not_called()

        with self.assertRaisesRegex(SystemExit, "token is missing or malformed"):
            publish_crates.execute_plan(
                self.root,
                {"packages": []},
                "tøken",
                {"expected-owner"},
                "false",
            )

    def test_visible_checksum_mismatch_fails_closed(self) -> None:
        with mock.patch.object(
            publish_crates, "published_checksum", return_value="b" * 64
        ):
            with self.assertRaisesRegex(SystemExit, "published checksum mismatch"):
                publish_crates.wait_until_visible(
                    "automata-ci-test", "0.1.0", "a" * 64
                )


if __name__ == "__main__":
    unittest.main()
