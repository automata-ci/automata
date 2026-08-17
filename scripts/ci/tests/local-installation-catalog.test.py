#!/usr/bin/env python3
"""Fail-closed tests for the local-installation release catalog."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import shutil
import sys
import tempfile
import unittest
from unittest import mock


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[3]
SCRIPT = REPOSITORY_ROOT / "scripts" / "ci" / "local_installation_catalog.py"
SPEC = importlib.util.spec_from_file_location("local_installation_catalog", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not load {SCRIPT}")
catalog = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = catalog
SPEC.loader.exec_module(catalog)


def rust_integer_constant(relative_path: str, name: str) -> int:
    source = (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")
    match = re.search(
        rf"^pub const {re.escape(name)}: [A-Za-z0-9_:]+ = "
        r"([0-9][0-9_]*(?: \* [0-9][0-9_]*)*);$",
        source,
        flags=re.MULTILINE,
    )
    if match is None:
        raise AssertionError(f"could not resolve Rust constant {name}")
    factors = (int(value.replace("_", "")) for value in match.group(1).split(" * "))
    result = 1
    for factor in factors:
        result *= factor
    return result


def rust_string_constant(relative_path: str, name: str) -> str:
    source = (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")
    match = re.search(
        rf'^(?:pub(?:\(crate\))? )?const {re.escape(name)}: &str = "([^"\\]*)";$',
        source,
        flags=re.MULTILINE,
    )
    if match is None:
        raise AssertionError(f"could not resolve Rust constant {name}")
    return match.group(1)


class LocalInstallationCatalogContract(unittest.TestCase):
    def setUp(self) -> None:
        self.release = {
            "commit": "a" * 40,
            "created": "2026-08-17T00:00:00+00:00",
            "prerelease": False,
            "source_date_epoch": 1_786_924_800,
            "tag": "v1.2.3",
            "tag_object": "b" * 40,
            "version": "1.2.3",
        }
        self.source = catalog.load_source(REPOSITORY_ROOT)
        self.candidate_binding = {
            "candidate_provenance_sha256": "1" * 64,
            "config_digest": f"sha256:{'2' * 64}",
            "image_digest": f"sha256:{'3' * 64}",
            "image_name": "ghcr.io/automata-ci/automata-service-proxy",
            "kind": "release-candidate",
            "oci_archive_sha256": "4" * 64,
            "path": catalog.SERVICE_PROXY_CANDIDATE_PATH,
            "sha256": "5" * 64,
            "source_provenance_sha256": "6" * 64,
        }

    def process(self, role: str) -> dict:
        expected = self.source["images"][role]["config"]
        labels = dict(expected["required_labels"])
        if role in catalog.RELEASE_REGISTRY_ROLES:
            labels.update(
                {
                    "org.opencontainers.image.created": self.release["created"],
                    "org.opencontainers.image.revision": self.release["commit"],
                    "org.opencontainers.image.version": self.release["version"],
                }
            )
        return {
            "Cmd": expected["command"],
            "Entrypoint": expected["entrypoint"],
            "Env": [
                f"{name}={value}"
                for name, value in expected["required_environment"].items()
            ],
            "Labels": labels,
            "User": expected["user"],
            "WorkingDir": expected["working_directory"],
        }

    def evidence(self, role: str, byte: str) -> dict:
        source = self.source["images"][role]["source"]
        if role in catalog.RELEASE_REGISTRY_ROLES:
            top = f"sha256:{byte * 64}"
            reference = f"{source['repository']}@{top}"
            platform = f"sha256:{chr(ord(byte) + 1) * 64}"
            config_digest = f"sha256:{chr(ord(byte) + 2) * 64}"
        else:
            reference = source["reference"]
            top = reference.rsplit("@", 1)[1]
            platform = source["platform_manifest_digest"]
            config_digest = source["config_digest"]
        return {
            "architecture": "amd64",
            "config": self.process(role),
            "config_digest": config_digest,
            "os": "linux",
            "platform_manifest_digest": platform,
            "reference": reference,
            "top_level_digest": top,
        }

    def all_evidence(self) -> dict[str, dict]:
        return {
            role: self.evidence(role, byte)
            for role, byte in zip(
                sorted(catalog.REGISTRY_ROLES), "789abc", strict=True
            )
        }

    def build(self) -> dict:
        with mock.patch.object(
            catalog,
            "validate_service_proxy_candidate",
            return_value=self.candidate_binding,
        ):
            return catalog.build_catalog(
                REPOSITORY_ROOT,
                self.release,
                self.all_evidence(),
                REPOSITORY_ROOT / catalog.SERVICE_PROXY_CANDIDATE_PATH,
            )

    def test_source_contract_and_profile_bind_exact_reviewed_bytes(self) -> None:
        source = catalog.load_source(REPOSITORY_ROOT)
        self.assertEqual(set(source["images"]), catalog.ROLES)
        self.assertEqual(source["scope"], {"engine": "linux/amd64", "host": "unix"})
        profile = catalog.load_profile(REPOSITORY_ROOT, source)
        self.assertEqual(
            profile["manifest"]["sha256"],
            "f7a6f8e592a484f59330bf2cedd839adc75488618ee58efcc3c3d4957d186e21",
        )
        self.assertEqual(
            profile["lock"]["sha256"],
            "05fb47e52d497bb1cb887c19e4b865cfe49da73d462df57451d1b6efaa669238",
        )
        self.assertEqual(profile["id"], source["profile"]["id"])
        self.assertEqual(
            source["services"]["runner"]["executor_contract"],
            {
                "ephemeral_disk_bytes": 0,
                "minimum_cpu_millis": 1000,
                "minimum_memory_bytes": 268435456,
                "minimum_pids": 3,
                "network": "private_egress",
                "privilege": "administrator",
                "root_filesystem": "writable",
                "runner_root": "/__automata",
                "workspace": "/__w",
            },
        )
        self.assertEqual(
            source["services"]["runner"]["maximum_parallel_jobs"], 256
        )

    def test_runtime_literals_track_the_production_contracts(self) -> None:
        source = self.source
        runner = source["services"]["runner"]
        executor = runner["executor_contract"]
        for role, containerfile_path in (
            ("automata", "images/automata.Containerfile"),
            ("runner", "images/automata-runner.Containerfile"),
            ("sandbox-guest", "images/automata-sandbox-guest.Containerfile"),
        ):
            self.assertEqual(
                source["images"][role]["config"]["working_directory"], "/"
            )
            containerfile = (REPOSITORY_ROOT / containerfile_path).read_text(
                encoding="utf-8"
            )
            self.assertRegex(containerfile, r"(?m)^WORKDIR /$")
        self.assertEqual(
            source["images"]["runner"]["runtime"]["product_config_schema"],
            rust_integer_constant(
                "crates/automata-ci-runner/src/product/config.rs",
                "RUNNER_PRODUCT_CONFIG_SCHEMA_VERSION",
            ),
        )
        self.assertEqual(
            source["images"]["sandbox-guest"]["runtime"]["guest_protocol"],
            rust_integer_constant(
                "crates/automata-ci-sandbox-guest/src/lib.rs",
                "GUEST_PROTOCOL_VERSION",
            ),
        )
        self.assertEqual(
            runner["maximum_parallel_jobs"],
            rust_integer_constant(
                "crates/automata-ci-local/src/lib.rs",
                "MAXIMUM_LOCAL_DOCKER_JOB_SLOTS",
            ),
        )
        for field, constant in (
            ("minimum_cpu_millis", "MINIMUM_LOCAL_DOCKER_SANDBOX_CPU_MILLIS"),
            ("minimum_memory_bytes", "MINIMUM_LOCAL_DOCKER_SANDBOX_MEMORY_BYTES"),
            ("minimum_pids", "MINIMUM_LOCAL_DOCKER_SANDBOX_PIDS"),
        ):
            self.assertEqual(
                executor[field],
                rust_integer_constant("crates/automata-ci-local/src/lib.rs", constant),
            )
        self.assertEqual(
            runner["provider_control_directory"],
            rust_string_constant(
                "crates/automata-ci-local/src/lib.rs",
                "LOCAL_DOCKER_CONTROL_DIRECTORY",
            ),
        )
        self.assertEqual(
            runner["provider_control_directory"],
            rust_string_constant(
                "crates/automata-ci-sandbox-guest/src/lib.rs",
                "LOCAL_CONTROL_DIRECTORY",
            ),
        )

        guest_protocol = str(
            source["images"]["sandbox-guest"]["runtime"]["guest_protocol"]
        )
        guest_containerfile = (
            REPOSITORY_ROOT / "images/automata-sandbox-guest.Containerfile"
        ).read_text(encoding="utf-8")
        self.assertIn(
            f'io.automata.sandbox-guest.protocol-version="{guest_protocol}"',
            guest_containerfile,
        )
        self.assertEqual(
            source["images"]["sandbox-guest"]["config"]["required_labels"][
                "io.automata.sandbox-guest.protocol-version"
            ],
            guest_protocol,
        )

        proxy_protocol = str(
            source["images"]["service-proxy"]["runtime"]["protocol"]
        )
        proxy_containerfile = (
            REPOSITORY_ROOT / "images/service-proxy/Containerfile"
        ).read_text(encoding="utf-8")
        self.assertIn(
            f'io.automata.service-proxy.protocol-version="{proxy_protocol}"',
            proxy_containerfile,
        )
        self.assertEqual(
            source["images"]["service-proxy"]["config"]["required_labels"][
                "io.automata.service-proxy.protocol-version"
            ],
            proxy_protocol,
        )
        self.assertEqual(
            proxy_protocol,
            rust_string_constant(
                "crates/automata-ci-local/src/local_docker/mod.rs",
                "RESULTS_PROXY_IMAGE_PROTOCOL_VERSION",
            ),
        )
        self.assertEqual(
            proxy_protocol,
            rust_string_constant(
                "crates/automata-ci-sandbox-podman/src/provider.rs",
                "SERVICE_PROXY_IMAGE_PROTOCOL_VERSION",
            ),
        )

    def test_catalog_round_trips_the_closed_role_and_payload_set(self) -> None:
        document = self.build()
        expected = {
            role: document["images"][role]["source"]["top_level_digest"]
            for role in catalog.RELEASE_REGISTRY_ROLES
        }
        with mock.patch.object(
            catalog,
            "validate_service_proxy_candidate",
            return_value=self.candidate_binding,
        ):
            digests, payloads = catalog.validate_catalog(
                document,
                self.release,
                repository_root=REPOSITORY_ROOT,
                expected_registry_digests=expected,
            )
        self.assertEqual(set(digests), catalog.REGISTRY_ROLES)
        self.assertEqual(payloads, [catalog.SERVICE_PROXY_CANDIDATE_PATH])
        self.assertEqual(
            catalog.canonical_json(document),
            catalog.canonical_json(
                json.loads(catalog.canonical_json(document))
            ),
        )

    def test_handoff_payload_revalidates_the_exact_candidate_bytes(self) -> None:
        document = self.build()
        release_digests = {
            role: document["images"][role]["source"]["top_level_digest"]
            for role in catalog.RELEASE_REGISTRY_ROLES
        }
        candidate_bytes = b"exact service-proxy candidate\n"

        def validate_candidate(
            _repository_root: pathlib.Path,
            candidate_path: pathlib.Path,
            _release: dict,
            _source_image: dict,
        ) -> dict:
            self.assertEqual(candidate_path.read_bytes(), candidate_bytes)
            return self.candidate_binding

        with mock.patch.object(
            catalog,
            "validate_service_proxy_candidate",
            side_effect=validate_candidate,
        ):
            _, payload_paths = catalog.validate_catalog(
                document,
                self.release,
                repository_root=REPOSITORY_ROOT,
                expected_registry_digests=release_digests,
                payloads={catalog.SERVICE_PROXY_CANDIDATE_PATH: candidate_bytes},
            )
        self.assertEqual(payload_paths, [catalog.SERVICE_PROXY_CANDIDATE_PATH])

        with self.assertRaisesRegex(SystemExit, "omits the service-proxy candidate"):
            catalog.validate_catalog(
                document,
                self.release,
                repository_root=REPOSITORY_ROOT,
                expected_registry_digests=release_digests,
                payloads={},
            )

    def test_real_candidate_catalog_and_handoff_survive_relocated_tools(self) -> None:
        publication_test_path = (
            REPOSITORY_ROOT
            / "scripts/ci/tests/service-proxy-publication.test.py"
        )
        publication_spec = importlib.util.spec_from_file_location(
            "catalog_integration_publication_fixture", publication_test_path
        )
        if publication_spec is None or publication_spec.loader is None:
            raise RuntimeError(f"could not load {publication_test_path}")
        publication_test = importlib.util.module_from_spec(publication_spec)
        sys.modules[publication_spec.name] = publication_test
        publication_spec.loader.exec_module(publication_test)
        fixture = publication_test.PublicationContract()
        fixture.setUp()
        try:
            scratch_root = (
                REPOSITORY_ROOT / "target/task-tmp/catalog-integration-tests"
            )
            scratch_root.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(
                prefix="relocated.", dir=scratch_root
            ) as temporary:
                relocated_root = pathlib.Path(temporary)
                copied_paths = (
                    "scripts/ci/release-handoff.py",
                    "scripts/ci/local_installation_catalog.py",
                    "scripts/ci/service-proxy-candidate.py",
                    "scripts/ci/service-proxy-publication.py",
                    "images/local-installation/catalog-v1.json",
                    catalog.PROFILE_MANIFEST_PATH,
                    catalog.PROFILE_LOCK_PATH,
                )
                for relative in copied_paths:
                    destination = relocated_root / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(REPOSITORY_ROOT / relative, destination)
                source_files = {
                    "Cargo.toml": fixture.source_directory / "Cargo.toml",
                    "LICENSE": fixture.context / "LICENSE",
                    "images/service-proxy/Containerfile": (
                        fixture.context / "Containerfile"
                    ),
                }
                for relative, source_path in source_files.items():
                    destination = relocated_root / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source_path, destination)

                handoff_path = relocated_root / "scripts/ci/release-handoff.py"
                handoff_spec = importlib.util.spec_from_file_location(
                    "relocated_catalog_release_handoff", handoff_path
                )
                if handoff_spec is None or handoff_spec.loader is None:
                    raise RuntimeError(f"could not load {handoff_path}")
                handoff = importlib.util.module_from_spec(handoff_spec)
                sys.modules[handoff_spec.name] = handoff
                handoff_spec.loader.exec_module(handoff)

                identity = handoff.ReleaseIdentity(
                    tag="v1.2.3",
                    tag_object="b" * 40,
                    commit=fixture.candidate_commit,
                    version=fixture.release["version"],
                    prerelease=False,
                    source_date_epoch=fixture.release["source_date_epoch"],
                    created=fixture.release["created"],
                )
                self.release = identity.document()
                evidence = self.all_evidence()
                candidate_path = relocated_root / handoff.SERVICE_PROXY_CANDIDATE_PATH
                candidate_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(fixture.candidate, candidate_path)
                document = handoff.local_catalog.build_catalog(
                    relocated_root,
                    identity.document(),
                    evidence,
                    candidate_path,
                )
                catalog_path = relocated_root / handoff.CATALOG_PATH
                catalog_path.parent.mkdir(parents=True, exist_ok=True)
                catalog_path.write_bytes(handoff.local_catalog.canonical_json(document))

                archive = relocated_root / handoff.ARCHIVE_PATH
                archive.parent.mkdir(parents=True, exist_ok=True)
                archive.write_bytes(b"release archive\n")
                archive_digest = handoff.file_digest(archive, "fixture archive")
                (relocated_root / handoff.CHECKSUM_PATH).write_text(
                    f"{archive_digest}  {archive.name}\n", encoding="ascii"
                )
                package = relocated_root / "target/package/fixture-crate-1.2.3.crate"
                package.parent.mkdir(parents=True, exist_ok=True)
                package.write_bytes(b"crate archive\n")
                release_digests = {
                    role: document["images"][role]["source"]["top_level_digest"]
                    for role in handoff.local_catalog.RELEASE_REGISTRY_ROLES
                }
                manifest = handoff.build_manifest(
                    relocated_root,
                    identity,
                    release_digests["automata"],
                    release_digests["runner"],
                    release_digests["sandbox-guest"],
                    ["fixture-crate"],
                )
                manifest_path = relocated_root / handoff.MANIFEST_PATH
                archive_path = relocated_root / "target/release-handoff/handoff.tar"
                _, archive_sha256 = handoff.create_handoff(
                    relocated_root,
                    manifest_path,
                    archive_path,
                    manifest,
                    identity,
                    ["fixture-crate"],
                )
                _, contents = handoff.verify_handoff(
                    archive_path,
                    identity,
                    release_digests["automata"],
                    release_digests["runner"],
                    release_digests["sandbox-guest"],
                    expected_handoff_digest=archive_sha256,
                )
                self.assertEqual(
                    contents[handoff.SERVICE_PROXY_CANDIDATE_PATH],
                    fixture.candidate.read_bytes(),
                )

                changed_payloads = dict(contents)
                changed_payloads[handoff.SERVICE_PROXY_CANDIDATE_PATH] += b"changed"
                with self.assertRaises(SystemExit):
                    handoff.local_catalog.validate_catalog(
                        document,
                        identity.document(),
                        repository_root=relocated_root,
                        expected_registry_digests=release_digests,
                        payloads=changed_payloads,
                    )
        finally:
            fixture.tearDown()

    def test_registry_contract_rejects_user_environment_and_digest_drift(self) -> None:
        for mutation, diagnostic in (
            (lambda evidence: evidence["config"].__setitem__("User", "0:0"), "user differs"),
            (
                lambda evidence: evidence["config"].__setitem__("Env", []),
                "environment differs",
            ),
            (
                lambda evidence: evidence.__setitem__(
                    "config_digest", f"sha256:{'f' * 64}"
                ),
                "config digest differs",
            ),
        ):
            evidence = self.evidence("postgres", "7")
            mutation(evidence)
            with self.assertRaisesRegex(SystemExit, diagnostic):
                catalog.validate_registry_evidence(
                    "postgres",
                    evidence,
                    self.source["images"]["postgres"],
                    self.release,
                )

    def test_release_registry_requires_exact_repository_and_release_labels(self) -> None:
        evidence = self.evidence("automata", "7")
        evidence["reference"] = (
            f"ghcr.io/example/automata@{evidence['top_level_digest']}"
        )
        with self.assertRaisesRegex(SystemExit, "repository differs"):
            catalog.validate_registry_evidence(
                "automata",
                evidence,
                self.source["images"]["automata"],
                self.release,
            )

        evidence = self.evidence("automata", "7")
        evidence["config"]["Labels"]["org.opencontainers.image.revision"] = "c" * 40
        with self.assertRaisesRegex(SystemExit, "release labels differ"):
            catalog.validate_registry_evidence(
                "automata",
                evidence,
                self.source["images"]["automata"],
                self.release,
            )

    def test_capture_resolves_one_linux_amd64_child_and_config_digest(self) -> None:
        child = {
            "config": {
                "digest": f"sha256:{'c' * 64}",
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "size": 1,
            },
            "layers": [],
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "schemaVersion": 2,
        }
        child_bytes = json.dumps(child, separators=(",", ":")).encode()
        child_digest = f"sha256:{catalog.sha256_bytes(child_bytes)}"
        top = {
            "manifests": [
                {
                    "digest": child_digest,
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "platform": {"architecture": "amd64", "os": "linux"},
                }
            ],
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "schemaVersion": 2,
        }
        top_bytes = json.dumps(top, separators=(",", ":")).encode()
        top_digest = f"sha256:{catalog.sha256_bytes(top_bytes)}"
        repository = "registry.example.test/team/image"
        reference = f"{repository}@{top_digest}"
        child_inspection = {
            "image": {
                "architecture": "amd64",
                "config": self.process("automata"),
                "os": "linux",
            },
            "manifest": {
                "digest": child_digest,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
            },
            "name": f"{repository}@{child_digest}",
        }
        with mock.patch.object(
            catalog,
            "run_inspect",
            side_effect=[
                top_bytes,
                child_bytes,
                json.dumps(child_inspection).encode(),
            ],
        ):
            evidence = catalog.capture_registry_evidence(reference)
        self.assertEqual(evidence["platform_manifest_digest"], child_digest)
        self.assertEqual(evidence["config_digest"], f"sha256:{'c' * 64}")

        top["manifests"].append(dict(top["manifests"][0]))
        top_bytes = json.dumps(top, separators=(",", ":")).encode()
        reference = (
            f"{repository}@sha256:{catalog.sha256_bytes(top_bytes)}"
        )
        with (
            mock.patch.object(
                catalog,
                "run_inspect",
                return_value=top_bytes,
            ),
            self.assertRaisesRegex(SystemExit, "exactly one linux/amd64"),
        ):
            catalog.capture_registry_evidence(reference)

        top["manifests"].pop()
        top_bytes = json.dumps(top, separators=(",", ":")).encode()
        reference = (
            f"{repository}@sha256:{catalog.sha256_bytes(top_bytes)}"
        )
        child_inspection["name"] = (
            f"registry.example.test/team/other@{child_digest}"
        )
        with (
            mock.patch.object(
                catalog,
                "run_inspect",
                side_effect=[
                    top_bytes,
                    child_bytes,
                    json.dumps(child_inspection).encode(),
                ],
            ),
            self.assertRaisesRegex(SystemExit, "inspection name differs"),
        ):
            catalog.capture_registry_evidence(reference)

    def test_verify_cli_emits_only_verified_release_bindings(self) -> None:
        document = self.build()
        expected_registry = {
            role: document["images"][role]["source"]["top_level_digest"]
            for role in catalog.REGISTRY_ROLES
        }
        scratch_root = REPOSITORY_ROOT / "target" / "task-tmp" / "catalog-tests"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="outputs.", dir=scratch_root) as temporary:
            directory = pathlib.Path(temporary)
            catalog_path = directory / "catalog.json"
            output_path = directory / "github-output"
            catalog_path.write_bytes(catalog.canonical_json(document))
            output_path.write_bytes(b"")
            arguments = [
                str(SCRIPT),
                "verify",
                "--repository-root",
                str(REPOSITORY_ROOT),
                "--catalog",
                str(catalog_path),
                "--tag",
                self.release["tag"],
                "--tag-object",
                self.release["tag_object"],
                "--commit",
                self.release["commit"],
                "--version",
                self.release["version"],
                "--prerelease",
                "false",
                "--source-date-epoch",
                str(self.release["source_date_epoch"]),
                "--created",
                self.release["created"],
                "--github-output",
                str(output_path),
            ]
            with (
                mock.patch.object(sys, "argv", arguments),
                mock.patch.object(
                    catalog,
                    "validate_catalog",
                    return_value=(expected_registry, [catalog.SERVICE_PROXY_CANDIDATE_PATH]),
                ),
            ):
                catalog.main()
            outputs = dict(
                line.split("=", 1)
                for line in output_path.read_text(encoding="utf-8").splitlines()
            )
        self.assertEqual(outputs["automata_digest"], expected_registry["automata"])
        self.assertEqual(outputs["runner_digest"], expected_registry["runner"])
        self.assertEqual(
            outputs["sandbox_guest_digest"], expected_registry["sandbox-guest"]
        )
        self.assertEqual(outputs["candidate_sha256"], self.candidate_binding["sha256"])
        self.assertEqual(outputs["image_digest"], self.candidate_binding["image_digest"])


if __name__ == "__main__":
    unittest.main()
