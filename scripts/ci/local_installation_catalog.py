#!/usr/bin/env python3
"""Build and verify the closed local-installation release catalog."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Mapping
from typing import NoReturn


CATALOG_SCHEMA = "automata.local/release-catalog/v1"
SOURCE_SCHEMA = "automata.local/release-catalog-source/v1"
SOURCE_PATH = "images/local-installation/catalog-v1.json"
PACKAGED_SOURCE_PATH = "crates/automata-ci-local/src/init/catalog-v1.source.json"
SOURCE_SHA256 = "4800b79a3f4e7b39183fcba05f69f1a1310d1d44f6d5ec4ac559d47e715250ca"
RENDERER_CONTRACT_FIXTURE_SCHEMA = "automata.local/renderer-contract-fixture/v1"
RENDERER_CONTRACT_FIXTURE_SHA256 = (
    "c700fdcc5b94f2450be767e2f7b8ca8fad4b724c65b2d5add4cb33058fc6d774"
)
CATALOG_PATH = "target/distribution/automata-local-installation-catalog.json"
PROFILE_MANIFEST_PATH = (
    "images/github-hosted-ubuntu-24.04-x64/profile-manifest.json"
)
PROFILE_LOCK_PATH = "images/github-hosted-ubuntu-24.04-x64/profile-lock.json"
SERVICE_PROXY_CANDIDATE_PATH = (
    "target/service-proxy-publication/"
    "automata-service-proxy-candidate-x86_64-unknown-linux-musl.tar"
)
ROLES = {
    "automata",
    "postgres",
    "profile",
    "runner",
    "rustfs",
    "sandbox-guest",
    "service-proxy",
}
REGISTRY_ROLES = ROLES - {"service-proxy"}
RELEASE_REGISTRY_ROLES = {"automata", "runner", "sandbox-guest"}
OCI_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_OBJECT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
IMAGE_REFERENCE = re.compile(
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?"
    r"@sha256:[0-9a-f]{64}"
)
MAX_JSON_SIZE = 1024 * 1024
MAX_CANDIDATE_SIZE = 160 * 1024 * 1024
MAX_TEXT_SIZE = 512
RELEASE_LABEL_ROLES = {
    "automata": "Automata",
    "runner": "Automata Runner",
    "sandbox-guest": "Automata Sandbox Guest",
}


def fail(message: str) -> NoReturn:
    raise SystemExit(f"local-installation-catalog: {message}")


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def sha256_bytes(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def read_regular(path: pathlib.Path, label: str, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail(f"{label} must be a regular, non-symbolic-link file: {path}: {error}")
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > maximum
        ):
            fail(f"{label} is not one bounded regular file: {path}")
        contents = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    if len(contents) != before.st_size or file_identity(before) != file_identity(after):
        fail(f"{label} changed while it was read: {path}")
    return contents


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    value: dict[str, object] = {}
    for name, entry in pairs:
        if name in value:
            raise ValueError(f"duplicate JSON key: {name}")
        value[name] = entry
    return value


def invalid_constant(value: str) -> NoReturn:
    raise ValueError(f"invalid JSON constant: {value}")


def parse_json(contents: bytes, label: str, *, canonical: bool) -> object:
    try:
        value = json.loads(
            contents,
            object_pairs_hook=unique_object,
            parse_constant=invalid_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        fail(f"{label} is invalid JSON: {error}")
    if canonical and canonical_json(value) != contents:
        fail(f"{label} is not canonical JSON")
    return value


def exact_object(value: object, keys: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        actual = sorted(value) if isinstance(value, dict) else type(value).__name__
        fail(f"{label} keys differ: expected {sorted(keys)!r}, got {actual!r}")
    return value


def exact_list(value: object, label: str, maximum: int = 64) -> list:
    if not isinstance(value, list) or len(value) > maximum:
        fail(f"{label} must be one bounded array")
    return value


def one_line(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_TEXT_SIZE
        or "\n" in value
        or "\r" in value
    ):
        fail(f"{label} must be one bounded non-empty line")
    return value


def digest(value: object, label: str, *, prefix: bool = True) -> str:
    pattern = OCI_DIGEST if prefix else SHA256
    text = one_line(value, label)
    if pattern.fullmatch(text) is None:
        fail(f"{label} is not one SHA-256 digest")
    return text


def load_canonical(path: pathlib.Path, label: str, maximum: int = MAX_JSON_SIZE) -> dict:
    value = parse_json(read_regular(path, label, maximum), label, canonical=True)
    if not isinstance(value, dict):
        fail(f"{label} root must be an object")
    return value


def load_source(repository_root: pathlib.Path) -> dict:
    path = repository_root / SOURCE_PATH
    contents = read_regular(path, "catalog source contract", MAX_JSON_SIZE)
    packaged_contents = read_regular(
        repository_root / PACKAGED_SOURCE_PATH,
        "packaged catalog source contract",
        MAX_JSON_SIZE,
    )
    if packaged_contents != contents:
        fail("packaged catalog source differs from the release source")
    if sha256_bytes(contents) != SOURCE_SHA256:
        fail("catalog source contract differs from the reviewed v1 bytes")
    value = parse_json(contents, "catalog source contract", canonical=True)
    source = exact_object(
        value,
        {
            "images",
            "lifecycle_runtime",
            "platform",
            "profile",
            "schema",
            "scope",
            "services",
        },
        "catalog source contract",
    )
    if source["schema"] != SOURCE_SCHEMA:
        fail("catalog source schema differs")
    if source["platform"] != {"architecture": "amd64", "os": "linux"}:
        fail("catalog source platform differs")
    if source["scope"] != {"engine": "linux/amd64", "host": "unix"}:
        fail("catalog source scope differs")
    require_lifecycle_runtime(source["lifecycle_runtime"])
    images = exact_object(source["images"], ROLES, "catalog source images")
    repositories: set[str] = set()
    for role in sorted(ROLES):
        image = exact_object(
            images[role],
            {"canonical_repository", "config", "runtime", "source"},
            f"catalog source {role}",
        )
        repository = one_line(
            image["canonical_repository"], f"catalog source {role} alias"
        )
        if not repository.startswith("automata.local/") or "@" in repository:
            fail(f"catalog source {role} alias is not canonical")
        if repository in repositories:
            fail("catalog source aliases must be unique")
        exact_object(
            image["config"],
            {
                "command",
                "entrypoint",
                "required_environment",
                "required_labels",
                "user",
                "working_directory",
            },
            f"catalog source {role} config",
        )
        if not isinstance(image["runtime"], dict) or not image["runtime"]:
            fail(f"catalog source {role} runtime contract is missing")
        source_binding = image["source"]
        if role == "service-proxy":
            expected = {"kind", "path"}
            kind = "release-candidate"
        elif role in RELEASE_REGISTRY_ROLES:
            expected = {"kind", "repository"}
            kind = "release-registry"
        else:
            expected = {
                "config_digest",
                "kind",
                "platform_manifest_digest",
                "reference",
            }
            kind = "registry"
        binding = exact_object(source_binding, expected, f"catalog source {role} source")
        if binding["kind"] != kind:
            fail(f"catalog source {role} kind differs")
    return source


def require_lifecycle_runtime(value: object) -> dict:
    runtime = exact_object(
        value,
        {
            "automata_commands",
            "compose",
            "daemon_prerequisites",
            "database_migration_ceiling",
            "engine_relay",
            "renderer_contract",
            "results_transit",
            "runner_commands",
            "runner_config_schema",
            "schema",
        },
        "catalog lifecycle runtime",
    )
    if runtime != {
        "automata_commands": {
            "bootstrap_runner": {
                "argv": ["internal", "local", "bootstrap-runner"],
                "enrollment_token_custody": {
                    "active_file": "/run/automata-bootstrap/active-runner-enrollment-token",
                    "active_file_mode": "0600",
                    "active_staging_file": "/run/automata-bootstrap/.active-runner-enrollment-token.automata-write",
                    "initial_generation": 0,
                    "parent_gid": 65532,
                    "parent_mode": "0700",
                    "parent_uid": 65532,
                    "receipt_file": "/run/automata-bootstrap/receipt.json",
                    "receipt_file_mode": "0600",
                    "receipt_staging_pattern": "/run/automata-bootstrap/.automata-bootstrap-receipt-<enrollment-id>.tmp",
                    "seed_file": "/run/automata-bootstrap/runner-enrollment-token",
                    "seed_file_mode": "0400",
                    "update_policy": "exact-replay-or-one-generation-exact-predecessor-v1",
                },
                "maximum_request_bytes": 4096,
                "receipt_schema": "automata.local/bootstrap-runner-receipt/v1",
                "request_schema": "automata.local/bootstrap-runner-request/v1",
            },
            "check_ready": {
                "argv": ["internal", "local", "check-ready"],
                "listen": "127.0.0.1:8080",
                "maximum_response_bytes": 4096,
                "request": "GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                "response_prefix": "HTTP/1.1 200 ",
                "response_suffix": "\r\n\r\nready\n",
                "timeout_seconds": 3,
            },
            "engine_check": {
                "argv": ["internal", "engine", "check"],
            },
            "engine_relay": {
                "argv": ["internal", "engine", "relay"],
            },
            "hold_lock": {
                "argv": ["internal", "local", "hold-lock"],
                "release": "stdin-fixed-frame-v1",
                "release_frame": "release\n",
            },
            "materialize": {
                "argv": ["internal", "local", "materialize"],
                "maximum_request_bytes": 524288,
                "request_schema": "automata.local/materialize-request/v1",
                "response_schema": "automata.local/materialize-response/v1",
            },
            "object_store_ensure_bucket": {
                "argv": ["internal", "object-store", "ensure-bucket"],
            },
            "read_cas_digest": {
                "argv": ["internal", "local", "read-cas-digest"],
                "purpose": "expected-old-sha256",
            },
            "read_desired": {
                "argv": ["internal", "local", "read-desired"],
                "maximum_bytes": 65536,
                "response_schema": "automata.local/desired-spec/v1",
            },
            "write_cas": {
                "argv": ["internal", "local", "write-cas"],
                "maximum_content_bytes": 262144,
                "maximum_request_bytes": 524288,
                "request_schema": "automata.local/lifecycle-cas/v1",
            },
        },
        "compose": {
            "minimum_version": "2.33.1",
            "named_volume_nocopy": True,
            "project_directory": "/",
            "trusted_lifecycle_services": [
                "automata",
                "bootstrap-runner",
                "engine-relay",
                "object-store-init",
                "postgres",
                "runner",
                "runner-enroll",
                "rustfs",
            ],
            "trusted_user_namespace": "host",
        },
        "daemon_prerequisites": {
            "cgroup_version": "2",
            "default_runtime": "runc",
            "default_user_namespace": "daemon-default-remapped",
            "live_restore": False,
            "post_create_drift": "fail-closed-sticky-lock",
            "required_controllers": {
                "cpu_cfs_period": True,
                "cpu_cfs_quota": True,
                "memory": True,
                "pids": True,
                "swap": True,
            },
            "required_security_options": [
                "name=cgroupns",
                "name=seccomp,profile=builtin",
                "name=userns",
            ],
            "rootful": True,
            "sole_optional_security_option": "name=no-new-privileges",
            "trusted_administrator_defaults": {
                "bridge_default_network_options": {},
                "default_ulimits": {},
                "log_options": {},
            },
        },
        "database_migration_ceiling": 63,
        "engine_relay": {
            "architecture": "amd64",
            "binding_directory": "/run/automata-engine-binding",
            "binding_directory_gid": 0,
            "binding_directory_mode": "0555",
            "binding_directory_uid": 0,
            "binding_file": "/run/automata-engine-binding/binding.json",
            "binding_file_gid": 0,
            "binding_file_maximum_bytes": 4096,
            "binding_file_mode": "0444",
            "binding_file_uid": 0,
            "binding_schema": 1,
            "downstream_directory": "/run/automata-engine",
            "downstream_directory_gid": 65532,
            "downstream_directory_mode": "0700",
            "downstream_directory_uid": 65532,
            "downstream_socket": "/run/automata-engine/docker.sock",
            "downstream_socket_gid": 65532,
            "downstream_socket_mode": "0600",
            "downstream_socket_uid": 65532,
            "engine_api": "1.48",
            "engine_id_maximum_bytes": 256,
            "engine_request_timeout_seconds": 5,
            "gid": 65532,
            "initial_capabilities": ["SETGID", "SETUID", "SETPCAP"],
            "minimum_engine_major": 28,
            "operating_system": "linux",
            "protocol_limits": {
                "connect_timeout_seconds": 5,
                "copy_buffer_bytes": 16384,
                "idle_timeout_seconds": 1800,
                "maximum_connections": 32,
                "shutdown_timeout_seconds": 5,
                "write_timeout_seconds": 30,
            },
            "server_version_maximum_bytes": 128,
            "uid": 65532,
            "upstream_directory": "/run/automata-host-engine",
            "upstream_directory_gid": 0,
            "upstream_directory_mode": "0755",
            "upstream_directory_uid": 0,
            "upstream_socket": "/run/automata-host-engine/docker.sock",
            "upstream_socket_gid": "adopted-host-socket-group",
            "upstream_socket_mode": "0660",
            "upstream_socket_uid": 0,
        },
        "renderer_contract": {
            "fixture_sha256": RENDERER_CONTRACT_FIXTURE_SHA256,
            "schema": RENDERER_CONTRACT_FIXTURE_SCHEMA,
        },
        "results_transit": {
            "ownership": "lifecycle-created-compose-external",
            "schema": 2,
        },
        "runner_commands": {
            "enroll": {
                "argv": ["enroll"],
                "configuration_schema": 8,
                "existing_custody": {
                    "current": "success-before-token-network-or-writer-lock",
                    "invalid": "fail-closed",
                    "recovery_policy": "exact-expired-unrevoked-predecessor-offline-no-live-session-no-live-leaf-linux",
                    "runner_generation": "atomic-increment",
                    "server_clock": "database-post-lock",
                    "token": "one-use-positive-generation",
                },
                "token_source": "file:/run/automata-bootstrap/active-runner-enrollment-token",
            },
            "local_check_ready": {
                "argv": [
                    "__local-check-ready",
                    "--config",
                    "/run/automata-runner-config/runner.json",
                ],
                "healthcheck_argv": [
                    "/usr/local/bin/automata-runner",
                    "__local-check-ready",
                    "--config",
                    "/run/automata-runner-config/runner.json",
                ],
                "listen": "127.0.0.1:9464",
                "maximum_response_bytes": 262144,
                "path": "/metrics",
                "protocol": "http-1.1-openmetrics-text-1.0.0",
                "required_metrics": [
                    "automata_ci_runner_ready 1",
                    "automata_ci_runner_session_connected 1",
                ],
                "tls_custody": {
                    "completion_receipt": "exact",
                    "config_path": "/run/automata-runner-config/runner.json",
                    "mutation": False,
                    "observation": "two-stable-no-follow-snapshots",
                    "order": "custody-before-metrics",
                    "required_state": "current-exact-completed",
                    "writer_lock": "not-acquired",
                },
                "timeout_seconds": 3,
            },
            "run": {
                "argv": ["run"],
                "configuration_schema": 8,
            },
        },
        "runner_config_schema": 8,
        "schema": "automata.local/lifecycle-runtime/v1",
    }:
        fail("catalog lifecycle runtime contract differs")
    return runtime


def load_profile(repository_root: pathlib.Path, source: dict) -> dict:
    profile = exact_object(
        source["profile"],
        {
            "compatibility_label",
            "id",
            "image_role",
            "lock_path",
            "lock_sha256",
            "manifest_path",
            "manifest_sha256",
        },
        "catalog source profile",
    )
    if (
        profile["lock_path"] != PROFILE_LOCK_PATH
        or profile["manifest_path"] != PROFILE_MANIFEST_PATH
        or profile["image_role"] != "profile"
    ):
        fail("catalog source profile paths or role differ")
    manifest_path = repository_root / PROFILE_MANIFEST_PATH
    lock_path = repository_root / PROFILE_LOCK_PATH
    manifest_contents = read_regular(
        manifest_path, "profile manifest", MAX_JSON_SIZE
    )
    manifest = parse_json(manifest_contents, "profile manifest", canonical=False)
    lock_contents = read_regular(lock_path, "profile lock", MAX_JSON_SIZE)
    lock = parse_json(lock_contents, "profile lock", canonical=False)
    if not isinstance(manifest, dict) or not isinstance(lock, dict):
        fail("profile manifest and lock must be objects")
    manifest_sha256 = sha256_bytes(manifest_contents)
    lock_sha256 = sha256_bytes(lock_contents)
    image_source = source["images"]["profile"]["source"]
    if (
        manifest_sha256 != profile["manifest_sha256"]
        or lock_sha256 != profile["lock_sha256"]
        or manifest.get("schema_version") != 2
        or manifest.get("profile_id") != profile["id"]
        or (manifest.get("platform") or {}).get("os") != "linux"
        or (manifest.get("platform") or {}).get("architecture") != "x86_64"
        or (manifest.get("platform") or {}).get("compatibility_label")
        != profile["compatibility_label"]
        or manifest.get("image") != image_source["reference"]
        or lock.get("schema_version") != 2
        or lock.get("profile_id") != profile["id"]
        or lock.get("profile_manifest_sha256") != manifest_sha256
        or lock.get("image") != image_source["reference"]
    ):
        fail("profile manifest, lock, and catalog source differ")
    return {
        "compatibility_label": profile["compatibility_label"],
        "id": profile["id"],
        "image_role": "profile",
        "lock": {
            "path": PROFILE_LOCK_PATH,
            "sha256": lock_sha256,
        },
        "manifest": {
            "path": PROFILE_MANIFEST_PATH,
            "sha256": manifest_sha256,
        },
    }


def repository_from_reference(reference: str) -> str:
    name = reference.rsplit("@", 1)[0]
    last_slash = name.rfind("/")
    tag = name.find(":", last_slash + 1)
    return name if tag == -1 else name[:tag]


def parse_environment(value: object, label: str) -> dict[str, str]:
    entries = exact_list(value if value is not None else [], label, 256)
    environment: dict[str, str] = {}
    for entry in entries:
        text = one_line(entry, f"{label} entry")
        name, separator, configured = text.partition("=")
        if not separator or not name or name in environment:
            fail(f"{label} contains a malformed or duplicate name")
        environment[name] = configured
    return environment


def process_value(process: dict, name: str, default: object) -> object:
    value = process.get(name, default)
    return default if value is None else value


def validate_process(
    role: str,
    process: object,
    expected: dict,
    release: Mapping[str, object],
) -> None:
    if not isinstance(process, dict):
        fail(f"{role} image process configuration is missing")
    actual = {
        "command": process_value(process, "Cmd", []),
        "entrypoint": process_value(process, "Entrypoint", []),
        "user": process_value(process, "User", ""),
        "working_directory": process_value(process, "WorkingDir", ""),
    }
    for name, value in actual.items():
        if value != expected[name]:
            fail(f"{role} image {name} differs from the catalog contract")
    environment = parse_environment(process.get("Env", []), f"{role} image environment")
    required_environment = expected["required_environment"]
    if not isinstance(required_environment, dict) or any(
        environment.get(name) != value
        for name, value in required_environment.items()
    ):
        fail(f"{role} image environment differs from the catalog contract")
    labels = process.get("Labels") or {}
    required_labels = expected["required_labels"]
    if (
        not isinstance(labels, dict)
        or not isinstance(required_labels, dict)
        or any(labels.get(name) != value for name, value in required_labels.items())
    ):
        fail(f"{role} image labels differ from the catalog contract")
    if role in RELEASE_LABEL_ROLES:
        dynamic = {
            "org.opencontainers.image.created": release["created"],
            "org.opencontainers.image.revision": release["commit"],
            "org.opencontainers.image.version": release["version"],
        }
        if any(labels.get(name) != value for name, value in dynamic.items()):
            fail(f"{role} image release labels differ from the gated release")


def require_release(value: object) -> dict:
    release = exact_object(
        value,
        {
            "commit",
            "created",
            "prerelease",
            "source_date_epoch",
            "tag",
            "tag_object",
            "version",
        },
        "catalog release",
    )
    for key in ("commit", "tag_object"):
        if GIT_OBJECT.fullmatch(one_line(release[key], f"catalog release {key}")) is None:
            fail(f"catalog release {key} is invalid")
    for key in ("created", "tag", "version"):
        one_line(release[key], f"catalog release {key}")
    if type(release["prerelease"]) is not bool:
        fail("catalog release prerelease must be a boolean")
    if type(release["source_date_epoch"]) is not int or release["source_date_epoch"] < 0:
        fail("catalog release source date epoch is invalid")
    if release["tag"] != f"v{release['version']}":
        fail("catalog release tag and version differ")
    return release


def run_inspect(arguments: list[str], label: str) -> bytes:
    try:
        result = subprocess.run(
            ["docker", "buildx", "imagetools", "inspect", *arguments],
            check=False,
            capture_output=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        fail(f"could not inspect {label}: {error}")
    if result.returncode != 0 or result.stderr:
        fail(f"could not inspect {label}")
    return result.stdout


def capture_registry_evidence(reference: str) -> dict:
    if IMAGE_REFERENCE.fullmatch(reference) is None:
        fail("registry source must be a canonical digest-qualified reference")
    top_digest = reference.rsplit("@", 1)[1]
    top_bytes = run_inspect([reference, "--raw"], "top-level manifest")
    if f"sha256:{sha256_bytes(top_bytes)}" != top_digest:
        fail("registry top-level manifest bytes differ from their digest")
    manifest = parse_json(top_bytes, "registry top-level manifest", canonical=False)
    if not isinstance(manifest, dict):
        fail("registry top-level manifest is missing")
    media_type = manifest.get("mediaType")
    if media_type == "application/vnd.oci.image.index.v1+json":
        manifests = manifest.get("manifests")
        if not isinstance(manifests, list):
            fail("registry index manifest set is missing")
        candidates = [
            entry
            for entry in manifests
            if isinstance(entry, dict)
            and entry.get("platform") == {"architecture": "amd64", "os": "linux"}
        ]
        if len(candidates) != 1:
            fail("registry index must contain exactly one linux/amd64 image")
        platform_digest = digest(
            candidates[0].get("digest"), "registry platform manifest digest"
        )
    elif media_type == "application/vnd.oci.image.manifest.v1+json":
        platform_digest = top_digest
    else:
        fail("registry image has an unsupported top-level media type")
    repository = repository_from_reference(reference)
    child_reference = f"{repository}@{platform_digest}"
    child_bytes = (
        top_bytes
        if platform_digest == top_digest
        else run_inspect([child_reference, "--raw"], "platform manifest")
    )
    if f"sha256:{sha256_bytes(child_bytes)}" != platform_digest:
        fail("registry platform manifest bytes differ from their digest")
    child = parse_json(child_bytes, "registry platform manifest", canonical=False)
    if not isinstance(child, dict) or child.get("mediaType") not in {
        None,
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
    }:
        fail("registry platform manifest schema differs")
    config = child.get("config")
    if not isinstance(config, dict):
        fail("registry platform manifest config descriptor is missing")
    config_digest = digest(config.get("digest"), "registry config digest")

    # Resolve the process configuration through the exact child descriptor, not
    # through the mutable tag or the index's convenience platform mapping.
    # Buildx verifies the content-addressed manifest and config descriptors while
    # producing this view; checking both the returned name and manifest digest
    # prevents process metadata from an unrelated inspection being accepted.
    formatted = run_inspect(
        [child_reference, "--format", "{{json .}}"], "platform image"
    )
    inspection = parse_json(formatted, "registry inspection", canonical=False)
    inspection = exact_object(
        inspection, {"image", "manifest", "name"}, "registry inspection"
    )
    if inspection["name"] != child_reference:
        fail("registry inspection name differs from the platform reference")
    inspected_manifest = inspection["manifest"]
    if (
        not isinstance(inspected_manifest, dict)
        or inspected_manifest.get("digest") != platform_digest
        or inspected_manifest.get("mediaType")
        not in {
            "application/vnd.docker.distribution.manifest.v2+json",
            "application/vnd.oci.image.manifest.v1+json",
        }
    ):
        fail("registry inspection platform manifest differs")
    image = inspection["image"]
    if not isinstance(image, dict):
        fail("registry image configuration is missing")
    if image.get("architecture") != "amd64" or image.get("os") != "linux":
        fail("registry image platform differs")
    process = image.get("config")
    if not isinstance(process, dict):
        fail("registry image process configuration is missing")
    return {
        "architecture": "amd64",
        "config": process,
        "config_digest": config_digest,
        "os": "linux",
        "platform_manifest_digest": platform_digest,
        "reference": reference,
        "top_level_digest": top_digest,
    }


def load_evidence(path: pathlib.Path, role: str) -> dict:
    evidence = load_canonical(path, f"{role} registry evidence")
    return exact_object(
        evidence,
        {
            "architecture",
            "config",
            "config_digest",
            "os",
            "platform_manifest_digest",
            "reference",
            "top_level_digest",
        },
        f"{role} registry evidence",
    )


def validate_registry_evidence(
    role: str,
    evidence: dict,
    source_image: dict,
    release: dict,
) -> dict:
    if evidence["architecture"] != "amd64" or evidence["os"] != "linux":
        fail(f"{role} registry evidence platform differs")
    reference = one_line(evidence["reference"], f"{role} registry reference")
    if IMAGE_REFERENCE.fullmatch(reference) is None:
        fail(f"{role} registry reference is not canonical and digest-qualified")
    top_digest = digest(evidence["top_level_digest"], f"{role} top-level digest")
    if reference.rsplit("@", 1)[1] != top_digest:
        fail(f"{role} registry reference and top-level digest differ")
    platform_digest = digest(
        evidence["platform_manifest_digest"], f"{role} platform digest"
    )
    config_digest = digest(evidence["config_digest"], f"{role} config digest")
    source_binding = source_image["source"]
    if role in RELEASE_REGISTRY_ROLES:
        expected_repository = source_binding["repository"]
        if repository_from_reference(reference) != expected_repository:
            fail(f"{role} registry repository differs from the release contract")
    else:
        if reference != source_binding["reference"]:
            fail(f"{role} registry reference differs from the fixed contract")
        if platform_digest != source_binding["platform_manifest_digest"]:
            fail(f"{role} platform digest differs from the fixed contract")
        if config_digest != source_binding["config_digest"]:
            fail(f"{role} config digest differs from the fixed contract")
    validate_process(role, evidence["config"], source_image["config"], release)
    return {
        "config_digest": config_digest,
        "kind": "registry",
        "platform_manifest_digest": platform_digest,
        "reference": reference,
        "top_level_digest": top_digest,
    }


def service_proxy_module() -> tuple[object, object]:
    script_directory = pathlib.Path(__file__).resolve().parent
    publication_path = script_directory / "service-proxy-publication.py"
    candidate_path = script_directory / "service-proxy-candidate.py"
    candidate_spec = importlib.util.spec_from_file_location(
        "local_catalog_service_proxy_candidate", candidate_path
    )
    if candidate_spec is None or candidate_spec.loader is None:
        raise RuntimeError(f"could not load {candidate_path}")
    candidate = importlib.util.module_from_spec(candidate_spec)
    sys.modules[candidate_spec.name] = candidate
    candidate_spec.loader.exec_module(candidate)
    publication_spec = importlib.util.spec_from_file_location(
        "local_catalog_service_proxy_publication", publication_path
    )
    if publication_spec is None or publication_spec.loader is None:
        raise RuntimeError(f"could not load {publication_path}")
    publication = importlib.util.module_from_spec(publication_spec)
    sys.modules[publication_spec.name] = publication
    publication_spec.loader.exec_module(publication)
    return publication, candidate


def oci_config_binding(oci_bytes: bytes, manifest_digest: str) -> tuple[str, dict]:
    try:
        with tarfile.open(fileobj=io.BytesIO(oci_bytes), mode="r:") as archive:
            members = {
                entry.name: archive.extractfile(entry).read()  # type: ignore[union-attr]
                for entry in archive.getmembers()
                if entry.isfile()
            }
    except tarfile.TarError:
        fail("service-proxy candidate OCI archive is invalid")
    manifest_name = f"blobs/sha256/{manifest_digest.removeprefix('sha256:')}"
    manifest = parse_json(
        members.get(manifest_name, b""),
        "service-proxy OCI manifest",
        canonical=False,
    )
    if not isinstance(manifest, dict):
        fail("service-proxy OCI manifest is not an object")
    config_descriptor = manifest.get("config")
    if not isinstance(config_descriptor, dict):
        fail("service-proxy OCI config descriptor is missing")
    config_digest = digest(
        config_descriptor.get("digest"), "service-proxy config digest"
    )
    config_name = f"blobs/sha256/{config_digest.removeprefix('sha256:')}"
    config = parse_json(
        members.get(config_name, b""),
        "service-proxy OCI config",
        canonical=False,
    )
    if not isinstance(config, dict):
        fail("service-proxy OCI config is not an object")
    return config_digest, config


def validate_service_proxy_candidate(
    repository_root: pathlib.Path,
    candidate_path: pathlib.Path,
    release: dict,
    source_image: dict,
) -> dict:
    publication, candidate_module = service_proxy_module()
    if candidate_module.LOCAL_IMAGE_NAME != source_image["canonical_repository"]:
        fail("service-proxy candidate local repository differs")
    members, source, identity, _, candidate_sha256 = (
        publication.load_candidate_archive(  # type: ignore[attr-defined]
            candidate_path,
            repository_root,
            release["commit"],
        )
    )
    if source["release"] != {
        "created": release["created"],
        "revision": release["commit"],
        "source_date_epoch": release["source_date_epoch"],
        "version": release["version"],
    }:
        fail("service-proxy candidate release differs from the gated release")
    image = identity["image"]
    manifest_digest = digest(
        image["manifest_digest"], "service-proxy image manifest digest"
    )
    oci_bytes = members[candidate_module.IMAGE_ARCHIVE_NAME]
    config_digest, config = oci_config_binding(oci_bytes, manifest_digest)
    _, load_config_digest = candidate_module.docker_load_archive(
        oci_bytes,
        manifest_digest,
        source["release"]["source_date_epoch"],
    )
    if load_config_digest != config_digest:
        fail("service-proxy Docker load config digest differs")
    if config.get("architecture") != "amd64" or config.get("os") != "linux":
        fail("service-proxy candidate platform differs")
    validate_process(
        "service-proxy", config.get("config"), source_image["config"], release
    )
    return {
        "candidate_provenance_sha256": sha256_bytes(
            members[candidate_module.IDENTITY_NAME]
        ),
        "config_digest": config_digest,
        "image_digest": manifest_digest,
        "image_name": image["name"],
        "kind": "release-candidate",
        "oci_archive_sha256": image["oci_archive_sha256"],
        "path": SERVICE_PROXY_CANDIDATE_PATH,
        "sha256": candidate_sha256,
        "source_provenance_sha256": image["source_provenance_sha256"],
    }


def validate_service_proxy_payload(
    repository_root: pathlib.Path,
    release: dict,
    source_image: dict,
    payloads: Mapping[str, bytes] | None,
) -> dict:
    if payloads is None:
        return validate_service_proxy_candidate(
            repository_root,
            repository_root / SERVICE_PROXY_CANDIDATE_PATH,
            release,
            source_image,
        )
    contents = payloads.get(SERVICE_PROXY_CANDIDATE_PATH)
    if contents is None:
        fail("local-installation payload omits the service-proxy candidate")
    if len(contents) > MAX_CANDIDATE_SIZE:
        fail("local-installation service-proxy candidate exceeds its size limit")
    scratch = repository_root / "target" / "task-tmp" / "catalog-verification"
    scratch.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary_path: pathlib.Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=scratch,
            prefix="service-proxy.",
            suffix=".tar",
            delete=False,
        ) as stream:
            temporary_path = pathlib.Path(stream.name)
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        return validate_service_proxy_candidate(
            repository_root, temporary_path, release, source_image
        )
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def build_catalog(
    repository_root: pathlib.Path,
    release_value: object,
    evidence: Mapping[str, dict],
    candidate_path: pathlib.Path,
) -> dict:
    release = require_release(release_value)
    source = load_source(repository_root)
    if set(evidence) != REGISTRY_ROLES:
        fail("registry evidence role set differs from the closed catalog")
    images: dict[str, dict] = {}
    for role in sorted(REGISTRY_ROLES):
        source_image = source["images"][role]
        images[role] = {
            "canonical_repository": source_image["canonical_repository"],
            "config": source_image["config"],
            "runtime": source_image["runtime"],
            "source": validate_registry_evidence(
                role, evidence[role], source_image, release
            ),
        }
    service_source = source["images"]["service-proxy"]
    images["service-proxy"] = {
        "canonical_repository": service_source["canonical_repository"],
        "config": service_source["config"],
        "runtime": service_source["runtime"],
        "source": validate_service_proxy_candidate(
            repository_root, candidate_path, release, service_source
        ),
    }
    return {
        "images": images,
        "lifecycle_runtime": source["lifecycle_runtime"],
        "platform": source["platform"],
        "profile": load_profile(repository_root, source),
        "release": release,
        "schema": CATALOG_SCHEMA,
        "scope": source["scope"],
        "services": source["services"],
        "source_contract_sha256": SOURCE_SHA256,
    }


def validate_catalog(
    document: object,
    expected_release: object,
    *,
    repository_root: pathlib.Path | None = None,
    expected_registry_digests: Mapping[str, str] | None = None,
    payloads: Mapping[str, bytes] | None = None,
) -> tuple[dict[str, str], list[str]]:
    catalog = exact_object(
        document,
        {
            "images",
            "lifecycle_runtime",
            "platform",
            "profile",
            "release",
            "schema",
            "scope",
            "services",
            "source_contract_sha256",
        },
        "local-installation catalog",
    )
    if catalog["schema"] != CATALOG_SCHEMA:
        fail("local-installation catalog schema differs")
    release = require_release(catalog["release"])
    if release != require_release(expected_release):
        fail("local-installation catalog release differs from the gated release")
    if catalog["source_contract_sha256"] != SOURCE_SHA256:
        fail("local-installation catalog source contract digest differs")
    if repository_root is None:
        repository_root = pathlib.Path(__file__).resolve().parents[2]
    source = load_source(repository_root)
    if (
        catalog["platform"] != source["platform"]
        or catalog["lifecycle_runtime"] != source["lifecycle_runtime"]
        or catalog["scope"] != source["scope"]
        or catalog["services"] != source["services"]
        or catalog["profile"] != load_profile(repository_root, source)
    ):
        fail("local-installation catalog platform/profile/service contract differs")
    images = exact_object(catalog["images"], ROLES, "local-installation images")
    registry_digests: dict[str, str] = {}
    payload_paths: list[str] = []
    for role in sorted(ROLES):
        value = exact_object(
            images[role],
            {"canonical_repository", "config", "runtime", "source"},
            f"local-installation {role}",
        )
        expected = source["images"][role]
        for key in ("canonical_repository", "config", "runtime"):
            if value[key] != expected[key]:
                fail(f"local-installation {role} {key} differs")
        binding = value["source"]
        if role == "service-proxy":
            binding = exact_object(
                binding,
                {
                    "candidate_provenance_sha256",
                    "config_digest",
                    "image_digest",
                    "image_name",
                    "kind",
                    "oci_archive_sha256",
                    "path",
                    "sha256",
                    "source_provenance_sha256",
                },
                "local-installation service-proxy source",
            )
            if (
                binding["kind"] != "release-candidate"
                or binding["path"] != SERVICE_PROXY_CANDIDATE_PATH
            ):
                fail("local-installation service-proxy source differs")
            for name in (
                "candidate_provenance_sha256",
                "oci_archive_sha256",
                "sha256",
                "source_provenance_sha256",
            ):
                digest(binding[name], f"service-proxy {name}", prefix=False)
            digest(binding["config_digest"], "service-proxy config digest")
            digest(binding["image_digest"], "service-proxy image digest")
            one_line(binding["image_name"], "service-proxy image name")
            actual = validate_service_proxy_payload(
                repository_root,
                release,
                expected,
                payloads,
            )
            if binding != actual:
                fail("local-installation service-proxy candidate binding differs")
            payload_paths.append(SERVICE_PROXY_CANDIDATE_PATH)
            continue
        binding = exact_object(
            binding,
            {
                "config_digest",
                "kind",
                "platform_manifest_digest",
                "reference",
                "top_level_digest",
            },
            f"local-installation {role} registry source",
        )
        if binding["kind"] != "registry":
            fail(f"local-installation {role} source kind differs")
        reference = one_line(binding["reference"], f"{role} registry reference")
        top_digest = digest(binding["top_level_digest"], f"{role} top digest")
        if IMAGE_REFERENCE.fullmatch(reference) is None or reference.rsplit("@", 1)[1] != top_digest:
            fail(f"local-installation {role} registry reference differs")
        digest(binding["platform_manifest_digest"], f"{role} platform digest")
        digest(binding["config_digest"], f"{role} config digest")
        if role in RELEASE_REGISTRY_ROLES:
            if repository_from_reference(reference) != expected["source"]["repository"]:
                fail(f"local-installation {role} release repository differs")
        elif (
            reference != expected["source"]["reference"]
            or binding["platform_manifest_digest"]
            != expected["source"]["platform_manifest_digest"]
            or binding["config_digest"] != expected["source"]["config_digest"]
        ):
            fail(f"local-installation {role} fixed registry binding differs")
        registry_digests[role] = top_digest
    if expected_registry_digests is not None:
        if set(expected_registry_digests) != RELEASE_REGISTRY_ROLES:
            fail("expected release registry digest role set differs")
        for role, expected_digest in expected_registry_digests.items():
            if registry_digests[role] != expected_digest:
                fail(f"local-installation {role} digest differs from staging")
    return registry_digests, payload_paths


def write_exclusive(path: pathlib.Path, contents: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o444)
    except OSError as error:
        fail(f"refusing to overwrite output {path}: {error}")
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def write_outputs(path: pathlib.Path | None, values: Mapping[str, str]) -> None:
    if path is None:
        return
    with path.open("a", encoding="utf-8") as stream:
        for name, value in values.items():
            one_line(value, f"output {name}")
            stream.write(f"{name}={value}\n")


def identity_from_arguments(arguments: argparse.Namespace) -> dict:
    return require_release(
        {
            "commit": arguments.commit,
            "created": arguments.created,
            "prerelease": arguments.prerelease == "true",
            "source_date_epoch": arguments.source_date_epoch,
            "tag": arguments.tag,
            "tag_object": arguments.tag_object,
            "version": arguments.version,
        }
    )


def add_identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--tag", required=True)
    parser.add_argument("--tag-object", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--prerelease", required=True, choices=("true", "false"))
    parser.add_argument("--source-date-epoch", required=True, type=int)
    parser.add_argument("--created", required=True)


def parse_evidence(values: list[str]) -> dict[str, pathlib.Path]:
    result: dict[str, pathlib.Path] = {}
    for value in values:
        role, separator, path = value.partition("=")
        if not separator or role not in REGISTRY_ROLES or role in result or not path:
            fail("--evidence must name each exact registry role once as ROLE=PATH")
        result[role] = pathlib.Path(path)
    if set(result) != REGISTRY_ROLES:
        fail("--evidence role set differs from the closed registry role set")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="operation", required=True)
    capture = subparsers.add_parser("capture-registry")
    capture.add_argument("--source", required=True)
    capture.add_argument("--output", required=True, type=pathlib.Path)

    create = subparsers.add_parser("create")
    add_identity_arguments(create)
    create.add_argument("--repository-root", required=True, type=pathlib.Path)
    create.add_argument("--output", required=True, type=pathlib.Path)
    create.add_argument("--evidence", action="append", required=True)
    create.add_argument(
        "--service-proxy-candidate", required=True, type=pathlib.Path
    )

    verify = subparsers.add_parser("verify")
    add_identity_arguments(verify)
    verify.add_argument("--repository-root", required=True, type=pathlib.Path)
    verify.add_argument("--catalog", required=True, type=pathlib.Path)
    verify.add_argument("--github-output", type=pathlib.Path)

    arguments = parser.parse_args()
    if arguments.operation == "capture-registry":
        evidence = capture_registry_evidence(arguments.source)
        write_exclusive(arguments.output, canonical_json(evidence))
        return
    repository_root = arguments.repository_root.resolve(strict=True)
    release = identity_from_arguments(arguments)
    if arguments.operation == "create":
        evidence_paths = parse_evidence(arguments.evidence)
        evidence = {
            role: load_evidence(path, role) for role, path in evidence_paths.items()
        }
        catalog = build_catalog(
            repository_root,
            release,
            evidence,
            arguments.service_proxy_candidate,
        )
        write_exclusive(arguments.output, canonical_json(catalog))
        return
    catalog = load_canonical(arguments.catalog, "local-installation catalog")
    registry_digests, _ = validate_catalog(
        catalog, release, repository_root=repository_root
    )
    service_proxy = catalog["images"]["service-proxy"]["source"]
    write_outputs(
        arguments.github_output,
        {
            "automata_digest": registry_digests["automata"],
            "candidate_filename": pathlib.PurePosixPath(service_proxy["path"]).name,
            "candidate_sha256": service_proxy["sha256"],
            "image_digest": service_proxy["image_digest"],
            "provenance_sha256": service_proxy["candidate_provenance_sha256"],
            "runner_digest": registry_digests["runner"],
            "sandbox_guest_digest": registry_digests["sandbox-guest"],
        },
    )


if __name__ == "__main__":
    main()
