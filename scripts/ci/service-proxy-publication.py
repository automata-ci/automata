#!/usr/bin/env python3
"""Validate immutable service-proxy candidate publication and promotion."""

from __future__ import annotations

import argparse
import datetime
import gzip
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import re
import stat
import sys
import tarfile
import tomllib
from typing import NoReturn


SCRIPT_DIRECTORY = pathlib.Path(__file__).resolve().parent
CANDIDATE_SCRIPT = SCRIPT_DIRECTORY / "service-proxy-candidate.py"
CANDIDATE_SPEC = importlib.util.spec_from_file_location(
    "automata_service_proxy_candidate", CANDIDATE_SCRIPT
)
if CANDIDATE_SPEC is None or CANDIDATE_SPEC.loader is None:
    raise RuntimeError(f"could not load {CANDIDATE_SCRIPT}")
candidate = importlib.util.module_from_spec(CANDIDATE_SPEC)
sys.modules[CANDIDATE_SPEC.name] = candidate
CANDIDATE_SPEC.loader.exec_module(candidate)

IMAGE_NAME = "ghcr.io/automata-ci/automata-service-proxy"
SHA256 = re.compile(r"[0-9a-f]{64}")
OCI_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
GIT_COMMIT = re.compile(r"[0-9a-f]{40}")
POSITIVE_INTEGER = re.compile(r"[1-9][0-9]*")
CREATED = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:Z|[+-][0-9]{2}:[0-9]{2})"
)
MAX_CANDIDATE_SIZE = 160 * 1024 * 1024
MAX_EXPANDED_LAYER_SIZE = 64 * 1024 * 1024
LOCK_KEYS = {
    "binary_sha256",
    "candidate_commit",
    "containerfile_sha256",
    "image",
    "publisher_commit",
    "sbom_sha256",
    "schema_version",
    "source_identity_sha256",
    "source_provenance_sha256",
}
CANDIDATE_MEMBERS = {
    candidate.IDENTITY_NAME,
    candidate.IMAGE_ARCHIVE_NAME,
    candidate.SBOM_NAME,
    candidate.SOURCE_NAME,
}


def fail(message: str) -> NoReturn:
    raise SystemExit(f"service-proxy-publication: {message}")


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def sha256(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def read_regular(path: pathlib.Path, maximum: int) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        fail(f"input must be an accessible regular file: {path}")
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            fail(f"input must be a regular file: {path}")
        if before.st_size > maximum:
            fail(f"input exceeds its size limit: {path}")
        contents = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    if len(contents) > maximum:
        fail(f"input exceeds its size limit: {path}")
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if identity_before != identity_after or len(contents) != before.st_size:
        fail(f"input changed while it was read: {path}")
    return contents


def exact_object(value: object, keys: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{label} keys differ")
    return value


def valid_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        fail(f"{label} is not one SHA-256")
    return value


def valid_commit(value: object, label: str) -> str:
    if not isinstance(value, str) or GIT_COMMIT.fullmatch(value) is None:
        fail(f"{label} is not one full lowercase Git commit")
    if value == "0" * 40:
        fail(f"{label} is a placeholder")
    return value


def valid_release(value: object, candidate_commit: str) -> dict:
    release = exact_object(
        value,
        {"created", "revision", "source_date_epoch", "version"},
        "source identity release",
    )
    if release["revision"] != candidate_commit:
        fail("source identity release revision differs from its candidate commit")
    created = release["created"]
    epoch = release["source_date_epoch"]
    version = release["version"]
    if not isinstance(created, str) or CREATED.fullmatch(created) is None:
        fail("source identity created timestamp is not canonical RFC 3339")
    if type(epoch) is not int or epoch < 0 or epoch > 8_589_934_591:
        fail("source identity epoch is invalid")
    if (
        not isinstance(version, str)
        or not version
        or len(version) > 120
        or "\n" in version
        or "\r" in version
    ):
        fail("source identity version is invalid")
    try:
        parsed = datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError:
        fail("source identity created timestamp is invalid")
    if parsed.utcoffset() is None or int(parsed.timestamp()) != epoch:
        fail("source identity release timestamps differ")
    return release


def load_canonical_json(contents: bytes, label: str) -> object:
    try:
        value = json.loads(
            contents,
            object_pairs_hook=unique_object,
            parse_constant=invalid_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        fail(f"{label} is invalid JSON")
    if canonical_json(value) != contents:
        fail(f"{label} is not canonical JSON")
    return value


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    value: dict[str, object] = {}
    for name, entry in pairs:
        if name in value:
            raise ValueError(f"duplicate JSON key: {name}")
        value[name] = entry
    return value


def invalid_json_constant(value: str) -> NoReturn:
    raise ValueError(f"invalid JSON constant: {value}")


def validate_cyclonedx(
    value: object, binary_sha256: str, version: str, label: str
) -> dict:
    if not isinstance(value, dict):
        fail(f"{label} is not a CycloneDX object")
    document_version = value.get("version")
    components = value.get("components")
    dependencies = value.get("dependencies")
    if (
        value.get("bomFormat") != "CycloneDX"
        or value.get("specVersion") != "1.5"
        or type(document_version) is not int
        or document_version < 1
        or not isinstance(components, list)
        or not all(isinstance(component, dict) for component in components)
        or not isinstance(dependencies, list)
        or not all(isinstance(dependency, dict) for dependency in dependencies)
    ):
        fail(f"{label} is not the required CycloneDX 1.5 document")
    metadata = value.get("metadata")
    component = metadata.get("component") if isinstance(metadata, dict) else None
    if not isinstance(component, dict):
        fail(f"{label} primary component is missing")
    hashes = component.get("hashes")
    if not isinstance(hashes, list) or not all(
        isinstance(entry, dict) for entry in hashes
    ):
        fail(f"{label} primary component hashes are malformed")
    sha256_hashes = [
        entry.get("content") for entry in hashes if entry.get("alg") == "SHA-256"
    ]
    if (
        component.get("name") != "automata-ci-service-proxy"
        or component.get("version") != version
        or component.get("type") != "application"
        or sha256_hashes != [binary_sha256]
    ):
        fail(f"{label} primary component identity differs")
    return value


def require_bounded_tar_entries(
    contents: bytes, mode: str, maximum: int, label: str
) -> None:
    try:
        with tarfile.open(fileobj=io.BytesIO(contents), mode=mode) as archive:
            for count, _ in enumerate(archive, start=1):
                if count > maximum:
                    fail(f"{label} contains too many entries")
    except tarfile.TarError:
        fail(f"{label} is invalid")


def load_lock(path: pathlib.Path) -> dict:
    contents = read_regular(path, 64 * 1024)
    lock = exact_object(
        load_canonical_json(contents, "reviewed lock"), LOCK_KEYS, "lock"
    )
    if lock["schema_version"] != 1 or type(lock["schema_version"]) is not int:
        fail("reviewed lock schema is unsupported")
    if any(lock[name] is None for name in LOCK_KEYS - {"schema_version"}):
        fail("reviewed lock is awaiting a candidate")
    valid_commit(lock["candidate_commit"], "lock candidate commit")
    valid_commit(lock["publisher_commit"], "lock publisher commit")
    expected_image = rf"{re.escape(IMAGE_NAME)}@(sha256:[0-9a-f]{{64}})"
    if not isinstance(lock["image"], str) or re.fullmatch(
        expected_image, lock["image"]
    ) is None:
        fail("reviewed lock image is not the exact canonical GHCR digest")
    for name in (
        "binary_sha256",
        "containerfile_sha256",
        "sbom_sha256",
        "source_identity_sha256",
        "source_provenance_sha256",
    ):
        value = valid_sha(lock[name], f"lock {name}")
        if value == "0" * 64:
            fail(f"lock {name} is a placeholder")
    return lock


def write_outputs(path: pathlib.Path | None, values: dict[str, str]) -> None:
    if path is None:
        return
    with path.open("a", encoding="utf-8") as stream:
        for name, value in values.items():
            if "\n" in value or "\r" in value:
                fail(f"output {name} is not one line")
            stream.write(f"{name}={value}\n")


def validate_request(arguments: argparse.Namespace) -> None:
    default_branch = arguments.default_branch
    if (
        not default_branch
        or len(default_branch) > 255
        or "\n" in default_branch
        or "\r" in default_branch
    ):
        fail("default branch is invalid")
    expected_ref = f"refs/heads/{default_branch}"
    if arguments.dispatch_ref != expected_ref:
        fail(f"trusted workflow must be dispatched from {expected_ref}")

    if arguments.operation == "build-candidate":
        candidate_commit = valid_commit(
            arguments.candidate_commit, "candidate_commit"
        )
        if arguments.confirmed_digest:
            fail("locked_digest must be empty for a candidate build")
        write_outputs(arguments.github_output, {"candidate_commit": candidate_commit})
        return

    if arguments.operation != "promote-locked":
        fail(f"unsupported operation: {arguments.operation}")
    if arguments.candidate_commit:
        fail("candidate_commit must be empty for promotion")
    lock = load_lock(arguments.lock)
    locked_digest = lock["image"].removeprefix(f"{IMAGE_NAME}@")
    if arguments.confirmed_digest != locked_digest:
        fail("pasted digest does not exactly match the reviewed lock")
    write_outputs(
        arguments.github_output,
        {
            "locked_digest": locked_digest,
            "locked_image": lock["image"],
            "candidate_commit": lock["candidate_commit"],
            "publisher_commit": lock["publisher_commit"],
        },
    )


def load_candidate_archive(
    path: pathlib.Path,
    source_directory: pathlib.Path,
    expected_commit: str,
) -> tuple[dict[str, bytes], dict, dict, dict[str, bytes], str]:
    archive_bytes = read_regular(path, MAX_CANDIDATE_SIZE)
    try:
        archive = tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:")
    except tarfile.TarError:
        fail("candidate archive is not an uncompressed tar archive")

    members: dict[str, bytes] = {}
    metadata: dict[str, tarfile.TarInfo] = {}
    entry_names: list[str] = []
    try:
        with archive:
            for entry in archive:
                entry_names.append(entry.name)
                if len(entry_names) > len(CANDIDATE_MEMBERS):
                    fail("candidate archive member set or order differs")
                if not entry.isfile() or entry.name in members:
                    fail("candidate archive contains a non-regular or duplicate member")
                if entry.mode != 0o444 or entry.uid != 0 or entry.gid != 0:
                    fail("candidate archive member metadata differs")
                if entry.uname or entry.gname or entry.pax_headers:
                    fail("candidate archive member ownership metadata differs")
                limit = (
                    candidate.MAX_ARCHIVE_SIZE
                    if entry.name == candidate.IMAGE_ARCHIVE_NAME
                    else 16 * 1024 * 1024
                )
                if entry.size > limit:
                    fail("candidate archive member size differs")
                stream = archive.extractfile(entry)
                if stream is None:
                    fail("candidate archive member is unreadable")
                contents = stream.read(limit + 1)
                if len(contents) != entry.size:
                    fail("candidate archive member size differs")
                members[entry.name] = contents
                metadata[entry.name] = entry
    except tarfile.TarError:
        fail("candidate archive is malformed")
    if entry_names != sorted(CANDIDATE_MEMBERS):
        fail("candidate archive member set or order differs")

    source_bytes = members[candidate.SOURCE_NAME]
    source = candidate.load_source(source_bytes)
    release = source["release"]
    if release["revision"] != expected_commit:
        fail("candidate source revision differs from the requested commit")
    for entry in metadata.values():
        if entry.mtime != release["source_date_epoch"]:
            fail("candidate archive member timestamp differs")

    sbom_bytes = members[candidate.SBOM_NAME]
    if sha256(sbom_bytes) != source["artifacts"]["sbom_sha256"]:
        fail("candidate SBOM differs from source provenance")
    validate_cyclonedx(
        load_canonical_json(sbom_bytes, "candidate SBOM"),
        source["artifacts"]["binary_sha256"],
        release["version"],
        "candidate SBOM",
    )

    source_sha256 = sha256(source_bytes)
    require_bounded_tar_entries(
        members[candidate.IMAGE_ARCHIVE_NAME], "r:", 64, "OCI archive"
    )
    manifest_digest, canonical_oci = candidate.load_oci(
        members[candidate.IMAGE_ARCHIVE_NAME], source, source_sha256
    )
    if canonical_oci != members[candidate.IMAGE_ARCHIVE_NAME]:
        fail("candidate OCI archive is not canonical")
    payload = load_image_payload(canonical_oci, source, source_bytes, sbom_bytes)
    verify_candidate_source(source_directory, source, payload)

    identity_bytes = members[candidate.IDENTITY_NAME]
    identity = load_canonical_json(identity_bytes, "candidate provenance")
    expected_identity = {
        "image": {
            "manifest_digest": manifest_digest,
            "name": IMAGE_NAME,
            "oci_archive_sha256": sha256(canonical_oci),
            "sbom_sha256": sha256(sbom_bytes),
            "source_provenance_sha256": source_sha256,
        },
        "release": release,
        "schema_version": 1,
    }
    if identity != expected_identity:
        fail("candidate provenance differs from the validated candidate")

    canonical_archive = io.BytesIO()
    with tarfile.open(
        fileobj=canonical_archive, mode="w", format=tarfile.USTAR_FORMAT
    ) as output:
        for name, contents in sorted(members.items()):
            candidate.add_tar_member(
                output, name, contents, release["source_date_epoch"]
            )
    if canonical_archive.getvalue() != archive_bytes:
        fail("candidate archive bytes are not canonical")
    return members, source, identity, payload, sha256(archive_bytes)


def expanded_layer(contents: bytes, media_type: str) -> bytes:
    if media_type == "application/vnd.oci.image.layer.v1.tar":
        if len(contents) > MAX_EXPANDED_LAYER_SIZE:
            fail("OCI image layer exceeds its expanded size limit")
        return contents
    if media_type != "application/vnd.oci.image.layer.v1.tar+gzip":
        fail("OCI image layer media type differs")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(contents), mode="rb") as stream:
            expanded = stream.read(MAX_EXPANDED_LAYER_SIZE + 1)
    except (OSError, EOFError):
        fail("OCI image layer compression is invalid")
    if len(expanded) > MAX_EXPANDED_LAYER_SIZE:
        fail("OCI image layer exceeds its expanded size limit")
    return expanded


def load_image_payload(
    oci_bytes: bytes, source: dict, source_bytes: bytes, sbom_bytes: bytes
) -> dict[str, bytes]:
    with tarfile.open(fileobj=io.BytesIO(oci_bytes), mode="r:") as archive:
        oci_members = {
            entry.name: archive.extractfile(entry).read()  # type: ignore[union-attr]
            for entry in archive.getmembers()
            if entry.isfile()
        }
    index = load_canonical_or_transport_json(oci_members["index.json"], "OCI index")
    manifest_digest = index["manifests"][0]["digest"].removeprefix("sha256:")
    manifest = load_canonical_or_transport_json(
        oci_members[f"blobs/sha256/{manifest_digest}"], "OCI manifest"
    )
    config_digest = manifest["config"]["digest"].removeprefix("sha256:")
    config = load_canonical_or_transport_json(
        oci_members[f"blobs/sha256/{config_digest}"], "OCI configuration"
    )
    if not isinstance(config, dict):
        fail("OCI image configuration is not an object")
    validate_process_config(config, source)
    rootfs = config.get("rootfs")
    if not isinstance(rootfs, dict) or rootfs.get("type") != "layers":
        fail("OCI image root filesystem metadata differs")
    diff_ids = rootfs.get("diff_ids")
    if not isinstance(diff_ids, list) or len(diff_ids) != len(manifest["layers"]):
        fail("OCI image layer identity set differs")

    files: dict[str, bytes] = {}
    file_modes: dict[str, int] = {}
    directories: set[str] = set()
    expanded_total = 0
    for index, descriptor in enumerate(manifest["layers"]):
        layer_digest = descriptor["digest"].removeprefix("sha256:")
        layer_bytes = expanded_layer(
            oci_members[f"blobs/sha256/{layer_digest}"], descriptor["mediaType"]
        )
        expanded_total += len(layer_bytes)
        if expanded_total > MAX_EXPANDED_LAYER_SIZE:
            fail("OCI image layers exceed their expanded size limit")
        if diff_ids[index] != f"sha256:{sha256(layer_bytes)}":
            fail("OCI image layer differs from its root filesystem identity")
        try:
            layer = tarfile.open(fileobj=io.BytesIO(layer_bytes), mode="r:")
        except tarfile.TarError:
            fail("OCI image layer is not an uncompressed tar payload")
        with layer:
            for entry_count, entry in enumerate(layer, start=1):
                if entry_count > 64:
                    fail("OCI image layer contains too many entries")
                path = pathlib.PurePosixPath(entry.name)
                if (
                    path.is_absolute()
                    or not path.parts
                    or "." in path.parts
                    or ".." in path.parts
                    or str(path) != entry.name
                    or entry.uid != 0
                    or entry.gid != 0
                    or entry.uname
                    or entry.gname
                    or entry.mtime != source["release"]["source_date_epoch"]
                    or entry.pax_headers
                ):
                    fail("OCI image layer contains an unsafe entry")
                normalized = str(path)
                if entry.isdir():
                    if entry.mode != 0o755:
                        fail("OCI image layer directory mode differs")
                    directories.add(normalized)
                    continue
                if not entry.isfile() or normalized in files:
                    fail("OCI image layer contains an unsupported or duplicate entry")
                if entry.size > MAX_EXPANDED_LAYER_SIZE:
                    fail("OCI image layer file exceeds its size limit")
                stream = layer.extractfile(entry)
                if stream is None:
                    fail("OCI image layer file is unreadable")
                contents = stream.read(MAX_EXPANDED_LAYER_SIZE + 1)
                if len(contents) != entry.size:
                    fail("OCI image layer file size differs")
                files[normalized] = contents
                file_modes[normalized] = entry.mode

    expected_directories = {
        "usr",
        "usr/libexec",
        "usr/share",
        "usr/share/doc",
        "usr/share/doc/automata-ci-service-proxy",
        "usr/share/licenses",
        "usr/share/licenses/automata-ci-service-proxy",
        "usr/share/sbom",
    }
    if directories != expected_directories:
        fail("OCI image payload directory set differs")
    expected_paths = {
        "usr/libexec/automata-ci-service-proxy": 0o555,
        "usr/share/doc/automata-ci-service-proxy/VERSION": 0o444,
        "usr/share/doc/automata-ci-service-proxy/source-provenance.json": 0o444,
        "usr/share/licenses/automata-ci-service-proxy/LICENSE": 0o444,
        "usr/share/licenses/automata-ci-service-proxy/THIRD_PARTY_LICENSES.txt": 0o444,
        "usr/share/licenses/automata-ci-service-proxy/THIRD_PARTY_NOTICES.txt": 0o444,
        "usr/share/sbom/automata-ci-service-proxy.cdx.json": 0o444,
    }
    if file_modes != expected_paths:
        fail("OCI image payload path or mode set differs")
    artifacts = source["artifacts"]
    if sha256(files["usr/libexec/automata-ci-service-proxy"]) != artifacts[
        "binary_sha256"
    ]:
        fail("OCI image binary differs from source provenance")
    if files["usr/share/sbom/automata-ci-service-proxy.cdx.json"] != sbom_bytes:
        fail("OCI image SBOM differs from the candidate SBOM")
    if (
        files["usr/share/doc/automata-ci-service-proxy/source-provenance.json"]
        != source_bytes
    ):
        fail("OCI image source provenance payload differs")
    expected_version = f"{source['release']['version']}\n".encode()
    if files["usr/share/doc/automata-ci-service-proxy/VERSION"] != expected_version:
        fail("OCI image version payload differs")
    return files


def expected_labels(source: dict) -> dict[str, str]:
    artifacts = source["artifacts"]
    release = source["release"]
    return {
        "io.automata.service-proxy.binary.sha256": artifacts["binary_sha256"],
        "io.automata.service-proxy.protocol-version": "2",
        "io.automata.service-proxy.sbom.sha256": artifacts["sbom_sha256"],
        "io.automata.service-proxy.source.sha256": sha256(canonical_json(source)),
        "org.opencontainers.image.created": release["created"],
        "org.opencontainers.image.description": (
            "Closed bounded service and Results proxy for Automata job sandboxes"
        ),
        "org.opencontainers.image.licenses": "MIT",
        "org.opencontainers.image.revision": release["revision"],
        "org.opencontainers.image.source": "https://github.com/automata-ci/automata",
        "org.opencontainers.image.title": "Automata CI service proxy",
        "org.opencontainers.image.version": release["version"],
    }


def validate_process_config(config_document: dict, source: dict) -> None:
    if config_document.get("architecture") != "amd64" or config_document.get(
        "os"
    ) != "linux":
        fail("image platform differs")
    process = config_document.get("config")
    if not isinstance(process, dict):
        fail("image process configuration is missing")
    expected_process = {
        "Entrypoint": ["/usr/libexec/automata-ci-service-proxy"],
        "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
        "Labels": expected_labels(source),
        "User": "65532:65532",
        "WorkingDir": "/",
    }
    if process != expected_process:
        fail("image process configuration or labels differ")


def verify_candidate_source(
    directory: pathlib.Path, source: dict, payload: dict[str, bytes]
) -> None:
    directory = directory.resolve()
    containerfile = read_regular(
        directory / "images/service-proxy/Containerfile", 1024 * 1024
    )
    if sha256(containerfile) != source["artifacts"]["containerfile_sha256"]:
        fail("candidate Containerfile differs from exact source checkout")
    license_bytes = read_regular(directory / "LICENSE", 1024 * 1024)
    if license_bytes != payload["usr/share/licenses/automata-ci-service-proxy/LICENSE"]:
        fail("candidate license differs from exact source checkout")
    manifest_bytes = read_regular(directory / "Cargo.toml", 1024 * 1024)
    try:
        manifest = tomllib.loads(manifest_bytes.decode("utf-8"))
        version = manifest["workspace"]["package"]["version"]
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, KeyError, TypeError):
        fail("candidate workspace version is invalid")
    if version != source["release"]["version"]:
        fail("candidate version differs from exact source checkout")


def write_exclusive(path: pathlib.Path, contents: bytes, mode: int = 0o444) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(contents)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
    except FileExistsError:
        fail(f"refusing to overwrite output: {path}")
    except OSError:
        fail(f"unable to create exact output: {path}")


def prepare_candidate(arguments: argparse.Namespace) -> None:
    candidate_commit = valid_commit(arguments.candidate_commit, "candidate commit")
    publisher_commit = valid_commit(arguments.publisher_commit, "publisher commit")
    for value, label in (
        (arguments.run_id, "run ID"),
        (arguments.run_attempt, "run attempt"),
    ):
        if POSITIVE_INTEGER.fullmatch(value) is None:
            fail(f"{label} is invalid")
    members, source, identity, payload, candidate_archive_sha256 = (
        load_candidate_archive(
            arguments.candidate,
            arguments.source_directory,
            candidate_commit,
        )
    )
    artifacts = source["artifacts"]
    source_identity = {
        "artifacts": {
            "binary_sha256": artifacts["binary_sha256"],
            "candidate_archive_sha256": candidate_archive_sha256,
            "candidate_provenance_sha256": sha256(
                members[candidate.IDENTITY_NAME]
            ),
            "containerfile_sha256": artifacts["containerfile_sha256"],
            "license_sha256": sha256(
                payload["usr/share/licenses/automata-ci-service-proxy/LICENSE"]
            ),
            "oci_archive_sha256": identity["image"]["oci_archive_sha256"],
            "sbom_sha256": artifacts["sbom_sha256"],
            "source_provenance_sha256": sha256(
                members[candidate.SOURCE_NAME]
            ),
            "third_party_licenses_sha256": sha256(
                payload[
                    "usr/share/licenses/automata-ci-service-proxy/"
                    "THIRD_PARTY_LICENSES.txt"
                ]
            ),
            "third_party_notices_sha256": sha256(
                payload[
                    "usr/share/licenses/automata-ci-service-proxy/"
                    "THIRD_PARTY_NOTICES.txt"
                ]
            ),
            "version_sha256": sha256(
                payload["usr/share/doc/automata-ci-service-proxy/VERSION"]
            ),
        },
        "build": {
            "candidate_commit": candidate_commit,
            "publisher_commit": publisher_commit,
        },
        "image": {
            "digest": identity["image"]["manifest_digest"],
            "name": IMAGE_NAME,
            "platform": {"architecture": "amd64", "os": "linux"},
        },
        "release": source["release"],
        "runtime": {
            "entrypoint": ["/usr/libexec/automata-ci-service-proxy"],
            "protocol_version": "2",
            "user": "65532:65532",
        },
        "schema_version": 1,
    }
    source_identity_bytes = canonical_json(source_identity)
    lock = {
        "binary_sha256": artifacts["binary_sha256"],
        "candidate_commit": candidate_commit,
        "containerfile_sha256": artifacts["containerfile_sha256"],
        "image": f"{IMAGE_NAME}@{identity['image']['manifest_digest']}",
        "publisher_commit": publisher_commit,
        "sbom_sha256": artifacts["sbom_sha256"],
        "schema_version": 1,
        "source_identity_sha256": sha256(source_identity_bytes),
        "source_provenance_sha256": sha256(members[candidate.SOURCE_NAME]),
    }
    validate_source_identity(source_identity, lock)

    output = arguments.output
    if output.exists() or output.is_symlink():
        fail("candidate review output already exists")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    output.mkdir(mode=0o700)
    output_files = {
        candidate.IMAGE_ARCHIVE_NAME: members[candidate.IMAGE_ARCHIVE_NAME],
        candidate.SBOM_NAME: members[candidate.SBOM_NAME],
        candidate.SOURCE_NAME: members[candidate.SOURCE_NAME],
        "service-proxy-source-identity.json": source_identity_bytes,
        "service-proxy-lock.proposed.json": canonical_json(lock),
    }
    for name, contents in output_files.items():
        write_exclusive(output / name, contents)

    tag = (
        f"{IMAGE_NAME}:candidate-{candidate_commit}-"
        f"run-{arguments.run_id}-attempt-{arguments.run_attempt}"
    )
    outputs = {
        "candidate_tag": tag,
        "exact_image": lock["image"],
        "image_digest": identity["image"]["manifest_digest"],
        "oci_archive": str(output / candidate.IMAGE_ARCHIVE_NAME),
        "proposed_lock": str(output / "service-proxy-lock.proposed.json"),
        "sbom": str(output / candidate.SBOM_NAME),
        "source_identity": str(output / "service-proxy-source-identity.json"),
        "source_identity_sha256": lock["source_identity_sha256"],
    }
    write_outputs(arguments.github_output, outputs)
    for name, value in outputs.items():
        print(f"{name}={value}")


def validate_source_identity(value: object, lock: dict | None = None) -> dict:
    identity = exact_object(
        value,
        {"artifacts", "build", "image", "release", "runtime", "schema_version"},
        "source identity",
    )
    if identity["schema_version"] != 1 or type(identity["schema_version"]) is not int:
        fail("source identity schema is unsupported")
    build = exact_object(
        identity["build"], {"candidate_commit", "publisher_commit"}, "source build"
    )
    candidate_commit = valid_commit(
        build["candidate_commit"], "source candidate commit"
    )
    publisher_commit = valid_commit(
        build["publisher_commit"], "source publisher commit"
    )
    release = valid_release(identity["release"], candidate_commit)
    image = exact_object(
        identity["image"], {"digest", "name", "platform"}, "source image"
    )
    if image["name"] != IMAGE_NAME or not isinstance(image["digest"], str):
        fail("source image name or digest differs")
    if OCI_DIGEST.fullmatch(image["digest"]) is None:
        fail("source image digest is invalid")
    if image["platform"] != {"architecture": "amd64", "os": "linux"}:
        fail("source image platform differs")
    runtime = exact_object(
        identity["runtime"],
        {"entrypoint", "protocol_version", "user"},
        "source runtime",
    )
    if runtime != {
        "entrypoint": ["/usr/libexec/automata-ci-service-proxy"],
        "protocol_version": "2",
        "user": "65532:65532",
    }:
        fail("source runtime contract differs")
    artifacts = exact_object(
        identity["artifacts"],
        {
            "binary_sha256",
            "candidate_archive_sha256",
            "candidate_provenance_sha256",
            "containerfile_sha256",
            "license_sha256",
            "oci_archive_sha256",
            "sbom_sha256",
            "source_provenance_sha256",
            "third_party_licenses_sha256",
            "third_party_notices_sha256",
            "version_sha256",
        },
        "source artifacts",
    )
    for name, value_digest in artifacts.items():
        valid_sha(value_digest, f"source {name}")
    if lock is not None:
        if lock["candidate_commit"] != candidate_commit:
            fail("source candidate commit differs from the reviewed lock")
        if lock["publisher_commit"] != publisher_commit:
            fail("source publisher commit differs from the reviewed lock")
        if lock["image"] != f"{IMAGE_NAME}@{image['digest']}":
            fail("source image differs from the reviewed lock")
        for name in (
            "binary_sha256",
            "containerfile_sha256",
            "sbom_sha256",
            "source_provenance_sha256",
        ):
            if lock[name] != artifacts[name]:
                fail(f"source {name} differs from the reviewed lock")
    identity["release"] = release
    return identity


def load_canonical_or_transport_json(contents: bytes, label: str) -> object:
    try:
        return json.loads(
            contents,
            object_pairs_hook=unique_object,
            parse_constant=invalid_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        fail(f"{label} is invalid JSON")


def verify_attestations(arguments: argparse.Namespace) -> None:
    del arguments
    fail(
        "Automata publication attestations are unsupported: GitHub-hosted "
        "Actions provenance cannot authenticate a self-hosted Automata job"
    )


def verify_image_config(arguments: argparse.Namespace) -> None:
    config_document = load_canonical_or_transport_json(
        read_regular(arguments.config, 16 * 1024 * 1024), "image configuration"
    )
    identity_contents = read_regular(arguments.identity, 1024 * 1024)
    identity = validate_source_identity(
        load_canonical_json(identity_contents, "verified source identity")
    )
    if not isinstance(config_document, dict):
        fail("image configuration is not an object")
    source = {
        "artifacts": {
            "binary_sha256": identity["artifacts"]["binary_sha256"],
            "containerfile_sha256": identity["artifacts"]["containerfile_sha256"],
            "sbom_sha256": identity["artifacts"]["sbom_sha256"],
        },
        "release": identity["release"],
        "schema_version": 1,
    }
    if sha256(canonical_json(source)) != identity["artifacts"][
        "source_provenance_sha256"
    ]:
        fail("verified source provenance identity differs")
    validate_process_config(config_document, source)


def verify_remote_head(arguments: argparse.Namespace) -> None:
    expected_sha = valid_commit(arguments.expected_sha, "expected default-branch head")
    expected_ref = arguments.expected_ref
    if (
        not expected_ref.startswith("refs/heads/")
        or "\n" in expected_ref
        or "\r" in expected_ref
    ):
        fail("expected default-branch ref is invalid")
    remote = read_regular(arguments.remote_output, 64 * 1024)
    match = re.fullmatch(rb"([0-9a-f]{40})\t([^\x00\r\n]+)\n", remote)
    if match is None or match.group(2).decode() != expected_ref:
        fail("direct remote returned a malformed default-branch ref")
    if match.group(1).decode() != expected_sha:
        fail("default branch moved after dispatch; rerun promotion")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)

    request = commands.add_parser("validate-request")
    request.add_argument("--operation", required=True)
    request.add_argument("--default-branch", required=True)
    request.add_argument("--dispatch-ref", required=True)
    request.add_argument("--candidate-commit", default="")
    request.add_argument("--confirmed-digest", default="")
    request.add_argument("--lock", required=True, type=pathlib.Path)
    request.add_argument("--github-output", type=pathlib.Path)
    request.set_defaults(handler=validate_request)

    prepare = commands.add_parser("prepare-candidate")
    prepare.add_argument("--candidate", required=True, type=pathlib.Path)
    prepare.add_argument("--source-directory", required=True, type=pathlib.Path)
    prepare.add_argument("--candidate-commit", required=True)
    prepare.add_argument("--publisher-commit", required=True)
    prepare.add_argument("--run-id", required=True)
    prepare.add_argument("--run-attempt", required=True)
    prepare.add_argument("--output", required=True, type=pathlib.Path)
    prepare.add_argument("--github-output", type=pathlib.Path)
    prepare.set_defaults(handler=prepare_candidate)

    verify = commands.add_parser("verify-attestations")
    verify.add_argument("--lock", required=True, type=pathlib.Path)
    verify.add_argument("--provenance-results", required=True, type=pathlib.Path)
    verify.add_argument("--identity-results", required=True, type=pathlib.Path)
    verify.add_argument("--sbom-results", required=True, type=pathlib.Path)
    verify.add_argument("--identity-output", required=True, type=pathlib.Path)
    verify.add_argument("--github-output", type=pathlib.Path)
    verify.set_defaults(handler=verify_attestations)

    image = commands.add_parser("verify-image-config")
    image.add_argument("--config", required=True, type=pathlib.Path)
    image.add_argument("--identity", required=True, type=pathlib.Path)
    image.set_defaults(handler=verify_image_config)

    remote = commands.add_parser("verify-remote-head")
    remote.add_argument("--remote-output", required=True, type=pathlib.Path)
    remote.add_argument("--expected-ref", required=True)
    remote.add_argument("--expected-sha", required=True)
    remote.set_defaults(handler=verify_remote_head)
    return root


def main() -> None:
    arguments = parser().parse_args()
    arguments.handler(arguments)


if __name__ == "__main__":
    main()
