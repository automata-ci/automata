#!/usr/bin/env python3
"""Create a digest-bound, unpublished service-proxy OCI candidate."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import pathlib
import re
import tarfile
from typing import NoReturn


IMAGE_NAME = "ghcr.io/automata-ci/automata-service-proxy"
IMAGE_ARCHIVE_NAME = "automata-service-proxy.oci.tar"
SBOM_NAME = "automata-ci-service-proxy.cdx.json"
SOURCE_NAME = "source-provenance.json"
IDENTITY_NAME = "candidate-provenance.json"
SHA256 = re.compile(r"[0-9a-f]{64}")
OCI_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
GIT_OBJECT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
MAX_ARCHIVE_SIZE = 128 * 1024 * 1024


def fail(message: str) -> NoReturn:
    raise SystemExit(f"service-proxy-candidate: {message}")


def canonical_json(value: dict) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def digest(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def read_regular(path: pathlib.Path, maximum: int = MAX_ARCHIVE_SIZE) -> bytes:
    if path.is_symlink() or not path.is_file():
        fail(f"input must be a regular file: {path}")
    contents = path.read_bytes()
    if len(contents) > maximum:
        fail(f"input exceeds its size limit: {path}")
    return contents


def exact_object(value: object, keys: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{label} keys differ")
    return value


def valid_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        fail(f"{label} is not one SHA-256")
    return value


def load_source(contents: bytes, context: pathlib.Path | None = None) -> dict:
    try:
        source = json.loads(contents)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("source provenance is invalid JSON")
    if not isinstance(source, dict) or canonical_json(source) != contents:
        fail("source provenance is not canonical JSON")
    source = exact_object(source, {"artifacts", "release", "schema_version"}, "source")
    if source["schema_version"] != 1 or type(source["schema_version"]) is not int:
        fail("source provenance schema is unsupported")
    artifacts = exact_object(
        source["artifacts"],
        {"binary_sha256", "containerfile_sha256", "sbom_sha256"},
        "source artifacts",
    )
    for name, value in artifacts.items():
        valid_sha(value, f"source {name}")
    release = exact_object(
        source["release"],
        {"created", "revision", "source_date_epoch", "version"},
        "source release",
    )
    if not isinstance(release["created"], str) or not release["created"]:
        fail("source created timestamp is invalid")
    if not isinstance(release["version"], str) or not release["version"]:
        fail("source version is invalid")
    if not isinstance(release["revision"], str) or GIT_OBJECT.fullmatch(release["revision"]) is None:
        fail("source revision is invalid")
    if type(release["source_date_epoch"]) is not int or release["source_date_epoch"] < 0:
        fail("source epoch is invalid")
    if context is not None:
        expected = {
            "binary_sha256": "automata-ci-service-proxy",
            "containerfile_sha256": "Containerfile",
            "sbom_sha256": "sbom/automata-ci-service-proxy.cdx.json",
        }
        for key, relative in expected.items():
            if digest(read_regular(context / relative)) != artifacts[key]:
                fail(f"source {key} does not match its context file")
    return source


def load_oci(archive_bytes: bytes, source: dict, source_sha256: str) -> tuple[str, bytes]:
    try:
        archive = tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*")
    except tarfile.TarError:
        fail("OCI archive is invalid")
    members: dict[str, bytes] = {}
    with archive:
        for member in archive.getmembers():
            path = pathlib.PurePosixPath(member.name)
            if member.isdir() and member.name.rstrip("/") in {"blobs", "blobs/sha256"}:
                continue
            if (
                not member.isfile()
                or path.is_absolute()
                or not path.parts
                or "." in path.parts
                or ".." in path.parts
                or member.name in members
            ):
                fail("OCI archive contains an unsafe member")
            stream = archive.extractfile(member)
            if stream is None:
                fail("OCI archive member is unreadable")
            members[member.name] = stream.read()
    try:
        layout = json.loads(members["oci-layout"])
        index = json.loads(members["index.json"])
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError):
        fail("OCI layout metadata is missing or invalid")
    if layout != {"imageLayoutVersion": "1.0.0"}:
        fail("OCI layout version differs")
    if not isinstance(index, dict):
        fail("OCI index is invalid")
    manifests = index.get("manifests")
    if (
        index.get("schemaVersion") != 2
        or index.get("mediaType") != "application/vnd.oci.image.index.v1+json"
        or not isinstance(manifests, list)
        or not manifests
    ):
        fail("OCI index must describe an image manifest")

    referenced_members = {"index.json", "oci-layout"}

    def descriptor_blob(value: object, label: str) -> tuple[dict, bytes]:
        if not isinstance(value, dict):
            fail(f"{label} descriptor is invalid")
        value_digest = value.get("digest")
        size = value.get("size")
        if not isinstance(value_digest, str) or OCI_DIGEST.fullmatch(value_digest) is None:
            fail(f"{label} digest is invalid")
        if type(size) is not int or size < 0:
            fail(f"{label} size is invalid")
        blob_name = f"blobs/sha256/{value_digest.removeprefix('sha256:')}"
        blob = members.get(blob_name)
        if blob is None or len(blob) != size or f"sha256:{digest(blob)}" != value_digest:
            fail(f"{label} blob does not match its descriptor")
        referenced_members.add(blob_name)
        return value, blob

    manifest_descriptor, manifest_bytes = descriptor_blob(manifests[0], "manifest")
    if manifest_descriptor.get("mediaType") != "application/vnd.oci.image.manifest.v1+json":
        fail("OCI manifest media type differs")
    manifest_identity = (
        manifest_descriptor["digest"],
        manifest_descriptor["size"],
        manifest_descriptor["mediaType"],
    )
    for duplicate in manifests[1:]:
        duplicate_descriptor, duplicate_bytes = descriptor_blob(
            duplicate, "manifest"
        )
        duplicate_identity = (
            duplicate_descriptor.get("digest"),
            duplicate_descriptor.get("size"),
            duplicate_descriptor.get("mediaType"),
        )
        if duplicate_identity != manifest_identity or duplicate_bytes != manifest_bytes:
            fail("OCI index must resolve to exactly one unique image manifest")
    try:
        manifest = json.loads(manifest_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("OCI manifest is invalid")
    if (
        not isinstance(manifest, dict)
        or manifest.get("schemaVersion") != 2
        or manifest.get("mediaType") != "application/vnd.oci.image.manifest.v1+json"
    ):
        fail("OCI manifest schema differs")
    config_descriptor, config_bytes = descriptor_blob(manifest.get("config"), "config")
    if config_descriptor.get("mediaType") != "application/vnd.oci.image.config.v1+json":
        fail("OCI config media type differs")
    layers = manifest.get("layers")
    if not isinstance(layers, list) or not layers or len(layers) > 32:
        fail("OCI manifest layer set is invalid")
    for layer in layers:
        layer_descriptor, _ = descriptor_blob(layer, "layer")
        if layer_descriptor.get("mediaType") not in {
            "application/vnd.oci.image.layer.v1.tar",
            "application/vnd.oci.image.layer.v1.tar+gzip",
        }:
            fail("OCI layer media type differs")
    if set(members) != referenced_members:
        fail("OCI archive contains an unreferenced member")
    try:
        config = json.loads(config_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("OCI image configuration is invalid")
    image_config = config.get("config") if isinstance(config, dict) else None
    if not isinstance(image_config, dict):
        fail("OCI image process configuration is missing")
    labels = image_config.get("Labels")
    release = source["release"]
    artifacts = source["artifacts"]
    expected_labels = {
        "org.opencontainers.image.created": release["created"],
        "org.opencontainers.image.revision": release["revision"],
        "org.opencontainers.image.version": release["version"],
        "io.automata.service-proxy.protocol-version": "1",
        "io.automata.service-proxy.binary.sha256": artifacts["binary_sha256"],
        "io.automata.service-proxy.sbom.sha256": artifacts["sbom_sha256"],
        "io.automata.service-proxy.source.sha256": source_sha256,
    }
    if not isinstance(labels, dict) or any(labels.get(k) != v for k, v in expected_labels.items()):
        fail("OCI image labels do not bind the source provenance")
    if image_config.get("User") != "65532:65532":
        fail("OCI image user differs")
    if image_config.get("Entrypoint") != ["/usr/libexec/automata-ci-service-proxy"]:
        fail("OCI image entrypoint differs")
    normalized_index = canonical_json(
        {
            "manifests": [
                {
                    "digest": manifest_descriptor["digest"],
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "size": manifest_descriptor["size"],
                }
            ],
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "schemaVersion": 2,
        }
    )
    members["index.json"] = normalized_index
    canonical_archive = io.BytesIO()
    with tarfile.open(fileobj=canonical_archive, mode="w", format=tarfile.USTAR_FORMAT) as output:
        for name in ("blobs", "blobs/sha256"):
            add_tar_directory(output, name, source["release"]["source_date_epoch"])
        for name, contents in sorted(members.items()):
            add_tar_member(output, name, contents, source["release"]["source_date_epoch"])
    return manifest_descriptor["digest"], canonical_archive.getvalue()


def add_tar_directory(archive: tarfile.TarFile, name: str, mtime: int) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    info.mode = 0o555
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = mtime
    archive.addfile(info)


def add_tar_member(archive: tarfile.TarFile, name: str, contents: bytes, mtime: int) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(contents)
    info.mode = 0o444
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = mtime
    archive.addfile(info, io.BytesIO(contents))


def create(arguments: argparse.Namespace) -> None:
    context = arguments.context.resolve()
    source_bytes = read_regular(context / SOURCE_NAME)
    source = load_source(source_bytes, context)
    sbom_bytes = read_regular(context / "sbom" / SBOM_NAME, 16 * 1024 * 1024)
    if digest(sbom_bytes) != source["artifacts"]["sbom_sha256"]:
        fail("SBOM differs from source provenance")
    source_oci_bytes = read_regular(arguments.oci_archive)
    source_sha256 = digest(source_bytes)
    image_digest, oci_bytes = load_oci(source_oci_bytes, source, source_sha256)
    identity = {
        "image": {
            "manifest_digest": image_digest,
            "name": IMAGE_NAME,
            "oci_archive_sha256": digest(oci_bytes),
            "sbom_sha256": digest(sbom_bytes),
            "source_provenance_sha256": source_sha256,
        },
        "release": source["release"],
        "schema_version": 1,
    }
    identity_bytes = canonical_json(identity)
    output = arguments.output
    if output.exists() or output.is_symlink():
        fail("refusing to overwrite candidate output")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tarfile.open(output, "w", format=tarfile.USTAR_FORMAT) as archive:
        for name, contents in sorted(
            (
                (IDENTITY_NAME, identity_bytes),
                (IMAGE_ARCHIVE_NAME, oci_bytes),
                (SBOM_NAME, sbom_bytes),
                (SOURCE_NAME, source_bytes),
            )
        ):
            add_tar_member(archive, name, contents, source["release"]["source_date_epoch"])
    candidate_sha256 = digest(read_regular(output))
    outputs = {
        "candidate_filename": output.name,
        "candidate_sha256": candidate_sha256,
        "image_digest": image_digest,
        "provenance_sha256": digest(identity_bytes),
    }
    if arguments.github_output is not None:
        with arguments.github_output.open("a", encoding="utf-8") as stream:
            for name, value in outputs.items():
                stream.write(f"{name}={value}\n")
    for name, value in outputs.items():
        print(f"{name}={value}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", required=True, type=pathlib.Path)
    parser.add_argument("--oci-archive", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--github-output", type=pathlib.Path)
    create(parser.parse_args())


if __name__ == "__main__":
    main()
