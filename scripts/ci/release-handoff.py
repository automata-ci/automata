#!/usr/bin/env python3
"""Create and verify the immutable artifact passed between release jobs."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import pathlib
import re
import stat
import tarfile
from collections.abc import Collection
from dataclasses import dataclass
from typing import BinaryIO, NoReturn


SCHEMA_VERSION = 1
ARCHIVE_PATH = "target/distribution/automata-x86_64-unknown-linux-musl.tar.gz"
CHECKSUM_PATH = f"{ARCHIVE_PATH}.sha256"
MANIFEST_PATH = "target/distribution/automata-release-manifest.json"
IMAGE_NAMES = {
    "automata": "ghcr.io/automata-ci/automata",
    "automata-runner": "ghcr.io/automata-ci/automata-runner",
}
SHA256 = re.compile(r"[0-9a-f]{64}")
OCI_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
GIT_OBJECT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
CRATE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*")
MAX_HANDOFF_SIZE = 768 * 1024 * 1024
MAX_HANDOFF_CONTENT_SIZE = 700 * 1024 * 1024
MAX_HANDOFF_MEMBER_SIZE = 256 * 1024 * 1024
MAX_HANDOFF_MEMBERS = 128
MAX_MANIFEST_SIZE = 1024 * 1024
MAX_CRATE_SIZE = 10 * 1024 * 1024
MAX_RELEASE_ARCHIVE_SIZE = 256 * 1024 * 1024
MAX_TEXT_SIZE = 512


def fail(message: str) -> NoReturn:
    raise SystemExit(f"release-handoff: {message}")


def canonical_json(document: dict) -> bytes:
    return (
        json.dumps(document, allow_nan=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def sha256_bytes(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def sha256_stream(stream: BinaryIO) -> str:
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def open_regular_file(
    path: pathlib.Path, label: str, maximum_size: int | None = None
) -> BinaryIO:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail(f"{label} must be a regular, non-symbolic-link file: {path}: {error}")
    stream = os.fdopen(descriptor, "rb")
    try:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            fail(f"{label} must be a regular, non-symbolic-link file: {path}")
        if metadata.st_nlink != 1:
            fail(f"{label} must not be hard linked: {path}")
        if maximum_size is not None and metadata.st_size > maximum_size:
            fail(f"{label} exceeds its size limit: {path}")
    except BaseException:
        stream.close()
        raise
    return stream


def file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def regular_file(path: pathlib.Path, label: str, maximum_size: int | None = None) -> None:
    with open_regular_file(path, label, maximum_size):
        pass


def file_digest(
    path: pathlib.Path, label: str, maximum_size: int | None = None
) -> str:
    with open_regular_file(path, label, maximum_size) as stream:
        before = file_identity(os.fstat(stream.fileno()))
        digest = sha256_stream(stream)
        if file_identity(os.fstat(stream.fileno())) != before:
            fail(f"{label} changed while it was read: {path}")
        return digest


def require_exact_keys(value: object, expected: set[str], label: str) -> dict:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        fail(f"{label} keys differ: expected {sorted(expected)!r}, got {sorted(actual)!r}")
    return value


def require_single_line(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_TEXT_SIZE
        or "\n" in value
        or "\r" in value
    ):
        fail(f"{label} must be one non-empty line")
    return value


def require_match(value: object, pattern: re.Pattern[str], label: str) -> str:
    text = require_single_line(value, label)
    if pattern.fullmatch(text) is None:
        fail(f"{label} has an invalid value: {text}")
    return text


@dataclass(frozen=True)
class ReleaseIdentity:
    tag: str
    tag_object: str
    commit: str
    version: str
    prerelease: bool
    source_date_epoch: int
    created: str

    @classmethod
    def from_arguments(cls, arguments: argparse.Namespace) -> "ReleaseIdentity":
        if arguments.prerelease not in ("true", "false"):
            fail("prerelease must be true or false")
        if type(arguments.source_date_epoch) is not int or arguments.source_date_epoch < 0:
            fail("source date epoch must be a non-negative integer")
        identity = cls(
            tag=require_single_line(arguments.tag, "tag"),
            tag_object=require_match(arguments.tag_object, GIT_OBJECT, "tag object"),
            commit=require_match(arguments.commit, GIT_OBJECT, "commit"),
            version=require_single_line(arguments.version, "version"),
            prerelease=arguments.prerelease == "true",
            source_date_epoch=arguments.source_date_epoch,
            created=require_single_line(arguments.created, "created timestamp"),
        )
        if identity.tag != f"v{identity.version}":
            fail("tag does not match v plus version")
        if "+" in identity.version:
            fail("release version must not contain build metadata")
        return identity

    def document(self) -> dict:
        return {
            "commit": self.commit,
            "created": self.created,
            "prerelease": self.prerelease,
            "source_date_epoch": self.source_date_epoch,
            "tag": self.tag,
            "tag_object": self.tag_object,
            "version": self.version,
        }


def file_entry(
    path: str,
    repository_root: pathlib.Path,
    label: str,
    maximum_size: int,
) -> dict:
    digest = file_digest(repository_root / path, label, maximum_size)
    return {"path": path, "sha256": digest}


def normalize_expected_crates(values: Collection[str]) -> set[str]:
    if not values:
        fail("at least one publishable crate must be expected")
    names: set[str] = set()
    for value in values:
        if not isinstance(value, str) or CRATE_NAME.fullmatch(value) is None:
            fail("expected crate list contains an invalid package name")
        if value in names:
            fail(f"expected crate list contains duplicate package {value}")
        names.add(value)
    return names


def package_entries(
    repository_root: pathlib.Path,
    version: str,
    expected_crates: Collection[str],
) -> list[dict]:
    package_directory = repository_root / "target" / "package"
    if package_directory.is_symlink() or not package_directory.is_dir():
        fail(f"package directory is missing or symbolic: {package_directory}")
    expected_names = normalize_expected_crates(expected_crates)
    suffix = f"-{version}.crate"
    entries: list[dict] = []
    names: set[str] = set()
    for archive in sorted(package_directory.glob("*.crate"), key=lambda item: item.name):
        regular_file(archive, "crate archive", MAX_CRATE_SIZE)
        if not archive.name.endswith(suffix):
            fail(f"crate archive does not use release version {version}: {archive.name}")
        name = archive.name[: -len(suffix)]
        if CRATE_NAME.fullmatch(name) is None:
            fail(f"crate archive has an invalid package name: {archive.name}")
        if name not in expected_names:
            fail(f"unexpected crate archive for non-publishable package: {name}")
        if name in names:
            fail(f"duplicate crate package name: {name}")
        names.add(name)
        relative_path = archive.relative_to(repository_root).as_posix()
        entries.append(
            {
                "name": name,
                "path": relative_path,
                "sha256": file_digest(
                    archive, f"{name} crate archive", MAX_CRATE_SIZE
                ),
                "version": version,
            }
        )
        if len(entries) > MAX_HANDOFF_MEMBERS - 3:
            fail("too many crate archives for one release handoff")
    if not entries:
        fail("no crate archives were found")
    missing = sorted(expected_names - names)
    if missing:
        fail(f"expected publishable crate archives are missing: {missing!r}")
    return sorted(entries, key=lambda entry: entry["name"])


def build_manifest(
    repository_root: pathlib.Path,
    identity: ReleaseIdentity,
    automata_digest: str,
    runner_digest: str,
    expected_crates: Collection[str],
) -> dict:
    automata_digest = require_match(automata_digest, OCI_DIGEST, "Automata image digest")
    runner_digest = require_match(runner_digest, OCI_DIGEST, "runner image digest")
    archive = file_entry(
        ARCHIVE_PATH,
        repository_root,
        "release archive",
        MAX_RELEASE_ARCHIVE_SIZE,
    )
    checksum = file_entry(
        CHECKSUM_PATH,
        repository_root,
        "release checksum",
        MAX_TEXT_SIZE,
    )
    validate_checksum(repository_root / CHECKSUM_PATH, archive["sha256"])
    return {
        "crates": package_entries(
            repository_root, identity.version, expected_crates
        ),
        "images": {
            "automata": {
                "digest": automata_digest,
                "name": IMAGE_NAMES["automata"],
            },
            "automata-runner": {
                "digest": runner_digest,
                "name": IMAGE_NAMES["automata-runner"],
            },
        },
        "release": identity.document(),
        "release_assets": [archive, checksum],
        "schema_version": SCHEMA_VERSION,
    }


def validate_checksum(path: pathlib.Path, expected_archive_digest: str) -> None:
    regular_file(path, "release checksum", MAX_TEXT_SIZE)
    expected = f"{expected_archive_digest}  {path.name.removesuffix('.sha256')}\n".encode()
    if path.read_bytes() != expected:
        fail("release checksum file does not exactly describe the release archive")


def load_manifest(path: pathlib.Path) -> tuple[dict, bytes]:
    regular_file(path, "release manifest", MAX_MANIFEST_SIZE)
    contents = path.read_bytes()
    try:
        document = json.loads(
            contents,
            parse_constant=lambda value: fail(
                f"release manifest contains invalid numeric constant {value}"
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"release manifest is invalid JSON: {error}")
    if not isinstance(document, dict):
        fail("release manifest root must be an object")
    if canonical_json(document) != contents:
        fail("release manifest is not in canonical JSON form")
    return document, contents


def validate_manifest(
    document: dict,
    identity: ReleaseIdentity,
    repository_root: pathlib.Path | None = None,
    expected_automata_digest: str | None = None,
    expected_runner_digest: str | None = None,
    expected_crates: Collection[str] | None = None,
) -> tuple[str, str, list[str]]:
    require_exact_keys(
        document,
        {"crates", "images", "release", "release_assets", "schema_version"},
        "manifest",
    )
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != SCHEMA_VERSION
    ):
        fail(f"unsupported manifest schema version: {document['schema_version']!r}")

    release = require_exact_keys(
        document["release"],
        {
            "commit",
            "created",
            "prerelease",
            "source_date_epoch",
            "tag",
            "tag_object",
            "version",
        },
        "manifest release identity",
    )
    require_match(release["tag_object"], GIT_OBJECT, "manifest tag object")
    require_match(release["commit"], GIT_OBJECT, "manifest commit")
    for key in ("created", "tag", "version"):
        require_single_line(release[key], f"manifest release {key}")
    if type(release["prerelease"]) is not bool:
        fail("manifest release prerelease must be a boolean")
    if (
        type(release["source_date_epoch"]) is not int
        or release["source_date_epoch"] < 0
    ):
        fail("manifest release source date epoch must be a non-negative integer")
    if release != identity.document():
        fail("manifest release identity differs from the gated release")

    assets = document["release_assets"]
    if not isinstance(assets, list) or len(assets) != 2:
        fail("manifest must contain exactly two release asset records")
    expected_asset_paths = [ARCHIVE_PATH, CHECKSUM_PATH]
    asset_paths: list[str] = []
    asset_digests: dict[str, str] = {}
    for index, value in enumerate(assets):
        entry = require_exact_keys(value, {"path", "sha256"}, "release asset record")
        path = require_single_line(entry["path"], "release asset path")
        digest = require_match(entry["sha256"], SHA256, "release asset digest")
        asset_paths.append(path)
        asset_digests[path] = digest
        if path != expected_asset_paths[index]:
            fail("manifest release assets are not in the canonical order")

    crates = document["crates"]
    if (
        not isinstance(crates, list)
        or not crates
        or len(crates) > MAX_HANDOFF_MEMBERS - 3
    ):
        fail("manifest must contain a bounded, non-empty crate archive list")
    crate_paths: list[str] = []
    crate_names: list[str] = []
    for value in crates:
        entry = require_exact_keys(
            value, {"name", "path", "sha256", "version"}, "crate record"
        )
        name = require_match(entry["name"], CRATE_NAME, "crate name")
        version = require_single_line(entry["version"], "crate version")
        if version != identity.version:
            fail(f"crate {name} does not use release version {identity.version}")
        expected_path = f"target/package/{name}-{version}.crate"
        path = require_single_line(entry["path"], "crate archive path")
        if path != expected_path:
            fail(f"crate {name} has non-canonical archive path: {path}")
        require_match(entry["sha256"], SHA256, f"{name} crate digest")
        crate_names.append(name)
        crate_paths.append(path)
    if crate_names != sorted(crate_names) or len(crate_names) != len(set(crate_names)):
        fail("crate records must have unique names in sorted order")
    if expected_crates is not None and set(crate_names) != normalize_expected_crates(
        expected_crates
    ):
        fail("manifest crate set differs from the publishable workspace set")

    images = require_exact_keys(
        document["images"], set(IMAGE_NAMES), "manifest images"
    )
    image_digests: dict[str, str] = {}
    for key, expected_name in IMAGE_NAMES.items():
        entry = require_exact_keys(images[key], {"digest", "name"}, f"{key} image")
        if entry["name"] != expected_name:
            fail(f"{key} image name differs from {expected_name}")
        image_digests[key] = require_match(
            entry["digest"], OCI_DIGEST, f"{key} image digest"
        )
    if expected_automata_digest is not None and (
        image_digests["automata"] != expected_automata_digest
    ):
        fail("manifest Automata image digest differs from the staged digest")
    if expected_runner_digest is not None and (
        image_digests["automata-runner"] != expected_runner_digest
    ):
        fail("manifest runner image digest differs from the staged digest")

    file_paths = asset_paths + crate_paths
    if len(file_paths) != len(set(file_paths)):
        fail("manifest contains duplicate file paths")
    if repository_root is not None:
        for entry in assets + crates:
            maximum_size = (
                MAX_RELEASE_ARCHIVE_SIZE
                if entry["path"] == ARCHIVE_PATH
                else MAX_TEXT_SIZE
                if entry["path"] == CHECKSUM_PATH
                else MAX_CRATE_SIZE
            )
            actual = file_digest(
                repository_root / entry["path"],
                f"manifest file {entry['path']}",
                maximum_size,
            )
            if actual != entry["sha256"]:
                fail(f"manifest digest mismatch for {entry['path']}")
        validate_checksum(
            repository_root / CHECKSUM_PATH, asset_digests[ARCHIVE_PATH]
        )
    return image_digests["automata"], image_digests["automata-runner"], file_paths


def write_file_exclusive(path: pathlib.Path, contents: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as error:
        fail(f"refusing to overwrite output {path}: {error}")
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def add_tar_file(
    archive: tarfile.TarFile,
    repository_root: pathlib.Path,
    relative_path: str,
    mtime: int,
) -> None:
    path = repository_root / relative_path
    maximum_size = (
        MAX_MANIFEST_SIZE
        if relative_path == MANIFEST_PATH
        else MAX_RELEASE_ARCHIVE_SIZE
        if relative_path == ARCHIVE_PATH
        else MAX_TEXT_SIZE
        if relative_path == CHECKSUM_PATH
        else MAX_CRATE_SIZE
    )
    regular_file(path, f"handoff member {relative_path}", maximum_size)
    info = tarfile.TarInfo(relative_path)
    info.size = path.stat().st_size
    info.mode = 0o444
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = mtime
    with path.open("rb") as stream:
        archive.addfile(info, stream)


def create_handoff(
    repository_root: pathlib.Path,
    manifest_path: pathlib.Path,
    handoff_path: pathlib.Path,
    manifest: dict,
    identity: ReleaseIdentity,
    expected_crates: Collection[str],
) -> tuple[str, str]:
    manifest_bytes = canonical_json(manifest)
    expected_manifest_path = repository_root / MANIFEST_PATH
    if manifest_path.resolve(strict=False) != expected_manifest_path.resolve(strict=False):
        fail(f"manifest output must be {expected_manifest_path}")
    write_file_exclusive(manifest_path, manifest_bytes)
    _, loaded_bytes = load_manifest(manifest_path)
    if loaded_bytes != manifest_bytes:
        fail("written manifest bytes changed unexpectedly")

    return pack_handoff(
        repository_root,
        manifest_path,
        handoff_path,
        identity,
        expected_crates,
    )


def pack_handoff(
    repository_root: pathlib.Path,
    manifest_path: pathlib.Path,
    handoff_path: pathlib.Path,
    identity: ReleaseIdentity,
    expected_crates: Collection[str],
) -> tuple[str, str]:
    expected_manifest_path = repository_root / MANIFEST_PATH
    if manifest_path.resolve(strict=False) != expected_manifest_path.resolve(strict=False):
        fail(f"manifest input must be {expected_manifest_path}")
    manifest, manifest_bytes = load_manifest(manifest_path)
    _, _, payload_paths = validate_manifest(
        manifest,
        identity,
        repository_root,
        expected_crates=expected_crates,
    )
    member_paths = sorted([MANIFEST_PATH, *payload_paths])
    handoff_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if handoff_path.exists() or handoff_path.is_symlink():
        fail(f"refusing to overwrite handoff archive: {handoff_path}")
    temporary_path = handoff_path.with_name(f".{handoff_path.name}.tmp")
    if temporary_path.exists() or temporary_path.is_symlink():
        fail(f"temporary handoff path already exists: {temporary_path}")
    try:
        with tarfile.open(temporary_path, "x", format=tarfile.USTAR_FORMAT) as archive:
            for relative_path in member_paths:
                add_tar_file(
                    archive,
                    repository_root,
                    relative_path,
                    identity.source_date_epoch,
                )
        if temporary_path.stat().st_size > MAX_HANDOFF_SIZE:
            fail("created handoff archive exceeds its size limit")
        os.replace(temporary_path, handoff_path)
    finally:
        temporary_path.unlink(missing_ok=True)
    return sha256_bytes(manifest_bytes), file_digest(
        handoff_path, "handoff archive", MAX_HANDOFF_SIZE
    )


def load_handoff_stream(
    stream: BinaryIO, handoff_size: int, identity: ReleaseIdentity
) -> tuple[dict, bytes, dict[str, bytes]]:
    try:
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode="r:") as archive:
            contents: dict[str, bytes] = {}
            previous_name: str | None = None
            total_size = 0
            for member in archive:
                if len(contents) >= MAX_HANDOFF_MEMBERS:
                    fail("handoff archive contains too many members")
                pure_path = pathlib.PurePosixPath(member.name)
                if (
                    pure_path.is_absolute()
                    or not pure_path.parts
                    or "." in pure_path.parts
                    or ".." in pure_path.parts
                    or member.type != tarfile.REGTYPE
                ):
                    fail(f"handoff archive contains an unsafe member: {member.name}")
                if member.name in contents:
                    fail("handoff archive contains duplicate paths")
                if previous_name is not None and member.name <= previous_name:
                    fail("handoff archive members are not in canonical order")
                previous_name = member.name
                if (
                    member.size < 0
                    or member.size > MAX_HANDOFF_MEMBER_SIZE
                    or member.pax_headers
                    or member.sparse is not None
                    or member.linkname
                    or member.mode != 0o444
                    or member.devmajor != 0
                    or member.devminor != 0
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname
                    or member.gname
                    or member.mtime != identity.source_date_epoch
                ):
                    fail(f"handoff member metadata is not canonical: {member.name}")
                total_size += member.size
                if total_size > MAX_HANDOFF_CONTENT_SIZE:
                    fail("handoff archive expands beyond its cumulative size limit")
                stream = archive.extractfile(member)
                if stream is None:
                    fail(f"could not read handoff member: {member.name}")
                member_contents = stream.read(member.size + 1)
                if len(member_contents) != member.size:
                    fail(f"handoff member has inconsistent size: {member.name}")
                contents[member.name] = member_contents
            canonical_size = (
                (archive.offset + 1024 + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE
            ) * tarfile.RECORDSIZE
            if handoff_size != canonical_size:
                fail("handoff archive has noncanonical padding or trailing data")
    except (OSError, tarfile.TarError) as error:
        fail(f"could not read handoff archive: {error}")
    manifest_bytes = contents.get(MANIFEST_PATH)
    if manifest_bytes is None:
        fail("handoff archive does not contain the release manifest")
    if len(manifest_bytes) > MAX_MANIFEST_SIZE:
        fail("release manifest is too large")
    try:
        manifest = json.loads(
            manifest_bytes,
            parse_constant=lambda value: fail(
                f"handoff manifest contains invalid numeric constant {value}"
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"handoff manifest is invalid JSON: {error}")
    if not isinstance(manifest, dict) or canonical_json(manifest) != manifest_bytes:
        fail("handoff manifest is not a canonical JSON object")
    return manifest, manifest_bytes, contents


def load_handoff(
    handoff_path: pathlib.Path, identity: ReleaseIdentity
) -> tuple[dict, bytes, dict[str, bytes]]:
    with open_regular_file(
        handoff_path, "handoff archive", MAX_HANDOFF_SIZE
    ) as stream:
        before = os.fstat(stream.fileno())
        result = load_handoff_stream(stream, before.st_size, identity)
        if file_identity(os.fstat(stream.fileno())) != file_identity(before):
            fail("handoff archive changed while it was read")
        return result


def verify_handoff(
    handoff_path: pathlib.Path,
    identity: ReleaseIdentity,
    expected_automata_digest: str,
    expected_runner_digest: str,
    *,
    expected_handoff_digest: str | None = None,
) -> tuple[dict, dict[str, bytes]]:
    with open_regular_file(
        handoff_path, "handoff archive", MAX_HANDOFF_SIZE
    ) as stream:
        before = os.fstat(stream.fileno())
        if expected_handoff_digest is not None:
            expected_handoff_digest = require_match(
                expected_handoff_digest, SHA256, "handoff digest"
            )
            if sha256_stream(stream) != expected_handoff_digest:
                fail("downloaded handoff digest differs from the staging job")
        manifest, _, contents = load_handoff_stream(stream, before.st_size, identity)
        if file_identity(os.fstat(stream.fileno())) != file_identity(before):
            fail("handoff archive changed while it was verified")
    _, _, payload_paths = validate_manifest(
        manifest,
        identity,
        expected_automata_digest=expected_automata_digest,
        expected_runner_digest=expected_runner_digest,
    )
    expected_members = sorted([MANIFEST_PATH, *payload_paths])
    if sorted(contents) != expected_members:
        fail(
            "handoff members differ from the exact manifest set: "
            f"{sorted(contents)!r}"
        )
    entries = [*manifest["release_assets"], *manifest["crates"]]
    for entry in entries:
        actual = sha256_bytes(contents[entry["path"]])
        if actual != entry["sha256"]:
            fail(f"handoff digest mismatch for {entry['path']}")
    checksum = contents[CHECKSUM_PATH]
    archive_digest = next(
        entry["sha256"]
        for entry in manifest["release_assets"]
        if entry["path"] == ARCHIVE_PATH
    )
    expected_checksum = (
        f"{archive_digest}  {pathlib.PurePosixPath(ARCHIVE_PATH).name}\n".encode()
    )
    if checksum != expected_checksum:
        fail("handoff checksum does not exactly describe the release archive")
    return manifest, contents


def extract_handoff(contents: dict[str, bytes], extraction_root: pathlib.Path) -> None:
    if extraction_root.is_symlink() or not extraction_root.is_dir():
        fail("handoff extraction root must be a real directory")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    try:
        root_descriptor = os.open(extraction_root, directory_flags)
    except OSError as error:
        fail(f"could not open handoff extraction root: {error}")
    try:
        for relative_path in sorted(contents):
            pure_path = pathlib.PurePosixPath(relative_path)
            if (
                pure_path.is_absolute()
                or not pure_path.parts
                or "." in pure_path.parts
                or ".." in pure_path.parts
            ):
                fail(f"handoff extraction path is unsafe: {relative_path}")
            parent_descriptor = os.dup(root_descriptor)
            try:
                for part in pure_path.parts[:-1]:
                    try:
                        os.mkdir(part, 0o700, dir_fd=parent_descriptor)
                    except FileExistsError:
                        pass
                    try:
                        child_descriptor = os.open(
                            part, directory_flags, dir_fd=parent_descriptor
                        )
                    except OSError as error:
                        fail(
                            f"handoff extraction parent is unsafe for "
                            f"{relative_path}: {error}"
                        )
                    os.close(parent_descriptor)
                    parent_descriptor = child_descriptor

                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                try:
                    descriptor = os.open(
                        pure_path.name,
                        flags,
                        0o644,
                        dir_fd=parent_descriptor,
                    )
                except OSError as error:
                    fail(f"refusing to overwrite output {relative_path}: {error}")
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(contents[relative_path])
                    stream.flush()
                    os.fsync(stream.fileno())
            finally:
                os.close(parent_descriptor)
    finally:
        os.close(root_descriptor)


def write_outputs(path: pathlib.Path | None, values: dict[str, str]) -> None:
    if path is None:
        return
    with path.open("a", encoding="utf-8") as stream:
        for name, value in values.items():
            require_single_line(value, f"output {name}")
            stream.write(f"{name}={value}\n")


def add_identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--tag", required=True)
    parser.add_argument("--tag-object", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--prerelease", required=True, choices=("true", "false"))
    parser.add_argument("--source-date-epoch", required=True, type=int)
    parser.add_argument("--created", required=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="operation", required=True)

    create = subparsers.add_parser("create")
    add_identity_arguments(create)
    create.add_argument("--repository-root", required=True, type=pathlib.Path)
    create.add_argument("--manifest", required=True, type=pathlib.Path)
    create.add_argument("--handoff", required=True, type=pathlib.Path)
    create.add_argument("--automata-digest", required=True)
    create.add_argument("--runner-digest", required=True)
    create.add_argument("--expected-crate", action="append", required=True)
    create.add_argument("--github-output", type=pathlib.Path)

    pack = subparsers.add_parser("pack")
    add_identity_arguments(pack)
    pack.add_argument("--repository-root", required=True, type=pathlib.Path)
    pack.add_argument("--manifest", required=True, type=pathlib.Path)
    pack.add_argument("--handoff", required=True, type=pathlib.Path)
    pack.add_argument("--expected-crate", action="append", required=True)
    pack.add_argument("--github-output", type=pathlib.Path)

    verify_manifest_parser = subparsers.add_parser("verify-manifest")
    add_identity_arguments(verify_manifest_parser)
    verify_manifest_parser.add_argument("--repository-root", required=True, type=pathlib.Path)
    verify_manifest_parser.add_argument("--manifest", required=True, type=pathlib.Path)
    verify_manifest_parser.add_argument("--github-output", type=pathlib.Path)

    verify = subparsers.add_parser("verify-handoff")
    add_identity_arguments(verify)
    verify.add_argument("--handoff", required=True, type=pathlib.Path)
    verify.add_argument("--handoff-sha256", required=True)
    verify.add_argument("--automata-digest", required=True)
    verify.add_argument("--runner-digest", required=True)
    verify.add_argument("--extract-root", type=pathlib.Path)
    verify.add_argument("--github-output", type=pathlib.Path)

    arguments = parser.parse_args()
    identity = ReleaseIdentity.from_arguments(arguments)

    if arguments.operation == "create":
        repository_root = arguments.repository_root.resolve(strict=True)
        manifest = build_manifest(
            repository_root,
            identity,
            arguments.automata_digest,
            arguments.runner_digest,
            arguments.expected_crate,
        )
        manifest_digest, handoff_digest = create_handoff(
            repository_root,
            arguments.manifest,
            arguments.handoff,
            manifest,
            identity,
            arguments.expected_crate,
        )
        write_outputs(
            arguments.github_output,
            {
                "manifest_sha256": manifest_digest,
                "handoff_sha256": handoff_digest,
                "handoff_filename": arguments.handoff.name,
            },
        )
        return

    if arguments.operation == "pack":
        repository_root = arguments.repository_root.resolve(strict=True)
        manifest_digest, handoff_digest = pack_handoff(
            repository_root,
            arguments.manifest,
            arguments.handoff,
            identity,
            arguments.expected_crate,
        )
        write_outputs(
            arguments.github_output,
            {
                "manifest_sha256": manifest_digest,
                "handoff_sha256": handoff_digest,
                "handoff_filename": arguments.handoff.name,
            },
        )
        return

    if arguments.operation == "verify-manifest":
        repository_root = arguments.repository_root.resolve(strict=True)
        manifest, contents = load_manifest(arguments.manifest)
        automata_digest, runner_digest, _ = validate_manifest(
            manifest, identity, repository_root
        )
        write_outputs(
            arguments.github_output,
            {
                "automata_digest": automata_digest,
                "runner_digest": runner_digest,
                "manifest_sha256": sha256_bytes(contents),
            },
        )
        return

    manifest, contents = verify_handoff(
        arguments.handoff,
        identity,
        arguments.automata_digest,
        arguments.runner_digest,
        expected_handoff_digest=arguments.handoff_sha256,
    )
    if arguments.extract_root is not None:
        extract_handoff(contents, arguments.extract_root)
    write_outputs(
        arguments.github_output,
        {
            "automata_digest": manifest["images"]["automata"]["digest"],
            "runner_digest": manifest["images"]["automata-runner"]["digest"],
            "manifest_sha256": sha256_bytes(contents[MANIFEST_PATH]),
        },
    )


if __name__ == "__main__":
    main()
