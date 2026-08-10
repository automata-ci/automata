#!/usr/bin/env python3
"""Publish the workspace to crates.io in dependency order, safely across retries."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import http.client
import io
import json
import os
import pathlib
import re
import socket
import stat
import struct
import subprocess
import tarfile
import time
import tomllib
import urllib.parse
from collections.abc import Callable
from typing import NoReturn


REPOSITORY = "https://github.com/automata-ci/automata"
HOMEPAGE = "https://automata-ci.github.io/automata/"
PUBLISH_ENDPOINT = "https://crates.io/api/v1/crates/new"
PLAN_SCHEMA_VERSION = 1
MAX_CRATE_SIZE = 10 * 1024 * 1024
MAX_CRATE_CONTENT_SIZE = 128 * 1024 * 1024
MAX_CRATE_MEMBER_SIZE = 16 * 1024 * 1024
MAX_CRATE_MEMBERS = 20_000
MAX_CRATE_STREAM_SIZE = (
    MAX_CRATE_CONTENT_SIZE + MAX_CRATE_MEMBERS * 1024 + 1024 * 1024
)
MAX_API_RESPONSE_SIZE = 1024 * 1024
MAX_PUBLISH_METADATA_SIZE = 256 * 1024
MAX_PLAN_SIZE = 1024 * 1024
MAX_SOURCE_FILE_SIZE = 2 * 1024 * 1024
MAX_TOKEN_SIZE = 4096
MAX_PUBLISH_SESSION_SECONDS = 20 * 60
MIN_UPLOAD_START_SECONDS = 90
EXISTING_CRATE_BURST = 30
EXISTING_CRATE_INTERVAL_SECONDS = 61
NEW_CRATE_BURST = 5
SHA256 = re.compile(r"[0-9a-f]{64}")
OWNER_LOGIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
CRATE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*")


def fail(message: str) -> NoReturn:
    raise SystemExit(f"publish-crates: {message}")


def cargo_metadata(repository_root: pathlib.Path) -> dict:
    result = subprocess.run(
        [
            "cargo",
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--all-features",
        ],
        cwd=repository_root,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return json.loads(result.stdout)


def publication_order(metadata: dict) -> list[dict]:
    workspace_ids = set(metadata["workspace_members"])
    packages = {
        package["id"]: package
        for package in metadata["packages"]
        if package["id"] in workspace_ids
    }
    if set(packages) != workspace_ids:
        fail("Cargo metadata omits one or more workspace packages")

    publishable_ids: set[str] = set()
    private_ids: set[str] = set()
    for package_id, package in packages.items():
        name = package.get("name")
        if not isinstance(name, str) or CRATE_NAME.fullmatch(name) is None:
            fail("workspace contains an invalid package name")
        publish = package.get("publish")
        if publish == ["crates-io"]:
            publishable_ids.add(package_id)
        elif publish == []:
            private_ids.add(package_id)
        else:
            fail(
                f"{name} must either set publish = false or restrict publishing "
                "to crates.io"
            )

    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    dependencies: dict[str, set[str]] = {}
    for package_id in publishable_ids:
        if package_id not in nodes:
            fail(
                "Cargo metadata omits the dependency node for "
                f"{packages[package_id]['name']}"
            )
        package_dependencies: set[str] = set()
        for dependency in nodes[package_id]["deps"]:
            if dependency["pkg"] not in workspace_ids:
                continue
            if dependency["dep_kinds"] and all(
                kind["kind"] == "dev" for kind in dependency["dep_kinds"]
            ):
                continue
            if dependency["pkg"] in private_ids:
                fail(
                    f"publishable crate {packages[package_id]['name']} has a "
                    f"non-development dependency on private workspace crate "
                    f"{packages[dependency['pkg']]['name']}"
                )
            package_dependencies.add(dependency["pkg"])
        dependencies[package_id] = package_dependencies

    ordered: list[str] = []
    remaining = set(publishable_ids)
    while remaining:
        ready = sorted(
            (
                package_id
                for package_id in remaining
                if not dependencies[package_id] & remaining
            ),
            key=lambda package_id: packages[package_id]["name"],
        )
        if not ready:
            cycle = ", ".join(sorted(packages[item]["name"] for item in remaining))
            fail(f"first-party non-development dependency cycle: {cycle}")
        ordered.extend(ready)
        remaining.difference_update(ready)
    return [packages[package_id] for package_id in ordered]


def canonical_json(document: object) -> bytes:
    return (
        json.dumps(document, allow_nan=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def publish_json(document: object) -> bytes:
    return json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sha256_bytes(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def regular_file_bytes(
    path: pathlib.Path, label: str, maximum_size: int = MAX_SOURCE_FILE_SIZE
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail(f"{label} must be a regular, non-symbolic-link file: {path}: {error}")
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            fail(f"{label} must be a regular, non-symbolic-link file: {path}")
        if metadata.st_nlink != 1:
            fail(f"{label} must not be hard linked: {path}")
        if metadata.st_size > maximum_size:
            fail(f"{label} exceeds its size limit: {path}")
        contents = stream.read(maximum_size + 1)
        after = os.fstat(stream.fileno())
        before_identity = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if after_identity != before_identity:
            fail(f"{label} changed while it was read: {path}")
    if len(contents) > maximum_size:
        fail(f"{label} exceeds its size limit: {path}")
    return contents


class BoundedDecompressedReader:
    """Expose gzip data while bounding hidden tar extension records."""

    def __init__(self, stream: gzip.GzipFile, maximum_size: int) -> None:
        self.stream = stream
        self.maximum_size = maximum_size
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        remaining = self.maximum_size - self.bytes_read
        requested = 1024 * 1024 if size < 0 else size
        requested = min(requested, remaining + 1, 1024 * 1024)
        contents = self.stream.read(requested)
        self.bytes_read += len(contents)
        if self.bytes_read > self.maximum_size:
            fail("crate archive decompressed stream exceeds its size limit")
        return contents


def validate_source_license(
    package_name: str,
    package_directory: pathlib.Path,
    expected_license: bytes,
) -> None:
    license_path = package_directory / "LICENSE"
    actual_license = regular_file_bytes(license_path, f"{package_name} license")
    if actual_license != expected_license:
        fail(f"{package_name} LICENSE differs from the repository LICENSE")


def inspect_crate(repository_root: pathlib.Path, package: dict) -> tuple[str, dict]:
    archive = repository_root / "target" / "package" / (
        f"{package['name']}-{package['version']}.crate"
    )
    archive_bytes = regular_file_bytes(archive, "preflight archive", MAX_CRATE_SIZE)
    archive_root = f"{package['name']}-{package['version']}"
    required_members = {
        f"{archive_root}/Cargo.toml",
        f"{archive_root}/Cargo.toml.orig",
        f"{archive_root}/LICENSE",
        f"{archive_root}/README.md",
    }
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(archive_bytes), mode="rb") as gzip_stream:
            bounded_stream = BoundedDecompressedReader(
                gzip_stream, MAX_CRATE_STREAM_SIZE
            )
            with tarfile.open(fileobj=bounded_stream, mode="r|") as package_archive:
                members: set[str] = set()
                selected: dict[str, bytes] = {}
                total_size = 0
                for member in package_archive:
                    if len(members) >= MAX_CRATE_MEMBERS:
                        fail(f"{package['name']} archive contains too many members")
                    member_path = pathlib.PurePosixPath(member.name)
                    if (
                        member_path.is_absolute()
                        or "." in member_path.parts
                        or ".." in member_path.parts
                        or not member_path.parts
                        or member_path.parts[0] != archive_root
                    ):
                        fail(
                            f"{package['name']} archive contains an unsafe path: "
                            f"{member.name}"
                        )
                    if member.name in members:
                        fail(f"{package['name']} archive contains duplicate paths")
                    members.add(member.name)
                    if (
                        member.type != tarfile.REGTYPE
                        or member.pax_headers
                        or member.sparse is not None
                        or member.linkname
                        or member.size < 0
                        or member.size > MAX_CRATE_MEMBER_SIZE
                    ):
                        fail(
                            f"{package['name']} archive contains a non-regular entry: "
                            f"{member.name}"
                        )
                    total_size += member.size
                    if total_size > MAX_CRATE_CONTENT_SIZE:
                        fail(f"{package['name']} archive expands beyond its size limit")
                    if member.name in required_members:
                        member_stream = package_archive.extractfile(member)
                        if member_stream is None:
                            fail(f"could not read required member {member.name}")
                        contents = member_stream.read(member.size + 1)
                        if len(contents) != member.size:
                            fail(f"archive member has inconsistent size: {member.name}")
                        selected[member.name] = contents
                missing = sorted(required_members - members)
                if missing:
                    fail(
                        f"{package['name']} {package['version']} archive is missing: "
                        + ", ".join(missing)
                    )
                packaged_license = selected[f"{archive_root}/LICENSE"]
                packaged_readme = selected[f"{archive_root}/README.md"]
            while bounded_stream.read(1024 * 1024):
                pass
    except (EOFError, gzip.BadGzipFile, OSError, tarfile.TarError) as error:
        fail(f"could not inspect preflight archive {archive}: {error}")
    expected_license = regular_file_bytes(
        repository_root / "LICENSE", "repository license"
    )
    if packaged_license != expected_license:
        fail(f"{package['name']} {package['version']} contains an unexpected LICENSE")
    expected_readme = regular_file_bytes(
        pathlib.Path(package["manifest_path"]).parent / "README.md",
        f"{package['name']} readme",
    )
    if packaged_readme != expected_readme:
        fail(f"{package['name']} {package['version']} contains an unexpected README")
    try:
        normalized_manifest = tomllib.loads(
            selected[f"{archive_root}/Cargo.toml"].decode("utf-8")
        )
        readme = packaged_readme.decode("utf-8")
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        fail(f"{package['name']} package metadata is not strict UTF-8 TOML: {error}")
    manifest_package = normalized_manifest.get("package")
    if not isinstance(manifest_package, dict):
        fail(f"{package['name']} normalized manifest has no package table")
    if (
        manifest_package.get("name") != package["name"]
        or manifest_package.get("version") != package["version"]
        or manifest_package.get("readme") != "README.md"
        or manifest_package.get("publish") != ["crates-io"]
        or manifest_package.get("repository") != REPOSITORY
        or manifest_package.get("license") != "MIT"
        or "license-file" in manifest_package
    ):
        fail(f"{package['name']} normalized manifest differs from Cargo metadata")
    metadata = {
        "name": package["name"],
        "readme": readme,
        "readme_file": "README.md",
        "vers": package["version"],
    }
    if len(publish_json(metadata)) > MAX_PUBLISH_METADATA_SIZE:
        fail(f"{package['name']} publish metadata exceeds its size limit")
    return sha256_bytes(archive_bytes), metadata


def crate_checksum(repository_root: pathlib.Path, package: dict) -> str:
    return inspect_crate(repository_root, package)[0]


def crates_io_document(path: str, label: str) -> dict | None:
    connection = http.client.HTTPSConnection("crates.io", 443, timeout=30)
    try:
        connection.request(
            "GET",
            path,
            headers={
                "Accept": "application/json",
                "User-Agent": f"automata-ci-release ({REPOSITORY})",
            },
        )
        response = connection.getresponse()
        contents = response.read(MAX_API_RESPONSE_SIZE + 1)
        if response.status == 404:
            return None
        if not 200 <= response.status < 300:
            fail(f"crates.io {label} returned HTTP {response.status}")
        if len(contents) > MAX_API_RESPONSE_SIZE:
            fail(f"crates.io returned an oversized {label}")
        document = json.loads(contents)
    except (ConnectionError, http.client.HTTPException, OSError) as error:
        fail(f"crates.io {label} failed: {type(error).__name__}")
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"crates.io {label} is invalid JSON: {error}")
    finally:
        connection.close()
    if not isinstance(document, dict):
        fail(f"crates.io {label} is not a JSON object")
    return document


def published_checksum(name: str, version: str) -> str | None:
    quoted_name = urllib.parse.quote(name, safe="")
    quoted_version = urllib.parse.quote(version, safe="")
    document = crates_io_document(
        f"/api/v1/crates/{quoted_name}/{quoted_version}",
        f"checksum response for {name} {version}",
    )
    if document is None:
        return None
    version_record = document.get("version")
    if (
        not isinstance(version_record, dict)
        or version_record.get("crate") != name
        or version_record.get("num") != version
    ):
        fail(f"crates.io returned the wrong identity for {name} {version}")
    if version_record.get("yanked") is not False:
        fail(f"crates.io reports {name} {version} as yanked")
    checksum = version_record.get("checksum")
    if not isinstance(checksum, str) or SHA256.fullmatch(checksum) is None:
        fail(f"crates.io returned an invalid checksum for {name} {version}")
    return checksum


def crate_exists(name: str) -> bool:
    quoted_name = urllib.parse.quote(name, safe="")
    return (
        crates_io_document(
            f"/api/v1/crates/{quoted_name}", f"name response for {name}"
        )
        is not None
    )


def crate_owner_logins(name: str) -> set[str]:
    quoted_name = urllib.parse.quote(name, safe="")
    document = crates_io_document(
        f"/api/v1/crates/{quoted_name}/owners", f"owner response for {name}"
    )
    if document is None or not isinstance(document.get("users"), list):
        fail(f"crates.io returned no owner list for {name}")
    logins: set[str] = set()
    for owner in document["users"]:
        login = owner.get("login") if isinstance(owner, dict) else None
        if not isinstance(login, str) or OWNER_LOGIN.fullmatch(login) is None:
            fail(f"crates.io returned an invalid owner for {name}")
        if login in logins:
            fail(f"crates.io returned a duplicate owner for {name}")
        logins.add(login)
    if not logins:
        fail(f"crates.io returned an empty owner list for {name}")
    return logins


def parse_owner_allowlist(value: str) -> set[str]:
    logins = value.split(",") if value else []
    if (
        not logins
        or any(OWNER_LOGIN.fullmatch(login) is None for login in logins)
        or logins != sorted(set(logins))
    ):
        fail(
            "CRATES_IO_EXPECTED_OWNER_LOGINS must be a sorted, comma-separated "
            "owner allowlist"
        )
    return set(logins)


def require_expected_owners(name: str, expected: set[str]) -> None:
    actual = crate_owner_logins(name)
    if actual != expected:
        fail(
            f"crates.io owners for {name} differ from the configured allowlist: "
            f"{sorted(actual)!r}"
        )


def check_initial_capacity(
    metadata: dict, expected_owners: set[str], override_approved: str
) -> list[str]:
    if override_approved not in {"", "false", "true"}:
        fail("CRATES_IO_INITIAL_BURST_OVERRIDE_APPROVED must be true or false")
    new_names: list[str] = []
    for package in publication_order(metadata):
        name = package["name"]
        if package.get("publish") != ["crates-io"]:
            fail(f"{name} is not restricted to crates.io publishing")
        if crate_exists(name):
            require_expected_owners(name, expected_owners)
        else:
            new_names.append(name)
    if len(new_names) > NEW_CRATE_BURST and override_approved != "true":
        fail(
            f"{len(new_names)} new crate names exceed crates.io's initial burst of "
            f"{NEW_CRATE_BURST}; obtain a publisher rate-limit override and set "
            "CRATES_IO_INITIAL_BURST_OVERRIDE_APPROVED=true before tagging"
        )
    return new_names


def release_manifest_crates(path: pathlib.Path) -> tuple[str, dict[str, dict]]:
    contents = regular_file_bytes(path, "release manifest", MAX_PLAN_SIZE)
    try:
        document = json.loads(contents)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"release manifest is invalid JSON: {error}")
    if not isinstance(document, dict) or canonical_json(document) != contents:
        fail("release manifest is not a canonical JSON object")
    crates = document.get("crates")
    if not isinstance(crates, list) or not crates or len(crates) > 128:
        fail("release manifest contains an invalid crate list")
    entries: dict[str, dict] = {}
    for entry in crates:
        if not isinstance(entry, dict) or set(entry) != {
            "name",
            "path",
            "sha256",
            "version",
        }:
            fail("release manifest contains an invalid crate record")
        name = entry["name"]
        version = entry["version"]
        digest = entry["sha256"]
        expected_path = f"target/package/{name}-{version}.crate"
        if (
            not isinstance(name, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", name) is None
            or not isinstance(version, str)
            or not version
            or entry["path"] != expected_path
            or not isinstance(digest, str)
            or SHA256.fullmatch(digest) is None
            or name in entries
        ):
            fail("release manifest contains an invalid crate record")
        entries[name] = entry
    return sha256_bytes(contents), entries


def build_publication_plan(
    repository_root: pathlib.Path,
    release_manifest: pathlib.Path | None = None,
) -> dict:
    packages = publication_order(cargo_metadata(repository_root))
    if not packages:
        fail("workspace has no publishable packages")
    expected_license = regular_file_bytes(
        repository_root / "LICENSE", "repository license"
    )
    manifest_digest: str | None = None
    manifest_crates: dict[str, dict] | None = None
    if release_manifest is not None:
        manifest_digest, manifest_crates = release_manifest_crates(release_manifest)

    plan_entries: list[dict] = []
    publish_required = False
    package_names: set[str] = set()
    for package in packages:
        if package.get("publish") != ["crates-io"]:
            fail(f"{package['name']} is not restricted to crates.io publishing")
        if package.get("license") != "MIT":
            fail(f"{package['name']} does not declare the workspace MIT license")
        if package.get("license_file") is not None:
            fail(f"{package['name']} must use SPDX metadata without license-file")
        if package.get("repository") != REPOSITORY:
            fail(f"{package['name']} does not use the canonical repository URL")
        if package.get("homepage") != HOMEPAGE:
            fail(f"{package['name']} does not use the canonical homepage URL")
        if (
            not isinstance(package.get("description"), str)
            or not package["description"].strip()
        ):
            fail(f"{package['name']} has no crates.io description")
        if package.get("readme") != "README.md":
            fail(f"{package['name']} does not publish its crate README")
        if pathlib.Path(package["manifest_path"]).parent.name != package["name"]:
            fail(f"{package['name']} does not match its package directory")
        validate_source_license(
            package["name"],
            pathlib.Path(package["manifest_path"]).parent,
            expected_license,
        )
        name = package["name"]
        version = package["version"]
        package_names.add(name)
        local_checksum, metadata = inspect_crate(repository_root, package)
        if manifest_crates is not None:
            manifest_entry = manifest_crates.get(name)
            if (
                manifest_entry is None
                or manifest_entry["version"] != version
                or manifest_entry["sha256"] != local_checksum
            ):
                fail(f"{name} package differs from the release handoff")
        remote_checksum = published_checksum(name, version)
        if remote_checksum is not None and remote_checksum != local_checksum:
            fail(f"existing {name} {version} differs from the preflight package")
        publish_required = publish_required or remote_checksum is None
        plan_entries.append(
            {
                "metadata": metadata,
                "name": name,
                "sha256": local_checksum,
                "version": version,
            }
        )

    if manifest_crates is not None and package_names != set(manifest_crates):
        missing = sorted(set(manifest_crates) - package_names)
        extra = sorted(package_names - set(manifest_crates))
        fail(
            "workspace and handoff package sets differ: "
            f"missing={missing!r}, extra={extra!r}"
        )
    return {
        "packages": plan_entries,
        "publish_required": publish_required,
        "release_manifest_sha256": manifest_digest,
        "schema_version": PLAN_SCHEMA_VERSION,
    }


def write_exclusive(path: pathlib.Path, contents: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        fail(f"refusing to overwrite publication plan {path}: {error}")
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(contents)
        stream.flush()
        os.fsync(stream.fileno())


def validate_publish_metadata(metadata: object, name: str, version: str) -> dict:
    if not isinstance(metadata, dict) or set(metadata) != {
        "name",
        "readme",
        "readme_file",
        "vers",
    }:
        fail("prepared publication plan has invalid crates.io metadata")
    if (
        metadata["name"] != name
        or metadata["vers"] != version
        or metadata["readme_file"] != "README.md"
        or not isinstance(metadata["readme"], str)
    ):
        fail("prepared publication metadata differs from its package record")
    if len(publish_json(metadata)) > MAX_PUBLISH_METADATA_SIZE:
        fail("prepared publication metadata exceeds its size limit")
    return metadata


def load_plan(path: pathlib.Path, expected_digest: str) -> dict:
    if SHA256.fullmatch(expected_digest) is None:
        fail("prepared plan digest is invalid")
    contents = regular_file_bytes(path, "prepared publication plan", MAX_PLAN_SIZE)
    if sha256_bytes(contents) != expected_digest:
        fail("prepared publication plan digest changed after authorization")
    try:
        plan = json.loads(contents)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"prepared publication plan is invalid JSON: {error}")
    if not isinstance(plan, dict) or canonical_json(plan) != contents:
        fail("prepared publication plan is not canonical JSON")
    if set(plan) != {
        "packages",
        "publish_required",
        "release_manifest_sha256",
        "schema_version",
    }:
        fail("prepared publication plan has unexpected fields")
    if type(plan["schema_version"]) is not int or plan["schema_version"] != 1:
        fail("prepared publication plan schema is unsupported")
    if type(plan["publish_required"]) is not bool:
        fail("prepared publication plan publish requirement is invalid")
    if (
        not isinstance(plan["release_manifest_sha256"], str)
        or SHA256.fullmatch(plan["release_manifest_sha256"]) is None
    ):
        fail("prepared publication plan is not bound to a release manifest")
    packages = plan["packages"]
    if not isinstance(packages, list) or not packages or len(packages) > 128:
        fail("prepared publication plan has an invalid package list")
    names: set[str] = set()
    for entry in packages:
        if not isinstance(entry, dict) or set(entry) != {
            "metadata",
            "name",
            "sha256",
            "version",
        }:
            fail("prepared publication plan has an invalid package record")
        if (
            not isinstance(entry["name"], str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", entry["name"]) is None
            or entry["name"] in names
            or not isinstance(entry["version"], str)
            or not entry["version"]
            or not isinstance(entry["sha256"], str)
            or SHA256.fullmatch(entry["sha256"]) is None
        ):
            fail("prepared publication plan has an invalid package record")
        validate_publish_metadata(entry["metadata"], entry["name"], entry["version"])
        names.add(entry["name"])
    return plan


def artifact_bytes(repository_root: pathlib.Path, name: str, version: str) -> bytes:
    path = repository_root / "target" / "package" / f"{name}-{version}.crate"
    return regular_file_bytes(path, f"prepared {name} archive", MAX_CRATE_SIZE)


class AmbiguousUpload(Exception):
    pass


def bounded_response(response) -> bytes:
    contents = response.read(MAX_API_RESPONSE_SIZE + 1)
    if len(contents) > MAX_API_RESPONSE_SIZE:
        raise AmbiguousUpload("oversized response")
    return contents


def framed_upload(metadata: dict, archive: bytes) -> bytes:
    metadata_bytes = publish_json(metadata)
    if len(metadata_bytes) > MAX_PUBLISH_METADATA_SIZE:
        fail("crates.io publish metadata exceeds its size limit")
    if len(archive) > MAX_CRATE_SIZE:
        fail("crate archive exceeds the crates.io upload limit")
    return b"".join(
        (
            struct.pack("<I", len(metadata_bytes)),
            metadata_bytes,
            struct.pack("<I", len(archive)),
            archive,
        )
    )


def upload_exact_archive(
    metadata: dict,
    archive: bytes,
    token: str,
    *,
    endpoint: str = PUBLISH_ENDPOINT,
    connection_factory: Callable[
        [urllib.parse.SplitResult], http.client.HTTPConnection
    ]
    | None = None,
) -> None:
    body = framed_upload(metadata, archive)
    target = urllib.parse.urlsplit(endpoint)
    if (
        target.username is not None
        or target.password is not None
        or target.fragment
        or target.query
        or not target.path.startswith("/")
    ):
        fail("crates.io publish endpoint is malformed")
    connection: http.client.HTTPConnection | None = None
    try:
        if connection_factory is None:
            if endpoint != PUBLISH_ENDPOINT:
                fail("refusing a non-canonical crates.io publish endpoint")
            connection = http.client.HTTPSConnection("crates.io", 443, timeout=60)
        else:
            connection = connection_factory(target)
        connection.request(
            "PUT",
            target.path,
            body=body,
            headers={
                "Accept": "application/json",
                "Authorization": token,
                "Content-Type": "application/octet-stream",
                "User-Agent": (
                    f"automata-ci-release/{metadata['vers']} ({REPOSITORY})"
                ),
            },
        )
        response = connection.getresponse()
        status = response.status
        contents = bounded_response(response)
        if 300 <= status < 400:
            raise AmbiguousUpload(f"redirect HTTP {status}")
        if not 200 <= status < 300:
            raise AmbiguousUpload(f"HTTP {status}")
    except (
        ConnectionError,
        http.client.HTTPException,
        OSError,
        socket.timeout,
        TimeoutError,
    ) as error:
        raise AmbiguousUpload(type(error).__name__) from error
    finally:
        if connection is not None:
            connection.close()
    try:
        document = json.loads(contents)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AmbiguousUpload("invalid JSON response") from error
    if not isinstance(document, dict):
        raise AmbiguousUpload("non-object response")
    if "errors" in document and (
        not isinstance(document["errors"], list) or document["errors"]
    ):
        raise AmbiguousUpload("error response")


def wait_until_visible(
    name: str,
    version: str,
    expected_checksum: str,
    *,
    timeout_seconds: int = 180,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        actual_checksum = published_checksum(name, version)
        if actual_checksum is None:
            time.sleep(3)
            continue
        if actual_checksum != expected_checksum:
            fail(f"published checksum mismatch for {name} {version}")
        return
    fail(f"{name} {version} did not become visible within {timeout_seconds} seconds")


def execute_plan(
    repository_root: pathlib.Path,
    plan: dict,
    token: str,
    expected_owners: set[str],
    initial_override_approved: str,
    *,
    endpoint: str = PUBLISH_ENDPOINT,
    connection_factory: Callable[
        [urllib.parse.SplitResult], http.client.HTTPConnection
    ]
    | None = None,
) -> None:
    upload_deadline = time.monotonic() + MAX_PUBLISH_SESSION_SECONDS
    if (
        not isinstance(token, str)
        or not token
        or len(token) > MAX_TOKEN_SIZE
        or re.fullmatch(r"[!-~]+", token) is None
    ):
        fail("crates.io token is missing or malformed")
    if initial_override_approved not in {"false", "true"}:
        fail("bound initial-burst override state is invalid")
    publication_plan: list[tuple[dict, bytes, str | None, bool]] = []
    for entry in plan["packages"]:
        archive = artifact_bytes(repository_root, entry["name"], entry["version"])
        local_checksum = sha256_bytes(archive)
        if local_checksum != entry["sha256"]:
            fail(f"prepared archive changed for {entry['name']} {entry['version']}")
        remote_checksum = published_checksum(entry["name"], entry["version"])
        if remote_checksum is not None and remote_checksum != local_checksum:
            fail(
                f"existing {entry['name']} {entry['version']} differs from the "
                "prepared package"
            )
        existing_name = remote_checksum is not None or crate_exists(entry["name"])
        if existing_name:
            require_expected_owners(entry["name"], expected_owners)
        publication_plan.append((entry, archive, remote_checksum, not existing_name))

    new_name_count = sum(new_name for _, _, _, new_name in publication_plan)
    if (
        new_name_count > NEW_CRATE_BURST
        and initial_override_approved != "true"
    ):
        fail(
            f"{new_name_count} new crate names exceed crates.io's initial burst; "
            "the gated rate-limit override is not approved"
        )

    existing_uploads = 0
    last_existing_upload = 0.0
    for entry, archive, remote_checksum, new_name in publication_plan:
        name = entry["name"]
        version = entry["version"]
        if remote_checksum is not None:
            print(f"already published: {name} {version}", flush=True)
            continue
        if new_name and crate_exists(name):
            require_expected_owners(name, expected_owners)
            raced_checksum = published_checksum(name, version)
            if raced_checksum is not None:
                if raced_checksum != entry["sha256"]:
                    fail(f"raced publication checksum mismatch for {name} {version}")
                print(
                    f"already published after preflight: {name} {version}",
                    flush=True,
                )
                continue
            new_name = False
        if not new_name:
            if existing_uploads >= EXISTING_CRATE_BURST:
                delay = (
                    last_existing_upload
                    + EXISTING_CRATE_INTERVAL_SECONDS
                    - time.monotonic()
                )
                if delay > 0:
                    if (
                        time.monotonic() + delay + MIN_UPLOAD_START_SECONDS
                        > upload_deadline
                    ):
                        fail(
                            "credential safety window cannot accommodate crates.io "
                            "rate-limit pacing; rerun to skip exact uploads"
                        )
                    time.sleep(delay)
            existing_uploads += 1
        if time.monotonic() + MIN_UPLOAD_START_SECONDS > upload_deadline:
            fail("credential safety window is exhausted; rerun to skip exact uploads")
        print(f"publishing exact archive: {name} {version}", flush=True)
        if not new_name:
            last_existing_upload = time.monotonic()
        try:
            upload_exact_archive(
                entry["metadata"],
                archive,
                token,
                endpoint=endpoint,
                connection_factory=connection_factory,
            )
        except AmbiguousUpload as error:
            print(
                f"reconciling ambiguous upload for {name} {version}: {error}",
                flush=True,
            )
        wait_until_visible(name, version, entry["sha256"], timeout_seconds=180)
        require_expected_owners(name, expected_owners)

    token = ""


def main() -> None:
    parser = argparse.ArgumentParser()
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument("--check-capacity", action="store_true")
    operation.add_argument("--list-publishable", action="store_true")
    operation.add_argument("--prepare", type=pathlib.Path)
    operation.add_argument("--execute-prepared", type=pathlib.Path)
    operation.add_argument("--verify-published", action="store_true")
    parser.add_argument("--release-manifest", type=pathlib.Path)
    parser.add_argument("--plan-sha256")
    parser.add_argument("--github-output", type=pathlib.Path)
    arguments = parser.parse_args()

    repository_root = pathlib.Path(__file__).resolve().parents[2]
    if arguments.list_publishable:
        if (
            arguments.release_manifest is not None
            or arguments.plan_sha256 is not None
            or arguments.github_output is not None
        ):
            fail("--list-publishable forbids operation-specific arguments")
        packages = publication_order(cargo_metadata(repository_root))
        if not packages:
            fail("workspace has no publishable packages")
        for package in packages:
            print(package["name"])
        return

    if arguments.check_capacity:
        if (
            arguments.release_manifest is not None
            or arguments.plan_sha256 is not None
        ):
            fail("--check-capacity forbids plan and release-manifest arguments")
        expected_owners = parse_owner_allowlist(
            os.environ.get("CRATES_IO_EXPECTED_OWNER_LOGINS", "")
        )
        metadata = cargo_metadata(repository_root)
        new_names = check_initial_capacity(
            metadata,
            expected_owners,
            os.environ.get("CRATES_IO_INITIAL_BURST_OVERRIDE_APPROVED", ""),
        )
        if arguments.github_output is not None:
            with arguments.github_output.open("a", encoding="utf-8") as output:
                output.write(f"new_crate_count={len(new_names)}\n")
        print(
            f"crates.io name preflight: {len(new_names)} new, "
            f"{len(publication_order(metadata)) - len(new_names)} owned",
            flush=True,
        )
        return

    if arguments.verify_published:
        if (
            arguments.release_manifest is None
            or arguments.plan_sha256 is not None
            or arguments.github_output is not None
        ):
            fail(
                "--verify-published requires --release-manifest and forbids "
                "output arguments"
            )
        expected_owners = parse_owner_allowlist(
            os.environ.get("CRATES_IO_EXPECTED_OWNER_LOGINS", "")
        )
        metadata = cargo_metadata(repository_root)
        missing_names = check_initial_capacity(metadata, expected_owners, "true")
        if missing_names:
            fail(f"crate names remain unpublished: {missing_names!r}")
        plan = build_publication_plan(repository_root, arguments.release_manifest)
        if plan["publish_required"]:
            fail("one or more exact crate versions remain unpublished")
        print("verified exact crates.io versions and owners", flush=True)
        return

    if arguments.prepare is not None:
        if arguments.release_manifest is None or arguments.plan_sha256 is not None:
            fail("--prepare requires --release-manifest and forbids --plan-sha256")
        plan = build_publication_plan(repository_root, arguments.release_manifest)
        plan_bytes = canonical_json(plan)
        write_exclusive(arguments.prepare, plan_bytes)
        digest = sha256_bytes(plan_bytes)
        if arguments.github_output is not None:
            with arguments.github_output.open("a", encoding="utf-8") as output:
                output.write(f"plan_sha256={digest}\n")
                output.write(
                    f"publish_required={str(plan['publish_required']).lower()}\n"
                )
        return

    if arguments.execute_prepared is not None:
        if (
            arguments.release_manifest is None
            or arguments.plan_sha256 is None
            or arguments.github_output is not None
        ):
            fail(
                "--execute-prepared requires --release-manifest and --plan-sha256"
            )
        plan = load_plan(arguments.execute_prepared, arguments.plan_sha256)
        manifest_digest, _ = release_manifest_crates(arguments.release_manifest)
        if manifest_digest != plan["release_manifest_sha256"]:
            fail("release manifest changed after publication preparation")
        token = os.environ.pop("CARGO_REGISTRY_TOKEN", "")
        expected_owners = parse_owner_allowlist(
            os.environ.pop("CRATES_IO_EXPECTED_OWNER_LOGINS", "")
        )
        initial_override_approved = os.environ.pop(
            "CRATES_IO_INITIAL_BURST_OVERRIDE_APPROVED", "false"
        )
        execute_plan(
            repository_root,
            plan,
            token,
            expected_owners,
            initial_override_approved,
        )
        return

    if (
        arguments.release_manifest is not None
        or arguments.plan_sha256 is not None
        or arguments.github_output is not None
    ):
        fail(
            "operation-specific arguments require --prepare, --execute-prepared, "
            "or --verify-published"
        )
    plan = build_publication_plan(repository_root)
    for entry in plan["packages"]:
        remote_checksum = published_checksum(entry["name"], entry["version"])
        state = "already published" if remote_checksum is not None else "would publish"
        print(f"{state}: {entry['name']} {entry['version']}", flush=True)


if __name__ == "__main__":
    main()
