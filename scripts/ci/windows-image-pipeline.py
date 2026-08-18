#!/usr/bin/env python3
"""Build and promote the exact Windows Server 2025 Hyper-V image contract."""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import tempfile
import urllib.parse
import urllib.request
from typing import BinaryIO, Iterator, NoReturn


PROFILE_ID = "automata.dev/windows-2025-x64-hyperv-v1"
BASE_REPOSITORY = "mcr.microsoft.com/windows/servercore"
EVIDENCE_MEDIA_TYPE = (
    "application/vnd.automata.windows-image-evidence-reference+json"
)
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
PROMOTION_PAYLOAD_FIELDS = (
    "schema_version",
    "decision",
    "profile_id",
    "base_image",
    "image",
    "manifest_sha256",
    "lock_sha256",
    "provenance_sha256",
    "sbom_sha256",
    "patch_report_sha256",
    "revocations_sha256",
    "revocation_generation",
    "provenance_accepted",
    "sbom_accepted",
    "patch_accepted",
    "revocations_accepted",
)
SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_COMMIT = re.compile(r"[0-9a-f]{40}")
IMMUTABLE_IMAGE = re.compile(
    r"[a-z0-9](?:[a-z0-9._:/-]*[a-z0-9])?@sha256:([0-9a-f]{64})"
)
IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]{2,127}")
KEY_HANDLE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,255}")
EXPECTED_SOURCES = ("pwsh", "node24")
EXPECTED_TOOLS = (
    ("pwsh", r"C:\Program Files\PowerShell\7\pwsh.exe"),
    (
        "powershell",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    ),
    ("cmd", r"C:\Windows\System32\cmd.exe"),
    ("sha256", r"C:\automata\tools\hash\automata-sha256.exe"),
    ("node24", r"C:\automata\externals\node24\node.exe"),
)
SUBJECT_MEDIA_TYPES = {
    "provenance": "application/vnd.in-toto+json",
    "sbom": "application/spdx+json",
    "patch_report": "application/vnd.automata.windows-patch-report+json",
    "revocations": "application/vnd.automata.image-revocations+json",
}
SUBJECT_FILENAMES = {
    "provenance": "provenance.intoto.json",
    "sbom": "sbom.subject.spdx.json",
    "patch_report": "patch-report.subject.json",
    "revocations": "revocations.subject.json",
}
REFERENCE_STATEMENTS = {
    "provenance": "Accepted in-toto SLSA provenance for the exact image identity.",
    "sbom": "Accepted SPDX 2.3 inventory for the exact image recipe and tools.",
    "patch_report": "Accepted Windows Server 2025 build, UBR, and executable inventory.",
    "revocations": "Accepted image revocation generation and validity window.",
}
REFERENCE_FILENAMES = {
    "provenance": "provenance.json",
    "sbom": "sbom.spdx.json",
    "patch_report": "patch-report.json",
    "revocations": "revocations.json",
}


def fail(message: str) -> NoReturn:
    raise SystemExit(f"windows-image-pipeline: {message}")


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def compact_json(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode()


def sha256(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    value: dict[str, object] = {}
    for name, entry in pairs:
        if name in value:
            raise ValueError(f"duplicate JSON key: {name}")
        value[name] = entry
    return value


def invalid_constant(value: str) -> NoReturn:
    raise ValueError(f"invalid JSON constant: {value}")


def read_open_regular(
    stream: BinaryIO, path: pathlib.Path, maximum: int = MAX_JSON_BYTES
) -> bytes:
    try:
        stream.seek(0)
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            fail(f"input is not a bounded regular file: {path}")
        contents = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    except OSError:
        fail(f"input must be an accessible regular file: {path}")
    identity = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )
    if (
        len(contents) > maximum
        or len(contents) != before.st_size
        or identity(before) != identity(after)
    ):
        fail(f"input changed or exceeded its size limit: {path}")
    return contents


def read_regular(path: pathlib.Path, maximum: int = MAX_JSON_BYTES) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        fail(f"input must be an accessible regular file: {path}")
    with os.fdopen(descriptor, "rb") as stream:
        return read_open_regular(stream, path, maximum)


def windows_file_descriptor(
    path: pathlib.Path,
    desired_access: int,
    share_mode: int,
    creation_disposition: int,
    flags_and_attributes: int,
    descriptor_flags: int,
) -> int:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    handle = create_file(
        str(path),
        desired_access,
        share_mode,
        None,
        creation_disposition,
        flags_and_attributes,
        None,
    )
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return msvcrt.open_osfhandle(int(handle), descriptor_flags)
    except OSError:
        close_handle(handle)
        raise


def open_retained_regular(path: pathlib.Path) -> int:
    if os.name == "nt":
        generic_read = 0x8000_0000
        file_share_read = 0x0000_0001
        open_existing = 3
        file_attribute_normal = 0x0000_0080
        file_flag_open_reparse_point = 0x0020_0000
        return windows_file_descriptor(
            path,
            generic_read,
            file_share_read,
            open_existing,
            file_attribute_normal | file_flag_open_reparse_point,
            os.O_RDONLY | getattr(os, "O_BINARY", 0),
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.open(path, flags)


@contextlib.contextmanager
def retain_exact_regular(
    path: pathlib.Path, expected: bytes, maximum: int
) -> Iterator[BinaryIO]:
    try:
        descriptor = open_retained_regular(path)
    except OSError:
        fail(f"could not retain signing snapshot: {path}")
    with os.fdopen(descriptor, "rb") as stream:
        if read_open_regular(stream, path, maximum) != expected:
            fail(f"signing snapshot differs after custody: {path}")
        yield stream


def open_new_regular(path: pathlib.Path, mode: int) -> int:
    if os.name == "nt":
        generic_read = 0x8000_0000
        generic_write = 0x4000_0000
        file_share_read = 0x0000_0001
        create_new = 1
        file_attribute_normal = 0x0000_0080
        file_flag_open_reparse_point = 0x0020_0000
        return windows_file_descriptor(
            path,
            generic_read | generic_write,
            file_share_read,
            create_new,
            file_attribute_normal | file_flag_open_reparse_point,
            os.O_RDWR | getattr(os, "O_BINARY", 0),
        )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.open(path, flags, mode)


def write_new_regular(
    path: pathlib.Path, contents: bytes, mode: int, label: str
) -> None:
    try:
        descriptor = open_new_regular(path, mode)
    except OSError:
        if path.exists() or path.is_symlink():
            fail(f"refusing to overwrite {label}")
        fail(f"could not create {label}")
    try:
        with os.fdopen(descriptor, "wb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size != 0:
                fail(f"new {label} is not an empty regular file")
            if stream.write(contents) != len(contents):
                fail(f"could not write complete {label}")
            stream.flush()
            os.fsync(stream.fileno())
            after = os.fstat(stream.fileno())
            if not stat.S_ISREG(after.st_mode) or after.st_size != len(contents):
                fail(f"new {label} changed while writing")
    except OSError:
        fail(f"could not write {label}")


def parse_json(contents: bytes, label: str, *, canonical: bool = False) -> object:
    try:
        value = json.loads(
            contents,
            object_pairs_hook=unique_object,
            parse_constant=invalid_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        fail(f"{label} is invalid JSON")
    if canonical and canonical_json(value) != contents:
        fail(f"{label} is not canonical JSON")
    reject_fixture_marker(value, label)
    return value


def reject_fixture_marker(value: object, label: str) -> None:
    if isinstance(value, dict):
        if "candidate_fixture" in value:
            fail(f"{label} contains a candidate fixture marker")
        for entry in value.values():
            reject_fixture_marker(entry, label)
    elif isinstance(value, list):
        for entry in value:
            reject_fixture_marker(entry, label)


def exact_object(value: object, keys: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{label} keys differ")
    return value


def valid_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        fail(f"{label} is not one lowercase SHA-256")
    if len(set(value)) == 1:
        fail(f"{label} is a placeholder")
    return value


def valid_commit(value: object, label: str) -> str:
    if not isinstance(value, str) or GIT_COMMIT.fullmatch(value) is None:
        fail(f"{label} is not one full lowercase Git commit")
    if value == "0" * 40:
        fail(f"{label} is a placeholder")
    return value


def image_digest(value: object, label: str) -> tuple[str, str]:
    if not isinstance(value, str):
        fail(f"{label} is not an immutable image reference")
    match = IMMUTABLE_IMAGE.fullmatch(value)
    if match is None:
        fail(f"{label} is not an immutable image reference")
    digest = valid_sha(match.group(1), f"{label} digest")
    repository = value.split("@", 1)[0]
    if "example" in repository or "localhost" in repository:
        fail(f"{label} uses a non-production repository")
    return value, digest


def load_source_lock(path: pathlib.Path) -> tuple[dict, bytes]:
    contents = read_regular(path)
    lock = exact_object(
        parse_json(contents, "source lock", canonical=True),
        {
            "architecture",
            "base_image",
            "profile_id",
            "schema_version",
            "sources",
            "variant",
        },
        "source lock",
    )
    if (
        lock["schema_version"] != 1
        or type(lock["schema_version"]) is not int
        or lock["architecture"] != "x86_64"
        or lock["profile_id"] != PROFILE_ID
        or lock["variant"] != "server-core-2025"
    ):
        fail("source lock profile differs")
    base_image, _ = image_digest(lock["base_image"], "base image")
    if base_image.split("@", 1)[0] != BASE_REPOSITORY:
        fail("source lock base repository differs")
    sources = lock["sources"]
    if not isinstance(sources, list) or len(sources) != len(EXPECTED_SOURCES):
        fail("source lock artifact set differs")
    for source, expected_kind in zip(sources, EXPECTED_SOURCES, strict=True):
        source = exact_object(
            source,
            {"filename", "kind", "sha256", "url", "version"},
            "source artifact",
        )
        if source["kind"] != expected_kind:
            fail("source lock artifact order differs")
        if (
            not isinstance(source["filename"], str)
            or pathlib.PurePath(source["filename"]).name != source["filename"]
            or not source["filename"].endswith(".zip")
        ):
            fail("source artifact filename is invalid")
        valid_sha(source["sha256"], f"{expected_kind} archive")
        if (
            not isinstance(source["version"], str)
            or not source["version"]
            or len(source["version"]) > 128
            or not source["version"].isascii()
        ):
            fail("source artifact version is invalid")
        if not isinstance(source["url"], str):
            fail("source artifact URL is invalid")
        parsed = urllib.parse.urlsplit(source["url"])
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or parsed.hostname not in {"github.com", "nodejs.org"}
        ):
            fail("source artifact URL is outside the approved HTTPS origins")
    return lock, contents


def load_build_inputs(path: pathlib.Path, lock_bytes: bytes) -> dict:
    value = exact_object(
        parse_json(read_regular(path), "build input lock", canonical=True),
        {
            "containerfile_sha256",
            "guest_agent",
            "hash_helper",
            "install_script_sha256",
            "schema_version",
            "source_commit",
            "source_date_epoch",
            "source_lock_sha256",
        },
        "build input lock",
    )
    if value["schema_version"] != 1 or type(value["schema_version"]) is not int:
        fail("build input lock schema differs")
    if value["source_lock_sha256"] != sha256(lock_bytes):
        fail("build input lock source digest differs")
    valid_commit(value["source_commit"], "build source commit")
    if (
        type(value["source_date_epoch"]) is not int
        or value["source_date_epoch"] <= 0
        or value["source_date_epoch"] > 8_589_934_591
    ):
        fail("build source epoch is invalid")
    valid_sha(value["containerfile_sha256"], "Containerfile")
    valid_sha(value["install_script_sha256"], "install script")
    for name in ("guest_agent", "hash_helper"):
        artifact = exact_object(
            value[name], {"filename", "sha256"}, f"{name} build artifact"
        )
        if (
            not isinstance(artifact["filename"], str)
            or pathlib.PurePath(artifact["filename"]).name != artifact["filename"]
        ):
            fail(f"{name} filename is invalid")
        valid_sha(artifact["sha256"], name)
    return value


def git_output(source_tree: pathlib.Path, arguments: list[str], label: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(source_tree), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        fail(f"could not inspect {label}")
    if result.returncode != 0 or result.stderr:
        fail(f"could not inspect {label}")
    return result.stdout


def verify_source_checkout(
    source_tree: pathlib.Path, recipe: pathlib.Path, commit: str
) -> int:
    source_tree = source_tree.resolve()
    expected_recipe = source_tree / "images" / "windows-server-2025-hyperv"
    if recipe != expected_recipe:
        fail("recipe directory is outside its fixed repository location")
    top = git_output(source_tree, ["rev-parse", "--show-toplevel"], "source tree")
    if pathlib.Path(os.fsdecode(top).strip()).resolve() != source_tree:
        fail("source tree is not the exact Git worktree root")
    head = os.fsdecode(
        git_output(source_tree, ["rev-parse", "HEAD"], "source HEAD")
    ).strip()
    if head != commit:
        fail("source checkout HEAD differs from the requested commit")
    status = git_output(
        source_tree,
        ["status", "--porcelain=v1", "--untracked-files=all"],
        "source status",
    )
    if status:
        fail("source checkout is not clean")
    for relative in (
        "images/windows-server-2025-hyperv/Containerfile",
        "images/windows-server-2025-hyperv/install-image.ps1",
        "images/windows-server-2025-hyperv/sources.lock.json",
    ):
        committed = os.fsdecode(
            git_output(
                source_tree,
                ["rev-parse", f"{commit}:{relative}"],
                f"committed {relative}",
            )
        ).strip()
        worktree = os.fsdecode(
            git_output(
                source_tree,
                ["hash-object", f"--path={relative}", str(source_tree / relative)],
                f"worktree {relative}",
            )
        ).strip()
        if committed != worktree:
            fail(f"source checkout file differs from its commit: {relative}")
    epoch_text = os.fsdecode(
        git_output(
            source_tree,
            ["show", "-s", "--format=%ct", commit],
            "source commit timestamp",
        )
    ).strip()
    if not epoch_text.isascii() or not epoch_text.isdigit():
        fail("source commit timestamp is invalid")
    epoch = int(epoch_text)
    if epoch <= 0 or epoch > 8_589_934_591:
        fail("source commit timestamp is invalid")
    return epoch


def download(source: dict, destination: pathlib.Path) -> None:
    request = urllib.request.Request(
        source["url"], headers={"User-Agent": "automata-windows-image-pipeline/1"}
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            final = urllib.parse.urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname not in {
                "github.com",
                "objects.githubusercontent.com",
                "release-assets.githubusercontent.com",
                "nodejs.org",
            }:
                fail("artifact download redirected outside approved HTTPS origins")
            expected_length = response.headers.get("Content-Length")
            contents = response.read(MAX_ARTIFACT_BYTES + 1)
    except OSError:
        fail(f"could not download pinned artifact: {source['kind']}")
    if len(contents) > MAX_ARTIFACT_BYTES:
        fail("downloaded artifact exceeds its size limit")
    if expected_length is not None:
        try:
            content_length = int(expected_length)
        except ValueError:
            fail("downloaded artifact length is invalid")
        if content_length < 0 or content_length != len(contents):
            fail("downloaded artifact length differs")
    if sha256(contents) != source["sha256"]:
        fail(f"downloaded artifact digest differs: {source['kind']}")
    destination.write_bytes(contents)


def prepare_context(arguments: argparse.Namespace) -> None:
    lock, lock_bytes = load_source_lock(arguments.lock)
    recipe = arguments.recipe_directory.resolve()
    output = arguments.output.resolve()
    if output.exists() or output.is_symlink():
        fail("refusing to overwrite image build context")
    if output.parent.is_symlink():
        fail("image build context parent must not be a symbolic link")

    guest_bytes = read_regular(arguments.guest_agent, MAX_ARTIFACT_BYTES)
    hash_bytes = read_regular(arguments.hash_helper, MAX_ARTIFACT_BYTES)
    if sha256(guest_bytes) != valid_sha(arguments.guest_agent_sha256, "guest agent"):
        fail("guest agent differs from its reviewed digest")
    if sha256(hash_bytes) != valid_sha(arguments.hash_helper_sha256, "hash helper"):
        fail("hash helper differs from its reviewed digest")
    commit = valid_commit(arguments.source_commit, "source commit")
    source_epoch = verify_source_checkout(
        arguments.source_tree, recipe, commit
    )
    containerfile_bytes = read_regular(recipe / "Containerfile")
    install_bytes = read_regular(recipe / "install-image.ps1")
    if lock["base_image"].encode() not in containerfile_bytes:
        fail("Containerfile does not use the exact locked base image")

    output.mkdir(parents=True, mode=0o700)
    try:
        (output / "sources.lock.json").write_bytes(lock_bytes)
        (output / "Containerfile").write_bytes(containerfile_bytes)
        (output / "install-image.ps1").write_bytes(install_bytes)
        (output / "automata-ci-sandbox-guest.exe").write_bytes(guest_bytes)
        (output / "automata-sha256.exe").write_bytes(hash_bytes)
        for source in lock["sources"]:
            destination = output / source["filename"]
            if arguments.artifact_directory is None:
                download(source, destination)
            else:
                contents = read_regular(
                    arguments.artifact_directory / source["filename"],
                    MAX_ARTIFACT_BYTES,
                )
                if sha256(contents) != source["sha256"]:
                    fail(f"provided artifact digest differs: {source['kind']}")
                destination.write_bytes(contents)
        build_inputs = {
            "containerfile_sha256": sha256(containerfile_bytes),
            "guest_agent": {
                "filename": "automata-ci-sandbox-guest.exe",
                "sha256": sha256(guest_bytes),
            },
            "hash_helper": {
                "filename": "automata-sha256.exe",
                "sha256": sha256(hash_bytes),
            },
            "install_script_sha256": sha256(install_bytes),
            "schema_version": 1,
            "source_commit": commit,
            "source_date_epoch": source_epoch,
            "source_lock_sha256": sha256(lock_bytes),
        }
        (output / "build-inputs.json").write_bytes(canonical_json(build_inputs))
        for path in output.iterdir():
            try:
                os.utime(path, (source_epoch, source_epoch), follow_symlinks=False)
            except NotImplementedError:
                # Windows does not expose follow_symlinks for utime. Every entry
                # was created above under a fresh, private directory.
                os.utime(path, (source_epoch, source_epoch))
    except BaseException:
        shutil.rmtree(output, ignore_errors=True)
        raise


def load_qualification(path: pathlib.Path, image: str, inputs: dict) -> dict:
    value = exact_object(
        parse_json(read_regular(path), "qualification"),
        {
            "architecture",
            "build_inputs_sha256",
            "container_user",
            "guest_agent_sha256",
            "hash_helper_sha256",
            "image",
            "isolation",
            "network_disabled",
            "os",
            "profile_id",
            "schema_version",
            "source_commit",
            "source_lock_sha256",
            "tools",
            "workspace",
        },
        "qualification",
    )
    if (
        value["schema_version"] != 2
        or type(value["schema_version"]) is not int
        or value["profile_id"] != PROFILE_ID
        or value["image"] != image
        or value["architecture"] != "amd64"
        or value["isolation"] != "hyperv"
        or value["network_disabled"] is not True
        or not isinstance(value["container_user"], str)
        or not value["container_user"].lower().endswith(r"\containeruser")
        or value["workspace"].lower() != r"c:\__w".lower()
        or value["guest_agent_sha256"] != inputs["guest_agent"]["sha256"]
        or value["hash_helper_sha256"] != inputs["hash_helper"]["sha256"]
        or value["build_inputs_sha256"] != sha256(canonical_json(inputs))
        or value["source_commit"] != inputs["source_commit"]
        or value["source_lock_sha256"] != inputs["source_lock_sha256"]
    ):
        fail("qualification boundary or local artifact identity differs")
    os_value = exact_object(
        value["os"],
        {"build", "display_version", "edition_id", "installation_type", "ubr"},
        "qualified operating system",
    )
    if (
        os_value["build"] != "26100"
        or os_value["installation_type"] != "Server Core"
        or not isinstance(os_value["ubr"], int)
        or type(os_value["ubr"]) is not int
        or os_value["ubr"] <= 0
        or any(
            not isinstance(os_value[name], str)
            or not os_value[name]
            or len(os_value[name]) > 128
            for name in ("display_version", "edition_id")
        )
    ):
        fail("qualified Windows Server 2025 patch identity is invalid")
    tools = value["tools"]
    if not isinstance(tools, list) or len(tools) != len(EXPECTED_TOOLS):
        fail("qualified tool set differs")
    for tool, expected in zip(tools, EXPECTED_TOOLS, strict=True):
        tool = exact_object(tool, {"kind", "path", "sha256", "version"}, "qualified tool")
        if tool["kind"] != expected[0] or tool["path"].lower() != expected[1].lower():
            fail("qualified tool order or path differs")
        valid_sha(tool["sha256"], f"{tool['kind']} executable")
        if (
            not isinstance(tool["version"], str)
            or not tool["version"]
            or len(tool["version"]) > 128
            or not tool["version"].isascii()
        ):
            fail("qualified tool version is invalid")
    if not tools[0]["version"].endswith("7.6.5"):
        fail("qualified PowerShell version differs from the source lock")
    if tools[3]["version"] != "automata-sha256 1.0.0":
        fail("qualified hash helper version differs")
    if tools[4]["version"] != "v24.19.0":
        fail("qualified Node 24 version differs from the source lock")
    return value


def load_revocations(
    path: pathlib.Path,
    generation: int,
    issued: int,
) -> dict:
    value = exact_object(
        parse_json(read_regular(path), "revocation input", canonical=True),
        {
            "expires_at_unix_millis",
            "generation",
            "issued_at_unix_millis",
            "revoked_images",
            "schema_version",
        },
        "revocation input",
    )
    if (
        any(
            type(value[name]) is not int
            for name in (
                "schema_version",
                "generation",
                "issued_at_unix_millis",
                "expires_at_unix_millis",
            )
        )
        or value["schema_version"] != 1
        or value["generation"] != generation
        or value["issued_at_unix_millis"] <= 0
        or value["expires_at_unix_millis"] <= value["issued_at_unix_millis"]
        or value["issued_at_unix_millis"] > issued
        or value["expires_at_unix_millis"] <= issued
    ):
        fail("revocation input generation or validity window differs")
    revoked = value["revoked_images"]
    if not isinstance(revoked, list) or len(revoked) > 4096 or revoked != sorted(set(revoked)):
        fail("revoked image set is not sorted and unique")
    for image in revoked:
        image_digest(image, "revoked image")
    return value


def timestamp(unix_millis: int) -> str:
    if unix_millis % 1000 != 0:
        fail("evidence issuance timestamp must use whole seconds")
    try:
        value = datetime.datetime.fromtimestamp(
            unix_millis // 1000, datetime.timezone.utc
        )
    except (OverflowError, OSError, ValueError):
        fail("promotion timestamp is outside the supported range")
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_timestamp(value: object, description: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
        value,
    ):
        fail(f"{description} timestamp is not canonical")
    try:
        parsed = datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc
        )
    except ValueError:
        fail(f"{description} timestamp is invalid")
    epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    delta = parsed - epoch
    unix_millis = (
        delta.days * 24 * 60 * 60 * 1000
        + delta.seconds * 1000
    )
    if unix_millis <= 0 or timestamp(unix_millis) != value:
        fail(f"{description} timestamp is invalid")
    return unix_millis


def make_provenance(
    image: str,
    image_sha: str,
    lock: dict,
    lock_bytes: bytes,
    inputs: dict,
    builder_id: str,
    issued: int,
) -> dict:
    dependencies = [
        {
            "digest": {"sha256": source["sha256"]},
            "uri": source["url"],
        }
        for source in lock["sources"]
    ]
    dependencies.extend(
        [
            {
                "digest": {"sha256": inputs["guest_agent"]["sha256"]},
                "uri": "pkg:cargo/automata-ci-sandbox-guest",
            },
            {
                "digest": {"sha256": inputs["hash_helper"]["sha256"]},
                "uri": "pkg:cargo/automata-ci-sandbox-guest#automata-sha256",
            },
            {
                "digest": {"sha256": sha256(lock_bytes)},
                "uri": "git+https://github.com/automata-ci/automata@"
                + inputs["source_commit"]
                + "#images/windows-server-2025-hyperv/sources.lock.json",
            },
            {
                "digest": {"sha256": inputs["containerfile_sha256"]},
                "uri": "git+https://github.com/automata-ci/automata@"
                + inputs["source_commit"]
                + "#images/windows-server-2025-hyperv/Containerfile",
            },
            {
                "digest": {"sha256": inputs["install_script_sha256"]},
                "uri": "git+https://github.com/automata-ci/automata@"
                + inputs["source_commit"]
                + "#images/windows-server-2025-hyperv/install-image.ps1",
            },
        ]
    )
    invocation = sha256(
        (image + inputs["source_commit"] + sha256(lock_bytes)).encode()
    )
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://automata.dev/build/windows-server-2025-hyperv/v1",
                "externalParameters": {
                    "base_image": lock["base_image"],
                    "build_inputs_sha256": sha256(canonical_json(inputs)),
                    "profile_id": PROFILE_ID,
                    "source_commit": inputs["source_commit"],
                },
                "internalParameters": {},
                "resolvedDependencies": dependencies,
            },
            "runDetails": {
                "builder": {"id": builder_id},
                "metadata": {
                    "finishedOn": timestamp(issued),
                    "invocationId": invocation,
                    "startedOn": timestamp(issued),
                },
            },
        },
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [{"digest": {"sha256": image_sha}, "name": image.split("@", 1)[0]}],
    }


def make_sbom(
    image: str,
    image_sha: str,
    lock: dict,
    inputs: dict,
    qualification: dict,
    serial: int,
    issued: int,
) -> dict:
    _, base_image_sha = image_digest(lock["base_image"], "SBOM base image")
    packages = [
        {
            "SPDXID": "SPDXRef-BaseImage",
            "checksums": [
                {"algorithm": "SHA256", "checksumValue": base_image_sha}
            ],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "name": "Microsoft Windows Server Core 2025 base image",
            "supplier": "Organization: Microsoft",
            "versionInfo": qualification["os"]["build"]
            + "."
            + str(qualification["os"]["ubr"]),
        }
    ]
    for index, source in enumerate(lock["sources"], start=1):
        packages.append(
            {
                "SPDXID": f"SPDXRef-Source-{index}",
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": source["sha256"]}
                ],
                "downloadLocation": source["url"],
                "filesAnalyzed": False,
                "name": source["kind"],
                "supplier": "NOASSERTION",
                "versionInfo": source["version"],
            }
        )
    packages.extend(
        [
            {
                "SPDXID": "SPDXRef-AutomataGuest",
                "checksums": [
                    {
                        "algorithm": "SHA256",
                        "checksumValue": inputs["guest_agent"]["sha256"],
                    }
                ],
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "name": "automata-ci-sandbox-guest",
                "supplier": "Organization: Automata CI",
                "versionInfo": "0.1.0",
            },
            {
                "SPDXID": "SPDXRef-AutomataSha256",
                "checksums": [
                    {
                        "algorithm": "SHA256",
                        "checksumValue": inputs["hash_helper"]["sha256"],
                    }
                ],
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "name": "automata-sha256",
                "supplier": "Organization: Automata CI",
                "versionInfo": "1.0.0",
            },
        ]
    )
    namespace = f"https://automata.dev/spdx/windows-2025/{image_sha}/{serial}"
    return {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": timestamp(issued),
            "creators": ["Tool: automata-windows-image-pipeline/1"],
        },
        "dataLicense": "CC0-1.0",
        "documentDescribes": [package["SPDXID"] for package in packages],
        "documentNamespace": namespace,
        "name": f"Automata Windows Server 2025 Hyper-V image {image}",
        "packages": packages,
        "spdxVersion": "SPDX-2.3",
    }


def reference_document(
    kind: str,
    image: str,
    subject_sha256: str,
    statement: str,
    revocations: dict | None = None,
) -> dict:
    value = {
        "image": image,
        "kind": kind,
        "profile_id": PROFILE_ID,
        "schema_version": 1,
        "statement": statement,
        "subject": {
            "media_type": SUBJECT_MEDIA_TYPES[kind],
            "sha256": subject_sha256,
        },
    }
    if revocations is not None:
        value.update(
            {
                "generation": revocations["generation"],
                "revoked_images": revocations["revoked_images"],
            }
        )
    return value


def assemble(arguments: argparse.Namespace) -> None:
    lock, lock_bytes = load_source_lock(arguments.lock)
    inputs = load_build_inputs(arguments.build_inputs, lock_bytes)
    if valid_commit(arguments.source_commit, "source commit") != inputs["source_commit"]:
        fail("promotion source commit differs from the build input lock")
    image, image_sha = image_digest(arguments.image, "promoted image")
    issued = arguments.issued_at_unix_millis
    serial = arguments.promotion_serial
    generation = arguments.revocation_generation
    if (
        type(issued) is not int
        or type(serial) is not int
        or type(generation) is not int
        or issued <= 0
        or serial <= 0
        or generation <= 0
    ):
        fail("promotion serial, generation, or issuance is invalid")
    if (
        not isinstance(arguments.builder_id, str)
        or len(arguments.builder_id) > 512
        or not arguments.builder_id.startswith("https://")
        or not arguments.builder_id.isascii()
    ):
        fail("builder identity must be one bounded HTTPS URI")
    qualification = load_qualification(arguments.qualification, image, inputs)
    revocations = load_revocations(arguments.revocations, generation, issued)
    if image in revocations["revoked_images"]:
        fail("promoted image is revoked")

    output = arguments.output.resolve()
    if output.exists() or output.is_symlink():
        fail("refusing to overwrite promotion bundle")
    output.mkdir(parents=True, mode=0o700)
    try:
        subjects: dict[str, dict] = {
            "provenance": make_provenance(
                image,
                image_sha,
                lock,
                lock_bytes,
                inputs,
                arguments.builder_id,
                issued,
            ),
            "sbom": make_sbom(
                image, image_sha, lock, inputs, qualification, serial, issued
            ),
            "patch_report": {
                "image": image,
                "operating_system": qualification["os"],
                "profile_id": PROFILE_ID,
                "qualified_tool_sha256": {
                    tool["kind"]: tool["sha256"] for tool in qualification["tools"]
                },
                "schema_version": 1,
            },
            "revocations": {
                "expires_at_unix_millis": revocations["expires_at_unix_millis"],
                "generation": generation,
                "issued_at_unix_millis": revocations["issued_at_unix_millis"],
                "profile_id": PROFILE_ID,
                "revoked_images": revocations["revoked_images"],
                "schema_version": 1,
            },
        }
        subject_bytes = {
            kind: canonical_json(value) for kind, value in subjects.items()
        }
        references = {
            "provenance": reference_document(
                "provenance",
                image,
                sha256(subject_bytes["provenance"]),
                REFERENCE_STATEMENTS["provenance"],
            ),
            "sbom": reference_document(
                "sbom",
                image,
                sha256(subject_bytes["sbom"]),
                REFERENCE_STATEMENTS["sbom"],
            ),
            "patch_report": reference_document(
                "patch_report",
                image,
                sha256(subject_bytes["patch_report"]),
                REFERENCE_STATEMENTS["patch_report"],
            ),
            "revocations": reference_document(
                "revocations",
                image,
                sha256(subject_bytes["revocations"]),
                REFERENCE_STATEMENTS["revocations"],
                revocations,
            ),
        }
        reference_bytes = {
            kind: canonical_json(value) for kind, value in references.items()
        }
        manifest = {
            "architecture": "x86_64",
            "base_image": lock["base_image"],
            "clean_workspace": True,
            "evidence": {
                kind: {
                    "media_type": EVIDENCE_MEDIA_TYPE,
                    "sha256": sha256(reference_bytes[kind]),
                }
                for kind in ("provenance", "sbom", "patch_report", "revocations")
            },
            "guest_agent": r"C:\automata\guest\automata-ci-sandbox-guest.exe",
            "image": image,
            "isolation": "hyperv-container",
            "network_disabled": True,
            "operating_system": "windows-server-2025",
            "profile_id": PROFILE_ID,
            "schema_version": 1,
            "status": "candidate",
            "tools": qualification["tools"],
            "unprivileged": True,
            "variant": "server-core",
            "workspace": r"C:\__w",
        }
        manifest_bytes = canonical_json(manifest)
        image_lock = {
            "base_image": lock["base_image"],
            "image": image,
            "manifest_sha256": sha256(manifest_bytes),
            "profile_id": PROFILE_ID,
            "schema_version": 1,
        }
        image_lock_bytes = canonical_json(image_lock)
        payload = {
            "schema_version": 1,
            "decision": "promote",
            "profile_id": PROFILE_ID,
            "base_image": lock["base_image"],
            "image": image,
            "manifest_sha256": sha256(manifest_bytes),
            "lock_sha256": sha256(image_lock_bytes),
            "provenance_sha256": sha256(reference_bytes["provenance"]),
            "sbom_sha256": sha256(reference_bytes["sbom"]),
            "patch_report_sha256": sha256(reference_bytes["patch_report"]),
            "revocations_sha256": sha256(reference_bytes["revocations"]),
            "revocation_generation": generation,
            "provenance_accepted": True,
            "sbom_accepted": True,
            "patch_accepted": True,
            "revocations_accepted": True,
        }
        payload_bytes = compact_json(payload)

        for kind, filename in SUBJECT_FILENAMES.items():
            (output / filename).write_bytes(subject_bytes[kind])
        for kind, filename in REFERENCE_FILENAMES.items():
            (output / filename).write_bytes(reference_bytes[kind])
        (output / "manifest.json").write_bytes(manifest_bytes)
        (output / "image.lock.json").write_bytes(image_lock_bytes)
        (output / "promotion.payload.json").write_bytes(payload_bytes)
        (output / "build-inputs.json").write_bytes(canonical_json(inputs))
        (output / "sources.lock.json").write_bytes(lock_bytes)
        (output / "qualification.json").write_bytes(canonical_json(qualification))
    except BaseException:
        shutil.rmtree(output, ignore_errors=True)
        raise
    verify_bundle(output)
    print(f"manifest_sha256={sha256(manifest_bytes)}")
    print(f"lock_sha256={sha256(image_lock_bytes)}")
    print(f"promotion_payload_sha256={sha256(payload_bytes)}")


def verify_bundle(directory: pathlib.Path) -> dict:
    directory = directory.resolve()
    required = {
        "build-inputs.json",
        "image.lock.json",
        "manifest.json",
        "patch-report.json",
        "patch-report.subject.json",
        "promotion.payload.json",
        "provenance.intoto.json",
        "provenance.json",
        "qualification.json",
        "revocations.json",
        "revocations.subject.json",
        "sbom.spdx.json",
        "sbom.subject.spdx.json",
        "sources.lock.json",
    }
    entries = list(directory.iterdir())
    if any(not path.is_file() or path.is_symlink() for path in entries):
        fail("promotion bundle contains a non-regular entry")
    actual = {path.name for path in entries}
    allowed = required | {"promotion.envelope.json"}
    if not required.issubset(actual) or not actual.issubset(allowed):
        fail("promotion bundle file set differs")
    lock, lock_bytes = load_source_lock(directory / "sources.lock.json")
    inputs = load_build_inputs(directory / "build-inputs.json", lock_bytes)
    manifest_bytes = read_regular(directory / "manifest.json")
    manifest = exact_object(
        parse_json(manifest_bytes, "image manifest", canonical=True),
        {
            "architecture",
            "base_image",
            "clean_workspace",
            "evidence",
            "guest_agent",
            "image",
            "isolation",
            "network_disabled",
            "operating_system",
            "profile_id",
            "schema_version",
            "status",
            "tools",
            "unprivileged",
            "variant",
            "workspace",
        },
        "image manifest",
    )
    image, _ = image_digest(manifest["image"], "manifest image")
    qualification = load_qualification(
        directory / "qualification.json", image, inputs
    )
    if (
        manifest["schema_version"] != 1
        or manifest["status"] != "candidate"
        or manifest["profile_id"] != PROFILE_ID
        or manifest["base_image"] != lock["base_image"]
        or manifest["architecture"] != "x86_64"
        or manifest["operating_system"] != "windows-server-2025"
        or manifest["variant"] != "server-core"
        or manifest["isolation"] != "hyperv-container"
        or manifest["network_disabled"] is not True
        or manifest["unprivileged"] is not True
        or manifest["clean_workspace"] is not True
        or manifest["workspace"].lower() != r"c:\__w".lower()
        or manifest["guest_agent"].lower()
        != r"c:\automata\guest\automata-ci-sandbox-guest.exe".lower()
        or manifest["tools"] != qualification["tools"]
    ):
        fail("image manifest differs from the qualified profile")
    evidence = exact_object(
        manifest["evidence"], set(SUBJECT_FILENAMES), "manifest evidence"
    )
    reference_digests: dict[str, str] = {}
    subject_documents: dict[str, dict] = {}
    reference_documents: dict[str, dict] = {}
    for kind in SUBJECT_FILENAMES:
        subject_bytes = read_regular(directory / SUBJECT_FILENAMES[kind])
        subject_document = parse_json(
            subject_bytes, f"{kind} subject", canonical=True
        )
        if not isinstance(subject_document, dict):
            fail(f"{kind} subject is not a JSON object")
        reference_bytes = read_regular(directory / REFERENCE_FILENAMES[kind])
        reference = exact_object(
            parse_json(reference_bytes, f"{kind} reference", canonical=True),
            (
                {
                    "image",
                    "kind",
                    "profile_id",
                    "schema_version",
                    "statement",
                    "subject",
                }
                if kind != "revocations"
                else {
                    "generation",
                    "image",
                    "kind",
                    "profile_id",
                    "revoked_images",
                    "schema_version",
                    "statement",
                    "subject",
                }
            ),
            f"{kind} reference",
        )
        subject = exact_object(
            reference["subject"], {"media_type", "sha256"}, f"{kind} subject"
        )
        if (
            reference["schema_version"] != 1
            or reference["kind"] != kind
            or reference["profile_id"] != PROFILE_ID
            or reference["image"] != image
            or reference["statement"] != REFERENCE_STATEMENTS[kind]
            or subject["media_type"] != SUBJECT_MEDIA_TYPES[kind]
            or subject["sha256"] != sha256(subject_bytes)
            or evidence[kind]
            != {
                "media_type": EVIDENCE_MEDIA_TYPE,
                "sha256": sha256(reference_bytes),
            }
        ):
            fail(f"{kind} evidence binding differs")
        reference_digests[kind] = sha256(reference_bytes)
        subject_documents[kind] = subject_document
        reference_documents[kind] = reference
    image_lock_bytes = read_regular(directory / "image.lock.json")
    image_lock = exact_object(
        parse_json(image_lock_bytes, "image lock", canonical=True),
        {"base_image", "image", "manifest_sha256", "profile_id", "schema_version"},
        "image lock",
    )
    if image_lock != {
        "base_image": lock["base_image"],
        "image": image,
        "manifest_sha256": sha256(manifest_bytes),
        "profile_id": PROFILE_ID,
        "schema_version": 1,
    }:
        fail("image lock differs from the manifest")
    payload_bytes = read_regular(directory / "promotion.payload.json")
    payload_value = parse_json(payload_bytes, "promotion payload")
    if not isinstance(payload_value, dict) or tuple(payload_value) != PROMOTION_PAYLOAD_FIELDS:
        fail("promotion payload field order differs from the verifier contract")
    payload = exact_object(
        payload_value,
        set(PROMOTION_PAYLOAD_FIELDS),
        "promotion payload",
    )
    if compact_json(payload) != payload_bytes:
        fail("promotion payload is not canonical compact JSON")
    if (
        any(
            type(payload[name]) is not int
            for name in (
                "schema_version",
                "revocation_generation",
            )
        )
        or any(
            type(payload[name]) is not bool
            for name in (
                "provenance_accepted",
                "sbom_accepted",
                "patch_accepted",
                "revocations_accepted",
            )
        )
        or any(
            not isinstance(payload[name], str)
            for name in ("decision", "profile_id", "base_image", "image")
        )
    ):
        fail("promotion payload field types differ")
    for name in (
        "manifest_sha256",
        "lock_sha256",
        "provenance_sha256",
        "sbom_sha256",
        "patch_report_sha256",
        "revocations_sha256",
    ):
        valid_sha(payload[name], f"promotion payload {name}")
    if (
        payload["schema_version"] != 1
        or payload["decision"] != "promote"
        or payload["revocation_generation"] <= 0
        or payload["profile_id"] != PROFILE_ID
        or payload["base_image"] != lock["base_image"]
        or payload["image"] != image
        or payload["manifest_sha256"] != sha256(manifest_bytes)
        or payload["lock_sha256"] != sha256(image_lock_bytes)
        or payload["provenance_sha256"] != reference_digests["provenance"]
        or payload["sbom_sha256"] != reference_digests["sbom"]
        or payload["patch_report_sha256"] != reference_digests["patch_report"]
        or payload["revocations_sha256"] != reference_digests["revocations"]
        or payload["revocation_generation"]
        != reference_documents["revocations"]["generation"]
        or any(
            payload[name] is not True
            for name in (
                "provenance_accepted",
                "sbom_accepted",
                "patch_accepted",
                "revocations_accepted",
            )
        )
    ):
        fail("promotion payload differs from the evidence bundle")

    revocation_reference = reference_documents["revocations"]
    if (
        type(revocation_reference["generation"]) is not int
        or revocation_reference["generation"] <= 0
    ):
        fail("revocation evidence generation is invalid")
    revoked_images = revocation_reference["revoked_images"]
    if (
        not isinstance(revoked_images, list)
        or len(revoked_images) > 4096
        or revoked_images != sorted(set(revoked_images))
    ):
        fail("revocation evidence image set is not sorted and unique")
    for revoked_image in revoked_images:
        image_digest(revoked_image, "revoked image")
    if image in revoked_images:
        fail("promotion bundle targets a revoked image")

    provenance = subject_documents["provenance"]
    sbom = subject_documents["sbom"]
    try:
        started = provenance["predicate"]["runDetails"]["metadata"]["startedOn"]
        finished = provenance["predicate"]["runDetails"]["metadata"]["finishedOn"]
        created = sbom["creationInfo"]["created"]
    except (KeyError, TypeError):
        fail("evidence issuance timestamp is absent")
    if started != finished or started != created:
        fail("evidence issuance timestamps differ")
    issued = parse_timestamp(started, "evidence issuance")

    revocation_subject = exact_object(
        subject_documents["revocations"],
        {
            "expires_at_unix_millis",
            "generation",
            "issued_at_unix_millis",
            "profile_id",
            "revoked_images",
            "schema_version",
        },
        "revocation subject",
    )
    if (
        any(
            type(revocation_subject[name]) is not int
            for name in (
                "schema_version",
                "generation",
                "issued_at_unix_millis",
                "expires_at_unix_millis",
            )
        )
        or revocation_subject["schema_version"] != 1
        or revocation_subject["profile_id"] != PROFILE_ID
        or revocation_subject["generation"] != revocation_reference["generation"]
        or revocation_subject["revoked_images"] != revoked_images
        or revocation_subject["issued_at_unix_millis"] <= 0
        or revocation_subject["expires_at_unix_millis"]
        <= revocation_subject["issued_at_unix_millis"]
        or revocation_subject["issued_at_unix_millis"] > issued
        or revocation_subject["expires_at_unix_millis"] <= issued
    ):
        fail("revocation subject differs or has an invalid validity window")

    _, image_sha = image_digest(image, "promoted image")
    try:
        namespace = sbom["documentNamespace"]
    except (KeyError, TypeError):
        fail("SBOM document namespace is absent")
    namespace_prefix = f"https://automata.dev/spdx/windows-2025/{image_sha}/"
    if not isinstance(namespace, str) or not namespace.startswith(namespace_prefix):
        fail("SBOM document namespace differs")
    serial_text = namespace.removeprefix(namespace_prefix)
    if not serial_text.isascii() or not serial_text.isdecimal():
        fail("SBOM promotion serial is invalid")
    serial = int(serial_text)
    if serial <= 0 or str(serial) != serial_text:
        fail("SBOM promotion serial is invalid")
    try:
        builder_id = provenance["predicate"]["runDetails"]["builder"]["id"]
    except (KeyError, TypeError):
        fail("provenance builder identity is absent")
    if (
        not isinstance(builder_id, str)
        or not builder_id.startswith("https://")
        or not builder_id.isascii()
        or len(builder_id) > 512
    ):
        fail("provenance builder identity is invalid")
    expected_subjects = {
        "provenance": make_provenance(
            image,
            image_sha,
            lock,
            lock_bytes,
            inputs,
            builder_id,
            issued,
        ),
        "sbom": make_sbom(
            image,
            image_sha,
            lock,
            inputs,
            qualification,
            serial,
            issued,
        ),
        "patch_report": {
            "image": image,
            "operating_system": qualification["os"],
            "profile_id": PROFILE_ID,
            "qualified_tool_sha256": {
                tool["kind"]: tool["sha256"] for tool in qualification["tools"]
            },
            "schema_version": 1,
        },
        "revocations": {
            "expires_at_unix_millis": revocation_subject[
                "expires_at_unix_millis"
            ],
            "generation": revocation_reference["generation"],
            "issued_at_unix_millis": revocation_subject[
                "issued_at_unix_millis"
            ],
            "profile_id": PROFILE_ID,
            "revoked_images": revoked_images,
            "schema_version": 1,
        },
    }
    if subject_documents != expected_subjects:
        fail("typed evidence subject differs from the deterministic recipe")
    return payload


def verify_command(arguments: argparse.Namespace) -> None:
    payload = verify_bundle(arguments.bundle)
    print(f"revocation_generation={payload['revocation_generation']}")
    print(
        "promotion_payload_sha256="
        + sha256(read_regular(arguments.bundle / "promotion.payload.json"))
    )


def sign(arguments: argparse.Namespace) -> None:
    payload = verify_bundle(arguments.bundle)
    if not IDENTIFIER.fullmatch(arguments.key_id):
        fail("promotion key ID is invalid")
    if not KEY_HANDLE.fullmatch(arguments.key_handle):
        fail("opaque signer key handle is invalid")
    if not arguments.signer.is_absolute():
        fail("signer executable must be absolute")
    signer = arguments.signer.resolve()
    signer_bytes = read_regular(signer, MAX_ARTIFACT_BYTES)
    if sha256(signer_bytes) != valid_sha(arguments.signer_sha256, "signer executable"):
        fail("signer executable differs from its reviewed digest")
    payload_path = arguments.bundle.resolve() / "promotion.payload.json"
    payload_bytes = read_regular(payload_path)
    if compact_json(payload) != payload_bytes:
        fail("promotion payload changed after verification")
    output = pathlib.Path(os.path.abspath(arguments.output))
    if output.exists() or output.is_symlink():
        fail("refusing to overwrite promotion envelope")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix="windows-image-sign-") as temporary:
        temporary_path = pathlib.Path(temporary)
        staged_signer = temporary_path / (
            "signer.exe" if os.name == "nt" else "signer"
        )
        staged_payload = temporary_path / "promotion.payload.json"
        signature_path = temporary_path / "signature.bin"
        write_new_regular(staged_signer, signer_bytes, 0o500, "signer snapshot")
        write_new_regular(staged_payload, payload_bytes, 0o400, "payload snapshot")
        environment = {
            name: os.environ[name]
            for name in ("SystemRoot", "WINDIR", "TEMP", "TMP")
            if name in os.environ
        }
        with retain_exact_regular(
            staged_signer, signer_bytes, MAX_ARTIFACT_BYTES
        ) as signer_stream, retain_exact_regular(
            staged_payload, payload_bytes, MAX_JSON_BYTES
        ) as payload_stream:
            try:
                result = subprocess.run(
                    [
                        str(staged_signer),
                        "sign-windows-image-v1",
                        "--key-handle",
                        arguments.key_handle,
                        "--payload",
                        str(staged_payload),
                        "--payload-sha256",
                        sha256(payload_bytes),
                        "--signature-output",
                        str(signature_path),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=environment,
                    check=False,
                    timeout=60,
                )
            except (OSError, subprocess.TimeoutExpired):
                fail("external promotion signer failed")
            if result.returncode != 0 or result.stdout or result.stderr:
                fail("external promotion signer returned an invalid result")
            signature = read_regular(signature_path, 64)
            if len(signature) != 64 or signature == bytes(64):
                fail("external promotion signature is invalid")
            if (
                read_open_regular(
                    signer_stream, staged_signer, MAX_ARTIFACT_BYTES
                )
                != signer_bytes
            ):
                fail("signer snapshot changed during signing")
            if (
                read_open_regular(payload_stream, staged_payload, MAX_JSON_BYTES)
                != payload_bytes
            ):
                fail("payload snapshot changed during signing")
            envelope_bytes = canonical_json(
                {
                    "key_id": arguments.key_id,
                    "payload_base64": base64.b64encode(payload_bytes).decode(),
                    "schema_version": 1,
                    "signature_base64": base64.b64encode(signature).decode(),
                }
            )
            write_new_regular(output, envelope_bytes, 0o600, "promotion envelope")
    print(f"promotion_envelope_sha256={sha256(envelope_bytes)}")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate-lock")
    validate.add_argument("--lock", required=True, type=pathlib.Path)
    validate.set_defaults(handler=lambda arguments: load_source_lock(arguments.lock))

    context = commands.add_parser("prepare-context")
    context.add_argument("--lock", required=True, type=pathlib.Path)
    context.add_argument("--recipe-directory", required=True, type=pathlib.Path)
    context.add_argument("--source-tree", required=True, type=pathlib.Path)
    context.add_argument("--guest-agent", required=True, type=pathlib.Path)
    context.add_argument("--guest-agent-sha256", required=True)
    context.add_argument("--hash-helper", required=True, type=pathlib.Path)
    context.add_argument("--hash-helper-sha256", required=True)
    context.add_argument("--source-commit", required=True)
    context.add_argument("--artifact-directory", type=pathlib.Path)
    context.add_argument("--output", required=True, type=pathlib.Path)
    context.set_defaults(handler=prepare_context)

    evidence = commands.add_parser("assemble")
    evidence.add_argument("--lock", required=True, type=pathlib.Path)
    evidence.add_argument("--build-inputs", required=True, type=pathlib.Path)
    evidence.add_argument("--qualification", required=True, type=pathlib.Path)
    evidence.add_argument("--revocations", required=True, type=pathlib.Path)
    evidence.add_argument("--image", required=True)
    evidence.add_argument("--source-commit", required=True)
    evidence.add_argument("--builder-id", required=True)
    evidence.add_argument("--issued-at-unix-millis", required=True, type=int)
    evidence.add_argument("--promotion-serial", required=True, type=int)
    evidence.add_argument("--revocation-generation", required=True, type=int)
    evidence.add_argument("--output", required=True, type=pathlib.Path)
    evidence.set_defaults(handler=assemble)

    verify = commands.add_parser("verify-bundle")
    verify.add_argument("--bundle", required=True, type=pathlib.Path)
    verify.set_defaults(handler=verify_command)

    promote = commands.add_parser("sign")
    promote.add_argument("--bundle", required=True, type=pathlib.Path)
    promote.add_argument("--key-id", required=True)
    promote.add_argument("--key-handle", required=True)
    promote.add_argument("--signer", required=True, type=pathlib.Path)
    promote.add_argument("--signer-sha256", required=True)
    promote.add_argument("--output", required=True, type=pathlib.Path)
    promote.set_defaults(handler=sign)
    return root


def main() -> None:
    arguments = parser().parse_args()
    arguments.handler(arguments)


if __name__ == "__main__":
    main()
