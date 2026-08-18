#!/usr/bin/env python3
"""Fingerprint every tracked or unignored workspace file plus Git HEAD."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True, type=Path)
    return parser.parse_args()


def git(repository: Path, *arguments: str) -> bytes:
    try:
        return subprocess.check_output(
            ["git", "-C", str(repository), *arguments], stderr=subprocess.PIPE
        )
    except subprocess.CalledProcessError as error:
        diagnostic = error.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"git {' '.join(arguments)} failed: {diagnostic}") from error


def framed(digest: Any, value: bytes) -> None:
    digest.update(len(value).to_bytes(8, byteorder="big"))
    digest.update(value)


def stable_metadata(initial: os.stat_result, final: os.stat_result) -> bool:
    fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    return all(getattr(initial, field) == getattr(final, field) for field in fields)


def regular_file_digest(path: Path, initial: os.stat_result) -> bytes:
    content = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as source:
        opened = os.fstat(source.fileno())
        if not stable_metadata(initial, opened) or not stat.S_ISREG(opened.st_mode):
            raise ValueError(f"workspace file changed before fingerprinting: {path}")
        for block in iter(lambda: source.read(1024 * 1024), b""):
            content.update(block)
        closed = os.fstat(source.fileno())
    final = os.stat(path, follow_symlinks=False)
    if not stable_metadata(initial, closed) or not stable_metadata(initial, final):
        raise ValueError(f"workspace file changed while fingerprinting: {path}")
    return content.digest()


def main() -> int:
    arguments = parse_arguments()
    repository = arguments.repository.resolve()
    if not repository.is_dir():
        raise ValueError(f"repository is not a directory: {repository}")
    top_level = Path(
        git(repository, "rev-parse", "--show-toplevel").decode("utf-8").strip()
    ).resolve()
    if top_level != repository:
        raise ValueError(f"repository must be the Git top level: {repository}")
    head = git(repository, "rev-parse", "--verify", "HEAD").decode("ascii").strip()
    if not head or any(character not in "0123456789abcdef" for character in head):
        raise ValueError("Git HEAD is not a lowercase hexadecimal object ID")

    raw_paths = git(
        repository,
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
    ).split(b"\0")
    paths = sorted(path for path in raw_paths if path)
    if len(paths) != len(set(paths)):
        raise ValueError("Git returned a duplicate workspace path")

    content_snapshot = hashlib.sha256()
    state_token = hashlib.sha256()
    framed(content_snapshot, b"automata-ci-workspace-content-v1")
    framed(state_token, b"automata-ci-workspace-state-v1")
    for digest in (content_snapshot, state_token):
        framed(digest, head.encode("ascii"))
    for raw_path in paths:
        if raw_path.startswith(b"/") or b"\0" in raw_path:
            raise ValueError("Git returned an invalid workspace path")
        relative = Path(os.fsdecode(raw_path))
        if ".." in relative.parts:
            raise ValueError("Git returned a traversing workspace path")
        path = repository / relative
        for digest in (content_snapshot, state_token):
            framed(digest, raw_path)
        try:
            metadata = os.stat(path, follow_symlinks=False)
        except FileNotFoundError:
            for digest in (content_snapshot, state_token):
                framed(digest, b"missing")
            continue
        mode = stat.S_IMODE(metadata.st_mode)
        for digest in (content_snapshot, state_token):
            framed(digest, f"{mode:04o}".encode("ascii"))
        framed(state_token, str(metadata.st_mtime_ns).encode("ascii"))
        framed(state_token, str(metadata.st_ctime_ns).encode("ascii"))
        if stat.S_ISREG(metadata.st_mode):
            file_digest = regular_file_digest(path, metadata)
            for digest in (content_snapshot, state_token):
                framed(digest, b"regular")
                framed(digest, str(metadata.st_size).encode("ascii"))
                framed(digest, file_digest)
        elif stat.S_ISLNK(metadata.st_mode):
            for digest in (content_snapshot, state_token):
                framed(digest, b"symlink")
            target = os.fsencode(os.readlink(path))
            final = os.stat(path, follow_symlinks=False)
            if not stable_metadata(metadata, final):
                raise ValueError(f"workspace symlink changed while fingerprinting: {path}")
            for digest in (content_snapshot, state_token):
                framed(digest, target)
        else:
            raise ValueError(f"unsupported nonignored workspace entry: {relative}")

    final_head = git(repository, "rev-parse", "--verify", "HEAD").decode("ascii").strip()
    final_paths = sorted(
        path
        for path in git(
            repository,
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ).split(b"\0")
        if path
    )
    if final_head != head or final_paths != paths:
        raise ValueError("workspace identity changed while fingerprinting")

    print(
        f"{head} {content_snapshot.hexdigest()} {state_token.hexdigest()} {len(paths)}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2) from error
