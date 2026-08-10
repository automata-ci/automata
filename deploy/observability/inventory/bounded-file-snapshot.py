#!/usr/bin/env python3
"""Copy one stable, bounded regular file to stdout without following symlinks."""

from __future__ import annotations

import os
import stat
import sys
from typing import NoReturn


def fail(message: str) -> NoReturn:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def stable_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def write_all(data: bytes) -> None:
    output = sys.stdout.fileno()
    offset = 0
    while offset < len(data):
        offset += os.write(output, data[offset:])


def main() -> None:
    if len(sys.argv) != 3:
        fail(f"usage: {os.path.basename(sys.argv[0])} SOURCE MAXIMUM_BYTES")

    source = sys.argv[1]
    try:
        maximum_bytes = int(sys.argv[2], 10)
    except ValueError:
        fail("maximum snapshot size must be a positive integer")
    if maximum_bytes <= 0:
        fail("maximum snapshot size must be a positive integer")

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW
    try:
        descriptor = os.open(source, flags)
    except OSError:
        fail("input could not be opened as a non-symlink file")

    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            fail("input must be a regular file")
        if before.st_size <= 0 or before.st_size > maximum_bytes:
            fail("input size is outside the bounded policy")

        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
    except OSError:
        fail("input changed or could not be read completely")
    finally:
        os.close(descriptor)

    if len(data) == 0 or len(data) > maximum_bytes or len(data) != before.st_size:
        fail("input size changed while it was being snapshotted")
    if stable_identity(before) != stable_identity(after):
        fail("input metadata changed while it was being snapshotted")
    write_all(data)


if __name__ == "__main__":
    main()
