#!/usr/bin/env python3
"""Run one command while holding a nonblocking POSIX advisory file lock."""

from __future__ import annotations

import argparse
import fcntl
import os
import stat
import subprocess


def fail(message: str) -> None:
    raise SystemExit(f"error: {message}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--conflict-exit-code", type=int, required=True)
    parser.add_argument("--lock-file", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    if not 1 <= arguments.conflict_exit_code <= 255:
        fail("conflict exit code must be between 1 and 255")
    if arguments.command and arguments.command[0] == "--":
        arguments.command.pop(0)
    if not arguments.command:
        fail("command is required")

    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(arguments.lock_file, flags, 0o644)
    except OSError as error:
        fail(f"could not open lock file: {error}")
    with os.fdopen(descriptor, "r+") as lock_file:
        metadata = os.fstat(lock_file.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            fail("lock file must be a singly linked regular file")
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit(arguments.conflict_exit_code) from None
        completed = subprocess.run(arguments.command, check=False)
    if completed.returncode < 0:
        raise SystemExit(128 - completed.returncode)
    raise SystemExit(completed.returncode)


if __name__ == "__main__":
    main()
