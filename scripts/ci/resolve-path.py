#!/usr/bin/env python3
"""Resolve one path with consistent Linux and macOS semantics."""

from __future__ import annotations

import argparse
import os
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"error: {message}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--existing", action="store_true")
    parser.add_argument("path")
    arguments = parser.parse_args()

    if "\n" in arguments.path or "\r" in arguments.path:
        fail("path must not contain a line ending")
    try:
        resolved = Path(arguments.path).resolve(strict=arguments.existing)
    except (OSError, RuntimeError) as error:
        fail(f"could not resolve path: {error}")
    if arguments.existing and not resolved.exists():
        fail("path does not exist")
    encoded = os.fsencode(resolved)
    if b"\n" in encoded or b"\r" in encoded:
        fail("resolved path must not contain a line ending")
    print(os.fsdecode(encoded))


if __name__ == "__main__":
    main()
