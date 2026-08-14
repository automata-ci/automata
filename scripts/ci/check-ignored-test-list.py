#!/usr/bin/env python3
"""Validate that a coverage command selects at least one ignored test."""

from __future__ import annotations

import sys


def main() -> int:
    selected = [
        line.removesuffix(": test")
        for line in sys.stdin.read().splitlines()
        if line.endswith(": test")
    ]
    if not selected:
        print("error: ignored coverage command selected zero tests", file=sys.stderr)
        return 2
    print(len(selected))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
