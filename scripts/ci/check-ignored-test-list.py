#!/usr/bin/env python3
"""Require a captured libtest listing to contain at least one selected test."""

from __future__ import annotations

import sys


def main() -> int:
    selected = sum(line.endswith(": test") for line in sys.stdin.read().splitlines())
    if selected == 0:
        print("error: ignored coverage command selected zero tests", file=sys.stderr)
        return 2
    print(selected)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
