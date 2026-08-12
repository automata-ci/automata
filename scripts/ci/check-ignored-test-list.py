#!/usr/bin/env python3
"""Validate the ignored tests selected by a coverage command."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


IGNORED_FUNCTION = re.compile(
    r"#\s*\[\s*ignore(?:[^\]]*)\]\s*"
    r"(?:(?:#\s*\[[^\]]*\]\s*)|(?:pub(?:\([^)]*\))?\s+))*"
    r"(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.MULTILINE,
)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--bundle")
    parser.add_argument("--source", type=Path)
    arguments = parser.parse_args()
    exact_options = [arguments.policy, arguments.bundle, arguments.source]
    if any(option is not None for option in exact_options) and not all(
        option is not None for option in exact_options
    ):
        parser.error("--policy, --bundle, and --source must be supplied together")
    return arguments


def exact_expected_tests(
    policy_path: Path, bundle: str, source_path: Path
) -> list[str]:
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    try:
        exact_bundles = policy["ignored_test_inventory"]["exact_test_bundles"]
        expected = exact_bundles[bundle][source_path.as_posix()]
    except (KeyError, TypeError) as error:
        raise ValueError(
            f"coverage policy has no exact ignored-test inventory for "
            f"{bundle}:{source_path.as_posix()}"
        ) from error
    if (
        not isinstance(expected, list)
        or not expected
        or any(not isinstance(name, str) or not name for name in expected)
        or len(expected) != len(set(expected))
    ):
        raise ValueError("exact ignored-test inventory must contain unique test names")

    expected_functions = []
    for name in expected:
        match = re.search(r"(?:^|::)([A-Za-z_][A-Za-z0-9_]*)$", name)
        if match is None:
            raise ValueError(f"invalid inventoried ignored test name: {name}")
        expected_functions.append(match.group(1))
    if len(expected_functions) != len(set(expected_functions)):
        raise ValueError("inventoried ignored tests must have unique function names per source")

    ignored_functions = IGNORED_FUNCTION.findall(
        source_path.read_text(encoding="utf-8")
    )
    if len(ignored_functions) != len(set(ignored_functions)):
        raise ValueError("ignored test function names must be unique within an exact source")
    if set(ignored_functions) != set(expected_functions):
        missing = sorted(set(ignored_functions) - set(expected_functions))
        stale = sorted(set(expected_functions) - set(ignored_functions))
        raise ValueError(
            "exact ignored-test source inventory differs"
            f" (missing from policy: {missing}; absent from source: {stale})"
        )
    return expected


def main() -> int:
    arguments = parse_arguments()
    selected = [
        line.removesuffix(": test")
        for line in sys.stdin.read().splitlines()
        if line.endswith(": test")
    ]
    if not selected:
        print("error: ignored coverage command selected zero tests", file=sys.stderr)
        return 2
    # A package-wide Cargo listing can contain the same unqualified function
    # name in separate integration-test binaries. That is still two selected
    # tests. Exact single-source inventories, however, must remain unique.
    if arguments.policy is not None and len(selected) != len(set(selected)):
        raise ValueError("ignored coverage command listed a test more than once")
    if arguments.policy is not None:
        expected = exact_expected_tests(
            arguments.policy, arguments.bundle, arguments.source
        )
        if set(selected) != set(expected):
            missing = sorted(set(expected) - set(selected))
            unexpected = sorted(set(selected) - set(expected))
            raise ValueError(
                "ignored coverage selection differs from its exact inventory"
                f" (missing: {missing}; unexpected: {unexpected})"
            )
    print(len(selected))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2) from error
