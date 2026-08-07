#!/usr/bin/env python3
"""Reject Cargo path packages outside the generated renderer workspace."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys


def verify(workspace: pathlib.Path, metadata_path: pathlib.Path) -> None:
    workspace = workspace.resolve()
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    outside = []
    for package in metadata["packages"]:
        if package["source"] is not None:
            continue
        manifest = pathlib.Path(package["manifest_path"]).resolve()
        try:
            manifest.relative_to(workspace)
        except ValueError:
            outside.append(f"{package['name']} ({manifest})")

    if outside:
        raise ValueError(
            "renderer path packages must be inside the wrapper workspace: "
            + ", ".join(sorted(outside))
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("workspace", type=pathlib.Path)
    parser.add_argument("metadata", type=pathlib.Path)
    arguments = parser.parse_args()
    try:
        verify(arguments.workspace, arguments.metadata)
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
