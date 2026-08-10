#!/usr/bin/env python3
"""Fail closed when a GitHub Release would overlap or move backwards."""

from __future__ import annotations

import argparse
import json
import re
import sys
from typing import NoReturn


STABLE_TAG = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)


def fail(message: str) -> NoReturn:
    raise SystemExit(f"release-order: {message}")


def parse_pages() -> list[dict]:
    try:
        pages = json.load(sys.stdin)
    except (OSError, json.JSONDecodeError) as error:
        fail(f"invalid GitHub Releases response: {error}")
    if not isinstance(pages, list) or any(not isinstance(page, list) for page in pages):
        fail("GitHub Releases response must be a list of pages")
    releases: list[dict] = []
    for page in pages:
        for release in page:
            if not isinstance(release, dict):
                fail("GitHub Releases response contains a non-object release")
            releases.append(release)
    return releases


def release_identity(release: dict) -> tuple[str, bool, bool]:
    tag = release.get("tag_name")
    draft = release.get("draft")
    prerelease = release.get("prerelease")
    if not isinstance(tag, str) or not tag:
        fail("GitHub Releases response contains an invalid tag name")
    if not isinstance(draft, bool) or not isinstance(prerelease, bool):
        fail(f"GitHub Releases response contains invalid state for {tag}")
    return tag, draft, prerelease


def stable_version(tag: str) -> tuple[int, int, int]:
    match = STABLE_TAG.fullmatch(tag)
    if match is None:
        fail(f"published stable release tag is not canonical: {tag}")
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def validate(
    releases: list[dict], requested_tag: str, version: str, prerelease: bool
) -> None:
    if requested_tag != f"v{version}":
        fail("requested tag does not match the release version")

    identities = [release_identity(release) for release in releases]
    tags = [tag for tag, _, _ in identities]
    if len(tags) != len(set(tags)):
        fail("GitHub Releases response contains duplicate tags")

    other_drafts = sorted(
        tag for tag, draft, _ in identities if draft and tag != requested_tag
    )
    if other_drafts:
        fail(f"unfinished release draft must be resolved first: {other_drafts[0]}")
    if any(tag == requested_tag and not draft for tag, draft, _ in identities):
        fail(f"release {requested_tag} is already public and immutable")
    if prerelease:
        return

    current = stable_version(requested_tag)
    published_stable = [
        (stable_version(tag), tag)
        for tag, draft, is_prerelease in identities
        if not draft and not is_prerelease
    ]
    newer = [item for item in published_stable if item[0] > current]
    if newer:
        _, newest_tag = max(newer)
        fail(f"refusing to publish {requested_tag} after newer stable release {newest_tag}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--requested-tag", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--prerelease", required=True, choices=("true", "false"))
    arguments = parser.parse_args()
    validate(
        parse_pages(),
        requested_tag=arguments.requested_tag,
        version=arguments.version,
        prerelease=arguments.prerelease == "true",
    )


if __name__ == "__main__":
    main()
