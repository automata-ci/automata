#!/usr/bin/env python3
"""Verify repository-owned Markdown structure and local links."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXCLUDED_PREFIXES = (
    "ui/renderer/vendor/",
    "crates/automata-ci-oidc-github/tests/fixtures/actions-core-3.0.1/",
)
LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*#*$")
FENCE = re.compile(r"^\s*(```|~~~)")
RESIDUE = {
    "assistant citation token": re.compile(r"\bturn\d+(?:search|fetch|view)\d+\b"),
    "content-reference token": re.compile(r"\b(?:contentReference|oaicite)\b"),
}


def tracked_markdown() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.md"],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
    )
    relative_paths = result.stdout.decode("utf-8").split("\0")
    return [
        REPOSITORY_ROOT / relative
        for relative in relative_paths
        if relative and not relative.startswith(EXCLUDED_PREFIXES)
    ]


def visible_lines(path: Path) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    fence_marker: str | None = None
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = FENCE.match(line)
        if match:
            marker = match.group(1)
            if fence_marker is None:
                fence_marker = marker
            elif marker == fence_marker:
                fence_marker = None
            continue
        if fence_marker is None:
            lines.append((number, line))
    return lines


def github_anchor(title: str) -> str:
    title = re.sub(r"<[^>]+>", "", title).strip().lower()
    title = re.sub(r"[^\w\- ]", "", title, flags=re.UNICODE)
    return re.sub(r" +", "-", title)


def headings(path: Path) -> list[tuple[int, int, str]]:
    found: list[tuple[int, int, str]] = []
    for number, line in visible_lines(path):
        match = HEADING.match(line)
        if match:
            found.append((number, len(match.group(1)), github_anchor(match.group(2))))
    return found


def destination_path(source: Path, destination: str) -> tuple[Path, str] | None:
    destination = destination.strip().split(maxsplit=1)[0].strip("<>")
    if destination.startswith(("http://", "https://", "mailto:")):
        return None
    path_text, separator, fragment = destination.partition("#")
    target = source if not path_text else source.parent / unquote(path_text)
    return target.resolve(), unquote(fragment) if separator else ""


def main() -> int:
    files = tracked_markdown()
    known_headings = {
        path.resolve(): {anchor for _, _, anchor in headings(path)} for path in files
    }
    failures: list[str] = []

    for path in files:
        relative = path.relative_to(REPOSITORY_ROOT)
        page_headings = headings(path)
        seen: dict[str, int] = {}
        previous_level = 0
        for number, level, anchor in page_headings:
            if anchor in seen:
                failures.append(
                    f"{relative}:{number}: duplicate heading also used on line {seen[anchor]}"
                )
            else:
                seen[anchor] = number
            if previous_level and level > previous_level + 1:
                failures.append(
                    f"{relative}:{number}: heading jumps from level {previous_level} to {level}"
                )
            previous_level = level

        for number, line in visible_lines(path):
            for label, pattern in RESIDUE.items():
                if pattern.search(line):
                    failures.append(f"{relative}:{number}: contains {label}")
            for raw_destination in LINK.findall(line):
                resolved = destination_path(path.resolve(), raw_destination)
                if resolved is None:
                    continue
                target, fragment = resolved
                if not target.exists():
                    failures.append(
                        f"{relative}:{number}: missing local link target {raw_destination}"
                    )
                    continue
                if fragment and target in known_headings:
                    if fragment not in known_headings[target]:
                        failures.append(
                            f"{relative}:{number}: missing local anchor {raw_destination}"
                        )

    if failures:
        for failure in failures:
            print(f"error: {failure}", file=sys.stderr)
        return 1

    print(f"documentation links and structure verified ({len(files)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
