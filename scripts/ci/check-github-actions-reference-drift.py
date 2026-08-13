#!/usr/bin/env python3
"""Compare the reviewed GitHub Actions catalog with current upstream sources."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import date
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT = Path("docs/governance/github-actions-reference-snapshot-v1.json")
RAW_URL = re.compile(
    r"https://raw\.githubusercontent\.com/"
    r"(?P<owner>[^/]+)/(?P<repository>[^/]+)/(?P<revision>[0-9a-f]{40})/"
    r"(?P<path>.+)"
)
MAX_SOURCE_BYTES = 1_048_576
MAX_CHANGES = 32


class DriftError(RuntimeError):
    """A source could not be checked safely."""


def request_bytes(url: str) -> bytes:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "automata-github-actions-reference-detector/1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read(MAX_SOURCE_BYTES + 1)
    except (OSError, urllib.error.HTTPError, urllib.error.URLError) as error:
        raise DriftError(f"cannot retrieve {url}: {error}") from error
    if len(body) > MAX_SOURCE_BYTES:
        raise DriftError(f"source exceeds {MAX_SOURCE_BYTES} bytes: {url}")
    return body


def request_json(url: str) -> dict[str, Any]:
    try:
        value = json.loads(request_bytes(url))
    except (json.JSONDecodeError, UnicodeError) as error:
        raise DriftError(f"GitHub returned invalid JSON for {url}: {error}") from error
    if not isinstance(value, dict):
        raise DriftError(f"GitHub returned a non-object for {url}")
    return value


def commit_for(owner: str, repository: str, revision: str) -> str:
    encoded = urllib.parse.quote(revision, safe="")
    value = request_json(
        f"https://api.github.com/repos/{owner}/{repository}/commits/{encoded}"
    )
    commit = value.get("sha")
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise DriftError(f"GitHub did not return an immutable commit for {owner}/{repository}")
    return commit


def current_revisions(snapshot: dict[str, Any]) -> tuple[dict[str, str], str]:
    revisions = {"github/docs": commit_for("github", "docs", "main")}
    release = request_json("https://api.github.com/repos/actions/runner/releases/latest")
    tag = release.get("tag_name")
    if not isinstance(tag, str) or re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag) is None:
        raise DriftError("latest actions/runner release has an unexpected tag")
    revisions["actions/runner"] = commit_for("actions", "runner", tag)
    if snapshot.get("runner", {}).get("repository") != "actions/runner":
        raise DriftError("snapshot runner repository is unsupported")
    return revisions, tag


def compare(snapshot: dict[str, Any]) -> dict[str, Any]:
    if snapshot.get("schema_version") != 1:
        raise DriftError("unsupported reference snapshot schema")
    references = snapshot.get("reference_groups")
    if not isinstance(references, list) or not references:
        raise DriftError("reference snapshot has no sources")

    revisions, runner_release = current_revisions(snapshot)
    changes: list[dict[str, Any]] = []
    for reference in references:
        if not isinstance(reference, dict):
            raise DriftError("reference source is not an object")
        match = RAW_URL.fullmatch(str(reference.get("url", "")))
        if match is None:
            raise DriftError(f"reference URL is not immutable: {reference.get('id')}")
        repository = f"{match['owner']}/{match['repository']}"
        if repository not in revisions:
            raise DriftError(f"reference repository is not reviewed: {repository}")

        baseline_body = request_bytes(match.group(0))
        baseline_digest = hashlib.sha256(baseline_body).hexdigest()
        if baseline_digest != reference.get("sha256") or len(baseline_body) != reference.get("bytes"):
            raise DriftError(f"pinned source no longer matches snapshot: {reference.get('id')}")

        latest_url = (
            f"https://raw.githubusercontent.com/{repository}/"
            f"{revisions[repository]}/{match['path']}"
        )
        latest_digest = hashlib.sha256(request_bytes(latest_url)).hexdigest()
        if latest_digest != baseline_digest:
            changes.append(
                {
                    "baseline_sha256": baseline_digest,
                    "categories": reference["categories"],
                    "id": reference["id"],
                    "latest_sha256": latest_digest,
                    "latest_url": latest_url,
                }
            )

    baseline_release = snapshot["runner"]["baseline_release"]
    if runner_release != baseline_release:
        changes.append(
            {
                "baseline_release": baseline_release,
                "categories": ["action_runtimes"],
                "id": "actions-runner-release",
                "latest_release": runner_release,
                "latest_url": f"https://github.com/actions/runner/releases/tag/{runner_release}",
            }
        )
    if len(changes) > MAX_CHANGES:
        raise DriftError("upstream diff exceeds the bounded report size")
    return {
        "baseline_catalog": snapshot["catalog_version"],
        "checked_on": date.today().isoformat(),
        "changes": changes,
        "observed": {
            "actions_runner_commit": revisions["actions/runner"],
            "actions_runner_release": runner_release,
            "github_docs_commit": revisions["github/docs"],
        },
        "schema_version": 1,
    }


def markdown(report: dict[str, Any]) -> str:
    lines = [
        "## GitHub Actions reference drift",
        "",
        f"Baseline catalog: `{report['baseline_catalog']}`",
        f"Checked on: `{report['checked_on']}`",
        "",
    ]
    changes = report["changes"]
    if not changes:
        lines.append("No reviewed source or runner-release drift was detected.")
    else:
        lines.extend(
            [
                "A human-reviewed replacement is required. Do not update pins from this issue alone.",
                "",
            ]
        )
        for change in changes:
            categories = ", ".join(change["categories"])
            lines.append(f"- `{change['id']}` ({categories}): {change['latest_url']}")
    lines.extend(
        [
            "",
            "Follow `docs/governance/github-actions-capabilities.md` and record two reviewers before replacing the snapshot.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, default=ROOT)
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, required=True)
    args = parser.parse_args()
    root = args.repository_root.resolve()
    snapshot_path = args.snapshot.resolve() if args.snapshot else root / SNAPSHOT
    output = args.output if args.output.is_absolute() else root / args.output
    markdown_path = args.markdown if args.markdown.is_absolute() else root / args.markdown
    for path, label in ((output, "JSON output"), (markdown_path, "Markdown output")):
        try:
            path.resolve().relative_to(root)
        except ValueError:
            print(f"error: {label} must stay within the repository", file=sys.stderr)
            return 1
        if path.parent.resolve() != root and not path.parent.is_dir():
            print(f"error: {label} parent directory does not exist", file=sys.stderr)
            return 1
    try:
        snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
        report = compare(snapshot)
    except (DriftError, OSError, UnicodeError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(markdown(report), encoding="utf-8")
    if report["changes"]:
        print(f"detected {len(report['changes'])} reviewed-source changes")
        return 2
    print("no GitHub Actions reference drift detected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
