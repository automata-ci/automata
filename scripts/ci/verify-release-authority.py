#!/usr/bin/env python3
"""Verify Automata revision CI for a release commit contained in main."""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse


APP_ID = 4_558_711
APP_OWNER = "automata-ci"
APP_SLUG = "automata-ci"
CHECK_NAME = "Automata CI / .ci/workflows/ci.yml"
DASHBOARD_ORIGIN = "https://ci.automata-ci.com"
EXTERNAL_ID = re.compile(
    r"automata-check:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}"
)
GIT_SHA = re.compile(r"[0-9a-f]{40}")


def fail(message: str) -> None:
    raise SystemExit(f"release-authority: {message}")


def load_document(path: str, label: str) -> dict:
    try:
        with open(path, encoding="utf-8") as source:
            document = json.load(source)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot read {label}: {error}")
    if not isinstance(document, dict):
        fail(f"{label} is not a JSON object")
    return document


def verify_main_ancestry(comparison: dict, commit: str) -> None:
    status = comparison.get("status")
    merge_base = comparison.get("merge_base_commit")
    if status not in {"ahead", "identical"}:
        fail("the release commit is not an ancestor of the current main branch")
    if not isinstance(merge_base, dict) or merge_base.get("sha") != commit:
        fail("GitHub did not return the release commit as the main merge base")


def verify_dashboard_url(value: object) -> None:
    if not isinstance(value, str):
        fail("the Automata Check has no dashboard URL")
    parsed = urllib.parse.urlsplit(value)
    if (
        f"{parsed.scheme}://{parsed.netloc}" != DASHBOARD_ORIGIN
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        fail("the Automata Check dashboard origin is not trusted")
    expected_prefix = "/automata-ci/automata/actions"
    if parsed.path != expected_prefix and not parsed.path.startswith(
        f"{expected_prefix}/runs/"
    ):
        fail("the Automata Check dashboard path is not for this repository")


def verify_check(checks: dict, commit: str) -> None:
    records = checks.get("check_runs")
    if not isinstance(records, list) or len(records) != 1:
        fail("expected one latest required Automata Check")
    check = records[0]
    if not isinstance(check, dict):
        fail("the Automata Check record is invalid")

    app = check.get("app")
    owner = app.get("owner") if isinstance(app, dict) else None
    if (
        not isinstance(app, dict)
        or app.get("id") != APP_ID
        or app.get("slug") != APP_SLUG
        or not isinstance(owner, dict)
        or owner.get("login") != APP_OWNER
        or owner.get("type") != "Organization"
    ):
        fail("the required Check was not created by the trusted Automata App")
    if check.get("name") != CHECK_NAME or check.get("head_sha") != commit:
        fail("the Automata Check identity does not match the release commit")
    if check.get("status") != "completed" or check.get("conclusion") != "success":
        fail("the required Automata Check did not complete successfully")
    external_id = check.get("external_id")
    if not isinstance(external_id, str) or EXTERNAL_ID.fullmatch(external_id) is None:
        fail("the Automata Check external identity is invalid")
    suite = check.get("check_suite")
    if (
        not isinstance(suite, dict)
        or not isinstance(suite.get("id"), int)
        or suite["id"] <= 0
    ):
        fail("the Automata Check has no GitHub Check Suite identity")
    verify_dashboard_url(check.get("details_url"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit", required=True)
    parser.add_argument("--comparison", required=True)
    parser.add_argument("--checks", required=True)
    arguments = parser.parse_args()
    if GIT_SHA.fullmatch(arguments.commit) is None:
        fail("the release commit is not a full lowercase Git object ID")

    comparison = load_document(arguments.comparison, "main comparison")
    checks = load_document(arguments.checks, "Check Run response")
    verify_main_ancestry(comparison, arguments.commit)
    verify_check(checks, arguments.commit)
    print(
        f"release authority verified: {CHECK_NAME} passed for {arguments.commit}",
        flush=True,
    )


if __name__ == "__main__":
    main()
