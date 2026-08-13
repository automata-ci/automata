#!/usr/bin/env python3
"""Contract tests for bounded reference-drift issue publication."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
import urllib.error
from email.message import Message
from pathlib import Path
from typing import Any
from unittest.mock import patch


CI_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = CI_ROOT / "open-github-actions-reference-drift-issue.py"
SPEC = importlib.util.spec_from_file_location("reference_issue", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
reference_issue = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reference_issue)
DETECTOR_SCRIPT = CI_ROOT / "check-github-actions-reference-drift.py"
DETECTOR_SPEC = importlib.util.spec_from_file_location(
    "reference_detector", DETECTOR_SCRIPT
)
assert DETECTOR_SPEC is not None and DETECTOR_SPEC.loader is not None
reference_detector = importlib.util.module_from_spec(DETECTOR_SPEC)
DETECTOR_SPEC.loader.exec_module(reference_detector)


BODY = """## GitHub Actions reference drift

A bounded change requires review.
"""


def published(number: int, body: str = BODY) -> dict[str, Any]:
    return {
        "body": body,
        "labels": [],
        "number": number,
        "title": reference_issue.ISSUE_TITLE,
    }


class ScriptedApi:
    repository_path = "/repos/automata-ci/automata"

    def __init__(self, responses: list[tuple[Any, dict[str, str]]]) -> None:
        self.responses = responses
        self.requests: list[tuple[str, str, Any]] = []

    def request(self, method: str, path: str, payload: Any = None) -> tuple[Any, Any]:
        self.requests.append((method, path, payload))
        return self.responses.pop(0)


class FakeResponse:
    def __init__(self, value: Any, headers: Message | None = None) -> None:
        self.body = json.dumps(value).encode("utf-8")
        self.headers = headers or Message()
        self.headers["Content-Type"] = "application/json; charset=utf-8"

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *unused: Any) -> None:
        return None

    def read(self, limit: int) -> bytes:
        return self.body[:limit]


class FakeOpener:
    def __init__(self, response: FakeResponse | Exception) -> None:
        self.response = response
        self.request: Any = None
        self.timeout: Any = None

    def open(self, request: Any, timeout: int) -> FakeResponse:
        self.request = request
        self.timeout = timeout
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class ReferenceIssueTests(unittest.TestCase):
    def test_create_uses_one_exact_bounded_payload(self) -> None:
        api = ScriptedApi([([], {}), (published(17), {})])

        self.assertEqual(reference_issue.upsert_issue(api, BODY), ("created", 17))
        self.assertEqual(api.requests[0][0], "GET")
        self.assertIn("per_page=100", api.requests[0][1])
        self.assertEqual(
            api.requests[1],
            (
                "POST",
                "/repos/automata-ci/automata/issues",
                {
                    "body": BODY,
                    "labels": [],
                    "title": "GitHub Actions reference drift",
                },
            ),
        )

    def test_update_matches_exact_title_and_resets_labels(self) -> None:
        api = ScriptedApi(
            [
                (
                    [
                        {"number": 3, "title": "unrelated"},
                        {
                            "number": 19,
                            "title": reference_issue.ISSUE_TITLE,
                            "labels": [{"name": "manually-added"}],
                        },
                    ],
                    {},
                ),
                (published(19), {}),
            ]
        )

        self.assertEqual(reference_issue.upsert_issue(api, BODY), ("updated", 19))
        self.assertEqual(api.requests[1][0:2], ("PATCH", "/repos/automata-ci/automata/issues/19"))
        self.assertEqual(api.requests[1][2]["labels"], [])

    def test_duplicate_or_paginated_inventory_fails_before_mutation(self) -> None:
        duplicate = ScriptedApi(
            [
                (
                    [
                        {"number": 1, "title": reference_issue.ISSUE_TITLE},
                        {"number": 2, "title": reference_issue.ISSUE_TITLE},
                    ],
                    {},
                )
            ]
        )
        with self.assertRaisesRegex(reference_issue.DriftIssueError, "multiple"):
            reference_issue.upsert_issue(duplicate, BODY)
        self.assertEqual(len(duplicate.requests), 1)

        paginated = ScriptedApi([([], {"Link": '<https://example.test>; rel="next"'})])
        with self.assertRaisesRegex(reference_issue.DriftIssueError, "exceeds"):
            reference_issue.upsert_issue(paginated, BODY)
        self.assertEqual(len(paginated.requests), 1)

    def test_response_must_retain_exact_title_body_and_labels(self) -> None:
        wrong = published(4, body="different\n")
        api = ScriptedApi([([], {}), (wrong, {})])
        with self.assertRaisesRegex(reference_issue.DriftIssueError, "exact issue"):
            reference_issue.upsert_issue(api, BODY)

    def test_body_contract_is_utf8_regular_bounded_canonical_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "body.md"
            path.write_text(BODY, encoding="utf-8", newline="")
            self.assertEqual(reference_issue.read_body(path), BODY)

            path.write_bytes(("x" * (reference_issue.MAX_BODY_BYTES + 1)).encode())
            with self.assertRaisesRegex(reference_issue.DriftIssueError, "byte bound"):
                reference_issue.read_body(path)

            path.write_bytes(BODY.replace("\n", "\r\n").encode())
            with self.assertRaisesRegex(reference_issue.DriftIssueError, "Markdown"):
                reference_issue.read_body(path)

    def test_configuration_rejects_unsafe_values(self) -> None:
        self.assertEqual(
            reference_issue.validate_api_url("https://api.github.com"),
            "https://api.github.com",
        )
        self.assertEqual(
            reference_issue.validate_repository("automata-ci/automata"),
            "/repos/automata-ci/automata",
        )
        with self.assertRaises(reference_issue.DriftIssueError):
            reference_issue.validate_api_url("http://api.github.test")
        with self.assertRaises(reference_issue.DriftIssueError):
            reference_issue.validate_repository("../automata")
        with self.assertRaises(reference_issue.DriftIssueError):
            reference_issue.validate_token("secret\nvalue")

    def test_client_uses_timeout_and_authorization_without_error_leakage(self) -> None:
        opener = FakeOpener(FakeResponse([]))
        client = reference_issue.GithubIssueApi(
            "https://api.github.com", "automata-ci/automata", "top-secret", opener
        )
        self.assertEqual(client.request("GET", "/repos/automata-ci/automata/issues")[0], [])
        self.assertEqual(opener.timeout, reference_issue.REQUEST_TIMEOUT_SECONDS)
        self.assertEqual(opener.request.get_header("Authorization"), "Bearer top-secret")

        error = urllib.error.HTTPError(
            "https://api.github.com", 422, "top-secret", Message(), None
        )
        failing = reference_issue.GithubIssueApi(
            "https://api.github.com",
            "automata-ci/automata",
            "top-secret",
            FakeOpener(error),
        )
        with self.assertRaises(reference_issue.DriftIssueError) as raised:
            failing.request("GET", "/repos/automata-ci/automata/issues")
        self.assertNotIn("top-secret", str(raised.exception))

    def test_detector_sends_token_only_to_exact_github_api_origin(self) -> None:
        api_opener = FakeOpener(FakeResponse({}))
        raw_opener = FakeOpener(FakeResponse({}))
        with patch.dict(os.environ, {"GITHUB_TOKEN": "top-secret"}, clear=False):
            with patch.object(reference_detector, "OPENER", api_opener):
                reference_detector.request_bytes("https://api.github.com/repos/github/docs")
            with patch.object(reference_detector, "OPENER", raw_opener):
                reference_detector.request_bytes(
                    "https://raw.githubusercontent.com/github/docs/"
                    + "0" * 40
                    + "/README.md"
                )

        self.assertEqual(
            api_opener.request.get_header("Authorization"), "Bearer top-secret"
        )
        self.assertIsNone(raw_opener.request.get_header("Authorization"))
        self.assertFalse(
            reference_detector.api_request("https://api.github.com.evil.test/repos/x/y")
        )


if __name__ == "__main__":
    unittest.main()
