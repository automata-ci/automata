#!/usr/bin/env python3
"""Create or update the one bounded GitHub Actions reference-drift issue."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Protocol


ISSUE_TITLE = "GitHub Actions reference drift"
# The repository does not require a pre-created label for this scheduled lane.
# Sending the exact empty set also removes manually added labels on update.
ISSUE_LABELS: tuple[str, ...] = ()
BODY_HEADING = f"## {ISSUE_TITLE}\n"
MAX_BODY_BYTES = 32_768
MAX_RESPONSE_BYTES = 1_048_576
MAX_OPEN_ISSUES = 100
MAX_TOKEN_BYTES = 4_096
REQUEST_TIMEOUT_SECONDS = 30
REPOSITORY = re.compile(
    r"(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)/"
    r"(?P<name>[A-Za-z0-9_.-]{1,100})"
)


class DriftIssueError(RuntimeError):
    """The issue could not be published without weakening the contract."""


class IssueApi(Protocol):
    repository_path: str

    def request(self, method: str, path: str, payload: Any = None) -> tuple[Any, Any]:
        """Send one authenticated API request."""


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> urllib.request.Request | None:
        del request, file_pointer, code, message, headers, new_url
        raise DriftIssueError("GitHub API redirects are not accepted")


class GithubIssueApi:
    """Bounded authenticated client for the repository Issues API."""

    def __init__(
        self,
        api_url: str,
        repository: str,
        token: str,
        opener: Any = None,
    ) -> None:
        self.api_url = validate_api_url(api_url)
        self.repository_path = validate_repository(repository)
        self.token = validate_token(token)
        self.opener = opener or urllib.request.build_opener(_RejectRedirects())

    def request(self, method: str, path: str, payload: Any = None) -> tuple[Any, Any]:
        if method not in {"GET", "PATCH", "POST"} or not path.startswith("/"):
            raise DriftIssueError("invalid GitHub API request")
        data = None
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode(
                "utf-8"
            )
        request = urllib.request.Request(
            f"{self.api_url}{path}",
            data=data,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "User-Agent": "automata-github-actions-reference-drift/1",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            method=method,
        )
        try:
            with self.opener.open(
                request, timeout=REQUEST_TIMEOUT_SECONDS
            ) as response:
                content_type = response.headers.get("Content-Type", "")
                if not content_type.lower().startswith("application/json"):
                    raise DriftIssueError("GitHub API returned a non-JSON response")
                body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise DriftIssueError("GitHub API response exceeds the configured bound")
                headers = response.headers
        except DriftIssueError:
            raise
        except urllib.error.HTTPError as error:
            raise DriftIssueError(
                f"GitHub API request failed with HTTP {error.code}"
            ) from None
        except (OSError, urllib.error.URLError):
            raise DriftIssueError("GitHub API request failed") from None
        try:
            return json.loads(body), headers
        except (UnicodeError, json.JSONDecodeError):
            raise DriftIssueError("GitHub API returned invalid JSON") from None


def validate_api_url(value: str) -> str:
    if not isinstance(value, str) or len(value) > 2_048:
        raise DriftIssueError("GITHUB_API_URL is invalid")
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise DriftIssueError("GITHUB_API_URL is invalid")
    return value.rstrip("/")


def validate_repository(value: str) -> str:
    match = REPOSITORY.fullmatch(value or "")
    if match is None or match["name"] in {".", ".."}:
        raise DriftIssueError("GITHUB_REPOSITORY is invalid")
    owner = urllib.parse.quote(match["owner"], safe="")
    name = urllib.parse.quote(match["name"], safe="")
    return f"/repos/{owner}/{name}"


def validate_token(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > MAX_TOKEN_BYTES
        or value.strip() != value
        or any(character.isspace() or is_control(character) for character in value)
    ):
        raise DriftIssueError("GITHUB_TOKEN is invalid")
    return value


def read_body(path: Path) -> str:
    try:
        if path.is_symlink() or not path.is_file():
            raise DriftIssueError("issue body must be a regular file")
        raw = path.read_bytes()
    except DriftIssueError:
        raise
    except OSError:
        raise DriftIssueError("issue body could not be read") from None
    if not raw or len(raw) > MAX_BODY_BYTES:
        raise DriftIssueError("issue body violates the configured byte bound")
    try:
        body = raw.decode("utf-8")
    except UnicodeError:
        raise DriftIssueError("issue body is not UTF-8") from None
    if (
        not body.startswith(BODY_HEADING)
        or not body.endswith("\n")
        or "\r" in body
        or any(
            is_control(character) and character not in {"\n", "\t"}
            for character in body
        )
    ):
        raise DriftIssueError("issue body violates the canonical Markdown contract")
    return body


def is_control(character: str) -> bool:
    return unicodedata.category(character) == "Cc"


def upsert_issue(client: IssueApi, body: str) -> tuple[str, int]:
    query = urllib.parse.urlencode({"per_page": MAX_OPEN_ISSUES, "state": "open"})
    issues, headers = client.request(
        "GET", f"{client.repository_path}/issues?{query}"
    )
    if not isinstance(issues, list) or len(issues) > MAX_OPEN_ISSUES:
        raise DriftIssueError("GitHub returned an invalid open-issue inventory")
    if 'rel="next"' in headers.get("Link", ""):
        raise DriftIssueError("open-issue inventory exceeds the configured bound")

    matches: list[int] = []
    for issue in issues:
        if not isinstance(issue, dict) or not isinstance(issue.get("title"), str):
            raise DriftIssueError("GitHub returned a malformed open issue")
        if issue["title"] != ISSUE_TITLE or "pull_request" in issue:
            continue
        number = issue.get("number")
        if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
            raise DriftIssueError("GitHub returned an invalid issue identity")
        matches.append(number)
    if len(matches) > 1:
        raise DriftIssueError("multiple open reference-drift issues require review")

    payload = {"body": body, "labels": list(ISSUE_LABELS), "title": ISSUE_TITLE}
    if matches:
        operation = "updated"
        issue, _ = client.request(
            "PATCH", f"{client.repository_path}/issues/{matches[0]}", payload
        )
    else:
        operation = "created"
        issue, _ = client.request("POST", f"{client.repository_path}/issues", payload)
    number = validate_published_issue(issue, body)
    return operation, number


def validate_published_issue(issue: Any, body: str) -> int:
    if not isinstance(issue, dict):
        raise DriftIssueError("GitHub returned a malformed published issue")
    number = issue.get("number")
    labels = issue.get("labels")
    if (
        not isinstance(number, int)
        or isinstance(number, bool)
        or number <= 0
        or issue.get("title") != ISSUE_TITLE
        or issue.get("body") != body
        or not isinstance(labels, list)
    ):
        raise DriftIssueError("GitHub did not retain the exact issue contract")
    names = []
    for label in labels:
        if not isinstance(label, dict) or not isinstance(label.get("name"), str):
            raise DriftIssueError("GitHub returned malformed issue labels")
        names.append(label["name"])
    if tuple(sorted(names)) != tuple(sorted(ISSUE_LABELS)):
        raise DriftIssueError("GitHub did not retain the exact issue labels")
    return number


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--body-file", type=Path, required=True)
    args = parser.parse_args()
    try:
        body = read_body(args.body_file)
        client = GithubIssueApi(
            os.environ.get("GITHUB_API_URL", ""),
            os.environ.get("GITHUB_REPOSITORY", ""),
            os.environ.get("GITHUB_TOKEN", ""),
        )
        operation, number = upsert_issue(client, body)
    except DriftIssueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except Exception:
        # Never render unexpected exception data: request headers contain a token.
        print("error: unexpected issue publication failure", file=sys.stderr)
        return 1
    print(f"{operation} bounded reference-drift issue #{number}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
