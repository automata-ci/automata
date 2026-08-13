#!/usr/bin/env python3
"""Run psql against the test database without exposing URI passwords in argv."""

from __future__ import annotations

import os
import pathlib
import sys
import urllib.parse
from typing import NoReturn


def fail(message: str) -> NoReturn:
    raise SystemExit(f"error: {message}")


def sanitized_connection() -> tuple[str, str | None]:
    raw = os.environ.get("AUTOMATA_TEST_DATABASE_URL", "")
    if not raw:
        fail("AUTOMATA_TEST_DATABASE_URL is required")

    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme not in {"postgres", "postgresql"}:
        fail("AUTOMATA_TEST_DATABASE_URL must use postgres or postgresql")
    if parsed.fragment:
        fail("AUTOMATA_TEST_DATABASE_URL must not contain a fragment")

    netloc = parsed.netloc
    password: str | None = None
    if "@" in netloc:
        userinfo, hostinfo = netloc.rsplit("@", 1)
        if ":" in userinfo:
            username, encoded_password = userinfo.split(":", 1)
            if not username:
                fail("AUTOMATA_TEST_DATABASE_URL has a password without a user")
            password = urllib.parse.unquote(encoded_password)
            netloc = f"{username}@{hostinfo}"

    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query_passwords = [value for key, value in query if key == "password"]
    if len(query_passwords) > 1:
        fail("AUTOMATA_TEST_DATABASE_URL contains multiple password parameters")
    if query_passwords:
        if password is not None:
            fail("AUTOMATA_TEST_DATABASE_URL contains two password authorities")
        password = query_passwords[0]
        query = [(key, value) for key, value in query if key != "password"]

    sanitized = urllib.parse.urlunsplit(
        (
            parsed.scheme,
            netloc,
            parsed.path,
            urllib.parse.urlencode(query, doseq=True),
            "",
        )
    )
    return sanitized, password


def main() -> NoReturn:
    for argument in sys.argv[1:]:
        if argument == "-d" or argument.startswith("--dbname"):
            fail("the psql test-database launcher owns --dbname")

    connection, password = sanitized_connection()
    environment = os.environ.copy()
    environment.pop("PGDATABASE", None)
    if password is not None:
        environment["PGPASSWORD"] = password

    binary = pathlib.Path(
        environment.get("AUTOMATA_PSQL_BINARY", "/usr/bin/psql")
    )
    if not binary.is_absolute():
        fail("AUTOMATA_PSQL_BINARY must be an absolute path")
    os.execve(
        binary,
        [str(binary), f"--dbname={connection}", *sys.argv[1:]],
        environment,
    )


if __name__ == "__main__":
    main()
