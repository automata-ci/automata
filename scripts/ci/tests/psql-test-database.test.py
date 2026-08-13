#!/usr/bin/env python3
"""Contracts for the secret-safe psql test-database launcher."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile


REPOSITORY = pathlib.Path(__file__).resolve().parents[3]
LAUNCHER = REPOSITORY / "scripts/ci/psql-test-database.py"


def run_launcher(database_url: str) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="automata-psql-launcher-") as directory:
        root = pathlib.Path(directory)
        capture = root / "capture.json"
        fake = root / "psql"
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys\n"
            "pathlib.Path(os.environ['AUTOMATA_PSQL_CAPTURE']).write_text(\n"
            "    json.dumps({'argv': sys.argv, 'password': os.environ.get('PGPASSWORD')}),\n"
            "    encoding='utf-8',\n"
            ")\n",
            encoding="utf-8",
        )
        fake.chmod(0o700)
        environment = os.environ.copy()
        environment.update(
            {
                "AUTOMATA_TEST_DATABASE_URL": database_url,
                "AUTOMATA_PSQL_BINARY": str(fake),
                "AUTOMATA_PSQL_CAPTURE": str(capture),
            }
        )
        subprocess.run(
            [str(LAUNCHER), "--no-psqlrc", "--command=SELECT 1"],
            check=True,
            cwd=REPOSITORY,
            env=environment,
        )
        return json.loads(capture.read_text(encoding="utf-8"))


userinfo = run_launcher(
    "postgresql://automata_ci:p%40ss%3Aword@127.0.0.1:5432/automata_ci?sslmode=disable"
)
assert userinfo["password"] == "p@ss:word"
assert pathlib.Path(userinfo["argv"][0]).name == "psql"
assert userinfo["argv"][1:] == [
    "--dbname=postgresql://automata_ci@127.0.0.1:5432/automata_ci?sslmode=disable",
    "--no-psqlrc",
    "--command=SELECT 1",
]
assert "p%40ss" not in " ".join(userinfo["argv"])

query = run_launcher(
    "postgres://automata_ci@localhost/automata_ci?password=query-secret&sslmode=require"
)
assert query["password"] == "query-secret"
assert query["argv"][1] == (
    "--dbname=postgres://automata_ci@localhost/automata_ci?sslmode=require"
)
assert "query-secret" not in " ".join(query["argv"])

print("secret-safe psql test-database launcher verified")
