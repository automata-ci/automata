#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${AUTOMATA_TEST_DATABASE_URL:-}" ]]; then
  printf 'AUTOMATA_TEST_DATABASE_URL is required\n' >&2
  exit 2
fi

expected_version="${AUTOMATA_EXPECTED_POSTGRES_VERSION_NUM:-180004}"
server_version="$(
  psql \
    --dbname="$AUTOMATA_TEST_DATABASE_URL" \
    --tuples-only \
    --no-align \
    --command='SHOW server_version_num'
)"

if [[ "$server_version" != "$expected_version" ]]; then
  printf 'expected PostgreSQL server_version_num=%s, got %s\n' \
    "$expected_version" "$server_version" >&2
  exit 1
fi

printf 'verified PostgreSQL server_version_num=%s\n' "$server_version"
