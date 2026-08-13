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
    --no-psqlrc \
    --set=ON_ERROR_STOP=1 \
    --tuples-only \
    --no-align \
    --command='SHOW server_version_num'
)"

if [[ "$server_version" != "$expected_version" ]]; then
  printf 'expected PostgreSQL server_version_num=%s, got %s\n' \
    "$expected_version" "$server_version" >&2
  exit 1
fi

can_create_database="$(
  psql \
    --dbname="$AUTOMATA_TEST_DATABASE_URL" \
    --no-psqlrc \
    --set=ON_ERROR_STOP=1 \
    --tuples-only \
    --no-align \
    --command="
      SELECT COALESCE(
        (
          SELECT rolcreatedb OR rolsuper
          FROM pg_catalog.pg_roles
          WHERE rolname = CURRENT_USER
        ),
        FALSE
      )
    "
)"
if [[ "$can_create_database" != t ]]; then
  printf 'PostgreSQL test role must have CREATEDB or SUPERUSER\n' >&2
  exit 1
fi

printf 'verified PostgreSQL server_version_num=%s and database-create authority\n' \
  "$server_version"
