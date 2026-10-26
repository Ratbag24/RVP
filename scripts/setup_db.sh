#!/usr/bin/env bash
#
# Creates the two roles and two databases this project needs.
#
# Why two roles rather than one:
#
#   Row level security is not enforced against a superuser, nor against a role
#   holding BYPASSRLS, nor (unless FORCE ROW LEVEL SECURITY is set) against the
#   table owner. If the application connected as the role that owns the tables,
#   every policy in this schema would be silently inert and the isolation tests
#   would pass for the wrong reason.
#
#   So:
#     rvp_owner  owns the schema, runs the migrations, and holds BYPASSRLS. It
#                is also the owner of the SECURITY DEFINER helper that walks the
#                organisation hierarchy, which is how that helper reads the
#                organisation table without re-triggering the policy that calls it.
#     rvp_app    is what the application connects as. No superuser, no BYPASSRLS,
#                not the table owner: policies apply to it in full.
#
# Run as a user that can create roles and databases, e.g.
#   sudo -u postgres ./scripts/setup_db.sh
#
set -euo pipefail

OWNER_ROLE="${OWNER_ROLE:-rvp_owner}"
OWNER_PASSWORD="${OWNER_PASSWORD:-rvp_owner}"
APP_ROLE="${APP_ROLE:-rvp_app}"
APP_PASSWORD="${APP_PASSWORD:-rvp_app}"
DEV_DB="${DEV_DB:-rvp}"
TEST_DB="${TEST_DB:-rvp_test}"

psql_super() { psql -v ON_ERROR_STOP=1 -q "$@"; }

# Roles are cluster-wide, so create them idempotently before touching databases.
psql_super -d postgres <<SQL
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${OWNER_ROLE}') THEN
        -- BYPASSRLS here is deliberate and is the only role that gets it.
        CREATE ROLE ${OWNER_ROLE} LOGIN PASSWORD '${OWNER_PASSWORD}' BYPASSRLS CREATEDB;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${APP_ROLE}') THEN
        CREATE ROLE ${APP_ROLE} LOGIN PASSWORD '${APP_PASSWORD}' NOBYPASSRLS;
    END IF;
END
\$\$;
SQL

for db in "${DEV_DB}" "${TEST_DB}"; do
    if ! psql -tAc "SELECT 1 FROM pg_database WHERE datname = '${db}'" -d postgres | grep -q 1; then
        psql_super -d postgres -c "CREATE DATABASE ${db} OWNER ${OWNER_ROLE}"
    fi
    # CONNECT only. Table privileges are granted by the migration, which knows
    # which tables exist and which of them are append-only.
    psql_super -d postgres -c "REVOKE ALL ON DATABASE ${db} FROM PUBLIC"
    psql_super -d postgres -c "GRANT CONNECT ON DATABASE ${db} TO ${APP_ROLE}"
    # citext needs an extension-creating role; do it here rather than in the
    # migration so the migration itself can run as an ordinary owner.
    psql_super -d "${db}" -c "CREATE EXTENSION IF NOT EXISTS citext"
done

echo "Ready: roles ${OWNER_ROLE}, ${APP_ROLE}; databases ${DEV_DB}, ${TEST_DB}."
