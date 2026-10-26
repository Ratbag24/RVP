"""row level security, the organisation hierarchy helper, and append-only audit

This is the migration that makes tenant isolation a property of the database
rather than a property of our SQL being careful. Three parts:

1.  `app.current_org_id()` and `app.org_in_scope()` - the whole of the "who can
    see what" rule, including the managed service provider hierarchy, in one
    place. Every policy below calls it; none of them reimplements it.

2.  A policy on every table that carries an `org_id`, plus `organisation`
    itself and `scan_target`. The default with row level security enabled and no
    matching policy is to see nothing, which is the right way to fail.

3.  A trigger that refuses UPDATE, DELETE and TRUNCATE on `audit_event`.

A note on who this constrains. Row level security does not apply to a superuser,
to a role with BYPASSRLS, or (absent FORCE ROW LEVEL SECURITY) to the table
owner. The owner role that runs this migration holds BYPASSRLS, so none of these
policies constrain it; they constrain the unprivileged application role, which is
what request handling connects as. If you find yourself testing isolation from
the owner connection, every policy here will look broken - it is the connection
that is wrong, not the policy.

Revision ID: 0002
Revises: 0001
"""
from __future__ import annotations

from alembic import op
from app.config import app_role
from app.models import ORG_SCOPED_TABLES

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

# `audit_event` carries org_id but gets a narrower policy: readable and
# insertable, never updatable or deletable. Handled separately below.
_APPEND_ONLY_TABLE = "audit_event"
_FULL_ACCESS_TABLES = tuple(t for t in ORG_SCOPED_TABLES if t != _APPEND_ONLY_TABLE)


CURRENT_ORG_FUNCTION = """
CREATE OR REPLACE FUNCTION app.current_org_id() RETURNS uuid
LANGUAGE sql
STABLE
AS $$
    -- The session variable is set per transaction by the application's session
    -- helper. The second argument to current_setting() is missing_ok: an unset
    -- variable gives NULL rather than an error, and NULL propagates into the
    -- policies as "no organisation", which matches nothing.
    SELECT nullif(current_setting('app.current_org_id', true), '')::uuid
$$;
"""

# The organisation hierarchy, in one function, called by every policy.
#
# SECURITY DEFINER is load-bearing here, not decoration. This function reads
# `organisation`, and `organisation` has a policy that calls this function. Run
# as the caller, that is infinite recursion. Run as the owner - which holds
# BYPASSRLS - the read inside the function is not subject to policies at all, so
# there is nothing to recurse into. search_path is pinned for the usual
# SECURITY DEFINER reason: without it, a caller could put their own
# `organisation` table earlier on the path and have this function read it.
ORG_IN_SCOPE_FUNCTION = """
CREATE OR REPLACE FUNCTION app.org_in_scope(target_org_id uuid, root_org_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    WITH RECURSIVE subtree(id, depth) AS (
        SELECT o.id, 1
        FROM public.organisation o
        WHERE o.id = root_org_id
      UNION ALL
        -- Descend: a managed service provider sees its clients, and its
        -- clients' clients. A child never sees its parent, so the direction of
        -- this join is the entire access rule.
        SELECT child.id, s.depth + 1
        FROM public.organisation child
        JOIN subtree s ON child.parent_org_id = s.id
        -- The depth bound is a safety net, not a business rule. A cycle in
        -- parent_org_id (which the check constraint only prevents at length
        -- one) would otherwise spin forever inside a policy evaluation, taking
        -- the whole request with it.
        WHERE s.depth < 16
    )
    SELECT EXISTS (SELECT 1 FROM subtree WHERE subtree.id = target_org_id)
$$;
"""

# One-argument form: the same rule, rooted at whoever the current transaction
# says it is. This is the form the policies use.
ORG_IN_SCOPE_CURRENT_FUNCTION = """
CREATE OR REPLACE FUNCTION app.org_in_scope(target_org_id uuid) RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT app.org_in_scope(target_org_id, app.current_org_id())
$$;
"""

AUDIT_APPEND_ONLY_FUNCTION = """
CREATE OR REPLACE FUNCTION app.audit_event_is_append_only() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- No branch, no exception for administrators: there is no legitimate reason
    -- to change an audit row, so there is no code path that allows it. Dropping
    -- the trigger is possible for the table owner, and that act is itself
    -- visible in the schema - which is the point.
    RAISE EXCEPTION 'audit_event is append-only: % is not permitted', tg_op
        USING errcode = 'restrict_violation',
              hint = 'Record a correcting event instead of altering history.';
END
$$;
"""


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS app")
    op.execute(CURRENT_ORG_FUNCTION)
    op.execute(ORG_IN_SCOPE_FUNCTION)
    op.execute(ORG_IN_SCOPE_CURRENT_FUNCTION)

    # SECURITY DEFINER functions are executable by PUBLIC by default. Take that
    # away and grant it deliberately, below, to the role that needs it.
    op.execute("REVOKE EXECUTE ON FUNCTION app.org_in_scope(uuid, uuid) FROM PUBLIC")

    # `organisation` has no org_id; its own id is what the rule keys on. An MSP
    # sees itself and its clients, a client sees only itself.
    op.execute("ALTER TABLE organisation ENABLE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY organisation_org_isolation ON organisation
            FOR ALL
            USING (app.org_in_scope(id))
            WITH CHECK (app.org_in_scope(id))
        """
    )

    for table in _FULL_ACCESS_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        # USING filters what existing rows are visible to SELECT, UPDATE and
        # DELETE; WITH CHECK validates rows being written by INSERT and UPDATE.
        # Both are needed: USING alone would let one org insert a row stamped
        # with another org's id and then lose sight of it.
        op.execute(
            f"""
            CREATE POLICY {table}_org_isolation ON {table}
                FOR ALL
                USING (app.org_in_scope(org_id))
                WITH CHECK (app.org_in_scope(org_id))
            """
        )

    # audit_event: two narrow policies rather than one FOR ALL. With RLS enabled
    # and no policy for UPDATE or DELETE, those commands match no rows at all -
    # so the append-only guarantee holds even if the trigger below were dropped.
    op.execute(f"ALTER TABLE {_APPEND_ONLY_TABLE} ENABLE ROW LEVEL SECURITY")
    op.execute(
        f"""
        CREATE POLICY {_APPEND_ONLY_TABLE}_org_read ON {_APPEND_ONLY_TABLE}
            FOR SELECT
            USING (app.org_in_scope(org_id))
        """
    )
    op.execute(
        f"""
        CREATE POLICY {_APPEND_ONLY_TABLE}_org_append ON {_APPEND_ONLY_TABLE}
            FOR INSERT
            WITH CHECK (app.org_in_scope(org_id))
        """
    )

    # scan_target has no org_id of its own - it is a join row - but it still
    # leaks which assets were scanned and under what authorisation, so it gets a
    # policy derived from its scan. The subquery reads `scan`, which is itself
    # policy-filtered; the explicit org_in_scope call makes the intent readable
    # rather than relying on that.
    op.execute("ALTER TABLE scan_target ENABLE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY scan_target_org_isolation ON scan_target
            FOR ALL
            USING (
                EXISTS (
                    SELECT 1 FROM scan s
                    WHERE s.id = scan_target.scan_id
                      AND app.org_in_scope(s.org_id)
                )
            )
            WITH CHECK (
                EXISTS (
                    SELECT 1 FROM scan s
                    WHERE s.id = scan_target.scan_id
                      AND app.org_in_scope(s.org_id)
                )
            )
        """
    )

    op.execute(AUDIT_APPEND_ONLY_FUNCTION)
    op.execute(
        """
        CREATE TRIGGER audit_event_no_update
            BEFORE UPDATE ON audit_event
            FOR EACH ROW EXECUTE FUNCTION app.audit_event_is_append_only()
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_event_no_delete
            BEFORE DELETE ON audit_event
            FOR EACH ROW EXECUTE FUNCTION app.audit_event_is_append_only()
        """
    )
    # TRUNCATE does not fire row-level triggers, so it needs its own statement
    # level one. Without this, "append-only" would have a one-command bypass.
    op.execute(
        """
        CREATE TRIGGER audit_event_no_truncate
            BEFORE TRUNCATE ON audit_event
            FOR EACH STATEMENT EXECUTE FUNCTION app.audit_event_is_append_only()
        """
    )

    _grant_application_privileges()


def _grant_application_privileges() -> None:
    """Grant the application role exactly what it needs, and no more.

    Guarded on the role existing so that `alembic upgrade head` works on a
    database where the role has a different name or has not been created yet
    (see scripts/setup_db.sh). A missing role is a notice, not a failed
    migration - but it does mean the application cannot connect, so the notice
    says so.
    """
    role = app_role()
    # Built in Python so the SQL below holds one string literal per statement;
    # relying on Postgres' newline-separated literal concatenation inside a DO
    # block is the kind of cleverness that breaks on reformatting.
    dml_tables = ", ".join((*_FULL_ACCESS_TABLES, "scan_target"))
    op.execute(
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
                RAISE NOTICE
                    'role % does not exist; skipping grants. Run scripts/setup_db.sh.',
                    '{role}';
                RETURN;
            END IF;

            EXECUTE format('GRANT USAGE ON SCHEMA app TO %I', '{role}');
            EXECUTE format(
                'GRANT EXECUTE ON FUNCTION app.current_org_id() TO %I', '{role}');
            EXECUTE format(
                'GRANT EXECUTE ON FUNCTION app.org_in_scope(uuid) TO %I', '{role}');
            EXECUTE format(
                'GRANT EXECUTE ON FUNCTION app.org_in_scope(uuid, uuid) TO %I',
                '{role}');

            -- Tenant data: full DML, constrained by the policies above.
            EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON {dml_tables} TO %I', '{role}');

            -- The audit log is insert and read only at the privilege level too,
            -- so a dropped trigger still leaves no route to rewrite it.
            EXECUTE format('GRANT SELECT, INSERT ON audit_event TO %I', '{role}');

            -- Creating and re-parenting organisations is administrative work,
            -- done by the owner role, not something a request can do.
            EXECUTE format('GRANT SELECT ON organisation TO %I', '{role}');
        END
        $$;
        """
    )


def downgrade() -> None:
    for trigger in ("audit_event_no_truncate", "audit_event_no_delete",
                    "audit_event_no_update"):
        op.execute(f"DROP TRIGGER IF EXISTS {trigger} ON audit_event")
    op.execute("DROP FUNCTION IF EXISTS app.audit_event_is_append_only()")

    op.execute("DROP POLICY IF EXISTS scan_target_org_isolation ON scan_target")
    op.execute("ALTER TABLE scan_target DISABLE ROW LEVEL SECURITY")

    op.execute(
        f"DROP POLICY IF EXISTS {_APPEND_ONLY_TABLE}_org_append ON {_APPEND_ONLY_TABLE}"
    )
    op.execute(
        f"DROP POLICY IF EXISTS {_APPEND_ONLY_TABLE}_org_read ON {_APPEND_ONLY_TABLE}"
    )
    op.execute(f"ALTER TABLE {_APPEND_ONLY_TABLE} DISABLE ROW LEVEL SECURITY")

    for table in _FULL_ACCESS_TABLES:
        op.execute(f"DROP POLICY IF EXISTS {table}_org_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")

    op.execute("DROP POLICY IF EXISTS organisation_org_isolation ON organisation")
    op.execute("ALTER TABLE organisation DISABLE ROW LEVEL SECURITY")

    op.execute("DROP FUNCTION IF EXISTS app.org_in_scope(uuid)")
    op.execute("DROP FUNCTION IF EXISTS app.org_in_scope(uuid, uuid)")
    op.execute("DROP FUNCTION IF EXISTS app.current_org_id()")
    # The schema is left in place; dropping it would take anything else that has
    # since been put there with it.
