"""The audit log is append-only, enforced by the database.

The brief's instruction was not to rely on the application behaving, so these
tests attack the table from the *owner* connection - the most privileged one the
project uses, the one that holds BYPASSRLS and could drop the policies. If the
guarantee holds against that, it holds against a careless ORM call.

Two independent mechanisms are checked here, and that redundancy is the point:

  the trigger     refuses UPDATE, DELETE and TRUNCATE outright, for everyone;
  the privileges  never grant UPDATE or DELETE on this table to the application
                  role at all, so a dropped trigger still leaves no route in.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from app.models import AuditEvent


@pytest.fixture
def an_event(owner_session, make_org) -> AuditEvent:
    org = make_org()
    event = AuditEvent(
        org_id=org.id,
        actor="system",
        action="test.event",
        detail={"note": "history"},
    )
    owner_session.add(event)
    owner_session.commit()
    return event


def test_an_event_can_be_appended(owner_session, an_event):
    stored = owner_session.get(AuditEvent, an_event.id)
    assert stored is not None
    assert stored.detail == {"note": "history"}
    # The database stamped it; the application did not have to.
    assert stored.occurred_at is not None


def test_update_is_refused_even_for_the_owner_role(owner_session, an_event):
    with pytest.raises(DBAPIError, match="append-only"):
        owner_session.execute(
            text("UPDATE audit_event SET action = 'tampered' WHERE id = :id"),
            {"id": an_event.id},
        )
    owner_session.rollback()

    unchanged = owner_session.get(AuditEvent, an_event.id)
    assert unchanged.action == "test.event"


def test_delete_is_refused_even_for_the_owner_role(owner_session, an_event):
    with pytest.raises(DBAPIError, match="append-only"):
        owner_session.execute(
            text("DELETE FROM audit_event WHERE id = :id"), {"id": an_event.id}
        )
    owner_session.rollback()

    assert owner_session.get(AuditEvent, an_event.id) is not None


def test_truncate_is_refused_even_for_the_owner_role(owner_session, an_event):
    """TRUNCATE does not fire row triggers, so it needs its own statement one.

    Without the statement-level trigger, "append-only" would have a single
    command that empties the whole table.
    """
    with pytest.raises(DBAPIError, match="append-only"):
        owner_session.execute(text("TRUNCATE audit_event"))
    owner_session.rollback()

    assert owner_session.get(AuditEvent, an_event.id) is not None


def test_the_triggers_are_enabled(owner_session):
    """A guard on the test suite itself.

    tests/conftest.py disables the TRUNCATE trigger to empty the table between
    tests. If it ever failed to switch it back on, every test above would pass
    for the wrong reason, so check the state of all three triggers directly.
    'O' is the enabled state in pg_trigger.tgenabled.
    """
    states = dict(
        owner_session.execute(
            text(
                "SELECT tgname, tgenabled FROM pg_trigger "
                "WHERE tgrelid = 'audit_event'::regclass AND NOT tgisinternal"
            )
        ).all()
    )
    assert states == {
        "audit_event_no_update": "O",
        "audit_event_no_delete": "O",
        "audit_event_no_truncate": "O",
    }


def test_application_role_has_no_update_or_delete_privilege(
    app_session, owner_session, an_event, make_org
):
    """Defence in depth: the trigger is not the only thing standing in the way.

    The application role was never granted UPDATE or DELETE on this table, so
    the attempt is refused on privileges before any trigger or policy is
    consulted.
    """
    org = make_org()
    for statement in (
        "UPDATE audit_event SET action = 'tampered'",
        "DELETE FROM audit_event",
    ):
        with pytest.raises(ProgrammingError, match="permission denied"):
            with app_session(org.id) as session:
                session.execute(text(statement))

    assert owner_session.get(AuditEvent, an_event.id) is not None


def test_audit_events_are_isolated_between_orgs(
    app_session, owner_session, make_org
):
    """An audit trail you can read across tenants is a disclosure of its own."""
    org_a = make_org(legal_name="A Ltd")
    org_b = make_org(legal_name="B Ltd")
    owner_session.add_all(
        [
            AuditEvent(org_id=org_a.id, actor="system", action="a.event", detail={}),
            AuditEvent(org_id=org_b.id, actor="system", action="b.event", detail={}),
        ]
    )
    owner_session.commit()

    with app_session(org_a.id) as session:
        actions = {e.action for e in session.scalars(select(AuditEvent))}

    assert actions == {"a.event"}


def test_application_role_can_append(app_session, owner_session, make_org):
    """Append must work from the application role, or the gate cannot audit."""
    org = make_org()
    with app_session(org.id) as session:
        session.add(
            AuditEvent(
                org_id=org.id,
                actor="worker:tls_config",
                action="authorisation.permitted",
                detail={"module": "tls_config"},
            )
        )

    owner_session.rollback()
    stored = owner_session.scalars(select(AuditEvent)).one()
    assert stored.actor == "worker:tls_config"
