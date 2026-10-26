"""Tenant isolation, proved at the database rather than argued about in review.

The question each of these tests answers is the one that matters: if the
application code forgets to filter by organisation - and over a long enough
codebase it will - does the database still refuse to hand over another
customer's rows?

Every query here is deliberately written the wrong way, with no WHERE clause on
org_id, because that is the mistake being guarded against.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import ProgrammingError

from app.db.session import session_factory
from app.models import Asset, Organisation, ScopeAgreement, UserAccount
from tests.conftest import MODULE_TLS

# A genuine argon2id hash, in the PHC string format the column is sized for.
# Hard-coded rather than computed: argon2 is deliberately slow, and nothing here
# is testing the hasher.
ARGON2_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$"
    "zAV0ehjOdrlnMb6I2NT5JQ$uOxNpnU2RVpmG51UJM/2lyOiG8KJD9r7+rgGABLxEF0"
)


def test_application_role_does_not_bypass_rls(app_engine):
    """Guards every other test in this file.

    If the application connected as a superuser, as the table owner, or as a
    role with BYPASSRLS, the policies would be inert and the isolation tests
    below would pass without proving anything. So check the premise first.
    """
    with app_engine.connect() as connection:
        row = connection.execute(
            text(
                "SELECT rolsuper, rolbypassrls FROM pg_roles "
                "WHERE rolname = current_user"
            )
        ).one()
        is_superuser, bypasses_rls = row
        assert is_superuser is False
        assert bypasses_rls is False

        owner = connection.execute(
            text("SELECT tableowner FROM pg_tables WHERE tablename = 'asset'")
        ).scalar_one()
        current_user = connection.execute(text("SELECT current_user")).scalar_one()
        assert owner != current_user, (
            "the application role must not own the tables, or row level "
            "security would not apply to it"
        )


def test_org_a_cannot_see_org_b_rows_even_with_an_unfiltered_query(
    app_session, make_org, make_agreement, make_asset
):
    """The brief's requirement: the query forgets to filter, and it still holds."""
    org_a = make_org(legal_name="A Ltd")
    org_b = make_org(legal_name="B Ltd")
    asset_a = make_asset(org_a, identifier="a.example.com")
    make_asset(org_b, identifier="b.example.com")
    make_agreement(org_a, permitted_modules=[MODULE_TLS])
    make_agreement(org_b, permitted_modules=[MODULE_TLS])

    with app_session(org_a.id) as session:
        # No WHERE clause anywhere. This is the bug the policies exist for.
        assets = list(session.scalars(select(Asset)))
        agreements = list(session.scalars(select(ScopeAgreement)))

    assert [a.id for a in assets] == [asset_a.id]
    assert {a.org_id for a in agreements} == {org_a.id}


def test_a_session_with_no_org_context_sees_nothing(app_engine, make_org, make_asset):
    """The default has to be "nothing", not "everything".

    A connection that never had `app.current_org_id` set is a bug, and the
    failure mode of that bug must be an empty result rather than the whole
    table. Note this session is built without the org-scoped helper on purpose -
    it is simulating the helper being bypassed.
    """
    org = make_org()
    make_asset(org)

    factory = session_factory(app_engine)
    session = factory()
    try:
        assert list(session.scalars(select(Asset))) == []
        assert list(session.scalars(select(Organisation))) == []
    finally:
        session.rollback()
        session.close()


def test_user_accounts_are_isolated_between_orgs(
    app_session, owner_session, make_org
):
    org_a = make_org(legal_name="A Ltd")
    org_b = make_org(legal_name="B Ltd")
    owner_session.add_all(
        [
            UserAccount(
                org_id=org_a.id,
                email="person@a.example.com",
                password_hash=ARGON2_HASH,
                role="admin",
            ),
            UserAccount(
                org_id=org_b.id,
                email="person@b.example.com",
                password_hash=ARGON2_HASH,
                role="admin",
            ),
        ]
    )
    owner_session.commit()

    with app_session(org_a.id) as session:
        emails = {u.email for u in session.scalars(select(UserAccount))}

    assert emails == {"person@a.example.com"}


def test_email_is_case_insensitive(app_session, owner_session, make_org):
    """citext, checked - a lookup must not depend on how the user typed it."""
    org = make_org()
    owner_session.add(
        UserAccount(
            org_id=org.id,
            email="Jo.Bloggs@Example.COM",
            password_hash=ARGON2_HASH,
            role="owner",
        )
    )
    owner_session.commit()

    with app_session(org.id) as session:
        found = session.scalars(
            select(UserAccount).where(UserAccount.email == "jo.bloggs@example.com")
        ).one()

    assert found.org_id == org.id


def test_parent_msp_sees_child_org_rows(
    app_session, make_org, make_asset
):
    """One rule, one place: the same function the gate calls."""
    msp = make_org(legal_name="MSP Ltd")
    client_one = make_org(legal_name="Client One Ltd", parent=msp)
    client_two = make_org(legal_name="Client Two Ltd", parent=msp)
    unrelated = make_org(legal_name="Unrelated Ltd")

    own = make_asset(msp, identifier="msp.example.com")
    first = make_asset(client_one, identifier="one.example.com")
    second = make_asset(client_two, identifier="two.example.com")
    make_asset(unrelated, identifier="nope.example.com")

    with app_session(msp.id) as session:
        visible = {a.id for a in session.scalars(select(Asset))}
        visible_orgs = {o.legal_name for o in session.scalars(select(Organisation))}

    assert visible == {own.id, first.id, second.id}
    assert visible_orgs == {"MSP Ltd", "Client One Ltd", "Client Two Ltd"}


def test_hierarchy_is_recursive(app_session, make_org, make_asset):
    group = make_org(legal_name="Group Ltd")
    msp = make_org(legal_name="MSP Ltd", parent=group)
    client = make_org(legal_name="Client Ltd", parent=msp)
    deep = make_asset(client, identifier="deep.example.com")

    with app_session(group.id) as session:
        assert deep.id in {a.id for a in session.scalars(select(Asset))}


def test_child_cannot_see_parent_rows(app_session, make_org, make_asset):
    """The hierarchy descends only. A client must not read its provider's data."""
    msp = make_org(legal_name="MSP Ltd")
    client = make_org(legal_name="Client Ltd", parent=msp)
    make_asset(msp, identifier="msp.example.com")
    own = make_asset(client, identifier="client.example.com")

    with app_session(client.id) as session:
        visible = {a.id for a in session.scalars(select(Asset))}
        visible_orgs = {o.legal_name for o in session.scalars(select(Organisation))}

    assert visible == {own.id}
    assert visible_orgs == {"Client Ltd"}


def test_siblings_cannot_see_each_other(app_session, make_org, make_asset):
    msp = make_org(legal_name="MSP Ltd")
    client_one = make_org(legal_name="Client One Ltd", parent=msp)
    client_two = make_org(legal_name="Client Two Ltd", parent=msp)
    make_asset(client_two, identifier="two.example.com")
    own = make_asset(client_one, identifier="one.example.com")

    with app_session(client_one.id) as session:
        assert {a.id for a in session.scalars(select(Asset))} == {own.id}


def test_cannot_insert_a_row_belonging_to_another_org(
    app_session, make_org
):
    """WITH CHECK, not just USING.

    Without the WITH CHECK half of the policy, org A could insert a row stamped
    with org B's id - writing into another tenant - and then immediately lose
    sight of it.
    """
    org_a = make_org(legal_name="A Ltd")
    org_b = make_org(legal_name="B Ltd")

    with pytest.raises(ProgrammingError, match="row-level security"):
        with app_session(org_a.id) as session:
            session.add(
                Asset(org_id=org_b.id, kind="domain", identifier="smuggled.example.com")
            )
            session.flush()


def test_cannot_move_a_row_into_another_org(app_session, make_org, make_asset):
    """An UPDATE that reassigns org_id is a cross-tenant write too."""
    org_a = make_org(legal_name="A Ltd")
    org_b = make_org(legal_name="B Ltd")
    asset = make_asset(org_a)

    with pytest.raises(ProgrammingError, match="row-level security"):
        with app_session(org_a.id) as session:
            mine = session.get(Asset, asset.id)
            mine.org_id = org_b.id
            session.flush()


def test_org_scope_context_is_transaction_local(app_engine, make_org, make_asset):
    """The session variable must not outlive its transaction.

    Connections are pooled and outlive a request. If the organisation context
    were session-scoped rather than transaction-scoped, the next request to be
    handed the same connection would inherit the previous tenant's identity -
    which is the worst bug this schema could have.
    """
    org = make_org()
    make_asset(org)

    factory = session_factory(app_engine)
    scoped = factory()
    try:
        scoped.execute(
            text("SELECT set_config('app.current_org_id', :org, true)"),
            {"org": str(org.id)},
        )
        assert len(list(scoped.scalars(select(Asset)))) == 1
        # Ending the transaction must take the setting with it.
        scoped.commit()
        assert scoped.execute(text("SELECT app.current_org_id()")).scalar_one() is None
        assert list(scoped.scalars(select(Asset))) == []
    finally:
        scoped.rollback()
        scoped.close()


def test_scoped_session_helper_survives_a_commit(app_session, make_org, make_asset):
    """...and the helper is the reason that is safe.

    The context set by `org_scoped_session` is reapplied on each new
    transaction, so a unit of work that commits halfway through keeps working.
    This test exists because the transaction-local setting above would otherwise
    make that a trap.
    """
    org = make_org()
    make_asset(org)

    with app_session(org.id) as session:
        assert len(list(session.scalars(select(Asset)))) == 1
        session.commit()
        # New transaction, same session.
        assert len(list(session.scalars(select(Asset)))) == 1


def test_org_in_scope_rejects_a_missing_context(app_session, make_org):
    """The helper function itself fails closed, not open."""
    org = make_org()
    with app_session(org.id) as session:
        assert session.execute(
            text("SELECT app.org_in_scope(:org, NULL)"), {"org": str(org.id)}
        ).scalar_one() is False
        assert session.execute(
            text("SELECT app.org_in_scope(NULL, :org)"), {"org": str(org.id)}
        ).scalar_one() is False


def test_application_role_cannot_create_organisations(app_session, make_org):
    """Provisioning is administrative work, granted to the owner role only."""
    org = make_org()
    with pytest.raises(ProgrammingError, match="permission denied"):
        with app_session(org.id) as session:
            session.add(Organisation(legal_name="Self Service Ltd"))
            session.flush()
