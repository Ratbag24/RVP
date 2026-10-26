"""Test fixtures.

These tests run against a real Postgres. That is not fussiness: row level
security, the append-only trigger, `citext`, native enum types and the recursive
hierarchy function are all Postgres features. A suite that passed against SQLite
would prove nothing about any of them, and would quietly stop testing the parts
most likely to be wrong.

The two-connection shape is the important thing here:

  owner_session  - connects as the owner role, which holds BYPASSRLS. Used to
                   build fixtures and to assert what is *really* in the
                   database, unfiltered. Nothing under test uses it.
  app_session    - connects as the unprivileged role with an organisation
                   context set, exactly as a request would. Everything under
                   test uses this, which is why the isolation assertions mean
                   something.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from alembic.config import Config as AlembicConfig
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from alembic import command
from app import config
from app.db.session import (
    create_app_engine,
    create_owner_engine,
    org_scoped_session,
    session_factory,
)
from app.enums import AssetKind, BusinessCriticality, VerificationMethod
from app.models import Asset, Organisation, ScopeAgreement

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# A fixed instant for every test. Nothing here reads the wall clock: the gate
# takes `at_time` explicitly, so the suite can pin a moment and reason about
# windows around it instead of racing midnight.
NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
DAY = timedelta(days=1)

# Module names used throughout. These are placeholders for step 1 - no module
# with any of these names exists yet, which is the point: the gate decides on
# names, not on implementations.
MODULE_TLS = "tls_config"
MODULE_DNS = "dns_hygiene"
MODULE_UNPERMITTED = "port_sweep"

# Any 64 hex characters will satisfy the sha256 check constraint; the real value
# is the hash of the signed PDF.
FAKE_DOCUMENT_HASH = "a" * 64

# Distinguishes "argument not given" from "given as None". Without it, a test
# asking for an unverified asset with verified_at=None would silently get the
# verified default, and would pass for the wrong reason.
UNSET: object = object()


@pytest.fixture(scope="session")
def owner_engine() -> Iterator[Engine]:
    engine = create_owner_engine(config.test_owner_database_url())
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture(scope="session")
def migrated_database(owner_engine: Engine) -> None:
    """Rebuild the test database from the migrations, once per session.

    The schema is dropped and recreated rather than merely migrated, so a stale
    object left over from an earlier run cannot make a broken migration look
    fine. Running the real migrations (rather than `metadata.create_all`) is
    deliberate too: the policies and triggers only exist in the migrations, so
    create_all would produce a schema with none of the guarantees under test.
    """
    with owner_engine.begin() as connection:
        connection.execute(text("DROP SCHEMA IF EXISTS app CASCADE"))
        connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        connection.execute(text("CREATE SCHEMA public"))
        # Recreating `public` by hand loses the grant every database normally
        # starts with, and without it the application role cannot see the schema
        # its tables live in.
        connection.execute(text("GRANT USAGE ON SCHEMA public TO PUBLIC"))

    alembic_config = AlembicConfig(os.path.join(PROJECT_ROOT, "alembic.ini"))
    alembic_config.set_main_option(
        "script_location", os.path.join(PROJECT_ROOT, "alembic")
    )
    # env.py reads this; it is what keeps the migrations pointed at the test
    # database rather than the development one.
    os.environ["RVP_MIGRATION_DATABASE_URL"] = config.test_owner_database_url()
    command.upgrade(alembic_config, "head")


@pytest.fixture(scope="session")
def app_engine(migrated_database: None) -> Iterator[Engine]:
    engine = create_app_engine(config.test_app_database_url())
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture(autouse=True)
def clean_tables(owner_engine: Engine, migrated_database: None) -> None:
    """Empty every table before each test.

    `audit_event` refuses TRUNCATE by trigger - that is the guarantee this whole
    schema is built around - so the trigger is switched off for the length of
    the truncate and switched straight back on. This is the one place in the
    project that does that, it runs as the table owner, and it is why
    tests/test_audit_append_only.py checks the trigger is in force afterwards.
    """
    with owner_engine.begin() as connection:
        connection.execute(
            text("ALTER TABLE audit_event DISABLE TRIGGER audit_event_no_truncate")
        )
        connection.execute(
            text(
                "TRUNCATE finding, scan_target, scan, audit_event, asset, "
                "scope_agreement, user_account, organisation CASCADE"
            )
        )
        connection.execute(
            text("ALTER TABLE audit_event ENABLE TRIGGER audit_event_no_truncate")
        )


@pytest.fixture
def owner_session(owner_engine: Engine) -> Iterator[Session]:
    """A BYPASSRLS session, for building fixtures and for unfiltered assertions."""
    factory = session_factory(owner_engine)
    session = factory()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def app_session(app_engine: Engine) -> Callable[[UUID], Session]:
    """Factory for organisation-scoped sessions, as a request would get one.

    Used as a context manager so the commit-or-rollback behaviour under test is
    the real one:

        with app_session(org.id) as session:
            ...
    """
    factory = session_factory(app_engine)

    @contextmanager
    def _scoped(org_id: UUID) -> Iterator[Session]:
        with org_scoped_session(org_id, factory) as session:
            yield session

    return _scoped


@pytest.fixture
def make_org(owner_session: Session) -> Callable[..., Organisation]:
    def _make(
        legal_name: str | None = None, parent: Organisation | None = None
    ) -> Organisation:
        org = Organisation(
            legal_name=legal_name or f"Org {uuid4().hex[:8]} Ltd",
            parent_org_id=parent.id if parent is not None else None,
        )
        owner_session.add(org)
        # Committed, not just flushed: the application session is a separate
        # connection and would not see an uncommitted row.
        owner_session.commit()
        return org

    return _make


@pytest.fixture
def make_agreement(owner_session: Session) -> Callable[..., ScopeAgreement]:
    def _make(
        org: Organisation,
        *,
        permitted_modules: list[str] | None = None,
        valid_from: datetime | None = None,
        valid_until: datetime | None = None,
        signed_at: datetime | None = None,
        revoked_at: datetime | None = None,
    ) -> ScopeAgreement:
        agreement = ScopeAgreement(
            org_id=org.id,
            signatory_name="A Director",
            signatory_email="director@example.com",
            signed_at=signed_at or (NOW - 30 * DAY),
            valid_from=valid_from if valid_from is not None else NOW - 7 * DAY,
            valid_until=valid_until if valid_until is not None else NOW + 358 * DAY,
            permitted_modules=(
                permitted_modules
                if permitted_modules is not None
                else [MODULE_TLS, MODULE_DNS]
            ),
            document_hash=FAKE_DOCUMENT_HASH,
            revoked_at=revoked_at,
        )
        owner_session.add(agreement)
        owner_session.commit()
        return agreement

    return _make


@pytest.fixture
def make_asset(owner_session: Session) -> Callable[..., Asset]:
    def _make(
        org: Organisation,
        *,
        identifier: str | None = None,
        kind: AssetKind = AssetKind.DOMAIN,
        verified_at: datetime | None | object = UNSET,
        verification_expires_at: datetime | None = None,
        verification_method: VerificationMethod | None = VerificationMethod.DNS_TXT,
        business_criticality: BusinessCriticality = BusinessCriticality.NORMAL,
    ) -> Asset:
        """Create an asset. Verified by default unless `verified_at=None`.

        The default is a verified asset because most tests are about some *other*
        condition; the unverified cases say so explicitly.
        """
        asset = Asset(
            org_id=org.id,
            kind=kind,
            identifier=identifier or f"{uuid4().hex[:10]}.example.com",
            verification_method=verification_method,
            verification_token="rvp-verify-" + uuid4().hex[:12],
            verified_at=NOW - 14 * DAY if verified_at is UNSET else verified_at,
            verification_expires_at=verification_expires_at,
            business_criticality=business_criticality,
        )
        owner_session.add(asset)
        owner_session.commit()
        return asset

    return _make
