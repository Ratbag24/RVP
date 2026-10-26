"""Engines, session factories, and the org-scoped session the policies rely on.

Every row level security policy in this schema keys on the session variable
`app.current_org_id`. A connection that has not had it set sees nothing at all,
which is the correct default: a missing tenant context should produce an empty
result, never the whole table.

Two details here are easy to get wrong and both are deliberate:

1.  The variable is set with `set_config(..., is_local => true)`, i.e. scoped to
    the current *transaction*, not the session. Connections come from a pool and
    outlive a request; a session-scoped setting would leak one tenant's identity
    into the next request that happened to get the same connection.

2.  Because the setting dies with the transaction, it is reapplied on every
    `after_begin` event rather than once at the start. A session that commits
    and then keeps working starts a new transaction, and without this listener
    that second transaction would run with no tenant context and see nothing.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from uuid import UUID

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from app import config

_SET_ORG_SQL = text("SELECT set_config('app.current_org_id', :org_id, true)")


def create_app_engine(url: str | None = None, **kwargs: Any) -> Engine:
    """Engine for the unprivileged application role - the normal case."""
    return create_engine(url or config.app_database_url(), **kwargs)


def create_owner_engine(url: str | None = None, **kwargs: Any) -> Engine:
    """Engine for the owner role: migrations, provisioning, tests fixtures.

    This role holds BYPASSRLS. Anything it reads is unfiltered by tenant, so
    keep its use to code paths that are explicitly cross-tenant.
    """
    return create_engine(url or config.owner_database_url(), **kwargs)


def session_factory(engine: Engine) -> sessionmaker[Session]:
    # expire_on_commit=False keeps already-loaded objects usable after a commit,
    # which spares callers a reload purely to read an attribute they just wrote.
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


def bind_org_context(session: Session, org_id: UUID) -> None:
    """Make `session` run every transaction as `org_id`.

    Applies to the transaction that is open now (if any) and to every subsequent
    one, for as long as the session lives. See the module docstring for why both
    halves are needed.
    """
    org_text = str(org_id)

    @event.listens_for(session, "after_begin")
    def _apply_org_context(  # noqa: ANN202 - SQLAlchemy event signature
        _session: Session, _transaction: Any, connection: Any
    ) -> None:
        connection.execute(_SET_ORG_SQL, {"org_id": org_text})

    # A transaction may already be open (SQLAlchemy begins lazily, but a caller
    # may have touched the session first), in which case after_begin has been
    # and gone for it and the setting has to be applied directly.
    if session.in_transaction():
        session.execute(_SET_ORG_SQL, {"org_id": org_text})


@contextmanager
def org_scoped_session(
    org_id: UUID, factory: sessionmaker[Session]
) -> Iterator[Session]:
    """A session that can only see `org_id` and the orgs beneath it.

    This is the single way application code should obtain a session. It commits
    on a clean exit and rolls back on an exception, so a half-applied unit of
    work cannot escape.
    """
    session = factory()
    bind_org_context(session, org_id)
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def make_session_dependency(factory: sessionmaker[Session]):
    """Build the per-request dependency, given a session factory.

    Kept free of any FastAPI import so this module stays importable (and
    testable) without a web framework. The returned callable takes the caller's
    org id and yields a scoped session, which is exactly the shape FastAPI's
    `Depends` wants:

        session_dep = make_session_dependency(session_factory(create_app_engine()))

        def get_session(org_id: UUID = Depends(current_org_id)):
            yield from session_dep(org_id)

    The org id must come from the verified request identity - a signed session or
    a validated token - and never from a request body or query parameter, or the
    whole isolation scheme reduces to asking the caller which tenant they would
    like to be.
    """

    def dependency(org_id: UUID) -> Iterator[Session]:
        with org_scoped_session(org_id, factory) as session:
            yield session

    return dependency
