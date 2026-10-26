"""Alembic environment.

Migrations run as the *owner* role, not the application role: they create
tables, enum types, policies and triggers, none of which the application role is
allowed to do. The URL therefore comes from `config.owner_database_url()` unless
something overrides it - see `RVP_MIGRATION_DATABASE_URL`, which the test suite
uses to point migrations at the test database.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

# Importing the models is what populates Base.metadata; without it autogenerate
# would conclude that every table should be dropped.
import app.models  # noqa: F401
from alembic import context
from app import config as app_config
from app.db.base import Base

alembic_config = context.config

if alembic_config.config_file_name is not None:
    fileConfig(alembic_config.config_file_name)

target_metadata = Base.metadata


def _database_url() -> str:
    return os.environ.get(
        "RVP_MIGRATION_DATABASE_URL", app_config.owner_database_url()
    )


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    section = alembic_config.get_section(alembic_config.config_ini_section) or {}
    section["sqlalchemy.url"] = _database_url()

    connectable = engine_from_config(
        section, prefix="sqlalchemy.", poolclass=pool.NullPool
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()

    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
