"""Database connection settings, read from the environment.

There are two URLs rather than one because there are two database roles, and
the difference between them is what makes row level security real:

  owner  - owns the tables, runs migrations, holds BYPASSRLS. Policies do not
           constrain it. Use it for migrations and administrative work only.
  app    - what request handling connects as. No BYPASSRLS, not the table
           owner, so every policy in the schema applies to it.

If the application ever connects with the owner URL, the isolation guarantees
in this schema quietly evaporate: the policies stay in place but stop filtering
anything. Hence the separate names, and hence `app_database_url()` being the
one the session helpers default to.
"""

from __future__ import annotations

import os

# Localhost defaults match scripts/setup_db.sh so a fresh checkout runs without
# a .env file. They are development credentials and are not secret.
_DEFAULT_OWNER_URL = "postgresql+psycopg://rvp_owner:rvp_owner@127.0.0.1:5432/rvp"
_DEFAULT_APP_URL = "postgresql+psycopg://rvp_app:rvp_app@127.0.0.1:5432/rvp"
_DEFAULT_TEST_OWNER_URL = "postgresql+psycopg://rvp_owner:rvp_owner@127.0.0.1:5432/rvp_test"
_DEFAULT_TEST_APP_URL = "postgresql+psycopg://rvp_app:rvp_app@127.0.0.1:5432/rvp_test"


def owner_database_url() -> str:
    """URL for the migration/admin role. Never use this to serve a request."""
    return os.environ.get("RVP_OWNER_DATABASE_URL", _DEFAULT_OWNER_URL)


def app_database_url() -> str:
    """URL for the unprivileged application role."""
    return os.environ.get("RVP_APP_DATABASE_URL", _DEFAULT_APP_URL)


def test_owner_database_url() -> str:
    return os.environ.get("RVP_TEST_OWNER_DATABASE_URL", _DEFAULT_TEST_OWNER_URL)


def test_app_database_url() -> str:
    return os.environ.get("RVP_TEST_APP_DATABASE_URL", _DEFAULT_TEST_APP_URL)


def app_role() -> str:
    """The role name the migration grants table privileges to."""
    return os.environ.get("RVP_APP_ROLE", "rvp_app")
