# Remote vulnerability assessment platform — step 1

The database schema and the authorisation gate. Nothing else.

This platform **detects and advises**. It does not exploit, and it does not
change customer systems. Every network action must be traceable to a written
authorisation — under the Computer Misuse Act 1990 that traceability is what
separates a service from an offence. That is why the gate is built, and proven,
before a single line of code exists that could send a packet.

There are no scan modules here, no network code, no job queue, no web UI and no
API endpoints. Those come after this part is correct.

## What is in here

| Path | What it is |
| --- | --- |
| `app/models.py` | The eight tables, with the reasoning for each decision in comments |
| `app/enums.py` | Every enumerated vocabulary, in one place |
| `app/db/session.py` | Engines, and the organisation-scoped session the policies depend on |
| `app/authorisation/gate.py` | The gate: pure logic, no HTTP, no network |
| `alembic/versions/0001_*` | Tables, enum types, constraints |
| `alembic/versions/0002_*` | Row level security, the hierarchy helper, the append-only trigger |
| `scripts/setup_db.sh` | Creates the two roles and two databases |
| `tests/` | 57 tests against a real Postgres |

## Local setup

Needs Postgres 16 and Python 3.12. The commands below assume you can reach
Postgres as a superuser (`sudo -u postgres` on Debian/Ubuntu).

```bash
# 1. Roles and databases. Creates rvp_owner and rvp_app, rvp and rvp_test.
sudo -u postgres ./scripts/setup_db.sh

# 2. Python environment.
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt

# 3. Schema.
.venv/bin/alembic upgrade head

# 4. Tests.
.venv/bin/python -m pytest
```

Connection details come from the environment, with localhost defaults that match
the setup script, so a fresh checkout runs without configuration. To point at
something else, copy `.env.example` and export the variables in it — there is no
dotenv dependency, deliberately; `set -a; . ./.env; set +a` is enough.

### Running the tests

```bash
.venv/bin/python -m pytest              # everything
.venv/bin/python -m pytest -k gate      # just the gate
.venv/bin/python -m pytest -q tests/test_row_level_security.py
```

The suite rebuilds `rvp_test` from the migrations at the start of each run — it
drops the schema, runs `alembic upgrade head`, and empties the tables between
tests. It does not touch the `rvp` development database.

**The tests need a real Postgres, not SQLite.** Row level security, the
append-only trigger, `citext`, native enum types and the recursive hierarchy
function are all Postgres features. A suite that passed against SQLite would
have quietly stopped testing every part of this most likely to be wrong.

## The two database roles

This is the one piece of setup worth understanding before reading anything else,
because it is what makes the isolation real rather than decorative.

Row level security does **not** apply to a superuser, to a role holding
`BYPASSRLS`, or — unless `FORCE ROW LEVEL SECURITY` is set — to the table owner.
So there are two roles:

- **`rvp_owner`** owns the tables, runs the migrations, and holds `BYPASSRLS`.
  Policies do not constrain it. Use it for migrations, provisioning, and nothing
  else.
- **`rvp_app`** is what the application connects as. Not a superuser, not the
  table owner, no `BYPASSRLS`: every policy applies to it in full.

If the application ever connects with the owner URL, every policy stays in place
and silently stops filtering anything. `tests/test_row_level_security.py` opens
by asserting that the test connection is not a superuser, does not bypass RLS,
and does not own the tables — otherwise the rest of that file would pass without
proving anything.

## Row level security

Every policy keys on the session variable `app.current_org_id`, set per
*transaction* (not per session) by `org_scoped_session` in `app/db/session.py`.
Transaction-scoped matters: connections are pooled and outlive a request, and a
session-scoped setting would leak one tenant's identity into the next request
handed the same connection. Because the setting dies with its transaction, the
helper reapplies it on every `after_begin`, so a unit of work that commits
halfway through keeps working.

A connection with no organisation context set sees **nothing at all**. That is
the correct way for this to fail.

The managed service provider hierarchy lives in exactly one place:
`app.org_in_scope(target_org_id, root_org_id)`, a recursive SQL function created
by migration 0002. Every policy calls it, and so does the gate's ownership
check, so the two cannot drift apart. It descends only — a provider sees its
clients and its clients' clients; a client never sees its provider.

That function is `SECURITY DEFINER`, which is load-bearing rather than
decorative: it reads `organisation`, and `organisation` has a policy that calls
it. Run as the caller, that is infinite recursion; run as the owner — which
holds `BYPASSRLS` — the read inside the function is not subject to policies, so
there is nothing to recurse into.

### Wiring it into FastAPI (step 2)

`app/db/session.py` has no FastAPI import, so it stays testable without a web
framework. The dependency is three lines:

```python
session_dep = make_session_dependency(session_factory(create_app_engine()))

def get_session(org_id: UUID = Depends(current_org_id)):
    yield from session_dep(org_id)
```

`current_org_id` must come from the verified request identity — a signed session
or a validated token — and never from a request body or query parameter, or the
whole scheme reduces to asking the caller which tenant they would like to be.

## The authorisation gate

```python
check_authorisation(session, org_id, asset_id, module_name, at_time) -> AuthorisationDecision
```

Refuses unless **all** of the following hold at `at_time`:

1. The asset belongs to `org_id`, or to an organisation beneath it.
2. A scope agreement for the asset's **owning** organisation is active:
   `valid_from <= at_time < valid_until`, and not revoked at or before `at_time`.
3. `module_name` is in that agreement's `permitted_modules`.
4. The asset's ownership verification was in force at `at_time`.

Checks run in that order and the first failure is the reason returned — who owns
it, whether they authorised anything, whether they authorised *this*, and
whether they proved they own it. Returning the first failure rather than all of
them also stops the gate being used to enumerate another tenant's configuration.

**Every call writes an `audit_event`, permitted or refused.** It is the refusals
that prove the gate was working on the day somebody asks.

The session must be scoped to `org_id` or to an organisation above it. Asking on
behalf of an unrelated organisation is a caller bug and raises `ValueError`
rather than producing a refusal — without that check the call would reach the
audit write and be rejected by the policy, which is the right outcome reported
in the wrong place. An administrative session with no organisation context (the
scheduler's path) is exempt, and the gate's own four checks still apply to it.

`at_time` is a parameter rather than `datetime.now(UTC)` read inside the
function. It makes expiry testable without freezing the clock, and it forces
callers to be honest about which moment they are asking about: a scan that
started twenty minutes ago should be judged against the moment it started. A
naive `datetime` raises `ValueError` rather than returning a refusal — that is a
bug in the caller, not a fact about the customer's authorisation.

### Decisions you may want to revisit

Three judgement calls that the brief left open, flagged here because they are
the ones with consequences:

- **Authority comes from the organisation that owns the asset.** A provider
  scanning a client's domain relies on the agreement *that client* signed; the
  provider's own agreement does not reach down into a client's assets. The
  provider's staff may well be the signatory on it. If the commercial model
  needs an MSP to sign once on behalf of every client, that is a change to
  `_evaluate()` in the gate and a change worth taking legal advice on.
- **The audit row is stamped with the asset's owning organisation**, not the
  requesting one, so a client sees in their own log that their asset was
  scanned. The hierarchy policy means the provider sees it too, and the
  requesting org is recorded in `detail`.
- **The audit row is written on the caller's session and flushed, not
  committed.** The caller must commit — so a caller that refuses a scan must
  commit the refusal rather than abandoning the transaction. Writing it on a
  separate connection would survive a rollback, but could not see rows the
  caller has not committed yet, which would make the gate unusable inside an
  ordinary unit of work.

## The audit log

`audit_event` is append-only, enforced by a trigger that raises on `UPDATE`,
`DELETE` and `TRUNCATE` — the application is not relied on to behave. `TRUNCATE`
needs its own statement-level trigger, because it does not fire row-level ones;
without it "append-only" would have a single-command bypass.

There are two independent mechanisms, and the redundancy is the point: the
trigger refuses those commands for everyone, and the application role was never
granted `UPDATE` or `DELETE` on the table at all, so a dropped trigger still
leaves no route in. `tests/test_audit_append_only.py` attacks the table from the
*owner* connection — the most privileged one the project uses — and checks the
triggers are still enabled afterwards, because the test fixtures have to disable
the `TRUNCATE` one to clean up between tests.

## Migrations

```bash
.venv/bin/alembic upgrade head        # apply
.venv/bin/alembic downgrade base      # full reverse; verified, including enum drops
.venv/bin/alembic check               # confirm the models and the schema agree
```

Migrations run as `rvp_owner`, from `RVP_MIGRATION_DATABASE_URL` if set and
`RVP_OWNER_DATABASE_URL` otherwise. There is no `sqlalchemy.url` in
`alembic.ini`, so a committed connection string cannot be pointed at the wrong
database.

0001 is the shape of the data; 0002 is the security. Keeping them separate means
either can be read, or reverted, without the other.

Enum types are created explicitly in 0001 from the single list in
`app/enums.py`, and the models declare their enum columns with
`create_type=False`, so DDL stays in the migration where the order is visible.
Adding a value to an enum later needs an `ALTER TYPE` migration — the trade-off
taken for a vocabulary that must never hold a typo.

## Known gaps, deliberately left for later steps

- **Login cannot work through the application role yet.** `user_account` has row
  level security keyed on `org_id`, so looking up a user by email before any
  organisation context exists finds nothing. Authentication will need a
  `SECURITY DEFINER` lookup function or a privileged path; step 2.
- **`mfa_secret` is stored in plaintext.** It needs encrypting at rest once
  there is a key management story. Noted in `app/models.py` so it does not get
  forgotten.
- **`finding.severity` is stored, not computed.** The column and the vocabulary
  exist; the scoring that fills it arrives with the modules.
- **`fastapi` and `argon2-cffi` are in `requirements.txt` but unused by step 1
  code.** They are the declared stack for the web layer and for
  `password_hash`, and are listed so the dependency set does not change shape
  when step 2 lands.
