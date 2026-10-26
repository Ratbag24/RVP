"""The authorisation gate: one test per way it can say no, and two ways it says yes.

Each test runs the gate on an application session with an organisation context
set, i.e. the connection a request would really use, with row level security in
force. The fixtures are built on the owner connection because provisioning an
organisation is administrative work, not something a request does.

Every test here also asserts an audit row, because "every call writes an
audit_event" is a property of the gate rather than of any one decision.
"""

from __future__ import annotations

from collections import Counter
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.authorisation import gate
from app.models import AuditEvent
from tests.conftest import DAY, MODULE_TLS, MODULE_UNPERMITTED, NOW


def audit_rows(owner_session) -> list[AuditEvent]:
    """Every audit row, unfiltered - the owner session holds BYPASSRLS.

    Read through a fresh transaction each time so rows committed by the
    application session since the last read are visible.
    """
    owner_session.rollback()
    return list(
        owner_session.scalars(select(AuditEvent).order_by(AuditEvent.occurred_at))
    )


def test_permitted_when_everything_is_valid(
    app_session, owner_session, make_org, make_agreement, make_asset
):
    org = make_org()
    agreement = make_agreement(org, permitted_modules=[MODULE_TLS])
    asset = make_asset(org)

    with app_session(org.id) as session:
        decision = gate.check_authorisation(
            session, org.id, asset.id, MODULE_TLS, NOW, actor="worker:tls_config"
        )

    assert decision.permitted is True
    assert decision.authorisation_id == agreement.id
    assert decision.reason.startswith(gate.REASON_PERMITTED)

    (event,) = audit_rows(owner_session)
    assert event.action == gate.ACTION_PERMITTED
    assert event.actor == "worker:tls_config"
    assert event.asset_id == asset.id
    # The agreement that permitted it is on the audit row, not just in the
    # decision: this is the link that makes a scan traceable to a signature.
    assert event.authorisation_id == agreement.id
    assert event.detail["module"] == MODULE_TLS
    assert event.detail["permitted"] is True


def test_refused_when_no_agreement_exists(
    app_session, owner_session, make_org, make_asset
):
    org = make_org()
    asset = make_asset(org)

    with app_session(org.id) as session:
        decision = gate.check_authorisation(
            session, org.id, asset.id, MODULE_TLS, NOW
        )

    assert decision.permitted is False
    assert decision.authorisation_id is None
    assert decision.reason.startswith(gate.REASON_NO_AGREEMENT)

    (event,) = audit_rows(owner_session)
    assert event.action == gate.ACTION_REFUSED
    assert event.authorisation_id is None


def test_refused_when_agreement_expired_before_at_time(
    app_session, owner_session, make_org, make_agreement, make_asset
):
    org = make_org()
    make_agreement(
        org,
        permitted_modules=[MODULE_TLS],
        valid_from=NOW - 400 * DAY,
        valid_until=NOW - DAY,
    )
    asset = make_asset(org)

    with app_session(org.id) as session:
        decision = gate.check_authorisation(
            session, org.id, asset.id, MODULE_TLS, NOW
        )

    assert decision.permitted is False
    assert decision.reason.startswith(gate.REASON_AGREEMENT_EXPIRED)
    assert audit_rows(owner_session)[0].action == gate.ACTION_REFUSED


def test_refused_when_agreement_not_yet_valid_at_at_time(
    app_session, owner_session, make_org, make_agreement, make_asset
):
    org = make_org()
    make_agreement(
        org,
        permitted_modules=[MODULE_TLS],
        valid_from=NOW + DAY,
        valid_until=NOW + 366 * DAY,
    )
    asset = make_asset(org)

    with app_session(org.id) as session:
        decision = gate.check_authorisation(
            session, org.id, asset.id, MODULE_TLS, NOW
        )

    assert decision.permitted is False
    assert decision.reason.startswith(gate.REASON_AGREEMENT_NOT_YET_VALID)
    assert audit_rows(owner_session)[0].action == gate.ACTION_REFUSED


def test_refused_when_agreement_revoked(
    app_session, owner_session, make_org, make_agreement, make_asset
):
    """Revocation beats a valid window: the customer withdrew permission."""
    org = make_org()
    make_agreement(org, permitted_modules=[MODULE_TLS], revoked_at=NOW - DAY)
    asset = make_asset(org)

    with app_session(org.id) as session:
        decision = gate.check_authorisation(
            session, org.id, asset.id, MODULE_TLS, NOW
        )

    assert decision.permitted is False
    assert decision.reason.startswith(gate.REASON_AGREEMENT_REVOKED)
    assert audit_rows(owner_session)[0].action == gate.ACTION_REFUSED


def test_permitted_before_a_later_revocation(
    app_session, make_org, make_agreement, make_asset
):
    """An agreement revoked tomorrow still authorised a scan that ran today.

    This is the case the explicit `at_time` parameter exists for: asking about a
    past moment must give the answer that was true then, not the answer that is
    true now.
    """
    org = make_org()
    agreement = make_agreement(
        org, permitted_modules=[MODULE_TLS], revoked_at=NOW + DAY
    )
    asset = make_asset(org)

    with app_session(org.id) as session:
        decision = gate.check_authorisation(
            session, org.id, asset.id, MODULE_TLS, NOW
        )

    assert decision.permitted is True
    assert decision.authorisation_id == agreement.id


def test_refused_when_module_not_in_permitted_modules(
    app_session, owner_session, make_org, make_agreement, make_asset
):
    org = make_org()
    make_agreement(org, permitted_modules=[MODULE_TLS])
    asset = make_asset(org)

    with app_session(org.id) as session:
        decision = gate.check_authorisation(
            session, org.id, asset.id, MODULE_UNPERMITTED, NOW
        )

    assert decision.permitted is False
    assert decision.authorisation_id is None
    assert decision.reason.startswith(gate.REASON_MODULE_NOT_PERMITTED)
    # The refusal names what the customer did permit, which is the first thing
    # support will be asked.
    assert MODULE_TLS in decision.reason
    assert audit_rows(owner_session)[0].detail["module"] == MODULE_UNPERMITTED


def test_refused_when_asset_never_verified(
    app_session, owner_session, make_org, make_agreement, make_asset
):
    org = make_org()
    make_agreement(org, permitted_modules=[MODULE_TLS])
    asset = make_asset(org, verified_at=None, verification_method=None)

    with app_session(org.id) as session:
        decision = gate.check_authorisation(
            session, org.id, asset.id, MODULE_TLS, NOW
        )

    assert decision.permitted is False
    # A signed agreement is not enough on its own: scanning an asset the
    # customer has not proved they control could be unauthorised access to
    # someone else's system.
    assert decision.reason.startswith(gate.REASON_ASSET_NOT_VERIFIED)
    assert audit_rows(owner_session)[0].action == gate.ACTION_REFUSED


def test_refused_when_asset_verification_expired(
    app_session, owner_session, make_org, make_agreement, make_asset
):
    org = make_org()
    make_agreement(org, permitted_modules=[MODULE_TLS])
    asset = make_asset(
        org,
        verified_at=NOW - 100 * DAY,
        verification_expires_at=NOW - DAY,
    )

    with app_session(org.id) as session:
        decision = gate.check_authorisation(
            session, org.id, asset.id, MODULE_TLS, NOW
        )

    assert decision.permitted is False
    assert decision.reason.startswith(gate.REASON_VERIFICATION_EXPIRED)
    assert audit_rows(owner_session)[0].action == gate.ACTION_REFUSED


def test_refused_when_verification_was_not_yet_in_place_at_at_time(
    app_session, make_org, make_agreement, make_asset
):
    """Verified since, but not then. The mirror image of expiry."""
    org = make_org()
    make_agreement(org, permitted_modules=[MODULE_TLS], valid_from=NOW - 30 * DAY)
    asset = make_asset(org, verified_at=NOW + DAY)

    with app_session(org.id) as session:
        decision = gate.check_authorisation(
            session, org.id, asset.id, MODULE_TLS, NOW
        )

    assert decision.permitted is False
    assert decision.reason.startswith(gate.REASON_VERIFICATION_NOT_YET_EFFECTIVE)


def test_refused_when_asset_belongs_to_a_different_org(
    app_session, owner_session, make_org, make_agreement, make_asset
):
    """Org A asks about org B's asset, with everything else in order.

    The refusal says "no such asset", not "that is someone else's", because row
    level security removed the row before the gate ever saw it - and because
    confirming that an id exists in another tenant is itself a disclosure. Org B
    has a valid agreement and a verified asset here, so the only thing stopping
    this is the isolation.
    """
    org_a = make_org(legal_name="A Ltd")
    org_b = make_org(legal_name="B Ltd")
    make_agreement(org_b, permitted_modules=[MODULE_TLS])
    asset_b = make_asset(org_b)

    with app_session(org_a.id) as session:
        decision = gate.check_authorisation(
            session, org_a.id, asset_b.id, MODULE_TLS, NOW
        )

    assert decision.permitted is False
    assert decision.authorisation_id is None
    assert decision.reason.startswith(gate.REASON_NO_SUCH_ASSET)

    # The refusal is logged against the organisation that asked, and does not
    # name org B's asset - a refusal must not become a way to confirm that an
    # asset id exists somewhere else.
    (event,) = audit_rows(owner_session)
    assert event.org_id == org_a.id
    assert event.asset_id is None
    assert event.detail["requested_asset_id"] == str(asset_b.id)


def test_refused_when_asset_belongs_to_a_sibling_org(
    app_session, owner_session, make_org, make_agreement, make_asset
):
    """The ownership check is not just row level security in disguise.

    A managed service provider can see both of its clients, so the row *is*
    visible to this session. The gate still refuses, because the organisation
    named in the call does not own the asset and is not above it.
    """
    msp = make_org(legal_name="MSP Ltd")
    client_one = make_org(legal_name="Client One Ltd", parent=msp)
    client_two = make_org(legal_name="Client Two Ltd", parent=msp)
    make_agreement(client_two, permitted_modules=[MODULE_TLS])
    asset_of_two = make_asset(client_two)

    with app_session(msp.id) as session:
        decision = gate.check_authorisation(
            session, client_one.id, asset_of_two.id, MODULE_TLS, NOW
        )

    assert decision.permitted is False
    assert decision.reason.startswith(gate.REASON_ASSET_OTHER_ORG)
    assert audit_rows(owner_session)[0].action == gate.ACTION_REFUSED


def test_permitted_for_parent_msp_scanning_a_child_org_asset(
    app_session, owner_session, make_org, make_agreement, make_asset
):
    """An MSP scans its client's verified asset, under the client's agreement.

    Note which organisation signed: the authority comes from the client, the
    organisation that owns the asset. An MSP's own agreement covers the MSP's own
    assets and does not reach down into a client's - the client has to have
    signed, even if the MSP's staff are the signatory.
    """
    msp = make_org(legal_name="MSP Ltd")
    client = make_org(legal_name="Client Ltd", parent=msp)
    agreement = make_agreement(client, permitted_modules=[MODULE_TLS])
    asset = make_asset(client)

    with app_session(msp.id) as session:
        decision = gate.check_authorisation(
            session, msp.id, asset.id, MODULE_TLS, NOW
        )

    assert decision.permitted is True
    assert decision.authorisation_id == agreement.id

    # The audit row is stamped with the client's organisation, so the client
    # sees in their own log that their asset was scanned. The hierarchy policy
    # means the MSP can see it too; the requesting org is in `detail`.
    (event,) = audit_rows(owner_session)
    assert event.org_id == client.id
    assert event.detail["requesting_org_id"] == str(msp.id)


def test_permitted_for_grandchild_org_asset(
    app_session, make_org, make_agreement, make_asset
):
    """The hierarchy is recursive, not one level deep."""
    group = make_org(legal_name="Group Ltd")
    msp = make_org(legal_name="MSP Ltd", parent=group)
    client = make_org(legal_name="Client Ltd", parent=msp)
    agreement = make_agreement(client, permitted_modules=[MODULE_TLS])
    asset = make_asset(client)

    with app_session(group.id) as session:
        decision = gate.check_authorisation(
            session, group.id, asset.id, MODULE_TLS, NOW
        )

    assert decision.permitted is True
    assert decision.authorisation_id == agreement.id


def test_refused_for_a_child_scanning_its_parents_asset(
    app_session, make_org, make_agreement, make_asset
):
    """The hierarchy only descends. A client cannot scan its provider."""
    msp = make_org(legal_name="MSP Ltd")
    client = make_org(legal_name="Client Ltd", parent=msp)
    make_agreement(msp, permitted_modules=[MODULE_TLS])
    msp_asset = make_asset(msp)

    with app_session(client.id) as session:
        decision = gate.check_authorisation(
            session, client.id, msp_asset.id, MODULE_TLS, NOW
        )

    assert decision.permitted is False
    assert decision.reason.startswith(gate.REASON_NO_SUCH_ASSET)


def test_refused_for_an_unknown_asset_id(app_session, owner_session, make_org):
    org = make_org()
    missing = uuid4()

    with app_session(org.id) as session:
        decision = gate.check_authorisation(session, org.id, missing, MODULE_TLS, NOW)

    assert decision.permitted is False
    assert decision.reason.startswith(gate.REASON_NO_SUCH_ASSET)
    # Still audited. An attempt to scan something that does not exist is exactly
    # the kind of thing worth having a record of.
    (event,) = audit_rows(owner_session)
    assert event.action == gate.ACTION_REFUSED
    assert event.detail["requested_asset_id"] == str(missing)


def test_agreement_window_is_half_open(
    app_session, make_org, make_agreement, make_asset
):
    """`valid_from` inclusive, `valid_until` exclusive.

    Pinned by a test because an off-by-one-instant at a boundary is the kind of
    thing that is argued about later, and because both boundaries must resolve
    against the customer.
    """
    org = make_org()
    make_agreement(
        org, permitted_modules=[MODULE_TLS], valid_from=NOW, valid_until=NOW + DAY
    )
    asset = make_asset(org, verified_at=NOW - DAY)

    with app_session(org.id) as session:
        at_start = gate.check_authorisation(session, org.id, asset.id, MODULE_TLS, NOW)
        at_end = gate.check_authorisation(
            session, org.id, asset.id, MODULE_TLS, NOW + DAY
        )

    assert at_start.permitted is True, "valid_from is inclusive"
    assert at_end.permitted is False, "valid_until is exclusive"
    assert at_end.reason.startswith(gate.REASON_AGREEMENT_EXPIRED)


def test_most_recently_signed_permitting_agreement_wins(
    app_session, make_org, make_agreement, make_asset
):
    """Where two agreements both permit the scan, the later signature governs."""
    org = make_org()
    make_agreement(
        org, permitted_modules=[MODULE_TLS], signed_at=NOW - 100 * DAY
    )
    newer = make_agreement(
        org, permitted_modules=[MODULE_TLS], signed_at=NOW - 2 * DAY
    )
    asset = make_asset(org)

    with app_session(org.id) as session:
        decision = gate.check_authorisation(
            session, org.id, asset.id, MODULE_TLS, NOW
        )

    assert decision.permitted is True
    assert decision.authorisation_id == newer.id


def test_naive_at_time_is_rejected_outright(
    app_session, make_org, make_agreement, make_asset
):
    """A naive datetime is a bug in the caller, not a refusal.

    Returning `permitted=False` would hide the mistake behind a plausible-looking
    decision; raising makes it impossible to ignore.
    """
    org = make_org()
    make_agreement(org, permitted_modules=[MODULE_TLS])
    asset = make_asset(org)

    with app_session(org.id) as session:
        with pytest.raises(ValueError, match="timezone-aware"):
            gate.check_authorisation(
                session, org.id, asset.id, MODULE_TLS, NOW.replace(tzinfo=None)
            )


def test_every_decision_writes_exactly_one_audit_event(
    app_session, owner_session, make_org, make_agreement, make_asset
):
    """The brief's rule, checked as a rule rather than one test at a time.

    Six calls across permitted and refused paths, six audit rows. A gate that
    logs only its refusals, or only its approvals, is not an audit trail.
    """
    org = make_org()
    make_agreement(org, permitted_modules=[MODULE_TLS])
    verified = make_asset(org)
    unverified = make_asset(org, verified_at=None, verification_method=None)
    other_org = make_org()
    other_asset = make_asset(other_org)

    calls = [
        (org.id, verified.id, MODULE_TLS, NOW),                 # permitted
        (org.id, verified.id, MODULE_UNPERMITTED, NOW),         # module refused
        (org.id, verified.id, MODULE_TLS, NOW - 400 * DAY),     # outside window
        (org.id, unverified.id, MODULE_TLS, NOW),               # unverified
        (org.id, uuid4(), MODULE_TLS, NOW),                      # unknown asset
        (org.id, other_asset.id, MODULE_TLS, NOW),               # other tenant
    ]

    with app_session(org.id) as session:
        decisions = [
            gate.check_authorisation(session, *call) for call in calls
        ]

    events = audit_rows(owner_session)
    assert len(events) == len(calls)
    # Compared as a multiset: all six rows share one transaction, so now() gives
    # them identical occurred_at values and there is no insertion order to rely
    # on. What matters is that each decision produced a row of the right kind.
    assert Counter(e.action for e in events) == Counter(
        gate.ACTION_PERMITTED if d.permitted else gate.ACTION_REFUSED
        for d in decisions
    )
    assert {e.detail["reason"] for e in events} == {d.reason for d in decisions}
    # Every event carries the reason it recorded, so the log explains itself
    # without needing the code that produced it.
    assert all(e.detail["reason"] for e in events)


def test_asking_on_behalf_of_an_unrelated_org_is_a_caller_error(
    app_session, owner_session, make_org, make_agreement, make_asset
):
    """A session may only ask about its own organisation, or one beneath it.

    Without this guard the call would get as far as the audit write and be
    refused by the row level security policy - the right outcome, since that row
    would be a cross-tenant write, but reported as a problem with the audit
    table rather than with the question. Raising keeps the diagnosis where the
    mistake is.
    """
    org_a = make_org(legal_name="A Ltd")
    org_b = make_org(legal_name="B Ltd")
    make_agreement(org_b, permitted_modules=[MODULE_TLS])
    asset_b = make_asset(org_b)

    with app_session(org_a.id) as session:
        with pytest.raises(ValueError, match="does not cover"):
            gate.check_authorisation(session, org_b.id, asset_b.id, MODULE_TLS, NOW)

    # No decision was taken, so there is nothing to audit.
    assert audit_rows(owner_session) == []


def test_a_privileged_session_with_no_org_context_may_still_ask(
    owner_session, make_org, make_agreement, make_asset
):
    """The scheduler's path: an administrative session, no organisation context.

    Such a session holds BYPASSRLS and is already outside the policies, so the
    context check exempts it. The gate's own ownership, agreement, module and
    verification checks all still apply - which is the point of having them in
    the gate rather than relying on the policies alone.
    """
    org = make_org()
    agreement = make_agreement(org, permitted_modules=[MODULE_TLS])
    asset = make_asset(org)

    decision = gate.check_authorisation(
        owner_session, org.id, asset.id, MODULE_TLS, NOW, actor="system"
    )
    owner_session.commit()

    assert decision.permitted is True
    assert decision.authorisation_id == agreement.id
    assert audit_rows(owner_session)[0].actor == "system"
