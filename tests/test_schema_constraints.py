"""The constraints the schema leans on, checked directly.

A constraint nobody has ever seen fire is a constraint you are only assuming
exists. These run on the owner connection because they are about the shape of
the data rather than about who can see it - the isolation tests live in
tests/test_row_level_security.py.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.enums import (
    FindingSeverity,
    FindingStatus,
    ScanStatus,
    ScanTriggerKind,
)
from app.models import Finding, Scan, ScanTarget, ScopeAgreement
from tests.conftest import DAY, MODULE_TLS, NOW


def make_scan(session, org, *, at_time=NOW) -> Scan:
    scan = Scan(
        org_id=org.id,
        trigger_kind=ScanTriggerKind.SCHEDULED,
        module_set=[MODULE_TLS],
        status=ScanStatus.COMPLETED,
        started_at=at_time,
        finished_at=at_time,
    )
    session.add(scan)
    session.commit()
    return scan


def make_finding(session, org, asset, scan, *, fingerprint="443/tcp:weak-cipher"):
    finding = Finding(
        org_id=org.id,
        asset_id=asset.id,
        rule_id="tls.weak_cipher_suite",
        fingerprint=fingerprint,
        title="Weak TLS cipher suite offered",
        description="The server offers a cipher suite with known weaknesses.",
        severity=FindingSeverity.MEDIUM,
        cve_ids=[],
        evidence={"port": 443, "suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
        first_seen_scan_id=scan.id,
        last_seen_scan_id=scan.id,
        first_seen_at=NOW,
        last_seen_at=NOW,
    )
    session.add(finding)
    session.commit()
    return finding


def test_a_finding_keeps_its_identity_across_scans(
    owner_session, make_org, make_asset
):
    """Findings are matched and updated, never deleted and reinserted.

    This is what trend reporting depends on: "open for 94 days" is only
    answerable if the row that was created on day one is the row still there on
    day ninety-four, with `first_seen_at` untouched.
    """
    org = make_org()
    asset = make_asset(org)
    first_scan = make_scan(owner_session, org)
    finding = make_finding(owner_session, org, asset, first_scan)
    original_id = finding.id

    # A later scan sees the same issue: update in place.
    second_scan = make_scan(owner_session, org, at_time=NOW + 7 * DAY)
    finding.last_seen_scan_id = second_scan.id
    finding.last_seen_at = NOW + 7 * DAY
    owner_session.commit()

    (stored,) = owner_session.scalars(select(Finding)).all()
    assert stored.id == original_id
    assert stored.first_seen_scan_id == first_scan.id
    assert stored.first_seen_at == NOW
    assert stored.last_seen_scan_id == second_scan.id
    assert stored.status is FindingStatus.OPEN


def test_the_same_issue_cannot_be_recorded_twice_on_one_asset(
    owner_session, make_org, make_asset
):
    """The unique constraint that makes the matching above the only option."""
    org = make_org()
    asset = make_asset(org)
    scan = make_scan(owner_session, org)
    make_finding(owner_session, org, asset, scan)

    with pytest.raises(IntegrityError, match="uq_finding_asset_id_rule_id_fingerprint"):
        make_finding(owner_session, org, asset, scan)
    owner_session.rollback()


def test_a_different_fingerprint_is_a_different_finding(
    owner_session, make_org, make_asset
):
    """Same rule, same asset, different specific issue - e.g. a second port."""
    org = make_org()
    asset = make_asset(org)
    scan = make_scan(owner_session, org)
    make_finding(owner_session, org, asset, scan, fingerprint="443/tcp:weak-cipher")
    make_finding(owner_session, org, asset, scan, fingerprint="8443/tcp:weak-cipher")

    assert len(owner_session.scalars(select(Finding)).all()) == 2


def test_an_identifier_is_unique_within_an_org_but_not_globally(
    owner_session, make_org, make_asset
):
    """Two customers may legitimately both claim the same domain."""
    org_a = make_org(legal_name="A Ltd")
    org_b = make_org(legal_name="B Ltd")
    make_asset(org_a, identifier="shared.example.com")
    # Allowed: a disputed or jointly managed domain is a real situation, and
    # resolving it is not the database's job.
    make_asset(org_b, identifier="shared.example.com")

    with pytest.raises(IntegrityError, match="uq_asset_org_id_identifier"):
        make_asset(org_a, identifier="shared.example.com")
    owner_session.rollback()


def test_an_agreement_window_must_be_ordered(owner_session, make_org, make_agreement):
    org = make_org()
    with pytest.raises(IntegrityError, match="validity_window_ordered"):
        make_agreement(org, valid_from=NOW, valid_until=NOW - DAY)
    owner_session.rollback()


def test_a_document_hash_must_look_like_sha256(owner_session, make_org):
    """The hash is the link between a row and the PDF somebody signed.

    A truncated or hex-invalid value would break that link silently, so the
    column refuses it rather than storing something that cannot be checked.
    """
    org = make_org()
    agreement = ScopeAgreement(
        org_id=org.id,
        signatory_name="A Director",
        signatory_email="director@example.com",
        signed_at=NOW,
        valid_from=NOW,
        valid_until=NOW + DAY,
        permitted_modules=[MODULE_TLS],
        document_hash="not-a-hash",
    )
    owner_session.add(agreement)
    with pytest.raises(IntegrityError, match="document_hash_is_sha256_hex"):
        owner_session.commit()
    owner_session.rollback()


def test_a_refused_scan_must_carry_a_reason(owner_session, make_org):
    """A refusal with no explanation is not reportable to the customer."""
    org = make_org()
    scan = Scan(
        org_id=org.id,
        trigger_kind=ScanTriggerKind.SCHEDULED,
        module_set=[MODULE_TLS],
        status=ScanStatus.REFUSED,
    )
    owner_session.add(scan)
    with pytest.raises(IntegrityError, match="refusal_has_reason"):
        owner_session.commit()
    owner_session.rollback()


def test_a_manual_scan_must_name_who_asked_for_it(owner_session, make_org):
    org = make_org()
    scan = Scan(
        org_id=org.id,
        trigger_kind=ScanTriggerKind.MANUAL,
        module_set=[MODULE_TLS],
        status=ScanStatus.QUEUED,
        triggered_by=None,
    )
    owner_session.add(scan)
    with pytest.raises(IntegrityError, match="manual_scan_has_actor"):
        owner_session.commit()
    owner_session.rollback()


def test_a_scan_target_records_the_agreement_that_permitted_it(
    owner_session, make_org, make_agreement, make_asset
):
    """The denormalised `authorisation_id` survives what happens next.

    The agreement is revoked after the scan ran. The scan's record of what
    permitted it is unchanged, which is the whole reason that column is not
    derived at read time.
    """
    org = make_org()
    agreement = make_agreement(org, permitted_modules=[MODULE_TLS])
    asset = make_asset(org)
    scan = make_scan(owner_session, org)

    owner_session.add(
        ScanTarget(scan_id=scan.id, asset_id=asset.id, authorisation_id=agreement.id)
    )
    owner_session.commit()

    agreement.revoked_at = NOW + DAY
    agreement.permitted_modules = []
    owner_session.commit()

    (target,) = owner_session.scalars(select(ScanTarget)).all()
    assert target.authorisation_id == agreement.id


def test_an_asset_cannot_be_targeted_twice_by_one_scan(
    owner_session, make_org, make_agreement, make_asset
):
    """The composite primary key, doing its job."""
    org = make_org()
    agreement = make_agreement(org)
    asset = make_asset(org)
    scan = make_scan(owner_session, org)
    owner_session.add(
        ScanTarget(scan_id=scan.id, asset_id=asset.id, authorisation_id=agreement.id)
    )
    owner_session.commit()

    owner_session.add(
        ScanTarget(scan_id=scan.id, asset_id=asset.id, authorisation_id=agreement.id)
    )
    with pytest.raises(IntegrityError, match="pk_scan_target"):
        owner_session.commit()
    owner_session.rollback()


def test_timestamps_come_back_timezone_aware(owner_session, make_org, make_asset):
    """timestamptz, end to end.

    If a timestamp came back naive, every comparison in the gate would be
    comparing an aware value with a naive one - which raises in Python, but only
    on the code path nobody tested.
    """
    org = make_org()
    asset = make_asset(org)
    owner_session.expire_all()

    reloaded = owner_session.get(type(asset), asset.id)
    assert reloaded.created_at.tzinfo is not None
    assert reloaded.verified_at.tzinfo is not None
    assert org.created_at.tzinfo is not None


def test_an_organisation_cannot_be_its_own_parent(owner_session, make_org):
    org = make_org()
    org.parent_org_id = org.id
    with pytest.raises(IntegrityError, match="parent_is_not_self"):
        owner_session.commit()
    owner_session.rollback()
