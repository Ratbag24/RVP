"""The authorisation gate: may we scan this asset, with this module, right now?

This is the module the whole product rests on. The governing rule is that the
platform detects and advises; it does not exploit and does not change customer
systems, and every network action must be traceable to a written authorisation.
Under the Computer Misuse Act 1990 that traceability is the difference between a
service and an offence, which is why this gate exists before any code that could
send a packet.

Shape of the thing, and why:

*   It takes a `Session` and returns a decision. No HTTP, no FastAPI, no
    network, no logging config - so it can be called from a request handler, a
    scheduled worker, or a test, and tested exhaustively in all the ways that
    matter.

*   `at_time` is a parameter rather than `datetime.now(UTC)` read inside. Expiry
    behaviour is then testable without freezing the clock, and - more
    importantly - callers are forced to be honest about which moment they are
    asking about. "Was this authorised?" and "is this authorised?" are different
    questions, and a scan that started twenty minutes ago should be judged
    against the moment it started.

*   Every call writes an `audit_event`, permitted or refused. A refusal that
    leaves no trace is worse than useless: it is the refusals that prove the
    gate was working on the day somebody asks.

The commit contract: the audit row is added and flushed on the session that was
passed in, so it lands in the caller's transaction. The caller must commit. If
the caller rolls back, the audit row goes with it - so a caller that refuses a
scan must commit the refusal rather than abandoning the transaction. Writing the
audit row on a separate connection would survive a rollback, but it could not see
rows the caller has not committed yet, which would make the gate unusable inside
an ordinary unit of work. The trade-off is noted here deliberately.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models import Asset, AuditEvent, ScopeAgreement

# Audit actions. Dotted names so a later reporting query can match a prefix.
ACTION_PERMITTED = "authorisation.permitted"
ACTION_REFUSED = "authorisation.refused"

# The default actor when the caller does not name one. "system" covers the
# scheduler; a worker should pass "worker:<name>", and a request handler should
# pass the acting user's id.
SYSTEM_ACTOR = "system"

# Reason prefixes. The `reason` field is human-readable text that ends up in
# front of a customer (via scan.refusal_reason), but tests and callers need
# something stable to match on, so each reason begins with one of these.
REASON_PERMITTED = "permitted"
REASON_NO_SUCH_ASSET = "no such asset is visible to this organisation"
REASON_ASSET_OTHER_ORG = "asset belongs to another organisation"
REASON_NO_AGREEMENT = "no scope agreement exists for the owning organisation"
REASON_AGREEMENT_NOT_YET_VALID = "scope agreement is not yet valid"
REASON_AGREEMENT_EXPIRED = "scope agreement has expired"
REASON_AGREEMENT_REVOKED = "scope agreement has been revoked"
REASON_MODULE_NOT_PERMITTED = "module is not permitted by the scope agreement"
REASON_ASSET_NOT_VERIFIED = "asset ownership has never been verified"
REASON_VERIFICATION_NOT_YET_EFFECTIVE = "asset ownership was not yet verified"
REASON_VERIFICATION_EXPIRED = "asset ownership verification has expired"


@dataclass(frozen=True)
class AuthorisationDecision:
    """The answer, and the evidence for it.

    Frozen because a decision is a fact about a moment: nothing downstream
    should be able to edit a refusal into a permission. `reason` is always
    populated, including on success, so that the audit trail reads the same way
    whichever way the decision went.
    """

    permitted: bool
    authorisation_id: UUID | None
    reason: str


def check_authorisation(
    session: Session,
    org_id: UUID,
    asset_id: UUID,
    module_name: str,
    at_time: datetime,
    *,
    actor: str = SYSTEM_ACTOR,
) -> AuthorisationDecision:
    """Decide whether `org_id` may run `module_name` against `asset_id` at `at_time`.

    Refuses unless all of the following hold at `at_time`:

    1. The asset belongs to `org_id`, or to an organisation beneath it.
    2. A scope agreement for the asset's owning organisation is active:
       ``valid_from <= at_time < valid_until``, and not revoked at or before
       `at_time`.
    3. `module_name` is in that agreement's `permitted_modules`.
    4. The asset's ownership verification was in force at `at_time`.

    The checks run in that order and the first failure is the reason returned,
    because that is the order in which the facts matter: who owns it, whether
    they authorised anything, whether they authorised *this*, and whether they
    proved they own it. Reporting the first failure rather than all of them also
    keeps the gate from being used to enumerate another tenant's configuration.

    `actor` is a keyword argument with a default so the positional signature
    stays exactly as specified, while a request handler can still record the user
    who asked.

    The session must be scoped to `org_id` or to an organisation above it - i.e.
    `org_id` is the caller's own organisation, or a client of it. Asking on
    behalf of an organisation the session has no business with is a caller bug,
    and is rejected rather than audited; see `_assert_session_covers`.

    Raises:
        ValueError: if `at_time` is naive, or if the session's organisation
            context does not cover `org_id`. Both are bugs in the caller rather
            than facts about the customer's authorisation, so neither produces a
            refusal: a refusal is a decision, and there is no decision to record
            when the question itself was malformed.
    """
    if at_time.tzinfo is None or at_time.utcoffset() is None:
        # Not a refusal: a refusal is a fact about the customer's authorisation,
        # and this is a fact about our own code being wrong.
        raise ValueError(
            "at_time must be timezone-aware; "
            "an authorisation window compared against a naive datetime is a bug"
        )

    _assert_session_covers(session, org_id)

    asset = session.get(Asset, asset_id)

    if asset is None:
        # Two distinct situations collapse into one answer here: the asset does
        # not exist, or it exists and row level security hid it from this
        # session. The gate must not distinguish them - telling a caller "that
        # id exists but is not yours" is itself a disclosure.
        return _record(
            session,
            org_id=org_id,
            asset=None,
            requested_asset_id=asset_id,
            module_name=module_name,
            at_time=at_time,
            actor=actor,
            decision=AuthorisationDecision(
                permitted=False,
                authorisation_id=None,
                reason=f"{REASON_NO_SUCH_ASSET}: asset {asset_id} not found",
            ),
        )

    # Ownership. The common case is the asset belonging to the calling org
    # directly; the hierarchy only needs consulting when it does not. The rule
    # itself lives in app.org_in_scope() in the database, which is also what
    # every row level security policy calls - one definition of "in scope", so
    # the gate and the policies cannot drift apart.
    owned_directly = asset.org_id == org_id
    if owned_directly:
        asset_in_scope = True
    else:
        asset_in_scope = bool(
            session.execute(
                select(func.app.org_in_scope(asset.org_id, org_id))
            ).scalar_one()
        )

    if not asset_in_scope:
        return _record(
            session,
            org_id=org_id,
            # Deliberately not linking the other tenant's asset into this
            # organisation's audit log; the requested id goes in `detail`.
            asset=None,
            requested_asset_id=asset_id,
            module_name=module_name,
            at_time=at_time,
            actor=actor,
            decision=AuthorisationDecision(
                permitted=False,
                authorisation_id=None,
                reason=(
                    f"{REASON_ASSET_OTHER_ORG}: asset {asset_id} is not owned by "
                    f"organisation {org_id} or any organisation beneath it"
                ),
            ),
        )

    decision = _evaluate(session, asset, module_name, at_time)
    return _record(
        session,
        org_id=org_id,
        asset=asset,
        requested_asset_id=asset_id,
        module_name=module_name,
        at_time=at_time,
        actor=actor,
        decision=decision,
    )


def _evaluate(
    session: Session, asset: Asset, module_name: str, at_time: datetime
) -> AuthorisationDecision:
    """Agreement, module and verification checks for an asset already in scope.

    Split out from `check_authorisation` so that the audit write happens in
    exactly one place, on every path, rather than being repeated at each `return`
    and eventually forgotten at one of them.
    """
    # Authority has to come from the organisation that owns the asset, not from
    # whoever is asking. A managed service provider scanning a client's domain
    # relies on the agreement that client signed (the provider's own name may
    # well be the signatory on it); the provider's agreement covering its own
    # assets does not reach down into a client's.
    agreements = list(
        session.scalars(
            select(ScopeAgreement)
            .where(ScopeAgreement.org_id == asset.org_id)
            # Most recently signed first: where several agreements could permit
            # the scan, the latest one the customer signed is the one that
            # governs.
            .order_by(ScopeAgreement.signed_at.desc())
        )
    )

    if not agreements:
        return AuthorisationDecision(
            permitted=False,
            authorisation_id=None,
            reason=(
                f"{REASON_NO_AGREEMENT}: organisation {asset.org_id} has no "
                f"scope agreement on record"
            ),
        )

    active = [a for a in agreements if _is_active(a, at_time)]

    if not active:
        return AuthorisationDecision(
            permitted=False,
            authorisation_id=None,
            reason=_inactive_reason(agreements, at_time),
        )

    permitting = [a for a in active if module_name in a.permitted_modules]

    if not permitting:
        # Listing what *is* permitted is safe - the customer signed it - and it
        # is the first thing anyone asks when a scan is refused.
        offered = sorted({m for a in active for m in a.permitted_modules})
        return AuthorisationDecision(
            permitted=False,
            authorisation_id=None,
            reason=(
                f"{REASON_MODULE_NOT_PERMITTED}: {module_name!r} is not in "
                f"{offered} (agreement {active[0].id})"
            ),
        )

    agreement = permitting[0]

    # Verification last, because it is a fact about us rather than about the
    # paperwork: the customer may have authorised everything, but if they have
    # not proved they control the asset then scanning it could be unauthorised
    # access to a third party's system, and the agreement would be no defence.
    if asset.verified_at is None:
        return AuthorisationDecision(
            permitted=False,
            authorisation_id=None,
            reason=(
                f"{REASON_ASSET_NOT_VERIFIED}: asset {asset.id} "
                f"({asset.identifier}) has no verified_at"
            ),
        )

    if asset.verified_at > at_time:
        # Verified since, but not then. This only bites when `at_time` is in the
        # past, which is exactly the case the explicit parameter exists for.
        return AuthorisationDecision(
            permitted=False,
            authorisation_id=None,
            reason=(
                f"{REASON_VERIFICATION_NOT_YET_EFFECTIVE}: asset {asset.id} was "
                f"verified at {asset.verified_at.isoformat()}, after {at_time.isoformat()}"
            ),
        )

    if (
        asset.verification_expires_at is not None
        and asset.verification_expires_at <= at_time
    ):
        return AuthorisationDecision(
            permitted=False,
            authorisation_id=None,
            reason=(
                f"{REASON_VERIFICATION_EXPIRED}: asset {asset.id} verification "
                f"expired at {asset.verification_expires_at.isoformat()}"
            ),
        )

    return AuthorisationDecision(
        permitted=True,
        authorisation_id=agreement.id,
        reason=(
            f"{REASON_PERMITTED}: module {module_name!r} on asset {asset.id} "
            f"({asset.identifier}) under agreement {agreement.id}, signed by "
            f"{agreement.signatory_name} on {agreement.signed_at.date().isoformat()}"
        ),
    )


def _is_active(agreement: ScopeAgreement, at_time: datetime) -> bool:
    """Is this agreement in force at `at_time`?

    The window is half-open: `valid_from` inclusive, `valid_until` exclusive, so
    an agreement ending at midnight does not authorise anything at midnight.
    Revocation is treated the same way - revoked *at* `at_time` means not
    authorised at `at_time`. Both boundaries resolve against the customer, which
    is the only safe direction for a default to lean.
    """
    if not (agreement.valid_from <= at_time < agreement.valid_until):
        return False
    return agreement.revoked_at is None or agreement.revoked_at > at_time


def _inactive_reason(
    agreements: list[ScopeAgreement], at_time: datetime
) -> str:
    """Explain why none of the org's agreements were in force.

    Precedence: revoked, then expired, then not yet valid. An agreement that was
    revoked inside its window is the most specific thing that can be said - the
    customer withdrew permission, rather than merely letting it lapse - so it is
    reported first.
    """
    revoked = [
        a
        for a in agreements
        if a.revoked_at is not None
        and a.revoked_at <= at_time
        and a.valid_from <= at_time < a.valid_until
    ]
    if revoked:
        agreement = revoked[0]
        return (
            f"{REASON_AGREEMENT_REVOKED}: agreement {agreement.id} was revoked at "
            f"{agreement.revoked_at.isoformat()}"
        )

    expired = [a for a in agreements if a.valid_until <= at_time]
    if expired:
        # The one that expired most recently is the one worth naming.
        agreement = max(expired, key=lambda a: a.valid_until)
        return (
            f"{REASON_AGREEMENT_EXPIRED}: agreement {agreement.id} expired at "
            f"{agreement.valid_until.isoformat()}"
        )

    future = [a for a in agreements if a.valid_from > at_time]
    if future:
        agreement = min(future, key=lambda a: a.valid_from)
        return (
            f"{REASON_AGREEMENT_NOT_YET_VALID}: agreement {agreement.id} is valid "
            f"from {agreement.valid_from.isoformat()}"
        )

    # Unreachable unless the window logic above and _is_active disagree. Say so
    # plainly rather than returning a misleading reason.
    return (
        f"{REASON_NO_AGREEMENT}: no agreement was in force at {at_time.isoformat()}"
    )


def _assert_session_covers(session: Session, org_id: UUID) -> None:
    """Check that the session's organisation context covers `org_id`.

    Without this, a session scoped to one organisation asking about another
    would reach the audit write and be rejected by the row level security policy
    - correctly, since that row would be a cross-tenant write, but with an error
    that points at the audit table rather than at the mistake. One cheap query
    turns that into a precise complaint.

    A session with no organisation context set is exempt: that is the
    administrative connection, which holds BYPASSRLS and is already outside the
    policies. The scheduler runs that way.
    """
    covered = session.execute(
        select(
            or_(
                func.app.current_org_id().is_(None),
                func.app.org_in_scope(org_id),
            )
        )
    ).scalar_one()

    if not covered:
        raise ValueError(
            f"this session's organisation context does not cover {org_id}; "
            "a session may only ask about its own organisation or one beneath it"
        )


def _record(
    session: Session,
    *,
    org_id: UUID,
    asset: Asset | None,
    requested_asset_id: UUID,
    module_name: str,
    at_time: datetime,
    actor: str,
    decision: AuthorisationDecision,
) -> AuthorisationDecision:
    """Write the audit row and return the decision unchanged.

    Every exit from the gate goes through here. The row is stamped with the
    asset's *owning* organisation where we have one, rather than the requesting
    organisation: a client whose asset a provider scanned should see that event
    in their own audit log, and the hierarchy policy means the provider sees it
    too. Where the asset is unknown or out of scope there is no owning org to
    use, so the requester is recorded and the requested id goes in `detail`.
    """
    event = AuditEvent(
        org_id=asset.org_id if asset is not None else org_id,
        # `occurred_at` is left to the database's now(): it records when the
        # decision was taken, which is not the same thing as `at_time`, the
        # moment the caller asked about. Both matter - "at 14:05 we refused a
        # request about 13:45" - so the question's moment goes in `detail`
        # rather than overwriting the event's own timestamp.
        actor=actor,
        action=ACTION_PERMITTED if decision.permitted else ACTION_REFUSED,
        asset_id=asset.id if asset is not None else None,
        authorisation_id=decision.authorisation_id,
        detail={
            "module": module_name,
            "at_time": at_time.isoformat(),
            "requesting_org_id": str(org_id),
            "requested_asset_id": str(requested_asset_id),
            "permitted": decision.permitted,
            "reason": decision.reason,
        },
    )
    session.add(event)
    # Flush rather than commit: the row belongs to the caller's transaction, and
    # flushing now means a policy or constraint violation surfaces here, at the
    # gate, instead of much later at an unrelated commit.
    session.flush()
    return decision
