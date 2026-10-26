"""SQLAlchemy models for the step 1 schema.

Read this file top to bottom: the tables are in dependency order, and the
comments explain the choices that are not obvious from the column list.

Two conventions throughout:

* Every timestamp is `timestamptz` and every value written to one is UTC. A
  naive timestamp in an authorisation window is a security bug waiting to
  happen - "valid until midnight" in whose timezone?
* Primary keys are UUIDs generated client-side by default, so a caller holds the
  id before the row is flushed and can build related rows in one go. The server
  default is there too, for inserts that come from SQL rather than the ORM.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, CITEXT, ENUM, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.enums import (
    AssetKind,
    BusinessCriticality,
    FindingSeverity,
    FindingStatus,
    ScanStatus,
    ScanTriggerKind,
    UserRole,
    VerificationMethod,
    enum_values,
)


def pg_enum(py_enum: type, name: str) -> ENUM:
    """A Postgres enum column type bound to an existing type in the database.

    `create_type=False` keeps DDL out of the ORM's hands: the types are created
    by the migration, once, in a known order. Without it SQLAlchemy would try to
    emit CREATE TYPE whenever it created a table that uses the enum, which fails
    the second time the type is referenced.
    """
    return ENUM(
        py_enum,
        name=name,
        create_type=False,
        values_callable=enum_values,
    )


def _timestamptz(**kwargs) -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), **kwargs)


class Organisation(Base):
    """A customer, or a managed service provider holding customers.

    `parent_org_id` is the whole of the MSP model: an IT support company gets one
    organisation row, and each of its clients gets a row pointing at it. The
    hierarchy is read in exactly one place - the `app.org_in_scope()` SQL
    function - which every row level security policy then calls. Putting the rule
    anywhere else, or in more than one place, is how a tenant isolation bug gets
    in.
    """

    __tablename__ = "organisation"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    legal_name: Mapped[str] = mapped_column(Text, nullable=False)
    # Nullable: sole traders and partnerships have no company number, and
    # non-UK entities will not have a Companies House one at all.
    companies_house_number: Mapped[str | None] = mapped_column(Text)
    parent_org_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        # RESTRICT, not CASCADE: deleting an MSP must not silently delete the
        # audit history of its clients. Detach the children first, deliberately.
        ForeignKey("organisation.id", ondelete="RESTRICT"),
    )
    created_at: Mapped[datetime] = _timestamptz(
        nullable=False, server_default=func.now()
    )

    # Self-referential one-to-many. `remote_side` goes on the many-to-one half
    # only; it tells SQLAlchemy which end of the join is the "one".
    parent: Mapped[Organisation | None] = relationship(
        back_populates="children", remote_side=lambda: [Organisation.id]
    )
    children: Mapped[list[Organisation]] = relationship(back_populates="parent")

    __table_args__ = (
        # Hierarchy walks start from a parent and look for its children.
        Index("ix_organisation_parent_org_id", "parent_org_id"),
        CheckConstraint("parent_org_id IS NULL OR parent_org_id <> id",
                        name="parent_is_not_self"),
    )


class UserAccount(Base):
    __tablename__ = "user_account"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organisation.id", ondelete="RESTRICT"),
        nullable=False,
    )
    # citext so "Jo@example.com" and "jo@example.com" are the same account.
    # Unique across the whole table, not per org: an address identifies one human
    # and one login. Someone who works for two orgs needs two addresses, which is
    # the lesser evil compared with an ambiguous login lookup.
    email: Mapped[str] = mapped_column(CITEXT, nullable=False, unique=True)
    # argon2id. Hashing lives in the auth module (step 2); this column only ever
    # holds the full PHC-format string, which carries its own parameters, so a
    # later parameter bump does not need a migration.
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[UserRole] = mapped_column(
        pg_enum(UserRole, "user_role"), nullable=False
    )
    # Nullable because MFA is opt-in at this stage. Stored encrypted at rest once
    # the key management story exists; a bare TOTP secret in a column is a
    # liability, and this comment is here so that does not get forgotten.
    mfa_secret: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _timestamptz(
        nullable=False, server_default=func.now()
    )
    last_login_at: Mapped[datetime | None] = _timestamptz()

    __table_args__ = (Index("ix_user_account_org_id", "org_id"),)


class ScopeAgreement(Base):
    """The signed authorisation to scan. The legal basis for everything else.

    Under the Computer Misuse Act 1990 an unauthorised access to a computer
    system is an offence; what makes our traffic lawful is this row and the
    document it hashes. That is why `document_hash` exists: the PDF lives in
    object storage, and this is the proof that the stored PDF is the one the
    signatory actually signed.
    """

    __tablename__ = "scope_agreement"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organisation.id", ondelete="RESTRICT"),
        nullable=False,
    )
    signatory_name: Mapped[str] = mapped_column(Text, nullable=False)
    signatory_email: Mapped[str] = mapped_column(CITEXT, nullable=False)
    signed_at: Mapped[datetime] = _timestamptz(nullable=False)
    # The permitted window. `valid_from` inclusive, `valid_until` exclusive - the
    # gate compares with `valid_from <= at_time < valid_until`, and keeping the
    # half-open convention consistent avoids an off-by-one-second argument about
    # the final moment of an agreement.
    valid_from: Mapped[datetime] = _timestamptz(nullable=False)
    valid_until: Mapped[datetime] = _timestamptz(nullable=False)
    # Module names the signatory agreed to, e.g. {tls_config, dns_hygiene}. A
    # text array rather than a join table: the list is short, read whole every
    # time, and is a snapshot of what a human signed rather than a live
    # relationship to a module catalogue that may change afterwards.
    permitted_modules: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default=text("'{}'::text[]")
    )
    document_hash: Mapped[str] = mapped_column(Text, nullable=False)
    # Set, never cleared. Revocation is immediate and permanent; a customer who
    # wants back in signs a new agreement, so the record of the revoked one
    # survives.
    revoked_at: Mapped[datetime | None] = _timestamptz()

    __table_args__ = (
        CheckConstraint("valid_from < valid_until", name="validity_window_ordered"),
        CheckConstraint(
            "document_hash ~ '^[0-9a-f]{64}$'", name="document_hash_is_sha256_hex"
        ),
        # The gate's hot path: agreements for an org, filtered by window.
        Index("ix_scope_agreement_org_id_valid_from_valid_until",
              "org_id", "valid_from", "valid_until"),
    )


class Asset(Base):
    """A thing that may be scanned, once someone has proved they control it."""

    __tablename__ = "asset"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organisation.id", ondelete="RESTRICT"),
        nullable=False,
    )
    kind: Mapped[AssetKind] = mapped_column(
        pg_enum(AssetKind, "asset_kind"), nullable=False
    )
    # The domain name, CIDR block, hostname, cloud account id, or tenant id.
    # Stored as text because the shapes differ per kind; validation per kind
    # belongs in the application, not in a column type that fits only one of them.
    identifier: Mapped[str] = mapped_column(Text, nullable=False)
    verification_method: Mapped[VerificationMethod | None] = mapped_column(
        pg_enum(VerificationMethod, "verification_method")
    )
    verification_token: Mapped[str | None] = mapped_column(Text)
    # Null means never verified, and the gate refuses on that. There is no
    # "assume verified" state anywhere in this schema.
    verified_at: Mapped[datetime | None] = _timestamptz()
    # Verification goes stale: domains change hands. Null means it does not
    # expire (a written attestation, typically); a timestamp in the past means
    # the asset must be re-verified before it can be scanned again.
    verification_expires_at: Mapped[datetime | None] = _timestamptz()
    business_criticality: Mapped[BusinessCriticality] = mapped_column(
        pg_enum(BusinessCriticality, "business_criticality"),
        nullable=False,
        server_default=text("'normal'::business_criticality"),
    )
    created_at: Mapped[datetime] = _timestamptz(
        nullable=False, server_default=func.now()
    )

    __table_args__ = (
        # One row per thing per org. Two orgs may legitimately both claim the
        # same domain (a dispute, or a shared parent), so this is scoped to the
        # org rather than global.
        UniqueConstraint("org_id", "identifier", name="uq_asset_org_id_identifier"),
    )


class Scan(Base):
    __tablename__ = "scan"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organisation.id", ondelete="RESTRICT"),
        nullable=False,
    )
    # Null for scheduled scans: nobody pressed the button. SET NULL on delete so
    # removing a user account does not erase the scan record.
    triggered_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user_account.id", ondelete="SET NULL")
    )
    trigger_kind: Mapped[ScanTriggerKind] = mapped_column(
        pg_enum(ScanTriggerKind, "scan_trigger_kind"), nullable=False
    )
    module_set: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default=text("'{}'::text[]")
    )
    status: Mapped[ScanStatus] = mapped_column(
        pg_enum(ScanStatus, "scan_status"),
        nullable=False,
        server_default=text("'queued'::scan_status"),
    )
    # Populated when the gate refuses; this is the customer-facing explanation,
    # and it is the same string the gate's decision carried.
    refusal_reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _timestamptz(
        nullable=False, server_default=func.now()
    )
    started_at: Mapped[datetime | None] = _timestamptz()
    finished_at: Mapped[datetime | None] = _timestamptz()

    __table_args__ = (
        # A refusal with no reason is not reportable, so the database declines it.
        CheckConstraint(
            "status <> 'refused' OR refusal_reason IS NOT NULL",
            name="refusal_has_reason",
        ),
        # A manual scan must name the human who asked for it; that is the point
        # of the distinction from a scheduled one.
        CheckConstraint(
            "trigger_kind <> 'manual' OR triggered_by IS NOT NULL",
            name="manual_scan_has_actor",
        ),
        Index("ix_scan_org_id_created_at", "org_id", "created_at"),
    )


class ScanTarget(Base):
    """Which assets a scan covered, and what permitted each one.

    `authorisation_id` is denormalised here deliberately. It records which
    agreement permitted this specific target at the time the scan ran, so the
    audit trail survives the agreement being revoked, superseded, or re-scoped
    afterwards. Deriving it later from the agreement table would give you the
    answer as it is now, not as it was - which is the opposite of what an audit
    trail is for.
    """

    __tablename__ = "scan_target"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan.id", ondelete="CASCADE"),
        primary_key=True,
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("asset.id", ondelete="RESTRICT"),
        primary_key=True,
    )
    authorisation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        # RESTRICT: an agreement that authorised a scan cannot be deleted while
        # that scan's record exists.
        ForeignKey("scope_agreement.id", ondelete="RESTRICT"),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_scan_target_asset_id", "asset_id"),
        Index("ix_scan_target_authorisation_id", "authorisation_id"),
    )


class Finding(Base):
    """One issue on one asset, carried across scans.

    The unique constraint on (asset_id, rule_id, fingerprint) is the heart of
    finding persistence. Findings are matched and updated across scans - never
    deleted and reinserted - because trend reporting depends on a finding keeping
    its identity over time. `first_seen_*` and `last_seen_*` are what make
    "open for 94 days" answerable.

    `fingerprint` is the stable identity of the specific issue, computed by the
    rule that produced it: for example the port and certificate serial, rather
    than the certificate expiry date, which changes on renewal and would make
    every renewal look like a new finding.
    """

    __tablename__ = "finding"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organisation.id", ondelete="RESTRICT"),
        nullable=False,
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("asset.id", ondelete="RESTRICT"),
        nullable=False,
    )
    rule_id: Mapped[str] = mapped_column(Text, nullable=False)
    fingerprint: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    # Computed from the rule's base severity and the asset's business
    # criticality, then stored. Stored rather than derived on read so that a
    # later change to the scoring rules does not silently rewrite history in
    # reports that have already gone to a customer.
    severity: Mapped[FindingSeverity] = mapped_column(
        pg_enum(FindingSeverity, "finding_severity"), nullable=False
    )
    cve_ids: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default=text("'{}'::text[]")
    )
    # jsonb, not json: we will want to query inside it (which port, which
    # header), and jsonb is the one that can be indexed.
    evidence: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    first_seen_scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan.id", ondelete="RESTRICT"),
        nullable=False,
    )
    last_seen_scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan.id", ondelete="RESTRICT"),
        nullable=False,
    )
    first_seen_at: Mapped[datetime] = _timestamptz(nullable=False)
    last_seen_at: Mapped[datetime] = _timestamptz(nullable=False)
    status: Mapped[FindingStatus] = mapped_column(
        pg_enum(FindingStatus, "finding_status"),
        nullable=False,
        server_default=text("'open'::finding_status"),
    )
    # Why a human moved it out of `open`: the business justification for an
    # accepted risk, or the reasoning behind a false positive call.
    status_reason: Mapped[str | None] = mapped_column(Text)
    # An accepted risk with an expiry comes back to `open` when it lapses, so
    # "accept and forget" is not available.
    accepted_until: Mapped[datetime | None] = _timestamptz()
    resolved_at: Mapped[datetime | None] = _timestamptz()

    __table_args__ = (
        UniqueConstraint(
            "asset_id", "rule_id", "fingerprint",
            name="uq_finding_asset_id_rule_id_fingerprint",
        ),
        Index("ix_finding_org_id_status_severity", "org_id", "status", "severity"),
        Index("ix_finding_last_seen_scan_id", "last_seen_scan_id"),
    )


class AuditEvent(Base):
    """Append-only record of everything that mattered.

    Append-only is enforced by a trigger in the database, not by this class and
    not by the application. Application-level discipline is a convention; a
    trigger is a guarantee, and it holds for a stray psql session and a future
    bug in our own code alike.

    Note there is no FK from `actor` to `user_account`: the actor may be
    "system", or "worker:tls_probe", and events must outlive the deletion of a
    user account. The cost is that the value is only as good as the writer; the
    gain is that nothing can delete an actor out from under an audit record.
    """

    __tablename__ = "audit_event"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organisation.id", ondelete="RESTRICT"),
        nullable=False,
    )
    occurred_at: Mapped[datetime] = _timestamptz(
        nullable=False, server_default=func.now()
    )
    actor: Mapped[str] = mapped_column(Text, nullable=False)
    # Dotted action names, e.g. "authorisation.permitted". Text rather than an
    # enum: the vocabulary grows with every module, and an append-only log should
    # never reject a write because a migration has not run yet.
    action: Mapped[str] = mapped_column(Text, nullable=False)
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("asset.id", ondelete="RESTRICT")
    )
    authorisation_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scope_agreement.id", ondelete="RESTRICT")
    )
    detail: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )

    __table_args__ = (
        Index("ix_audit_event_org_id_occurred_at", "org_id", "occurred_at"),
        Index("ix_audit_event_asset_id_occurred_at", "asset_id", "occurred_at"),
    )


# Tables whose rows belong to exactly one organisation, named by an `org_id`
# column. The migration enables row level security on each of these and attaches
# the same policy, so this list is the definition of "tenant data".
ORG_SCOPED_TABLES: tuple[str, ...] = (
    "user_account",
    "scope_agreement",
    "asset",
    "scan",
    "finding",
    "audit_event",
)
