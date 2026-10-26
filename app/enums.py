"""Enumerated values, in one place.

These are Postgres native enum types rather than text-with-a-check-constraint.
The trade-off: native enums give a real type error on a bad value and read well
in psql, but adding a value needs an ALTER TYPE migration. For a vocabulary like
severity, which changes rarely and must never hold a typo, that is the right way
round.

Each member's *value* is what gets stored. The models pass `values_callable` to
SQLAlchemy for exactly this reason - by default SQLAlchemy would store the member
*name*, which would mean `IP_RANGE` in the database rather than `ip_range`.

They are `StrEnum`, so a member compares equal to its own string. That keeps
comparisons against values read back from SQL, or arriving in a request body,
from needing a conversion step at every boundary.
"""

from __future__ import annotations

from enum import Enum, StrEnum


class UserRole(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    VIEWER = "viewer"


class AssetKind(StrEnum):
    DOMAIN = "domain"
    IP_RANGE = "ip_range"
    HOST = "host"
    CLOUD_ACCOUNT = "cloud_account"
    SAAS_TENANT = "saas_tenant"


class VerificationMethod(StrEnum):
    """How the customer proved they control an asset.

    Verification is not paperwork: scanning an asset the customer does not
    actually control is unauthorised access to a third party's system, whatever
    the scope agreement says.
    """

    DNS_TXT = "dns_txt"
    WHOIS_MATCH = "whois_match"
    WRITTEN_ATTESTATION = "written_attestation"


class BusinessCriticality(StrEnum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"


class ScanTriggerKind(StrEnum):
    MANUAL = "manual"
    SCHEDULED = "scheduled"


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    # `refused` is distinct from `failed` on purpose. Failed means the scan broke;
    # refused means the authorisation gate declined to run it, and that outcome is
    # a product feature rather than an error.
    REFUSED = "refused"


class FindingSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(StrEnum):
    OPEN = "open"
    RESOLVED = "resolved"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"


# Type names as they exist in Postgres, paired with the Python enum that defines
# their members. The migration iterates this to create and drop the types, so the
# value lists live in exactly one place.
PG_ENUM_TYPES: dict[str, type[Enum]] = {
    "user_role": UserRole,
    "asset_kind": AssetKind,
    "verification_method": VerificationMethod,
    "business_criticality": BusinessCriticality,
    "scan_trigger_kind": ScanTriggerKind,
    "scan_status": ScanStatus,
    "finding_severity": FindingSeverity,
    "finding_status": FindingStatus,
}


def enum_values(py_enum: type[Enum]) -> list[str]:
    return [member.value for member in py_enum]
