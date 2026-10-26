"""initial schema

Tables, enum types and constraints. Row level security, the organisation
hierarchy helper and the append-only audit trigger are all in 0002; this
migration deliberately stops at the shape of the data, so that the two concerns
can be read - and reverted - separately.

Revision ID: 0001
Revises:
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op
from app.enums import PG_ENUM_TYPES, enum_values

revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()

    # citext, for case-insensitive email addresses. It is a "trusted" extension
    # in Postgres 16, so the database owner can install it without superuser
    # rights; scripts/setup_db.sh also creates it, which makes this a no-op on a
    # database set up that way.
    op.execute("CREATE EXTENSION IF NOT EXISTS citext")

    # Create every enum type up front, from the single list in app/enums.py.
    # Doing it here rather than letting SQLAlchemy create types as a side effect
    # of CREATE TABLE keeps the order explicit and makes the downgrade symmetric.
    for type_name, py_enum in PG_ENUM_TYPES.items():
        postgresql.ENUM(
            *enum_values(py_enum), name=type_name, create_type=False
        ).create(bind, checkfirst=True)

    op.create_table('organisation',
    sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('legal_name', sa.Text(), nullable=False),
    sa.Column('companies_house_number', sa.Text(), nullable=True),
    sa.Column('parent_org_id', sa.UUID(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('parent_org_id IS NULL OR parent_org_id <> id', name=op.f('ck_organisation_parent_is_not_self')),
    sa.ForeignKeyConstraint(['parent_org_id'], ['organisation.id'], name=op.f('fk_organisation_parent_org_id'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_organisation'))
    )
    op.create_index('ix_organisation_parent_org_id', 'organisation', ['parent_org_id'], unique=False)
    op.create_table('asset',
    sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('org_id', sa.UUID(), nullable=False),
    sa.Column('kind', postgresql.ENUM('domain', 'ip_range', 'host', 'cloud_account', 'saas_tenant', name='asset_kind', create_type=False), nullable=False),
    sa.Column('identifier', sa.Text(), nullable=False),
    sa.Column('verification_method', postgresql.ENUM('dns_txt', 'whois_match', 'written_attestation', name='verification_method', create_type=False), nullable=True),
    sa.Column('verification_token', sa.Text(), nullable=True),
    sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('verification_expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('business_criticality', postgresql.ENUM('low', 'normal', 'high', name='business_criticality', create_type=False), server_default=sa.text("'normal'::business_criticality"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['org_id'], ['organisation.id'], name=op.f('fk_asset_org_id'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_asset')),
    sa.UniqueConstraint('org_id', 'identifier', name='uq_asset_org_id_identifier')
    )
    op.create_table('scope_agreement',
    sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('org_id', sa.UUID(), nullable=False),
    sa.Column('signatory_name', sa.Text(), nullable=False),
    sa.Column('signatory_email', postgresql.CITEXT(), nullable=False),
    sa.Column('signed_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('valid_from', sa.DateTime(timezone=True), nullable=False),
    sa.Column('valid_until', sa.DateTime(timezone=True), nullable=False),
    sa.Column('permitted_modules', postgresql.ARRAY(sa.Text()), server_default=sa.text("'{}'::text[]"), nullable=False),
    sa.Column('document_hash', sa.Text(), nullable=False),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("document_hash ~ '^[0-9a-f]{64}$'", name=op.f('ck_scope_agreement_document_hash_is_sha256_hex')),
    sa.CheckConstraint('valid_from < valid_until', name=op.f('ck_scope_agreement_validity_window_ordered')),
    sa.ForeignKeyConstraint(['org_id'], ['organisation.id'], name=op.f('fk_scope_agreement_org_id'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_scope_agreement'))
    )
    op.create_index('ix_scope_agreement_org_id_valid_from_valid_until', 'scope_agreement', ['org_id', 'valid_from', 'valid_until'], unique=False)
    op.create_table('user_account',
    sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('org_id', sa.UUID(), nullable=False),
    sa.Column('email', postgresql.CITEXT(), nullable=False),
    sa.Column('password_hash', sa.Text(), nullable=False),
    sa.Column('role', postgresql.ENUM('owner', 'admin', 'viewer', name='user_role', create_type=False), nullable=False),
    sa.Column('mfa_secret', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['org_id'], ['organisation.id'], name=op.f('fk_user_account_org_id'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_user_account')),
    sa.UniqueConstraint('email', name=op.f('uq_user_account_email'))
    )
    op.create_index('ix_user_account_org_id', 'user_account', ['org_id'], unique=False)
    op.create_table('audit_event',
    sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('org_id', sa.UUID(), nullable=False),
    sa.Column('occurred_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('actor', sa.Text(), nullable=False),
    sa.Column('action', sa.Text(), nullable=False),
    sa.Column('asset_id', sa.UUID(), nullable=True),
    sa.Column('authorisation_id', sa.UUID(), nullable=True),
    sa.Column('detail', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.ForeignKeyConstraint(['asset_id'], ['asset.id'], name=op.f('fk_audit_event_asset_id'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['authorisation_id'], ['scope_agreement.id'], name=op.f('fk_audit_event_authorisation_id'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['org_id'], ['organisation.id'], name=op.f('fk_audit_event_org_id'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_event'))
    )
    op.create_index('ix_audit_event_asset_id_occurred_at', 'audit_event', ['asset_id', 'occurred_at'], unique=False)
    op.create_index('ix_audit_event_org_id_occurred_at', 'audit_event', ['org_id', 'occurred_at'], unique=False)
    op.create_table('scan',
    sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('org_id', sa.UUID(), nullable=False),
    sa.Column('triggered_by', sa.UUID(), nullable=True),
    sa.Column('trigger_kind', postgresql.ENUM('manual', 'scheduled', name='scan_trigger_kind', create_type=False), nullable=False),
    sa.Column('module_set', postgresql.ARRAY(sa.Text()), server_default=sa.text("'{}'::text[]"), nullable=False),
    sa.Column('status', postgresql.ENUM('queued', 'running', 'completed', 'failed', 'refused', name='scan_status', create_type=False), server_default=sa.text("'queued'::scan_status"), nullable=False),
    sa.Column('refusal_reason', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("status <> 'refused' OR refusal_reason IS NOT NULL", name=op.f('ck_scan_refusal_has_reason')),
    sa.CheckConstraint("trigger_kind <> 'manual' OR triggered_by IS NOT NULL", name=op.f('ck_scan_manual_scan_has_actor')),
    sa.ForeignKeyConstraint(['org_id'], ['organisation.id'], name=op.f('fk_scan_org_id'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['triggered_by'], ['user_account.id'], name=op.f('fk_scan_triggered_by'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_scan'))
    )
    op.create_index('ix_scan_org_id_created_at', 'scan', ['org_id', 'created_at'], unique=False)
    op.create_table('finding',
    sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('org_id', sa.UUID(), nullable=False),
    sa.Column('asset_id', sa.UUID(), nullable=False),
    sa.Column('rule_id', sa.Text(), nullable=False),
    sa.Column('fingerprint', sa.Text(), nullable=False),
    sa.Column('title', sa.Text(), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('severity', postgresql.ENUM('info', 'low', 'medium', 'high', 'critical', name='finding_severity', create_type=False), nullable=False),
    sa.Column('cve_ids', postgresql.ARRAY(sa.Text()), server_default=sa.text("'{}'::text[]"), nullable=False),
    sa.Column('evidence', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('first_seen_scan_id', sa.UUID(), nullable=False),
    sa.Column('last_seen_scan_id', sa.UUID(), nullable=False),
    sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('status', postgresql.ENUM('open', 'resolved', 'accepted_risk', 'false_positive', name='finding_status', create_type=False), server_default=sa.text("'open'::finding_status"), nullable=False),
    sa.Column('status_reason', sa.Text(), nullable=True),
    sa.Column('accepted_until', sa.DateTime(timezone=True), nullable=True),
    sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['asset_id'], ['asset.id'], name=op.f('fk_finding_asset_id'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['first_seen_scan_id'], ['scan.id'], name=op.f('fk_finding_first_seen_scan_id'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['last_seen_scan_id'], ['scan.id'], name=op.f('fk_finding_last_seen_scan_id'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['org_id'], ['organisation.id'], name=op.f('fk_finding_org_id'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_finding')),
    sa.UniqueConstraint('asset_id', 'rule_id', 'fingerprint', name='uq_finding_asset_id_rule_id_fingerprint')
    )
    op.create_index('ix_finding_last_seen_scan_id', 'finding', ['last_seen_scan_id'], unique=False)
    op.create_index('ix_finding_org_id_status_severity', 'finding', ['org_id', 'status', 'severity'], unique=False)
    op.create_table('scan_target',
    sa.Column('scan_id', sa.UUID(), nullable=False),
    sa.Column('asset_id', sa.UUID(), nullable=False),
    sa.Column('authorisation_id', sa.UUID(), nullable=False),
    sa.ForeignKeyConstraint(['asset_id'], ['asset.id'], name=op.f('fk_scan_target_asset_id'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['authorisation_id'], ['scope_agreement.id'], name=op.f('fk_scan_target_authorisation_id'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['scan_id'], ['scan.id'], name=op.f('fk_scan_target_scan_id'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('scan_id', 'asset_id', name=op.f('pk_scan_target'))
    )
    op.create_index('ix_scan_target_asset_id', 'scan_target', ['asset_id'], unique=False)
    op.create_index('ix_scan_target_authorisation_id', 'scan_target', ['authorisation_id'], unique=False)


def downgrade() -> None:
    bind = op.get_bind()

    op.drop_index('ix_scan_target_authorisation_id', table_name='scan_target')
    op.drop_index('ix_scan_target_asset_id', table_name='scan_target')
    op.drop_table('scan_target')
    op.drop_index('ix_finding_org_id_status_severity', table_name='finding')
    op.drop_index('ix_finding_last_seen_scan_id', table_name='finding')
    op.drop_table('finding')
    op.drop_index('ix_scan_org_id_created_at', table_name='scan')
    op.drop_table('scan')
    op.drop_index('ix_audit_event_org_id_occurred_at', table_name='audit_event')
    op.drop_index('ix_audit_event_asset_id_occurred_at', table_name='audit_event')
    op.drop_table('audit_event')
    op.drop_index('ix_user_account_org_id', table_name='user_account')
    op.drop_table('user_account')
    op.drop_index('ix_scope_agreement_org_id_valid_from_valid_until', table_name='scope_agreement')
    op.drop_table('scope_agreement')
    op.drop_table('asset')
    op.drop_index('ix_organisation_parent_org_id', table_name='organisation')
    op.drop_table('organisation')

    # Types are not dropped by DROP TABLE; they have to go explicitly, and only
    # once no column references them any more.
    for type_name, py_enum in PG_ENUM_TYPES.items():
        postgresql.ENUM(
            *enum_values(py_enum), name=type_name, create_type=False
        ).drop(bind, checkfirst=True)

    # citext is left installed on purpose: dropping an extension is not this
    # migration's business, and something else in the database may rely on it.
