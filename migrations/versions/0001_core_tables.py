"""
0001_core_tables

Creates all 7 core tables with correct CHECK constraints derived from risk_engine.h.

Enum strings used in CHECK constraints (must match C enum values):
  DecisionType: ALLOW, RESTRICT, MFA_REQUIRED, BLOCK
  RiskLevel:    LOW, MEDIUM, HIGH, CRITICAL
  EventType:    LOGIN, API_CALL, FILE_DOWNLOAD, PASSWORD_CHANGE,
                ADMIN_ACTION, DATA_EXPORT, FAILED_AUTH

sizeof(UserProfile) = 320 bytes confirmed by ctypes — profile_blob capped at 320.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

_DECISION = "decision IN ('ALLOW','RESTRICT','MFA_REQUIRED','BLOCK')"
_RISK_LVL = "risk_level IN ('LOW','MEDIUM','HIGH','CRITICAL')"
_EVT_TYPE  = ("event_type IN ('LOGIN','API_CALL','FILE_DOWNLOAD','PASSWORD_CHANGE',"
              "'ADMIN_ACTION','DATA_EXPORT','FAILED_AUTH')")


def upgrade():
    op.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')

    # ── users ────────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("email",         sa.String(255), nullable=False),
        sa.Column("password_hash", sa.Text(),       nullable=False),
        sa.Column("role",          sa.String(20),   nullable=False,
                  server_default="user"),
        sa.Column("profile_blob",  sa.LargeBinary(), nullable=True),
        sa.Column("is_active",     sa.Boolean(),    nullable=False,
                  server_default="true"),
        sa.Column("mfa_enabled",   sa.Boolean(),    nullable=False,
                  server_default="false"),
        sa.Column("created_at",    sa.DateTime(timezone=True),
                  server_default=sa.text("NOW()"), nullable=False),
        sa.Column("updated_at",    sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email", name="uq_users_email"),
        # 320 = sizeof(UserProfile) confirmed from Uthkarsh's risk_engine.h
        sa.CheckConstraint(
            "profile_blob IS NULL OR octet_length(profile_blob) <= 320",
            name="ck_users_profile_blob_max_320"
        ),
        sa.CheckConstraint(
            "role IN ('user','admin','readonly')",
            name="ck_users_role"
        ),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    # ── active_sessions ──────────────────────────────────────────────────────
    op.create_table(
        "active_sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("user_id",            postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("jwt_jti",            sa.String(64),  nullable=False),
        sa.Column("device_hash",        sa.String(64),  nullable=False),
        sa.Column("ip_hash",            sa.String(64),  nullable=False),
        sa.Column("current_risk_score", sa.Float(),     nullable=False,
                  server_default="0.0"),
        sa.Column("current_risk_level", sa.String(10),  nullable=False,
                  server_default="LOW"),
        sa.Column("current_decision",   sa.String(15),  nullable=False,
                  server_default="ALLOW"),
        sa.Column("created_at",         sa.DateTime(timezone=True),
                  server_default=sa.text("NOW()"), nullable=False),
        sa.Column("expires_at",         sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_event_at",      sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("jwt_jti", name="uq_active_sessions_jwt_jti"),
        sa.CheckConstraint(
            "current_decision IN ('ALLOW','RESTRICT','MFA_REQUIRED','BLOCK')",
            name="ck_active_sessions_decision"
        ),
        sa.CheckConstraint(
            "current_risk_level IN ('LOW','MEDIUM','HIGH','CRITICAL')",
            name="ck_active_sessions_risk_level"
        ),
        sa.CheckConstraint(
            "current_risk_score >= 0.0 AND current_risk_score <= 1.0",
            name="ck_active_sessions_score_range"
        ),
    )
    op.create_index("ix_active_sessions_user_id",
                    "active_sessions", ["user_id"])
    op.create_index("ix_active_sessions_jwt_jti",
                    "active_sessions", ["jwt_jti"], unique=True)

    # ── risk_event_log ───────────────────────────────────────────────────────
    op.create_table(
        "risk_event_log",
        sa.Column("id",                sa.BigInteger(), autoincrement=True,
                  nullable=False),
        sa.Column("session_id",        postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id",           postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_type",        sa.String(20),  nullable=False),
        sa.Column("risk_score_before", sa.Float(),     nullable=False),
        sa.Column("risk_score_after",  sa.Float(),     nullable=False),
        sa.Column("rule_score",        sa.Float(),     nullable=False),
        sa.Column("ml_score",          sa.Float(),     nullable=True),
        sa.Column("decision",          sa.String(15),  nullable=False),
        sa.Column("risk_level",        sa.String(10),  nullable=False),
        sa.Column("feature_vector",    postgresql.ARRAY(sa.Float()), nullable=True),
        sa.Column("hmac",              sa.String(64),  nullable=False),
        sa.Column("created_at",        sa.DateTime(timezone=True),
                  server_default=sa.text("NOW()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["session_id"], ["active_sessions.id"]),
        sa.ForeignKeyConstraint(["user_id"],    ["users.id"]),
        sa.CheckConstraint(_DECISION,  name="ck_rel_decision"),
        sa.CheckConstraint(_RISK_LVL,  name="ck_rel_risk_level"),
        sa.CheckConstraint(_EVT_TYPE,  name="ck_rel_event_type"),
        sa.CheckConstraint(
            "feature_vector IS NULL OR array_length(feature_vector, 1) = 6",
            name="ck_rel_feature_vector_len"
        ),
    )
    op.create_index("ix_rel_session_created",
                    "risk_event_log", ["session_id", "created_at"])
    op.create_index("ix_rel_user_created",
                    "risk_event_log", ["user_id", "created_at"])
    op.create_index("ix_rel_created_at",
                    "risk_event_log", ["created_at"])

    # ── admin_audit_log ──────────────────────────────────────────────────────
    op.create_table(
        "admin_audit_log",
        sa.Column("id",                sa.BigInteger(), autoincrement=True,
                  nullable=False),
        sa.Column("admin_user_id",     postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("action_type",       sa.String(50),  nullable=False),
        sa.Column("target_user_id",    postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("target_session_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("details",           postgresql.JSONB(), nullable=True),
        sa.Column("created_at",        sa.DateTime(timezone=True),
                  server_default=sa.text("NOW()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["admin_user_id"], ["users.id"]),
    )
    op.create_index("ix_aal_created_at",
                    "admin_audit_log", ["created_at"])

    # ── device_registry ──────────────────────────────────────────────────────
    op.create_table(
        "device_registry",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("user_id",     postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("device_hash", sa.String(64), nullable=False),
        sa.Column("is_trusted",  sa.Boolean(),  nullable=False,
                  server_default="false"),
        sa.Column("first_seen",  sa.DateTime(timezone=True),
                  server_default=sa.text("NOW()"), nullable=False),
        sa.Column("last_seen",   sa.DateTime(timezone=True),
                  server_default=sa.text("NOW()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_device_registry_user_device",
                    "device_registry", ["user_id", "device_hash"], unique=True)

    # ── alerts ───────────────────────────────────────────────────────────────
    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("user_id",     postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("session_id",  postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("alert_type",  sa.String(50), nullable=False),
        sa.Column("severity",    sa.String(10), nullable=False),
        sa.Column("resolved",    sa.Boolean(),  nullable=False,
                  server_default="false"),
        sa.Column("resolved_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at",  sa.DateTime(timezone=True),
                  server_default=sa.text("NOW()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["user_id"],    ["users.id"]),
        sa.ForeignKeyConstraint(["session_id"], ["active_sessions.id"]),
        sa.CheckConstraint(
            "severity IN ('LOW','MEDIUM','HIGH','CRITICAL')",
            name="ck_alerts_severity"
        ),
    )
    op.create_index("ix_alerts_user_id",          "alerts", ["user_id"])
    op.create_index("ix_alerts_resolved_created", "alerts", ["resolved", "created_at"])

    # ── ml_model_versions ────────────────────────────────────────────────────
    op.create_table(
        "ml_model_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("file_path",           sa.Text(),    nullable=False),
        sa.Column("training_date",       sa.DateTime(timezone=True), nullable=False),
        sa.Column("training_data_size",  sa.Integer(), nullable=False),
        sa.Column("false_positive_rate", sa.Float(),   nullable=False),
        sa.Column("detection_rate",      sa.Float(),   nullable=False),
        sa.Column("active",              sa.Boolean(), nullable=False,
                  server_default="false"),
        sa.Column("created_at",          sa.DateTime(timezone=True),
                  server_default=sa.text("NOW()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade():
    for tbl in ["ml_model_versions", "alerts", "device_registry",
                "admin_audit_log", "risk_event_log",
                "active_sessions", "users"]:
        op.drop_table(tbl)
        