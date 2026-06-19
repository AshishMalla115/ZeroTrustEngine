"""
0004_hmac_verification

Creates tamper_log table and a PostgreSQL function used by verify_hmac.py.

The tamper_log records any risk_event_log row whose HMAC fails verification.
The SQL function efficiently pulls risk_event_log rows since a timestamp
so verify_hmac.py can recompute and compare HMACs in Python.

The actual HMAC computation stays in Python (HMAC_SECRET_KEY must not be
stored in the database).
"""
from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade():
    # tamper_log: written by verify_hmac.py when a mismatch is found
    op.create_table(
        "tamper_log",
        sa.Column("id",            sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("risk_event_id", sa.BigInteger(), nullable=False),
        sa.Column("detected_at",   sa.DateTime(timezone=True),
                  server_default=sa.text("NOW()"), nullable=False),
        sa.Column("stored_hmac",   sa.String(64),   nullable=False),
        sa.Column("notes",         sa.Text(),        nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["risk_event_id"], ["risk_event_log.id"]),
    )
    op.create_index("ix_tamper_log_detected_at", "tamper_log", ["detected_at"])

    # SQL function: verify_hmac.py calls this to pull rows efficiently
    # Returns all columns needed to recompute the HMAC canonical string
    op.execute("""
        CREATE OR REPLACE FUNCTION get_risk_events_since(since_ts TIMESTAMPTZ)
        RETURNS TABLE (
            id                BIGINT,
            session_id        UUID,
            user_id           UUID,
            event_type        VARCHAR(20),
            risk_score_before FLOAT8,
            risk_score_after  FLOAT8,
            rule_score        FLOAT8,
            ml_score          FLOAT8,
            decision          VARCHAR(15),
            risk_level        VARCHAR(10),
            feature_vector    FLOAT8[],
            hmac              VARCHAR(64),
            created_at        TIMESTAMPTZ
        )
        LANGUAGE SQL
        STABLE
        AS $$
            SELECT
                id, session_id, user_id, event_type,
                risk_score_before, risk_score_after,
                rule_score, ml_score,
                decision, risk_level,
                feature_vector, hmac, created_at
            FROM risk_event_log
            WHERE created_at >= since_ts
            ORDER BY id ASC;
        $$;
    """)


def downgrade():
    op.execute("DROP FUNCTION IF EXISTS get_risk_events_since(TIMESTAMPTZ)")
    op.drop_table("tamper_log")
    