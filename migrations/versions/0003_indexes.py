"""
0003_indexes

Partial indexes for the admin dashboard real-time query patterns.

Every WebSocket push from Ashish's backend triggers at least one of these queries.
They must complete in under 5ms under concurrent load (project requirement Stage 8).

Partial indexes are smaller and faster than full indexes because they only
index the rows that dashboard queries actually care about.
"""
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade():
    # Dashboard query: "show me sessions that need attention, highest risk first"
    # SELECT * FROM active_sessions
    # WHERE current_decision IN ('MFA_REQUIRED','RESTRICT','BLOCK')
    # ORDER BY current_risk_score DESC LIMIT 50;
    op.execute("""
        CREATE INDEX ix_active_sessions_high_risk
        ON active_sessions (current_risk_score DESC)
        WHERE current_decision IN ('MFA_REQUIRED','RESTRICT','BLOCK');
    """)

    # Dashboard query: "show me unresolved alerts, newest first"
    # SELECT * FROM alerts WHERE resolved = false ORDER BY created_at DESC;
    op.execute("""
        CREATE INDEX ix_alerts_unresolved
        ON alerts (created_at DESC)
        WHERE resolved = false;
    """)

    # Ashish's middleware: "did this user have recent block/restrict decisions?"
    # SELECT * FROM risk_event_log
    # WHERE user_id = $1 AND decision IN ('RESTRICT','BLOCK')
    # ORDER BY created_at DESC LIMIT 5;
    op.execute("""
        CREATE INDEX ix_rel_blocks_by_user
        ON risk_event_log (user_id, created_at DESC)
        WHERE decision IN ('RESTRICT','BLOCK');
    """)

    # Adnaan's retraining pipeline: "give me feature vectors for training"
    # SELECT feature_vector, decision, ... FROM risk_event_log
    # WHERE feature_vector IS NOT NULL ORDER BY created_at ASC;
    op.execute("""
        CREATE INDEX ix_rel_feature_vectors
        ON risk_event_log (created_at ASC)
        WHERE feature_vector IS NOT NULL;
    """)

    # verify_hmac.py uses this: pulls rows since a given timestamp in order
    op.execute("""
        CREATE INDEX ix_rel_id_asc
        ON risk_event_log (id ASC);
    """)


def downgrade():
    op.execute("DROP INDEX IF EXISTS ix_active_sessions_high_risk")
    op.execute("DROP INDEX IF EXISTS ix_alerts_unresolved")
    op.execute("DROP INDEX IF EXISTS ix_rel_blocks_by_user")
    op.execute("DROP INDEX IF EXISTS ix_rel_feature_vectors")
    op.execute("DROP INDEX IF EXISTS ix_rel_id_asc")
    