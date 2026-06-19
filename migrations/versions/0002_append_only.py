"""
0002_append_only

Security enforcement on the two audit tables.
Revokes UPDATE and DELETE from ztrust_app on risk_event_log and admin_audit_log.
Also creates no-op PostgreSQL RULEs as belt-and-suspenders protection.

This is a security property, not a coding preference. A compromised backend
cannot delete audit records because the database user has no permission to do so.
"""
import os
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

APP = os.environ.get("DB_USER", "ztrust_app")


def upgrade():
    # Grant audit tables: INSERT + SELECT only — no UPDATE, no DELETE
    op.execute(f"GRANT SELECT, INSERT ON risk_event_log  TO {APP}")
    op.execute(f"GRANT SELECT, INSERT ON admin_audit_log TO {APP}")
    op.execute(f"REVOKE UPDATE, DELETE ON risk_event_log  FROM {APP}")
    op.execute(f"REVOKE UPDATE, DELETE ON admin_audit_log FROM {APP}")

    # Sequences for BIGSERIAL columns
    op.execute(f"GRANT USAGE, SELECT ON SEQUENCE risk_event_log_id_seq  TO {APP}")
    op.execute(f"GRANT USAGE, SELECT ON SEQUENCE admin_audit_log_id_seq TO {APP}")

    # Full access on all other tables
    for tbl in ["users", "active_sessions", "device_registry",
                "alerts", "ml_model_versions"]:
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {tbl} TO {APP}")

    # PostgreSQL RULEs: even if someone bypasses REVOKE, DELETE/UPDATE become no-ops
    op.execute("""
        CREATE OR REPLACE RULE risk_event_log_no_delete AS
            ON DELETE TO risk_event_log DO INSTEAD NOTHING;
    """)
    op.execute("""
        CREATE OR REPLACE RULE risk_event_log_no_update AS
            ON UPDATE TO risk_event_log DO INSTEAD NOTHING;
    """)
    op.execute("""
        CREATE OR REPLACE RULE admin_audit_log_no_delete AS
            ON DELETE TO admin_audit_log DO INSTEAD NOTHING;
    """)
    op.execute("""
        CREATE OR REPLACE RULE admin_audit_log_no_update AS
            ON UPDATE TO admin_audit_log DO INSTEAD NOTHING;
    """)

    # Read-only user for Adnaan's retraining pipeline
    op.execute("GRANT SELECT ON risk_event_log    TO ztrust_readonly")
    op.execute("GRANT SELECT ON ml_model_versions TO ztrust_readonly")
    op.execute("GRANT INSERT ON ml_model_versions TO ztrust_readonly")
    


def downgrade():
    for rule in ["risk_event_log_no_delete", "risk_event_log_no_update",
                 "admin_audit_log_no_delete", "admin_audit_log_no_update"]:
        tbl = "risk_event_log" if "risk" in rule else "admin_audit_log"
        op.execute(f"DROP RULE IF EXISTS {rule} ON {tbl}")
        