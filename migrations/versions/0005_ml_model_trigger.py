"""
0005_ml_model_trigger

Creates a PostgreSQL trigger that enforces exactly one active model row at a time.

When Adnaan's retraining pipeline inserts a new row with active=TRUE,
the trigger automatically sets active=FALSE on all other rows.

Adnaan's Python code only needs to do:
    INSERT INTO ml_model_versions (..., active) VALUES (..., TRUE)
No additional UPDATE statement needed.
"""
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade():
    # Trigger function: deactivates all other rows when a new active row arrives
    op.execute("""
        CREATE OR REPLACE FUNCTION enforce_single_active_model()
        RETURNS TRIGGER
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF NEW.active = TRUE THEN
                UPDATE ml_model_versions
                   SET active = FALSE
                 WHERE id != NEW.id
                   AND active = TRUE;
            END IF;
            RETURN NEW;
        END;
        $$;
    """)

    # Fire AFTER INSERT OR UPDATE so NEW.id is already assigned
    op.execute("""
        CREATE TRIGGER trg_single_active_model
        AFTER INSERT OR UPDATE ON ml_model_versions
        FOR EACH ROW
        EXECUTE FUNCTION enforce_single_active_model();
    """)

    # Give ztrust_readonly INSERT so Adnaan can add model versions
    


def downgrade():
    op.execute(
        "DROP TRIGGER IF EXISTS trg_single_active_model ON ml_model_versions"
    )
    op.execute("DROP FUNCTION IF EXISTS enforce_single_active_model()")
    